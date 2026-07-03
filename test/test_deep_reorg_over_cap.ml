(* Deep-reorg-over-cap LIVE proof (camlcoin) — Core-parity Class-A fix.

   Bitcoin Core's [ActivateBestChainStep] disconnects to the fork point with
   NO depth limit: an ARCHIVE node (pruning disabled = default) follows the
   most-work valid chain to ANY depth.  camlcoin previously enforced a fixed
   288-block reorg cap unconditionally, so it would REFUSE a >288-deep
   higher-work chain and strand itself on the lower-work minority branch —
   a consensus split (Class A).

   This harness drives the REAL daemon reorg pipeline (Mining.submit_block ->
   Sync.try_attach_side_branch_and_reorg -> Sync.reorganize) with a competing
   fork that forks at GENESIS and is deeper than the 288 cap on BOTH the
   disconnect and the connect side:

     - chain A: [chain_a_depth] blocks off genesis (coinbase-only, OP_TRUE),
     - branch B: [chain_b_depth] = chain_a_depth + 1 blocks off genesis,
       strictly heavier, so Core would reorg to it.

   With chain_a_depth = 290 the reorg is disconnect=290 / connect=291, both
   > MAX_REORG_DEPTH=288.

   PRE-fix expectation (cap unconditional): submit of B's tip returns the
   "Reorg depth ... exceeds MAX_REORG_DEPTH" error; the active tip STAYS on
   chain A.
   POST-fix expectation (cap gated on pruning; archive default): the reorg
   succeeds and the active tip FLIPS to branch B's deepest block. *)

open Camlcoin

let test_db_path = Printf.sprintf "/tmp/deep-reorg-cap-%d-db" (Unix.getpid ())
let rocksdb_path = test_db_path ^ "_rocksdb_utxo"

let rm_rf path =
  let rec go p =
    if Sys.file_exists p then
      if Sys.is_directory p then begin
        Array.iter (fun f -> go (Filename.concat p f)) (Sys.readdir p);
        (try Unix.rmdir p with _ -> ())
      end else (try Unix.unlink p with _ -> ())
  in
  go path

let cleanup () = rm_rf test_db_path; rm_rf rocksdb_path

let op_true = Cstruct.of_string "\x51"

(* Re-mine the nonce against the (trivial) regtest target. *)
let remine (block : Types.block) : Types.block =
  let h = ref block.Types.header in
  let n = ref 0l in
  let found = ref false in
  while not !found && Int32.compare !n 5_000_000l < 0 do
    h := { !h with Types.nonce = !n };
    if Consensus.hash_meets_target (Crypto.compute_block_hash !h) !h.Types.bits
    then found := true
    else n := Int32.add !n 1l
  done;
  if not !found then failwith "remine: no nonce found";
  { block with Types.header = !h }

(* MAX_REORG_DEPTH is 288; go one past on the disconnect side and two past on
   the connect side so BOTH depths exceed the cap. *)
let chain_a_depth = 290
let chain_b_depth = chain_a_depth + 1

let () =
  cleanup ();
  let db = Storage.ChainDB.create test_db_path in
  let chain = Sync.create_chain_state db Consensus.regtest in
  let rocksdb = Rocksdb_store.open_db rocksdb_path in
  Storage.ChainDB.attach_rocksdb_utxo db rocksdb;
  let optimized =
    Utxo.OptimizedUtxoSet.create ~cache_size:65536 ~rocksdb db in
  let utxo = Utxo.UtxoSet.create db in
  let mp = Mempool.create ~network:Consensus.regtest
    ~require_standard:false ~verify_scripts:false ~utxo ~current_height:0 () in

  (* Archive node: pruning disabled (the default). This is the config under
     which Core follows most-work to any depth. *)
  assert (chain.Sync.prune_target = 0);

  let submit (b : Types.block) : (unit, string) result =
    Mining.submit_block ~utxo:optimized
      ~network_type:Consensus.Regtest b chain mp
  in
  let submit_ok (b : Types.block) : unit =
    match submit b with
    | Ok () -> ()
    | Error e -> failwith (Printf.sprintf "submit_block failed: %s" e)
  in

  (* --- chain A: mine chain_a_depth blocks off genesis. --- *)
  let mine_on_tip () : Types.block =
    let tmpl = Mining.create_block_template ~chain ~mp ~payout_script:op_true in
    match Mining.mine_block tmpl 5_000_000l with
    | Some b -> b
    | None -> failwith "mine_block (tip) failed"
  in
  for _ = 1 to chain_a_depth do submit_ok (mine_on_tip ()) done;
  let tip_a = match chain.Sync.tip with Some t -> t | None -> assert false in
  assert (tip_a.Sync.height = chain_a_depth);
  let tip_a_hash = tip_a.Sync.hash in
  Printf.printf "OK  chain A mined to height %d\n%!" chain_a_depth;

  (* --- branch B: build chain_b_depth blocks off genesis, strictly heavier. ---
     Built by hand (create_block_template only extends the ACTIVE tip). Each B
     block carries a distinct extra_nonce (branch tag 0xB) so its coinbase —
     and therefore its block hash — differs from chain A at the same height. *)
  let genesis_hash =
    Crypto.compute_block_hash Consensus.regtest.genesis_header in
  let genesis_ts = Consensus.regtest.genesis_header.Types.timestamp in
  let build_b_block ~(prev_hash : Types.hash256) ~(height : int)
      : Types.block =
    let extra_nonce = Cstruct.create 8 in
    Cstruct.LE.set_uint64 extra_nonce 0
      (Int64.of_int ((height lsl 4) lor 0xB));
    let placeholder_cb =
      Mining.create_coinbase ~height ~total_fee:0L ~payout_script:op_true
        ~extra_nonce ~witness_root:None ~network_type:Consensus.Regtest () in
    let witness_root =
      Mining.compute_witness_merkle_root [ placeholder_cb ] in
    let coinbase =
      Mining.create_coinbase ~height ~total_fee:0L ~payout_script:op_true
        ~extra_nonce ~witness_root:(Some witness_root)
        ~network_type:Consensus.Regtest () in
    let (merkle_root, _) =
      Crypto.merkle_root [ Crypto.compute_txid coinbase ] in
    let header : Types.block_header =
      { version = 4l; prev_block = prev_hash; merkle_root;
        (* strictly-increasing timestamps clear MTP on branch B *)
        timestamp = Int32.add genesis_ts (Int32.of_int height);
        bits = Consensus.regtest.pow_limit; nonce = 0l } in
    remine { Types.header; transactions = [ coinbase ] }
  in
  let prev = ref genesis_hash in
  let b_tip_hash = ref genesis_hash in
  let reorg_error = ref None in
  (try
    for height = 1 to chain_b_depth do
      let blk = build_b_block ~prev_hash:!prev ~height in
      b_tip_hash := Crypto.compute_block_hash blk.Types.header;
      (match submit blk with
       | Ok () -> ()
       | Error e ->
         (* The only submit that can trigger a reorg is B's deepest block
            (the first to be strictly heavier than chain A). Capture its
            error so we can distinguish PRE-fix (cap rejects) from POST-fix
            (reorg succeeds). *)
         reorg_error := Some (height, e);
         raise Exit);
      prev := !b_tip_hash
    done
  with Exit -> ());

  let final_tip = match chain.Sync.tip with Some t -> t | None -> assert false in
  (match !reorg_error with
   | Some (height, e) ->
     Printf.printf
       "REORG REFUSED at B height %d: %s\n%!" height e;
     Printf.printf
       "    active tip still on chain A (height %d, hash %s)\n%!"
       final_tip.Sync.height
       (Types.hash256_to_hex_display final_tip.Sync.hash);
     if final_tip.Sync.height = chain_a_depth
        && Cstruct.equal final_tip.Sync.hash tip_a_hash then
       Printf.printf
         "PRE-FIX BEHAVIOR CONFIRMED: >288-deep higher-work chain REFUSED; \
          node stranded on minority chain A (Class-A divergence).\n%!"
     else
       failwith "unexpected tip state after a refused reorg";
     (* A refused deep reorg is the PRE-fix result; exit non-zero so the
        harness fails loudly when run against the un-gated code. *)
     exit 1
   | None ->
     (* No error => the deepest B block triggered a successful reorg. *)
     if final_tip.Sync.height = chain_b_depth
        && Cstruct.equal final_tip.Sync.hash !b_tip_hash then begin
       Printf.printf
         "OK  REORG SUCCEEDED: active tip FLIPPED to branch B height %d \
          (hash %s)\n%!"
         final_tip.Sync.height
         (Types.hash256_to_hex_display final_tip.Sync.hash);
       Printf.printf
         "    disconnect_depth=%d connect_depth=%d (both > MAX_REORG_DEPTH=288)\n%!"
         chain_a_depth chain_b_depth;
       (* Sanity: the flipped tip must NOT be chain A's tip. *)
       assert (not (Cstruct.equal final_tip.Sync.hash tip_a_hash));
       Printf.printf
         "POST-FIX BEHAVIOR CONFIRMED: archive node followed the most-work \
          valid chain past the 288 cap, matching Bitcoin Core.\n%!"
     end else
       failwith (Printf.sprintf
         "reorg did not flip to B tip (got height %d)" final_tip.Sync.height));

  Rocksdb_store.close rocksdb;
  Storage.ChainDB.close db;
  cleanup ();
  Printf.printf "ALL DEEP-REORG-OVER-CAP CHECKS PASSED\n%!"
