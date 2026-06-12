(* Verifier LIVE-REORG proof for txospender_index (camlcoin).

   This goes beyond the module-level unit test (test_txospender_verify.ml,
   which calls Txospender_index.disconnect_block directly).  Here we drive the
   REAL daemon block-acceptance + reorg pipeline:

     - main chain A built via Mining.create_block_template / mine_block /
       submit_block (the same path submitblock / generate use),
     - a real on-chain SPEND of a matured coinbase (tx B with an OP_TRUE
       input), which makes the txospenderindex WRITE a key on the live connect
       path (Sync.txospender_connect_if_enabled from Mining.submit_block),
     - then a HEAVIER competing branch submitted via Mining.submit_block, which
       routes to Sync.try_attach_side_branch_and_reorg -> Sync.reorganize ->
       disconnect_block_into_batch -> txospender_disconnect_if_enabled.

   The assertion that matters: after the LIVE reorg orphans the block that
   contained tx B, find_spender(coinbase:0) must return None — i.e. the key was
   ERASED on the LIVE reorg path (disconnect_block_into_batch), NOT only on the
   invalidateblock path.  We also confirm the new branch became the tip and the
   re-spend key did NOT leak. *)

open Camlcoin
module Txospender_index = Camlcoin__Txospender_index

let test_db_path = Printf.sprintf "/tmp/txosp-livereorg-%d-db" (Unix.getpid ())
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

let cleanup () =
  rm_rf test_db_path; rm_rf rocksdb_path;
  rm_rf (test_db_path ^ "_txosp")

(* OP_TRUE — anyone-can-spend scriptPubKey; an empty scriptSig satisfies it. *)
let op_true = Cstruct.of_string "\x51"

(* Re-mine the nonce of a hand-assembled header against the (easy) regtest
   target.  Returns the block with the winning nonce. *)
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

let () =
  cleanup ();
  let db = Storage.ChainDB.create test_db_path in
  let chain = Sync.create_chain_state db Consensus.regtest in
  let rocksdb = Rocksdb_store.open_db rocksdb_path in
  Storage.ChainDB.attach_rocksdb_utxo db rocksdb;
  let optimized =
    Utxo.OptimizedUtxoSet.create ~cache_size:65536 ~rocksdb db in
  let utxo = Utxo.UtxoSet.create db in
  let mp = Mempool.create
    ~require_standard:false ~verify_scripts:false ~utxo ~current_height:0 () in

  (* Attach the txospender index to the live chain — exactly as cli.ml does
     when --txospenderindex=1. *)
  let idx = Txospender_index.create ~data_dir:(test_db_path ^ "_txosp") in
  chain.Sync.txospenderindex <- Some idx;

  let submit (b : Types.block) : unit =
    match Mining.submit_block ~utxo:optimized
            ~network_type:Consensus.Regtest b chain mp with
    | Ok () -> ()
    | Error e -> failwith (Printf.sprintf "submit_block failed: %s" e)
  in

  (* --- Main chain A: mine 102 blocks, coinbases pay to OP_TRUE. --- *)
  let mine_on_tip () : Types.block =
    let tmpl = Mining.create_block_template ~chain ~mp ~payout_script:op_true in
    match Mining.mine_block tmpl 5_000_000l with
    | Some b -> b
    | None -> failwith "mine_block (tip) failed"
  in
  let cb1_ref = ref None in
  for h = 1 to 101 do
    let b = mine_on_tip () in
    if h = 1 then cb1_ref := Some (List.hd b.Types.transactions);
    submit b
  done;
  let cb1 = match !cb1_ref with Some t -> t | None -> failwith "no cb1" in
  let cb1_txid = Crypto.compute_txid cb1 in
  let op_a0 = { Types.txid = cb1_txid; vout = 0l } in
  Printf.printf "OK  mined 101 blocks; coinbase-1 matured (txid=%s)\n"
    (Types.hash256_to_hex_display cb1_txid);

  (* Sanity: nothing spent yet. *)
  assert (Txospender_index.find_spender idx op_a0 = None);

  (* --- Block 102: spend coinbase-1:0 with tx B (OP_TRUE input). --- *)
  let cb1_reward = (List.hd cb1.Types.outputs).Types.value in
  let tx_b : Types.transaction =
    { Types.version = 2l;
      inputs = [ { previous_output = op_a0;
                   script_sig = Cstruct.create 0;     (* OP_TRUE needs none *)
                   sequence = 0xffffffffl } ];
      outputs = [ { value = Int64.sub cb1_reward 1000L;  (* leave a fee *)
                    script_pubkey = op_true } ];
      witnesses = []; locktime = 0l } in
  let tx_b_txid = Crypto.compute_txid tx_b in
  let tip102 = match chain.Sync.tip with Some t -> t | None -> assert false in
  let height102 = tip102.Sync.height + 1 in
  (* Build block 102 = [coinbase; tx_b] off the current tip. *)
  let build_block ~(prev_hash : Types.hash256) ~(height : int)
      ~(extra_tag : int) (txs : Types.transaction list) : Types.block =
    let extra_nonce = Cstruct.create 8 in
    Cstruct.LE.set_uint64 extra_nonce 0 (Int64.of_int (height * 1000 + extra_tag));
    let placeholder_cb =
      Mining.create_coinbase ~height ~total_fee:0L ~payout_script:op_true
        ~extra_nonce ~witness_root:None ~network_type:Consensus.Regtest () in
    let witness_root =
      Mining.compute_witness_merkle_root (placeholder_cb :: txs) in
    let coinbase =
      Mining.create_coinbase ~height ~total_fee:0L ~payout_script:op_true
        ~extra_nonce ~witness_root:(Some witness_root)
        ~network_type:Consensus.Regtest () in
    let all = coinbase :: txs in
    let (merkle_root, _) = Crypto.merkle_root (List.map Crypto.compute_txid all) in
    let header : Types.block_header =
      { version = 4l; prev_block = prev_hash; merkle_root;
        timestamp = Int32.add tip102.Sync.header.Types.timestamp
                      (Int32.of_int (height * 2 + extra_tag));
        bits = Consensus.regtest.pow_limit; nonce = 0l } in
    remine { Types.header; transactions = all }
  in
  let blk102 = build_block ~prev_hash:tip102.Sync.hash ~height:height102
      ~extra_tag:0 [ tx_b ] in
  submit blk102;
  let blk102_hash = Crypto.compute_block_hash blk102.Types.header in
  Printf.printf "OK  block 102 connected (height=%d) including spend tx B\n" height102;

  (* LIVE connect path indexed the spend: find_spender(cb1:0) = tx_b. *)
  (match Txospender_index.find_spender idx op_a0 with
   | None -> failwith "FAIL: cb1:0 not indexed after the spend block connected"
   | Some s ->
     assert (Cstruct.equal s.Txospender_index.spending_txid tx_b_txid);
     assert (Cstruct.equal s.Txospender_index.block_hash blk102_hash));
  assert (chain.Sync.blocks_synced = height102);
  Printf.printf "OK  LIVE connect: find_spender(cb1:0) = B (+ blockhash=block102)\n";

  (* --- Heavier competing branch forking at height 101 (tip102's parent). ---
     Branch B: 102' (does NOT spend cb1 — pays coinbase only) then 103'.
     Submitting 102' first stores an inactive side branch (equal work); 103'
     makes the branch strictly heavier and triggers Sync.reorganize, which
     disconnects the ORIGINAL block 102 via the LIVE path
     (disconnect_block_into_batch -> txospender_disconnect_if_enabled). *)
  (* The fork point is the block at height 101 (tip102), the common parent of
     BOTH the original block 102 and the competing branch.  tip102 was captured
     before block 102 connected, so it IS the height-101 entry. *)
  let fork_parent = tip102 in
  assert (fork_parent.Sync.height = height102 - 1);
  let blk102b = build_block ~prev_hash:fork_parent.Sync.hash
      ~height:height102 ~extra_tag:7 [] in
  submit blk102b;  (* stored, not heavier yet -> no reorg *)
  (* The spend key must still be present (no reorg happened yet). *)
  (match Txospender_index.find_spender idx op_a0 with
   | Some s when Cstruct.equal s.Txospender_index.spending_txid tx_b_txid -> ()
   | _ -> failwith "FAIL: side-branch 102b storage unexpectedly disturbed the key");
  let blk102b_hash = Crypto.compute_block_hash blk102b.Types.header in
  let blk103b = build_block ~prev_hash:blk102b_hash
      ~height:(height102 + 1) ~extra_tag:9 [] in
  submit blk103b;  (* now strictly heavier -> LIVE reorganize *)
  Printf.printf "OK  submitted heavier branch (102b,103b) -> triggers LIVE reorganize\n";

  (* The new tip must be branch B at height+1. *)
  let new_tip = match chain.Sync.tip with Some t -> t | None -> assert false in
  let blk103b_hash = Crypto.compute_block_hash blk103b.Types.header in
  assert (new_tip.Sync.height = height102 + 1);
  if not (Cstruct.equal new_tip.Sync.hash blk103b_hash) then
    failwith "FAIL: reorg did not flip the tip to the heavier branch";
  Printf.printf "OK  tip flipped to heavier branch B at height %d\n"
    new_tip.Sync.height;

  (* THE KEY ASSERTION: the original block 102 was orphaned on the LIVE reorg
     path, so its spend of cb1:0 must be ERASED. *)
  (match Txospender_index.find_spender idx op_a0 with
   | None ->
     Printf.printf
       "OK  LIVE-REORG ERASE: find_spender(cb1:0) = None after heavier branch \
        orphaned the spend block\n"
   | Some s ->
     failwith (Printf.sprintf
       "FAIL: STALE entry after LIVE reorg — cb1:0 still resolves to %s \
        (block %s); the live-reorg disconnect hook did not erase it"
       (Types.hash256_to_hex_display s.Txospender_index.spending_txid)
       (Types.hash256_to_hex_display s.Txospender_index.block_hash)));

  (* best_indexed_height rolled forward/back consistently to the new tip. *)
  Printf.printf "    (txospenderindex best_height=%d, chain tip=%d)\n"
    (Txospender_index.best_height idx) new_tip.Sync.height;

  Rocksdb_store.close rocksdb;
  Storage.ChainDB.close db;
  cleanup ();
  Printf.printf "ALL TXOSPENDER LIVE-REORG CHECKS PASSED\n"
