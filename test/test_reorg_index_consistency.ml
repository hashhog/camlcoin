(* Post-reorg RPC chain-state consistency proof for camlcoin.

   Regression for the "submitblock-triggered reorg leaves RPC chain-state
   inconsistent" bug: after a submitblock-driven reorg, the height counter
   (getblockcount) advanced to the new chain's length, but the active-chain
   height->hash index and the best-block-hash pointer were left pointing at
   the ABANDONED branch:

     - getblockhash(tip)      -> null  (index slot never written)
     - getblockhash(tip - 1)  -> the old chain-A block (stale)
     - getbestblockhash       -> all-zeros (block_tip resolves height->hash
                                 at blocks_synced, which was null)

   Root cause: [Sync.reorganize] staged the UTXO delta, undo data, block
   bodies, tx_index pointers, and the chain-tip flip into its atomic batch,
   but NEVER updated the height->hash active-chain index (the on-disk
   equivalent of Bitcoin Core's [CChain] / [CChain::SetTip], chain.cpp:16).

   This test drives the REAL daemon reorg pipeline
   (Mining.submit_block -> Sync.try_attach_side_branch_and_reorg ->
   Sync.reorganize) and asserts the three RPC read paths agree after the
   reorg:

     getbestblockhash == getblockhash(getblockcount) == new tip
     getblockhash(tip - 1) == the NEW chain's block (not the orphaned one)

   Pre-fix: FAILS (index slot at the new tip is None). Post-fix: PASSES. *)

open Camlcoin

let test_db_path = Printf.sprintf "/tmp/reorg-index-%d-db" (Unix.getpid ())
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

(* OP_TRUE — anyone-can-spend scriptPubKey. *)
let op_true = Cstruct.of_string "\x51"

(* Re-mine the nonce of a hand-assembled header against the easy regtest
   target. *)
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

let zero_hash =
  "0000000000000000000000000000000000000000000000000000000000000000"

(* getbestblockhash — exactly the RPC handler's source (Sync.block_tip). *)
let getbestblockhash (chain : Sync.chain_state) : string =
  match Sync.block_tip chain with
  | Some t -> Types.hash256_to_hex_display t.hash
  | None -> zero_hash

(* getblockhash(height) — exactly the RPC handler's source. *)
let getblockhash (chain : Sync.chain_state) (height : int) : string option =
  match Storage.ChainDB.get_hash_at_height chain.Sync.db height with
  | Some hash -> Some (Types.hash256_to_hex_display hash)
  | None -> None

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

  let submit (b : Types.block) : unit =
    match Mining.submit_block ~utxo:optimized
            ~network_type:Consensus.Regtest b chain mp with
    | Ok () -> ()
    | Error e -> failwith (Printf.sprintf "submit_block failed: %s" e)
  in

  (* --- Main chain A: mine 105 blocks off the tip. --- *)
  let mine_on_tip () : Types.block =
    let tmpl = Mining.create_block_template ~chain ~mp ~payout_script:op_true in
    match Mining.mine_block tmpl 5_000_000l with
    | Some b -> b
    | None -> failwith "mine_block (tip) failed"
  in
  for _ = 1 to 106 do submit (mine_on_tip ()) done;

  let tipA = match chain.Sync.tip with Some t -> t | None -> assert false in
  assert (tipA.Sync.height = 106);
  assert (chain.Sync.blocks_synced = 106);
  Printf.printf "OK  mined 106 blocks on chain A (tip height=106)\n";

  (* Deterministic block builder off an arbitrary parent. *)
  let build_block ~(prev_hash : Types.hash256) ~(height : int)
      ~(prev_time : int32) ~(extra_tag : int) : Types.block =
    let extra_nonce = Cstruct.create 8 in
    Cstruct.LE.set_uint64 extra_nonce 0 (Int64.of_int (height * 1000 + extra_tag));
    let placeholder_cb =
      Mining.create_coinbase ~height ~total_fee:0L ~payout_script:op_true
        ~extra_nonce ~witness_root:None ~network_type:Consensus.Regtest () in
    let witness_root = Mining.compute_witness_merkle_root [ placeholder_cb ] in
    let coinbase =
      Mining.create_coinbase ~height ~total_fee:0L ~payout_script:op_true
        ~extra_nonce ~witness_root:(Some witness_root)
        ~network_type:Consensus.Regtest () in
    let (merkle_root, _) =
      Crypto.merkle_root [ Crypto.compute_txid coinbase ] in
    let header : Types.block_header =
      { version = 4l; prev_block = prev_hash; merkle_root;
        timestamp = Int32.add prev_time (Int32.of_int (2 + extra_tag));
        bits = Consensus.regtest.pow_limit; nonce = 0l } in
    remine { Types.header; transactions = [ coinbase ] }
  in

  (* --- Competing branch B forking at height 100 (depth-6 reorg). ---
     Fork parent = the height-100 block on chain A. Build B: 101'..107'
     (7 blocks above the fork). Chain A has 6 blocks above the fork
     (101..106), so:
       - B's 101'..106' are equal-or-lighter work than A's active tip and
         are STORED as inactive side branches (no reorg — Core requires
         STRICTLY more work to switch tips), and
       - B's 107' makes branch B strictly heavier, triggering a SINGLE
         Sync.reorganize that lands the validated tip directly on 107'
         (height 107). This is the exact submitblock-reorg-finalize path. *)
  let fork_parent =
    match Sync.get_header_at_height chain 100 with
    | Some e -> e | None -> assert false in
  assert (fork_parent.Sync.height = 100);

  let branch = ref [] in
  let prev_hash = ref fork_parent.Sync.hash in
  let prev_time = ref fork_parent.Sync.header.Types.timestamp in
  for h = 101 to 107 do
    let b = build_block ~prev_hash:!prev_hash ~height:h
        ~prev_time:!prev_time ~extra_tag:7 in
    branch := b :: !branch;
    prev_hash := Crypto.compute_block_hash b.Types.header;
    prev_time := b.Types.header.Types.timestamp
  done;
  let branch = List.rev !branch in  (* 101' .. 107', ascending *)

  (* Store 101'..106' as inactive side branches (equal/lighter work). *)
  let n = List.length branch in
  List.iteri (fun i b -> if i < n - 1 then submit b) branch;
  if chain.Sync.blocks_synced <> 106 then
    failwith (Printf.sprintf
      "side-branch prefix unexpectedly reorged: blocks_synced=%d (want 106)"
      chain.Sync.blocks_synced);
  Printf.printf "OK  stored branch B prefix 101'..106' (no reorg yet)\n";

  (* Submit the final block 107' -> strictly heavier -> single reorganize. *)
  let blk107b = List.nth branch (n - 1) in
  let blk106b = List.nth branch (n - 2) in
  submit blk107b;

  let blk107b_hash =
    Types.hash256_to_hex_display (Crypto.compute_block_hash blk107b.Types.header) in
  let blk106b_hash =
    Types.hash256_to_hex_display (Crypto.compute_block_hash blk106b.Types.header) in

  (* Sanity: the reorg happened — height counter advanced to the new
     chain's length (this part was already correct pre-fix). *)
  if chain.Sync.blocks_synced <> 107 then
    failwith (Printf.sprintf
      "reorg did not advance to branch B: blocks_synced=%d (want 107)"
      chain.Sync.blocks_synced);
  Printf.printf "OK  reorg fired: getblockcount -> 107\n";

  let count = chain.Sync.blocks_synced in

  (* THE CONSISTENCY ASSERTIONS (all three RPC read paths must agree). *)
  let best = getbestblockhash chain in
  let at_tip = getblockhash chain count in
  let at_tip_minus1 = getblockhash chain (count - 1) in

  Printf.printf "    getbestblockhash      = %s\n" best;
  Printf.printf "    getblockhash(%d)      = %s\n" count
    (match at_tip with Some h -> h | None -> "null");
  Printf.printf "    getblockhash(%d)      = %s\n" (count - 1)
    (match at_tip_minus1 with Some h -> h | None -> "null");

  (* 1. getblockhash(tip) must be the new chain's tip, not null. *)
  (match at_tip with
   | None ->
     failwith "FAIL: getblockhash(getblockcount) = null after reorg \
               (height->hash index slot at the new tip was never written)"
   | Some h when h <> blk107b_hash ->
     failwith (Printf.sprintf
       "FAIL: getblockhash(tip) = %s, expected new-chain tip %s" h blk107b_hash)
   | Some _ -> ());

  (* 2. getbestblockhash must equal getblockhash(tip) and be the new tip. *)
  if best = zero_hash then
    failwith "FAIL: getbestblockhash = all-zeros after reorg \
              (best-block pointer left dangling on the abandoned branch)";
  if Some best <> at_tip then
    failwith (Printf.sprintf
      "FAIL: getbestblockhash (%s) != getblockhash(getblockcount) (%s)"
      best (match at_tip with Some h -> h | None -> "null"));
  if best <> blk107b_hash then
    failwith (Printf.sprintf
      "FAIL: getbestblockhash = %s, expected new-chain tip %s" best blk107b_hash);

  (* 3. getblockhash(tip - 1) must be the NEW chain's block at that height,
        NOT the orphaned chain-A block. *)
  (match at_tip_minus1 with
   | Some h when h = blk106b_hash -> ()
   | Some h ->
     failwith (Printf.sprintf
       "FAIL: getblockhash(tip-1) = %s (stale/abandoned), expected new-chain \
        block %s" h blk106b_hash)
   | None ->
     failwith "FAIL: getblockhash(tip-1) = null after reorg");

  Rocksdb_store.close rocksdb;
  Storage.ChainDB.close db;
  cleanup ();
  Printf.printf
    "ALL POST-REORG RPC CHAIN-STATE CONSISTENCY CHECKS PASSED\n\
    \  (getbestblockhash == getblockhash(getblockcount) == new tip 107')\n"
