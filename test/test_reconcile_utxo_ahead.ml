(* Regression tests for the apply_block_atomic crash-window wedge fix.

   BUG (live mainnet camlcoin wedge at 952223/952224, queue=408):
   [apply_block_atomic] (storage.ml:665-697) commits the RocksDB UTXO batch
   FIRST and the cf_chainstate chain_tip SECOND, so a crash in that window
   leaves the persisted UTXO set AHEAD of chain_tip [rdb_tip = N, chain_tip = M]
   with N > M.  The OLD boot check (cli.ml) treated rdb_tip > chain_tip as SAFE
   and only LOGGED, trusting a "forward re-apply is idempotent" claim
   (storage.ml:638-641) that is FALSE for cross-block spends: re-applying block
   M+1 reads the UTXO set (validation.ml:1136-1182) and raises TxMissingInputs
   because a prevout was already deleted by an already-committed later block in
   the window -> block rejected -> re-downloaded forever -> permanent wedge.

   FIX (PART A): the rdb_tip > chain_tip boot branch RECONCILES the UTXO set
   DOWN to chain_tip via [Sync.reconcile_rdb_to_chain_tip], mirroring Bitcoin
   Core's [Chainstate::ReplayBlocks] / [RollbackBlock] (validation.cpp:4773-4858)
   which rolls the coins DB back along the over-applied branch using stored
   undo data, then rolls forward.  If undo data for any window block is missing,
   reconcile returns Error and the caller falls back to a full resync.

   These tests pin down [reconcile_rdb_to_chain_tip]:

     1. cross_block_spend_reconciled  — window block 2 spends an output created
        by block 1 (the EXACT bug shape).  Pre-reconcile the spent prevout is
        gone from RDB (the missing-inputs trigger); reconcile to chain_tip
        RESTORES the spent prevout, REMOVES the window-created output, and
        lowers rdb_tip to chain_tip.  A subsequent UTXO lookup of the prevout
        SUCCEEDS, so the re-apply of block 2 will not hit TxMissingInputs.

     2. missing_undo_falls_back       — same window but the window block has NO
        undo data on disk (the post-IBD connect paths do not persist undo);
        reconcile returns Error so the caller can full-resync instead of
        spinning in the infinite missing-inputs loop.

     3. multi_block_window_reconciled — a two-block crash window
        [chain_tip=1, rdb_tip=3] with a cross-block spend chain; reconcile
        unwinds both window blocks back to chain_tip. *)

open Camlcoin

let test_root = "/tmp/camlcoin_test_reconcile_utxo_ahead"

let cleanup () =
  let rec rm_rf path =
    if Sys.file_exists path then begin
      if Sys.is_directory path then begin
        Array.iter (fun f -> rm_rf (Filename.concat path f)) (Sys.readdir path);
        Unix.rmdir path
      end else Unix.unlink path
    end
  in
  rm_rf test_root

(* Open the dual-DB layout the way [Cli.run] does. *)
let open_dual_db () =
  Unix.mkdir test_root 0o755;
  let db = Storage.ChainDB.create (Filename.concat test_root "chain") in
  let rdb = Rocksdb_store.open_db (Filename.concat test_root "rocksdb") in
  Storage.ChainDB.attach_rocksdb_utxo db rdb;
  db, rdb

let close_dual_db db rdb =
  Rocksdb_store.close rdb;
  Storage.ChainDB.close db

let p2pkh_script tag =
  Cstruct.of_string
    (Printf.sprintf "\x76\xa9\x14%c%c%c\x04\x05\x06\x07\x08\x09\x0a\
                     \x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x88\xac"
       (Char.chr (tag land 0xff))
       (Char.chr ((tag lsr 8) land 0xff))
       (Char.chr ((tag lsr 16) land 0xff)))

let make_header ~height ~nonce =
  Types.{
    version = 1l;
    prev_block = Types.zero_hash;
    merkle_root = Types.zero_hash;
    timestamp = Int32.of_int (1700000000 + height);
    bits = 0x207fffffl;
    nonce = Int32.of_int nonce;
  }

(* A coinbase tx with one spendable output (tag picks a distinct script). *)
let coinbase_tx ~height ~tag ~value =
  let cb_in : Types.tx_in = {
    previous_output = { txid = Types.zero_hash; vout = -1l };
    script_sig = Cstruct.of_string (Printf.sprintf "\x03h=%d" height);
    sequence = 0xffffffffl;
  } in
  let cb_out : Types.tx_out = { value; script_pubkey = p2pkh_script tag } in
  ({ version = 1l; inputs = [cb_in]; outputs = [cb_out];
     witnesses = []; locktime = 0l } : Types.transaction)

(* A non-coinbase tx that spends (prev_txid, 0) and creates one output. *)
let spend_tx ~prev_txid ~tag ~value =
  let inp : Types.tx_in = {
    previous_output = { txid = prev_txid; vout = 0l };
    script_sig = Cstruct.empty;
    sequence = 0xffffffffl;
  } in
  let out : Types.tx_out = { value; script_pubkey = p2pkh_script tag } in
  ({ version = 1l; inputs = [inp]; outputs = [out];
     witnesses = []; locktime = 0l } : Types.transaction)

let utxo_bytes ~value ~script_pubkey ~height ~is_coinbase =
  Sync.encode_utxo value script_pubkey height is_coinbase

(* Apply a block to BOTH backends atomically (the happy path), advancing
   both rdb_tip and chain_tip. Mirrors apply_block_atomic's ops shape, and
   ALSO stores undo data the way the IBD connect path does so reconcile has
   something to roll back. [spent] is the list of (outpoint, utxo_entry) the
   non-coinbase txs spend, grouped per tx; pass [] for a coinbase-only block. *)
let apply_block_both db ~block ~height ~spent =
  let hash = Crypto.compute_block_hash block.Types.header in
  Storage.ChainDB.store_block db hash block;
  Storage.ChainDB.set_height_hash db height hash;
  (* Build undo data (one tx_undo per non-coinbase tx). *)
  let n_txs = List.length block.Types.transactions in
  let tx_undos = List.mapi (fun i s ->
    ignore i;
    Utxo.{ spent_outputs = s }
  ) spent in
  ignore n_txs;
  let undo : Utxo.undo_data = { height; tx_undos } in
  let uw = Serialize.writer_create () in
  Utxo.serialize_undo_data uw undo;
  Storage.ChainDB.store_undo_data db hash
    (Cstruct.to_string (Serialize.writer_to_cstruct uw));
  (* Build UTXO ops: delete spent prevouts, add created outputs. *)
  let ops = ref [] in
  List.iteri (fun tx_idx (tx : Types.transaction) ->
    let txid = Crypto.compute_txid tx in
    let is_cb = (tx_idx = 0) in
    if not is_cb then
      List.iter (fun (inp : Types.tx_in) ->
        ops := (inp.previous_output.txid,
                Int32.to_int inp.previous_output.vout, `Del) :: !ops
      ) tx.inputs;
    List.iteri (fun vout (out : Types.tx_out) ->
      if not (Utxo.is_unspendable_script out.script_pubkey) then
        let data = utxo_bytes ~value:out.value
          ~script_pubkey:out.script_pubkey ~height ~is_coinbase:is_cb in
        ops := (txid, vout, `Add data) :: !ops
    ) tx.outputs
  ) block.transactions;
  Storage.ChainDB.apply_block_atomic db
    ~tip_hash:hash ~tip_height:height
    ~header_tip_hash:hash ~header_tip_height:height
    (List.rev !ops);
  hash

(* Apply a block to RDB ONLY (the crash window): RDB UTXO mutations + rdb_tip
   advance, but chain_tip (CF) stays where it is. We DO store the block body,
   the height->hash map, and (optionally) the undo data — exactly what the IBD
   connect path persists before apply_block_atomic. *)
let apply_block_rdb_only db rdb ~block ~height ~spent ~write_undo =
  let hash = Crypto.compute_block_hash block.Types.header in
  Storage.ChainDB.store_block db hash block;
  Storage.ChainDB.set_height_hash db height hash;
  if write_undo then begin
    let tx_undos = List.map (fun s -> Utxo.{ spent_outputs = s }) spent in
    let undo : Utxo.undo_data = { height; tx_undos } in
    let uw = Serialize.writer_create () in
    Utxo.serialize_undo_data uw undo;
    Storage.ChainDB.store_undo_data db hash
      (Cstruct.to_string (Serialize.writer_to_cstruct uw))
  end;
  let rdb_ops = ref [] in
  List.iteri (fun tx_idx (tx : Types.transaction) ->
    let txid = Crypto.compute_txid tx in
    let is_cb = (tx_idx = 0) in
    if not is_cb then
      List.iter (fun (inp : Types.tx_in) ->
        let k = Storage.ChainDB.rocksdb_utxo_key
          inp.previous_output.txid (Int32.to_int inp.previous_output.vout) in
        rdb_ops := (k, None) :: !rdb_ops
      ) tx.inputs;
    List.iteri (fun vout (out : Types.tx_out) ->
      if not (Utxo.is_unspendable_script out.script_pubkey) then begin
        let data = utxo_bytes ~value:out.value
          ~script_pubkey:out.script_pubkey ~height ~is_coinbase:is_cb in
        let k = Storage.ChainDB.rocksdb_utxo_key txid vout in
        rdb_ops := (k, Some data) :: !rdb_ops
      end
    ) tx.outputs
  ) block.transactions;
  Rocksdb_store.batch_write ~tip_height:height rdb (List.rev !rdb_ops);
  hash

let rdb_has db rdb ~txid ~vout =
  let k = Storage.ChainDB.rocksdb_utxo_key txid vout in
  ignore db;
  Option.is_some (Rocksdb_store.get rdb k)

(* ----------------------------------------------------------------------
   Test 1 — Cross-block spend: the exact wedge shape.
   ---------------------------------------------------------------------- *)
let test_cross_block_spend_reconciled () =
  cleanup ();
  let db, rdb = open_dual_db () in
  let chain = Sync.create_chain_state db Consensus.regtest in

  (* Block 1: coinbase creates output X (the prevout block 2 will spend).
     Apply to BOTH backends -> chain_tip = rdb_tip = 1. *)
  let cb1 = coinbase_tx ~height:1 ~tag:0x11 ~value:5000000000L in
  let x_txid = Crypto.compute_txid cb1 in
  let x_script = p2pkh_script 0x11 in
  let blk1 : Types.block = { header = make_header ~height:1 ~nonce:1;
                             transactions = [cb1] } in
  let _ = apply_block_both db ~block:blk1 ~height:1 ~spent:[] in

  Alcotest.(check int) "chain_tip == 1 after block 1"
    1 (match Storage.ChainDB.get_chain_tip db with Some (_, h) -> h | None -> -1);
  Alcotest.(check bool) "X present in RDB after block 1"
    true (rdb_has db rdb ~txid:x_txid ~vout:0);

  (* Block 2 (CRASH WINDOW): coinbase + a tx that spends X (deleting it) and
     creates output Y.  Apply to RDB ONLY, advancing rdb_tip to 2 while
     chain_tip stays at 1.  Undo data records X's value/script so reconcile
     can restore it. *)
  let cb2 = coinbase_tx ~height:2 ~tag:0x22 ~value:5000000000L in
  let spend = spend_tx ~prev_txid:x_txid ~tag:0x23 ~value:4000000000L in
  let y_txid = Crypto.compute_txid spend in
  let x_entry = Utxo.{ value = 5000000000L; script_pubkey = x_script;
                       height = 1; is_coinbase = true } in
  let blk2 : Types.block = { header = make_header ~height:2 ~nonce:2;
                             transactions = [cb2; spend] } in
  (* spent grouped per non-coinbase tx: one tx, spending X. *)
  let _ = apply_block_rdb_only db rdb ~block:blk2 ~height:2
            ~spent:[[ ({ txid = x_txid; vout = 0l } : Types.outpoint), x_entry ]]
            ~write_undo:true in

  (* The crash window is now realised. *)
  Alcotest.(check int) "rdb_tip advanced to 2 (crash window)"
    2 (match Rocksdb_store.get_tip_height rdb with Some h -> h | None -> -1);
  Alcotest.(check int) "chain_tip still 1 (CF not committed)"
    1 (match Storage.ChainDB.get_chain_tip db with Some (_, h) -> h | None -> -1);
  (* THE BUG: X (the prevout for the block-2 spend) is already gone from RDB,
     even though chain_tip is still 1 — re-applying block 2 would read X,
     get None, and raise TxMissingInputs (the infinite-redownload wedge). *)
  Alcotest.(check bool) "X DELETED from RDB by the window block (the wedge)"
    false (rdb_has db rdb ~txid:x_txid ~vout:0);
  Alcotest.(check bool) "Y present in RDB (window-created)"
    true (rdb_has db rdb ~txid:y_txid ~vout:0);

  (* THE FIX: reconcile the UTXO set DOWN to chain_tip = 1. *)
  chain.Sync.blocks_synced <- 1;
  (match Sync.reconcile_rdb_to_chain_tip chain rdb
           ~rdb_height:2 ~target_height:1 with
   | Ok () -> ()
   | Error msg -> Alcotest.failf "reconcile returned Error: %s" msg);

  (* Post-reconcile invariants:
       - rdb_tip lowered to chain_tip,
       - X RESTORED (so re-apply of block 2 will NOT hit TxMissingInputs),
       - Y REMOVED (window-created output undone). *)
  Alcotest.(check int) "rdb_tip lowered to chain_tip (1)"
    1 (match Rocksdb_store.get_tip_height rdb with Some h -> h | None -> -1);
  Alcotest.(check bool) "X RESTORED in RDB after reconcile (no missing-inputs)"
    true (rdb_has db rdb ~txid:x_txid ~vout:0);
  Alcotest.(check bool) "Y REMOVED from RDB after reconcile"
    false (rdb_has db rdb ~txid:y_txid ~vout:0);
  (* The restored X must carry its original value/script so validation passes. *)
  let restored =
    let k = Storage.ChainDB.rocksdb_utxo_key x_txid 0 in
    match Rocksdb_store.get rdb k with
    | None -> None
    | Some data ->
      let r = Serialize.reader_of_cstruct (Cstruct.of_string data) in
      Some (Utxo.deserialize_utxo_entry r)
  in
  (match restored with
   | Some e ->
     Alcotest.(check int64) "restored X value" 5000000000L e.Utxo.value;
     Alcotest.(check bool) "restored X is_coinbase" true e.Utxo.is_coinbase
   | None -> Alcotest.fail "X not restored");

  close_dual_db db rdb; cleanup ()

(* ----------------------------------------------------------------------
   Test 2 — Missing undo data: reconcile must fail so the caller can
   fall back to a full resync (not spin in the missing-inputs loop).
   ---------------------------------------------------------------------- *)
let test_missing_undo_falls_back () =
  cleanup ();
  let db, rdb = open_dual_db () in
  let chain = Sync.create_chain_state db Consensus.regtest in

  let cb1 = coinbase_tx ~height:1 ~tag:0x11 ~value:5000000000L in
  let x_txid = Crypto.compute_txid cb1 in
  let blk1 : Types.block = { header = make_header ~height:1 ~nonce:1;
                             transactions = [cb1] } in
  let _ = apply_block_both db ~block:blk1 ~height:1 ~spent:[] in

  let cb2 = coinbase_tx ~height:2 ~tag:0x22 ~value:5000000000L in
  let spend = spend_tx ~prev_txid:x_txid ~tag:0x23 ~value:4000000000L in
  let blk2 : Types.block = { header = make_header ~height:2 ~nonce:2;
                             transactions = [cb2; spend] } in
  (* write_undo:false — the post-IBD connect path does NOT persist undo. *)
  let _ = apply_block_rdb_only db rdb ~block:blk2 ~height:2
            ~spent:[] ~write_undo:false in

  chain.Sync.blocks_synced <- 1;
  (match Sync.reconcile_rdb_to_chain_tip chain rdb
           ~rdb_height:2 ~target_height:1 with
   | Ok () ->
     Alcotest.fail "reconcile should have FAILED (no undo data) so the \
                    caller falls back to a full resync"
   | Error _ -> ());

  close_dual_db db rdb; cleanup ()

(* ----------------------------------------------------------------------
   Test 3 — Multi-block crash window: chain_tip=1, rdb_tip=3, a spend
   chain across blocks 2 and 3. Reconcile must unwind both.
   ---------------------------------------------------------------------- *)
let test_multi_block_window_reconciled () =
  cleanup ();
  let db, rdb = open_dual_db () in
  let chain = Sync.create_chain_state db Consensus.regtest in

  (* Block 1: coinbase X. Both backends. *)
  let cb1 = coinbase_tx ~height:1 ~tag:0x11 ~value:5000000000L in
  let x_txid = Crypto.compute_txid cb1 in
  let x_script = p2pkh_script 0x11 in
  let blk1 : Types.block = { header = make_header ~height:1 ~nonce:1;
                             transactions = [cb1] } in
  let _ = apply_block_both db ~block:blk1 ~height:1 ~spent:[] in
  let x_entry = Utxo.{ value = 5000000000L; script_pubkey = x_script;
                       height = 1; is_coinbase = true } in

  (* Block 2 (window): coinbase + spend of X -> creates Y. RDB only -> tip 2. *)
  let cb2 = coinbase_tx ~height:2 ~tag:0x22 ~value:5000000000L in
  let spend2 = spend_tx ~prev_txid:x_txid ~tag:0x23 ~value:4000000000L in
  let y_txid = Crypto.compute_txid spend2 in
  let y_script = p2pkh_script 0x23 in
  let blk2 : Types.block = { header = make_header ~height:2 ~nonce:2;
                             transactions = [cb2; spend2] } in
  let _ = apply_block_rdb_only db rdb ~block:blk2 ~height:2
            ~spent:[[ ({ txid = x_txid; vout = 0l } : Types.outpoint), x_entry ]]
            ~write_undo:true in
  let y_entry = Utxo.{ value = 4000000000L; script_pubkey = y_script;
                       height = 2; is_coinbase = false } in

  (* Block 3 (window): coinbase + spend of Y -> creates Z. RDB only -> tip 3. *)
  let cb3 = coinbase_tx ~height:3 ~tag:0x33 ~value:5000000000L in
  let spend3 = spend_tx ~prev_txid:y_txid ~tag:0x34 ~value:3000000000L in
  let z_txid = Crypto.compute_txid spend3 in
  let blk3 : Types.block = { header = make_header ~height:3 ~nonce:3;
                             transactions = [cb3; spend3] } in
  let _ = apply_block_rdb_only db rdb ~block:blk3 ~height:3
            ~spent:[[ ({ txid = y_txid; vout = 0l } : Types.outpoint), y_entry ]]
            ~write_undo:true in

  Alcotest.(check int) "rdb_tip == 3 (two-block window)"
    3 (match Rocksdb_store.get_tip_height rdb with Some h -> h | None -> -1);
  Alcotest.(check bool) "X gone (spent by block 2)"
    false (rdb_has db rdb ~txid:x_txid ~vout:0);
  Alcotest.(check bool) "Y gone (spent by block 3)"
    false (rdb_has db rdb ~txid:y_txid ~vout:0);
  Alcotest.(check bool) "Z present (created by block 3)"
    true (rdb_has db rdb ~txid:z_txid ~vout:0);

  chain.Sync.blocks_synced <- 1;
  (match Sync.reconcile_rdb_to_chain_tip chain rdb
           ~rdb_height:3 ~target_height:1 with
   | Ok () -> ()
   | Error msg -> Alcotest.failf "multi-block reconcile Error: %s" msg);

  Alcotest.(check int) "rdb_tip lowered to 1"
    1 (match Rocksdb_store.get_tip_height rdb with Some h -> h | None -> -1);
  Alcotest.(check bool) "X RESTORED (chain_tip=1 base output present)"
    true (rdb_has db rdb ~txid:x_txid ~vout:0);
  Alcotest.(check bool) "Y REMOVED (window block-2 output undone)"
    false (rdb_has db rdb ~txid:y_txid ~vout:0);
  Alcotest.(check bool) "Z REMOVED (window block-3 output undone)"
    false (rdb_has db rdb ~txid:z_txid ~vout:0);

  close_dual_db db rdb; cleanup ()

let () =
  cleanup ();
  let open Alcotest in
  run "Reconcile_utxo_ahead" [
    "reconcile_rdb_to_chain_tip", [
      test_case "cross-block spend window reconciles to chain_tip" `Quick
        test_cross_block_spend_reconciled;
      test_case "missing undo data -> Error (full-resync fallback)" `Quick
        test_missing_undo_falls_back;
      test_case "multi-block window unwinds both blocks" `Quick
        test_multi_block_window_reconciled;
    ];
  ]
