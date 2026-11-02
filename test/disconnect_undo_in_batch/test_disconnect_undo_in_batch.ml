(* A disconnect that fails before its commit must change nothing.

   Security audit 2026-10-31 H13.  [disconnect_to_target_via_utxo]
   (invalidateblock) and [disconnect_to_target] (DB-direct: invalidateblock
   without a threaded UTXO set, dumptxoutset rollback) walk the blocks to
   disconnect tip-first and commit the coin delta and the lower tip only at
   the end.  Two things happened before that commit:

   - each block's undo data was DELETED as soon as the block was rolled back
     in memory.  When a deeper block then failed (missing undo, a corrupt
     undo record) the call returned Error with the tip unchanged, but the
     blocks above the failure had lost their undo: they could never be
     disconnected again, so neither invalidateblock nor a reorg could ever
     move the tip below them.  A crash anywhere in the loop did the same.
   - [disconnect_to_target_via_utxo] rolled the LIVE dirty set back block by
     block.  On Error those mutations stayed, so the next flush persisted a
     partial rollback under the old tip: coins spent on the active chain
     restored, coins it created deleted.

   Core never erases undo in DisconnectTip, and InvalidateBlock's
   DisconnectTip works on a CCoinsViewCache child view that is flushed only
   when the block disconnected cleanly (validation.cpp DisconnectTip:
   "view.Flush()" after "DisconnectBlock(...) != DISCONNECT_OK" returns
   false).

     dune exec --no-buffer test/disconnect_undo_in_batch/test_disconnect_undo_in_batch.exe
*)

open Camlcoin

(* ======================================================================
   Fixture 1: dual DB (Rocksdb_store + ChainDB CF), blocks connected
   through the live UTXO primitive with no PoW (as
   test_disconnect_utxo_fresh.ml does).  Lets a block carry spends.
   ====================================================================== *)

let open_dual_db path =
  let db = Storage.ChainDB.create (Filename.concat path "chain") in
  let rdb = Rocksdb_store.open_db (Filename.concat path "rocksdb") in
  Storage.ChainDB.attach_rocksdb_utxo db rdb;
  db, rdb

let p2pkh tag =
  let s = Cstruct.create 25 in
  Cstruct.set_uint8 s 0 0x76; Cstruct.set_uint8 s 1 0xa9;
  Cstruct.set_uint8 s 2 0x14; Cstruct.set_uint8 s 3 tag;
  Cstruct.set_uint8 s 23 0x88; Cstruct.set_uint8 s 24 0xac;
  s

let make_header ~prev ~nonce : Types.block_header =
  { version = 1l; prev_block = prev; merkle_root = Types.zero_hash;
    timestamp = Int32.of_int (1700000000 + nonce);
    bits = 0x207fffffl; nonce = Int32.of_int nonce }

let coinbase_tx ~height ~tag : Types.transaction =
  { version = 1l;
    inputs = [{ previous_output = { txid = Types.zero_hash; vout = -1l };
                script_sig = Cstruct.of_string (Printf.sprintf "\x03h=%d" height);
                sequence = 0xffffffffl }];
    outputs = [{ value = 5_000_000_000L; script_pubkey = p2pkh tag }];
    witnesses = []; locktime = 0l }

let spend_tx ~prev_txid ~tag ~value : Types.transaction =
  { version = 1l;
    inputs = [{ previous_output = { txid = prev_txid; vout = 0l };
                script_sig = Cstruct.empty; sequence = 0xffffffffl }];
    outputs = [{ value; script_pubkey = p2pkh tag }];
    witnesses = []; locktime = 0l }

let p_txid =
  let b = Cstruct.create 32 in
  Cstruct.set_uint8 b 0 0x10; Cstruct.set_uint8 b 31 0x5a; b

type fixture = {
  db : Storage.ChainDB.t;
  rdb : Rocksdb_store.t;
  chain : Sync.chain_state;
  utxo : Utxo.OptimizedUtxoSet.t;
  genesis : Sync.header_entry;
}

let persist utxo ~hash ~height =
  Utxo.OptimizedUtxoSet.persist_dirty_atomic utxo
    ~tip_hash:hash ~tip_height:height
    ~header_tip_hash:hash ~header_tip_height:height

let with_fixture label f =
  Test_tmp.with_dir ~label ~mkdir:true (fun path ->
    let db, rdb = open_dual_db path in
    Fun.protect
      ~finally:(fun () ->
        (try Rocksdb_store.close rdb with _ -> ());
        (try Storage.ChainDB.close db with _ -> ()))
      (fun () ->
        let chain = Sync.create_chain_state db Consensus.regtest in
        let genesis = match chain.Sync.tip with
          | Some g -> g
          | None ->
            let gh = Consensus.regtest.genesis_header in
            let g : Sync.header_entry =
              { header = gh; hash = Crypto.compute_block_hash gh; height = 0;
                total_work = Cstruct.create 32 } in
            chain.Sync.tip <- Some g; g
        in
        let utxo =
          Utxo.OptimizedUtxoSet.create ~cache_size:1000 ~rocksdb:rdb db in
        (* A pre-state coin P, on disk before any block. *)
        Utxo.OptimizedUtxoSet.add utxo p_txid 0
          { value = 1_000_000_000L; script_pubkey = p2pkh 0x10; height = 0;
            is_coinbase = false };
        persist utxo ~hash:genesis.hash ~height:0;
        f { db; rdb; chain; utxo; genesis }))

let connect fx ~(parent : Sync.header_entry) ~nonce ~txs ~commit =
  let height = parent.height + 1 in
  let block : Types.block =
    { header = make_header ~prev:parent.hash ~nonce; transactions = txs } in
  let hash = Crypto.compute_block_hash block.header in
  let undo =
    match Utxo.connect_block_optimized fx.utxo block height with
    | Ok u -> u
    | Error e -> Alcotest.failf "connect_block_optimized h=%d: %s" height e
  in
  Storage.ChainDB.store_block fx.db hash block;
  Storage.ChainDB.set_height_hash fx.db height hash;
  let uw = Serialize.writer_create () in
  Utxo.serialize_undo_data uw undo;
  Storage.ChainDB.store_undo_data fx.db hash (Serialize.writer_to_string uw);
  let e : Sync.header_entry =
    { header = block.header; hash; height; total_work = Cstruct.create 32 } in
  Hashtbl.replace fx.chain.Sync.headers (Cstruct.to_string hash) e;
  fx.chain.Sync.tip <- Some e;
  fx.chain.Sync.blocks_synced <- height;
  if commit then persist fx.utxo ~hash ~height;
  e

(* The coin set the node validates against: on-disk store + dirty overlay. *)
let committed_view utxo =
  let acc = ref [] in
  Utxo.OptimizedUtxoSet.iter_committed utxo (fun t v data ->
    acc := (Storage.ChainDB.rocksdb_utxo_key t v, data) :: !acc);
  List.rev !acc

let cf_snapshot db =
  let acc = ref [] in
  Storage.ChainDB.iter_utxos db (fun t v data ->
    acc := (Storage.ChainDB.rocksdb_utxo_key t v, data) :: !acc);
  List.rev !acc

let rdb_snapshot rdb =
  let acc = ref [] in
  Rocksdb_store.iter_utxos rdb (fun t v data ->
    acc := (Storage.ChainDB.rocksdb_utxo_key t v, data) :: !acc);
  List.rev !acc

let has_undo db (e : Sync.header_entry) =
  Storage.ChainDB.get_undo_data db e.hash <> None

let coins = Alcotest.(list (pair string string))

let tip_height (st : Sync.chain_state) =
  match st.Sync.tip with Some t -> t.height | None -> -1

(* Three blocks on top of P:
     b1: cb1, A spends P -> X        (committed)
     b2: cb2, B spends X -> Y        (NOT committed: pending in the dirty set)
     b3: cb3                         (NOT committed)
   so disconnecting b2 has to restore X (a Disc_put) and delete Y and cb2
   (Disc_dels) in the live dirty set. *)
let three_blocks fx =
  let txa = spend_tx ~prev_txid:p_txid ~tag:0xa1 ~value:900_000_000L in
  let x_id = Crypto.compute_txid txa in
  let txb = spend_tx ~prev_txid:x_id ~tag:0xb1 ~value:800_000_000L in
  let y_id = Crypto.compute_txid txb in
  let b1 = connect fx ~parent:fx.genesis ~nonce:1
      ~txs:[coinbase_tx ~height:1 ~tag:0xc1; txa] ~commit:true in
  let b2 = connect fx ~parent:b1 ~nonce:2
      ~txs:[coinbase_tx ~height:2 ~tag:0xc2; txb] ~commit:false in
  let b3 = connect fx ~parent:b2 ~nonce:3
      ~txs:[coinbase_tx ~height:3 ~tag:0xc3] ~commit:false in
  b1, b2, b3, x_id, y_id

(* Fault: the deepest block to disconnect has no undo data, so the loop
   rolls b3 and b2 back in memory and then fails on b1. *)
let take_undo db (e : Sync.header_entry) =
  match Storage.ChainDB.get_undo_data db e.hash with
  | None -> Alcotest.fail "fixture: block has no undo data"
  | Some u -> Storage.ChainDB.delete_undo_data db e.hash; u

(* invalidateblock primitive (live UTXO set). *)
let test_via_utxo_error_changes_nothing () =
  with_fixture "h13_via_utxo" (fun fx ->
    let b1, b2, b3, x_id, y_id = three_blocks fx in
    let view_before = committed_view fx.utxo in
    let saved = take_undo fx.db b1 in
    (match Sync.disconnect_to_target_via_utxo fx.chain fx.utxo fx.genesis with
     | Ok () -> Alcotest.fail "disconnect must fail: b1 has no undo"
     | Error _ -> ());
    Alcotest.(check int) "tip unchanged" 3 (tip_height fx.chain);
    Alcotest.(check bool) "b3 undo kept" true (has_undo fx.db b3);
    Alcotest.(check bool) "b2 undo kept" true (has_undo fx.db b2);
    Alcotest.(check bool) "X still spent (b2 still connected)" true
      (Utxo.OptimizedUtxoSet.get fx.utxo x_id 0 = None);
    Alcotest.(check bool) "Y still unspent" true
      (Utxo.OptimizedUtxoSet.get fx.utxo y_id 0 <> None);
    Alcotest.check coins "live coin view == pre-call view" view_before
      (committed_view fx.utxo);
    (* The next flush must persist the tip-3 coin set, not a partial
       rollback. *)
    persist fx.utxo ~hash:b3.hash ~height:3;
    Alcotest.check coins "flushed Rocksdb_store == pre-call view"
      view_before (rdb_snapshot fx.rdb);
    Alcotest.check coins "flushed CF == pre-call view" view_before
      (cf_snapshot fx.db);
    (* With the undo back, the same disconnect goes all the way down. *)
    Storage.ChainDB.store_undo_data fx.db b1.hash saved;
    (match Sync.disconnect_to_target_via_utxo fx.chain fx.utxo fx.genesis with
     | Ok () -> ()
     | Error e -> Alcotest.failf "disconnect after repair: %s" e);
    Alcotest.(check int) "tip at genesis" 0 (tip_height fx.chain);
    Alcotest.(check bool) "P restored" true
      (Utxo.OptimizedUtxoSet.get fx.utxo p_txid 0 <> None);
    Alcotest.(check int) "only P left (view)" 1
      (List.length (committed_view fx.utxo));
    Alcotest.(check int) "only P left (Rocksdb_store)" 1
      (List.length (rdb_snapshot fx.rdb)))

(* A partial rollback must not survive in the dirty set even when the
   blocks it rolled back were already flushed (no pending entries). *)
let test_via_utxo_error_committed_blocks () =
  with_fixture "h13_via_utxo_flushed" (fun fx ->
    let b1, b2, b3, _, _ = three_blocks fx in
    persist fx.utxo ~hash:b3.hash ~height:3;
    let disk_before = rdb_snapshot fx.rdb in
    let _ = take_undo fx.db b1 in
    (match Sync.disconnect_to_target_via_utxo fx.chain fx.utxo fx.genesis with
     | Ok () -> Alcotest.fail "disconnect must fail: b1 has no undo"
     | Error _ -> ());
    Alcotest.(check bool) "b3 undo kept" true (has_undo fx.db b3);
    Alcotest.(check bool) "b2 undo kept" true (has_undo fx.db b2);
    Alcotest.(check int) "no dirty entries left behind" 0
      (Utxo.OptimizedUtxoSet.dirty_count fx.utxo);
    persist fx.utxo ~hash:b3.hash ~height:3;
    Alcotest.check coins "Rocksdb_store unchanged" disk_before
      (rdb_snapshot fx.rdb))

(* DB-direct primitive (invalidateblock without a UTXO set, dumptxoutset
   rollback). *)
let test_db_direct_error_keeps_undo () =
  with_fixture "h13_db_direct" (fun fx ->
    let b1, b2, b3, _, _ = three_blocks fx in
    persist fx.utxo ~hash:b3.hash ~height:3;
    let cf_before = cf_snapshot fx.db in
    let saved = take_undo fx.db b1 in
    (match Sync.disconnect_to_target fx.chain fx.genesis with
     | Ok () -> Alcotest.fail "disconnect must fail: b1 has no undo"
     | Error _ -> ());
    Alcotest.(check int) "tip unchanged" 3 (tip_height fx.chain);
    Alcotest.(check bool) "b3 undo kept" true (has_undo fx.db b3);
    Alcotest.(check bool) "b2 undo kept" true (has_undo fx.db b2);
    Alcotest.check coins "CF unchanged" cf_before (cf_snapshot fx.db);
    Storage.ChainDB.store_undo_data fx.db b1.hash saved;
    (match Sync.disconnect_to_target fx.chain fx.genesis with
     | Ok () -> ()
     | Error e -> Alcotest.failf "disconnect after repair: %s" e);
    Alcotest.(check int) "tip at genesis" 0 (tip_height fx.chain);
    Alcotest.(check int) "CF: only P left" 1 (List.length (cf_snapshot fx.db)))

(* CONTROL (passes before and after): a clean disconnect still drops the
   undo of the blocks it disconnected, in the same commit. *)
let test_control_success_drops_undo () =
  with_fixture "h13_control" (fun fx ->
    let b1, b2, b3, _, _ = three_blocks fx in
    (match Sync.disconnect_to_target_via_utxo fx.chain fx.utxo b1 with
     | Ok () -> ()
     | Error e -> Alcotest.failf "disconnect: %s" e);
    Alcotest.(check int) "tip at b1" 1 (tip_height fx.chain);
    Alcotest.(check bool) "b3 undo dropped" false (has_undo fx.db b3);
    Alcotest.(check bool) "b2 undo dropped" false (has_undo fx.db b2);
    Alcotest.(check bool) "b1 undo kept" true (has_undo fx.db b1))

(* ======================================================================
   Fixture 2: the RPC-level path.  Real PoW blocks through
   Mining.submit_block, then Sync.invalidate_block / reconsider_block.
   ====================================================================== *)

let op_true = Cstruct.of_string "\x51"

let remine (block : Types.block) : Types.block =
  let h = ref block.Types.header in
  let n = ref 0l in
  let found = ref false in
  while (not !found) && Int32.compare !n 5_000_000l < 0 do
    h := { !h with Types.nonce = !n };
    if Consensus.hash_meets_target (Crypto.compute_block_hash !h) !h.Types.bits
    then found := true
    else n := Int32.add !n 1l
  done;
  if not !found then failwith "remine: no nonce found";
  { block with Types.header = !h }

let make_block ~prev_hash ~prev_time ~height : Types.block =
  let extra_nonce = Cstruct.create 8 in
  Cstruct.LE.set_uint64 extra_nonce 0 (Int64.of_int height);
  let mk wr =
    Mining.create_coinbase ~height ~total_fee:0L ~payout_script:op_true
      ~extra_nonce ~witness_root:wr ~network_type:Consensus.Regtest ()
  in
  let wr = Mining.compute_witness_merkle_root [mk None] in
  let coinbase = mk (Some wr) in
  let merkle_root, _ = Crypto.merkle_root [Crypto.compute_txid coinbase] in
  remine { Types.header = { version = 4l; prev_block = prev_hash; merkle_root;
                            timestamp = Int32.add prev_time 600l;
                            bits = Consensus.regtest.pow_limit; nonce = 0l };
           transactions = [coinbase] }

let hash_of (b : Types.block) = Crypto.compute_block_hash b.Types.header

let chain5 () =
  let g = Consensus.regtest.Consensus.genesis_header in
  let rec go acc prev_hash prev_time h =
    if h > 5 then List.rev acc
    else
      let b = make_block ~prev_hash ~prev_time ~height:h in
      go (b :: acc) (hash_of b) b.Types.header.Types.timestamp (h + 1)
  in
  go [] Consensus.regtest.Consensus.genesis_hash g.Types.timestamp 1

let test_invalidate_reconsider_after_failed_invalidate () =
  let blocks = chain5 () in
  let nth i = List.nth blocks (i - 1) in
  Test_tmp.with_dir ~label:"h13_rpc" ~mkdir:true (fun path ->
    let db = Storage.ChainDB.create path in
    Fun.protect ~finally:(fun () -> try Storage.ChainDB.close db with _ -> ())
      (fun () ->
        let state = Sync.create_chain_state db Consensus.regtest in
        state.Sync.sync_state <- Sync.FullySynced;
        let utxo = Utxo.OptimizedUtxoSet.create ~cache_size:10_000 db in
        Sync.shared_utxo_set := Some utxo;
        Fun.protect ~finally:(fun () -> Sync.shared_utxo_set := None)
          (fun () ->
            let mp = Mempool.create ~network:Consensus.regtest
                ~require_standard:false ~verify_scripts:false
                ~utxo:(Utxo.UtxoSet.create db) ~current_height:0 () in
            List.iter (fun b ->
              match Mining.submit_block ~utxo ~network_type:Consensus.Regtest
                      b state mp with
              | Ok () -> ()
              | Error e -> Alcotest.failf "submitblock: %s" e) blocks;
            let tip () = match Sync.block_tip state with
              | Some e -> e.height | None -> -1 in
            let undo_of i =
              Storage.ChainDB.get_undo_data db (hash_of (nth i)) in
            Alcotest.(check int) "tip 5" 5 (tip ());
            List.iter (fun i ->
              Alcotest.(check bool) (Printf.sprintf "fixture: undo %d" i)
                true (undo_of i <> None)) [2; 3; 4; 5];
            let view_before = committed_view utxo in
            let saved = Option.get (undo_of 2) in
            Storage.ChainDB.delete_undo_data db (hash_of (nth 2));
            (* invalidateblock 2 fails on block 2's missing undo. *)
            (match Sync.invalidate_block state ~utxo_set:utxo
                     (hash_of (nth 2)) with
             | Ok h -> Alcotest.failf "invalidateblock 2 succeeded (tip %d)" h
             | Error _ -> ());
            Alcotest.(check int) "tip still 5" 5 (tip ());
            List.iter (fun i ->
              Alcotest.(check bool) (Printf.sprintf "undo %d kept" i)
                true (undo_of i <> None)) [3; 4; 5];
            Alcotest.check coins "coin view unchanged" view_before
              (committed_view utxo);
            (match Sync.reconsider_block state ~utxo_set:utxo
                     (hash_of (nth 2)) with
             | Ok _ -> ()
             | Error e -> Alcotest.failf "reconsiderblock 2: %s" e);
            Alcotest.(check int) "tip 5 after reconsider" 5 (tip ());
            (* Block 2's undo restored: a shallower invalidate must still
               be able to disconnect 5, 4 and 3. *)
            Storage.ChainDB.store_undo_data db (hash_of (nth 2)) saved;
            (match Sync.invalidate_block state ~utxo_set:utxo
                     (hash_of (nth 3)) with
             | Ok h -> Alcotest.(check int) "invalidateblock 3 -> tip 2" 2 h
             | Error e -> Alcotest.failf "invalidateblock 3: %s" e);
            (match Sync.reconsider_block state ~utxo_set:utxo
                     (hash_of (nth 3)) with
             | Ok _ -> ()
             | Error e -> Alcotest.failf "reconsiderblock 3: %s" e);
            Alcotest.(check int) "tip 5 again" 5 (tip ());
            Alcotest.check coins "coin view back to the original"
              view_before (committed_view utxo))))

let () =
  Alcotest.run "disconnect_undo_in_batch" [
    "disconnect", [
      Alcotest.test_case "via_utxo: failed disconnect changes nothing" `Quick
        test_via_utxo_error_changes_nothing;
      Alcotest.test_case "via_utxo: failed disconnect over flushed blocks"
        `Quick test_via_utxo_error_committed_blocks;
      Alcotest.test_case "db-direct: failed disconnect keeps undo" `Quick
        test_db_direct_error_keeps_undo;
      Alcotest.test_case "control: clean disconnect drops undo" `Quick
        test_control_success_drops_undo;
    ];
    "rpc", [
      Alcotest.test_case "invalidate/reconsider after a failed invalidate"
        `Quick test_invalidate_reconsider_after_failed_invalidate;
    ];
  ]
