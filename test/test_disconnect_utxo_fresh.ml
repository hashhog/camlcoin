(* Disconnect-path UTXO correctness: two bugs that each leave a SPENT coin in
   the durable UTXO set.

   BUG 1 — FRESH over DIRTY (Core coins.cpp CCoinsViewCache::AddCoin).
   [OptimizedUtxoSet.add] always recorded [`Added] ("never on disk"), even
   over a pending [`Removed] (a delete not yet flushed: the coin is STILL on
   disk) or over a clean cached coin.  [remove_fast] treats [`Added] as
   never-on-disk and drops the entry, so the pending delete was lost:

     coin C on disk -> spent (unflushed `Removed) -> re-added (undo restore)
       -> removed again via remove_fast -> flush/persist
       => C survives in BOTH Rocksdb_store and the ChainDB utxo CF.

   The invalidateblock path hits it directly: disconnecting block 2 restores
   X (which block 2 spent, unflushed) and disconnecting block 1 then removes
   X (which block 1 created) through remove_fast.

   BUG 2 — disconnect order (Core validation.cpp DisconnectBlock).
   The disconnect loops removed ALL of a block's outputs first and then
   restored ALL undo prevouts.  camlcoin's undo carries one entry per input,
   including inputs that spend an output created EARLIER IN THE SAME BLOCK,
   so a block with tx2 spending tx1:0 resurrected tx1:0 on disconnect.  Core
   walks txs in REVERSE: for each tx remove its outputs, then restore its own
   inputs — the later restore of tx1:0 is then undone by tx1's own removal.
   Three loops had the shape: [disconnect_to_target_via_utxo]
   (invalidateblock), [disconnect_to_target] (DB-direct, dumptxoutset
   rollback) and [reconcile_rdb_to_chain_tip] (boot crash-window repair).

   Command (from _build/default/test):
     ./test_disconnect_utxo_fresh.exe
*)

open Camlcoin

(* One directory per test case: an assertion failure skips [close_dual_db],
   and a leaked open RocksDB would otherwise poison every later case. *)
let root_base = "/tmp/camlcoin_test_disconnect_utxo_fresh"
let case_n = ref 0
let test_root_ref = ref root_base
let next_root () =
  incr case_n;
  test_root_ref :=
    Test_tmp.register (Printf.sprintf "%s_%d_%d" root_base (Unix.getpid ())
                         !case_n)

let rec rm_rf path =
  if Sys.file_exists path then begin
    if Sys.is_directory path then begin
      Array.iter (fun f -> rm_rf (Filename.concat path f)) (Sys.readdir path);
      Unix.rmdir path
    end else Unix.unlink path
  end

let cleanup () = rm_rf !test_root_ref

let open_dual_db () =
  next_root ();
  cleanup ();
  let test_root = !test_root_ref in
  Unix.mkdir test_root 0o755;
  let db = Storage.ChainDB.create (Filename.concat test_root "chain") in
  let rdb = Rocksdb_store.open_db (Filename.concat test_root "rocksdb") in
  Storage.ChainDB.attach_rocksdb_utxo db rdb;
  db, rdb

let close_dual_db db rdb =
  Rocksdb_store.close rdb;
  Storage.ChainDB.close db;
  cleanup ()

let p2pkh tag =
  let s = Cstruct.create 25 in
  Cstruct.set_uint8 s 0 0x76; Cstruct.set_uint8 s 1 0xa9;
  Cstruct.set_uint8 s 2 0x14; Cstruct.set_uint8 s 3 tag;
  Cstruct.set_uint8 s 23 0x88; Cstruct.set_uint8 s 24 0xac;
  s

let txid_of_byte b =
  let buf = Cstruct.create 32 in
  Cstruct.set_uint8 buf 0 b; Cstruct.set_uint8 buf 31 0x5a;
  buf

let entry ?(is_coinbase = false) ~tag ~value ~height () : Utxo.utxo_entry =
  { value; script_pubkey = p2pkh tag; height; is_coinbase }

(* Presence in each durable store, checked independently. *)
let in_rdb rdb txid vout =
  Option.is_some
    (Rocksdb_store.get rdb (Storage.ChainDB.rocksdb_utxo_key txid vout))

let in_cf db txid vout =
  let key = Storage.ChainDB.rocksdb_utxo_key txid vout in
  let found = ref false in
  Storage.ChainDB.iter_utxos db (fun t v _ ->
    if Storage.ChainDB.rocksdb_utxo_key t v = key then found := true);
  !found

let check_absent_everywhere label db rdb txid vout =
  Alcotest.(check bool) (label ^ ": absent from Rocksdb_store") false
    (in_rdb rdb txid vout);
  Alcotest.(check bool) (label ^ ": absent from ChainDB.get_utxo") false
    (Option.is_some (Storage.ChainDB.get_utxo db txid vout));
  Alcotest.(check bool) (label ^ ": absent from ChainDB utxo CF") false
    (in_cf db txid vout)

let check_present_everywhere label db rdb txid vout =
  Alcotest.(check bool) (label ^ ": present in Rocksdb_store") true
    (in_rdb rdb txid vout);
  Alcotest.(check bool) (label ^ ": present in ChainDB utxo CF") true
    (in_cf db txid vout)

(* Full CF snapshot, sorted (iter_utxos is already key-ordered). *)
let cf_snapshot db =
  let acc = ref [] in
  Storage.ChainDB.iter_utxos db (fun t v data ->
    acc := (Storage.ChainDB.rocksdb_utxo_key t v, data) :: !acc);
  List.rev !acc

let rdb_values rdb keys =
  List.map (fun (t, v) ->
    Rocksdb_store.get rdb (Storage.ChainDB.rocksdb_utxo_key t v)) keys

let persist utxo ~hash ~height =
  Utxo.OptimizedUtxoSet.persist_dirty_atomic utxo
    ~tip_hash:hash ~tip_height:height
    ~header_tip_hash:hash ~header_tip_height:height

(* ======================================================================
   BUG 1 — the dirty-set state machine, against the real OptimizedUtxoSet.
   ====================================================================== *)

let c_txid = txid_of_byte 0x42

(* (a) The exact task sequence, committed with [flush]. *)
let test_fresh_over_removed_flush () =
  let db, rdb = open_dual_db () in
  let utxo = Utxo.OptimizedUtxoSet.create ~cache_size:1000 ~rocksdb:rdb db in
  let c = entry ~tag:1 ~value:1000L ~height:1 () in
  Utxo.OptimizedUtxoSet.add utxo c_txid 0 c;
  Utxo.OptimizedUtxoSet.flush utxo;
  check_present_everywhere "C after first flush" db rdb c_txid 0;
  ignore (Utxo.OptimizedUtxoSet.remove utxo c_txid 0);  (* unflushed delete *)
  Utxo.OptimizedUtxoSet.add utxo c_txid 0 c;            (* undo restore   *)
  Utxo.OptimizedUtxoSet.remove_fast utxo c_txid 0;      (* spent again    *)
  Utxo.OptimizedUtxoSet.flush utxo;
  check_absent_everywhere "C after spend/re-add/spend/flush" db rdb c_txid 0;
  Alcotest.(check bool) "C not visible through the cache" true
    (Utxo.OptimizedUtxoSet.get utxo c_txid 0 = None);
  close_dual_db db rdb

(* (a') Same sequence committed with [persist_dirty_atomic] — the
   invalidateblock / submitblock commit path. *)
let test_fresh_over_removed_persist () =
  let db, rdb = open_dual_db () in
  let utxo = Utxo.OptimizedUtxoSet.create ~cache_size:1000 ~rocksdb:rdb db in
  let h = txid_of_byte 0x01 in
  let c = entry ~tag:1 ~value:1000L ~height:1 () in
  Utxo.OptimizedUtxoSet.add utxo c_txid 0 c;
  persist utxo ~hash:h ~height:1;
  ignore (Utxo.OptimizedUtxoSet.remove utxo c_txid 0);
  Utxo.OptimizedUtxoSet.add utxo c_txid 0 c;
  Utxo.OptimizedUtxoSet.remove_fast utxo c_txid 0;
  persist utxo ~hash:h ~height:1;
  check_absent_everywhere "C after persist_dirty_atomic" db rdb c_txid 0;
  close_dual_db db rdb

(* (a'') remove_fast (not remove) as the first spend, and a cache of
   capacity 0 (so no LRU entry can mask the dirty state). *)
let test_fresh_over_removed_fast_nocache () =
  let db, rdb = open_dual_db () in
  let utxo = Utxo.OptimizedUtxoSet.create ~cache_size:0 ~rocksdb:rdb db in
  let c = entry ~tag:1 ~value:1000L ~height:1 () in
  Utxo.OptimizedUtxoSet.add utxo c_txid 0 c;
  Utxo.OptimizedUtxoSet.flush utxo;
  Utxo.OptimizedUtxoSet.remove_fast utxo c_txid 0;
  Utxo.OptimizedUtxoSet.add utxo c_txid 0 c;
  Utxo.OptimizedUtxoSet.remove_fast utxo c_txid 0;
  Utxo.OptimizedUtxoSet.flush utxo;
  check_absent_everywhere "C (cache 0, remove_fast twice)" db rdb c_txid 0;
  close_dual_db db rdb

(* A clean coin (on disk, still in the LRU after the flush) re-added and
   then spent: Core's AddCoin never marks a coin FRESH when the cache holds
   it unspent — it is on disk. *)
let test_readd_over_clean_cached () =
  let db, rdb = open_dual_db () in
  let utxo = Utxo.OptimizedUtxoSet.create ~cache_size:1000 ~rocksdb:rdb db in
  let c = entry ~tag:1 ~value:1000L ~height:1 () in
  Utxo.OptimizedUtxoSet.add utxo c_txid 0 c;
  Utxo.OptimizedUtxoSet.flush utxo;
  Utxo.OptimizedUtxoSet.add utxo c_txid 0 c;
  Utxo.OptimizedUtxoSet.remove_fast utxo c_txid 0;
  Utxo.OptimizedUtxoSet.flush utxo;
  check_absent_everywhere "clean cached C re-added then spent" db rdb c_txid 0;
  close_dual_db db rdb

(* CONTROL (passes before and after): the FRESH shortcut itself must keep
   working — a coin created and spent inside one flush window never reaches
   disk and leaves no dirty entry behind. *)
let test_control_fresh_shortcut () =
  let db, rdb = open_dual_db () in
  let utxo = Utxo.OptimizedUtxoSet.create ~cache_size:1000 ~rocksdb:rdb db in
  let c = entry ~tag:1 ~value:1000L ~height:1 () in
  Utxo.OptimizedUtxoSet.add utxo c_txid 0 c;
  Utxo.OptimizedUtxoSet.remove_fast utxo c_txid 0;
  Alcotest.(check int) "FRESH add+spend leaves no dirty entry" 0
    (Utxo.OptimizedUtxoSet.dirty_count utxo);
  Utxo.OptimizedUtxoSet.flush utxo;
  check_absent_everywhere "never-flushed C" db rdb c_txid 0;
  close_dual_db db rdb

(* [~possible_overwrite:true] (Core AddCoins for coinbases, ApplyTxInUndo
   when !fClean) on a coin that is on disk but NOT cached at all: the cache
   cannot see the durable copy, so only the flag keeps it from being FRESH. *)
let test_possible_overwrite_uncached_durable () =
  let db, rdb = open_dual_db () in
  let utxo = Utxo.OptimizedUtxoSet.create ~cache_size:0 ~rocksdb:rdb db in
  let c = entry ~is_coinbase:true ~tag:1 ~value:1000L ~height:1 () in
  Utxo.OptimizedUtxoSet.add utxo c_txid 0 c;
  Utxo.OptimizedUtxoSet.flush utxo;          (* durable, and cache is empty *)
  Utxo.OptimizedUtxoSet.add ~possible_overwrite:true utxo c_txid 0 c;
  Utxo.OptimizedUtxoSet.remove_fast utxo c_txid 0;
  Utxo.OptimizedUtxoSet.flush utxo;
  check_absent_everywhere "overwrite-added durable C spent" db rdb c_txid 0;
  close_dual_db db rdb

(* ======================================================================
   BUG 2 (and BUG 1 on the live invalidateblock path) — real blocks through
   connect_block_optimized, then the disconnect primitives.
   ====================================================================== *)

let make_header ~prev ~nonce : Types.block_header =
  { version = 1l; prev_block = prev; merkle_root = Types.zero_hash;
    timestamp = Int32.of_int (1700000000 + nonce);
    bits = 0x207fffffl; nonce = Int32.of_int nonce }

let coinbase_tx ~height ~tag ~value : Types.transaction =
  { version = 1l;
    inputs = [{ previous_output = { txid = Types.zero_hash; vout = -1l };
                script_sig = Cstruct.of_string (Printf.sprintf "\x03h=%d" height);
                sequence = 0xffffffffl }];
    outputs = [{ value; script_pubkey = p2pkh tag }];
    witnesses = []; locktime = 0l }

let spend_tx ~prev_txid ~prev_vout ~tag ~value : Types.transaction =
  { version = 1l;
    inputs = [{ previous_output = { txid = prev_txid;
                                    vout = Int32.of_int prev_vout };
                script_sig = Cstruct.empty; sequence = 0xffffffffl }];
    outputs = [{ value; script_pubkey = p2pkh tag }];
    witnesses = []; locktime = 0l }

(* A pre-state coin P, on disk before any block is connected. *)
let p_txid = txid_of_byte 0x10
let p_entry = entry ~tag:0x10 ~value:1_000_000_000L ~height:0 ()

type fixture = {
  db : Storage.ChainDB.t;
  rdb : Rocksdb_store.t;
  chain : Sync.chain_state;
  utxo : Utxo.OptimizedUtxoSet.t;
  genesis : Sync.header_entry;
}

let setup () =
  let db, rdb = open_dual_db () in
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
  let utxo = Utxo.OptimizedUtxoSet.create ~cache_size:1000 ~rocksdb:rdb db in
  Utxo.OptimizedUtxoSet.add utxo p_txid 0 p_entry;
  persist utxo ~hash:genesis.hash ~height:0;
  { db; rdb; chain; utxo; genesis }

(* Connect [txs] on top of [parent] via the live UTXO primitive, storing the
   block body, undo data and header exactly as the connect path does.
   [commit] = persist the dirty set now (otherwise it stays unflushed, as it
   does for up to 500 blocks during IBD). *)
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

(* Block with an intra-block chain:  tx1 spends P, tx2 spends tx1:0. *)
let chained_block_txs () =
  let cb = coinbase_tx ~height:1 ~tag:0xc1 ~value:5_000_000_000L in
  let tx1 = spend_tx ~prev_txid:p_txid ~prev_vout:0 ~tag:0x21
              ~value:900_000_000L in
  let tx1_id = Crypto.compute_txid tx1 in
  let tx2 = spend_tx ~prev_txid:tx1_id ~prev_vout:0 ~tag:0x22
              ~value:800_000_000L in
  let tx2_id = Crypto.compute_txid tx2 in
  [cb; tx1; tx2], Crypto.compute_txid cb, tx1_id, tx2_id

let all_keys cb_id tx1_id tx2_id = [p_txid, 0; cb_id, 0; tx1_id, 0; tx2_id, 0]

let check_prestate label fx ~cf_before ~rdb_before ~keys ~cb_id ~tx1_id ~tx2_id =
  check_present_everywhere (label ^ " P restored") fx.db fx.rdb p_txid 0;
  check_absent_everywhere (label ^ " tx1:0 (intra-block, spent)")
    fx.db fx.rdb tx1_id 0;
  check_absent_everywhere (label ^ " tx2:0") fx.db fx.rdb tx2_id 0;
  check_absent_everywhere (label ^ " coinbase:0") fx.db fx.rdb cb_id 0;
  Alcotest.(check (list (pair string string)))
    (label ^ ": CF utxo set == pre-connect snapshot") cf_before
    (cf_snapshot fx.db);
  Alcotest.(check (list (option string)))
    (label ^ ": Rocksdb values == pre-connect") rdb_before
    (rdb_values fx.rdb keys)

(* (b) invalidateblock primitive, block committed before the disconnect. *)
let test_via_utxo_intrablock_chain () =
  let fx = setup () in
  let txs, cb_id, tx1_id, tx2_id = chained_block_txs () in
  let keys = all_keys cb_id tx1_id tx2_id in
  let cf_before = cf_snapshot fx.db and rdb_before = rdb_values fx.rdb keys in
  let _b1 = connect fx ~parent:fx.genesis ~nonce:1 ~txs ~commit:true in
  check_absent_everywhere "tx1:0 after connect (spent in-block)"
    fx.db fx.rdb tx1_id 0;
  check_present_everywhere "tx2:0 after connect" fx.db fx.rdb tx2_id 0;
  (match Sync.disconnect_to_target_via_utxo fx.chain fx.utxo fx.genesis with
   | Ok () -> ()
   | Error e -> Alcotest.failf "disconnect_to_target_via_utxo: %s" e);
  check_prestate "via_utxo" fx ~cf_before ~rdb_before ~keys ~cb_id ~tx1_id
    ~tx2_id;
  Alcotest.(check bool) "cache view: tx1:0 absent" true
    (Utxo.OptimizedUtxoSet.get fx.utxo tx1_id 0 = None);
  close_dual_db fx.db fx.rdb

(* (b') Same, but the connected block is still UNFLUSHED when invalidated
   (the dirty set only flushes every 500 blocks). *)
let test_via_utxo_intrablock_chain_unflushed () =
  let fx = setup () in
  let txs, cb_id, tx1_id, tx2_id = chained_block_txs () in
  let keys = all_keys cb_id tx1_id tx2_id in
  let cf_before = cf_snapshot fx.db and rdb_before = rdb_values fx.rdb keys in
  let _b1 = connect fx ~parent:fx.genesis ~nonce:1 ~txs ~commit:false in
  (match Sync.disconnect_to_target_via_utxo fx.chain fx.utxo fx.genesis with
   | Ok () -> ()
   | Error e -> Alcotest.failf "disconnect_to_target_via_utxo: %s" e);
  check_prestate "via_utxo unflushed" fx ~cf_before ~rdb_before ~keys ~cb_id
    ~tx1_id ~tx2_id;
  close_dual_db fx.db fx.rdb

(* BUG 1 on the live invalidateblock path.  Block 1 creates X (tx A spends
   P) and is committed.  Block 2 spends X and is NOT committed (X is a
   pending `Removed while still on disk).  Invalidating block 1 disconnects
   block 2 (restores X) and then block 1 (remove_fast X).  X must be gone. *)
let test_via_utxo_two_blocks_pending_spend () =
  let fx = setup () in
  let cb1 = coinbase_tx ~height:1 ~tag:0xc1 ~value:5_000_000_000L in
  let txa = spend_tx ~prev_txid:p_txid ~prev_vout:0 ~tag:0xa1
              ~value:900_000_000L in
  let x_id = Crypto.compute_txid txa in
  let cb2 = coinbase_tx ~height:2 ~tag:0xc2 ~value:5_000_000_000L in
  let txb = spend_tx ~prev_txid:x_id ~prev_vout:0 ~tag:0xb1
              ~value:800_000_000L in
  let y_id = Crypto.compute_txid txb in
  let keys = [p_txid, 0; Crypto.compute_txid cb1, 0; x_id, 0;
              Crypto.compute_txid cb2, 0; y_id, 0] in
  let cf_before = cf_snapshot fx.db and rdb_before = rdb_values fx.rdb keys in
  let b1 = connect fx ~parent:fx.genesis ~nonce:1 ~txs:[cb1; txa] ~commit:true in
  check_present_everywhere "X on disk after block 1" fx.db fx.rdb x_id 0;
  let _b2 = connect fx ~parent:b1 ~nonce:2 ~txs:[cb2; txb] ~commit:false in
  (match Sync.disconnect_to_target_via_utxo fx.chain fx.utxo fx.genesis with
   | Ok () -> ()
   | Error e -> Alcotest.failf "disconnect_to_target_via_utxo: %s" e);
  check_absent_everywhere "X (created by b1, spent by unflushed b2)"
    fx.db fx.rdb x_id 0;
  check_absent_everywhere "Y" fx.db fx.rdb y_id 0;
  check_present_everywhere "P restored" fx.db fx.rdb p_txid 0;
  Alcotest.(check (list (pair string string)))
    "CF utxo set == pre-connect snapshot" cf_before (cf_snapshot fx.db);
  Alcotest.(check (list (option string)))
    "Rocksdb values == pre-connect" rdb_before (rdb_values fx.rdb keys);
  close_dual_db fx.db fx.rdb

(* (b'') DB-direct [disconnect_to_target] (dumptxoutset rollback,
   invalidateblock without a threaded UTXO set).  It writes the CF only. *)
let test_db_direct_intrablock_chain () =
  let fx = setup () in
  let txs, cb_id, tx1_id, tx2_id = chained_block_txs () in
  let cf_before = cf_snapshot fx.db in
  let _b1 = connect fx ~parent:fx.genesis ~nonce:1 ~txs ~commit:true in
  (match Sync.disconnect_to_target fx.chain fx.genesis with
   | Ok () -> ()
   | Error e -> Alcotest.failf "disconnect_to_target: %s" e);
  Alcotest.(check bool) "CF: tx1:0 absent" false (in_cf fx.db tx1_id 0);
  Alcotest.(check bool) "CF: tx2:0 absent" false (in_cf fx.db tx2_id 0);
  Alcotest.(check bool) "CF: coinbase absent" false (in_cf fx.db cb_id 0);
  Alcotest.(check (list (pair string string)))
    "CF utxo set == pre-connect snapshot" cf_before (cf_snapshot fx.db);
  close_dual_db fx.db fx.rdb

(* (b''') Boot crash-window repair [reconcile_rdb_to_chain_tip]. *)
let test_reconcile_intrablock_chain () =
  let fx = setup () in
  let txs, cb_id, tx1_id, tx2_id = chained_block_txs () in
  let keys = all_keys cb_id tx1_id tx2_id in
  let cf_before = cf_snapshot fx.db and rdb_before = rdb_values fx.rdb keys in
  let _b1 = connect fx ~parent:fx.genesis ~nonce:1 ~txs ~commit:true in
  (match Sync.reconcile_rdb_to_chain_tip fx.chain fx.rdb
           ~rdb_height:1 ~target_height:0 with
   | Ok () -> ()
   | Error e -> Alcotest.failf "reconcile_rdb_to_chain_tip: %s" e);
  check_prestate "reconcile" fx ~cf_before ~rdb_before ~keys ~cb_id ~tx1_id
    ~tx2_id;
  close_dual_db fx.db fx.rdb

(* Undo whose shape does not match the block must refuse, not guess (Core:
   "transaction and undo data inconsistent"), and must leave the UTXO set
   untouched. *)
let test_inconsistent_undo_refused () =
  let fx = setup () in
  let txs, _cb_id, _tx1_id, tx2_id = chained_block_txs () in
  let b1 = connect fx ~parent:fx.genesis ~nonce:1 ~txs ~commit:true in
  (* Replace the stored undo with one that drops tx2's group. *)
  let bad : Utxo.undo_data =
    { height = 1;
      tx_undos = [ { spent_outputs = [ ({ txid = p_txid; vout = 0l }
                                        : Types.outpoint), p_entry ] } ] } in
  let uw = Serialize.writer_create () in
  Utxo.serialize_undo_data uw bad;
  Storage.ChainDB.store_undo_data fx.db b1.hash (Serialize.writer_to_string uw);
  (match Sync.disconnect_to_target_via_utxo fx.chain fx.utxo fx.genesis with
   | Ok () -> Alcotest.fail "inconsistent undo accepted"
   | Error _ -> ());
  check_present_everywhere "tx2:0 untouched" fx.db fx.rdb tx2_id 0;
  close_dual_db fx.db fx.rdb

let () =
  Alcotest.run "disconnect_utxo_fresh" [
    "bug1_fresh_over_dirty", [
      Alcotest.test_case "add/flush/remove/add/remove_fast/flush" `Quick
        test_fresh_over_removed_flush;
      Alcotest.test_case "same, committed via persist_dirty_atomic" `Quick
        test_fresh_over_removed_persist;
      Alcotest.test_case "remove_fast twice, cache capacity 0" `Quick
        test_fresh_over_removed_fast_nocache;
      Alcotest.test_case "re-add over clean cached coin" `Quick
        test_readd_over_clean_cached;
      Alcotest.test_case "CONTROL fresh add+spend shortcut" `Quick
        test_control_fresh_shortcut;
      Alcotest.test_case "possible_overwrite on uncached durable coin" `Quick
        test_possible_overwrite_uncached_durable;
    ];
    "bug2_disconnect_order", [
      Alcotest.test_case "via_utxo intra-block chain (flushed)" `Quick
        test_via_utxo_intrablock_chain;
      Alcotest.test_case "via_utxo intra-block chain (unflushed)" `Quick
        test_via_utxo_intrablock_chain_unflushed;
      Alcotest.test_case "DB-direct disconnect_to_target" `Quick
        test_db_direct_intrablock_chain;
      Alcotest.test_case "boot reconcile_rdb_to_chain_tip" `Quick
        test_reconcile_intrablock_chain;
      Alcotest.test_case "inconsistent undo refused" `Quick
        test_inconsistent_undo_refused;
    ];
    "bug1_invalidate_path", [
      Alcotest.test_case "two blocks, pending spend, invalidate both" `Quick
        test_via_utxo_two_blocks_pending_spend;
    ];
  ]
