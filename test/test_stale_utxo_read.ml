(* Control: gettxoutsetinfo must hash the committed UTXO set, not the
   last-flushed CF, and must not persist the dirty overlay.

   Ladder ranges are shorter than Sync.utxo_flush_interval (500), so
   IBD coins sit in OptimizedUtxoSet.dirty while ChainDB.iter_utxos
   still yields the previous rung.  After fc8935d the RPC walked the
   CF alone (STALE-UTXO-READ).  Re-adding ForceFlushStateToDisk
   reopens the two-instance torn-write window (RDB coins then CF
   chain_tip) that wedges a default assume-valid datadir on crash.

   This file fails if either defect comes back:

     * disk-only walk  → hash_serialized_3 equals the stale CF hash
     * RPC force-flush → the CF changes (or chain_tip advances) during
       the call

   Command:
     dune exec --no-buffer test/test_stale_utxo_read.exe
*)

open Camlcoin

let test_root = "/tmp/camlcoin_test_stale_utxo_read"

let rec rm_rf path =
  if Sys.file_exists path then begin
    if Sys.is_directory path then begin
      Array.iter (fun f -> rm_rf (Filename.concat path f)) (Sys.readdir path);
      Unix.rmdir path
    end else
      Unix.unlink path
  end

let cleanup () = rm_rf test_root

let p2pkh tag =
  let script = Cstruct.create 25 in
  Cstruct.set_uint8 script 0 0x76;
  Cstruct.set_uint8 script 1 0xa9;
  Cstruct.set_uint8 script 2 0x14;
  Cstruct.set_uint8 script 3 tag;
  Cstruct.set_uint8 script 23 0x88;
  Cstruct.set_uint8 script 24 0xac;
  script

let entry ~tag ~value ~height : Utxo.utxo_entry =
  { value; script_pubkey = p2pkh tag; height; is_coinbase = false }

(* Distinct 32-byte txids that sort A < B < C so the overlay merge
   has to emit B between the two on-disk coins, not append it. *)
let txid_of_byte b =
  let buf = Cstruct.create 32 in
  Cstruct.set_uint8 buf 0 b;
  buf

let txid_a = txid_of_byte 0x00
let txid_b = txid_of_byte 0x80
let txid_c = txid_of_byte 0xff

let disk_hash_hex db =
  Types.hash256_to_hex_display (Assume_utxo.compute_utxo_hash_from_db db)

let snapshot_disk db =
  let acc = ref [] in
  Storage.ChainDB.iter_utxos db (fun txid vout data ->
    acc := (Types.hash256_to_hex txid, vout, data) :: !acc);
  List.sort compare !acc

let make_ctx db ~utxo =
  let legacy = Utxo.UtxoSet.create db in
  let mp =
    Mempool.create ~network:Consensus.regtest ~require_standard:false
      ~verify_scripts:false ~utxo:legacy ~current_height:100 ()
  in
  let chain = Sync.create_chain_state db Consensus.mainnet in
  let pm = Peer_manager.create Consensus.mainnet in
  let fe = Fee_estimation.create () in
  Rpc.create_context ~chain ~mempool:mp ~peer_manager:pm ~wallet:None
    ~fee_estimator:fe ~network:Consensus.mainnet ~utxo ()

let rpc_setinfo ctx =
  match Rpc.handle_gettxoutsetinfo ctx [`String "hash_serialized_3"] with
  | Error msg -> Alcotest.fail ("gettxoutsetinfo: " ^ msg)
  | Ok (`Assoc fields) -> fields
  | Ok _ -> Alcotest.fail "gettxoutsetinfo: expected object"

let field_string fields name =
  match List.assoc_opt name fields with
  | Some (`String s) -> s
  | _ -> Alcotest.fail ("missing string field " ^ name)

let field_int fields name =
  match List.assoc_opt name fields with
  | Some (`Int n) -> n
  | _ -> Alcotest.fail ("missing int field " ^ name)

(* Open a ChainDB under [test_root/<name>], run [f], always close+rm. *)
let with_db name f =
  cleanup ();
  Unix.mkdir test_root 0o755;
  let path = Filename.concat test_root name in
  let db = Storage.ChainDB.create path in
  Fun.protect
    ~finally:(fun () -> Storage.ChainDB.close db; cleanup ())
    (fun () -> f db)

(* The ladder shape: CF holds the previous rung {A,C}; dirty spends A
   and creates B.  Committed set is {B,C}.  A disk-only walk answers
   {A,C} — the STALE-UTXO-READ the range harness flags. *)
let test_committed_not_stale_and_no_write () =
  with_db "merge" (fun db ->
    let cache = Utxo.OptimizedUtxoSet.create db in
    let e_a = entry ~tag:1 ~value:1_000_000L ~height:10 in
    let e_b = entry ~tag:2 ~value:2_000_000L ~height:11 in
    let e_c = entry ~tag:3 ~value:3_000_000L ~height:10 in
    Utxo.OptimizedUtxoSet.add cache txid_a 0 e_a;
    Utxo.OptimizedUtxoSet.add cache txid_c 0 e_c;
    Utxo.OptimizedUtxoSet.flush cache;
    Alcotest.(check int) "flushed window is clean"
      0 (Utxo.OptimizedUtxoSet.dirty_count cache);
    Utxo.OptimizedUtxoSet.add cache txid_b 0 e_b;
    Utxo.OptimizedUtxoSet.remove_fast cache txid_a 0;
    let dirty_before = Utxo.OptimizedUtxoSet.dirty_count cache in
    Alcotest.(check bool) "unflushed spend+create sit in dirty"
      true (dirty_before >= 2);
    let stale = disk_hash_hex db in
    let disk_before = snapshot_disk db in
    let tip_before = Storage.ChainDB.get_chain_tip db in
    let ctx = make_ctx db ~utxo:(Some cache) in
    let fields = rpc_setinfo ctx in
    let live = field_string fields "hash_serialized_3" in
    let txouts = field_int fields "txouts" in
    Alcotest.(check int) "committed txouts = {B,C}" 2 txouts;
    Alcotest.(check bool)
      "RPC hash is not the previous-rung (stale) CF hash"
      true (live <> stale);
    Alcotest.(check int) "RPC did not drain dirty"
      dirty_before (Utxo.OptimizedUtxoSet.dirty_count cache);
    Alcotest.(check bool) "RPC did not persist the overlay onto the CF"
      true (disk_before = snapshot_disk db);
    let tip_hex = function
      | None -> None
      | Some (h, n) -> Some (Types.hash256_to_hex h, n)
    in
    Alcotest.(check bool) "RPC did not advance chain_tip"
      true (tip_hex tip_before = tip_hex (Storage.ChainDB.get_chain_tip db));
    (* Same cache, now flushed: the CF is the committed set.  The RPC
       answer taken *before* this write must match it.  If the handler
       walked iter_utxos, [live] still equals [stale] and this fails. *)
    Utxo.OptimizedUtxoSet.flush cache;
    let committed = disk_hash_hex db in
    Alcotest.(check bool) "flushed CF moved off the stale rung"
      true (committed <> stale);
    Alcotest.(check string)
      "pre-flush RPC hash equals the committed (flushed) set"
      committed live)

(* Empty CF, coins only in dirty — the first flush window after a
   snapshot whose CF walk would report txouts=0. *)
let test_dirty_only_not_empty_disk () =
  with_db "dirty-only" (fun db ->
    let cache = Utxo.OptimizedUtxoSet.create db in
    Utxo.OptimizedUtxoSet.add cache txid_b 0
      (entry ~tag:9 ~value:50_000_000L ~height:1);
    let stale = disk_hash_hex db in
    let ctx = make_ctx db ~utxo:(Some cache) in
    let fields = rpc_setinfo ctx in
    let live = field_string fields "hash_serialized_3" in
    Alcotest.(check int) "committed txouts" 1 (field_int fields "txouts");
    Alcotest.(check bool) "disk is still empty after the RPC"
      true (snapshot_disk db = []);
    Alcotest.(check bool) "empty-CF hash is not the committed hash"
      true (live <> stale);
    Utxo.OptimizedUtxoSet.flush cache;
    Alcotest.(check string)
      "pre-flush RPC hash equals flushed committed set"
      (disk_hash_hex db) live)

(* Overlay is identity when dirty is empty: no regression vs the
   flushed-at-tip path. *)
let test_empty_dirty_matches_disk () =
  with_db "identity" (fun db ->
    let cache = Utxo.OptimizedUtxoSet.create db in
    Utxo.OptimizedUtxoSet.add cache txid_a 0
      (entry ~tag:1 ~value:1L ~height:4);
    Utxo.OptimizedUtxoSet.add cache txid_c 0
      (entry ~tag:3 ~value:3L ~height:4);
    Utxo.OptimizedUtxoSet.flush cache;
    Alcotest.(check int) "dirty empty" 0
      (Utxo.OptimizedUtxoSet.dirty_count cache);
    let ctx = make_ctx db ~utxo:(Some cache) in
    let fields = rpc_setinfo ctx in
    Alcotest.(check string) "RPC hash equals on-disk hash"
      (disk_hash_hex db) (field_string fields "hash_serialized_3");
    Alcotest.(check int) "txouts" 2 (field_int fields "txouts"))

let () =
  cleanup ();
  Alcotest.run "stale-utxo-read" [
    "gettxoutsetinfo", [
      Alcotest.test_case
        "committed overlay, not stale CF; RPC does not write" `Quick
        test_committed_not_stale_and_no_write;
      Alcotest.test_case
        "dirty-only window is not an empty-CF hash" `Quick
        test_dirty_only_not_empty_disk;
      Alcotest.test_case
        "empty dirty matches disk" `Quick
        test_empty_dirty_matches_disk;
    ];
  ]
