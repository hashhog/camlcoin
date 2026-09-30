(* gettxoutsetinfo must walk the coin store validation reads.

   OptimizedUtxoSet.get reads LRU -> dirty -> Rocksdb_store (utxo.ml [get]);
   it never consults the Cf_chainstate UTXO column family.  The snapshot
   import and every [flush] before 57ae4b0 wrote coins to Rocksdb_store
   ONLY, so on a snapshot-bootstrapped datadir the CF holds a subset.
   gettxoutsetinfo walked the CF (plus the dirty overlay): live mainnet at
   969284 reported 34,404,890 txouts / 4,330,938.887 BTC against Core's
   165,162,133 / 20,091,285.502 BTC, while gettxout had every coin.

   The fixture reproduces that shape: coins written straight into
   Rocksdb_store (the pre-57ae4b0 import / flush), one coin written by a
   post-57ae4b0 flush (both stores), and an unflushed dirty overlay that
   spends an RDB-only coin and creates a new one.

   NEGATIVE CONTROL: [test_fixture_cf_is_partial] proves the CF really is a
   strict subset here and that its hash differs from the committed set, so
   a walk of the CF cannot pass [test_rpc_walks_rdb].  Against master
   (iter_committed on ChainDB.iter_utxos) test_rpc_walks_rdb fails with
   txouts 2 <> 4.

   Command:
     dune exec --no-buffer test/test_txoutset_walks_coin_store.exe *)

open Camlcoin

let root_base = "/tmp/camlcoin_test_txoutset_walks_coin_store"
let case_n = ref 0
let root_ref = ref root_base

let rec rm_rf path =
  if Sys.file_exists path then begin
    if Sys.is_directory path then begin
      Array.iter (fun f -> rm_rf (Filename.concat path f)) (Sys.readdir path);
      Unix.rmdir path
    end else Unix.unlink path
  end

let with_dual f =
  incr case_n;
  root_ref :=
    Test_tmp.register
      (Printf.sprintf "%s_%d_%d" root_base (Unix.getpid ()) !case_n);
  rm_rf !root_ref;
  Unix.mkdir !root_ref 0o755;
  let db = Storage.ChainDB.create (Filename.concat !root_ref "chain") in
  let rdb = Rocksdb_store.open_db (Filename.concat !root_ref "rocksdb") in
  Storage.ChainDB.attach_rocksdb_utxo db rdb;
  Fun.protect
    ~finally:(fun () ->
      Rocksdb_store.close rdb; Storage.ChainDB.close db; rm_rf !root_ref)
    (fun () -> f db rdb)

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

let entry ~tag ~value ~height : Utxo.utxo_entry =
  { value; script_pubkey = p2pkh tag; height; is_coinbase = false }

let ser (e : Utxo.utxo_entry) =
  let w = Serialize.writer_create () in
  Utxo.serialize_utxo_entry w e;
  Serialize.writer_to_string w

(* Coins.  vout 256 on txid_a sorts BEFORE vout 0 in LE32 key order; the
   hash must still come out in numeric vout order. *)
let txid_a = txid_of_byte 0x10
let txid_e = txid_of_byte 0x30
let txid_c = txid_of_byte 0x50
let txid_d = txid_of_byte 0x90
let e_a0 = entry ~tag:1 ~value:5_000_000_000L ~height:100
let e_a256 = entry ~tag:2 ~value:1_234L ~height:100
let e_c = entry ~tag:3 ~value:7_000L ~height:200
let e_d = entry ~tag:4 ~value:9_000_000L ~height:150
let e_e = entry ~tag:5 ~value:42L ~height:201

(* Committed set after [build]: {A:0, A:256, E:0, C:1}. *)
let expected = [ (txid_a, 0, e_a0); (txid_a, 256, e_a256);
                 (txid_e, 0, e_e); (txid_c, 1, e_c) ]

let expected_hash_hex () =
  let acc = Assume_utxo.hash_serialized_create () in
  List.iter (fun (txid, vout, (e : Utxo.utxo_entry)) ->
    let outpoint = { Types.txid; vout = Int32.of_int vout } in
    Assume_utxo.hash_serialized_add acc outpoint
      { Assume_utxo.outpoint; value = e.value;
        script_pubkey = e.script_pubkey; height = e.height;
        is_coinbase = e.is_coinbase })
    expected;
  Types.hash256_to_hex_display (Assume_utxo.hash_serialized_finish acc)

let build db rdb =
  (* Pre-57ae4b0 import / flush: Rocksdb_store only, with the tip meta key. *)
  Rocksdb_store.batch_write ~tip_height:199 rdb [
    (Storage.ChainDB.rocksdb_utxo_key txid_a 0, Some (ser e_a0));
    (Storage.ChainDB.rocksdb_utxo_key txid_a 256, Some (ser e_a256));
    (Storage.ChainDB.rocksdb_utxo_key txid_d 0, Some (ser e_d));
  ];
  let cache = Utxo.OptimizedUtxoSet.create ~rocksdb:rdb db in
  (* Post-57ae4b0 flush: mirrored into both stores. *)
  Utxo.OptimizedUtxoSet.add cache txid_c 1 e_c;
  Utxo.OptimizedUtxoSet.flush ~tip_height:200 cache;
  (* Unflushed block: spends RDB-only D, creates E. *)
  Utxo.OptimizedUtxoSet.remove_fast cache txid_d 0;
  Utxo.OptimizedUtxoSet.add cache txid_e 0 e_e;
  cache

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

let field fields name =
  match List.assoc_opt name fields with
  | Some v -> v
  | None -> Alcotest.fail ("missing field " ^ name)

let walk_hash iter =
  let acc = Assume_utxo.hash_serialized_create () in
  let n = ref 0 in
  iter (fun txid vout data ->
    incr n;
    let e = Utxo.deserialize_utxo_entry
        (Serialize.reader_of_cstruct (Cstruct.of_string data)) in
    let outpoint = { Types.txid; vout = Int32.of_int vout } in
    Assume_utxo.hash_serialized_add acc outpoint
      { Assume_utxo.outpoint; value = e.value;
        script_pubkey = e.script_pubkey; height = e.height;
        is_coinbase = e.is_coinbase });
  (!n, Types.hash256_to_hex_display (Assume_utxo.hash_serialized_finish acc))

(* Negative control: the fixture's CF is a strict subset of the committed
   set, so a CF-based walk (master) cannot produce the expected answer. *)
let test_fixture_cf_is_partial () =
  with_dual (fun db rdb ->
    let cache = build db rdb in
    let n_cf = ref 0 in
    Storage.ChainDB.iter_utxos db (fun _ _ _ -> incr n_cf);
    Alcotest.(check int) "CF holds only the mirrored coin" 1 !n_cf;
    (* Master's walk, reproduced: the CF as base, overlaid with the same
       unflushed block.  A cache with no Rocksdb_store walks exactly that. *)
    let cf_cache = Utxo.OptimizedUtxoSet.create db in
    Utxo.OptimizedUtxoSet.remove_fast cf_cache txid_d 0;
    Utxo.OptimizedUtxoSet.add cf_cache txid_e 0 e_e;
    let n_master, h_master =
      walk_hash (Utxo.iter_committed_utxos (Some cf_cache) db) in
    Alcotest.(check int) "CF-based walk sees 2 of 4 coins" 2 n_master;
    Alcotest.(check bool) "CF-based hash differs from the committed set"
      true (h_master <> expected_hash_hex ());
    let n_fixed, h_fixed = walk_hash (Utxo.iter_committed_utxos (Some cache) db) in
    Alcotest.(check int) "store-based walk sees all 4" 4 n_fixed;
    Alcotest.(check string) "store-based hash = committed set"
      (expected_hash_hex ()) h_fixed)

let test_rpc_walks_rdb () =
  with_dual (fun db rdb ->
    let cache = build db rdb in
    let fields = rpc_setinfo (make_ctx db ~utxo:(Some cache)) in
    Alcotest.(check int) "txouts = committed set" 4
      (match field fields "txouts" with `Int n -> n | _ -> -1);
    Alcotest.(check int) "transactions (distinct txids)" 3
      (match field fields "transactions" with `Int n -> n | _ -> -1);
    let total =
      List.fold_left (fun a (_, _, (e : Utxo.utxo_entry)) -> Int64.add a e.value)
        0L expected in
    Alcotest.(check string) "total_amount"
      (Yojson.Safe.to_string (Rpc.btc_amount_json total))
      (Yojson.Safe.to_string (field fields "total_amount"));
    Alcotest.(check string) "hash_serialized_3 = independent hash of set"
      (expected_hash_hex ())
      (match field fields "hash_serialized_3" with `String s -> s | _ -> "");
    (* Read-only: the RPC flushed nothing. *)
    Alcotest.(check int) "dirty untouched" 2
      (Utxo.OptimizedUtxoSet.dirty_count cache))

(* Every coin the walk reports is one validation resolves, with the same
   value; the spent coin is in neither. *)
let test_walk_agrees_with_get () =
  with_dual (fun db rdb ->
    let cache = build db rdb in
    let walked = ref [] in
    Utxo.iter_committed_utxos (Some cache) db (fun txid vout data ->
      walked := (txid, vout, data) :: !walked);
    Alcotest.(check int) "walk size" 4 (List.length !walked);
    List.iter (fun (txid, vout, data) ->
      match Utxo.OptimizedUtxoSet.get cache txid vout with
      | None -> Alcotest.fail "walked coin not resolvable by get"
      | Some e -> Alcotest.(check string) "same bytes" data (ser e))
      !walked;
    Alcotest.(check bool) "spent D not resolvable" true
      (Utxo.OptimizedUtxoSet.get cache txid_d 0 = None);
    Alcotest.(check bool) "spent D not walked" false
      (List.exists (fun (t, v, _) -> Cstruct.equal t txid_d && v = 0) !walked))

(* Rocksdb_store.iter_utxos: skips the __meta__ keys, bytewise order, and an
   exception from the callback propagates without wedging the store. *)
let test_rdb_iter () =
  with_dual (fun db rdb ->
    ignore (build db rdb);
    Alcotest.(check (option int)) "meta key present" (Some 200)
      (Rocksdb_store.get_tip_height rdb);
    let keys = ref [] in
    Rocksdb_store.iter_utxos rdb (fun txid vout _ ->
      keys := Storage.ChainDB.rocksdb_utxo_key txid vout :: !keys);
    let keys = List.rev !keys in
    Alcotest.(check int) "coins only (A0, A256, C, D on disk)" 4
      (List.length keys);
    Alcotest.(check bool) "bytewise order" true
      (keys = List.sort String.compare keys);
    (match Rocksdb_store.iter_utxos rdb (fun _ _ _ -> raise Exit) with
     | () -> Alcotest.fail "callback exception swallowed"
     | exception Exit -> ());
    let n = ref 0 in
    Rocksdb_store.iter_utxos rdb (fun _ _ _ -> incr n);
    Alcotest.(check int) "walk after exception" 4 !n)

let () =
  Alcotest.run "txoutset-walks-coin-store" [
    "gettxoutsetinfo", [
      Alcotest.test_case "negative control: CF is partial" `Quick
        test_fixture_cf_is_partial;
      Alcotest.test_case "RPC walks Rocksdb_store + overlay" `Quick
        test_rpc_walks_rdb;
      Alcotest.test_case "walk agrees with OptimizedUtxoSet.get" `Quick
        test_walk_agrees_with_get;
      Alcotest.test_case "Rocksdb_store.iter_utxos" `Quick test_rdb_iter;
    ];
  ]
