(* gettxoutsetinfo must not freeze the node (release gate 3a).

   Live mainnet 2026-10-01: the 35-55 min walk ran on the preemptive pool's
   systhread inside the MAIN domain, holding [rpc_worker_mutex].  Systhreads
   share their domain's runtime lock, so the Lwt loop (RPC, P2P, block
   connection) only got it in tick-sized slivers; and the walk read
   [OptimizedUtxoSet.dirty] while the Lwt thread mutated it, over a RocksDB
   iterator whose implicit snapshot was pinned at walk start, not when the
   tip was read.

   The fix captures tip + dirty copy + explicit RocksDB snapshot in one
   main-thread step ([Rpc.gettxoutsetinfo_prepare]) and walks that view on its
   own domain ([Rpc.handle_gettxoutsetinfo_lwt]).

   [test_view_is_isolated]: blocks that connect AND flush after the capture do
   not leak into the result (negative control: a fresh walk sees them).
   [test_lwt_loop_live_during_walk]: with the walk held busy for 2 s, the Lwt
   loop keeps ticking.  Its control runs the same busy walk the OLD way (a
   systhread of the main domain) and must starve the loop -- that is the
   freeze, and it is what this test fails on if the walk moves back.

   Command:
     dune exec --no-buffer test/test_txoutset_snapshot_walk.exe *)

open Camlcoin

let root_base = "/tmp/camlcoin_test_txoutset_snapshot_walk"
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

let e_f = entry ~tag:6 ~value:77L ~height:202
let txid_f = txid_of_byte 0x70

let test_view_is_isolated () =
  with_dual (fun db rdb ->
    let cache = build db rdb in
    let ctx = make_ctx db ~utxo:(Some cache) in
    let job =
      match Rpc.gettxoutsetinfo_prepare ctx [`String "hash_serialized_3"] with
      | Ok (`Walk j) -> j
      | Ok (`Json _) -> Alcotest.fail "expected a walk job"
      | Error m -> Alcotest.fail m
    in
    (* After the capture: a block spends A:0 and creates F, the set is
       flushed to Rocksdb_store (dirty cleared), and one more block's coin
       sits in dirty. *)
    Utxo.OptimizedUtxoSet.remove_fast cache txid_a 0;
    Utxo.OptimizedUtxoSet.add cache txid_f 0 e_f;
    Utxo.OptimizedUtxoSet.flush ~tip_height:201 cache;
    Utxo.OptimizedUtxoSet.add cache txid_f 1 e_f;
    let fields =
      match Rpc.run_txoutset_job job with
      | `Assoc f -> f
      | _ -> Alcotest.fail "expected object"
    in
    Alcotest.(check int) "txouts = captured set" 4
      (match field fields "txouts" with `Int n -> n | _ -> -1);
    Alcotest.(check string) "hash = captured set" (expected_hash_hex ())
      (match field fields "hash_serialized_3" with `String s -> s | _ -> "");
    (* Negative control: the post-capture blocks ARE visible to a new walk,
       so the equality above is not vacuous. *)
    let now = rpc_setinfo ctx in
    Alcotest.(check int) "fresh walk sees the new blocks" 5
      (match field now "txouts" with `Int n -> n | _ -> -1);
    Alcotest.(check bool) "fresh hash differs" true
      (field now "hash_serialized_3" <> field fields "hash_serialized_3"))

(* Count Lwt timer ticks (5 ms sleeps) while [busy] runs; return the tick
   count and the longest gap between ticks. *)
let ticks_while (busy : unit -> 'a Lwt.t) : int * float =
  Lwt_main.run begin
    let finished = ref false in
    let ticks = ref 0 in
    let max_gap = ref 0.0 in
    let rec ticker last =
      if !finished then Lwt.return_unit
      else
        let%lwt () = Lwt_unix.sleep 0.005 in
        let now = Unix.gettimeofday () in
        incr ticks;
        if now -. last > !max_gap then max_gap := now -. last;
        ticker now
    in
    let t = ticker (Unix.gettimeofday ()) in
    let%lwt _ = busy () in
    finished := true;
    let%lwt () = t in
    Lwt.return (!ticks, !max_gap)
  end

let spin s =
  let t0 = Unix.gettimeofday () in
  while Unix.gettimeofday () -. t0 < s do () done

let test_lwt_loop_live_during_walk () =
  with_dual (fun db rdb ->
    let cache = build db rdb in
    let ctx = make_ctx db ~utxo:(Some cache) in
    Rpc.test_txoutset_walk_spin_s := 2.0;
    let ticks, gap =
      Fun.protect ~finally:(fun () -> Rpc.test_txoutset_walk_spin_s := 0.0)
        (fun () ->
          ticks_while (fun () ->
            match%lwt Rpc.handle_gettxoutsetinfo_lwt ctx
                        [`String "hash_serialized_3"] with
            | Ok (`Assoc f) ->
              Alcotest.(check string) "walk result" (expected_hash_hex ())
                (match field f "hash_serialized_3" with
                 | `String s -> s | _ -> "");
              Lwt.return_unit
            | Ok _ -> Alcotest.fail "expected object"
            | Error m -> Alcotest.fail m))
    in
    (* Control: the same 2 s busy walk the OLD way, on a preemptive systhread
       of the main domain. *)
    let c_ticks, c_gap =
      ticks_while (fun () -> Lwt_preemptive.detach (fun () -> spin 2.0) ())
    in
    Printf.printf "domain walk: %d ticks, max gap %.3fs | old systhread walk: \
                   %d ticks, max gap %.3fs\n%!" ticks gap c_ticks c_gap;
    Alcotest.(check bool) "Lwt loop kept ticking during the walk" true
      (ticks >= 100);
    Alcotest.(check bool) "no Lwt stall > 0.5 s during the walk" true
      (gap < 0.5);
    Alcotest.(check bool) "control: the old systhread walk starves Lwt" true
      (c_ticks * 2 < ticks))

let () =
  Alcotest.run "txoutset-snapshot-walk" [
    "gettxoutsetinfo", [
      Alcotest.test_case "captured view is isolated" `Quick
        test_view_is_isolated;
      Alcotest.test_case "Lwt loop live during the walk" `Quick
        test_lwt_loop_live_during_walk;
    ];
  ]
