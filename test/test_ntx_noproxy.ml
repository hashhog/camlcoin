(* R3 no-proxy: camlcoin answers only from its own state.

   Older builds forwarded three RPC paths to the co-located Bitcoin Core
   (127.0.0.1:8332, authenticating with Core's .cookie) and PERSISTED the
   nTx answer into the block index. This file pins both halves of the fix:

   1. Source guard: no library module reads Core's cookie or dials 8332,
      and the three oracle functions are gone.
   2. Ntx_reconcile, the one-time startup pass that removes the borrowed
      values, per class:
        body held (off active chain)      -> recounted from the body
        validated here, no body (undo)    -> kept
        validated here, active & in range -> kept
        never processed here              -> reset (key deleted)
        derived cumulative "c:"           -> deleted
        second run                        -> skipped via the marker
      plus getblockheader answering nTx 0 for a header-only block. *)

open Camlcoin

let read_file path =
  let ic = open_in_bin path in
  Fun.protect ~finally:(fun () -> close_in ic)
    (fun () -> really_input_string ic (in_channel_length ic))

let contains hay needle =
  let n = String.length needle and h = String.length hay in
  let rec go i = i + n <= h && (String.sub hay i n = needle || go (i + 1)) in
  go 0

let lib_sources () =
  Sys.readdir "../lib" |> Array.to_list
  |> List.filter (fun f -> Filename.check_suffix f ".ml")
  |> List.map (fun f -> (f, read_file (Filename.concat "../lib" f)))

(* ---------- 1. source guard ---------- *)

let forbidden = [
  "bitcoin-core/.cookie";          (* Core's RPC credential *)
  "hashhog-mainnet/bitcoin-core";  (* the live Core datadir *)
  "(8332,";                        (* the (port, cookie) oracle tuple *)
  "ntx_from_core";
  "fees_from_core";
  "prevouts_from_core";
]

let test_source_guard () =
  let srcs = lib_sources () in
  Alcotest.(check bool) "guard actually scanned rpc.ml" true
    (List.mem_assoc "rpc.ml" srcs && List.length srcs > 50);
  List.iter (fun (f, body) ->
    List.iter (fun pat ->
      if contains body pat then
        Alcotest.failf "lib/%s contains forbidden Core-proxy marker %S" f pat)
      forbidden) srcs;
  (* rpc.ml is a server: it must never open an outbound TCP connection. *)
  Alcotest.(check bool) "rpc.ml has no Unix.connect" false
    (contains (List.assoc "rpc.ml" srcs) "Unix.connect")

(* ---------- 2. reconcile ---------- *)

let mk_hash i =
  let cs = Cstruct.create 32 in
  Cstruct.set_uint8 cs 0 (i land 0xff);
  Cstruct.set_uint8 cs 1 ((i lsr 8) land 0xff);
  Cstruct.set_uint8 cs 31 0xab;
  cs

(* Raw body: 80-byte header + CompactSize(n) + filler; only the count
   matters to Storage.ChainDB.get_block_ntx_from_body. *)
let put_body db hash n =
  Cf_chainstate.put_block_data db.Storage.ChainDB.cf hash
    (String.make 80 '\000' ^ String.make 1 (Char.chr n) ^ "xx")

let genesis = mk_hash 0

type fixture = {
  db : Storage.ChainDB.t;
  heights : (string, int) Hashtbl.t;
  tip : int;
}

(* Layout (tip = 20, bodies held for 11..20 => floor 11, i.e. an
   assumeUTXO-style datadir whose base is 10):
     active 1..10   : n: from Core (no body, no undo)      -> reset
                      except height 5 has undo              -> kept
     active 11..20  : n: from connect, body held            -> kept (in range)
     fork F (h 15)  : body held (3 txs) but n: says 9       -> recounted to 3
     fork G (h 16)  : body held (2 txs), n: says 2          -> recounted, same
     header-only H  : height 21, no body/undo, n: from Core -> reset
     "c:" at 3, 8 (below floor, >= lowest reset)           -> deleted
     "c:" at 12 (in range, connect-time)                   -> kept
     "c:" for H                                            -> deleted *)
let build db =
  let heights = Hashtbl.create 32 in
  let reg h hash = Hashtbl.replace heights (Cstruct.to_string hash) h in
  reg 0 genesis;
  Storage.ChainDB.set_height_hash db 0 genesis;
  Storage.ChainDB.store_block_ntx db genesis 1;
  for h = 1 to 20 do
    let hash = mk_hash h in
    reg h hash;
    Storage.ChainDB.set_height_hash db h hash;
    Storage.ChainDB.store_block_ntx db hash (h + 100);
    if h >= 11 then put_body db hash (h + 100)
  done;
  Storage.ChainDB.store_undo_data db (mk_hash 5) "undo-bytes";
  let f = mk_hash 1015 and g = mk_hash 1016 and hdr = mk_hash 1021 in
  reg 15 f; reg 16 g; reg 21 hdr;
  put_body db f 3; Storage.ChainDB.store_block_ntx db f 9;
  put_body db g 2; Storage.ChainDB.store_block_ntx db g 2;
  Storage.ChainDB.store_block_ntx db hdr 4242;
  List.iter (fun h ->
    Storage.ChainDB.store_chain_tx_count db (mk_hash h) (Int64.of_int (h * 7)))
    [3; 8; 12];
  Storage.ChainDB.store_chain_tx_count db hdr 99L;
  { db; heights; tip = 20 }

let run fx =
  Ntx_reconcile.run ~db:fx.db ~genesis_hash:genesis ~tip:fx.tip
    ~height_of:(Hashtbl.find_opt fx.heights)

let ntx db i = Storage.ChainDB.get_block_ntx db (mk_hash i)

let with_fixture f =
  Test_tmp.with_chaindb (fun db -> f (build db))

let first_run fx =
  match run fx with
  | Ntx_reconcile.Ran s -> s
  | Ntx_reconcile.Skipped_already_done -> Alcotest.fail "skipped on first run"
  | Ntx_reconcile.Failed e -> Alcotest.failf "reconcile failed: %s" e

let opt_int = Alcotest.(option int)

let test_body_recount () =
  with_fixture (fun fx ->
    let s = first_run fx in
    Alcotest.check opt_int "fork F recounted from body" (Some 3) (ntx fx.db 1015);
    Alcotest.check opt_int "fork G unchanged" (Some 2) (ntx fx.db 1016);
    Alcotest.(check int) "recounted_changed" 1 s.recounted_changed;
    Alcotest.(check int) "recounted_same" 1 s.recounted_same)

let test_validated_no_body_kept () =
  with_fixture (fun fx ->
    let s = first_run fx in
    Alcotest.check opt_int "height 5 (undo held) kept" (Some 105) (ntx fx.db 5);
    Alcotest.(check int) "kept_undo" 1 s.kept_undo;
    Alcotest.check opt_int "genesis kept" (Some 1)
      (Storage.ChainDB.get_block_ntx fx.db genesis);
    for h = 11 to 20 do
      Alcotest.check opt_int (Printf.sprintf "in-range %d kept" h)
        (Some (h + 100)) (ntx fx.db h)
    done;
    Alcotest.(check int) "kept_in_range" 10 s.kept_in_range)

let test_not_validated_reset () =
  with_fixture (fun fx ->
    let s = first_run fx in
    List.iter (fun h ->
      Alcotest.check opt_int (Printf.sprintf "height %d reset" h) None (ntx fx.db h))
      [1; 2; 3; 4; 6; 7; 8; 9; 10];
    Alcotest.check opt_int "header-only reset" None (ntx fx.db 1021);
    Alcotest.(check int) "reset count" 10 s.reset;
    let cum i = Storage.ChainDB.get_chain_tx_count fx.db (mk_hash i) in
    Alcotest.(check (option int64)) "c: at 3 deleted" None (cum 3);
    Alcotest.(check (option int64)) "c: at 8 deleted" None (cum 8);
    Alcotest.(check (option int64)) "c: header-only deleted" None (cum 1021);
    Alcotest.(check (option int64)) "c: at 12 kept" (Some 84L) (cum 12);
    Alcotest.(check int) "cum_deleted" 3 s.cum_deleted)

let test_second_run_skipped () =
  with_fixture (fun fx ->
    ignore (first_run fx);
    (* Plant a value that a second pass WOULD reset. *)
    Storage.ChainDB.store_block_ntx fx.db (mk_hash 2) 777;
    (match run fx with
     | Ntx_reconcile.Skipped_already_done -> ()
     | Ntx_reconcile.Ran _ -> Alcotest.fail "second run was not skipped"
     | Ntx_reconcile.Failed e -> Alcotest.failf "failed: %s" e);
    Alcotest.check opt_int "untouched by skipped run" (Some 777) (ntx fx.db 2);
    Alcotest.(check bool) "marker persisted" true
      (Storage.ChainDB.get_meta fx.db Ntx_reconcile.marker_key <> None))

(* getblockheader on a header-only block answers nTx 0 (Core: nTx is 0
   until the block's transactions are received) — no oracle. *)
let test_getblockheader_header_only_ntx_zero () =
  Test_tmp.with_chaindb (fun db ->
    let network = Consensus.regtest in
    let chain = Sync.create_chain_state db network in
    let utxo = Utxo.UtxoSet.create db in
    let mempool =
      Mempool.create ~network ~require_standard:false ~verify_scripts:false
        ~utxo ~current_height:0 ()
    in
    let ctx : Rpc.rpc_context = {
      chain; mempool; peer_manager = Peer_manager.create network;
      wallet = None; wallet_manager = None;
      fee_estimator = Fee_estimation.create (); network;
      filter_index = None; utxo = None; data_dir = None;
      snapshot_activation = None;
    } in
    let g = network.Consensus.genesis_header in
    let hdr = { g with Types.prev_block = network.Consensus.genesis_hash;
                       timestamp = Int32.add g.Types.timestamp 600l } in
    let hash = Crypto.compute_block_hash hdr in
    Storage.ChainDB.store_block_header db hash hdr;
    let hex = Types.hash256_to_hex_display hash in
    match Rpc.dispatch_rpc ctx "getblockheader" [`String hex] with
    | Ok (`Assoc fs) ->
      Alcotest.(check bool) "nTx is 0" true (List.assoc_opt "nTx" fs = Some (`Int 0));
      Alcotest.check opt_int "nothing persisted" None
        (Storage.ChainDB.get_block_ntx db hash)
    | Ok j -> Alcotest.failf "unexpected %s" (Yojson.Safe.to_string j)
    | Error (c, m) -> Alcotest.failf "error %d %s" c m)

let () =
  Alcotest.run "R3 no-proxy (camlcoin)" [
    "source_guard", [
      Alcotest.test_case "no Core cookie / 8332 client in lib/" `Quick
        test_source_guard ];
    "ntx_reconcile", [
      Alcotest.test_case "body held -> recount" `Quick test_body_recount;
      Alcotest.test_case "validated, no body -> keep" `Quick
        test_validated_no_body_kept;
      Alcotest.test_case "not validated -> reset (+ derived c:)" `Quick
        test_not_validated_reset;
      Alcotest.test_case "second run skipped via marker" `Quick
        test_second_run_skipped ];
    "getblockheader", [
      Alcotest.test_case "header-only block -> nTx 0, no oracle" `Quick
        test_getblockheader_header_only_ntx_zero ];
  ]
