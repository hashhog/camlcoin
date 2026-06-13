(* W14x getnodeaddresses — camlcoin (OCaml)
   Regression test for the getnodeaddresses RPC handler.

   Reference: bitcoin-core/src/rpc/net.cpp:911-970 (getnodeaddresses) and
   src/netbase.cpp:100-128 (ParseNetwork / GetNetworkName).

   Core shape: a JSON ARRAY of objects, each with EXACTLY 5 keys in THIS
   serialized order:
       time     (NUM_TIME, unix seconds INTEGER)
       services (NUM, raw services bitfield as INTEGER — NOT a hex string)
       address  (STR, ip / .onion / .b32.i2p literal, NO port)
       port     (NUM, INTEGER)
       network  (STR: ipv4 / ipv6 / onion / i2p / cjdns / not_publicly_routable
                 / internal)

   Param semantics:
     count   (positional 0, default 1) = max returned; 0 = ALL; <0 -> error -8
             message EXACTLY "Address count out of range".
     network (positional 1, optional) lowercased; accept ONLY
             ipv4|ipv6|onion|i2p|cjdns; anything else -> error -8 message
             EXACTLY "Network not recognized: <raw arg>".
   Empty addrman -> [] (not an error). *)

open Camlcoin

(* Each make_ctx call gets its OWN db dir.  Reusing one path across tests
   triggers RocksDB MANIFEST corruption when a freshly-created store is
   reopened on top of a partially-removed directory, so we never reopen. *)
let db_counter = ref 0

let fresh_db_path () =
  incr db_counter;
  Printf.sprintf "/tmp/camlcoin_test_w14x_getnodeaddresses_db_%d_%d"
    (Unix.getpid ()) !db_counter

let rm_rf path =
  let rec go path =
    if Sys.file_exists path then begin
      if Sys.is_directory path then begin
        Array.iter (fun f -> go (Filename.concat path f)) (Sys.readdir path);
        Unix.rmdir path
      end else
        Unix.unlink path
    end
  in
  go path

(* Build a minimal RPC context whose peer_manager we control directly.
   getnodeaddresses only reaches into ctx.peer_manager, but the record is
   total so we populate every field with a throwaway chain/mempool/utxo. *)
let make_ctx () =
  let test_db_path = fresh_db_path () in
  rm_rf test_db_path;
  let db = Storage.ChainDB.create test_db_path in
  let utxo = Utxo.UtxoSet.create db in
  let mp =
    Mempool.create
      ~require_standard:false
      ~verify_scripts:false
      ~utxo
      ~current_height:0
      ()
  in
  let chain = Sync.create_chain_state db Consensus.mainnet in
  let pm = Peer_manager.create Consensus.mainnet in
  let fe = Fee_estimation.create () in
  let ctx : Rpc.rpc_context = {
    chain;
    mempool = mp;
    peer_manager = pm;
    wallet = None;
    wallet_manager = None;
    fee_estimator = fe;
    network = Consensus.mainnet;
    filter_index = None;
    utxo = None;
    data_dir = None;
    snapshot_activation = None;
  } in
  (ctx, pm)

(* Inject one known address with a fully controlled record so the emitted
   shape is deterministic (time/services/port/network all known). *)
let inject pm ~address ~port ~services ~last_connected =
  Peer_manager.add_known_addr pm {
    Peer_manager.address;
    port;
    services;
    last_connected;
    last_attempt = 0.0;
    failures = 0;
    banned_until = 0.0;
    source = Peer_manager.Addr;
    table_status = Peer_manager.NotInTable;
    last_success = 0.0;
  }

(* ---- small assoc helpers (used only AFTER the byte-order test) -------- *)

let obj_fields = function
  | `Assoc kvs -> kvs
  | _ -> Alcotest.fail "expected a JSON object"

let str_field obj k =
  match List.assoc_opt k (obj_fields obj) with
  | Some (`String s) -> s
  | _ -> Alcotest.failf "expected string field %s" k

(* ===================================================================
   Case 1: empty addrman -> [] (a JSON array, not an error)
   =================================================================== *)
let test_empty_addrman () =
  let (ctx, _pm) = make_ctx () in
  match Rpc.handle_getnodeaddresses ctx [] with
  | Error (code, msg) ->
    Alcotest.failf "empty addrman must not error (got %d %s)" code msg
  | Ok (`List []) -> ()
  | Ok other ->
    Alcotest.failf "empty addrman must be `List [] (got %s)"
      (Yojson.Safe.to_string other)

(* ===================================================================
   Case 2: default count (no args) caps the result at 1
   =================================================================== *)
let test_default_count_is_one () =
  let (ctx, pm) = make_ctx () in
  inject pm ~address:"1.2.3.4" ~port:8333 ~services:1033L ~last_connected:111.0;
  inject pm ~address:"5.6.7.8" ~port:8333 ~services:1033L ~last_connected:222.0;
  match Rpc.handle_getnodeaddresses ctx [] with
  | Ok (`List l) ->
    Alcotest.(check int) "default count returns exactly 1" 1 (List.length l)
  | Ok other ->
    Alcotest.failf "expected `List (got %s)" (Yojson.Safe.to_string other)
  | Error (code, msg) -> Alcotest.failf "unexpected error %d %s" code msg

(* ===================================================================
   Case 3: count 0 means ALL
   =================================================================== *)
let test_count_zero_returns_all () =
  let (ctx, pm) = make_ctx () in
  inject pm ~address:"1.2.3.4" ~port:8333 ~services:1033L ~last_connected:111.0;
  inject pm ~address:"5.6.7.8" ~port:8333 ~services:1033L ~last_connected:222.0;
  inject pm ~address:"20.0.0.1" ~port:8333 ~services:1L ~last_connected:333.0;
  match Rpc.handle_getnodeaddresses ctx [`Int 0] with
  | Ok (`List l) ->
    Alcotest.(check int) "count 0 returns all 3" 3 (List.length l)
  | Ok other ->
    Alcotest.failf "expected `List (got %s)" (Yojson.Safe.to_string other)
  | Error (code, msg) -> Alcotest.failf "unexpected error %d %s" code msg

(* ===================================================================
   Case 4: count < 0 -> error -8 "Address count out of range"
   =================================================================== *)
let test_negative_count_errors () =
  let (ctx, pm) = make_ctx () in
  inject pm ~address:"1.2.3.4" ~port:8333 ~services:1033L ~last_connected:1.0;
  match Rpc.handle_getnodeaddresses ctx [`Int (-1)] with
  | Error (code, msg) ->
    Alcotest.(check int) "negative count -> RPC_INVALID_PARAMETER (-8)"
      (-8) code;
    Alcotest.(check string) "exact error message"
      "Address count out of range" msg
  | Ok other ->
    Alcotest.failf "negative count must error (got %s)"
      (Yojson.Safe.to_string other)

(* ===================================================================
   Case 5: unrecognised network filter -> error -8
            "Network not recognized: <raw>"  (raw = the original arg)
   =================================================================== *)
let test_bad_network_errors () =
  let (ctx, pm) = make_ctx () in
  inject pm ~address:"1.2.3.4" ~port:8333 ~services:1033L ~last_connected:1.0;
  match Rpc.handle_getnodeaddresses ctx [`Int 0; `String "bogus"] with
  | Error (code, msg) ->
    Alcotest.(check int) "bad network -> RPC_INVALID_PARAMETER (-8)" (-8) code;
    Alcotest.(check string) "exact error message"
      "Network not recognized: bogus" msg
  | Ok other ->
    Alcotest.failf "bad network must error (got %s)"
      (Yojson.Safe.to_string other)

(* ===================================================================
   Case 6: SERIALIZED key order + types — the load-bearing assertion.
   We compare the ACTUAL emitted JSON bytes (Yojson.Safe.to_string), not
   an order-insensitive key lookup, so a reordering encoder or a hex-string
   services field would fail.  Core emits, in this order:
       time, services, address, port, network
   with services a BARE INTEGER (1033, not "1033" and not "0x409").
   =================================================================== *)
let test_serialized_order_and_types () =
  let (ctx, pm) = make_ctx () in
  inject pm ~address:"1.2.3.4" ~port:8333 ~services:1033L ~last_connected:1234.0;
  match Rpc.handle_getnodeaddresses ctx [`Int 0] with
  | Ok (`List [obj]) ->
    let bytes = Yojson.Safe.to_string obj in
    (* Built by explicit concatenation so no string-literal line
       continuation can sneak whitespace into the expected bytes. *)
    let expected =
      "{"
      ^ "\"time\":1234,"
      ^ "\"services\":1033,"
      ^ "\"address\":\"1.2.3.4\","
      ^ "\"port\":8333,"
      ^ "\"network\":\"ipv4\""
      ^ "}"
    in
    Alcotest.(check string)
      "exact serialized bytes: key order time,services,address,port,network \
       with services as a bare integer"
      expected
      bytes
  | Ok other ->
    Alcotest.failf "expected `List [single obj] (got %s)"
      (Yojson.Safe.to_string other)
  | Error (code, msg) -> Alcotest.failf "unexpected error %d %s" code msg

(* ===================================================================
   Case 7: network "ipv4" filter returns only ipv4 entries.
   Inject one IPv4 and one IPv6 address; filtering to ipv4 must drop the
   IPv6 one.  Also confirms the network name on the surviving entry.
   =================================================================== *)
let test_network_filter_ipv4 () =
  let (ctx, pm) = make_ctx () in
  inject pm ~address:"1.2.3.4"     ~port:8333 ~services:1033L ~last_connected:1.0;
  inject pm ~address:"2001:db8::1" ~port:8333 ~services:1033L ~last_connected:2.0;
  (* sanity: both are present when unfiltered *)
  (match Rpc.handle_getnodeaddresses ctx [`Int 0] with
   | Ok (`List l) -> Alcotest.(check int) "both addrs stored" 2 (List.length l)
   | Ok o -> Alcotest.failf "expected list (got %s)" (Yojson.Safe.to_string o)
   | Error (c, m) -> Alcotest.failf "unexpected error %d %s" c m);
  (* filter to ipv4: only the 1.2.3.4 entry survives *)
  match Rpc.handle_getnodeaddresses ctx [`Int 0; `String "ipv4"] with
  | Ok (`List l) ->
    Alcotest.(check int) "ipv4 filter returns exactly 1" 1 (List.length l);
    let obj = List.hd l in
    Alcotest.(check string) "surviving entry is the ipv4 address"
      "1.2.3.4" (str_field obj "address");
    Alcotest.(check string) "network field is ipv4"
      "ipv4" (str_field obj "network")
  | Ok other ->
    Alcotest.failf "expected `List (got %s)" (Yojson.Safe.to_string other)
  | Error (code, msg) -> Alcotest.failf "unexpected error %d %s" code msg

(* ===================================================================
   Case 8: a `network "ipv6"` filter that matches nothing -> [] (not error)
   =================================================================== *)
let test_network_filter_no_match () =
  let (ctx, pm) = make_ctx () in
  inject pm ~address:"1.2.3.4" ~port:8333 ~services:1033L ~last_connected:1.0;
  match Rpc.handle_getnodeaddresses ctx [`Int 0; `String "ipv6"] with
  | Ok (`List []) -> ()
  | Ok other ->
    Alcotest.failf "no-match filter must be `List [] (got %s)"
      (Yojson.Safe.to_string other)
  | Error (code, msg) -> Alcotest.failf "unexpected error %d %s" code msg

let () =
  Alcotest.run "w14x_getnodeaddresses" [
    "getnodeaddresses", [
      Alcotest.test_case "empty addrman -> []"           `Quick test_empty_addrman;
      Alcotest.test_case "default count is 1"            `Quick test_default_count_is_one;
      Alcotest.test_case "count 0 returns all"           `Quick test_count_zero_returns_all;
      Alcotest.test_case "count < 0 -> -8"               `Quick test_negative_count_errors;
      Alcotest.test_case "bad network -> -8"             `Quick test_bad_network_errors;
      Alcotest.test_case "serialized key order + types"  `Quick test_serialized_order_and_types;
      Alcotest.test_case "network=ipv4 filter"           `Quick test_network_filter_ipv4;
      Alcotest.test_case "network filter no match -> []" `Quick test_network_filter_no_match;
    ];
  ]
