(* Tests for peer manager and discovery *)

open Camlcoin

(* Test addr_source type *)
let test_addr_source () =
  let _ : Peer_manager.addr_source = Peer_manager.Dns in
  let _ : Peer_manager.addr_source = Peer_manager.Addr in
  let _ : Peer_manager.addr_source = Peer_manager.Manual in
  ()

(* Test peer_info creation *)
let test_peer_info () =
  let info : Peer_manager.peer_info = {
    address = "192.168.1.1";
    port = 8333;
    services = 9L;  (* NODE_NETWORK | NODE_WITNESS *)
    last_connected = 0.0;
    last_attempt = 0.0;
    failures = 0;
    banned_until = 0.0;
    source = Peer_manager.Dns;
  } in
  Alcotest.(check string) "address" "192.168.1.1" info.address;
  Alcotest.(check int) "port" 8333 info.port;
  Alcotest.(check int64) "services" 9L info.services;
  Alcotest.(check int) "failures" 0 info.failures

(* Test default config values *)
let test_default_config () =
  let cfg = Peer_manager.default_config in
  Alcotest.(check int) "max_outbound" 8 cfg.max_outbound;
  Alcotest.(check int) "max_inbound" 117 cfg.max_inbound;
  Alcotest.(check int) "max_failures" 5 cfg.max_failures

(* Test peer manager creation *)
let test_create () =
  let pm = Peer_manager.create Consensus.mainnet in
  Alcotest.(check int32) "initial height" 0l (Peer_manager.get_height pm);
  Alcotest.(check int) "initial peer count" 0 (Peer_manager.peer_count pm);
  Alcotest.(check int) "initial ready count" 0 (Peer_manager.ready_peer_count pm)

(* Test peer manager creation with custom config *)
let test_create_with_config () =
  let config = { Peer_manager.default_config with
    max_outbound = 4;
    max_inbound = 50;
  } in
  let pm = Peer_manager.create ~config Consensus.mainnet in
  Alcotest.(check int32) "initial height" 0l (Peer_manager.get_height pm)

(* Test height setting *)
let test_set_height () =
  let pm = Peer_manager.create Consensus.mainnet in
  Peer_manager.set_height pm 100000l;
  Alcotest.(check int32) "updated height" 100000l (Peer_manager.get_height pm)

(* Test is_banned with no addresses *)
let test_is_banned_empty () =
  let pm = Peer_manager.create Consensus.mainnet in
  Alcotest.(check bool) "not banned" false
    (Peer_manager.is_banned pm "192.168.1.1")

(* Test ban_addr *)
let test_ban_addr () =
  let pm = Peer_manager.create Consensus.mainnet in
  Peer_manager.ban_addr pm "192.168.1.1" ~duration:1000.0 ();
  Alcotest.(check bool) "is banned" true
    (Peer_manager.is_banned pm "192.168.1.1");
  (* Another address should not be banned *)
  Alcotest.(check bool) "other not banned" false
    (Peer_manager.is_banned pm "192.168.1.2")

(* Test add_known_addr *)
let test_add_known_addr () =
  let pm = Peer_manager.create Consensus.mainnet in
  let info : Peer_manager.peer_info = {
    address = "10.0.0.1";
    port = 8333;
    services = 9L;
    last_connected = 0.0;
    last_attempt = 0.0;
    failures = 0;
    banned_until = 0.0;
    source = Peer_manager.Manual;
  } in
  Peer_manager.add_known_addr pm info;
  let stats = Peer_manager.get_addr_stats pm in
  Alcotest.(check int) "total known" 1 stats.total_known

(* Test get_connection_candidates with no addresses *)
let test_get_candidates_empty () =
  let pm = Peer_manager.create Consensus.mainnet in
  let candidates = Peer_manager.get_connection_candidates pm 10 in
  Alcotest.(check int) "no candidates" 0 (List.length candidates)

(* Test get_connection_candidates filters banned *)
let test_get_candidates_filters_banned () =
  let pm = Peer_manager.create Consensus.mainnet in
  let info : Peer_manager.peer_info = {
    address = "10.0.0.1";
    port = 8333;
    services = 9L;
    last_connected = 0.0;
    last_attempt = 0.0;
    failures = 0;
    banned_until = Unix.gettimeofday () +. 1000.0;  (* Banned *)
    source = Peer_manager.Manual;
  } in
  Peer_manager.add_known_addr pm info;
  let candidates = Peer_manager.get_connection_candidates pm 10 in
  Alcotest.(check int) "banned filtered" 0 (List.length candidates)

(* Test get_connection_candidates returns valid candidates *)
let test_get_candidates_returns_valid () =
  let pm = Peer_manager.create Consensus.mainnet in
  let info : Peer_manager.peer_info = {
    address = "10.0.0.1";
    port = 8333;
    services = 9L;
    last_connected = 0.0;
    last_attempt = 0.0;  (* Never tried *)
    failures = 0;
    banned_until = 0.0;
    source = Peer_manager.Manual;
  } in
  Peer_manager.add_known_addr pm info;
  let candidates = Peer_manager.get_connection_candidates pm 10 in
  Alcotest.(check int) "one candidate" 1 (List.length candidates);
  let c = List.hd candidates in
  Alcotest.(check string) "correct address" "10.0.0.1" c.address

(* Test get_connection_candidates respects limit *)
let test_get_candidates_respects_limit () =
  let pm = Peer_manager.create Consensus.mainnet in
  for i = 1 to 10 do
    let info : Peer_manager.peer_info = {
      address = Printf.sprintf "10.0.0.%d" i;
      port = 8333;
      services = 9L;
      last_connected = 0.0;
      last_attempt = 0.0;
      failures = 0;
      banned_until = 0.0;
      source = Peer_manager.Manual;
    } in
    Peer_manager.add_known_addr pm info
  done;
  let candidates = Peer_manager.get_connection_candidates pm 3 in
  Alcotest.(check int) "limited to 3" 3 (List.length candidates)

(* Test fallback peers for mainnet *)
let test_mainnet_fallback_peers () =
  let fallback = Peer_manager.get_fallback_peers Consensus.mainnet in
  Alcotest.(check bool) "has fallback peers" true (List.length fallback > 0);
  List.iter (fun info ->
    Alcotest.(check int) "mainnet port" 8333 info.Peer_manager.port
  ) fallback

(* Test fallback peers for testnet *)
let test_testnet_fallback_peers () =
  let fallback = Peer_manager.get_fallback_peers Consensus.testnet in
  Alcotest.(check bool) "has fallback peers" true (List.length fallback > 0);
  List.iter (fun info ->
    Alcotest.(check int) "testnet port" 18333 info.Peer_manager.port
  ) fallback

(* Test addr_stats *)
let test_addr_stats () =
  let pm = Peer_manager.create Consensus.mainnet in
  let stats = Peer_manager.get_addr_stats pm in
  Alcotest.(check int) "initial total" 0 stats.total_known;
  Alcotest.(check int) "initial banned" 0 stats.banned;
  Alcotest.(check int) "initial tried" 0 stats.tried;
  Alcotest.(check int) "initial connected" 0 stats.connected

(* Test addr_stats with banned address *)
let test_addr_stats_with_banned () =
  let pm = Peer_manager.create Consensus.mainnet in
  Peer_manager.ban_addr pm "10.0.0.1" ~duration:1000.0 ();
  let stats = Peer_manager.get_addr_stats pm in
  Alcotest.(check int) "total" 1 stats.total_known;
  Alcotest.(check int) "banned" 1 stats.banned

(* Test find_peer_by_addr with no peers *)
let test_find_peer_by_addr_empty () =
  let pm = Peer_manager.create Consensus.mainnet in
  let result = Peer_manager.find_peer_by_addr pm "10.0.0.1" in
  Alcotest.(check bool) "not found" true (Option.is_none result)

(* Test find_peer_by_id with no peers *)
let test_find_peer_by_id_empty () =
  let pm = Peer_manager.create Consensus.mainnet in
  let result = Peer_manager.find_peer_by_id pm 0 in
  Alcotest.(check bool) "not found" true (Option.is_none result)

(* Test get_ready_peers with no peers *)
let test_get_ready_peers_empty () =
  let pm = Peer_manager.create Consensus.mainnet in
  let ready = Peer_manager.get_ready_peers pm in
  Alcotest.(check int) "no ready peers" 0 (List.length ready)

(* Test get_peer_stats with no peers *)
let test_get_peer_stats_empty () =
  let pm = Peer_manager.create Consensus.mainnet in
  let stats = Peer_manager.get_peer_stats pm in
  Alcotest.(check int) "no stats" 0 (List.length stats)

(* Test handle_addr with empty list *)
let test_handle_addr_empty () =
  let pm = Peer_manager.create Consensus.mainnet in
  Peer_manager.handle_addr pm [];
  let stats = Peer_manager.get_addr_stats pm in
  Alcotest.(check int) "still empty" 0 stats.total_known

(* Test handle_addr adds addresses *)
let test_handle_addr_adds () =
  let pm = Peer_manager.create Consensus.mainnet in
  (* Create a net_addr with IPv4-mapped IPv6 address 192.168.1.1 *)
  let addr_bytes = Cstruct.create 16 in
  Cstruct.set_uint8 addr_bytes 10 0xFF;
  Cstruct.set_uint8 addr_bytes 11 0xFF;
  Cstruct.set_uint8 addr_bytes 12 192;
  Cstruct.set_uint8 addr_bytes 13 168;
  Cstruct.set_uint8 addr_bytes 14 1;
  Cstruct.set_uint8 addr_bytes 15 1;
  let net_addr : Types.net_addr = {
    services = 9L;
    addr = addr_bytes;
    port = 8333;
  } in
  Peer_manager.handle_addr pm [(0l, net_addr)];
  let stats = Peer_manager.get_addr_stats pm in
  Alcotest.(check int) "one address added" 1 stats.total_known

(* Test handle_addr deduplicates *)
let test_handle_addr_dedupes () =
  let pm = Peer_manager.create Consensus.mainnet in
  let addr_bytes = Cstruct.create 16 in
  Cstruct.set_uint8 addr_bytes 10 0xFF;
  Cstruct.set_uint8 addr_bytes 11 0xFF;
  Cstruct.set_uint8 addr_bytes 12 10;
  Cstruct.set_uint8 addr_bytes 13 0;
  Cstruct.set_uint8 addr_bytes 14 0;
  Cstruct.set_uint8 addr_bytes 15 1;
  let net_addr : Types.net_addr = {
    services = 9L;
    addr = addr_bytes;
    port = 8333;
  } in
  (* Add same address twice *)
  Peer_manager.handle_addr pm [(0l, net_addr)];
  Peer_manager.handle_addr pm [(0l, net_addr)];
  let stats = Peer_manager.get_addr_stats pm in
  Alcotest.(check int) "still one" 1 stats.total_known

(* Test build_locator with empty database *)
let test_build_locator_empty () =
  (* Create temp directory for test database *)
  let tmp_dir = Filename.temp_file "chaindb_test" "" in
  Unix.unlink tmp_dir;
  Unix.mkdir tmp_dir 0o755;
  let db = Storage.ChainDB.create tmp_dir in
  let locator = Peer_manager.build_locator db 0 in
  (* Should be empty or just genesis (which doesn't exist) *)
  Alcotest.(check bool) "locator small" true (List.length locator <= 1);
  Storage.ChainDB.close db;
  (* Cleanup *)
  ignore (Sys.command (Printf.sprintf "rm -rf %s" tmp_dir))

(* Test build_locator with some blocks *)
let test_build_locator_with_blocks () =
  let tmp_dir = Filename.temp_file "chaindb_test" "" in
  Unix.unlink tmp_dir;
  Unix.mkdir tmp_dir 0o755;
  let db = Storage.ChainDB.create tmp_dir in
  (* Add some block hashes *)
  for i = 0 to 20 do
    let hash = Cstruct.create 32 in
    Cstruct.set_uint8 hash 0 i;
    Storage.ChainDB.set_height_hash db i hash
  done;
  let locator = Peer_manager.build_locator db 20 in
  (* Should have entries *)
  Alcotest.(check bool) "has entries" true (List.length locator > 0);
  (* First entry should be tip (height 20) *)
  let tip = List.hd locator in
  Alcotest.(check int) "tip byte" 20 (Cstruct.get_uint8 tip 0);
  (* Last entry should be genesis (height 0) *)
  let genesis = List.hd (List.rev locator) in
  Alcotest.(check int) "genesis byte" 0 (Cstruct.get_uint8 genesis 0);
  Storage.ChainDB.close db;
  ignore (Sys.command (Printf.sprintf "rm -rf %s" tmp_dir))

(* Test build_locator exponential stepping *)
let test_build_locator_exponential () =
  let tmp_dir = Filename.temp_file "chaindb_test" "" in
  Unix.unlink tmp_dir;
  Unix.mkdir tmp_dir 0o755;
  let db = Storage.ChainDB.create tmp_dir in
  (* Add 100 block hashes *)
  for i = 0 to 99 do
    let hash = Cstruct.create 32 in
    Cstruct.BE.set_uint32 hash 0 (Int32.of_int i);
    Storage.ChainDB.set_height_hash db i hash
  done;
  let locator = Peer_manager.build_locator db 99 in
  (* Should have reasonable number of entries due to exponential stepping *)
  (* First 10 are sequential, then exponential *)
  Alcotest.(check bool) "reasonable size" true
    (List.length locator > 10 && List.length locator < 50);
  Storage.ChainDB.close db;
  ignore (Sys.command (Printf.sprintf "rm -rf %s" tmp_dir))

(* All tests *)
let () =
  Alcotest.run "Peer_manager" [
    "types", [
      Alcotest.test_case "addr_source" `Quick test_addr_source;
      Alcotest.test_case "peer_info" `Quick test_peer_info;
      Alcotest.test_case "default_config" `Quick test_default_config;
    ];
    "creation", [
      Alcotest.test_case "create" `Quick test_create;
      Alcotest.test_case "create_with_config" `Quick test_create_with_config;
      Alcotest.test_case "set_height" `Quick test_set_height;
    ];
    "banning", [
      Alcotest.test_case "is_banned_empty" `Quick test_is_banned_empty;
      Alcotest.test_case "ban_addr" `Quick test_ban_addr;
    ];
    "known_addrs", [
      Alcotest.test_case "add_known_addr" `Quick test_add_known_addr;
      Alcotest.test_case "get_candidates_empty" `Quick test_get_candidates_empty;
      Alcotest.test_case "get_candidates_filters_banned" `Quick
        test_get_candidates_filters_banned;
      Alcotest.test_case "get_candidates_returns_valid" `Quick
        test_get_candidates_returns_valid;
      Alcotest.test_case "get_candidates_respects_limit" `Quick
        test_get_candidates_respects_limit;
    ];
    "fallback_peers", [
      Alcotest.test_case "mainnet" `Quick test_mainnet_fallback_peers;
      Alcotest.test_case "testnet" `Quick test_testnet_fallback_peers;
    ];
    "stats", [
      Alcotest.test_case "addr_stats" `Quick test_addr_stats;
      Alcotest.test_case "addr_stats_with_banned" `Quick test_addr_stats_with_banned;
    ];
    "peer_lookup", [
      Alcotest.test_case "find_by_addr_empty" `Quick test_find_peer_by_addr_empty;
      Alcotest.test_case "find_by_id_empty" `Quick test_find_peer_by_id_empty;
      Alcotest.test_case "get_ready_peers_empty" `Quick test_get_ready_peers_empty;
      Alcotest.test_case "get_peer_stats_empty" `Quick test_get_peer_stats_empty;
    ];
    "handle_addr", [
      Alcotest.test_case "empty" `Quick test_handle_addr_empty;
      Alcotest.test_case "adds" `Quick test_handle_addr_adds;
      Alcotest.test_case "dedupes" `Quick test_handle_addr_dedupes;
    ];
    "locator", [
      Alcotest.test_case "empty_db" `Quick test_build_locator_empty;
      Alcotest.test_case "with_blocks" `Quick test_build_locator_with_blocks;
      Alcotest.test_case "exponential" `Quick test_build_locator_exponential;
    ];
  ]
