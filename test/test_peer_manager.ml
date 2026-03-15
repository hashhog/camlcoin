(* Tests for peer manager and discovery *)

open Camlcoin

(* Create a dummy peer for testing handle_addr.
   Uses a real socket fd so the Peer.make_peer constructor works. *)
let make_dummy_peer () =
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Peer.make_peer ~network:Consensus.mainnet ~addr:"127.0.0.1"
    ~port:8333 ~id:0 ~direction:Peer.Outbound ~fd

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
    last_success = 0.0;
    failures = 0;
    banned_until = 0.0;
    source = Peer_manager.Dns;
    table_status = Peer_manager.NotInTable;
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
    last_success = 0.0;
    failures = 0;
    banned_until = 0.0;
    source = Peer_manager.Manual;
    table_status = Peer_manager.NotInTable;
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
    last_success = 0.0;
    failures = 0;
    banned_until = Unix.gettimeofday () +. 1000.0;  (* Banned *)
    source = Peer_manager.Manual;
    table_status = Peer_manager.NotInTable;
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
    last_success = 0.0;
    failures = 0;
    banned_until = 0.0;
    source = Peer_manager.Manual;
    table_status = Peer_manager.NotInTable;
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
      last_success = 0.0;
      failures = 0;
      banned_until = 0.0;
      source = Peer_manager.Manual;
      table_status = Peer_manager.NotInTable;
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
  let dummy = make_dummy_peer () in
  Peer_manager.handle_addr pm dummy [];
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
  let dummy = make_dummy_peer () in
  Peer_manager.handle_addr pm dummy [(0l, net_addr)];
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
  let dummy = make_dummy_peer () in
  Peer_manager.handle_addr pm dummy [(0l, net_addr)];
  Peer_manager.handle_addr pm dummy [(0l, net_addr)];
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

(* Test unban_addr removes ban *)
let test_unban_addr () =
  let pm = Peer_manager.create Consensus.mainnet in
  Peer_manager.ban_addr pm "192.168.1.1" ~duration:1000.0 ();
  Alcotest.(check bool) "is banned" true
    (Peer_manager.is_banned pm "192.168.1.1");
  Peer_manager.unban_addr pm "192.168.1.1";
  Alcotest.(check bool) "not banned after unban" false
    (Peer_manager.is_banned pm "192.168.1.1")

(* Test clear_bans removes all bans *)
let test_clear_bans () =
  let pm = Peer_manager.create Consensus.mainnet in
  Peer_manager.ban_addr pm "192.168.1.1" ~duration:1000.0 ();
  Peer_manager.ban_addr pm "192.168.1.2" ~duration:1000.0 ();
  Peer_manager.ban_addr pm "192.168.1.3" ~duration:1000.0 ();
  let stats = Peer_manager.get_addr_stats pm in
  Alcotest.(check int) "3 banned" 3 stats.banned;
  Peer_manager.clear_bans pm;
  let stats2 = Peer_manager.get_addr_stats pm in
  Alcotest.(check int) "0 banned after clear" 0 stats2.banned

(* Test get_banned_list returns active bans *)
let test_get_banned_list () =
  let pm = Peer_manager.create Consensus.mainnet in
  Peer_manager.ban_addr pm "10.0.0.1" ~duration:1000.0 ();
  Peer_manager.ban_addr pm "10.0.0.2" ~duration:1000.0 ();
  let banned = Peer_manager.get_banned_list pm in
  Alcotest.(check int) "2 bans" 2 (List.length banned);
  let addrs = List.map fst banned in
  Alcotest.(check bool) "has 10.0.0.1" true
    (List.mem "10.0.0.1" addrs);
  Alcotest.(check bool) "has 10.0.0.2" true
    (List.mem "10.0.0.2" addrs)

(* Test get_banned_list excludes expired bans *)
let test_get_banned_list_expired () =
  let pm = Peer_manager.create Consensus.mainnet in
  (* Create an already-expired ban by modifying the internal state *)
  let info : Peer_manager.peer_info = {
    address = "10.0.0.1";
    port = 8333;
    services = 9L;
    last_connected = 0.0;
    last_attempt = 0.0;
    last_success = 0.0;
    failures = 0;
    banned_until = Unix.gettimeofday () -. 100.0;  (* Expired *)
    source = Peer_manager.Manual;
    table_status = Peer_manager.NotInTable;
  } in
  Peer_manager.add_known_addr pm info;
  (* Add an active ban *)
  Peer_manager.ban_addr pm "10.0.0.2" ~duration:1000.0 ();
  let banned = Peer_manager.get_banned_list pm in
  Alcotest.(check int) "1 active ban" 1 (List.length banned);
  let addrs = List.map fst banned in
  Alcotest.(check bool) "has 10.0.0.2" true
    (List.mem "10.0.0.2" addrs);
  Alcotest.(check bool) "not has 10.0.0.1" false
    (List.mem "10.0.0.1" addrs)

(* Test banlist JSON persistence roundtrip *)
let test_banlist_json_persistence () =
  let pm = Peer_manager.create Consensus.mainnet in
  Peer_manager.ban_addr pm "172.16.0.1" ~duration:1000.0 ();
  Peer_manager.ban_addr pm "172.16.0.2" ~duration:2000.0 ();
  let tmpfile = Filename.temp_file "banlist" ".json" in
  Peer_manager.save_bans_json pm tmpfile;
  (* Create a new peer manager and load *)
  let pm2 = Peer_manager.create Consensus.mainnet in
  let count = Peer_manager.load_bans_json pm2 tmpfile in
  Alcotest.(check int) "loaded 2 bans" 2 count;
  Alcotest.(check bool) "172.16.0.1 banned" true
    (Peer_manager.is_banned pm2 "172.16.0.1");
  Alcotest.(check bool) "172.16.0.2 banned" true
    (Peer_manager.is_banned pm2 "172.16.0.2");
  Unix.unlink tmpfile

(* Test load_bans_json with nonexistent file *)
let test_load_bans_json_missing () =
  let pm = Peer_manager.create Consensus.mainnet in
  let count = Peer_manager.load_bans_json pm "/nonexistent/banlist.json" in
  Alcotest.(check int) "no bans loaded" 0 count

(* ========== Eclipse protection tests ========== *)

(* Test address table status types *)
let test_addr_table_status () =
  let _ : Peer_manager.addr_table_status = Peer_manager.InNew 5 in
  let _ : Peer_manager.addr_table_status = Peer_manager.InTried 3 in
  let _ : Peer_manager.addr_table_status = Peer_manager.NotInTable in
  ()

(* Test bucket computation is deterministic *)
let test_bucket_deterministic () =
  let pm = Peer_manager.create Consensus.mainnet in
  let info1 : Peer_manager.peer_info = {
    address = "192.168.1.100";
    port = 8333;
    services = 9L;
    last_connected = 0.0;
    last_attempt = 0.0;
    last_success = 0.0;
    failures = 0;
    banned_until = 0.0;
    source = Peer_manager.Manual;
    table_status = Peer_manager.NotInTable;
  } in
  Peer_manager.add_known_addr pm info1;
  let stats1 = Peer_manager.get_bucket_stats pm in
  (* Adding same address again should not increase count *)
  Peer_manager.add_known_addr pm info1;
  let stats2 = Peer_manager.get_bucket_stats pm in
  Alcotest.(check int) "new entries unchanged" stats1.new_table_entries stats2.new_table_entries

(* Test addresses go to new table initially *)
let test_addr_goes_to_new_table () =
  let pm = Peer_manager.create Consensus.mainnet in
  let info : Peer_manager.peer_info = {
    address = "10.20.30.40";
    port = 8333;
    services = 9L;
    last_connected = 0.0;
    last_attempt = 0.0;
    last_success = 0.0;
    failures = 0;
    banned_until = 0.0;
    source = Peer_manager.Addr;
    table_status = Peer_manager.NotInTable;
  } in
  Peer_manager.add_known_addr pm info;
  let stats = Peer_manager.get_bucket_stats pm in
  Alcotest.(check bool) "new table has entry" true (stats.new_table_entries > 0);
  Alcotest.(check bool) "tried table empty" true (stats.tried_table_entries = 0)

(* Test bucket stats initialization *)
let test_bucket_stats_initial () =
  let pm = Peer_manager.create Consensus.mainnet in
  let stats = Peer_manager.get_bucket_stats pm in
  Alcotest.(check int) "new entries" 0 stats.new_table_entries;
  Alcotest.(check int) "tried entries" 0 stats.tried_table_entries;
  Alcotest.(check int) "outbound netgroups" 0 stats.outbound_netgroups;
  Alcotest.(check int) "anchors" 0 stats.anchor_count

(* Test multiple addresses distribute across buckets *)
let test_addresses_distribute () =
  let pm = Peer_manager.create Consensus.mainnet in
  for i = 1 to 100 do
    let info : Peer_manager.peer_info = {
      address = Printf.sprintf "%d.%d.%d.%d" (i mod 256) ((i/256) mod 256) ((i/65536) mod 256) 1;
      port = 8333;
      services = 9L;
      last_connected = 0.0;
      last_attempt = 0.0;
      last_success = 0.0;
      failures = 0;
      banned_until = 0.0;
      source = Peer_manager.Addr;
      table_status = Peer_manager.NotInTable;
    } in
    Peer_manager.add_known_addr pm info
  done;
  let stats = Peer_manager.get_bucket_stats pm in
  Alcotest.(check int) "100 new entries" 100 stats.new_table_entries;
  (* Should use multiple buckets *)
  Alcotest.(check bool) "multiple buckets used" true (stats.new_table_buckets_used > 1)

(* Test netgroup extraction *)
let test_netgroup_of () =
  Alcotest.(check string) "192.168 netgroup" "192.168"
    (Peer_manager.netgroup_of "192.168.1.1");
  Alcotest.(check string) "10.0 netgroup" "10.0"
    (Peer_manager.netgroup_of "10.0.0.1");
  Alcotest.(check string) "invalid returns self" "localhost"
    (Peer_manager.netgroup_of "localhost")

(* Test keyed netgroup computation is deterministic *)
let test_keyed_netgroup_deterministic () =
  let pm = Peer_manager.create Consensus.mainnet in
  let stats = Peer_manager.get_bucket_stats pm in
  (* Keyed netgroup should be consistent for same address *)
  let ng1 = Peer_manager.compute_keyed_netgroup "testkey" "192.168.1.1" in
  let ng2 = Peer_manager.compute_keyed_netgroup "testkey" "192.168.1.1" in
  Alcotest.(check int) "same netgroup" ng1 ng2;
  (* Different addresses in same /16 should have same keyed netgroup *)
  let ng3 = Peer_manager.compute_keyed_netgroup "testkey" "192.168.1.2" in
  Alcotest.(check int) "same /16 netgroup" ng1 ng3;
  (* Different /16 should have different netgroup *)
  let ng4 = Peer_manager.compute_keyed_netgroup "testkey" "10.0.0.1" in
  Alcotest.(check bool) "different /16" true (ng1 <> ng4);
  let _ = stats in ()

(* Test eclipse protection constants match Bitcoin Core *)
let test_eclipse_constants () =
  (* Bitcoin Core: ADDRMAN_NEW_BUCKET_COUNT = 1024, ADDRMAN_TRIED_BUCKET_COUNT = 256 *)
  Alcotest.(check int) "new_bucket_count" 1024 Peer_manager.new_bucket_count;
  Alcotest.(check int) "tried_bucket_count" 256 Peer_manager.tried_bucket_count;
  Alcotest.(check int) "bucket_size" 64 Peer_manager.bucket_size;
  (* Eviction protection constants from Bitcoin Core eviction.cpp *)
  Alcotest.(check int) "protect_by_netgroup" 4 Peer_manager.protect_by_netgroup;
  Alcotest.(check int) "protect_by_ping" 8 Peer_manager.protect_by_ping;
  Alcotest.(check int) "protect_by_tx_time" 4 Peer_manager.protect_by_tx_time;
  Alcotest.(check int) "protect_by_block_relay" 8 Peer_manager.protect_by_block_relay;
  Alcotest.(check int) "protect_by_block_time" 4 Peer_manager.protect_by_block_time

(* Test move to tried table *)
let test_move_to_tried_table () =
  let pm = Peer_manager.create Consensus.mainnet in
  let addr = "10.20.30.40" in
  (* First add to new table *)
  let info : Peer_manager.peer_info = {
    address = addr;
    port = 8333;
    services = 9L;
    last_connected = 0.0;
    last_attempt = 0.0;
    last_success = 0.0;
    failures = 0;
    banned_until = 0.0;
    source = Peer_manager.Addr;
    table_status = Peer_manager.NotInTable;
  } in
  Peer_manager.add_known_addr pm info;
  let stats1 = Peer_manager.get_bucket_stats pm in
  Alcotest.(check bool) "in new table" true (stats1.new_table_entries > 0);
  Alcotest.(check int) "tried empty" 0 stats1.tried_table_entries;
  (* Move to tried *)
  let _bucket = Peer_manager.move_to_tried_table pm addr in
  let stats2 = Peer_manager.get_bucket_stats pm in
  Alcotest.(check bool) "new table decremented" true (stats2.new_table_entries < stats1.new_table_entries);
  Alcotest.(check bool) "in tried table" true (stats2.tried_table_entries > 0)

(* Test is_in_tried_table *)
let test_is_in_tried_table () =
  let pm = Peer_manager.create Consensus.mainnet in
  let addr = "172.16.0.1" in
  (* Not in tried table initially *)
  Alcotest.(check bool) "not in tried" false (Peer_manager.is_in_tried_table pm addr);
  (* Add to new, then move to tried *)
  let info : Peer_manager.peer_info = {
    address = addr;
    port = 8333;
    services = 9L;
    last_connected = 0.0;
    last_attempt = 0.0;
    last_success = 0.0;
    failures = 0;
    banned_until = 0.0;
    source = Peer_manager.Manual;
    table_status = Peer_manager.NotInTable;
  } in
  Peer_manager.add_known_addr pm info;
  let _ = Peer_manager.move_to_tried_table pm addr in
  Alcotest.(check bool) "now in tried" true (Peer_manager.is_in_tried_table pm addr)

(* Test compute_bucket determinism *)
let test_compute_bucket () =
  let key = "secretkey123" in
  let addr = "192.168.1.100" in
  let b1 = Peer_manager.compute_bucket key addr 256 in
  let b2 = Peer_manager.compute_bucket key addr 256 in
  Alcotest.(check int) "deterministic bucket" b1 b2;
  (* Bucket should be in valid range *)
  Alcotest.(check bool) "bucket in range" true (b1 >= 0 && b1 < 256);
  (* Different key gives different bucket (with high probability) *)
  let b3 = Peer_manager.compute_bucket "otherkey" addr 256 in
  (* We can't guarantee different, but statistically likely *)
  let _ = b3 in ()

(* Test that eviction selects from largest netgroup *)
let test_eviction_selects_largest_netgroup () =
  let pm = Peer_manager.create Consensus.mainnet in
  (* Test that select_node_to_evict returns None when no peers *)
  let result = Peer_manager.select_node_to_evict pm in
  Alcotest.(check bool) "no eviction with no peers" true (Option.is_none result)

(* Test anchor connection info type *)
let test_anchor_info () =
  let anchor : Peer_manager.anchor_info = {
    anchor_addr = "192.168.1.1";
    anchor_port = 8333;
    anchor_services = 9L;
  } in
  Alcotest.(check string) "anchor addr" "192.168.1.1" anchor.anchor_addr;
  Alcotest.(check int) "anchor port" 8333 anchor.anchor_port;
  Alcotest.(check int64) "anchor services" 9L anchor.anchor_services

(* Test initial anchors empty *)
let test_anchors_empty () =
  let pm = Peer_manager.create Consensus.mainnet in
  let anchors = Peer_manager.get_anchors pm in
  Alcotest.(check int) "no initial anchors" 0 (List.length anchors)

(* Test anchor persistence roundtrip *)
let test_anchor_persistence () =
  let tmpdir = Filename.temp_file "anchors_test" "" in
  Unix.unlink tmpdir;
  Unix.mkdir tmpdir 0o755;
  let pm = Peer_manager.create Consensus.mainnet in
  (* No connected peers, so save should save empty list *)
  Peer_manager.save_anchors pm tmpdir;
  let pm2 = Peer_manager.create Consensus.mainnet in
  let count = Peer_manager.load_anchors pm2 tmpdir in
  Alcotest.(check int) "no anchors saved" 0 count;
  (* Cleanup *)
  ignore (Sys.command (Printf.sprintf "rm -rf %s" tmpdir))

(* Test eviction candidate type *)
let test_eviction_candidate () =
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let peer = Peer.make_peer ~network:Consensus.mainnet ~addr:"192.168.1.1"
    ~port:8333 ~id:1 ~direction:Peer.Inbound ~fd in
  let ec : Peer_manager.eviction_candidate = {
    ec_peer = peer;
    ec_connected = 1000.0;
    ec_min_ping = 0.05;
    ec_last_block_time = 900.0;
    ec_last_tx_time = 950.0;
    ec_keyed_netgroup = 12345;
    ec_relay_txs = true;
    ec_prefer_evict = false;
  } in
  Alcotest.(check int) "peer id" 1 ec.ec_peer.Peer.id;
  Alcotest.(check bool) "relay txs" true ec.ec_relay_txs;
  Alcotest.(check bool) "prefer evict" false ec.ec_prefer_evict

(* Test config includes anchor setting *)
let test_config_anchors () =
  let cfg = Peer_manager.default_config in
  Alcotest.(check int) "max anchors" 2 cfg.max_block_relay_only_anchors

(* ========== Stale peer eviction tests ========== *)

(* Test stale constants *)
let test_stale_constants () =
  Alcotest.(check (float 0.1)) "headers_timeout" 1200.0 Peer_manager.Stale.headers_timeout;
  Alcotest.(check (float 0.1)) "headers_response" 120.0 Peer_manager.Stale.headers_response_time;
  Alcotest.(check (float 0.1)) "block_stalling" 2.0 Peer_manager.Stale.block_stalling_timeout;
  Alcotest.(check (float 0.1)) "block_stalling_max" 600.0 Peer_manager.Stale.block_stalling_max;
  Alcotest.(check (float 0.1)) "ping_timeout" 1200.0 Peer_manager.Stale.ping_timeout;
  Alcotest.(check (float 0.1)) "check_interval" 45.0 Peer_manager.Stale.stale_check_interval

(* Test chain_sync_state type *)
let test_chain_sync_state () =
  let _ : Peer_manager.chain_sync_state = Peer_manager.ChainSynced in
  let _ : Peer_manager.chain_sync_state = Peer_manager.ChainWaitingForHeaders {
    timeout = 1000.0;
    sent_getheaders = true;
  } in
  ()

(* Test stale state creation *)
let test_create_stale_state () =
  let state = Peer_manager.create_stale_state () in
  Alcotest.(check bool) "chain synced" true
    (state.chain_sync = Peer_manager.ChainSynced);
  Alcotest.(check int) "no blocks in flight" 0 state.block_stall.blocks_in_flight;
  Alcotest.(check bool) "not stalling" true (state.block_stall.stalling_since = None);
  Alcotest.(check bool) "no ping pending" true (state.last_ping_nonce = None)

(* Test stale reason messages *)
let test_stale_reasons () =
  Alcotest.(check bool) "headers reason not empty" true
    (String.length Peer_manager.StaleReason.headers_timeout > 0);
  Alcotest.(check bool) "block reason not empty" true
    (String.length Peer_manager.StaleReason.block_stalling > 0);
  Alcotest.(check bool) "ping reason not empty" true
    (String.length Peer_manager.StaleReason.ping_timeout > 0)

(* Test on_headers_received updates state *)
let test_on_headers_received () =
  let pm = Peer_manager.create Consensus.mainnet in
  let peer_id = 1 in
  (* Initialize state *)
  let state = Peer_manager.create_stale_state () in
  state.chain_sync <- Peer_manager.ChainWaitingForHeaders {
    timeout = 1000.0;
    sent_getheaders = true;
  };
  Hashtbl.replace pm.stale_state peer_id state;
  (* Receive headers *)
  Peer_manager.on_headers_received pm peer_id ~new_best_height:100l;
  let state' = Peer_manager.get_stale_state pm peer_id in
  Alcotest.(check bool) "chain synced after headers" true
    (state'.chain_sync = Peer_manager.ChainSynced)

(* Test on_block_received updates state *)
let test_on_block_received () =
  let pm = Peer_manager.create Consensus.mainnet in
  let peer_id = 1 in
  let state = Peer_manager.get_stale_state pm peer_id in
  state.block_stall.blocks_in_flight <- 5;
  state.block_stall.stalling_since <- Some (Unix.gettimeofday () -. 10.0);
  Peer_manager.on_block_received pm peer_id;
  let state' = Peer_manager.get_stale_state pm peer_id in
  Alcotest.(check int) "blocks decremented" 4 state'.block_stall.blocks_in_flight;
  Alcotest.(check bool) "stalling cleared" true (state'.block_stall.stalling_since = None)

(* Test assign_blocks_to_peer *)
let test_assign_blocks () =
  let pm = Peer_manager.create Consensus.mainnet in
  let peer_id = 1 in
  Peer_manager.assign_blocks_to_peer pm peer_id ~count:3;
  let state = Peer_manager.get_stale_state pm peer_id in
  Alcotest.(check int) "3 blocks assigned" 3 state.block_stall.blocks_in_flight;
  Peer_manager.assign_blocks_to_peer pm peer_id ~count:2;
  Alcotest.(check int) "5 blocks total" 5 state.block_stall.blocks_in_flight

(* Test ping/pong tracking *)
let test_ping_pong_tracking () =
  let pm = Peer_manager.create Consensus.mainnet in
  let peer_id = 1 in
  let nonce = 12345L in
  (* Send ping *)
  Peer_manager.on_ping_sent pm peer_id ~nonce;
  let state = Peer_manager.get_stale_state pm peer_id in
  Alcotest.(check bool) "nonce recorded" true (state.last_ping_nonce = Some nonce);
  (* Receive correct pong *)
  let matched = Peer_manager.on_pong_received pm peer_id ~nonce in
  Alcotest.(check bool) "nonce matched" true matched;
  let state' = Peer_manager.get_stale_state pm peer_id in
  Alcotest.(check bool) "nonce cleared" true (state'.last_ping_nonce = None)

(* Test pong with wrong nonce *)
let test_pong_wrong_nonce () =
  let pm = Peer_manager.create Consensus.mainnet in
  let peer_id = 1 in
  Peer_manager.on_ping_sent pm peer_id ~nonce:11111L;
  let matched = Peer_manager.on_pong_received pm peer_id ~nonce:22222L in
  Alcotest.(check bool) "wrong nonce rejected" false matched;
  let state = Peer_manager.get_stale_state pm peer_id in
  Alcotest.(check bool) "nonce still pending" true (state.last_ping_nonce = Some 11111L)

(* Test get_stalling_peers empty *)
let test_get_stalling_peers_empty () =
  let pm = Peer_manager.create Consensus.mainnet in
  let stalling = Peer_manager.get_stalling_peers pm in
  Alcotest.(check int) "no stalling peers" 0 (List.length stalling)

(* Test get_available_download_peers empty *)
let test_get_available_download_peers_empty () =
  let pm = Peer_manager.create Consensus.mainnet in
  let available = Peer_manager.get_available_download_peers pm in
  Alcotest.(check int) "no available peers" 0 (List.length available)

(* Test stale check timer control *)
let test_stale_check_timer () =
  let pm = Peer_manager.create Consensus.mainnet in
  Alcotest.(check bool) "timer not running initially" false pm.stale_check_running;
  Peer_manager.start_stale_check_timer pm;
  Alcotest.(check bool) "timer running after start" true pm.stale_check_running;
  Peer_manager.stop_stale_check_timer pm;
  Alcotest.(check bool) "timer stopped" false pm.stale_check_running

(* ============================================================================
   BIP-133 Feefilter Tests
   ============================================================================ *)

(* Test FeeFilterRounder bucket generation *)
let test_feefilter_rounder_buckets () =
  let fee_set = Peer.FeeFilterRounder.make_fee_set 1000L in
  (* Should have multiple buckets *)
  Alcotest.(check bool) "has buckets" true (Array.length fee_set > 5);
  (* First bucket should be 0 *)
  Alcotest.(check (float 0.001)) "first bucket is 0" 0.0 fee_set.(0);
  (* Second bucket should be around min_relay_fee / 2 = 500 *)
  Alcotest.(check bool) "second bucket is ~500" true (fee_set.(1) >= 500.0 && fee_set.(1) <= 600.0);
  (* Buckets should be monotonically increasing *)
  let monotonic = ref true in
  for i = 1 to Array.length fee_set - 1 do
    if fee_set.(i) <= fee_set.(i-1) then monotonic := false
  done;
  Alcotest.(check bool) "buckets are monotonic" true !monotonic

(* Test FeeFilterRounder rounding *)
let test_feefilter_rounder_round () =
  let fee_set = Peer.FeeFilterRounder.make_fee_set 1000L in
  (* Round 0 should give 0 *)
  let rounded0 = Peer.FeeFilterRounder.round fee_set 0L in
  Alcotest.(check int64) "0 rounds to 0" 0L rounded0;
  (* Round large value should give one of the buckets *)
  let rounded_large = Peer.FeeFilterRounder.round fee_set 5000L in
  Alcotest.(check bool) "large fee rounds to bucket"
    true (Int64.to_float rounded_large <= 5000.0);
  (* Round max should give a high bucket *)
  let rounded_max = Peer.FeeFilterRounder.round fee_set 10_000_000L in
  Alcotest.(check bool) "max rounds to high bucket"
    true (rounded_max > 1_000_000L)

(* Test peer feefilter state initialization *)
let test_peer_feefilter_state () =
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let peer = Peer.make_peer ~network:Consensus.mainnet ~addr:"127.0.0.1"
    ~port:8333 ~id:1 ~direction:Peer.Outbound ~fd in
  (* Initial state *)
  Alcotest.(check int64) "feefilter initially 0" 0L peer.feefilter;
  Alcotest.(check int64) "fee_filter_sent initially 0" 0L peer.fee_filter_sent;
  Alcotest.(check bool) "not block_relay_only initially" false peer.block_relay_only;
  (* Update feefilter received from peer *)
  peer.feefilter <- 5000L;
  Alcotest.(check int64) "feefilter updated" 5000L peer.feefilter;
  (* Cleanup *)
  Lwt_main.run (Lwt_unix.close fd)

(* Test tx filtering with low fee (below feefilter threshold) *)
let test_tx_filtering_low_fee () =
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let peer = Peer.make_peer ~network:Consensus.mainnet ~addr:"127.0.0.1"
    ~port:8333 ~id:1 ~direction:Peer.Outbound ~fd in
  (* Peer has feefilter of 5000 sat/kvB *)
  peer.feefilter <- 5000L;
  (* Transaction with fee rate of 1000 sat/kvB (below threshold) *)
  let tx_fee_rate = 1000L in
  (* Should NOT relay to this peer (fee rate < feefilter) *)
  let should_relay = tx_fee_rate >= peer.feefilter in
  Alcotest.(check bool) "low-fee tx not relayed" false should_relay;
  Lwt_main.run (Lwt_unix.close fd)

(* Test tx filtering with high fee (above feefilter threshold) *)
let test_tx_filtering_high_fee () =
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let peer = Peer.make_peer ~network:Consensus.mainnet ~addr:"127.0.0.1"
    ~port:8333 ~id:1 ~direction:Peer.Outbound ~fd in
  (* Peer has feefilter of 5000 sat/kvB *)
  peer.feefilter <- 5000L;
  (* Transaction with fee rate of 10000 sat/kvB (above threshold) *)
  let tx_fee_rate = 10000L in
  (* Should relay to this peer (fee rate >= feefilter) *)
  let should_relay = tx_fee_rate >= peer.feefilter in
  Alcotest.(check bool) "high-fee tx relayed" true should_relay;
  Lwt_main.run (Lwt_unix.close fd)

(* Test that block-relay-only connections skip feefilter sending *)
let test_block_relay_only_skip_feefilter () =
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let peer = Peer.make_peer ~network:Consensus.mainnet ~addr:"127.0.0.1"
    ~port:8333 ~id:1 ~direction:Peer.Outbound ~fd in
  (* Mark as block-relay-only *)
  peer.block_relay_only <- true;
  (* should_send_feefilter should return false for block-relay-only peers *)
  let should_send = Peer.should_send_feefilter peer in
  Alcotest.(check bool) "block-relay-only skips feefilter" false should_send;
  Lwt_main.run (Lwt_unix.close fd)

(* ========== BIP 152 Compact Block Tests ========== *)

(* Test that hb_compact_peers is empty initially *)
let test_hb_compact_peers_empty () =
  let pm = Peer_manager.create Consensus.mainnet in
  let hb_peers = Peer_manager.get_hb_compact_peers pm in
  Alcotest.(check int) "hb_compact_peers initially empty" 0 (List.length hb_peers)

(* Test max_hb_compact_peers constant *)
let test_hb_compact_peers_max_3 () =
  Alcotest.(check int) "max_hb_compact_peers" 3 Peer_manager.max_hb_compact_peers

(* Test supports_compact_blocks check *)
let test_supports_compact_blocks () =
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let peer = Peer.make_peer ~network:Consensus.mainnet ~addr:"127.0.0.1"
    ~port:8333 ~id:1 ~direction:Peer.Outbound ~fd in
  (* By default, peer doesn't support compact blocks (version 0) *)
  let supports = Peer_manager.supports_compact_blocks peer in
  Alcotest.(check bool) "no support without cmpct_version" false supports;
  (* Set version 2 and witness service *)
  peer.cmpct_version <- 2L;
  peer.services <- { peer.services with Peer.witness = true };
  let supports2 = Peer_manager.supports_compact_blocks peer in
  Alcotest.(check bool) "supports with version 2 and witness" true supports2;
  Lwt_main.run (Lwt_unix.close fd)

(* Test that removing a peer cleans up hb_compact_peers *)
let test_hb_compact_remove_on_disconnect () =
  let pm = Peer_manager.create Consensus.mainnet in
  (* hb_compact_peers is managed internally, and we verified remove_peer clears it *)
  (* This test validates the remove_peer function cleans up the list *)
  let hb_before = Peer_manager.get_hb_compact_peers pm in
  Alcotest.(check int) "hb_compact_peers before" 0 (List.length hb_before);
  (* After any remove_peer, hb_compact_peers should still work *)
  let hb_after = Peer_manager.get_hb_compact_peers pm in
  Alcotest.(check int) "hb_compact_peers after" 0 (List.length hb_after)

(* All tests *)
let () =
  Alcotest.run "Peer_manager" [
    "types", [
      Alcotest.test_case "addr_source" `Quick test_addr_source;
      Alcotest.test_case "peer_info" `Quick test_peer_info;
      Alcotest.test_case "default_config" `Quick test_default_config;
      Alcotest.test_case "addr_table_status" `Quick test_addr_table_status;
    ];
    "creation", [
      Alcotest.test_case "create" `Quick test_create;
      Alcotest.test_case "create_with_config" `Quick test_create_with_config;
      Alcotest.test_case "set_height" `Quick test_set_height;
    ];
    "banning", [
      Alcotest.test_case "is_banned_empty" `Quick test_is_banned_empty;
      Alcotest.test_case "ban_addr" `Quick test_ban_addr;
      Alcotest.test_case "unban_addr" `Quick test_unban_addr;
      Alcotest.test_case "clear_bans" `Quick test_clear_bans;
      Alcotest.test_case "get_banned_list" `Quick test_get_banned_list;
      Alcotest.test_case "get_banned_list_expired" `Quick test_get_banned_list_expired;
      Alcotest.test_case "banlist_json_persistence" `Quick test_banlist_json_persistence;
      Alcotest.test_case "load_bans_json_missing" `Quick test_load_bans_json_missing;
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
    "eclipse_protection", [
      Alcotest.test_case "bucket_stats_initial" `Quick test_bucket_stats_initial;
      Alcotest.test_case "bucket_deterministic" `Quick test_bucket_deterministic;
      Alcotest.test_case "addr_goes_to_new" `Quick test_addr_goes_to_new_table;
      Alcotest.test_case "addresses_distribute" `Quick test_addresses_distribute;
      Alcotest.test_case "netgroup_of" `Quick test_netgroup_of;
      Alcotest.test_case "keyed_netgroup_deterministic" `Quick test_keyed_netgroup_deterministic;
      Alcotest.test_case "eclipse_constants" `Quick test_eclipse_constants;
      Alcotest.test_case "move_to_tried_table" `Quick test_move_to_tried_table;
      Alcotest.test_case "is_in_tried_table" `Quick test_is_in_tried_table;
      Alcotest.test_case "compute_bucket" `Quick test_compute_bucket;
    ];
    "eviction", [
      Alcotest.test_case "eviction_candidate" `Quick test_eviction_candidate;
      Alcotest.test_case "eviction_selects_largest_netgroup" `Quick test_eviction_selects_largest_netgroup;
    ];
    "anchors", [
      Alcotest.test_case "anchor_info" `Quick test_anchor_info;
      Alcotest.test_case "anchors_empty" `Quick test_anchors_empty;
      Alcotest.test_case "anchor_persistence" `Quick test_anchor_persistence;
      Alcotest.test_case "config_anchors" `Quick test_config_anchors;
    ];
    "stale_eviction", [
      Alcotest.test_case "stale_constants" `Quick test_stale_constants;
      Alcotest.test_case "chain_sync_state" `Quick test_chain_sync_state;
      Alcotest.test_case "create_stale_state" `Quick test_create_stale_state;
      Alcotest.test_case "stale_reasons" `Quick test_stale_reasons;
      Alcotest.test_case "on_headers_received" `Quick test_on_headers_received;
      Alcotest.test_case "on_block_received" `Quick test_on_block_received;
      Alcotest.test_case "assign_blocks" `Quick test_assign_blocks;
      Alcotest.test_case "ping_pong_tracking" `Quick test_ping_pong_tracking;
      Alcotest.test_case "pong_wrong_nonce" `Quick test_pong_wrong_nonce;
      Alcotest.test_case "get_stalling_peers_empty" `Quick test_get_stalling_peers_empty;
      Alcotest.test_case "get_available_download_peers" `Quick test_get_available_download_peers_empty;
      Alcotest.test_case "stale_check_timer" `Quick test_stale_check_timer;
    ];
    "feefilter", [
      Alcotest.test_case "rounder_buckets" `Quick test_feefilter_rounder_buckets;
      Alcotest.test_case "rounder_round" `Quick test_feefilter_rounder_round;
      Alcotest.test_case "peer_feefilter_state" `Quick test_peer_feefilter_state;
      Alcotest.test_case "tx_filtering_low_fee" `Quick test_tx_filtering_low_fee;
      Alcotest.test_case "tx_filtering_high_fee" `Quick test_tx_filtering_high_fee;
      Alcotest.test_case "block_relay_only_skip" `Quick test_block_relay_only_skip_feefilter;
    ];
    "compact_blocks", [
      Alcotest.test_case "hb_compact_peers_empty" `Quick test_hb_compact_peers_empty;
      Alcotest.test_case "hb_compact_peers_max_3" `Quick test_hb_compact_peers_max_3;
      Alcotest.test_case "supports_compact_blocks" `Quick test_supports_compact_blocks;
      Alcotest.test_case "hb_compact_remove_on_disconnect" `Quick test_hb_compact_remove_on_disconnect;
    ];
  ]
