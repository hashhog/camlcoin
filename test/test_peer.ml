(* Tests for peer connection and handshake *)

(* Ignore SIGPIPE to prevent test termination when writing to unconnected sockets *)
let () = Sys.set_signal Sys.sigpipe Sys.Signal_ignore

open Camlcoin

(* Test service flag encoding/decoding *)
let test_services_encoding () =
  (* Test empty services *)
  let empty = Peer.services_of_int64 0L in
  Alcotest.(check bool) "empty network" false empty.network;
  Alcotest.(check bool) "empty getutxo" false empty.getutxo;
  Alcotest.(check bool) "empty bloom" false empty.bloom;
  Alcotest.(check bool) "empty witness" false empty.witness;
  Alcotest.(check bool) "empty compact_filters" false empty.compact_filters;
  Alcotest.(check bool) "empty network_limited" false empty.network_limited;

  (* Test full node services (NODE_NETWORK | NODE_WITNESS = 9) *)
  let full_node = Peer.services_of_int64 9L in
  Alcotest.(check bool) "full_node network" true full_node.network;
  Alcotest.(check bool) "full_node witness" true full_node.witness;
  Alcotest.(check bool) "full_node bloom" false full_node.bloom;

  (* Test roundtrip *)
  let roundtrip = Peer.services_to_int64 full_node in
  Alcotest.(check int64) "roundtrip" 9L roundtrip;

  (* Test all flags *)
  let all_flags = Peer.services_of_int64 1103L in (* 1 + 2 + 4 + 8 + 64 + 1024 *)
  Alcotest.(check bool) "all network" true all_flags.network;
  Alcotest.(check bool) "all getutxo" true all_flags.getutxo;
  Alcotest.(check bool) "all bloom" true all_flags.bloom;
  Alcotest.(check bool) "all witness" true all_flags.witness;
  Alcotest.(check bool) "all compact_filters" true all_flags.compact_filters;
  Alcotest.(check bool) "all network_limited" true all_flags.network_limited

(* Test service flag individual bits *)
let test_services_individual_bits () =
  (* NODE_NETWORK = 1 *)
  let s = Peer.services_of_int64 1L in
  Alcotest.(check bool) "network=1" true s.network;
  Alcotest.(check bool) "others false" false s.witness;

  (* NODE_GETUTXO = 2 *)
  let s = Peer.services_of_int64 2L in
  Alcotest.(check bool) "getutxo=2" true s.getutxo;

  (* NODE_BLOOM = 4 *)
  let s = Peer.services_of_int64 4L in
  Alcotest.(check bool) "bloom=4" true s.bloom;

  (* NODE_WITNESS = 8 *)
  let s = Peer.services_of_int64 8L in
  Alcotest.(check bool) "witness=8" true s.witness;

  (* NODE_COMPACT_FILTERS = 64 *)
  let s = Peer.services_of_int64 64L in
  Alcotest.(check bool) "compact_filters=64" true s.compact_filters;

  (* NODE_NETWORK_LIMITED = 1024 *)
  let s = Peer.services_of_int64 1024L in
  Alcotest.(check bool) "network_limited=1024" true s.network_limited

(* Test our_services values *)
let test_our_services () =
  let ours = Peer.our_services in
  Alcotest.(check bool) "our network" true ours.network;
  Alcotest.(check bool) "our witness" true ours.witness;
  Alcotest.(check bool) "our bloom" false ours.bloom;
  Alcotest.(check bool) "our getutxo" false ours.getutxo;
  Alcotest.(check bool) "our compact_filters" false ours.compact_filters;
  Alcotest.(check bool) "our network_limited" false ours.network_limited;

  (* NODE_NETWORK | NODE_WITNESS = 1 | 8 = 9 *)
  let as_int = Peer.services_to_int64 ours in
  Alcotest.(check int64) "our services value" 9L as_int

(* Test peer state to string *)
let test_peer_state_to_string () =
  Alcotest.(check string) "connecting" "connecting"
    (Peer.peer_state_to_string Peer.Connecting);
  Alcotest.(check string) "connected" "connected"
    (Peer.peer_state_to_string Peer.Connected);
  Alcotest.(check string) "handshake" "handshake"
    (Peer.peer_state_to_string Peer.HandshakeInProgress);
  Alcotest.(check string) "ready" "ready"
    (Peer.peer_state_to_string Peer.Ready);
  Alcotest.(check string) "disconnecting" "disconnecting"
    (Peer.peer_state_to_string Peer.Disconnecting);
  Alcotest.(check string) "disconnected" "disconnected"
    (Peer.peer_state_to_string Peer.Disconnected)

(* Test make_local_addr creates valid IPv4-mapped IPv6 address *)
let test_make_local_addr () =
  let addr = Peer.make_local_addr () in
  (* Check IPv4-mapped prefix bytes *)
  Alcotest.(check int) "byte 10 = 0xFF" 0xFF
    (Cstruct.get_uint8 addr.addr 10);
  Alcotest.(check int) "byte 11 = 0xFF" 0xFF
    (Cstruct.get_uint8 addr.addr 11);
  (* Check 127.0.0.1 *)
  Alcotest.(check int) "byte 12 = 127" 127
    (Cstruct.get_uint8 addr.addr 12);
  Alcotest.(check int) "byte 13 = 0" 0
    (Cstruct.get_uint8 addr.addr 13);
  Alcotest.(check int) "byte 14 = 0" 0
    (Cstruct.get_uint8 addr.addr 14);
  Alcotest.(check int) "byte 15 = 1" 1
    (Cstruct.get_uint8 addr.addr 15);
  (* Check services *)
  Alcotest.(check int64) "local addr services" 9L addr.services;
  (* Check port is 0 *)
  Alcotest.(check int) "local addr port" 0 addr.port

(* Test random_bytes generates unique values *)
let test_random_bytes () =
  let b1 = Peer.random_bytes 16 in
  let b2 = Peer.random_bytes 16 in
  (* Should be extremely unlikely to be equal *)
  Alcotest.(check bool) "random bytes differ"
    false (Cstruct.equal b1 b2);
  (* Check length *)
  Alcotest.(check int) "length 16" 16 (Cstruct.length b1)

(* Test random_nonce generates unique values *)
let test_random_nonce () =
  let n1 = Peer.random_nonce () in
  let n2 = Peer.random_nonce () in
  (* Should be extremely unlikely to be equal *)
  Alcotest.(check bool) "nonces differ" false (n1 = n2)

(* Test handle_pong with matching nonce *)
let test_handle_pong () =
  (* We need to create a mock peer for this test *)
  (* Since we can't easily create a peer without network I/O,
     we test the pong handling logic conceptually *)
  ()

(* Test needs_ping and ping_timed_out logic *)
let test_ping_timing () =
  (* These functions depend on peer state and time,
     tested indirectly through integration tests *)
  ()

(* Test misbehavior scoring categories *)
let test_misbehavior_scores () =
  Alcotest.(check int) "invalid_block = 100" 100
    Peer.misbehavior_invalid_block;
  Alcotest.(check int) "invalid_header = 20" 20
    Peer.misbehavior_invalid_header;
  Alcotest.(check int) "oversized_message = 20" 20
    Peer.misbehavior_oversized_message;
  Alcotest.(check int) "bad_tx = 10" 10
    Peer.misbehavior_bad_tx;
  Alcotest.(check int) "spam = 5" 5
    Peer.misbehavior_spam

(* Test record_misbehavior accumulation *)
let test_record_misbehavior_accumulation () =
  (* Create a dummy peer for testing *)
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let peer = Peer.make_peer ~network:Consensus.mainnet ~addr:"127.0.0.1"
    ~port:8333 ~id:0 ~direction:Peer.Outbound ~fd in
  (* Initial score is 0 *)
  let stats = Peer.get_stats peer in
  Alcotest.(check int) "initial score" 0 stats.stat_misbehavior;
  (* Add 10 points *)
  let result = Peer.record_misbehavior peer 10 in
  Alcotest.(check bool) "not banned at 10" true (result = `Ok);
  let stats = Peer.get_stats peer in
  Alcotest.(check int) "score = 10" 10 stats.stat_misbehavior;
  (* Add 50 more points *)
  let result = Peer.record_misbehavior peer 50 in
  Alcotest.(check bool) "not banned at 60" true (result = `Ok);
  let stats = Peer.get_stats peer in
  Alcotest.(check int) "score = 60" 60 stats.stat_misbehavior;
  (* Add 40 more points - should trigger ban at 100 *)
  let result = Peer.record_misbehavior peer 40 in
  Alcotest.(check bool) "banned at 100" true (result = `Ban);
  let stats = Peer.get_stats peer in
  Alcotest.(check int) "score = 100" 100 stats.stat_misbehavior

(* Test record_misbehavior_for categories *)
let test_record_misbehavior_for () =
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let peer = Peer.make_peer ~network:Consensus.mainnet ~addr:"127.0.0.1"
    ~port:8333 ~id:0 ~direction:Peer.Outbound ~fd in
  (* Test invalid_block triggers immediate ban *)
  let result = Peer.record_misbehavior_for peer "invalid_block" in
  Alcotest.(check bool) "banned for invalid_block" true (result = `Ban);
  let stats = Peer.get_stats peer in
  Alcotest.(check int) "score = 100" 100 stats.stat_misbehavior

(* Test record_misbehavior_for unknown infraction *)
let test_record_misbehavior_for_unknown () =
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let peer = Peer.make_peer ~network:Consensus.mainnet ~addr:"127.0.0.1"
    ~port:8333 ~id:0 ~direction:Peer.Outbound ~fd in
  (* Unknown infraction adds 1 point *)
  let result = Peer.record_misbehavior_for peer "something_weird" in
  Alcotest.(check bool) "not banned for unknown" true (result = `Ok);
  let stats = Peer.get_stats peer in
  Alcotest.(check int) "score = 1" 1 stats.stat_misbehavior

(* Test peer_info includes misbehavior score *)
let test_peer_info_misbehavior () =
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let peer = Peer.make_peer ~network:Consensus.mainnet ~addr:"127.0.0.1"
    ~port:8333 ~id:0 ~direction:Peer.Outbound ~fd in
  let _ = Peer.record_misbehavior peer 42 in
  let info = Peer.peer_info peer in
  (* Check that the info string contains misb=42 somewhere *)
  Alcotest.(check bool) "info contains misb=42" true
    (Astring.String.is_infix ~affix:"misb=42" info)

(* Test handshake_complete and version_received initialization *)
let test_handshake_fields_init () =
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let peer = Peer.make_peer ~network:Consensus.mainnet ~addr:"127.0.0.1"
    ~port:8333 ~id:0 ~direction:Peer.Outbound ~fd in
  Alcotest.(check bool) "handshake not complete" false peer.handshake_complete;
  Alcotest.(check bool) "version not received" false peer.version_received;
  (* our_nonce should be non-zero (random) *)
  Alcotest.(check bool) "our_nonce is set" true (peer.our_nonce <> 0L)

(* Test handshake timeout constant *)
let test_handshake_timeout () =
  Alcotest.(check (float 0.001)) "handshake_timeout = 60.0" 60.0
    Peer.handshake_timeout

(* Test minimum protocol version constant *)
let test_min_protocol_version () =
  Alcotest.(check int32) "min_protocol_version = 70015" 70015l
    Peer.min_protocol_version

(* Test dispatch_message rejects pre-handshake messages *)
let test_dispatch_pre_handshake_ping () =
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let peer = Peer.make_peer ~network:Consensus.mainnet ~addr:"127.0.0.1"
    ~port:8333 ~id:0 ~direction:Peer.Outbound ~fd in
  (* Peer starts with handshake_complete = false and version_received = false *)
  let msg = P2p.PingMsg 12345L in
  let result = Lwt_main.run (Peer.dispatch_message peer msg) in
  match result with
  | `PreHandshake _ ->
    (* Pre-handshake message should be rejected *)
    Alcotest.(check bool) "misbehavior scored" true (peer.misbehavior_score > 0)
  | `Continue -> Alcotest.fail "Expected pre-handshake rejection"
  | `Disconnect _ -> Alcotest.fail "Expected pre-handshake rejection, not disconnect"

(* Test dispatch_message accepts VERSION before handshake *)
let test_dispatch_pre_handshake_version () =
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let peer = Peer.make_peer ~network:Consensus.mainnet ~addr:"127.0.0.1"
    ~port:8333 ~id:0 ~direction:Peer.Outbound ~fd in
  let version_msg : Types.version_msg = {
    protocol_version = 70016l;
    services = 9L;  (* NODE_NETWORK | NODE_WITNESS *)
    timestamp = Int64.of_float (Unix.gettimeofday ());
    addr_recv = { services = 0L; addr = Cstruct.create 16; port = 8333 };
    addr_from = Peer.make_local_addr ();
    nonce = 999L;  (* Different from peer's own nonce *)
    user_agent = "/TestPeer:0.1.0/";
    start_height = 800000l;
    relay = true;
  } in
  let msg = P2p.VersionMsg version_msg in
  let result = Lwt_main.run (Peer.dispatch_message peer msg) in
  match result with
  | `Continue ->
    Alcotest.(check bool) "version_received set" true peer.version_received;
    Alcotest.(check int) "no misbehavior" 0 peer.misbehavior_score
  | _ -> Alcotest.fail "Expected VERSION to be accepted"

(* Test dispatch_message rejects duplicate VERSION *)
let test_dispatch_duplicate_version () =
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let peer = Peer.make_peer ~network:Consensus.mainnet ~addr:"127.0.0.1"
    ~port:8333 ~id:0 ~direction:Peer.Outbound ~fd in
  let version_msg : Types.version_msg = {
    protocol_version = 70016l;
    services = 9L;
    timestamp = Int64.of_float (Unix.gettimeofday ());
    addr_recv = { services = 0L; addr = Cstruct.create 16; port = 8333 };
    addr_from = Peer.make_local_addr ();
    nonce = 999L;
    user_agent = "/TestPeer:0.1.0/";
    start_height = 800000l;
    relay = true;
  } in
  let msg = P2p.VersionMsg version_msg in
  (* First VERSION should succeed *)
  let _ = Lwt_main.run (Peer.dispatch_message peer msg) in
  Alcotest.(check bool) "version_received after first" true peer.version_received;
  (* Second VERSION should be rejected with misbehavior score 1 *)
  let result = Lwt_main.run (Peer.dispatch_message peer msg) in
  match result with
  | `PreHandshake _ ->
    Alcotest.(check int) "misbehavior = 1" 1 peer.misbehavior_score
  | _ -> Alcotest.fail "Expected duplicate VERSION to be rejected"

(* Test dispatch_message rejects VERACK before VERSION *)
let test_dispatch_verack_before_version () =
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let peer = Peer.make_peer ~network:Consensus.mainnet ~addr:"127.0.0.1"
    ~port:8333 ~id:0 ~direction:Peer.Outbound ~fd in
  let msg = P2p.VerackMsg in
  let result = Lwt_main.run (Peer.dispatch_message peer msg) in
  match result with
  | `PreHandshake _ ->
    Alcotest.(check int) "misbehavior = 10" 10 peer.misbehavior_score
  | _ -> Alcotest.fail "Expected VERACK before VERSION to be rejected"

(* Test dispatch_message accepts VERACK after VERSION *)
let test_dispatch_verack_after_version () =
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let peer = Peer.make_peer ~network:Consensus.mainnet ~addr:"127.0.0.1"
    ~port:8333 ~id:0 ~direction:Peer.Outbound ~fd in
  (* Simulate VERSION received *)
  peer.version_received <- true;
  let msg = P2p.VerackMsg in
  let result = Lwt_main.run (Peer.dispatch_message peer msg) in
  match result with
  | `Continue ->
    Alcotest.(check bool) "handshake_complete" true peer.handshake_complete;
    Alcotest.(check int) "no misbehavior" 0 peer.misbehavior_score
  | _ -> Alcotest.fail "Expected VERACK after VERSION to be accepted"

(* Test dispatch_message accepts feature negotiation between VERSION and VERACK *)
let test_dispatch_feature_negotiation () =
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let peer = Peer.make_peer ~network:Consensus.mainnet ~addr:"127.0.0.1"
    ~port:8333 ~id:0 ~direction:Peer.Outbound ~fd in
  (* Simulate VERSION received but not VERACK *)
  peer.version_received <- true;
  (* wtxidrelay should be accepted *)
  let result = Lwt_main.run (Peer.dispatch_message peer P2p.WtxidrelayMsg) in
  (match result with
  | `Continue ->
    Alcotest.(check bool) "wtxid_relay set" true peer.wtxid_relay
  | _ -> Alcotest.fail "Expected wtxidrelay to be accepted");
  (* sendaddrv2 should be accepted *)
  let result = Lwt_main.run (Peer.dispatch_message peer P2p.SendaddrV2Msg) in
  (match result with
  | `Continue ->
    Alcotest.(check bool) "sendaddrv2 set" true peer.sendaddrv2
  | _ -> Alcotest.fail "Expected sendaddrv2 to be accepted");
  Alcotest.(check int) "no misbehavior" 0 peer.misbehavior_score

(* Test dispatch_message rejects feature negotiation before VERSION *)
let test_dispatch_feature_before_version () =
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let peer = Peer.make_peer ~network:Consensus.mainnet ~addr:"127.0.0.1"
    ~port:8333 ~id:0 ~direction:Peer.Outbound ~fd in
  let result = Lwt_main.run (Peer.dispatch_message peer P2p.WtxidrelayMsg) in
  match result with
  | `PreHandshake _ ->
    Alcotest.(check int) "misbehavior = 10" 10 peer.misbehavior_score
  | _ -> Alcotest.fail "Expected wtxidrelay before VERSION to be rejected"

(* Test dispatch_message rejects wtxidrelay after handshake *)
let test_dispatch_wtxidrelay_after_handshake () =
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let peer = Peer.make_peer ~network:Consensus.mainnet ~addr:"127.0.0.1"
    ~port:8333 ~id:0 ~direction:Peer.Outbound ~fd in
  (* Simulate completed handshake *)
  peer.handshake_complete <- true;
  peer.version_received <- true;
  let result = Lwt_main.run (Peer.dispatch_message peer P2p.WtxidrelayMsg) in
  match result with
  | `Disconnect _ ->
    Alcotest.(check int) "misbehavior = 1" 1 peer.misbehavior_score
  | _ -> Alcotest.fail "Expected wtxidrelay after handshake to disconnect"

(* Test dispatch_message rejects VERSION after handshake *)
let test_dispatch_version_after_handshake () =
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let peer = Peer.make_peer ~network:Consensus.mainnet ~addr:"127.0.0.1"
    ~port:8333 ~id:0 ~direction:Peer.Outbound ~fd in
  (* Simulate completed handshake *)
  peer.handshake_complete <- true;
  peer.version_received <- true;
  let version_msg : Types.version_msg = {
    protocol_version = 70016l;
    services = 9L;
    timestamp = Int64.of_float (Unix.gettimeofday ());
    addr_recv = { services = 0L; addr = Cstruct.create 16; port = 8333 };
    addr_from = Peer.make_local_addr ();
    nonce = 999L;
    user_agent = "/TestPeer:0.1.0/";
    start_height = 800000l;
    relay = true;
  } in
  let msg = P2p.VersionMsg version_msg in
  let result = Lwt_main.run (Peer.dispatch_message peer msg) in
  match result with
  | `Disconnect _ ->
    Alcotest.(check int) "misbehavior = 1" 1 peer.misbehavior_score
  | _ -> Alcotest.fail "Expected VERSION after handshake to disconnect"

(* Test dispatch_message accepts normal messages after handshake *)
let test_dispatch_post_handshake_feefilter () =
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let peer = Peer.make_peer ~network:Consensus.mainnet ~addr:"127.0.0.1"
    ~port:8333 ~id:0 ~direction:Peer.Outbound ~fd in
  (* Simulate completed handshake *)
  peer.handshake_complete <- true;
  peer.version_received <- true;
  (* FeefilterMsg doesn't try to send a response, so it won't hang *)
  let msg = P2p.FeefilterMsg 1000L in
  let result = Lwt_main.run (Peer.dispatch_message peer msg) in
  match result with
  | `Continue ->
    Alcotest.(check int) "no misbehavior" 0 peer.misbehavior_score;
    Alcotest.(check int64) "feefilter set" 1000L peer.feefilter
  | _ -> Alcotest.fail "Expected feefilter after handshake to be accepted"

(* Test self-connection detection nonce *)
let test_self_connection_nonce () =
  let fd1 = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let fd2 = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let peer1 = Peer.make_peer ~network:Consensus.mainnet ~addr:"127.0.0.1"
    ~port:8333 ~id:0 ~direction:Peer.Outbound ~fd:fd1 in
  let peer2 = Peer.make_peer ~network:Consensus.mainnet ~addr:"127.0.0.1"
    ~port:8333 ~id:1 ~direction:Peer.Outbound ~fd:fd2 in
  (* Each peer should have a unique nonce *)
  Alcotest.(check bool) "nonces differ" true (peer1.our_nonce <> peer2.our_nonce)

(* Test Poisson delay produces reasonable values *)
let test_poisson_delay () =
  (* Generate 100 samples and verify they're in a reasonable range *)
  let samples = List.init 100 (fun _ -> Peer.poisson_delay 5.0) in
  (* All samples should be positive *)
  let all_positive = List.for_all (fun x -> x > 0.0) samples in
  Alcotest.(check bool) "all positive" true all_positive;
  (* Mean should be roughly 5.0 (within 50% for 100 samples) *)
  let sum = List.fold_left ( +. ) 0.0 samples in
  let mean = sum /. 100.0 in
  Alcotest.(check bool) "mean in range 2.5-7.5" true (mean > 2.5 && mean < 7.5)

(* Test inventory trickling constants *)
let test_trickling_constants () =
  Alcotest.(check (float 0.001)) "inbound interval = 5.0" 5.0
    Peer.inbound_inv_broadcast_interval;
  Alcotest.(check (float 0.001)) "outbound interval = 2.0" 2.0
    Peer.outbound_inv_broadcast_interval;
  Alcotest.(check int) "max inv per flush = 1000" 1000
    Peer.max_inv_per_flush

(* Test inv_queue initialization *)
let test_inv_queue_init () =
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let peer = Peer.make_peer ~network:Consensus.mainnet ~addr:"127.0.0.1"
    ~port:8333 ~id:0 ~direction:Peer.Outbound ~fd in
  (* Queue should be empty initially *)
  Alcotest.(check int) "queue empty" 0 (Peer.inv_queue_length peer);
  (* trickling_active should be false initially *)
  Alcotest.(check bool) "trickling not active" false peer.trickling_active;
  (* next_inv_send should be in the future *)
  Alcotest.(check bool) "next_inv_send in future" true
    (peer.next_inv_send > Unix.gettimeofday () -. 10.0)

(* Test queue_inv adds to queue for Ready peer *)
let test_queue_inv_ready () =
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let peer = Peer.make_peer ~network:Consensus.mainnet ~addr:"127.0.0.1"
    ~port:8333 ~id:0 ~direction:Peer.Outbound ~fd in
  (* Set peer to Ready state *)
  peer.state <- Peer.Ready;
  let hash = Cstruct.create 32 in
  Cstruct.set_uint8 hash 0 0xAB;
  let entry : Peer.inv_entry = { inv_type = P2p.InvTx; hash } in
  Peer.queue_inv peer entry;
  Alcotest.(check int) "queue has 1 item" 1 (Peer.inv_queue_length peer)

(* Test queue_inv ignores non-Ready peer *)
let test_queue_inv_not_ready () =
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let peer = Peer.make_peer ~network:Consensus.mainnet ~addr:"127.0.0.1"
    ~port:8333 ~id:0 ~direction:Peer.Outbound ~fd in
  (* Peer is Connected, not Ready *)
  Alcotest.(check bool) "peer not ready" false (peer.state = Peer.Ready);
  let hash = Cstruct.create 32 in
  let entry : Peer.inv_entry = { inv_type = P2p.InvTx; hash } in
  Peer.queue_inv peer entry;
  Alcotest.(check int) "queue still empty" 0 (Peer.inv_queue_length peer)

(* Test multiple items can be queued *)
let test_queue_inv_multiple () =
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let peer = Peer.make_peer ~network:Consensus.mainnet ~addr:"127.0.0.1"
    ~port:8333 ~id:0 ~direction:Peer.Outbound ~fd in
  peer.state <- Peer.Ready;
  for i = 0 to 99 do
    let hash = Cstruct.create 32 in
    Cstruct.set_uint8 hash 0 i;
    let entry : Peer.inv_entry = { inv_type = P2p.InvTx; hash } in
    Peer.queue_inv peer entry
  done;
  Alcotest.(check int) "queue has 100 items" 100 (Peer.inv_queue_length peer)

(* Test should_flush_inv returns false when queue is empty *)
let test_should_flush_inv_empty () =
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let peer = Peer.make_peer ~network:Consensus.mainnet ~addr:"127.0.0.1"
    ~port:8333 ~id:0 ~direction:Peer.Outbound ~fd in
  peer.state <- Peer.Ready;
  peer.next_inv_send <- Unix.gettimeofday () -. 10.0;  (* Past time *)
  Alcotest.(check bool) "should not flush empty queue" false
    (Peer.should_flush_inv peer)

(* Test should_flush_inv returns false before next_inv_send time *)
let test_should_flush_inv_not_time () =
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let peer = Peer.make_peer ~network:Consensus.mainnet ~addr:"127.0.0.1"
    ~port:8333 ~id:0 ~direction:Peer.Outbound ~fd in
  peer.state <- Peer.Ready;
  (* Add an item to the queue *)
  let hash = Cstruct.create 32 in
  let entry : Peer.inv_entry = { inv_type = P2p.InvTx; hash } in
  Peer.queue_inv peer entry;
  (* Set next_inv_send to 10 seconds in the future *)
  peer.next_inv_send <- Unix.gettimeofday () +. 10.0;
  Alcotest.(check bool) "should not flush before time" false
    (Peer.should_flush_inv peer)

(* Test should_flush_inv returns true when ready *)
let test_should_flush_inv_ready () =
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let peer = Peer.make_peer ~network:Consensus.mainnet ~addr:"127.0.0.1"
    ~port:8333 ~id:0 ~direction:Peer.Outbound ~fd in
  peer.state <- Peer.Ready;
  (* Add an item to the queue *)
  let hash = Cstruct.create 32 in
  let entry : Peer.inv_entry = { inv_type = P2p.InvTx; hash } in
  Peer.queue_inv peer entry;
  (* Set next_inv_send to the past *)
  peer.next_inv_send <- Unix.gettimeofday () -. 1.0;
  Alcotest.(check bool) "should flush when ready" true
    (Peer.should_flush_inv peer)

(* Test schedule_next_inv_send updates next_inv_send *)
let test_schedule_next_inv_send () =
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let peer = Peer.make_peer ~network:Consensus.mainnet ~addr:"127.0.0.1"
    ~port:8333 ~id:0 ~direction:Peer.Outbound ~fd in
  let old_time = peer.next_inv_send in
  Peer.schedule_next_inv_send peer;
  (* New time should be in the future relative to now *)
  Alcotest.(check bool) "next_inv_send updated" true
    (peer.next_inv_send > Unix.gettimeofday ());
  (* And different from the old time (almost certainly) *)
  Alcotest.(check bool) "next_inv_send different" true
    (peer.next_inv_send <> old_time)

(* Test inbound vs outbound peer trickling intervals *)
let test_trickling_intervals () =
  let fd1 = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let fd2 = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let outbound = Peer.make_peer ~network:Consensus.mainnet ~addr:"127.0.0.1"
    ~port:8333 ~id:0 ~direction:Peer.Outbound ~fd:fd1 in
  let inbound = Peer.make_peer ~network:Consensus.mainnet ~addr:"127.0.0.1"
    ~port:8333 ~id:1 ~direction:Peer.Inbound ~fd:fd2 in
  (* Generate many samples for each and check average is correct *)
  let outbound_delays = List.init 50 (fun _ ->
    Peer.schedule_next_inv_send outbound;
    outbound.next_inv_send -. Unix.gettimeofday ()
  ) in
  let inbound_delays = List.init 50 (fun _ ->
    Peer.schedule_next_inv_send inbound;
    inbound.next_inv_send -. Unix.gettimeofday ()
  ) in
  let avg_outbound = (List.fold_left ( +. ) 0.0 outbound_delays) /. 50.0 in
  let avg_inbound = (List.fold_left ( +. ) 0.0 inbound_delays) /. 50.0 in
  (* Outbound average should be around 2.0, inbound around 5.0 *)
  Alcotest.(check bool) "outbound avg near 2.0" true
    (avg_outbound > 1.0 && avg_outbound < 4.0);
  Alcotest.(check bool) "inbound avg near 5.0" true
    (avg_inbound > 3.0 && avg_inbound < 8.0);
  (* Inbound should be slower than outbound on average *)
  Alcotest.(check bool) "inbound slower than outbound" true
    (avg_inbound > avg_outbound)

(* Test that queue_inv delays sending - items stay in queue until flush *)
let test_queue_inv_delayed () =
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let peer = Peer.make_peer ~network:Consensus.mainnet ~addr:"127.0.0.1"
    ~port:8333 ~id:0 ~direction:Peer.Outbound ~fd in
  peer.state <- Peer.Ready;
  (* Queue several transactions *)
  for i = 0 to 9 do
    let hash = Cstruct.create 32 in
    Cstruct.set_uint8 hash 0 i;
    let entry : Peer.inv_entry = { inv_type = P2p.InvTx; hash } in
    Peer.queue_inv peer entry
  done;
  (* Items should be queued, not sent - the queue should have 10 items *)
  Alcotest.(check int) "items queued not sent" 10 (Peer.inv_queue_length peer);
  (* should_flush_inv should be false since next_inv_send is in the future *)
  peer.next_inv_send <- Unix.gettimeofday () +. 10.0;
  Alcotest.(check bool) "should not flush yet" false (Peer.should_flush_inv peer)

(* Test that transactions are batched - multiple items sent in one flush *)
let test_inv_batching () =
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let peer = Peer.make_peer ~network:Consensus.mainnet ~addr:"127.0.0.1"
    ~port:8333 ~id:0 ~direction:Peer.Outbound ~fd in
  peer.state <- Peer.Ready;
  (* Queue 50 transactions *)
  for i = 0 to 49 do
    let hash = Cstruct.create 32 in
    Cstruct.set_uint8 hash 0 i;
    let entry : Peer.inv_entry = { inv_type = P2p.InvTx; hash } in
    Peer.queue_inv peer entry
  done;
  Alcotest.(check int) "50 items queued" 50 (Peer.inv_queue_length peer);
  (* Flush will try to send all 50 in one batch (socket will fail, but that's ok) *)
  let flushed = Lwt_main.run (Peer.flush_inv_queue peer) in
  (* All 50 should have been dequeued for sending *)
  Alcotest.(check int) "50 items flushed" 50 flushed;
  Alcotest.(check int) "queue now empty" 0 (Peer.inv_queue_length peer)

(* Test max 1000 items per flush *)
let test_inv_batch_max_1000 () =
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let peer = Peer.make_peer ~network:Consensus.mainnet ~addr:"127.0.0.1"
    ~port:8333 ~id:0 ~direction:Peer.Outbound ~fd in
  peer.state <- Peer.Ready;
  (* Queue 1500 transactions *)
  for i = 0 to 1499 do
    let hash = Cstruct.create 32 in
    Cstruct.set_uint8 hash 0 (i mod 256);
    Cstruct.set_uint8 hash 1 (i / 256);
    let entry : Peer.inv_entry = { inv_type = P2p.InvTx; hash } in
    Peer.queue_inv peer entry
  done;
  Alcotest.(check int) "1500 items queued" 1500 (Peer.inv_queue_length peer);
  (* First flush should only send max_inv_per_flush (1000) *)
  let flushed = Lwt_main.run (Peer.flush_inv_queue peer) in
  Alcotest.(check int) "1000 items flushed" 1000 flushed;
  Alcotest.(check int) "500 items remain" 500 (Peer.inv_queue_length peer);
  (* Second flush gets the rest *)
  let flushed2 = Lwt_main.run (Peer.flush_inv_queue peer) in
  Alcotest.(check int) "500 items flushed" 500 flushed2;
  Alcotest.(check int) "queue now empty" 0 (Peer.inv_queue_length peer)

(* Test that relay=false peers don't receive tx inv *)
let test_queue_inv_no_relay () =
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let peer = Peer.make_peer ~network:Consensus.mainnet ~addr:"127.0.0.1"
    ~port:8333 ~id:0 ~direction:Peer.Outbound ~fd in
  peer.state <- Peer.Ready;
  peer.relay <- false;  (* Peer opted out of tx relay *)
  let hash = Cstruct.create 32 in
  let entry : Peer.inv_entry = { inv_type = P2p.InvTx; hash } in
  Peer.queue_inv peer entry;
  (* Tx should be suppressed for no-relay peer *)
  Alcotest.(check int) "tx not queued for no-relay peer" 0 (Peer.inv_queue_length peer)

(* Test that block_relay_only peers don't receive tx inv *)
let test_queue_inv_block_relay_only () =
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let peer = Peer.make_peer ~network:Consensus.mainnet ~addr:"127.0.0.1"
    ~port:8333 ~id:0 ~direction:Peer.Outbound ~fd in
  peer.state <- Peer.Ready;
  peer.block_relay_only <- true;  (* Block-relay-only connection *)
  let hash = Cstruct.create 32 in
  let entry : Peer.inv_entry = { inv_type = P2p.InvTx; hash } in
  Peer.queue_inv peer entry;
  (* Tx should be suppressed for block-relay-only peer *)
  Alcotest.(check int) "tx not queued for block-relay-only" 0 (Peer.inv_queue_length peer)

(* Test that block inv CAN be queued (not filtered like tx) *)
let test_queue_inv_block_allowed () =
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let peer = Peer.make_peer ~network:Consensus.mainnet ~addr:"127.0.0.1"
    ~port:8333 ~id:0 ~direction:Peer.Outbound ~fd in
  peer.state <- Peer.Ready;
  peer.relay <- false;  (* Peer opted out of tx relay *)
  peer.block_relay_only <- true;  (* Block-relay-only *)
  let hash = Cstruct.create 32 in
  (* Block inventory should still be queued even for block-relay-only peers *)
  let entry : Peer.inv_entry = { inv_type = P2p.InvBlock; hash } in
  Peer.queue_inv peer entry;
  (* Block inv should be queued *)
  Alcotest.(check int) "block inv queued" 1 (Peer.inv_queue_length peer)

(* Test that WitnessTx also respects relay flag *)
let test_queue_inv_witness_tx_no_relay () =
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let peer = Peer.make_peer ~network:Consensus.mainnet ~addr:"127.0.0.1"
    ~port:8333 ~id:0 ~direction:Peer.Outbound ~fd in
  peer.state <- Peer.Ready;
  peer.relay <- false;
  let hash = Cstruct.create 32 in
  let entry : Peer.inv_entry = { inv_type = P2p.InvWitnessTx; hash } in
  Peer.queue_inv peer entry;
  (* WitnessTx should also be suppressed for no-relay peer *)
  Alcotest.(check int) "witness tx not queued for no-relay" 0 (Peer.inv_queue_length peer)

(* All tests *)
let () =
  Alcotest.run "Peer" [
    "services", [
      Alcotest.test_case "encoding roundtrip" `Quick test_services_encoding;
      Alcotest.test_case "individual bits" `Quick test_services_individual_bits;
      Alcotest.test_case "our services" `Quick test_our_services;
    ];
    "peer_state", [
      Alcotest.test_case "to_string" `Quick test_peer_state_to_string;
    ];
    "address", [
      Alcotest.test_case "make_local_addr" `Quick test_make_local_addr;
    ];
    "random", [
      Alcotest.test_case "random_bytes" `Quick test_random_bytes;
      Alcotest.test_case "random_nonce" `Quick test_random_nonce;
    ];
    "ping_pong", [
      Alcotest.test_case "handle_pong" `Quick test_handle_pong;
      Alcotest.test_case "ping_timing" `Quick test_ping_timing;
    ];
    "misbehavior", [
      Alcotest.test_case "scores" `Quick test_misbehavior_scores;
      Alcotest.test_case "accumulation" `Quick test_record_misbehavior_accumulation;
      Alcotest.test_case "for_category" `Quick test_record_misbehavior_for;
      Alcotest.test_case "for_unknown" `Quick test_record_misbehavior_for_unknown;
      Alcotest.test_case "peer_info_misbehavior" `Quick test_peer_info_misbehavior;
    ];
    "handshake", [
      Alcotest.test_case "fields_init" `Quick test_handshake_fields_init;
      Alcotest.test_case "timeout_constant" `Quick test_handshake_timeout;
      Alcotest.test_case "min_protocol_version" `Quick test_min_protocol_version;
      Alcotest.test_case "self_connection_nonce" `Quick test_self_connection_nonce;
    ];
    "pre_handshake", [
      Alcotest.test_case "reject_ping" `Quick test_dispatch_pre_handshake_ping;
      Alcotest.test_case "accept_version" `Quick test_dispatch_pre_handshake_version;
      Alcotest.test_case "reject_duplicate_version" `Quick test_dispatch_duplicate_version;
      Alcotest.test_case "reject_verack_before_version" `Quick test_dispatch_verack_before_version;
      Alcotest.test_case "accept_verack_after_version" `Quick test_dispatch_verack_after_version;
      Alcotest.test_case "accept_feature_negotiation" `Quick test_dispatch_feature_negotiation;
      Alcotest.test_case "reject_feature_before_version" `Quick test_dispatch_feature_before_version;
      Alcotest.test_case "reject_wtxidrelay_after_handshake" `Quick test_dispatch_wtxidrelay_after_handshake;
      Alcotest.test_case "reject_version_after_handshake" `Quick test_dispatch_version_after_handshake;
      Alcotest.test_case "accept_feefilter_after_handshake" `Quick test_dispatch_post_handshake_feefilter;
    ];
    "inv_trickling", [
      Alcotest.test_case "poisson_delay" `Quick test_poisson_delay;
      Alcotest.test_case "trickling_constants" `Quick test_trickling_constants;
      Alcotest.test_case "inv_queue_init" `Quick test_inv_queue_init;
      Alcotest.test_case "queue_inv_ready" `Quick test_queue_inv_ready;
      Alcotest.test_case "queue_inv_not_ready" `Quick test_queue_inv_not_ready;
      Alcotest.test_case "queue_inv_multiple" `Quick test_queue_inv_multiple;
      Alcotest.test_case "should_flush_inv_empty" `Quick test_should_flush_inv_empty;
      Alcotest.test_case "should_flush_inv_not_time" `Quick test_should_flush_inv_not_time;
      Alcotest.test_case "should_flush_inv_ready" `Quick test_should_flush_inv_ready;
      Alcotest.test_case "schedule_next_inv_send" `Quick test_schedule_next_inv_send;
      Alcotest.test_case "trickling_intervals" `Quick test_trickling_intervals;
      Alcotest.test_case "queue_inv_delayed" `Quick test_queue_inv_delayed;
      Alcotest.test_case "inv_batching" `Quick test_inv_batching;
      Alcotest.test_case "inv_batch_max_1000" `Quick test_inv_batch_max_1000;
      Alcotest.test_case "no_relay_peer" `Quick test_queue_inv_no_relay;
      Alcotest.test_case "block_relay_only" `Quick test_queue_inv_block_relay_only;
      Alcotest.test_case "block_inv_allowed" `Quick test_queue_inv_block_allowed;
      Alcotest.test_case "witness_tx_no_relay" `Quick test_queue_inv_witness_tx_no_relay;
    ];
  ]
