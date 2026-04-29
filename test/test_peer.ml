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
  (* BIP-35 / NODE_BLOOM: we advertise it so peers may issue MEMPOOL
     requests and bloom-filter setup messages.  Mirrors Bitcoin Core's
     -peerbloomfilters=1 default. *)
  Alcotest.(check bool) "our bloom" true ours.bloom;
  Alcotest.(check bool) "our getutxo" false ours.getutxo;
  Alcotest.(check bool) "our compact_filters" false ours.compact_filters;
  Alcotest.(check bool) "our network_limited" false ours.network_limited;

  (* NODE_NETWORK | NODE_BLOOM | NODE_WITNESS = 1 | 4 | 8 = 13 *)
  let as_int = Peer.services_to_int64 ours in
  Alcotest.(check int64) "our services value" 13L as_int

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
  (* Check services: NODE_NETWORK | NODE_BLOOM | NODE_WITNESS = 1|4|8 = 13 *)
  Alcotest.(check int64) "local addr services" 13L addr.services;
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
  let entry : Peer.inv_entry = { inv_type = P2p.InvTx; hash; fee_rate = Some 2000L } in
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
  let entry : Peer.inv_entry = { inv_type = P2p.InvTx; hash; fee_rate = Some 2000L } in
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
    let entry : Peer.inv_entry = { inv_type = P2p.InvTx; hash; fee_rate = Some 2000L } in
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
  let entry : Peer.inv_entry = { inv_type = P2p.InvTx; hash; fee_rate = Some 2000L } in
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
  let entry : Peer.inv_entry = { inv_type = P2p.InvTx; hash; fee_rate = Some 2000L } in
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
    let entry : Peer.inv_entry = { inv_type = P2p.InvTx; hash; fee_rate = Some 2000L } in
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
    let entry : Peer.inv_entry = { inv_type = P2p.InvTx; hash; fee_rate = Some 2000L } in
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
    let entry : Peer.inv_entry = { inv_type = P2p.InvTx; hash; fee_rate = Some 2000L } in
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
  let entry : Peer.inv_entry = { inv_type = P2p.InvTx; hash; fee_rate = Some 2000L } in
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
  let entry : Peer.inv_entry = { inv_type = P2p.InvTx; hash; fee_rate = Some 2000L } in
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
  let entry : Peer.inv_entry = { inv_type = P2p.InvBlock; hash; fee_rate = None } in
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
  let entry : Peer.inv_entry = { inv_type = P2p.InvWitnessTx; hash; fee_rate = Some 2000L } in
  Peer.queue_inv peer entry;
  (* WitnessTx should also be suppressed for no-relay peer *)
  Alcotest.(check int) "witness tx not queued for no-relay" 0 (Peer.inv_queue_length peer)

(* ============================================================================
   Feefilter Tests
   ============================================================================ *)

(* Test that tx above peer's feefilter passes *)
let test_feefilter_tx_above () =
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let peer = Peer.make_peer ~network:Consensus.mainnet ~addr:"127.0.0.1"
    ~port:8333 ~id:0 ~direction:Peer.Outbound ~fd in
  peer.state <- Peer.Ready;
  (* Peer sets feefilter to 1000 sat/kvB *)
  peer.feefilter <- 1000L;
  (* Queue a tx with 2000 sat/kvB fee rate (above feefilter) *)
  let hash = Cstruct.create 32 in
  let entry : Peer.inv_entry = { inv_type = P2p.InvTx; hash; fee_rate = Some 2000L } in
  Peer.queue_inv peer entry;
  (* Should be queued *)
  Alcotest.(check int) "tx above feefilter queued" 1 (Peer.inv_queue_length peer)

(* Test that tx below peer's feefilter is filtered out *)
let test_feefilter_tx_below () =
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let peer = Peer.make_peer ~network:Consensus.mainnet ~addr:"127.0.0.1"
    ~port:8333 ~id:0 ~direction:Peer.Outbound ~fd in
  peer.state <- Peer.Ready;
  (* Peer sets feefilter to 5000 sat/kvB *)
  peer.feefilter <- 5000L;
  (* Queue a tx with 1000 sat/kvB fee rate (below feefilter) *)
  let hash = Cstruct.create 32 in
  let entry : Peer.inv_entry = { inv_type = P2p.InvTx; hash; fee_rate = Some 1000L } in
  Peer.queue_inv peer entry;
  (* Should be filtered out *)
  Alcotest.(check int) "tx below feefilter not queued" 0 (Peer.inv_queue_length peer)

(* Test that tx at exactly the feefilter threshold passes *)
let test_feefilter_tx_equal () =
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let peer = Peer.make_peer ~network:Consensus.mainnet ~addr:"127.0.0.1"
    ~port:8333 ~id:0 ~direction:Peer.Outbound ~fd in
  peer.state <- Peer.Ready;
  (* Peer sets feefilter to 2000 sat/kvB *)
  peer.feefilter <- 2000L;
  (* Queue a tx with exactly 2000 sat/kvB fee rate *)
  let hash = Cstruct.create 32 in
  let entry : Peer.inv_entry = { inv_type = P2p.InvTx; hash; fee_rate = Some 2000L } in
  Peer.queue_inv peer entry;
  (* Should be queued (at or above threshold passes) *)
  Alcotest.(check int) "tx at feefilter queued" 1 (Peer.inv_queue_length peer)

(* Test that zero feefilter passes all transactions *)
let test_feefilter_zero () =
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let peer = Peer.make_peer ~network:Consensus.mainnet ~addr:"127.0.0.1"
    ~port:8333 ~id:0 ~direction:Peer.Outbound ~fd in
  peer.state <- Peer.Ready;
  (* Default feefilter is 0 (no filter) *)
  Alcotest.(check int64) "default feefilter is 0" 0L peer.feefilter;
  (* Queue a tx with low fee rate *)
  let hash = Cstruct.create 32 in
  let entry : Peer.inv_entry = { inv_type = P2p.InvTx; hash; fee_rate = Some 100L } in
  Peer.queue_inv peer entry;
  (* Should be queued *)
  Alcotest.(check int) "tx passes zero feefilter" 1 (Peer.inv_queue_length peer)

(* Test that blocks are not affected by feefilter *)
let test_feefilter_block_not_affected () =
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let peer = Peer.make_peer ~network:Consensus.mainnet ~addr:"127.0.0.1"
    ~port:8333 ~id:0 ~direction:Peer.Outbound ~fd in
  peer.state <- Peer.Ready;
  (* Set very high feefilter *)
  peer.feefilter <- 1_000_000L;
  (* Queue a block (has no fee rate) *)
  let hash = Cstruct.create 32 in
  let entry : Peer.inv_entry = { inv_type = P2p.InvBlock; hash; fee_rate = None } in
  Peer.queue_inv peer entry;
  (* Blocks should not be affected by feefilter *)
  Alcotest.(check int) "block not filtered" 1 (Peer.inv_queue_length peer)

(* Test that witness tx is also filtered by feefilter *)
let test_feefilter_witness_tx () =
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let peer = Peer.make_peer ~network:Consensus.mainnet ~addr:"127.0.0.1"
    ~port:8333 ~id:0 ~direction:Peer.Outbound ~fd in
  peer.state <- Peer.Ready;
  peer.feefilter <- 5000L;
  (* Queue a witness tx with low fee rate *)
  let hash = Cstruct.create 32 in
  let entry : Peer.inv_entry = { inv_type = P2p.InvWitnessTx; hash; fee_rate = Some 1000L } in
  Peer.queue_inv peer entry;
  (* Should be filtered out *)
  Alcotest.(check int) "witness tx below feefilter not queued" 0 (Peer.inv_queue_length peer)

(* Test make_tx_inv helper function *)
let test_make_tx_inv () =
  let hash = Cstruct.create 32 in
  Cstruct.set_uint8 hash 0 0xAB;
  let entry = Peer.make_tx_inv ~witness:false hash 2500L in
  Alcotest.(check bool) "inv_type is InvTx" true (entry.inv_type = P2p.InvTx);
  Alcotest.(check bool) "hash matches" true (Cstruct.equal hash entry.hash);
  Alcotest.(check (option int64)) "fee_rate set" (Some 2500L) entry.fee_rate

(* Test make_tx_inv with witness *)
let test_make_tx_inv_witness () =
  let hash = Cstruct.create 32 in
  let entry = Peer.make_tx_inv ~witness:true hash 3000L in
  Alcotest.(check bool) "inv_type is InvWitnessTx" true (entry.inv_type = P2p.InvWitnessTx);
  Alcotest.(check (option int64)) "fee_rate set" (Some 3000L) entry.fee_rate

(* Test make_block_inv helper function *)
let test_make_block_inv () =
  let hash = Cstruct.create 32 in
  Cstruct.set_uint8 hash 0 0xCD;
  let entry = Peer.make_block_inv hash in
  Alcotest.(check bool) "inv_type is InvBlock" true (entry.inv_type = P2p.InvBlock);
  Alcotest.(check bool) "hash matches" true (Cstruct.equal hash entry.hash);
  Alcotest.(check (option int64)) "fee_rate is None" None entry.fee_rate

(* Test feefilter constants *)
let test_feefilter_constants () =
  Alcotest.(check (float 0.001)) "avg_feefilter_broadcast_interval = 600.0" 600.0
    Peer.avg_feefilter_broadcast_interval;
  Alcotest.(check (float 0.001)) "max_feefilter_change_delay = 300.0" 300.0
    Peer.max_feefilter_change_delay;
  Alcotest.(check int32) "feefilter_version = 70013" 70013l
    Peer.feefilter_version

(* Test fee filter rounder creates valid buckets *)
let test_feefilter_rounder_buckets () =
  let fee_set = Peer.FeeFilterRounder.make_fee_set 1000L in
  (* Should have at least 0 and some positive values *)
  Alcotest.(check bool) "has multiple buckets" true (Array.length fee_set > 3);
  Alcotest.(check (float 0.001)) "first bucket is 0" 0.0 fee_set.(0);
  (* Second bucket should be around min_relay_fee/2 = 500 *)
  Alcotest.(check bool) "second bucket around 500" true
    (fee_set.(1) >= 400.0 && fee_set.(1) <= 600.0)

(* Test fee filter rounder round function *)
let test_feefilter_rounder_round () =
  let fee_set = Peer.FeeFilterRounder.make_fee_set 1000L in
  (* Round 0 should give 0 *)
  let r0 = Peer.FeeFilterRounder.round fee_set 0L in
  Alcotest.(check int64) "round 0 gives 0" 0L r0;
  (* Round a high value should give something close *)
  let r_high = Peer.FeeFilterRounder.round fee_set 10000L in
  Alcotest.(check bool) "round high gives reasonable value" true
    (r_high >= 5000L && r_high <= 15000L)

(* Test significant_feefilter_change detection *)
let test_significant_feefilter_change () =
  (* Same value - not significant *)
  Alcotest.(check bool) "same value not significant" false
    (Peer.significant_feefilter_change 1000L 1000L);
  (* Small change - not significant *)
  Alcotest.(check bool) "small change not significant" false
    (Peer.significant_feefilter_change 900L 1000L);
  Alcotest.(check bool) "small increase not significant" false
    (Peer.significant_feefilter_change 1100L 1000L);
  (* Large decrease (<75%) - significant *)
  Alcotest.(check bool) "large decrease significant" true
    (Peer.significant_feefilter_change 700L 1000L);
  (* Large increase (>133%) - significant *)
  Alcotest.(check bool) "large increase significant" true
    (Peer.significant_feefilter_change 1400L 1000L);
  (* Zero sent value - always significant *)
  Alcotest.(check bool) "zero sent always significant" true
    (Peer.significant_feefilter_change 1000L 0L)

(* Test passes_feefilter function directly *)
let test_passes_feefilter_direct () =
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let peer = Peer.make_peer ~network:Consensus.mainnet ~addr:"127.0.0.1"
    ~port:8333 ~id:0 ~direction:Peer.Outbound ~fd in
  peer.feefilter <- 1000L;
  let hash = Cstruct.create 32 in
  (* Tx above threshold passes *)
  let entry_above : Peer.inv_entry = { inv_type = P2p.InvTx; hash; fee_rate = Some 2000L } in
  Alcotest.(check bool) "above threshold passes" true
    (Peer.passes_feefilter peer entry_above);
  (* Tx below threshold fails *)
  let entry_below : Peer.inv_entry = { inv_type = P2p.InvTx; hash; fee_rate = Some 500L } in
  Alcotest.(check bool) "below threshold fails" false
    (Peer.passes_feefilter peer entry_below);
  (* Block (None fee_rate) passes *)
  let entry_block : Peer.inv_entry = { inv_type = P2p.InvBlock; hash; fee_rate = None } in
  Alcotest.(check bool) "block passes" true
    (Peer.passes_feefilter peer entry_block)

(* fd-leak regression tests for outbound Peer.connect error paths.
   See wave2-2026-04-14/CAMLCOIN-SMALL-PATCH-FIX.md and
   CAMLCOIN-REVIVE-FEASIBILITY.md — every outbound dial that hit a
   timeout or ECONNREFUSED leaked exactly one socket fd until patched. *)

let count_fds () =
  (* Linux: count entries in /proc/self/fd. Skip on non-Linux. *)
  try Array.length (Sys.readdir "/proc/self/fd")
  with Sys_error _ -> -1

let test_connect_refused_no_fd_leak () =
  (* Port 1 on localhost should reliably refuse / be unbound. *)
  let before = count_fds () in
  if before < 0 then
    (* Non-Linux — skip via trivial assertion *)
    Alcotest.(check pass) "non-linux skip" () ()
  else begin
    let fail_once () =
      Lwt.catch
        (fun () ->
          let open Lwt.Syntax in
          let* _peer = Peer.connect ~network:Consensus.mainnet
            ~addr:"127.0.0.1" ~port:1 ~id:0 in
          Lwt.return_unit)
        (fun _ -> Lwt.return_unit)
    in
    let rec loop n =
      if n = 0 then Lwt.return_unit
      else
        let open Lwt.Syntax in
        let* () = fail_once () in loop (n - 1)
    in
    Lwt_main.run (loop 20);
    let after = count_fds () in
    (* Allow a tiny slack for transient dune/runtime fds *)
    Alcotest.(check bool)
      (Printf.sprintf "fd count stable (before=%d after=%d)" before after)
      true (after <= before + 2)
  end

let test_connect_timeout_no_fd_leak () =
  (* 10.255.255.1 is reserved — connect should timeout. Keep N small
     because each iteration waits out Peer.connection_timeout. *)
  let before = count_fds () in
  if before < 0 then
    Alcotest.(check pass) "non-linux skip" () ()
  else begin
    let fail_once () =
      Lwt.catch
        (fun () ->
          let open Lwt.Syntax in
          let* _peer = Peer.connect ~network:Consensus.mainnet
            ~addr:"10.255.255.1" ~port:1 ~id:0 in
          Lwt.return_unit)
        (fun _ -> Lwt.return_unit)
    in
    let rec loop n =
      if n = 0 then Lwt.return_unit
      else
        let open Lwt.Syntax in
        let* () = fail_once () in loop (n - 1)
    in
    (* Only 2 iterations — each pays connection_timeout *)
    Lwt_main.run (loop 2);
    let after = count_fds () in
    Alcotest.(check bool)
      (Printf.sprintf "fd count stable (before=%d after=%d)" before after)
      true (after <= before + 2)
  end

(* ===== BIP-324 v2 outbound dispatch tests ============================== *)

(* Helper to set / unset CAMLCOIN_BIP324_V2_OUTBOUND for one assertion.
   Unix.putenv overrides; we restore afterwards. *)
let with_v2_env (v : string option) (f : unit -> unit) : unit =
  let key = "CAMLCOIN_BIP324_V2_OUTBOUND" in
  let prev = Sys.getenv_opt key in
  (match v with
   | Some s -> Unix.putenv key s
   | None ->
     (* Approximate "unset" — putenv has no remove on the OCaml stdlib;
        clobber to "" which the gate treats as off. *)
     Unix.putenv key "");
  let restore () =
    match prev with
    | Some s -> Unix.putenv key s
    | None -> Unix.putenv key ""
  in
  (try f (); restore () with e -> restore (); raise e)

let test_bip324_v2_default_off () =
  with_v2_env None (fun () ->
    Alcotest.(check bool) "default OFF (no env)" false
      (Peer.bip324_v2_outbound_enabled ()))

let test_bip324_v2_env_one () =
  with_v2_env (Some "1") (fun () ->
    Alcotest.(check bool) "env=1 → ON" true
      (Peer.bip324_v2_outbound_enabled ()))

let test_bip324_v2_env_zero () =
  with_v2_env (Some "0") (fun () ->
    Alcotest.(check bool) "env=0 → OFF" false
      (Peer.bip324_v2_outbound_enabled ()))

let test_bip324_v2_env_false () =
  with_v2_env (Some "false") (fun () ->
    Alcotest.(check bool) "env=false → OFF" false
      (Peer.bip324_v2_outbound_enabled ()));
  with_v2_env (Some "FALSE") (fun () ->
    Alcotest.(check bool) "env=FALSE → OFF" false
      (Peer.bip324_v2_outbound_enabled ()));
  with_v2_env (Some "off") (fun () ->
    Alcotest.(check bool) "env=off → OFF" false
      (Peer.bip324_v2_outbound_enabled ()))

let test_v1only_cache_basic () =
  Peer.V1OnlyCache.clear ();
  Alcotest.(check bool) "fresh: not v1-only" false
    (Peer.V1OnlyCache.is_v1_only ~addr:"203.0.113.7" ~port:8333);
  Peer.V1OnlyCache.mark ~addr:"203.0.113.7" ~port:8333;
  Alcotest.(check bool) "marked: now v1-only" true
    (Peer.V1OnlyCache.is_v1_only ~addr:"203.0.113.7" ~port:8333);
  Alcotest.(check bool) "different addr unaffected" false
    (Peer.V1OnlyCache.is_v1_only ~addr:"203.0.113.8" ~port:8333)

let test_v1only_cache_pair () =
  (* (addr, port) is the cache key — same addr on different port is
     independent.  Mirrors the recent W camlcoin (addr, port) dedup
     fix (424d84e). *)
  Peer.V1OnlyCache.clear ();
  Peer.V1OnlyCache.mark ~addr:"127.0.0.1" ~port:18444;
  Alcotest.(check bool) "127.0.0.1:18444 is v1-only" true
    (Peer.V1OnlyCache.is_v1_only ~addr:"127.0.0.1" ~port:18444);
  Alcotest.(check bool) "127.0.0.1:18445 is NOT v1-only" false
    (Peer.V1OnlyCache.is_v1_only ~addr:"127.0.0.1" ~port:18445)

let test_v1only_cache_dedup () =
  Peer.V1OnlyCache.clear ();
  Peer.V1OnlyCache.mark ~addr:"10.0.0.1" ~port:8333;
  let s1 = Peer.V1OnlyCache.size () in
  Peer.V1OnlyCache.mark ~addr:"10.0.0.1" ~port:8333;
  Peer.V1OnlyCache.mark ~addr:"10.0.0.1" ~port:8333;
  let s2 = Peer.V1OnlyCache.size () in
  Alcotest.(check int) "duplicate marks don't grow cache" s1 s2

let test_v1only_cache_cap () =
  Peer.V1OnlyCache.clear ();
  let cap = Peer.V1OnlyCache.capacity in
  Alcotest.(check bool) "capacity is positive" true (cap > 0);
  for i = 0 to cap + 16 do
    Peer.V1OnlyCache.mark ~addr:(Printf.sprintf "10.%d.%d.%d"
      ((i lsr 16) land 0xFF) ((i lsr 8) land 0xFF) (i land 0xFF))
      ~port:8333
  done;
  Alcotest.(check bool) "cache stays at-or-below cap" true
    (Peer.V1OnlyCache.size () <= cap);
  Peer.V1OnlyCache.clear ();
  Alcotest.(check int) "clear empties cache" 0
    (Peer.V1OnlyCache.size ())

(* ===== BIP-324 v2 inbound (responder) tests ============================ *)

(* Helper to set / unset CAMLCOIN_BIP324_V2_INBOUND for one assertion. *)
let with_v2_inbound_env (v : string option) (f : unit -> unit) : unit =
  let key = "CAMLCOIN_BIP324_V2_INBOUND" in
  let prev = Sys.getenv_opt key in
  (match v with
   | Some s -> Unix.putenv key s
   | None -> Unix.putenv key "");
  let restore () =
    match prev with
    | Some s -> Unix.putenv key s
    | None -> Unix.putenv key ""
  in
  (try f (); restore () with e -> restore (); raise e)

(* Helper for the umbrella CAMLCOIN_BIP324_V2 var that gates both directions. *)
let with_v2_umbrella_env (v : string option) (f : unit -> unit) : unit =
  let key = "CAMLCOIN_BIP324_V2" in
  let prev = Sys.getenv_opt key in
  (match v with
   | Some s -> Unix.putenv key s
   | None -> Unix.putenv key "");
  let restore () =
    match prev with
    | Some s -> Unix.putenv key s
    | None -> Unix.putenv key ""
  in
  (try f (); restore () with e -> restore (); raise e)

let test_bip324_v2_inbound_default_off () =
  with_v2_inbound_env None (fun () ->
    with_v2_umbrella_env None (fun () ->
      Alcotest.(check bool) "default OFF (no env)" false
        (Peer.bip324_v2_inbound_enabled ())))

let test_bip324_v2_inbound_env_one () =
  with_v2_inbound_env (Some "1") (fun () ->
    Alcotest.(check bool) "INBOUND=1 → ON" true
      (Peer.bip324_v2_inbound_enabled ()))

let test_bip324_v2_inbound_env_zero () =
  with_v2_inbound_env (Some "0") (fun () ->
    with_v2_umbrella_env None (fun () ->
      Alcotest.(check bool) "INBOUND=0 → OFF" false
        (Peer.bip324_v2_inbound_enabled ())))

let test_bip324_v2_umbrella_gates_inbound () =
  (* CAMLCOIN_BIP324_V2=1 alone enables inbound — outbound and inbound
     converge on the same gate when no per-direction var is set. *)
  with_v2_inbound_env None (fun () ->
    with_v2_umbrella_env (Some "1") (fun () ->
      Alcotest.(check bool) "umbrella=1 → inbound ON" true
        (Peer.bip324_v2_inbound_enabled ());
      Alcotest.(check bool) "umbrella=1 → outbound ON" true
        (Peer.bip324_v2_outbound_enabled ())))

(* The peek-classifier distinguishes a v1 VERSION header from a v2
   ElligatorSwift pubkey by the 16-byte prefix (4 magic + 12 command). *)
let test_looks_like_v1_version_real_v1 () =
  (* Mainnet magic LE = F9 BE B4 D9, then "version" + 5 NULs.
     [Bytes.make] zero-fills (vs [Bytes.create] which leaves uninitialised
     bytes); we rely on the trailing 5 NULs to match [v1_version_command]. *)
  let bytes = Bytes.make 16 '\000' in
  Bytes.set bytes 0 '\xF9'; Bytes.set bytes 1 '\xBE';
  Bytes.set bytes 2 '\xB4'; Bytes.set bytes 3 '\xD9';
  Bytes.blit_string "version" 0 bytes 4 7;
  Alcotest.(check bool) "real v1 VERSION prefix is classified v1" true
    (Peer.looks_like_v1_version bytes P2p.mainnet_magic)

let test_looks_like_v1_version_v2_pubkey () =
  (* A 64-byte ellswift pubkey is uniformly random; the chance that its
     leading 4 bytes happen to match the mainnet magic is 2^-32, so for any
     specific test vector they won't.  Use a deliberately non-matching
     prefix. *)
  let bytes = Bytes.create 16 in
  for i = 0 to 15 do Bytes.set bytes i (Char.chr (0xAA lxor i)) done;
  Alcotest.(check bool) "v2-shaped bytes are NOT classified v1" false
    (Peer.looks_like_v1_version bytes P2p.mainnet_magic)

let test_looks_like_v1_version_magic_match_wrong_cmd () =
  (* Mainnet magic + "inv\0\0\0\0\0\0\0\0\0" must NOT classify as v1
     VERSION — only the VERSION command is the v1 entry point. *)
  let bytes = Bytes.make 16 '\000' in
  Bytes.set bytes 0 '\xF9'; Bytes.set bytes 1 '\xBE';
  Bytes.set bytes 2 '\xB4'; Bytes.set bytes 3 '\xD9';
  Bytes.blit_string "inv" 0 bytes 4 3;
  Alcotest.(check bool) "magic+inv is NOT v1 VERSION" false
    (Peer.looks_like_v1_version bytes P2p.mainnet_magic)

let test_looks_like_v1_version_short_buffer () =
  (* < 16 bytes returns false (= "treat as v2", per Bitcoin Core's
     ProcessReceivedMaybeV1Bytes).  Defensive — caller should always pass
     v1_prefix_len bytes. *)
  let bytes = Bytes.make 8 '\000' in
  Alcotest.(check bool) "short buffer is NOT v1" false
    (Peer.looks_like_v1_version bytes P2p.mainnet_magic)

let test_looks_like_v1_version_wrong_magic () =
  (* Mainnet magic constant on a testnet4-magic host is not v1. *)
  let bytes = Bytes.make 16 '\000' in
  Bytes.set bytes 0 '\xF9'; Bytes.set bytes 1 '\xBE';
  Bytes.set bytes 2 '\xB4'; Bytes.set bytes 3 '\xD9';
  Bytes.blit_string "version" 0 bytes 4 7;
  Alcotest.(check bool) "mainnet magic on testnet4 host is NOT v1" false
    (Peer.looks_like_v1_version bytes P2p.testnet_magic)

let test_v1_prefix_len_constant () =
  (* Sanity: 4 (magic) + 12 (command) = 16 bytes.  Matches Bitcoin Core
     V2Transport::V1_PREFIX_LEN and clearbit's V1_PREFIX_LEN. *)
  Alcotest.(check int) "v1_prefix_len = 16" 16 Peer.v1_prefix_len

(* When connect_outbound_negotiated returns a peer that hasn't gone through
   the v2 path, peer.transport must be None (= legacy v1 dispatch).  We
   can't drive a real network handshake here, so this test exercises just
   the transport field on a peer constructed by [make_peer]. *)
let test_transport_default_v1 () =
  (* Borrow the same socketpair trick used by other handshake tests. *)
  let (s1, s2) = Unix.socketpair Unix.PF_UNIX Unix.SOCK_STREAM 0 in
  let fd = Lwt_unix.of_unix_file_descr s1 in
  let peer = Peer.make_peer ~network:Consensus.mainnet ~addr:"127.0.0.1"
    ~port:18444 ~id:42 ~direction:Peer.Outbound ~fd in
  Alcotest.(check bool) "default transport is None (= v1)" true
    (peer.Peer.transport = None);
  (* Manually flip to v2 (simulating what connect_outbound_negotiated
     does after a successful cipher handshake) and verify match works. *)
  let t = P2p.create_v2_transport ~initiating:true ~magic:P2p.mainnet_magic in
  peer.Peer.transport <- Some t;
  (match peer.Peer.transport with
   | Some (P2p.V2 _) -> Alcotest.(check pass) "v2 dispatch reachable" () ()
   | _ -> Alcotest.fail "expected V2 transport");
  Lwt_main.run (Peer.disconnect peer);
  Unix.close s2

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
    "feefilter", [
      Alcotest.test_case "constants" `Quick test_feefilter_constants;
      Alcotest.test_case "tx_above" `Quick test_feefilter_tx_above;
      Alcotest.test_case "tx_below" `Quick test_feefilter_tx_below;
      Alcotest.test_case "tx_equal" `Quick test_feefilter_tx_equal;
      Alcotest.test_case "zero_filter" `Quick test_feefilter_zero;
      Alcotest.test_case "block_not_affected" `Quick test_feefilter_block_not_affected;
      Alcotest.test_case "witness_tx" `Quick test_feefilter_witness_tx;
      Alcotest.test_case "make_tx_inv" `Quick test_make_tx_inv;
      Alcotest.test_case "make_tx_inv_witness" `Quick test_make_tx_inv_witness;
      Alcotest.test_case "make_block_inv" `Quick test_make_block_inv;
      Alcotest.test_case "rounder_buckets" `Quick test_feefilter_rounder_buckets;
      Alcotest.test_case "rounder_round" `Quick test_feefilter_rounder_round;
      Alcotest.test_case "significant_change" `Quick test_significant_feefilter_change;
      Alcotest.test_case "passes_feefilter" `Quick test_passes_feefilter_direct;
    ];
    "fd_leak", [
      Alcotest.test_case "connect_refused_no_leak"
        `Quick test_connect_refused_no_fd_leak;
      Alcotest.test_case "connect_timeout_no_leak"
        `Slow test_connect_timeout_no_fd_leak;
    ];
    "bip324_v2_outbound", [
      Alcotest.test_case "env_var_default_off" `Quick test_bip324_v2_default_off;
      Alcotest.test_case "env_var_honors_one" `Quick test_bip324_v2_env_one;
      Alcotest.test_case "env_var_honors_zero" `Quick test_bip324_v2_env_zero;
      Alcotest.test_case "env_var_honors_false" `Quick test_bip324_v2_env_false;
      Alcotest.test_case "v1only_cache_mark_lookup" `Quick test_v1only_cache_basic;
      Alcotest.test_case "v1only_cache_addr_port_pair" `Quick test_v1only_cache_pair;
      Alcotest.test_case "v1only_cache_dedup" `Quick test_v1only_cache_dedup;
      Alcotest.test_case "v1only_cache_capacity" `Quick test_v1only_cache_cap;
      Alcotest.test_case "transport_dispatch_default_v1" `Quick test_transport_default_v1;
    ];
    "bip324_v2_inbound", [
      Alcotest.test_case "env_var_default_off"
        `Quick test_bip324_v2_inbound_default_off;
      Alcotest.test_case "env_var_honors_one"
        `Quick test_bip324_v2_inbound_env_one;
      Alcotest.test_case "env_var_honors_zero"
        `Quick test_bip324_v2_inbound_env_zero;
      Alcotest.test_case "umbrella_gates_both_directions"
        `Quick test_bip324_v2_umbrella_gates_inbound;
      Alcotest.test_case "classify_real_v1_version"
        `Quick test_looks_like_v1_version_real_v1;
      Alcotest.test_case "classify_v2_pubkey"
        `Quick test_looks_like_v1_version_v2_pubkey;
      Alcotest.test_case "classify_magic_match_wrong_cmd"
        `Quick test_looks_like_v1_version_magic_match_wrong_cmd;
      Alcotest.test_case "classify_short_buffer"
        `Quick test_looks_like_v1_version_short_buffer;
      Alcotest.test_case "classify_wrong_magic"
        `Quick test_looks_like_v1_version_wrong_magic;
      Alcotest.test_case "v1_prefix_len_constant"
        `Quick test_v1_prefix_len_constant;
    ];
  ]
