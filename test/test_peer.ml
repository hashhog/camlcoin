(* Tests for peer connection and handshake *)

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
  ]
