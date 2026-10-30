(* getpeerinfo conntime must be the time the peer connected (Core
   CNode::m_connected), fixed at connect, not a moving last-activity time. *)
open Camlcoin

let mk () =
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Peer.make_peer ~network:Consensus.mainnet ~addr:"1.2.3.4" ~port:8333
    ~id:1 ~direction:Peer.Outbound ~fd ()

let test_conntime_stable () =
  let peer = mk () in
  let s1 = Peer.get_stats peer in
  Unix.sleepf 2.0;
  (* activity moves last_seen, as message receipt does *)
  peer.Peer.last_seen <- Unix.gettimeofday ();
  let s2 = Peer.get_stats peer in
  Alcotest.(check (float 0.0)) "conn_time unchanged across calls"
    s1.Peer.stat_conn_time s2.Peer.stat_conn_time;
  Alcotest.(check bool) "last_seen moved" true
    (s2.Peer.stat_last_seen -. s1.Peer.stat_last_seen >= 1.9);
  Alcotest.(check bool) "conn_time is not now" true
    (Unix.gettimeofday () -. s2.Peer.stat_conn_time >= 1.9)

let () = Alcotest.run "conntime"
  [ "conntime", [ Alcotest.test_case "stable" `Quick test_conntime_stable ] ]
