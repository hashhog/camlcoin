(* Outbound budgets are independent (Core net.h: 8 full-relay + 2
   block-relay-only).  camlcoin counted block-relay-only peers against the 8
   full-relay slots, so a fully-connected node held 6 full-relay + 2 BRO, and
   getpeerinfo reported every outbound peer as "outbound-full-relay", which
   made the fleet sampler read the shortfall as "8 full-relay" while DONE
   criterion 3b (8 full-relay outbound) was never actually met. *)

open Camlcoin

let make_pm () =
  Peer_manager.create Consensus.mainnet

let make_peer ~id ~bro =
  let (a, _b) = Unix.socketpair Unix.PF_UNIX Unix.SOCK_STREAM 0 in
  let fd = Lwt_unix.of_unix_file_descr a in
  let p = Peer.make_peer ~network:Consensus.mainnet
      ~addr:(Printf.sprintf "198.51.%d.1" id) ~port:8333 ~id
      ~direction:Peer.Outbound ~fd () in
  p.Peer.state <- Peer.Ready;
  p.Peer.block_relay_only <- bro;
  p

let fill pm ~full ~bro =
  let mk n bro base = List.init n (fun i -> make_peer ~id:(base + i) ~bro) in
  pm.Peer_manager.peers <- mk full false 1 @ mk bro true 100

let test_full_relay_count_excludes_bro () =
  let pm = make_pm () in
  fill pm ~full:6 ~bro:2;
  Alcotest.(check int) "6 full + 2 BRO counts 6 full-relay" 6
    (Peer_manager.outbound_peer_count pm);
  Alcotest.(check int) "BRO count is its own" 2
    (Peer_manager.block_relay_only_count pm)

let test_eight_full_relay_slots_fill_alongside_bro () =
  let pm = make_pm () in
  fill pm ~full:7 ~bro:2;
  (* One slot short of 8 full-relay: the dialer must still want one more. *)
  Alcotest.(check bool) "7 full + 2 BRO leaves a full-relay slot open" true
    (Peer_manager.outbound_peer_count pm < pm.Peer_manager.config.max_outbound);
  fill pm ~full:8 ~bro:2;
  Alcotest.(check int) "8 full + 2 BRO = 8 full-relay" 8
    (Peer_manager.outbound_peer_count pm);
  Alcotest.(check bool) "8 full-relay fills the budget" true
    (Peer_manager.outbound_peer_count pm >= pm.Peer_manager.config.max_outbound)

let test_connection_type () =
  Alcotest.(check string) "full relay" "outbound-full-relay"
    (Peer_manager.connection_type_of_peer (make_peer ~id:1 ~bro:false));
  Alcotest.(check string) "block relay only" "block-relay-only"
    (Peer_manager.connection_type_of_peer (make_peer ~id:2 ~bro:true))

let () =
  Alcotest.run "outbound_budget"
    [ ("budget", [
        Alcotest.test_case "full-relay count excludes BRO" `Quick
          test_full_relay_count_excludes_bro;
        Alcotest.test_case "8 full-relay slots alongside 2 BRO" `Quick
          test_eight_full_relay_slots_fill_alongside_bro;
        Alcotest.test_case "getpeerinfo connection_type" `Quick
          test_connection_type ]) ]
