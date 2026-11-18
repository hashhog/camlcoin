(* A pruned node must not advertise NODE_NETWORK (Core init.cpp ~1947-1950)
   and must disconnect a non-NoBan peer asking for a block deeper than
   288+2 below tip (Core ProcessGetBlockData ~2383-2391).  Only uses
   [Peer.our_services]/[set_prune_mode_advertise]/[handle_getdata] so it
   compiles on the pre-fix tree (the ?pruned arg is not used there). *)
open Camlcoin

let bits () = Peer.services_to_int64 (Peer.our_services ())
let with_prune v f =
  Peer.set_prune_mode_advertise v;
  Fun.protect ~finally:(fun () -> Peer.set_prune_mode_advertise false) f

let test_pruned_no_network () =
  with_prune true (fun () ->
    Alcotest.(check bool) "network off" false (Peer.our_services ()).Peer.network;
    Alcotest.(check bool) "limited on" true (Peer.our_services ()).Peer.network_limited;
    Alcotest.(check bool) "witness on" true (Peer.our_services ()).Peer.witness;
    Alcotest.(check int64) "bit0 clear" 0L (Int64.logand (bits ()) 1L))

let test_full_keeps_network () =
  with_prune false (fun () ->
    Alcotest.(check bool) "network on" true (Peer.our_services ()).Peer.network;
    Alcotest.(check int64) "bit0 set" 1L (Int64.logand (bits ()) 1L);
    Alcotest.(check int64) "limited bit" 0x400L (Int64.logand (bits ()) 0x400L))

let mk_peer ~no_ban =
  let (a, b) = Unix.socketpair Unix.PF_UNIX Unix.SOCK_STREAM 0 in
  let p = Peer.make_peer ~network:Consensus.mainnet ~addr:"1.2.3.4" ~port:8333
      ~id:1 ~direction:Peer.Inbound ~no_ban
      ~fd:(Lwt_unix.of_unix_file_descr a) () in
  (p, b)

let hash = Types.hash256_of_hex
    "0000000000000000000000000000000000000000000000000000000000000001"

let run_getdata ~pruned ~no_ban ~block_h =
  with_prune pruned @@ fun () ->
  let (p, _b) = mk_peer ~no_ban in
  let items = [ { P2p.inv_type = P2p.InvWitnessBlock; hash } ] in
  let call () =
    Peer.handle_getdata p items
      ~lookup_block:(fun _ -> None) ~lookup_tx:(fun _ -> None)
      ~lookup_wtx:(fun _ -> None) ~tip_height:1000
      ~lookup_block_height:(fun _ -> Some block_h) in
  Lwt_main.run (call ());
  (p.Peer.state = Peer.Disconnecting || p.Peer.state = Peer.Disconnected)

let test_pruned_deep_disconnects () =
  Alcotest.(check bool) "disconnected" true
    (run_getdata ~pruned:true ~no_ban:false ~block_h:500)

let test_pruned_boundary () =
  (* 1000 - 710 = 290 is NOT > 290: keep; 709 -> 291: disconnect *)
  Alcotest.(check bool) "290 kept" false
    (run_getdata ~pruned:true ~no_ban:false ~block_h:710);
  Alcotest.(check bool) "291 dropped" true
    (run_getdata ~pruned:true ~no_ban:false ~block_h:709)

let test_noban_kept () =
  Alcotest.(check bool) "noban kept" false
    (run_getdata ~pruned:true ~no_ban:true ~block_h:500)

let test_nonpruned_deep_kept () =
  Alcotest.(check bool) "non-pruned kept" false
    (run_getdata ~pruned:false ~no_ban:false ~block_h:500)

let () =
  Alcotest.run "pruned-services" [
    "services", [
      Alcotest.test_case "pruned_no_network" `Quick test_pruned_no_network;
      Alcotest.test_case "full_keeps_network" `Quick test_full_keeps_network ];
    "getdata", [
      Alcotest.test_case "pruned_deep_disconnects" `Quick test_pruned_deep_disconnects;
      Alcotest.test_case "pruned_boundary" `Quick test_pruned_boundary;
      Alcotest.test_case "noban_kept" `Quick test_noban_kept;
      Alcotest.test_case "nonpruned_deep_kept" `Quick test_nonpruned_deep_kept ] ]
