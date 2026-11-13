(* One Core-style ConsiderEviction, not two.

   Mainnet restart.log: "Evicting outbound peer N: behind our tip for
   >1200s" came from maintain_connections, which removed any Ready outbound
   peer whose best_height < our_h - 1 for 20 minutes with no getheaders
   challenge.  best_height only moves on a headers message / VERSION, so a
   peer that announced the new tip by cmpctblock / inv / block (and was never
   asked for headers) looked behind forever and was dropped.  Core has a
   single chain-sync eviction (net_processing.cpp ConsiderEviction), which
   challenges first; camlcoin's Stale path (check_stale_peers /
   check_headers_timeout) already does that.

   Command: dune build @test/drop_behind_tip_eviction/runtest --force *)

open Camlcoin

let make_pm () =
  let pm = Peer_manager.create Consensus.regtest in
  Peer_manager.set_height pm 100l;
  Peer_manager.set_header_height pm 100l;
  (* --connect mode: no addrman dialing; the peer below is already
     connected so nothing is re-dialed either. *)
  Peer_manager.set_connect_peers pm [ ("198.51.100.7", 18444) ];
  pm

let make_outbound pm ~best =
  let a, b = Unix.socketpair Unix.PF_UNIX Unix.SOCK_STREAM 0 in
  let p =
    Peer.make_peer ~network:Consensus.regtest ~addr:"198.51.100.7"
      ~port:18444 ~id:7 ~direction:Peer.Outbound
      ~fd:(Lwt_unix.of_unix_file_descr a) ()
  in
  p.Peer.state <- Peer.Ready;
  p.Peer.best_height <- best;
  pm.Peer_manager.peers <- [ p ];
  (p, b)

(* Run one iteration of maintain_connections (it sleeps 10 s after the
   first sweep) and stop it. *)
let one_tick pm =
  Lwt_main.run
    (Lwt.pick
       [ Peer_manager.maintain_connections pm;
         (let%lwt () = Lwt_unix.sleep 0.5 in
          pm.Peer_manager.running <- false;
          Lwt.return_unit) ])

(* Peer announced our tip by cmpctblock/inv/block: best_height stays one
   below ours, no headers message ever arrives, first seen behind 21 min
   ago.  Must survive the maintenance sweep. *)
let test_peer_announcing_tip_without_headers_kept () =
  let pm = make_pm () in
  let p, _b = make_outbound pm ~best:99l in
  pm.Peer_manager.running <- true;
  Hashtbl.replace pm.Peer_manager.chain_sync_behind_since 7
    (Unix.gettimeofday () -. 1300.0);
  (* Also behind by more than the old "- 1" slack. *)
  p.Peer.best_height <- 98l;
  one_tick pm;
  Alcotest.(check bool)
    "outbound peer behind only by best_height bookkeeping is not evicted by \
     maintain_connections"
    true
    (List.exists (fun q -> q.Peer.id = 7) pm.Peer_manager.peers)

(* Control: a peer that really is behind is still evicted, via the
   ConsiderEviction path (challenge, then timeout). *)
let test_really_behind_peer_still_evicted_via_challenge () =
  let pm = make_pm () in
  Peer_manager.set_locator_builder pm (fun () -> []);
  let p, _b = make_outbound pm ~best:90l in
  let st = Peer_manager.get_stale_state pm 7 in
  st.Peer_manager.last_header_time <- Unix.gettimeofday () -. 1300.0;
  Lwt_main.run
    (let%lwt evicted_now = Peer_manager.check_stale_peers pm in
     Alcotest.(check int) "challenge armed, nobody evicted yet" 0
       (List.length evicted_now);
     let later =
       Unix.gettimeofday () +. Peer_manager.Stale.headers_response_time +. 1.0
     in
     Alcotest.(check bool) "unanswered challenge evicts the peer" true
       (Peer_manager.check_headers_timeout pm p ~now:later <> None);
     Lwt.return_unit)

let () =
  Alcotest.run "drop_behind_tip_eviction"
    [ ( "eviction",
        [ Alcotest.test_case "tip announced without headers: kept" `Quick
            test_peer_announcing_tip_without_headers_kept;
          Alcotest.test_case "really behind: still evicted via challenge"
            `Quick test_really_behind_peer_still_evicted_via_challenge ] ) ]
