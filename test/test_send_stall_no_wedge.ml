(* A peer that stops reading must not slow anyone else down, and must be
   dropped — camlcoin C-1 (fleet sweep 2026-10-05 item 5).

   Core never blocks on a socket (net.cpp: per-peer send queue, pause-recv,
   InactivityCheck).  camlcoin b08ea33 awaited sends with a 10 s ABSOLUTE
   timeout whose failure every broadcaster swallowed, so a non-reading peer
   stayed Ready and cost each later send another 10 s; announce_block /
   broadcast awaited every peer before returning; a slow-but-reading peer
   was cut off mid-message after 10 s even while it kept draining.

   Real Peer / Peer_manager code over Unix socketpairs (8 KiB buffers).
   S = stuck (remote never reads), G = good (remote reads everything),
   W = slow (remote reads 8 KiB per 100 ms).  Each "big" message is an inv
   with 35,000 entries (~1.26 MB), far more than the socket buffers hold. *)

open Camlcoin

let ( let* ) = Lwt.bind

let net = Consensus.regtest

let small_buf fd =
  (try Unix.setsockopt_int fd Unix.SO_SNDBUF 8192 with _ -> ());
  (try Unix.setsockopt_int fd Unix.SO_RCVBUF 8192 with _ -> ())

(* (our peer, remote raw fd) *)
let mk_peer id =
  let a, b = Unix.socketpair Unix.PF_UNIX Unix.SOCK_STREAM 0 in
  small_buf a; small_buf b;
  let fd = Lwt_unix.of_unix_file_descr ~blocking:false a in
  let p = Peer.make_peer ~network:net ~addr:"127.0.0.1" ~port:(18500 + id) ~id
      ~direction:Peer.Inbound ~fd () in
  p.Peer.state <- Peer.Ready;
  (p, Lwt_unix.of_unix_file_descr ~blocking:false b)

let big_inv () =
  let h i = let c = Cstruct.create 32 in Cstruct.LE.set_uint32 c 0 (Int32.of_int i); c in
  P2p.InvMsg (List.init 35_000 (fun i -> { P2p.inv_type = P2p.InvTx; hash = h i }))

(* Remote side that reads everything forever; counts bytes. *)
let drain ?(chunk = 65536) ?(pause = 0.0) remote counter =
  let buf = Bytes.create chunk in
  let rec go () =
    let* n = Lwt.catch (fun () -> Lwt_unix.read remote buf 0 chunk)
        (fun _ -> Lwt.return 0) in
    if n = 0 then Lwt.return_unit
    else begin
      counter := !counter + n;
      let* () = if pause > 0.0 then Lwt_unix.sleep pause else Lwt.return_unit in
      go ()
    end
  in
  Lwt.async go

(* Fill S's socket: send big messages until one does not complete within
   [settle] s (S's buffers are full and its writer is parked). *)
let wedge (s : Peer.peer) =
  let pending = Lwt.catch (fun () -> Peer.send_message s (big_inv ()))
      (fun _ -> Lwt.return_unit) in
  let* () = Lwt_unix.sleep 0.5 in
  Alcotest.(check bool) "S is wedged (its first big send has not completed)"
    true (Lwt.state pending = Lwt.Sleep);
  Lwt.return pending

let time f =
  let t0 = Unix.gettimeofday () in
  let* r = f () in
  Lwt.return (r, Unix.gettimeofday () -. t0)

(* 1. A stalled send fails within the send timeout AND drops the peer (it
      was left Ready on b08ea33), and the peer's own message loop removes it
      from the manager. *)
let test_stuck_peer_is_dropped () =
  Lwt_main.run begin
    let pm = Peer_manager.create net in
    pm.Peer_manager.running <- true;
    let (s, _remote) = mk_peer 1 in
    pm.Peer_manager.peers <- [s];
    Peer_manager.ensure_msg_loop pm s;
    let* pending = wedge s in
    let* ((), dt) = time (fun () -> pending) in
    let* () = Lwt_unix.sleep 1.0 in
    Printf.printf "[stuck] send settled after %.1fs; state=%s; in pm=%b\n%!" dt
      (match s.Peer.state with Peer.Ready -> "Ready" | Peer.Disconnected -> "Disconnected"
                             | Peer.Disconnecting -> "Disconnecting" | _ -> "other")
      (List.memq s pm.Peer_manager.peers);
    Alcotest.(check bool) "stalled send settles within ~send_timeout" true (dt < Peer.send_timeout +. 5.0);
    Alcotest.(check bool) "stuck peer is no longer Ready" true (s.Peer.state <> Peer.Ready);
    Alcotest.(check bool) "stuck peer removed from the manager" false
      (List.memq s pm.Peer_manager.peers);
    pm.Peer_manager.running <- false;
    Lwt.return_unit
  end

(* 2. announce_block / broadcast return at once even with a stuck peer, and
      the good peer still gets the announcement promptly. *)
let test_broadcasts_do_not_wait () =
  Lwt_main.run begin
    let pm = Peer_manager.create net in
    let (s, _rs) = mk_peer 2 in
    let (g, rg) = mk_peer 3 in
    let got = ref 0 in
    drain rg got;
    pm.Peer_manager.peers <- [s; g];
    let* _pending = wedge s in
    let header = Types.{ version = 1l; prev_block = Types.zero_hash;
                         merkle_root = Types.zero_hash; timestamp = 0l;
                         bits = 0x207fffffl; nonce = 0l } in
    let before = !got in
    let* ((), dt1) = time (fun () ->
      Peer_manager.announce_block pm header Types.zero_hash) in
    let* ((), dt2) = time (fun () -> Peer_manager.broadcast pm P2p.GetaddrMsg) in
    let* () = Lwt_unix.sleep 0.5 in
    Printf.printf "[broadcast] announce_block %.2fs broadcast %.2fs; G got %d bytes\n%!"
      dt1 dt2 (!got - before);
    Alcotest.(check bool) "announce_block does not wait on the stuck peer" true (dt1 < 1.0);
    Alcotest.(check bool) "broadcast does not wait on the stuck peer" true (dt2 < 1.0);
    Alcotest.(check bool) "good peer received the announcements" true (!got - before > 0);
    Lwt.return_unit
  end

(* 3. CONTROL: a slow-but-reading peer receives a big message in full (short
      transfer, well inside the timeout — passes before and after). *)
let test_slow_reader_short () =
  Lwt_main.run begin
    let (w, rw) = mk_peer 4 in
    let got = ref 0 in
    drain ~chunk:65536 ~pause:0.05 rw got;
    let* (r, dt) = time (fun () ->
      Lwt.catch (fun () -> let* () = Peer.send_message w (big_inv ()) in Lwt.return true)
        (fun _ -> Lwt.return false)) in
    Printf.printf "[slow-short] ok=%b in %.1fs, %d bytes read, state Ready=%b\n%!"
      r dt !got (w.Peer.state = Peer.Ready);
    Alcotest.(check bool) "slow reader got the whole message" true r;
    Alcotest.(check bool) "slow reader stays connected" true (w.Peer.state = Peer.Ready);
    Lwt.return_unit
  end

(* 4. A slow-but-reading peer is NOT cut off while it keeps draining, even
      when the message takes longer than send_timeout (b08ea33's absolute
      10 s deadline dropped it mid-message). *)
let test_slow_reader_longer_than_timeout () =
  Lwt_main.run begin
    let (w, rw) = mk_peer 5 in
    let got = ref 0 in
    (* ~80 KB/s: 1.26 MB takes ~16 s > send_timeout (10 s). *)
    drain ~chunk:8192 ~pause:0.1 rw got;
    let* (r, dt) = time (fun () ->
      Lwt.catch (fun () -> let* () = Peer.send_message w (big_inv ()) in Lwt.return true)
        (fun _ -> Lwt.return false)) in
    Printf.printf "[slow-long] ok=%b in %.1fs, %d bytes read, state Ready=%b\n%!"
      r dt !got (w.Peer.state = Peer.Ready);
    Alcotest.(check bool) "transfer outlasted send_timeout (test is meaningful)"
      true (dt > Peer.send_timeout || not r);
    Alcotest.(check bool) "slow-but-draining peer got the whole message" true r;
    Lwt.return_unit
  end

let () =
  (* As in production (cli.ml): a write to a closed socket must be EPIPE,
     not a process-killing SIGPIPE. *)
  Sys.set_signal Sys.sigpipe Sys.Signal_ignore;
  Alcotest.run "send_stall_no_wedge" [
    "send-stall", [
      Alcotest.test_case "stuck peer: send bounded, peer dropped + removed" `Slow
        test_stuck_peer_is_dropped;
      Alcotest.test_case "announce_block/broadcast never wait on a stuck peer" `Slow
        test_broadcasts_do_not_wait;
      Alcotest.test_case "CONTROL slow reader, short transfer" `Slow test_slow_reader_short;
      Alcotest.test_case "slow reader, transfer longer than send_timeout" `Slow
        test_slow_reader_longer_than_timeout;
    ];
  ]
