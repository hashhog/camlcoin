(* CC-4: the "unique staller" disconnect livelocks block download at tip
   (receipts/arch-concurrency-liveness-audit-2026-10-07.md CC-4; live mainnet
   stall 2026-10-07 ~19:50-20:15Z, SCRATCH/camlcoin-stall/
   stall-20261007T2015Z-tail.txt: block 970381 took ~10 min and 970382 never
   arrived while ~5 peers/min were disconnected "block download stall /
   unique staller", next_proc pinned with 3 blocks in flight).

   Core (net_processing.cpp): a peer is a staller only when the 1024-block
   download WINDOW cannot move because of it (FindNextBlocksToDownload sets
   m_stalling_since only when nothing else in the window can be requested);
   the timeout starts at BLOCK_STALLING_TIMEOUT_DEFAULT (2 s), DOUBLES after
   each stall disconnect (to 64 s) "so that we don't disconnect multiple
   peers if our own bandwidth is insufficient", and decays by 0.85 per
   connected block.  At tip, with a handful of blocks outstanding, the window
   never blocks: a slow holder is handled by the per-block download timeout.

   d4e6f77 disconnects the head-of-line holder after a FIXED 2 s whenever
   another peer exists, window or not.  Under load (297k-tx mempool, box
   load ~40) no peer delivers a 1.5 MB block in 2 s, so each re-request goes
   to a fresh peer that is disconnected 2 s later: a livelock.

     dune exec --no-buffer test/test_cc4_staller.exe
*)

open Camlcoin

let fake_hash h =
  let cs = Cstruct.create 32 in
  Cstruct.LE.set_uint32 cs 0 (Int32.of_int h);
  Cstruct.set_uint8 cs 31 0xCC;
  cs

let with_ibd f =
  Test_tmp.with_dir ~label:"cc4" ~mkdir:true (fun path ->
    let db = Storage.ChainDB.create path in
    Fun.protect ~finally:(fun () -> try Storage.ChainDB.close db with _ -> ())
      (fun () ->
        let state = Sync.create_chain_state db Consensus.regtest in
        let ibd = Sync.create_ibd_state state in
        f ibd))

(* queue heights [hol .. hol+n-1]; the HOL held by [hol_peer] requested
   [hol_age] seconds ago; the rest held by other peers, requested now. *)
let fill ibd ~hol ~n ~hol_peer ~hol_age =
  let now = Unix.gettimeofday () in
  ibd.Sync.next_process_height <- hol;
  ibd.Sync.next_download_height <- hol + n;
  for i = 0 to n - 1 do
    let h = hol + i in
    let peer_id, at = if i = 0 then (hol_peer, now -. hol_age)
      else (1000 + (i mod 8), now) in
    Sync.queue_add ibd
      { Sync.hash = fake_hash h; height = h;
        download_state = Sync.Requested
            { peer_id; requested_at = at; timeout = Sync.hol_fetch_timeout };
        tried_peers = [] };
    ibd.Sync.total_blocks_in_flight <- ibd.Sync.total_blocks_in_flight + 1
  done

let rerequest_hol ibd ~peer ~age =
  match Sync.queue_find_by_height ibd ibd.Sync.next_process_height with
  | Some e ->
    e.Sync.download_state <- Sync.Requested
        { peer_id = peer; requested_at = Unix.gettimeofday () -. age;
          timeout = Sync.hol_fetch_timeout }
  | None -> Alcotest.fail "no HOL entry"

let show l = "[" ^ String.concat ";" (List.map string_of_int l) ^ "]"

(* At tip: 4 blocks outstanding (the live 970382..970385 shape), HOL held
   for 3 s by peer 1, 10 ready peers.  The window is nowhere near blocked:
   Core never calls this a stall. *)
let test_at_tip_not_a_staller () =
  with_ibd (fun ibd ->
    fill ibd ~hol:970382 ~n:4 ~hol_peer:1 ~hol_age:3.0;
    let d = Sync.check_stalled_downloads ~n_ready_peers:10 ibd in
    Printf.printf "  at tip, HOL held 3 s, 4 in flight: disconnect %s\n%!" (show d);
    Alcotest.(check (list int))
      "no stall disconnect while the download window can still move" [] d)

(* Window blocked (the queue is full to the buffer cap and every slot is
   in flight): the first holder that exceeds 2 s is a staller (both builds),
   but the NEXT holder must get a longer timeout (Core doubles it), or every
   peer is disconnected 2 s after it receives the request. *)
let test_window_blocked_backs_off () =
  with_ibd (fun ibd ->
    let n = Sync.max_blocks_buffered_ahead in
    fill ibd ~hol:1000 ~n ~hol_peer:1 ~hol_age:0.0;
    (* first stall: the window blocks now; 2.3 s later peer 1 stalls it *)
    ignore (Sync.check_stalled_downloads ~n_ready_peers:10 ibd);
    Unix.sleepf 2.3;
    let d1 = Sync.check_stalled_downloads ~n_ready_peers:10 ibd in
    Printf.printf "  window blocked 2.3 s by peer 1: disconnect %s\n%!" (show d1);
    Alcotest.(check (list int)) "the first staller is disconnected" [ 1 ] d1;
    (* the HOL is re-requested from peer 2, which needs 3 s to deliver *)
    rerequest_hol ibd ~peer:2 ~age:0.0;
    ignore (Sync.check_stalled_downloads ~n_ready_peers:10 ibd);
    Unix.sleepf 3.0;
    let d2 = Sync.check_stalled_downloads ~n_ready_peers:10 ibd in
    Printf.printf "  peer 2 holding the HOL 3 s later: disconnect %s\n%!" (show d2);
    Alcotest.(check (list int))
      "after a stall disconnect the timeout doubles (Core): peer 2 is kept" [] d2;
    Unix.sleepf 1.3;
    let d3 = Sync.check_stalled_downloads ~n_ready_peers:10 ibd in
    Printf.printf "  peer 2 at 4.3 s: disconnect %s\n%!" (show d3);
    Alcotest.(check (list int)) "past the doubled timeout it is a staller" [ 2 ] d3)

let () =
  Alcotest.run "cc4_staller" [
    "unique staller", [
      Alcotest.test_case "at tip a slow HOL holder is not a staller" `Quick
        test_at_tip_not_a_staller;
      Alcotest.test_case "window blocked: stall timeout backs off" `Slow
        test_window_blocked_backs_off;
    ];
  ]
