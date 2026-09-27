(* Control: one-peer campaign HOL-cap stall. Assert a RATE, not
   eventual completion.

   Range 419311→450000 (2026-09-18T17:17Z) STALLED at 421316 after 600 s
   of zero progress on ONE local replay peer. Log:
     Stale tip check (no update for 131s), polling peer 1
       (peer reports height 423311 vs our block 421311 header 421311)
   Polling VERSION height is not re-requesting the body. GC compact_stall
   totalled 363 s spread across the run — a tax, not this stall.

   ouroboros 7e55946: requesting tip+1 is not enough if it sits behind
   far-ahead in-flight in a FIFO queue. Evicting those requests made
   HOL the next map entry, but un-marking does not cancel a getdata
   already on the wire — the peer still delivers the block and the
   next pass requests it again (515000 slice: in-flight collapsed to
   1). HOL now takes one slot over the per-peer cap; far-ahead
   in-flight stays requested. blockbrew 09695ad: size the stall
   timeout for a max-weight body at 32 KiB/s (1.54 MB ≈ 47 s; a 2 s /
   60 s budget aborts a healthy fetch). A "does it finish" test passes
   on the broken scheduler.

   Command (red on HEAD, green after):
     dune exec --no-buffer test/test_campaign_hol_cap_wedge.exe
*)

open Camlcoin

let regtest = Consensus.regtest

let near_max_body_bytes = 1_539_532
let min_live_block_throughput = 32 * 1024
let near_max_fetch_s =
  float_of_int near_max_body_bytes /. float_of_int min_live_block_throughput
let max_block_serialized_size = 4_000_000
let max_weight_fetch_s =
  float_of_int max_block_serialized_size
  /. float_of_int min_live_block_throughput
let buffered_far_ahead = 725
let ticks = 32

let dummy_block : Types.block =
  { header = regtest.genesis_header; transactions = [] }

let h n : Types.hash256 = Printf.sprintf "%064x" n |> Types.hash256_of_hex

let make_pair ~id =
  let a_u, b_u = Unix.socketpair Unix.PF_UNIX Unix.SOCK_STREAM 0 in
  Unix.set_nonblock a_u;
  Unix.set_nonblock b_u;
  let node_fd = Lwt_unix.of_unix_file_descr ~blocking:false a_u in
  let peer =
    Peer.make_peer ~network:regtest ~addr:"127.0.0.1" ~port:(8000 + id) ~id
      ~direction:Peer.Outbound ~fd:node_fd ()
  in
  peer.Peer.state <- Peer.Ready;
  peer.Peer.handshake_complete <- true;
  peer.Peer.msg_loop_started <- true;
  peer

let with_ibd f =
  Test_tmp.with_chaindb (fun db ->
      let chain = Sync.create_chain_state db regtest in
      chain.Sync.sync_state <- Sync.SyncingBlocks;
      let ibd = Sync.create_ibd_state chain in
      f chain ibd)

let seed_queue ibd n =
  for i = 1 to n do
    Sync.queue_add ibd
      {
        Sync.hash = h i;
        height = i;
        download_state = NotRequested;
        tried_peers = [];
      }
  done

let assign_inflight ibd ~peer_id ~lo ~hi ~age_s =
  let now = Unix.gettimeofday () in
  for height = lo to hi do
    match Sync.queue_find_by_height ibd height with
    | None -> Alcotest.failf "missing queue height %d" height
    | Some e ->
      e.Sync.download_state <-
        Requested
          {
            peer_id;
            requested_at = now -. age_s;
            timeout = Sync.base_block_timeout;
          };
      ibd.Sync.total_blocks_in_flight <- ibd.Sync.total_blocks_in_flight + 1;
      let ps = Sync.get_peer_state ibd peer_id in
      ps.Sync.blocks_in_flight <- ps.Sync.blocks_in_flight + 1
  done

let load ibd peer_id =
  match Hashtbl.find_opt ibd.Sync.peer_states peer_id with
  | Some ps -> ps.Sync.blocks_in_flight
  | None -> 0

let buffer_range ibd ~lo ~hi =
  for height = lo to hi do
    match Sync.queue_find_by_height ibd height with
    | None -> Alcotest.failf "missing buffer height %d" height
    | Some e ->
      e.Sync.download_state <-
        Downloaded { block = dummy_block; peer_id = Some 1 }
  done

let request ibd peer =
  Lwt_main.run (Sync.request_blocks ibd [ peer ])

(* ---- (a) one peer at cap must still request the connect cursor ---- *)

let test_single_peer_at_cap_still_requests_connect_cursor () =
  with_ibd (fun _chain ibd ->
      let n =
        buffered_far_ahead + Sync.max_blocks_per_peer + Sync.max_blocks_per_peer
      in
      seed_queue ibd n;
      ibd.Sync.next_process_height <- 1;
      (* Head-of-window 1..8 empty. Buffer 9..(8+725). Far in-flight after
         that, filling the only peer's 16-slot cap. HOL (height 1) is
         neither buffered nor in-flight. *)
      buffer_range ibd ~lo:9 ~hi:(8 + buffered_far_ahead);
      let far_lo = 9 + buffered_far_ahead in
      let far_hi = far_lo + Sync.max_blocks_per_peer - 1 in
      assign_inflight ibd ~peer_id:1 ~lo:far_lo ~hi:far_hi ~age_s:1.0;
      Alcotest.(check int) "peer at cap" Sync.max_blocks_per_peer (load ibd 1);
      (match Sync.queue_find_by_height ibd 1 with
      | Some e -> (
        match e.Sync.download_state with
        | NotRequested -> ()
        | _ -> Alcotest.fail "HOL should start NotRequested")
      | None -> Alcotest.fail "HOL missing");
      let peer = make_pair ~id:1 in
      request ibd peer;
      (match Sync.queue_find_by_height ibd 1 with
      | Some e -> (
        match e.Sync.download_state with
        | Requested { peer_id; _ } ->
          Alcotest.(check int) "HOL assigned to the only peer" 1 peer_id
        | NotRequested ->
          Alcotest.fail
            "connect cursor (tip+1) was not requested while the only \
             peer sat at the in-flight cap"
        | _ -> Alcotest.fail "HOL in unexpected state")
      | None -> Alcotest.fail "HOL missing after request");
      Alcotest.(check int)
        (Printf.sprintf
           "HOL is one extra slot over the cap (load=%d); evicting a \
            far-ahead getdata does not cancel it"
           (load ibd 1))
        (Sync.max_blocks_per_peer + 1)
        (load ibd 1);
      let still_far = ref 0 in
      for height = far_lo to far_hi do
        match Sync.queue_find_by_height ibd height with
        | Some { download_state = Requested _; _ } -> incr still_far
        | _ -> ()
      done;
      Alcotest.(check int)
        "far-ahead in-flight stays requested"
        Sync.max_blocks_per_peer !still_far)

(* ---- (b) timeout sized for a max-weight body at 32 KiB/s ---- *)

let test_head_timeout_covers_near_max_body_at_32kib () =
  Alcotest.(check bool)
    (Printf.sprintf
       "base_block_timeout %.1fs does not cover a %d-byte body at %d B/s \
        (%.1fs) — the timeout is the bug, not the peer"
       Sync.base_block_timeout near_max_body_bytes min_live_block_throughput
       near_max_fetch_s)
    true
    (Sync.base_block_timeout > near_max_fetch_s);
  Alcotest.(check bool)
    (Printf.sprintf
       "base_block_timeout %.1fs does not cover a 4_000_000-byte body at \
        32 KiB/s (%.1fs); blockbrew BaseStallTimeout is 128 s, Core \
        BLOCK_DOWNLOAD_TIMEOUT_BASE is 600 s"
       Sync.base_block_timeout max_weight_fetch_s)
    true
    (Sync.base_block_timeout >= max_weight_fetch_s)

(* ---- (c) in-flight HOL inside that budget is not a stall ---- *)

let test_inflight_hol_inside_realistic_fetch_is_not_stalled () =
  with_ibd (fun _chain ibd ->
      seed_queue ibd 8;
      ibd.Sync.next_process_height <- 1;
      assign_inflight ibd ~peer_id:1 ~lo:1 ~hi:1 ~age_s:near_max_fetch_s;
      let orig =
        match Sync.queue_find_by_height ibd 1 with
        | Some { download_state = Requested { requested_at; _ }; _ } ->
          requested_at
        | _ -> Alcotest.fail "HOL not in-flight"
      in
      let to_drop = Sync.check_stalled_downloads ibd in
      Alcotest.(check (list int))
        "one-peer HOL inside a realistic fetch is not a unique staller" []
        to_drop;
      match Sync.queue_find_by_height ibd 1 with
      | Some e -> (
        match e.Sync.download_state with
        | Requested { requested_at; peer_id; _ } ->
          Alcotest.(check int) "still on the same peer" 1 peer_id;
          Alcotest.(check (float 1e-9))
            "in-flight timestamp was not reset — a still-arriving body \
             is not a stall"
            orig requested_at
        | NotRequested ->
          Alcotest.fail
            (Printf.sprintf
               "HOL download was dropped mid-fetch (elapsed=%.1fs)"
               near_max_fetch_s)
        | _ -> Alcotest.fail "HOL left Requested")
      | None -> Alcotest.fail "HOL missing")

(* ---- (d) RATE, not eventual completion ---- *)

let stamp ibd height =
  match Sync.queue_find_by_height ibd height with
  | Some { download_state = Requested { requested_at; _ }; _ } -> requested_at
  | _ -> Alcotest.failf "height %d is not in-flight" height

let test_next_inflight_delivery_is_the_connect_cursor () =
  with_ibd (fun _chain ibd ->
      let n = buffered_far_ahead + 32 in
      seed_queue ibd n;
      ibd.Sync.next_process_height <- 1;
      let far_lo = 17 in
      let far_hi = far_lo + Sync.max_blocks_per_peer - 1 in
      assign_inflight ibd ~peer_id:1 ~lo:far_lo ~hi:far_hi ~age_s:1.0;
      let far_ts = stamp ibd far_lo in
      let before = ibd.Sync.total_blocks_in_flight in
      let peer = make_pair ~id:1 in
      request ibd peer;
      (match Sync.queue_find_by_height ibd 1 with
      | Some { download_state = Requested _; _ } -> ()
      | _ ->
        Alcotest.fail
          "connect cursor was not requested — eventual-completion path \
           regressed");
      Alcotest.(check int)
        "in-flight grew by the connect cursor only (far-ahead not cleared)"
        (before + 1) ibd.Sync.total_blocks_in_flight;
      Alcotest.(check bool)
        "far-ahead already on the wire was not re-requested" true
        (stamp ibd far_lo = far_ts);
      let still_far = ref 0 in
      for height = far_lo to far_hi do
        match Sync.queue_find_by_height ibd height with
        | Some { download_state = Requested _; _ } -> incr still_far
        | _ -> ()
      done;
      Alcotest.(check int)
        "every far-ahead request is still outstanding" Sync.max_blocks_per_peer
        !still_far)

let test_connect_cursor_rate_when_only_peer_is_at_cap () =
  with_ibd (fun _chain ibd ->
      let n = ticks + Sync.max_blocks_per_peer + 16 in
      seed_queue ibd n;
      ibd.Sync.next_process_height <- 1;
      let far_lo = ticks + 1 in
      let far_hi = far_lo + Sync.max_blocks_per_peer - 1 in
      assign_inflight ibd ~peer_id:1 ~lo:far_lo ~hi:far_hi ~age_s:1.0;
      let peer = make_pair ~id:1 in
      request ibd peer;
      let inflight = ibd.Sync.total_blocks_in_flight in
      let far_ts = stamp ibd far_lo in
      let hol_ts = stamp ibd 1 in
      for _ = 1 to 8 do
        request ibd peer
      done;
      Alcotest.(check int)
        "later passes do not drop or duplicate in-flight (the live \
         defect collapsed the counter to 1)"
        inflight ibd.Sync.total_blocks_in_flight;
      Alcotest.(check bool)
        "far-ahead timestamp stable — eviction would re-issue the getdata"
        true
        (stamp ibd far_lo = far_ts);
      Alcotest.(check bool) "connect-cursor timestamp stable" true
        (stamp ibd 1 = hol_ts))

let test_campaign_buffer_shape_does_not_stall_the_cursor () =
  with_ibd (fun _chain ibd ->
      let n =
        buffered_far_ahead + Sync.max_blocks_per_peer + 16
      in
      seed_queue ibd n;
      ibd.Sync.next_process_height <- 1;
      buffer_range ibd ~lo:9 ~hi:(8 + buffered_far_ahead);
      let far_lo = 9 + buffered_far_ahead in
      let far_hi = far_lo + Sync.max_blocks_per_peer - 1 in
      assign_inflight ibd ~peer_id:1 ~lo:far_lo ~hi:far_hi ~age_s:1.0;
      let far_ts = stamp ibd far_lo in
      let peer = make_pair ~id:1 in
      request ibd peer;
      (match Sync.queue_find_by_height ibd 1 with
      | Some { download_state = Requested _; _ } -> ()
      | _ ->
        Alcotest.fail
          "campaign shape: 725 buffered, peer at cap, connect cursor \
           was not requested");
      let still_far = ref 0 in
      for height = far_lo to far_hi do
        match Sync.queue_find_by_height ibd height with
        | Some { download_state = Requested _; _ } -> incr still_far
        | _ -> ()
      done;
      Alcotest.(check int)
        "campaign shape does not evict the far-ahead cap" Sync.max_blocks_per_peer
        !still_far;
      Alcotest.(check int)
        "in-flight is the cap plus the connect cursor"
        (Sync.max_blocks_per_peer + 1)
        ibd.Sync.total_blocks_in_flight;
      for _ = 1 to 8 do
        request ibd peer
      done;
      Alcotest.(check bool)
        "eight more passes do not re-request the far-ahead block" true
        (stamp ibd far_lo = far_ts))

let () =
  Alcotest.run "campaign_hol_cap_wedge"
    [
      ( "cap",
        [
          Alcotest.test_case
            "single peer at cap still requests connect cursor" `Quick
            test_single_peer_at_cap_still_requests_connect_cursor;
        ] );
      ( "timeout",
        [
          Alcotest.test_case "timeout covers near-max body at 32 KiB/s" `Quick
            test_head_timeout_covers_near_max_body_at_32kib;
          Alcotest.test_case
            "in-flight HOL inside realistic fetch is not stalled" `Quick
            test_inflight_hol_inside_realistic_fetch_is_not_stalled;
        ] );
      ( "rate",
        [
          Alcotest.test_case
            "far-ahead in-flight is kept when the connect cursor is requested"
            `Quick test_next_inflight_delivery_is_the_connect_cursor;
          Alcotest.test_case
            "later passes do not re-request in-flight blocks" `Quick
            test_connect_cursor_rate_when_only_peer_is_at_cap;
          Alcotest.test_case
            "campaign buffer shape does not re-request far-ahead" `Quick
            test_campaign_buffer_shape_does_not_stall_the_cursor;
        ] );
    ]
