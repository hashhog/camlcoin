(* Control: one-peer campaign HOL-cap stall. Assert a RATE, not
   eventual completion.

   Range 419311→450000 (2026-09-18T17:17Z) STALLED at 421316 after 600 s
   of zero progress on ONE local replay peer. Log:
     Stale tip check (no update for 131s), polling peer 1
       (peer reports height 423311 vs our block 421311 header 421311)
   Polling VERSION height is not re-requesting the body. GC compact_stall
   totalled 363 s spread across the run — a tax, not this stall.

   ouroboros 7e55946: requesting tip+1 is not enough if it sits behind
   far-ahead in-flight in a FIFO queue; evict the far-ahead so HOL is
   the NEXT delivery. blockbrew 09695ad: size the stall timeout for a
   max-weight body at 32 KiB/s (1.54 MB ≈ 47 s; a 2 s / 60 s budget
   aborts a healthy fetch). A "does it finish" test passes on the
   broken scheduler.

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
let min_connect_rate = ticks * 3 / 4

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

let oldest_inflight ibd : Sync.block_queue_entry option =
  let best = ref None in
  Queue.iter
    (fun (e : Sync.block_queue_entry) ->
      match e.Sync.download_state with
      | Sync.Requested { requested_at; _ } -> (
        match !best with
        | None -> best := Some (requested_at, e.height, e)
        | Some (t, h, _) ->
          if requested_at < t
             || (requested_at = t && e.height < h)
          then best := Some (requested_at, e.height, e))
      | _ -> ())
    ibd.Sync.block_queue;
  match !best with Some (_, _, e) -> Some e | None -> None

let release_requested ibd (e : Sync.block_queue_entry) =
  match e.Sync.download_state with
  | Sync.Requested { peer_id; _ } ->
    ibd.Sync.total_blocks_in_flight <-
      max 0 (ibd.Sync.total_blocks_in_flight - 1);
    let ps = Sync.get_peer_state ibd peer_id in
    ps.Sync.blocks_in_flight <- max 0 (ps.Sync.blocks_in_flight - 1)
  | _ -> ()

let rec drain_ready ibd acc =
  match Sync.queue_find_by_height ibd ibd.Sync.next_process_height with
  | Some e -> (
    match e.Sync.download_state with
    | Sync.Downloaded _ | Sync.Validated ->
      e.Sync.download_state <- Validated;
      ibd.Sync.next_process_height <- ibd.Sync.next_process_height + 1;
      drain_ready ibd (acc + 1)
    | _ -> acc)
  | None -> acc

let deliver_oldest ibd =
  match oldest_inflight ibd with
  | None -> 0
  | Some e ->
    let height = e.Sync.height in
    release_requested ibd e;
    if height = ibd.Sync.next_process_height then begin
      e.Sync.download_state <- Validated;
      ibd.Sync.next_process_height <- ibd.Sync.next_process_height + 1;
      drain_ready ibd 1
    end else begin
      e.Sync.download_state <-
        Downloaded { block = dummy_block; peer_id = Some 1 };
      drain_ready ibd 0
    end

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
      Alcotest.(check bool)
        (Printf.sprintf
           "HOL fits under the per-peer cap (load=%d, cap=%d); a 17th \
            getdata is how the campaign feeder never delivered tip+1"
           (load ibd 1) Sync.max_blocks_per_peer)
        true
        (load ibd 1 <= Sync.max_blocks_per_peer);
      let still_far = ref 0 in
      for height = far_lo to far_hi do
        match Sync.queue_find_by_height ibd height with
        | Some { download_state = Requested _; _ } -> incr still_far
        | _ -> ()
      done;
      Alcotest.(check bool)
        "a far-ahead in-flight slot was evicted to make room for tip+1"
        true
        (!still_far < Sync.max_blocks_per_peer))

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

let test_next_inflight_delivery_is_the_connect_cursor () =
  with_ibd (fun _chain ibd ->
      let n = buffered_far_ahead + 32 in
      seed_queue ibd n;
      ibd.Sync.next_process_height <- 1;
      let far_lo = 17 in
      let far_hi = far_lo + Sync.max_blocks_per_peer - 1 in
      assign_inflight ibd ~peer_id:1 ~lo:far_lo ~hi:far_hi ~age_s:1.0;
      Alcotest.(check int) "at cap" Sync.max_blocks_per_peer (load ibd 1);
      let peer = make_pair ~id:1 in
      request ibd peer;
      (match Sync.queue_find_by_height ibd 1 with
      | Some { download_state = Requested _; _ } -> ()
      | _ ->
        Alcotest.fail
          "connect cursor was not requested — eventual-completion path \
           regressed");
      match oldest_inflight ibd with
      | None -> Alcotest.fail "no in-flight after request"
      | Some e ->
        Alcotest.(check int)
          (Printf.sprintf
             "next FIFO delivery on the only peer is height %d, not \
              tip+1. HOL is in-flight but behind far-ahead — that is \
              the halved-throughput stall"
             e.Sync.height)
          1 e.Sync.height)

let test_connect_cursor_rate_when_only_peer_is_at_cap () =
  with_ibd (fun _chain ibd ->
      let n = ticks + Sync.max_blocks_per_peer + 16 in
      seed_queue ibd n;
      ibd.Sync.next_process_height <- 1;
      let far_lo = ticks + 1 in
      let far_hi = far_lo + Sync.max_blocks_per_peer - 1 in
      assign_inflight ibd ~peer_id:1 ~lo:far_lo ~hi:far_hi ~age_s:1.0;
      let peer = make_pair ~id:1 in
      let connects = ref 0 in
      let first_connect_at = ref None in
      let longest_zero = ref 0 in
      let zero_run = ref 0 in
      for tick = 1 to ticks do
        request ibd peer;
        let n_this = deliver_oldest ibd in
        if n_this > 0 then begin
          connects := !connects + n_this;
          if !first_connect_at = None then first_connect_at := Some tick;
          zero_run := 0
        end else begin
          incr zero_run;
          longest_zero := max !longest_zero !zero_run
        end
      done;
      (match !first_connect_at with
      | Some t when t <= 2 -> ()
      | other ->
        Alcotest.fail
          (Printf.sprintf
             "first connect at tick %s — connect cursor waited behind \
              far-ahead FIFO. connects=%d/%d longest_zero=%d"
             (match other with None -> "never" | Some t -> string_of_int t)
             !connects ticks !longest_zero));
      Alcotest.(check bool)
        (Printf.sprintf
           "longest zero-connect run is %d ticks; the live defect was \
            multi-minute stalls. connects=%d/%d"
           !longest_zero !connects ticks)
        true (!longest_zero <= 2);
      Alcotest.(check bool)
        (Printf.sprintf
           "connect rate %d/%d blk/tick is the halved-throughput defect \
            (healthy ≈%d; eventual-completion tests pass on this). \
            longest_zero=%d"
           !connects ticks ticks !longest_zero)
        true
        (!connects >= min_connect_rate))

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
      let peer = make_pair ~id:1 in
      request ibd peer;
      (match oldest_inflight ibd with
      | Some e ->
        Alcotest.(check int)
          (Printf.sprintf
             "campaign shape: 725 buffered, peer at cap, next FIFO \
              delivery is height %d not tip+1 — HOL waits behind \
              far-ahead"
             e.Sync.height)
          1 e.Sync.height
      | None -> Alcotest.fail "no in-flight after request");
      let connects = ref 0 in
      let longest_zero = ref 0 in
      let zero_run = ref 0 in
      for _ = 1 to 8 do
        request ibd peer;
        let n_this = deliver_oldest ibd in
        if n_this > 0 then begin
          connects := !connects + n_this;
          zero_run := 0
        end else begin
          incr zero_run;
          longest_zero := max !longest_zero !zero_run
        end
      done;
      Alcotest.(check bool)
        (Printf.sprintf
           "first 8 ticks must not be a zero-connect stall \
            (connects=%d longest_zero=%d)"
           !connects !longest_zero)
        true
        (!connects >= 1 && !longest_zero <= 2))

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
          Alcotest.test_case "next FIFO delivery is the connect cursor" `Quick
            test_next_inflight_delivery_is_the_connect_cursor;
          Alcotest.test_case
            "connect-cursor rate when only peer is at cap" `Quick
            test_connect_cursor_rate_when_only_peer_is_at_cap;
          Alcotest.test_case
            "campaign buffer shape does not stall the cursor" `Quick
            test_campaign_buffer_shape_does_not_stall_the_cursor;
        ] );
    ]
