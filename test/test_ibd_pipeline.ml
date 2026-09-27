(* Control for the 515000-slice IBD stall (QUEUES.md, 2026-09-26).

   Observed on pre-afefc61 code, height ~537k:
     mean UpdateTip 3.71 s/block;
     [gc] backstop compaction (ibd-cadence) every ~20 blocks, 7-14 s
     stop-the-world (~600 s per 1000 blocks);
     in-flight stuck at 1 with "evicted N far-ahead in-flight ... so the
     connect cursor is next" — un-marking a getdata does not cancel it,
     so the peer delivers the block and the next pass requests it again.
     Each stale copy decremented total_blocks_in_flight a second time.
   The download queue also held 1024 parsed blocks (~2.5 GB live) and
   script-check spawned one domain per core (31), so every minor
   collection rendezvoused 32 domains.

   This executable asserts the repaired scheduler. It compiles against
   the pre-fix tree too, and there it fails:
     queue length 400 (window 1024) vs 256;
     far-ahead requested_at rewritten (evict + re-request);
     a second copy of a downloaded block drops in-flight 1 -> 0;
     script-check extras 31 vs 15;
     sync.ml still calls compact_now ~reason:"ibd-cadence".

   Command:
     dune exec --no-buffer test/test_ibd_pipeline.exe
*)

open Camlcoin

let regtest = Consensus.regtest

let h n : Types.hash256 = Printf.sprintf "%064x" n |> Types.hash256_of_hex

let contains s sub =
  let ls = String.length s and lsub = String.length sub in
  let rec loop i =
    if i + lsub > ls then false
    else if String.sub s i lsub = sub then true
    else loop (i + 1)
  in
  if lsub = 0 then true else loop 0

let read_file path =
  let ic = open_in_bin path in
  Fun.protect
    ~finally:(fun () -> close_in ic)
    (fun () -> really_input_string ic (in_channel_length ic))

let find_repo_file rel =
  let exe_dir = Filename.dirname Sys.executable_name in
  let candidates =
    [
      rel;
      Filename.concat (Sys.getcwd ()) rel;
      Filename.concat exe_dir (Filename.concat "../../../" rel);
      Filename.concat exe_dir (Filename.concat "../../../../" rel);
    ]
  in
  match List.find_opt Sys.file_exists candidates with
  | Some p -> p
  | None ->
      Alcotest.failf "cannot find %s (cwd=%s exe=%s)" rel (Sys.getcwd ())
        Sys.executable_name

let with_ibd f =
  Test_tmp.with_chaindb (fun db ->
      let chain = Sync.create_chain_state db regtest in
      chain.Sync.sync_state <- Sync.SyncingBlocks;
      let ibd = Sync.create_ibd_state chain in
      f chain ibd)

let make_pair ~id =
  let a_u, b_u = Unix.socketpair Unix.PF_UNIX Unix.SOCK_STREAM 0 in
  Unix.set_nonblock a_u;
  Unix.set_nonblock b_u;
  let node_fd = Lwt_unix.of_unix_file_descr ~blocking:false a_u in
  let peer =
    Peer.make_peer ~network:regtest ~addr:"127.0.0.1" ~port:(18000 + id) ~id
      ~direction:Peer.Outbound ~fd:node_fd ()
  in
  peer.Peer.state <- Peer.Ready;
  peer.Peer.handshake_complete <- true;
  peer.Peer.msg_loop_started <- true;
  peer

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

let requested_at ibd height =
  match Sync.queue_find_by_height ibd height with
  | Some { download_state = Requested { requested_at; _ }; _ } -> requested_at
  | _ -> Alcotest.failf "height %d is not in-flight" height

let request ibd peer = Lwt_main.run (Sync.request_blocks ibd [ peer ])

(* ---- download window: 256 parsed blocks, not Core's 1024 ---- *)

let install_headers chain n =
  let hashes = Array.init (n + 1) h in
  for height = 1 to n do
    let hash = hashes.(height) in
    let header =
      {
        Types.version = 1l;
        prev_block = hashes.(height - 1);
        merkle_root = h 0;
        timestamp = Int32.of_int height;
        bits = 0x1d00ffffl;
        nonce = 0l;
      }
    in
    let entry =
      { Sync.header; hash; height; total_work = Cstruct.create 32 }
    in
    Hashtbl.replace chain.Sync.headers (Cstruct.to_string hash) entry;
    if height = n then chain.Sync.tip <- Some entry
  done;
  chain.Sync.headers_synced <- n

let test_buffer_caps_at_256 () =
  Test_tmp.with_chaindb (fun db ->
      let chain = Sync.create_chain_state db regtest in
      chain.Sync.blocks_synced <- 0;
      install_headers chain 400;
      let ibd = Sync.create_ibd_state chain in
      Sync.fill_download_queue ibd;
      let n = Queue.length ibd.Sync.block_queue in
      Alcotest.(check int)
        "parsed-block window is 256, not the 1024-block download window \
         (400 headers ahead)"
        256 n;
      Alcotest.(check bool)
        "height 256 is queued" true
        (Sync.queue_find_by_height ibd 256 <> None);
      Alcotest.(check bool)
        "height 257 is not queued" true
        (Sync.queue_find_by_height ibd 257 = None))

(* ---- do not evict / re-request a block that is already on the wire ---- *)

let test_far_ahead_inflight_is_not_rerequested () =
  with_ibd (fun _chain ibd ->
      seed_queue ibd 48;
      ibd.Sync.next_process_height <- 1;
      let far_lo = 9 in
      let far_hi = far_lo + Sync.max_blocks_per_peer - 1 in
      assign_inflight ibd ~peer_id:1 ~lo:far_lo ~hi:far_hi ~age_s:1.0;
      let before = ibd.Sync.total_blocks_in_flight in
      let far_ts = requested_at ibd far_lo in
      let peer = make_pair ~id:1 in
      request ibd peer;
      Alcotest.(check int)
        "connect cursor took one slot over the cap; far-ahead was not cleared"
        (before + 1) ibd.Sync.total_blocks_in_flight;
      (match Sync.queue_find_by_height ibd 1 with
      | Some { download_state = Requested { peer_id = 1; _ }; _ } -> ()
      | _ ->
          Alcotest.fail
            "connect cursor was not requested while the only peer sat at cap");
      Alcotest.(check bool)
        "far-ahead requested_at unchanged (evict + re-request rewrites it)"
        true
        (requested_at ibd far_lo = far_ts);
      let inflight = ibd.Sync.total_blocks_in_flight in
      let hol_ts = requested_at ibd 1 in
      for _ = 1 to 5 do
        request ibd peer
      done;
      Alcotest.(check int)
        "later passes do not drop or duplicate in-flight" inflight
        ibd.Sync.total_blocks_in_flight;
      Alcotest.(check bool)
        "far-ahead timestamp stable across passes" true
        (requested_at ibd far_lo = far_ts);
      Alcotest.(check bool)
        "connect-cursor timestamp stable across passes" true
        (requested_at ibd 1 = hol_ts))

(* ---- a second copy must not decrement in-flight again ---- *)

let block_with nonce =
  let header =
    {
      Types.version = 2l;
      prev_block = h 99;
      merkle_root = h nonce;
      timestamp = 1_600_000_000l;
      bits = 0x1d00ffffl;
      nonce = Int32.of_int nonce;
    }
  in
  let block = { Types.header; transactions = [] } in
  (block, Crypto.compute_block_hash header)

let test_duplicate_delivery_does_not_drop_inflight () =
  with_ibd (fun _chain ibd ->
      let block_a, hash_a = block_with 1 in
      let _block_b, hash_b = block_with 2 in
      Sync.queue_add ibd
        {
          Sync.hash = hash_a;
          height = 1;
          download_state = NotRequested;
          tried_peers = [];
        };
      Sync.queue_add ibd
        {
          Sync.hash = hash_b;
          height = 2;
          download_state = NotRequested;
          tried_peers = [];
        };
      assign_inflight ibd ~peer_id:1 ~lo:1 ~hi:2 ~age_s:0.1;
      Alcotest.(check int) "two in flight" 2 ibd.Sync.total_blocks_in_flight;
      (match Sync.receive_block ibd block_a with
      | Ok () -> ()
      | Error e -> Alcotest.failf "first delivery: %s" e);
      Alcotest.(check int)
        "first delivery clears one slot" 1 ibd.Sync.total_blocks_in_flight;
      (match Sync.receive_block ibd block_a with
      | Ok () -> ()
      | Error e -> Alcotest.failf "duplicate delivery: %s" e);
      Alcotest.(check int)
        "duplicate of an already-downloaded block does not decrement \
         in-flight (the other request is still outstanding)"
        1 ibd.Sync.total_blocks_in_flight)

(* ---- script-check width: Core's MAX_SCRIPTCHECK_THREADS ---- *)

let test_scriptcheck_threads_clamped () =
  Validation.set_par 0;
  Validation.stop_script_check_queue ();
  Validation.start_script_check_queue ();
  Fun.protect
    ~finally:(fun () -> Validation.stop_script_check_queue ())
    (fun () ->
      match !Validation.script_check_queue with
      | None -> Alcotest.fail "script-check queue was not started"
      | Some q ->
          let n = Validation.extra_workers q in
          let raw = Validation.resolve_script_check_workers 0 in
          Alcotest.(check int)
            (Printf.sprintf
               "script-check extras clamped to <=15 (auto raw=%d, this box \
                has more cores than Core's MAX_SCRIPTCHECK_THREADS)"
               raw)
            (min 15 raw) n)

(* ---- IBD compaction is a heap-ceiling backstop, not every 16 blocks ---- *)

let test_ibd_compaction_is_not_every_16_blocks () =
  let src = read_file (find_repo_file "lib/sync.ml") in
  Alcotest.(check bool)
    "run_ibd consults ibd_compaction_due" true
    (contains src "ibd_compaction_due");
  Alcotest.(check bool)
    "run_ibd does not call compact_now ~reason:\"ibd-cadence\" on every \
     16 connected blocks"
    false
    (contains src "compact_now ~reason:\"ibd-cadence\"")

let () =
  Alcotest.run "ibd_pipeline"
    [
      ( "window",
        [
          Alcotest.test_case "parsed-block buffer caps at 256" `Quick
            test_buffer_caps_at_256;
        ] );
      ( "inflight",
        [
          Alcotest.test_case "far-ahead in-flight is not re-requested" `Quick
            test_far_ahead_inflight_is_not_rerequested;
          Alcotest.test_case "duplicate delivery does not drop in-flight"
            `Quick test_duplicate_delivery_does_not_drop_inflight;
        ] );
      ( "scriptcheck",
        [
          Alcotest.test_case "extra workers clamped to 15" `Quick
            test_scriptcheck_threads_clamped;
        ] );
      ( "compact",
        [
          Alcotest.test_case "IBD compaction is not the 16-block cadence"
            `Quick test_ibd_compaction_is_not_every_16_blocks;
        ] );
    ]
