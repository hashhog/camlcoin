(* Control: R4 slice 950000->958794 stalled at its base (QUEUES camlcoin
   item 0, 2026-10-04, a8e8f30 and 6fcfb3d).

   The replay store keeps ONE block per height; Core's index holds two
   fully-validated blocks at 963853 and the store kept the stale one. So
   its header chain is: ... 963852, STALE 963853, main 963854 (prev =
   main 963853) ... The node accepted 962001..963853(stale), the next
   batch did not connect, and the blocking header-sync loop re-sent the
   same locator 10x, dropped the peer, slept 10 s and started again —
   354 rounds — with header tip 963853 >> block tip 950000. Block 950001
   was never requested.

   Core never gates block download on header sync finishing
   (FindNextBlocksToDownload uses whatever headers we hold;
   HandleUnconnectingHeaders sends one getheaders). Fix: when the loop
   cannot advance but we already hold downloadable headers, leave it in
   SyncingBlocks.

   Same shape here on regtest: node at an assumeUTXO-like block tip 10,
   peer serves main 1..N with a stale sibling substituted at T.

   Command (red on 6fcfb3d's lib/sync.ml, green after):
     dune exec --no-buffer test/test_slice_header_tie.exe
*)

open Camlcoin

let regtest = Consensus.regtest
let genesis_ts = regtest.genesis_header.Types.timestamp

let mine ~prev ~height ~salt : Types.block_header * Types.hash256 =
  let rec grind nonce =
    let hdr =
      Types.
        {
          version = 0x20000000l;
          prev_block = prev;
          merkle_root = Types.zero_hash;
          timestamp =
            Int32.add genesis_ts (Int32.of_int ((height * 600) + salt));
          bits = 0x207fffffl;
          nonce;
        }
    in
    let hash = Crypto.compute_block_hash hdr in
    if Consensus.check_proof_of_work hash hdr.Types.bits regtest then
      (hdr, hash)
    else grind (Int32.succ nonce)
  in
  grind 0l

(* Main chain 0..n; slot [tie] replaced by a sibling of main[tie]
   exactly like blk-replay-server's one-block-per-height index. *)
type served = {
  hdrs : Types.block_header array; (* by height, as served *)
  hash2h : (string, int) Hashtbl.t;
  main_hashes : Types.hash256 array;
}

let build_served ~n ~tie =
  let genesis_hash = Crypto.compute_block_hash regtest.genesis_header in
  let hdrs = Array.make (n + 1) regtest.genesis_header in
  let main_hashes = Array.make (n + 1) genesis_hash in
  let hash2h = Hashtbl.create (2 * n) in
  Hashtbl.replace hash2h (Cstruct.to_string genesis_hash) 0;
  for h = 1 to n do
    let hdr, hash = mine ~prev:main_hashes.(h - 1) ~height:h ~salt:0 in
    hdrs.(h) <- hdr;
    main_hashes.(h) <- hash
  done;
  (match tie with
   | Some t ->
     let s_hdr, _ = mine ~prev:main_hashes.(t - 1) ~height:t ~salt:1 in
     hdrs.(t) <- s_hdr
   | None -> ());
  Array.iteri
    (fun h hdr ->
      if h > 0 then
        Hashtbl.replace hash2h
          (Cstruct.to_string (Crypto.compute_block_hash hdr)) h)
    hdrs;
  { hdrs; hash2h; main_hashes }

(* blk-replay-server.py handle_getheaders: first known locator hash, then
   up to 2000 consecutive heights from the one-per-height table. *)
let serve (s : served) (locator : Types.hash256 list) =
  let start =
    1
    + (match
         List.find_map
           (fun h -> Hashtbl.find_opt s.hash2h (Cstruct.to_string h))
           locator
       with
      | Some h -> h
      | None -> -1)
  in
  let last = Array.length s.hdrs - 1 in
  let stop = min (start + P2p.max_headers_count - 1) last in
  if stop < start then []
  else List.init (stop - start + 1) (fun i -> s.hdrs.(start + i))

let make_pair () =
  let a, b = Unix.socketpair Unix.PF_UNIX Unix.SOCK_STREAM 0 in
  let mk fd id =
    let p =
      Peer.make_peer ~network:regtest ~addr:"127.0.0.1" ~port:(9000 + id) ~id
        ~direction:Peer.Outbound
        ~fd:(Lwt_unix.of_unix_file_descr ~blocking:false fd)
        ()
    in
    p.Peer.state <- Peer.Ready;
    p.Peer.handshake_complete <- true;
    p
  in
  (mk a 0, mk b 1)

let rec server_loop (srv : Peer.peer) (s : served) (getheaders : int ref) =
  let open Lwt.Syntax in
  let* m = Peer.read_message_with_timeout srv 30.0 in
  match m with
  | None -> Lwt.return_unit
  | Some (P2p.GetheadersMsg { locator_hashes; _ }) ->
    incr getheaders;
    let* () =
      Peer.send_message srv (P2p.HeadersMsg (serve s locator_hashes))
    in
    server_loop srv s getheaders
  | Some _ -> server_loop srv s getheaders

(* Node holds main 0..base as headers and has validated through [base]. *)
let seed_node (state : Sync.chain_state) (s : served) ~base =
  for h = 1 to base do
    match Sync.validate_header state s.hdrs.(h) with
    | Ok e -> Sync.accept_header state e
    | Error e -> Alcotest.failf "seed header %d: %s" h e
  done;
  state.Sync.blocks_synced <- base

let run_sync state s =
  let node, srv = make_pair () in
  let getheaders = ref 0 in
  let server = server_loop srv s getheaders in
  let outcome =
    Lwt_main.run
      (Lwt.pick
         [
           (let open Lwt.Syntax in
            let* () = Sync.sync_headers state node in
            Lwt.return `Returned);
           (let open Lwt.Syntax in
            let* () = Lwt_unix.sleep 60.0 in
            Lwt.return `Hung);
         ])
  in
  Lwt.cancel server;
  (outcome, !getheaders)

let state_name = Sync.sync_state_to_string

(* (a) The slice shape: tie at T, block tip far below it. Must leave the
   loop for block download after the first unconnecting batch, with the
   valid prefix kept. *)
let test_tie_above_header_tip_starts_block_download () =
  let base = 10 and tie = 1500 and n = 2600 in
  let s = build_served ~n ~tie:(Some tie) in
  Test_tmp.with_chaindb (fun db ->
      let state = Sync.create_chain_state db regtest in
      seed_node state s ~base;
      let outcome, gh = run_sync state s in
      Alcotest.(check bool) "sync_headers returned" true (outcome = `Returned);
      Alcotest.(check int) "valid prefix kept: header tip = tie height" tie
        state.Sync.headers_synced;
      Alcotest.(check string) "left for block download"
        (state_name Sync.SyncingBlocks) (state_name state.Sync.sync_state);
      (* first batch + the one unconnecting re-ask; pre-fix: 1 + 11 *)
      Alcotest.(check bool)
        (Printf.sprintf "no 10x same-locator loop (getheaders sent=%d)" gh)
        true (gh <= 3);
      (* the downloadable span is main-chain ancestry *)
      match Sync.get_ancestor state (Option.get state.Sync.tip) (tie - 1) with
      | Some e ->
        Alcotest.(check bool) "tie-1 is main" true
          (Cstruct.equal e.Sync.hash s.main_hashes.(tie - 1))
      | None -> Alcotest.fail "no header at tie-1")

(* (b) Negative control: nothing above the block tip to download (the
   peer's chain never connects). The old retry-then-drop behaviour must
   stand — Idle, so the driver tries another peer. *)
let test_nothing_to_download_keeps_idle () =
  let base = 10 in
  let s = build_served ~n:2600 ~tie:None in
  Test_tmp.with_chaindb (fun db ->
      let state = Sync.create_chain_state db regtest in
      seed_node state s ~base;
      (* foreign chain: same heights, every header off a different genesis
         child, so nothing the peer sends ever connects *)
      let foreign = build_served ~n:2600 ~tie:None in
      let junk = Cstruct.create 32 in
      Cstruct.memset junk 0x5a;
      let fh, _ = mine ~prev:junk ~height:base ~salt:7 in
      foreign.hdrs.(base + 1) <- fh;
      Hashtbl.reset foreign.hash2h;
      (* unknown locator -> start at height 0+1; serve from base+1 instead *)
      let served =
        { foreign with
          hdrs = Array.sub foreign.hdrs base (Array.length foreign.hdrs - base) }
      in
      let outcome, gh = run_sync state served in
      Alcotest.(check bool) "sync_headers returned" true (outcome = `Returned);
      Alcotest.(check int) "header tip unchanged" base state.Sync.headers_synced;
      Alcotest.(check string) "Idle (rotate peer)"
        (state_name Sync.Idle) (state_name state.Sync.sync_state);
      Alcotest.(check bool)
        (Printf.sprintf "retried to the unconnecting limit (getheaders=%d)" gh)
        true (gh > Sync.max_num_unconnecting_headers_msgs))

let () =
  Alcotest.run "slice_header_tie"
    [
      ( "header-sync",
        [
          Alcotest.test_case "tie above header tip -> block download" `Quick
            test_tie_above_header_tip_starts_block_download;
          Alcotest.test_case "nothing to download -> Idle (control)" `Quick
            test_nothing_to_download_keeps_idle;
        ] );
    ]
