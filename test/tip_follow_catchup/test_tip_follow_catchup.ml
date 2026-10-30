(* At tip, a one-block gap must not open a catch-up IBD session.

   Live mainnet 2026-10-30 (restart.log, heights 973804..973813). The normal
   path is the post-IBD gap-fill: the HeadersMsg listener asks the
   announcing peer for the block and it connects within seconds:

     Post-IBD gap-fill: requesting 1 missing blocks [973812..973812] from peer 175
     UpdateTip: ... height=973812 ... elapsed=2.551s

   But when the 30 s status tick lands between the header and the block, it
   calls [ensure_catchup_ibd], whose predicate only asked "header tip ahead
   of block tip?". For a one-block gap at tip that opened a full IBD session:

     Post-IBD gap-fill: requesting 1 missing blocks [973809..973809] from peer 175
     Starting catch-up block download (header tip 973809, block tip 973808)
     Starting IBD from height 973808 to 973809
     IBD stall: queue=1 in-flight=0 next_dl=973810 next_proc=973810   (x5)
     Stale tip check (no update for 802s) ... our block 973809 header 973811
     IBD complete at height 973811 (2 blocks in 975.6s, 0 blk/s)

   While that session exists the gap-fill paths stand down
   ([ibd_state_ref <> None]), so the next blocks were fetched by
   [request_blocks] from whichever peer it picked, under the IBD per-block
   timeout (128 s base, doubling) instead of the 2 s gap-fill rotation.
   973806 sat with its header known for ~4 minutes; 973810/973811 for over a
   minute each. That is the lag>=1 run the audit counted.

   Core has no separate IBD session: FindNextBlocksToDownload asks the
   announcing peer, which is what gap-fill does. Catch-up IBD stays for what
   it was added for: header sync still racing (assumeUTXO campaigns) and
   gaps wider than one gap-fill batch (the 2026-09-16 967188/967316 stall,
   pinned in test_stall_class_231). *)

open Camlcoin

let at_tip ?(sync_state = Sync.FullySynced) ~gap () =
  Sync.should_start_catchup_ibd ~ibd_running:false ~already_started:true
    ~sync_state ~header_height:(973808 + gap) ~block_height:973808
    ~has_download_peer:true

let test_one_block_gap_left_to_gapfill () =
  Alcotest.(check bool)
    "FullySynced one-block gap does not start catch-up IBD" false
    (at_tip ~gap:1 ())

let test_three_block_gap_left_to_gapfill () =
  (* 973809..973811 arrived inside one stalled session. *)
  Alcotest.(check bool)
    "FullySynced three-block gap does not start catch-up IBD" false
    (at_tip ~gap:3 ())

(* One gap-fill batch: Core MAX_BLOCKS_IN_TRANSIT_PER_PEER = 16. *)
let window = 16

let test_full_gapfill_batch_left_to_gapfill () =
  Alcotest.(check bool)
    "FullySynced gap of one gap-fill batch does not start catch-up IBD" false
    (at_tip ~gap:window ())

let test_wider_gap_still_catches_up () =
  Alcotest.(check bool)
    "FullySynced gap wider than one gap-fill batch starts catch-up IBD" true
    (at_tip ~gap:(window + 1) ())

let test_header_sync_still_catches_up () =
  (* assumeUTXO: header tip racing ahead while header sync runs. *)
  Alcotest.(check bool)
    "SyncingHeaders one-block gap starts catch-up IBD" true
    (at_tip ~sync_state:Sync.SyncingHeaders ~gap:1 ())

let test_syncing_blocks_still_catches_up () =
  Alcotest.(check bool)
    "SyncingBlocks one-block gap starts catch-up IBD" true
    (at_tip ~sync_state:Sync.SyncingBlocks ~gap:1 ())

let test_no_gap_no_catchup () =
  Alcotest.(check bool) "no gap starts nothing" false (at_tip ~gap:0 ())

let () =
  Alcotest.run "tip_follow_catchup"
    [
      ( "at-tip gap goes to gap-fill",
        [
          Alcotest.test_case "one-block gap" `Quick
            test_one_block_gap_left_to_gapfill;
          Alcotest.test_case "three-block gap" `Quick
            test_three_block_gap_left_to_gapfill;
          Alcotest.test_case "one gap-fill batch" `Quick
            test_full_gapfill_batch_left_to_gapfill;
        ] );
      ( "catch-up IBD kept where it belongs",
        [
          Alcotest.test_case "wider than a gap-fill batch" `Quick
            test_wider_gap_still_catches_up;
          Alcotest.test_case "header sync running" `Quick
            test_header_sync_still_catches_up;
          Alcotest.test_case "SyncingBlocks" `Quick
            test_syncing_blocks_still_catches_up;
          Alcotest.test_case "no gap" `Quick test_no_gap_no_catchup;
        ] );
    ]
