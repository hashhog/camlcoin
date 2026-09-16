(* Control: stall class 231 CRITICALs (QUEUES.md item 3).

   Live 2026-09-16: pin 7921e5a, FullySynced, blocks=967188 headers=967316
   for 22 h. At-tip gap fill requested 16 blocks every 30 s; stale-tip
   picked a VERSION liar (972471 vs our 967188) and rotated peers;
   getheaders came back "2000 known headers, locator may be stale"
   (the re-anchor-on-restart deadlock's cousin, not a restart).

   Three production helpers this file pins:

     1. Peer_manager.should_rotate_stale_peer — must NOT rotate while
        header_tip > block_tip (rotation kills in-flight getdata).
     2. Peer_manager.version_height_is_plausible — VERSION start_height
        thousands above the header tip is a liar, not "ahead".
     3. Sync.header_tip_after_block_connect — connecting a gap block
        must not rewind state.tip; next_blocks_to_download reads it.
     4. Sync.should_start_catchup_ibd — FullySynced + header-ahead must
        re-enter IBD even after the first catch-up has finished.

   Command (fails on the pre-fix bodies, passes after):
     dune exec --no-buffer test/test_stall_class_231.exe
*)

open Camlcoin

(* Negative control: the inlined check_stale_tip condition that ran on
   the live pin. Fires on any VERSION-ahead peer after 2× 30 min, even
   during a header-ahead catch-up. *)
let legacy_should_rotate ~has_ahead_peer ~time_since_update ~interval =
  has_ahead_peer && time_since_update > 2.0 *. interval

let dummy_entry height : Sync.header_entry =
  let h =
    Types.
      {
        version = 1l;
        prev_block = Types.zero_hash;
        merkle_root = Types.zero_hash;
        timestamp = Int32.of_int (1_600_000_000 + (height * 600));
        bits = 0x207fffffl;
        nonce = Int32.of_int height;
      }
  in
  {
    Sync.header = h;
    hash = Types.zero_hash;
    height;
    total_work = Consensus.zero_work;
  }

(* Live numbers from 2026-09-16T20:06Z. *)
let live_block = 967188
let live_header = 967316
let live_liar = 972471l
let live_stale_s = 79500.0
let live_interval = 1800.0

let test_legacy_rotate_fires_during_catchup () =
  Alcotest.(check bool)
    "legacy inlined condition WOULD rotate during the 967188 freeze"
    true
    (legacy_should_rotate ~has_ahead_peer:true
       ~time_since_update:live_stale_s ~interval:live_interval)

let test_no_rotate_during_header_ahead_catchup () =
  let got =
    Peer_manager.should_rotate_stale_peer ~header_height:live_header
      ~block_height:live_block ~time_since_update:live_stale_s
      ~stale_tip_check_interval:live_interval
      ~has_plausibly_ahead_peer:true
  in
  Alcotest.(check bool)
    "production must NOT rotate while headers are ahead of blocks" false got

let test_rotate_still_fires_when_caught_up () =
  let got =
    Peer_manager.should_rotate_stale_peer ~header_height:live_header
      ~block_height:live_header ~time_since_update:live_stale_s
      ~stale_tip_check_interval:live_interval
      ~has_plausibly_ahead_peer:true
  in
  Alcotest.(check bool)
    "rotation still fires at header==block after 2× interval" true got

let test_version_liar_is_not_plausible () =
  let got =
    Peer_manager.version_height_is_plausible ~our_header_height:live_header
      live_liar
  in
  Alcotest.(check bool)
    "VERSION start_height 972471 vs header tip 967316 is a liar" false got

let test_honest_peer_slightly_ahead_is_plausible () =
  let got =
    Peer_manager.version_height_is_plausible ~our_header_height:live_header
      (Int32.of_int (live_header + 8))
  in
  Alcotest.(check bool) "a peer 8 blocks ahead of headers is plausible" true
    got

let test_header_tip_not_rewound_on_gap_connect () =
  let header_tip = dummy_entry 20 in
  let connected = dummy_entry 11 in
  match Sync.header_tip_after_block_connect (Some header_tip) connected with
  | None -> Alcotest.fail "header tip became None"
  | Some t ->
    Alcotest.(check int)
      "connecting height 11 must leave the header tip at 20" 20 t.Sync.height

let test_header_tip_advances_when_connecting_the_tip () =
  let header_tip = dummy_entry 10 in
  let connected = dummy_entry 11 in
  match Sync.header_tip_after_block_connect (Some header_tip) connected with
  | None -> Alcotest.fail "header tip became None"
  | Some t ->
    Alcotest.(check int) "connecting the header tip advances it" 11
      t.Sync.height

let test_rewound_tip_makes_next_blocks_empty () =
  (* Why (3) matters: next_blocks_to_download walks state.tip. If a gap
     connect rewinds tip to the connected block, the remaining header
     gap is invisible and at-tip fill logs nothing. *)
  let n_headers = 20 in
  let n_validated = 10 in
  let db_path = "/tmp/camlcoin_test_stall_class_231_rewind" in
  let rec rm_rf path =
    if Sys.file_exists path then
      if Sys.is_directory path then begin
        Array.iter (fun f -> rm_rf (Filename.concat path f)) (Sys.readdir path);
        Unix.rmdir path
      end
      else Unix.unlink path
  in
  rm_rf db_path;
  let db = Storage.ChainDB.create db_path in
  let state = Sync.create_chain_state db Consensus.regtest in
  let genesis = Option.get state.Sync.tip in
  let hashes = Array.make (n_headers + 1) genesis.Sync.hash in
  let prev = ref genesis in
  for h = 1 to n_headers do
    let hdr =
      Types.
        {
          version = 1l;
          prev_block = !prev.Sync.hash;
          merkle_root = Types.zero_hash;
          timestamp = Int32.of_int (1_600_000_000 + (h * 600));
          bits = 0x207fffffl;
          nonce = Int32.of_int h;
        }
    in
    let hash = Crypto.compute_block_hash hdr in
    let work =
      Consensus.work_add !prev.Sync.total_work
        (Consensus.work_from_compact hdr.Types.bits)
    in
    let e : Sync.header_entry =
      { header = hdr; hash; height = h; total_work = work }
    in
    Hashtbl.replace state.Sync.headers (Cstruct.to_string hash) e;
    state.Sync.tip <- Some e;
    state.Sync.headers_synced <- h;
    hashes.(h) <- hash;
    prev := e
  done;
  state.Sync.blocks_synced <- n_validated;
  let before = Sync.next_blocks_to_download ~count:16 state in
  Alcotest.(check int) "gap of 10 yields 10 hashes before rewind"
    10 (List.length before);
  (* Apply the production helper as process_new_block does. *)
  let connected = Option.get (Sync.best_header_at_height state (n_validated + 1)) in
  state.Sync.tip <- Sync.header_tip_after_block_connect state.Sync.tip connected;
  state.Sync.blocks_synced <- n_validated + 1;
  let after = Sync.next_blocks_to_download ~count:16 state in
  (* Post-fix: tip stays at 20, blocks_synced=11 → 9 remaining hashes.
     Pre-fix: tip rewound to 11, blocks_synced=11 → 0 hashes. *)
  Alcotest.(check int)
    "after connecting height 11 the remaining header gap is still requested"
    9 (List.length after);
  Alcotest.(check bool) "first remaining hash is height 12" true
    (Cstruct.equal (List.hd after) hashes.(12));
  Storage.ChainDB.close db;
  rm_rf db_path

let test_catchup_reenters_after_first_ibd () =
  let got =
    Sync.should_start_catchup_ibd ~ibd_running:false ~already_started:true
      ~sync_state:Sync.FullySynced ~header_height:live_header
      ~block_height:live_block ~has_download_peer:true
  in
  Alcotest.(check bool)
    "FullySynced + header-ahead re-enters catch-up IBD after the first run"
    true got

let test_catchup_does_not_start_when_caught_up () =
  let got =
    Sync.should_start_catchup_ibd ~ibd_running:false ~already_started:true
      ~sync_state:Sync.FullySynced ~header_height:live_header
      ~block_height:live_header ~has_download_peer:true
  in
  Alcotest.(check bool) "no catch-up when header_tip == block_tip" false got

let () =
  Alcotest.run "stall_class_231" [
    ( "stale-tip rotation",
      [
        Alcotest.test_case "legacy condition would rotate during catch-up"
          `Quick test_legacy_rotate_fires_during_catchup;
        Alcotest.test_case "production does not rotate during header-ahead catch-up"
          `Quick test_no_rotate_during_header_ahead_catchup;
        Alcotest.test_case "production still rotates when caught up and stale"
          `Quick test_rotate_still_fires_when_caught_up;
      ] );
    ( "VERSION liar",
      [
        Alcotest.test_case "972471 vs header 967316 is not plausible"
          `Quick test_version_liar_is_not_plausible;
        Alcotest.test_case "peer 8 ahead of headers is plausible"
          `Quick test_honest_peer_slightly_ahead_is_plausible;
      ] );
    ( "header tip on gap connect",
      [
        Alcotest.test_case "connecting height 11 leaves header tip at 20"
          `Quick test_header_tip_not_rewound_on_gap_connect;
        Alcotest.test_case "connecting the header tip still advances it"
          `Quick test_header_tip_advances_when_connecting_the_tip;
        Alcotest.test_case "rewound tip would empty next_blocks_to_download"
          `Quick test_rewound_tip_makes_next_blocks_empty;
      ] );
    ( "catch-up IBD re-entry",
      [
        Alcotest.test_case "re-enters after first IBD when headers are ahead"
          `Quick test_catchup_reenters_after_first_ibd;
        Alcotest.test_case "does not start when already at the header tip"
          `Quick test_catchup_does_not_start_when_caught_up;
      ] );
  ]
