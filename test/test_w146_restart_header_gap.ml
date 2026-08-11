(* W146: restart with header_tip AHEAD of block_tip on disk.

   Reproduces the 2026-08-11 mainnet incident
   (receipts/camlcoin-repair-executed-2026-08-11.md), two coupled symptoms:

   (A) RE-ANCHOR DEADLOCK: since fecf534 the height->hash index projects
       only the ACTIVE validated chain, so on restart the restore loop
       finds no rows for (chain_tip, header_tip], leaves [state.tip] =
       None, and mis-fires the snapshot-bootstrap re-anchor — rewinding
       header sync to genesis even though every header's bytes ARE in the
       block_header CF.  The from-genesis re-sync then deadlocks (every
       peer batch is already known -> discarded as stale).

   (B) POST-RESTORE DOWNLOAD GAP: fill_download_queue and the post-IBD
       gap-fill resolved download targets through the same active-chain
       index, so every height above blocks_synced was silently skipped:
       IBD completed instantly with 0 blocks and the block tip froze while
       the header tip advanced.

   The tests set up a datadir EXACTLY like the live condition — header
   bytes + header_tip at height 30, active-chain index rows + chain_tip at
   height 10, NO index rows for 11..30 — then restore and assert:
     - restore rebuilds the in-memory header chain to height 30 (no
       re-anchor: headers_synced = 30, not 0);
     - the getheaders locator anchors at the HEADER tip (a peer at the
       same height replies with an empty batch -> header sync completes ->
       SyncingBlocks -> IBD starts), not at the validated tip;
     - fill_download_queue queues exactly the gap heights 11..30 (these
       are the getdata targets, i.e. the node downloads the gap);
     - the genuine assumeUTXO snapshot re-anchor (header bytes truly
       absent) still fires.

   Pre-fix: restore leaves tip=None / headers_synced=0 (re-anchor) and the
   download queue stays empty.  Post-fix: all assertions hold. *)

open Camlcoin

(* Per-test db path: a failing assertion raises past [close db], and a
   shared rocksdb dir then poisons every later test in the run — so each
   test gets its own directory. *)
let test_db_base = "/tmp/camlcoin_test_w146_restart_header_gap"
let test_db_path = ref test_db_base

let cleanup_test_db () =
  let rec rm_rf path =
    if Sys.file_exists path then begin
      if Sys.is_directory path then begin
        Array.iter (fun f -> rm_rf (Filename.concat path f)) (Sys.readdir path);
        Unix.rmdir path
      end else
        Unix.unlink path
    end
  in
  rm_rf !test_db_path

let use_db (name : string) : unit =
  test_db_path := test_db_base ^ "_" ^ name;
  cleanup_test_db ()

(* Regtest header (pow_no_retargeting; PoW is not re-checked by the restore
   or download-queue paths under test, and regtest's 0x207fffff target is
   trivially satisfiable anyway). *)
let make_header ~prev_block ~ts ~nc =
  Types.{
    version = 1l;
    prev_block;
    merkle_root = Types.zero_hash;
    timestamp = ts;
    bits = 0x207fffffl;
    nonce = nc;
  }

let n_headers = 30    (* stored header chain: heights 1..30 *)
let n_validated = 10  (* validated (active-chain) tip: height 10 *)

(* Build the on-disk state of a node that crashed/restarted while header
   sync was ahead of block validation:
     - block_header CF: genesis + headers 1..30, header_tip @ 30
     - height->hash index: rows 0..10 ONLY (the active chain — the only
       rows the post-fecf534 writers ever produce)
     - chain_tip @ 10
   Returns the by-height hash array (0..30). *)
let build_header_ahead_datadir (name : string) =
  use_db name;
  let db = Storage.ChainDB.create !test_db_path in
  (* Seeds genesis header + height row 0 + header_tip genesis. *)
  let _state = Sync.create_chain_state db Consensus.regtest in
  let genesis_hash = Crypto.compute_block_hash Consensus.regtest.genesis_header in
  let hashes = Array.make (n_headers + 1) genesis_hash in
  let prev = ref genesis_hash in
  for h = 1 to n_headers do
    let hdr = make_header ~prev_block:!prev
        ~ts:(Int32.of_int (1600000000 + (h * 600)))
        ~nc:(Int32.of_int h) in
    let hash = Crypto.compute_block_hash hdr in
    (* What accept_header persists post-fecf534: header bytes + header_tip,
       and NOTHING in the height->hash index. *)
    Storage.ChainDB.store_block_header db hash hdr;
    Storage.ChainDB.set_header_tip db hash h;
    hashes.(h) <- hash;
    prev := hash
  done;
  (* What apply_block_atomic persisted for the validated prefix: the
     active-chain height rows + chain_tip. *)
  for h = 1 to n_validated do
    Storage.ChainDB.set_height_hash db h hashes.(h)
  done;
  Storage.ChainDB.set_chain_tip db hashes.(n_validated) n_validated;
  Storage.ChainDB.close db;
  hashes

(* (A) Restore must rebuild the in-memory header chain from the
   block-header CF up to the stored header tip — NOT re-anchor to
   genesis. *)
let test_restore_rebuilds_header_chain () =
  let hashes = build_header_ahead_datadir "restore" in
  let db = Storage.ChainDB.create !test_db_path in
  let state = Sync.restore_chain_state db Consensus.regtest in
  (* Pre-fix: tip = None -> re-anchor fires -> tip = genesis (height 0)
     and headers_synced = 0.  Post-fix: tip is the stored header tip. *)
  (match state.Sync.tip with
   | None -> Alcotest.fail "restore left state.tip = None"
   | Some t ->
     Alcotest.(check int) "tip height is the header tip" n_headers t.Sync.height;
     Alcotest.(check bool) "tip hash matches stored header tip" true
       (Cstruct.equal t.Sync.hash hashes.(n_headers)));
  Alcotest.(check int) "headers_synced = header tip (re-anchor did NOT fire)"
    n_headers state.Sync.headers_synced;
  Alcotest.(check int) "blocks_synced = validated tip"
    n_validated state.Sync.blocks_synced;
  (* Every gap header must be connectable in memory (this is what lets
     later peer headers extend the chain and lets MTP/retarget walks see
     real ancestors). *)
  for h = n_validated + 1 to n_headers do
    match Sync.best_header_at_height state h with
    | None ->
      Alcotest.fail
        (Printf.sprintf "best_header_at_height missed gap height %d" h)
    | Some e ->
      Alcotest.(check bool)
        (Printf.sprintf "gap header at height %d has the right hash" h)
        true (Cstruct.equal e.Sync.hash hashes.(h))
  done;
  (* Cumulative work must be monotonic across the rebuilt span (the work
     chain is what clears minimum_chain_work on mainnet). *)
  (match Sync.best_header_at_height state n_validated,
         Sync.best_header_at_height state n_headers with
   | Some low, Some high ->
     Alcotest.(check bool) "work accumulates over the rebuilt span" true
       (Consensus.work_compare high.Sync.total_work low.Sync.total_work > 0)
   | _ -> Alcotest.fail "work-chain endpoints missing");
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* (A2) The getheaders locator must anchor at the HEADER tip.  Pre-fix it
   was built from the height->hash index, whose highest row is the
   validated tip — so a peer replied with 20 already-known headers, the
   batch was discarded as stale, and header sync never completed (which is
   what kept SyncingBlocks / IBD from ever starting on the live node). *)
let test_locator_anchors_at_header_tip () =
  let hashes = build_header_ahead_datadir "locator" in
  let db = Storage.ChainDB.create !test_db_path in
  let state = Sync.restore_chain_state db Consensus.regtest in
  (match Sync.build_locator state with
   | [] -> Alcotest.fail "empty locator"
   | first :: _ ->
     Alcotest.(check bool) "locator head is the header tip hash" true
       (Cstruct.equal first hashes.(n_headers)));
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* (B) Block download must service the (block_tip, header_tip] gap: after
   restore, fill_download_queue must queue exactly heights 11..30.
   Pre-fix the index-driven loop silently skipped all of them (no rows),
   the queue stayed empty, and run_ibd declared "IBD complete (0 blocks)"
   with the block tip frozen. *)
let test_download_queue_covers_gap () =
  let hashes = build_header_ahead_datadir "dlqueue" in
  let db = Storage.ChainDB.create !test_db_path in
  let state = Sync.restore_chain_state db Consensus.regtest in
  let ibd = Sync.create_ibd_state state in
  Sync.fill_download_queue ibd;
  for h = n_validated + 1 to n_headers do
    match Sync.queue_find_by_height ibd h with
    | None ->
      Alcotest.fail
        (Printf.sprintf "gap height %d missing from download queue" h)
    | Some entry ->
      Alcotest.(check bool)
        (Printf.sprintf "queued hash at height %d matches header chain" h)
        true (Cstruct.equal entry.Sync.hash hashes.(h))
  done;
  Alcotest.(check bool) "validated height not re-queued" true
    (Sync.queue_find_by_height ibd n_validated = None);
  Alcotest.(check bool) "nothing queued beyond the header tip" true
    (Sync.queue_find_by_height ibd (n_headers + 1) = None);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Guard: the genuine assumeUTXO snapshot-bootstrap re-anchor must STILL
   fire when the header-tip bytes are truly absent (a bare UTXO snapshot
   carries no headers).  The fix narrows the re-anchor's trigger; it must
   not remove it. *)
let test_snapshot_reanchor_still_fires () =
  use_db "snapshot";
  let db = Storage.ChainDB.create !test_db_path in
  let _state = Sync.create_chain_state db Consensus.regtest in
  (* Snapshot-loader shape: header_tip/chain_tip point at a base whose
     header bytes are NOT on disk; only genesis is present. *)
  let base_hash = Cstruct.create 32 in
  Cstruct.memset base_hash 0xAA;
  Storage.ChainDB.set_header_tip db base_hash 100;
  Storage.ChainDB.set_chain_tip db base_hash 100;
  Storage.ChainDB.close db;
  let db = Storage.ChainDB.create !test_db_path in
  let state = Sync.restore_chain_state db Consensus.regtest in
  (match state.Sync.tip with
   | Some t ->
     Alcotest.(check int) "re-anchored to genesis" 0 t.Sync.height
   | None -> Alcotest.fail "snapshot restore left no tip at all");
  Alcotest.(check int) "headers_synced rewound to 0 for from-genesis rebuild"
    0 state.Sync.headers_synced;
  Alcotest.(check int) "blocks_synced preserved at the snapshot base"
    100 state.Sync.blocks_synced;
  Storage.ChainDB.close db;
  cleanup_test_db ()

let () =
  Alcotest.run "w146_restart_header_gap" [
    "restart with header_tip > block_tip", [
      Alcotest.test_case
        "restore rebuilds in-memory header chain (no genesis re-anchor)"
        `Quick test_restore_rebuilds_header_chain;
      Alcotest.test_case
        "getheaders locator anchors at the header tip, not the block tip"
        `Quick test_locator_anchors_at_header_tip;
      Alcotest.test_case
        "fill_download_queue queues the (block_tip, header_tip] gap"
        `Quick test_download_queue_covers_gap;
    ];
    "assumeUTXO snapshot guard", [
      Alcotest.test_case
        "re-anchor still fires when header bytes are genuinely absent"
        `Quick test_snapshot_reanchor_still_fires;
    ];
  ]
