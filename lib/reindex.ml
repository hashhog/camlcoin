(* -reindex driver — wipe and rebuild the chainstate.
 *
 * Bitcoin Core's [-reindex] (init.cpp + validation.cpp) wipes the
 * UTXO + chain-state in chainstate/ and re-validates every block
 * from height 0 forward, retaining the on-disk block bodies in
 * blocks/blk*.dat. CamlCoin's storage layout is different but the
 * spirit is the same:
 *
 *   - cf_block_header / cf_block_data / cf_block_height : retained
 *     (these are the canonical block store; rebuilding them would
 *     mean re-downloading from peers, which is the user's fallback
 *     if they want a deeper wipe).
 *   - cf_utxo / cf_chain_state / cf_undo_data : wiped and rebuilt
 *     by replaying every stored block forward.
 *   - rocksdb_utxo/ (the assume-utxo store used by OptimizedUtxoSet
 *     during IBD) : entire directory removed before reopening,
 *     equivalent to a full table truncate.
 *
 * Order of operations matters:
 *   1. Caller has NOT yet opened ChainDB (we need to remove the
 *      rocksdb_utxo subdirectory).
 *   2. We open the CF chainstate, clear the three CFs, close it.
 *   3. We rm-rf rocksdb_utxo/.
 *   4. Caller opens ChainDB + Rocksdb_store fresh, calls
 *      Sync.restore_chain_state → blocks_synced = 0 (no tip).
 *   5. Caller invokes [replay_stored_blocks] which drives
 *      Sync.connect_stored_blocks until no contiguous block at
 *      blocks_synced+1 remains.
 *   6. Daemon continues into normal IBD / FullySynced operation.
 *
 * Honest-progress note: replay uses [Sync.connect_stored_blocks]
 * which writes through [Storage.ChainDB.apply_block_atomic] (i.e.
 * one CF batch + one Rocksdb_store batch per block). This is
 * slower than the IBD pipeline that batches via OptimizedUtxoSet,
 * but it works without a deeper refactor of the validation entry
 * point. For mainnet-scale rebuilds the operator should expect
 * hours, not minutes — see TODO(reindex-fastpath) below.
 *)

(* Recursively remove [path] (file or directory). Best-effort: any
   single rm failure is logged but does not abort the wipe — a
   partially-wiped subdir is still safe because the boot path will
   reopen RocksDB which will repair its own metadata. *)
let rec rm_rf (path : string) : unit =
  try
    let st = Unix.lstat path in
    match st.Unix.st_kind with
    | Unix.S_DIR ->
      let entries = try Sys.readdir path with _ -> [||] in
      Array.iter (fun name ->
        rm_rf (Filename.concat path name)
      ) entries;
      (try Unix.rmdir path with _ -> ())
    | _ ->
      (try Unix.unlink path with _ -> ())
  with Unix.Unix_error (Unix.ENOENT, _, _) -> ()
     | exn ->
       Logs.warn (fun m ->
         m "reindex: rm_rf %s failed: %s" path (Printexc.to_string exn))

(* Phase 1: pre-open wipe. Must run BEFORE the daemon opens ChainDB
   or the Rocksdb_store. Returns [Ok ()] on success or [Error msg]
   if a step failed in a way that would leave the datadir in a
   half-baked state. *)
let pre_open_wipe ~(data_dir : string) : (unit, string) result =
  let chainstate_dir = Filename.concat data_dir "chainstate" in
  let cf_path = Filename.concat chainstate_dir "chainstate-rocks" in
  let rocksdb_utxo_path = Filename.concat data_dir "rocksdb_utxo" in
  Logs.info (fun m ->
    m "reindex: phase 1 — wiping UTXO + chain_state + undo_data");
  (* Open the CF chainstate just long enough to clear three CFs. *)
  if not (Sys.file_exists cf_path) then begin
    Logs.info (fun m ->
      m "reindex: chainstate-rocks/ not present at %s — nothing to wipe \
         (fresh datadir; full IBD will run from genesis)" cf_path);
    rm_rf rocksdb_utxo_path;
    Ok ()
  end else begin
    try
      let cf = Cf_chainstate.open_db cf_path in
      let n_utxo = Cf_chainstate.cf_clear_utxo cf in
      Logs.info (fun m ->
        m "reindex: cleared %d entries from cf_utxo" n_utxo);
      (* Clear only the chain-tip pointer (tip_hash, tip_height),
         keeping the header tip intact. restore_chain_state needs
         header_tip_hash + header_tip_height to reload the in-memory
         header chain from cf_block_header — which is what drives the
         post-wipe block replay. *)
      let n_chain = Cf_chainstate.cf_clear_chain_tip_only cf in
      Logs.info (fun m ->
        m "reindex: cleared %d chain-tip entries from cf_chain_state \
           (header_tip retained)" n_chain);
      let n_undo = Cf_chainstate.cf_clear_undo_data cf in
      Logs.info (fun m ->
        m "reindex: cleared %d entries from cf_undo_data" n_undo);
      Cf_chainstate.close cf;
      Logs.info (fun m ->
        m "reindex: removing %s" rocksdb_utxo_path);
      rm_rf rocksdb_utxo_path;
      (* Stale derived state files: mempool.dat, fee_estimates.dat —
         these are hashes/keys against the now-wiped chainstate, so
         loading them on next boot would either fail or insert phantom
         conflicts. Drop them now. *)
      let stale =
        [ Filename.concat data_dir "mempool.dat";
          Filename.concat data_dir "fee_estimates.dat" ]
      in
      List.iter (fun p ->
        if Sys.file_exists p then begin
          Logs.info (fun m -> m "reindex: removing stale %s" p);
          (try Unix.unlink p with _ -> ())
        end
      ) stale;
      Ok ()
    with exn ->
      Error (Printf.sprintf
               "reindex pre-open wipe failed: %s"
               (Printexc.to_string exn))
  end

(* Phase 2: post-open replay. Caller has already opened ChainDB +
   OptimizedUtxoSet and built the [chain_state] via
   [Sync.restore_chain_state]. This walks forward from
   [blocks_synced + 1] using the existing [Sync.connect_stored_blocks]
   helper (which validates and applies each block atomically).
   Logs a progress line every [progress_interval] blocks.

   Returns the number of blocks replayed.

   Header-tip handling: [Sync.connect_stored_blocks] calls
   [apply_block_atomic] with [header_tip_height:next_height] on every
   block, which means the on-disk header_tip walks backwards to
   genesis at the very first replay step. We snapshot the original
   header tip on entry and write it back when the replay completes
   so a clean reindex leaves the header chain visible to the next
   restart. A mid-replay crash still loses the tail headers but the
   block data is intact; the next start will re-fetch via getheaders.

   TODO(reindex-fastpath): connect_stored_blocks routes through
   apply_block_atomic which writes per-block to BOTH cf_utxo and
   rocksdb_utxo. The IBD pipeline batches these via
   OptimizedUtxoSet.flush which can be 10-100x faster on mainnet.
   A future enhancement could plumb the OptimizedUtxoSet here, but
   the validation entry point currently expects the
   [Storage.ChainDB.get_utxo] fallback chain rather than
   OptimizedUtxoSet directly. Out of scope for the initial
   implementation. *)
let replay_stored_blocks
    ?(progress_interval = 10_000)
    (state : Sync.chain_state) : int =
  Logs.info (fun m ->
    m "reindex: phase 2 — replaying stored blocks from height %d \
       (header tip = %d)"
      (state.blocks_synced + 1)
      state.headers_synced);
  (* Snapshot the original header tip so we can restore it after the
     replay walks forward (each apply_block_atomic clobbers header_tip
     to the just-connected block). *)
  let orig_header_tip =
    match Storage.ChainDB.get_header_tip state.db with
    | Some (h, ht) -> Some (h, ht)
    | None -> None
  in
  let orig_header_synced = state.headers_synced in
  let total = ref 0 in
  let last_log = ref state.blocks_synced in
  let t0 = Unix.gettimeofday () in
  let continue_replay = ref true in
  while !continue_replay do
    let n = Sync.connect_stored_blocks state in
    if n = 0 then
      continue_replay := false
    else begin
      total := !total + n;
      if state.blocks_synced - !last_log >= progress_interval then begin
        let elapsed = Unix.gettimeofday () -. t0 in
        let rate =
          if elapsed > 0.0 then float_of_int !total /. elapsed else 0.0 in
        Logs.info (fun m ->
          m "reindex: replayed %d blocks (height %d / header tip %d, \
             %.0f blk/s, %.1fs elapsed)"
            !total state.blocks_synced orig_header_synced rate elapsed);
        last_log := state.blocks_synced
      end
    end
  done;
  let elapsed = Unix.gettimeofday () -. t0 in
  (* Restore the original header tip if it was further along than the
     replay reached (e.g. the operator wiped a chainstate that had
     header-synced past the last validated block). *)
  (match orig_header_tip with
   | Some (orig_h, orig_ht) when orig_ht > state.blocks_synced ->
     Storage.ChainDB.set_header_tip state.db orig_h orig_ht;
     state.headers_synced <- orig_ht;
     Logs.info (fun m ->
       m "reindex: restored header tip to height %d" orig_ht)
   | _ -> ());
  Logs.info (fun m ->
    m "reindex: phase 2 complete — replayed %d blocks in %.1fs \
       (height %d / header tip %d)"
      !total elapsed state.blocks_synced state.headers_synced);
  !total
