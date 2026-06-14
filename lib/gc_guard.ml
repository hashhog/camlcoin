(* gc_guard.ml — shared heap-compaction guard for the at-tip / hot-path
   memory-reclamation machinery.

   WHY THIS MODULE EXISTS (2026-06-09 hot-path compaction fix):
   The original machinery lived as a closure inside cli.ml's [run] — a
   detached Lwt timer (gc_thread, 5 s tick) plus a 120 s time-floor in the
   status loop.  Two structural failures vs Bitcoin Core:

   (a) STARVATION: the Lwt loop runs the select(2) backend, so Lwt_unix.sleep
       timers only fire BETWEEN callbacks.  Fully-synchronous multi-second
       stretches on the Lwt main thread (connect_stored_blocks' drain, a
       sendrawtransaction accept, a package accept, a big block connect)
       defer the 5 s tick indefinitely — the heap can accumulate many GB
       before the timer ever gets a turn (the live ~17 G-vs-3 G-threshold
       incident, and the 111 G re-IBD pathology where the FullySynced gate
       kept the timer off entirely).

   (b) RATE MISMATCH: even when the timer runs, a wall-clock tick cannot
       scale with the work rate.  Bitcoin Core has NO detached flush timer:
       FlushStateToDisk is invoked synchronously FROM the hot paths
       (ConnectTip → IF_NEEDED per block, validation.cpp:3063;
       AcceptToMemoryPool → PERIODIC per acceptance, validation.cpp:1803),
       so the budget check rides the work itself.

   The fix mirrors Core: [maybe_compact] is a cheap inline check
   (Gc.quick_stat is O(1) counter reads — no heap walk) called once per
   tx-accept / package-batch / block-connect at the hot-path exits in
   mempool.ml, sync.ml and mining.ml, sharing ONE [last_compact_time] +
   threshold + anti-thrash floor with cli.ml's surviving gc_thread
   (idle-reclamation fallback) and 120 s time-floor.  All call sites run on
   the Lwt main thread — the identical execution context as the old
   gc_thread call, proven safe by the live soak.

   CALL CHOICE: Gc.compact + Rocksdb.malloc_trim (NOT Gc.full_major, not a
   tiered scheme).  On OCaml 5.3 only compaction unmaps empty major-heap
   pools; full_major+trim would plateau RSS near the high-water mark instead
   of the proven ~2 G troughs.  The historical 30-60 s compaction blackouts
   were a symptom of compacting 17-21 G of STARVED accumulation; with an
   un-starvable trigger capping the heap at ~threshold+one-batch, each
   compact is sub-second (live set ~600 MB).

   GATING: the hot-path checks are deliberately UNGATED by sync_state.  The
   at-tip listeners are FullySynced-gated upstream, so steady-state behavior
   is unchanged; the catch-up drain / re-IBD states — exactly where the
   111 G pathology lived with gc_thread gated OFF and run_ibd's 16-block
   cadence stalled at 0 blk/s — gain a backstop.  IBD throughput cost is
   bounded by the anti-thrash floor.  run_ibd's 16-block cadence routes
   through [compact_now] so IBD and the hot-path guard share the floor and
   never double-compact back-to-back. *)

(* Single shared stamp: every trigger (threshold timer, time-floor,
   hot-path sites, IBD cadence) resets every other trigger's floor. *)
let last_compact_time = ref 0.0

(* Time-floor fallback: compact at least this often even under the
   threshold, so idle off-heap/arena memory is still returned (matches the
   prior 120 s behavior).  Used by cli.ml's status loop via
   [compact_if_overdue]. *)
let compact_interval_s = 120.0

(* Heap-size cap: compact as soon as the live OCaml heap exceeds this many
   bytes.  ~3 GB keeps each Gc.compact + malloc_trim small (the freed
   amount, not the 17.5 GB the 120 s window used to accumulate) so the RPC
   stall is sub-second.  Read via Gc.quick_stat().heap_words (cheap — no
   heap walk).  Overridable via CAMLCOIN_COMPACT_THRESHOLD_MB (used by the
   regtest gc-load gate to exercise the guard at 512 MB, far below the
   harness cgroup cap); invalid / non-positive values fall back to the
   default. *)
let default_compact_threshold_mb = 3072.0

let compact_heap_threshold_bytes =
  let mb =
    match Sys.getenv_opt "CAMLCOIN_COMPACT_THRESHOLD_MB" with
    | Some s ->
      (match float_of_string_opt (String.trim s) with
       | Some v when v > 0.0 -> v
       | _ -> default_compact_threshold_mb)
    | None -> default_compact_threshold_mb
  in
  mb *. 1024.0 *. 1024.0

(* Anti-thrash floor: never compact more often than this even when over the
   threshold, so a sustained allocation burst does not spin Gc.compact
   (each is still stop-the-world) back-to-back and starve the event loop.
   This is the Core-parity bound on hot-path-triggered compaction cost. *)
let compact_min_interval_s = 8.0

(* Fast-tick cadence for cli.ml's dedicated GC timer (the idle fallback).
   Must be <= the min-interval floor so the timer can react to a threshold
   breach within roughly one floor window when the loop is idle. *)
let gc_check_interval_s = 5.0

let mb_of_words w = float_of_int w *. 8.0 /. 1_048_576.0

let rss_mb () =
  try
    let ic = open_in "/proc/self/statm" in
    let line = input_line ic in
    close_in ic;
    (match String.split_on_char ' ' line with
     | _ :: res :: _ -> float_of_string res *. 4096.0 /. 1_048_576.0
     | _ -> 0.0)
  with _ -> 0.0

(* Unconditional compaction step (shared body of every trigger).  [reason]
   tags the [gc] log line so soak / load-test logs show which trigger fired:
   "threshold" (gc_thread), "time-floor" (status loop), "hot-path:*"
   (inline hot-path sites), "ibd-cadence" (run_ibd's 16-block cadence). *)
let compact_now ~reason =
  last_compact_time := Unix.gettimeofday ();
  let st_before = Gc.quick_stat () in
  (* Instrumentation (pure logging, no behaviour change): Gc.compact is a
     stop-the-world pause that blocks every OCaml thread — it IS the RPC /
     block-connect stall.  malloc_trim releases the runtime lock (see below),
     so it does NOT stall RPC.  Time them separately so a soak can histogram
     the real stall distribution and correlate it with the pre-compaction heap
     size (the lever a threshold/cadence tune would pull). *)
  let t0 = Unix.gettimeofday () in
  Gc.compact ();
  let t1 = Unix.gettimeofday () in
  (* Gc.compact frees the OCaml-side proxies for the transient
     validation/idle Bigarrays; malloc_trim(0) then returns that now-unused
     glibc arena memory to the OS.  Same binding the IBD path uses.
     (rocksdb_stubs.c wraps malloc_trim in caml_release/acquire_
     runtime_system so other OS threads — incl. the RPC thread — run during
     the trim; do not remove that.) *)
  Rocksdb.malloc_trim ();
  let t2 = Unix.gettimeofday () in
  let st_after = Gc.quick_stat () in
  Logs.info (fun m ->
    m "[gc] at-tip compaction (%s): heap=%d words (%.0fMB->%.0fMB) \
       rss=%.0fMB compact_stall=%.3fs trim=%.3fs total=%.3fs"
      reason
      st_after.Gc.heap_words
      (mb_of_words st_before.Gc.heap_words)
      (mb_of_words st_after.Gc.heap_words)
      (rss_mb ())
      (t1 -. t0)
      (t2 -. t1)
      (t2 -. t0))

(* The hot-path / threshold check: compact iff the major heap is over the
   size threshold AND the anti-thrash floor has elapsed.  O(1) when it does
   not fire (one Gc.quick_stat + one gettimeofday) — cheap enough to ride
   every tx-accept / block-connect exit, but call it once per BATCH/BLOCK,
   never per-input. *)
let maybe_compact ~reason =
  if float_of_int (Gc.quick_stat ()).Gc.heap_words *. 8.0
     >= compact_heap_threshold_bytes
     && Unix.gettimeofday () -. !last_compact_time >= compact_min_interval_s
  then compact_now ~reason

(* The wall-clock time-floor: compact when [compact_interval_s] has elapsed
   since ANY trigger last fired, regardless of heap size.  Guarantees idle
   off-heap/Domain-arena memory is still returned when allocation is slow
   and the threshold is never reached. *)
let compact_if_overdue ~reason =
  if Unix.gettimeofday () -. !last_compact_time >= compact_interval_s
  then compact_now ~reason
