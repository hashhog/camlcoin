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

   The fix mirrors Core: a cheap inline check (Gc.quick_stat is O(1) counter
   reads — no heap walk) called once per tx-accept / package-batch /
   block-connect at the hot-path exits in mempool.ml, sync.ml and mining.ml,
   sharing ONE [last_compact_time] + threshold + anti-thrash floor with
   cli.ml's surviving gc_thread (idle-reclamation fallback) and 120 s
   time-floor.  All call sites run on the Lwt main thread — the identical
   execution context as the old gc_thread call, proven safe by the live soak.

   ──────────────────────────────────────────────────────────────────────────
   2026-06-24 GC-COMPACTION RPC-STALL FIX (un-pin blocker — see
   CORE-PARITY-AUDIT/_camlcoin-gc-rpc-stall-rootcause-2026-06-24.md):

   ROOT CAUSE: [Gc.compact] is a STOP-THE-WORLD full-heap compaction that
   freezes EVERY OCaml domain at a safepoint for its whole duration.  camlcoin
   runs the Cohttp/Lwt JSON-RPC server, the GC timer, mempool-accept and
   block-connect ALL as cooperative Lwt promises on the SAME single OCaml main
   domain.  The RPC callback is just another mutator on that domain, so while
   [Gc.compact] runs the RPC handler makes no progress — the compaction pause
   IS the RPC stall.  Under public-peer load the mempool flood inflates the
   major heap fast, so the heap-size compaction trigger fired every ~8-15 s,
   and the recurring STW pauses were the observed thrash (RSS 22 G, RPC >15 s,
   peers dropped, lag grew) that forced the un-pin revert twice.

   THE FIX keeps STW compaction OFF the steady-state RPC-serving path,
   mirroring Bitcoin Core (which never STW-pauses its RPC thread):

   (a) STEADY STATE — non-STW.  [maybe_keep_up] drives the major collector
       forward with [Gc.major_slice] (a BOUNDED increment of mark-and-sweep
       that returns WITHOUT a stop-the-world barrier), plus a coarse periodic
       [malloc_trim] (already off the RPC path — rocksdb_stubs.c releases the
       runtime lock during it).  Running slices on every tick / hot-path exit
       keeps the collector caught up with the transient-allocation rate so the
       heap never balloons to the point a compaction is needed.  The RPC
       callback interleaves between slices.  Replaces the per-tick / per-accept
       [Gc.compact] triggers (gc_thread threshold + mempool hot-path).

   (b) BACKSTOP — rare STW on a DEDICATED domain.  A genuine
       [Gc.compact]+[malloc_trim] is kept ONLY as a high-RSS-ceiling backstop
       ([Backstop] module below: a persistent worker Domain modelled on
       Sync.Validation_worker).  It fires only when the heap exceeds a HIGH
       ceiling (default 5000 MB, far above where the slice holds it) or on a
       coarse 300 s wall-clock floor.  The Lwt side parks on
       [Lwt_preemptive.detach] (in cli.ml) so the main domain releases the
       runtime lock — the (often dominant) [malloc_trim] half then runs with
       RPC interleaving.  HONEST OCaml semantics: spawning the compact on
       another domain does NOT make it non-STW (the compaction still freezes
       all domains for its duration); what it buys is (1) the trim half is
       off-path, and (2) because (a) keeps the heap small, the backstop
       compaction operates on a small heap and is sub-second + rare — so even
       its residual STW is negligible to RPC p99.

   (c) GC TUNING (bin/main.ml): space_overhead lowered 200→120 so the
       incremental collector keeps the heap tighter; the large minor heap is
       kept (transients die young), max_overhead stays high (the runtime's own
       auto-compaction stays off — the [Backstop] domain owns all compaction).

   The IBD 16-block [compact_now] cadence (sync.ml) is UNCHANGED: IBD has no
   RPC-latency SLA, and submit_lwt already parks the Lwt thread during block
   validation, so a per-16-block STW there is fine.

   CALL CHOICE: the steady-state primitive is [Gc.major_slice] (non-STW); only
   the rare backstop uses [Gc.compact] (+ malloc_trim) because on OCaml 5.3
   only compaction unmaps empty major-heap pools back to the OS.

   GATING: the hot-path checks are deliberately UNGATED by sync_state.  The
   at-tip listeners are FullySynced-gated upstream, so steady-state behavior
   is unchanged; the catch-up drain / re-IBD states gain a backstop. *)

(* Single shared stamp: every BACKSTOP trigger (threshold timer ceiling,
   time-floor, IBD cadence) resets every other backstop trigger's floor.  The
   steady-state slice path (a) is cheap + non-STW and shares NO floor. *)
let last_compact_time = ref 0.0

(* Backstop wall-clock time-floor: run a genuine compaction at least this
   often even under the ceiling, so idle off-heap/arena memory is still
   returned.  Coarse (300 s, was 120 s) because the steady-state slice now
   does the routine reclamation; the backstop should fire rarely.  Used by
   cli.ml's status loop via [backstop_if_overdue]. *)
let compact_interval_s = 300.0

(* Backstop heap-size CEILING: request a genuine compaction once the live
   OCaml heap exceeds this many bytes.  This is a HIGH ceiling (default
   5000 MB, was the 1500 MB production threshold) far above where the
   steady-state [Gc.major_slice] normally holds the heap — so the backstop is
   a true high-water guard, not the routine path.  Read via
   Gc.quick_stat().heap_words (cheap — no heap walk).  Overridable via
   CAMLCOIN_COMPACT_THRESHOLD_MB (repurposed: this env now drives the
   BACKSTOP CEILING, not a steady-state threshold — production should RAISE it
   to ~4000-6000; the regtest gc-load gate can still lower it to exercise the
   backstop far below the harness cgroup cap); invalid / non-positive values
   fall back to the default. *)
let default_compact_threshold_mb = 5000.0

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

(* Anti-thrash floor: never run a BACKSTOP compaction more often than this
   even when over the ceiling, so a sustained allocation burst does not spin
   Gc.compact (still stop-the-world) back-to-back.  The steady-state slice
   path needs no floor (it is cheap + non-STW). *)
let compact_min_interval_s = 8.0

(* Minimum heap size below which the wall-clock TIME-FLOOR backstop is
   skipped (2026-07-01, un-pin attempt #3 post-mortem).  The soak logs showed
   the 300 s time-floor firing a genuine STW Gc.compact with the heap already
   at its post-compact baseline (591 MB -> 591 MB, compact_stall ~0.6 s) —
   i.e. a guaranteed ~0.6 s RPC stall every 5 minutes that reclaimed NOTHING.
   With the steady-state slice + 60 s malloc_trim already returning transient
   memory, a compaction is only worth its STW when the heap has actually
   grown.  Gate the time-floor on heap ≥ this floor; the heap-size CEILING
   backstop is unaffected (it is the emergency guard).  Overridable via
   CAMLCOIN_BACKSTOP_MIN_HEAP_MB (the regtest gc-load gate can lower it to
   exercise the time-floor path); invalid / non-positive values fall back to
   the default. *)
let default_backstop_min_heap_mb = 1024.0

let backstop_min_heap_bytes =
  let mb =
    match Sys.getenv_opt "CAMLCOIN_BACKSTOP_MIN_HEAP_MB" with
    | Some s ->
      (match float_of_string_opt (String.trim s) with
       | Some v when v > 0.0 -> v
       | _ -> default_backstop_min_heap_mb)
    | None -> default_backstop_min_heap_mb
  in
  mb *. 1024.0 *. 1024.0

(* Fast-tick cadence for cli.ml's dedicated GC timer.  Drives the
   steady-state [Gc.major_slice] every tick (keeping the collector caught up)
   and checks the backstop ceiling.  5 s keeps the slice cadence frequent
   enough that the heap never drifts far from the slice target between ticks. *)
let gc_check_interval_s = 5.0

(* Size of the incremental major-GC slice driven per steady-state call.  0
   lets the OCaml runtime size the slice to the current allocation rate (the
   recommended default for "keep the collector caught up" without a STW
   barrier).  Overridable via CAMLCOIN_MAJOR_SLICE for soak tuning; <0 falls
   back to 0. *)
let major_slice_budget =
  match Sys.getenv_opt "CAMLCOIN_MAJOR_SLICE" with
  | Some s ->
    (match int_of_string_opt (String.trim s) with
     | Some v when v >= 0 -> v
     | _ -> 0)
  | None -> 0

(* Coarse cadence for the off-RPC-path [malloc_trim] that accompanies the
   steady-state slice.  The slice (a) reclaims the OCaml heap but does NOT
   unmap glibc arenas; a periodic trim returns transient arena memory to the
   OS WITHOUT a STW pause (rocksdb_stubs.c releases the runtime lock during
   malloc_trim).  60 s keeps RSS from drifting up between rare backstops
   without the cost of trimming on every 5 s tick. *)
let slice_trim_interval_s = 60.0
let last_slice_trim_time = ref 0.0

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

(* ── (a) STEADY STATE: non-STW incremental reclamation ──────────────────────
   Drive the major collector forward by one bounded slice.  [Gc.major_slice]
   does NOT impose a stop-the-world barrier (unlike Gc.compact / Gc.full_major)
   so the RPC callback — another mutator on the same domain — interleaves
   between slices.  A coarse periodic malloc_trim returns transient glibc-arena
   memory to the OS off the RPC path (rocksdb_stubs.c releases the runtime
   lock during the trim).  Cheap enough to ride every tick / hot-path exit. *)
let maybe_keep_up ~reason:_ =
  ignore (Gc.major_slice major_slice_budget);
  let now = Unix.gettimeofday () in
  if now -. !last_slice_trim_time >= slice_trim_interval_s then begin
    last_slice_trim_time := now;
    (* Off-RPC-path: rocksdb_stubs.c wraps malloc_trim(0) in
       caml_release/acquire_runtime_system so other OS threads — incl. the RPC
       thread — run during the trim; do not remove that. *)
    Rocksdb.malloc_trim ()
  end

(* ── BACKSTOP worker domain (template: Sync.Validation_worker) ──────────────
   A tiny persistent worker Domain whose only job is the rare STW
   [Gc.compact (); Rocksdb.malloc_trim ()].  Plain Mutex+Condition channel —
   the Lwt side (cli.ml) parks on [Lwt_preemptive.detach run_blocking] so the
   main domain releases the runtime lock while the worker runs (the trim half
   then interleaves with RPC; the Gc.compact half is still a global STW
   barrier but is small — heap kept tight by (a) — and rare).  Single-slot,
   coalescing: a request while one is pending/running is a no-op, so a burst
   of ceiling breaches collapses to one compaction. *)
module Backstop = struct
  type req_chan = {
    rmutex : Mutex.t;
    rcond : Condition.t;
    mutable pending : bool;       (* a compaction is requested but not started *)
    mutable running : bool;       (* worker is mid-compaction *)
    mutable shutdown : bool;
    (* tagged reason of the in-flight request, for the [gc] log line *)
    mutable reason : string;
  }

  let chan = {
    rmutex = Mutex.create ();
    rcond = Condition.create ();
    pending = false;
    running = false;
    shutdown = false;
    reason = "";
  }

  let domain : unit Domain.t option ref = ref None

  (* The actual reclamation step (runs ON the worker domain).  [reason] tags
     the [gc] log line so soak logs separate the rare backstop from the
     steady-state slice. *)
  let do_compact ~reason =
    last_compact_time := Unix.gettimeofday ();
    let st_before = Gc.quick_stat () in
    let t0 = Unix.gettimeofday () in
    Gc.compact ();
    let t1 = Unix.gettimeofday () in
    Rocksdb.malloc_trim ();
    let t2 = Unix.gettimeofday () in
    let st_after = Gc.quick_stat () in
    Logs.info (fun m ->
      m "[gc] backstop compaction (%s): heap=%d words (%.0fMB->%.0fMB) \
         rss=%.0fMB compact_stall=%.3fs trim=%.3fs total=%.3fs"
        reason
        st_after.Gc.heap_words
        (mb_of_words st_before.Gc.heap_words)
        (mb_of_words st_after.Gc.heap_words)
        (rss_mb ())
        (t1 -. t0)
        (t2 -. t1)
        (t2 -. t0))

  let worker_loop () =
    let rec loop () =
      Mutex.lock chan.rmutex;
      while (not chan.pending) && (not chan.shutdown) do
        Condition.wait chan.rcond chan.rmutex
      done;
      if chan.shutdown then (Mutex.unlock chan.rmutex)
      else begin
        let reason = chan.reason in
        chan.pending <- false;
        chan.running <- true;
        Mutex.unlock chan.rmutex;
        (try do_compact ~reason
         with exn ->
           Logs.warn (fun m ->
             m "[gc] backstop compaction raised: %s"
               (Printexc.to_string exn)));
        Mutex.lock chan.rmutex;
        chan.running <- false;
        (* wake any Lwt-side waiter parked on run_blocking *)
        Condition.broadcast chan.rcond;
        Mutex.unlock chan.rmutex;
        loop ()
      end
    in
    loop ()

  (* Lazily spawn the worker domain on first use so test / non-node code paths
     that link the library but never compact do not spawn an extra domain. *)
  let ensure_started () =
    match !domain with
    | Some _ -> ()
    | None ->
      Mutex.lock chan.rmutex;
      (match !domain with
       | Some _ -> Mutex.unlock chan.rmutex
       | None ->
         chan.shutdown <- false;
         domain := Some (Domain.spawn worker_loop);
         Mutex.unlock chan.rmutex)

  (* Enqueue a compaction request (non-blocking, coalescing).  Returns
     immediately; the worker domain performs the STW compaction.  Use
     [run_blocking] from the Lwt side to park while it completes. *)
  let request ~reason =
    ensure_started ();
    Mutex.lock chan.rmutex;
    if (not chan.pending) && (not chan.running) then begin
      chan.pending <- true;
      chan.reason <- reason;
      Condition.broadcast chan.rcond
    end;
    Mutex.unlock chan.rmutex

  (* Blocking variant for the Lwt side: enqueue (if not already in flight) and
     wait until the worker finishes the current compaction.  MUST be invoked
     via [Lwt_preemptive.detach] so the Lwt scheduler parks (releasing the
     runtime lock) — that is what lets the malloc_trim half interleave with the
     RPC callback on the main domain. *)
  let run_blocking ~reason =
    ensure_started ();
    Mutex.lock chan.rmutex;
    if (not chan.pending) && (not chan.running) then begin
      chan.pending <- true;
      chan.reason <- reason;
      Condition.broadcast chan.rcond
    end;
    (* wait until neither pending nor running, i.e. the compaction is done *)
    while chan.pending || chan.running do
      Condition.wait chan.rcond chan.rmutex
    done;
    Mutex.unlock chan.rmutex

  let shutdown () =
    match !domain with
    | None -> ()
    | Some d ->
      Mutex.lock chan.rmutex;
      chan.shutdown <- true;
      Condition.broadcast chan.rcond;
      Mutex.unlock chan.rmutex;
      Domain.join d;
      domain := None
end

(* Unconditional STW compaction step on the CALLER's thread/domain.  Retained
   for the IBD 16-block cadence (sync.ml:5112), which has no RPC-latency SLA
   and where submit_lwt already parks the Lwt thread between blocks — a
   per-16-block STW there is fine and keeps IBD reclamation simple.  At-tip /
   hot-path callers MUST NOT use this (it STW-stalls the RPC mutator); they use
   [maybe_keep_up] (slice) + the [Backstop] domain instead. *)
let compact_now ~reason =
  Backstop.do_compact ~reason

(* ── BACKSTOP triggers ──────────────────────────────────────────────────────
   Request a genuine compaction iff the major heap is over the HIGH ceiling
   AND the anti-thrash floor has elapsed.  O(1) when it does not fire.  The
   request is enqueued to the [Backstop] domain (non-blocking); call once per
   tick / batch, never per-input.  Returns true iff a request was enqueued
   (so the Lwt caller can choose to park on run_blocking instead). *)
let backstop_due ~reason:_ =
  float_of_int (Gc.quick_stat ()).Gc.heap_words *. 8.0
  >= compact_heap_threshold_bytes
  && Unix.gettimeofday () -. !last_compact_time >= compact_min_interval_s

(* Fire-and-forget ceiling backstop (non-Lwt callers / hot path). *)
let maybe_backstop ~reason =
  if backstop_due ~reason then Backstop.request ~reason

(* Backstop wall-clock time-floor: request a compaction when
   [compact_interval_s] has elapsed since the last backstop AND the heap has
   actually grown past [backstop_min_heap_bytes].  (2026-07-01: no longer
   unconditional — an idle-heap time-floor compaction is a pure ~0.6 s STW
   RPC stall that reclaims nothing; transient arena memory is already
   returned by the 60 s slice-path malloc_trim.) *)
let backstop_overdue ~reason:_ =
  Unix.gettimeofday () -. !last_compact_time >= compact_interval_s
  && float_of_int (Gc.quick_stat ()).Gc.heap_words *. 8.0
     >= backstop_min_heap_bytes

let backstop_if_overdue ~reason =
  if backstop_overdue ~reason then Backstop.request ~reason

(* ── Back-compat shims ──────────────────────────────────────────────────────
   The pre-2026-06-24 names [maybe_compact] / [compact_if_overdue] are kept so
   any caller not yet migrated still compiles; they now route to the NON-STW
   steady-state slice ([maybe_keep_up]) rather than a STW compaction.  New code
   should call [maybe_keep_up] / [backstop_*] directly. *)
let maybe_compact ~reason = maybe_keep_up ~reason
let compact_if_overdue ~reason = backstop_if_overdue ~reason
