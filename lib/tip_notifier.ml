(* Tip-change notification primitive for the wait-family RPCs.

   Bitcoin Core registers a [WaitTipChanged] condition variable (kernel
   [Notifications] / [KernelNotifications::blockTip]) signalled on every
   active-chain tip update.  The [waitfornewblock] / [waitforblock] /
   [waitforblockheight] RPCs (bitcoin-core/src/rpc/blockchain.cpp:290-470)
   block on it with a deadline, re-checking their predicate (new tip / hash
   match / height >=) after each wake and returning the current tip
   [{hash, height}] on match OR timeout.

   [Tip_notifier] is the camlcoin analogue, mirroring the proven ouroboros
   pilot ([ouroboros/src/ouroboros/tip_notifier.py]).  It is deliberately
   tiny and dependency-free so the RPC server (lib/rpc.ml) and every
   tip-advance chokepoint (lib/sync.ml connect + reorg, lib/mining.ml
   submitblock/generate accept, lib/block_import.ml) can reach it without
   creating a module dependency cycle.

   Concurrency model.  camlcoin's Cohttp RPC server runs on a single Lwt
   event loop (one domain).  The wake mechanism is therefore an
   [Lwt_condition.t]; [notify] uses [broadcast] so every coroutine currently
   in [wait_for_change] is released.

   Lost-wakeup safety.  A monotonically increasing [generation] counter lets
   a waiter detect a tip change that happened *between* its predicate check
   and its await (the classic lost-wakeup race).  The wait loop in rpc.ml:
     1. snapshots [generation ()],
     2. re-reads the AUTHORITATIVE database tip and checks its predicate,
     3. calls [wait_for_change ~last_generation:<the snapshot> ~timeout].
   [wait_for_change] returns immediately if the generation has already moved
   past the snapshot (a [notify] raced in after the predicate check but
   before/within the await), so no wakeup is lost.  Under Lwt's cooperative
   single-domain scheduling there is in fact no yield point between the
   snapshot and the [Lwt_condition.wait] registration, but the generation
   fast-path keeps correctness independent of that and robust to coalesced
   notifies (two blocks connected back-to-back before a waiter wakes): the
   waiter re-reads the real tip on every wake and after the timeout, exactly
   like Core. *)

(* Shared singleton.  The notify chokepoints and the RPC waiters all act on
   the one process-wide tip-change source, matching Core's single
   [KernelNotifications]. *)
let cond : unit Lwt_condition.t = Lwt_condition.create ()
let generation_ref : int ref = ref 0

(* Current tip-change generation (bumped on every [notify]). *)
let generation () : int = !generation_ref

(* Signal that the active-chain tip advanced.

   Bumps the generation counter and wakes every coroutine currently in
   [wait_for_change] so each re-evaluates its predicate against the
   authoritative DB tip.  Safe to call from any connect / reorg / accept
   chokepoint on the Lwt event loop.  Best-effort by contract: callers wrap
   it so a notifier fault never stalls block connection. *)
let notify () : unit =
  incr generation_ref;
  Lwt_condition.broadcast cond ()

(* Await the next tip change after [last_generation].

   [last_generation] is the generation the caller snapshotted *before* it
   last checked its predicate.  If the generation has already advanced past
   it (a notify raced in), return [true] immediately without blocking.

   [timeout] is in seconds, or [None] to wait indefinitely.

   Returns [true] if a tip change was observed within the deadline, [false]
   if the wait timed out.  Either way the caller MUST re-evaluate its
   predicate against the authoritative DB tip. *)
let wait_for_change ~(last_generation : int) ~(timeout : float option)
    : bool Lwt.t =
  (* Fast path: a notify already raced in since the caller's snapshot. *)
  if !generation_ref <> last_generation then Lwt.return_true
  else
    match timeout with
    | None ->
      (* Wait indefinitely for the next tip change. *)
      Lwt.bind (Lwt_condition.wait cond) (fun () -> Lwt.return_true)
    | Some t ->
      if t <= 0.0 then Lwt.return_false
      else
        (* Race the condition wake against a sleep deadline.  Whichever
           fires first wins; [Lwt.pick] cancels the loser. *)
        Lwt.pick [
          Lwt.bind (Lwt_condition.wait cond) (fun () -> Lwt.return_true);
          Lwt.bind (Lwt_unix.sleep t) (fun () -> Lwt.return_false);
        ]
