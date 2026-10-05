(* Gate 6: a system fault (OOM, I/O error, dead worker, secp context
   failure, timeout) leads to retry or halt -- NEVER to a reject or an
   accept.

   Bitcoin Core: FatalError -> AbortNode (validation.cpp, node/abort.cpp).
   A failed ConnectBlock caused by a system error never reaches
   InvalidBlockFound, the block is never marked BLOCK_FAILED_VALID, the
   delivering peer is never punished, and the node shuts down with
   EXIT_FAILURE.  The coins cache is discarded, not flushed.

   [System_fault] is the typed channel: it is raised by the script layer
   when a check could not be COMPLETED (as opposed to completed and
   failed), and by the chainstate write path when a durable write failed
   twice.  Every consensus caller lets it propagate; none converts it into
   a verdict.

   The latch is process-wide.  Once set:
   - every connect path (P2P, gap-fill drain, IBD, reorg, submitblock)
     refuses to start,
   - submitblock answers RPC_VERIFY_ERROR (-25), never a BIP-22 token,
   - the mempool refuses with a non-verdict reason (no recent-rejects),
   - graceful shutdown SKIPS the chainstate / UTXO flush (memory may be
     ahead of or torn against disk -- Core discards the cache),
   - the process exits 1 so the supervisor restarts it. *)

exception System_fault of string

let () =
  Printexc.register_printer (function
    | System_fault m -> Some ("System_fault: " ^ m)
    | _ -> None)

let latched : bool Atomic.t = Atomic.make false
let reason_ref : string option Atomic.t = Atomic.make None

let is_latched () = Atomic.get latched
let reason () = match Atomic.get reason_ref with Some r -> r | None -> ""

(* Set by the daemon (cli.ml) to start a graceful shutdown.  Must be safe
   to call from any domain/thread (it is invoked from validation worker
   domains).  Default: no-op (tests, tools). *)
let shutdown_request : (unit -> unit) ref = ref (fun () -> ())

(* Prefix of every non-verdict error string produced for a system fault.
   RPC uses it to answer -25; the mempool uses it to keep the tx out of any
   reject cache. *)
let rpc_prefix = "system-fault: "

(* AbortNode.  Idempotent; the first reason wins. *)
let abort_node (msg : string) : unit =
  if Atomic.compare_and_set latched false true then begin
    Atomic.set reason_ref (Some msg);
    Logs.err (fun m ->
      m "FATAL (AbortNode): %s -- connecting stopped, nothing marked \
         invalid, no peer punished; shutting down WITHOUT flushing the \
         chainstate (exit 1)" msg);
    (try !shutdown_request () with _ -> ())
  end

(* Raise if latched: the guard at the top of every connect entry point. *)
let check () : unit =
  if is_latched () then
    raise (System_fault ("node halted after a fatal error: " ^ reason ()))

(* Exceptions that must never be swallowed into a retry: asynchronous
   control flow.  (OCaml has no async kill exceptions like GHC, but
   Stack_overflow / Out_of_memory are resource faults and are handled as
   such by [run_write].) *)

(* Durable write, write-before-forget: [f] performs the write; callers
   mutate memory only after this returns.  One retry (a transient EIO /
   EAGAIN), then AbortNode + raise. *)
let run_write ~(what : string) (f : unit -> 'a) : 'a =
  check ();
  match f () with
  | v -> v
  | exception (System_fault _ as e) -> raise e
  | exception e1 ->
    Logs.warn (fun m ->
      m "%s failed (%s) -- retrying once" what (Printexc.to_string e1));
    (match f () with
     | v -> v
     | exception (System_fault _ as e) -> raise e
     | exception e2 ->
       let msg = Printf.sprintf "%s failed twice: %s" what
           (Printexc.to_string e2) in
       abort_node msg;
       raise (System_fault msg))

(* ---- Test hooks (inert in production: [None] unless a test sets them) ---- *)

(* Called at the start of every chainstate commit
   ([Storage.ChainDB.apply_block_atomic]); a test makes it raise to model
   ENOSPC / EIO. *)
let write_fault_hook : (string -> unit) option ref = ref None

let fire_write_hook (what : string) : unit =
  match !write_fault_hook with None -> () | Some f -> f what

(* Tests only: clear the latch between cases. *)
let reset_for_tests () =
  Atomic.set latched false;
  Atomic.set reason_ref None
