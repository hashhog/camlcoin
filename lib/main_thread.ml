(* The Lwt main thread is camlcoin's cs_main.

   Every connect path (catch-up IBD, process_new_block, the stored-block
   drain, ActivateBestChain / reorganize, invalidate / reconsider /
   precious), every mempool mutation (P2P ATMP, removeForBlock) and every
   Lwt primitive runs on the thread that executes [Lwt_main.run].  Code on
   that thread is atomic with respect to all of them between Lwt yields,
   and the connect paths re-check the tip after each yield (a validation
   await).  That atomicity is the chain lock.

   RPC handlers run on Lwt_preemptive systhreads (34cd72c), which the
   runtime preempts at any allocation once the 50 ms tick fires.  A handler
   that reads-then-writes chain, coin-cache, mempool, wallet or peer state
   must therefore hand that work to the main thread: [run f] executes [f]
   there and returns its result (or re-raises its exception).

   LOCK ORDER (outermost first):
     1. Rpc.rpc_lwt_mutex       (Lwt_mutex; serialises RPC handlers; taken on
                                 the Lwt side BEFORE a pool thread is used)
     2. the main thread         ([run] / being on it)
     3. OptimizedUtxoSet.lock   (Mutex; leaf: short critical sections, never
                                 calls [run], never blocks on 1 or 2)
   Rules: never call [run] while holding 3; never block the main thread on
   a Mutex a pool thread can hold while it waits for [run] (deadlock); never
   do network I/O inside [run] -- schedule it with Lwt.async (the send then
   runs on the loop after [run]'s job returns). *)

let id = Thread.id (Thread.self ())

let is_main () = Thread.id (Thread.self ()) = id

let run (f : unit -> 'a) : 'a =
  if is_main () then f ()
  else Lwt_preemptive.run_in_main (fun () -> Lwt.return (f ()))
