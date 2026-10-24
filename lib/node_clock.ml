(* Node clock with Bitcoin Core's mocktime semantics.

   Core's GetTime() returns the mock time when one is set (setmocktime, a
   -regtest-only RPC) and the system time otherwise (src/util/time.cpp).
   Mocktime 0 means "use the system time".  Only the mempool's policy clock
   (rolling min-fee decay, entry time, orphan and 14-day expiry) reads this
   clock.  Block-validation time checks (header time-too-new) deliberately keep
   the system clock: they are consensus code and are not changed here.  *)

let mock_time : float ref = ref 0.0

let set_mock_time (t : int64) : unit = mock_time := Int64.to_float t

let now () : float =
  if !mock_time > 0.0 then !mock_time else Unix.gettimeofday ()
