(* Logs from several domains through camlcoin's installed reporter must
   not corrupt the shared Format state.

   Mainnet restart.log (both runs oom-killed at 48G, 2026-09-21 and
   2026-09-25) carries interleaved half-lines and
   "[gc] backstop compaction raised: Stdlib.Queue.Empty": the Backstop
   domain's Logs.info raced the Lwt main domain inside one
   Logs_fmt/Format.std_formatter.  Cli.setup_logging now installs a
   reentrant Logs.set_reporter_mutex.

   Check: 4 domains x 20k reports.  Zero exceptions out of Logs, every
   output line intact and the line count exact.  Negative control:
   drop [Report_lock.install ()] from setup_logging -> tens of thousands
   of Queue.Empty and a short, garbled line count.  Also: a message whose
   closure logs (nested report on the same thread) must not deadlock.

   Command:
     dune exec --no-buffer test/test_log_reporter_domains.exe
*)

open Camlcoin

let per_domain = 20_000
let n_domains = 4

let () =
  let tmp = Filename.temp_file "camlcoin-lograce" ".log" in
  let saved = Unix.dup Unix.stdout in
  let fd = Unix.openfile tmp [Unix.O_WRONLY; Unix.O_TRUNC] 0o644 in
  Unix.dup2 fd Unix.stdout;
  Unix.dup2 fd Unix.stderr |> ignore;
  Cli.setup_logging false ();
  let exns = Atomic.make 0 in
  let first = Atomic.make "" in
  let work id () =
    for i = 1 to per_domain do
      try
        Logs.info (fun m ->
          m "LOGRACE d=%d i=%d [gc] backstop compaction (%s): heap=%d words"
            id i "hot-path:atmp" (i * 7))
      with e ->
        Atomic.incr exns;
        ignore (Atomic.compare_and_set first "" (Printexc.to_string e))
    done
  in
  let ds = List.init (n_domains - 1) (fun k -> Domain.spawn (work (k + 1))) in
  work 0 ();
  List.iter Domain.join ds;
  (* nested report on one thread: the inner log runs while the outer
     message closure holds the lock *)
  Logs.info (fun m ->
    Logs.info (fun m2 -> m2 "LOGRACE-NESTED inner");
    m "LOGRACE-NESTED outer");
  Format.pp_print_flush Format.std_formatter ();
  Format.pp_print_flush Format.err_formatter ();
  flush stdout; flush stderr;
  Unix.dup2 saved Unix.stdout;
  Unix.dup2 saved Unix.stderr;
  let ic = open_in tmp in
  let good = ref 0 and bad = ref 0 and nested = ref 0 in
  let re_ok line =
    (* one intact report per line: exactly one tag, well-formed tail *)
    let count sub =
      let n = ref 0 and i = ref 0 in
      let ls = String.length sub in
      while !i + ls <= String.length line do
        if String.sub line !i ls = sub then (incr n; i := !i + ls) else incr i
      done; !n
    in
    count "LOGRACE d=" = 1
    && String.length line > 7
    && String.sub line (String.length line - 6) 6 = " words"
  in
  (try
     while true do
       let l = input_line ic in
       if String.length l >= 14 && (let rec has i = i + 14 <= String.length l
                                      && (String.sub l i 14 = "LOGRACE-NESTED" || has (i+1)) in has 0)
       then incr nested
       else if re_ok l then incr good
       else if l <> "" then incr bad
     done
   with End_of_file -> close_in ic);
  Sys.remove tmp;
  let total = per_domain * n_domains in
  Printf.printf
    "log-race: exns=%d first=%s good=%d/%d bad=%d nested=%d\n%!"
    (Atomic.get exns) (Atomic.get first) !good total !bad !nested;
  let ok =
    Atomic.get exns = 0 && !good = total && !bad = 0 && !nested = 2
  in
  if not ok then (print_endline "FAIL"; exit 1) else print_endline "PASS"
