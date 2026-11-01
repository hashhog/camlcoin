(* Poll_engine: the poll(2) Lwt engine and Poll_engine.run_main.

   Lwt's select engine raises EINVAL for an fd >= FD_SETSIZE (1024) and
   that ends Lwt_main.run.  These cases put a pipe at fd 1500 and wait on
   it through Lwt. *)

open Camlcoin

let () = Poll_engine.install ()

(* A pipe whose read end is dup2'd to [target]. *)
let high_pipe target =
  let r, w = Unix.pipe ~cloexec:true () in
  let hi = (Obj.magic target : Unix.file_descr) in
  Unix.dup2 ~cloexec:true r hi;
  Unix.close r;
  hi, w

let test_read_above_fd_setsize () =
  let hi, w = high_pipe 1500 in
  let lfd = Lwt_unix.of_unix_file_descr ~blocking:false hi in
  let got = Lwt_main.run (
    let open Lwt.Syntax in
    Lwt.async (fun () ->
      let* () = Lwt_unix.sleep 0.05 in
      ignore (Unix.write_substring w "x" 0 1);
      Lwt.return_unit);
    let buf = Bytes.create 1 in
    let* n = Lwt_unix.read lfd buf 0 1 in
    Lwt.return (n, Bytes.get buf 0)) in
  Alcotest.(check (pair int char)) "read on fd 1500 via Lwt" (1, 'x') got;
  Lwt_main.run (Lwt_unix.close lfd);
  Unix.close w

let test_eof_and_timer () =
  (* hangup reads as readable (EOF), and timers still fire. *)
  let hi, w = high_pipe 1501 in
  Unix.close w;
  let lfd = Lwt_unix.of_unix_file_descr ~blocking:false hi in
  let n = Lwt_main.run (
    let open Lwt.Syntax in
    let* () = Lwt_unix.sleep 0.02 in
    Lwt_unix.read lfd (Bytes.create 1) 0 1) in
  Alcotest.(check int) "EOF on fd 1501" 0 n;
  Lwt_main.run (Lwt_unix.close lfd)

let test_writable () =
  let r, w = Unix.pipe ~cloexec:true () in
  let hi = (Obj.magic 1502 : Unix.file_descr) in
  Unix.dup2 ~cloexec:true w hi;
  Unix.close w;
  let lfd = Lwt_unix.of_unix_file_descr ~blocking:false hi in
  let n = Lwt_main.run (Lwt_unix.write_string lfd "ab" 0 2) in
  Alcotest.(check int) "write on fd 1502" 2 n;
  Lwt_main.run (Lwt_unix.close lfd);
  Unix.close r

(* run_main: an exception from the event loop (not from the promise) is
   logged and the loop continues; the promise's own failure still raises. *)
let test_run_main_survives_loop_exn () =
  let fired = ref 0 in
  let hook = Lwt_main.Enter_iter_hooks.add_first (fun () ->
      if !fired < 3 then begin incr fired; failwith "loop boom" end) in
  let v = Fun.protect
      ~finally:(fun () -> Lwt_main.Enter_iter_hooks.remove hook)
      (fun () ->
         Poll_engine.run_main
           (let open Lwt.Syntax in
            let* () = Lwt_unix.sleep 0.05 in
            Lwt.return 42)) in
  Alcotest.(check int) "promise result after 3 loop errors" 42 v;
  Alcotest.(check int) "hook raised 3 times" 3 !fired

let test_run_main_raises_promise_failure () =
  Alcotest.check_raises "promise failure propagates" (Failure "node failed")
    (fun () ->
       Poll_engine.run_main
         (let open Lwt.Syntax in
          let* () = Lwt_unix.sleep 0.01 in
          Lwt.fail_with "node failed"))

let test_run_main_gives_up () =
  let hook = Lwt_main.Enter_iter_hooks.add_first
      (fun () -> failwith "always") in
  Fun.protect ~finally:(fun () -> Lwt_main.Enter_iter_hooks.remove hook)
    (fun () ->
    Alcotest.check_raises "persistent loop error is raised"
      (Failure "always")
      (fun () ->
         Poll_engine.run_main ~max_errors:5 ~window:10.0
           (fst (Lwt.wait ()))))

let () =
  Alcotest.run "poll_engine" [
    "engine", [
      Alcotest.test_case "read on fd 1500" `Quick test_read_above_fd_setsize;
      Alcotest.test_case "EOF on fd 1501" `Quick test_eof_and_timer;
      Alcotest.test_case "write on fd 1502" `Quick test_writable;
    ];
    "run_main", [
      Alcotest.test_case "survives loop exception" `Quick
        test_run_main_survives_loop_exn;
      Alcotest.test_case "promise failure raises" `Quick
        test_run_main_raises_promise_failure;
      Alcotest.test_case "persistent loop error raises" `Quick
        test_run_main_gives_up;
    ];
  ]
