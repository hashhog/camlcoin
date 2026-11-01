(* A poll(2)-based Lwt engine.

   Lwt here is built without libev (Lwt_config._HAVE_LIBEV = false), so the
   default engine is select(2).  select cannot take an fd >= FD_SETSIZE
   (1024): Unix.select raises EINVAL, Lwt_engine.select#iter catches only
   EINTR and EBADF, and the exception leaves Lwt_main.run, which ends the
   process.  Any socket that lands above fd 1023 (P2P, RPC, REST, metrics)
   did that.  Core uses poll/epoll (util/sock.cpp) and has no such limit.

   [install] swaps the engine; call it after daemonize and before
   Lwt_main.run. *)

external poll_stub :
  Unix.file_descr array -> int array -> int array -> float -> int
  = "camlcoin_poll"

class poll_engine = object
  inherit Lwt_engine.poll_based

  method private poll fds timeout =
    let n = List.length fds in
    let fd_arr = Array.make n Unix.stdin in
    let ev_arr = Array.make n 0 in
    List.iteri (fun i (fd, r, w) ->
      fd_arr.(i) <- fd;
      ev_arr.(i) <- (if r then 1 else 0) lor (if w then 2 else 0)) fds;
    let re_arr = Array.make n 0 in
    let ready = poll_stub fd_arr ev_arr re_arr timeout in
    if ready = 0 then []
    else begin
      let out = ref [] in
      for i = n - 1 downto 0 do
        let re = re_arr.(i) in
        if re <> 0 then
          out := (fd_arr.(i), re land 1 <> 0, re land 2 <> 0) :: !out
      done;
      !out
    end
end

let install () = Lwt_engine.set (new poll_engine)

(* Lwt_main.run [p], surviving an exception raised by the event loop itself
   (the engine's wait, an iteration hook) rather than by [p].  Such an
   exception leaves [p] pending; it is logged and the loop is entered
   again.  An exception from [p] (a rejected promise) is raised as before.
   More than [max_errors] loop errors within [window] seconds means the
   fault is persistent, so the last one is raised rather than spinning. *)
let run_main ?(max_errors = 50) ?(window = 10.0) (p : 'a Lwt.t) : 'a =
  let recent = Queue.create () in
  let rec go () =
    match Lwt_main.run p with
    | v -> v
    | exception exn when Lwt.state p = Lwt.Sleep ->
      let bt = Printexc.get_backtrace () in
      let now = Unix.gettimeofday () in
      Queue.push now recent;
      while Queue.length recent > 0 && now -. Queue.peek recent > window do
        ignore (Queue.pop recent)
      done;
      Printf.eprintf "[EVENT-LOOP-EXN] event loop raised: %s\n%s%!"
        (Printexc.to_string exn) bt;
      Logs.err (fun m ->
        m "event loop raised %s; continuing" (Printexc.to_string exn));
      if Queue.length recent > max_errors then begin
        Logs.err (fun m ->
          m "event loop raised %d times in %.0f s; giving up"
            (Queue.length recent) window);
        raise exn
      end;
      go ()
  in
  go ()
