(* Connection limits for the JSON-RPC and REST listeners.

   Both used to call [Cohttp_lwt_unix.Server.create ~ctx ~mode server] with
   no [?timeout] (cohttp-lwt-unix 6.2.1 has no default).  A client that
   connected and sent nothing, or stopped half-way through a request line,
   held its socket and its fd for ever.  The request head was bounded only
   by cohttp's 16 KiB input buffer.

   Core (httpserver.cpp InitHTTPServer):
     evhttp_set_timeout(http, -rpcservertimeout)   default 30 s
     evhttp_set_max_headers_size(http, MAX_HEADERS_SIZE)   8192 bytes

   Core has no cap on HTTP connections: its 503 "Work queue depth exceeded"
   counts queued requests (-rpcworkqueue), not sockets, so idle connections
   never lock the operator out; the timeout is what bounds them.  There is
   no connection cap here either.  test/inbound_fd_cap holds 1,100 idle RPC
   sockets and needs getblockcount to answer, as it would on Core.

   libevent's timeout is a read/write timeout, not a lifetime: it runs while
   the server waits for request bytes (including an idle keep-alive
   connection) or for the socket to take response bytes, and not while a
   handler runs.  A dumptxoutset or a waitfornewblock that takes minutes
   still answers.  Conduit's [serve ~timeout], which metrics_server.ml uses,
   is a lifetime ([Lwt.pick] against one sleep for the whole connection), so
   it would cut those calls off.  This module therefore wraps each
   connection's channels and closes the connection when a read or a write
   has been in flight for [timeout] seconds with no progress.  cohttp reads
   only while it waits for or parses a request (cohttp-lwt server.ml
   handle_client: read, handle, write, loop), so a handler that is still
   working never trips it.

   The head cap is the size of cohttp's request buffer: cohttp parses the
   request line and headers only out of that buffer and, when it is full
   without a complete head, treats the connection as EOF and closes it. *)

let default_timeout_s = 30.0      (* Core DEFAULT_HTTP_SERVER_TIMEOUT *)
let max_headers_size = 8192       (* Core MAX_HEADERS_SIZE *)

(* One watchdog per connection instead of one timer per read: the poll
   engine keeps a stopped sleep in its timer heap until the sleep's own
   deadline, so a [Lwt_unix.with_timeout] around every read would leave one
   30 s entry behind per read on a busy keep-alive connection.

   [busy] counts reads and writes in flight on the raw channels, [last] is
   when one last started from idle or finished.  The watchdog sleeps while
   nothing is in flight (a handler is running), and otherwise shuts the
   socket down once [timeout] seconds pass with no progress. *)
type watch = {
  mutable busy : int;
  mutable last : float;
  mutable finished : bool;
  wake : unit Lwt_condition.t;
}

let new_watch () =
  { busy = 0; last = Unix.gettimeofday (); finished = false;
    wake = Lwt_condition.create () }

let watched w f =
  w.busy <- w.busy + 1;
  if w.busy = 1 then begin
    (* [busy] is raised first: the woken watchdog may run right here. *)
    w.last <- Unix.gettimeofday ();
    Lwt_condition.broadcast w.wake ()
  end;
  Lwt.finalize f (fun () ->
    w.busy <- w.busy - 1;
    w.last <- Unix.gettimeofday ();
    Lwt.return_unit)

let rec watchdog ~timeout ~abort w =
  if w.finished then Lwt.return_unit
  else if w.busy = 0 then
    Lwt.bind (Lwt_condition.wait w.wake) (fun () ->
      watchdog ~timeout ~abort w)
  else
    let left = w.last +. timeout -. Unix.gettimeofday () in
    if left <= 0. then abort ()
    else
      Lwt.bind (Lwt_unix.sleep left) (fun () -> watchdog ~timeout ~abort w)

(* shutdown(2) on the raw socket wakes the stalled read (EOF) or write
   (EPIPE) at once, plain or TLS, and the fd is then closed by Conduit's
   normal close.  Lwt_io.abort is not enough: on a TLS channel it runs
   Tls_lwt's close, which first writes close_notify onto the same stalled
   socket and so blocks for ever. *)
let shutdown_flow (flow : Conduit_lwt_unix.flow) ic oc () =
  match flow with
  | Conduit_lwt_unix.TCP { fd; _ } | Conduit_lwt_unix.Domain_socket { fd; _ } ->
    (try Lwt_unix.shutdown fd Unix.SHUTDOWN_ALL
     with Unix.Unix_error _ -> ());
    Lwt.return_unit
  | _ ->
    let quiet ch = Lwt.catch (fun () -> Lwt_io.abort ch)
        (fun _ -> Lwt.return_unit) in
    Lwt.bind (quiet oc) (fun () -> quiet ic)

let timed_input w (ic : Lwt_io.input_channel) =
  Lwt_io.make ~mode:Lwt_io.input (fun buf off len ->
    watched w (fun () -> Lwt_io.read_into_bigstring ic buf off len))

(* Each write is pushed through to the socket before it counts as done, so
   the timeout covers the socket taking the bytes, not just a buffer copy. *)
let timed_output w (oc : Lwt_io.output_channel) =
  Lwt_io.make ~mode:Lwt_io.output (fun buf off len ->
    watched w (fun () ->
      Lwt.bind (Lwt_io.write_from_exactly_bigstring oc buf off len)
        (fun () -> Lwt.bind (Lwt_io.flush oc) (fun () -> Lwt.return len))))

(* libevent answers a head over evhttp_set_max_headers_size with
   HTTP_ENTITYTOOLARGE and closes (evhttp_connection_incoming_fail). *)
let head_too_large_response =
  "HTTP/1.1 413 Request Entity Too Large\r\n\
   Content-Type: text/plain\r\n\
   Content-Length: 25\r\n\
   Connection: close\r\n\r\n\
   Request header too large\n"

(* cohttp returns from [callback] as if at EOF when its request buffer fills
   up without a complete request head (Request.read refills a full buffer
   with length 0).  A full buffer when [callback] returns is that case: a
   request that was parsed has had its head dropped from the buffer and its
   body drained. *)
let head_overflowed (ic : Cohttp_lwt_unix.Private.Input_channel.t) =
  Cohttp_lwt.Private.Bytebuffer.length
    ic.Cohttp_lwt_unix.Private.Input_channel.buf >= max_headers_size

(* A client that went away, or a connection the watchdog shut down, is
   routine.  Anything else is logged the way cohttp's default on_exn does. *)
let log_exn = function
  | Out_of_memory -> raise Out_of_memory
  | (Unix.Unix_error _ | Lwt_io.Channel_closed _) as exn ->
    Logs.debug (fun m -> m "HTTP connection: %s" (Printexc.to_string exn))
  | exn ->
    Logs.warn (fun m -> m "HTTP connection: %s" (Printexc.to_string exn))

(* Serve [server] on [mode] (bound to [ctx]) with the limits above.  This is
   [Cohttp_lwt_unix.Server.create] (cohttp-lwt-unix 6.x server.ml) with the
   channels wrapped before [Cohttp_lwt_unix.Server.callback]. *)
let serve ?(timeout = default_timeout_s)
    ~(ctx : Cohttp_lwt_unix.Net.ctx) ~(mode : Conduit_lwt_unix.server)
    (server : Cohttp_lwt_unix.Server.t) : unit Lwt.t =
  let handle flow ic oc =
    let w = new_watch () in
    let dog = watchdog ~timeout ~abort:(shutdown_flow flow ic oc) w in
    let tic = timed_input w ic and toc = timed_output w oc in
    let finish () =
      (* The response cohttp wrote last may still sit in [toc]'s buffer;
         Conduit closes the raw channels as soon as this returns. *)
      Lwt.bind
        (Lwt.catch (fun () -> Lwt_io.close toc) (fun _ -> Lwt.return_unit))
        (fun () ->
           w.finished <- true;
           Lwt.cancel dog;
           Lwt.return_unit)
    in
    let cic = Cohttp_lwt_unix.Private.Input_channel.create
        ~buf_len:max_headers_size tic in
    Lwt.finalize
      (fun () ->
         Lwt.catch
           (fun () ->
              Lwt.bind (Cohttp_lwt_unix.Server.callback server flow cic toc)
                (fun () ->
                   if head_overflowed cic then
                     Lwt_io.write toc head_too_large_response
                   else Lwt.return_unit))
           (fun exn -> log_exn exn; Lwt.return_unit))
      finish
  in
  Conduit_lwt_unix.serve ~on_exn:log_exn ~ctx:ctx.Cohttp_lwt_unix.Net.ctx
    ~mode handle
