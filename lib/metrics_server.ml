(* Prometheus metrics listener.

   It used to be started inline in Cli with [`TCP (`Port p)] and no Conduit
   context.  Conduit binds that mode to ctx.src and falls back to INADDR_ANY,
   so the unauthenticated endpoint answered on every interface (mainnet
   listened on 0.0.0.0:9357), the same bug 75482af fixed for RPC.  It also had
   no timeout and no connection cap, so each idle connection held one fd for
   ever, on a process that dies at fd 1024 under the select engine.

   Core has no such listener, so there is nothing to match; the endpoint is
   kept but bound to --metricsbind (loopback by default), every connection is
   closed after [timeout_s] seconds, and at most [max_connections] are served
   at once.  Connections over the cap are accepted and closed at once, so they
   cannot queue up in the kernel backlog either.

   [Conduit_lwt_unix.set_max_active] is not used: it is one global counter
   shared with the RPC and REST listeners.  The accept callback is therefore
   ours, and it wraps the raw channel the way Cohttp_lwt_unix.Server.create
   does (cohttp-lwt-unix 6.x server.ml) before handing it to
   Server.callback. *)

let default_host = "127.0.0.1"
let timeout_s = 10
let max_connections = 8

let start ?(timeout = timeout_s) ?(max_conns = max_connections)
    ~host ~port ~(body : unit -> string) () =
  let callback _conn _req _body =
    let headers = Cohttp.Header.init_with
        "Content-Type" "text/plain; version=0.0.4; charset=utf-8" in
    Cohttp_lwt_unix.Server.respond_string ~status:`OK ~headers
      ~body:(body ()) ()
  in
  let server = Cohttp_lwt_unix.Server.make ~callback () in
  let active = ref 0 in
  let handle flow ic oc =
    if !active >= max_conns then Lwt.return_unit
    else begin
      incr active;
      Lwt.finalize
        (fun () ->
           Cohttp_lwt_unix.Server.callback server flow
             (Cohttp_lwt_unix.Private.Input_channel.create ic) oc)
        (fun () -> decr active; Lwt.return_unit)
    end
  in
  Lwt.bind (Conduit_lwt_unix.init ~src:host ()) (fun ctx ->
    Conduit_lwt_unix.serve ~timeout
      ~on_exn:(fun exn ->
        Logs.debug (fun m ->
          m "metrics connection: %s" (Printexc.to_string exn)))
      ~ctx ~mode:(`TCP (`Port port)) handle)
