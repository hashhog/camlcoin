(* The JSON-RPC and REST listeners must close an idle connection, close a
   connection whose client stopped reading a response, and bound the
   request head.

   Both used to call [Cohttp_lwt_unix.Server.create ~ctx ~mode server] with
   no [?timeout] (cohttp-lwt-unix 6.2.1 has no default): a client that
   connected and sent nothing, or half a request line, kept its socket and
   fd for ever.  Core sets evhttp_set_timeout (-rpcservertimeout, default
   30 s) and evhttp_set_max_headers_size (8192) in httpserver.cpp
   InitHTTPServer.

   The write-stall cases send a batch whose answer is far larger than the
   socket buffers, read the status line, and stop reading.  The server's
   side of that socket must be closed by the timeout: /proc/net/tcp lists a
   socket a process still holds with a non-zero inode.  The TLS case is
   there because Lwt_io.abort on a TLS channel writes close_notify onto the
   stalled socket and blocks; the fix shuts the raw socket down instead.

   Controls:
   - Core's timeout is a read/write timeout, not a connection lifetime, so
     a handler that runs 35 s (a dumptxoutset, a waitfornewblock) still
     answers.
   - keep-alive still serves a second request, and a 7000-byte head still
     answers.
   - Core has no connection cap (its 503 counts queued requests, not
     sockets), so 100 idle connections held open do not stop RPC answering.

   Everything runs in one Lwt_main.run so the 30 s waits overlap: the whole
   file takes about 40 s with the fix and about 50 s without it. *)

open Camlcoin

let () = Sys.set_signal Sys.sigpipe Sys.Signal_ignore

let core_timeout = 30.0
let held_idle = 100

(* /proc/net/tcp row of the server's side of the connection from
   [client_port]: [`Owned] while a process holds the socket (inode <> 0),
   [`Orphan] once it is closed but the kernel still drains it, [`Absent]
   when it is gone. *)
let server_socket_state ~server_port ~client_port =
  let ic = open_in "/proc/net/tcp" in
  let port_of s = match String.split_on_char ':' s with
    | [_; p] -> int_of_string ("0x" ^ p) | _ -> -1 in
  let rec loop () =
    match input_line ic with
    | exception End_of_file -> `Absent
    | line ->
      (match List.filter (fun x -> x <> "") (String.split_on_char ' ' line)
       with
       | _ :: local :: rem :: _ :: _ :: _ :: _ :: _ :: _ :: inode :: _
         when port_of local = server_port && port_of rem = client_port ->
         if inode = "0" then `Orphan else `Owned
       | _ -> loop ()) in
  ignore (input_line ic);
  Fun.protect ~finally:(fun () -> close_in ic) loop

let show_state = function
  | `Owned -> "still held by the server"
  | `Orphan -> "closed by the server (kernel draining)"
  | `Absent -> "gone"

let make_rpc_ctx db_path =
  let db = Storage.ChainDB.create db_path in
  let utxo = Utxo.UtxoSet.create db in
  let mempool =
    Mempool.create ~network:Consensus.regtest ~require_standard:false
      ~verify_scripts:false ~utxo ~current_height:0 ()
  in
  let network = Consensus.regtest in
  let chain_state = Sync.create_chain_state db network in
  let peer_manager = Peer_manager.create network in
  let fee_estimator = Fee_estimation.create () in
  Rpc.create_context ~chain:chain_state ~mempool ~peer_manager ~wallet:None
    ~fee_estimator ~network ()

let pick_free_port () =
  let s = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Unix.bind s (Unix.ADDR_INET (Unix.inet_addr_loopback, 0));
  let port = match Unix.getsockname s with
    | Unix.ADDR_INET (_, p) -> p | _ -> assert false in
  Unix.close s; port

let ( let* ) = Lwt.bind

let connect port =
  let s = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Lwt.catch
    (fun () ->
       let* () = Lwt_unix.connect s
           (Unix.ADDR_INET (Unix.inet_addr_loopback, port)) in
       Lwt.return s)
    (fun e -> let* () = Lwt_unix.close s in Lwt.fail e)

let close s = Lwt.catch (fun () -> Lwt_unix.close s) (fun _ -> Lwt.return_unit)

let send s str =
  let b = Bytes.of_string str in
  let rec go off =
    if off >= Bytes.length b then Lwt.return_unit
    else
      let* n = Lwt_unix.write s b off (Bytes.length b - off) in
      go (off + n) in
  go 0

(* Read until the server closes or [secs] pass: (bytes received, [Some t]
   when it closed after t seconds, [None] when it was still open). *)
let read_until_close ?(secs = 45.0) s =
  let t0 = Unix.gettimeofday () in
  let buf = Buffer.create 512 and b = Bytes.create 4096 in
  let rec loop () =
    let left = secs -. (Unix.gettimeofday () -. t0) in
    if left <= 0. then Lwt.return (Buffer.contents buf, None)
    else
      Lwt.catch
        (fun () ->
           let* n = Lwt_unix.with_timeout left
               (fun () -> Lwt_unix.read s b 0 4096) in
           if n = 0 then
             Lwt.return (Buffer.contents buf,
                         Some (Unix.gettimeofday () -. t0))
           else (Buffer.add_subbytes buf b 0 n; loop ()))
        (function
          | Lwt_unix.Timeout -> Lwt.return (Buffer.contents buf, None)
          | Unix.Unix_error _ ->
            Lwt.return (Buffer.contents buf,
                        Some (Unix.gettimeofday () -. t0))
          | e -> Lwt.fail e) in
  loop ()

(* Whatever arrives within [secs], without waiting for a close. *)
let read_for secs s =
  let t0 = Unix.gettimeofday () in
  let buf = Buffer.create 512 and b = Bytes.create 4096 in
  let rec loop () =
    let left = secs -. (Unix.gettimeofday () -. t0) in
    if left <= 0. then Lwt.return (Buffer.contents buf)
    else
      Lwt.catch
        (fun () ->
           let* n = Lwt_unix.with_timeout left
               (fun () -> Lwt_unix.read s b 0 4096) in
           if n = 0 then Lwt.return (Buffer.contents buf)
           else (Buffer.add_subbytes buf b 0 n; loop ()))
        (fun _ -> Lwt.return (Buffer.contents buf)) in
  loop ()

let status_line r =
  match String.index_opt r '\r' with
  | Some i -> String.sub r 0 i
  | None -> r

let count ~sub s =
  let n = String.length sub in
  let rec go i acc =
    if i + n > String.length s then acc
    else if String.sub s i n = sub then go (i + n) (acc + 1)
    else go (i + 1) acc in
  go 0 0

(* rpc_user "u", rpc_password "p" *)
let auth = "Authorization: Basic dTpw\r\n"

let rpc_request ?(close = true) ?(extra = "") meth =
  let body = Printf.sprintf
      {|{"jsonrpc":"1.0","id":1,"method":"%s","params":[]}|} meth in
  Printf.sprintf "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\n%s%s\
                  Content-Type: application/json\r\n\
                  Content-Length: %d\r\nConnection: %s\r\n\r\n%s"
    auth extra (String.length body) (if close then "close" else "keep-alive")
    body

let rest_request ?(extra = "") path =
  Printf.sprintf "GET %s HTTP/1.1\r\nHost: 127.0.0.1\r\n%s\
                  Connection: close\r\n\r\n" path extra

let pad n = "X-Pad: " ^ String.make n 'a' ^ "\r\n"

(* One full exchange on a fresh connection. *)
let exchange port req =
  let* s = connect port in
  let* () = send s req in
  let* r, _ = read_until_close ~secs:20.0 s in
  let* () = close s in
  Lwt.return r

let idle_probe port =
  let* s = connect port in
  let* r = read_until_close s in
  let* () = close s in
  Lwt.return r

(* Enough "help" calls in one batch that the answer is at least 16 MiB:
   well past tcp_wmem's 4 MiB ceiling plus the client's 4 KiB receive
   buffer, so the server's write has to stall. *)
let stall_target = 16 * 1024 * 1024

let content_length r =
  let lower = String.lowercase_ascii r in
  let key = "content-length: " in
  let n = String.length key in
  let rec find i =
    if i + n > String.length lower then None
    else if String.sub lower i n = key then
      let j = try String.index_from lower (i + n) '\r'
        with Not_found -> String.length lower in
      int_of_string_opt (String.trim (String.sub lower (i + n) (j - i - n)))
    else find (i + 1) in
  find 0

let batch_request ~calls =
  let one i = Printf.sprintf
      {|{"jsonrpc":"1.0","id":%d,"method":"help","params":[]}|} i in
  let body = "[" ^ String.concat "," (List.init calls one) ^ "]" in
  Printf.sprintf "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\n%s\
                  Content-Type: application/json\r\n\
                  Content-Length: %d\r\nConnection: close\r\n\r\n%s"
    auth (String.length body) body

let local_port fd =
  match Lwt_unix.getsockname fd with
  | Unix.ADDR_INET (_, p) -> p | _ -> -1

let small_rcvbuf_socket () =
  let s = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Lwt_unix.setsockopt_int s Unix.SO_RCVBUF 4096;
  s

(* Read until the response head has arrived, then stop reading. *)
let read_head read =
  let buf = Buffer.create 4096 and b = Bytes.create 1024 in
  let rec go () =
    if Buffer.length buf > 64 * 1024 then Lwt.return (Buffer.contents buf)
    else
      let s = Buffer.contents buf in
      let has_end = try ignore (Str.search_forward (Str.regexp_string
                                                       "\r\n\r\n") s 0);
          true with Not_found -> false in
      if has_end then Lwt.return s
      else
        let* n = read b in
        if n = 0 then Lwt.return (Buffer.contents buf)
        else (Buffer.add_subbytes buf b 0 n; go ()) in
  Lwt_unix.with_timeout 20.0 go

(* (client fd to keep open, client port, response head) *)
let stall_tcp port req =
  let s = small_rcvbuf_socket () in
  let* () = Lwt_unix.connect s
      (Unix.ADDR_INET (Unix.inet_addr_loopback, port)) in
  let* () = send s req in
  let* head = read_head (fun b -> Lwt_unix.read s b 0 (Bytes.length b)) in
  Lwt.return ((fun () -> close s), local_port s, head)

let tls_client_config () =
  match Tls.Config.client ~authenticator:(fun ?ip:_ ~host:_ _ -> Ok None) ()
  with
  | Ok c -> c
  | Error (`Msg m) -> failwith ("Tls.Config.client: " ^ m)

let stall_tls port req =
  let s = small_rcvbuf_socket () in
  let* () = Lwt_unix.connect s
      (Unix.ADDR_INET (Unix.inet_addr_loopback, port)) in
  let* t = Tls_lwt.Unix.client_of_fd (tls_client_config ()) s in
  let ic, oc = Tls_lwt.of_t t in
  let* () = Lwt_io.write oc req in
  let* () = Lwt_io.flush oc in
  let* head = read_head (fun b -> Lwt_io.read_into ic b 0 (Bytes.length b)) in
  Lwt.return ((fun () -> close s), local_port s, head)

let self_signed_cert dir =
  let cert = Filename.concat dir "cert.pem"
  and key = Filename.concat dir "key.pem" in
  let rc = Sys.command (Printf.sprintf
      "openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 \
       -subj '/CN=localhost' -keyout %s -out %s 2>/dev/null"
      (Filename.quote key) (Filename.quote cert)) in
  if rc <> 0 then failwith "openssl could not make a test certificate";
  (cert, key)

type results = {
  rpc_idle : string * float option;
  rest_idle : string * float option;
  rpc_partial : string * float option;
  rpc_slow : string * float option;
  rpc_keepalive : string * string;
  rpc_head_over : string;
  rpc_head_under : string;
  rest_head_over : string;
  rest_head_under : string;
  rpc_with_idle_held : string;
  help_len : int;
  stall_tcp : string * [ `Owned | `Orphan | `Absent ];
  stall_tls : string * [ `Owned | `Orphan | `Absent ];
}

let rec wait_listening port n =
  Lwt.catch
    (fun () -> let* s = connect port in close s)
    (fun _ ->
       if n = 0 then Lwt.fail_with "listener did not come up"
       else let* () = Lwt_unix.sleep 0.05 in wait_listening port (n - 1))

let run_probes () =
  Test_tmp.with_dir ~label:"http_idle_timeout" (fun db_path ->
    let ctx = make_rpc_ctx db_path in
    let rpc1 = pick_free_port () and rpc2 = pick_free_port ()
    and rest = pick_free_port () and rpc_tls = pick_free_port () in
    Mirage_crypto_rng_unix.use_default ();
    let cert, key = self_signed_cert db_path in
    let rpc_server port =
      Rpc.start_rpc_server ~ctx ~host:"127.0.0.1" ~port ~rpc_user:"u"
        ~rpc_password:"p" ~cookie_password:None () in
    let servers =
      [ rpc_server rpc1; rpc_server rpc2;
        Rest.start_rest_server ~ctx ~host:"127.0.0.1" ~port:rest ();
        Rpc.start_rpc_server ~ctx ~host:"127.0.0.1" ~port:rpc_tls
          ~rpc_user:"u" ~rpc_password:"p" ~cookie_password:None
          ~tls_cert_path:(Some cert) ~tls_key_path:(Some key) () ] in
    let probes =
      let* () = wait_listening rpc1 100 in
      let* () = wait_listening rpc2 100 in
      let* () = wait_listening rest 100 in
      let* () = wait_listening rpc_tls 100 in
      (* Two requests on one keep-alive connection, 3 s apart. *)
      let* rpc_keepalive =
        let* s = connect rpc1 in
        let* () = send s (rpc_request ~close:false "getblockcount") in
        let* first = read_for 3.0 s in
        let* () = send s (rpc_request "getblockcount") in
        let* second, _ = read_until_close ~secs:20.0 s in
        let* () = close s in
        Lwt.return (first, second) in
      let* rpc_head_over =
        exchange rpc1 (rpc_request ~extra:(pad 9000) "getblockcount") in
      let* rpc_head_under =
        exchange rpc1 (rpc_request ~extra:(pad 7000) "getblockcount") in
      let* rest_head_over =
        exchange rest (rest_request ~extra:(pad 9000) "/rest/chaininfo.json") in
      let* rest_head_under =
        exchange rest (rest_request ~extra:(pad 7000) "/rest/chaininfo.json") in
      (* Hold idle connections on rpc2, then ask it something. *)
      let rec open_n n acc =
        if n = 0 then Lwt.return acc
        else let* s = connect rpc2 in open_n (n - 1) (s :: acc) in
      let* held = open_n held_idle [] in
      let* () = Lwt_unix.sleep 1.0 in
      let* rpc_with_idle_held = exchange rpc2 (rpc_request "getblockcount") in
      let* () = Lwt_list.iter_p close held in
      (* Write stalls: start both before the 30 s cases, after the batch
         has been answered (the head has arrived), so that nothing queues
         behind the slow handler's RPC lock. *)
      let* help = exchange rpc1 (rpc_request "help") in
      let help_len = Option.value ~default:0 (content_length help) in
      let calls = stall_target / max 1 help_len + 1 in
      let req = batch_request ~calls in
      let* close_tcp, tcp_port, tcp_head = stall_tcp rpc2 req in
      let* close_tls, tls_port, tls_head = stall_tls rpc_tls req in
      let stall_t0 = Unix.gettimeofday () in
      (* The 30 s cases run last and side by side: nothing else may queue
         behind the slow handler's RPC lock. *)
      (* Long-running handler: getblockchaininfo goes to the preemptive
         pool, where the test hook sleeps past the timeout. *)
      Rpc.test_sync_sleep_s := core_timeout +. 5.0;
      let slow =
        let* s = connect rpc1 in
        let* () = send s (rpc_request "getblockchaininfo") in
        let* r = read_until_close ~secs:60.0 s in
        let* () = close s in
        Lwt.return r in
      let idle_rpc = idle_probe rpc1 and idle_rest = idle_probe rest in
      let partial =
        let* s = connect rpc1 in
        let* () = send s "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\n" in
        let* r = read_until_close s in
        let* () = close s in
        Lwt.return r in
      let* rpc_idle = idle_rpc in
      let* rest_idle = idle_rest in
      let* rpc_partial = partial in
      let* rpc_slow = slow in
      Rpc.test_sync_sleep_s := 0.0;
      let* () = Lwt_unix.sleep
          (max 0. (stall_t0 +. core_timeout +. 8.0 -. Unix.gettimeofday ())) in
      let stall_tcp = (tcp_head, server_socket_state ~server_port:rpc2
                         ~client_port:tcp_port) in
      let stall_tls = (tls_head, server_socket_state ~server_port:rpc_tls
                         ~client_port:tls_port) in
      let* () = close_tcp () in
      let* () = close_tls () in
      Lwt.return { rpc_idle; rest_idle; rpc_partial; rpc_slow; rpc_keepalive;
                   rpc_head_over; rpc_head_under; rest_head_over;
                   rest_head_under; rpc_with_idle_held; help_len; stall_tcp;
                   stall_tls }
    in
    Lwt_main.run
      (Lwt.pick
         (probes
          :: List.map (fun s ->
              Lwt.bind s (fun () -> Lwt.fail_with "server exited"))
            servers)))

let results = lazy (run_probes ())

let show = function
  | None -> "still open after 45 s"
  | Some t -> Printf.sprintf "closed after %.1f s" t

let check_closed_on_timeout what (_, closed) =
  Printf.printf "%s: %s\n%!" what (show closed);
  let ok = match closed with
    | Some t -> t >= core_timeout -. 5.0 && t <= core_timeout +. 10.0
    | None -> false in
  if not ok then
    Alcotest.failf "%s: want closed after ~%.0f s, got %s" what core_timeout
      (show closed)

let test_rpc_idle () =
  check_closed_on_timeout "idle RPC connection" (Lazy.force results).rpc_idle

let test_rest_idle () =
  check_closed_on_timeout "idle REST connection"
    (Lazy.force results).rest_idle

let test_rpc_partial () =
  check_closed_on_timeout "RPC connection stalled mid-head"
    (Lazy.force results).rpc_partial

let test_rpc_slow_handler () =
  let r, closed = (Lazy.force results).rpc_slow in
  Printf.printf "35 s handler: %s, %s\n%!" (status_line r) (show closed);
  Alcotest.(check string) "35 s handler still answers"
    "HTTP/1.1 200 OK" (status_line r);
  (match closed with
   | Some t when t >= core_timeout +. 4.0 -> ()
   | c -> Alcotest.failf "handler did not run past the timeout: %s" (show c))

let test_rpc_keepalive () =
  let first, second = (Lazy.force results).rpc_keepalive in
  Alcotest.(check int) "first keep-alive response" 1
    (count ~sub:"HTTP/1.1 200 OK" first);
  Alcotest.(check int) "second response on the same connection" 1
    (count ~sub:"HTTP/1.1 200 OK" second)

let test_rpc_head_over () =
  Alcotest.(check string) "RPC 9000-byte header"
    "HTTP/1.1 413 Request Entity Too Large"
    (status_line (Lazy.force results).rpc_head_over)

let test_rpc_head_under () =
  Alcotest.(check string) "RPC 7000-byte header" "HTTP/1.1 200 OK"
    (status_line (Lazy.force results).rpc_head_under)

let test_rest_head_over () =
  Alcotest.(check string) "REST 9000-byte header"
    "HTTP/1.1 413 Request Entity Too Large"
    (status_line (Lazy.force results).rest_head_over)

let test_rest_head_under () =
  Alcotest.(check string) "REST 7000-byte header" "HTTP/1.1 200 OK"
    (status_line (Lazy.force results).rest_head_under)

let check_stall what (head, state) =
  let r = Lazy.force results in
  Printf.printf "%s: help %d bytes, response %s bytes, server socket %s\n%!"
    what r.help_len
    (match content_length head with Some n -> string_of_int n | None -> "?")
    (show_state state);
  Alcotest.(check string) (what ^ ": response started") "HTTP/1.1 200 OK"
    (status_line head);
  (match content_length head with
   | Some n when n >= stall_target -> ()
   | n -> Alcotest.failf "%s: response too small to stall the socket (%s)"
            what (match n with Some n -> string_of_int n | None -> "none"));
  if state = `Owned then
    Alcotest.failf "%s: client stopped reading %.0f s ago, server socket %s"
      what (core_timeout +. 8.0) (show_state state)

let test_rpc_write_stall () =
  check_stall "RPC write stall" (Lazy.force results).stall_tcp

let test_rpc_tls_write_stall () =
  check_stall "RPC TLS write stall" (Lazy.force results).stall_tls

let test_rpc_idle_held () =
  Alcotest.(check string)
    (Printf.sprintf "with %d idle connections held" held_idle)
    "HTTP/1.1 200 OK"
    (status_line (Lazy.force results).rpc_with_idle_held)

let () =
  Alcotest.run "http_idle_timeout"
    [ ( "http_idle_timeout",
        [ Alcotest.test_case "RPC closes an idle connection after 30 s"
            `Quick test_rpc_idle;
          Alcotest.test_case "REST closes an idle connection after 30 s"
            `Quick test_rest_idle;
          Alcotest.test_case "RPC closes a connection stalled mid-head"
            `Quick test_rpc_partial;
          Alcotest.test_case "RPC handler longer than the timeout answers"
            `Quick test_rpc_slow_handler;
          Alcotest.test_case "RPC keep-alive serves a second request"
            `Quick test_rpc_keepalive;
          Alcotest.test_case "RPC request head over 8 KiB gets 413"
            `Quick test_rpc_head_over;
          Alcotest.test_case "RPC request head under 8 KiB answers"
            `Quick test_rpc_head_under;
          Alcotest.test_case "REST request head over 8 KiB gets 413"
            `Quick test_rest_head_over;
          Alcotest.test_case "REST request head under 8 KiB answers"
            `Quick test_rest_head_under;
          Alcotest.test_case "RPC answers with 100 idle connections held"
            `Quick test_rpc_idle_held;
          Alcotest.test_case "RPC closes a connection that stopped reading"
            `Quick test_rpc_write_stall;
          Alcotest.test_case "RPC over TLS closes one that stopped reading"
            `Quick test_rpc_tls_write_stall ] ) ]
