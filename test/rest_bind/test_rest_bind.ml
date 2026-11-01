(* The REST listener on its own --restport must bind --restbind, must not
   read an oversized request body, and must serve POST /payjoin only when
   --restpayjoin asks for it (security audit H2).

   It used to be created with [`TCP (`Port p)] and no Conduit context, which
   Conduit binds to INADDR_ANY: --restbind 127.0.0.1 was only a log line.
   POST /payjoin, unauthenticated, read the whole body with Body.to_string
   before any check.  Core caps HTTP bodies at MAX_SIZE (32 MiB) and has no
   payjoin endpoint.

   Each case boots bin/main.exe on regtest.  The bound address is read from
   /proc/net/tcp and cross-checked by connecting through 127.0.0.2: all of
   127/8 reaches lo on Linux, so a socket bound to 127.0.0.1 refuses it while
   a wildcard socket accepts it. *)

let () = Sys.set_signal Sys.sigpipe Sys.Signal_ignore

let max_size = 0x02000000

let free_port () =
  let s = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Unix.bind s (Unix.ADDR_INET (Unix.inet_addr_loopback, 0));
  let p = match Unix.getsockname s with
    | Unix.ADDR_INET (_, p) -> p | _ -> assert false in
  Unix.close s; p

(* /proc/net/tcp local_address is "AABBCCDD:PPPP": the IPv4 address as a
   host-order (little-endian on x86) hex word, the port in hex.  State 0A is
   LISTEN.  Returns the dotted-quad of every LISTEN socket on [port]. *)
let listen_addrs_on port =
  let ic = open_in "/proc/net/tcp" in
  let rec loop acc =
    match input_line ic with
    | exception End_of_file -> close_in ic; List.rev acc
    | line ->
      let fields =
        List.filter (fun s -> s <> "") (String.split_on_char ' ' line) in
      (match fields with
       | _sl :: local :: _rem :: st :: _ when st = "0A" ->
         (match String.split_on_char ':' local with
          | [a; p] when int_of_string ("0x" ^ p) = port ->
            let w = int_of_string ("0x" ^ a) in
            let ip = Printf.sprintf "%d.%d.%d.%d"
                (w land 0xff) ((w lsr 8) land 0xff)
                ((w lsr 16) land 0xff) ((w lsr 24) land 0xff) in
            loop (ip :: acc)
          | _ -> loop acc)
       | _ -> loop acc)
  in
  ignore (input_line ic);  (* header *)
  loop []

let connect ip port =
  let s = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  try Unix.connect s (Unix.ADDR_INET (Unix.inet_addr_of_string ip, port)); s
  with e -> Unix.close s; raise e

let can_connect ip port =
  match connect ip port with
  | s -> Unix.close s; true
  | exception Unix.Unix_error _ -> false

let write_all s str =
  let rec go off =
    if off < String.length str then
      go (off + Unix.write_substring s str off (String.length str - off)) in
  go 0

(* Everything the server sends until it closes or is silent for [secs]. *)
let read_reply ?(secs = 10.0) s =
  let buf = Buffer.create 512 and b = Bytes.create 4096 in
  let rec rd () =
    match Unix.select [s] [] [] secs with
    | [], _, _ -> ()
    | _ ->
      let n = try Unix.read s b 0 4096 with Unix.Unix_error _ -> 0 in
      if n > 0 then (Buffer.add_subbytes buf b 0 n; rd ()) in
  rd (); Buffer.contents buf

let request ?(meth = "GET") ?(headers = []) ?(body = "") path =
  Printf.sprintf "%s %s HTTP/1.1\r\nHost: 127.0.0.1\r\n\
                  Connection: close\r\n%s\r\n%s"
    meth path
    (String.concat "" (List.map (fun (k, v) -> k ^ ": " ^ v ^ "\r\n")
                         (headers @ (if meth = "GET" then [] else
                                       [ "Content-Length",
                                         string_of_int (String.length body) ]))))
    body

let http ?meth ?headers ?body port path =
  let s = connect "127.0.0.1" port in
  Fun.protect ~finally:(fun () -> try Unix.close s with _ -> ()) (fun () ->
    write_all s (request ?meth ?headers ?body path);
    read_reply s)

let status_line r =
  match String.index_opt r '\r' with
  | Some i -> String.sub r 0 i
  | None -> r

let contains ~sub s =
  let n = String.length sub in
  let rec go i = i + n <= String.length s
                 && (String.sub s i n = sub || go (i + 1)) in
  go 0

let main_exe =
  let p = Filename.concat (Sys.getcwd ()) "../../bin/main.exe" in
  if Sys.file_exists p then p else failwith ("missing " ^ p)

let read_file p =
  let ic = open_in_bin p in
  Fun.protect ~finally:(fun () -> close_in ic)
    (fun () -> really_input_string ic (in_channel_length ic))

(* Boot main.exe with --rest on a separate --restport plus [extra], wait
   until the REST port is in LISTEN, run [f rest_port], then stop the node
   over RPC (cookie auth). *)
let with_node ~label extra f =
  Test_tmp.with_dir ~label ~mkdir:true (fun datadir ->
    let rpcport = free_port () and p2pport = free_port ()
    and restport = free_port () in
    let log = Filename.concat datadir "node.log" in
    let fd = Unix.openfile log [Unix.O_WRONLY; Unix.O_CREAT; Unix.O_TRUNC]
        0o600 in
    let args = Array.of_list ([ main_exe; "--network=regtest";
      "--datadir=" ^ datadir; "--rpchost=127.0.0.1";
      Printf.sprintf "--rpcport=%d" rpcport;
      Printf.sprintf "--port=%d" p2pport;
      "--metricsport=0"; "--nodnsseed"; "--connect=127.0.0.1:1";
      "--rest"; Printf.sprintf "--restport=%d" restport ] @ extra) in
    let pid = Unix.create_process main_exe args Unix.stdin fd fd in
    Unix.close fd;
    let stop () =
      let cookie = Filename.concat datadir ".cookie" in
      if Sys.file_exists cookie then
        (try ignore (http ~meth:"POST" rpcport "/"
                       ~headers:[ "Authorization",
                                  "Basic " ^ Base64.encode_string
                                    (read_file cookie) ]
                       ~body:{|{"jsonrpc":"1.0","id":1,"method":"stop","params":[]}|})
         with _ -> ()) in
    let reap () =
      stop ();
      let rec wait n =
        match Unix.waitpid [Unix.WNOHANG] pid with
        | 0, _ when n > 0 -> Unix.sleepf 0.1; wait (n - 1)
        | 0, _ ->
          (* our own child, still up after 30 s: force it *)
          (try Unix.kill pid Sys.sigkill with _ -> ());
          ignore (Unix.waitpid [] pid)
        | _ -> ()
        | exception Unix.Unix_error (Unix.ECHILD, _, _) -> () in
      wait 300 in
    Fun.protect ~finally:reap (fun () ->
      let rec ready n =
        let exited = match Unix.waitpid [Unix.WNOHANG] pid with
          | 0, _ -> false | _ -> true
          | exception Unix.Unix_error _ -> true in
        if exited || n = 0 then
          failwith ("REST listener did not come up; log:\n" ^ read_file log)
        else if listen_addrs_on restport = [] ||
                not (Sys.file_exists (Filename.concat datadir ".cookie"))
        then (Unix.sleepf 0.2; ready (n - 1)) in
      ready 600;
      f restport))

let payjoin_path = "/payjoin?v=1"
let pj_headers = [ "Content-Type", "text/plain" ]

let test_restbind_loopback () =
  let addrs, lo1, lo2, resp =
    with_node ~label:"rest_bind_loopback" [ "--restbind=127.0.0.1" ]
      (fun port ->
         (listen_addrs_on port, can_connect "127.0.0.1" port,
          can_connect "127.0.0.2" port, http port "/rest/chaininfo.json")) in
  Alcotest.(check (list string))
    "--restbind 127.0.0.1 LISTEN address" ["127.0.0.1"] addrs;
  Alcotest.(check bool) "reachable on 127.0.0.1" true lo1;
  Alcotest.(check bool) "refused on 127.0.0.2" false lo2;
  Alcotest.(check bool) "GET /rest/chaininfo.json still answers" true
    (contains ~sub:{|"chain":"regtest"|} resp)

(* Control: the bind address does follow the flag, it is not pinned. *)
let test_restbind_wildcard () =
  let addrs, lo2 = with_node ~label:"rest_bind_any" [ "--restbind=0.0.0.0" ]
      (fun port -> (listen_addrs_on port, can_connect "127.0.0.2" port)) in
  Alcotest.(check (list string))
    "--restbind 0.0.0.0 LISTEN address" ["0.0.0.0"] addrs;
  Alcotest.(check bool) "reachable on 127.0.0.2" true lo2

let test_payjoin_off_by_default () =
  let r = with_node ~label:"rest_payjoin_off" [] (fun port ->
      http ~meth:"POST" ~headers:pj_headers ~body:"cHNidP8=" port
        payjoin_path) in
  Alcotest.(check string) "POST /payjoin without --restpayjoin"
    "HTTP/1.1 405 Method Not Allowed" (status_line r);
  Alcotest.(check bool) "no BIP-78 receiver answered" false
    (contains ~sub:"errorCode" r)

(* Only the headers are sent.  A server that waits for (or reads) the
   declared 64 MiB never answers; the cap answers 413 at once. *)
let declared_oversized port =
  let s = connect "127.0.0.1" port in
  Fun.protect ~finally:(fun () -> try Unix.close s with _ -> ()) (fun () ->
    write_all s (Printf.sprintf
                   "POST %s HTTP/1.1\r\nHost: 127.0.0.1\r\n\
                    Content-Type: text/plain\r\nContent-Length: %d\r\n\r\n"
                   payjoin_path (2 * max_size));
    let t0 = Unix.gettimeofday () in
    let r = read_reply ~secs:5.0 s in
    (status_line r, Unix.gettimeofday () -. t0))

let test_declared_oversized_default () =
  let st, dt = with_node ~label:"rest_body_cap_default" [] declared_oversized in
  Alcotest.(check string) "64 MiB Content-Length, no body sent"
    "HTTP/1.1 413 Request Entity Too Large" st;
  Alcotest.(check bool) "answered without waiting for the body" true
    (dt < 4.0)

let test_declared_oversized_payjoin () =
  let st, dt = with_node ~label:"rest_body_cap_payjoin" [ "--restpayjoin" ]
      declared_oversized in
  Alcotest.(check string) "--restpayjoin: 64 MiB Content-Length, no body"
    "HTTP/1.1 413 Request Entity Too Large" st;
  Alcotest.(check bool) "answered without waiting for the body" true
    (dt < 4.0)

(* A chunked body declares no length: the cap must count what it reads and
   stop past 32 MiB, not buffer the lot. *)
let test_chunked_oversized_payjoin () =
  let st, alive = with_node ~label:"rest_body_cap_chunked"
      [ "--restpayjoin" ] (fun port ->
      let s = connect "127.0.0.1" port in
      let st = Fun.protect ~finally:(fun () -> try Unix.close s with _ -> ())
          (fun () ->
             write_all s (Printf.sprintf
                            "POST %s HTTP/1.1\r\nHost: 127.0.0.1\r\n\
                             Content-Type: text/plain\r\n\
                             Transfer-Encoding: chunked\r\n\r\n" payjoin_path);
             let chunk = String.make (1 lsl 20) 'A' in
             let frame = Printf.sprintf "%x\r\n%s\r\n"
                 (String.length chunk) chunk in
             (try
                for _ = 1 to (max_size lsr 20) + 1 do write_all s frame done;
                write_all s "0\r\n\r\n"
              with Unix.Unix_error _ -> ());
             status_line (read_reply ~secs:5.0 s)) in
      (st, contains ~sub:{|"chain":"regtest"|}
         (http port "/rest/chaininfo.json"))) in
  Alcotest.(check string) "--restpayjoin: 33 MiB chunked body"
    "HTTP/1.1 413 Request Entity Too Large" st;
  Alcotest.(check bool) "REST still serves afterwards" true alive

(* With the flag the receiver is still reachable for a normal-size body. *)
let test_payjoin_enabled_small_body () =
  let r = with_node ~label:"rest_payjoin_on" [ "--restpayjoin" ] (fun port ->
      http ~meth:"POST" ~headers:pj_headers ~body:"cHNidP8=" port
        payjoin_path) in
  Alcotest.(check bool) "BIP-78 receiver answered" true
    (contains ~sub:"errorCode" r)

let () =
  Alcotest.run "rest_bind"
    [ ( "rest_bind",
        [ Alcotest.test_case "--restbind 127.0.0.1 binds 127.0.0.1 only"
            `Quick test_restbind_loopback;
          Alcotest.test_case "--restbind 0.0.0.0 binds the wildcard"
            `Quick test_restbind_wildcard;
          Alcotest.test_case "POST /payjoin is off by default"
            `Quick test_payjoin_off_by_default;
          Alcotest.test_case "declared oversized body gets 413 unread"
            `Quick test_declared_oversized_default;
          Alcotest.test_case "--restpayjoin declared oversized body gets 413"
            `Quick test_declared_oversized_payjoin;
          Alcotest.test_case "--restpayjoin chunked body over 32 MiB gets 413"
            `Quick test_chunked_oversized_payjoin;
          Alcotest.test_case "--restpayjoin small body reaches the receiver"
            `Quick test_payjoin_enabled_small_body ] ) ]
