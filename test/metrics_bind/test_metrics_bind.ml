(* The Prometheus metrics listener must bind loopback by default, close idle
   connections, and cap how many it holds open.

   It used to be created with [`TCP (`Port p)] and no Conduit context, which
   Conduit binds to INADDR_ANY: the unauthenticated endpoint answered on
   every interface (mainnet listened on 0.0.0.0:9357; the security audit
   reached it over the host's LAN address on regtest).  It also had no
   timeout and no connection cap, so each idle connection kept one fd open
   for ever.  This is the same bug 75482af fixed for the RPC listener.

   Each case boots bin/main.exe on regtest.  The bound address is read from
   /proc/net/tcp (the kernel's view of the LISTEN socket) and cross-checked
   by connecting through 127.0.0.2: all of 127/8 reaches lo on Linux, so a
   socket bound to 127.0.0.1 refuses it while a wildcard socket accepts it. *)

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

(* [`Closed] if the peer closed [s] (EOF or reset) within [secs], [`Open] if
   nothing arrived.  The client never sends a byte, so data cannot arrive. *)
let closed_within s secs =
  match Unix.select [s] [] [] secs with
  | [], _, _ -> `Open
  | _ ->
    (match Unix.read s (Bytes.create 1) 0 1 with
     | 0 -> `Closed
     | _ -> `Open
     | exception Unix.Unix_error _ -> `Closed)

let http ?(meth = "GET") ?(headers = []) ?(body = "") port path =
  let s = connect "127.0.0.1" port in
  Fun.protect ~finally:(fun () -> try Unix.close s with _ -> ()) (fun () ->
    let req = Printf.sprintf "%s %s HTTP/1.1\r\nHost: 127.0.0.1\r\n\
                              Connection: close\r\nContent-Length: %d\r\n%s\r\n%s"
        meth path (String.length body)
        (String.concat "" (List.map (fun (k, v) -> k ^ ": " ^ v ^ "\r\n")
                             headers)) body in
    ignore (Unix.write_substring s req 0 (String.length req));
    let buf = Buffer.create 512 and b = Bytes.create 4096 in
    let rec rd () =
      match Unix.select [s] [] [] 10.0 with
      | [], _, _ -> ()
      | _ ->
        let n = try Unix.read s b 0 4096 with Unix.Unix_error _ -> 0 in
        if n > 0 then (Buffer.add_subbytes buf b 0 n; rd ()) in
    rd (); Buffer.contents buf)

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

(* Boot main.exe with [extra] args and --metricsport=<free port>, wait until
   the metrics port is in LISTEN, run [f metrics_port], then stop the node
   over RPC (cookie auth). *)
let with_node ~label extra f =
  Test_tmp.with_dir ~label ~mkdir:true (fun datadir ->
    let rpcport = free_port () and p2pport = free_port ()
    and mport = free_port () in
    let log = Filename.concat datadir "node.log" in
    let fd = Unix.openfile log [Unix.O_WRONLY; Unix.O_CREAT; Unix.O_TRUNC]
        0o600 in
    let args = Array.of_list ([ main_exe; "--network=regtest";
      "--datadir=" ^ datadir; "--rpchost=127.0.0.1";
      Printf.sprintf "--rpcport=%d" rpcport;
      Printf.sprintf "--port=%d" p2pport;
      Printf.sprintf "--metricsport=%d" mport; "--nodnsseed";
      "--connect=127.0.0.1:1" ] @ extra) in
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
          failwith ("metrics listener did not come up; log:\n" ^ read_file log)
        else if listen_addrs_on mport = [] ||
                not (Sys.file_exists (Filename.concat datadir ".cookie"))
        then (Unix.sleepf 0.2; ready (n - 1)) in
      ready 600;
      f mport))

let test_default_is_loopback () =
  let addrs, lo1, lo2, resp = with_node ~label:"metrics_bind_default" []
      (fun port ->
         (listen_addrs_on port, can_connect "127.0.0.1" port,
          can_connect "127.0.0.2" port, http port "/metrics")) in
  Alcotest.(check (list string))
    "default metrics LISTEN address" ["127.0.0.1"] addrs;
  Alcotest.(check bool) "reachable on 127.0.0.1" true lo1;
  Alcotest.(check bool) "refused on 127.0.0.2" false lo2;
  Alcotest.(check bool) "GET /metrics still answers" true
    (contains ~sub:"bitcoin_blocks_total 0" resp)

let test_metricsbind_wildcard () =
  let addrs, lo2 = with_node ~label:"metrics_bind_any"
      [ "--metricsbind=0.0.0.0" ]
      (fun port -> (listen_addrs_on port, can_connect "127.0.0.2" port)) in
  Alcotest.(check (list string))
    "--metricsbind 0.0.0.0 LISTEN address" ["0.0.0.0"] addrs;
  Alcotest.(check bool) "reachable on 127.0.0.2" true lo2

(* Eight idle connections fill the cap; the ninth is closed at once.  Once
   they go, a normal scrape is served again. *)
let test_connection_cap () =
  let ninth, after = with_node ~label:"metrics_bind_cap" [] (fun port ->
      let held = List.init 8 (fun _ -> connect "127.0.0.1" port) in
      Unix.sleepf 0.5;
      let s = connect "127.0.0.1" port in
      let ninth = closed_within s 3.0 in
      List.iter Unix.close (s :: held);
      Unix.sleepf 0.5;
      (ninth, http port "/metrics")) in
  Alcotest.(check bool) "9th idle connection closed by the server" true
    (ninth = `Closed);
  Alcotest.(check bool) "scrape served after the idle ones close" true
    (contains ~sub:"bitcoin_blocks_total" after)

(* An idle connection is closed by the server's timeout (10 s). *)
let test_idle_timeout () =
  let first = with_node ~label:"metrics_bind_timeout" [] (fun port ->
      let s = connect "127.0.0.1" port in
      Fun.protect ~finally:(fun () -> Unix.close s)
        (fun () -> closed_within s 15.0)) in
  Alcotest.(check bool) "idle connection closed within 15 s" true
    (first = `Closed)

let () =
  Alcotest.run "metrics_bind"
    [ ( "metrics_bind",
        [ Alcotest.test_case "default metrics listener binds 127.0.0.1 only"
            `Quick test_default_is_loopback;
          Alcotest.test_case "--metricsbind 0.0.0.0 binds the wildcard"
            `Quick test_metricsbind_wildcard;
          Alcotest.test_case "connection cap closes the 9th idle connection"
            `Quick test_connection_cap;
          Alcotest.test_case "idle connection is closed by the timeout"
            `Slow test_idle_timeout ] ) ]
