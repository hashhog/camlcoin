(* Idle inbound sockets cannot kill the node.

   Two defects let ~1,000 silent TCP connections end the process:

   - accept_inbound compared only finished handshakes (pm.peers) against
     max_inbound, so every socket still handshaking was accepted and held
     for up to 60 s.  Core counts every accepted inbound socket against
     m_max_inbound (net.cpp AcceptConnection / CreateNodeFromAcceptedSocket).
   - Lwt ran its select(2) engine.  Once any fd the loop waits on reaches
     FD_SETSIZE (1024), Unix.select raises EINVAL out of Lwt_main.run and
     the process exits.  Core uses poll/epoll (util/sock.cpp).

   The cases boot bin/main.exe on regtest and hold idle sockets the way the
   audit's repro_idle_fds.py does.  Everything here is plain blocking Unix:
   the test itself holds over 1,024 fds, so it must not use Lwt's select
   engine either. *)

(* A peer that closes mid-write must not SIGPIPE the test. *)
let () = Sys.set_signal Sys.sigpipe Sys.Signal_ignore

let free_port () =
  let s = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Unix.bind s (Unix.ADDR_INET (Unix.inet_addr_loopback, 0));
  let p = match Unix.getsockname s with
    | Unix.ADDR_INET (_, p) -> p | _ -> assert false in
  Unix.close s; p

let main_exe =
  let p = Filename.concat (Sys.getcwd ()) "../../bin/main.exe" in
  if Sys.file_exists p then p else failwith ("missing " ^ p)

let read_file p =
  try
    let ic = open_in_bin p in
    Fun.protect ~finally:(fun () -> close_in ic)
      (fun () -> really_input_string ic (in_channel_length ic))
  with _ -> ""

let tail n s =
  let len = String.length s in
  if len <= n then s else String.sub s (len - n) n

let connect port =
  let s = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  (try Unix.connect s (Unix.ADDR_INET (Unix.inet_addr_loopback, port))
   with e -> Unix.close s; raise e);
  s

(* POST one JSON-RPC call over a fresh blocking socket; returns the HTTP
   status, or 0 when the node does not answer. *)
let rpc ~port ~cookie meth =
  match connect port with
  | exception _ -> 0
  | s ->
    Fun.protect ~finally:(fun () -> try Unix.close s with _ -> ()) (fun () ->
      try
        Unix.setsockopt_float s Unix.SO_RCVTIMEO 15.0;
        let body = Printf.sprintf
            {|{"jsonrpc":"1.0","id":1,"method":"%s","params":[]}|} meth in
        let req = Printf.sprintf
            "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Basic %s\r\n\
             Content-Type: text/plain\r\nContent-Length: %d\r\n\
             Connection: close\r\n\r\n%s"
            (Base64.encode_string cookie) (String.length body) body in
        ignore (Unix.write_substring s req 0 (String.length req));
        let buf = Bytes.create 64 in
        let n = Unix.read s buf 0 64 in
        let line = Bytes.sub_string buf 0 n in
        match String.split_on_char ' ' line with
        | _ :: code :: _ -> (try int_of_string code with _ -> 0)
        | _ -> 0
      with _ -> 0)

let alive pid =
  match Unix.waitpid [Unix.WNOHANG] pid with
  | 0, _ -> true
  | _ -> false
  | exception Unix.Unix_error (Unix.ECHILD, _, _) -> false

let node_fds pid =
  try Array.length (Sys.readdir (Printf.sprintf "/proc/%d/fd" pid))
  with _ -> -1

(* Did the node close this socket?  Non-blocking peek: EOF or reset means
   the node closed it; EAGAIN means it is still held open. *)
let closed_by_node s =
  Unix.set_nonblock s;
  let b = Bytes.create 1 in
  match Unix.recv s b 0 1 [Unix.MSG_PEEK] with
  | 0 -> true
  | _ -> false
  | exception Unix.Unix_error ((Unix.EAGAIN | Unix.EWOULDBLOCK), _, _) -> false
  | exception Unix.Unix_error (_, _, _) -> true

(* Open [n] idle sockets; a failed connect stops the run (the node may
   already be gone).  Raises if this process cannot hold [n] fds. *)
let open_idle port n =
  let rec go acc i =
    if i = n then List.rev acc
    else match connect port with
      | s -> go (s :: acc) (i + 1)
      | exception Unix.Unix_error ((Unix.EMFILE | Unix.ENFILE), _, _) ->
        List.iter (fun s -> try Unix.close s with _ -> ()) acc;
        Alcotest.failf
          "test process cannot hold %d sockets: raise RLIMIT_NOFILE \
           (ulimit -n) above %d" n (2 * n + 100)
      | exception _ -> List.rev acc in
  go [] 0

let close_all = List.iter (fun s -> try Unix.close s with _ -> ())

type node = { pid : int; rpcport : int; p2pport : int; cookie : string;
              log : string }

(* Boot main.exe on regtest, wait until RPC answers and the P2P port
   accepts, run [f node], then stop the node and reap it. *)
let with_node ~label extra f =
  Test_tmp.with_dir ~label ~mkdir:true (fun datadir ->
    let rpcport = free_port () and p2pport = free_port () in
    let log = Filename.concat datadir "node.log" in
    let fd = Unix.openfile log [Unix.O_WRONLY; Unix.O_CREAT; Unix.O_TRUNC]
        0o600 in
    let args = Array.of_list ([ main_exe; "--network=regtest";
      "--datadir=" ^ datadir; "--rpchost=127.0.0.1";
      Printf.sprintf "--rpcport=%d" rpcport;
      Printf.sprintf "--port=%d" p2pport; "--metricsport=0"; "--nodnsseed";
      "--connect=127.0.0.1:1" ] @ extra) in
    let pid = Unix.create_process main_exe args Unix.stdin fd fd in
    Unix.close fd;
    let cookie_path = Filename.concat datadir ".cookie" in
    let reap () =
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
        if n = 0 || not (alive pid) then
          Alcotest.failf "node did not come up; log tail:\n%s"
            (tail 3000 (read_file log))
        else if not (Sys.file_exists cookie_path) then
          (Unix.sleepf 0.2; ready (n - 1))
        else
          let cookie = read_file cookie_path in
          let p2p_up = match connect p2pport with
            | s -> Unix.close s; true
            | exception _ -> false in
          if p2p_up && rpc ~port:rpcport ~cookie "getblockcount" = 200
          then cookie
          else (Unix.sleepf 0.2; ready (n - 1)) in
      let cookie = ready 600 in
      let node = { pid; rpcport; p2pport; cookie; log } in
      Fun.protect
        ~finally:(fun () ->
          if alive pid then ignore (rpc ~port:rpcport ~cookie "stop"))
        (fun () -> f node)))

let check_alive node what =
  if not (alive node.pid) then
    Alcotest.failf "node exited after %s; log tail:\n%s" what
      (tail 3000 (read_file node.log));
  Alcotest.(check int) (what ^ ": RPC still answers") 200
    (rpc ~port:node.rpcport ~cookie:node.cookie "getblockcount")

(* Poll until [pred ()] holds or [secs] pass. *)
let wait_for secs pred =
  let deadline = Unix.gettimeofday () +. secs in
  let rec go () =
    if pred () then true
    else if Unix.gettimeofday () > deadline then false
    else (Unix.sleepf 0.2; go ()) in
  go ()

let count_closed = List.fold_left
    (fun n s -> if closed_by_node s then n + 1 else n) 0

(* max_inbound counts sockets that are still handshaking, so idle sockets
   beyond --maxinbound are closed at accept instead of being held for the
   60 s handshake timeout. *)
let test_extras_refused_at_accept () =
  with_node ~label:"fdcap_extras" [ "--maxinbound=8" ] (fun node ->
    let socks = open_idle node.p2pport 40 in
    Fun.protect ~finally:(fun () -> close_all socks) (fun () ->
      Alcotest.(check int) "opened 40 idle sockets" 40 (List.length socks);
      let refused = ref 0 in
      ignore (wait_for 3.0 (fun () ->
        refused := count_closed socks; !refused >= 32));
      Alcotest.(check bool)
        (Printf.sprintf "at least 32 of 40 idle sockets refused at accept \
                         with --maxinbound=8 (refused %d)" !refused)
        true (!refused >= 32);
      check_alive node "40 idle P2P sockets"))

(* Handshaking slots are released when the handshake ends: idle sockets
   that the client closes stop counting, and the next ones are accepted. *)
let test_slots_released () =
  with_node ~label:"fdcap_release" [ "--maxinbound=8" ] (fun node ->
    let first = open_idle node.p2pport 8 in
    Unix.sleepf 0.5;
    close_all first;
    (* the node's v1/v2 peek sees EOF and drops each pending handshake *)
    let accepted = ref 0 in
    let ok = wait_for 10.0 (fun () ->
      let socks = open_idle node.p2pport 8 in
      Unix.sleepf 1.0;
      accepted := 8 - count_closed socks;
      close_all socks;
      !accepted = 8) in
    Alcotest.(check bool)
      (Printf.sprintf "8 new idle sockets held after the first 8 closed \
                       (held %d)" !accepted)
      true ok;
    check_alive node "released handshake slots")

(* The audit's attack: 1,100 silent P2P connections. *)
let test_1100_idle_p2p () =
  with_node ~label:"fdcap_p2p1100" [] (fun node ->
    let socks = open_idle node.p2pport 1100 in
    Fun.protect ~finally:(fun () -> close_all socks) (fun () ->
      Unix.sleepf 3.0;
      check_alive node "1,100 idle P2P sockets";
      let fds = node_fds node.pid in
      Alcotest.(check bool)
        (Printf.sprintf "node holds < 400 fds under the flood (holds %d)" fds)
        true (fds >= 0 && fds < 400)))

(* An fd above FD_SETSIZE in the event loop must not kill the process.
   The RPC listener has no connection cap, so 1,100 idle RPC sockets put
   the node's fds past 1,024; the getblockcount after them is served on an
   fd > 1,024. *)
let test_1100_idle_rpc () =
  with_node ~label:"fdcap_rpc1100" [] (fun node ->
    let socks = open_idle node.rpcport 1100 in
    Fun.protect ~finally:(fun () -> close_all socks) (fun () ->
      Unix.sleepf 2.0;
      let fds = node_fds node.pid in
      check_alive node "1,100 idle RPC sockets";
      Alcotest.(check bool)
        (Printf.sprintf "node fds passed 1,024 (%d)" fds) true (fds > 1024)))

let () =
  Alcotest.run "inbound_fd_cap" [
    "p2p", [
      Alcotest.test_case "extras beyond maxinbound refused at accept" `Slow
        test_extras_refused_at_accept;
      Alcotest.test_case "handshake slots released" `Slow test_slots_released;
      Alcotest.test_case "1100 idle p2p sockets: node survives" `Slow
        test_1100_idle_p2p;
    ];
    "engine", [
      Alcotest.test_case "fd above 1024: node survives" `Slow
        test_1100_idle_rpc;
    ];
  ]
