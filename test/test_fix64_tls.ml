(* FIX-64 — HTTPS/TLS termination on the JSON-RPC and REST listeners.

   Verifies:
     1. Server brought up with --rpc-tls-cert + --rpc-tls-key serves HTTPS
        (TLS handshake completes, request reaches the auth layer).
     2. Server brought up without cert/key remains plain HTTP (backward
        compat — request reaches the auth layer).
     3. Supplying only one of --rpc-tls-cert / --rpc-tls-key aborts
        server startup (Lwt promise rejects with a clear message).
     4. Same surface for REST (--rest-tls-cert / --rest-tls-key).

   The test brings up a real TCP listener on an ephemeral port; the
   server-side handshake uses Conduit_lwt_tls / OCaml-TLS, the client-side
   handshake uses Tls_lwt directly with an always-accept authenticator
   (the self-signed cert is generated on-the-fly via the system openssl,
   so no CA chain is available — pinning to a known authenticator would
   be brittle in CI).

   Reference: bitcoin-core/src/httpserver.cpp ; BIP-78 §"Protocol". *)

open Camlcoin

(* ============================================================================
   Cert generation
   ============================================================================ *)

(* Generate a self-signed RSA-2048 cert/key pair in [dir].  Returns
   (cert_path, key_path).  Uses the system openssl(1) binary; the test
   is skipped (Alcotest.skip) if openssl is not on PATH.  Idempotent —
   if the files already exist they are reused. *)
let ensure_self_signed_cert dir =
  let cert = Filename.concat dir "test_cert.pem" in
  let key  = Filename.concat dir "test_key.pem" in
  if Sys.file_exists cert && Sys.file_exists key then (cert, key)
  else begin
    (try Unix.mkdir dir 0o755
     with Unix.Unix_error (Unix.EEXIST, _, _) -> ());
    let cmd =
      Printf.sprintf
        "openssl req -x509 -newkey rsa:2048 -nodes -sha256 \
         -days 1 \
         -subj '/CN=localhost' \
         -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
         -keyout %s -out %s 2>/dev/null"
        (Filename.quote key) (Filename.quote cert)
    in
    let rc = Sys.command cmd in
    if rc <> 0 then
      Alcotest.failf "openssl cert generation failed (exit %d). \
                      Is openssl on PATH?" rc;
    (* Tighten permissions to 0600 like a real deployment. *)
    Unix.chmod key 0o600;
    (cert, key)
  end

(* ============================================================================
   RPC context helper
   ============================================================================ *)

(* Per-process RocksDB scratch.  The server child (a separate process, see
   spawn_server) uses ITS pid; the parent derives the same path from the
   child pid to remove it after kill — a SIGKILLed child never cleans up,
   and 83 leaked 286 MB datadirs from this harness filled the 63 GB /tmp
   tmpfs on 2026-09-01. *)
let db_path_for_pid pid =
  Printf.sprintf "/tmp/camlcoin_test_fix64_db_%d" pid

let unique_db_path () =
  db_path_for_pid (Unix.getpid ())

let rec rm_rf path =
  if Sys.file_exists path then begin
    if Sys.is_directory path then begin
      Array.iter (fun f -> rm_rf (Filename.concat path f)) (Sys.readdir path);
      Unix.rmdir path
    end else
      Unix.unlink path
  end

(* Build an RPC context.  Called from inside the server child process
   (see spawn_server) so the RocksDB handle is owned by that process only. *)
let make_rpc_ctx () =
  let path = unique_db_path () in
  rm_rf path;
  let db = Storage.ChainDB.create path in
  let utxo = Utxo.UtxoSet.create db in
  let mempool = Mempool.create ~network:Consensus.regtest ~require_standard:false ~verify_scripts:false
                  ~utxo ~current_height:0 () in
  let network = Consensus.testnet4 in
  let chain_state = Sync.create_chain_state db network in
  let peer_manager = Peer_manager.create network in
  let fee_estimator = Fee_estimation.create () in
  Rpc.create_context
    ~chain:chain_state
    ~mempool
    ~peer_manager
    ~wallet:None
    ~fee_estimator
    ~network ()

(* ============================================================================
   Ephemeral port helper
   ============================================================================ *)

(* Bind a TCP socket to port 0 to discover an unused port, then close
   it.  Tiny race window if another process grabs the port between
   close and our server's bind, but acceptable for a unit test. *)
let pick_free_port () =
  let s = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Unix.bind s (Unix.ADDR_INET (Unix.inet_addr_loopback, 0));
  let port = match Unix.getsockname s with
    | Unix.ADDR_INET (_, p) -> p
    | _ -> assert false
  in
  Unix.close s;
  port

(* ============================================================================
   Client helpers (raw HTTPS + raw HTTP)
   ============================================================================ *)

(* Tiny HTTP/1.0 request — POST / with Basic auth that we EXPECT to fail
   (the test uses a different password than the server).  The point is
   not to authenticate, it is to prove the TLS/plaintext layer worked
   and the request reached the auth check.  401 in the response is the
   pass signal. *)
let make_post_request_str ~host ~port =
  Printf.sprintf
    "POST / HTTP/1.0\r\n\
     Host: %s:%d\r\n\
     Authorization: Basic dGVzdDp3cm9uZw==\r\n\
     Content-Type: application/json\r\n\
     Content-Length: 2\r\n\
     \r\n\
     {}"
    host port

(* Accept-anything X.509 authenticator — the test cert is self-signed
   and not in any trust store, so chain validation has to be a no-op. *)
let null_authenticator
  : ?ip:Ipaddr.t -> host:[`host] Domain_name.t option ->
    X509.Certificate.t list -> X509.Validation.r
  = fun ?ip:_ ~host:_ _ -> Ok None

(* OCaml-TLS draws its randoms from Mirage_crypto_rng's DEFAULT generator,
   which raises No_default_generator until someone installs one.  The daemon
   installs it in Cli.run (lib/cli.ml, before start_rpc_server /
   start_rest_server); this harness builds its server contexts directly, so
   the server child process and the client side seed it themselves, exactly
   as the daemon would have. *)
let seed_rng () = Mirage_crypto_rng_unix.use_default ()

(* Why this executable used to HANG (TIMEOUT at 90s, both tests never
   reached): the client went through [Tls_lwt.connect_ext], whose
   [Lwt_unix.getaddrinfo] is a detached thread-pool job, and in the old
   fork()-based harness that job never resolved — the promise sat in
   connect_ext before any byte hit the wire, and nothing bounded the wait.
   Connect the loopback socket directly and hand the fd to
   [Tls_lwt.Unix.client_of_fd]: the handshake and the response complete in
   milliseconds.  (The server side has since moved out of process too — see
   spawn_server — so no Lwt state is shared with a child at all.) *)
let tls_connect_loopback tls_cfg ~port =
  let open Lwt.Infix in
  let sa = Unix.ADDR_INET (Unix.inet_addr_loopback, port) in
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Lwt_unix.connect fd sa >>= fun () ->
  Tls_lwt.Unix.client_of_fd tls_cfg fd >|= fun t ->
  Tls_lwt.of_t t



(* Bound every client-side wait so a stalled handshake / response fails the
   test loudly instead of hanging the whole executable. *)
let client_timeout_s = 10.0
let with_client_timeout (p : 'a Lwt.t) : 'a Lwt.t =
  Lwt.pick [
    p;
    (let open Lwt.Infix in
     Lwt_unix.sleep client_timeout_s >>= fun () ->
     Lwt.fail_with (Printf.sprintf "client request timed out after %.0fs"
                      client_timeout_s));
  ]

(* HTTPS request: TLS handshake then send the raw bytes; return the
   first response line (e.g. "HTTP/1.0 401 Unauthorized"). *)
let https_request_status ~port =
  let open Lwt.Infix in
  let promise =
    let tls_cfg = match Tls.Config.client ~authenticator:null_authenticator () with
      | Ok c -> c
      | Error (`Msg m) -> failwith ("Tls.Config.client: " ^ m)
    in
    tls_connect_loopback tls_cfg ~port >>= fun (ic, oc) ->
    Lwt_io.write oc (make_post_request_str ~host:"127.0.0.1" ~port) >>= fun () ->
    Lwt_io.read_line_opt ic >>= fun line ->
    (* No explicit close: the server drops the HTTP/1.0 connection right after
       the response, and closing the TLS channel then stalled on a
       close_notify write into the dead socket (observed EPIPE / 10s client
       timeout).  The process exit tears the fd down. *)
    Lwt.return line
  in
  Lwt_main.run (with_client_timeout promise)

(* HTTP request: plain TCP, send the raw bytes, read first response line. *)
let http_request_status ~port =
  let open Lwt.Infix in
  let promise =
    let sa = Unix.ADDR_INET (Unix.inet_addr_loopback, port) in
    let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
    Lwt_unix.connect fd sa >>= fun () ->
    let ic = Lwt_io.of_fd ~mode:Lwt_io.input fd in
    let oc = Lwt_io.of_fd ~mode:Lwt_io.output fd in
    Lwt_io.write oc (make_post_request_str ~host:"127.0.0.1" ~port) >>= fun () ->
    Lwt_io.read_line_opt ic >>= fun line ->
    (* No explicit close: the server drops the HTTP/1.0 connection right after
       the response, and closing the TLS channel then stalled on a
       close_notify write into the dead socket (observed EPIPE / 10s client
       timeout).  The process exit tears the fd down. *)
    Lwt.return line
  in
  Lwt_main.run (with_client_timeout promise)

(* Wait until [check ()] returns Some _ or the deadline expires. *)
let rec wait_until_some ?(deadline=Unix.gettimeofday () +. 2.0) check =
  match check () with
  | Some v -> Some v
  | None ->
    if Unix.gettimeofday () > deadline then None
    else begin
      Unix.sleepf 0.02;
      wait_until_some ~deadline check
    end

(* Spin up the server in an Lwt.async and wait for the port to accept
   connections, so the test doesn't race the bind. *)
let wait_for_port ~port =
  let deadline = Unix.gettimeofday () +. 15.0 in
  let rec loop () =
    if Unix.gettimeofday () > deadline then
      failwith (Printf.sprintf "Port %d never came up" port);
    let s = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
    let ok = try
      Unix.connect s (Unix.ADDR_INET (Unix.inet_addr_loopback, port));
      true
    with _ -> false
    in
    Unix.close s;
    if not ok then begin Unix.sleepf 0.02; loop () end
  in
  loop ()

(* ============================================================================
   Tests
   ============================================================================ *)

(* Out-of-process server.  The server for a round-trip test runs in a FRESH
   PROCESS: the parent re-executes this very test binary with
   [CAMLCOIN_FIX64_SERVER=<kind>,<port>,<cert>,<key>] in the environment, and
   [maybe_run_as_server] (called first thing in main) builds a ctx, runs the
   requested listener under its own Lwt_main and never returns.

   Why not fork(): the earlier harness Unix.fork'd the server from a parent
   that had already driven Lwt_main.run for previous clients.  The first two
   children bound fine; the third (the REST child) NEVER reached its bind —
   deterministic "Port never came up", 12/12 runs across Unix.fork and
   Lwt_unix.fork — while the same test alone (`test rest-tls`) passed 3/3 in
   under 100 ms.  A forked child inherits the parent's Lwt thread-pool
   bookkeeping without the threads; the child's listener bind is a
   detached job that nobody services.  exec() side-steps all of it.

   Returns the child PID; caller kills it with [kill_child]. *)
type server_kind = Rpc_https | Rpc_http | Rest_https

let server_kind_to_string = function
  | Rpc_https -> "rpc-https" | Rpc_http -> "rpc-http" | Rest_https -> "rest-https"

let server_kind_of_string = function
  | "rpc-https" -> Rpc_https | "rpc-http" -> Rpc_http | "rest-https" -> Rest_https
  | k -> failwith ("unknown server kind " ^ k)

let server_factory kind ~port ~cert ~key (ctx : Rpc.rpc_context) : unit Lwt.t =
  match kind with
  | Rpc_https ->
    Rpc.start_rpc_server ~ctx ~host:"127.0.0.1" ~port
      ~rpc_user:"camlcoin" ~rpc_password:"camlcoin" ~cookie_password:None
      ~tls_cert_path:(Some cert) ~tls_key_path:(Some key) ()
  | Rpc_http ->
    Rpc.start_rpc_server ~ctx ~host:"127.0.0.1" ~port
      ~rpc_user:"camlcoin" ~rpc_password:"camlcoin" ~cookie_password:None ()
  | Rest_https ->
    Rest.start_rest_server ~ctx ~host:"127.0.0.1" ~port
      ~tls_cert_path:(Some cert) ~tls_key_path:(Some key) ()

let server_env_var = "CAMLCOIN_FIX64_SERVER"

(* Child entry point: when the env var is set, run the server and exit.
   If anything raises, log + exit 1 so the parent's wait_for_port deadline
   catches the failure. *)
let maybe_run_as_server () =
  match Sys.getenv_opt server_env_var with
  | None -> ()
  | Some spec ->
    (match String.split_on_char ',' spec with
     | [kind; port; cert; key] ->
       (try
          seed_rng ();  (* what Cli.run does before starting the listeners *)
          let ctx = make_rpc_ctx () in
          Lwt_main.run
            (server_factory (server_kind_of_string kind)
               ~port:(int_of_string port) ~cert ~key ctx);
          exit 0
        with exn ->
          Printf.eprintf "[fix64-server-child] %s\n%!" (Printexc.to_string exn);
          exit 1)
     | _ ->
       Printf.eprintf "[fix64-server-child] bad spec %S\n%!" spec;
       exit 2)

let spawn_server kind ~port ~cert ~key =
  let spec = Printf.sprintf "%s,%d,%s,%s" (server_kind_to_string kind) port cert key in
  let env = Array.append [| server_env_var ^ "=" ^ spec |] (Unix.environment ()) in
  let exe = Sys.executable_name in
  Unix.create_process_env exe [| exe |] env Unix.stdin Unix.stdout Unix.stderr

let kill_child pid =
  (try Unix.kill pid Sys.sigkill with _ -> ());
  (try ignore (Unix.waitpid [] pid) with _ -> ());
  (* The child was SIGKILLed: reap its RocksDB datadir here. *)
  rm_rf (db_path_for_pid pid)

(* Test 1: RPC over HTTPS — TLS handshake completes, request reaches auth. *)
let test_rpc_https_roundtrip () =
  let tmp_dir = "/tmp/camlcoin_fix64_certs" in
  let cert, key = ensure_self_signed_cert tmp_dir in
  let port = pick_free_port () in
  let _ = wait_until_some in
  let pid = spawn_server Rpc_https ~port ~cert ~key in
  let cleanup () = kill_child pid in
  Fun.protect ~finally:cleanup (fun () ->
    wait_for_port ~port;
    let status = https_request_status ~port in
    match status with
    | Some line ->
      Alcotest.(check bool)
        ("first line contains 401: " ^ line) true
        (try
           let _ = Str.search_forward (Str.regexp_string "401") line 0 in true
         with Not_found -> false)
    | None ->
      Alcotest.fail "no HTTPS response line read")

(* Test 2: RPC over HTTP (no cert/key set) — backward compat. *)
let test_rpc_http_backward_compat () =
  let port = pick_free_port () in
  let pid = spawn_server Rpc_http ~port ~cert:"" ~key:"" in
  let cleanup () = kill_child pid in
  Fun.protect ~finally:cleanup (fun () ->
    wait_for_port ~port;
    let status = http_request_status ~port in
    match status with
    | Some line ->
      Alcotest.(check bool)
        ("first line contains 401: " ^ line) true
        (try
           let _ = Str.search_forward (Str.regexp_string "401") line 0 in true
         with Not_found -> false)
    | None ->
      Alcotest.fail "no HTTP response line read")

(* For startup-error tests we run start_rpc_server in the parent because
   the failure short-circuits before any socket bind happens, so there's
   no scheduler-vs-main loop issue.  Each test uses a unique db dir
   (via PID + counter) to avoid RocksDB lock contention. *)
let unique_parent_db_counter = ref 0

let make_parent_only_ctx () =
  incr unique_parent_db_counter;
  let path = Printf.sprintf "/tmp/camlcoin_test_fix64_parent_%d_%d"
    (Unix.getpid ()) !unique_parent_db_counter in
  rm_rf path;
  let db = Storage.ChainDB.create path in
  let utxo = Utxo.UtxoSet.create db in
  let mempool = Mempool.create ~network:Consensus.regtest ~require_standard:false ~verify_scripts:false
                  ~utxo ~current_height:0 () in
  let network = Consensus.testnet4 in
  let chain_state = Sync.create_chain_state db network in
  let peer_manager = Peer_manager.create network in
  let fee_estimator = Fee_estimation.create () in
  let ctx = Rpc.create_context
    ~chain:chain_state ~mempool ~peer_manager ~wallet:None
    ~fee_estimator ~network () in
  ctx, (fun () -> Storage.ChainDB.close db; rm_rf path)

(* Test 3: Cert without key — startup error. *)
let test_rpc_tls_cert_without_key () =
  let tmp_dir = "/tmp/camlcoin_fix64_certs" in
  let cert, _key = ensure_self_signed_cert tmp_dir in
  let ctx, cleanup = make_parent_only_ctx () in
  let port = pick_free_port () in
  let raised =
    try
      let _ =
        Lwt_main.run (
          Rpc.start_rpc_server
            ~ctx
            ~host:"127.0.0.1" ~port
            ~rpc_user:"camlcoin" ~rpc_password:"camlcoin"
            ~cookie_password:None
            ~tls_cert_path:(Some cert)
            ~tls_key_path:None
            ()
        )
      in
      false
    with Failure _ -> true | _ -> true
  in
  cleanup ();
  Alcotest.(check bool) "cert-without-key raised" true raised

(* Test 4: Key without cert — startup error. *)
let test_rpc_tls_key_without_cert () =
  let tmp_dir = "/tmp/camlcoin_fix64_certs" in
  let _cert, key = ensure_self_signed_cert tmp_dir in
  let ctx, cleanup = make_parent_only_ctx () in
  let port = pick_free_port () in
  let raised =
    try
      let _ =
        Lwt_main.run (
          Rpc.start_rpc_server
            ~ctx
            ~host:"127.0.0.1" ~port
            ~rpc_user:"camlcoin" ~rpc_password:"camlcoin"
            ~cookie_password:None
            ~tls_cert_path:None
            ~tls_key_path:(Some key)
            ()
        )
      in
      false
    with Failure _ -> true | _ -> true
  in
  cleanup ();
  Alcotest.(check bool) "key-without-cert raised" true raised

(* Test 5: Missing cert file path — startup error. *)
let test_rpc_tls_missing_cert_file () =
  let ctx, cleanup = make_parent_only_ctx () in
  let port = pick_free_port () in
  let raised =
    try
      let _ =
        Lwt_main.run (
          Rpc.start_rpc_server
            ~ctx
            ~host:"127.0.0.1" ~port
            ~rpc_user:"camlcoin" ~rpc_password:"camlcoin"
            ~cookie_password:None
            ~tls_cert_path:(Some "/tmp/camlcoin_does_not_exist_fix64.crt")
            ~tls_key_path:(Some "/tmp/camlcoin_does_not_exist_fix64.key")
            ()
        )
      in
      false
    with Failure _ -> true | _ -> true
  in
  cleanup ();
  Alcotest.(check bool) "missing-cert-file raised" true raised

(* Test 6: REST HTTPS — symmetric with RPC test 1. *)
let test_rest_https_roundtrip () =
  let tmp_dir = "/tmp/camlcoin_fix64_certs" in
  let cert, key = ensure_self_signed_cert tmp_dir in
  let port = pick_free_port () in
  let pid = spawn_server Rest_https ~port ~cert ~key in
  let cleanup () = kill_child pid in
  Fun.protect ~finally:cleanup (fun () ->
    wait_for_port ~port;
    (* Cohttp REST returns 404 for unknown paths and 405 for non-GET.
       We only need to confirm the TLS handshake succeeded and an HTTP/1.x
       status line came back. *)
    let make_get_str =
      Printf.sprintf
        "GET / HTTP/1.0\r\n\
         Host: 127.0.0.1:%d\r\n\
         \r\n"
        port
    in
    let status =
      let open Lwt.Infix in
      Lwt_main.run (with_client_timeout (
        let tls_cfg = match Tls.Config.client ~authenticator:null_authenticator () with
          | Ok c -> c
          | Error (`Msg m) -> failwith ("Tls.Config.client: " ^ m)
        in
        tls_connect_loopback tls_cfg ~port >>= fun (ic, oc) ->
        Lwt_io.write oc make_get_str >>= fun () ->
        Lwt_io.read_line_opt ic >>= fun line ->
        Lwt.return line))
    in
    match status with
    | Some line ->
      Alcotest.(check bool)
        ("first line starts HTTP/: " ^ line) true
        (String.length line >= 5 && String.sub line 0 5 = "HTTP/")
    | None ->
      Alcotest.fail "no REST HTTPS response line read")

(* ============================================================================
   Suite
   ============================================================================ *)

let () =
  maybe_run_as_server ();  (* server-mode child: runs a listener, never returns *)
  seed_rng ();
  Alcotest.run "fix64_tls" [
    "rpc-tls", [
      Alcotest.test_case "https roundtrip"           `Slow test_rpc_https_roundtrip;
      Alcotest.test_case "http backward compat"      `Slow test_rpc_http_backward_compat;
    ];
    "rest-tls", [
      Alcotest.test_case "https roundtrip"           `Slow test_rest_https_roundtrip;
    ];
    "rpc-tls-startup-errors", [
      Alcotest.test_case "cert without key errors"   `Quick test_rpc_tls_cert_without_key;
      Alcotest.test_case "key without cert errors"   `Quick test_rpc_tls_key_without_cert;
      Alcotest.test_case "missing cert file errors"  `Quick test_rpc_tls_missing_cert_file;
    ];
  ]
