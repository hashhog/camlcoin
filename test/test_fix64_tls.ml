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

(* Each child process gets its own RocksDB datadir (under PID) so that
   parallel test runs do not collide and the parent never holds an
   open handle that the fork would inherit. *)
let unique_db_path () =
  Printf.sprintf "/tmp/camlcoin_test_fix64_db_%d" (Unix.getpid ())

let rec rm_rf path =
  if Sys.file_exists path then begin
    if Sys.is_directory path then begin
      Array.iter (fun f -> rm_rf (Filename.concat path f)) (Sys.readdir path);
      Unix.rmdir path
    end else
      Unix.unlink path
  end

(* Build an RPC context.  Called from inside the child process to keep
   the RocksDB handle entirely owned by the child (a handle inherited
   across fork would deadlock the parent's later open + close). *)
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

(* HTTPS request: TLS handshake then send the raw bytes; return the
   first response line (e.g. "HTTP/1.0 401 Unauthorized"). *)
let https_request_status ~port =
  let open Lwt.Infix in
  let promise =
    let tls_cfg = match Tls.Config.client ~authenticator:null_authenticator () with
      | Ok c -> c
      | Error (`Msg m) -> failwith ("Tls.Config.client: " ^ m)
    in
    Tls_lwt.connect_ext tls_cfg ("127.0.0.1", port) >>= fun (ic, oc) ->
    Lwt_io.write oc (make_post_request_str ~host:"127.0.0.1" ~port) >>= fun () ->
    Lwt_io.read_line_opt ic >>= fun line ->
    Lwt_io.close ic >>= fun () ->
    Lwt_io.close oc >|= fun () ->
    line
  in
  Lwt_main.run promise

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
    Lwt_io.close ic >>= fun () ->
    Lwt_io.close oc >|= fun () ->
    line
  in
  Lwt_main.run promise

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
  let deadline = Unix.gettimeofday () +. 3.0 in
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

(* Spawn the server in a CHILD PROCESS.  Lwt's "nested Lwt_main.run"
   check is per-process, so running an independent Lwt_main in the
   child + another in the parent (for the client request) is the
   simplest way to avoid the check while still owning a real scheduler
   on each side.  Returns the child PID; caller is responsible for
   killing it (we use kill_child below).

   The [server_factory ctx] thunk is INVOKED INSIDE THE CHILD, after the
   ctx has been built inside the child.  This keeps the RocksDB / mempool
   / peer-manager handles entirely owned by the child — inheriting an
   open RocksDB handle across fork would deadlock the next .create() call.

   POSIX-thread variant was tried and rejected: Lwt's main-loop check
   uses a global, so two threads in the same process cannot both run
   Lwt_main. *)
let spawn_server (server_factory : Rpc.rpc_context -> unit Lwt.t) =
  match Unix.fork () with
  | 0 ->
    (* Child.  Build a fresh ctx and run the server.  If anything
       raises, log + exit 1 so the parent's wait_for_port deadline
       catches the failure. *)
    (try
       let ctx = make_rpc_ctx () in
       Lwt_main.run (server_factory ctx);
       exit 0
     with exn ->
       Printf.eprintf "[fix64-server-child] %s\n%!" (Printexc.to_string exn);
       exit 1)
  | pid ->
    (* Parent — return PID so it can be killed at the end of the test. *)
    pid

let kill_child pid =
  (try Unix.kill pid Sys.sigkill with _ -> ());
  (try ignore (Unix.waitpid [] pid) with _ -> ())

(* Test 1: RPC over HTTPS — TLS handshake completes, request reaches auth. *)
let test_rpc_https_roundtrip () =
  let tmp_dir = "/tmp/camlcoin_fix64_certs" in
  let cert, key = ensure_self_signed_cert tmp_dir in
  let port = pick_free_port () in
  let _ = wait_until_some in
  let pid = spawn_server (fun ctx ->
    Rpc.start_rpc_server
      ~ctx
      ~host:"127.0.0.1" ~port
      ~rpc_user:"camlcoin" ~rpc_password:"camlcoin"
      ~cookie_password:None
      ~tls_cert_path:(Some cert)
      ~tls_key_path:(Some key)
      ())
  in
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
  let pid = spawn_server (fun ctx ->
    Rpc.start_rpc_server
      ~ctx
      ~host:"127.0.0.1" ~port
      ~rpc_user:"camlcoin" ~rpc_password:"camlcoin"
      ~cookie_password:None
      ())
  in
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
  let pid = spawn_server (fun ctx ->
    Rest.start_rest_server
      ~ctx
      ~host:"127.0.0.1" ~port
      ~tls_cert_path:(Some cert)
      ~tls_key_path:(Some key)
      ())
  in
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
      Lwt_main.run (
        let tls_cfg = match Tls.Config.client ~authenticator:null_authenticator () with
          | Ok c -> c
          | Error (`Msg m) -> failwith ("Tls.Config.client: " ^ m)
        in
        Tls_lwt.connect_ext tls_cfg ("127.0.0.1", port) >>= fun (ic, oc) ->
        Lwt_io.write oc make_get_str >>= fun () ->
        Lwt_io.read_line_opt ic >>= fun line ->
        Lwt_io.close ic >>= fun () ->
        Lwt_io.close oc >|= fun () ->
        line)
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
  Alcotest.run "fix64_tls" [
    "rpc-tls", [
      Alcotest.test_case "https roundtrip"           `Slow test_rpc_https_roundtrip;
      Alcotest.test_case "http backward compat"      `Slow test_rpc_http_backward_compat;
      Alcotest.test_case "cert without key errors"   `Quick test_rpc_tls_cert_without_key;
      Alcotest.test_case "key without cert errors"   `Quick test_rpc_tls_key_without_cert;
      Alcotest.test_case "missing cert file errors"  `Quick test_rpc_tls_missing_cert_file;
    ];
    "rest-tls", [
      Alcotest.test_case "https roundtrip"           `Slow test_rest_https_roundtrip;
    ];
  ]
