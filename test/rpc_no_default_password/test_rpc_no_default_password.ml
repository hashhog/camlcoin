(* RPC auth has no built-in login.

   --rpcuser and --rpcpassword both defaulted to "camlcoin", and check_auth
   accepted that pair next to the cookie, so anyone who could reach the RPC
   port had full RPC (stop, send*, invalidateblock, file writes) with
   "Authorization: Basic Y2FtbGNvaW46Y2FtbGNvaW4=".  The mainnet node passes
   no password and has no conf file.  Core has no built-in password: with
   -rpcpassword unset it accepts only the cookie (httprpc.cpp
   InitRPCAuthentication), compares with TimingResistantEqual, and sleeps
   250 ms before answering a wrong Authorization header (HTTPReq_JSONRPC).

   Server cases call Rpc.start_rpc_server with Cli.default_config's
   credentials.  Node cases boot bin/main.exe on regtest so the CLI and
   camlcoin.conf defaults are covered too. *)

open Camlcoin

let free_port () =
  let s = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Unix.bind s (Unix.ADDR_INET (Unix.inet_addr_loopback, 0));
  let p = match Unix.getsockname s with
    | Unix.ADDR_INET (_, p) -> p | _ -> assert false in
  Unix.close s; p

let basic user pass = "Basic " ^ Base64.encode_string (user ^ ":" ^ pass)

let body = {|{"jsonrpc":"1.0","id":1,"method":"getblockcount","params":[]}|}

(* POST getblockcount; returns the HTTP status code, or 0 when the
   connection is refused. *)
let post ?auth port =
  let open Lwt.Syntax in
  let uri = Uri.of_string (Printf.sprintf "http://127.0.0.1:%d/" port) in
  let headers = Cohttp.Header.init_with "Content-Type" "text/plain" in
  let headers = match auth with
    | None -> headers
    | Some a -> Cohttp.Header.add headers "Authorization" a in
  Lwt.catch
    (fun () ->
       let* resp, b =
         Cohttp_lwt_unix.Client.post ~headers
           ~body:(Cohttp_lwt.Body.of_string body) uri in
       let* _ = Cohttp_lwt.Body.to_string b in
       Lwt.return (Cohttp.Code.code_of_status (Cohttp.Response.status resp)))
    (fun _ -> Lwt.return 0)

(* ---- server: Rpc.start_rpc_server ------------------------------------ *)

let with_server ~rpc_user ~rpc_password ~cookie f =
  Test_tmp.with_dir ~label:"rpc_no_default_pw" (fun db_path ->
    let db = Storage.ChainDB.create db_path in
    let network = Consensus.regtest in
    let utxo = Utxo.UtxoSet.create db in
    let mempool = Mempool.create ~network ~require_standard:false
        ~verify_scripts:false ~utxo ~current_height:0 () in
    let ctx = Rpc.create_context
        ~chain:(Sync.create_chain_state db network) ~mempool
        ~peer_manager:(Peer_manager.create network) ~wallet:None
        ~fee_estimator:(Fee_estimation.create ()) ~network () in
    let port = free_port () in
    let r = Lwt_main.run (
      let open Lwt.Syntax in
      let server =
        Rpc.start_rpc_server ~ctx ~host:"127.0.0.1" ~port ~rpc_user
          ~rpc_password ~cookie_password:cookie () in
      let rec ready n =
        let* c = post port in
        if c <> 0 || n = 0 then Lwt.return_unit
        else let* () = Lwt_unix.sleep 0.05 in ready (n - 1) in
      Lwt.pick [ Lwt.bind server (fun () -> Lwt.fail_with "server exited");
                 (let* () = ready 100 in f port) ]) in
    Storage.ChainDB.close db;
    r)

let cookie = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

let test_default_login_rejected () =
  let c = Cli.default_config in
  let got = with_server ~rpc_user:c.rpc_user ~rpc_password:c.rpc_password
      ~cookie:(Some cookie) (fun port ->
        let open Lwt.Syntax in
        let* builtin = post ~auth:(basic "camlcoin" "camlcoin") port in
        let* defaults =
          post ~auth:(basic c.rpc_user c.rpc_password) port in
        let* ck = post ~auth:(basic "__cookie__" cookie) port in
        Lwt.return (builtin, defaults, ck)) in
  let builtin, defaults, ck = got in
  Alcotest.(check int) "camlcoin:camlcoin with no rpcpassword -> 401"
    401 builtin;
  Alcotest.(check int) "default_config user:password -> 401" 401 defaults;
  Alcotest.(check int) "cookie -> 200" 200 ck

let test_explicit_password_accepted () =
  let got = with_server ~rpc_user:"alice" ~rpc_password:"s3cret"
      ~cookie:(Some cookie) (fun port ->
        let open Lwt.Syntax in
        let* ok = post ~auth:(basic "alice" "s3cret") port in
        let* wrong = post ~auth:(basic "alice" "s3cre") port in
        let* builtin = post ~auth:(basic "camlcoin" "camlcoin") port in
        let* ck = post ~auth:(basic "__cookie__" cookie) port in
        Lwt.return (ok, wrong, builtin, ck)) in
  let ok, wrong, builtin, ck = got in
  Alcotest.(check int) "explicit user:password -> 200" 200 ok;
  Alcotest.(check int) "wrong password -> 401" 401 wrong;
  Alcotest.(check int) "camlcoin:camlcoin -> 401" 401 builtin;
  Alcotest.(check int) "cookie still -> 200" 200 ck

let test_failed_auth_delay () =
  let got = with_server ~rpc_user:"alice" ~rpc_password:"s3cret"
      ~cookie:(Some cookie) (fun port ->
        let open Lwt.Syntax in
        let t0 = Unix.gettimeofday () in
        let* bad = post ~auth:(basic "alice" "nope") port in
        let t1 = Unix.gettimeofday () in
        let* good = post ~auth:(basic "alice" "s3cret") port in
        let t2 = Unix.gettimeofday () in
        Lwt.return (bad, t1 -. t0, good, t2 -. t1)) in
  let bad, bad_s, good, good_s = got in
  Alcotest.(check int) "wrong password -> 401" 401 bad;
  Alcotest.(check bool)
    (Printf.sprintf "failed auth waits >= 250 ms (took %.3f s)" bad_s)
    true (bad_s >= 0.25);
  Alcotest.(check int) "right password -> 200" 200 good;
  Alcotest.(check bool)
    (Printf.sprintf "good auth is not delayed (took %.3f s)" good_s)
    true (good_s < 0.25)

(* ---- node: bin/main.exe on regtest ----------------------------------- *)

let main_exe =
  let p = Filename.concat (Sys.getcwd ()) "../../bin/main.exe" in
  if Sys.file_exists p then p else failwith ("missing " ^ p)

let read_file p =
  let ic = open_in_bin p in
  Fun.protect ~finally:(fun () -> close_in ic)
    (fun () -> really_input_string ic (in_channel_length ic))

(* Boot main.exe with [extra] args (and an optional camlcoin.conf), wait
   until RPC answers, run [f port cookie], then stop the node over RPC. *)
let with_node ?conf ~label extra f =
  Test_tmp.with_dir ~label ~mkdir:true (fun datadir ->
    (match conf with
     | None -> ()
     | Some text ->
       let oc = open_out (Filename.concat datadir "camlcoin.conf") in
       output_string oc text; close_out oc);
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
      Lwt_main.run (
        let open Lwt.Syntax in
        let rec ready n =
          if n = 0 then
            Lwt.fail_with ("node did not come up; log:\n" ^ read_file log)
          else if not (Sys.file_exists cookie_path) then
            let* () = Lwt_unix.sleep 0.2 in ready (n - 1)
          else
            let ck = read_file cookie_path in
            let* c = post ~auth:("Basic " ^ Base64.encode_string ck) rpcport in
            if c = 200 then Lwt.return ck
            else let* () = Lwt_unix.sleep 0.2 in ready (n - 1) in
        let* ck = ready 600 in
        let* r = f rpcport ck in
        let stop = Printf.sprintf
            {|{"jsonrpc":"1.0","id":1,"method":"stop","params":[]}|} in
        let* () = Lwt.catch (fun () ->
            let* _ = Cohttp_lwt_unix.Client.post
                ~headers:(Cohttp.Header.init_with "Authorization"
                            ("Basic " ^ Base64.encode_string ck))
                ~body:(Cohttp_lwt.Body.of_string stop)
                (Uri.of_string (Printf.sprintf "http://127.0.0.1:%d/" rpcport))
            in Lwt.return_unit) (fun _ -> Lwt.return_unit) in
        Lwt.return r)))

let test_node_no_password_is_cookie_only () =
  let builtin, ck = with_node ~label:"rpcnopw_default" [] (fun port ck ->
      let open Lwt.Syntax in
      let* builtin = post ~auth:(basic "camlcoin" "camlcoin") port in
      let* c = post ~auth:("Basic " ^ Base64.encode_string ck) port in
      Lwt.return (builtin, c)) in
  Alcotest.(check int)
    "main.exe, no --rpcpassword: camlcoin:camlcoin -> 401" 401 builtin;
  Alcotest.(check int) "main.exe, no --rpcpassword: cookie -> 200" 200 ck

let test_node_cli_password () =
  let ok, builtin = with_node ~label:"rpcnopw_cli"
      [ "--rpcuser=alice"; "--rpcpassword=s3cret" ] (fun port _ ->
        let open Lwt.Syntax in
        let* ok = post ~auth:(basic "alice" "s3cret") port in
        let* builtin = post ~auth:(basic "camlcoin" "camlcoin") port in
        Lwt.return (ok, builtin)) in
  Alcotest.(check int) "--rpcuser/--rpcpassword -> 200" 200 ok;
  Alcotest.(check int) "camlcoin:camlcoin -> 401" 401 builtin

let test_node_conf_password () =
  let ok, builtin = with_node ~label:"rpcnopw_conf"
      ~conf:"rpcuser=bob\nrpcpassword=hunter2\n" [] (fun port _ ->
        let open Lwt.Syntax in
        let* ok = post ~auth:(basic "bob" "hunter2") port in
        let* builtin = post ~auth:(basic "camlcoin" "camlcoin") port in
        Lwt.return (ok, builtin)) in
  Alcotest.(check int) "camlcoin.conf rpcuser=/rpcpassword= -> 200" 200 ok;
  Alcotest.(check int) "camlcoin:camlcoin -> 401" 401 builtin

let () =
  Alcotest.run "rpc_no_default_password"
    [ ( "server",
        [ Alcotest.test_case "default config rejects camlcoin:camlcoin"
            `Quick test_default_login_rejected;
          Alcotest.test_case "explicit rpcpassword still accepted" `Quick
            test_explicit_password_accepted;
          Alcotest.test_case "failed auth delayed 250 ms" `Quick
            test_failed_auth_delay ] );
      ( "node",
        [ Alcotest.test_case "no rpcpassword: cookie only" `Slow
            test_node_no_password_is_cookie_only;
          Alcotest.test_case "--rpcuser/--rpcpassword accepted" `Slow
            test_node_cli_password;
          Alcotest.test_case "camlcoin.conf rpcpassword accepted" `Slow
            test_node_conf_password ] ) ]
