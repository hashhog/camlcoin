(* Wallet files are private to the node's user.

   Wallet files hold plaintext "private_key" hex.  camlcoin set no umask
   outside --daemon, created the wallet temp file with open_out_bin (0666
   & umask) and made wallets/ with 0755, so on a box with umask 0002 a
   fresh wallet was 0664, wallets/ 0755 and the datadir 0775: any local
   user could read the keys.  Core calls umask(077) in SetupEnvironment
   (common/system.cpp) before anything touches the datadir.

   Library cases run under umask 0o022 and check that wallet.ml's own
   modes are tight whatever the umask.  The node case boots bin/main.exe
   under umask 0o002 (the maxbox default), does createwallet +
   getnewaddress over RPC, and checks every file and directory it made. *)

open Camlcoin

let mode p = (Unix.stat p).Unix.st_perm land 0o777

let check_mode what want p =
  Alcotest.(check string) (Printf.sprintf "%s (%s) mode" what p)
    (Printf.sprintf "%o" want) (Printf.sprintf "%o" (mode p))

let with_umask m f =
  let old = Unix.umask m in
  Fun.protect ~finally:(fun () -> ignore (Unix.umask old)) f

(* ---- library: Wallet under umask 0o022 ------------------------------- *)

let test_lib_create_wallet () =
  with_umask 0o022 (fun () ->
    Test_tmp.with_dir ~label:"wfm_lib" ~mkdir:true (fun root ->
      let wallets_dir = Filename.concat root "wallets" in
      let wm = Wallet.create_wallet_manager ~wallets_dir ~network:`Regtest in
      check_mode "wallets dir" 0o700 wallets_dir;
      let w = match Wallet.create_wallet wm "w1" () with
        | Ok w -> w | Error e -> Alcotest.fail e in
      ignore (Wallet.get_new_address w);
      Wallet.save w;
      check_mode "wallet file" 0o600 (Filename.concat wallets_dir "w1")))

let test_lib_save_load_backup () =
  with_umask 0o022 (fun () ->
    Test_tmp.with_dir ~label:"wfm_lib2" ~mkdir:true (fun root ->
      let db_path = Filename.concat root "wallet.json" in
      let w = Wallet.create ~network:`Regtest ~db_path in
      Wallet.init_from_mnemonic w (Bip39.generate_mnemonic ~strength:128 ()) ();
      ignore (Wallet.get_new_address w);
      Wallet.save w;
      check_mode "saved wallet" 0o600 db_path;
      (* a clean load writes the .bak sidecar *)
      let w2 = Wallet.load ~network:`Regtest ~db_path in
      check_mode "wallet .bak" 0o600 (db_path ^ ".bak");
      let dest = Filename.concat root "backup.json" in
      (match Wallet.backup_wallet w2 dest with
       | Ok () -> () | Error e -> Alcotest.fail e);
      check_mode "backupwallet file" 0o600 dest;
      (* A stale temp file left 0664 by an older build must not carry its
         mode onto the renamed wallet file. *)
      let tmp = db_path ^ ".tmp" in
      let oc = open_out_gen [Open_wronly; Open_creat; Open_trunc] 0o664 tmp in
      close_out oc;
      Unix.chmod tmp 0o664;
      Wallet.save w2;
      check_mode "wallet saved over a stale 0664 .tmp" 0o600 db_path))

(* ---- node: bin/main.exe on regtest under umask 0o002 ----------------- *)

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
  let ic = open_in_bin p in
  Fun.protect ~finally:(fun () -> close_in ic)
    (fun () -> really_input_string ic (in_channel_length ic))

(* POST one JSON-RPC call; returns (status, body), status 0 on refusal. *)
let rpc ~port ~cookie ?(path = "/") meth params =
  let open Lwt.Syntax in
  let uri = Uri.of_string (Printf.sprintf "http://127.0.0.1:%d%s" port path) in
  let headers = Cohttp.Header.of_list [
      "Content-Type", "text/plain";
      "Authorization", "Basic " ^ Base64.encode_string cookie ] in
  let body = Yojson.Safe.to_string (`Assoc [
      "jsonrpc", `String "1.0"; "id", `Int 1; "method", `String meth;
      "params", `List params ]) in
  Lwt.catch
    (fun () ->
       let* resp, b = Cohttp_lwt_unix.Client.post ~headers
           ~body:(Cohttp_lwt.Body.of_string body) uri in
       let* s = Cohttp_lwt.Body.to_string b in
       Lwt.return
         (Cohttp.Code.code_of_status (Cohttp.Response.status resp), s))
    (fun _ -> Lwt.return (0, ""))

let test_node_wallet_modes () =
  Test_tmp.with_dir ~label:"wfm_node" ~mkdir:true (fun root ->
    (* The node creates the datadir itself, so its mode is the node's. *)
    let datadir = Filename.concat root "node" in
    let rpcport = free_port () and p2pport = free_port () in
    let log = Filename.concat root "node.log" in
    let fd = Unix.openfile log [Unix.O_WRONLY; Unix.O_CREAT; Unix.O_TRUNC]
        0o600 in
    let args = [| main_exe; "--network=regtest"; "--datadir=" ^ datadir;
                  "--rpchost=127.0.0.1"; Printf.sprintf "--rpcport=%d" rpcport;
                  Printf.sprintf "--port=%d" p2pport; "--metricsport=0";
                  "--nodnsseed"; "--connect=127.0.0.1:1" |] in
    let pid = with_umask 0o002 (fun () ->
        Unix.create_process main_exe args Unix.stdin fd fd) in
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
            let* c, _ = rpc ~port:rpcport ~cookie:ck "getblockcount" [] in
            if c = 200 then Lwt.return ck
            else let* () = Lwt_unix.sleep 0.2 in ready (n - 1) in
        let* ck = ready 600 in
        let* c, b = rpc ~port:rpcport ~cookie:ck "createwallet" [`String "w1"] in
        if c <> 200 then
          Lwt.fail_with (Printf.sprintf "createwallet -> %d %s" c b)
        else
        let* c, b = rpc ~port:rpcport ~cookie:ck ~path:"/wallet/w1"
            "getnewaddress" [] in
        if c <> 200 then
          Lwt.fail_with (Printf.sprintf "getnewaddress -> %d %s" c b)
        else
        let* _ = rpc ~port:rpcport ~cookie:ck "stop" [] in
        Lwt.return_unit));
    let w1 = Filename.concat datadir "wallets/w1" in
    (* the instrument: the file under test really holds key material *)
    Alcotest.(check bool) "wallets/w1 holds a private_key" true
      (try ignore (Str.search_forward (Str.regexp_string "\"private_key\"")
                     (read_file w1) 0); true
       with Not_found -> false);
    check_mode "datadir" 0o700 datadir;
    check_mode "wallets dir" 0o700 (Filename.concat datadir "wallets");
    check_mode "wallet file" 0o600 w1;
    check_mode "boot wallet.json" 0o600 (Filename.concat datadir "wallet.json");
    let bak = Filename.concat datadir "wallet.json.bak" in
    if Sys.file_exists bak then check_mode "boot wallet.json.bak" 0o600 bak)

let () =
  Alcotest.run "wallet_file_modes" [
    "library", [
      Alcotest.test_case "create_wallet: wallets/ 700, wallet 600" `Quick
        test_lib_create_wallet;
      Alcotest.test_case "save, .bak, backupwallet, stale .tmp: 600" `Quick
        test_lib_save_load_backup;
    ];
    "node", [
      Alcotest.test_case "createwallet+getnewaddress under umask 002" `Slow
        test_node_wallet_modes;
    ];
  ]
