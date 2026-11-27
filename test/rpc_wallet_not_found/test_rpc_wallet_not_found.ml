(* /wallet/<name> must name a loaded wallet; a miss is -18, not the default.

   context_with_wallet returned the unchanged context when /wallet/<name>
   named no loaded wallet, and when a base-path request ("/") had no default
   wallet and zero or several wallets loaded.  Wallet RPCs then ran on
   whatever wallet the context already held: the boot/default wallet, or a
   wallet that had since been unloaded.  So getwalletinfo on
   /wallet/doesnotexist described the default wallet, backupwallet copied it
   to the caller's path, and sendtoaddress tried to spend from it.

   Core GetWalletForJSONRPCRequest (wallet/rpc/util.cpp):
   - /wallet/<name>: the name is URL-decoded (GetWalletNameFromJSONRPCRequest
     UrlDecode) and looked up; a miss is RPC_WALLET_NOT_FOUND (-18)
     "Requested wallet does not exist or is not loaded".
   - no wallet endpoint: the sole loaded wallet; none loaded is -18 "No wallet
     is loaded. ..."; several is RPC_WALLET_NOT_SPECIFIED (-19) "Multiple
     wallets are loaded. ...".
   Only RPCs that call GetWalletForJSONRPCRequest are refused: getblockcount
   on /wallet/doesnotexist still answers.

   Every case goes through Rpc.start_rpc_server over HTTP, so the URL is
   parsed and routed exactly as for a real client. *)

open Camlcoin

let free_port () =
  let s = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Unix.bind s (Unix.ADDR_INET (Unix.inet_addr_loopback, 0));
  let p = match Unix.getsockname s with
    | Unix.ADDR_INET (_, p) -> p | _ -> assert false in
  Unix.close s; p

let auth = "Basic " ^ Base64.encode_string "u:p"

(* POST [body] to [path]; the parsed JSON reply, or `Null when the
   connection is refused. *)
let post_raw port path body =
  let open Lwt.Syntax in
  let uri = Uri.of_string (Printf.sprintf "http://127.0.0.1:%d%s" port path) in
  let headers = Cohttp.Header.of_list
      [ ("Content-Type", "application/json"); ("Authorization", auth) ] in
  Lwt.catch
    (fun () ->
       let* _resp, b =
         Cohttp_lwt_unix.Client.post ~headers
           ~body:(Cohttp_lwt.Body.of_string body) uri in
       let* s = Cohttp_lwt.Body.to_string b in
       Lwt.return (Yojson.Safe.from_string s))
    (fun _ -> Lwt.return `Null)

let req ?(params = []) meth =
  `Assoc [ ("jsonrpc", `String "1.0"); ("id", `Int 1);
           ("method", `String meth); ("params", `List params) ]

let call port path ?params meth =
  post_raw port path (Yojson.Safe.to_string (req ?params meth))

(* Wallets in the manager, by key.  [boot] is registered under "" the way
   Cli does at startup; the others through Wallet.create_wallet, which
   registers only the name (no promotion to the default).  [unload_default]
   then drops "" from the manager while the context still holds [boot], as
   after an unloadwallet of the default wallet. *)
let with_server ?(unload_default = false) ~named f =
  Test_tmp.with_dir ~label:"rpc_wallet_nf" ~mkdir:true (fun dir ->
    let db = Storage.ChainDB.create (Filename.concat dir "chain") in
    let network = Consensus.regtest in
    let utxo = Utxo.UtxoSet.create db in
    let mempool = Mempool.create ~network ~require_standard:false
        ~verify_scripts:false ~utxo ~current_height:0 () in
    let wm = Wallet.create_wallet_manager
        ~wallets_dir:(Filename.concat dir "wallets") ~network:`Regtest in
    let boot = Wallet.create ~network:`Regtest
        ~db_path:(Filename.concat dir "wallet.json") in
    Hashtbl.replace wm.Wallet.wallets "" boot;
    List.iter (fun n ->
        match Wallet.create_wallet wm n () with
        | Ok _ -> ()
        | Error e -> Alcotest.failf "create_wallet %S: %s" n e) named;
    let ctx = Rpc.create_context_with_wallet_manager
        ~chain:(Sync.create_chain_state db network) ~mempool
        ~peer_manager:(Peer_manager.create network) ~wallet_manager:wm
        ~fee_estimator:(Fee_estimation.create ()) ~network () in
    if unload_default then Hashtbl.remove wm.Wallet.wallets "";
    let port = free_port () in
    let r = Lwt_main.run (
      let open Lwt.Syntax in
      let server =
        Rpc.start_rpc_server ~ctx ~host:"127.0.0.1" ~port ~rpc_user:"u"
          ~rpc_password:"p" ~cookie_password:None () in
      let rec ready n =
        let* j = call port "/" "getblockcount" in
        if j <> `Null || n = 0 then Lwt.return_unit
        else let* () = Lwt_unix.sleep 0.05 in ready (n - 1) in
      Lwt.pick [ Lwt.bind server (fun () -> Lwt.fail_with "server exited");
                 (let* () = ready 100 in f dir port) ]) in
    Storage.ChainDB.close db;
    r)

let field k = function
  | `Assoc kv -> (match List.assoc_opt k kv with Some v -> v | None -> `Null)
  | _ -> `Null

let error_of j =
  match field "error" j with
  | `Assoc _ as e ->
    (match field "code" e, field "message" e with
     | `Int c, `String m -> Some (c, m)
     | `Int c, _ -> Some (c, "")
     | _ -> None)
  | _ -> None

let show j = Yojson.Safe.to_string j

let expect_error ~what ~code ~message j =
  match error_of j with
  | Some (c, m) ->
    Alcotest.(check int) (what ^ ": code") code c;
    Alcotest.(check string) (what ^ ": message") message m
  | None -> Alcotest.failf "%s: expected error %d, got %s" what code (show j)

let walletname j =
  match error_of j with
  | Some (c, m) -> Alcotest.failf "getwalletinfo failed: %d %s" c m
  | None ->
    (match field "walletname" (field "result" j) with
     | `String s -> s
     | other -> Alcotest.failf "no walletname in %s" (show other))

let not_found = "Requested wallet does not exist or is not loaded"
let none_loaded =
  "No wallet is loaded. Load a wallet using loadwallet or create a new one \
   with createwallet. (Note: A default wallet is no longer automatically \
   created)"
let multiple =
  "Multiple wallets are loaded. Please select which wallet to use by \
   requesting the RPC through the /wallet/<walletname> URI path."

let run f = with_server ~named:[ "a"; "my wallet" ] f

(* ---- /wallet/<name> naming no loaded wallet ------------------------- *)

let test_getwalletinfo_unloaded () =
  let j = run (fun _ port -> call port "/wallet/doesnotexist" "getwalletinfo") in
  expect_error ~what:"getwalletinfo /wallet/doesnotexist" ~code:(-18)
    ~message:not_found j

let test_backupwallet_unloaded () =
  let j, dest, exists = run (fun dir port ->
      let open Lwt.Syntax in
      let dest = Filename.concat dir "backup-of-nothing.dat" in
      let* j = call port "/wallet/doesnotexist" "backupwallet"
          ~params:[ `String dest ] in
      Lwt.return (j, dest, Sys.file_exists dest)) in
  expect_error ~what:"backupwallet /wallet/doesnotexist" ~code:(-18)
    ~message:not_found j;
  Alcotest.(check bool) ("no backup written at " ^ dest) false exists

let test_sendtoaddress_unloaded () =
  let j = run (fun _ port ->
      call port "/wallet/doesnotexist" "sendtoaddress"
        ~params:[ `String "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
                  `Float 0.1 ]) in
  expect_error ~what:"sendtoaddress /wallet/doesnotexist" ~code:(-18)
    ~message:not_found j

(* Core: "/wallet/" is the wallet endpoint with the name "", looked up
   like any other name, not the base path's sole-wallet rule. *)
let test_empty_name_endpoint () =
  let j = with_server ~unload_default:true ~named:[ "a" ] (fun _ port ->
      call port "/wallet/" "getwalletinfo") in
  expect_error ~what:"getwalletinfo /wallet/ with no \"\" wallet" ~code:(-18)
    ~message:not_found j

(* A batch on a bad endpoint: the wallet call is refused, the others run. *)
let test_batch_unloaded () =
  let j = run (fun _ port ->
      post_raw port "/wallet/doesnotexist"
        (Yojson.Safe.to_string
           (`List [ req "getblockcount"; req "getwalletinfo" ]))) in
  match j with
  | `List [ a; b ] ->
    Alcotest.(check string) "batch getblockcount result" "0"
      (show (field "result" a));
    expect_error ~what:"batch getwalletinfo" ~code:(-18) ~message:not_found b
  | other -> Alcotest.failf "batch: expected two replies, got %s" (show other)

(* ---- the routing that must keep working ----------------------------- *)

let test_named_routes () =
  let n = run (fun _ port -> call port "/wallet/a" "getwalletinfo") in
  Alcotest.(check string) "/wallet/a is wallet a" "a" (walletname n)

let test_url_decoded_name () =
  let n = run (fun _ port -> call port "/wallet/my%20wallet" "getwalletinfo") in
  Alcotest.(check string) "/wallet/my%20wallet is \"my wallet\"" "my wallet"
    (walletname n)

let test_non_wallet_method_on_bad_endpoint () =
  let j = run (fun _ port -> call port "/wallet/doesnotexist" "getblockcount") in
  Alcotest.(check (option (pair int string))) "no error" None (error_of j);
  Alcotest.(check string) "getblockcount" "0" (show (field "result" j))

(* Arity is checked before the wallet, as in Core's RPCHelpMan: getwalletinfo
   takes no argument (resources/core-arity.json), so a surplus one is -1
   even on an endpoint that names no wallet. *)
let test_arity_before_wallet () =
  let j = run (fun _ port ->
      call port "/wallet/doesnotexist" "getwalletinfo"
        ~params:[ `String "unexpected" ]) in
  match error_of j with
  | Some (c, _) -> Alcotest.(check int) "surplus argument -> -1" (-1) c
  | None -> Alcotest.failf "expected an arity error, got %s" (show j)

let test_base_default_routes () =
  let n = run (fun _ port -> call port "/" "getwalletinfo") in
  Alcotest.(check string) "/ is the \"\" default wallet" "" (walletname n)

let test_base_sole_wallet_routes () =
  let n = with_server ~unload_default:true ~named:[ "a" ] (fun _ port ->
      call port "/" "getwalletinfo") in
  Alcotest.(check string) "/ with only a loaded is a" "a" (walletname n)

(* ---- base path, no default wallet ----------------------------------- *)

let test_base_two_wallets () =
  let j = with_server ~unload_default:true ~named:[ "a"; "b" ] (fun _ port ->
      call port "/" "getwalletinfo") in
  expect_error ~what:"getwalletinfo / with a and b loaded" ~code:(-19)
    ~message:multiple j

let test_base_no_wallets () =
  let j = with_server ~unload_default:true ~named:[] (fun _ port ->
      call port "/" "getwalletinfo") in
  expect_error ~what:"getwalletinfo / with no wallet loaded" ~code:(-18)
    ~message:none_loaded j

let () =
  Alcotest.run "rpc_wallet_not_found" [
    "unloaded endpoint", [
      Alcotest.test_case "getwalletinfo_is_18" `Quick test_getwalletinfo_unloaded;
      Alcotest.test_case "backupwallet_is_18_writes_nothing" `Quick
        test_backupwallet_unloaded;
      Alcotest.test_case "sendtoaddress_is_18" `Quick test_sendtoaddress_unloaded;
      Alcotest.test_case "empty_name_endpoint_is_18" `Quick
        test_empty_name_endpoint;
      Alcotest.test_case "batch_refuses_only_wallet_call" `Quick
        test_batch_unloaded;
    ];
    "routing", [
      Alcotest.test_case "named_endpoint" `Quick test_named_routes;
      Alcotest.test_case "url_decoded_name" `Quick test_url_decoded_name;
      Alcotest.test_case "non_wallet_method_on_bad_endpoint" `Quick
        test_non_wallet_method_on_bad_endpoint;
      Alcotest.test_case "arity_before_wallet" `Quick test_arity_before_wallet;
      Alcotest.test_case "base_default_wallet" `Quick test_base_default_routes;
      Alcotest.test_case "base_sole_wallet" `Quick test_base_sole_wallet_routes;
    ];
    "base path", [
      Alcotest.test_case "two_wallets_no_default_is_19" `Quick
        test_base_two_wallets;
      Alcotest.test_case "no_wallet_is_18" `Quick test_base_no_wallets;
    ];
  ]
