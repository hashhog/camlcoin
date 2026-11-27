(* createwallet with a passphrase ends encrypted and locked
   (cffix-camlcoin-createwallet-passphrase-lock).

   create_wallet handed a passphrase to save_encrypted, which wrapped the
   whole file in AES and set encrypted/salt/iv, and nothing else.  The
   wallet stayed Unlocked { expires = infinity } with no encrypted master
   key, so every "has_key_crypto && is_locked" gate let a spend through
   without the passphrase.  walletlock then zeroed the keys and
   walletpassphrase failed with "Wallet encryption data is missing": the
   keys were gone until a restart, and after a restart the whole-file
   header loaded as an empty wallet.

   Core CreateWallet (wallet/wallet.cpp:432-454) calls
   EncryptWallet(passphrase) and, for a non-blank wallet, Unlock, sets up
   the descriptors, then Lock.  The wallet is encrypted and locked when
   createwallet returns, and a spend needs walletpassphrase first
   (EnsureWalletIsUnlocked, RPC_WALLET_UNLOCK_NEEDED -13).

   Library cases drive Wallet directly.  The node case runs the sequence
   over RPC on bin/main.exe (regtest), across a restart. *)

open Camlcoin

let read_file p =
  let ic = open_in_bin p in
  Fun.protect ~finally:(fun () -> close_in ic)
    (fun () -> really_input_string ic (in_channel_length ic))

let contains hay needle =
  try ignore (Str.search_forward (Str.regexp_string needle) hay 0); true
  with Not_found -> false

let ok_or_fail what = function
  | Ok x -> x
  | Error e -> Alcotest.fail (what ^ ": " ^ e)

let mnemonic =
  "abandon abandon abandon abandon abandon abandon \
   abandon abandon abandon abandon abandon about"

let key_table w =
  List.map (fun kp ->
      (Address.address_to_string kp.Wallet.address,
       Wallet.cstruct_to_hex kp.Wallet.private_key))
    w.Wallet.keys

let zero_hex = String.make 64 '0'

(* A regtest address the wallets under test do not own. *)
let foreign_address () =
  let w = Wallet.create ~network:`Regtest ~db_path:"" in
  Wallet.init_from_mnemonic w mnemonic ();
  ignore (Wallet.get_new_address w);
  fst (List.hd (key_table w))

let with_passphrase ?(blank = false) p =
  { Wallet.default_wallet_options with Wallet.passphrase = p; blank }

let manager root =
  Wallet.create_wallet_manager ~wallets_dir:(Filename.concat root "wallets")
    ~network:`Regtest

let locked_spend_refused what w dest =
  match Wallet.create_transaction w ~dest_address:dest ~amount:10_000L
          ~fee_rate:1.0 () with
  | Error e ->
    Alcotest.(check string) (what ^ ": unlock needed")
      Wallet.wallet_locked_msg e
  | Ok _ -> Alcotest.fail (what ^ ": spent without the passphrase")

(* The item's test, on the library: created with a passphrase, the wallet
   is encrypted with real key crypto and locked; a spend is refused until
   walletpassphrase; walletlock then walletpassphrase works; the file holds
   no plaintext key; a reload comes back locked and the same keys decrypt. *)
let test_create_with_passphrase_locked () =
  Test_tmp.with_dir ~label:"cwpl_lib" ~mkdir:true (fun root ->
    let dest = foreign_address () in
    let wm = manager root in
    let w = ok_or_fail "create_wallet"
        (Wallet.create_wallet wm "w1" ~options:(with_passphrase (Some "pw1"))
           ()) in
    Alcotest.(check bool) "encrypted" true (Wallet.is_encrypted w);
    Alcotest.(check bool) "has an encrypted master key" true
      (Wallet.has_key_crypto w);
    Alcotest.(check bool) "locked when createwallet returns" true
      (Wallet.is_locked w);
    locked_spend_refused "fresh passphrase wallet" w dest;
    (* walletlock is valid on it, and then the passphrase unlocks it *)
    Wallet.wallet_lock w;
    Alcotest.(check bool) "wrong passphrase refused" true
      (Result.is_error
         (Wallet.wallet_passphrase w ~passphrase:"nope" ~timeout:60.));
    ok_or_fail "walletpassphrase after walletlock"
      (Wallet.wallet_passphrase w ~passphrase:"pw1" ~timeout:60.);
    Alcotest.(check bool) "unlocked" false (Wallet.is_locked w);
    (* unlocked: keys mint and the spend gets past the lock *)
    ignore (Wallet.get_new_address w);
    ignore (Wallet.get_new_address_typed w Wallet.P2PKH);
    let before = key_table w in
    List.iter (fun (a, k) ->
        Alcotest.(check bool) ("instrument: real key for " ^ a) false
          (k = zero_hex))
      before;
    (match Wallet.create_transaction w ~dest_address:dest ~amount:10_000L
             ~fee_rate:1.0 () with
     | Error e ->
       Alcotest.(check bool) ("unlocked spend gets past the lock: " ^ e)
         false (e = Wallet.wallet_locked_msg)
     | Ok _ -> ());
    Wallet.wallet_lock w;
    locked_spend_refused "after walletlock" w dest;
    Wallet.save w;
    let path = Wallet.wallet_path wm "w1" in
    let data = read_file path in
    Alcotest.(check bool) "instrument: file lists the address" true
      (contains data (fst (List.hd before)));
    Alcotest.(check bool) "file holds an encrypted master key" true
      (contains data "\"encrypted_master_key\"");
    Alcotest.(check bool) "no \"private_key\" on disk" false
      (contains data "\"private_key\"");
    List.iter (fun (a, k) ->
        Alcotest.(check bool) ("key of " ^ a ^ " not on disk") false
          (contains data k))
      before;
    ok_or_fail "unload" (Wallet.unload_wallet wm "w1");
    let w = ok_or_fail "load_wallet" (Wallet.load_wallet wm "w1") in
    Alcotest.(check bool) "reloaded encrypted" true (Wallet.is_encrypted w);
    Alcotest.(check bool) "reloaded locked" true (Wallet.is_locked w);
    locked_spend_refused "after reload" w dest;
    ok_or_fail "walletpassphrase after reload"
      (Wallet.wallet_passphrase w ~passphrase:"pw1" ~timeout:60.);
    Alcotest.(check (list (pair string string)))
      "every key decrypts after reload" before (key_table w))

(* The item's second half on its own: walletlock, then walletpassphrase
   with the createwallet passphrase, must unlock and give back real keys.
   (Before the fix: "Wallet encryption data is missing", keys zeroed.) *)
let test_lock_then_unlock () =
  Test_tmp.with_dir ~label:"cwpl_relock" ~mkdir:true (fun root ->
    let wm = manager root in
    let w = ok_or_fail "create_wallet"
        (Wallet.create_wallet wm "w1" ~options:(with_passphrase (Some "pw1"))
           ()) in
    (* a key to check, minted while unlocked *)
    ok_or_fail "first walletpassphrase"
      (Wallet.wallet_passphrase w ~passphrase:"pw1" ~timeout:60.);
    ignore (Wallet.get_new_address w);
    let before = key_table w in
    Wallet.wallet_lock w;
    ok_or_fail "walletpassphrase after walletlock"
      (Wallet.wallet_passphrase w ~passphrase:"pw1" ~timeout:60.);
    Alcotest.(check (list (pair string string)))
      "keys restored after walletlock + walletpassphrase" before
      (key_table w))

(* Core encrypts a blank wallet too (only the descriptor setup is skipped). *)
let test_blank_with_passphrase_locked () =
  Test_tmp.with_dir ~label:"cwpl_blank" ~mkdir:true (fun root ->
    let wm = manager root in
    let w = ok_or_fail "create_wallet"
        (Wallet.create_wallet wm "b1"
           ~options:(with_passphrase ~blank:true (Some "pw1")) ()) in
    Alcotest.(check bool) "blank: encrypted" true (Wallet.is_encrypted w);
    Alcotest.(check bool) "blank: key crypto" true (Wallet.has_key_crypto w);
    Alcotest.(check bool) "blank: locked" true (Wallet.is_locked w);
    Wallet.wallet_lock w;
    ok_or_fail "blank: walletpassphrase"
      (Wallet.wallet_passphrase w ~passphrase:"pw1" ~timeout:60.))

(* Control: no passphrase (or an empty one) leaves the wallet unencrypted
   and unlocked, as before and as in Core. *)
let test_no_passphrase_unchanged () =
  Test_tmp.with_dir ~label:"cwpl_ctl" ~mkdir:true (fun root ->
    let wm = manager root in
    List.iter (fun (name, p) ->
        let w = ok_or_fail "create_wallet"
            (Wallet.create_wallet wm name ~options:(with_passphrase p) ()) in
        Alcotest.(check bool) (name ^ ": not encrypted") false
          (Wallet.is_encrypted w);
        Alcotest.(check bool) (name ^ ": not locked") false
          (Wallet.is_locked w);
        ignore (Wallet.get_new_address w);
        Wallet.save w;
        Alcotest.(check bool) (name ^ ": plaintext key on disk") true
          (contains (read_file (Wallet.wallet_path wm name))
             "\"private_key\""))
      [ ("c_none", None); ("c_empty", Some "") ])

(* The gates key on encryption, not on the presence of key crypto: an
   encrypted, locked wallet without an encrypted master key (a whole-file
   encrypted file from an older build) must not spend or mint either. *)
let test_gates_key_on_encryption () =
  let dest = foreign_address () in
  let w = Wallet.create ~network:`Regtest ~db_path:"" in
  Wallet.init_from_mnemonic w mnemonic ();
  ignore (Wallet.get_new_address w);
  w.Wallet.encryption.Wallet.encrypted <- true;
  w.Wallet.encryption.Wallet.lock_state <- Wallet.Locked;
  Alcotest.(check bool) "instrument: no key crypto" false
    (Wallet.has_key_crypto w);
  locked_spend_refused "whole-file encrypted, locked" w dest;
  let n = List.length w.Wallet.keys in
  (match Wallet.generate_key w with
   | exception Failure _ -> ()
   | _ -> Alcotest.fail "minted a key on a locked encrypted wallet");
  Alcotest.(check int) "no key added" n (List.length w.Wallet.keys)

(* ---- node: the sequence over RPC on bin/main.exe (regtest) ----------- *)

let free_port () =
  let s = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Unix.bind s (Unix.ADDR_INET (Unix.inet_addr_loopback, 0));
  let p = match Unix.getsockname s with
    | Unix.ADDR_INET (_, p) -> p | _ -> assert false in
  Unix.close s; p

let main_exe =
  let p = Filename.concat (Sys.getcwd ()) "../../bin/main.exe" in
  if Sys.file_exists p then p else failwith ("missing " ^ p)

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
       let* _resp, b = Cohttp_lwt_unix.Client.post ~headers
           ~body:(Cohttp_lwt.Body.of_string body) uri in
       let* s = Cohttp_lwt.Body.to_string b in
       Lwt.return (try Yojson.Safe.from_string s with _ -> `String s))
    (fun _ -> Lwt.return `Null)

let field k = function
  | `Assoc l -> (try List.assoc k l with Not_found -> `Null)
  | _ -> `Null

let result_ok what r =
  match field "error" r with
  | `Null -> field "result" r
  | e -> failwith (Printf.sprintf "%s -> %s" what (Yojson.Safe.to_string e))

let error_code r =
  match field "code" (field "error" r) with `Int c -> c | _ -> 0

let error_message r =
  match field "message" (field "error" r) with `String m -> m | _ -> ""

let with_node root datadir ~run f =
  let rpcport = free_port () and p2pport = free_port () in
  let log = Filename.concat root (Printf.sprintf "node%d.log" run) in
  let fd = Unix.openfile log [Unix.O_WRONLY; Unix.O_CREAT; Unix.O_TRUNC]
      0o600 in
  let args = [| main_exe; "--network=regtest"; "--datadir=" ^ datadir;
                "--rpchost=127.0.0.1"; Printf.sprintf "--rpcport=%d" rpcport;
                Printf.sprintf "--port=%d" p2pport; "--metricsport=0";
                "--nodnsseed"; "--connect=127.0.0.1:1";
                "--fallbackfee=0.0002" |] in
  let pid = Unix.create_process main_exe args Unix.stdin fd fd in
  Unix.close fd;
  let cookie_path = Filename.concat datadir ".cookie" in
  (try Sys.remove cookie_path with _ -> ());
  let reap () =
    let rec wait n =
      match Unix.waitpid [Unix.WNOHANG] pid with
      | 0, _ when n > 0 -> Unix.sleepf 0.1; wait (n - 1)
      | 0, _ ->
        (* our own child, still up after 60 s: force it *)
        (try Unix.kill pid Sys.sigkill with _ -> ());
        ignore (Unix.waitpid [] pid)
      | _ -> ()
      | exception Unix.Unix_error (Unix.ECHILD, _, _) -> () in
    wait 600 in
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
          let* r = rpc ~port:rpcport ~cookie:ck "getblockcount" [] in
          match field "result" r with
          | `Int _ -> Lwt.return ck
          | _ -> let* () = Lwt_unix.sleep 0.2 in ready (n - 1) in
      let* ck = ready 600 in
      let* () = f (rpc ~port:rpcport ~cookie:ck) in
      let* _ = rpc ~port:rpcport ~cookie:ck "stop" [] in
      Lwt.return_unit))

let check_unlock_needed what r =
  Alcotest.(check int) (what ^ ": -13 (" ^ error_message r ^ ")") (-13)
    (error_code r);
  Alcotest.(check string) (what ^ ": Core's message")
    Wallet.wallet_locked_msg (error_message r)

let txid_of what r =
  match result_ok what r with
  | `String s when String.length s = 64 -> s
  | j -> failwith (what ^ ": no txid: " ^ Yojson.Safe.to_string j)

let load_tolerant rpc name =
  let open Lwt.Syntax in
  let* r = rpc "loadwallet" [`String name] in
  (match field "error" r with
   | `Null -> ()
   | _ when error_code r = -35 -> ()   (* already loaded at boot *)
   | e -> failwith ("loadwallet -> " ^ Yojson.Safe.to_string e));
  Lwt.return_unit

let test_node_createwallet_passphrase () =
  Test_tmp.with_dir ~label:"cwpl_node" ~mkdir:true (fun root ->
    let datadir = Filename.concat root "node" in
    let w0 = "/wallet/w0" and w1 = "/wallet/w1" in
    let dest = ref "" and a1 = ref "" and legacy = ref "" in
    let open Lwt.Syntax in
    with_node root datadir ~run:1 (fun rpc ->
      (* control wallet, no passphrase: supplies a foreign address *)
      let* r = rpc "createwallet" [`String "w0"] in
      ignore (result_ok "createwallet w0" r);
      let* r = rpc ~path:w0 "getnewaddress" [] in
      dest := (match result_ok "getnewaddress w0" r with
          | `String a -> a | _ -> failwith "getnewaddress: no address");
      let* r = rpc "createwallet"
          [`String "w1"; `Bool false; `Bool false; `String "s3cret"] in
      ignore (result_ok "createwallet w1 with passphrase" r);
      (* the item: no walletpassphrase yet, so a spend is -13 *)
      let* r = rpc ~path:w1 "sendtoaddress" [`String !dest; `Float 0.001] in
      check_unlock_needed "fresh passphrase wallet sendtoaddress" r;
      (* walletlock, then walletpassphrase, both succeed *)
      let* r = rpc ~path:w1 "walletlock" [] in
      ignore (result_ok "walletlock" r);
      let* r = rpc ~path:w1 "walletpassphrase" [`String "wrong"; `Int 60] in
      Alcotest.(check bool) "wrong passphrase refused" true
        (error_code r <> 0);
      let* r = rpc ~path:w1 "walletpassphrase" [`String "s3cret"; `Int 600] in
      ignore (result_ok "walletpassphrase after walletlock" r);
      (* unlocked: mint, mine a mature coin, spend it *)
      let* r = rpc ~path:w1 "getnewaddress" [] in
      a1 := (match result_ok "getnewaddress w1" r with
          | `String a -> a | _ -> failwith "getnewaddress: no address");
      let* r = rpc "generatetoaddress" [`Int 101; `String !a1] in
      ignore (result_ok "generatetoaddress" r);
      let* r = rpc ~path:w1 "sendtoaddress" [`String !dest; `Float 1.0] in
      ignore (txid_of "unlocked sendtoaddress" r);
      (* a P2PKH key, for signmessage after the restart *)
      let* r = rpc ~path:w1 "getnewaddress" [`String ""; `String "legacy"] in
      legacy := (match result_ok "getnewaddress legacy" r with
          | `String a -> a | _ -> failwith "getnewaddress: no address");
      let* r = rpc ~path:w1 "walletlock" [] in
      ignore (result_ok "walletlock after spend" r);
      let* r = rpc ~path:w1 "sendtoaddress" [`String !dest; `Float 1.0] in
      check_unlock_needed "relocked sendtoaddress" r;
      (* control: the unencrypted wallet is not gated and not encrypted *)
      let* r = rpc ~path:w0 "sendtoaddress" [`String !a1; `Float 0.001] in
      Alcotest.(check bool) "control: unencrypted wallet not -13" true
        (error_code r <> -13);
      let* r = rpc ~path:w0 "walletpassphrase" [`String "x"; `Int 60] in
      Alcotest.(check bool) "control: walletpassphrase on unencrypted fails"
        true (error_code r <> 0);
      Lwt.return_unit);
    let data = read_file (Filename.concat datadir "wallets/w1") in
    Alcotest.(check bool) "instrument: wallets/w1 lists the address" true
      (contains data !a1);
    Alcotest.(check bool) "wallets/w1 holds no plaintext private_key" false
      (contains data "\"private_key\"");
    with_node root datadir ~run:2 (fun rpc ->
      let* () = load_tolerant rpc "w1" in
      let* r = rpc ~path:w1 "sendtoaddress" [`String !dest; `Float 1.0] in
      check_unlock_needed "locked after restart" r;
      let* r = rpc ~path:w1 "walletpassphrase" [`String "s3cret"; `Int 60] in
      ignore (result_ok "walletpassphrase after restart" r);
      let* r = rpc ~path:w1 "getaddressinfo" [`String !a1] in
      Alcotest.(check string) "address still ismine after restart" "true"
        (Yojson.Safe.to_string (field "ismine" (result_ok "getaddressinfo" r)));
      (* the decrypted key is the real one: it signs for its address.
         (No second spend here: a restart re-lists a coin the wallet already
         spent, unencrypted wallets included, which is a separate bug.) *)
      let* r = rpc ~path:w1 "signmessage" [`String !legacy; `String "cwpl"] in
      let sg = match result_ok "signmessage after restart and unlock" r with
        | `String s -> s | _ -> failwith "signmessage: no signature" in
      let* r = rpc "verifymessage" [`String !legacy; `String sg; `String "cwpl"] in
      Alcotest.(check string) "the key signs after restart and unlock" "true"
        (Yojson.Safe.to_string (result_ok "verifymessage" r));
      Lwt.return_unit))

let () =
  Alcotest.run "createwallet_passphrase_lock" [
    "library", [
      Alcotest.test_case "createwallet passphrase: encrypted, locked" `Quick
        test_create_with_passphrase_locked;
      Alcotest.test_case "createwallet passphrase: walletlock, unlock" `Quick
        test_lock_then_unlock;
      Alcotest.test_case "blank createwallet passphrase: locked" `Quick
        test_blank_with_passphrase_locked;
      Alcotest.test_case "no passphrase: unchanged" `Quick
        test_no_passphrase_unchanged;
      Alcotest.test_case "locked gates key on encryption" `Quick
        test_gates_key_on_encryption;
    ];
    "node", [
      Alcotest.test_case "createwallet passphrase over RPC, restart" `Slow
        test_node_createwallet_passphrase;
    ];
  ]
