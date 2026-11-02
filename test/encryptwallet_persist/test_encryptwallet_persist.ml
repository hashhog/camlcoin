(* encryptwallet survives a save and a restart (fix-camlcoin-sec-h14).

   encrypt_wallet only changed memory: it zeroed the plaintext keys and kept
   the ciphertexts and the encrypted master key in a table that
   wallet_to_json never wrote.  The next Wallet.save (rescanblockchain,
   sethdseed, importdescriptors and shutdown all call it) wrote
   "private_key": "0000..." for every key; the load then failed and fell
   back to the boot .bak or to a fresh wallet, so every key made since the
   last boot was gone.  Without such a save, a restart silently dropped the
   encryption instead.  Core's EncryptWallet rewrites every key encrypted,
   with the master key, in one DB transaction.

   Library cases drive Wallet directly.  The node case is the audit's
   regtest repro over RPC on bin/main.exe. *)

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

(* (address, private key hex) for every key, in wallet order *)
let key_table w =
  List.map (fun kp ->
      (Address.address_to_string kp.Wallet.address,
       Wallet.cstruct_to_hex kp.Wallet.private_key))
    w.Wallet.keys

let zero_hex = String.make 64 '0'

(* A wallet on disk with one key of each type, then encrypted. *)
let encrypted_wallet root =
  let db_path = Filename.concat root "wallet.json" in
  let w = Wallet.create ~network:`Regtest ~db_path in
  Wallet.init_from_mnemonic w mnemonic ();
  List.iter (fun t -> ignore (Wallet.get_new_address_typed w t))
    [ Wallet.P2WPKH; Wallet.P2PKH; Wallet.P2SH_P2WPKH; Wallet.P2TR ];
  Wallet.save w;
  let before = key_table w in
  List.iter (fun (_, k) ->
      Alcotest.(check bool) "instrument: a real key" false (k = zero_hex))
    before;
  ok_or_fail "encrypt_wallet" (Wallet.encrypt_wallet w ~passphrase:"pw1");
  (db_path, w, before)

(* The file holds no plaintext key: neither the old field nor any key's
   hex.  The instrument check above makes sure there is hex to look for. *)
let check_no_plaintext db_path before =
  let data = read_file db_path in
  Alcotest.(check bool) "no \"private_key\" field on disk" false
    (contains data "\"private_key\"");
  List.iter (fun (a, k) ->
      Alcotest.(check bool) (Printf.sprintf "key of %s not on disk" a) false
        (contains data k))
    before

(* Reload from disk: encrypted, locked, same addresses; a wrong passphrase
   is refused and the right one restores every key. *)
let check_reload ~passphrase ?wrong db_path before =
  let w = Wallet.load ~network:`Regtest ~db_path in
  Alcotest.(check bool) "reloaded wallet is encrypted" true
    (Wallet.is_encrypted w);
  Alcotest.(check bool) "reloaded wallet is locked" true (Wallet.is_locked w);
  Alcotest.(check (list string)) "same addresses after reload"
    (List.map fst before) (List.map fst (key_table w));
  (match wrong with
   | Some p ->
     Alcotest.(check bool) "wrong passphrase refused" true
       (Result.is_error (Wallet.wallet_passphrase w ~passphrase:p ~timeout:60.))
   | None -> ());
  ok_or_fail "walletpassphrase after reload"
    (Wallet.wallet_passphrase w ~passphrase ~timeout:60.);
  Alcotest.(check (list (pair string string)))
    "every key recovered after walletpassphrase" before (key_table w);
  w

let test_encrypt_persists () =
  Test_tmp.with_dir ~label:"ewp_enc" ~mkdir:true (fun root ->
    let db_path, _w, before = encrypted_wallet root in
    check_no_plaintext db_path before;
    ignore (check_reload ~passphrase:"pw1" ~wrong:"nope" db_path before))

(* rescanblockchain / sethdseed / importdescriptors / shutdown call
   Wallet.save on a locked wallet; save_safe is the per-mutation path. *)
let test_locked_save () =
  Test_tmp.with_dir ~label:"ewp_save" ~mkdir:true (fun root ->
    let db_path, w, before = encrypted_wallet root in
    Wallet.save w;
    Wallet.save_safe w;
    Wallet.flush w;
    check_no_plaintext db_path before;
    ignore (check_reload ~passphrase:"pw1" db_path before))

(* A key made while unlocked is encrypted before the lock zeroes it. *)
let test_unlocked_key_survives () =
  Test_tmp.with_dir ~label:"ewp_newkey" ~mkdir:true (fun root ->
    let db_path, w, _ = encrypted_wallet root in
    ok_or_fail "unlock" (Wallet.wallet_passphrase w ~passphrase:"pw1"
                           ~timeout:60.);
    ignore (Wallet.get_new_address w);
    let before = key_table w in
    Wallet.save_safe w;
    check_no_plaintext db_path before;
    Wallet.wallet_lock w;
    Wallet.save w;
    check_no_plaintext db_path before;
    ignore (check_reload ~passphrase:"pw1" db_path before))

(* A key minted while locked (a regtest generate, a change key) has no
   ciphertext: it must never reach disk as plaintext, a lock must not
   destroy it, and the next unlock encrypts it so it survives a reload. *)
let test_locked_key_encrypted_at_unlock () =
  Test_tmp.with_dir ~label:"ewp_lockedkey" ~mkdir:true (fun root ->
    let db_path, w, before = encrypted_wallet root in
    let kp = Wallet.generate_key w in
    let secret = Wallet.cstruct_to_hex kp.Wallet.private_key in
    let before =
      before @ [ (Address.address_to_string kp.Wallet.address, secret) ] in
    Wallet.save w;
    check_no_plaintext db_path before;
    Wallet.wallet_lock w;
    Alcotest.(check string) "lock keeps the unencrypted new key" secret
      (Wallet.cstruct_to_hex kp.Wallet.private_key);
    ok_or_fail "unlock" (Wallet.wallet_passphrase w ~passphrase:"pw1"
                           ~timeout:60.);
    Wallet.wallet_lock w;
    Wallet.save w;
    check_no_plaintext db_path before;
    ignore (check_reload ~passphrase:"pw1" ~wrong:"nope" db_path before))

let test_passphrase_change_persists () =
  Test_tmp.with_dir ~label:"ewp_change" ~mkdir:true (fun root ->
    let db_path, w, before = encrypted_wallet root in
    ok_or_fail "walletpassphrasechange"
      (Wallet.wallet_passphrase_change w ~old_passphrase:"pw1"
         ~new_passphrase:"pw2");
    check_no_plaintext db_path before;
    ignore (check_reload ~passphrase:"pw2" ~wrong:"pw1" db_path before))

(* ---- node: the audit's sequence on bin/main.exe (regtest) ------------ *)

let free_port () =
  let s = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Unix.bind s (Unix.ADDR_INET (Unix.inet_addr_loopback, 0));
  let p = match Unix.getsockname s with
    | Unix.ADDR_INET (_, p) -> p | _ -> assert false in
  Unix.close s; p

let main_exe =
  let p = Filename.concat (Sys.getcwd ()) "../../bin/main.exe" in
  if Sys.file_exists p then p else failwith ("missing " ^ p)

(* POST one JSON-RPC call; returns the parsed reply, `Null on refusal. *)
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

(* Boot the node on [datadir], run [f port cookie], then stop it. *)
let with_node root datadir ~run f =
  let rpcport = free_port () and p2pport = free_port () in
  let log = Filename.concat root (Printf.sprintf "node%d.log" run) in
  let fd = Unix.openfile log [Unix.O_WRONLY; Unix.O_CREAT; Unix.O_TRUNC]
      0o600 in
  let args = [| main_exe; "--network=regtest"; "--datadir=" ^ datadir;
                "--rpchost=127.0.0.1"; Printf.sprintf "--rpcport=%d" rpcport;
                Printf.sprintf "--port=%d" p2pport; "--metricsport=0";
                "--nodnsseed"; "--connect=127.0.0.1:1" |] in
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

let test_node_restart () =
  Test_tmp.with_dir ~label:"ewp_node" ~mkdir:true (fun root ->
    let datadir = Filename.concat root "node" in
    let w1 = "/wallet/w1" in
    let addr = ref "" in
    let open Lwt.Syntax in
    with_node root datadir ~run:1 (fun rpc ->
      let* r = rpc "createwallet" [`String "w1"] in
      ignore (result_ok "createwallet" r);
      (* legacy: signmessage needs a P2PKH key *)
      let* r = rpc ~path:w1 "getnewaddress" [`String ""; `String "legacy"] in
      addr := (match result_ok "getnewaddress" r with
          | `String a -> a | _ -> failwith "getnewaddress: no address");
      let* r = rpc ~path:w1 "encryptwallet" [`String "s3cret"] in
      ignore (result_ok "encryptwallet" r);
      let* r = rpc ~path:w1 "rescanblockchain" [] in
      ignore (result_ok "rescanblockchain" r);
      Lwt.return_unit);
    let wfile = Filename.concat datadir "wallets/w1" in
    let data = read_file wfile in
    Alcotest.(check bool) "instrument: wallets/w1 lists the address" true
      (contains data !addr);
    Alcotest.(check bool) "wallets/w1 holds no plaintext private_key" false
      (contains data "\"private_key\"");
    with_node root datadir ~run:2 (fun rpc ->
      let* r = rpc "loadwallet" [`String "w1"] in
      (match field "error" r with
       | `Null -> ()
       | _ when error_code r = -35 -> ()   (* already loaded at boot *)
       | e -> failwith ("loadwallet -> " ^ Yojson.Safe.to_string e));
      let* r = rpc ~path:w1 "getaddressinfo" [`String !addr] in
      Alcotest.(check string) "address still ismine after restart" "true"
        (Yojson.Safe.to_string (field "ismine" (result_ok "getaddressinfo" r)));
      (* still encrypted: walletlock is only valid on an encrypted wallet *)
      let* r = rpc ~path:w1 "walletlock" [] in
      ignore (result_ok "walletlock (wallet still encrypted)" r);
      (* locked: a new key could not be stored encrypted (Core -12) *)
      let* r = rpc ~path:w1 "getnewaddress" [] in
      Alcotest.(check int) "locked getnewaddress refused (-12)" (-12)
        (error_code r);
      let* r = rpc ~path:w1 "walletpassphrase" [`String "wrong"; `Int 60] in
      Alcotest.(check bool) "wrong passphrase refused" true
        (error_code r <> 0);
      let* r = rpc ~path:w1 "walletpassphrase" [`String "s3cret"; `Int 60] in
      ignore (result_ok "walletpassphrase" r);
      let* r = rpc ~path:w1 "signmessage" [`String !addr; `String "h14"] in
      let sg = match result_ok "signmessage" r with
        | `String s -> s | _ -> failwith "signmessage: no signature" in
      let* r = rpc "verifymessage" [`String !addr; `String sg; `String "h14"] in
      Alcotest.(check string) "the address's key signs after unlock" "true"
        (Yojson.Safe.to_string (result_ok "verifymessage" r));
      Lwt.return_unit))

let () =
  Alcotest.run "encryptwallet_persist" [
    "library", [
      Alcotest.test_case "encrypt_wallet persists ciphertexts" `Quick
        test_encrypt_persists;
      Alcotest.test_case "locked save keeps every key" `Quick
        test_locked_save;
      Alcotest.test_case "key made while unlocked survives lock" `Quick
        test_unlocked_key_survives;
      Alcotest.test_case "key made while locked encrypted at unlock" `Quick
        test_locked_key_encrypted_at_unlock;
      Alcotest.test_case "walletpassphrasechange persists" `Quick
        test_passphrase_change_persists;
    ];
    "node", [
      Alcotest.test_case "encrypt, rescan, restart, unlock, sign" `Slow
        test_node_restart;
    ];
  ]
