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

(* A key minted while locked (a regtest generate, a change key) could only
   be saved with no secret and no ciphertext: a restart before the next
   unlock would load it as a zero key, ismine but unspendable.  So no path
   may mint one while locked (Core: keypool ran out / unlock needed), and
   the refusal leaves the wallet and its file unchanged. *)
let test_locked_mint_refused () =
  Test_tmp.with_dir ~label:"ewp_lockedkey" ~mkdir:true (fun root ->
    let db_path, w, before = encrypted_wallet root in
    let file_before = read_file db_path in
    let refused what f =
      (match f () with
       | exception Failure _ -> ()
       | _ -> Alcotest.fail (what ^ ": minted a key while locked"));
      Alcotest.(check int) (what ^ ": no key added")
        (List.length before) (List.length w.Wallet.keys) in
    refused "generate_key" (fun () -> ignore (Wallet.generate_key w));
    refused "generate_key_typed legacy"
      (fun () -> ignore (Wallet.generate_key_typed w Wallet.P2PKH));
    refused "generate_change_key"
      (fun () -> ignore (Wallet.generate_change_key w));
    refused "get_new_address" (fun () -> ignore (Wallet.get_new_address w));
    (match Wallet.create_transaction w
             ~dest_address:(fst (List.hd before)) ~amount:10_000L
             ~fee_rate:1.0 () with
     | Error e ->
       Alcotest.(check string) "create_transaction: unlock needed"
         "Error: Please enter the wallet passphrase with walletpassphrase \
          first." e
     | Ok _ -> Alcotest.fail "create_transaction while locked");
    Alcotest.(check int) "create_transaction: no change key added"
      (List.length before) (List.length w.Wallet.keys);
    Wallet.save w;
    Alcotest.(check string) "a refused mint leaves the file unchanged"
      file_before (read_file db_path);
    (* unlocked, minting works again and the key is saved encrypted *)
    ok_or_fail "unlock" (Wallet.wallet_passphrase w ~passphrase:"pw1"
                           ~timeout:60.);
    ignore (Wallet.generate_key w);
    let before = key_table w in
    Wallet.wallet_lock w;
    Wallet.save w;
    check_no_plaintext db_path before;
    ignore (check_reload ~passphrase:"pw1" ~wrong:"nope" db_path before))

(* [load] copies the wallet file to [.bak] on every clean load, so a wallet
   loaded and then encrypted had its plaintext keys beside the encrypted
   file, and a later unparseable file made [load] restore that copy and
   drop the encryption.  After encrypt_wallet, no file next to the wallet
   may hold a plaintext key. *)
let test_load_encrypt_backup_scrubbed () =
  Test_tmp.with_dir ~label:"ewp_bak" ~mkdir:true (fun root ->
    let db_path = Filename.concat root "wallet.json" in
    let w = Wallet.create ~network:`Regtest ~db_path in
    Wallet.init_from_mnemonic w mnemonic ();
    List.iter (fun t -> ignore (Wallet.get_new_address_typed w t))
      [ Wallet.P2WPKH; Wallet.P2PKH; Wallet.P2SH_P2WPKH; Wallet.P2TR ];
    Wallet.save w;
    let before = key_table w in
    let w = Wallet.load ~network:`Regtest ~db_path in
    let bak = db_path ^ ".bak" and tmp = db_path ^ ".tmp" in
    (* instrument: the load wrote a .bak, and it holds the keys in clear *)
    Alcotest.(check bool) "instrument: load wrote .bak" true
      (Sys.file_exists bak);
    Alcotest.(check bool) "instrument: .bak holds a key's hex" true
      (contains (read_file bak) (snd (List.hd before)));
    ok_or_fail "encrypt_wallet" (Wallet.encrypt_wallet w ~passphrase:"pw1");
    List.iter (fun p ->
        if Sys.file_exists p then begin
          let data = read_file p in
          Alcotest.(check bool) (Filename.basename p ^ ": no private_key")
            false (contains data "\"private_key\"");
          List.iter (fun (a, k) ->
              Alcotest.(check bool)
                (Printf.sprintf "%s: key of %s absent"
                   (Filename.basename p) a) false (contains data k))
            before
        end)
      [ db_path; bak; tmp ];
    Alcotest.(check bool) "no .tmp left" false (Sys.file_exists tmp);
    (* the fallback path: an unparseable wallet file recovers from .bak,
       which must give back the encrypted wallet, not the plaintext one *)
    let oc = open_out_bin db_path in
    output_string oc "{\"truncated"; close_out oc;
    ignore (check_reload ~passphrase:"pw1" ~wrong:"nope" db_path before);
    check_no_plaintext db_path before)

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

(* The locked mint over RPC, with a restart between it and the unlock:
   a regtest generate on the locked wallet must be refused (-12) and a
   sendtoaddress, whose change key is minted the same way, must be refused
   (-13), so nothing reaches disk without a ciphertext.  After the restart
   the unlocked wallet mints and mines normally, and every key in the file
   decrypts to a real secret. *)
let test_node_locked_mint_restart () =
  Test_tmp.with_dir ~label:"ewp_node_mint" ~mkdir:true (fun root ->
    let datadir = Filename.concat root "node" in
    let w1 = "/wallet/w1" in
    let addr = ref "" in
    let open Lwt.Syntax in
    with_node root datadir ~run:1 (fun rpc ->
      let* r = rpc "createwallet" [`String "w1"] in
      ignore (result_ok "createwallet" r);
      let* r = rpc ~path:w1 "getnewaddress" [] in
      addr := (match result_ok "getnewaddress" r with
          | `String a -> a | _ -> failwith "getnewaddress: no address");
      let* r = rpc ~path:w1 "encryptwallet" [`String "s3cret"] in
      ignore (result_ok "encryptwallet" r);
      Lwt.return_unit);
    let wfile = Filename.concat datadir "wallets/w1" in
    let keys_in_file () =
      match Yojson.Safe.from_string (read_file wfile) with
      | `Assoc l ->
        (match List.assoc_opt "keys" l with Some (`List ks) -> ks | _ -> [])
      | _ -> [] in
    let n_keys = List.length (keys_in_file ()) in
    Alcotest.(check bool) "instrument: the wallet file lists keys" true
      (n_keys > 0);
    with_node root datadir ~run:2 (fun rpc ->
      let* r = rpc "loadwallet" [`String "w1"] in
      (match field "error" r with
       | `Null -> ()
       | _ when error_code r = -35 -> ()
       | e -> failwith ("loadwallet -> " ^ Yojson.Safe.to_string e));
      let* r = rpc ~path:w1 "walletlock" [] in
      ignore (result_ok "walletlock" r);
      let* r = rpc ~path:w1 "generate" [`Int 1] in
      Alcotest.(check int) "locked generate refused (-12)" (-12)
        (error_code r);
      let* r = rpc ~path:w1 "sendtoaddress" [`String !addr; `Float 0.001] in
      Alcotest.(check int) "locked sendtoaddress refused (-13)" (-13)
        (error_code r);
      Lwt.return_unit);
    let keys = keys_in_file () in
    Alcotest.(check int) "no key added by the locked calls" n_keys
      (List.length keys);
    List.iter (fun k ->
        Alcotest.(check bool) "every key on disk has a ciphertext" true
          (field "crypted_key" k <> `Null))
      keys;
    with_node root datadir ~run:3 (fun rpc ->
      let* r = rpc "loadwallet" [`String "w1"] in
      (match field "error" r with
       | `Null -> ()
       | _ when error_code r = -35 -> ()
       | e -> failwith ("loadwallet -> " ^ Yojson.Safe.to_string e));
      let* r = rpc ~path:w1 "walletpassphrase" [`String "s3cret"; `Int 60] in
      ignore (result_ok "walletpassphrase" r);
      let* r = rpc ~path:w1 "generate" [`Int 1] in
      ignore (result_ok "unlocked generate" r);
      Lwt.return_unit);
    let keys = keys_in_file () in
    Alcotest.(check int) "the unlocked generate minted one key" (n_keys + 1)
      (List.length keys);
    List.iter (fun k ->
        Alcotest.(check bool) "every key on disk has a ciphertext" true
          (field "crypted_key" k <> `Null))
      keys;
    let w = Wallet.load ~network:`Regtest ~db_path:wfile in
    ok_or_fail "walletpassphrase on the file"
      (Wallet.wallet_passphrase w ~passphrase:"s3cret" ~timeout:60.);
    List.iter (fun (a, k) ->
        Alcotest.(check bool) (Printf.sprintf "key of %s decrypts" a) false
          (k = zero_hex))
      (key_table w))

(* Funding on a locked wallet, in Core's terms.  Core's FundTransaction and
   send never call EnsureWalletIsUnlocked: a locked fund that needs no change
   output returns the funded transaction (wallet_fundrawtransaction.py
   test_locked_wallet asserts changepos -1), one that needs a change key
   fails -4 "Transaction needs a change address, but we can't generate it."
   (wallet/spend.cpp CreateTransactionInternal), and a locked send with no
   fee estimate and -fallbackfee off fails -4 on the fee before anything
   about the lock.  None of them may add a key to the file. *)
let test_node_locked_funding () =
  Test_tmp.with_dir ~label:"ewp_node_fund" ~mkdir:true (fun root ->
    let datadir = Filename.concat root "node" in
    let w1 = "/wallet/w1" in
    let wfile = Filename.concat datadir "wallets/w1" in
    let n_keys_in_file () =
      match Yojson.Safe.from_string (read_file wfile) with
      | `Assoc l ->
        (match List.assoc_opt "keys" l with
         | Some (`List ks) -> List.length ks | _ -> 0)
      | _ -> 0 in
    let error_message r =
      match field "message" (field "error" r) with `String m -> m | _ -> "" in
    let change_msg =
      "Transaction needs a change address, but we can't generate it." in
    let starts_with ~prefix s =
      String.length s >= String.length prefix
      && String.sub s 0 (String.length prefix) = prefix in
    let open Lwt.Syntax in
    with_node root datadir ~run:1 (fun rpc ->
      let* r = rpc "createwallet" [`String "w1"] in
      ignore (result_ok "createwallet" r);
      let* r = rpc ~path:w1 "getnewaddress" [] in
      let addr = match result_ok "getnewaddress" r with
        | `String a -> a | _ -> failwith "getnewaddress: no address" in
      (* one mature 50 BTC coinbase *)
      let* r = rpc "generatetoaddress" [`Int 101; `String addr] in
      ignore (result_ok "generatetoaddress" r);
      let* r = rpc ~path:w1 "encryptwallet" [`String "s3cret"] in
      ignore (result_ok "encryptwallet" r);
      let* r = rpc ~path:w1 "walletlock" [] in
      ignore (result_ok "walletlock" r);
      let n_keys = n_keys_in_file () in
      Alcotest.(check bool) "instrument: the wallet file lists keys" true
        (n_keys > 0);
      let fee = `Assoc ["fee_rate", `Int 1] in
      (* 1 BTC out of a 50 BTC coin: needs a change key *)
      let* r = rpc ~path:w1 "createrawtransaction"
          [`List []; `Assoc [addr, `Float 1.0]] in
      let raw = result_ok "createrawtransaction" r in
      let* r = rpc ~path:w1 "fundrawtransaction" [raw; fee] in
      Alcotest.(check int) "locked fundrawtransaction needing change (-4)"
        (-4) (error_code r);
      Alcotest.(check bool)
        ("fundrawtransaction: Core's change message, got: "
         ^ error_message r) true
        (starts_with ~prefix:change_msg (error_message r));
      let* r = rpc ~path:w1 "walletcreatefundedpsbt"
          [`List []; `List [`Assoc [addr, `Float 1.0]]; `Int 0; fee] in
      Alcotest.(check int) "locked walletcreatefundedpsbt needing change (-4)"
        (-4) (error_code r);
      Alcotest.(check bool)
        ("walletcreatefundedpsbt: Core's change message, got: "
         ^ error_message r) true
        (starts_with ~prefix:change_msg (error_message r));
      (* all but 600 sat of the coin: the leftover after a 1 sat/vB fee is
         dust, so no change output and no key are needed *)
      let* r = rpc ~path:w1 "createrawtransaction"
          [`List []; `Assoc [addr, `Float 49.999994]] in
      let raw = result_ok "createrawtransaction" r in
      let* r = rpc ~path:w1 "fundrawtransaction" [raw; fee] in
      let funded = result_ok "locked changeless fundrawtransaction" r in
      Alcotest.(check string) "changeless fund: changepos -1" "-1"
        (Yojson.Safe.to_string (field "changepos" funded));
      (* send, no estimate, -fallbackfee off: the fee fails first *)
      let* r = rpc ~path:w1 "send" [`List [`Assoc [addr, `Float 1.0]]] in
      Alcotest.(check int) "locked send without a fee: -4 on the fee" (-4)
        (error_code r);
      Alcotest.(check bool)
        ("locked send: fee estimation message, got: " ^ error_message r) true
        (starts_with ~prefix:"Fee estimation failed" (error_message r));
      Alcotest.(check int) "no key added by the locked calls" n_keys
        (n_keys_in_file ());
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
      Alcotest.test_case "no key minted while locked" `Quick
        test_locked_mint_refused;
      Alcotest.test_case "load, encrypt: no plaintext in .bak or .tmp" `Quick
        test_load_encrypt_backup_scrubbed;
      Alcotest.test_case "walletpassphrasechange persists" `Quick
        test_passphrase_change_persists;
    ];
    "node", [
      Alcotest.test_case "encrypt, rescan, restart, unlock, sign" `Slow
        test_node_restart;
      Alcotest.test_case "locked generate refused across a restart" `Slow
        test_node_locked_mint_restart;
      Alcotest.test_case "locked funding: Core's -4, no key" `Slow
        test_node_locked_funding;
    ];
  ]
