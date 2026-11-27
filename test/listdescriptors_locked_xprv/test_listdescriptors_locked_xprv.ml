(* listdescriptors true on a locked encrypted wallet
   (cffix-camlcoin-listdescriptors-locked-xprv).

   The wallet's HD master (w.master_key: the BIP-32 private key and chain
   code) was set by createwallet / sethdseed and never touched by
   encrypt_wallet or wallet_lock: every other private key was zeroed, the
   one they all derive from stayed in memory in plaintext.
   handle_listdescriptors serialized it as an xprv for include_private with
   no lock check, so createwallet, encryptwallet, walletlock,
   listdescriptors true handed out every key of the "locked" wallet.

   Core: listdescriptors calls EnsureWalletIsUnlocked when private=true
   (wallet/rpc/backup.cpp), RPC_WALLET_UNLOCK_NEEDED (-13), and a locked
   descriptor wallet holds only encrypted keys.  The encryptwallet reply also
   said "a new HD seed was generated", which camlcoin does not do.

   Library cases drive Wallet directly.  The node case is the audit's
   sequence over RPC on bin/main.exe. *)

open Camlcoin

let contains hay needle =
  try ignore (Str.search_forward (Str.regexp_string needle) hay 0); true
  with Not_found -> false

let ok_or_fail what = function
  | Ok x -> x
  | Error e -> Alcotest.fail (what ^ ": " ^ e)

let mnemonic =
  "abandon abandon abandon abandon abandon abandon \
   abandon abandon abandon abandon abandon about"

let hd w =
  match w.Wallet.master_key with
  | Some ek -> ek
  | None -> Alcotest.fail "wallet has no HD master"

(* hex of the HD master's key field: the 32-byte secret while it is held *)
let hd_key_hex w = Wallet.cstruct_to_hex (hd w).Wallet.key

let hd_xpub w = Wallet.serialize_xpub (hd w)

let check_hd_secret_gone what w secret =
  Alcotest.(check bool) (what ^ ": HD private key not in memory") false
    (contains (hd_key_hex w) secret)

let check_hd_secret_back what w secret =
  Alcotest.(check string) (what ^ ": HD private key restored") secret
    (hd_key_hex w)

(* A wallet from a known mnemonic, with a key of each type. *)
let hd_wallet () =
  let w = Wallet.create ~network:`Regtest ~db_path:"" in
  Wallet.init_from_mnemonic w mnemonic ();
  List.iter (fun t -> ignore (Wallet.get_new_address_typed w t))
    [ Wallet.P2WPKH; Wallet.P2PKH; Wallet.P2SH_P2WPKH; Wallet.P2TR ];
  let secret = hd_key_hex w and xpub = hd_xpub w in
  Alcotest.(check int) "instrument: HD key is a 32-byte secret" 64
    (String.length secret);
  Alcotest.(check bool) "instrument: the secret is not zero" false
    (secret = String.make 64 '0');
  (w, secret, xpub)

let test_encrypt_drops_hd_key () =
  let w, secret, xpub = hd_wallet () in
  ok_or_fail "encrypt_wallet" (Wallet.encrypt_wallet w ~passphrase:"pw1");
  Alcotest.(check bool) "locked after encryptwallet" true (Wallet.is_locked w);
  check_hd_secret_gone "after encryptwallet" w secret;
  (* the public half stays: listdescriptors (no private) and the
     fingerprint keep working while locked, as in Core *)
  Alcotest.(check string) "xpub unchanged while locked" xpub (hd_xpub w);
  Alcotest.(check bool) "wallet still reports an HD seed" true
    (Option.is_some w.Wallet.master_key)

let test_lock_unlock_cycle () =
  let w, secret, xpub = hd_wallet () in
  ok_or_fail "encrypt_wallet" (Wallet.encrypt_wallet w ~passphrase:"pw1");
  for i = 1 to 2 do
    let tag = Printf.sprintf "cycle %d" i in
    ok_or_fail "walletpassphrase"
      (Wallet.wallet_passphrase w ~passphrase:"pw1" ~timeout:60.);
    check_hd_secret_back (tag ^ " unlocked") w secret;
    Wallet.wallet_lock w;
    check_hd_secret_gone (tag ^ " after walletlock") w secret;
    Alcotest.(check string) (tag ^ ": xpub unchanged") xpub (hd_xpub w)
  done

let test_wrong_passphrase_keeps_locked () =
  let w, secret, _ = hd_wallet () in
  ok_or_fail "encrypt_wallet" (Wallet.encrypt_wallet w ~passphrase:"pw1");
  Alcotest.(check bool) "wrong passphrase refused" true
    (Result.is_error
       (Wallet.wallet_passphrase w ~passphrase:"nope" ~timeout:60.));
  check_hd_secret_gone "after a wrong passphrase" w secret

(* The restored HD key derives the same chain: an unlocked encrypted
   wallet hands out the addresses an unencrypted twin would. *)
let test_unlocked_derivation_unchanged () =
  let w0, _, _ = hd_wallet () in
  let w1, _, _ = hd_wallet () in
  ok_or_fail "encrypt_wallet" (Wallet.encrypt_wallet w1 ~passphrase:"pw1");
  ok_or_fail "walletpassphrase"
    (Wallet.wallet_passphrase w1 ~passphrase:"pw1" ~timeout:60.);
  Wallet.wallet_lock w1;
  ok_or_fail "walletpassphrase again"
    (Wallet.wallet_passphrase w1 ~passphrase:"pw1" ~timeout:60.);
  let next w =
    List.map (fun t -> Wallet.get_new_address_typed w t)
      [ Wallet.P2WPKH; Wallet.P2PKH; Wallet.P2SH_P2WPKH; Wallet.P2TR;
        Wallet.P2WPKH ] in
  Alcotest.(check (list string)) "same receive addresses as the plain twin"
    (next w0) (next w1);
  let change w =
    List.map (fun _ ->
        Address.address_to_string (Wallet.generate_change_key w).Wallet.address)
      [ 1; 2 ] in
  Alcotest.(check (list string)) "same change addresses as the plain twin"
    (change w0) (change w1)

(* No key may come out of the locked HD master. *)
let test_locked_no_mint () =
  let w, _, _ = hd_wallet () in
  ok_or_fail "encrypt_wallet" (Wallet.encrypt_wallet w ~passphrase:"pw1");
  let n = List.length w.Wallet.keys in
  (match Wallet.generate_key w with
   | exception Failure _ -> ()
   | _ -> Alcotest.fail "minted a key while locked");
  Alcotest.(check int) "no key added" n (List.length w.Wallet.keys)

(* sethdseed while unlocked: the new seed is the one that gets locked away
   and comes back, not the seed encryptwallet saw. *)
let test_sethdseed_then_lock () =
  let w, _, _ = hd_wallet () in
  ok_or_fail "encrypt_wallet" (Wallet.encrypt_wallet w ~passphrase:"pw1");
  ok_or_fail "walletpassphrase"
    (Wallet.wallet_passphrase w ~passphrase:"pw1" ~timeout:60.);
  Wallet.set_hd_seed w (Cstruct.of_string (String.make 32 '\x07'));
  let secret2 = hd_key_hex w and xpub2 = hd_xpub w in
  Wallet.wallet_lock w;
  check_hd_secret_gone "new seed after walletlock" w secret2;
  Alcotest.(check string) "new seed's xpub while locked" xpub2 (hd_xpub w);
  ok_or_fail "walletpassphrase"
    (Wallet.wallet_passphrase w ~passphrase:"pw1" ~timeout:60.);
  check_hd_secret_back "new seed after walletpassphrase" w secret2

(* An unlock that ran out is noticed lazily (is_locked flips the state to
   Locked without zeroing); the relock timer then calls wallet_lock on a
   wallet already marked Locked, and that must still drop the HD key. *)
let test_expired_unlock_then_lock () =
  let w, secret, _ = hd_wallet () in
  ok_or_fail "encrypt_wallet" (Wallet.encrypt_wallet w ~passphrase:"pw1");
  ok_or_fail "walletpassphrase"
    (Wallet.wallet_passphrase w ~passphrase:"pw1" ~timeout:0.05);
  check_hd_secret_back "unlocked" w secret;
  Unix.sleepf 0.1;
  Alcotest.(check bool) "instrument: the unlock expired" true
    (Wallet.is_locked w);
  Wallet.wallet_lock w;
  check_hd_secret_gone "after the expired unlock's walletlock" w secret;
  ok_or_fail "walletpassphrase"
    (Wallet.wallet_passphrase w ~passphrase:"pw1" ~timeout:60.);
  check_hd_secret_back "unlocked again" w secret

let test_passphrase_change () =
  let w, secret, _ = hd_wallet () in
  ok_or_fail "encrypt_wallet" (Wallet.encrypt_wallet w ~passphrase:"pw1");
  ok_or_fail "walletpassphrasechange"
    (Wallet.wallet_passphrase_change w ~old_passphrase:"pw1"
       ~new_passphrase:"pw2");
  check_hd_secret_gone "after walletpassphrasechange" w secret;
  ok_or_fail "walletpassphrase pw2"
    (Wallet.wallet_passphrase w ~passphrase:"pw2" ~timeout:60.);
  check_hd_secret_back "unlocked with the new passphrase" w secret

(* ---- node: the audit's sequence on bin/main.exe (regtest) ------------ *)

let read_file p =
  let ic = open_in_bin p in
  Fun.protect ~finally:(fun () -> close_in ic)
    (fun () -> really_input_string ic (in_channel_length ic))

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

let error_message r =
  match field "message" (field "error" r) with `String m -> m | _ -> ""

(* Boot the node on [datadir], run [f rpc], then stop it. *)
let with_node root datadir f =
  let rpcport = free_port () and p2pport = free_port () in
  let log = Filename.concat root "node.log" in
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

let descs what r =
  match field "descriptors" (result_ok what r) with
  | `List l ->
    List.map (fun d -> match field "desc" d with
        | `String s -> s | _ -> failwith (what ^ ": desc not a string")) l
  | _ -> failwith (what ^ ": no descriptors list")

let unlock_needed_msg =
  "Error: Please enter the wallet passphrase with walletpassphrase first."

let test_node_locked_listdescriptors () =
  Test_tmp.with_dir ~label:"ldx_node" ~mkdir:true (fun root ->
    let datadir = Filename.concat root "node" in
    let w1 = "/wallet/w1" in
    let open Lwt.Syntax in
    with_node root datadir (fun rpc ->
      let* r = rpc "createwallet" [`String "w1"] in
      ignore (result_ok "createwallet" r);
      let* r = rpc ~path:w1 "listdescriptors" [`Bool true] in
      let priv = descs "listdescriptors true (unencrypted)" r in
      let* r = rpc ~path:w1 "listdescriptors" [] in
      let pub = descs "listdescriptors (unencrypted)" r in
      Alcotest.(check bool) "instrument: the wallet has descriptors" true
        (priv <> []);
      Alcotest.(check bool) "instrument: private descriptors carry an xprv"
        true (List.for_all (fun d -> contains d "xprv") priv);
      let* r = rpc ~path:w1 "encryptwallet" [`String "s3cret"] in
      let reply = match result_ok "encryptwallet" r with
        | `String s -> s | _ -> failwith "encryptwallet: no message" in
      let check_refused what =
        let* r = rpc ~path:w1 "listdescriptors" [`Bool true] in
        Alcotest.(check int) (what ^ ": listdescriptors true is -13") (-13)
          (error_code r);
        Alcotest.(check string) (what ^ ": Core's unlock message")
          unlock_needed_msg (error_message r);
        Alcotest.(check bool) (what ^ ": no xprv in the reply") false
          (contains (Yojson.Safe.to_string r) "xprv");
        let* r = rpc ~path:w1 "listdescriptors" [] in
        Alcotest.(check (list string))
          (what ^ ": listdescriptors (public) still answers") pub
          (descs (what ^ ": listdescriptors") r);
        Lwt.return_unit in
      let* () = check_refused "after encryptwallet" in
      let* r = rpc ~path:w1 "walletlock" [] in
      ignore (result_ok "walletlock" r);
      let* () = check_refused "after walletlock" in
      let* r = rpc ~path:w1 "walletpassphrase" [`String "s3cret"; `Int 60] in
      ignore (result_ok "walletpassphrase" r);
      let* r = rpc ~path:w1 "listdescriptors" [`Bool true] in
      Alcotest.(check (list string))
        "unlocked: listdescriptors true gives the same xprv descriptors" priv
        (descs "listdescriptors true (unlocked)" r);
      let* r = rpc ~path:w1 "walletlock" [] in
      ignore (result_ok "walletlock" r);
      let* () = check_refused "after relock" in
      (* camlcoin keeps the existing seed; the reply must not say otherwise *)
      Alcotest.(check bool)
        ("encryptwallet reply does not claim a new HD seed: " ^ reply) false
        (contains reply "a new HD seed was generated");
      Lwt.return_unit))

let () =
  Alcotest.run "listdescriptors_locked_xprv" [
    "library", [
      Alcotest.test_case "encryptwallet drops the plaintext HD key" `Quick
        test_encrypt_drops_hd_key;
      Alcotest.test_case "walletlock drops it, walletpassphrase restores it"
        `Quick test_lock_unlock_cycle;
      Alcotest.test_case "wrong passphrase restores nothing" `Quick
        test_wrong_passphrase_keeps_locked;
      Alcotest.test_case "unlocked: HD derivation unchanged" `Quick
        test_unlocked_derivation_unchanged;
      Alcotest.test_case "locked: no key minted" `Quick test_locked_no_mint;
      Alcotest.test_case "sethdseed while unlocked, then lock" `Quick
        test_sethdseed_then_lock;
      Alcotest.test_case "expired unlock, then walletlock" `Quick
        test_expired_unlock_then_lock;
      Alcotest.test_case "walletpassphrasechange keeps it locked" `Quick
        test_passphrase_change;
    ];
    "node", [
      Alcotest.test_case "createwallet, encryptwallet, walletlock, \
                          listdescriptors true is -13" `Slow
        test_node_locked_listdescriptors;
    ];
  ]
