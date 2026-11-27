(* signrawtransactionwithwallet and signmessage on a locked wallet
   (cffix-camlcoin-sign-rpcs-unlock).

   Neither handler checked the lock.  On its own that only produced a
   garbage answer for a wallet locked by walletlock (its keys are zeroed),
   but an unlock that ran out was different: Wallet.is_locked noticed the
   expiry and set lock_state to Locked without zeroing a single key, and the
   walletpassphrase timer then saw an already-Locked wallet and did nothing.
   So after walletpassphrase <pw> 1 and one is_locked call, every private
   key stayed in memory and signmessage / signrawtransactionwithwallet
   signed with them.

   Core: both call EnsureWalletIsUnlocked (wallet/rpc/spend.cpp
   signrawtransactionwithwallet, after DecodeHexTx; wallet/rpc/signmessage.cpp
   signmessage, before the address is parsed) -> RPC_WALLET_UNLOCK_NEEDED
   (-13), "Error: Please enter the wallet passphrase with walletpassphrase
   first."  CWallet::Lock is the only way a wallet becomes locked, and it
   drops the keys.

   The expiry is forced by setting the unlock deadline in the past (the
   lock_state field is the test hook): sleeping out a real timeout would
   race the Lwt timer, which never runs here anyway. *)

open Camlcoin

let ok_or_fail what = function
  | Ok x -> x
  | Error e -> Alcotest.fail (what ^ ": " ^ e)

let mnemonic =
  "abandon abandon abandon abandon abandon abandon \
   abandon abandon abandon abandon abandon about"

let passphrase = "pw1"
let locked_msg =
  "Error: Please enter the wallet passphrase with walletpassphrase first."

let db_root = Test_tmp.register "/tmp/camlcoin_test_sign_rpcs_unlock"

let rec rm_rf path =
  if Sys.file_exists path then
    if Sys.is_directory path then begin
      Array.iter (fun f -> rm_rf (Filename.concat path f)) (Sys.readdir path);
      Unix.rmdir path
    end else Unix.unlink path

let fresh_dir name =
  if not (Sys.file_exists db_root) then Unix.mkdir db_root 0o755;
  let d = Filename.concat db_root name in
  rm_rf d;
  Unix.mkdir d 0o755;
  d

let is_zero cs =
  let z = ref true in
  for i = 0 to Cstruct.length cs - 1 do
    if Cstruct.get_uint8 cs i <> 0 then z := false
  done;
  !z

(* A wallet with a P2PKH (signmessage) and a P2WPKH key; encrypted unless
   [~encrypt:false].  Returns the wallet and its P2PKH address. *)
let make_wallet ?(encrypt = true) name =
  let dir = fresh_dir name in
  let w = Wallet.create ~network:`Regtest
      ~db_path:(Filename.concat dir "wallet.json") in
  Wallet.init_from_mnemonic w mnemonic ();
  let p2pkh = Wallet.get_new_address_typed w Wallet.P2PKH in
  ignore (Wallet.get_new_address_typed w Wallet.P2WPKH);
  List.iter (fun kp ->
      Alcotest.(check bool) "instrument: a real key before encryption" false
        (is_zero kp.Wallet.private_key))
    w.Wallet.keys;
  if encrypt then
    ok_or_fail "encrypt_wallet" (Wallet.encrypt_wallet w ~passphrase);
  (w, p2pkh, dir)

let make_ctx dir wallet : Rpc.rpc_context * Storage.ChainDB.t =
  let db = Storage.ChainDB.create (Filename.concat dir "chain") in
  let utxo = Utxo.UtxoSet.create db in
  let mp = Mempool.create ~network:Consensus.regtest
      ~require_standard:false ~verify_scripts:false ~utxo ~current_height:0 () in
  let chain = Sync.create_chain_state db Consensus.regtest in
  let pm = Peer_manager.create Consensus.regtest in
  let fe = Fee_estimation.create () in
  let ctx : Rpc.rpc_context = {
    chain; mempool = mp; peer_manager = pm;
    wallet = Some wallet; wallet_manager = None; fee_estimator = fe;
    network = Consensus.regtest; filter_index = None; utxo = None;
    data_dir = None; snapshot_activation = None;
  } in
  (ctx, db)

(* Unlock for 1 s, then move the deadline into the past: the state a
   walletpassphrase <pw> 1 leaves once the second is up. *)
let unlock_then_expire w =
  ok_or_fail "walletpassphrase"
    (Wallet.wallet_passphrase w ~passphrase ~timeout:1.0);
  List.iter (fun kp ->
      Alcotest.(check bool) "instrument: unlock restored the key" false
        (is_zero kp.Wallet.private_key))
    w.Wallet.keys;
  match w.Wallet.encryption.lock_state with
  | Wallet.Unlocked { master_key; _ } ->
    w.Wallet.encryption.lock_state <-
      Wallet.Unlocked { master_key; expires = Unix.gettimeofday () -. 10.0 }
  | Wallet.Locked -> Alcotest.fail "instrument: walletpassphrase left it locked"

(* An unsigned tx spending an outpoint no wallet holds: Core gates before
   it looks at the inputs, so the lock answer must not depend on them. *)
let raw_unsigned =
  "0200000001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
   0000000000fdffffff01a086010000000000160014751e76e8199196d454941c45d1b3a323\
   f1433bd600000000"

let expect_locked label = function
  | Error (code, msg) ->
    Alcotest.(check int) (label ^ ": RPC_WALLET_UNLOCK_NEEDED") (-13) code;
    Alcotest.(check string) (label ^ ": message") locked_msg msg
  | Ok j ->
    Alcotest.failf "%s: expected -13 on a locked wallet, got Ok %s"
      label (Yojson.Safe.to_string j)

let signmessage ctx addr =
  Rpc.dispatch_rpc ctx "signmessage" [`String addr; `String "hello"]

let signraw ctx =
  Rpc.dispatch_rpc ctx "signrawtransactionwithwallet" [`String raw_unsigned]

let with_ctx name ?encrypt f =
  let (w, addr, dir) = make_wallet ?encrypt name in
  let (ctx, db) = make_ctx dir w in
  Fun.protect ~finally:(fun () -> Storage.ChainDB.close db)
    (fun () -> f w addr ctx)

(* ---- the lazy expiry ------------------------------------------------- *)

(* The item's test: walletpassphrase 1, the deadline passes, is_locked.
   Locked must mean the keys are gone, as after walletlock. *)
let test_expiry_zeroes_keys () =
  with_ctx "expiry_zeroes" (fun w _ _ ->
      unlock_then_expire w;
      Alcotest.(check bool) "is_locked after the deadline" true
        (Wallet.is_locked w);
      List.iter (fun kp ->
          Alcotest.(check bool)
            (Printf.sprintf "key of %s zeroed by the expiry"
               (Address.address_to_string kp.Wallet.address))
            true (is_zero kp.Wallet.private_key))
        w.Wallet.keys)

(* The zeroing must not cost a key: one minted during the unlock (it has no
   ciphertext yet) comes back from the next walletpassphrase. *)
let test_expiry_keeps_new_keys_recoverable () =
  with_ctx "expiry_new_key" (fun w _ _ ->
      ok_or_fail "walletpassphrase"
        (Wallet.wallet_passphrase w ~passphrase ~timeout:1.0);
      let addr = Wallet.get_new_address_typed w Wallet.P2PKH in
      let secret =
        match Wallet.find_by_address w addr with
        | Some kp -> Cstruct.to_string kp.Wallet.private_key
        | None -> Alcotest.fail "minted key not found" in
      (match w.Wallet.encryption.lock_state with
       | Wallet.Unlocked { master_key; _ } ->
         w.Wallet.encryption.lock_state <-
           Wallet.Unlocked { master_key; expires = 0.0 }
       | Wallet.Locked -> Alcotest.fail "instrument: not unlocked");
      Alcotest.(check bool) "is_locked after the deadline" true
        (Wallet.is_locked w);
      ok_or_fail "walletpassphrase again"
        (Wallet.wallet_passphrase w ~passphrase ~timeout:60.0);
      match Wallet.find_by_address w addr with
      | Some kp ->
        Alcotest.(check bool) "key minted while unlocked restored" true
          (Cstruct.to_string kp.Wallet.private_key = secret)
      | None -> Alcotest.fail "minted key lost")

(* ---- signmessage ----------------------------------------------------- *)

let test_signmessage_after_expiry () =
  with_ctx "sm_expiry" (fun w addr ctx ->
      unlock_then_expire w;
      expect_locked "signmessage after expiry" (signmessage ctx addr))

let test_signmessage_after_walletlock () =
  with_ctx "sm_walletlock" (fun w addr ctx ->
      ok_or_fail "walletpassphrase"
        (Wallet.wallet_passphrase w ~passphrase ~timeout:60.0);
      Wallet.wallet_lock w;
      expect_locked "signmessage after walletlock" (signmessage ctx addr))

(* Core checks the lock before it parses the address *)
let test_signmessage_locked_bad_address () =
  with_ctx "sm_badaddr" (fun _ _ ctx ->
      expect_locked "signmessage locked, invalid address"
        (signmessage ctx "notanaddress"))

(* Control: unlocked, the same call signs and the signature verifies. *)
let test_signmessage_unlocked_control () =
  with_ctx "sm_unlocked" (fun w addr ctx ->
      ok_or_fail "walletpassphrase"
        (Wallet.wallet_passphrase w ~passphrase ~timeout:60.0);
      match signmessage ctx addr with
      | Ok (`String sig_b64) ->
        (match Rpc.dispatch_rpc ctx "verifymessage"
                 [`String addr; `String sig_b64; `String "hello"] with
         | Ok (`Bool true) -> ()
         | Ok j -> Alcotest.failf "verifymessage: %s" (Yojson.Safe.to_string j)
         | Error (c, m) -> Alcotest.failf "verifymessage: %d %s" c m)
      | Ok j -> Alcotest.failf "signmessage: %s" (Yojson.Safe.to_string j)
      | Error (c, m) -> Alcotest.failf "signmessage unlocked: %d %s" c m)

(* Control: an unencrypted wallet is never locked. *)
let test_signmessage_unencrypted_control () =
  with_ctx "sm_plain" ~encrypt:false (fun _ addr ctx ->
      match signmessage ctx addr with
      | Ok (`String _) -> ()
      | Ok j -> Alcotest.failf "signmessage: %s" (Yojson.Safe.to_string j)
      | Error (c, m) -> Alcotest.failf "signmessage unencrypted: %d %s" c m)

(* ---- signrawtransactionwithwallet ------------------------------------ *)

let test_signraw_after_expiry () =
  with_ctx "sr_expiry" (fun w _ ctx ->
      unlock_then_expire w;
      expect_locked "signrawtransactionwithwallet after expiry" (signraw ctx))

let test_signraw_after_walletlock () =
  with_ctx "sr_walletlock" (fun w _ ctx ->
      ok_or_fail "walletpassphrase"
        (Wallet.wallet_passphrase w ~passphrase ~timeout:60.0);
      Wallet.wallet_lock w;
      expect_locked "signrawtransactionwithwallet after walletlock"
        (signraw ctx))

(* Core decodes the hex before the lock check: a bad hex on a locked wallet
   is a decode error, not -13. *)
let test_signraw_locked_decode_first () =
  with_ctx "sr_decode" (fun _ _ ctx ->
      match Rpc.dispatch_rpc ctx "signrawtransactionwithwallet"
              [`String "00"] with
      | Error (c, m) ->
        Alcotest.(check bool) "not -13" true (c <> -13);
        Alcotest.(check bool) ("decode error first: " ^ m) true
          (String.length m >= 16 && String.sub m 0 16 = "TX decode failed")
      | Ok j -> Alcotest.failf "bad hex accepted: %s" (Yojson.Safe.to_string j))

(* Control: unlocked, the call answers (nothing to sign: complete false). *)
let test_signraw_unlocked_control () =
  with_ctx "sr_unlocked" (fun w _ ctx ->
      ok_or_fail "walletpassphrase"
        (Wallet.wallet_passphrase w ~passphrase ~timeout:60.0);
      match signraw ctx with
      | Ok (`Assoc f) ->
        Alcotest.(check bool) "has hex" true (List.mem_assoc "hex" f)
      | Ok j -> Alcotest.failf "signraw: %s" (Yojson.Safe.to_string j)
      | Error (c, m) -> Alcotest.failf "signraw unlocked: %d %s" c m)

let () =
  Alcotest.run "sign_rpcs_unlock" [
    "expiry", [
      Alcotest.test_case "expiry_zeroes_keys" `Quick test_expiry_zeroes_keys;
      Alcotest.test_case "expiry_keeps_new_keys_recoverable" `Quick
        test_expiry_keeps_new_keys_recoverable;
    ];
    "signmessage", [
      Alcotest.test_case "after_expiry" `Quick test_signmessage_after_expiry;
      Alcotest.test_case "after_walletlock" `Quick
        test_signmessage_after_walletlock;
      Alcotest.test_case "locked_bad_address" `Quick
        test_signmessage_locked_bad_address;
      Alcotest.test_case "unlocked_control" `Quick
        test_signmessage_unlocked_control;
      Alcotest.test_case "unencrypted_control" `Quick
        test_signmessage_unencrypted_control;
    ];
    "signrawtransactionwithwallet", [
      Alcotest.test_case "after_expiry" `Quick test_signraw_after_expiry;
      Alcotest.test_case "after_walletlock" `Quick
        test_signraw_after_walletlock;
      Alcotest.test_case "locked_decode_first" `Quick
        test_signraw_locked_decode_first;
      Alcotest.test_case "unlocked_control" `Quick
        test_signraw_unlocked_control;
    ];
  ]
