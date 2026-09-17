(* R5 T3 missing surface — send / backupwallet / restorewallet.

   CONTROL: `dune exec --no-buffer test/test_r5_send_backup_restore.exe`

   tools/r5-probes.d/wallet.jsonl (lane_order 110/120/160), Core
   bitcoin-core/src/wallet/rpc/spend.cpp send() and backup.cpp:

     send invalid-address   [[{"notanaddress": 0.001}]]              -> -5
     send no-outputs        [[]]                                     -> -8
     send success-complete  [[{own-dest: 0.5}], null, null, 10]      -> {complete:true,txid}
     backupwallet success   ["<file>"]                               -> null
     backupwallet bad-dest  ["/nonexistent-r5probe-dir/backup.dat"]  -> -4
     restorewallet missing  ["r5probe_fresh", "/nonexistent/..."]    -> -8
     restorewallet success  ["r5restored", "<backup>"]               -> {name:"r5restored"}
     restorewallet exists   ["r5", "<backup>"]                       -> -36
     help lists all three methods

   Dispatch goes through [Rpc.dispatch_rpc] so a missing method (-32601)
   fails these. *)

open Camlcoin

let dest_addr = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"

let dummy_tip (height : int) : Sync.header_entry =
  { header = { version = 1l; prev_block = Types.zero_hash;
               merkle_root = Types.zero_hash; timestamp = 0l;
               bits = 0l; nonce = 0l };
    hash = Types.zero_hash;
    height;
    total_work = Cstruct.create 32 }

let with_ctx ?(height = 6) ?(wallets_dir : string option) f =
  Test_tmp.with_chaindb (fun db ->
      let utxo = Utxo.UtxoSet.create db in
      let mp = Mempool.create ~network:Consensus.regtest
          ~require_standard:false ~verify_scripts:false ~utxo
          ~current_height:height () in
      let chain = Sync.create_chain_state db Consensus.regtest in
      chain.tip <- Some (dummy_tip height);
      let wallet, wallet_manager =
        match wallets_dir with
        | None ->
          (Wallet.create ~network:`Regtest ~db_path:"", None)
        | Some dir ->
          let wm = Wallet.create_wallet_manager ~wallets_dir:dir
              ~network:`Regtest in
          (match Wallet.create_wallet wm "r5" () with
           | Error e -> Alcotest.fail ("create_wallet r5: " ^ e)
           | Ok w -> (w, Some wm))
      in
      let ctx : Rpc.rpc_context = {
        chain; mempool = mp;
        peer_manager = Peer_manager.create Consensus.regtest;
        wallet = Some wallet; wallet_manager;
        fee_estimator = Fee_estimation.create ();
        network = Consensus.regtest; filter_index = None; utxo = None;
        data_dir = None; snapshot_activation = None;
      } in
      f ctx wallet utxo)

let fund_three (w : Wallet.t) (utxo : Utxo.UtxoSet.t) : string =
  let kp = Wallet.generate_key w in
  let script = Wallet.build_p2wpkh_script (Crypto.hash160 kp.Wallet.public_key) in
  let mk i =
    let txid = Cstruct.create 32 in
    Cstruct.set_uint8 txid 0 (i + 1);
    let entry = { Utxo.value = 250_000_000L; script_pubkey = script;
                  height = 1; is_coinbase = false } in
    Utxo.UtxoSet.add utxo txid 0 entry;
    { Wallet.outpoint = { Types.txid; vout = 0l };
      utxo = entry; key_index = 0; confirmed = true; watch_only = false }
  in
  w.utxos <- [mk 0; mk 1; mk 2];
  Address.address_to_string kp.Wallet.address

let check_err ~label ~code ?msg result =
  match result with
  | Error (c, m) ->
    Alcotest.(check int) (label ^ ": code") code c;
    (match msg with
     | Some expected -> Alcotest.(check string) (label ^ ": message") expected m
     | None -> ())
  | Ok j ->
    Alcotest.failf "%s: expected error (%d) but got Ok %s"
      label code (Yojson.Safe.to_string j)

(* ============================================================================
   send invalid-address -> -5  (spend.cpp ParseOutputs)
   ============================================================================ *)

let test_send_invalid_address () =
  with_ctx (fun ctx _w _u ->
      check_err ~label:"send invalid-address"
        ~code:(-5) ~msg:"Invalid Bitcoin address: notanaddress"
        (Rpc.dispatch_rpc ctx "send"
           [`List [`Assoc [("notanaddress", `Float 0.001)]]]))

(* ============================================================================
   send no-outputs -> -8  (spend.cpp:679 "TX must have at least one output")
   ============================================================================ *)

let test_send_no_outputs () =
  with_ctx (fun ctx _w _u ->
      check_err ~label:"send no-outputs"
        ~code:(-8) ~msg:"TX must have at least one output"
        (Rpc.dispatch_rpc ctx "send" [`List []]))

(* ============================================================================
   send success-complete: {complete: true, txid: 64-hex}
   ============================================================================ *)

let test_send_success_complete () =
  with_ctx ~height:6 (fun ctx w utxo ->
      let _own = fund_three w utxo in
      match Rpc.dispatch_rpc ctx "send"
              [`List [`Assoc [(dest_addr, `Float 0.5)]];
               `Null; `Null; `Int 10] with
      | Error (c, m) ->
        Alcotest.failf "send success-complete: error (%d) %s" c m
      | Ok (`Assoc fs) ->
        (match List.assoc_opt "complete" fs with
         | Some (`Bool true) -> ()
         | Some v ->
           Alcotest.failf "complete: expected true, got %s"
             (Yojson.Safe.to_string v)
         | None -> Alcotest.fail "missing field complete");
        (match List.assoc_opt "txid" fs with
         | Some (`String s) when String.length s = 64 -> ()
         | Some v ->
           Alcotest.failf "txid: expected 64-hex, got %s"
             (Yojson.Safe.to_string v)
         | None -> Alcotest.fail "missing field txid")
      | Ok j ->
        Alcotest.failf "send success-complete: expected object, got %s"
          (Yojson.Safe.to_string j))

(* ============================================================================
   backupwallet bad-destination -> -4
   ============================================================================ *)

let test_backup_bad_destination () =
  Test_tmp.with_dir ~label:"wallets" ~mkdir:true (fun dir ->
      with_ctx ~wallets_dir:dir (fun ctx _w _u ->
          check_err ~label:"backupwallet bad-destination"
            ~code:(-4) ~msg:"Error: Wallet backup failed!"
            (Rpc.dispatch_rpc ctx "backupwallet"
               [`String "/nonexistent-r5probe-dir/backup.dat"])))

(* ============================================================================
   backupwallet success-null -> JSON null
   ============================================================================ *)

let test_backup_success_null () =
  Test_tmp.with_dir ~label:"wallets" ~mkdir:true (fun dir ->
      with_ctx ~wallets_dir:dir (fun ctx _w _u ->
          let dest = Filename.concat dir "backup.dat" in
          match Rpc.dispatch_rpc ctx "backupwallet" [`String dest] with
          | Error (c, m) ->
            Alcotest.failf "backupwallet success-null: error (%d) %s" c m
          | Ok `Null ->
            Alcotest.(check bool) "backup file exists" true
              (Sys.file_exists dest)
          | Ok j ->
            Alcotest.failf "backupwallet success-null: expected null, got %s"
              (Yojson.Safe.to_string j)))

(* ============================================================================
   restorewallet backup-missing -> -8  (checked before already-exists)
   ============================================================================ *)

let test_restore_backup_missing () =
  Test_tmp.with_dir ~label:"wallets" ~mkdir:true (fun dir ->
      with_ctx ~wallets_dir:dir (fun ctx _w _u ->
          check_err ~label:"restorewallet backup-missing"
            ~code:(-8) ~msg:"Backup file does not exist"
            (Rpc.dispatch_rpc ctx "restorewallet"
               [`String "r5probe_fresh";
                `String "/nonexistent/r5probe-nope.bak"])))

(* ============================================================================
   restorewallet success-shape -> {name: "r5restored"}
   ============================================================================ *)

let test_restore_success_shape () =
  Test_tmp.with_dir ~label:"wallets" ~mkdir:true (fun dir ->
      with_ctx ~wallets_dir:dir (fun ctx _w _u ->
          let dest = Filename.concat dir "backup.dat" in
          (match Rpc.dispatch_rpc ctx "backupwallet" [`String dest] with
           | Ok `Null -> ()
           | Error (c, m) -> Alcotest.failf "backup for restore: (%d) %s" c m
           | Ok j -> Alcotest.failf "backup for restore: %s"
                       (Yojson.Safe.to_string j));
          match Rpc.dispatch_rpc ctx "restorewallet"
                  [`String "r5restored"; `String dest] with
          | Error (c, m) ->
            Alcotest.failf "restorewallet success-shape: error (%d) %s" c m
          | Ok (`Assoc fs) ->
            (match List.assoc_opt "name" fs with
             | Some (`String "r5restored") -> ()
             | Some v ->
               Alcotest.failf "name: expected r5restored, got %s"
                 (Yojson.Safe.to_string v)
             | None -> Alcotest.fail "missing field name")
          | Ok j ->
            Alcotest.failf "restorewallet success-shape: expected object, got %s"
              (Yojson.Safe.to_string j)))

(* ============================================================================
   restorewallet already-exists -> -36
   ============================================================================ *)

let test_restore_already_exists () =
  Test_tmp.with_dir ~label:"wallets" ~mkdir:true (fun dir ->
      with_ctx ~wallets_dir:dir (fun ctx _w _u ->
          let dest = Filename.concat dir "backup.dat" in
          (match Rpc.dispatch_rpc ctx "backupwallet" [`String dest] with
           | Ok `Null -> ()
           | Error (c, m) -> Alcotest.failf "backup for exists: (%d) %s" c m
           | Ok j -> Alcotest.failf "backup for exists: %s"
                       (Yojson.Safe.to_string j));
          check_err ~label:"restorewallet already-exists"
            ~code:(-36)
            (Rpc.dispatch_rpc ctx "restorewallet"
               [`String "r5"; `String dest])))

(* ============================================================================
   help-parity: send, backupwallet, restorewallet listed
   ============================================================================ *)

let test_help_lists_methods () =
  with_ctx (fun ctx _w _u ->
      match Rpc.dispatch_rpc ctx "help" [] with
      | Error (c, m) -> Alcotest.failf "help: error (%d) %s" c m
      | Ok (`String s) ->
        let listed name =
          let found = ref false in
          List.iter (fun line ->
              let line = String.trim line in
              if line <> "" && line.[0] <> '=' then
                let tok =
                  match String.split_on_char ' ' line with
                  | t :: _ ->
                    (match String.split_on_char '(' t with
                     | h :: _ -> h | [] -> t)
                  | [] -> ""
                in
                if tok = name then found := true)
            (String.split_on_char '\n' s);
          !found
        in
        Alcotest.(check bool) "help lists send" true (listed "send");
        Alcotest.(check bool) "help lists backupwallet" true
          (listed "backupwallet");
        Alcotest.(check bool) "help lists restorewallet" true
          (listed "restorewallet")
      | Ok j ->
        Alcotest.failf "help: expected string, got %s"
          (Yojson.Safe.to_string j))

let () =
  let open Alcotest in
  run "R5 send/backupwallet/restorewallet (Core probe vectors)" [
    "send", [
      test_case "invalid-address -> -5" `Quick test_send_invalid_address;
      test_case "no-outputs -> -8" `Quick test_send_no_outputs;
      test_case "success-complete fields" `Quick test_send_success_complete;
    ];
    "backupwallet", [
      test_case "bad-destination -> -4" `Quick test_backup_bad_destination;
      test_case "success-null" `Quick test_backup_success_null;
    ];
    "restorewallet", [
      test_case "backup-missing -> -8" `Quick test_restore_backup_missing;
      test_case "success-shape" `Quick test_restore_success_shape;
      test_case "already-exists -> -36" `Quick test_restore_already_exists;
    ];
    "help", [
      test_case "lists send/backupwallet/restorewallet" `Quick
        test_help_lists_methods;
    ];
  ]
