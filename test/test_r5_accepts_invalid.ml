(* R5 accepts-invalid class — Core-validated probe vectors.

   CONTROL: `dune exec --no-buffer test/test_r5_accepts_invalid.exe`

   Encodes the seven methods that accepted input live Bitcoin Core rejects
   (tools/r5-probes.d, probe 2026-09-17T06:19Z):

     combinerawtransaction unknown-input          -> -25
     deriveaddresses missing-checksum             -> -5
     deriveaddresses range-on-unranged            -> -8
     getblockstats invalid-stat                   -> -8
     getblocktemplate missing-segwit-rule         -> -8
     getindexinfo wrong-type-arg                  -> -3
     getnetworkhashps type-error                  -> -3
     signrawtransactionwithkey bad-privkey        -> -5

   Plus the two same-method success/complete probes that also failed on
   that sweep (deriveaddresses success-exact-single; sign-complete).

   Dispatch goes through [Rpc.dispatch_rpc] so a handler that returns Ok
   (or the wrong code) fails these. *)

open Camlcoin

let test_db_path = Test_tmp.register "/tmp/camlcoin_test_r5_accepts_invalid_db"

let cleanup_test_db () =
  let rec rm_rf path =
    if Sys.file_exists path then begin
      if Sys.is_directory path then begin
        Array.iter (fun f -> rm_rf (Filename.concat path f)) (Sys.readdir path);
        Unix.rmdir path
      end else
        Unix.unlink path
    end
  in
  rm_rf test_db_path

let make_ctx () : Rpc.rpc_context * Storage.ChainDB.t =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let utxo = Utxo.UtxoSet.create db in
  let mp = Mempool.create ~network:Consensus.mainnet
    ~require_standard:false ~verify_scripts:false ~utxo ~current_height:0 () in
  let chain = Sync.create_chain_state db Consensus.mainnet in
  let pm = Peer_manager.create Consensus.mainnet in
  let fe = Fee_estimation.create () in
  let ctx : Rpc.rpc_context = {
    chain; mempool = mp; peer_manager = pm;
    wallet = None; wallet_manager = None; fee_estimator = fe;
    network = Consensus.mainnet; filter_index = None; utxo = None;
    data_dir = None; snapshot_activation = None;
  } in
  (ctx, db)

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

let raw_unknown =
  "0200000001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
   0000000000fdffffff01a086010000000000160014751e76e8199196d454941c45d1b3a323\
   f1433bd600000000"

let desc_no_csum =
  "wpkh(03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd)"
let desc_csum = desc_no_csum ^ "#e72f49hy"

let wif_priv1 = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"

(* ============================================================================
   combinerawtransaction unknown-input -> -25
   Core rawtransaction.cpp:650-653
   ============================================================================ *)

let test_combinerawtransaction_unknown_input () =
  let (ctx, db) = make_ctx () in
  check_err ~label:"combinerawtransaction unknown-input"
    ~code:(-25) ~msg:"Input not found or already spent"
    (Rpc.dispatch_rpc ctx "combinerawtransaction"
       [`List [`String raw_unknown; `String raw_unknown]]);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* ============================================================================
   deriveaddresses
   ============================================================================ *)

let test_deriveaddresses_missing_checksum () =
  let (ctx, db) = make_ctx () in
  check_err ~label:"deriveaddresses missing-checksum"
    ~code:(-5) ~msg:"Missing checksum"
    (Rpc.dispatch_rpc ctx "deriveaddresses" [`String desc_no_csum]);
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_deriveaddresses_range_on_unranged () =
  let (ctx, db) = make_ctx () in
  check_err ~label:"deriveaddresses range-on-unranged"
    ~code:(-8)
    ~msg:"Range should not be specified for an un-ranged descriptor"
    (Rpc.dispatch_rpc ctx "deriveaddresses"
       [`String desc_csum; `List [`Int 0; `Int 2]]);
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_deriveaddresses_success_exact_single () =
  let (ctx, db) = make_ctx () in
  let result = Rpc.dispatch_rpc ctx "deriveaddresses" [`String desc_csum] in
  Storage.ChainDB.close db;
  cleanup_test_db ();
  match result with
  | Error (c, m) ->
    Alcotest.failf "deriveaddresses success-exact-single: error (%d) %s" c m
  | Ok (`List [`String addr]) ->
    Alcotest.(check string) "Core address"
      "bc1qgp3v3thdf7qu94ellp2299tsyyv3ug9kkau5q5" addr
  | Ok j ->
    Alcotest.failf "expected one-address list, got %s" (Yojson.Safe.to_string j)

(* ============================================================================
   getblockstats invalid-stat -> -8
   ============================================================================ *)

let test_getblockstats_invalid_stat () =
  let (ctx, db) = make_ctx () in
  check_err ~label:"getblockstats invalid-stat"
    ~code:(-8) ~msg:"Invalid selected statistic 'bogusstat'"
    (Rpc.dispatch_rpc ctx "getblockstats"
       [`String (String.make 64 '0'); `List [`String "bogusstat"]]);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* ============================================================================
   getblocktemplate missing-segwit-rule -> -8
   ============================================================================ *)

let test_getblocktemplate_missing_segwit () =
  let (ctx, db) = make_ctx () in
  check_err ~label:"getblocktemplate missing-segwit-rule"
    ~code:(-8)
    ~msg:"getblocktemplate must be called with the segwit rule set (call with {\"rules\": [\"segwit\"]})"
    (Rpc.dispatch_rpc ctx "getblocktemplate" [`Assoc []]);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* ============================================================================
   getindexinfo wrong-type-arg -> -3
   ============================================================================ *)

let test_getindexinfo_wrong_type () =
  let (ctx, db) = make_ctx () in
  check_err ~label:"getindexinfo wrong-type-arg"
    ~code:(-3)
    ~msg:"JSON value of type number is not of expected type string"
    (Rpc.dispatch_rpc ctx "getindexinfo" [`Int 123]);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* ============================================================================
   getnetworkhashps type-error -> -3
   ============================================================================ *)

let test_getnetworkhashps_type_error () =
  let (ctx, db) = make_ctx () in
  check_err ~label:"getnetworkhashps type-error"
    ~code:(-3)
    ~msg:"JSON value of type string is not of expected type number"
    (Rpc.dispatch_rpc ctx "getnetworkhashps" [`String "foo"]);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* ============================================================================
   signrawtransactionwithkey
   ============================================================================ *)

let test_signrawtransactionwithkey_bad_privkey () =
  let (ctx, db) = make_ctx () in
  check_err ~label:"signrawtransactionwithkey bad-privkey"
    ~code:(-5) ~msg:"Invalid private key"
    (Rpc.dispatch_rpc ctx "signrawtransactionwithkey"
       [`String raw_unknown; `List [`String "notakey"]]);
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_signrawtransactionwithkey_complete () =
  let (ctx, db) = make_ctx () in
  let prevtxs = `List [
    `Assoc [
      ("txid", `String (String.make 64 'a'));
      ("vout", `Int 0);
      ("scriptPubKey", `String "0014751e76e8199196d454941c45d1b3a323f1433bd6");
      ("amount", `Float 0.002);
    ]
  ] in
  let result = Rpc.dispatch_rpc ctx "signrawtransactionwithkey"
    [`String raw_unknown; `List [`String wif_priv1]; prevtxs] in
  Storage.ChainDB.close db;
  cleanup_test_db ();
  match result with
  | Error (c, m) ->
    Alcotest.failf "sign-complete: error (%d) %s" c m
  | Ok (`Assoc fields) ->
    (match List.assoc_opt "complete" fields with
     | Some (`Bool true) -> ()
     | Some v ->
       Alcotest.failf "complete: expected true, got %s" (Yojson.Safe.to_string v)
     | None -> Alcotest.fail "missing complete");
    (match List.assoc_opt "hex" fields with
     | Some (`String h) when String.length h > 0 -> ()
     | _ -> Alcotest.fail "missing signed hex")
  | Ok j ->
    Alcotest.failf "expected object, got %s" (Yojson.Safe.to_string j)

let () =
  let open Alcotest in
  run "R5 accepts-invalid (Core probe vectors)" [
    "combinerawtransaction", [
      test_case "unknown-input -> -25" `Quick
        test_combinerawtransaction_unknown_input;
    ];
    "deriveaddresses", [
      test_case "missing-checksum -> -5" `Quick
        test_deriveaddresses_missing_checksum;
      test_case "range-on-unranged -> -8" `Quick
        test_deriveaddresses_range_on_unranged;
      test_case "success-exact-single" `Quick
        test_deriveaddresses_success_exact_single;
    ];
    "getblockstats", [
      test_case "invalid-stat -> -8" `Quick test_getblockstats_invalid_stat;
    ];
    "getblocktemplate", [
      test_case "missing-segwit-rule -> -8" `Quick
        test_getblocktemplate_missing_segwit;
    ];
    "getindexinfo", [
      test_case "wrong-type-arg -> -3" `Quick test_getindexinfo_wrong_type;
    ];
    "getnetworkhashps", [
      test_case "type-error -> -3" `Quick test_getnetworkhashps_type_error;
    ];
    "signrawtransactionwithkey", [
      test_case "bad-privkey -> -5" `Quick
        test_signrawtransactionwithkey_bad_privkey;
      test_case "sign-complete" `Quick
        test_signrawtransactionwithkey_complete;
    ];
  ]
