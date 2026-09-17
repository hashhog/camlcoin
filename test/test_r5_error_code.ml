(* R5 error-code parity class — Core-validated probe vectors.

   CONTROL: `dune exec --no-buffer test/test_r5_error_code.exe`

   Encodes the 21 T1/T2 methods whose live-lane error-check failed against
   Bitcoin Core (tools/r5-probes.d, probe 2026-09-17T05:41Z):

     getmempoolentry not-in-mempool          -> -5
     addnode invalid-command                 -> -1
     submitblock decode-error                -> -22
     sendrawtransaction decode-error         -> -22
     getchaintxstats bad-blockcount          -> -8
     getdeploymentinfo notfound              -> -5
     getmempoolancestors not-in-mempool      -> -5
     getmempooldescendants not-in-mempool    -> -5
     gettxoutproof tx-not-in-block           -> -5
     verifytxoutproof nonhex                 -> -8
     prioritisetransaction bad-txid          -> -8
     scantxoutset bad-action                 -> -8
     decodescript nonhex                     -> -8
     createpsbt bad-txid                     -> -8
     createpsbt canonical-exact              (same-method success)
     combinepsbt empty-array                 -> -8
     finalizepsbt bad-base64                 -> -22
     descriptorprocesspsbt bad-descriptor    -> -5
     descriptorprocesspsbt update-exact      (same-method success)
     submitpackage empty-array               -> -8
     submitpackage nonhex                    -> -22
     createmultisig invalid-pubkey           -> -5
     createmultisig not-enough-keys          -> -8
     getdescriptorinfo invalid-descriptor    -> -5
     getdescriptorinfo bad-checksum          -> -5
     verifymessage malformed-sig             -> -3

   Oracle: live Core v31.99 :8332, 2026-09-17. Dispatch through
   [Rpc.dispatch_rpc]. *)

open Camlcoin

let with_ctx f =
  Test_tmp.with_chaindb (fun db ->
      let utxo = Utxo.UtxoSet.create db in
      let mp =
        Mempool.create ~network:Consensus.mainnet ~require_standard:false
          ~verify_scripts:false ~utxo ~current_height:0 ()
      in
      let chain = Sync.create_chain_state db Consensus.mainnet in
      let ctx : Rpc.rpc_context =
        {
          chain;
          mempool = mp;
          peer_manager = Peer_manager.create Consensus.mainnet;
          wallet = None;
          wallet_manager = None;
          fee_estimator = Fee_estimation.create ();
          network = Consensus.mainnet;
          filter_index = None;
          utxo = None;
          data_dir = None;
          snapshot_activation = None;
        }
      in
      f ctx)

let check_err ~label ~code ?msg result =
  match result with
  | Error (c, m) ->
    Alcotest.(check int) (label ^ ": code") code c;
    (match msg with
    | Some expected -> Alcotest.(check string) (label ^ ": message") expected m
    | None -> ())
  | Ok j ->
    Alcotest.failf "%s: expected error (%d) but got Ok %s" label code
      (Yojson.Safe.to_string j)

let require_help_lists ctx method_name =
  match Rpc.dispatch_rpc ctx "help" [] with
  | Error (c, m) -> Alcotest.failf "help: error (%d) %s" c m
  | Ok (`String s) ->
    (try ignore (Str.search_forward (Str.regexp_string method_name) s 0)
     with Not_found -> Alcotest.fail (method_name ^ " not listed in help"))
  | Ok j ->
    Alcotest.failf "help: expected string, got %s" (Yojson.Safe.to_string j)

let zeros64 = String.make 64 '0'
let ones64 = String.make 63 '0' ^ "1"

let analyze_psbt_b64 =
  "cHNidP8BAFICAAAAAaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqAAAAAAD9////\
   AaCGAQAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9YAAAAAAAAA"

(* ============================================================================
   T1
   ============================================================================ *)

let test_getmempoolentry_not_in_mempool () =
  with_ctx (fun ctx ->
      check_err ~label:"getmempoolentry not-in-mempool" ~code:(-5)
        ~msg:"Transaction not in mempool"
        (Rpc.dispatch_rpc ctx "getmempoolentry" [ `String ones64 ]))

let test_addnode_invalid_command () =
  with_ctx (fun ctx ->
      check_err ~label:"addnode invalid-command" ~code:(-1)
        (Rpc.dispatch_rpc ctx "addnode"
           [ `String "192.0.2.1:8333"; `String "notacommand" ]))

let test_submitblock_decode_error () =
  with_ctx (fun ctx ->
      check_err ~label:"submitblock decode-error" ~code:(-22)
        ~msg:"Block decode failed"
        (Rpc.dispatch_rpc ctx "submitblock" [ `String "deadbeef" ]))

let test_sendrawtransaction_decode_error () =
  with_ctx (fun ctx ->
      check_err ~label:"sendrawtransaction decode-error" ~code:(-22)
        ~msg:"TX decode failed. Make sure the tx has at least one input."
        (Rpc.dispatch_rpc ctx "sendrawtransaction" [ `String "deadbeef" ]))

(* ============================================================================
   T2 chain / mempool
   ============================================================================ *)

let test_getchaintxstats_bad_blockcount () =
  with_ctx (fun ctx ->
      check_err ~label:"getchaintxstats bad-blockcount" ~code:(-8)
        (Rpc.dispatch_rpc ctx "getchaintxstats" [ `Int (-1) ]))

let test_getdeploymentinfo_notfound () =
  with_ctx (fun ctx ->
      check_err ~label:"getdeploymentinfo notfound" ~code:(-5)
        ~msg:"Block not found"
        (Rpc.dispatch_rpc ctx "getdeploymentinfo" [ `String ones64 ]))

let test_getmempoolancestors_not_in_mempool () =
  with_ctx (fun ctx ->
      check_err ~label:"getmempoolancestors not-in-mempool" ~code:(-5)
        ~msg:"Transaction not in mempool"
        (Rpc.dispatch_rpc ctx "getmempoolancestors" [ `String zeros64 ]))

let test_getmempooldescendants_not_in_mempool () =
  with_ctx (fun ctx ->
      check_err ~label:"getmempooldescendants not-in-mempool" ~code:(-5)
        ~msg:"Transaction not in mempool"
        (Rpc.dispatch_rpc ctx "getmempooldescendants" [ `String zeros64 ]))

let test_gettxoutproof_tx_not_in_block () =
  with_ctx (fun ctx ->
      check_err ~label:"gettxoutproof tx-not-in-block" ~code:(-5)
        ~msg:"Transaction not yet in block"
        (Rpc.dispatch_rpc ctx "gettxoutproof" [ `List [ `String zeros64 ] ]))

let test_verifytxoutproof_nonhex () =
  with_ctx (fun ctx ->
      check_err ~label:"verifytxoutproof nonhex" ~code:(-8)
        ~msg:"proof must be hexadecimal string (not 'zz')"
        (Rpc.dispatch_rpc ctx "verifytxoutproof" [ `String "zz" ]))

let test_prioritisetransaction_bad_txid () =
  with_ctx (fun ctx ->
      check_err ~label:"prioritisetransaction bad-txid" ~code:(-8)
        ~msg:"txid must be of length 64 (not 2, for 'zz')"
        (Rpc.dispatch_rpc ctx "prioritisetransaction"
           [ `String "zz"; `Int 0; `Int 1000 ]))

let test_scantxoutset_bad_action () =
  with_ctx (fun ctx ->
      check_err ~label:"scantxoutset bad-action" ~code:(-8)
        ~msg:"Invalid action 'bogus'"
        (Rpc.dispatch_rpc ctx "scantxoutset" [ `String "bogus" ]))

(* ============================================================================
   T2 rawtx / PSBT / util
   ============================================================================ *)

let test_decodescript_nonhex () =
  with_ctx (fun ctx ->
      check_err ~label:"decodescript nonhex" ~code:(-8)
        ~msg:"argument must be hexadecimal string (not 'zz')"
        (Rpc.dispatch_rpc ctx "decodescript" [ `String "zz" ]))

let createpsbt_inputs =
  `List
    [
      `Assoc
        [
          ( "txid",
            `String
              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
          );
          ("vout", `Int 0);
        ];
    ]

let createpsbt_outputs =
  `Assoc [ ("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", `Float 0.001) ]

let test_createpsbt_canonical_exact () =
  with_ctx (fun ctx ->
      match
        Rpc.dispatch_rpc ctx "createpsbt"
          [ createpsbt_inputs; createpsbt_outputs ]
      with
      | Error (c, m) -> Alcotest.failf "canonical-exact: error (%d) %s" c m
      | Ok (`String s) ->
        Alcotest.(check string) "createpsbt canonical" analyze_psbt_b64 s
      | Ok j ->
        Alcotest.failf "expected string, got %s" (Yojson.Safe.to_string j))

let test_createpsbt_bad_txid () =
  with_ctx (fun ctx ->
      let inputs =
        `List
          [ `Assoc [ ("txid", `String "zz"); ("vout", `Int 0) ] ]
      in
      check_err ~label:"createpsbt bad-txid" ~code:(-8)
        ~msg:"txid must be of length 64 (not 2, for 'zz')"
        (Rpc.dispatch_rpc ctx "createpsbt" [ inputs; createpsbt_outputs ]))

let test_combinepsbt_empty_array () =
  with_ctx (fun ctx ->
      check_err ~label:"combinepsbt empty-array" ~code:(-8)
        ~msg:"Parameter 'txs' cannot be empty"
        (Rpc.dispatch_rpc ctx "combinepsbt" [ `List [] ]))

let test_finalizepsbt_bad_base64 () =
  with_ctx (fun ctx ->
      check_err ~label:"finalizepsbt bad-base64" ~code:(-22)
        ~msg:"TX decode failed invalid base64"
        (Rpc.dispatch_rpc ctx "finalizepsbt" [ `String "notbase64!!" ]))

let test_descriptorprocesspsbt_bad_descriptor () =
  with_ctx (fun ctx ->
      check_err ~label:"descriptorprocesspsbt bad-descriptor" ~code:(-5)
        (Rpc.dispatch_rpc ctx "descriptorprocesspsbt"
           [ `String analyze_psbt_b64; `List [ `String "nonsense(desc)" ] ]))

let test_descriptorprocesspsbt_update_exact () =
  with_ctx (fun ctx ->
      let desc =
        "wpkh(KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn)"
      in
      match
        Rpc.dispatch_rpc ctx "descriptorprocesspsbt"
          [ `String analyze_psbt_b64; `List [ `String desc ] ]
      with
      | Error (c, m) -> Alcotest.failf "update-exact: error (%d) %s" c m
      | Ok (`Assoc fields) ->
        (match List.assoc_opt "complete" fields with
        | Some (`Bool false) -> ()
        | Some j ->
          Alcotest.failf "complete: %s" (Yojson.Safe.to_string j)
        | None -> Alcotest.fail "missing complete");
        (match List.assoc_opt "hex" fields with
        | None -> ()
        | Some j ->
          Alcotest.failf "unexpected hex: %s" (Yojson.Safe.to_string j));
        (match List.assoc_opt "psbt" fields with
        | Some (`String s) ->
          Alcotest.(check string) "psbt"
            "cHNidP8BAFICAAAAAaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqAAAAAAD9////AaCGAQAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9YAAAAAAAAiAgJ5vmZ++dy7rFWgYpXOhwsHApv82y3OKNlZ8oFbFvgXmAR1HnboAA=="
            s
        | Some j ->
          Alcotest.failf "psbt: %s" (Yojson.Safe.to_string j)
        | None -> Alcotest.fail "missing psbt")
      | Ok j ->
        Alcotest.failf "expected object, got %s" (Yojson.Safe.to_string j))

let test_descriptorprocesspsbt_listed_in_help () =
  with_ctx (fun ctx -> require_help_lists ctx "descriptorprocesspsbt")

let test_submitpackage_empty_array () =
  with_ctx (fun ctx ->
      check_err ~label:"submitpackage empty-array" ~code:(-8)
        (Rpc.dispatch_rpc ctx "submitpackage" [ `List [] ]))

let test_submitpackage_nonhex () =
  with_ctx (fun ctx ->
      check_err ~label:"submitpackage nonhex" ~code:(-22)
        (Rpc.dispatch_rpc ctx "submitpackage" [ `List [ `String "zz" ] ]))

let test_createmultisig_invalid_pubkey () =
  with_ctx (fun ctx ->
      check_err ~label:"createmultisig invalid-pubkey" ~code:(-5)
        (Rpc.dispatch_rpc ctx "createmultisig"
           [ `Int 1; `List [ `String "deadbeef" ] ]))

let test_createmultisig_not_enough_keys () =
  with_ctx (fun ctx ->
      check_err ~label:"createmultisig not-enough-keys" ~code:(-8)
        (Rpc.dispatch_rpc ctx "createmultisig"
           [
             `Int 3;
             `List
               [
                 `String
                   "03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd";
                 `String
                   "03dbc6764b8884a92e871274b87583e6d5c2a58819473e17e107ef3f6aa5a61626";
               ];
           ]))

let test_getdescriptorinfo_invalid () =
  with_ctx (fun ctx ->
      check_err ~label:"getdescriptorinfo invalid-descriptor" ~code:(-5)
        (Rpc.dispatch_rpc ctx "getdescriptorinfo"
           [ `String "notadescriptor" ]))

let test_getdescriptorinfo_bad_checksum () =
  with_ctx (fun ctx ->
      check_err ~label:"getdescriptorinfo bad-checksum" ~code:(-5)
        (Rpc.dispatch_rpc ctx "getdescriptorinfo"
           [
             `String
               "wpkh(03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd)#00000000";
           ]))

let test_verifymessage_malformed_sig () =
  with_ctx (fun ctx ->
      check_err ~label:"verifymessage malformed-sig" ~code:(-3)
        ~msg:"Malformed base64 encoding"
        (Rpc.dispatch_rpc ctx "verifymessage"
           [
             `String "1GAehh7TsJAHuUAeKZcXf5CnwuGuGgyX2S";
             `String "not-base64!!";
             `String "hashhog r5 probe";
           ]))

let () =
  let open Alcotest in
  run "R5 error-code parity (Core probe vectors)"
    [
      ( "t1",
        [
          test_case "getmempoolentry not-in-mempool -> -5" `Quick
            test_getmempoolentry_not_in_mempool;
          test_case "addnode invalid-command -> -1" `Quick
            test_addnode_invalid_command;
          test_case "submitblock decode-error -> -22" `Quick
            test_submitblock_decode_error;
          test_case "sendrawtransaction decode-error -> -22" `Quick
            test_sendrawtransaction_decode_error;
        ] );
      ( "t2-chain",
        [
          test_case "getchaintxstats bad-blockcount -> -8" `Quick
            test_getchaintxstats_bad_blockcount;
          test_case "getdeploymentinfo notfound -> -5" `Quick
            test_getdeploymentinfo_notfound;
          test_case "getmempoolancestors not-in-mempool -> -5" `Quick
            test_getmempoolancestors_not_in_mempool;
          test_case "getmempooldescendants not-in-mempool -> -5" `Quick
            test_getmempooldescendants_not_in_mempool;
          test_case "gettxoutproof tx-not-in-block -> -5" `Quick
            test_gettxoutproof_tx_not_in_block;
          test_case "verifytxoutproof nonhex -> -8" `Quick
            test_verifytxoutproof_nonhex;
          test_case "prioritisetransaction bad-txid -> -8" `Quick
            test_prioritisetransaction_bad_txid;
          test_case "scantxoutset bad-action -> -8" `Quick
            test_scantxoutset_bad_action;
        ] );
      ( "t2-rawtx",
        [
          test_case "decodescript nonhex -> -8" `Quick test_decodescript_nonhex;
          test_case "createpsbt canonical-exact" `Quick
            test_createpsbt_canonical_exact;
          test_case "createpsbt bad-txid -> -8" `Quick test_createpsbt_bad_txid;
          test_case "combinepsbt empty-array -> -8" `Quick
            test_combinepsbt_empty_array;
          test_case "finalizepsbt bad-base64 -> -22" `Quick
            test_finalizepsbt_bad_base64;
          test_case "descriptorprocesspsbt bad-descriptor -> -5" `Quick
            test_descriptorprocesspsbt_bad_descriptor;
          test_case "descriptorprocesspsbt update-exact" `Quick
            test_descriptorprocesspsbt_update_exact;
          test_case "descriptorprocesspsbt listed in help" `Quick
            test_descriptorprocesspsbt_listed_in_help;
          test_case "submitpackage empty-array -> -8" `Quick
            test_submitpackage_empty_array;
          test_case "submitpackage nonhex -> -22" `Quick
            test_submitpackage_nonhex;
          test_case "createmultisig invalid-pubkey -> -5" `Quick
            test_createmultisig_invalid_pubkey;
          test_case "createmultisig not-enough-keys -> -8" `Quick
            test_createmultisig_not_enough_keys;
          test_case "getdescriptorinfo invalid-descriptor -> -5" `Quick
            test_getdescriptorinfo_invalid;
          test_case "getdescriptorinfo bad-checksum -> -5" `Quick
            test_getdescriptorinfo_bad_checksum;
          test_case "verifymessage malformed-sig -> -3" `Quick
            test_verifymessage_malformed_sig;
        ] );
    ]
