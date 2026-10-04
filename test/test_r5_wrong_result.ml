(* R5 "returns a different result than Core" class — Core-validated
   probe vectors.

   CONTROL: `dune exec --no-buffer test/test_r5_wrong_result.exe`

   Encodes the four methods whose live-lane exact-check failed against
   Bitcoin Core (tools/r5-probes.d, probe 2026-09-17T05:40Z):

     validateaddress exact-invalid
       Core key_io.cpp DecodeDestination: "notanaddress" is valid
       Base58 alphabet with a bad checksum
       -> {isvalid:false, error_locations:[],
           error:"Invalid checksum or length of Base58 address (P2PKH or P2SH)"}
     validateaddress exact-valid-bech32 / exact-valid-legacy
       (same probe object; already passed live, pinned here so a
       regression in the valid branch fails the same control)
     analyzepsbt analyze-exact
       Core node/psbt.cpp AnalyzePSBT: no UTXO -> omit estimated_vsize
       (camlcoin used to emit estimated_vsize:0)
       inputs[].next = "updater", next = "updater"
     analyzepsbt bad-base64 -> -22 "TX decode failed invalid base64"
     testmempoolaccept missing-inputs-exact
       Core rpc/mempool.cpp: txid AND wtxid, allowed:false,
       reject-reason:"missing-inputs"
     testmempoolaccept decode-error -> -22
     getnetworkhashps help-parity
       listed in `help` (live lane also requires this; the numeric
       exact-check is a function of chainwork at a tip-anchored height)

   Dispatch goes through [Rpc.dispatch_rpc]. *)

open Camlcoin

let with_ctx_net network f =
  Test_tmp.with_chaindb (fun db ->
      let utxo = Utxo.UtxoSet.create db in
      let mp =
        Mempool.create ~network ~require_standard:false ~verify_scripts:false
          ~utxo ~current_height:0 ()
      in
      let chain = Sync.create_chain_state db network in
      let ctx : Rpc.rpc_context =
        {
          chain;
          mempool = mp;
          peer_manager = Peer_manager.create network;
          wallet = None;
          wallet_manager = None;
          fee_estimator = Fee_estimation.create ();
          network;
          filter_index = None;
          utxo = None;
          data_dir = None;
          snapshot_activation = None;
        }
      in
      f ctx)

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

let field_bool fields name =
  match List.assoc_opt name fields with
  | Some (`Bool b) -> b
  | Some j ->
    Alcotest.failf "%s: expected bool, got %s" name (Yojson.Safe.to_string j)
  | None -> Alcotest.failf "missing field %s" name

let field_string fields name =
  match List.assoc_opt name fields with
  | Some (`String s) -> s
  | Some j ->
    Alcotest.failf "%s: expected string, got %s" name (Yojson.Safe.to_string j)
  | None -> Alcotest.failf "missing field %s" name

let field_list fields name =
  match List.assoc_opt name fields with
  | Some (`List xs) -> xs
  | Some j ->
    Alcotest.failf "%s: expected list, got %s" name (Yojson.Safe.to_string j)
  | None -> Alcotest.failf "missing field %s" name

let require_absent fields name =
  match List.assoc_opt name fields with
  | None -> ()
  | Some j ->
    Alcotest.failf "unexpected field %s: %s" name (Yojson.Safe.to_string j)

(* ============================================================================
   validateaddress — tools/r5-probes.d/util.jsonl
   Core src/key_io.cpp:85 DecodeDestination + src/rpc/misc.cpp validateaddress
   ============================================================================ *)

let test_validateaddress_exact_invalid () =
  with_ctx (fun ctx ->
      match Rpc.dispatch_rpc ctx "validateaddress" [ `String "notanaddress" ] with
      | Error (c, m) -> Alcotest.failf "exact-invalid: error (%d) %s" c m
      | Ok (`Assoc fields) ->
        Alcotest.(check bool) "isvalid" false (field_bool fields "isvalid");
        (match List.assoc_opt "error_locations" fields with
        | Some (`List []) -> ()
        | Some j ->
          Alcotest.failf "error_locations: %s" (Yojson.Safe.to_string j)
        | None -> Alcotest.fail "missing error_locations");
        Alcotest.(check string) "error"
          "Invalid checksum or length of Base58 address (P2PKH or P2SH)"
          (field_string fields "error")
      | Ok j ->
        Alcotest.failf "expected object, got %s" (Yojson.Safe.to_string j))

let test_validateaddress_exact_valid_bech32 () =
  with_ctx (fun ctx ->
      let addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4" in
      match Rpc.dispatch_rpc ctx "validateaddress" [ `String addr ] with
      | Error (c, m) -> Alcotest.failf "exact-valid-bech32: error (%d) %s" c m
      | Ok (`Assoc fields) ->
        Alcotest.(check bool) "isvalid" true (field_bool fields "isvalid");
        Alcotest.(check string) "address" addr (field_string fields "address");
        Alcotest.(check string) "scriptPubKey"
          "0014751e76e8199196d454941c45d1b3a323f1433bd6"
          (field_string fields "scriptPubKey");
        Alcotest.(check bool) "isscript" false (field_bool fields "isscript");
        Alcotest.(check bool) "iswitness" true (field_bool fields "iswitness");
        (match List.assoc_opt "witness_version" fields with
        | Some (`Int 0) -> ()
        | Some j ->
          Alcotest.failf "witness_version: %s" (Yojson.Safe.to_string j)
        | None -> Alcotest.fail "missing witness_version");
        Alcotest.(check string) "witness_program"
          "751e76e8199196d454941c45d1b3a323f1433bd6"
          (field_string fields "witness_program")
      | Ok j ->
        Alcotest.failf "expected object, got %s" (Yojson.Safe.to_string j))

let test_validateaddress_exact_valid_legacy () =
  with_ctx (fun ctx ->
      let addr = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2" in
      match Rpc.dispatch_rpc ctx "validateaddress" [ `String addr ] with
      | Error (c, m) -> Alcotest.failf "exact-valid-legacy: error (%d) %s" c m
      | Ok (`Assoc fields) ->
        Alcotest.(check bool) "isvalid" true (field_bool fields "isvalid");
        Alcotest.(check string) "address" addr (field_string fields "address");
        Alcotest.(check string) "scriptPubKey"
          "76a91477bff20c60e522dfaa3350c39b030a5d004e839a88ac"
          (field_string fields "scriptPubKey");
        Alcotest.(check bool) "isscript" false (field_bool fields "isscript");
        Alcotest.(check bool) "iswitness" false (field_bool fields "iswitness")
      | Ok j ->
        Alcotest.failf "expected object, got %s" (Yojson.Safe.to_string j))

(* ============================================================================
   analyzepsbt — tools/r5-probes.d/rawtx-psbt.jsonl
   Core src/node/psbt.cpp AnalyzePSBT + rpc/rawtransaction.cpp analyzepsbt
   ============================================================================ *)

let analyze_psbt_b64 =
  "cHNidP8BAFICAAAAAaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqAAAAAAD9////\
   AaCGAQAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9YAAAAAAAAA"

let test_analyzepsbt_analyze_exact () =
  with_ctx (fun ctx ->
      match Rpc.dispatch_rpc ctx "analyzepsbt" [ `String analyze_psbt_b64 ] with
      | Error (c, m) -> Alcotest.failf "analyze-exact: error (%d) %s" c m
      | Ok (`Assoc fields) ->
        require_absent fields "estimated_vsize";
        require_absent fields "estimated_feerate";
        require_absent fields "fee";
        Alcotest.(check string) "next" "updater" (field_string fields "next");
        (match field_list fields "inputs" with
        | [ `Assoc inp ] ->
          Alcotest.(check bool) "has_utxo" false (field_bool inp "has_utxo");
          Alcotest.(check bool) "is_final" false (field_bool inp "is_final");
          Alcotest.(check string) "input.next" "updater"
            (field_string inp "next")
        | _ -> Alcotest.fail "inputs: expected one object")
      | Ok j ->
        Alcotest.failf "expected object, got %s" (Yojson.Safe.to_string j))

let test_analyzepsbt_bad_base64 () =
  with_ctx (fun ctx ->
      check_err ~label:"analyzepsbt bad-base64" ~code:(-22)
        ~msg:"TX decode failed invalid base64"
        (Rpc.dispatch_rpc ctx "analyzepsbt" [ `String "notbase64!!" ]))

(* ============================================================================
   testmempoolaccept — tools/r5-probes.d/mining-relay.jsonl
   Core src/rpc/mempool.cpp testmempoolaccept
   ============================================================================ *)

let missing_inputs_hex =
  "02000000010100000000000000000000000000000000000000000000000000000000000000\
   0000000000fdffffff01a086010000000000160014751e76e8199196d454941c45d1b3a323\
   f1433bd600000000"

let missing_inputs_txid =
  "5df91f99045afe09848faea0ccad4f30937be5775bf19044c4ba1fbedca54a62"

let test_testmempoolaccept_missing_inputs_exact () =
  with_ctx (fun ctx ->
      match
        Rpc.dispatch_rpc ctx "testmempoolaccept"
          [ `List [ `String missing_inputs_hex ] ]
      with
      | Error (c, m) ->
        Alcotest.failf "missing-inputs-exact: error (%d) %s" c m
      | Ok (`List [ `Assoc fields ]) ->
        Alcotest.(check string) "txid" missing_inputs_txid
          (field_string fields "txid");
        Alcotest.(check string) "wtxid" missing_inputs_txid
          (field_string fields "wtxid");
        Alcotest.(check bool) "allowed" false (field_bool fields "allowed");
        Alcotest.(check string) "reject-reason" "missing-inputs"
          (field_string fields "reject-reason")
      | Ok j ->
        Alcotest.failf "expected [{...}], got %s" (Yojson.Safe.to_string j))

let test_testmempoolaccept_decode_error () =
  with_ctx (fun ctx ->
      check_err ~label:"testmempoolaccept decode-error" ~code:(-22)
        (Rpc.dispatch_rpc ctx "testmempoolaccept"
           [ `List [ `String "deadbeef" ] ]))

(* ============================================================================
   getnetworkhashps — tools/r5-probes.d/mining-relay.jsonl
   Help-parity is part of the method score. The type-error probe lives in
   test_r5_accepts_invalid.ml (already closed). The numeric exact-check is
   a function of live chainwork; this control pins the help listing.
   ============================================================================ *)

let test_getnetworkhashps_listed_in_help () =
  with_ctx (fun ctx ->
      match Rpc.dispatch_rpc ctx "help" [] with
      | Error (c, m) -> Alcotest.failf "help: error (%d) %s" c m
      | Ok (`String s) ->
        (try
           ignore
             (Str.search_forward (Str.regexp_string "getnetworkhashps") s 0)
         with Not_found ->
           Alcotest.fail "getnetworkhashps not listed in help")
      | Ok j ->
        Alcotest.failf "help: expected string, got %s" (Yojson.Safe.to_string j))

(* getnetworkhashps VALUE — Core rpc/mining.cpp GetNetworkHashPS (:65-104).
   A deterministic 110-block regtest chain: block h has
   time = 1296688602 + 600*h + (h*7919 mod 300), every block (genesis too)
   bits 0x207fffff so chainwork(h) = 2*(h+1). The expected values were read
   from a scratch regtest Core v31.99 that mined exactly this chain under
   setmocktime (2026-10-04). Before the fix every row returned 0: the
   rate was ~3.3e-3 and int_of_float truncated anything below 2^53. *)
let regtest_hashps_chain (ctx : Rpc.rpc_context) =
  let genesis =
    match Sync.get_header_at_height ctx.chain 0 with
    | Some e -> e
    | None -> Alcotest.fail "no genesis"
  in
  let work n =
    let cs = Cstruct.create 32 in
    Cstruct.LE.set_uint32 cs 0 (Int32.of_int n);
    cs
  in
  Alcotest.(check int32) "regtest genesis time" 1296688602l
    genesis.Sync.header.Types.timestamp;
  let prev = ref genesis in
  for h = 1 to 110 do
    let hash = Cstruct.create 32 in
    Cstruct.LE.set_uint32 hash 0 (Int32.of_int h);
    Cstruct.set_uint8 hash 4 0xA5;
    let header =
      { !prev.Sync.header with
        Types.prev_block = !prev.Sync.hash;
        timestamp = Int32.of_int (1296688602 + 600 * h + (h * 7919) mod 300) }
    in
    let e : Sync.header_entry =
      { header; hash; height = h; total_work = work (2 * (h + 1)) } in
    Hashtbl.replace ctx.chain.Sync.headers (Cstruct.to_string hash) e;
    Storage.ChainDB.set_height_hash ctx.chain.db h hash;
    prev := e
  done;
  ctx.chain.Sync.blocks_synced <- 110;
  ctx.chain.Sync.headers_synced <- 110;
  ctx.chain.Sync.tip <- Some !prev

let core_hashps_vectors = [
  (120, -1, 0.00332376491917208);     (* lookup clamps to 110: walks to genesis *)
  (120, 50, 0.003305785123966942);    (* the R5 probe shape: nblocks >= height *)
  (50, 50, 0.003305785123966942);
  (49, 50, 0.003318546612034811);
  (10, 50, 0.00333889816360601);
  (1, 1, 0.002781641168289291);
  (-1, -1, 0.00332376491917208);
  (-1, 30, 0.003284072249589491);
  (1000, 110, 0.00332376491917208);
  (110, 110, 0.00332376491917208);
  (109, 110, 0.003329718501321196);
  (3, 100, 0.003231017770597738);
]

let test_getnetworkhashps_core_values () =
  with_ctx_net Consensus.regtest (fun ctx ->
      regtest_hashps_chain ctx;
      List.iter
        (fun (nb, ht, want) ->
          let label = Printf.sprintf "getnetworkhashps %d %d" nb ht in
          match Rpc.dispatch_rpc ctx "getnetworkhashps" [ `Int nb; `Int ht ] with
          | Error (c, m) -> Alcotest.failf "%s: error (%d) %s" label c m
          | Ok (`Float f) ->
            if Float.abs (f -. want) > 1e-15 *. Float.abs want then
              Alcotest.failf "%s: got %.17g, Core %.17g" label f want
          | Ok j ->
            Alcotest.failf "%s: got %s, Core %.17g" label
              (Yojson.Safe.to_string j) want)
        core_hashps_vectors;
      (* height 0: Core returns the integer 0 (pb->nHeight == 0) *)
      match Rpc.dispatch_rpc ctx "getnetworkhashps" [ `Int 120; `Int 0 ] with
      | Ok (`Int 0) -> ()
      | Ok j -> Alcotest.failf "height 0: got %s" (Yojson.Safe.to_string j)
      | Error (c, m) -> Alcotest.failf "height 0: error (%d) %s" c m)

let () =
  let open Alcotest in
  run "R5 wrong-result (Core probe vectors)"
    [
      ( "validateaddress",
        [
          test_case "exact-invalid" `Quick test_validateaddress_exact_invalid;
          test_case "exact-valid-bech32" `Quick
            test_validateaddress_exact_valid_bech32;
          test_case "exact-valid-legacy" `Quick
            test_validateaddress_exact_valid_legacy;
        ] );
      ( "analyzepsbt",
        [
          test_case "analyze-exact" `Quick test_analyzepsbt_analyze_exact;
          test_case "bad-base64 -> -22" `Quick test_analyzepsbt_bad_base64;
        ] );
      ( "testmempoolaccept",
        [
          test_case "missing-inputs-exact" `Quick
            test_testmempoolaccept_missing_inputs_exact;
          test_case "decode-error -> -22" `Quick
            test_testmempoolaccept_decode_error;
        ] );
      ( "getnetworkhashps",
        [
          test_case "listed in help" `Quick
            test_getnetworkhashps_listed_in_help;
          test_case "Core values on a regtest chain" `Quick
            test_getnetworkhashps_core_values;
        ] );
    ]
