(* RPC-formatting rows from the camlcoin Core-regtest baseline
   (item camlcoin-regtest-rpc-format-rows).  Each test is one row class:
   Core's value is quoted in the test, from the v31.1 regtest oracle run. *)

open Camlcoin

let with_ctx f =
  Test_tmp.with_chaindb (fun db ->
      let utxo = Utxo.UtxoSet.create db in
      let mp =
        Mempool.create ~network:Consensus.regtest ~require_standard:false
          ~verify_scripts:false ~utxo ~current_height:0 ()
      in
      let chain = Sync.create_chain_state db Consensus.regtest in
      let ctx : Rpc.rpc_context =
        {
          chain;
          mempool = mp;
          peer_manager = Peer_manager.create Consensus.regtest;
          wallet = None;
          wallet_manager = None;
          fee_estimator = Fee_estimation.create ();
          network = Consensus.regtest;
          filter_index = None;
          utxo = None;
          data_dir = None;
          snapshot_activation = None;
        }
      in
      f ctx)

let put_utxo ?(coinbase = true) (ctx : Rpc.rpc_context) ~vout script_hex =
  let e : Utxo.utxo_entry =
    { value = 5_000_000_000L; script_pubkey = Cstruct.of_hex script_hex;
      height = 1; is_coinbase = coinbase } in
  let w = Serialize.writer_create () in
  Utxo.serialize_utxo_entry w e;
  Storage.ChainDB.store_utxo ctx.chain.db
    (Cstruct.of_string (String.make 32 '\x07')) vout
    (Serialize.writer_to_string w)

(* Core scantxoutset: unspents[].desc = InferDescriptor(scriptPubKey), with
   checksum.  Core (regtest) answered
   addr(2ND8PB9RrfCaAcjfjP1Y6nAgFd9zWHYX4DN)#pn0u88a8 for this script;
   the node answered raw(a914...) with no checksum. *)
let test_scantxoutset_desc () =
  with_ctx (fun ctx ->
      let spk = "a914da1745e9b549bd0bfa1a569971c77eba30cd5a4b87" in
      put_utxo ctx ~vout:0 spk;
      match Rpc.dispatch_rpc ctx "scantxoutset"
              [ `String "start"; `List [ `String ("raw(" ^ spk ^ ")") ] ] with
      | Error (c, m) -> Alcotest.failf "scantxoutset: error (%d) %s" c m
      | Ok j ->
        let open Yojson.Safe.Util in
        let u = List.hd (j |> member "unspents" |> to_list) in
        Alcotest.(check string) "desc"
          "addr(2ND8PB9RrfCaAcjfjP1Y6nAgFd9zWHYX4DN)#pn0u88a8"
          (u |> member "desc" |> to_string))

(* ---- locally submitted tx: unbroadcast + getmempoolinfo bytes ---- *)

let op_true = Cstruct.of_string "\x51"

let tx_hex (tx : Types.transaction) =
  let w = Serialize.writer_create () in
  Serialize.serialize_transaction w tx;
  let s = Serialize.writer_to_string w in
  String.concat "" (List.init (String.length s)
                      (fun i -> Printf.sprintf "%02x" (Char.code s.[i])))

(* Spend the seeded OP_TRUE coin (txid 0x07.., vout 0) with a witness-carrying
   input so the tx weight is not a multiple of 4. *)
let seeded_spend () : Types.transaction =
  { Types.version = 2l;
    inputs = [ { Types.previous_output =
                   { Types.txid = Cstruct.of_string (String.make 32 '\x07');
                     vout = 0l };
                 script_sig = Cstruct.create 0; sequence = 0xFFFFFFFFl } ];
    outputs = [ { Types.value = 4_999_990_000L; script_pubkey = op_true };
                { Types.value = 0L;
                  script_pubkey = Cstruct.of_string ("\x6a\x14" ^ String.make 20 'x') } ];
    witnesses = [ { Types.items = [ Cstruct.of_string "\x01" ] } ];
    locktime = 0l }

let submit ctx =
  put_utxo ~coinbase:false ctx ~vout:0 "51";
  let tx = seeded_spend () in
  (match Rpc.dispatch_rpc ctx "sendrawtransaction" [ `String (tx_hex tx) ] with
   | Ok _ -> ()
   | Error (c, m) -> Alcotest.failf "sendrawtransaction: error (%d) %s" c m);
  tx

(* Core: BroadcastTransaction -> AddUnbroadcastTx, kept until a peer fetches
   it.  With no peers the entry is unbroadcast=true and getmempoolinfo counts
   it (regtest rows mempool/entry/*:unbroadcast, mempool/info/pool:
   unbroadcastcount). *)
let test_unbroadcast_after_sendraw () =
  with_ctx (fun ctx ->
      let tx = submit ctx in
      let txid = Types.hash256_to_hex_display (Crypto.compute_txid tx) in
      let open Yojson.Safe.Util in
      (match Rpc.dispatch_rpc ctx "getmempoolentry" [ `String txid ] with
       | Error (c, m) -> Alcotest.failf "getmempoolentry: error (%d) %s" c m
       | Ok j ->
         Alcotest.(check bool) "entry.unbroadcast" true
           (j |> member "unbroadcast" |> to_bool));
      (match Rpc.dispatch_rpc ctx "getmempoolinfo" [] with
       | Error (c, m) -> Alcotest.failf "getmempoolinfo: error (%d) %s" c m
       | Ok j ->
         Alcotest.(check int) "unbroadcastcount" 1
           (j |> member "unbroadcastcount" |> to_int)))

(* Once a peer has been served the tx (getdata) it is no longer unbroadcast. *)
let test_unbroadcast_cleared_when_served () =
  with_ctx (fun ctx ->
      let tx = submit ctx in
      let id = Crypto.compute_txid tx in
      let open Yojson.Safe.Util in
      let unbroadcast () =
        match Rpc.dispatch_rpc ctx "getmempoolentry"
                [ `String (Types.hash256_to_hex_display id) ] with
        | Error (c, m) -> Alcotest.failf "getmempoolentry: error (%d) %s" c m
        | Ok j -> j |> member "unbroadcast" |> to_bool
      in
      Alcotest.(check bool) "before serving" true (unbroadcast ());
      Mempool.remove_unbroadcast ctx.mempool id;
      Alcotest.(check bool) "after serving" false (unbroadcast ()))

(* Core getmempoolinfo.bytes = sum of per-tx vsize (ceil), not
   floor(total weight / 4) (regtest row ...info:bytes: core 220, node 218). *)
let test_info_bytes_sums_vsize () =
  with_ctx (fun ctx ->
      let tx = submit ctx in
      let w = Serialize.writer_create () in
      Serialize.serialize_transaction w tx;
      let weight = Validation.compute_tx_weight tx in
      let open Yojson.Safe.Util in
      match Rpc.dispatch_rpc ctx "getmempoolinfo" [] with
      | Error (c, m) -> Alcotest.failf "getmempoolinfo: error (%d) %s" c m
      | Ok j ->
        Alcotest.(check bool) "weight is not a multiple of 4" true
          (weight mod 4 <> 0);
        Alcotest.(check int) "bytes" ((weight + 3) / 4)
          (j |> member "bytes" |> to_int))

(* ---- operator rows: error text and argument forms ---- *)

let err_of = function
  | Error (c, m) -> (c, m)
  | Ok j -> Alcotest.failf "expected error, got Ok %s" (Yojson.Safe.to_string j)

let check_err ~label ~code ~msg r =
  let c, m = err_of r in
  Alcotest.(check int) (label ^ ": code") code c;
  Alcotest.(check string) (label ^ ": message") msg m

(* Core: DecodeHexTx failures are the bare "TX decode failed" (-22); operator/
   decoderawtransaction/{empty,not-hex,one-byte,truncated}:message. *)
let test_decoderawtransaction_message () =
  with_ctx (fun ctx ->
      List.iter (fun hex ->
          check_err ~label:("decode " ^ hex) ~code:(-22) ~msg:"TX decode failed"
            (Rpc.dispatch_rpc ctx "decoderawtransaction" [ `String hex ]))
        [ ""; "zz"; "02"; "0200000001" ])

(* Core rejects a hex string with bytes left over after the transaction
   (operator/decoderawtransaction/trailing:$ -> -22), and iswitness=false on a
   witness-serialized tx (segwit-iswitness-false:$ -> -22). *)
let test_decoderawtransaction_trailing_and_iswitness () =
  with_ctx (fun ctx ->
      let tx = seeded_spend () in
      let hex = tx_hex tx in
      (match Rpc.dispatch_rpc ctx "decoderawtransaction" [ `String hex ] with
       | Ok _ -> ()
       | Error (c, m) -> Alcotest.failf "plain decode: (%d) %s" c m);
      check_err ~label:"trailing" ~code:(-22) ~msg:"TX decode failed"
        (Rpc.dispatch_rpc ctx "decoderawtransaction" [ `String (hex ^ "00") ]);
      check_err ~label:"iswitness=false" ~code:(-22) ~msg:"TX decode failed"
        (Rpc.dispatch_rpc ctx "decoderawtransaction"
           [ `String hex; `Bool false ]))

(* Core getrawtransaction names the txid argument "parameter 1" and appends the
   wallet hint to the not-in-block message. *)
let test_getrawtransaction_messages () =
  with_ctx (fun ctx ->
      check_err ~label:"short txid" ~code:(-8)
        ~msg:"parameter 1 must be of length 64 (not 2, for '00')"
        (Rpc.dispatch_rpc ctx "getrawtransaction" [ `String "00" ]))

(* getblock accepts the boolean verbosity (true -> 1, false -> 0): an absent
   block is -5, not an argument-shape error (operator/getblock/{true,false}). *)
let test_getblock_bool_verbosity () =
  with_ctx (fun ctx ->
      let absent = String.make 64 'a' in
      List.iter (fun b ->
          let c, _ = err_of (Rpc.dispatch_rpc ctx "getblock"
                               [ `String absent; `Bool b ]) in
          Alcotest.(check int) "code" (-5) c) [ true; false ])

(* Core only fills fee/prevout from a block's undo data: a mempool tx at
   verbosity 2 carries neither. *)
let test_getrawtransaction_mempool_v2 () =
  with_ctx (fun ctx ->
      let tx = submit ctx in
      (* Give the spent coin a creating block + tx index entry, the source the
         old code used to invent fee/prevout for a mempool tx. *)
      let creating : Types.transaction =
        { Types.version = 2l;
          inputs = [ { Types.previous_output =
                         { Types.txid = Cstruct.create 32; vout = 0xFFFFFFFFl };
                       script_sig = Cstruct.of_string "\x01\x01";
                       sequence = 0xFFFFFFFFl } ];
          outputs = [ { Types.value = 5_000_000_000L; script_pubkey = op_true } ];
          witnesses = []; locktime = 0l } in
      let header : Types.block_header =
        { version = 4l; prev_block = Cstruct.create 32;
          merkle_root = Cstruct.create 32; timestamp = 1l; bits = 0x207fffffl;
          nonce = 1l } in
      let bh = Crypto.compute_block_hash header in
      Storage.ChainDB.store_block ctx.chain.db bh
        { Types.header; transactions = [ creating ] };
      Storage.ChainDB.store_tx_index ctx.chain.db
        (Cstruct.of_string (String.make 32 '\x07')) bh 0;
      let txid = Types.hash256_to_hex_display (Crypto.compute_txid tx) in
      let open Yojson.Safe.Util in
      match Rpc.dispatch_rpc ctx "getrawtransaction"
              [ `String txid; `Int 2 ] with
      | Error (c, m) -> Alcotest.failf "getrawtransaction: (%d) %s" c m
      | Ok j ->
        Alcotest.(check bool) "no fee" true (member "fee" j = `Null);
        let vin0 = List.hd (j |> member "vin" |> to_list) in
        Alcotest.(check bool) "no prevout" true (member "prevout" vin0 = `Null))

(* ---- network-dependent encodings on regtest ---- *)

let tpub =
  "tpubD6NzVbkrYhZ4XgiXtGrdW5XDAPFCL9h7we1vwNCpn8tGbBcgfVYjXyhWo4E1xkh56hjod1RhGjxbaTLV3X4FyWuejifB9jusQ46QzG87VKp"

(* Core echoes the key as given: a tpub stays a tpub (r5-remeasure-2026-10-04:
   the node returned an xpub on regtest). *)
let test_getdescriptorinfo_keeps_tpub () =
  with_ctx (fun ctx ->
      let open Yojson.Safe.Util in
      match Rpc.dispatch_rpc ctx "getdescriptorinfo"
              [ `String ("wpkh(" ^ tpub ^ "/0/*)") ] with
      | Error (c, m) -> Alcotest.failf "getdescriptorinfo: (%d) %s" c m
      | Ok j ->
        Alcotest.(check string) "descriptor"
          ("wpkh(" ^ tpub ^ "/0/*)")
          (let d = j |> member "descriptor" |> to_string in
           match String.index_opt d '#' with
           | Some i -> String.sub d 0 i
           | None -> d))

let psbt_b64 =
  "cHNidP8BAFICAAAAAaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqAAAAAAD9////\
   AaCGAQAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9YAAAAAAAAA"

(* decodepsbt encodes addresses for the node's own network: bcrt1 on regtest. *)
let test_decodepsbt_regtest_hrp () =
  with_ctx (fun ctx ->
      let open Yojson.Safe.Util in
      match Rpc.dispatch_rpc ctx "decodepsbt" [ `String psbt_b64 ] with
      | Error (c, m) -> Alcotest.failf "decodepsbt: (%d) %s" c m
      | Ok j ->
        let vout0 = List.hd (j |> member "tx" |> member "vout" |> to_list) in
        Alcotest.(check string) "address"
          "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"
          (vout0 |> member "scriptPubKey" |> member "address" |> to_string))

(* A mainnet address is not valid on regtest (Core DecodeDestination checks
   the chain's prefixes). *)
let test_validateaddress_wrong_network () =
  with_ctx (fun ctx ->
      let open Yojson.Safe.Util in
      let check addr err =
        match Rpc.dispatch_rpc ctx "validateaddress" [ `String addr ] with
        | Error (c, m) -> Alcotest.failf "validateaddress: (%d) %s" c m
        | Ok j ->
          Alcotest.(check bool) (addr ^ " isvalid") false
            (j |> member "isvalid" |> to_bool);
          Alcotest.(check string) (addr ^ " error") err
            (j |> member "error" |> to_string)
      in
      check "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        "Invalid or unsupported prefix for Segwit (Bech32) address \
         (expected bcrt, got bc).";
      check "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
        "Invalid or unsupported Base58-encoded address.";
      (match Rpc.dispatch_rpc ctx "validateaddress"
               [ `String "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080" ] with
       | Ok j -> Alcotest.(check bool) "regtest address valid" true
                   (j |> member "isvalid" |> to_bool)
       | Error (c, m) -> Alcotest.failf "validateaddress: (%d) %s" c m))

(* getblock verbosity 3: non-coinbase inputs carry prevout from the undo data
   (operator/getblock/bad-verbosity:tx[N].vin[0].prevout). *)
let test_getblock_verbosity3_prevout () =
  with_ctx (fun ctx ->
      let spend = seeded_spend () in
      let cb : Types.transaction =
        { Types.version = 2l;
          inputs = [ { Types.previous_output =
                         { Types.txid = Cstruct.create 32; vout = 0xFFFFFFFFl };
                       script_sig = Cstruct.of_string "\x01\x01";
                       sequence = 0xFFFFFFFFl } ];
          outputs = [ { Types.value = 1L; script_pubkey = op_true } ];
          witnesses = []; locktime = 0l } in
      let header : Types.block_header =
        { version = 4l; prev_block = Cstruct.create 32;
          merkle_root = Cstruct.create 32; timestamp = 1l; bits = 0x207fffffl;
          nonce = 0l } in
      let block = { Types.header; transactions = [ cb; spend ] } in
      let hash = Crypto.compute_block_hash header in
      Storage.ChainDB.store_block ctx.chain.db hash block;
      let entry : Utxo.utxo_entry =
        { value = 5_000_000_000L; script_pubkey = op_true; height = 7;
          is_coinbase = true } in
      let undo : Utxo.undo_data =
        { height = 1;
          tx_undos = [ { spent_outputs =
                           [ (List.hd spend.inputs).previous_output, entry ] } ] } in
      let w = Serialize.writer_create () in
      Utxo.serialize_undo_data w undo;
      Storage.ChainDB.store_undo_data ctx.chain.db hash
        (Serialize.writer_to_string w);
      let open Yojson.Safe.Util in
      match Rpc.dispatch_rpc ctx "getblock"
              [ `String (Types.hash256_to_hex_display hash); `Int 3 ] with
      | Error (c, m) -> Alcotest.failf "getblock: (%d) %s" c m
      | Ok j ->
        let tx1 = List.nth (j |> member "tx" |> to_list) 1 in
        let prevout = List.hd (tx1 |> member "vin" |> to_list) |> member "prevout" in
        Alcotest.(check bool) "generated" true (prevout |> member "generated" |> to_bool);
        Alcotest.(check int) "height" 7 (prevout |> member "height" |> to_int);
        Alcotest.(check string) "hex" "51"
          (prevout |> member "scriptPubKey" |> member "hex" |> to_string);
        (* verbosity 2 stays prevout-free *)
        (match Rpc.dispatch_rpc ctx "getblock"
                 [ `String (Types.hash256_to_hex_display hash); `Int 2 ] with
         | Error (c, m) -> Alcotest.failf "getblock v2: (%d) %s" c m
         | Ok j2 ->
           let v = List.hd (List.nth (j2 |> member "tx" |> to_list) 1
                            |> member "vin" |> to_list) in
           Alcotest.(check bool) "v2 has no prevout" true
             (member "prevout" v = `Null)))

(* getrawtransaction / testmempoolaccept / submitpackage fee fields. *)
let test_feerate_floor_and_testmempoolaccept () =
  with_ctx (fun ctx ->
      put_utxo ~coinbase:false ctx ~vout:0 "51";
      let tx = seeded_spend () in
      let open Yojson.Safe.Util in
      match Rpc.dispatch_rpc ctx "testmempoolaccept"
              [ `List [ `String (tx_hex tx) ] ] with
      | Error (c, m) -> Alcotest.failf "testmempoolaccept: (%d) %s" c m
      | Ok j ->
        let r = List.hd (to_list j) in
        let fees = r |> member "fees" in
        let vsize = r |> member "vsize" |> to_int in
        (* Core: integer sat/kvB = 10000 * 1000 / vsize, shown in BTC/kvB *)
        let want = Float.of_int (10_000_000 / vsize) /. 1e8 in
        Alcotest.(check (float 1e-12)) "effective-feerate" want
          (fees |> member "effective-feerate" |> to_float);
        Alcotest.(check (list string)) "effective-includes"
          [ r |> member "wtxid" |> to_string ]
          (fees |> member "effective-includes" |> to_list |> List.map to_string))

(* Core AcceptPackage: a zero-fee parent is only accepted together with its
   child; both then report the package feerate and both wtxids in
   effective-includes (package/submit/cpfp, seed_submitpackage/valid-cpfp). *)
let test_submitpackage_cpfp_effective () =
  with_ctx (fun ctx ->
      put_utxo ~coinbase:false ctx ~vout:0 "51";
      let pad = Cstruct.of_string ("\x6a\x14" ^ String.make 20 'x') in
      let mk prev value : Types.transaction =
        { Types.version = 2l;
          inputs = [ { Types.previous_output = { Types.txid = prev; vout = 0l };
                       script_sig = Cstruct.create 0; sequence = 0xFFFFFFFFl } ];
          outputs = [ { Types.value = value; script_pubkey = op_true };
                      { Types.value = 0L; script_pubkey = pad } ];
          witnesses = []; locktime = 0l } in
      let parent = mk (Cstruct.of_string (String.make 32 '\x07')) 4_999_999_999L in
      let child = mk (Crypto.compute_txid parent) 4_999_989_999L in
      let open Yojson.Safe.Util in
      match Rpc.dispatch_rpc ctx "submitpackage"
              [ `List [ `String (tx_hex parent); `String (tx_hex child) ] ] with
      | Error (c, m) -> Alcotest.failf "submitpackage: (%d) %s" c m
      | Ok j ->
        Alcotest.(check string) "package_msg" "success"
          (j |> member "package_msg" |> to_string);
        let ws = List.map (fun t ->
          Types.hash256_to_hex_display (Crypto.compute_wtxid t)) [ parent; child ] in
        let vsize t = (Validation.compute_tx_weight t + 3) / 4 in
        let want = Float.of_int ((1 + 10_000) * 1000 / (vsize parent + vsize child))
                   /. 1e8 in
        List.iter (fun w ->
          let fees = j |> member "tx-results" |> member w |> member "fees" in
          Alcotest.(check (list string)) "includes" ws
            (fees |> member "effective-includes" |> to_list |> List.map to_string);
          Alcotest.(check (float 1e-12)) "package feerate" want
            (fees |> member "effective-feerate" |> to_float)) ws)

(* RBF feerate-diagram failure (rbf/diagram rows): testmempoolaccept answers the
   token "replacement-failed" and the detail separately; sendrawtransaction
   shows "token, detail" (Core state.ToString()). *)
let test_replacement_failed_token () =
  let msg = "insufficient feerate: does not improve feerate diagram" in
  Alcotest.(check string) "testmempoolaccept" "replacement-failed"
    (Rpc.canonical_mempool_reject_reason ~testmempoolaccept:true msg);
  Alcotest.(check string) "sendrawtransaction"
    ("replacement-failed, " ^ msg)
    (Rpc.canonical_mempool_reject_reason ~testmempoolaccept:false msg)

(* A package member that cannot be admitted: package_msg "transaction failed"
   and the bare token for the failing tx (package/submit/missing-input). *)
let test_submitpackage_failed_member () =
  with_ctx (fun ctx ->
      put_utxo ~coinbase:false ctx ~vout:0 "51";
      let good = seeded_spend () in
      let bad : Types.transaction =
        { good with
          inputs = [ { Types.previous_output =
                         { Types.txid = Crypto.compute_txid good; vout = 5l };
                       script_sig = Cstruct.create 0; sequence = 0xFFFFFFFFl } ];
          witnesses = [] } in
      let open Yojson.Safe.Util in
      match Rpc.dispatch_rpc ctx "submitpackage"
              [ `List [ `String (tx_hex good); `String (tx_hex bad) ] ] with
      | Error (c, m) -> Alcotest.failf "submitpackage: (%d) %s" c m
      | Ok j ->
        Alcotest.(check string) "package_msg" "transaction failed"
          (j |> member "package_msg" |> to_string);
        let w = Types.hash256_to_hex_display (Crypto.compute_wtxid bad) in
        Alcotest.(check string) "error" "bad-txns-inputs-missingorspent"
          (j |> member "tx-results" |> member w |> member "error" |> to_string))

let () =
  Alcotest.run "rpc_format_rows"
    [ ("scantxoutset",
       [ Alcotest.test_case "unspents[].desc is addr()#checksum" `Quick
           test_scantxoutset_desc ]);
      ("mempool",
       [ Alcotest.test_case "sendrawtransaction leaves tx unbroadcast" `Quick
           test_unbroadcast_after_sendraw;
         Alcotest.test_case "serving the tx clears unbroadcast" `Quick
           test_unbroadcast_cleared_when_served;
         Alcotest.test_case "getmempoolinfo bytes sums per-tx vsize" `Quick
           test_info_bytes_sums_vsize ]);
      ("network",
       [ Alcotest.test_case "getdescriptorinfo keeps tpub" `Quick
           test_getdescriptorinfo_keeps_tpub;
         Alcotest.test_case "decodepsbt uses the regtest hrp" `Quick
           test_decodepsbt_regtest_hrp;
         Alcotest.test_case "validateaddress rejects other-network address" `Quick
           test_validateaddress_wrong_network ]);
      ("fees",
       [ Alcotest.test_case "getblock verbosity 3 carries prevout" `Quick
           test_getblock_verbosity3_prevout;
         Alcotest.test_case "testmempoolaccept effective-feerate/includes" `Quick
           test_feerate_floor_and_testmempoolaccept;
         Alcotest.test_case "replacement-failed token / detail split" `Quick
           test_replacement_failed_token;
         Alcotest.test_case "submitpackage failed member message/token" `Quick
           test_submitpackage_failed_member;
         Alcotest.test_case "submitpackage cpfp reports the package feerate" `Quick
           test_submitpackage_cpfp_effective ]);
      ("operator",
       [ Alcotest.test_case "decoderawtransaction message" `Quick
           test_decoderawtransaction_message;
         Alcotest.test_case "decoderawtransaction trailing / iswitness" `Quick
           test_decoderawtransaction_trailing_and_iswitness;
         Alcotest.test_case "getrawtransaction parameter 1" `Quick
           test_getrawtransaction_messages;
         Alcotest.test_case "getblock boolean verbosity" `Quick
           test_getblock_bool_verbosity;
         Alcotest.test_case "getrawtransaction mempool v2 no fee/prevout" `Quick
           test_getrawtransaction_mempool_v2 ]) ]
