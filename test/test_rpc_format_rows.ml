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
