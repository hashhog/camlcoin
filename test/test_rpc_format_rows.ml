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
           test_info_bytes_sums_vsize ]) ]
