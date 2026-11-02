open Camlcoin

let with_ctx ?(verify_scripts = true) f =
  Test_tmp.with_chaindb (fun db ->
      let utxo = Utxo.UtxoSet.create db in
      let mp =
        Mempool.create ~network:Consensus.regtest ~require_standard:false
          ~verify_scripts ~utxo ~current_height:0 ()
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

let coin_txid = Cstruct.of_string (String.make 32 '\x07')
let coin_value = 5_000_000_000L

(* An OP_TRUE confirmed coin (txid 0x07.., [vout]). *)
let put_coin (ctx : Rpc.rpc_context) ~vout =
  let e : Utxo.utxo_entry =
    { value = coin_value; script_pubkey = Cstruct.of_string "\x51";
      height = 1; is_coinbase = false } in
  let w = Serialize.writer_create () in
  Utxo.serialize_utxo_entry w e;
  Storage.ChainDB.store_utxo ctx.chain.db coin_txid vout
    (Serialize.writer_to_string w)

let op_true = Cstruct.of_string "\x51"

let tx_hex (tx : Types.transaction) =
  let w = Serialize.writer_create () in
  Serialize.serialize_transaction w tx;
  let s = Serialize.writer_to_string w in
  String.concat "" (List.init (String.length s)
                      (fun i -> Printf.sprintf "%02x" (Char.code s.[i])))

(* One input, one value output plus a zero-value OP_RETURN so the
   non-witness size clears MIN_STANDARD_TX_NONWITNESS_SIZE. *)
let spend ~(prev_txid : Types.hash256) ~prev_vout ~value ~spk
    ?(script_sig = Cstruct.create 0) () : Types.transaction =
  { Types.version = 2l;
    inputs = [ { Types.previous_output =
                   { Types.txid = prev_txid; vout = Int32.of_int prev_vout };
                 script_sig; sequence = 0xFFFFFFFFl } ];
    outputs = [ { Types.value = value; script_pubkey = spk };
                { Types.value = 0L;
                  script_pubkey = Cstruct.of_string ("\x6a\x14" ^ String.make 20 'x') } ];
    witnesses = [];
    locktime = 0l }


let str j k = Yojson.Safe.Util.(j |> member k |> to_string)
let bool_ j k = Yojson.Safe.Util.(j |> member k |> to_bool)

let tx_ok ctx = 
  put_coin ctx ~vout:0;
  spend ~prev_txid:coin_txid ~prev_vout:0
    ~value:(Int64.sub coin_value 10_000L) ~spk:op_true ()

(* Core BroadcastTransaction: re-sending a tx already in the mempool returns
   its txid.  camlcoin answered -26 "rejecting replacement ... 0 < 11"
   (operator/sendrawtransaction/in-mempool). *)
let test_sendraw_in_mempool () =
  with_ctx ~verify_scripts:false (fun ctx ->
      let tx = tx_ok ctx in
      let hex = tx_hex tx in
      let want = Types.hash256_to_hex_display (Crypto.compute_txid tx) in
      (match Rpc.dispatch_rpc ctx "sendrawtransaction" [ `String hex ] with
       | Ok (`String s) -> Alcotest.(check string) "first send" want s
       | _ -> Alcotest.fail "first send failed");
      match Rpc.dispatch_rpc ctx "sendrawtransaction" [ `String hex ] with
      | Ok (`String s) -> Alcotest.(check string) "second send" want s
      | Ok j -> Alcotest.failf "unexpected %s" (Yojson.Safe.to_string j)
      | Error (c, m) -> Alcotest.failf "second send error (%d) %s" c m)

(* Core testmempoolaccept takes [rawtxs, maxfeerate]; 0 lifts the cap.
   camlcoin answered "Invalid parameters: expected [[rawtx]]"
   (operator/testmempoolaccept/maxfeerate-zero). *)
let test_tma_maxfeerate_arg () =
  with_ctx ~verify_scripts:false (fun ctx ->
      let tx = tx_ok ctx in
      match Rpc.dispatch_rpc ctx "testmempoolaccept"
              [ `List [ `String (tx_hex tx) ]; `Int 0 ] with
      | Ok (`List [ r ]) -> Alcotest.(check bool) "allowed" true (bool_ r "allowed")
      | Ok j -> Alcotest.failf "unexpected %s" (Yojson.Safe.to_string j)
      | Error (c, m) -> Alcotest.failf "error (%d) %s" c m)

(* A fee above the cap is allowed=false / max-fee-exceeded (10000 sat on a
   ~110 vB tx is ~0.0009 BTC/kvB, so a 0.0001 cap trips it). *)
let test_tma_maxfeerate_exceeded () =
  with_ctx ~verify_scripts:false (fun ctx ->
      let tx = tx_ok ctx in
      match Rpc.dispatch_rpc ctx "testmempoolaccept"
              [ `List [ `String (tx_hex tx) ]; `Float 0.0001 ] with
      | Ok (`List [ r ]) ->
        Alcotest.(check bool) "allowed" false (bool_ r "allowed");
        Alcotest.(check string) "reason" "max-fee-exceeded" (str r "reject-reason")
      | Ok j -> Alcotest.failf "unexpected %s" (Yojson.Safe.to_string j)
      | Error (c, m) -> Alcotest.failf "error (%d) %s" c m)

let () =
  Alcotest.run "node_error_rows"
    [ ("sendrawtransaction", [ Alcotest.test_case "in-mempool returns txid" `Quick test_sendraw_in_mempool ]);
      ("testmempoolaccept", [
          Alcotest.test_case "maxfeerate arg" `Quick test_tma_maxfeerate_arg;
          Alcotest.test_case "maxfeerate exceeded" `Quick test_tma_maxfeerate_exceeded ]) ]
