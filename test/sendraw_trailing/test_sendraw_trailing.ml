(* Core's DecodeHexTx (core_io.cpp) requires the hex to be consumed exactly:
   a valid tx followed by extra bytes fails with RPC_DESERIALIZATION_ERROR
   (-22) "TX decode failed. Make sure the tx has at least one input."
   Regtest ratchet row operator/sendrawtransaction/trailing: Core -22,
   camlcoin used to accept the tx and return its txid. *)
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
        { chain; mempool = mp;
          peer_manager = Peer_manager.create Consensus.regtest;
          wallet = None; wallet_manager = None;
          fee_estimator = Fee_estimation.create ();
          network = Consensus.regtest; filter_index = None; utxo = None;
          data_dir = None; snapshot_activation = None }
      in
      f ctx)

let coin_txid = Cstruct.of_string (String.make 32 '\x07')

let put_coin (ctx : Rpc.rpc_context) =
  let e : Utxo.utxo_entry =
    { value = 5_000_000_000L; script_pubkey = Cstruct.of_string "\x51";
      height = 1; is_coinbase = false } in
  let w = Serialize.writer_create () in
  Utxo.serialize_utxo_entry w e;
  Storage.ChainDB.store_utxo ctx.chain.db coin_txid 0
    (Serialize.writer_to_string w)

let tx_hex (tx : Types.transaction) =
  let w = Serialize.writer_create () in
  Serialize.serialize_transaction w tx;
  let s = Serialize.writer_to_string w in
  String.concat "" (List.init (String.length s)
                      (fun i -> Printf.sprintf "%02x" (Char.code s.[i])))

let spend : Types.transaction =
  { Types.version = 2l;
    inputs = [ { Types.previous_output = { Types.txid = coin_txid; vout = 0l };
                 script_sig = Cstruct.create 0; sequence = 0xFFFFFFFFl } ];
    outputs = [ { Types.value = 4_999_990_000L;
                  script_pubkey = Cstruct.of_string "\x51" };
                { Types.value = 0L;
                  script_pubkey = Cstruct.of_string ("\x6a\x14" ^ String.make 20 'x') } ];
    witnesses = []; locktime = 0l }

let test_trailing_rejected () =
  with_ctx (fun ctx ->
      put_coin ctx;
      match Rpc.dispatch_rpc ctx "sendrawtransaction"
              [ `String (tx_hex spend ^ "00") ] with
      | Error (c, m) ->
        Alcotest.(check int) "code" (-22) c;
        Alcotest.(check string) "message"
          "TX decode failed. Make sure the tx has at least one input." m
      | Ok j -> Alcotest.failf "trailing bytes accepted: %s"
                  (Yojson.Safe.to_string j))

let test_exact_accepted () =
  with_ctx (fun ctx ->
      put_coin ctx;
      match Rpc.dispatch_rpc ctx "sendrawtransaction" [ `String (tx_hex spend) ] with
      | Ok (`String _) -> ()
      | Ok j -> Alcotest.failf "unexpected %s" (Yojson.Safe.to_string j)
      | Error (c, m) -> Alcotest.failf "control rejected: %d %s" c m)

let () =
  Alcotest.run "sendraw_trailing"
    [ ("sendrawtransaction",
       [ Alcotest.test_case "trailing bytes -> -22" `Quick test_trailing_rejected;
         Alcotest.test_case "exact hex still accepted" `Quick test_exact_accepted ]) ]
