(* Core without -txindex: getrawtransaction <confirmed txid> with no blockhash
   -> RPC_INVALID_ADDRESS_OR_KEY (-5) "No such mempool transaction. Use
   -txindex or provide a block hash ...".  camlcoin always keeps the index and
   used to return the tx (ratchet row operator/getrawtransaction/confirmed-no-index). *)
open Camlcoin

let core_msg =
  "No such mempool transaction. Use -txindex or provide a block hash to \
   enable blockchain transaction queries. Use gettransaction for wallet \
   transactions."

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

let tx : Types.transaction =
  { Types.version = 2l;
    inputs = [ { Types.previous_output =
                   { Types.txid = Cstruct.of_string (String.make 32 '\x07'); vout = 0l };
                 script_sig = Cstruct.create 0; sequence = 0xFFFFFFFFl } ];
    outputs = [ { Types.value = 1000L; script_pubkey = Cstruct.of_string "\x51" } ];
    witnesses = []; locktime = 0l }

(* Store [tx] as confirmed (txindex entry + body) in a fake block. *)
let confirm ctx =
  let txid = Crypto.compute_txid tx in
  let bh = Cstruct.of_string (String.make 32 '\x09') in
  Storage.ChainDB.store_tx_index ctx.Rpc.chain.db txid bh 0;
  Storage.ChainDB.store_transaction ctx.Rpc.chain.db txid tx;
  txid

let hex_of_txid txid =
  let n = Cstruct.length txid in
  String.concat "" (List.init n (fun i ->
      Printf.sprintf "%02x" (Cstruct.get_uint8 txid (n - 1 - i))))

let call ctx txid =
  Rpc.dispatch_rpc ctx "getrawtransaction" [ `String (hex_of_txid txid) ]

let test_default_errors () =
  with_ctx (fun ctx ->
      let txid = confirm ctx in
      match call ctx txid with
      | Error (c, m) ->
        Alcotest.(check int) "code" (-5) c;
        Alcotest.(check string) "message" core_msg m
      | Ok _ -> Alcotest.fail "confirmed tx returned without -txindex")

let test_unknown_message () =
  with_ctx (fun ctx ->
      match call ctx (Cstruct.of_string (String.make 32 '\x33')) with
      | Error (c, m) ->
        Alcotest.(check int) "code" (-5) c;
        Alcotest.(check string) "message" core_msg m
      | Ok _ -> Alcotest.fail "unknown tx returned")

let () =
  Alcotest.run "getrawtx_txindex"
    [ ("getrawtransaction",
       [ Alcotest.test_case "no -txindex: confirmed tx -> -5" `Quick test_default_errors;
         Alcotest.test_case "unknown tx message" `Quick test_unknown_message ]) ]
