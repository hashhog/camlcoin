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

let put_utxo (ctx : Rpc.rpc_context) ~vout script_hex =
  let e : Utxo.utxo_entry =
    { value = 5_000_000_000L; script_pubkey = Cstruct.of_hex script_hex;
      height = 1; is_coinbase = true } in
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

let () =
  Alcotest.run "rpc_format_rows"
    [ ("scantxoutset",
       [ Alcotest.test_case "unspents[].desc is addr()#checksum" `Quick
           test_scantxoutset_desc ]) ]
