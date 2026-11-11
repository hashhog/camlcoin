(* getwalletinfo must not emit balance / unconfirmed_balance / immature_balance.

   Core v31.1 wallet/rpc/wallet.cpp RPCHelpMan getwalletinfo has no balance
   fields (they live in getbalances / getbalance).  camlcoin emitted all
   three, immature_balance as a constant 0.0. *)

open Camlcoin

let with_ctx f =
  Test_tmp.with_chaindb (fun db ->
      let utxo = Utxo.UtxoSet.create db in
      let mp = Mempool.create ~network:Consensus.regtest
          ~require_standard:false ~verify_scripts:false ~utxo
          ~current_height:6 () in
      let chain = Sync.create_chain_state db Consensus.regtest in
      let wallet = Wallet.create ~network:`Regtest ~db_path:"" in
      let ctx : Rpc.rpc_context = {
        chain; mempool = mp;
        peer_manager = Peer_manager.create Consensus.regtest;
        wallet = Some wallet; wallet_manager = None;
        fee_estimator = Fee_estimation.create ();
        network = Consensus.regtest; filter_index = None; utxo = None;
        data_dir = None; snapshot_activation = None;
      } in
      f ctx)

let keys_of ctx =
  match Rpc.handle_getwalletinfo ctx None [] with
  | Ok (`Assoc kv) -> List.map fst kv
  | Ok _ -> Alcotest.fail "getwalletinfo: not an object"
  | Error e -> Alcotest.failf "getwalletinfo failed: %s" e

let test_no_balance_fields () =
  with_ctx (fun ctx ->
      let keys = keys_of ctx in
      List.iter (fun k ->
          if List.mem k keys then
            Alcotest.failf
              "getwalletinfo still reports '%s': Core v31 has no such field" k)
        ["balance"; "unconfirmed_balance"; "immature_balance"])

let test_keeps_core_fields () =
  with_ctx (fun ctx ->
      let keys = keys_of ctx in
      List.iter (fun k ->
          Alcotest.(check bool) ("has " ^ k) true (List.mem k keys))
        ["walletname"; "walletversion"; "format"; "txcount"; "keypoolsize";
         "private_keys_enabled"; "avoid_reuse"; "scanning"; "descriptors";
         "external_signer"; "blank"; "flags"; "lastprocessedblock"])

let () =
  Alcotest.run "getwalletinfo_no_balance" [
    "getwalletinfo", [
      Alcotest.test_case "has no balance fields" `Quick test_no_balance_fields;
      Alcotest.test_case "keeps Core fields" `Quick test_keeps_core_fields;
    ];
  ]
