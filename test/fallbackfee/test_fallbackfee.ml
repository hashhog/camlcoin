(* -fallbackfee: sendtoaddress / send must not sign at a hardcoded rate.

   Core wallet/fees.cpp GetMinimumFeeRate: estimator answer for conf_target,
   else -fallbackfee, else (wallet/spend.cpp CreateTransactionInternal) the
   spend fails with "Fee estimation failed. Fallbackfee is disabled. Wait a
   few blocks or enable -fallbackfee."; SendMoney maps every such failure to
   RPC_WALLET_INSUFFICIENT_FUNDS (-6).  camlcoin used a literal 1.0 sat/vB. *)

open Camlcoin

let dest_addr = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"

let core_msg =
  "Fee estimation failed. Fallbackfee is disabled. \
   Wait a few blocks or enable -fallbackfee."

let dummy_tip (height : int) : Sync.header_entry =
  { header = { version = 1l; prev_block = Types.zero_hash;
               merkle_root = Types.zero_hash; timestamp = 0l;
               bits = 0l; nonce = 0l };
    hash = Types.zero_hash; height; total_work = Cstruct.create 32 }

let with_ctx f =
  Test_tmp.with_chaindb (fun db ->
      let utxo = Utxo.UtxoSet.create db in
      let mp = Mempool.create ~network:Consensus.regtest
          ~require_standard:false ~verify_scripts:false ~utxo
          ~current_height:6 () in
      let chain = Sync.create_chain_state db Consensus.regtest in
      chain.tip <- Some (dummy_tip 6);
      let wallet = Wallet.create ~network:`Regtest ~db_path:"" in
      let ctx : Rpc.rpc_context = {
        chain; mempool = mp;
        peer_manager = Peer_manager.create Consensus.regtest;
        wallet = Some wallet; wallet_manager = None;
        fee_estimator = Fee_estimation.create ();
        network = Consensus.regtest; filter_index = None; utxo = None;
        data_dir = None; snapshot_activation = None;
      } in
      let kp = Wallet.generate_key wallet in
      let script =
        Wallet.build_p2wpkh_script (Crypto.hash160 kp.Wallet.public_key) in
      let txid = Cstruct.create 32 in
      Cstruct.set_uint8 txid 0 1;
      let entry = { Utxo.value = 250_000_000L; script_pubkey = script;
                    height = 1; is_coinbase = false } in
      Utxo.UtxoSet.add utxo txid 0 entry;
      wallet.utxos <-
        [{ Wallet.outpoint = { Types.txid; vout = 0l }; utxo = entry;
           key_index = 0; confirmed = true; watch_only = false }];
      f ctx)

let with_fallback v f =
  let saved = !Fee_estimation.fallback_fee_sat_per_vb in
  Fee_estimation.fallback_fee_sat_per_vb := v;
  Fun.protect ~finally:(fun () ->
      Fee_estimation.fallback_fee_sat_per_vb := saved) f

let check_fee_err label = function
  | Error (c, m) ->
    Alcotest.(check int) (label ^ ": code") (-6) c;
    Alcotest.(check string) (label ^ ": message") core_msg m
  | Ok j ->
    Alcotest.failf "%s: spent with no estimate and no -fallbackfee: %s"
      label (Yojson.Safe.to_string j)

let test_default_is_disabled () =
  Alcotest.(check (float 0.0)) "default fallback" 0.0
    !Fee_estimation.fallback_fee_sat_per_vb

let test_sendtoaddress_without_fallbackfee () =
  with_fallback 0.0 (fun () ->
      with_ctx (fun ctx ->
          check_fee_err "sendtoaddress"
            (Rpc.dispatch_rpc ctx "sendtoaddress"
               [`String dest_addr; `Float 0.5]);
          Alcotest.(check int) "nothing in mempool" 0
            (Hashtbl.length ctx.mempool.Mempool.entries)))

let test_send_without_fallbackfee () =
  with_fallback 0.0 (fun () ->
      with_ctx (fun ctx ->
          check_fee_err "send"
            (Rpc.dispatch_rpc ctx "send"
               [`List [`Assoc [(dest_addr, `Float 0.5)]]]);
          (* an explicit fee_rate never consults the fallback *)
          match Rpc.dispatch_rpc ctx "send"
                  [`List [`Assoc [(dest_addr, `Float 0.5)]];
                   `Null; `Null; `Int 10] with
          | Ok _ -> ()
          | Error (c, m) -> Alcotest.failf "send fee_rate=10: (%d) %s" c m))

let test_sendtoaddress_pays_fallbackfee () =
  with_fallback 20.0 (fun () ->
      with_ctx (fun ctx ->
          match Rpc.dispatch_rpc ctx "sendtoaddress"
                  [`String dest_addr; `Float 0.5] with
          | Error (c, m) -> Alcotest.failf "sendtoaddress: (%d) %s" c m
          | Ok _ ->
            let fees = Hashtbl.fold (fun _ (e : Mempool.mempool_entry) acc ->
                (Int64.to_float e.fee /. (float_of_int e.weight /. 4.0)) :: acc)
                ctx.mempool.Mempool.entries [] in
            match fees with
            | [r] ->
              if r < 19.5 || r > 25.0 then
                Alcotest.failf "fee rate %.2f sat/vB, want ~20" r
            | l -> Alcotest.failf "want 1 mempool entry, got %d"
                     (List.length l)))

let () =
  Alcotest.run "fallbackfee" [
    "fallbackfee", [
      Alcotest.test_case "default disabled" `Quick test_default_is_disabled;
      Alcotest.test_case "sendtoaddress without fallbackfee -> -6" `Quick
        test_sendtoaddress_without_fallbackfee;
      Alcotest.test_case "send without fallbackfee -> -6" `Quick
        test_send_without_fallbackfee;
      Alcotest.test_case "sendtoaddress pays fallbackfee" `Quick
        test_sendtoaddress_pays_fallbackfee;
    ]]
