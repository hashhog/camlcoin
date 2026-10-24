(* setmocktime (item done-camlcoin-setmocktime).  Core rpc/node.cpp: regtest
   only, 0 restores the system clock, negative is -8.  The mempool's policy
   clock (rolling min-fee decay) must follow the mock time. *)

open Camlcoin

let with_ctx ?(network = Consensus.regtest) f =
  Test_tmp.with_chaindb (fun db ->
      let utxo = Utxo.UtxoSet.create db in
      let mp =
        Mempool.create ~network ~require_standard:false
          ~verify_scripts:false ~utxo ~current_height:0 ()
      in
      let chain = Sync.create_chain_state db network in
      let ctx : Rpc.rpc_context =
        {
          chain; mempool = mp;
          peer_manager = Peer_manager.create network;
          wallet = None; wallet_manager = None;
          fee_estimator = Fee_estimation.create ();
          network; filter_index = None; utxo = None; data_dir = None;
          snapshot_activation = None;
        }
      in
      f ctx)

let reset () = Node_clock.set_mock_time 0L

let test_regtest_accepts () =
  with_ctx (fun ctx ->
      (match Rpc.dispatch_rpc ctx "setmocktime" [ `Int 1700000000 ] with
       | Ok `Null -> ()
       | Ok j -> Alcotest.failf "expected null, got %s" (Yojson.Safe.to_string j)
       | Error (c, m) -> Alcotest.failf "setmocktime: (%d) %s" c m);
      Alcotest.(check (float 0.0)) "now" 1700000000.0 (Node_clock.now ());
      ignore (Rpc.dispatch_rpc ctx "setmocktime" [ `Int 0 ]);
      Alcotest.(check bool) "system clock restored" true
        (Node_clock.now () > 1.7e9 && Node_clock.now () <> 1700000000.0);
      reset ())

let test_negative_rejected () =
  with_ctx (fun ctx ->
      match Rpc.dispatch_rpc ctx "setmocktime" [ `Int (-1) ] with
      | Error (-8, _) -> ()
      | _ -> Alcotest.fail "negative mocktime must be -8")

let test_mainnet_refused () =
  with_ctx ~network:Consensus.mainnet (fun ctx ->
      match Rpc.dispatch_rpc ctx "setmocktime" [ `Int 1700000000 ] with
      | Error (-1, m) ->
        Alcotest.(check string) "msg"
          "setmocktime is for regression testing (-regtest mode) only" m;
        Alcotest.(check bool) "clock untouched" true
          (Node_clock.now () <> 1700000000.0)
      | _ -> Alcotest.fail "mainnet must refuse setmocktime")

(* Rolling min-fee decay (Core txmempool.cpp GetMinFee) runs on mocktime:
   12h half-life, quartered to 3h when the pool is < 1/4 full, so advancing
   the mock clock 3h halves the rate. *)
let test_decay_follows_mocktime () =
  with_ctx (fun ctx ->
      let mp = ctx.mempool in
      Node_clock.set_mock_time 1_700_000_000L;
      mp.rolling_min_fee_rate <- 8000.0;
      mp.last_rolling_fee_update <- Node_clock.now ();
      mp.block_since_last_rolling_fee_bump <- true;
      Node_clock.set_mock_time (Int64.add 1_700_000_000L 10_800L);
      let fee = Mempool.get_min_fee mp in
      reset ();
      Alcotest.(check int64) "halved after 3h" 4000L fee)

let () =
  Alcotest.run "setmocktime"
    [ ("setmocktime",
       [ Alcotest.test_case "regtest accepts, 0 restores" `Quick test_regtest_accepts;
         Alcotest.test_case "negative is -8" `Quick test_negative_rejected;
         Alcotest.test_case "mainnet refused" `Quick test_mainnet_refused;
         Alcotest.test_case "decay follows mocktime" `Quick test_decay_follows_mocktime ]) ]
