(* getbalances must split mature from immature coinbases like Core
   (wallet/rpc/coins.cpp getbalances; wallet/receive.cpp GetBalance:
   m_mine_immature = IsTxImmatureCoinBase).  camlcoin hard-coded
   mine.immature to 0, so a fresh regtest wallet with 101 mined blocks showed
   immature 0 where Core shows 5000 (wallet/receive/getbalances:mine.immature). *)

open Camlcoin

let dummy_tip (height : int) : Sync.header_entry =
  { header = { version = 1l; prev_block = Types.zero_hash;
               merkle_root = Types.zero_hash; timestamp = 0l;
               bits = 0l; nonce = 0l };
    hash = Types.zero_hash; height; total_work = Cstruct.create 32 }

let with_ctx ~height f =
  Test_tmp.with_dir ~label:"wallets" ~mkdir:true (fun dir ->
      Test_tmp.with_chaindb (fun db ->
          let utxo = Utxo.UtxoSet.create db in
          let mp = Mempool.create ~network:Consensus.regtest
              ~require_standard:false ~verify_scripts:false ~utxo
              ~current_height:height () in
          let chain = Sync.create_chain_state db Consensus.regtest in
          chain.tip <- Some (dummy_tip height);
          let wm = Wallet.create_wallet_manager ~wallets_dir:dir
              ~network:`Regtest in
          let wallet =
            match Wallet.create_wallet wm "g" () with
            | Error e -> Alcotest.fail ("create_wallet: " ^ e)
            | Ok w -> w in
          Hashtbl.replace wm.Wallet.wallets "" wallet;
          let ctx : Rpc.rpc_context = {
            chain; mempool = mp;
            peer_manager = Peer_manager.create Consensus.regtest;
            wallet = Some wallet; wallet_manager = Some wm;
            fee_estimator = Fee_estimation.create ();
            network = Consensus.regtest; filter_index = None; utxo = None;
            data_dir = None; snapshot_activation = None;
          } in
          f ctx wallet))

let coin n ~height ~is_coinbase value : Wallet.wallet_utxo =
  let txid = Cstruct.of_string (String.make 32 (Char.chr n)) in
  { Wallet.outpoint = { Types.txid; vout = 0l };
    utxo = { Utxo.value; script_pubkey = Cstruct.create 22; height;
             is_coinbase };
    key_index = 0; confirmed = true; watch_only = false }

let btc = function
  | `Float f -> f
  | `Int n -> float_of_int n
  | j -> Alcotest.failf "not a number: %s" (Yojson.Safe.to_string j)

(* Tip 101, coinbases at heights 1 (101 confs: mature) and 2..101 (immature).
   Core regtest after 101 blocks: trusted 50, immature 5000 (100 x 50). *)
let test_immature_split () =
  with_ctx ~height:101 (fun ctx w ->
      let cb h = coin h ~height:h ~is_coinbase:true 5_000_000_000L in
      w.Wallet.utxos <-
        List.init 100 (fun i -> cb (i + 2)) @ [cb 1];
      match Rpc.dispatch_rpc ctx "getbalances" [] with
      | Error (c, m) -> Alcotest.failf "getbalances: (%d) %s" c m
      | Ok (`Assoc fs) ->
        (match List.assoc "mine" fs with
         | `Assoc mine ->
           Alcotest.(check (float 1e-9)) "trusted" 50.0
             (btc (List.assoc "trusted" mine));
           Alcotest.(check (float 1e-9)) "immature" 5000.0
             (btc (List.assoc "immature" mine));
           Alcotest.(check (float 1e-9)) "untrusted_pending" 0.0
             (btc (List.assoc "untrusted_pending" mine))
         | _ -> Alcotest.fail "mine is not an object")
      | Ok _ -> Alcotest.fail "getbalances: not an object")

(* Boundary: a coinbase with exactly 100 confirmations is still immature
   (needs 101), 101 is mature. tip=100, coinbase at height 1 -> 100 confs. *)
let test_boundary () =
  with_ctx ~height:100 (fun ctx w ->
      w.Wallet.utxos <- [coin 1 ~height:1 ~is_coinbase:true 5_000_000_000L];
      match Rpc.dispatch_rpc ctx "getbalances" [] with
      | Ok (`Assoc fs) ->
        (match List.assoc "mine" fs with
         | `Assoc mine ->
           Alcotest.(check (float 1e-9)) "trusted" 0.0
             (btc (List.assoc "trusted" mine));
           Alcotest.(check (float 1e-9)) "immature" 50.0
             (btc (List.assoc "immature" mine))
         | _ -> Alcotest.fail "mine")
      | _ -> Alcotest.fail "getbalances")

let () =
  Alcotest.run "wallet_cause_g_getbalances"
    [ "getbalances",
      [ Alcotest.test_case "immature split" `Quick test_immature_split;
        Alcotest.test_case "maturity boundary" `Quick test_boundary ] ]
