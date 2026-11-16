(* sendtoaddress for more than the wallet holds.

   Core CreateTransactionInternal (wallet/spend.cpp): when SelectCoins finds
   no selection and returns no specific error, the result is
   util::Error{_("Insufficient funds")}, which sendtoaddress raises as
   RPC_WALLET_INSUFFICIENT_FUNDS (-6) with exactly the message
   "Insufficient funds".  camlcoin answered -6 but with
   "Insufficient funds: have <n> satoshis, need <m>" (core-regtest row
   wallet/error/insufficient:message). *)

open Camlcoin

let dest_addr = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"

let dummy_tip (height : int) : Sync.header_entry =
  { header = { version = 1l; prev_block = Types.zero_hash;
               merkle_root = Types.zero_hash; timestamp = 0l;
               bits = 0l; nonce = 0l };
    hash = Types.zero_hash;
    height;
    total_work = Cstruct.create 32 }

(* The core-regtest harness launches camlcoin with -fallbackfee, as Core's
   own regtest wallet tests do; without it the spend stops at fee estimation
   before coin selection runs. *)
let () = Fee_estimation.fallback_fee_sat_per_vb := 2.0

let with_ctx f =
  let height = 200 in
  Test_tmp.with_chaindb (fun db ->
      let utxo = Utxo.UtxoSet.create db in
      let mp = Mempool.create ~network:Consensus.regtest
          ~require_standard:false ~verify_scripts:false ~utxo
          ~current_height:height () in
      let chain = Sync.create_chain_state db Consensus.regtest in
      chain.tip <- Some (dummy_tip height);
      let wallet = Wallet.create ~network:`Regtest ~db_path:"" in
      let ctx : Rpc.rpc_context = {
        chain; mempool = mp;
        peer_manager = Peer_manager.create Consensus.regtest;
        wallet = Some wallet; wallet_manager = None;
        fee_estimator = Fee_estimation.create ();
        network = Consensus.regtest; filter_index = None; utxo = None;
        data_dir = None; snapshot_activation = None;
      } in
      f ctx wallet)

let p2wpkh_script pkh =
  let s = Cstruct.create 22 in
  Cstruct.set_uint8 s 0 0x00;
  Cstruct.set_uint8 s 1 0x14;
  Cstruct.blit pkh 0 s 2 20;
  s

(* Credit [value] sat to a fresh wallet key in a confirmed, non-coinbase tx. *)
let fund w value =
  let kp = Wallet.generate_key w in
  let prev = Cstruct.create 32 in
  Cstruct.set_uint8 prev 0 0x42;
  let tx : Types.transaction = {
    version = 2l;
    inputs = [{ Types.previous_output =
                  { txid = prev; vout = 0l };
                script_sig = Cstruct.empty; sequence = 0xFFFFFFFEl }];
    outputs = [{ Types.value;
                 script_pubkey = p2wpkh_script (Crypto.hash160 kp.Wallet.public_key) }];
    witnesses = []; locktime = 0l } in
  let block : Types.block =
    { header = { version = 1l; prev_block = Types.zero_hash;
                 merkle_root = Types.zero_hash; timestamp = 0l; bits = 0l;
                 nonce = 0l };
      transactions = [tx] } in
  Wallet.scan_block w block 150

let expect_insufficient label result =
  match result with
  | Error (code, msg) ->
    Alcotest.(check int) (label ^ ": code") (-6) code;
    Alcotest.(check string) (label ^ ": message") "Insufficient funds" msg
  | Ok j ->
    Alcotest.failf "%s: expected -6 but got Ok %s" label
      (Yojson.Safe.to_string j)

(* The harness case: a funded wallet asked for far more than it holds. *)
let test_funded_short () =
  with_ctx (fun ctx w ->
      fund w 1_000_000L;
      expect_insufficient "funded wallet, 1000 BTC"
        (Rpc.dispatch_rpc ctx "sendtoaddress" [`String dest_addr; `Int 1000]))

let test_empty_wallet () =
  with_ctx (fun ctx _w ->
      expect_insufficient "empty wallet, 1 BTC"
        (Rpc.dispatch_rpc ctx "sendtoaddress" [`String dest_addr; `Int 1]))

(* Control: the same funded wallet selects coins for an affordable amount,
   so the error above is the coin-selection shortfall and not a wallet that
   holds nothing spendable. *)
let test_affordable_selection_control () =
  with_ctx (fun _ctx w ->
      fund w 1_000_000L;
      match Wallet.select_coins w 100_000L 2.0 ~tip_height:200 () with
      | Ok sel ->
        Alcotest.(check int64) "selected input total" 1_000_000L
          sel.Wallet.total_input
      | Error e -> Alcotest.failf "affordable selection failed: %s" e)

let () =
  Alcotest.run "sendtoaddress_insufficient_message" [
    "insufficient-funds", [
      Alcotest.test_case "funded wallet short: message is Insufficient funds"
        `Quick test_funded_short;
      Alcotest.test_case "empty wallet: message is Insufficient funds"
        `Quick test_empty_wallet;
      Alcotest.test_case "control: affordable selection succeeds"
        `Quick test_affordable_selection_control;
    ];
  ]
