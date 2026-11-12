(* gettransaction.details for a send to one of the wallet's own addresses.

   Core CachedTxGetAmounts (wallet/receive.cpp), used by ListTransactions
   (wallet/rpc/transactions.cpp): when the wallet paid for the tx, change is
   skipped, every other output is a "send" entry and every owned non-change
   output is ALSO a "receive" entry.  So a 1 BTC payment to a second own
   address lists exactly [send -1; receive +1], and the net amount is 0.
   camlcoin listed only the send. *)

open Camlcoin

let p2wpkh_script pkh =
  let s = Cstruct.create 22 in
  Cstruct.set_uint8 s 0 0x00;
  Cstruct.set_uint8 s 1 0x14;
  Cstruct.blit pkh 0 s 2 20;
  s

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
      f ctx wallet)

let block_of txs : Types.block =
  { header = { version = 1l; prev_block = Types.zero_hash;
               merkle_root = Types.zero_hash; timestamp = 0l; bits = 0l;
               nonce = 0l };
    transactions = txs }

(* Fund the wallet, pay [dest] 100_000 sat, confirm the spend, and return the
   gettransaction result of the spend. *)
let spend_and_gettransaction ctx w ~to_self =
  let kp = Wallet.generate_key w in
  let funding : Types.transaction = {
    version = 1l;
    inputs = [{ Types.previous_output =
                  { txid = Types.zero_hash; vout = 0xFFFFFFFFl };
                script_sig = Cstruct.create 2; sequence = 0xFFFFFFFFl }];
    outputs = [{ Types.value = 1_000_000L;
                 script_pubkey = p2wpkh_script (Crypto.hash160 kp.Wallet.public_key) }];
    witnesses = []; locktime = 0l } in
  Wallet.scan_block w (block_of [funding]) 100;
  let dest =
    if to_self then Wallet.get_new_address w
    else
      let other = Wallet.create ~network:`Regtest ~db_path:"" in
      Wallet.get_new_address other in
  match Wallet.create_transaction w ~dest_address:dest ~amount:100_000L
          ~fee_rate:1.0 () with
  | Error e -> Alcotest.failf "create_transaction: %s" e
  | Ok tx ->
    Wallet.scan_block w (block_of [tx]) 101;
    let txid = Types.hash256_to_hex_display (Crypto.compute_txid tx) in
    (match Rpc.handle_gettransaction ctx [`String txid] with
     | Ok j -> j
     | Error e -> Alcotest.failf "gettransaction: %s" e)

let details j =
  match j with
  | `Assoc kv ->
    (match List.assoc_opt "details" kv with
     | Some (`List l) -> l
     | _ -> Alcotest.fail "no details array")
  | _ -> Alcotest.fail "not an object"

let cat d =
  match d with
  | `Assoc kv ->
    (match List.assoc "category" kv with `String s -> s | _ -> "?")
  | _ -> "?"

let test_selfsend_lists_send_and_receive () =
  with_ctx (fun ctx w ->
      let j = spend_and_gettransaction ctx w ~to_self:true in
      let cats = List.map cat (details j) in
      Alcotest.(check (list string)) "details categories (change omitted)"
        ["send"; "receive"] cats;
      (match j with
       | `Assoc kv ->
         (match List.assoc_opt "amount" kv with
          | Some (`Float a) ->
            Alcotest.(check (float 1e-12)) "net amount of a self-send" 0.0 a
          | _ -> Alcotest.fail "no amount")
       | _ -> ()))

let test_foreign_send_unchanged () =
  with_ctx (fun ctx w ->
      let j = spend_and_gettransaction ctx w ~to_self:false in
      Alcotest.(check (list string)) "control: one send, change not listed"
        ["send"] (List.map cat (details j)))

let () =
  Alcotest.run "selfsend_details"
    [ "gettransaction.details",
      [ Alcotest.test_case "send-to-self lists send + receive" `Quick
          test_selfsend_lists_send_and_receive;
        Alcotest.test_case "control: foreign send unchanged" `Quick
          test_foreign_send_unchanged ] ]
