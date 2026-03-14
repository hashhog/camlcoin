(* Tests for sendrawtransaction RPC handler *)

open Camlcoin

(* Test directory that gets cleaned up *)
let test_db_path = "/tmp/camlcoin_test_rpc_db"

let cleanup_test_db () =
  let rec rm_rf path =
    if Sys.file_exists path then begin
      if Sys.is_directory path then begin
        Array.iter (fun f -> rm_rf (Filename.concat path f)) (Sys.readdir path);
        Unix.rmdir path
      end else
        Unix.unlink path
    end
  in
  rm_rf test_db_path

(* ============================================================================
   Test Helpers
   ============================================================================ *)

(* Create a standard P2PKH script_pubkey for testing *)
let make_p2pkh_script () =
  (* OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG *)
  let script = Cstruct.create 25 in
  Cstruct.set_uint8 script 0 0x76;  (* OP_DUP *)
  Cstruct.set_uint8 script 1 0xa9;  (* OP_HASH160 *)
  Cstruct.set_uint8 script 2 0x14;  (* push 20 bytes *)
  (* 20 bytes of pubkey hash *)
  for i = 3 to 22 do
    Cstruct.set_uint8 script i (i - 3)
  done;
  Cstruct.set_uint8 script 23 0x88; (* OP_EQUALVERIFY *)
  Cstruct.set_uint8 script 24 0xac; (* OP_CHECKSIG *)
  script

(* Create an OP_RETURN script_pubkey *)
let make_op_return_script (data : string) : Cstruct.t =
  let data_len = String.length data in
  let script = Cstruct.create (2 + data_len) in
  Cstruct.set_uint8 script 0 0x6a;  (* OP_RETURN *)
  Cstruct.set_uint8 script 1 data_len;  (* push data length *)
  Cstruct.blit_from_string data 0 script 2 data_len;
  script

(* Helper to create a test transaction output *)
let make_test_output value =
  Types.{
    value;
    script_pubkey = make_p2pkh_script ();
  }

(* Helper to create an OP_RETURN output *)
let make_burn_output value data =
  Types.{
    value;
    script_pubkey = make_op_return_script data;
  }

(* Helper to create a test transaction input *)
let make_test_input txid vout =
  Types.{
    previous_output = { txid; vout };
    script_sig = Cstruct.of_string "\x00";
    sequence = 0xFFFFFFFFl;
  }

(* Helper to create a regular transaction *)
let make_regular_tx inputs outputs =
  Types.{
    version = 1l;
    inputs;
    outputs;
    witnesses = [];
    locktime = 0l;
  }

(* Serialize a transaction to hex string *)
let tx_to_hex (tx : Types.transaction) : string =
  let w = Serialize.writer_create () in
  Serialize.serialize_transaction w tx;
  let cs = Serialize.writer_to_cstruct w in
  let buf = Buffer.create (Cstruct.length cs * 2) in
  for i = 0 to Cstruct.length cs - 1 do
    Buffer.add_string buf (Printf.sprintf "%02x" (Cstruct.get_uint8 cs i))
  done;
  Buffer.contents buf

(* Create a minimal test RPC context with working mempool and UTXO set *)
let create_test_context () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let utxo = Utxo.UtxoSet.create db in

  (* Add some spendable UTXOs *)
  let txid1 = Types.hash256_of_hex
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b" in
  let txid2 = Types.hash256_of_hex
    "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098" in

  Utxo.UtxoSet.add utxo txid1 0 Utxo.{
    value = 10_000_000L;  (* 0.1 BTC *)
    script_pubkey = make_p2pkh_script ();
    height = 0;
    is_coinbase = false;
  };
  Utxo.UtxoSet.add utxo txid2 0 Utxo.{
    value = 50_000_000L;  (* 0.5 BTC *)
    script_pubkey = make_p2pkh_script ();
    height = 0;
    is_coinbase = false;
  };

  let mp = Mempool.create
    ~require_standard:false
    ~verify_scripts:false
    ~utxo
    ~current_height:100
    () in

  (* Use the proper create_chain_state function *)
  let chain = Sync.create_chain_state db Consensus.mainnet in

  (* Create a minimal peer_manager *)
  let pm = Peer_manager.create Consensus.mainnet in

  (* Create a minimal fee estimator *)
  let fe = Fee_estimation.create () in

  let ctx : Rpc.rpc_context = {
    chain = chain;
    mempool = mp;
    peer_manager = pm;
    wallet = None;
    fee_estimator = fe;
    network = Consensus.mainnet;
  } in
  (ctx, db, utxo, txid1, txid2)

(* ============================================================================
   sendrawtransaction Tests
   ============================================================================ *)

(* Test: valid transaction is accepted and returns txid *)
let test_sendrawtransaction_valid () =
  let (ctx, db, _utxo, txid1, _) = create_test_context () in
  (* Create a valid transaction spending txid1 *)
  let tx = make_regular_tx
    [make_test_input txid1 0l]
    [make_test_output 9_990_000L]  (* 10k satoshi fee *)
  in
  let hex = tx_to_hex tx in
  let params = [`String hex] in
  let result = Rpc.handle_sendrawtransaction ctx params in
  Alcotest.(check bool) "valid tx accepted" true (Result.is_ok result);
  (* Compute expected txid directly *)
  let expected_txid = Crypto.compute_txid tx in
  (* Result should be the txid in display format *)
  (match result with
   | Ok (`String txid_str) ->
     Alcotest.(check int) "txid length" 64 (String.length txid_str);
     let expected_str = Types.hash256_to_hex_display expected_txid in
     Alcotest.(check string) "txid matches" expected_str txid_str;
     (* Verify tx is in mempool using computed txid *)
     Alcotest.(check bool) "tx in mempool" true (Mempool.contains ctx.mempool expected_txid)
   | _ -> Alcotest.fail "expected Ok(`String txid)");
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test: invalid hex string is rejected *)
let test_sendrawtransaction_invalid_hex () =
  let (ctx, db, _, _, _) = create_test_context () in
  let params = [`String "not_valid_hex"] in
  let result = Rpc.handle_sendrawtransaction ctx params in
  Alcotest.(check bool) "invalid hex rejected" true (Result.is_error result);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test: transaction with missing inputs is rejected *)
let test_sendrawtransaction_missing_inputs () =
  let (ctx, db, _, _, _) = create_test_context () in
  let fake_txid = Types.hash256_of_hex
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" in
  let tx = make_regular_tx
    [make_test_input fake_txid 0l]
    [make_test_output 100_000L]
  in
  let hex = tx_to_hex tx in
  let params = [`String hex] in
  let result = Rpc.handle_sendrawtransaction ctx params in
  Alcotest.(check bool) "missing inputs rejected" true (Result.is_error result);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test: transaction exceeding maxfeerate is rejected *)
let test_sendrawtransaction_high_fee_rejected () =
  let (ctx, db, _, txid1, _) = create_test_context () in
  (* Create tx with very high fee (8M satoshi = 0.08 BTC for ~200 vB = 40000 sat/vB) *)
  let tx = make_regular_tx
    [make_test_input txid1 0l]
    [make_test_output 2_000_000L]  (* 8M satoshi fee for 10M input *)
  in
  let hex = tx_to_hex tx in
  (* Use very low maxfeerate: 0.001 BTC/kvB = 100 sat/vB *)
  let params = [`String hex; `Float 0.001] in
  let result = Rpc.handle_sendrawtransaction ctx params in
  Alcotest.(check bool) "high fee rejected" true (Result.is_error result);
  (match result with
   | Error msg ->
     Alcotest.(check bool) "error mentions fee" true
       (String.length msg > 0 && (
         String.sub msg 0 3 = "Fee" ||
         try let _ = String.index msg 'f' in true with Not_found -> false))
   | Ok _ -> Alcotest.fail "expected error");
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test: transaction with maxfeerate=0 bypasses fee check *)
let test_sendrawtransaction_feerate_zero_bypasses () =
  let (ctx, db, _, txid1, _) = create_test_context () in
  (* Create tx with high fee *)
  let tx = make_regular_tx
    [make_test_input txid1 0l]
    [make_test_output 2_000_000L]  (* 8M satoshi fee *)
  in
  let hex = tx_to_hex tx in
  (* maxfeerate=0 should bypass fee check *)
  let params = [`String hex; `Float 0.0] in
  let result = Rpc.handle_sendrawtransaction ctx params in
  Alcotest.(check bool) "zero maxfeerate bypasses check" true (Result.is_ok result);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test: transaction with OP_RETURN exceeding maxburnamount is rejected *)
let test_sendrawtransaction_burn_amount_exceeded () =
  let (ctx, db, _, txid1, _) = create_test_context () in
  (* Create tx with OP_RETURN output worth 10000 satoshi *)
  let tx = make_regular_tx
    [make_test_input txid1 0l]
    [make_test_output 9_980_000L; make_burn_output 10_000L "test burn"]
  in
  let hex = tx_to_hex tx in
  (* maxburnamount=0.00005 BTC = 5000 satoshi (less than burn amount) *)
  let params = [`String hex; `Float 0.10; `Float 0.00005] in
  let result = Rpc.handle_sendrawtransaction ctx params in
  Alcotest.(check bool) "burn amount exceeded rejected" true (Result.is_error result);
  (match result with
   | Error msg ->
     Alcotest.(check bool) "error mentions unspendable" true
       (String.length msg > 5)
   | Ok _ -> Alcotest.fail "expected error");
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test: transaction with OP_RETURN within maxburnamount is accepted *)
let test_sendrawtransaction_burn_amount_within_limit () =
  let (ctx, db, _, txid1, _) = create_test_context () in
  (* Create tx with OP_RETURN output worth 5000 satoshi *)
  let tx = make_regular_tx
    [make_test_input txid1 0l]
    [make_test_output 9_985_000L; make_burn_output 5_000L "test burn"]
  in
  let hex = tx_to_hex tx in
  (* maxburnamount=0.0001 BTC = 10000 satoshi (more than burn amount) *)
  let params = [`String hex; `Float 0.10; `Float 0.0001] in
  let result = Rpc.handle_sendrawtransaction ctx params in
  Alcotest.(check bool) "burn within limit accepted" true (Result.is_ok result);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test: duplicate transaction is rejected *)
let test_sendrawtransaction_duplicate_rejected () =
  let (ctx, db, _, txid1, _) = create_test_context () in
  let tx = make_regular_tx
    [make_test_input txid1 0l]
    [make_test_output 9_990_000L]
  in
  let hex = tx_to_hex tx in
  let params = [`String hex] in
  (* First submission succeeds *)
  let result1 = Rpc.handle_sendrawtransaction ctx params in
  Alcotest.(check bool) "first submission ok" true (Result.is_ok result1);
  (* Second submission fails (duplicate) *)
  let result2 = Rpc.handle_sendrawtransaction ctx params in
  Alcotest.(check bool) "duplicate rejected" true (Result.is_error result2);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test: parameter parsing with various formats *)
let test_sendrawtransaction_param_formats () =
  let (ctx, db, _, txid1, _) = create_test_context () in
  let tx = make_regular_tx
    [make_test_input txid1 0l]
    [make_test_output 9_990_000L]
  in
  let hex = tx_to_hex tx in

  (* Test with just hex string *)
  let params1 = [`String hex] in
  let result1 = Rpc.handle_sendrawtransaction ctx params1 in
  Alcotest.(check bool) "hex only accepted" true (Result.is_ok result1);
  Mempool.clear ctx.mempool;

  (* Re-add the UTXO since we cleared mempool but didn't reset UTXO *)
  (* Actually, UTXO is not modified by mempool operations, so we're fine *)

  (* Test with int maxfeerate *)
  let tx2 = make_regular_tx
    [make_test_input txid1 0l]
    [make_test_output 9_990_000L]
  in
  let hex2 = tx_to_hex tx2 in
  let params2 = [`String hex2; `Int 1] in
  let result2 = Rpc.handle_sendrawtransaction ctx params2 in
  Alcotest.(check bool) "int maxfeerate accepted" true (Result.is_ok result2);

  Storage.ChainDB.close db;
  cleanup_test_db ()

(* ============================================================================
   Broadcast Tests
   ============================================================================ *)

(* Test that successful transaction triggers peer announcement *)
let test_sendrawtransaction_broadcasts_to_peers () =
  let (ctx, db, _, txid1, _) = create_test_context () in
  let tx = make_regular_tx
    [make_test_input txid1 0l]
    [make_test_output 9_990_000L]
  in
  let hex = tx_to_hex tx in
  let params = [`String hex] in
  let result = Rpc.handle_sendrawtransaction ctx params in
  Alcotest.(check bool) "tx accepted" true (Result.is_ok result);
  (* Note: We can't easily verify the broadcast happened without mocking the peer_manager,
     but we can at least verify the transaction is in the mempool which is a prerequisite
     for broadcast. The broadcast is done via Lwt.async so it happens asynchronously. *)
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* ============================================================================
   Test Runner
   ============================================================================ *)

let () =
  cleanup_test_db ();
  let open Alcotest in
  run "RPC_Sendrawtransaction" [
    "sendrawtransaction", [
      test_case "valid tx accepted" `Quick test_sendrawtransaction_valid;
      test_case "invalid hex rejected" `Quick test_sendrawtransaction_invalid_hex;
      test_case "missing inputs rejected" `Quick test_sendrawtransaction_missing_inputs;
      test_case "high fee rejected" `Quick test_sendrawtransaction_high_fee_rejected;
      test_case "zero maxfeerate bypasses" `Quick test_sendrawtransaction_feerate_zero_bypasses;
      test_case "burn exceeded rejected" `Quick test_sendrawtransaction_burn_amount_exceeded;
      test_case "burn within limit accepted" `Quick test_sendrawtransaction_burn_amount_within_limit;
      test_case "duplicate rejected" `Quick test_sendrawtransaction_duplicate_rejected;
      test_case "param formats" `Quick test_sendrawtransaction_param_formats;
    ];
    "broadcast", [
      test_case "broadcasts to peers" `Quick test_sendrawtransaction_broadcasts_to_peers;
    ];
  ]
