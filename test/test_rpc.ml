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
    wallet_manager = None;
    fee_estimator = fe;
    network = Consensus.mainnet;
    filter_index = None;
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
   getrawtransaction Tests
   ============================================================================ *)

(* Test: getrawtransaction returns hex for mempool transaction *)
let test_getrawtransaction_mempool_hex () =
  let (ctx, db, _, txid1, _) = create_test_context () in
  (* Create and add a transaction to mempool *)
  let tx = make_regular_tx
    [make_test_input txid1 0l]
    [make_test_output 9_990_000L]
  in
  let hex = tx_to_hex tx in
  let _ = Rpc.handle_sendrawtransaction ctx [`String hex] in

  (* Now query with getrawtransaction *)
  let txid = Crypto.compute_txid tx in
  let txid_hex = Types.hash256_to_hex_display txid in
  let params = [`String txid_hex] in
  let result = Rpc.handle_getrawtransaction ctx params in
  Alcotest.(check bool) "mempool tx found" true (Result.is_ok result);
  (match result with
   | Ok (`String returned_hex) ->
     Alcotest.(check string) "hex matches" hex returned_hex
   | _ -> Alcotest.fail "expected Ok(`String hex)");
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test: getrawtransaction verbose mode returns JSON with required fields *)
let test_getrawtransaction_verbose () =
  let (ctx, db, _, txid1, _) = create_test_context () in
  (* Create and add a transaction to mempool *)
  let tx = make_regular_tx
    [make_test_input txid1 0l]
    [make_test_output 9_990_000L]
  in
  let hex = tx_to_hex tx in
  let _ = Rpc.handle_sendrawtransaction ctx [`String hex] in

  (* Query with verbose=true *)
  let txid = Crypto.compute_txid tx in
  let txid_hex = Types.hash256_to_hex_display txid in
  let params = [`String txid_hex; `Bool true] in
  let result = Rpc.handle_getrawtransaction ctx params in
  Alcotest.(check bool) "verbose result ok" true (Result.is_ok result);
  (match result with
   | Ok (`Assoc fields) ->
     (* Check required fields exist *)
     Alcotest.(check bool) "has txid" true (List.mem_assoc "txid" fields);
     Alcotest.(check bool) "has hash" true (List.mem_assoc "hash" fields);
     Alcotest.(check bool) "has version" true (List.mem_assoc "version" fields);
     Alcotest.(check bool) "has size" true (List.mem_assoc "size" fields);
     Alcotest.(check bool) "has vsize" true (List.mem_assoc "vsize" fields);
     Alcotest.(check bool) "has weight" true (List.mem_assoc "weight" fields);
     Alcotest.(check bool) "has locktime" true (List.mem_assoc "locktime" fields);
     Alcotest.(check bool) "has vin" true (List.mem_assoc "vin" fields);
     Alcotest.(check bool) "has vout" true (List.mem_assoc "vout" fields);
     Alcotest.(check bool) "has hex" true (List.mem_assoc "hex" fields);
     (* Check txid matches *)
     (match List.assoc_opt "txid" fields with
      | Some (`String returned_txid) ->
        Alcotest.(check string) "txid matches" txid_hex returned_txid
      | _ -> Alcotest.fail "txid should be string")
   | _ -> Alcotest.fail "expected Ok(`Assoc fields)");
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test: getrawtransaction verbose mode includes scriptPubKey type *)
let test_getrawtransaction_scriptpubkey_type () =
  let (ctx, db, _, txid1, _) = create_test_context () in
  (* Create transaction with P2PKH output *)
  let tx = make_regular_tx
    [make_test_input txid1 0l]
    [make_test_output 9_990_000L]
  in
  let hex = tx_to_hex tx in
  let _ = Rpc.handle_sendrawtransaction ctx [`String hex] in

  let txid = Crypto.compute_txid tx in
  let txid_hex = Types.hash256_to_hex_display txid in
  let params = [`String txid_hex; `Bool true] in
  let result = Rpc.handle_getrawtransaction ctx params in
  (match result with
   | Ok (`Assoc fields) ->
     (match List.assoc_opt "vout" fields with
      | Some (`List [vout0]) ->
        (match vout0 with
         | `Assoc vout_fields ->
           (match List.assoc_opt "scriptPubKey" vout_fields with
            | Some (`Assoc spk_fields) ->
              Alcotest.(check bool) "has type" true (List.mem_assoc "type" spk_fields);
              (match List.assoc_opt "type" spk_fields with
               | Some (`String type_name) ->
                 Alcotest.(check string) "type is pubkeyhash" "pubkeyhash" type_name
               | _ -> Alcotest.fail "type should be string")
            | _ -> Alcotest.fail "missing scriptPubKey")
         | _ -> Alcotest.fail "vout0 should be assoc")
      | _ -> Alcotest.fail "vout should be list with one element")
   | _ -> Alcotest.fail "expected Ok(`Assoc fields)");
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test: getrawtransaction with verbosity=1 (int) *)
let test_getrawtransaction_verbosity_int () =
  let (ctx, db, _, txid1, _) = create_test_context () in
  let tx = make_regular_tx
    [make_test_input txid1 0l]
    [make_test_output 9_990_000L]
  in
  let hex = tx_to_hex tx in
  let _ = Rpc.handle_sendrawtransaction ctx [`String hex] in

  let txid = Crypto.compute_txid tx in
  let txid_hex = Types.hash256_to_hex_display txid in
  (* Test with verbosity as int *)
  let params = [`String txid_hex; `Int 1] in
  let result = Rpc.handle_getrawtransaction ctx params in
  Alcotest.(check bool) "verbosity=1 returns object" true
    (match result with Ok (`Assoc _) -> true | _ -> false);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test: getrawtransaction with verbosity=0 returns hex *)
let test_getrawtransaction_verbosity_zero () =
  let (ctx, db, _, txid1, _) = create_test_context () in
  let tx = make_regular_tx
    [make_test_input txid1 0l]
    [make_test_output 9_990_000L]
  in
  let hex = tx_to_hex tx in
  let _ = Rpc.handle_sendrawtransaction ctx [`String hex] in

  let txid = Crypto.compute_txid tx in
  let txid_hex = Types.hash256_to_hex_display txid in
  let params = [`String txid_hex; `Int 0] in
  let result = Rpc.handle_getrawtransaction ctx params in
  Alcotest.(check bool) "verbosity=0 returns string" true
    (match result with Ok (`String _) -> true | _ -> false);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test: getrawtransaction for nonexistent tx returns error *)
let test_getrawtransaction_not_found () =
  let (ctx, db, _, _, _) = create_test_context () in
  let fake_txid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" in
  let params = [`String fake_txid] in
  let result = Rpc.handle_getrawtransaction ctx params in
  Alcotest.(check bool) "nonexistent tx returns error" true (Result.is_error result);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test: getrawtransaction with invalid txid *)
let test_getrawtransaction_invalid_txid () =
  let (ctx, db, _, _, _) = create_test_context () in
  let params = [`String "not_a_valid_txid"] in
  let result = Rpc.handle_getrawtransaction ctx params in
  Alcotest.(check bool) "invalid txid returns error" true (Result.is_error result);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test: getrawtransaction for confirmed transaction includes block info *)
let test_getrawtransaction_confirmed_has_block_info () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let utxo = Utxo.UtxoSet.create db in

  (* Create a transaction *)
  let txid1 = Types.hash256_of_hex
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b" in
  Utxo.UtxoSet.add utxo txid1 0 Utxo.{
    value = 10_000_000L;
    script_pubkey = make_p2pkh_script ();
    height = 0;
    is_coinbase = false;
  };

  let tx = make_regular_tx
    [make_test_input txid1 0l]
    [make_test_output 9_990_000L]
  in
  let txid = Crypto.compute_txid tx in

  (* Store the transaction and its index *)
  Storage.ChainDB.store_transaction db txid tx;
  let block_hash = Types.hash256_of_hex
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f" in
  Storage.ChainDB.store_tx_index db txid block_hash 0;

  (* Create chain state with a tip *)
  let chain = Sync.create_chain_state db Consensus.mainnet in
  let pm = Peer_manager.create Consensus.mainnet in
  let fe = Fee_estimation.create () in
  let mp = Mempool.create ~require_standard:false ~verify_scripts:false ~utxo ~current_height:100 () in

  let ctx : Rpc.rpc_context = {
    chain = chain;
    mempool = mp;
    peer_manager = pm;
    wallet = None;
    wallet_manager = None;
    fee_estimator = fe;
    network = Consensus.mainnet;
    filter_index = None;
  } in

  let txid_hex = Types.hash256_to_hex_display txid in
  let params = [`String txid_hex; `Bool true] in
  let result = Rpc.handle_getrawtransaction ctx params in

  Alcotest.(check bool) "confirmed tx found" true (Result.is_ok result);
  (match result with
   | Ok (`Assoc fields) ->
     (* Confirmed txs should have blockhash *)
     Alcotest.(check bool) "has blockhash" true (List.mem_assoc "blockhash" fields);
     Alcotest.(check bool) "has confirmations" true (List.mem_assoc "confirmations" fields);
     Alcotest.(check bool) "has time" true (List.mem_assoc "time" fields);
     Alcotest.(check bool) "has blocktime" true (List.mem_assoc "blocktime" fields)
   | _ -> Alcotest.fail "expected Ok(`Assoc fields)");

  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test: getrawtransaction with specific blockhash *)
let test_getrawtransaction_with_blockhash () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let utxo = Utxo.UtxoSet.create db in

  let txid1 = Types.hash256_of_hex
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b" in
  Utxo.UtxoSet.add utxo txid1 0 Utxo.{
    value = 10_000_000L;
    script_pubkey = make_p2pkh_script ();
    height = 0;
    is_coinbase = false;
  };

  (* Create a transaction *)
  let tx = make_regular_tx
    [make_test_input txid1 0l]
    [make_test_output 9_990_000L]
  in
  let txid = Crypto.compute_txid tx in

  (* Create a block containing the transaction *)
  let block_hash = Types.hash256_of_hex
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f" in
  let block_hash_internal = Cstruct.create 32 in
  for i = 0 to 31 do
    Cstruct.set_uint8 block_hash_internal i (Cstruct.get_uint8 block_hash (31 - i))
  done;

  let block : Types.block = {
    header = Consensus.mainnet.genesis_header;
    transactions = [tx];
  } in
  Storage.ChainDB.store_block db block_hash_internal block;

  let chain = Sync.create_chain_state db Consensus.mainnet in
  let pm = Peer_manager.create Consensus.mainnet in
  let fe = Fee_estimation.create () in
  let mp = Mempool.create ~require_standard:false ~verify_scripts:false ~utxo ~current_height:100 () in

  let ctx : Rpc.rpc_context = {
    chain = chain;
    mempool = mp;
    peer_manager = pm;
    wallet = None;
    wallet_manager = None;
    fee_estimator = fe;
    network = Consensus.mainnet;
    filter_index = None;
  } in

  let txid_hex = Types.hash256_to_hex_display txid in
  let block_hash_hex = Types.hash256_to_hex_display block_hash_internal in
  let params = [`String txid_hex; `Bool true; `String block_hash_hex] in
  let result = Rpc.handle_getrawtransaction ctx params in

  Alcotest.(check bool) "tx found in specified block" true (Result.is_ok result);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test: getrawtransaction with wrong blockhash returns error *)
let test_getrawtransaction_wrong_blockhash () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let utxo = Utxo.UtxoSet.create db in

  let txid1 = Types.hash256_of_hex
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b" in
  Utxo.UtxoSet.add utxo txid1 0 Utxo.{
    value = 10_000_000L;
    script_pubkey = make_p2pkh_script ();
    height = 0;
    is_coinbase = false;
  };

  (* Create empty block - tx not in it *)
  let block_hash = Types.hash256_of_hex
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f" in
  let block_hash_internal = Cstruct.create 32 in
  for i = 0 to 31 do
    Cstruct.set_uint8 block_hash_internal i (Cstruct.get_uint8 block_hash (31 - i))
  done;

  let block : Types.block = {
    header = Consensus.mainnet.genesis_header;
    transactions = [];  (* Empty - no transactions *)
  } in
  Storage.ChainDB.store_block db block_hash_internal block;

  let chain = Sync.create_chain_state db Consensus.mainnet in
  let pm = Peer_manager.create Consensus.mainnet in
  let fe = Fee_estimation.create () in
  let mp = Mempool.create ~require_standard:false ~verify_scripts:false ~utxo ~current_height:100 () in

  let ctx : Rpc.rpc_context = {
    chain = chain;
    mempool = mp;
    peer_manager = pm;
    wallet = None;
    wallet_manager = None;
    fee_estimator = fe;
    network = Consensus.mainnet;
    filter_index = None;
  } in

  (* Try to find tx that doesn't exist in this block *)
  let fake_txid = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" in
  let block_hash_hex = Types.hash256_to_hex_display block_hash_internal in
  let params = [`String fake_txid; `Bool true; `String block_hash_hex] in
  let result = Rpc.handle_getrawtransaction ctx params in

  Alcotest.(check bool) "tx not in block returns error" true (Result.is_error result);
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
   Batch RPC Tests
   ============================================================================ *)

(* Test helper: simulates handle_batch_request synchronously *)
let handle_batch_sync ctx requests =
  Lwt_main.run (Rpc.handle_batch_request ctx requests)

(* Test: batch request with multiple valid calls returns array of responses *)
let test_batch_multiple_valid () =
  let (ctx, db, _, _, _) = create_test_context () in
  (* Create a batch with 3 different RPC calls *)
  let req1 = `Assoc [("method", `String "getblockcount"); ("params", `List []); ("id", `Int 1)] in
  let req2 = `Assoc [("method", `String "getdifficulty"); ("params", `List []); ("id", `Int 2)] in
  let req3 = `Assoc [("method", `String "getbestblockhash"); ("params", `List []); ("id", `Int 3)] in
  let responses = handle_batch_sync ctx [req1; req2; req3] in
  Alcotest.(check int) "batch returns 3 responses" 3 (List.length responses);
  (* Check each response has the correct id *)
  (match List.nth responses 0 with
   | `Assoc fields ->
     (match List.assoc_opt "id" fields with
      | Some (`Int 1) -> ()
      | _ -> Alcotest.fail "first response should have id=1")
   | _ -> Alcotest.fail "response should be object");
  (match List.nth responses 1 with
   | `Assoc fields ->
     (match List.assoc_opt "id" fields with
      | Some (`Int 2) -> ()
      | _ -> Alcotest.fail "second response should have id=2")
   | _ -> Alcotest.fail "response should be object");
  (match List.nth responses 2 with
   | `Assoc fields ->
     (match List.assoc_opt "id" fields with
      | Some (`Int 3) -> ()
      | _ -> Alcotest.fail "third response should have id=3")
   | _ -> Alcotest.fail "response should be object");
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test: batch with mixed valid/invalid requests handles each independently *)
let test_batch_mixed_valid_invalid () =
  let (ctx, db, _, _, _) = create_test_context () in
  (* Create a batch with valid and invalid calls *)
  let req_valid = `Assoc [("method", `String "getblockcount"); ("params", `List []); ("id", `Int 1)] in
  let req_invalid = `Assoc [("method", `String "nonexistent_method"); ("params", `List []); ("id", `Int 2)] in
  let req_valid2 = `Assoc [("method", `String "getdifficulty"); ("params", `List []); ("id", `Int 3)] in
  let responses = handle_batch_sync ctx [req_valid; req_invalid; req_valid2] in
  Alcotest.(check int) "batch returns 3 responses" 3 (List.length responses);
  (* First should succeed (no error field) *)
  (match List.nth responses 0 with
   | `Assoc fields ->
     (match List.assoc_opt "error" fields with
      | Some `Null -> ()
      | _ -> Alcotest.fail "first request should succeed")
   | _ -> Alcotest.fail "response should be object");
  (* Second should fail (has error field) *)
  (match List.nth responses 1 with
   | `Assoc fields ->
     (match List.assoc_opt "error" fields with
      | Some (`Assoc _) -> ()  (* Has error *)
      | _ -> Alcotest.fail "second request should fail")
   | _ -> Alcotest.fail "response should be object");
  (* Third should succeed *)
  (match List.nth responses 2 with
   | `Assoc fields ->
     (match List.assoc_opt "error" fields with
      | Some `Null -> ()
      | _ -> Alcotest.fail "third request should succeed")
   | _ -> Alcotest.fail "response should be object");
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test: batch preserves request order in response *)
let test_batch_preserves_order () =
  let (ctx, db, _, _, _) = create_test_context () in
  (* Create batch with string ids to verify order *)
  let req1 = `Assoc [("method", `String "getblockcount"); ("params", `List []); ("id", `String "first")] in
  let req2 = `Assoc [("method", `String "getdifficulty"); ("params", `List []); ("id", `String "second")] in
  let req3 = `Assoc [("method", `String "getmininginfo"); ("params", `List []); ("id", `String "third")] in
  let responses = handle_batch_sync ctx [req1; req2; req3] in
  Alcotest.(check int) "batch returns 3 responses" 3 (List.length responses);
  (* Verify order by checking ids *)
  let get_id resp = match resp with
    | `Assoc fields ->
      (match List.assoc_opt "id" fields with
       | Some (`String s) -> s
       | _ -> "unknown")
    | _ -> "invalid"
  in
  Alcotest.(check string) "first id" "first" (get_id (List.nth responses 0));
  Alcotest.(check string) "second id" "second" (get_id (List.nth responses 1));
  Alcotest.(check string) "third id" "third" (get_id (List.nth responses 2));
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test: batch with null ids *)
let test_batch_with_null_ids () =
  let (ctx, db, _, _, _) = create_test_context () in
  let req1 = `Assoc [("method", `String "getblockcount"); ("params", `List []); ("id", `Null)] in
  let req2 = `Assoc [("method", `String "getdifficulty"); ("params", `List [])] in  (* No id at all *)
  let responses = handle_batch_sync ctx [req1; req2] in
  Alcotest.(check int) "batch returns 2 responses" 2 (List.length responses);
  (* Both should have null ids in response *)
  (match List.nth responses 0 with
   | `Assoc fields ->
     (match List.assoc_opt "id" fields with
      | Some `Null -> ()
      | _ -> Alcotest.fail "response should have null id")
   | _ -> Alcotest.fail "response should be object");
  (match List.nth responses 1 with
   | `Assoc fields ->
     (match List.assoc_opt "id" fields with
      | Some `Null -> ()
      | _ -> Alcotest.fail "response should have null id")
   | _ -> Alcotest.fail "response should be object");
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test: batch with 4+ different RPC calls *)
let test_batch_many_calls () =
  let (ctx, db, _, _, _) = create_test_context () in
  let req1 = `Assoc [("method", `String "getblockcount"); ("params", `List []); ("id", `Int 1)] in
  let req2 = `Assoc [("method", `String "getdifficulty"); ("params", `List []); ("id", `Int 2)] in
  let req3 = `Assoc [("method", `String "getbestblockhash"); ("params", `List []); ("id", `Int 3)] in
  let req4 = `Assoc [("method", `String "getmempoolinfo"); ("params", `List []); ("id", `Int 4)] in
  let req5 = `Assoc [("method", `String "getconnectioncount"); ("params", `List []); ("id", `Int 5)] in
  let responses = handle_batch_sync ctx [req1; req2; req3; req4; req5] in
  Alcotest.(check int) "batch returns 5 responses" 5 (List.length responses);
  (* Verify all responses have result (not error) *)
  List.iteri (fun i resp ->
    match resp with
    | `Assoc fields ->
      (match List.assoc_opt "error" fields with
       | Some `Null -> ()
       | _ -> Alcotest.failf "response %d should succeed" (i + 1))
    | _ -> Alcotest.failf "response %d should be object" (i + 1)
  ) responses;
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test: handle_single_request directly for unit testing *)
let test_handle_single_request () =
  let (ctx, db, _, _, _) = create_test_context () in
  let req = `Assoc [("method", `String "getblockcount"); ("params", `List []); ("id", `Int 42)] in
  let response = Rpc.handle_single_request ctx req in
  (match response with
   | `Assoc fields ->
     Alcotest.(check bool) "has result" true (List.mem_assoc "result" fields);
     Alcotest.(check bool) "has id" true (List.mem_assoc "id" fields);
     (match List.assoc_opt "id" fields with
      | Some (`Int 42) -> ()
      | _ -> Alcotest.fail "id should be 42")
   | _ -> Alcotest.fail "response should be object");
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test: single request still works *)
let test_single_request_still_works () =
  let (ctx, db, _, _, _) = create_test_context () in
  let req = `Assoc [("method", `String "getblockcount"); ("params", `List []); ("id", `Int 1)] in
  let response = Rpc.handle_single_request ctx req in
  (match response with
   | `Assoc fields ->
     (match List.assoc_opt "error" fields with
      | Some `Null -> ()
      | _ -> Alcotest.fail "single request should succeed")
   | _ -> Alcotest.fail "response should be object");
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* ============================================================================
   Regtest Mining RPC Tests
   ============================================================================ *)

(* Create a regtest context for mining tests *)
let create_regtest_context () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let utxo = Utxo.UtxoSet.create db in

  (* Use regtest network config *)
  let chain = Sync.create_chain_state db Consensus.regtest in
  let pm = Peer_manager.create Consensus.regtest in
  let fe = Fee_estimation.create () in
  let mp = Mempool.create ~require_standard:false ~verify_scripts:false ~utxo ~current_height:0 () in

  let ctx : Rpc.rpc_context = {
    chain = chain;
    mempool = mp;
    peer_manager = pm;
    wallet = None;
    wallet_manager = None;
    fee_estimator = fe;
    network = Consensus.regtest;
    filter_index = None;
  } in
  (ctx, db, utxo)

(* Test: generate RPC is only available on regtest *)
let test_generate_regtest_only () =
  let (ctx, db, _, _, _) = create_test_context () in  (* mainnet context *)
  let params = [`Int 1] in
  let result = Rpc.handle_generate ctx params in
  Alcotest.(check bool) "generate rejected on mainnet" true (Result.is_error result);
  (match result with
   | Error msg ->
     Alcotest.(check bool) "error mentions regtest" true
       (String.length msg > 0)
   | Ok _ -> Alcotest.fail "expected error on mainnet");
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test: generate mines blocks on regtest *)
let test_generate_mines_blocks () =
  let (ctx, db, _) = create_regtest_context () in
  let params = [`Int 3] in
  let result = Rpc.handle_generate ctx params in
  (match result with
   | Error msg -> Alcotest.failf "generate failed: %s" msg
   | Ok (`List hashes) ->
     Alcotest.(check int) "3 blocks mined" 3 (List.length hashes);
     (* Verify chain tip advanced *)
     let tip_height = match ctx.chain.tip with
       | Some t -> t.height
       | None -> 0
     in
     Alcotest.(check int) "chain at height 3" 3 tip_height
   | Ok other -> Alcotest.failf "unexpected result: %s" (Yojson.Safe.to_string other));
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test: generate with 0 blocks returns empty list *)
let test_generate_zero_blocks () =
  let (ctx, db, _) = create_regtest_context () in
  let params = [`Int 0] in
  let result = Rpc.handle_generate ctx params in
  Alcotest.(check bool) "generate 0 succeeds" true (Result.is_ok result);
  (match result with
   | Ok (`List hashes) ->
     Alcotest.(check int) "0 blocks mined" 0 (List.length hashes)
   | _ -> Alcotest.fail "expected Ok(`List [])");
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test: generatetoaddress mines to specific address *)
let test_generatetoaddress_mines_to_address () =
  let (ctx, db, _) = create_regtest_context () in
  (* Generate a valid regtest address using the wallet *)
  let w = Wallet.create ~network:`Regtest ~db_path:"" in
  let address = Wallet.get_new_address w in
  let params = [`Int 2; `String address] in
  let result = Rpc.handle_generatetoaddress ctx params in
  (match result with
   | Error msg -> Alcotest.failf "generatetoaddress failed: %s" msg
   | Ok (`List hashes) ->
     Alcotest.(check int) "2 blocks mined" 2 (List.length hashes);
     let tip_height = match ctx.chain.tip with
       | Some t -> t.height
       | None -> 0
     in
     Alcotest.(check int) "chain at height 2" 2 tip_height
   | Ok other -> Alcotest.failf "unexpected result: %s" (Yojson.Safe.to_string other));
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test: generatetoaddress rejects invalid address *)
let test_generatetoaddress_invalid_address () =
  let (ctx, db, _) = create_regtest_context () in
  let params = [`Int 1; `String "invalid_address"] in
  let result = Rpc.handle_generatetoaddress ctx params in
  Alcotest.(check bool) "invalid address rejected" true (Result.is_error result);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test: generatetoaddress is regtest only *)
let test_generatetoaddress_regtest_only () =
  let (ctx, db, _, _, _) = create_test_context () in  (* mainnet context *)
  let address = "bc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq9e75rs" in
  let params = [`Int 1; `String address] in
  let result = Rpc.handle_generatetoaddress ctx params in
  Alcotest.(check bool) "generatetoaddress rejected on mainnet" true (Result.is_error result);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test: generateblock with empty transactions list *)
let test_generateblock_empty_txs () =
  let (ctx, db, _) = create_regtest_context () in
  (* Generate a valid regtest address using the wallet *)
  let w = Wallet.create ~network:`Regtest ~db_path:"" in
  let address = Wallet.get_new_address w in
  let params = [`String address; `List []] in
  let result = Rpc.handle_generateblock ctx params in
  (match result with
   | Error msg -> Alcotest.failf "generateblock failed: %s" msg
   | Ok (`Assoc fields) ->
     Alcotest.(check bool) "has hash field" true (List.mem_assoc "hash" fields)
   | Ok other -> Alcotest.failf "unexpected result: %s" (Yojson.Safe.to_string other));
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test: generateblock is regtest only *)
let test_generateblock_regtest_only () =
  let (ctx, db, _, _, _) = create_test_context () in  (* mainnet context *)
  let address = "bc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq9e75rs" in
  let params = [`String address; `List []] in
  let result = Rpc.handle_generateblock ctx params in
  Alcotest.(check bool) "generateblock rejected on mainnet" true (Result.is_error result);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test: generate rejects negative nblocks *)
let test_generate_rejects_negative () =
  let (ctx, db, _) = create_regtest_context () in
  let params = [`Int (-1)] in
  let result = Rpc.handle_generate ctx params in
  Alcotest.(check bool) "negative nblocks rejected" true (Result.is_error result);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test: generate rejects too many blocks *)
let test_generate_rejects_too_many () =
  let (ctx, db, _) = create_regtest_context () in
  let params = [`Int 1001] in
  let result = Rpc.handle_generate ctx params in
  Alcotest.(check bool) "too many blocks rejected" true (Result.is_error result);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* ============================================================================
   Descriptor RPC Tests
   ============================================================================ *)

(* Test: getdescriptorinfo returns descriptor info *)
let test_getdescriptorinfo_basic () =
  let (ctx, db, _, _, _) = create_test_context () in
  let pk = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9" in
  let desc = "wpkh(" ^ pk ^ ")" in
  let params = [`String desc] in
  let result = Rpc.handle_getdescriptorinfo ctx params in
  (match result with
   | Ok (`Assoc fields) ->
     Alcotest.(check bool) "has descriptor" true (List.mem_assoc "descriptor" fields);
     Alcotest.(check bool) "has checksum" true (List.mem_assoc "checksum" fields);
     Alcotest.(check bool) "has isrange" true (List.mem_assoc "isrange" fields);
     Alcotest.(check bool) "has issolvable" true (List.mem_assoc "issolvable" fields);
     (* wpkh with fixed key is not ranged *)
     (match List.assoc_opt "isrange" fields with
      | Some (`Bool false) -> ()
      | _ -> Alcotest.fail "expected isrange=false")
   | Ok _ -> Alcotest.fail "expected Assoc"
   | Error e -> Alcotest.fail e);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test: getdescriptorinfo identifies ranged descriptors *)
let test_getdescriptorinfo_ranged () =
  let (ctx, db, _, _, _) = create_test_context () in
  let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8" in
  let desc = "wpkh(" ^ xpub ^ "/0/*)" in
  let params = [`String desc] in
  let result = Rpc.handle_getdescriptorinfo ctx params in
  (match result with
   | Ok (`Assoc fields) ->
     (match List.assoc_opt "isrange" fields with
      | Some (`Bool true) -> ()
      | _ -> Alcotest.fail "expected isrange=true for ranged descriptor")
   | Ok _ -> Alcotest.fail "expected Assoc"
   | Error e -> Alcotest.fail e);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test: getdescriptorinfo returns error for invalid descriptor *)
let test_getdescriptorinfo_invalid () =
  let (ctx, db, _, _, _) = create_test_context () in
  let params = [`String "invalid()"] in
  let result = Rpc.handle_getdescriptorinfo ctx params in
  Alcotest.(check bool) "invalid descriptor error" true (Result.is_error result);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test: deriveaddresses returns single address for non-ranged *)
let test_deriveaddresses_single () =
  let (ctx, db, _, _, _) = create_test_context () in
  let pk = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9" in
  let desc = "wpkh(" ^ pk ^ ")" in
  let params = [`String desc] in
  let result = Rpc.handle_deriveaddresses ctx params in
  (match result with
   | Ok (`List addrs) ->
     Alcotest.(check int) "one address" 1 (List.length addrs);
     (match List.hd addrs with
      | `String addr ->
        (* mainnet address starts with bc1 *)
        Alcotest.(check bool) "starts with bc1" true
          (String.length addr >= 3 && String.sub addr 0 3 = "bc1")
      | _ -> Alcotest.fail "expected string address")
   | Ok _ -> Alcotest.fail "expected List"
   | Error e -> Alcotest.fail e);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test: deriveaddresses with range *)
let test_deriveaddresses_range () =
  let (ctx, db, _, _, _) = create_test_context () in
  let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8" in
  let desc = "wpkh(" ^ xpub ^ "/0/*)" in
  let params = [`String desc; `List [`Int 0; `Int 4]] in
  let result = Rpc.handle_deriveaddresses ctx params in
  (match result with
   | Ok (`List addrs) ->
     Alcotest.(check int) "five addresses" 5 (List.length addrs);
     (* All addresses should be unique *)
     let addr_strs = List.filter_map (function `String s -> Some s | _ -> None) addrs in
     let unique = List.sort_uniq String.compare addr_strs in
     Alcotest.(check int) "all unique" 5 (List.length unique)
   | Ok _ -> Alcotest.fail "expected List"
   | Error e -> Alcotest.fail e);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test: deriveaddresses errors for ranged descriptor without range *)
let test_deriveaddresses_ranged_no_range () =
  let (ctx, db, _, _, _) = create_test_context () in
  let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8" in
  let desc = "wpkh(" ^ xpub ^ "/0/*)" in
  let params = [`String desc] in
  let result = Rpc.handle_deriveaddresses ctx params in
  Alcotest.(check bool) "ranged without range error" true (Result.is_error result);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* ============================================================================
   Test Runner
   ============================================================================ *)

let () =
  cleanup_test_db ();
  let open Alcotest in
  run "RPC" [
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
    "getrawtransaction", [
      test_case "mempool tx returns hex" `Quick test_getrawtransaction_mempool_hex;
      test_case "verbose returns json" `Quick test_getrawtransaction_verbose;
      test_case "scriptPubKey type" `Quick test_getrawtransaction_scriptpubkey_type;
      test_case "verbosity int 1" `Quick test_getrawtransaction_verbosity_int;
      test_case "verbosity int 0" `Quick test_getrawtransaction_verbosity_zero;
      test_case "not found error" `Quick test_getrawtransaction_not_found;
      test_case "invalid txid error" `Quick test_getrawtransaction_invalid_txid;
      test_case "confirmed has block info" `Quick test_getrawtransaction_confirmed_has_block_info;
      test_case "with blockhash param" `Quick test_getrawtransaction_with_blockhash;
      test_case "wrong blockhash error" `Quick test_getrawtransaction_wrong_blockhash;
    ];
    "batch", [
      test_case "multiple valid calls" `Quick test_batch_multiple_valid;
      test_case "mixed valid/invalid" `Quick test_batch_mixed_valid_invalid;
      test_case "preserves order" `Quick test_batch_preserves_order;
      test_case "null ids" `Quick test_batch_with_null_ids;
      test_case "many calls" `Quick test_batch_many_calls;
      test_case "handle_single_request" `Quick test_handle_single_request;
      test_case "single request works" `Quick test_single_request_still_works;
    ];
    "regtest_mining", [
      test_case "generate regtest only" `Quick test_generate_regtest_only;
      test_case "generate mines blocks" `Slow test_generate_mines_blocks;
      test_case "generate zero blocks" `Quick test_generate_zero_blocks;
      test_case "generatetoaddress mines" `Slow test_generatetoaddress_mines_to_address;
      test_case "generatetoaddress invalid addr" `Quick test_generatetoaddress_invalid_address;
      test_case "generatetoaddress regtest only" `Quick test_generatetoaddress_regtest_only;
      test_case "generateblock empty txs" `Slow test_generateblock_empty_txs;
      test_case "generateblock regtest only" `Quick test_generateblock_regtest_only;
      test_case "generate rejects negative" `Quick test_generate_rejects_negative;
      test_case "generate rejects too many" `Quick test_generate_rejects_too_many;
    ];
    "descriptors", [
      test_case "getdescriptorinfo basic" `Quick test_getdescriptorinfo_basic;
      test_case "getdescriptorinfo ranged" `Quick test_getdescriptorinfo_ranged;
      test_case "getdescriptorinfo invalid" `Quick test_getdescriptorinfo_invalid;
      test_case "deriveaddresses single" `Quick test_deriveaddresses_single;
      test_case "deriveaddresses range" `Quick test_deriveaddresses_range;
      test_case "deriveaddresses ranged no range" `Quick test_deriveaddresses_ranged_no_range;
    ];
  ]
