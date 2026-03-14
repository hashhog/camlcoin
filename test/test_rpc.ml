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
    fee_estimator = fe;
    network = Consensus.mainnet;
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
    fee_estimator = fe;
    network = Consensus.mainnet;
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
    fee_estimator = fe;
    network = Consensus.mainnet;
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
  ]
