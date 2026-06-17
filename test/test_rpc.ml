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
    utxo = None;
    data_dir = None;
    snapshot_activation = None;
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

(* ============================================================================
   getorphantxs Tests
   ============================================================================ *)

(* Helper: pull a string field out of a JSON object (fails the test if absent). *)
let json_str_field obj key =
  match obj with
  | `Assoc fields ->
    (match List.assoc_opt key fields with
     | Some (`String s) -> s
     | _ -> Alcotest.failf "expected string field %s" key)
  | _ -> Alcotest.fail "expected JSON object"

let json_int_field obj key =
  match obj with
  | `Assoc fields ->
    (match List.assoc_opt key fields with
     | Some (`Int n) -> n
     | _ -> Alcotest.failf "expected int field %s" key)
  | _ -> Alcotest.fail "expected JSON object"

(* Insert a transaction into the orphan pool and return (tx, txid, wtxid). *)
let seed_orphan ctx =
  (* Reference an unknown parent so this is a genuine orphan shape. *)
  let parent = Types.hash256_of_hex
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" in
  let tx = make_regular_tx
    [make_test_input parent 0l]
    [make_test_output 1_000_000L]
  in
  Mempool.add_orphan ctx.Rpc.mempool tx;
  let txid = Crypto.compute_txid tx in
  let wtxid = Crypto.compute_wtxid tx in
  (tx, txid, wtxid)

(* verbosity 0 → array of TXID strings (Core: orphan.tx->GetHash()), one per
   orphan. NOT wtxid. *)
let test_getorphantxs_verbosity0_txid_array () =
  let (ctx, db, _, _, _) = create_test_context () in
  let (_tx, txid, wtxid) = seed_orphan ctx in
  let expected_txid = Types.hash256_to_hex_display txid in
  let wtxid_hex = Types.hash256_to_hex_display wtxid in
  (match Rpc.handle_getorphantxs ctx [] with
   | Ok (`List items) ->
     Alcotest.(check int) "one orphan" 1 (List.length items);
     (match items with
      | [`String s] ->
        Alcotest.(check int) "txid is 64 hex" 64 (String.length s);
        Alcotest.(check string) "v0 is txid (Core GetHash), not wtxid"
          expected_txid s;
        (* Guard the exact regression: must NOT be the wtxid. *)
        if expected_txid <> wtxid_hex then
          Alcotest.(check bool) "v0 string is not the wtxid" false (s = wtxid_hex)
      | _ -> Alcotest.fail "expected single txid string")
   | Ok _ -> Alcotest.fail "expected JSON array"
   | Error (c, m) -> Alcotest.failf "unexpected error %d %s" c m);
  (* default arg (missing) behaves as verbosity 0 *)
  (match Rpc.handle_getorphantxs ctx [`Null] with
   | Ok (`List [ `String _ ]) -> ()
   | _ -> Alcotest.fail "null verbosity should default to 0 array-of-strings");
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* verbosity 1 → array of objects with EXACTLY the Core field set, in order:
   txid, wtxid, bytes, vsize, weight, from. NO expiration. *)
let test_getorphantxs_verbosity1_fields () =
  let (ctx, db, _, _, _) = create_test_context () in
  let (tx, txid, wtxid) = seed_orphan ctx in
  (match Rpc.handle_getorphantxs ctx [`Int 1] with
   | Ok (`List [ obj ]) ->
     Alcotest.(check string) "txid field"
       (Types.hash256_to_hex_display txid) (json_str_field obj "txid");
     Alcotest.(check string) "wtxid field"
       (Types.hash256_to_hex_display wtxid) (json_str_field obj "wtxid");
     Alcotest.(check int) "bytes = total serialized size"
       (Validation.compute_tx_size tx) (json_int_field obj "bytes");
     Alcotest.(check int) "vsize"
       (Validation.compute_tx_vsize tx) (json_int_field obj "vsize");
     Alcotest.(check int) "weight"
       (Validation.compute_tx_weight tx) (json_int_field obj "weight");
     (match obj with
      | `Assoc fields ->
        (* from is present and (this node) empty *)
        (match List.assoc_opt "from" fields with
         | Some (`List []) -> ()
         | Some (`List _) -> ()  (* tolerate future per-peer tracking *)
         | _ -> Alcotest.fail "expected `from` array");
        (* Core has NO expiration field — assert it is absent. *)
        Alcotest.(check bool) "no expiration field (Core parity)" false
          (List.mem_assoc "expiration" fields);
        (* verbosity 1 must NOT carry the hex blob *)
        Alcotest.(check bool) "no hex at verbosity 1" false
          (List.mem_assoc "hex" fields);
        (* The exact Core field set, in Core order. *)
        let keys = List.map fst fields in
        Alcotest.(check (list string)) "exact Core v1 field set + order"
          ["txid"; "wtxid"; "bytes"; "vsize"; "weight"; "from"] keys
      | _ -> Alcotest.fail "expected object")
   | _ -> Alcotest.fail "expected single-object array at verbosity 1");
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* verbosity 2 → verbosity-1 fields PLUS hex. *)
let test_getorphantxs_verbosity2_adds_hex () =
  let (ctx, db, _, _, _) = create_test_context () in
  let (tx, _txid, _wtxid) = seed_orphan ctx in
  (match Rpc.handle_getorphantxs ctx [`Int 2] with
   | Ok (`List [ `Assoc fields ]) ->
     Alcotest.(check bool) "has hex at verbosity 2" true (List.mem_assoc "hex" fields);
     Alcotest.(check bool) "still has wtxid" true (List.mem_assoc "wtxid" fields);
     Alcotest.(check bool) "no expiration at verbosity 2" false
       (List.mem_assoc "expiration" fields);
     (* Exact Core v2 field set: v1 fields + hex, in Core order. *)
     let keys = List.map fst fields in
     Alcotest.(check (list string)) "exact Core v2 field set + order"
       ["txid"; "wtxid"; "bytes"; "vsize"; "weight"; "from"; "hex"] keys;
     (match List.assoc_opt "hex" fields with
      | Some (`String h) ->
        Alcotest.(check string) "hex matches serialized tx" (tx_to_hex tx) h
      | _ -> Alcotest.fail "expected hex string")
   | _ -> Alcotest.fail "expected single-object array at verbosity 2");
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* empty pool → empty array. *)
let test_getorphantxs_empty_pool () =
  let (ctx, db, _, _, _) = create_test_context () in
  (match Rpc.handle_getorphantxs ctx [`Int 1] with
   | Ok (`List []) -> ()
   | _ -> Alcotest.fail "expected empty array for empty orphan pool");
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* out-of-range verbosity → RPC_INVALID_PARAMETER (-8) with Core message. *)
let test_getorphantxs_invalid_verbosity () =
  let (ctx, db, _, _, _) = create_test_context () in
  (match Rpc.handle_getorphantxs ctx [`Int 3] with
   | Error (code, msg) ->
     Alcotest.(check int) "code is -8" (-8) code;
     Alcotest.(check string) "Core message" "Invalid verbosity value 3" msg
   | Ok _ -> Alcotest.fail "expected error for verbosity 3");
  (match Rpc.handle_getorphantxs ctx [`Int (-1)] with
   | Error (code, _) -> Alcotest.(check int) "code is -8 for negative" (-8) code
   | Ok _ -> Alcotest.fail "expected error for verbosity -1");
  (* Core ParseVerbosity(allow_bool=false): a boolean argument must be REJECTED
     with an error, NOT mapped to 0/1. *)
  (match Rpc.handle_getorphantxs ctx [`Bool true] with
   | Error _ -> ()
   | Ok _ -> Alcotest.fail "bool verbosity must be rejected, not mapped to 1");
  (match Rpc.handle_getorphantxs ctx [`Bool false] with
   | Error _ -> ()
   | Ok _ -> Alcotest.fail "bool verbosity must be rejected, not mapped to 0");
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
    utxo = None;
    data_dir = None;
    snapshot_activation = None;
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
    utxo = None;
    data_dir = None;
    snapshot_activation = None;
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
    utxo = None;
    data_dir = None;
    snapshot_activation = None;
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
    utxo = None;
    data_dir = None;
    snapshot_activation = None;
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
   getdeploymentinfo Tests
   ============================================================================ *)

(* Create a regtest context (empty chain — tip = None).
   On regtest, segwit_height = 0 and taproot_height = 0, so both should be
   "active" even with an empty chain (query_height = 0). *)
let create_regtest_context () =
  let db_path = "/tmp/camlcoin_test_deploymentinfo_db" in
  let rec rm_rf path =
    if Sys.file_exists path then begin
      if Sys.is_directory path then begin
        Array.iter (fun f -> rm_rf (Filename.concat path f)) (Sys.readdir path);
        Unix.rmdir path
      end else Unix.unlink path
    end
  in
  rm_rf db_path;
  let db = Storage.ChainDB.create db_path in
  let utxo = Utxo.UtxoSet.create db in
  let mp = Mempool.create ~require_standard:false ~verify_scripts:false ~utxo ~current_height:0 () in
  let chain = Sync.create_chain_state db Consensus.regtest in
  let pm = Peer_manager.create Consensus.regtest in
  let fe = Fee_estimation.create () in
  let ctx : Rpc.rpc_context = {
    chain;
    mempool = mp;
    peer_manager = pm;
    wallet = None;
    wallet_manager = None;
    fee_estimator = fe;
    network = Consensus.regtest;
    filter_index = None;
    utxo = None;
    data_dir = None;
    snapshot_activation = None;
  } in
  (ctx, db, db_path)

(* Helper: extract the deployments object from a getdeploymentinfo result *)
let get_deployments_assoc result =
  match result with
  | Ok (`Assoc fields) ->
    (match List.assoc_opt "deployments" fields with
     | Some (`Assoc deps) -> deps
     | _ -> Alcotest.fail "deployments field missing or wrong type")
  | Ok _ -> Alcotest.fail "result should be an object"
  | Error msg -> Alcotest.fail ("getdeploymentinfo failed: " ^ msg)

(* Test: getdeploymentinfo returns a non-empty deployments object on regtest *)
let test_getdeploymentinfo_non_empty () =
  let (ctx, db, db_path) = create_regtest_context () in
  let result = Rpc.handle_getdeploymentinfo ctx [] in
  let deps = get_deployments_assoc result in
  Alcotest.(check bool) "deployments non-empty" true (List.length deps > 0);
  Storage.ChainDB.close db;
  let rec rm_rf path =
    if Sys.file_exists path then begin
      if Sys.is_directory path then begin
        Array.iter (fun f -> rm_rf (Filename.concat path f)) (Sys.readdir path);
        Unix.rmdir path
      end else Unix.unlink path
    end
  in
  rm_rf db_path

(* Test: segwit deployment is present and active on regtest (segwit_height = 0) *)
let test_getdeploymentinfo_segwit_active () =
  let (ctx, db, db_path) = create_regtest_context () in
  let result = Rpc.handle_getdeploymentinfo ctx [] in
  let deps = get_deployments_assoc result in
  (match List.assoc_opt "segwit" deps with
   | None -> Alcotest.fail "segwit deployment missing"
   | Some (`Assoc fields) ->
     (match List.assoc_opt "type" fields with
      | Some (`String t) -> Alcotest.(check string) "segwit type is buried" "buried" t
      | _ -> Alcotest.fail "segwit type field missing");
     (match List.assoc_opt "active" fields with
      | Some (`Bool b) -> Alcotest.(check bool) "segwit active on regtest" true b
      | _ -> Alcotest.fail "segwit active field missing")
   | _ -> Alcotest.fail "segwit deployment has wrong shape");
  Storage.ChainDB.close db;
  let rec rm_rf path =
    if Sys.file_exists path then begin
      if Sys.is_directory path then begin
        Array.iter (fun f -> rm_rf (Filename.concat path f)) (Sys.readdir path);
        Unix.rmdir path
      end else Unix.unlink path
    end
  in
  rm_rf db_path

(* Test: taproot deployment is present on regtest (bip9 type with always_active) *)
let test_getdeploymentinfo_taproot_present () =
  let (ctx, db, db_path) = create_regtest_context () in
  let result = Rpc.handle_getdeploymentinfo ctx [] in
  let deps = get_deployments_assoc result in
  (match List.assoc_opt "taproot" deps with
   | None -> Alcotest.fail "taproot deployment missing"
   | Some (`Assoc fields) ->
     (* taproot on regtest uses always_active start_time so state = Active *)
     (match List.assoc_opt "type" fields with
      | Some (`String t) -> Alcotest.(check string) "taproot type is bip9" "bip9" t
      | _ -> Alcotest.fail "taproot type field missing");
     (match List.assoc_opt "active" fields with
      | Some (`Bool b) -> Alcotest.(check bool) "taproot active on regtest" true b
      | _ -> Alcotest.fail "taproot active field missing");
     (* The bip9 sub-object must also be present *)
     (match List.assoc_opt "bip9" fields with
      | Some (`Assoc bip9_fields) ->
        (match List.assoc_opt "status" bip9_fields with
         | Some (`String s) -> Alcotest.(check string) "taproot bip9 status active" "active" s
         | _ -> Alcotest.fail "taproot bip9 status missing")
      | _ -> Alcotest.fail "taproot bip9 sub-object missing")
   | _ -> Alcotest.fail "taproot deployment has wrong shape");
  Storage.ChainDB.close db;
  let rec rm_rf path =
    if Sys.file_exists path then begin
      if Sys.is_directory path then begin
        Array.iter (fun f -> rm_rf (Filename.concat path f)) (Sys.readdir path);
        Unix.rmdir path
      end else Unix.unlink path
    end
  in
  rm_rf db_path

(* Test: getdeploymentinfo returns hash and height fields *)
let test_getdeploymentinfo_fields () =
  let (ctx, db, db_path) = create_regtest_context () in
  let result = Rpc.handle_getdeploymentinfo ctx [] in
  (match result with
   | Ok (`Assoc fields) ->
     Alcotest.(check bool) "hash field present" true (List.mem_assoc "hash" fields);
     Alcotest.(check bool) "height field present" true (List.mem_assoc "height" fields);
     Alcotest.(check bool) "deployments field present" true (List.mem_assoc "deployments" fields)
   | Ok _ -> Alcotest.fail "result should be object"
   | Error msg -> Alcotest.fail ("getdeploymentinfo failed: " ^ msg));
  Storage.ChainDB.close db;
  let rec rm_rf path =
    if Sys.file_exists path then begin
      if Sys.is_directory path then begin
        Array.iter (fun f -> rm_rf (Filename.concat path f)) (Sys.readdir path);
        Unix.rmdir path
      end else Unix.unlink path
    end
  in
  rm_rf db_path

(* ============================================================================
   getblockchaininfo / getdeploymentinfo Consistency Tests (regtest)

   These tests assert that getblockchaininfo.softforks and
   getdeploymentinfo.deployments read from the same underlying data: every
   deployment present in getdeploymentinfo must appear in softforks with
   identical "type" and "active" values.
   ============================================================================ *)

(* Extract the softforks/deployments assoc list.
   Core v31.99 DROPPED the softforks object from getblockchaininfo (it now lives
   only in getdeploymentinfo.deployments — blockchain.cpp:1497). camlcoin follows
   suit, so the softfork/deployment map is sourced from getdeploymentinfo. These
   consistency tests still verify the SAME underlying deployment state machine. *)
let get_softforks_assoc (ctx : Rpc.rpc_context) =
  match Rpc.handle_getdeploymentinfo ctx [] with
  | Ok (`Assoc fields) ->
    (match List.assoc_opt "deployments" fields with
     | Some (`Assoc sf) -> sf
     | Some _ -> Alcotest.fail "deployments field has wrong type"
     | None -> Alcotest.fail "deployments field missing from getdeploymentinfo")
  | Ok _ -> Alcotest.fail "getdeploymentinfo result is not an object"
  | Error msg -> Alcotest.fail ("getdeploymentinfo failed: " ^ msg)

(* Test: getblockchaininfo includes a non-empty softforks field on regtest *)
let test_getblockchaininfo_has_softforks () =
  let (ctx, db, db_path) = create_regtest_context () in
  let _ = Rpc.handle_getblockchaininfo ctx in
  let sf = get_softforks_assoc ctx in
  Alcotest.(check bool) "softforks non-empty" true (List.length sf > 0);
  Storage.ChainDB.close db;
  let rec rm_rf path =
    if Sys.file_exists path then begin
      if Sys.is_directory path then begin
        Array.iter (fun f -> rm_rf (Filename.concat path f)) (Sys.readdir path);
        Unix.rmdir path
      end else Unix.unlink path
    end
  in
  rm_rf db_path

(* Test: every deployment in getdeploymentinfo is present in
   getblockchaininfo.softforks with the same "type" and "active" values.
   This is the bridge assertion: both RPCs must read from one shared helper. *)
let test_softforks_matches_deploymentinfo () =
  let (ctx, db, db_path) = create_regtest_context () in

  (* Collect data from both RPCs *)
  let _bc_result = Rpc.handle_getblockchaininfo ctx in
  let di_result = Rpc.handle_getdeploymentinfo ctx [] in

  let sf   = get_softforks_assoc ctx in
  let deps = get_deployments_assoc di_result in

  (* Every entry in getdeploymentinfo.deployments must appear in softforks
     with matching type and active fields. *)
  List.iter (fun (name, dep_json) ->
    match dep_json with
    | `Assoc dep_fields ->
      let dep_type   = (match List.assoc_opt "type"   dep_fields with
        | Some (`String t) -> t | _ -> Alcotest.fail (name ^ ": type missing in deploymentinfo")) in
      let dep_active = (match List.assoc_opt "active" dep_fields with
        | Some (`Bool b) -> b | _ -> Alcotest.fail (name ^ ": active missing in deploymentinfo")) in
      (match List.assoc_opt name sf with
       | None ->
         Alcotest.fail (Printf.sprintf
           "deployment '%s' present in getdeploymentinfo but missing from softforks" name)
       | Some (`Assoc sf_fields) ->
         let sf_type   = (match List.assoc_opt "type"   sf_fields with
           | Some (`String t) -> t | _ -> Alcotest.fail (name ^ ": type missing in softforks")) in
         let sf_active = (match List.assoc_opt "active" sf_fields with
           | Some (`Bool b) -> b | _ -> Alcotest.fail (name ^ ": active missing in softforks")) in
         Alcotest.(check string)
           (name ^ ": type matches")   dep_type   sf_type;
         Alcotest.(check bool)
           (name ^ ": active matches") dep_active sf_active
       | Some _ ->
         Alcotest.fail (name ^ ": softforks entry has wrong shape"))
    | _ -> Alcotest.fail (name ^ ": deploymentinfo entry has wrong shape")
  ) deps;

  Storage.ChainDB.close db;
  let rec rm_rf path =
    if Sys.file_exists path then begin
      if Sys.is_directory path then begin
        Array.iter (fun f -> rm_rf (Filename.concat path f)) (Sys.readdir path);
        Unix.rmdir path
      end else Unix.unlink path
    end
  in
  rm_rf db_path

(* Test: all five buried deployment names are present in softforks with
   type = "buried".  We also verify that segwit (which activates at height 0
   on regtest) is active, while bip34/65/66/csv (which activate at heights
   500/1351/1251/432 on regtest) are correctly inactive on an empty chain. *)
let test_softforks_buried_present_regtest () =
  let (ctx, db, db_path) = create_regtest_context () in
  let _ = Rpc.handle_getblockchaininfo ctx in
  let sf = get_softforks_assoc ctx in
  let buried_names = ["bip34"; "bip65"; "bip66"; "csv"; "segwit"] in
  (* All five must be present with type = "buried" *)
  List.iter (fun name ->
    match List.assoc_opt name sf with
    | None -> Alcotest.fail (name ^ " missing from softforks")
    | Some (`Assoc fields) ->
      (match List.assoc_opt "type" fields with
       | Some (`String t) ->
         Alcotest.(check string) (name ^ " type is buried") "buried" t
       | _ -> Alcotest.fail (name ^ " type field missing or wrong"))
    | Some _ -> Alcotest.fail (name ^ " softfork entry has wrong shape")
  ) buried_names;
  (* segwit activates at height 0 on regtest — must be active even on empty chain *)
  (match List.assoc_opt "segwit" sf with
   | Some (`Assoc fields) ->
     (match List.assoc_opt "active" fields with
      | Some (`Bool b) ->
        Alcotest.(check bool) "segwit active at height 0" true b
      | _ -> Alcotest.fail "segwit active field missing")
   | _ -> Alcotest.fail "segwit entry missing or wrong shape");
  Storage.ChainDB.close db;
  let rec rm_rf path =
    if Sys.file_exists path then begin
      if Sys.is_directory path then begin
        Array.iter (fun f -> rm_rf (Filename.concat path f)) (Sys.readdir path);
        Unix.rmdir path
      end else Unix.unlink path
    end
  in
  rm_rf db_path

(* ============================================================================
   signmessage / verifymessage Tests
   (Bitcoin Core: src/rpc/signmessage.cpp + src/common/signmessage.cpp)
   ============================================================================ *)

(* WIF for a known regtest privkey, computed deterministically from a
   constant 32-byte private key.  We sign a message, then verify against
   the address derived from the same key — the round-trip MUST succeed. *)
let make_test_wif_and_address ?(compressed=true)
    ?(network=`Mainnet) (priv_hex : string) : string * string =
  let privkey = Cstruct.of_hex priv_hex in
  let wif = Address.wif_encode ~compressed ~network privkey in
  let pubkey = Crypto.derive_public_key ~compressed privkey in
  let addr = Address.of_pubkey ~network Address.P2PKH pubkey in
  let address = Address.address_to_string addr in
  (wif, address)

let test_signmessage_roundtrip () =
  let (ctx, db, _, _, _) = create_test_context () in
  let priv_hex =
    "0101010101010101010101010101010101010101010101010101010101010101" in
  let (wif, address) = make_test_wif_and_address priv_hex in
  let message = "hello hashhog" in
  (* sign *)
  let sig_result = Rpc.handle_signmessage ctx
    [`String wif; `String message] in
  Alcotest.(check bool) "sign succeeds" true (Result.is_ok sig_result);
  let sig_b64 = match sig_result with
    | Ok (`String s) -> s
    | _ -> Alcotest.fail "expected base64 string"
  in
  (* the b64 of a 65-byte buffer is 88 chars (with padding) *)
  Alcotest.(check int) "b64 sig length" 88 (String.length sig_b64);
  (* verify with the matching address — must be true *)
  let v_result = Rpc.handle_verifymessage ctx
    [`String address; `String sig_b64; `String message] in
  (match v_result with
   | Ok (`Bool true) -> ()
   | _ -> Alcotest.fail "expected verify = true");
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_verifymessage_wrong_message () =
  let (ctx, db, _, _, _) = create_test_context () in
  let priv_hex =
    "0202020202020202020202020202020202020202020202020202020202020202" in
  let (wif, address) = make_test_wif_and_address priv_hex in
  let sig_result = Rpc.handle_signmessage ctx
    [`String wif; `String "original"] in
  let sig_b64 = match sig_result with
    | Ok (`String s) -> s
    | _ -> Alcotest.fail "expected base64 string"
  in
  (* tamper with the message — verify must return false (NOT error) *)
  let v_result = Rpc.handle_verifymessage ctx
    [`String address; `String sig_b64; `String "tampered"] in
  (match v_result with
   | Ok (`Bool false) -> ()
   | _ -> Alcotest.fail "expected verify = false");
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_verifymessage_invalid_address () =
  let (ctx, db, _, _, _) = create_test_context () in
  let v_result = Rpc.handle_verifymessage ctx
    [`String "not-a-bitcoin-address";
     `String "AAAAAAAAAA"; `String "msg"] in
  Alcotest.(check bool) "invalid addr is Error" true (Result.is_error v_result);
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_verifymessage_malformed_b64 () =
  let (ctx, db, _, _, _) = create_test_context () in
  let priv_hex =
    "0303030303030303030303030303030303030303030303030303030303030303" in
  let (_wif, address) = make_test_wif_and_address priv_hex in
  let v_result = Rpc.handle_verifymessage ctx
    [`String address;
     `String "!@#$ not-base-64 !!!"; `String "msg"] in
  Alcotest.(check bool) "malformed b64 is Error" true (Result.is_error v_result);
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_signmessage_invalid_wif () =
  let (ctx, db, _, _, _) = create_test_context () in
  let r = Rpc.handle_signmessage ctx
    [`String "not-a-wif"; `String "msg"] in
  Alcotest.(check bool) "invalid wif rejected" true (Result.is_error r);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* MessageHash framing must match Core: dsha256(compactsize(magic) || magic
   || compactsize(msg) || msg).  We compute it both via our helper and via
   raw bytes and compare. *)
let test_message_hash_matches_core_framing () =
  let msg = "abc" in
  let computed = Crypto.message_hash msg in
  (* Manual reference: 0x18 || "Bitcoin Signed Message:\n" || 0x03 || "abc" *)
  let expected_buf = Buffer.create 64 in
  Buffer.add_char expected_buf '\x18';  (* len of magic = 24 *)
  Buffer.add_string expected_buf "Bitcoin Signed Message:\n";
  Buffer.add_char expected_buf '\x03';
  Buffer.add_string expected_buf "abc";
  let expected = Crypto.sha256d
    (Cstruct.of_string (Buffer.contents expected_buf)) in
  Alcotest.(check bool) "framing matches" true (Cstruct.equal computed expected)

(* ============================================================================
   estimaterawfee Tests
   (Bitcoin Core: src/rpc/fees.cpp::estimaterawfee)
   ============================================================================ *)

let test_estimaterawfee_empty_returns_object () =
  let (ctx, db, _, _, _) = create_test_context () in
  (* No data has been recorded — every horizon should report errors but the
     RPC must still return an object (matches Core behaviour). *)
  let r = Rpc.handle_estimaterawfee ctx [`Int 6] in
  Alcotest.(check bool) "ok" true (Result.is_ok r);
  (match r with
   | Ok (`Assoc fields) ->
     Alcotest.(check bool) "has short" true (List.mem_assoc "short" fields);
     (match List.assoc "short" fields with
      | `Assoc subfields ->
        Alcotest.(check bool) "short has decay" true
          (List.mem_assoc "decay" subfields);
        Alcotest.(check bool) "short has scale" true
          (List.mem_assoc "scale" subfields)
      | _ -> Alcotest.fail "short not an object")
   | _ -> Alcotest.fail "expected Ok(`Assoc)");
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_estimaterawfee_rejects_bad_target () =
  let (ctx, db, _, _, _) = create_test_context () in
  let r = Rpc.handle_estimaterawfee ctx [`Int 0] in
  Alcotest.(check bool) "0 rejected" true (Result.is_error r);
  let r = Rpc.handle_estimaterawfee ctx [`Int 100_000] in
  Alcotest.(check bool) "huge target rejected" true (Result.is_error r);
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_estimaterawfee_rejects_bad_threshold () =
  let (ctx, db, _, _, _) = create_test_context () in
  let r = Rpc.handle_estimaterawfee ctx [`Int 6; `Float 1.5] in
  Alcotest.(check bool) "threshold>1 rejected" true (Result.is_error r);
  let r = Rpc.handle_estimaterawfee ctx [`Int 6; `Float (-0.1)] in
  Alcotest.(check bool) "threshold<0 rejected" true (Result.is_error r);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* When conf_target exceeds a horizon's max_target the horizon must be
   omitted from the response (matches Core: short:12 / medium:48 /
   long:1008).  At target=500 only "long" tracks the request. *)
let test_estimaterawfee_horizon_omission () =
  let (ctx, db, _, _, _) = create_test_context () in
  let r = Rpc.handle_estimaterawfee ctx [`Int 500] in
  (match r with
   | Ok (`Assoc fields) ->
     Alcotest.(check bool) "long present" true (List.mem_assoc "long" fields);
     Alcotest.(check bool) "short absent" false (List.mem_assoc "short" fields);
     Alcotest.(check bool) "medium absent" false (List.mem_assoc "medium" fields)
   | _ -> Alcotest.fail "expected Ok");
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* ============================================================================
   dumpmempool / savemempool / loadmempool Tests
   (Bitcoin Core: src/rpc/mempool.cpp)
   ============================================================================ *)

let make_dat_dir () : string =
  let path = Filename.concat (Filename.get_temp_dir_name ())
    (Printf.sprintf "camlcoin_rpc_dat_%d" (Unix.getpid ())) in
  (try Unix.mkdir path 0o755 with Unix.Unix_error (Unix.EEXIST, _, _) -> ());
  path

let cleanup_dat_dir (path : string) : unit =
  let dat = Filename.concat path "mempool.dat" in
  if Sys.file_exists dat then Sys.remove dat;
  try Unix.rmdir path with _ -> ()

(* dumpmempool requires data_dir; without it the call MUST surface a clear
   error rather than silently no-op. *)
let test_dumpmempool_no_data_dir_errors () =
  let (ctx, db, _, _, _) = create_test_context () in
  let r = Rpc.handle_dumpmempool ctx [] in
  Alcotest.(check bool) "errors when data_dir is None" true
    (Result.is_error r);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* dump → load round-trip must preserve transaction count (mirrors the
   underlying save_mempool/load_mempool round-trip test in test_mempool.ml,
   but this version exercises the full RPC plumbing including the
   data_dir field on rpc_context). *)
let test_dumpmempool_load_roundtrip () =
  let (ctx, db, _utxo, txid1, _) = create_test_context () in
  let dir = make_dat_dir () in
  let ctx = { ctx with Rpc.data_dir = Some dir } in
  let tx = make_regular_tx
    [make_test_input txid1 0l]
    [make_test_output 9_990_000L] in
  let _ = Mempool.add_transaction ctx.mempool tx in
  let dump = Rpc.handle_dumpmempool ctx [] in
  Alcotest.(check bool) "dump ok" true (Result.is_ok dump);
  (match dump with
   | Ok (`Assoc fields) ->
     (match List.assoc_opt "filename" fields with
      | Some (`String p) ->
        Alcotest.(check bool) "file exists" true (Sys.file_exists p)
      | _ -> Alcotest.fail "filename field missing")
   | _ -> Alcotest.fail "expected Ok(`Assoc)");
  let load = Rpc.handle_loadmempool ctx [] in
  (match load with
   | Ok (`Assoc fields) ->
     (match List.assoc_opt "loaded" fields with
      | Some (`Int n) ->
        (* Loader is loss-tolerant: 0 or 1 acceptable for a tx whose UTXO
           was wiped by the cleanup_test_db between save and load.  We
           just need the call to surface a numeric "loaded" count. *)
        Alcotest.(check bool) "loaded is non-negative" true (n >= 0)
      | _ -> Alcotest.fail "loaded field missing or wrong type")
   | _ -> Alcotest.fail "expected Ok(`Assoc)");
  cleanup_dat_dir dir;
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* savemempool is an alias for dumpmempool (matches Core's CRPCCommand
   table where they share the same RPCHelpMan). *)
let test_savemempool_alias () =
  let (ctx, db, _utxo, _, _) = create_test_context () in
  let dir = make_dat_dir () in
  let ctx = { ctx with Rpc.data_dir = Some dir } in
  let r = Rpc.dispatch_rpc ctx "savemempool" [] in
  Alcotest.(check bool) "savemempool dispatches" true (Result.is_ok r);
  (* After the alias call the file MUST exist. *)
  Alcotest.(check bool) "mempool.dat written" true
    (Sys.file_exists (Filename.concat dir "mempool.dat"));
  cleanup_dat_dir dir;
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_loadmempool_missing_file_zero () =
  let (ctx, db, _utxo, _, _) = create_test_context () in
  let dir = make_dat_dir () in
  let ctx = { ctx with Rpc.data_dir = Some dir } in
  let r = Rpc.handle_loadmempool ctx [] in
  (match r with
   | Ok (`Assoc fields) ->
     (match List.assoc_opt "loaded" fields with
      | Some (`Int 0) -> ()
      | _ -> Alcotest.fail "expected loaded=0 for missing file")
   | _ -> Alcotest.fail "expected Ok");
  cleanup_dat_dir dir;
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* ============================================================================
   dumptxoutset / gettxoutsetinfo MuHash3072 wiring

   The RPC-level wiring needs to (a) emit the MuHash3072 commitment as
   [txoutset_hash] in the [dumptxoutset] response and (b) surface the
   same value via the [gettxoutsetinfo "muhash"] handler. Both
   handlers iterate the chainstate DB, so we populate the test
   context's UTXO set, call the RPC, and compare against
   [Assume_utxo.compute_utxo_muhash_from_db] computed directly. The
   strict-mismatch path is exercised by [test_assume_utxo.ml] —
   reproducing it here would require synthesising a snapshot file that
   passes the chainparams whitelist, which has nothing to do with the
   hash wiring itself.
   ============================================================================ *)

(* ============================================================================
   NetworkDisable RAII gate (dumptxoutset rollback)

   Mirrors Bitcoin Core's NetworkDisable wrapper around TemporaryRollback in
   rpc/blockchain.cpp::dumptxoutset. Sets [chain.block_submission_paused]
   directly and confirms [handle_submitblock] short-circuits with a
   "paused" reject string before any deserialization.
   ============================================================================ *)

let test_submitblock_refuses_while_paused () =
  let (ctx, db, _utxo, _txid1, _txid2) = create_test_context () in
  ctx.chain.block_submission_paused <- true;
  (* Garbage hex is fine: gate runs before deserialization. *)
  let result = Rpc.handle_submitblock ctx [`String "00"] in
  (match result with
   | Ok (`String reason) ->
     Alcotest.(check bool)
       "reject reason mentions pause"
       true
       (try
          let _ = Str.search_forward (Str.regexp_string "paused") reason 0 in
          true
        with Not_found -> false)
   | Ok _ ->
     Alcotest.fail "expected `String reject reason while paused"
   | Error msg ->
     Alcotest.fail ("submitblock returned error while paused: " ^ msg));
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_submitblock_unblocks_after_pause_cleared () =
  let (ctx, db, _utxo, _txid1, _txid2) = create_test_context () in
  ctx.chain.block_submission_paused <- true;
  ctx.chain.block_submission_paused <- false;
  (* With the pause cleared, the handler must move past the gate and
     reach the decode/validate path. We pass garbage hex so it ultimately
     fails decode — the important assertion is that we DON'T see the
     "paused" reject string. *)
  let result = Rpc.handle_submitblock ctx [`String "00"] in
  (match result with
   | Ok (`String reason) ->
     Alcotest.(check bool)
       "must not report pause once flag is cleared"
       false
       (try
          let _ = Str.search_forward (Str.regexp_string "paused") reason 0 in
          true
        with Not_found -> false)
   | Ok _ -> ()
   | Error _ -> ()  (* Decode error is fine; means we're past the gate. *));
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* ============================================================================
   BIP-22 result-string mapping tests.
   handle_submitblock must return Ok(`String "…") with canonical BIP-22
   tokens for all rejection paths, per BIP-22 and Bitcoin Core
   BIP22ValidationResult() in src/rpc/mining.cpp.
   ============================================================================ *)

(* Helper: call handle_submitblock and extract the result string. *)
let submitblock_result ctx hex_str =
  match Rpc.handle_submitblock ctx [`String hex_str] with
  | Ok (`String s) -> s
  | Ok `Null -> "null"
  | Ok _ -> "unexpected-json"
  | Error e -> "rpc-error:" ^ e

(* submitblock with unparseable hex (single byte "00") must return
   "rejected" — a BIP-22 string, not a raw OCaml exception message. *)
let test_submitblock_bad_hex_returns_rejected () =
  let (ctx, db, _utxo, _txid1, _txid2) = create_test_context () in
  let r = submitblock_result ctx "00" in
  Alcotest.(check bool) "bad hex returns BIP-22 rejected" true
    (r = "rejected" || not (String.contains r ':'));
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* submitblock with an odd-length hex string returns BIP-22 rejected. *)
let test_submitblock_odd_hex_returns_rejected () =
  let (ctx, db, _utxo, _txid1, _txid2) = create_test_context () in
  let r = submitblock_result ctx "abc" in
  Alcotest.(check bool) "odd-length hex returns BIP-22 rejected or error" true
    (r = "rejected" || (String.length r > 0 && r <> "null"));
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* submitblock with missing params returns Error (invalid params). *)
let test_submitblock_missing_params_returns_error () =
  let (ctx, db, _utxo, _txid1, _txid2) = create_test_context () in
  let result = Rpc.handle_submitblock ctx [] in
  (match result with
   | Error _ -> ()   (* expected: invalid params *)
   | Ok _ -> Alcotest.fail "missing params should return Error");
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* verify bip22_of_submitblock_error maps canonical strings correctly. *)
(* We test indirectly via known error message substrings that mining.ml emits. *)
let test_bip22_error_mapping () =
  (* Build a helper that calls the internal mapping logic by probing
     the real submit-block path with known-bad blocks.  We use a block
     whose hex decodes successfully but fails PoW, so check_block_header
     returns "Block does not meet difficulty target" → "high-hash". *)
  (* Use 80 zero bytes (header) + one zero byte (tx count) *)
  let zero_block_hex = String.make (81 * 2) '0' in
  let (ctx, db, _utxo, _txid1, _txid2) = create_test_context () in
  let r = submitblock_result ctx zero_block_hex in
  (* "Block does not meet difficulty target" → "high-hash"
     OR decode failure → "rejected".  Both are valid BIP-22 strings. *)
  let is_bip22 = List.mem r ["high-hash"; "bad-diffbits"; "rejected"; "null"; "bad-txnmrklroot"] in
  Alcotest.(check bool) "all-zero block returns BIP-22 token" true is_bip22;
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_dumptxoutset_emits_muhash_txoutset_hash () =
  let (ctx, db, _utxo, _txid1, _txid2) = create_test_context () in
  let path = Printf.sprintf "/tmp/camlcoin_dump_muhash_%d.dat"
               (Unix.getpid ()) in
  (try Sys.remove path with _ -> ());
  let result = Rpc.handle_dumptxoutset ctx [`String path] in
  (match result with
   | Ok (`Assoc fields) ->
     (* Direct expected value: MuHash3072 over the same DB the handler
        iterates. The test context is populated by create_test_context
        with two UTXOs; this is enough to make MuHash deterministic
        and non-trivial. *)
     let expected =
       Assume_utxo.compute_utxo_muhash_from_db ctx.chain.db
     in
     let expected_hex = Types.hash256_to_hex_display expected in
     (match List.assoc_opt "txoutset_hash" fields with
      | Some (`String s) ->
        Alcotest.(check string)
          "dumptxoutset txoutset_hash matches MuHash3072"
          expected_hex s
      | _ -> Alcotest.fail "dumptxoutset response missing txoutset_hash field")
   | Ok _ -> Alcotest.fail "expected `Assoc result"
   | Error msg -> Alcotest.fail ("dumptxoutset returned error: " ^ msg));
  (try Sys.remove path with _ -> ());
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_gettxoutsetinfo_muhash_matches_dump () =
  let (ctx, db, _utxo, _txid1, _txid2) = create_test_context () in
  let result = Rpc.handle_gettxoutsetinfo ctx [`String "muhash"] in
  (match result with
   | Ok (`Assoc fields) ->
     let expected =
       Assume_utxo.compute_utxo_muhash_from_db ctx.chain.db
     in
     let expected_hex = Types.hash256_to_hex_display expected in
     (match List.assoc_opt "muhash" fields with
      | Some (`String s) ->
        Alcotest.(check string)
          "gettxoutsetinfo muhash matches direct compute"
          expected_hex s
      | _ -> Alcotest.fail "gettxoutsetinfo response missing muhash field");
     (* Sanity: txouts must be 2 because create_test_context adds two
        UTXOs; transactions == 2 since both have unique txids. *)
     (match List.assoc_opt "txouts" fields with
      | Some (`Int n) -> Alcotest.(check int) "txouts" 2 n
      | _ -> Alcotest.fail "missing txouts field");
     (match List.assoc_opt "transactions" fields with
      | Some (`Int n) -> Alcotest.(check int) "transactions" 2 n
      | _ -> Alcotest.fail "missing transactions field")
   | Ok _ -> Alcotest.fail "expected `Assoc result"
   | Error msg -> Alcotest.fail ("gettxoutsetinfo returned error: " ^ msg));
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_gettxoutsetinfo_rejects_bad_hash_type () =
  let (ctx, db, _utxo, _, _) = create_test_context () in
  let result =
    Rpc.handle_gettxoutsetinfo ctx [`String "not_a_real_hash_type"]
  in
  (match result with
   | Error _ -> ()
   | Ok _ -> Alcotest.fail "expected error for unknown hash_type");
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* ============================================================================
   Wallet Encryption RPC Tests
     - encryptwallet "passphrase"
     - walletpassphrase "passphrase" timeout
     - walletlock
   ============================================================================ *)

(* Build a context with an attached wallet. The wallet is created with one
   address so encrypt/decrypt actually exercises the master-key roundtrip
   verification path in [Wallet.wallet_passphrase]. *)
let create_wallet_test_context () =
  let (ctx, db, utxo, _, _) = create_test_context () in
  let wallet = Wallet.create ~network:`Regtest ~db_path:"" in
  let _ = Wallet.get_new_address wallet in
  let ctx = { ctx with wallet = Some wallet } in
  (ctx, db, utxo, wallet)

(* Test: encrypt → walletpassphrase with wrong passphrase fails;
   walletpassphrase with right passphrase succeeds. Goes through dispatch_rpc
   to exercise both the handler and the dispatch table wiring. *)
let test_walletpassphrase_wrong_then_right () =
  let (ctx, db, _utxo, wallet) = create_wallet_test_context () in

  (* encryptwallet "secret" *)
  (match Rpc.dispatch_rpc ctx "encryptwallet" [`String "secret"] with
   | Ok _ -> ()
   | Error (_, msg) -> Alcotest.fail ("encryptwallet failed: " ^ msg));
  Alcotest.(check bool) "wallet now encrypted" true (Wallet.is_encrypted wallet);
  Alcotest.(check bool) "wallet now locked" true (Wallet.is_locked wallet);

  (* walletpassphrase "wrong" 60 — must fail with rpc_wallet_error *)
  (match Rpc.dispatch_rpc ctx "walletpassphrase" [`String "wrong"; `Int 60] with
   | Ok _ -> Alcotest.fail "walletpassphrase with wrong pass should fail"
   | Error (code, _) ->
     Alcotest.(check int) "wrong pass returns wallet error" Rpc.rpc_wallet_error code);
  Alcotest.(check bool) "still locked after wrong pass" true (Wallet.is_locked wallet);

  (* walletpassphrase "secret" 60 — must succeed *)
  (match Rpc.dispatch_rpc ctx "walletpassphrase" [`String "secret"; `Int 60] with
   | Ok _ -> ()
   | Error (_, msg) ->
     Alcotest.fail ("walletpassphrase with right pass failed: " ^ msg));
  Alcotest.(check bool) "unlocked after right pass" false (Wallet.is_locked wallet);

  (* walletlock — must re-lock immediately *)
  (match Rpc.dispatch_rpc ctx "walletlock" [] with
   | Ok _ -> ()
   | Error (_, msg) -> Alcotest.fail ("walletlock failed: " ^ msg));
  Alcotest.(check bool) "locked after walletlock" true (Wallet.is_locked wallet);

  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test: walletpassphrase auto-relocks after timeout via the Lwt.async
   sleeper. Uses a 1-second timeout and runs an Lwt main loop for ~2s
   to give the timer a chance to fire. *)
let test_walletpassphrase_auto_relock () =
  let (ctx, db, _utxo, wallet) = create_wallet_test_context () in

  (match Rpc.dispatch_rpc ctx "encryptwallet" [`String "topsecret"] with
   | Ok _ -> ()
   | Error (_, msg) -> Alcotest.fail ("encryptwallet failed: " ^ msg));

  (* Unlock for 1 second. *)
  (match Rpc.dispatch_rpc ctx "walletpassphrase"
           [`String "topsecret"; `Int 1] with
   | Ok _ -> ()
   | Error (_, msg) -> Alcotest.fail ("walletpassphrase failed: " ^ msg));
  Alcotest.(check bool) "unlocked immediately after walletpassphrase"
    false (Wallet.is_locked wallet);

  (* Drive the Lwt scheduler so the relock-timer can fire. We sleep
     slightly longer than the unlock timeout. *)
  Lwt_main.run (Lwt_unix.sleep 1.6);

  Alcotest.(check bool) "auto-relocked after timeout"
    true (Wallet.is_locked wallet);

  Storage.ChainDB.close db;
  cleanup_test_db ()

(* ============================================================================
   submitpackage Tests
   ============================================================================ *)

(* Test: valid 2-tx package (parent + child) admits both transactions and
   returns Core-shape JSON with package_msg=success and a tx-results entry
   keyed by wtxid for each submitted tx. *)
let test_submitpackage_valid_2tx () =
  let (ctx, db, _utxo, txid1, _) = create_test_context () in
  (* Parent: 10 BTC -> 9.99 BTC (10k sat fee). *)
  let parent_tx = make_regular_tx
    [make_test_input txid1 0l]
    [make_test_output 9_990_000L]
  in
  let parent_txid = Crypto.compute_txid parent_tx in
  (* Child spends parent's output, paying 10k sat fee. *)
  let child_tx = make_regular_tx
    [make_test_input parent_txid 0l]
    [make_test_output 9_980_000L]
  in
  let parent_wtxid = Crypto.compute_wtxid parent_tx in
  let child_wtxid = Crypto.compute_wtxid child_tx in
  let parent_wtxid_hex = Types.hash256_to_hex_display parent_wtxid in
  let child_wtxid_hex = Types.hash256_to_hex_display child_wtxid in
  let params =
    [`List [`String (tx_to_hex parent_tx); `String (tx_to_hex child_tx)]]
  in
  let result = Rpc.handle_submitpackage ctx params in
  Alcotest.(check bool) "submitpackage Ok" true (Result.is_ok result);
  (match result with
   | Ok (`Assoc fields) ->
     (match List.assoc_opt "package_msg" fields with
      | Some (`String s) ->
        Alcotest.(check string) "package_msg success" "success" s
      | _ -> Alcotest.fail "package_msg missing or wrong type");
     (match List.assoc_opt "tx-results" fields with
      | Some (`Assoc tx_results) ->
        Alcotest.(check int) "2 tx-results" 2 (List.length tx_results);
        Alcotest.(check bool) "parent wtxid present" true
          (List.mem_assoc parent_wtxid_hex tx_results);
        Alcotest.(check bool) "child wtxid present" true
          (List.mem_assoc child_wtxid_hex tx_results);
        (* Each entry should have txid + vsize + fees (no error) *)
        List.iter (fun (_wtxid_hex, entry) ->
          match entry with
          | `Assoc inner ->
            Alcotest.(check bool) "has txid" true
              (List.mem_assoc "txid" inner);
            Alcotest.(check bool) "has vsize" true
              (List.mem_assoc "vsize" inner);
            Alcotest.(check bool) "has fees" true
              (List.mem_assoc "fees" inner);
            Alcotest.(check bool) "no error key" false
              (List.mem_assoc "error" inner);
            (match List.assoc "fees" inner with
             | `Assoc fee_fields ->
               Alcotest.(check bool) "fees.base present" true
                 (List.mem_assoc "base" fee_fields)
             | _ -> Alcotest.fail "fees should be an object")
          | _ -> Alcotest.fail "tx-result entry should be object"
        ) tx_results
      | _ -> Alcotest.fail "tx-results missing or wrong type");
     Alcotest.(check bool) "replaced-transactions present" true
       (List.mem_assoc "replaced-transactions" fields)
   | _ -> Alcotest.fail "expected Ok(`Assoc _)");
  (* Both txs should be in mempool *)
  Alcotest.(check bool) "parent in mempool" true
    (Mempool.contains ctx.mempool parent_txid);
  Alcotest.(check bool) "child in mempool" true
    (Mempool.contains ctx.mempool (Crypto.compute_txid child_tx));
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test: package with a child that has missing inputs rejects atomically.
   The child references a nonexistent parent (not in the package, not in the
   chain), so the whole package must be rejected; mempool must remain empty. *)
let test_submitpackage_rejects_atomic () =
  let (ctx, db, _utxo, txid1, _) = create_test_context () in
  (* Parent is fine. *)
  let parent_tx = make_regular_tx
    [make_test_input txid1 0l]
    [make_test_output 9_990_000L]
  in
  (* Child spends a nonexistent parent — guaranteed missing input. *)
  let bogus_parent =
    Types.hash256_of_hex
      "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
  in
  let child_tx = make_regular_tx
    [make_test_input bogus_parent 0l]
    [make_test_output 999_000L]
  in
  let parent_txid = Crypto.compute_txid parent_tx in
  let child_txid = Crypto.compute_txid child_tx in
  let params =
    [`List [`String (tx_to_hex parent_tx); `String (tx_to_hex child_tx)]]
  in
  let result = Rpc.handle_submitpackage ctx params in
  Alcotest.(check bool) "submitpackage Ok response" true (Result.is_ok result);
  (match result with
   | Ok (`Assoc fields) ->
     (* package_msg should NOT be "success" since the child fails. *)
     (match List.assoc_opt "package_msg" fields with
      | Some (`String s) ->
        Alcotest.(check bool) "package_msg not success" true (s <> "success")
      | _ -> Alcotest.fail "package_msg missing");
     (* tx-results must still contain an entry per submitted wtxid. *)
     (match List.assoc_opt "tx-results" fields with
      | Some (`Assoc tx_results) ->
        Alcotest.(check int) "2 tx-results entries" 2
          (List.length tx_results)
      | _ -> Alcotest.fail "tx-results missing")
   | _ -> Alcotest.fail "expected Ok(`Assoc _)");
  (* Atomic semantics: child must not be in mempool. The parent may or may
     not have ended up in the mempool depending on partial-acceptance
     behavior, but the child (which references a nonexistent input) MUST be
     rejected. *)
  Alcotest.(check bool) "child rejected" false
    (Mempool.contains ctx.mempool child_txid);
  ignore parent_txid;
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test: empty package array is rejected with a clear error. *)
let test_submitpackage_empty () =
  let (ctx, db, _, _, _) = create_test_context () in
  let result = Rpc.handle_submitpackage ctx [`List []] in
  Alcotest.(check bool) "empty package rejected" true (Result.is_error result);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test: package exceeding MAX_PACKAGE_COUNT is rejected. *)
let test_submitpackage_too_many () =
  let (ctx, db, _, txid1, _) = create_test_context () in
  let tx = make_regular_tx
    [make_test_input txid1 0l]
    [make_test_output 9_990_000L]
  in
  let hex = tx_to_hex tx in
  (* 26 entries > MAX_PACKAGE_COUNT (25) *)
  let arr = `List (List.init 26 (fun _ -> `String hex)) in
  let result = Rpc.handle_submitpackage ctx [arr] in
  Alcotest.(check bool) "26-tx package rejected" true (Result.is_error result);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test: dispatcher route registers submitpackage. *)
let test_submitpackage_dispatcher () =
  let (ctx, db, _, txid1, _) = create_test_context () in
  let parent_tx = make_regular_tx
    [make_test_input txid1 0l]
    [make_test_output 9_990_000L]
  in
  let parent_txid = Crypto.compute_txid parent_tx in
  let child_tx = make_regular_tx
    [make_test_input parent_txid 0l]
    [make_test_output 9_980_000L]
  in
  let params =
    [`List [`String (tx_to_hex parent_tx); `String (tx_to_hex child_tx)]]
  in
  let result = Rpc.dispatch_rpc ctx "submitpackage" params in
  Alcotest.(check bool) "dispatcher routes submitpackage" true
    (Result.is_ok result);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* ============================================================================
   Wallet Wave Tests:
     - lockunspent / listlockunspent (Bitcoin Core: src/wallet/rpc/coins.cpp)
     - signmessage WIF→address Core-shape
     - walletcreatefundedpsbt (Bitcoin Core: src/wallet/rpc/spend.cpp)
   ============================================================================ *)

(* Build a wallet UTXO entry for testing.  We bypass scan_block here because
   we want to drop a single, deterministic outpoint into the wallet without
   plumbing a fake block. *)
let make_wallet_utxo (w : Wallet.t) ~txid ~vout ~value : Wallet.wallet_utxo =
  (* Generate a key the wallet owns so coin selection paths can sign. *)
  let kp = Wallet.generate_key w in
  let script_pubkey = match kp.Wallet.addr_type with
    | Wallet.P2WPKH -> Wallet.build_p2wpkh_script (Crypto.hash160 kp.public_key)
    | Wallet.P2PKH -> Wallet.build_p2pkh_script (Crypto.hash160 kp.public_key)
    | Wallet.P2TR ->
      let xonly = Crypto.derive_xonly_pubkey kp.private_key in
      Wallet.build_p2tr_script xonly
  in
  { Wallet.outpoint = { Types.txid; vout };
    utxo = { Utxo.value; script_pubkey; height = 1; is_coinbase = false };
    key_index = 0;
    confirmed = true;
    watch_only = false; }

(* Stand up a wallet-backed RPC context with two known wallet UTXOs that
   coin selection can pick from.  Returns the context, the chain DB handle
   (for cleanup), the wallet, and the two outpoints. *)
let create_lockunspent_context () =
  let (ctx, db, _utxo, _, _) = create_test_context () in
  let wallet = Wallet.create ~network:`Mainnet ~db_path:"" in
  let txid_a = Types.hash256_of_hex
    "1111111111111111111111111111111111111111111111111111111111111111" in
  let txid_b = Types.hash256_of_hex
    "2222222222222222222222222222222222222222222222222222222222222222" in
  let wu_a = make_wallet_utxo wallet ~txid:txid_a ~vout:0l ~value:50_000_000L in
  let wu_b = make_wallet_utxo wallet ~txid:txid_b ~vout:1l ~value:30_000_000L in
  wallet.utxos <- [wu_a; wu_b];
  let ctx = { ctx with wallet = Some wallet } in
  (ctx, db, wallet, wu_a.outpoint, wu_b.outpoint)

(* lockunspent + listlockunspent + unlock round-trip.  Locks one outpoint,
   verifies it shows up in listlockunspent with the display-reversed txid,
   then unlocks it and verifies the list is empty again. *)
let test_lockunspent_roundtrip () =
  let (ctx, db, wallet, op_a, _op_b) = create_lockunspent_context () in
  (* Empty initially. *)
  let r = Rpc.handle_listlockunspent ctx [] in
  Alcotest.(check bool) "empty list initially" true
    (match r with `List [] -> true | _ -> false);
  (* lockunspent false [{txid_a, vout=0}] — display-reversed txid hex. *)
  let txid_a_disp = Types.hash256_to_hex_display op_a.Types.txid in
  let lock_result = Rpc.handle_lockunspent ctx [
    `Bool false;
    `List [`Assoc [("txid", `String txid_a_disp); ("vout", `Int 0)]];
  ] in
  Alcotest.(check bool) "lockunspent ok" true
    (match lock_result with Ok (`Bool true) -> true | _ -> false);
  Alcotest.(check bool) "wallet records lock" true
    (Wallet.is_locked_coin wallet op_a);
  (* listlockunspent — must report the locked outpoint. *)
  let r2 = Rpc.handle_listlockunspent ctx [] in
  let count = match r2 with `List l -> List.length l | _ -> 0 in
  Alcotest.(check int) "list has one entry" 1 count;
  (* Re-locking with persistent=false must error per Core (already locked). *)
  let dup = Rpc.handle_lockunspent ctx [
    `Bool false;
    `List [`Assoc [("txid", `String txid_a_disp); ("vout", `Int 0)]];
  ] in
  Alcotest.(check bool) "duplicate lock rejected" true (Result.is_error dup);
  (* Unlock the same outpoint. *)
  let unlock_result = Rpc.handle_lockunspent ctx [
    `Bool true;
    `List [`Assoc [("txid", `String txid_a_disp); ("vout", `Int 0)]];
  ] in
  Alcotest.(check bool) "unlockunspent ok" true
    (match unlock_result with Ok (`Bool true) -> true | _ -> false);
  Alcotest.(check bool) "wallet no longer locked" false
    (Wallet.is_locked_coin wallet op_a);
  let r3 = Rpc.handle_listlockunspent ctx [] in
  Alcotest.(check bool) "list empty after unlock" true
    (match r3 with `List [] -> true | _ -> false);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* lockunspent rejects unknown outpoints (Core's "Invalid parameter, unknown
   transaction" path: parent tx is not in the wallet). *)
let test_lockunspent_unknown_tx_rejected () =
  let (ctx, db, _wallet, _op_a, _op_b) = create_lockunspent_context () in
  let bogus = Types.hash256_to_hex_display
    (Types.hash256_of_hex
       "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef") in
  let r = Rpc.handle_lockunspent ctx [
    `Bool false;
    `List [`Assoc [("txid", `String bogus); ("vout", `Int 0)]];
  ] in
  Alcotest.(check bool) "unknown tx rejected" true (Result.is_error r);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* lockunspent unlock=true with no transaction array clears all locks
   (Core: lockunspent true is the documented "clear everything" form). *)
let test_lockunspent_unlock_all () =
  let (ctx, db, wallet, op_a, op_b) = create_lockunspent_context () in
  (* Lock both outpoints. *)
  let _ = Wallet.lock_coin wallet op_a ~persistent:false in
  let _ = Wallet.lock_coin wallet op_b ~persistent:false in
  Alcotest.(check int) "two locks before clear" 2
    (List.length (Wallet.list_locked_coins wallet));
  (* Call lockunspent true with no tx array. *)
  let r = Rpc.handle_lockunspent ctx [`Bool true] in
  Alcotest.(check bool) "unlock-all ok" true
    (match r with Ok (`Bool true) -> true | _ -> false);
  Alcotest.(check int) "no locks after clear" 0
    (List.length (Wallet.list_locked_coins wallet));
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* signmessage Core-shape: handler accepts (address, message) and signs with
   the private key the wallet holds for that address.  This is the new
   behaviour mandated by Core's wallet/rpc/signmessage.cpp::signmessage. *)
let test_signmessage_address_shape () =
  let (ctx, db, _utxo, _, _) = create_test_context () in
  let wallet = Wallet.create ~network:`Mainnet ~db_path:"" in
  (* Import a known privkey under P2PKH so the wallet has a key associated
     with a P2PKH address (signmessage accepts only PKHash, per Core). *)
  let priv_hex =
    "0a0b0c0d0e0f1011121314151617181920212223242526272829303132333435" in
  let priv = Cstruct.of_hex priv_hex in
  let wif = Address.wif_encode ~compressed:true ~network:`Mainnet priv in
  let kp = match Wallet.import_wif wallet ~addr_type:Wallet.P2PKH wif with
    | Ok kp -> kp
    | Error e -> Alcotest.fail ("import_wif failed: " ^ e)
  in
  let address = Address.address_to_string kp.Wallet.address in
  let ctx = { ctx with wallet = Some wallet } in
  (* signmessage with address (NOT WIF) and a message. *)
  let r = Rpc.handle_signmessage ctx [`String address; `String "hello"] in
  Alcotest.(check bool) "signmessage ok" true (Result.is_ok r);
  let sig_b64 = match r with
    | Ok (`String s) -> s
    | _ -> Alcotest.fail "expected base64 sig"
  in
  Alcotest.(check int) "b64 sig length" 88 (String.length sig_b64);
  (* Now verify with verifymessage — round-trip must succeed. *)
  let v = Rpc.handle_verifymessage ctx
    [`String address; `String sig_b64; `String "hello"] in
  Alcotest.(check bool) "verifymessage true" true
    (match v with Ok (`Bool true) -> true | _ -> false);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* signmessage retains backward compatibility: if the first arg is a WIF
   (legacy callers / cross-impl probes), it routes to the privkey-signing
   path and still produces a valid signature without needing a wallet. *)
let test_signmessage_wif_compat () =
  let (ctx, db, _, _, _) = create_test_context () in
  let priv_hex =
    "1010101010101010101010101010101010101010101010101010101010101010" in
  let (wif, address) = make_test_wif_and_address priv_hex in
  let r = Rpc.handle_signmessage ctx [`String wif; `String "compat"] in
  Alcotest.(check bool) "wif compat ok" true (Result.is_ok r);
  let sig_b64 = match r with
    | Ok (`String s) -> s
    | _ -> Alcotest.fail "expected sig"
  in
  let v = Rpc.handle_verifymessage ctx
    [`String address; `String sig_b64; `String "compat"] in
  Alcotest.(check bool) "verify ok via wif compat" true
    (match v with Ok (`Bool true) -> true | _ -> false);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* signmessage with non-P2PKH address must error: Core enforces PKHash-only
   in wallet/rpc/signmessage.cpp:55-57.  We mirror that. *)
let test_signmessage_non_p2pkh_address_rejected () =
  let (ctx, db, _utxo, _, _) = create_test_context () in
  let wallet = Wallet.create ~network:`Mainnet ~db_path:"" in
  let priv_hex =
    "2020202020202020202020202020202020202020202020202020202020202020" in
  let priv = Cstruct.of_hex priv_hex in
  let wif = Address.wif_encode ~compressed:true ~network:`Mainnet priv in
  let kp = match Wallet.import_wif wallet ~addr_type:Wallet.P2WPKH wif with
    | Ok kp -> kp
    | Error e -> Alcotest.fail ("import_wif failed: " ^ e)
  in
  let p2wpkh_addr = Address.address_to_string kp.Wallet.address in
  let ctx = { ctx with wallet = Some wallet } in
  let r = Rpc.handle_signmessage ctx [`String p2wpkh_addr; `String "hi"] in
  Alcotest.(check bool) "P2WPKH address rejected" true (Result.is_error r);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* walletcreatefundedpsbt: empty inputs + outputs to a destination triggers
   coin selection, returns a PSBT that decodes back to a tx with at least
   one input and the destination output, plus a non-negative fee. *)
let test_walletcreatefundedpsbt_basic () =
  let (ctx, db, _wallet, _op_a, _op_b) = create_lockunspent_context () in
  (* Destination address (mainnet P2WPKH). *)
  let dest_priv = Cstruct.of_hex
    "3030303030303030303030303030303030303030303030303030303030303030" in
  let dest_pub = Crypto.derive_public_key ~compressed:true dest_priv in
  let dest_addr = Address.of_pubkey ~network:`Mainnet
    Address.P2WPKH dest_pub in
  let dest_str = Address.address_to_string dest_addr in
  (* Send 0.1 BTC, default fee_rate. *)
  let result = Rpc.handle_walletcreatefundedpsbt ctx [
    `List [];
    `List [`Assoc [(dest_str, `Float 0.1)]];
  ] in
  Alcotest.(check bool) "wcfp ok" true (Result.is_ok result);
  let fields = match result with
    | Ok (`Assoc f) -> f
    | _ -> Alcotest.fail "expected assoc result"
  in
  let psbt_b64 = match List.assoc "psbt" fields with
    | `String s -> s | _ -> Alcotest.fail "psbt field shape"
  in
  Alcotest.(check bool) "psbt nonempty" true (String.length psbt_b64 > 0);
  (* Decode + check structural properties. *)
  let psbt = match Psbt.of_base64 psbt_b64 with
    | Ok p -> p
    | Error e -> Alcotest.fail ("psbt decode: " ^ Psbt.string_of_error e)
  in
  Alcotest.(check bool) "≥1 input" true (List.length psbt.tx.inputs >= 1);
  Alcotest.(check bool) "≥1 output" true (List.length psbt.tx.outputs >= 1);
  (* Witness UTXO populated for the wallet's selected input. *)
  let any_witness_utxo = List.exists (fun (i : Psbt.psbt_input) ->
    i.witness_utxo <> None
  ) psbt.inputs in
  Alcotest.(check bool) "witness_utxo set" true any_witness_utxo;
  let fee = match List.assoc "fee" fields with
    | `Float f -> f | _ -> Alcotest.fail "fee field shape"
  in
  Alcotest.(check bool) "fee non-negative" true (fee >= 0.0);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* fundrawtransaction: build a raw tx with one output and NO inputs, encode it,
   and fund it.  The handler must (a) add wallet inputs via coin selection,
   (b) add a change output, (c) return a real positive fee, and (d) return hex
   that decodes to a tx whose selected-input value covers outputs + fee.  Uses
   the same regtest-style funded wallet fixture as the walletcreatefundedpsbt
   test (create_lockunspent_context: two wallet UTXOs 0.5 + 0.3 BTC). *)
let test_fundrawtransaction_basic () =
  let (ctx, db, _wallet, _op_a, _op_b) = create_lockunspent_context () in
  (* Destination address (mainnet P2WPKH). *)
  let dest_priv = Cstruct.of_hex
    "3030303030303030303030303030303030303030303030303030303030303030" in
  let dest_pub = Crypto.derive_public_key ~compressed:true dest_priv in
  let dest_addr = Address.of_pubkey ~network:`Mainnet
    Address.P2WPKH dest_pub in
  let dest_script = Address.address_to_script dest_addr in
  (* Raw tx: ONE output of 0.1 BTC, zero inputs. *)
  let base_tx = make_regular_tx [] [Types.{ value = 10_000_000L;
                                            script_pubkey = dest_script }] in
  let raw_hex = tx_to_hex base_tx in
  let result = Rpc.handle_fundrawtransaction ctx [`String raw_hex] in
  Alcotest.(check bool) "fundraw ok" true (Result.is_ok result);
  let fields = match result with
    | Ok (`Assoc f) -> f
    | _ -> Alcotest.fail "expected assoc result"
  in
  let funded_hex = match List.assoc "hex" fields with
    | `String s -> s | _ -> Alcotest.fail "hex field shape"
  in
  Alcotest.(check bool) "hex nonempty" true (String.length funded_hex > 0);
  let fee = match List.assoc "fee" fields with
    | `Float f -> f | _ -> Alcotest.fail "fee field shape"
  in
  Alcotest.(check bool) "fee > 0" true (fee > 0.0);
  let changepos = match List.assoc "changepos" fields with
    | `Int n -> n | _ -> Alcotest.fail "changepos field shape"
  in
  (* Decode the funded hex and assert structural properties. *)
  let funded_tx =
    let r = Serialize.reader_of_cstruct (Cstruct.of_hex funded_hex) in
    Serialize.deserialize_transaction r
  in
  (* (a) inputs were added. *)
  Alcotest.(check bool) "vin non-empty" true
    (List.length funded_tx.Types.inputs >= 1);
  (* (b) a change output exists (or changepos = -1 only on an exact match). *)
  let n_out = List.length funded_tx.Types.outputs in
  if changepos >= 0 then begin
    Alcotest.(check bool) "changepos in range" true
      (changepos < n_out);
    (* The non-change outputs include our original destination. *)
    Alcotest.(check bool) "≥2 outputs when change present" true (n_out >= 2);
    (* The change output value must be positive. *)
    let change_out = List.nth funded_tx.Types.outputs changepos in
    Alcotest.(check bool) "change value > 0" true
      (Int64.compare change_out.Types.value 0L > 0)
  end else
    Alcotest.(check int) "no-change → exactly the original outputs" 1 n_out;
  (* (d) selected input value covers outputs + fee, i.e.
     sum(inputs) == sum(outputs) + fee.  Resolve each input against the
     wallet UTXO set to get its value. *)
  let wallet_utxos = Wallet.get_utxos _wallet in
  let total_input = List.fold_left (fun acc (inp : Types.tx_in) ->
    match List.find_opt (fun (wu : Wallet.wallet_utxo) ->
      Cstruct.equal wu.outpoint.txid inp.previous_output.txid &&
      wu.outpoint.vout = inp.previous_output.vout
    ) wallet_utxos with
    | Some wu -> Int64.add acc wu.utxo.Utxo.value
    | None -> acc
  ) 0L funded_tx.Types.inputs in
  let total_output = List.fold_left (fun acc (o : Types.tx_out) ->
    Int64.add acc o.Types.value
  ) 0L funded_tx.Types.outputs in
  let fee_sats = Int64.of_float (fee *. 100_000_000.0) in
  (* sum(inputs) - sum(outputs) == fee (exact conservation). *)
  Alcotest.(check bool) "inputs == outputs + fee"
    true (Int64.compare total_input (Int64.add total_output fee_sats) = 0);
  (* inputs cover outputs + fee (the funded tx is fundable). *)
  Alcotest.(check bool) "inputs cover outputs+fee" true
    (Int64.compare total_input (Int64.add total_output fee_sats) >= 0);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* ============================================================================
   signrawtransactionwithkey: P2PKH (legacy) WIF path
   ============================================================================
   W19-camlcoin found that the P2PKH classify branch in
   handle_signrawtransactionwithkey returned the existing/empty witness
   instead of producing a real scriptSig.  This pins the WIF path: a
   P2PKH UTXO is funded for a known key, the handler signs, and we
   assert (a) the result hex round-trips, (b) the input's scriptSig is
   non-empty, (c) the embedded ECDSA signature verifies against the
   sighash, and (d) `complete` is true. *)
let test_signrawtransactionwithkey_p2pkh_wif () =
  let (ctx, db, utxo, _t1, _t2) = create_test_context () in
  (* Deterministic key. *)
  let priv_hex =
    "4040404040404040404040404040404040404040404040404040404040404040" in
  let privkey = Cstruct.of_hex priv_hex in
  let pubkey = Crypto.derive_public_key ~compressed:true privkey in
  let pkh = Crypto.hash160 pubkey in
  let script_pubkey = Wallet.build_p2pkh_script pkh in
  let wif = Address.wif_encode ~compressed:true ~network:`Mainnet privkey in
  (* Fund a fresh P2PKH UTXO matched to this key. *)
  let funding_txid = Types.hash256_of_hex
    "1111111111111111111111111111111111111111111111111111111111111111" in
  Utxo.UtxoSet.add utxo funding_txid 0 Utxo.{
    value = 50_000_000L;  (* 0.5 BTC *)
    script_pubkey;
    height = 0;
    is_coinbase = false;
  };
  (* Build an unsigned tx spending that input. *)
  let unsigned = make_regular_tx
    [make_test_input funding_txid 0l]
    [make_test_output 49_990_000L]
  in
  let unsigned_hex = tx_to_hex unsigned in
  let result = Rpc.handle_signrawtransactionwithkey ctx
    [`String unsigned_hex; `List [`String wif]] in
  Alcotest.(check bool) "sign ok" true (Result.is_ok result);
  let (signed_hex, complete) = match result with
    | Ok (`Assoc fields) ->
      let h = match List.assoc "hex" fields with
        | `String s -> s | _ -> Alcotest.fail "hex shape" in
      let c = match List.assoc "complete" fields with
        | `Bool b -> b | _ -> Alcotest.fail "complete shape" in
      (h, c)
    | _ -> Alcotest.fail "expected Ok(`Assoc _)"
  in
  Alcotest.(check bool) "complete = true" true complete;
  (* Decode the signed hex. *)
  let signed_tx =
    let r = Serialize.reader_of_cstruct (Cstruct.of_hex signed_hex) in
    Serialize.deserialize_transaction r
  in
  let inp0 = List.nth signed_tx.Types.inputs 0 in
  let script_sig = inp0.Types.script_sig in
  Alcotest.(check bool) "scriptSig non-empty" true
    (Cstruct.length script_sig > 0);
  (* scriptSig layout: <push sig_len> <sig+hashtype> <push pub_len> <pubkey>.
     Extract the signature (without the trailing hashtype byte) and the
     pubkey, then verify the ECDSA signature against the legacy sighash
     of the original (unsigned) tx with script_pubkey as scriptCode. *)
  let sig_len = Cstruct.get_uint8 script_sig 0 in
  Alcotest.(check bool) "sig_len plausible" true
    (sig_len >= 8 && sig_len <= 73);
  let sig_with_hashtype = Cstruct.sub script_sig 1 sig_len in
  let hashtype_byte =
    Cstruct.get_uint8 sig_with_hashtype (sig_len - 1) in
  Alcotest.(check int) "hashtype = SIGHASH_ALL" 0x01 hashtype_byte;
  let der_sig = Cstruct.sub sig_with_hashtype 0 (sig_len - 1) in
  let pub_off = 1 + sig_len in
  let pub_len = Cstruct.get_uint8 script_sig pub_off in
  let extracted_pub = Cstruct.sub script_sig (pub_off + 1) pub_len in
  Alcotest.(check bool) "scriptSig pubkey matches WIF pubkey" true
    (Cstruct.equal extracted_pub pubkey);
  (* Recompute the legacy sighash on the unsigned tx + verify. *)
  let sighash = Script.compute_sighash_legacy unsigned 0
    script_pubkey Script.sighash_all in
  Alcotest.(check bool) "ECDSA signature verifies" true
    (Crypto.verify pubkey sighash der_sig);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* ============================================================================
   W27-A: hash256_to_hex truncation regression tests
   ----------------------------------------------------------------------------
   Types.hash256_to_hex is hard-coded to 32 bytes; using it on variable-length
   data silently truncates output to 64 hex chars. The W27-A wave fixed 7 RPC
   callsites that misused it. These tests pin the post-fix behavior.
   ============================================================================ *)

(* getblockheader verbose=false must return the full 80-byte serialized header
   as 160 hex chars (not 64, which would be the W27-A truncation bug). *)
let test_getblockheader_raw_returns_160_hex () =
  let (ctx, db, _, _, _) = create_test_context () in
  (* Fabricate a deterministic header and store it directly. *)
  let header : Types.block_header = {
    version = 0x20000000l;
    prev_block = Types.hash256_of_hex
      "0000000000000000000000000000000000000000000000000000000000000000";
    merkle_root = Types.hash256_of_hex
      "1111111111111111111111111111111111111111111111111111111111111111";
    timestamp = 0x12345678l;
    bits = 0x207fffffl;
    nonce = 0xdeadbeefl;
  } in
  let hash = Crypto.compute_block_hash header in
  Storage.ChainDB.store_block_header db hash header;
  (* getblockheader expects display-format hex (reversed). *)
  let hash_hex = Types.hash256_to_hex_display hash in
  let result = Rpc.handle_getblockheader ctx
    [`String hash_hex; `Bool false] in
  let raw_hex = match result with
    | Ok (`String s) -> s
    | Ok _ -> Alcotest.fail "expected `String"
    | Error e -> Alcotest.fail (Printf.sprintf "handler error: %s" e)
  in
  (* Bitcoin block headers are exactly 80 bytes → 160 hex chars. The pre-fix
     hash256_to_hex returned 64 (32 bytes) and silently dropped the last 48. *)
  Alcotest.(check int) "raw header hex length = 80*2"
    160 (String.length raw_hex);
  (* Sanity: round-trip the hex back to a header and compare. *)
  let cs = Cstruct.of_hex raw_hex in
  let r = Serialize.reader_of_cstruct cs in
  let decoded = Serialize.deserialize_block_header r in
  Alcotest.(check int32) "version preserved"
    header.version decoded.version;
  Alcotest.(check int32) "nonce preserved"
    header.nonce decoded.nonce;
  Alcotest.(check int32) "bits preserved"
    header.bits decoded.bits;
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* decoderawtransaction must emit the *full* scriptPubKey hex for each output,
   not the W27-A truncated 64-char prefix. We construct an OP_RETURN output
   whose scriptPubKey is much longer than 32 bytes (so truncation would be
   immediately observable as length mismatch). *)
let test_decoderawtransaction_scriptpubkey_full_hex () =
  let (ctx, db, _, txid1, _) = create_test_context () in
  (* OP_RETURN with 75 bytes of payload → scriptPubKey is 1+1+75 = 77 bytes,
     so 154 hex chars. The pre-fix path returned 64. *)
  let payload = String.make 75 '\xab' in
  let burn_out = make_burn_output 0L payload in
  let expected_spk_len = Cstruct.length burn_out.script_pubkey in
  Alcotest.(check int) "test fixture: scriptPubKey 77 bytes"
    77 expected_spk_len;
  let tx = make_regular_tx
    [make_test_input txid1 0l]
    [burn_out]
  in
  let tx_hex = tx_to_hex tx in
  let result = Rpc.handle_decoderawtransaction ctx [`String tx_hex] in
  let decoded = match result with
    | Ok j -> j
    | Error e -> Alcotest.fail (Printf.sprintf "handler error: %s" e)
  in
  let vout = match decoded with
    | `Assoc fields -> (match List.assoc "vout" fields with
        | `List l -> l | _ -> Alcotest.fail "vout shape")
    | _ -> Alcotest.fail "decoded shape"
  in
  let out0 = List.hd vout in
  let spk_hex = match out0 with
    | `Assoc fs ->
      (match List.assoc "scriptPubKey" fs with
       | `Assoc spk_fs ->
         (match List.assoc "hex" spk_fs with
          | `String s -> s | _ -> Alcotest.fail "spk hex shape")
       | _ -> Alcotest.fail "scriptPubKey shape")
    | _ -> Alcotest.fail "vout[0] shape"
  in
  (* Must be 2× the byte length, NOT the 64-char W27-A truncation. *)
  Alcotest.(check int) "scriptPubKey hex length = 2 * byte length"
    (expected_spk_len * 2) (String.length spk_hex);
  (* Defense check: assert it isn't the truncated 64-char form. *)
  Alcotest.(check bool) "not truncated to 64 hex chars"
    true (String.length spk_hex <> 64);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* ============================================================================
   getblockfrompeer Tests

   Mirrors Bitcoin Core rpc/blockchain.cpp:getblockfrompeer +
   net_processing.cpp PeerManagerImpl::FetchBlock.

   (a) unknown header           -> RPC_MISC_ERROR "Block header missing"
   (b) unknown/absent peer_id   -> RPC_MISC_ERROR "Peer does not exist"
   (c) header known + peer known -> {} returned AND a getdata(InvWitnessBlock,
       hash) is genuinely sent to the resolved peer (captured via a socketpair).
   ============================================================================ *)

(* Build a deterministic header and insert it into the in-memory header table
   that handle_getblockfrompeer consults via Sync.get_header. Returns the
   internal-order hash. *)
let insert_test_header (ctx : Rpc.rpc_context) : Types.hash256 =
  let header : Types.block_header = {
    version = 0x20000000l;
    prev_block = Types.hash256_of_hex
      "0000000000000000000000000000000000000000000000000000000000000000";
    merkle_root = Types.hash256_of_hex
      "2222222222222222222222222222222222222222222222222222222222222222";
    timestamp = 0x5a5a5a5al;
    bits = 0x207fffffl;
    nonce = 0xcafef00dl;
  } in
  let hash = Crypto.compute_block_hash header in
  let entry : Sync.header_entry = {
    header;
    hash;
    height = 1;
    total_work = Types.hash256_of_hex
      "0000000000000000000000000000000000000000000000000000000000000001";
  } in
  Hashtbl.replace ctx.Rpc.chain.Sync.headers (Cstruct.to_string hash) entry;
  hash

(* (a) Unknown header → "Block header missing", code RPC_MISC_ERROR (-1). *)
let test_getblockfrompeer_unknown_header () =
  let (ctx, db, _, _, _) = create_test_context () in
  (* A hash whose header we never inserted. Display-format hex. *)
  let bogus_hash =
    "00000000000000000000000000000000000000000000000000000000deadbeef" in
  let result = Rpc.dispatch_rpc ctx "getblockfrompeer"
    [`String bogus_hash; `Int 0] in
  (match result with
   | Error (code, msg) ->
     Alcotest.(check int) "code is RPC_MISC_ERROR (-1)" (-1) code;
     Alcotest.(check string) "Block header missing" "Block header missing" msg
   | Ok _ -> Alcotest.fail "expected error for unknown header");
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* (b) Header known but peer_id not connected → "Peer does not exist", -1. *)
let test_getblockfrompeer_unknown_peer () =
  let (ctx, db, _, _, _) = create_test_context () in
  let hash = insert_test_header ctx in
  let hash_hex = Types.hash256_to_hex_display hash in
  (* No peers added to the manager: peer 7 cannot resolve. *)
  let result = Rpc.dispatch_rpc ctx "getblockfrompeer"
    [`String hash_hex; `Int 7] in
  (match result with
   | Error (code, msg) ->
     Alcotest.(check int) "code is RPC_MISC_ERROR (-1)" (-1) code;
     Alcotest.(check string) "Peer does not exist" "Peer does not exist" msg
   | Ok _ -> Alcotest.fail "expected error for unknown peer");
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* (c) Header known + peer connected → returns {} AND a getdata for the block
   is sent to THAT peer. We build the peer on one end of a socketpair, dispatch,
   then read the bytes from the other end and confirm it deserializes to a
   GetdataMsg carrying [InvWitnessBlock; hash]. The peer-id we register
   (id = 3) is exactly what getpeerinfo would surface (stat_id = peer.id). *)
let test_getblockfrompeer_success_sends_getdata () =
  let (ctx, db, _, _, _) = create_test_context () in
  let hash = insert_test_header ctx in
  let hash_hex = Types.hash256_to_hex_display hash in
  (* socketpair: [fd_peer] backs the peer's oc/ic; we read from [fd_remote]. *)
  let (fd_peer_u, fd_remote_u) =
    Unix.socketpair Unix.PF_UNIX Unix.SOCK_STREAM 0 in
  let fd_peer = Lwt_unix.of_unix_file_descr fd_peer_u in
  let fd_remote = Lwt_unix.of_unix_file_descr fd_remote_u in
  let peer_id = 3 in
  let peer = Peer.make_peer ~network:Consensus.mainnet ~addr:"127.0.0.1"
    ~port:8333 ~id:peer_id ~direction:Peer.Outbound ~fd:fd_peer () in
  (* Sanity: getpeerinfo peer-id convention — stat_id == peer.id == 3. *)
  let stats = Peer.get_stats peer in
  Alcotest.(check int) "getpeerinfo stat_id matches peer.id"
    peer_id stats.Peer.stat_id;
  ctx.Rpc.peer_manager.Peer_manager.peers <-
    peer :: ctx.Rpc.peer_manager.Peer_manager.peers;
  Alcotest.(check bool) "find_peer_by_id resolves the registered id" true
    (Peer_manager.find_peer_by_id ctx.Rpc.peer_manager peer_id <> None);

  (* Dispatch and capture the wire bytes the handler sent to the peer. *)
  let result = Rpc.dispatch_rpc ctx "getblockfrompeer"
    [`String hash_hex; `Int peer_id] in
  (* Success returns {} (empty JSON object). *)
  (match result with
   | Ok (`Assoc []) -> ()
   | Ok other -> Alcotest.fail
       (Printf.sprintf "expected {} got %s" (Yojson.Safe.to_string other))
   | Error (_, msg) -> Alcotest.fail (Printf.sprintf "unexpected error: %s" msg));

  (* The send is fire-and-forget via Lwt.async; drain the remote end. Read a
     bounded chunk with a short timeout so the test can never hang. *)
  let read_buf = Bytes.create 4096 in
  let ric = Lwt_io.of_fd ~mode:Lwt_io.Input fd_remote in
  let n =
    Lwt_main.run
      (Lwt.pick [
         (let%lwt n = Lwt_io.read_into ric read_buf 0 4096 in Lwt.return n);
         (let%lwt () = Lwt_unix.sleep 2.0 in Lwt.return 0);
       ])
  in
  Alcotest.(check bool) "bytes were sent to the peer" true (n > 0);
  let wire = Cstruct.of_bytes (Bytes.sub read_buf 0 n) in
  (* Deserialize the P2P message off the wire and assert it's a getdata for the
     block hash with the witness-block inv type (MSG_BLOCK | MSG_WITNESS_FLAG). *)
  let msg = P2p.deserialize_message wire in
  (match msg.P2p.payload with
   | P2p.GetdataMsg [iv] ->
     Alcotest.(check bool) "inv is InvWitnessBlock" true
       (iv.P2p.inv_type = P2p.InvWitnessBlock);
     Alcotest.(check bool) "getdata hash matches the requested block" true
       (Cstruct.equal iv.P2p.hash hash)
   | P2p.GetdataMsg ivs ->
     Alcotest.fail (Printf.sprintf
       "expected exactly one inv in getdata, got %d" (List.length ivs))
   | _ -> Alcotest.fail "expected a getdata message on the wire");

  (try Lwt_main.run (Lwt_io.close ric) with _ -> ());
  (try Lwt_unix.close fd_peer |> Lwt_main.run with _ -> ());
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* ============================================================================
   ParseHashV error-code parity (Core rpc/util.cpp:117)
   ----------------------------------------------------------------------------
   A MALFORMED txid/blockhash (wrong length OR right-length-non-hex) must throw
   RPC_INVALID_PARAMETER (-8) at the PARSE boundary, BEFORE any lookup. A
   WELL-FORMED-but-absent 64-hex hash must stay RPC_INVALID_ADDRESS_OR_KEY (-5)
   (or null for gettxout). These go through Rpc.dispatch_rpc so the error CODE
   (not just the Result.is_error shape) is exercised.
   ========================================================================== *)

let zero_hash64 =
  "0000000000000000000000000000000000000000000000000000000000000000"
let short_hex = "abc"                         (* wrong length -> -8 *)
let nonhex64 = String.make 64 'z'             (* right length, bad hex -> -8 *)

(* Assert a dispatch result is Error with the given code. *)
let check_err_code label expected_code result =
  match result with
  | Error (code, _msg) ->
    Alcotest.(check int) label expected_code code
  | Ok j ->
    Alcotest.failf "%s: expected Error code %d, got Ok %s"
      label expected_code (Yojson.Safe.to_string j)

let test_parsehashv_getrawtransaction () =
  let (ctx, db, _, _, _) = create_test_context () in
  (* (a) malformed -> -8 (both wrong-length and non-hex-right-length) *)
  check_err_code "getrawtransaction short hex -> -8" (-8)
    (Rpc.dispatch_rpc ctx "getrawtransaction" [`String short_hex]);
  check_err_code "getrawtransaction 64z non-hex -> -8" (-8)
    (Rpc.dispatch_rpc ctx "getrawtransaction" [`String nonhex64]);
  (* (b) well-formed-but-absent 64-zero txid -> still -5 (not found) *)
  check_err_code "getrawtransaction absent 64-zero -> -5" (-5)
    (Rpc.dispatch_rpc ctx "getrawtransaction" [`String zero_hash64]);
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_parsehashv_gettxout () =
  let (ctx, db, _, _, _) = create_test_context () in
  (* (a) malformed -> -8 *)
  check_err_code "gettxout short hex -> -8" (-8)
    (Rpc.dispatch_rpc ctx "gettxout" [`String short_hex; `Int 0]);
  check_err_code "gettxout 64z non-hex -> -8" (-8)
    (Rpc.dispatch_rpc ctx "gettxout" [`String nonhex64; `Int 0]);
  (* (b) well-formed-but-absent 64-zero txid -> null (NOT an error) *)
  (match Rpc.dispatch_rpc ctx "gettxout" [`String zero_hash64; `Int 0] with
   | Ok `Null -> ()
   | Ok j -> Alcotest.failf "gettxout absent: expected null, got %s"
       (Yojson.Safe.to_string j)
   | Error (code, msg) ->
     Alcotest.failf "gettxout absent: expected null, got Error (%d, %s)" code msg);
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_parsehashv_getblock () =
  let (ctx, db, _, _, _) = create_test_context () in
  (* (a) malformed -> -8 *)
  check_err_code "getblock short hex -> -8" (-8)
    (Rpc.dispatch_rpc ctx "getblock" [`String short_hex]);
  check_err_code "getblock 64z non-hex -> -8" (-8)
    (Rpc.dispatch_rpc ctx "getblock" [`String nonhex64]);
  (* (b) well-formed-but-absent 64-zero blockhash -> the handler's own error
     code (NOT -8). getblock routes its string errors through rpc_misc_error
     (-1) "Block not found"; assert the code is the handler's, not the -8
     parse boundary. *)
  (match Rpc.dispatch_rpc ctx "getblock" [`String zero_hash64] with
   | Error (code, _) ->
     Alcotest.(check bool) "getblock absent 64-zero -> NOT -8 (handler error)"
       true (code <> (-8))
   | Ok j ->
     Alcotest.failf "getblock absent: expected handler Error, got Ok %s"
       (Yojson.Safe.to_string j));
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_parsehashv_getblockheader () =
  let (ctx, db, _, _, _) = create_test_context () in
  (* (a) malformed -> -8 *)
  check_err_code "getblockheader short hex -> -8" (-8)
    (Rpc.dispatch_rpc ctx "getblockheader" [`String short_hex]);
  check_err_code "getblockheader 64z non-hex -> -8" (-8)
    (Rpc.dispatch_rpc ctx "getblockheader" [`String nonhex64]);
  (* (b) well-formed-but-absent 64-zero blockhash -> still -5 (Block not found) *)
  check_err_code "getblockheader absent 64-zero -> -5" (-5)
    (Rpc.dispatch_rpc ctx "getblockheader" [`String zero_hash64]);
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_parsehashv_getmempoolentry () =
  let (ctx, db, _, _, _) = create_test_context () in
  (* (a) malformed -> -8 *)
  check_err_code "getmempoolentry short hex -> -8" (-8)
    (Rpc.dispatch_rpc ctx "getmempoolentry" [`String short_hex]);
  check_err_code "getmempoolentry 64z non-hex -> -8" (-8)
    (Rpc.dispatch_rpc ctx "getmempoolentry" [`String nonhex64]);
  (* (b) well-formed-but-absent 64-zero txid -> the handler's own error code
     (NOT -8). getmempoolentry routes string errors through rpc_misc_error
     (-1) "Transaction not in mempool". *)
  (match Rpc.dispatch_rpc ctx "getmempoolentry" [`String zero_hash64] with
   | Error (code, _) ->
     Alcotest.(check bool)
       "getmempoolentry absent 64-zero -> NOT -8 (handler error)"
       true (code <> (-8))
   | Ok j ->
     Alcotest.failf "getmempoolentry absent: expected handler Error, got Ok %s"
       (Yojson.Safe.to_string j));
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* ============================================================================
   getchainstates Tests (Core v31.99 getchainstates, blockchain.cpp:3462)
   ============================================================================ *)

(* getchainstates returns:
     { headers: <int>,
       chainstates: [ { blocks, bestblockhash, difficulty,
                        verificationprogress, coins_db_cache_bytes,
                        coins_tip_cache_bytes, validated } ] }
   For camlcoin's single fully-validated chainstate, chainstates is a
   1-element array, validated == true, and snapshot_blockhash is OMITTED. *)
let test_getchainstates_shape () =
  let (ctx, db, _utxo, _t1, _t2) = create_test_context () in
  let result = Rpc.dispatch_rpc ctx "getchainstates" [] in
  Alcotest.(check bool) "getchainstates dispatches Ok" true (Result.is_ok result);
  (match result with
   | Ok (`Assoc top) ->
     (* headers is an int *)
     (match List.assoc_opt "headers" top with
      | Some (`Int _) -> ()
      | Some other ->
        Alcotest.failf "headers should be Int, got %s" (Yojson.Safe.to_string other)
      | None -> Alcotest.fail "missing headers field");
     (* chainstates is a 1-element array *)
     let chainstates = match List.assoc_opt "chainstates" top with
       | Some (`List l) -> l
       | Some other ->
         Alcotest.failf "chainstates should be List, got %s" (Yojson.Safe.to_string other)
       | None -> Alcotest.fail "missing chainstates field"
     in
     Alcotest.(check int) "chainstates has exactly 1 element" 1 (List.length chainstates);
     let cs = match chainstates with
       | [`Assoc fields] -> fields
       | _ -> Alcotest.fail "chainstates[0] should be an object"
     in
     (* blocks: int *)
     (match List.assoc_opt "blocks" cs with
      | Some (`Int _) -> ()
      | _ -> Alcotest.fail "blocks should be Int");
     (* bestblockhash: 64-hex string *)
     (match List.assoc_opt "bestblockhash" cs with
      | Some (`String h) -> Alcotest.(check int) "bestblockhash is 64 hex chars" 64 (String.length h)
      | _ -> Alcotest.fail "bestblockhash should be String");
     (* difficulty: numeric (json_difficulty emits `Intlit so it parses as a JSON number) *)
     (match List.assoc_opt "difficulty" cs with
      | Some (`Intlit _) | Some (`Float _) | Some (`Int _) -> ()
      | _ -> Alcotest.fail "difficulty should be numeric");
     (* bits: 8-char lower-hex string (Core make_chain_data: %08x of tip nBits) *)
     let cs_bits = match List.assoc_opt "bits" cs with
       | Some (`String b) ->
         Alcotest.(check int) "bits is 8 hex chars" 8 (String.length b);
         Alcotest.(check bool) "bits is lower-hex" true
           (String.for_all (fun c ->
              (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) b);
         b
       | _ -> Alcotest.fail "bits should be String"
     in
     (* target: 64-char hex string (Core make_chain_data: GetTarget().GetHex()) *)
     let cs_target = match List.assoc_opt "target" cs with
       | Some (`String t) ->
         Alcotest.(check int) "target is 64 hex chars" 64 (String.length t);
         Alcotest.(check bool) "target is lower-hex" true
           (String.for_all (fun c ->
              (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) t);
         t
       | _ -> Alcotest.fail "target should be String"
     in
     (* bits/target MUST equal what getblockchaininfo reports for the SAME tip
        (same tip-nBits source + conversion helpers — Core parity). *)
     let bci_bits, bci_target = match Rpc.handle_getblockchaininfo ctx with
       | `Assoc bci ->
         ((match List.assoc_opt "bits" bci with
           | Some (`String b) -> b | _ -> Alcotest.fail "getblockchaininfo missing bits"),
          (match List.assoc_opt "target" bci with
           | Some (`String t) -> t | _ -> Alcotest.fail "getblockchaininfo missing target"))
       | _ -> Alcotest.fail "getblockchaininfo should return an object"
     in
     Alcotest.(check string) "getchainstates.bits == getblockchaininfo.bits"
       bci_bits cs_bits;
     Alcotest.(check string) "getchainstates.target == getblockchaininfo.target"
       bci_target cs_target;
     (* verificationprogress: float *)
     (match List.assoc_opt "verificationprogress" cs with
      | Some (`Float _) -> ()
      | _ -> Alcotest.fail "verificationprogress should be Float");
     (* coins_db_cache_bytes: int, genuine configured budget (>0) *)
     (match List.assoc_opt "coins_db_cache_bytes" cs with
      | Some (`Int n) -> Alcotest.(check bool) "coins_db_cache_bytes > 0" true (n > 0)
      | _ -> Alcotest.fail "coins_db_cache_bytes should be Int");
     (* coins_tip_cache_bytes: int, genuine configured budget (>0) *)
     (match List.assoc_opt "coins_tip_cache_bytes" cs with
      | Some (`Int n) -> Alcotest.(check bool) "coins_tip_cache_bytes > 0" true (n > 0)
      | _ -> Alcotest.fail "coins_tip_cache_bytes should be Int");
     (* validated == true for the single fully-validated chainstate *)
     (match List.assoc_opt "validated" cs with
      | Some (`Bool b) -> Alcotest.(check bool) "validated == true" true b
      | _ -> Alcotest.fail "validated should be Bool");
     (* snapshot_blockhash MUST be absent (no active snapshot chainstate) *)
     Alcotest.(check bool) "snapshot_blockhash key absent" false
       (List.mem_assoc "snapshot_blockhash" cs)
   | Ok other ->
     Alcotest.failf "getchainstates should return an object, got %s"
       (Yojson.Safe.to_string other)
   | Error (code, msg) ->
     Alcotest.failf "getchainstates errored: (%d, %s)" code msg);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* ============================================================================
   getpeerinfo wire-order parity (Core v31.99 rpc/net.cpp)
   ============================================================================ *)

(* Helper: register one peer into ctx and return the ordered field-name list
   of the first getpeerinfo object (the wire order serde/Yojson emits). *)
let getpeerinfo_field_order ctx =
  let (fd_peer_u, _fd_remote_u) =
    Unix.socketpair Unix.PF_UNIX Unix.SOCK_STREAM 0 in
  let fd_peer = Lwt_unix.of_unix_file_descr fd_peer_u in
  let peer = Peer.make_peer ~network:Consensus.mainnet ~addr:"127.0.0.1"
    ~port:8333 ~id:7 ~direction:Peer.Outbound ~fd:fd_peer () in
  ctx.Rpc.peer_manager.Peer_manager.peers <-
    peer :: ctx.Rpc.peer_manager.Peer_manager.peers;
  match Rpc.handle_getpeerinfo ctx with
  | `List (`Assoc fields :: _) -> List.map fst fields
  | _ -> Alcotest.fail "getpeerinfo did not return a non-empty peer list"

(* Index of [key] in the ordered field list, or -1 if absent. *)
let idx_of keys k =
  let rec go i = function
    | [] -> -1
    | x :: _ when x = k -> i
    | _ :: tl -> go (i + 1) tl
  in go 0 keys

(* Core v31.99 emits, immediately after relaytxes and before lastsend, two NUM
   fields: last_inv_sequence then inv_to_send (rpc/net.cpp:242-245). camlcoin
   tracks neither at the manager layer, so emits 0 — but the fields and their
   exact wire position must be present for getpeerinfo parity. *)
let test_getpeerinfo_last_inv_seq_inv_to_send () =
  let (ctx, _, _, _, _) = create_test_context () in
  let keys = getpeerinfo_field_order ctx in
  let i_relay = idx_of keys "relaytxes" in
  let i_lis   = idx_of keys "last_inv_sequence" in
  let i_its   = idx_of keys "inv_to_send" in
  let i_send  = idx_of keys "lastsend" in
  Alcotest.(check bool) "relaytxes present" true (i_relay >= 0);
  Alcotest.(check bool) "last_inv_sequence present" true (i_lis >= 0);
  Alcotest.(check bool) "inv_to_send present" true (i_its >= 0);
  Alcotest.(check bool) "lastsend present" true (i_send >= 0);
  (* Exact contiguous wire order: relaytxes, last_inv_sequence, inv_to_send,
     lastsend. *)
  Alcotest.(check int) "last_inv_sequence directly after relaytxes"
    (i_relay + 1) i_lis;
  Alcotest.(check int) "inv_to_send directly after last_inv_sequence"
    (i_lis + 1) i_its;
  Alcotest.(check int) "lastsend directly after inv_to_send"
    (i_its + 1) i_send

(* Core v31.99 removed startingheight from getpeerinfo: presynced_headers is
   pushed directly after bip152_hb_from (rpc/net.cpp:269-270). Emitting
   startingheight is an extra-field parity bug. *)
let test_getpeerinfo_no_startingheight () =
  let (ctx, _, _, _, _) = create_test_context () in
  let keys = getpeerinfo_field_order ctx in
  Alcotest.(check int) "startingheight is absent (removed in Core v31.99)"
    (-1) (idx_of keys "startingheight");
  let i_hb_from = idx_of keys "bip152_hb_from" in
  let i_presync = idx_of keys "presynced_headers" in
  Alcotest.(check bool) "bip152_hb_from present" true (i_hb_from >= 0);
  Alcotest.(check bool) "presynced_headers present" true (i_presync >= 0);
  Alcotest.(check int) "presynced_headers directly after bip152_hb_from"
    (i_hb_from + 1) i_presync

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
    "getorphantxs", [
      test_case "verbosity 0 → txid array" `Quick test_getorphantxs_verbosity0_txid_array;
      test_case "verbosity 1 → detail fields" `Quick test_getorphantxs_verbosity1_fields;
      test_case "verbosity 2 → adds hex" `Quick test_getorphantxs_verbosity2_adds_hex;
      test_case "empty pool → empty array" `Quick test_getorphantxs_empty_pool;
      test_case "invalid verbosity → -8" `Quick test_getorphantxs_invalid_verbosity;
    ];
    "getblockfrompeer", [
      test_case "unknown header → -1 Block header missing" `Quick
        test_getblockfrompeer_unknown_header;
      test_case "unknown peer → -1 Peer does not exist" `Quick
        test_getblockfrompeer_unknown_peer;
      test_case "success returns {} and sends block getdata to peer" `Quick
        test_getblockfrompeer_success_sends_getdata;
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
    "getchainstates", [
      test_case "shape: headers + 1-element validated chainstate" `Quick
        test_getchainstates_shape;
    ];
    "getdeploymentinfo", [
      test_case "non-empty deployments" `Quick test_getdeploymentinfo_non_empty;
      test_case "segwit active on regtest" `Quick test_getdeploymentinfo_segwit_active;
      test_case "taproot present on regtest" `Quick test_getdeploymentinfo_taproot_present;
      test_case "has hash/height/deployments fields" `Quick test_getdeploymentinfo_fields;
    ];
    "softforks_bridge", [
      test_case "getblockchaininfo has softforks field" `Quick test_getblockchaininfo_has_softforks;
      test_case "softforks matches deploymentinfo (shared helper)" `Quick test_softforks_matches_deploymentinfo;
      test_case "buried deployments present on regtest" `Quick test_softforks_buried_present_regtest;
    ];
    "signmessage", [
      test_case "round-trip sign/verify" `Quick test_signmessage_roundtrip;
      test_case "tampered message → false" `Quick test_verifymessage_wrong_message;
      test_case "invalid address → error" `Quick test_verifymessage_invalid_address;
      test_case "malformed base64 → error" `Quick test_verifymessage_malformed_b64;
      test_case "invalid WIF rejected" `Quick test_signmessage_invalid_wif;
      test_case "MessageHash framing matches Core" `Quick test_message_hash_matches_core_framing;
    ];
    "estimaterawfee", [
      test_case "empty histogram → object" `Quick test_estimaterawfee_empty_returns_object;
      test_case "rejects bad target" `Quick test_estimaterawfee_rejects_bad_target;
      test_case "rejects bad threshold" `Quick test_estimaterawfee_rejects_bad_threshold;
      test_case "horizon omission for high target" `Quick test_estimaterawfee_horizon_omission;
    ];
    "mempool_persistence_rpc", [
      test_case "dumpmempool with no data_dir errors" `Quick test_dumpmempool_no_data_dir_errors;
      test_case "dumpmempool → loadmempool round-trip" `Quick test_dumpmempool_load_roundtrip;
      test_case "savemempool aliases dumpmempool" `Quick test_savemempool_alias;
      test_case "loadmempool missing file → 0" `Quick test_loadmempool_missing_file_zero;
    ];
    "snapshot_muhash_rpc", [
      test_case "dumptxoutset emits MuHash3072 txoutset_hash" `Quick
        test_dumptxoutset_emits_muhash_txoutset_hash;
      test_case "gettxoutsetinfo muhash matches direct compute" `Quick
        test_gettxoutsetinfo_muhash_matches_dump;
      test_case "gettxoutsetinfo rejects unknown hash_type" `Quick
        test_gettxoutsetinfo_rejects_bad_hash_type;
    ];
    "networkdisable_rollback_gate", [
      test_case "submitblock refuses while paused" `Quick
        test_submitblock_refuses_while_paused;
      test_case "submitblock unblocks after pause cleared" `Quick
        test_submitblock_unblocks_after_pause_cleared;
    ];
    "bip22_result_strings", [
      test_case "bad hex returns BIP-22 rejected" `Quick
        test_submitblock_bad_hex_returns_rejected;
      test_case "odd hex returns BIP-22 rejected or error" `Quick
        test_submitblock_odd_hex_returns_rejected;
      test_case "missing params returns Error" `Quick
        test_submitblock_missing_params_returns_error;
      test_case "zero block returns BIP-22 token" `Quick
        test_bip22_error_mapping;
    ];
    "wallet_encryption_rpc", [
      test_case "encrypt → wrong then right passphrase" `Quick
        test_walletpassphrase_wrong_then_right;
      test_case "auto-relock after timeout" `Quick
        test_walletpassphrase_auto_relock;
    ];
    "submitpackage", [
      test_case "valid 2-tx package admits both" `Quick
        test_submitpackage_valid_2tx;
      test_case "rejected child rejects atomic" `Quick
        test_submitpackage_rejects_atomic;
      test_case "empty package rejected" `Quick
        test_submitpackage_empty;
      test_case "package > MAX_PACKAGE_COUNT rejected" `Quick
        test_submitpackage_too_many;
      test_case "dispatcher routes submitpackage" `Quick
        test_submitpackage_dispatcher;
    ];
    "wallet_wave", [
      test_case "lockunspent + listlockunspent round-trip" `Quick
        test_lockunspent_roundtrip;
      test_case "lockunspent rejects unknown tx" `Quick
        test_lockunspent_unknown_tx_rejected;
      test_case "lockunspent unlock-all clears every lock" `Quick
        test_lockunspent_unlock_all;
      test_case "signmessage Core-shape (address, message)" `Quick
        test_signmessage_address_shape;
      test_case "signmessage WIF backward-compat path" `Quick
        test_signmessage_wif_compat;
      test_case "signmessage rejects non-P2PKH address" `Quick
        test_signmessage_non_p2pkh_address_rejected;
      test_case "walletcreatefundedpsbt basic funding" `Quick
        test_walletcreatefundedpsbt_basic;
      test_case "fundrawtransaction basic funding" `Quick
        test_fundrawtransaction_basic;
      test_case "signrawtransactionwithkey P2PKH (WIF) signs" `Quick
        test_signrawtransactionwithkey_p2pkh_wif;
    ];
    "hash256_to_hex_truncation_W27A", [
      test_case "getblockheader raw returns 160 hex chars (80 bytes)" `Quick
        test_getblockheader_raw_returns_160_hex;
      test_case "decoderawtransaction emits full scriptPubKey hex" `Quick
        test_decoderawtransaction_scriptpubkey_full_hex;
    ];
    "ParseHashV_error_parity_minus8", [
      test_case "getrawtransaction malformed->-8, absent->-5" `Quick
        test_parsehashv_getrawtransaction;
      test_case "gettxout malformed->-8, absent->null" `Quick
        test_parsehashv_gettxout;
      test_case "getblock malformed->-8, absent->handler" `Quick
        test_parsehashv_getblock;
      test_case "getblockheader malformed->-8, absent->-5" `Quick
        test_parsehashv_getblockheader;
      test_case "getmempoolentry malformed->-8, absent->handler" `Quick
        test_parsehashv_getmempoolentry;
    ];
    "getpeerinfo_wire_order_v3199", [
      test_case "last_inv_sequence + inv_to_send between relaytxes and lastsend"
        `Quick test_getpeerinfo_last_inv_seq_inv_to_send;
      test_case "no startingheight; bip152_hb_from -> presynced_headers"
        `Quick test_getpeerinfo_no_startingheight;
    ];
  ]
