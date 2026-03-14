(* Tests for UTXO set module *)

open Camlcoin

(* Test directory that gets cleaned up *)
let test_db_path = "/tmp/camlcoin_test_utxo_db"

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

(* Helper to create a test transaction output *)
let make_test_output value =
  Types.{
    value;
    script_pubkey = Cstruct.of_string "\x76\xa9\x14test_script_pubkey\x88\xac";
  }

(* Helper to create a test transaction input *)
let make_test_input txid vout =
  Types.{
    previous_output = { txid; vout };
    script_sig = Cstruct.of_string "\x00";
    sequence = 0xFFFFFFFFl;
  }

(* Helper to create a coinbase transaction *)
let make_coinbase_tx height outputs =
  let height_script = Consensus.encode_height_in_coinbase height in
  let script_sig = Cstruct.concat [height_script; Cstruct.of_string "test_coinbase"] in
  Types.{
    version = 1l;
    inputs = [{
      previous_output = { txid = Types.zero_hash; vout = -1l };
      script_sig;
      sequence = 0xFFFFFFFFl;
    }];
    outputs;
    witnesses = [];
    locktime = 0l;
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

(* Helper to make a test block with coinbase *)
let make_test_block height coinbase_value txs =
  let coinbase = make_coinbase_tx height [make_test_output coinbase_value] in
  let all_txs = coinbase :: txs in
  let txids = List.map Crypto.compute_txid all_txs in
  let (merkle_root, _) = Crypto.merkle_root txids in
  Types.{
    header = {
      version = 1l;
      prev_block = Types.zero_hash;
      merkle_root;
      timestamp = Int32.of_int (1231006505 + height * 600);
      bits = 0x207fffffl;  (* easy difficulty *)
      nonce = Int32.of_int height;
    };
    transactions = all_txs;
  }

(* ============================================================================
   UTXO Entry Serialization Tests
   ============================================================================ *)

let test_utxo_entry_serialization () =
  let entry = Utxo.{
    value = 5000000000L;  (* 50 BTC *)
    script_pubkey = Cstruct.of_string "\x76\xa9\x14test_pubkey_hash\x88\xac";
    height = 100;
    is_coinbase = true;
  } in
  let w = Serialize.writer_create () in
  Utxo.serialize_utxo_entry w entry;
  let data = Serialize.writer_to_cstruct w in
  let r = Serialize.reader_of_cstruct data in
  let decoded = Utxo.deserialize_utxo_entry r in
  Alcotest.(check int64) "value" entry.value decoded.value;
  Alcotest.(check int) "height" entry.height decoded.height;
  Alcotest.(check bool) "is_coinbase" entry.is_coinbase decoded.is_coinbase;
  Alcotest.(check bool) "script_pubkey equal"
    true (Cstruct.equal entry.script_pubkey decoded.script_pubkey)

let test_utxo_entry_regular () =
  let entry = Utxo.{
    value = 100000L;  (* 0.001 BTC *)
    script_pubkey = Cstruct.of_string "\x00\x14witness_program";
    height = 500000;
    is_coinbase = false;
  } in
  let w = Serialize.writer_create () in
  Utxo.serialize_utxo_entry w entry;
  let data = Serialize.writer_to_cstruct w in
  let r = Serialize.reader_of_cstruct data in
  let decoded = Utxo.deserialize_utxo_entry r in
  Alcotest.(check int64) "value" entry.value decoded.value;
  Alcotest.(check int) "height" entry.height decoded.height;
  Alcotest.(check bool) "is_coinbase" entry.is_coinbase decoded.is_coinbase

(* ============================================================================
   UTXO Set Basic Operations Tests
   ============================================================================ *)

let test_utxoset_add_get () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let utxo = Utxo.UtxoSet.create db in
  let txid = Types.hash256_of_hex
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b" in
  let entry = Utxo.{
    value = 5000000000L;
    script_pubkey = Cstruct.of_string "\x76\xa9\x14test\x88\xac";
    height = 0;
    is_coinbase = true;
  } in
  (* Add entry *)
  Utxo.UtxoSet.add utxo txid 0 entry;
  (* Get entry *)
  let retrieved = Utxo.UtxoSet.get utxo txid 0 in
  Alcotest.(check bool) "entry found" true (Option.is_some retrieved);
  let got = Option.get retrieved in
  Alcotest.(check int64) "value" entry.value got.value;
  Alcotest.(check int) "height" entry.height got.height;
  (* Check exists *)
  Alcotest.(check bool) "exists" true (Utxo.UtxoSet.exists utxo txid 0);
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_utxoset_remove () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let utxo = Utxo.UtxoSet.create db in
  let txid = Types.hash256_of_hex
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b" in
  let entry = Utxo.{
    value = 5000000000L;
    script_pubkey = Cstruct.of_string "\x76\xa9\x14test\x88\xac";
    height = 0;
    is_coinbase = true;
  } in
  Utxo.UtxoSet.add utxo txid 0 entry;
  (* Remove and verify *)
  let removed = Utxo.UtxoSet.remove utxo txid 0 in
  Alcotest.(check bool) "removed entry found" true (Option.is_some removed);
  Alcotest.(check int64) "removed value" entry.value (Option.get removed).value;
  (* Should no longer exist *)
  Alcotest.(check bool) "no longer exists" false (Utxo.UtxoSet.exists utxo txid 0);
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_utxoset_multiple_outputs () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let utxo = Utxo.UtxoSet.create db in
  let txid = Types.hash256_of_hex
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b" in
  (* Add multiple outputs for same txid *)
  for vout = 0 to 4 do
    let entry = Utxo.{
      value = Int64.of_int (vout * 100000);
      script_pubkey = Cstruct.of_string (Printf.sprintf "script_%d" vout);
      height = 100;
      is_coinbase = false;
    } in
    Utxo.UtxoSet.add utxo txid vout entry
  done;
  (* Verify all outputs *)
  for vout = 0 to 4 do
    let got = Utxo.UtxoSet.get utxo txid vout in
    Alcotest.(check bool) (Printf.sprintf "vout %d exists" vout) true (Option.is_some got);
    Alcotest.(check int64) (Printf.sprintf "vout %d value" vout)
      (Int64.of_int (vout * 100000)) (Option.get got).value
  done;
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_utxoset_cache_stats () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let utxo = Utxo.UtxoSet.create db in
  let txid = Types.hash256_of_hex
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b" in
  let entry = Utxo.{
    value = 100000L;
    script_pubkey = Cstruct.of_string "test";
    height = 0;
    is_coinbase = false;
  } in
  Utxo.UtxoSet.add utxo txid 0 entry;
  (* First get is a cache hit (added to cache during add) *)
  ignore (Utxo.UtxoSet.get utxo txid 0);
  (* Clear cache *)
  Utxo.UtxoSet.clear_cache utxo;
  (* Now get will be a cache miss *)
  ignore (Utxo.UtxoSet.get utxo txid 0);
  let (hits, misses) = Utxo.UtxoSet.cache_stats utxo in
  Alcotest.(check int) "cache hits after clear" 0 hits;
  Alcotest.(check int) "cache misses after clear" 1 misses;
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* ============================================================================
   Undo Data Serialization Tests
   ============================================================================ *)

let test_undo_data_serialization () =
  let txid1 = Types.hash256_of_hex
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b" in
  let txid2 = Types.hash256_of_hex
    "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098" in
  let undo = Utxo.{
    height = 100;
    spent_outputs = [
      ({ Types.txid = txid1; vout = 0l },
       { value = 5000000000L;
         script_pubkey = Cstruct.of_string "script1";
         height = 50;
         is_coinbase = true });
      ({ Types.txid = txid2; vout = 1l },
       { value = 100000L;
         script_pubkey = Cstruct.of_string "script2";
         height = 75;
         is_coinbase = false });
    ];
  } in
  let w = Serialize.writer_create () in
  Utxo.serialize_undo_data w undo;
  let data = Serialize.writer_to_cstruct w in
  let r = Serialize.reader_of_cstruct data in
  let decoded = Utxo.deserialize_undo_data r in
  Alcotest.(check int) "height" undo.height decoded.height;
  Alcotest.(check int) "spent count" 2 (List.length decoded.spent_outputs);
  let (op1, e1) = List.hd decoded.spent_outputs in
  Alcotest.(check int64) "first entry value" 5000000000L e1.value;
  Alcotest.(check bool) "first entry is_coinbase" true e1.is_coinbase;
  Alcotest.(check int32) "first outpoint vout" 0l op1.Types.vout

(* ============================================================================
   Block Connection Tests
   ============================================================================ *)

let test_connect_coinbase_only_block () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let utxo = Utxo.UtxoSet.create db in
  (* Create a block with just coinbase *)
  let subsidy = Consensus.block_subsidy 0 in
  let block = make_test_block 0 subsidy [] in
  let result = Utxo.connect_block utxo block 0 in
  Alcotest.(check bool) "connect succeeded" true (Result.is_ok result);
  (* Verify coinbase output is in UTXO set *)
  let coinbase_txid = Crypto.compute_txid (List.hd block.transactions) in
  let got = Utxo.UtxoSet.get utxo coinbase_txid 0 in
  Alcotest.(check bool) "coinbase output exists" true (Option.is_some got);
  let entry = Option.get got in
  Alcotest.(check int64) "coinbase value" subsidy entry.value;
  Alcotest.(check bool) "is_coinbase flag" true entry.is_coinbase;
  Alcotest.(check int) "height" 0 entry.height;
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_connect_block_with_spend () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let utxo = Utxo.UtxoSet.create db in
  (* Connect block 0 (genesis with coinbase) *)
  let subsidy0 = Consensus.block_subsidy 0 in
  let block0 = make_test_block 0 subsidy0 [] in
  let _result0 = Utxo.connect_block utxo block0 0 in
  let cb0_txid = Crypto.compute_txid (List.hd block0.transactions) in
  (* We need to wait 100 blocks for coinbase maturity, but for this test
     let's just add a non-coinbase UTXO that we can spend immediately *)
  let fake_txid = Types.hash256_of_hex
    "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098" in
  Utxo.UtxoSet.add utxo fake_txid 0 Utxo.{
    value = 1000000L;
    script_pubkey = Cstruct.of_string "test";
    height = 0;
    is_coinbase = false;  (* not coinbase, so no maturity wait *)
  };
  (* Create block 1 that spends the fake UTXO *)
  let spend_tx = make_regular_tx
    [make_test_input fake_txid 0l]
    [make_test_output 900000L]  (* 100000 satoshi fee *)
  in
  let subsidy1 = Consensus.block_subsidy 1 in
  let block1 = make_test_block 1 (Int64.add subsidy1 100000L) [spend_tx] in
  let result1 = Utxo.connect_block utxo block1 1 in
  Alcotest.(check bool) "block 1 connect succeeded" true (Result.is_ok result1);
  (* Verify spent UTXO is removed *)
  Alcotest.(check bool) "spent UTXO removed" false
    (Utxo.UtxoSet.exists utxo fake_txid 0);
  (* Verify new output is created *)
  let spend_txid = Crypto.compute_txid spend_tx in
  Alcotest.(check bool) "new output exists" true
    (Utxo.UtxoSet.exists utxo spend_txid 0);
  (* Check undo data *)
  let undo = Result.get_ok result1 in
  Alcotest.(check int) "undo height" 1 undo.height;
  Alcotest.(check int) "undo spent count" 1 (List.length undo.spent_outputs);
  let _ = cb0_txid in  (* suppress unused warning *)
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_connect_block_coinbase_maturity () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let utxo = Utxo.UtxoSet.create db in
  (* Add a coinbase UTXO at height 0 *)
  let cb_txid = Types.hash256_of_hex
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b" in
  Utxo.UtxoSet.add utxo cb_txid 0 Utxo.{
    value = 5000000000L;
    script_pubkey = Cstruct.of_string "test";
    height = 0;
    is_coinbase = true;
  };
  (* Try to spend at height 99 (should fail - only 99 confirmations) *)
  let spend_tx = make_regular_tx
    [make_test_input cb_txid 0l]
    [make_test_output 4999900000L]
  in
  let subsidy = Consensus.block_subsidy 99 in
  let block99 = make_test_block 99 (Int64.add subsidy 100000L) [spend_tx] in
  let result99 = Utxo.connect_block utxo block99 99 in
  Alcotest.(check bool) "block 99 connect fails (immature)" true (Result.is_error result99);
  (match result99 with
   | Error msg ->
     Alcotest.(check bool) "error mentions maturity" true
       (String.sub msg 0 8 = "Immature")
   | Ok _ -> ());
  (* At height 100, spending should succeed (100 confirmations) *)
  let block100 = make_test_block 100 (Int64.add subsidy 100000L) [spend_tx] in
  let result100 = Utxo.connect_block utxo block100 100 in
  Alcotest.(check bool) "block 100 connect succeeds" true (Result.is_ok result100);
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_connect_block_output_exceeds_input () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let utxo = Utxo.UtxoSet.create db in
  (* Add a small UTXO *)
  let txid = Types.hash256_of_hex
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b" in
  Utxo.UtxoSet.add utxo txid 0 Utxo.{
    value = 100000L;
    script_pubkey = Cstruct.of_string "test";
    height = 0;
    is_coinbase = false;
  };
  (* Try to create output larger than input *)
  let spend_tx = make_regular_tx
    [make_test_input txid 0l]
    [make_test_output 200000L]  (* More than input! *)
  in
  let block = make_test_block 1 (Consensus.block_subsidy 1) [spend_tx] in
  let result = Utxo.connect_block utxo block 1 in
  Alcotest.(check bool) "connect fails (output > input)" true (Result.is_error result);
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_connect_block_missing_utxo () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let utxo = Utxo.UtxoSet.create db in
  (* Try to spend non-existent UTXO *)
  let fake_txid = Types.hash256_of_hex
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b" in
  let spend_tx = make_regular_tx
    [make_test_input fake_txid 0l]
    [make_test_output 100000L]
  in
  let block = make_test_block 1 (Consensus.block_subsidy 1) [spend_tx] in
  let result = Utxo.connect_block utxo block 1 in
  Alcotest.(check bool) "connect fails (missing UTXO)" true (Result.is_error result);
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_connect_block_coinbase_too_large () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let utxo = Utxo.UtxoSet.create db in
  (* Create block with coinbase claiming more than subsidy + fees *)
  let subsidy = Consensus.block_subsidy 0 in
  let block = make_test_block 0 (Int64.add subsidy 1L) [] in  (* 1 satoshi too much *)
  let result = Utxo.connect_block utxo block 0 in
  Alcotest.(check bool) "connect fails (coinbase too large)" true (Result.is_error result);
  (match result with
   | Error msg ->
     Alcotest.(check bool) "error mentions coinbase" true
       (String.sub msg 0 8 = "Coinbase")
   | Ok _ -> ());
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* ============================================================================
   Block Disconnection Tests
   ============================================================================ *)

let test_disconnect_block () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let utxo = Utxo.UtxoSet.create db in
  (* Add a spendable UTXO *)
  let input_txid = Types.hash256_of_hex
    "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098" in
  let original_entry = Utxo.{
    value = 1000000L;
    script_pubkey = Cstruct.of_string "original_script";
    height = 0;
    is_coinbase = false;
  } in
  Utxo.UtxoSet.add utxo input_txid 0 original_entry;
  (* Connect a block that spends it *)
  let spend_tx = make_regular_tx
    [make_test_input input_txid 0l]
    [make_test_output 900000L]
  in
  let subsidy = Consensus.block_subsidy 1 in
  let block = make_test_block 1 (Int64.add subsidy 100000L) [spend_tx] in
  let undo = Result.get_ok (Utxo.connect_block utxo block 1) in
  let spend_txid = Crypto.compute_txid spend_tx in
  let cb_txid = Crypto.compute_txid (List.hd block.transactions) in
  (* Verify state after connection *)
  Alcotest.(check bool) "original spent" false (Utxo.UtxoSet.exists utxo input_txid 0);
  Alcotest.(check bool) "new output exists" true (Utxo.UtxoSet.exists utxo spend_txid 0);
  Alcotest.(check bool) "coinbase exists" true (Utxo.UtxoSet.exists utxo cb_txid 0);
  (* Disconnect the block *)
  Utxo.disconnect_block utxo block undo;
  (* Verify state after disconnection *)
  Alcotest.(check bool) "original restored" true (Utxo.UtxoSet.exists utxo input_txid 0);
  Alcotest.(check bool) "new output removed" false (Utxo.UtxoSet.exists utxo spend_txid 0);
  Alcotest.(check bool) "coinbase removed" false (Utxo.UtxoSet.exists utxo cb_txid 0);
  (* Verify restored entry has correct values *)
  let restored = Option.get (Utxo.UtxoSet.get utxo input_txid 0) in
  Alcotest.(check int64) "restored value" original_entry.value restored.value;
  Alcotest.(check bool) "restored script" true
    (Cstruct.equal original_entry.script_pubkey restored.script_pubkey);
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_connect_disconnect_multiple () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let utxo = Utxo.UtxoSet.create db in
  (* Connect 3 blocks in sequence *)
  let block0 = make_test_block 0 (Consensus.block_subsidy 0) [] in
  let undo0 = Result.get_ok (Utxo.connect_block utxo block0 0) in
  let block1 = make_test_block 1 (Consensus.block_subsidy 1) [] in
  let undo1 = Result.get_ok (Utxo.connect_block utxo block1 1) in
  let block2 = make_test_block 2 (Consensus.block_subsidy 2) [] in
  let undo2 = Result.get_ok (Utxo.connect_block utxo block2 2) in
  let cb0 = Crypto.compute_txid (List.hd block0.transactions) in
  let cb1 = Crypto.compute_txid (List.hd block1.transactions) in
  let cb2 = Crypto.compute_txid (List.hd block2.transactions) in
  (* All 3 coinbase outputs should exist *)
  Alcotest.(check bool) "cb0 exists" true (Utxo.UtxoSet.exists utxo cb0 0);
  Alcotest.(check bool) "cb1 exists" true (Utxo.UtxoSet.exists utxo cb1 0);
  Alcotest.(check bool) "cb2 exists" true (Utxo.UtxoSet.exists utxo cb2 0);
  (* Disconnect in reverse order *)
  Utxo.disconnect_block utxo block2 undo2;
  Alcotest.(check bool) "cb2 removed" false (Utxo.UtxoSet.exists utxo cb2 0);
  Alcotest.(check bool) "cb1 still exists" true (Utxo.UtxoSet.exists utxo cb1 0);
  Utxo.disconnect_block utxo block1 undo1;
  Alcotest.(check bool) "cb1 removed" false (Utxo.UtxoSet.exists utxo cb1 0);
  Alcotest.(check bool) "cb0 still exists" true (Utxo.UtxoSet.exists utxo cb0 0);
  Utxo.disconnect_block utxo block0 undo0;
  Alcotest.(check bool) "cb0 removed" false (Utxo.UtxoSet.exists utxo cb0 0);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* ============================================================================
   Undo Data Storage Tests
   ============================================================================ *)

let test_undo_data_storage () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let block_hash = Types.hash256_of_hex
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f" in
  let txid = Types.hash256_of_hex
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b" in
  let undo = Utxo.{
    height = 1;
    spent_outputs = [
      ({ Types.txid; vout = 0l },
       { value = 5000000000L;
         script_pubkey = Cstruct.of_string "test";
         height = 0;
         is_coinbase = true });
    ];
  } in
  (* Serialize and store *)
  let w = Serialize.writer_create () in
  Utxo.serialize_undo_data w undo;
  let undo_bytes = Cstruct.to_string (Serialize.writer_to_cstruct w) in
  Storage.ChainDB.store_undo_data db block_hash undo_bytes;
  (* Retrieve and deserialize *)
  let retrieved = Storage.ChainDB.get_undo_data db block_hash in
  Alcotest.(check bool) "undo data found" true (Option.is_some retrieved);
  let r = Serialize.reader_of_cstruct (Cstruct.of_string (Option.get retrieved)) in
  let decoded = Utxo.deserialize_undo_data r in
  Alcotest.(check int) "undo height" 1 decoded.height;
  Alcotest.(check int) "spent count" 1 (List.length decoded.spent_outputs);
  (* Delete *)
  Storage.ChainDB.delete_undo_data db block_hash;
  let deleted = Storage.ChainDB.get_undo_data db block_hash in
  Alcotest.(check bool) "undo data deleted" true (Option.is_none deleted);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* ============================================================================
   UTXO Statistics Tests
   ============================================================================ *)

let test_utxo_stats () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let utxo = Utxo.UtxoSet.create db in
  (* Add some UTXOs *)
  let txid1 = Types.hash256_of_hex
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b" in
  let txid2 = Types.hash256_of_hex
    "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098" in
  Utxo.UtxoSet.add utxo txid1 0 Utxo.{
    value = 5000000000L;
    script_pubkey = Cstruct.of_string "test1";
    height = 0;
    is_coinbase = true;
  };
  Utxo.UtxoSet.add utxo txid2 0 Utxo.{
    value = 100000L;
    script_pubkey = Cstruct.of_string "test2";
    height = 1;
    is_coinbase = false;
  };
  Utxo.UtxoSet.add utxo txid2 1 Utxo.{
    value = 200000L;
    script_pubkey = Cstruct.of_string "test3";
    height = 1;
    is_coinbase = false;
  };
  let stats = Utxo.compute_stats utxo in
  Alcotest.(check int) "total count" 3 stats.total_count;
  Alcotest.(check int64) "total value" 5000300000L stats.total_value;
  Alcotest.(check int) "coinbase count" 1 stats.coinbase_count;
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* ============================================================================
   Layered UTXO Cache Tests
   ============================================================================ *)

(* Helper to create a coin for testing *)
let make_test_coin value height is_coinbase =
  Utxo.{
    txout = {
      Types.value;
      script_pubkey = Cstruct.of_string "\x76\xa9\x14test_script\x88\xac";
    };
    height;
    is_coinbase;
  }

(* Helper to create an outpoint for testing *)
let make_test_outpoint txid_hex vout =
  Types.{
    txid = Types.hash256_of_hex txid_hex;
    vout = Int32.of_int vout;
  }

let test_utxo_cache_add_get () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let db_view = Utxo.DbView.create db in
  let cache = Utxo.UtxoCache.create db_view in
  let outpoint = make_test_outpoint
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b" 0 in
  let coin = make_test_coin 5000000000L 0 true in
  (* Add coin *)
  Utxo.UtxoCache.add_coin cache outpoint coin ~possible_overwrite:false;
  (* Get coin - should be cache hit *)
  let retrieved = Utxo.UtxoCache.get_coin cache outpoint in
  Alcotest.(check bool) "coin found" true (Option.is_some retrieved);
  let got = Option.get retrieved in
  Alcotest.(check int64) "value matches" coin.txout.value got.txout.value;
  Alcotest.(check int) "height matches" coin.height got.height;
  Alcotest.(check bool) "is_coinbase matches" coin.is_coinbase got.is_coinbase;
  (* Check stats *)
  let stats = Utxo.UtxoCache.get_stats cache in
  Alcotest.(check int) "cache hits" 1 stats.hits;
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_utxo_cache_miss_then_hit () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let db_view = Utxo.DbView.create db in
  let cache = Utxo.UtxoCache.create db_view in
  let outpoint = make_test_outpoint
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b" 0 in
  (* First lookup - should miss (not in cache or db) *)
  let result1 = Utxo.UtxoCache.get_coin cache outpoint in
  Alcotest.(check bool) "first lookup misses" true (Option.is_none result1);
  let stats = Utxo.UtxoCache.get_stats cache in
  Alcotest.(check int) "misses after first lookup" 1 stats.misses;
  (* Add directly to DB via db_view *)
  let coin = make_test_coin 100000L 50 false in
  Utxo.DbView.add_coin db_view outpoint coin ~possible_overwrite:false;
  (* Create fresh cache (simulates restart) *)
  let cache2 = Utxo.UtxoCache.create db_view in
  (* Lookup should hit DB, then cache *)
  let result2 = Utxo.UtxoCache.get_coin cache2 outpoint in
  Alcotest.(check bool) "db lookup succeeds" true (Option.is_some result2);
  let stats2 = Utxo.UtxoCache.get_stats cache2 in
  Alcotest.(check int) "misses (fetched from db)" 1 stats2.misses;
  (* Second lookup should hit cache *)
  let result3 = Utxo.UtxoCache.get_coin cache2 outpoint in
  Alcotest.(check bool) "cache lookup succeeds" true (Option.is_some result3);
  let stats3 = Utxo.UtxoCache.get_stats cache2 in
  Alcotest.(check int) "hits after cache fetch" 1 stats3.hits;
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_utxo_cache_spend () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let db_view = Utxo.DbView.create db in
  let cache = Utxo.UtxoCache.create db_view in
  let outpoint = make_test_outpoint
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b" 0 in
  let coin = make_test_coin 5000000000L 0 true in
  (* Add coin *)
  Utxo.UtxoCache.add_coin cache outpoint coin ~possible_overwrite:false;
  Alcotest.(check bool) "coin exists before spend" true
    (Utxo.UtxoCache.have_coin cache outpoint);
  (* Spend coin *)
  let spent = Utxo.UtxoCache.spend_coin cache outpoint in
  Alcotest.(check bool) "spend returns coin" true (Option.is_some spent);
  Alcotest.(check int64) "spent coin value" coin.txout.value
    (Option.get spent).txout.value;
  (* Coin should no longer exist *)
  Alcotest.(check bool) "coin gone after spend" false
    (Utxo.UtxoCache.have_coin cache outpoint);
  (* Spending again should return None *)
  let spent2 = Utxo.UtxoCache.spend_coin cache outpoint in
  Alcotest.(check bool) "second spend returns none" true (Option.is_none spent2);
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_utxo_cache_flush () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let db_view = Utxo.DbView.create db in
  let cache = Utxo.UtxoCache.create db_view in
  let outpoint1 = make_test_outpoint
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b" 0 in
  let outpoint2 = make_test_outpoint
    "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098" 0 in
  let coin1 = make_test_coin 5000000000L 0 true in
  let coin2 = make_test_coin 100000L 1 false in
  (* Add coins to cache *)
  Utxo.UtxoCache.add_coin cache outpoint1 coin1 ~possible_overwrite:false;
  Utxo.UtxoCache.add_coin cache outpoint2 coin2 ~possible_overwrite:false;
  Alcotest.(check int) "entry count before flush" 2 (Utxo.UtxoCache.entry_count cache);
  (* Flush to disk *)
  let flushed = Lwt_main.run (Utxo.UtxoCache.flush cache) in
  Alcotest.(check int) "flushed count" 2 flushed;
  Alcotest.(check int) "entry count after flush" 0 (Utxo.UtxoCache.entry_count cache);
  (* Create fresh cache and verify coins are in db *)
  let cache2 = Utxo.UtxoCache.create db_view in
  Alcotest.(check bool) "coin1 in db" true (Utxo.UtxoCache.have_coin cache2 outpoint1);
  Alcotest.(check bool) "coin2 in db" true (Utxo.UtxoCache.have_coin cache2 outpoint2);
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_utxo_cache_flush_erased () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let db_view = Utxo.DbView.create db in
  let outpoint = make_test_outpoint
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b" 0 in
  let coin = make_test_coin 5000000000L 0 true in
  (* Add coin directly to DB *)
  Utxo.DbView.add_coin db_view outpoint coin ~possible_overwrite:false;
  (* Create cache, verify coin exists *)
  let cache = Utxo.UtxoCache.create db_view in
  Alcotest.(check bool) "coin exists in db" true (Utxo.UtxoCache.have_coin cache outpoint);
  (* Spend the coin (should mark as Erased since it's from DB) *)
  let _ = Utxo.UtxoCache.spend_coin cache outpoint in
  Alcotest.(check bool) "coin gone after spend" false (Utxo.UtxoCache.have_coin cache outpoint);
  let stats = Utxo.UtxoCache.get_stats cache in
  Alcotest.(check int) "erased count" 1 stats.erased_count;
  (* Flush should propagate deletion to DB *)
  let _ = Lwt_main.run (Utxo.UtxoCache.flush cache) in
  (* Create fresh cache - coin should be gone from DB too *)
  let cache2 = Utxo.UtxoCache.create db_view in
  Alcotest.(check bool) "coin deleted from db" false (Utxo.UtxoCache.have_coin cache2 outpoint);
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_utxo_cache_add_spend_roundtrip () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let db_view = Utxo.DbView.create db in
  let cache = Utxo.UtxoCache.create db_view in
  (* Simulate a transaction: add outputs, spend inputs *)
  let input_outpoint = make_test_outpoint
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b" 0 in
  let output_outpoint1 = make_test_outpoint
    "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098" 0 in
  let output_outpoint2 = make_test_outpoint
    "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098" 1 in
  let input_coin = make_test_coin 5000000000L 0 true in
  let output_coin1 = make_test_coin 2500000000L 1 false in
  let output_coin2 = make_test_coin 2499900000L 1 false in  (* 100000 sat fee *)
  (* Add input UTXO (simulates previous block's output) *)
  Utxo.UtxoCache.add_coin cache input_outpoint input_coin ~possible_overwrite:false;
  (* Process transaction: spend input, add outputs *)
  let spent = Utxo.UtxoCache.spend_coin cache input_outpoint in
  Alcotest.(check bool) "input spent" true (Option.is_some spent);
  Utxo.UtxoCache.add_coin cache output_outpoint1 output_coin1 ~possible_overwrite:false;
  Utxo.UtxoCache.add_coin cache output_outpoint2 output_coin2 ~possible_overwrite:false;
  (* Verify final state *)
  Alcotest.(check bool) "input gone" false (Utxo.UtxoCache.have_coin cache input_outpoint);
  Alcotest.(check bool) "output1 exists" true (Utxo.UtxoCache.have_coin cache output_outpoint1);
  Alcotest.(check bool) "output2 exists" true (Utxo.UtxoCache.have_coin cache output_outpoint2);
  (* Flush and verify persistence *)
  let _ = Lwt_main.run (Utxo.UtxoCache.flush cache) in
  let cache2 = Utxo.UtxoCache.create db_view in
  Alcotest.(check bool) "input still gone" false (Utxo.UtxoCache.have_coin cache2 input_outpoint);
  Alcotest.(check bool) "output1 persisted" true (Utxo.UtxoCache.have_coin cache2 output_outpoint1);
  Alcotest.(check bool) "output2 persisted" true (Utxo.UtxoCache.have_coin cache2 output_outpoint2);
  (* Verify values *)
  let got1 = Option.get (Utxo.UtxoCache.get_coin cache2 output_outpoint1) in
  let got2 = Option.get (Utxo.UtxoCache.get_coin cache2 output_outpoint2) in
  Alcotest.(check int64) "output1 value" output_coin1.txout.value got1.txout.value;
  Alcotest.(check int64) "output2 value" output_coin2.txout.value got2.txout.value;
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_utxo_cache_memory_tracking () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let db_view = Utxo.DbView.create db in
  (* Use small max_size to trigger flush threshold.
     Each coin is ~77 bytes (tag + overhead + value + script + height + bool).
     Use 500 bytes threshold so 10 coins (770 bytes) will exceed it. *)
  let cache = Utxo.UtxoCache.create ~max_size:500 db_view in
  Alcotest.(check int) "initial memory" 0 (Utxo.UtxoCache.memory_usage cache);
  (* Add some coins *)
  for i = 0 to 9 do
    let outpoint = make_test_outpoint
      (Printf.sprintf "%064x" i) 0 in
    let coin = make_test_coin (Int64.of_int (i * 100000)) i false in
    Utxo.UtxoCache.add_coin cache outpoint coin ~possible_overwrite:false
  done;
  let mem = Utxo.UtxoCache.memory_usage cache in
  Alcotest.(check bool) "memory > 0 after adds" true (mem > 0);
  Alcotest.(check bool) "memory > threshold" true (mem > 500);
  (* Check needs_flush with small threshold *)
  Alcotest.(check bool) "needs_flush with small threshold" true
    (Utxo.UtxoCache.needs_flush cache);
  (* maybe_flush should flush when needed *)
  let flushed = Lwt_main.run (Utxo.UtxoCache.maybe_flush cache) in
  Alcotest.(check int) "flushed 10 entries" 10 flushed;
  Alcotest.(check int) "memory reset after flush" 0 (Utxo.UtxoCache.memory_usage cache);
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_utxo_cache_hit_rate () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let db_view = Utxo.DbView.create db in
  let cache = Utxo.UtxoCache.create db_view in
  (* Add some coins *)
  for i = 0 to 4 do
    let outpoint = make_test_outpoint
      (Printf.sprintf "%064x" i) 0 in
    let coin = make_test_coin (Int64.of_int (i * 100000)) i false in
    Utxo.UtxoCache.add_coin cache outpoint coin ~possible_overwrite:false
  done;
  (* All lookups should be hits *)
  for i = 0 to 4 do
    let outpoint = make_test_outpoint
      (Printf.sprintf "%064x" i) 0 in
    let _ = Utxo.UtxoCache.get_coin cache outpoint in
    ()
  done;
  (* One miss for non-existent entry *)
  let missing = make_test_outpoint
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" 99 in
  let _ = Utxo.UtxoCache.get_coin cache missing in
  let hit_rate = Utxo.UtxoCache.hit_rate cache in
  (* 5 hits / 6 total = 0.833... *)
  Alcotest.(check bool) "hit rate > 0.8" true (hit_rate > 0.8);
  Alcotest.(check bool) "hit rate < 0.9" true (hit_rate < 0.9);
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_coin_conversion () =
  let entry = Utxo.{
    value = 5000000000L;
    script_pubkey = Cstruct.of_string "\x76\xa9\x14test\x88\xac";
    height = 100;
    is_coinbase = true;
  } in
  let coin = Utxo.coin_of_utxo_entry entry in
  Alcotest.(check int64) "coin value" entry.value coin.txout.value;
  Alcotest.(check int) "coin height" entry.height coin.height;
  Alcotest.(check bool) "coin is_coinbase" entry.is_coinbase coin.is_coinbase;
  let entry2 = Utxo.utxo_entry_of_coin coin in
  Alcotest.(check int64) "roundtrip value" entry.value entry2.value;
  Alcotest.(check int) "roundtrip height" entry.height entry2.height;
  Alcotest.(check bool) "roundtrip is_coinbase" entry.is_coinbase entry2.is_coinbase

(* ============================================================================
   Test Runner
   ============================================================================ *)

let () =
  cleanup_test_db ();
  let open Alcotest in
  run "Utxo" [
    "serialization", [
      test_case "utxo_entry round-trip" `Quick test_utxo_entry_serialization;
      test_case "utxo_entry regular" `Quick test_utxo_entry_regular;
      test_case "undo_data round-trip" `Quick test_undo_data_serialization;
    ];
    "utxo_set", [
      test_case "add and get" `Quick test_utxoset_add_get;
      test_case "remove" `Quick test_utxoset_remove;
      test_case "multiple outputs" `Quick test_utxoset_multiple_outputs;
      test_case "cache stats" `Quick test_utxoset_cache_stats;
    ];
    "connect_block", [
      test_case "coinbase only block" `Quick test_connect_coinbase_only_block;
      test_case "block with spend" `Quick test_connect_block_with_spend;
      test_case "coinbase maturity" `Quick test_connect_block_coinbase_maturity;
      test_case "output exceeds input" `Quick test_connect_block_output_exceeds_input;
      test_case "missing UTXO" `Quick test_connect_block_missing_utxo;
      test_case "coinbase too large" `Quick test_connect_block_coinbase_too_large;
    ];
    "disconnect_block", [
      test_case "basic disconnect" `Quick test_disconnect_block;
      test_case "connect/disconnect multiple" `Quick test_connect_disconnect_multiple;
    ];
    "storage", [
      test_case "undo data storage" `Quick test_undo_data_storage;
    ];
    "stats", [
      test_case "utxo statistics" `Quick test_utxo_stats;
    ];
    "utxo_cache", [
      test_case "add and get" `Quick test_utxo_cache_add_get;
      test_case "miss then hit" `Quick test_utxo_cache_miss_then_hit;
      test_case "spend" `Quick test_utxo_cache_spend;
      test_case "flush" `Quick test_utxo_cache_flush;
      test_case "flush erased" `Quick test_utxo_cache_flush_erased;
      test_case "add/spend roundtrip" `Quick test_utxo_cache_add_spend_roundtrip;
      test_case "memory tracking" `Quick test_utxo_cache_memory_tracking;
      test_case "hit rate" `Quick test_utxo_cache_hit_rate;
      test_case "coin conversion" `Quick test_coin_conversion;
    ];
  ]
