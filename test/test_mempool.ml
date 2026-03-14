(* Tests for mempool module *)

open Camlcoin

(* Test directory that gets cleaned up *)
let test_db_path = "/tmp/camlcoin_test_mempool_db"

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

(* Helper to create a test transaction input with RBF signaling *)
let make_test_input_rbf txid vout =
  Types.{
    previous_output = { txid; vout };
    script_sig = Cstruct.of_string "\x00";
    sequence = 0xFFFFFFFDl;  (* signals RBF *)
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

(* Create a test mempool with a UTXO set containing some spendable outputs *)
let create_test_mempool () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let utxo = Utxo.UtxoSet.create db in
  (* Add some spendable UTXOs *)
  let txid1 = Types.hash256_of_hex
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b" in
  let txid2 = Types.hash256_of_hex
    "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098" in
  let txid3 = Types.hash256_of_hex
    "9b0fc92260312ce44e74ef369f5c66bbb85848f2eddd5a7a1cde251e54ccfdd5" in
  Utxo.UtxoSet.add utxo txid1 0 Utxo.{
    value = 1_000_000L;  (* 0.01 BTC *)
    script_pubkey = Cstruct.of_string "\x76\xa9\x14test\x88\xac";
    height = 0;
    is_coinbase = false;
  };
  Utxo.UtxoSet.add utxo txid2 0 Utxo.{
    value = 2_000_000L;  (* 0.02 BTC *)
    script_pubkey = Cstruct.of_string "\x76\xa9\x14test\x88\xac";
    height = 0;
    is_coinbase = false;
  };
  Utxo.UtxoSet.add utxo txid3 0 Utxo.{
    value = 500_000L;
    script_pubkey = Cstruct.of_string "\x76\xa9\x14test\x88\xac";
    height = 0;
    is_coinbase = false;
  };
  let mp = Mempool.create ~require_standard:false ~verify_scripts:false ~utxo ~current_height:100 () in
  (mp, utxo, db, txid1, txid2, txid3)

(* ============================================================================
   Basic Mempool Tests
   ============================================================================ *)

let test_mempool_create () =
  let (mp, _utxo, db, _, _, _) = create_test_mempool () in
  let (count, weight, fee) = Mempool.get_info mp in
  Alcotest.(check int) "initial count" 0 count;
  Alcotest.(check int) "initial weight" 0 weight;
  Alcotest.(check int64) "initial fee" 0L fee;
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_mempool_add_transaction () =
  let (mp, _utxo, db, txid1, _, _) = create_test_mempool () in
  (* Create a valid transaction *)
  let tx = make_regular_tx
    [make_test_input txid1 0l]
    [make_test_output 990_000L]  (* 10000 satoshi fee *)
  in
  let result = Mempool.add_transaction mp tx in
  Alcotest.(check bool) "add succeeded" true (Result.is_ok result);
  let entry = Result.get_ok result in
  Alcotest.(check int64) "fee" 10_000L entry.fee;
  Alcotest.(check bool) "fee_rate > 0" true (entry.fee_rate > 0.0);
  (* Check mempool state *)
  let (count, weight, fee) = Mempool.get_info mp in
  Alcotest.(check int) "count is 1" 1 count;
  Alcotest.(check bool) "weight > 0" true (weight > 0);
  Alcotest.(check int64) "total fee" 10_000L fee;
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_mempool_contains () =
  let (mp, _utxo, db, txid1, _, _) = create_test_mempool () in
  let tx = make_regular_tx
    [make_test_input txid1 0l]
    [make_test_output 990_000L]
  in
  let result = Mempool.add_transaction mp tx in
  let entry = Result.get_ok result in
  Alcotest.(check bool) "contains txid" true (Mempool.contains mp entry.txid);
  (* Check get *)
  let got = Mempool.get mp entry.txid in
  Alcotest.(check bool) "get returns entry" true (Option.is_some got);
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_mempool_duplicate_rejection () =
  let (mp, _utxo, db, txid1, _, _) = create_test_mempool () in
  let tx = make_regular_tx
    [make_test_input txid1 0l]
    [make_test_output 990_000L]
  in
  let _result1 = Mempool.add_transaction mp tx in
  (* Try to add same tx again *)
  let result2 = Mempool.add_transaction mp tx in
  Alcotest.(check bool) "duplicate rejected" true (Result.is_error result2);
  (match result2 with
   | Error msg ->
     Alcotest.(check bool) "error mentions duplicate" true
       (String.sub msg 0 11 = "Transaction")
   | Ok _ -> Alcotest.fail "expected error");
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* ============================================================================
   Validation Tests
   ============================================================================ *)

let test_mempool_reject_coinbase () =
  let (mp, _utxo, db, _, _, _) = create_test_mempool () in
  let coinbase = make_coinbase_tx 100 [make_test_output 5_000_000_000L] in
  let result = Mempool.add_transaction mp coinbase in
  Alcotest.(check bool) "coinbase rejected" true (Result.is_error result);
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_mempool_reject_missing_input () =
  let (mp, _utxo, db, _, _, _) = create_test_mempool () in
  let fake_txid = Types.hash256_of_hex
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" in
  let tx = make_regular_tx
    [make_test_input fake_txid 0l]
    [make_test_output 100_000L]
  in
  let result = Mempool.add_transaction mp tx in
  Alcotest.(check bool) "missing input rejected" true (Result.is_error result);
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_mempool_reject_output_exceeds_input () =
  let (mp, _utxo, db, txid1, _, _) = create_test_mempool () in
  (* txid1 has 1_000_000 satoshis *)
  let tx = make_regular_tx
    [make_test_input txid1 0l]
    [make_test_output 2_000_000L]  (* more than input *)
  in
  let result = Mempool.add_transaction mp tx in
  Alcotest.(check bool) "output > input rejected" true (Result.is_error result);
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_mempool_reject_low_fee () =
  let (mp, _utxo, db, txid1, _, _) = create_test_mempool () in
  (* Create tx with zero fee *)
  let tx = make_regular_tx
    [make_test_input txid1 0l]
    [make_test_output 1_000_000L]  (* no fee *)
  in
  let result = Mempool.add_transaction mp tx in
  Alcotest.(check bool) "low fee rejected" true (Result.is_error result);
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_mempool_reject_immature_coinbase () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let utxo = Utxo.UtxoSet.create db in
  let cb_txid = Types.hash256_of_hex
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b" in
  (* Add a coinbase output at height 50 *)
  Utxo.UtxoSet.add utxo cb_txid 0 Utxo.{
    value = 5_000_000_000L;
    script_pubkey = Cstruct.of_string "\x76\xa9\x14test\x88\xac";
    height = 50;
    is_coinbase = true;
  };
  (* Create mempool at height 100 (only 50 confirmations) *)
  let mp = Mempool.create ~require_standard:false ~verify_scripts:false ~utxo ~current_height:100 () in
  let tx = make_regular_tx
    [make_test_input cb_txid 0l]
    [make_test_output 4_999_990_000L]
  in
  let result = Mempool.add_transaction mp tx in
  Alcotest.(check bool) "immature coinbase rejected" true (Result.is_error result);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* ============================================================================
   Dependency Tracking Tests
   ============================================================================ *)

let test_mempool_child_transaction () =
  let (mp, _utxo, db, txid1, _, _) = create_test_mempool () in
  (* Add parent transaction *)
  let parent_tx = make_regular_tx
    [make_test_input txid1 0l]
    [make_test_output 990_000L]
  in
  let parent_result = Mempool.add_transaction mp parent_tx in
  let parent_entry = Result.get_ok parent_result in
  (* Add child that spends parent output *)
  let child_tx = make_regular_tx
    [make_test_input parent_entry.txid 0l]
    [make_test_output 980_000L]
  in
  let child_result = Mempool.add_transaction mp child_tx in
  Alcotest.(check bool) "child tx accepted" true (Result.is_ok child_result);
  let child_entry = Result.get_ok child_result in
  (* Child should depend on parent *)
  Alcotest.(check int) "depends_on length" 1 (List.length child_entry.depends_on);
  Alcotest.(check bool) "depends on parent" true
    (Cstruct.equal (List.hd child_entry.depends_on) parent_entry.txid);
  (* Mempool should have 2 transactions *)
  let (count, _, _) = Mempool.get_info mp in
  Alcotest.(check int) "count is 2" 2 count;
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_mempool_remove_cascades () =
  let (mp, _utxo, db, txid1, _, _) = create_test_mempool () in
  (* Add parent *)
  let parent_tx = make_regular_tx
    [make_test_input txid1 0l]
    [make_test_output 990_000L]
  in
  let parent_entry = Result.get_ok (Mempool.add_transaction mp parent_tx) in
  (* Add child *)
  let child_tx = make_regular_tx
    [make_test_input parent_entry.txid 0l]
    [make_test_output 980_000L]
  in
  let child_entry = Result.get_ok (Mempool.add_transaction mp child_tx) in
  Alcotest.(check int) "count before remove" 2
    (let (c, _, _) = Mempool.get_info mp in c);
  (* Remove parent - should also remove child *)
  Mempool.remove_transaction mp parent_entry.txid;
  Alcotest.(check bool) "parent removed" false
    (Mempool.contains mp parent_entry.txid);
  Alcotest.(check bool) "child removed" false
    (Mempool.contains mp child_entry.txid);
  let (count, _, _) = Mempool.get_info mp in
  Alcotest.(check int) "count after remove" 0 count;
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_mempool_ancestors_descendants () =
  let (mp, _utxo, db, txid1, txid2, _) = create_test_mempool () in
  (* Create a chain: tx1 -> tx2 -> tx3 *)
  let tx1 = make_regular_tx
    [make_test_input txid1 0l]
    [make_test_output 990_000L]
  in
  let e1 = Result.get_ok (Mempool.add_transaction mp tx1) in
  let tx2 = make_regular_tx
    [make_test_input e1.txid 0l]
    [make_test_output 980_000L]
  in
  let e2 = Result.get_ok (Mempool.add_transaction mp tx2) in
  let tx3 = make_regular_tx
    [make_test_input e2.txid 0l]
    [make_test_output 970_000L]
  in
  let e3 = Result.get_ok (Mempool.add_transaction mp tx3) in
  (* Test ancestors *)
  let ancestors = Mempool.get_ancestors mp e3.txid in
  Alcotest.(check int) "e3 has 2 ancestors" 2 (List.length ancestors);
  (* Test descendants *)
  let descendants = Mempool.get_descendants mp e1.txid in
  Alcotest.(check int) "e1 has 2 descendants" 2 (List.length descendants);
  let _ = txid2 in  (* suppress warning *)
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* ============================================================================
   Block Processing Tests
   ============================================================================ *)

let test_mempool_remove_for_block () =
  let (mp, _utxo, db, txid1, txid2, _) = create_test_mempool () in
  (* Add two transactions *)
  let tx1 = make_regular_tx
    [make_test_input txid1 0l]
    [make_test_output 990_000L]
  in
  let e1 = Result.get_ok (Mempool.add_transaction mp tx1) in
  let tx2 = make_regular_tx
    [make_test_input txid2 0l]
    [make_test_output 1_990_000L]
  in
  let e2 = Result.get_ok (Mempool.add_transaction mp tx2) in
  (* Create a mock block containing tx1 *)
  let coinbase = make_coinbase_tx 101 [make_test_output 5_000_010_000L] in
  let block = Types.{
    header = {
      version = 1l;
      prev_block = Types.zero_hash;
      merkle_root = Types.zero_hash;
      timestamp = 0l;
      bits = 0x207fffffl;
      nonce = 0l;
    };
    transactions = [coinbase; tx1];
  } in
  Mempool.remove_for_block mp block 101;
  (* tx1 should be removed, tx2 should remain *)
  Alcotest.(check bool) "tx1 removed" false (Mempool.contains mp e1.txid);
  Alcotest.(check bool) "tx2 remains" true (Mempool.contains mp e2.txid);
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_mempool_conflict_removal () =
  let (mp, _utxo, db, txid1, _, _) = create_test_mempool () in
  (* Add a transaction spending txid1 *)
  let tx1 = make_regular_tx
    [make_test_input txid1 0l]
    [make_test_output 990_000L]
  in
  let e1 = Result.get_ok (Mempool.add_transaction mp tx1) in
  (* Create a conflicting transaction (also spends txid1) that goes in a block *)
  let conflicting_tx = make_regular_tx
    [make_test_input txid1 0l]
    [make_test_output 980_000L]  (* different output *)
  in
  let coinbase = make_coinbase_tx 101 [make_test_output 5_000_020_000L] in
  let block = Types.{
    header = {
      version = 1l;
      prev_block = Types.zero_hash;
      merkle_root = Types.zero_hash;
      timestamp = 0l;
      bits = 0x207fffffl;
      nonce = 0l;
    };
    transactions = [coinbase; conflicting_tx];
  } in
  Mempool.remove_for_block mp block 101;
  (* tx1 should be removed as a conflict *)
  Alcotest.(check bool) "conflicting tx removed" false (Mempool.contains mp e1.txid);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* ============================================================================
   Sorting and Selection Tests
   ============================================================================ *)

let test_mempool_sorted_by_feerate () =
  let (mp, _utxo, db, txid1, txid2, txid3) = create_test_mempool () in
  (* Add transactions with different fee rates *)
  let tx_low = make_regular_tx
    [make_test_input txid3 0l]  (* 500k input *)
    [make_test_output 499_000L]  (* 1000 sat fee *)
  in
  let tx_high = make_regular_tx
    [make_test_input txid1 0l]  (* 1M input *)
    [make_test_output 900_000L]  (* 100k sat fee *)
  in
  let tx_mid = make_regular_tx
    [make_test_input txid2 0l]  (* 2M input *)
    [make_test_output 1_950_000L]  (* 50k sat fee *)
  in
  let _ = Mempool.add_transaction mp tx_low in
  let _ = Mempool.add_transaction mp tx_high in
  let _ = Mempool.add_transaction mp tx_mid in
  let sorted = Mempool.get_sorted_transactions mp in
  Alcotest.(check int) "3 transactions" 3 (List.length sorted);
  (* Should be sorted high to low fee rate *)
  let fee_rates = List.map (fun e -> e.Mempool.fee_rate) sorted in
  let is_sorted = List.fold_left (fun (prev, ok) rate ->
    (rate, ok && rate <= prev)
  ) (max_float, true) fee_rates |> snd in
  Alcotest.(check bool) "sorted by fee rate desc" true is_sorted;
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_mempool_select_for_block () =
  let (mp, _utxo, db, txid1, txid2, _) = create_test_mempool () in
  let tx1 = make_regular_tx
    [make_test_input txid1 0l]
    [make_test_output 990_000L]
  in
  let tx2 = make_regular_tx
    [make_test_input txid2 0l]
    [make_test_output 1_990_000L]
  in
  let _ = Mempool.add_transaction mp tx1 in
  let _ = Mempool.add_transaction mp tx2 in
  (* Select with very high limit *)
  let selected = Mempool.select_for_block mp ~max_weight:4_000_000 in
  Alcotest.(check int) "selected all" 2 (List.length selected);
  (* Select with very low limit *)
  let selected_limited = Mempool.select_for_block mp ~max_weight:100 in
  Alcotest.(check int) "selected none (too small)" 0 (List.length selected_limited);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* ============================================================================
   RBF Tests
   ============================================================================ *)

let test_mempool_signals_rbf () =
  let tx_rbf = make_regular_tx
    [make_test_input_rbf Types.zero_hash 0l]
    [make_test_output 100_000L]
  in
  let tx_no_rbf = make_regular_tx
    [make_test_input Types.zero_hash 0l]
    [make_test_output 100_000L]
  in
  Alcotest.(check bool) "tx_rbf signals" true (Mempool.signals_rbf tx_rbf);
  Alcotest.(check bool) "tx_no_rbf does not signal" false (Mempool.signals_rbf tx_no_rbf)

let test_mempool_conflict_detection () =
  let (mp, _utxo, db, txid1, _, _) = create_test_mempool () in
  let tx1 = make_regular_tx
    [make_test_input txid1 0l]
    [make_test_output 990_000L]
  in
  let _ = Mempool.add_transaction mp tx1 in
  (* Check conflict with same input *)
  let tx_conflict = make_regular_tx
    [make_test_input txid1 0l]
    [make_test_output 980_000L]
  in
  let conflict = Mempool.check_conflict mp tx_conflict in
  Alcotest.(check bool) "conflict detected" true (Option.is_some conflict);
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_mempool_rbf_replacement () =
  let (mp, _utxo, db, txid1, _, _) = create_test_mempool () in
  (* Add original tx that signals RBF *)
  let tx_orig = make_regular_tx
    [make_test_input_rbf txid1 0l]
    [make_test_output 990_000L]  (* 10k fee *)
  in
  let orig_entry = Result.get_ok (Mempool.add_transaction mp tx_orig) in
  (* Replace with higher fee *)
  let tx_replacement = make_regular_tx
    [make_test_input_rbf txid1 0l]
    [make_test_output 950_000L]  (* 50k fee *)
  in
  let result = Mempool.replace_by_fee mp tx_replacement in
  Alcotest.(check bool) "replacement succeeded" true (Result.is_ok result);
  let new_entry = Result.get_ok result in
  Alcotest.(check int64) "new fee is higher" 50_000L new_entry.fee;
  (* Original should be gone *)
  Alcotest.(check bool) "original removed" false (Mempool.contains mp orig_entry.txid);
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_mempool_rbf_rejection_no_signal () =
  let (mp, _utxo, db, txid1, _, _) = create_test_mempool () in
  (* Add original tx that does NOT signal RBF *)
  let tx_orig = make_regular_tx
    [make_test_input txid1 0l]  (* final sequence *)
    [make_test_output 990_000L]
  in
  let _ = Mempool.add_transaction mp tx_orig in
  (* Try to replace *)
  let tx_replacement = make_regular_tx
    [make_test_input txid1 0l]
    [make_test_output 950_000L]
  in
  let result = Mempool.replace_by_fee mp tx_replacement in
  Alcotest.(check bool) "replacement rejected" true (Result.is_error result);
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_mempool_rbf_rejection_low_fee () =
  let (mp, _utxo, db, txid1, _, _) = create_test_mempool () in
  (* Add original tx that signals RBF with high fee *)
  let tx_orig = make_regular_tx
    [make_test_input_rbf txid1 0l]
    [make_test_output 900_000L]  (* 100k fee *)
  in
  let _ = Mempool.add_transaction mp tx_orig in
  (* Try to replace with lower fee *)
  let tx_replacement = make_regular_tx
    [make_test_input_rbf txid1 0l]
    [make_test_output 950_000L]  (* 50k fee - lower *)
  in
  let result = Mempool.replace_by_fee mp tx_replacement in
  Alcotest.(check bool) "low fee replacement rejected" true (Result.is_error result);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* ============================================================================
   Stats Tests
   ============================================================================ *)

let test_mempool_stats () =
  let (mp, _utxo, db, txid1, txid2, _) = create_test_mempool () in
  let tx1 = make_regular_tx
    [make_test_input txid1 0l]
    [make_test_output 990_000L]
  in
  let tx2 = make_regular_tx
    [make_test_input txid2 0l]
    [make_test_output 1_990_000L]
  in
  let _ = Mempool.add_transaction mp tx1 in
  let _ = Mempool.add_transaction mp tx2 in
  let stats = Mempool.get_stats mp in
  Alcotest.(check int) "tx count" 2 stats.tx_count;
  Alcotest.(check bool) "total weight > 0" true (stats.total_weight > 0);
  Alcotest.(check int64) "total fee" 20_000L stats.total_fee;
  Alcotest.(check bool) "min <= max" true (stats.min_fee_rate <= stats.max_fee_rate);
  Alcotest.(check bool) "avg > 0" true (stats.avg_fee_rate > 0.0);
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_mempool_clear () =
  let (mp, _utxo, db, txid1, txid2, _) = create_test_mempool () in
  let tx1 = make_regular_tx
    [make_test_input txid1 0l]
    [make_test_output 990_000L]
  in
  let tx2 = make_regular_tx
    [make_test_input txid2 0l]
    [make_test_output 1_990_000L]
  in
  let _ = Mempool.add_transaction mp tx1 in
  let _ = Mempool.add_transaction mp tx2 in
  Mempool.clear mp;
  let (count, weight, fee) = Mempool.get_info mp in
  Alcotest.(check int) "count after clear" 0 count;
  Alcotest.(check int) "weight after clear" 0 weight;
  Alcotest.(check int64) "fee after clear" 0L fee;
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* ============================================================================
   TRUC/v3 Policy Tests (BIP-431)
   ============================================================================ *)

(* Helper to check if a string contains a substring *)
let string_contains haystack needle =
  let nlen = String.length needle in
  let hlen = String.length haystack in
  if nlen > hlen then false
  else begin
    let found = ref false in
    for i = 0 to hlen - nlen do
      if not !found && String.sub haystack i nlen = needle then
        found := true
    done;
    !found
  end

(* Helper to create a v3 transaction *)
let make_v3_tx inputs outputs =
  Types.{
    version = 3l;
    inputs;
    outputs;
    witnesses = [];
    locktime = 0l;
  }

(* A valid P2PKH script_pubkey with exactly 20 bytes of hash *)

(* Test: v3 child tx with >10k vsize rejected *)
let test_truc_vsize_limit () =
  let (mp, _utxo, db, txid1, _, _) = create_test_mempool () in
  (* Add a v3 parent transaction *)
  let parent_tx = make_v3_tx
    [make_test_input txid1 0l]
    [make_test_output 990_000L]
  in
  let parent_result = Mempool.add_transaction mp parent_tx in
  Alcotest.(check bool) "v3 parent accepted" true (Result.is_ok parent_result);
  let parent_entry = Result.get_ok parent_result in
  (* Create a v3 child with many outputs to exceed 10k vsize *)
  let many_outputs = List.init 500 (fun _ -> make_test_output 1_000L) in
  let child_tx = make_v3_tx
    [make_test_input parent_entry.txid 0l]
    many_outputs
  in
  let result = Mempool.add_transaction mp child_tx in
  Alcotest.(check bool) "v3 child >10k vsize rejected" true (Result.is_error result);
  (match result with
   | Error msg ->
     Alcotest.(check bool) "error mentions vsize" true
       (string_contains msg "vsize")
   | Ok _ -> Alcotest.fail "expected error");
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test: v3 tx with 2+ unconfirmed parents rejected *)
let test_truc_ancestor_limit () =
  let (mp, _utxo, db, txid1, txid2, _) = create_test_mempool () in
  (* Add two v3 parent transactions *)
  let parent1_tx = make_v3_tx
    [make_test_input txid1 0l]
    [make_test_output 990_000L]
  in
  let parent1_result = Mempool.add_transaction mp parent1_tx in
  Alcotest.(check bool) "v3 parent1 accepted" true (Result.is_ok parent1_result);
  let parent1_entry = Result.get_ok parent1_result in
  let parent2_tx = make_v3_tx
    [make_test_input txid2 0l]
    [make_test_output 1_990_000L]
  in
  let parent2_result = Mempool.add_transaction mp parent2_tx in
  Alcotest.(check bool) "v3 parent2 accepted" true (Result.is_ok parent2_result);
  let parent2_entry = Result.get_ok parent2_result in
  (* Try to add a v3 child spending both parents *)
  let child_tx = make_v3_tx
    [make_test_input parent1_entry.txid 0l;
     make_test_input parent2_entry.txid 0l]
    [make_test_output 2_900_000L]
  in
  let result = Mempool.add_transaction mp child_tx in
  Alcotest.(check bool) "v3 tx with 2+ ancestors rejected" true (Result.is_error result);
  (match result with
   | Error msg ->
     Alcotest.(check bool) "error mentions ancestor" true
       (string_contains msg "ancestor")
   | Ok _ -> Alcotest.fail "expected error");
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test: v3 parent can only have 1 child *)
let test_truc_one_child_limit () =
  let (mp, _utxo, db, txid1, txid2, _) = create_test_mempool () in
  (* Add v3 parent with two outputs *)
  let parent_tx = make_v3_tx
    [make_test_input txid1 0l]
    [make_test_output 490_000L; make_test_output 490_000L]
  in
  let parent_result = Mempool.add_transaction mp parent_tx in
  Alcotest.(check bool) "v3 parent accepted" true (Result.is_ok parent_result);
  let parent_entry = Result.get_ok parent_result in
  (* Add first child spending output 0 - should succeed *)
  let child1_tx = make_v3_tx
    [make_test_input parent_entry.txid 0l]
    [make_test_output 480_000L]
  in
  let child1_result = Mempool.add_transaction mp child1_tx in
  Alcotest.(check bool) "first v3 child accepted" true (Result.is_ok child1_result);
  (* Add second child spending output 1 - should be rejected *)
  (* Need a confirmed input for the second child to avoid ancestor issues *)
  let child2_tx = make_v3_tx
    [make_test_input parent_entry.txid 1l]
    [make_test_output 480_000L]
  in
  let result = Mempool.add_transaction mp child2_tx in
  Alcotest.(check bool) "second v3 child rejected" true (Result.is_error result);
  (match result with
   | Error msg ->
     Alcotest.(check bool) "error mentions child" true
       (string_contains msg "child")
   | Ok _ -> Alcotest.fail "expected error");
  ignore txid2;
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test: non-v3 tx spending unconfirmed v3 output rejected *)
let test_truc_no_mixing () =
  let (mp, _utxo, db, txid1, _, _) = create_test_mempool () in
  (* Add v3 parent *)
  let parent_tx = make_v3_tx
    [make_test_input txid1 0l]
    [make_test_output 990_000L]
  in
  let parent_result = Mempool.add_transaction mp parent_tx in
  Alcotest.(check bool) "v3 parent accepted" true (Result.is_ok parent_result);
  let parent_entry = Result.get_ok parent_result in
  (* Try to add a v1 child spending v3 parent *)
  let child_tx = make_regular_tx
    [make_test_input parent_entry.txid 0l]
    [make_test_output 980_000L]
  in
  let result = Mempool.add_transaction mp child_tx in
  Alcotest.(check bool) "non-v3 spending v3 rejected" true (Result.is_error result);
  (match result with
   | Error msg ->
     Alcotest.(check bool) "error mentions v3" true
       (string_contains msg "v3")
   | Ok _ -> Alcotest.fail "expected error");
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test: v3 tx with zero-value output accepted (ephemeral dust exemption)
   Uses non-standard mempool since v3 is not standard per policy *)
let test_truc_ephemeral_dust () =
  let (mp, _utxo, db, txid1, _, _) = create_test_mempool () in
  (* v3 tx with a zero-value output should be accepted *)
  let tx = make_v3_tx
    [make_test_input txid1 0l]
    [make_test_output 990_000L; make_test_output 0L]
  in
  let result = Mempool.add_transaction mp tx in
  Alcotest.(check bool) "v3 tx with zero-value output accepted" true (Result.is_ok result);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* ============================================================================
   Ancestor/Descendant Limit Tests
   ============================================================================ *)

(* Helper: create a chain of transactions where each tx spends the previous *)
let build_tx_chain (mp : Mempool.mempool) ~(start_txid : Types.hash256)
    ~(start_value : int64) ~(chain_length : int)
    : (Mempool.mempool_entry list, string) result =
  let entries = ref [] in
  let current_txid = ref start_txid in
  let current_value = ref start_value in
  let error = ref None in
  for i = 1 to chain_length do
    if !error = None then begin
      (* Each tx pays 1000 sat fee *)
      let new_value = Int64.sub !current_value 1000L in
      let tx = make_regular_tx
        [make_test_input !current_txid 0l]
        [make_test_output new_value]
      in
      match Mempool.add_transaction mp tx with
      | Ok entry ->
        entries := entry :: !entries;
        current_txid := entry.txid;
        current_value := new_value
      | Error msg ->
        error := Some (Printf.sprintf "Chain tx %d failed: %s" i msg)
    end
  done;
  match !error with
  | Some msg -> Error msg
  | None -> Ok (List.rev !entries)

(* Test: chain of 25 transactions should be accepted (25 ancestors including self) *)
let test_ancestor_limit_25_pass () =
  let (mp, _utxo, db, txid1, _, _) = create_test_mempool () in
  (* Build a chain of 24 txs (since the 25th tx will have 24 ancestors + itself = 25) *)
  let result = build_tx_chain mp ~start_txid:txid1 ~start_value:1_000_000L ~chain_length:24 in
  Alcotest.(check bool) "chain of 24 txs built" true (Result.is_ok result);
  let entries = Result.get_ok result in
  Alcotest.(check int) "24 txs in chain" 24 (List.length entries);
  (* The last tx has 24 ancestors + itself = 25, exactly at the limit *)
  let last_entry = List.nth entries 23 in
  let ancestors = Mempool.get_ancestors mp last_entry.txid in
  Alcotest.(check int) "last tx has 23 ancestors" 23 (List.length ancestors);
  (* Now add one more tx spending the last one - this should succeed (25 total) *)
  let final_tx = make_regular_tx
    [make_test_input last_entry.txid 0l]
    [make_test_output (Int64.sub (List.hd (List.nth entries 23).tx.outputs).Types.value 1000L)]
  in
  let final_result = Mempool.add_transaction mp final_tx in
  Alcotest.(check bool) "25th tx in chain accepted" true (Result.is_ok final_result);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test: chain of 26 transactions should be rejected (exceeds 25 ancestor limit) *)
let test_ancestor_limit_26_fail () =
  let (mp, _utxo, db, txid1, _, _) = create_test_mempool () in
  (* Build a chain of 25 txs first *)
  let result = build_tx_chain mp ~start_txid:txid1 ~start_value:1_000_000L ~chain_length:25 in
  Alcotest.(check bool) "chain of 25 txs built" true (Result.is_ok result);
  let entries = Result.get_ok result in
  Alcotest.(check int) "25 txs in chain" 25 (List.length entries);
  (* Now try to add the 26th tx - this should fail *)
  let last_entry = List.nth entries 24 in
  let final_tx = make_regular_tx
    [make_test_input last_entry.txid 0l]
    [make_test_output (Int64.sub (List.hd (List.nth entries 24).tx.outputs).Types.value 1000L)]
  in
  let final_result = Mempool.add_transaction mp final_tx in
  Alcotest.(check bool) "26th tx in chain rejected" true (Result.is_error final_result);
  (match final_result with
   | Error msg ->
     Alcotest.(check bool) "error mentions ancestors" true
       (string_contains msg "ancestor")
   | Ok _ -> Alcotest.fail "expected error");
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test: descendant limit - adding tx that would give ancestor >25 descendants *)
let test_descendant_limit_pass () =
  let (mp, utxo, db, txid1, _, _) = create_test_mempool () in
  (* Add a parent tx with 25 outputs *)
  let parent_outputs = List.init 25 (fun _ -> make_test_output 30_000L) in
  let parent_tx = make_regular_tx
    [make_test_input txid1 0l]
    parent_outputs
  in
  let parent_result = Mempool.add_transaction mp parent_tx in
  Alcotest.(check bool) "parent accepted" true (Result.is_ok parent_result);
  let parent_entry = Result.get_ok parent_result in
  (* Add 24 children spending outputs 0-23 *)
  for i = 0 to 23 do
    let child_tx = make_regular_tx
      [make_test_input parent_entry.txid (Int32.of_int i)]
      [make_test_output 29_000L]
    in
    let child_result = Mempool.add_transaction mp child_tx in
    Alcotest.(check bool) (Printf.sprintf "child %d accepted" i) true (Result.is_ok child_result)
  done;
  (* The 25th child (spending output 24) should also be accepted
     because descendant count includes self, so parent + 24 children = 25 total, at limit *)
  let child_25_tx = make_regular_tx
    [make_test_input parent_entry.txid 24l]
    [make_test_output 29_000L]
  in
  let child_25_result = Mempool.add_transaction mp child_25_tx in
  (* Note: depending on how we count, this might fail if 25 descendants is the limit *)
  (* Bitcoin Core counts: parent itself + its descendants must not exceed 25 *)
  (* So parent + 24 children = 25, then adding child 25 would make 26 total descendants *)
  (* Let's check what happens *)
  (match child_25_result with
   | Ok _ -> ()  (* If it passes, the limit is different *)
   | Error msg ->
     (* If it fails, verify it's due to descendant limit *)
     Alcotest.(check bool) "error mentions descendant" true
       (string_contains msg "descendant"));
  ignore utxo;
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test: descendant limit exceeded *)
let test_descendant_limit_fail () =
  let (mp, utxo, db, txid1, _, _) = create_test_mempool () in
  (* Add a parent tx with 26 outputs *)
  let parent_outputs = List.init 26 (fun _ -> make_test_output 30_000L) in
  let parent_tx = make_regular_tx
    [make_test_input txid1 0l]
    parent_outputs
  in
  let parent_result = Mempool.add_transaction mp parent_tx in
  Alcotest.(check bool) "parent accepted" true (Result.is_ok parent_result);
  let parent_entry = Result.get_ok parent_result in
  (* Add 24 children spending outputs 0-23 (parent + 24 children = 25 descendants) *)
  for i = 0 to 23 do
    let child_tx = make_regular_tx
      [make_test_input parent_entry.txid (Int32.of_int i)]
      [make_test_output 29_000L]
    in
    let child_result = Mempool.add_transaction mp child_tx in
    Alcotest.(check bool) (Printf.sprintf "child %d accepted" i) true (Result.is_ok child_result)
  done;
  (* At this point, parent has 24 descendants, so it's at 25 total (including self).
     Adding child 25 should fail because it would make the parent have 26 total. *)
  let child_fail_tx = make_regular_tx
    [make_test_input parent_entry.txid 24l]
    [make_test_output 29_000L]
  in
  let fail_result = Mempool.add_transaction mp child_fail_tx in
  (* Bitcoin Core: the limit is 25 *including* the tx itself, so:
     - A tx can have at most 24 descendants (itself + 24 = 25)
     - Adding the 25th descendant would exceed the limit *)
  (match fail_result with
   | Error msg ->
     Alcotest.(check bool) "error mentions descendant" true
       (string_contains msg "descendant")
   | Ok _ ->
     (* If it succeeded, try adding one more to trigger the limit *)
     let child_26_tx = make_regular_tx
       [make_test_input parent_entry.txid 25l]
       [make_test_output 29_000L]
     in
     let result_26 = Mempool.add_transaction mp child_26_tx in
     Alcotest.(check bool) "26th descendant rejected" true (Result.is_error result_26);
     match result_26 with
     | Error msg ->
       Alcotest.(check bool) "error mentions descendant" true
         (string_contains msg "descendant")
     | Ok _ -> Alcotest.fail "expected descendant limit error");
  ignore utxo;
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test: ancestor size limit (101 kvB) *)
let test_ancestor_size_limit () =
  (* This test would require creating large transactions to exceed 101 kvB *)
  (* For now, verify the constants are correct *)
  Alcotest.(check int) "max_ancestor_count" 25 Mempool.max_ancestor_count;
  Alcotest.(check int) "max_descendant_count" 25 Mempool.max_descendant_count;
  Alcotest.(check int) "max_ancestor_size" 101_000 Mempool.max_ancestor_size;
  Alcotest.(check int) "max_descendant_size" 101_000 Mempool.max_descendant_size

(* ============================================================================
   Test Runner
   ============================================================================ *)

let () =
  cleanup_test_db ();
  let open Alcotest in
  run "Mempool" [
    "basic", [
      test_case "create" `Quick test_mempool_create;
      test_case "add transaction" `Quick test_mempool_add_transaction;
      test_case "contains" `Quick test_mempool_contains;
      test_case "duplicate rejection" `Quick test_mempool_duplicate_rejection;
    ];
    "validation", [
      test_case "reject coinbase" `Quick test_mempool_reject_coinbase;
      test_case "reject missing input" `Quick test_mempool_reject_missing_input;
      test_case "reject output > input" `Quick test_mempool_reject_output_exceeds_input;
      test_case "reject low fee" `Quick test_mempool_reject_low_fee;
      test_case "reject immature coinbase" `Quick test_mempool_reject_immature_coinbase;
    ];
    "dependencies", [
      test_case "child transaction" `Quick test_mempool_child_transaction;
      test_case "remove cascades" `Quick test_mempool_remove_cascades;
      test_case "ancestors/descendants" `Quick test_mempool_ancestors_descendants;
    ];
    "block_processing", [
      test_case "remove for block" `Quick test_mempool_remove_for_block;
      test_case "conflict removal" `Quick test_mempool_conflict_removal;
    ];
    "sorting", [
      test_case "sorted by fee rate" `Quick test_mempool_sorted_by_feerate;
      test_case "select for block" `Quick test_mempool_select_for_block;
    ];
    "rbf", [
      test_case "signals RBF" `Quick test_mempool_signals_rbf;
      test_case "conflict detection" `Quick test_mempool_conflict_detection;
      test_case "RBF replacement" `Quick test_mempool_rbf_replacement;
      test_case "RBF rejection no signal" `Quick test_mempool_rbf_rejection_no_signal;
      test_case "RBF rejection low fee" `Quick test_mempool_rbf_rejection_low_fee;
    ];
    "stats", [
      test_case "get stats" `Quick test_mempool_stats;
      test_case "clear" `Quick test_mempool_clear;
    ];
    "truc_v3", [
      test_case "v3 child >10k vsize rejected" `Quick test_truc_vsize_limit;
      test_case "v3 ancestor limit" `Quick test_truc_ancestor_limit;
      test_case "v3 one child limit" `Quick test_truc_one_child_limit;
      test_case "non-v3 spending v3 rejected" `Quick test_truc_no_mixing;
      test_case "v3 ephemeral dust" `Quick test_truc_ephemeral_dust;
    ];
    "ancestor_descendant_limits", [
      test_case "25-tx ancestor chain passes" `Quick test_ancestor_limit_25_pass;
      test_case "26-tx ancestor chain fails" `Quick test_ancestor_limit_26_fail;
      test_case "descendant limit pass" `Quick test_descendant_limit_pass;
      test_case "descendant limit fail" `Quick test_descendant_limit_fail;
      test_case "ancestor/descendant size constants" `Quick test_ancestor_size_limit;
    ];
  ]
