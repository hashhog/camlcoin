(* Tests for fee estimation module *)

open Camlcoin

(* ============================================================================
   Helper Functions
   ============================================================================ *)

(* Create a test txid from an integer *)
let make_txid (n : int) : Types.hash256 =
  let buf = Cstruct.create 32 in
  Cstruct.LE.set_uint32 buf 0 (Int32.of_int n);
  buf

(* Create a minimal transaction for testing *)
let make_test_tx () : Types.transaction =
  Types.{
    version = 1l;
    inputs = [{
      previous_output = { txid = Types.zero_hash; vout = 0l };
      script_sig = Cstruct.of_string "\x00";
      sequence = 0xFFFFFFFFl;
    }];
    outputs = [{
      value = 100_000L;
      script_pubkey = Cstruct.of_string "\x76\xa9\x14test\x88\xac";
    }];
    witnesses = [];
    locktime = 0l;
  }

(* ============================================================================
   Basic Tests
   ============================================================================ *)

let test_create () =
  let est = Fee_estimation.create () in
  Alcotest.(check int) "initial height is 0" 0
    (Fee_estimation.current_height est);
  Alcotest.(check int) "no tracked txs" 0
    (Fee_estimation.tracked_count est);
  Alcotest.(check int) "has buckets" 20
    (Fee_estimation.bucket_count est)

let test_track_transaction () =
  let est = Fee_estimation.create () in
  let txid = make_txid 1 in
  Fee_estimation.track_transaction est txid 50.0 100;
  Alcotest.(check int) "one tracked tx" 1
    (Fee_estimation.tracked_count est);
  (* Check bucket got updated *)
  match Fee_estimation.get_bucket_stats est 9 with (* 50.0 is in bucket 9 *)
  | None -> Alcotest.fail "bucket should exist"
  | Some stats ->
    Alcotest.(check int) "unconfirmed count" 1 stats.unconfirmed

let test_remove_transaction () =
  let est = Fee_estimation.create () in
  let txid = make_txid 1 in
  Fee_estimation.track_transaction est txid 50.0 100;
  Alcotest.(check int) "tracked" 1 (Fee_estimation.tracked_count est);
  Fee_estimation.remove_transaction est txid;
  Alcotest.(check int) "removed" 0 (Fee_estimation.tracked_count est)

let test_record_confirmation () =
  let est = Fee_estimation.create () in
  let txid = make_txid 1 in
  (* Track at height 100 *)
  Fee_estimation.track_transaction est txid 50.0 100;
  (* Confirm at height 102 (2 blocks later) *)
  Fee_estimation.record_confirmation est txid 102;
  Alcotest.(check int) "no longer tracked" 0
    (Fee_estimation.tracked_count est);
  (* Check bucket stats *)
  match Fee_estimation.get_bucket_stats est 9 with
  | None -> Alcotest.fail "bucket should exist"
  | Some stats ->
    Alcotest.(check int) "confirmed count" 1 stats.confirmed;
    Alcotest.(check int) "sample count" 1 stats.sample_count;
    Alcotest.(check (option (float 0.01))) "median blocks" (Some 2.0)
      stats.median_blocks

(* ============================================================================
   Estimation Tests
   ============================================================================ *)

let test_estimate_insufficient_data () =
  let est = Fee_estimation.create () in
  (* With no data, should return default *)
  let high = Fee_estimation.estimate_high_priority est in
  let medium = Fee_estimation.estimate_medium_priority est in
  let low = Fee_estimation.estimate_low_priority est in
  Alcotest.(check (float 0.01)) "default high" 20.0 high;
  Alcotest.(check (float 0.01)) "default medium" 10.0 medium;
  Alcotest.(check (float 0.01)) "default low" 1.0 low

let test_estimate_with_data () =
  let est = Fee_estimation.create () in
  (* Add 15 samples to the 50 sat/vB bucket (index 9), all confirming in 1 block *)
  for i = 1 to 15 do
    let txid = make_txid i in
    Fee_estimation.track_transaction est txid 50.0 100;
    Fee_estimation.record_confirmation est txid 101
  done;
  (* Should now estimate 50.0 for high priority (1 block) *)
  let high = Fee_estimation.estimate_high_priority est in
  Alcotest.(check (float 0.01)) "estimated 50 for high" 50.0 high

let test_estimate_target_blocks () =
  let est = Fee_estimation.create () in
  (* Add samples to 100 sat/vB bucket, confirming in 3 blocks *)
  for i = 1 to 15 do
    let txid = make_txid i in
    Fee_estimation.track_transaction est txid 100.0 100;
    Fee_estimation.record_confirmation est txid 103
  done;
  (* Add samples to 50 sat/vB bucket, confirming in 6 blocks *)
  for i = 100 to 114 do
    let txid = make_txid i in
    Fee_estimation.track_transaction est txid 50.0 100;
    Fee_estimation.record_confirmation est txid 106
  done;
  (* Estimate for 1 block should return None (no bucket has 1-block median) *)
  let result1 = Fee_estimation.estimate_fee est 1 in
  (* 100 sat/vB has median 3, 50 has median 6 - neither meets 1 block *)
  Alcotest.(check (option (float 0.01))) "1 block estimate none"
    None result1;
  (* Estimate for 3 blocks should return 100.0 (lowest that meets target) *)
  let result3 = Fee_estimation.estimate_fee est 3 in
  Alcotest.(check (option (float 0.01))) "3 block estimate"
    (Some 100.0) result3;
  (* Estimate for 6 blocks should return 50.0 (lowest that meets target) *)
  let result6 = Fee_estimation.estimate_fee est 6 in
  Alcotest.(check (option (float 0.01))) "6 block estimate"
    (Some 50.0) result6

let test_estimate_finds_lowest_sufficient () =
  let est = Fee_estimation.create () in
  (* Multiple buckets all confirm in 1 block *)
  (* 10 sat/vB bucket *)
  for i = 1 to 15 do
    let txid = make_txid i in
    Fee_estimation.track_transaction est txid 10.0 100;
    Fee_estimation.record_confirmation est txid 101
  done;
  (* 50 sat/vB bucket *)
  for i = 100 to 114 do
    let txid = make_txid i in
    Fee_estimation.track_transaction est txid 50.0 100;
    Fee_estimation.record_confirmation est txid 101
  done;
  (* Should return the LOWEST fee rate that meets target (10.0) *)
  let high = Fee_estimation.estimate_high_priority est in
  Alcotest.(check (float 0.01)) "picks lowest sufficient rate" 10.0 high

(* ============================================================================
   Bucket Tests
   ============================================================================ *)

let test_bucket_boundaries () =
  let est = Fee_estimation.create () in
  (* Test various fee rates end up in correct buckets *)
  (* 0.5 sat/vB should go to bucket 0 (1.0 min) *)
  Fee_estimation.track_transaction est (make_txid 1) 0.5 100;
  match Fee_estimation.get_bucket_stats est 0 with
  | None -> Alcotest.fail "bucket 0 should exist"
  | Some stats ->
    Alcotest.(check int) "0.5 in bucket 0" 1 stats.unconfirmed;
  (* 1.5 sat/vB should go to bucket 0 (1.0-2.0 range) *)
  Fee_estimation.track_transaction est (make_txid 2) 1.5 100;
  (match Fee_estimation.get_bucket_stats est 0 with
   | None -> Alcotest.fail "bucket 0 should exist"
   | Some stats ->
     Alcotest.(check int) "1.5 in bucket 0" 2 stats.unconfirmed);
  (* 2000.0+ should go to last bucket *)
  Fee_estimation.track_transaction est (make_txid 3) 5000.0 100;
  let last_bucket = Fee_estimation.bucket_count est - 1 in
  match Fee_estimation.get_bucket_stats est last_bucket with
  | None -> Alcotest.fail "last bucket should exist"
  | Some stats ->
    Alcotest.(check int) "5000 in last bucket" 1 stats.unconfirmed

let test_bucket_stats () =
  let est = Fee_estimation.create () in
  (* Add some data to bucket 9 (50.0-75.0) *)
  for i = 1 to 5 do
    let txid = make_txid i in
    Fee_estimation.track_transaction est txid 50.0 100;
    Fee_estimation.record_confirmation est txid (100 + i)
  done;
  match Fee_estimation.get_bucket_stats est 9 with
  | None -> Alcotest.fail "bucket should exist"
  | Some stats ->
    Alcotest.(check (float 0.01)) "min rate" 50.0 stats.min_rate;
    Alcotest.(check (float 0.01)) "max rate" 75.0 stats.max_rate;
    Alcotest.(check int) "confirmed" 5 stats.confirmed;
    Alcotest.(check int) "sample count" 5 stats.sample_count

let test_bucket_out_of_range () =
  let est = Fee_estimation.create () in
  let result = Fee_estimation.get_bucket_stats est 100 in
  Alcotest.(check bool) "invalid bucket returns None" true
    (Option.is_none result);
  let result2 = Fee_estimation.get_bucket_stats est (-1) in
  Alcotest.(check bool) "negative bucket returns None" true
    (Option.is_none result2)

(* ============================================================================
   Sample Management Tests
   ============================================================================ *)

let test_max_samples_per_bucket () =
  let est = Fee_estimation.create () in
  (* Add more than max_samples_per_bucket confirmations *)
  for i = 1 to 1100 do
    let txid = make_txid i in
    Fee_estimation.track_transaction est txid 50.0 100;
    Fee_estimation.record_confirmation est txid 102
  done;
  match Fee_estimation.get_bucket_stats est 9 with
  | None -> Alcotest.fail "bucket should exist"
  | Some stats ->
    (* Should be capped at 1000 samples *)
    Alcotest.(check bool) "samples capped at 1000" true
      (stats.sample_count <= 1000);
    Alcotest.(check int) "total confirmed" 1100 stats.confirmed

(* ============================================================================
   Clear Tests
   ============================================================================ *)

let test_clear () =
  let est = Fee_estimation.create () in
  (* Add some data *)
  for i = 1 to 20 do
    let txid = make_txid i in
    Fee_estimation.track_transaction est txid 50.0 100;
    if i <= 10 then
      Fee_estimation.record_confirmation est txid 102
  done;
  Alcotest.(check int) "10 tracked" 10 (Fee_estimation.tracked_count est);
  (* Clear everything *)
  Fee_estimation.clear est;
  Alcotest.(check int) "no tracked after clear" 0
    (Fee_estimation.tracked_count est);
  match Fee_estimation.get_bucket_stats est 9 with
  | None -> Alcotest.fail "bucket should exist"
  | Some stats ->
    Alcotest.(check int) "confirmed cleared" 0 stats.confirmed;
    Alcotest.(check int) "unconfirmed cleared" 0 stats.unconfirmed;
    Alcotest.(check int) "samples cleared" 0 stats.sample_count

(* ============================================================================
   Process Block Tests
   ============================================================================ *)

let test_process_block () =
  let est = Fee_estimation.create () in
  (* Track a transaction *)
  let tx = make_test_tx () in
  let txid = Crypto.compute_txid tx in
  Fee_estimation.track_transaction est txid 50.0 100;
  Alcotest.(check int) "tracked" 1 (Fee_estimation.tracked_count est);
  (* Process a block containing this transaction *)
  let block = Types.{
    header = {
      version = 1l;
      prev_block = Types.zero_hash;
      merkle_root = Types.zero_hash;
      timestamp = 0l;
      bits = 0x207fffffl;
      nonce = 0l;
    };
    transactions = [tx];
  } in
  Fee_estimation.process_block est block 105;
  (* Should update height and record confirmation *)
  Alcotest.(check int) "height updated" 105
    (Fee_estimation.current_height est);
  Alcotest.(check int) "tx confirmed" 0
    (Fee_estimation.tracked_count est)

(* ============================================================================
   Priority Estimates Tests
   ============================================================================ *)

let test_priority_estimates_with_varied_data () =
  let est = Fee_estimation.create () in
  (* High fee rate: confirms in 1 block *)
  for i = 1 to 15 do
    let txid = make_txid i in
    Fee_estimation.track_transaction est txid 200.0 100;
    Fee_estimation.record_confirmation est txid 101
  done;
  (* Medium fee rate: confirms in 5 blocks *)
  for i = 100 to 114 do
    let txid = make_txid i in
    Fee_estimation.track_transaction est txid 30.0 100;
    Fee_estimation.record_confirmation est txid 105
  done;
  (* Low fee rate: confirms in 20 blocks *)
  for i = 200 to 214 do
    let txid = make_txid i in
    Fee_estimation.track_transaction est txid 5.0 100;
    Fee_estimation.record_confirmation est txid 120
  done;
  let high = Fee_estimation.estimate_high_priority est in
  let medium = Fee_estimation.estimate_medium_priority est in
  let low = Fee_estimation.estimate_low_priority est in
  (* High priority (1 block): 200 sat/vB is only one that confirms in 1 *)
  Alcotest.(check (float 0.01)) "high priority" 200.0 high;
  (* Medium priority (6 blocks): 30 sat/vB confirms in 5 *)
  Alcotest.(check (float 0.01)) "medium priority" 30.0 medium;
  (* Low priority (25 blocks): 5 sat/vB confirms in 20 *)
  Alcotest.(check (float 0.01)) "low priority" 5.0 low

(* ============================================================================
   Test Runner
   ============================================================================ *)

let () =
  let open Alcotest in
  run "Fee_estimation" [
    "basic", [
      test_case "create" `Quick test_create;
      test_case "track transaction" `Quick test_track_transaction;
      test_case "remove transaction" `Quick test_remove_transaction;
      test_case "record confirmation" `Quick test_record_confirmation;
    ];
    "estimation", [
      test_case "insufficient data" `Quick test_estimate_insufficient_data;
      test_case "with data" `Quick test_estimate_with_data;
      test_case "target blocks" `Quick test_estimate_target_blocks;
      test_case "finds lowest sufficient" `Quick test_estimate_finds_lowest_sufficient;
    ];
    "buckets", [
      test_case "boundaries" `Quick test_bucket_boundaries;
      test_case "stats" `Quick test_bucket_stats;
      test_case "out of range" `Quick test_bucket_out_of_range;
    ];
    "samples", [
      test_case "max samples per bucket" `Quick test_max_samples_per_bucket;
    ];
    "clear", [
      test_case "clear" `Quick test_clear;
    ];
    "process_block", [
      test_case "process block" `Quick test_process_block;
    ];
    "priorities", [
      test_case "varied data" `Quick test_priority_estimates_with_varied_data;
    ];
  ]
