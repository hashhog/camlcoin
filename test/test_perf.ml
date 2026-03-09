(* Tests for Performance Optimization module *)

open Camlcoin

(* ============================================================================
   LRU Cache Tests
   ============================================================================ *)

let test_lru_basic_operations () =
  let cache = Perf.LRU.create 5 in
  (* Test put and get *)
  Perf.LRU.put cache "a" 1;
  Perf.LRU.put cache "b" 2;
  Perf.LRU.put cache "c" 3;
  Alcotest.(check (option int)) "get existing key" (Some 1) (Perf.LRU.get cache "a");
  Alcotest.(check (option int)) "get existing key b" (Some 2) (Perf.LRU.get cache "b");
  Alcotest.(check (option int)) "get non-existent key" None (Perf.LRU.get cache "z");
  Alcotest.(check int) "cache size" 3 (Perf.LRU.size cache)

let test_lru_eviction () =
  let cache = Perf.LRU.create 3 in
  Perf.LRU.put cache "a" 1;
  Perf.LRU.put cache "b" 2;
  Perf.LRU.put cache "c" 3;
  (* Cache is now full *)
  Alcotest.(check int) "cache at capacity" 3 (Perf.LRU.size cache);
  (* Adding another should evict oldest (a) *)
  Perf.LRU.put cache "d" 4;
  Alcotest.(check int) "cache still at capacity" 3 (Perf.LRU.size cache);
  Alcotest.(check (option int)) "oldest evicted" None (Perf.LRU.get cache "a");
  Alcotest.(check (option int)) "newest present" (Some 4) (Perf.LRU.get cache "d");
  Alcotest.(check (option int)) "b still present" (Some 2) (Perf.LRU.get cache "b")

let test_lru_access_order () =
  let cache = Perf.LRU.create 3 in
  Perf.LRU.put cache "a" 1;
  Perf.LRU.put cache "b" 2;
  Perf.LRU.put cache "c" 3;
  (* Access "a" to make it most recently used *)
  ignore (Perf.LRU.get cache "a");
  (* Now add "d" - should evict "b" (least recently used) *)
  Perf.LRU.put cache "d" 4;
  Alcotest.(check (option int)) "a still present (was accessed)" (Some 1) (Perf.LRU.get cache "a");
  Alcotest.(check (option int)) "b evicted" None (Perf.LRU.get cache "b");
  Alcotest.(check (option int)) "c still present" (Some 3) (Perf.LRU.get cache "c");
  Alcotest.(check (option int)) "d present" (Some 4) (Perf.LRU.get cache "d")

let test_lru_update_existing () =
  let cache = Perf.LRU.create 3 in
  Perf.LRU.put cache "a" 1;
  Perf.LRU.put cache "b" 2;
  (* Update "a" with new value *)
  Perf.LRU.put cache "a" 10;
  Alcotest.(check (option int)) "updated value" (Some 10) (Perf.LRU.get cache "a");
  Alcotest.(check int) "size unchanged" 2 (Perf.LRU.size cache)

let test_lru_remove () =
  let cache = Perf.LRU.create 5 in
  Perf.LRU.put cache "a" 1;
  Perf.LRU.put cache "b" 2;
  Perf.LRU.remove cache "a";
  Alcotest.(check (option int)) "removed key" None (Perf.LRU.get cache "a");
  Alcotest.(check (option int)) "other key present" (Some 2) (Perf.LRU.get cache "b");
  Alcotest.(check int) "size decreased" 1 (Perf.LRU.size cache)

let test_lru_clear () =
  let cache = Perf.LRU.create 5 in
  Perf.LRU.put cache "a" 1;
  Perf.LRU.put cache "b" 2;
  Perf.LRU.put cache "c" 3;
  Perf.LRU.clear cache;
  Alcotest.(check int) "cleared cache size" 0 (Perf.LRU.size cache);
  Alcotest.(check (option int)) "cleared key a" None (Perf.LRU.get cache "a")

let test_lru_mem () =
  let cache = Perf.LRU.create 5 in
  Perf.LRU.put cache "a" 1;
  Alcotest.(check bool) "mem existing" true (Perf.LRU.mem cache "a");
  Alcotest.(check bool) "mem non-existing" false (Perf.LRU.mem cache "z")

let test_lru_capacity () =
  let cache = Perf.LRU.create 10 in
  Alcotest.(check int) "capacity" 10 (Perf.LRU.capacity cache)

(* ============================================================================
   Timer Tests
   ============================================================================ *)

let test_timer_basic () =
  let timer = Perf.Timer.create "test_timer_basic" in
  Alcotest.(check int) "initial call count" 0 timer.call_count;
  Alcotest.(check (float 0.0001)) "initial total time" 0.0 timer.total_time

let test_timer_time_function () =
  let timer = Perf.Timer.create "test_timer_time" in
  let result = Perf.Timer.time timer (fun () ->
    (* Do some work *)
    let sum = ref 0 in
    for i = 0 to 1000 do sum := !sum + i done;
    !sum
  ) in
  Alcotest.(check int) "function result" 500500 result;
  Alcotest.(check int) "call count incremented" 1 timer.call_count;
  Alcotest.(check bool) "total time increased" true (timer.total_time > 0.0)

let test_timer_avg_time () =
  let timer = Perf.Timer.create "test_timer_avg" in
  (* Run 3 times *)
  for _ = 1 to 3 do
    ignore (Perf.Timer.time timer (fun () -> ()))
  done;
  Alcotest.(check int) "call count" 3 timer.call_count;
  let avg = Perf.Timer.avg_time timer in
  Alcotest.(check bool) "avg calculated" true (avg >= 0.0)

let test_timer_reset () =
  let timer = Perf.Timer.create "test_timer_reset" in
  ignore (Perf.Timer.time timer (fun () -> ()));
  Perf.Timer.reset timer;
  Alcotest.(check int) "reset call count" 0 timer.call_count;
  Alcotest.(check (float 0.0001)) "reset total time" 0.0 timer.total_time

let test_timer_report () =
  let _ = Perf.Timer.create "test_report_timer" in
  let report = Perf.Timer.report () in
  Alcotest.(check bool) "report not empty" true (String.length report > 0)

let test_timer_to_json () =
  let _ = Perf.Timer.create "test_json_timer" in
  let json = Perf.Timer.to_json () in
  match json with
  | `Assoc _ -> Alcotest.(check pass) "json is object" () ()
  | _ -> Alcotest.fail "expected json object"

let test_predefined_timers () =
  (* Just verify the predefined timers exist *)
  Alcotest.(check string) "block_validation name" "block_validation"
    Perf.Timer.block_validation.name;
  Alcotest.(check string) "script_execution name" "script_execution"
    Perf.Timer.script_execution.name;
  Alcotest.(check string) "utxo_lookup name" "utxo_lookup"
    Perf.Timer.utxo_lookup.name;
  Alcotest.(check string) "hash_compute name" "hash_compute"
    Perf.Timer.hash_compute.name

(* ============================================================================
   Compact Headers Tests
   ============================================================================ *)

let test_compact_headers_basic () =
  let headers = Perf.CompactHeaders.create ~initial_capacity:10 () in
  Alcotest.(check int) "initial count" 0 (Perf.CompactHeaders.length headers)

let test_compact_headers_add_get () =
  let headers = Perf.CompactHeaders.create ~initial_capacity:10 () in
  (* Create a test header *)
  let header = Consensus.mainnet_genesis_header in
  Perf.CompactHeaders.add_header headers header;
  Alcotest.(check int) "count after add" 1 (Perf.CompactHeaders.length headers);
  (* Retrieve and verify *)
  let retrieved = Perf.CompactHeaders.get_header headers 0 in
  Alcotest.(check int32) "version matches" header.version retrieved.version;
  Alcotest.(check int32) "timestamp matches" header.timestamp retrieved.timestamp;
  Alcotest.(check int32) "nonce matches" header.nonce retrieved.nonce;
  Alcotest.(check int32) "bits matches" header.bits retrieved.bits

let test_compact_headers_multiple () =
  let headers = Perf.CompactHeaders.create ~initial_capacity:10 () in
  let genesis = Consensus.mainnet_genesis_header in
  (* Add multiple headers with different nonces to distinguish them *)
  for i = 0 to 4 do
    let h = { genesis with Types.nonce = Int32.of_int i } in
    Perf.CompactHeaders.add_header headers h
  done;
  Alcotest.(check int) "count" 5 (Perf.CompactHeaders.length headers);
  (* Verify each header *)
  for i = 0 to 4 do
    let retrieved = Perf.CompactHeaders.get_header headers i in
    Alcotest.(check int32) (Printf.sprintf "nonce %d" i)
      (Int32.of_int i) retrieved.nonce
  done

let test_compact_headers_grow () =
  (* Create with small capacity *)
  let headers = Perf.CompactHeaders.create ~initial_capacity:2 () in
  let genesis = Consensus.mainnet_genesis_header in
  (* Add more than initial capacity *)
  for i = 0 to 4 do
    let h = { genesis with Types.nonce = Int32.of_int i } in
    Perf.CompactHeaders.add_header headers h
  done;
  Alcotest.(check int) "count after grow" 5 (Perf.CompactHeaders.length headers);
  (* Verify data integrity after grow *)
  for i = 0 to 4 do
    let retrieved = Perf.CompactHeaders.get_header headers i in
    Alcotest.(check int32) (Printf.sprintf "nonce %d after grow" i)
      (Int32.of_int i) retrieved.nonce
  done

let test_compact_headers_clear () =
  let headers = Perf.CompactHeaders.create ~initial_capacity:10 () in
  let genesis = Consensus.mainnet_genesis_header in
  Perf.CompactHeaders.add_header headers genesis;
  Perf.CompactHeaders.add_header headers genesis;
  Perf.CompactHeaders.clear headers;
  Alcotest.(check int) "count after clear" 0 (Perf.CompactHeaders.length headers)

let test_compact_headers_out_of_bounds () =
  let headers = Perf.CompactHeaders.create ~initial_capacity:10 () in
  let raised = ref false in
  (try ignore (Perf.CompactHeaders.get_header headers 0)
   with Failure _ -> raised := true);
  Alcotest.(check bool) "out of bounds raises" true !raised

let test_compact_headers_raw_bytes () =
  let headers = Perf.CompactHeaders.create ~initial_capacity:10 () in
  (* Create and add a header *)
  let genesis = Consensus.mainnet_genesis_header in
  let w = Serialize.writer_create () in
  Serialize.serialize_block_header w genesis;
  let raw_bytes = Serialize.writer_to_cstruct w in
  (* Add using raw bytes method *)
  Perf.CompactHeaders.add headers raw_bytes;
  (* Retrieve using raw bytes method *)
  let retrieved_bytes = Perf.CompactHeaders.get headers 0 in
  Alcotest.(check int) "raw bytes length" 80 (Cstruct.length retrieved_bytes);
  (* Verify content matches *)
  Alcotest.(check bool) "raw bytes equal" true
    (Cstruct.equal raw_bytes retrieved_bytes)

(* ============================================================================
   UTXO Cache Stats Tests
   ============================================================================ *)

let test_utxo_cache_stats_create () =
  let stats = Perf.create_utxo_stats () in
  Alcotest.(check int) "initial lookups" 0 stats.lookups;
  Alcotest.(check int) "initial cache_hits" 0 stats.cache_hits;
  Alcotest.(check int) "initial db_hits" 0 stats.db_hits;
  Alcotest.(check int) "initial misses" 0 stats.misses

let test_utxo_cache_stats_hit_rate () =
  let stats = Perf.create_utxo_stats () in
  (* No lookups yet *)
  Alcotest.(check (float 0.0001)) "hit rate with no lookups" 0.0
    (Perf.utxo_hit_rate stats);
  (* Simulate some lookups *)
  stats.lookups <- 100;
  stats.cache_hits <- 75;
  stats.db_hits <- 20;
  stats.misses <- 5;
  Alcotest.(check (float 0.0001)) "75% hit rate" 0.75
    (Perf.utxo_hit_rate stats)

let test_utxo_cache_stats_to_json () =
  let stats = Perf.create_utxo_stats () in
  stats.lookups <- 100;
  stats.cache_hits <- 75;
  let json = Perf.utxo_stats_to_json stats in
  match json with
  | `Assoc fields ->
    (match List.assoc_opt "lookups" fields with
     | Some (`Int 100) -> Alcotest.(check pass) "lookups field" () ()
     | _ -> Alcotest.fail "expected lookups=100");
    (match List.assoc_opt "cache_hits" fields with
     | Some (`Int 75) -> Alcotest.(check pass) "cache_hits field" () ()
     | _ -> Alcotest.fail "expected cache_hits=75");
    (match List.assoc_opt "hit_rate" fields with
     | Some (`Float r) when r > 0.74 && r < 0.76 ->
       Alcotest.(check pass) "hit_rate field" () ()
     | _ -> Alcotest.fail "expected hit_rate ~0.75")
  | _ -> Alcotest.fail "expected json object"

(* ============================================================================
   Optimized Hash Functions Tests
   ============================================================================ *)

let test_sha256d_inplace () =
  let data = Cstruct.of_string "test data for hashing" in
  let output = Cstruct.create 32 in
  Perf.sha256d_inplace data output;
  (* Verify it produces same result as regular sha256d *)
  let expected = Crypto.sha256d data in
  Alcotest.(check bool) "sha256d_inplace matches"
    true (Cstruct.equal expected output)

let test_sha256d_fast () =
  let data = Cstruct.of_string "another test string" in
  let result = Perf.sha256d_fast data in
  (* Verify it produces same result as regular sha256d *)
  let expected = Crypto.sha256d data in
  Alcotest.(check bool) "sha256d_fast matches"
    true (Cstruct.equal expected result);
  Alcotest.(check int) "result length" 32 (Cstruct.length result)

(* ============================================================================
   Batch Processing Tests
   ============================================================================ *)

let test_process_batch_success () =
  let items = [1; 2; 3; 4; 5] in
  let sum = ref 0 in
  let result = Perf.process_batch items (fun i ->
    sum := !sum + i;
    Ok ()
  ) in
  Alcotest.(check (result int string)) "all processed" (Ok 5) result;
  Alcotest.(check int) "sum computed" 15 !sum

let test_process_batch_failure () =
  let items = [1; 2; 3; 4; 5] in
  let processed = ref 0 in
  let result = Perf.process_batch items (fun i ->
    if i = 3 then Error "stopped at 3"
    else begin
      incr processed;
      Ok ()
    end
  ) in
  match result with
  | Error "stopped at 3" ->
    Alcotest.(check int) "processed before error" 2 !processed
  | _ -> Alcotest.fail "expected error"

let test_process_batch_empty () =
  let items = [] in
  let result = Perf.process_batch items (fun _ -> Ok ()) in
  Alcotest.(check (result int string)) "empty batch" (Ok 0) result

(* ============================================================================
   Test Runner
   ============================================================================ *)

let () =
  let open Alcotest in
  run "Perf" [
    "lru_cache", [
      test_case "basic operations" `Quick test_lru_basic_operations;
      test_case "eviction" `Quick test_lru_eviction;
      test_case "access order" `Quick test_lru_access_order;
      test_case "update existing" `Quick test_lru_update_existing;
      test_case "remove" `Quick test_lru_remove;
      test_case "clear" `Quick test_lru_clear;
      test_case "mem" `Quick test_lru_mem;
      test_case "capacity" `Quick test_lru_capacity;
    ];
    "timer", [
      test_case "basic" `Quick test_timer_basic;
      test_case "time function" `Quick test_timer_time_function;
      test_case "avg time" `Quick test_timer_avg_time;
      test_case "reset" `Quick test_timer_reset;
      test_case "report" `Quick test_timer_report;
      test_case "to_json" `Quick test_timer_to_json;
      test_case "predefined timers" `Quick test_predefined_timers;
    ];
    "compact_headers", [
      test_case "basic" `Quick test_compact_headers_basic;
      test_case "add and get" `Quick test_compact_headers_add_get;
      test_case "multiple" `Quick test_compact_headers_multiple;
      test_case "grow" `Quick test_compact_headers_grow;
      test_case "clear" `Quick test_compact_headers_clear;
      test_case "out of bounds" `Quick test_compact_headers_out_of_bounds;
      test_case "raw bytes" `Quick test_compact_headers_raw_bytes;
    ];
    "utxo_cache_stats", [
      test_case "create" `Quick test_utxo_cache_stats_create;
      test_case "hit rate" `Quick test_utxo_cache_stats_hit_rate;
      test_case "to_json" `Quick test_utxo_cache_stats_to_json;
    ];
    "optimized_hash", [
      test_case "sha256d_inplace" `Quick test_sha256d_inplace;
      test_case "sha256d_fast" `Quick test_sha256d_fast;
    ];
    "batch_processing", [
      test_case "success" `Quick test_process_batch_success;
      test_case "failure" `Quick test_process_batch_failure;
      test_case "empty" `Quick test_process_batch_empty;
    ];
  ]
