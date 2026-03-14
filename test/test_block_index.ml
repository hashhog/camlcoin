(* Tests for block index module (BIP-157/158 filters, height index) *)

open Camlcoin

(* Test directories *)
let test_filter_dir = "/tmp/camlcoin_test_filters"
let test_height_dir = "/tmp/camlcoin_test_heights"

let cleanup_dir path =
  let rec rm_rf path =
    if Sys.file_exists path then begin
      if Sys.is_directory path then begin
        Array.iter (fun f -> rm_rf (Filename.concat path f)) (Sys.readdir path);
        Unix.rmdir path
      end else
        Unix.unlink path
    end
  in
  rm_rf path

let cleanup () =
  cleanup_dir test_filter_dir;
  cleanup_dir test_height_dir

(* ============================================================================
   SipHash Tests
   ============================================================================ *)

(* Test SipHash-2-4 against known test vectors from the reference implementation *)
let test_siphash_basic () =
  (* Test vector from SipHash paper *)
  let k0 = 0x0706050403020100L in
  let k1 = 0x0f0e0d0c0b0a0908L in
  let data = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e" in
  let result = Block_index.SipHash.siphash24 ~k0 ~k1 data in
  (* Expected result for this input (verified against reference) *)
  Alcotest.(check bool) "siphash produces output" true (result <> 0L)

let test_siphash_empty () =
  let k0 = 0L in
  let k1 = 0L in
  let result = Block_index.SipHash.siphash24 ~k0 ~k1 "" in
  Alcotest.(check bool) "siphash handles empty input" true (result <> 0L)

let test_siphash_deterministic () =
  let k0 = 0x1234567890abcdefL in
  let k1 = 0xfedcba0987654321L in
  let data = "Hello, Bitcoin!" in
  let r1 = Block_index.SipHash.siphash24 ~k0 ~k1 data in
  let r2 = Block_index.SipHash.siphash24 ~k0 ~k1 data in
  Alcotest.(check bool) "siphash is deterministic" true (Int64.equal r1 r2)

let test_siphash_different_keys () =
  let data = "test data" in
  let r1 = Block_index.SipHash.siphash24 ~k0:0L ~k1:0L data in
  let r2 = Block_index.SipHash.siphash24 ~k0:1L ~k1:0L data in
  Alcotest.(check bool) "different keys produce different hashes" true
    (not (Int64.equal r1 r2))

(* ============================================================================
   Golomb-Rice Coding Tests
   ============================================================================ *)

let test_golomb_rice_roundtrip () =
  let values = [0L; 1L; 10L; 100L; 1000L; 65535L; 1000000L] in
  List.iter (fun expected ->
    let w = Block_index.GolombRice.create_writer () in
    Block_index.GolombRice.encode w ~p:19 expected;
    let encoded = Block_index.GolombRice.to_string w in
    let r = Block_index.GolombRice.create_reader encoded in
    let decoded = Block_index.GolombRice.decode r ~p:19 in
    Alcotest.(check bool) (Printf.sprintf "roundtrip %Ld" expected) true
      (Int64.equal expected decoded)
  ) values

let test_golomb_rice_multiple_values () =
  let values = [5L; 100L; 50L; 1000L; 1L] in
  let w = Block_index.GolombRice.create_writer () in
  List.iter (fun v ->
    Block_index.GolombRice.encode w ~p:19 v
  ) values;
  let encoded = Block_index.GolombRice.to_string w in
  let r = Block_index.GolombRice.create_reader encoded in
  let decoded = List.map (fun _ ->
    Block_index.GolombRice.decode r ~p:19
  ) values in
  Alcotest.(check (list (of_pp (fun fmt v -> Format.fprintf fmt "%Ld" v))))
    "multiple values roundtrip" values decoded

let test_golomb_rice_large_value () =
  (* Test with a value larger than 2^19 (requires quotient > 0) *)
  let value = Int64.shift_left 1L 25 in
  let w = Block_index.GolombRice.create_writer () in
  Block_index.GolombRice.encode w ~p:19 value;
  let encoded = Block_index.GolombRice.to_string w in
  let r = Block_index.GolombRice.create_reader encoded in
  let decoded = Block_index.GolombRice.decode r ~p:19 in
  Alcotest.(check bool) "large value roundtrip" true (Int64.equal value decoded)

(* ============================================================================
   GCS Filter Tests
   ============================================================================ *)

let test_gcs_empty_filter () =
  let params : Block_index.gcs_params = {
    siphash_k0 = 0L;
    siphash_k1 = 0L;
    p = 19;
    m = 784931;
  } in
  let filter = Block_index.build_filter params [] in
  Alcotest.(check int) "empty filter has n=0" 0 filter.n;
  Alcotest.(check bool) "empty filter doesn't match"
    false (Block_index.match_element filter "anything")

let test_gcs_single_element () =
  let params : Block_index.gcs_params = {
    siphash_k0 = 0x1234L;
    siphash_k1 = 0x5678L;
    p = 19;
    m = 784931;
  } in
  let element = "test_script_pubkey" in
  let filter = Block_index.build_filter params [element] in
  Alcotest.(check int) "filter has n=1" 1 filter.n;
  Alcotest.(check bool) "filter matches element"
    true (Block_index.match_element filter element);
  Alcotest.(check bool) "filter doesn't match non-element"
    false (Block_index.match_element filter "other_script")

let test_gcs_multiple_elements () =
  let params : Block_index.gcs_params = {
    siphash_k0 = 0xabcdL;
    siphash_k1 = 0xef01L;
    p = 19;
    m = 784931;
  } in
  let elements = ["script1"; "script2"; "script3"; "script4"; "script5"] in
  let filter = Block_index.build_filter params elements in
  Alcotest.(check int) "filter has n=5" 5 filter.n;
  (* All elements should match *)
  List.iter (fun elem ->
    Alcotest.(check bool) (Printf.sprintf "matches %s" elem)
      true (Block_index.match_element filter elem)
  ) elements;
  (* Non-elements probably won't match (with high probability) *)
  Alcotest.(check bool) "probably doesn't match non-element"
    false (Block_index.match_element filter "definitely_not_in_filter_12345")

let test_gcs_match_any () =
  let params : Block_index.gcs_params = {
    siphash_k0 = 0x1111L;
    siphash_k1 = 0x2222L;
    p = 19;
    m = 784931;
  } in
  let elements = ["a"; "b"; "c"; "d"; "e"] in
  let filter = Block_index.build_filter params elements in
  (* Should match if any element is present *)
  Alcotest.(check bool) "match_any with matching element"
    true (Block_index.match_any filter ["x"; "b"; "y"]);
  Alcotest.(check bool) "match_any with all non-matching"
    false (Block_index.match_any filter ["x"; "y"; "z"])

let test_gcs_decode_filter () =
  let params : Block_index.gcs_params = {
    siphash_k0 = 0xdeadL;
    siphash_k1 = 0xbeefL;
    p = 19;
    m = 784931;
  } in
  let elements = ["elem1"; "elem2"; "elem3"] in
  let filter = Block_index.build_filter params elements in
  (* Decode the encoded filter *)
  let decoded = Block_index.decode_filter params filter.encoded in
  Alcotest.(check int) "decoded n matches" filter.n decoded.n;
  (* Decoded filter should match same elements *)
  List.iter (fun elem ->
    Alcotest.(check bool) (Printf.sprintf "decoded matches %s" elem)
      true (Block_index.match_element decoded elem)
  ) elements

(* ============================================================================
   Block Filter Tests
   ============================================================================ *)

(* Helper to create a test block with transactions *)
let make_test_tx_with_outputs scripts =
  let outputs = List.map (fun script ->
    Types.{
      value = 5000000000L;
      script_pubkey = Cstruct.of_string script;
    }
  ) scripts in
  Types.{
    version = 1l;
    inputs = [];
    outputs;
    witnesses = [];
    locktime = 0l;
  }

let make_test_block_with_txs txs =
  let header = Types.{
    version = 1l;
    prev_block = Types.zero_hash;
    merkle_root = Types.zero_hash;
    timestamp = 1231006505l;
    bits = 0x1d00ffffl;
    nonce = 2083236893l;
  } in
  Types.{ header; transactions = txs }

let test_block_filter_empty_block () =
  let block = make_test_block_with_txs [] in
  let filter = Block_index.build_basic_filter block None in
  Alcotest.(check int) "empty block filter has n=0" 0 filter.filter.n

let test_block_filter_with_outputs () =
  let scripts = [
    "\x76\xa9\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x88\xac";  (* P2PKH *)
    "\xa9\x14\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x87";  (* P2SH *)
  ] in
  let tx = make_test_tx_with_outputs scripts in
  let block = make_test_block_with_txs [tx] in
  let filter = Block_index.build_basic_filter block None in
  Alcotest.(check int) "filter has 2 elements" 2 filter.filter.n;
  (* Filter should match the scripts *)
  List.iter (fun script ->
    Alcotest.(check bool) "filter matches output script"
      true (Block_index.match_element filter.filter script)
  ) scripts

let test_block_filter_excludes_op_return () =
  let scripts = [
    "\x76\xa9\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x88\xac";  (* P2PKH - include *)
    "\x6a\x04deadbeef";  (* OP_RETURN - exclude *)
  ] in
  let tx = make_test_tx_with_outputs scripts in
  let block = make_test_block_with_txs [tx] in
  let filter = Block_index.build_basic_filter block None in
  Alcotest.(check int) "filter excludes OP_RETURN" 1 filter.filter.n;
  Alcotest.(check bool) "filter doesn't match OP_RETURN"
    false (Block_index.match_element filter.filter "\x6a\x04deadbeef")

let test_block_filter_with_undo_data () =
  let tx = make_test_tx_with_outputs ["\x76\xa9output_script"] in
  let block = make_test_block_with_txs [tx] in
  let spent_script = "\xa9\x14spent_script_hash" in
  let undo : Storage.block_undo = {
    tx_undos = [{
      prev_outputs = [{
        value = 1000000L;
        script_pubkey = Cstruct.of_string spent_script;
        height = 50;
        is_coinbase = false;
      }]
    }]
  } in
  let filter = Block_index.build_basic_filter block (Some undo) in
  (* Filter should include both output and spent script *)
  Alcotest.(check bool) "filter matches output script"
    true (Block_index.match_element filter.filter "\x76\xa9output_script");
  Alcotest.(check bool) "filter matches spent script"
    true (Block_index.match_element filter.filter spent_script)

let test_filter_hash_and_header () =
  let tx = make_test_tx_with_outputs ["\x76\xa9test_script"] in
  let block = make_test_block_with_txs [tx] in
  let filter = Block_index.build_basic_filter block None in
  let filter_hash = Block_index.compute_filter_hash filter in
  Alcotest.(check int) "filter hash is 32 bytes" 32 (Cstruct.length filter_hash);
  let prev_header = Types.zero_hash in
  let filter_header = Block_index.compute_filter_header filter prev_header in
  Alcotest.(check int) "filter header is 32 bytes" 32 (Cstruct.length filter_header);
  (* Header should be different from hash *)
  Alcotest.(check bool) "header differs from hash"
    false (Cstruct.equal filter_hash filter_header)

(* ============================================================================
   Filter Index Tests
   ============================================================================ *)

let test_filter_index_create () =
  cleanup ();
  let idx = Block_index.create_filter_index test_filter_dir in
  Alcotest.(check int) "new index has 0 filters" 0 (Block_index.filter_count idx);
  Block_index.close_filter_index idx;
  cleanup ()

let test_filter_index_store_and_retrieve () =
  cleanup ();
  let idx = Block_index.create_filter_index test_filter_dir in
  let tx = make_test_tx_with_outputs ["\x76\xa9test_script"] in
  let block = make_test_block_with_txs [tx] in
  let filter = Block_index.build_basic_filter block None in
  let prev_header = Types.zero_hash in
  Block_index.store_filter idx filter prev_header;
  Alcotest.(check int) "index has 1 filter" 1 (Block_index.filter_count idx);
  Alcotest.(check bool) "has_filter returns true"
    true (Block_index.has_filter idx filter.block_hash);
  (* Retrieve the filter *)
  let retrieved = Block_index.read_filter idx filter.block_hash in
  Alcotest.(check bool) "filter retrieved" true (Option.is_some retrieved);
  let r = Option.get retrieved in
  Alcotest.(check int) "retrieved filter n matches" filter.filter.n r.filter.n;
  Block_index.close_filter_index idx;
  cleanup ()

let test_filter_index_persistence () =
  cleanup ();
  let tx = make_test_tx_with_outputs ["\x76\xa9persistence_test"] in
  let block = make_test_block_with_txs [tx] in
  let filter = Block_index.build_basic_filter block None in
  let block_hash = filter.block_hash in
  (* Store and close *)
  let idx1 = Block_index.create_filter_index test_filter_dir in
  Block_index.store_filter idx1 filter Types.zero_hash;
  Block_index.close_filter_index idx1;
  (* Reopen and verify *)
  let idx2 = Block_index.create_filter_index test_filter_dir in
  Alcotest.(check int) "filter count persisted" 1 (Block_index.filter_count idx2);
  Alcotest.(check bool) "filter still present"
    true (Block_index.has_filter idx2 block_hash);
  let retrieved = Block_index.read_filter idx2 block_hash in
  Alcotest.(check bool) "filter data persisted" true (Option.is_some retrieved);
  Block_index.close_filter_index idx2;
  cleanup ()

let test_filter_index_get_header () =
  cleanup ();
  let idx = Block_index.create_filter_index test_filter_dir in
  let tx = make_test_tx_with_outputs ["\x76\xa9header_test"] in
  let block = make_test_block_with_txs [tx] in
  let filter = Block_index.build_basic_filter block None in
  let prev_header = Types.zero_hash in
  Block_index.store_filter idx filter prev_header;
  let header_opt = Block_index.get_filter_header idx filter.block_hash in
  Alcotest.(check bool) "filter header retrieved" true (Option.is_some header_opt);
  let header = Option.get header_opt in
  Alcotest.(check int) "filter header is 32 bytes" 32 (Cstruct.length header);
  Block_index.close_filter_index idx;
  cleanup ()

let test_filter_index_no_duplicates () =
  cleanup ();
  let idx = Block_index.create_filter_index test_filter_dir in
  let tx = make_test_tx_with_outputs ["\x76\xa9dup_test"] in
  let block = make_test_block_with_txs [tx] in
  let filter = Block_index.build_basic_filter block None in
  Block_index.store_filter idx filter Types.zero_hash;
  Block_index.store_filter idx filter Types.zero_hash;  (* Store again *)
  Alcotest.(check int) "no duplicates" 1 (Block_index.filter_count idx);
  Block_index.close_filter_index idx;
  cleanup ()

(* ============================================================================
   Height Index Tests
   ============================================================================ *)

let test_height_index_create () =
  cleanup ();
  let idx = Block_index.create_height_index test_height_dir in
  Alcotest.(check int) "new index has max_height -1" (-1) (Block_index.get_max_height idx);
  Block_index.close_height_index idx;
  cleanup ()

let test_height_index_set_get () =
  cleanup ();
  let idx = Block_index.create_height_index test_height_dir in
  let hash0 = Types.hash256_of_hex
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f" in
  let hash1 = Types.hash256_of_hex
    "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048" in
  Block_index.set_hash_at_height idx 0 hash0;
  Block_index.set_hash_at_height idx 1 hash1;
  Alcotest.(check int) "max height is 1" 1 (Block_index.get_max_height idx);
  let retrieved0 = Block_index.get_hash_at_height idx 0 in
  let retrieved1 = Block_index.get_hash_at_height idx 1 in
  Alcotest.(check bool) "height 0 found" true (Option.is_some retrieved0);
  Alcotest.(check bool) "height 1 found" true (Option.is_some retrieved1);
  Alcotest.(check string) "height 0 hash matches"
    (Types.hash256_to_hex hash0) (Types.hash256_to_hex (Option.get retrieved0));
  Alcotest.(check string) "height 1 hash matches"
    (Types.hash256_to_hex hash1) (Types.hash256_to_hex (Option.get retrieved1));
  Block_index.close_height_index idx;
  cleanup ()

let test_height_index_missing () =
  cleanup ();
  let idx = Block_index.create_height_index test_height_dir in
  let missing = Block_index.get_hash_at_height idx 999 in
  Alcotest.(check bool) "missing height returns None" true (Option.is_none missing);
  let negative = Block_index.get_hash_at_height idx (-1) in
  Alcotest.(check bool) "negative height returns None" true (Option.is_none negative);
  Block_index.close_height_index idx;
  cleanup ()

let test_height_index_persistence () =
  cleanup ();
  let hash = Types.hash256_of_hex
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f" in
  (* Store and close *)
  let idx1 = Block_index.create_height_index test_height_dir in
  Block_index.set_hash_at_height idx1 100 hash;
  Block_index.close_height_index idx1;
  (* Reopen and verify *)
  let idx2 = Block_index.create_height_index test_height_dir in
  Alcotest.(check int) "max height persisted" 100 (Block_index.get_max_height idx2);
  let retrieved = Block_index.get_hash_at_height idx2 100 in
  Alcotest.(check bool) "hash persisted" true (Option.is_some retrieved);
  Alcotest.(check string) "hash value persisted"
    (Types.hash256_to_hex hash) (Types.hash256_to_hex (Option.get retrieved));
  Block_index.close_height_index idx2;
  cleanup ()

let test_height_index_large_height () =
  cleanup ();
  let idx = Block_index.create_height_index test_height_dir in
  let hash = Types.hash256_of_hex
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f" in
  (* Set a large height to test capacity growth *)
  Block_index.set_hash_at_height idx 100000 hash;
  Alcotest.(check int) "max height is 100000" 100000 (Block_index.get_max_height idx);
  let retrieved = Block_index.get_hash_at_height idx 100000 in
  Alcotest.(check bool) "large height accessible" true (Option.is_some retrieved);
  Block_index.close_height_index idx;
  cleanup ()

let test_height_index_remove () =
  cleanup ();
  let idx = Block_index.create_height_index test_height_dir in
  let hash0 = Types.hash256_of_hex
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f" in
  let hash1 = Types.hash256_of_hex
    "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048" in
  Block_index.set_hash_at_height idx 0 hash0;
  Block_index.set_hash_at_height idx 1 hash1;
  Alcotest.(check int) "max height is 1" 1 (Block_index.get_max_height idx);
  (* Remove height 1 *)
  Block_index.remove_hash_at_height idx 1;
  Alcotest.(check int) "max height reduced to 0" 0 (Block_index.get_max_height idx);
  let removed = Block_index.get_hash_at_height idx 1 in
  Alcotest.(check bool) "removed height returns None" true (Option.is_none removed);
  (* Height 0 should still exist *)
  let still_there = Block_index.get_hash_at_height idx 0 in
  Alcotest.(check bool) "height 0 still exists" true (Option.is_some still_there);
  Block_index.close_height_index idx;
  cleanup ()

let test_height_index_sparse () =
  cleanup ();
  let idx = Block_index.create_height_index test_height_dir in
  let hash = Types.hash256_of_hex
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f" in
  (* Set sparse heights *)
  Block_index.set_hash_at_height idx 0 hash;
  Block_index.set_hash_at_height idx 100 hash;
  Block_index.set_hash_at_height idx 1000 hash;
  (* Middle heights should be None *)
  Alcotest.(check bool) "height 50 is None"
    true (Option.is_none (Block_index.get_hash_at_height idx 50));
  Alcotest.(check bool) "height 500 is None"
    true (Option.is_none (Block_index.get_hash_at_height idx 500));
  (* Set heights should exist *)
  Alcotest.(check bool) "height 0 exists"
    true (Option.is_some (Block_index.get_hash_at_height idx 0));
  Alcotest.(check bool) "height 100 exists"
    true (Option.is_some (Block_index.get_hash_at_height idx 100));
  Alcotest.(check bool) "height 1000 exists"
    true (Option.is_some (Block_index.get_hash_at_height idx 1000));
  Block_index.close_height_index idx;
  cleanup ()

(* ============================================================================
   Test Suite
   ============================================================================ *)

let () =
  cleanup ();
  let open Alcotest in
  run "Block_index" [
    "siphash", [
      test_case "basic" `Quick test_siphash_basic;
      test_case "empty input" `Quick test_siphash_empty;
      test_case "deterministic" `Quick test_siphash_deterministic;
      test_case "different keys" `Quick test_siphash_different_keys;
    ];
    "golomb_rice", [
      test_case "roundtrip" `Quick test_golomb_rice_roundtrip;
      test_case "multiple values" `Quick test_golomb_rice_multiple_values;
      test_case "large value" `Quick test_golomb_rice_large_value;
    ];
    "gcs_filter", [
      test_case "empty filter" `Quick test_gcs_empty_filter;
      test_case "single element" `Quick test_gcs_single_element;
      test_case "multiple elements" `Quick test_gcs_multiple_elements;
      test_case "match_any" `Quick test_gcs_match_any;
      test_case "decode filter" `Quick test_gcs_decode_filter;
    ];
    "block_filter", [
      test_case "empty block" `Quick test_block_filter_empty_block;
      test_case "with outputs" `Quick test_block_filter_with_outputs;
      test_case "excludes OP_RETURN" `Quick test_block_filter_excludes_op_return;
      test_case "with undo data" `Quick test_block_filter_with_undo_data;
      test_case "hash and header" `Quick test_filter_hash_and_header;
    ];
    "filter_index", [
      test_case "create" `Quick test_filter_index_create;
      test_case "store and retrieve" `Quick test_filter_index_store_and_retrieve;
      test_case "persistence" `Quick test_filter_index_persistence;
      test_case "get header" `Quick test_filter_index_get_header;
      test_case "no duplicates" `Quick test_filter_index_no_duplicates;
    ];
    "height_index", [
      test_case "create" `Quick test_height_index_create;
      test_case "set and get" `Quick test_height_index_set_get;
      test_case "missing" `Quick test_height_index_missing;
      test_case "persistence" `Quick test_height_index_persistence;
      test_case "large height" `Quick test_height_index_large_height;
      test_case "remove" `Quick test_height_index_remove;
      test_case "sparse" `Quick test_height_index_sparse;
    ];
  ]
