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
   BIP-157 Index Bundle Tests (high-level append + backfill + rewind)
   ============================================================================ *)

let test_bip157_dir = "/tmp/camlcoin_test_bip157"

let cleanup_bip157 () =
  cleanup_dir test_bip157_dir

(* Helper: build a block with [n] outputs whose scriptPubKeys differ so
   the test can verify the filter actually includes them. We also vary
   the prev_block field to make each block hash unique — without that,
   [bip157_has_height] dedup would mask append-side bugs. *)
let make_unique_block ~(prev_block : Types.hash256) tag =
  let header = Types.{
    version = 1l;
    prev_block;
    merkle_root = Types.zero_hash;
    timestamp = Int32.of_int (1231006505 + tag);
    bits = 0x1d00ffffl;
    nonce = Int32.of_int (2083236893 + tag);
  } in
  let scripts = [
    Printf.sprintf "\x76\xa9\x14unique_%020dXX\x88\xac" tag;
  ] in
  let tx = make_test_tx_with_outputs scripts in
  Types.{ header; transactions = [tx] }

(* Sanity: opening + closing an empty bundle leaves best_height = -1 and
   creates the [<data_dir>/indexes/blockfilter/basic] directory. *)
let test_bip157_create_empty () =
  cleanup_bip157 ();
  let idx = Block_index.create_bip157_index ~data_dir:test_bip157_dir in
  Alcotest.(check int) "empty bundle best_height = -1"
    (-1) (Block_index.bip157_best_height idx);
  Alcotest.(check bool) "filter sub-dir exists" true
    (Sys.file_exists (Filename.concat test_bip157_dir "indexes/blockfilter/basic"));
  Block_index.close_bip157_index idx;
  cleanup_bip157 ()

(* End-to-end: append a chain of 3 blocks, verify each is indexed and
   each filter header chains against the previous filter header
   (filter_header[0] = SHA256d(filter_hash[0] || zero_hash);
    filter_header[h] = SHA256d(filter_hash[h] || filter_header[h-1])). *)
let test_bip157_append_chain () =
  cleanup_bip157 ();
  let idx = Block_index.create_bip157_index ~data_dir:test_bip157_dir in
  let prev_block = ref Types.zero_hash in
  let block_hashes = ref [] in
  for h = 0 to 2 do
    let block = make_unique_block ~prev_block:!prev_block h in
    let block_hash = Crypto.compute_block_hash block.header in
    block_hashes := block_hash :: !block_hashes;
    prev_block := block_hash;
    let r = Block_index.append_block_filter idx
              ~block ~height:h ~spent_scripts:[] in
    Alcotest.(check bool) (Printf.sprintf "append height=%d ok" h)
      true (match r with Ok () -> true | Error _ -> false)
  done;
  Alcotest.(check int) "best_height advanced to 2"
    2 (Block_index.bip157_best_height idx);
  (* Idempotent re-append at height 0: a no-op, must not raise. *)
  let block0 = make_unique_block ~prev_block:Types.zero_hash 0 in
  let r = Block_index.append_block_filter idx
            ~block:block0 ~height:0 ~spent_scripts:[] in
  Alcotest.(check bool) "idempotent re-append" true
    (match r with Ok () -> true | Error _ -> false);
  Alcotest.(check int) "best_height unchanged after idempotent append"
    2 (Block_index.bip157_best_height idx);
  (* Filter header chaining: pull filter_header at heights 0..2 and
     verify they match the chained recomputation. *)
  let block_hashes = List.rev !block_hashes in  (* now in height order 0..2 *)
  let prev_fh = ref Types.zero_hash in
  List.iteri (fun h hash ->
    let bf = match Block_index.read_filter idx.filter_idx hash with
      | Some f -> f | None -> Alcotest.fail "filter missing" in
    let expected_fh = Block_index.compute_filter_header bf !prev_fh in
    let stored_fh = match Block_index.get_filter_header idx.filter_idx hash with
      | Some f -> f | None -> Alcotest.fail "filter_header missing" in
    Alcotest.(check string)
      (Printf.sprintf "filter header chain at height %d" h)
      (Cstruct.to_string expected_fh)
      (Cstruct.to_string stored_fh);
    prev_fh := stored_fh
  ) block_hashes;
  Block_index.close_bip157_index idx;
  cleanup_bip157 ()

(* The "parent not indexed" guard: appending at height 5 with no chain
   below it must fail with a backfill-needed error, not silently chain
   against zero_hash (which would corrupt the filter-header chain). *)
let test_bip157_append_skip_height_rejected () =
  cleanup_bip157 ();
  let idx = Block_index.create_bip157_index ~data_dir:test_bip157_dir in
  let block = make_unique_block ~prev_block:Types.zero_hash 5 in
  let r = Block_index.append_block_filter idx
            ~block ~height:5 ~spent_scripts:[] in
  (match r with
   | Ok () -> Alcotest.fail "append at height 5 should be rejected"
   | Error msg ->
     Alcotest.(check bool) "error mentions backfill"
       true (try
               let _ = Str.search_forward
                 (Str.regexp_string "backfill") msg 0 in true
             with Not_found -> false));
  Alcotest.(check int) "no entries indexed"
    (-1) (Block_index.bip157_best_height idx);
  Block_index.close_bip157_index idx;
  cleanup_bip157 ()

(* Reorg-style rewind: append heights 0..4, then rewind to height 2.
   Heights 3 and 4 must drop from both the filter index and the
   height->hash sidecar; heights 0..2 must stay. *)
let test_bip157_rewind_drops_above_target () =
  cleanup_bip157 ();
  let idx = Block_index.create_bip157_index ~data_dir:test_bip157_dir in
  let prev_block = ref Types.zero_hash in
  let block_hashes = Array.make 5 Types.zero_hash in
  for h = 0 to 4 do
    let block = make_unique_block ~prev_block:!prev_block h in
    let block_hash = Crypto.compute_block_hash block.header in
    block_hashes.(h) <- block_hash;
    prev_block := block_hash;
    let _ = Block_index.append_block_filter idx
              ~block ~height:h ~spent_scripts:[] in ()
  done;
  Alcotest.(check int) "pre-rewind best_height = 4"
    4 (Block_index.bip157_best_height idx);
  Block_index.rewind_bip157_index idx ~target_height:2;
  Alcotest.(check int) "post-rewind best_height = 2"
    2 (Block_index.bip157_best_height idx);
  Alcotest.(check bool) "height 4 filter dropped" false
    (Block_index.has_filter idx.filter_idx block_hashes.(4));
  Alcotest.(check bool) "height 3 filter dropped" false
    (Block_index.has_filter idx.filter_idx block_hashes.(3));
  Alcotest.(check bool) "height 2 filter retained" true
    (Block_index.has_filter idx.filter_idx block_hashes.(2));
  Alcotest.(check bool) "height 0 filter retained" true
    (Block_index.has_filter idx.filter_idx block_hashes.(0));
  (* After rewind, re-appending the dropped heights must succeed
     (parent at height 2 is still indexed, so the chain reconnects). *)
  let block3 = make_unique_block ~prev_block:block_hashes.(2) 3 in
  let r = Block_index.append_block_filter idx
            ~block:block3 ~height:3 ~spent_scripts:[] in
  Alcotest.(check bool) "post-rewind re-append succeeds" true
    (match r with Ok () -> true | Error _ -> false);
  Block_index.close_bip157_index idx;
  cleanup_bip157 ()

(* Persistence across close+reopen: the bundle must reload its
   best_height and filter contents from disk so a daemon restart
   doesn't trigger a wasteful full backfill. *)
let test_bip157_persistence () =
  cleanup_bip157 ();
  let prev_block = ref Types.zero_hash in
  let last_hash = ref Types.zero_hash in
  let idx1 = Block_index.create_bip157_index ~data_dir:test_bip157_dir in
  for h = 0 to 2 do
    let block = make_unique_block ~prev_block:!prev_block h in
    let block_hash = Crypto.compute_block_hash block.header in
    last_hash := block_hash;
    prev_block := block_hash;
    let _ = Block_index.append_block_filter idx1
              ~block ~height:h ~spent_scripts:[] in ()
  done;
  Block_index.close_bip157_index idx1;
  let idx2 = Block_index.create_bip157_index ~data_dir:test_bip157_dir in
  Alcotest.(check int) "best_height persisted"
    2 (Block_index.bip157_best_height idx2);
  Alcotest.(check bool) "filter for last height retained across reopen"
    true (Block_index.has_filter idx2.filter_idx !last_hash);
  Block_index.close_bip157_index idx2;
  cleanup_bip157 ()

(* ============================================================================
   BIP-158 Official Test Vectors

   These vectors are from Bitcoin Core's test/data/blockfilters.json and
   the BIP-158 reference implementation.  Each entry specifies a raw block
   (hex), a list of previous-output scriptPubKeys spent in the block (hex),
   the expected basic filter (hex), and the expected filter header (hex).

   The filters and headers are compared byte-for-byte so any deviation in:
     - SipHash key derivation (filter_key_of_block_hash)
     - FastRange64 mapping
     - Golomb-Rice encode/decode
     - OP_RETURN / empty-script exclusion rules
     - SHA256d chain for filter_hash + filter_header
   will cause a test failure.
   ============================================================================ *)

(** Decode a hex string to a raw byte string *)
let hex_decode (s : string) : string =
  let n = String.length s in
  assert (n mod 2 = 0);
  Bytes.init (n / 2) (fun i ->
    Char.chr (int_of_string ("0x" ^ String.sub s (i * 2) 2))
  ) |> Bytes.to_string

(** Encode bytes to lowercase hex *)
let hex_encode (s : string) : string =
  let buf = Buffer.create (String.length s * 2) in
  String.iter (fun c ->
    Buffer.add_string buf (Printf.sprintf "%02x" (Char.code c))
  ) s;
  Buffer.contents buf

(** Build a block_filter from a raw block hex + list of spent scriptPubKey hexes.
    The block is deserialized from its wire format; each prev_script_hex is a
    hex-encoded scriptPubKey of a spent output.  This mirrors Bitcoin Core's
    BlockFilter(BlockFilterType::BASIC, block, block_undo) constructor. *)
let build_filter_from_hex (block_hex : string) (prev_script_hexes : string list)
    : Block_index.block_filter =
  let raw_block = hex_decode block_hex in
  let r = Serialize.reader_of_cstruct (Cstruct.of_string raw_block) in
  let block = Serialize.deserialize_block r in
  let spent_scripts = List.map (fun h ->
    Cstruct.of_string (hex_decode h)
  ) prev_script_hexes in
  Block_index.build_basic_filter_from_scripts block spent_scripts

(** Compute the filter header given a filter and a previous header hex string. *)
let compute_header_from_hex (bf : Block_index.block_filter) (prev_hex : string)
    : string =
  let prev_bytes = hex_decode prev_hex in
  (* prev_hex is in "display" order (reversed) — convert to internal byte order *)
  let prev_len = String.length prev_bytes in
  assert (prev_len = 32);
  let prev_internal = Cstruct.create 32 in
  for i = 0 to 31 do
    Cstruct.set_uint8 prev_internal i
      (Char.code (String.get prev_bytes (31 - i)))
  done;
  let header = Block_index.compute_filter_header bf prev_internal in
  (* Return in display order (reversed) *)
  let buf = Buffer.create 64 in
  for i = 31 downto 0 do
    Buffer.add_string buf (Printf.sprintf "%02x" (Cstruct.get_uint8 header i))
  done;
  Buffer.contents buf

(* BIP-158 test vector: block height 0 (testnet genesis block).
   Reference: bitcoin-core/src/test/data/blockfilters.json row 1.
   Expected basic filter bytes: 019dfca8
   Expected basic header: 21584579b7eb08997773e5aeff3a7f932700042d0ed2a6129012b7d7ae81b750 *)
let test_bip158_vector_genesis () =
  let block_hex = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae180101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000" in
  let prev_scripts = [] in
  let prev_header_hex =
    "0000000000000000000000000000000000000000000000000000000000000000" in
  let expected_filter_hex = "019dfca8" in
  let expected_header_hex =
    "21584579b7eb08997773e5aeff3a7f932700042d0ed2a6129012b7d7ae81b750" in

  let bf = build_filter_from_hex block_hex prev_scripts in
  let actual_filter_hex = hex_encode bf.Block_index.filter.Block_index.encoded in
  Alcotest.(check string) "genesis filter bytes" expected_filter_hex actual_filter_hex;

  let actual_header_hex = compute_header_from_hex bf prev_header_hex in
  Alcotest.(check string) "genesis filter header" expected_header_hex actual_header_hex

(* BIP-158 test vector: block height 2 (testnet).
   Reference: bitcoin-core/src/test/data/blockfilters.json row 2.
   Expected basic filter: 0174a170
   Expected basic header: 186afd11ef2b5e7e3504f2e8cbf8df28a1fd251fe53d60dff8b1467d1b386cf0 *)
let test_bip158_vector_height2 () =
  let block_hex = "0100000006128e87be8b1b4dea47a7247d5528d2702c96826c7a648497e773b800000000e241352e3bec0a95a6217e10c3abb54adfa05abb12c126695595580fb92e222032e7494dffff001d00d235340101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0e0432e7494d010e062f503253482fffffffff0100f2052a010000002321038a7f6ef1c8ca0c588aa53fa860128077c9e6c11e6830f4d7ee4e763a56b7718fac00000000" in
  let prev_scripts = [] in
  let prev_header_hex =
    "d7bdac13a59d745b1add0d2ce852f1a0442e8945fc1bf3848d3cbffd88c24fe1" in
  let expected_filter_hex = "0174a170" in
  let expected_header_hex =
    "186afd11ef2b5e7e3504f2e8cbf8df28a1fd251fe53d60dff8b1467d1b386cf0" in

  let bf = build_filter_from_hex block_hex prev_scripts in
  let actual_filter_hex = hex_encode bf.Block_index.filter.Block_index.encoded in
  Alcotest.(check string) "height-2 filter bytes" expected_filter_hex actual_filter_hex;

  let actual_header_hex = compute_header_from_hex bf prev_header_hex in
  Alcotest.(check string) "height-2 filter header" expected_header_hex actual_header_hex

(* BIP-158 test vector: block height 3 (testnet).
   Reference: bitcoin-core/src/test/data/blockfilters.json row 3.
   Expected basic filter: 016cf7a0
   Expected basic header: 8d63aadf5ab7257cb6d2316a57b16f517bff1c6388f124ec4c04af1212729d2a *)
let test_bip158_vector_height3 () =
  let block_hex = "0100000020782a005255b657696ea057d5b98f34defcf75196f64f6eeac8026c0000000041ba5afc532aae03151b8aa87b65e1594f97504a768e010c98c0add79216247186e7494dffff001d058dc2b60101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0e0486e7494d0151062f503253482fffffffff0100f2052a01000000232103f6d9ff4c12959445ca5549c811683bf9c88e637b222dd2e0311154c4c85cf423ac00000000" in
  let prev_scripts = [] in
  let prev_header_hex =
    "186afd11ef2b5e7e3504f2e8cbf8df28a1fd251fe53d60dff8b1467d1b386cf0" in
  let expected_filter_hex = "016cf7a0" in
  let expected_header_hex =
    "8d63aadf5ab7257cb6d2316a57b16f517bff1c6388f124ec4c04af1212729d2a" in

  let bf = build_filter_from_hex block_hex prev_scripts in
  let actual_filter_hex = hex_encode bf.Block_index.filter.Block_index.encoded in
  Alcotest.(check string) "height-3 filter bytes" expected_filter_hex actual_filter_hex;

  let actual_header_hex = compute_header_from_hex bf prev_header_hex in
  Alcotest.(check string) "height-3 filter header" expected_header_hex actual_header_hex

(* BIP-158 test vector: block with empty data (height 1414221).
   Reference: last entry in blockfilters.json.
   Coinbase-only block, no outputs, expected filter: 00  (N=0)
   Expected basic header: 021e8882ef5a0ed932edeebbecfeda1d7ce528ec7b3daa27641acf1189d7b5dc *)
let test_bip158_vector_empty_filter () =
  (* This block has only a coinbase with an un-parseable output (empty value=0 script=empty).
     The coinbase output scriptPubKey is empty (len=0), so it is excluded.
     Expected filter: 00  (N=0, compact size 0) *)
  let block_hex = "000000204ea88307a7959d8207968f152bedca5a93aefab253f1fb2cfb032a400000000070cebb14ec6dbc27a9dfd066d9849a4d3bac5f674665f73a5fe1de01a022a0c851fda85bf05f4c19a779d1450102000000010000000000000000000000000000000000000000000000000000000000000000ffffffff18034d94154d696e6572476174653030310d000000f238f401ffffffff01c817a804000000000000000000" in
  let prev_scripts = [] in
  let prev_header_hex =
    "5e5e12d90693c8e936f01847859404c67482439681928353ca1296982042864e" in
  let expected_filter_hex = "00" in
  let expected_header_hex =
    "021e8882ef5a0ed932edeebbecfeda1d7ce528ec7b3daa27641acf1189d7b5dc" in

  let bf = build_filter_from_hex block_hex prev_scripts in
  let actual_filter_hex = hex_encode bf.Block_index.filter.Block_index.encoded in
  Alcotest.(check string) "empty-filter block filter bytes" expected_filter_hex actual_filter_hex;

  let actual_header_hex = compute_header_from_hex bf prev_header_hex in
  Alcotest.(check string) "empty-filter block filter header" expected_header_hex actual_header_hex

(* ============================================================================
   SipHash-2-4 official test vector (RFC / siphash.net reference).
   Key: 00 01 02 03 04 05 06 07 | 08 09 0a 0b 0c 0d 0e 0f
   Input: 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e
   Expected output: 0xa129ca6149be45e5 (little-endian: e5 45 be 49 61 ca 29 a1)
   ============================================================================ *)
let test_siphash_reference_vector () =
  let k0 = 0x0706050403020100L in
  let k1 = 0x0f0e0d0c0b0a0908L in
  (* 15 bytes: 0x00..0x0e *)
  let data =
    "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e"
  in
  let result = Block_index.SipHash.siphash24 ~k0 ~k1 data in
  (* SipHash-2-4 reference output for this input: 0xa129ca6149be45e5 *)
  let expected = 0xa129ca6149be45e5L in
  Alcotest.(check bool) "siphash reference vector"
    true (Int64.equal result expected)

(* ============================================================================
   P2P message serialization round-trip tests for BIP-157 message types.
   Verifies that getcfilters/cfilter/getcfheaders/cfheaders/
   getcfcheckpt/cfcheckpt parse correctly through the p2p layer.
   ============================================================================ *)

let test_p2p_getcfilters_roundtrip () =
  let stop_hash = Types.hash256_of_hex
    "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943" in
  let msg = P2p.GetcfiltersMsg {
    filter_type = 0;
    start_height = 0l;
    stop_hash;
  } in
  let serialized = P2p.serialize_message 0xd9b4bef9l msg in
  let deserialized = P2p.deserialize_message serialized in
  match deserialized.P2p.payload with
  | P2p.GetcfiltersMsg { filter_type; start_height; stop_hash = sh } ->
    Alcotest.(check int) "filter_type" 0 filter_type;
    Alcotest.(check int32) "start_height" 0l start_height;
    Alcotest.(check string) "stop_hash"
      (Cstruct.to_string stop_hash) (Cstruct.to_string sh)
  | _ -> Alcotest.fail "expected GetcfiltersMsg"

let test_p2p_cfilter_roundtrip () =
  let block_hash = Types.hash256_of_hex
    "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943" in
  let filter_data = Cstruct.of_string (hex_decode "019dfca8") in
  let msg = P2p.CfilterMsg {
    filter_type = 0;
    block_hash;
    filter_data;
  } in
  let serialized = P2p.serialize_message 0xd9b4bef9l msg in
  let deserialized = P2p.deserialize_message serialized in
  match deserialized.P2p.payload with
  | P2p.CfilterMsg { filter_type; filter_data = fd; _ } ->
    Alcotest.(check int) "filter_type" 0 filter_type;
    Alcotest.(check string) "filter_data"
      (Cstruct.to_string filter_data) (Cstruct.to_string fd)
  | _ -> Alcotest.fail "expected CfilterMsg"

let test_p2p_getcfheaders_roundtrip () =
  let stop_hash = Types.hash256_of_hex
    "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943" in
  let msg = P2p.GetcfheadersMsg {
    filter_type = 0;
    start_height = 100l;
    stop_hash;
  } in
  let serialized = P2p.serialize_message 0xd9b4bef9l msg in
  let deserialized = P2p.deserialize_message serialized in
  match deserialized.P2p.payload with
  | P2p.GetcfheadersMsg { filter_type; start_height; stop_hash = sh } ->
    Alcotest.(check int) "filter_type" 0 filter_type;
    Alcotest.(check int32) "start_height" 100l start_height;
    Alcotest.(check string) "stop_hash"
      (Cstruct.to_string stop_hash) (Cstruct.to_string sh)
  | _ -> Alcotest.fail "expected GetcfheadersMsg"

let test_p2p_cfheaders_roundtrip () =
  let stop_hash = Types.hash256_of_hex
    "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943" in
  let prev_fh = Types.zero_hash in
  let fh1 = Types.hash256_of_hex
    "21584579b7eb08997773e5aeff3a7f932700042d0ed2a6129012b7d7ae81b750" in
  let msg = P2p.CfheadersMsg {
    filter_type = 0;
    stop_hash;
    prev_filter_header = prev_fh;
    filter_hashes = [fh1];
  } in
  let serialized = P2p.serialize_message 0xd9b4bef9l msg in
  let deserialized = P2p.deserialize_message serialized in
  match deserialized.P2p.payload with
  | P2p.CfheadersMsg { filter_type; filter_hashes; _ } ->
    Alcotest.(check int) "filter_type" 0 filter_type;
    Alcotest.(check int) "filter_hashes count" 1 (List.length filter_hashes);
    Alcotest.(check string) "filter_hash[0]"
      (Cstruct.to_string fh1) (Cstruct.to_string (List.nth filter_hashes 0))
  | _ -> Alcotest.fail "expected CfheadersMsg"

let test_p2p_getcfcheckpt_roundtrip () =
  let stop_hash = Types.hash256_of_hex
    "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943" in
  let msg = P2p.GetcfcheckptMsg {
    filter_type = 0;
    stop_hash;
  } in
  let serialized = P2p.serialize_message 0xd9b4bef9l msg in
  let deserialized = P2p.deserialize_message serialized in
  match deserialized.P2p.payload with
  | P2p.GetcfcheckptMsg { filter_type; stop_hash = sh } ->
    Alcotest.(check int) "filter_type" 0 filter_type;
    Alcotest.(check string) "stop_hash"
      (Cstruct.to_string stop_hash) (Cstruct.to_string sh)
  | _ -> Alcotest.fail "expected GetcfcheckptMsg"

let test_p2p_cfcheckpt_roundtrip () =
  let stop_hash = Types.hash256_of_hex
    "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943" in
  let fh1 = Types.hash256_of_hex
    "21584579b7eb08997773e5aeff3a7f932700042d0ed2a6129012b7d7ae81b750" in
  let msg = P2p.CfcheckptMsg {
    filter_type = 0;
    stop_hash;
    filter_headers = [fh1];
  } in
  let serialized = P2p.serialize_message 0xd9b4bef9l msg in
  let deserialized = P2p.deserialize_message serialized in
  match deserialized.P2p.payload with
  | P2p.CfcheckptMsg { filter_type; filter_headers; _ } ->
    Alcotest.(check int) "filter_type" 0 filter_type;
    Alcotest.(check int) "filter_headers count" 1 (List.length filter_headers);
    Alcotest.(check string) "filter_headers[0]"
      (Cstruct.to_string fh1) (Cstruct.to_string (List.nth filter_headers 0))
  | _ -> Alcotest.fail "expected CfcheckptMsg"

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
      test_case "reference vector" `Quick test_siphash_reference_vector;
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
    "bip158_vectors", [
      test_case "genesis block (height 0)" `Quick test_bip158_vector_genesis;
      test_case "height 2" `Quick test_bip158_vector_height2;
      test_case "height 3" `Quick test_bip158_vector_height3;
      test_case "empty filter (height 1414221)" `Quick test_bip158_vector_empty_filter;
    ];
    "p2p_bip157_messages", [
      test_case "getcfilters roundtrip" `Quick test_p2p_getcfilters_roundtrip;
      test_case "cfilter roundtrip" `Quick test_p2p_cfilter_roundtrip;
      test_case "getcfheaders roundtrip" `Quick test_p2p_getcfheaders_roundtrip;
      test_case "cfheaders roundtrip" `Quick test_p2p_cfheaders_roundtrip;
      test_case "getcfcheckpt roundtrip" `Quick test_p2p_getcfcheckpt_roundtrip;
      test_case "cfcheckpt roundtrip" `Quick test_p2p_cfcheckpt_roundtrip;
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
    "bip157_bundle", [
      test_case "create empty bundle" `Quick test_bip157_create_empty;
      test_case "append chain + idempotent re-append" `Quick
        test_bip157_append_chain;
      test_case "skip-height append rejected" `Quick
        test_bip157_append_skip_height_rejected;
      test_case "rewind drops above target" `Quick
        test_bip157_rewind_drops_above_target;
      test_case "persistence across close+reopen" `Quick
        test_bip157_persistence;
    ];
  ]
