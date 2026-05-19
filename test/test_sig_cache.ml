(* Tests for signature/script verification cache *)

open Camlcoin

(* ============================================================================
   Helper Functions
   ============================================================================ *)

(* Create a cache key with the given parameters.
   W159 BUG-17 / W160 BUG-1: field renamed txid → wtxid (witness-covering)
   to prevent SegWit-malleability cache poisoning.  Helper keeps the
   [txid_byte] argument name for backward-compatibility of test bodies;
   the byte is written into wtxid. *)
let make_key ?(txid_byte=1) ?(input_index=0) ?(flags=0) () : Sig_cache.cache_key =
  let wtxid = Cstruct.create 32 in
  Cstruct.set_uint8 wtxid 0 txid_byte;
  { Sig_cache.wtxid; input_index; flags }

(* ============================================================================
   Basic Cache Operations Tests
   ============================================================================ *)

(* Test: Cache creation with default size *)
let test_create_default () =
  let cache = Sig_cache.create () in
  Alcotest.(check int) "empty cache size" 0 (Sig_cache.size cache)

(* Test: Cache creation with custom size *)
let test_create_custom_size () =
  let cache = Sig_cache.create ~max_entries:100 () in
  Alcotest.(check int) "empty cache size" 0 (Sig_cache.size cache)

(* Test: Lookup on empty cache returns None *)
let test_lookup_empty () =
  let cache = Sig_cache.create () in
  let key = make_key () in
  match Sig_cache.lookup cache key with
  | None -> ()
  | Some _ -> Alcotest.fail "Empty cache should return None"

(* Test: Insert and lookup succeeds *)
let test_insert_and_lookup () =
  let cache = Sig_cache.create () in
  let key = make_key ~txid_byte:0x42 ~input_index:3 ~flags:0x11 () in
  Sig_cache.insert cache key true;
  Alcotest.(check int) "cache size after insert" 1 (Sig_cache.size cache);
  match Sig_cache.lookup cache key with
  | Some true -> ()
  | Some false -> Alcotest.fail "Cache returned false instead of true"
  | None -> Alcotest.fail "Cache should have found the entry"

(* Test: Insert false (failed verification) is not cached *)
let test_insert_false_not_cached () =
  let cache = Sig_cache.create () in
  let key = make_key () in
  Sig_cache.insert cache key false;  (* Should not be cached *)
  Alcotest.(check int) "cache size after false insert" 0 (Sig_cache.size cache);
  match Sig_cache.lookup cache key with
  | None -> ()  (* Expected: not cached *)
  | Some _ -> Alcotest.fail "False results should not be cached"

(* Test: Different keys are stored separately *)
let test_different_keys () =
  let cache = Sig_cache.create () in
  let key1 = make_key ~txid_byte:1 () in
  let key2 = make_key ~txid_byte:2 () in
  let key3 = make_key ~txid_byte:1 ~input_index:1 () in
  let key4 = make_key ~txid_byte:1 ~flags:1 () in

  Sig_cache.insert cache key1 true;
  Sig_cache.insert cache key2 true;
  Sig_cache.insert cache key3 true;
  Sig_cache.insert cache key4 true;

  Alcotest.(check int) "cache size with 4 keys" 4 (Sig_cache.size cache);

  (* All should be found *)
  Alcotest.(check bool) "key1 found" true (Sig_cache.lookup cache key1 = Some true);
  Alcotest.(check bool) "key2 found" true (Sig_cache.lookup cache key2 = Some true);
  Alcotest.(check bool) "key3 found" true (Sig_cache.lookup cache key3 = Some true);
  Alcotest.(check bool) "key4 found" true (Sig_cache.lookup cache key4 = Some true)

(* Test: Same key is not duplicated *)
let test_no_duplicate_insert () =
  let cache = Sig_cache.create () in
  let key = make_key () in
  Sig_cache.insert cache key true;
  Sig_cache.insert cache key true;  (* Duplicate insert *)
  Sig_cache.insert cache key true;  (* Another duplicate *)
  Alcotest.(check int) "no duplicates" 1 (Sig_cache.size cache)

(* Test: Clear removes all entries *)
let test_clear () =
  let cache = Sig_cache.create () in
  for i = 0 to 9 do
    let key = make_key ~txid_byte:i () in
    Sig_cache.insert cache key true
  done;
  Alcotest.(check int) "size before clear" 10 (Sig_cache.size cache);
  Sig_cache.clear cache;
  Alcotest.(check int) "size after clear" 0 (Sig_cache.size cache);
  (* Verify entries are gone *)
  let key = make_key ~txid_byte:5 () in
  match Sig_cache.lookup cache key with
  | None -> ()
  | Some _ -> Alcotest.fail "Entry should be gone after clear"

(* ============================================================================
   Eviction Tests
   ============================================================================ *)

(* Test: Eviction occurs when max_entries is exceeded *)
let test_eviction () =
  let max_entries = 100 in
  let cache = Sig_cache.create ~max_entries () in
  (* Insert more than max_entries *)
  for i = 0 to max_entries + 50 do
    let key = make_key ~txid_byte:(i mod 256) ~input_index:(i / 256) () in
    Sig_cache.insert cache key true
  done;
  (* Size should not exceed max_entries *)
  Alcotest.(check bool) "size bounded by max_entries" true
    (Sig_cache.size cache <= max_entries)

(* Test: Eviction doesn't lose all entries *)
let test_eviction_preserves_some () =
  let max_entries = 50 in
  let cache = Sig_cache.create ~max_entries () in
  (* Insert exactly max_entries *)
  for i = 0 to max_entries - 1 do
    let key = make_key ~txid_byte:i () in
    Sig_cache.insert cache key true
  done;
  Alcotest.(check int) "size at max" max_entries (Sig_cache.size cache);
  (* Insert one more to trigger eviction *)
  let extra_key = make_key ~txid_byte:255 ~input_index:999 () in
  Sig_cache.insert cache extra_key true;
  (* Should still have entries (not cleared) *)
  Alcotest.(check bool) "still has entries after eviction" true
    (Sig_cache.size cache > 0);
  (* The new entry should be present *)
  Alcotest.(check bool) "new entry present" true
    (Sig_cache.lookup cache extra_key = Some true)

(* ============================================================================
   Flags Tests (Different flags = different cache entries)
   ============================================================================ *)

(* Test: Different flags produce different cache entries *)
let test_flags_differentiate () =
  let cache = Sig_cache.create () in
  let key_no_flags = make_key ~flags:0 () in
  let key_with_witness = make_key ~flags:Script.script_verify_witness () in
  let key_with_p2sh = make_key ~flags:Script.script_verify_p2sh () in

  Sig_cache.insert cache key_no_flags true;
  Sig_cache.insert cache key_with_witness true;
  Sig_cache.insert cache key_with_p2sh true;

  (* Should have 3 separate entries *)
  Alcotest.(check int) "different flags = different entries" 3 (Sig_cache.size cache);

  (* Each should be independently found *)
  Alcotest.(check bool) "no flags found" true
    (Sig_cache.lookup cache key_no_flags = Some true);
  Alcotest.(check bool) "witness flags found" true
    (Sig_cache.lookup cache key_with_witness = Some true);
  Alcotest.(check bool) "p2sh flags found" true
    (Sig_cache.lookup cache key_with_p2sh = Some true)

(* Test: Stricter flags entry doesn't satisfy looser flags lookup *)
let test_flags_not_interchangeable () =
  let cache = Sig_cache.create () in
  (* Insert with WITNESS flag *)
  let key_strict = make_key ~flags:Script.script_verify_witness () in
  Sig_cache.insert cache key_strict true;

  (* Lookup without WITNESS flag should NOT find it *)
  let key_loose = make_key ~flags:0 () in
  match Sig_cache.lookup cache key_loose with
  | None -> ()  (* Expected: different flags = different key *)
  | Some _ -> Alcotest.fail "Stricter flags should not satisfy looser lookup"

(* ============================================================================
   Global Cache Tests
   ============================================================================ *)

(* Test: Global cache initialization *)
let test_global_init () =
  Sig_cache.init_global ~max_entries:1000 ();
  let cache = Sig_cache.get_global () in
  Alcotest.(check int) "global cache starts empty" 0 (Sig_cache.size cache)

(* Test: Global cache clear *)
let test_global_clear () =
  Sig_cache.init_global ();
  let cache = Sig_cache.get_global () in
  let key = make_key () in
  Sig_cache.insert cache key true;
  Alcotest.(check int) "size before clear" 1 (Sig_cache.size cache);
  Sig_cache.clear_global ();
  let cache2 = Sig_cache.get_global () in
  Alcotest.(check int) "size after clear_global" 0 (Sig_cache.size cache2)

(* Test: Global cache is shared *)
let test_global_shared () =
  Sig_cache.init_global ();
  let cache1 = Sig_cache.get_global () in
  let key = make_key ~txid_byte:0xAB () in
  Sig_cache.insert cache1 key true;

  let cache2 = Sig_cache.get_global () in
  (* Should be the same cache instance *)
  match Sig_cache.lookup cache2 key with
  | Some true -> ()
  | _ -> Alcotest.fail "Global cache should be shared"

(* ============================================================================
   Hash Function Tests
   ============================================================================ *)

(* Test: Hash function produces consistent results *)
let test_hash_consistent () =
  let key = make_key ~txid_byte:0x55 ~input_index:7 ~flags:0xFF () in
  let h1 = Sig_cache.hash_key key in
  let h2 = Sig_cache.hash_key key in
  Alcotest.(check int) "hash is consistent" h1 h2

(* Test: Different keys generally produce different hashes *)
let test_hash_varies () =
  let key1 = make_key ~txid_byte:1 () in
  let key2 = make_key ~txid_byte:2 () in
  let h1 = Sig_cache.hash_key key1 in
  let h2 = Sig_cache.hash_key key2 in
  (* Not guaranteed to be different, but extremely likely *)
  Alcotest.(check bool) "different keys have different hashes (usually)" true
    (h1 <> h2)

(* ============================================================================
   Key Equality Tests
   ============================================================================ *)

(* Test: Key equality works correctly *)
let test_key_equality () =
  let key1 = make_key ~txid_byte:0x12 ~input_index:5 ~flags:0x34 () in
  let key2 = make_key ~txid_byte:0x12 ~input_index:5 ~flags:0x34 () in
  Alcotest.(check bool) "equal keys" true (Sig_cache.key_equal key1 key2)

(* Test: Key inequality on different txid *)
let test_key_inequality_txid () =
  let key1 = make_key ~txid_byte:1 () in
  let key2 = make_key ~txid_byte:2 () in
  Alcotest.(check bool) "different txid" false (Sig_cache.key_equal key1 key2)

(* Test: Key inequality on different input_index *)
let test_key_inequality_input_index () =
  let key1 = make_key ~input_index:0 () in
  let key2 = make_key ~input_index:1 () in
  Alcotest.(check bool) "different input_index" false (Sig_cache.key_equal key1 key2)

(* Test: Key inequality on different flags *)
let test_key_inequality_flags () =
  let key1 = make_key ~flags:0 () in
  let key2 = make_key ~flags:1 () in
  Alcotest.(check bool) "different flags" false (Sig_cache.key_equal key1 key2)

(* ============================================================================
   W159 BUG-17 / W160 BUG-1 — SegWit Malleability Cache-Poisoning Test
   ============================================================================ *)

(* Helper: build a non-coinbase tx with a single SegWit input and a single
   output.  Differs only in witness items.  Used by the malleability test
   to construct two transactions with IDENTICAL txid (witness data is NOT
   covered by txid serialisation) but DIFFERENT wtxid. *)
let make_segwit_tx (witness_items : Cstruct.t list) : Types.transaction =
  let outpoint_txid = Cstruct.create 32 in
  Cstruct.set_uint8 outpoint_txid 0 0xAA;
  let script_pubkey = Cstruct.create 22 in
  Cstruct.set_uint8 script_pubkey 0 0x00;  (* OP_0 *)
  Cstruct.set_uint8 script_pubkey 1 0x14;  (* push 20 *)
  {
    version = 2l;
    inputs = [
      { previous_output = { txid = outpoint_txid; vout = 0l };
        script_sig = Cstruct.empty;
        sequence = 0xFFFFFFFFl }
    ];
    outputs = [
      { value = 50_000L; script_pubkey }
    ];
    witnesses = [{ items = witness_items }];
    locktime = 0l;
  }

(* Test: Two SegWit transactions with the SAME non-witness txid but
   DIFFERENT witnesses must produce DIFFERENT cache keys.  This is the
   SegWit-malleability chain-split candidate the audit (W159 BUG-17 /
   W160 BUG-1) documents.

   Pre-fix behaviour: cache_key = (txid, input_index, flags); since
   compute_txid excludes witness data (BIP-141), the two txs hash to the
   SAME cache_key — a malleated invalid witness inherits the cached
   `true` of the canonical valid witness and is admitted.

   Post-fix behaviour: cache_key = (wtxid, input_index, flags); wtxid
   COVERS witness data, so the two txs hash to DIFFERENT cache_keys and
   the malleated witness must be re-verified (and rejected). *)
let test_segwit_malleability_distinct_cache_keys () =
  let open Camlcoin in
  (* Two SegWit txs identical EXCEPT witness items. *)
  let sig_valid = Cstruct.of_string (String.make 71 '\x01') in
  let sig_malleated = Cstruct.of_string (String.make 71 '\x02') in
  let pubkey = Cstruct.of_string (String.make 33 '\xAB') in
  let tx_canonical = make_segwit_tx [sig_valid; pubkey] in
  let tx_malleated = make_segwit_tx [sig_malleated; pubkey] in
  (* Sanity: txid identical (no-witness serialisation is bit-equal). *)
  let txid_canonical  = Crypto.compute_txid tx_canonical in
  let txid_malleated  = Crypto.compute_txid tx_malleated in
  Alcotest.(check bool) "txids match (witness not covered by txid)" true
    (Cstruct.equal txid_canonical txid_malleated);
  (* But wtxid MUST differ (witness IS covered by wtxid). *)
  let wtxid_canonical = Crypto.compute_wtxid tx_canonical in
  let wtxid_malleated = Crypto.compute_wtxid tx_malleated in
  Alcotest.(check bool) "wtxids differ (witness covered by wtxid)" true
    (not (Cstruct.equal wtxid_canonical wtxid_malleated));
  (* The chain-split-closing assertion: cache keys for the two txs must
     differ at the same input_index and flags. *)
  let key_canonical : Sig_cache.cache_key =
    { wtxid = wtxid_canonical; input_index = 0; flags = 0 } in
  let key_malleated : Sig_cache.cache_key =
    { wtxid = wtxid_malleated; input_index = 0; flags = 0 } in
  Alcotest.(check bool)
    "SegWit-malleated witness must NOT cache-hit the canonical witness"
    false (Sig_cache.key_equal key_canonical key_malleated);
  (* End-to-end via the actual cache: insert canonical, lookup malleated
     MUST miss.  Pre-fix this returned Some true (the bug). *)
  let cache = Sig_cache.create () in
  Sig_cache.insert cache key_canonical true;
  match Sig_cache.lookup cache key_malleated with
  | None -> ()  (* Expected after fix. *)
  | Some _ ->
    Alcotest.fail
      "BUG: malleated witness cache-hit the canonical entry — \
       chain-split candidate vs Core (W159 BUG-17 / W160 BUG-1 NOT fixed)"

(* ============================================================================
   Test Registration
   ============================================================================ *)

let () =
  let open Alcotest in
  run "Sig_cache" [
    "basic", [
      test_case "create with default size" `Quick test_create_default;
      test_case "create with custom size" `Quick test_create_custom_size;
      test_case "lookup on empty cache" `Quick test_lookup_empty;
      test_case "insert and lookup" `Quick test_insert_and_lookup;
      test_case "false not cached" `Quick test_insert_false_not_cached;
      test_case "different keys stored separately" `Quick test_different_keys;
      test_case "no duplicate inserts" `Quick test_no_duplicate_insert;
      test_case "clear removes all" `Quick test_clear;
    ];
    "eviction", [
      test_case "eviction when full" `Quick test_eviction;
      test_case "eviction preserves some entries" `Quick test_eviction_preserves_some;
    ];
    "flags", [
      test_case "different flags = different entries" `Quick test_flags_differentiate;
      test_case "strict flags not interchangeable" `Quick test_flags_not_interchangeable;
    ];
    "global", [
      test_case "global init" `Quick test_global_init;
      test_case "global clear" `Quick test_global_clear;
      test_case "global shared" `Quick test_global_shared;
    ];
    "hash", [
      test_case "hash consistent" `Quick test_hash_consistent;
      test_case "hash varies" `Quick test_hash_varies;
    ];
    "key_equality", [
      test_case "equal keys" `Quick test_key_equality;
      test_case "different txid" `Quick test_key_inequality_txid;
      test_case "different input_index" `Quick test_key_inequality_input_index;
      test_case "different flags" `Quick test_key_inequality_flags;
    ];
    "segwit_malleability", [
      test_case "W159 BUG-17 / W160 BUG-1: malleated witness must not cache-hit"
        `Quick test_segwit_malleability_distinct_cache_keys;
    ];
  ]
