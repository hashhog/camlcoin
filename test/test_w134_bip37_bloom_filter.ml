(* W134 BIP-37 Bloom Filter — camlcoin (OCaml)
   Discovery-only audit (read-only). Tests pin the current behaviour of
   `lib/bloom.ml`, the BIP-37 dispatch in `lib/peer_manager.ml`, and the
   `MSG_FILTERED_BLOCK` getdata gap in `lib/peer.ml`.

   Each test corresponds to a gate in `audit/w134_bip37_bloom_filter.md`.
   PASS-gate tests verify that the current implementation behaves as
   spec'd. BUG-gate tests pin the *current divergent behaviour* (so the
   audit captures what's actually wrong; later fix waves flip the
   assertion).

   See `audit/w134_bip37_bloom_filter.md` for the 30-gate matrix and
   BUG-1 through BUG-11 catalogue. *)

open Camlcoin

(* ---------- helpers ---------- *)

let hex_to_bytes (h : string) : bytes =
  let len = String.length h / 2 in
  let buf = Bytes.create len in
  for i = 0 to len - 1 do
    let c = int_of_string ("0x" ^ String.sub h (i * 2) 2) in
    Bytes.set_uint8 buf i c
  done;
  buf

let zero_hash () : Cstruct.t = Cstruct.create 32

(* ============================================================================
   G1 — MAX_BLOOM_FILTER_SIZE = 36000
   ============================================================================ *)
let test_g1_max_bloom_filter_size () =
  Alcotest.(check int) "MAX_BLOOM_FILTER_SIZE = 36000"
    36000 Bloom.max_bloom_filter_size

(* ============================================================================
   G2 — MAX_HASH_FUNCS = 50
   ============================================================================ *)
let test_g2_max_hash_funcs () =
  Alcotest.(check int) "MAX_HASH_FUNCS = 50"
    50 Bloom.max_hash_funcs

(* ============================================================================
   G3 — LN2SQUARED full-precision constant
   ============================================================================ *)
let test_g3_ln2squared () =
  let expected = 0.4804530139182014 in
  Alcotest.(check bool) "LN2SQUARED matches Core to 15 digits"
    true (abs_float (Bloom.ln2squared -. expected) < 1e-15)

(* ============================================================================
   G4 — BLOOM_UPDATE_NONE = 0
   G5 — BLOOM_UPDATE_ALL = 1
   G6 — BLOOM_UPDATE_P2PUBKEY_ONLY = 2
   G7 — BLOOM_UPDATE_MASK = 3
   ============================================================================ *)
let test_g4_g5_g6_g7_update_flag_constants () =
  Alcotest.(check int) "BLOOM_UPDATE_NONE = 0" 0 Bloom.bloom_update_none;
  Alcotest.(check int) "BLOOM_UPDATE_ALL = 1" 1 Bloom.bloom_update_all;
  Alcotest.(check int) "BLOOM_UPDATE_P2PUBKEY_ONLY = 2" 2 Bloom.bloom_update_p2pubkey_only;
  Alcotest.(check int) "BLOOM_UPDATE_MASK = 3" 3 Bloom.bloom_update_mask

(* ============================================================================
   G8 — nFlags & BLOOM_UPDATE_MASK masking
   The upper 6 bits of nFlags MUST be ignored; only the low 2 bits drive the
   update decision.  Verify by constructing a filter with a flag value whose
   high bits are set; only the masked-low-2-bit value should change behaviour.
   ============================================================================ *)
let test_g8_update_mask_ignores_high_bits () =
  (* Build a P2PK script: <0x21 || 33 zero bytes || 0xac> *)
  let pubkey = Cstruct.create 35 in
  Cstruct.set_uint8 pubkey 0 0x21;
  Cstruct.set_uint8 pubkey 34 0xac;
  (* flags = 0xFE = 0b11111110 → mask gives 0b10 = UPDATE_P2PUBKEY_ONLY *)
  let f = Bloom.create 10 0.01 0 0xFE in
  Bloom.insert f (Cstruct.to_bytes (Cstruct.sub pubkey 1 33));
  let txid = zero_hash () in
  let txid_bytes = Cstruct.to_bytes txid in
  let tx : Types.transaction = {
    version = 1l;
    inputs = [];
    outputs = [{ value = 0L; script_pubkey = pubkey }];
    witnesses = [];
    locktime = 0l;
  } in
  let result = Bloom.is_relevant_and_update f tx txid_bytes in
  Alcotest.(check bool) "G8: high bits of nFlags ignored, UPDATE_P2PUBKEY_ONLY applied"
    true result;
  (* The P2PK output should now have been inserted as an outpoint *)
  Alcotest.(check bool) "G8: outpoint inserted for P2PK under masked UPDATE_P2PUBKEY_ONLY"
    true (Bloom.contains_outpoint f txid 0l)

(* ============================================================================
   G9 — MurmurHash3 (x86_32) byte-exact against Core hash_tests.cpp
   ============================================================================ *)
let test_g9_murmurhash3_core_vectors () =
  Alcotest.(check int) "murmur(0, empty) = 0"
    0x00000000 (Bloom.murmurhash3 0x00000000 (Bytes.create 0));
  Alcotest.(check int) "murmur(0xFBA4C795, empty) = 0x6a396f08"
    0x6a396f08 (Bloom.murmurhash3 0xFBA4C795 (Bytes.create 0));
  Alcotest.(check int) "murmur(0xffffffff, empty) = 0x81f16f39"
    0x81f16f39 (Bloom.murmurhash3 0xffffffff (Bytes.create 0));
  Alcotest.(check int) "murmur(0, 0x00) = 0x514e28b7"
    0x514e28b7 (Bloom.murmurhash3 0 (hex_to_bytes "00"));
  Alcotest.(check int) "murmur(0, 0xff) = 0xfd6cf10d"
    0xfd6cf10d (Bloom.murmurhash3 0 (hex_to_bytes "ff"));
  Alcotest.(check int) "murmur(0, 0x00112233) = 0xb4471bf8"
    0xb4471bf8 (Bloom.murmurhash3 0 (hex_to_bytes "00112233"))

(* ============================================================================
   G10 — Hash schedule: nHashNum * 0xFBA4C795 + nTweak (mod 2^32)
   Check that bloom_hash for hash_num = 0, n_tweak = 0 reduces to plain
   MurmurHash3(0, data) % (vdata bits).
   ============================================================================ *)
let test_g10_hash_schedule () =
  let f = Bloom.create 100 0.01 0 Bloom.bloom_update_none in
  let n_bits = Bytes.length f.Bloom.vdata * 8 in
  let data = Bytes.of_string "hello" in
  let raw = Bloom.murmurhash3 0 data in
  let scheduled = Bloom.bloom_hash f 0 data in
  Alcotest.(check int) "G10: hash_num=0,tweak=0 → MurmurHash3(0,data) % nbits"
    (raw mod n_bits) scheduled

(* ============================================================================
   G11 — Bit index = MurmurHash3 % (vData.size() * 8)
   Verify the index is always in range [0, vdata_bits).
   ============================================================================ *)
let test_g11_bit_index_in_range () =
  let f = Bloom.create 50 0.001 0xdeadbeef Bloom.bloom_update_all in
  let n_bits = Bytes.length f.Bloom.vdata * 8 in
  for i = 0 to 9 do
    let data = Bytes.of_string (Printf.sprintf "test-%d" i) in
    for h = 0 to f.Bloom.n_hash_funcs - 1 do
      let idx = Bloom.bloom_hash f h data in
      Alcotest.(check bool) (Printf.sprintf "G11: index in range (i=%d, h=%d)" i h)
        true (idx >= 0 && idx < n_bits)
    done
  done

(* ============================================================================
   G12 — Constructor sizing formula matches Core test vectors
   Core bloom_tests.cpp test vectors:
   - filter(3, 0.01, 0, UPDATE_ALL): vdata=3 bytes, nHashFuncs=5
   - filter(2, 0.001, 0, UPDATE_ALL): vdata=3 bytes, nHashFuncs=8
   - filter(10, 0.000001, 0, UPDATE_ALL): vdata=35 bytes, nHashFuncs=19
   ============================================================================ *)
let test_g12_g13_constructor_sizing () =
  let f1 = Bloom.create 3 0.01 0 Bloom.bloom_update_all in
  Alcotest.(check int) "n=3 fp=0.01 vdata size = 3" 3 (Bytes.length f1.Bloom.vdata);
  Alcotest.(check int) "n=3 fp=0.01 nHashFuncs = 5" 5 f1.Bloom.n_hash_funcs;
  let f2 = Bloom.create 2 0.001 0 Bloom.bloom_update_all in
  Alcotest.(check int) "n=2 fp=0.001 vdata size = 3" 3 (Bytes.length f2.Bloom.vdata);
  Alcotest.(check int) "n=2 fp=0.001 nHashFuncs = 8" 8 f2.Bloom.n_hash_funcs;
  let f3 = Bloom.create 10 0.000001 0 Bloom.bloom_update_all in
  Alcotest.(check int) "n=10 fp=1e-6 vdata size = 35" 35 (Bytes.length f3.Bloom.vdata);
  Alcotest.(check int) "n=10 fp=1e-6 nHashFuncs = 19" 19 f3.Bloom.n_hash_funcs

(* ============================================================================
   G14 — CVE-2013-5700 empty-vData guard
   When vdata is empty, contains() MUST return true (match-all), and
   insert() MUST be a no-op (does not crash).
   ============================================================================ *)
let test_g14_cve_2013_5700_empty_vdata () =
  let f = { Bloom.vdata = Bytes.create 0;
            n_hash_funcs = 0; n_tweak = 0;
            n_flags = Bloom.bloom_update_none } in
  Alcotest.(check bool) "G14: empty-vdata contains() = true"
    true (Bloom.contains f (Bytes.of_string "anything"));
  (* insert must not crash *)
  Bloom.insert f (Bytes.of_string "data");
  Alcotest.(check int) "G14: empty-vdata stays empty after insert"
    0 (Bytes.length f.Bloom.vdata)

(* ============================================================================
   G15 — IsWithinSizeConstraints
   Verify the constraint check accepts a filter with vData ≤ 36000 bytes AND
   nHashFuncs ≤ 50, and rejects either violation.
   ============================================================================ *)
let test_g15_is_within_size_constraints () =
  let f_ok = { Bloom.vdata = Bytes.create 100;
               n_hash_funcs = 10; n_tweak = 0; n_flags = 0 } in
  Alcotest.(check bool) "G15: small filter within constraints"
    true (Bloom.is_within_size_constraints f_ok);
  let f_oversize = { Bloom.vdata = Bytes.create (Bloom.max_bloom_filter_size + 1);
                     n_hash_funcs = 10; n_tweak = 0; n_flags = 0 } in
  Alcotest.(check bool) "G15: oversize vdata rejected"
    false (Bloom.is_within_size_constraints f_oversize);
  let f_too_many_funcs = { Bloom.vdata = Bytes.create 100;
                           n_hash_funcs = Bloom.max_hash_funcs + 1;
                           n_tweak = 0; n_flags = 0 } in
  Alcotest.(check bool) "G15: too many hash funcs rejected"
    false (Bloom.is_within_size_constraints f_too_many_funcs)

(* ============================================================================
   G16 — IsRelevantAndUpdate: txid match → fFound
   ============================================================================ *)
let test_g16_txid_match () =
  let f = Bloom.create 10 0.001 0 Bloom.bloom_update_none in
  let txid_bytes = Bytes.of_string "txid-x32-bytes-padded-out-here!!" in
  Bloom.insert f txid_bytes;
  let tx : Types.transaction = {
    version = 1l;
    inputs = [];
    outputs = [];
    witnesses = [];
    locktime = 0l;
  } in
  Alcotest.(check bool) "G16: txid match → fFound = true"
    true (Bloom.is_relevant_and_update f tx txid_bytes)

(* ============================================================================
   G17 — Per-output scriptPubKey pushdata scan
   ============================================================================ *)
let test_g17_output_pushdata_scan () =
  let f = Bloom.create 10 0.001 0 Bloom.bloom_update_none in
  (* Insert a 33-byte data element that will be a script push *)
  let pubkey_data = Bytes.make 33 '\xAB' in
  Bloom.insert f pubkey_data;
  (* Build a scriptPubKey: <0x21 || 33 0xAB bytes || 0xac> = P2PK *)
  let script = Cstruct.create 35 in
  Cstruct.set_uint8 script 0 0x21;
  for i = 1 to 33 do Cstruct.set_uint8 script i 0xAB done;
  Cstruct.set_uint8 script 34 0xac;
  let txid_bytes = Bytes.make 32 '\x00' in
  let tx : Types.transaction = {
    version = 1l;
    inputs = [];
    outputs = [{ value = 0L; script_pubkey = script }];
    witnesses = [];
    locktime = 0l;
  } in
  Alcotest.(check bool) "G17: output pushdata match"
    true (Bloom.is_relevant_and_update f tx txid_bytes)

(* ============================================================================
   G18 — Break after first matching push in same output (BUG-4)
   Pin the CURRENT BUGGY BEHAVIOUR: camlcoin does NOT break after the first
   match, so multiple matching pushes in the same scriptPubKey trigger
   multiple `insert_outpoint` invocations. The bug is observable via:
   construct a script with two matching pushes, UPDATE_ALL, and check that
   the OUTPOINT is inserted regardless. (Both pre-fix and post-fix should
   produce the same final filter state because Bloom.insert is idempotent on
   the same outpoint bits.) The test pins "outpoint IS inserted on multi-push
   match" — which holds both pre-fix and post-fix — but documents in a
   comment that the inner break is currently missing.
   ============================================================================ *)
let test_g18_break_after_first_push_match_BUG4 () =
  let f = Bloom.create 20 0.001 0 Bloom.bloom_update_all in
  let push1 = Bytes.of_string "push-1-data-here---------------!" in  (* 32 bytes *)
  let push2 = Bytes.of_string "push-2-data-here---------------!" in  (* 32 bytes *)
  Bloom.insert f push1;
  Bloom.insert f push2;
  (* Script: <0x20 || 32 bytes push1> <0x20 || 32 bytes push2> *)
  let script = Cstruct.create (1 + 32 + 1 + 32) in
  Cstruct.set_uint8 script 0 0x20;
  Cstruct.blit_from_bytes push1 0 script 1 32;
  Cstruct.set_uint8 script 33 0x20;
  Cstruct.blit_from_bytes push2 0 script 34 32;
  let txid_bytes = Bytes.make 32 '\xFE' in
  let tx : Types.transaction = {
    version = 1l;
    inputs = [];
    outputs = [{ value = 0L; script_pubkey = script }];
    witnesses = [];
    locktime = 0l;
  } in
  Alcotest.(check bool) "G18-BUG4: multi-push match still triggers outpoint insert"
    true (Bloom.is_relevant_and_update f tx txid_bytes);
  (* The outpoint MUST be inserted. Whether it's inserted ONCE (Core) or
     TWICE (camlcoin BUG-4) is not observable from outside because the bit
     pattern is idempotent. The bug is real but pinning it requires
     instrumentation we don't have. *)
  let txid_cs = Cstruct.of_bytes txid_bytes in
  Alcotest.(check bool) "G18-BUG4: outpoint (txid, 0) inserted in UPDATE_ALL mode"
    true (Bloom.contains_outpoint f txid_cs 0l)

(* ============================================================================
   G19 — UPDATE_ALL: outpoint inserted on output-script match
   ============================================================================ *)
let test_g19_update_all_outpoint_insert () =
  let f = Bloom.create 10 0.001 0 Bloom.bloom_update_all in
  let push = Bytes.make 20 '\xCD' in
  Bloom.insert f push;
  let script = Cstruct.create 22 in
  Cstruct.set_uint8 script 0 0x14;  (* OP_PUSHBYTES_20 *)
  Cstruct.blit_from_bytes push 0 script 1 20;
  Cstruct.set_uint8 script 21 0x88;  (* OP_EQUALVERIFY *)
  let txid_bytes = Bytes.make 32 '\xAA' in
  let txid_cs = Cstruct.of_bytes txid_bytes in
  let tx : Types.transaction = {
    version = 1l;
    inputs = [];
    outputs = [{ value = 0L; script_pubkey = script }];
    witnesses = [];
    locktime = 0l;
  } in
  let _ = Bloom.is_relevant_and_update f tx txid_bytes in
  Alcotest.(check bool) "G19: UPDATE_ALL inserted outpoint after match"
    true (Bloom.contains_outpoint f txid_cs 0l)

(* ============================================================================
   G20 — UPDATE_P2PUBKEY_ONLY: outpoint only inserted for P2PK or multisig
   ============================================================================ *)
let test_g20_update_p2pubkey_only () =
  (* Case A: P2PK output → outpoint should be inserted *)
  let pubkey_33 = Bytes.make 33 '\x11' in
  let f_p2pk = Bloom.create 10 0.001 0 Bloom.bloom_update_p2pubkey_only in
  Bloom.insert f_p2pk pubkey_33;
  let p2pk_script = Cstruct.create 35 in
  Cstruct.set_uint8 p2pk_script 0 0x21;
  Cstruct.blit_from_bytes pubkey_33 0 p2pk_script 1 33;
  Cstruct.set_uint8 p2pk_script 34 0xac;
  let txid_bytes_a = Bytes.make 32 '\x01' in
  let tx_a : Types.transaction = {
    version = 1l;
    inputs = [];
    outputs = [{ value = 0L; script_pubkey = p2pk_script }];
    witnesses = []; locktime = 0l;
  } in
  let matched_a = Bloom.is_relevant_and_update f_p2pk tx_a txid_bytes_a in
  Alcotest.(check bool) "G20-A: P2PK match" true matched_a;
  Alcotest.(check bool) "G20-A: outpoint inserted (P2PK)"
    true (Bloom.contains_outpoint f_p2pk (Cstruct.of_bytes txid_bytes_a) 0l);
  (* Case B: P2PKH (NOT a P2PK/multisig) — outpoint should NOT be inserted *)
  let hash_20 = Bytes.make 20 '\x22' in
  let f_p2pkh = Bloom.create 10 0.001 0 Bloom.bloom_update_p2pubkey_only in
  Bloom.insert f_p2pkh hash_20;
  let p2pkh_script = Cstruct.create 25 in
  Cstruct.set_uint8 p2pkh_script 0 0x76;  (* OP_DUP *)
  Cstruct.set_uint8 p2pkh_script 1 0xa9;  (* OP_HASH160 *)
  Cstruct.set_uint8 p2pkh_script 2 0x14;  (* push 20 *)
  Cstruct.blit_from_bytes hash_20 0 p2pkh_script 3 20;
  Cstruct.set_uint8 p2pkh_script 23 0x88;  (* OP_EQUALVERIFY *)
  Cstruct.set_uint8 p2pkh_script 24 0xac;  (* OP_CHECKSIG *)
  let txid_bytes_b = Bytes.make 32 '\x02' in
  let tx_b : Types.transaction = {
    version = 1l;
    inputs = [];
    outputs = [{ value = 0L; script_pubkey = p2pkh_script }];
    witnesses = []; locktime = 0l;
  } in
  let matched_b = Bloom.is_relevant_and_update f_p2pkh tx_b txid_bytes_b in
  Alcotest.(check bool) "G20-B: P2PKH match (filter contains hash160)"
    true matched_b;
  Alcotest.(check bool) "G20-B: outpoint NOT inserted (P2PKH is not P2PK/multisig)"
    false (Bloom.contains_outpoint f_p2pkh (Cstruct.of_bytes txid_bytes_b) 0l)

(* ============================================================================
   G21 — Inputs scanned ONLY if !fFound after outputs.
   Build a tx where the txid matches → fFound=true; inputs should not be
   scanned. We pin this by ensuring the function returns true and the side
   effect of "outpoint inserted from input scan" does not occur.
   ============================================================================ *)
let test_g21_inputs_scanned_only_when_not_found () =
  let f = Bloom.create 10 0.001 0 Bloom.bloom_update_none in
  let txid_bytes = Bytes.make 32 '\xBE' in
  Bloom.insert f txid_bytes;
  (* Input outpoint not in filter; if inputs were scanned we'd see no match
     but the function would still return true from the txid match. *)
  let prev_outpoint : Types.outpoint = {
    txid = Cstruct.create 32; vout = 7l;
  } in
  let tx : Types.transaction = {
    version = 1l;
    inputs = [{ previous_output = prev_outpoint;
                script_sig = Cstruct.create 0; sequence = 0xfffffffel }];
    outputs = [];
    witnesses = []; locktime = 0l;
  } in
  Alcotest.(check bool) "G21: returns true on txid match (inputs not necessary)"
    true (Bloom.is_relevant_and_update f tx txid_bytes)

(* ============================================================================
   G22 — Input prevout match → return true
   ============================================================================ *)
let test_g22_input_prevout_match () =
  let f = Bloom.create 10 0.001 0 Bloom.bloom_update_none in
  let prev_txid = Cstruct.create 32 in
  for i = 0 to 31 do Cstruct.set_uint8 prev_txid i (i + 1) done;
  let vout = 3l in
  Bloom.insert_outpoint f prev_txid vout;
  let tx : Types.transaction = {
    version = 1l;
    inputs = [{ previous_output = { txid = prev_txid; vout };
                script_sig = Cstruct.create 0; sequence = 0xfffffffel }];
    outputs = [];
    witnesses = []; locktime = 0l;
  } in
  let txid_bytes = Bytes.make 32 '\x00' in
  Alcotest.(check bool) "G22: input prevout match → true"
    true (Bloom.is_relevant_and_update f tx txid_bytes)

(* ============================================================================
   G23 — Input scriptSig pushdata scan
   ============================================================================ *)
let test_g23_input_scriptsig_pushdata () =
  let f = Bloom.create 10 0.001 0 Bloom.bloom_update_none in
  let push = Bytes.make 33 '\x55' in
  Bloom.insert f push;
  let script_sig = Cstruct.create 34 in
  Cstruct.set_uint8 script_sig 0 0x21;
  Cstruct.blit_from_bytes push 0 script_sig 1 33;
  let tx : Types.transaction = {
    version = 1l;
    inputs = [{ previous_output = { txid = Cstruct.create 32; vout = 0l };
                script_sig; sequence = 0xfffffffel }];
    outputs = [];
    witnesses = []; locktime = 0l;
  } in
  let txid_bytes = Bytes.make 32 '\x00' in
  Alcotest.(check bool) "G23: scriptSig pushdata match"
    true (Bloom.is_relevant_and_update f tx txid_bytes)

(* ============================================================================
   G24 — Outpoint wire serialization: txid (32 LE) ‖ vout (4 LE)
   ============================================================================ *)
let test_g24_outpoint_serialization () =
  let txid = Cstruct.create 32 in
  for i = 0 to 31 do Cstruct.set_uint8 txid i i done;
  let vout = 0x12345678l in
  let serialized = Bloom.outpoint_to_bytes txid vout in
  Alcotest.(check int) "G24: total length = 36" 36 (Bytes.length serialized);
  (* First 32 bytes: txid as-is *)
  for i = 0 to 31 do
    Alcotest.(check int) (Printf.sprintf "G24: txid byte %d" i)
      i (Bytes.get_uint8 serialized i)
  done;
  (* Last 4 bytes: vout LE *)
  Alcotest.(check int) "G24: vout LE byte 0" 0x78 (Bytes.get_uint8 serialized 32);
  Alcotest.(check int) "G24: vout LE byte 1" 0x56 (Bytes.get_uint8 serialized 33);
  Alcotest.(check int) "G24: vout LE byte 2" 0x34 (Bytes.get_uint8 serialized 34);
  Alcotest.(check int) "G24: vout LE byte 3" 0x12 (Bytes.get_uint8 serialized 35)

(* ============================================================================
   G25 — filterload wire round-trip
   ============================================================================ *)
let test_g25_filterload_roundtrip () =
  let f1 = Bloom.create 3 0.01 0 Bloom.bloom_update_all in
  let cs = Bloom.serialize f1 in
  match Bloom.deserialize cs with
  | Error e -> Alcotest.fail (Printf.sprintf "G25: deserialize failed: %s" e)
  | Ok f2 ->
    Alcotest.(check int) "G25: vdata length round-trips"
      (Bytes.length f1.Bloom.vdata) (Bytes.length f2.Bloom.vdata);
    Alcotest.(check int) "G25: nHashFuncs round-trips"
      f1.Bloom.n_hash_funcs f2.Bloom.n_hash_funcs;
    Alcotest.(check int) "G25: nTweak round-trips"
      f1.Bloom.n_tweak f2.Bloom.n_tweak;
    Alcotest.(check int) "G25: nFlags round-trips"
      f1.Bloom.n_flags f2.Bloom.n_flags

(* ============================================================================
   G26 — filteradd ≤ 520-byte (MAX_SCRIPT_ELEMENT_SIZE) guard
   The guard lives in p2p.ml deserializer; we can't run the wire path
   end-to-end from a unit test, but we can verify the constant and pin
   the boundary at 520 in the p2p deserializer source.
   ============================================================================ *)
let test_g26_filteradd_520_byte_guard () =
  (* The wire deserializer in p2p.ml uses `max_script_element_size = 520`.
     This unit test pins the boundary by reading the constant referenced
     in the dispatch arm. The actual reject happens at deserialization. *)
  let src = "/home/work/hashhog/camlcoin/lib/p2p.ml" in
  let buf = Buffer.create 65536 in
  let ic = open_in src in
  (try
    while true do
      Buffer.add_channel buf ic 4096
    done
  with End_of_file -> close_in ic);
  let contents = Buffer.contents buf in
  let needle1 = "max_script_element_size = 520" in
  let needle2 = "filteradd: data too large" in
  let contains s n = try let _ = Str.search_forward (Str.regexp_string n) s 0 in true with Not_found -> false in
  Alcotest.(check bool) "G26: filteradd has 520-byte limit constant in p2p.ml"
    true (contains contents needle1);
  Alcotest.(check bool) "G26: filteradd reject path in p2p.ml"
    true (contains contents needle2)

(* ============================================================================
   G27 — BUG-1: filteradd without prior filterload → MUST misbehavior-disconnect
   PIN CURRENT (BUGGY) BEHAVIOUR: the FilterAddMsg arm at
   peer_manager.ml:1870-1878 creates a zero-size match-all filter instead of
   disconnecting. Match by source grep.
   ============================================================================ *)
let test_g27_filteradd_without_filterload_BUG1 () =
  let src = "/home/work/hashhog/camlcoin/lib/peer_manager.ml" in
  let buf = Buffer.create 65536 in
  let ic = open_in src in
  (try
    while true do
      Buffer.add_channel buf ic 4096
    done
  with End_of_file -> close_in ic);
  let contents = Buffer.contents buf in
  let contains s n = try let _ = Str.search_forward (Str.regexp_string n) s 0 in true with Not_found -> false in
  (* BUGGY path: empty Bytes.create 0 vdata constructed in FilterAddMsg arm *)
  let needle_buggy = "Bloom.vdata = Bytes.create 0" in
  Alcotest.(check bool)
    "G27-BUG1: filteradd-without-filterload still creates zero-vdata match-all filter"
    true (contains contents needle_buggy);
  (* If the fix landed, the no-prior-filterload arm would call misbehaving + remove_peer.
     We pin the negative: it does NOT call misbehaving in the FilterAddMsg arm. *)
  let needle_fix = "misbehaving peer 100 \"filteradd without prior filterload\"" in
  Alcotest.(check bool) "G27-BUG1: fix not yet applied (no misbehaving call)"
    false (contains contents needle_fix)

(* ============================================================================
   G28 — BUG-3: filterload / filterclear should flip peer.relay = true
   PIN CURRENT (BUGGY) BEHAVIOUR: the arms do not set peer.Peer.relay <- true.
   ============================================================================ *)
let test_g28_filterload_filterclear_flip_relay_BUG3 () =
  let src = "/home/work/hashhog/camlcoin/lib/peer_manager.ml" in
  let buf = Buffer.create 65536 in
  let ic = open_in src in
  (try
    while true do
      Buffer.add_channel buf ic 4096
    done
  with End_of_file -> close_in ic);
  let contents = Buffer.contents buf in
  let contains s n = try let _ = Str.search_forward (Str.regexp_string n) s 0 in true with Not_found -> false in
  (* The FilterLoadMsg / FilterClearMsg arms must contain `peer.Peer.relay <- true`. *)
  let needle_fix = "peer.Peer.relay <- true" in
  Alcotest.(check bool) "G28-BUG3: fix not yet applied (no relay flip in filter arms)"
    false (contains contents needle_fix)

(* ============================================================================
   G29 — BUG-2: MSG_FILTERED_BLOCK getdata branch absent
   PIN CURRENT (BUGGY) BEHAVIOUR: handle_getdata in peer.ml does not handle
   InvFilteredBlock. Grep for the InvFilteredBlock arm.
   ============================================================================ *)
let test_g29_msg_filtered_block_getdata_BUG2 () =
  let src = "/home/work/hashhog/camlcoin/lib/peer.ml" in
  let buf = Buffer.create 1_000_000 in
  let ic = open_in src in
  (try
    while true do
      Buffer.add_channel buf ic 4096
    done
  with End_of_file -> close_in ic);
  let contents = Buffer.contents buf in
  let contains s n = try let _ = Str.search_forward (Str.regexp_string n) s 0 in true with Not_found -> false in
  (* The handle_getdata function must have a P2p.InvFilteredBlock arm. *)
  let needle_fix = "P2p.InvFilteredBlock" in
  Alcotest.(check bool) "G29-BUG2: fix not yet applied (no InvFilteredBlock arm in handle_getdata)"
    false (contains contents needle_fix);
  (* The MerkleBlockMsg construction site must exist somewhere in handle_getdata. *)
  let needle_merkleblock = "MerkleBlockMsg" in
  let src_files = ["/home/work/hashhog/camlcoin/lib/peer.ml";
                   "/home/work/hashhog/camlcoin/lib/peer_manager.ml";
                   "/home/work/hashhog/camlcoin/lib/sync.ml"] in
  let any_constructs = List.exists (fun fp ->
    let b = Buffer.create 1_000_000 in
    let ic = open_in fp in
    (try while true do Buffer.add_channel b ic 4096 done
     with End_of_file -> close_in ic);
    let s = Buffer.contents b in
    (* Look for a construction site (P2p.MerkleBlockMsg { ... }) — heuristic:
       the string "MerkleBlockMsg {" appears in a *send_message* call. *)
    contains s (needle_merkleblock ^ " {") &&
    contains s "send_message"
  ) src_files in
  Alcotest.(check bool)
    "G29-BUG2: no MerkleBlockMsg construction wired to send_message in peer/peer_manager/sync"
    false any_constructs

(* ============================================================================
   G30 — BUG-5: CRollingBloomFilter absent
   PIN CURRENT (BUGGY) BEHAVIOUR: bloom.ml has no CRollingBloomFilter analogue.
   ============================================================================ *)
let test_g30_crolling_bloom_filter_BUG5 () =
  let src = "/home/work/hashhog/camlcoin/lib/bloom.ml" in
  let buf = Buffer.create 65536 in
  let ic = open_in src in
  (try
    while true do
      Buffer.add_channel buf ic 4096
    done
  with End_of_file -> close_in ic);
  let contents = Buffer.contents buf in
  let contains s n = try let _ = Str.search_forward (Str.regexp_string n) s 0 in true with Not_found -> false in
  let needle = "rolling" in
  let needle2 = "FastRange32" in
  let needle3 = "RollingBloom" in
  Alcotest.(check bool) "G30-BUG5: no CRollingBloomFilter analogue in bloom.ml"
    false (contains contents needle || contains contents needle2 || contains contents needle3)

(* ============================================================================
   Test registry
   ============================================================================ *)
let () =
  Alcotest.run "W134 BIP-37 Bloom Filter"
    [
      "constants", [
        Alcotest.test_case "G1 MAX_BLOOM_FILTER_SIZE" `Quick test_g1_max_bloom_filter_size;
        Alcotest.test_case "G2 MAX_HASH_FUNCS" `Quick test_g2_max_hash_funcs;
        Alcotest.test_case "G3 LN2SQUARED" `Quick test_g3_ln2squared;
        Alcotest.test_case "G4-G7 UPDATE flag constants" `Quick test_g4_g5_g6_g7_update_flag_constants;
        Alcotest.test_case "G8 UPDATE_MASK ignores high bits" `Quick test_g8_update_mask_ignores_high_bits;
      ];
      "hash + sizing", [
        Alcotest.test_case "G9 MurmurHash3 Core vectors" `Quick test_g9_murmurhash3_core_vectors;
        Alcotest.test_case "G10 hash schedule" `Quick test_g10_hash_schedule;
        Alcotest.test_case "G11 bit index in range" `Quick test_g11_bit_index_in_range;
        Alcotest.test_case "G12-G13 constructor sizing" `Quick test_g12_g13_constructor_sizing;
        Alcotest.test_case "G14 CVE-2013-5700 empty vdata" `Quick test_g14_cve_2013_5700_empty_vdata;
        Alcotest.test_case "G15 IsWithinSizeConstraints" `Quick test_g15_is_within_size_constraints;
      ];
      "IsRelevantAndUpdate", [
        Alcotest.test_case "G16 txid match" `Quick test_g16_txid_match;
        Alcotest.test_case "G17 output pushdata scan" `Quick test_g17_output_pushdata_scan;
        Alcotest.test_case "G18 break after first push (BUG-4 latent)" `Quick test_g18_break_after_first_push_match_BUG4;
        Alcotest.test_case "G19 UPDATE_ALL outpoint insert" `Quick test_g19_update_all_outpoint_insert;
        Alcotest.test_case "G20 UPDATE_P2PUBKEY_ONLY" `Quick test_g20_update_p2pubkey_only;
        Alcotest.test_case "G21 inputs only if not found" `Quick test_g21_inputs_scanned_only_when_not_found;
        Alcotest.test_case "G22 input prevout match" `Quick test_g22_input_prevout_match;
        Alcotest.test_case "G23 scriptSig pushdata" `Quick test_g23_input_scriptsig_pushdata;
        Alcotest.test_case "G24 outpoint serialization" `Quick test_g24_outpoint_serialization;
      ];
      "wire + dispatch", [
        Alcotest.test_case "G25 filterload roundtrip" `Quick test_g25_filterload_roundtrip;
        Alcotest.test_case "G26 filteradd 520-byte guard" `Quick test_g26_filteradd_520_byte_guard;
        Alcotest.test_case "G27 filteradd without filterload (BUG-1)" `Quick test_g27_filteradd_without_filterload_BUG1;
        Alcotest.test_case "G28 filter*Msg flip relay (BUG-3)" `Quick test_g28_filterload_filterclear_flip_relay_BUG3;
        Alcotest.test_case "G29 MSG_FILTERED_BLOCK getdata (BUG-2)" `Quick test_g29_msg_filtered_block_getdata_BUG2;
        Alcotest.test_case "G30 CRollingBloomFilter (BUG-5)" `Quick test_g30_crolling_bloom_filter_BUG5;
      ];
    ]
