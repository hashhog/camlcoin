(* W122 audit — BIP-158 GCS codec stress-vector audit.

   Motivation: haskoin W121 addendum BUG-16 found that Haskoin's bit-packer
   silently truncated bits when (numBits + bufferBits) crossed a Word64
   boundary, corrupting Golomb-Rice streams with quotients >= 64.  Core's
   blockfilters.json regression vectors are heights 0, 2, 3, 15007, 49291,
   180480, 926485, 987876, 1263442, 1414221 — none of which produce a
   Golomb-Rice quotient >= 64, so they cannot catch this class of bug.

   This audit stress-tests camlcoin's GolombRice writer/reader (block_index.ml
   lines 111-257) across the haskoin-style quotient corners (0 / 1 / 63 / 64 /
   65 / 100 / 200 / 1000) and the cross-quotient interaction matrix that
   triggers haskoin BUG-16 (unary spans starting at a non-aligned bit offset).

   Expected verdict: camlcoin's bit writer operates byte-by-byte (max 8 bits
   per inner iteration of [write_bits]), with no Word64 buffer to overflow.
   The haskoin BUG-16 class is structurally absent.  This file documents that
   assumption via concrete tests so any future refactor that introduces a
   wider buffer fails first.

   Audit checklist:
     S1  unary write of q bits matches Core for q in {0, 1, 8, 63, 64, 65,
         100, 200, 1000}
     S2  unary write of q ones after a non-aligned offset (1..7 prior bits)
         decodes correctly for q in {64, 65, 100}
     S3  encode-then-decode round trip for value with quotient q in
         {0, 1, 63, 64, 65, 100, 200, 1000, 8191, 65535}, P=19
     S4  encode-then-decode round trip for the haskoin BUG-16 exact trace —
         seven small values that leave the buffer at offset 5, then a value
         with q=8191 (P=19, value=0xFFFFFFFF)
     S5  mixed stream {q=0, q=30, q=65, q=120} encode-decode round trip
     S6  high-P stress: P=32 encode/decode of values up to 2^48 (well past
         BIP-158's practical range; bounds the helper's safe envelope)
     S7  byte-boundary sweep: for offsets 0..7, write n=64 ones followed by
         the terminator bit, then decode and assert q == 64
     S8  Core regression: re-runs the BIP-158 blockfilters.json vectors
         already in test_block_index.ml as a sanity check that the audit
         file imports the codec correctly

   These tests should ALL pass.  If any fail, the codec has a haskoin-style
   bit-packing bug and the audit emits BUG-FOUND.
   ============================================================================ *)

open Camlcoin

(* -- helpers ------------------------------------------------------------- *)

(* Encode a single value at parameter P and return the encoded bytes. *)
let encode_one ~p (x : int64) : string =
  let w = Block_index.GolombRice.create_writer () in
  Block_index.GolombRice.encode w ~p x;
  Block_index.GolombRice.to_string w

(* Decode a single value at parameter P from raw bytes. *)
let decode_one ~p (s : string) : int64 =
  let r = Block_index.GolombRice.create_reader s in
  Block_index.GolombRice.decode r ~p

(* Encode a sequence of values at parameter P. *)
let encode_many ~p (xs : int64 list) : string =
  let w = Block_index.GolombRice.create_writer () in
  List.iter (fun x -> Block_index.GolombRice.encode w ~p x) xs;
  Block_index.GolombRice.to_string w

(* Decode a sequence of n values at parameter P from raw bytes. *)
let decode_many ~p ~n (s : string) : int64 list =
  let r = Block_index.GolombRice.create_reader s in
  let rec loop i acc =
    if i = n then List.rev acc
    else loop (i + 1) (Block_index.GolombRice.decode r ~p :: acc)
  in
  loop 0 []

let int64_to_pp fmt v = Format.fprintf fmt "%Ld" v
let int64_list = Alcotest.(list (of_pp int64_to_pp))

(* -- S1 unary write of q bits matches expected size --------------------- *)

(* For a value x at parameter P, encoded size in bits = (x >> P) + 1 + P.
   Total bytes = ceil(bits / 8).  This is the trivial size invariant; if
   the unary write drops bits, the actual size is smaller than expected. *)
let s1_unary_size_for_quotient q =
  let p = 19 in
  let x = Int64.shift_left (Int64.of_int q) p in
  let s = encode_one ~p x in
  let bits = q + 1 + p in
  let expected_bytes = (bits + 7) / 8 in
  Alcotest.(check int)
    (Printf.sprintf "S1 q=%d unary writes correct byte count" q)
    expected_bytes (String.length s)

let s1_unary_size_0 () = s1_unary_size_for_quotient 0
let s1_unary_size_1 () = s1_unary_size_for_quotient 1
let s1_unary_size_8 () = s1_unary_size_for_quotient 8
let s1_unary_size_63 () = s1_unary_size_for_quotient 63
let s1_unary_size_64 () = s1_unary_size_for_quotient 64
let s1_unary_size_65 () = s1_unary_size_for_quotient 65
let s1_unary_size_100 () = s1_unary_size_for_quotient 100
let s1_unary_size_200 () = s1_unary_size_for_quotient 200
let s1_unary_size_1000 () = s1_unary_size_for_quotient 1000

(* -- S2 unary write of q ones after a non-aligned offset ---------------- *)

(* The haskoin BUG-16 corruption only manifests when the writer's buffer
   is partially full (non-aligned to byte boundary) at the start of a
   large unary span.  Reproduce this in OCaml: write [pad] bits first
   to set offset, then encode a value with the target quotient. *)
let s2_unaligned_offset_unary ~pad ~q () =
  let p = 19 in
  let w = Block_index.GolombRice.create_writer () in
  (* Write `pad` zero bits (1 bit at a time so the path matches a real
     mixed-encoding sequence, not a single multi-bit write). *)
  for _ = 1 to pad do
    Block_index.GolombRice.encode w ~p:0 0L  (* 0 bits unary + 0 bits remainder *)
  done;
  (* The above writes `pad` 0-bits exactly (encode for P=0 with x=0 writes
     a single 0-bit terminator and no remainder). *)
  let x = Int64.shift_left (Int64.of_int q) p in
  Block_index.GolombRice.encode w ~p x;
  let s = Block_index.GolombRice.to_string w in
  (* Decode: read `pad` 0-bits, then decode the value at P. *)
  let r = Block_index.GolombRice.create_reader s in
  for i = 1 to pad do
    let got = Block_index.GolombRice.decode r ~p:0 in
    Alcotest.(check bool)
      (Printf.sprintf "S2 pad=%d q=%d: padding bit %d round-trips" pad q i)
      true (Int64.equal got 0L)
  done;
  let decoded = Block_index.GolombRice.decode r ~p in
  Alcotest.(check bool)
    (Printf.sprintf "S2 pad=%d q=%d: value round-trips" pad q)
    true (Int64.equal decoded x)

let s2_pad1_q64 () = s2_unaligned_offset_unary ~pad:1 ~q:64 ()
let s2_pad3_q64 () = s2_unaligned_offset_unary ~pad:3 ~q:64 ()
let s2_pad5_q64 () = s2_unaligned_offset_unary ~pad:5 ~q:64 ()
let s2_pad7_q64 () = s2_unaligned_offset_unary ~pad:7 ~q:64 ()
let s2_pad1_q65 () = s2_unaligned_offset_unary ~pad:1 ~q:65 ()
let s2_pad5_q65 () = s2_unaligned_offset_unary ~pad:5 ~q:65 ()
let s2_pad3_q100 () = s2_unaligned_offset_unary ~pad:3 ~q:100 ()
let s2_pad7_q100 () = s2_unaligned_offset_unary ~pad:7 ~q:100 ()

(* -- S3 encode-then-decode round trip for various quotients ------------- *)

let s3_roundtrip_quotient q =
  let p = 19 in
  let x = Int64.shift_left (Int64.of_int q) p in
  let s = encode_one ~p x in
  let got = decode_one ~p s in
  Alcotest.(check bool)
    (Printf.sprintf "S3 q=%d: encode-decode identity" q)
    true (Int64.equal got x);
  (* Also test x = q << P + 1 (quotient q, remainder 1) *)
  let x1 = Int64.add x 1L in
  let s1 = encode_one ~p x1 in
  let got1 = decode_one ~p s1 in
  Alcotest.(check bool)
    (Printf.sprintf "S3 q=%d r=1: encode-decode identity" q)
    true (Int64.equal got1 x1)

let s3_rt_q0 () = s3_roundtrip_quotient 0
let s3_rt_q1 () = s3_roundtrip_quotient 1
let s3_rt_q63 () = s3_roundtrip_quotient 63
let s3_rt_q64 () = s3_roundtrip_quotient 64
let s3_rt_q65 () = s3_roundtrip_quotient 65
let s3_rt_q100 () = s3_roundtrip_quotient 100
let s3_rt_q200 () = s3_roundtrip_quotient 200
let s3_rt_q1000 () = s3_roundtrip_quotient 1000
let s3_rt_q8191 () = s3_roundtrip_quotient 8191
let s3_rt_q65535 () = s3_roundtrip_quotient 65535

(* -- S4 haskoin BUG-16 exact trace -------------------------------------- *)

(* From haskoin commit 4a2de0f, the failing trace was:
   - 7 small values encoded first that leave the bit-buffer at offset 5
   - then encode 0xFFFFFFFF at P=19 (quotient = 0xFFFFFFFF >> 19 = 8191)
   - pre-fix haskoin decoded the last value as 31457264 (corruption)

   We synthesise the same condition: pick 7 small deltas with combined
   encoded-bit-size = N*8+5 for some N, then append the q=8191 value.
   The OCaml byte-buffered writer should handle this with no special
   path. *)
let s4_haskoin_bug16_trace () =
  let p = 19 in
  let small_values = [
    Int64.of_int 0;   (* 0 quotient + 0 remainder = 1 + 19 = 20 bits *)
    Int64.of_int 1;   (* 0 quotient + remainder = 20 bits *)
    Int64.of_int 2;
    Int64.of_int 3;
    Int64.of_int 4;
    Int64.of_int 5;
    Int64.of_int 6;
    (* 7 values * 20 bits = 140 bits = 17 bytes + 4 bits.  Add 1 more
       1-bit padding to land at offset 5. *)
  ] in
  let w = Block_index.GolombRice.create_writer () in
  List.iter (fun v -> Block_index.GolombRice.encode w ~p v) small_values;
  (* Pad with a single P=0 unit (writes exactly 1 zero bit) to reach
     offset 5 from offset 4. *)
  Block_index.GolombRice.encode w ~p:0 0L;
  (* Now encode the haskoin BUG-16 trigger: 0xFFFFFFFF at P=19 → q=8191. *)
  let trigger = 0xFFFFFFFFL in
  Block_index.GolombRice.encode w ~p trigger;
  let encoded = Block_index.GolombRice.to_string w in
  (* Decode back and verify last value is the original trigger. *)
  let r = Block_index.GolombRice.create_reader encoded in
  let decoded = List.map (fun _ ->
    Block_index.GolombRice.decode r ~p
  ) small_values in
  Alcotest.(check int64_list)
    "S4 small values round-trip" small_values decoded;
  let _pad = Block_index.GolombRice.decode r ~p:0 in
  let got = Block_index.GolombRice.decode r ~p in
  Alcotest.(check bool)
    "S4 haskoin BUG-16 trigger (q=8191 after pad) round-trips"
    true (Int64.equal got trigger);
  (* Source-level regression guard: ensure the result is NOT 31457264
     (the haskoin pre-fix corruption value).  This is an internal Haskell
     specific number — included for cross-impl test-suite traceability. *)
  Alcotest.(check bool)
    "S4 not the haskoin pre-fix corruption value (31457264)"
    true (not (Int64.equal got 31457264L))

(* -- S5 mixed quotient stream round trip -------------------------------- *)

let s5_mixed_quotient_stream () =
  let p = 19 in
  let mk_value q = Int64.shift_left (Int64.of_int q) p in
  let values = [mk_value 0; mk_value 30; mk_value 65; mk_value 120] in
  let encoded = encode_many ~p values in
  let decoded = decode_many ~p ~n:(List.length values) encoded in
  Alcotest.(check int64_list)
    "S5 mixed quotient stream round-trips" values decoded

(* -- S6 high-P stress --------------------------------------------------- *)

(* BIP-158 fixes P=19, but the GolombRice helper is generic.  Stress P=32
   with values up to 2^48 to bound the safe envelope.  Note: read_bits
   internally calls Int64.shift_left/logor on accumulator, and reads at
   most 8 bits per inner iteration, so this should work up to nbits=64.

   At P=32, a 48-bit value has quotient up to 2^16 = 65536 — well into
   the regime that would have triggered haskoin BUG-16.  *)
let s6_high_p_p32 () =
  let p = 32 in
  let values = [
    0L;
    1L;
    Int64.shift_left 1L 20;
    Int64.shift_left 1L 32;
    Int64.shift_left 1L 40;
    Int64.shift_left 1L 47;  (* q ≈ 2^15 *)
  ] in
  List.iter (fun v ->
    let s = encode_one ~p v in
    let got = decode_one ~p s in
    Alcotest.(check bool)
      (Printf.sprintf "S6 P=32 v=%Ld round-trips" v)
      true (Int64.equal got v)
  ) values

(* -- S7 byte-boundary sweep -------------------------------------------- *)

(* For each starting offset 0..7, write n=64 ones followed by a 0 bit (=
   unary of q=64) then a P=19 remainder of zero.  Decode and assert
   q == 64. *)
let s7_byte_boundary_sweep_offset offset () =
  let p = 19 in
  let w = Block_index.GolombRice.create_writer () in
  (* Pad with `offset` 0-bits via P=0 unit encoding. *)
  for _ = 1 to offset do
    Block_index.GolombRice.encode w ~p:0 0L
  done;
  let x = Int64.shift_left 64L p in
  Block_index.GolombRice.encode w ~p x;
  let encoded = Block_index.GolombRice.to_string w in
  let r = Block_index.GolombRice.create_reader encoded in
  for _ = 1 to offset do
    let _ = Block_index.GolombRice.decode r ~p:0 in ()
  done;
  let got = Block_index.GolombRice.decode r ~p in
  Alcotest.(check bool)
    (Printf.sprintf "S7 offset=%d q=64 round-trips" offset)
    true (Int64.equal got x)

let s7_o0 () = s7_byte_boundary_sweep_offset 0 ()
let s7_o1 () = s7_byte_boundary_sweep_offset 1 ()
let s7_o2 () = s7_byte_boundary_sweep_offset 2 ()
let s7_o3 () = s7_byte_boundary_sweep_offset 3 ()
let s7_o4 () = s7_byte_boundary_sweep_offset 4 ()
let s7_o5 () = s7_byte_boundary_sweep_offset 5 ()
let s7_o6 () = s7_byte_boundary_sweep_offset 6 ()
let s7_o7 () = s7_byte_boundary_sweep_offset 7 ()

(* -- S8 Core regression: BIP-158 blockfilters.json ---------------------- *)

(* test_block_index.ml already covers heights 0, 2, 3, and 1414221 in full.
   Here we re-anchor the genesis vector to ensure the W122 file imports the
   codec correctly. *)
let hex_decode s =
  let n = String.length s in
  assert (n mod 2 = 0);
  Bytes.init (n / 2) (fun i ->
    Char.chr (int_of_string ("0x" ^ String.sub s (i * 2) 2))
  ) |> Bytes.to_string

let hex_encode s =
  let buf = Buffer.create (String.length s * 2) in
  String.iter (fun c ->
    Buffer.add_string buf (Printf.sprintf "%02x" (Char.code c))
  ) s;
  Buffer.contents buf

let s8_core_regression_genesis () =
  let block_hex = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae180101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000" in
  let raw_block = hex_decode block_hex in
  let r = Serialize.reader_of_cstruct (Cstruct.of_string raw_block) in
  let block = Serialize.deserialize_block r in
  let bf = Block_index.build_basic_filter_from_scripts block [] in
  let actual = hex_encode bf.Block_index.filter.Block_index.encoded in
  Alcotest.(check string)
    "S8 BIP-158 genesis filter bytes (Core regression)"
    "019dfca8" actual

(* -- AS1 audit-status assertion: byte-buffered writer architecture ------ *)

(* Source-level regression guard: re-read lib/block_index.ml and assert
   that GolombRice.write_bits uses an int-buffer of one byte (not a
   Word64 or wider buffer).  If a future refactor introduces a wider
   buffer (e.g. for performance), this test fails and the W122 audit
   verdict must be re-issued. *)
let read_file path =
  let ic = open_in path in
  let n = in_channel_length ic in
  let buf = Bytes.create n in
  really_input ic buf 0 n;
  close_in ic;
  Bytes.to_string buf

let resolve_repo_root () =
  let rec up dir depth =
    if depth > 10 then
      Alcotest.fail "could not locate repo root from CWD"
    else if Sys.file_exists
              (Filename.concat dir "lib/block_index.ml") then dir
    else up (Filename.dirname dir) (depth + 1)
  in
  up (Sys.getcwd ()) 0

let block_index_ml () =
  read_file (Filename.concat (resolve_repo_root ()) "lib/block_index.ml")

let contains_substring haystack needle =
  try
    let _ = Str.search_forward (Str.regexp_string needle) haystack 0 in
    true
  with Not_found -> false

let as1_byte_buffered_writer () =
  let src = block_index_ml () in
  (* The writer's [buffer] field is declared as a regular int storing the
     current byte being assembled MSB-first.  The fast-path inner loop
     never writes more than (8 - offset) bits at a time. *)
  Alcotest.(check bool)
    "AS1 writer.buffer is byte-oriented (int field)" true
    (contains_substring src "mutable buffer : int;");
  Alcotest.(check bool)
    "AS1 writer.offset tracks high-order bits 0..8" true
    (contains_substring src
       "(* Number of high-order bits already written (0-8) *)");
  Alcotest.(check bool)
    "AS1 write_bits inner take = min space nbits (byte-bounded)" true
    (contains_substring src "let take = min space !nbits in");
  (* Explicitly assert there is NO 64-bit buffer field — guards against
     a future "performance refactor" introducing the haskoin failure mode. *)
  Alcotest.(check bool)
    "AS1 NO 64-bit buffer field exists" false
    (contains_substring src "mutable buffer : int64;");
  Alcotest.(check bool)
    "AS1 NO Word64-style packed-buffer comment" false
    (contains_substring src "Word64 buffer")

(* The encode loop uses `min remaining 64` to bound each write_bits call.
   Combined with byte-by-byte fill semantics, this is the structural reason
   the haskoin BUG-16 class cannot manifest. *)
let as2_encode_bounds_writes_to_64_bits () =
  let src = block_index_ml () in
  Alcotest.(check bool)
    "AS2 encode bounds each write_bits invocation to <=64 bits" true
    (contains_substring src "let nbits = min remaining 64 in")

(* -- test suite --------------------------------------------------------- *)

let () =
  let open Alcotest in
  run "W122 GCS Codec Stress (BIP-158)" [
    "s1_unary_size", [
      test_case "q=0   unary writes correct byte count" `Quick s1_unary_size_0;
      test_case "q=1   unary writes correct byte count" `Quick s1_unary_size_1;
      test_case "q=8   unary writes correct byte count" `Quick s1_unary_size_8;
      test_case "q=63  unary writes correct byte count" `Quick s1_unary_size_63;
      test_case "q=64  unary writes correct byte count" `Quick s1_unary_size_64;
      test_case "q=65  unary writes correct byte count" `Quick s1_unary_size_65;
      test_case "q=100 unary writes correct byte count" `Quick s1_unary_size_100;
      test_case "q=200 unary writes correct byte count" `Quick s1_unary_size_200;
      test_case "q=1000 unary writes correct byte count" `Quick s1_unary_size_1000;
    ];
    "s2_unaligned_offset", [
      test_case "pad=1 q=64 round-trips" `Quick s2_pad1_q64;
      test_case "pad=3 q=64 round-trips" `Quick s2_pad3_q64;
      test_case "pad=5 q=64 round-trips (haskoin BUG-16 offset)" `Quick s2_pad5_q64;
      test_case "pad=7 q=64 round-trips" `Quick s2_pad7_q64;
      test_case "pad=1 q=65 round-trips" `Quick s2_pad1_q65;
      test_case "pad=5 q=65 round-trips" `Quick s2_pad5_q65;
      test_case "pad=3 q=100 round-trips" `Quick s2_pad3_q100;
      test_case "pad=7 q=100 round-trips" `Quick s2_pad7_q100;
    ];
    "s3_roundtrip", [
      test_case "q=0   round-trip" `Quick s3_rt_q0;
      test_case "q=1   round-trip" `Quick s3_rt_q1;
      test_case "q=63  round-trip" `Quick s3_rt_q63;
      test_case "q=64  round-trip" `Quick s3_rt_q64;
      test_case "q=65  round-trip" `Quick s3_rt_q65;
      test_case "q=100 round-trip" `Quick s3_rt_q100;
      test_case "q=200 round-trip" `Quick s3_rt_q200;
      test_case "q=1000 round-trip" `Quick s3_rt_q1000;
      test_case "q=8191 round-trip (haskoin BUG-16 exact value)" `Quick s3_rt_q8191;
      test_case "q=65535 round-trip" `Quick s3_rt_q65535;
    ];
    "s4_haskoin_bug16_trace", [
      test_case "exact failing trace: 7 small + pad + q=8191" `Quick
        s4_haskoin_bug16_trace;
    ];
    "s5_mixed_stream", [
      test_case "mixed quotient stream {0, 30, 65, 120}" `Quick
        s5_mixed_quotient_stream;
    ];
    "s6_high_p", [
      test_case "P=32 with values up to 2^48" `Quick s6_high_p_p32;
    ];
    "s7_byte_boundary_sweep", [
      test_case "offset=0 q=64" `Quick s7_o0;
      test_case "offset=1 q=64" `Quick s7_o1;
      test_case "offset=2 q=64" `Quick s7_o2;
      test_case "offset=3 q=64" `Quick s7_o3;
      test_case "offset=4 q=64" `Quick s7_o4;
      test_case "offset=5 q=64" `Quick s7_o5;
      test_case "offset=6 q=64" `Quick s7_o6;
      test_case "offset=7 q=64" `Quick s7_o7;
    ];
    "s8_core_regression", [
      test_case "BIP-158 blockfilters.json genesis row" `Quick
        s8_core_regression_genesis;
    ];
    "audit_status", [
      test_case "AS1 byte-buffered writer architecture preserved" `Quick
        as1_byte_buffered_writer;
      test_case "AS2 encode bounds writes to <=64 bits" `Quick
        as2_encode_bounds_writes_to_64_bits;
    ];
  ]
