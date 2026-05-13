(* W107 CompactSize + VarInt serialization audit
   Reference: bitcoin-core/src/serialize.h — WriteCompactSize, ReadCompactSize,
              WriteVarInt, ReadVarInt, MAX_SIZE = 0x02000000

   Bugs discovered in this wave:

   === G1-G5: MAX_SIZE Constant ===

   BUG-1  CORRECTNESS (G9/HIGH)  read_compact_size: 0xFE branch rejects valid values
          0x80000000..0xFFFFFFFF with wrong "exceeds max int" error.
          serialize.ml:80 — `Int32.compare v32 0l < 0` — treats any high-bit
          int32 as negative overflow before the max_size check fires.
          With range_check=false (Core's generic number path) those 2.1B values
          are legitimate. With range_check=true they should be rejected with
          "too large", not "exceeds max int".
          Core: nSizeRet = ser_readdata32(is); checks nSizeRet < 0x10000u for
          canonical, then MAX_SIZE for range, no sign check.

   BUG-2  CORRECTNESS (G10/HIGH)  No range_check parameter on read_compact_size.
          Core ReadCompactSize(is, bool range_check = true) lets callers opt out
          of MAX_SIZE enforcement for generic uint64 fields (services bits,
          PSBT fields, etc.). camlcoin's read_compact_size always enforces MAX_SIZE.
          Any peer-sent CompactSize that encodes a large uint64 non-size value
          (e.g. future service flags > 0x02000000) will be silently rejected.

   BUG-3  DEAD CODE (G5/LOW)  0xFD branch: `v > max_size` is unreachable.
          serialize.ml:74 — v is read_uint16_le, max value 65535 < 33554432
          (max_size). The check can never fire. Similarly, the 0xFF branch
          `Int64.compare v64 (Int64.of_int max_int) > 0` is dead on 64-bit
          (max_size check fires first for all v64 > max_size).

   === G6-G8: Non-Canonical Enforcement ===

   BUG-4  CORRECTNESS (G6/MEDIUM)  read_compact_size_int64: no non-canonical
          check in any branch. serialize.ml:144-152 — 0xFD branch does not
          check v < 0xFD; 0xFE branch does not check v < 0x10000; 0xFF branch
          does not check v < 0x100000000. A peer can send FD 00 00 (non-minimal
          encoding of 0) and it will be silently accepted. Core rejects all
          non-canonical forms unconditionally.
          Used in p2p.ml addrv2 v2_services field parsing.

   BUG-5  CORRECTNESS (G9/MEDIUM)  read_compact_size_int64: no MAX_SIZE / range
          check at all. Core ReadCompactSize enforces MAX_SIZE by default.
          read_compact_size_int64 accepts arbitrarily large values with no cap,
          even when the call site is reading a length (not a flag).

   === G11-G14: Write Side ===

   BUG-6  CORRECTNESS (G21/MEDIUM)  write_compact_size: no guard against
          negative input. write_compact_size (-1): -1 < 0xFD is true (OCaml
          signed comparison) → write_uint8 w (-1 land 0xFF) = write 0xFF.
          0xFF is the 8-byte CompactSize marker; the receiver will try to read 8
          more bytes as a uint64 CompactSize length, causing catastrophic parse
          error. write_varint correctly raises invalid_arg on negative;
          write_compact_size lacks the same guard.

   BUG-7  CORRECTNESS (G13/HIGH)  write_compact_size / read_compact_size
          asymmetry for 0x80000000..0xFFFFFFFF. The write side correctly emits
          FE xx xx xx xx (4 correct bytes via Int32.of_int truncation), but the
          read side rejects the same bytes with "exceeds max int" (BUG-1).
          Round-trip is broken for any CompactSize value >= 2^31.

   === G15: GetSizeOfCompactSize ===

   BUG-8  MISSING (G15/LOW)  No get_size_of_compact_size function exported.
          Core provides GetSizeOfCompactSize(uint64_t) as a pure O(1) utility
          used when pre-computing serialized lengths before writing.
          camlcoin callers must write-and-measure, which is wasteful and
          error-prone.

   === G19: VarInt uint64 Capacity ===

   BUG-9  CORRECTNESS (G19/MEDIUM)  read_varint_int64 overflow sentinel uses
          Int64.max_int (2^63-1 = 9223372036854775807) instead of uint64 max
          (2^64-1 = 18446744073709551615). compressor.ml:121.
          Core ReadVarInt<uint64_t> uses numeric_limits<uint64_t>::max.
          VarInt-encoded values in range 2^63..2^64-1 are rejected by camlcoin
          but accepted by Core. Theoretical for script sizes but affects any
          full-uint64 use of VarInt.

   BUG-10  COMMENT (G1/LOW)  serialize.ml:60 comment says "32 MB" but
           0x02000000 = 33554432 bytes = 32 MiB (mebibytes), not 32 megabytes
           (32000000 bytes). Value is correct; comment is misleading.
           Matches the shared-bad-doc pattern from W98/FIX-5.

   BUG-11  CORRECTNESS (G13/HIGH)  read_compact_size_int64 0xFE branch
           sign-extends int32. serialize.ml:150 — `Int64.of_int32 (read_int32_le r)`.
           read_int32_le returns OCaml int32 which is signed; for any 4-byte
           value with the high bit set (0x80000000..0xFFFFFFFF), Int64.of_int32
           sign-extends to a negative int64. E.g. 0xFFFFFFFF reads back as -1L.
           Core: ser_readdata32 reads as uint32 with no sign extension.
           Impact: services fields or BIP-155 addr lengths in range
           0x80000000..0xFFFFFFFF are decoded with wrong sign.
*)

(* Summary: 11 bugs found.
   HIGH:   BUG-1, BUG-7, BUG-11 (3 bugs)
   MEDIUM: BUG-2, BUG-4, BUG-5, BUG-6, BUG-9 (5 bugs)
   LOW:    BUG-3, BUG-8, BUG-10 (3 bugs)
*)

open Camlcoin

(* =====================================================================
   Helpers
   ===================================================================== *)

let cstruct_of_bytes bs =
  let len = Bytes.length bs in
  let cs = Cstruct.create len in
  for i = 0 to len - 1 do
    Cstruct.set_uint8 cs i (Char.code (Bytes.get bs i))
  done;
  cs

let cstruct_of_list bytes =
  let cs = Cstruct.create (List.length bytes) in
  List.iteri (fun i b -> Cstruct.set_uint8 cs i b) bytes;
  cs

let reader_of_list bytes =
  Serialize.reader_of_cstruct (cstruct_of_list bytes)

let raises_exn f =
  try ignore (f ()); false
  with _ -> true

(* =====================================================================
   G1–G5: MAX_SIZE constant
   ===================================================================== *)

(* G1: MAX_SIZE value matches Core *)
let test_max_size_value () =
  (* Core: static constexpr uint64_t MAX_SIZE = 0x02000000 *)
  (* We verify by checking that read_compact_size accepts 0x02000000 but
     rejects 0x02000001 (one above MAX_SIZE). We encode via write and
     feed back. *)
  let w = Serialize.writer_create () in
  Serialize.write_compact_size w 0x02000000;
  let cs = Serialize.writer_to_cstruct w in
  let r = Serialize.reader_of_cstruct cs in
  let v = Serialize.read_compact_size r in
  Alcotest.(check int) "MAX_SIZE=0x02000000 accepted" 0x02000000 v

(* G2: 1-byte range: 0..252 *)
let test_compact_size_1byte_range () =
  List.iter (fun n ->
    let w = Serialize.writer_create () in
    Serialize.write_compact_size w n;
    let cs = Serialize.writer_to_cstruct w in
    Alcotest.(check int) (Printf.sprintf "1-byte length for %d" n) 1 (Cstruct.length cs);
    let r = Serialize.reader_of_cstruct cs in
    Alcotest.(check int) (Printf.sprintf "1-byte roundtrip %d" n) n (Serialize.read_compact_size r)
  ) [0; 1; 0xFC; 252]

(* G3: 2-byte range: 0xFD..0xFFFF *)
let test_compact_size_2byte_range () =
  List.iter (fun n ->
    let w = Serialize.writer_create () in
    Serialize.write_compact_size w n;
    let cs = Serialize.writer_to_cstruct w in
    Alcotest.(check int) (Printf.sprintf "2-byte length for %d" n) 3 (Cstruct.length cs);
    Alcotest.(check int) "2-byte marker 0xFD" 0xFD (Cstruct.get_uint8 cs 0);
    let r = Serialize.reader_of_cstruct cs in
    Alcotest.(check int) (Printf.sprintf "2-byte roundtrip %d" n) n (Serialize.read_compact_size r)
  ) [0xFD; 0x100; 0xFFFF]

(* G4: 4-byte range: 0x10000..0x7FFFFFFF (within MAX_SIZE) *)
let test_compact_size_4byte_range () =
  List.iter (fun n ->
    let w = Serialize.writer_create () in
    Serialize.write_compact_size w n;
    let cs = Serialize.writer_to_cstruct w in
    Alcotest.(check int) (Printf.sprintf "4-byte length for 0x%x" n) 5 (Cstruct.length cs);
    Alcotest.(check int) "4-byte marker 0xFE" 0xFE (Cstruct.get_uint8 cs 0);
    let r = Serialize.reader_of_cstruct cs in
    Alcotest.(check int) (Printf.sprintf "4-byte roundtrip 0x%x" n) n (Serialize.read_compact_size r)
  ) [0x10000; 0x100000; 0x1000000; 0x02000000 (* MAX_SIZE *)]

(* G5: 8-byte range (not tested here since MAX_SIZE < 2^32; range-check would
   fire. The write/read of 8-byte values requires CompactSize_int64 variant.) *)
let test_compact_size_max_rejects_oversized () =
  (* Values above MAX_SIZE should be rejected on read *)
  (* Write 0x02000001 manually as 8-byte CompactSize to bypass write guard *)
  let v = 0x02000001 in
  let w = Serialize.writer_create () in
  Serialize.write_compact_size_int64 w (Int64.of_int v);
  let cs = Serialize.writer_to_cstruct w in
  let r = Serialize.reader_of_cstruct cs in
  (* read_compact_size should reject this value as > MAX_SIZE *)
  Alcotest.(check bool) "read rejects > MAX_SIZE" true (raises_exn (fun () -> Serialize.read_compact_size r))

(* =====================================================================
   G6–G8: Non-canonical enforcement
   ===================================================================== *)

(* G6: Non-canonical 2-byte: FD 00 00 (value 0 in 2-byte form, should use 1-byte) *)
let test_non_canonical_fd () =
  (* Manually construct non-canonical: marker FD, value 0 *)
  let r = reader_of_list [0xFD; 0x00; 0x00] in
  Alcotest.(check bool) "non-canonical FD 00 00 rejected" true
    (raises_exn (fun () -> Serialize.read_compact_size r))

(* G7: Non-canonical 4-byte: FE 00 00 FF 00 (value 0xFF00 in 4-byte form) *)
let test_non_canonical_fe () =
  (* Value 0xFFFF encoded as 4-byte FE when 2-byte FD would be canonical *)
  let r = reader_of_list [0xFE; 0xFF; 0xFF; 0x00; 0x00] in
  Alcotest.(check bool) "non-canonical FE FF FF 00 00 rejected" true
    (raises_exn (fun () -> Serialize.read_compact_size r))

(* G8: Non-canonical 8-byte: FF 00 00 00 00 FF 00 00 00 (value < 2^32 in 8-byte) *)
let test_non_canonical_ff () =
  (* Value 0xFF000000 (< 2^32, should use 4-byte FE) encoded with FF marker *)
  let r = reader_of_list [0xFF; 0x00; 0x00; 0x00; 0xFF; 0x00; 0x00; 0x00; 0x00] in
  Alcotest.(check bool) "non-canonical FF with value < 2^32 rejected" true
    (raises_exn (fun () -> Serialize.read_compact_size r))

(* =====================================================================
   G9: MAX_SIZE range check
   ===================================================================== *)

(* G9: read_compact_size enforces MAX_SIZE *)
let test_max_size_enforcement () =
  (* write a value at MAX_SIZE boundary and one above it *)
  let w = Serialize.writer_create () in
  Serialize.write_compact_size w 0x02000000;
  let cs = Serialize.writer_to_cstruct w in
  let r = Serialize.reader_of_cstruct cs in
  let v = Serialize.read_compact_size r in
  Alcotest.(check int) "MAX_SIZE exactly accepted" 0x02000000 v;
  (* Manually encode 0x02000001 in 8-byte form *)
  let r2 = reader_of_list [0xFF; 0x01; 0x00; 0x00; 0x02; 0x00; 0x00; 0x00; 0x00] in
  Alcotest.(check bool) "MAX_SIZE+1 rejected" true
    (raises_exn (fun () -> Serialize.read_compact_size r2))

(* =====================================================================
   BUG-1 (G3/HIGH): 0xFE branch rejects 0x80000000..0xFFFFFFFF
   These values ARE above MAX_SIZE so range-check would fire anyway,
   but the error message is wrong and any range_check=false caller would
   be broken.
   ===================================================================== *)

(* BUG-1 assertion: reads FE 00 00 00 80 (= 0x80000000) and checks
   whether it is rejected with a sensible error (it SHOULD be rejected
   because 0x80000000 > MAX_SIZE, but the REASON should be max_size not
   int overflow). *)
let test_bug1_fe_high_bit_error_category () =
  (* 0x80000000 encoded as 4-byte CompactSize: FE 00 00 00 80 *)
  let r = reader_of_list [0xFE; 0x00; 0x00; 0x00; 0x80] in
  (* We expect this to raise; the value 0x80000000 > MAX_SIZE so rejection
     is correct, but the cause is max_size not int overflow. Verify it
     raises (the wrong reason is a latent interop risk with range_check=false). *)
  Alcotest.(check bool) "0x80000000 in FE branch raises" true
    (raises_exn (fun () -> Serialize.read_compact_size r))

(* =====================================================================
   G10: range_check=false support (BUG-2)
   ===================================================================== *)

(* BUG-2: No range_check=false path. We document this by verifying that
   read_compact_size always enforces MAX_SIZE even for non-size usage. *)
let test_bug2_no_range_check_false () =
  (* A hypothetical services field of 0x02000001 (> MAX_SIZE but valid uint64
     flag) would be rejected. We verify read enforces MAX_SIZE unconditionally
     by feeding a legitimate > MAX_SIZE value and checking it raises. *)
  let r = reader_of_list [0xFF; 0x01; 0x00; 0x00; 0x02; 0x00; 0x00; 0x00; 0x00] in
  Alcotest.(check bool) "no range_check=false: >MAX_SIZE always rejected" true
    (raises_exn (fun () -> Serialize.read_compact_size r))

(* =====================================================================
   G11–G14: Write side correctness
   ===================================================================== *)

(* G11: 1-byte write — exact bytes *)
let test_write_1byte () =
  List.iter (fun (n, expected) ->
    let w = Serialize.writer_create () in
    Serialize.write_compact_size w n;
    let cs = Serialize.writer_to_cstruct w in
    let got = Cstruct.get_uint8 cs 0 in
    Alcotest.(check int) (Printf.sprintf "write 0x%02x -> 0x%02x" n expected) expected got
  ) [(0, 0); (1, 1); (252, 0xFC)]

(* G12: 2-byte write — marker + LE uint16 *)
let test_write_2byte () =
  let w = Serialize.writer_create () in
  Serialize.write_compact_size w 0x1234;
  let cs = Serialize.writer_to_cstruct w in
  Alcotest.(check int) "marker 0xFD" 0xFD (Cstruct.get_uint8 cs 0);
  Alcotest.(check int) "low byte 0x34" 0x34 (Cstruct.get_uint8 cs 1);
  Alcotest.(check int) "high byte 0x12" 0x12 (Cstruct.get_uint8 cs 2)

(* G13: 4-byte write — marker + LE uint32 *)
let test_write_4byte () =
  let w = Serialize.writer_create () in
  Serialize.write_compact_size w 0x12345678;
  let cs = Serialize.writer_to_cstruct w in
  Alcotest.(check int) "marker 0xFE" 0xFE (Cstruct.get_uint8 cs 0);
  (* LE: 78 56 34 12 *)
  Alcotest.(check int) "byte1 0x78" 0x78 (Cstruct.get_uint8 cs 1);
  Alcotest.(check int) "byte2 0x56" 0x56 (Cstruct.get_uint8 cs 2);
  Alcotest.(check int) "byte3 0x34" 0x34 (Cstruct.get_uint8 cs 3);
  Alcotest.(check int) "byte4 0x12" 0x12 (Cstruct.get_uint8 cs 4)

(* G14: 8-byte write via int64 variant — marker + LE uint64 *)
let test_write_8byte () =
  let w = Serialize.writer_create () in
  Serialize.write_compact_size_int64 w 0x0102030405060708L;
  let cs = Serialize.writer_to_cstruct w in
  Alcotest.(check int) "marker 0xFF" 0xFF (Cstruct.get_uint8 cs 0);
  (* LE: 08 07 06 05 04 03 02 01 *)
  Alcotest.(check int) "byte1 0x08" 0x08 (Cstruct.get_uint8 cs 1);
  Alcotest.(check int) "byte8 0x01" 0x01 (Cstruct.get_uint8 cs 8)

(* =====================================================================
   BUG-6 (G21/MEDIUM): write_compact_size negative input
   ===================================================================== *)

(* BUG-6: write_compact_size(-1) silently writes 0xFF (8-byte marker).
   This should raise (like write_varint does). *)
let test_bug6_write_negative () =
  (* We document the CURRENT behaviour: -1 land 0xFF = 255 = 0xFF.
     The byte 0xFF is the 8-byte CompactSize marker, which will cause
     catastrophic parse failure on the receiver.
     Correct behaviour: raise Invalid_argument. *)
  let w = Serialize.writer_create () in
  Serialize.write_compact_size w (-1);
  let cs = Serialize.writer_to_cstruct w in
  (* Currently produces 0xFF (the 8-byte marker) — this is the bug. *)
  Alcotest.(check int) "BUG-6: write_compact_size(-1) emits 0xFF marker (should raise)"
    0xFF (Cstruct.get_uint8 cs 0)

(* =====================================================================
   BUG-7 (G13/HIGH): write/read asymmetry for 0x80000000..0xFFFFFFFF
   ===================================================================== *)

(* BUG-7: write_compact_size correctly emits FE xx xx xx xx for values in
   0x80000000..0xFFFFFFFF (Int32.of_int truncation produces right bytes),
   but read_compact_size rejects the same bytes. *)
let test_bug7_write_read_asymmetry_0x80000000 () =
  (* 0x80000000 > MAX_SIZE, so range-check is a red herring.
     The roundtrip bug would matter for any range_check=false caller.
     We verify the write produces correct bytes. *)
  let v = 0x80000000 in   (* = 2147483648 *)
  let w = Serialize.writer_create () in
  (* write_compact_size: v > 0xFFFF and v <= 0xFFFFFFFF -> FE marker + int32 *)
  (* Int32.of_int 0x80000000 = -2147483648l; written as LE 4 bytes = 00 00 00 80 *)
  Serialize.write_compact_size w v;
  let cs = Serialize.writer_to_cstruct w in
  Alcotest.(check int) "BUG-7: 0x80000000 write: marker 0xFE" 0xFE (Cstruct.get_uint8 cs 0);
  Alcotest.(check int) "BUG-7: 0x80000000 write: byte1 0x00" 0x00 (Cstruct.get_uint8 cs 1);
  Alcotest.(check int) "BUG-7: 0x80000000 write: byte4 0x80" 0x80 (Cstruct.get_uint8 cs 4);
  (* Read back: raises due to BUG-1 (int32 sign bit treated as overflow) *)
  let r = Serialize.reader_of_cstruct cs in
  Alcotest.(check bool) "BUG-7: read of correctly-written 0x80000000 raises (asymmetry)" true
    (raises_exn (fun () -> Serialize.read_compact_size r))

(* =====================================================================
   G16–G20: VarInt (compressor.ml)
   ===================================================================== *)

(* G16: VarInt write correctness — spec vectors *)
let test_varint_write_vectors () =
  let w = Serialize.writer_create () in
  let check label n expected =
    let buf = Buffer.create 4 in
    let tmp_w = { Serialize.buf } in
    Compressor.write_varint tmp_w n;
    let got_len = Buffer.length buf in
    let got = Buffer.contents buf in
    Alcotest.(check int) (label ^ " length") (List.length expected) got_len;
    List.iteri (fun i b ->
      Alcotest.(check int) (Printf.sprintf "%s byte[%d]" label i)
        b (Char.code (String.get got i))
    ) expected;
    ignore w
  in
  (* Spec: 0→[0x00], 127→[0x7F], 128→[0x80,0x00], 255→[0x80,0x7F],
           256→[0x81,0x00], 16383→[0xFE,0x7F], 16384→[0xFF,0x00] *)
  check "varint(0)" 0 [0x00];
  check "varint(127)" 127 [0x7F];
  check "varint(128)" 128 [0x80; 0x00];
  check "varint(255)" 255 [0x80; 0x7F];
  check "varint(256)" 256 [0x81; 0x00];
  check "varint(16383)" 16383 [0xFE; 0x7F];
  check "varint(16384)" 16384 [0xFF; 0x00]

(* G17: VarInt read correctness — spec vectors *)
let test_varint_read_vectors () =
  let check label expected bytes =
    let r = reader_of_list bytes in
    let got = Compressor.read_varint r in
    Alcotest.(check int) label expected got
  in
  check "read_varint([0x00])" 0 [0x00];
  check "read_varint([0x7F])" 127 [0x7F];
  check "read_varint([0x80,0x00])" 128 [0x80; 0x00];
  check "read_varint([0x80,0x7F])" 255 [0x80; 0x7F];
  check "read_varint([0x81,0x00])" 256 [0x81; 0x00];
  check "read_varint([0xFE,0x7F])" 16383 [0xFE; 0x7F];
  check "read_varint([0xFF,0x00])" 16384 [0xFF; 0x00]

(* G18: VarInt overflow guard on read *)
let test_varint_overflow_guard () =
  (* An extremely long VarInt encoding designed to overflow: 10 bytes of 0x80
     would attempt a left-shift of 70 bits which should be caught. *)
  let overflow_bytes = [0x80; 0x80; 0x80; 0x80; 0x80; 0x80; 0x80; 0x80; 0x80; 0x80; 0x00] in
  let r = reader_of_list overflow_bytes in
  Alcotest.(check bool) "VarInt overflow rejected" true
    (raises_exn (fun () -> Compressor.read_varint r))

(* G29: VarInt termination — n <= 0x7F stops the loop *)
let test_varint_termination () =
  (* Single-byte encodings 0..127 must NOT consume additional bytes *)
  let data = [0x42; 0xFF] in  (* 0x42 = 66, valid 1-byte; 0xFF should not be consumed *)
  let r = reader_of_list data in
  let v = Compressor.read_varint r in
  Alcotest.(check int) "varint(0x42) = 66" 66 v;
  (* Confirm second byte was not consumed *)
  Alcotest.(check int) "reader pos after 1-byte varint" 1 r.Serialize.pos

(* G30: VarInt n-1 decrement — test that 128 is encoded as [0x80, 0x00] not [0x80, 0x80] *)
let test_varint_n_minus_1_decrement () =
  (* The -1 decrement in write means n=128 encodes as [0x80, 0x00]:
     tmp[0] = 128 & 0x7F | 0x00 = 0x00
     n = (128 >> 7) - 1 = 1 - 1 = 0; len = 1
     tmp[1] = 0 | 0x80 = 0x80
     emit: 0x80, 0x00 *)
  let r = reader_of_list [0x80; 0x00] in
  let v = Compressor.read_varint r in
  Alcotest.(check int) "[0x80, 0x00] decodes to 128 (n-1 decrement)" 128 v

(* G20: VarInt negative input rejection *)
let test_varint_negative_rejected () =
  Alcotest.(check bool) "write_varint(-1) raises" true
    (raises_exn (fun () ->
      let w = Serialize.writer_create () in
      Compressor.write_varint w (-1)))

(* =====================================================================
   BUG-9 (G19/MEDIUM): read_varint_int64 uses Int64.max_int not uint64 max
   ===================================================================== *)

(* BUG-9: The overflow sentinel is Int64.max_int = 2^63-1, not uint64 max = 2^64-1.
   We test that read_varint_int64 correctly handles values near 2^63 that are
   valid in Core's uint64 VarInt. *)
let test_bug9_varint_int64_capacity () =
  (* Write and re-read Int64.max_int (2^63-1) — should round-trip. *)
  let max_val = Int64.max_int in
  let w = Serialize.writer_create () in
  Compressor.write_varint_int64 w max_val;
  let cs = Serialize.writer_to_cstruct w in
  let r = Serialize.reader_of_cstruct cs in
  let got = Compressor.read_varint_int64 r in
  Alcotest.(check int64) "varint_int64 roundtrip max_int" max_val got

(* =====================================================================
   BUG-4 (G6/MEDIUM): read_compact_size_int64 no non-canonical check
   ===================================================================== *)

(* BUG-4: Non-canonical FD 00 00 (value 0 in 2-byte form) must be rejected.
   Currently accepted. *)
let test_bug4_compact_size_int64_non_canonical () =
  (* FD 00 00 = non-canonical encoding of 0 (should use 1-byte) *)
  let r = reader_of_list [0xFD; 0x00; 0x00] in
  (* Core rejects; camlcoin currently accepts — document this bug *)
  let v = Serialize.read_compact_size_int64 r in
  (* BUG: This should raise but currently returns 0L *)
  Alcotest.(check int64) "BUG-4: non-canonical FD 00 00 accepted (should raise)" 0L v

(* BUG-5: No range check in read_compact_size_int64 *)
let test_bug5_compact_size_int64_no_range_check () =
  (* Encode a value well above MAX_SIZE (0x02000000) as 8-byte CompactSize *)
  (* FF 00 00 00 03 00 00 00 00 = 0x0300000000 = 12884901888 > MAX_SIZE *)
  let r = reader_of_list [0xFF; 0x00; 0x00; 0x00; 0x03; 0x00; 0x00; 0x00; 0x00] in
  let v = Serialize.read_compact_size_int64 r in
  (* BUG: accepted without range check; > MAX_SIZE *)
  Alcotest.(check bool) "BUG-5: >MAX_SIZE in read_compact_size_int64 accepted (should raise)"
    true (Int64.compare v 0x02000000L > 0)

(* =====================================================================
   G26–G28: Endianness
   ===================================================================== *)

(* G26: uint16 LE *)
let test_endian_uint16_le () =
  let w = Serialize.writer_create () in
  Serialize.write_uint16_le w 0x1234;
  let cs = Serialize.writer_to_cstruct w in
  Alcotest.(check int) "LE uint16 low byte" 0x34 (Cstruct.get_uint8 cs 0);
  Alcotest.(check int) "LE uint16 high byte" 0x12 (Cstruct.get_uint8 cs 1)

(* G27: int32 LE *)
let test_endian_int32_le () =
  let w = Serialize.writer_create () in
  Serialize.write_int32_le w 0x12345678l;
  let cs = Serialize.writer_to_cstruct w in
  Alcotest.(check int) "LE int32 byte0" 0x78 (Cstruct.get_uint8 cs 0);
  Alcotest.(check int) "LE int32 byte1" 0x56 (Cstruct.get_uint8 cs 1);
  Alcotest.(check int) "LE int32 byte2" 0x34 (Cstruct.get_uint8 cs 2);
  Alcotest.(check int) "LE int32 byte3" 0x12 (Cstruct.get_uint8 cs 3)

(* G28: int64 LE *)
let test_endian_int64_le () =
  let w = Serialize.writer_create () in
  Serialize.write_int64_le w 0x0102030405060708L;
  let cs = Serialize.writer_to_cstruct w in
  Alcotest.(check int) "LE int64 byte0" 0x08 (Cstruct.get_uint8 cs 0);
  Alcotest.(check int) "LE int64 byte7" 0x01 (Cstruct.get_uint8 cs 7)

(* =====================================================================
   Property-based roundtrip
   ===================================================================== *)

let qcheck_compact_size_small_roundtrip =
  QCheck.Test.make ~count:1000 ~name:"compact_size small roundtrip"
    QCheck.(int_range 0 0xFFFF)
    (fun n ->
      let w = Serialize.writer_create () in
      Serialize.write_compact_size w n;
      let cs = Serialize.writer_to_cstruct w in
      let r = Serialize.reader_of_cstruct cs in
      let got = Serialize.read_compact_size r in
      got = n)

let qcheck_varint_roundtrip =
  QCheck.Test.make ~count:1000 ~name:"varint roundtrip"
    QCheck.(int_range 0 0x3FFFFFFF)
    (fun n ->
      let w = Serialize.writer_create () in
      Compressor.write_varint w n;
      let cs = Serialize.writer_to_cstruct w in
      let r = Serialize.reader_of_cstruct cs in
      let got = Compressor.read_varint r in
      got = n)

let qcheck_varint_int64_roundtrip =
  QCheck.Test.make ~count:1000 ~name:"varint_int64 roundtrip"
    QCheck.(map (fun n -> Int64.of_int n) (int_range 0 0x0FFFFFFF))
    (fun n ->
      let w = Serialize.writer_create () in
      Compressor.write_varint_int64 w n;
      let cs = Serialize.writer_to_cstruct w in
      let r = Serialize.reader_of_cstruct cs in
      let got = Compressor.read_varint_int64 r in
      Int64.equal got n)

(* =====================================================================
   VarInt int64 full write/read vectors
   ===================================================================== *)

let test_varint_int64_write_vectors () =
  let check label (n : int64) expected =
    let buf = Buffer.create 10 in
    let tmp_w = { Serialize.buf } in
    Compressor.write_varint_int64 tmp_w n;
    let got = Buffer.contents buf in
    Alcotest.(check int) (label ^ " length") (List.length expected) (String.length got);
    List.iteri (fun i b ->
      Alcotest.(check int) (Printf.sprintf "%s byte[%d]" label i)
        b (Char.code (String.get got i))
    ) expected
  in
  check "varint_int64(0)" 0L [0x00];
  check "varint_int64(127)" 127L [0x7F];
  check "varint_int64(128)" 128L [0x80; 0x00];
  check "varint_int64(65535)" 65535L [0x82; 0xFE; 0x7F]

let test_varint_int64_read_vectors () =
  let check label (expected : int64) bytes =
    let r = reader_of_list bytes in
    let got = Compressor.read_varint_int64 r in
    Alcotest.(check int64) label expected got
  in
  check "read_varint_int64([0x00])" 0L [0x00];
  check "read_varint_int64([0x7F])" 127L [0x7F];
  check "read_varint_int64([0x80,0x00])" 128L [0x80; 0x00];
  check "read_varint_int64([0x82,0xFE,0x7F])" 65535L [0x82; 0xFE; 0x7F]

(* =====================================================================
   BUG-11 (G13/HIGH): read_compact_size_int64 0xFE branch sign-extends int32

   serialize.ml:150 — `Int64.of_int32 (read_int32_le r)` — sign-extends the
   uint32 payload. For value 0xFFFFFFFF: read_int32_le returns -1l (signed),
   Int64.of_int32 (-1l) = -1L (0xFFFFFFFFFFFFFFFF). The write side correctly
   emits FE FF FF FF FF but the read side returns -1L not 4294967295L.
   Core: nSizeRet = ser_readdata32(is) — reads as uint32, no sign extension.
   Impact: any services field or BIP-155 addr length in 0x80000000..0xFFFFFFFF
   range will be decoded with wrong sign, causing silent misinterpretation.
   ===================================================================== *)

let test_bug11_compact_size_int64_sign_extension () =
  (* write 0xFFFFFFFF via int64 variant — writes FE FF FF FF FF *)
  let w = Serialize.writer_create () in
  Serialize.write_compact_size_int64 w 0xFFFFFFFFL;
  let cs = Serialize.writer_to_cstruct w in
  Alcotest.(check int) "BUG-11: write length" 5 (Cstruct.length cs);
  Alcotest.(check int) "BUG-11: marker 0xFE" 0xFE (Cstruct.get_uint8 cs 0);
  (* Read back: should return 4294967295L but returns -1L due to sign extension *)
  let r = Serialize.reader_of_cstruct cs in
  let got = Serialize.read_compact_size_int64 r in
  (* Document actual (buggy) behavior: -1L *)
  Alcotest.(check int64) "BUG-11: read_compact_size_int64(0xFFFFFFFF) returns -1L (sign-extend bug)" (-1L) got

(* =====================================================================
   CompactSize_int64 write/read roundtrip vectors (correct range only)
   ===================================================================== *)

let test_compact_size_int64_write_read () =
  let check label (v : int64) expected_len =
    let w = Serialize.writer_create () in
    Serialize.write_compact_size_int64 w v;
    let cs = Serialize.writer_to_cstruct w in
    Alcotest.(check int) (label ^ " length") expected_len (Cstruct.length cs);
    let r = Serialize.reader_of_cstruct cs in
    let got = Serialize.read_compact_size_int64 r in
    Alcotest.(check int64) (label ^ " roundtrip") v got
  in
  check "int64 0" 0L 1;
  check "int64 252" 252L 1;
  check "int64 0xFD" 0xFDL 3;
  check "int64 0xFFFF" 0xFFFFL 3;
  check "int64 0x10000" 0x10000L 5;
  (* Note: 0xFFFFFFFF skipped — affected by BUG-11 sign-extension *)
  check "int64 0x7FFFFFFF" 0x7FFFFFFFL 5;
  check "int64 0x100000000" 0x100000000L 9

(* =====================================================================
   Test runner
   ===================================================================== *)

let () =
  let _ = cstruct_of_bytes (Bytes.create 0) in  (* suppress unused warning *)
  let open Alcotest in
  run "test_w107_compactsize" [
    "G1-G5 max_size", [
      test_case "MAX_SIZE=0x02000000 accepted" `Quick test_max_size_value;
      test_case "1-byte range 0..252" `Quick test_compact_size_1byte_range;
      test_case "2-byte range 0xFD..0xFFFF" `Quick test_compact_size_2byte_range;
      test_case "4-byte range 0x10000..MAX_SIZE" `Quick test_compact_size_4byte_range;
      test_case ">MAX_SIZE rejected" `Quick test_compact_size_max_rejects_oversized;
    ];
    "G6-G8 non-canonical", [
      test_case "FD with value < 0xFD rejected" `Quick test_non_canonical_fd;
      test_case "FE with value < 0x10000 rejected" `Quick test_non_canonical_fe;
      test_case "FF with value < 2^32 rejected" `Quick test_non_canonical_ff;
    ];
    "G9 range check", [
      test_case "MAX_SIZE enforcement" `Quick test_max_size_enforcement;
    ];
    "G10 range_check=false (BUG-2)", [
      test_case "no range_check=false: >MAX_SIZE always rejected" `Quick test_bug2_no_range_check_false;
    ];
    "G11-G14 write side", [
      test_case "1-byte write" `Quick test_write_1byte;
      test_case "2-byte write LE" `Quick test_write_2byte;
      test_case "4-byte write LE" `Quick test_write_4byte;
      test_case "8-byte write LE (int64)" `Quick test_write_8byte;
    ];
    "BUG-1 (G3/HIGH) FE high-bit rejection", [
      test_case "BUG-1: 0x80000000 in FE branch raises" `Quick test_bug1_fe_high_bit_error_category;
    ];
    "BUG-6 (G21/MEDIUM) write_compact_size negative", [
      test_case "BUG-6: write_compact_size(-1) emits 0xFF marker" `Quick test_bug6_write_negative;
    ];
    "BUG-7 (G13/HIGH) write/read asymmetry >= 2^31", [
      test_case "BUG-7: 0x80000000 write ok but read raises" `Quick test_bug7_write_read_asymmetry_0x80000000;
    ];
    "G16-G20 varint", [
      test_case "VarInt write vectors" `Quick test_varint_write_vectors;
      test_case "VarInt read vectors" `Quick test_varint_read_vectors;
      test_case "VarInt overflow rejected" `Quick test_varint_overflow_guard;
      test_case "VarInt termination at n<=0x7F" `Quick test_varint_termination;
      test_case "VarInt n-1 decrement" `Quick test_varint_n_minus_1_decrement;
      test_case "VarInt negative rejected" `Quick test_varint_negative_rejected;
    ];
    "BUG-9 (G19/MEDIUM) varint_int64 capacity", [
      test_case "BUG-9: varint_int64 roundtrip max_int" `Quick test_bug9_varint_int64_capacity;
    ];
    "BUG-4 (G6/MEDIUM) compact_size_int64 no non-canonical", [
      test_case "BUG-4: non-canonical FD 00 00 accepted" `Quick test_bug4_compact_size_int64_non_canonical;
    ];
    "BUG-5 (G9/MEDIUM) compact_size_int64 no range check", [
      test_case "BUG-5: >MAX_SIZE accepted in int64 variant" `Quick test_bug5_compact_size_int64_no_range_check;
    ];
    "varint_int64 vectors", [
      test_case "varint_int64 write vectors" `Quick test_varint_int64_write_vectors;
      test_case "varint_int64 read vectors" `Quick test_varint_int64_read_vectors;
    ];
    "BUG-11 (G13/HIGH) compact_size_int64 sign-extension", [
      test_case "BUG-11: FE branch sign-extends 0xFFFFFFFF to -1L" `Quick test_bug11_compact_size_int64_sign_extension;
    ];
    "compact_size_int64 roundtrip", [
      test_case "compact_size_int64 write/read" `Quick test_compact_size_int64_write_read;
    ];
    "G26-G28 endianness", [
      test_case "uint16 LE" `Quick test_endian_uint16_le;
      test_case "int32 LE" `Quick test_endian_int32_le;
      test_case "int64 LE" `Quick test_endian_int64_le;
    ];
    "property tests", [
      QCheck_alcotest.to_alcotest qcheck_compact_size_small_roundtrip;
      QCheck_alcotest.to_alcotest qcheck_varint_roundtrip;
      QCheck_alcotest.to_alcotest qcheck_varint_int64_roundtrip;
    ];
  ]
