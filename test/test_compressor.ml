(* Tests for the Compressor module (Bitcoin Core CompressAmount,
   CompressScript, VARINT round-trip + known-vector parity). *)

open Camlcoin

let pass name = Printf.printf "  [PASS] %s\n" name
let fail name msg = Printf.printf "  [FAIL] %s: %s\n" name msg; exit 1

(* ============================================================================
   VARINT round-trips
   ============================================================================ *)

let test_varint_roundtrip () =
  let name = "VARINT roundtrip int" in
  let cases = [
    0; 1; 0x7f; 0x80; 0xff; 0x100; 0xffff; 0x10000; 0xffffff;
    0x7fffffff; max_int / 2;
  ] in
  List.iter (fun v ->
    let w = Serialize.writer_create () in
    Compressor.write_varint w v;
    let cs = Serialize.writer_to_cstruct w in
    let r = Serialize.reader_of_cstruct cs in
    let got = Compressor.read_varint r in
    if got <> v then
      fail name (Printf.sprintf "v=%d got=%d" v got)
  ) cases;
  pass name

let test_varint_roundtrip_int64 () =
  let name = "VARINT roundtrip int64" in
  let cases = [
    0L; 1L; 0x7fL; 0x80L; 0xffL; 0x100L; 0xffffL; 0x10000L;
    0xffff_ffffL; 0x1_0000_0000L; 0x7fff_ffff_ffff_ffffL;
    Int64.max_int;
  ] in
  List.iter (fun v ->
    let w = Serialize.writer_create () in
    Compressor.write_varint_int64 w v;
    let cs = Serialize.writer_to_cstruct w in
    let r = Serialize.reader_of_cstruct cs in
    let got = Compressor.read_varint_int64 r in
    if Int64.compare got v <> 0 then
      fail name (Printf.sprintf "v=%Ld got=%Ld" v got)
  ) cases;
  pass name

(* Known-vector parity with Bitcoin Core's WriteVarInt. Hand-derived from
   src/serialize.h: numbers in [0, 0x7F] encode as the single byte n;
   0x80 encodes as 0x80 0x00; 0xff encodes as 0x80 0x7f; 0x100 as 0x81
   0x00; etc. *)
let test_varint_known_vectors () =
  let name = "VARINT known vectors" in
  let cases = [
    (0,    "\x00");
    (1,    "\x01");
    (0x7f, "\x7f");
    (0x80, "\x80\x00");
    (0xff, "\x80\x7f");
    (0x100,"\x81\x00");
    (0x3FFF, "\xfe\x7f");
    (0x4000, "\xff\x00");
  ] in
  List.iter (fun (v, want) ->
    let w = Serialize.writer_create () in
    Compressor.write_varint w v;
    let cs = Serialize.writer_to_cstruct w in
    let got = Cstruct.to_string cs in
    if got <> want then
      fail name (Printf.sprintf "v=%d got=%S want=%S"
                   v (String.escaped got) (String.escaped want))
  ) cases;
  pass name

(* ============================================================================
   CompressAmount round-trips
   ============================================================================ *)

let test_compress_amount_roundtrip () =
  let name = "CompressAmount roundtrip" in
  let cases = [
    0L; 1L; 9L; 10L; 100L; 1_000L; 10_000L;
    100_000_000L;       (* 1 BTC *)
    21_000_000_000_000_000L;  (* MAX_MONEY: 21M BTC *)
    50_000_000_000L;    (* original block reward 50 BTC *)
    546L;               (* dust limit *)
    (* CompressAmount is only defined for [0, MAX_MONEY] per Core's
       contract; values beyond that overflow the (n*9+d-1)*10 formula. *)
  ] in
  List.iter (fun v ->
    let c = Compressor.compress_amount v in
    let d = Compressor.decompress_amount c in
    if Int64.compare d v <> 0 then
      fail name (Printf.sprintf "v=%Ld c=%Ld d=%Ld" v c d)
  ) cases;
  pass name

(* Known vectors hand-verified against Bitcoin Core compressor.cpp:
   - 5e9 (50 BTC) trims to e=9 and n=5 → 1 + (5-1)*10 + 9 = 50.
   - 1e8 (1 BTC)  trims to e=8 and n=1 → 1 + (1-1)*10 + 8 = 9.
   - 1                            (e=0, d=1, n=0) → 1 + (0*9 + 0)*10 + 0 = 1 (after subtracting 1: 0... wait)
     Actually: e=0, d=1, n=(1/10)=0 → output = 1 + (0*9 + 1 - 1)*10 + 0 = 1.
   - 0                                                          → 0. *)
let test_compress_amount_known () =
  let name = "CompressAmount known vectors" in
  let cases = [
    (0L, 0L);
    (1L, 1L);
    (100_000_000L, 9L);     (* 1 BTC = 0x09 *)
    (5_000_000_000L, 50L);  (* 50 BTC = 0x32 *)
  ] in
  List.iter (fun (v, want) ->
    let got = Compressor.compress_amount v in
    if Int64.compare got want <> 0 then
      fail name (Printf.sprintf "v=%Ld want=%Ld got=%Ld" v want got)
  ) cases;
  pass name

(* ============================================================================
   ScriptCompression
   ============================================================================ *)

let test_script_compress_p2pkh () =
  let name = "Script compression: P2PKH 25 -> 21" in
  let s = Bytes.create 25 in
  Bytes.set s 0 '\x76';
  Bytes.set s 1 '\xa9';
  Bytes.set s 2 '\x14';
  for i = 0 to 19 do Bytes.set s (3 + i) (Char.chr i) done;
  Bytes.set s 23 '\x88';
  Bytes.set s 24 '\xac';
  let cs = Cstruct.of_string (Bytes.unsafe_to_string s) in
  match Compressor.compress_script cs with
  | None -> fail name "P2PKH should compress"
  | Some out ->
    if Cstruct.length out <> 21 then
      fail name (Printf.sprintf "expected 21 bytes, got %d"
                   (Cstruct.length out))
    else if Cstruct.get_uint8 out 0 <> 0x00 then
      fail name "P2PKH prefix must be 0x00"
    else pass name

let test_script_compress_p2sh () =
  let name = "Script compression: P2SH 23 -> 21" in
  let s = Bytes.create 23 in
  Bytes.set s 0 '\xa9';
  Bytes.set s 1 '\x14';
  for i = 0 to 19 do Bytes.set s (2 + i) (Char.chr (i + 0x40)) done;
  Bytes.set s 22 '\x87';
  let cs = Cstruct.of_string (Bytes.unsafe_to_string s) in
  match Compressor.compress_script cs with
  | None -> fail name "P2SH should compress"
  | Some out ->
    if Cstruct.length out <> 21 then
      fail name "expected 21 bytes"
    else if Cstruct.get_uint8 out 0 <> 0x01 then
      fail name "P2SH prefix must be 0x01"
    else pass name

(* P2WPKH (witness v0, 22 bytes) is NOT a special case in Core's
   ScriptCompression — verify it falls through to fallback. *)
let test_script_compress_p2wpkh_fallback () =
  let name = "Script compression: P2WPKH stays raw" in
  let s = Bytes.create 22 in
  Bytes.set s 0 '\x00';
  Bytes.set s 1 '\x14';
  for i = 0 to 19 do Bytes.set s (2 + i) (Char.chr (i + 0x70)) done;
  let cs = Cstruct.of_string (Bytes.unsafe_to_string s) in
  match Compressor.compress_script cs with
  | None -> pass name  (* Expected: not compressible *)
  | Some _ -> fail name "P2WPKH must NOT match a special case"

(* Bitcoin Core's [DecompressScript] for nSize=4/5: rebuild an uncompressed
   P2PK from the parity bit + 32-byte x via secp256k1 point decompression.
   Vector: the secp256k1 generator G.
     compressed (parity even, prefix 0x02):
       02 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
     uncompressed (0x04 || X || Y):
       04 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
          483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
   The expected P2PK script is [0x41 || pubkey[65] || OP_CHECKSIG]. *)
let test_decompress_uncompressed_p2pk_g () =
  let name = "DecompressScript: uncompressed P2PK (generator G)" in
  let hex_to_cstruct h =
    let b = Bytes.create (String.length h / 2) in
    for i = 0 to Bytes.length b - 1 do
      Bytes.set b i (Char.chr (int_of_string ("0x" ^ String.sub h (2*i) 2)))
    done;
    Cstruct.of_bytes b
  in
  let x =
    hex_to_cstruct
      "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
  in
  let y =
    hex_to_cstruct
      "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
  in
  (* parity of G's Y is even (Y[31] = 0xb8 → low bit 0), so the compressed
     prefix is 0x02 and the snapshot tag is 0x04. *)
  match Compressor.decompress_script 0x04 x with
  | None -> fail name "decompress returned None for valid generator G"
  | Some script ->
    if Cstruct.length script <> 67 then
      fail name (Printf.sprintf "expected 67-byte script, got %d"
                   (Cstruct.length script));
    if Cstruct.get_uint8 script 0 <> 65 then
      fail name "leading push byte must be 65 (0x41)";
    if Cstruct.get_uint8 script 1 <> 0x04 then
      fail name "uncompressed pubkey must start with 0x04";
    let got_x = Cstruct.sub script 2 32 in
    let got_y = Cstruct.sub script 34 32 in
    if not (Cstruct.equal got_x x) then
      fail name "X coordinate mismatch";
    if not (Cstruct.equal got_y y) then
      fail name "Y coordinate mismatch";
    if Cstruct.get_uint8 script 66 <> 0xac then
      fail name "trailing opcode must be OP_CHECKSIG (0xac)";
    pass name

(* Tag 0x05 (parity odd) using -G = (G_x, p - G_y).  The point -G has
   X = G's X but Y with low bit 1, so parity-odd.  We expect tag 0x05 to
   yield X || (p - G_y). *)
let test_decompress_uncompressed_p2pk_neg_g () =
  let name = "DecompressScript: uncompressed P2PK (-G, parity odd)" in
  let hex_to_cstruct h =
    let b = Bytes.create (String.length h / 2) in
    for i = 0 to Bytes.length b - 1 do
      Bytes.set b i (Char.chr (int_of_string ("0x" ^ String.sub h (2*i) 2)))
    done;
    Cstruct.of_bytes b
  in
  let x =
    hex_to_cstruct
      "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
  in
  (* Y(-G) = p - Y(G) mod p, where p = secp256k1 field prime
       FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
     Computed in Python and confirmed by libsecp256k1:
       p - 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
       = 0xb7c52588d95c3b9aa25b0403f1eef75702e84bb7597aabe663b82f6f04ef2777 *)
  let y_neg =
    hex_to_cstruct
      "b7c52588d95c3b9aa25b0403f1eef75702e84bb7597aabe663b82f6f04ef2777"
  in
  match Compressor.decompress_script 0x05 x with
  | None -> fail name "decompress returned None for valid -G"
  | Some script ->
    if Cstruct.length script <> 67 then
      fail name (Printf.sprintf "expected 67 bytes, got %d"
                   (Cstruct.length script));
    let got_x = Cstruct.sub script 2 32 in
    let got_y = Cstruct.sub script 34 32 in
    if not (Cstruct.equal got_x x) then fail name "X mismatch";
    if not (Cstruct.equal got_y y_neg) then
      fail name (Printf.sprintf "Y mismatch: got %s"
                   (String.escaped (Cstruct.to_string got_y)));
    pass name

(* Negative case: an invalid x-coord (not on the curve) must fail-closed. *)
let test_decompress_uncompressed_p2pk_invalid () =
  let name = "DecompressScript: invalid x-coord fail-closed" in
  (* All-zero x is not a valid secp256k1 x-coordinate: y^2 = x^3 + 7 = 7,
     and 7 is a quadratic non-residue mod p (well-known). *)
  let bad_x = Cstruct.create 32 in  (* all zeros *)
  match Compressor.decompress_script 0x04 bad_x with
  | None -> pass name
  | Some _ ->
    fail name "decompress should have returned None for off-curve x"

(* Round-trip through the public ScriptCompression entry points: an
   uncompressed P2PK encoded by [serialize_script] must decode identically.
   This proves that compress→decompress is a fixpoint for the 0x04/0x05
   path, matching Core's invariant. *)
let test_script_serialize_roundtrip_uncompressed_p2pk () =
  let name = "Script roundtrip: uncompressed P2PK" in
  let hex_to_cstruct h =
    let b = Bytes.create (String.length h / 2) in
    for i = 0 to Bytes.length b - 1 do
      Bytes.set b i (Char.chr (int_of_string ("0x" ^ String.sub h (2*i) 2)))
    done;
    Cstruct.of_bytes b
  in
  (* Build the canonical 67-byte P2PK script for G. *)
  let g_uncomp =
    hex_to_cstruct
      ("0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
       ^ "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
  in
  let script = Cstruct.create 67 in
  Cstruct.set_uint8 script 0 65;
  Cstruct.blit g_uncomp 0 script 1 65;
  Cstruct.set_uint8 script 66 0xac;
  let w = Serialize.writer_create () in
  Compressor.serialize_script w script;
  let bytes = Serialize.writer_to_cstruct w in
  (* Must compress: first byte 0x04 (parity even), then 32-byte X. *)
  if Cstruct.length bytes <> 33 then
    fail name (Printf.sprintf "expected 33-byte compressed form, got %d"
                 (Cstruct.length bytes));
  if Cstruct.get_uint8 bytes 0 <> 0x04 then
    fail name (Printf.sprintf "expected tag 0x04, got 0x%02x"
                 (Cstruct.get_uint8 bytes 0));
  let r = Serialize.reader_of_cstruct bytes in
  let back = Compressor.deserialize_script r in
  if not (Cstruct.equal back script) then
    fail name "round-trip differs from original";
  pass name

(* Round-trip via the public ScriptCompression entry points: any script that
   is encoded by [serialize_script] must decode identically. *)
let test_script_serialize_roundtrip () =
  let name = "Script serialize/deserialize roundtrip" in
  let mk_p2pkh () =
    let s = Bytes.create 25 in
    Bytes.set s 0 '\x76'; Bytes.set s 1 '\xa9'; Bytes.set s 2 '\x14';
    for i = 0 to 19 do Bytes.set s (3 + i) (Char.chr (i + 0x21)) done;
    Bytes.set s 23 '\x88'; Bytes.set s 24 '\xac';
    Cstruct.of_string (Bytes.unsafe_to_string s)
  in
  let mk_p2wsh () =
    let s = Bytes.create 34 in
    Bytes.set s 0 '\x00'; Bytes.set s 1 '\x20';
    for i = 0 to 31 do Bytes.set s (2 + i) (Char.chr (i + 0x05)) done;
    Cstruct.of_string (Bytes.unsafe_to_string s)
  in
  let cases = [
    Cstruct.empty;
    mk_p2pkh ();
    mk_p2wsh ();
    Cstruct.of_string "\x6a\x04\xde\xad\xbe\xef";  (* OP_RETURN 4 *)
  ] in
  List.iter (fun cs ->
    let w = Serialize.writer_create () in
    Compressor.serialize_script w cs;
    let bytes = Serialize.writer_to_cstruct w in
    let r = Serialize.reader_of_cstruct bytes in
    let back = Compressor.deserialize_script r in
    if not (Cstruct.equal back cs) then
      fail name (Printf.sprintf "mismatch on script %s"
                   (String.escaped (Cstruct.to_string cs)))
  ) cases;
  pass name

let () =
  Printf.printf "Running compressor tests...\n";
  test_varint_roundtrip ();
  test_varint_roundtrip_int64 ();
  test_varint_known_vectors ();
  test_compress_amount_roundtrip ();
  test_compress_amount_known ();
  test_script_compress_p2pkh ();
  test_script_compress_p2sh ();
  test_script_compress_p2wpkh_fallback ();
  test_decompress_uncompressed_p2pk_g ();
  test_decompress_uncompressed_p2pk_neg_g ();
  test_decompress_uncompressed_p2pk_invalid ();
  test_script_serialize_roundtrip_uncompressed_p2pk ();
  test_script_serialize_roundtrip ();
  Printf.printf "All compressor tests passed!\n"
