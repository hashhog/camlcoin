(* Unit tests for MuHash3072. Test vectors come straight from
   bitcoin-core/src/test/crypto_tests.cpp BOOST_AUTO_TEST_CASE(muhash_tests). *)

open Camlcoin

(* ============================================================================
   Helpers
   ============================================================================ *)

let pass name = Printf.printf "  [PASS] %s\n" name
let fail name msg = Printf.printf "  [FAIL] %s: %s\n" name msg; exit 1

(* Match Core's helper:
       static MuHash3072 FromInt(unsigned char i) {
           unsigned char tmp[32] = {i, 0};
           return MuHash3072(tmp);
       }
   i.e. a 32-byte buffer with [i] at index 0 and zeros elsewhere. *)
let from_int (i : int) : Muhash.t =
  let tmp = Bytes.make 32 '\x00' in
  Bytes.set tmp 0 (Char.chr (i land 0xff));
  Muhash.singleton (Bytes.unsafe_to_string tmp)

let bytes_to_hex_lower (b : bytes) : string =
  let buf = Buffer.create (Bytes.length b * 2) in
  Bytes.iter (fun c ->
    Buffer.add_string buf (Printf.sprintf "%02x" (Char.code c)))
    b;
  Buffer.contents buf

(* Bitcoin Core's [uint256{"AABB...ZZ"}] parses hex in display order, which
   is the byte-REVERSE of the underlying raw 32-byte little-endian buffer.
   Our [Muhash.finalize] returns raw bytes, so to compare against Core's
   uint256 hex literal we need to reverse the byte order. *)
let bytes_to_uint256_display (b : bytes) : string =
  let n = Bytes.length b in
  let buf = Buffer.create (n * 2) in
  for i = n - 1 downto 0 do
    Buffer.add_string buf (Printf.sprintf "%02x" (Char.code (Bytes.get b i)))
  done;
  Buffer.contents buf

let read_file_trim (path : string) : string =
  let ic = open_in path in
  let n = in_channel_length ic in
  let s = really_input_string ic n in
  close_in ic;
  String.trim s

(* ============================================================================
   Vector 1: Core's "FromInt(0) * FromInt(1) / FromInt(2)" finalize hash
   ============================================================================ *)

let test_vector_finalize_via_div () =
  let name = "muhash: FromInt(0)*FromInt(1)/FromInt(2) finalize matches Core" in
  let acc = from_int 0 in
  Muhash.mul_into acc (from_int 1);
  Muhash.div_into acc (from_int 2);
  let out = Muhash.finalize acc in
  (* Core's BOOST_CHECK_EQUAL(out, uint256{"10d312b1..."}) compares against
     the DISPLAY form (byte-reversed from raw SHA256 output). *)
  let expected_display =
    "10d312b100cbd32ada024a6646e40d3482fcff103668d2625f10002a607d5863"
  in
  let got = bytes_to_uint256_display out in
  if got = expected_display then pass name
  else fail name (Printf.sprintf "expected %s, got %s" expected_display got)

let test_vector_finalize_via_insert_remove () =
  let name = "muhash: FromInt(0); Insert(1); Remove(2) finalize matches Core" in
  let acc = from_int 0 in
  let buf1 = Bytes.make 32 '\x00' in Bytes.set buf1 0 '\x01';
  Muhash.add acc (Bytes.unsafe_to_string buf1);
  let buf2 = Bytes.make 32 '\x00' in Bytes.set buf2 0 '\x02';
  Muhash.remove acc (Bytes.unsafe_to_string buf2);
  let out = Muhash.finalize acc in
  let expected_display =
    "10d312b100cbd32ada024a6646e40d3482fcff103668d2625f10002a607d5863"
  in
  let got = bytes_to_uint256_display out in
  if got = expected_display then pass name
  else fail name (Printf.sprintf "expected %s, got %s" expected_display got)

(* ============================================================================
   Vector 2: Empty MuHash finalize
   ============================================================================ *)

let test_empty_finalize () =
  let name = "muhash: empty finalize matches SHA256(LE(1, 384 bytes))" in
  let acc = Muhash.create () in
  let got = bytes_to_hex_lower (Muhash.finalize acc) in
  let preimage = Bytes.make 384 '\x00' in
  Bytes.set preimage 0 '\x01';
  let expected_digest =
    Crypto.sha256 (Cstruct.of_string (Bytes.unsafe_to_string preimage))
  in
  let expected = bytes_to_hex_lower (Bytes.of_string
                                       (Cstruct.to_string expected_digest)) in
  if got = expected then pass name
  else fail name (Printf.sprintf "expected %s, got %s" expected got)

(* ============================================================================
   Vector 3: Algebraic relation
   ============================================================================ *)

let test_algebraic_identity () =
  let name = "muhash: (x*y) / (y*x) reduces to empty" in
  let x = from_int 7 in
  let y = from_int 13 in
  let z = Muhash.create () in
  Muhash.mul_into z x;
  Muhash.mul_into z y;
  let y_prime = Muhash.copy y in
  Muhash.mul_into y_prime x;
  Muhash.div_into z y_prime;
  let got = bytes_to_hex_lower (Muhash.finalize z) in
  let empty = Muhash.create () in
  let want = bytes_to_hex_lower (Muhash.finalize empty) in
  if got = want then pass name
  else fail name (Printf.sprintf "z=%s empty=%s" got want)

(* ============================================================================
   Vector 4: Overflow vector — limbs = 0xff*384 (numerator)
   ============================================================================

   From crypto_tests.cpp:1275-1281: deserialize a numerator of 384 0xff bytes
   (= 2^3072 - 1) and a denominator of {1, 0...}, then finalize.
   The expected hex literal is what HexStr(out4) prints, i.e. raw byte order
   of the SHA256 output (NO reversal). *)

let test_overflow_deserialize () =
  let name = "muhash: deserialize 0xff^384 numerator (overflow) -> Core hash" in
  let ser = Bytes.make 768 '\x00' in
  Bytes.fill ser 0 384 '\xff';
  Bytes.set ser 384 '\x01';
  let acc = Muhash.deserialize ser in
  let got = bytes_to_hex_lower (Muhash.finalize acc) in
  let expected =
    "3a31e6903aff0de9f62f9a9f7f8b861de76ce2cda09822b90014319ae5dc2271"
  in
  if got = expected then pass name
  else fail name (Printf.sprintf "expected %s, got %s" expected got)

(* ============================================================================
   Vector 5: Order independence
   ============================================================================ *)

let test_order_invariance () =
  let name = "muhash: insert order does not affect finalize" in
  let elems = ["aaa"; "bbb"; "ccc"; "ddd"] in
  let pad32 s =
    let b = Bytes.make 32 '\x00' in
    let n = min (String.length s) 32 in
    Bytes.blit_string s 0 b 0 n;
    Bytes.unsafe_to_string b
  in
  let order1 = elems in
  let order2 = List.rev elems in
  let h1 = Muhash.create () in
  List.iter (fun e -> Muhash.add h1 (pad32 e)) order1;
  let h2 = Muhash.create () in
  List.iter (fun e -> Muhash.add h2 (pad32 e)) order2;
  let got1 = bytes_to_hex_lower (Muhash.finalize h1) in
  let got2 = bytes_to_hex_lower (Muhash.finalize h2) in
  if got1 = got2 then pass name
  else fail name (Printf.sprintf "%s vs %s" got1 got2)

(* ============================================================================
   Vector 6: Serialization round-trip
   ============================================================================ *)

let test_serialize_roundtrip () =
  let name = "muhash: serialize/deserialize roundtrip" in
  let h = from_int 42 in
  Muhash.mul_into h (from_int 99);
  Muhash.div_into h (from_int 7);
  let ser = Muhash.serialize h in
  if Bytes.length ser <> 768 then
    fail name (Printf.sprintf "bad ser length %d" (Bytes.length ser))
  else
  let h' = Muhash.deserialize ser in
  let f1 = bytes_to_hex_lower (Muhash.finalize h) in
  let f2 = bytes_to_hex_lower (Muhash.finalize h') in
  if f1 = f2 then pass name
  else fail name (Printf.sprintf "%s vs %s" f1 f2)

(* ============================================================================
   Vector 7: Serialized numerator/denominator wire prefix matches Core
   ============================================================================
   ser_exp = serialization of FromInt(1) * FromInt(2). The full hex is
   1536 chars; we ship it as a resource so the OCaml source stays sane. *)

let test_core_serialization_vector () =
  let name = "muhash: serialize FromInt(1)*FromInt(2) matches Core wire bytes" in
  let acc = from_int 1 in
  Muhash.mul_into acc (from_int 2);
  let got = bytes_to_hex_lower (Muhash.serialize acc) in
  let core_ser = read_file_trim "../resources/muhash_core_ser_vector.hex" in
  if got = core_ser then pass name
  else
    let n = String.length got in
    let m = String.length core_ser in
    fail name
      (Printf.sprintf "len got=%d want=%d; first 32 hex got=%s want=%s"
         n m
         (String.sub got 0 (min 32 n))
         (String.sub core_ser 0 (min 32 m)))

(* ============================================================================
   Vector 8: TxOutSer — quick sanity on the per-coin preimage shape
   ============================================================================ *)

let test_txoutser_shape () =
  let name = "muhash: serialize_txout produces outpoint||code||value||script" in
  let outpoint : Types.outpoint = {
    txid = Types.hash256_of_hex
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    vout = 7l;
  } in
  let script = Cstruct.of_string "\x76\xa9\x14abcdef0123456789abcd\x88\xac" in
  let buf = Muhash.serialize_txout outpoint
              ~value:5_000_000_000L ~script_pubkey:script
              ~height:42 ~is_coinbase:false in
  let expected_len = 32 + 4 + 4 + 8 + 1 + Cstruct.length script in
  if Bytes.length buf <> expected_len then
    fail name (Printf.sprintf "len got=%d want=%d"
                 (Bytes.length buf) expected_len)
  else begin
    (* Verify code byte: (42 << 1) | 0 = 84 = 0x54, LE32 = 54 00 00 00. *)
    let code = Bytes.sub_string buf 36 4 in
    if code <> "\x54\x00\x00\x00" then
      fail name (Printf.sprintf "bad code bytes %s"
                   (String.escaped code))
    else pass name
  end

let test_txoutser_coinbase_bit () =
  let name = "muhash: serialize_txout sets coinbase low bit of code" in
  let outpoint : Types.outpoint = {
    txid = Cstruct.of_string (Bytes.unsafe_to_string (Bytes.make 32 '\x00'));
    vout = 0l;
  } in
  let script = Cstruct.of_string "\x00\x14padpadpadpadpadpadpadpa" in
  let buf = Muhash.serialize_txout outpoint
              ~value:50_00000000L ~script_pubkey:script
              ~height:1 ~is_coinbase:true in
  let code = Bytes.sub_string buf 36 4 in
  if code = "\x03\x00\x00\x00" then pass name
  else fail name (Printf.sprintf "bad code bytes %s" (String.escaped code))

(* ============================================================================
   Vector 9: insert(coin); remove(coin) returns to empty
   ============================================================================ *)

let test_coin_apply_reversible () =
  let name = "muhash: insert(coin); remove(coin) returns to empty" in
  let outpoint : Types.outpoint = {
    txid = Types.hash256_of_hex
      "0011223344556677889900112233445566778899001122334455667788990011";
    vout = 3l;
  } in
  let script = Cstruct.of_string "\x76\xa9\x14abcdef0123456789abcd\x88\xac" in
  let coin_buf =
    Muhash.serialize_txout outpoint ~value:12345L
      ~script_pubkey:script ~height:777 ~is_coinbase:false
    |> Bytes.unsafe_to_string in
  let acc = Muhash.create () in
  Muhash.add acc coin_buf;
  Muhash.remove acc coin_buf;
  let empty = Muhash.create () in
  let f1 = bytes_to_hex_lower (Muhash.finalize acc) in
  let f2 = bytes_to_hex_lower (Muhash.finalize empty) in
  if f1 = f2 then pass name
  else fail name (Printf.sprintf "%s vs %s" f1 f2)

(* ============================================================================
   Runner
   ============================================================================ *)

let () =
  Printf.printf "Running muhash tests...\n";
  test_empty_finalize ();
  test_vector_finalize_via_div ();
  test_vector_finalize_via_insert_remove ();
  test_algebraic_identity ();
  test_overflow_deserialize ();
  test_order_invariance ();
  test_serialize_roundtrip ();
  test_core_serialization_vector ();
  test_txoutser_shape ();
  test_txoutser_coinbase_bit ();
  test_coin_apply_reversible ();
  Printf.printf "All muhash tests passed!\n"
