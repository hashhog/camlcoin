(* Tests for cryptographic primitives *)

open Camlcoin

(* Helper to convert hex string to Cstruct *)
let hex_to_cstruct s =
  let len = String.length s / 2 in
  let buf = Cstruct.create len in
  for i = 0 to len - 1 do
    let byte = int_of_string ("0x" ^ String.sub s (i * 2) 2) in
    Cstruct.set_uint8 buf i byte
  done;
  buf

(* Helper to convert Cstruct to hex string *)
let cstruct_to_hex cs =
  let buf = Buffer.create (Cstruct.length cs * 2) in
  for i = 0 to Cstruct.length cs - 1 do
    Buffer.add_string buf (Printf.sprintf "%02x" (Cstruct.get_uint8 cs i))
  done;
  Buffer.contents buf

(* SHA-256d tests *)
let test_sha256d_empty () =
  (* SHA256d("") = SHA256(SHA256("")) *)
  (* SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 *)
  (* SHA256(above) = 5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456 *)
  let input = Cstruct.create 0 in
  let result = Crypto.sha256d input in
  let expected = "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456" in
  Alcotest.(check string) "sha256d empty" expected (cstruct_to_hex result)

let test_sha256d_hello () =
  (* Test with "hello" *)
  let input = Cstruct.of_string "hello" in
  let result = Crypto.sha256d input in
  (* SHA256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824 *)
  (* SHA256(above) = 9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50 *)
  let expected = "9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50" in
  Alcotest.(check string) "sha256d hello" expected (cstruct_to_hex result)

let test_sha256_single () =
  (* Single SHA256 of empty string *)
  let input = Cstruct.create 0 in
  let result = Crypto.sha256 input in
  let expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in
  Alcotest.(check string) "sha256 empty" expected (cstruct_to_hex result)

(* Hash160 tests *)
let test_hash160 () =
  (* RIPEMD160(SHA256("hello")) *)
  (* SHA256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824 *)
  (* RIPEMD160(above) = b6a9c8c230722b7c748331a8b450f05566dc7d0f *)
  let input = Cstruct.of_string "hello" in
  let result = Crypto.hash160 input in
  let expected = "b6a9c8c230722b7c748331a8b450f05566dc7d0f" in
  Alcotest.(check string) "hash160 hello" expected (cstruct_to_hex result)

let test_hash160_pubkey () =
  (* Test with a known compressed public key *)
  (* This tests the typical address generation use case *)
  let pubkey_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" in
  let pubkey = hex_to_cstruct pubkey_hex in
  let result = Crypto.hash160 pubkey in
  (* Known result for this public key (the generator point G) *)
  let expected = "751e76e8199196d454941c45d1b3a323f1433bd6" in
  Alcotest.(check string) "hash160 pubkey" expected (cstruct_to_hex result)

(* Key generation and signing tests *)
let test_keygen_roundtrip () =
  (* Generate a private key and derive public key *)
  let privkey = Crypto.generate_private_key () in
  Alcotest.(check int) "private key length" 32 (Cstruct.length privkey);
  let pubkey = Crypto.derive_public_key privkey in
  Alcotest.(check int) "compressed pubkey length" 33 (Cstruct.length pubkey);
  (* Compressed pubkeys start with 0x02 or 0x03 *)
  let prefix = Cstruct.get_uint8 pubkey 0 in
  Alcotest.(check bool) "pubkey prefix" true (prefix = 0x02 || prefix = 0x03)

let test_keygen_uncompressed () =
  let privkey = Crypto.generate_private_key () in
  let pubkey = Crypto.derive_public_key ~compressed:false privkey in
  Alcotest.(check int) "uncompressed pubkey length" 65 (Cstruct.length pubkey);
  (* Uncompressed pubkeys start with 0x04 *)
  let prefix = Cstruct.get_uint8 pubkey 0 in
  Alcotest.(check int) "uncompressed prefix" 0x04 prefix

let test_sign_verify_roundtrip () =
  (* Generate key pair *)
  let privkey = Crypto.generate_private_key () in
  let pubkey = Crypto.derive_public_key privkey in
  (* Create a message hash (32 bytes) *)
  let msg_hash = Crypto.sha256d (Cstruct.of_string "test message") in
  (* Sign the message *)
  let signature = Crypto.sign privkey msg_hash in
  (* DER signatures are typically 70-72 bytes *)
  Alcotest.(check bool) "signature length valid" true
    (Cstruct.length signature >= 68 && Cstruct.length signature <= 72);
  (* Verify the signature *)
  let valid = Crypto.verify pubkey msg_hash signature in
  Alcotest.(check bool) "signature valid" true valid

let test_verify_wrong_message () =
  let privkey = Crypto.generate_private_key () in
  let pubkey = Crypto.derive_public_key privkey in
  let msg_hash = Crypto.sha256d (Cstruct.of_string "test message") in
  let signature = Crypto.sign privkey msg_hash in
  (* Try to verify with wrong message *)
  let wrong_hash = Crypto.sha256d (Cstruct.of_string "wrong message") in
  let valid = Crypto.verify pubkey wrong_hash signature in
  Alcotest.(check bool) "wrong message fails" false valid

let test_verify_wrong_key () =
  let privkey1 = Crypto.generate_private_key () in
  let privkey2 = Crypto.generate_private_key () in
  let pubkey2 = Crypto.derive_public_key privkey2 in
  let msg_hash = Crypto.sha256d (Cstruct.of_string "test message") in
  let signature = Crypto.sign privkey1 msg_hash in
  (* Try to verify with wrong public key *)
  let valid = Crypto.verify pubkey2 msg_hash signature in
  Alcotest.(check bool) "wrong key fails" false valid

(* Merkle root tests *)
let test_merkle_root_empty () =
  let (result, _) = Crypto.merkle_root [] in
  Alcotest.(check string) "merkle empty" (String.make 64 '0') (cstruct_to_hex result)

let test_merkle_root_single () =
  let hash = hex_to_cstruct "0000000000000000000000000000000000000000000000000000000000000001" in
  let (result, _) = Crypto.merkle_root [hash] in
  Alcotest.(check string) "merkle single" (cstruct_to_hex hash) (cstruct_to_hex result)

let test_merkle_root_two () =
  (* With two hashes: merkle_root = SHA256d(h1 || h2) *)
  let h1 = hex_to_cstruct "0000000000000000000000000000000000000000000000000000000000000001" in
  let h2 = hex_to_cstruct "0000000000000000000000000000000000000000000000000000000000000002" in
  let (result, _) = Crypto.merkle_root [h1; h2] in
  (* Compute expected: SHA256d(h1 || h2) *)
  let combined = Cstruct.concat [h1; h2] in
  let expected = Crypto.sha256d combined in
  Alcotest.(check string) "merkle two" (cstruct_to_hex expected) (cstruct_to_hex result)

let test_merkle_root_three () =
  (* With three hashes: duplicate the last one *)
  (* Level 0: h1, h2, h3 *)
  (* Level 1: SHA256d(h1||h2), SHA256d(h3||h3) *)
  (* Level 2: SHA256d(level1[0] || level1[1]) *)
  let h1 = hex_to_cstruct "0000000000000000000000000000000000000000000000000000000000000001" in
  let h2 = hex_to_cstruct "0000000000000000000000000000000000000000000000000000000000000002" in
  let h3 = hex_to_cstruct "0000000000000000000000000000000000000000000000000000000000000003" in
  let (result, _) = Crypto.merkle_root [h1; h2; h3] in
  (* Compute expected *)
  let l1_0 = Crypto.sha256d (Cstruct.concat [h1; h2]) in
  let l1_1 = Crypto.sha256d (Cstruct.concat [h3; h3]) in
  let expected = Crypto.sha256d (Cstruct.concat [l1_0; l1_1]) in
  Alcotest.(check string) "merkle three" (cstruct_to_hex expected) (cstruct_to_hex result)

let test_merkle_root_four () =
  (* With four hashes: no duplication needed *)
  let h1 = hex_to_cstruct "0000000000000000000000000000000000000000000000000000000000000001" in
  let h2 = hex_to_cstruct "0000000000000000000000000000000000000000000000000000000000000002" in
  let h3 = hex_to_cstruct "0000000000000000000000000000000000000000000000000000000000000003" in
  let h4 = hex_to_cstruct "0000000000000000000000000000000000000000000000000000000000000004" in
  let (result, _) = Crypto.merkle_root [h1; h2; h3; h4] in
  let l1_0 = Crypto.sha256d (Cstruct.concat [h1; h2]) in
  let l1_1 = Crypto.sha256d (Cstruct.concat [h3; h4]) in
  let expected = Crypto.sha256d (Cstruct.concat [l1_0; l1_1]) in
  Alcotest.(check string) "merkle four" (cstruct_to_hex expected) (cstruct_to_hex result)

(* Test suite *)
let sha256_tests = [
  Alcotest.test_case "sha256d empty" `Quick test_sha256d_empty;
  Alcotest.test_case "sha256d hello" `Quick test_sha256d_hello;
  Alcotest.test_case "sha256 single" `Quick test_sha256_single;
]

let hash160_tests = [
  Alcotest.test_case "hash160 hello" `Quick test_hash160;
  Alcotest.test_case "hash160 pubkey" `Quick test_hash160_pubkey;
]

let keygen_tests = [
  Alcotest.test_case "keygen roundtrip" `Quick test_keygen_roundtrip;
  Alcotest.test_case "keygen uncompressed" `Quick test_keygen_uncompressed;
]

let signing_tests = [
  Alcotest.test_case "sign verify roundtrip" `Quick test_sign_verify_roundtrip;
  Alcotest.test_case "verify wrong message" `Quick test_verify_wrong_message;
  Alcotest.test_case "verify wrong key" `Quick test_verify_wrong_key;
]

let merkle_tests = [
  Alcotest.test_case "merkle empty" `Quick test_merkle_root_empty;
  Alcotest.test_case "merkle single" `Quick test_merkle_root_single;
  Alcotest.test_case "merkle two" `Quick test_merkle_root_two;
  Alcotest.test_case "merkle three" `Quick test_merkle_root_three;
  Alcotest.test_case "merkle four" `Quick test_merkle_root_four;
]

(* Genesis block hash tests *)
let test_mainnet_genesis_hash () =
  let header = Consensus.mainnet_genesis_header in
  let hash = Crypto.compute_block_hash header in
  let display = Types.hash256_to_hex_display hash in
  Alcotest.(check string) "mainnet genesis hash"
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    display

let test_regtest_genesis_hash () =
  let header = Consensus.regtest.genesis_header in
  let hash = Crypto.compute_block_hash header in
  let display = Types.hash256_to_hex_display hash in
  Alcotest.(check string) "regtest genesis hash"
    "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
    display

let genesis_tests = [
  Alcotest.test_case "mainnet genesis hash" `Quick test_mainnet_genesis_hash;
  Alcotest.test_case "regtest genesis hash" `Quick test_regtest_genesis_hash;
]

(* QCheck property-based tests *)
let qcheck_sign_verify_roundtrip =
  QCheck.Test.make ~count:20 ~name:"sign_verify roundtrip"
    QCheck.string
    (fun msg ->
      let privkey = Crypto.generate_private_key () in
      let pubkey = Crypto.derive_public_key privkey in
      let msg_hash = Crypto.sha256d (Cstruct.of_string msg) in
      let signature = Crypto.sign privkey msg_hash in
      Crypto.verify pubkey msg_hash signature)

(* Hardware-accelerated crypto tests *)
let test_verify_ecdsa_fast () =
  let privkey = Crypto.generate_private_key () in
  let pubkey = Crypto.derive_public_key privkey in
  let msg_hash = Crypto.sha256d (Cstruct.of_string "test message") in
  let signature = Crypto.sign privkey msg_hash in
  (* Fast verify should match regular verify *)
  let valid_fast = Crypto.verify_ecdsa_fast ~pubkey ~msg32:msg_hash ~signature in
  let valid_regular = Crypto.verify pubkey msg_hash signature in
  Alcotest.(check bool) "fast verify matches regular" valid_regular valid_fast;
  Alcotest.(check bool) "signature valid" true valid_fast

let test_verify_ecdsa_fast_wrong_message () =
  let privkey = Crypto.generate_private_key () in
  let pubkey = Crypto.derive_public_key privkey in
  let msg_hash = Crypto.sha256d (Cstruct.of_string "test message") in
  let signature = Crypto.sign privkey msg_hash in
  let wrong_hash = Crypto.sha256d (Cstruct.of_string "wrong message") in
  let valid = Crypto.verify_ecdsa_fast ~pubkey ~msg32:wrong_hash ~signature in
  Alcotest.(check bool) "wrong message fails" false valid

let test_verify_ecdsa_normalized () =
  let privkey = Crypto.generate_private_key () in
  let pubkey = Crypto.derive_public_key privkey in
  let msg_hash = Crypto.sha256d (Cstruct.of_string "test message") in
  let signature = Crypto.sign privkey msg_hash in
  (* Normalized verify should work *)
  let valid = Crypto.verify_ecdsa_normalized ~pubkey ~msg32:msg_hash ~signature in
  Alcotest.(check bool) "normalized verify works" true valid

let test_schnorr_verify_batch_empty () =
  let result = Crypto.schnorr_verify_batch [] in
  Alcotest.(check bool) "empty batch is valid" true result

let test_schnorr_verify_batch_single () =
  let privkey = Crypto.generate_private_key () in
  let pubkey_x = Crypto.derive_xonly_pubkey privkey in
  let msg = Crypto.sha256d (Cstruct.of_string "test message") in
  let sig_ = Crypto.schnorr_sign ~privkey ~msg in
  let result = Crypto.schnorr_verify_batch [(pubkey_x, msg, sig_)] in
  Alcotest.(check bool) "single batch valid" true result

let test_schnorr_verify_batch_multiple () =
  (* Generate 5 valid signatures *)
  let items = List.init 5 (fun i ->
    let privkey = Crypto.generate_private_key () in
    let pubkey_x = Crypto.derive_xonly_pubkey privkey in
    let msg = Crypto.sha256d (Cstruct.of_string (Printf.sprintf "message %d" i)) in
    let sig_ = Crypto.schnorr_sign ~privkey ~msg in
    (pubkey_x, msg, sig_)
  ) in
  let result = Crypto.schnorr_verify_batch items in
  Alcotest.(check bool) "multiple batch valid" true result

let test_schnorr_verify_batch_one_invalid () =
  (* Generate 4 valid + 1 invalid *)
  let items = List.init 5 (fun i ->
    let privkey = Crypto.generate_private_key () in
    let pubkey_x = Crypto.derive_xonly_pubkey privkey in
    let msg = Crypto.sha256d (Cstruct.of_string (Printf.sprintf "message %d" i)) in
    let sig_ = Crypto.schnorr_sign ~privkey ~msg in
    if i = 2 then
      (* Corrupt the signature for item 2 *)
      let bad_sig = Cstruct.sub sig_ 0 64 in
      Cstruct.set_uint8 bad_sig 0 (0xFF lxor Cstruct.get_uint8 bad_sig 0);
      (pubkey_x, msg, bad_sig)
    else
      (pubkey_x, msg, sig_)
  ) in
  let result = Crypto.schnorr_verify_batch items in
  Alcotest.(check bool) "batch with invalid fails" false result

let test_is_valid_pubkey () =
  let privkey = Crypto.generate_private_key () in
  let pubkey_compressed = Crypto.derive_public_key ~compressed:true privkey in
  let pubkey_uncompressed = Crypto.derive_public_key ~compressed:false privkey in
  Alcotest.(check bool) "compressed pubkey valid" true
    (Crypto.is_valid_pubkey pubkey_compressed);
  Alcotest.(check bool) "uncompressed pubkey valid" true
    (Crypto.is_valid_pubkey pubkey_uncompressed);
  (* Invalid pubkeys *)
  Alcotest.(check bool) "empty not valid" false
    (Crypto.is_valid_pubkey (Cstruct.create 0));
  Alcotest.(check bool) "wrong length not valid" false
    (Crypto.is_valid_pubkey (Cstruct.create 20));
  let bad_pubkey = Cstruct.create 33 in
  Cstruct.set_uint8 bad_pubkey 0 0x04;  (* Wrong prefix for 33 bytes *)
  Alcotest.(check bool) "bad prefix not valid" false
    (Crypto.is_valid_pubkey bad_pubkey)

let test_compress_pubkey () =
  let privkey = Crypto.generate_private_key () in
  let pubkey_uncompressed = Crypto.derive_public_key ~compressed:false privkey in
  let pubkey_compressed = Crypto.derive_public_key ~compressed:true privkey in
  (* Compress the uncompressed key *)
  match Crypto.compress_pubkey pubkey_uncompressed with
  | None -> Alcotest.fail "compression failed"
  | Some compressed ->
    Alcotest.(check int) "compressed length" 33 (Cstruct.length compressed);
    Alcotest.(check bool) "compressed matches" true
      (Cstruct.equal compressed pubkey_compressed)

let test_compress_already_compressed () =
  let privkey = Crypto.generate_private_key () in
  let pubkey = Crypto.derive_public_key ~compressed:true privkey in
  match Crypto.compress_pubkey pubkey with
  | None -> Alcotest.fail "should return Some for already compressed"
  | Some result ->
    Alcotest.(check bool) "returns same" true (Cstruct.equal result pubkey)

let hardware_accel_tests = [
  Alcotest.test_case "verify_ecdsa_fast" `Quick test_verify_ecdsa_fast;
  Alcotest.test_case "verify_ecdsa_fast wrong message" `Quick test_verify_ecdsa_fast_wrong_message;
  Alcotest.test_case "verify_ecdsa_normalized" `Quick test_verify_ecdsa_normalized;
  Alcotest.test_case "schnorr_verify_batch empty" `Quick test_schnorr_verify_batch_empty;
  Alcotest.test_case "schnorr_verify_batch single" `Quick test_schnorr_verify_batch_single;
  Alcotest.test_case "schnorr_verify_batch multiple" `Quick test_schnorr_verify_batch_multiple;
  Alcotest.test_case "schnorr_verify_batch invalid" `Quick test_schnorr_verify_batch_one_invalid;
  Alcotest.test_case "is_valid_pubkey" `Quick test_is_valid_pubkey;
  Alcotest.test_case "compress_pubkey" `Quick test_compress_pubkey;
  Alcotest.test_case "compress already compressed" `Quick test_compress_already_compressed;
]

let qcheck_tests = [
  QCheck_alcotest.to_alcotest qcheck_sign_verify_roundtrip;
]

(* ============================================================================
   BIP-66 / IsValidSignatureEncoding tests
   Covers all ~22 gates from Bitcoin Core interpreter.cpp:108-171.
   Input format: 0x30 total_len 0x02 R_len R 0x02 S_len S hashtype
   Minimum 9 bytes, maximum 73 bytes.
   ============================================================================ *)

(* Canonical valid minimal signature: R=1 byte, S=1 byte, HT=SIGHASH_ALL *)
(* 0x30 0x06 0x02 0x01 0x01 0x02 0x01 0x01 0x01 *)
let valid_minimal_der = "3006020101020101" ^ "01"

(* Canonical valid maximal-ish signature: R=33 bytes, S=1 byte *)
let make_der_sig ?(ht=0x01) r_hex s_hex =
  let r_len = String.length r_hex / 2 in
  let s_len = String.length s_hex / 2 in
  let total = r_len + s_len + 4 in  (* 02 R_len R 02 S_len S *)
  Printf.sprintf "30%02x02%02x%s02%02x%s%02x"
    total r_len r_hex s_len s_hex ht

(* Gate 1: minimum length < 9 → false *)
let test_der_too_short () =
  (* 8-byte sig: 30 05 02 01 01 02 01 01 — missing hashtype *)
  let sig_bytes = hex_to_cstruct "3005020101020101" in
  Alcotest.(check bool) "8-byte sig too short" false
    (Crypto.is_valid_signature_encoding sig_bytes)

(* Gate 2: maximum length > 73 → false.
   Build a 74-byte sig: R=34 bytes (leading 0x00 + 33 zero bytes),
   S=1 byte.  Outer: 30 <total> 02 22 <R[34]> 02 01 <S[1]> <HT>
   total = 34+1+4 = 39; sig = 2+39+1 = 42 bytes — NOT 74.
   To reach 74: R=33, S=33.  total=70; sig=2+70+1=73 — exactly valid!
   For 74: R=34, S=33.  total=71; sig=2+71+1=74. *)
let test_der_too_long () =
  let r34 = String.make (34 * 2) '1' in  (* 34 bytes, no high bit *)
  let s33 = String.make (33 * 2) '1' in  (* 33 bytes, no high bit *)
  let total = 34 + 33 + 4 in             (* 71 *)
  let sig_hex = Printf.sprintf "30%02x02%02x%s02%02x%s01"
    total 34 r34 33 s33 in
  let sig_bytes = hex_to_cstruct sig_hex in
  Alcotest.(check bool) "74-byte sig too long" false
    (Crypto.is_valid_signature_encoding sig_bytes)

(* Gate 3: first byte != 0x30 → false.
   31 06 02 01 01 02 01 01 01 — compound tag 0x31 instead of 0x30, 9 bytes *)
let test_der_wrong_compound_tag () =
  let sig_bytes = hex_to_cstruct "310602010102010101" in
  Alcotest.(check bool) "wrong compound tag 0x31" false
    (Crypto.is_valid_signature_encoding sig_bytes)

(* Gate 4: total-length byte wrong → false.
   30 05 02 01 01 02 01 01 01: total_len=5, sig.size()=9, 9-3=6 ≠ 5 → false *)
let test_der_wrong_total_length () =
  let sig_bytes = hex_to_cstruct "300502010102010101" in
  Alcotest.(check bool) "wrong total-length field" false
    (Crypto.is_valid_signature_encoding sig_bytes)

(* Gate 5: R integer tag sig[2] != 0x02 → false.
   30 06 03 01 01 02 01 01 01 — R tag is 0x03 instead of 0x02 *)
let test_der_wrong_r_tag () =
  let sig_bytes = hex_to_cstruct "300603010102010101" in
  Alcotest.(check bool) "wrong R tag 0x03" false
    (Crypto.is_valid_signature_encoding sig_bytes)

(* Gate 6: lenR = 0 → false.
   30 05 02 00 02 01 01 01 — R length is 0 (needs hashtype for 9 bytes total) *)
let test_der_zero_r_length () =
  (* 30 05 02 00 02 01 01 01 = 8 bytes, too short.  Need total_len consistent:
     30 04 02 00 02 01 01 01 = 8 bytes, len<9 → fails length gate first.
     Use a slightly bigger sig: 30 06 02 00 XX 02 01 01 01 where XX is padding. *)
  (* Simplest: build 30 05 02 00 02 01 01 HT.  len=8 <9 → fails length. *)
  (* For gate 6 specifically: need sig.size()>=9 and total-len field OK but lenR=0.
     sig: 30 06 02 00 02 01 01 XX 01 — wait: total_len=6, sig.size()=9, 9-3=6 ok.
     But lenR=0 → gate 6 fires.  sig[4]=0x02 (S tag) and lenS byte at sig[5]=0x01.
     lenR+lenS+7 = 0+1+7=8 ≠ 9 → gate 10 fires first.
     Build with consistent lengths: R=0, S=3: 30 07 02 00 02 03 aa bb cc 01
     total=7, sig.size()=10, 10-3=7 ok; lenR=0 → gate 6.  *)
  let sig_bytes = hex_to_cstruct "300702000203aabbcc01" in
  Alcotest.(check bool) "zero R length" false
    (Crypto.is_valid_signature_encoding sig_bytes)

(* Gate 7: 5+lenR >= sig.size() — R overflows sig → false.
   30 06 02 05 01 02 01 01 01 — lenR=5 but only 1 byte of R follows; 5+5=10 >= 9 *)
let test_der_r_overflow () =
  (* sig = 30 06 02 05 01 02 01 01 01: 9 bytes, total_len=6 ok; lenR=5; 5+5=10>=9 → false *)
  let sig_bytes = hex_to_cstruct "300602050102010101" in
  Alcotest.(check bool) "R overflows sig" false
    (Crypto.is_valid_signature_encoding sig_bytes)

(* Gate 8: S integer tag != 0x02 → false.
   Build a structurally consistent sig but with S tag = 0x03.
   R=1 byte, S=1 byte, S_tag=0x03: 30 06 02 01 01 03 01 01 01 *)
let test_der_wrong_s_tag () =
  let sig_bytes = hex_to_cstruct "300602010103010101" in
  Alcotest.(check bool) "wrong S tag 0x03" false
    (Crypto.is_valid_signature_encoding sig_bytes)

(* Gate 9: lenS = 0 → false.
   30 06 02 01 01 02 00 XX 01 — lenS=0, consistent total.
   lenR=1, lenS=0: lenR+lenS+7=8 ≠ 9 → gate 10 fires.
   Need lenR+lenS+7 = sig.size(): lenR=1, lenS=0, 7+1+0=8 → sig.size()=8 < 9.
   Use lenR=2, lenS=0: 7+2+0=9 → sig.size()=9.
   30 07 02 02 01 02 02 00 01: total_len=7, sig.size()=9?
   Wait: 30 total_len 02 02 R[2] 02 00 hashtype = 1+1+1+1+2+1+1+1 = 9 bytes ✓
   total_len = sig.size()-3 = 6, not 7 → mismatch. Fix: total_len=6.
   30 06 02 02 01 01 02 00 01: 1+1+1+1+2+1+1+1=9 bytes, total_len=6=9-3 ✓
   lenR=2, lenS=0; 5+lenR=7; 7<9 ✓; S_tag at sig[4+2]=sig[6]=0x02 ✓; lenS=0 → gate 9 *)
let test_der_zero_s_length () =
  let sig_bytes = hex_to_cstruct "300602020101020001" in
  Alcotest.(check bool) "zero S length" false
    (Crypto.is_valid_signature_encoding sig_bytes)

(* Gate 10: total length mismatch lenR+lenS+7 != sig.size() → false.
   Build a sig where the lengths are individually OK but don't sum correctly.
   R=1, S=1 → should be 9 bytes.  Append an extra byte to make it 10. *)
let test_der_total_mismatch () =
  (* 30 07 02 01 01 02 01 01 XX 01: 10 bytes, total_len=7=10-3 ✓;
     lenR=1, lenS=1; lenR+lenS+7=9 ≠ 10 → gate 10 *)
  let sig_bytes = hex_to_cstruct "3007020101020101ff01" in
  Alcotest.(check bool) "total length mismatch" false
    (Crypto.is_valid_signature_encoding sig_bytes)

(* Gate 11: R negative (high bit set on first R byte) → false.
   30 06 02 01 80 02 01 01 01 — R[0] = 0x80 *)
let test_der_r_negative () =
  let sig_bytes = hex_to_cstruct "300602018002010101" in
  Alcotest.(check bool) "R is negative (high bit)" false
    (Crypto.is_valid_signature_encoding sig_bytes)

(* Gate 12: R excessively padded (leading 0x00 when next byte < 0x80) → false.
   30 07 02 02 00 01 02 01 01 01 — R = [00 01], unnecessary leading zero.
   10 bytes: total_len=7=10-3 ✓, lenR=2, lenS=1, lenR+lenS+7=10 ✓ *)
let test_der_r_excess_zero () =
  let sig_bytes = hex_to_cstruct "30070202000102010101" in
  Alcotest.(check bool) "R excess leading zero" false
    (Crypto.is_valid_signature_encoding sig_bytes)

(* Gate 13: R with valid leading zero (next byte >= 0x80) → true.
   30 07 02 02 00 80 02 01 01 01 — R = [00 80], required leading zero *)
let test_der_r_valid_leading_zero () =
  let sig_bytes = hex_to_cstruct "30070202008002010101" in
  Alcotest.(check bool) "R valid leading zero (next byte high)" true
    (Crypto.is_valid_signature_encoding sig_bytes)

(* Gate 14: S negative → false.
   30 06 02 01 01 02 01 80 01 — S[0] = 0x80 *)
let test_der_s_negative () =
  let sig_bytes = hex_to_cstruct "300602010102018001" in
  Alcotest.(check bool) "S is negative (high bit)" false
    (Crypto.is_valid_signature_encoding sig_bytes)

(* Gate 15: S excessively padded → false.
   30 07 02 01 01 02 02 00 01 01 — S = [00 01], unnecessary leading zero.
   10 bytes: total_len=7=10-3 ✓, lenR=1, lenS=2, lenR+lenS+7=10 ✓ *)
let test_der_s_excess_zero () =
  let sig_bytes = hex_to_cstruct "30070201010202000101" in
  Alcotest.(check bool) "S excess leading zero" false
    (Crypto.is_valid_signature_encoding sig_bytes)

(* Gate 16: S with valid leading zero → true.
   30 07 02 01 01 02 02 00 80 01 — S = [00 80], required leading zero *)
let test_der_s_valid_leading_zero () =
  let sig_bytes = hex_to_cstruct "30070201010202008001" in
  Alcotest.(check bool) "S valid leading zero" true
    (Crypto.is_valid_signature_encoding sig_bytes)

(* Valid minimal DER signature *)
let test_der_valid_minimal () =
  let sig_bytes = hex_to_cstruct valid_minimal_der in
  Alcotest.(check bool) "valid minimal DER sig" true
    (Crypto.is_valid_signature_encoding sig_bytes)

(* Valid signature with SIGHASH_ANYONECANPAY | SIGHASH_ALL = 0x81 *)
let test_der_valid_anyonecanpay () =
  let sig_bytes = hex_to_cstruct (make_der_sig ~ht:0x81 "01" "01") in
  Alcotest.(check bool) "valid DER sig ANYONECANPAY" true
    (Crypto.is_valid_signature_encoding sig_bytes)

(* SIGHASH_NONE = 0x02 *)
let test_der_valid_sighash_none () =
  let sig_bytes = hex_to_cstruct (make_der_sig ~ht:0x02 "01" "01") in
  Alcotest.(check bool) "valid DER sig SIGHASH_NONE" true
    (Crypto.is_valid_signature_encoding sig_bytes)

(* SIGHASH_SINGLE = 0x03 *)
let test_der_valid_sighash_single () =
  let sig_bytes = hex_to_cstruct (make_der_sig ~ht:0x03 "01" "01") in
  Alcotest.(check bool) "valid DER sig SIGHASH_SINGLE" true
    (Crypto.is_valid_signature_encoding sig_bytes)

(* Hashtype 0x00 is not valid per STRICTENC (tested separately in script tests)
   but is_valid_signature_encoding does NOT check hashtype — only structure.
   So 0x00 hashtype is structurally valid. *)
let test_der_hashtype_zero_structurally_valid () =
  let sig_bytes = hex_to_cstruct (make_der_sig ~ht:0x00 "01" "01") in
  Alcotest.(check bool) "hashtype 0x00 structurally valid (encoding check only)" true
    (Crypto.is_valid_signature_encoding sig_bytes)

(* ============================================================================
   is_defined_hash_type tests
   Tests the is_defined_hash_type predicate in script.ml.
   Valid types (after stripping ANYONECANPAY bit): 0x01 ALL, 0x02 NONE, 0x03 SINGLE.
   ============================================================================ *)

let test_defined_hashtype_all () =
  Alcotest.(check bool) "SIGHASH_ALL (0x01) is defined" true
    (Script.is_defined_hash_type 0x01)

let test_defined_hashtype_none () =
  Alcotest.(check bool) "SIGHASH_NONE (0x02) is defined" true
    (Script.is_defined_hash_type 0x02)

let test_defined_hashtype_single () =
  Alcotest.(check bool) "SIGHASH_SINGLE (0x03) is defined" true
    (Script.is_defined_hash_type 0x03)

let test_defined_hashtype_anyonecanpay_all () =
  Alcotest.(check bool) "ANYONECANPAY|ALL (0x81) is defined" true
    (Script.is_defined_hash_type 0x81)

let test_defined_hashtype_anyonecanpay_none () =
  Alcotest.(check bool) "ANYONECANPAY|NONE (0x82) is defined" true
    (Script.is_defined_hash_type 0x82)

let test_defined_hashtype_anyonecanpay_single () =
  Alcotest.(check bool) "ANYONECANPAY|SINGLE (0x83) is defined" true
    (Script.is_defined_hash_type 0x83)

let test_defined_hashtype_zero_invalid () =
  Alcotest.(check bool) "0x00 is not a defined hashtype" false
    (Script.is_defined_hash_type 0x00)

let test_defined_hashtype_four_invalid () =
  Alcotest.(check bool) "0x04 is not a defined hashtype" false
    (Script.is_defined_hash_type 0x04)

let test_defined_hashtype_anyonecanpay_zero_invalid () =
  Alcotest.(check bool) "ANYONECANPAY|0x00 (0x80) is not defined" false
    (Script.is_defined_hash_type 0x80)

let test_defined_hashtype_anyonecanpay_four_invalid () =
  Alcotest.(check bool) "ANYONECANPAY|0x04 (0x84) is not defined" false
    (Script.is_defined_hash_type 0x84)

let bip66_der_tests = [
  Alcotest.test_case "too short (8 bytes)" `Quick test_der_too_short;
  Alcotest.test_case "too long (74 bytes)" `Quick test_der_too_long;
  Alcotest.test_case "wrong compound tag 0x31" `Quick test_der_wrong_compound_tag;
  Alcotest.test_case "wrong total-length field" `Quick test_der_wrong_total_length;
  Alcotest.test_case "wrong R integer tag 0x03" `Quick test_der_wrong_r_tag;
  Alcotest.test_case "zero R length" `Quick test_der_zero_r_length;
  Alcotest.test_case "R overflows sig" `Quick test_der_r_overflow;
  Alcotest.test_case "wrong S integer tag 0x03" `Quick test_der_wrong_s_tag;
  Alcotest.test_case "zero S length" `Quick test_der_zero_s_length;
  Alcotest.test_case "total length mismatch" `Quick test_der_total_mismatch;
  Alcotest.test_case "R negative (high bit)" `Quick test_der_r_negative;
  Alcotest.test_case "R excess leading zero" `Quick test_der_r_excess_zero;
  Alcotest.test_case "R valid leading zero" `Quick test_der_r_valid_leading_zero;
  Alcotest.test_case "S negative (high bit)" `Quick test_der_s_negative;
  Alcotest.test_case "S excess leading zero" `Quick test_der_s_excess_zero;
  Alcotest.test_case "S valid leading zero" `Quick test_der_s_valid_leading_zero;
  Alcotest.test_case "valid minimal (R=1, S=1)" `Quick test_der_valid_minimal;
  Alcotest.test_case "valid ANYONECANPAY|ALL" `Quick test_der_valid_anyonecanpay;
  Alcotest.test_case "valid SIGHASH_NONE" `Quick test_der_valid_sighash_none;
  Alcotest.test_case "valid SIGHASH_SINGLE" `Quick test_der_valid_sighash_single;
  Alcotest.test_case "hashtype 0x00 structurally valid" `Quick test_der_hashtype_zero_structurally_valid;
]

let defined_hashtype_tests = [
  Alcotest.test_case "SIGHASH_ALL defined" `Quick test_defined_hashtype_all;
  Alcotest.test_case "SIGHASH_NONE defined" `Quick test_defined_hashtype_none;
  Alcotest.test_case "SIGHASH_SINGLE defined" `Quick test_defined_hashtype_single;
  Alcotest.test_case "ANYONECANPAY|ALL defined" `Quick test_defined_hashtype_anyonecanpay_all;
  Alcotest.test_case "ANYONECANPAY|NONE defined" `Quick test_defined_hashtype_anyonecanpay_none;
  Alcotest.test_case "ANYONECANPAY|SINGLE defined" `Quick test_defined_hashtype_anyonecanpay_single;
  Alcotest.test_case "0x00 not defined" `Quick test_defined_hashtype_zero_invalid;
  Alcotest.test_case "0x04 not defined" `Quick test_defined_hashtype_four_invalid;
  Alcotest.test_case "0x80 not defined" `Quick test_defined_hashtype_anyonecanpay_zero_invalid;
  Alcotest.test_case "0x84 not defined" `Quick test_defined_hashtype_anyonecanpay_four_invalid;
]

let () = Alcotest.run "test_crypto" [
  ("sha256", sha256_tests);
  ("hash160", hash160_tests);
  ("keygen", keygen_tests);
  ("signing", signing_tests);
  ("merkle", merkle_tests);
  ("genesis", genesis_tests);
  ("property", qcheck_tests);
  ("hardware_accel", hardware_accel_tests);
  ("bip66_der_encoding", bip66_der_tests);
  ("defined_hashtype", defined_hashtype_tests);
]
