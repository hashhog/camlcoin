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

let () = Alcotest.run "test_crypto" [
  ("sha256", sha256_tests);
  ("hash160", hash160_tests);
  ("keygen", keygen_tests);
  ("signing", signing_tests);
  ("merkle", merkle_tests);
  ("genesis", genesis_tests);
  ("property", qcheck_tests);
  ("hardware_accel", hardware_accel_tests);
]
