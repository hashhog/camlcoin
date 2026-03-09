(* Tests for Bitcoin address encoding/decoding *)

open Camlcoin

(* Helper to create Cstruct from hex string *)
let hex_to_cstruct hex =
  let len = String.length hex / 2 in
  let buf = Cstruct.create len in
  for i = 0 to len - 1 do
    let byte = int_of_string ("0x" ^ String.sub hex (i * 2) 2) in
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

(* ========== Base58 Tests ========== *)

let test_base58_encode_basic () =
  (* Test vector: "Hello World" -> 2NEpo7TZRRrLZSi2U *)
  let data = Cstruct.of_string "Hello World" in
  let encoded = Address.base58_encode data in
  Alcotest.(check string) "encode Hello World" "JxF12TrwUP45BMd" encoded

let test_base58_encode_leading_zeros () =
  (* Leading zero bytes should become '1' characters *)
  (* 0x00 0x00 0xFF -> two leading zeros (11) + base58(255) = 115Q *)
  let data = hex_to_cstruct "0000ff" in
  let encoded = Address.base58_encode data in
  Alcotest.(check string) "encode with leading zeros" "115Q" encoded

let test_base58_roundtrip () =
  let original = hex_to_cstruct "0102030405060708090a0b0c0d0e0f" in
  let encoded = Address.base58_encode original in
  let decoded = Address.base58_decode encoded in
  Alcotest.(check string) "roundtrip" (cstruct_to_hex original) (cstruct_to_hex decoded)

let test_base58_empty () =
  let data = Cstruct.create 0 in
  let encoded = Address.base58_encode data in
  Alcotest.(check string) "encode empty" "" encoded;
  let decoded = Address.base58_decode "" in
  Alcotest.(check int) "decode empty" 0 (Cstruct.length decoded)

(* ========== Base58Check Tests ========== *)

let test_base58check_encode_p2pkh () =
  (* Test vector: version 0x00 + 20-byte hash *)
  (* This is the hash160 of a specific pubkey that gives address 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2 *)
  let hash = hex_to_cstruct "77bff20c60e522dfaa3350c39b030a5d004e839a" in
  let payload = Cstruct.create 21 in
  Cstruct.set_uint8 payload 0 0x00;
  Cstruct.blit hash 0 payload 1 20;
  let addr = Address.base58check_encode payload in
  Alcotest.(check string) "P2PKH address" "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2" addr

let test_base58check_decode_valid () =
  let addr = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2" in
  match Address.base58check_decode addr with
  | Ok payload ->
    Alcotest.(check int) "payload length" 21 (Cstruct.length payload);
    Alcotest.(check int) "version byte" 0x00 (Cstruct.get_uint8 payload 0)
  | Error e ->
    Alcotest.fail ("decode failed: " ^ e)

let test_base58check_decode_invalid_checksum () =
  (* Modify last character to create invalid checksum *)
  let addr = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3" in
  match Address.base58check_decode addr with
  | Ok _ -> Alcotest.fail "should have failed"
  | Error _ -> ()

let test_base58check_roundtrip () =
  let original = Cstruct.concat [hex_to_cstruct "05"; hex_to_cstruct "0102030405060708091011121314151617181920"] in
  let encoded = Address.base58check_encode original in
  match Address.base58check_decode encoded with
  | Ok decoded ->
    Alcotest.(check string) "roundtrip" (cstruct_to_hex original) (cstruct_to_hex decoded)
  | Error e ->
    Alcotest.fail ("decode failed: " ^ e)

(* ========== Bech32 Tests ========== *)

let test_bech32_encode_p2wpkh () =
  (* Test vector from BIP-173 *)
  let hash = hex_to_cstruct "751e76e8199196d454941c45d1b3a323f1433bd6" in
  let data_8bit = List.init 20 (fun i -> Cstruct.get_uint8 hash i) in
  match Address.convert_bits ~from_bits:8 ~to_bits:5 ~pad:true data_8bit with
  | Some data_5bit ->
    let addr = Address.bech32_encode Address.Bech32 "bc" (0 :: data_5bit) in
    Alcotest.(check string) "P2WPKH address"
      "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4" addr
  | None -> Alcotest.fail "convert_bits failed"

let test_bech32_decode_p2wpkh () =
  let addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4" in
  match Address.bech32_decode addr with
  | Some (enc, hrp, data) ->
    Alcotest.(check string) "hrp" "bc" hrp;
    (match enc with
     | Address.Bech32 -> ()
     | Address.Bech32m -> Alcotest.fail "expected Bech32");
    Alcotest.(check int) "witness version" 0 (List.hd data)
  | None -> Alcotest.fail "decode failed"

let test_bech32m_encode_p2tr () =
  (* Test vector from BIP-350 *)
  let hash = hex_to_cstruct "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" in
  let data_8bit = List.init 32 (fun i -> Cstruct.get_uint8 hash i) in
  match Address.convert_bits ~from_bits:8 ~to_bits:5 ~pad:true data_8bit with
  | Some data_5bit ->
    let addr = Address.bech32_encode Address.Bech32m "bc" (1 :: data_5bit) in
    Alcotest.(check string) "P2TR address"
      "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0" addr
  | None -> Alcotest.fail "convert_bits failed"

let test_bech32m_decode_p2tr () =
  let addr = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0" in
  match Address.bech32_decode addr with
  | Some (enc, hrp, data) ->
    Alcotest.(check string) "hrp" "bc" hrp;
    (match enc with
     | Address.Bech32m -> ()
     | Address.Bech32 -> Alcotest.fail "expected Bech32m");
    Alcotest.(check int) "witness version" 1 (List.hd data)
  | None -> Alcotest.fail "decode failed"

(* ========== High-level Address Tests ========== *)

let test_address_p2pkh_roundtrip () =
  let hash = hex_to_cstruct "77bff20c60e522dfaa3350c39b030a5d004e839a" in
  let addr = { Address.addr_type = Address.P2PKH; hash; network = `Mainnet } in
  let s = Address.address_to_string addr in
  Alcotest.(check bool) "starts with 1" true (String.length s > 0 && s.[0] = '1');
  match Address.address_of_string s with
  | Ok decoded ->
    Alcotest.(check string) "hash roundtrip"
      (cstruct_to_hex hash) (cstruct_to_hex decoded.hash);
    (match decoded.addr_type with
     | Address.P2PKH -> ()
     | _ -> Alcotest.fail "expected P2PKH")
  | Error e -> Alcotest.fail ("decode failed: " ^ e)

let test_address_p2sh_roundtrip () =
  let hash = hex_to_cstruct "89abcdefabbaabbaabbaabbaabbaabbaabbaabba" in
  let addr = { Address.addr_type = Address.P2SH; hash; network = `Mainnet } in
  let s = Address.address_to_string addr in
  Alcotest.(check bool) "starts with 3" true (String.length s > 0 && s.[0] = '3');
  match Address.address_of_string s with
  | Ok decoded ->
    Alcotest.(check string) "hash roundtrip"
      (cstruct_to_hex hash) (cstruct_to_hex decoded.hash);
    (match decoded.addr_type with
     | Address.P2SH -> ()
     | _ -> Alcotest.fail "expected P2SH")
  | Error e -> Alcotest.fail ("decode failed: " ^ e)

let test_address_p2wpkh_roundtrip () =
  let hash = hex_to_cstruct "751e76e8199196d454941c45d1b3a323f1433bd6" in
  let addr = { Address.addr_type = Address.P2WPKH; hash; network = `Mainnet } in
  let s = Address.address_to_string addr in
  Alcotest.(check bool) "starts with bc1q" true (String.length s > 3 && String.sub s 0 4 = "bc1q");
  match Address.address_of_string s with
  | Ok decoded ->
    Alcotest.(check string) "hash roundtrip"
      (cstruct_to_hex hash) (cstruct_to_hex decoded.hash);
    (match decoded.addr_type with
     | Address.P2WPKH -> ()
     | _ -> Alcotest.fail "expected P2WPKH")
  | Error e -> Alcotest.fail ("decode failed: " ^ e)

let test_address_p2tr_roundtrip () =
  let hash = hex_to_cstruct "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" in
  let addr = { Address.addr_type = Address.P2TR; hash; network = `Mainnet } in
  let s = Address.address_to_string addr in
  Alcotest.(check bool) "starts with bc1p" true (String.length s > 3 && String.sub s 0 4 = "bc1p");
  match Address.address_of_string s with
  | Ok decoded ->
    Alcotest.(check string) "hash roundtrip"
      (cstruct_to_hex hash) (cstruct_to_hex decoded.hash);
    (match decoded.addr_type with
     | Address.P2TR -> ()
     | _ -> Alcotest.fail "expected P2TR")
  | Error e -> Alcotest.fail ("decode failed: " ^ e)

let test_address_testnet_p2pkh () =
  let hash = hex_to_cstruct "77bff20c60e522dfaa3350c39b030a5d004e839a" in
  let addr = { Address.addr_type = Address.P2PKH; hash; network = `Testnet } in
  let s = Address.address_to_string addr in
  Alcotest.(check bool) "starts with m or n" true
    (String.length s > 0 && (s.[0] = 'm' || s.[0] = 'n'));
  match Address.address_of_string s with
  | Ok decoded ->
    (match decoded.network with
     | `Testnet -> ()
     | _ -> Alcotest.fail "expected testnet")
  | Error e -> Alcotest.fail ("decode failed: " ^ e)

let test_address_testnet_bech32 () =
  let hash = hex_to_cstruct "751e76e8199196d454941c45d1b3a323f1433bd6" in
  let addr = { Address.addr_type = Address.P2WPKH; hash; network = `Testnet } in
  let s = Address.address_to_string addr in
  Alcotest.(check bool) "starts with tb1" true
    (String.length s >= 3 && String.sub s 0 3 = "tb1");
  match Address.address_of_string s with
  | Ok decoded ->
    (match decoded.network with
     | `Testnet -> ()
     | _ -> Alcotest.fail "expected testnet")
  | Error e -> Alcotest.fail ("decode failed: " ^ e)

(* ========== WIF Tests ========== *)

let test_wif_encode_compressed_mainnet () =
  (* Known test vector *)
  let privkey = hex_to_cstruct "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d" in
  let wif = Address.wif_encode ~compressed:true ~network:`Mainnet privkey in
  Alcotest.(check string) "WIF compressed mainnet"
    "KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617" wif

let test_wif_encode_uncompressed_mainnet () =
  let privkey = hex_to_cstruct "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d" in
  let wif = Address.wif_encode ~compressed:false ~network:`Mainnet privkey in
  Alcotest.(check string) "WIF uncompressed mainnet"
    "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ" wif

let test_wif_decode_compressed () =
  let wif = "KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617" in
  match Address.wif_decode wif with
  | Ok (privkey, compressed, network) ->
    Alcotest.(check bool) "compressed" true compressed;
    (match network with
     | `Mainnet -> ()
     | _ -> Alcotest.fail "expected mainnet");
    Alcotest.(check string) "privkey"
      "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d"
      (cstruct_to_hex privkey)
  | Error e -> Alcotest.fail ("decode failed: " ^ e)

let test_wif_decode_uncompressed () =
  let wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ" in
  match Address.wif_decode wif with
  | Ok (privkey, compressed, network) ->
    Alcotest.(check bool) "uncompressed" false compressed;
    (match network with
     | `Mainnet -> ()
     | _ -> Alcotest.fail "expected mainnet");
    Alcotest.(check string) "privkey"
      "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d"
      (cstruct_to_hex privkey)
  | Error e -> Alcotest.fail ("decode failed: " ^ e)

let test_wif_roundtrip () =
  let privkey = hex_to_cstruct "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef" in
  let wif = Address.wif_encode ~compressed:true ~network:`Testnet privkey in
  match Address.wif_decode wif with
  | Ok (decoded, compressed, network) ->
    Alcotest.(check bool) "compressed" true compressed;
    (match network with
     | `Testnet -> ()
     | _ -> Alcotest.fail "expected testnet");
    Alcotest.(check string) "privkey roundtrip"
      (cstruct_to_hex privkey) (cstruct_to_hex decoded)
  | Error e -> Alcotest.fail ("decode failed: " ^ e)

(* ========== Address from Pubkey Tests ========== *)

let test_of_pubkey_p2pkh () =
  (* Use a known compressed public key *)
  let pubkey = hex_to_cstruct "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" in
  let addr = Address.of_pubkey ~network:`Mainnet Address.P2PKH pubkey in
  let s = Address.address_to_string addr in
  (* Verify it's a valid P2PKH address starting with '1' *)
  Alcotest.(check bool) "starts with 1" true (String.length s > 0 && s.[0] = '1')

let test_of_pubkey_p2wpkh () =
  let pubkey = hex_to_cstruct "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" in
  let addr = Address.of_pubkey ~network:`Mainnet Address.P2WPKH pubkey in
  let s = Address.address_to_string addr in
  (* Verify it's a valid P2WPKH address starting with 'bc1q' *)
  Alcotest.(check bool) "starts with bc1q" true
    (String.length s > 3 && String.sub s 0 4 = "bc1q")

(* ========== Test Suite ========== *)

let base58_tests = [
  Alcotest.test_case "encode basic" `Quick test_base58_encode_basic;
  Alcotest.test_case "encode leading zeros" `Quick test_base58_encode_leading_zeros;
  Alcotest.test_case "roundtrip" `Quick test_base58_roundtrip;
  Alcotest.test_case "empty" `Quick test_base58_empty;
]

let base58check_tests = [
  Alcotest.test_case "encode P2PKH" `Quick test_base58check_encode_p2pkh;
  Alcotest.test_case "decode valid" `Quick test_base58check_decode_valid;
  Alcotest.test_case "decode invalid checksum" `Quick test_base58check_decode_invalid_checksum;
  Alcotest.test_case "roundtrip" `Quick test_base58check_roundtrip;
]

let bech32_tests = [
  Alcotest.test_case "encode P2WPKH" `Quick test_bech32_encode_p2wpkh;
  Alcotest.test_case "decode P2WPKH" `Quick test_bech32_decode_p2wpkh;
  Alcotest.test_case "encode P2TR (Bech32m)" `Quick test_bech32m_encode_p2tr;
  Alcotest.test_case "decode P2TR (Bech32m)" `Quick test_bech32m_decode_p2tr;
]

let address_tests = [
  Alcotest.test_case "P2PKH roundtrip" `Quick test_address_p2pkh_roundtrip;
  Alcotest.test_case "P2SH roundtrip" `Quick test_address_p2sh_roundtrip;
  Alcotest.test_case "P2WPKH roundtrip" `Quick test_address_p2wpkh_roundtrip;
  Alcotest.test_case "P2TR roundtrip" `Quick test_address_p2tr_roundtrip;
  Alcotest.test_case "testnet P2PKH" `Quick test_address_testnet_p2pkh;
  Alcotest.test_case "testnet Bech32" `Quick test_address_testnet_bech32;
]

let wif_tests = [
  Alcotest.test_case "encode compressed mainnet" `Quick test_wif_encode_compressed_mainnet;
  Alcotest.test_case "encode uncompressed mainnet" `Quick test_wif_encode_uncompressed_mainnet;
  Alcotest.test_case "decode compressed" `Quick test_wif_decode_compressed;
  Alcotest.test_case "decode uncompressed" `Quick test_wif_decode_uncompressed;
  Alcotest.test_case "roundtrip" `Quick test_wif_roundtrip;
]

let pubkey_tests = [
  Alcotest.test_case "of_pubkey P2PKH" `Quick test_of_pubkey_p2pkh;
  Alcotest.test_case "of_pubkey P2WPKH" `Quick test_of_pubkey_p2wpkh;
]

let () =
  Alcotest.run "Address" [
    "Base58", base58_tests;
    "Base58Check", base58check_tests;
    "Bech32", bech32_tests;
    "Address", address_tests;
    "WIF", wif_tests;
    "Pubkey", pubkey_tests;
  ]
