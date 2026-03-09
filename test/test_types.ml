open Camlcoin

(* Test hash hex conversions *)
let test_hash256_roundtrip () =
  let hex = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f" in
  let hash = Types.hash256_of_hex hex in
  let result = Types.hash256_to_hex hash in
  Alcotest.(check string) "roundtrip" hex result

let test_hash256_display_reverse () =
  (* Bitcoin genesis block hash in internal byte order *)
  let internal_hex = "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000" in
  let hash = Types.hash256_of_hex internal_hex in
  let display = Types.hash256_to_hex_display hash in
  (* Display format should be reversed *)
  let expected = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f" in
  Alcotest.(check string) "display reversed" expected display

let test_zero_hash () =
  let zero = Types.zero_hash in
  Alcotest.(check int) "length" 32 (Cstruct.length zero);
  (* Check all bytes are zero *)
  for i = 0 to 31 do
    Alcotest.(check int) "zero byte" 0 (Cstruct.get_uint8 zero i)
  done;
  let hex = Types.hash256_to_hex zero in
  let expected = "0000000000000000000000000000000000000000000000000000000000000000" in
  Alcotest.(check string) "zero hash" expected hex

let test_hash256_invalid_length () =
  Alcotest.check_raises "short hex" (Failure "hash256_of_hex: expected 64 hex chars")
    (fun () -> ignore (Types.hash256_of_hex "00112233"))

(* QCheck property tests *)
let hex_chars = [|'0';'1';'2';'3';'4';'5';'6';'7';'8';'9';'a';'b';'c';'d';'e';'f'|]

let hex64_gen st =
  String.init 64 (fun _ -> hex_chars.(Random.State.int st 16))

let qcheck_hash_roundtrip =
  QCheck.Test.make ~count:100 ~name:"hash256 roundtrip property"
    (QCheck.make hex64_gen)
    (fun hex ->
      let hash = Types.hash256_of_hex hex in
      let result = Types.hash256_to_hex hash in
      result = hex)

let () =
  let open Alcotest in
  run "test_types" [
    "hash256", [
      test_case "roundtrip" `Quick test_hash256_roundtrip;
      test_case "display reverse" `Quick test_hash256_display_reverse;
      test_case "zero hash" `Quick test_zero_hash;
      test_case "invalid length" `Quick test_hash256_invalid_length;
    ];
    "property tests", [
      QCheck_alcotest.to_alcotest qcheck_hash_roundtrip;
    ];
  ]
