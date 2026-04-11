open Camlcoin

(* Convert a hex string to Cstruct *)
let cstruct_of_hex s =
  let len = String.length s / 2 in
  let buf = Cstruct.create len in
  for i = 0 to len - 1 do
    let byte = int_of_string ("0x" ^ String.sub s (i * 2) 2) in
    Cstruct.set_uint8 buf i byte
  done;
  buf

(* Convert Cstruct to lowercase hex string — bytes in natural order *)
let hex_of_cstruct cs =
  let buf = Buffer.create (Cstruct.length cs * 2) in
  for i = 0 to Cstruct.length cs - 1 do
    Buffer.add_string buf (Printf.sprintf "%02x" (Cstruct.get_uint8 cs i))
  done;
  Buffer.contents buf

(* Bitcoin Core's sighash.json stores expected hashes with GetHex()
   which reverses the raw SHA256d bytes (display/little-endian order).
   compute_sighash_legacy returns raw SHA256d bytes (internal order).
   Reverse the 32-byte expected hex so both are in the same byte order. *)
let reverse_hash_hex s =
  (* s is a 64-char hex string; reverse the 32-byte sequence *)
  let bytes = Array.init 32 (fun i ->
    String.sub s ((31 - i) * 2) 2
  ) in
  Array.fold_left ( ^ ) "" bytes

(* Load and parse the sighash.json test vectors.
   Format: JSON array of arrays. First element is a comment header.
   Each subsequent element: [raw_tx_hex, script_hex, input_index, hash_type, expected_hash_hex] *)
let load_test_vectors path =
  let json = Yojson.Basic.from_file path in
  match json with
  | `List entries ->
    (* Skip the first entry which is a comment/header *)
    let test_entries = List.tl entries in
    List.filter_map (fun entry ->
      match entry with
      | `List [`String raw_tx; `String script; `Int input_index;
               `Int hash_type; `String expected_hash] ->
        Some (raw_tx, script, input_index, hash_type, expected_hash)
      | _ ->
        (* Skip comment lines or malformed entries *)
        None
    ) test_entries
  | _ -> failwith "Expected JSON array at top level"

(* Deserialize a transaction from a raw hex string.
   The sighash.json vectors use non-segwit serialization format. *)
let deserialize_tx_hex hex_str =
  let raw = cstruct_of_hex hex_str in
  let reader = Serialize.reader_of_cstruct raw in
  Serialize.deserialize_transaction reader

(* Run all sighash test vectors *)
let test_sighash_vectors () =
  let vector_path =
    (* resources/ is available relative to the test working directory via
       (deps (source_tree ../resources)) in test/dune *)
    "../resources/sighash.json"
  in
  let vectors = load_test_vectors vector_path in
  let total = List.length vectors in
  let passed = ref 0 in
  let failed = ref 0 in
  let errors = ref 0 in
  List.iteri (fun i (raw_tx, script_hex, input_index, hash_type, expected_hex) ->
    try
      let tx = deserialize_tx_hex raw_tx in
      let script_code = cstruct_of_hex script_hex in
      let sighash = Script.compute_sighash_legacy tx input_index script_code hash_type in
      let got_hex = hex_of_cstruct sighash in
      (* expected_hex is in reversed/display order (Bitcoin Core GetHex convention);
         convert it to internal byte order before comparing. *)
      let expected_internal = reverse_hash_hex expected_hex in
      if String.lowercase_ascii got_hex = String.lowercase_ascii expected_internal then
        incr passed
      else begin
        incr failed;
        Printf.printf "FAIL vector %d: expected (internal) %s, got %s\n" i expected_internal got_hex
      end
    with exn ->
      incr errors;
      Printf.printf "ERROR vector %d: %s\n  raw_tx prefix: %s...\n"
        i (Printexc.to_string exn) (String.sub raw_tx 0 (min 40 (String.length raw_tx)))
  ) vectors;
  Printf.printf "\nSighash test vectors: %d total, %d passed, %d failed, %d errors\n"
    total !passed !failed !errors;
  Alcotest.(check bool) "all vectors pass" true (!failed = 0 && !errors = 0)

let () =
  Alcotest.run "sighash_vectors" [
    "Bitcoin Core sighash.json", [
      Alcotest.test_case "legacy sighash vectors" `Quick test_sighash_vectors;
    ];
  ]
