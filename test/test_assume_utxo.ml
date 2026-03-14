(* Tests for AssumeUTXO implementation *)

open Camlcoin

(* ============================================================================
   Test Utilities
   ============================================================================ *)

let test_passed name =
  Printf.printf "  [PASS] %s\n" name

let test_failed name msg =
  Printf.printf "  [FAIL] %s: %s\n" name msg;
  exit 1

(* Create a temporary directory for test databases *)
let temp_dir () =
  let name = Printf.sprintf "/tmp/camlcoin_test_%d_%d"
               (Unix.getpid ()) (Random.int 100000) in
  Unix.mkdir name 0o755;
  name

(* Clean up a temporary directory *)
let cleanup_dir path =
  (* Remove all files in directory *)
  let entries = Sys.readdir path in
  Array.iter (fun name ->
    let full_path = Filename.concat path name in
    if Sys.is_directory full_path then
      (* Simple recursive delete for subdirs *)
      ignore (Sys.command (Printf.sprintf "rm -rf %s" full_path))
    else
      Sys.remove full_path
  ) entries;
  Unix.rmdir path

(* ============================================================================
   Snapshot Metadata Tests
   ============================================================================ *)

let test_metadata_serialization () =
  let name = "metadata serialization roundtrip" in
  let metadata : Assume_utxo.snapshot_metadata = {
    network_magic = 0xF9BEB4D9l;  (* mainnet *)
    base_blockhash = Types.hash256_of_hex
      "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5";
    coins_count = 177_240_679L;
  } in

  (* Serialize *)
  let w = Serialize.writer_create () in
  Assume_utxo.serialize_metadata w metadata;
  let data = Serialize.writer_to_cstruct w in

  (* Deserialize *)
  let r = Serialize.reader_of_cstruct data in
  match Assume_utxo.deserialize_metadata r ~expected_network_magic:0xF9BEB4D9l with
  | Error msg -> test_failed name msg
  | Ok decoded ->
    if decoded.network_magic <> metadata.network_magic then
      test_failed name "network_magic mismatch"
    else if not (Cstruct.equal decoded.base_blockhash metadata.base_blockhash) then
      test_failed name "base_blockhash mismatch"
    else if decoded.coins_count <> metadata.coins_count then
      test_failed name "coins_count mismatch"
    else
      test_passed name

let test_metadata_network_mismatch () =
  let name = "metadata network mismatch" in
  let metadata : Assume_utxo.snapshot_metadata = {
    network_magic = 0xF9BEB4D9l;  (* mainnet *)
    base_blockhash = Types.hash256_of_hex
      "0000000000000000000000000000000000000000000000000000000000000001";
    coins_count = 100L;
  } in

  (* Serialize *)
  let w = Serialize.writer_create () in
  Assume_utxo.serialize_metadata w metadata;
  let data = Serialize.writer_to_cstruct w in

  (* Deserialize with wrong expected network *)
  let r = Serialize.reader_of_cstruct data in
  match Assume_utxo.deserialize_metadata r ~expected_network_magic:0x1C163F28l with
  | Error _ -> test_passed name  (* Expected to fail *)
  | Ok _ -> test_failed name "Should have failed with network mismatch"

let test_invalid_magic () =
  let name = "invalid snapshot magic" in
  (* Create data with wrong magic bytes *)
  let data = Cstruct.of_string "wrong" in
  let r = Serialize.reader_of_cstruct data in
  match Assume_utxo.deserialize_metadata r ~expected_network_magic:0xF9BEB4D9l with
  | Error _ -> test_passed name  (* Expected to fail *)
  | Ok _ -> test_failed name "Should have failed with invalid magic"

(* ============================================================================
   Snapshot Coin Tests
   ============================================================================ *)

let test_coin_serialization () =
  let name = "coin serialization roundtrip" in
  let coin : Assume_utxo.snapshot_coin = {
    outpoint = {
      Types.txid = Types.hash256_of_hex
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
      vout = 2l;
    };
    value = 5_000_000_000L;
    script_pubkey = Cstruct.of_string "\x76\xa9\x14test_pubkey_hash_20b\x88\xac";
    height = 500000;
    is_coinbase = false;
  } in

  (* Serialize *)
  let w = Serialize.writer_create () in
  Assume_utxo.serialize_coin w coin;
  let data = Serialize.writer_to_cstruct w in

  (* Deserialize *)
  let r = Serialize.reader_of_cstruct data in
  let decoded = Assume_utxo.deserialize_coin r in

  if not (Cstruct.equal decoded.outpoint.txid coin.outpoint.txid) then
    test_failed name "txid mismatch"
  else if decoded.outpoint.vout <> coin.outpoint.vout then
    test_failed name "vout mismatch"
  else if decoded.value <> coin.value then
    test_failed name "value mismatch"
  else if decoded.height <> coin.height then
    test_failed name "height mismatch"
  else if decoded.is_coinbase <> coin.is_coinbase then
    test_failed name "is_coinbase mismatch"
  else
    test_passed name

let test_coinbase_coin () =
  let name = "coinbase coin serialization" in
  let coin : Assume_utxo.snapshot_coin = {
    outpoint = {
      Types.txid = Types.hash256_of_hex
        "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
      vout = 0l;
    };
    value = 50_000_000_00L;  (* 50 BTC *)
    script_pubkey = Cstruct.of_string "\x00\x14test_witness_program";
    height = 100;
    is_coinbase = true;
  } in

  (* Serialize *)
  let w = Serialize.writer_create () in
  Assume_utxo.serialize_coin w coin;
  let data = Serialize.writer_to_cstruct w in

  (* Deserialize *)
  let r = Serialize.reader_of_cstruct data in
  let decoded = Assume_utxo.deserialize_coin r in

  if not decoded.is_coinbase then
    test_failed name "is_coinbase should be true"
  else if decoded.height <> 100 then
    test_failed name "height mismatch"
  else
    test_passed name

(* ============================================================================
   AssumeUTXO State Tests
   ============================================================================ *)

let test_assumeutxo_state_to_string () =
  let name = "assumeutxo_state_to_string" in
  if Assume_utxo.assumeutxo_state_to_string Assume_utxo.Validated <> "validated" then
    test_failed name "Validated string wrong"
  else if Assume_utxo.assumeutxo_state_to_string Assume_utxo.Unvalidated <> "unvalidated" then
    test_failed name "Unvalidated string wrong"
  else if Assume_utxo.assumeutxo_state_to_string Assume_utxo.Invalid <> "invalid" then
    test_failed name "Invalid string wrong"
  else
    test_passed name

(* ============================================================================
   Hardcoded Params Tests
   ============================================================================ *)

let test_mainnet_params () =
  let name = "mainnet assumeutxo params lookup" in
  match Assume_utxo.get_assumeutxo_params_mainnet 840000 with
  | None -> test_failed name "Should have params for height 840000"
  | Some params ->
    if params.height <> 840000 then
      test_failed name "height mismatch"
    else if params.coins_count <> 177_240_679L then
      test_failed name "coins_count mismatch"
    else
      test_passed name

let test_unknown_height () =
  let name = "unknown height returns None" in
  match Assume_utxo.get_assumeutxo_params_mainnet 123456 with
  | None -> test_passed name
  | Some _ -> test_failed name "Should return None for unknown height"

let test_testnet4_params () =
  let name = "testnet4 assumeutxo params lookup" in
  match Assume_utxo.get_assumeutxo_params_testnet4 160000 with
  | None -> test_failed name "Should have params for height 160000"
  | Some params ->
    if params.height <> 160000 then
      test_failed name "height mismatch"
    else
      test_passed name

(* ============================================================================
   Chainstate ID Tests
   ============================================================================ *)

let test_chainstate_id_to_string () =
  let name = "chainstate_id_to_string" in
  if Assume_utxo.chainstate_id_to_string Assume_utxo.Ibd <> "ibd" then
    test_failed name "Ibd string wrong"
  else if Assume_utxo.chainstate_id_to_string Assume_utxo.Snapshot <> "snapshot" then
    test_failed name "Snapshot string wrong"
  else
    test_passed name

(* ============================================================================
   File I/O Tests
   ============================================================================ *)

let test_snapshot_file_io () =
  let name = "snapshot file write and read metadata" in
  let dir = temp_dir () in
  let path = Filename.concat dir "test_snapshot.dat" in

  let metadata : Assume_utxo.snapshot_metadata = {
    network_magic = 0xF9BEB4D9l;
    base_blockhash = Types.hash256_of_hex
      "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5";
    coins_count = 3L;
  } in

  (* Write a simple snapshot with coins *)
  let coins : Assume_utxo.snapshot_coin list = [
    { outpoint = { Types.txid = Cstruct.create 32; vout = 0l };
      value = 100L; script_pubkey = Cstruct.empty; height = 1; is_coinbase = true };
    { outpoint = { Types.txid = Cstruct.create 32; vout = 1l };
      value = 200L; script_pubkey = Cstruct.empty; height = 2; is_coinbase = false };
    { outpoint = { Types.txid = Cstruct.create 32; vout = 2l };
      value = 300L; script_pubkey = Cstruct.empty; height = 3; is_coinbase = false };
  ] in

  let result = Assume_utxo.write_snapshot path metadata
      ~iter_coins:(fun f -> List.iter f coins) in

  match result with
  | Error msg ->
    cleanup_dir dir;
    test_failed name ("Write failed: " ^ msg)
  | Ok () ->
    (* Read back metadata *)
    (match Assume_utxo.read_snapshot_metadata path
             ~expected_network_magic:0xF9BEB4D9l with
    | Error msg ->
      cleanup_dir dir;
      test_failed name ("Read failed: " ^ msg)
    | Ok decoded ->
      if decoded.coins_count <> 3L then begin
        cleanup_dir dir;
        test_failed name "coins_count mismatch"
      end
      else begin
        cleanup_dir dir;
        test_passed name
      end)

(* ============================================================================
   Background Validation State Tests
   ============================================================================ *)

let test_background_validation_states () =
  let name = "background validation state transitions" in
  let params : Assume_utxo.assumeutxo_params = {
    height = 100;
    blockhash = Cstruct.create 32;
    coins_count = 50L;
    coins_hash = Cstruct.create 32;
  } in
  let bg = Assume_utxo.create_background_validation ~snapshot_params:params in

  if bg.state <> Assume_utxo.BgNotStarted then
    test_failed name "Initial state should be BgNotStarted"
  else if bg.target_height <> 100 then
    test_failed name "target_height mismatch"
  else if bg.validated_height <> 0 then
    test_failed name "validated_height should be 0 initially"
  else
    test_passed name

(* ============================================================================
   Main Test Runner
   ============================================================================ *)

let () =
  Random.self_init ();
  Printf.printf "Running assume_utxo tests...\n";

  (* Metadata tests *)
  test_metadata_serialization ();
  test_metadata_network_mismatch ();
  test_invalid_magic ();

  (* Coin tests *)
  test_coin_serialization ();
  test_coinbase_coin ();

  (* State tests *)
  test_assumeutxo_state_to_string ();
  test_chainstate_id_to_string ();

  (* Hardcoded params tests *)
  test_mainnet_params ();
  test_unknown_height ();
  test_testnet4_params ();

  (* File I/O tests *)
  test_snapshot_file_io ();

  (* Background validation tests *)
  test_background_validation_states ();

  Printf.printf "All assume_utxo tests passed!\n"
