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
    network_magic = 0xD9B4BEF9l;  (* mainnet, OCaml int32 form *)
    base_blockhash = Types.hash256_of_hex
      "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5";
    coins_count = 177_240_679L;
  } in

  (* Serialize *)
  let w = Serialize.writer_create () in
  Assume_utxo.serialize_metadata w metadata;
  let data = Serialize.writer_to_cstruct w in

  (* The serialized metadata block is exactly 51 bytes: magic 5 + version 2
     + network 4 + blockhash 32 + coins_count 8. *)
  if Cstruct.length data <> 51 then
    test_failed name (Printf.sprintf "expected 51-byte metadata, got %d"
                        (Cstruct.length data))
  else
  (* Bytes 0..4 are 'utxo\xff'; bytes 5..6 are version 2 LE; bytes 7..10 are
     mainnet pchMessageStart {f9, be, b4, d9}. *)
  let prefix = Cstruct.to_string (Cstruct.sub data 0 11) in
  let expected_prefix = "utxo\xff\x02\x00\xf9\xbe\xb4\xd9" in
  if prefix <> expected_prefix then
    test_failed name (Printf.sprintf
                        "Wire prefix mismatch (got %s, want %s)"
                        (String.escaped prefix)
                        (String.escaped expected_prefix))
  else
  (* Deserialize *)
  let r = Serialize.reader_of_cstruct data in
  match Assume_utxo.deserialize_metadata r ~expected_network_magic:0xD9B4BEF9l with
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
    network_magic = 0xD9B4BEF9l;  (* mainnet *)
    base_blockhash = Types.hash256_of_hex
      "0000000000000000000000000000000000000000000000000000000000000001";
    coins_count = 100L;
  } in

  (* Serialize *)
  let w = Serialize.writer_create () in
  Assume_utxo.serialize_metadata w metadata;
  let data = Serialize.writer_to_cstruct w in

  (* Deserialize with wrong expected network (testnet4) *)
  let r = Serialize.reader_of_cstruct data in
  match Assume_utxo.deserialize_metadata r ~expected_network_magic:0x1C163F28l with
  | Error _ -> test_passed name  (* Expected to fail *)
  | Ok _ -> test_failed name "Should have failed with network mismatch"

let test_invalid_magic () =
  let name = "invalid snapshot magic" in
  (* Create data with wrong magic bytes *)
  let data = Cstruct.of_string "wrong" in
  let r = Serialize.reader_of_cstruct data in
  match Assume_utxo.deserialize_metadata r ~expected_network_magic:0xD9B4BEF9l with
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
    else if params.chain_tx_count <> 991_032_194L then
      test_failed name "chain_tx_count mismatch (must match Core 31.99 chainparams.cpp)"
    else
      test_passed name

(* Verify all four mainnet AssumeUTXO heights from Bitcoin Core 31.99
   chainparams.cpp (heights 840k / 880k / 910k / 935k) are present and
   carry the canonical chain_tx_count + blockhash. *)
let test_mainnet_all_heights () =
  let name = "mainnet assumeutxo all four heights" in
  let expected = [
    (840_000,
       "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5",
       991_032_194L);
    (880_000,
       "000000000000000000010b17283c3c400507969a9c2afd1dcf2082ec5cca2880",
       1_145_604_538L);
    (910_000,
       "0000000000000000000108970acb9522ffd516eae17acddcb1bd16469194a821",
       1_226_586_151L);
    (935_000,
       "0000000000000000000147034958af1652b2b91bba607beacc5e72a56f0fb5ee",
       1_305_397_408L);
  ] in
  let ok = List.for_all (fun (h, want_hash, want_chain_tx) ->
    match Assume_utxo.get_assumeutxo_params_mainnet h with
    | None -> false
    | Some p ->
      Types.hash256_to_hex_display p.blockhash = want_hash
      && Int64.equal p.chain_tx_count want_chain_tx
  ) expected in
  if ok then test_passed name
  else test_failed name "one or more entries missing or mismatched"

let test_unknown_height () =
  let name = "unknown height returns None" in
  match Assume_utxo.get_assumeutxo_params_mainnet 123456 with
  | None -> test_passed name
  | Some _ -> test_failed name "Should return None for unknown height"

(* Testnet4 has no Core-published AssumeUTXO heights as of Core 31.99.
   Verify [get_assumeutxo_params_testnet4] returns None for any height. *)
let test_testnet4_params () =
  let name = "testnet4 assumeutxo: no published heights" in
  match Assume_utxo.get_assumeutxo_params_testnet4 160000 with
  | None -> test_passed name
  | Some _ ->
    test_failed name
      "Testnet4 AssumeUTXO is not yet defined upstream; should return None"

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
    network_magic = 0xD9B4BEF9l;
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
             ~expected_network_magic:0xD9B4BEF9l with
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
   Core Wire-Format Snapshot Tests
   ============================================================================ *)

(* Build a deterministic 32-byte hash from a one-byte tag, used to fabricate
   distinct txids for the wire-format roundtrip tests. *)
let mk_txid (tag : int) : Types.hash256 =
  let buf = Cstruct.create 32 in
  Cstruct.set_uint8 buf 0 tag;
  buf

let test_snapshot_wire_roundtrip () =
  let name = "snapshot wire-format roundtrip (Core layout)" in
  let dir = temp_dir () in
  let path = Filename.concat dir "snap_wire.dat" in
  (* Three coins under two distinct txids: txid A has vouts 0 and 1, txid B
     has vout 0. Exercises the per-txid grouping codepath. *)
  let txid_a = mk_txid 0xAA in
  let txid_b = mk_txid 0xBB in
  let p2pkh_script =
    let s = Cstruct.create 25 in
    Cstruct.set_uint8 s 0 0x76;  (* OP_DUP *)
    Cstruct.set_uint8 s 1 0xa9;  (* OP_HASH160 *)
    Cstruct.set_uint8 s 2 20;
    for i = 0 to 19 do
      Cstruct.set_uint8 s (3 + i) (i + 0x10)
    done;
    Cstruct.set_uint8 s 23 0x88;  (* OP_EQUALVERIFY *)
    Cstruct.set_uint8 s 24 0xac;  (* OP_CHECKSIG *)
    s
  in
  let custom_script = Cstruct.of_string "\x6a\x04\xde\xad\xbe\xef" in
  let coin1 : Assume_utxo.snapshot_coin = {
    outpoint = { Types.txid = txid_a; vout = 0l };
    value = 5_000_000_000L;
    script_pubkey = p2pkh_script;
    height = 100;
    is_coinbase = true;
  } in
  let coin2 : Assume_utxo.snapshot_coin = {
    outpoint = { Types.txid = txid_a; vout = 1l };
    value = 21_000L;
    script_pubkey = custom_script;
    height = 100;
    is_coinbase = false;
  } in
  let coin3 : Assume_utxo.snapshot_coin = {
    outpoint = { Types.txid = txid_b; vout = 0l };
    value = 1L;
    script_pubkey = Cstruct.empty;
    height = 0;
    is_coinbase = false;
  } in
  let coins = [coin1; coin2; coin3] in
  let metadata : Assume_utxo.snapshot_metadata = {
    network_magic = 0xD9B4BEF9l;
    base_blockhash = Cstruct.create 32;
    coins_count = 3L;
  } in
  match Assume_utxo.write_snapshot path metadata
          ~iter_coins:(fun f -> List.iter f coins) with
  | Error msg -> cleanup_dir dir; test_failed name ("write: " ^ msg)
  | Ok () ->
    (* Reopen and stream all coins back via the public iterator. *)
    let ic = open_in_bin path in
    let sr = Assume_utxo.Stream_reader.create ic
               ~start_offset:Assume_utxo.snapshot_body_offset in
    let acc = ref [] in
    let res =
      Assume_utxo.iter_snapshot_coins sr ~coins_count:3L
        ~f:(fun coin -> acc := coin :: !acc)
    in
    close_in ic;
    cleanup_dir dir;
    match res with
    | Error msg -> test_failed name ("iter: " ^ msg)
    | Ok n ->
      let decoded = List.rev !acc in
      let same_coin (a : Assume_utxo.snapshot_coin)
                    (b : Assume_utxo.snapshot_coin) =
        Cstruct.equal a.outpoint.txid b.outpoint.txid
        && Int32.equal a.outpoint.vout b.outpoint.vout
        && Int64.equal a.value b.value
        && Cstruct.equal a.script_pubkey b.script_pubkey
        && a.height = b.height
        && a.is_coinbase = b.is_coinbase
      in
      if Int64.compare n 3L <> 0 then
        test_failed name (Printf.sprintf "expected 3 coins, got %Ld" n)
      else if not (List.length decoded = 3
                   && List.for_all2 same_coin decoded coins) then
        test_failed name "decoded coins do not match input"
      else
        test_passed name

(* Verify the on-wire byte layout for a single 2-coin / 1-txid group
   matches Core exactly. Construct a coin with a known compressed P2PKH
   script and known small amount and compare bytes. *)
let test_snapshot_wire_bytes () =
  let name = "snapshot wire bytes match Core layout" in
  let dir = temp_dir () in
  let path = Filename.concat dir "snap_bytes.dat" in
  let txid = mk_txid 0xCC in
  let coin : Assume_utxo.snapshot_coin = {
    outpoint = { Types.txid; vout = 0l };
    value = 1L;
    script_pubkey = Cstruct.empty;  (* fallback path: VARINT(6) + 0 bytes *)
    height = 0;
    is_coinbase = false;
  } in
  let metadata : Assume_utxo.snapshot_metadata = {
    network_magic = 0xD9B4BEF9l;
    base_blockhash = Cstruct.create 32;
    coins_count = 1L;
  } in
  (match Assume_utxo.write_snapshot path metadata
           ~iter_coins:(fun f -> f coin) with
   | Error msg -> cleanup_dir dir; test_failed name ("write: " ^ msg)
   | Ok () ->
     let ic = open_in_bin path in
     let len = in_channel_length ic in
     let body_len = len - Assume_utxo.snapshot_body_offset in
     seek_in ic Assume_utxo.snapshot_body_offset;
     let body = really_input_string ic body_len in
     close_in ic;
     cleanup_dir dir;
     (* Expected body bytes:
          txid (32 raw) || coins_per_txid CompactSize 0x01
          || vout CompactSize 0x00 || code VARINT(0) = 0x00
          || amount VARINT(CompressAmount(1)) — CompressAmount(1) = 1,
             VARINT(1) = 0x01
          || script size VARINT(0+6) = 0x06 then 0 raw bytes. *)
     let expected = Bytes.create (32 + 1 + 1 + 1 + 1 + 1) in
     Cstruct.blit_to_bytes txid 0 expected 0 32;
     Bytes.set expected 32 (Char.chr 0x01);  (* coins_per_txid *)
     Bytes.set expected 33 (Char.chr 0x00);  (* vout = 0 *)
     Bytes.set expected 34 (Char.chr 0x00);  (* code VARINT *)
     Bytes.set expected 35 (Char.chr 0x01);  (* VARINT(CompressAmount(1)) *)
     Bytes.set expected 36 (Char.chr 0x06);  (* script size VARINT(0+6) *)
     let want = Bytes.unsafe_to_string expected in
     if String.equal body want then test_passed name
     else test_failed name (Printf.sprintf
       "wire bytes mismatch: got=%s want=%s"
       (String.escaped body) (String.escaped want)))

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
    chain_tx_count = 0L;
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
   UTXO Hash Computation Tests
   ============================================================================ *)

let test_utxo_hash_empty () =
  let name = "utxo hash of empty set" in
  try
    let hash = Assume_utxo.compute_utxo_hash
        ~iter_coins:(fun _f -> ()) in
    (* Empty input should hash to sha256d("") *)
    let expected = Crypto.sha256d Cstruct.empty in
    if Cstruct.equal hash expected then
      test_passed name
    else
      test_failed name "Empty hash mismatch"
  with e ->
    test_failed name (Printexc.to_string e)

let test_utxo_hash_single_coin () =
  let name = "utxo hash of single coin" in
  try
    let coin : Assume_utxo.snapshot_coin = {
      outpoint = {
        Types.txid = Types.hash256_of_hex
          "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        vout = 0l;
      };
      value = 5_000_000_000L;  (* 50 BTC *)
      script_pubkey = Cstruct.of_string "\x76\xa9\x14abcdefghijklmnopqrst\x88\xac";
      height = 100;
      is_coinbase = true;
    } in
    let hash1 = Assume_utxo.compute_utxo_hash
        ~iter_coins:(fun f -> f coin.outpoint coin) in
    (* Running again should produce same hash *)
    let hash2 = Assume_utxo.compute_utxo_hash
        ~iter_coins:(fun f -> f coin.outpoint coin) in
    if Cstruct.equal hash1 hash2 then
      test_passed name
    else
      test_failed name "Hash not deterministic"
  with e ->
    test_failed name (Printexc.to_string e)

let test_utxo_hash_multiple_coins () =
  let name = "utxo hash of multiple coins" in
  try
    let coin1 : Assume_utxo.snapshot_coin = {
      outpoint = { Types.txid = Cstruct.create 32; vout = 0l };
      value = 100L;
      script_pubkey = Cstruct.of_string "\x51"; (* OP_TRUE *)
      height = 1;
      is_coinbase = true;
    } in
    let coin2 : Assume_utxo.snapshot_coin = {
      outpoint = { Types.txid = Cstruct.create 32; vout = 1l };
      value = 200L;
      script_pubkey = Cstruct.of_string "\x52"; (* OP_2 *)
      height = 2;
      is_coinbase = false;
    } in
    let hash_both = Assume_utxo.compute_utxo_hash
        ~iter_coins:(fun f -> f coin1.outpoint coin1; f coin2.outpoint coin2) in
    let hash_single = Assume_utxo.compute_utxo_hash
        ~iter_coins:(fun f -> f coin1.outpoint coin1) in
    (* Hash of multiple coins should differ from single coin *)
    if Cstruct.equal hash_both hash_single then
      test_failed name "Multiple coins should produce different hash than single"
    else
      test_passed name
  with e ->
    test_failed name (Printexc.to_string e)

let test_utxo_hash_order_matters () =
  let name = "utxo hash order matters" in
  try
    let coin1 : Assume_utxo.snapshot_coin = {
      outpoint = { Types.txid = Cstruct.create 32; vout = 0l };
      value = 100L;
      script_pubkey = Cstruct.of_string "\x51";
      height = 1;
      is_coinbase = true;
    } in
    let coin2 : Assume_utxo.snapshot_coin = {
      outpoint = { Types.txid = Cstruct.create 32; vout = 1l };
      value = 200L;
      script_pubkey = Cstruct.of_string "\x52";
      height = 2;
      is_coinbase = false;
    } in
    let hash_12 = Assume_utxo.compute_utxo_hash
        ~iter_coins:(fun f -> f coin1.outpoint coin1; f coin2.outpoint coin2) in
    let hash_21 = Assume_utxo.compute_utxo_hash
        ~iter_coins:(fun f -> f coin2.outpoint coin2; f coin1.outpoint coin1) in
    (* Order should matter for deterministic hashing *)
    if Cstruct.equal hash_12 hash_21 then
      test_failed name "Hash should be order-dependent"
    else
      test_passed name
  with e ->
    test_failed name (Printexc.to_string e)

let test_coin_height_encoding () =
  let name = "coin height encoding in hash" in
  try
    let make_coin height is_coinbase =
      let coin : Assume_utxo.snapshot_coin = {
        outpoint = { Types.txid = Cstruct.create 32; vout = 0l };
        value = 100L;
        script_pubkey = Cstruct.of_string "\x51";
        height;
        is_coinbase;
      } in
      Assume_utxo.compute_utxo_hash
        ~iter_coins:(fun f -> f coin.outpoint coin)
    in
    (* Different heights should produce different hashes *)
    let h100 = make_coin 100 false in
    let h200 = make_coin 200 false in
    if Cstruct.equal h100 h200 then
      test_failed name "Different heights should produce different hashes"
    else begin
      (* Coinbase flag should also change hash *)
      let h100_cb = make_coin 100 true in
      if Cstruct.equal h100 h100_cb then
        test_failed name "Coinbase flag should change hash"
      else
        test_passed name
    end
  with e ->
    test_failed name (Printexc.to_string e)

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
  test_mainnet_all_heights ();
  test_unknown_height ();
  test_testnet4_params ();

  (* File I/O tests *)
  test_snapshot_file_io ();
  test_snapshot_wire_roundtrip ();
  test_snapshot_wire_bytes ();

  (* Background validation tests *)
  test_background_validation_states ();

  (* UTXO hash computation tests *)
  test_utxo_hash_empty ();
  test_utxo_hash_single_coin ();
  test_utxo_hash_multiple_coins ();
  test_utxo_hash_order_matters ();
  test_coin_height_encoding ();

  Printf.printf "All assume_utxo tests passed!\n"
