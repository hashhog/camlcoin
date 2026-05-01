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

(* Core-strict whitelist rejection (matches
   bitcoin-core/src/validation.cpp:5775-5780). The regtest genesis hash is
   intentionally absent from [mainnet_au_data], so any snapshot whose
   metadata advertises that hash as the [base_blockhash] must be refused
   by [get_assumeutxo_for_hash] regardless of how it was framed. *)
let test_regtest_genesis_rejected () =
  let name = "regtest-genesis blockhash rejected by mainnet whitelist" in
  let regtest_genesis = Camlcoin.Consensus.regtest.genesis_hash in
  match Assume_utxo.get_assumeutxo_for_hash
          ~network:Camlcoin.Consensus.mainnet regtest_genesis with
  | None -> test_passed name
  | Some _ ->
    test_failed name
      "Regtest genesis hash must NOT match any mainnet AssumeUTXO entry"

(* End-to-end snapshot rejection: write a snapshot whose metadata carries
   the regtest genesis as [base_blockhash], read it back through the same
   helpers the [loadtxoutset] RPC uses, and assert the whitelist lookup
   refuses it. This is the exact decision point in [handle_loadtxoutset]:
   the RPC reports
     "Assumeutxo height in snapshot metadata not recognized (...) -
      refusing to load snapshot"
   when this lookup returns None. *)
let test_loadtxoutset_regtest_genesis_refused () =
  let name = "loadtxoutset path: regtest-genesis snapshot is refused" in
  let dir = temp_dir () in
  let path = Filename.concat dir "regtest_genesis_snapshot.dat" in
  let regtest_genesis = Camlcoin.Consensus.regtest.genesis_hash in
  let metadata : Assume_utxo.snapshot_metadata = {
    network_magic = Camlcoin.Consensus.mainnet.magic;
    base_blockhash = regtest_genesis;
    coins_count = 0L;
  } in
  (match Assume_utxo.write_snapshot path metadata
           ~iter_coins:(fun _emit -> ()) with
  | Error msg ->
    cleanup_dir dir;
    test_failed name ("Snapshot write failed: " ^ msg)
  | Ok () ->
    (match Assume_utxo.read_snapshot_metadata path
             ~expected_network_magic:Camlcoin.Consensus.mainnet.magic with
    | Error msg ->
      cleanup_dir dir;
      test_failed name ("Snapshot read failed: " ^ msg)
    | Ok decoded ->
      (match Assume_utxo.get_assumeutxo_for_hash
               ~network:Camlcoin.Consensus.mainnet decoded.base_blockhash with
      | None ->
        cleanup_dir dir;
        test_passed name
      | Some _ ->
        cleanup_dir dir;
        test_failed name
          "Regtest-genesis snapshot must be refused by the whitelist")))

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
   MuHash3072 UTXO commitment tests

   These exercise [Assume_utxo.compute_utxo_muhash_from_db] and
   [verify_loaded_utxo_muhash] against a fresh per-test DB so we can
   pin down the exact preimage shape without dragging in a chainstate
   bootstrap. The MuHash3072 module itself is exhaustively covered by
   [test/test_muhash.ml] (Core's canonical vectors); these tests focus
   on the wiring into the snapshot-validation paths.
   ============================================================================ *)

(* Insert a UTXO into a chain DB using the same encoding the snapshot
   loader / IBD path uses (Utxo.serialize_utxo_entry). Returns nothing;
   reading back via Storage.ChainDB.iter_utxos is what the production
   compute_utxo_muhash_from_db does. *)
let put_test_utxo (db : Storage.ChainDB.t) ~txid_hex ~vout
    ~value ~script ~height ~is_coinbase =
  let entry : Utxo.utxo_entry = {
    Utxo.value;
    script_pubkey = Cstruct.of_string script;
    height;
    is_coinbase;
  } in
  let w = Serialize.writer_create () in
  Utxo.serialize_utxo_entry w entry;
  let cs = Serialize.writer_to_cstruct w in
  let txid = Types.hash256_of_hex txid_hex in
  Storage.ChainDB.store_utxo db txid vout (Cstruct.to_string cs)

let test_muhash_empty_db () =
  let name = "muhash: empty UTXO set is canonical empty MuHash" in
  let dir = temp_dir () in
  let db = Storage.ChainDB.create (Filename.concat dir "chain") in
  let actual = Assume_utxo.compute_utxo_muhash_from_db db in
  let expected =
    Cstruct.of_bytes (Muhash.finalize (Muhash.create ()))
  in
  Storage.ChainDB.close db;
  cleanup_dir dir;
  if Cstruct.equal actual expected then test_passed name
  else test_failed name "Empty MuHash mismatch with finalize(create())"

let test_muhash_deterministic () =
  let name = "muhash: identical UTXO sets produce identical MuHash" in
  let dir1 = temp_dir () in
  let dir2 = temp_dir () in
  let db1 = Storage.ChainDB.create (Filename.concat dir1 "chain") in
  let db2 = Storage.ChainDB.create (Filename.concat dir2 "chain") in
  let load db =
    put_test_utxo db
      ~txid_hex:
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
      ~vout:0 ~value:5_000_000_000L
      ~script:"\x76\xa9\x14abcdefghijklmnopqrst\x88\xac"
      ~height:100 ~is_coinbase:true;
    put_test_utxo db
      ~txid_hex:
        "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
      ~vout:7 ~value:21_000L
      ~script:"\x51" ~height:200 ~is_coinbase:false
  in
  load db1; load db2;
  let h1 = Assume_utxo.compute_utxo_muhash_from_db db1 in
  let h2 = Assume_utxo.compute_utxo_muhash_from_db db2 in
  Storage.ChainDB.close db1;
  Storage.ChainDB.close db2;
  cleanup_dir dir1;
  cleanup_dir dir2;
  if Cstruct.equal h1 h2 then test_passed name
  else test_failed name "Same UTXO set produced different MuHash values"

let test_muhash_differs_from_sha256d () =
  let name = "muhash: MuHash != sha256d hash for same UTXO set" in
  let dir = temp_dir () in
  let db = Storage.ChainDB.create (Filename.concat dir "chain") in
  put_test_utxo db
    ~txid_hex:
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    ~vout:0 ~value:5_000_000_000L
    ~script:"\x51" ~height:1 ~is_coinbase:true;
  let muhash = Assume_utxo.compute_utxo_muhash_from_db db in
  let sha256d = Assume_utxo.compute_utxo_hash_from_db db in
  Storage.ChainDB.close db;
  cleanup_dir dir;
  if Cstruct.equal muhash sha256d then
    test_failed name "MuHash and sha256d should not collide on a non-empty set"
  else test_passed name

let test_muhash_set_change_changes_hash () =
  let name = "muhash: changing one UTXO changes the commitment" in
  let dir = temp_dir () in
  let db = Storage.ChainDB.create (Filename.concat dir "chain") in
  put_test_utxo db
    ~txid_hex:
      "1111111111111111111111111111111111111111111111111111111111111111"
    ~vout:0 ~value:1_000L ~script:"\x51"
    ~height:10 ~is_coinbase:false;
  let h1 = Assume_utxo.compute_utxo_muhash_from_db db in
  put_test_utxo db
    ~txid_hex:
      "2222222222222222222222222222222222222222222222222222222222222222"
    ~vout:0 ~value:2_000L ~script:"\x52"
    ~height:11 ~is_coinbase:false;
  let h2 = Assume_utxo.compute_utxo_muhash_from_db db in
  Storage.ChainDB.close db;
  cleanup_dir dir;
  if Cstruct.equal h1 h2 then
    test_failed name "Adding a UTXO must change the MuHash commitment"
  else test_passed name

let test_verify_loaded_utxo_muhash_match () =
  let name =
    "verify_loaded_utxo_muhash: agreeing hash returns Ok actual"
  in
  let dir = temp_dir () in
  let db = Storage.ChainDB.create (Filename.concat dir "chain") in
  put_test_utxo db
    ~txid_hex:
      "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    ~vout:0 ~value:9_999L ~script:"\x51"
    ~height:42 ~is_coinbase:false;
  let expected = Assume_utxo.compute_utxo_muhash_from_db db in
  match Assume_utxo.verify_loaded_utxo_muhash ~db ~expected with
  | Ok actual ->
    Storage.ChainDB.close db; cleanup_dir dir;
    if Cstruct.equal actual expected then test_passed name
    else test_failed name "Returned hash differs from expected on match"
  | Error msg ->
    Storage.ChainDB.close db; cleanup_dir dir;
    test_failed name ("Verification rejected matching hash: " ^ msg)

(* ============================================================================
   Strict-gate tests: HASH_SERIALIZED (SHA256d), NOT MuHash3072.

   Pins the [loadtxoutset] strict snapshot content-hash check to
   Bitcoin Core's [HASH_SERIALIZED] semantics
   ([src/validation.cpp:5902-5915] +
   [src/kernel/coinstats.cpp:161-163]). The chainparams
   [m_assumeutxo_data.hash_serialized] field holds the SHA256d
   commitment (e.g. mainnet 840k = a2a5521b...), not the MuHash3072
   commitment. Reverts the regression in 649d85d which mis-wired the
   gate to MuHash3072.
   ============================================================================ *)

let test_verify_loaded_utxo_hash_match () =
  let name =
    "verify_loaded_utxo_hash: SHA256d agreeing hash returns Ok actual"
  in
  let dir = temp_dir () in
  let db = Storage.ChainDB.create (Filename.concat dir "chain") in
  put_test_utxo db
    ~txid_hex:
      "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    ~vout:0 ~value:9_999L ~script:"\x51"
    ~height:42 ~is_coinbase:false;
  let expected = Assume_utxo.compute_utxo_hash_from_db db in
  match Assume_utxo.verify_loaded_utxo_hash ~db ~expected with
  | Ok actual ->
    Storage.ChainDB.close db; cleanup_dir dir;
    if Cstruct.equal actual expected then test_passed name
    else test_failed name "Returned hash differs from expected on match"
  | Error msg ->
    Storage.ChainDB.close db; cleanup_dir dir;
    test_failed name ("Verification rejected matching hash: " ^ msg)

let test_verify_loaded_utxo_hash_mismatch_uses_core_wording () =
  let name =
    "verify_loaded_utxo_hash: SHA256d mismatch returns Core's verbatim error"
  in
  let dir = temp_dir () in
  let db = Storage.ChainDB.create (Filename.concat dir "chain") in
  put_test_utxo db
    ~txid_hex:
      "abababababababababababababababababababababababababababababababab"
    ~vout:0 ~value:50_000L ~script:"\x51"
    ~height:5 ~is_coinbase:false;
  (* Wrong expected: the 840k mainnet AssumeUTXO commitment, which our
     synthetic single-coin DB cannot possibly match. *)
  let bogus_expected =
    (List.hd Assume_utxo.mainnet_au_data).coins_hash
  in
  match Assume_utxo.verify_loaded_utxo_hash ~db ~expected:bogus_expected with
  | Ok _ ->
    Storage.ChainDB.close db; cleanup_dir dir;
    test_failed name "Mismatch must NOT return Ok"
  | Error msg ->
    Storage.ChainDB.close db; cleanup_dir dir;
    let prefix = "Bad snapshot content hash: expected " in
    let plen = String.length prefix in
    if String.length msg >= plen
       && String.sub msg 0 plen = prefix then test_passed name
    else
      test_failed name
        (Printf.sprintf "Wrong error wording: %s" msg)

(* The strict gate MUST use SHA256d (HASH_SERIALIZED), not MuHash3072.
   Pins the regression: feeding the MuHash3072 commitment to the
   strict-gate verifier MUST fail, because the chainparams pin is a
   SHA256d. *)
let test_verify_loaded_utxo_hash_rejects_muhash_value () =
  let name =
    "verify_loaded_utxo_hash: rejects MuHash3072 commitment as expected value"
  in
  let dir = temp_dir () in
  let db = Storage.ChainDB.create (Filename.concat dir "chain") in
  put_test_utxo db
    ~txid_hex:
      "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
    ~vout:0 ~value:1L ~script:"\x51"
    ~height:7 ~is_coinbase:false;
  let muhash = Assume_utxo.compute_utxo_muhash_from_db db in
  let sha256d = Assume_utxo.compute_utxo_hash_from_db db in
  if Cstruct.equal muhash sha256d then begin
    Storage.ChainDB.close db; cleanup_dir dir;
    test_failed name "MuHash and SHA256d collided on a non-empty set; \
                      cannot pin strict gate"
  end else
    match Assume_utxo.verify_loaded_utxo_hash ~db ~expected:muhash with
    | Ok _ ->
      Storage.ChainDB.close db; cleanup_dir dir;
      test_failed name
        "Strict gate accepted MuHash3072 value; gate is wired to MuHash, \
         not HASH_SERIALIZED (regression)"
    | Error _ ->
      (* Sanity-check the converse: feeding the SHA256d value DOES pass. *)
      match Assume_utxo.verify_loaded_utxo_hash ~db ~expected:sha256d with
      | Ok actual when Cstruct.equal actual sha256d ->
        Storage.ChainDB.close db; cleanup_dir dir;
        test_passed name
      | Ok _ ->
        Storage.ChainDB.close db; cleanup_dir dir;
        test_failed name
          "Strict gate accepted SHA256d but returned wrong actual"
      | Error msg ->
        Storage.ChainDB.close db; cleanup_dir dir;
        test_failed name
          ("Strict gate rejected matching SHA256d: " ^ msg)

let test_verify_loaded_utxo_muhash_mismatch_uses_core_wording () =
  (* This is the test the operator asked for: when the loaded UTXO's
     MuHash disagrees with the chainparams-pinned commitment, the
     loadtxoutset path must surface Core's verbatim wording so external
     tooling that scrapes RPC errors keeps working. *)
  let name =
    "verify_loaded_utxo_muhash: mismatch returns Core's verbatim error"
  in
  let dir = temp_dir () in
  let db = Storage.ChainDB.create (Filename.concat dir "chain") in
  put_test_utxo db
    ~txid_hex:
      "abababababababababababababababababababababababababababababababab"
    ~vout:0 ~value:50_000L ~script:"\x51"
    ~height:5 ~is_coinbase:false;
  (* Wrong expected: the 840k mainnet AssumeUTXO MuHash, which our
     synthetic single-coin DB cannot possibly match. *)
  let bogus_expected =
    (List.hd Assume_utxo.mainnet_au_data).coins_hash
  in
  match Assume_utxo.verify_loaded_utxo_muhash ~db ~expected:bogus_expected with
  | Ok _ ->
    Storage.ChainDB.close db; cleanup_dir dir;
    test_failed name "Mismatch must NOT return Ok"
  | Error msg ->
    Storage.ChainDB.close db; cleanup_dir dir;
    let prefix = "Bad snapshot content hash: expected " in
    let plen = String.length prefix in
    if String.length msg >= plen
       && String.sub msg 0 plen = prefix then test_passed name
    else
      test_failed name
        (Printf.sprintf "Wrong error wording: %s" msg)

(* ============================================================================
   handle_dumptxoutset rollback-mode tests

   Mirrors Bitcoin Core's [src/rpc/blockchain.cpp:dumptxoutset] three-mode
   parameter parsing: ["latest"], ["rollback"], and the named [{"rollback":
   <h|hash>}] option. The rewind path itself is exercised over a no-op
   tip (target == current tip) so this suite stays self-contained — full
   multi-block reorg tests live in test_sync.ml's reorganize coverage and
   in the regtest harness ([test/test_regtest.ml]).
   ============================================================================ *)

(* Build a minimal [Rpc.rpc_context] suitable for [handle_dumptxoutset]
   parameter-parsing tests. The chain starts on mainnet genesis with no
   additional blocks; that's enough to exercise the rollback selector
   logic but obviously cannot test multi-block disconnect. *)
let make_dump_test_ctx () =
  let dir = temp_dir () in
  let db_path = Filename.concat dir "chain" in
  let db = Storage.ChainDB.create db_path in
  let utxo = Utxo.UtxoSet.create db in
  let chain = Sync.create_chain_state db Consensus.mainnet in
  let mp = Mempool.create
    ~require_standard:false
    ~verify_scripts:false
    ~utxo
    ~current_height:0
    () in
  let pm = Peer_manager.create Consensus.mainnet in
  let fe = Fee_estimation.create () in
  let ctx : Rpc.rpc_context = {
    chain;
    mempool = mp;
    peer_manager = pm;
    wallet = None;
    wallet_manager = None;
    fee_estimator = fe;
    network = Consensus.mainnet;
    filter_index = None;
    utxo = None;
    data_dir = Some dir;
  } in
  (ctx, db, dir)

let cleanup_dump_test_ctx db dir =
  Storage.ChainDB.close db;
  cleanup_dir dir

let unique_dump_path label =
  Printf.sprintf "/tmp/camlcoin_dump_%s_%d_%d.dat"
    label (Unix.getpid ()) (Random.int 100000)

let test_dump_rollback_latest_mode () =
  let name = "dumptxoutset: \"latest\" mode emits genesis tip metadata" in
  let (ctx, db, dir) = make_dump_test_ctx () in
  let path = unique_dump_path "latest" in
  (try Sys.remove path with _ -> ());
  let result =
    Rpc.handle_dumptxoutset ctx [`String path; `String "latest"] in
  (try Sys.remove path with _ -> ());
  cleanup_dump_test_ctx db dir;
  match result with
  | Ok (`Assoc fields) ->
    (match List.assoc_opt "base_height" fields with
     | Some (`Int 0) -> test_passed name
     | Some other ->
       test_failed name
         (Printf.sprintf "base_height: wanted 0 (genesis), got %s"
            (Yojson.Safe.to_string other))
     | None -> test_failed name "missing base_height field")
  | Ok _ -> test_failed name "expected `Assoc"
  | Error msg -> test_failed name msg

let test_dump_rollback_default_is_latest () =
  let name = "dumptxoutset: legacy [path] form behaves as \"latest\"" in
  let (ctx, db, dir) = make_dump_test_ctx () in
  let path = unique_dump_path "legacy" in
  (try Sys.remove path with _ -> ());
  let result = Rpc.handle_dumptxoutset ctx [`String path] in
  (try Sys.remove path with _ -> ());
  cleanup_dump_test_ctx db dir;
  match result with
  | Ok (`Assoc fields) ->
    (match List.assoc_opt "base_height" fields with
     | Some (`Int 0) -> test_passed name
     | _ -> test_failed name "expected base_height = 0 (genesis)")
  | _ -> test_failed name "expected Ok `Assoc"

let test_dump_rollback_no_target_genesis_chain_errors () =
  let name =
    "dumptxoutset: \"rollback\" w/o target on genesis-only chain errors"
  in
  (* No assumeutxo entry is ≤ genesis (height 0), so the selector
     should reject this with the "no available snapshot heights" message
     rather than silently dump genesis. Mirrors Core's behaviour when
     [GetAvailableSnapshotHeights] returns an empty filtered list. *)
  let (ctx, db, dir) = make_dump_test_ctx () in
  let path = unique_dump_path "rollback_noh" in
  (try Sys.remove path with _ -> ());
  let result =
    Rpc.handle_dumptxoutset ctx [`String path; `String "rollback"] in
  (try Sys.remove path with _ -> ());
  cleanup_dump_test_ctx db dir;
  match result with
  | Error msg ->
    if try
         let prefix = "No assumeutxo snapshot heights" in
         String.length msg >= String.length prefix
         && String.sub msg 0 (String.length prefix) = prefix
       with _ -> false
    then test_passed name
    else
      test_failed name
        (Printf.sprintf "wrong error wording: %s" msg)
  | Ok _ -> test_failed name "expected Error, got Ok"

let test_dump_rollback_named_option_height_above_tip_errors () =
  let name =
    "dumptxoutset: rollback={height} above current tip errors"
  in
  let (ctx, db, dir) = make_dump_test_ctx () in
  let path = unique_dump_path "rollback_above" in
  (try Sys.remove path with _ -> ());
  let result = Rpc.handle_dumptxoutset ctx [
    `String path;
    `String "";
    `Assoc [("rollback", `Int 1_000)]
  ] in
  (try Sys.remove path with _ -> ());
  cleanup_dump_test_ctx db dir;
  match result with
  | Error msg ->
    if try
         let needle = "after current tip" in
         let nlen = String.length needle in
         let mlen = String.length msg in
         let rec search i =
           if i + nlen > mlen then false
           else if String.sub msg i nlen = needle then true
           else search (i + 1)
         in
         search 0
       with _ -> false
    then test_passed name
    else
      test_failed name
        (Printf.sprintf "wrong error wording: %s" msg)
  | Ok _ -> test_failed name "expected Error, got Ok"

let test_dump_rollback_named_option_height_zero_works () =
  let name =
    "dumptxoutset: rollback={0} on genesis chain dumps genesis (no-op rewind)"
  in
  (* Target == current tip (genesis at height 0) should be a no-op:
     the rollback selector resolves the target, but [disconnect_to_target]
     short-circuits because [Cstruct.equal target.hash tip.hash]. *)
  let (ctx, db, dir) = make_dump_test_ctx () in
  let path = unique_dump_path "rollback_zero" in
  (try Sys.remove path with _ -> ());
  let result = Rpc.handle_dumptxoutset ctx [
    `String path;
    `String "rollback";
    `Assoc [("rollback", `Int 0)]
  ] in
  (try Sys.remove path with _ -> ());
  cleanup_dump_test_ctx db dir;
  match result with
  | Ok (`Assoc fields) ->
    (match List.assoc_opt "base_height" fields with
     | Some (`Int 0) -> test_passed name
     | _ -> test_failed name "expected base_height = 0")
  | _ -> test_failed name "expected Ok `Assoc"

let test_dump_rollback_negative_height_errors () =
  let name = "dumptxoutset: rollback={-1} errors with \"is negative\"" in
  let (ctx, db, dir) = make_dump_test_ctx () in
  let path = unique_dump_path "rollback_neg" in
  (try Sys.remove path with _ -> ());
  let result = Rpc.handle_dumptxoutset ctx [
    `String path;
    `String "";
    `Assoc [("rollback", `Int (-1))]
  ] in
  (try Sys.remove path with _ -> ());
  cleanup_dump_test_ctx db dir;
  match result with
  | Error msg ->
    if try
         let needle = "is negative" in
         let nlen = String.length needle in
         let mlen = String.length msg in
         let rec search i =
           if i + nlen > mlen then false
           else if String.sub msg i nlen = needle then true
           else search (i + 1)
         in
         search 0
       with _ -> false
    then test_passed name
    else
      test_failed name
        (Printf.sprintf "wrong error wording: %s" msg)
  | Ok _ -> test_failed name "expected Error, got Ok"

let test_dump_rollback_type_conflicts_with_named_option () =
  let name =
    "dumptxoutset: type=\"latest\" + rollback={...} option errors"
  in
  let (ctx, db, dir) = make_dump_test_ctx () in
  let path = unique_dump_path "conflict" in
  (try Sys.remove path with _ -> ());
  let result = Rpc.handle_dumptxoutset ctx [
    `String path;
    `String "latest";
    `Assoc [("rollback", `Int 0)]
  ] in
  (try Sys.remove path with _ -> ());
  cleanup_dump_test_ctx db dir;
  match result with
  | Error msg ->
    if try
         let needle = "specified with rollback option" in
         let nlen = String.length needle in
         let mlen = String.length msg in
         let rec search i =
           if i + nlen > mlen then false
           else if String.sub msg i nlen = needle then true
           else search (i + 1)
         in
         search 0
       with _ -> false
    then test_passed name
    else
      test_failed name
        (Printf.sprintf "wrong error wording: %s" msg)
  | Ok _ -> test_failed name "expected Error, got Ok"

let test_dump_rollback_invalid_type_string_errors () =
  let name = "dumptxoutset: type=\"bogus\" errors with Core wording" in
  let (ctx, db, dir) = make_dump_test_ctx () in
  let path = unique_dump_path "bogus" in
  (try Sys.remove path with _ -> ());
  let result =
    Rpc.handle_dumptxoutset ctx [`String path; `String "bogus"] in
  (try Sys.remove path with _ -> ());
  cleanup_dump_test_ctx db dir;
  match result with
  | Error msg ->
    if try
         let needle = "Please specify \"rollback\" or \"latest\"" in
         let nlen = String.length needle in
         let mlen = String.length msg in
         let rec search i =
           if i + nlen > mlen then false
           else if String.sub msg i nlen = needle then true
           else search (i + 1)
         in
         search 0
       with _ -> false
    then test_passed name
    else
      test_failed name
        (Printf.sprintf "wrong error wording: %s" msg)
  | Ok _ -> test_failed name "expected Error, got Ok"

let test_disconnect_to_target_noop_on_current_tip () =
  let name =
    "Sync.disconnect_to_target: target == tip is a no-op (Ok ())"
  in
  let (ctx, db, dir) = make_dump_test_ctx () in
  let result =
    match ctx.chain.tip with
    | Some t -> Sync.disconnect_to_target ctx.chain t
    | None -> Error "no tip"
  in
  cleanup_dump_test_ctx db dir;
  match result with
  | Ok () -> test_passed name
  | Error msg -> test_failed name msg

let test_disconnect_to_target_unknown_target_errors () =
  let name =
    "Sync.disconnect_to_target: target above tip errors"
  in
  let (ctx, db, dir) = make_dump_test_ctx () in
  let bogus_target : Sync.header_entry = {
    header = Consensus.mainnet.genesis_header;
    hash = Types.zero_hash;
    height = 1_000_000;
    total_work = Types.zero_hash;
  } in
  let result = Sync.disconnect_to_target ctx.chain bogus_target in
  cleanup_dump_test_ctx db dir;
  match result with
  | Error _ -> test_passed name
  | Ok () -> test_failed name "expected Error, got Ok"

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
  test_regtest_genesis_rejected ();
  test_loadtxoutset_regtest_genesis_refused ();
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

  (* MuHash3072 wiring tests *)
  test_muhash_empty_db ();
  test_muhash_deterministic ();
  test_muhash_differs_from_sha256d ();
  test_muhash_set_change_changes_hash ();
  test_verify_loaded_utxo_muhash_match ();
  test_verify_loaded_utxo_muhash_mismatch_uses_core_wording ();

  (* Strict-gate (SHA256d / HASH_SERIALIZED) regression tests *)
  test_verify_loaded_utxo_hash_match ();
  test_verify_loaded_utxo_hash_mismatch_uses_core_wording ();
  test_verify_loaded_utxo_hash_rejects_muhash_value ();

  (* dumptxoutset rollback-mode tests (Bitcoin Core blockchain.cpp:dumptxoutset) *)
  test_dump_rollback_latest_mode ();
  test_dump_rollback_default_is_latest ();
  test_dump_rollback_no_target_genesis_chain_errors ();
  test_dump_rollback_named_option_height_above_tip_errors ();
  test_dump_rollback_named_option_height_zero_works ();
  test_dump_rollback_negative_height_errors ();
  test_dump_rollback_type_conflicts_with_named_option ();
  test_dump_rollback_invalid_type_string_errors ();
  test_disconnect_to_target_noop_on_current_tip ();
  test_disconnect_to_target_unknown_target_errors ();

  Printf.printf "All assume_utxo tests passed!\n"
