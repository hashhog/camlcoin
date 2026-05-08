(* Tests for UTXO set module *)

open Camlcoin

(* Test directory that gets cleaned up *)
let test_db_path = "/tmp/camlcoin_test_utxo_db"

let cleanup_test_db () =
  let rec rm_rf path =
    if Sys.file_exists path then begin
      if Sys.is_directory path then begin
        Array.iter (fun f -> rm_rf (Filename.concat path f)) (Sys.readdir path);
        Unix.rmdir path
      end else
        Unix.unlink path
    end
  in
  rm_rf test_db_path

(* Helper to create a test transaction output *)
let make_test_output value =
  Types.{
    value;
    script_pubkey = Cstruct.of_string "\x76\xa9\x14test_script_pubkey\x88\xac";
  }

(* Helper to create a coinbase transaction *)
let make_coinbase_tx height outputs =
  let height_script = Consensus.encode_height_in_coinbase height in
  let script_sig = Cstruct.concat [height_script; Cstruct.of_string "test_coinbase"] in
  Types.{
    version = 1l;
    inputs = [{
      previous_output = { txid = Types.zero_hash; vout = -1l };
      script_sig;
      sequence = 0xFFFFFFFFl;
    }];
    outputs;
    witnesses = [];
    locktime = 0l;
  }

(* Helper to make a test block with coinbase *)
let make_test_block height coinbase_value txs =
  let coinbase = make_coinbase_tx height [make_test_output coinbase_value] in
  let all_txs = coinbase :: txs in
  let txids = List.map Crypto.compute_txid all_txs in
  let (merkle_root, _) = Crypto.merkle_root txids in
  Types.{
    header = {
      version = 1l;
      prev_block = Types.zero_hash;
      merkle_root;
      timestamp = Int32.of_int (1231006505 + height * 600);
      bits = 0x207fffffl;  (* easy difficulty *)
      nonce = Int32.of_int height;
    };
    transactions = all_txs;
  }

(* ============================================================================
   UTXO Entry Serialization Tests
   ============================================================================ *)

let test_utxo_entry_serialization () =
  let entry = Utxo.{
    value = 5000000000L;  (* 50 BTC *)
    script_pubkey = Cstruct.of_string "\x76\xa9\x14test_pubkey_hash\x88\xac";
    height = 100;
    is_coinbase = true;
  } in
  let w = Serialize.writer_create () in
  Utxo.serialize_utxo_entry w entry;
  let data = Serialize.writer_to_cstruct w in
  let r = Serialize.reader_of_cstruct data in
  let decoded = Utxo.deserialize_utxo_entry r in
  Alcotest.(check int64) "value" entry.value decoded.value;
  Alcotest.(check int) "height" entry.height decoded.height;
  Alcotest.(check bool) "is_coinbase" entry.is_coinbase decoded.is_coinbase;
  Alcotest.(check bool) "script_pubkey equal"
    true (Cstruct.equal entry.script_pubkey decoded.script_pubkey)

let test_utxo_entry_regular () =
  let entry = Utxo.{
    value = 100000L;  (* 0.001 BTC *)
    script_pubkey = Cstruct.of_string "\x00\x14witness_program";
    height = 500000;
    is_coinbase = false;
  } in
  let w = Serialize.writer_create () in
  Utxo.serialize_utxo_entry w entry;
  let data = Serialize.writer_to_cstruct w in
  let r = Serialize.reader_of_cstruct data in
  let decoded = Utxo.deserialize_utxo_entry r in
  Alcotest.(check int64) "value" entry.value decoded.value;
  Alcotest.(check int) "height" entry.height decoded.height;
  Alcotest.(check bool) "is_coinbase" entry.is_coinbase decoded.is_coinbase

(* ============================================================================
   UTXO Set Basic Operations Tests
   ============================================================================ *)

let test_utxoset_add_get () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let utxo = Utxo.UtxoSet.create db in
  let txid = Types.hash256_of_hex
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b" in
  let entry = Utxo.{
    value = 5000000000L;
    script_pubkey = Cstruct.of_string "\x76\xa9\x14test\x88\xac";
    height = 0;
    is_coinbase = true;
  } in
  (* Add entry *)
  Utxo.UtxoSet.add utxo txid 0 entry;
  (* Get entry *)
  let retrieved = Utxo.UtxoSet.get utxo txid 0 in
  Alcotest.(check bool) "entry found" true (Option.is_some retrieved);
  let got = Option.get retrieved in
  Alcotest.(check int64) "value" entry.value got.value;
  Alcotest.(check int) "height" entry.height got.height;
  (* Check exists *)
  Alcotest.(check bool) "exists" true (Utxo.UtxoSet.exists utxo txid 0);
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_utxoset_remove () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let utxo = Utxo.UtxoSet.create db in
  let txid = Types.hash256_of_hex
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b" in
  let entry = Utxo.{
    value = 5000000000L;
    script_pubkey = Cstruct.of_string "\x76\xa9\x14test\x88\xac";
    height = 0;
    is_coinbase = true;
  } in
  Utxo.UtxoSet.add utxo txid 0 entry;
  (* Remove and verify *)
  let removed = Utxo.UtxoSet.remove utxo txid 0 in
  Alcotest.(check bool) "removed entry found" true (Option.is_some removed);
  Alcotest.(check int64) "removed value" entry.value (Option.get removed).value;
  (* Should no longer exist *)
  Alcotest.(check bool) "no longer exists" false (Utxo.UtxoSet.exists utxo txid 0);
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_utxoset_multiple_outputs () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let utxo = Utxo.UtxoSet.create db in
  let txid = Types.hash256_of_hex
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b" in
  (* Add multiple outputs for same txid *)
  for vout = 0 to 4 do
    let entry = Utxo.{
      value = Int64.of_int (vout * 100000);
      script_pubkey = Cstruct.of_string (Printf.sprintf "script_%d" vout);
      height = 100;
      is_coinbase = false;
    } in
    Utxo.UtxoSet.add utxo txid vout entry
  done;
  (* Verify all outputs *)
  for vout = 0 to 4 do
    let got = Utxo.UtxoSet.get utxo txid vout in
    Alcotest.(check bool) (Printf.sprintf "vout %d exists" vout) true (Option.is_some got);
    Alcotest.(check int64) (Printf.sprintf "vout %d value" vout)
      (Int64.of_int (vout * 100000)) (Option.get got).value
  done;
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_utxoset_cache_stats () =
  (* The UtxoSet.get implementation delegates all reads directly to RocksDB
     to avoid unbounded GC heap growth from an OCaml-side Hashtbl cache.
     As a result cache_hits and cache_misses are always 0; only add/remove
     touch the write-side Hashtbl.  This test verifies that clear_cache
     resets the stats to (0, 0) and that subsequent gets return correct data. *)
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let utxo = Utxo.UtxoSet.create db in
  let txid = Types.hash256_of_hex
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b" in
  let entry = Utxo.{
    value = 100000L;
    script_pubkey = Cstruct.of_string "test";
    height = 0;
    is_coinbase = false;
  } in
  Utxo.UtxoSet.add utxo txid 0 entry;
  ignore (Utxo.UtxoSet.get utxo txid 0);
  Utxo.UtxoSet.clear_cache utxo;
  (* get goes directly to RocksDB — no in-process cache stats are updated *)
  ignore (Utxo.UtxoSet.get utxo txid 0);
  let (hits, misses) = Utxo.UtxoSet.cache_stats utxo in
  Alcotest.(check int) "cache hits after clear" 0 hits;
  Alcotest.(check int) "cache misses after clear" 0 misses;
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* ============================================================================
   Undo Data Serialization Tests
   ============================================================================ *)

let test_undo_data_serialization () =
  let txid1 = Types.hash256_of_hex
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b" in
  let txid2 = Types.hash256_of_hex
    "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098" in
  let undo = Utxo.{
    height = 100;
    tx_undos = [
      { spent_outputs = [
          ({ Types.txid = txid1; vout = 0l },
           { value = 5000000000L;
             script_pubkey = Cstruct.of_string "script1";
             height = 50;
             is_coinbase = true });
          ({ Types.txid = txid2; vout = 1l },
           { value = 100000L;
             script_pubkey = Cstruct.of_string "script2";
             height = 75;
             is_coinbase = false });
        ] };
    ];
  } in
  let w = Serialize.writer_create () in
  Utxo.serialize_undo_data w undo;
  let data = Serialize.writer_to_cstruct w in
  let r = Serialize.reader_of_cstruct data in
  let decoded = Utxo.deserialize_undo_data r in
  Alcotest.(check int) "height" undo.height decoded.height;
  Alcotest.(check int) "tx_undo count" 1 (List.length decoded.tx_undos);
  let all_spent = List.concat_map (fun (tu : Utxo.tx_undo) -> tu.spent_outputs) decoded.tx_undos in
  Alcotest.(check int) "spent count" 2 (List.length all_spent);
  let (op1, e1) = List.hd all_spent in
  Alcotest.(check int64) "first entry value" 5000000000L e1.value;
  Alcotest.(check bool) "first entry is_coinbase" true e1.is_coinbase;
  Alcotest.(check int32) "first outpoint vout" 0l op1.Types.vout

(* ============================================================================
   Block Connection Tests
   ============================================================================

   The legacy [Utxo.connect_block] / [Utxo.disconnect_block] (UtxoSet.t-based)
   helpers were dead code (wave-33b ledger) and had a genesis-coinbase bug
   that diverged from Bitcoin Core. They were deleted in W25 (2026-05-07)
   along with all six [connect_block_*] Alcotest cases that exercised them
   (including the bug-pinning [test_connect_coinbase_only_block]).

   The W24 [test_connect_block_optimized_genesis_noop] below covers the
   genesis-no-op contract on the live optimized path. *)

(* W24 defense-in-depth: connect_block_optimized must short-circuit on the
   genesis block (height = 0) without mutating UTXO state. Mirrors Bitcoin
   Core's validation.cpp:2337-2343 special-case. Three caller-side guards
   already prevent height=0 from reaching the function in normal IBD/mining
   flow, but a future caller skipping them must not silently insert the
   genesis coinbase into the UTXO set. *)
let test_connect_block_optimized_genesis_noop () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let utxo = Utxo.OptimizedUtxoSet.create db in
  (* Plant a sentinel UTXO so we can prove no mutation occurs. *)
  let sentinel_txid = Types.hash256_of_hex
    "deadbeefcafebabe0123456789abcdef0123456789abcdefdeadbeefcafebabe" in
  let sentinel_entry = Utxo.{
    value = 42_000L;
    script_pubkey = Cstruct.of_string "\x76\xa9\x14sentinel\x88\xac";
    height = 7;
    is_coinbase = false;
  } in
  Utxo.OptimizedUtxoSet.add utxo sentinel_txid 0 sentinel_entry;
  Alcotest.(check bool) "sentinel present pre-call" true
    (Option.is_some (Utxo.OptimizedUtxoSet.get utxo sentinel_txid 0));
  (* Construct a fake genesis block with a coinbase paying the subsidy. *)
  let subsidy = Consensus.block_subsidy 0 in
  let genesis_block = make_test_block 0 subsidy [] in
  let coinbase_txid =
    Crypto.compute_txid (List.hd genesis_block.transactions) in
  (* Call connect_block_optimized directly with height=0. *)
  let result = Utxo.connect_block_optimized utxo genesis_block 0 in
  Alcotest.(check bool) "genesis returns Ok" true (Result.is_ok result);
  let undo = Result.get_ok result in
  Alcotest.(check int) "undo height = 0" 0 undo.height;
  Alcotest.(check int) "undo tx_undos empty" 0 (List.length undo.tx_undos);
  (* Genesis coinbase MUST NOT be in the UTXO set. *)
  Alcotest.(check bool) "genesis coinbase NOT in UTXO" false
    (Option.is_some (Utxo.OptimizedUtxoSet.get utxo coinbase_txid 0));
  (* Sentinel must be unchanged (proves no add and no remove happened). *)
  let after = Utxo.OptimizedUtxoSet.get utxo sentinel_txid 0 in
  Alcotest.(check bool) "sentinel still present" true (Option.is_some after);
  let after_entry = Option.get after in
  Alcotest.(check int64) "sentinel value unchanged"
    sentinel_entry.value after_entry.value;
  Alcotest.(check int) "sentinel height unchanged"
    sentinel_entry.height after_entry.height;
  Alcotest.(check bool) "sentinel is_coinbase unchanged"
    sentinel_entry.is_coinbase after_entry.is_coinbase;
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* ============================================================================
   Block Disconnection Tests — DELETED in W25 (2026-05-07).

   The legacy [Utxo.disconnect_block] (UtxoSet.t-based) was dead code with
   no production callers; live reorg disconnect lives in the layered UTXO
   cache. Tests that exercised it were removed alongside the function.
   ============================================================================ *)

(* ============================================================================
   Undo Data Storage Tests
   ============================================================================ *)

let test_undo_data_storage () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let block_hash = Types.hash256_of_hex
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f" in
  let txid = Types.hash256_of_hex
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b" in
  let undo = Utxo.{
    height = 1;
    tx_undos = [
      { spent_outputs = [
          ({ Types.txid; vout = 0l },
           { value = 5000000000L;
             script_pubkey = Cstruct.of_string "test";
             height = 0;
             is_coinbase = true });
        ] };
    ];
  } in
  (* Serialize and store *)
  let w = Serialize.writer_create () in
  Utxo.serialize_undo_data w undo;
  let undo_bytes = Cstruct.to_string (Serialize.writer_to_cstruct w) in
  Storage.ChainDB.store_undo_data db block_hash undo_bytes;
  (* Retrieve and deserialize *)
  let retrieved = Storage.ChainDB.get_undo_data db block_hash in
  Alcotest.(check bool) "undo data found" true (Option.is_some retrieved);
  let r = Serialize.reader_of_cstruct (Cstruct.of_string (Option.get retrieved)) in
  let decoded = Utxo.deserialize_undo_data r in
  Alcotest.(check int) "undo height" 1 decoded.height;
  let all_spent = List.concat_map (fun (tu : Utxo.tx_undo) -> tu.spent_outputs) decoded.tx_undos in
  Alcotest.(check int) "spent count" 1 (List.length all_spent);
  (* Delete *)
  Storage.ChainDB.delete_undo_data db block_hash;
  let deleted = Storage.ChainDB.get_undo_data db block_hash in
  Alcotest.(check bool) "undo data deleted" true (Option.is_none deleted);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* ============================================================================
   UTXO Statistics Tests
   ============================================================================ *)

let test_utxo_stats () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let utxo = Utxo.UtxoSet.create db in
  (* Add some UTXOs *)
  let txid1 = Types.hash256_of_hex
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b" in
  let txid2 = Types.hash256_of_hex
    "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098" in
  Utxo.UtxoSet.add utxo txid1 0 Utxo.{
    value = 5000000000L;
    script_pubkey = Cstruct.of_string "test1";
    height = 0;
    is_coinbase = true;
  };
  Utxo.UtxoSet.add utxo txid2 0 Utxo.{
    value = 100000L;
    script_pubkey = Cstruct.of_string "test2";
    height = 1;
    is_coinbase = false;
  };
  Utxo.UtxoSet.add utxo txid2 1 Utxo.{
    value = 200000L;
    script_pubkey = Cstruct.of_string "test3";
    height = 1;
    is_coinbase = false;
  };
  let stats = Utxo.compute_stats utxo in
  Alcotest.(check int) "total count" 3 stats.total_count;
  Alcotest.(check int64) "total value" 5000300000L stats.total_value;
  Alcotest.(check int) "coinbase count" 1 stats.coinbase_count;
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* ============================================================================
   Layered UTXO Cache Tests
   ============================================================================ *)

(* Helper to create a coin for testing *)
let make_test_coin value height is_coinbase =
  Utxo.{
    txout = {
      Types.value;
      script_pubkey = Cstruct.of_string "\x76\xa9\x14test_script\x88\xac";
    };
    height;
    is_coinbase;
  }

(* Helper to create an outpoint for testing *)
let make_test_outpoint txid_hex vout =
  Types.{
    txid = Types.hash256_of_hex txid_hex;
    vout = Int32.of_int vout;
  }

let test_utxo_cache_add_get () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let db_view = Utxo.DbView.create db in
  let cache = Utxo.UtxoCache.create db_view in
  let outpoint = make_test_outpoint
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b" 0 in
  let coin = make_test_coin 5000000000L 0 true in
  (* Add coin *)
  Utxo.UtxoCache.add_coin cache outpoint coin ~possible_overwrite:false;
  (* Get coin - should be cache hit *)
  let retrieved = Utxo.UtxoCache.get_coin cache outpoint in
  Alcotest.(check bool) "coin found" true (Option.is_some retrieved);
  let got = Option.get retrieved in
  Alcotest.(check int64) "value matches" coin.txout.value got.txout.value;
  Alcotest.(check int) "height matches" coin.height got.height;
  Alcotest.(check bool) "is_coinbase matches" coin.is_coinbase got.is_coinbase;
  (* Check stats *)
  let stats = Utxo.UtxoCache.get_stats cache in
  Alcotest.(check int) "cache hits" 1 stats.hits;
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_utxo_cache_miss_then_hit () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let db_view = Utxo.DbView.create db in
  let cache = Utxo.UtxoCache.create db_view in
  let outpoint = make_test_outpoint
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b" 0 in
  (* First lookup - should miss (not in cache or db) *)
  let result1 = Utxo.UtxoCache.get_coin cache outpoint in
  Alcotest.(check bool) "first lookup misses" true (Option.is_none result1);
  let stats = Utxo.UtxoCache.get_stats cache in
  Alcotest.(check int) "misses after first lookup" 1 stats.misses;
  (* Add directly to DB via db_view *)
  let coin = make_test_coin 100000L 50 false in
  Utxo.DbView.add_coin db_view outpoint coin ~possible_overwrite:false;
  (* Create fresh cache (simulates restart) *)
  let cache2 = Utxo.UtxoCache.create db_view in
  (* Lookup should hit DB, then cache *)
  let result2 = Utxo.UtxoCache.get_coin cache2 outpoint in
  Alcotest.(check bool) "db lookup succeeds" true (Option.is_some result2);
  let stats2 = Utxo.UtxoCache.get_stats cache2 in
  Alcotest.(check int) "misses (fetched from db)" 1 stats2.misses;
  (* Second lookup should hit cache *)
  let result3 = Utxo.UtxoCache.get_coin cache2 outpoint in
  Alcotest.(check bool) "cache lookup succeeds" true (Option.is_some result3);
  let stats3 = Utxo.UtxoCache.get_stats cache2 in
  Alcotest.(check int) "hits after cache fetch" 1 stats3.hits;
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_utxo_cache_spend () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let db_view = Utxo.DbView.create db in
  let cache = Utxo.UtxoCache.create db_view in
  let outpoint = make_test_outpoint
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b" 0 in
  let coin = make_test_coin 5000000000L 0 true in
  (* Add coin *)
  Utxo.UtxoCache.add_coin cache outpoint coin ~possible_overwrite:false;
  Alcotest.(check bool) "coin exists before spend" true
    (Utxo.UtxoCache.have_coin cache outpoint);
  (* Spend coin *)
  let spent = Utxo.UtxoCache.spend_coin cache outpoint in
  Alcotest.(check bool) "spend returns coin" true (Option.is_some spent);
  Alcotest.(check int64) "spent coin value" coin.txout.value
    (Option.get spent).txout.value;
  (* Coin should no longer exist *)
  Alcotest.(check bool) "coin gone after spend" false
    (Utxo.UtxoCache.have_coin cache outpoint);
  (* Spending again should return None *)
  let spent2 = Utxo.UtxoCache.spend_coin cache outpoint in
  Alcotest.(check bool) "second spend returns none" true (Option.is_none spent2);
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_utxo_cache_flush () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let db_view = Utxo.DbView.create db in
  let cache = Utxo.UtxoCache.create db_view in
  let outpoint1 = make_test_outpoint
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b" 0 in
  let outpoint2 = make_test_outpoint
    "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098" 0 in
  let coin1 = make_test_coin 5000000000L 0 true in
  let coin2 = make_test_coin 100000L 1 false in
  (* Add coins to cache *)
  Utxo.UtxoCache.add_coin cache outpoint1 coin1 ~possible_overwrite:false;
  Utxo.UtxoCache.add_coin cache outpoint2 coin2 ~possible_overwrite:false;
  Alcotest.(check int) "entry count before flush" 2 (Utxo.UtxoCache.entry_count cache);
  (* Flush to disk *)
  let flushed = Lwt_main.run (Utxo.UtxoCache.flush cache) in
  Alcotest.(check int) "flushed count" 2 flushed;
  Alcotest.(check int) "entry count after flush" 0 (Utxo.UtxoCache.entry_count cache);
  (* Create fresh cache and verify coins are in db *)
  let cache2 = Utxo.UtxoCache.create db_view in
  Alcotest.(check bool) "coin1 in db" true (Utxo.UtxoCache.have_coin cache2 outpoint1);
  Alcotest.(check bool) "coin2 in db" true (Utxo.UtxoCache.have_coin cache2 outpoint2);
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_utxo_cache_flush_erased () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let db_view = Utxo.DbView.create db in
  let outpoint = make_test_outpoint
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b" 0 in
  let coin = make_test_coin 5000000000L 0 true in
  (* Add coin directly to DB *)
  Utxo.DbView.add_coin db_view outpoint coin ~possible_overwrite:false;
  (* Create cache, verify coin exists *)
  let cache = Utxo.UtxoCache.create db_view in
  Alcotest.(check bool) "coin exists in db" true (Utxo.UtxoCache.have_coin cache outpoint);
  (* Spend the coin (should mark as Erased since it's from DB) *)
  let _ = Utxo.UtxoCache.spend_coin cache outpoint in
  Alcotest.(check bool) "coin gone after spend" false (Utxo.UtxoCache.have_coin cache outpoint);
  let stats = Utxo.UtxoCache.get_stats cache in
  Alcotest.(check int) "erased count" 1 stats.erased_count;
  (* Flush should propagate deletion to DB *)
  let _ = Lwt_main.run (Utxo.UtxoCache.flush cache) in
  (* Create fresh cache - coin should be gone from DB too *)
  let cache2 = Utxo.UtxoCache.create db_view in
  Alcotest.(check bool) "coin deleted from db" false (Utxo.UtxoCache.have_coin cache2 outpoint);
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_utxo_cache_add_spend_roundtrip () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let db_view = Utxo.DbView.create db in
  let cache = Utxo.UtxoCache.create db_view in
  (* Simulate a transaction: add outputs, spend inputs *)
  let input_outpoint = make_test_outpoint
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b" 0 in
  let output_outpoint1 = make_test_outpoint
    "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098" 0 in
  let output_outpoint2 = make_test_outpoint
    "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098" 1 in
  let input_coin = make_test_coin 5000000000L 0 true in
  let output_coin1 = make_test_coin 2500000000L 1 false in
  let output_coin2 = make_test_coin 2499900000L 1 false in  (* 100000 sat fee *)
  (* Add input UTXO (simulates previous block's output) *)
  Utxo.UtxoCache.add_coin cache input_outpoint input_coin ~possible_overwrite:false;
  (* Process transaction: spend input, add outputs *)
  let spent = Utxo.UtxoCache.spend_coin cache input_outpoint in
  Alcotest.(check bool) "input spent" true (Option.is_some spent);
  Utxo.UtxoCache.add_coin cache output_outpoint1 output_coin1 ~possible_overwrite:false;
  Utxo.UtxoCache.add_coin cache output_outpoint2 output_coin2 ~possible_overwrite:false;
  (* Verify final state *)
  Alcotest.(check bool) "input gone" false (Utxo.UtxoCache.have_coin cache input_outpoint);
  Alcotest.(check bool) "output1 exists" true (Utxo.UtxoCache.have_coin cache output_outpoint1);
  Alcotest.(check bool) "output2 exists" true (Utxo.UtxoCache.have_coin cache output_outpoint2);
  (* Flush and verify persistence *)
  let _ = Lwt_main.run (Utxo.UtxoCache.flush cache) in
  let cache2 = Utxo.UtxoCache.create db_view in
  Alcotest.(check bool) "input still gone" false (Utxo.UtxoCache.have_coin cache2 input_outpoint);
  Alcotest.(check bool) "output1 persisted" true (Utxo.UtxoCache.have_coin cache2 output_outpoint1);
  Alcotest.(check bool) "output2 persisted" true (Utxo.UtxoCache.have_coin cache2 output_outpoint2);
  (* Verify values *)
  let got1 = Option.get (Utxo.UtxoCache.get_coin cache2 output_outpoint1) in
  let got2 = Option.get (Utxo.UtxoCache.get_coin cache2 output_outpoint2) in
  Alcotest.(check int64) "output1 value" output_coin1.txout.value got1.txout.value;
  Alcotest.(check int64) "output2 value" output_coin2.txout.value got2.txout.value;
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_utxo_cache_memory_tracking () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let db_view = Utxo.DbView.create db in
  (* Use small max_size to trigger flush threshold.
     Each coin is ~77 bytes (tag + overhead + value + script + height + bool).
     Use 500 bytes threshold so 10 coins (770 bytes) will exceed it. *)
  let cache = Utxo.UtxoCache.create ~max_size:500 db_view in
  Alcotest.(check int) "initial memory" 0 (Utxo.UtxoCache.memory_usage cache);
  (* Add some coins *)
  for i = 0 to 9 do
    let outpoint = make_test_outpoint
      (Printf.sprintf "%064x" i) 0 in
    let coin = make_test_coin (Int64.of_int (i * 100000)) i false in
    Utxo.UtxoCache.add_coin cache outpoint coin ~possible_overwrite:false
  done;
  let mem = Utxo.UtxoCache.memory_usage cache in
  Alcotest.(check bool) "memory > 0 after adds" true (mem > 0);
  Alcotest.(check bool) "memory > threshold" true (mem > 500);
  (* Check needs_flush with small threshold *)
  Alcotest.(check bool) "needs_flush with small threshold" true
    (Utxo.UtxoCache.needs_flush cache);
  (* maybe_flush should flush when needed *)
  let flushed = Lwt_main.run (Utxo.UtxoCache.maybe_flush cache) in
  Alcotest.(check int) "flushed 10 entries" 10 flushed;
  Alcotest.(check int) "memory reset after flush" 0 (Utxo.UtxoCache.memory_usage cache);
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_utxo_cache_hit_rate () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let db_view = Utxo.DbView.create db in
  let cache = Utxo.UtxoCache.create db_view in
  (* Add some coins *)
  for i = 0 to 4 do
    let outpoint = make_test_outpoint
      (Printf.sprintf "%064x" i) 0 in
    let coin = make_test_coin (Int64.of_int (i * 100000)) i false in
    Utxo.UtxoCache.add_coin cache outpoint coin ~possible_overwrite:false
  done;
  (* All lookups should be hits *)
  for i = 0 to 4 do
    let outpoint = make_test_outpoint
      (Printf.sprintf "%064x" i) 0 in
    let _ = Utxo.UtxoCache.get_coin cache outpoint in
    ()
  done;
  (* One miss for non-existent entry *)
  let missing = make_test_outpoint
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" 99 in
  let _ = Utxo.UtxoCache.get_coin cache missing in
  let hit_rate = Utxo.UtxoCache.hit_rate cache in
  (* 5 hits / 6 total = 0.833... *)
  Alcotest.(check bool) "hit rate > 0.8" true (hit_rate > 0.8);
  Alcotest.(check bool) "hit rate < 0.9" true (hit_rate < 0.9);
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_coin_conversion () =
  let entry = Utxo.{
    value = 5000000000L;
    script_pubkey = Cstruct.of_string "\x76\xa9\x14test\x88\xac";
    height = 100;
    is_coinbase = true;
  } in
  let coin = Utxo.coin_of_utxo_entry entry in
  Alcotest.(check int64) "coin value" entry.value coin.txout.value;
  Alcotest.(check int) "coin height" entry.height coin.height;
  Alcotest.(check bool) "coin is_coinbase" entry.is_coinbase coin.is_coinbase;
  let entry2 = Utxo.utxo_entry_of_coin coin in
  Alcotest.(check int64) "roundtrip value" entry.value entry2.value;
  Alcotest.(check int) "roundtrip height" entry.height entry2.height;
  Alcotest.(check bool) "roundtrip is_coinbase" entry.is_coinbase entry2.is_coinbase

(* ============================================================================
   Test Runner
   ============================================================================ *)

let () =
  cleanup_test_db ();
  let open Alcotest in
  run "Utxo" [
    "serialization", [
      test_case "utxo_entry round-trip" `Quick test_utxo_entry_serialization;
      test_case "utxo_entry regular" `Quick test_utxo_entry_regular;
      test_case "undo_data round-trip" `Quick test_undo_data_serialization;
    ];
    "utxo_set", [
      test_case "add and get" `Quick test_utxoset_add_get;
      test_case "remove" `Quick test_utxoset_remove;
      test_case "multiple outputs" `Quick test_utxoset_multiple_outputs;
      test_case "cache stats" `Quick test_utxoset_cache_stats;
    ];
    "connect_block", [
      test_case "optimized genesis no-op (W24)" `Quick test_connect_block_optimized_genesis_noop;
    ];
    "storage", [
      test_case "undo data storage" `Quick test_undo_data_storage;
    ];
    "stats", [
      test_case "utxo statistics" `Quick test_utxo_stats;
    ];
    "utxo_cache", [
      test_case "add and get" `Quick test_utxo_cache_add_get;
      test_case "miss then hit" `Quick test_utxo_cache_miss_then_hit;
      test_case "spend" `Quick test_utxo_cache_spend;
      test_case "flush" `Quick test_utxo_cache_flush;
      test_case "flush erased" `Quick test_utxo_cache_flush_erased;
      test_case "add/spend roundtrip" `Quick test_utxo_cache_add_spend_roundtrip;
      test_case "memory tracking" `Quick test_utxo_cache_memory_tracking;
      test_case "hit rate" `Quick test_utxo_cache_hit_rate;
      test_case "coin conversion" `Quick test_coin_conversion;
    ];
  ]
