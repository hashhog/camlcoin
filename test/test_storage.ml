(* Tests for storage module *)

open Camlcoin

(* Test directory that gets cleaned up *)
let test_db_path = "/tmp/camlcoin_test_db"

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

(* Helper to create a test block header *)
let make_test_header ~ver ~ts ~nc =
  Types.{
    version = ver;
    prev_block = Types.zero_hash;
    merkle_root = Types.zero_hash;
    timestamp = ts;
    bits = 0x1d00ffffl;
    nonce = nc;
  }

(* Helper to create a test block *)
let make_test_block ~ver ~ts ~nc =
  let header = make_test_header ~ver ~ts ~nc in
  Types.{ header; transactions = [] }

(* Test FileStorage basic operations *)
let test_file_storage_basic () =
  cleanup_test_db ();
  let db = Storage.FileStorage.open_db test_db_path in
  (* Test put and get *)
  Storage.FileStorage.put db "key1" "value1";
  let v = Storage.FileStorage.get db "key1" in
  Alcotest.(check (option string)) "get returns put value" (Some "value1") v;
  (* Test missing key *)
  let missing = Storage.FileStorage.get db "nonexistent" in
  Alcotest.(check (option string)) "missing key returns None" None missing;
  (* Test delete *)
  Storage.FileStorage.delete db "key1";
  let deleted = Storage.FileStorage.get db "key1" in
  Alcotest.(check (option string)) "deleted key returns None" None deleted;
  Storage.FileStorage.close db;
  cleanup_test_db ()

(* Test FileStorage batch operations *)
let test_file_storage_batch () =
  cleanup_test_db ();
  let db = Storage.FileStorage.open_db test_db_path in
  let batch = Storage.FileStorage.batch_create () in
  Storage.FileStorage.batch_put batch "key1" "value1";
  Storage.FileStorage.batch_put batch "key2" "value2";
  Storage.FileStorage.batch_put batch "key3" "value3";
  Storage.FileStorage.batch_write db batch;
  (* Verify all keys were written *)
  Alcotest.(check (option string)) "batch key1" (Some "value1")
    (Storage.FileStorage.get db "key1");
  Alcotest.(check (option string)) "batch key2" (Some "value2")
    (Storage.FileStorage.get db "key2");
  Alcotest.(check (option string)) "batch key3" (Some "value3")
    (Storage.FileStorage.get db "key3");
  (* Test batch delete *)
  let batch2 = Storage.FileStorage.batch_create () in
  Storage.FileStorage.batch_delete batch2 "key2";
  Storage.FileStorage.batch_write db batch2;
  Alcotest.(check (option string)) "batch delete key2" None
    (Storage.FileStorage.get db "key2");
  Storage.FileStorage.close db;
  cleanup_test_db ()

(* Test FileStorage iter_prefix *)
let test_file_storage_iter_prefix () =
  cleanup_test_db ();
  let db = Storage.FileStorage.open_db test_db_path in
  Storage.FileStorage.put db "prefix_a" "val_a";
  Storage.FileStorage.put db "prefix_b" "val_b";
  Storage.FileStorage.put db "other_c" "val_c";
  let found = ref [] in
  Storage.FileStorage.iter_prefix db "prefix_" (fun k v ->
    found := (k, v) :: !found
  );
  Alcotest.(check int) "iter_prefix count" 2 (List.length !found);
  Storage.FileStorage.close db;
  cleanup_test_db ()

(* Test ChainDB block header storage *)
let test_chaindb_block_header () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let header = make_test_header ~ver:1l ~ts:1231006505l ~nc:2083236893l in
  let hash = Crypto.compute_block_hash header in
  Storage.ChainDB.store_block_header db hash header;
  let retrieved = Storage.ChainDB.get_block_header db hash in
  Alcotest.(check bool) "header retrieved" true (Option.is_some retrieved);
  let h = Option.get retrieved in
  Alcotest.(check int32) "header version" 1l h.version;
  Alcotest.(check int32) "header timestamp" 1231006505l h.timestamp;
  Alcotest.(check int32) "header nonce" 2083236893l h.nonce;
  (* Test missing header *)
  let fake_hash = Types.hash256_of_hex
    "0000000000000000000000000000000000000000000000000000000000000001" in
  let missing = Storage.ChainDB.get_block_header db fake_hash in
  Alcotest.(check bool) "missing header" true (Option.is_none missing);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test ChainDB full block storage *)
let test_chaindb_block () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let block = make_test_block ~ver:1l ~ts:1231006505l ~nc:2083236893l in
  let hash = Crypto.compute_block_hash block.header in
  Storage.ChainDB.store_block db hash block;
  let retrieved = Storage.ChainDB.get_block db hash in
  Alcotest.(check bool) "block retrieved" true (Option.is_some retrieved);
  let b = Option.get retrieved in
  Alcotest.(check int32) "block version" 1l b.header.version;
  Alcotest.(check int) "block tx count" 0 (List.length b.transactions);
  (* Test has_block *)
  Alcotest.(check bool) "has_block true" true (Storage.ChainDB.has_block db hash);
  let fake_hash = Types.hash256_of_hex
    "0000000000000000000000000000000000000000000000000000000000000001" in
  Alcotest.(check bool) "has_block false" false (Storage.ChainDB.has_block db fake_hash);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test ChainDB height to hash mapping *)
let test_chaindb_height_hash () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let hash0 = Types.hash256_of_hex
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f" in
  let hash1 = Types.hash256_of_hex
    "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048" in
  Storage.ChainDB.set_height_hash db 0 hash0;
  Storage.ChainDB.set_height_hash db 1 hash1;
  let retrieved0 = Storage.ChainDB.get_hash_at_height db 0 in
  let retrieved1 = Storage.ChainDB.get_hash_at_height db 1 in
  Alcotest.(check bool) "height 0 found" true (Option.is_some retrieved0);
  Alcotest.(check bool) "height 1 found" true (Option.is_some retrieved1);
  Alcotest.(check string) "height 0 hash"
    (Types.hash256_to_hex hash0)
    (Types.hash256_to_hex (Option.get retrieved0));
  Alcotest.(check string) "height 1 hash"
    (Types.hash256_to_hex hash1)
    (Types.hash256_to_hex (Option.get retrieved1));
  (* Test missing height *)
  let missing = Storage.ChainDB.get_hash_at_height db 999 in
  Alcotest.(check bool) "missing height" true (Option.is_none missing);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test ChainDB UTXO operations *)
let test_chaindb_utxo () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let txid = Types.hash256_of_hex
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b" in
  let utxo_data = "test_utxo_output_data" in
  (* Store UTXO *)
  Storage.ChainDB.store_utxo db txid 0 utxo_data;
  Storage.ChainDB.store_utxo db txid 1 "second_output";
  (* Retrieve UTXO *)
  let retrieved0 = Storage.ChainDB.get_utxo db txid 0 in
  let retrieved1 = Storage.ChainDB.get_utxo db txid 1 in
  Alcotest.(check (option string)) "utxo 0" (Some utxo_data) retrieved0;
  Alcotest.(check (option string)) "utxo 1" (Some "second_output") retrieved1;
  (* Delete UTXO *)
  Storage.ChainDB.delete_utxo db txid 0;
  let deleted = Storage.ChainDB.get_utxo db txid 0 in
  Alcotest.(check (option string)) "deleted utxo" None deleted;
  (* Other output still exists *)
  let still_there = Storage.ChainDB.get_utxo db txid 1 in
  Alcotest.(check (option string)) "other utxo still exists" (Some "second_output") still_there;
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test ChainDB chain tip *)
let test_chaindb_chain_tip () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  (* Initially no tip *)
  let initial = Storage.ChainDB.get_chain_tip db in
  Alcotest.(check bool) "no initial tip" true (Option.is_none initial);
  (* Set tip *)
  let hash = Types.hash256_of_hex
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f" in
  Storage.ChainDB.set_chain_tip db hash 0;
  let tip0 = Storage.ChainDB.get_chain_tip db in
  Alcotest.(check bool) "tip 0 found" true (Option.is_some tip0);
  let (tip_hash, tip_height) = Option.get tip0 in
  Alcotest.(check int) "tip height 0" 0 tip_height;
  Alcotest.(check string) "tip hash 0"
    (Types.hash256_to_hex hash)
    (Types.hash256_to_hex tip_hash);
  (* Update tip *)
  let hash2 = Types.hash256_of_hex
    "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048" in
  Storage.ChainDB.set_chain_tip db hash2 1;
  let tip1 = Storage.ChainDB.get_chain_tip db in
  let (tip_hash1, tip_height1) = Option.get tip1 in
  Alcotest.(check int) "tip height 1" 1 tip_height1;
  Alcotest.(check string) "tip hash 1"
    (Types.hash256_to_hex hash2)
    (Types.hash256_to_hex tip_hash1);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test ChainDB transaction index *)
let test_chaindb_tx_index () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let txid = Types.hash256_of_hex
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b" in
  let block_hash = Types.hash256_of_hex
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f" in
  Storage.ChainDB.store_tx_index db txid block_hash 0;
  let retrieved = Storage.ChainDB.get_tx_index db txid in
  Alcotest.(check bool) "tx index found" true (Option.is_some retrieved);
  let (blk_hash, tx_idx) = Option.get retrieved in
  Alcotest.(check int) "tx index value" 0 tx_idx;
  Alcotest.(check string) "tx block hash"
    (Types.hash256_to_hex block_hash)
    (Types.hash256_to_hex blk_hash);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test ChainDB batch operations *)
let test_chaindb_batch () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let batch = Storage.ChainDB.batch_create () in
  let txid1 = Types.hash256_of_hex
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b" in
  let txid2 = Types.hash256_of_hex
    "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098" in
  let tip_hash = Types.hash256_of_hex
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f" in
  Storage.ChainDB.batch_store_utxo batch txid1 0 "utxo1";
  Storage.ChainDB.batch_store_utxo batch txid2 0 "utxo2";
  Storage.ChainDB.batch_set_chain_tip batch tip_hash 100;
  Storage.ChainDB.batch_write db batch;
  (* Verify batch wrote everything *)
  Alcotest.(check (option string)) "batch utxo1" (Some "utxo1")
    (Storage.ChainDB.get_utxo db txid1 0);
  Alcotest.(check (option string)) "batch utxo2" (Some "utxo2")
    (Storage.ChainDB.get_utxo db txid2 0);
  let tip = Storage.ChainDB.get_chain_tip db in
  let (_, height) = Option.get tip in
  Alcotest.(check int) "batch tip height" 100 height;
  (* Test batch delete *)
  let batch2 = Storage.ChainDB.batch_create () in
  Storage.ChainDB.batch_delete_utxo batch2 txid1 0;
  Storage.ChainDB.batch_write db batch2;
  Alcotest.(check (option string)) "batch deleted utxo1" None
    (Storage.ChainDB.get_utxo db txid1 0);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test height encoding sorts correctly *)
let test_height_encoding_order () =
  (* Heights encoded as big-endian should sort lexicographically *)
  let encode h =
    let cs = Cstruct.create 4 in
    Cstruct.BE.set_uint32 cs 0 (Int32.of_int h);
    Cstruct.to_string cs
  in
  let h0 = encode 0 in
  let h1 = encode 1 in
  let h255 = encode 255 in
  let h256 = encode 256 in
  let h1000 = encode 1000 in
  Alcotest.(check bool) "0 < 1" true (h0 < h1);
  Alcotest.(check bool) "1 < 255" true (h1 < h255);
  Alcotest.(check bool) "255 < 256" true (h255 < h256);
  Alcotest.(check bool) "256 < 1000" true (h256 < h1000)

(* ============================================================================
   Undo Data Tests
   ============================================================================ *)

(* Test tx_in_undo serialization roundtrip *)
let test_tx_in_undo_roundtrip () =
  let script = Cstruct.of_string "\x76\xa9\x14\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x88\xac" in
  let u : Storage.tx_in_undo = {
    value = 5000000000L;
    script_pubkey = script;
    height = 100;
    is_coinbase = true;
  } in
  let w = Serialize.writer_create () in
  Storage.serialize_tx_in_undo w u;
  let data = Serialize.writer_to_cstruct w in
  let r = Serialize.reader_of_cstruct data in
  let u2 = Storage.deserialize_tx_in_undo r in
  Alcotest.(check int64) "value" u.value u2.value;
  Alcotest.(check bool) "script_pubkey" true (Cstruct.equal u.script_pubkey u2.script_pubkey);
  Alcotest.(check int) "height" u.height u2.height;
  Alcotest.(check bool) "is_coinbase" u.is_coinbase u2.is_coinbase

(* Test tx_undo serialization roundtrip *)
let test_tx_undo_roundtrip () =
  let script1 = Cstruct.of_string "\x76\xa9\x14\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x88\xac" in
  let script2 = Cstruct.of_string "\xa9\x14\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x87" in
  let u : Storage.tx_undo = {
    prev_outputs = [
      { value = 1000000L; script_pubkey = script1; height = 50; is_coinbase = false };
      { value = 2000000L; script_pubkey = script2; height = 75; is_coinbase = true };
    ]
  } in
  let w = Serialize.writer_create () in
  Storage.serialize_tx_undo w u;
  let data = Serialize.writer_to_cstruct w in
  let r = Serialize.reader_of_cstruct data in
  let u2 = Storage.deserialize_tx_undo r in
  Alcotest.(check int) "prev_outputs count" (List.length u.prev_outputs) (List.length u2.prev_outputs);
  let o1 = List.nth u.prev_outputs 0 in
  let o1' = List.nth u2.prev_outputs 0 in
  Alcotest.(check int64) "first output value" o1.value o1'.value;
  let o2 = List.nth u.prev_outputs 1 in
  let o2' = List.nth u2.prev_outputs 1 in
  Alcotest.(check bool) "second output is_coinbase" o2.is_coinbase o2'.is_coinbase

(* Test block_undo serialization roundtrip with checksum *)
let test_block_undo_roundtrip () =
  let script = Cstruct.of_string "\x76\xa9\x14\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x88\xac" in
  let u : Storage.block_undo = {
    tx_undos = [
      { prev_outputs = [
          { value = 1000000L; script_pubkey = script; height = 50; is_coinbase = false }
        ] };
      { prev_outputs = [
          { value = 2000000L; script_pubkey = script; height = 60; is_coinbase = false };
          { value = 3000000L; script_pubkey = script; height = 70; is_coinbase = true };
        ] };
    ]
  } in
  let w = Serialize.writer_create () in
  Storage.serialize_block_undo w u;
  let data = Serialize.writer_to_cstruct w in
  let r = Serialize.reader_of_cstruct data in
  let u2 = Storage.deserialize_block_undo r in
  Alcotest.(check int) "tx_undos count" (List.length u.tx_undos) (List.length u2.tx_undos);
  let tx1 = List.nth u.tx_undos 0 in
  let tx1' = List.nth u2.tx_undos 0 in
  Alcotest.(check int) "tx1 prev_outputs count"
    (List.length tx1.prev_outputs) (List.length tx1'.prev_outputs);
  let tx2 = List.nth u.tx_undos 1 in
  let tx2' = List.nth u2.tx_undos 1 in
  Alcotest.(check int) "tx2 prev_outputs count"
    (List.length tx2.prev_outputs) (List.length tx2'.prev_outputs)

(* Test block_undo checksum verification fails on corruption *)
let test_block_undo_checksum_failure () =
  let script = Cstruct.of_string "\x76\xa9\x14\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x88\xac" in
  let u : Storage.block_undo = {
    tx_undos = [
      { prev_outputs = [
          { value = 1000000L; script_pubkey = script; height = 50; is_coinbase = false }
        ] };
    ]
  } in
  let w = Serialize.writer_create () in
  Storage.serialize_block_undo w u;
  let data = Serialize.writer_to_cstruct w in
  (* Corrupt a byte in the middle *)
  let len = Cstruct.length data in
  if len > 10 then begin
    (* Create a copy by going through bytes *)
    let corrupted = Cstruct.create len in
    Cstruct.blit data 0 corrupted 0 len;
    Cstruct.set_uint8 corrupted 5 0xFF;
    let r = Serialize.reader_of_cstruct corrupted in
    let raised = ref false in
    (try
      let _ = Storage.deserialize_block_undo r in ()
    with Failure _ -> raised := true);
    Alcotest.(check bool) "checksum failure raises" true !raised
  end

(* Test empty block_undo *)
let test_block_undo_empty () =
  let u : Storage.block_undo = { tx_undos = [] } in
  let w = Serialize.writer_create () in
  Storage.serialize_block_undo w u;
  let data = Serialize.writer_to_cstruct w in
  let r = Serialize.reader_of_cstruct data in
  let u2 = Storage.deserialize_block_undo r in
  Alcotest.(check int) "empty tx_undos" 0 (List.length u2.tx_undos)

(* Test disconnect_block with missing undo data *)
let test_disconnect_block_missing_undo () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let block = make_test_block ~ver:1l ~ts:1231006505l ~nc:2083236893l in
  let block_hash = Crypto.compute_block_hash block.header in
  (* Don't store any undo data - just call disconnect *)
  let add_utxo _txid _vout _u = () in
  let remove_utxo _txid _vout = () in
  let result = Storage.disconnect_block db block block_hash ~add_utxo ~remove_utxo in
  (match result with
   | Error (Storage.MissingUndoData _) ->
     Alcotest.(check bool) "missing undo data error" true true
   | _ ->
     Alcotest.fail "expected MissingUndoData error");
  Storage.ChainDB.close db;
  cleanup_test_db ()

let () =
  cleanup_test_db ();
  let open Alcotest in
  run "Storage" [
    "file_storage", [
      test_case "basic operations" `Quick test_file_storage_basic;
      test_case "batch operations" `Quick test_file_storage_batch;
      test_case "iter_prefix" `Quick test_file_storage_iter_prefix;
    ];
    "chain_db", [
      test_case "block header" `Quick test_chaindb_block_header;
      test_case "full block" `Quick test_chaindb_block;
      test_case "height hash mapping" `Quick test_chaindb_height_hash;
      test_case "utxo operations" `Quick test_chaindb_utxo;
      test_case "chain tip" `Quick test_chaindb_chain_tip;
      test_case "tx index" `Quick test_chaindb_tx_index;
      test_case "batch operations" `Quick test_chaindb_batch;
    ];
    "encoding", [
      test_case "height encoding order" `Quick test_height_encoding_order;
    ];
    "undo_data", [
      test_case "tx_in_undo roundtrip" `Quick test_tx_in_undo_roundtrip;
      test_case "tx_undo roundtrip" `Quick test_tx_undo_roundtrip;
      test_case "block_undo roundtrip" `Quick test_block_undo_roundtrip;
      test_case "block_undo checksum failure" `Quick test_block_undo_checksum_failure;
      test_case "block_undo empty" `Quick test_block_undo_empty;
      test_case "disconnect_block missing undo" `Quick test_disconnect_block_missing_undo;
    ];
  ]
