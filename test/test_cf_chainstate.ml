(* Tests for Cf_chainstate — Option D RocksDB-CF chainstate. *)

open Camlcoin

let tmp_root = "/tmp/camlcoin_cf_chainstate_test"

let cleanup_tmp () =
  let rec rm_rf path =
    if Sys.file_exists path then begin
      if Sys.is_directory path then begin
        Array.iter (fun f -> rm_rf (Filename.concat path f))
          (Sys.readdir path);
        Unix.rmdir path
      end else
        Unix.unlink path
    end
  in
  rm_rf tmp_root

(* Build a deterministic 32-byte "hash" for tests. *)
let mk_hash byte =
  let b = Bytes.make 32 (Char.chr byte) in
  Cstruct.of_bytes b

let with_db f =
  cleanup_tmp ();
  Unix.mkdir tmp_root 0o755;
  let path = Filename.concat tmp_root "rocks" in
  let db = Cf_chainstate.open_db path in
  Fun.protect
    ~finally:(fun () -> Cf_chainstate.close db)
    (fun () -> f db)

let test_block_header_roundtrip () =
  with_db (fun db ->
    let hash = mk_hash 0xab in
    let payload = "header-bytes-here" in
    Cf_chainstate.put_block_header db hash payload;
    let got = Cf_chainstate.get_block_header db hash in
    Alcotest.(check (option string)) "block header roundtrip"
      (Some payload) got;
    let other = mk_hash 0xcd in
    let miss = Cf_chainstate.get_block_header db other in
    Alcotest.(check (option string)) "missing header is None"
      None miss)

let test_block_data_roundtrip () =
  with_db (fun db ->
    let hash = mk_hash 0x01 in
    let payload = String.make 4096 'x' in
    Cf_chainstate.put_block_data db hash payload;
    Alcotest.(check (option string)) "block data roundtrip"
      (Some payload) (Cf_chainstate.get_block_data db hash);
    Cf_chainstate.delete_block_data db hash;
    Alcotest.(check (option string)) "block data deleted"
      None (Cf_chainstate.get_block_data db hash))

let test_utxo_roundtrip () =
  with_db (fun db ->
    let txid = mk_hash 0x42 in
    Cf_chainstate.put_utxo db txid 0 "utxo-0";
    Cf_chainstate.put_utxo db txid 1 "utxo-1";
    Alcotest.(check (option string)) "utxo 0"
      (Some "utxo-0") (Cf_chainstate.get_utxo db txid 0);
    Alcotest.(check (option string)) "utxo 1"
      (Some "utxo-1") (Cf_chainstate.get_utxo db txid 1);
    Alcotest.(check (option string)) "missing utxo"
      None (Cf_chainstate.get_utxo db txid 2);
    Cf_chainstate.delete_utxo db txid 0;
    Alcotest.(check (option string)) "deleted utxo 0"
      None (Cf_chainstate.get_utxo db txid 0);
    Alcotest.(check (option string)) "still have utxo 1"
      (Some "utxo-1") (Cf_chainstate.get_utxo db txid 1))

let test_height_hash_mapping () =
  with_db (fun db ->
    let h0 = mk_hash 0x10 in
    let h1 = mk_hash 0x11 in
    Cf_chainstate.put_block_height db 0 h0;
    Cf_chainstate.put_block_height db 1 h1;
    Cf_chainstate.put_block_height db 1_000_000 h1;
    let g0 = Cf_chainstate.get_block_height db 0 in
    let g1 = Cf_chainstate.get_block_height db 1 in
    let g_huge = Cf_chainstate.get_block_height db 1_000_000 in
    let g_miss = Cf_chainstate.get_block_height db 9999999 in
    Alcotest.(check bool) "h0 found" true (Option.is_some g0);
    Alcotest.(check bool) "h1 found" true (Option.is_some g1);
    Alcotest.(check bool) "huge found" true (Option.is_some g_huge);
    Alcotest.(check bool) "missing height" true (Option.is_none g_miss);
    Alcotest.(check string) "h0 == h0"
      (Cstruct.to_string h0)
      (Cstruct.to_string (Option.get g0)))

let test_chain_state_metadata () =
  with_db (fun db ->
    Cf_chainstate.put_chain_state db "tip_height"
      (Cf_chainstate.encode_height 12345);
    let got = Cf_chainstate.get_chain_state db "tip_height" in
    Alcotest.(check bool) "tip_height stored" true (Option.is_some got);
    let h = Cf_chainstate.decode_height (Option.get got) in
    Alcotest.(check int) "tip_height value" 12345 h)

let test_invalidated () =
  with_db (fun db ->
    let h = mk_hash 0x88 in
    Alcotest.(check bool) "not invalidated initially"
      false (Cf_chainstate.is_invalidated db h);
    Cf_chainstate.put_invalidated db h;
    Alcotest.(check bool) "invalidated after put"
      true (Cf_chainstate.is_invalidated db h);
    Cf_chainstate.delete_invalidated db h;
    Alcotest.(check bool) "not invalidated after delete"
      false (Cf_chainstate.is_invalidated db h))

let test_atomic_batch () =
  with_db (fun db ->
    let h = mk_hash 0x55 in
    let txid = mk_hash 0x66 in
    let b = Cf_chainstate.batch_create db in
    Cf_chainstate.batch_put_block_header b h "hdr";
    Cf_chainstate.batch_put_block_data b h "blk";
    Cf_chainstate.batch_put_utxo b txid 0 "utxo";
    Cf_chainstate.batch_put_block_height b 100 h;
    Cf_chainstate.batch_put_chain_state b "tip_height"
      (Cf_chainstate.encode_height 100);
    Cf_chainstate.batch_write b;
    Alcotest.(check (option string)) "batched header"
      (Some "hdr") (Cf_chainstate.get_block_header db h);
    Alcotest.(check (option string)) "batched block data"
      (Some "blk") (Cf_chainstate.get_block_data db h);
    Alcotest.(check (option string)) "batched utxo"
      (Some "utxo") (Cf_chainstate.get_utxo db txid 0);
    Alcotest.(check (option string)) "batched chain_state"
      (Some (Cf_chainstate.encode_height 100))
      (Cf_chainstate.get_chain_state db "tip_height"))

let test_close_reopen () =
  cleanup_tmp ();
  Unix.mkdir tmp_root 0o755;
  let path = Filename.concat tmp_root "rocks" in
  let db = Cf_chainstate.open_db path in
  let h = mk_hash 0x99 in
  Cf_chainstate.put_block_header db h "persistent";
  Cf_chainstate.close db;
  let db2 = Cf_chainstate.open_db path in
  let got = Cf_chainstate.get_block_header db2 h in
  Alcotest.(check (option string)) "header survives reopen"
    (Some "persistent") got;
  Cf_chainstate.close db2;
  cleanup_tmp ()

let test_list_column_families () =
  cleanup_tmp ();
  Unix.mkdir tmp_root 0o755;
  let path = Filename.concat tmp_root "rocks" in
  let db = Cf_chainstate.open_db path in
  Cf_chainstate.close db;
  let cfs = Rocksdb.list_column_families path in
  let cf_set = Array.fold_left (fun acc s ->
    s :: acc) [] cfs in
  let has name = List.exists ((=) name) cf_set in
  Alcotest.(check bool) "has default CF" true (has "default");
  Alcotest.(check bool) "has block_header CF" true (has "block_header");
  Alcotest.(check bool) "has utxo CF" true (has "utxo");
  Alcotest.(check bool) "has chain_state CF" true (has "chain_state");
  cleanup_tmp ()

let () =
  cleanup_tmp ();
  let open Alcotest in
  run "Cf_chainstate" [
    "namespace_roundtrip", [
      test_case "block header" `Quick test_block_header_roundtrip;
      test_case "block data" `Quick test_block_data_roundtrip;
      test_case "utxo" `Quick test_utxo_roundtrip;
      test_case "height->hash" `Quick test_height_hash_mapping;
      test_case "chain_state metadata" `Quick test_chain_state_metadata;
      test_case "invalidated" `Quick test_invalidated;
    ];
    "atomic_batch", [
      test_case "multi-CF batch" `Quick test_atomic_batch;
    ];
    "persistence", [
      test_case "close+reopen" `Quick test_close_reopen;
      test_case "list CFs on disk" `Quick test_list_column_families;
    ];
  ]
