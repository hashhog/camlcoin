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

(* Ban list (Option D step 3): peer_manager's persistent ban table is
   now a CF, not a "B"-prefixed LogStorage keyspace. Verify that
   put/iter/delete behave correctly. *)
let test_ban_list_roundtrip () =
  with_db (fun db ->
    let mk_value t =
      let cs = Cstruct.create 8 in
      Cstruct.BE.set_uint64 cs 0 (Int64.bits_of_float t);
      Cstruct.to_string cs
    in
    Cf_chainstate.put_ban db "1.2.3.4" (mk_value 1.0);
    Cf_chainstate.put_ban db "5.6.7.8" (mk_value 2.0);
    Cf_chainstate.put_ban db "9.0.1.2" (mk_value 3.0);
    Alcotest.(check (option string)) "ban 1 stored"
      (Some (mk_value 1.0)) (Cf_chainstate.get_ban db "1.2.3.4");
    let collected = ref [] in
    Cf_chainstate.iter_bans db (fun addr v ->
      collected := (addr, v) :: !collected);
    Alcotest.(check int) "iter sees 3 bans" 3 (List.length !collected);
    Cf_chainstate.delete_ban db "5.6.7.8";
    Alcotest.(check (option string)) "deleted ban gone"
      None (Cf_chainstate.get_ban db "5.6.7.8");
    let collected2 = ref [] in
    Cf_chainstate.iter_bans db (fun addr v ->
      collected2 := (addr, v) :: !collected2);
    Alcotest.(check int) "iter sees 2 bans after delete"
      2 (List.length !collected2))

(* End-to-end integration test (Option D step 3): boot a fresh ChainDB,
   apply ~100 blocks worth of state spread across all 9 namespaces,
   close + reopen, and verify every namespace persisted. This exercises
   ChainDB's swap from LogStorage -> Cf_chainstate end-to-end without
   needing a full p2p / sync / validation harness. *)
let test_chaindb_end_to_end_100_blocks () =
  cleanup_tmp ();
  Unix.mkdir tmp_root 0o755;
  let datadir = Filename.concat tmp_root "datadir" in
  Unix.mkdir datadir 0o755;
  let db_path = Filename.concat datadir "chainstate" in
  let db = Storage.ChainDB.create db_path in
  let n_blocks = 100 in
  (* Build 100 fake block hashes and apply to every namespace. *)
  let mk_block_hash i =
    let b = Bytes.make 32 (Char.chr (i land 0xff)) in
    Bytes.set b 0 (Char.chr ((i lsr 8) land 0xff));
    Cstruct.of_bytes b
  in
  let mk_txid i = mk_block_hash (1_000 + i) in
  for i = 0 to n_blocks - 1 do
    let bh = mk_block_hash i in
    let txid = mk_txid i in
    (* block_header CF *)
    let header = {
      Types.version = Int32.of_int (i + 1);
      prev_block = mk_block_hash (max 0 (i - 1));
      merkle_root = mk_block_hash (i + 100);
      timestamp = Int32.of_int (1700000000 + i);
      bits = 0x1d00ffffl;
      nonce = Int32.of_int i;
    } in
    Storage.ChainDB.store_block_header db bh header;
    (* block_data CF — we use a tiny synthetic block *)
    let block = { Types.header; transactions = [] } in
    Storage.ChainDB.store_block db bh block;
    (* block_height CF *)
    Storage.ChainDB.set_height_hash db i bh;
    (* tx CF — pretend a coinbase lives here *)
    let tx_hash = txid in
    (* Coinbase tx — single null input + a tiny output. Needs at least
       one tx_in/tx_out so the round-trip (de)serialization doesn't
       trip the segwit flag check. *)
    let tx = {
      Types.version = 1l;
      inputs = [{
        Types.previous_output = {
          Types.txid = Cstruct.create 32;
          vout = 0xffffffffl;
        };
        script_sig = Cstruct.empty;
        sequence = 0xffffffffl;
      }];
      outputs = [{
        Types.value = 5000000000L;
        script_pubkey = Cstruct.empty;
      }];
      witnesses = [];
      locktime = 0l;
    } in
    Storage.ChainDB.store_transaction db tx_hash tx;
    (* tx_index CF *)
    Storage.ChainDB.store_tx_index db txid bh i;
    (* utxo CF *)
    Storage.ChainDB.store_utxo db txid 0 (Printf.sprintf "utxo-%d" i);
    (* undo_data CF *)
    Storage.ChainDB.store_undo_data db bh (Printf.sprintf "undo-%d" i);
    (* invalidated CF — mark every 10th block invalid for variety *)
    if i mod 10 = 0 then
      Storage.ChainDB.set_block_invalidated db bh
  done;
  (* chain_state CF *)
  let tip = mk_block_hash (n_blocks - 1) in
  Storage.ChainDB.set_chain_tip db tip (n_blocks - 1);
  Storage.ChainDB.set_header_tip db tip (n_blocks - 1);
  Storage.ChainDB.close db;
  (* Reopen and verify *)
  let db = Storage.ChainDB.create db_path in
  for i = 0 to n_blocks - 1 do
    let bh = mk_block_hash i in
    let txid = mk_txid i in
    Alcotest.(check bool)
      (Printf.sprintf "block %d header present" i) true
      (Option.is_some (Storage.ChainDB.get_block_header db bh));
    Alcotest.(check bool)
      (Printf.sprintf "block %d body present" i) true
      (Storage.ChainDB.has_block db bh);
    let h_at = Storage.ChainDB.get_hash_at_height db i in
    Alcotest.(check bool)
      (Printf.sprintf "height %d -> hash present" i) true
      (Option.is_some h_at);
    Alcotest.(check string)
      (Printf.sprintf "height %d -> correct hash" i)
      (Cstruct.to_string bh)
      (Cstruct.to_string (Option.get h_at));
    Alcotest.(check bool)
      (Printf.sprintf "tx %d present" i) true
      (Option.is_some (Storage.ChainDB.get_transaction db txid));
    Alcotest.(check bool)
      (Printf.sprintf "tx_index %d present" i) true
      (Option.is_some (Storage.ChainDB.get_tx_index db txid));
    Alcotest.(check (option string))
      (Printf.sprintf "utxo %d preserved" i)
      (Some (Printf.sprintf "utxo-%d" i))
      (Storage.ChainDB.get_utxo db txid 0);
    Alcotest.(check (option string))
      (Printf.sprintf "undo %d preserved" i)
      (Some (Printf.sprintf "undo-%d" i))
      (Storage.ChainDB.get_undo_data db bh);
    if i mod 10 = 0 then
      Alcotest.(check bool)
        (Printf.sprintf "block %d invalidated" i) true
        (Storage.ChainDB.is_block_invalidated db bh)
  done;
  (match Storage.ChainDB.get_chain_tip db with
   | None -> Alcotest.fail "chain tip missing after reopen"
   | Some (h, height) ->
     Alcotest.(check int) "tip height" (n_blocks - 1) height;
     Alcotest.(check string) "tip hash"
       (Cstruct.to_string tip) (Cstruct.to_string h));
  (match Storage.ChainDB.get_header_tip db with
   | None -> Alcotest.fail "header tip missing after reopen"
   | Some (_, height) ->
     Alcotest.(check int) "header tip height" (n_blocks - 1) height);
  let invalid = Storage.ChainDB.get_all_invalidated_blocks db in
  Alcotest.(check int) "10 invalidated blocks across 100"
    10 (List.length invalid);
  Storage.ChainDB.close db;
  cleanup_tmp ()

(* Boot-guard test (Option D step 3): when data.log is present but
   .migration-complete is missing, the daemon must refuse to boot.
   We test the underlying Migration.check_or_refuse_to_boot helper
   in a subprocess so we can observe the exit code.

   The subprocess is the test executable itself, re-invoked with a
   marker env var set so it knows to call check_or_refuse_to_boot
   and exit (rather than running the test harness). *)
let test_boot_guard_refuses_unmigrated_datadir () =
  cleanup_tmp ();
  Unix.mkdir tmp_root 0o755;
  let chainstate = Filename.concat tmp_root "chainstate" in
  Unix.mkdir chainstate 0o755;
  (* Plant a fake data.log file *)
  let dl = Filename.concat chainstate "data.log" in
  let oc = open_out dl in
  output_string oc "fake-legacy-logstorage-data";
  close_out oc;
  (* No marker. Boot guard MUST refuse with exit 12. *)
  let argv0 = Sys.executable_name in
  let cmd =
    Printf.sprintf "CAMLCOIN_TEST_BOOT_GUARD_TARGET=%s %s 2>/dev/null"
      (Filename.quote chainstate) (Filename.quote argv0)
  in
  let rc = Sys.command cmd in
  Alcotest.(check int) "boot guard refuses with exit 12" 12 rc;
  (* Now write the marker -> guard accepts. *)
  let mc = Filename.concat chainstate ".migration-complete" in
  let oc = open_out mc in
  output_string oc "complete\n";
  close_out oc;
  let rc = Sys.command cmd in
  Alcotest.(check int) "boot guard accepts after marker"
    0 rc;
  cleanup_tmp ()

(* When the test executable is invoked with CAMLCOIN_TEST_BOOT_GUARD_TARGET
   set, it skips the alcotest run and instead exercises the boot guard
   directly. Lets the test above observe exit 12 / 0 from the same
   binary. *)
let () =
  match Sys.getenv_opt "CAMLCOIN_TEST_BOOT_GUARD_TARGET" with
  | Some target ->
    Migration.check_or_refuse_to_boot target;
    exit 0
  | None -> ()

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
      test_case "ban list" `Quick test_ban_list_roundtrip;
    ];
    "atomic_batch", [
      test_case "multi-CF batch" `Quick test_atomic_batch;
    ];
    "persistence", [
      test_case "close+reopen" `Quick test_close_reopen;
      test_case "list CFs on disk" `Quick test_list_column_families;
    ];
    "option_d_integration", [
      test_case "ChainDB end-to-end 100 blocks" `Quick
        test_chaindb_end_to_end_100_blocks;
      test_case "boot guard refuses unmigrated datadir" `Quick
        test_boot_guard_refuses_unmigrated_datadir;
    ];
  ]
