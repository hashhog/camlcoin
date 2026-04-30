(* Tests for Migration — LogStorage -> Cf_chainstate (Option D). *)

open Camlcoin

let tmp_root = "/tmp/camlcoin_migration_test"

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

let mk_hash byte =
  let b = Bytes.make 32 (Char.chr byte) in
  Cstruct.of_bytes b

(* Build a fresh fake chainstate dir with a populated data.log, then
   close it so the migration can reopen + read the live records. *)
let build_fake_chainstate () =
  cleanup_tmp ();
  Unix.mkdir tmp_root 0o755;
  let chainstate = Filename.concat tmp_root "chainstate" in
  Unix.mkdir chainstate 0o755;
  let log = Storage.LogStorage.open_db chainstate in
  (* Block header under "h" prefix *)
  let bh_hash = mk_hash 0xa0 in
  Storage.LogStorage.put log
    (Storage.prefix_block_header ^ Cstruct.to_string bh_hash)
    "block-header-bytes";
  (* Block data under "b" prefix *)
  let bd_hash = mk_hash 0xb0 in
  Storage.LogStorage.put log
    (Storage.prefix_block_data ^ Cstruct.to_string bd_hash)
    "block-data-bytes";
  (* Tx under "t" prefix *)
  let tx_hash = mk_hash 0x10 in
  Storage.LogStorage.put log
    (Storage.prefix_tx ^ Cstruct.to_string tx_hash)
    "tx-payload-bytes";
  (* UTXO under "u" prefix - key is u + txid32 + vout_le32 *)
  let u_txid = mk_hash 0x20 in
  let u_key =
    let b = Bytes.create 36 in
    Cstruct.blit_to_bytes u_txid 0 b 0 32;
    Bytes.set b 32 (Char.chr 0); Bytes.set b 33 (Char.chr 0);
    Bytes.set b 34 (Char.chr 0); Bytes.set b 35 (Char.chr 0);
    Bytes.unsafe_to_string b
  in
  Storage.LogStorage.put log
    (Storage.prefix_utxo ^ u_key) "utxo-entry-bytes";
  (* Height -> hash under "n" prefix *)
  let n_hash = mk_hash 0xa0 in
  let height_key =
    let cs = Cstruct.create 4 in
    Cstruct.BE.set_uint32 cs 0 (Int32.of_int 7);
    Cstruct.to_string cs
  in
  Storage.LogStorage.put log
    (Storage.prefix_block_height ^ height_key)
    (Cstruct.to_string n_hash);
  (* Tx index under "x" prefix *)
  Storage.LogStorage.put log
    (Storage.prefix_tx_index ^ Cstruct.to_string tx_hash)
    "tx-index-bytes";
  (* Chain state under "s" prefix *)
  Storage.LogStorage.put log
    (Storage.prefix_chain_state ^ "tip_hash")
    (Cstruct.to_string bh_hash);
  Storage.LogStorage.put log
    (Storage.prefix_chain_state ^ "tip_height")
    height_key;
  (* Undo data under "r" prefix *)
  Storage.LogStorage.put log
    (Storage.prefix_undo_data ^ Cstruct.to_string bd_hash)
    "undo-data-bytes";
  (* Invalidated under "i" prefix *)
  let inv_hash = mk_hash 0x99 in
  Storage.LogStorage.put log
    (Storage.prefix_invalidated ^ Cstruct.to_string inv_hash) "1";
  Storage.LogStorage.close log;
  chainstate

(* Verify that all records made it into the right CFs after migration. *)
let verify_migrated chainstate =
  let cf_path = Filename.concat chainstate "chainstate-rocks" in
  let cfdb = Cf_chainstate.open_db cf_path in
  let bh_hash = mk_hash 0xa0 in
  let bd_hash = mk_hash 0xb0 in
  let tx_hash = mk_hash 0x10 in
  let u_txid = mk_hash 0x20 in
  let n_hash = mk_hash 0xa0 in
  let inv_hash = mk_hash 0x99 in
  Alcotest.(check (option string)) "block_header migrated"
    (Some "block-header-bytes")
    (Cf_chainstate.get_block_header cfdb bh_hash);
  Alcotest.(check (option string)) "block_data migrated"
    (Some "block-data-bytes")
    (Cf_chainstate.get_block_data cfdb bd_hash);
  Alcotest.(check (option string)) "tx migrated"
    (Some "tx-payload-bytes")
    (Cf_chainstate.get_tx cfdb tx_hash);
  Alcotest.(check (option string)) "utxo migrated"
    (Some "utxo-entry-bytes")
    (Cf_chainstate.get_utxo cfdb u_txid 0);
  let got_n = Cf_chainstate.get_block_height cfdb 7 in
  Alcotest.(check bool) "height->hash migrated" true (Option.is_some got_n);
  Alcotest.(check string) "height->hash bytes match"
    (Cstruct.to_string n_hash)
    (Cstruct.to_string (Option.get got_n));
  Alcotest.(check (option string)) "tx_index migrated"
    (Some "tx-index-bytes")
    (Cf_chainstate.get_tx_index cfdb tx_hash);
  Alcotest.(check (option string)) "chain_state tip_hash migrated"
    (Some (Cstruct.to_string bh_hash))
    (Cf_chainstate.get_chain_state cfdb "tip_hash");
  Alcotest.(check (option string)) "undo_data migrated"
    (Some "undo-data-bytes")
    (Cf_chainstate.get_undo_data cfdb bd_hash);
  Alcotest.(check bool) "invalidated migrated"
    true (Cf_chainstate.is_invalidated cfdb inv_hash);
  Cf_chainstate.close cfdb

let test_full_migration () =
  let chainstate = build_fake_chainstate () in
  let rc = Migration.run ~chainstate_dir:chainstate in
  Alcotest.(check int) "migration succeeds" 0 rc;
  Alcotest.(check bool) "complete marker written"
    true (Sys.file_exists (Migration.complete_marker chainstate));
  Alcotest.(check bool) "data.log renamed to backup"
    true (Sys.file_exists (Migration.backup_path chainstate));
  Alcotest.(check bool) "data.log no longer at original path"
    false (Sys.file_exists (Migration.data_log_path chainstate));
  verify_migrated chainstate;
  cleanup_tmp ()

let test_migration_idempotent () =
  let chainstate = build_fake_chainstate () in
  let rc1 = Migration.run ~chainstate_dir:chainstate in
  Alcotest.(check int) "first migration succeeds" 0 rc1;
  let rc2 = Migration.run ~chainstate_dir:chainstate in
  (* On the second run, data.log was already renamed away in run 1,
     so the function should treat it as "no data.log -- nothing to
     migrate" and short-circuit successfully. *)
  Alcotest.(check int) "second run is idempotent (returns 0)" 0 rc2;
  verify_migrated chainstate;
  cleanup_tmp ()

(* Simulate crash mid-migration by populating the CF DB partway, then
   running the full migration from the still-intact data.log, and
   checking that pre-existing records are skipped (idempotency at the
   per-record level). *)
let test_crash_resumption () =
  let chainstate = build_fake_chainstate () in
  let cf_path = Filename.concat chainstate "chainstate-rocks" in
  (* Pre-populate the CF DB with a block_header record matching what
     migration is about to write. This simulates "we crashed after
     writing this record but before checkpointing offset". *)
  let bh_hash = mk_hash 0xa0 in
  let cfdb = Cf_chainstate.open_db cf_path in
  Cf_chainstate.put_block_header cfdb bh_hash "block-header-bytes";
  Cf_chainstate.close cfdb;
  let rc = Migration.run ~chainstate_dir:chainstate in
  Alcotest.(check int) "migration completes after partial state"
    0 rc;
  verify_migrated chainstate;
  (* Inspect the progress file to confirm at least one skip was
     recorded — the pre-existing block_header. Note: progress file
     remains after a successful run; tests just want to see counts. *)
  let p = Migration.read_progress chainstate in
  Alcotest.(check bool) "skipped >= 1"
    true (p.n_skipped >= 1);
  cleanup_tmp ()

(* Boot guard: when env var set, refuse to start with data.log
   present + no marker. We can't easily test [exit 12] without
   forking, so we verify the lower-level helpers behave as expected. *)
let test_boot_guard_helpers () =
  cleanup_tmp ();
  Unix.mkdir tmp_root 0o755;
  let chainstate = Filename.concat tmp_root "chainstate" in
  Unix.mkdir chainstate 0o755;
  (* No data.log yet -> guard would not refuse. We just check the
     marker/data.log paths report sensibly via Sys.file_exists. *)
  Alcotest.(check bool) "no data.log -> nothing to refuse"
    false (Sys.file_exists (Migration.data_log_path chainstate));
  Alcotest.(check bool) "no marker yet"
    false (Sys.file_exists (Migration.complete_marker chainstate));
  cleanup_tmp ()

(* When the chainstate dir has no data.log, run should be a no-op
   that writes the complete marker (treating it as a fresh datadir). *)
let test_run_on_empty_chainstate () =
  cleanup_tmp ();
  Unix.mkdir tmp_root 0o755;
  let chainstate = Filename.concat tmp_root "chainstate" in
  Unix.mkdir chainstate 0o755;
  let rc = Migration.run ~chainstate_dir:chainstate in
  Alcotest.(check int) "fresh chainstate returns 0" 0 rc;
  Alcotest.(check bool) "marker written"
    true (Sys.file_exists (Migration.complete_marker chainstate));
  cleanup_tmp ()

(* --- Torn-record tolerance regression (Apr 28 → Apr 30 mainnet repro) --- *)

(* Direct repro of the iter_prefix-walks-past-EOF bug. Open LogStorage,
   write three records, then truncate data.log under the live handle so
   the third record's value is no longer fully on disk. With the fix,
   iter_prefix must skip the torn entry, surface it via
   [n_torn_records], and yield the two intact records to the callback.
   Without the fix, the [Hashtbl.fold] in iter_prefix raises
   [End_of_file] inside the mutex and the entire walk aborts before
   the callback is invoked even once. *)
let test_iter_prefix_tolerates_torn_entry () =
  cleanup_tmp ();
  Unix.mkdir tmp_root 0o755;
  let chainstate = Filename.concat tmp_root "chainstate" in
  Unix.mkdir chainstate 0o755;
  let log = Storage.LogStorage.open_db chainstate in
  Storage.LogStorage.put log "k1" (String.make 64 'A');
  Storage.LogStorage.put log "k2" (String.make 64 'B');
  Storage.LogStorage.put log "k3" (String.make 64 'C');
  (* Truncate the live data.log so k3's value is no longer fully on
     disk. We chop 32 bytes — well within the 64-byte value, so k3's
     index entry now claims (offset, 64) but the file only has bytes
     up to offset+32. *)
  let dlog = Filename.concat chainstate "data.log" in
  let cur_size = (Unix.stat dlog).Unix.st_size in
  Unix.truncate dlog (cur_size - 32);
  (* Pre-fix: this raised [End_of_file] from inside iter_prefix; the
     callback never fired. Post-fix: callback fires for the two intact
     records, k3 is silently skipped, n_torn_records reports 1. *)
  let collected = ref [] in
  Storage.LogStorage.iter_prefix log "" (fun k v ->
    collected := (k, v) :: !collected);
  Alcotest.(check int) "iter yielded the 2 intact records"
    2 (List.length !collected);
  Alcotest.(check int) "n_torn_records counted the torn k3"
    1 (Storage.LogStorage.n_torn_records log);
  (* Sanity: the values returned for k1+k2 are still correct. *)
  let by_key = List.sort compare !collected in
  Alcotest.(check (list (pair string string))) "k1+k2 round-trip"
    [("k1", String.make 64 'A'); ("k2", String.make 64 'B')]
    by_key;
  Storage.LogStorage.close log;
  cleanup_tmp ()

(* iter_prefix and get share the bounds-check helper, so a torn entry
   that iter_prefix skips must also be reported as missing (not as a
   raised exception) via [get]. This locks the read paths together. *)
let test_get_tolerates_torn_entry () =
  cleanup_tmp ();
  Unix.mkdir tmp_root 0o755;
  let chainstate = Filename.concat tmp_root "chainstate" in
  Unix.mkdir chainstate 0o755;
  let log = Storage.LogStorage.open_db chainstate in
  Storage.LogStorage.put log "live" "value-of-live-record";
  Storage.LogStorage.put log "torn" (String.make 200 'Z');
  let dlog = Filename.concat chainstate "data.log" in
  let cur_size = (Unix.stat dlog).Unix.st_size in
  Unix.truncate dlog (cur_size - 100);
  Alcotest.(check (option string)) "live record still readable"
    (Some "value-of-live-record")
    (Storage.LogStorage.get log "live");
  Alcotest.(check (option string)) "torn record returns None (no exception)"
    None
    (Storage.LogStorage.get log "torn");
  Alcotest.(check int) "n_torn_records bumped"
    1 (Storage.LogStorage.n_torn_records log);
  Storage.LogStorage.close log;
  cleanup_tmp ()

(* Helper for the run-level synthetic-snapshot-corruption test. We need
   the index loaded by [open_db] to contain entries pointing past the
   real on-disk EOF — which is what happens when the writer process
   was killed mid-write and the snapshot's watermark covers records
   the file never fully held. We build that state by:
     1. Writing a clean datadir + closing (snapshot now exists, valid).
     2. Truncating data.log to chop off the tail.
     3. Patching the snapshot file's watermark field to equal the new
        (shorter) on-disk size, so [try_load_snapshot]'s watermark
        check passes and the stale per-entry offsets are kept. *)
let read_be64_at ic off =
  seek_in ic off;
  let r = ref 0 in
  for _ = 0 to 7 do
    r := (!r lsl 8) lor (input_byte ic)
  done;
  !r

let write_be64_at oc off n =
  seek_out oc off;
  for i = 0 to 7 do
    output_char oc (Char.chr ((n lsr ((7 - i) * 8)) land 0xff))
  done

let corrupt_snapshot_to_make_index_torn chainstate =
  let dlog = Filename.concat chainstate "data.log" in
  let snap = Filename.concat chainstate "data.log.idx" in
  Alcotest.(check bool) "data.log.idx exists post-close"
    true (Sys.file_exists snap);
  let cur = (Unix.stat dlog).Unix.st_size in
  let chop = 64 in
  Alcotest.(check bool) "data.log big enough to chop" true (cur > chop + 32);
  let new_size = cur - chop in
  Unix.truncate dlog new_size;
  (* Patch watermark (bytes 12..19 of the snapshot, big-endian) to
     equal new_size so try_load_snapshot accepts it. *)
  let ic = open_in_bin snap in
  let _orig_watermark = read_be64_at ic 12 in
  close_in ic;
  let oc = open_out_gen [Open_wronly; Open_binary] 0o644 snap in
  write_be64_at oc 12 new_size;
  close_out oc

(* Run the full Migration.run end-to-end against a torn datadir.
   Asserts the migration completes without raising, returns a non-
   success code, refuses to write [.migration-complete], and leaves
   data.log in place for repair. *)
let test_run_refuses_to_complete_on_torn_records () =
  let chainstate = build_fake_chainstate () in
  corrupt_snapshot_to_make_index_torn chainstate;
  let rc = Migration.run ~chainstate_dir:chainstate in
  Alcotest.(check bool) "non-zero rc on torn data.log" true (rc <> 0);
  Alcotest.(check int) "exits with the documented torn-record code"
    4 rc;
  Alcotest.(check bool) ".migration-complete NOT written"
    false (Sys.file_exists (Migration.complete_marker chainstate));
  Alcotest.(check bool) "data.log preserved (not renamed to bak)"
    true (Sys.file_exists (Migration.data_log_path chainstate));
  Alcotest.(check bool) "no pre-migration backup yet"
    false (Sys.file_exists (Migration.backup_path chainstate));
  (* Progress file should have torn>0 so the operator can see it. *)
  let p = Migration.read_progress chainstate in
  Alcotest.(check bool) "progress.n_torn > 0" true (p.n_torn > 0);
  cleanup_tmp ()

(* Idempotency under torn records: running the migration twice on the
   same torn datadir must produce consistent counts and consistent
   exit codes (both 4). The second run must not silently mark
   complete just because RocksDB CFs already hold the records the
   first run was able to route. *)
let test_run_idempotent_on_torn_records () =
  let chainstate = build_fake_chainstate () in
  corrupt_snapshot_to_make_index_torn chainstate;
  let rc1 = Migration.run ~chainstate_dir:chainstate in
  Alcotest.(check int) "first run: torn rc" 4 rc1;
  let p1 = Migration.read_progress chainstate in
  let rc2 = Migration.run ~chainstate_dir:chainstate in
  Alcotest.(check int) "second run: same torn rc" 4 rc2;
  let p2 = Migration.read_progress chainstate in
  Alcotest.(check int) "n_torn stable across runs" p1.n_torn p2.n_torn;
  Alcotest.(check bool) "still no .migration-complete"
    false (Sys.file_exists (Migration.complete_marker chainstate));
  cleanup_tmp ()

(* Synthetic torn-record-at-tail test, per the Apr 30 fix prompt: a
   data.log with N good records and a single torn header at the end.
   The pre-existing rebuild_index path already handles this by
   truncating the partial tail; the migration must therefore complete
   successfully, processing the N intact records without crashing. *)
let test_torn_tail_record_truncated_on_open () =
  cleanup_tmp ();
  Unix.mkdir tmp_root 0o755;
  let chainstate = Filename.concat tmp_root "chainstate" in
  Unix.mkdir chainstate 0o755;
  (* Step 1: write 10 good records using the normal API + close. *)
  let log = Storage.LogStorage.open_db chainstate in
  for i = 0 to 9 do
    let key =
      Printf.sprintf "%c%s"
        (String.get Storage.prefix_block_data 0)
        (String.make 32 (Char.chr (i + 1)))
    in
    Storage.LogStorage.put log key (Printf.sprintf "block-%d" i)
  done;
  Storage.LogStorage.close log;
  (* Step 2: drop the snapshot so the next open does a full rebuild
     (so the torn tail we are about to append exercises the
     rebuild_index truncation path, not the snapshot path). *)
  let snap = Filename.concat chainstate "data.log.idx" in
  if Sys.file_exists snap then Unix.unlink snap;
  (* Step 3: append a torn header to data.log: 'P' opcode + klen=4 +
     "torn" + vlen=1000 + only 50 bytes of value. The next open's
     rebuild_index will read past EOF on the value, hit End_of_file,
     and truncate the file at the last valid record. *)
  let dlog = Filename.concat chainstate "data.log" in
  let oc = open_out_gen [Open_wronly; Open_append; Open_binary] 0o644 dlog in
  output_char oc 'P';
  (* klen = 4 *)
  output_char oc '\x00'; output_char oc '\x00';
  output_char oc '\x00'; output_char oc '\x04';
  output_string oc "torn";
  (* vlen header claims 1000 bytes... *)
  output_char oc '\x00'; output_char oc '\x00';
  output_char oc '\x03'; output_char oc '\xe8';
  (* ...but we only write 50 bytes of value before "crashing". *)
  output_string oc (String.make 50 'X');
  close_out oc;
  (* Step 4: run the migration. Expected: rebuild_index trims the
     torn tail, the 10 good records migrate, marker is written. *)
  let rc = Migration.run ~chainstate_dir:chainstate in
  Alcotest.(check int) "torn-tail data.log: migration succeeds" 0 rc;
  Alcotest.(check bool) "marker written"
    true (Sys.file_exists (Migration.complete_marker chainstate));
  let p = Migration.read_progress chainstate in
  Alcotest.(check int) "no torn-index records (tail was truncated)"
    0 p.n_torn;
  Alcotest.(check int) "10 block_data records migrated"
    10 p.n_block_data;
  cleanup_tmp ()

let () =
  cleanup_tmp ();
  let open Alcotest in
  run "Migration" [
    "logstorage_to_cf", [
      test_case "full migration" `Quick test_full_migration;
      test_case "idempotency" `Quick test_migration_idempotent;
      test_case "crash resumption" `Quick test_crash_resumption;
      test_case "empty chainstate" `Quick test_run_on_empty_chainstate;
    ];
    "boot_guard", [
      test_case "helpers" `Quick test_boot_guard_helpers;
    ];
    "torn_records", [
      test_case "iter_prefix tolerates torn entry"
        `Quick test_iter_prefix_tolerates_torn_entry;
      test_case "get tolerates torn entry"
        `Quick test_get_tolerates_torn_entry;
      test_case "run refuses to complete on torn records"
        `Quick test_run_refuses_to_complete_on_torn_records;
      test_case "run is idempotent on torn records"
        `Quick test_run_idempotent_on_torn_records;
      test_case "torn tail record truncated on open"
        `Quick test_torn_tail_record_truncated_on_open;
    ];
  ]
