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
  ]
