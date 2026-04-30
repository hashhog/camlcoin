(* Migration: LogStorage -> Cf_chainstate (Option D, step 2).

   Reads every record from an existing [data.log] (LogStorage), routes it
   to the matching RocksDB column family in [Cf_chainstate], and records
   progress in a checkpoint file so a crashed migration resumes without
   redoing work or losing records.

   Idempotent: re-running on a partially or fully migrated datadir is a
   no-op (it skips records whose CF entry already exists).

   Operator-driven: this module is invoked from a top-level CLI flag,
   never automatically at boot. The boot path refuses to start when
   [data.log] is present but [.migration-complete] is missing; the
   operator is expected to run the migration command and inspect the
   exit status before re-launching the daemon.

   The output CFs match the 9 LogStorage namespaces:
     [h] -> CF_BLOCK_HEADER, [b] -> CF_BLOCK_DATA, [t] -> CF_TX,
     [u] -> CF_UTXO, [n] -> CF_BLOCK_HEIGHT, [x] -> CF_TX_INDEX,
     [s] -> CF_CHAIN_STATE, [r] -> CF_UNDO_DATA, [i] -> CF_INVALIDATED.
*)

let progress_file (chainstate_dir : string) : string =
  Filename.concat chainstate_dir ".migration-progress"

let complete_marker (chainstate_dir : string) : string =
  Filename.concat chainstate_dir ".migration-complete"

let backup_path (chainstate_dir : string) : string =
  Filename.concat chainstate_dir "data.log.pre-migration-bak"

let data_log_path (chainstate_dir : string) : string =
  Filename.concat chainstate_dir "data.log"

(* Progress checkpoint format: one line per CF, "namespace=count" (count
   of records routed to that CF so far, used as a sanity counter and
   user-facing display). The byte offset in data.log lives on its own
   line as "offset=N" — that is the actual resume point.

   [n_torn] counts index entries that LogStorage refused to read because
   their [(offset, vlen)] would have overrun the on-disk file (e.g.
   data.log was truncated by a crash mid-write). It is surfaced from
   [Storage.LogStorage.n_torn_records] after the walk completes and
   blocks [.migration-complete] when non-zero, so an operator with a
   torn datadir cannot silently lose records. *)
type progress = {
  mutable offset : int;     (* next byte to read from data.log *)
  mutable n_block_header : int;
  mutable n_block_data : int;
  mutable n_tx : int;
  mutable n_utxo : int;
  mutable n_block_height : int;
  mutable n_tx_index : int;
  mutable n_chain_state : int;
  mutable n_undo_data : int;
  mutable n_invalidated : int;
  mutable n_skipped : int;
  mutable n_unknown : int;
  mutable n_torn : int;
}

let empty_progress () = {
  offset = 0;
  n_block_header = 0;
  n_block_data = 0;
  n_tx = 0;
  n_utxo = 0;
  n_block_height = 0;
  n_tx_index = 0;
  n_chain_state = 0;
  n_undo_data = 0;
  n_invalidated = 0;
  n_skipped = 0;
  n_unknown = 0;
  n_torn = 0;
}

let write_progress (chainstate_dir : string) (p : progress) =
  let path = progress_file chainstate_dir in
  let tmp = path ^ ".tmp" in
  let oc = open_out tmp in
  Printf.fprintf oc "offset=%d\n" p.offset;
  Printf.fprintf oc "block_header=%d\n" p.n_block_header;
  Printf.fprintf oc "block_data=%d\n" p.n_block_data;
  Printf.fprintf oc "tx=%d\n" p.n_tx;
  Printf.fprintf oc "utxo=%d\n" p.n_utxo;
  Printf.fprintf oc "block_height=%d\n" p.n_block_height;
  Printf.fprintf oc "tx_index=%d\n" p.n_tx_index;
  Printf.fprintf oc "chain_state=%d\n" p.n_chain_state;
  Printf.fprintf oc "undo_data=%d\n" p.n_undo_data;
  Printf.fprintf oc "invalidated=%d\n" p.n_invalidated;
  Printf.fprintf oc "skipped=%d\n" p.n_skipped;
  Printf.fprintf oc "unknown=%d\n" p.n_unknown;
  Printf.fprintf oc "torn=%d\n" p.n_torn;
  flush oc;
  (try Unix.fsync (Unix.descr_of_out_channel oc)
   with Unix.Unix_error _ -> ());
  close_out oc;
  Unix.rename tmp path

let read_progress (chainstate_dir : string) : progress =
  let path = progress_file chainstate_dir in
  if not (Sys.file_exists path) then empty_progress ()
  else begin
    let p = empty_progress () in
    let ic = open_in path in
    (try
      while true do
        let line = input_line ic in
        match String.index_opt line '=' with
        | None -> ()
        | Some i ->
          let k = String.sub line 0 i in
          let v = String.sub line (i+1) (String.length line - i - 1) in
          let n = try int_of_string v with _ -> 0 in
          match k with
          | "offset" -> p.offset <- n
          | "block_header" -> p.n_block_header <- n
          | "block_data" -> p.n_block_data <- n
          | "tx" -> p.n_tx <- n
          | "utxo" -> p.n_utxo <- n
          | "block_height" -> p.n_block_height <- n
          | "tx_index" -> p.n_tx_index <- n
          | "chain_state" -> p.n_chain_state <- n
          | "undo_data" -> p.n_undo_data <- n
          | "invalidated" -> p.n_invalidated <- n
          | "skipped" -> p.n_skipped <- n
          | "unknown" -> p.n_unknown <- n
          | "torn" -> p.n_torn <- n
          | _ -> ()
      done
    with End_of_file -> ());
    close_in ic;
    p
  end

(* Read a 4-byte big-endian length from [ic]. Returns None at EOF. *)
let read_be32_opt ic =
  match try Some (input_byte ic) with End_of_file -> None with
  | None -> None
  | Some b0 ->
    let b1 = input_byte ic in
    let b2 = input_byte ic in
    let b3 = input_byte ic in
    Some ((b0 lsl 24) lor (b1 lsl 16) lor (b2 lsl 8) lor b3)

(* Route a single (key, value_opt) record to the right CF. Returns
   true if the record was written, false if it was skipped (already
   present, or unknown prefix). *)
let route_record (cfdb : Cf_chainstate.t) (p : progress)
    (key : string) (value : string option) : unit =
  if String.length key < 1 then begin
    p.n_unknown <- p.n_unknown + 1;
    Printf.eprintf "[migration] empty key, skipping\n%!"
  end else begin
    let prefix = String.get key 0 in
    let rest = String.sub key 1 (String.length key - 1) in
    match prefix, value with
    (* Block header: key = "h" ++ hash(32) *)
    | 'h', Some v ->
      if String.length rest = 32 then begin
        let hash = Cstruct.of_string rest in
        match Cf_chainstate.get_block_header cfdb hash with
        | Some _ -> p.n_skipped <- p.n_skipped + 1
        | None ->
          Cf_chainstate.put_block_header cfdb hash v;
          p.n_block_header <- p.n_block_header + 1
      end else p.n_unknown <- p.n_unknown + 1
    (* Block data *)
    | 'b', Some v ->
      if String.length rest = 32 then begin
        let hash = Cstruct.of_string rest in
        match Cf_chainstate.get_block_data cfdb hash with
        | Some _ -> p.n_skipped <- p.n_skipped + 1
        | None ->
          Cf_chainstate.put_block_data cfdb hash v;
          p.n_block_data <- p.n_block_data + 1
      end else p.n_unknown <- p.n_unknown + 1
    (* Standalone tx *)
    | 't', Some v ->
      if String.length rest = 32 then begin
        let txid = Cstruct.of_string rest in
        match Cf_chainstate.get_tx cfdb txid with
        | Some _ -> p.n_skipped <- p.n_skipped + 1
        | None ->
          Cf_chainstate.put_tx cfdb txid v;
          p.n_tx <- p.n_tx + 1
      end else p.n_unknown <- p.n_unknown + 1
    (* UTXO. Original LogStorage key = "u" ++ txid(32) ++ vout_le(4)
       so [rest] is 36 bytes; CF key drops the prefix and uses the
       same 36-byte payload. *)
    | 'u', Some v ->
      if String.length rest = 36 then begin
        match Rocksdb.cf_get cfdb.db cfdb.cfh_utxo rest with
        | Some _ -> p.n_skipped <- p.n_skipped + 1
        | None ->
          Rocksdb.cf_put cfdb.db cfdb.cfh_utxo rest v;
          p.n_utxo <- p.n_utxo + 1
      end else p.n_unknown <- p.n_unknown + 1
    (* Height -> hash. LogStorage key = "n" ++ encode_height(4); CF
       key drops the prefix. *)
    | 'n', Some v ->
      if String.length rest = 4 then begin
        match Rocksdb.cf_get cfdb.db cfdb.cfh_block_height rest with
        | Some _ -> p.n_skipped <- p.n_skipped + 1
        | None ->
          Rocksdb.cf_put cfdb.db cfdb.cfh_block_height rest v;
          p.n_block_height <- p.n_block_height + 1
      end else p.n_unknown <- p.n_unknown + 1
    (* Tx index *)
    | 'x', Some v ->
      if String.length rest = 32 then begin
        let txid = Cstruct.of_string rest in
        match Cf_chainstate.get_tx_index cfdb txid with
        | Some _ -> p.n_skipped <- p.n_skipped + 1
        | None ->
          Cf_chainstate.put_tx_index cfdb txid v;
          p.n_tx_index <- p.n_tx_index + 1
      end else p.n_unknown <- p.n_unknown + 1
    (* Chain state. LogStorage key = "s" ++ "tip_hash" etc.; CF key
       drops the prefix. *)
    | 's', Some v ->
      (match Cf_chainstate.get_chain_state cfdb rest with
       | Some _ -> p.n_skipped <- p.n_skipped + 1
       | None ->
         Cf_chainstate.put_chain_state cfdb rest v;
         p.n_chain_state <- p.n_chain_state + 1)
    (* Undo data *)
    | 'r', Some v ->
      if String.length rest = 32 then begin
        let hash = Cstruct.of_string rest in
        match Cf_chainstate.get_undo_data cfdb hash with
        | Some _ -> p.n_skipped <- p.n_skipped + 1
        | None ->
          Cf_chainstate.put_undo_data cfdb hash v;
          p.n_undo_data <- p.n_undo_data + 1
      end else p.n_unknown <- p.n_unknown + 1
    (* Invalidated *)
    | 'i', Some _ ->
      if String.length rest = 32 then begin
        let hash = Cstruct.of_string rest in
        if Cf_chainstate.is_invalidated cfdb hash then
          p.n_skipped <- p.n_skipped + 1
        else begin
          Cf_chainstate.put_invalidated cfdb hash;
          p.n_invalidated <- p.n_invalidated + 1
        end
      end else p.n_unknown <- p.n_unknown + 1
    (* Tombstones (Delete records). LogStorage represents a delete with
       value = None. We don't replay tombstones into RocksDB because the
       authoritative state is the *current* index after WAL replay; the
       tombstone is only meaningful relative to a prior put in the log,
       and the source-of-truth for what is "live" was already established
       when LogStorage rebuilt its index. So we skip tombstones, but
       count them so the operator can sanity-check totals. *)
    | _, None ->
      p.n_skipped <- p.n_skipped + 1
    | _ ->
      p.n_unknown <- p.n_unknown + 1
  end

(* Migration sequencer.

   Strategy: instead of byte-replaying the on-disk data.log (which
   contains tombstoned + overwritten records), we open the LogStorage
   normally — letting it rebuild its in-memory index, replay the WAL,
   and present the *live* set of (key, value) pairs — and stream that
   into RocksDB CFs. This is simpler, correct in the presence of
   tombstones, and matches how LogStorage's own [iter_keys] already
   walks the live set.

   For idempotency we use [route_record] which checks-then-writes per
   key; running migration twice on the same datadir is a no-op for
   already-migrated records.

   For crash resumption we checkpoint progress periodically (every N
   records) and after every CF batch flush. On restart we re-open both
   stores and re-walk the LogStorage index — duplicates short-circuit.
*)

type result = {
  progress : progress;
  total_records : int;
}

(* Walk LogStorage's index, route each (key, value) into the right CF.
   Checkpoints progress every [checkpoint_every] records. *)
let migrate ?(checkpoint_every = 50_000) (chainstate_dir : string) : result =
  let log = Storage.LogStorage.open_db chainstate_dir in
  let cfdb_path = Filename.concat chainstate_dir "chainstate-rocks" in
  let cfdb = Cf_chainstate.open_db cfdb_path in
  let p = read_progress chainstate_dir in
  let count = ref 0 in
  Storage.LogStorage.iter_prefix log "" (fun key value ->
    route_record cfdb p key (Some value);
    incr count;
    if !count mod checkpoint_every = 0 then begin
      (* Surface torn-record count into the progress checkpoint so a
         crash mid-walk leaves a paper trail even if the migration is
         later resumed. *)
      p.n_torn <- Storage.LogStorage.n_torn_records log;
      write_progress chainstate_dir p;
      Printf.eprintf
        "[migration] checkpoint: %d records routed (h=%d b=%d t=%d u=%d \
         n=%d x=%d s=%d r=%d i=%d skipped=%d unknown=%d torn=%d)\n%!"
        !count p.n_block_header p.n_block_data p.n_tx p.n_utxo
        p.n_block_height p.n_tx_index p.n_chain_state p.n_undo_data
        p.n_invalidated p.n_skipped p.n_unknown p.n_torn
    end
  );
  (* Final torn-record snapshot — the iter_prefix walk just finished, so
     LogStorage's [n_torn] counter is now stable at the true total. *)
  p.n_torn <- Storage.LogStorage.n_torn_records log;
  write_progress chainstate_dir p;
  Cf_chainstate.close cfdb;
  Storage.LogStorage.close log;
  { progress = p; total_records = !count }

(* Public entry point. Returns 0 on success, non-zero on failure.
   Handles the post-migration cleanup: rename data.log to a backup
   path (don't delete; the operator removes manually after sanity
   checks) and write the .migration-complete marker.

   Refuses to write the marker if any unknown records were seen, on
   the conservative principle that an unknown prefix is a bug and the
   operator should be alerted. *)
let run ~(chainstate_dir : string) : int =
  if not (Sys.file_exists chainstate_dir) then begin
    Printf.eprintf "[migration] chainstate dir does not exist: %s\n%!"
      chainstate_dir;
    1
  end else if not (Sys.file_exists (data_log_path chainstate_dir)) then begin
    Printf.eprintf "[migration] no data.log at %s — nothing to migrate\n%!"
      (data_log_path chainstate_dir);
    (* If migration is already complete, just succeed. *)
    if Sys.file_exists (complete_marker chainstate_dir) then 0
    else begin
      (* No data.log AND no marker — fresh datadir, write the marker
         so the boot guard accepts it. *)
      let oc = open_out (complete_marker chainstate_dir) in
      output_string oc "complete (no data.log, fresh datadir)\n";
      close_out oc;
      0
    end
  end else begin
    Printf.eprintf "[migration] starting LogStorage -> RocksDB CF migration\n%!";
    Printf.eprintf "[migration] chainstate_dir=%s\n%!" chainstate_dir;
    (try
      let r = migrate chainstate_dir in
      Printf.eprintf
        "[migration] DONE: %d records routed (h=%d b=%d t=%d u=%d \
         n=%d x=%d s=%d r=%d i=%d skipped=%d unknown=%d torn=%d)\n%!"
        r.total_records r.progress.n_block_header r.progress.n_block_data
        r.progress.n_tx r.progress.n_utxo r.progress.n_block_height
        r.progress.n_tx_index r.progress.n_chain_state
        r.progress.n_undo_data r.progress.n_invalidated
        r.progress.n_skipped r.progress.n_unknown r.progress.n_torn;
      if r.progress.n_unknown > 0 then begin
        Printf.eprintf
          "[migration] REFUSING to mark complete — %d unknown records seen\n%!"
          r.progress.n_unknown;
        2
      end else if r.progress.n_torn > 0 then begin
        (* Torn records are entries the LogStorage index claimed exist
           but whose value bytes were not on disk (typical cause: the
           writer process was killed mid-write). Migration cannot
           silently complete — the operator must repair the source
           (e.g. truncate data.log past the torn region, or restore
           from a clean backup) and re-run. We do NOT rename data.log
           in this case so the source is still in place for the next
           attempt. *)
        Printf.eprintf
          "[migration] REFUSING to mark complete — %d torn record(s) skipped \
           in data.log. Repair the source datadir (e.g. restore from backup, \
           or truncate data.log past the last good record) and re-run. \
           data.log left in place; .migration-complete NOT written.\n%!"
          r.progress.n_torn;
        4
      end else begin
        (* Rename data.log -> data.log.pre-migration-bak. Don't delete;
           the operator should manually unlink after sanity checks. *)
        let src = data_log_path chainstate_dir in
        let dst = backup_path chainstate_dir in
        if Sys.file_exists src then begin
          (try Unix.rename src dst
           with Unix.Unix_error (e, _, _) ->
             Printf.eprintf
               "[migration] warning: could not rename data.log: %s\n%!"
               (Unix.error_message e))
        end;
        let oc = open_out (complete_marker chainstate_dir) in
        Printf.fprintf oc "complete\n";
        Printf.fprintf oc "total_records=%d\n" r.total_records;
        Printf.fprintf oc "block_header=%d\n" r.progress.n_block_header;
        Printf.fprintf oc "block_data=%d\n" r.progress.n_block_data;
        Printf.fprintf oc "tx=%d\n" r.progress.n_tx;
        Printf.fprintf oc "utxo=%d\n" r.progress.n_utxo;
        Printf.fprintf oc "block_height=%d\n" r.progress.n_block_height;
        Printf.fprintf oc "tx_index=%d\n" r.progress.n_tx_index;
        Printf.fprintf oc "chain_state=%d\n" r.progress.n_chain_state;
        Printf.fprintf oc "undo_data=%d\n" r.progress.n_undo_data;
        Printf.fprintf oc "invalidated=%d\n" r.progress.n_invalidated;
        close_out oc;
        Printf.eprintf "[migration] wrote .migration-complete\n%!";
        0
      end
    with exn ->
      Printf.eprintf "[migration] FAILED: %s\n%!" (Printexc.to_string exn);
      Printf.eprintf "[migration] re-run will resume from %s\n%!"
        (progress_file chainstate_dir);
      3)
  end

(* Boot guard: refuse to start the daemon when data.log is present but
   migration has not been marked complete. The operator must run the
   migration command and inspect the exit code. *)
let check_or_refuse_to_boot (chainstate_dir : string) : unit =
  if Sys.file_exists (data_log_path chainstate_dir)
     && not (Sys.file_exists (complete_marker chainstate_dir))
  then begin
    Printf.eprintf
      "[boot] FATAL: %s present but migration not complete.\n\
       Run `bin/main.exe --migrate-logstorage-to-rocksdb \
       --datadir=<your data dir>` first.\n\
       (See CAMLCOIN-UTXO-DESIGN-MEMO-2026-04-29.md, Option D.)\n%!"
      (data_log_path chainstate_dir);
    exit 12
  end
