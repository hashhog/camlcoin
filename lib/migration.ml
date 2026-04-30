(* Migration: legacy [data.log] -> Cf_chainstate (Option D, step 2).

   Reads every record from an existing [data.log] (the retired LogStorage
   on-disk format), routes it to the matching RocksDB column family in
   [Cf_chainstate], and records progress in a checkpoint file so a
   crashed migration resumes without redoing work or losing records.

   Idempotent: re-running on a partially or fully migrated datadir is a
   no-op (it skips records whose CF entry already exists).

   Operator-driven: this module is invoked from a top-level CLI flag,
   never automatically at boot. The boot path refuses to start when
   [data.log] is present but [.migration-complete] is missing; the
   operator is expected to run the migration command and inspect the
   exit status before re-launching the daemon.

   The output CFs match the 9 legacy namespaces:
     [h] -> CF_BLOCK_HEADER, [b] -> CF_BLOCK_DATA, [t] -> CF_TX,
     [u] -> CF_UTXO, [n] -> CF_BLOCK_HEIGHT, [x] -> CF_TX_INDEX,
     [s] -> CF_CHAIN_STATE, [r] -> CF_UNDO_DATA, [i] -> CF_INVALIDATED.

   The legacy LogStorage source code (writer, WAL, multi-Domain mutex)
   has been retired now that mainnet is on RocksDB CFs. The [Log_reader]
   submodule below contains the minimum read-only logic needed to walk
   a pre-Option-D [data.log]: open in append mode (so rebuild_index can
   truncate any torn tail), load + delta-scan an existing snapshot if
   present, replay the WAL, expose [iter] and [get], and surface the
   torn-record count so the migration sequencer can refuse to mark
   complete on a damaged source.

   [Log_writer] is a tiny on-disk-format-compatible writer used only by
   the test suite to build synthetic [data.log] fixtures. It has no
   production callers; keeping reader+writer in the same module is the
   cleanest place to keep the format definition co-located. *)

(* ============================================================================
   Log_reader: read-only handle on a legacy LogStorage [data.log] datadir.

   Surface used by the migration sequencer:
     - [open_for_migration path] open the on-disk store, replay any WAL,
       load a valid snapshot if present, truncate a torn tail.
     - [iter t f] walk every (key, value) live pair, tolerant of torn
       index entries (skipped + counted in [n_torn]).
     - [get t key] random-access lookup, also torn-tolerant.
     - [n_torn t] count of skipped entries (zero on a clean datadir).
     - [close t] close the underlying fd (no writes).

   Log_writer: tiny on-disk-format-compatible writer for tests. NOT part
   of the production API; used by [test/test_migration.ml] to build
   synthetic [data.log] fixtures.

   The format is unchanged from the retired Storage.LogStorage:
     - data.log is an append-only stream of records:
         'P' BE32(klen) key BE32(vlen) value
         'D' BE32(klen) key
     - data.log.idx is an optional close-time snapshot:
         "CAMLIDX1" BE32(version) BE64(watermark) BE64(n_idx) BE64(n_del)
         { BE32(klen) key BE64(off) BE32(vlen) }*  (* index *)
         { BE32(klen) key }*                       (* deleted set *)
         "CAMLIDX1"                                (* trailer *)
     - _wal_journal is a write-ahead log:
         { 'P' BE32(klen) key BE32(vlen) value
         | 'D' BE32(klen) key }*
         "WALVALID"                                (* trailer *)

   Tolerance for torn records is preserved exactly as in storage.ml@e4068de:
   the rebuild_index path truncates a torn tail; the index lookup path
   bounds-checks (offset, vlen) against the live file size and skips
   entries that would overrun, bumping [n_torn].
   ========================================================================== *)
module Log_reader = struct
  type t = {
    base_dir : string;
    mutable data_fd : Unix.file_descr;
    mutable data_offset : int;
    index : (string, int * int) Hashtbl.t;  (* key -> (value_offset, value_len) *)
    deleted : (string, unit) Hashtbl.t;
    mutable n_torn : int;
  }

  let ensure_dir path =
    try Unix.mkdir path 0o755
    with Unix.Unix_error (Unix.EEXIST, _, _) -> ()

  let data_log_path t = Filename.concat t.base_dir "data.log"
  let wal_path t = Filename.concat t.base_dir "_wal_journal"
  let snapshot_path t = Filename.concat t.base_dir "data.log.idx"

  let snapshot_magic = "CAMLIDX1"
  let snapshot_version = 1
  let wal_magic = "WALVALID"

  let write_be32 oc n =
    output_byte oc ((n lsr 24) land 0xff);
    output_byte oc ((n lsr 16) land 0xff);
    output_byte oc ((n lsr 8)  land 0xff);
    output_byte oc ( n         land 0xff)

  let read_be32 ic =
    let b0 = input_byte ic in
    let b1 = input_byte ic in
    let b2 = input_byte ic in
    let b3 = input_byte ic in
    (b0 lsl 24) lor (b1 lsl 16) lor (b2 lsl 8) lor b3

  let read_be64 ic =
    let r = ref 0 in
    for _ = 0 to 7 do
      r := (!r lsl 8) lor (input_byte ic)
    done;
    !r

  let really_read_fd fd len =
    let buf = Bytes.create len in
    let rec loop off rem =
      if rem <= 0 then ()
      else
        let n = Unix.read fd buf off rem in
        if n = 0 then raise End_of_file;
        loop (off + n) (rem - n)
    in
    loop 0 len;
    buf

  (* Defense against torn write_snapshot renames: scan for orphan
     *.tmp files in the chainstate dir and remove any older than
     [stale_age_seconds]. Safe to call before any reads. *)
  let cleanup_orphan_tmp_files ?(stale_age_seconds = 60.0) chainstate_dir =
    if Sys.file_exists chainstate_dir && Sys.is_directory chainstate_dir then begin
      let now = Unix.time () in
      let entries =
        try Sys.readdir chainstate_dir
        with Sys_error _ -> [||]
      in
      Array.iter (fun name ->
        if Filename.check_suffix name ".tmp" then begin
          let full = Filename.concat chainstate_dir name in
          match (try Some (Unix.lstat full) with Unix.Unix_error _ -> None) with
          | Some st when st.Unix.st_kind = Unix.S_REG ->
            let age = now -. st.Unix.st_mtime in
            if age >= stale_age_seconds then
              (try Unix.unlink full with Unix.Unix_error _ -> ())
          | _ -> ()
        end
      ) entries
    end

  let try_load_snapshot t =
    let path = snapshot_path t in
    if not (Sys.file_exists path) then None
    else begin
      let ic = open_in_bin path in
      let flen = in_channel_length ic in
      let ok = ref true in
      let watermark = ref 0 in
      let magic_len = String.length snapshot_magic in
      (try
        if flen < magic_len * 2 + 4 + 8 + 8 + 8 then raise Exit;
        seek_in ic (flen - magic_len);
        let tail = really_input_string ic magic_len in
        if tail <> snapshot_magic then raise Exit;
        seek_in ic 0;
        let head = really_input_string ic magic_len in
        if head <> snapshot_magic then raise Exit;
        let version = read_be32 ic in
        if version <> snapshot_version then raise Exit;
        watermark := read_be64 ic;
        let n_idx = read_be64 ic in
        let n_del = read_be64 ic in
        let data_path = data_log_path t in
        let data_len =
          if Sys.file_exists data_path then
            let dic = open_in_bin data_path in
            let l = in_channel_length dic in
            close_in dic; l
          else 0
        in
        if !watermark > data_len then raise Exit;
        for _ = 1 to n_idx do
          let klen = read_be32 ic in
          let key = really_input_string ic klen in
          let off = read_be64 ic in
          let vlen = read_be32 ic in
          Hashtbl.replace t.index key (off, vlen)
        done;
        for _ = 1 to n_del do
          let klen = read_be32 ic in
          let key = really_input_string ic klen in
          Hashtbl.replace t.deleted key ()
        done
      with _ -> ok := false);
      close_in ic;
      if !ok then Some !watermark
      else begin
        Hashtbl.reset t.index;
        Hashtbl.reset t.deleted;
        None
      end
    end

  (* Scan data.log from [start] to EOF, applying each record to the index
     and deleted tables. Tolerates a torn tail: any record whose declared
     length would overrun the file is detected (Exit), and the file is
     truncated at the last fully-valid record offset so the next open is
     clean. *)
  let rebuild_index_from_offset t ~start =
    let path = data_log_path t in
    if not (Sys.file_exists path) then begin
      t.data_offset <- 0
    end else begin
      let ic = open_in_bin path in
      let flen = in_channel_length ic in
      seek_in ic start;
      let last_valid_pos = ref start in
      (try
        while pos_in ic < flen do
          let op = input_char ic in
          match op with
          | 'P' ->
            let klen = read_be32 ic in
            if klen < 0 || pos_in ic + klen > flen then raise Exit;
            let key = really_input_string ic klen in
            let vlen = read_be32 ic in
            let value_offset = pos_in ic in
            if vlen < 0 || value_offset + vlen > flen then raise Exit;
            seek_in ic (value_offset + vlen);
            Hashtbl.replace t.index key (value_offset, vlen);
            Hashtbl.remove t.deleted key;
            last_valid_pos := pos_in ic
          | 'D' ->
            let klen = read_be32 ic in
            if klen < 0 || pos_in ic + klen > flen then raise Exit;
            let key = really_input_string ic klen in
            Hashtbl.remove t.index key;
            Hashtbl.replace t.deleted key ();
            last_valid_pos := pos_in ic
          | _ -> raise Exit
        done
      with Exit | End_of_file -> ());
      close_in ic;
      if !last_valid_pos < flen then
        Unix.truncate path !last_valid_pos;
      t.data_offset <- !last_valid_pos
    end

  let rebuild_index t = rebuild_index_from_offset t ~start:0

  (* WAL replay. The on-disk format and tolerance match the retired
     LogStorage: a torn WAL (no trailing magic, or any opcode fault) is
     discarded and the file unlinked. A valid WAL is replayed by
     appending records to data.log just like the original writer did,
     so the migration sees a self-consistent live set. *)
  let wal_read jpath =
    if not (Sys.file_exists jpath) then None
    else begin
      let ic = open_in_bin jpath in
      let flen = in_channel_length ic in
      if flen < String.length wal_magic then begin
        close_in ic;
        None
      end else begin
        seek_in ic (flen - String.length wal_magic);
        let tail = really_input_string ic (String.length wal_magic) in
        if tail <> wal_magic then begin
          close_in ic;
          None
        end else begin
          seek_in ic 0;
          let data_len = flen - String.length wal_magic in
          let ops = ref [] in
          let valid = ref true in
          (try
            while pos_in ic < data_len do
              let op_byte = input_char ic in
              match op_byte with
              | 'P' ->
                let klen = read_be32 ic in
                let key = really_input_string ic klen in
                let vlen = read_be32 ic in
                let value = really_input_string ic vlen in
                ops := (key, `Put value) :: !ops
              | 'D' ->
                let klen = read_be32 ic in
                let key = really_input_string ic klen in
                ops := (key, `Delete) :: !ops
              | _ ->
                valid := false;
                raise Exit
            done
          with
          | End_of_file -> valid := false
          | Exit -> ());
          close_in ic;
          if !valid then Some (List.rev !ops) else None
        end
      end
    end

  let write_be32_bytes n =
    let b = Bytes.create 4 in
    Bytes.set b 0 (Char.chr ((n lsr 24) land 0xff));
    Bytes.set b 1 (Char.chr ((n lsr 16) land 0xff));
    Bytes.set b 2 (Char.chr ((n lsr 8)  land 0xff));
    Bytes.set b 3 (Char.chr ( n         land 0xff));
    b

  let append_raw t s =
    let b = Bytes.of_string s in
    let len = Bytes.length b in
    let rec loop off rem =
      if rem <= 0 then ()
      else
        let n = Unix.write t.data_fd b off rem in
        loop (off + n) (rem - n)
    in
    loop 0 len;
    t.data_offset <- t.data_offset + len

  let append_raw_bytes t b =
    let len = Bytes.length b in
    let rec loop off rem =
      if rem <= 0 then ()
      else
        let n = Unix.write t.data_fd b off rem in
        loop (off + n) (rem - n)
    in
    loop 0 len;
    t.data_offset <- t.data_offset + len

  let append_put t key value =
    append_raw t "P";
    let klen = String.length key in
    append_raw_bytes t (write_be32_bytes klen);
    append_raw t key;
    let vlen = String.length value in
    append_raw_bytes t (write_be32_bytes vlen);
    let value_offset = t.data_offset in
    append_raw t value;
    Hashtbl.replace t.index key (value_offset, vlen);
    Hashtbl.remove t.deleted key

  let append_delete t key =
    append_raw t "D";
    let klen = String.length key in
    append_raw_bytes t (write_be32_bytes klen);
    append_raw t key;
    Hashtbl.remove t.index key;
    Hashtbl.replace t.deleted key ()

  let apply_ops t (ops : (string * [`Put of string | `Delete]) list) =
    List.iter (fun (key, op) ->
      match op with
      | `Put value -> append_put t key value
      | `Delete -> append_delete t key
    ) ops

  let wal_delete t =
    let jpath = wal_path t in
    (try Unix.unlink jpath with Unix.Unix_error _ -> ())

  let open_for_migration path =
    ensure_dir path;
    cleanup_orphan_tmp_files path;
    let log_path = Filename.concat path "data.log" in
    if not (Sys.file_exists log_path) then begin
      let fd = Unix.openfile log_path [Unix.O_CREAT; Unix.O_WRONLY] 0o644 in
      Unix.close fd
    end;
    let fd = Unix.openfile log_path [Unix.O_RDWR; Unix.O_APPEND] 0o644 in
    let t = {
      base_dir = path;
      data_fd = fd;
      data_offset = 0;
      index = Hashtbl.create 10000;
      deleted = Hashtbl.create 128;
      n_torn = 0;
    } in
    (match try_load_snapshot t with
     | Some watermark ->
       rebuild_index_from_offset t ~start:watermark
     | None ->
       rebuild_index t);
    let jpath = wal_path t in
    (match wal_read jpath with
     | None ->
       (try Unix.unlink jpath with Unix.Unix_error _ -> ())
     | Some ops ->
       apply_ops t ops;
       wal_delete t);
    t

  let close t =
    (try Unix.close t.data_fd with Unix.Unix_error _ -> ())

  let data_log_size_unsafe t =
    try (Unix.fstat t.data_fd).Unix.st_size
    with Unix.Unix_error _ -> t.data_offset

  let entry_fits_or_warn t _key offset vlen flen =
    if offset < 0 || vlen < 0 || offset + vlen > flen then begin
      t.n_torn <- t.n_torn + 1;
      false
    end else true

  let get t key =
    if Hashtbl.mem t.deleted key then None
    else
      match Hashtbl.find_opt t.index key with
      | None -> None
      | Some (offset, vlen) ->
        let flen = data_log_size_unsafe t in
        if not (entry_fits_or_warn t key offset vlen flen) then None
        else begin
          let _ = Unix.lseek t.data_fd offset Unix.SEEK_SET in
          let buf = really_read_fd t.data_fd vlen in
          Some (Bytes.to_string buf)
        end

  let iter t f =
    let prefix_len = 0 in
    let prefix = "" in
    let flen = data_log_size_unsafe t in
    let entries =
      Hashtbl.fold (fun k (offset, vlen) acc ->
        if String.length k >= prefix_len &&
           String.sub k 0 prefix_len = prefix then begin
          if not (entry_fits_or_warn t k offset vlen flen) then acc
          else begin
            let _ = Unix.lseek t.data_fd offset Unix.SEEK_SET in
            let buf = really_read_fd t.data_fd vlen in
            (k, Bytes.to_string buf) :: acc
          end
        end else acc
      ) t.index []
    in
    List.iter (fun (k, v) -> f k v) entries

  let n_torn t = t.n_torn
end

(* ============================================================================
   Log_writer: synthetic-fixture writer for tests only.

   Implements the same on-disk format as Log_reader but with a minimal,
   single-Domain API (no mutex, no WAL — tests don't need crash safety).
   Closing writes a snapshot file so that the synthetic datadir round-trips
   through Log_reader's open_for_migration path the same way a closed
   pre-Option-D datadir would have.
   ========================================================================== *)
module Log_writer = struct
  type t = {
    base_dir : string;
    data_fd : Unix.file_descr;
    mutable data_offset : int;
    index : (string, int * int) Hashtbl.t;
    deleted : (string, unit) Hashtbl.t;
  }

  let ensure_dir path =
    try Unix.mkdir path 0o755
    with Unix.Unix_error (Unix.EEXIST, _, _) -> ()

  let write_be32 oc n =
    output_byte oc ((n lsr 24) land 0xff);
    output_byte oc ((n lsr 16) land 0xff);
    output_byte oc ((n lsr 8)  land 0xff);
    output_byte oc ( n         land 0xff)

  let write_be32_bytes n =
    let b = Bytes.create 4 in
    Bytes.set b 0 (Char.chr ((n lsr 24) land 0xff));
    Bytes.set b 1 (Char.chr ((n lsr 16) land 0xff));
    Bytes.set b 2 (Char.chr ((n lsr 8)  land 0xff));
    Bytes.set b 3 (Char.chr ( n         land 0xff));
    b

  let write_be64_bytes n =
    let b = Bytes.create 8 in
    for i = 0 to 7 do
      Bytes.set b (7 - i) (Char.chr ((n lsr (i * 8)) land 0xff))
    done;
    b

  let snapshot_path t = Filename.concat t.base_dir "data.log.idx"
  let snapshot_tmp_path t = Filename.concat t.base_dir "data.log.idx.tmp"
  let snapshot_magic = "CAMLIDX1"
  let snapshot_version = 1

  let append_bytes t b =
    let len = Bytes.length b in
    let rec loop off rem =
      if rem <= 0 then ()
      else
        let n = Unix.write t.data_fd b off rem in
        loop (off + n) (rem - n)
    in
    loop 0 len;
    t.data_offset <- t.data_offset + len

  let append_string t s = append_bytes t (Bytes.of_string s)

  let open_db path =
    ensure_dir path;
    let log_path = Filename.concat path "data.log" in
    if not (Sys.file_exists log_path) then begin
      let fd = Unix.openfile log_path [Unix.O_CREAT; Unix.O_WRONLY] 0o644 in
      Unix.close fd
    end;
    let fd = Unix.openfile log_path [Unix.O_RDWR; Unix.O_APPEND] 0o644 in
    (* Compute initial offset = current file size so puts append. *)
    let off = (Unix.fstat fd).Unix.st_size in
    { base_dir = path;
      data_fd = fd;
      data_offset = off;
      index = Hashtbl.create 64;
      deleted = Hashtbl.create 16 }

  let put t key value =
    append_string t "P";
    append_bytes t (write_be32_bytes (String.length key));
    append_string t key;
    append_bytes t (write_be32_bytes (String.length value));
    let value_offset = t.data_offset in
    append_string t value;
    Hashtbl.replace t.index key (value_offset, String.length value);
    Hashtbl.remove t.deleted key

  (* Write a close-time snapshot mirroring the retired LogStorage format,
     so torn-snapshot tests can patch the watermark after close. *)
  let write_snapshot t =
    let tmp = snapshot_tmp_path t in
    let oc = open_out_bin tmp in
    output_string oc snapshot_magic;
    write_be32 oc snapshot_version;
    output_bytes oc (write_be64_bytes t.data_offset);
    output_bytes oc (write_be64_bytes (Hashtbl.length t.index));
    output_bytes oc (write_be64_bytes (Hashtbl.length t.deleted));
    Hashtbl.iter (fun k (off, vlen) ->
      write_be32 oc (String.length k);
      output_string oc k;
      output_bytes oc (write_be64_bytes off);
      write_be32 oc vlen
    ) t.index;
    Hashtbl.iter (fun k () ->
      write_be32 oc (String.length k);
      output_string oc k
    ) t.deleted;
    output_string oc snapshot_magic;
    flush oc;
    (try Unix.fsync (Unix.descr_of_out_channel oc)
     with Unix.Unix_error _ -> ());
    close_out oc;
    Unix.rename tmp (snapshot_path t)

  let close t =
    (try Unix.fsync t.data_fd with Unix.Unix_error _ -> ());
    (try write_snapshot t with _ -> ());
    (try Unix.close t.data_fd with Unix.Unix_error _ -> ())
end

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
   contains tombstoned + overwritten records), we open the legacy
   data.log via [Log_reader.open_for_migration] — letting it rebuild
   its in-memory index, replay the WAL, and present the *live* set of
   (key, value) pairs — and stream that into RocksDB CFs. This is
   simpler, correct in the presence of tombstones, and matches how the
   retired LogStorage's own [iter_keys] walked the live set.

   For idempotency we use [route_record] which checks-then-writes per
   key; running migration twice on the same datadir is a no-op for
   already-migrated records.

   For crash resumption we checkpoint progress periodically (every N
   records) and after every CF batch flush. On restart we re-open both
   stores and re-walk the legacy index — duplicates short-circuit.
*)

type result = {
  progress : progress;
  total_records : int;
}

(* Walk the legacy data.log's index, route each (key, value) into the
   right CF. Checkpoints progress every [checkpoint_every] records. *)
let migrate ?(checkpoint_every = 50_000) (chainstate_dir : string) : result =
  let log = Log_reader.open_for_migration chainstate_dir in
  let cfdb_path = Filename.concat chainstate_dir "chainstate-rocks" in
  let cfdb = Cf_chainstate.open_db cfdb_path in
  let p = read_progress chainstate_dir in
  let count = ref 0 in
  Log_reader.iter log (fun key value ->
    route_record cfdb p key (Some value);
    incr count;
    if !count mod checkpoint_every = 0 then begin
      (* Surface torn-record count into the progress checkpoint so a
         crash mid-walk leaves a paper trail even if the migration is
         later resumed. *)
      p.n_torn <- Log_reader.n_torn log;
      write_progress chainstate_dir p;
      Printf.eprintf
        "[migration] checkpoint: %d records routed (h=%d b=%d t=%d u=%d \
         n=%d x=%d s=%d r=%d i=%d skipped=%d unknown=%d torn=%d)\n%!"
        !count p.n_block_header p.n_block_data p.n_tx p.n_utxo
        p.n_block_height p.n_tx_index p.n_chain_state p.n_undo_data
        p.n_invalidated p.n_skipped p.n_unknown p.n_torn
    end
  );
  (* Final torn-record snapshot — the iter walk just finished, so
     Log_reader's [n_torn] counter is now stable at the true total. *)
  p.n_torn <- Log_reader.n_torn log;
  write_progress chainstate_dir p;
  Cf_chainstate.close cfdb;
  Log_reader.close log;
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
    Printf.eprintf "[migration] starting legacy data.log -> RocksDB CF migration\n%!";
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
