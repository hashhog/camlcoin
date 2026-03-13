(* Database layer using file-based storage (RocksDB fallback) *)

(* TODO: For production use with millions of UTXOs, replace FileStorage with
   a proper embedded key-value store (LevelDB, RocksDB, or LMDB) via an opam
   binding. The current file-per-key approach does not scale beyond ~100k keys
   due to filesystem overhead. The WAL provides crash-safety but not the
   throughput a real blockchain node needs. *)

(* Storage module signature *)
module type STORAGE = sig
  type t
  type batch

  val open_db : string -> t
  val close : t -> unit

  val get : t -> string -> string option
  val put : t -> string -> string -> unit
  val delete : t -> string -> unit

  val batch_create : unit -> batch
  val batch_put : batch -> string -> string -> unit
  val batch_delete : batch -> string -> unit
  val batch_write : t -> batch -> unit

  val iter_prefix : t -> string -> (string -> string -> unit) -> unit

  val sync : t -> unit
end

(* File-based storage implementation for development without RocksDB.
   Provides crash-safe batch writes via a write-ahead log (WAL) and
   disk-scanning iter_prefix that does not rely solely on the in-memory cache. *)
module FileStorage : STORAGE = struct
  type t = {
    base_dir : string;
    mutable cache : (string, string) Hashtbl.t;
    (* Keys that have been deleted in this session but may still have files
       on disk. Tracked so iter_prefix can skip them without a file check. *)
    mutable deleted_keys : (string, unit) Hashtbl.t;
  }

  type batch = (string * [`Put of string | `Delete]) list ref

  (* --- Path helpers --------------------------------------------------- *)

  let key_to_path t key =
    let hex = Types.hash256_to_hex (Crypto.sha256 (Cstruct.of_string key)) in
    Filename.concat t.base_dir (String.sub hex 0 2)
    |> fun dir -> Filename.concat dir hex

  let ensure_dir path =
    try Unix.mkdir path 0o755
    with Unix.Unix_error (Unix.EEXIST, _, _) -> ()

  (* --- On-disk file format -------------------------------------------- *)
  (* Each data file stores: [4-byte BE key_len][key bytes][value bytes]
     This allows iter_prefix to recover the original key from any file,
     since the filename is the SHA-256 of the key (a one-way hash). *)

  let write_data_file path key value =
    let dir = Filename.dirname path in
    ensure_dir dir;
    let tmp = path ^ ".tmp" in
    let oc = open_out_bin tmp in
    (* Write key length as 4-byte big-endian *)
    let klen = String.length key in
    output_byte oc ((klen lsr 24) land 0xff);
    output_byte oc ((klen lsr 16) land 0xff);
    output_byte oc ((klen lsr 8)  land 0xff);
    output_byte oc ( klen         land 0xff);
    output_string oc key;
    output_string oc value;
    close_out oc;
    (* Atomic rename *)
    Unix.rename tmp path

  let read_data_file path =
    (* Returns (key, value) *)
    let ic = open_in_bin path in
    let len = in_channel_length ic in
    if len < 4 then begin
      close_in ic;
      None  (* corrupt or legacy file *)
    end else begin
      let b0 = input_byte ic in
      let b1 = input_byte ic in
      let b2 = input_byte ic in
      let b3 = input_byte ic in
      let klen = (b0 lsl 24) lor (b1 lsl 16) lor (b2 lsl 8) lor b3 in
      if klen < 0 || 4 + klen > len then begin
        close_in ic;
        None
      end else begin
        let key = really_input_string ic klen in
        let vlen = len - 4 - klen in
        let value = really_input_string ic vlen in
        close_in ic;
        Some (key, value)
      end
    end

  (* Legacy support: read a file that has no key header (just raw value).
     We cannot recover the key, but we can still return the value if the
     caller already knows the key. *)
  let read_value_for_key path =
    let ic = open_in_bin path in
    let len = in_channel_length ic in
    if len < 4 then begin
      (* Too short to have a header -- treat entire content as value *)
      let data = really_input_string ic len in
      close_in ic;
      Some data
    end else begin
      (* Peek at key-length header *)
      let b0 = input_byte ic in
      let b1 = input_byte ic in
      let b2 = input_byte ic in
      let b3 = input_byte ic in
      let klen = (b0 lsl 24) lor (b1 lsl 16) lor (b2 lsl 8) lor b3 in
      if klen >= 0 && 4 + klen <= len then begin
        (* Looks like new format: skip key, return value *)
        let _key = really_input_string ic klen in
        let vlen = len - 4 - klen in
        let value = really_input_string ic vlen in
        close_in ic;
        Some value
      end else begin
        (* Not new format -- treat entire file as raw value (legacy) *)
        seek_in ic 0;
        let data = really_input_string ic len in
        close_in ic;
        Some data
      end
    end

  (* --- Write-ahead log (WAL) ----------------------------------------- *)
  (* Journal format (one record per operation, all lengths big-endian):
       [1 byte op]  -- 'P' for put, 'D' for delete
       [4 bytes key_len]
       [key bytes]
       For 'P' only:
         [4 bytes value_len]
         [value bytes]
     The journal ends with 8 magic bytes "WALVALID" written after all
     records have been fsynced.  On replay we only apply a journal whose
     last 8 bytes are "WALVALID" -- an incomplete journal is discarded. *)

  let wal_path t = Filename.concat t.base_dir "_wal_journal"

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

  let wal_magic = "WALVALID"

  (* Write a complete, synced journal for a batch of operations.
     Returns the path to the journal file. *)
  let wal_write t (ops : (string * [`Put of string | `Delete]) list) =
    let jpath = wal_path t in
    let oc = open_out_bin jpath in
    List.iter (fun (key, op) ->
      match op with
      | `Put value ->
        output_char oc 'P';
        write_be32 oc (String.length key);
        output_string oc key;
        write_be32 oc (String.length value);
        output_string oc value
      | `Delete ->
        output_char oc 'D';
        write_be32 oc (String.length key);
        output_string oc key
    ) ops;
    output_string oc wal_magic;
    flush oc;
    (* fsync the journal so it is durable before we apply *)
    let fd = Unix.descr_of_out_channel oc in
    (try Unix.fsync fd with Unix.Unix_error _ -> ());
    close_out oc

  (* Parse a journal file and return the list of operations, or None
     if the journal is invalid / incomplete. *)
  let wal_read jpath : (string * [`Put of string | `Delete]) list option =
    if not (Sys.file_exists jpath) then None
    else begin
      let ic = open_in_bin jpath in
      let flen = in_channel_length ic in
      if flen < String.length wal_magic then begin
        close_in ic;
        None
      end else begin
        (* Check magic at the end *)
        seek_in ic (flen - String.length wal_magic);
        let tail = really_input_string ic (String.length wal_magic) in
        if tail <> wal_magic then begin
          close_in ic;
          None  (* incomplete journal -- discard *)
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

  let wal_delete t =
    let jpath = wal_path t in
    (try Unix.unlink jpath with Unix.Unix_error _ -> ())

  (* Apply a list of operations directly to disk + cache. Used both for
     normal batch_write (after journal is written) and for WAL replay. *)
  let apply_ops t (ops : (string * [`Put of string | `Delete]) list) =
    List.iter (fun (key, op) ->
      match op with
      | `Put value ->
        Hashtbl.replace t.cache key value;
        Hashtbl.remove t.deleted_keys key;
        let path = key_to_path t key in
        write_data_file path key value
      | `Delete ->
        Hashtbl.remove t.cache key;
        Hashtbl.replace t.deleted_keys key ();
        let path = key_to_path t key in
        (try Unix.unlink path with Unix.Unix_error _ -> ())
    ) ops

  (* Replay any incomplete WAL found on startup *)
  let wal_replay t =
    let jpath = wal_path t in
    match wal_read jpath with
    | None ->
      (* No valid journal -- remove stale file if present *)
      (try Unix.unlink jpath with Unix.Unix_error _ -> ())
    | Some ops ->
      apply_ops t ops;
      wal_delete t

  (* --- Public API ----------------------------------------------------- *)

  let open_db path =
    ensure_dir path;
    let t = {
      base_dir = path;
      cache = Hashtbl.create 10000;
      deleted_keys = Hashtbl.create 128;
    } in
    (* Crash recovery: replay WAL if present *)
    wal_replay t;
    t

  let close _t = ()

  (* Flush the in-memory cache to disk.  Every cached key that does NOT
     already have a corresponding file on disk is written out.  This is a
     best-effort durability measure – it does NOT use the WAL, so it is
     not atomic, but it guarantees that no cached data is silently lost
     when the process exits. *)
  let sync (t : t) : unit =
    Hashtbl.iter (fun key value ->
      let path = key_to_path t key in
      (* Only write if the file does not exist yet – avoids redundant I/O
         for entries that were already persisted via put / batch_write. *)
      if not (Sys.file_exists path) then
        write_data_file path key value
    ) t.cache

  let get t key =
    if Hashtbl.mem t.deleted_keys key then None
    else
      match Hashtbl.find_opt t.cache key with
      | Some v -> Some v
      | None ->
        let path = key_to_path t key in
        if Sys.file_exists path then begin
          match read_value_for_key path with
          | Some data ->
            Hashtbl.replace t.cache key data;
            Some data
          | None -> None
        end else None

  let put t key value =
    Hashtbl.replace t.cache key value;
    Hashtbl.remove t.deleted_keys key;
    let path = key_to_path t key in
    write_data_file path key value

  let delete t key =
    Hashtbl.remove t.cache key;
    Hashtbl.replace t.deleted_keys key ();
    let path = key_to_path t key in
    (try Unix.unlink path with Unix.Unix_error _ -> ())

  let batch_create () = ref []
  let batch_put b key value = b := (key, `Put value) :: !b
  let batch_delete b key = b := (key, `Delete) :: !b

  (* Atomic batch write via write-ahead log:
     1. Write all operations to the journal file and fsync
     2. Apply operations to disk + cache
     3. Delete the journal
     If the process crashes between 1 and 3, the next open_db will replay
     the journal, ensuring all-or-nothing semantics. *)
  let batch_write t b =
    let ops = List.rev !b in
    if ops <> [] then begin
      wal_write t ops;
      apply_ops t ops;
      wal_delete t
    end

  (* Iterate over all entries whose key starts with [prefix].
     Scans both the in-memory cache AND the on-disk files so that
     entries not yet loaded into the cache are still visited.

     Algorithm:
     1. Collect matching keys from the cache.
     2. Walk every subdirectory of base_dir, read each data file to
        recover its key, and if it matches the prefix and is NOT already
        in the set from step 1, yield it as well.
     Cache entries take precedence (they are always the freshest). *)
  let iter_prefix t prefix f =
    let prefix_len = String.length prefix in
    let seen = Hashtbl.create 256 in
    (* Phase 1: cache entries *)
    Hashtbl.iter (fun k v ->
      if String.length k >= prefix_len &&
         String.sub k 0 prefix_len = prefix then begin
        f k v;
        Hashtbl.replace seen k ()
      end
    ) t.cache;
    (* Phase 2: scan disk *)
    let scan_dir subdir_path =
      if Sys.file_exists subdir_path && Sys.is_directory subdir_path then begin
        let entries = Sys.readdir subdir_path in
        Array.iter (fun fname ->
          (* Skip temporary and WAL files *)
          if not (String.length fname > 4 &&
                  String.sub fname (String.length fname - 4) 4 = ".tmp") then begin
            let fpath = Filename.concat subdir_path fname in
            if not (Sys.is_directory fpath) then begin
              match read_data_file fpath with
              | Some (key, value) ->
                if not (Hashtbl.mem seen key) &&
                   not (Hashtbl.mem t.deleted_keys key) &&
                   String.length key >= prefix_len &&
                   String.sub key 0 prefix_len = prefix then begin
                  f key value;
                  Hashtbl.replace seen key ()
                end
              | None -> ()  (* corrupt / legacy file without key header *)
            end
          end
        ) entries
      end
    in
    (* Walk the two-character hex subdirectories *)
    if Sys.file_exists t.base_dir && Sys.is_directory t.base_dir then begin
      let subdirs = Sys.readdir t.base_dir in
      Array.iter (fun name ->
        let spath = Filename.concat t.base_dir name in
        (* Only descend into 2-char hex subdirectories *)
        if String.length name = 2 && Sys.is_directory spath then
          scan_dir spath
      ) subdirs
    end
end

(* Append-only log storage implementation.  All key-value pairs live in a
   single file (data.log) with an in-memory hash-table index that is rebuilt
   on open by scanning the log.  This avoids the filesystem-overhead-per-key
   problem of FileStorage while requiring no external C libraries. *)
module LogStorage : STORAGE = struct
  type t = {
    base_dir : string;
    mutable data_fd : Unix.file_descr;
    mutable data_offset : int;
    index : (string, int * int) Hashtbl.t;  (* key -> (value_offset, value_len) *)
    deleted : (string, unit) Hashtbl.t;
  }

  type batch = (string * [`Put of string | `Delete]) list ref

  (* --- helpers --------------------------------------------------------- *)

  let ensure_dir path =
    try Unix.mkdir path 0o755
    with Unix.Unix_error (Unix.EEXIST, _, _) -> ()

  let write_be32_bytes n =
    let b = Bytes.create 4 in
    Bytes.set b 0 (Char.chr ((n lsr 24) land 0xff));
    Bytes.set b 1 (Char.chr ((n lsr 16) land 0xff));
    Bytes.set b 2 (Char.chr ((n lsr 8)  land 0xff));
    Bytes.set b 3 (Char.chr ( n         land 0xff));
    b

  let read_be32_from buf off =
    let b0 = Char.code (Bytes.get buf off) in
    let b1 = Char.code (Bytes.get buf (off+1)) in
    let b2 = Char.code (Bytes.get buf (off+2)) in
    let b3 = Char.code (Bytes.get buf (off+3)) in
    (b0 lsl 24) lor (b1 lsl 16) lor (b2 lsl 8) lor b3

  let data_log_path t = Filename.concat t.base_dir "data.log"

  let wal_path t = Filename.concat t.base_dir "_wal_journal"

  (* Fully read [len] bytes from fd at current position *)
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

  (* Append raw bytes string to data.log, advance data_offset *)
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

  (* --- WAL (reused logic from FileStorage, adapted) -------------------- *)

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

  let wal_write t (ops : (string * [`Put of string | `Delete]) list) =
    let jpath = wal_path t in
    let oc = open_out_bin jpath in
    List.iter (fun (key, op) ->
      match op with
      | `Put value ->
        output_char oc 'P';
        write_be32 oc (String.length key);
        output_string oc key;
        write_be32 oc (String.length value);
        output_string oc value
      | `Delete ->
        output_char oc 'D';
        write_be32 oc (String.length key);
        output_string oc key
    ) ops;
    output_string oc wal_magic;
    flush oc;
    let fd = Unix.descr_of_out_channel oc in
    (try Unix.fsync fd with Unix.Unix_error _ -> ());
    close_out oc

  let wal_read jpath : (string * [`Put of string | `Delete]) list option =
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

  let wal_delete t =
    let jpath = wal_path t in
    (try Unix.unlink jpath with Unix.Unix_error _ -> ())

  (* --- Append operations to data.log ----------------------------------- *)

  (* Append a put record and update the index. Returns unit. *)
  let append_put t key value =
    (* op byte *)
    append_raw t "P";
    (* key length + key *)
    let klen = String.length key in
    append_raw_bytes t (write_be32_bytes klen);
    append_raw t key;
    (* value length + value *)
    let vlen = String.length value in
    append_raw_bytes t (write_be32_bytes vlen);
    let value_offset = t.data_offset in
    append_raw t value;
    (* update index *)
    Hashtbl.replace t.index key (value_offset, vlen);
    Hashtbl.remove t.deleted key

  let append_delete t key =
    append_raw t "D";
    let klen = String.length key in
    append_raw_bytes t (write_be32_bytes klen);
    append_raw t key;
    Hashtbl.remove t.index key;
    Hashtbl.replace t.deleted key ()

  (* Apply WAL ops by appending to data.log *)
  let apply_ops t (ops : (string * [`Put of string | `Delete]) list) =
    List.iter (fun (key, op) ->
      match op with
      | `Put value -> append_put t key value
      | `Delete -> append_delete t key
    ) ops

  (* --- Scan data.log to rebuild the in-memory index -------------------- *)

  let rebuild_index t =
    let path = data_log_path t in
    (* Read entire file into memory for fast scanning *)
    let ic = open_in_bin path in
    let flen = in_channel_length ic in
    let buf =
      if flen > 0 then begin
        let b = Bytes.create flen in
        really_input ic b 0 flen;
        b
      end else
        Bytes.empty
    in
    close_in ic;
    let pos = ref 0 in
    (try
      while !pos < flen do
        let op = Bytes.get buf !pos in
        pos := !pos + 1;
        match op with
        | 'P' ->
          if !pos + 4 > flen then raise Exit;
          let klen = read_be32_from buf !pos in
          pos := !pos + 4;
          if !pos + klen > flen then raise Exit;
          let key = Bytes.sub_string buf !pos klen in
          pos := !pos + klen;
          if !pos + 4 > flen then raise Exit;
          let vlen = read_be32_from buf !pos in
          pos := !pos + 4;
          if !pos + vlen > flen then raise Exit;
          let value_offset = !pos in
          pos := !pos + vlen;
          (* last write wins *)
          Hashtbl.replace t.index key (value_offset, vlen);
          Hashtbl.remove t.deleted key
        | 'D' ->
          if !pos + 4 > flen then raise Exit;
          let klen = read_be32_from buf !pos in
          pos := !pos + 4;
          if !pos + klen > flen then raise Exit;
          let key = Bytes.sub_string buf !pos klen in
          pos := !pos + klen;
          Hashtbl.remove t.index key;
          Hashtbl.replace t.deleted key ()
        | _ -> raise Exit  (* corrupt -- stop scanning *)
      done
    with Exit -> ());
    t.data_offset <- flen

  (* --- Public API ------------------------------------------------------ *)

  let open_db path =
    ensure_dir path;
    let log_path = Filename.concat path "data.log" in
    (* Create data.log if it doesn't exist *)
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
    } in
    rebuild_index t;
    (* Replay WAL if present *)
    let jpath = Filename.concat path "_wal_journal" in
    (match wal_read jpath with
     | None ->
       (try Unix.unlink jpath with Unix.Unix_error _ -> ())
     | Some ops ->
       apply_ops t ops;
       wal_delete t);
    t

  let close t =
    (try Unix.fsync t.data_fd with Unix.Unix_error _ -> ());
    (try Unix.close t.data_fd with Unix.Unix_error _ -> ())

  let sync t =
    (try Unix.fsync t.data_fd with Unix.Unix_error _ -> ())

  let get t key =
    if Hashtbl.mem t.deleted key then None
    else
      match Hashtbl.find_opt t.index key with
      | None -> None
      | Some (offset, vlen) ->
        let _ = Unix.lseek t.data_fd offset Unix.SEEK_SET in
        let buf = really_read_fd t.data_fd vlen in
        Some (Bytes.to_string buf)

  let put t key value = append_put t key value

  let delete t key = append_delete t key

  let batch_create () = ref []
  let batch_put b key value = b := (key, `Put value) :: !b
  let batch_delete b key = b := (key, `Delete) :: !b

  let batch_write t b =
    let ops = List.rev !b in
    if ops <> [] then begin
      wal_write t ops;
      apply_ops t ops;
      wal_delete t
    end

  let iter_prefix t prefix f =
    let prefix_len = String.length prefix in
    Hashtbl.iter (fun k (offset, vlen) ->
      if String.length k >= prefix_len &&
         String.sub k 0 prefix_len = prefix then begin
        let _ = Unix.lseek t.data_fd offset Unix.SEEK_SET in
        let buf = really_read_fd t.data_fd vlen in
        f k (Bytes.to_string buf)
      end
    ) t.index
end

(* Key prefix constants for namespace separation *)
let prefix_block_header = "h"
let prefix_block_data   = "b"
let prefix_tx           = "t"
let prefix_utxo         = "u"
let prefix_block_height = "n"
let prefix_tx_index     = "x"
let prefix_chain_state  = "s"
let prefix_undo_data    = "r"  (* undo data for chain reorg *)

(* Higher-level chain database built on top of the storage layer *)
module ChainDB = struct
  type t = { db : LogStorage.t }

  let create path = { db = LogStorage.open_db path }
  let close t = LogStorage.close t.db

  (* Flush any cached-but-not-yet-persisted data to disk.  Call before
     close to ensure no writes are lost on shutdown. *)
  let sync t = LogStorage.sync t.db

  (* Encode height as 4-byte big-endian for lexicographic sorting *)
  let encode_height (h : int) : string =
    let cs = Cstruct.create 4 in
    Cstruct.BE.set_uint32 cs 0 (Int32.of_int h);
    Cstruct.to_string cs

  let decode_height (s : string) : int =
    let cs = Cstruct.of_string s in
    Int32.to_int (Cstruct.BE.get_uint32 cs 0)

  (* Block header storage *)
  let store_block_header t (hash : Types.hash256) (header : Types.block_header) =
    let w = Serialize.writer_create () in
    Serialize.serialize_block_header w header;
    let key = prefix_block_header ^ Cstruct.to_string hash in
    LogStorage.put t.db key
      (Cstruct.to_string (Serialize.writer_to_cstruct w))

  let get_block_header t (hash : Types.hash256)
      : Types.block_header option =
    let key = prefix_block_header ^ Cstruct.to_string hash in
    match LogStorage.get t.db key with
    | None -> None
    | Some data ->
      let r = Serialize.reader_of_cstruct (Cstruct.of_string data) in
      Some (Serialize.deserialize_block_header r)

  (* Full block storage *)
  let store_block t (hash : Types.hash256) (block : Types.block) =
    let w = Serialize.writer_create () in
    Serialize.serialize_block w block;
    let key = prefix_block_data ^ Cstruct.to_string hash in
    LogStorage.put t.db key
      (Cstruct.to_string (Serialize.writer_to_cstruct w))

  let get_block t (hash : Types.hash256) : Types.block option =
    let key = prefix_block_data ^ Cstruct.to_string hash in
    match LogStorage.get t.db key with
    | None -> None
    | Some data ->
      let r = Serialize.reader_of_cstruct (Cstruct.of_string data) in
      Some (Serialize.deserialize_block r)

  (* Height to hash mapping *)
  let set_height_hash t (height : int) (hash : Types.hash256) =
    let key = prefix_block_height ^ encode_height height in
    LogStorage.put t.db key (Cstruct.to_string hash)

  let get_hash_at_height t (height : int) : Types.hash256 option =
    let key = prefix_block_height ^ encode_height height in
    match LogStorage.get t.db key with
    | None -> None
    | Some data -> Some (Cstruct.of_string data)

  (* Transaction storage *)
  let store_transaction t (txid : Types.hash256) (tx : Types.transaction) =
    let w = Serialize.writer_create () in
    Serialize.serialize_transaction w tx;
    let key = prefix_tx ^ Cstruct.to_string txid in
    LogStorage.put t.db key
      (Cstruct.to_string (Serialize.writer_to_cstruct w))

  let get_transaction t (txid : Types.hash256) : Types.transaction option =
    let key = prefix_tx ^ Cstruct.to_string txid in
    match LogStorage.get t.db key with
    | None -> None
    | Some data ->
      let r = Serialize.reader_of_cstruct (Cstruct.of_string data) in
      Some (Serialize.deserialize_transaction r)

  (* UTXO storage - keyed by txid + vout for O(1) lookup *)
  let store_utxo t (txid : Types.hash256) (vout : int) (utxo_data : string) =
    let w = Serialize.writer_create () in
    Serialize.write_bytes w txid;
    Serialize.write_int32_le w (Int32.of_int vout);
    let key = prefix_utxo ^
      Cstruct.to_string (Serialize.writer_to_cstruct w) in
    LogStorage.put t.db key utxo_data

  let get_utxo t (txid : Types.hash256) (vout : int) : string option =
    let w = Serialize.writer_create () in
    Serialize.write_bytes w txid;
    Serialize.write_int32_le w (Int32.of_int vout);
    let key = prefix_utxo ^
      Cstruct.to_string (Serialize.writer_to_cstruct w) in
    LogStorage.get t.db key

  let delete_utxo t (txid : Types.hash256) (vout : int) =
    let w = Serialize.writer_create () in
    Serialize.write_bytes w txid;
    Serialize.write_int32_le w (Int32.of_int vout);
    let key = prefix_utxo ^
      Cstruct.to_string (Serialize.writer_to_cstruct w) in
    LogStorage.delete t.db key

  (* Chain state - tip hash and height (validated blocks) *)
  let set_chain_tip t (hash : Types.hash256) (height : int) =
    LogStorage.put t.db
      (prefix_chain_state ^ "tip_hash") (Cstruct.to_string hash);
    LogStorage.put t.db
      (prefix_chain_state ^ "tip_height") (encode_height height)

  let get_chain_tip t : (Types.hash256 * int) option =
    match LogStorage.get t.db (prefix_chain_state ^ "tip_hash"),
          LogStorage.get t.db (prefix_chain_state ^ "tip_height") with
    | Some hash_str, Some height_str ->
      let hash = Cstruct.of_string hash_str in
      let height = decode_height height_str in
      Some (hash, height)
    | _ -> None

  (* Header tip - separate from chain tip (headers can be ahead of validated blocks) *)
  (* IMPORTANT: header_tip tracks downloaded headers, chain_tip tracks validated blocks *)
  let set_header_tip t (hash : Types.hash256) (height : int) =
    LogStorage.put t.db
      (prefix_chain_state ^ "header_tip_hash") (Cstruct.to_string hash);
    LogStorage.put t.db
      (prefix_chain_state ^ "header_tip_height") (encode_height height)

  let get_header_tip t : (Types.hash256 * int) option =
    match LogStorage.get t.db (prefix_chain_state ^ "header_tip_hash"),
          LogStorage.get t.db (prefix_chain_state ^ "header_tip_height") with
    | Some hash_str, Some height_str ->
      let hash = Cstruct.of_string hash_str in
      let height = decode_height height_str in
      Some (hash, height)
    | _ -> None

  (* Transaction index - map txid to (block_hash, tx_index) *)
  let store_tx_index t (txid : Types.hash256) (block_hash : Types.hash256) (tx_idx : int) =
    let w = Serialize.writer_create () in
    Serialize.write_bytes w block_hash;
    Serialize.write_int32_le w (Int32.of_int tx_idx);
    let key = prefix_tx_index ^ Cstruct.to_string txid in
    LogStorage.put t.db key
      (Cstruct.to_string (Serialize.writer_to_cstruct w))

  let get_tx_index t (txid : Types.hash256) : (Types.hash256 * int) option =
    let key = prefix_tx_index ^ Cstruct.to_string txid in
    match LogStorage.get t.db key with
    | None -> None
    | Some data ->
      let r = Serialize.reader_of_cstruct (Cstruct.of_string data) in
      let block_hash = Serialize.read_bytes r 32 in
      let tx_idx = Int32.to_int (Serialize.read_int32_le r) in
      Some (block_hash, tx_idx)

  (* Batch operations for atomic updates *)
  let batch_create () = LogStorage.batch_create ()

  let batch_store_block_header batch (hash : Types.hash256) (header : Types.block_header) =
    let w = Serialize.writer_create () in
    Serialize.serialize_block_header w header;
    let key = prefix_block_header ^ Cstruct.to_string hash in
    LogStorage.batch_put batch key
      (Cstruct.to_string (Serialize.writer_to_cstruct w))

  let batch_store_utxo batch (txid : Types.hash256) (vout : int) (utxo_data : string) =
    let w = Serialize.writer_create () in
    Serialize.write_bytes w txid;
    Serialize.write_int32_le w (Int32.of_int vout);
    let key = prefix_utxo ^
      Cstruct.to_string (Serialize.writer_to_cstruct w) in
    LogStorage.batch_put batch key utxo_data

  let batch_delete_utxo batch (txid : Types.hash256) (vout : int) =
    let w = Serialize.writer_create () in
    Serialize.write_bytes w txid;
    Serialize.write_int32_le w (Int32.of_int vout);
    let key = prefix_utxo ^
      Cstruct.to_string (Serialize.writer_to_cstruct w) in
    LogStorage.batch_delete batch key

  let batch_set_chain_tip batch (hash : Types.hash256) (height : int) =
    LogStorage.batch_put batch
      (prefix_chain_state ^ "tip_hash") (Cstruct.to_string hash);
    LogStorage.batch_put batch
      (prefix_chain_state ^ "tip_height") (encode_height height)

  let batch_set_header_tip batch (hash : Types.hash256) (height : int) =
    LogStorage.batch_put batch
      (prefix_chain_state ^ "header_tip_hash") (Cstruct.to_string hash);
    LogStorage.batch_put batch
      (prefix_chain_state ^ "header_tip_height") (encode_height height)

  let batch_write t batch = LogStorage.batch_write t.db batch

  (* Iterate over all UTXOs *)
  let iter_utxos t f =
    LogStorage.iter_prefix t.db prefix_utxo (fun key value ->
      (* Extract txid and vout from key *)
      let key_data = String.sub key 1 (String.length key - 1) in
      let r = Serialize.reader_of_cstruct (Cstruct.of_string key_data) in
      let txid = Serialize.read_bytes r 32 in
      let vout = Int32.to_int (Serialize.read_int32_le r) in
      f txid vout value
    )

  (* Check if block exists *)
  let has_block t (hash : Types.hash256) : bool =
    let key = prefix_block_data ^ Cstruct.to_string hash in
    Option.is_some (LogStorage.get t.db key)

  let has_block_header t (hash : Types.hash256) : bool =
    let key = prefix_block_header ^ Cstruct.to_string hash in
    Option.is_some (LogStorage.get t.db key)

  (* Undo data storage - keyed by block hash for chain reorganizations *)
  let store_undo_data t (block_hash : Types.hash256) (undo_data : string) =
    let key = prefix_undo_data ^ Cstruct.to_string block_hash in
    let checksum = Crypto.sha256 (Cstruct.of_string undo_data) in
    LogStorage.put t.db key (undo_data ^ Cstruct.to_string checksum)

  let get_undo_data t (block_hash : Types.hash256) : string option =
    let key = prefix_undo_data ^ Cstruct.to_string block_hash in
    match LogStorage.get t.db key with
    | None -> None
    | Some raw ->
      let len = String.length raw in
      if len < 32 then None  (* too short for checksum *)
      else
        let data = String.sub raw 0 (len - 32) in
        let stored_checksum = String.sub raw (len - 32) 32 in
        let computed = Crypto.sha256 (Cstruct.of_string data) in
        if Cstruct.to_string computed = stored_checksum then Some data
        else None  (* checksum mismatch = corrupt *)

  let delete_undo_data t (block_hash : Types.hash256) =
    let key = prefix_undo_data ^ Cstruct.to_string block_hash in
    LogStorage.delete t.db key

  (* Batch undo data operations *)
  let batch_store_undo_data batch (block_hash : Types.hash256) (undo_data : string) =
    let key = prefix_undo_data ^ Cstruct.to_string block_hash in
    let checksum = Crypto.sha256 (Cstruct.of_string undo_data) in
    LogStorage.batch_put batch key (undo_data ^ Cstruct.to_string checksum)

  let batch_delete_undo_data batch (block_hash : Types.hash256) =
    let key = prefix_undo_data ^ Cstruct.to_string block_hash in
    LogStorage.batch_delete batch key
end
