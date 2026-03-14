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

  (* Flush the in-memory cache to disk atomically via WAL-protected batch.
     Every cached key that does NOT already have a corresponding file on
     disk is collected into a batch and written atomically, ensuring no
     partial state is visible on crash. *)
  let sync (t : t) : unit =
    let batch = batch_create () in
    Hashtbl.iter (fun key value ->
      let path = key_to_path t key in
      if not (Sys.file_exists path) then
        batch_put batch key value
    ) t.cache;
    batch_write t batch

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
    if not (Sys.file_exists path) then begin
      t.data_offset <- 0
    end else begin
      let ic = open_in_bin path in
      let flen = in_channel_length ic in
      let last_valid_pos = ref 0 in
      (try
        while pos_in ic < flen do
          let op = input_char ic in
          match op with
          | 'P' ->
            let klen = read_be32 ic in
            let key = really_input_string ic klen in
            let vlen = read_be32 ic in
            let value_offset = pos_in ic in
            seek_in ic (value_offset + vlen);
            Hashtbl.replace t.index key (value_offset, vlen);
            Hashtbl.remove t.deleted key;
            last_valid_pos := pos_in ic
          | 'D' ->
            let klen = read_be32 ic in
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
    let batch = LogStorage.batch_create () in
    LogStorage.batch_put batch (prefix_chain_state ^ "tip_hash") (Cstruct.to_string hash);
    LogStorage.batch_put batch (prefix_chain_state ^ "tip_height") (encode_height height);
    LogStorage.batch_write t.db batch

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
    let batch = LogStorage.batch_create () in
    LogStorage.batch_put batch (prefix_chain_state ^ "header_tip_hash") (Cstruct.to_string hash);
    LogStorage.batch_put batch (prefix_chain_state ^ "header_tip_height") (encode_height height);
    LogStorage.batch_write t.db batch

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

  let delete_block t (hash : Types.hash256) =
    let key = prefix_block_data ^ Cstruct.to_string hash in
    LogStorage.delete t.db key

  let batch_delete_block batch (hash : Types.hash256) =
    let key = prefix_block_data ^ Cstruct.to_string hash in
    LogStorage.batch_delete batch key

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

(* ============================================================================
   Undo Data Types for Chain Reorganizations (BIP-compatible)

   Reference: Bitcoin Core's undo.h (CTxUndo, CBlockUndo)

   Undo data stores the UTXOs consumed by each block's transactions so that
   blocks can be disconnected during chain reorganizations. Without undo data,
   reorgs would require re-downloading and re-validating the entire chain.

   Structure:
   - tx_undo: One entry per transaction input, storing the spent UTXO
     (amount, scriptPubKey, height, is_coinbase)
   - block_undo: One tx_undo per non-coinbase transaction in the block
     (coinbase has no inputs, so no undo data)

   Stored in rev{nnnnn}.dat files alongside blk{nnnnn}.dat in Bitcoin Core,
   but here we use the ChainDB key-value store with the "r" prefix.
   ============================================================================ *)

(** Undo information for a single transaction input.
    Stores the UTXO that was spent by this input. *)
type tx_in_undo = {
  value : int64;            (** Output value in satoshis *)
  script_pubkey : Cstruct.t; (** Locking script of the spent output *)
  height : int;             (** Block height where output was created *)
  is_coinbase : bool;       (** Whether this was a coinbase output *)
}

(** Undo information for a single transaction.
    Contains one tx_in_undo per input (prev_outputs list).
    Matches Bitcoin Core's CTxUndo which has vprevout vector. *)
type tx_undo = {
  prev_outputs : tx_in_undo list;
}

(** Undo information for a block.
    Contains one tx_undo per non-coinbase transaction.
    The coinbase (index 0) has no inputs to undo, so it's excluded.
    Matches Bitcoin Core's CBlockUndo which has vtxundo vector. *)
type block_undo = {
  tx_undos : tx_undo list;  (** One entry per non-coinbase transaction *)
}

(* Serialize a single input's undo data *)
let serialize_tx_in_undo w (u : tx_in_undo) =
  Serialize.write_int64_le w u.value;
  Serialize.write_compact_size w (Cstruct.length u.script_pubkey);
  Serialize.write_bytes w u.script_pubkey;
  Serialize.write_int32_le w (Int32.of_int u.height);
  Serialize.write_uint8 w (if u.is_coinbase then 1 else 0)

(* Deserialize a single input's undo data *)
let deserialize_tx_in_undo r : tx_in_undo =
  let value = Serialize.read_int64_le r in
  let script_len = Serialize.read_compact_size r in
  let script_pubkey = Serialize.read_bytes r script_len in
  let height = Int32.to_int (Serialize.read_int32_le r) in
  let is_coinbase = Serialize.read_uint8 r <> 0 in
  { value; script_pubkey; height; is_coinbase }

(* Serialize a transaction's undo data (all inputs) *)
let serialize_tx_undo w (u : tx_undo) =
  Serialize.write_compact_size w (List.length u.prev_outputs);
  List.iter (serialize_tx_in_undo w) u.prev_outputs

(* Deserialize a transaction's undo data *)
let deserialize_tx_undo r : tx_undo =
  let count = Serialize.read_compact_size r in
  let prev_outputs = List.init count (fun _ -> deserialize_tx_in_undo r) in
  { prev_outputs }

(* Serialize block undo data with checksum for integrity verification *)
let serialize_block_undo w (u : block_undo) =
  Serialize.write_compact_size w (List.length u.tx_undos);
  List.iter (serialize_tx_undo w) u.tx_undos;
  (* Compute SHA256 checksum over the serialized data for integrity *)
  let data = Serialize.writer_to_cstruct w in
  let checksum = Crypto.sha256 data in
  Serialize.write_bytes w checksum

(* Deserialize block undo data, verifying checksum *)
let deserialize_block_undo r : block_undo =
  let count = Serialize.read_compact_size r in
  let tx_undos = List.init count (fun _ -> deserialize_tx_undo r) in
  (* Verify checksum if present *)
  let remaining = Cstruct.length r.Serialize.buf - r.Serialize.pos in
  if remaining = 32 then begin
    (* Position just before the checksum *)
    let data_end = r.Serialize.pos in
    let stored_checksum = Serialize.read_bytes r 32 in
    let data_to_hash = Cstruct.sub r.Serialize.buf 0 data_end in
    let computed_checksum = Crypto.sha256 data_to_hash in
    if not (Cstruct.equal stored_checksum computed_checksum) then
      failwith "Block undo data checksum verification failed"
  end else if remaining > 0 then
    failwith (Printf.sprintf "Block undo data has unexpected trailing bytes (%d)" remaining);
  { tx_undos }

(* ============================================================================
   Flat File Block Storage (Bitcoin Core blk/rev format)

   Reference: Bitcoin Core's node/blockstorage.cpp and flatfile.cpp

   Bitcoin stores blocks in sequential flat files (blk00000.dat, blk00001.dat, ...)
   with a simple format: [magic:4][size:4][block_data:N] repeated.

   This implementation:
   - Uses blk{nnnnn}.dat files with 128MB max size
   - Tracks file position for each block via FlatFilePos
   - Maintains a block index (hash -> file_pos) for fast lookups
   - Persists the index to disk for fast startup
   ============================================================================ *)

(** Maximum block file size (128 MB = 0x8000000) *)
let max_blockfile_size = 0x8000000

(** Storage header size: 4 bytes magic + 4 bytes block size *)
let storage_header_bytes = 8

(** Network magic bytes for mainnet *)
let mainnet_magic = 0xF9BEB4D9l

(** Network magic bytes for testnet4 *)
let testnet4_magic = 0x1C163F28l

(** Network magic bytes for regtest *)
let regtest_magic = 0xDAB5BFFAl

(** Position within a flat file sequence *)
type flat_file_pos = {
  file_num : int;   (** File number (0, 1, 2, ...) *)
  pos : int;        (** Byte offset within the file *)
}

(** Null position indicating invalid/unset *)
let null_pos = { file_num = -1; pos = 0 }

let is_null_pos p = p.file_num < 0

(** Block status flags matching Bitcoin Core *)
type block_status =
  | Block_valid_unknown
  | Block_valid_header    (** Header is valid *)
  | Block_valid_tree      (** Header connects to known chain *)
  | Block_valid_transactions  (** Transactions are parseable *)
  | Block_valid_chain     (** Outputs are spendable *)
  | Block_valid_scripts   (** Scripts verified *)
  | Block_have_data       (** Full block data available *)
  | Block_have_undo       (** Undo data available *)
  | Block_failed          (** Validation failed *)

(** Block index entry stored for each block *)
type block_index_entry = {
  file_pos : flat_file_pos;
  undo_pos : flat_file_pos;
  height : int;
  header : Types.block_header;
  status : block_status list;
  n_tx : int;  (** Number of transactions *)
}

(** File info for each blk file *)
type block_file_info = {
  mutable n_blocks : int;      (** Number of blocks in this file *)
  mutable n_size : int;        (** Current size of block data *)
  mutable n_undo_size : int;   (** Current size of undo data *)
  mutable height_first : int;  (** Lowest block height in file *)
  mutable height_last : int;   (** Highest block height in file *)
  mutable time_first : int32;  (** Earliest block timestamp *)
  mutable time_last : int32;   (** Latest block timestamp *)
}

(** Create empty file info *)
let empty_file_info () = {
  n_blocks = 0;
  n_size = 0;
  n_undo_size = 0;
  height_first = max_int;
  height_last = 0;
  time_first = Int32.max_int;
  time_last = 0l;
}

(** Flat file storage for blocks *)
module FlatFileStorage = struct
  type t = {
    blocks_dir : string;
    mutable magic : int32;  (** Network magic bytes *)
    mutable last_file : int;
    mutable file_info : block_file_info array;
    block_index : (string, block_index_entry) Hashtbl.t;  (** hash -> entry *)
    mutable dirty : bool;  (** Index needs persisting *)
  }

  (* --- Path helpers --- *)

  let block_file_path t file_num =
    Filename.concat t.blocks_dir (Printf.sprintf "blk%05d.dat" file_num)

  let undo_file_path t file_num =
    Filename.concat t.blocks_dir (Printf.sprintf "rev%05d.dat" file_num)

  let index_path t =
    Filename.concat t.blocks_dir "index.dat"

  let ensure_dir path =
    try Unix.mkdir path 0o755
    with Unix.Unix_error (Unix.EEXIST, _, _) -> ()

  (* --- Serialization helpers --- *)

  let write_le32 oc v =
    output_byte oc (Int32.to_int (Int32.logand v 0xFFl));
    output_byte oc (Int32.to_int (Int32.logand (Int32.shift_right_logical v 8) 0xFFl));
    output_byte oc (Int32.to_int (Int32.logand (Int32.shift_right_logical v 16) 0xFFl));
    output_byte oc (Int32.to_int (Int32.logand (Int32.shift_right_logical v 24) 0xFFl))

  let read_le32 ic =
    let b0 = input_byte ic in
    let b1 = input_byte ic in
    let b2 = input_byte ic in
    let b3 = input_byte ic in
    Int32.logor
      (Int32.of_int b0)
      (Int32.logor
        (Int32.shift_left (Int32.of_int b1) 8)
        (Int32.logor
          (Int32.shift_left (Int32.of_int b2) 16)
          (Int32.shift_left (Int32.of_int b3) 24)))

  (* --- Index persistence --- *)

  let serialize_pos w (p : flat_file_pos) =
    Serialize.write_int32_le w (Int32.of_int p.file_num);
    Serialize.write_int32_le w (Int32.of_int p.pos)

  let deserialize_pos r : flat_file_pos =
    let file_num = Int32.to_int (Serialize.read_int32_le r) in
    let pos = Int32.to_int (Serialize.read_int32_le r) in
    { file_num; pos }

  let status_to_int = function
    | Block_valid_unknown -> 0
    | Block_valid_header -> 1
    | Block_valid_tree -> 2
    | Block_valid_transactions -> 3
    | Block_valid_chain -> 4
    | Block_valid_scripts -> 5
    | Block_have_data -> 6
    | Block_have_undo -> 7
    | Block_failed -> 8

  let int_to_status = function
    | 0 -> Block_valid_unknown
    | 1 -> Block_valid_header
    | 2 -> Block_valid_tree
    | 3 -> Block_valid_transactions
    | 4 -> Block_valid_chain
    | 5 -> Block_valid_scripts
    | 6 -> Block_have_data
    | 7 -> Block_have_undo
    | 8 -> Block_failed
    | _ -> Block_valid_unknown

  let serialize_entry w (e : block_index_entry) =
    serialize_pos w e.file_pos;
    serialize_pos w e.undo_pos;
    Serialize.write_int32_le w (Int32.of_int e.height);
    Serialize.serialize_block_header w e.header;
    (* Status as bitmask *)
    let mask = List.fold_left (fun acc s ->
      acc lor (1 lsl (status_to_int s))
    ) 0 e.status in
    Serialize.write_int32_le w (Int32.of_int mask);
    Serialize.write_int32_le w (Int32.of_int e.n_tx)

  let deserialize_entry r : block_index_entry =
    let file_pos = deserialize_pos r in
    let undo_pos = deserialize_pos r in
    let height = Int32.to_int (Serialize.read_int32_le r) in
    let header = Serialize.deserialize_block_header r in
    let mask = Int32.to_int (Serialize.read_int32_le r) in
    let status = List.filter (fun s ->
      (mask land (1 lsl (status_to_int s))) <> 0
    ) [Block_valid_unknown; Block_valid_header; Block_valid_tree;
       Block_valid_transactions; Block_valid_chain; Block_valid_scripts;
       Block_have_data; Block_have_undo; Block_failed] in
    let n_tx = Int32.to_int (Serialize.read_int32_le r) in
    { file_pos; undo_pos; height; header; status; n_tx }

  let save_index t =
    if not t.dirty then ()
    else begin
      let path = index_path t in
      let tmp = path ^ ".tmp" in
      let oc = open_out_bin tmp in
      (* Header: magic, version, entry count, last_file *)
      output_string oc "BLKIDX01";  (* Magic + version *)
      write_le32 oc (Int32.of_int (Hashtbl.length t.block_index));
      write_le32 oc (Int32.of_int t.last_file);
      (* Write file info for each file *)
      write_le32 oc (Int32.of_int (Array.length t.file_info));
      Array.iter (fun fi ->
        write_le32 oc (Int32.of_int fi.n_blocks);
        write_le32 oc (Int32.of_int fi.n_size);
        write_le32 oc (Int32.of_int fi.n_undo_size);
        write_le32 oc (Int32.of_int fi.height_first);
        write_le32 oc (Int32.of_int fi.height_last);
        write_le32 oc fi.time_first;
        write_le32 oc fi.time_last
      ) t.file_info;
      (* Write each entry *)
      Hashtbl.iter (fun hash entry ->
        (* Hash is 32 bytes *)
        output_string oc hash;
        let w = Serialize.writer_create () in
        serialize_entry w entry;
        let data = Serialize.writer_to_cstruct w in
        write_le32 oc (Int32.of_int (Cstruct.length data));
        output_string oc (Cstruct.to_string data)
      ) t.block_index;
      close_out oc;
      Unix.rename tmp path;
      t.dirty <- false
    end

  let load_index t =
    let path = index_path t in
    if not (Sys.file_exists path) then ()
    else begin
      let ic = open_in_bin path in
      (try
        let magic = really_input_string ic 8 in
        if magic <> "BLKIDX01" then raise Exit;
        let count = Int32.to_int (read_le32 ic) in
        t.last_file <- Int32.to_int (read_le32 ic);
        (* Read file info *)
        let fi_count = Int32.to_int (read_le32 ic) in
        t.file_info <- Array.init fi_count (fun _ ->
          let n_blocks = Int32.to_int (read_le32 ic) in
          let n_size = Int32.to_int (read_le32 ic) in
          let n_undo_size = Int32.to_int (read_le32 ic) in
          let height_first = Int32.to_int (read_le32 ic) in
          let height_last = Int32.to_int (read_le32 ic) in
          let time_first = read_le32 ic in
          let time_last = read_le32 ic in
          { n_blocks; n_size; n_undo_size; height_first; height_last;
            time_first; time_last }
        );
        for _ = 1 to count do
          let hash = really_input_string ic 32 in
          let entry_len = Int32.to_int (read_le32 ic) in
          let entry_data = really_input_string ic entry_len in
          let r = Serialize.reader_of_cstruct (Cstruct.of_string entry_data) in
          let entry = deserialize_entry r in
          Hashtbl.replace t.block_index hash entry
        done
      with _ -> ());
      close_in ic
    end

  (* --- Public API --- *)

  let create ?(magic = mainnet_magic) blocks_dir =
    ensure_dir blocks_dir;
    let t = {
      blocks_dir;
      magic;
      last_file = 0;
      file_info = [| empty_file_info () |];
      block_index = Hashtbl.create 10000;
      dirty = false;
    } in
    load_index t;
    t

  let close t =
    save_index t

  let sync t =
    save_index t

  (** Find position for next block, potentially creating new file *)
  let find_next_block_pos t block_size height timestamp =
    let add_size = block_size + storage_header_bytes in
    (* Ensure we have file_info for current file *)
    if t.last_file >= Array.length t.file_info then begin
      let new_arr = Array.make (t.last_file + 1) (empty_file_info ()) in
      Array.blit t.file_info 0 new_arr 0 (Array.length t.file_info);
      t.file_info <- new_arr
    end;
    (* Check if current file has space *)
    let fi = t.file_info.(t.last_file) in
    if fi.n_size + add_size > max_blockfile_size then begin
      (* Move to next file *)
      t.last_file <- t.last_file + 1;
      let new_arr = Array.make (t.last_file + 1) (empty_file_info ()) in
      Array.blit t.file_info 0 new_arr 0 (Array.length t.file_info);
      t.file_info <- new_arr
    end;
    let file_num = t.last_file in
    let fi = t.file_info.(file_num) in
    let pos = fi.n_size in
    (* Update file info *)
    fi.n_blocks <- fi.n_blocks + 1;
    fi.n_size <- fi.n_size + add_size;
    if height < fi.height_first then fi.height_first <- height;
    if height > fi.height_last then fi.height_last <- height;
    if Int32.compare timestamp fi.time_first < 0 then fi.time_first <- timestamp;
    if Int32.compare timestamp fi.time_last > 0 then fi.time_last <- timestamp;
    t.dirty <- true;
    { file_num; pos = pos + storage_header_bytes }  (* pos points past header *)

  (** Write a block to disk, returns file position *)
  let write_block t (block : Types.block) height : flat_file_pos =
    (* Serialize the block *)
    let w = Serialize.writer_create () in
    Serialize.serialize_block w block;
    let block_data = Serialize.writer_to_cstruct w in
    let block_size = Cstruct.length block_data in
    (* Find position *)
    let pos = find_next_block_pos t block_size height block.header.timestamp in
    let file_path = block_file_path t pos.file_num in
    (* Create or open file *)
    let flags = [Unix.O_WRONLY; Unix.O_CREAT] in
    let fd = Unix.openfile file_path flags 0o644 in
    (* Seek to position before header *)
    let _ = Unix.lseek fd (pos.pos - storage_header_bytes) Unix.SEEK_SET in
    (* Write magic and size *)
    let header_buf = Bytes.create 8 in
    Bytes.set header_buf 0 (Char.chr (Int32.to_int (Int32.logand t.magic 0xFFl)));
    Bytes.set header_buf 1 (Char.chr (Int32.to_int (Int32.logand (Int32.shift_right_logical t.magic 8) 0xFFl)));
    Bytes.set header_buf 2 (Char.chr (Int32.to_int (Int32.logand (Int32.shift_right_logical t.magic 16) 0xFFl)));
    Bytes.set header_buf 3 (Char.chr (Int32.to_int (Int32.logand (Int32.shift_right_logical t.magic 24) 0xFFl)));
    let size32 = Int32.of_int block_size in
    Bytes.set header_buf 4 (Char.chr (Int32.to_int (Int32.logand size32 0xFFl)));
    Bytes.set header_buf 5 (Char.chr (Int32.to_int (Int32.logand (Int32.shift_right_logical size32 8) 0xFFl)));
    Bytes.set header_buf 6 (Char.chr (Int32.to_int (Int32.logand (Int32.shift_right_logical size32 16) 0xFFl)));
    Bytes.set header_buf 7 (Char.chr (Int32.to_int (Int32.logand (Int32.shift_right_logical size32 24) 0xFFl)));
    let _ = Unix.write fd header_buf 0 8 in
    (* Write block data *)
    let _ = Unix.write fd (Cstruct.to_bytes block_data) 0 block_size in
    Unix.close fd;
    (* Update block index *)
    let hash = Crypto.compute_block_hash block.header in
    let entry = {
      file_pos = pos;
      undo_pos = null_pos;
      height;
      header = block.header;
      status = [Block_have_data; Block_valid_header];
      n_tx = List.length block.transactions;
    } in
    Hashtbl.replace t.block_index (Cstruct.to_string hash) entry;
    t.dirty <- true;
    pos

  (** Read a block from disk given its position *)
  let read_block_at_pos t (pos : flat_file_pos) : Types.block option =
    if is_null_pos pos then None
    else begin
      let file_path = block_file_path t pos.file_num in
      if not (Sys.file_exists file_path) then None
      else begin
        let fd = Unix.openfile file_path [Unix.O_RDONLY] 0 in
        (try
          (* Seek to header position *)
          let _ = Unix.lseek fd (pos.pos - storage_header_bytes) Unix.SEEK_SET in
          (* Read header *)
          let header_buf = Bytes.create 8 in
          let n = Unix.read fd header_buf 0 8 in
          if n <> 8 then begin
            Unix.close fd;
            None
          end
          else begin
            (* Verify magic *)
            let magic =
              Int32.logor (Int32.of_int (Char.code (Bytes.get header_buf 0)))
                (Int32.logor
                  (Int32.shift_left (Int32.of_int (Char.code (Bytes.get header_buf 1))) 8)
                  (Int32.logor
                    (Int32.shift_left (Int32.of_int (Char.code (Bytes.get header_buf 2))) 16)
                    (Int32.shift_left (Int32.of_int (Char.code (Bytes.get header_buf 3))) 24))) in
            if not (Int32.equal magic t.magic) then begin
              Unix.close fd;
              None
            end
            else begin
              (* Read size *)
              let size =
                (Char.code (Bytes.get header_buf 4))
                lor (Char.code (Bytes.get header_buf 5) lsl 8)
                lor (Char.code (Bytes.get header_buf 6) lsl 16)
                lor (Char.code (Bytes.get header_buf 7) lsl 24) in
              (* Read block data *)
              let block_buf = Bytes.create size in
              let n = Unix.read fd block_buf 0 size in
              Unix.close fd;
              if n <> size then None
              else begin
                let r = Serialize.reader_of_cstruct (Cstruct.of_bytes block_buf) in
                try Some (Serialize.deserialize_block r)
                with _ -> None
              end
            end
          end
        with _ ->
          Unix.close fd;
          None)
      end
    end

  (** Read a block from disk given its hash *)
  let read_block t (hash : Types.hash256) : Types.block option =
    match Hashtbl.find_opt t.block_index (Cstruct.to_string hash) with
    | None -> None
    | Some entry -> read_block_at_pos t entry.file_pos

  (** Get block index entry *)
  let get_block_index t (hash : Types.hash256) : block_index_entry option =
    Hashtbl.find_opt t.block_index (Cstruct.to_string hash)

  (** Check if block exists *)
  let has_block t (hash : Types.hash256) : bool =
    Hashtbl.mem t.block_index (Cstruct.to_string hash)

  (** Update block index entry (e.g., after adding undo data) *)
  let update_block_index t (hash : Types.hash256) (entry : block_index_entry) =
    Hashtbl.replace t.block_index (Cstruct.to_string hash) entry;
    t.dirty <- true

  (** Write undo data for a block *)
  let write_undo t (block_hash : Types.hash256) (undo : block_undo) : flat_file_pos option =
    match Hashtbl.find_opt t.block_index (Cstruct.to_string block_hash) with
    | None -> None
    | Some entry ->
      let w = Serialize.writer_create () in
      serialize_block_undo w undo;
      let undo_data = Serialize.writer_to_cstruct w in
      let undo_size = Cstruct.length undo_data in
      let file_num = entry.file_pos.file_num in
      (* Ensure file_info exists *)
      if file_num >= Array.length t.file_info then begin
        let new_arr = Array.make (file_num + 1) (empty_file_info ()) in
        Array.blit t.file_info 0 new_arr 0 (Array.length t.file_info);
        t.file_info <- new_arr
      end;
      let fi = t.file_info.(file_num) in
      let pos = fi.n_undo_size + storage_header_bytes in
      fi.n_undo_size <- fi.n_undo_size + undo_size + storage_header_bytes;
      (* Write to rev file *)
      let file_path = undo_file_path t file_num in
      let flags = [Unix.O_WRONLY; Unix.O_CREAT] in
      let fd = Unix.openfile file_path flags 0o644 in
      let _ = Unix.lseek fd (pos - storage_header_bytes) Unix.SEEK_SET in
      (* Write magic and size *)
      let header_buf = Bytes.create 8 in
      Bytes.set header_buf 0 (Char.chr (Int32.to_int (Int32.logand t.magic 0xFFl)));
      Bytes.set header_buf 1 (Char.chr (Int32.to_int (Int32.logand (Int32.shift_right_logical t.magic 8) 0xFFl)));
      Bytes.set header_buf 2 (Char.chr (Int32.to_int (Int32.logand (Int32.shift_right_logical t.magic 16) 0xFFl)));
      Bytes.set header_buf 3 (Char.chr (Int32.to_int (Int32.logand (Int32.shift_right_logical t.magic 24) 0xFFl)));
      let size32 = Int32.of_int undo_size in
      Bytes.set header_buf 4 (Char.chr (Int32.to_int (Int32.logand size32 0xFFl)));
      Bytes.set header_buf 5 (Char.chr (Int32.to_int (Int32.logand (Int32.shift_right_logical size32 8) 0xFFl)));
      Bytes.set header_buf 6 (Char.chr (Int32.to_int (Int32.logand (Int32.shift_right_logical size32 16) 0xFFl)));
      Bytes.set header_buf 7 (Char.chr (Int32.to_int (Int32.logand (Int32.shift_right_logical size32 24) 0xFFl)));
      let _ = Unix.write fd header_buf 0 8 in
      let _ = Unix.write fd (Cstruct.to_bytes undo_data) 0 undo_size in
      Unix.close fd;
      (* Update entry *)
      let undo_pos = { file_num; pos } in
      let new_entry = { entry with
        undo_pos;
        status = Block_have_undo :: entry.status;
      } in
      Hashtbl.replace t.block_index (Cstruct.to_string block_hash) new_entry;
      t.dirty <- true;
      Some undo_pos

  (** Read undo data for a block *)
  let read_undo t (block_hash : Types.hash256) : block_undo option =
    match Hashtbl.find_opt t.block_index (Cstruct.to_string block_hash) with
    | None -> None
    | Some entry ->
      if is_null_pos entry.undo_pos then None
      else begin
        let file_path = undo_file_path t entry.undo_pos.file_num in
        if not (Sys.file_exists file_path) then None
        else begin
          let fd = Unix.openfile file_path [Unix.O_RDONLY] 0 in
          (try
            let _ = Unix.lseek fd (entry.undo_pos.pos - storage_header_bytes) Unix.SEEK_SET in
            let header_buf = Bytes.create 8 in
            let n = Unix.read fd header_buf 0 8 in
            if n <> 8 then begin
              Unix.close fd;
              None
            end
            else begin
              let size =
                (Char.code (Bytes.get header_buf 4))
                lor (Char.code (Bytes.get header_buf 5) lsl 8)
                lor (Char.code (Bytes.get header_buf 6) lsl 16)
                lor (Char.code (Bytes.get header_buf 7) lsl 24) in
              let undo_buf = Bytes.create size in
              let n = Unix.read fd undo_buf 0 size in
              Unix.close fd;
              if n <> size then None
              else begin
                let r = Serialize.reader_of_cstruct (Cstruct.of_bytes undo_buf) in
                try Some (deserialize_block_undo r)
                with _ -> None
              end
            end
          with _ ->
            Unix.close fd;
            None)
        end
      end

  (** Iterate over all blocks in the index *)
  let iter_blocks t f =
    Hashtbl.iter (fun hash_str entry ->
      let hash = Cstruct.of_string hash_str in
      f hash entry
    ) t.block_index

  (** Get the number of blocks in the index *)
  let block_count t = Hashtbl.length t.block_index

  (** Get file info *)
  let get_file_info t file_num =
    if file_num < Array.length t.file_info then
      Some t.file_info.(file_num)
    else
      None

  (** Get last file number *)
  let last_file_num t = t.last_file
end

(* ============================================================================
   Chain State Management with Block Disconnect Support
   ============================================================================ *)

(** Error type for chain operations *)
type chain_error =
  | MissingBlock of Types.hash256
  | MissingUndoData of Types.hash256
  | InvalidUndoChecksum of Types.hash256
  | UtxoError of string

let chain_error_to_string = function
  | MissingBlock h -> Printf.sprintf "Missing block: %s" (Types.hash256_to_hex_display h)
  | MissingUndoData h -> Printf.sprintf "Missing undo data: %s" (Types.hash256_to_hex_display h)
  | InvalidUndoChecksum h -> Printf.sprintf "Invalid undo checksum: %s" (Types.hash256_to_hex_display h)
  | UtxoError msg -> Printf.sprintf "UTXO error: %s" msg

(** Build block_undo from a block during connect_block.
    Call this BEFORE consuming UTXOs to capture the spent outputs.
    Returns block_undo with one tx_undo per non-coinbase transaction. *)
let build_block_undo (block : Types.block)
    ~(lookup_utxo : Types.outpoint -> tx_in_undo option)
    : (block_undo, string) result =
  let error = ref None in
  let tx_undos = List.mapi (fun tx_idx tx ->
    if tx_idx = 0 then
      (* Coinbase has no inputs, return empty tx_undo *)
      { prev_outputs = [] }
    else begin
      let prev_outputs = List.map (fun inp ->
        let outpoint = inp.Types.previous_output in
        match lookup_utxo outpoint with
        | Some u -> u
        | None ->
          if !error = None then
            error := Some (Printf.sprintf "Missing UTXO for input %s:%ld"
              (Types.hash256_to_hex_display outpoint.txid) outpoint.vout);
          (* Return dummy - will be ignored due to error *)
          { value = 0L; script_pubkey = Cstruct.empty; height = 0; is_coinbase = false }
      ) tx.Types.inputs in
      { prev_outputs }
    end
  ) block.transactions in
  match !error with
  | Some e -> Error e
  | None ->
    (* Filter out the coinbase's empty tx_undo *)
    let tx_undos = match tx_undos with
      | _ :: rest -> rest  (* Remove first (coinbase) entry *)
      | [] -> []
    in
    Ok { tx_undos }

(** Disconnect a block from the chain state.
    This reverses the effects of connect_block:
    1. Remove outputs created by all transactions in the block
    2. Restore spent UTXOs from the undo data

    db: The chain database
    block: The block to disconnect
    block_hash: Hash of the block (for undo data lookup)
    add_utxo: Callback to add a UTXO back to the set
    remove_utxo: Callback to remove a UTXO from the set

    Transactions are processed in reverse order to properly handle
    intra-block dependencies where later transactions spend outputs
    from earlier transactions in the same block. *)
let disconnect_block (db : ChainDB.t) (block : Types.block)
    (block_hash : Types.hash256)
    ~(add_utxo : Types.hash256 -> int -> tx_in_undo -> unit)
    ~(remove_utxo : Types.hash256 -> int -> unit)
    : (unit, chain_error) result =
  (* Load undo data for this block *)
  match ChainDB.get_undo_data db block_hash with
  | None -> Error (MissingUndoData block_hash)
  | Some undo_raw ->
    let undo =
      try
        let r = Serialize.reader_of_cstruct (Cstruct.of_string undo_raw) in
        deserialize_block_undo r
      with Failure msg ->
        (* Checksum or format error *)
        if String.length msg >= 10 && String.sub msg 0 10 = "Block undo" then
          raise (Invalid_argument (chain_error_to_string (InvalidUndoChecksum block_hash)))
        else
          raise (Invalid_argument msg)
    in
    (* Process transactions in reverse order *)
    let txs_reversed = List.rev block.transactions in
    List.iter (fun tx ->
      let txid = Crypto.compute_txid tx in
      (* Remove outputs created by this transaction *)
      List.iteri (fun vout _out ->
        remove_utxo txid vout
      ) tx.outputs
    ) txs_reversed;
    (* Restore spent UTXOs from undo data.
       The tx_undos list corresponds to non-coinbase transactions in order,
       so we iterate the original transactions (skipping coinbase) and match
       each input with its corresponding undo entry. *)
    let non_coinbase_txs = match block.transactions with
      | _ :: rest -> rest
      | [] -> []
    in
    List.iteri (fun tx_idx tx ->
      if tx_idx < List.length undo.tx_undos then begin
        let tx_undo = List.nth undo.tx_undos tx_idx in
        List.iteri (fun inp_idx inp ->
          if inp_idx < List.length tx_undo.prev_outputs then begin
            let prev_out = List.nth tx_undo.prev_outputs inp_idx in
            let outpoint = inp.Types.previous_output in
            add_utxo outpoint.txid (Int32.to_int outpoint.vout) prev_out
          end
        ) tx.Types.inputs
      end
    ) non_coinbase_txs;
    (* Delete the undo data for this block *)
    ChainDB.delete_undo_data db block_hash;
    Ok ()
