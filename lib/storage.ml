(* Database layer using file-based storage with write-ahead log for crash safety *)

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

  val iter_keys : t -> (string -> unit) -> unit
  val iter_prefix : t -> string -> (string -> string -> unit) -> unit

  val sync : t -> unit

  (* Remove stale `*.tmp` files from a chainstate directory left behind
     by torn writes (e.g. a failed [Unix.rename] in [write_snapshot]).
     Conservative: only files older than [stale_age_seconds] (default 60s)
     are removed; only the immediate directory is scanned. Idempotent. *)
  val cleanup_orphan_tmp_files :
    ?stale_age_seconds:float -> string -> unit
end

(* File-based storage implementation with write-ahead log (WAL) for crash safety.
   Provides durable key-value storage with batch writes, disk-scanning
   iter_prefix, and an in-memory cache for fast reads. *)
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

  (* Iterate over all keys in the database. *)
  let iter_keys t f =
    let seen = Hashtbl.create 256 in
    (* Phase 1: cache keys *)
    Hashtbl.iter (fun k _v ->
      f k;
      Hashtbl.replace seen k ()
    ) t.cache;
    (* Phase 2: scan disk for any keys not in cache *)
    let scan_dir subdir_path =
      if Sys.file_exists subdir_path && Sys.is_directory subdir_path then begin
        let entries = Sys.readdir subdir_path in
        Array.iter (fun fname ->
          if not (String.length fname > 4 &&
                  String.sub fname (String.length fname - 4) 4 = ".tmp") then begin
            let fpath = Filename.concat subdir_path fname in
            if not (Sys.is_directory fpath) then begin
              match read_data_file fpath with
              | Some (key, _value) ->
                if not (Hashtbl.mem seen key) &&
                   not (Hashtbl.mem t.deleted_keys key) then begin
                  f key;
                  Hashtbl.replace seen key ()
                end
              | None -> ()
            end
          end
        ) entries
      end
    in
    if Sys.file_exists t.base_dir && Sys.is_directory t.base_dir then begin
      let subdirs = Sys.readdir t.base_dir in
      Array.iter (fun name ->
        let spath = Filename.concat t.base_dir name in
        if String.length name = 2 && Sys.is_directory spath then
          scan_dir spath
      ) subdirs
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

  (* FileStorage doesn't write [*.tmp] files itself, but the public STORAGE
     signature requires this entry point so callers can opt in to a
     consistent startup-time cleanup regardless of backend. Behaviour
     mirrors LogStorage.cleanup_orphan_tmp_files; safe to call when the
     directory does not exist. *)
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
let prefix_invalidated  = "i"  (* manually invalidated block hashes *)

(* Higher-level chain database, Option D (Cf_chainstate-backed).

   This module is the public chainstate API consumed by sync, validation,
   block_import, peer_manager, RPC, and the test suite. Storage is in
   RocksDB column families via [Cf_chainstate]. The legacy LogStorage
   source has been retired (see CAMLCOIN-UTXO-DESIGN-MEMO-2026-04-29.md,
   Option D); the read-only walker needed by the migration tool now
   lives in [Migration.Log_reader].

   The external API (function names, signatures, and semantics) is
   identical to the previous LogStorage-backed implementation; only the
   underlying storage changes. The [batch] type is now backed by a
   [Cf_chainstate.batch] (multi-CF RocksDB write batch) so all puts +
   deletes in one [batch_write] commit atomically across all
   namespaces, mirroring [CCoinsViewDB::BatchWrite] in
   bitcoin-core/src/txdb.cpp:23-83. *)
module ChainDB = struct
  (* [rocksdb_utxo] is the optional dual-read/dual-delete backend used to
     recover pre-assume-valid UTXOs that live only in the RocksDB store.
     Assume-valid IBD writes UTXOs exclusively through [OptimizedUtxoSet]
     → Rocksdb_store.  When [rocksdb_utxo] is attached, [get_utxo] falls
     back to the assume-utxo store on a CF miss and [delete_utxo]
     removes from both stores so a spent output does not reappear from
     the fallback path. *)
  type t = {
    cf : Cf_chainstate.t;
    mutable rocksdb_utxo : Rocksdb_store.t option;
    (* [batch_write_count] counts non-empty [batch_write] commits.  Used
       only by the test suite to assert "exactly one disk batch per
       reorg" (Pattern D-FULL atomicity invariant); production code
       does not branch on the value.  An empty batch (no put/delete
       queued) is a no-op and does not increment. *)
    mutable batch_write_count : int;
  }

  (* Open the Option-D chainstate. Lives at <datadir>/chainstate-rocks/ —
     the same path Migration writes into. The parent dir is created
     here so callers don't have to mkdir before passing in a fresh
     chainstate path (matches the historical LogStorage.open_db
     behaviour). *)
  let create path =
    (try Unix.mkdir path 0o755
     with Unix.Unix_error (Unix.EEXIST, _, _) -> ());
    let cf_path = Filename.concat path "chainstate-rocks" in
    { cf = Cf_chainstate.open_db cf_path; rocksdb_utxo = None;
      batch_write_count = 0 }

  let close t = Cf_chainstate.close t.cf

  let attach_rocksdb_utxo t r = t.rocksdb_utxo <- Some r

  (* 36-byte key format used by Rocksdb_store / OptimizedUtxoSet.utxo_key.
     [Cf_chainstate.utxo_key] uses the same layout for the CF backend. *)
  let rocksdb_utxo_key (txid : Types.hash256) (vout : int) : string =
    Cf_chainstate.utxo_key txid vout

  (* Flush any cached-but-not-yet-persisted data to disk.  RocksDB writes
     are durable as soon as [cf_put] / [batch_write] returns when the WAL
     is on (the default), so this is a no-op for parity with the old
     LogStorage.sync. Kept for ABI compatibility with callers that still
     invoke it before close. *)
  let sync t = Cf_chainstate.flush t.cf

  (* Encode height as 4-byte big-endian for lexicographic sorting *)
  let encode_height = Cf_chainstate.encode_height
  let decode_height = Cf_chainstate.decode_height

  (* Block header storage *)
  let store_block_header t (hash : Types.hash256) (header : Types.block_header) =
    let w = Serialize.writer_create () in
    Serialize.serialize_block_header w header;
    Cf_chainstate.put_block_header t.cf hash
      (Cstruct.to_string (Serialize.writer_to_cstruct w))

  let get_block_header t (hash : Types.hash256)
      : Types.block_header option =
    match Cf_chainstate.get_block_header t.cf hash with
    | None -> None
    | Some data ->
      let r = Serialize.reader_of_cstruct (Cstruct.of_string data) in
      Some (Serialize.deserialize_block_header r)

  (* Full block storage *)
  let store_block t (hash : Types.hash256) (block : Types.block) =
    let w = Serialize.writer_create () in
    Serialize.serialize_block w block;
    Cf_chainstate.put_block_data t.cf hash
      (Cstruct.to_string (Serialize.writer_to_cstruct w))

  let get_block t (hash : Types.hash256) : Types.block option =
    match Cf_chainstate.get_block_data t.cf hash with
    | None -> None
    | Some data ->
      let r = Serialize.reader_of_cstruct (Cstruct.of_string data) in
      Some (Serialize.deserialize_block r)

  (* Height to hash mapping *)
  let set_height_hash t (height : int) (hash : Types.hash256) =
    Cf_chainstate.put_block_height t.cf height hash

  let get_hash_at_height t (height : int) : Types.hash256 option =
    Cf_chainstate.get_block_height t.cf height

  (* Transaction storage *)
  let store_transaction t (txid : Types.hash256) (tx : Types.transaction) =
    let w = Serialize.writer_create () in
    Serialize.serialize_transaction w tx;
    Cf_chainstate.put_tx t.cf txid
      (Cstruct.to_string (Serialize.writer_to_cstruct w))

  let get_transaction t (txid : Types.hash256) : Types.transaction option =
    match Cf_chainstate.get_tx t.cf txid with
    | None -> None
    | Some data ->
      let r = Serialize.reader_of_cstruct (Cstruct.of_string data) in
      Some (Serialize.deserialize_transaction r)

  (* UTXO storage - keyed by txid + vout for O(1) lookup *)
  let store_utxo t (txid : Types.hash256) (vout : int) (utxo_data : string) =
    Cf_chainstate.put_utxo t.cf txid vout utxo_data

  let get_utxo t (txid : Types.hash256) (vout : int) : string option =
    match Cf_chainstate.get_utxo t.cf txid vout with
    | Some _ as v -> v
    | None ->
      (* CF miss: fall back to RocksDB if attached.  The stored value
         format (Utxo.serialize_utxo_entry) is identical in both
         backends, so the fallback is a transparent string option. *)
      (match t.rocksdb_utxo with
       | None -> None
       | Some r -> Rocksdb_store.get r (rocksdb_utxo_key txid vout))

  let delete_utxo t (txid : Types.hash256) (vout : int) =
    Cf_chainstate.delete_utxo t.cf txid vout;
    (* Mirror the delete into RocksDB so a spent pre-AV output cannot
       resurface via the [get_utxo] fallback above. *)
    (match t.rocksdb_utxo with
     | None -> ()
     | Some r -> Rocksdb_store.delete r (rocksdb_utxo_key txid vout))

  (* Atomically apply a block's UTXO delta and advance both backends' tips.
     CF batch:        UTXO puts + deletes + chain_tip + header_tip
     RocksDB batch:   UTXO puts + deletes + tip_height (via batch_write)

     Commit order is CF-first so a crash between the two commits leaves
     rdb_tip < chain_tip, which [cli.ml]'s boot consistency check
     already handles (rewinds blocks_synced to rdb_tip; the next IBD
     re-processes the gap using RocksDB as the authoritative pre-gap
     UTXO snapshot via [get_utxo]'s fallback path). *)
  let apply_block_atomic t
      ~(tip_hash : Types.hash256) ~(tip_height : int)
      ~(header_tip_hash : Types.hash256) ~(header_tip_height : int)
      (ops : (Types.hash256 * int * [ `Add of string | `Del ]) list)
      : unit =
    let cf_batch = Cf_chainstate.batch_create t.cf in
    let rdb_ops =
      List.rev_map (fun (txid, vout, op) ->
        let rdb_key = rocksdb_utxo_key txid vout in
        (match op with
         | `Add data ->
           Cf_chainstate.batch_put_utxo cf_batch txid vout data;
           (rdb_key, Some data)
         | `Del ->
           Cf_chainstate.batch_delete_utxo cf_batch txid vout;
           (rdb_key, None))
      ) ops
    in
    Cf_chainstate.batch_put_chain_state cf_batch
      "tip_hash" (Cstruct.to_string tip_hash);
    Cf_chainstate.batch_put_chain_state cf_batch
      "tip_height" (encode_height tip_height);
    Cf_chainstate.batch_put_chain_state cf_batch
      "header_tip_hash" (Cstruct.to_string header_tip_hash);
    Cf_chainstate.batch_put_chain_state cf_batch
      "header_tip_height" (encode_height header_tip_height);
    Cf_chainstate.batch_write cf_batch;
    (match t.rocksdb_utxo with
     | None -> ()
     | Some r -> Rocksdb_store.batch_write ~tip_height r rdb_ops)

  (* Chain state - tip hash and height (validated blocks) *)
  let set_chain_tip t (hash : Types.hash256) (height : int) =
    let batch = Cf_chainstate.batch_create t.cf in
    Cf_chainstate.batch_put_chain_state batch "tip_hash"
      (Cstruct.to_string hash);
    Cf_chainstate.batch_put_chain_state batch "tip_height"
      (encode_height height);
    Cf_chainstate.batch_write batch

  let get_chain_tip t : (Types.hash256 * int) option =
    match Cf_chainstate.get_chain_state t.cf "tip_hash",
          Cf_chainstate.get_chain_state t.cf "tip_height" with
    | Some hash_str, Some height_str ->
      let hash = Cstruct.of_string hash_str in
      let height = decode_height height_str in
      Some (hash, height)
    | _ -> None

  (* Header tip - separate from chain tip (headers can be ahead of validated blocks) *)
  let set_header_tip t (hash : Types.hash256) (height : int) =
    let batch = Cf_chainstate.batch_create t.cf in
    Cf_chainstate.batch_put_chain_state batch "header_tip_hash"
      (Cstruct.to_string hash);
    Cf_chainstate.batch_put_chain_state batch "header_tip_height"
      (encode_height height);
    Cf_chainstate.batch_write batch

  let get_header_tip t : (Types.hash256 * int) option =
    match Cf_chainstate.get_chain_state t.cf "header_tip_hash",
          Cf_chainstate.get_chain_state t.cf "header_tip_height" with
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
    Cf_chainstate.put_tx_index t.cf txid
      (Cstruct.to_string (Serialize.writer_to_cstruct w))

  let get_tx_index t (txid : Types.hash256) : (Types.hash256 * int) option =
    match Cf_chainstate.get_tx_index t.cf txid with
    | None -> None
    | Some data ->
      let r = Serialize.reader_of_cstruct (Cstruct.of_string data) in
      let block_hash = Serialize.read_bytes r 32 in
      let tx_idx = Int32.to_int (Serialize.read_int32_le r) in
      Some (block_hash, tx_idx)

  (* Delete a tx_index entry. Used by [Sync.reorganize] to revert the
     txid -> (block_hash, tx_index) mapping when a block is disconnected.
     Mirrors Bitcoin Core's [BaseIndex::BlockDisconnected] -> [CustomRemove]
     in [src/index/txindex.cpp] (TxIndex::CustomRemove). *)
  let delete_tx_index t (txid : Types.hash256) =
    Cf_chainstate.delete_tx_index t.cf txid

  (* Invalidated block tracking for invalidateblock/reconsiderblock RPCs *)
  let set_block_invalidated t (hash : Types.hash256) =
    Cf_chainstate.put_invalidated t.cf hash

  let clear_block_invalidated t (hash : Types.hash256) =
    Cf_chainstate.delete_invalidated t.cf hash

  let is_block_invalidated t (hash : Types.hash256) : bool =
    Cf_chainstate.is_invalidated t.cf hash

  let get_all_invalidated_blocks t : Types.hash256 list =
    let results = ref [] in
    Cf_chainstate.iter_invalidated t.cf (fun hash ->
      results := hash :: !results);
    !results

  (* Batch operations for atomic updates.

     The batch type is a [Cf_chainstate.batch], but we hide it behind
     an indirection so [batch_create] can keep its old [unit]
     signature. The batch is materialized lazily on first put/delete
     by stashing the parent ChainDB.t in a ref. The [batch_write]
     entry point promotes the ref to a real batch and commits it. *)
  type batch = {
    mutable inner : Cf_chainstate.batch option;
    pending : (Cf_chainstate.batch -> unit) Queue.t;
  }

  let batch_create () : batch = {
    inner = None;
    pending = Queue.create ();
  }

  let with_batch_for (batch : batch) (t : t) (f : Cf_chainstate.batch -> unit) =
    let b =
      match batch.inner with
      | Some b -> b
      | None ->
        let b = Cf_chainstate.batch_create t.cf in
        batch.inner <- Some b;
        (* Drain previously queued operations into the now-realized batch. *)
        Queue.iter (fun op -> op b) batch.pending;
        Queue.clear batch.pending;
        b
    in
    f b

  (* When the parent ChainDB is not yet known (e.g. callers create a batch
     and then call [batch_*_*] before [batch_write]), queue the operation
     and replay against the real batch when [batch_write t b] runs. *)
  let queue_op (batch : batch) (op : Cf_chainstate.batch -> unit) =
    match batch.inner with
    | Some b -> op b
    | None -> Queue.add op batch.pending

  let batch_store_block_header batch (hash : Types.hash256)
      (header : Types.block_header) =
    let w = Serialize.writer_create () in
    Serialize.serialize_block_header w header;
    let data = Cstruct.to_string (Serialize.writer_to_cstruct w) in
    queue_op batch (fun b ->
      Cf_chainstate.batch_put_block_header b hash data)

  let batch_store_utxo batch (txid : Types.hash256) (vout : int)
      (utxo_data : string) =
    queue_op batch (fun b ->
      Cf_chainstate.batch_put_utxo b txid vout utxo_data)

  let batch_delete_utxo batch (txid : Types.hash256) (vout : int) =
    queue_op batch (fun b ->
      Cf_chainstate.batch_delete_utxo b txid vout)

  let batch_set_chain_tip batch (hash : Types.hash256) (height : int) =
    let h = encode_height height in
    let hs = Cstruct.to_string hash in
    queue_op batch (fun b ->
      Cf_chainstate.batch_put_chain_state b "tip_hash" hs;
      Cf_chainstate.batch_put_chain_state b "tip_height" h)

  let batch_set_header_tip batch (hash : Types.hash256) (height : int) =
    let h = encode_height height in
    let hs = Cstruct.to_string hash in
    queue_op batch (fun b ->
      Cf_chainstate.batch_put_chain_state b "header_tip_hash" hs;
      Cf_chainstate.batch_put_chain_state b "header_tip_height" h)

  let batch_write t (batch : batch) : unit =
    with_batch_for batch t (fun _b -> ());
    (match batch.inner with
     | None -> ()  (* empty batch, nothing to commit *)
     | Some b ->
       Cf_chainstate.batch_write b;
       batch.inner <- None;
       t.batch_write_count <- t.batch_write_count + 1)

  (* Test-facing accessors for the batch-commit counter.  See [batch_write_count]
     above for rationale. *)
  let get_batch_write_count t : int = t.batch_write_count
  let reset_batch_write_count t : unit = t.batch_write_count <- 0

  (* Iterate over all UTXOs *)
  let iter_utxos t f =
    Rocksdb.cf_iter t.cf.db t.cf.cfh_utxo (fun key value ->
      (* Key layout: txid(32) ++ vout_le(4), no prefix. *)
      if String.length key = 36 then begin
        let txid = Cstruct.of_string (String.sub key 0 32) in
        let b0 = Char.code key.[32] in
        let b1 = Char.code key.[33] in
        let b2 = Char.code key.[34] in
        let b3 = Char.code key.[35] in
        let vout = b0 lor (b1 lsl 8) lor (b2 lsl 16) lor (b3 lsl 24) in
        f txid vout value
      end)

  (* Check if block exists *)
  let has_block t (hash : Types.hash256) : bool =
    Option.is_some (Cf_chainstate.get_block_data t.cf hash)

  let has_block_header t (hash : Types.hash256) : bool =
    Option.is_some (Cf_chainstate.get_block_header t.cf hash)

  let delete_block t (hash : Types.hash256) =
    Cf_chainstate.delete_block_data t.cf hash

  let batch_delete_block batch (hash : Types.hash256) =
    queue_op batch (fun b ->
      Cf_chainstate.batch_delete_block_data b hash)

  (* Block nTx index: stores transaction count per block hash.
     Written for every connected block (including assume-valid IBD) so
     getblockheader can return a correct nTx without needing the full block
     body in the block data CF.  The key lives in cfh_chain_state with a
     "n:" prefix to avoid collisions with the short ASCII chain-state keys
     ("tip_hash", etc.). *)
  let store_block_ntx t (hash : Types.hash256) (n : int) =
    Cf_chainstate.put_block_ntx t.cf hash n

  let get_block_ntx t (hash : Types.hash256) : int option =
    Cf_chainstate.get_block_ntx t.cf hash

  (* Undo data storage - keyed by block hash for chain reorganizations.
     We append a sha256 checksum to the value (matching the legacy
     LogStorage layout) so corruption from a torn write surfaces as a
     [None] read instead of a silently-bad block disconnect. *)
  let store_undo_data t (block_hash : Types.hash256) (undo_data : string) =
    let checksum = Crypto.sha256 (Cstruct.of_string undo_data) in
    Cf_chainstate.put_undo_data t.cf block_hash
      (undo_data ^ Cstruct.to_string checksum)

  let get_undo_data t (block_hash : Types.hash256) : string option =
    match Cf_chainstate.get_undo_data t.cf block_hash with
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
    Cf_chainstate.delete_undo_data t.cf block_hash

  (* Batch undo data operations *)
  let batch_store_undo_data batch (block_hash : Types.hash256)
      (undo_data : string) =
    let checksum = Crypto.sha256 (Cstruct.of_string undo_data) in
    let payload = undo_data ^ Cstruct.to_string checksum in
    queue_op batch (fun b ->
      Cf_chainstate.batch_put_undo_data b block_hash payload)

  let batch_delete_undo_data batch (block_hash : Types.hash256) =
    queue_op batch (fun b ->
      Cf_chainstate.batch_delete_undo_data b block_hash)

  (* --- Batched block / tx / tx_index / height-hash operations ---------------
     Added for the Pattern D-FULL reorg-atomicity refactor (sync.ml::reorganize):
     a multi-block reorg accumulates UTXO + undo + block + tx_index + tip
     mutations into ONE shared batch, and commits with a single batch_write.
     Mirrors Bitcoin Core's CCoinsViewDB::BatchWrite + BlockManager
     [WriteBlockToDisk] coordination on the active-chain flip. *)

  let batch_store_block batch (hash : Types.hash256) (block : Types.block) =
    let w = Serialize.writer_create () in
    Serialize.serialize_block w block;
    let data = Cstruct.to_string (Serialize.writer_to_cstruct w) in
    queue_op batch (fun b ->
      Cf_chainstate.batch_put_block_data b hash data)

  let batch_set_height_hash batch (height : int) (hash : Types.hash256) =
    queue_op batch (fun b ->
      Cf_chainstate.batch_put_block_height b height hash)

  let batch_store_transaction batch (txid : Types.hash256)
      (tx : Types.transaction) =
    let w = Serialize.writer_create () in
    Serialize.serialize_transaction w tx;
    let data = Cstruct.to_string (Serialize.writer_to_cstruct w) in
    queue_op batch (fun b ->
      Cf_chainstate.batch_put_tx b txid data)

  let batch_store_tx_index batch (txid : Types.hash256)
      (block_hash : Types.hash256) (tx_idx : int) =
    let w = Serialize.writer_create () in
    Serialize.write_bytes w block_hash;
    Serialize.write_int32_le w (Int32.of_int tx_idx);
    let data = Cstruct.to_string (Serialize.writer_to_cstruct w) in
    queue_op batch (fun b ->
      Cf_chainstate.batch_put_tx_index b txid data)

  let batch_delete_tx_index batch (txid : Types.hash256) =
    queue_op batch (fun b ->
      Cf_chainstate.batch_delete_tx_index b txid)

  (* --- Ban list (peer_manager.ml) -----------------------------------------
     Bans were stored under LogStorage prefix "B"; in the CF backend they
     live in their own namespace ([Cf_chainstate.cf_ban_list]) so the
     per-peer-banlist iteration no longer needs a prefix scan over a
     mixed keyspace. *)
  let put_ban t (addr : string) (data : string) =
    Cf_chainstate.put_ban t.cf addr data

  let delete_ban t (addr : string) =
    Cf_chainstate.delete_ban t.cf addr

  let iter_bans t (f : string -> string -> unit) =
    Cf_chainstate.iter_bans t.cf f
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
  | Block_failed_child    (** Descendant of a failed block *)
  | Block_pruned          (** Block data has been pruned *)

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
    | Block_failed_child -> 10
    | Block_pruned -> 9

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
    | 10 -> Block_failed_child
    | 9 -> Block_pruned
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
       Block_have_data; Block_have_undo; Block_failed; Block_failed_child;
       Block_pruned] in
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

  (* ============================================================================
     Block Pruning (Bitcoin Core compatible)

     Reference: Bitcoin Core's node/blockstorage.cpp (PruneOneBlockFile, FindFilesToPrune)

     Pruning removes old block and undo data files to reduce disk usage.
     Key constraints:
     - Minimum prune target: 550MB
     - Keep at least 288 blocks (MIN_BLOCKS_TO_KEEP) for reorg safety
     - Pruned blocks cannot be served to peers (getdata returns notfound)
     - Transaction index (-txindex) is incompatible with pruning
     ============================================================================ *)

  (** Minimum prune target in bytes (550 MB) *)
  let min_prune_target_bytes = 550 * 1024 * 1024

  (** Minimum blocks to keep for reorg safety (2 days worth) *)
  let min_blocks_to_keep = 288

  (** Calculate current disk usage (sum of block + undo sizes for all files) *)
  let calculate_current_usage t =
    Array.fold_left (fun acc fi ->
      acc + fi.n_size + fi.n_undo_size
    ) 0 t.file_info

  (** Check if a block has been pruned *)
  let is_block_pruned t (hash : Types.hash256) : bool =
    match Hashtbl.find_opt t.block_index (Cstruct.to_string hash) with
    | None -> false
    | Some entry -> List.mem Block_pruned entry.status

  (** Check if we have block data (not pruned) *)
  let has_block_data t (hash : Types.hash256) : bool =
    match Hashtbl.find_opt t.block_index (Cstruct.to_string hash) with
    | None -> false
    | Some entry ->
      List.mem Block_have_data entry.status &&
      not (List.mem Block_pruned entry.status)

  (** Prune a single block file (matching Bitcoin Core's PruneOneBlockFile).
      Clears BLOCK_HAVE_DATA and BLOCK_HAVE_UNDO flags for all blocks in the file,
      marks them as pruned, resets file positions, and clears file info. *)
  let prune_one_block_file t (file_number : int) : unit =
    (* Update all block index entries that reference this file *)
    Hashtbl.iter (fun hash_key entry ->
      if entry.file_pos.file_num = file_number then begin
        (* Clear data/undo flags and add pruned flag *)
        let new_status =
          Block_pruned ::
          (List.filter (fun s ->
            s <> Block_have_data && s <> Block_have_undo
          ) entry.status)
        in
        let new_entry = {
          entry with
          file_pos = null_pos;
          undo_pos = null_pos;
          status = new_status;
        } in
        Hashtbl.replace t.block_index hash_key new_entry
      end
    ) t.block_index;
    (* Clear the file info *)
    if file_number < Array.length t.file_info then begin
      let fi = t.file_info.(file_number) in
      fi.n_blocks <- 0;
      fi.n_size <- 0;
      fi.n_undo_size <- 0;
      fi.height_first <- max_int;
      fi.height_last <- 0;
      fi.time_first <- Int32.max_int;
      fi.time_last <- 0l
    end;
    t.dirty <- true

  (** Delete the actual blk/rev files from disk *)
  let unlink_pruned_files t (file_numbers : int list) : unit =
    List.iter (fun file_num ->
      let blk_path = block_file_path t file_num in
      let rev_path = undo_file_path t file_num in
      (try Sys.remove blk_path with Sys_error _ -> ());
      (try Sys.remove rev_path with Sys_error _ -> ())
    ) file_numbers

  (** Find files eligible for pruning based on target size.
      Returns list of file numbers to prune.

      A file is eligible if:
      1. It has data (n_size > 0)
      2. All blocks in the file are below the pruning height
         (height_last <= chain_height - min_blocks_to_keep)

      prune_target_bytes: target disk usage in bytes
      chain_height: current validated chain height *)
  let find_files_to_prune t ~(prune_target_bytes : int) ~(chain_height : int)
      : int list =
    let current_usage = calculate_current_usage t in
    if current_usage <= prune_target_bytes then
      []  (* Already below target *)
    else begin
      let last_block_can_prune = chain_height - min_blocks_to_keep in
      let files_to_prune = ref [] in
      let running_usage = ref current_usage in
      (* Iterate through files in order (prune oldest first) *)
      for file_num = 0 to Array.length t.file_info - 1 do
        if !running_usage > prune_target_bytes then begin
          let fi = t.file_info.(file_num) in
          (* Check if file has data and all blocks are below prune height *)
          if fi.n_size > 0 && fi.height_last <= last_block_can_prune then begin
            files_to_prune := file_num :: !files_to_prune;
            running_usage := !running_usage - fi.n_size - fi.n_undo_size
          end
        end
      done;
      List.rev !files_to_prune
    end

  (** Perform pruning to reduce disk usage below target.
      Returns the number of files pruned.

      prune_target_mb: target disk usage in MB (minimum 550)
      chain_height: current validated chain height *)
  let prune_block_files t ~(prune_target_mb : int) ~(chain_height : int) : int =
    (* Enforce minimum prune target *)
    let target_bytes = max min_prune_target_bytes (prune_target_mb * 1024 * 1024) in
    let files_to_prune = find_files_to_prune t ~prune_target_bytes:target_bytes
        ~chain_height in
    (* Prune each file *)
    List.iter (fun file_num ->
      prune_one_block_file t file_num
    ) files_to_prune;
    (* Delete actual files from disk *)
    unlink_pruned_files t files_to_prune;
    (* Save updated index *)
    if files_to_prune <> [] then
      save_index t;
    List.length files_to_prune

  (** Check if pruning is enabled and compatible with current settings.
      Returns Error if -txindex is enabled with pruning. *)
  let check_prune_compatibility ~(txindex : bool) ~(prune_target_mb : int)
      : (unit, string) result =
    if prune_target_mb > 0 && txindex then
      Error "Pruning is incompatible with -txindex. Disable txindex or pruning."
    else if prune_target_mb > 0 && prune_target_mb < 550 then
      Error "Prune target must be at least 550 MB"
    else
      Ok ()

  (** Get pruning statistics *)
  type prune_stats = {
    current_usage_mb : int;
    pruned_files : int;
    total_files : int;
    pruned_blocks : int;
  }

  let get_prune_stats t : prune_stats =
    let current_usage = calculate_current_usage t in
    let pruned_files = ref 0 in
    let pruned_blocks = ref 0 in
    let total_files = Array.length t.file_info in
    (* Count files with zero size (pruned) *)
    Array.iter (fun fi ->
      if fi.n_size = 0 && fi.n_blocks = 0 then
        incr pruned_files
    ) t.file_info;
    (* Count pruned blocks *)
    Hashtbl.iter (fun _ entry ->
      if List.mem Block_pruned entry.status then
        incr pruned_blocks
    ) t.block_index;
    {
      current_usage_mb = current_usage / 1024 / 1024;
      pruned_files = !pruned_files;
      total_files;
      pruned_blocks = !pruned_blocks;
    }
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
