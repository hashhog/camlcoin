(* RocksDB-backed UTXO store.
   Wraps the low-level Rocksdb module with UTXO-specific key encoding
   and serialization, configured for high-throughput IBD. *)

type t = {
  db : Rocksdb.t;
  block_cache_mb : int;
  write_buffer_mb : int;
}

(* --dbcache N is ENTRIES. range-runner.sh converts MiB → entries as
   [MiB * 4096], i.e. 256 bytes/entry, so the campaign's
   `--dbcache 4194304` is a ~1 GiB budget. The OCaml LRU is sized in
   those entries; the RocksDB SST cache used to ignore the flag and
   open at 8192 MiB (plus the CF store at 2048 MiB). Slice 419311→450000
   on 2da7d6b then held 11.2 GB RSS against that 1 GiB budget. *)
let bytes_per_dbcache_entry = 256
let default_dbcache_entries = 4_000_000

let budget_mb entries =
  max 0 (entries / 4096)

(* 1/4 of the implied byte budget, min 32 MiB so a tiny --dbcache still
   has an SST cache, cap 512 MiB so raising --dbcache cannot recreate
   the 8 GiB side allocation. Campaign 4_194_304 → 256 MiB. *)
let block_cache_mb_of_dbcache entries =
  max 32 (min 512 (budget_mb entries / 4))

(* 1/16 of the implied byte budget, min 16 MiB, cap 64 MiB.
   Campaign 4_194_304 → 64 MiB (× max_write_buffer_number=3 in the stub). *)
let write_buffer_mb_of_dbcache entries =
  max 16 (min 64 (budget_mb entries / 16))

let default_block_cache_mb =
  block_cache_mb_of_dbcache default_dbcache_entries

let default_write_buffer_mb =
  write_buffer_mb_of_dbcache default_dbcache_entries

let is_camlcoin_tmp_path path =
  let has_prefix pfx =
    let n = String.length pfx in
    String.length path >= n && String.sub path 0 n = pfx
  in
  has_prefix "/tmp/camlcoin_"
  || has_prefix (Filename.concat (Filename.get_temp_dir_name ()) "camlcoin_")

(* Open (or create) a RocksDB database at [path].
   Block cache and write buffer are derived from --dbcache (see
   [block_cache_mb_of_dbcache]) unless the caller passes them. Paths
   under /tmp/camlcoin_* keep the 1 MiB / 8 MiB test convention so a
   forgotten teardown cannot pin hundreds of MiB on the tmpfs. *)
let open_db ?write_buffer_mb ?block_cache_mb ?(bloom_bits=10)
    (path : string) : t =
  (try Unix.mkdir path 0o755
   with Unix.Unix_error (Unix.EEXIST, _, _) -> ());
  let test_path = is_camlcoin_tmp_path path in
  let write_buffer_mb =
    match write_buffer_mb with
    | Some n -> n
    | None -> if test_path then 1 else default_write_buffer_mb
  in
  let block_cache_mb =
    match block_cache_mb with
    | Some n -> n
    | None -> if test_path then 8 else default_block_cache_mb
  in
  let db = Rocksdb.open_db path write_buffer_mb block_cache_mb bloom_bits in
  { db; block_cache_mb; write_buffer_mb }

let close (t : t) : unit =
  Rocksdb.close t.db

let block_cache_mb (t : t) : int = t.block_cache_mb
let write_buffer_mb (t : t) : int = t.write_buffer_mb
let block_cache_bytes (t : t) : int = t.block_cache_mb * 1024 * 1024

(* Raw key-value access — keys are the 36-byte outpoint strings
   already constructed by OptimizedUtxoSet.utxo_key *)

let get (t : t) (key : string) : string option =
  Rocksdb.get t.db key

let put (t : t) (key : string) (value : string) : unit =
  Rocksdb.put t.db key value

let delete (t : t) (key : string) : unit =
  Rocksdb.delete t.db key

(* Metadata key prefix — uses a prefix that cannot collide with
   the 36-byte outpoint keys (which are raw binary). *)
let meta_key k = "__meta__" ^ k

(* Atomic batch write.  Each element is (key, value_opt) where
   None means delete and Some v means put.
   When [tip_height] is provided it is included in the SAME WriteBatch
   so that UTXO mutations and the recorded tip are always consistent. *)
let batch_write ?(tip_height : int option) (t : t)
    (ops : (string * string option) list) : unit =
  let wb = Rocksdb.write_batch_create () in
  List.iter (fun (key, v_opt) ->
    match v_opt with
    | Some v -> Rocksdb.write_batch_put wb key v
    | None   -> Rocksdb.write_batch_delete wb key
  ) ops;
  (* Include tip_height in the same atomic batch *)
  (match tip_height with
   | Some h ->
     let buf = Bytes.create 4 in
     Bytes.set buf 0 (Char.chr (h land 0xff));
     Bytes.set buf 1 (Char.chr ((h lsr 8) land 0xff));
     Bytes.set buf 2 (Char.chr ((h lsr 16) land 0xff));
     Bytes.set buf 3 (Char.chr ((h lsr 24) land 0xff));
     Rocksdb.write_batch_put wb (meta_key "tip_height")
       (Bytes.unsafe_to_string buf)
   | None -> ());
  Rocksdb.write_batch_write t.db wb;
  Rocksdb.write_batch_destroy wb

(* Store the UTXO tip height so we can detect inconsistency with
   the chainstate's chain_tip on startup. *)
let set_tip_height (t : t) (height : int) : unit =
  let buf = Bytes.create 4 in
  Bytes.set buf 0 (Char.chr (height land 0xff));
  Bytes.set buf 1 (Char.chr ((height lsr 8) land 0xff));
  Bytes.set buf 2 (Char.chr ((height lsr 16) land 0xff));
  Bytes.set buf 3 (Char.chr ((height lsr 24) land 0xff));
  Rocksdb.put t.db (meta_key "tip_height") (Bytes.unsafe_to_string buf)

(* Flush a dirty hashtable directly into a WriteBatch, avoiding the
   intermediate list allocation that batch_write requires.
   Each dirty entry is serialized and added to the batch in-place. *)
let flush_dirty ?(tip_height : int option) (t : t)
    (dirty : (string, [ `Added of Cstruct.t | `Removed ]) Hashtbl.t) : unit =
  let wb = Rocksdb.write_batch_create () in
  Hashtbl.iter (fun key entry ->
    match entry with
    | `Added data -> Rocksdb.write_batch_put wb key (Cstruct.to_string data)
    | `Removed -> Rocksdb.write_batch_delete wb key
  ) dirty;
  (match tip_height with
   | Some h ->
     let buf = Bytes.create 4 in
     Bytes.set buf 0 (Char.chr (h land 0xff));
     Bytes.set buf 1 (Char.chr ((h lsr 8) land 0xff));
     Bytes.set buf 2 (Char.chr ((h lsr 16) land 0xff));
     Bytes.set buf 3 (Char.chr ((h lsr 24) land 0xff));
     Rocksdb.write_batch_put wb (meta_key "tip_height")
       (Bytes.unsafe_to_string buf)
   | None -> ());
  Rocksdb.write_batch_write t.db wb;
  Rocksdb.write_batch_destroy wb

let get_tip_height (t : t) : int option =
  match Rocksdb.get t.db (meta_key "tip_height") with
  | None -> None
  | Some s ->
    if String.length s < 4 then None
    else
      let b0 = Char.code (String.get s 0) in
      let b1 = Char.code (String.get s 1) in
      let b2 = Char.code (String.get s 2) in
      let b3 = Char.code (String.get s 3) in
      Some (b0 lor (b1 lsl 8) lor (b2 lsl 16) lor (b3 lsl 24))
