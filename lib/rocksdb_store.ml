(* RocksDB-backed UTXO store.
   Wraps the low-level Rocksdb module with UTXO-specific key encoding
   and serialization, configured for high-throughput IBD. *)

type t = {
  db : Rocksdb.t;
}

(* Open (or create) a RocksDB database at [path].
   Tuning: 256 MB write buffer, 8 GB block cache, 10-bit bloom filter.
   The block cache was raised 2 GB -> 8 GB: profiling the mainnet sync showed
   camlcoin disk-I/O bound (~40% of time in random RocksDB UTXO reads), so a
   larger SST block cache cuts read amplification on the hot UTXO column. *)
let open_db ?(write_buffer_mb=256) ?(block_cache_mb=8192) ?(bloom_bits=10)
    (path : string) : t =
  (* Ensure parent directory exists *)
  (try Unix.mkdir path 0o755
   with Unix.Unix_error (Unix.EEXIST, _, _) -> ());
  let db = Rocksdb.open_db path write_buffer_mb block_cache_mb bloom_bits in
  { db }

let close (t : t) : unit =
  Rocksdb.close t.db

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
