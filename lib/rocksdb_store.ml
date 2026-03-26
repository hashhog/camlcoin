(* RocksDB-backed UTXO store.
   Wraps the low-level Rocksdb module with UTXO-specific key encoding
   and serialization, configured for high-throughput IBD. *)

type t = {
  db : Rocksdb.t;
}

(* Open (or create) a RocksDB database at [path].
   Tuning: 64 MB write buffer, 256 MB block cache, 10-bit bloom filter. *)
let open_db ?(write_buffer_mb=64) ?(block_cache_mb=256) ?(bloom_bits=10)
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

(* Atomic batch write.  Each element is (key, value_opt) where
   None means delete and Some v means put. *)
let batch_write (t : t) (ops : (string * string option) list) : unit =
  let wb = Rocksdb.write_batch_create () in
  List.iter (fun (key, v_opt) ->
    match v_opt with
    | Some v -> Rocksdb.write_batch_put wb key v
    | None   -> Rocksdb.write_batch_delete wb key
  ) ops;
  Rocksdb.write_batch_write t.db wb;
  Rocksdb.write_batch_destroy wb
