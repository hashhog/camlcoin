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

(* Walk every coin in the store, in outpoint-key order (txid32 ++ vout LE32,
   bytewise -- the same order and layout as Cf_chainstate's UTXO CF, so
   Storage.ChainDB.iter_utxos and this walk interleave identically).  The
   store also holds [meta_key] entries ("__meta__tip_height", 18 bytes);
   every coin key is exactly 36 bytes, so the length test skips metadata
   without having to name each meta key.  Read-only; one point-in-time
   RocksDB snapshot for the whole walk. *)
let iter_utxos (t : t) (f : Types.hash256 -> int -> string -> unit) : unit =
  Rocksdb.iter t.db (fun key value ->
    if String.length key = 36 then begin
      let txid = Cstruct.of_string (String.sub key 0 32) in
      let vout =
        Char.code key.[32]
        lor (Char.code key.[33] lsl 8)
        lor (Char.code key.[34] lsl 16)
        lor (Char.code key.[35] lsl 24)
      in
      f txid vout value
    end)

(* Explicit point-in-time view of the coin store, for a walk that runs
   later and elsewhere (gettxoutsetinfo on its own domain).  Take it in the
   same main-thread instant as any in-memory state the walk overlays. *)
type snapshot = Rocksdb.snapshot

let snapshot (t : t) : snapshot = Rocksdb.snapshot_create t.db

let release_snapshot (s : snapshot) : unit = Rocksdb.snapshot_release s

(* [iter_utxos] over [snap]: same order, same 36-byte key filter. *)
let iter_utxos_at (snap : snapshot)
    (f : Types.hash256 -> int -> string -> unit) : unit =
  Rocksdb.iter_snapshot snap (fun key value ->
    if String.length key = 36 then begin
      let txid = Cstruct.of_string (String.sub key 0 32) in
      let vout =
        Char.code key.[32]
        lor (Char.code key.[33] lsl 8)
        lor (Char.code key.[34] lsl 16)
        lor (Char.code key.[35] lsl 24)
      in
      f txid vout value
    end)

(* Metadata key prefix — uses a prefix that cannot collide with
   the 36-byte outpoint keys (which are raw binary). *)
let meta_key k = "__meta__" ^ k

(* 4-byte little-endian tip_height value, as every writer below stores it. *)
let encode_tip_height (h : int) : string =
  let buf = Bytes.create 4 in
  Bytes.set buf 0 (Char.chr (h land 0xff));
  Bytes.set buf 1 (Char.chr ((h lsr 8) land 0xff));
  Bytes.set buf 2 (Char.chr ((h lsr 16) land 0xff));
  Bytes.set buf 3 (Char.chr ((h lsr 24) land 0xff));
  Bytes.unsafe_to_string buf

(* Head marker (Core DB_HEAD_BLOCKS, txdb.cpp).  The coins live in this
   store AND in the chainstate column families (Storage.ChainDB), which
   also hold the tip.  They are two RocksDB instances, so no WriteBatch
   spans both: every commit writes this store first and the chainstate
   second.  A crash between the two leaves [tip_height] here ahead of, or
   (after a reorg) on another branch from, the chainstate tip, and heights
   alone cannot say which block this coin set belongs to.

   So every batch that moves [tip_height] also records, in the SAME batch,
   the block hash the coins are now at ([head_new]) and the chainstate tip
   they moved away from ([head_old]), with the height.  At boot,
   [Chainstate_heads.recover_on_boot] compares [head_new] with the
   chainstate tip by hash and, if the second commit is missing, replays it.
   A batch that moves [tip_height] without a hash deletes the marker, so a
   stale marker can never describe a newer coin set; boot then falls back
   to the height checks in cli.ml. *)
let head_blocks_key = meta_key "head_blocks"

type head_blocks = {
  head_new : Types.hash256;
  head_old : Types.hash256;
  head_height : int;
}

let encode_head_blocks ~(new_hash : Types.hash256) ~(old_hash : Types.hash256)
    (height : int) : string =
  Cstruct.to_string new_hash ^ Cstruct.to_string old_hash
  ^ encode_tip_height height

let decode_head_blocks (s : string) : head_blocks option =
  if String.length s <> 68 then None
  else
    let b i = Char.code s.[64 + i] in
    Some { head_new = Cstruct.of_string (String.sub s 0 32);
           head_old = Cstruct.of_string (String.sub s 32 32);
           head_height = b 0 lor (b 1 lsl 8) lor (b 2 lsl 16) lor (b 3 lsl 24) }

let get_head_blocks (t : t) : head_blocks option =
  match Rocksdb.get t.db head_blocks_key with
  | None -> None
  | Some s -> decode_head_blocks s

(* Stage [tip_height] and the head marker into [wb]. *)
let batch_put_tip wb ~(tip_height : int option)
    ~(head : (Types.hash256 * Types.hash256) option) =
  match tip_height with
  | None -> ()
  | Some h ->
    Rocksdb.write_batch_put wb (meta_key "tip_height") (encode_tip_height h);
    (match head with
     | Some (new_hash, old_hash) ->
       Rocksdb.write_batch_put wb head_blocks_key
         (encode_head_blocks ~new_hash ~old_hash h)
     | None -> Rocksdb.write_batch_delete wb head_blocks_key)

(* Atomic batch write.  Each element is (key, value_opt) where
   None means delete and Some v means put.
   When [tip_height] is provided it is included in the SAME WriteBatch
   so that UTXO mutations and the recorded tip are always consistent;
   [head] is the (new, old) block hash pair for the head marker above. *)
let batch_write ?(tip_height : int option) ?head (t : t)
    (ops : (string * string option) list) : unit =
  let wb = Rocksdb.write_batch_create () in
  List.iter (fun (key, v_opt) ->
    match v_opt with
    | Some v -> Rocksdb.write_batch_put wb key v
    | None   -> Rocksdb.write_batch_delete wb key
  ) ops;
  batch_put_tip wb ~tip_height ~head;
  Rocksdb.write_batch_write t.db wb;
  Rocksdb.write_batch_destroy wb

(* Store the UTXO tip height so we can detect inconsistency with
   the chainstate's chain_tip on startup. *)
let set_tip_height ?head (t : t) (height : int) : unit =
  batch_write ~tip_height:height ?head t []

(* Flush a dirty hashtable directly into a WriteBatch, avoiding the
   intermediate list allocation that batch_write requires.
   Each dirty entry is serialized and added to the batch in-place. *)
let flush_dirty ?(tip_height : int option) ?head (t : t)
    (dirty : (string, [ `Added of Cstruct.t | `Removed ]) Hashtbl.t) : unit =
  let wb = Rocksdb.write_batch_create () in
  Hashtbl.iter (fun key entry ->
    match entry with
    | `Added data -> Rocksdb.write_batch_put wb key (Cstruct.to_string data)
    | `Removed -> Rocksdb.write_batch_delete wb key
  ) dirty;
  batch_put_tip wb ~tip_height ~head;
  Rocksdb.write_batch_write t.db wb;
  Rocksdb.write_batch_destroy wb

(* Delete every key: all coins, [tip_height] and the head marker.  For a
   rewind of the chainstate to genesis: a coin set left behind would meet
   every block of the re-sync as a duplicate (BIP30) or a spent input.
   Deleted in batches while iterating (the iterator reads a snapshot, as
   in [Cf_chainstate.cf_clear]).  Returns the number of keys deleted. *)
let clear ?(batch_size = 10_000) (t : t) : int =
  let count = ref 0 in
  let pending = ref [] and n = ref 0 in
  let flush () =
    if !pending <> [] then begin
      let wb = Rocksdb.write_batch_create () in
      List.iter (fun k -> Rocksdb.write_batch_delete wb k) !pending;
      Rocksdb.write_batch_write t.db wb;
      Rocksdb.write_batch_destroy wb;
      pending := []; n := 0
    end
  in
  Rocksdb.iter t.db (fun key _value ->
    pending := key :: !pending;
    incr n; incr count;
    if !n >= batch_size then flush ());
  flush ();
  !count

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
