(* Cf_chainstate — RocksDB column-family chainstate (Option D).

   This is the long-term replacement for [Storage.LogStorage]. It owns one
   RocksDB DB with one column family per logical namespace (block bodies,
   undo data, tx index, etc.) and exposes a typed get/put API for each.

   Why CFs and not one DB per namespace? CFs share the LSM, the WAL, the
   block cache, and crucially the [WriteBatch] commit boundary, which
   matches Bitcoin Core's [CCoinsViewDB::BatchWrite] pattern (see
   bitcoin-core/src/txdb.cpp:23-83). One [batch_write] commits to all CFs
   atomically — that property is what we need to keep [chain_tip],
   [header_tip], block bodies, undo data, and the corresponding UTXO
   mutations all consistent across crashes.

   The 9 namespaces follow the LogStorage prefix layout
   (lib/storage.ml:923-932):

     [h]  block_header   — full block header by hash
     [b]  block_data     — full block body by hash
     [t]  tx             — full tx by txid (used by tx index path)
     [u]  utxo           — UTXO entries
     [n]  block_height   — height -> hash
     [x]  tx_index       — txid -> (block_hash, tx_index)
     [s]  chain_state    — tip / header tip metadata
     [r]  undo_data      — block undo blob + sha256 checksum
     [i]  invalidated    — manually invalidated block hashes

   Each namespace becomes a CF; the keys inside a CF no longer need the
   1-byte prefix that LogStorage required for namespacing in a flat
   keyspace. We keep them prefix-free here, matching Bitcoin Core's
   per-CF layout.

   TODO(option-d):
     - Wire ChainDB call sites (lib/storage.ml ChainDB) to dispatch to
       this module behind a feature flag once the migration command lands.
     - Replace the [LogStorage.iter_prefix] callers in peer_manager.ml
       (ban list) once banlist is migrated.
     - Add per-CF tuning (block bodies want compression+large block
       size, UTXO wants small block size+bloom).  Currently all CFs share
       the same options — cheap and simple, fine for migration scaffolding.
*)

(* CF names. These appear on disk in [chainstate-rocks/] and can be
   listed via [Rocksdb.list_column_families]. Keep stable — changing a
   name is a breaking schema change. *)
let cf_default      = "default"
let cf_block_header = "block_header"
let cf_block_data   = "block_data"
let cf_tx           = "tx"
let cf_utxo         = "utxo"
let cf_block_height = "block_height"
let cf_tx_index     = "tx_index"
let cf_chain_state  = "chain_state"
let cf_undo_data    = "undo_data"
let cf_invalidated  = "invalidated"
(* Ban list CF: holds peer bans previously stored in LogStorage with
   key prefix "B" (peer_manager.ml). The CF naming gives us the
   namespace; keys are bare address strings. *)
let cf_ban_list     = "ban_list"

(* Order MUST match the [cfh] indices in [open_db]. *)
let all_cf_names = [|
  cf_default;
  cf_block_header;
  cf_block_data;
  cf_tx;
  cf_utxo;
  cf_block_height;
  cf_tx_index;
  cf_chain_state;
  cf_undo_data;
  cf_invalidated;
  cf_ban_list;
|]

type t = {
  path : string;
  db : Rocksdb.t;
  cfh_default      : Rocksdb.cf_handle;
  cfh_block_header : Rocksdb.cf_handle;
  cfh_block_data   : Rocksdb.cf_handle;
  cfh_tx           : Rocksdb.cf_handle;
  cfh_utxo         : Rocksdb.cf_handle;
  cfh_block_height : Rocksdb.cf_handle;
  cfh_tx_index     : Rocksdb.cf_handle;
  cfh_chain_state  : Rocksdb.cf_handle;
  cfh_undo_data    : Rocksdb.cf_handle;
  cfh_invalidated  : Rocksdb.cf_handle;
  cfh_ban_list     : Rocksdb.cf_handle;
  mutable closed   : bool;
}

(* In-process registry of open DBs by absolute path. RocksDB acquires
   an OS file lock on each open; opening the same path twice from the
   same process fails with "lock hold by current process". Test
   harnesses (e.g. test_rest.ml) call ChainDB.create on the same path
   across many tests without closing in between, which used to work
   under LogStorage but now needs explicit close-then-reopen. To keep
   the test surface small we transparently close any existing handle
   for the same path before opening a new one. Production callers go
   through ChainDB.create + ChainDB.close exactly once per datadir, so
   this registry is invisible to them. *)
let open_handles : (string, t) Hashtbl.t = Hashtbl.create 8
let registry_lock = Mutex.create ()

let ensure_dir path =
  try Unix.mkdir path 0o755
  with Unix.Unix_error (Unix.EEXIST, _, _) -> ()

let close_unlocked (t : t) : unit =
  if not t.closed then begin
    (* Per the C stub contract: destroy CF handles BEFORE closing the DB.
       We swallow any individual destroy/close failure so that a torn-down
       datadir (e.g. test harness rm -rf while a handle is still open)
       doesn't propagate into the next caller. The handle is marked closed
       either way, so the registry can drop it and a fresh open can
       proceed. *)
    let safe_destroy h =
      try Rocksdb.cf_destroy t.db h with _ -> ()
    in
    safe_destroy t.cfh_default;
    safe_destroy t.cfh_block_header;
    safe_destroy t.cfh_block_data;
    safe_destroy t.cfh_tx;
    safe_destroy t.cfh_utxo;
    safe_destroy t.cfh_block_height;
    safe_destroy t.cfh_tx_index;
    safe_destroy t.cfh_chain_state;
    safe_destroy t.cfh_undo_data;
    safe_destroy t.cfh_invalidated;
    safe_destroy t.cfh_ban_list;
    (try Rocksdb.close t.db with _ -> ());
    t.closed <- true
  end

(* Open (or create) the chainstate at [path]. Creates all 11 CFs +
   the implicit default CF on first call. Subsequent opens require
   the CFs to exist on disk; missing CFs are created automatically
   thanks to [create_missing_column_families = 1] in the C stub. *)
let open_db ?(write_buffer_mb = 256) ?(block_cache_mb = 2048)
    ?(bloom_bits = 10) (path : string) : t =
  ensure_dir path;
  Mutex.protect registry_lock (fun () ->
    (match Hashtbl.find_opt open_handles path with
     | Some prior when not prior.closed ->
       (* Another caller (e.g. an earlier test) already opened the
          same datadir and never called close. RocksDB's per-path
          OS lock would refuse the new open; tear the prior handle
          down first. *)
       close_unlocked prior;
       Hashtbl.remove open_handles path
     | _ -> ()));
  let db, cfhs =
    Rocksdb.open_cfs path all_cf_names
      write_buffer_mb block_cache_mb bloom_bits
  in
  if Array.length cfhs <> Array.length all_cf_names then
    failwith
      "Cf_chainstate.open_db: cf handle count mismatch (rocksdb stub bug)";
  let t = {
    path;
    db;
    cfh_default      = cfhs.(0);
    cfh_block_header = cfhs.(1);
    cfh_block_data   = cfhs.(2);
    cfh_tx           = cfhs.(3);
    cfh_utxo         = cfhs.(4);
    cfh_block_height = cfhs.(5);
    cfh_tx_index     = cfhs.(6);
    cfh_chain_state  = cfhs.(7);
    cfh_undo_data    = cfhs.(8);
    cfh_invalidated  = cfhs.(9);
    cfh_ban_list     = cfhs.(10);
    closed = false;
  } in
  Mutex.protect registry_lock (fun () ->
    Hashtbl.replace open_handles path t);
  t

let close (t : t) : unit =
  Mutex.protect registry_lock (fun () ->
    close_unlocked t;
    (* Only remove the registry entry if it still points at [t] —
       another open could have raced past the registry update. *)
    match Hashtbl.find_opt open_handles t.path with
    | Some t' when t' == t -> Hashtbl.remove open_handles t.path
    | _ -> ())

(* --- Helpers ---------------------------------------------------------- *)

(* Encode height as 4-byte big-endian — matches LogStorage's
   [ChainDB.encode_height] so the migration command doesn't need to
   re-serialize values, only re-route them. *)
let encode_height (h : int) : string =
  let cs = Cstruct.create 4 in
  Cstruct.BE.set_uint32 cs 0 (Int32.of_int h);
  Cstruct.to_string cs

let decode_height (s : string) : int =
  let cs = Cstruct.of_string s in
  Int32.to_int (Cstruct.BE.get_uint32 cs 0)

(* --- Per-namespace get/put -------------------------------------------- *)

(* Block headers, keyed by 32-byte hash *)
let put_block_header (t : t) (hash : Types.hash256) (data : string) =
  Rocksdb.cf_put t.db t.cfh_block_header (Cstruct.to_string hash) data

let get_block_header (t : t) (hash : Types.hash256) : string option =
  Rocksdb.cf_get t.db t.cfh_block_header (Cstruct.to_string hash)

(* Block bodies, keyed by 32-byte hash *)
let put_block_data (t : t) (hash : Types.hash256) (data : string) =
  Rocksdb.cf_put t.db t.cfh_block_data (Cstruct.to_string hash) data

let get_block_data (t : t) (hash : Types.hash256) : string option =
  Rocksdb.cf_get t.db t.cfh_block_data (Cstruct.to_string hash)

let delete_block_data (t : t) (hash : Types.hash256) =
  Rocksdb.cf_delete t.db t.cfh_block_data (Cstruct.to_string hash)

(* Standalone tx, keyed by 32-byte txid *)
let put_tx (t : t) (txid : Types.hash256) (data : string) =
  Rocksdb.cf_put t.db t.cfh_tx (Cstruct.to_string txid) data

let get_tx (t : t) (txid : Types.hash256) : string option =
  Rocksdb.cf_get t.db t.cfh_tx (Cstruct.to_string txid)

(* UTXO. Key is 36-byte raw [txid32 ++ vout_le32] — matches
   Rocksdb_store/OptimizedUtxoSet.utxo_key, with no extra prefix byte
   (the CF supplies the namespacing). *)
let utxo_key (txid : Types.hash256) (vout : int) : string =
  let buf = Bytes.create 36 in
  Cstruct.blit_to_bytes txid 0 buf 0 32;
  Bytes.set buf 32 (Char.chr (vout land 0xff));
  Bytes.set buf 33 (Char.chr ((vout lsr 8) land 0xff));
  Bytes.set buf 34 (Char.chr ((vout lsr 16) land 0xff));
  Bytes.set buf 35 (Char.chr ((vout lsr 24) land 0xff));
  Bytes.unsafe_to_string buf

let put_utxo (t : t) (txid : Types.hash256) (vout : int) (data : string) =
  Rocksdb.cf_put t.db t.cfh_utxo (utxo_key txid vout) data

let get_utxo (t : t) (txid : Types.hash256) (vout : int) : string option =
  Rocksdb.cf_get t.db t.cfh_utxo (utxo_key txid vout)

let delete_utxo (t : t) (txid : Types.hash256) (vout : int) =
  Rocksdb.cf_delete t.db t.cfh_utxo (utxo_key txid vout)

(* Height -> hash, key is 4-byte big-endian height *)
let put_block_height (t : t) (height : int) (hash : Types.hash256) =
  Rocksdb.cf_put t.db t.cfh_block_height
    (encode_height height) (Cstruct.to_string hash)

let get_block_height (t : t) (height : int) : Types.hash256 option =
  match Rocksdb.cf_get t.db t.cfh_block_height (encode_height height) with
  | None -> None
  | Some s -> Some (Cstruct.of_string s)

(* Tx index — txid -> serialized (block_hash, tx_index) blob *)
let put_tx_index (t : t) (txid : Types.hash256) (data : string) =
  Rocksdb.cf_put t.db t.cfh_tx_index (Cstruct.to_string txid) data

let get_tx_index (t : t) (txid : Types.hash256) : string option =
  Rocksdb.cf_get t.db t.cfh_tx_index (Cstruct.to_string txid)

let delete_tx_index (t : t) (txid : Types.hash256) =
  Rocksdb.cf_delete t.db t.cfh_tx_index (Cstruct.to_string txid)

(* Chain state metadata. Keys are short ASCII strings:
   "tip_hash", "tip_height", "header_tip_hash", "header_tip_height".
   No prefix byte needed; the CF gives us the namespace. *)
let put_chain_state (t : t) (key : string) (value : string) =
  Rocksdb.cf_put t.db t.cfh_chain_state key value

let get_chain_state (t : t) (key : string) : string option =
  Rocksdb.cf_get t.db t.cfh_chain_state key

(* Block nTx index: stores transaction count per block, keyed by
   "n:" prefix + 32-byte raw block hash.  Written for every connected
   block (including assume-valid IBD) so getblockheader can return
   a correct nTx without needing the full block body. *)
let ntx_key (hash : Types.hash256) : string =
  "n:" ^ Cstruct.to_string hash

let put_block_ntx (t : t) (hash : Types.hash256) (n : int) =
  (* Encode n_tx as 4-byte little-endian int32 *)
  let buf = Bytes.create 4 in
  Bytes.set buf 0 (Char.chr (n land 0xFF));
  Bytes.set buf 1 (Char.chr ((n lsr 8) land 0xFF));
  Bytes.set buf 2 (Char.chr ((n lsr 16) land 0xFF));
  Bytes.set buf 3 (Char.chr ((n lsr 24) land 0xFF));
  Rocksdb.cf_put t.db t.cfh_chain_state (ntx_key hash) (Bytes.to_string buf)

let get_block_ntx (t : t) (hash : Types.hash256) : int option =
  match Rocksdb.cf_get t.db t.cfh_chain_state (ntx_key hash) with
  | None -> None
  | Some s when String.length s >= 4 ->
    let b0 = Char.code s.[0] in
    let b1 = Char.code s.[1] in
    let b2 = Char.code s.[2] in
    let b3 = Char.code s.[3] in
    Some (b0 lor (b1 lsl 8) lor (b2 lsl 16) lor (b3 lsl 24))
  | Some _ -> None

(* Undo data, keyed by 32-byte block hash *)
let put_undo_data (t : t) (hash : Types.hash256) (data : string) =
  Rocksdb.cf_put t.db t.cfh_undo_data (Cstruct.to_string hash) data

let get_undo_data (t : t) (hash : Types.hash256) : string option =
  Rocksdb.cf_get t.db t.cfh_undo_data (Cstruct.to_string hash)

let delete_undo_data (t : t) (hash : Types.hash256) =
  Rocksdb.cf_delete t.db t.cfh_undo_data (Cstruct.to_string hash)

(* Invalidated block hashes. Value is a constant "1"; the key is what
   matters. *)
let put_invalidated (t : t) (hash : Types.hash256) =
  Rocksdb.cf_put t.db t.cfh_invalidated (Cstruct.to_string hash) "1"

let delete_invalidated (t : t) (hash : Types.hash256) =
  Rocksdb.cf_delete t.db t.cfh_invalidated (Cstruct.to_string hash)

let is_invalidated (t : t) (hash : Types.hash256) : bool =
  match Rocksdb.cf_get t.db t.cfh_invalidated (Cstruct.to_string hash) with
  | None -> false
  | Some _ -> true

let iter_invalidated (t : t) (f : Types.hash256 -> unit) =
  Rocksdb.cf_iter t.db t.cfh_invalidated (fun key _value ->
    f (Cstruct.of_string key))

(* Ban list. Keys are address strings, values are 8-byte BE encoded
   floats (Int64.bits_of_float banned_until). The format is identical
   to what LogStorage stored under prefix "B"; only the storage
   backend changes. *)
let put_ban (t : t) (addr : string) (data : string) =
  Rocksdb.cf_put t.db t.cfh_ban_list addr data

let get_ban (t : t) (addr : string) : string option =
  Rocksdb.cf_get t.db t.cfh_ban_list addr

let delete_ban (t : t) (addr : string) =
  Rocksdb.cf_delete t.db t.cfh_ban_list addr

let iter_bans (t : t) (f : string -> string -> unit) =
  Rocksdb.cf_iter t.db t.cfh_ban_list f

(* Flush (sync) — RocksDB writes are durable on each [cf_put] /
   [batch_write] when WAL is on (the default), so this is a no-op
   for parity with LogStorage.sync. Provided so ChainDB.sync can
   keep its existing signature. *)
let flush (_t : t) : unit = ()

(* --- Atomic batches ---------------------------------------------------- *)

(* Multi-CF write batch. Mirrors Bitcoin Core's CCoinsViewDB::BatchWrite
   (txdb.cpp:100+) — every mutation needed to advance the chain by one
   block goes into a single batch and lands together. *)
type batch = {
  raw : Rocksdb.batch;
  parent : t;
}

let batch_create (t : t) : batch =
  { raw = Rocksdb.write_batch_create (); parent = t }

let batch_put_block_header (b : batch) (hash : Types.hash256) (data : string) =
  Rocksdb.write_batch_put_cf b.raw b.parent.cfh_block_header
    (Cstruct.to_string hash) data

let batch_put_block_data (b : batch) (hash : Types.hash256) (data : string) =
  Rocksdb.write_batch_put_cf b.raw b.parent.cfh_block_data
    (Cstruct.to_string hash) data

let batch_delete_block_data (b : batch) (hash : Types.hash256) =
  Rocksdb.write_batch_delete_cf b.raw b.parent.cfh_block_data
    (Cstruct.to_string hash)

let batch_put_tx (b : batch) (txid : Types.hash256) (data : string) =
  Rocksdb.write_batch_put_cf b.raw b.parent.cfh_tx
    (Cstruct.to_string txid) data

let batch_put_utxo (b : batch) (txid : Types.hash256) (vout : int)
    (data : string) =
  Rocksdb.write_batch_put_cf b.raw b.parent.cfh_utxo
    (utxo_key txid vout) data

let batch_delete_utxo (b : batch) (txid : Types.hash256) (vout : int) =
  Rocksdb.write_batch_delete_cf b.raw b.parent.cfh_utxo
    (utxo_key txid vout)

let batch_put_block_height (b : batch) (height : int) (hash : Types.hash256) =
  Rocksdb.write_batch_put_cf b.raw b.parent.cfh_block_height
    (encode_height height) (Cstruct.to_string hash)

let batch_put_tx_index (b : batch) (txid : Types.hash256) (data : string) =
  Rocksdb.write_batch_put_cf b.raw b.parent.cfh_tx_index
    (Cstruct.to_string txid) data

let batch_delete_tx_index (b : batch) (txid : Types.hash256) =
  Rocksdb.write_batch_delete_cf b.raw b.parent.cfh_tx_index
    (Cstruct.to_string txid)

let batch_put_chain_state (b : batch) (key : string) (value : string) =
  Rocksdb.write_batch_put_cf b.raw b.parent.cfh_chain_state key value

let batch_put_undo_data (b : batch) (hash : Types.hash256) (data : string) =
  Rocksdb.write_batch_put_cf b.raw b.parent.cfh_undo_data
    (Cstruct.to_string hash) data

let batch_delete_undo_data (b : batch) (hash : Types.hash256) =
  Rocksdb.write_batch_delete_cf b.raw b.parent.cfh_undo_data
    (Cstruct.to_string hash)

let batch_put_invalidated (b : batch) (hash : Types.hash256) =
  Rocksdb.write_batch_put_cf b.raw b.parent.cfh_invalidated
    (Cstruct.to_string hash) "1"

let batch_delete_invalidated (b : batch) (hash : Types.hash256) =
  Rocksdb.write_batch_delete_cf b.raw b.parent.cfh_invalidated
    (Cstruct.to_string hash)

let batch_write (b : batch) : unit =
  Rocksdb.write_batch_write b.parent.db b.raw;
  Rocksdb.write_batch_destroy b.raw

(* --- Reindex helpers -------------------------------------------------- *)

(* Wipe every key in a single CF using batched [delete] operations.
   Iterates the CF, accumulates keys into a batch, and flushes every
   [batch_size] keys. Returns the number of keys deleted.

   This is intentionally simple — RocksDB's [DeleteRange] would be
   faster but is not exposed by our C stub layer; we'd add it as a
   follow-up if reindex turns out to be a hot path. For -reindex (a
   one-shot operator action) the row-by-row delete is acceptable. *)
let cf_clear (t : t) (cfh : Rocksdb.cf_handle) ?(batch_size = 10_000) () : int =
  let count = ref 0 in
  let pending = ref [] in
  let flush () =
    if !pending <> [] then begin
      let wb = Rocksdb.write_batch_create () in
      List.iter (fun k -> Rocksdb.write_batch_delete_cf wb cfh k) !pending;
      Rocksdb.write_batch_write t.db wb;
      Rocksdb.write_batch_destroy wb;
      pending := []
    end
  in
  Rocksdb.cf_iter t.db cfh (fun key _value ->
    pending := key :: !pending;
    incr count;
    if List.length !pending >= batch_size then flush ());
  flush ();
  !count

(* Wipe the UTXO column family. Used by -reindex. *)
let cf_clear_utxo (t : t) : int =
  cf_clear t t.cfh_utxo ()

(* Wipe the chain_state CF (tip_hash, tip_height, header_tip_hash,
   header_tip_height — only 4 keys). Used by -reindex. *)
let cf_clear_chain_state (t : t) : int =
  cf_clear t t.cfh_chain_state ()

(* Clear ONLY the two chain-tip pointer keys (tip_hash, tip_height),
   leaving header_tip_* intact. Used by -reindex so that the next
   restore_chain_state still sees the header tip and can reload the
   in-memory header chain from cf_block_header — which is what drives
   the post-wipe block replay. Returns the number of keys deleted
   (0, 1, or 2). *)
let cf_clear_chain_tip_only (t : t) : int =
  let count = ref 0 in
  (match Rocksdb.cf_get t.db t.cfh_chain_state "tip_hash" with
   | None -> ()
   | Some _ ->
     Rocksdb.cf_delete t.db t.cfh_chain_state "tip_hash";
     incr count);
  (match Rocksdb.cf_get t.db t.cfh_chain_state "tip_height" with
   | None -> ()
   | Some _ ->
     Rocksdb.cf_delete t.db t.cfh_chain_state "tip_height";
     incr count);
  !count

(* Wipe the undo_data CF. Used by -reindex (undo data must be regenerated
   alongside the new UTXO state; stale undo from a previous run could
   silently mis-rewind a future reorg). *)
let cf_clear_undo_data (t : t) : int =
  cf_clear t t.cfh_undo_data ()
