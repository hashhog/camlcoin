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
|]

type t = {
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
  mutable closed   : bool;
}

let ensure_dir path =
  try Unix.mkdir path 0o755
  with Unix.Unix_error (Unix.EEXIST, _, _) -> ()

(* Open (or create) the chainstate at [path]. Creates all 9 CFs +
   the implicit default CF on first call. Subsequent opens require
   the CFs to exist on disk; missing CFs are created automatically
   thanks to [create_missing_column_families = 1] in the C stub. *)
let open_db ?(write_buffer_mb = 256) ?(block_cache_mb = 2048)
    ?(bloom_bits = 10) (path : string) : t =
  ensure_dir path;
  let db, cfhs =
    Rocksdb.open_cfs path all_cf_names
      write_buffer_mb block_cache_mb bloom_bits
  in
  if Array.length cfhs <> Array.length all_cf_names then
    failwith
      "Cf_chainstate.open_db: cf handle count mismatch (rocksdb stub bug)";
  {
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
    closed = false;
  }

let close (t : t) : unit =
  if not t.closed then begin
    (* Per the C stub contract: destroy CF handles BEFORE closing the DB. *)
    Rocksdb.cf_destroy t.db t.cfh_default;
    Rocksdb.cf_destroy t.db t.cfh_block_header;
    Rocksdb.cf_destroy t.db t.cfh_block_data;
    Rocksdb.cf_destroy t.db t.cfh_tx;
    Rocksdb.cf_destroy t.db t.cfh_utxo;
    Rocksdb.cf_destroy t.db t.cfh_block_height;
    Rocksdb.cf_destroy t.db t.cfh_tx_index;
    Rocksdb.cf_destroy t.db t.cfh_chain_state;
    Rocksdb.cf_destroy t.db t.cfh_undo_data;
    Rocksdb.cf_destroy t.db t.cfh_invalidated;
    Rocksdb.close t.db;
    t.closed <- true
  end

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

(* Chain state metadata. Keys are short ASCII strings:
   "tip_hash", "tip_height", "header_tip_hash", "header_tip_height".
   No prefix byte needed; the CF gives us the namespace. *)
let put_chain_state (t : t) (key : string) (value : string) =
  Rocksdb.cf_put t.db t.cfh_chain_state key value

let get_chain_state (t : t) (key : string) : string option =
  Rocksdb.cf_get t.db t.cfh_chain_state key

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

let batch_put_chain_state (b : batch) (key : string) (value : string) =
  Rocksdb.write_batch_put_cf b.raw b.parent.cfh_chain_state key value

let batch_put_undo_data (b : batch) (hash : Types.hash256) (data : string) =
  Rocksdb.write_batch_put_cf b.raw b.parent.cfh_undo_data
    (Cstruct.to_string hash) data

let batch_put_invalidated (b : batch) (hash : Types.hash256) =
  Rocksdb.write_batch_put_cf b.raw b.parent.cfh_invalidated
    (Cstruct.to_string hash) "1"

let batch_delete_invalidated (b : batch) (hash : Types.hash256) =
  Rocksdb.write_batch_delete_cf b.raw b.parent.cfh_invalidated
    (Cstruct.to_string hash)

let batch_write (b : batch) : unit =
  Rocksdb.write_batch_write b.parent.db b.raw;
  Rocksdb.write_batch_destroy b.raw
