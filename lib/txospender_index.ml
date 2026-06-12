(* Transaction-output spender index — Bitcoin Core -txospenderindex parity.

   For every input of every NON-coinbase transaction in a connected block
   this index records ONE key mapping the SPENT outpoint -> the SPENDING
   transaction: its txid, the hash of the block that confirmed it, and the
   full wire-serialized spending tx (so [return_spending_tx] can be answered
   without a second lookup). It is the data source for the CONFIRMED-spend
   path of the [gettxspendingprevout] RPC.

   This mirrors Bitcoin Core's [TxoSpenderIndex]
   (bitcoin-core/src/index/txospenderindex.{h,cpp}). Core stores the spending
   tx's on-disk LOCATION ([CDiskTxPos]) keyed by a per-DB-salted
   [siphash(outpoint)] and reads the tx back from the block files on lookup (a
   flat-file optimisation that also disambiguates siphash collisions). The
   txospenderindex.cpp header comment notes a from-scratch implementation may
   legitimately store [outpoint -> spending-txid] directly; that is the
   simpler, faithful equivalent and is what this index does. NO salt and NO
   separate undo data are needed: the disconnect path RE-DERIVES the exact
   same keys from the disconnected block's OWN inputs and erases them, exactly
   like Core's [CustomRemove(BuildSpenderPositions(block))].

   Default-off, gated by [--txospenderindex], matching Core's
   [DEFAULT_TXOSPENDERINDEX{false}].

   Design — reorg-safe, incremental on the PRIMARY block-connect path
   -----------------------------------------------------------------
   The index is updated on the node's primary block connect+disconnect path
   (IBD [process_downloaded_blocks], post-IBD [process_new_block] /
   [connect_stored_blocks], the [submitblock] / mining accept path, and the
   reorg connect+disconnect halves in [reorganize] / [disconnect_to_target] /
   [disconnect_to_target_via_utxo] / [invalidate_block]) — exactly where
   txindex / coinstatsindex / blockfilterindex are maintained, NOT only on the
   submitblock RPC path.

   Per Bitcoin Core [CustomAppend] / [CustomRemove]:

     * connect(H): for every non-coinbase input of every tx, write
       [spent_outpoint -> (spending_txid, block_hash, spending_tx_bytes)].
     * disconnect(H): RE-DERIVE those same keys from the block's inputs and
       delete them (no undo data). Persist a [best_indexed_height] rollback.

   ⚠️ REORG-SAFETY: unlike [coinstats_index] (which persists a self-contained
   per-height snapshot, so a reorg disconnect is a trivial [rewind_to] that
   drops snapshots), the spender index keys are derived from each block's OWN
   inputs. So the disconnect side MUST be handed the actual disconnected
   block to re-derive its keys. The hook [disconnect_block] takes the block
   and is wired into BOTH the [invalidateblock] path AND the LIVE reorg path
   (the [reorganize] disconnect loop), disconnect-BEFORE-connect, so a reorg
   that spends the same outpoint by different txs on each branch erases the
   old-branch entry before the new-branch entry is written.

   Storage layout (file-per-spend, sharded by outpoint-key prefix, under
   [<data_dir>/indexes/txospender/])::

       <data_dir>/indexes/txospender/
           VERSION                       # schema version text file
           best_indexed_height           # highest height indexed (or "none")
           best_indexed_hash             # 32-byte hash of that height's block
           spend/<aa>/<keyhex>.s         # per-spend record (binary)

   The per-spend key is [sha256(outpoint.txid || outpoint.vout LE)] so two
   distinct outpoints never share a file and a lookup is a single O(1) open.
   An outpoint can be spent only once on a single chain, so each key file
   holds at most one record. All writes use write-then-rename (atomic on
   POSIX) so a crash mid-connect cannot leave a half-written record. A single
   [Mutex] serialises connect / disconnect.

   References:
     - bitcoin-core/src/index/txospenderindex.{h,cpp}  (CustomAppend / CustomRemove)
     - bitcoin-core/src/rpc/mempool.cpp::gettxspendingprevout
     - camlcoin coinstats_index.ml (this impl's index storage plumbing)
     - blockbrew internal/storage/txospenderindex.go,
       ouroboros src/ouroboros/txospenderindex.py,
       rustoshi crates/storage/.../txospenderindex.rs (committed reorg-safe refs) *)

(* ---------------------------------------------------------------------- *)
(* Per-spend record (persisted per spent outpoint)                        *)
(* ---------------------------------------------------------------------- *)

(* Decoded value of a spender-index entry. *)
type spender = {
  spending_txid : Types.hash256;   (* internal byte order *)
  block_hash : Types.hash256;      (* internal byte order; confirming block *)
  spending_tx_bytes : Cstruct.t;   (* full wire-serialized spending tx (w/ witness) *)
}

(* ---------------------------------------------------------------------- *)
(* Index handle                                                           *)
(* ---------------------------------------------------------------------- *)

type t = {
  root_dir : string;             (* <data_dir>/indexes/txospender *)
  spend_dir : string;            (* <root>/spend *)
  mutable best_height : int;     (* highest indexed height, -1 if empty *)
  mutable best_hash : Types.hash256 option;  (* hash at best_height *)
  cache : (string, spender) Hashtbl.t;  (* keyhex -> record; bounded by clear *)
  lock : Mutex.t;
}

let schema_version = 1

let ensure_dir (d : string) : unit =
  if not (Sys.file_exists d) then
    (try Unix.mkdir d 0o755 with Unix.Unix_error (Unix.EEXIST, _, _) -> ())

(* Stable per-outpoint key: sha256(txid(32) || vout(4 LE)).  Collapses the
   36-byte outpoint to a fixed 32-byte digest safe to shard as a hex filename,
   mirroring how coinstats shards by zero-padded height.  An outpoint is spent
   at most once on a chain, so the key space is collision-free in practice. *)
let outpoint_key (outpoint : Types.outpoint) : string =
  let w = Serialize.writer_create () in
  Serialize.write_bytes w outpoint.Types.txid;
  Serialize.write_int32_le w outpoint.Types.vout;
  let cs = Serialize.writer_to_cstruct w in
  let digest = Crypto.sha256 cs in
  Cstruct.to_string digest

let keyhex (key : string) : string =
  let buf = Buffer.create 64 in
  String.iter (fun c -> Buffer.add_string buf (Printf.sprintf "%02x" (Char.code c))) key;
  Buffer.contents buf

let spend_file (t : t) (key : string) : string =
  let kh = keyhex key in
  let shard = Filename.concat t.spend_dir (String.sub kh 0 2) in
  Filename.concat shard (kh ^ ".s")

let best_height_file (t : t) : string =
  Filename.concat t.root_dir "best_indexed_height"

let best_hash_file (t : t) : string =
  Filename.concat t.root_dir "best_indexed_hash"

let atomic_write (path : string) (data : string) : unit =
  let tmp = path ^ ".tmp" in
  let oc = open_out_bin tmp in
  output_string oc data;
  flush oc;
  (try Unix.fsync (Unix.descr_of_out_channel oc) with _ -> ());
  close_out oc;
  Sys.rename tmp path

let load_best_height (root_dir : string) : int =
  let path = Filename.concat root_dir "best_indexed_height" in
  if not (Sys.file_exists path) then -1
  else
    try
      let ic = open_in path in
      let line = (try input_line ic with End_of_file -> "") in
      close_in ic;
      let s = String.trim line in
      if s = "" || s = "none" then -1 else int_of_string s
    with _ -> -1

let load_best_hash (root_dir : string) : Types.hash256 option =
  let path = Filename.concat root_dir "best_indexed_hash" in
  if not (Sys.file_exists path) then None
  else
    try
      let ic = open_in_bin path in
      let len = in_channel_length ic in
      let data = really_input_string ic len in
      close_in ic;
      if String.length data >= 32 then Some (Cstruct.of_string (String.sub data 0 32))
      else None
    with _ -> None

let persist_best (t : t) : unit =
  let v = if t.best_height < 0 then "none" else string_of_int t.best_height in
  (try atomic_write (best_height_file t) (v ^ "\n") with _ -> ());
  let hb = match t.best_hash with
    | Some h when Cstruct.length h = 32 -> Cstruct.to_string h
    | _ -> String.make 32 '\000'
  in
  (try atomic_write (best_hash_file t) hb with _ -> ())

(* Create or open the index rooted at [<data_dir>/indexes/txospender]. *)
let create ~(data_dir : string) : t =
  ensure_dir data_dir;
  let indexes_root = Filename.concat data_dir "indexes" in
  ensure_dir indexes_root;
  let root_dir = Filename.concat indexes_root "txospender" in
  ensure_dir root_dir;
  let spend_dir = Filename.concat root_dir "spend" in
  ensure_dir spend_dir;
  let version_path = Filename.concat root_dir "VERSION" in
  if not (Sys.file_exists version_path) then
    (try atomic_write version_path (string_of_int schema_version ^ "\n")
     with _ -> ());
  {
    root_dir;
    spend_dir;
    best_height = load_best_height root_dir;
    best_hash = load_best_hash root_dir;
    cache = Hashtbl.create 4096;
    lock = Mutex.create ();
  }

let root_dir (t : t) : string = t.root_dir
let best_height (t : t) : int = t.best_height

(* ---------------------------------------------------------------------- *)
(* Record serialization                                                   *)
(* ---------------------------------------------------------------------- *)

(* Wire format (little-endian):
     spending_txid    32 bytes (internal byte order)
     block_hash       32 bytes (internal byte order)
     tx_len           compact-size
     tx_bytes         tx_len bytes (wire-serialized spending tx, with witness) *)
let serialize_record (rec_ : spender) : string =
  let w = Serialize.writer_create () in
  Serialize.write_bytes w rec_.spending_txid;
  Serialize.write_bytes w rec_.block_hash;
  Serialize.write_compact_size w (Cstruct.length rec_.spending_tx_bytes);
  Serialize.write_bytes w rec_.spending_tx_bytes;
  Cstruct.to_string (Serialize.writer_to_cstruct w)

let deserialize_record (data : string) : spender =
  let r = Serialize.reader_of_cstruct (Cstruct.of_string data) in
  let spending_txid = Serialize.read_bytes r 32 in
  let block_hash = Serialize.read_bytes r 32 in
  let tx_len = Serialize.read_compact_size r in
  let spending_tx_bytes = Serialize.read_bytes r tx_len in
  { spending_txid; block_hash; spending_tx_bytes }

(* ---------------------------------------------------------------------- *)
(* Record read / write (no lock — callers hold it)                        *)
(* ---------------------------------------------------------------------- *)

let write_record_unlocked (t : t) (key : string) (rec_ : spender) : unit =
  let path = spend_file t key in
  ensure_dir (Filename.dirname path);
  atomic_write path (serialize_record rec_);
  if Hashtbl.length t.cache > 8192 then Hashtbl.clear t.cache;
  Hashtbl.replace t.cache key rec_

let erase_record_unlocked (t : t) (key : string) : unit =
  let path = spend_file t key in
  (try if Sys.file_exists path then Sys.remove path with _ -> ());
  Hashtbl.remove t.cache key

let read_record_unlocked (t : t) (key : string) : spender option =
  match Hashtbl.find_opt t.cache key with
  | Some s -> Some s
  | None ->
    let path = spend_file t key in
    if not (Sys.file_exists path) then None
    else
      try
        let ic = open_in_bin path in
        let len = in_channel_length ic in
        let data = really_input_string ic len in
        close_in ic;
        let s = deserialize_record data in
        if Hashtbl.length t.cache > 8192 then Hashtbl.clear t.cache;
        Hashtbl.replace t.cache key s;
        Some s
      with _ -> None

(* ---------------------------------------------------------------------- *)
(* Key derivation (Core BuildSpenderPositions)                            *)
(* ---------------------------------------------------------------------- *)

(* Re-derive every (outpoint-key, spending-tx) pair from a block.  Mirrors
   Core [BuildSpenderPositions]: for each non-coinbase tx, one entry per
   input.  Both the connect (write) and disconnect (erase) paths call this so
   the keys are a pure function of the block's own inputs (no undo data
   required). *)
let spend_entries_for_block (block : Types.block)
    : (string * Types.transaction) list =
  let out = ref [] in
  List.iteri (fun tx_idx (tx : Types.transaction) ->
    if tx_idx > 0 then  (* skip the coinbase (null prevout, spends nothing) *)
      List.iter (fun (inp : Types.tx_in) ->
        out := (outpoint_key inp.Types.previous_output, tx) :: !out
      ) tx.Types.inputs
  ) block.transactions;
  List.rev !out

(* ---------------------------------------------------------------------- *)
(* Primary connect / disconnect hooks                                     *)
(* ---------------------------------------------------------------------- *)

(* Connect [block] at [height]: write [spent_outpoint -> spending tx] for
   every non-coinbase input.  Idempotent: a repeat connect at the same height
   overwrites the same keys with the same values.  The genesis block (height
   0) has only a coinbase, so nothing is written; we just record the best
   pointer (Core's CustomAppend writes nothing for a coinbase-only block). *)
let connect_block (t : t) ~(block : Types.block) ~(height : int)
    ~(block_hash : Types.hash256) : unit =
  Mutex.lock t.lock;
  (if height > 0 then
     List.iter (fun (key, (tx : Types.transaction)) ->
       let txid = Crypto.compute_txid tx in
       let w = Serialize.writer_create () in
       Serialize.serialize_transaction w tx;
       let tx_bytes = Serialize.writer_to_cstruct w in
       write_record_unlocked t key
         { spending_txid = txid; block_hash; spending_tx_bytes = tx_bytes }
     ) (spend_entries_for_block block));
  (if height > t.best_height then begin
     t.best_height <- height;
     t.best_hash <- Some block_hash;
     persist_best t
   end else if height = t.best_height then begin
     t.best_hash <- Some block_hash;
     persist_best t
   end);
  Mutex.unlock t.lock

(* Disconnect [block] at [height] (reorg / invalidate hook).  RE-DERIVES the
   block's spend keys and erases them, mirroring Core's
   [CustomRemove(BuildSpenderPositions(block))].  Rolls [best_height] back to
   [height-1].  No undo data needed — the keys are a pure function of the
   disconnected block's inputs.  Idempotent. *)
let disconnect_block (t : t) ~(block : Types.block) ~(height : int)
    ~(prev_block_hash : Types.hash256 option) : unit =
  Mutex.lock t.lock;
  List.iter (fun (key, _tx) -> erase_record_unlocked t key)
    (spend_entries_for_block block);
  (if t.best_height >= height then begin
     t.best_height <- height - 1;
     t.best_hash <- (if height - 1 < 0 then None else prev_block_hash);
     persist_best t
   end);
  Mutex.unlock t.lock

(* ---------------------------------------------------------------------- *)
(* Query API (used by gettxspendingprevout / getindexinfo)                *)
(* ---------------------------------------------------------------------- *)

(* Return the on-chain tx that spends [outpoint], or None when unspent
   on-chain.  Mirrors Core's [TxoSpenderIndex::FindSpender] (std::nullopt when
   unspent). *)
let find_spender (t : t) (outpoint : Types.outpoint) : spender option =
  Mutex.lock t.lock;
  let r = read_record_unlocked t (outpoint_key outpoint) in
  Mutex.unlock t.lock;
  r

let is_synced (t : t) ~(chain_tip_height : int) : bool =
  chain_tip_height >= 0 && t.best_height >= chain_tip_height

let close (t : t) : unit =
  Mutex.lock t.lock;
  persist_best t;
  Hashtbl.clear t.cache;
  Mutex.unlock t.lock
