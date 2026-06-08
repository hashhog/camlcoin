(* Coin-stats index — Bitcoin Core -coinstatsindex parity.

   Maintains, PER BLOCK HEIGHT, a running MuHash3072 commitment over the
   UTXO set together with cumulative counts (txouts), total amount, and
   bogo-size. This lets [gettxoutsetinfo] answer for a HISTORICAL
   [hash_or_height] (not just the chain tip) byte-exactly versus Bitcoin
   Core's coinstatsindex, and lets [getindexinfo] report the index.

   Design — reorg-safe, incremental on the PRIMARY block-connect path
   -----------------------------------------------------------------
   The index is updated on the node's primary block connect+disconnect
   path (IBD [process_downloaded_blocks], post-IBD
   [process_new_block] / [connect_stored_blocks], the [submitblock] /
   mining accept path, and the reorg connect+disconnect halves in
   [reorganize] / [disconnect_to_target] / [invalidate_block]) — exactly
   where txindex / blockfilterindex are maintained, NOT only on the
   submitblock RPC path.

   Per Bitcoin Core [src/index/coinstatsindex.cpp] ([CustomAppend]):

     * Created outputs: for every output of every tx in the block, build
       the coin [(out, block.height, is_coinbase)] and Insert its
       TxOutSer element into the running MuHash — SKIPPING provably-
       unspendable scripts ([CScript::IsUnspendable]: OP_RETURN-prefixed
       or > MAX_SCRIPT_SIZE), which Core never adds to the UTXO set.
       Increment txouts / total_amount / bogo_size accordingly.
     * Spent prevouts: for every non-coinbase input, Remove the spent
       coin's TxOutSer element (using the prevout's ORIGINAL height +
       coinbase flag, read from the undo / spent-coin record). Decrement
       the counters.

   Each height persists a SELF-CONTAINED snapshot of the running state, so:

     * connect(H): take running state of H-1 (or empty for genesis), apply
       the block's delta, write the H snapshot.
     * disconnect(H): drop the H snapshot. The running state for the new
       tip is simply the already-persisted H-1 snapshot — no
       recomputation, which makes reorg trivially correct.

   TxOutSer / MuHash element encoding and the MuHash3072 accumulator are
   REUSED verbatim from [Muhash] (the same code path [gettxoutsetinfo]
   uses at the tip), guaranteeing the historical digest is byte-identical
   to the @tip digest construction.

   Storage layout (file-per-height under [<data_dir>/indexes/coinstats/])::

       <data_dir>/indexes/coinstats/
           VERSION                       # schema version text file
           best_indexed_height           # highest height indexed (or "none")
           snap/<8-digit>.csi            # per-height snapshot record (binary)

   All writes use write-then-rename (atomic on POSIX) so a crash mid-
   connect cannot leave a half-written snapshot.

   References:
     - bitcoin-core/src/index/coinstatsindex.cpp  (CustomAppend / CustomRewind)
     - bitcoin-core/src/kernel/coinstats.cpp       (TxOutSer / ApplyCoinHash /
                                                    GetBogoSize)
     - bitcoin-core/src/script/script.h            (CScript::IsUnspendable)
     - blockbrew internal/storage/coinstatsindex.go,
       nimrod, haskoin (reorgAtomic Phase E),
       rustoshi (write_coinstats_index on the 4 primary connect sites),
       ouroboros src/ouroboros/coinstatsindex.py (committed reorg-safe refs) *)

(* ---------------------------------------------------------------------- *)
(* Running per-height accumulator                                          *)
(* ---------------------------------------------------------------------- *)

(* Per-coin bogo-size (kernel/coinstats.cpp GetBogoSize):
   32 + 4 + 4 + 8 + 2 + scriptPubKey.size(). *)
let bogo_size_of (script : Cstruct.t) : int =
  32 + 4 + 4 + 8 + 2 + Cstruct.length script

(* A mutable running coinstats state for a single height. *)
type running = {
  mutable muhash : Muhash.t;
  mutable txouts : int;
  mutable total_amount : int64;   (* sats *)
  mutable bogo_size : int64;
}

let running_empty () : running = {
  muhash = Muhash.create ();
  txouts = 0;
  total_amount = 0L;
  bogo_size = 0L;
}

let running_copy (r : running) : running = {
  muhash = Muhash.copy r.muhash;
  txouts = r.txouts;
  total_amount = r.total_amount;
  bogo_size = r.bogo_size;
}

(* ---------------------------------------------------------------------- *)
(* Snapshot record (persisted per height)                                 *)
(* ---------------------------------------------------------------------- *)

(* Self-contained per-height snapshot.  [block_hash] is the internal-byte-
   order hash of the block AT this height (gettxoutsetinfo returns it
   reversed/display as [bestblock]).  [muhash] is finalized lazily by the
   reader; we persist the raw MuHash3072 (num||den, 768 bytes) so the
   running state can be resumed across restarts WITHOUT collapsing the
   fraction (collapsing is fine for the digest but resuming wants the
   un-collapsed accumulator; serialize handles both since finalize is on a
   copy). *)
type snapshot = {
  height : int;
  block_hash : Types.hash256;
  muhash_serialized : bytes;  (* 768 bytes: num (384 LE) || den (384 LE) *)
  txouts : int;
  total_amount : int64;
  bogo_size : int64;
}

(* ---------------------------------------------------------------------- *)
(* Index handle                                                           *)
(* ---------------------------------------------------------------------- *)

type t = {
  root_dir : string;             (* <data_dir>/indexes/coinstats *)
  snap_dir : string;             (* <root>/snap *)
  mutable best_height : int;     (* highest indexed height, -1 if empty *)
  cache : (int, snapshot) Hashtbl.t;  (* small LRU-ish cache; bounded by clear *)
  lock : Mutex.t;
}

let schema_version = 1

let ensure_dir (d : string) : unit =
  if not (Sys.file_exists d) then
    (try Unix.mkdir d 0o755 with Unix.Unix_error (Unix.EEXIST, _, _) -> ())

let snap_file (t : t) (height : int) : string =
  Filename.concat t.snap_dir (Printf.sprintf "%08d.csi" height)

let best_height_file (t : t) : string =
  Filename.concat t.root_dir "best_indexed_height"

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

let persist_best_height (t : t) : unit =
  let v = if t.best_height < 0 then "none" else string_of_int t.best_height in
  (try atomic_write (best_height_file t) (v ^ "\n") with _ -> ())

(* Create or open the index rooted at [<data_dir>/indexes/coinstats]. *)
let create ~(data_dir : string) : t =
  ensure_dir data_dir;
  let indexes_root = Filename.concat data_dir "indexes" in
  ensure_dir indexes_root;
  let root_dir = Filename.concat indexes_root "coinstats" in
  ensure_dir root_dir;
  let snap_dir = Filename.concat root_dir "snap" in
  ensure_dir snap_dir;
  let version_path = Filename.concat root_dir "VERSION" in
  if not (Sys.file_exists version_path) then
    (try atomic_write version_path (string_of_int schema_version ^ "\n")
     with _ -> ());
  {
    root_dir;
    snap_dir;
    best_height = load_best_height root_dir;
    cache = Hashtbl.create 256;
    lock = Mutex.create ();
  }

(* ---------------------------------------------------------------------- *)
(* Snapshot serialization                                                 *)
(* ---------------------------------------------------------------------- *)

(* Wire format (little-endian):
     height           i32
     block_hash       32 bytes (internal byte order)
     muhash           768 bytes (num 384 LE || den 384 LE)
     txouts           i64
     total_amount     i64 (sats)
     bogo_size        i64 *)
let serialize_snapshot (s : snapshot) : string =
  let w = Serialize.writer_create () in
  Serialize.write_int32_le w (Int32.of_int s.height);
  Serialize.write_bytes w s.block_hash;
  Serialize.write_bytes w (Cstruct.of_bytes s.muhash_serialized);
  Serialize.write_int64_le w (Int64.of_int s.txouts);
  Serialize.write_int64_le w s.total_amount;
  Serialize.write_int64_le w s.bogo_size;
  Cstruct.to_string (Serialize.writer_to_cstruct w)

let deserialize_snapshot (data : string) : snapshot =
  let r = Serialize.reader_of_cstruct (Cstruct.of_string data) in
  let height = Int32.to_int (Serialize.read_int32_le r) in
  let block_hash = Serialize.read_bytes r 32 in
  let muhash_serialized = Cstruct.to_bytes (Serialize.read_bytes r 768) in
  let txouts = Int64.to_int (Serialize.read_int64_le r) in
  let total_amount = Serialize.read_int64_le r in
  let bogo_size = Serialize.read_int64_le r in
  { height; block_hash; muhash_serialized; txouts; total_amount; bogo_size }

(* ---------------------------------------------------------------------- *)
(* Snapshot read / write (no lock — callers hold it)                      *)
(* ---------------------------------------------------------------------- *)

let read_snapshot_unlocked (t : t) (height : int) : snapshot option =
  match Hashtbl.find_opt t.cache height with
  | Some s -> Some s
  | None ->
    let path = snap_file t height in
    if not (Sys.file_exists path) then None
    else
      try
        let ic = open_in_bin path in
        let len = in_channel_length ic in
        let data = really_input_string ic len in
        close_in ic;
        let s = deserialize_snapshot data in
        if Hashtbl.length t.cache > 512 then Hashtbl.clear t.cache;
        Hashtbl.replace t.cache height s;
        Some s
      with _ -> None

let write_snapshot_unlocked (t : t) (s : snapshot) : unit =
  let path = snap_file t s.height in
  atomic_write path (serialize_snapshot s);
  if Hashtbl.length t.cache > 512 then Hashtbl.clear t.cache;
  Hashtbl.replace t.cache s.height s

let drop_snapshot_unlocked (t : t) (height : int) : unit =
  let path = snap_file t height in
  (try if Sys.file_exists path then Sys.remove path with _ -> ());
  Hashtbl.remove t.cache height

(* Resume the running accumulator from the snapshot at [height] (the parent
   of the height being connected). For height < 0 (i.e. connecting genesis
   height 0) the running state is empty. *)
let running_at_unlocked (t : t) (height : int) : running option =
  if height < 0 then Some (running_empty ())
  else
    match read_snapshot_unlocked t height with
    | None -> None
    | Some s ->
      let muhash = Muhash.deserialize s.muhash_serialized in
      Some { muhash; txouts = s.txouts;
             total_amount = s.total_amount; bogo_size = s.bogo_size }

(* ---------------------------------------------------------------------- *)
(* Public accessors                                                       *)
(* ---------------------------------------------------------------------- *)

let best_height (t : t) : int = t.best_height

let has_height (t : t) (height : int) : bool =
  Mutex.lock t.lock;
  let r =
    Hashtbl.mem t.cache height || Sys.file_exists (snap_file t height) in
  Mutex.unlock t.lock;
  r

(* Read the finalized per-height stats for [gettxoutsetinfo hash_or_height].
   Returns the muhash digest (display/reversed hex is the caller's job),
   bestblock (internal hash), txouts, total_amount (sats), bogo_size. *)
type at_height_stats = {
  s_height : int;
  s_block_hash : Types.hash256;       (* internal byte order *)
  s_muhash : bytes;                    (* 32-byte SHA256 digest *)
  s_txouts : int;
  s_total_amount : int64;
  s_bogo_size : int64;
}

let get_at_height (t : t) (height : int) : at_height_stats option =
  Mutex.lock t.lock;
  let r =
    match read_snapshot_unlocked t height with
    | None -> None
    | Some s ->
      let acc = Muhash.deserialize s.muhash_serialized in
      let digest = Muhash.finalize acc in
      Some {
        s_height = s.height;
        s_block_hash = s.block_hash;
        s_muhash = digest;
        s_txouts = s.txouts;
        s_total_amount = s.total_amount;
        s_bogo_size = s.bogo_size;
      }
  in
  Mutex.unlock t.lock;
  r

(* ---------------------------------------------------------------------- *)
(* Delta application (connect / disconnect)                               *)
(* ---------------------------------------------------------------------- *)

(* A spent prevout, carrying the ORIGINAL coin metadata needed to rebuild
   its TxOutSer element exactly. *)
type spent_coin = {
  sc_outpoint : Types.outpoint;
  sc_value : int64;
  sc_script_pubkey : Cstruct.t;
  sc_height : int;
  sc_is_coinbase : bool;
}

(* Apply one block's delta to a running accumulator IN PLACE.

   [created]: for every tx in the block, every (vout, tx_out) that is NOT
   provably-unspendable, paired with whether the tx is the coinbase.  The
   caller passes block + height; we compute txids.
   [spent]: the spent prevouts with original metadata (empty for the
   coinbase, which spends nothing).

   Mirrors coinstatsindex.cpp CustomAppend: insert created, remove spent.
   Genesis coinbase (height 0) is excluded by the caller (Core never adds
   the genesis coinbase to the UTXO set). *)
let apply_block_delta (run : running) ~(block : Types.block) ~(height : int)
    ~(spent : spent_coin list) : unit =
  (* Created outputs. *)
  List.iteri (fun tx_idx (tx : Types.transaction) ->
    let is_cb = (tx_idx = 0) in
    (* Genesis coinbase is never added to the UTXO set. *)
    if not (height = 0 && is_cb) then begin
      let txid = Crypto.compute_txid tx in
      List.iteri (fun vout (out : Types.tx_out) ->
        if not (Utxo.is_unspendable_script out.Types.script_pubkey) then begin
          let outpoint = { Types.txid; vout = Int32.of_int vout } in
          let buf =
            Muhash.serialize_txout outpoint
              ~value:out.Types.value
              ~script_pubkey:out.Types.script_pubkey
              ~height ~is_coinbase:is_cb
          in
          Muhash.add run.muhash (Bytes.unsafe_to_string buf);
          run.txouts <- run.txouts + 1;
          run.total_amount <- Int64.add run.total_amount out.Types.value;
          run.bogo_size <-
            Int64.add run.bogo_size
              (Int64.of_int (bogo_size_of out.Types.script_pubkey))
        end
      ) tx.Types.outputs
    end
  ) block.transactions;
  (* Spent prevouts. *)
  List.iter (fun (sc : spent_coin) ->
    if not (Utxo.is_unspendable_script sc.sc_script_pubkey) then begin
      let buf =
        Muhash.serialize_txout sc.sc_outpoint
          ~value:sc.sc_value
          ~script_pubkey:sc.sc_script_pubkey
          ~height:sc.sc_height ~is_coinbase:sc.sc_is_coinbase
      in
      Muhash.remove run.muhash (Bytes.unsafe_to_string buf);
      run.txouts <- run.txouts - 1;
      run.total_amount <- Int64.sub run.total_amount sc.sc_value;
      run.bogo_size <-
        Int64.sub run.bogo_size
          (Int64.of_int (bogo_size_of sc.sc_script_pubkey))
    end
  ) spent

(* Connect a block at [height]: load the H-1 running state, apply the
   block's delta, persist the H snapshot, advance best_height.

   Idempotent: if the snapshot at [height] already exists AND its block
   hash matches, this is a no-op (re-connect of an already-indexed block).
   If a snapshot exists for the height but with a DIFFERENT hash (a reorg
   replacing this height with a different block), it is overwritten by
   recomputing from H-1.

   Returns Ok () on success; Error if the parent snapshot is missing (the
   caller should run a backfill / has wired the index mid-chain). *)
let connect_block (t : t) ~(block : Types.block) ~(height : int)
    ~(spent : spent_coin list) : (unit, string) result =
  Mutex.lock t.lock;
  let result =
    let block_hash = Crypto.compute_block_hash block.header in
    (* Idempotency: same height + same hash already indexed. *)
    let already =
      match read_snapshot_unlocked t height with
      | Some s -> Cstruct.equal s.block_hash block_hash
      | None -> false
    in
    if already then Ok ()
    else
      match running_at_unlocked t (height - 1) with
      | None ->
        Error (Printf.sprintf
          "coinstatsindex: parent snapshot for height %d missing (backfill needed)"
          (height - 1))
      | Some run ->
        apply_block_delta run ~block ~height ~spent;
        let muhash_serialized = Muhash.serialize run.muhash in
        let snap = {
          height; block_hash; muhash_serialized;
          txouts = run.txouts;
          total_amount = run.total_amount;
          bogo_size = run.bogo_size;
        } in
        write_snapshot_unlocked t snap;
        if height > t.best_height then begin
          t.best_height <- height;
          persist_best_height t
        end;
        Ok ()
  in
  Mutex.unlock t.lock;
  result

(* Disconnect the block at [height]: drop the H snapshot. The running state
   for the new tip is the already-persisted H-1 snapshot. best_height is
   lowered to height-1 if it was at height. Idempotent. *)
let disconnect_block (t : t) ~(height : int) : unit =
  Mutex.lock t.lock;
  drop_snapshot_unlocked t height;
  if t.best_height >= height then begin
    t.best_height <- height - 1;
    persist_best_height t
  end;
  Mutex.unlock t.lock

(* Rewind the index down to (and including) [target_height] as the new best:
   drop every snapshot above [target_height]. Used by the reorg disconnect
   half so the connect half re-appends from target_height+1. Idempotent. *)
let rewind_to (t : t) ~(target_height : int) : unit =
  Mutex.lock t.lock;
  let h = ref t.best_height in
  while !h > target_height do
    drop_snapshot_unlocked t !h;
    decr h
  done;
  if t.best_height > target_height then begin
    t.best_height <- target_height;
    persist_best_height t
  end;
  Mutex.unlock t.lock

let close (t : t) : unit =
  Mutex.lock t.lock;
  persist_best_height t;
  Hashtbl.clear t.cache;
  Mutex.unlock t.lock
