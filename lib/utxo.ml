(* UTXO Set & Chain State Management

   The Unspent Transaction Output (UTXO) set tracks all spendable outputs
   on the blockchain. It supports efficient insertion/deletion during
   block connection/disconnection and maintains undo data for chain
   reorganizations.

   KNOWN PITFALL — Hash byte order: LE internal, reversed display.
   Confusion causes UTXO lookup misses.

   KNOWN PITFALL — header_tip vs chain_tip: Separate DB entries.
   Header sync updates header_tip, block validation updates chain_tip. *)

(* ============================================================================
   UTXO Entry Type
   ============================================================================ *)

type utxo_entry = {
  value : int64;            (* Output value in satoshis *)
  script_pubkey : Cstruct.t; (* Locking script *)
  height : int;             (* Block height where output was created *)
  is_coinbase : bool;       (* Coinbase outputs need 100-block maturity *)
}

(* Serialize a UTXO entry for database storage *)
let serialize_utxo_entry w (e : utxo_entry) =
  Serialize.write_int64_le w e.value;
  Serialize.write_compact_size w (Cstruct.length e.script_pubkey);
  Serialize.write_bytes w e.script_pubkey;
  Serialize.write_int32_le w (Int32.of_int e.height);
  Serialize.write_uint8 w (if e.is_coinbase then 1 else 0)

(* Deserialize a UTXO entry from database storage *)
let deserialize_utxo_entry r : utxo_entry =
  let value = Serialize.read_int64_le r in
  let script_len = Serialize.read_compact_size r in
  let script_pubkey = Serialize.read_bytes r script_len in
  let height = Int32.to_int (Serialize.read_int32_le r) in
  let is_coinbase = Serialize.read_uint8 r <> 0 in
  { value; script_pubkey; height; is_coinbase }

(* ============================================================================
   UTXO Set with Write-Through Cache (Legacy)
   ============================================================================ *)

module UtxoSet = struct
  type t = {
    db : Storage.ChainDB.t;
    cache : (string, utxo_entry) Hashtbl.t;
    mutable cache_hits : int;
    mutable cache_misses : int;
  }

  (* Create a new UTXO set backed by the given database *)
  let create (db : Storage.ChainDB.t) : t =
    { db;
      cache = Hashtbl.create 100_000;
      cache_hits = 0;
      cache_misses = 0 }

  (* Create a cache key from txid and output index *)
  let utxo_key (txid : Types.hash256) (vout : int) : string =
    let w = Serialize.writer_create () in
    Serialize.write_bytes w txid;
    Serialize.write_int32_le w (Int32.of_int vout);
    Cstruct.to_string (Serialize.writer_to_cstruct w)

  (* Get a UTXO entry, checking cache first then database *)
  let get (t : t) (txid : Types.hash256) (vout : int)
      : utxo_entry option =
    let key = utxo_key txid vout in
    match Hashtbl.find_opt t.cache key with
    | Some entry ->
      t.cache_hits <- t.cache_hits + 1;
      Some entry
    | None ->
      t.cache_misses <- t.cache_misses + 1;
      match Storage.ChainDB.get_utxo t.db txid vout with
      | None -> None
      | Some data ->
        let r = Serialize.reader_of_cstruct
          (Cstruct.of_string data) in
        let entry = deserialize_utxo_entry r in
        Hashtbl.replace t.cache key entry;
        Some entry

  (* Add a UTXO entry to both cache and database (write-through) *)
  let add (t : t) (txid : Types.hash256) (vout : int)
      (entry : utxo_entry) : unit =
    let key = utxo_key txid vout in
    Hashtbl.replace t.cache key entry;
    let w = Serialize.writer_create () in
    serialize_utxo_entry w entry;
    Storage.ChainDB.store_utxo t.db txid vout
      (Cstruct.to_string (Serialize.writer_to_cstruct w))

  (* Remove a UTXO entry, returning the removed entry if it existed *)
  let remove (t : t) (txid : Types.hash256) (vout : int)
      : utxo_entry option =
    let key = utxo_key txid vout in
    let existing = Hashtbl.find_opt t.cache key in
    Hashtbl.remove t.cache key;
    Storage.ChainDB.delete_utxo t.db txid vout;
    match existing with
    | Some _ -> existing
    | None ->
      (* Was in DB but not cache - need to deserialize *)
      match Storage.ChainDB.get_utxo t.db txid vout with
      | None -> None
      | Some data ->
        let r = Serialize.reader_of_cstruct
          (Cstruct.of_string data) in
        Some (deserialize_utxo_entry r)

  (* Check if a UTXO exists *)
  let exists (t : t) (txid : Types.hash256) (vout : int) : bool =
    get t txid vout <> None

  (* Get cache statistics *)
  let cache_stats (t : t) : int * int =
    (t.cache_hits, t.cache_misses)

  (* Clear the in-memory cache (DB unchanged) *)
  let clear_cache (t : t) : unit =
    Hashtbl.clear t.cache;
    t.cache_hits <- 0;
    t.cache_misses <- 0

  (* Get cache size *)
  let cache_size (t : t) : int =
    Hashtbl.length t.cache
end

(* ============================================================================
   Undo Data for Block Disconnection
   ============================================================================ *)

type undo_data = {
  height : int;
  spent_outputs : (Types.outpoint * utxo_entry) list;
}

(* Serialize undo data for storage.
   Format: [height][count][spent_outputs...][verification_count][sha256_checksum]
   The trailing 4-byte count and 32-byte SHA256 checksum protect against
   corruption of undo data (disk errors, partial writes). *)
let serialize_undo_data w (undo : undo_data) =
  Serialize.write_int32_le w (Int32.of_int undo.height);
  let num_spent = List.length undo.spent_outputs in
  Serialize.write_compact_size w num_spent;
  List.iter (fun (outpoint, entry) ->
    Serialize.serialize_outpoint w outpoint;
    serialize_utxo_entry w entry
  ) undo.spent_outputs;
  (* Append verification count (4 bytes) *)
  Serialize.write_int32_le w (Int32.of_int num_spent);
  (* Compute SHA256 checksum over everything serialized so far *)
  let data_so_far = Serialize.writer_to_cstruct w in
  let checksum = Crypto.sha256 data_so_far in
  Serialize.write_bytes w checksum

(* Deserialize undo data from storage.
   Backward-compatible: if data ends exactly after spent outputs (legacy format
   with no trailing count+checksum), accept as-is. If extra bytes are present,
   verify the 4-byte count and 32-byte SHA256 checksum. *)
let deserialize_undo_data r : undo_data =
  let height = Int32.to_int (Serialize.read_int32_le r) in
  let count = Serialize.read_compact_size r in
  let spent_outputs = List.init count (fun _ ->
    let outpoint = Serialize.deserialize_outpoint r in
    let entry = deserialize_utxo_entry r in
    (outpoint, entry)
  ) in
  (* Check for trailing checksum data (new format) *)
  let remaining = Cstruct.length r.Serialize.buf - r.Serialize.pos in
  if remaining > 0 then begin
    (* New format: 4-byte verification count + 32-byte SHA256 checksum = 36 bytes *)
    if remaining <> 36 then
      failwith (Printf.sprintf
        "Undo data: unexpected trailing bytes (%d, expected 0 or 36)" remaining);
    (* Position just before the verification count *)
    let data_before_checksum_end = r.Serialize.pos + 4 in
    (* Read and verify the count *)
    let verify_count = Int32.to_int (Serialize.read_int32_le r) in
    if verify_count <> count then
      failwith (Printf.sprintf
        "Undo data checksum verification failed: count mismatch (%d vs %d)"
        count verify_count);
    (* Read the 32-byte checksum *)
    let stored_checksum = Serialize.read_bytes r 32 in
    (* Compute expected checksum over data up to (but not including) the checksum *)
    let data_to_hash = Cstruct.sub r.Serialize.buf 0 data_before_checksum_end in
    let computed_checksum = Crypto.sha256 data_to_hash in
    if not (Cstruct.equal stored_checksum computed_checksum) then
      failwith "Undo data checksum verification failed: SHA256 mismatch"
  end;
  { height; spent_outputs }

(* ============================================================================
   Block Connection (Apply Block to UTXO Set)
   ============================================================================ *)

(* Connect a block to the UTXO set.

   For each transaction:
   - Non-coinbase: consume inputs (remove from UTXO set), record for undo
   - All: create new outputs (add to UTXO set)

   Returns undo data on success, error message on failure.

   IMPORTANT: This modifies the UTXO set. If validation fails partway
   through, the UTXO set will be in an inconsistent state. Callers should
   use batch operations or be prepared to disconnect. *)
let connect_block (utxo : UtxoSet.t) (block : Types.block)
    (height : int)
    : (undo_data, string) result =
  let spent = ref [] in
  let error = ref None in
  let total_fees = ref 0L in

  (* Process each transaction *)
  List.iteri (fun tx_idx tx ->
    if !error = None then begin
      let txid = Crypto.compute_txid tx in
      let is_coinbase = tx_idx = 0 in

      if not is_coinbase then begin
        (* Consume inputs *)
        let input_sum = ref 0L in
        List.iter (fun inp ->
          if !error = None then begin
            let prev = inp.Types.previous_output in
            match UtxoSet.get utxo prev.txid
                    (Int32.to_int prev.vout) with
            | None ->
              error := Some (Printf.sprintf
                "Missing UTXO: %s:%ld"
                (Types.hash256_to_hex_display prev.txid)
                prev.vout)
            | Some entry ->
              (* Check coinbase maturity (100 blocks) *)
              if entry.is_coinbase &&
                 height - entry.height < Consensus.coinbase_maturity then
                error := Some "Immature coinbase spend"
              else begin
                spent := (prev, entry) :: !spent;
                input_sum := Int64.add !input_sum entry.value;
                ignore (UtxoSet.remove utxo prev.txid
                  (Int32.to_int prev.vout))
              end
          end
        ) tx.inputs;

        (* Compute fee *)
        if !error = None then begin
          let output_sum = List.fold_left
            (fun acc out -> Int64.add acc out.Types.value)
            0L tx.outputs in
          if output_sum > !input_sum then
            error := Some "Output exceeds input"
          else
            total_fees :=
              Int64.add !total_fees
                (Int64.sub !input_sum output_sum)
        end
      end;

      (* Create new outputs (for both coinbase and regular tx) *)
      if !error = None then
        List.iteri (fun vout out ->
          UtxoSet.add utxo txid vout {
            value = out.Types.value;
            script_pubkey = out.script_pubkey;
            height;
            is_coinbase;
          }
        ) tx.outputs
    end
  ) block.transactions;

  match !error with
  | Some e -> Error e
  | None ->
    (* Verify coinbase value <= subsidy + total_fees *)
    let subsidy = Consensus.block_subsidy height in
    let max_coinbase = Int64.add subsidy !total_fees in
    let coinbase = List.hd block.transactions in
    let coinbase_out = List.fold_left
      (fun acc out -> Int64.add acc out.Types.value)
      0L coinbase.outputs in
    if coinbase_out > max_coinbase then
      Error (Printf.sprintf
        "Coinbase too large: %Ld > %Ld"
        coinbase_out max_coinbase)
    else
      Ok { height; spent_outputs = !spent }

(* ============================================================================
   Block Disconnection (Undo Block from UTXO Set)
   ============================================================================ *)

(* Disconnect a block from the UTXO set (for chain reorganization).

   This reverses the effects of connect_block:
   - Remove outputs created by the block
   - Restore spent outputs using the undo data

   Transactions are processed in reverse order to properly handle
   intra-block dependencies. *)
let disconnect_block (utxo : UtxoSet.t)
    (block : Types.block) (undo : undo_data) : unit =
  (* Process transactions in reverse order *)
  let txs = List.rev block.transactions in
  List.iter (fun tx ->
    let txid = Crypto.compute_txid tx in
    (* Remove outputs created by this tx *)
    List.iteri (fun vout _out ->
      ignore (UtxoSet.remove utxo txid vout)
    ) tx.outputs
  ) txs;

  (* Restore spent outputs *)
  List.iter (fun (outpoint, entry) ->
    UtxoSet.add utxo outpoint.Types.txid
      (Int32.to_int outpoint.vout) entry
  ) undo.spent_outputs

(* ============================================================================
   Genesis Block Handling
   ============================================================================ *)

(* Initialize the UTXO set with the genesis block.

   NOTE: The Bitcoin genesis block coinbase output is NOT spendable
   (it was not included in the UTXO set by the original code).
   We follow this convention. *)
let initialize_genesis (utxo : UtxoSet.t)
    (network : Consensus.network_config) : unit =
  (* The genesis block has a coinbase but we don't add it to the UTXO set *)
  (* This matches Bitcoin Core's behavior where the genesis coinbase is
     not spendable due to how it was handled in the original code *)
  let _ = utxo in
  let _ = network in
  ()

(* ============================================================================
   Batch Connect/Disconnect for Multiple Blocks
   ============================================================================ *)

(* Connect multiple blocks in sequence, returning all undo data *)
let connect_blocks (utxo : UtxoSet.t) (blocks : (Types.block * int) list)
    : (undo_data list, string) result =
  let rec loop acc = function
    | [] -> Ok (List.rev acc)
    | (block, height) :: rest ->
      match connect_block utxo block height with
      | Error e -> Error e
      | Ok undo -> loop (undo :: acc) rest
  in
  loop [] blocks

(* Disconnect multiple blocks in reverse sequence *)
let disconnect_blocks (utxo : UtxoSet.t)
    (blocks_with_undo : (Types.block * undo_data) list) : unit =
  (* Must process in reverse order (newest to oldest) *)
  List.iter (fun (block, undo) ->
    disconnect_block utxo block undo
  ) (List.rev blocks_with_undo)

(* ============================================================================
   UTXO Statistics
   ============================================================================ *)

type utxo_stats = {
  total_count : int;
  total_value : int64;
  coinbase_count : int;
  cache_hits : int;
  cache_misses : int;
  cache_size : int;
}

(* Compute UTXO set statistics (expensive - iterates entire set) *)
let compute_stats (utxo : UtxoSet.t) : utxo_stats =
  let total_count = ref 0 in
  let total_value = ref 0L in
  let coinbase_count = ref 0 in

  Storage.ChainDB.iter_utxos utxo.db (fun _txid _vout data ->
    let r = Serialize.reader_of_cstruct (Cstruct.of_string data) in
    let entry = deserialize_utxo_entry r in
    incr total_count;
    total_value := Int64.add !total_value entry.value;
    if entry.is_coinbase then incr coinbase_count
  );

  let (cache_hits, cache_misses) = UtxoSet.cache_stats utxo in
  {
    total_count = !total_count;
    total_value = !total_value;
    coinbase_count = !coinbase_count;
    cache_hits;
    cache_misses;
    cache_size = UtxoSet.cache_size utxo;
  }

(* ============================================================================
   Optimized UTXO Set with Write-Back LRU Cache
   ============================================================================

   Enhanced UTXO set implementation that uses an LRU cache for frequently
   accessed UTXOs with write-back semantics. Changes are accumulated in a
   dirty set and only flushed to disk when `flush` is called, using the
   storage layer's atomic batch write for crash safety.

   The default cache size of 500,000 entries covers the typical UTXO working
   set during normal operation.

   During IBD, the most recently created UTXOs are the most likely to be
   spent, so an LRU eviction policy is ideal. The write-back strategy
   dramatically reduces disk I/O by batching writes. *)

module OptimizedUtxoSet = struct
  type dirty_entry = [ `Added of utxo_entry | `Removed ]

  type t = {
    db : Storage.ChainDB.t;
    cache : (string, utxo_entry) Perf.LRU.t;
    dirty : (string, dirty_entry) Hashtbl.t;
    mutable stats : Perf.utxo_cache_stats;
  }

  let create ?(cache_size=500_000) db = {
    db;
    cache = Perf.LRU.create cache_size;
    dirty = Hashtbl.create 10_000;
    stats = Perf.create_utxo_stats ();
  }

  (* Create a cache key from txid and output index *)
  let utxo_key (txid : Types.hash256) (vout : int) : string =
    let w = Serialize.writer_create () in
    Serialize.write_bytes w txid;
    Serialize.write_int32_le w (Int32.of_int vout);
    Cstruct.to_string (Serialize.writer_to_cstruct w)

  (* Get a UTXO entry: check LRU cache, then dirty set, then database *)
  let get (t : t) (txid : Types.hash256) (vout : int)
      : utxo_entry option =
    let key = utxo_key txid vout in
    t.stats.lookups <- t.stats.lookups + 1;
    (* 1. Check LRU cache first *)
    match Perf.LRU.get t.cache key with
    | Some entry ->
      t.stats.cache_hits <- t.stats.cache_hits + 1;
      Some entry
    | None ->
      (* 2. Check dirty set - it may have entries not yet in cache
             (e.g. evicted from LRU but not yet flushed) *)
      match Hashtbl.find_opt t.dirty key with
      | Some `Removed ->
        (* Marked for deletion - does not exist *)
        t.stats.misses <- t.stats.misses + 1;
        None
      | Some (`Added entry) ->
        (* In dirty set but evicted from LRU - re-add to cache *)
        t.stats.cache_hits <- t.stats.cache_hits + 1;
        Perf.LRU.put t.cache key entry;
        Some entry
      | None ->
        (* 3. Fall through to database *)
        (match Storage.ChainDB.get_utxo t.db txid vout with
        | None ->
          t.stats.misses <- t.stats.misses + 1;
          None
        | Some data ->
          t.stats.db_hits <- t.stats.db_hits + 1;
          let r = Serialize.reader_of_cstruct
            (Cstruct.of_string data) in
          let entry = deserialize_utxo_entry r in
          Perf.LRU.put t.cache key entry;
          Some entry)

  (* Add a UTXO entry to LRU cache and mark dirty. Does NOT write to disk. *)
  let add (t : t) (txid : Types.hash256) (vout : int)
      (entry : utxo_entry) : unit =
    let key = utxo_key txid vout in
    Perf.LRU.put t.cache key entry;
    Hashtbl.replace t.dirty key (`Added entry)

  (* Remove a UTXO entry. Marks as Removed in dirty set, removes from LRU.
     Does NOT delete from disk immediately.
     Returns the removed entry if it existed. *)
  let remove (t : t) (txid : Types.hash256) (vout : int)
      : utxo_entry option =
    let key = utxo_key txid vout in
    (* Try to find existing entry: LRU cache, dirty set, then DB *)
    let existing =
      match Perf.LRU.get t.cache key with
      | Some entry -> Some entry
      | None ->
        match Hashtbl.find_opt t.dirty key with
        | Some (`Added entry) -> Some entry
        | Some `Removed -> None
        | None ->
          match Storage.ChainDB.get_utxo t.db txid vout with
          | None -> None
          | Some data ->
            let r = Serialize.reader_of_cstruct
              (Cstruct.of_string data) in
            Some (deserialize_utxo_entry r)
    in
    Perf.LRU.remove t.cache key;
    Hashtbl.replace t.dirty key `Removed;
    existing

  (* Check if a UTXO exists *)
  let exists (t : t) (txid : Types.hash256) (vout : int) : bool =
    let key = utxo_key txid vout in
    if Perf.LRU.mem t.cache key then true
    else
      match Hashtbl.find_opt t.dirty key with
      | Some `Removed -> false
      | Some (`Added _) -> true
      | None -> Option.is_some (Storage.ChainDB.get_utxo t.db txid vout)

  (* Flush all dirty entries to disk in a single atomic batch transaction.
     This writes all Added entries and deletes all Removed entries, then
     clears the dirty set. *)
  let flush (t : t) : unit =
    let count = Hashtbl.length t.dirty in
    if count > 0 then begin
      let batch = Storage.ChainDB.batch_create () in
      Hashtbl.iter (fun key entry ->
        (* Extract txid (32 bytes) and vout (4 bytes LE) from the key *)
        let key_cs = Cstruct.of_string key in
        let txid = Cstruct.sub key_cs 0 32 in
        let vout = Int32.to_int (Cstruct.LE.get_uint32 key_cs 32) in
        match entry with
        | `Added utxo ->
          let w = Serialize.writer_create () in
          serialize_utxo_entry w utxo;
          Storage.ChainDB.batch_store_utxo batch txid vout
            (Cstruct.to_string (Serialize.writer_to_cstruct w))
        | `Removed ->
          Storage.ChainDB.batch_delete_utxo batch txid vout
      ) t.dirty;
      Storage.ChainDB.batch_write t.db batch;
      Hashtbl.clear t.dirty;
      Logs.debug (fun m -> m "Flushed %d dirty UTXO entries to disk" count)
    end

  (* Get the number of pending dirty entries *)
  let dirty_count (t : t) : int =
    Hashtbl.length t.dirty

  (* Get cache hit rate *)
  let hit_rate t =
    Perf.utxo_hit_rate t.stats

  (* Get cache statistics *)
  let get_stats t = t.stats

  (* Get cache size *)
  let cache_size t = Perf.LRU.size t.cache

  (* Clear the in-memory cache and dirty set.
     WARNING: Unflushed dirty entries will be lost! Call flush first. *)
  let clear_cache t =
    Perf.LRU.clear t.cache;
    Hashtbl.clear t.dirty;
    t.stats <- Perf.create_utxo_stats ()
end

(* ============================================================================
   Batch Block Connection for IBD
   ============================================================================

   Process multiple blocks in sequence with reduced overhead.
   Returns the number of blocks successfully connected or an error. *)

let connect_block_optimized (utxo : OptimizedUtxoSet.t) (block : Types.block)
    (height : int)
    : (undo_data, string) result =
  let spent = ref [] in
  let error = ref None in
  let total_fees = ref 0L in

  (* Process each transaction *)
  List.iteri (fun tx_idx tx ->
    if !error = None then begin
      let txid = Crypto.compute_txid tx in
      let is_coinbase = tx_idx = 0 in

      if not is_coinbase then begin
        (* Consume inputs *)
        let input_sum = ref 0L in
        List.iter (fun inp ->
          if !error = None then begin
            let prev = inp.Types.previous_output in
            match OptimizedUtxoSet.get utxo prev.txid
                    (Int32.to_int prev.vout) with
            | None ->
              error := Some (Printf.sprintf
                "Missing UTXO: %s:%ld"
                (Types.hash256_to_hex_display prev.txid)
                prev.vout)
            | Some entry ->
              (* Check coinbase maturity (100 blocks) *)
              if entry.is_coinbase &&
                 height - entry.height < Consensus.coinbase_maturity then
                error := Some "Immature coinbase spend"
              else begin
                spent := (prev, entry) :: !spent;
                input_sum := Int64.add !input_sum entry.value;
                ignore (OptimizedUtxoSet.remove utxo prev.txid
                  (Int32.to_int prev.vout))
              end
          end
        ) tx.inputs;

        (* Compute fee *)
        if !error = None then begin
          let output_sum = List.fold_left
            (fun acc out -> Int64.add acc out.Types.value)
            0L tx.outputs in
          if output_sum > !input_sum then
            error := Some "Output exceeds input"
          else
            total_fees :=
              Int64.add !total_fees
                (Int64.sub !input_sum output_sum)
        end
      end;

      (* Create new outputs (for both coinbase and regular tx) *)
      if !error = None then
        List.iteri (fun vout out ->
          OptimizedUtxoSet.add utxo txid vout {
            value = out.Types.value;
            script_pubkey = out.script_pubkey;
            height;
            is_coinbase;
          }
        ) tx.outputs
    end
  ) block.transactions;

  match !error with
  | Some e -> Error e
  | None ->
    (* Verify coinbase value <= subsidy + total_fees *)
    let subsidy = Consensus.block_subsidy height in
    let max_coinbase = Int64.add subsidy !total_fees in
    let coinbase = List.hd block.transactions in
    let coinbase_out = List.fold_left
      (fun acc out -> Int64.add acc out.Types.value)
      0L coinbase.outputs in
    if coinbase_out > max_coinbase then
      Error (Printf.sprintf
        "Coinbase too large: %Ld > %Ld"
        coinbase_out max_coinbase)
    else
      Ok { height; spent_outputs = !spent }

(* Process multiple blocks in batch during IBD *)
let process_blocks_batch (blocks : Types.block list)
    (utxo : OptimizedUtxoSet.t) (start_height : int)
    : (int, string) result =
  let height = ref start_height in
  let error = ref None in
  List.iter (fun block ->
    if !error = None then begin
      match connect_block_optimized utxo block !height with
      | Ok _undo ->
        incr height
      | Error e ->
        error := Some e
    end
  ) blocks;
  match !error with
  | Some e -> Error e
  | None -> Ok (!height - start_height)

(* ============================================================================
   Layered UTXO Cache with Batch Flushing
   ============================================================================

   Bitcoin Core reference: coins.cpp (CCoinsViewCache, CCoinsViewDB)

   This implements a layered UTXO cache that accumulates changes in memory and
   periodically flushes to disk, avoiding per-transaction disk writes. The
   design mirrors Bitcoin Core's CCoinsViewCache with:

   1. A coin type containing txout, height, and is_coinbase
   2. Cache entry states: Fresh (new), Dirty (modified), Erased (spent)
   3. Parent view abstraction for hierarchical caching
   4. Async flush with configurable max_size threshold

   Cache Entry State Semantics (matching Bitcoin Core):
   - Fresh: Entry doesn't exist in parent (or parent has it as spent).
            Fresh coins can be deleted entirely when spent.
   - Dirty: Entry differs from parent cache (must flush to parent).
   - Erased: Coin has been spent. Kept in cache to remember the spend
            for proper flush to parent.

   Valid state transitions:
   - None -> Fresh (add_coin when not in parent)
   - Fresh -> Erased (spend_coin on fresh entry - entry deleted)
   - Dirty -> Erased (spend_coin on dirty entry - kept as Erased)
   - Parent hit -> Dirty (modify coin from parent)

   The flush operation writes Fresh/Dirty entries to parent and removes
   Erased entries, then clears the cache. *)

(** Coin type representing a spendable output.
    Maps to Bitcoin Core's Coin class. *)
type coin = {
  txout : Types.tx_out;   (** The output (value + scriptPubKey) *)
  height : int;           (** Block height where output was created *)
  is_coinbase : bool;     (** Coinbase outputs need 100-block maturity *)
}

(** Cache entry states following Bitcoin Core's CCoinsCacheEntry flags.
    Fresh: new coin not in parent, Dirty: modified from parent, Erased: spent *)
type cache_entry =
  | Fresh of coin       (** Coin not in parent (can delete on spend) *)
  | Dirty of coin       (** Coin modified from parent (must flush) *)
  | Erased              (** Coin spent (must propagate to parent on flush) *)

(** Abstract UTXO view interface.
    Allows stacking cache layers (cache on cache on database). *)
module type UTXO_VIEW = sig
  type t

  (** Get a coin by outpoint. Returns None if not found or spent. *)
  val get_coin : t -> Types.outpoint -> coin option

  (** Check if a coin exists. *)
  val have_coin : t -> Types.outpoint -> bool

  (** Add a coin to the view.
      @param possible_overwrite true if replacing existing coin is allowed *)
  val add_coin : t -> Types.outpoint -> coin -> possible_overwrite:bool -> unit

  (** Spend a coin, returning the spent coin if it existed. *)
  val spend_coin : t -> Types.outpoint -> coin option

  (** Flush changes to underlying storage. Returns entry count flushed. *)
  val flush : t -> int Lwt.t

  (** Get current memory usage estimate in bytes. *)
  val memory_usage : t -> int
end

(** Database-backed UTXO view (the bottom layer).
    Wraps ChainDB with the UTXO_VIEW interface. *)
module DbView : sig
  type t
  val create : Storage.ChainDB.t -> t
  val db : t -> Storage.ChainDB.t
  val serialize_coin : coin -> string
  include UTXO_VIEW with type t := t
end = struct
  type t = {
    db : Storage.ChainDB.t;
  }

  let create db = { db }
  let db t = t.db

  (** Serialize a coin for database storage *)
  let serialize_coin (c : coin) : string =
    let w = Serialize.writer_create () in
    Serialize.write_int64_le w c.txout.value;
    Serialize.write_compact_size w (Cstruct.length c.txout.script_pubkey);
    Serialize.write_bytes w c.txout.script_pubkey;
    Serialize.write_int32_le w (Int32.of_int c.height);
    Serialize.write_uint8 w (if c.is_coinbase then 1 else 0);
    Cstruct.to_string (Serialize.writer_to_cstruct w)

  (** Deserialize a coin from database storage *)
  let deserialize_coin (data : string) : coin =
    let r = Serialize.reader_of_cstruct (Cstruct.of_string data) in
    let value = Serialize.read_int64_le r in
    let script_len = Serialize.read_compact_size r in
    let script_pubkey = Serialize.read_bytes r script_len in
    let height = Int32.to_int (Serialize.read_int32_le r) in
    let is_coinbase = Serialize.read_uint8 r <> 0 in
    { txout = { value; script_pubkey }; height; is_coinbase }

  let get_coin t outpoint =
    match Storage.ChainDB.get_utxo t.db outpoint.Types.txid
            (Int32.to_int outpoint.vout) with
    | None -> None
    | Some data -> Some (deserialize_coin data)

  let have_coin t outpoint =
    Option.is_some (get_coin t outpoint)

  let add_coin t outpoint coin ~possible_overwrite:_ =
    let data = serialize_coin coin in
    Storage.ChainDB.store_utxo t.db outpoint.Types.txid
      (Int32.to_int outpoint.vout) data

  let spend_coin t outpoint =
    let existing = get_coin t outpoint in
    if Option.is_some existing then
      Storage.ChainDB.delete_utxo t.db outpoint.Types.txid
        (Int32.to_int outpoint.vout);
    existing

  let flush _t = Lwt.return 0  (* No-op for DB view *)

  let memory_usage _t = 0  (* DB doesn't contribute to memory pressure *)
end

(** Outpoint hashing for use in Hashtbl *)
let outpoint_to_key (op : Types.outpoint) : string =
  let w = Serialize.writer_create () in
  Serialize.write_bytes w op.txid;
  Serialize.write_int32_le w op.vout;
  Cstruct.to_string (Serialize.writer_to_cstruct w)

(** Default max cache size: 450MB worth of entries.
    Assuming ~100 bytes per entry average, this is ~4.5M entries. *)
let default_max_cache_bytes = 450 * 1024 * 1024

(** Estimate memory usage of a single coin entry *)
let coin_memory_size (c : coin) : int =
  (* Base overhead + txout value (8) + script_pubkey + height (8) + bool (1) *)
  32 + 8 + Cstruct.length c.txout.script_pubkey + 8 + 1

(** Estimate memory usage of a cache entry *)
let entry_memory_size = function
  | Fresh c -> 8 + coin_memory_size c  (* tag + coin *)
  | Dirty c -> 8 + coin_memory_size c
  | Erased -> 8  (* just the tag *)

(** Layered UTXO cache with parent view abstraction.
    Accumulates changes in memory and flushes to parent when:
    - Cache exceeds max_size (default 450MB)
    - flush is explicitly called (e.g., on shutdown)
    - A sync point is reached (e.g., every N blocks) *)
module UtxoCache = struct
  type t = {
    entries : (string, cache_entry) Hashtbl.t;
    parent : DbView.t;
    max_size : int;
    mutable memory_usage : int;
    mutable stats : cache_stats;
  }

  and cache_stats = {
    mutable hits : int;
    mutable misses : int;
    mutable fresh_count : int;
    mutable dirty_count : int;
    mutable erased_count : int;
  }

  let create ?(max_size = default_max_cache_bytes) parent =
    {
      entries = Hashtbl.create 100_000;
      parent;
      max_size;
      memory_usage = 0;
      stats = {
        hits = 0; misses = 0;
        fresh_count = 0; dirty_count = 0; erased_count = 0;
      };
    }

  (** Get a coin from cache, falling back to parent if needed. *)
  let get_coin t outpoint =
    let key = outpoint_to_key outpoint in
    match Hashtbl.find_opt t.entries key with
    | Some Erased ->
      (* Marked as spent in cache *)
      t.stats.hits <- t.stats.hits + 1;
      None
    | Some (Fresh coin) | Some (Dirty coin) ->
      t.stats.hits <- t.stats.hits + 1;
      Some coin
    | None ->
      (* Not in cache, check parent *)
      t.stats.misses <- t.stats.misses + 1;
      match DbView.get_coin t.parent outpoint with
      | None -> None
      | Some coin ->
        (* Cache the result from parent as Dirty (it exists in parent) *)
        let entry = Dirty coin in
        let mem = entry_memory_size entry in
        Hashtbl.replace t.entries key entry;
        t.memory_usage <- t.memory_usage + mem;
        t.stats.dirty_count <- t.stats.dirty_count + 1;
        Some coin

  let have_coin t outpoint =
    Option.is_some (get_coin t outpoint)

  (** Add a coin to the cache.
      Fresh if not in parent, Dirty otherwise. *)
  let add_coin t outpoint coin ~possible_overwrite =
    let key = outpoint_to_key outpoint in
    let entry =
      (* Check if it exists in parent to determine Fresh vs Dirty *)
      match Hashtbl.find_opt t.entries key with
      | Some (Fresh _) ->
        (* Re-adding a fresh entry - keep as Fresh *)
        Fresh coin
      | Some (Dirty _) | Some Erased ->
        (* Modifying a dirty/erased entry - mark as Dirty *)
        Dirty coin
      | None ->
        (* New entry - check parent to determine Fresh vs Dirty *)
        if not (DbView.have_coin t.parent outpoint) then
          Fresh coin
        else
          Dirty coin
    in
    (* Update memory tracking *)
    let old_mem = match Hashtbl.find_opt t.entries key with
      | Some e -> entry_memory_size e
      | None -> 0
    in
    let new_mem = entry_memory_size entry in
    t.memory_usage <- t.memory_usage - old_mem + new_mem;
    (* Update stats *)
    (match Hashtbl.find_opt t.entries key with
     | Some (Fresh _) -> t.stats.fresh_count <- t.stats.fresh_count - 1
     | Some (Dirty _) -> t.stats.dirty_count <- t.stats.dirty_count - 1
     | Some Erased -> t.stats.erased_count <- t.stats.erased_count - 1
     | None -> ());
    (match entry with
     | Fresh _ -> t.stats.fresh_count <- t.stats.fresh_count + 1
     | Dirty _ -> t.stats.dirty_count <- t.stats.dirty_count + 1
     | Erased -> t.stats.erased_count <- t.stats.erased_count + 1);
    Hashtbl.replace t.entries key entry

  (** Spend a coin, returning the spent coin if it existed. *)
  let spend_coin t outpoint =
    let key = outpoint_to_key outpoint in
    match Hashtbl.find_opt t.entries key with
    | Some (Fresh coin) ->
      (* Fresh coin can be deleted entirely - no need to remember *)
      t.memory_usage <- t.memory_usage - entry_memory_size (Fresh coin);
      t.stats.fresh_count <- t.stats.fresh_count - 1;
      Hashtbl.remove t.entries key;
      Some coin
    | Some (Dirty coin) ->
      (* Must keep as Erased to propagate deletion to parent *)
      let old_mem = entry_memory_size (Dirty coin) in
      let new_mem = entry_memory_size Erased in
      t.memory_usage <- t.memory_usage - old_mem + new_mem;
      t.stats.dirty_count <- t.stats.dirty_count - 1;
      t.stats.erased_count <- t.stats.erased_count + 1;
      Hashtbl.replace t.entries key Erased;
      Some coin
    | Some Erased ->
      (* Already spent *)
      None
    | None ->
      (* Not in cache, fetch from parent then mark as erased *)
      match DbView.get_coin t.parent outpoint with
      | None -> None
      | Some coin ->
        (* Mark as Erased (exists in parent, needs deletion on flush) *)
        let mem = entry_memory_size Erased in
        Hashtbl.replace t.entries key Erased;
        t.memory_usage <- t.memory_usage + mem;
        t.stats.erased_count <- t.stats.erased_count + 1;
        Some coin

  (** Flush all changes to parent view.
      Fresh/Dirty entries are written, Erased entries are deleted.
      Returns the number of entries flushed. *)
  let flush t =
    let open Lwt.Syntax in
    let count = Hashtbl.length t.entries in
    if count = 0 then Lwt.return 0
    else begin
      let batch = Storage.ChainDB.batch_create () in
      Hashtbl.iter (fun key entry ->
        (* Extract outpoint from key *)
        let key_cs = Cstruct.of_string key in
        let txid = Cstruct.sub key_cs 0 32 in
        let vout = Int32.to_int (Cstruct.LE.get_uint32 key_cs 32) in
        match entry with
        | Fresh coin | Dirty coin ->
          let data = DbView.serialize_coin coin in
          Storage.ChainDB.batch_store_utxo batch txid vout data
        | Erased ->
          Storage.ChainDB.batch_delete_utxo batch txid vout
      ) t.entries;
      (* Write batch to parent's database *)
      Storage.ChainDB.batch_write (DbView.db t.parent) batch;
      (* Clear the cache *)
      Hashtbl.clear t.entries;
      t.memory_usage <- 0;
      t.stats.fresh_count <- 0;
      t.stats.dirty_count <- 0;
      t.stats.erased_count <- 0;
      let* () = Lwt.pause () in  (* Yield to async scheduler *)
      Logs.debug (fun m -> m "Flushed %d UTXO cache entries to disk" count);
      Lwt.return count
    end

  (** Check if cache needs flushing based on memory usage *)
  let needs_flush t =
    t.memory_usage > t.max_size

  (** Flush if cache exceeds max_size threshold *)
  let maybe_flush t =
    if needs_flush t then flush t
    else Lwt.return 0

  (** Get current memory usage estimate in bytes *)
  let memory_usage t = t.memory_usage

  (** Get cache statistics *)
  let get_stats t = t.stats

  (** Get entry count *)
  let entry_count t = Hashtbl.length t.entries

  (** Clear cache without flushing (use with caution - loses changes!) *)
  let clear t =
    Hashtbl.clear t.entries;
    t.memory_usage <- 0;
    t.stats <- {
      hits = 0; misses = 0;
      fresh_count = 0; dirty_count = 0; erased_count = 0;
    }

  (** Cache hit rate *)
  let hit_rate t =
    let total = t.stats.hits + t.stats.misses in
    if total = 0 then 1.0
    else float_of_int t.stats.hits /. float_of_int total
end

(** Convert a utxo_entry (legacy type) to coin (new type) *)
let coin_of_utxo_entry (e : utxo_entry) : coin =
  { txout = { Types.value = e.value; script_pubkey = e.script_pubkey };
    height = e.height;
    is_coinbase = e.is_coinbase }

(** Convert a coin (new type) to utxo_entry (legacy type) *)
let utxo_entry_of_coin (c : coin) : utxo_entry =
  { value = c.txout.value;
    script_pubkey = c.txout.script_pubkey;
    height = c.height;
    is_coinbase = c.is_coinbase }
