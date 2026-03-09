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
   UTXO Set with Write-Through Cache
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

(* Serialize undo data for storage *)
let serialize_undo_data w (undo : undo_data) =
  Serialize.write_int32_le w (Int32.of_int undo.height);
  Serialize.write_compact_size w (List.length undo.spent_outputs);
  List.iter (fun (outpoint, entry) ->
    Serialize.serialize_outpoint w outpoint;
    serialize_utxo_entry w entry
  ) undo.spent_outputs

(* Deserialize undo data from storage *)
let deserialize_undo_data r : undo_data =
  let height = Int32.to_int (Serialize.read_int32_le r) in
  let count = Serialize.read_compact_size r in
  let spent_outputs = List.init count (fun _ ->
    let outpoint = Serialize.deserialize_outpoint r in
    let entry = deserialize_utxo_entry r in
    (outpoint, entry)
  ) in
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
