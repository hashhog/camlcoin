(* Memory Pool for Unconfirmed Transactions

   The mempool holds transactions that have been validated against the
   current UTXO set but not yet included in a block. Features:

   - Validation against chain UTXO set plus other mempool transactions
   - Fee-rate based prioritization (satoshis per weight unit)
   - Size limits with eviction of lowest fee-rate transactions
   - Transaction dependency tracking (child-pays-for-parent)
   - Conflict detection when blocks are mined

   KNOWN PITFALL — When a transaction is removed, all dependent
   transactions must also be removed (descendants spending its outputs). *)

(* ============================================================================
   Mempool Entry Type
   ============================================================================ *)

type mempool_entry = {
  tx : Types.transaction;
  txid : Types.hash256;
  fee : int64;
  weight : int;
  fee_rate : float;           (* satoshis per weight unit *)
  time_added : float;
  height_added : int;
  depends_on : Types.hash256 list;  (* parent txids in mempool *)
}

(* ============================================================================
   Mempool State
   ============================================================================ *)

type mempool = {
  mutable entries : (string, mempool_entry) Hashtbl.t;
  mutable total_weight : int;
  mutable total_fee : int64;
  max_size_bytes : int;       (* default 300 MB *)
  min_relay_fee : int64;      (* minimum fee rate in sat/kvB *)
  utxo : Utxo.UtxoSet.t;
  mutable current_height : int;
}

(* ============================================================================
   Mempool Creation
   ============================================================================ *)

let create ~(utxo : Utxo.UtxoSet.t) ~(current_height : int) : mempool =
  { entries = Hashtbl.create 10_000;
    total_weight = 0;
    total_fee = 0L;
    max_size_bytes = 300 * 1024 * 1024;
    min_relay_fee = 1000L;  (* 1 sat/vB = 1000 sat/kvB *)
    utxo;
    current_height }

(* ============================================================================
   Basic Queries
   ============================================================================ *)

(* Check if a transaction is already in the mempool *)
let contains (mp : mempool) (txid : Types.hash256) : bool =
  Hashtbl.mem mp.entries (Cstruct.to_string txid)

(* Get a transaction from the mempool *)
let get (mp : mempool) (txid : Types.hash256) : mempool_entry option =
  Hashtbl.find_opt mp.entries (Cstruct.to_string txid)

(* ============================================================================
   UTXO Lookup (Chain + Mempool)
   ============================================================================ *)

(* Look up a UTXO considering both chain state and mempool *)
let lookup_utxo (mp : mempool) (outpoint : Types.outpoint)
    : Utxo.utxo_entry option =
  (* First check chain UTXO set *)
  match Utxo.UtxoSet.get mp.utxo outpoint.txid
          (Int32.to_int outpoint.vout) with
  | Some entry -> Some entry
  | None ->
    (* Check mempool for unconfirmed parent *)
    let txid_key = Cstruct.to_string outpoint.txid in
    match Hashtbl.find_opt mp.entries txid_key with
    | None -> None
    | Some parent_entry ->
      let vout = Int32.to_int outpoint.vout in
      if vout < List.length parent_entry.tx.outputs then begin
        let out = List.nth parent_entry.tx.outputs vout in
        Some {
          Utxo.value = out.Types.value;
          script_pubkey = out.script_pubkey;
          height = mp.current_height;
          is_coinbase = false;
        }
      end else None

(* ============================================================================
   Transaction Removal
   ============================================================================ *)

(* Remove a transaction and its dependents recursively *)
let rec remove_transaction (mp : mempool) (txid : Types.hash256) : unit =
  let txid_key = Cstruct.to_string txid in
  match Hashtbl.find_opt mp.entries txid_key with
  | None -> ()
  | Some entry ->
    Hashtbl.remove mp.entries txid_key;
    mp.total_weight <- mp.total_weight - entry.weight;
    mp.total_fee <- Int64.sub mp.total_fee entry.fee;
    (* Remove dependents (transactions that spend our outputs) *)
    Hashtbl.iter (fun _k dep ->
      if List.exists (fun d -> Cstruct.equal d txid) dep.depends_on then
        remove_transaction mp dep.txid
    ) mp.entries

(* ============================================================================
   Eviction Policy
   ============================================================================ *)

(* Evict lowest fee-rate transactions when mempool is full *)
let evict_lowest_feerate (mp : mempool) : unit =
  let entries = Hashtbl.fold (fun _ v acc -> v :: acc) mp.entries [] in
  let sorted = List.sort
    (fun a b -> compare a.fee_rate b.fee_rate) entries in
  (* Target 75% of max size *)
  let target = mp.max_size_bytes / 4 * 3 / 4 in
  let rec evict = function
    | [] -> ()
    | entry :: rest ->
      if mp.total_weight <= target then ()
      else begin
        remove_transaction mp entry.txid;
        evict rest
      end
  in
  evict sorted

(* ============================================================================
   Transaction Addition
   ============================================================================ *)

(* Validate and add a transaction to the mempool *)
let add_transaction (mp : mempool) (tx : Types.transaction)
    : (mempool_entry, string) result =
  let txid = Crypto.compute_txid tx in
  let txid_key = Cstruct.to_string txid in

  (* Check for duplicate *)
  if Hashtbl.mem mp.entries txid_key then
    Error "Transaction already in mempool"

  (* Basic structure validation *)
  else match Validation.check_transaction tx with
  | Error e -> Error (Validation.tx_error_to_string e)
  | Ok () ->
    (* Must not be a coinbase *)
    let first_input = List.hd tx.inputs in
    if Cstruct.equal first_input.previous_output.txid Types.zero_hash then
      Error "Coinbase in mempool"
    else begin
      (* Validate inputs *)
      let input_sum = ref 0L in
      let depends = ref [] in
      let error = ref None in

      List.iter (fun inp ->
        if !error = None then begin
          let prev = inp.Types.previous_output in
          match lookup_utxo mp prev with
          | None ->
            error := Some (Printf.sprintf
              "Missing input: %s:%ld"
              (Types.hash256_to_hex_display prev.txid)
              prev.vout)
          | Some entry ->
            if entry.is_coinbase &&
               mp.current_height - entry.height < Consensus.coinbase_maturity then
              error := Some "Spending immature coinbase"
            else begin
              input_sum := Int64.add !input_sum entry.value;
              (* Track mempool dependencies *)
              if Hashtbl.mem mp.entries (Cstruct.to_string prev.txid) then
                depends := prev.txid :: !depends
            end
        end
      ) tx.inputs;

      match !error with
      | Some e -> Error e
      | None ->
        let output_sum = List.fold_left
          (fun acc out -> Int64.add acc out.Types.value)
          0L tx.outputs in

        if output_sum > !input_sum then
          Error "Output exceeds input"
        else begin
          let fee = Int64.sub !input_sum output_sum in
          let weight = Validation.compute_tx_weight tx in
          let fee_rate =
            Int64.to_float fee /. float_of_int weight in

          (* Check minimum relay fee *)
          let min_fee = Int64.of_float (
            Int64.to_float mp.min_relay_fee *.
            float_of_int weight /. 4000.0) in

          if fee < min_fee then
            Error "Fee below minimum relay fee"
          else begin
            let entry = {
              tx;
              txid;
              fee;
              weight;
              fee_rate;
              time_added = Unix.gettimeofday ();
              height_added = mp.current_height;
              depends_on = !depends;
            } in

            Hashtbl.replace mp.entries txid_key entry;
            mp.total_weight <- mp.total_weight + weight;
            mp.total_fee <- Int64.add mp.total_fee fee;

            (* Evict if over size limit *)
            if mp.total_weight > mp.max_size_bytes / 4 then
              evict_lowest_feerate mp;

            Ok entry
          end
        end
    end

(* ============================================================================
   Block Processing
   ============================================================================ *)

(* Remove confirmed transactions after a block is mined *)
let remove_for_block (mp : mempool) (block : Types.block) (height : int)
    : unit =
  mp.current_height <- height;

  List.iter (fun tx ->
    let txid = Crypto.compute_txid tx in
    remove_transaction mp txid;

    (* Also remove any conflicts (double-spends) *)
    List.iter (fun inp ->
      Hashtbl.iter (fun _k entry ->
        List.iter (fun entry_inp ->
          if Cstruct.equal
               entry_inp.Types.previous_output.txid
               inp.Types.previous_output.txid &&
             entry_inp.previous_output.vout = inp.previous_output.vout then
            remove_transaction mp entry.txid
        ) entry.tx.inputs
      ) mp.entries
    ) tx.inputs
  ) block.transactions

(* ============================================================================
   Block Template Construction
   ============================================================================ *)

(* Get transactions sorted by fee rate for block template *)
let get_sorted_transactions (mp : mempool) : mempool_entry list =
  let entries = Hashtbl.fold (fun _ v acc -> v :: acc) mp.entries [] in
  List.sort (fun a b -> compare b.fee_rate a.fee_rate) entries

(* Select transactions for a block template respecting dependencies *)
let select_for_block (mp : mempool) ~(max_weight : int)
    : mempool_entry list =
  let sorted = get_sorted_transactions mp in
  let selected = ref [] in
  let selected_txids = Hashtbl.create 100 in
  let current_weight = ref 0 in

  List.iter (fun entry ->
    (* Check if we have room *)
    if !current_weight + entry.weight <= max_weight then begin
      (* Check if all dependencies are satisfied *)
      let deps_ok = List.for_all (fun dep_txid ->
        Hashtbl.mem selected_txids (Cstruct.to_string dep_txid)
      ) entry.depends_on in

      if deps_ok then begin
        selected := entry :: !selected;
        Hashtbl.add selected_txids (Cstruct.to_string entry.txid) ();
        current_weight := !current_weight + entry.weight
      end
    end
  ) sorted;

  List.rev !selected

(* ============================================================================
   Mempool Info
   ============================================================================ *)

(* Get mempool statistics *)
let get_info (mp : mempool) : (int * int * int64) =
  let count = Hashtbl.length mp.entries in
  (count, mp.total_weight, mp.total_fee)

(* Get detailed mempool stats *)
type mempool_stats = {
  tx_count : int;
  total_weight : int;
  total_fee : int64;
  min_fee_rate : float;
  max_fee_rate : float;
  avg_fee_rate : float;
}

let get_stats (mp : mempool) : mempool_stats =
  let entries = Hashtbl.fold (fun _ v acc -> v :: acc) mp.entries [] in
  let count = List.length entries in

  if count = 0 then
    { tx_count = 0;
      total_weight = 0;
      total_fee = 0L;
      min_fee_rate = 0.0;
      max_fee_rate = 0.0;
      avg_fee_rate = 0.0 }
  else begin
    let fee_rates = List.map (fun e -> e.fee_rate) entries in
    let min_fr = List.fold_left min max_float fee_rates in
    let max_fr = List.fold_left max 0.0 fee_rates in
    let sum_fr = List.fold_left (+.) 0.0 fee_rates in

    { tx_count = count;
      total_weight = mp.total_weight;
      total_fee = mp.total_fee;
      min_fee_rate = min_fr;
      max_fee_rate = max_fr;
      avg_fee_rate = sum_fr /. float_of_int count }
  end

(* ============================================================================
   Conflict Detection
   ============================================================================ *)

(* Check if a transaction conflicts with one in the mempool *)
let check_conflict (mp : mempool) (tx : Types.transaction)
    : Types.hash256 option =
  let conflict = ref None in

  List.iter (fun inp ->
    if !conflict = None then
      Hashtbl.iter (fun _k entry ->
        if !conflict = None then
          List.iter (fun entry_inp ->
            if Cstruct.equal
                 entry_inp.Types.previous_output.txid
                 inp.Types.previous_output.txid &&
               entry_inp.previous_output.vout =
                 inp.previous_output.vout then
              conflict := Some entry.txid
          ) entry.tx.inputs
      ) mp.entries
  ) tx.inputs;

  !conflict

(* ============================================================================
   Replace-by-Fee (RBF) Support
   ============================================================================ *)

(* Check if a transaction signals RBF (BIP-125) *)
let signals_rbf (tx : Types.transaction) : bool =
  List.exists (fun inp ->
    (* Sequence number < 0xFFFFFFFE signals RBF *)
    Int32.compare inp.Types.sequence 0xFFFFFFFEl < 0
  ) tx.inputs

(* Attempt to replace an existing transaction with higher fee *)
let replace_by_fee (mp : mempool) (tx : Types.transaction)
    : (mempool_entry, string) result =
  match check_conflict mp tx with
  | None ->
    (* No conflict, just add normally *)
    add_transaction mp tx
  | Some conflicting_txid ->
    match get mp conflicting_txid with
    | None ->
      (* Conflict was removed, add normally *)
      add_transaction mp tx
    | Some existing ->
      (* Check if existing tx signals RBF *)
      if not (signals_rbf existing.tx) then
        Error "Existing transaction does not signal RBF"
      else begin
        (* Calculate new transaction fee *)
        let input_sum = ref 0L in
        let error = ref None in

        List.iter (fun inp ->
          if !error = None then begin
            let prev = inp.Types.previous_output in
            match lookup_utxo mp prev with
            | None -> error := Some "Missing input"
            | Some entry ->
              input_sum := Int64.add !input_sum entry.value
          end
        ) tx.inputs;

        match !error with
        | Some e -> Error e
        | None ->
          let output_sum = List.fold_left
            (fun acc out -> Int64.add acc out.Types.value)
            0L tx.outputs in

          if output_sum > !input_sum then
            Error "Output exceeds input"
          else begin
            let new_fee = Int64.sub !input_sum output_sum in

            (* New fee must be higher than old fee *)
            if new_fee <= existing.fee then
              Error (Printf.sprintf
                "Replacement fee %Ld not higher than existing %Ld"
                new_fee existing.fee)
            else begin
              (* Remove old transaction and add new *)
              remove_transaction mp conflicting_txid;
              add_transaction mp tx
            end
          end
      end

(* ============================================================================
   Ancestor/Descendant Tracking
   ============================================================================ *)

(* Get all ancestors of a transaction (transactions it depends on) *)
let get_ancestors (mp : mempool) (txid : Types.hash256)
    : mempool_entry list =
  let rec collect visited txid =
    let txid_key = Cstruct.to_string txid in
    if Hashtbl.mem visited txid_key then []
    else begin
      Hashtbl.add visited txid_key ();
      match Hashtbl.find_opt mp.entries txid_key with
      | None -> []
      | Some entry ->
        let parent_ancestors = List.concat_map
          (collect visited) entry.depends_on in
        entry :: parent_ancestors
    end
  in
  let visited = Hashtbl.create 16 in
  match Hashtbl.find_opt mp.entries (Cstruct.to_string txid) with
  | None -> []
  | Some entry ->
    List.concat_map (collect visited) entry.depends_on

(* Get all descendants of a transaction (transactions that depend on it) *)
let get_descendants (mp : mempool) (txid : Types.hash256)
    : mempool_entry list =
  let rec collect visited txid =
    let txid_key = Cstruct.to_string txid in
    if Hashtbl.mem visited txid_key then []
    else begin
      Hashtbl.add visited txid_key ();
      (* Find all entries that depend on this txid *)
      let children = Hashtbl.fold (fun _ entry acc ->
        if List.exists (fun d -> Cstruct.equal d txid) entry.depends_on
        then entry :: acc
        else acc
      ) mp.entries [] in

      (* Recursively get descendants of children *)
      let grandchildren = List.concat_map
        (fun e -> collect visited e.txid) children in
      children @ grandchildren
    end
  in
  collect (Hashtbl.create 16) txid

(* ============================================================================
   Update Current Height
   ============================================================================ *)

let update_height (mp : mempool) (height : int) : unit =
  mp.current_height <- height

(* ============================================================================
   Clear Mempool
   ============================================================================ *)

let clear (mp : mempool) : unit =
  Hashtbl.clear mp.entries;
  mp.total_weight <- 0;
  mp.total_fee <- 0L
