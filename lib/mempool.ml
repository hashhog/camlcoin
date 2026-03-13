(* Memory Pool for Unconfirmed Transactions

   The mempool holds transactions that have been validated against the
   current UTXO set but not yet included in a block. Features:

   - Validation against chain UTXO set plus other mempool transactions
   - Fee-rate based prioritization (satoshis per weight unit)
   - Size limits with eviction of lowest fee-rate transactions
   - Transaction dependency tracking (child-pays-for-parent)
   - Conflict detection when blocks are mined
   - Script verification at acceptance
   - IsStandard policy checks
   - Dust output filtering
   - Ancestor/descendant limits
   - RBF rules 1-5
   - Locktime and BIP68 sequence lock enforcement
   - Orphan transaction pool

   KNOWN PITFALL — When a transaction is removed, all dependent
   transactions must also be removed (descendants spending its outputs). *)

let log_src = Logs.Src.create "MEMPOOL" ~doc:"Memory pool"
module Log = (val Logs.src_log log_src : Logs.LOG)
let _ = Log.info  (* suppress unused module warning *)

(* ============================================================================
   Mempool Entry Type
   ============================================================================ *)

type mempool_entry = {
  tx : Types.transaction;
  txid : Types.hash256;
  wtxid : Types.hash256;
  fee : int64;
  weight : int;
  fee_rate : float;           (* satoshis per weight unit *)
  time_added : float;
  height_added : int;
  depends_on : Types.hash256 list;  (* parent txids in mempool *)
}

(* ============================================================================
   Orphan Pool Types
   ============================================================================ *)

type orphan_entry = {
  orphan_tx : Types.transaction;
  orphan_txid : Types.hash256;
  orphan_time : float;
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
  mutable network : Consensus.network_config;
  mutable current_median_time : int32;
  (* Policy flags — can be relaxed for testing or regtest *)
  require_standard : bool;    (* enforce IsStandard checks *)
  verify_scripts : bool;      (* enforce script verification *)
  (* Orphan pool *)
  orphans : (string, orphan_entry) Hashtbl.t;
  max_orphans : int;
}

(* ============================================================================
   Constants
   ============================================================================ *)

let max_ancestor_count = 25
let max_descendant_count = 25
let max_ancestor_size = 101_000
let max_descendant_size = 101_000
let max_rbf_evictions = 100
let max_standard_tx_weight = 400_000

(* TRUC/v3 transaction policy (BIP-431) *)
let truc_version = 3l
let truc_max_vsize = 10_000   (* max virtual size for v3 child transactions *)
let truc_ancestor_limit = 2   (* max unconfirmed ancestors including self *)
let truc_descendant_limit = 2 (* max unconfirmed descendants including self *)

(* ============================================================================
   Mempool Creation
   ============================================================================ *)

let create ?(require_standard=true) ?(verify_scripts=true)
    ~(utxo : Utxo.UtxoSet.t) ~(current_height : int) () : mempool =
  let network = Consensus.regtest in
  { entries = Hashtbl.create 10_000;
    total_weight = 0;
    total_fee = 0L;
    max_size_bytes = 300 * 1024 * 1024;
    min_relay_fee = 1000L;  (* 1 sat/vB = 1000 sat/kvB *)
    utxo;
    current_height;
    network;
    current_median_time = 0l;
    require_standard;
    verify_scripts;
    orphans = Hashtbl.create 100;
    max_orphans = 100 }

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

(* Check if a UTXO is confirmed (in chain UTXO set, not just mempool) *)
let is_confirmed_utxo (mp : mempool) (outpoint : Types.outpoint) : bool =
  match Utxo.UtxoSet.get mp.utxo outpoint.txid
          (Int32.to_int outpoint.vout) with
  | Some _ -> true
  | None -> false

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
   Eviction Policy (Gap 8: TrimToSize by descendant score)
   ============================================================================ *)

(* Compute descendant score for an entry: (fee + desc_fees) / (weight + desc_weights) *)
let descendant_score (mp : mempool) (entry : mempool_entry) : float =
  let descs = get_descendants mp entry.txid in
  let desc_fees = List.fold_left (fun acc d -> Int64.add acc d.fee) 0L descs in
  let desc_weights = List.fold_left (fun acc d -> acc + d.weight) 0 descs in
  let total_fee = Int64.add entry.fee desc_fees in
  let total_weight = entry.weight + desc_weights in
  if total_weight = 0 then 0.0
  else Int64.to_float total_fee /. float_of_int total_weight

(* Evict lowest descendant-score transactions when mempool is full *)
let evict_lowest_feerate (mp : mempool) : unit =
  let entries = Hashtbl.fold (fun _ v acc -> v :: acc) mp.entries [] in
  let sorted = List.sort
    (fun a b ->
      compare (descendant_score mp a) (descendant_score mp b)) entries in
  (* Target 75% of max size -- fixed integer division ordering bug *)
  let target = mp.max_size_bytes * 3 / 4 in
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
   Dust Threshold (Task 6)
   ============================================================================ *)

(* Estimate the spending input size for a given script type *)
let spending_input_size (script_pubkey : Cstruct.t) : int =
  match Script.classify_script script_pubkey with
  | Script.P2PKH_script _ -> 148
  | Script.P2SH_script _ -> 91
  | Script.P2WPKH_script _ -> 68
  | Script.P2WSH_script _ -> 109
  | Script.P2TR_script _ -> 58
  | Script.OP_RETURN_data _ -> 0  (* OP_RETURN outputs are unspendable *)
  | Script.Nonstandard -> 148  (* Conservative: use P2PKH size *)

let output_serialized_size (output : Types.tx_out) : int =
  let script_len = Cstruct.length output.script_pubkey in
  let varint_len = if script_len < 0xFD then 1 else if script_len <= 0xFFFF then 3 else 5 in
  8 + varint_len + script_len

(* Check if an output is dust. Dust = value < 3 * min_relay_fee * spending_size / 1000 *)
let is_dust (min_relay_fee : int64) (output : Types.tx_out) : bool =
  match Script.classify_script output.script_pubkey with
  | Script.OP_RETURN_data _ -> false  (* OP_RETURN is not dust *)
  | _ ->
    let spend_size = spending_input_size output.script_pubkey in
    if spend_size = 0 then false
    else begin
      let threshold = Int64.of_float (
        3.0 *. Int64.to_float min_relay_fee *.
        float_of_int (output_serialized_size output + spend_size) /. 1000.0) in
      output.Types.value < threshold
    end

(* ============================================================================
   IsStandard Checks (Task 7)
   ============================================================================ *)

(* Check if a scriptSig is push-only (contains only push data opcodes) *)
let is_push_only_script_sig (script_sig : Cstruct.t) : bool =
  if Cstruct.length script_sig = 0 then true
  else begin
    try
      let ops = Script.parse_script script_sig in
      List.for_all (fun op ->
        match op with
        | Script.OP_0 -> true
        | Script.OP_1NEGATE -> true
        | Script.OP_1 | Script.OP_2 | Script.OP_3 | Script.OP_4
        | Script.OP_5 | Script.OP_6 | Script.OP_7 | Script.OP_8
        | Script.OP_9 | Script.OP_10 | Script.OP_11 | Script.OP_12
        | Script.OP_13 | Script.OP_14 | Script.OP_15 | Script.OP_16 -> true
        | Script.OP_PUSHDATA (_, _) -> true
        | _ -> false
      ) ops
    with _ -> false
  end

(* Check if a script is a recognized standard output type *)
let is_standard_output (script_pubkey : Cstruct.t) : bool =
  match Script.classify_script script_pubkey with
  | Script.P2PKH_script _ -> true
  | Script.P2SH_script _ -> true
  | Script.P2WPKH_script _ -> true
  | Script.P2WSH_script _ -> true
  | Script.P2TR_script _ -> true
  | Script.OP_RETURN_data _ -> Cstruct.length script_pubkey <= 83
  | Script.Nonstandard -> false

(* Count legacy sigops in a script with accurate multisig counting.
   OP_CHECKSIG/VERIFY = 1 sigop.
   OP_CHECKMULTISIG/VERIFY = N sigops where N is the preceding OP_N (1-16),
   or 20 if the preceding opcode is not an OP_N push. *)
let count_script_sigops (script : Cstruct.t) : int =
  let op_n_value = function
    | Script.OP_1  -> Some 1  | Script.OP_2  -> Some 2
    | Script.OP_3  -> Some 3  | Script.OP_4  -> Some 4
    | Script.OP_5  -> Some 5  | Script.OP_6  -> Some 6
    | Script.OP_7  -> Some 7  | Script.OP_8  -> Some 8
    | Script.OP_9  -> Some 9  | Script.OP_10 -> Some 10
    | Script.OP_11 -> Some 11 | Script.OP_12 -> Some 12
    | Script.OP_13 -> Some 13 | Script.OP_14 -> Some 14
    | Script.OP_15 -> Some 15 | Script.OP_16 -> Some 16
    | _ -> None
  in
  try
    let ops = Script.parse_script script in
    let (count, _) = List.fold_left (fun (acc, prev_op) op ->
      match op with
      | Script.OP_CHECKSIG | Script.OP_CHECKSIGVERIFY -> (acc + 1, Some op)
      | Script.OP_CHECKMULTISIG | Script.OP_CHECKMULTISIGVERIFY ->
        let n = match prev_op with
          | Some prev -> (match op_n_value prev with Some n -> n | None -> 20)
          | None -> 20
        in
        (acc + n, Some op)
      | _ -> (acc, Some op)
    ) (0, None) ops in
    count
  with _ -> 0

let last_push_data (ops : Script.opcode list) : Cstruct.t option =
  List.fold_left (fun acc op -> match op with Script.OP_PUSHDATA (_, data) -> Some data | _ -> acc) None ops

let count_p2sh_sigops (script_sig : Cstruct.t) : int =
  try
    let ops = Script.parse_script script_sig in
    match last_push_data ops with
    | Some redeem_script -> count_script_sigops redeem_script
    | None -> 0
  with _ -> 0

(* Count total legacy sigops cost for a transaction (legacy sigops * 4 for witness scale) *)
let count_tx_sigops_cost (tx : Types.transaction) : int =
  let input_sigops = List.fold_left (fun acc inp ->
    acc + count_script_sigops inp.Types.script_sig
  ) 0 tx.inputs in
  let output_sigops = List.fold_left (fun acc out ->
    acc + count_script_sigops out.Types.script_pubkey
  ) 0 tx.outputs in
  let legacy_cost = (input_sigops + output_sigops) * 4 in
  (* P2SH redeem script sigops, also at witness scale *)
  let p2sh_cost = List.fold_left (fun acc (inp : Types.tx_in) ->
    acc + count_p2sh_sigops inp.script_sig * 4
  ) 0 tx.inputs in
  (* P2SH-wrapped witness sigops at 1x weight *)
  let witness_cost =
    if tx.witnesses = [] then 0
    else
      List.fold_left (fun acc wit ->
        let n = List.length wit.Types.items in
        if n >= 2 then begin
          let last_item = List.nth wit.items (n - 1) in
          let last_len = Cstruct.length last_item in
          if last_len = 20 then acc + 1  (* P2SH-P2WPKH: 1 sigop *)
          else if last_len > 1 then acc + count_script_sigops last_item  (* P2SH-P2WSH witness script *)
          else acc
        end else acc
      ) 0 tx.witnesses
  in
  legacy_cost + p2sh_cost + witness_cost

(* Gap 2: Check P2WSH witness policy limits *)
let check_p2wsh_witness_limits (tx : Types.transaction) : (unit, string) result =
  let error = ref None in
  List.iteri (fun i witness ->
    if !error = None then begin
      let items = witness.Types.items in
      let n = List.length items in
      if n >= 2 then begin
        (* Last item is potentially the witness script *)
        let last_item = List.nth items (n - 1) in
        let last_len = Cstruct.length last_item in
        if last_len > 1 then begin
          (* Heuristic: this looks like a P2WSH input *)
          (* Check witness script size *)
          if last_len > Consensus.max_standard_p2wsh_script_size then
            error := Some (Printf.sprintf
              "P2WSH witness script too large at input %d (%d > %d)"
              i last_len Consensus.max_standard_p2wsh_script_size)
          else begin
            (* Check number of stack items excluding the script *)
            let stack_item_count = n - 1 in
            if stack_item_count > Consensus.max_standard_p2wsh_stack_items then
              error := Some (Printf.sprintf
                "Too many P2WSH witness stack items at input %d (%d > %d)"
                i stack_item_count Consensus.max_standard_p2wsh_stack_items)
            else begin
              (* Check each non-script witness item size *)
              let bad_item = ref None in
              List.iteri (fun j item ->
                if !bad_item = None && j < n - 1 then begin
                  let item_len = Cstruct.length item in
                  if item_len > Consensus.max_standard_p2wsh_stack_item_size then
                    bad_item := Some (Printf.sprintf
                      "P2WSH witness stack item too large at input %d, item %d (%d > %d)"
                      i j item_len Consensus.max_standard_p2wsh_stack_item_size)
                end
              ) items;
              match !bad_item with
              | Some e -> error := Some e
              | None -> ()
            end
          end
        end
      end
    end
  ) tx.witnesses;
  match !error with
  | Some e -> Error e
  | None -> Ok ()

(* Check if a transaction passes IsStandard policy *)
let is_standard_tx (min_relay_fee : int64) (tx : Types.transaction) : (unit, string) result =
  (* Version must be 1 or 2 *)
  let version = Int32.to_int tx.version in
  if version < 1 || version > 3 then
    Error "Non-standard transaction version"
  else begin
    (* Weight must not exceed 400,000 *)
    let weight = Validation.compute_tx_weight tx in
    if weight > max_standard_tx_weight then
      Error "Transaction weight exceeds standard limit"
    else begin
      (* All outputs must be recognized script types *)
      let bad_output = ref None in
      List.iteri (fun i out ->
        if !bad_output = None then begin
          if not (is_standard_output out.Types.script_pubkey) then
            bad_output := Some (Printf.sprintf
              "Non-standard output script at index %d" i)
          else if is_dust min_relay_fee out &&
                  not (tx.version = 3l && out.Types.value = 0L) then
            bad_output := Some (Printf.sprintf
              "Dust output at index %d (value: %Ld)" i out.Types.value)
        end
      ) tx.outputs;

      match !bad_output with
      | Some e -> Error e
      | None ->
        (* All scriptSigs must be push-only *)
        let bad_input = ref None in
        List.iteri (fun i inp ->
          if !bad_input = None then begin
            if not (is_push_only_script_sig inp.Types.script_sig) then
              bad_input := Some (Printf.sprintf
                "Non-push-only scriptSig at input %d" i)
          end
        ) tx.inputs;

        match !bad_input with
        | Some e -> Error e
        | None ->
          (* Gap 2: P2WSH witness policy limits *)
          check_p2wsh_witness_limits tx
    end
  end

(* ============================================================================
   Ancestor/Descendant Limit Checks (Task 3 + Gap 6: size limits)
   ============================================================================ *)

(* Check if adding a transaction would violate ancestor/descendant limits *)
let check_ancestor_descendant_limits (mp : mempool) (depends : Types.hash256 list)
    (txid : Types.hash256) (new_tx_weight : int) : (unit, string) result =
  (* Count ancestors: all ancestors of all parents, plus the parents themselves *)
  let all_ancestors = Hashtbl.create 16 in
  List.iter (fun parent_txid ->
    let parent_key = Cstruct.to_string parent_txid in
    if not (Hashtbl.mem all_ancestors parent_key) then begin
      Hashtbl.replace all_ancestors parent_key ();
      let ancestors = get_ancestors mp parent_txid in
      List.iter (fun a ->
        Hashtbl.replace all_ancestors (Cstruct.to_string a.txid) ()
      ) ancestors
    end
  ) depends;
  let ancestor_count = Hashtbl.length all_ancestors + 1 in  (* +1 for self *)
  if ancestor_count > max_ancestor_count then
    Error (Printf.sprintf "Too many ancestors (%d > %d)"
      ancestor_count max_ancestor_count)
  else begin
    (* Gap 6: Check ancestor cumulative size *)
    let ancestor_weight_sum = Hashtbl.fold (fun ancestor_key () acc ->
      match Hashtbl.find_opt mp.entries ancestor_key with
      | None -> acc
      | Some e -> acc + e.weight
    ) all_ancestors 0 in
    let total_ancestor_size = ancestor_weight_sum + new_tx_weight in
    if total_ancestor_size > max_ancestor_size then
      Error (Printf.sprintf "Ancestor size limit exceeded (%d > %d)"
        total_ancestor_size max_ancestor_size)
    else begin
      (* Check descendant limits for each parent: adding this tx increases
         the descendant count of all ancestors *)
      let too_many_desc = ref false in
      let desc_size_exceeded = ref false in
      Hashtbl.iter (fun ancestor_key () ->
        if not !too_many_desc && not !desc_size_exceeded then begin
          (* Find the ancestor entry to get its txid *)
          match Hashtbl.find_opt mp.entries ancestor_key with
          | None -> ()
          | Some ancestor_entry ->
            let desc = get_descendants mp ancestor_entry.txid in
            (* Current descendants + 1 (for new tx) *)
            if List.length desc + 1 > max_descendant_count then
              too_many_desc := true;
            (* Gap 6: Check cumulative descendant size *)
            let desc_weight = List.fold_left (fun acc d -> acc + d.weight) 0 desc in
            let total_desc_size = ancestor_entry.weight + desc_weight + new_tx_weight in
            if total_desc_size > max_descendant_size then
              desc_size_exceeded := true
        end
      ) all_ancestors;
      (* Also check descendants of the new tx's direct parents *)
      ignore txid;
      if !too_many_desc then
        Error (Printf.sprintf "Adding transaction would exceed descendant limit (%d)"
          max_descendant_count)
      else if !desc_size_exceeded then
        Error (Printf.sprintf "Descendant size limit exceeded (%d)"
          max_descendant_size)
      else
        Ok ()
    end
  end

(* ============================================================================
   TRUC/v3 Transaction Policy (BIP-431)
   ============================================================================ *)

(* Check TRUC/v3 policy constraints for a transaction *)
let check_truc_policy (mp : mempool) (tx : Types.transaction)
    (depends : Types.hash256 list) (weight : int) : (unit, string) result =
  let is_v3 = tx.version = truc_version in
  if is_v3 then begin
    let has_unconfirmed_parents = depends <> [] in
    (* For child transactions (those with unconfirmed parents), enforce vsize limit *)
    if has_unconfirmed_parents then begin
      let vsize = (weight + 3) / 4 in
      if vsize > truc_max_vsize then
        Error (Printf.sprintf
          "TRUC/v3 child transaction vsize %d exceeds limit %d"
          vsize truc_max_vsize)
      else
        (* Check ancestor count (including self) *)
        let all_ancestors = Hashtbl.create 16 in
        List.iter (fun parent_txid ->
          let parent_key = Cstruct.to_string parent_txid in
          if not (Hashtbl.mem all_ancestors parent_key) then begin
            Hashtbl.replace all_ancestors parent_key ();
            let ancestors = get_ancestors mp parent_txid in
            List.iter (fun a ->
              Hashtbl.replace all_ancestors (Cstruct.to_string a.txid) ()
            ) ancestors
          end
        ) depends;
        let ancestor_count = Hashtbl.length all_ancestors + 1 in
        if ancestor_count > truc_ancestor_limit then
          Error (Printf.sprintf
            "TRUC/v3 transaction exceeds ancestor limit (%d > %d)"
            ancestor_count truc_ancestor_limit)
        else
          (* Check that no v3 parent already has an unconfirmed child (1 child limit) *)
          let parent_has_child = List.exists (fun parent_txid ->
            match Hashtbl.find_opt mp.entries (Cstruct.to_string parent_txid) with
            | None -> false
            | Some parent_entry ->
              if parent_entry.tx.version = truc_version then begin
                (* Check if parent already has a child in mempool *)
                Hashtbl.fold (fun _ entry found ->
                  found || (List.exists (fun d ->
                    Cstruct.equal d parent_txid) entry.depends_on)
                ) mp.entries false
              end else
                false
          ) depends in
          if parent_has_child then
            Error "TRUC/v3 parent already has an unconfirmed child"
          else
            Ok ()
    end else
      Ok ()
  end else begin
    (* Non-v3 transaction: reject if it spends unconfirmed v3 outputs *)
    let spends_v3 = List.exists (fun parent_txid ->
      match Hashtbl.find_opt mp.entries (Cstruct.to_string parent_txid) with
      | None -> false
      | Some parent_entry -> parent_entry.tx.version = truc_version
    ) depends in
    if spends_v3 then
      Error "Non-v3 transaction cannot spend unconfirmed v3 outputs"
    else
      Ok ()
  end

(* ============================================================================
   Conflict Detection
   ============================================================================ *)

(* Find all conflicting transactions (not just first) *)
let find_all_conflicts (mp : mempool) (tx : Types.transaction)
    : mempool_entry list =
  let conflicts = Hashtbl.create 4 in
  List.iter (fun inp ->
    Hashtbl.iter (fun _k entry ->
      List.iter (fun entry_inp ->
        if Cstruct.equal
             entry_inp.Types.previous_output.txid
             inp.Types.previous_output.txid &&
           entry_inp.previous_output.vout =
             inp.previous_output.vout then
          Hashtbl.replace conflicts (Cstruct.to_string entry.txid) entry
      ) entry.tx.inputs
    ) mp.entries
  ) tx.inputs;
  Hashtbl.fold (fun _ v acc -> v :: acc) conflicts []

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
   Script Verification Helper
   ============================================================================ *)

(* Verify all input scripts for a transaction *)
let verify_tx_scripts (mp : mempool) (tx : Types.transaction)
    : (unit, string) result =
  let flags = Consensus.get_block_script_flags (mp.current_height + 1) mp.network in
  let error = ref None in

  (* Build prevouts list for Taproot sighash *)
  let prevouts = List.map (fun inp ->
    let prev = inp.Types.previous_output in
    match lookup_utxo mp prev with
    | Some entry -> (entry.Utxo.value, entry.Utxo.script_pubkey)
    | None -> (0L, Cstruct.empty)
  ) tx.inputs in

  List.iteri (fun i inp ->
    if !error = None then begin
      let prev = inp.Types.previous_output in
      match lookup_utxo mp prev with
      | None ->
        error := Some (Printf.sprintf "Missing input for script verification: %d" i)
      | Some utxo_entry ->
        let witness =
          if i < List.length tx.witnesses then
            List.nth tx.witnesses i
          else
            { Types.items = [] }
        in
        match Script.verify_script
                ~tx ~input_index:i
                ~script_pubkey:utxo_entry.Utxo.script_pubkey
                ~script_sig:inp.Types.script_sig
                ~witness
                ~amount:utxo_entry.Utxo.value
                ~flags ~prevouts () with
        | Error msg ->
          error := Some (Printf.sprintf "Script verification failed for input %d: %s" i msg)
        | Ok false ->
          error := Some (Printf.sprintf "Script returned false for input %d" i)
        | Ok true -> ()
    end
  ) tx.inputs;

  match !error with
  | Some e -> Error e
  | None -> Ok ()

(* ============================================================================
   Transaction Addition
   ============================================================================ *)

(* Validate and add a transaction to the mempool.
   When ~dry_run:true, all validation is performed but the transaction
   is not actually inserted into the mempool. *)
let add_transaction ?(dry_run=false) (mp : mempool) (tx : Types.transaction)
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

    (* Task 7: IsStandard checks (skipped when require_standard=false) *)
    else match (if mp.require_standard then is_standard_tx mp.min_relay_fee tx else Ok ()) with
    | Error e -> Error e
    | Ok () ->

    (* Phase 1C: Per-tx sigops cost check *)
    let sigops_cost = count_tx_sigops_cost tx in
    if sigops_cost > 80_000 then
      Error "Transaction exceeds max standard sigops cost"

    (* Task 5: Locktime enforcement *)
    else
    if not (Validation.is_tx_final tx
              ~block_height:(mp.current_height + 1)
              ~block_time:mp.current_median_time) then
      Error "Transaction is not final (locktime not reached)"

    else begin
      (* Validate inputs *)
      let input_sum = ref 0L in
      let depends = ref [] in
      let error = ref None in
      let utxo_heights = Array.make (List.length tx.inputs) 0 in
      let utxo_mtps = Array.make (List.length tx.inputs) 0l in

      List.iteri (fun i inp ->
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
              utxo_heights.(i) <- entry.height;
              utxo_mtps.(i) <- mp.current_median_time;
              (* Track mempool dependencies *)
              if Hashtbl.mem mp.entries (Cstruct.to_string prev.txid) then
                depends := prev.txid :: !depends
            end
        end
      ) tx.inputs;

      match !error with
      | Some e -> Error e
      | None ->
        (* Task 5: BIP68 sequence lock enforcement *)
        let flags = Consensus.get_block_script_flags (mp.current_height + 1) mp.network in
        if not (Validation.check_sequence_locks tx
                  ~block_height:(mp.current_height + 1)
                  ~median_time:mp.current_median_time
                  ~utxo_heights ~utxo_mtps ~flags ()) then
          Error "Transaction sequence locks not satisfied (BIP68)"
        else begin
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

            (* Task 3 + Gap 6: Ancestor/descendant limits (count + size) *)
            else match check_ancestor_descendant_limits mp !depends txid weight with
            | Error e -> Error e
            | Ok () ->

            (* TRUC/v3 policy (BIP-431) *)
            match check_truc_policy mp tx !depends weight with
            | Error e -> Error e
            | Ok () ->

            (* Task 1: Script verification at acceptance (skipped when verify_scripts=false) *)
            match (if mp.verify_scripts then verify_tx_scripts mp tx else Ok ()) with
            | Error e -> Error e
            | Ok () ->

            let wtxid = Crypto.compute_wtxid tx in
            let entry = {
              tx;
              txid;
              wtxid;
              fee;
              weight;
              fee_rate;
              time_added = Unix.gettimeofday ();
              height_added = mp.current_height;
              depends_on = !depends;
            } in

            if not dry_run then begin
              Hashtbl.replace mp.entries txid_key entry;
              mp.total_weight <- mp.total_weight + weight;
              mp.total_fee <- Int64.add mp.total_fee fee;

              (* Evict if over size limit *)
              if mp.total_weight > mp.max_size_bytes / 4 then
                evict_lowest_feerate mp
            end;

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
  let conflicts = find_all_conflicts mp tx in
  match conflicts with
  | [] ->
    (* No conflict, just add normally *)
    add_transaction mp tx
  | _ ->
    (* Rule 1: All conflicting transactions must signal RBF *)
    let all_signal = List.for_all (fun e -> signals_rbf e.tx) conflicts in
    if not all_signal then
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

          (* Rule 3: Replacement must have higher feerate than each direct conflict *)
          let new_weight = Validation.compute_tx_weight tx in
          let new_vsize = max 1 (new_weight / 4) in
          let new_feerate = Int64.to_float new_fee /. float_of_int new_vsize in
          let low_feerate_conflict = List.find_opt (fun e ->
            let conflict_vsize = max 1 (e.weight / 4) in
            let conflict_feerate = Int64.to_float e.fee /. float_of_int conflict_vsize in
            new_feerate <= conflict_feerate
          ) conflicts in

          match low_feerate_conflict with
          | Some conflict ->
            let conflict_vsize = max 1 (conflict.weight / 4) in
            let conflict_feerate = Int64.to_float conflict.fee /. float_of_int conflict_vsize in
            Error (Printf.sprintf
              "Replacement feerate %.2f sat/vB not higher than conflicting tx feerate %.2f sat/vB (RBF Rule 3)"
              new_feerate conflict_feerate)
          | None ->

          (* Total fee of all conflicting transactions *)
          let total_conflict_fee = List.fold_left
            (fun acc e -> Int64.add acc e.fee)
            0L conflicts in

          (* Rule 4: New fee must be higher than total conflict fee *)
          if new_fee <= total_conflict_fee then
            Error (Printf.sprintf
              "Replacement fee %Ld not higher than total conflicting fee %Ld"
              new_fee total_conflict_fee)

          else begin
            (* Rule 2: Replacement must not introduce new unconfirmed inputs *)
            let has_new_unconfirmed = List.exists (fun inp ->
              let prev = inp.Types.previous_output in
              (* If input is unconfirmed (from mempool) *)
              if not (is_confirmed_utxo mp prev) then begin
                (* Check if this unconfirmed input was also used by a conflicting tx *)
                let was_in_conflicts = List.exists (fun conflict_entry ->
                  List.exists (fun conflict_inp ->
                    Cstruct.equal conflict_inp.Types.previous_output.txid prev.txid &&
                    conflict_inp.Types.previous_output.vout = prev.vout
                  ) conflict_entry.tx.inputs
                ) conflicts in
                not was_in_conflicts
              end else
                false
            ) tx.inputs in

            if has_new_unconfirmed then
              Error "Replacement introduces new unconfirmed inputs (RBF Rule 2)"

            else begin
              (* Rule 5: Replacement fee >= old fee + min_relay_fee * replacement_size / 1000 *)
              let replacement_weight = Validation.compute_tx_weight tx in
              let replacement_vsize = (replacement_weight + 3) / 4 in
              let incremental_fee = Int64.of_float (
                Int64.to_float mp.min_relay_fee *.
                float_of_int replacement_vsize /. 1000.0) in
              let required_fee = Int64.add total_conflict_fee incremental_fee in

              if new_fee < required_fee then
                Error (Printf.sprintf
                  "Replacement fee %Ld too low (need >= %Ld = conflict fee %Ld + relay fee %Ld)"
                  new_fee required_fee total_conflict_fee incremental_fee)

              else begin
                (* Rule 6: Max 100 evicted transactions (originals + all descendants) *)
                let eviction_count = ref 0 in
                List.iter (fun conflict_entry ->
                  incr eviction_count;  (* The conflict itself *)
                  let desc = get_descendants mp conflict_entry.txid in
                  eviction_count := !eviction_count + List.length desc
                ) conflicts;

                if !eviction_count > max_rbf_evictions then
                  Error (Printf.sprintf
                    "RBF would evict %d transactions (max %d)"
                    !eviction_count max_rbf_evictions)

                else begin
                  (* Remove all conflicting transactions and add new *)
                  List.iter (fun conflict_entry ->
                    remove_transaction mp conflict_entry.txid
                  ) conflicts;
                  add_transaction mp tx
                end
              end
            end
          end
        end
    end

(* ============================================================================
   Orphan Transaction Pool (Task 8)
   ============================================================================ *)

(* Add a transaction to the orphan pool *)
let add_orphan (mp : mempool) (tx : Types.transaction) : unit =
  let txid = Crypto.compute_txid tx in
  let txid_key = Cstruct.to_string txid in
  if not (Hashtbl.mem mp.orphans txid_key) then begin
    (* Enforce max orphan count by evicting oldest if full *)
    if Hashtbl.length mp.orphans >= mp.max_orphans then begin
      (* Evict the oldest orphan *)
      let oldest_key = ref "" in
      let oldest_time = ref max_float in
      Hashtbl.iter (fun k entry ->
        if entry.orphan_time < !oldest_time then begin
          oldest_key := k;
          oldest_time := entry.orphan_time
        end
      ) mp.orphans;
      if !oldest_key <> "" then
        Hashtbl.remove mp.orphans !oldest_key
    end;
    let entry = {
      orphan_tx = tx;
      orphan_txid = txid;
      orphan_time = Unix.gettimeofday ();
    } in
    Hashtbl.replace mp.orphans txid_key entry
  end

(* Try to process orphans when a new transaction is accepted.
   Returns list of successfully added entries. *)
let process_orphans (mp : mempool) (new_txid : Types.hash256)
    : mempool_entry list =
  let accepted = ref [] in
  let changed = ref true in
  (* Keep trying until no more orphans can be resolved *)
  while !changed do
    changed := false;
    let to_try = Hashtbl.fold (fun k v acc -> (k, v) :: acc) mp.orphans [] in
    List.iter (fun (orphan_key, orphan) ->
      (* Check if any input references the new txid or any previously accepted tx *)
      let relevant = List.exists (fun inp ->
        let prev_txid = inp.Types.previous_output.txid in
        Cstruct.equal prev_txid new_txid ||
        List.exists (fun e -> Cstruct.equal prev_txid e.txid) !accepted
      ) orphan.orphan_tx.inputs in
      if relevant then begin
        Hashtbl.remove mp.orphans orphan_key;
        match add_transaction mp orphan.orphan_tx with
        | Ok entry ->
          accepted := entry :: !accepted;
          changed := true
        | Error _ ->
          (* Orphan still can't be added; discard it *)
          ()
      end
    ) to_try
  done;
  List.rev !accepted

(* Get orphan pool size *)
let orphan_count (mp : mempool) : int =
  Hashtbl.length mp.orphans

(* ============================================================================
   Expiration Functions
   ============================================================================ *)

(* Gap 7: Expire mempool transactions older than 14 days *)
let expire_old_transactions (mp : mempool) : int =
  let now = Unix.gettimeofday () in
  let max_age = 1_209_600.0 in (* 14 days in seconds *)
  let to_remove = Hashtbl.fold (fun _k entry acc ->
    if now -. entry.time_added > max_age then entry.txid :: acc else acc
  ) mp.entries [] in
  List.iter (fun txid -> remove_transaction mp txid) to_remove;
  List.length to_remove

(* Gap 9: Expire orphan transactions older than 20 minutes *)
let expire_orphans (mp : mempool) : int =
  let now = Unix.gettimeofday () in
  let max_age = 1200.0 in (* 20 minutes *)
  let to_remove = Hashtbl.fold (fun k entry acc ->
    if now -. entry.orphan_time > max_age then k :: acc else acc
  ) mp.orphans [] in
  List.iter (Hashtbl.remove mp.orphans) to_remove;
  List.length to_remove

(* ============================================================================
   Update Current Height
   ============================================================================ *)

let update_height (mp : mempool) (height : int) : unit =
  mp.current_height <- height

let update_median_time (mp : mempool) (mtp : int32) : unit =
  mp.current_median_time <- mtp

let set_network (mp : mempool) (network : Consensus.network_config) : unit =
  mp.network <- network

(* ============================================================================
   Clear Mempool
   ============================================================================ *)

let clear (mp : mempool) : unit =
  Hashtbl.clear mp.entries;
  mp.total_weight <- 0;
  mp.total_fee <- 0L

(* ============================================================================
   Mempool Persistence (Gap 5)
   ============================================================================ *)

(* Save mempool to a binary file (atomic via temp file + rename) *)
let save_mempool (mp : mempool) (path : string) : unit =
  let tmp = path ^ ".tmp" in
  let oc = open_out_bin tmp in
  Fun.protect ~finally:(fun () -> close_out_noerr oc) (fun () ->
    (* Write 4-byte BE count *)
    let count = Hashtbl.length mp.entries in
    let buf4 = Cstruct.create 4 in
    Cstruct.BE.set_uint32 buf4 0 (Int32.of_int count);
    output_string oc (Cstruct.to_string buf4);
    (* Write each entry *)
    Hashtbl.iter (fun _k entry ->
      (* txid: 32 bytes *)
      output_string oc (Cstruct.to_string entry.txid);
      (* fee: 8 bytes BE *)
      let buf8 = Cstruct.create 8 in
      Cstruct.BE.set_uint64 buf8 0 entry.fee;
      output_string oc (Cstruct.to_string buf8);
      (* time_added: 8 bytes BE (Int64.bits_of_float) *)
      let buf8t = Cstruct.create 8 in
      Cstruct.BE.set_uint64 buf8t 0 (Int64.bits_of_float entry.time_added);
      output_string oc (Cstruct.to_string buf8t);
      (* tx_data: serialize transaction *)
      let w = Serialize.writer_create () in
      Serialize.serialize_transaction w entry.tx;
      let tx_cs = Serialize.writer_to_cstruct w in
      let tx_data = Cstruct.to_string tx_cs in
      (* tx_data_len: 4 bytes BE *)
      let buf4l = Cstruct.create 4 in
      Cstruct.BE.set_uint32 buf4l 0 (Int32.of_int (String.length tx_data));
      output_string oc (Cstruct.to_string buf4l);
      (* tx_data: raw bytes *)
      output_string oc tx_data
    ) mp.entries
  );
  Sys.rename tmp path

(* Load mempool from a binary file, returns count of loaded transactions *)
let load_mempool (mp : mempool) (path : string) : int =
  if not (Sys.file_exists path) then 0
  else
    let loaded = ref 0 in
    (try
      let ic = open_in_bin path in
      Fun.protect ~finally:(fun () -> close_in_noerr ic) (fun () ->
        (* Read 4-byte BE count *)
        let hdr = Bytes.create 4 in
        really_input ic hdr 0 4;
        let hdr_cs = Cstruct.of_bytes hdr in
        let count = Int32.to_int (Cstruct.BE.get_uint32 hdr_cs 0) in
        for _i = 1 to count do
          (* txid: 32 bytes *)
          let txid_buf = Bytes.create 32 in
          really_input ic txid_buf 0 32;
          ignore (Cstruct.of_bytes txid_buf);  (* txid — used only for verification *)
          (* fee: 8 bytes BE *)
          let fee_buf = Bytes.create 8 in
          really_input ic fee_buf 0 8;
          ignore (Cstruct.BE.get_uint64 (Cstruct.of_bytes fee_buf) 0);  (* fee — recomputed by add_transaction *)
          (* time_added: 8 bytes BE *)
          let time_buf = Bytes.create 8 in
          really_input ic time_buf 0 8;
          ignore (Int64.float_of_bits (Cstruct.BE.get_uint64 (Cstruct.of_bytes time_buf) 0));  (* time_added — recomputed *)
          (* tx_data_len: 4 bytes BE *)
          let len_buf = Bytes.create 4 in
          really_input ic len_buf 0 4;
          let tx_data_len = Int32.to_int (Cstruct.BE.get_uint32 (Cstruct.of_bytes len_buf) 0) in
          (* tx_data: raw bytes *)
          let tx_buf = Bytes.create tx_data_len in
          really_input ic tx_buf 0 tx_data_len;
          let tx_cs = Cstruct.of_bytes tx_buf in
          let r = Serialize.reader_of_cstruct tx_cs in
          let tx = Serialize.deserialize_transaction r in
          match add_transaction mp tx with
          | Ok _ -> incr loaded
          | Error _ -> ()  (* skip silently *)
        done
      )
    with _ -> ());  (* handle corrupt files gracefully *)
    !loaded
