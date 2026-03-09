(* Block and transaction validation *)

(* ============================================================================
   Validation Error Types
   ============================================================================ *)

type tx_validation_error =
  | TxEmptyInputs
  | TxEmptyOutputs
  | TxOversizeWeight of int
  | TxNegativeOutput of int
  | TxOutputOverflow
  | TxDuplicateInputs
  | TxMissingInputs
  | TxInsufficientFee
  | TxScriptFailed of int * string
  | TxNonFinalLocktime
  | TxBadCoinbase
  | TxInvalidWitness

type block_validation_error =
  | BlockEmptyTransactions
  | BlockNoCoinbase
  | BlockBadMerkleRoot
  | BlockBadTimestamp
  | BlockBadDifficulty
  | BlockOverweight of int
  | BlockTooManySigops
  | BlockBadCoinbaseValue of int64 * int64
  | BlockDuplicateTx
  | BlockTxValidationFailed of int * tx_validation_error

(* ============================================================================
   Error formatting
   ============================================================================ *)

let tx_error_to_string = function
  | TxEmptyInputs -> "transaction has no inputs"
  | TxEmptyOutputs -> "transaction has no outputs"
  | TxOversizeWeight w ->
    Printf.sprintf "transaction exceeds max weight (%d > %d)" w Consensus.max_tx_weight
  | TxNegativeOutput i ->
    Printf.sprintf "output %d has negative or excessive value" i
  | TxOutputOverflow -> "total output value overflow"
  | TxDuplicateInputs -> "transaction has duplicate inputs"
  | TxMissingInputs -> "transaction references missing inputs"
  | TxInsufficientFee -> "transaction fee is insufficient"
  | TxScriptFailed (i, msg) ->
    Printf.sprintf "script verification failed for input %d: %s" i msg
  | TxNonFinalLocktime -> "transaction is not final (locktime)"
  | TxBadCoinbase -> "invalid coinbase transaction"
  | TxInvalidWitness -> "invalid witness data"

let block_error_to_string = function
  | BlockEmptyTransactions -> "block has no transactions"
  | BlockNoCoinbase -> "block has no coinbase transaction"
  | BlockBadMerkleRoot -> "merkle root mismatch"
  | BlockBadTimestamp -> "block timestamp is invalid"
  | BlockBadDifficulty -> "block does not meet difficulty target"
  | BlockOverweight w ->
    Printf.sprintf "block exceeds max weight (%d > %d)" w Consensus.max_block_weight
  | BlockTooManySigops -> "block exceeds sigop limit"
  | BlockBadCoinbaseValue (actual, expected) ->
    Printf.sprintf "coinbase value too high (%Ld > %Ld)" actual expected
  | BlockDuplicateTx -> "block contains duplicate transactions"
  | BlockTxValidationFailed (i, e) ->
    Printf.sprintf "transaction %d validation failed: %s" i (tx_error_to_string e)

(* ============================================================================
   Transaction Weight Computation (BIP-141)
   ============================================================================ *)

(* Compute transaction weight per BIP-141:
   weight = (non_witness_bytes * 3) + total_bytes

   IMPORTANT: This is NOT non_witness_bytes * 4. The formula is:
   - base_size * (scale_factor - 1) + total_size
   - = base_size * 3 + total_size
   - = base_size * 3 + base_size + witness_size
   - = base_size * 4 + witness_size (equivalent form)

   This gives witness data a 75% discount. *)
let compute_tx_weight (tx : Types.transaction) : int =
  (* Serialize without witness to get base size *)
  let w_base = Serialize.writer_create () in
  Serialize.serialize_transaction_no_witness w_base tx;
  let base_size = Cstruct.length (Serialize.writer_to_cstruct w_base) in

  (* Serialize with witness to get total size *)
  let w_total = Serialize.writer_create () in
  Serialize.serialize_transaction w_total tx;
  let total_size = Cstruct.length (Serialize.writer_to_cstruct w_total) in

  (* weight = base_size * 3 + total_size *)
  base_size * (Consensus.witness_scale_factor - 1) + total_size

(* Virtual size is weight / 4, rounded up *)
let compute_tx_vsize (tx : Types.transaction) : int =
  (compute_tx_weight tx + 3) / 4

(* ============================================================================
   Basic Transaction Validation
   ============================================================================ *)

(* Check basic transaction structure *)
let check_transaction (tx : Types.transaction) : (unit, tx_validation_error) result =
  (* Must have at least one input *)
  if tx.inputs = [] then
    Error TxEmptyInputs
  (* Must have at least one output *)
  else if tx.outputs = [] then
    Error TxEmptyOutputs
  else begin
    (* Check weight limit *)
    let weight = compute_tx_weight tx in
    if weight > Consensus.max_tx_weight then
      Error (TxOversizeWeight weight)
    else begin
      (* Check output values *)
      let total_out = ref 0L in
      let bad_output = ref None in
      List.iteri (fun i out ->
        if !bad_output = None then begin
          (* Check for negative value *)
          if out.Types.value < 0L then
            bad_output := Some (TxNegativeOutput i)
          (* Check for value exceeding max money *)
          else if out.Types.value > Consensus.max_money then
            bad_output := Some (TxNegativeOutput i)
          else begin
            (* Check for overflow in total *)
            total_out := Int64.add !total_out out.Types.value;
            if !total_out < 0L || !total_out > Consensus.max_money then
              bad_output := Some TxOutputOverflow
          end
        end
      ) tx.outputs;

      match !bad_output with
      | Some e -> Error e
      | None ->
        (* Check for duplicate inputs *)
        let seen = Hashtbl.create (List.length tx.inputs) in
        let dup = ref false in
        List.iter (fun inp ->
          let key = (Cstruct.to_string inp.Types.previous_output.txid,
                     inp.Types.previous_output.vout) in
          if Hashtbl.mem seen key then
            dup := true;
          Hashtbl.replace seen key ()
        ) tx.inputs;

        if !dup then Error TxDuplicateInputs
        else Ok ()
    end
  end

(* Check if a transaction is a coinbase transaction *)
let is_coinbase (tx : Types.transaction) : bool =
  match tx.inputs with
  | [inp] ->
    Cstruct.equal inp.Types.previous_output.txid Types.zero_hash &&
    inp.Types.previous_output.vout = (-1l)
  | _ -> false

(* ============================================================================
   Coinbase Transaction Validation
   ============================================================================ *)

(* Check coinbase transaction structure *)
let check_coinbase (tx : Types.transaction) (height : int)
    : (unit, tx_validation_error) result =
  (* Coinbase must have exactly one input *)
  if List.length tx.inputs <> 1 then
    Error TxBadCoinbase
  else begin
    let inp = List.hd tx.inputs in
    (* Input must reference null outpoint (txid=0, vout=0xFFFFFFFF) *)
    let is_null =
      Cstruct.equal inp.Types.previous_output.txid Types.zero_hash &&
      inp.Types.previous_output.vout = (-1l)  (* -1l = 0xFFFFFFFF as signed *)
    in
    if not is_null then
      Error TxBadCoinbase
    else begin
      (* Script sig length must be between 2 and 100 bytes *)
      let script_len = Cstruct.length inp.Types.script_sig in
      if script_len < 2 || script_len > 100 then
        Error TxBadCoinbase
      else begin
        (* BIP-34: Check block height encoding in coinbase script
           Only enforced at heights where BIP-34 is active *)
        if height >= 0 then begin
          let expected = Consensus.encode_height_in_coinbase height in
          let expected_len = Cstruct.length expected in
          if script_len < expected_len then
            Error TxBadCoinbase
          else begin
            let actual = Cstruct.sub inp.Types.script_sig 0 expected_len in
            if not (Cstruct.equal expected actual) then
              Error TxBadCoinbase
            else
              Ok ()
          end
        end else
          Ok ()
      end
    end
  end

(* ============================================================================
   Signature Operation Counting
   ============================================================================ *)

(* Count legacy sigops in a script (for block sigop limit) *)
let count_sigops (script : Cstruct.t) : int =
  try
    let ops = Script.parse_script script in
    List.fold_left (fun count op ->
      match op with
      | Script.OP_CHECKSIG | Script.OP_CHECKSIGVERIFY ->
        count + 1
      | Script.OP_CHECKMULTISIG | Script.OP_CHECKMULTISIGVERIFY ->
        (* Worst case: 20 pubkeys *)
        count + 20
      | _ -> count
    ) 0 ops
  with _ ->
    (* If parsing fails, return 0 (unparseable scripts have no sigops) *)
    0

(* Count P2SH sigops (called when evaluating P2SH scripts) *)
let count_p2sh_sigops (redeem_script : Cstruct.t) : int =
  try
    let ops = Script.parse_script redeem_script in
    (* For P2SH, we use actual pubkey count for multisig *)
    let rec count_with_context ops last_push_value acc =
      match ops with
      | [] -> acc
      | Script.OP_CHECKSIG :: rest | Script.OP_CHECKSIGVERIFY :: rest ->
        count_with_context rest None (acc + 1)
      | Script.OP_CHECKMULTISIG :: rest | Script.OP_CHECKMULTISIGVERIFY :: rest ->
        (* Use last push value as pubkey count if available *)
        let n = match last_push_value with
          | Some n when n >= 0 && n <= 20 -> n
          | _ -> 20  (* Worst case *)
        in
        count_with_context rest None (acc + n)
      | Script.OP_1 :: rest -> count_with_context rest (Some 1) acc
      | Script.OP_2 :: rest -> count_with_context rest (Some 2) acc
      | Script.OP_3 :: rest -> count_with_context rest (Some 3) acc
      | Script.OP_4 :: rest -> count_with_context rest (Some 4) acc
      | Script.OP_5 :: rest -> count_with_context rest (Some 5) acc
      | Script.OP_6 :: rest -> count_with_context rest (Some 6) acc
      | Script.OP_7 :: rest -> count_with_context rest (Some 7) acc
      | Script.OP_8 :: rest -> count_with_context rest (Some 8) acc
      | Script.OP_9 :: rest -> count_with_context rest (Some 9) acc
      | Script.OP_10 :: rest -> count_with_context rest (Some 10) acc
      | Script.OP_11 :: rest -> count_with_context rest (Some 11) acc
      | Script.OP_12 :: rest -> count_with_context rest (Some 12) acc
      | Script.OP_13 :: rest -> count_with_context rest (Some 13) acc
      | Script.OP_14 :: rest -> count_with_context rest (Some 14) acc
      | Script.OP_15 :: rest -> count_with_context rest (Some 15) acc
      | Script.OP_16 :: rest -> count_with_context rest (Some 16) acc
      | _ :: rest -> count_with_context rest None acc
    in
    count_with_context ops None 0
  with _ -> 0

(* Count witness sigops (for segwit transactions) *)
let count_witness_sigops (witness_script : Cstruct.t) : int =
  (* Same as P2SH counting for witness scripts *)
  count_p2sh_sigops witness_script

(* Count total sigops for a transaction *)
let count_tx_sigops (tx : Types.transaction) : int =
  (* Count sigops in scriptSig of all inputs *)
  let in_sigops = List.fold_left (fun acc inp ->
    acc + count_sigops inp.Types.script_sig
  ) 0 tx.Types.inputs in

  (* Count sigops in scriptPubKey of all outputs *)
  let out_sigops = List.fold_left (fun acc out ->
    acc + count_sigops out.Types.script_pubkey
  ) 0 tx.Types.outputs in

  in_sigops + out_sigops

(* Count sigops for entire block *)
let count_block_sigops (block : Types.block) : int =
  List.fold_left (fun acc tx ->
    acc + count_tx_sigops tx
  ) 0 block.transactions

(* ============================================================================
   Block Validation
   ============================================================================ *)

(* Check for duplicate transaction IDs in a block *)
let check_duplicate_txids (transactions : Types.transaction list)
    : (unit, block_validation_error) result =
  let seen = Hashtbl.create (List.length transactions) in
  let rec check = function
    | [] -> Ok ()
    | tx :: rest ->
      let txid = Crypto.compute_txid tx in
      let key = Cstruct.to_string txid in
      if Hashtbl.mem seen key then
        Error BlockDuplicateTx
      else begin
        Hashtbl.add seen key ();
        check rest
      end
  in
  check transactions

(* Validate a full block *)
let check_block (block : Types.block) (height : int)
    ~(expected_bits : int32) ~(median_time : int32)
    : (unit, block_validation_error) result =
  let txs = block.transactions in

  (* Block must have at least one transaction *)
  if txs = [] then
    Error BlockEmptyTransactions
  else begin
    (* First transaction must be coinbase *)
    let coinbase = List.hd txs in
    if not (is_coinbase coinbase) then
      Error BlockNoCoinbase
    else begin
      (* Validate coinbase structure *)
      match check_coinbase coinbase height with
      | Error e -> Error (BlockTxValidationFailed (0, e))
      | Ok () ->
        (* Check difficulty target *)
        if block.header.bits <> expected_bits then
          Error BlockBadDifficulty
        else begin
          (* Check that block hash meets target *)
          let block_hash = Crypto.compute_block_hash block.header in
          if not (Consensus.hash_meets_target block_hash block.header.bits) then
            Error BlockBadDifficulty
          else begin
            (* Check timestamp is after median time past *)
            if block.header.timestamp <= median_time then
              Error BlockBadTimestamp
            else begin
              (* Verify merkle root *)
              let txids = List.map Crypto.compute_txid txs in
              let computed_merkle = Crypto.merkle_root txids in
              if not (Cstruct.equal computed_merkle block.header.merkle_root) then
                Error BlockBadMerkleRoot
              else begin
                (* Check for duplicate txids *)
                match check_duplicate_txids txs with
                | Error e -> Error e
                | Ok () ->
                  (* Check total block weight *)
                  let total_weight = List.fold_left (fun acc tx ->
                    acc + compute_tx_weight tx
                  ) 0 txs in
                  if total_weight > Consensus.max_block_weight then
                    Error (BlockOverweight total_weight)
                  else begin
                    (* Check sigop limit *)
                    let total_sigops = count_block_sigops block in
                    if total_sigops > Consensus.max_block_sigops_cost / Consensus.witness_scale_factor then
                      Error BlockTooManySigops
                    else begin
                      (* Validate each non-coinbase transaction *)
                      let error = ref None in
                      List.iteri (fun i tx ->
                        if i > 0 && !error = None then
                          match check_transaction tx with
                          | Error e ->
                            error := Some (BlockTxValidationFailed (i, e))
                          | Ok () -> ()
                      ) txs;

                      match !error with
                      | Some e -> Error e
                      | None ->
                        (* Check coinbase value
                           Note: This is a simplified check. Full validation
                           requires knowing the fees from all transactions. *)
                        let subsidy = Consensus.block_subsidy height in
                        let coinbase_value = List.fold_left (fun acc out ->
                          Int64.add acc out.Types.value
                        ) 0L coinbase.outputs in
                        (* Coinbase can claim subsidy + fees
                           Here we just check it doesn't exceed subsidy
                           (fees would be added during full validation) *)
                        if coinbase_value > subsidy then
                          (* This is overly strict - real validation needs fees *)
                          (* For now, allow some headroom for fees *)
                          if coinbase_value > Int64.add subsidy Consensus.max_money then
                            Error (BlockBadCoinbaseValue (coinbase_value, subsidy))
                          else
                            Ok ()
                        else
                          Ok ()
                    end
                  end
              end
            end
          end
        end
    end
  end

(* ============================================================================
   Context-Free Block Header Validation
   ============================================================================ *)

(* Check block header without full chain context *)
let check_block_header (header : Types.block_header) : (unit, string) result =
  (* Check that timestamp is not too far in the future *)
  let max_future_time = Int32.add (Int32.of_float (Unix.time ())) 7200l in  (* 2 hours *)
  if header.timestamp > max_future_time then
    Error "Block timestamp too far in future"
  else begin
    (* Check proof of work *)
    let block_hash = Crypto.compute_block_hash header in
    if not (Consensus.hash_meets_target block_hash header.bits) then
      Error "Block does not meet difficulty target"
    else
      Ok ()
  end

(* ============================================================================
   Transaction Finality Checks
   ============================================================================ *)

(* Check if transaction is final based on locktime and sequences *)
let is_tx_final (tx : Types.transaction) ~(block_height : int) ~(block_time : int32)
    : bool =
  (* Locktime of 0 means the transaction is always final *)
  if tx.locktime = 0l then
    true
  else begin
    let locktime = Int32.to_int tx.locktime in
    (* If all inputs have final sequence (0xFFFFFFFF), tx is final *)
    if List.for_all (fun inp ->
         Int32.equal inp.Types.sequence 0xFFFFFFFFl
       ) tx.inputs then
      true
    else begin
      (* Check if locktime has been reached *)
      if locktime < 500_000_000 then
        (* Locktime is a block height *)
        block_height >= locktime
      else
        (* Locktime is a unix timestamp *)
        Int32.compare block_time (Int32.of_int locktime) >= 0
    end
  end

(* ============================================================================
   Input Validation with UTXO Set
   ============================================================================ *)

(* UTXO entry for validation *)
type utxo = {
  txid : Types.hash256;
  vout : int32;
  value : int64;
  script_pubkey : Cstruct.t;
  height : int;  (* Height at which this UTXO was created *)
  is_coinbase : bool;
}

(* UTXO lookup result *)
type utxo_lookup = Types.outpoint -> utxo option

(* Validate transaction inputs against UTXO set

   IMPORTANT: This handles intra-block UTXO spending.
   Transactions within a block CAN spend outputs from earlier
   transactions in the same block. The UTXO set must be updated
   during the validation loop, not after. *)
let validate_tx_inputs (tx : Types.transaction) ~(lookup : utxo_lookup)
    ~(block_height : int) ~(flags : int)
    : (int64, tx_validation_error) result =
  (* Skip coinbase transactions - they have no real inputs *)
  if is_coinbase tx then
    Ok 0L
  else begin
    let total_in = ref 0L in
    let error = ref None in

    (* Process each input *)
    List.iteri (fun i inp ->
      if !error = None then begin
        match lookup inp.Types.previous_output with
        | None ->
          error := Some TxMissingInputs
        | Some utxo ->
          (* Check coinbase maturity *)
          if utxo.is_coinbase && block_height - utxo.height < Consensus.coinbase_maturity then
            error := Some TxMissingInputs  (* Immature coinbase *)
          else begin
            (* Add to total input value *)
            total_in := Int64.add !total_in utxo.value;

            (* Get witness for this input *)
            let witness =
              if i < List.length tx.witnesses then
                List.nth tx.witnesses i
              else
                { Types.items = [] }
            in

            (* Verify script *)
            match Script.verify_script
                    ~tx ~input_index:i
                    ~script_pubkey:utxo.script_pubkey
                    ~script_sig:inp.Types.script_sig
                    ~witness
                    ~amount:utxo.value
                    ~flags with
            | Error msg ->
              error := Some (TxScriptFailed (i, msg))
            | Ok false ->
              error := Some (TxScriptFailed (i, "Script returned false"))
            | Ok true -> ()
          end
      end
    ) tx.inputs;

    match !error with
    | Some e -> Error e
    | None -> Ok !total_in
  end

(* Calculate transaction fee *)
let calculate_tx_fee (tx : Types.transaction) ~(lookup : utxo_lookup)
    : int64 option =
  if is_coinbase tx then
    Some 0L  (* Coinbase has no fee *)
  else begin
    (* Sum input values *)
    let total_in = ref 0L in
    let all_found = ref true in
    List.iter (fun inp ->
      match lookup inp.Types.previous_output with
      | None -> all_found := false
      | Some utxo -> total_in := Int64.add !total_in utxo.value
    ) tx.inputs;

    if not !all_found then
      None
    else begin
      (* Sum output values *)
      let total_out = List.fold_left (fun acc out ->
        Int64.add acc out.Types.value
      ) 0L tx.outputs in

      (* Fee = inputs - outputs *)
      if !total_in >= total_out then
        Some (Int64.sub !total_in total_out)
      else
        None  (* Invalid: outputs > inputs *)
    end
  end

(* ============================================================================
   Full Block Validation with UTXO Set
   ============================================================================ *)

(* Validate block with full UTXO tracking

   IMPORTANT: This properly handles intra-block spending by updating
   a local UTXO view during validation. *)
let validate_block_with_utxos (block : Types.block) (height : int)
    ~(expected_bits : int32) ~(median_time : int32)
    ~(base_lookup : utxo_lookup) ~(flags : int)
    : (int64, block_validation_error) result =

  (* First do context-free checks *)
  match check_block block height ~expected_bits ~median_time with
  | Error e -> Error e
  | Ok () ->
    (* Build local UTXO set for intra-block spending *)
    let local_utxos : (string * int32, utxo) Hashtbl.t = Hashtbl.create 64 in
    let spent_in_block : (string * int32, unit) Hashtbl.t = Hashtbl.create 64 in

    (* Lookup that checks local UTXOs first, then base *)
    let lookup outpoint =
      let key = (Cstruct.to_string outpoint.Types.txid, outpoint.Types.vout) in
      (* Check if already spent in this block *)
      if Hashtbl.mem spent_in_block key then
        None
      else
        (* Check local UTXOs from this block *)
        match Hashtbl.find_opt local_utxos key with
        | Some utxo -> Some utxo
        | None -> base_lookup outpoint
    in

    let total_fees = ref 0L in
    let error = ref None in

    List.iteri (fun i tx ->
      if !error = None then begin
        let txid = Crypto.compute_txid tx in
        let is_cb = (i = 0) in

        (* Validate inputs (skip for coinbase) *)
        if not is_cb then begin
          match validate_tx_inputs tx ~lookup ~block_height:height ~flags with
          | Error e ->
            error := Some (BlockTxValidationFailed (i, e))
          | Ok total_in ->
            (* Calculate and accumulate fee *)
            let total_out = List.fold_left (fun acc out ->
              Int64.add acc out.Types.value
            ) 0L tx.outputs in
            let fee = Int64.sub total_in total_out in
            if fee < 0L then
              error := Some (BlockTxValidationFailed (i, TxInsufficientFee))
            else begin
              total_fees := Int64.add !total_fees fee;

              (* Mark inputs as spent *)
              List.iter (fun inp ->
                let key = (Cstruct.to_string inp.Types.previous_output.txid,
                           inp.Types.previous_output.vout) in
                Hashtbl.add spent_in_block key ()
              ) tx.inputs
            end
        end;

        (* Add outputs to local UTXO set for intra-block spending *)
        if !error = None then begin
          List.iteri (fun vout out ->
            let utxo = {
              txid;
              vout = Int32.of_int vout;
              value = out.Types.value;
              script_pubkey = out.Types.script_pubkey;
              height;
              is_coinbase = is_cb;
            } in
            let key = (Cstruct.to_string txid, Int32.of_int vout) in
            Hashtbl.add local_utxos key utxo
          ) tx.outputs
        end
      end
    ) block.transactions;

    match !error with
    | Some e -> Error e
    | None ->
      (* Verify coinbase value <= subsidy + fees *)
      let coinbase = List.hd block.transactions in
      let coinbase_value = List.fold_left (fun acc out ->
        Int64.add acc out.Types.value
      ) 0L coinbase.outputs in
      let max_coinbase = Int64.add (Consensus.block_subsidy height) !total_fees in
      if coinbase_value > max_coinbase then
        Error (BlockBadCoinbaseValue (coinbase_value, max_coinbase))
      else
        Ok !total_fees
