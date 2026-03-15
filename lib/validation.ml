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
  | TxUnexpectedCoinbase
  | TxNullPrevout
  | TxDuplicateTxid
  | TxSequenceLocksFailed
  | TxCoinbaseMaturity of int (* spending coinbase with insufficient confirmations *)

type block_validation_error =
  | BlockEmptyTransactions
  | BlockNoCoinbase
  | BlockBadMerkleRoot
  | BlockBadTimestamp
  | BlockBadDifficulty
  | BlockOverweight of int
  | BlockOversized of int
  | BlockTooManySigops
  | BlockBadCoinbaseValue of int64 * int64
  | BlockDuplicateTx
  | BlockTxValidationFailed of int * tx_validation_error
  | BlockBadWitnessCommitment
  | BlockBadVersion
  | BlockMutatedMerkle

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
  | TxUnexpectedCoinbase -> "unexpected coinbase transaction (not first in block)"
  | TxNullPrevout -> "non-coinbase transaction references null outpoint"
  | TxDuplicateTxid -> "transaction has duplicate txid in UTXO set (BIP30)"
  | TxSequenceLocksFailed -> "transaction sequence locks not satisfied (BIP68)"
  | TxCoinbaseMaturity confirmations ->
    Printf.sprintf "spending immature coinbase (%d < %d confirmations required)"
      confirmations Consensus.coinbase_maturity

let block_error_to_string = function
  | BlockEmptyTransactions -> "block has no transactions"
  | BlockNoCoinbase -> "block has no coinbase transaction"
  | BlockBadMerkleRoot -> "merkle root mismatch"
  | BlockBadTimestamp -> "block timestamp is invalid"
  | BlockBadDifficulty -> "block does not meet difficulty target"
  | BlockOverweight w ->
    Printf.sprintf "block exceeds max weight (%d > %d)" w Consensus.max_block_weight
  | BlockOversized s ->
    Printf.sprintf "block exceeds max serialized size (%d > %d)" s Consensus.max_block_serialized_size
  | BlockTooManySigops -> "block exceeds sigop limit"
  | BlockBadCoinbaseValue (actual, expected) ->
    Printf.sprintf "coinbase value too high (%Ld > %Ld)" actual expected
  | BlockDuplicateTx -> "block contains duplicate transactions"
  | BlockTxValidationFailed (i, e) ->
    Printf.sprintf "transaction %d validation failed: %s" i (tx_error_to_string e)
  | BlockBadWitnessCommitment -> "witness commitment mismatch"
  | BlockBadVersion -> "block version too low for active soft forks"
  | BlockMutatedMerkle -> "merkle tree has mutated duplicate transactions"

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

(* Compute the full serialized size of a transaction including witness data *)
let compute_tx_size (tx : Types.transaction) : int =
  let w = Serialize.writer_create () in
  Serialize.serialize_transaction w tx;
  Cstruct.length (Serialize.writer_to_cstruct w)

(* ============================================================================
   Basic Transaction Validation
   ============================================================================ *)

(* Check if a transaction input references the null outpoint
   (txid = all zeros AND vout = 0xFFFFFFFF) *)
let is_null_outpoint (outpoint : Types.outpoint) : bool =
  Cstruct.equal outpoint.Types.txid Types.zero_hash &&
  outpoint.Types.vout = (-1l)  (* -1l = 0xFFFFFFFF as signed int32 *)

(* Check basic transaction structure.
   ~is_coinbase: when true, skip the null prevout check and duplicate input
   check (coinbase always has a single null input). Default: false. *)
let check_transaction ?(is_coinbase = false) (tx : Types.transaction)
    : (unit, tx_validation_error) result =
  (* Must have at least one input *)
  if tx.inputs = [] then
    Error TxEmptyInputs
  (* Must have at least one output *)
  else if tx.outputs = [] then
    Error TxEmptyOutputs
  else begin
    (* Check consensus size limit: base_size * WITNESS_SCALE_FACTOR must not
       exceed MAX_BLOCK_WEIGHT. This uses the non-witness serialization size,
       matching Bitcoin Core's CheckTransaction in tx_check.cpp. *)
    let w_base = Serialize.writer_create () in
    Serialize.serialize_transaction_no_witness w_base tx;
    let base_size = Cstruct.length (Serialize.writer_to_cstruct w_base) in
    let base_weight = base_size * Consensus.witness_scale_factor in
    if base_weight > Consensus.max_block_weight then
      Error (TxOversizeWeight base_weight)
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
        else begin
          (* Task 3: Check that non-coinbase inputs don't reference null outpoints *)
          if not is_coinbase then begin
            let has_null = List.exists (fun inp ->
              is_null_outpoint inp.Types.previous_output
            ) tx.inputs in
            if has_null then Error TxNullPrevout
            else Ok ()
          end else
            Ok ()
        end
    end
  end

(* Check if a transaction is a coinbase transaction *)
let is_coinbase_tx (tx : Types.transaction) : bool =
  match tx.inputs with
  | [inp] ->
    Cstruct.equal inp.Types.previous_output.txid Types.zero_hash &&
    inp.Types.previous_output.vout = (-1l)
  | _ -> false

(* Keep the old name as an alias for backward compatibility *)
let is_coinbase = is_coinbase_tx

(* ============================================================================
   Coinbase Transaction Validation
   ============================================================================ *)

(* Check coinbase transaction structure *)
let check_coinbase ~network:(network : Consensus.network_config) (tx : Types.transaction) (height : int)
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
        if height >= network.bip34_height then begin
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
   Script Verification Flags by Height
   ============================================================================ *)

(** Get the consensus script verification flags for a given block height.
    This matches Bitcoin Core's GetBlockScriptFlags() in validation.cpp.
    IMPORTANT: Only consensus flags are included. Policy flags (CLEANSTACK,
    SIGPUSHONLY, LOW_S, etc.) must NOT be added here. *)
let get_script_flags_for_height ~(network : Consensus.network_config) (height : int) : int =
  let flags = ref 0 in

  (* BIP16: P2SH (activated at different heights per network) *)
  if height >= 1 then  (* P2SH is active from genesis in practice *)
    flags := !flags lor Script.script_verify_p2sh;

  (* BIP66: Strict DER signatures *)
  if height >= network.bip66_height then
    flags := !flags lor Script.script_verify_dersig;

  (* BIP65: OP_CHECKLOCKTIMEVERIFY *)
  if height >= network.bip65_height then
    flags := !flags lor Script.script_verify_checklocktimeverify;

  (* BIP68/112/113: Relative lock-time (CSV) *)
  if height >= network.csv_height then
    flags := !flags lor Script.script_verify_checksequenceverify;

  (* BIP141/143: SegWit + NULLDUMMY *)
  if height >= network.segwit_height then begin
    flags := !flags lor Script.script_verify_witness;
    flags := !flags lor Script.script_verify_nulldummy
  end;

  (* BIP341/342: Taproot *)
  if height >= network.taproot_height then
    flags := !flags lor Script.script_verify_taproot;

  !flags

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

(* Extract the last push data from a script (used for P2SH redeem script).
   Walks through the script tracking each push data element, returns the last
   one found. Returns None if no push data is found or parsing fails. *)
let extract_last_push_data (script : Cstruct.t) : Cstruct.t option =
  try
    let len = Cstruct.length script in
    let last = ref None in
    let i = ref 0 in
    while !i < len do
      let opcode = Cstruct.get_uint8 script !i in
      if opcode >= 0x01 && opcode <= 0x4b then begin
        (* Direct push: opcode is the number of bytes to push *)
        if !i + 1 + opcode <= len then begin
          last := Some (Cstruct.sub script (!i + 1) opcode);
          i := !i + 1 + opcode
        end else
          i := len  (* Malformed, stop *)
      end else if opcode = 0x4c then begin
        (* OP_PUSHDATA1: next byte is length *)
        if !i + 1 < len then begin
          let push_len = Cstruct.get_uint8 script (!i + 1) in
          if !i + 2 + push_len <= len then begin
            last := Some (Cstruct.sub script (!i + 2) push_len);
            i := !i + 2 + push_len
          end else
            i := len
        end else
          i := len
      end else if opcode = 0x4d then begin
        (* OP_PUSHDATA2: next 2 bytes (LE) are length *)
        if !i + 2 < len then begin
          let push_len = Cstruct.get_uint8 script (!i + 1)
                       lor (Cstruct.get_uint8 script (!i + 2) lsl 8) in
          if !i + 3 + push_len <= len then begin
            last := Some (Cstruct.sub script (!i + 3) push_len);
            i := !i + 3 + push_len
          end else
            i := len
        end else
          i := len
      end else if opcode = 0x4e then begin
        (* OP_PUSHDATA4: next 4 bytes (LE) are length *)
        if !i + 4 < len then begin
          let push_len = Cstruct.get_uint8 script (!i + 1)
                       lor (Cstruct.get_uint8 script (!i + 2) lsl 8)
                       lor (Cstruct.get_uint8 script (!i + 3) lsl 16)
                       lor (Cstruct.get_uint8 script (!i + 4) lsl 24) in
          if push_len >= 0 && !i + 5 + push_len <= len then begin
            last := Some (Cstruct.sub script (!i + 5) push_len);
            i := !i + 5 + push_len
          end else
            i := len
        end else
          i := len
      end else begin
        (* Non-push opcode, just skip *)
        i := !i + 1
      end
    done;
    !last
  with _ -> None

(* Count witness sigops for a specific witness program version.
   Returns the number of sigops (not weighted - witness sigops cost 1 each).
   Per BIP-141:
   - Version 0, 20-byte program (P2WPKH): 1 sigop
   - Version 0, 32-byte program (P2WSH): count sigops in witness script
   - Other versions: 0 (reserved for future soft forks) *)
let witness_sigops (wit_version : int) (program : Cstruct.t)
    (witness : Types.tx_witness) : int =
  if wit_version = 0 then begin
    if Cstruct.length program = 20 then
      (* P2WPKH: 1 sigop *)
      1
    else if Cstruct.length program = 32 && List.length witness.items > 0 then
      (* P2WSH: count sigops in witness script (last stack item) *)
      let witness_script = List.hd (List.rev witness.items) in
      count_witness_sigops witness_script
    else
      0
  end else
    (* Future witness versions: 0 sigops for now *)
    0

(* Count witness sigops for an input given its scriptSig, scriptPubKey, and witness.
   Per Bitcoin Core's CountWitnessSigOps in interpreter.cpp.
   Returns 0 if SCRIPT_VERIFY_WITNESS flag is not set.
   Handles both native SegWit and P2SH-wrapped SegWit. *)
let count_input_witness_sigops ~(script_sig : Cstruct.t)
    ~(script_pubkey : Cstruct.t) ~(witness : Types.tx_witness) ~(flags : int) : int =
  (* If witness flag not set, no witness sigops *)
  if flags land Script.script_verify_witness = 0 then
    0
  else begin
    (* Check for native witness program *)
    match Script.get_witness_program script_pubkey with
    | Some (version, program) ->
      witness_sigops version program witness
    | None ->
      (* Check for P2SH-wrapped witness program *)
      match Script.classify_script script_pubkey with
      | Script.P2SH_script _ when Script.is_push_only script_sig ->
        begin match extract_last_push_data script_sig with
        | Some redeem_script ->
          begin match Script.get_witness_program redeem_script with
          | Some (version, program) ->
            witness_sigops version program witness
          | None -> 0
          end
        | None -> 0
        end
      | _ -> 0
  end

(* Count weighted sigops cost for a transaction per BIP-141.
   prev_script_pubkey_lookup: returns the scriptPubKey of the previous output
   for a given outpoint (None if not found, e.g. for coinbase).
   flags: script verification flags (to check P2SH and WITNESS activation).

   Per Bitcoin Core GetTransactionSigOpCost in tx_verify.cpp:
   - Legacy sigops (scriptSig + scriptPubKey) × WITNESS_SCALE_FACTOR
   - P2SH sigops (if P2SH flag set) × WITNESS_SCALE_FACTOR
   - Witness sigops (if WITNESS flag set) × 1 (no multiplier) *)
let count_tx_sigops_cost (tx : Types.transaction)
    ~(prev_script_pubkey_lookup : Types.outpoint -> Cstruct.t option)
    ~(flags : int) : int =
  let wsf = Consensus.witness_scale_factor in

  (* Legacy sigops in scriptSig and scriptPubKey, weighted by scale factor *)
  let legacy_cost =
    let in_sigops = List.fold_left (fun acc inp ->
      acc + count_sigops inp.Types.script_sig
    ) 0 tx.Types.inputs in
    let out_sigops = List.fold_left (fun acc out ->
      acc + count_sigops out.Types.script_pubkey
    ) 0 tx.Types.outputs in
    (in_sigops + out_sigops) * wsf
  in

  (* For coinbase, only legacy sigops count *)
  if is_coinbase tx then
    legacy_cost
  else begin
    (* P2SH sigops (if P2SH flag is set) *)
    let p2sh_cost =
      if flags land Script.script_verify_p2sh = 0 then 0
      else
        List.fold_left (fun acc inp ->
          match prev_script_pubkey_lookup inp.Types.previous_output with
          | None -> acc
          | Some prev_spk ->
            match Script.classify_script prev_spk with
            | Script.P2SH_script _ ->
              begin match extract_last_push_data inp.Types.script_sig with
              | Some redeem_script ->
                (* Don't count P2SH sigops for P2SH-wrapped witness programs;
                   those are counted separately via CountWitnessSigOps *)
                begin match Script.get_witness_program redeem_script with
                | Some _ -> acc  (* Witness program, skip P2SH count *)
                | None -> acc + count_p2sh_sigops redeem_script * wsf
                end
              | None -> acc
              end
            | _ -> acc
        ) 0 tx.Types.inputs
    in

    (* Witness sigops (if WITNESS flag is set) *)
    let witness_cost =
      List.fold_left (fun acc_cost (i, inp) ->
        match prev_script_pubkey_lookup inp.Types.previous_output with
        | None -> acc_cost
        | Some prev_spk ->
          let witness =
            if i < List.length tx.witnesses then
              List.nth tx.witnesses i
            else { Types.items = [] }
          in
          acc_cost + count_input_witness_sigops
            ~script_sig:inp.Types.script_sig
            ~script_pubkey:prev_spk
            ~witness
            ~flags
      ) 0 (List.mapi (fun i inp -> (i, inp)) tx.Types.inputs)
    in

    legacy_cost + p2sh_cost + witness_cost
  end

(* Backward-compatible wrapper that uses full flags *)
let count_tx_sigops_cost_simple (tx : Types.transaction)
    ~(prev_script_pubkey_lookup : Types.outpoint -> Cstruct.t option) : int =
  let flags = Script.script_verify_p2sh lor Script.script_verify_witness in
  count_tx_sigops_cost tx ~prev_script_pubkey_lookup ~flags

(* Count weighted sigops cost for entire block per BIP-141 *)
let count_block_sigops_cost (block : Types.block)
    ~(prev_script_pubkey_lookup : Types.outpoint -> Cstruct.t option)
    ~(flags : int) : int =
  List.fold_left (fun acc tx ->
    acc + count_tx_sigops_cost tx ~prev_script_pubkey_lookup ~flags
  ) 0 block.transactions

(* Legacy unweighted sigops count (backward compatibility for mining template).
   Counts raw sigops in scriptSig and scriptPubKey without BIP-141 weighting. *)
let count_tx_sigops (tx : Types.transaction) : int =
  let in_sigops = List.fold_left (fun acc inp ->
    acc + count_sigops inp.Types.script_sig
  ) 0 tx.Types.inputs in
  let out_sigops = List.fold_left (fun acc out ->
    acc + count_sigops out.Types.script_pubkey
  ) 0 tx.Types.outputs in
  in_sigops + out_sigops

(* ============================================================================
   Witness Commitment Verification (BIP-141)
   ============================================================================ *)

(* Check if a block has any transactions with non-empty witness data *)
let block_has_witness (block : Types.block) : bool =
  List.exists (fun tx ->
    List.exists (fun w -> w.Types.items <> []) tx.Types.witnesses
  ) block.transactions

(* Find the witness commitment in the coinbase transaction.
   Scans coinbase outputs IN REVERSE for one whose scriptPubKey starts with
   bytes [0x6a; 0x24; 0xaa; 0x21; 0xa9; 0xed] (OP_RETURN + push36 + magic).
   Returns the 32-byte commitment hash if found. *)
let find_witness_commitment (coinbase : Types.transaction) : Cstruct.t option =
  let prefix = Cstruct.of_string "\x6a\x24\xaa\x21\xa9\xed" in
  let outputs = List.rev coinbase.outputs in
  let rec scan = function
    | [] -> None
    | out :: rest ->
      let spk = out.Types.script_pubkey in
      if Cstruct.length spk >= 38 then begin
        let spk_prefix = Cstruct.sub spk 0 6 in
        if Cstruct.equal spk_prefix prefix then
          Some (Cstruct.sub spk 6 32)
        else
          scan rest
      end else
        scan rest
  in
  scan outputs

(* Compute witness transaction ID (wtxid).
   For coinbase, wtxid is always zero.
   For other transactions, wtxid includes witness data (full serialization). *)
let compute_wtxid (tx : Types.transaction) (is_cb : bool) : Types.hash256 =
  if is_cb then
    Types.zero_hash
  else begin
    let w = Serialize.writer_create () in
    Serialize.serialize_transaction w tx;
    Crypto.sha256d (Serialize.writer_to_cstruct w)
  end

(* Compute the witness merkle root from a list of transactions.
   The first transaction (coinbase) has wtxid = 0. *)
let compute_witness_merkle_root (transactions : Types.transaction list)
    : Types.hash256 =
  let wtxids = List.mapi (fun i tx ->
    compute_wtxid tx (i = 0)
  ) transactions in
  let (root, _mutated) = Crypto.merkle_root wtxids in
  root

(* Verify the witness commitment in a block. *)
let check_witness_commitment (block : Types.block)
    : (unit, block_validation_error) result =
  let coinbase = List.hd block.transactions in
  match find_witness_commitment coinbase with
  | Some commitment ->
    (* Witness commitment found in coinbase — always validate it,
       regardless of whether transactions have witness data *)
    let witness_nonce =
      match coinbase.witnesses with
      | [] -> None
      | w :: _ ->
        match w.Types.items with
        | [item] when Cstruct.length item = 32 -> Some item
        | _ -> None
    in
    (match witness_nonce with
    | None -> Error BlockBadWitnessCommitment
    | Some nonce ->
      let witness_root = compute_witness_merkle_root block.transactions in
      let combined = Cstruct.concat [witness_root; nonce] in
      let expected = Crypto.sha256d combined in
      if Cstruct.equal expected commitment then
        Ok ()
      else
        Error BlockBadWitnessCommitment)
  | None ->
    (* No commitment — reject if any transaction has witness data *)
    if block_has_witness block then
      Error BlockBadWitnessCommitment
    else
      Ok ()

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
let check_block ~network:(network : Consensus.network_config) (block : Types.block) (height : int)
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
      match check_coinbase ~network coinbase height with
      | Error e -> Error (BlockTxValidationFailed (0, e))
      | Ok () ->
        (* Bug 5: Block version enforcement after BIP activation heights *)
        if height >= network.bip34_height && Int32.compare block.header.version 2l < 0 then
          Error BlockBadVersion
        else if height >= network.bip66_height && Int32.compare block.header.version 3l < 0 then
          Error BlockBadVersion
        else if height >= network.bip65_height && Int32.compare block.header.version 4l < 0 then
          Error BlockBadVersion
        else
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
              let (computed_merkle, mutated) = Crypto.merkle_root txids in
              if mutated then
                Error BlockMutatedMerkle
              else if not (Cstruct.equal computed_merkle block.header.merkle_root) then
                Error BlockBadMerkleRoot
              else begin
                (* Check for duplicate txids *)
                match check_duplicate_txids txs with
                | Error e -> Error e
                | Ok () ->
                  (* Context-free legacy sigops check (fast early rejection).
                     This underestimates sigops because it doesn't count
                     P2SH or witness sigops, but catches obviously invalid blocks
                     without UTXO context. Matches Bitcoin Core's CheckBlock. *)
                  let legacy_sigops = List.fold_left (fun acc tx ->
                    acc + count_tx_sigops tx
                  ) 0 txs in
                  if legacy_sigops * Consensus.witness_scale_factor > Consensus.max_block_sigops_cost then
                    Error BlockTooManySigops
                  else
                  (* Check raw serialized block size against the 4MB limit.
                     This is separate from the weight limit and matches
                     Bitcoin Core's MAX_BLOCK_SERIALIZED_SIZE check. *)
                  let w_block = Serialize.writer_create () in
                  Serialize.serialize_block w_block block;
                  let block_size = Cstruct.length (Serialize.writer_to_cstruct w_block) in
                  if block_size > Consensus.max_block_serialized_size then
                    Error (BlockOversized block_size)
                  else
                  (* Check total block weight: sum of individual transaction
                     weights only. Bitcoin Core's CheckBlock does NOT include
                     the block header or txcount varint in the weight. *)
                  let total_weight = List.fold_left (fun acc tx ->
                    acc + compute_tx_weight tx
                  ) 0 txs in
                  if total_weight > Consensus.max_block_weight then
                    Error (BlockOverweight total_weight)
                  else begin
                    (* Sigop cost check is deferred to validate_block_with_utxos
                       which has UTXO context needed for BIP-141 weighted sigops
                       cost calculation (P2SH redeem scripts, witness programs). *)
                    begin
                      (* Task 1 & 2: Validate ALL transactions including coinbase.
                         Also check that non-first transactions are NOT coinbase. *)
                      let error = ref None in
                      List.iteri (fun i tx ->
                        if !error = None then begin
                          (* Task 1: Non-first transactions must NOT be coinbase *)
                          if i > 0 && is_coinbase tx then
                            error := Some (BlockTxValidationFailed (i, TxUnexpectedCoinbase))
                          else begin
                            (* Task 2: Run check_transaction on ALL transactions
                               including coinbase (i = 0). Pass ~is_coinbase for
                               the coinbase so null prevout check is skipped. *)
                            match check_transaction ~is_coinbase:(i = 0) tx with
                            | Error e ->
                              error := Some (BlockTxValidationFailed (i, e))
                            | Ok () -> ()
                          end
                        end
                      ) txs;

                      match !error with
                      | Some e -> Error e
                      | None ->
                        (* Task 6: Verify witness commitment *)
                        match check_witness_commitment block with
                        | Error e -> Error e
                        | Ok () ->
                          (* Coinbase value check is deferred to
                             validate_block_with_utxos which has UTXO context
                             to compute actual fees. Without knowing fees, any
                             check here would either be too strict (rejecting
                             valid blocks) or too loose to be useful. *)
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

(* Check if transaction is final based on locktime and sequences.
   Locktime is unsigned 32-bit: values < 500_000_000 are block heights,
   values >= 500_000_000 are Unix timestamps. *)
let is_tx_final (tx : Types.transaction) ~(block_height : int) ~(block_time : int32)
    : bool =
  if tx.locktime = 0l then
    true
  else begin
    if List.for_all (fun inp ->
         Int32.equal inp.Types.sequence 0xFFFFFFFFl
       ) tx.inputs then
      true
    else begin
      (* Treat locktime as unsigned 32-bit *)
      let locktime_unsigned = Int64.logand (Int64.of_int32 tx.locktime) 0xFFFFFFFFL in
      if locktime_unsigned < 500_000_000L then
        (* Locktime is a block height *)
        Int64.of_int block_height >= locktime_unsigned
      else
        (* Locktime is a unix timestamp - compare unsigned *)
        let block_time_unsigned = Int64.logand (Int64.of_int32 block_time) 0xFFFFFFFFL in
        block_time_unsigned >= locktime_unsigned
    end
  end

(* ============================================================================
   BIP68 Sequence Locks
   ============================================================================ *)


(* Check BIP68 sequence locks for a transaction.
   For each input where tx.version >= 2 and the input's sequence doesn't have
   the disable flag (bit 31) set:
   - If bit 22 is clear (height-based): utxo_heights[i] + (sequence & 0xFFFF) <= block_height
   - If bit 22 is set (time-based): use MTP-based comparison

   utxo_heights: array of block heights where each input's UTXO was created.
   utxo_mtps: array of median-time-past values for each input's UTXO block.
     When get_mtp_at_height is provided, both this array and the time-based lock
     check use MTP at (utxo_height - 1) per BIP68. Otherwise falls back to the
     caller-supplied approximation. Height-based locks are implemented correctly. *)
let check_sequence_locks (tx : Types.transaction) ~(block_height : int)
    ~(median_time : int32) ~(utxo_heights : int array) ~(utxo_mtps : int32 array)
    ?(get_mtp_at_height : (int -> int32) option) ~flags () : bool =
  if Int32.compare tx.version 2l < 0 then true
  else if flags land Script.script_verify_checksequenceverify = 0 then true
  else begin
    let ok = ref true in
    List.iteri (fun i inp ->
      if !ok then begin
        let seq32 = inp.Types.sequence in
        (* Check if disable flag (bit 31) is set *)
        if Int32.logand seq32 0x80000000l <> 0l then
          ()  (* Sequence lock disabled for this input, skip *)
        else begin
          let masked = Int32.to_int (Int32.logand seq32 0xFFFFl) in
          if Int32.logand seq32 0x00400000l = 0l then begin
            (* Height-based lock *)
            let required_height = utxo_heights.(i) + masked in
            if block_height < required_height then
              ok := false
          end else begin
            (* Time-based lock *)
            let input_mtp = match get_mtp_at_height with
              | Some f -> f (max 0 (utxo_heights.(i) - 1))
              | None -> utxo_mtps.(i)
            in
            let time_offset = Int32.of_int (masked lsl 9) in
            let required_time = Int32.add input_mtp time_offset in
            if Int32.compare median_time required_time < 0 then
              ok := false
          end
        end
      end
    ) tx.inputs;
    !ok
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

(* UTXO view for transaction validation (alias for cleaner API) *)
type utxo_view = utxo_lookup

(* Get transaction sigop cost using UTXO view.
   This is a convenience wrapper matching the canonical signature
   mentioned in Bitcoin Core references.
   Uses full flags (P2SH + WITNESS) by default. *)
let get_transaction_sigop_cost (tx : Types.transaction) (view : utxo_view) : int =
  let flags = Script.script_verify_p2sh lor Script.script_verify_witness in
  let prev_script_pubkey_lookup outpoint =
    match view outpoint with
    | Some utxo -> Some utxo.script_pubkey
    | None -> None
  in
  count_tx_sigops_cost tx ~prev_script_pubkey_lookup ~flags

(* Validate transaction inputs against UTXO set

   IMPORTANT: This handles intra-block UTXO spending.
   Transactions within a block CAN spend outputs from earlier
   transactions in the same block. The UTXO set must be updated
   during the validation loop, not after. *)
let validate_tx_inputs (tx : Types.transaction) ~(lookup : utxo_lookup)
    ~(block_height : int) ~(flags : int) ?(skip_scripts=false) ()
    : (int64, tx_validation_error) result =
  (* Skip coinbase transactions - they have no real inputs *)
  if is_coinbase tx then
    Ok 0L
  else begin
    (* First pass: collect all UTXOs and check maturity *)
    let n_inputs = List.length tx.inputs in
    let utxos = Array.make n_inputs None in
    let error = ref None in

    List.iteri (fun i inp ->
      if !error = None then begin
        match lookup inp.Types.previous_output with
        | None ->
          error := Some TxMissingInputs
        | Some utxo ->
          (* Task 7: Validate input value is in MoneyRange *)
          if not (Consensus.is_valid_money utxo.value) then
            error := Some TxOutputOverflow
          else if utxo.is_coinbase && block_height - utxo.height < Consensus.coinbase_maturity then begin
            let confirmations = block_height - utxo.height in
            error := Some (TxCoinbaseMaturity confirmations)
          end
          else
            utxos.(i) <- Some utxo
      end
    ) tx.inputs;

    match !error with
    | Some e -> Error e
    | None ->
      (* Build prevouts list for Taproot sighash: (amount, scriptPubKey) for all inputs *)
      let prevouts = Array.to_list (Array.map (fun opt ->
        match opt with
        | Some utxo -> (utxo.value, utxo.script_pubkey)
        | None -> (0L, Cstruct.empty)  (* Should not happen *)
      ) utxos) in

      let total_in = ref 0L in

      (* Second pass: verify scripts with prevouts context *)
      List.iteri (fun i inp ->
        if !error = None then begin
          match utxos.(i) with
          | None -> error := Some TxMissingInputs
          | Some utxo ->
            total_in := Int64.add !total_in utxo.value;

            (* Task 7: Check cumulative total_in is in MoneyRange *)
            if not (Consensus.is_valid_money !total_in) then
              error := Some TxOutputOverflow
            else if not skip_scripts then begin
              let witness =
                if i < List.length tx.witnesses then
                  List.nth tx.witnesses i
                else
                  { Types.items = [] }
              in

              match Script.verify_script
                      ~tx ~input_index:i
                      ~script_pubkey:utxo.script_pubkey
                      ~script_sig:inp.Types.script_sig
                      ~witness
                      ~amount:utxo.value
                      ~flags ~prevouts () with
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

(* BIP30 exception heights: these historical Bitcoin blocks had duplicate
   coinbase txids that were later spent. *)
let bip30_exception_heights = [91842; 91880]

(* Check BIP30: no unspent outputs exist with the same txid.
   We probe output indices 0 through n_outputs-1 in the UTXO set. *)
let check_bip30 ~(lookup : utxo_lookup) ~(txid : Types.hash256)
    ~(n_outputs : int) : bool =
  let found = ref false in
  for vout = 0 to n_outputs - 1 do
    let outpoint = { Types.txid; vout = Int32.of_int vout } in
    match lookup outpoint with
    | Some _ -> found := true
    | None -> ()
  done;
  not !found

(* Validate block with full UTXO tracking

   IMPORTANT: This properly handles intra-block spending by updating
   a local UTXO view during validation. *)
let validate_block_with_utxos ~network:(network : Consensus.network_config) (block : Types.block) (height : int)
    ~(expected_bits : int32) ~(median_time : int32)
    ~(base_lookup : utxo_lookup) ~(flags : int)
    ?(skip_scripts=false) ?get_mtp_at_height ()
    : (int64, block_validation_error) result =

  (* First do context-free checks *)
  match check_block ~network block height ~expected_bits ~median_time with
  | Error e -> Error e
  | Ok () ->
    (* Build local UTXO set for intra-block spending *)
    let local_utxos : (string * int32, utxo) Hashtbl.t = Hashtbl.create 64 in
    let spent_in_block : (string * int32, unit) Hashtbl.t = Hashtbl.create 64 in

    (* Lookup that checks local UTXOs first, then base *)
    let lookup outpoint =
      let key = (Cstruct.to_string outpoint.Types.txid, outpoint.Types.vout) in
      if Hashtbl.mem spent_in_block key then
        None
      else
        match Hashtbl.find_opt local_utxos key with
        | Some utxo -> Some utxo
        | None -> base_lookup outpoint
    in

    (* Accumulate sigops during per-tx validation so intra-block UTXOs are visible *)
    let total_sigops_cost = ref 0 in
    let total_fees = ref 0L in
    let error = ref None in

    List.iteri (fun i tx ->
      if !error = None then begin
        let txid = Crypto.compute_txid tx in
        let is_cb = (i = 0) in

        (* Task 4: BIP30 duplicate txid check *)
        if not (List.mem height bip30_exception_heights) then begin
          let n_outputs = List.length tx.outputs in
          if not (check_bip30 ~lookup:base_lookup ~txid ~n_outputs) then
            error := Some (BlockTxValidationFailed (i, TxDuplicateTxid))
        end;

        (* BIP-141 per-tx sigops cost, accumulated across block.
           Uses full lookup so intra-block outputs are visible for P2SH/witness. *)
        if !error = None then begin
          let prev_script_pubkey_lookup outpoint =
            match lookup outpoint with
            | Some utxo -> Some utxo.script_pubkey
            | None -> None
          in
          let tx_sigops = count_tx_sigops_cost tx ~prev_script_pubkey_lookup ~flags in
          total_sigops_cost := !total_sigops_cost + tx_sigops;
          if !total_sigops_cost > Consensus.max_block_sigops_cost then
            error := Some BlockTooManySigops
        end;

        (* Validate inputs (skip for coinbase) *)
        if !error = None && not is_cb then begin
          (* BIP-113: use median time past for locktime comparison
             only after CSV activation. Before CSV, use block timestamp. *)
          let locktime_cutoff =
            if flags land Script.script_verify_checksequenceverify <> 0 then
              median_time
            else
              block.header.timestamp
          in
          if not (is_tx_final tx ~block_height:height ~block_time:locktime_cutoff) then
            error := Some (BlockTxValidationFailed (i, TxNonFinalLocktime))
          else begin
            match validate_tx_inputs tx ~lookup ~block_height:height ~flags ~skip_scripts () with
            | Error e ->
              error := Some (BlockTxValidationFailed (i, e))
            | Ok total_in ->
              (* Task 5: BIP68 sequence locks *)
              if !error = None then begin
                let n_inputs = List.length tx.inputs in
                let utxo_heights = Array.make n_inputs 0 in
                let utxo_mtps = Array.make n_inputs 0l in
                (* Collect UTXO heights for sequence lock checks *)
                List.iteri (fun j inp ->
                  match lookup inp.Types.previous_output with
                  | Some utxo ->
                    utxo_heights.(j) <- utxo.height;
                    utxo_mtps.(j) <- (match get_mtp_at_height with
                      | Some f -> f (utxo.height - 1)
                      | None -> median_time)
                  | None -> ()
                ) tx.inputs;
                if not (check_sequence_locks tx ~block_height:height
                          ~median_time ~utxo_heights ~utxo_mtps
                          ?get_mtp_at_height ~flags ()) then
                  error := Some (BlockTxValidationFailed (i, TxSequenceLocksFailed))
              end;

              if !error = None then begin
                (* Calculate and accumulate fee *)
                let total_out = List.fold_left (fun acc out ->
                  Int64.add acc out.Types.value
                ) 0L tx.outputs in
                let fee = Int64.sub total_in total_out in
                if fee < 0L then
                  error := Some (BlockTxValidationFailed (i, TxInsufficientFee))
                else begin
                  total_fees := Int64.add !total_fees fee;

                  (* Task 8: Fee overflow check *)
                  if not (Consensus.is_valid_money !total_fees) then
                    error := Some (BlockTxValidationFailed (i, TxOutputOverflow))
                  else begin
                    (* Mark inputs as spent *)
                    List.iter (fun inp ->
                      let key = (Cstruct.to_string inp.Types.previous_output.txid,
                                 inp.Types.previous_output.vout) in
                      Hashtbl.add spent_in_block key ()
                    ) tx.inputs
                  end
                end
              end
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
      let max_coinbase = Int64.add (Consensus.block_subsidy_for_network network.network_type height) !total_fees in
      if coinbase_value > max_coinbase then
        Error (BlockBadCoinbaseValue (coinbase_value, max_coinbase))
      else
        Ok !total_fees
