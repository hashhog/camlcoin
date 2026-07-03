(* Block and transaction validation *)

(* ============================================================================
   Validation Error Types
   ============================================================================ *)

type tx_validation_error =
  | TxEmptyInputs
  | TxEmptyOutputs
  | TxOversizeWeight of int
  | TxNegativeOutput of int     (* output value < 0 (signed int64): bad-txns-vout-negative *)
  | TxOutputTooLarge of int     (* output value > MAX_MONEY: bad-txns-vout-toolarge *)
  | TxOutputOverflow
  | TxDuplicateInputs
  | TxMissingInputs
  | TxInsufficientFee
  | TxScriptFailed of int * string
  | TxNonFinalLocktime
  | TxBadCoinbase
  | TxCoinbaseScriptSigTooLong  (* scriptSig length outside 2..100 bytes; bad-cb-length *)
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
  | BlockBadWitnessCommitment    (* bad-witness-merkle-match *)
  | BlockBadWitnessNonceSize     (* bad-witness-nonce-size: coinbase scriptWitness must be 1 item of 32 bytes *)
  | BlockUnexpectedWitness       (* unexpected-witness: witness data in non-segwit block *)
  | BlockBadVersion
  | BlockMutatedMerkle
  | BlockTimeWarpAttack  (* time-timewarp-attack: BIP-94 retarget-boundary timestamp too early *)

(* ============================================================================
   Error formatting
   ============================================================================ *)

let tx_error_to_string = function
  | TxEmptyInputs -> "transaction has no inputs"
  | TxEmptyOutputs -> "transaction has no outputs"
  | TxOversizeWeight w ->
    Printf.sprintf "transaction exceeds max weight (%d > %d)" w Consensus.max_tx_weight
  | TxNegativeOutput i ->
    Printf.sprintf "output %d has negative value" i
  | TxOutputTooLarge i ->
    Printf.sprintf "output %d value exceeds MAX_MONEY" i
  | TxOutputOverflow -> "total output value overflow"
  | TxDuplicateInputs -> "transaction has duplicate inputs"
  | TxMissingInputs -> "transaction references missing inputs"
  | TxInsufficientFee -> "transaction fee is insufficient"
  | TxScriptFailed (i, msg) ->
    Printf.sprintf "script verification failed for input %d: %s" i msg
  | TxNonFinalLocktime -> "transaction is not final (locktime)"
  | TxBadCoinbase -> "invalid coinbase transaction"
  | TxCoinbaseScriptSigTooLong -> "coinbase scriptSig length out of range (bad-cb-length)"
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
  | BlockBadWitnessCommitment -> "bad-witness-merkle-match"
  | BlockBadWitnessNonceSize -> "bad-witness-nonce-size"
  | BlockUnexpectedWitness -> "unexpected-witness"
  | BlockBadVersion -> "block version too low for active soft forks"
  | BlockMutatedMerkle -> "merkle tree has mutated duplicate transactions"
  | BlockTimeWarpAttack -> "time-timewarp-attack"

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

(* Byte length of a Bitcoin CompactSize encoding of [n] (the tx-count prefix). *)
let compact_size_len (n : int) : int =
  if n < 0xFD then 1
  else if n <= 0xFFFF then 3
  else if n <= 0xFFFF_FFFF then 5
  else 9

(* Block weight, Bitcoin Core consensus/validation.h::GetBlockWeight:
   GetSerializeSize(TX_NO_WITNESS(block)) * (WSF-1) + GetSerializeSize(TX_WITH_WITNESS(block)).
   This serializes the WHOLE block, which prepends an 80-byte header and a
   CompactSize transaction count to the transactions. Both are witness-free, so
   they appear in both serializations and count at the full WITNESS_SCALE_FACTOR:
   the block weight is (80 + compact_size_len n) * WSF + sum(per-tx weight).
   Summing only the per-tx weights under-counts by (80 + varint) * WSF (324 for a
   1-byte varint, up to 332), which false-accepts a block whose true Core weight
   is in (MAX_BLOCK_WEIGHT, MAX_BLOCK_WEIGHT + that gap] -- Core rejects it with
   bad-blk-weight, so accepting it is a chain split. *)
let compute_block_weight (txs : Types.transaction list) : int =
  let n = List.length txs in
  let header_varint_weight =
    (80 + compact_size_len n) * Consensus.witness_scale_factor
  in
  List.fold_left (fun acc tx -> acc + compute_tx_weight tx) header_varint_weight txs

(* Virtual size is weight / 4, rounded up.
   For the plain (no-sigop-adjustment) case only. Use get_virtual_transaction_size
   when you have a sigop cost to apply. *)
let compute_tx_vsize (tx : Types.transaction) : int =
  (compute_tx_weight tx + 3) / 4

(* GetSigOpsAdjustedWeight — policy/policy.cpp:390-393
   Returns max(weight, sigop_cost * bytes_per_sigop).
   When bytes_per_sigop = 0 (no sigop adjustment requested) this reduces to weight.
   This prevents sigop-exhaustion attacks by making high-sigop transactions
   appear heavier for feerate and vsize purposes. *)
let get_sigops_adjusted_weight ~(weight : int) ~(sigop_cost : int)
    ~(bytes_per_sigop : int) : int =
  if bytes_per_sigop = 0 then weight
  else max weight (sigop_cost * bytes_per_sigop)

(* GetVirtualTransactionSize — policy/policy.cpp:395-398
   vsize = ceil(get_sigops_adjusted_weight(weight, sigop_cost, bytes_per_sigop) / WITNESS_SCALE_FACTOR)
   When sigop_cost = 0 or bytes_per_sigop = 0 this is just ceil(weight / 4). *)
let get_virtual_transaction_size ~(weight : int) ~(sigop_cost : int)
    ~(bytes_per_sigop : int) : int =
  let adj = get_sigops_adjusted_weight ~weight ~sigop_cost ~bytes_per_sigop in
  (adj + Consensus.witness_scale_factor - 1) / Consensus.witness_scale_factor

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
          (* Check for negative value — mirrors Core consensus/tx_check.cpp::CheckTransaction *)
          if out.Types.value < 0L then
            bad_output := Some (TxNegativeOutput i)
          (* Check for value exceeding max money *)
          else if out.Types.value > Consensus.max_money then
            bad_output := Some (TxOutputTooLarge i)
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
      (* Script sig length must be between 2 and 100 bytes.
         Bitcoin Core consensus/tx_check.cpp:49. *)
      let script_len = Cstruct.length inp.Types.script_sig in
      if script_len < 2 || script_len > 100 then
        Error TxCoinbaseScriptSigTooLong
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

(* Raw byte walker for sigop counting, mirroring Bitcoin Core's
   CScript::GetSigOpCount (script/script.cpp:158-180).

   The previous implementation wrapped parse_script in `try ... with _ -> 0`,
   so ANY script that failed to fully parse (e.g. leading OP_CHECKSIGs followed
   by a truncated push) returned 0 sigops.  Bitcoin Core's GetSigOpCount instead
   walks the script opcode-by-opcode via GetOp and, when GetOp returns false
   (truncated push — not enough bytes for the length prefix or the data body),
   BREAKS and returns the count accumulated SO FAR.  An attacker can construct a
   block whose true (Core) sigop cost exceeds MAX_BLOCK_SIGOPS_COST while this
   node counted ~0, causing a false-accept and a latent chain-split.

   [accurate=false]: OP_CHECKMULTISIG/VERIFY always counts as MAX_PUBKEYS_PER_MULTISIG
   (20), matching GetSigOpCount(fAccurate=false).  Used for legacy scriptSig /
   scriptPubKey counting.
   [accurate=true]: OP_CHECKMULTISIG/VERIFY uses the directly preceding OP_1..OP_16
   opcode value (0x51..0x60 → 1..16), matching GetSigOpCount(fAccurate=true).
   Used for P2SH redeem-script and witness-script counting.

   In both modes, on a truncated push the walker STOPS and returns the partial
   count — NOT 0. *)
let count_sigops_raw ~(accurate : bool) (script : Cstruct.t) : int =
  let len = Cstruct.length script in
  let count = ref 0 in
  let last_opcode = ref 0x00 in   (* 0 is OP_0, not in OP_1..OP_16 range *)
  let pos = ref 0 in
  let stop = ref false in
  while not !stop && !pos < len do
    let opcode = Cstruct.get_uint8 script !pos in
    pos := !pos + 1;
    (* Skip push data.  Mirror GetOp: if the script is truncated (not enough
       bytes for the length prefix or the data itself), Core's GetOp returns
       false → the loop breaks BEFORE the sigop check.  We set stop := true and
       skip the sigop-count update below. *)
    if opcode >= 0x01 && opcode <= 0x4b then begin
      (* Direct push of [opcode] bytes *)
      let new_pos = !pos + opcode in
      if new_pos > len then stop := true
      else pos := new_pos
    end else if opcode = 0x4c then begin
      (* OP_PUSHDATA1: 1-byte length then data *)
      if !pos >= len then stop := true
      else begin
        let data_len = Cstruct.get_uint8 script !pos in
        let new_pos = !pos + 1 + data_len in
        if new_pos > len then stop := true
        else pos := new_pos
      end
    end else if opcode = 0x4d then begin
      (* OP_PUSHDATA2: 2-byte LE length then data *)
      if !pos + 1 >= len then stop := true
      else begin
        let data_len =
          Cstruct.get_uint8 script !pos
          lor (Cstruct.get_uint8 script (!pos + 1) lsl 8)
        in
        let new_pos = !pos + 2 + data_len in
        if new_pos > len then stop := true
        else pos := new_pos
      end
    end else if opcode = 0x4e then begin
      (* OP_PUSHDATA4: 4-byte LE length then data *)
      if !pos + 3 >= len then stop := true
      else begin
        let b0 = Cstruct.get_uint8 script !pos in
        let b1 = Cstruct.get_uint8 script (!pos + 1) in
        let b2 = Cstruct.get_uint8 script (!pos + 2) in
        let b3 = Cstruct.get_uint8 script (!pos + 3) in
        (* OCaml int is 63 bits on 64-bit systems; safe for all PUSHDATA4 values *)
        let data_len = b0 lor (b1 lsl 8) lor (b2 lsl 16) lor (b3 lsl 24) in
        if data_len < 0 then stop := true  (* defensive guard for 32-bit builds *)
        else begin
          let new_pos = !pos + 4 + data_len in
          if new_pos > len then stop := true
          else pos := new_pos
        end
      end
    end;
    (* Count sigop opcodes — only when the opcode was fully consumed (not stopped
       by a truncated push), matching Core's post-GetOp sigop check. *)
    if not !stop then begin
      (* OP_CHECKSIG=0xac, OP_CHECKSIGVERIFY=0xad *)
      (if opcode = 0xac || opcode = 0xad then
        count := !count + 1
      (* OP_CHECKMULTISIG=0xae, OP_CHECKMULTISIGVERIFY=0xaf *)
      else if opcode = 0xae || opcode = 0xaf then begin
        let n =
          if accurate && !last_opcode >= 0x51 && !last_opcode <= 0x60 then
            (* OP_1=0x51→1, OP_2=0x52→2, …, OP_16=0x60→16 (DecodeOP_N) *)
            !last_opcode - 0x50
          else
            20  (* MAX_PUBKEYS_PER_MULTISIG *)
        in
        count := !count + n
      end);
      last_opcode := opcode
    end
  done;
  !count

(* Count legacy sigops in a script (for block sigop limit).
   Mirrors CScript::GetSigOpCount(fAccurate=false) (script/script.cpp:158-180):
   walks raw bytes, counts CHECKSIG/CHECKSIGVERIFY as 1,
   CHECKMULTISIG/CHECKMULTISIGVERIFY as 20, and on a truncated push STOPS and
   returns the count so far (not 0). *)
let count_sigops (script : Cstruct.t) : int =
  count_sigops_raw ~accurate:false script

(* Count P2SH / witness sigops (accurate multisig counting).
   Mirrors CScript::GetSigOpCount(fAccurate=true): same raw byte walk but
   OP_CHECKMULTISIG/VERIFY uses the value of the directly preceding OP_1..OP_16
   opcode (if any) rather than the 20-pubkey worst-case. *)
let count_p2sh_sigops (redeem_script : Cstruct.t) : int =
  count_sigops_raw ~accurate:true redeem_script

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
        (* Bitcoin Core GetScriptOp clears pvchRet at the top of every call and only
           refills it for opcodes <= OP_PUSHDATA4 (0x4e).  Opcodes outside that range
           leave vData EMPTY.  GetSigOpCount(scriptSig) also returns 0 immediately for
           any opcode above OP_16 (0x60).  Mirror both rules here:
           - opcode > OP_16 (0x61+): signal "return 0 sigops" by setting last := None
             and breaking out of the loop.
           - OP_0 (0x00), OP_1NEGATE (0x4f), OP_RESERVED (0x50), OP_1..OP_16 (0x51..0x60):
             Core clears vData → empty redeemScript → 0 sigops; mirror with empty Cstruct. *)
        if opcode > 0x60 then begin
          last := None;
          i := len  (* Break: opcode > OP_16, Core returns 0 immediately *)
        end else begin
          (* OP_0 (0x00) or OP_1NEGATE..OP_16 (0x4f..0x60): empty vData in Core *)
          last := Some (Cstruct.create 0);
          i := !i + 1
        end
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

(* Verify the witness commitment in a block.
   Mirrors Bitcoin Core's CheckWitnessMalleation (validation.cpp:3870-3916).

   When segwit_active=true (expect_witness_commitment in Core):
     - Find the LAST coinbase output whose scriptPubKey starts with
       OP_RETURN 0x24 0xaa 0x21 0xa9 0xed and is >= 38 bytes.
     - If found:
         - coinbase scriptWitness must be exactly 1 stack item of 32 bytes
           (the witness reserved value / nonce).  Fail with
           BlockBadWitnessNonceSize otherwise.  [Core: bad-witness-nonce-size]
         - SHA256d(witness_merkle_root || nonce) must equal the 32 bytes at
           scriptPubKey[6..38].  Fail with BlockBadWitnessCommitment otherwise.
           [Core: bad-witness-merkle-match]
     - If not found: fall through to unexpected-witness check.

   When segwit_active=false (pre-segwit block):
     - Skip the commitment check entirely (no commitment is required).
     - Still reject any block that contains witness data.
       [Core: unexpected-witness]

   Reference: bitcoin-core/src/consensus/validation.h:147-165
              bitcoin-core/src/validation.cpp:3870-3916 *)
let check_witness_commitment ~(segwit_active : bool) (block : Types.block)
    : (unit, block_validation_error) result =
  let coinbase = List.hd block.transactions in
  if segwit_active then begin
    match find_witness_commitment coinbase with
    | Some commitment ->
      (* Gate 10: coinbase scriptWitness[0] must be exactly 1 item of 32 bytes.
         Core: validation.cpp:3880-3885 (bad-witness-nonce-size) *)
      let witness_nonce =
        match coinbase.witnesses with
        | [] -> None
        | w :: _ ->
          match w.Types.items with
          | [item] when Cstruct.length item = 32 -> Some item
          | _ -> None
      in
      (match witness_nonce with
      | None -> Error BlockBadWitnessNonceSize
      | Some nonce ->
        (* Gate 11: SHA256d(witness_merkle_root || nonce) must match commitment.
           Core: validation.cpp:3890-3898 (bad-witness-merkle-match) *)
        let witness_root = compute_witness_merkle_root block.transactions in
        let combined = Cstruct.concat [witness_root; nonce] in
        let expected = Crypto.sha256d combined in
        if Cstruct.equal expected commitment then
          Ok ()
        else
          Error BlockBadWitnessCommitment)
    | None ->
      (* Gate 12: segwit active, no commitment → reject if any tx has witness.
         Core: validation.cpp:3905-3913 (unexpected-witness) *)
      if block_has_witness block then
        Error BlockUnexpectedWitness
      else
        Ok ()
  end else begin
    (* Pre-segwit: commitment check skipped entirely.
       Only check for unexpected witness data.
       Core: CheckWitnessMalleation with expect_witness_commitment=false,
             validation.cpp:3905-3913 *)
    if block_has_witness block then
      Error BlockUnexpectedWitness
    else
      Ok ()
  end

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

(* ============================================================================
   Transaction Finality Checks (IsFinalTx)
   Placed here (before check_block) because check_block calls is_tx_final.
   ============================================================================ *)

(* Check if transaction is final based on locktime and sequences.
   Locktime is unsigned 32-bit: values < 500_000_000 are block heights,
   values >= 500_000_000 are Unix timestamps.
   Reference: Bitcoin Core consensus/tx_verify.cpp:17-37 IsFinalTx()
   Core semantics: nLockTime is the *last invalid* height/time, so a tx
   becomes final when block_height/time STRICTLY EXCEEDS nLockTime.
   i.e. return true when (int64_t)tx.nLockTime < nBlockHeight/nBlockTime.
   Bug fixed: was using >= (off-by-one), must use > (strict greater-than). *)
let is_tx_final (tx : Types.transaction) ~(block_height : int) ~(block_time : int32)
    : bool =
  if tx.locktime = 0l then
    true
  else begin
    (* Treat locktime as unsigned 32-bit *)
    let locktime_unsigned = Int64.logand (Int64.of_int32 tx.locktime) 0xFFFFFFFFL in
    let locktime_satisfied =
      if locktime_unsigned < 500_000_000L then
        (* Locktime is a block height: final when block_height > locktime
           (Core: nLockTime < nBlockHeight, strict less-than) *)
        Int64.of_int block_height > locktime_unsigned
      else
        (* Locktime is a unix timestamp: final when block_time > locktime
           (Core: nLockTime < nBlockTime, strict less-than) *)
        let block_time_unsigned = Int64.logand (Int64.of_int32 block_time) 0xFFFFFFFFL in
        block_time_unsigned > locktime_unsigned
    in
    if locktime_satisfied then
      true
    else begin
      (* Even if locktime not satisfied, tx is final if ALL inputs have
         nSequence == SEQUENCE_FINAL (0xffffffff), which disables locktime.
         Reference: Core tx_verify.cpp:32-36 *)
      List.for_all (fun inp ->
        Int32.equal inp.Types.sequence 0xFFFFFFFFl
      ) tx.inputs
    end
  end

(* Validate a full block (contextual + context-free checks).

   [prev_block_time]: timestamp of the previous block; used for BIP-94
   timewarp check.  Callers that don't have this (e.g. unit tests) may
   pass 0l — the check fires only when network.enforce_bip94 is true
   (testnet4) and height is a difficulty-adjustment boundary.
   Reference: bitcoin-core/src/validation.cpp ContextualCheckBlockHeader. *)
let check_block ~network:(network : Consensus.network_config) (block : Types.block) (height : int)
    ~(expected_bits : int32) ~(median_time : int32)
    ?(prev_block_time = 0l)
    ?(skip_pow = false)
    ()
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
        (* Block version enforcement after BIP activation heights.
           Reference: bitcoin-core/src/validation.cpp ContextualCheckBlockHeader:4113-4118. *)
        if height >= network.bip34_height && Int32.compare block.header.version 2l < 0 then
          Error BlockBadVersion
        else if height >= network.bip66_height && Int32.compare block.header.version 3l < 0 then
          Error BlockBadVersion
        else if height >= network.bip65_height && Int32.compare block.header.version 4l < 0 then
          Error BlockBadVersion
        else
        (* Check difficulty target.
           Reference: bitcoin-core/src/validation.cpp ContextualCheckBlockHeader:4088-4089. *)
        if block.header.bits <> expected_bits then
          Error BlockBadDifficulty
        else begin
          (* Check that block hash meets target.
             skip_pow mirrors Bitcoin Core's CheckBlock(..., fCheckPOW)
             (validation.cpp CheckBlockHeader -> CheckProofOfWork). The
             fCheckPOW parameter defaults true (PoW enforced); a false value
             skips ONLY the proof-of-work hash<=target test (the
             expected_bits/difficulty-target equality check above is the
             ContextualCheckBlockHeader rule and is NOT gated by fCheckPOW).
             Default skip_pow=false preserves current behavior for all
             existing callers. *)
          let block_hash = Crypto.compute_block_hash block.header in
          if (not skip_pow)
             && not (Consensus.hash_meets_target block_hash block.header.bits) then
            Error BlockBadDifficulty
          else begin
            (* Check timestamp is after median time past (time-too-old).
               Core treats nTime as uint32_t; widen both sides to unsigned int64
               before comparing so post-2038 timestamps (>= 0x80000000, negative in
               OCaml int32) sort after past MTP values, matching Core's int64_t cast.
               Reference: bitcoin-core/src/validation.cpp ContextualCheckBlockHeader:4092-4093;
                          bitcoin-core/src/chain.h:221 (GetBlockTime returns (int64_t)nTime). *)
            let u32 x = Int64.logand (Int64.of_int32 x) 0xFFFFFFFFL in
            if Int64.compare (u32 block.header.timestamp) (u32 median_time) <= 0 then
              Error BlockBadTimestamp
            (* BIP-94 timewarp protection: at difficulty-adjustment boundaries the new
               block's timestamp must not predate the previous block's by more than
               MAX_TIMEWARP=600 seconds.
               Reference: bitcoin-core/src/validation.cpp ContextualCheckBlockHeader:4097-4104. *)
            else if not (Consensus.check_timewarp_rule
                           ~height
                           ~header_time:block.header.timestamp
                           ~prev_block_time
                           ~network) then
              Error BlockTimeWarpAttack
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
                  (* Check total block weight. Bitcoin Core's GetBlockWeight
                     (consensus/validation.h) is the weight of the WHOLE
                     serialized block: the 80-byte header and the CompactSize
                     tx-count count at the full WITNESS_SCALE_FACTOR on top of
                     the per-tx weights. See compute_block_weight. *)
                  let total_weight = compute_block_weight txs in
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
                        (* Task 6: Verify witness commitment.
                           Gate on segwit activation height, matching Core's
                           CheckWitnessMalleation(expect_witness_commitment=
                             DeploymentActiveAfter(..., DEPLOYMENT_SEGWIT))
                           in ContextualCheckBlock, validation.cpp:4169. *)
                        let segwit_active = height >= network.segwit_height in
                        match check_witness_commitment ~segwit_active block with
                        | Error e -> Error e
                        | Ok () ->
                          (* Task 7: ContextualCheckBlock — IsFinalTx for every tx.
                             Bitcoin Core validation.cpp:4146 enforces this even when
                             scripts are skipped (assumevalid only skips script verify).
                             lock_time_cutoff = median_time when BIP-113/CSV is active
                             (height >= csv_height), else block header timestamp.
                             Reference: bitcoin-core/src/consensus/tx_verify.cpp IsFinalTx
                                        BIP-113 (median-time-past locktime) *)
                          let csv_active = height >= network.csv_height in
                          let lock_time_cutoff =
                            if csv_active then median_time
                            else block.header.timestamp
                          in
                          let error2 = ref None in
                          List.iteri (fun i tx ->
                            if !error2 = None then begin
                              (* 6D: IsFinalTx applies to ALL transactions including the
                                 coinbase (i=0). Bitcoin Core validation.cpp:4144-4148 loops
                                 ALL block.vtx with no coinbase exemption. A coinbase with
                                 a non-zero nLockTime and a non-SEQUENCE_FINAL input is
                                 non-final and must be rejected. *)
                              if not (is_tx_final tx ~block_height:height ~block_time:lock_time_cutoff) then
                                error2 := Some (BlockTxValidationFailed (i, TxNonFinalLocktime))
                            end
                          ) txs;
                          (match !error2 with
                           | Some e -> Error e
                           | None ->
                          (* Coinbase value check is deferred to
                             validate_block_with_utxos which has UTXO context
                             to compute actual fees. Without knowing fees, any
                             check here would either be too strict (rejecting
                             valid blocks) or too loose to be useful. *)
                          Ok ())
                    end
                  end
              end
            end  (* closes else begin after timewarp check *)
          end
        end
    end
  end

(* ============================================================================
   Context-Free Block Header Validation
   ============================================================================ *)

(* Check block header without full chain context.

   [current_time] injects the adjusted-network-time "now" the time-too-new gate
   measures against (Core ContextualCheckBlockHeader:4108, against
   GetAdjustedTime()). It is an [int32 option]:
     - None    (the DEFAULT, every existing production caller) — use the wall
               clock (Unix.time ()), byte-identical to the original behavior.
     - Some 0l (harness sentinel) — DISABLE the time-too-new gate (vector is
               not exercising it), matching the rustoshi/blockbrew header
               differential contract.
     - Some t  (t<>0l) — measure against the deterministic injected clock t.
   Default-preserving: with the argument omitted the branch below is exactly
   the prior `Int32.add (Int32.of_float (Unix.time ())) 7200l` test.
   Reference: bitcoin-core/src/validation.cpp ContextualCheckBlockHeader:4108
   (block.GetBlockTime() > now + MAX_FUTURE_BLOCK_TIME). *)
let check_block_header ?(current_time : int32 option)
    ?(network : Consensus.network_config option) (header : Types.block_header)
    : (unit, string) result =
  (* Check that timestamp is not too far in the future. *)
  (* Widen timestamps to unsigned int64 before comparing, matching Core's
     (int64_t)nTime semantics (block.Time() is std::chrono derived from uint32_t nTime).
     OCaml int32 is signed, so timestamps >= 0x80000000 (post-2038) appear negative
     and would slip past a signed > check even when they are far in the future.
     Reference: bitcoin-core/src/validation.cpp:4108 (block.Time() vs NodeClock::now()). *)
  let u32 x = Int64.logand (Int64.of_int32 x) 0xFFFFFFFFL in
  let future_violation =
    match current_time with
    | None ->
        (* Production default: wall clock. *)
        let max_future_time = Int64.add (Int64.of_float (Unix.time ())) 7200L in
        Int64.compare (u32 header.timestamp) max_future_time > 0
    | Some 0l ->
        (* Harness sentinel: time-too-new disabled. *)
        false
    | Some now ->
        (* Deterministic injected clock. *)
        let max_future_time = Int64.add (u32 now) 7200L in
        Int64.compare (u32 header.timestamp) max_future_time > 0
  in
  if future_violation then
    Error "Block timestamp too far in future"
  else begin
    (* Check proof of work.
       When [network] is provided, use check_proof_of_work which enforces the full
       DeriveTarget validation from Bitcoin Core pow.cpp:146-170:
         - negative nBits (sign bit set with non-zero mantissa)
         - overflow nBits (target would exceed 2^256)
         - zero target
         - target above pow_limit
       When [network] is absent (legacy callers), fall back to hash_meets_target
       which only checks hash <= target without validating nBits bounds. *)
    let block_hash = Crypto.compute_block_hash header in
    let pow_ok = match network with
      | None -> Consensus.hash_meets_target block_hash header.bits
      | Some n -> Consensus.check_proof_of_work block_hash header.bits n
    in
    if not pow_ok then
      Error "Block does not meet difficulty target"
    else
      Ok ()
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

(* BIP-68 applies only when version >= 2. Core stores version as uint32_t and
   compares it UNSIGNED (fEnforceBIP68 = tx.version >= 2, tx_verify.cpp:51), so a
   high-bit version (e.g. 0x80000002) STILL enforces BIP-68. OCaml Int32 is signed
   (0x80000002 parses to a negative int32), so a signed compare would treat it as
   < 2 and SKIP enforcement, false-accepting a tx with an unmet relative timelock
   (a chain split). Mask to the unsigned 32-bit value before comparing -- same as
   the OP_CSV path (script.ml:2348). *)
let bip68_version_active (version : int32) : bool =
  Int64.logand (Int64.of_int32 version) 0xFFFFFFFFL >= 2L

let check_sequence_locks (tx : Types.transaction) ~(block_height : int)
    ~(median_time : int32) ~(utxo_heights : int array) ~(utxo_mtps : int32 array)
    ?(get_mtp_at_height : (int -> int32) option) ~flags () : bool =
  if not (bip68_version_active tx.version) then true
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
            (* Time-based lock.
               Use Int64 arithmetic throughout to match Bitcoin Core's int64_t
               in CalculateSequenceLocks (tx_verify.cpp:88):
                 nMinTime = max(nMinTime,
                   nCoinTime + (int64_t)((seq & MASK) << GRANULARITY) - 1)
               then EvaluateSequenceLocks checks nMinTime >= nBlockTime.
               Int32 would overflow for large timestamps + offsets. *)
            let input_mtp = match get_mtp_at_height with
              | Some f -> f (max 0 (utxo_heights.(i) - 1))
              | None -> utxo_mtps.(i)
            in
            let input_mtp64 = Int64.logand (Int64.of_int32 input_mtp) 0xFFFFFFFFL in
            let median_time64 = Int64.logand (Int64.of_int32 median_time) 0xFFFFFFFFL in
            let time_offset64 = Int64.of_int (masked lsl 9) in
            (* Core semantics: required = nCoinTime + offset - 1; fail if block_mtp <= required,
               i.e. fail if median_time64 < input_mtp64 + time_offset64 *)
            let required_time64 = Int64.add input_mtp64 time_offset64 in
            if Int64.compare median_time64 required_time64 < 0 then
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

              (* Compute wtxid for cache key.
                 W159 BUG-17 / W160 BUG-1: must use witness-covering wtxid,
                 NOT no-witness txid, otherwise SegWit malleation can poison
                 the cache (two txs with same txid but different witness
                 cache-hit each other, accepting an invalid witness via the
                 cached "true" → chain-split vs Core). *)
              let wtxid = Crypto.compute_wtxid tx in
              let cache_key : Sig_cache.cache_key = {
                wtxid;
                input_index = i;
                flags;
              } in

              (* Check sig cache first *)
              let cache = Sig_cache.get_global () in
              match Sig_cache.lookup cache cache_key with
              | Some true ->
                (* Cache hit: verification already succeeded *)
                ()
              | _ ->
                (* Cache miss: run verification *)
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
                | Ok true ->
                  (* Cache successful verification *)
                  Sig_cache.insert cache cache_key true
            end
        end
      ) tx.inputs;

      match !error with
      | Some e -> Error e
      | None -> Ok !total_in
  end

(* ============================================================================
   Parallel Script Verification (OCaml 5 Domain-based)
   ============================================================================ *)

(* Minimum inputs per block for parallel execution.
   Below this threshold the Domain spawn overhead exceeds the benefit. *)
let min_inputs_for_parallel = 16

(* Mutex protecting all sig-cache reads and writes.
   OCaml 5 Hashtbl is NOT Domain-safe; we serialise access around a single
   Mutex so that cache lookups from worker domains do not race with inserts
   from the main domain.  The critical section is short (hash lookup / insert)
   so contention is negligible compared to secp256k1 verification. *)
let sig_cache_mutex : Mutex.t = Mutex.create ()

(* Thread-safe sig-cache lookup.  Returns Some true if cached, None otherwise. *)
let cache_lookup (cache : Sig_cache.t) (key : Sig_cache.cache_key) : bool option =
  Mutex.lock sig_cache_mutex;
  let r = Sig_cache.lookup cache key in
  Mutex.unlock sig_cache_mutex;
  r

(* Thread-safe sig-cache insert (only called for successful verifications). *)
let cache_insert (cache : Sig_cache.t) (key : Sig_cache.cache_key) (v : bool) : unit =
  Mutex.lock sig_cache_mutex;
  Sig_cache.insert cache key v;
  Mutex.unlock sig_cache_mutex

(* Thread-safe global sig-cache clear (called on reorg by sync.ml).
   W165 (un-pin deep fix): with the at-tip mempool-verify pool
   (Mempool_verify_pool, below) verification now runs on worker Domains
   ASYNCHRONOUSLY with respect to the block/reorg path — a reorg that clears
   the cache can race a worker's cache_insert.  Both the sig-cache result and
   the eviction are deterministic per (wtxid,input_index,flags), so the only
   real hazard is the Hashtbl STRUCTURAL race (clear vs insert mutating the
   same table).  Routing clear through sig_cache_mutex closes it.  Cost is one
   uncontended lock on the reorg path (rare). *)
let cache_clear_global () : unit =
  Mutex.lock sig_cache_mutex;
  Sig_cache.clear_global ();
  Mutex.unlock sig_cache_mutex

(* Verify a single input.  Returns Ok () on success, Error (index, msg) on
   failure.  Safe to call from any Domain — sig-cache access is serialised.

   W159 BUG-17 / W160 BUG-1: cache key uses wtxid (witness-covering),
   NOT txid (no-witness), to prevent SegWit-malleability cache poisoning. *)
let verify_one_input
    ~(tx : Types.transaction) ~(flags : int)
    ~(prevouts : (int64 * Cstruct.t) list)
    ~(wtxid : Types.hash256)
    ~(cache : Sig_cache.t)
    (i : int) (inp : Types.tx_in) (utxo : utxo)
    : (unit, int * string) result =
  let witness =
    if i < List.length tx.witnesses then List.nth tx.witnesses i
    else { Types.items = [] }
  in
  let cache_key : Sig_cache.cache_key = { wtxid; input_index = i; flags } in
  match cache_lookup cache cache_key with
  | Some true -> Ok ()
  | _ ->
    (match Script.verify_script
             ~tx ~input_index:i
             ~script_pubkey:utxo.script_pubkey
             ~script_sig:inp.Types.script_sig
             ~witness
             ~amount:utxo.value
             ~flags ~prevouts () with
    | Error msg -> Error (i, msg)
    | Ok false -> Error (i, "Script returned false")
    | Ok true ->
      cache_insert cache cache_key true;
      Ok ())

(* Verify a slice of (index, input, utxo) triples in the current domain.
   Returns the first error encountered, or Ok (). *)
let verify_input_slice
    ~(tx : Types.transaction) ~(flags : int)
    ~(prevouts : (int64 * Cstruct.t) list)
    ~(wtxid : Types.hash256)
    ~(cache : Sig_cache.t)
    (tasks : (int * Types.tx_in * utxo) list)
    : (unit, int * string) result =
  List.fold_left (fun acc (i, inp, utxo) ->
    match acc with
    | Error _ as e -> e
    | Ok () -> verify_one_input ~tx ~flags ~prevouts ~wtxid ~cache i inp utxo
  ) (Ok ()) tasks

(* ----------------------------------------------------------------------------
   W143: Persistent IBD-scoped script-check worker pool.

   Reference: Bitcoin Core's CCheckQueue (src/checkqueue.h) — a fixed-size
   thread pool created ONCE for the lifetime of the chainstate, fed batches of
   CScriptCheck closures, never re-spawned per transaction.

   The PRE-W143 code spawned up to recommended_domain_count()-1 (≈31) fresh
   OCaml Domains PER TRANSACTION inside verify_scripts_parallel_domain.  During
   IBD that is tens of thousands of Domain spawn/join cycles per block — the
   spawn/join overhead dwarfs the secp256k1 work (~0 blk/s) and every Domain
   reserves a minor-heap arena (~111 GB RSS).  Core never does this: it has one
   pool with at most MAX_SCRIPTCHECK_THREADS=15 workers (validation.h:90).

   This pool replaces the per-call spawn with submission to a persistent,
   fixed-size, generation-barrier parallel-map pool (hand-rolled on Mutex +
   Condition — Domainslib is intentionally NOT a dependency of this sensitive
   node).  It processes ONE batch at a time: verify_scripts_parallel_domain
   submits a transaction's input slices synchronously and blocks until they all
   complete.  No two batches overlap, so a single results array + a single
   generation counter suffice.

   IBD-scoped: created in Validation_worker.create (sync.ml) when the IBD
   validation Domain starts, torn down in Validation_worker.shutdown.  When no
   pool is active (script_check_pool = None — e.g. at-tip / regtest /
   submitblock paths) verify_scripts_parallel_domain falls back to a pure
   serial in-thread fold.  This deliberately keeps idle script Domains out of
   the FullySynced at-tip path (camlcoin's documented Gc.compact thrash).
   ---------------------------------------------------------------------------- *)

(* Per-batch parameters shared with the workers.  verify_scripts_parallel_domain
   sets these under the mutex before bumping the generation, so each worker
   reads the CURRENT batch's tx/flags/prevouts/wtxid/cache for its slice. *)
type batch_params = {
  bp_tx : Types.transaction;
  bp_flags : int;
  bp_prevouts : (int64 * Cstruct.t) list;
  bp_wtxid : Types.hash256;
  bp_cache : Sig_cache.t;
}

type script_check_pool = {
  pool_mutex : Mutex.t;
  work_cond : Condition.t;   (* workers wait here for a new generation *)
  done_cond : Condition.t;   (* submitter waits here for pending = 0 *)
  (* #8 at-tip block-connect offload: the pool is now live at tip (small,
     bounded) as well as during IBD.  During IBD the sole submitter is the IBD
     validation Domain; at tip the sole submitter is the post-IBD block-connect
     Domain (the mempool path stays serial — verify_scripts_parallel passes
     ~use_pool:false).  submit_mutex serialises whole batches so that ANY future
     concurrent submitter (e.g. a reorg path) cannot clobber the single shared
     slices/results/params/generation state mid-batch.  Held across the entire
     pool_submit (including the done_cond wait); uncontended in the
     single-submitter case ⇒ zero behaviour change for the proven IBD path. *)
  submit_mutex : Mutex.t;
  nworkers : int;            (* 0 ⇒ serial-in-thread submit (no Domains) *)
  (* Per-worker slices for the current batch; index = worker id. *)
  mutable slices : (int * Types.tx_in * utxo) list array;
  (* Per-worker result for the current batch. *)
  mutable results : (unit, int * string) result array;
  (* Current batch parameters (None between batches). *)
  mutable params : batch_params option;
  mutable generation : int;  (* bumped once per submitted batch *)
  mutable pending : int;     (* workers still to finish this batch *)
  mutable shutdown : bool;
  mutable workers : unit Domain.t array;
}

(* Worker loop: each worker services slices.(my_index) for every generation it
   has not yet serviced.  Bookkeeping is under the mutex; the expensive
   verify_input_slice runs OUTSIDE the mutex. *)
let pool_worker_loop (pool : script_check_pool) (my_index : int) : unit =
  let last_serviced = ref 0 in
  let continue = ref true in
  while !continue do
    Mutex.lock pool.pool_mutex;
    (* Wait until either shutdown or a new generation appears.  Guard against
       spurious wakeups by re-checking the predicate in the while condition. *)
    while (not pool.shutdown) && pool.generation = !last_serviced do
      Condition.wait pool.work_cond pool.pool_mutex
    done;
    if pool.shutdown then begin
      Mutex.unlock pool.pool_mutex;
      continue := false
    end else begin
      let gen = pool.generation in
      let slice = pool.slices.(my_index) in
      let params = match pool.params with
        | Some p -> p
        | None -> assert false   (* generation advanced ⇒ params set *)
      in
      Mutex.unlock pool.pool_mutex;
      (* Run the slice outside the lock — this is the expensive part. *)
      let r =
        try
          verify_input_slice
            ~tx:params.bp_tx ~flags:params.bp_flags
            ~prevouts:params.bp_prevouts ~wtxid:params.bp_wtxid
            ~cache:params.bp_cache slice
        with e ->
          (* Never let a worker exception deadlock the submitter: surface it as
             an Error so pending still reaches 0.  Index -1 marks "no specific
             input" (the submitter's first-error scan still reports it). *)
          Error (-1, Printexc.to_string e)
      in
      Mutex.lock pool.pool_mutex;
      pool.results.(my_index) <- r;
      pool.pending <- pool.pending - 1;
      last_serviced := gen;
      if pool.pending = 0 then Condition.signal pool.done_cond;
      Mutex.unlock pool.pool_mutex
    end
  done

(* Partition [tasks] into [n] near-even contiguous slices (slice i gets every
   item; sizes differ by at most 1).  Deterministic worker-index order: slice 0
   holds the lowest input indices, matching a pure serial left-to-right fold. *)
let partition_tasks (tasks : (int * Types.tx_in * utxo) list) (n : int)
    : (int * Types.tx_in * utxo) list array =
  let arr = Array.of_list tasks in
  let total = Array.length arr in
  let base = total / n in
  let rem = total mod n in
  let slices = Array.make n [] in
  let pos = ref 0 in
  for i = 0 to n - 1 do
    let len = base + (if i < rem then 1 else 0) in
    slices.(i) <- Array.to_list (Array.sub arr !pos len);
    pos := !pos + len
  done;
  slices

(* Submit one batch synchronously and return its first error (deterministic:
   scanned in worker-index then in-slice order, identical to a serial fold). *)
let pool_submit (pool : script_check_pool)
    (tx : Types.transaction) (flags : int)
    (prevouts : (int64 * Cstruct.t) list)
    (wtxid : Types.hash256) (cache : Sig_cache.t)
    (tasks : (int * Types.tx_in * utxo) list)
    : (unit, int * string) result =
  if pool.nworkers = 0 then
    (* No Domains: run the whole batch serially in the calling thread. *)
    verify_input_slice ~tx ~flags ~prevouts ~wtxid ~cache tasks
  else begin
    (* Serialise the whole batch: only ONE submitter may drive the shared
       slices/results/params/generation state at a time.  Held across the
       done_cond wait below (which releases only pool_mutex, not submit_mutex),
       so a second submitter blocks here until this batch fully completes. *)
    Mutex.lock pool.submit_mutex;
    Fun.protect
      ~finally:(fun () ->
        (* G18: guarantee params is cleared even if the batch body raised, so a
           raised submit cannot pin the batch's tx.  Done HERE (still holding
           submit_mutex) so it is serialised against other submitters and can
           never nil a concurrent batch's params.  On the normal path params was
           already set to None below (redundant, harmless). *)
        Mutex.lock pool.pool_mutex;
        pool.params <- None;
        Mutex.unlock pool.pool_mutex;
        Mutex.unlock pool.submit_mutex)
      (fun () ->
    let params = {
      bp_tx = tx; bp_flags = flags; bp_prevouts = prevouts;
      bp_wtxid = wtxid; bp_cache = cache;
    } in
    let slices = partition_tasks tasks pool.nworkers in
    Mutex.lock pool.pool_mutex;
    pool.slices <- slices;
    pool.results <- Array.make pool.nworkers (Ok ());
    pool.params <- Some params;
    pool.pending <- pool.nworkers;
    pool.generation <- pool.generation + 1;
    Condition.broadcast pool.work_cond;
    while pool.pending > 0 do
      Condition.wait pool.done_cond pool.pool_mutex
    done;
    (* Snapshot results before releasing the lock; clear params so a leaked
       reference cannot pin the batch's tx/prevouts. *)
    let results = Array.copy pool.results in
    pool.params <- None;
    Mutex.unlock pool.pool_mutex;
    (* First error in deterministic order (worker-index then in-slice, which is
       input-index order because partition_tasks keeps slices contiguous). *)
    let rec scan i =
      if i >= Array.length results then Ok ()
      else match results.(i) with
        | Error _ as e -> e
        | Ok () -> scan (i + 1)
    in
    scan 0)
  end

(* Create the worker pool.  nworkers = min(recommended-1, max_workers) clamped
   at >= 0, mirroring Core MAX_SCRIPTCHECK_THREADS (validation.h:90).
   [max_workers] defaults to 15 (the IBD full pool); the #8 at-tip block-connect
   pool passes a small cap (4) so the FullySynced steady state carries only a
   handful of parked worker Domains (see Validation_worker.ensure_tip_script_pool
   in sync.ml).  nworkers = 0 yields a pool whose submit runs serially in-thread
   (no Domains) — for tiny machines / regtest. *)
let create_pool ?(max_workers = 15) () : script_check_pool =
  let nworkers = max 0 (min (Domain.recommended_domain_count () - 1) max_workers) in
  let pool = {
    pool_mutex = Mutex.create ();
    work_cond = Condition.create ();
    done_cond = Condition.create ();
    submit_mutex = Mutex.create ();
    nworkers;
    slices = [||];
    results = [||];
    params = None;
    generation = 0;
    pending = 0;
    shutdown = false;
    workers = [||];
  } in
  if nworkers > 0 then
    pool.workers <- Array.init nworkers (fun i ->
      Domain.spawn (fun () -> pool_worker_loop pool i));
  pool

(* Tear down the pool: signal shutdown, wake all workers, join them. *)
let shutdown_pool (pool : script_check_pool) : unit =
  Mutex.lock pool.pool_mutex;
  pool.shutdown <- true;
  Condition.broadcast pool.work_cond;
  Mutex.unlock pool.pool_mutex;
  Array.iter Domain.join pool.workers;
  pool.workers <- [||]

(* Global handle for the active IBD-scoped pool.
   None ⇒ no pool active ⇒ verify_scripts_parallel_domain uses serial fallback
   (at-tip / not-IBD / submitblock / regtest / tests). *)
let script_check_pool : script_check_pool option ref = ref None

(* Verify all inputs of a transaction.
   Reference: Bitcoin Core's CCheckQueue (src/checkqueue.h) which distributes
   CScriptCheck jobs across N-1 worker threads + the master thread.

   W143: the per-tx Domain.spawn/join was replaced by submission to the
   persistent IBD-scoped script_check_pool.  No code path spawns a Domain per
   transaction anymore.  The accept/reject DECISION is identical to the old
   per-tx-spawn code and to a pure serial fold: the FIRST error (deterministic,
   in input-index order), else Ok ().

   UTXO apply (the caller's responsibility) must complete in tx order before
   this function is called — scripts are checked after the UTXO is committed,
   matching Bitcoin Core's ConnectBlock() ordering.

   Sig-cache reads/inserts are serialised via sig_cache_mutex to prevent
   data races on the underlying Hashtbl. *)
let verify_scripts_parallel_domain
    ?(use_pool = true)
    ~(tx : Types.transaction) ~(flags : int)
    ~(prevouts : (int64 * Cstruct.t) list)
    ~(utxos : utxo option array)
    ()
    : (unit, tx_validation_error) result =
  (* Build task list, propagating any missing-input errors immediately. *)
  let tasks_or_error =
    List.fold_right (fun (i, inp) acc ->
      match acc with
      | Error _ as e -> e
      | Ok ts ->
        (match utxos.(i) with
         | None -> Error (TxScriptFailed (i, "missing input"))
         | Some utxo -> Ok ((i, inp, utxo) :: ts))
    ) (List.mapi (fun i inp -> (i, inp)) tx.inputs) (Ok [])
  in
  match tasks_or_error with
  | Error e -> Error e
  | Ok tasks ->
    let ntasks = List.length tasks in
    if ntasks = 0 then Ok ()
    else begin
      (* W159 BUG-17 / W160 BUG-1: cache key must use wtxid (witness-covering)
         to prevent SegWit-malleability cache poisoning across parallel
         workers (the cache is global; the malleated tx's wtxid differs
         from the canonical tx's wtxid → cache miss → re-verify → reject). *)
      let wtxid = Crypto.compute_wtxid tx in
      let cache = Sig_cache.get_global () in
      (* Decide serial-in-thread vs pool submission.  USE the previously-dead
         min_inputs_for_parallel threshold (fixes audit G3): below it the pool
         hand-off costs more than the saved secp256k1 work.  Also fall back to
         serial when no pool is active (at-tip / not-IBD / nworkers=0). *)
      let result =
        match (if use_pool then !script_check_pool else None) with
        | Some pool when ntasks >= min_inputs_for_parallel && pool.nworkers > 0 ->
          (* G18 exception-safety (clearing pool.params so a raised submit cannot
             pin the batch's tx) lives INSIDE pool_submit's own submit_mutex-
             protected finaliser.  It MUST NOT be done here: an outer clear runs
             AFTER pool_submit has released submit_mutex, so with a concurrent
             submitter it would nil the params of the NEXT batch mid-flight — a
             worker of that batch then reads params=None ⇒ assert false ⇒ worker
             Domain dies ⇒ permanent deadlock (pending never reaches 0).  This
             was latent under the single IBD submitter; the #8 at-tip pool with a
             concurrent path (or back-to-back tip submits) exposes it. *)
          pool_submit pool tx flags prevouts wtxid cache tasks
        | _ ->
          (* Serial fallback — no Domains spawned. *)
          verify_input_slice ~tx ~flags ~prevouts ~wtxid ~cache tasks
      in
      match result with
      | Ok () -> Ok ()
      | Error (idx, msg) -> Error (TxScriptFailed (idx, msg))
    end

(* ============================================================================
   W165 UN-PIN DEEP FIX — at-tip mempool-verify Domain pool
   ============================================================================
   Root cause of the camlcoin un-pin blocker (elimination ladder: NOT reads
   [#6], NOT STW Gc.compact [#7], IS single-domain accept serialization):
   at tip the IBD [script_check_pool] is torn down (Sync.Validation_worker.
   stop_script_pool), so [verify_scripts_parallel] below used to run
   [verify_scripts_parallel_domain] INLINE on the Lwt main thread (serial
   fold, no Domains).  Per-input ECDSA/Schnorr/witness verification is the
   CPU-heavy part; running it on the Lwt/RPC domain blocks the Cohttp RPC
   callback (another promise on the same domain) for the whole verify, so a
   sustained mempool flood wedges getblockcount to 60s (soak #4/#7).

   Fix: a persistent pool of N worker Domains that verify whole transactions
   OFF the Lwt main thread.  The Lwt wrapper submits an IMMUTABLE job to the
   pool and awaits the result via [Lwt_preemptive.detach], so the Lwt
   scheduler PARKS (releasing domain-0's runtime lock) and keeps servicing
   RPC while the worker Domain — its OWN domain, its OWN runtime lock — runs
   secp256k1 in true parallel.  Mirrors the already-proven
   Sync.Validation_worker pattern (Lwt_preemptive.detach put/take around a
   Domain), specialised for per-tx script verification.

   Correctness / race-freedom:
   - Jobs carry only immutable copies (tx, flags, prevouts list, utxos array)
     built by the caller BEFORE submission; workers never touch live
     UTXO/mempool state.  TOCTOU is handled by the sync ATMP body re-reading
     lookup_utxo after verify (mempool.ml accept_transaction_with_replaced_lwt
     comment) — UTXOs only disappear, never change, so the worst case is a
     redundant verify + a clean reject, never a false-accept.
   - Sig-cache access is serialised via sig_cache_mutex (cache_lookup /
     cache_insert / cache_clear_global).
   - secp256k1 uses a single static context that is const after a one-time
     init; concurrent verify is thread-safe.  We WARM it on the main thread
     before spawning workers so the assumeUTXO-start path (which may reach tip
     without IBD-replay verification) cannot hit the lazy-init race.
   - Each job has a private result slot (Mutex+Condition); the shared work
     queue is Mutex+Condition protected.  N workers verify N distinct txs
     concurrently — no per-tx shared mutable state.
   - Domains are spawned LAZILY on first at-tip accept — i.e. after
     daemonize + Lwt_main.run — never before the fork (Domain.spawn before a
     fork would be lost).

   Bound: CAMLCOIN_VERIFY_WORKERS (default 3; 0 disables the pool and restores
   the previous inline behaviour — the safe revert lever). *)
module Mempool_verify_pool = struct
  type job = {
    j_tx : Types.transaction;
    j_flags : int;
    j_prevouts : (int64 * Cstruct.t) list;
    j_utxos : utxo option array;
    j_mutex : Mutex.t;
    j_cond : Condition.t;
    mutable j_result : (unit, tx_validation_error) result option;
  }

  type t = {
    q_mutex : Mutex.t;
    q_cond : Condition.t;               (* workers wait for a non-empty queue *)
    q : job Queue.t;
    mutable shutdown : bool;
    mutable workers : unit Domain.t array;
  }

  (* Worker loop: pop a job, verify it wholly on THIS Domain (off the Lwt main
     thread), publish the result.  ~use_pool:false: THIS worker Domain IS the
     mempool parallelism (one whole tx per worker) — it must verify its tx's
     inputs serially in-thread and must NOT re-dispatch into the #8 at-tip
     block-connect [script_check_pool] (which is now live at tip).  That keeps
     the mempool path fully decoupled from the block pool and leaves the block
     pool with a single submitter (the post-IBD block-connect Domain). *)
  let worker_loop (t : t) : unit =
    let rec loop () =
      Mutex.lock t.q_mutex;
      while (not t.shutdown) && Queue.is_empty t.q do
        Condition.wait t.q_cond t.q_mutex
      done;
      if t.shutdown && Queue.is_empty t.q then
        Mutex.unlock t.q_mutex
      else begin
        let job = Queue.pop t.q in
        Mutex.unlock t.q_mutex;
        let r =
          try
            verify_scripts_parallel_domain
              ~use_pool:false
              ~tx:job.j_tx ~flags:job.j_flags
              ~prevouts:job.j_prevouts ~utxos:job.j_utxos ()
          with e ->
            Error (TxScriptFailed (-1, Printexc.to_string e))
        in
        Mutex.lock job.j_mutex;
        job.j_result <- Some r;
        Condition.broadcast job.j_cond;
        Mutex.unlock job.j_mutex;
        loop ()
      end
    in
    loop ()

  let create (nworkers : int) : t =
    (* Warm the single static secp256k1 context on THIS (main) thread before
       spawning workers, so the first concurrent verify cannot race the lazy
       ensure_ctx() init.  Crypto.verify swallows all exceptions internally. *)
    (try
       ignore (Crypto.verify (Cstruct.create 33) (Cstruct.create 32)
                 (Cstruct.create 64))
     with _ -> ());
    let t = {
      q_mutex = Mutex.create ();
      q_cond = Condition.create ();
      q = Queue.create ();
      shutdown = false;
      workers = [||];
    } in
    t.workers <- Array.init nworkers (fun _ ->
      Domain.spawn (fun () -> worker_loop t));
    t

  (* Enqueue a job and block the CALLING (Lwt_preemptive) systhread until the
     result is ready.  Never called on the Lwt main thread directly — always
     wrapped in Lwt_preemptive.detach by verify_scripts_parallel. *)
  let submit_blocking (t : t)
      ~(tx : Types.transaction) ~(flags : int)
      ~(prevouts : (int64 * Cstruct.t) list)
      ~(utxos : utxo option array)
      : (unit, tx_validation_error) result =
    let job = {
      j_tx = tx; j_flags = flags; j_prevouts = prevouts; j_utxos = utxos;
      j_mutex = Mutex.create (); j_cond = Condition.create (); j_result = None;
    } in
    Mutex.lock t.q_mutex;
    Queue.push job t.q;
    Condition.signal t.q_cond;
    Mutex.unlock t.q_mutex;
    Mutex.lock job.j_mutex;
    while job.j_result = None do Condition.wait job.j_cond job.j_mutex done;
    let r = match job.j_result with Some v -> v | None -> assert false in
    Mutex.unlock job.j_mutex;
    r
end

(* Number of at-tip mempool-verify worker Domains.  0 ⇒ pool disabled ⇒
   verify_scripts_parallel runs inline on the Lwt main thread (previous
   behaviour / safe revert). *)
let mempool_verify_workers : int =
  match Sys.getenv_opt "CAMLCOIN_VERIFY_WORKERS" with
  | Some s -> (try max 0 (int_of_string (String.trim s)) with _ -> 3)
  | None -> 3

let mempool_verify_pool : Mempool_verify_pool.t option ref = ref None
let mempool_verify_pool_lock : Mutex.t = Mutex.create ()

(* Lazily create the pool on first use (post-fork, post-Lwt_main.run). *)
let get_mempool_verify_pool () : Mempool_verify_pool.t option =
  if mempool_verify_workers <= 0 then None
  else match !mempool_verify_pool with
    | Some _ as p -> p
    | None ->
      Mutex.lock mempool_verify_pool_lock;
      let p = (match !mempool_verify_pool with
        | Some _ as p -> p
        | None ->
          let p = Mempool_verify_pool.create mempool_verify_workers in
          mempool_verify_pool := Some p;
          Some p) in
      Mutex.unlock mempool_verify_pool_lock;
      p

(* Lwt-compatible wrapper for at-tip mempool-accept script verification.

   W165 un-pin deep fix: when the mempool-verify pool is enabled, submit the
   (immutable) verification job to a worker Domain and await it via
   [Lwt_preemptive.detach], so the Lwt scheduler PARKS and keeps servicing RPC
   while secp256k1 runs on another Domain.  This is the fix for the at-tip
   RPC-stall un-pin blocker.  When disabled (CAMLCOIN_VERIFY_WORKERS=0) or when
   the IBD [script_check_pool] is active (in which case the Domains are already
   off the main thread inside verify_scripts_parallel_domain), fall back to the
   previous inline behaviour. *)
let verify_scripts_parallel ~(tx : Types.transaction) ~(flags : int)
    ~(prevouts : (int64 * Cstruct.t) list)
    ~(utxos : utxo option array)
    : (unit, tx_validation_error) result Lwt.t =
  match get_mempool_verify_pool () with
  | None ->
    (* Safe-revert / workers=0: inline serial on the Lwt main thread, exactly as
       before.  ~use_pool:false so it does not submit into the #8 at-tip
       block-connect [script_check_pool] (which would block the Lwt loop on the
       pool's done_cond) — preserving the documented inline-revert behaviour. *)
    Lwt.return
      (verify_scripts_parallel_domain ~use_pool:false ~tx ~flags ~prevouts ~utxos ())
  | Some pool ->
    Lwt_preemptive.detach
      (fun () ->
         Mempool_verify_pool.submit_blocking pool ~tx ~flags ~prevouts ~utxos)
      ()

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

(* Check BIP30: no unspent outputs exist with the same txid.
   We probe output indices 0 through n_outputs-1 in the UTXO set.
   Bitcoin Core validation.cpp:2468-2475 (ConnectBlock BIP30 loop). *)
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

(* Determine whether BIP-30 must be enforced for this block.
   Mirrors Bitcoin Core's logic in ConnectBlock (validation.cpp:2402-2467).

   Gate 1: IsBIP30Repeat — if this block IS one of the two historical repeat
   blocks (h=91842 or h=91880 with their specific canonical hashes), skip
   BIP-30 checking entirely.  Height-only is WRONG: any fork block at those
   heights would be incorrectly exempted.

   Gate 4: BIP34Hash skip — once we know BIP34 activated at the canonical
   BIP34Height block (verified by matching BIP34Hash), duplicate coinbases
   can no longer be created, so BIP-30 checking is redundant.  We verify
   this only when the caller passes the hash of the block at BIP34Height
   (bip34_height_hash).  Without it we conservatively enforce BIP-30.

   Gate 5: BIP34_IMPLIES_BIP30_LIMIT — at h >= 1,983,702 BIP-34 height
   encoding wraps around and could theoretically repeat pre-BIP34 heights,
   so BIP-30 checking is re-enabled regardless.

   Bitcoin Core references:
   - IsBIP30Repeat: validation.cpp:6189-6192
   - fEnforceBIP30 = !IsBIP30Repeat: validation.cpp:2402
   - BIP34Hash ancestor check: validation.cpp:2460-2462
   - BIP34_IMPLIES_BIP30_LIMIT = 1,983,702: validation.cpp:2430
   - Final gate: validation.cpp:2467 *)
let bip30_should_enforce
    ~(network : Consensus.network_config)
    ~(height : int)
    ~(block_hash : Types.hash256)
    ~(bip34_height_hash : Types.hash256 option)
    : bool =
  let bip34_implies_bip30_limit = 1983702 in

  (* Gate 1 / Gate 3: IsBIP30Repeat — exempt only the specific canonical blocks *)
  if Consensus.is_bip30_repeat height block_hash then
    false
  else
    (* Gate 4: BIP34Hash skip optimization.
       If we know the block at BIP34Height has the expected canonical hash,
       then BIP34 is truly activated on this chain and BIP-30 can be skipped
       (for heights below BIP34_IMPLIES_BIP30_LIMIT). *)
    let bip34_confirmed_on_canonical_chain =
      match (network.Consensus.bip34_hash, bip34_height_hash) with
      | (Some expected_hash, Some actual_hash) ->
        Cstruct.equal expected_hash actual_hash
      | _ -> false  (* No BIP34 hash info → cannot confirm canonical chain *)
    in
    if bip34_confirmed_on_canonical_chain
       && height >= network.Consensus.bip34_height
       && height < bip34_implies_bip30_limit then
      false  (* BIP34 active on canonical chain: skip BIP-30 for performance *)
    else if height >= network.Consensus.bip34_height
            && height < bip34_implies_bip30_limit
            && network.Consensus.bip34_hash = None then
      false  (* bip34_hash=None means BIP34 active from genesis (testnet4/regtest);
                no pre-BIP34 window exists, so BIP30 violations are impossible *)
    else
      true  (* Enforce BIP-30: either pre-BIP34, or >= BIP34_IMPLIES_BIP30_LIMIT *)

(* Validate block with full UTXO tracking

   IMPORTANT: This properly handles intra-block spending by updating
   a local UTXO view during validation.

   [bip34_height_hash]: hash of the block at [network.bip34_height] on the
   current chain, used to confirm BIP-34 is activated on the canonical chain
   (Gate 4 of BIP-30 enforcement).  Pass [Some hash] when the caller has the
   block index and can provide it; [None] causes the conservative fallback
   (BIP-30 is enforced at heights >= bip34_height on any chain). *)
let validate_block_with_utxos ~network:(network : Consensus.network_config) (block : Types.block) (height : int)
    ~(expected_bits : int32) ~(median_time : int32)
    ~(base_lookup : utxo_lookup) ~(flags : int)
    ?(skip_scripts=false) ?(skip_pow=false) ?(prev_block_time = 0l) ?get_mtp_at_height ?bip34_height_hash ()
    : ((int64 * Types.hash256 array * (Types.outpoint * utxo) list), block_validation_error) result =

  (* W93 Bug 5/6 fix: BIP-68 SequenceLocks and BIP-113 IsFinalTx are
     enforced on assumevalid (fast path) too — Bitcoin Core
     validation.cpp:2480-2482 computes nLockTimeFlags from
     DEPLOYMENT_CSV state independently of fScriptChecks.  Callers may
     pass flags=0 when [skip_scripts=true]; compute the locktime flag
     locally from network activation height so CSV-aware locktime gates
     fire on the fast path just like Core.  Reference:
     bitcoin-core/src/validation.cpp:2480-2482 (nLockTimeFlags) and
     :2549-2561 (SequenceLocks). *)
  let csv_active_at_height = height >= network.csv_height in
  let lock_time_flags =
    if csv_active_at_height
    then flags lor Script.script_verify_checksequenceverify
    else flags
  in

  (* ====================================================================
     FAST PATH: Assume-valid IBD (skip_scripts = true)
     During assume-valid IBD, we trust the block structure and scripts.
     We only need to: compute txids, verify merkle root, update UTXOs.
     This dramatically speeds up the 50-100k spam block range.
     ==================================================================== *)
  if skip_scripts then begin
    (* W93 Bug 10 fix: assumevalid only skips CScriptCheck per Bitcoin
       Core (validation.cpp:2320 calls CheckBlock unconditionally before
       the script_check_reason branch).  Pre-W93 the fast path skipped
       check_block entirely, silently bypassing every structural and
       contextual gate (version-bits, BIP-94 timewarp, witness
       commitment, max_block_weight/size, sigops upper bound, dup-txid,
       per-tx CheckTransaction, IsFinalTx) on the assumevalid IBD path.
       A malicious peer could feed structurally-invalid blocks below
       assumevalid and they would all be silently accepted, then the
       chain would diverge at the assumevalid block.

       Calling check_block here restores parity: CheckBlock runs on
       BOTH paths; only the inner script verification is skipped. *)
    match check_block ~network block height ~expected_bits ~median_time
            ~prev_block_time ~skip_pow () with
    | Error e -> Error e
    | Ok () ->
    let txs = block.transactions in
    if txs = [] then
      Error BlockEmptyTransactions
    else begin
      let n_txs = List.length txs in
      (* Fix 1: Compute txids exactly ONCE *)
      let txid_arr = Array.make n_txs Cstruct.empty in
      List.iteri (fun i tx ->
        txid_arr.(i) <- Crypto.compute_txid tx
      ) txs;

      (* Verify merkle root using pre-computed txids.
         W93 Bug 11 fix: mutated merkle (duplicate tx in tree) is a Core
         BLOCK_MUTATED outcome (validation.cpp:2321-2326) — fatal
         corruption, not just bad merkle. CheckBlock above already
         catches the mutated flag, but we keep this redundant test on
         the pre-computed txids to fail closed if the path changes. *)
      let txid_list = Array.to_list txid_arr in
      let (computed_merkle, mutated) = Crypto.merkle_root txid_list in
      if mutated then
        Error BlockMutatedMerkle
      else if not (Cstruct.equal computed_merkle block.header.merkle_root) then
        Error BlockBadMerkleRoot
      else begin
        (* Compute block hash once for BIP-30 repeat-block check.
           Uses the same header, so this is deterministic and idempotent. *)
        let block_hash_for_bip30 = Crypto.compute_block_hash block.header in

        (* Build local UTXO set for intra-block spending *)
        let local_utxos : (string * int32, utxo) Hashtbl.t = Hashtbl.create 64 in
        let spent_in_block : (string * int32, unit) Hashtbl.t = Hashtbl.create 64 in

        let total_fees = ref 0L in
        let error = ref None in
        let spent_utxos = ref [] in
        (* W93 Bug 2 fix: BIP-141 weighted sigops cost is checked on
           BOTH paths in Core (validation.cpp:2568-2572); accumulate
           on the fast path too so a malicious peer can't sneak a
           sigop-bomb block in below assumevalid. Uses the same
           overlay-aware prev_script_pubkey_lookup as the full path. *)
        let total_sigops_cost = ref 0 in

        (* ContextualCheckBlock: IsFinalTx for all txs — runs even on fast path.
           Bitcoin Core validation.cpp:4146: assumevalid only skips script
           verification; structural rules including IsFinalTx still apply.
           lock_time_cutoff uses MTP when CSV (BIP-113) is active.
           W93 Bug 6 fix: use lock_time_flags (CSV-aware regardless of
           caller's script flags) instead of [flags], which is forced to
           0 by the IBD/reorg dispatcher on assumevalid. *)
        let locktime_cutoff_fast =
          if lock_time_flags land Script.script_verify_checksequenceverify <> 0
          then median_time
          else block.header.timestamp
        in

        List.iteri (fun i (tx : Types.transaction) ->
          if !error = None then begin
            let txid = txid_arr.(i) in
            let is_cb = (i = 0) in

            (* IsFinalTx check — applies to ALL transactions including the coinbase.
               6D: Bitcoin Core validation.cpp:4144-4148 loops ALL block.vtx with no
               coinbase exemption; a non-final coinbase (non-zero nLockTime + non-final
               sequence) must be rejected. *)
            if not (is_tx_final tx ~block_height:height ~block_time:locktime_cutoff_fast) then
              error := Some (BlockTxValidationFailed (i, TxNonFinalLocktime));

            (* BIP-30: always run even on the fast (assumevalid) path.
               Bitcoin Core ConnectBlock enforces BIP-30 unconditionally —
               assumevalid only skips script verification.
               Uses height+hash for the repeat-block exemption (Gates 1/3)
               and the BIP34Hash canonical-chain optimization (Gate 4).
               Reference: Bitcoin Core validation.cpp ConnectBlock (line 2402-2467). *)
            if !error = None then begin
              if bip30_should_enforce ~network ~height
                   ~block_hash:block_hash_for_bip30
                   ~bip34_height_hash then begin
                let n_outputs = List.length tx.outputs in
                if not (check_bip30 ~lookup:base_lookup ~txid ~n_outputs) then
                  error := Some (BlockTxValidationFailed (i, TxDuplicateTxid))
              end
            end;

            (* W93 Bug 2 fix: BIP-141 weighted sigops cost is checked on
               both paths in Core [validation.cpp:2568-2572].  We must
               also accumulate it here so a malicious peer can't sneak a
               sigop-bomb block in below assumevalid.  Uses the overlay-
               aware lookup (local_utxos + spent_in_block + base_lookup)
               so intra-block P2SH/witness redeems resolve correctly.
               Use STANDARD block flags for sigops counting (P2SH +
               WITNESS) so post-segwit blocks count witness sigops even
               though the caller passes flags=0 on the assumevalid
               dispatch — matches Core, which computes flags via
               GetBlockScriptFlags pindex [validation.cpp:2485] and
               passes them to GetTransactionSigOpCost [:2568]
               unconditionally. *)
            if !error = None then begin
              let prev_script_pubkey_lookup_fast outpoint =
                let key =
                  (Cstruct.to_string outpoint.Types.txid,
                   outpoint.Types.vout)
                in
                if Hashtbl.mem spent_in_block key then None
                else match Hashtbl.find_opt local_utxos key with
                  | Some utxo -> Some utxo.script_pubkey
                  | None -> (match base_lookup outpoint with
                             | Some utxo -> Some utxo.script_pubkey
                             | None -> None)
              in
              let sigops_flags =
                Consensus.get_block_script_flags ~block_hash:block_hash_for_bip30 height network
              in
              let tx_sigops = count_tx_sigops_cost tx
                                ~prev_script_pubkey_lookup:prev_script_pubkey_lookup_fast
                                ~flags:sigops_flags in
              total_sigops_cost := !total_sigops_cost + tx_sigops;
              if !total_sigops_cost > Consensus.max_block_sigops_cost then
                error := Some BlockTooManySigops
            end;

            if !error = None && not is_cb then begin
              (* Fix 3: Single-pass UTXO lookup - resolve all inputs once.
                 Pre-compute string key per input, reuse for lookup and
                 spent_in_block. *)
              let n_inputs = List.length tx.inputs in
              let resolved_utxos = Array.make n_inputs None in
              let input_keys = Array.make n_inputs ("", 0l) in
              let total_in = ref 0L in
              List.iteri (fun j inp ->
                if !error = None then begin
                  let outpoint = inp.Types.previous_output in
                  let key = (Cstruct.to_string outpoint.Types.txid, outpoint.Types.vout) in
                  input_keys.(j) <- key;
                  (* Inline lookup using pre-computed key *)
                  let result =
                    if Hashtbl.mem spent_in_block key then None
                    else match Hashtbl.find_opt local_utxos key with
                      | Some utxo -> Some utxo
                      | None -> base_lookup outpoint
                  in
                  match result with
                  | None ->
                    error := Some (BlockTxValidationFailed (i, TxMissingInputs))
                  | Some utxo ->
                    (* W93 Bug 3 fix: coinbase maturity. Core's
                       Consensus::CheckTxInputs (tx_verify.cpp:179-182)
                       is called from ConnectBlock unconditionally —
                       assumevalid does NOT skip it. *)
                    if utxo.is_coinbase
                       && height - utxo.height < Consensus.coinbase_maturity then
                      error := Some (BlockTxValidationFailed
                                       (i, TxCoinbaseMaturity (height - utxo.height)))
                    (* W93 Bug 7 fix: per-input MoneyRange check
                       (bad-txns-inputvalues-outofrange).
                       tx_verify.cpp:186-188. *)
                    else if not (Consensus.is_valid_money utxo.value) then
                      error := Some (BlockTxValidationFailed (i, TxOutputOverflow))
                    else begin
                      resolved_utxos.(j) <- Some utxo;
                      total_in := Int64.add !total_in utxo.value;
                      (* W93 Bug 7 fix: cumulative input MoneyRange check
                         (also bad-txns-inputvalues-outofrange).
                         tx_verify.cpp:186. *)
                      if not (Consensus.is_valid_money !total_in) then
                        error := Some (BlockTxValidationFailed (i, TxOutputOverflow))
                    end
                end
              ) tx.inputs;

              if !error = None then begin
                (* BIP-68 SequenceLocks: enforced even on the fast/assumevalid path.
                   Bitcoin Core validation.cpp ConnectBlock (~line 2557) runs
                   SequenceLocks BEFORE the fScriptChecks guard, so it fires
                   regardless of assumevalid.  We must do the same here.
                   Reference: bitcoin-core/src/consensus/tx_verify.cpp:107-110.
                   W93 Bug 5 fix: use lock_time_flags (CSV-aware) instead of
                   [flags], which is forced to 0 by the IBD/reorg dispatcher
                   on the assumevalid fast path — that path was silently
                   skipping SequenceLocks before this fix. *)
                let utxo_heights_arr = Array.make n_inputs 0 in
                let utxo_mtps_arr = Array.make n_inputs 0l in
                Array.iteri (fun j opt ->
                  match opt with
                  | Some utxo ->
                    utxo_heights_arr.(j) <- utxo.height;
                    utxo_mtps_arr.(j) <- (match get_mtp_at_height with
                      | Some f -> f (max 0 (utxo.height - 1))
                      | None -> median_time)
                  | None -> ()
                ) resolved_utxos;
                if not (check_sequence_locks tx ~block_height:height
                          ~median_time ~utxo_heights:utxo_heights_arr
                          ~utxo_mtps:utxo_mtps_arr
                          ?get_mtp_at_height ~flags:lock_time_flags ()) then
                  error := Some (BlockTxValidationFailed (i, TxSequenceLocksFailed))
              end;

              if !error = None then begin
                (* Calculate fee *)
                let total_out = List.fold_left (fun acc out ->
                  Int64.add acc out.Types.value
                ) 0L tx.outputs in
                let fee = Int64.sub !total_in total_out in
                if fee < 0L then
                  error := Some (BlockTxValidationFailed (i, TxInsufficientFee))
                else begin
                  total_fees := Int64.add !total_fees fee;

                  (* Accumulated fee MoneyRange check — mirrors Core
                     validation.cpp:2543-2547 (bad-txns-accumulated-fee-outofrange).
                     This fires even on the assumevalid fast path because ConnectBlock
                     runs this check unconditionally (it is not guarded by
                     fScriptChecks). *)
                  if not (Consensus.is_valid_money !total_fees) then
                    error := Some (BlockTxValidationFailed (i, TxOutputOverflow))
                  else begin
                    (* Mark inputs as spent using pre-computed keys *)
                    List.iteri (fun j inp ->
                      let outpoint = inp.Types.previous_output in
                      let key = input_keys.(j) in
                      (match resolved_utxos.(j) with
                       | Some utxo ->
                         spent_utxos := (outpoint, utxo) :: !spent_utxos
                       | None -> ());
                      Hashtbl.add spent_in_block key ()
                    ) tx.inputs
                  end
                end
              end
            end;

            (* Add outputs to local UTXO set.
               Compute txid string once, reuse for all outputs. *)
            if !error = None then begin
              let txid_str = Cstruct.to_string txid in
              List.iteri (fun vout out ->
                let utxo = {
                  txid;
                  vout = Int32.of_int vout;
                  value = out.Types.value;
                  script_pubkey = out.Types.script_pubkey;
                  height;
                  is_coinbase = is_cb;
                } in
                let key = (txid_str, Int32.of_int vout) in
                Hashtbl.add local_utxos key utxo
              ) tx.outputs
            end
          end
        ) txs;

        match !error with
        | Some e -> Error e
        | None ->
          (* Coinbase value check — mirrors Core validation.cpp:2610-2613
             (bad-cb-amount).  ConnectBlock runs this after the tx loop and is
             NOT guarded by fScriptChecks, so it must fire on the fast
             (assumevalid) path too. *)
          let coinbase = List.hd block.transactions in
          let coinbase_value = List.fold_left (fun acc out ->
            Int64.add acc out.Types.value
          ) 0L coinbase.outputs in
          let max_coinbase =
            Int64.add
              (Consensus.block_subsidy_for_network network.network_type height)
              !total_fees
          in
          if coinbase_value > max_coinbase then
            Error (BlockBadCoinbaseValue (coinbase_value, max_coinbase))
          else
            Ok (!total_fees, txid_arr, List.rev !spent_utxos)
      end
    end
  end

  (* ====================================================================
     FULL VALIDATION PATH (non-assume-valid)
     ==================================================================== *)
  else begin
  (* First do context-free + contextual header checks *)
  match check_block ~network block height ~expected_bits ~median_time ~prev_block_time ~skip_pow () with
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

    (* Compute txids ONCE up front (Fix 1) *)
    let n_txs = List.length block.transactions in
    let txid_arr = Array.make n_txs Cstruct.empty in
    List.iteri (fun i tx ->
      txid_arr.(i) <- Crypto.compute_txid tx
    ) block.transactions;

    (* Compute block hash once for BIP-30 repeat-block check. *)
    let block_hash_for_bip30 = Crypto.compute_block_hash block.header in

    (* Accumulate sigops during per-tx validation so intra-block UTXOs are visible *)
    let total_sigops_cost = ref 0 in
    let total_fees = ref 0L in
    let error = ref None in
    let spent_utxos = ref [] in

    List.iteri (fun i (tx : Types.transaction) ->
      if !error = None then begin
        let txid = txid_arr.(i) in
        let is_cb = (i = 0) in

        (* BIP-30: reject any block whose transactions would overwrite an
           existing unspent output in the UTXO set (CVE-2012-1909).
           Uses height+hash for the repeat-block exemption (Gates 1/3)
           and the BIP34Hash canonical-chain optimization (Gate 4).
           Reference: Bitcoin Core validation.cpp ConnectBlock (line 2402-2467)
           and IsBIP30Repeat() (line 6189-6192). *)
        if bip30_should_enforce ~network ~height
             ~block_hash:block_hash_for_bip30
             ~bip34_height_hash then begin
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

        (* 6D: IsFinalTx — applies to ALL transactions including the coinbase.
           Bitcoin Core validation.cpp:4144-4148 loops ALL block.vtx with no
           coinbase exemption; a non-final coinbase must be rejected.
           BIP-113: use median time past for locktime comparison after CSV
           activation. Before CSV, use block timestamp.
           W93: use lock_time_flags (CSV-aware regardless of caller's script
           flags) for parity with the fast path. *)
        if !error = None then begin
          let locktime_cutoff =
            if lock_time_flags land Script.script_verify_checksequenceverify <> 0 then
              median_time
            else
              block.header.timestamp
          in
          if not (is_tx_final tx ~block_height:height ~block_time:locktime_cutoff) then
            error := Some (BlockTxValidationFailed (i, TxNonFinalLocktime))
        end;

        (* Validate inputs (skip for coinbase) *)
        if !error = None && not is_cb then begin
          (* Fix 3: Single-pass UTXO lookup for non-coinbase txs.
             Pre-compute string keys once per input to avoid repeated
             Cstruct.to_string allocations. *)
          let n_inputs = List.length tx.inputs in
          let resolved_utxos = Array.make n_inputs None in
          let resolve_error = ref None in
          List.iteri (fun j inp ->
            if !resolve_error = None then begin
              match lookup inp.Types.previous_output with
              | None ->
                resolve_error := Some TxMissingInputs
              | Some utxo ->
                (* Check coinbase maturity *)
                if utxo.is_coinbase && height - utxo.height < Consensus.coinbase_maturity then
                  resolve_error := Some (TxCoinbaseMaturity (height - utxo.height))
                else if not (Consensus.is_valid_money utxo.value) then
                  resolve_error := Some TxOutputOverflow
                else
                  resolved_utxos.(j) <- Some utxo
            end
          ) tx.inputs;

          match !resolve_error with
            | Some e ->
              error := Some (BlockTxValidationFailed (i, e))
            | None ->
              (* Build prevouts for script verification *)
              let prevouts = Array.to_list (Array.map (fun opt ->
                match opt with
                | Some utxo -> (utxo.value, utxo.script_pubkey)
                | None -> (0L, Cstruct.empty)
              ) resolved_utxos) in

              (* Compute total_in from resolved UTXOs *)
              let total_in = ref 0L in
              Array.iter (fun opt ->
                match opt with
                | Some utxo -> total_in := Int64.add !total_in utxo.value
                | None -> ()
              ) resolved_utxos;

              (* Check cumulative total_in is in MoneyRange *)
              if not (Consensus.is_valid_money !total_in) then
                error := Some (BlockTxValidationFailed (i, TxOutputOverflow))
              else begin
                (* BIP-68 SequenceLocks: check relative lock-times BEFORE
                   script verification.
                   Reference: Bitcoin Core validation.cpp ConnectBlock() ~line 2549:
                     prevheights[j] = view.AccessCoin(tx.vin[j].prevout).nHeight;
                     if (!SequenceLocks(tx, nLockTimeFlags, prevheights, *pindex))
                       state.Invalid(..., "bad-txns-nonfinal", ...)
                   Core fires this BEFORE CheckInputScripts (script-eval), so
                   blocks with unsatisfied relative lock-times must be rejected
                   with bad-txns-nonfinal, not block-script-verify-flag-failed.
                   Moving this before verify_scripts_parallel_domain restores
                   Core ordering parity (ordering bug surfaced in wave-35 corpus). *)
                let utxo_heights = Array.make n_inputs 0 in
                let utxo_mtps = Array.make n_inputs 0l in
                Array.iteri (fun j opt ->
                  match opt with
                  | Some utxo ->
                    utxo_heights.(j) <- utxo.height;
                    utxo_mtps.(j) <- (match get_mtp_at_height with
                      | Some f -> f (utxo.height - 1)
                      | None -> median_time)
                  | None -> ()
                ) resolved_utxos;
                if not (check_sequence_locks tx ~block_height:height
                          ~median_time ~utxo_heights ~utxo_mtps
                          ?get_mtp_at_height ~flags:lock_time_flags ()) then
                  error := Some (BlockTxValidationFailed (i, TxSequenceLocksFailed));

                if !error = None then begin
                (* Parallel script verification using OCaml 5 Domains.
                   Reference: Bitcoin Core's CCheckQueue (src/checkqueue.h) —
                   N-1 worker threads + master thread verify inputs concurrently.
                   Here we spawn Domain.recommended_domain_count()-1 Domains and
                   have the main domain process one partition.  Each Domain calls
                   verify_one_input which serialises sig-cache access via
                   sig_cache_mutex (OCaml Hashtbl is not Domain-safe).
                   UTXO apply must have completed before entering this section. *)
                let script_result =
                  verify_scripts_parallel_domain
                    ~tx ~flags ~prevouts ~utxos:resolved_utxos ()
                in

                match script_result with
                | Error e -> error := Some (BlockTxValidationFailed (i, e))
                | Ok () ->

                  if !error = None then begin
                    (* Calculate and accumulate fee *)
                    let total_out = List.fold_left (fun acc out ->
                      Int64.add acc out.Types.value
                    ) 0L tx.outputs in
                    let fee = Int64.sub !total_in total_out in
                    if fee < 0L then
                      error := Some (BlockTxValidationFailed (i, TxInsufficientFee))
                    else begin
                      total_fees := Int64.add !total_fees fee;

                      (* Fee overflow check *)
                      if not (Consensus.is_valid_money !total_fees) then
                        error := Some (BlockTxValidationFailed (i, TxOutputOverflow))
                      else begin
                        (* Mark inputs as spent using pre-resolved UTXOs *)
                        List.iteri (fun j inp ->
                          let outpoint = inp.Types.previous_output in
                          let key = (Cstruct.to_string outpoint.txid,
                                     outpoint.vout) in
                          (match resolved_utxos.(j) with
                           | Some utxo ->
                             spent_utxos := (outpoint, utxo) :: !spent_utxos
                           | None -> ());
                          Hashtbl.add spent_in_block key ()
                        ) tx.inputs
                      end
                    end
                  end
              end (* if !error = None then begin — script-eval guard *)
              end (* else begin — MoneyRange check *)
        end;

        (* Add outputs to local UTXO set for intra-block spending.
           Compute txid string once, reuse for all outputs. *)
        if !error = None then begin
          let txid_str = Cstruct.to_string txid in
          List.iteri (fun vout out ->
            let utxo = {
              txid;
              vout = Int32.of_int vout;
              value = out.Types.value;
              script_pubkey = out.Types.script_pubkey;
              height;
              is_coinbase = is_cb;
            } in
            let key = (txid_str, Int32.of_int vout) in
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
        Ok (!total_fees, txid_arr, List.rev !spent_utxos)
  end

(* ============================================================================
   Unified Block Acceptance Helper — mirrors Bitcoin Core ProcessNewBlock
   ============================================================================

   All block-acceptance entry points (submitblock RPC, P2P block handler,
   connect_stored_blocks gap-fill, IBD pipeline) route through this single
   function.  This ensures every path receives the same validation sequence:

     1. validate_block_with_utxos — full contextual validation (internally
        calls check_block for context-free checks, then performs UTXO-aware
        checks: BIP-30 dup-UTXO, per-input scripts, BIP-141 sigops cost,
        coinbase value ≤ subsidy+fees, BIP-68 sequence locks).

   On the assumevalid fast path (skip_scripts=true), validate_block_with_utxos
   skips script verification but still enforces IsFinalTx, BIP-30, and
   fee/value accounting — matching Bitcoin Core's ConnectBlock behaviour where
   assumevalid only skips CScriptCheck jobs.

   Reference: Bitcoin Core validation.cpp
     - AcceptBlockHeader (PoW/timestamp/version/difficulty)
     - AcceptBlock → CheckBlock (context-free structural checks)
     - ActivateBestChain → ConnectBlock (contextual + UTXO checks)
   Both submitblock RPC and P2P block handling call ProcessNewBlock,
   which internally calls AcceptBlock → ActivateBestChain (ConnectBlock).

   Return value mirrors validate_block_with_utxos:
     AB_ok (fees, txid_arr, spent_utxos)
     AB_err error

   DO NOT call connect_block / apply_block_atomic inside this function.
   Callers are responsible for UTXO mutations after accept_block succeeds.

   Porting note (wave-31 refactor): this replaces the per-entry-point
   hand-rolled check sequences that caused camlcoin to appear on the
   consensus-bug list in waves 3, 7, 15, 22, and 23.  The submitblock
   path previously called check_block (line ~566 mining.ml) and THEN
   validate_block_with_utxos (which calls check_block again internally),
   running check_block twice.  The IBD path called validate_block_with_utxos
   once.  Both now call accept_block which defers entirely to
   validate_block_with_utxos (single entry for all structural + contextual
   checks). *)

type accept_block_result =
  | AB_ok of int64 * Types.hash256 array * (Types.outpoint * utxo) list
  | AB_err of block_validation_error

let accept_block
    ~(network : Consensus.network_config)
    ~(block : Types.block)
    ~(height : int)
    ~(expected_bits : int32)
    ~(median_time : int32)
    ~(base_lookup : utxo_lookup)
    ~(flags : int)
    ?(skip_scripts = false)
    ?(skip_pow = false)
    ?(prev_block_time = 0l)
    ?get_mtp_at_height
    ?bip34_height_hash
    ()
    : accept_block_result =
  match validate_block_with_utxos ~network block height
          ~expected_bits ~median_time ~prev_block_time
          ~base_lookup ~flags ~skip_scripts ~skip_pow
          ?get_mtp_at_height ?bip34_height_hash () with
  | Ok (fees, txid_arr, spent_utxos) ->
    AB_ok (fees, txid_arr, spent_utxos)
  | Error e ->
    AB_err e
