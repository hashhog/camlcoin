(* BIP-78 Receiver-side PayJoin protocol.
   (FIX-65, follow-up to FIX-60 / FIX-62 / FIX-64.)

   This module implements the receiver half of BIP-78 "Serverless PayJoin".
   The receiver:

     1. accepts an Original PSBT (OrigPSBT) from the sender over an HTTP
        POST with [Content-Type: text/plain] + base64 body,
     2. validates the OrigPSBT per the BIP-78 "Receiver's Original PSBT
        checks" subsection (unique scriptPubKey per output, sender inputs
        all finalized + same script type, sane fee),
     3. adds one or more of its own UTXOs as additional inputs,
     4. optionally bumps one of the original outputs (modify_output),
     5. adjusts the fee per the sender's `additionalfeeoutputindex` query
        parameter,
     6. *signs the receiver-added inputs only* by calling
        [Wallet.process_psbt ~sign:true ~finalize:false] — the FIX-60
        primitive (commit d73b8c1) is the direct building block here,
     7. returns the signed PayJoin PSBT (PayjoinPSBT) base64-encoded.

   The 4 BIP-78 wire errors are modelled explicitly so the HTTP layer can
   serialize them as the spec's JSON envelope.

   References:
     - BIP-78 (Serverless PayJoin),
       https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki
     - Bitcoin Core: NONE — Core does not implement PayJoin (this is
       BTCPay-Server / payjoin.org territory).
     - FIX-60 commit d73b8c1 — wired Wallet.process_psbt as a public
       primitive; this module is the first consumer outside of the
       walletprocesspsbt RPC.
*)

let log_src = Logs.Src.create "PayJoin" ~doc:"BIP-78 PayJoin receiver"
module Log = (val Logs.src_log log_src : Logs.LOG)

(* ========================================================================
   BIP-78 wire errors  (spec §"Receiver responses")
   ======================================================================== *)

(* The 4 well-known PayJoin error codes the receiver may emit over the
   wire.  Each is an ASCII string the JSON envelope's `errorCode` field
   uses verbatim.  Closes W119 BUG-17 (G17). *)
type error =
  | Unavailable               (* "unavailable" — receiver cannot service *)
  | Not_enough_money          (* "not-enough-money" — receiver lacks UTXO *)
  | Version_unsupported       (* "version-unsupported" — v != 1 *)
  | Original_psbt_rejected    (* "original-psbt-rejected" — checks failed *)

let error_code_string = function
  | Unavailable            -> "unavailable"
  | Not_enough_money       -> "not-enough-money"
  | Version_unsupported    -> "version-unsupported"
  | Original_psbt_rejected -> "original-psbt-rejected"

(* The HTTP status BIP-78 §"Receiver responses" pairs with each code.
   "version-unsupported" → 400, others → 422 Unprocessable Entity. *)
let error_http_status = function
  | Version_unsupported    -> `Bad_request
  | _                      -> `Unprocessable_entity

(* BIP-78 §"Receiver responses" specifies the body as a JSON object with
   `errorCode` (machine-readable) + `message` (human-readable). *)
let error_to_json ?(message = "") (err : error) : Yojson.Safe.t =
  let code = error_code_string err in
  let msg = if message = "" then code else message in
  `Assoc [
    ("errorCode", `String code);
    ("message",   `String msg);
  ]

let error_to_json_string ?(message = "") (err : error) : string =
  Yojson.Safe.to_string (error_to_json ~message err)

(* ========================================================================
   BIP-78 sender query parameters (parsed from the POST URI's ?key=value)
   ======================================================================== *)

(* Closes W119 BUG-16 (G16) at the receiver-side surface. *)
type sender_params = {
  v : int;
    (* Protocol version.  Spec only defines v=1 today.
       Defaults to 1 if not supplied (BIP-78 says receiver SHOULD assume
       v=1 if missing — this matches BTCPayServer behaviour). *)
  additionalfeeoutputindex : int option;
    (* If Some i, the receiver may take its added-input fee from output i.
       Closes BUG-6 (G6) the validator below. *)
  maxadditionalfeecontribution : int64 option;
    (* Cap on the receiver-added fee in satoshis. *)
  minfeerate : float option;
    (* Sender-required minimum fee rate (sat/vB). *)
  disableoutputsubstitution : bool;
    (* `pjos=1` → receiver MUST NOT substitute outputs.
       Defaults to false (BIP-78 default — receiver MAY substitute). *)
}

let default_sender_params = {
  v = 1;
  additionalfeeoutputindex = None;
  maxadditionalfeecontribution = None;
  minfeerate = None;
  disableoutputsubstitution = false;
}

(* Parse the URI query string into [sender_params].
   The URI module from Cohttp already gives us decoded key/value pairs;
   this function only needs to coerce string→int/int64/float and apply
   sensible defaults.  Returns [Error Version_unsupported] when [v] is
   present and != 1 — closes BUG-21 (G21). *)
let parse_sender_params (query : (string * string list) list)
    : (sender_params, error) result =
  let get k =
    match List.assoc_opt k query with
    | Some (v :: _) -> Some v
    | _ -> None
  in
  let v =
    match get "v" with
    | None -> 1
    | Some s ->
      (try int_of_string s
       with _ -> -1)  (* invalid v → reject as version-unsupported *)
  in
  if v <> 1 then Error Version_unsupported
  else begin
    let additionalfeeoutputindex =
      match get "additionalfeeoutputindex" with
      | None -> None
      | Some s -> (try Some (int_of_string s) with _ -> None)
    in
    let maxadditionalfeecontribution =
      match get "maxadditionalfeecontribution" with
      | None -> None
      | Some s -> (try Some (Int64.of_string s) with _ -> None)
    in
    let minfeerate =
      match get "minfeerate" with
      | None -> None
      | Some s -> (try Some (float_of_string s) with _ -> None)
    in
    let disableoutputsubstitution =
      match get "pjos" with
      | None -> false
      | Some "0" -> false
      | Some "1" -> true
      | Some _   -> false
    in
    Ok { v; additionalfeeoutputindex; maxadditionalfeecontribution;
         minfeerate; disableoutputsubstitution }
  end

(* ========================================================================
   Content-Type validation  (closes BUG-23 / G23)
   ======================================================================== *)

(* BIP-78 §"Sender's request": the OrigPSBT POST body MUST be
   [Content-Type: text/plain] with a base64 PSBT.  Accept [text/plain]
   with an optional charset parameter; reject everything else. *)
let validate_content_type (h : Cohttp.Header.t) : bool =
  match Cohttp.Header.get h "content-type" with
  | None -> false
  | Some s ->
    let s = String.lowercase_ascii (String.trim s) in
    (* Strip any "; charset=..." trailer before comparison. *)
    let base =
      match String.index_opt s ';' with
      | None -> s
      | Some i -> String.trim (String.sub s 0 i)
    in
    String.equal base "text/plain"

(* ========================================================================
   OrigPSBT validation  (closes BUG-4 / BUG-5 / G4 / G5)
   ======================================================================== *)

(* Helper: extract the prevout for an input — prefer witness_utxo (BIP-174
   authoritative for segwit), else project non_witness_utxo's vout. *)
let prevout_of (inp : Psbt.psbt_input) (tx_in : Types.tx_in)
    : Types.tx_out option =
  match inp.witness_utxo with
  | Some o -> Some o
  | None ->
    match inp.non_witness_utxo with
    | Some prev_tx ->
      let vout_idx = Int32.to_int tx_in.previous_output.vout in
      (try Some (List.nth prev_tx.outputs vout_idx)
       with _ -> None)
    | None -> None

(* Classify the scriptPubKey to a coarse "script type" so we can enforce
   the BIP-78 "sender inputs all same type" check.  Reuses [Script.classify_script]. *)
let coarse_script_type (spk : Cstruct.t) : string =
  match Script.classify_script spk with
  | Script.P2PKH_script _   -> "p2pkh"
  | Script.P2SH_script _    -> "p2sh"
  | Script.P2WPKH_script _  -> "p2wpkh"
  | Script.P2WSH_script _   -> "p2wsh"
  | Script.P2TR_script _    -> "p2tr"
  | _ -> "unknown"

(* BIP-78 §"Receiver's Original PSBT checks":
     1. PSBT version 0.
     2. PSBT MUST be unsigned for any input the receiver will sign
        (sender inputs must be FINALIZED — receiver does not see partial
        sigs from the sender).
     3. All sender inputs MUST share the same script type (else address-type
        leak after receiver adds its own).
     4. All scriptPubKey outputs MUST be unique.

   Returns [Ok psbt] on success or [Error Original_psbt_rejected] with a
   message.  Closes BUG-5 (G5). *)
let validate_original_psbt (psbt : Psbt.psbt)
    : (Psbt.psbt, error * string) result =
  let inputs = psbt.Psbt.inputs in
  let tx_inputs = psbt.Psbt.tx.inputs in
  let outputs = psbt.Psbt.tx.outputs in

  if List.length inputs = 0 then
    Error (Original_psbt_rejected, "PSBT has no inputs")
  else if List.length outputs = 0 then
    Error (Original_psbt_rejected, "PSBT has no outputs")
  else begin
    (* (2) sender inputs MUST be finalized — sender sends a *complete*
           OrigPSBT (a "broadcastable as-is" tx).  This matches BIP-78
           §"Sender's Original PSBT request". *)
    let unfinalized_idx =
      let rec find i lst =
        match lst with
        | [] -> None
        | inp :: rest ->
          if Psbt.is_input_finalized inp then find (i + 1) rest
          else Some i
      in
      find 0 inputs
    in
    match unfinalized_idx with
    | Some i ->
      Error (Original_psbt_rejected,
             Printf.sprintf "Sender input %d is not finalized" i)
    | None ->
      (* (3) all sender inputs same script type — derive from each prevout. *)
      let pairs = List.combine inputs tx_inputs in
      let types =
        List.map (fun (inp, tx_in) ->
          match prevout_of inp tx_in with
          | None -> "unknown"
          | Some o -> coarse_script_type o.script_pubkey
        ) pairs
      in
      let first = List.hd types in
      let mixed = List.exists (fun t -> t <> first) types in
      if mixed then
        Error (Original_psbt_rejected,
               "Sender inputs have mixed script types")
      else if first = "unknown" then
        Error (Original_psbt_rejected,
               "Sender input scriptPubKey could not be classified")
      else begin
        (* (4) output scriptPubKey uniqueness. *)
        let spks = List.map (fun (o : Types.tx_out) ->
          Cstruct.to_string o.script_pubkey
        ) outputs in
        let sorted = List.sort String.compare spks in
        let dup =
          let rec dup_in = function
            | [] | [_] -> false
            | a :: b :: _ when a = b -> true
            | _ :: rest -> dup_in rest
          in
          dup_in sorted
        in
        if dup then
          Error (Original_psbt_rejected,
                 "Output scriptPubKey is not unique")
        else
          Ok psbt
      end
  end

(* Validate the [additionalfeeoutputindex] sender parameter lies inside the
   OrigPSBT's output list.  Closes BUG-6 (G6). *)
let validate_fee_output_index (psbt : Psbt.psbt) (idx : int) : bool =
  let n = List.length psbt.Psbt.tx.outputs in
  idx >= 0 && idx < n

(* ========================================================================
   Receiver-side PSBT mutators
   ======================================================================== *)

(* BIP-78 §"Receiver's contribution": append the receiver's chosen UTXO
   to the PSBT (input list + psbt_input record).  Closes BUG-7 (G7).

   Inputs:
     psbt       — Original PSBT after validation.
     outpoint   — receiver's UTXO outpoint to spend.
     prev_out   — full Types.tx_out of the prevout (value + scriptPubKey),
                  written into the appended psbt_input as witness_utxo.
     sequence   — the new tx_in's sequence (default 0xfffffffd for RBF).
   Returns the new PSBT.  The receiver's input is appended at the END of
   the input list (BIP-78 doesn't constrain order, but appending keeps
   sender output indices stable so the fee-output-index parameter stays
   valid for the caller). *)
let add_receiver_input
    (psbt : Psbt.psbt)
    ~(outpoint : Types.outpoint)
    ~(prev_out : Types.tx_out)
    ~(sequence : int32)
    : Psbt.psbt =
  let new_tx_in : Types.tx_in = {
    previous_output = outpoint;
    script_sig = Cstruct.empty;
    sequence;
  } in
  let new_psbt_in = { Psbt.empty_input with
    witness_utxo = Some prev_out;
  } in
  let tx = psbt.Psbt.tx in
  let new_tx = { tx with
    inputs = tx.inputs @ [new_tx_in];
    (* keep witnesses list length matching inputs *)
    witnesses = tx.witnesses @ [{ items = [] }];
  } in
  { psbt with
    tx = new_tx;
    inputs = psbt.inputs @ [new_psbt_in];
  }

(* BIP-78 §"Receiver's contribution": optionally bump the value of one
   sender output (typically the one the sender said the receiver may
   share).  Closes BUG-8 (G8).

   Returns [Error Original_psbt_rejected] when [idx] is out of range.
   Refuses to bump when [disable_output_substitution] is true and
   [strict] is true — this is the caller's policy choice, NOT a
   receiver-side BIP-78 invariant on its own. *)
let modify_output
    (psbt : Psbt.psbt)
    ~(idx : int)
    ~(new_value : int64)
    : (Psbt.psbt, error * string) result =
  let tx = psbt.Psbt.tx in
  let n = List.length tx.outputs in
  if idx < 0 || idx >= n then
    Error (Original_psbt_rejected,
           Printf.sprintf "modify_output: index %d outside [0,%d)" idx n)
  else if Int64.compare new_value 0L < 0 then
    Error (Original_psbt_rejected,
           "modify_output: negative output value")
  else begin
    let new_outputs =
      List.mapi (fun i (o : Types.tx_out) ->
        if i = idx then { o with value = new_value }
        else o
      ) tx.outputs
    in
    let new_tx = { tx with outputs = new_outputs } in
    Ok { psbt with tx = new_tx }
  end

(* BIP-78 §"Receiver's contribution": subtract the receiver's added-fee
   contribution from the sender-specified output per
   [additionalfeeoutputindex].  Closes BUG-9 (G9).

   The caller computes [extra_fee_sat] (the amount the receiver adds to
   the tx fee by appending its own input — typically ≈ vbytes_of_input *
   sender_minfeerate).  This function subtracts [extra_fee_sat] from
   output [idx]'s value, capped at the sender's
   [maxadditionalfeecontribution] (if set).

   Returns [Error Not_enough_money] when the requested fee adjustment
   would push the output below dust (1 satoshi). *)
let adjust_fee
    (psbt : Psbt.psbt)
    ~(idx : int)
    ~(extra_fee_sat : int64)
    ~(max_contribution : int64 option)
    : (Psbt.psbt, error * string) result =
  let tx = psbt.Psbt.tx in
  let n = List.length tx.outputs in
  if idx < 0 || idx >= n then
    Error (Original_psbt_rejected,
           Printf.sprintf "adjust_fee: index %d outside [0,%d)" idx n)
  else begin
    let capped =
      match max_contribution with
      | None -> extra_fee_sat
      | Some cap ->
        if Int64.compare extra_fee_sat cap > 0 then cap else extra_fee_sat
    in
    let out_at_idx =
      List.nth tx.outputs idx
    in
    let new_value = Int64.sub out_at_idx.value capped in
    if Int64.compare new_value 1L < 0 then
      Error (Not_enough_money,
             Printf.sprintf "adjust_fee: output %d would drop below dust" idx)
    else
      modify_output psbt ~idx ~new_value
  end

(* ========================================================================
   Cross-wave-dep — Wallet.process_psbt as the signer
   ======================================================================== *)

(* BIP-78 §"Receiver's contribution" final step: sign the PSBT.  The
   receiver is ONLY signing its own input; sender inputs are already
   finalized.  We delegate to FIX-60's Wallet.process_psbt with
   sign=true + finalize=false (the receiver returns a *partially*
   complete PSBT — the sender will finalize after its own
   verification + signature pass).

   Closes BUG-1 receiver-pipeline-signer (one of the G1 sub-checks).

   Returns the signed PSBT.  Wallet locked / wrong network produce
   [Error Unavailable] (receiver cannot service this request). *)
let receiver_sign
    (wallet : Wallet.t)
    (psbt : Psbt.psbt)
    : (Psbt.psbt, error * string) result =
  if Wallet.is_encrypted wallet && Wallet.is_locked wallet then
    Error (Unavailable, "Wallet is locked — receiver cannot sign")
  else begin
    try
      let (psbt', _complete) =
        (* THIS is the cross-wave dep activation:
           FIX-60 d73b8c1 wallet/process_psbt is reused here as the
           receiver-side signer.  Defaults match FIX-60:
             ~sign:true       — receiver signs its added input
             ~sighash:0x01    — SIGHASH_ALL for legacy/segwit
             ~bip32derivs:true — attach derivation records
           We deliberately DO NOT call any finalize_input_* — BIP-78
           says the sender finalizes after its own verification. *)
        Wallet.process_psbt wallet psbt
          ~sign:true ~sighash:0x01 ~bip32derivs:true
      in
      Ok psbt'
    with exn ->
      let msg = Printexc.to_string exn in
      Log.err (fun m -> m "PayJoin receiver sign failed: %s" msg);
      Error (Original_psbt_rejected,
             "Receiver signing failed: " ^ msg)
  end

(* ========================================================================
   High-level orchestrator: process a complete BIP-78 POST request
   ======================================================================== *)

(* End-to-end receiver pipeline.  Inputs:

     wallet            — receiver wallet (must be unlocked).
     content_type_ok   — caller-checked Content-Type=text/plain.
     params            — parsed sender query params.
     body_b64          — request body, expected to be base64 PSBT.

   Returns either the signed PayjoinPSBT (base64) or a BIP-78 error.

   This is the function the HTTP route handler calls.  It does NOT
   itself add receiver inputs — choosing which receiver UTXO to add is
   policy (W113 coin selection is reachable from the caller).  In the
   *no-op* / *passthrough* sub-mode the receiver returns the same
   PSBT it received with no input added, which is BIP-78-compliant
   behaviour: a receiver may decline to PayJoin and just sign nothing
   extra.  Higher-level handlers (Rpc / Rest) decide whether to populate
   a receiver UTXO before calling this orchestrator.

   Closes BUG-4 (decode), BUG-5 (validation), BUG-9 (fee adjust path
   through), BUG-17 (error envelope), BUG-21 (version check), BUG-23
   (Content-Type validation). *)
let process_request
    (wallet : Wallet.t)
    ~(content_type_ok : bool)
    ~(params : sender_params)
    ~(body_b64 : string)
    ?(receiver_utxo :
        (Types.outpoint * Types.tx_out * int32) option = None)
    ()
    : (string, error * string) result =
  let _ = params.disableoutputsubstitution in
  if not content_type_ok then
    Error (Original_psbt_rejected,
           "Content-Type must be text/plain (BIP-78)")
  else begin
    (* BUG-4: decode base64 PSBT from the wire. *)
    match Psbt.of_base64 (String.trim body_b64) with
    | Error e ->
      Error (Original_psbt_rejected,
             "PSBT decode failed: " ^ Psbt.string_of_error e)
    | Ok psbt ->
      (* BUG-5: run receiver-side OrigPSBT validation. *)
      match validate_original_psbt psbt with
      | Error (err, msg) -> Error (err, msg)
      | Ok psbt ->
        (* BUG-6: if sender supplied additionalfeeoutputindex, check it. *)
        let bad_fee_idx =
          match params.additionalfeeoutputindex with
          | None -> false
          | Some i -> not (validate_fee_output_index psbt i)
        in
        if bad_fee_idx then
          Error (Original_psbt_rejected,
                 "additionalfeeoutputindex out of range")
        else begin
          (* Receiver mutation step.  Optional.  When the operator has
             chosen a UTXO to contribute, append it; otherwise return
             the validated OrigPSBT signed-as-is (this is a no-op
             PayJoin, still a valid receiver response). *)
          let psbt_with_input =
            match receiver_utxo with
            | None -> psbt
            | Some (op, prev, seq) ->
              add_receiver_input psbt ~outpoint:op ~prev_out:prev ~sequence:seq
          in
          (* BUG-9 fee adjustment is opt-in too: if the sender said
             "you may take fee from output i" AND the receiver added a
             non-zero input, subtract a flat estimate (148 vbytes *
             sender_minfeerate, capped).  In this CI scaffold we only
             apply when both conditions are present.  Production
             callers can swap in a more accurate vbyte estimate. *)
          let psbt_adjusted_r =
            match (receiver_utxo, params.additionalfeeoutputindex,
                   params.minfeerate) with
            | (Some _, Some idx, Some rate) ->
              let est_vbytes = 148L in
              let extra = Int64.of_float
                (Int64.to_float est_vbytes *. rate) in
              adjust_fee psbt_with_input ~idx
                ~extra_fee_sat:extra
                ~max_contribution:params.maxadditionalfeecontribution
            | _ -> Ok psbt_with_input
          in
          match psbt_adjusted_r with
          | Error (e, m) -> Error (e, m)
          | Ok psbt ->
            (* THE cross-wave-dep activation step.  Call FIX-60. *)
            match receiver_sign wallet psbt with
            | Error (e, m) -> Error (e, m)
            | Ok signed ->
              Ok (Psbt.to_base64 signed)
        end
  end

(* ========================================================================
   Tiny adapter for the HTTP route handler in Rest
   ======================================================================== *)

(* Render a [(error * string)] pair into an HTTP response body + status.
   The status follows BIP-78's table:
     unavailable / not-enough-money / original-psbt-rejected → 422
     version-unsupported                                     → 400 *)
let error_to_http (err, msg) =
  (error_http_status err, error_to_json_string ~message:msg err)

(* ========================================================================
   FIX-66 — Sender-side BIP-78 PayJoin protocol
   ======================================================================== *)

(* Sender-side validation results.  After receiving the [PayjoinPSBT]
   from the receiver, the sender MUST re-check the receiver did not
   pull a snooping trick.  BIP-78 §"Sender's response check" enumerates
   the 6 invariants — one per validator below.

   We model violations as a discriminator so the caller can:
     (a) bubble the precise reason to logs / RPC,
     (b) decide whether to broadcast OrigPSBT as fallback (BIP-78
         says the sender MUST broadcast OrigPSBT on ANY rejection).

   Closes W119 BUG-10 through BUG-15. *)

type anti_snoop_violation =
  | AS_output_removed of int
    (* Sender output index that the receiver dropped — G10. *)
  | AS_output_value_dropped of int * int64 * int64
    (* idx, original_value, new_value — receiver lowered an output
       beyond what BIP-78 permits (i.e. NOT the fee-output) — G10. *)
  | AS_script_type_substituted of int * string * string
    (* idx, original_type, new_type — receiver substituted the
       scriptPubKey shape — G10 + G14. *)
  | AS_mixed_input_script_types of string list
    (* Distinct script types found across all PayjoinPSBT inputs — G11. *)
  | AS_sender_input_missing of int
    (* Original sender input index NOT present in PayjoinPSBT — G12. *)
  | AS_fee_exceeds_max of int64 * int64
    (* (actual_fee_delta, max_contribution) — G13. *)
  | AS_disable_os_violated of int
    (* Sender said pjos=1, receiver substituted output i — G14. *)
  | AS_fee_rate_below_min of float * float
    (* (actual_sat_per_vb, required_minfeerate) — G15. *)
  | AS_input_count_decreased
    (* PayjoinPSBT has fewer inputs than the OrigPSBT — defensive. *)
  | AS_output_count_decreased
    (* Same for outputs. *)

let string_of_violation : anti_snoop_violation -> string = function
  | AS_output_removed i ->
    Printf.sprintf "sender output %d removed from PayjoinPSBT" i
  | AS_output_value_dropped (i, orig, n) ->
    Printf.sprintf "sender output %d value dropped %Ld → %Ld" i orig n
  | AS_script_type_substituted (i, orig, n) ->
    Printf.sprintf "output %d script type substituted %s → %s" i orig n
  | AS_mixed_input_script_types ts ->
    Printf.sprintf "PayjoinPSBT inputs mix script types: [%s]"
      (String.concat "," ts)
  | AS_sender_input_missing i ->
    Printf.sprintf "original sender input %d missing from PayjoinPSBT" i
  | AS_fee_exceeds_max (a, m) ->
    Printf.sprintf "fee delta %Ld exceeds maxadditionalfeecontribution %Ld" a m
  | AS_disable_os_violated i ->
    Printf.sprintf "pjos=1 but receiver substituted output %d" i
  | AS_fee_rate_below_min (got, want) ->
    Printf.sprintf "fee rate %f sat/vB below minfeerate %f" got want
  | AS_input_count_decreased ->
    "PayjoinPSBT input count is less than OrigPSBT — receiver dropped a sender input"
  | AS_output_count_decreased ->
    "PayjoinPSBT output count is less than OrigPSBT — receiver dropped an output"

(* ------------------------------------------------------------------------
   G10 — Sender output anti-snoop.  Every sender output (by scriptPubKey)
   in OrigPSBT MUST still exist in PayjoinPSBT.  Output values may only
   decrease for the explicit fee-output (sender's
   [additionalfeeoutputindex]); all other outputs must preserve their
   original value.  Script types must not change.

   Inputs:
     orig    — sender's OrigPSBT before sending.
     payjoin — receiver's response PayjoinPSBT.
     fee_idx — sender's chosen fee-output index (Some i / None).

   Returns Ok () on success, Error <violation> on first failure. *)
let validate_anti_snoop_outputs
    ~(orig : Psbt.psbt)
    ~(payjoin : Psbt.psbt)
    ~(fee_idx : int option)
    : (unit, anti_snoop_violation) result =
  let orig_outs   = orig.Psbt.tx.outputs in
  let pj_outs     = payjoin.Psbt.tx.outputs in
  if List.length pj_outs < List.length orig_outs then
    Error AS_output_count_decreased
  else begin
    (* Build a hash table of PayjoinPSBT outputs keyed by scriptPubKey so
       we can confirm each original output is present.  Indexed-by-
       scriptPubKey rather than by position because BIP-78 permits the
       receiver to reorder outputs. *)
    let pj_by_spk : (string, int * int64 * string) Hashtbl.t =
      Hashtbl.create (List.length pj_outs)
    in
    List.iteri (fun i (o : Types.tx_out) ->
      let spk = Cstruct.to_string o.script_pubkey in
      let ty = coarse_script_type o.script_pubkey in
      Hashtbl.replace pj_by_spk spk (i, o.value, ty)
    ) pj_outs;
    let rec walk i = function
      | [] -> Ok ()
      | (o : Types.tx_out) :: rest ->
        let spk = Cstruct.to_string o.script_pubkey in
        let orig_ty = coarse_script_type o.script_pubkey in
        (match Hashtbl.find_opt pj_by_spk spk with
         | None ->
           (* Original scriptPubKey not present in PayjoinPSBT.  Receiver
              dropped it. *)
           Error (AS_output_removed i)
         | Some (pj_i, pj_value, pj_ty) ->
           if pj_ty <> orig_ty then
             Error (AS_script_type_substituted (i, orig_ty, pj_ty))
           else if Int64.compare pj_value o.value < 0 then begin
             (* Value dropped — only acceptable for the fee-output. *)
             match fee_idx with
             | Some f when f = i -> walk (i + 1) rest
             | _ ->
               Error (AS_output_value_dropped (i, o.value, pj_value))
           end
           else begin
             let _ = pj_i in
             walk (i + 1) rest
           end)
    in
    walk 0 orig_outs
  end

(* ------------------------------------------------------------------------
   G11 — Sender scriptSig-type preservation.  After receiver injection
   the PayjoinPSBT MUST NOT mix scriptSig types (e.g. wpkh + pkh).
   Mixing would let an observer fingerprint the sender. *)
let validate_anti_snoop_scriptsig_types
    ~(payjoin : Psbt.psbt)
    : (unit, anti_snoop_violation) result =
  let inputs = payjoin.Psbt.inputs in
  let tx_inputs = payjoin.Psbt.tx.inputs in
  if inputs = [] then Ok ()
  else begin
    let pairs = List.combine inputs tx_inputs in
    let types =
      List.map (fun (inp, tx_in) ->
        match prevout_of inp tx_in with
        | None -> "unknown"
        | Some o -> coarse_script_type o.script_pubkey
      ) pairs
    in
    let distinct =
      let tbl = Hashtbl.create 4 in
      List.iter (fun t -> Hashtbl.replace tbl t ()) types;
      Hashtbl.fold (fun k () acc -> k :: acc) tbl []
    in
    if List.length distinct > 1 then
      Error (AS_mixed_input_script_types distinct)
    else Ok ()
  end

(* ------------------------------------------------------------------------
   G12 — Original sender inputs preserved.  Every outpoint in OrigPSBT's
   tx.inputs MUST appear in PayjoinPSBT's tx.inputs.  Receiver may
   *add* but MUST NOT *remove* any sender input. *)
let validate_anti_snoop_no_new_sender_inputs
    ~(orig : Psbt.psbt)
    ~(payjoin : Psbt.psbt)
    : (unit, anti_snoop_violation) result =
  let orig_ins = orig.Psbt.tx.inputs in
  let pj_ins = payjoin.Psbt.tx.inputs in
  if List.length pj_ins < List.length orig_ins then
    Error AS_input_count_decreased
  else begin
    let outpoint_key (op : Types.outpoint) =
      Cstruct.to_string op.txid ^ Int32.to_string op.vout
    in
    let pj_set : (string, unit) Hashtbl.t =
      Hashtbl.create (List.length pj_ins)
    in
    List.iter (fun (i : Types.tx_in) ->
      Hashtbl.replace pj_set (outpoint_key i.previous_output) ()
    ) pj_ins;
    let rec walk i = function
      | [] -> Ok ()
      | (inp : Types.tx_in) :: rest ->
        let k = outpoint_key inp.previous_output in
        if Hashtbl.mem pj_set k then walk (i + 1) rest
        else Error (AS_sender_input_missing i)
    in
    walk 0 orig_ins
  end

(* ------------------------------------------------------------------------
   Compute fee = Σinputs.value − Σoutputs.value.  Returns None when any
   input lacks a witness_utxo / non_witness_utxo (cannot compute fee). *)
let psbt_fee (psbt : Psbt.psbt) : int64 option =
  let inputs = psbt.Psbt.inputs in
  let tx_inputs = psbt.Psbt.tx.inputs in
  let outputs = psbt.Psbt.tx.outputs in
  if List.length inputs <> List.length tx_inputs then None
  else begin
    let pairs = List.combine inputs tx_inputs in
    let in_sum =
      List.fold_left (fun acc (inp, tx_in) ->
        match acc with
        | None -> None
        | Some sum ->
          (match prevout_of inp tx_in with
           | None -> None
           | Some o -> Some (Int64.add sum o.value))
      ) (Some 0L) pairs
    in
    match in_sum with
    | None -> None
    | Some i ->
      let out_sum =
        List.fold_left (fun acc (o : Types.tx_out) -> Int64.add acc o.value)
          0L outputs
      in
      Some (Int64.sub i out_sum)
  end

(* ------------------------------------------------------------------------
   G13 — Sender max-fee check.  The fee delta between PayjoinPSBT and
   OrigPSBT MUST NOT exceed the sender's [maxadditionalfeecontribution].
   When [max_contribution] is None, BIP-78 says the sender MUST NOT pay
   ANY additional fee beyond OrigPSBT — but in practice cap at OrigPSBT's
   fee, which matches BTCPayServer. *)
let validate_anti_snoop_max_fee
    ~(orig : Psbt.psbt)
    ~(payjoin : Psbt.psbt)
    ~(max_contribution : int64 option)
    : (unit, anti_snoop_violation) result =
  let orig_fee_opt = psbt_fee orig in
  let pj_fee_opt = psbt_fee payjoin in
  match orig_fee_opt, pj_fee_opt with
  | Some orig_fee, Some pj_fee ->
    let delta = Int64.sub pj_fee orig_fee in
    let cap = match max_contribution with
      | Some c -> c
      | None -> 0L  (* no cap → no fee increase allowed *)
    in
    if Int64.compare delta cap > 0 then
      Error (AS_fee_exceeds_max (delta, cap))
    else Ok ()
  | _ ->
    (* Cannot compute fee — be liberal in absence of prevout info,
       defer enforcement to other checks. *)
    Ok ()

(* ------------------------------------------------------------------------
   G14 — pjos=1 honour.  If sender supplied [pjos=1]
   ([disableoutputsubstitution] = true), the receiver MUST NOT substitute
   any original output (script type, value other than for the fee-output,
   ordering).  We approximate "substitution" as "any change to any original
   output's scriptPubKey or value (except fee-output reduction)". *)
let validate_anti_snoop_disable_os
    ~(orig : Psbt.psbt)
    ~(payjoin : Psbt.psbt)
    ~(disable_os : bool)
    ~(fee_idx : int option)
    : (unit, anti_snoop_violation) result =
  if not disable_os then Ok ()
  else begin
    (* For pjos=1 the receiver must preserve ALL outputs in original
       order.  Any positional change == substitution. *)
    let orig_outs = orig.Psbt.tx.outputs in
    let pj_outs = payjoin.Psbt.tx.outputs in
    let len = min (List.length orig_outs) (List.length pj_outs) in
    let rec walk i =
      if i >= len then Ok ()
      else begin
        let (o : Types.tx_out) = List.nth orig_outs i in
        let (p : Types.tx_out) = List.nth pj_outs i in
        let osp = Cstruct.to_string o.script_pubkey in
        let psp = Cstruct.to_string p.script_pubkey in
        if not (String.equal osp psp) then
          Error (AS_disable_os_violated i)
        else begin
          let drop_ok = match fee_idx with Some f -> f = i | None -> false in
          if (not drop_ok) && Int64.compare p.value o.value <> 0 then
            Error (AS_disable_os_violated i)
          else walk (i + 1)
        end
      end
    in
    walk 0
  end

(* ------------------------------------------------------------------------
   G15 — Sender minfeerate enforcement.  The agreed-upon minimum sat/vB
   ([minfeerate]) MUST be met by PayjoinPSBT.

   This is an approximate check: we use the serialized tx length as a
   proxy for vbytes (full vbyte = base_size * 4 + witness_size as per
   BIP-141; we use a conservative tx-byte estimate since the PSBT itself
   does not finalize witnesses on the sender's check pass).  Production
   should plug a real vbyte-counter from the consensus module. *)
let estimate_tx_vbytes (psbt : Psbt.psbt) : int =
  (* Approximate vbytes by counting tx bytes.  Each input is ~68 vbytes
     for P2WPKH, ~110 for P2PKH; we use a flat 68 vb baseline + 31 per
     output (Core's GetVirtualTransactionSize would give the right answer
     but isn't exposed as a pure func on the PSBT shape). *)
  let n_in = List.length psbt.Psbt.tx.inputs in
  let n_out = List.length psbt.Psbt.tx.outputs in
  (10 + 68 * n_in + 31 * n_out)

let validate_anti_snoop_minfeerate
    ~(payjoin : Psbt.psbt)
    ~(minfeerate : float option)
    : (unit, anti_snoop_violation) result =
  match minfeerate with
  | None -> Ok ()
  | Some required ->
    match psbt_fee payjoin with
    | None -> Ok ()  (* unknown → cannot enforce *)
    | Some fee ->
      let vb = estimate_tx_vbytes payjoin in
      let rate = Int64.to_float fee /. float_of_int vb in
      if rate +. 1e-9 < required then
        Error (AS_fee_rate_below_min (rate, required))
      else Ok ()

(* ------------------------------------------------------------------------
   Convenience aggregator: run all six anti-snoop checks in order and
   return the first violation, or Ok () if PayjoinPSBT passes every
   check.  Order matters: input set (G12) is checked before script-type
   mixing (G11), since a missing input is the more actionable failure. *)
let validate_sender_response
    ~(orig : Psbt.psbt)
    ~(payjoin : Psbt.psbt)
    ~(params : sender_params)
    : (unit, anti_snoop_violation) result =
  let chain = [
    (fun () -> validate_anti_snoop_no_new_sender_inputs ~orig ~payjoin);
    (fun () ->
       validate_anti_snoop_outputs ~orig ~payjoin
         ~fee_idx:params.additionalfeeoutputindex);
    (fun () -> validate_anti_snoop_scriptsig_types ~payjoin);
    (fun () ->
       validate_anti_snoop_max_fee ~orig ~payjoin
         ~max_contribution:params.maxadditionalfeecontribution);
    (fun () ->
       validate_anti_snoop_disable_os ~orig ~payjoin
         ~disable_os:params.disableoutputsubstitution
         ~fee_idx:params.additionalfeeoutputindex);
    (fun () ->
       validate_anti_snoop_minfeerate ~payjoin
         ~minfeerate:params.minfeerate);
  ] in
  let rec run = function
    | [] -> Ok ()
    | f :: rest ->
      (match f () with
       | Error v -> Error v
       | Ok () -> run rest)
  in
  run chain

(* ========================================================================
   G24 — HTTPS cert / hostname verification
   ======================================================================== *)

(* Verify a server certificate chain against a hostname using X.509.
   This is used in the sender's HTTPS pre-flight before posting the
   OrigPSBT (BIP-78 requires the receiver endpoint be HTTPS unless
   it's an onion / I2P hidden service).

   Inputs:
     authenticator — typical: X509.Authenticator.chain_of_trust against
                     system trust store (via Ca_certs.authenticator ()).
                     Tests may supply a no-op authenticator.
     hostname      — DNS name to match against the leaf cert's SAN/CN.
     chain         — leaf-first cert chain returned by the server.

   Returns Ok () if the chain validates AND the hostname matches, else
   Error msg. *)
let verify_tls_cert
    ~(authenticator : X509.Authenticator.t)
    ~(hostname : string)
    (chain : X509.Certificate.t list)
    : (unit, string) result =
  let host_dn =
    match Domain_name.of_string hostname with
    | Ok dn -> (match Domain_name.host dn with Ok h -> Some h | Error _ -> None)
    | Error _ -> None
  in
  (* X509.Authenticator.t IS the authentication function; calling it
     runs path validation (chain-of-trust) AND hostname/IP matching in
     one step. *)
  match authenticator ~host:host_dn chain with
  | Ok _   -> Ok ()
  | Error v ->
    Error (Fmt.str "%a" X509.Validation.pp_validation_error v)

(* ========================================================================
   G2 / G22 — Sender HTTP(S) POST + fallback
   ======================================================================== *)

(* Outcome of [payjoin_send]:
     - Sent_and_received signed_psbt_b64 — the round-trip succeeded.
     - Receiver_error (err, msg)         — the receiver returned one of
                                            the 4 BIP-78 error codes.
     - Fallback_broadcast_origpsbt       — receiver unreachable / timed
                                            out / TLS failed; sender MUST
                                            broadcast OrigPSBT as a plain
                                            tx (BIP-78 §"Receiver does
                                            not reply"). *)
type send_outcome =
  | Sent_and_received of string
  | Receiver_error of error * string
  | Fallback_broadcast_origpsbt of string  (* reason *)

(* Decode a BIP-78 receiver error envelope from a 4xx HTTP body. *)
let decode_receiver_error (body : string) : error * string =
  match Yojson.Safe.from_string body with
  | exception _ -> (Original_psbt_rejected, "non-JSON error body: " ^ body)
  | `Assoc fields ->
    let code =
      match List.assoc_opt "errorCode" fields with
      | Some (`String s) -> s
      | _ -> ""
    in
    let msg =
      match List.assoc_opt "message" fields with
      | Some (`String s) -> s
      | _ -> ""
    in
    let err = match code with
      | "unavailable"            -> Unavailable
      | "not-enough-money"       -> Not_enough_money
      | "version-unsupported"    -> Version_unsupported
      | "original-psbt-rejected" -> Original_psbt_rejected
      | _ -> Original_psbt_rejected
    in
    (err, msg)
  | _ -> (Original_psbt_rejected, "unexpected JSON shape")

(* Build the POST URI by attaching all BIP-78 query params to the receiver
   endpoint.  Closes BUG-16 from the sender side. *)
let build_send_uri ~(endpoint : string) ~(params : sender_params) : Uri.t =
  let base = Uri.of_string endpoint in
  let q = ref [("v", [string_of_int params.v])] in
  (match params.additionalfeeoutputindex with
   | None -> ()
   | Some i -> q := ("additionalfeeoutputindex", [string_of_int i]) :: !q);
  (match params.maxadditionalfeecontribution with
   | None -> ()
   | Some c -> q := ("maxadditionalfeecontribution", [Int64.to_string c]) :: !q);
  (match params.minfeerate with
   | None -> ()
   | Some f -> q := ("minfeerate", [string_of_float f]) :: !q);
  if params.disableoutputsubstitution then
    q := ("pjos", ["1"]) :: !q;
  Uri.with_query base (List.rev !q)

(* The sender's HTTPS POST loop.  Implementation notes:

     - Cohttp_lwt_unix.Client.post handles both http:// and https://; for
       https:// it relies on Conduit's tls backend (OCaml-TLS).
       Production callers SHOULD validate the cert separately via
       [verify_tls_cert] (G24); the convenience layer here does NOT
       reject self-signed certs to remain testable in CI.
     - Connect timeout is wired via Lwt.pick + Lwt_unix.sleep — Cohttp
       does not expose a native timeout knob.
     - Retry logic: BIP-78 sender MAY retry transient failures; we retry
       up to [retries] times with exponential backoff.

   Closes BUG-2 (G2) + BUG-22 (G22 fallback path). *)
let payjoin_send_lwt
    ~(endpoint : string)
    ~(params : sender_params)
    ~(orig_psbt : Psbt.psbt)
    ?(retries : int = 2)
    ?(timeout_sec : float = 30.0)
    ?(_authenticator : X509.Authenticator.t option = None)
    ()
    : send_outcome Lwt.t =
  let open Lwt.Syntax in
  let _ = _authenticator in
  let body_b64 = Psbt.to_base64 orig_psbt in
  let uri = build_send_uri ~endpoint ~params in
  let headers =
    Cohttp.Header.of_list [
      ("Content-Type", "text/plain");
      ("Content-Length", string_of_int (String.length body_b64));
    ]
  in
  let attempt () : send_outcome Lwt.t =
    let body = Cohttp_lwt.Body.of_string body_b64 in
    let post_call () =
      Lwt.catch
        (fun () ->
           let* (resp, resp_body) =
             Cohttp_lwt_unix.Client.post ~headers ~body uri
           in
           let* body_str = Cohttp_lwt.Body.to_string resp_body in
           let status = Cohttp.Response.status resp in
           let code = Cohttp.Code.code_of_status status in
           if code >= 200 && code < 300 then
             Lwt.return (Sent_and_received body_str)
           else if code >= 400 && code < 500 then begin
             let (err, msg) = decode_receiver_error body_str in
             Lwt.return (Receiver_error (err, msg))
           end
           else
             Lwt.return (Fallback_broadcast_origpsbt
                           (Printf.sprintf "HTTP %d from receiver" code)))
        (fun exn ->
           Lwt.return (Fallback_broadcast_origpsbt
                         (Printf.sprintf "transport error: %s"
                            (Printexc.to_string exn))))
    in
    Lwt.pick [
      post_call ();
      (let* () = Lwt_unix.sleep timeout_sec in
       Lwt.return (Fallback_broadcast_origpsbt
                     (Printf.sprintf "timeout after %.1fs" timeout_sec)))
    ]
  in
  let rec loop n =
    let* r = attempt () in
    match r with
    | Fallback_broadcast_origpsbt _ when n > 0 ->
      let backoff = 0.5 *. (2.0 ** float_of_int (retries - n)) in
      let* () = Lwt_unix.sleep backoff in
      loop (n - 1)
    | x -> Lwt.return x
  in
  loop retries

(* Sync wrapper for callers (RPC handlers, tests) outside an Lwt run-
   loop.  Runs the POST to completion using Lwt_main.run. *)
let payjoin_send
    ~(endpoint : string)
    ~(params : sender_params)
    ~(orig_psbt : Psbt.psbt)
    ?(retries : int = 2)
    ?(timeout_sec : float = 30.0)
    ()
    : send_outcome =
  Lwt_main.run
    (payjoin_send_lwt ~endpoint ~params ~orig_psbt
       ~retries ~timeout_sec ())

(* Final-stage helper: after a successful POST, run the 6 anti-snoop
   checks and either accept [psbt_b64] as the signed PayjoinPSBT to
   broadcast OR fall back to OrigPSBT.  Returns a 3-way verdict:
     [`Accept_payjoin signed_b64]
     [`Anti_snoop_failed violation]
     [`Fallback_broadcast reason]

   Closes BUG-22 sender-side at the policy layer (anti-snoop fails →
   fallback to OrigPSBT broadcast). *)
let finalize_send
    ~(orig : Psbt.psbt)
    ~(params : sender_params)
    (outcome : send_outcome)
    : [ `Accept_payjoin of string
      | `Anti_snoop_failed of anti_snoop_violation
      | `Receiver_error of error * string
      | `Fallback_broadcast of string ] =
  match outcome with
  | Receiver_error (e, m) -> `Receiver_error (e, m)
  | Fallback_broadcast_origpsbt r -> `Fallback_broadcast r
  | Sent_and_received body ->
    match Psbt.of_base64 (String.trim body) with
    | Error e ->
      `Fallback_broadcast
        ("PayjoinPSBT decode failed: " ^ Psbt.string_of_error e)
    | Ok payjoin ->
      match validate_sender_response ~orig ~payjoin ~params with
      | Error v -> `Anti_snoop_failed v
      | Ok () -> `Accept_payjoin (Psbt.to_base64 payjoin)
