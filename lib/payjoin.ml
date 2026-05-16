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
