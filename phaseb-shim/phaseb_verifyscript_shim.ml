(* Phase B `verifyscript` shim for camlcoin.
 *
 * Drives camlcoin's real consensus interpreter
 * (lib/script.ml: verify_script, :2569) against the Phase B bounded
 * reject-bar harness (tools/phaseb-vectors).
 *
 * It reconstructs the SAME crediting + spending transaction pair Core
 * builds for its VerifyScript vectors
 * (bitcoin-core/src/test/util/transaction_utils.cpp:
 *  BuildCreditingTransaction / BuildSpendingTransaction) so that any
 * signature-dependent rows compute an identical sighash, then runs
 * camlcoin's real Script.verify_script with the prevout (amount,
 * scriptPubKey) supplied for BIP-143 / BIP-341 sighash.
 *
 * Protocol (line-delimited JSON on stdin/stdout):
 *
 *   request:  {"op":"verifyscript",
 *              "scriptSig_hex":"...","scriptPubKey_hex":"...",
 *              "witness":["hex",...],"amount_sats":0,
 *              "flags":["P2SH","WITNESS",...]}
 *   response: {"result":true}                  (accept)
 *             {"result":false,"reason":"..."}  (reject)
 *             {"error":"..."}                  (could not evaluate / unmapped flag)
 *)

module Script = Camlcoin.Script
module Types = Camlcoin.Types
module Crypto = Camlcoin.Crypto
module Serialize = Camlcoin.Serialize
module Validation = Camlcoin.Validation
module Consensus = Camlcoin.Consensus

(* hex string -> Cstruct.t *)
let hex_decode (s : string) : Cstruct.t =
  let n = String.length s in
  if n mod 2 <> 0 then failwith (Printf.sprintf "odd hex length: %d" n);
  let out = Cstruct.create (n / 2) in
  let nibble c =
    match c with
    | '0' .. '9' -> Char.code c - Char.code '0'
    | 'a' .. 'f' -> Char.code c - Char.code 'a' + 10
    | 'A' .. 'F' -> Char.code c - Char.code 'A' + 10
    | _ -> failwith (Printf.sprintf "bad hex char %C" c)
  in
  for i = 0 to (n / 2) - 1 do
    let hi = nibble s.[2 * i] in
    let lo = nibble s.[(2 * i) + 1] in
    Cstruct.set_uint8 out i ((hi lsl 4) lor lo)
  done;
  out

(* reverse a Cstruct's bytes (Bitcoin display<->internal/wire byte order) *)
let cstruct_rev (c : Cstruct.t) : Cstruct.t =
  let n = Cstruct.length c in
  let out = Cstruct.create n in
  for i = 0 to n - 1 do
    Cstruct.set_uint8 out i (Cstruct.get_uint8 c (n - 1 - i))
  done;
  out

(* Map Core flag tokens (interpreter.cpp:2168 ScriptFlagNamesToEnum) to
   camlcoin's integer flag bitmask (lib/script.ml:116-139). Unknown token
   raises Failure so the driver records it as a shim error (skipped). *)
let flag_bit (name : string) : int =
  match name with
  | "P2SH" -> Script.script_verify_p2sh
  | "STRICTENC" -> Script.script_verify_strictenc
  | "DERSIG" -> Script.script_verify_dersig
  | "LOW_S" -> Script.script_verify_low_s
  | "SIGPUSHONLY" -> Script.script_verify_sigpushonly
  | "MINIMALDATA" -> Script.script_verify_minimaldata
  | "NULLDUMMY" -> Script.script_verify_nulldummy
  | "DISCOURAGE_UPGRADABLE_NOPS" -> Script.script_verify_discourage_upgradable_nops
  | "CLEANSTACK" -> Script.script_verify_cleanstack
  | "MINIMALIF" -> Script.script_verify_minimalif
  | "NULLFAIL" -> Script.script_verify_nullfail
  | "CHECKLOCKTIMEVERIFY" -> Script.script_verify_checklocktimeverify
  | "CHECKSEQUENCEVERIFY" -> Script.script_verify_checksequenceverify
  | "WITNESS" -> Script.script_verify_witness
  | "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM" ->
      Script.script_verify_discourage_upgradable_witness
  | "WITNESS_PUBKEYTYPE" -> Script.script_verify_witness_pubkeytype
  | "CONST_SCRIPTCODE" -> Script.script_verify_const_scriptcode
  | "TAPROOT" -> Script.script_verify_taproot
  | "DISCOURAGE_UPGRADABLE_PUBKEYTYPE" ->
      Script.script_verify_discourage_upgradable_pubkeytype
  | "DISCOURAGE_OP_SUCCESS" -> Script.script_verify_discourage_op_success
  | "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION" ->
      Script.script_verify_discourage_upgradable_taproot_version
  | other -> failwith (Printf.sprintf "unknown flag token: %s" other)

let build_flags (tokens : string list) : int =
  List.fold_left (fun acc t -> acc lor flag_bit t) Script.script_verify_none tokens

(* Core's BuildCreditingTransaction (transaction_utils.cpp:10):
   version 1, locktime 0, one input with a NULL prevout and scriptSig
   OP_0 OP_0 (CScriptNum(0) << CScriptNum(0) => bytes 0x00 0x00),
   sequence 0xFFFFFFFF; one output with the test scriptPubKey + amount. *)
let null_outpoint () : Types.outpoint =
  { Types.txid = Cstruct.create 32 (* 32 zero bytes *); vout = 0xFFFFFFFFl }

let build_crediting_tx (script_pubkey : Cstruct.t) (amount : int64) :
    Types.transaction =
  let ssig = Cstruct.create 2 in
  Cstruct.set_uint8 ssig 0 0x00;
  Cstruct.set_uint8 ssig 1 0x00;
  {
    Types.version = 1l;
    inputs =
      [
        {
          Types.previous_output = null_outpoint ();
          script_sig = ssig;
          sequence = 0xFFFFFFFFl;
        };
      ];
    outputs = [ { Types.value = amount; script_pubkey } ];
    witnesses = [];
    locktime = 0l;
  }

(* Core's BuildSpendingTransaction (transaction_utils.cpp:26):
   version 1, locktime 0, one input spending credit vout 0 with the test
   scriptSig + witness, sequence 0xFFFFFFFF; one empty-script output with
   the same amount. The witness is also placed in tx.witnesses so the
   serialized spend matches Core's structure (sighash itself is driven by
   amount/prevouts, but we keep the tx faithful). *)
let build_spending_tx (script_sig : Cstruct.t) (witness : Types.tx_witness)
    (credit : Types.transaction) : Types.transaction =
  let credit_txid = Crypto.compute_txid credit in
  {
    Types.version = 1l;
    inputs =
      [
        {
          Types.previous_output = { Types.txid = credit_txid; vout = 0l };
          script_sig;
          sequence = 0xFFFFFFFFl;
        };
      ];
    outputs =
      [
        {
          Types.value = (List.hd credit.outputs).value;
          script_pubkey = Cstruct.create 0;
        };
      ];
    witnesses = [ witness ];
    locktime = 0l;
  }

let json_escape (s : string) : string =
  let buf = Buffer.create (String.length s + 8) in
  String.iter
    (fun c ->
      match c with
      | '"' -> Buffer.add_string buf "\\\""
      | '\\' -> Buffer.add_string buf "\\\\"
      | '\n' -> Buffer.add_string buf "\\n"
      | '\r' -> Buffer.add_string buf "\\r"
      | '\t' -> Buffer.add_string buf "\\t"
      | c when Char.code c < 0x20 ->
          Buffer.add_string buf (Printf.sprintf "\\u%04x" (Char.code c))
      | c -> Buffer.add_char buf c)
    s;
  Buffer.contents buf

(* op "verifyscript" (back-compat default): rebuild Core's synthetic
   credit/spend pair (transaction_utils.cpp) and run verify_script on the
   single input. Drives script_tests.json. *)
let process_verifyscript (j : Yojson.Safe.t) : string =
  let member k = Yojson.Safe.Util.member k j in
  let to_hex v = Yojson.Safe.Util.to_string v in
  let ssig = hex_decode (to_hex (member "scriptSig_hex")) in
  let spk = hex_decode (to_hex (member "scriptPubKey_hex")) in
  let amount =
    match member "amount_sats" with
    | `Int i -> Int64.of_int i
    | `Intlit s -> Int64.of_string s
    | `Null -> 0L
    | other -> Int64.of_string (Yojson.Safe.to_string other)
  in
  let witness_items =
    match member "witness" with
    | `List l -> List.map (fun v -> hex_decode (to_hex v)) l
    | `Null -> []
    | _ -> failwith "witness not a list"
  in
  let flags =
    match member "flags" with
    | `List l -> build_flags (List.map (fun v -> to_hex v) l)
    | `Null -> Script.script_verify_none
    | _ -> failwith "flags not a list"
  in
  let witness : Types.tx_witness = { Types.items = witness_items } in
  let credit = build_crediting_tx spk amount in
  let spend = build_spending_tx ssig witness credit in
  (* prevouts: (amount, scriptPubKey) for all inputs (one here) — needed
     for BIP-341 taproot sighash, and harmless for legacy/BIP-143. *)
  let prevouts = [ (amount, spk) ] in
  match
    Script.verify_script ~tx:spend ~input_index:0 ~script_pubkey:spk
      ~script_sig:ssig ~witness ~amount ~flags ~prevouts ()
  with
  | Ok true -> {|{"result":true}|}
  | Ok false -> {|{"result":false,"reason":"VerifyFailed (stack-top false)"}|}
  | Error e ->
      Printf.sprintf {|{"result":false,"reason":"%s"}|} (json_escape e)

(* op "verifytx" (tx_valid.json / tx_invalid.json): unlike verifyscript,
   these vectors give a REAL serialized multi-input tx, so the sighash is
   computed over THAT tx (transaction_tests.cpp::CheckTxScripts). Mirror
   the rustoshi-shim template (rustoshi-shim/src/main.rs::process_verifytx):
   deserialize tx_hex with camlcoin's own segwit-aware deserializer, build
   the prevout map (txid,vout)->(amount,scriptPubKey), then run camlcoin's
   real verify_script per input with the signature checker bound to THE REAL
   TX + input index + amount + all-prevouts (BIP-143/BIP-341 commitment).
   Valid iff ALL inputs pass; reject on the FIRST failing input (Core's
   `i < vin.size() && fValid` short-circuit). *)
let process_verifytx (j : Yojson.Safe.t) : string =
  let member k = Yojson.Safe.Util.member k j in
  let to_hex v = Yojson.Safe.Util.to_string v in
  let to_int64 v =
    match v with
    | `Int i -> Int64.of_int i
    | `Intlit s -> Int64.of_string s
    | `Null -> 0L
    | other -> Int64.of_string (Yojson.Safe.to_string other)
  in
  let tx_bytes = hex_decode (to_hex (member "tx_hex")) in
  let r = Serialize.reader_of_cstruct tx_bytes in
  let tx = Serialize.deserialize_transaction r in
  let flags =
    match member "flags" with
    | `List l -> build_flags (List.map (fun v -> to_hex v) l)
    | `Null -> Script.script_verify_none
    | _ -> failwith "flags not a list"
  in
  (* Build the prevout map keyed by (DISPLAY-order txid hex, vout). The
     request supplies txid as Bitcoin display-order hex; we key the lookup
     on the SAME display-order string so no reversal logic lives in the
     shim — for each tx input we render its wire-order prevout txid back to
     display order via hash256_to_hex_display. The driver already cast vout
     to a u32 (coinbase -1 -> 0xFFFFFFFF), matching the deserialized int32
     when both are read as 32 unsigned bits. amount defaults to 0 (Core). *)
  let tbl : (string * int32, int64 * Cstruct.t) Hashtbl.t = Hashtbl.create 16 in
  let prevouts_json =
    match member "prevouts" with
    | `List l -> l
    | _ -> failwith "prevouts not a list"
  in
  List.iter
    (fun p ->
      let pm k = Yojson.Safe.Util.member k p in
      let txid_hex = to_hex (pm "txid") in
      let vout =
        match pm "vout" with
        | `Int i -> Int32.of_int i
        | `Intlit s -> Int32.of_string s
        | other -> Int32.of_string (Yojson.Safe.to_string other)
      in
      let spk = hex_decode (to_hex (pm "scriptPubKey_hex")) in
      let amount = to_int64 (pm "amount_sats") in
      Hashtbl.replace tbl (txid_hex, vout) (amount, spk))
    prevouts_json;
  (* Assemble per-input (amount, scriptPubKey) in the tx's own input order
     so verify_script's ~prevouts lines up with input i (BIP-341 commits to
     ALL prevouts). A prevout missing from the map => malformed row =>
     failwith => {"error"} so the driver SKIPS it (never fake-pass). *)
  let inputs = Array.of_list tx.Types.inputs in
  let n = Array.length inputs in
  let per_input =
    Array.map
      (fun (input : Types.tx_in) ->
        let key =
          ( Types.hash256_to_hex_display input.previous_output.txid,
            input.previous_output.vout )
        in
        match Hashtbl.find_opt tbl key with
        | Some pv -> pv
        | None ->
            failwith
              (Printf.sprintf "no prevout for input %s:%lu"
                 (Types.hash256_to_hex_display input.previous_output.txid)
                 input.previous_output.vout))
      inputs
  in
  let prevouts = Array.to_list (Array.map (fun (a, s) -> (a, s)) per_input) in
  let witnesses = Array.of_list tx.Types.witnesses in
  let n_wit = Array.length witnesses in
  (* Per-input VerifyScript over the real tx; reject on first failure. *)
  let rec loop i =
    if i >= n then {|{"valid":true}|}
    else begin
      let input = inputs.(i) in
      let amount, spk = per_input.(i) in
      (* tx.witnesses is empty for a non-segwit tx, else one stack per input
         in input order. *)
      let witness : Types.tx_witness =
        if n_wit = 0 then { Types.items = [] }
        else if i < n_wit then witnesses.(i)
        else { Types.items = [] }
      in
      match
        Script.verify_script ~tx ~input_index:i ~script_pubkey:spk
          ~script_sig:input.script_sig ~witness ~amount ~flags ~prevouts ()
      with
      | Ok true -> loop (i + 1)
      | Ok false ->
          Printf.sprintf {|{"valid":false,"reason":"input %d: %s"}|} i
            (json_escape "VerifyFailed (stack-top false)")
      | Error e ->
          Printf.sprintf {|{"valid":false,"reason":"input %d: %s"}|} i
            (json_escape e)
    end
  in
  loop 0

(* op "checktx" (tx_invalid BADTX rows + tx_valid checktx invariant):
   CheckTransaction-level, CONTEXT-FREE structural validation. Mirrors
   bitcoin-core/src/consensus/tx_check.cpp::CheckTransaction — the checks
   `verifytx` (per-input VerifyScript only) cannot catch: empty vin/vout,
   output value range + running total, duplicate inputs, oversize,
   non-coinbase null prevout, and coinbase scriptSig length.

   It delegates to camlcoin's OWN consensus code (lib/validation.ml), so a
   divergence here is a camlcoin CheckTransaction bug, NOT a shim bug. No
   UTXO/chain state is needed. Two camlcoin design facts shape the call:

   1. `Validation.check_transaction` takes an `?is_coinbase` flag (default
      false) instead of detecting coinbase internally the way Core's
      CheckTransaction does (`tx.IsCoinBase()`). With the default, a
      coinbase-shaped tx (single null-prevout input) is rejected as
      `TxNullPrevout` and the bad-cb-length check is never reached — which
      would WRONGLY reject the structurally-valid coinbase rows in
      tx_valid.json (idx 49/52). So we first detect coinbase via camlcoin's
      own `Validation.is_coinbase_tx` and pass `~is_coinbase` accordingly,
      exactly mirroring Core's `if (tx.IsCoinBase()) ... else ...` branch.

   2. camlcoin's bad-cb-length rule (scriptSig length in [2,100],
      tx_check.cpp:49) lives in `Validation.check_coinbase`, not in
      `check_transaction`. `check_coinbase` also folds in context-DEPENDENT
      BIP-34 height encoding, gated on `height >= network.bip34_height`. We
      call it with `~network:Consensus.mainnet` and `height = 0`, which is
      below mainnet's bip34_height (227931), so the BIP-34 branch is skipped
      and `check_coinbase` reduces to exactly the context-free coinbase
      structural checks (one input, null outpoint, scriptSig length 2..100)
      — i.e. Core's coinbase branch of CheckTransaction. This reuses
      camlcoin's real consensus code for bad-cb-length rather than
      reimplementing the [2,100] bound in the shim.

   A tx is structurally VALID iff `check_transaction` accepts AND (for a
   coinbase) `check_coinbase` accepts; reject on the first failing check,
   matching Core's early-return order. *)
let process_checktx (j : Yojson.Safe.t) : string =
  let member k = Yojson.Safe.Util.member k j in
  let to_hex v = Yojson.Safe.Util.to_string v in
  let tx_bytes = hex_decode (to_hex (member "tx_hex")) in
  let r = Serialize.reader_of_cstruct tx_bytes in
  let tx = Serialize.deserialize_transaction r in
  let is_coinbase = Validation.is_coinbase_tx tx in
  match Validation.check_transaction ~is_coinbase tx with
  | Error e ->
      Printf.sprintf {|{"valid":false,"reason":"%s"}|}
        (json_escape (Validation.tx_error_to_string e))
  | Ok () ->
      if is_coinbase then
        (* Apply camlcoin's own bad-cb-length rule via check_coinbase with
           height=0 (< bip34_height) so only the context-free coinbase
           structural checks run. *)
        (match
           Validation.check_coinbase ~network:Consensus.mainnet tx 0
         with
        | Error e ->
            Printf.sprintf {|{"valid":false,"reason":"%s"}|}
              (json_escape (Validation.tx_error_to_string e))
        | Ok () -> {|{"valid":true}|})
      else {|{"valid":true}|}

(* op "connecttx" (Phase B connect-time ECONOMIC differential): drive
   camlcoin's REAL connect-time Consensus::CheckTxInputs equivalent
   (bitcoin-core/src/consensus/tx_verify.cpp:164-214) — the no-inflation rule
   (value-in >= value-out, bad-txns-in-belowout) + per-input & running-sum
   MoneyRange (bad-txns-inputvalues-outofrange) + coinbase maturity 100
   (bad-txns-premature-spend-of-coinbase) + missing/spent inputs
   (bad-txns-inputs-missingorspent).

   CRITICAL per-impl wiring: camlcoin's `Validation.validate_tx_inputs` ALONE
   returns total_in WITHOUT the value-in >= value-out no-inflation check
   (driving it alone = a real inflation false-accept). So we drive the REAL
   composite that connect-time validation actually uses:

     valid  IFF  Validation.validate_tx_inputs = Ok            (maturity / MoneyRange / missing)
             AND  Validation.calculate_tx_fee   = Some f        (the no-inflation Some/None: total_in>=total_out)
             AND  Consensus.is_valid_money f                    (fee in MoneyRange)

   We do NOT re-implement value-in>=out / maturity / missing in the shim — each
   of the three real predicates is camlcoin's own consensus code, so a crafted
   reject returning valid=true is a genuine camlcoin false-accept finding.

   SCRIPT verification is isolated OUT (~skip_scripts:true on
   validate_tx_inputs) so a script failure cannot mask the ECONOMIC verdict —
   this op scores only the connect-time economic decision, exactly as Core's
   CheckTxInputs is amount-only (script checks live in CheckInputScripts).

   In-memory UTXO VIEW: one coin per prevout entry (value + height +
   is_coinbase). The lookup is keyed on the prevout txid in Bitcoin DISPLAY
   order; for each tx input we render its wire-order prevout txid back to
   display via hash256_to_hex_display (reusing the verifytx prevout plumbing —
   no reversal logic in the shim). An OMITTED prevout (absent from the view)
   models a missing/spent input → lookup returns None → TxMissingInputs.

   request:  {"op":"connecttx","tx_hex":"<segwit-aware>",
              "prevouts":[{"txid":"<DISPLAY-hex>","vout":N,
                           "scriptPubKey_hex":"<spk>","value_sats":<i64>,
                           "height":<int coin.nHeight>,"is_coinbase":<bool>}],
              "spend_height":<int nSpendHeight>}
   response: {"valid":true,"fee_sats":<i64>}
             {"valid":false,"reason":"<bad-txns-*>"}
             {"error":"..."}   (could not evaluate -> driver SKIPS) *)
let process_connecttx (j : Yojson.Safe.t) : string =
  let member k = Yojson.Safe.Util.member k j in
  let to_hex v = Yojson.Safe.Util.to_string v in
  let to_int64 v =
    match v with
    | `Int i -> Int64.of_int i
    | `Intlit s -> Int64.of_string s
    | `Null -> 0L
    | other -> Int64.of_string (Yojson.Safe.to_string other)
  in
  let to_int v =
    match v with
    | `Int i -> i
    | `Intlit s -> int_of_string s
    | `String s -> int_of_string s
    | other -> failwith (Printf.sprintf "expected int, got %s" (Yojson.Safe.to_string other))
  in
  let to_bool v =
    match v with
    | `Bool b -> b
    | `Int i -> i <> 0
    | `Null -> false
    | other -> failwith (Printf.sprintf "expected bool, got %s" (Yojson.Safe.to_string other))
  in
  let tx_bytes = hex_decode (to_hex (member "tx_hex")) in
  let r = Serialize.reader_of_cstruct tx_bytes in
  let tx = Serialize.deserialize_transaction r in
  let spend_height = to_int (member "spend_height") in
  (* Seed the in-memory UTXO view: one coin per prevout entry, keyed by
     (DISPLAY-order txid hex, vout). Carries value + height + is_coinbase
     (script_pubkey too, though scripts are skipped for this op). *)
  let tbl : (string * int32, Validation.utxo) Hashtbl.t = Hashtbl.create 16 in
  let prevouts_json =
    match member "prevouts" with
    | `List l -> l
    | _ -> failwith "prevouts not a list"
  in
  List.iter
    (fun p ->
      let pm k = Yojson.Safe.Util.member k p in
      let txid_hex = to_hex (pm "txid") in
      let vout =
        match pm "vout" with
        | `Int i -> Int32.of_int i
        | `Intlit s -> Int32.of_string s
        | other -> Int32.of_string (Yojson.Safe.to_string other)
      in
      let spk = hex_decode (to_hex (pm "scriptPubKey_hex")) in
      let value = to_int64 (pm "value_sats") in
      let height = to_int (pm "height") in
      let is_coinbase = to_bool (pm "is_coinbase") in
      (* internal/wire txid for the utxo record (mirror display->wire) *)
      let txid_wire = cstruct_rev (Types.hash256_of_hex txid_hex) in
      let coin : Validation.utxo =
        { txid = txid_wire; vout; value; script_pubkey = spk; height; is_coinbase }
      in
      Hashtbl.replace tbl (txid_hex, vout) coin)
    prevouts_json;
  (* UTXO lookup: render the incoming outpoint's wire-order txid back to
     DISPLAY order (hash256_to_hex_display) and probe the view. Absent entry =>
     None => missing/spent input (no reversal logic lives in the shim). *)
  let lookup (op : Types.outpoint) : Validation.utxo option =
    let key = (Types.hash256_to_hex_display op.Types.txid, op.Types.vout) in
    Hashtbl.find_opt tbl key
  in
  (* REAL composite connect-time economic decision. skip_scripts:true isolates
     the economic verdict from any script failure (Core CheckTxInputs is
     amount-only). flags=0 is irrelevant under skip_scripts. *)
  match
    Validation.validate_tx_inputs tx ~lookup ~block_height:spend_height
      ~flags:Script.script_verify_none ~skip_scripts:true ()
  with
  | Error TxMissingInputs ->
      {|{"valid":false,"reason":"bad-txns-inputs-missingorspent"}|}
  | Error TxOutputOverflow ->
      {|{"valid":false,"reason":"bad-txns-inputvalues-outofrange"}|}
  | Error (TxCoinbaseMaturity _) ->
      {|{"valid":false,"reason":"bad-txns-premature-spend-of-coinbase"}|}
  | Error e ->
      (* any other validate_tx_inputs error: reject with the impl's own text *)
      Printf.sprintf {|{"valid":false,"reason":"%s"}|}
        (json_escape (Validation.tx_error_to_string e))
  | Ok _total_in -> (
      (* maturity / MoneyRange / missing all passed; now the no-inflation
         (value-in >= value-out) Some/None gate + fee MoneyRange. *)
      match Validation.calculate_tx_fee tx ~lookup with
      | None ->
          (* total_in < total_out (no-inflation violation), or a missing input
             — but missing was already caught above, so this is belowout. *)
          {|{"valid":false,"reason":"bad-txns-in-belowout"}|}
      | Some fee ->
          if not (Consensus.is_valid_money fee) then
            {|{"valid":false,"reason":"bad-txns-in-belowout"}|}
          else
            Printf.sprintf {|{"valid":true,"fee_sats":%Ld}|} fee)

(* op "nextwork" (Phase B PoW differential): drive camlcoin's REAL
   Consensus.get_next_work_required (the BlockIndex/chain-generic entrypoint
   at lib/consensus.ml:376 that does the retarget + off-by-one + clamps +
   powLimit + BIP94) against Core's GetNextWorkRequired (pow.cpp).

   request:  {"op":"nextwork","network":"mainnet","height":<H>,
              "block_time":<u32>,
              "last":{"height":<int>,"bits":"<8hex>","time":<u32>},
              "first":{"height":<int>,"bits":"<8hex>","time":<u32>}}
             "first" present ONLY on retarget-boundary rows (H%2016==0); it is
             the block at height H-2016 (= pindexLast.height-2015).
   response: {"nbits":"<8hex>"}   (the impl's REAL computed required nBits)
             {"error":"..."}      (could not compute -> driver SKIPS)

   bits are 8-lowercase-hex (Core getblockheader format). camlcoin stores bits
   as int32 internally, so we parse on entry and Printf "%08lx" on exit.

   For boundary rows we populate a Hashtbl(height -> (time,bits)) with the
   `first` block (and `last`, for completeness) and close a get_block_info
   over it. The mainnet boundary branch looks up get_block_info(H-2016) which
   lands exactly on `first`. For passthrough rows the impl returns last.bits
   and never consults get_block_info. block_time only matters for testnet
   min-diff (mainnet ignores it). *)
let network_of_string (s : string) : Consensus.network_config =
  match s with
  | "mainnet" | "main" -> Consensus.mainnet
  | "testnet" | "testnet3" | "test" -> Consensus.testnet
  | "testnet4" -> Consensus.testnet4
  | "regtest" -> Consensus.regtest
  | other -> failwith (Printf.sprintf "unknown network: %s" other)

(* parse a JSON int (Int / Intlit / String) into an OCaml int *)
let json_to_int (v : Yojson.Safe.t) : int =
  match v with
  | `Int i -> i
  | `Intlit s -> int_of_string s
  | `String s -> int_of_string s
  | other -> failwith (Printf.sprintf "expected int, got %s" (Yojson.Safe.to_string other))

(* parse a u32 timestamp into int32 *)
let json_to_u32 (v : Yojson.Safe.t) : int32 =
  match v with
  | `Int i -> Int32.of_int i
  | `Intlit s -> Int32.of_string s
  | `String s -> Int32.of_string s
  | other -> failwith (Printf.sprintf "expected u32, got %s" (Yojson.Safe.to_string other))

(* parse 8-lowercase-hex bits (Core getblockheader format) -> int32 compact *)
let bits_of_hex (s : string) : int32 =
  if String.length s <> 8 then failwith (Printf.sprintf "bits must be 8 hex chars: %s" s);
  (* Int32.of_string handles 0x-prefixed; prepend 0x and accept the full u32. *)
  Int32.of_string ("0x" ^ s)

let process_nextwork (j : Yojson.Safe.t) : string =
  let member k = Yojson.Safe.Util.member k j in
  let network = network_of_string (Yojson.Safe.Util.to_string (member "network")) in
  let height = json_to_int (member "height") in
  let block_time = json_to_u32 (member "block_time") in
  let last = member "last" in
  let lm k = Yojson.Safe.Util.member k last in
  let prev_block_time = json_to_u32 (lm "time") in
  let prev_bits = bits_of_hex (Yojson.Safe.Util.to_string (lm "bits")) in
  let last_height = json_to_int (lm "height") in
  (* Build the height -> (time, bits) table from last (+ first if present). *)
  let tbl : (int, int32 * int32) Hashtbl.t = Hashtbl.create 4 in
  Hashtbl.replace tbl last_height (prev_block_time, prev_bits);
  (match member "first" with
   | `Null -> ()
   | first ->
       let fm k = Yojson.Safe.Util.member k first in
       let f_height = json_to_int (fm "height") in
       let f_time = json_to_u32 (fm "time") in
       let f_bits = bits_of_hex (Yojson.Safe.Util.to_string (fm "bits")) in
       Hashtbl.replace tbl f_height (f_time, f_bits));
  let get_block_info (h : int) : int32 * int32 =
    match Hashtbl.find_opt tbl h with
    | Some v -> v
    | None -> failwith (Printf.sprintf "no block info at height %d" h)
  in
  let nbits =
    Consensus.get_next_work_required ~height ~block_time ~prev_block_time
      ~prev_bits ~get_block_info ~network
  in
  Printf.sprintf {|{"nbits":"%08lx"}|} nbits

(* op "merkleroot" (Phase B tx-merkle + CVE-2012-2459 differential): drive
   camlcoin's REAL merkle primitive Crypto.merkle_root (lib/crypto.ml:359),
   which returns (root, mutated) where `mutated` is camlcoin's own
   block-acceptance-path CVE-2012-2459 adjacent-pair-equal check
   (crypto.ml:378, run BEFORE odd-element duplication, mirroring Core's
   ComputeMerkleRoot). We do NOT re-implement that check in the shim — we
   report whatever camlcoin's real merkle code concludes, so a cve2459 row
   coming back mutated=false would be a genuine camlcoin false-accept finding.

   request:  {"op":"merkleroot","txids":["<64-hex display-order>",...]}
   response: {"root":"<64-hex display-order>","mutated":<bool>}
             {"error":"..."}   (could not compute -> driver SKIPS)

   txids arrive in Bitcoin DISPLAY order (Core getblock convention,
   big-endian). camlcoin's merkle code works in INTERNAL (wire) byte order, so
   we reverse each txid into internal order before feeding merkle_root — the
   inverse of the verifytx op, which renders internal txids back to display via
   Types.hash256_to_hex_display for its prevout-map keys. The computed internal
   root is then reversed back to display order (hash256_to_hex_display) so it
   matches Core's header merkleroot. *)
let process_merkleroot (j : Yojson.Safe.t) : string =
  let member k = Yojson.Safe.Util.member k j in
  let txids_json =
    match member "txids" with
    | `List l -> l
    | _ -> failwith "txids not a list"
  in
  (* display-order hex -> 32-byte cstruct (display byte order) -> reverse to
     internal/wire byte order for the merkle primitive. *)
  let hashes =
    List.map
      (fun v ->
        let hex = Yojson.Safe.Util.to_string v in
        cstruct_rev (Types.hash256_of_hex hex))
      txids_json
  in
  if hashes = [] then failwith "empty txids";
  let root_internal, mutated = Crypto.merkle_root hashes in
  (* reverse the internal root back to display order to match Core's header. *)
  let root_display = Types.hash256_to_hex_display root_internal in
  Printf.sprintf {|{"root":"%s","mutated":%b}|} root_display mutated

(* op "subsidy" (Phase B block-subsidy differential): drive camlcoin's REAL
   block-subsidy fn (Consensus.block_subsidy_for_network, lib/consensus.ml:93)
   at MAINNET params (halving interval 210000) — the same fn block validation
   uses for the coinbase cap. We do NOT re-implement the halving schedule here,
   so a halving-boundary off-by-one or missing >=64 zero-guard in the impl
   surfaces directly.

   request:  {"op":"subsidy","height":<int>}
   response: {"subsidy_sats":<int>}   (the impl's REAL subsidy in satoshis)
             {"error":"..."}          (could not compute -> driver SKIPS) *)
let process_subsidy (j : Yojson.Safe.t) : string =
  let member k = Yojson.Safe.Util.member k j in
  let height = json_to_int (member "height") in
  let subsidy = Consensus.block_subsidy_for_network Consensus.Mainnet height in
  Printf.sprintf {|{"subsidy_sats":%Ld}|} subsidy

(* op "checkblock" (Phase B VALIDATE-ONLY block differential): generalizes
   `connecttx` from a single tx to a FULL BLOCK. Drives camlcoin's REAL
   block-acceptance pipeline end to end:

     CheckBlock(check_pow = not skip_pow)        (structural + contextual gates)
       -> ContextualCheckBlock(spend_height)     (IsFinalTx, witness commitment, ...)
         -> ConnectBlock(spend_height, seeded-view) with REAL scripts
            (skip_scripts:false) + the block's OWN coinbase + MAINNET params.

   This is exactly `Validation.accept_block`, which folds all three layers into
   `validate_block_with_utxos`. We do NOT re-implement any block rule in the
   shim — a crafted mutant returning valid=true is a genuine camlcoin
   false-accept finding, and the real block rejecting is a genuine false-reject.

   MAINNET params (NOT regtest): regtest's halving interval (150) breaks
   bad-cb-amount and its soft-fork activation heights collapse to 1, which would
   change the bad-cb-height / version / witness verdicts. spend_height 709742 is
   post-Taproot so every mainnet deployment is active.

   skip_pow:true is REQUIRED here: the corpus block_hex is the FINAL/mutated
   block, which no longer meets mainnet's PoW target. With skip_pow false, EVERY
   case (real + 9 mutants) would reject on the PoW hash gate before any body gate
   runs — a silent DEAD-GATE. skip_pow gates ONLY the hash<=target test
   (Core CheckBlock fCheckPOW), never the expected_bits difficulty-equality rule.

   block_hex is validated AS-IS (we deserialize with camlcoin's own segwit-aware
   deserializer; the merkle root is NOT recomputed — the block's stored header
   merkle_root is checked against the txs by check_block, which is precisely how
   bad-txnmrklroot / bad-witness-merkle-match are caught).

   UTXO VIEW: identical seeding plumbing to `connecttx` — one coin per prevout
   entry (value + height + is_coinbase + scriptPubKey, NOW USED because
   skip_scripts:false), keyed by (DISPLAY-order txid hex, vout). The lookup
   renders each incoming wire-order outpoint txid back to display via
   hash256_to_hex_display; an OMITTED prevout => None => missing input. This is
   passed as accept_block's ~base_lookup.

   request:  {"op":"checkblock","block_hex":"<FINAL block bytes>",
              "prevouts":[{"txid":"<DISPLAY-hex>","vout":N,
                           "scriptPubKey_hex":"<spk>","value_sats":<u64>,
                           "height":<int>,"is_coinbase":<bool>}...one per
                          NON-COINBASE input across all non-coinbase txs],
              "spend_height":709742,"skip_pow":true,"skip_scripts":false}
   response: {"valid":true} | {"valid":false,"reason":"<advisory>"} | {"error":".."}
*)
let process_checkblock (j : Yojson.Safe.t) : string =
  let member k = Yojson.Safe.Util.member k j in
  let to_hex v = Yojson.Safe.Util.to_string v in
  let to_int64 v =
    match v with
    | `Int i -> Int64.of_int i
    | `Intlit s -> Int64.of_string s
    | `Null -> 0L
    | other -> Int64.of_string (Yojson.Safe.to_string other)
  in
  let to_int v =
    match v with
    | `Int i -> i
    | `Intlit s -> int_of_string s
    | `String s -> int_of_string s
    | other -> failwith (Printf.sprintf "expected int, got %s" (Yojson.Safe.to_string other))
  in
  let to_bool v =
    match v with
    | `Bool b -> b
    | `Int i -> i <> 0
    | `Null -> false
    | other -> failwith (Printf.sprintf "expected bool, got %s" (Yojson.Safe.to_string other))
  in
  let to_bool_default v d =
    match v with `Null -> d | other -> to_bool other
  in
  (* Deserialize the FINAL block AS-IS with camlcoin's segwit-aware reader. *)
  let block_bytes = hex_decode (to_hex (member "block_hex")) in
  let r = Serialize.reader_of_cstruct block_bytes in
  let block = Serialize.deserialize_block r in
  let spend_height = to_int (member "spend_height") in
  let skip_pow = to_bool_default (member "skip_pow") true in
  let skip_scripts = to_bool_default (member "skip_scripts") false in
  (* Seed the in-memory UTXO view: one coin per prevout entry, keyed by
     (DISPLAY-order txid hex, vout). Identical plumbing to process_connecttx. *)
  let tbl : (string * int32, Validation.utxo) Hashtbl.t = Hashtbl.create 1024 in
  let prevouts_json =
    match member "prevouts" with
    | `List l -> l
    | _ -> failwith "prevouts not a list"
  in
  List.iter
    (fun p ->
      let pm k = Yojson.Safe.Util.member k p in
      let txid_hex = to_hex (pm "txid") in
      let vout =
        match pm "vout" with
        | `Int i -> Int32.of_int i
        | `Intlit s -> Int32.of_string s
        | other -> Int32.of_string (Yojson.Safe.to_string other)
      in
      let spk = hex_decode (to_hex (pm "scriptPubKey_hex")) in
      let value = to_int64 (pm "value_sats") in
      let height = to_int (pm "height") in
      let is_coinbase = to_bool (pm "is_coinbase") in
      let txid_wire = cstruct_rev (Types.hash256_of_hex txid_hex) in
      let coin : Validation.utxo =
        { txid = txid_wire; vout; value; script_pubkey = spk; height; is_coinbase }
      in
      Hashtbl.replace tbl (txid_hex, vout) coin)
    prevouts_json;
  (* base_lookup: render the incoming outpoint's wire-order txid back to DISPLAY
     order and probe the seeded view. Absent => None => missing input. *)
  let base_lookup (op : Types.outpoint) : Validation.utxo option =
    let key = (Types.hash256_to_hex_display op.Types.txid, op.Types.vout) in
    Hashtbl.find_opt tbl key
  in
  (* expected_bits = the block's OWN header bits (the difficulty-target equality
     rule is satisfied trivially; skip_pow only drops the hash<=target test). *)
  let expected_bits = block.Types.header.bits in
  (* MAINNET consensus flags at spend_height (post-Taproot: all forks active). *)
  let flags = Consensus.get_block_script_flags spend_height Consensus.mainnet in
  (* median_time (= the prev block's GetMedianTimePast). Not supplied by the
     corpus, so we synthesize a faithful value: ONE SECOND below the block's own
     timestamp. Two camlcoin gates consume median_time:
       (a) the time-too-old gate (block.timestamp <= median_time) — Core's
           ContextualCheckBlockHeader rule; MTP is strictly < a valid block's
           time, so timestamp-1 keeps this NON-binding (real block passes) while
           NOT being self-referential (which `= timestamp` would be, tripping
           the <= and spuriously rejecting EVERY case before any body gate).
       (b) the BIP-113 IsFinalTx lock_time_cutoff (CSV active at 709742) — Core's
           MTP at this height sits just below the block time, so timestamp-1
           keeps the real already-mined final txs final (no spurious
           TxNonFinalLocktime), exactly matching mainnet semantics.
     This makes the time gates non-binding so the body verdict (the 9 mutants)
     is what gets scored, never masked by a synthetic time rejection. *)
  let median_time = Int32.sub block.Types.header.timestamp 1l in
  match
    Validation.accept_block ~network:Consensus.mainnet ~block
      ~height:spend_height ~expected_bits ~median_time ~base_lookup ~flags
      ~skip_scripts ~skip_pow ()
  with
  | Validation.AB_ok _ -> {|{"valid":true}|}
  | Validation.AB_err e ->
      Printf.sprintf {|{"valid":false,"reason":"%s"}|}
        (json_escape (Validation.block_error_to_string e))

let process (line : string) : string =
  try
    let j = Yojson.Safe.from_string line in
    let op =
      match Yojson.Safe.Util.member "op" j with
      | `String s -> s
      | _ -> "verifyscript"
    in
    match op with
    | "verifyscript" -> process_verifyscript j
    | "verifytx" -> process_verifytx j
    | "checktx" -> process_checktx j
    | "connecttx" -> process_connecttx j
    | "checkblock" -> process_checkblock j
    | "nextwork" -> process_nextwork j
    | "merkleroot" -> process_merkleroot j
    | "subsidy" -> process_subsidy j
    | other -> Printf.sprintf {|{"error":"unknown op: %s"}|} (json_escape other)
  with
  | Failure msg -> Printf.sprintf {|{"error":"%s"}|} (json_escape msg)
  | e ->
      Printf.sprintf {|{"error":"%s"}|}
        (json_escape ("exn: " ^ Printexc.to_string e))

let () =
  try
    while true do
      let line = input_line stdin in
      let trimmed = String.trim line in
      if String.length trimmed > 0 then begin
        let resp =
          try process line
          with e ->
            Printf.sprintf {|{"error":"%s"}|}
              (json_escape ("top: " ^ Printexc.to_string e))
        in
        print_string resp;
        print_newline ();
        flush stdout
      end
    done
  with End_of_file -> ()
