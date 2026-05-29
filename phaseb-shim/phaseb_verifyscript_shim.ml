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
