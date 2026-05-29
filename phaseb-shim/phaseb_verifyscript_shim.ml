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

let process (line : string) : string =
  try
    let j = Yojson.Safe.from_string line in
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
