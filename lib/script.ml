(* Bitcoin Script interpreter *)

(* ============================================================================
   Opcode Definitions
   ============================================================================ *)

type opcode =
  (* Constants *)
  | OP_0                    (* 0x00 -- push empty byte vector *)
  | OP_PUSHDATA of int * Cstruct.t (* (opbyte, data) 0x01-0x4e -- push N bytes *)
  | OP_1NEGATE              (* 0x4f -- push -1 *)
  | OP_1                    (* 0x51 -- push 1, also OP_TRUE *)
  | OP_2  | OP_3  | OP_4  | OP_5  | OP_6  | OP_7  | OP_8
  | OP_9  | OP_10 | OP_11 | OP_12 | OP_13 | OP_14 | OP_15 | OP_16
  (* Flow control *)
  | OP_NOP                  (* 0x61 *)
  | OP_IF                   (* 0x63 *)
  | OP_NOTIF                (* 0x64 *)
  | OP_ELSE                 (* 0x67 *)
  | OP_ENDIF                (* 0x68 *)
  | OP_VERIFY               (* 0x69 *)
  | OP_RETURN               (* 0x6a *)
  (* Stack *)
  | OP_TOALTSTACK           (* 0x6b *)
  | OP_FROMALTSTACK         (* 0x6c *)
  | OP_IFDUP                (* 0x73 *)
  | OP_DEPTH                (* 0x74 *)
  | OP_DROP                 (* 0x75 *)
  | OP_DUP                  (* 0x76 *)
  | OP_NIP                  (* 0x77 *)
  | OP_OVER                 (* 0x78 *)
  | OP_PICK                 (* 0x79 *)
  | OP_ROLL                 (* 0x7a *)
  | OP_ROT                  (* 0x7b *)
  | OP_SWAP                 (* 0x7c *)
  | OP_TUCK                 (* 0x7d *)
  | OP_2DROP                (* 0x6d *)
  | OP_2DUP                 (* 0x6e *)
  | OP_3DUP                 (* 0x6f *)
  | OP_2OVER                (* 0x70 *)
  | OP_2ROT                 (* 0x71 *)
  | OP_2SWAP                (* 0x72 *)
  (* Splice (most disabled) *)
  | OP_SIZE                 (* 0x82 *)
  (* Bitwise logic *)
  | OP_EQUAL                (* 0x87 *)
  | OP_EQUALVERIFY          (* 0x88 *)
  (* Arithmetic *)
  | OP_1ADD                 (* 0x8b *)
  | OP_1SUB                 (* 0x8c *)
  | OP_NEGATE               (* 0x8f *)
  | OP_ABS                  (* 0x90 *)
  | OP_NOT                  (* 0x91 *)
  | OP_0NOTEQUAL            (* 0x92 *)
  | OP_ADD                  (* 0x93 *)
  | OP_SUB                  (* 0x94 *)
  | OP_BOOLAND              (* 0x9a *)
  | OP_BOOLOR               (* 0x9b *)
  | OP_NUMEQUAL             (* 0x9c *)
  | OP_NUMEQUALVERIFY       (* 0x9d *)
  | OP_NUMNOTEQUAL          (* 0x9e *)
  | OP_LESSTHAN             (* 0x9f *)
  | OP_GREATERTHAN          (* 0xa0 *)
  | OP_LESSTHANOREQUAL      (* 0xa1 *)
  | OP_GREATERTHANOREQUAL   (* 0xa2 *)
  | OP_MIN                  (* 0xa3 *)
  | OP_MAX                  (* 0xa4 *)
  | OP_WITHIN               (* 0xa5 *)
  (* Crypto *)
  | OP_RIPEMD160            (* 0xa6 *)
  | OP_SHA1                 (* 0xa7 *)
  | OP_SHA256               (* 0xa8 *)
  | OP_HASH160              (* 0xa9 *)
  | OP_HASH256              (* 0xaa *)
  | OP_CODESEPARATOR        (* 0xab *)
  | OP_CHECKSIG             (* 0xac *)
  | OP_CHECKSIGVERIFY       (* 0xad *)
  | OP_CHECKMULTISIG        (* 0xae *)
  | OP_CHECKMULTISIGVERIFY  (* 0xaf *)
  (* Locktime *)
  | OP_CHECKLOCKTIMEVERIFY  (* 0xb1, BIP-65 *)
  | OP_CHECKSEQUENCEVERIFY  (* 0xb2, BIP-112 *)
  (* SegWit / Tapscript *)
  | OP_CHECKSIGADD          (* 0xba, Tapscript BIP-342 *)
  (* NOPs for soft-fork expansion *)
  | OP_NOP1 | OP_NOP4 | OP_NOP5 | OP_NOP6 | OP_NOP7
  | OP_NOP8 | OP_NOP9 | OP_NOP10
  (* Reserved/Disabled *)
  | OP_RESERVED             (* 0x50 *)
  | OP_VER                  (* 0x62 *)
  | OP_VERIF                (* 0x65 *)
  | OP_VERNOTIF             (* 0x66 *)
  | OP_RESERVED1            (* 0x89 *)
  | OP_RESERVED2            (* 0x8a *)
  (* Invalid/unknown *)
  | OP_INVALID of int

(* ============================================================================
   Constants
   ============================================================================ *)

let max_script_size = 10000
let max_script_element_size = 520
let max_stack_size = 1000
let max_ops_per_script = 201
let max_pubkeys_per_multisig = 20

(* Sighash types *)
let sighash_all          = 0x01
let sighash_none         = 0x02
let sighash_single       = 0x03
let sighash_anyonecanpay = 0x80
let sighash_default      = 0x00  (* Taproot only *)

(* Script verification flags - consensus only *)
let script_verify_none           = 0
let script_verify_p2sh           = 1 lsl 0   (* BIP-16 *)
let script_verify_dersig         = 1 lsl 2   (* BIP-66 *)
let script_verify_checklocktimeverify = 1 lsl 9  (* BIP-65 *)
let script_verify_checksequenceverify = 1 lsl 10 (* BIP-112 *)
let script_verify_witness        = 1 lsl 11  (* BIP-141 *)
let script_verify_nulldummy      = 1 lsl 4   (* BIP-147 *)
let script_verify_taproot        = 1 lsl 17  (* BIP-341/342 *)

(* Additional script verification flags *)
let script_verify_strictenc      = 1 lsl 1   (* BIP-62 strict signature encoding *)
let script_verify_low_s          = 1 lsl 3   (* BIP-62 rule 5 - low S values *)
let script_verify_minimaldata    = 1 lsl 5   (* BIP-62 minimal push encoding *)
let script_verify_sigpushonly    = 1 lsl 6   (* Require scriptSig is push-only *)
let script_verify_cleanstack     = 1 lsl 7   (* Require exactly one stack element after execution *)
let script_verify_nullfail       = 1 lsl 12  (* BIP-146 NULLFAIL *)
let script_verify_minimalif      = 1 lsl 13  (* Minimal IF/NOTIF arguments *)
let script_verify_witness_pubkeytype = 1 lsl 14 (* BIP-141 compressed keys for witness v0 *)
let script_verify_const_scriptcode   = 1 lsl 15 (* Making OP_CODESEP non-standard *)
let script_verify_discourage_upgradable_nops    = 1 lsl 8  (* Discourage upgradable NOPs *)
let script_verify_discourage_upgradable_witness = 1 lsl 16 (* Discourage unknown witness versions *)
let script_verify_discourage_op_success = 1 lsl 18  (* Discourage OP_SUCCESSx in tapscript *)
let script_verify_discourage_upgradable_taproot_version = 1 lsl 19  (* Discourage unknown taproot leaf versions *)
let script_verify_discourage_upgradable_pubkeytype = 1 lsl 20  (* Discourage unknown pubkey types in tapscript *)

(* Signature version for sighash computation *)
type sig_version =
  | SigVersionBase      (* Legacy pre-segwit *)
  | SigVersionWitnessV0 (* BIP-143 segwit v0 *)
  | SigVersionTaproot   (* BIP-341 key path *)
  | SigVersionTapscript (* BIP-342 script path *)

(* ============================================================================
   Script Parsing
   ============================================================================ *)

let parse_script (raw : Cstruct.t) : opcode list =
  let len = Cstruct.length raw in
  if len > max_script_size then
    failwith "Script exceeds maximum size";
  let r = Serialize.reader_of_cstruct raw in
  let ops = ref [] in
  while r.pos < len do
    let byte = Serialize.read_uint8 r in
    let op = match byte with
      | 0x00 -> OP_0
      | n when n >= 0x01 && n <= 0x4b ->
        if r.pos + n > len then failwith "Truncated PUSHDATA";
        OP_PUSHDATA (n, Serialize.read_bytes r n)
      | 0x4c ->
        let push_len = Serialize.read_uint8 r in
        if r.pos + push_len > len then failwith "Truncated PUSHDATA1";
        OP_PUSHDATA (0x4c, Serialize.read_bytes r push_len)
      | 0x4d ->
        let push_len = Serialize.read_uint16_le r in
        if r.pos + push_len > len then failwith "Truncated PUSHDATA2";
        OP_PUSHDATA (0x4d, Serialize.read_bytes r push_len)
      | 0x4e ->
        let push_len = Int32.to_int (Serialize.read_int32_le r) in
        if push_len < 0 || r.pos + push_len > len then failwith "Truncated PUSHDATA4";
        OP_PUSHDATA (0x4e, Serialize.read_bytes r push_len)
      | 0x4f -> OP_1NEGATE
      | 0x50 -> OP_RESERVED
      | 0x51 -> OP_1
      | 0x52 -> OP_2   | 0x53 -> OP_3   | 0x54 -> OP_4
      | 0x55 -> OP_5   | 0x56 -> OP_6   | 0x57 -> OP_7
      | 0x58 -> OP_8   | 0x59 -> OP_9   | 0x5a -> OP_10
      | 0x5b -> OP_11  | 0x5c -> OP_12  | 0x5d -> OP_13
      | 0x5e -> OP_14  | 0x5f -> OP_15  | 0x60 -> OP_16
      | 0x61 -> OP_NOP
      | 0x62 -> OP_VER
      | 0x63 -> OP_IF  | 0x64 -> OP_NOTIF
      | 0x65 -> OP_VERIF | 0x66 -> OP_VERNOTIF
      | 0x67 -> OP_ELSE | 0x68 -> OP_ENDIF
      | 0x69 -> OP_VERIFY | 0x6a -> OP_RETURN
      | 0x6b -> OP_TOALTSTACK | 0x6c -> OP_FROMALTSTACK
      | 0x6d -> OP_2DROP | 0x6e -> OP_2DUP | 0x6f -> OP_3DUP
      | 0x70 -> OP_2OVER | 0x71 -> OP_2ROT | 0x72 -> OP_2SWAP
      | 0x73 -> OP_IFDUP | 0x74 -> OP_DEPTH
      | 0x75 -> OP_DROP  | 0x76 -> OP_DUP
      | 0x77 -> OP_NIP   | 0x78 -> OP_OVER
      | 0x79 -> OP_PICK  | 0x7a -> OP_ROLL
      | 0x7b -> OP_ROT   | 0x7c -> OP_SWAP  | 0x7d -> OP_TUCK
      | 0x82 -> OP_SIZE
      | 0x87 -> OP_EQUAL | 0x88 -> OP_EQUALVERIFY
      | 0x89 -> OP_RESERVED1 | 0x8a -> OP_RESERVED2
      | 0x8b -> OP_1ADD  | 0x8c -> OP_1SUB
      | 0x8f -> OP_NEGATE | 0x90 -> OP_ABS
      | 0x91 -> OP_NOT   | 0x92 -> OP_0NOTEQUAL
      | 0x93 -> OP_ADD   | 0x94 -> OP_SUB
      | 0x9a -> OP_BOOLAND | 0x9b -> OP_BOOLOR
      | 0x9c -> OP_NUMEQUAL | 0x9d -> OP_NUMEQUALVERIFY
      | 0x9e -> OP_NUMNOTEQUAL
      | 0x9f -> OP_LESSTHAN | 0xa0 -> OP_GREATERTHAN
      | 0xa1 -> OP_LESSTHANOREQUAL | 0xa2 -> OP_GREATERTHANOREQUAL
      | 0xa3 -> OP_MIN | 0xa4 -> OP_MAX | 0xa5 -> OP_WITHIN
      | 0xa6 -> OP_RIPEMD160 | 0xa7 -> OP_SHA1
      | 0xa8 -> OP_SHA256 | 0xa9 -> OP_HASH160 | 0xaa -> OP_HASH256
      | 0xab -> OP_CODESEPARATOR
      | 0xac -> OP_CHECKSIG | 0xad -> OP_CHECKSIGVERIFY
      | 0xae -> OP_CHECKMULTISIG | 0xaf -> OP_CHECKMULTISIGVERIFY
      | 0xb0 -> OP_NOP1
      | 0xb1 -> OP_CHECKLOCKTIMEVERIFY
      | 0xb2 -> OP_CHECKSEQUENCEVERIFY
      | 0xb3 -> OP_NOP4 | 0xb4 -> OP_NOP5
      | 0xb5 -> OP_NOP6 | 0xb6 -> OP_NOP7
      | 0xb7 -> OP_NOP8 | 0xb8 -> OP_NOP9 | 0xb9 -> OP_NOP10
      | 0xba -> OP_CHECKSIGADD
      | n -> OP_INVALID n
    in
    ops := op :: !ops
  done;
  List.rev !ops

(* Serialize an opcode back to bytes *)
let serialize_opcode (w : Serialize.writer) (op : opcode) : unit =
  match op with
  | OP_0 -> Serialize.write_uint8 w 0x00
  | OP_PUSHDATA (opbyte, data) ->
    let len = Cstruct.length data in
    if opbyte >= 0x01 && opbyte <= 0x4b then begin
      Serialize.write_uint8 w len;
      Serialize.write_bytes w data
    end else if opbyte = 0x4c then begin
      Serialize.write_uint8 w 0x4c;
      Serialize.write_uint8 w len;
      Serialize.write_bytes w data
    end else if opbyte = 0x4d then begin
      Serialize.write_uint8 w 0x4d;
      Serialize.write_uint16_le w len;
      Serialize.write_bytes w data
    end else if opbyte = 0x4e then begin
      Serialize.write_uint8 w 0x4e;
      Serialize.write_int32_le w (Int32.of_int len);
      Serialize.write_bytes w data
    end else begin
      (* Fallback: use minimal encoding *)
      if len <= 0x4b then begin
        Serialize.write_uint8 w len;
        Serialize.write_bytes w data
      end else if len <= 0xff then begin
        Serialize.write_uint8 w 0x4c;
        Serialize.write_uint8 w len;
        Serialize.write_bytes w data
      end else if len <= 0xffff then begin
        Serialize.write_uint8 w 0x4d;
        Serialize.write_uint16_le w len;
        Serialize.write_bytes w data
      end else begin
        Serialize.write_uint8 w 0x4e;
        Serialize.write_int32_le w (Int32.of_int len);
        Serialize.write_bytes w data
      end
    end
  | OP_1NEGATE -> Serialize.write_uint8 w 0x4f
  | OP_RESERVED -> Serialize.write_uint8 w 0x50
  | OP_1 -> Serialize.write_uint8 w 0x51
  | OP_2 -> Serialize.write_uint8 w 0x52 | OP_3 -> Serialize.write_uint8 w 0x53
  | OP_4 -> Serialize.write_uint8 w 0x54 | OP_5 -> Serialize.write_uint8 w 0x55
  | OP_6 -> Serialize.write_uint8 w 0x56 | OP_7 -> Serialize.write_uint8 w 0x57
  | OP_8 -> Serialize.write_uint8 w 0x58 | OP_9 -> Serialize.write_uint8 w 0x59
  | OP_10 -> Serialize.write_uint8 w 0x5a | OP_11 -> Serialize.write_uint8 w 0x5b
  | OP_12 -> Serialize.write_uint8 w 0x5c | OP_13 -> Serialize.write_uint8 w 0x5d
  | OP_14 -> Serialize.write_uint8 w 0x5e | OP_15 -> Serialize.write_uint8 w 0x5f
  | OP_16 -> Serialize.write_uint8 w 0x60
  | OP_NOP -> Serialize.write_uint8 w 0x61
  | OP_VER -> Serialize.write_uint8 w 0x62
  | OP_IF -> Serialize.write_uint8 w 0x63 | OP_NOTIF -> Serialize.write_uint8 w 0x64
  | OP_VERIF -> Serialize.write_uint8 w 0x65 | OP_VERNOTIF -> Serialize.write_uint8 w 0x66
  | OP_ELSE -> Serialize.write_uint8 w 0x67 | OP_ENDIF -> Serialize.write_uint8 w 0x68
  | OP_VERIFY -> Serialize.write_uint8 w 0x69 | OP_RETURN -> Serialize.write_uint8 w 0x6a
  | OP_TOALTSTACK -> Serialize.write_uint8 w 0x6b | OP_FROMALTSTACK -> Serialize.write_uint8 w 0x6c
  | OP_2DROP -> Serialize.write_uint8 w 0x6d | OP_2DUP -> Serialize.write_uint8 w 0x6e
  | OP_3DUP -> Serialize.write_uint8 w 0x6f | OP_2OVER -> Serialize.write_uint8 w 0x70
  | OP_2ROT -> Serialize.write_uint8 w 0x71 | OP_2SWAP -> Serialize.write_uint8 w 0x72
  | OP_IFDUP -> Serialize.write_uint8 w 0x73 | OP_DEPTH -> Serialize.write_uint8 w 0x74
  | OP_DROP -> Serialize.write_uint8 w 0x75 | OP_DUP -> Serialize.write_uint8 w 0x76
  | OP_NIP -> Serialize.write_uint8 w 0x77 | OP_OVER -> Serialize.write_uint8 w 0x78
  | OP_PICK -> Serialize.write_uint8 w 0x79 | OP_ROLL -> Serialize.write_uint8 w 0x7a
  | OP_ROT -> Serialize.write_uint8 w 0x7b | OP_SWAP -> Serialize.write_uint8 w 0x7c
  | OP_TUCK -> Serialize.write_uint8 w 0x7d
  | OP_SIZE -> Serialize.write_uint8 w 0x82
  | OP_EQUAL -> Serialize.write_uint8 w 0x87 | OP_EQUALVERIFY -> Serialize.write_uint8 w 0x88
  | OP_RESERVED1 -> Serialize.write_uint8 w 0x89 | OP_RESERVED2 -> Serialize.write_uint8 w 0x8a
  | OP_1ADD -> Serialize.write_uint8 w 0x8b | OP_1SUB -> Serialize.write_uint8 w 0x8c
  | OP_NEGATE -> Serialize.write_uint8 w 0x8f | OP_ABS -> Serialize.write_uint8 w 0x90
  | OP_NOT -> Serialize.write_uint8 w 0x91 | OP_0NOTEQUAL -> Serialize.write_uint8 w 0x92
  | OP_ADD -> Serialize.write_uint8 w 0x93 | OP_SUB -> Serialize.write_uint8 w 0x94
  | OP_BOOLAND -> Serialize.write_uint8 w 0x9a | OP_BOOLOR -> Serialize.write_uint8 w 0x9b
  | OP_NUMEQUAL -> Serialize.write_uint8 w 0x9c | OP_NUMEQUALVERIFY -> Serialize.write_uint8 w 0x9d
  | OP_NUMNOTEQUAL -> Serialize.write_uint8 w 0x9e
  | OP_LESSTHAN -> Serialize.write_uint8 w 0x9f | OP_GREATERTHAN -> Serialize.write_uint8 w 0xa0
  | OP_LESSTHANOREQUAL -> Serialize.write_uint8 w 0xa1
  | OP_GREATERTHANOREQUAL -> Serialize.write_uint8 w 0xa2
  | OP_MIN -> Serialize.write_uint8 w 0xa3 | OP_MAX -> Serialize.write_uint8 w 0xa4
  | OP_WITHIN -> Serialize.write_uint8 w 0xa5
  | OP_RIPEMD160 -> Serialize.write_uint8 w 0xa6 | OP_SHA1 -> Serialize.write_uint8 w 0xa7
  | OP_SHA256 -> Serialize.write_uint8 w 0xa8 | OP_HASH160 -> Serialize.write_uint8 w 0xa9
  | OP_HASH256 -> Serialize.write_uint8 w 0xaa
  | OP_CODESEPARATOR -> Serialize.write_uint8 w 0xab
  | OP_CHECKSIG -> Serialize.write_uint8 w 0xac
  | OP_CHECKSIGVERIFY -> Serialize.write_uint8 w 0xad
  | OP_CHECKMULTISIG -> Serialize.write_uint8 w 0xae
  | OP_CHECKMULTISIGVERIFY -> Serialize.write_uint8 w 0xaf
  | OP_NOP1 -> Serialize.write_uint8 w 0xb0
  | OP_CHECKLOCKTIMEVERIFY -> Serialize.write_uint8 w 0xb1
  | OP_CHECKSEQUENCEVERIFY -> Serialize.write_uint8 w 0xb2
  | OP_NOP4 -> Serialize.write_uint8 w 0xb3 | OP_NOP5 -> Serialize.write_uint8 w 0xb4
  | OP_NOP6 -> Serialize.write_uint8 w 0xb5 | OP_NOP7 -> Serialize.write_uint8 w 0xb6
  | OP_NOP8 -> Serialize.write_uint8 w 0xb7 | OP_NOP9 -> Serialize.write_uint8 w 0xb8
  | OP_NOP10 -> Serialize.write_uint8 w 0xb9
  | OP_CHECKSIGADD -> Serialize.write_uint8 w 0xba
  | OP_INVALID n -> Serialize.write_uint8 w n

let serialize_script (ops : opcode list) : Cstruct.t =
  let w = Serialize.writer_create () in
  List.iter (serialize_opcode w) ops;
  Serialize.writer_to_cstruct w

(* ============================================================================
   CScriptNum: Bitcoin's Script Number Encoding
   ============================================================================ *)

(* Check if a byte value corresponds to a disabled opcode.
   Bitcoin Core rejects these even in non-executing branches. *)
let is_disabled_opcode (n : int) : bool =
  match n with
  | 0x7E | 0x7F | 0x80 | 0x81  (* OP_CAT, OP_SUBSTR, OP_LEFT, OP_RIGHT *)
  | 0x83 | 0x84 | 0x85 | 0x86  (* OP_INVERT, OP_AND, OP_OR, OP_XOR *)
  | 0x8D | 0x8E                 (* OP_2MUL, OP_2DIV *)
  | 0x95 | 0x96 | 0x97 | 0x98 | 0x99 (* OP_MUL, OP_DIV, OP_MOD, OP_LSHIFT, OP_RSHIFT *)
    -> true
  | _ -> false

(* Check if number requires more than 4 bytes (overflow for arithmetic) *)
let script_num_require_minimal (data : Cstruct.t) : bool =
  let len = Cstruct.length data in
  if len = 0 then true
  else if len > 4 then false
  else if len >= 2 then
    (* Check for non-minimal encoding *)
    let last = Cstruct.get_uint8 data (len - 1) in
    let second_last = Cstruct.get_uint8 data (len - 2) in
    (* If last byte is 0x00 or 0x80, second-to-last should have high bit set *)
    if (last = 0x00 || last = 0x80) && (second_last land 0x80 = 0) then false
    else true
  else true

(* Decode script number from bytes (sign-magnitude little-endian) *)
let script_num_of_bytes ?(require_minimal=false) ?(max_bytes=4) (data : Cstruct.t) : int64 =
  let len = Cstruct.length data in
  if require_minimal && not (script_num_require_minimal data) then
    failwith "Non-minimal script number encoding"
  else if len = 0 then 0L
  else if len > max_bytes then
    (* Numbers in script are limited to max_bytes bytes *)
    failwith "Script number overflow"
  else begin
    let result = ref 0L in
    for i = 0 to len - 1 do
      result := Int64.logor !result
        (Int64.shift_left (Int64.of_int (Cstruct.get_uint8 data i)) (8 * i))
    done;
    (* Check sign bit *)
    if Cstruct.get_uint8 data (len - 1) land 0x80 <> 0 then begin
      (* Clear sign bit and negate *)
      let mask = Int64.shift_left 0x80L (8 * (len - 1)) in
      result := Int64.logand !result (Int64.lognot mask);
      result := Int64.neg !result
    end;
    !result
  end

(* Encode script number to bytes *)
let bytes_of_script_num (n : int64) : Cstruct.t =
  if n = 0L then Cstruct.create 0
  else begin
    let negative = n < 0L in
    let absn = if negative then Int64.neg n else n in
    let bytes = ref [] in
    let v = ref absn in
    while !v > 0L do
      bytes := Int64.to_int (Int64.logand !v 0xFFL) :: !bytes;
      v := Int64.shift_right_logical !v 8
    done;
    let bytes = List.rev !bytes in
    let bytes =
      match bytes with
      | [] -> [0]
      | _ ->
        let last = List.nth bytes (List.length bytes - 1) in
        if last land 0x80 <> 0 then
          (* Need an extra byte for sign *)
          bytes @ [if negative then 0x80 else 0x00]
        else if negative then
          (* Set sign bit on last byte *)
          let rev = List.rev bytes in
          List.rev ((List.hd rev lor 0x80) :: List.tl rev)
        else bytes
    in
    let result = Cstruct.create (List.length bytes) in
    List.iteri (fun i b -> Cstruct.set_uint8 result i b) bytes;
    result
  end

(* ============================================================================
   Stack Machine State
   ============================================================================ *)

type script_error =
  | ScriptOk
  | ErrScript of string

type eval_state = {
  mutable stack : Cstruct.t list;
  mutable altstack : Cstruct.t list;
  mutable if_stack : bool list;  (* Track nested IF execution state *)
  mutable op_count : int;
  mutable codesep_pos : int;     (* Position of last OP_CODESEPARATOR *)
  mutable current_op_idx : int;  (* Current opcode index during execution *)
  tx : Types.transaction;
  input_index : int;
  amount : int64;
  flags : int;
  sig_version : sig_version;
  (* Taproot context fields *)
  prevouts : (int64 * Cstruct.t) list;  (* (amount, scriptPubKey) for all inputs *)
  annex_hash : Cstruct.t option;         (* SHA256 of annex if present *)
  tapleaf_hash : Cstruct.t option;       (* tapleaf hash for script path *)
  mutable sigops_budget : int;           (* Tapscript validation weight budget *)
}

let create_eval_state ~tx ~input_index ~amount ~flags ~sig_version
    ?(prevouts=[]) ?(annex_hash=None) ?(tapleaf_hash=None) ?(sigops_budget=max_int) () =
  {
    stack = [];
    altstack = [];
    if_stack = [];
    op_count = 0;
    codesep_pos = 0xFFFFFFFF;  (* Initialize to 0xFFFFFFFF per Bitcoin Core *)
    current_op_idx = 0;
    tx;
    input_index;
    amount;
    flags;
    sig_version;
    prevouts;
    annex_hash;
    tapleaf_hash;
    sigops_budget;
  }

(* Stack operations *)
let stack_top st =
  match st.stack with
  | [] -> Error "Stack empty"
  | x :: _ -> Ok x

let stack_pop st =
  match st.stack with
  | [] -> Error "Stack underflow"
  | x :: rest -> st.stack <- rest; Ok x

let stack_push st v =
  if List.length st.stack + List.length st.altstack >= max_stack_size then
    Error "Stack overflow"
  else begin
    st.stack <- v :: st.stack;
    Ok ()
  end

let stack_size st = List.length st.stack

(* Check if we're currently executing (not in a false IF branch) *)
let is_executing st =
  List.for_all (fun b -> b) st.if_stack

(* Check if a stack element is "true" (non-zero) *)
let is_true (data : Cstruct.t) : bool =
  let len = Cstruct.length data in
  if len = 0 then false
  else begin
    let all_zero = ref true in
    for i = 0 to len - 1 do
      let b = Cstruct.get_uint8 data i in
      if i = len - 1 then begin
        (* Last byte: 0x00 or 0x80 (negative zero) counts as false *)
        if b <> 0x00 && b <> 0x80 then all_zero := false
      end else
        if b <> 0x00 then all_zero := false
    done;
    not !all_zero
  end

let bool_to_stack b =
  if b then Cstruct.of_string "\x01"
  else Cstruct.create 0

(* ============================================================================
   Script Template Classification
   ============================================================================ *)

type script_template =
  | P2PKH_script of Types.hash160     (* OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG *)
  | P2SH_script of Types.hash160      (* OP_HASH160 <20> OP_EQUAL *)
  | P2WPKH_script of Types.hash160    (* OP_0 <20> *)
  | P2WSH_script of Types.hash256     (* OP_0 <32> *)
  | P2TR_script of Types.hash256      (* OP_1 <32> *)
  | OP_RETURN_data of Cstruct.t       (* OP_RETURN <data> *)
  | Nonstandard

let classify_script (script : Cstruct.t) : script_template =
  let len = Cstruct.length script in
  (* P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG *)
  (* 76 a9 14 <20 bytes> 88 ac = 25 bytes *)
  if len = 25 &&
     Cstruct.get_uint8 script 0 = 0x76 &&
     Cstruct.get_uint8 script 1 = 0xa9 &&
     Cstruct.get_uint8 script 2 = 0x14 &&
     Cstruct.get_uint8 script 23 = 0x88 &&
     Cstruct.get_uint8 script 24 = 0xac
  then P2PKH_script (Cstruct.sub script 3 20)
  (* P2SH: OP_HASH160 <20 bytes> OP_EQUAL *)
  (* a9 14 <20 bytes> 87 = 23 bytes *)
  else if len = 23 &&
     Cstruct.get_uint8 script 0 = 0xa9 &&
     Cstruct.get_uint8 script 1 = 0x14 &&
     Cstruct.get_uint8 script 22 = 0x87
  then P2SH_script (Cstruct.sub script 2 20)
  (* P2WPKH: OP_0 <20 bytes> *)
  (* 00 14 <20 bytes> = 22 bytes *)
  else if len = 22 &&
     Cstruct.get_uint8 script 0 = 0x00 &&
     Cstruct.get_uint8 script 1 = 0x14
  then P2WPKH_script (Cstruct.sub script 2 20)
  (* P2WSH: OP_0 <32 bytes> *)
  (* 00 20 <32 bytes> = 34 bytes *)
  else if len = 34 &&
     Cstruct.get_uint8 script 0 = 0x00 &&
     Cstruct.get_uint8 script 1 = 0x20
  then P2WSH_script (Cstruct.sub script 2 32)
  (* P2TR: OP_1 <32 bytes> *)
  (* 51 20 <32 bytes> = 34 bytes *)
  else if len = 34 &&
     Cstruct.get_uint8 script 0 = 0x51 &&
     Cstruct.get_uint8 script 1 = 0x20
  then P2TR_script (Cstruct.sub script 2 32)
  (* OP_RETURN: starts with 0x6a *)
  else if len >= 1 && Cstruct.get_uint8 script 0 = 0x6a
  then OP_RETURN_data (Cstruct.sub script 1 (len - 1))
  else Nonstandard

(* Check if script is a witness program (OP_n followed by push of 2-40 bytes) *)
let get_witness_program (script : Cstruct.t) : (int * Cstruct.t) option =
  let len = Cstruct.length script in
  if len < 4 || len > 42 then None
  else
    let version_byte = Cstruct.get_uint8 script 0 in
    let version =
      if version_byte = 0x00 then Some 0
      else if version_byte >= 0x51 && version_byte <= 0x60 then
        Some (version_byte - 0x50)
      else None
    in
    match version with
    | None -> None
    | Some v ->
      let push_len = Cstruct.get_uint8 script 1 in
      if push_len >= 2 && push_len <= 40 && len = push_len + 2 then
        Some (v, Cstruct.sub script 2 push_len)
      else None

(* ============================================================================
   Sighash Computation
   ============================================================================ *)

(* Strip all OP_CODESEPARATOR (0xAB) opcodes from a raw script, properly
   skipping push data so that 0xAB bytes inside push data are preserved. *)
let strip_codeseparator (script : Cstruct.t) : Cstruct.t =
  let len = Cstruct.length script in
  let buf = Buffer.create len in
  let i = ref 0 in
  while !i < len do
    let b = Cstruct.get_uint8 script !i in
    if b >= 0x01 && b <= 0x4b then begin
      (* Direct push of b bytes *)
      let data_len = b in
      let chunk_len = 1 + data_len in
      let safe_len = min chunk_len (len - !i) in
      for j = 0 to safe_len - 1 do
        Buffer.add_char buf (Char.chr (Cstruct.get_uint8 script (!i + j)))
      done;
      i := !i + safe_len
    end else if b = 0x4c then begin
      (* OP_PUSHDATA1 *)
      if !i + 1 < len then begin
        let data_len = Cstruct.get_uint8 script (!i + 1) in
        let chunk_len = 2 + data_len in
        let safe_len = min chunk_len (len - !i) in
        for j = 0 to safe_len - 1 do
          Buffer.add_char buf (Char.chr (Cstruct.get_uint8 script (!i + j)))
        done;
        i := !i + safe_len
      end else begin
        Buffer.add_char buf (Char.chr b);
        i := !i + 1
      end
    end else if b = 0x4d then begin
      (* OP_PUSHDATA2 *)
      if !i + 2 < len then begin
        let data_len = Cstruct.LE.get_uint16 script (!i + 1) in
        let chunk_len = 3 + data_len in
        let safe_len = min chunk_len (len - !i) in
        for j = 0 to safe_len - 1 do
          Buffer.add_char buf (Char.chr (Cstruct.get_uint8 script (!i + j)))
        done;
        i := !i + safe_len
      end else begin
        Buffer.add_char buf (Char.chr b);
        i := !i + 1
      end
    end else if b = 0x4e then begin
      (* OP_PUSHDATA4 *)
      if !i + 4 < len then begin
        let data_len = Int32.to_int (Cstruct.LE.get_uint32 script (!i + 1)) in
        let chunk_len = 5 + data_len in
        let safe_len = min chunk_len (len - !i) in
        for j = 0 to safe_len - 1 do
          Buffer.add_char buf (Char.chr (Cstruct.get_uint8 script (!i + j)))
        done;
        i := !i + safe_len
      end else begin
        Buffer.add_char buf (Char.chr b);
        i := !i + 1
      end
    end else if b = 0xab then begin
      (* OP_CODESEPARATOR - skip it *)
      i := !i + 1
    end else begin
      (* Any other opcode - keep it *)
      Buffer.add_char buf (Char.chr b);
      i := !i + 1
    end
  done;
  Cstruct.of_string (Buffer.contents buf)

(* Compute the subscript starting after opcode number n (0-based) by walking
   raw bytes. Used to implement OP_CODESEPARATOR for legacy/segwit v0: the
   scriptCode for sighash is everything after the last OP_CODESEPARATOR. *)
let compute_subscript_from_pos (script : Cstruct.t) (after_op_idx : int) : Cstruct.t =
  let len = Cstruct.length script in
  let i = ref 0 in
  let op_idx = ref 0 in
  while !i < len && !op_idx < after_op_idx do
    let b = Cstruct.get_uint8 script !i in
    if b >= 0x01 && b <= 0x4b then
      i := !i + 1 + b
    else if b = 0x4c then begin
      if !i + 1 < len then begin
        let data_len = Cstruct.get_uint8 script (!i + 1) in
        i := !i + 2 + data_len
      end else
        i := !i + 1
    end else if b = 0x4d then begin
      if !i + 2 < len then begin
        let data_len = Cstruct.LE.get_uint16 script (!i + 1) in
        i := !i + 3 + data_len
      end else
        i := !i + 1
    end else if b = 0x4e then begin
      if !i + 4 < len then begin
        let data_len = Int32.to_int (Cstruct.LE.get_uint32 script (!i + 1)) in
        i := !i + 5 + data_len
      end else
        i := !i + 1
    end else
      i := !i + 1;
    op_idx := !op_idx + 1
  done;
  if !i >= len then Cstruct.create 0
  else Cstruct.sub script !i (len - !i)

(* Check if a hash type byte is one of the defined sighash types *)
let is_defined_hash_type (hash_type : int) : bool =
  let base = hash_type land (lnot 0x80) in  (* strip ANYONECANPAY *)
  base >= 1 && base <= 3  (* SIGHASH_ALL=1, NONE=2, SINGLE=3 *)

(* Check public key encoding validity *)
let check_pubkey_encoding (pk : Cstruct.t) (flags : int) (sig_version : sig_version) : (unit, string) result =
  let pk_len = Cstruct.length pk in
  if pk_len = 0 then Ok ()
  else begin
    (* STRICTENC: must be valid compressed (33 bytes, 0x02/0x03) or uncompressed (65 bytes, 0x04) *)
    if flags land script_verify_strictenc <> 0 then begin
      let valid_encoding =
        (pk_len = 33 && (let prefix = Cstruct.get_uint8 pk 0 in prefix = 0x02 || prefix = 0x03))
        || (pk_len = 65 && Cstruct.get_uint8 pk 0 = 0x04)
      in
      if not valid_encoding then
        Error "Invalid public key encoding"
      else if flags land script_verify_witness_pubkeytype <> 0 &&
              (sig_version = SigVersionWitnessV0) &&
              not (pk_len = 33 && (let prefix = Cstruct.get_uint8 pk 0 in prefix = 0x02 || prefix = 0x03)) then
        Error "Witness requires compressed pubkey"
      else
        Ok ()
    end else begin
      (* Even without STRICTENC, check WITNESS_PUBKEYTYPE *)
      if flags land script_verify_witness_pubkeytype <> 0 &&
         (sig_version = SigVersionWitnessV0) &&
         not (pk_len = 33 && (let prefix = Cstruct.get_uint8 pk 0 in prefix = 0x02 || prefix = 0x03)) then
        Error "Witness requires compressed pubkey"
      else
        Ok ()
    end
  end

(* FindAndDelete: Remove all occurrences of a signature from script
   Only used for legacy sighash, NOT for witness v0 or tapscript *)
let find_and_delete (script : Cstruct.t) (sig_data : Cstruct.t) : Cstruct.t * bool =
  let sig_len = Cstruct.length sig_data in
  if sig_len = 0 then (script, false)
  else
    (* Build the push encoding of the signature *)
    let push_encoded =
      let w = Serialize.writer_create () in
      serialize_opcode w (OP_PUSHDATA (Cstruct.length sig_data, sig_data));
      Serialize.writer_to_cstruct w
    in
    let push_len = Cstruct.length push_encoded in
    let script_len = Cstruct.length script in
    let result = Buffer.create script_len in
    let removed = ref false in
    let i = ref 0 in
    while !i < script_len do
      if !i + push_len <= script_len &&
         Cstruct.equal (Cstruct.sub script !i push_len) push_encoded then begin
        (* Skip the signature *)
        removed := true;
        i := !i + push_len
      end else begin
        Buffer.add_char result (Char.chr (Cstruct.get_uint8 script !i));
        incr i
      end
    done;
    (Cstruct.of_string (Buffer.contents result), !removed)

(* Legacy sighash computation (pre-segwit) *)
let compute_sighash_legacy (tx : Types.transaction) (input_index : int)
    (script_code : Cstruct.t) (hash_type : int) : Types.hash256 =
  (* Bitcoin Core strips OP_CODESEPARATOR from scriptCode before serialization *)
  let script_code = strip_codeseparator script_code in
  let base_type = hash_type land 0x1f in
  let anyone_can_pay = hash_type land sighash_anyonecanpay <> 0 in

  (* SIGHASH_SINGLE bug: if input index >= output count, return special hash *)
  if base_type = sighash_single && input_index >= List.length tx.outputs then begin
    let one = Cstruct.create 32 in
    Cstruct.set_uint8 one 0 1;
    one
  end
  else begin
    (* Build modified transaction *)
    let modified_inputs =
      if anyone_can_pay then
        (* Only include the input being signed *)
        let inp = List.nth tx.inputs input_index in
        [{ inp with Types.script_sig = script_code }]
      else
        List.mapi (fun i inp ->
          if i = input_index then
            { inp with Types.script_sig = script_code }
          else
            let seq =
              if base_type = sighash_none || base_type = sighash_single then
                0l  (* Zero sequence for non-signed inputs *)
              else inp.Types.sequence
            in
            { inp with Types.script_sig = Cstruct.create 0; sequence = seq }
        ) tx.inputs
    in

    let modified_outputs =
      match base_type with
      | t when t = sighash_none ->
        []
      | t when t = sighash_single ->
        (* Only outputs up to and including the signed input's index *)
        List.mapi (fun i out ->
          if i < input_index then
            (* Empty outputs for indices before input_index *)
            { Types.value = (-1L); script_pubkey = Cstruct.create 0 }
          else
            out
        ) (List.filteri (fun i _ -> i <= input_index) tx.outputs)
      | _ -> tx.outputs  (* SIGHASH_ALL *)
    in

    let modified_tx = {
      tx with
      inputs = modified_inputs;
      outputs = modified_outputs;
      witnesses = []
    } in
    let w = Serialize.writer_create () in
    Serialize.serialize_transaction_no_witness w modified_tx;
    Serialize.write_int32_le w (Int32.of_int hash_type);
    Crypto.sha256d (Serialize.writer_to_cstruct w)
  end

(* BIP-143 segwit v0 sighash computation *)
let compute_sighash_segwit (tx : Types.transaction) (input_index : int)
    (script_code : Cstruct.t) (amount : int64) (hash_type : int) : Types.hash256 =
  let base_type = hash_type land 0x1f in
  let anyone_can_pay = hash_type land sighash_anyonecanpay <> 0 in

  (* hashPrevouts *)
  let hash_prevouts =
    if anyone_can_pay then Types.zero_hash
    else begin
      let w = Serialize.writer_create () in
      List.iter (fun inp ->
        Serialize.serialize_outpoint w inp.Types.previous_output
      ) tx.inputs;
      Crypto.sha256d (Serialize.writer_to_cstruct w)
    end
  in

  (* hashSequence *)
  let hash_sequence =
    if anyone_can_pay || base_type = sighash_none || base_type = sighash_single
    then Types.zero_hash
    else begin
      let w = Serialize.writer_create () in
      List.iter (fun inp ->
        Serialize.write_int32_le w inp.Types.sequence
      ) tx.inputs;
      Crypto.sha256d (Serialize.writer_to_cstruct w)
    end
  in

  (* hashOutputs *)
  let hash_outputs =
    if base_type <> sighash_none && base_type <> sighash_single then begin
      let w = Serialize.writer_create () in
      List.iter (Serialize.serialize_tx_out w) tx.outputs;
      Crypto.sha256d (Serialize.writer_to_cstruct w)
    end
    else if base_type = sighash_single && input_index < List.length tx.outputs then begin
      let w = Serialize.writer_create () in
      Serialize.serialize_tx_out w (List.nth tx.outputs input_index);
      Crypto.sha256d (Serialize.writer_to_cstruct w)
    end
    else Types.zero_hash
  in

  (* Build preimage *)
  let w = Serialize.writer_create () in
  Serialize.write_int32_le w tx.version;
  Serialize.write_bytes w hash_prevouts;
  Serialize.write_bytes w hash_sequence;
  let inp = List.nth tx.inputs input_index in
  Serialize.serialize_outpoint w inp.previous_output;
  Serialize.write_compact_size w (Cstruct.length script_code);
  Serialize.write_bytes w script_code;
  Serialize.write_int64_le w amount;
  Serialize.write_int32_le w inp.sequence;
  Serialize.write_bytes w hash_outputs;
  Serialize.write_int32_le w tx.locktime;
  Serialize.write_int32_le w (Int32.of_int hash_type);
  Crypto.sha256d (Serialize.writer_to_cstruct w)

(* BIP-341 Taproot sighash computation (SignatureHashSchnorr).

   Parameters:
   - tx: the transaction being signed
   - input_index: index of the input being signed
   - prevouts: list of ALL input amounts and scriptPubKeys (needed for Taproot)
   - hash_type: the sighash type byte (0x00 = SIGHASH_DEFAULT = ALL)
   - annex_hash: optional SHA256 hash of (compact_size(len) || annex_bytes)
   - tapleaf_hash: optional leaf hash for script path spends
   - codesep_pos: OP_CODESEPARATOR position (0xFFFFFFFF if none)

   prevouts is a list of (amount, scriptPubKey) for ALL inputs. *)
let compute_sighash_taproot
    (tx : Types.transaction)
    (input_index : int)
    (prevouts : (int64 * Cstruct.t) list)
    (hash_type : int)
    ?(annex_hash : Cstruct.t option)
    ?(tapleaf_hash : Cstruct.t option)
    ?(codesep_pos : int = 0xFFFFFFFF)
    () : Cstruct.t =
  (* Validate hash_type *)
  let base_type = hash_type land 0x03 in
  let anyone_can_pay = hash_type land 0x80 <> 0 in
  if not (List.mem hash_type [0x00; 0x01; 0x02; 0x03; 0x81; 0x82; 0x83]) then
    failwith (Printf.sprintf "Invalid Taproot hash_type: 0x%02x" hash_type);

  (* Compute spend_type byte *)
  let has_annex = annex_hash <> None in
  let has_tapleaf = tapleaf_hash <> None in
  let spend_type =
    (if has_annex then 1 else 0) lor
    (if has_tapleaf then 2 else 0)
  in

  (* Begin building the preimage *)
  let w = Serialize.writer_create () in

  (* epoch *)
  Serialize.write_uint8 w 0x00;

  (* hash_type *)
  Serialize.write_uint8 w hash_type;

  (* nVersion *)
  Serialize.write_int32_le w tx.version;

  (* nLockTime *)
  Serialize.write_int32_le w tx.locktime;

  (* If not ANYONECANPAY, compute and write shared input hashes *)
  if not anyone_can_pay then begin
    (* sha_prevouts: SHA256 of all outpoints *)
    let sha_prevouts =
      let pw = Serialize.writer_create () in
      List.iter (fun inp -> Serialize.serialize_outpoint pw inp.Types.previous_output) tx.inputs;
      Crypto.sha256 (Serialize.writer_to_cstruct pw)
    in
    (* sha_amounts: SHA256 of all input amounts *)
    let sha_amounts =
      let pw = Serialize.writer_create () in
      List.iter (fun (amount, _) -> Serialize.write_int64_le pw amount) prevouts;
      Crypto.sha256 (Serialize.writer_to_cstruct pw)
    in
    (* sha_scriptpubkeys: SHA256 of all input scriptPubKeys with compact_size prefix *)
    let sha_scriptpubkeys =
      let pw = Serialize.writer_create () in
      List.iter (fun (_, spk) ->
        Serialize.write_compact_size pw (Cstruct.length spk);
        Serialize.write_bytes pw spk
      ) prevouts;
      Crypto.sha256 (Serialize.writer_to_cstruct pw)
    in
    (* sha_sequences: SHA256 of all input sequences *)
    let sha_sequences =
      let pw = Serialize.writer_create () in
      List.iter (fun inp -> Serialize.write_int32_le pw inp.Types.sequence) tx.inputs;
      Crypto.sha256 (Serialize.writer_to_cstruct pw)
    in
    Serialize.write_bytes w sha_prevouts;
    Serialize.write_bytes w sha_amounts;
    Serialize.write_bytes w sha_scriptpubkeys;
    Serialize.write_bytes w sha_sequences
  end;

  (* If hash_type base is not NONE and not SINGLE, write sha_outputs *)
  if base_type <> 2 && base_type <> 3 then begin
    let sha_outputs =
      let pw = Serialize.writer_create () in
      List.iter (fun out ->
        Serialize.write_int64_le pw out.Types.value;
        Serialize.write_compact_size pw (Cstruct.length out.Types.script_pubkey);
        Serialize.write_bytes pw out.Types.script_pubkey
      ) tx.outputs;
      Crypto.sha256 (Serialize.writer_to_cstruct pw)
    in
    Serialize.write_bytes w sha_outputs
  end;

  (* spend_type *)
  Serialize.write_uint8 w spend_type;

  (* Input data *)
  if anyone_can_pay then begin
    let inp = List.nth tx.inputs input_index in
    let (amount, spk) = List.nth prevouts input_index in
    Serialize.serialize_outpoint w inp.Types.previous_output;
    Serialize.write_int64_le w amount;
    Serialize.write_compact_size w (Cstruct.length spk);
    Serialize.write_bytes w spk;
    Serialize.write_int32_le w inp.sequence
  end else begin
    Serialize.write_int32_le w (Int32.of_int input_index)
  end;

  (* If SIGHASH_SINGLE, write sha_single_output *)
  if base_type = 3 then begin
    if input_index >= List.length tx.outputs then
      failwith "SIGHASH_SINGLE: input_index exceeds number of outputs";
    let out = List.nth tx.outputs input_index in
    let pw = Serialize.writer_create () in
    Serialize.write_int64_le pw out.Types.value;
    Serialize.write_compact_size pw (Cstruct.length out.Types.script_pubkey);
    Serialize.write_bytes pw out.Types.script_pubkey;
    let sha_single_output = Crypto.sha256 (Serialize.writer_to_cstruct pw) in
    Serialize.write_bytes w sha_single_output
  end;

  (* If annex is present *)
  (match annex_hash with
   | Some ah -> Serialize.write_bytes w ah
   | None -> ());

  (* If tapscript (script path spend) *)
  (match tapleaf_hash with
   | Some lh ->
     Serialize.write_bytes w lh;
     (* key_version *)
     Serialize.write_uint8 w 0x00;
     (* codesep_pos *)
     Serialize.write_int32_le w (Int32.of_int codesep_pos)
   | None -> ());

  (* Final tagged hash *)
  Crypto.tagged_hash "TapSighash" (Serialize.writer_to_cstruct w)

(* BIP-342: OP_SUCCESSx opcodes that make tapscript succeed unconditionally *)
let is_op_success (op : int) : bool =
  op = 80 || op = 98 ||
  (op >= 126 && op <= 129) ||
  (op >= 131 && op <= 134) ||
  (op >= 137 && op <= 138) ||
  (op >= 141 && op <= 142) ||
  (op >= 149 && op <= 153) ||
  (op >= 187 && op <= 254)

(* ============================================================================
   Signature Verification Helpers
   ============================================================================ *)

(* Extract hash type from DER signature (last byte) *)
let get_signature_hash_type (sig_bytes : Cstruct.t) : int =
  let len = Cstruct.length sig_bytes in
  if len = 0 then sighash_all
  else Cstruct.get_uint8 sig_bytes (len - 1)

(* Remove hash type byte from signature *)
let strip_hash_type (sig_bytes : Cstruct.t) : Cstruct.t =
  let len = Cstruct.length sig_bytes in
  if len = 0 then sig_bytes
  else Cstruct.sub sig_bytes 0 (len - 1)

(* Build P2PKH script from pubkey hash *)
let build_p2pkh_script (hash : Types.hash160) : Cstruct.t =
  let w = Serialize.writer_create () in
  Serialize.write_uint8 w 0x76;  (* OP_DUP *)
  Serialize.write_uint8 w 0xa9;  (* OP_HASH160 *)
  Serialize.write_uint8 w 0x14;  (* push 20 bytes *)
  Serialize.write_bytes w hash;
  Serialize.write_uint8 w 0x88;  (* OP_EQUALVERIFY *)
  Serialize.write_uint8 w 0xac;  (* OP_CHECKSIG *)
  Serialize.writer_to_cstruct w

(* ============================================================================
   Opcode Execution
   ============================================================================ *)

(* Check if an opcode is a push operation (doesn't count toward op limit) *)
let is_push_opcode = function
  | OP_0 | OP_PUSHDATA (_, _) | OP_1NEGATE
  | OP_1 | OP_2 | OP_3 | OP_4 | OP_5 | OP_6 | OP_7 | OP_8
  | OP_9 | OP_10 | OP_11 | OP_12 | OP_13 | OP_14 | OP_15 | OP_16 -> true
  | _ -> false

(* Execute a single opcode *)
let rec exec_opcode (st : eval_state) (op : opcode) (script_code : Cstruct.t)
    : (unit, string) result =
  let executing = is_executing st in

  (* Count non-push opcodes *)
  if not (is_push_opcode op) then begin
    st.op_count <- st.op_count + 1;
    if st.sig_version <> SigVersionTapscript && st.op_count > max_ops_per_script then
      Error "Opcode limit exceeded"
    else
      (* Continue with opcode execution *)
      exec_opcode_inner st op script_code executing
  end
  else
    exec_opcode_inner st op script_code executing

and exec_opcode_inner (st : eval_state) (op : opcode) (script_code : Cstruct.t)
    (executing : bool) : (unit, string) result =
  (* Handle flow control even when not executing *)
  match op with
  | OP_IF | OP_NOTIF ->
    if executing then begin
      match stack_pop st with
      | Error e -> Error e
      | Ok top ->
        (* MINIMALIF: in tapscript, or when flag is set, argument must be
           exactly empty (false) or exactly 0x01 (true) *)
        if st.sig_version = SigVersionTapscript ||
           (st.flags land script_verify_minimalif <> 0) then begin
          let len = Cstruct.length top in
          let valid_if = len = 0 ||
                         (len = 1 && Cstruct.get_uint8 top 0 = 1) in
          if not valid_if then
            Error "MINIMALIF: argument must be empty or 0x01"
          else begin
            let cond = is_true top in
            let cond = match op with OP_NOTIF -> not cond | _ -> cond in
            st.if_stack <- cond :: st.if_stack;
            Ok ()
          end
        end else begin
          let cond = is_true top in
          let cond = match op with OP_NOTIF -> not cond | _ -> cond in
          st.if_stack <- cond :: st.if_stack;
          Ok ()
        end
    end else begin
      (* Not executing: still track nesting *)
      st.if_stack <- false :: st.if_stack;
      Ok ()
    end

  | OP_ELSE ->
    begin match st.if_stack with
    | [] -> Error "OP_ELSE without OP_IF"
    | b :: rest -> st.if_stack <- (not b) :: rest; Ok ()
    end

  | OP_ENDIF ->
    begin match st.if_stack with
    | [] -> Error "OP_ENDIF without OP_IF"
    | _ :: rest -> st.if_stack <- rest; Ok ()
    end

  | OP_INVALID n when is_disabled_opcode n ->
    (* Disabled opcodes fail unconditionally, even in non-executing branches *)
    Error (Printf.sprintf "Disabled opcode 0x%02x" n)

  | OP_CODESEPARATOR when st.sig_version = SigVersionBase &&
                          st.flags land script_verify_const_scriptcode <> 0 ->
    (* CONST_SCRIPTCODE: OP_CODESEPARATOR rejected even in non-executing branches *)
    Error "CONST_SCRIPTCODE: OP_CODESEPARATOR in legacy script"

  | _ when not executing ->
    (* Skip all other opcodes when not executing *)
    Ok ()

  (* Constants *)
  | OP_0 ->
    stack_push st (Cstruct.create 0)

  | OP_PUSHDATA (opbyte, data) ->
    if st.sig_version <> SigVersionTapscript && Cstruct.length data > max_script_element_size then
      Error "Push data exceeds maximum size"
    else if st.flags land script_verify_minimaldata <> 0 then begin
      let dlen = Cstruct.length data in
      let not_minimal =
        if dlen = 0 then
          (* Empty data should use OP_0 (separate opcode), so any OP_PUSHDATA with empty is non-minimal *)
          true
        else if dlen = 1 then begin
          let byte = Cstruct.get_uint8 data 0 in
          if byte >= 1 && byte <= 16 then true  (* Should use OP_1..OP_16 *)
          else if byte = 0x81 then true  (* Should use OP_1NEGATE *)
          else false
        end
        else false
      in
      let not_minimal = not_minimal ||
        (dlen <= 75 && (opbyte = 0x4c || opbyte = 0x4d || opbyte = 0x4e)) ||
        (dlen <= 255 && (opbyte = 0x4d || opbyte = 0x4e)) ||
        (dlen <= 65535 && opbyte = 0x4e)
      in
      if not_minimal then
        Error "Non-minimal push"
      else
        stack_push st data
    end else
      stack_push st data

  | OP_1NEGATE ->
    stack_push st (bytes_of_script_num (-1L))

  | OP_1 -> stack_push st (bytes_of_script_num 1L)
  | OP_2 -> stack_push st (bytes_of_script_num 2L)
  | OP_3 -> stack_push st (bytes_of_script_num 3L)
  | OP_4 -> stack_push st (bytes_of_script_num 4L)
  | OP_5 -> stack_push st (bytes_of_script_num 5L)
  | OP_6 -> stack_push st (bytes_of_script_num 6L)
  | OP_7 -> stack_push st (bytes_of_script_num 7L)
  | OP_8 -> stack_push st (bytes_of_script_num 8L)
  | OP_9 -> stack_push st (bytes_of_script_num 9L)
  | OP_10 -> stack_push st (bytes_of_script_num 10L)
  | OP_11 -> stack_push st (bytes_of_script_num 11L)
  | OP_12 -> stack_push st (bytes_of_script_num 12L)
  | OP_13 -> stack_push st (bytes_of_script_num 13L)
  | OP_14 -> stack_push st (bytes_of_script_num 14L)
  | OP_15 -> stack_push st (bytes_of_script_num 15L)
  | OP_16 -> stack_push st (bytes_of_script_num 16L)

  (* Flow control *)
  | OP_NOP -> Ok ()

  | OP_VERIFY ->
    begin match stack_pop st with
    | Error e -> Error e
    | Ok top ->
      if is_true top then Ok ()
      else Error "OP_VERIFY failed"
    end

  | OP_RETURN ->
    Error "OP_RETURN"

  (* Stack operations *)
  | OP_TOALTSTACK ->
    begin match stack_pop st with
    | Error e -> Error e
    | Ok v ->
      if List.length st.stack + List.length st.altstack >= max_stack_size then
        Error "Alt stack overflow"
      else begin
        st.altstack <- v :: st.altstack;
        Ok ()
      end
    end

  | OP_FROMALTSTACK ->
    begin match st.altstack with
    | [] -> Error "Alt stack empty"
    | v :: rest ->
      st.altstack <- rest;
      stack_push st v
    end

  | OP_IFDUP ->
    begin match stack_top st with
    | Error e -> Error e
    | Ok top ->
      if is_true top then stack_push st top
      else Ok ()
    end

  | OP_DEPTH ->
    stack_push st (bytes_of_script_num (Int64.of_int (stack_size st)))

  | OP_DROP ->
    begin match stack_pop st with
    | Error e -> Error e
    | Ok _ -> Ok ()
    end

  | OP_DUP ->
    begin match stack_top st with
    | Error e -> Error e
    | Ok top -> stack_push st top
    end

  | OP_NIP ->
    begin match st.stack with
    | [] | [_] -> Error "Stack underflow"
    | a :: _ :: rest -> st.stack <- a :: rest; Ok ()
    end

  | OP_OVER ->
    begin match st.stack with
    | [] | [_] -> Error "Stack underflow"
    | _ :: b :: _ -> stack_push st b
    end

  | OP_PICK ->
    begin match stack_pop st with
    | Error e -> Error e
    | Ok n_bytes ->
      let n = Int64.to_int (script_num_of_bytes ~require_minimal:(st.flags land script_verify_minimaldata <> 0) n_bytes) in
      if n < 0 || n >= stack_size st then Error "Invalid stack index"
      else begin
        let v = List.nth st.stack n in
        stack_push st v
      end
    end

  | OP_ROLL ->
    begin match stack_pop st with
    | Error e -> Error e
    | Ok n_bytes ->
      let n = Int64.to_int (script_num_of_bytes ~require_minimal:(st.flags land script_verify_minimaldata <> 0) n_bytes) in
      if n < 0 || n >= stack_size st then Error "Invalid stack index"
      else begin
        let v = List.nth st.stack n in
        let before = List.filteri (fun i _ -> i < n) st.stack in
        let after = List.filteri (fun i _ -> i > n) st.stack in
        st.stack <- v :: (before @ after);
        Ok ()
      end
    end

  | OP_ROT ->
    begin match st.stack with
    | a :: b :: c :: rest -> st.stack <- c :: a :: b :: rest; Ok ()
    | _ -> Error "Stack underflow"
    end

  | OP_SWAP ->
    begin match st.stack with
    | a :: b :: rest -> st.stack <- b :: a :: rest; Ok ()
    | _ -> Error "Stack underflow"
    end

  | OP_TUCK ->
    begin match st.stack with
    | a :: b :: rest ->
      st.stack <- a :: b :: a :: rest;
      if List.length st.stack + List.length st.altstack > max_stack_size then
        Error "Stack overflow"
      else
        Ok ()
    | _ -> Error "Stack underflow"
    end

  | OP_2DROP ->
    begin match st.stack with
    | _ :: _ :: rest -> st.stack <- rest; Ok ()
    | _ -> Error "Stack underflow"
    end

  | OP_2DUP ->
    begin match st.stack with
    | a :: b :: _ ->
      st.stack <- a :: b :: st.stack;
      if List.length st.stack + List.length st.altstack > max_stack_size then
        Error "Stack overflow"
      else
        Ok ()
    | _ -> Error "Stack underflow"
    end

  | OP_3DUP ->
    begin match st.stack with
    | a :: b :: c :: _ ->
      st.stack <- a :: b :: c :: st.stack;
      if List.length st.stack + List.length st.altstack > max_stack_size then
        Error "Stack overflow"
      else
        Ok ()
    | _ -> Error "Stack underflow"
    end

  | OP_2OVER ->
    begin match st.stack with
    | _ :: _ :: c :: d :: _ ->
      st.stack <- c :: d :: st.stack;
      if List.length st.stack + List.length st.altstack > max_stack_size then
        Error "Stack overflow"
      else
        Ok ()
    | _ -> Error "Stack underflow"
    end

  | OP_2ROT ->
    begin match st.stack with
    | a :: b :: c :: d :: e :: f :: rest ->
      st.stack <- e :: f :: a :: b :: c :: d :: rest; Ok ()
    | _ -> Error "Stack underflow"
    end

  | OP_2SWAP ->
    begin match st.stack with
    | a :: b :: c :: d :: rest ->
      st.stack <- c :: d :: a :: b :: rest; Ok ()
    | _ -> Error "Stack underflow"
    end

  | OP_SIZE ->
    begin match stack_top st with
    | Error e -> Error e
    | Ok top ->
      stack_push st (bytes_of_script_num (Int64.of_int (Cstruct.length top)))
    end

  (* Bitwise logic *)
  | OP_EQUAL ->
    begin match stack_pop st with
    | Error e -> Error e
    | Ok a ->
      begin match stack_pop st with
      | Error e -> Error e
      | Ok b ->
        let eq = Cstruct.equal a b in
        stack_push st (bool_to_stack eq)
      end
    end

  | OP_EQUALVERIFY ->
    begin match stack_pop st with
    | Error e -> Error e
    | Ok a ->
      begin match stack_pop st with
      | Error e -> Error e
      | Ok b ->
        if Cstruct.equal a b then Ok ()
        else Error "OP_EQUALVERIFY failed"
      end
    end

  (* Arithmetic *)
  | OP_1ADD ->
    begin match stack_pop st with
    | Error e -> Error e
    | Ok a ->
      let n = script_num_of_bytes ~require_minimal:(st.flags land script_verify_minimaldata <> 0) a in
      stack_push st (bytes_of_script_num (Int64.add n 1L))
    end

  | OP_1SUB ->
    begin match stack_pop st with
    | Error e -> Error e
    | Ok a ->
      let n = script_num_of_bytes ~require_minimal:(st.flags land script_verify_minimaldata <> 0) a in
      stack_push st (bytes_of_script_num (Int64.sub n 1L))
    end

  | OP_NEGATE ->
    begin match stack_pop st with
    | Error e -> Error e
    | Ok a ->
      let n = script_num_of_bytes ~require_minimal:(st.flags land script_verify_minimaldata <> 0) a in
      stack_push st (bytes_of_script_num (Int64.neg n))
    end

  | OP_ABS ->
    begin match stack_pop st with
    | Error e -> Error e
    | Ok a ->
      let n = script_num_of_bytes ~require_minimal:(st.flags land script_verify_minimaldata <> 0) a in
      stack_push st (bytes_of_script_num (Int64.abs n))
    end

  | OP_NOT ->
    begin match stack_pop st with
    | Error e -> Error e
    | Ok a ->
      let n = script_num_of_bytes ~require_minimal:(st.flags land script_verify_minimaldata <> 0) a in
      let result = if n = 0L then 1L else 0L in
      stack_push st (bytes_of_script_num result)
    end

  | OP_0NOTEQUAL ->
    begin match stack_pop st with
    | Error e -> Error e
    | Ok a ->
      let n = script_num_of_bytes ~require_minimal:(st.flags land script_verify_minimaldata <> 0) a in
      let result = if n = 0L then 0L else 1L in
      stack_push st (bytes_of_script_num result)
    end

  | OP_ADD ->
    begin match stack_pop st with
    | Error e -> Error e
    | Ok a ->
      begin match stack_pop st with
      | Error e -> Error e
      | Ok b ->
        let na = script_num_of_bytes ~require_minimal:(st.flags land script_verify_minimaldata <> 0) a in
        let nb = script_num_of_bytes ~require_minimal:(st.flags land script_verify_minimaldata <> 0) b in
        stack_push st (bytes_of_script_num (Int64.add na nb))
      end
    end

  | OP_SUB ->
    begin match stack_pop st with
    | Error e -> Error e
    | Ok a ->
      begin match stack_pop st with
      | Error e -> Error e
      | Ok b ->
        let na = script_num_of_bytes ~require_minimal:(st.flags land script_verify_minimaldata <> 0) a in
        let nb = script_num_of_bytes ~require_minimal:(st.flags land script_verify_minimaldata <> 0) b in
        (* Note: b - a because a is on top of stack *)
        stack_push st (bytes_of_script_num (Int64.sub nb na))
      end
    end

  | OP_BOOLAND ->
    begin match stack_pop st with
    | Error e -> Error e
    | Ok a ->
      begin match stack_pop st with
      | Error e -> Error e
      | Ok b ->
        let na = script_num_of_bytes ~require_minimal:(st.flags land script_verify_minimaldata <> 0) a in
        let nb = script_num_of_bytes ~require_minimal:(st.flags land script_verify_minimaldata <> 0) b in
        let result = if na <> 0L && nb <> 0L then 1L else 0L in
        stack_push st (bytes_of_script_num result)
      end
    end

  | OP_BOOLOR ->
    begin match stack_pop st with
    | Error e -> Error e
    | Ok a ->
      begin match stack_pop st with
      | Error e -> Error e
      | Ok b ->
        let na = script_num_of_bytes ~require_minimal:(st.flags land script_verify_minimaldata <> 0) a in
        let nb = script_num_of_bytes ~require_minimal:(st.flags land script_verify_minimaldata <> 0) b in
        let result = if na <> 0L || nb <> 0L then 1L else 0L in
        stack_push st (bytes_of_script_num result)
      end
    end

  | OP_NUMEQUAL ->
    begin match stack_pop st with
    | Error e -> Error e
    | Ok a ->
      begin match stack_pop st with
      | Error e -> Error e
      | Ok b ->
        let na = script_num_of_bytes ~require_minimal:(st.flags land script_verify_minimaldata <> 0) a in
        let nb = script_num_of_bytes ~require_minimal:(st.flags land script_verify_minimaldata <> 0) b in
        let result = if na = nb then 1L else 0L in
        stack_push st (bytes_of_script_num result)
      end
    end

  | OP_NUMEQUALVERIFY ->
    begin match stack_pop st with
    | Error e -> Error e
    | Ok a ->
      begin match stack_pop st with
      | Error e -> Error e
      | Ok b ->
        let na = script_num_of_bytes ~require_minimal:(st.flags land script_verify_minimaldata <> 0) a in
        let nb = script_num_of_bytes ~require_minimal:(st.flags land script_verify_minimaldata <> 0) b in
        if na = nb then Ok ()
        else Error "OP_NUMEQUALVERIFY failed"
      end
    end

  | OP_NUMNOTEQUAL ->
    begin match stack_pop st with
    | Error e -> Error e
    | Ok a ->
      begin match stack_pop st with
      | Error e -> Error e
      | Ok b ->
        let na = script_num_of_bytes ~require_minimal:(st.flags land script_verify_minimaldata <> 0) a in
        let nb = script_num_of_bytes ~require_minimal:(st.flags land script_verify_minimaldata <> 0) b in
        let result = if na <> nb then 1L else 0L in
        stack_push st (bytes_of_script_num result)
      end
    end

  | OP_LESSTHAN ->
    begin match stack_pop st with
    | Error e -> Error e
    | Ok a ->
      begin match stack_pop st with
      | Error e -> Error e
      | Ok b ->
        let na = script_num_of_bytes ~require_minimal:(st.flags land script_verify_minimaldata <> 0) a in
        let nb = script_num_of_bytes ~require_minimal:(st.flags land script_verify_minimaldata <> 0) b in
        let result = if nb < na then 1L else 0L in
        stack_push st (bytes_of_script_num result)
      end
    end

  | OP_GREATERTHAN ->
    begin match stack_pop st with
    | Error e -> Error e
    | Ok a ->
      begin match stack_pop st with
      | Error e -> Error e
      | Ok b ->
        let na = script_num_of_bytes ~require_minimal:(st.flags land script_verify_minimaldata <> 0) a in
        let nb = script_num_of_bytes ~require_minimal:(st.flags land script_verify_minimaldata <> 0) b in
        let result = if nb > na then 1L else 0L in
        stack_push st (bytes_of_script_num result)
      end
    end

  | OP_LESSTHANOREQUAL ->
    begin match stack_pop st with
    | Error e -> Error e
    | Ok a ->
      begin match stack_pop st with
      | Error e -> Error e
      | Ok b ->
        let na = script_num_of_bytes ~require_minimal:(st.flags land script_verify_minimaldata <> 0) a in
        let nb = script_num_of_bytes ~require_minimal:(st.flags land script_verify_minimaldata <> 0) b in
        let result = if nb <= na then 1L else 0L in
        stack_push st (bytes_of_script_num result)
      end
    end

  | OP_GREATERTHANOREQUAL ->
    begin match stack_pop st with
    | Error e -> Error e
    | Ok a ->
      begin match stack_pop st with
      | Error e -> Error e
      | Ok b ->
        let na = script_num_of_bytes ~require_minimal:(st.flags land script_verify_minimaldata <> 0) a in
        let nb = script_num_of_bytes ~require_minimal:(st.flags land script_verify_minimaldata <> 0) b in
        let result = if nb >= na then 1L else 0L in
        stack_push st (bytes_of_script_num result)
      end
    end

  | OP_MIN ->
    begin match stack_pop st with
    | Error e -> Error e
    | Ok a ->
      begin match stack_pop st with
      | Error e -> Error e
      | Ok b ->
        let na = script_num_of_bytes ~require_minimal:(st.flags land script_verify_minimaldata <> 0) a in
        let nb = script_num_of_bytes ~require_minimal:(st.flags land script_verify_minimaldata <> 0) b in
        stack_push st (bytes_of_script_num (min na nb))
      end
    end

  | OP_MAX ->
    begin match stack_pop st with
    | Error e -> Error e
    | Ok a ->
      begin match stack_pop st with
      | Error e -> Error e
      | Ok b ->
        let na = script_num_of_bytes ~require_minimal:(st.flags land script_verify_minimaldata <> 0) a in
        let nb = script_num_of_bytes ~require_minimal:(st.flags land script_verify_minimaldata <> 0) b in
        stack_push st (bytes_of_script_num (max na nb))
      end
    end

  | OP_WITHIN ->
    begin match stack_pop st with
    | Error e -> Error e
    | Ok max_bytes ->
      begin match stack_pop st with
      | Error e -> Error e
      | Ok min_bytes ->
        begin match stack_pop st with
        | Error e -> Error e
        | Ok x_bytes ->
          let x = script_num_of_bytes ~require_minimal:(st.flags land script_verify_minimaldata <> 0) x_bytes in
          let min_val = script_num_of_bytes ~require_minimal:(st.flags land script_verify_minimaldata <> 0) min_bytes in
          let max_val = script_num_of_bytes ~require_minimal:(st.flags land script_verify_minimaldata <> 0) max_bytes in
          let result = if x >= min_val && x < max_val then 1L else 0L in
          stack_push st (bytes_of_script_num result)
        end
      end
    end

  (* Crypto *)
  | OP_RIPEMD160 ->
    begin match stack_pop st with
    | Error e -> Error e
    | Ok data ->
      let hash = Digestif.RMD160.digest_string (Cstruct.to_string data) in
      let result = Cstruct.of_string (Digestif.RMD160.to_raw_string hash) in
      stack_push st result
    end

  | OP_SHA1 ->
    begin match stack_pop st with
    | Error e -> Error e
    | Ok data ->
      let hash = Digestif.SHA1.digest_string (Cstruct.to_string data) in
      let result = Cstruct.of_string (Digestif.SHA1.to_raw_string hash) in
      stack_push st result
    end

  | OP_SHA256 ->
    begin match stack_pop st with
    | Error e -> Error e
    | Ok data ->
      let result = Crypto.sha256 data in
      stack_push st result
    end

  | OP_HASH160 ->
    begin match stack_pop st with
    | Error e -> Error e
    | Ok data ->
      let result = Crypto.hash160 data in
      stack_push st result
    end

  | OP_HASH256 ->
    begin match stack_pop st with
    | Error e -> Error e
    | Ok data ->
      let result = Crypto.sha256d data in
      stack_push st result
    end

  | OP_CODESEPARATOR ->
    st.codesep_pos <- st.current_op_idx;
    Ok ()

  | OP_CHECKSIG ->
    (* Pop pubkey first (top), then signature (deeper) - PITFALL *)
    begin match stack_pop st with
    | Error e -> Error e
    | Ok pubkey ->
      begin match stack_pop st with
      | Error e -> Error e
      | Ok sig_bytes ->
        if st.sig_version = SigVersionTapscript then begin
          (* Tapscript OP_CHECKSIG: Schnorr verification *)
          if Cstruct.length pubkey = 0 then
            Error "Empty pubkey in tapscript OP_CHECKSIG"
          else if Cstruct.length pubkey <> 32 then begin
            (* Unknown pubkey type: treat as success unless discouraged *)
            if st.flags land script_verify_discourage_upgradable_pubkeytype <> 0 then
              Error "Discouraged unknown public key type in tapscript"
            else
              stack_push st (bool_to_stack true)
          end
          else if Cstruct.length sig_bytes = 0 then begin
            (* Empty signature: push false, no sigops budget cost *)
            stack_push st (bool_to_stack false)
          end else begin
            st.sigops_budget <- st.sigops_budget - 50;
            if st.sigops_budget < 0 then
              Error "Tapscript validation weight budget exceeded"
            else begin
              let sig_len = Cstruct.length sig_bytes in
              if sig_len <> 64 && sig_len <> 65 then
                Error "Invalid tapscript signature length"
              else begin
                let hash_type = if sig_len = 65 then
                  Cstruct.get_uint8 sig_bytes 64
                else 0
                in
                if sig_len = 65 && hash_type = 0 then
                  Error "Invalid hash_type 0x00 in 65-byte tapscript sig"
                else begin
                  let sig_64 = Cstruct.sub sig_bytes 0 64 in
                  let sighash = compute_sighash_taproot st.tx st.input_index st.prevouts hash_type
                    ?annex_hash:st.annex_hash ?tapleaf_hash:st.tapleaf_hash
                    ~codesep_pos:st.codesep_pos () in
                  let valid = Crypto.schnorr_verify ~pubkey_x:pubkey ~msg:sighash ~signature:sig_64 in
                  if not valid then
                    Error "Tapscript OP_CHECKSIG Schnorr verification failed"
                  else
                    stack_push st (bool_to_stack true)
                end
              end
            end
          end
        end else begin
          (* Legacy / SegWit v0 OP_CHECKSIG: ECDSA verification *)
          (* Check pubkey encoding *)
          match check_pubkey_encoding pubkey st.flags st.sig_version with
          | Error e -> Error e
          | Ok () ->
          if Cstruct.length sig_bytes = 0 then
            stack_push st (bool_to_stack false)
          else begin
            let sig_der = strip_hash_type sig_bytes in
            (* DER strict encoding check *)
            if st.flags land script_verify_dersig <> 0 &&
               not (Crypto.is_valid_signature_encoding sig_der) then
              Error "Non-strict DER signature"
            (* LOW_S check *)
            else if st.flags land script_verify_low_s <> 0 &&
                    not (Crypto.is_low_der_s sig_der) then
              Error "Non-low-S signature"
            else begin
              let hash_type = get_signature_hash_type sig_bytes in
              (* STRICTENC hash type validation *)
              if st.flags land script_verify_strictenc <> 0 &&
                 not (is_defined_hash_type hash_type) then
                Error "Invalid hash type"
              else begin
                (* Compute effective scriptCode accounting for OP_CODESEPARATOR *)
                let effective_script_code =
                  if st.codesep_pos <> 0xFFFFFFFF then
                    compute_subscript_from_pos script_code (st.codesep_pos + 1)
                  else script_code
                in
                let checksig_result = match st.sig_version with
                  | SigVersionBase ->
                    let (cleaned, removed) = find_and_delete effective_script_code sig_bytes in
                    if removed && st.flags land script_verify_const_scriptcode <> 0 then
                      Error "CONST_SCRIPTCODE: find_and_delete modified scriptCode"
                    else
                      let sighash = compute_sighash_legacy st.tx st.input_index cleaned hash_type in
                      Ok sighash
                  | SigVersionWitnessV0 ->
                    Ok (compute_sighash_segwit st.tx st.input_index effective_script_code st.amount hash_type)
                  | SigVersionTaproot | SigVersionTapscript ->
                    Ok (compute_sighash_segwit st.tx st.input_index effective_script_code st.amount hash_type)
                in
                match checksig_result with
                | Error e -> Error e
                | Ok sighash ->
                let valid = Crypto.verify pubkey sighash sig_der in
                if (not valid) && Cstruct.length sig_bytes > 0 &&
                   (st.flags land script_verify_nullfail <> 0) then
                  Error "NULLFAIL: non-empty signature on failed CHECKSIG"
                else
                  stack_push st (bool_to_stack valid)
              end
            end
          end
        end
      end
    end

  | OP_CHECKSIGVERIFY ->
    begin match stack_pop st with
    | Error e -> Error e
    | Ok pubkey ->
      begin match stack_pop st with
      | Error e -> Error e
      | Ok sig_bytes ->
        if st.sig_version = SigVersionTapscript then begin
          (* Tapscript OP_CHECKSIGVERIFY: Schnorr verification *)
          if Cstruct.length pubkey = 0 then
            Error "Empty pubkey in tapscript OP_CHECKSIGVERIFY"
          else if Cstruct.length pubkey <> 32 then begin
            (* Unknown pubkey type: treat as success unless discouraged *)
            if st.flags land script_verify_discourage_upgradable_pubkeytype <> 0 then
              Error "Discouraged unknown public key type in tapscript"
            else
              Ok ()
          end
          else if Cstruct.length sig_bytes = 0 then
            Error "OP_CHECKSIGVERIFY failed (empty sig in tapscript)"
          else begin
            st.sigops_budget <- st.sigops_budget - 50;
            if st.sigops_budget < 0 then
              Error "Tapscript validation weight budget exceeded"
            else begin
              let sig_len = Cstruct.length sig_bytes in
              if sig_len <> 64 && sig_len <> 65 then
                Error "Invalid tapscript signature length"
              else begin
                let hash_type = if sig_len = 65 then
                  Cstruct.get_uint8 sig_bytes 64
                else 0
                in
                if sig_len = 65 && hash_type = 0 then
                  Error "Invalid hash_type 0x00 in 65-byte tapscript sig"
                else begin
                  let sig_64 = Cstruct.sub sig_bytes 0 64 in
                  let sighash = compute_sighash_taproot st.tx st.input_index st.prevouts hash_type
                    ?annex_hash:st.annex_hash ?tapleaf_hash:st.tapleaf_hash
                    ~codesep_pos:st.codesep_pos () in
                  let valid = Crypto.schnorr_verify ~pubkey_x:pubkey ~msg:sighash ~signature:sig_64 in
                  if valid then Ok ()
                  else Error "Tapscript OP_CHECKSIGVERIFY Schnorr verification failed"
                end
              end
            end
          end
        end else begin
          (* Legacy / SegWit v0 OP_CHECKSIGVERIFY *)
          (* Check pubkey encoding *)
          match check_pubkey_encoding pubkey st.flags st.sig_version with
          | Error e -> Error e
          | Ok () ->
          if Cstruct.length sig_bytes = 0 then
            Error "OP_CHECKSIGVERIFY failed (empty sig)"
          else begin
            let sig_der = strip_hash_type sig_bytes in
            if st.flags land script_verify_dersig <> 0 &&
               not (Crypto.is_valid_signature_encoding sig_der) then
              Error "Non-strict DER signature"
            else if st.flags land script_verify_low_s <> 0 &&
                    not (Crypto.is_low_der_s sig_der) then
              Error "Non-low-S signature"
            else begin
              let hash_type = get_signature_hash_type sig_bytes in
              (* STRICTENC hash type validation *)
              if st.flags land script_verify_strictenc <> 0 &&
                 not (is_defined_hash_type hash_type) then
                Error "Invalid hash type"
              else begin
                (* Compute effective scriptCode accounting for OP_CODESEPARATOR *)
                let effective_script_code =
                  if st.codesep_pos <> 0xFFFFFFFF then
                    compute_subscript_from_pos script_code (st.codesep_pos + 1)
                  else script_code
                in
                let checksig_result = match st.sig_version with
                  | SigVersionBase ->
                    let (cleaned, removed) = find_and_delete effective_script_code sig_bytes in
                    if removed && st.flags land script_verify_const_scriptcode <> 0 then
                      Error "CONST_SCRIPTCODE: find_and_delete modified scriptCode"
                    else
                      let sighash = compute_sighash_legacy st.tx st.input_index cleaned hash_type in
                      Ok sighash
                  | SigVersionWitnessV0 ->
                    Ok (compute_sighash_segwit st.tx st.input_index effective_script_code st.amount hash_type)
                  | SigVersionTaproot | SigVersionTapscript ->
                    Ok (compute_sighash_segwit st.tx st.input_index effective_script_code st.amount hash_type)
                in
                match checksig_result with
                | Error e -> Error e
                | Ok sighash ->
                let valid = Crypto.verify pubkey sighash sig_der in
                if valid then Ok ()
                else if Cstruct.length sig_bytes > 0 &&
                        (st.flags land script_verify_nullfail <> 0) then
                  Error "NULLFAIL: non-empty signature on failed CHECKSIGVERIFY"
                else Error "OP_CHECKSIGVERIFY failed"
              end
            end
          end
        end
      end
    end

  | OP_CHECKMULTISIG | OP_CHECKMULTISIGVERIFY ->
    (* BIP-342: OP_CHECKMULTISIG is disabled in tapscript *)
    if st.sig_version = SigVersionTapscript then
      Error "OP_CHECKMULTISIG(VERIFY) is disabled in tapscript"
    else
    (* Shared logic for both variants *)
    let is_verify = match op with OP_CHECKMULTISIGVERIFY -> true | _ -> false in
    begin match stack_pop st with
    | Error e -> Error e
    | Ok n_bytes ->
      let n_pubkeys = Int64.to_int (script_num_of_bytes n_bytes) in
      if n_pubkeys < 0 || n_pubkeys > max_pubkeys_per_multisig then
        Error "Invalid pubkey count"
      else begin
        st.op_count <- st.op_count + n_pubkeys;
        if st.op_count > max_ops_per_script then
          Error "Opcode limit exceeded"
        else begin
          (* Pop n pubkeys *)
          let rec pop_n n acc =
            if n = 0 then Ok (List.rev acc)
            else match stack_pop st with
              | Error e -> Error e
              | Ok v -> pop_n (n - 1) (v :: acc)
          in
          match pop_n n_pubkeys [] with
          | Error e -> Error e
          | Ok pubkeys ->
            (* Check pubkey encoding for all pubkeys *)
            let pk_check_err = ref None in
            List.iter (fun pk ->
              if !pk_check_err = None then
                match check_pubkey_encoding pk st.flags st.sig_version with
                | Error e -> pk_check_err := Some e
                | Ok () -> ()
            ) pubkeys;
            begin match !pk_check_err with
            | Some e -> Error e
            | None ->
            begin match stack_pop st with
            | Error e -> Error e
            | Ok m_bytes ->
              let m_sigs = Int64.to_int (script_num_of_bytes m_bytes) in
              if m_sigs < 0 || m_sigs > n_pubkeys then
                Error "Invalid signature count"
              else begin
                (* Pop m signatures *)
                match pop_n m_sigs [] with
                | Error e -> Error e
                | Ok sigs ->
                  (* Pop the dummy element (CHECKMULTISIG bug) *)
                  begin match stack_pop st with
                  | Error e -> Error e
                  | Ok dummy ->
                    (* NULLDUMMY check for witness *)
                    if st.flags land script_verify_nulldummy <> 0 &&
                       Cstruct.length dummy <> 0 then
                      Error "NULLDUMMY violation"
                    else begin
                      (* DER/LOW_S/STRICTENC checks on all non-empty signatures *)
                      let sig_check_err = ref None in
                      List.iter (fun sig_bytes ->
                        if Cstruct.length sig_bytes > 0 && !sig_check_err = None then begin
                          let sig_der = strip_hash_type sig_bytes in
                          if st.flags land script_verify_dersig <> 0 &&
                             not (Crypto.is_valid_signature_encoding sig_der) then
                            sig_check_err := Some "Non-strict DER signature"
                          else if st.flags land script_verify_low_s <> 0 &&
                                  not (Crypto.is_low_der_s sig_der) then
                            sig_check_err := Some "Non-low-S signature"
                          else if st.flags land script_verify_strictenc <> 0 then begin
                            let ht = get_signature_hash_type sig_bytes in
                            if not (is_defined_hash_type ht) then
                              sig_check_err := Some "Invalid hash type"
                          end
                        end
                      ) sigs;
                      match !sig_check_err with
                      | Some e -> Error e
                      | None ->
                      (* Compute effective scriptCode accounting for OP_CODESEPARATOR *)
                      let effective_script_code =
                        if st.codesep_pos <> 0xFFFFFFFF then
                          compute_subscript_from_pos script_code (st.codesep_pos + 1)
                        else script_code
                      in
                      (* Pre-clean scriptCode by removing ALL signatures (FindAndDelete) *)
                      let any_removed = ref false in
                      let cleaned_script = List.fold_left (fun sc sig_bytes ->
                        if Cstruct.length sig_bytes > 0 then begin
                          let (result, removed) = find_and_delete sc sig_bytes in
                          if removed then any_removed := true;
                          result
                        end else sc
                      ) effective_script_code sigs in
                      if !any_removed && st.sig_version = SigVersionBase &&
                         st.flags land script_verify_const_scriptcode <> 0 then
                        Error "CONST_SCRIPTCODE: find_and_delete modified scriptCode"
                      else
                      (* Verify signatures in order *)
                      let rec verify_sigs sigs pubkeys success =
                        match sigs with
                        | [] -> success
                        | sig_bytes :: rest_sigs ->
                          if Cstruct.length sig_bytes = 0 then false
                          else begin
                            let hash_type = get_signature_hash_type sig_bytes in
                            let sig_der = strip_hash_type sig_bytes in
                            let sighash = match st.sig_version with
                              | SigVersionBase ->
                                compute_sighash_legacy st.tx st.input_index cleaned_script hash_type
                              | SigVersionWitnessV0 ->
                                compute_sighash_segwit st.tx st.input_index cleaned_script st.amount hash_type
                              | SigVersionTaproot | SigVersionTapscript ->
                                compute_sighash_segwit st.tx st.input_index cleaned_script st.amount hash_type
                            in
                            (* Try each remaining pubkey *)
                            let rec try_pubkeys = function
                              | [] -> false  (* No more pubkeys *)
                              | pk :: rest_pks ->
                                if Crypto.verify pk sighash sig_der then
                                  verify_sigs rest_sigs rest_pks true
                                else
                                  try_pubkeys rest_pks
                            in
                            try_pubkeys pubkeys
                          end
                      in
                      let success = m_sigs = 0 || verify_sigs sigs pubkeys true in
                      (* NULLFAIL: if verification failed, all signatures must be empty *)
                      if (not success) &&
                         (st.flags land script_verify_nullfail <> 0) &&
                         List.exists (fun s -> Cstruct.length s > 0) sigs then
                        Error "NULLFAIL: non-empty signature on failed CHECKMULTISIG"
                      else if is_verify then
                        if success then Ok () else Error "OP_CHECKMULTISIGVERIFY failed"
                      else
                        stack_push st (bool_to_stack success)
                    end
                  end
              end
            end
            end
        end
      end
    end

  (* Locktime operations *)
  | OP_CHECKLOCKTIMEVERIFY ->
    if st.flags land script_verify_checklocktimeverify = 0 then
      Ok ()  (* Treat as NOP if not enabled *)
    else begin
      match stack_top st with
      | Error e -> Error e
      | Ok lock_bytes ->
        if Cstruct.length lock_bytes > 5 then
          Error "CLTV argument too long"
        else begin
          let locktime = script_num_of_bytes ~max_bytes:5 lock_bytes in
          if locktime < 0L then
            Error "Negative locktime"
          else begin
            let tx_locktime = Int64.of_int32 (Int32.logand st.tx.locktime 0xFFFFFFFFl) in
            (* Check same type (blocks vs time) *)
            let both_blocks = locktime < 500000000L && tx_locktime < 500000000L in
            let both_time = locktime >= 500000000L && tx_locktime >= 500000000L in
            if not (both_blocks || both_time) then
              Error "CLTV type mismatch"
            else if tx_locktime < locktime then
              Error "CLTV not satisfied"
            else begin
              (* Check sequence is not final *)
              let inp = List.nth st.tx.inputs st.input_index in
              if Int32.equal inp.sequence 0xFFFFFFFFl then
                Error "CLTV with final sequence"
              else
                Ok ()
            end
          end
        end
    end

  | OP_CHECKSEQUENCEVERIFY ->
    if st.flags land script_verify_checksequenceverify = 0 then
      Ok ()  (* Treat as NOP if not enabled *)
    else begin
      match stack_top st with
      | Error e -> Error e
      | Ok seq_bytes ->
        if Cstruct.length seq_bytes > 5 then
          Error "CSV argument too long"
        else begin
          let sequence = script_num_of_bytes ~max_bytes:5 seq_bytes in
          if sequence < 0L then
            Error "Negative sequence"
          else begin
            (* If disable flag is set, treat as NOP *)
            if Int64.logand sequence 0x80000000L <> 0L then
              Ok ()
            else begin
              (* Check tx version >= 2 *)
              if st.tx.version < 2l then
                Error "CSV requires tx version >= 2"
              else begin
                let inp = List.nth st.tx.inputs st.input_index in
                let tx_seq = Int64.of_int32 (Int32.logand inp.sequence 0xFFFFFFFFl) in
                (* Check disable flag in tx sequence *)
                if Int64.logand tx_seq 0x80000000L <> 0L then
                  Error "CSV on disabled input"
                else begin
                  (* Compare masked values *)
                  let mask = 0x0000FFFFL in
                  let type_mask = 0x00400000L in
                  let seq_type = Int64.logand sequence type_mask in
                  let tx_type = Int64.logand tx_seq type_mask in
                  if seq_type <> tx_type then
                    Error "CSV type mismatch"
                  else begin
                    let seq_val = Int64.logand sequence mask in
                    let tx_val = Int64.logand tx_seq mask in
                    if tx_val < seq_val then
                      Error "CSV not satisfied"
                    else
                      Ok ()
                  end
                end
              end
            end
          end
        end
    end

  | OP_CHECKSIGADD ->
    (* BIP-342: OP_CHECKSIGADD is only valid in tapscript *)
    if st.sig_version <> SigVersionTapscript then
      Error "OP_CHECKSIGADD is only valid in tapscript"
    else begin
      (* Pop pubkey, n, sig *)
      match stack_pop st with
      | Error e -> Error e
      | Ok pubkey ->
        begin match stack_pop st with
        | Error e -> Error e
        | Ok n_bytes ->
          begin match stack_pop st with
          | Error e -> Error e
          | Ok sig_bytes ->
            if Cstruct.length pubkey = 0 then
              Error "Empty pubkey in tapscript OP_CHECKSIGADD"
            else if Cstruct.length pubkey <> 32 then begin
              (* Unknown pubkey type: treat as success unless discouraged *)
              if st.flags land script_verify_discourage_upgradable_pubkeytype <> 0 then
                Error "Discouraged unknown public key type in tapscript"
              else begin
                let n = script_num_of_bytes n_bytes in
                stack_push st (bytes_of_script_num (Int64.add n 1L))
              end
            end
            else begin
              let n = script_num_of_bytes n_bytes in
              if Cstruct.length sig_bytes = 0 then
                (* Empty signature: push n unchanged, no sigops budget cost *)
                stack_push st (bytes_of_script_num n)
              else begin
                st.sigops_budget <- st.sigops_budget - 50;
                if st.sigops_budget < 0 then
                  Error "Tapscript validation weight budget exceeded"
                else begin
                  let sig_len = Cstruct.length sig_bytes in
                  if sig_len <> 64 && sig_len <> 65 then
                    Error "Invalid tapscript signature length"
                  else begin
                    let hash_type = if sig_len = 65 then
                      Cstruct.get_uint8 sig_bytes 64
                    else 0
                    in
                    if sig_len = 65 && hash_type = 0 then
                      Error "Invalid hash_type 0x00 in 65-byte tapscript sig"
                    else begin
                      let sig_64 = Cstruct.sub sig_bytes 0 64 in
                      let sighash = compute_sighash_taproot st.tx st.input_index st.prevouts hash_type
                        ?annex_hash:st.annex_hash ?tapleaf_hash:st.tapleaf_hash
                        ~codesep_pos:st.codesep_pos () in
                      let valid = Crypto.schnorr_verify ~pubkey_x:pubkey ~msg:sighash ~signature:sig_64 in
                      if valid then
                        stack_push st (bytes_of_script_num (Int64.add n 1L))
                      else
                        Error "OP_CHECKSIGADD Schnorr verification failed"
                    end
                  end
                end
              end
            end
          end
        end
    end

  (* NOP operations *)
  | OP_NOP1 | OP_NOP4 | OP_NOP5 | OP_NOP6 | OP_NOP7
  | OP_NOP8 | OP_NOP9 | OP_NOP10 ->
    if st.flags land script_verify_discourage_upgradable_nops <> 0 then
      Error "Upgradable NOP used"
    else Ok ()

  (* Reserved/Invalid *)
  | OP_RESERVED | OP_VER | OP_RESERVED1 | OP_RESERVED2 ->
    Error "Reserved opcode"

  | OP_VERIF | OP_VERNOTIF ->
    Error "Disabled opcode"

  | OP_INVALID n ->
    Error (Printf.sprintf "Invalid opcode 0x%02x" n)

(* ============================================================================
   Script Evaluation
   ============================================================================ *)

(* Check that all push operations in raw script bytes use minimal encoding.
   BIP-62 rule 3: push operators must use the smallest possible opcode. *)
let check_minimal_push (script : Cstruct.t) : (unit, string) result =
  let len = Cstruct.length script in
  let pc = ref 0 in
  let err = ref None in
  while !pc < len && !err = None do
    let op = Cstruct.get_uint8 script !pc in
    incr pc;
    if op >= 0x01 && op <= 0x4b then begin
      (* Direct push of op bytes *)
      let data_len = op in
      if !pc + data_len <= len then begin
        if data_len = 1 then begin
          let byte = Cstruct.get_uint8 script !pc in
          if byte = 0 then
            err := Some "Non-minimal push: should use OP_0"
          else if byte >= 1 && byte <= 16 then
            err := Some "Non-minimal push: should use OP_1 through OP_16"
          else if byte = 0x81 then
            err := Some "Non-minimal push: should use OP_1NEGATE"
        end;
        pc := !pc + data_len
      end else
        pc := len
    end else if op = 0x4c then begin (* OP_PUSHDATA1 *)
      if !pc < len then begin
        let data_len = Cstruct.get_uint8 script !pc in
        if data_len <= 75 then
          err := Some "Non-minimal push: OP_PUSHDATA1 unnecessary";
        pc := !pc + 1 + data_len
      end else pc := len
    end else if op = 0x4d then begin (* OP_PUSHDATA2 *)
      if !pc + 2 <= len then begin
        let data_len = Cstruct.get_uint8 script !pc
                       lor (Cstruct.get_uint8 script (!pc + 1) lsl 8) in
        if data_len <= 255 then
          err := Some "Non-minimal push: OP_PUSHDATA2 unnecessary";
        pc := !pc + 2 + data_len
      end else pc := len
    end else if op = 0x4e then begin (* OP_PUSHDATA4 *)
      if !pc + 4 <= len then begin
        let data_len = Cstruct.get_uint8 script !pc
                       lor (Cstruct.get_uint8 script (!pc + 1) lsl 8)
                       lor (Cstruct.get_uint8 script (!pc + 2) lsl 16)
                       lor (Cstruct.get_uint8 script (!pc + 3) lsl 24) in
        if data_len <= 65535 then
          err := Some "Non-minimal push: OP_PUSHDATA4 unnecessary";
        pc := !pc + 4 + data_len
      end else pc := len
    end
    (* All other opcodes: no data to skip *)
  done;
  match !err with
  | Some msg -> Error msg
  | None -> Ok ()

(* Execute a script and return success/failure for execution only.
   The stack-top truthiness check is done separately by the caller (verify_script).
   This matches Bitcoin Core's EvalScript behavior. *)
let eval_script (st : eval_state) (script : Cstruct.t) : (unit, string) result =
  (* MINIMALDATA push checks are now done per-opcode during execution,
     only when the opcode is actually executed (not in dead branches).
     See exec_opcode_inner for OP_PUSHDATA handling. *)
  let script_code = script in  (* Used for sighash computation *)
  try
    let ops = parse_script script in
    let rec exec = function
      | [] ->
        if st.if_stack <> [] then
          Error "Unbalanced IF"
        else
          Ok ()
      | op :: rest ->
        st.current_op_idx <- st.current_op_idx + 1;
        match exec_opcode st op script_code with
        | Error e -> Error e
        | Ok () -> exec rest
    in
    exec ops
  with
  | Failure msg -> Error msg
  | _ -> Error "Script execution error"

(* ============================================================================
   Script Verification (Full Transaction Input Verification)
   ============================================================================ *)

(* Check that all witness items are within the maximum element size limit *)
let check_witness_item_sizes ~sig_version:_ (witness : Types.tx_witness) : (unit, string) result =
  if List.exists (fun item -> Cstruct.length item > max_script_element_size) witness.items then
    Error "Witness item exceeds maximum element size"
  else Ok ()

(* Helper: check stack top for final script result *)
let check_stack_top (st : eval_state) : (bool, string) result =
  match st.stack with
  | [] -> Ok false
  | top :: _ -> Ok (is_true top)

(* Verify a transaction input's script *)
let verify_script ~(tx : Types.transaction) ~(input_index : int)
    ~(script_pubkey : Cstruct.t) ~(script_sig : Cstruct.t)
    ~(witness : Types.tx_witness) ~(amount : int64)
    ~(flags : int) ?(prevouts=[]) () : (bool, string) result =

  let run_script st script =
    eval_script st script
  in

  (* SIGPUSHONLY: scriptSig must contain only push operations *)
  let sigpushonly_ok =
    if flags land script_verify_sigpushonly <> 0 && Cstruct.length script_sig > 0 then
      try
        let ops = parse_script script_sig in
        List.for_all is_push_opcode ops
      with _ -> false
    else true
  in
  if not sigpushonly_ok then
    Error "scriptSig contains non-push opcode"
  else

  (* Check for unknown witness programs (v2-v16) -- succeed unconditionally *)
  match get_witness_program script_pubkey with
  | Some (v, _program) when v >= 2 && v <= 16 ->
    if flags land script_verify_witness <> 0 then begin
      (* Native segwit: scriptSig must be empty *)
      if Cstruct.length script_sig > 0 then
        Error "scriptSig must be empty for witness program"
      else if flags land script_verify_discourage_upgradable_witness <> 0 then
        Error "Upgradable witness program used"
      else
        Ok true  (* Unconditional success for unknown witness versions *)
    end else begin
      (* Witness flag not set, fall through to normal execution *)
      let st = create_eval_state ~tx ~input_index ~amount ~flags
                 ~sig_version:SigVersionBase () in
      begin match run_script st script_sig with
      | Error e -> Error e
      | Ok () ->
        begin match run_script st script_pubkey with
        | Error e -> Error e
        | Ok () ->
          if flags land script_verify_cleanstack <> 0 && stack_size st <> 1 then
            Error "Stack not clean after execution"
          else
            check_stack_top st
        end
      end
    end
  | _ ->

  match classify_script script_pubkey with
  | P2PKH_script _ ->
    (* WITNESS_UNEXPECTED: non-witness scripts must not have witness data *)
    if flags land script_verify_witness <> 0 && witness.Types.items <> [] then
      Error "Unexpected witness data for non-witness script"
    else begin
      (* Legacy P2PKH: run scriptSig, then scriptPubKey *)
      let st = create_eval_state ~tx ~input_index ~amount ~flags
                 ~sig_version:SigVersionBase () in
      begin match run_script st script_sig with
      | Error e -> Error e
      | Ok () ->
        (* Copy stack and continue with scriptPubKey *)
        begin match run_script st script_pubkey with
        | Error e -> Error e
        | Ok () ->
          if flags land script_verify_cleanstack <> 0 && stack_size st <> 1 then
            Error "Stack not clean after execution"
          else
            check_stack_top st
        end
      end
    end

  | P2SH_script hash ->
    (* BIP-16 P2SH *)
    if flags land script_verify_p2sh = 0 then
      (* P2SH not enabled, treat as regular script *)
      let st = create_eval_state ~tx ~input_index ~amount ~flags
                 ~sig_version:SigVersionBase () in
      begin match run_script st script_sig with
      | Error e -> Error e
      | Ok () ->
        begin match run_script st script_pubkey with
        | Error e -> Error e
        | Ok () -> check_stack_top st
        end
      end
    else begin
      (* BIP-16: P2SH requires scriptSig to be push-only and exactly one push *)
      let p2sh_pushonly_ok =
        try
          let sig_ops = parse_script script_sig in
          List.for_all is_push_opcode sig_ops && List.length sig_ops = 1
        with _ -> false
      in
      if not p2sh_pushonly_ok then
        Error "P2SH scriptSig must be push-only"
      else begin
      (* Run scriptSig *)
      let st = create_eval_state ~tx ~input_index ~amount ~flags
                 ~sig_version:SigVersionBase () in
      begin match run_script st script_sig with
      | Error e -> Error e
      | Ok () ->
        (* Save stack before running P2SH redeem script check *)
        let stack_copy = st.stack in
        (* Run scriptPubKey (OP_HASH160 <hash> OP_EQUAL) *)
        begin match run_script st script_pubkey with
        | Error e -> Error e
        | Ok () ->
          (* Check that scriptPubKey left true on the stack *)
          begin match st.stack with
          | [] -> Ok false
          | top :: _ when not (is_true top) -> Ok false
          | _ ->
          (* The top of the original stack is the serialized redeem script *)
          begin match stack_copy with
          | [] -> Error "P2SH: empty stack"
          | redeem_script :: _ ->
            (* Verify hash matches *)
            let redeem_hash = Crypto.hash160 redeem_script in
            if not (Cstruct.equal redeem_hash hash) then
              Ok false
            else begin
              (* Check for P2SH-wrapped witness program *)
              match get_witness_program redeem_script with
              | Some (0, program) when Cstruct.length program = 20 ->
                (* P2SH-P2WPKH *)
                if flags land script_verify_witness = 0 then
                  Error "Witness program in non-witness mode"
                else begin
                  match check_witness_item_sizes ~sig_version:SigVersionWitnessV0 witness with
                  | Error e -> Error e
                  | Ok () ->
                  let wit_items = witness.Types.items in
                  if List.length wit_items <> 2 then
                    Error "P2WPKH requires exactly 2 witness items"
                  else begin
                    let wit_sig = List.nth wit_items 0 in
                    let wit_pubkey = List.nth wit_items 1 in
                    (* WITNESS_PUBKEYTYPE: require compressed pubkey *)
                    if flags land script_verify_witness_pubkeytype <> 0 &&
                       Cstruct.length wit_pubkey <> 33 then
                      Error "Witness v0 requires compressed public key"
                    else begin
                      (* Verify pubkey hashes to program *)
                      let pubkey_hash = Crypto.hash160 wit_pubkey in
                      if not (Cstruct.equal pubkey_hash program) then
                        Ok false
                      else begin
                        (* Build implicit P2PKH script and run *)
                        let implicit_script = build_p2pkh_script program in
                        let st2 = create_eval_state ~tx ~input_index ~amount ~flags
                                    ~sig_version:SigVersionWitnessV0 () in
                        st2.stack <- [wit_sig; wit_pubkey];
                        begin match run_script st2 implicit_script with
                        | Error e -> Error e
                        | Ok () ->
                          if flags land script_verify_cleanstack <> 0 && stack_size st2 <> 1 then
                            Error "Stack not clean after execution"
                          else
                            check_stack_top st2
                        end
                      end
                    end
                  end
                end
              | Some (0, program) when Cstruct.length program = 32 ->
                (* P2SH-P2WSH *)
                if flags land script_verify_witness = 0 then
                  Error "Witness program in non-witness mode"
                else begin
                  match check_witness_item_sizes ~sig_version:SigVersionWitnessV0 witness with
                  | Error e -> Error e
                  | Ok () ->
                  let wit_items = witness.Types.items in
                  if List.length wit_items = 0 then
                    Error "Empty witness for P2WSH"
                  else begin
                    (* Last witness item is the witness script *)
                    let witness_script = List.nth wit_items (List.length wit_items - 1) in
                    let script_hash = Crypto.sha256 witness_script in
                    if not (Cstruct.equal script_hash program) then
                      Ok false
                    else begin
                      (* Initialize stack with witness items (reversed per PITFALL) *)
                      let wit_stack = List.rev (List.filteri (fun i _ -> i < List.length wit_items - 1) wit_items) in
                      let st2 = create_eval_state ~tx ~input_index ~amount ~flags
                                  ~sig_version:SigVersionWitnessV0 () in
                      st2.stack <- wit_stack;
                      begin match run_script st2 witness_script with
                      | Error e -> Error e
                      | Ok () ->
                        if flags land script_verify_cleanstack <> 0 && stack_size st2 <> 1 then
                          Error "Stack not clean after execution"
                        else
                          check_stack_top st2
                      end
                    end
                  end
                end
              | _ ->
                (* Regular P2SH: run redeem script with remaining stack *)
                let st2 = create_eval_state ~tx ~input_index ~amount ~flags
                            ~sig_version:SigVersionBase () in
                st2.stack <- List.tl stack_copy;
                begin match run_script st2 redeem_script with
                | Error e -> Error e
                | Ok () ->
                  if flags land script_verify_cleanstack <> 0 && stack_size st2 <> 1 then
                    Error "Stack not clean after execution"
                  else
                    check_stack_top st2
                end
              end
            end
          end
        end
      end
      end
    end

  | P2WPKH_script program ->
    (* Native SegWit v0 P2WPKH *)
    if flags land script_verify_witness = 0 then
      (* Witness not enabled, scriptSig must be empty, fail *)
      if Cstruct.length script_sig <> 0 then
        Error "scriptSig must be empty for witness"
      else
        Ok true  (* Pre-witness rules would succeed *)
    else begin
      if Cstruct.length script_sig <> 0 then
        Error "scriptSig must be empty for native witness"
      else begin
        match check_witness_item_sizes ~sig_version:SigVersionWitnessV0 witness with
        | Error e -> Error e
        | Ok () ->
        let wit_items = witness.Types.items in
        if List.length wit_items <> 2 then
          Error "P2WPKH requires exactly 2 witness items"
        else begin
          let wit_sig = List.nth wit_items 0 in
          let wit_pubkey = List.nth wit_items 1 in
          (* WITNESS_PUBKEYTYPE: require compressed pubkey *)
          if flags land script_verify_witness_pubkeytype <> 0 &&
             Cstruct.length wit_pubkey <> 33 then
            Error "Witness v0 requires compressed public key"
          else begin
            (* Verify pubkey hashes to program *)
            let pubkey_hash = Crypto.hash160 wit_pubkey in
            if not (Cstruct.equal pubkey_hash program) then
              Ok false
            else begin
              (* Build implicit P2PKH script *)
              let implicit_script = build_p2pkh_script program in
              let st = create_eval_state ~tx ~input_index ~amount ~flags
                         ~sig_version:SigVersionWitnessV0 () in
              st.stack <- [wit_sig; wit_pubkey];
              begin match run_script st implicit_script with
              | Error e -> Error e
              | Ok () ->
                if flags land script_verify_cleanstack <> 0 && stack_size st <> 1 then
                  Error "Stack not clean after execution"
                else
                  check_stack_top st
              end
            end
          end
        end
      end
    end

  | P2WSH_script program ->
    (* Native SegWit v0 P2WSH *)
    if flags land script_verify_witness = 0 then
      if Cstruct.length script_sig <> 0 then
        Error "scriptSig must be empty for witness"
      else
        Ok true
    else begin
      if Cstruct.length script_sig <> 0 then
        Error "scriptSig must be empty for native witness"
      else begin
        match check_witness_item_sizes ~sig_version:SigVersionWitnessV0 witness with
        | Error e -> Error e
        | Ok () ->
        let wit_items = witness.Types.items in
        if List.length wit_items = 0 then
          Error "Empty witness for P2WSH"
        else begin
          (* Last witness item is the witness script *)
          let witness_script = List.nth wit_items (List.length wit_items - 1) in
          let script_hash = Crypto.sha256 witness_script in
          if not (Cstruct.equal script_hash program) then
            Ok false
          else begin
            (* Initialize stack with witness items (excluding script, reversed) *)
            let wit_stack = List.rev (List.filteri (fun i _ -> i < List.length wit_items - 1) wit_items) in
            let st = create_eval_state ~tx ~input_index ~amount ~flags
                       ~sig_version:SigVersionWitnessV0 () in
            st.stack <- wit_stack;
            begin match run_script st witness_script with
            | Error e -> Error e
            | Ok () ->
              if flags land script_verify_cleanstack <> 0 && stack_size st <> 1 then
                Error "Stack not clean after execution"
              else
                check_stack_top st
            end
          end
        end
      end
    end

  | P2TR_script program ->
    (* Taproot (BIP-341/342) full verification *)
    if flags land script_verify_taproot = 0 then
      if Cstruct.length script_sig <> 0 then
        Error "scriptSig must be empty for witness"
      else
        Ok true
    else begin
      if Cstruct.length script_sig <> 0 then
        Error "scriptSig must be empty for taproot"
      else begin
        let wit_items = witness.Types.items in
        match wit_items with
        | [] -> Error "Empty witness for taproot"
        | _ ->
          (* Check for annex: last item starts with 0x50, and there are >= 2 items *)
          let n = List.length wit_items in
          let has_annex =
            n >= 2 &&
            let last = List.nth wit_items (n - 1) in
            Cstruct.length last > 0 && Cstruct.get_uint8 last 0 = 0x50
          in
          let annex_hash =
            if has_annex then
              let annex = List.nth wit_items (n - 1) in
              (* SHA256(compact_size(annex_len) || annex) *)
              let w = Serialize.writer_create () in
              Serialize.write_compact_size w (Cstruct.length annex);
              Serialize.write_bytes w annex;
              Some (Crypto.sha256 (Serialize.writer_to_cstruct w))
            else None
          in
          let effective_items = if has_annex then
            List.filteri (fun i _ -> i < n - 1) wit_items
          else wit_items in
          let eff_n = List.length effective_items in

          if eff_n = 1 then begin
            (* KEY PATH SPEND *)
            let sig_bytes = List.hd effective_items in
            let sig_len = Cstruct.length sig_bytes in
            if sig_len <> 64 && sig_len <> 65 then
              Error "Invalid taproot key path signature length"
            else begin
              let hash_type = if sig_len = 65 then
                Cstruct.get_uint8 sig_bytes 64
              else 0 (* SIGHASH_DEFAULT *)
              in
              if sig_len = 65 && hash_type = 0 then
                Error "Invalid taproot hash type 0x00 in 65-byte signature"
              else begin
                let sig_64 = Cstruct.sub sig_bytes 0 64 in
                let sighash = compute_sighash_taproot tx input_index prevouts hash_type
                  ?annex_hash () in
                if Crypto.schnorr_verify ~pubkey_x:program ~msg:sighash ~signature:sig_64 then
                  Ok true
                else
                  Error "Taproot key path signature verification failed"
              end
            end
          end else if eff_n >= 2 then begin
            (* SCRIPT PATH SPEND *)
            let control = List.nth effective_items (eff_n - 1) in
            let tap_script = List.nth effective_items (eff_n - 2) in
            let control_len = Cstruct.length control in

            (* Validate control block size: 33 + 32*k, where 0 <= k <= 128 *)
            if control_len < 33 || (control_len - 33) mod 32 <> 0 then
              Error "Invalid control block size"
            else begin
              let path_len = (control_len - 33) / 32 in
              if path_len > 128 then
                Error "Control block path too long"
              else begin
                (* Extract leaf version and parity from first byte *)
                let leaf_version = Cstruct.get_uint8 control 0 land 0xFE in
                let output_key_parity = Cstruct.get_uint8 control 0 land 0x01 in

                (* Extract internal key (32 bytes starting at offset 1) *)
                let internal_key = Cstruct.sub control 1 32 in

                (* Compute tapleaf hash: tagged_hash("TapLeaf", leaf_version || compact_size(script_len) || script) *)
                let tapleaf_w = Serialize.writer_create () in
                Serialize.write_uint8 tapleaf_w leaf_version;
                Serialize.write_compact_size tapleaf_w (Cstruct.length tap_script);
                Serialize.write_bytes tapleaf_w tap_script;
                let tapleaf_hash = Crypto.tagged_hash "TapLeaf" (Serialize.writer_to_cstruct tapleaf_w) in

                (* Walk Merkle path to compute root *)
                let rec walk_path hash idx =
                  if idx >= path_len then hash
                  else begin
                    let sibling = Cstruct.sub control (33 + idx * 32) 32 in
                    let branch_hash =
                      if Cstruct.compare hash sibling <= 0 then
                        Crypto.tagged_hash "TapBranch" (Cstruct.concat [hash; sibling])
                      else
                        Crypto.tagged_hash "TapBranch" (Cstruct.concat [sibling; hash])
                    in
                    walk_path branch_hash (idx + 1)
                  end
                in
                let merkle_root = walk_path tapleaf_hash 0 in

                (* Compute tweak: tagged_hash("TapTweak", internal_key || merkle_root) *)
                let tweak = Crypto.tagged_hash "TapTweak" (Cstruct.concat [internal_key; merkle_root]) in

                (* Verify: tweaked internal key == output key *)
                if not (Crypto.xonly_pubkey_tweak_add_check
                          ~internal_pk:internal_key ~tweaked_pk:program
                          ~tweaked_parity:output_key_parity ~tweak) then
                  Error "Taproot commitment verification failed"
                else begin
                  (* LEAF VERSION GATING: only execute leaf version 0xC0 *)
                  if leaf_version <> 0xC0 then begin
                    if flags land script_verify_discourage_upgradable_taproot_version <> 0 then
                      Error "Discouraged unknown taproot leaf version"
                    else
                      Ok true  (* Unknown leaf version: succeed unconditionally *)
                  end
                  else begin
                    (* OP_SUCCESSx pre-scan *)
                    let has_op_success_flag = ref false in
                    let script_bytes = tap_script in
                    let pc = ref 0 in
                    let slen = Cstruct.length script_bytes in
                    while !pc < slen do
                      let op = Cstruct.get_uint8 script_bytes !pc in
                      incr pc;
                      (* Skip push data *)
                      if op >= 0x01 && op <= 0x4b then
                        pc := !pc + op
                      else if op = 0x4c && !pc < slen then begin
                        let dlen = Cstruct.get_uint8 script_bytes !pc in
                        pc := !pc + 1 + dlen
                      end else if op = 0x4d && !pc + 2 <= slen then begin
                        let dlen = Cstruct.get_uint8 script_bytes !pc lor (Cstruct.get_uint8 script_bytes (!pc+1) lsl 8) in
                        pc := !pc + 2 + dlen
                      end else if op = 0x4e && !pc + 4 <= slen then begin
                        let dlen = Cstruct.get_uint8 script_bytes !pc lor
                                   (Cstruct.get_uint8 script_bytes (!pc+1) lsl 8) lor
                                   (Cstruct.get_uint8 script_bytes (!pc+2) lsl 16) lor
                                   (Cstruct.get_uint8 script_bytes (!pc+3) lsl 24) in
                        pc := !pc + 4 + dlen
                      end else begin
                        (* Check for OP_SUCCESSx opcodes *)
                        if is_op_success op then
                          has_op_success_flag := true
                      end
                    done;

                    if !has_op_success_flag then begin
                      if flags land script_verify_discourage_op_success <> 0 then
                        Error "Discouraged OP_SUCCESS opcode in tapscript"
                      else
                        Ok true  (* OP_SUCCESS makes script unconditionally succeed *)
                    end
                    else begin
                      (* Compute serialized witness size for sigops budget *)
                      let compact_size_len n =
                        if n < 253 then 1
                        else if n < 0x10000 then 3
                        else if n < 0x100000000 then 5
                        else 9
                      in
                      let witness_size = compact_size_len (List.length witness.Types.items) +
                        List.fold_left (fun acc item ->
                          acc + compact_size_len (Cstruct.length item) + Cstruct.length item
                        ) 0 witness.Types.items in
                      let sigops_budget = 50 + witness_size in

                      (* Execute tapscript *)
                      let wit_stack = List.rev (List.filteri (fun i _ -> i < eff_n - 2) effective_items) in
                      (* Task 7: Tapscript initial stack size check *)
                      if List.length wit_stack > max_stack_size then
                        Error "Tapscript initial stack too large"
                      else begin
                        (* Task 6: Witness item size check for tapscript *)
                        match check_witness_item_sizes ~sig_version:SigVersionTapscript witness with
                        | Error e -> Error e
                        | Ok () ->
                          let st = create_eval_state ~tx ~input_index ~amount ~flags
                                     ~sig_version:SigVersionTapscript
                                     ~prevouts ~annex_hash:(annex_hash)
                                     ~tapleaf_hash:(Some tapleaf_hash) ~sigops_budget () in
                          st.stack <- wit_stack;
                          begin match run_script st tap_script with
                          | Error e -> Error e
                          | Ok () -> check_stack_top st
                          end
                      end
                    end
                  end
                end
              end
            end
          end else
            Error "Invalid taproot witness"
      end
    end

  | OP_RETURN_data _ ->
    (* OP_RETURN scripts are unspendable *)
    Ok false

  | Nonstandard ->
    (* WITNESS_UNEXPECTED: non-witness scripts must not have witness data *)
    if flags land script_verify_witness <> 0 && witness.Types.items <> [] then
      Error "Unexpected witness data for non-witness script"
    else begin
      (* Generic script execution *)
      let st = create_eval_state ~tx ~input_index ~amount ~flags
                 ~sig_version:SigVersionBase () in
      begin match run_script st script_sig with
      | Error e -> Error e
      | Ok () ->
        begin match run_script st script_pubkey with
        | Error e -> Error e
        | Ok () ->
          if flags land script_verify_cleanstack <> 0 && stack_size st <> 1 then
            Error "Stack not clean after execution"
          else
            check_stack_top st
        end
      end
    end
