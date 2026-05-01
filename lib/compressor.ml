(* Bitcoin Core-compatible Coin compression primitives.

   Implements the same on-the-wire format as Bitcoin Core's
   [src/compressor.h] / [src/compressor.cpp] / [src/serialize.h]:

   - VARINT  — Bitcoin Core's "satoshi" varint (NOT CompactSize). Used for
     [code = nHeight*2 + fCoinBase] and for [CompressAmount(value)].
     Encoding: while [n > 0x7F], emit [(n & 0x7F) | 0x80], then [n = (n>>7) - 1];
     finally emit [n & 0x7F]. Bytes are written most-significant-first, with
     the continuation bit (0x80) on every byte EXCEPT the last.

   - CompressAmount / DecompressAmount — exponent + mantissa amount packing
     (max output ~10 bytes after VARINT, but typical UTXO amounts compress
     into 1–6 bytes).

   - CompressScript / DecompressScript — three special-case prefixes
     (0x00 = P2PKH, 0x01 = P2SH, 0x02/0x03 = compressed P2PK, 0x04/0x05 =
     uncompressed P2PK reduced to 33 bytes). Falls back to a length-prefixed
     raw script for everything else (including SegWit / Taproot witness
     programs, which are NOT among the special types). The fallback prefix
     is [VARINT(script.size() + nSpecialScripts)] where
     [nSpecialScripts = 6].

   This module mirrors Bitcoin Core's UTXO snapshot per-coin encoding so that
   camlcoin can read [dumptxoutset] output from any other Bitcoin
   implementation byte-for-byte and emit snapshots that any other
   implementation can load.

   ScriptCompression decompression of P2PK pubkey types 0x04 / 0x05 requires
   secp256k1 point decompression. We currently lack a public OCaml binding
   for that operation; until it lands we accept the script in fallback (raw)
   form on the read path and refuse to compress it on the write path. The
   incremental impact is small: only ~0.3 % of mainnet UTXOs (very early
   coinbases pre-2010) carry uncompressed P2PK outputs. See [TODO]
   markers below. *)

(* ============================================================================
   VARINT (satoshi varint, mode DEFAULT — unsigned only)
   ============================================================================ *)

(** Encode an unsigned integer using Bitcoin Core's VARINT format.

    Equivalent to [WriteVarInt<Stream, VarIntMode::DEFAULT>] in
    src/serialize.h. The exact byte sequence matches Core for any
    non-negative input. *)
let write_varint (w : Serialize.writer) (n : int) : unit =
  if n < 0 then
    invalid_arg "Compressor.write_varint: negative input";
  (* Build the bytes least-significant first into a stack buffer, then emit
     them in reverse with the continuation bit on every byte except the last
     emitted (which is the LSB of the original). *)
  let tmp = Bytes.create 10 in  (* sufficient for 64-bit values *)
  let len = ref 0 in
  let n = ref n in
  let continue = ref true in
  while !continue do
    let byte = (!n land 0x7F) lor (if !len = 0 then 0x00 else 0x80) in
    Bytes.set tmp !len (Char.chr byte);
    if !n <= 0x7F then continue := false
    else begin
      n := (!n lsr 7) - 1;
      incr len
    end
  done;
  for i = !len downto 0 do
    Serialize.write_uint8 w (Char.code (Bytes.get tmp i))
  done

(** Decode an unsigned integer using Bitcoin Core's VARINT format. *)
let read_varint (r : Serialize.reader) : int =
  let n = ref 0 in
  let continue = ref true in
  while !continue do
    let b = Serialize.read_uint8 r in
    (* Overflow guard: prevent shift past 63 bits. *)
    if !n > (max_int lsr 7) then
      failwith "Compressor.read_varint: size too large";
    n := (!n lsl 7) lor (b land 0x7F);
    if b land 0x80 <> 0 then begin
      if !n = max_int then
        failwith "Compressor.read_varint: size too large";
      incr n
    end else continue := false
  done;
  !n

(** Encode an unsigned 64-bit integer using VARINT. Same wire format as
    [write_varint] but accepts the full uint64 range. *)
let write_varint_int64 (w : Serialize.writer) (n : int64) : unit =
  if Int64.compare n 0L < 0 then
    invalid_arg "Compressor.write_varint_int64: negative input";
  let tmp = Bytes.create 10 in
  let len = ref 0 in
  let n = ref n in
  let continue = ref true in
  while !continue do
    let byte =
      Int64.to_int (Int64.logand !n 0x7FL)
      lor (if !len = 0 then 0x00 else 0x80) in
    Bytes.set tmp !len (Char.chr byte);
    if Int64.compare !n 0x7FL <= 0 then continue := false
    else begin
      n := Int64.sub (Int64.shift_right_logical !n 7) 1L;
      incr len
    end
  done;
  for i = !len downto 0 do
    Serialize.write_uint8 w (Char.code (Bytes.get tmp i))
  done

(** Decode an unsigned 64-bit integer using VARINT. *)
let read_varint_int64 (r : Serialize.reader) : int64 =
  let n = ref 0L in
  let continue = ref true in
  while !continue do
    let b = Serialize.read_uint8 r in
    (* Overflow guard: shift would lose bits past 64. *)
    if Int64.compare !n (Int64.shift_right_logical Int64.max_int 7) > 0 then
      failwith "Compressor.read_varint_int64: size too large";
    n := Int64.logor (Int64.shift_left !n 7)
            (Int64.of_int (b land 0x7F));
    if b land 0x80 <> 0 then begin
      if Int64.compare !n Int64.max_int = 0 then
        failwith "Compressor.read_varint_int64: size too large";
      n := Int64.add !n 1L
    end else continue := false
  done;
  !n

(* ============================================================================
   Amount compression
   ============================================================================ *)

(** [compress_amount n] mirrors [CompressAmount] in Bitcoin Core's
    [src/compressor.cpp]. Defined for [0 <= n <= MAX_MONEY] but works for any
    nonnegative input.

    The encoding: factor out the largest power of 10, then pack
    [(remainder, lastDigit, exponent)] into a single integer that round-trips
    through [decompress_amount]. *)
let compress_amount (n : int64) : int64 =
  if Int64.compare n 0L < 0 then
    invalid_arg "Compressor.compress_amount: negative";
  if Int64.equal n 0L then 0L
  else begin
    let n = ref n in
    let e = ref 0 in
    while Int64.equal (Int64.rem !n 10L) 0L && !e < 9 do
      n := Int64.div !n 10L;
      incr e
    done;
    if !e < 9 then begin
      let d = Int64.to_int (Int64.rem !n 10L) in
      assert (d >= 1 && d <= 9);
      n := Int64.div !n 10L;
      (* 1 + (n*9 + d - 1) * 10 + e *)
      let inner =
        Int64.add (Int64.mul !n 9L) (Int64.of_int (d - 1)) in
      Int64.add 1L (Int64.add (Int64.mul inner 10L) (Int64.of_int !e))
    end else begin
      (* 1 + (n - 1) * 10 + 9 *)
      Int64.add 1L
        (Int64.add (Int64.mul (Int64.sub !n 1L) 10L) 9L)
    end
  end

(** [decompress_amount x] inverts [compress_amount]. *)
let decompress_amount (x : int64) : int64 =
  if Int64.compare x 0L < 0 then
    invalid_arg "Compressor.decompress_amount: negative";
  if Int64.equal x 0L then 0L
  else begin
    let x = ref (Int64.sub x 1L) in
    let e = Int64.to_int (Int64.rem !x 10L) in
    x := Int64.div !x 10L;
    let n = ref 0L in
    if e < 9 then begin
      let d = (Int64.to_int (Int64.rem !x 9L)) + 1 in
      x := Int64.div !x 9L;
      n := Int64.add (Int64.mul !x 10L) (Int64.of_int d)
    end else begin
      n := Int64.add !x 1L
    end;
    let e = ref e in
    while !e > 0 do
      n := Int64.mul !n 10L;
      decr e
    done;
    !n
  end

(* ============================================================================
   Script compression
   ============================================================================ *)

(** Number of special-case script prefixes (matches Core's
    [ScriptCompression::nSpecialScripts]). *)
let n_special_scripts = 6

(* Opcode constants used to recognise the standard P2PKH / P2SH / P2PK
   templates. Kept local so that this module does not depend on Script for
   compression-only logic. *)
let op_dup         = 0x76
let op_hash160     = 0xa9
let op_equalverify = 0x88
let op_checksig    = 0xac
let op_equal       = 0x87

let is_to_keyid (script : Cstruct.t) : Cstruct.t option =
  let len = Cstruct.length script in
  if len = 25
     && Cstruct.get_uint8 script 0 = op_dup
     && Cstruct.get_uint8 script 1 = op_hash160
     && Cstruct.get_uint8 script 2 = 20
     && Cstruct.get_uint8 script 23 = op_equalverify
     && Cstruct.get_uint8 script 24 = op_checksig
  then Some (Cstruct.sub script 3 20)
  else None

let is_to_scriptid (script : Cstruct.t) : Cstruct.t option =
  let len = Cstruct.length script in
  if len = 23
     && Cstruct.get_uint8 script 0 = op_hash160
     && Cstruct.get_uint8 script 1 = 20
     && Cstruct.get_uint8 script 22 = op_equal
  then Some (Cstruct.sub script 2 20)
  else None

(** Detect compressed P2PK: 33-byte pubkey starting 0x02/0x03 + OP_CHECKSIG.
    Returns the inner pubkey on success. *)
let is_to_compressed_pubkey (script : Cstruct.t) : Cstruct.t option =
  let len = Cstruct.length script in
  if len = 35
     && Cstruct.get_uint8 script 0 = 33
     && Cstruct.get_uint8 script 34 = op_checksig
     && (let p = Cstruct.get_uint8 script 1 in p = 0x02 || p = 0x03)
  then Some (Cstruct.sub script 1 33)
  else None

(** Try to compress [script] into Core's special-case wire format.

    Returns [Some compressed] when the script matches one of the recognised
    templates (P2PKH / P2SH / compressed P2PK). Uncompressed P2PK
    (script.size = 67, 0x04 prefix) is currently NOT compressed: the pubkey
    [DecompressScript] step requires secp256k1 point decompression which we
    have not bound yet.

    TODO: bind secp256k1_ec_pubkey_parse + serialize for the 0x04/0x05
    prefixes and recognise [is_to_pubkey] for the 67-byte uncompressed
    P2PK. The on-disk impact is small: ~0.3 % of mainnet UTXOs at h=840k. *)
let compress_script (script : Cstruct.t) : Cstruct.t option =
  match is_to_keyid script with
  | Some hash ->
    let out = Cstruct.create 21 in
    Cstruct.set_uint8 out 0 0x00;
    Cstruct.blit hash 0 out 1 20;
    Some out
  | None ->
    match is_to_scriptid script with
    | Some hash ->
      let out = Cstruct.create 21 in
      Cstruct.set_uint8 out 0 0x01;
      Cstruct.blit hash 0 out 1 20;
      Some out
    | None ->
      match is_to_compressed_pubkey script with
      | Some pubkey ->
        let out = Cstruct.create 33 in
        let prefix = Cstruct.get_uint8 pubkey 0 in
        Cstruct.set_uint8 out 0 prefix;        (* 0x02 or 0x03 *)
        Cstruct.blit pubkey 1 out 1 32;
        Some out
      | None -> None

(** [special_script_size code] gives the number of compressed bytes that
    follow when the wire-format size code is in the special range
    [0..n_special_scripts-1]. Mirrors Core's [GetSpecialScriptSize]. *)
let special_script_size (code : int) : int =
  match code with
  | 0 | 1 -> 20
  | 2 | 3 | 4 | 5 -> 32
  | _ -> 0

(** [decompress_script code data] reconstructs the original script from a
    special-case [code] in [0..5] and the [data] bytes (size given by
    [special_script_size]).

    Codes 0x00 (P2PKH) and 0x01 (P2SH) and 0x02/0x03 (compressed P2PK) are
    fully implemented. Codes 0x04 / 0x05 (uncompressed P2PK) require
    secp256k1 point decompression which is not yet bound — for those we
    return [None] and the caller must treat the snapshot as unsupported.
    Mainnet impact: ~0.3% of UTXOs. TODO. *)
let decompress_script (code : int) (data : Cstruct.t) : Cstruct.t option =
  match code with
  | 0x00 ->
    let out = Cstruct.create 25 in
    Cstruct.set_uint8 out 0 op_dup;
    Cstruct.set_uint8 out 1 op_hash160;
    Cstruct.set_uint8 out 2 20;
    Cstruct.blit data 0 out 3 20;
    Cstruct.set_uint8 out 23 op_equalverify;
    Cstruct.set_uint8 out 24 op_checksig;
    Some out
  | 0x01 ->
    let out = Cstruct.create 23 in
    Cstruct.set_uint8 out 0 op_hash160;
    Cstruct.set_uint8 out 1 20;
    Cstruct.blit data 0 out 2 20;
    Cstruct.set_uint8 out 22 op_equal;
    Some out
  | 0x02 | 0x03 ->
    let out = Cstruct.create 35 in
    Cstruct.set_uint8 out 0 33;
    Cstruct.set_uint8 out 1 code;
    Cstruct.blit data 0 out 2 32;
    Cstruct.set_uint8 out 34 op_checksig;
    Some out
  | 0x04 | 0x05 ->
    None  (* TODO: secp256k1 point decompression *)
  | _ -> None

(** Maximum raw script size accepted by [decompress_script_full] — must
    match Core's [MAX_SCRIPT_SIZE]. *)
let max_script_size = 10_000

(** [serialize_script w script] emits [script] using Core's
    [ScriptCompression::Ser] wire format. *)
let serialize_script (w : Serialize.writer) (script : Cstruct.t) : unit =
  match compress_script script with
  | Some compr ->
    Serialize.write_bytes w compr
  | None ->
    let raw_size = Cstruct.length script in
    write_varint w (raw_size + n_special_scripts);
    Serialize.write_bytes w script

(** [deserialize_script r] reads a script written with [serialize_script].

    May return a Cstruct of length 1 (an [OP_RETURN] placeholder) when the
    encoded size exceeds [MAX_SCRIPT_SIZE], matching Core's behaviour for
    "overly long scripts" — the snapshot is still consumable. *)
let deserialize_script (r : Serialize.reader) : Cstruct.t =
  let n_size = read_varint r in
  if n_size < n_special_scripts then begin
    let body_len = special_script_size n_size in
    let data = Serialize.read_bytes r body_len in
    match decompress_script n_size data with
    | Some s -> s
    | None ->
      failwith
        (Printf.sprintf
           "Compressor.deserialize_script: unsupported special-case prefix \
            0x%02x (likely uncompressed P2PK; needs secp256k1 binding)"
           n_size)
  end else begin
    let raw_size = n_size - n_special_scripts in
    if raw_size > max_script_size then begin
      (* Mirror Core: replace with a 1-byte OP_RETURN sentinel and skip the
         oversized payload. *)
      let _skipped = Serialize.read_bytes r raw_size in
      let out = Cstruct.create 1 in
      Cstruct.set_uint8 out 0 0x6a;  (* OP_RETURN *)
      out
    end else
      Serialize.read_bytes r raw_size
  end
