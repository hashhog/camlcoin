(* MuHash3072 — multiplicative-set hash for Bitcoin's UTXO commitments.

   Reference: bitcoin-core/src/crypto/muhash.{h,cpp} (Num3072, MuHash3072).

   The accumulator is a fraction num/den of 3072-bit numbers modulo
   p = 2^3072 - 1103717 (the largest 3072-bit safe prime). Each insert
   multiplies into the numerator, each remove multiplies into the
   denominator, and the final hash is SHA256 of the 384-LE-byte encoding
   of (num * den^-1) mod p.

   We back the big-integer arithmetic with Zarith (GMP), which exposes
   [Z.powm], [Z.invert], [Z.to_bits], [Z.of_bits] natively. This keeps
   [lib/muhash.ml] short and avoids re-implementing safegcd in OCaml. *)

(* ============================================================================
   Num3072 (raw 3072-bit modular accumulator)
   ============================================================================ *)

(** Byte size of a serialized Num3072. *)
let byte_size = 384

(** The MuHash3072 modulus: [2^3072 - 1103717]. *)
let modulus =
  let p = Z.shift_left Z.one 3072 in
  Z.sub p (Z.of_int 1103717)

(** [num3072_of_bytes b] reads 384 LE-encoded bytes as a Num3072 value.
    Mirrors [Num3072::Num3072(const unsigned char (&)[BYTE_SIZE])] in Core,
    which loads each [LIMB_SIZE]-bit limb in little-endian order. The
    resulting value is taken modulo the prime, matching Core's behaviour
    where the multiplication routine reduces overflowed inputs. *)
let num3072_of_bytes (b : string) : Z.t =
  if String.length b <> byte_size then
    invalid_arg
      (Printf.sprintf "Muhash.num3072_of_bytes: expected %d bytes, got %d"
         byte_size (String.length b));
  Z.rem (Z.of_bits b) modulus

(** [num3072_to_bytes z] serializes [z] as 384 little-endian bytes.
    Inverse of [num3072_of_bytes] for any [z] in [0, modulus). The output
    is exactly [byte_size] bytes; [Z.to_bits] returns a left-truncated
    string when the high limbs are zero, so we right-pad. *)
let num3072_to_bytes (z : Z.t) : string =
  let raw = Z.to_bits z in
  let len = String.length raw in
  if len = byte_size then raw
  else if len < byte_size then
    raw ^ String.make (byte_size - len) '\x00'
  else
    (* Caller-side bug: number does not fit in 3072 bits. *)
    invalid_arg
      (Printf.sprintf "Muhash.num3072_to_bytes: value exceeds 3072 bits (got %d)"
         len)

(** [num3072_one] is the multiplicative identity. *)
let num3072_one : Z.t = Z.one

(** Modular multiplication: [num3072_mul a b] = (a * b) mod p. *)
let num3072_mul (a : Z.t) (b : Z.t) : Z.t =
  Z.rem (Z.mul a b) modulus

(** Modular inverse: [num3072_inv a] = a^{-1} mod p, defined for a != 0
    mod p. Raises [Division_by_zero] otherwise. *)
let num3072_inv (a : Z.t) : Z.t =
  Z.invert a modulus

(** Modular division: [num3072_div a b] = (a * b^{-1}) mod p. *)
let num3072_div (a : Z.t) (b : Z.t) : Z.t =
  num3072_mul a (num3072_inv b)

(* ============================================================================
   ChaCha20-based byte expander
   ============================================================================

   Bitcoin Core's [MuHash3072::ToNum3072(span)] is:

       uint256 h = SHA256(in);
       byte tmp[384] = ChaCha20Aligned(h).Keystream(384);
       return Num3072{tmp};

   The ChaCha20 constructor sets nonce + counter to 0, so the keystream is
   deterministic in [h]. mirage-crypto's [Chacha20.crypt] supports the
   IETF mode (32-byte key, 12-byte nonce, 32-bit counter) which matches
   Core's [ChaCha20Aligned] layout exactly. XORing zeros against the
   keystream returns the keystream itself.
*)

let zero_nonce_12 = String.make 12 '\x00'
let zero_data_384 = String.make byte_size '\x00'

(** [coin_bytes_to_num3072 buf] hashes [buf] with SHA256, expands the
    32-byte digest to 384 ChaCha20 keystream bytes, and decodes those
    bytes as a Num3072 value (reduced mod p). *)
let coin_bytes_to_num3072 (buf : string) : Z.t =
  let key =
    Mirage_crypto.Chacha20.of_secret
      (Cstruct.to_string (Crypto.sha256 (Cstruct.of_string buf)))
  in
  let stream =
    Mirage_crypto.Chacha20.crypt ~key ~nonce:zero_nonce_12 ~ctr:0L
      zero_data_384
  in
  num3072_of_bytes stream

(* ============================================================================
   MuHash3072 accumulator
   ============================================================================ *)

(** Mutable MuHash3072 accumulator. The fields [num] and [den] are kept
    reduced modulo the prime. *)
type t = {
  mutable num : Z.t;
  mutable den : Z.t;
}

(** [create ()] returns the empty MuHash, equivalent to [MuHash3072{}]. *)
let create () : t = { num = num3072_one; den = num3072_one }

(** [singleton buf] returns the MuHash of the singleton set [{buf}],
    equivalent to [MuHash3072(span)] in Core. *)
let singleton (buf : string) : t =
  { num = coin_bytes_to_num3072 buf; den = num3072_one }

(** [add t buf] inserts [buf] into the accumulated set
    (multiplies the numerator by [ToNum3072(buf)]). *)
let add (t : t) (buf : string) : unit =
  t.num <- num3072_mul t.num (coin_bytes_to_num3072 buf)

(** [remove t buf] removes [buf] from the accumulated set
    (multiplies the denominator by [ToNum3072(buf)]). *)
let remove (t : t) (buf : string) : unit =
  t.den <- num3072_mul t.den (coin_bytes_to_num3072 buf)

(** [mul_into dst src] folds [src] into [dst] (set union):
    [dst.num *= src.num], [dst.den *= src.den]. *)
let mul_into (dst : t) (src : t) : unit =
  dst.num <- num3072_mul dst.num src.num;
  dst.den <- num3072_mul dst.den src.den

(** [div_into dst src] divides [dst] by [src] (set difference):
    [dst.num *= src.den], [dst.den *= src.num]. *)
let div_into (dst : t) (src : t) : unit =
  dst.num <- num3072_mul dst.num src.den;
  dst.den <- num3072_mul dst.den src.num

(** Clone the accumulator so the caller can finalize without disturbing
    the original. *)
let copy (t : t) : t = { num = t.num; den = t.den }

(** [finalize t] returns the 32-byte SHA256 of the canonical
    little-endian byte serialization of [num/den mod p]. As in Core, the
    fraction is collapsed (denominator reset to 1) so subsequent
    insert/remove operations remain valid. *)
let finalize (t : t) : bytes =
  let combined = num3072_div t.num t.den in
  t.num <- combined;
  t.den <- num3072_one;
  let bytes_384 = num3072_to_bytes combined in
  let digest = Crypto.sha256 (Cstruct.of_string bytes_384) in
  Bytes.of_string (Cstruct.to_string digest)

(** [finalize_copy t] is [finalize] but on a temporary copy, so [t] is
    untouched. Useful when the caller wants to keep accumulating. *)
let finalize_copy (t : t) : bytes =
  finalize (copy t)

(* ============================================================================
   Serialization (Core-compatible)
   ============================================================================

   Core serializes a MuHash3072 as 48 LE64 numerator limbs (384 bytes)
   followed by 48 LE64 denominator limbs (384 bytes), total 768 bytes.
   That's exactly what [num3072_to_bytes] produces per side. *)

(** [serialize t] returns the 768-byte wire form: numerator limbs then
    denominator limbs, each in canonical LE byte order. *)
let serialize (t : t) : bytes =
  let n = num3072_to_bytes t.num in
  let d = num3072_to_bytes t.den in
  Bytes.of_string (n ^ d)

(** [deserialize buf] reads the 768-byte wire form. The caller is
    responsible for handling overflow (raw limbs > modulus): we reduce
    modulo the prime, matching Core's behaviour where overflowed inputs
    are reduced lazily during the next [Multiply]. *)
let deserialize (buf : bytes) : t =
  if Bytes.length buf <> 2 * byte_size then
    invalid_arg
      (Printf.sprintf "Muhash.deserialize: expected %d bytes, got %d"
         (2 * byte_size) (Bytes.length buf));
  let n = Bytes.sub_string buf 0 byte_size in
  let d = Bytes.sub_string buf byte_size byte_size in
  { num = num3072_of_bytes n; den = num3072_of_bytes d }

(* ============================================================================
   Coin serialization (TxOutSer) — used by ApplyCoinHash callers
   ============================================================================

   Bitcoin Core's [kernel/coinstats.cpp] defines the per-coin preimage
   used by both HASH_SERIALIZED and MUHASH:

       outpoint                  // 32-byte txid + 4-byte LE vout
       uint32_t (height << 1 | fCoinBase)
       CTxOut                    // int64 value + scriptPubKey (varint + bytes)

   The same buffer is fed to [MuHash3072::Insert] and [::Remove], which
   makes this the canonical "coin bytes" the [add]/[remove] functions
   above expect. *)
let serialize_txout (outpoint : Types.outpoint) ~(value : int64)
    ~(script_pubkey : Cstruct.t) ~(height : int) ~(is_coinbase : bool)
  : bytes =
  let w = Serialize.writer_create () in
  (* Outpoint: txid (32) + vout (LE 4) *)
  Serialize.write_bytes w outpoint.Types.txid;
  Serialize.write_int32_le w outpoint.Types.vout;
  (* Code: (height << 1) | fCoinBase as LE32 *)
  let code =
    Int32.of_int ((height lsl 1) lor (if is_coinbase then 1 else 0))
  in
  Serialize.write_int32_le w code;
  (* CTxOut: value (LE 8) + scriptPubKey (varint + bytes) *)
  Serialize.write_int64_le w value;
  Serialize.write_compact_size w (Cstruct.length script_pubkey);
  Serialize.write_bytes w script_pubkey;
  Bytes.of_string (Cstruct.to_string (Serialize.writer_to_cstruct w))
