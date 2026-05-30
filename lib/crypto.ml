(* Cryptographic primitives for Bitcoin
 *
 * This module provides cryptographic operations required for Bitcoin:
 * - Hash functions (SHA256, SHA256d, RIPEMD160, Hash160)
 * - ECDSA signatures (secp256k1)
 * - Schnorr signatures (BIP-340)
 * - Taproot operations (BIP-341)
 *
 * Hardware acceleration:
 * - secp256k1 operations use libsecp256k1's optimized assembly where available
 * - digestif uses C implementations with potential hardware SHA intrinsics
 *)

(* All secp256k1 operations route through the vendored libsecp256k1 via thin
   C stubs in lib/schnorr_stubs.c. The opam secp256k1-internal binding has
   been removed so there is exactly one secp256k1 implementation linked into
   the binary. See "drop duplicate secp256k1 source" commit. *)

(* Hardware-accelerated SHA-256 via OpenSSL C stubs *)
external sha256_accel : string -> string = "caml_sha256_accel"
external sha256d_accel : string -> string = "caml_sha256d_accel"
external sha256_hw_info : unit -> string = "caml_sha256_hw_info"

(* Hash functions using digestif *)

(* Double SHA-256: SHA256(SHA256(data)) — Bitcoin's primary hash *)
let sha256d (data : Cstruct.t) : Types.hash256 =
  try
    Cstruct.of_string (sha256d_accel (Cstruct.to_string data))
  with _ ->
    (* Fallback to digestif if NIF not loaded *)
    let h1 = Digestif.SHA256.digest_string (Cstruct.to_string data) in
    let h2 = Digestif.SHA256.digest_string (Digestif.SHA256.to_raw_string h1) in
    Cstruct.of_string (Digestif.SHA256.to_raw_string h2)

let sha256 (data : Cstruct.t) : Cstruct.t =
  try
    Cstruct.of_string (sha256_accel (Cstruct.to_string data))
  with _ ->
    (* Fallback to digestif if NIF not loaded *)
    let h = Digestif.SHA256.digest_string (Cstruct.to_string data) in
    Cstruct.of_string (Digestif.SHA256.to_raw_string h)

(* BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg) *)
let tagged_hash (tag : string) (msg : Cstruct.t) : Cstruct.t =
  let tag_hash = sha256 (Cstruct.of_string tag) in
  let preimage = Cstruct.concat [tag_hash; tag_hash; msg] in
  sha256 preimage

(* RIPEMD160(SHA256(data)) — used for address generation *)
let hash160 (data : Cstruct.t) : Types.hash160 =
  let h1 = Digestif.SHA256.digest_string (Cstruct.to_string data) in
  let h2 = Digestif.RMD160.digest_string (Digestif.SHA256.to_raw_string h1) in
  Cstruct.of_string (Digestif.RMD160.to_raw_string h2)

(* High-level types *)
type private_key = Cstruct.t   (* 32 bytes *)
type public_key = Cstruct.t    (* 33 bytes compressed or 65 uncompressed *)
type signature = Cstruct.t     (* DER-encoded *)

(* Helper to convert Cstruct to Bigstring *)
let cstruct_to_bigstring cs =
  let len = Cstruct.length cs in
  let bs = Bigstring.create len in
  for i = 0 to len - 1 do
    Bigstring.set bs i (Char.chr (Cstruct.get_uint8 cs i))
  done;
  bs

(* Helper to convert Bigstring to Cstruct *)
let bigstring_to_cstruct bs =
  let len = Bigstring.length bs in
  let cs = Cstruct.create len in
  for i = 0 to len - 1 do
    Cstruct.set_uint8 cs i (Char.code (Bigstring.get bs i))
  done;
  cs

let generate_private_key () : private_key =
  (* Use OS random source for 32 bytes *)
  let buf = Cstruct.create 32 in
  let ic = open_in_bin "/dev/urandom" in
  let bytes = really_input_string ic 32 in
  close_in ic;
  Cstruct.blit_from_string bytes 0 buf 0 32;
  buf

(* Derive public key from private key.
   C stub calls vendored libsecp256k1's secp256k1_ec_pubkey_create +
   secp256k1_ec_pubkey_serialize. *)
external ec_pubkey_create_raw : Bigstring.t -> int -> Bigstring.t
  = "caml_ec_pubkey_create"

let derive_public_key ?(compressed=true) (privkey : private_key) : public_key =
  let sk_bs = cstruct_to_bigstring privkey in
  let pk_bs = ec_pubkey_create_raw sk_bs (if compressed then 1 else 0) in
  bigstring_to_cstruct pk_bs

(* ECDSA sign + low-S normalize + DER serialize.
   C stub calls vendored libsecp256k1's secp256k1_ecdsa_sign +
   secp256k1_ecdsa_signature_normalize + secp256k1_ecdsa_signature_serialize_der. *)
external ecdsa_sign_der_raw : Bigstring.t -> Bigstring.t -> Bigstring.t
  = "caml_ecdsa_sign_der"

let sign (privkey : private_key) (msg_hash : Types.hash256) : signature =
  let sk_bs = cstruct_to_bigstring privkey in
  let msg_bs = cstruct_to_bigstring msg_hash in
  let der_bs = ecdsa_sign_der_raw sk_bs msg_bs in
  bigstring_to_cstruct der_bs

(* Check strict DER encoding of a signature.
   Input sig_bytes INCLUDES the trailing hash-type byte (as in script evaluation).
   Format: 0x30 <total_len> 0x02 <R_len> <R> 0x02 <S_len> <S> <hashtype>
   Minimum 9 bytes (R=1, S=1, plus hashtype), maximum 73 bytes.
   See Bitcoin Core's IsValidSignatureEncoding in script/interpreter.cpp:108-171. *)
let is_valid_signature_encoding (sig_bytes : Cstruct.t) : bool =
  let len = Cstruct.length sig_bytes in
  (* Minimum 9 bytes (tag+len+R_tag+R_len+R[1]+S_tag+S_len+S[1]+hashtype),
     maximum 73 bytes (R=33, S=33, plus 7 overhead bytes including hashtype). *)
  if len < 9 || len > 73 then false
  else
    let b i = Cstruct.get_uint8 sig_bytes i in
    (* A signature is of type 0x30 (compound) *)
    if b 0 <> 0x30 then false
    (* Make sure the length covers the entire signature *)
    else if b 1 <> len - 3 then false
    (* Make sure the length of the S element is still inside the signature *)
    else if b 2 <> 0x02 then false
    else
      let len_r = b 3 in
      (* Make sure the length of the R element is reasonable *)
      if len_r = 0 then false
      (* Verify that the length of the signature matches the sum of the length
         of the elements *)
      else if 5 + len_r >= len then false
      else if b (4 + len_r) <> 0x02 then false
      else
        let len_s = b (5 + len_r) in
        if len_s = 0 then false
        else if len_r + len_s + 7 <> len then false
        (* Check whether the R element is an integer *)
        (* Negative zeros are not allowed for R *)
        else if b 4 land 0x80 <> 0 then false
        (* Null bytes at the start of R are not allowed, unless R would
           otherwise be interpreted as a negative number *)
        else if len_r > 1 && b 4 = 0x00 && b 5 land 0x80 = 0 then false
        (* Check whether the S element is an integer *)
        (* Negative zeros are not allowed for S *)
        else if b (len_r + 6) land 0x80 <> 0 then false
        (* Null bytes at the start of S are not allowed, unless S would
           otherwise be interpreted as a negative number *)
        else if len_s > 1 && b (len_r + 6) = 0x00 && b (len_r + 7) land 0x80 = 0 then false
        else true

(* Check if a DER-encoded signature (without hash type byte) has a low S value.
   BIP-62 rule 5. C stub parses DER and uses libsecp256k1's normalize to detect
   high-S. Returns false on parse failure. *)
external ecdsa_signature_is_low_s_raw : Bigstring.t -> bool
  = "caml_ecdsa_signature_is_low_s"

let is_low_der_s (sig_bytes : Cstruct.t) : bool =
  try
    let sig_bs = cstruct_to_bigstring sig_bytes in
    ecdsa_signature_is_low_s_raw sig_bs
  with _ -> false

(* ECDSA verify (strict DER parsing, no low-S normalize, mirrors the
   historical Sign.verify_exn semantics).  Routed through the same
   caml_ecdsa_verify C stub as verify_ecdsa_fast (declared below) to keep
   exactly one secp256k1 implementation in the binary. *)
external verify_ecdsa_strict_raw : Bigstring.t -> Bigstring.t -> Bigstring.t -> bool
  = "caml_ecdsa_verify"

let verify (pubkey_bytes : public_key) (msg_hash : Types.hash256) (sig_bytes : signature) : bool =
  try
    let pk_bs = cstruct_to_bigstring pubkey_bytes in
    let msg_bs = cstruct_to_bigstring msg_hash in
    let sig_bs = cstruct_to_bigstring sig_bytes in
    verify_ecdsa_strict_raw pk_bs msg_bs sig_bs
  with _ -> false

(* ============================================================================
   Compact Recoverable ECDSA signatures (Bitcoin Core "signmessage" format)

   Format (matches Bitcoin Core's CKey::SignCompact / CPubKey::RecoverCompact
   in src/key.cpp + src/pubkey.cpp):
     [0]      header byte = 27 + recid + (compressed ? 4 : 0)
     [1..33)  32-byte R
     [33..65) 32-byte S

   The header byte's low 2 bits hold the recovery id (0..3); bit 2 is the
   compressed-pubkey flag. The libsecp256k1 OCaml binding stores the
   recoverable signature serialization as 65 raw bytes: 64-byte compact body
   followed by a 1-byte recid at index 64. We translate between the two.
   ============================================================================ *)

(* C stubs (lib/schnorr_stubs.c) — vendored libsecp256k1 with the recovery
   module enabled. Same vendored copy as every other secp256k1 call in the
   binary; the duplicate-link via secp256k1-internal has been retired. *)
external ecdsa_sign_compact_raw : Bigstring.t -> Bigstring.t -> int -> Bigstring.t
  = "caml_ecdsa_sign_compact"

external ecdsa_recover_compact_raw : Bigstring.t -> Bigstring.t -> Bigstring.t
  = "caml_ecdsa_recover_compact"

(* Sign [msg_hash] with [privkey] and return a 65-byte Bitcoin compact
   signature.  [compressed] sets the +4 flag in the header byte and reflects
   whether the corresponding pubkey is the 33-byte compressed SEC encoding. *)
let sign_compact ?(compressed=true) (privkey : private_key)
    (msg_hash : Types.hash256) : Cstruct.t =
  let sk_bs = cstruct_to_bigstring privkey in
  let msg_bs = cstruct_to_bigstring msg_hash in
  let out_bs = ecdsa_sign_compact_raw sk_bs msg_bs (if compressed then 1 else 0) in
  bigstring_to_cstruct out_bs

(* Recover the public key that produced [sig_bytes] over [msg_hash].
   Returns the SEC-encoded public key (compressed if header byte's bit-2 is
   set, else uncompressed) on success.  Returns None on a malformed signature
   or when recovery fails (the C stub returns a 0-length bigstring on
   failure). *)
let recover_compact (sig_bytes : Cstruct.t) (msg_hash : Types.hash256)
    : public_key option =
  if Cstruct.length sig_bytes <> 65 then None
  else
    try
      let sig_bs = cstruct_to_bigstring sig_bytes in
      let msg_bs = cstruct_to_bigstring msg_hash in
      let pub_bs = ecdsa_recover_compact_raw sig_bs msg_bs in
      if Bigstring.length pub_bs = 0 then None
      else Some (bigstring_to_cstruct pub_bs)
    with _ -> None

(* Bitcoin Core's MESSAGE_MAGIC prefix used by signmessage / verifymessage
   (src/common/signmessage.cpp). *)
let message_magic = "Bitcoin Signed Message:\n"

(* Encode a CompactSize-prefixed string the same way Bitcoin Core's
   HashWriter::operator<<(string) does: compact-size length, then raw bytes. *)
let put_compact_size (buf : Buffer.t) (n : int) : unit =
  if n < 0xFD then
    Buffer.add_char buf (Char.chr n)
  else if n <= 0xFFFF then begin
    Buffer.add_char buf '\xFD';
    Buffer.add_char buf (Char.chr (n land 0xFF));
    Buffer.add_char buf (Char.chr ((n lsr 8) land 0xFF))
  end else if n <= 0xFFFFFFFF then begin
    Buffer.add_char buf '\xFE';
    Buffer.add_char buf (Char.chr (n land 0xFF));
    Buffer.add_char buf (Char.chr ((n lsr 8) land 0xFF));
    Buffer.add_char buf (Char.chr ((n lsr 16) land 0xFF));
    Buffer.add_char buf (Char.chr ((n lsr 24) land 0xFF))
  end else begin
    Buffer.add_char buf '\xFF';
    for i = 0 to 7 do
      Buffer.add_char buf (Char.chr ((n lsr (i * 8)) land 0xFF))
    done
  end

(* Compute the double-SHA256 hash that signmessage / verifymessage operate on:
     dsha256(compact_size(magic) || magic || compact_size(msg) || msg)
   Mirrors src/common/signmessage.cpp::MessageHash. *)
let message_hash (message : string) : Types.hash256 =
  let buf = Buffer.create
    (10 + String.length message_magic + String.length message) in
  put_compact_size buf (String.length message_magic);
  Buffer.add_string buf message_magic;
  put_compact_size buf (String.length message);
  Buffer.add_string buf message;
  sha256d (Cstruct.of_string (Buffer.contents buf))

(* Schnorr signature verification (BIP-340) *)
external schnorr_verify_raw : Bigstring.t -> Bigstring.t -> Bigstring.t -> bool
  = "caml_schnorr_verify"

let schnorr_verify ~(pubkey_x : Cstruct.t) ~(msg : Cstruct.t) ~(signature : Cstruct.t) : bool =
  if Cstruct.length pubkey_x <> 32 || Cstruct.length msg <> 32 || Cstruct.length signature <> 64 then
    false
  else
    try
      schnorr_verify_raw
        (cstruct_to_bigstring pubkey_x)
        (cstruct_to_bigstring msg)
        (cstruct_to_bigstring signature)
    with _ -> false

(* Schnorr signature creation (BIP-340) *)
external schnorr_sign_raw : Bigstring.t -> Bigstring.t -> Bigstring.t
  = "caml_schnorr_sign"

let schnorr_sign ~(privkey : Cstruct.t) ~(msg : Cstruct.t) : Cstruct.t =
  if Cstruct.length privkey <> 32 || Cstruct.length msg <> 32 then
    failwith "schnorr_sign: privkey must be 32 bytes, msg must be 32 bytes"
  else
    bigstring_to_cstruct (schnorr_sign_raw
      (cstruct_to_bigstring privkey)
      (cstruct_to_bigstring msg))

(* Schnorr signing with BIP-341 taproot key tweak *)
external schnorr_sign_tweaked_raw : Bigstring.t -> Bigstring.t -> Bigstring.t -> Bigstring.t
  = "caml_schnorr_sign_tweaked"

let schnorr_sign_tweaked ~(privkey : Cstruct.t) ~(tweak : Cstruct.t) ~(msg : Cstruct.t) : Cstruct.t =
  if Cstruct.length privkey <> 32 || Cstruct.length tweak <> 32 || Cstruct.length msg <> 32 then
    failwith "schnorr_sign_tweaked: all arguments must be 32 bytes"
  else
    bigstring_to_cstruct (schnorr_sign_tweaked_raw
      (cstruct_to_bigstring privkey)
      (cstruct_to_bigstring tweak)
      (cstruct_to_bigstring msg))

(* Compute the BIP-341 TapTweak for key-path-only spending (no script tree) *)
let compute_taptweak_keypath (internal_pubkey_xonly : Cstruct.t) : Cstruct.t =
  tagged_hash "TapTweak" internal_pubkey_xonly

(* Derive x-only public key from private key (32-byte output for Taproot) *)
external derive_xonly_pubkey_raw : Bigstring.t -> Bigstring.t
  = "caml_derive_xonly_pubkey"

let derive_xonly_pubkey (privkey : Cstruct.t) : Cstruct.t =
  if Cstruct.length privkey <> 32 then
    failwith "derive_xonly_pubkey: privkey must be 32 bytes"
  else
    bigstring_to_cstruct (derive_xonly_pubkey_raw (cstruct_to_bigstring privkey))

(* X-only pubkey tweak add check (for Taproot commitment verification) *)
external xonly_tweak_add_check_raw : Bigstring.t -> Bigstring.t -> int -> Bigstring.t -> bool
  = "caml_xonly_pubkey_tweak_add_check"

let xonly_pubkey_tweak_add_check ~(internal_pk : Cstruct.t) ~(tweaked_pk : Cstruct.t)
    ~(tweaked_parity : int) ~(tweak : Cstruct.t) : bool =
  if Cstruct.length internal_pk <> 32 || Cstruct.length tweaked_pk <> 32 || Cstruct.length tweak <> 32 then
    false
  else
    try
      xonly_tweak_add_check_raw
        (cstruct_to_bigstring internal_pk)
        (cstruct_to_bigstring tweaked_pk)
        tweaked_parity
        (cstruct_to_bigstring tweak)
    with _ -> false

(* Compute transaction ID (double SHA-256 of serialized tx without witness) *)
let compute_txid (tx : Types.transaction) : Types.hash256 =
  let w = Serialize.writer_create () in
  Serialize.serialize_transaction_no_witness w tx;
  sha256d (Serialize.writer_to_cstruct w)

(* Compute block hash (double SHA-256 of serialized header) *)
let compute_block_hash (header : Types.block_header) : Types.hash256 =
  let w = Serialize.writer_create () in
  Serialize.serialize_block_header w header;
  sha256d (Serialize.writer_to_cstruct w)

(* Merkle root computation with CVE-2012-2459 mutation detection.
   Returns (root_hash, mutated) where mutated is true if any two adjacent
   hashes at any level are identical. This matches Bitcoin Core's
   ComputeMerkleRoot: the mutation check runs BEFORE odd-element duplication,
   so the forced self-duplication of an odd last element does NOT set the flag. *)
let merkle_root (hashes : Types.hash256 list) : (Types.hash256 * bool) =
  match hashes with
  | [] -> (Types.zero_hash, false)
  | [h] -> (h, false)
  | _ ->
    let mutated = ref false in
    let rec loop = function
      | [] -> failwith "impossible"
      | [h] -> h
      | items ->
        let pairs = ref [] in
        let rec pair = function
          | [] -> ()
          | [a] ->
            (* Odd element: duplicate last. Per Bitcoin Core, the mutation
               check runs before duplication, so this does NOT set mutated. *)
            let combined = Cstruct.concat [a; a] in
            pairs := sha256d combined :: !pairs
          | a :: b :: rest ->
            if Cstruct.equal a b then mutated := true;
            let combined = Cstruct.concat [a; b] in
            pairs := sha256d combined :: !pairs;
            pair rest
        in
        pair items;
        loop (List.rev !pairs)
    in
    (* OCaml evaluates tuple elements RIGHT-TO-LEFT, so writing
       `(loop hashes, !mutated)` reads !mutated BEFORE loop runs and the flag
       is always still false. Force loop to run first by binding root. *)
    let root = loop hashes in
    (root, !mutated)

(* Compute witness transaction ID (wtxid).
   For the coinbase transaction (index 0), the wtxid is always 32 zero bytes.
   For all other transactions, wtxid = SHA256d of the full serialized tx
   including witness data. *)
let compute_wtxid (tx : Types.transaction) : Types.hash256 =
  (* Check if this is a coinbase: first input has null prevout txid and vout=0xFFFFFFFF *)
  let is_coinbase = match tx.inputs with
    | [inp] ->
      Cstruct.equal inp.previous_output.txid Types.zero_hash
      && inp.previous_output.vout = 0xFFFFFFFFl
    | _ -> false
  in
  if is_coinbase then
    Types.zero_hash
  else begin
    let w = Serialize.writer_create () in
    Serialize.serialize_transaction w tx;
    sha256d (Serialize.writer_to_cstruct w)
  end

(* Compute the witness merkle root from a list of transactions.
   The coinbase's wtxid slot is zero_hash (handled by compute_wtxid).
   No mutation detection needed for the witness merkle tree. *)
let witness_merkle_root (txs : Types.transaction list) : Types.hash256 =
  let wtxids = List.map compute_wtxid txs in
  fst (merkle_root wtxids)

(* BIP-341 Taproot tree helper functions *)

(* Compute tapleaf hash: tagged_hash("TapLeaf", leaf_version || compact_size(script_len) || script) *)
let compute_tapleaf_hash (leaf_version : int) (script : Cstruct.t) : Cstruct.t =
  let w = Serialize.writer_create () in
  Serialize.write_uint8 w leaf_version;
  Serialize.write_compact_size w (Cstruct.length script);
  Serialize.write_bytes w script;
  tagged_hash "TapLeaf" (Serialize.writer_to_cstruct w)

(* Compute tapbranch hash: tagged_hash("TapBranch", sorted(left, right))
   Per BIP-341, the lexicographically smaller hash goes first. *)
let compute_tapbranch_hash (left : Cstruct.t) (right : Cstruct.t) : Cstruct.t =
  let a, b =
    if Cstruct.compare left right <= 0 then (left, right)
    else (right, left)
  in
  tagged_hash "TapBranch" (Cstruct.concat [a; b])

(* Compute taproot merkle root from a control block path.
   The control block contains: leaf_version (1 byte) || internal_key (32 bytes) || path (32 bytes each)
   This function takes the tapleaf hash and the path elements, and computes
   the merkle root by iteratively combining with tapbranch hashes. *)
let compute_taproot_merkle_root_from_path (leaf_hash : Cstruct.t)
    (path : Cstruct.t list) : Cstruct.t =
  List.fold_left (fun acc node ->
    compute_tapbranch_hash acc node
  ) leaf_hash path

(* ============================================================================
   SipHash-2-4 (BIP 152 compact blocks)

   SipHash is a fast pseudorandom hash function used for compact block short
   transaction IDs. The implementation follows Bitcoin Core's crypto/siphash.cpp.
   ============================================================================ *)

module SipHash = struct
  (* SipHash constants *)
  let c0 = 0x736f6d6570736575L
  let c1 = 0x646f72616e646f6dL
  let c2 = 0x6c7967656e657261L
  let c3 = 0x7465646279746573L

  (* Left rotate 64-bit value *)
  let rotl64 (x : int64) (n : int) : int64 =
    Int64.logor
      (Int64.shift_left x n)
      (Int64.shift_right_logical x (64 - n))

  (* SipRound: the core mixing function *)
  let sipround (v0, v1, v2, v3) =
    let v0 = Int64.add v0 v1 in
    let v1 = rotl64 v1 13 in
    let v1 = Int64.logxor v1 v0 in
    let v0 = rotl64 v0 32 in
    let v2 = Int64.add v2 v3 in
    let v3 = rotl64 v3 16 in
    let v3 = Int64.logxor v3 v2 in
    let v0 = Int64.add v0 v3 in
    let v3 = rotl64 v3 21 in
    let v3 = Int64.logxor v3 v0 in
    let v2 = Int64.add v2 v1 in
    let v1 = rotl64 v1 17 in
    let v1 = Int64.logxor v1 v2 in
    let v2 = rotl64 v2 32 in
    (v0, v1, v2, v3)

  (* Initialize SipHash state from k0, k1 *)
  let init (k0 : int64) (k1 : int64) =
    (Int64.logxor c0 k0, Int64.logxor c1 k1,
     Int64.logxor c2 k0, Int64.logxor c3 k1)

  (* Read a little-endian uint64 from a Cstruct *)
  let get_uint64_le (cs : Cstruct.t) (off : int) : int64 =
    Cstruct.LE.get_uint64 cs off

  (* Hash a uint256 (32 bytes) with the given SipHash state.
     This is the PresaltedSipHasher::operator()(const uint256&) equivalent. *)
  let hash_uint256 (k0 : int64) (k1 : int64) (data : Cstruct.t) : int64 =
    if Cstruct.length data <> 32 then
      failwith "SipHash.hash_uint256: expected 32 bytes";
    let (v0, v1, v2, v3) = init k0 k1 in
    (* Process 4 x 8-byte words *)
    let d0 = get_uint64_le data 0 in
    let v3 = Int64.logxor v3 d0 in
    let (v0, v1, v2, v3) = sipround (v0, v1, v2, v3) in
    let (v0, v1, v2, v3) = sipround (v0, v1, v2, v3) in
    let v0 = Int64.logxor v0 d0 in

    let d1 = get_uint64_le data 8 in
    let v3 = Int64.logxor v3 d1 in
    let (v0, v1, v2, v3) = sipround (v0, v1, v2, v3) in
    let (v0, v1, v2, v3) = sipround (v0, v1, v2, v3) in
    let v0 = Int64.logxor v0 d1 in

    let d2 = get_uint64_le data 16 in
    let v3 = Int64.logxor v3 d2 in
    let (v0, v1, v2, v3) = sipround (v0, v1, v2, v3) in
    let (v0, v1, v2, v3) = sipround (v0, v1, v2, v3) in
    let v0 = Int64.logxor v0 d2 in

    let d3 = get_uint64_le data 24 in
    let v3 = Int64.logxor v3 d3 in
    let (v0, v1, v2, v3) = sipround (v0, v1, v2, v3) in
    let (v0, v1, v2, v3) = sipround (v0, v1, v2, v3) in
    let v0 = Int64.logxor v0 d3 in

    (* Finalize: length byte (32 = 0x20) in top byte + padding *)
    (* For 32 bytes: ((uint64_t{4}) << 59) which is 4*8=32 bytes *)
    let len_word = Int64.shift_left 4L 59 in
    let v3 = Int64.logxor v3 len_word in
    let (v0, v1, v2, v3) = sipround (v0, v1, v2, v3) in
    let (v0, v1, v2, v3) = sipround (v0, v1, v2, v3) in
    let v0 = Int64.logxor v0 len_word in

    let v2 = Int64.logxor v2 0xFFL in
    let (v0, v1, v2, v3) = sipround (v0, v1, v2, v3) in
    let (v0, v1, v2, v3) = sipround (v0, v1, v2, v3) in
    let (v0, v1, v2, v3) = sipround (v0, v1, v2, v3) in
    let (v0, v1, v2, v3) = sipround (v0, v1, v2, v3) in
    Int64.logxor (Int64.logxor (Int64.logxor v0 v1) v2) v3

  (* Derive SipHash keys from block header and nonce.
     Per BIP 152 / Bitcoin Core FillShortTxIDSelector:
       SHA256(serialize(header) || nonce_le_8bytes) -> first 16 bytes as (k0, k1).
     The preimage is the 80-byte serialized block header followed by the 8-byte
     little-endian nonce.  Bitcoin Core writes: stream << header << nonce, then
     calls CSHA256 (single SHA-256) on the stream — NOT SHA256d(header_hash).
     Taking SHA256(header_hash || nonce) was Bug #1: wrong 40-byte preimage
     (32-byte double-SHA256 hash instead of 80-byte raw header bytes). *)
  let derive_keys (header : Types.block_header) (nonce : int64) : (int64 * int64) =
    let w = Serialize.writer_create () in
    Serialize.serialize_block_header w header;
    let nonce_cs = Cstruct.create 8 in
    Cstruct.LE.set_uint64 nonce_cs 0 nonce;
    let preimage = Cstruct.concat [Serialize.writer_to_cstruct w; nonce_cs] in
    let hash = sha256 preimage in
    let k0 = get_uint64_le hash 0 in
    let k1 = get_uint64_le hash 8 in
    (k0, k1)
end

(* Compute short transaction ID for compact blocks (BIP 152).
   Returns lower 6 bytes of SipHash output as int64. *)
let compute_short_txid (k0 : int64) (k1 : int64) (wtxid : Types.hash256) : int64 =
  let hash = SipHash.hash_uint256 k0 k1 wtxid in
  Int64.logand hash 0xFFFFFFFFFFFFL  (* lower 48 bits = 6 bytes *)

(* ============================================================================
   BIP-341 Taproot Output Key Computation
   ============================================================================ *)

(* Taproot tweak add - computes tweaked output pubkey from internal key and merkle root.
   Uses secp256k1's xonly_pubkey_tweak_add via FFI. Returns the x-only tweaked output key. *)
external xonly_tweak_add_raw : Bigstring.t -> Bigstring.t -> Bigstring.t
  = "caml_xonly_pubkey_tweak_add"

(* Compute the taproot tweak from internal key and optional merkle root.
   Per BIP-341: t = tagged_hash("TapTweak", P || h) where P is internal key, h is merkle root *)
let compute_taproot_tweak (internal_pk : Cstruct.t) (merkle_root : Cstruct.t option) : Cstruct.t =
  let msg = match merkle_root with
    | None -> internal_pk
    | Some root -> Cstruct.concat [internal_pk; root]
  in
  tagged_hash "TapTweak" msg

(* X-only pubkey tweak add with parity (for Taproot control block construction) *)
external xonly_tweak_add_with_parity_raw : Bigstring.t -> Bigstring.t -> (Bigstring.t * int)
  = "caml_xonly_pubkey_tweak_add_with_parity"

let compute_taproot_output_key_with_parity (internal_pk : Cstruct.t) (merkle_root : Cstruct.t option) : (Cstruct.t * int) =
  if Cstruct.length internal_pk <> 32 then
    failwith "compute_taproot_output_key_with_parity: internal_pk must be 32 bytes";
  let tweak = compute_taproot_tweak internal_pk merkle_root in
  let (result, parity) = xonly_tweak_add_with_parity_raw
    (cstruct_to_bigstring internal_pk)
    (cstruct_to_bigstring tweak)
  in
  (bigstring_to_cstruct result, parity)

(* Compute the taproot output key from internal public key and optional script tree merkle root.
   This is Q = P + t*G where t = tagged_hash("TapTweak", P || m), P is internal key, m is merkle root.
   Returns the 32-byte x-only output pubkey. *)
let compute_taproot_output_key (internal_pk : Cstruct.t) (merkle_root : Cstruct.t option) : Cstruct.t =
  if Cstruct.length internal_pk <> 32 then
    failwith "compute_taproot_output_key: internal_pk must be 32 bytes";
  let tweak = compute_taproot_tweak internal_pk merkle_root in
  let result = xonly_tweak_add_raw
    (cstruct_to_bigstring internal_pk)
    (cstruct_to_bigstring tweak)
  in
  bigstring_to_cstruct result

(* ============================================================================
   Hardware-Accelerated ECDSA Verification
   ============================================================================

   These functions use the vendored libsecp256k1 directly via FFI.
   libsecp256k1 uses hand-optimized assembly for x86_64 when available. *)

(* Raw FFI binding for fast ECDSA verification *)
external ecdsa_verify_raw : Bigstring.t -> Bigstring.t -> Bigstring.t -> bool
  = "caml_ecdsa_verify"

(* Raw FFI binding for ECDSA verification with low-S normalization *)
external ecdsa_verify_normalized_raw : Bigstring.t -> Bigstring.t -> Bigstring.t -> bool
  = "caml_ecdsa_verify_normalized"

(* Fast ECDSA verification using libsecp256k1 FFI directly.
   This is typically 2-3x faster than going through OCaml bindings. *)
let verify_ecdsa_fast ~(pubkey : Cstruct.t) ~(msg32 : Cstruct.t) ~(signature : Cstruct.t) : bool =
  if Cstruct.length msg32 <> 32 then false
  else if Cstruct.length pubkey <> 33 && Cstruct.length pubkey <> 65 then false
  else
    try
      ecdsa_verify_raw
        (cstruct_to_bigstring pubkey)
        (cstruct_to_bigstring msg32)
        (cstruct_to_bigstring signature)
    with _ -> false

(* ECDSA verification with automatic low-S normalization.
   This is useful for verifying legacy signatures that may have high-S values. *)
let verify_ecdsa_normalized ~(pubkey : Cstruct.t) ~(msg32 : Cstruct.t) ~(signature : Cstruct.t) : bool =
  if Cstruct.length msg32 <> 32 then false
  else if Cstruct.length pubkey <> 33 && Cstruct.length pubkey <> 65 then false
  else
    try
      ecdsa_verify_normalized_raw
        (cstruct_to_bigstring pubkey)
        (cstruct_to_bigstring msg32)
        (cstruct_to_bigstring signature)
    with _ -> false

(* Raw FFI binding for ECDSA verification with lax DER parsing *)
external ecdsa_verify_lax_raw : Bigstring.t -> Bigstring.t -> Bigstring.t -> bool
  = "caml_ecdsa_verify_lax"

(* ECDSA verification with lax DER parsing and low-S normalization.
   This is needed for Bitcoin script verification: signatures that passed the
   separate strict-DER check (when DERSIG/STRICTENC flags are set) can use
   strict parsing, but all signatures should go through lax parsing + normalize
   since Bitcoin Core does this for consensus verification. *)
let verify_lax (pubkey_bytes : public_key) (msg_hash : Types.hash256) (sig_bytes : signature) : bool =
  let pk_len = Cstruct.length pubkey_bytes in
  if Cstruct.length msg_hash <> 32 then false
  else if pk_len <> 33 && pk_len <> 65 then false
  else
    try
      ecdsa_verify_lax_raw
        (cstruct_to_bigstring pubkey_bytes)
        (cstruct_to_bigstring msg_hash)
        (cstruct_to_bigstring sig_bytes)
    with _ -> false

(* ============================================================================
   Batch Schnorr Verification
   ============================================================================

   Batch verification can be faster than individual verification for multiple
   signatures due to amortized computation in multi-scalar multiplication.
   This is particularly useful when validating taproot transactions in blocks. *)

(* Raw FFI binding for batch Schnorr verification *)
external schnorr_verify_batch_raw : Bigstring.t -> Bigstring.t -> Bigstring.t -> int -> bool
  = "caml_schnorr_verify_batch"

(* Batch-verify multiple Schnorr signatures.
   Returns true only if ALL signatures are valid.
   Each element: pubkey (32 bytes x-only), msg (32 bytes), sig (64 bytes) *)
let schnorr_verify_batch (items : (Cstruct.t * Cstruct.t * Cstruct.t) list) : bool =
  let count = List.length items in
  if count = 0 then true
  else begin
    (* Validate sizes *)
    let valid_sizes = List.for_all (fun (pk, msg, sig_) ->
      Cstruct.length pk = 32 && Cstruct.length msg = 32 && Cstruct.length sig_ = 64
    ) items in
    if not valid_sizes then false
    else begin
      (* Pack into contiguous arrays *)
      let pubkeys = Bigstring.create (count * 32) in
      let msgs = Bigstring.create (count * 32) in
      let sigs = Bigstring.create (count * 64) in
      List.iteri (fun i (pk, msg, sig_) ->
        let pk_bs = cstruct_to_bigstring pk in
        let msg_bs = cstruct_to_bigstring msg in
        let sig_bs = cstruct_to_bigstring sig_ in
        (* Bigstring.blit src src_off dst dst_off len *)
        Bigstring.blit pk_bs 0 pubkeys (i * 32) 32;
        Bigstring.blit msg_bs 0 msgs (i * 32) 32;
        Bigstring.blit sig_bs 0 sigs (i * 64) 64
      ) items;
      try
        schnorr_verify_batch_raw pubkeys msgs sigs count
      with _ -> false
    end
  end

(* ============================================================================
   Public Key Operations
   ============================================================================ *)

(* Raw FFI binding for pubkey validation *)
external pubkey_parse_check_raw : Bigstring.t -> bool
  = "caml_pubkey_parse_check"

(* Raw FFI binding for pubkey compression *)
external pubkey_serialize_compressed_raw : Bigstring.t -> Bigstring.t
  = "caml_pubkey_serialize_compressed"

(* Fast check if bytes represent a valid secp256k1 public key *)
let is_valid_pubkey (pubkey : Cstruct.t) : bool =
  let len = Cstruct.length pubkey in
  if len <> 33 && len <> 65 then false
  else
    try
      pubkey_parse_check_raw (cstruct_to_bigstring pubkey)
    with _ -> false

(* Compress an uncompressed public key (65 bytes -> 33 bytes) *)
let compress_pubkey (pubkey : Cstruct.t) : Cstruct.t option =
  if Cstruct.length pubkey = 33 then
    Some pubkey  (* Already compressed *)
  else if Cstruct.length pubkey <> 65 then
    None
  else
    try
      Some (bigstring_to_cstruct (pubkey_serialize_compressed_raw (cstruct_to_bigstring pubkey)))
    with _ -> None
