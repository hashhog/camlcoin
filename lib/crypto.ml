(* Cryptographic primitives for Bitcoin *)

module Secp = Libsecp256k1.External

(* Hash functions using digestif *)

(* Double SHA-256: SHA256(SHA256(data)) — Bitcoin's primary hash *)
let sha256d (data : Cstruct.t) : Types.hash256 =
  let h1 = Digestif.SHA256.digest_string (Cstruct.to_string data) in
  let h2 = Digestif.SHA256.digest_string (Digestif.SHA256.to_raw_string h1) in
  Cstruct.of_string (Digestif.SHA256.to_raw_string h2)

let sha256 (data : Cstruct.t) : Cstruct.t =
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

(* Global secp256k1 context — created once for signing and verification *)
let secp_ctx = Secp.Context.create ~sign:true ~verify:true ()

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

let derive_public_key ?(compressed=true) (privkey : private_key) : public_key =
  let sk_bs = cstruct_to_bigstring privkey in
  let sk = Secp.Key.read_sk_exn secp_ctx sk_bs in
  let pk = Secp.Key.neuterize_exn secp_ctx sk in
  let pk_bs = Secp.Key.to_bytes ~compress:compressed secp_ctx pk in
  bigstring_to_cstruct pk_bs

let sign (privkey : private_key) (msg_hash : Types.hash256) : signature =
  let sk_bs = cstruct_to_bigstring privkey in
  let sk = Secp.Key.read_sk_exn secp_ctx sk_bs in
  let msg_bs = cstruct_to_bigstring msg_hash in
  let sig_ = Secp.Sign.sign_exn secp_ctx ~sk msg_bs in
  (* Serialize as DER *)
  let der_bs = Secp.Sign.to_bytes ~der:true secp_ctx sig_ in
  bigstring_to_cstruct der_bs

(* Check strict DER encoding of a signature (without hash type byte).
   DER format: 0x30 <total_len> 0x02 <R_len> <R> 0x02 <S_len> <S>
   See Bitcoin Core's IsValidSignatureEncoding in script/interpreter.cpp *)
let is_valid_signature_encoding (sig_bytes : Cstruct.t) : bool =
  let len = Cstruct.length sig_bytes in
  (* Minimum DER signature is 8 bytes, maximum is 73 bytes *)
  if len < 8 || len > 73 then false
  else
    let b i = Cstruct.get_uint8 sig_bytes i in
    (* A signature is of type 0x30 (compound) *)
    if b 0 <> 0x30 then false
    (* Make sure the length covers the entire signature *)
    else if b 1 <> len - 2 then false
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
        else if len_r + len_s + 6 <> len then false
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
   BIP-62 rule 5. Uses libsecp256k1's normalize to detect high-S. *)
let is_low_der_s (sig_bytes : Cstruct.t) : bool =
  try
    let sig_bs = cstruct_to_bigstring sig_bytes in
    let sig_ = Secp.Sign.read_der_exn secp_ctx sig_bs in
    (* normalize returns None if already low-S, Some _ if it was high-S *)
    match Secp.Sign.normalize secp_ctx sig_ with
    | None -> true     (* Already normalized / low-S *)
    | Some _ -> false  (* Was high-S, needed normalization *)
  with _ -> false

let verify (pubkey_bytes : public_key) (msg_hash : Types.hash256) (sig_bytes : signature) : bool =
  try
    let pk_bs = cstruct_to_bigstring pubkey_bytes in
    let pk = Secp.Key.read_pk_exn secp_ctx pk_bs in
    let msg_bs = cstruct_to_bigstring msg_hash in
    let sig_bs = cstruct_to_bigstring sig_bytes in
    let sig_ = Secp.Sign.read_der_exn secp_ctx sig_bs in
    Secp.Sign.verify_exn secp_ctx ~pk ~msg:msg_bs ~signature:sig_
  with _ -> false

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
    (loop hashes, !mutated)

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
