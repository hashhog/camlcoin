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

let verify (pubkey_bytes : public_key) (msg_hash : Types.hash256) (sig_bytes : signature) : bool =
  try
    let pk_bs = cstruct_to_bigstring pubkey_bytes in
    let pk = Secp.Key.read_pk_exn secp_ctx pk_bs in
    let msg_bs = cstruct_to_bigstring msg_hash in
    let sig_bs = cstruct_to_bigstring sig_bytes in
    let sig_ = Secp.Sign.read_der_exn secp_ctx sig_bs in
    Secp.Sign.verify_exn secp_ctx ~pk ~msg:msg_bs ~signature:sig_
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

(* Merkle root computation *)
let merkle_root (hashes : Types.hash256 list) : Types.hash256 =
  match hashes with
  | [] -> Types.zero_hash
  | [h] -> h
  | _ ->
    let rec loop = function
      | [] -> failwith "impossible"
      | [h] -> h
      | items ->
        let pairs = ref [] in
        let rec pair = function
          | [] -> ()
          | [a] ->
            (* Duplicate last element if odd number *)
            let combined = Cstruct.concat [a; a] in
            pairs := sha256d combined :: !pairs
          | a :: b :: rest ->
            let combined = Cstruct.concat [a; b] in
            pairs := sha256d combined :: !pairs;
            pair rest
        in
        pair items;
        loop (List.rev !pairs)
    in
    loop hashes
