(* Bitcoin address encoding and decoding *)
(* Supports Base58Check (P2PKH, P2SH), Bech32 (P2WPKH, P2WSH), Bech32m (P2TR) *)

(* Address types *)
type address_type =
  | P2PKH       (* Pay to Public Key Hash — 1... *)
  | P2SH        (* Pay to Script Hash — 3... *)
  | P2WPKH      (* Pay to Witness Public Key Hash — bc1q... *)
  | P2WSH       (* Pay to Witness Script Hash — bc1q... (longer) *)
  | P2TR        (* Pay to Taproot — bc1p... *)

type network = [`Mainnet | `Testnet | `Regtest]

type address = {
  addr_type : address_type;
  hash : Cstruct.t;     (* 20 bytes for P2PKH/P2SH/P2WPKH, 32 for P2WSH/P2TR *)
  network : network;
}

(* ========== Base58 Encoding ========== *)

let base58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

(* Convert bytes to Base58: treat input as big-endian integer, repeatedly divide by 58 *)
let base58_encode (data : Cstruct.t) : string =
  let len = Cstruct.length data in
  if len = 0 then ""
  else begin
    (* Count leading zero bytes — each becomes a '1' *)
    let leading_zeros = ref 0 in
    while !leading_zeros < len &&
          Cstruct.get_uint8 data !leading_zeros = 0 do
      incr leading_zeros
    done;
    (* Convert to big integer and repeatedly mod 58 *)
    let digits = Array.make (len * 2) 0 in
    let digit_count = ref 0 in
    (* Simple byte-by-byte conversion *)
    let values = Array.make (len * 2) 0 in
    let value_len = ref 0 in
    for i = 0 to len - 1 do
      let carry = ref (Cstruct.get_uint8 data i) in
      let j = ref 0 in
      while !j < !value_len || !carry <> 0 do
        let v = if !j < !value_len then values.(!j) else 0 in
        let acc = v * 256 + !carry in
        values.(!j) <- acc mod 58;
        carry := acc / 58;
        incr j
      done;
      value_len := !j
    done;
    for i = !value_len - 1 downto 0 do
      digits.(!digit_count) <- values.(i);
      incr digit_count
    done;
    let buf = Buffer.create (!leading_zeros + !digit_count) in
    for _ = 1 to !leading_zeros do
      Buffer.add_char buf '1'
    done;
    for i = 0 to !digit_count - 1 do
      Buffer.add_char buf (String.get base58_alphabet digits.(i))
    done;
    Buffer.contents buf
  end

let base58_decode (s : string) : Cstruct.t =
  let len = String.length s in
  if len = 0 then Cstruct.create 0
  else begin
    let leading_ones = ref 0 in
    while !leading_ones < len && s.[!leading_ones] = '1' do
      incr leading_ones
    done;
    let values = Array.make (len * 2) 0 in
    let value_len = ref 0 in
    for i = 0 to len - 1 do
      let c = s.[i] in
      let digit = match String.index_opt base58_alphabet c with
        | Some d -> d
        | None -> failwith ("Invalid base58 character: " ^ String.make 1 c)
      in
      let carry = ref digit in
      let j = ref 0 in
      while !j < !value_len || !carry <> 0 do
        let v = if !j < !value_len then values.(!j) else 0 in
        let acc = v * 58 + !carry in
        values.(!j) <- acc mod 256;
        carry := acc / 256;
        incr j
      done;
      value_len := !j
    done;
    let total_len = !leading_ones + !value_len in
    let result = Cstruct.create total_len in
    for i = 0 to !leading_ones - 1 do
      Cstruct.set_uint8 result i 0
    done;
    for i = 0 to !value_len - 1 do
      Cstruct.set_uint8 result (!leading_ones + i) values.(!value_len - 1 - i)
    done;
    result
  end

(* ========== Base58Check Encoding ========== *)

(* Base58Check = Base58(payload || checksum) where checksum = first 4 bytes of SHA256d(payload) *)
let base58check_encode (payload : Cstruct.t) : string =
  let checksum = Cstruct.sub (Crypto.sha256d payload) 0 4 in
  let with_check = Cstruct.concat [payload; checksum] in
  base58_encode with_check

let base58check_decode (s : string) : (Cstruct.t, string) result =
  try
    let data = base58_decode s in
    let len = Cstruct.length data in
    if len < 5 then Error "Too short for Base58Check"
    else begin
      let payload = Cstruct.sub data 0 (len - 4) in
      let given_checksum = Cstruct.sub data (len - 4) 4 in
      let computed_checksum = Cstruct.sub (Crypto.sha256d payload) 0 4 in
      if Cstruct.equal given_checksum computed_checksum then
        Ok payload
      else
        Error "Invalid Base58Check checksum"
    end
  with
  | Failure msg -> Error msg

(* ========== Bech32 / Bech32m Encoding ========== *)

let bech32_charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

let bech32_polymod (values : int list) : int =
  let generator = [| 0x3b6a57b2; 0x26508e6d; 0x1ea119fa; 0x3d4233dd; 0x2a1462b3 |] in
  let chk = ref 1 in
  List.iter (fun v ->
    let b = !chk lsr 25 in
    chk := ((!chk land 0x1ffffff) lsl 5) lxor v;
    for i = 0 to 4 do
      if (b lsr i) land 1 <> 0 then
        chk := !chk lxor generator.(i)
    done
  ) values;
  !chk

let bech32_hrp_expand (hrp : string) : int list =
  let len = String.length hrp in
  let result = ref [] in
  (* High bits of each character *)
  for i = 0 to len - 1 do
    result := (Char.code hrp.[i] lsr 5) :: !result
  done;
  result := 0 :: !result;
  (* Low bits of each character *)
  for i = 0 to len - 1 do
    result := (Char.code hrp.[i] land 0x1f) :: !result
  done;
  List.rev !result

(* Bech32 constant = 1, Bech32m constant = 0x2bc830a3 *)
type bech32_encoding = Bech32 | Bech32m

let encoding_constant = function
  | Bech32  -> 1
  | Bech32m -> 0x2bc830a3

let bech32_create_checksum (enc : bech32_encoding) (hrp : string) (data : int list) : int list =
  let values = bech32_hrp_expand hrp @ data @ [0; 0; 0; 0; 0; 0] in
  let polymod = bech32_polymod values lxor (encoding_constant enc) in
  List.init 6 (fun i -> (polymod lsr (5 * (5 - i))) land 0x1f)

let bech32_verify_checksum (enc : bech32_encoding) (hrp : string) (data : int list) : bool =
  bech32_polymod (bech32_hrp_expand hrp @ data) = encoding_constant enc

let bech32_encode (enc : bech32_encoding) (hrp : string) (data : int list) : string =
  let checksum = bech32_create_checksum enc hrp data in
  let all_data = data @ checksum in
  let buf = Buffer.create (String.length hrp + 1 + List.length all_data) in
  Buffer.add_string buf hrp;
  Buffer.add_char buf '1';
  List.iter (fun d ->
    Buffer.add_char buf (String.get bech32_charset d)
  ) all_data;
  Buffer.contents buf

let bech32_decode (s : string) : (bech32_encoding * string * int list) option =
  (* Find the separator '1' (last occurrence) *)
  let pos = match String.rindex_opt s '1' with
    | Some p -> p
    | None -> -1
  in
  if pos < 1 then None
  else begin
    let hrp = String.lowercase_ascii (String.sub s 0 pos) in
    let data_part = String.sub s (pos + 1) (String.length s - pos - 1) in
    if String.length data_part < 6 then None
    else begin
      (* Convert data part to 5-bit values *)
      let data_lower = String.lowercase_ascii data_part in
      let data = List.init (String.length data_lower) (fun i ->
        match String.index_opt bech32_charset data_lower.[i] with
        | Some d -> d
        | None -> -1
      ) in
      if List.exists (fun d -> d = -1) data then None
      else if bech32_verify_checksum Bech32 hrp data then
        Some (Bech32, hrp, List.filteri (fun i _ -> i < List.length data - 6) data)
      else if bech32_verify_checksum Bech32m hrp data then
        Some (Bech32m, hrp, List.filteri (fun i _ -> i < List.length data - 6) data)
      else None
    end
  end

(* Convert between 8-bit bytes and 5-bit groups for Bech32 *)
let convert_bits ~from_bits ~to_bits ~pad (data : int list) : int list option =
  let acc = ref 0 in
  let bits = ref 0 in
  let result = ref [] in
  let maxv = (1 lsl to_bits) - 1 in
  let max_acc = (1 lsl (from_bits + to_bits - 1)) - 1 in
  List.iter (fun v ->
    if v < 0 || (v lsr from_bits) <> 0 then
      ()  (* invalid value, will be handled *)
    else begin
      acc := ((!acc lsl from_bits) lor v) land max_acc;
      bits := !bits + from_bits;
      while !bits >= to_bits do
        bits := !bits - to_bits;
        result := ((!acc lsr !bits) land maxv) :: !result
      done
    end
  ) data;
  if pad then begin
    if !bits > 0 then
      result := ((!acc lsl (to_bits - !bits)) land maxv) :: !result;
    Some (List.rev !result)
  end else begin
    if !bits >= from_bits || ((!acc lsl (to_bits - !bits)) land maxv) <> 0 then
      None  (* Invalid padding *)
    else
      Some (List.rev !result)
  end

(* ========== High-level Address Functions ========== *)

let address_to_string (addr : address) : string =
  match addr.addr_type with
  | P2PKH ->
    let version = match addr.network with
      | `Mainnet -> 0x00
      | `Testnet | `Regtest -> 0x6F
    in
    let payload = Cstruct.create (1 + Cstruct.length addr.hash) in
    Cstruct.set_uint8 payload 0 version;
    Cstruct.blit addr.hash 0 payload 1 (Cstruct.length addr.hash);
    base58check_encode payload
  | P2SH ->
    let version = match addr.network with
      | `Mainnet -> 0x05
      | `Testnet | `Regtest -> 0xC4
    in
    let payload = Cstruct.create (1 + Cstruct.length addr.hash) in
    Cstruct.set_uint8 payload 0 version;
    Cstruct.blit addr.hash 0 payload 1 (Cstruct.length addr.hash);
    base58check_encode payload
  | P2WPKH | P2WSH ->
    let hrp = match addr.network with
      | `Mainnet -> "bc"
      | `Testnet -> "tb"
      | `Regtest -> "bcrt"
    in
    let witness_version = 0 in
    let data_8bit = List.init (Cstruct.length addr.hash) (fun i ->
      Cstruct.get_uint8 addr.hash i
    ) in
    (match convert_bits ~from_bits:8 ~to_bits:5 ~pad:true data_8bit with
     | Some data_5bit ->
       bech32_encode Bech32 hrp (witness_version :: data_5bit)
     | None -> failwith "convert_bits failed")
  | P2TR ->
    let hrp = match addr.network with
      | `Mainnet -> "bc"
      | `Testnet -> "tb"
      | `Regtest -> "bcrt"
    in
    let witness_version = 1 in
    let data_8bit = List.init (Cstruct.length addr.hash) (fun i ->
      Cstruct.get_uint8 addr.hash i
    ) in
    (match convert_bits ~from_bits:8 ~to_bits:5 ~pad:true data_8bit with
     | Some data_5bit ->
       bech32_encode Bech32m hrp (witness_version :: data_5bit)
     | None -> failwith "convert_bits failed")

let address_of_string (s : string) : (address, string) result =
  if String.length s = 0 then Error "Empty address"
  else match s.[0] with
  | '1' ->
    (* P2PKH mainnet *)
    (match base58check_decode s with
     | Ok payload when Cstruct.length payload = 21 && Cstruct.get_uint8 payload 0 = 0x00 ->
       Ok { addr_type = P2PKH; hash = Cstruct.sub payload 1 20; network = `Mainnet }
     | Ok _ -> Error "Invalid P2PKH payload"
     | Error e -> Error e)
  | '3' ->
    (* P2SH mainnet *)
    (match base58check_decode s with
     | Ok payload when Cstruct.length payload = 21 && Cstruct.get_uint8 payload 0 = 0x05 ->
       Ok { addr_type = P2SH; hash = Cstruct.sub payload 1 20; network = `Mainnet }
     | Ok _ -> Error "Invalid P2SH payload"
     | Error e -> Error e)
  | 'b' | 'B' ->
    (* Bech32/Bech32m mainnet or regtest *)
    (match bech32_decode s with
     | Some (enc, hrp, data) when List.length data > 0 ->
       let witness_version = List.hd data in
       let data_5bit = List.tl data in
       let network = match hrp with
         | "bc" -> `Mainnet
         | "bcrt" -> `Regtest
         | _ -> `Mainnet
       in
       (match convert_bits ~from_bits:5 ~to_bits:8 ~pad:false data_5bit with
        | Some data_8bit ->
          let hash = Cstruct.create (List.length data_8bit) in
          List.iteri (fun i b -> Cstruct.set_uint8 hash i b) data_8bit;
          let addr_type = match witness_version, Cstruct.length hash, enc with
            | 0, 20, Bech32 -> P2WPKH
            | 0, 32, Bech32 -> P2WSH
            | 1, 32, Bech32m -> P2TR
            | _ -> P2WPKH (* fallback *)
          in
          Ok { addr_type; hash; network }
        | None -> Error "convert_bits failed")
     | _ -> Error "Invalid bech32 address")
  | 't' | 'T' ->
    (* Bech32/Bech32m testnet *)
    (match bech32_decode s with
     | Some (enc, hrp, data) when List.length data > 0 && hrp = "tb" ->
       let witness_version = List.hd data in
       let data_5bit = List.tl data in
       (match convert_bits ~from_bits:5 ~to_bits:8 ~pad:false data_5bit with
        | Some data_8bit ->
          let hash = Cstruct.create (List.length data_8bit) in
          List.iteri (fun i b -> Cstruct.set_uint8 hash i b) data_8bit;
          let addr_type = match witness_version, Cstruct.length hash, enc with
            | 0, 20, Bech32 -> P2WPKH
            | 0, 32, Bech32 -> P2WSH
            | 1, 32, Bech32m -> P2TR
            | _ -> P2WPKH
          in
          Ok { addr_type; hash; network = `Testnet }
        | None -> Error "convert_bits failed")
     | _ -> Error "Invalid bech32 testnet address")
  | 'm' | 'n' ->
    (* P2PKH testnet *)
    (match base58check_decode s with
     | Ok payload when Cstruct.length payload = 21 && Cstruct.get_uint8 payload 0 = 0x6F ->
       Ok { addr_type = P2PKH; hash = Cstruct.sub payload 1 20; network = `Testnet }
     | Ok _ -> Error "Invalid testnet P2PKH payload"
     | Error e -> Error e)
  | '2' ->
    (* P2SH testnet *)
    (match base58check_decode s with
     | Ok payload when Cstruct.length payload = 21 && Cstruct.get_uint8 payload 0 = 0xC4 ->
       Ok { addr_type = P2SH; hash = Cstruct.sub payload 1 20; network = `Testnet }
     | Ok _ -> Error "Invalid testnet P2SH payload"
     | Error e -> Error e)
  | _ -> Error ("Unknown address format: " ^ s)

(* Create address from public key *)
let of_pubkey ?(network=`Mainnet) (addr_type : address_type) (pubkey : Cstruct.t) : address =
  match addr_type with
  | P2PKH | P2WPKH ->
    let hash = Crypto.hash160 pubkey in
    { addr_type; hash; network }
  | P2TR ->
    (* For Taproot, hash is the x-only public key (32 bytes) *)
    let hash = if Cstruct.length pubkey = 33 then
      Cstruct.sub pubkey 1 32
    else
      pubkey
    in
    { addr_type; hash; network }
  | P2SH | P2WSH -> failwith "Cannot create P2SH/P2WSH address from a single public key"

(* Create P2SH address from script hash *)
let of_script_hash ?(network=`Mainnet) (script_hash : Cstruct.t) : address =
  { addr_type = P2SH; hash = script_hash; network }

(* Create P2WSH address from witness script hash *)
let of_witness_script_hash ?(network=`Mainnet) (script_hash : Cstruct.t) : address =
  { addr_type = P2WSH; hash = script_hash; network }

(* ========== WIF (Wallet Import Format) ========== *)

let wif_encode ?(compressed=true) ?(network=`Mainnet) (privkey : Cstruct.t) : string =
  let prefix = match network with
    | `Mainnet -> 0x80
    | `Testnet | `Regtest -> 0xEF
  in
  let payload_len = 1 + 32 + (if compressed then 1 else 0) in
  let payload = Cstruct.create payload_len in
  Cstruct.set_uint8 payload 0 prefix;
  Cstruct.blit privkey 0 payload 1 32;
  if compressed then Cstruct.set_uint8 payload 33 0x01;
  base58check_encode payload

let wif_decode (s : string) : (Cstruct.t * bool * network, string) result =
  match base58check_decode s with
  | Error e -> Error e
  | Ok payload ->
    let len = Cstruct.length payload in
    if len < 33 then Error "WIF too short"
    else begin
      let version = Cstruct.get_uint8 payload 0 in
      let network : network = match version with
        | 0x80 -> `Mainnet
        | 0xEF -> `Testnet
        | _ -> `Mainnet
      in
      let compressed = len = 34 && Cstruct.get_uint8 payload 33 = 0x01 in
      let privkey = Cstruct.sub payload 1 32 in
      Ok (privkey, compressed, network)
    end

(* ========== Address Type Utilities ========== *)

let address_type_to_string = function
  | P2PKH -> "P2PKH"
  | P2SH -> "P2SH"
  | P2WPKH -> "P2WPKH"
  | P2WSH -> "P2WSH"
  | P2TR -> "P2TR"

let network_to_string = function
  | `Mainnet -> "mainnet"
  | `Testnet -> "testnet"
  | `Regtest -> "regtest"

let is_segwit addr =
  match addr.addr_type with
  | P2WPKH | P2WSH | P2TR -> true
  | P2PKH | P2SH -> false

let hash_length addr =
  Cstruct.length addr.hash
