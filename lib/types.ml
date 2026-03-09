(* Core Bitcoin types using OCaml's algebraic type system *)

let version = "0.1.0"
let protocol_version = 70016l

(* Hash types *)
type hash256 = Cstruct.t  (* 32 bytes, SHA-256d result *)
type hash160 = Cstruct.t  (* 20 bytes, RIPEMD160(SHA256(x)) result *)

let zero_hash : hash256 = Cstruct.create 32

let hash256_of_hex (s : string) : hash256 =
  let len = String.length s in
  if len <> 64 then failwith "hash256_of_hex: expected 64 hex chars";
  let buf = Cstruct.create 32 in
  for i = 0 to 31 do
    let byte = int_of_string ("0x" ^ String.sub s (i * 2) 2) in
    Cstruct.set_uint8 buf i byte
  done;
  buf

let hash256_to_hex (h : hash256) : string =
  let buf = Buffer.create 64 in
  for i = 0 to 31 do
    Buffer.add_string buf (Printf.sprintf "%02x" (Cstruct.get_uint8 h i))
  done;
  Buffer.contents buf

(* Bitcoin displays hashes in reverse byte order *)
let hash256_to_hex_display (h : hash256) : string =
  let buf = Buffer.create 64 in
  for i = 31 downto 0 do
    Buffer.add_string buf (Printf.sprintf "%02x" (Cstruct.get_uint8 h i))
  done;
  Buffer.contents buf

(* Transaction types *)
type outpoint = {
  txid : hash256;
  vout : int32;
}

type tx_in = {
  previous_output : outpoint;
  script_sig : Cstruct.t;
  sequence : int32;
}

type tx_out = {
  value : int64;  (* satoshis *)
  script_pubkey : Cstruct.t;
}

type tx_witness = {
  items : Cstruct.t list;
}

type transaction = {
  version : int32;
  inputs : tx_in list;
  outputs : tx_out list;
  witnesses : tx_witness list;  (* empty list if non-segwit *)
  locktime : int32;
}

(* Block types *)
type block_header = {
  version : int32;
  prev_block : hash256;
  merkle_root : hash256;
  timestamp : int32;
  bits : int32;  (* compact difficulty target *)
  nonce : int32;
}

type block = {
  header : block_header;
  transactions : transaction list;
}

(* Network types *)
type net_addr = {
  services : int64;
  addr : Cstruct.t;  (* 16 bytes, IPv6-mapped IPv4 *)
  port : int;
}

type version_msg = {
  protocol_version : int32;
  services : int64;
  timestamp : int64;
  addr_recv : net_addr;
  addr_from : net_addr;
  nonce : int64;
  user_agent : string;
  start_height : int32;
  relay : bool;
}
