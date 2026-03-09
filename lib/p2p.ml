(* Bitcoin P2P network protocol message serialization *)

(* Bitcoin P2P message header: 24 bytes
   - 4 bytes: network magic
   - 12 bytes: command name (null-padded ASCII)
   - 4 bytes: payload length (LE uint32)
   - 4 bytes: checksum (first 4 bytes of SHA256d of payload) *)

let message_header_size = 24
let max_message_size = 32 * 1024 * 1024  (* 32 MB max message *)
let max_inv_count = 50_000
let max_headers_count = 2000
let max_addr_count = 1000

(* Network magic bytes for different networks *)
let mainnet_magic = 0xD9B4BEF9l
let testnet_magic = 0x0709110Bl
let regtest_magic = 0xDAB5BFFAl
let signet_magic = 0x40CF030Al

type command =
  | Version
  | Verack
  | Ping
  | Pong
  | Getaddr
  | Addr
  | Inv
  | Getdata
  | Notfound
  | Getblocks
  | Getheaders
  | Headers
  | Block
  | Tx
  | Mempool
  | Reject
  | Sendheaders
  | Sendcmpct
  | Feefilter
  | Getblocktxn
  | Blocktxn
  | Wtxidrelay
  | Sendaddrv2
  | Alert
  | Unknown of string

let command_to_string = function
  | Version -> "version"
  | Verack -> "verack"
  | Ping -> "ping"
  | Pong -> "pong"
  | Getaddr -> "getaddr"
  | Addr -> "addr"
  | Inv -> "inv"
  | Getdata -> "getdata"
  | Notfound -> "notfound"
  | Getblocks -> "getblocks"
  | Getheaders -> "getheaders"
  | Headers -> "headers"
  | Block -> "block"
  | Tx -> "tx"
  | Mempool -> "mempool"
  | Reject -> "reject"
  | Sendheaders -> "sendheaders"
  | Sendcmpct -> "sendcmpct"
  | Feefilter -> "feefilter"
  | Getblocktxn -> "getblocktxn"
  | Blocktxn -> "blocktxn"
  | Wtxidrelay -> "wtxidrelay"
  | Sendaddrv2 -> "sendaddrv2"
  | Alert -> "alert"
  | Unknown s -> s

let command_of_string s =
  match String.lowercase_ascii (String.trim s) with
  | "version" -> Version
  | "verack" -> Verack
  | "ping" -> Ping
  | "pong" -> Pong
  | "getaddr" -> Getaddr
  | "addr" -> Addr
  | "inv" -> Inv
  | "getdata" -> Getdata
  | "notfound" -> Notfound
  | "getblocks" -> Getblocks
  | "getheaders" -> Getheaders
  | "headers" -> Headers
  | "block" -> Block
  | "tx" -> Tx
  | "mempool" -> Mempool
  | "reject" -> Reject
  | "sendheaders" -> Sendheaders
  | "sendcmpct" -> Sendcmpct
  | "feefilter" -> Feefilter
  | "getblocktxn" -> Getblocktxn
  | "blocktxn" -> Blocktxn
  | "wtxidrelay" -> Wtxidrelay
  | "sendaddrv2" -> Sendaddrv2
  | "alert" -> Alert
  | other -> Unknown other

(* Inventory vector types *)
type inv_type =
  | InvError           (* 0 *)
  | InvTx              (* 1 *)
  | InvBlock           (* 2 *)
  | InvFilteredBlock   (* 3 *)
  | InvCompactBlock    (* 4 *)
  | InvWitnessTx       (* 0x40000001 *)
  | InvWitnessBlock    (* 0x40000002 *)
  | InvUnknown of int32

let inv_type_to_int32 = function
  | InvError -> 0l
  | InvTx -> 1l
  | InvBlock -> 2l
  | InvFilteredBlock -> 3l
  | InvCompactBlock -> 4l
  | InvWitnessTx -> 0x40000001l
  | InvWitnessBlock -> 0x40000002l
  | InvUnknown n -> n

let inv_type_of_int32 = function
  | 0l -> InvError
  | 1l -> InvTx
  | 2l -> InvBlock
  | 3l -> InvFilteredBlock
  | 4l -> InvCompactBlock
  | n when n = 0x40000001l -> InvWitnessTx
  | n when n = 0x40000002l -> InvWitnessBlock
  | n -> InvUnknown n

type inv_vector = {
  inv_type : inv_type;
  hash : Types.hash256;
}

(* Reject message codes *)
type reject_code =
  | RejectMalformed       (* 0x01 *)
  | RejectInvalid         (* 0x10 *)
  | RejectObsolete        (* 0x11 *)
  | RejectDuplicate       (* 0x12 *)
  | RejectNonstandard     (* 0x40 *)
  | RejectDust            (* 0x41 *)
  | RejectInsufficientFee (* 0x42 *)
  | RejectCheckpoint      (* 0x43 *)
  | RejectUnknown of int

let reject_code_to_int = function
  | RejectMalformed -> 0x01
  | RejectInvalid -> 0x10
  | RejectObsolete -> 0x11
  | RejectDuplicate -> 0x12
  | RejectNonstandard -> 0x40
  | RejectDust -> 0x41
  | RejectInsufficientFee -> 0x42
  | RejectCheckpoint -> 0x43
  | RejectUnknown n -> n

let reject_code_of_int = function
  | 0x01 -> RejectMalformed
  | 0x10 -> RejectInvalid
  | 0x11 -> RejectObsolete
  | 0x12 -> RejectDuplicate
  | 0x40 -> RejectNonstandard
  | 0x41 -> RejectDust
  | 0x42 -> RejectInsufficientFee
  | 0x43 -> RejectCheckpoint
  | n -> RejectUnknown n

(* Message payload types *)
type message_payload =
  | VersionMsg of Types.version_msg
  | VerackMsg
  | PingMsg of int64
  | PongMsg of int64
  | GetaddrMsg
  | AddrMsg of (int32 * Types.net_addr) list
  | InvMsg of inv_vector list
  | GetdataMsg of inv_vector list
  | NotfoundMsg of inv_vector list
  | GetblocksMsg of {
      version : int32;
      locator_hashes : Types.hash256 list;
      hash_stop : Types.hash256;
    }
  | GetheadersMsg of {
      version : int32;
      locator_hashes : Types.hash256 list;
      hash_stop : Types.hash256;
    }
  | HeadersMsg of Types.block_header list
  | BlockMsg of Types.block
  | TxMsg of Types.transaction
  | MempoolMsg
  | RejectMsg of {
      message : string;
      ccode : int;
      reason : string;
      data : Cstruct.t;
    }
  | SendheadersMsg
  | SendcmpctMsg of { announce : bool; version : int64 }
  | FeefilterMsg of int64
  | WtxidrelayMsg
  | SendaddrV2Msg
  | UnknownMsg of { cmd : string; payload : Cstruct.t }

type message = {
  magic : int32;
  command : command;
  payload : message_payload;
}

(* Message header serialization *)
let serialize_message_header w (magic : int32) (cmd : command)
    (payload : Cstruct.t) =
  Serialize.write_int32_le w magic;
  let cmd_str = command_to_string cmd in
  let cmd_bytes = Cstruct.create 12 in
  Cstruct.blit_from_string cmd_str 0 cmd_bytes 0
    (min (String.length cmd_str) 12);
  Serialize.write_bytes w cmd_bytes;
  Serialize.write_int32_le w
    (Int32.of_int (Cstruct.length payload));
  let checksum = Cstruct.sub (Crypto.sha256d payload) 0 4 in
  Serialize.write_bytes w checksum

let deserialize_message_header r =
  let magic = Serialize.read_int32_le r in
  let cmd_bytes = Serialize.read_bytes r 12 in
  let cmd_str =
    let s = Cstruct.to_string cmd_bytes in
    let null_pos = match String.index_opt s '\x00' with
      | Some p -> p | None -> 12
    in
    String.sub s 0 null_pos
  in
  let cmd = command_of_string cmd_str in
  let length = Int32.to_int (Serialize.read_int32_le r) in
  let checksum = Serialize.read_bytes r 4 in
  (magic, cmd, length, checksum)

(* Inventory vector serialization *)
let serialize_inv_vector w (iv : inv_vector) =
  Serialize.write_int32_le w (inv_type_to_int32 iv.inv_type);
  Serialize.write_bytes w iv.hash

let deserialize_inv_vector r : inv_vector =
  let inv_type = inv_type_of_int32 (Serialize.read_int32_le r) in
  let hash = Serialize.read_bytes r 32 in
  { inv_type; hash }

let serialize_inv_list w ivs =
  Serialize.write_compact_size w (List.length ivs);
  List.iter (serialize_inv_vector w) ivs

let deserialize_inv_list r =
  let count = Serialize.read_compact_size r in
  if count > max_inv_count then
    failwith "inv count exceeds maximum";
  List.init count (fun _ -> deserialize_inv_vector r)

(* Getblocks/getheaders serialization *)
let serialize_getblocks w ~version ~locator_hashes ~hash_stop =
  Serialize.write_int32_le w version;
  Serialize.write_compact_size w
    (List.length locator_hashes);
  List.iter (Serialize.write_bytes w) locator_hashes;
  Serialize.write_bytes w hash_stop

let deserialize_getblocks r =
  let version = Serialize.read_int32_le r in
  let count = Serialize.read_compact_size r in
  let locator_hashes = List.init count
    (fun _ -> Serialize.read_bytes r 32) in
  let hash_stop = Serialize.read_bytes r 32 in
  (version, locator_hashes, hash_stop)

(* Headers message serialization *)
let serialize_headers_msg w (headers : Types.block_header list) =
  Serialize.write_compact_size w (List.length headers);
  List.iter (fun h ->
    Serialize.serialize_block_header w h;
    Serialize.write_compact_size w 0  (* tx_count always 0 *)
  ) headers

let deserialize_headers_msg r : Types.block_header list =
  let count = Serialize.read_compact_size r in
  if count > max_headers_count then
    failwith "headers count exceeds maximum";
  List.init count (fun _ ->
    let header = Serialize.deserialize_block_header r in
    let _tx_count = Serialize.read_compact_size r in
    header
  )

(* Unified payload serialization *)
let serialize_payload w = function
  | VersionMsg v -> Serialize.serialize_version_msg w v
  | VerackMsg -> ()
  | PingMsg nonce -> Serialize.write_int64_le w nonce
  | PongMsg nonce -> Serialize.write_int64_le w nonce
  | GetaddrMsg -> ()
  | AddrMsg addrs ->
    if List.length addrs > max_addr_count then
      failwith "addr count exceeds maximum";
    Serialize.write_compact_size w (List.length addrs);
    List.iter (fun (ts, addr) ->
      Serialize.write_int32_le w ts;
      Serialize.serialize_net_addr w addr
    ) addrs
  | InvMsg ivs -> serialize_inv_list w ivs
  | GetdataMsg ivs -> serialize_inv_list w ivs
  | NotfoundMsg ivs -> serialize_inv_list w ivs
  | GetblocksMsg { version; locator_hashes; hash_stop } ->
    serialize_getblocks w ~version ~locator_hashes ~hash_stop
  | GetheadersMsg { version; locator_hashes; hash_stop } ->
    serialize_getblocks w ~version ~locator_hashes ~hash_stop
  | HeadersMsg headers -> serialize_headers_msg w headers
  | BlockMsg block -> Serialize.serialize_block w block
  | TxMsg tx -> Serialize.serialize_transaction w tx
  | MempoolMsg -> ()
  | SendheadersMsg -> ()
  | SendcmpctMsg { announce; version } ->
    Serialize.write_uint8 w (if announce then 1 else 0);
    Serialize.write_int64_le w version
  | FeefilterMsg feerate ->
    Serialize.write_int64_le w feerate
  | WtxidrelayMsg -> ()
  | SendaddrV2Msg -> ()
  | RejectMsg { message; ccode; reason; data } ->
    Serialize.write_string w message;
    Serialize.write_uint8 w ccode;
    Serialize.write_string w reason;
    Serialize.write_bytes w data
  | UnknownMsg { payload; _ } ->
    Serialize.write_bytes w payload

let payload_to_command = function
  | VersionMsg _ -> Version
  | VerackMsg -> Verack
  | PingMsg _ -> Ping
  | PongMsg _ -> Pong
  | GetaddrMsg -> Getaddr
  | AddrMsg _ -> Addr
  | InvMsg _ -> Inv
  | GetdataMsg _ -> Getdata
  | NotfoundMsg _ -> Notfound
  | GetblocksMsg _ -> Getblocks
  | GetheadersMsg _ -> Getheaders
  | HeadersMsg _ -> Headers
  | BlockMsg _ -> Block
  | TxMsg _ -> Tx
  | MempoolMsg -> Mempool
  | RejectMsg _ -> Reject
  | SendheadersMsg -> Sendheaders
  | SendcmpctMsg _ -> Sendcmpct
  | FeefilterMsg _ -> Feefilter
  | WtxidrelayMsg -> Wtxidrelay
  | SendaddrV2Msg -> Sendaddrv2
  | UnknownMsg { cmd; _ } -> Unknown cmd

let serialize_message (magic : int32) (payload : message_payload)
    : Cstruct.t =
  let cmd = payload_to_command payload in
  let pw = Serialize.writer_create () in
  serialize_payload pw payload;
  let payload_bytes = Serialize.writer_to_cstruct pw in
  if Cstruct.length payload_bytes > max_message_size then
    failwith "message exceeds maximum size";
  let hw = Serialize.writer_create () in
  serialize_message_header hw magic cmd payload_bytes;
  Cstruct.concat [Serialize.writer_to_cstruct hw; payload_bytes]

(* Unified payload deserialization *)
let deserialize_payload (cmd : command) (r : Serialize.reader)
    : message_payload =
  match cmd with
  | Version -> VersionMsg (Serialize.deserialize_version_msg r)
  | Verack -> VerackMsg
  | Ping -> PingMsg (Serialize.read_int64_le r)
  | Pong -> PongMsg (Serialize.read_int64_le r)
  | Getaddr -> GetaddrMsg
  | Addr ->
    let count = Serialize.read_compact_size r in
    if count > max_addr_count then
      failwith "addr count exceeds maximum";
    let addrs = List.init count (fun _ ->
      let ts = Serialize.read_int32_le r in
      let addr = Serialize.deserialize_net_addr r in
      (ts, addr)
    ) in
    AddrMsg addrs
  | Inv -> InvMsg (deserialize_inv_list r)
  | Getdata -> GetdataMsg (deserialize_inv_list r)
  | Notfound -> NotfoundMsg (deserialize_inv_list r)
  | Getblocks ->
    let (version, locator_hashes, hash_stop) =
      deserialize_getblocks r in
    GetblocksMsg { version; locator_hashes; hash_stop }
  | Getheaders ->
    let (version, locator_hashes, hash_stop) =
      deserialize_getblocks r in
    GetheadersMsg { version; locator_hashes; hash_stop }
  | Headers -> HeadersMsg (deserialize_headers_msg r)
  | Block -> BlockMsg (Serialize.deserialize_block r)
  | Tx -> TxMsg (Serialize.deserialize_transaction r)
  | Mempool -> MempoolMsg
  | Sendheaders -> SendheadersMsg
  | Sendcmpct ->
    let announce = Serialize.read_uint8 r <> 0 in
    let version = Serialize.read_int64_le r in
    SendcmpctMsg { announce; version }
  | Feefilter -> FeefilterMsg (Serialize.read_int64_le r)
  | Wtxidrelay -> WtxidrelayMsg
  | Sendaddrv2 -> SendaddrV2Msg
  | Reject ->
    let message = Serialize.read_string r in
    let ccode = Serialize.read_uint8 r in
    let reason = Serialize.read_string r in
    let remaining = Cstruct.length r.buf - r.pos in
    let data = if remaining > 0 then
      Serialize.read_bytes r remaining
    else
      Cstruct.empty
    in
    RejectMsg { message; ccode; reason; data }
  | Alert | Getblocktxn | Blocktxn | Unknown _ ->
    let remaining = Cstruct.length r.buf - r.pos in
    let payload = if remaining > 0 then
      Serialize.read_bytes r remaining
    else
      Cstruct.empty
    in
    UnknownMsg { cmd = command_to_string cmd; payload }

let deserialize_message cs : message =
  let r = Serialize.reader_of_cstruct cs in
  let (magic, cmd, length, expected_checksum) =
    deserialize_message_header r in
  if length > max_message_size then
    failwith "message exceeds maximum size";
  let payload_bytes = Serialize.read_bytes r length in
  let actual_checksum = Cstruct.sub (Crypto.sha256d payload_bytes) 0 4 in
  if not (Cstruct.equal expected_checksum actual_checksum) then
    failwith "checksum mismatch";
  let pr = Serialize.reader_of_cstruct payload_bytes in
  let payload = deserialize_payload cmd pr in
  { magic; command = cmd; payload }

(* Helper to create common messages *)
let make_version_msg
    ~protocol_version ~services ~timestamp
    ~addr_recv ~addr_from ~nonce ~user_agent
    ~start_height ~relay : message_payload =
  VersionMsg {
    protocol_version; services; timestamp;
    addr_recv; addr_from; nonce; user_agent;
    start_height; relay
  }

let make_ping_msg nonce : message_payload =
  PingMsg nonce

let make_pong_msg nonce : message_payload =
  PongMsg nonce

let make_getblocks_msg ~version ~locator_hashes ~hash_stop : message_payload =
  GetblocksMsg { version; locator_hashes; hash_stop }

let make_getheaders_msg ~version ~locator_hashes ~hash_stop : message_payload =
  GetheadersMsg { version; locator_hashes; hash_stop }

let make_inv_msg items : message_payload =
  InvMsg items

let make_getdata_msg items : message_payload =
  GetdataMsg items

let make_headers_msg headers : message_payload =
  HeadersMsg headers

let make_block_msg block : message_payload =
  BlockMsg block

let make_tx_msg tx : message_payload =
  TxMsg tx

(* Create an empty network address (for localhost/unknown) *)
let empty_net_addr () : Types.net_addr =
  { services = 0L;
    addr = Cstruct.create 16;
    port = 0 }

(* Create IPv4-mapped IPv6 address *)
let ipv4_to_net_addr ?(services=0L) ipv4_bytes port : Types.net_addr =
  let addr = Cstruct.create 16 in
  (* IPv4-mapped: 10 zeros, 2 0xFF bytes, 4 IPv4 bytes *)
  Cstruct.set_uint8 addr 10 0xFF;
  Cstruct.set_uint8 addr 11 0xFF;
  Cstruct.blit ipv4_bytes 0 addr 12 4;
  { services; addr; port }
