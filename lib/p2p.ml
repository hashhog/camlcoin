(* Bitcoin P2P network protocol message serialization *)

(* Bitcoin P2P message header: 24 bytes
   - 4 bytes: network magic
   - 12 bytes: command name (null-padded ASCII)
   - 4 bytes: payload length (LE uint32)
   - 4 bytes: checksum (first 4 bytes of SHA256d of payload) *)

let message_header_size = 24
let max_message_size = 4 * 1000 * 1000  (* 4 MB max message, matches Bitcoin Core MAX_PROTOCOL_MESSAGE_LENGTH *)
let max_inv_count = 50_000
let max_headers_count = 2000
let max_addr_count = 1000

(* Network magic bytes for different networks *)
let mainnet_magic = 0xD9B4BEF9l
let testnet_magic = 0x1C163F28l
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
  | Cmpctblock
  | Feefilter
  | Getblocktxn
  | Blocktxn
  | Wtxidrelay
  | Sendaddrv2
  | Addrv2
  | Alert
  (* BIP 331: Package Relay *)
  | Sendpackages
  | Getpkgtxns
  | Pkgtxns
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
  | Cmpctblock -> "cmpctblock"
  | Feefilter -> "feefilter"
  | Getblocktxn -> "getblocktxn"
  | Blocktxn -> "blocktxn"
  | Wtxidrelay -> "wtxidrelay"
  | Sendaddrv2 -> "sendaddrv2"
  | Addrv2 -> "addrv2"
  | Alert -> "alert"
  | Sendpackages -> "sendpackages"
  | Getpkgtxns -> "getpkgtxns"
  | Pkgtxns -> "pkgtxns"
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
  | "cmpctblock" -> Cmpctblock
  | "feefilter" -> Feefilter
  | "getblocktxn" -> Getblocktxn
  | "blocktxn" -> Blocktxn
  | "wtxidrelay" -> Wtxidrelay
  | "sendaddrv2" -> Sendaddrv2
  | "addrv2" -> Addrv2
  | "alert" -> Alert
  | "sendpackages" -> Sendpackages
  | "getpkgtxns" -> Getpkgtxns
  | "pkgtxns" -> Pkgtxns
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

(* Compact block prefilled transaction (BIP 152) *)
type prefilled_tx = {
  index : int;        (* differential index from last prefilled tx *)
  tx : Types.transaction;
}

(* Compact block structure (BIP 152) *)
type compact_block = {
  header : Types.block_header;
  nonce : int64;
  short_ids : int64 list;      (* 6-byte short IDs stored as int64 *)
  prefilled_txs : prefilled_tx list;
}

(* Block transactions request (BIP 152) *)
type block_txns_request = {
  block_hash : Types.hash256;
  indexes : int list;          (* differential encoded indexes *)
}

(* Block transactions response (BIP 152) *)
type block_txns = {
  block_hash : Types.hash256;
  txs : Types.transaction list;
}

(* BIP 331: Package Relay Types *)

(* Package relay version *)
let package_relay_version = 1L

(* sendpackages message: announce package relay support *)
type sendpackages_msg = {
  pkg_version : int64;       (* package relay protocol version *)
  pkg_max_count : int32;     (* max transactions in a package *)
  pkg_max_weight : int32;    (* max package weight *)
}

(* getpkgtxns: request transactions for a package by wtxids *)
type getpkgtxns_msg = {
  pkg_wtxids : Types.hash256 list;  (* wtxids of requested transactions *)
}

(* pkgtxns: response with package transactions *)
type pkgtxns_msg = {
  pkg_txs : Types.transaction list;  (* transactions in topological order *)
}

(* BIP-155 addrv2 network IDs *)
type addrv2_network_id =
  | Addrv2_IPv4    (* 1: 4 bytes *)
  | Addrv2_IPv6    (* 2: 16 bytes *)
  | Addrv2_TorV2   (* 3: 10 bytes (deprecated) *)
  | Addrv2_TorV3   (* 4: 32 bytes *)
  | Addrv2_I2P     (* 5: 32 bytes *)
  | Addrv2_CJDNS   (* 6: 16 bytes *)
  | Addrv2_Unknown of int

type addrv2_addr = {
  v2_time : int32;
  v2_services : int64;
  v2_network_id : addrv2_network_id;
  v2_addr : Cstruct.t;
  v2_port : int;
}

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
  | CmpctblockMsg of compact_block
  | GetblocktxnMsg of block_txns_request
  | BlocktxnMsg of block_txns
  | FeefilterMsg of int64
  | WtxidrelayMsg
  | SendaddrV2Msg
  | Addrv2Msg of addrv2_addr list
  (* BIP 331: Package Relay *)
  | SendpackagesMsg of sendpackages_msg
  | GetpkgtxnsMsg of getpkgtxns_msg
  | PkgtxnsMsg of pkgtxns_msg
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

(* BIP 152: Compact block constants *)
let cmpctblock_version = 2L  (* Version 2 is witness-aware *)
let max_compact_block_txs = 100_000

(* Write a 6-byte short ID (lower 48 bits of int64) in little-endian *)
let write_short_id w (id : int64) =
  for i = 0 to 5 do
    let byte = Int64.to_int (Int64.logand (Int64.shift_right_logical id (i * 8)) 0xFFL) in
    Serialize.write_uint8 w byte
  done

(* Read a 6-byte short ID as int64 in little-endian *)
let read_short_id r : int64 =
  let result = ref 0L in
  for i = 0 to 5 do
    let byte = Int64.of_int (Serialize.read_uint8 r) in
    result := Int64.logor !result (Int64.shift_left byte (i * 8))
  done;
  !result

(* Serialize prefilled transaction: differential index + transaction *)
let serialize_prefilled_tx w (ptx : prefilled_tx) =
  Serialize.write_compact_size w ptx.index;
  Serialize.serialize_transaction w ptx.tx

(* Deserialize prefilled transaction *)
let deserialize_prefilled_tx r : prefilled_tx =
  let index = Serialize.read_compact_size r in
  let tx = Serialize.deserialize_transaction r in
  { index; tx }

(* Serialize compact block (BIP 152) *)
let serialize_compact_block w (cb : compact_block) =
  Serialize.serialize_block_header w cb.header;
  Serialize.write_int64_le w cb.nonce;
  (* Short IDs *)
  Serialize.write_compact_size w (List.length cb.short_ids);
  List.iter (write_short_id w) cb.short_ids;
  (* Prefilled transactions *)
  Serialize.write_compact_size w (List.length cb.prefilled_txs);
  List.iter (serialize_prefilled_tx w) cb.prefilled_txs

(* Deserialize compact block (BIP 152) *)
let deserialize_compact_block r : compact_block =
  let header = Serialize.deserialize_block_header r in
  let nonce = Serialize.read_int64_le r in
  (* Short IDs *)
  let short_id_count = Serialize.read_compact_size r in
  if short_id_count > max_compact_block_txs then
    failwith "compact block short ID count exceeds maximum";
  let short_ids = List.init short_id_count (fun _ -> read_short_id r) in
  (* Prefilled transactions *)
  let prefilled_count = Serialize.read_compact_size r in
  if prefilled_count > max_compact_block_txs then
    failwith "compact block prefilled count exceeds maximum";
  let prefilled_txs = List.init prefilled_count (fun _ -> deserialize_prefilled_tx r) in
  { header; nonce; short_ids; prefilled_txs }

(* Serialize block transactions request (getblocktxn) *)
let serialize_block_txns_request w (req : block_txns_request) =
  Serialize.write_bytes w req.block_hash;
  Serialize.write_compact_size w (List.length req.indexes);
  List.iter (fun idx -> Serialize.write_compact_size w idx) req.indexes

(* Deserialize block transactions request (getblocktxn) *)
let deserialize_block_txns_request r : block_txns_request =
  let block_hash = Serialize.read_bytes r 32 in
  let count = Serialize.read_compact_size r in
  if count > max_compact_block_txs then
    failwith "block txns request count exceeds maximum";
  let indexes = List.init count (fun _ -> Serialize.read_compact_size r) in
  { block_hash; indexes }

(* Serialize block transactions response (blocktxn) *)
let serialize_block_txns w (resp : block_txns) =
  Serialize.write_bytes w resp.block_hash;
  Serialize.write_compact_size w (List.length resp.txs);
  List.iter (Serialize.serialize_transaction w) resp.txs

(* Deserialize block transactions response (blocktxn) *)
let deserialize_block_txns r : block_txns =
  let block_hash = Serialize.read_bytes r 32 in
  let count = Serialize.read_compact_size r in
  if count > max_compact_block_txs then
    failwith "block txns response count exceeds maximum";
  let txs = List.init count (fun _ -> Serialize.deserialize_transaction r) in
  { block_hash; txs }

(* ============================================================================
   BIP 331: Package Relay Serialization
   ============================================================================ *)

let max_package_txs = 25  (* Maximum transactions in a package *)

(* Serialize sendpackages message *)
let serialize_sendpackages w (msg : sendpackages_msg) =
  Serialize.write_int64_le w msg.pkg_version;
  Serialize.write_int32_le w msg.pkg_max_count;
  Serialize.write_int32_le w msg.pkg_max_weight

(* Deserialize sendpackages message *)
let deserialize_sendpackages r : sendpackages_msg =
  let pkg_version = Serialize.read_int64_le r in
  let pkg_max_count = Serialize.read_int32_le r in
  let pkg_max_weight = Serialize.read_int32_le r in
  { pkg_version; pkg_max_count; pkg_max_weight }

(* Serialize getpkgtxns message *)
let serialize_getpkgtxns w (msg : getpkgtxns_msg) =
  Serialize.write_compact_size w (List.length msg.pkg_wtxids);
  List.iter (Serialize.write_bytes w) msg.pkg_wtxids

(* Deserialize getpkgtxns message *)
let deserialize_getpkgtxns r : getpkgtxns_msg =
  let count = Serialize.read_compact_size r in
  if count > max_package_txs then
    failwith "package wtxid count exceeds maximum";
  let pkg_wtxids = List.init count (fun _ -> Serialize.read_bytes r 32) in
  { pkg_wtxids }

(* Serialize pkgtxns message *)
let serialize_pkgtxns w (msg : pkgtxns_msg) =
  Serialize.write_compact_size w (List.length msg.pkg_txs);
  List.iter (Serialize.serialize_transaction w) msg.pkg_txs

(* Deserialize pkgtxns message *)
let deserialize_pkgtxns r : pkgtxns_msg =
  let count = Serialize.read_compact_size r in
  if count > max_package_txs then
    failwith "package transaction count exceeds maximum";
  let pkg_txs = List.init count (fun _ -> Serialize.deserialize_transaction r) in
  { pkg_txs }

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
  | CmpctblockMsg cb -> serialize_compact_block w cb
  | GetblocktxnMsg req -> serialize_block_txns_request w req
  | BlocktxnMsg resp -> serialize_block_txns w resp
  | FeefilterMsg feerate ->
    Serialize.write_int64_le w feerate
  | WtxidrelayMsg -> ()
  | SendaddrV2Msg -> ()
  | Addrv2Msg addrs ->
    Serialize.write_compact_size w (List.length addrs);
    List.iter (fun a ->
      Serialize.write_int32_le w a.v2_time;
      Serialize.write_compact_size_int64 w a.v2_services;
      let net_id = match a.v2_network_id with
        | Addrv2_IPv4 -> 1 | Addrv2_IPv6 -> 2 | Addrv2_TorV2 -> 3
        | Addrv2_TorV3 -> 4 | Addrv2_I2P -> 5 | Addrv2_CJDNS -> 6
        | Addrv2_Unknown n -> n in
      Serialize.write_uint8 w net_id;
      Serialize.write_compact_size w (Cstruct.length a.v2_addr);
      Serialize.write_bytes w a.v2_addr;
      Serialize.write_uint16_be w a.v2_port
    ) addrs
  | SendpackagesMsg msg -> serialize_sendpackages w msg
  | GetpkgtxnsMsg msg -> serialize_getpkgtxns w msg
  | PkgtxnsMsg msg -> serialize_pkgtxns w msg
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
  | CmpctblockMsg _ -> Cmpctblock
  | GetblocktxnMsg _ -> Getblocktxn
  | BlocktxnMsg _ -> Blocktxn
  | FeefilterMsg _ -> Feefilter
  | WtxidrelayMsg -> Wtxidrelay
  | SendaddrV2Msg -> Sendaddrv2
  | Addrv2Msg _ -> Addrv2
  | SendpackagesMsg _ -> Sendpackages
  | GetpkgtxnsMsg _ -> Getpkgtxns
  | PkgtxnsMsg _ -> Pkgtxns
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
  | Cmpctblock -> CmpctblockMsg (deserialize_compact_block r)
  | Getblocktxn -> GetblocktxnMsg (deserialize_block_txns_request r)
  | Blocktxn -> BlocktxnMsg (deserialize_block_txns r)
  | Feefilter -> FeefilterMsg (Serialize.read_int64_le r)
  | Wtxidrelay -> WtxidrelayMsg
  | Sendaddrv2 -> SendaddrV2Msg
  | Addrv2 ->
    let count = Serialize.read_compact_size r in
    if count > max_addr_count then failwith "addrv2 count exceeds maximum";
    let addrs = List.init count (fun _ ->
      let v2_time = Serialize.read_int32_le r in
      let v2_services = Serialize.read_compact_size_int64 r in
      let net_byte = Serialize.read_uint8 r in
      let v2_network_id = match net_byte with
        | 1 -> Addrv2_IPv4 | 2 -> Addrv2_IPv6 | 3 -> Addrv2_TorV2
        | 4 -> Addrv2_TorV3 | 5 -> Addrv2_I2P | 6 -> Addrv2_CJDNS
        | n -> Addrv2_Unknown n in
      let addr_len = Serialize.read_compact_size r in
      let expected_len = match v2_network_id with
        | Addrv2_IPv4 -> 4 | Addrv2_IPv6 -> 16 | Addrv2_TorV2 -> 10
        | Addrv2_TorV3 -> 32 | Addrv2_I2P -> 32 | Addrv2_CJDNS -> 16
        | Addrv2_Unknown _ -> addr_len in
      if addr_len <> expected_len then
        failwith (Printf.sprintf "addrv2: wrong addr length %d for network %d" addr_len net_byte);
      let v2_addr = Serialize.read_bytes r addr_len in
      let v2_port = Serialize.read_uint16_be r in
      { v2_time; v2_services; v2_network_id; v2_addr; v2_port }
    ) in
    Addrv2Msg addrs
  | Sendpackages -> SendpackagesMsg (deserialize_sendpackages r)
  | Getpkgtxns -> GetpkgtxnsMsg (deserialize_getpkgtxns r)
  | Pkgtxns -> PkgtxnsMsg (deserialize_pkgtxns r)
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
  | Alert | Unknown _ ->
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

(* ============================================================================
   BIP 152 Compact Block Functions
   ============================================================================ *)

(* Generate a random nonce for compact block *)
let generate_compact_nonce () : int64 =
  Random.int64 Int64.max_int

(* Create a compact block from a full block.
   Always includes coinbase (index 0) as prefilled.
   Uses wtxid for all transactions except coinbase. *)
let create_compact_block (block : Types.block) : compact_block =
  let header = block.header in
  let nonce = generate_compact_nonce () in
  let header_hash = Crypto.compute_block_hash header in
  let (k0, k1) = Crypto.SipHash.derive_keys header_hash nonce in

  (* Coinbase is always prefilled at index 0 *)
  let coinbase = List.hd block.transactions in
  let prefilled_txs = [{ index = 0; tx = coinbase }] in

  (* Compute short IDs for remaining transactions using wtxids *)
  let short_ids =
    List.mapi (fun i tx ->
      if i = 0 then None  (* coinbase is prefilled *)
      else
        let wtxid = Crypto.compute_wtxid tx in
        Some (Crypto.compute_short_txid k0 k1 wtxid)
    ) block.transactions
    |> List.filter_map (fun x -> x)
  in

  { header; nonce; short_ids; prefilled_txs }

(* Compute the total transaction count from a compact block *)
let compact_block_tx_count (cb : compact_block) : int =
  (* Total = short_ids count + prefilled_txs count *)
  List.length cb.short_ids + List.length cb.prefilled_txs

(* Result type for block reconstruction *)
type reconstruct_status =
  | ReconstructComplete of Types.block
  | ReconstructNeedTxs of int list  (* missing transaction indices *)
  | ReconstructFailed of string

(* Build a lookup table mapping wtxid to transaction *)
type tx_lookup = {
  by_short_id : (int64, Types.transaction) Hashtbl.t;
}

(* Create a transaction lookup from a list of transactions and SipHash keys *)
let create_tx_lookup ~k0 ~k1 (txs : Types.transaction list) : tx_lookup =
  let tbl = Hashtbl.create (List.length txs) in
  List.iter (fun tx ->
    let wtxid = Crypto.compute_wtxid tx in
    let short_id = Crypto.compute_short_txid k0 k1 wtxid in
    Hashtbl.replace tbl short_id tx
  ) txs;
  { by_short_id = tbl }

(* Attempt to reconstruct a block from a compact block and available transactions.
   Returns ReconstructComplete if all transactions found,
   ReconstructNeedTxs with list of missing indices,
   ReconstructFailed on error. *)
let reconstruct_block (cb : compact_block) (lookup : tx_lookup)
    : reconstruct_status =
  (* Total number of transactions *)
  let tx_count = List.length cb.short_ids + List.length cb.prefilled_txs in
  if tx_count = 0 then
    ReconstructFailed "compact block has no transactions"
  else begin
    (* Build transaction array - initially None *)
    let txs = Array.make tx_count None in
    let missing = ref [] in

    (* Fill in prefilled transactions *)
    let last_idx = ref (-1) in
    List.iter (fun ptx ->
      let abs_idx = !last_idx + ptx.index + 1 in
      if abs_idx >= tx_count then
        () (* invalid index, will fail later *)
      else begin
        txs.(abs_idx) <- Some ptx.tx;
        last_idx := abs_idx
      end
    ) cb.prefilled_txs;

    (* Fill in transactions from short IDs using array for O(1) access *)
    let short_ids_arr = Array.of_list cb.short_ids in
    let n_short_ids = Array.length short_ids_arr in
    let short_idx = ref 0 in
    for i = 0 to tx_count - 1 do
      if txs.(i) = None then begin
        if !short_idx >= n_short_ids then
          missing := i :: !missing
        else begin
          let short_id = short_ids_arr.(!short_idx) in
          incr short_idx;
          match Hashtbl.find_opt lookup.by_short_id short_id with
          | Some tx -> txs.(i) <- Some tx
          | None -> missing := i :: !missing
        end
      end
    done;

    if !missing <> [] then
      ReconstructNeedTxs (List.rev !missing)
    else begin
      (* All transactions found - build the block *)
      let transactions = Array.to_list (Array.map Option.get txs) in
      ReconstructComplete { header = cb.header; transactions }
    end
  end

(* Fill in missing transactions from a blocktxn response.
   Converts differential indices to absolute indices. *)
let fill_missing_txs (cb : compact_block) (partial_txs : Types.transaction option array)
    (missing_indices : int list) (received_txs : Types.transaction list)
    : (Types.block, string) result =
  if List.length missing_indices <> List.length received_txs then
    Error "received transaction count mismatch"
  else begin
    (* Fill in the missing transactions *)
    List.iteri (fun i idx ->
      if idx < Array.length partial_txs then
        partial_txs.(idx) <- Some (List.nth received_txs i)
    ) missing_indices;

    (* Check all slots are filled *)
    let all_filled = Array.for_all (fun x -> x <> None) partial_txs in
    if not all_filled then
      Error "not all transactions filled"
    else begin
      let transactions = Array.to_list (Array.map Option.get partial_txs) in
      Ok { Types.header = cb.header; transactions }
    end
  end

(* Create getblocktxn request from missing indices.
   Converts absolute indices to differential encoding. *)
let make_getblocktxn_request (block_hash : Types.hash256) (missing : int list)
    : block_txns_request =
  (* Sort and convert to differential encoding *)
  let sorted = List.sort compare missing in
  let rec to_differential prev = function
    | [] -> []
    | idx :: rest ->
      let diff = idx - prev - 1 in
      diff :: to_differential idx rest
  in
  let indexes = match sorted with
    | [] -> []
    | first :: rest -> first :: to_differential first rest
  in
  { block_hash; indexes }

(* Decode differential indices from getblocktxn to absolute indices *)
let decode_differential_indices (indexes : int list) : int list =
  let rec decode prev acc = function
    | [] -> List.rev acc
    | diff :: rest ->
      let abs_idx = prev + diff + 1 in
      decode abs_idx (abs_idx :: acc) rest
  in
  match indexes with
  | [] -> []
  | first :: rest -> decode first (first :: []) rest

(* Create sendcmpct message for version 2 (segwit-aware) *)
let make_sendcmpct_msg ~high_bandwidth : message_payload =
  SendcmpctMsg { announce = high_bandwidth; version = cmpctblock_version }

(* Create cmpctblock message *)
let make_cmpctblock_msg (cb : compact_block) : message_payload =
  CmpctblockMsg cb

(* Create getblocktxn message *)
let make_getblocktxn_msg (req : block_txns_request) : message_payload =
  GetblocktxnMsg req

(* Create blocktxn message *)
let make_blocktxn_msg (resp : block_txns) : message_payload =
  BlocktxnMsg resp

(* ============================================================================
   BIP 331: Package Relay Message Helpers
   ============================================================================ *)

(* Default package relay parameters *)
let default_pkg_max_count = 25l
let default_pkg_max_weight = 404_000l

(* Create sendpackages message to announce package relay support *)
let make_sendpackages_msg
    ?(max_count = default_pkg_max_count)
    ?(max_weight = default_pkg_max_weight)
    () : message_payload =
  SendpackagesMsg {
    pkg_version = package_relay_version;
    pkg_max_count = max_count;
    pkg_max_weight = max_weight;
  }

(* Create getpkgtxns message to request package transactions by wtxid *)
let make_getpkgtxns_msg (wtxids : Types.hash256 list) : message_payload =
  GetpkgtxnsMsg { pkg_wtxids = wtxids }

(* Create pkgtxns message with package transactions in topological order *)
let make_pkgtxns_msg (txs : Types.transaction list) : message_payload =
  PkgtxnsMsg { pkg_txs = txs }

(* ============================================================================
   BIP324 v2 Encrypted Transport

   Implements encrypted P2P communication using:
   - ElligatorSwift key exchange (64-byte encoded public keys)
   - ChaCha20-Poly1305 AEAD encryption
   - Short message type IDs (1-byte vs 12-byte ASCII)

   Reference: BIP324, Bitcoin Core bip324.cpp/h, net.cpp V2Transport
   ============================================================================ *)

(* BIP324 constants *)
module Bip324 = struct
  let ellswift_pubkey_size = 64
  let garbage_terminator_len = 16
  let rekey_interval = 224
  let length_len = 3
  let header_len = 1
  let poly1305_tag_len = 16
  let expansion = length_len + header_len + poly1305_tag_len  (* 20 bytes *)
  let max_garbage_len = 4095
  let session_id_len = 32
  let ignore_bit = 0x80

  (* V1 prefix to detect v1 vs v2 connections *)
  let v1_prefix_len = 16

  (* Short message IDs as defined in BIP324 *)
  let v2_message_ids = [|
    "";              (* 0: 12 bytes follow encoding message type like V1 *)
    "addr";          (* 1 *)
    "block";         (* 2 *)
    "blocktxn";      (* 3 *)
    "cmpctblock";    (* 4 *)
    "feefilter";     (* 5 *)
    "filteradd";     (* 6 *)
    "filterclear";   (* 7 *)
    "filterload";    (* 8 *)
    "getblocks";     (* 9 *)
    "getblocktxn";   (* 10 *)
    "getdata";       (* 11 *)
    "getheaders";    (* 12 *)
    "headers";       (* 13 *)
    "inv";           (* 14 *)
    "mempool";       (* 15 *)
    "merkleblock";   (* 16 *)
    "notfound";      (* 17 *)
    "ping";          (* 18 *)
    "pong";          (* 19 *)
    "sendcmpct";     (* 20 *)
    "tx";            (* 21 *)
    "getcfilters";   (* 22 *)
    "cfilter";       (* 23 *)
    "getcfheaders";  (* 24 *)
    "cfheaders";     (* 25 *)
    "getcfcheckpt";  (* 26 *)
    "cfcheckpt";     (* 27 *)
    "addrv2";        (* 28 *)
    "";              (* 29: reserved *)
    "";              (* 30: reserved *)
    "";              (* 31: reserved *)
    "";              (* 32: reserved *)
  |]

  (* Build reverse lookup table for short message IDs *)
  let v2_message_map : (string, int) Hashtbl.t =
    let tbl = Hashtbl.create 33 in
    Array.iteri (fun i name ->
      if name <> "" then Hashtbl.replace tbl name i
    ) v2_message_ids;
    tbl

  (* Look up short message ID for a command *)
  let short_id_of_command (cmd : string) : int option =
    Hashtbl.find_opt v2_message_map cmd

  (* Look up command name for a short message ID *)
  let command_of_short_id (id : int) : string option =
    if id > 0 && id < Array.length v2_message_ids then
      let name = v2_message_ids.(id) in
      if name <> "" then Some name else None
    else
      None
end

(* HKDF-SHA256 for key derivation (BIP324 uses HKDF-HMAC-SHA256-L32) *)
module Hkdf = struct
  (* HMAC-SHA256 *)
  let hmac_sha256 (key : Cstruct.t) (data : Cstruct.t) : Cstruct.t =
    let key_str = Cstruct.to_string key in
    let data_str = Cstruct.to_string data in
    let mac = Digestif.SHA256.hmac_string ~key:key_str data_str in
    Cstruct.of_string (Digestif.SHA256.to_raw_string mac)

  (* HKDF-Extract: PRK = HMAC-Hash(salt, IKM) *)
  let extract ~(salt : string) ~(ikm : Cstruct.t) : Cstruct.t =
    hmac_sha256 (Cstruct.of_string salt) ikm

  (* HKDF-Expand for 32 bytes: T = HMAC-Hash(PRK, info || 0x01) *)
  let expand32 (prk : Cstruct.t) (info : string) : Cstruct.t =
    let info_cs = Cstruct.of_string info in
    let one = Cstruct.create 1 in
    Cstruct.set_uint8 one 0 0x01;
    let data = Cstruct.concat [info_cs; one] in
    hmac_sha256 prk data
end

(* ChaCha20-Poly1305 AEAD encryption

   Note: This is a simplified implementation. For production use,
   the underlying crypto should use optimized C bindings (e.g., libsodium). *)
module ChaCha20Poly1305 = struct

  (* ChaCha20 quarter round *)
  let quarter_round (a, b, c, d) =
    let rotl32 x n = Int32.logor (Int32.shift_left x n) (Int32.shift_right_logical x (32 - n)) in
    let a = Int32.add a b in
    let d = rotl32 (Int32.logxor d a) 16 in
    let c = Int32.add c d in
    let b = rotl32 (Int32.logxor b c) 12 in
    let a = Int32.add a b in
    let d = rotl32 (Int32.logxor d a) 8 in
    let c = Int32.add c d in
    let b = rotl32 (Int32.logxor b c) 7 in
    (a, b, c, d)

  (* Initialize ChaCha20 state *)
  let init_state (key : Cstruct.t) (nonce : Cstruct.t) (counter : int32) : int32 array =
    let state = Array.make 16 0l in
    (* Constants "expand 32-byte k" *)
    state.(0) <- 0x61707865l;
    state.(1) <- 0x3320646el;
    state.(2) <- 0x79622d32l;
    state.(3) <- 0x6b206574l;
    (* Key (8 words) *)
    for i = 0 to 7 do
      state.(4 + i) <- Cstruct.LE.get_uint32 key (i * 4)
    done;
    (* Counter *)
    state.(12) <- counter;
    (* Nonce (3 words, 96-bit) *)
    for i = 0 to 2 do
      state.(13 + i) <- Cstruct.LE.get_uint32 nonce (i * 4)
    done;
    state

  (* ChaCha20 block function *)
  let chacha20_block (key : Cstruct.t) (nonce : Cstruct.t) (counter : int32) : Cstruct.t =
    let state = init_state key nonce counter in
    let working = Array.copy state in

    (* 20 rounds (10 double rounds) *)
    for _ = 0 to 9 do
      (* Column rounds *)
      let (a0, a4, a8, a12) = quarter_round (working.(0), working.(4), working.(8), working.(12)) in
      working.(0) <- a0; working.(4) <- a4; working.(8) <- a8; working.(12) <- a12;
      let (a1, a5, a9, a13) = quarter_round (working.(1), working.(5), working.(9), working.(13)) in
      working.(1) <- a1; working.(5) <- a5; working.(9) <- a9; working.(13) <- a13;
      let (a2, a6, a10, a14) = quarter_round (working.(2), working.(6), working.(10), working.(14)) in
      working.(2) <- a2; working.(6) <- a6; working.(10) <- a10; working.(14) <- a14;
      let (a3, a7, a11, a15) = quarter_round (working.(3), working.(7), working.(11), working.(15)) in
      working.(3) <- a3; working.(7) <- a7; working.(11) <- a11; working.(15) <- a15;
      (* Diagonal rounds *)
      let (a0, a5, a10, a15) = quarter_round (working.(0), working.(5), working.(10), working.(15)) in
      working.(0) <- a0; working.(5) <- a5; working.(10) <- a10; working.(15) <- a15;
      let (a1, a6, a11, a12) = quarter_round (working.(1), working.(6), working.(11), working.(12)) in
      working.(1) <- a1; working.(6) <- a6; working.(11) <- a11; working.(12) <- a12;
      let (a2, a7, a8, a13) = quarter_round (working.(2), working.(7), working.(8), working.(13)) in
      working.(2) <- a2; working.(7) <- a7; working.(8) <- a8; working.(13) <- a13;
      let (a3, a4, a9, a14) = quarter_round (working.(3), working.(4), working.(9), working.(14)) in
      working.(3) <- a3; working.(4) <- a4; working.(9) <- a9; working.(14) <- a14;
    done;

    (* Add initial state *)
    let output = Cstruct.create 64 in
    for i = 0 to 15 do
      Cstruct.LE.set_uint32 output (i * 4) (Int32.add working.(i) state.(i))
    done;
    output

  (* ChaCha20 encrypt/decrypt (XOR with keystream) *)
  let chacha20_crypt (key : Cstruct.t) (nonce : Cstruct.t) (counter : int32) (data : Cstruct.t) : Cstruct.t =
    let len = Cstruct.length data in
    let output = Cstruct.create len in
    let num_blocks = (len + 63) / 64 in
    let pos = ref 0 in
    for block = 0 to num_blocks - 1 do
      let keystream = chacha20_block key nonce (Int32.add counter (Int32.of_int block)) in
      let block_len = min 64 (len - !pos) in
      for i = 0 to block_len - 1 do
        let p = Cstruct.get_uint8 data (!pos + i) in
        let k = Cstruct.get_uint8 keystream i in
        Cstruct.set_uint8 output (!pos + i) (p lxor k)
      done;
      pos := !pos + 64
    done;
    output

  (* Poly1305 MAC computation using 64-bit arithmetic
     Based on the reference implementation in RFC 8439.
     Uses a limb representation with 5x26-bit limbs for accumulator and r. *)
  let poly1305_mac (key : Cstruct.t) (data : Cstruct.t) : Cstruct.t =
    (* Read r and s from key *)
    let r0 = Cstruct.LE.get_uint32 key 0 in
    let r1 = Cstruct.LE.get_uint32 key 4 in
    let r2 = Cstruct.LE.get_uint32 key 8 in
    let r3 = Cstruct.LE.get_uint32 key 12 in

    (* Clamp r per Poly1305 spec *)
    let r0 = Int32.logand r0 0x0fffffffl in
    let r1 = Int32.logand r1 0x0ffffffcl in
    let r2 = Int32.logand r2 0x0ffffffcl in
    let r3 = Int32.logand r3 0x0ffffffcl in

    (* Convert r to 5x26-bit limbs *)
    let r0_26 = Int64.of_int32 (Int32.logand r0 0x03ffffffl) in
    let r1_26 = Int64.of_int32 (Int32.logand
      (Int32.logor (Int32.shift_right_logical r0 26) (Int32.shift_left r1 6)) 0x03ffffffl) in
    let r2_26 = Int64.of_int32 (Int32.logand
      (Int32.logor (Int32.shift_right_logical r1 20) (Int32.shift_left r2 12)) 0x03ffffffl) in
    let r3_26 = Int64.of_int32 (Int32.logand
      (Int32.logor (Int32.shift_right_logical r2 14) (Int32.shift_left r3 18)) 0x03ffffffl) in
    let r4_26 = Int64.of_int32 (Int32.shift_right_logical r3 8) in

    (* Precompute 5*r for reduction *)
    let s1 = Int64.mul r1_26 5L in
    let s2 = Int64.mul r2_26 5L in
    let s3 = Int64.mul r3_26 5L in
    let s4 = Int64.mul r4_26 5L in

    (* Accumulator in 5x26-bit limbs *)
    let h0 = ref 0L in
    let h1 = ref 0L in
    let h2 = ref 0L in
    let h3 = ref 0L in
    let h4 = ref 0L in

    (* Process data in 16-byte blocks *)
    let len = Cstruct.length data in
    let num_full_blocks = len / 16 in

    for block = 0 to num_full_blocks - 1 do
      let offset = block * 16 in
      (* Read 16-byte block as 4x32-bit little-endian *)
      let t0 = Int64.of_int32 (Cstruct.LE.get_uint32 data offset) in
      let t1 = Int64.of_int32 (Cstruct.LE.get_uint32 data (offset + 4)) in
      let t2 = Int64.of_int32 (Cstruct.LE.get_uint32 data (offset + 8)) in
      let t3 = Int64.of_int32 (Cstruct.LE.get_uint32 data (offset + 12)) in

      (* Add block to accumulator + high bit *)
      h0 := Int64.add !h0 (Int64.logand t0 0x03ffffffL);
      h1 := Int64.add !h1 (Int64.logand (Int64.logor (Int64.shift_right_logical t0 26) (Int64.shift_left t1 6)) 0x03ffffffL);
      h2 := Int64.add !h2 (Int64.logand (Int64.logor (Int64.shift_right_logical t1 20) (Int64.shift_left t2 12)) 0x03ffffffL);
      h3 := Int64.add !h3 (Int64.logand (Int64.logor (Int64.shift_right_logical t2 14) (Int64.shift_left t3 18)) 0x03ffffffL);
      h4 := Int64.add !h4 (Int64.logor (Int64.shift_right_logical t3 8) 0x01000000L);  (* high bit = 2^128 = 1 << 128, in limb 4 at bit 24 *)

      (* Multiply h by r *)
      let d0 = Int64.add (Int64.add (Int64.add (Int64.add
        (Int64.mul !h0 r0_26) (Int64.mul !h1 s4)) (Int64.mul !h2 s3)) (Int64.mul !h3 s2)) (Int64.mul !h4 s1) in
      let d1 = Int64.add (Int64.add (Int64.add (Int64.add
        (Int64.mul !h0 r1_26) (Int64.mul !h1 r0_26)) (Int64.mul !h2 s4)) (Int64.mul !h3 s3)) (Int64.mul !h4 s2) in
      let d2 = Int64.add (Int64.add (Int64.add (Int64.add
        (Int64.mul !h0 r2_26) (Int64.mul !h1 r1_26)) (Int64.mul !h2 r0_26)) (Int64.mul !h3 s4)) (Int64.mul !h4 s3) in
      let d3 = Int64.add (Int64.add (Int64.add (Int64.add
        (Int64.mul !h0 r3_26) (Int64.mul !h1 r2_26)) (Int64.mul !h2 r1_26)) (Int64.mul !h3 r0_26)) (Int64.mul !h4 s4) in
      let d4 = Int64.add (Int64.add (Int64.add (Int64.add
        (Int64.mul !h0 r4_26) (Int64.mul !h1 r3_26)) (Int64.mul !h2 r2_26)) (Int64.mul !h3 r1_26)) (Int64.mul !h4 r0_26) in

      (* Partial reduction mod 2^130-5 *)
      let c = Int64.shift_right_logical d0 26 in
      h0 := Int64.logand d0 0x03ffffffL;
      let d1 = Int64.add d1 c in
      let c = Int64.shift_right_logical d1 26 in
      h1 := Int64.logand d1 0x03ffffffL;
      let d2 = Int64.add d2 c in
      let c = Int64.shift_right_logical d2 26 in
      h2 := Int64.logand d2 0x03ffffffL;
      let d3 = Int64.add d3 c in
      let c = Int64.shift_right_logical d3 26 in
      h3 := Int64.logand d3 0x03ffffffL;
      let d4 = Int64.add d4 c in
      let c = Int64.shift_right_logical d4 26 in
      h4 := Int64.logand d4 0x03ffffffL;
      h0 := Int64.add !h0 (Int64.mul c 5L);
      let c = Int64.shift_right_logical !h0 26 in
      h0 := Int64.logand !h0 0x03ffffffL;
      h1 := Int64.add !h1 c;
    done;

    (* Process final partial block if any *)
    let remaining = len - (num_full_blocks * 16) in
    if remaining > 0 then begin
      let block_buf = Cstruct.create 16 in
      Cstruct.blit data (num_full_blocks * 16) block_buf 0 remaining;
      Cstruct.set_uint8 block_buf remaining 0x01;  (* hibit *)

      let t0 = Int64.of_int32 (Cstruct.LE.get_uint32 block_buf 0) in
      let t1 = Int64.of_int32 (Cstruct.LE.get_uint32 block_buf 4) in
      let t2 = Int64.of_int32 (Cstruct.LE.get_uint32 block_buf 8) in
      let t3 = Int64.of_int32 (Cstruct.LE.get_uint32 block_buf 12) in

      h0 := Int64.add !h0 (Int64.logand t0 0x03ffffffL);
      h1 := Int64.add !h1 (Int64.logand (Int64.logor (Int64.shift_right_logical t0 26) (Int64.shift_left t1 6)) 0x03ffffffL);
      h2 := Int64.add !h2 (Int64.logand (Int64.logor (Int64.shift_right_logical t1 20) (Int64.shift_left t2 12)) 0x03ffffffL);
      h3 := Int64.add !h3 (Int64.logand (Int64.logor (Int64.shift_right_logical t2 14) (Int64.shift_left t3 18)) 0x03ffffffL);
      h4 := Int64.add !h4 (Int64.shift_right_logical t3 8);  (* no hibit in limb for partial block, added via buffer *)

      let d0 = Int64.add (Int64.add (Int64.add (Int64.add
        (Int64.mul !h0 r0_26) (Int64.mul !h1 s4)) (Int64.mul !h2 s3)) (Int64.mul !h3 s2)) (Int64.mul !h4 s1) in
      let d1 = Int64.add (Int64.add (Int64.add (Int64.add
        (Int64.mul !h0 r1_26) (Int64.mul !h1 r0_26)) (Int64.mul !h2 s4)) (Int64.mul !h3 s3)) (Int64.mul !h4 s2) in
      let d2 = Int64.add (Int64.add (Int64.add (Int64.add
        (Int64.mul !h0 r2_26) (Int64.mul !h1 r1_26)) (Int64.mul !h2 r0_26)) (Int64.mul !h3 s4)) (Int64.mul !h4 s3) in
      let d3 = Int64.add (Int64.add (Int64.add (Int64.add
        (Int64.mul !h0 r3_26) (Int64.mul !h1 r2_26)) (Int64.mul !h2 r1_26)) (Int64.mul !h3 r0_26)) (Int64.mul !h4 s4) in
      let d4 = Int64.add (Int64.add (Int64.add (Int64.add
        (Int64.mul !h0 r4_26) (Int64.mul !h1 r3_26)) (Int64.mul !h2 r2_26)) (Int64.mul !h3 r1_26)) (Int64.mul !h4 r0_26) in

      let c = Int64.shift_right_logical d0 26 in
      h0 := Int64.logand d0 0x03ffffffL;
      let d1 = Int64.add d1 c in
      let c = Int64.shift_right_logical d1 26 in
      h1 := Int64.logand d1 0x03ffffffL;
      let d2 = Int64.add d2 c in
      let c = Int64.shift_right_logical d2 26 in
      h2 := Int64.logand d2 0x03ffffffL;
      let d3 = Int64.add d3 c in
      let c = Int64.shift_right_logical d3 26 in
      h3 := Int64.logand d3 0x03ffffffL;
      let d4 = Int64.add d4 c in
      let c = Int64.shift_right_logical d4 26 in
      h4 := Int64.logand d4 0x03ffffffL;
      h0 := Int64.add !h0 (Int64.mul c 5L);
      let c = Int64.shift_right_logical !h0 26 in
      h0 := Int64.logand !h0 0x03ffffffL;
      h1 := Int64.add !h1 c;
    end;

    (* Full reduction mod 2^130-5 *)
    let c = Int64.shift_right_logical !h1 26 in
    h1 := Int64.logand !h1 0x03ffffffL;
    h2 := Int64.add !h2 c;
    let c = Int64.shift_right_logical !h2 26 in
    h2 := Int64.logand !h2 0x03ffffffL;
    h3 := Int64.add !h3 c;
    let c = Int64.shift_right_logical !h3 26 in
    h3 := Int64.logand !h3 0x03ffffffL;
    h4 := Int64.add !h4 c;
    let c = Int64.shift_right_logical !h4 26 in
    h4 := Int64.logand !h4 0x03ffffffL;
    h0 := Int64.add !h0 (Int64.mul c 5L);
    let c = Int64.shift_right_logical !h0 26 in
    h0 := Int64.logand !h0 0x03ffffffL;
    h1 := Int64.add !h1 c;

    (* Compute h + -p *)
    let g0 = Int64.add !h0 5L in
    let c = Int64.shift_right_logical g0 26 in
    let g0 = Int64.logand g0 0x03ffffffL in
    let g1 = Int64.add !h1 c in
    let c = Int64.shift_right_logical g1 26 in
    let g1 = Int64.logand g1 0x03ffffffL in
    let g2 = Int64.add !h2 c in
    let c = Int64.shift_right_logical g2 26 in
    let g2 = Int64.logand g2 0x03ffffffL in
    let g3 = Int64.add !h3 c in
    let c = Int64.shift_right_logical g3 26 in
    let g3 = Int64.logand g3 0x03ffffffL in
    let g4 = Int64.add (Int64.sub !h4 0x04000000L) c in

    (* Select h if h < p, or h - p if h >= p *)
    let mask = Int64.shift_right (Int64.sub g4 0L) 63 in  (* -1 if g4 < 0, else 0 *)
    let mask = Int64.sub mask 1L in  (* 0 if g4 < 0, else -1 *)
    h0 := Int64.logxor !h0 (Int64.logand (Int64.logxor g0 !h0) mask);
    h1 := Int64.logxor !h1 (Int64.logand (Int64.logxor g1 !h1) mask);
    h2 := Int64.logxor !h2 (Int64.logand (Int64.logxor g2 !h2) mask);
    h3 := Int64.logxor !h3 (Int64.logand (Int64.logxor g3 !h3) mask);
    h4 := Int64.logxor !h4 (Int64.logand (Int64.logxor g4 !h4) mask);

    (* Convert from 5x26-bit to 4x32-bit *)
    let h0_32 = Int64.logor !h0 (Int64.shift_left !h1 26) in
    let h1_32 = Int64.logor (Int64.shift_right_logical !h1 6) (Int64.shift_left !h2 20) in
    let h2_32 = Int64.logor (Int64.shift_right_logical !h2 12) (Int64.shift_left !h3 14) in
    let h3_32 = Int64.logor (Int64.shift_right_logical !h3 18) (Int64.shift_left !h4 8) in

    (* Add s *)
    let s0 = Int64.of_int32 (Cstruct.LE.get_uint32 key 16) in
    let s1 = Int64.of_int32 (Cstruct.LE.get_uint32 key 20) in
    let s2 = Int64.of_int32 (Cstruct.LE.get_uint32 key 24) in
    let s3 = Int64.of_int32 (Cstruct.LE.get_uint32 key 28) in

    let f0 = Int64.add (Int64.logand h0_32 0xffffffffL) s0 in
    let f1 = Int64.add (Int64.add (Int64.logand h1_32 0xffffffffL) s1) (Int64.shift_right_logical f0 32) in
    let f2 = Int64.add (Int64.add (Int64.logand h2_32 0xffffffffL) s2) (Int64.shift_right_logical f1 32) in
    let f3 = Int64.add (Int64.add (Int64.logand h3_32 0xffffffffL) s3) (Int64.shift_right_logical f2 32) in

    let tag = Cstruct.create 16 in
    Cstruct.LE.set_uint32 tag 0 (Int64.to_int32 f0);
    Cstruct.LE.set_uint32 tag 4 (Int64.to_int32 f1);
    Cstruct.LE.set_uint32 tag 8 (Int64.to_int32 f2);
    Cstruct.LE.set_uint32 tag 12 (Int64.to_int32 f3);
    tag

  (* Pad to 16-byte boundary *)
  let pad16 (data : Cstruct.t) : Cstruct.t =
    let len = Cstruct.length data in
    let rem = len mod 16 in
    if rem = 0 then data
    else
      let padding = Cstruct.create (16 - rem) in
      Cstruct.concat [data; padding]

  (* AEAD_CHACHA20_POLY1305 encrypt
     cipher = plaintext || tag
     tag = Poly1305(poly_key, AAD || pad(AAD) || ciphertext || pad(ciphertext) || len(AAD) || len(ciphertext)) *)
  let encrypt ~(key : Cstruct.t) ~(nonce : Cstruct.t) ~(aad : Cstruct.t) ~(plaintext : Cstruct.t) : Cstruct.t =
    (* Generate Poly1305 key using ChaCha20 block 0 *)
    let poly_key = Cstruct.sub (chacha20_block key nonce 0l) 0 32 in
    (* Encrypt plaintext with ChaCha20 starting at block 1 *)
    let ciphertext = chacha20_crypt key nonce 1l plaintext in
    (* Compute tag *)
    let aad_len = Cstruct.length aad in
    let ct_len = Cstruct.length ciphertext in
    let len_block = Cstruct.create 16 in
    Cstruct.LE.set_uint64 len_block 0 (Int64.of_int aad_len);
    Cstruct.LE.set_uint64 len_block 8 (Int64.of_int ct_len);
    let mac_data = Cstruct.concat [pad16 aad; pad16 ciphertext; len_block] in
    let tag = poly1305_mac poly_key mac_data in
    Cstruct.concat [ciphertext; tag]

  (* AEAD_CHACHA20_POLY1305 decrypt
     Returns None if authentication fails *)
  let decrypt ~(key : Cstruct.t) ~(nonce : Cstruct.t) ~(aad : Cstruct.t) ~(ciphertext_and_tag : Cstruct.t) : Cstruct.t option =
    let len = Cstruct.length ciphertext_and_tag in
    if len < 16 then None
    else begin
      let ciphertext = Cstruct.sub ciphertext_and_tag 0 (len - 16) in
      let tag = Cstruct.sub ciphertext_and_tag (len - 16) 16 in
      (* Generate Poly1305 key *)
      let poly_key = Cstruct.sub (chacha20_block key nonce 0l) 0 32 in
      (* Verify tag *)
      let aad_len = Cstruct.length aad in
      let ct_len = Cstruct.length ciphertext in
      let len_block = Cstruct.create 16 in
      Cstruct.LE.set_uint64 len_block 0 (Int64.of_int aad_len);
      Cstruct.LE.set_uint64 len_block 8 (Int64.of_int ct_len);
      let mac_data = Cstruct.concat [pad16 aad; pad16 ciphertext; len_block] in
      let expected_tag = poly1305_mac poly_key mac_data in
      if not (Cstruct.equal tag expected_tag) then None
      else begin
        (* Decrypt *)
        let plaintext = chacha20_crypt key nonce 1l ciphertext in
        Some plaintext
      end
    end
end

(* Forward-Secure ChaCha20Poly1305 with rekeying (FSChaCha20Poly1305)
   Per BIP324: rekeys every REKEY_INTERVAL messages *)
module FSChaCha20Poly1305 = struct
  type t = {
    mutable key : Cstruct.t;
    rekey_interval : int;
    mutable packet_counter : int;
    mutable rekey_counter : int64;
  }

  let create (key : Cstruct.t) (rekey_interval : int) : t =
    { key = Cstruct.sub_copy key 0 32;
      rekey_interval;
      packet_counter = 0;
      rekey_counter = 0L }

  (* Construct nonce from rekey_counter (little-endian) and packet_counter *)
  let make_nonce (t : t) : Cstruct.t =
    let nonce = Cstruct.create 12 in
    (* Lower 4 bytes: packet_counter *)
    Cstruct.LE.set_uint32 nonce 0 (Int32.of_int t.packet_counter);
    (* Upper 8 bytes: rekey_counter *)
    Cstruct.LE.set_uint64 nonce 4 t.rekey_counter;
    nonce

  (* Advance to next packet, rekey if needed *)
  let next_packet (t : t) : unit =
    t.packet_counter <- t.packet_counter + 1;
    if t.packet_counter = t.rekey_interval then begin
      (* Rekey: new_key = ChaCha20(old_key, nonce, 0)[0:32] *)
      let nonce = make_nonce t in
      let keystream = ChaCha20Poly1305.chacha20_block t.key nonce 0l in
      t.key <- Cstruct.sub_copy keystream 0 32;
      t.packet_counter <- 0;
      t.rekey_counter <- Int64.add t.rekey_counter 1L
    end

  let encrypt (t : t) ~(aad : Cstruct.t) ~(plaintext : Cstruct.t) : Cstruct.t =
    let nonce = make_nonce t in
    let result = ChaCha20Poly1305.encrypt ~key:t.key ~nonce ~aad ~plaintext in
    next_packet t;
    result

  let decrypt (t : t) ~(aad : Cstruct.t) ~(ciphertext : Cstruct.t) : Cstruct.t option =
    let nonce = make_nonce t in
    let result = ChaCha20Poly1305.decrypt ~key:t.key ~nonce ~aad ~ciphertext_and_tag:ciphertext in
    next_packet t;
    result
end

(* FSChaCha20 for length encryption (no authentication) *)
module FSChaCha20 = struct
  type t = {
    mutable key : Cstruct.t;
    rekey_interval : int;
    mutable packet_counter : int;
    mutable rekey_counter : int64;
  }

  let create (key : Cstruct.t) (rekey_interval : int) : t =
    { key = Cstruct.sub_copy key 0 32;
      rekey_interval;
      packet_counter = 0;
      rekey_counter = 0L }

  let make_nonce (t : t) : Cstruct.t =
    let nonce = Cstruct.create 12 in
    Cstruct.LE.set_uint32 nonce 0 (Int32.of_int t.packet_counter);
    Cstruct.LE.set_uint64 nonce 4 t.rekey_counter;
    nonce

  let next_packet (t : t) : unit =
    t.packet_counter <- t.packet_counter + 1;
    if t.packet_counter = t.rekey_interval then begin
      let nonce = make_nonce t in
      let keystream = ChaCha20Poly1305.chacha20_block t.key nonce 0l in
      t.key <- Cstruct.sub_copy keystream 0 32;
      t.packet_counter <- 0;
      t.rekey_counter <- Int64.add t.rekey_counter 1L
    end

  (* Encrypt/decrypt 3-byte length field *)
  let crypt (t : t) (data : Cstruct.t) : Cstruct.t =
    let nonce = make_nonce t in
    let result = ChaCha20Poly1305.chacha20_crypt t.key nonce 0l data in
    next_packet t;
    result
end

(* BIP324 Cipher state *)
type bip324_cipher = {
  mutable send_l_cipher : FSChaCha20.t option;
  mutable recv_l_cipher : FSChaCha20.t option;
  mutable send_p_cipher : FSChaCha20Poly1305.t option;
  mutable recv_p_cipher : FSChaCha20Poly1305.t option;
  session_id : Cstruct.t;
  send_garbage_terminator : Cstruct.t;
  recv_garbage_terminator : Cstruct.t;
}

(* Initialize BIP324 cipher from ECDH shared secret *)
let init_bip324_cipher ~(ecdh_secret : Cstruct.t) ~(initiator : bool) ~(network_magic : int32) : bip324_cipher =
  (* Construct salt: "bitcoin_v2_shared_secret" + network magic bytes *)
  let magic_bytes = Cstruct.create 4 in
  Cstruct.LE.set_uint32 magic_bytes 0 network_magic;
  let salt = "bitcoin_v2_shared_secret" ^ Cstruct.to_string magic_bytes in

  (* HKDF extract *)
  let prk = Hkdf.extract ~salt ~ikm:ecdh_secret in

  (* Derive keys *)
  let initiator_l_key = Hkdf.expand32 prk "initiator_L" in
  let initiator_p_key = Hkdf.expand32 prk "initiator_P" in
  let responder_l_key = Hkdf.expand32 prk "responder_L" in
  let responder_p_key = Hkdf.expand32 prk "responder_P" in
  let garbage_terminators = Hkdf.expand32 prk "garbage_terminators" in
  let session_id = Hkdf.expand32 prk "session_id" in

  (* Assign keys based on role *)
  let (send_l_key, recv_l_key, send_p_key, recv_p_key) =
    if initiator then
      (initiator_l_key, responder_l_key, initiator_p_key, responder_p_key)
    else
      (responder_l_key, initiator_l_key, responder_p_key, initiator_p_key)
  in

  (* Extract garbage terminators (first 16 bytes for initiator send, last 16 for responder) *)
  let (send_gt, recv_gt) =
    if initiator then
      (Cstruct.sub garbage_terminators 0 Bip324.garbage_terminator_len,
       Cstruct.sub garbage_terminators 16 Bip324.garbage_terminator_len)
    else
      (Cstruct.sub garbage_terminators 16 Bip324.garbage_terminator_len,
       Cstruct.sub garbage_terminators 0 Bip324.garbage_terminator_len)
  in

  {
    send_l_cipher = Some (FSChaCha20.create send_l_key Bip324.rekey_interval);
    recv_l_cipher = Some (FSChaCha20.create recv_l_key Bip324.rekey_interval);
    send_p_cipher = Some (FSChaCha20Poly1305.create send_p_key Bip324.rekey_interval);
    recv_p_cipher = Some (FSChaCha20Poly1305.create recv_p_key Bip324.rekey_interval);
    session_id;
    send_garbage_terminator = send_gt;
    recv_garbage_terminator = recv_gt;
  }

(* Encrypt a BIP324 packet *)
let bip324_encrypt (cipher : bip324_cipher) ~(aad : Cstruct.t) ~(contents : Cstruct.t) ~(ignore : bool) : Cstruct.t =
  let l_cipher = Option.get cipher.send_l_cipher in
  let p_cipher = Option.get cipher.send_p_cipher in

  (* Encode length (3 bytes little-endian) *)
  let len = Cstruct.length contents in
  let len_bytes = Cstruct.create 3 in
  Cstruct.set_uint8 len_bytes 0 (len land 0xFF);
  Cstruct.set_uint8 len_bytes 1 ((len lsr 8) land 0xFF);
  Cstruct.set_uint8 len_bytes 2 ((len lsr 16) land 0xFF);

  (* Encrypt length *)
  let encrypted_len = FSChaCha20.crypt l_cipher len_bytes in

  (* Encrypt header + contents *)
  let header = Cstruct.create 1 in
  Cstruct.set_uint8 header 0 (if ignore then Bip324.ignore_bit else 0);
  let plaintext = Cstruct.concat [header; contents] in
  let encrypted_payload = FSChaCha20Poly1305.encrypt p_cipher ~aad ~plaintext in

  Cstruct.concat [encrypted_len; encrypted_payload]

(* Decrypt BIP324 packet length (3 bytes) *)
let bip324_decrypt_length (cipher : bip324_cipher) (encrypted_len : Cstruct.t) : int =
  let l_cipher = Option.get cipher.recv_l_cipher in
  let len_bytes = FSChaCha20.crypt l_cipher encrypted_len in
  let b0 = Cstruct.get_uint8 len_bytes 0 in
  let b1 = Cstruct.get_uint8 len_bytes 1 in
  let b2 = Cstruct.get_uint8 len_bytes 2 in
  b0 lor (b1 lsl 8) lor (b2 lsl 16)

(* Decrypt BIP324 packet payload *)
let bip324_decrypt (cipher : bip324_cipher) ~(aad : Cstruct.t) ~(ciphertext : Cstruct.t) : (bool * Cstruct.t) option =
  let p_cipher = Option.get cipher.recv_p_cipher in
  match FSChaCha20Poly1305.decrypt p_cipher ~aad ~ciphertext with
  | None -> None
  | Some plaintext ->
    if Cstruct.length plaintext < 1 then None
    else begin
      let header = Cstruct.get_uint8 plaintext 0 in
      let ignore = (header land Bip324.ignore_bit) <> 0 in
      let contents = Cstruct.sub plaintext 1 (Cstruct.length plaintext - 1) in
      Some (ignore, contents)
    end

(* V2 Transport receive state machine *)
type v2_recv_state =
  | V2RecvKeyMaybeV1       (* Responder: waiting for key, might be V1 *)
  | V2RecvKey              (* Initiator: waiting for peer's public key *)
  | V2RecvGarbageTerminator (* Waiting for garbage terminator *)
  | V2RecvVersion          (* Reading version packet *)
  | V2RecvApp              (* Reading application packets *)
  | V2RecvAppReady         (* A complete message is ready *)
  | V2RecvV1Fallback       (* Fell back to V1 protocol *)

(* V2 Transport send state machine *)
type v2_send_state =
  | V2SendMaybeV1          (* Responder: waiting to know if V1 or V2 *)
  | V2SendAwaitingKey      (* Initiator: sent key, waiting for peer's key *)
  | V2SendReady            (* Ready to send encrypted messages *)
  | V2SendV1Fallback       (* Fell back to V1 protocol *)

(* V2 Transport state *)
type v2_state = {
  initiating : bool;
  mutable recv_state : v2_recv_state;
  mutable send_state : v2_send_state;
  mutable our_privkey : Cstruct.t;
  mutable our_ellswift_pubkey : Cstruct.t;
  mutable cipher : bip324_cipher option;
  mutable recv_buffer : Cstruct.t;
  mutable recv_len : int;                    (* Decrypted length, valid in RecvVersion/App *)
  mutable recv_aad : Cstruct.t;              (* AAD for next packet (garbage during handshake) *)
  mutable recv_decode_buffer : Cstruct.t;    (* Decoded message contents *)
  mutable send_buffer : Cstruct.t;
  mutable send_garbage : Cstruct.t;
  network_magic : int32;
}

(* V1 Transport state (legacy) *)
type v1_state = {
  v1_magic : int32;
  mutable v1_recv_buffer : Cstruct.t;
  mutable v1_header_complete : bool;
  mutable v1_expected_len : int;
}

(* Transport abstraction *)
type transport =
  | V1 of v1_state
  | V2 of v2_state

(* Create V1 transport *)
let create_v1_transport (magic : int32) : transport =
  V1 {
    v1_magic = magic;
    v1_recv_buffer = Cstruct.empty;
    v1_header_complete = false;
    v1_expected_len = 0;
  }

(* Generate random garbage (0-4095 bytes) *)
let generate_garbage () : Cstruct.t =
  let ic = open_in_bin "/dev/urandom" in
  let len_bytes = really_input_string ic 2 in
  close_in ic;
  let len = (Char.code len_bytes.[0] lor (Char.code len_bytes.[1] lsl 8)) mod (Bip324.max_garbage_len + 1) in
  let garbage = Cstruct.create len in
  if len > 0 then begin
    let ic = open_in_bin "/dev/urandom" in
    let bytes = really_input_string ic len in
    close_in ic;
    Cstruct.blit_from_string bytes 0 garbage 0 len
  end;
  garbage

(* Generate random 32-byte private key *)
let generate_privkey () : Cstruct.t =
  let ic = open_in_bin "/dev/urandom" in
  let bytes = really_input_string ic 32 in
  close_in ic;
  Cstruct.of_string bytes

(* Compute ElligatorSwift encoding of public key (64 bytes)
   Note: This is a simplified placeholder. Real implementation requires
   libsecp256k1's ellswift module. For now, we use pubkey || random padding. *)
let compute_ellswift_pubkey (privkey : Cstruct.t) : Cstruct.t =
  (* Derive compressed public key *)
  let pubkey = Crypto.derive_public_key ~compressed:true privkey in
  (* ElligatorSwift encoding would produce 64 uniform-looking bytes
     For now, concatenate pubkey with random padding *)
  let padding = Cstruct.create (64 - Cstruct.length pubkey) in
  let ic = open_in_bin "/dev/urandom" in
  let bytes = really_input_string ic (64 - Cstruct.length pubkey) in
  close_in ic;
  Cstruct.blit_from_string bytes 0 padding 0 (Cstruct.length padding);
  Cstruct.concat [pubkey; padding]

(* Compute ECDH shared secret from our private key and peer's ellswift pubkey
   Note: Real implementation requires libsecp256k1's ellswift_xdh. *)
let compute_ecdh_secret (our_privkey : Cstruct.t) (their_ellswift : Cstruct.t)
    (our_ellswift : Cstruct.t) (initiator : bool) : Cstruct.t =
  (* For real implementation, we'd use secp256k1_ellswift_xdh
     which computes BIP324-specific ECDH with both ellswift pubkeys.
     Here we simulate with a tagged hash of the inputs. *)
  let data = Cstruct.concat [
    (if initiator then our_ellswift else their_ellswift);
    (if initiator then their_ellswift else our_ellswift);
    our_privkey
  ] in
  Crypto.tagged_hash "bip324_ecdh" data

(* Create V2 transport (initiator or responder) *)
let create_v2_transport ~(initiating : bool) ~(magic : int32) : transport =
  let privkey = generate_privkey () in
  let ellswift = compute_ellswift_pubkey privkey in
  let garbage = generate_garbage () in

  let (recv_state, send_state) =
    if initiating then (V2RecvKey, V2SendAwaitingKey)
    else (V2RecvKeyMaybeV1, V2SendMaybeV1)
  in

  (* Build initial send buffer: ellswift pubkey + garbage *)
  let send_buffer =
    if initiating then Cstruct.concat [ellswift; garbage]
    else Cstruct.empty  (* Responder waits for key detection first *)
  in

  V2 {
    initiating;
    recv_state;
    send_state;
    our_privkey = privkey;
    our_ellswift_pubkey = ellswift;
    cipher = None;
    recv_buffer = Cstruct.empty;
    recv_len = 0;
    recv_aad = Cstruct.empty;
    recv_decode_buffer = Cstruct.empty;
    send_buffer;
    send_garbage = garbage;
    network_magic = magic;
  }

(* Check if bytes look like V1 version message magic *)
let looks_like_v1_magic (data : Cstruct.t) (magic : int32) : bool =
  if Cstruct.length data < 4 then false
  else Cstruct.LE.get_uint32 data 0 = magic

(* Process received bytes for V2 transport *)
let v2_receive_bytes (state : v2_state) (data : Cstruct.t) : bool =
  state.recv_buffer <- Cstruct.concat [state.recv_buffer; data];

  let rec process () =
    match state.recv_state with
    | V2RecvKeyMaybeV1 ->
      (* Check if this looks like a V1 connection *)
      if Cstruct.length state.recv_buffer >= 4 then begin
        if looks_like_v1_magic state.recv_buffer state.network_magic then begin
          (* Fall back to V1 *)
          state.recv_state <- V2RecvV1Fallback;
          state.send_state <- V2SendV1Fallback;
          true
        end else begin
          (* Proceed as V2 *)
          state.recv_state <- V2RecvKey;
          process ()
        end
      end else
        true  (* Need more data *)

    | V2RecvKey ->
      if Cstruct.length state.recv_buffer >= Bip324.ellswift_pubkey_size then begin
        (* Extract peer's ellswift public key *)
        let their_ellswift = Cstruct.sub state.recv_buffer 0 Bip324.ellswift_pubkey_size in
        state.recv_buffer <- Cstruct.sub state.recv_buffer Bip324.ellswift_pubkey_size
          (Cstruct.length state.recv_buffer - Bip324.ellswift_pubkey_size);

        (* Compute ECDH shared secret and initialize ciphers *)
        let ecdh_secret = compute_ecdh_secret state.our_privkey their_ellswift
          state.our_ellswift_pubkey state.initiating in
        let cipher = init_bip324_cipher ~ecdh_secret ~initiator:state.initiating
          ~network_magic:state.network_magic in
        state.cipher <- Some cipher;

        (* Update states *)
        state.recv_state <- V2RecvGarbageTerminator;
        if state.initiating then begin
          (* Initiator was already sending, just need to append garbage terminator + version *)
          state.send_state <- V2SendReady;
          let version_packet = bip324_encrypt cipher ~aad:state.send_garbage
            ~contents:Cstruct.empty ~ignore:false in
          state.send_buffer <- Cstruct.concat [
            state.send_buffer;
            cipher.send_garbage_terminator;
            version_packet
          ]
        end else begin
          (* Responder: send our key + garbage + garbage terminator + version *)
          state.send_state <- V2SendReady;
          let version_packet = bip324_encrypt cipher ~aad:state.send_garbage
            ~contents:Cstruct.empty ~ignore:false in
          state.send_buffer <- Cstruct.concat [
            state.our_ellswift_pubkey;
            state.send_garbage;
            cipher.send_garbage_terminator;
            version_packet
          ]
        end;
        process ()
      end else
        true

    | V2RecvGarbageTerminator ->
      let cipher = Option.get state.cipher in
      let term_len = Bip324.garbage_terminator_len in
      (* Search for garbage terminator in received data *)
      let buf_len = Cstruct.length state.recv_buffer in
      if buf_len >= term_len then begin
        let rec find_terminator offset =
          if offset > Bip324.max_garbage_len then
            false  (* Too much garbage, connection failed *)
          else if offset + term_len > buf_len then
            true  (* Need more data *)
          else begin
            let candidate = Cstruct.sub state.recv_buffer offset term_len in
            if Cstruct.equal candidate cipher.recv_garbage_terminator then begin
              (* Found terminator, save garbage as AAD for version packet *)
              state.recv_aad <- Cstruct.sub state.recv_buffer 0 offset;
              state.recv_buffer <- Cstruct.sub state.recv_buffer (offset + term_len)
                (buf_len - offset - term_len);
              state.recv_state <- V2RecvVersion;
              process ()
            end else
              find_terminator (offset + 1)
          end
        in
        find_terminator 0
      end else
        true

    | V2RecvVersion | V2RecvApp ->
      let cipher = Option.get state.cipher in
      (* Read 3-byte encrypted length if we don't have it *)
      if state.recv_len = 0 then begin
        if Cstruct.length state.recv_buffer >= Bip324.length_len then begin
          let enc_len = Cstruct.sub state.recv_buffer 0 Bip324.length_len in
          state.recv_len <- bip324_decrypt_length cipher enc_len;
          state.recv_buffer <- Cstruct.sub state.recv_buffer Bip324.length_len
            (Cstruct.length state.recv_buffer - Bip324.length_len);
          process ()
        end else
          true
      end else begin
        (* Read payload + tag *)
        let needed = state.recv_len + Bip324.header_len + Bip324.poly1305_tag_len in
        if Cstruct.length state.recv_buffer >= needed then begin
          let ciphertext = Cstruct.sub state.recv_buffer 0 needed in
          state.recv_buffer <- Cstruct.sub state.recv_buffer needed
            (Cstruct.length state.recv_buffer - needed);

          (* Determine AAD: use recv_aad for version packet (contains garbage) *)
          let aad = if state.recv_state = V2RecvVersion then state.recv_aad else Cstruct.empty in

          match bip324_decrypt cipher ~aad ~ciphertext with
          | None ->
            false  (* Decryption failed *)
          | Some (ignore_flag, contents) ->
            state.recv_len <- 0;
            if ignore_flag then begin
              (* Decoy packet, continue reading *)
              if state.recv_state = V2RecvVersion then begin
                state.recv_state <- V2RecvVersion;  (* More version packets may follow *)
                state.recv_aad <- Cstruct.empty;    (* Clear AAD after first packet *)
              end;
              process ()
            end else begin
              if state.recv_state = V2RecvVersion then begin
                (* Version packet received (contents ignored per BIP324) *)
                state.recv_state <- V2RecvApp;
                state.recv_aad <- Cstruct.empty;
                process ()
              end else begin
                (* Application packet ready *)
                state.recv_decode_buffer <- contents;
                state.recv_state <- V2RecvAppReady;
                true
              end
            end
        end else
          true
      end

    | V2RecvAppReady | V2RecvV1Fallback ->
      true
  in
  process ()

(* Check if a complete message is available *)
let v2_message_complete (state : v2_state) : bool =
  state.recv_state = V2RecvAppReady

(* Get the decoded message type from V2 packet *)
let v2_get_message_type (contents : Cstruct.t) : (command * Cstruct.t) option =
  if Cstruct.length contents = 0 then None
  else begin
    let first_byte = Cstruct.get_uint8 contents 0 in
    let payload = Cstruct.sub contents 1 (Cstruct.length contents - 1) in

    if first_byte <> 0 then begin
      (* Short message ID *)
      match Bip324.command_of_short_id first_byte with
      | Some name -> Some (command_of_string name, payload)
      | None -> None  (* Unknown short ID *)
    end else begin
      (* Long encoding: 12 bytes of ASCII command name *)
      if Cstruct.length payload < 12 then None
      else begin
        let cmd_bytes = Cstruct.sub payload 0 12 in
        let cmd_str = Cstruct.to_string cmd_bytes in
        (* Find null terminator *)
        let null_pos = match String.index_opt cmd_str '\x00' with
          | Some p -> p | None -> 12
        in
        let cmd_name = String.sub cmd_str 0 null_pos in
        let actual_payload = Cstruct.sub payload 12 (Cstruct.length payload - 12) in
        Some (command_of_string cmd_name, actual_payload)
      end
    end
  end

(* Get received message from V2 transport *)
let v2_get_message (state : v2_state) : message option =
  if state.recv_state <> V2RecvAppReady then None
  else begin
    let contents = state.recv_decode_buffer in
    state.recv_decode_buffer <- Cstruct.empty;
    state.recv_state <- V2RecvApp;

    match v2_get_message_type contents with
    | None -> None
    | Some (cmd, payload) ->
      let r = Serialize.reader_of_cstruct payload in
      let msg_payload = deserialize_payload cmd r in
      Some { magic = state.network_magic; command = cmd; payload = msg_payload }
  end

(* Encode message contents for V2 transport *)
let v2_encode_message (cmd : command) (payload : Cstruct.t) : Cstruct.t =
  let cmd_str = command_to_string cmd in
  match Bip324.short_id_of_command cmd_str with
  | Some short_id ->
    (* Use short encoding *)
    let header = Cstruct.create 1 in
    Cstruct.set_uint8 header 0 short_id;
    Cstruct.concat [header; payload]
  | None ->
    (* Use long encoding: 0x00 + 12 bytes command *)
    let header = Cstruct.create 13 in
    Cstruct.set_uint8 header 0 0;
    let cmd_len = min 12 (String.length cmd_str) in
    Cstruct.blit_from_string cmd_str 0 header 1 cmd_len;
    Cstruct.concat [header; payload]

(* Set message to send on V2 transport *)
let v2_set_message (state : v2_state) (msg : message_payload) : bool =
  if state.send_state <> V2SendReady then false
  else begin
    let cipher = Option.get state.cipher in
    let cmd = payload_to_command msg in

    (* Serialize payload *)
    let pw = Serialize.writer_create () in
    serialize_payload pw msg;
    let payload_bytes = Serialize.writer_to_cstruct pw in

    (* Encode with message type *)
    let contents = v2_encode_message cmd payload_bytes in

    (* Encrypt *)
    let encrypted = bip324_encrypt cipher ~aad:Cstruct.empty ~contents ~ignore:false in
    state.send_buffer <- Cstruct.concat [state.send_buffer; encrypted];
    true
  end

(* Get bytes to send from V2 transport *)
let v2_get_bytes_to_send (state : v2_state) : Cstruct.t =
  let result = state.send_buffer in
  state.send_buffer <- Cstruct.empty;
  result

(* Get session ID for optional authentication *)
let v2_get_session_id (state : v2_state) : Cstruct.t option =
  match state.cipher with
  | None -> None
  | Some cipher -> Some cipher.session_id
