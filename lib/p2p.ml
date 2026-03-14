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
