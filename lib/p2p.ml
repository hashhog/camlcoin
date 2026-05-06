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
let max_locator_size = 101  (* Core MAX_LOCATOR_SZ; chain.h *)
let max_addr_count = 1000

(* Network magic bytes for different networks *)
let mainnet_magic = 0xD9B4BEF9l
let testnet_magic = 0x283F161Cl
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
  (* BIP 330: Erlay Transaction Reconciliation *)
  | Sendtxrcncl
  | Reqrecon
  | Sketch
  | Reqbisec
  | Reconcildiff
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
  | Sendtxrcncl -> "sendtxrcncl"
  | Reqrecon -> "reqrecon"
  | Sketch -> "sketch"
  | Reqbisec -> "reqbisec"
  | Reconcildiff -> "reconcildiff"
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
  | "sendtxrcncl" -> Sendtxrcncl
  | "reqrecon" -> Reqrecon
  | "sketch" -> Sketch
  | "reqbisec" -> Reqbisec
  | "reconcildiff" -> Reconcildiff
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

(* ============================================================================
   BIP 330: Erlay Transaction Reconciliation Types
   ============================================================================ *)

(* Erlay protocol version (BIP-330) *)
let erlay_protocol_version = 1l

(* sendtxrcncl: announce transaction reconciliation support *)
type sendtxrcncl_msg = {
  recon_version : int32;   (* reconciliation protocol version *)
  recon_salt : int64;      (* 64-bit salt for short txid computation *)
}

(* reqrecon: request transaction reconciliation
   Initiator requests a sketch from the responder *)
type reqrecon_msg = {
  recon_set_size : int32;  (* announced local set size estimate *)
  recon_q : int32;         (* coefficient for sketch capacity calculation *)
}

(* sketch: response containing a minisketch of transactions *)
type sketch_msg = {
  sketch_data : Cstruct.t;  (* serialized minisketch data *)
}

(* reqbisec: request extension round with larger sketch
   Sent when initial sketch decode fails *)
type reqbisec_msg = {
  bisec_set_size : int32;  (* new set size estimate *)
  bisec_q : int32;         (* new coefficient *)
}

(* reconcildiff: communicate reconciliation result *)
type reconcildiff_msg = {
  success : bool;          (* whether reconciliation succeeded *)
  ask_short_ids : Cstruct.t list;    (* short txids we're missing (initiator asks) *)
  announce_short_ids : Cstruct.t list; (* short txids we have that peer is missing *)
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
  (* BIP 330: Erlay Transaction Reconciliation *)
  | SendtxrcnclMsg of sendtxrcncl_msg
  | ReqreconMsg of reqrecon_msg
  | SketchMsg of sketch_msg
  | ReqbisecMsg of reqbisec_msg
  | ReconcildiffMsg of reconcildiff_msg
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
  (* Anti-DoS: Bitcoin Core MAX_LOCATOR_SZ = 101 (chain.h). Reject before
     allocating the list to prevent an attacker from forcing arbitrary
     memory allocation via a crafted getblocks/getheaders message. *)
  if count > max_locator_size then
    failwith (Printf.sprintf "locator size %d exceeds MAX_LOCATOR_SZ" count);
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

(* ============================================================================
   BIP 330: Erlay Transaction Reconciliation Serialization
   ============================================================================ *)

(* Maximum elements in reconciliation set *)
let max_recon_set_size = 5000

(* Serialize sendtxrcncl message *)
let serialize_sendtxrcncl w (msg : sendtxrcncl_msg) =
  Serialize.write_int32_le w msg.recon_version;
  Serialize.write_int64_le w msg.recon_salt

(* Deserialize sendtxrcncl message *)
let deserialize_sendtxrcncl r : sendtxrcncl_msg =
  let recon_version = Serialize.read_int32_le r in
  let recon_salt = Serialize.read_int64_le r in
  { recon_version; recon_salt }

(* Serialize reqrecon message *)
let serialize_reqrecon w (msg : reqrecon_msg) =
  Serialize.write_int32_le w msg.recon_set_size;
  Serialize.write_int32_le w msg.recon_q

(* Deserialize reqrecon message *)
let deserialize_reqrecon r : reqrecon_msg =
  let recon_set_size = Serialize.read_int32_le r in
  let recon_q = Serialize.read_int32_le r in
  { recon_set_size; recon_q }

(* Serialize sketch message *)
let serialize_sketch w (msg : sketch_msg) =
  Serialize.write_compact_size w (Cstruct.length msg.sketch_data);
  Serialize.write_bytes w msg.sketch_data

(* Deserialize sketch message *)
let deserialize_sketch r : sketch_msg =
  let len = Serialize.read_compact_size r in
  (* Sanity limit: sketch shouldn't be larger than ~128KB for reasonable capacity *)
  if len > 131072 then
    failwith "sketch data exceeds maximum size";
  let sketch_data = Serialize.read_bytes r len in
  { sketch_data }

(* Serialize reqbisec message *)
let serialize_reqbisec w (msg : reqbisec_msg) =
  Serialize.write_int32_le w msg.bisec_set_size;
  Serialize.write_int32_le w msg.bisec_q

(* Deserialize reqbisec message *)
let deserialize_reqbisec r : reqbisec_msg =
  let bisec_set_size = Serialize.read_int32_le r in
  let bisec_q = Serialize.read_int32_le r in
  { bisec_set_size; bisec_q }

(* Serialize reconcildiff message *)
let serialize_reconcildiff w (msg : reconcildiff_msg) =
  Serialize.write_uint8 w (if msg.success then 1 else 0);
  Serialize.write_compact_size w (List.length msg.ask_short_ids);
  List.iter (Serialize.write_bytes w) msg.ask_short_ids;
  Serialize.write_compact_size w (List.length msg.announce_short_ids);
  List.iter (Serialize.write_bytes w) msg.announce_short_ids

(* Deserialize reconcildiff message *)
let deserialize_reconcildiff r : reconcildiff_msg =
  let success = Serialize.read_uint8 r <> 0 in
  let ask_count = Serialize.read_compact_size r in
  if ask_count > max_recon_set_size then
    failwith "reconcildiff ask count exceeds maximum";
  let ask_short_ids = List.init ask_count (fun _ -> Serialize.read_bytes r 8) in
  let announce_count = Serialize.read_compact_size r in
  if announce_count > max_recon_set_size then
    failwith "reconcildiff announce count exceeds maximum";
  let announce_short_ids = List.init announce_count (fun _ -> Serialize.read_bytes r 8) in
  { success; ask_short_ids; announce_short_ids }

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
  | SendtxrcnclMsg msg -> serialize_sendtxrcncl w msg
  | ReqreconMsg msg -> serialize_reqrecon w msg
  | SketchMsg msg -> serialize_sketch w msg
  | ReqbisecMsg msg -> serialize_reqbisec w msg
  | ReconcildiffMsg msg -> serialize_reconcildiff w msg
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
  | SendtxrcnclMsg _ -> Sendtxrcncl
  | ReqreconMsg _ -> Reqrecon
  | SketchMsg _ -> Sketch
  | ReqbisecMsg _ -> Reqbisec
  | ReconcildiffMsg _ -> Reconcildiff
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
  | Sendtxrcncl -> SendtxrcnclMsg (deserialize_sendtxrcncl r)
  | Reqrecon -> ReqreconMsg (deserialize_reqrecon r)
  | Sketch -> SketchMsg (deserialize_sketch r)
  | Reqbisec -> ReqbisecMsg (deserialize_reqbisec r)
  | Reconcildiff -> ReconcildiffMsg (deserialize_reconcildiff r)
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
   BIP 330: Erlay Transaction Reconciliation Logic
   ============================================================================ *)

(* Per-peer Erlay reconciliation state *)
type erlay_peer_state = {
  mutable recon_enabled : bool;         (* Peer supports reconciliation *)
  mutable recon_version : int32;        (* Negotiated reconciliation version *)
  mutable is_initiator : bool;          (* We are the reconciliation initiator *)
  mutable local_set : (string, unit) Hashtbl.t;  (* txids we have but haven't reconciled *)
  mutable pending_recon : bool;         (* A reconciliation round is in progress *)
  mutable last_recon_time : float;      (* Timestamp of last reconciliation *)
}

let create_erlay_peer_state () : erlay_peer_state = {
  recon_enabled = false;
  recon_version = 0l;
  is_initiator = false;
  local_set = Hashtbl.create 64;
  pending_recon = false;
  last_recon_time = 0.0;
}

(* Global Erlay state for the node *)
type erlay_state = {
  peer_states : (int, erlay_peer_state) Hashtbl.t;  (* peer_id -> state *)
  recon_interval : float;   (* seconds between reconciliation rounds, ~2s per BIP330 *)
}

let create_erlay_state () : erlay_state = {
  peer_states = Hashtbl.create 16;
  recon_interval = 2.0;
}

(* Handle incoming sendtxrcncl: peer announces reconciliation support.
   Called during version handshake. We register the peer and decide roles. *)
let handle_sendtxrcncl (state : erlay_state) (peer_id : int) (msg : sendtxrcncl_msg)
    ~(our_initiator : bool) : message_payload option =
  let ps = create_erlay_peer_state () in
  ps.recon_enabled <- true;
  ps.recon_version <- Int32.min msg.recon_version erlay_protocol_version;
  (* BIP330: the peer with higher salt is the initiator by default;
     the our_initiator flag is pre-determined by connection direction. *)
  ps.is_initiator <- our_initiator;
  Hashtbl.replace state.peer_states peer_id ps;
  (* Send our own sendtxrcncl if we haven't already *)
  Some (SendtxrcnclMsg {
    recon_version = erlay_protocol_version;
    recon_salt = Int64.of_float (Unix.gettimeofday () *. 1000.0);
  })

(* Add a transaction to the reconciliation set for all Erlay peers.
   Called when we accept a tx into the mempool via Erlay (not fanout). *)
let add_tx_to_reconciliation_sets (state : erlay_state) (txid : Types.hash256) : unit =
  let key = Cstruct.to_string txid in
  Hashtbl.iter (fun _peer_id ps ->
    if ps.recon_enabled then
      Hashtbl.replace ps.local_set key ()
  ) state.peer_states

(* Initiate a reconciliation round with a peer.
   Sends reqrecon with our set size and a capacity coefficient q.
   Returns the message to send, or None if reconciliation is not due. *)
let initiate_reconciliation (state : erlay_state) (peer_id : int)
    : message_payload option =
  match Hashtbl.find_opt state.peer_states peer_id with
  | None -> None
  | Some ps ->
    if not ps.recon_enabled || ps.pending_recon then None
    else
      let now = Unix.gettimeofday () in
      if now -. ps.last_recon_time < state.recon_interval then None
      else begin
        ps.pending_recon <- true;
        let set_size = Hashtbl.length ps.local_set in
        (* q coefficient: ratio of set sizes, encoded as fixed-point.
           For the initial request, use set_size as an approximation. *)
        Some (ReqreconMsg {
          recon_set_size = Int32.of_int set_size;
          recon_q = Int32.of_int (max 1 (set_size / 2));
        })
      end

(* Handle incoming reqrecon: peer requests reconciliation.
   We compute a sketch of our local set and send it back. *)
let handle_reqrecon (state : erlay_state) (peer_id : int) (_msg : reqrecon_msg)
    : message_payload option =
  match Hashtbl.find_opt state.peer_states peer_id with
  | None -> None
  | Some ps ->
    if not ps.recon_enabled then None
    else begin
      (* Build a minisketch from our local reconciliation set.
         In a full implementation this would use an actual minisketch library.
         Here we send a serialized set of short txid hashes. *)
      let sketch_buf = Buffer.create 256 in
      Hashtbl.iter (fun txid_key () ->
        (* Use first 8 bytes of txid as short ID for the sketch *)
        let short_id = if String.length txid_key >= 8
          then String.sub txid_key 0 8
          else txid_key in
        Buffer.add_string sketch_buf short_id
      ) ps.local_set;
      let sketch_data = Cstruct.of_string (Buffer.contents sketch_buf) in
      Some (SketchMsg { sketch_data })
    end

(* Handle incoming sketch: peer sends their reconciliation sketch.
   We decode it against our local set to find the symmetric difference,
   then send reconcildiff with the txids we need and the ones we can announce. *)
let handle_sketch (state : erlay_state) (peer_id : int) (msg : sketch_msg)
    : message_payload option =
  match Hashtbl.find_opt state.peer_states peer_id with
  | None -> None
  | Some ps ->
    if not ps.recon_enabled then None
    else begin
      (* Decode the sketch to find txids the peer has that we don't (ask_txids)
         and txids we have that the peer doesn't (announce_txids).
         In a full implementation, this uses minisketch decode. *)
      let remote_ids : (string, unit) Hashtbl.t = Hashtbl.create 64 in
      let data = Cstruct.to_string msg.sketch_data in
      let pos = ref 0 in
      while !pos + 8 <= String.length data do
        let short_id = String.sub data !pos 8 in
        Hashtbl.replace remote_ids short_id ();
        pos := !pos + 8
      done;

      (* Compute symmetric difference *)
      let ask_txids = ref [] in    (* txids peer has, we don't *)
      let announce_txids = ref [] in  (* txids we have, peer doesn't *)

      Hashtbl.iter (fun short_id () ->
        let local_key = Hashtbl.fold (fun k () found ->
          if found <> "" then found
          else if String.length k >= 8 && String.sub k 0 8 = short_id then k
          else ""
        ) ps.local_set "" in
        if local_key = "" then
          ask_txids := Cstruct.of_string short_id :: !ask_txids
      ) remote_ids;

      Hashtbl.iter (fun full_key () ->
        let short_id = if String.length full_key >= 8
          then String.sub full_key 0 8
          else full_key in
        if not (Hashtbl.mem remote_ids short_id) then
          announce_txids := Cstruct.of_string full_key :: !announce_txids
      ) ps.local_set;

      (* Clear the reconciliation set and mark round complete *)
      Hashtbl.clear ps.local_set;
      ps.pending_recon <- false;
      ps.last_recon_time <- Unix.gettimeofday ();

      let success = true in (* Sketch decoded successfully *)
      Some (ReconcildiffMsg {
        success;
        ask_short_ids = !ask_txids;
        announce_short_ids = !announce_txids;
      })
    end

(* Handle incoming reconcildiff: peer tells us what they need and what they have.
   - ask_txids: txids the peer wants us to send (we announce via inv)
   - announce_txids: txids the peer is announcing to us (we request via getdata)
   Returns (inv_items, getdata_items) to be sent. *)
let handle_reconcildiff (state : erlay_state) (peer_id : int) (msg : reconcildiff_msg)
    : (inv_vector list * inv_vector list) =
  (match Hashtbl.find_opt state.peer_states peer_id with
   | None -> ()
   | Some ps ->
     ps.pending_recon <- false;
     ps.last_recon_time <- Unix.gettimeofday ();
     Hashtbl.clear ps.local_set);

  if not msg.success then
    (* Reconciliation failed; fall back to flooding for this round *)
    ([], [])
  else begin
    (* Build inv messages for txids the peer asked for *)
    let inv_items = List.map (fun short_id ->
      { inv_type = InvTx;
        hash = short_id }
    ) msg.ask_short_ids in
    (* Build getdata for txids the peer announced *)
    let getdata_items = List.map (fun short_id ->
      { inv_type = InvTx;
        hash = short_id }
    ) msg.announce_short_ids in
    (inv_items, getdata_items)
  end

(* Remove a peer's Erlay state (on disconnect) *)
let remove_erlay_peer (state : erlay_state) (peer_id : int) : unit =
  Hashtbl.remove state.peer_states peer_id

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

  (* AEAD_CHACHA20_POLY1305 encrypt / decrypt — RFC 8439 + IETF mode.

     We delegate to mirage-crypto's verified Chacha20.authenticate_encrypt /
     authenticate_decrypt rather than wiring our hand-rolled chacha20_crypt
     to our hand-rolled poly1305_mac. The previous in-tree wiring carried
     two latent Int64 sign-extension bugs in poly1305_mac that produced
     wrong tags for any AAD/key/message in which a 32-bit dword had bit 31
     set — i.e., on roughly half of all real BIP-324 sessions. mirage-crypto
     Chacha20 is RFC-8439-validated and treats nonce = 12 bytes, counter =
     32-bit, exactly matching BIP-324 semantics. *)
  let encrypt ~(key : Cstruct.t) ~(nonce : Cstruct.t) ~(aad : Cstruct.t) ~(plaintext : Cstruct.t) : Cstruct.t =
    let mc_key = Mirage_crypto.Chacha20.of_secret (Cstruct.to_string key) in
    let nonce_s = Cstruct.to_string nonce in
    let adata = Cstruct.to_string aad in
    let pt = Cstruct.to_string plaintext in
    let ct_with_tag = Mirage_crypto.Chacha20.authenticate_encrypt
        ~key:mc_key ~nonce:nonce_s ~adata pt
    in
    Cstruct.of_string ct_with_tag

  let decrypt ~(key : Cstruct.t) ~(nonce : Cstruct.t) ~(aad : Cstruct.t) ~(ciphertext_and_tag : Cstruct.t) : Cstruct.t option =
    let mc_key = Mirage_crypto.Chacha20.of_secret (Cstruct.to_string key) in
    let nonce_s = Cstruct.to_string nonce in
    let adata = Cstruct.to_string aad in
    let ct = Cstruct.to_string ciphertext_and_tag in
    match Mirage_crypto.Chacha20.authenticate_decrypt
            ~key:mc_key ~nonce:nonce_s ~adata ct
    with
    | Some pt -> Some (Cstruct.of_string pt)
    | None -> None
end

(* Forward-Secure ChaCha20Poly1305 with rekeying (FSChaCha20Poly1305)
   Per BIP324: rekeys every REKEY_INTERVAL messages.

   Per-packet nonce:    LE32(packet_counter) || LE64(rekey_counter)
   Per-packet AEAD:     standard ChaCha20-Poly1305 (block 0 = poly key,
                        block 1+ = ciphertext keystream).
   Rekey trigger:       after the (REKEY_INTERVAL - 1)-th packet of an epoch,
                        i.e. just before packet_counter would wrap to 0.
   Rekey nonce:         LE32(0xFFFFFFFF) || LE64(rekey_counter)
                        (NOT packet_counter — Bitcoin Core puts a sentinel
                         in the packet-counter slot to avoid colliding with
                         a real packet-nonce).
   Rekey body:          AEAD-encrypt 32 zero bytes under (old_key, rekey_nonce,
                        empty aad); the new key is the first 32 bytes of the
                        ciphertext (which is just the keystream of block 1
                        XOR'd with zeros — equivalent to ChaCha20 block 1
                        first 32 bytes; block 0 is reserved for the Poly1305
                        one-time key and must NOT be reused as keying
                        material). *)
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

  (* Per-packet nonce:
       bytes 0..3 = packet_counter (LE32)
       bytes 4..11 = rekey_counter  (LE64) *)
  let make_packet_nonce (t : t) : Cstruct.t =
    let nonce = Cstruct.create 12 in
    Cstruct.LE.set_uint32 nonce 0 (Int32.of_int t.packet_counter);
    Cstruct.LE.set_uint64 nonce 4 t.rekey_counter;
    nonce

  (* Rekey nonce:
       bytes 0..3 = 0xFFFFFFFF sentinel (NOT packet_counter)
       bytes 4..11 = rekey_counter (LE64)
     This matches Bitcoin Core (chacha20poly1305.cpp NextPacket):
       m_aead.Keystream({0xFFFFFFFF, m_rekey_counter}, ...) *)
  let make_rekey_nonce (t : t) : Cstruct.t =
    let nonce = Cstruct.create 12 in
    Cstruct.LE.set_uint32 nonce 0 0xFFFFFFFFl;
    Cstruct.LE.set_uint64 nonce 4 t.rekey_counter;
    nonce

  (* Advance to next packet, rekey if needed.
     Bitcoin Core increments packet_counter then tests == rekey_interval, so a
     rekey occurs after exactly rekey_interval packets in the current epoch. *)
  let next_packet (t : t) : unit =
    t.packet_counter <- t.packet_counter + 1;
    if t.packet_counter = t.rekey_interval then begin
      (* New key = AEAD_ChaCha20Poly1305(old_key, rekey_nonce, "", 32-zeros)[0:32]
         which is exactly the first 32 bytes of ChaCha20 keystream block 1
         under (old_key, rekey_nonce). We compute it directly via the
         ChaCha20 block function (block index = 1) to avoid building a
         full AEAD frame just to discard the tag. *)
      let rekey_nonce = make_rekey_nonce t in
      let keystream_block1 = ChaCha20Poly1305.chacha20_block t.key rekey_nonce 1l in
      t.key <- Cstruct.sub_copy keystream_block1 0 32;
      t.packet_counter <- 0;
      t.rekey_counter <- Int64.add t.rekey_counter 1L
    end

  let encrypt (t : t) ~(aad : Cstruct.t) ~(plaintext : Cstruct.t) : Cstruct.t =
    let nonce = make_packet_nonce t in
    let result = ChaCha20Poly1305.encrypt ~key:t.key ~nonce ~aad ~plaintext in
    next_packet t;
    result

  let decrypt (t : t) ~(aad : Cstruct.t) ~(ciphertext : Cstruct.t) : Cstruct.t option =
    let nonce = make_packet_nonce t in
    let result = ChaCha20Poly1305.decrypt ~key:t.key ~nonce ~aad ~ciphertext_and_tag:ciphertext in
    next_packet t;
    result
end

(* FSChaCha20 for length encryption (no authentication).

   Per BIP-324 + Bitcoin Core (crypto/chacha20.cpp FSChaCha20::Crypt), the
   length cipher must produce a CONTINUOUS keystream within a rekey epoch:
   one ChaCha20 stream cipher seeded with (key, nonce=(0||LE64(rekey_counter)),
   block_counter=0) and advanced naturally by every Crypt() call. The
   "packet counter" only triggers the rekey after rekey_interval crypts; it
   does NOT enter the nonce.

   The previous implementation rebuilt a fresh ChaCha20 from block 0 every
   Crypt() and stuffed packet_counter into the nonce. That decrypts the very
   first packet's length field correctly (both sides happen to seed from
   block 0), but every subsequent packet uses a different keystream than the
   peer expects, so the length prefix becomes garbage and the AEAD payload
   that follows fails authentication. This is the same family of bug that
   was fixed in clearbit (cb04a1f), haskoin (5343d02), blockbrew (7351ce8)
   and others.

   Rekey, per Core: at rekey_interval packets, draw the next 32 bytes of
   keystream (which is buffered, advancing block_counter past the data
   consumed so far) as the new key, then Seek to (block 0, nonce =
   (0 || LE64(++rekey_counter))) and reset the keystream buffer. *)
module FSChaCha20 = struct
  type t = {
    mutable key : Cstruct.t;
    rekey_interval : int;
    mutable packet_counter : int;
    mutable rekey_counter : int64;
    (* Stateful keystream buffer: holds the unconsumed tail of the most
       recently-generated 64-byte keystream block, plus a block_counter
       that records the index of the NEXT block to generate. *)
    mutable block_counter : int32;
    mutable buffer : Cstruct.t;        (* 0..64 bytes of keystream *)
  }

  let create (key : Cstruct.t) (rekey_interval : int) : t =
    { key = Cstruct.sub_copy key 0 32;
      rekey_interval;
      packet_counter = 0;
      rekey_counter = 0L;
      block_counter = 0l;
      buffer = Cstruct.create 0 }

  (* Epoch nonce: bytes 0..3 = 0, bytes 4..11 = rekey_counter (LE64).
     Constant within a rekey epoch — what changes per call is the
     internal block_counter, not the nonce. *)
  let epoch_nonce (t : t) : Cstruct.t =
    let nonce = Cstruct.create 12 in
    Cstruct.LE.set_uint32 nonce 0 0l;
    Cstruct.LE.set_uint64 nonce 4 t.rekey_counter;
    nonce

  (* Pull `nbytes` of keystream from the continuing ChaCha20 stream,
     refilling the 64-byte buffer as needed. *)
  let get_keystream (t : t) (nbytes : int) : Cstruct.t =
    let out = Cstruct.create nbytes in
    let written = ref 0 in
    while !written < nbytes do
      if Cstruct.length t.buffer = 0 then begin
        (* Need a fresh block. *)
        let nonce = epoch_nonce t in
        t.buffer <- ChaCha20Poly1305.chacha20_block t.key nonce t.block_counter;
        t.block_counter <- Int32.add t.block_counter 1l
      end;
      let avail = Cstruct.length t.buffer in
      let want = nbytes - !written in
      let n = if avail < want then avail else want in
      Cstruct.blit t.buffer 0 out !written n;
      (* Drop n bytes from the front of the buffer. *)
      t.buffer <- Cstruct.sub t.buffer n (avail - n);
      written := !written + n
    done;
    out

  (* Reset keystream state to start of a new epoch. *)
  let begin_new_epoch (t : t) (new_key : Cstruct.t) : unit =
    t.key <- Cstruct.sub_copy new_key 0 32;
    t.packet_counter <- 0;
    t.rekey_counter <- Int64.add t.rekey_counter 1L;
    t.block_counter <- 0l;
    t.buffer <- Cstruct.create 0

  (* Encrypt/decrypt the 3-byte length field with the continuing keystream,
     then optionally rekey. *)
  let crypt (t : t) (data : Cstruct.t) : Cstruct.t =
    let len = Cstruct.length data in
    let ks = get_keystream t len in
    let out = Cstruct.create len in
    for i = 0 to len - 1 do
      Cstruct.set_uint8 out i
        (Cstruct.get_uint8 data i lxor Cstruct.get_uint8 ks i)
    done;
    t.packet_counter <- t.packet_counter + 1;
    if t.packet_counter = t.rekey_interval then begin
      (* New key = next 32 bytes of the current epoch's keystream.
         This consumes from the buffer + advances block_counter as needed,
         exactly like Bitcoin Core's m_chacha20.Keystream(new_key). *)
      let new_key = get_keystream t 32 in
      begin_new_epoch t new_key
    end;
    out
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
  (* True iff [recv_len] has been decrypted for the in-flight packet but
     the payload has not yet been fully received.  Disambiguates the
     "no length read yet" case from the "length is zero" case (BIP-324's
     version packet has empty contents per spec, so [recv_len] = 0 is
     a valid post-decrypt state).  Without this flag the FSChaCha20 length
     cipher's keystream advances twice for the same packet on every empty
     payload — corrupting all subsequent length decrypts and stalling the
     handshake on the responder side. *)
  mutable recv_len_known : bool;
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

(* libsecp256k1 ElligatorSwift FFI (see lib/schnorr_stubs.c).
   Backed by secp256k1_ellswift_create / secp256k1_ellswift_xdh with
   secp256k1_ellswift_xdh_hash_function_bip324 — i.e. real BIP-324 v2,
   not a placeholder. *)
external ellswift_create_raw : Bigstring.t -> Bigstring.t -> Bigstring.t
  = "caml_ellswift_create"
external ellswift_xdh_raw : Bigstring.t -> Bigstring.t -> Bigstring.t -> bool -> Bigstring.t
  = "caml_ellswift_xdh"

(* Compute ElligatorSwift encoding of the public key for [privkey] (64 bytes).
   Uses libsecp256k1's secp256k1_ellswift_create. The 32 bytes of auxrand
   are read from /dev/urandom; per BIP-324 / libsecp256k1, this just
   strengthens uniformity of the encoding and is not load-bearing for
   correctness. *)
let compute_ellswift_pubkey (privkey : Cstruct.t) : Cstruct.t =
  if Cstruct.length privkey <> 32 then
    invalid_arg "compute_ellswift_pubkey: privkey must be 32 bytes";
  let sk_bs = Crypto.cstruct_to_bigstring privkey in
  let aux_cs = Cstruct.create 32 in
  let ic = open_in_bin "/dev/urandom" in
  let aux = really_input_string ic 32 in
  close_in ic;
  Cstruct.blit_from_string aux 0 aux_cs 0 32;
  let aux_bs = Crypto.cstruct_to_bigstring aux_cs in
  let ell_bs = ellswift_create_raw sk_bs aux_bs in
  Crypto.bigstring_to_cstruct ell_bs

(* Compute the BIP-324 32-byte ECDH shared secret from our private key,
   our 64-byte ElligatorSwift encoding, and the peer's 64-byte ElligatorSwift
   encoding. Calls secp256k1_ellswift_xdh with the BIP-324 hash function.
   The party byte is derived from [initiator] inside the C stub. *)
let compute_ecdh_secret (our_privkey : Cstruct.t) (their_ellswift : Cstruct.t)
    (our_ellswift : Cstruct.t) (initiator : bool) : Cstruct.t =
  if Cstruct.length our_privkey <> 32 then
    invalid_arg "compute_ecdh_secret: privkey must be 32 bytes";
  if Cstruct.length their_ellswift <> 64 then
    invalid_arg "compute_ecdh_secret: their_ellswift must be 64 bytes";
  if Cstruct.length our_ellswift <> 64 then
    invalid_arg "compute_ecdh_secret: our_ellswift must be 64 bytes";
  let sk_bs = Crypto.cstruct_to_bigstring our_privkey in
  let their_bs = Crypto.cstruct_to_bigstring their_ellswift in
  let our_bs = Crypto.cstruct_to_bigstring our_ellswift in
  let shared_bs = ellswift_xdh_raw sk_bs their_bs our_bs initiator in
  Crypto.bigstring_to_cstruct shared_bs

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
    recv_len_known = false;
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
      (* Read 3-byte encrypted length if we don't have it.  The FSChaCha20
         length cipher advances by exactly one chunk per packet, so we MUST
         decrypt the length only once even if we re-enter this branch while
         waiting for the rest of the ciphertext.  Use [recv_len_known] (not
         [recv_len = 0]) as the sentinel — version/decoy packets legitimately
         carry [recv_len = 0] (empty contents), and re-decrypting the next 3
         bytes as a fresh length corrupts the keystream and produces garbage
         length values that wedge the responder. *)
      if not state.recv_len_known then begin
        if Cstruct.length state.recv_buffer >= Bip324.length_len then begin
          let enc_len = Cstruct.sub state.recv_buffer 0 Bip324.length_len in
          state.recv_len <- bip324_decrypt_length cipher enc_len;
          state.recv_len_known <- true;
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
            (* Reset per-packet length tracking for the next packet. *)
            state.recv_len <- 0;
            state.recv_len_known <- false;
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

(* ============================================================================
   SOCKS5 Proxy Client (RFC 1928)

   Implements SOCKS5 handshake for connecting through proxies like Tor.
   Reference: Bitcoin Core netbase.cpp Socks5(), ConnectThroughProxy()
   ============================================================================ *)

module Socks5 = struct
  (* SOCKS5 constants *)
  let version = 0x05
  let auth_none = 0x00
  let auth_username_password = 0x02
  let auth_no_acceptable = 0xFF
  let cmd_connect = 0x01
  let atyp_ipv4 = 0x01
  let atyp_domain = 0x03
  let atyp_ipv6 = 0x04

  (* SOCKS5 reply codes *)
  type reply_code =
    | Succeeded
    | GeneralFailure
    | NotAllowed
    | NetworkUnreachable
    | HostUnreachable
    | ConnectionRefused
    | TtlExpired
    | CommandNotSupported
    | AddressTypeNotSupported
    (* Tor-specific error codes *)
    | TorOnionNotFound        (* 0xF0 *)
    | TorOnionInvalid         (* 0xF1 *)
    | TorIntroFailed          (* 0xF2 *)
    | TorRendFailed           (* 0xF3 *)
    | TorMissingAuth          (* 0xF4 *)
    | TorWrongAuth            (* 0xF5 *)
    | TorBadAddress           (* 0xF6 *)
    | TorIntroTimeout         (* 0xF7 *)
    | UnknownError of int

  let reply_code_of_int = function
    | 0x00 -> Succeeded
    | 0x01 -> GeneralFailure
    | 0x02 -> NotAllowed
    | 0x03 -> NetworkUnreachable
    | 0x04 -> HostUnreachable
    | 0x05 -> ConnectionRefused
    | 0x06 -> TtlExpired
    | 0x07 -> CommandNotSupported
    | 0x08 -> AddressTypeNotSupported
    | 0xF0 -> TorOnionNotFound
    | 0xF1 -> TorOnionInvalid
    | 0xF2 -> TorIntroFailed
    | 0xF3 -> TorRendFailed
    | 0xF4 -> TorMissingAuth
    | 0xF5 -> TorWrongAuth
    | 0xF6 -> TorBadAddress
    | 0xF7 -> TorIntroTimeout
    | n -> UnknownError n

  let reply_code_to_string = function
    | Succeeded -> "succeeded"
    | GeneralFailure -> "general failure"
    | NotAllowed -> "connection not allowed"
    | NetworkUnreachable -> "network unreachable"
    | HostUnreachable -> "host unreachable"
    | ConnectionRefused -> "connection refused"
    | TtlExpired -> "TTL expired"
    | CommandNotSupported -> "command not supported"
    | AddressTypeNotSupported -> "address type not supported"
    | TorOnionNotFound -> "onion service descriptor not found"
    | TorOnionInvalid -> "onion service descriptor invalid"
    | TorIntroFailed -> "onion service introduction failed"
    | TorRendFailed -> "onion service rendezvous failed"
    | TorMissingAuth -> "onion service missing client authorization"
    | TorWrongAuth -> "onion service wrong client authorization"
    | TorBadAddress -> "onion service invalid address"
    | TorIntroTimeout -> "onion service introduction timed out"
    | UnknownError n -> Printf.sprintf "unknown error (0x%02x)" n

  (* Proxy credentials for Tor stream isolation *)
  type credentials = {
    username : string;
    password : string;
  }

  (* SOCKS5 connection result *)
  type connect_result =
    | Connected of Lwt_unix.file_descr
    | ProxyError of string
    | TargetError of reply_code

  (* SOCKS5 receive timeout (Tor can be slow) *)
  let recv_timeout = 60.0  (* 60 seconds *)

  (* Read exactly n bytes with timeout *)
  let read_exact_timeout (ic : Lwt_io.input_channel) (n : int) : bytes option Lwt.t =
    let open Lwt.Syntax in
    let buf = Bytes.create n in
    let read_task =
      let* () = Lwt_io.read_into_exactly ic buf 0 n in
      Lwt.return (Some buf)
    in
    let timeout_task =
      let* () = Lwt_unix.sleep recv_timeout in
      Lwt.return None
    in
    Lwt.pick [read_task; timeout_task]

  (* Connect through a SOCKS5 proxy.
     This establishes a connection to the proxy, performs the SOCKS5 handshake,
     and returns an fd connected to the target through the proxy.

     For .onion addresses, the hostname is passed through SOCKS5 and DNS
     resolution happens on the Tor side. *)
  let connect ~(proxy_addr : string) ~(proxy_port : int)
      ?(credentials : credentials option) ~(target_host : string)
      ~(target_port : int) () : connect_result Lwt.t =
    let open Lwt.Syntax in

    (* Validate hostname length (SOCKS5 limit is 255 bytes) *)
    if String.length target_host > 255 then
      Lwt.return (ProxyError "hostname too long (max 255 bytes)")
    else begin
      (* Resolve proxy address and connect *)
      let* addresses =
        Lwt.catch
          (fun () -> Lwt_unix.getaddrinfo proxy_addr (string_of_int proxy_port)
              [Unix.AI_SOCKTYPE Unix.SOCK_STREAM])
          (fun _ -> Lwt.return [])
      in
      match addresses with
      | [] -> Lwt.return (ProxyError (Printf.sprintf "cannot resolve proxy: %s" proxy_addr))
      | ai :: _ ->
        let fd = Lwt_unix.socket ai.ai_family ai.ai_socktype ai.ai_protocol in
        Lwt.catch (fun () ->
          (* Connect to proxy with timeout *)
          let connect_task = Lwt_unix.connect fd ai.ai_addr in
          let timeout_task =
            let* () = Lwt_unix.sleep 10.0 in
            Lwt.fail_with "proxy connection timeout"
          in
          let* () = Lwt.pick [connect_task; timeout_task] in

          let ic = Lwt_io.of_fd ~mode:Lwt_io.Input fd in
          let oc = Lwt_io.of_fd ~mode:Lwt_io.Output fd in

          (* Step 1: Send greeting - version, number of methods, methods *)
          let greeting = match credentials with
            | None -> Bytes.of_string (Printf.sprintf "%c%c%c"
                (Char.chr version) (Char.chr 1) (Char.chr auth_none))
            | Some _ -> Bytes.of_string (Printf.sprintf "%c%c%c%c"
                (Char.chr version) (Char.chr 2) (Char.chr auth_none) (Char.chr auth_username_password))
          in
          let* () = Lwt_io.write_from_exactly oc greeting 0 (Bytes.length greeting) in
          let* () = Lwt_io.flush oc in

          (* Step 2: Receive method selection *)
          let* method_response = read_exact_timeout ic 2 in
          match method_response with
          | None ->
            let* () = Lwt_unix.close fd in
            Lwt.return (ProxyError "timeout waiting for proxy greeting response")
          | Some resp ->
            let resp_version = Char.code (Bytes.get resp 0) in
            let selected_method = Char.code (Bytes.get resp 1) in

            if resp_version <> version then begin
              let* () = Lwt_unix.close fd in
              Lwt.return (ProxyError (Printf.sprintf "proxy returned wrong version: %d" resp_version))
            end else if selected_method = auth_no_acceptable then begin
              let* () = Lwt_unix.close fd in
              Lwt.return (ProxyError "proxy: no acceptable authentication method")
            end else begin
              (* Step 3: Handle authentication if required *)
              let* auth_ok =
                if selected_method = auth_username_password then begin
                  match credentials with
                  | None ->
                    Lwt.return (Error "proxy requires authentication but no credentials provided")
                  | Some cred ->
                    if String.length cred.username > 255 || String.length cred.password > 255 then
                      Lwt.return (Error "username or password too long")
                    else begin
                      (* Send username/password authentication (RFC 1929) *)
                      let auth_buf = Bytes.create (3 + String.length cred.username + String.length cred.password) in
                      Bytes.set auth_buf 0 (Char.chr 0x01);  (* subnegotiation version *)
                      Bytes.set auth_buf 1 (Char.chr (String.length cred.username));
                      Bytes.blit_string cred.username 0 auth_buf 2 (String.length cred.username);
                      let pw_offset = 2 + String.length cred.username in
                      Bytes.set auth_buf pw_offset (Char.chr (String.length cred.password));
                      Bytes.blit_string cred.password 0 auth_buf (pw_offset + 1) (String.length cred.password);
                      let* () = Lwt_io.write_from_exactly oc auth_buf 0 (Bytes.length auth_buf) in
                      let* () = Lwt_io.flush oc in

                      (* Receive auth response *)
                      let* auth_response = read_exact_timeout ic 2 in
                      match auth_response with
                      | None -> Lwt.return (Error "timeout waiting for auth response")
                      | Some auth_resp ->
                        let auth_version = Char.code (Bytes.get auth_resp 0) in
                        let auth_status = Char.code (Bytes.get auth_resp 1) in
                        if auth_version <> 0x01 || auth_status <> 0x00 then
                          Lwt.return (Error "proxy authentication failed")
                        else
                          Lwt.return (Ok ())
                    end
                end else
                  Lwt.return (Ok ())
              in

              match auth_ok with
              | Error msg ->
                let* () = Lwt_unix.close fd in
                Lwt.return (ProxyError msg)
              | Ok () ->
                (* Step 4: Send connect request *)
                (* Format: VER=5, CMD=1 (connect), RSV=0, ATYP=3 (domain), LEN, ADDR, PORT *)
                let connect_buf = Bytes.create (7 + String.length target_host) in
                Bytes.set connect_buf 0 (Char.chr version);
                Bytes.set connect_buf 1 (Char.chr cmd_connect);
                Bytes.set connect_buf 2 (Char.chr 0x00);  (* reserved *)
                Bytes.set connect_buf 3 (Char.chr atyp_domain);
                Bytes.set connect_buf 4 (Char.chr (String.length target_host));
                Bytes.blit_string target_host 0 connect_buf 5 (String.length target_host);
                let port_offset = 5 + String.length target_host in
                Bytes.set connect_buf port_offset (Char.chr ((target_port lsr 8) land 0xFF));
                Bytes.set connect_buf (port_offset + 1) (Char.chr (target_port land 0xFF));
                let* () = Lwt_io.write_from_exactly oc connect_buf 0 (Bytes.length connect_buf) in
                let* () = Lwt_io.flush oc in

                (* Step 5: Receive connect response (at least 4 bytes header) *)
                let* connect_response = read_exact_timeout ic 4 in
                match connect_response with
                | None ->
                  let* () = Lwt_unix.close fd in
                  Lwt.return (ProxyError "timeout waiting for connect response")
                | Some resp ->
                  let resp_version = Char.code (Bytes.get resp 0) in
                  let reply = Char.code (Bytes.get resp 1) in
                  (* let _reserved = Char.code (Bytes.get resp 2) in *)
                  let atyp = Char.code (Bytes.get resp 3) in

                  if resp_version <> version then begin
                    let* () = Lwt_unix.close fd in
                    Lwt.return (ProxyError "proxy returned wrong version in connect response")
                  end else begin
                    let reply_code = reply_code_of_int reply in
                    if reply_code <> Succeeded then begin
                      let* () = Lwt_unix.close fd in
                      Lwt.return (TargetError reply_code)
                    end else begin
                      (* Skip bound address based on address type *)
                      let* skip_result =
                        match atyp with
                        | 0x01 -> (* IPv4: 4 bytes addr + 2 bytes port *)
                          read_exact_timeout ic 6
                        | 0x04 -> (* IPv6: 16 bytes addr + 2 bytes port *)
                          read_exact_timeout ic 18
                        | 0x03 -> (* Domain: 1 byte len, then len bytes + 2 bytes port *)
                          let* len_byte = read_exact_timeout ic 1 in
                          (match len_byte with
                           | None -> Lwt.return None
                           | Some lb ->
                             let len = Char.code (Bytes.get lb 0) in
                             read_exact_timeout ic (len + 2))
                        | _ ->
                          Lwt.return None
                      in
                      match skip_result with
                      | None ->
                        let* () = Lwt_unix.close fd in
                        Lwt.return (ProxyError "error reading bound address")
                      | Some _ ->
                        (* Success! Return the connected fd *)
                        Lwt.return (Connected fd)
                    end
                  end
            end
        ) (fun exn ->
          let* () = Lwt.catch (fun () -> Lwt_unix.close fd) (fun _ -> Lwt.return_unit) in
          Lwt.return (ProxyError (Printf.sprintf "SOCKS5 error: %s" (Printexc.to_string exn)))
        )
    end

  (* Check if an address is a .onion address *)
  let is_onion_address (host : string) : bool =
    let lower = String.lowercase_ascii host in
    String.length lower > 6 && String.sub lower (String.length lower - 6) 6 = ".onion"

  (* Check if an address is a .b32.i2p address *)
  let is_i2p_address (host : string) : bool =
    let lower = String.lowercase_ascii host in
    String.length lower > 8 && String.sub lower (String.length lower - 8) 8 = ".b32.i2p"
end

(* ============================================================================
   I2P SAM Protocol Client

   Implements the SAM 3.1 protocol for connecting to I2P destinations.
   Reference: Bitcoin Core i2p.cpp, https://geti2p.net/en/docs/api/samv3
   ============================================================================ *)

module I2P = struct
  (* I2P SAM default port *)
  let sam_default_port = 7656

  (* I2P uses port 0 for all connections (SAM 3.1 doesn't use ports) *)
  let i2p_port = 0

  (* SAM session styles *)
  type session_style = Stream | Datagram | Raw

  (* SAM reply result *)
  type sam_result =
    | Ok of (string * string) list  (* key=value pairs *)
    | Error of string

  (* Parse a SAM reply line into key=value pairs *)
  let parse_sam_reply (line : string) : (string * string) list =
    let parts = String.split_on_char ' ' line in
    List.filter_map (fun part ->
      match String.index_opt part '=' with
      | Some pos ->
        let key = String.sub part 0 pos in
        let value = String.sub part (pos + 1) (String.length part - pos - 1) in
        Some (key, value)
      | None -> None
    ) parts

  (* Read a line from the SAM bridge (terminated by \n) *)
  let read_sam_line (ic : Lwt_io.input_channel) : string option Lwt.t =
    let open Lwt.Syntax in
    let read_task =
      let* line = Lwt_io.read_line ic in
      Lwt.return (Some line)
    in
    let timeout_task =
      let* () = Lwt_unix.sleep 60.0 in
      Lwt.return None
    in
    Lwt.catch
      (fun () -> Lwt.pick [read_task; timeout_task])
      (fun _ -> Lwt.return None)

  (* Send a SAM command and get the reply *)
  let sam_command (ic : Lwt_io.input_channel) (oc : Lwt_io.output_channel)
      (cmd : string) : sam_result Lwt.t =
    let open Lwt.Syntax in
    let* () = Lwt_io.write oc (cmd ^ "\n") in
    let* () = Lwt_io.flush oc in
    let* response = read_sam_line ic in
    match response with
    | None -> Lwt.return (Error "timeout waiting for SAM response")
    | Some line ->
      let pairs = parse_sam_reply line in
      let result = List.assoc_opt "RESULT" pairs in
      match result with
      | Some "OK" -> Lwt.return (Ok pairs)
      | Some err ->
        let message = match List.assoc_opt "MESSAGE" pairs with
          | Some msg -> msg
          | None -> err
        in
        Lwt.return (Error message)
      | None ->
        (* Check if this is a valid reply without RESULT= (like destination) *)
        if pairs <> [] then Lwt.return (Ok pairs)
        else Lwt.return (Error "invalid SAM response")

  (* I2P Base64 uses - and ~ instead of + and / *)
  let i2p_base64_of_std_base64 (s : string) : string =
    String.map (function
      | '+' -> '-'
      | '/' -> '~'
      | c -> c
    ) s

  let std_base64_of_i2p_base64 (s : string) : string =
    String.map (function
      | '-' -> '+'
      | '~' -> '/'
      | c -> c
    ) s

  (* Simple Base32 encoder (RFC 4648) *)
  let base32_encode (data : string) : string =
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" in
    let len = String.length data in
    if len = 0 then "" else
    let out_len = ((len * 8 + 4) / 5) in
    let result = Bytes.create out_len in
    let bit_buffer = ref 0 in
    let bits_in_buffer = ref 0 in
    let out_pos = ref 0 in
    for i = 0 to len - 1 do
      bit_buffer := (!bit_buffer lsl 8) lor (Char.code data.[i]);
      bits_in_buffer := !bits_in_buffer + 8;
      while !bits_in_buffer >= 5 do
        bits_in_buffer := !bits_in_buffer - 5;
        let index = (!bit_buffer lsr !bits_in_buffer) land 0x1F in
        Bytes.set result !out_pos alphabet.[index];
        incr out_pos
      done
    done;
    (* Handle remaining bits *)
    if !bits_in_buffer > 0 then begin
      let index = (!bit_buffer lsl (5 - !bits_in_buffer)) land 0x1F in
      Bytes.set result !out_pos alphabet.[index]
    end;
    Bytes.sub_string result 0 !out_pos

  (* Derive .b32.i2p address from I2P destination (SHA-256 hash of destination) *)
  let dest_to_b32_addr (dest_b64 : string) : string =
    (* Decode I2P Base64 to binary *)
    let std_b64 = std_base64_of_i2p_base64 dest_b64 in
    (* Pad if needed *)
    let padded = std_b64 ^ String.make ((4 - (String.length std_b64 mod 4)) mod 4) '=' in
    let dest_bin = Base64.decode_exn padded in
    (* SHA-256 hash *)
    let hash = Digestif.SHA256.digest_string dest_bin in
    let hash_str = Digestif.SHA256.to_raw_string hash in
    (* Base32 encode (lowercase, no padding) *)
    let b32 = base32_encode hash_str in
    String.lowercase_ascii b32 ^ ".b32.i2p"

  (* Generate a unique session ID *)
  let generate_session_id () : string =
    let ic = open_in_bin "/dev/urandom" in
    let bytes = really_input_string ic 8 in
    close_in ic;
    let hex = String.init 16 (fun i ->
      let nibble = if i mod 2 = 0 then
        (Char.code bytes.[i / 2]) lsr 4
      else
        (Char.code bytes.[i / 2]) land 0xF
      in
      "0123456789abcdef".[nibble]
    ) in
    "camlcoin_" ^ hex

  (* SAM session state *)
  type session = {
    mutable control_fd : Lwt_unix.file_descr option;
    mutable control_ic : Lwt_io.input_channel option;
    mutable control_oc : Lwt_io.output_channel option;
    mutable session_id : string;
    mutable our_dest : string;  (* Our I2P destination in Base64 *)
    mutable our_addr : string;  (* Our .b32.i2p address *)
    sam_addr : string;
    sam_port : int;
    transient : bool;  (* Use transient destination? *)
  }

  (* Create a new SAM session *)
  let create_session ~(sam_addr : string) ~(sam_port : int) ~(transient : bool) : session =
    {
      control_fd = None;
      control_ic = None;
      control_oc = None;
      session_id = "";
      our_dest = "";
      our_addr = "";
      sam_addr;
      sam_port;
      transient;
    }

  (* Connect to SAM bridge and perform handshake *)
  let connect_sam (session : session) : (Lwt_io.input_channel * Lwt_io.output_channel * Lwt_unix.file_descr) option Lwt.t =
    let open Lwt.Syntax in
    let* addresses =
      Lwt.catch
        (fun () -> Lwt_unix.getaddrinfo session.sam_addr (string_of_int session.sam_port)
            [Unix.AI_SOCKTYPE Unix.SOCK_STREAM])
        (fun _ -> Lwt.return [])
    in
    match addresses with
    | [] -> Lwt.return None
    | ai :: _ ->
      let fd = Lwt_unix.socket ai.ai_family ai.ai_socktype ai.ai_protocol in
      Lwt.catch (fun () ->
        let* () = Lwt_unix.connect fd ai.ai_addr in
        let ic = Lwt_io.of_fd ~mode:Lwt_io.Input fd in
        let oc = Lwt_io.of_fd ~mode:Lwt_io.Output fd in

        (* SAM handshake: HELLO VERSION *)
        let* result = sam_command ic oc "HELLO VERSION MIN=3.1 MAX=3.1" in
        match result with
        | Error _ ->
          let* () = Lwt_unix.close fd in
          Lwt.return None
        | Ok _ -> Lwt.return (Some (ic, oc, fd))
      ) (fun _ ->
        let* () = Lwt.catch (fun () -> Lwt_unix.close fd) (fun _ -> Lwt.return_unit) in
        Lwt.return None
      )

  (* Initialize the session (create destination) *)
  let init_session (session : session) : bool Lwt.t =
    let open Lwt.Syntax in
    let* conn = connect_sam session in
    match conn with
    | None -> Lwt.return false
    | Some (ic, oc, fd) ->
      session.control_fd <- Some fd;
      session.control_ic <- Some ic;
      session.control_oc <- Some oc;
      session.session_id <- generate_session_id ();

      (* Create session with transient or persistent destination *)
      let dest_spec = if session.transient then "TRANSIENT" else "TRANSIENT" in
      let cmd = Printf.sprintf "SESSION CREATE STYLE=STREAM ID=%s DESTINATION=%s SIGNATURE_TYPE=7 i2cp.leaseSetEncType=4,0 inbound.quantity=1 outbound.quantity=1"
        session.session_id dest_spec
      in
      let* result = sam_command ic oc cmd in
      match result with
      | Error msg ->
        let* () = Lwt_unix.close fd in
        session.control_fd <- None;
        session.control_ic <- None;
        session.control_oc <- None;
        ignore msg;
        Lwt.return false
      | Ok pairs ->
        (* Extract our destination from the reply *)
        (match List.assoc_opt "DESTINATION" pairs with
         | Some dest ->
           session.our_dest <- dest;
           session.our_addr <- dest_to_b32_addr dest;
           Lwt.return true
         | None ->
           (* Session created but no destination returned - OK for connect-only *)
           Lwt.return true)

  (* Connect to an I2P destination through this session *)
  let connect (session : session) (dest_b32 : string) : Lwt_unix.file_descr option Lwt.t =
    let open Lwt.Syntax in
    (* Ensure session is initialized *)
    let* init_ok =
      if session.control_fd = None then init_session session
      else Lwt.return true
    in
    if not init_ok then Lwt.return None
    else begin
      (* Create a new socket for this stream connection *)
      let* stream_conn = connect_sam session in
      match stream_conn with
      | None -> Lwt.return None
      | Some (ic, oc, fd) ->
        (* Look up the destination by name (the .b32.i2p address) *)
        let* lookup_result = sam_command ic oc (Printf.sprintf "NAMING LOOKUP NAME=%s" dest_b32) in
        match lookup_result with
        | Error _ ->
          let* () = Lwt_unix.close fd in
          Lwt.return None
        | Ok pairs ->
          let dest = match List.assoc_opt "VALUE" pairs with
            | Some d -> d
            | None -> dest_b32  (* Use as-is if no lookup result *)
          in
          (* Connect to the destination *)
          let* connect_result = sam_command ic oc
            (Printf.sprintf "STREAM CONNECT ID=%s DESTINATION=%s SILENT=false"
               session.session_id dest)
          in
          match connect_result with
          | Error _ ->
            let* () = Lwt_unix.close fd in
            Lwt.return None
          | Ok reply_pairs ->
            let result = List.assoc_opt "RESULT" reply_pairs in
            if result = Some "OK" then
              Lwt.return (Some fd)
            else begin
              let* () = Lwt_unix.close fd in
              Lwt.return None
            end
    end

  (* Close the session *)
  let close_session (session : session) : unit Lwt.t =
    match session.control_fd with
    | None -> Lwt.return_unit
    | Some fd ->
      session.control_fd <- None;
      session.control_ic <- None;
      session.control_oc <- None;
      Lwt.catch (fun () -> Lwt_unix.close fd) (fun _ -> Lwt.return_unit)
end

(* ============================================================================
   Proxy Configuration and Network Detection
   ============================================================================ *)

(* Proxy type *)
type proxy_type =
  | NoProxy
  | Socks5Proxy of {
      addr : string;
      port : int;
      credentials : Socks5.credentials option;
      tor_stream_isolation : bool;  (* Use random credentials for circuit isolation *)
    }
  | I2PSam of {
      addr : string;
      port : int;
    }

(* Network type for routing decisions *)
type network_type =
  | Net_IPv4
  | Net_IPv6
  | Net_Onion
  | Net_I2P
  | Net_CJDNS
  | Net_Internal

(* Detect network type from hostname *)
let network_type_of_host (host : string) : network_type =
  let lower = String.lowercase_ascii host in
  if Socks5.is_onion_address lower then Net_Onion
  else if Socks5.is_i2p_address lower then Net_I2P
  else if String.length lower > 0 && lower.[0] = '[' then Net_IPv6
  else if String.contains lower ':' then Net_IPv6
  else Net_IPv4

(* Proxy configuration *)
type proxy_config = {
  default_proxy : proxy_type;    (* -proxy: default SOCKS5 proxy *)
  onion_proxy : proxy_type;      (* -onion: proxy for .onion addresses *)
  i2p_sam : proxy_type;          (* -i2psam: I2P SAM bridge *)
  onlynet : network_type list;   (* -onlynet: restrict to these networks *)
}

let default_proxy_config : proxy_config = {
  default_proxy = NoProxy;
  onion_proxy = NoProxy;
  i2p_sam = NoProxy;
  onlynet = [];  (* Empty = all networks allowed *)
}

(* Get the appropriate proxy for a target *)
let get_proxy_for_target (config : proxy_config) (host : string) : proxy_type =
  let net_type = network_type_of_host host in
  match net_type with
  | Net_Onion ->
    (* .onion addresses use onion proxy if configured, else default *)
    (match config.onion_proxy with
     | NoProxy -> config.default_proxy
     | proxy -> proxy)
  | Net_I2P ->
    (* .b32.i2p addresses use I2P SAM *)
    config.i2p_sam
  | _ ->
    (* IPv4/IPv6 use default proxy *)
    config.default_proxy

(* Check if a network is allowed by -onlynet *)
let is_network_allowed (config : proxy_config) (net : network_type) : bool =
  match config.onlynet with
  | [] -> true  (* Empty = all allowed *)
  | allowed -> List.mem net allowed

(* Generate random credentials for Tor stream isolation.
   Different credentials = different Tor circuits. *)
let generate_isolation_credentials () : Socks5.credentials =
  let ic = open_in_bin "/dev/urandom" in
  let bytes = really_input_string ic 8 in
  close_in ic;
  let hex = String.init 16 (fun i ->
    let nibble = if i mod 2 = 0 then
      (Char.code bytes.[i / 2]) lsr 4
    else
      (Char.code bytes.[i / 2]) land 0xF
    in
    "0123456789abcdef".[nibble]
  ) in
  { Socks5.username = hex; password = hex }

(* Connect to a target, using proxy if configured *)
let connect_with_proxy ~(config : proxy_config) ~(host : string) ~(port : int)
    : (Lwt_unix.file_descr, string) result Lwt.t =
  let open Lwt.Syntax in
  let net_type = network_type_of_host host in

  (* Check if network is allowed *)
  if not (is_network_allowed config net_type) then
    Lwt.return (Error (Printf.sprintf "network not allowed: %s"
      (match net_type with
       | Net_IPv4 -> "ipv4"
       | Net_IPv6 -> "ipv6"
       | Net_Onion -> "onion"
       | Net_I2P -> "i2p"
       | Net_CJDNS -> "cjdns"
       | Net_Internal -> "internal")))
  else begin
    let proxy = get_proxy_for_target config host in
    match proxy with
    | NoProxy ->
      (* Direct connection *)
      if net_type = Net_Onion || net_type = Net_I2P then
        Lwt.return (Error "cannot connect to .onion/.i2p without proxy")
      else begin
        let* addresses =
          Lwt.catch
            (fun () -> Lwt_unix.getaddrinfo host (string_of_int port)
                [Unix.AI_SOCKTYPE Unix.SOCK_STREAM])
            (fun _ -> Lwt.return [])
        in
        match addresses with
        | [] -> Lwt.return (Error ("cannot resolve: " ^ host))
        | ai :: _ ->
          let fd = Lwt_unix.socket ai.ai_family ai.ai_socktype ai.ai_protocol in
          Lwt.catch (fun () ->
            let* () = Lwt_unix.connect fd ai.ai_addr in
            Lwt.return (Ok fd)
          ) (fun exn ->
            let* () = Lwt.catch (fun () -> Lwt_unix.close fd) (fun _ -> Lwt.return_unit) in
            Lwt.return (Error (Printexc.to_string exn))
          )
      end

    | Socks5Proxy { addr; port = proxy_port; credentials; tor_stream_isolation } ->
      (* SOCKS5 proxy connection *)
      let creds = if tor_stream_isolation then
        Some (generate_isolation_credentials ())
      else
        credentials
      in
      let* result = Socks5.connect ~proxy_addr:addr ~proxy_port ?credentials:creds
          ~target_host:host ~target_port:port ()
      in
      (match result with
       | Socks5.Connected fd -> Lwt.return (Ok fd)
       | Socks5.ProxyError msg -> Lwt.return (Error ("proxy error: " ^ msg))
       | Socks5.TargetError code ->
         Lwt.return (Error ("target unreachable: " ^ Socks5.reply_code_to_string code)))

    | I2PSam { addr; port = sam_port } ->
      (* I2P SAM connection *)
      let session = I2P.create_session ~sam_addr:addr ~sam_port ~transient:true in
      let* fd_opt = I2P.connect session host in
      match fd_opt with
      | Some fd -> Lwt.return (Ok fd)
      | None -> Lwt.return (Error "I2P connection failed")
  end

(* Parse proxy URL: socks5://host:port or socks5://user:pass@host:port *)
let parse_proxy_url (url : string) : proxy_type option =
  let url = String.lowercase_ascii url in
  let prefix = "socks5://" in
  let prefix_len = 9 in
  if String.length url < prefix_len then None
  else if String.sub url 0 prefix_len = prefix then begin
    let rest = String.sub url prefix_len (String.length url - prefix_len) in
    (* Check for credentials *)
    match String.index_opt rest '@' with
    | Some at_pos ->
      let cred_part = String.sub rest 0 at_pos in
      let host_part = String.sub rest (at_pos + 1) (String.length rest - at_pos - 1) in
      (match String.index_opt cred_part ':' with
       | Some colon_pos ->
         let username = String.sub cred_part 0 colon_pos in
         let password = String.sub cred_part (colon_pos + 1) (String.length cred_part - colon_pos - 1) in
         (match String.rindex_opt host_part ':' with
          | Some port_pos ->
            let addr = String.sub host_part 0 port_pos in
            let port_str = String.sub host_part (port_pos + 1) (String.length host_part - port_pos - 1) in
            (match int_of_string_opt port_str with
             | Some port -> Some (Socks5Proxy { addr; port; credentials = Some { Socks5.username; password }; tor_stream_isolation = false })
             | None -> None)
          | None -> None)
       | None -> None)
    | None ->
      (* No credentials, just host:port *)
      (match String.rindex_opt rest ':' with
       | Some port_pos ->
         let addr = String.sub rest 0 port_pos in
         let port_str = String.sub rest (port_pos + 1) (String.length rest - port_pos - 1) in
         (match int_of_string_opt port_str with
          | Some port -> Some (Socks5Proxy { addr; port; credentials = None; tor_stream_isolation = false })
          | None -> None)
       | None -> None)
  end else
    None

(* Parse I2P SAM address: host:port *)
let parse_i2p_sam (addr_port : string) : proxy_type option =
  match String.rindex_opt addr_port ':' with
  | Some pos ->
    let addr = String.sub addr_port 0 pos in
    let port_str = String.sub addr_port (pos + 1) (String.length addr_port - pos - 1) in
    (match int_of_string_opt port_str with
     | Some port -> Some (I2PSam { addr; port })
     | None -> None)
  | None -> None
