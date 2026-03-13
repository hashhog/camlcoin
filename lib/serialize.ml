(* Bitcoin binary serialization format *)

(* Reading from a Cstruct buffer with a mutable offset *)
type reader = {
  buf : Cstruct.t;
  mutable pos : int;
}

let reader_of_cstruct cs = { buf = cs; pos = 0 }

let read_uint8 r =
  let v = Cstruct.get_uint8 r.buf r.pos in
  r.pos <- r.pos + 1;
  v

let read_uint16_le r =
  let v = Cstruct.LE.get_uint16 r.buf r.pos in
  r.pos <- r.pos + 2;
  v

let read_int32_le r =
  let v = Cstruct.LE.get_uint32 r.buf r.pos in
  r.pos <- r.pos + 4;
  v

let read_int64_le r =
  let v = Cstruct.LE.get_uint64 r.buf r.pos in
  r.pos <- r.pos + 8;
  v

let read_bytes r n =
  let cs = Cstruct.sub r.buf r.pos n in
  r.pos <- r.pos + n;
  cs

(* Maximum serialized object size *)
let max_size = 0x02000000  (* 32 MB *)

(* Bitcoin CompactSize unsigned integer encoding:
   value < 0xFD        -> 1 byte
   value <= 0xFFFF     -> 0xFD followed by 2 bytes LE
   value <= 0xFFFFFFFF -> 0xFE followed by 4 bytes LE
   value > 0xFFFFFFFF  -> 0xFF followed by 8 bytes LE
   Rejects non-minimal encodings per Bitcoin Core consensus rules. *)
let read_compact_size r =
  let first = read_uint8 r in
  if first < 0xFD then first
  else if first = 0xFD then begin
    let v = read_uint16_le r in
    if v < 0xFD then failwith "non-canonical CompactSize";
    if v > max_size then failwith "CompactSize exceeds max size";
    v
  end
  else if first = 0xFE then begin
    let v = Int32.to_int (read_int32_le r) in
    if v < 0x10000 then failwith "non-canonical CompactSize";
    if v > max_size then failwith "CompactSize exceeds max size";
    v
  end
  else begin
    let v = Int64.to_int (read_int64_le r) in
    if v < 0x100000000 then failwith "non-canonical CompactSize";
    if v > max_size then failwith "CompactSize exceeds max size";
    v
  end

let read_string r =
  let len = read_compact_size r in
  let cs = read_bytes r len in
  Cstruct.to_string cs

(* Writing to a buffer *)
type writer = {
  mutable buf : Buffer.t;
}

let writer_create () = { buf = Buffer.create 256 }

let write_uint8 w v =
  Buffer.add_char w.buf (Char.chr (v land 0xFF))

let write_uint16_le w v =
  let cs = Cstruct.create 2 in
  Cstruct.LE.set_uint16 cs 0 v;
  Buffer.add_string w.buf (Cstruct.to_string cs)

let write_int32_le w v =
  let cs = Cstruct.create 4 in
  Cstruct.LE.set_uint32 cs 0 v;
  Buffer.add_string w.buf (Cstruct.to_string cs)

let write_int64_le w v =
  let cs = Cstruct.create 8 in
  Cstruct.LE.set_uint64 cs 0 v;
  Buffer.add_string w.buf (Cstruct.to_string cs)

let write_bytes w cs =
  Buffer.add_string w.buf (Cstruct.to_string cs)

let write_compact_size w n =
  if n < 0xFD then write_uint8 w n
  else if n <= 0xFFFF then begin
    write_uint8 w 0xFD;
    write_uint16_le w n
  end else if n <= 0xFFFFFFFF then begin
    write_uint8 w 0xFE;
    write_int32_le w (Int32.of_int n)
  end else begin
    write_uint8 w 0xFF;
    write_int64_le w (Int64.of_int n)
  end

let write_string w s =
  write_compact_size w (String.length s);
  Buffer.add_string w.buf s

let writer_to_cstruct w =
  Cstruct.of_string (Buffer.contents w.buf)

(* Outpoint serialization *)
let serialize_outpoint w (op : Types.outpoint) =
  write_bytes w op.txid;
  write_int32_le w op.vout

let deserialize_outpoint r : Types.outpoint =
  let txid = read_bytes r 32 in
  let vout = read_int32_le r in
  { txid; vout }

(* Transaction input serialization *)
let serialize_tx_in w (ti : Types.tx_in) =
  serialize_outpoint w ti.previous_output;
  write_compact_size w (Cstruct.length ti.script_sig);
  write_bytes w ti.script_sig;
  write_int32_le w ti.sequence

let deserialize_tx_in r : Types.tx_in =
  let previous_output = deserialize_outpoint r in
  let script_len = read_compact_size r in
  let script_sig = read_bytes r script_len in
  let sequence = read_int32_le r in
  { previous_output; script_sig; sequence }

(* Transaction output serialization *)
let serialize_tx_out w (to_ : Types.tx_out) =
  write_int64_le w to_.value;
  write_compact_size w (Cstruct.length to_.script_pubkey);
  write_bytes w to_.script_pubkey

let deserialize_tx_out r : Types.tx_out =
  let value = read_int64_le r in
  let script_len = read_compact_size r in
  let script_pubkey = read_bytes r script_len in
  { value; script_pubkey }

(* Witness serialization *)
let serialize_witness w (wit : Types.tx_witness) =
  write_compact_size w (List.length wit.items);
  List.iter (fun item ->
    write_compact_size w (Cstruct.length item);
    write_bytes w item
  ) wit.items

let deserialize_witness r : Types.tx_witness =
  let count = read_compact_size r in
  let items = List.init count (fun _ ->
    let len = read_compact_size r in
    read_bytes r len
  ) in
  { items }

(* Full transaction serialization with segwit support *)
let serialize_transaction w (tx : Types.transaction) =
  let has_witness = tx.witnesses <> [] in
  write_int32_le w tx.version;
  if has_witness then begin
    write_uint8 w 0x00;  (* marker *)
    write_uint8 w 0x01;  (* flag *)
  end;
  write_compact_size w (List.length tx.inputs);
  List.iter (serialize_tx_in w) tx.inputs;
  write_compact_size w (List.length tx.outputs);
  List.iter (serialize_tx_out w) tx.outputs;
  if has_witness then
    List.iter (serialize_witness w) tx.witnesses;
  write_int32_le w tx.locktime

let deserialize_transaction r : Types.transaction =
  let version = read_int32_le r in
  let marker = Cstruct.get_uint8 r.buf r.pos in
  let has_witness = marker = 0x00 in
  if has_witness then begin
    r.pos <- r.pos + 1;  (* skip marker 0x00 *)
    let flag = read_uint8 r in
    if flag <> 0x01 then failwith "Invalid witness flag"
  end;
  let in_count = read_compact_size r in
  let inputs = List.init in_count (fun _ -> deserialize_tx_in r) in
  let out_count = read_compact_size r in
  let outputs = List.init out_count (fun _ -> deserialize_tx_out r) in
  let witnesses =
    if has_witness then
      List.init in_count (fun _ -> deserialize_witness r)
    else []
  in
  let locktime = read_int32_le r in
  { version; inputs; outputs; witnesses; locktime }

(* Serialize transaction without witness data (for txid computation) *)
let serialize_transaction_no_witness w (tx : Types.transaction) =
  write_int32_le w tx.version;
  write_compact_size w (List.length tx.inputs);
  List.iter (serialize_tx_in w) tx.inputs;
  write_compact_size w (List.length tx.outputs);
  List.iter (serialize_tx_out w) tx.outputs;
  write_int32_le w tx.locktime

(* Block header serialization - always exactly 80 bytes *)
let serialize_block_header w (bh : Types.block_header) =
  write_int32_le w bh.version;
  write_bytes w bh.prev_block;
  write_bytes w bh.merkle_root;
  write_int32_le w bh.timestamp;
  write_int32_le w bh.bits;
  write_int32_le w bh.nonce

let deserialize_block_header r : Types.block_header =
  let version = read_int32_le r in
  let prev_block = read_bytes r 32 in
  let merkle_root = read_bytes r 32 in
  let timestamp = read_int32_le r in
  let bits = read_int32_le r in
  let nonce = read_int32_le r in
  { version; prev_block; merkle_root; timestamp; bits; nonce }

(* Block serialization *)
let serialize_block w (b : Types.block) =
  serialize_block_header w b.header;
  write_compact_size w (List.length b.transactions);
  List.iter (serialize_transaction w) b.transactions

let deserialize_block r : Types.block =
  let header = deserialize_block_header r in
  let tx_count = read_compact_size r in
  let transactions = List.init tx_count (fun _ -> deserialize_transaction r) in
  { header; transactions }

(* Network address serialization *)
let serialize_net_addr w (addr : Types.net_addr) =
  write_int64_le w addr.services;
  write_bytes w addr.addr;
  (* Port is big-endian in Bitcoin protocol *)
  write_uint8 w ((addr.port lsr 8) land 0xFF);
  write_uint8 w (addr.port land 0xFF)

let deserialize_net_addr r : Types.net_addr =
  let services = read_int64_le r in
  let addr = read_bytes r 16 in
  let port_hi = read_uint8 r in
  let port_lo = read_uint8 r in
  let port = (port_hi lsl 8) lor port_lo in
  { services; addr; port }

(* Version message serialization *)
let serialize_version_msg w (msg : Types.version_msg) =
  write_int32_le w msg.protocol_version;
  write_int64_le w msg.services;
  write_int64_le w msg.timestamp;
  serialize_net_addr w msg.addr_recv;
  serialize_net_addr w msg.addr_from;
  write_int64_le w msg.nonce;
  write_string w msg.user_agent;
  write_int32_le w msg.start_height;
  write_uint8 w (if msg.relay then 1 else 0)

let deserialize_version_msg r : Types.version_msg =
  let protocol_version = read_int32_le r in
  let services = read_int64_le r in
  let timestamp = read_int64_le r in
  let addr_recv = deserialize_net_addr r in
  let addr_from = deserialize_net_addr r in
  let nonce = read_int64_le r in
  let user_agent = read_string r in
  let start_height = read_int32_le r in
  let relay = read_uint8 r <> 0 in
  { protocol_version; services; timestamp; addr_recv; addr_from;
    nonce; user_agent; start_height; relay }
