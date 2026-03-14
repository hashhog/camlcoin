(* ZeroMQ publish/subscribe notifications for real-time block and transaction events.

   Implements the same ZMQ interface as Bitcoin Core:
   - Multi-part messages: [topic] [data] [sequence]
   - Topics: hashblock, hashtx, rawblock, rawtx, sequence
   - Sequence number: 4-byte LE counter per topic

   Reference: Bitcoin Core src/zmq/zmqpublishnotifier.cpp

   This module provides a pure OCaml implementation that buffers messages
   and can be connected to actual ZMQ sockets when the zmq library is available.
   Without ZMQ, it operates as a buffered notification system. *)

(* Topic types for ZMQ notifications *)
type topic =
  | HashBlock   (* 32-byte block hash in display format *)
  | HashTx      (* 32-byte txid in display format *)
  | RawBlock    (* Full serialized block *)
  | RawTx       (* Full serialized transaction *)
  | Sequence    (* Block connect/disconnect, tx accept/remove events *)

(* Sequence event labels (matches Bitcoin Core) *)
type sequence_event =
  | BlockConnect      (* 'C' *)
  | BlockDisconnect   (* 'D' *)
  | TxAcceptance      (* 'A' *)
  | TxRemoval         (* 'R' *)

(* A single ZMQ message (3-part: topic, data, sequence) *)
type zmq_message = {
  topic : string;
  data : string;
  sequence : int32;
}

(* Configuration for a ZMQ publisher endpoint *)
type endpoint_config = {
  address : string;                  (* e.g., "tcp://127.0.0.1:28332" *)
  topics : topic list;               (* Topics to publish on this endpoint *)
  high_water_mark : int;             (* Max queued messages (default 1000) *)
}

(* Per-topic state tracking sequence numbers *)
type topic_state = {
  mutable sequence : int32;
  mutable message_queue : zmq_message list;
  max_queue_size : int;
}

(* Callback type for external ZMQ send implementation *)
type send_callback = zmq_message -> bool

(* A ZMQ notifier manages notification state *)
type t = {
  (* Map from topic to state *)
  publishers : (topic, topic_state) Hashtbl.t;
  mutable enabled : bool;
  mutable send_cb : send_callback option;
}

(* Topic name strings (matches Bitcoin Core) *)
let topic_to_string = function
  | HashBlock -> "hashblock"
  | HashTx -> "hashtx"
  | RawBlock -> "rawblock"
  | RawTx -> "rawtx"
  | Sequence -> "sequence"

let sequence_event_to_char = function
  | BlockConnect -> 'C'
  | BlockDisconnect -> 'D'
  | TxAcceptance -> 'A'
  | TxRemoval -> 'R'

(* Reverse a hash256 for display format (Bitcoin displays hashes reversed) *)
let reverse_hash (h : Types.hash256) : Cstruct.t =
  let len = Cstruct.length h in
  let reversed = Cstruct.create len in
  for i = 0 to len - 1 do
    Cstruct.set_uint8 reversed (len - 1 - i) (Cstruct.get_uint8 h i)
  done;
  reversed

(* Encode a 32-bit LE sequence number *)
let encode_sequence_le (seq : int32) : string =
  let buf = Cstruct.create 4 in
  Cstruct.LE.set_uint32 buf 0 seq;
  Cstruct.to_string buf

(* Encode a 64-bit LE value *)
let encode_int64_le (v : int64) : string =
  let buf = Cstruct.create 8 in
  Cstruct.LE.set_uint64 buf 0 v;
  Cstruct.to_string buf

(* Create a new ZMQ notifier with the given endpoint configurations *)
let create (configs : endpoint_config list) : t =
  let publishers = Hashtbl.create 8 in

  (* For each configuration, create state for each topic *)
  List.iter (fun config ->
    List.iter (fun topic ->
      if not (Hashtbl.mem publishers topic) then begin
        let state = {
          sequence = 0l;
          message_queue = [];
          max_queue_size = config.high_water_mark;
        } in
        Hashtbl.add publishers topic state
      end
    ) config.topics
  ) configs;

  { publishers; enabled = true; send_cb = None }

(* Create a notifier with default configuration *)
let create_default ?(address = "tcp://127.0.0.1:28332") () : t =
  create [{
    address;
    topics = [HashBlock; HashTx; RawBlock; RawTx; Sequence];
    high_water_mark = 1000;
  }]

(* Create a disabled notifier (no-op for all operations) *)
let create_disabled () : t =
  { publishers = Hashtbl.create 0; enabled = false; send_cb = None }

(* Set a callback for external ZMQ sending *)
let set_send_callback (t : t) (cb : send_callback) : unit =
  t.send_cb <- Some cb

(* Send or queue a message *)
let send_message (t : t) (state : topic_state) (topic_str : string) (data : string) : bool =
  let msg = {
    topic = topic_str;
    data;
    sequence = state.sequence;
  } in

  (* Increment sequence after creating message *)
  state.sequence <- Int32.add state.sequence 1l;

  (* Try to send via callback, otherwise queue *)
  match t.send_cb with
  | Some cb ->
    let result = cb msg in
    if not result then begin
      (* Failed to send, queue it if within limits *)
      if List.length state.message_queue < state.max_queue_size then
        state.message_queue <- state.message_queue @ [msg]
    end;
    result
  | None ->
    (* No callback, just queue *)
    if List.length state.message_queue < state.max_queue_size then
      state.message_queue <- state.message_queue @ [msg];
    true

(* Notify a new block hash *)
let notify_hashblock (t : t) (block_hash : Types.hash256) : bool =
  if not t.enabled then true
  else match Hashtbl.find_opt t.publishers HashBlock with
  | None -> true  (* Topic not configured *)
  | Some state ->
    let topic_str = topic_to_string HashBlock in
    (* Send reversed hash (display format) *)
    let reversed = reverse_hash block_hash in
    let data = Cstruct.to_string reversed in
    let result = send_message t state topic_str data in
    if result then
      Logs.debug (fun m -> m "ZMQ: Published %s %s" topic_str
        (Types.hash256_to_hex_display block_hash));
    result

(* Notify a new transaction hash *)
let notify_hashtx (t : t) (txid : Types.hash256) : bool =
  if not t.enabled then true
  else match Hashtbl.find_opt t.publishers HashTx with
  | None -> true
  | Some state ->
    let topic_str = topic_to_string HashTx in
    let reversed = reverse_hash txid in
    let data = Cstruct.to_string reversed in
    let result = send_message t state topic_str data in
    if result then
      Logs.debug (fun m -> m "ZMQ: Published %s %s" topic_str
        (Types.hash256_to_hex_display txid));
    result

(* Notify a raw block *)
let notify_rawblock (t : t) (block : Types.block) : bool =
  if not t.enabled then true
  else match Hashtbl.find_opt t.publishers RawBlock with
  | None -> true
  | Some state ->
    let topic_str = topic_to_string RawBlock in
    (* Serialize the full block *)
    let w = Serialize.writer_create () in
    Serialize.serialize_block w block;
    let data = Buffer.contents w.buf in
    let result = send_message t state topic_str data in
    if result then begin
      let block_hash = Crypto.sha256d (Serialize.writer_to_cstruct
        (let w = Serialize.writer_create () in
         Serialize.serialize_block_header w block.header;
         w)) in
      Logs.debug (fun m -> m "ZMQ: Published %s %s (%d bytes)" topic_str
        (Types.hash256_to_hex_display block_hash) (String.length data))
    end;
    result

(* Notify a raw transaction *)
let notify_rawtx (t : t) (tx : Types.transaction) : bool =
  if not t.enabled then true
  else match Hashtbl.find_opt t.publishers RawTx with
  | None -> true
  | Some state ->
    let topic_str = topic_to_string RawTx in
    (* Serialize with witness data *)
    let w = Serialize.writer_create () in
    Serialize.serialize_transaction w tx;
    let data = Buffer.contents w.buf in
    let result = send_message t state topic_str data in
    if result then begin
      let txid = Crypto.compute_txid tx in
      Logs.debug (fun m -> m "ZMQ: Published %s %s (%d bytes)" topic_str
        (Types.hash256_to_hex_display txid) (String.length data))
    end;
    result

(* Notify a sequence event *)
let notify_sequence (t : t) (hash : Types.hash256) (event : sequence_event)
    ?(mempool_sequence : int64 option) () : bool =
  if not t.enabled then true
  else match Hashtbl.find_opt t.publishers Sequence with
  | None -> true
  | Some state ->
    let topic_str = topic_to_string Sequence in
    (* Build data: reversed hash + label byte + optional 8-byte mempool sequence *)
    let reversed = reverse_hash hash in
    let label = String.make 1 (sequence_event_to_char event) in
    let data = match mempool_sequence with
      | None ->
        Cstruct.to_string reversed ^ label
      | Some seq ->
        Cstruct.to_string reversed ^ label ^ encode_int64_le seq
    in
    let result = send_message t state topic_str data in
    if result then
      Logs.debug (fun m -> m "ZMQ: Published %s %s %c" topic_str
        (Types.hash256_to_hex_display hash) (sequence_event_to_char event));
    result

(* Convenience function: notify block connect *)
let notify_block_connect (t : t) (block_hash : Types.hash256) : bool =
  notify_sequence t block_hash BlockConnect ()

(* Convenience function: notify block disconnect *)
let notify_block_disconnect (t : t) (block_hash : Types.hash256) : bool =
  notify_sequence t block_hash BlockDisconnect ()

(* Convenience function: notify tx acceptance *)
let notify_tx_acceptance (t : t) (txid : Types.hash256) (mempool_sequence : int64) : bool =
  notify_sequence t txid TxAcceptance ~mempool_sequence ()

(* Convenience function: notify tx removal *)
let notify_tx_removal (t : t) (txid : Types.hash256) (mempool_sequence : int64) : bool =
  notify_sequence t txid TxRemoval ~mempool_sequence ()

(* Shutdown and clean up *)
let shutdown (t : t) : unit =
  Hashtbl.clear t.publishers;
  t.enabled <- false;
  t.send_cb <- None

(* Check if notifier is enabled *)
let is_enabled (t : t) : bool = t.enabled

(* Get current sequence number for a topic *)
let get_sequence (t : t) (topic : topic) : int32 option =
  match Hashtbl.find_opt t.publishers topic with
  | Some state -> Some state.sequence
  | None -> None

(* Get queued messages for a topic (for testing or external delivery) *)
let get_queued_messages (t : t) (topic : topic) : zmq_message list =
  match Hashtbl.find_opt t.publishers topic with
  | Some state -> state.message_queue
  | None -> []

(* Clear queued messages for a topic *)
let clear_queue (t : t) (topic : topic) : unit =
  match Hashtbl.find_opt t.publishers topic with
  | Some state -> state.message_queue <- []
  | None -> ()

(* Drain all queued messages (returns and clears) *)
let drain_queue (t : t) (topic : topic) : zmq_message list =
  match Hashtbl.find_opt t.publishers topic with
  | Some state ->
    let msgs = state.message_queue in
    state.message_queue <- [];
    msgs
  | None -> []

(* Lwt-compatible async wrappers *)
module Lwt = struct
  (* Async version of notify_hashblock *)
  let notify_hashblock (t : t) (block_hash : Types.hash256) : bool Lwt.t =
    Lwt.return (notify_hashblock t block_hash)

  (* Async version of notify_hashtx *)
  let notify_hashtx (t : t) (txid : Types.hash256) : bool Lwt.t =
    Lwt.return (notify_hashtx t txid)

  (* Async version of notify_rawblock *)
  let notify_rawblock (t : t) (block : Types.block) : bool Lwt.t =
    Lwt.return (notify_rawblock t block)

  (* Async version of notify_rawtx *)
  let notify_rawtx (t : t) (tx : Types.transaction) : bool Lwt.t =
    Lwt.return (notify_rawtx t tx)

  (* Async version of notify_sequence *)
  let notify_sequence (t : t) (hash : Types.hash256) (event : sequence_event)
      ?(mempool_sequence : int64 option) () : bool Lwt.t =
    Lwt.return (notify_sequence t hash event ?mempool_sequence ())

  (* Async version of notify_block_connect *)
  let notify_block_connect (t : t) (block_hash : Types.hash256) : bool Lwt.t =
    Lwt.return (notify_block_connect t block_hash)

  (* Async version of notify_block_disconnect *)
  let notify_block_disconnect (t : t) (block_hash : Types.hash256) : bool Lwt.t =
    Lwt.return (notify_block_disconnect t block_hash)

  (* Async version of notify_tx_acceptance *)
  let notify_tx_acceptance (t : t) (txid : Types.hash256) (mempool_sequence : int64) : bool Lwt.t =
    Lwt.return (notify_tx_acceptance t txid mempool_sequence)

  (* Async version of notify_tx_removal *)
  let notify_tx_removal (t : t) (txid : Types.hash256) (mempool_sequence : int64) : bool Lwt.t =
    Lwt.return (notify_tx_removal t txid mempool_sequence)

  (* Helper to notify all block-related topics at once *)
  let notify_block (t : t) (block : Types.block) (block_hash : Types.hash256) : unit Lwt.t =
    let open Lwt.Infix in
    notify_hashblock t block_hash >>= fun _ ->
    notify_rawblock t block >>= fun _ ->
    notify_block_connect t block_hash >>= fun _ ->
    Lwt.return_unit

  (* Helper to notify all tx-related topics at once *)
  let notify_transaction (t : t) (tx : Types.transaction) (txid : Types.hash256)
      (mempool_sequence : int64) : unit Lwt.t =
    let open Lwt.Infix in
    notify_hashtx t txid >>= fun _ ->
    notify_rawtx t tx >>= fun _ ->
    notify_tx_acceptance t txid mempool_sequence >>= fun _ ->
    Lwt.return_unit
end

(* Parse command-line ZMQ configuration *)
module Config = struct
  type zmq_option = {
    topic : topic;
    address : string;
  }

  let parse_topic_name = function
    | "hashblock" | "pubhashblock" -> Some HashBlock
    | "hashtx" | "pubhashtx" -> Some HashTx
    | "rawblock" | "pubrawblock" -> Some RawBlock
    | "rawtx" | "pubrawtx" -> Some RawTx
    | "sequence" | "pubsequence" -> Some Sequence
    | _ -> None

  (* Parse a -zmqpub<topic>=<address> style option *)
  let parse_zmq_option (opt : string) : zmq_option option =
    if String.length opt > 7 && String.sub opt 0 7 = "-zmqpub" then
      let rest = String.sub opt 7 (String.length opt - 7) in
      match String.index_opt rest '=' with
      | Some idx ->
        let topic_name = String.sub rest 0 idx in
        let address = String.sub rest (idx + 1) (String.length rest - idx - 1) in
        (match parse_topic_name topic_name with
         | Some topic -> Some { topic; address }
         | None -> None)
      | None -> None
    else
      None

  (* Build endpoint configs from parsed options *)
  let build_configs (options : zmq_option list) : endpoint_config list =
    (* Group by address *)
    let by_addr = Hashtbl.create 4 in
    List.iter (fun opt ->
      let topics = match Hashtbl.find_opt by_addr opt.address with
        | Some ts -> ts
        | None -> []
      in
      Hashtbl.replace by_addr opt.address (opt.topic :: topics)
    ) options;
    (* Build configs *)
    Hashtbl.fold (fun address topics acc ->
      { address; topics; high_water_mark = 1000 } :: acc
    ) by_addr []

  (* Create notifier from command-line options *)
  let create_from_options (options : zmq_option list) : t =
    if options = [] then
      create_disabled ()
    else
      create (build_configs options)
end

(* Message encoding utilities for external ZMQ integration *)
module Encoding = struct
  (* Encode a message into the 3-part format for ZMQ send_all *)
  let encode_message (msg : zmq_message) : string list =
    [ msg.topic; msg.data; encode_sequence_le msg.sequence ]

  (* Decode a 3-part ZMQ message *)
  let decode_message (parts : string list) : zmq_message option =
    match parts with
    | [topic; data; seq] when String.length seq = 4 ->
      let seq_cs = Cstruct.of_string seq in
      let sequence = Cstruct.LE.get_uint32 seq_cs 0 in
      Some { topic; data; sequence }
    | _ -> None
end
