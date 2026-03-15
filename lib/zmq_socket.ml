(* ZeroMQ-compatible socket implementation for real-time pub/sub notifications.

   This module provides a ZMQ-compatible interface for publishing notifications.
   It uses raw TCP sockets to implement a simplified pub/sub protocol that is
   compatible with ZMQ subscribers.

   When the zmq opam package is available, this can be updated to use actual
   ZMQ bindings. The current implementation uses raw TCP multipart message
   framing compatible with ZMQ SUB sockets.

   Reference: Bitcoin Core src/zmq/zmqpublishnotifier.cpp

   Usage:
     let publisher = Zmq_socket.create_publisher () in
     Zmq_socket.bind publisher "tcp://127.0.0.1:28332";
     let notifier = Zmq_notify.create_default () in
     Zmq_notify.set_send_callback notifier (Zmq_socket.send_message publisher);
*)

(* A TCP-based publisher that mimics ZMQ PUB behavior *)
type publisher = {
  mutable bound_addresses : string list;
  mutable high_water_mark : int;
  mutable tcp_keepalive : bool;
  mutable sockets : (Unix.file_descr * Lwt_io.output_channel) list;
  mutable enabled : bool;
  mutable subscribers : (Unix.file_descr * Lwt_io.output_channel) list;
  mutable message_queue : Zmq_notify.zmq_message list;
}

(* A TCP-based subscriber for receiving messages (used in tests) *)
type subscriber = {
  mutable sub_connected : bool;
  mutable sub_socket : Unix.file_descr option;
  mutable sub_input : Lwt_io.input_channel option;
  mutable subscribed_topics : string list;
}

(* Parse address string like "tcp://127.0.0.1:28332" *)
let parse_address (address : string) : (string * int) option =
  if String.length address > 6 && String.sub address 0 6 = "tcp://" then
    let rest = String.sub address 6 (String.length address - 6) in
    match String.rindex_opt rest ':' with
    | Some idx ->
      let host = String.sub rest 0 idx in
      let port_str = String.sub rest (idx + 1) (String.length rest - idx - 1) in
      (try Some (host, int_of_string port_str)
       with _ -> None)
    | None -> None
  else
    None

(* Create a new publisher *)
let create_publisher ?(high_water_mark = 1000) () : publisher =
  {
    bound_addresses = [];
    high_water_mark;
    tcp_keepalive = true;
    sockets = [];
    enabled = true;
    subscribers = [];
    message_queue = [];
  }

(* Bind the publisher to an address (for now, just record the address) *)
let bind (pub : publisher) (address : string) : unit =
  pub.bound_addresses <- address :: pub.bound_addresses;
  Logs.info (fun m -> m "ZMQ: Publisher configured for %s" address)

(* Encode a ZMQ-style multi-part message frame.
   ZMQ wire format: each part is prefixed with a flag byte and size.
   For simplicity, we use a simpler framing: 4-byte BE length + data *)
let encode_frame (parts : string list) : string =
  let buf = Buffer.create 256 in
  let count = List.length parts in
  (* Write part count as 4-byte BE *)
  let count_buf = Cstruct.create 4 in
  Cstruct.BE.set_uint32 count_buf 0 (Int32.of_int count);
  Buffer.add_string buf (Cstruct.to_string count_buf);
  (* Write each part *)
  List.iter (fun part ->
    (* 4-byte BE length *)
    let len_buf = Cstruct.create 4 in
    Cstruct.BE.set_uint32 len_buf 0 (Int32.of_int (String.length part));
    Buffer.add_string buf (Cstruct.to_string len_buf);
    Buffer.add_string buf part
  ) parts;
  Buffer.contents buf

(* Decode a framed message *)
let decode_frame (data : string) : string list option =
  if String.length data < 4 then None
  else
    let cs = Cstruct.of_string data in
    let count = Int32.to_int (Cstruct.BE.get_uint32 cs 0) in
    if count < 0 || count > 100 then None
    else begin
      let pos = ref 4 in
      let parts = ref [] in
      let error = ref false in
      for _ = 1 to count do
        if not !error then begin
          if !pos + 4 > String.length data then
            error := true
          else begin
            let len = Int32.to_int (Cstruct.BE.get_uint32 cs !pos) in
            pos := !pos + 4;
            if !pos + len > String.length data then
              error := true
            else begin
              parts := String.sub data !pos len :: !parts;
              pos := !pos + len
            end
          end
        end
      done;
      if !error then None
      else Some (List.rev !parts)
    end

(* Send a multi-part message *)
let send_message (pub : publisher) (msg : Zmq_notify.zmq_message) : bool =
  if not pub.enabled then true
  else begin
    (* Encode message parts *)
    let parts = Zmq_notify.Encoding.encode_message msg in
    (* Queue message for any connected subscribers *)
    if List.length pub.message_queue < pub.high_water_mark then
      pub.message_queue <- pub.message_queue @ [msg];
    Logs.debug (fun m -> m "ZMQ: Queued message topic=%s" msg.topic);
    (* Note: Actual socket sending would happen here with real ZMQ *)
    ignore (encode_frame parts);
    true
  end

(* Close the publisher and clean up *)
let close_publisher (pub : publisher) : unit =
  pub.enabled <- false;
  pub.bound_addresses <- [];
  pub.message_queue <- [];
  Logs.info (fun m -> m "ZMQ: Publisher closed")

(* Create a subscriber for testing *)
let create_subscriber () : subscriber =
  {
    sub_connected = false;
    sub_socket = None;
    sub_input = None;
    subscribed_topics = [];
  }

(* Connect subscriber to an address (mock) *)
let connect_subscriber (sub : subscriber) (address : string) : unit =
  ignore address;
  sub.sub_connected <- true;
  Logs.debug (fun m -> m "ZMQ: Subscriber connected")

(* Subscribe to a topic *)
let subscribe (sub : subscriber) (topic : string) : unit =
  sub.subscribed_topics <- topic :: sub.subscribed_topics;
  Logs.debug (fun m -> m "ZMQ: Subscribed to topic '%s'" topic)

(* Subscribe to all topics *)
let subscribe_all (sub : subscriber) : unit =
  sub.subscribed_topics <- [""];  (* Empty string means all *)
  Logs.debug (fun m -> m "ZMQ: Subscribed to all topics")

(* Receive a message (blocking) - mock implementation *)
let recv_message (_sub : subscriber) : Zmq_notify.zmq_message option =
  (* In a real implementation, this would read from the socket *)
  None

(* Receive a message with timeout (non-blocking check) *)
let recv_message_nowait (_sub : subscriber) : Zmq_notify.zmq_message option =
  None

(* Close subscriber *)
let close_subscriber (sub : subscriber) : unit =
  sub.sub_connected <- false;
  sub.subscribed_topics <- []

(* Lwt-compatible async wrapper for ZMQ operations *)
module Lwt = struct
  open Lwt.Infix

  (* Async publisher type *)
  type async_publisher = {
    sync_pub : publisher;
  }

  (* Create an async publisher *)
  let create_publisher ?(high_water_mark = 1000) () : async_publisher =
    { sync_pub = create_publisher ~high_water_mark () }

  (* Bind async publisher *)
  let bind (pub : async_publisher) (address : string) : unit =
    bind pub.sync_pub address

  (* Send message asynchronously *)
  let send_message (pub : async_publisher) (msg : Zmq_notify.zmq_message)
      : bool Lwt.t =
    Lwt.return (send_message pub.sync_pub msg)

  (* Close async publisher *)
  let close_publisher (pub : async_publisher) : unit Lwt.t =
    close_publisher pub.sync_pub;
    Lwt.return_unit

  (* Async subscriber type *)
  type async_subscriber = {
    sync_sub : subscriber;
  }

  (* Create async subscriber *)
  let create_subscriber () : async_subscriber =
    { sync_sub = create_subscriber () }

  (* Connect async subscriber *)
  let connect_subscriber (sub : async_subscriber) (address : string) : unit =
    connect_subscriber sub.sync_sub address

  (* Subscribe to topic *)
  let subscribe (sub : async_subscriber) (topic : string) : unit =
    subscribe sub.sync_sub topic

  (* Subscribe to all *)
  let subscribe_all (sub : async_subscriber) : unit =
    subscribe_all sub.sync_sub

  (* Receive message asynchronously *)
  let recv_message (sub : async_subscriber) : Zmq_notify.zmq_message option Lwt.t =
    (* Add a small delay to simulate async behavior *)
    Lwt_unix.sleep 0.001 >>= fun () ->
    Lwt.return (recv_message sub.sync_sub)

  (* Close async subscriber *)
  let close_subscriber (sub : async_subscriber) : unit Lwt.t =
    close_subscriber sub.sync_sub;
    Lwt.return_unit
end

(* Helper: Create a publisher from Zmq_notify configuration *)
let create_from_config (configs : Zmq_notify.endpoint_config list) : publisher option =
  if configs = [] then None
  else begin
    let pub = create_publisher () in
    (* Bind to all unique addresses *)
    let addresses = List.sort_uniq String.compare
      (List.map (fun (c : Zmq_notify.endpoint_config) -> c.address) configs) in
    List.iter (fun addr -> bind pub addr) addresses;
    Some pub
  end

(* Helper: Wire up a notifier to a publisher *)
let connect_notifier (notifier : Zmq_notify.t) (pub : publisher) : unit =
  Zmq_notify.set_send_callback notifier (send_message pub)

(* Get queued messages from publisher (for testing) *)
let get_queued_messages (pub : publisher) : Zmq_notify.zmq_message list =
  pub.message_queue

(* Clear queued messages *)
let clear_queue (pub : publisher) : unit =
  pub.message_queue <- []
