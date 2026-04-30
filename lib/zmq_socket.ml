(* ZeroMQ-compatible publisher built on real libzmq.
 *
 * Wraps lib/zmq_bindings.ml (the C-stub binding to libzmq.so.5) in the
 * publisher / subscriber types that the rest of the codebase, the test
 * suite, and the in-process queue drain helper already speak.
 *
 * Behaviour:
 *   - [create_publisher] creates a fresh ZMQ context lazily; nothing is
 *     allocated on the wire yet.
 *   - [bind addr] opens a real PUB socket on demand, calls [zmq_bind],
 *     and sets the SNDHWM. Multiple [bind] calls add additional bound
 *     endpoints — same socket, more wires.
 *   - [send_message] publishes a 3-frame ZMQ message
 *     ([topic; body; seq_le32]) on every bound endpoint. If no bind has
 *     been performed (or libzmq returned ENETDOWN, or the socket was
 *     torn down by [close_publisher]), we fall back to the in-process
 *     queue so the existing test surface keeps working as a unit test.
 *   - [close_publisher] closes the socket, terminates the context, and
 *     marks the publisher disabled.
 *
 * Reference: Bitcoin Core src/zmq/zmqpublishnotifier.cpp.
 *
 * Subscriber side is intentionally a stub — camlcoin only publishes,
 * mirroring Core's notifier.
 *
 * Usage:
 *     let publisher = Zmq_socket.create_publisher () in
 *     Zmq_socket.bind publisher "tcp://127.0.0.1:28332";
 *     let notifier = Zmq_notify.create_default () in
 *     Zmq_notify.set_send_callback notifier (Zmq_socket.send_message publisher);
 *     ... node loop runs ...
 *     Zmq_socket.close_publisher publisher
 *)

(* A publisher manages a single ZMQ context + PUB socket plus the
   in-process queue used for unit tests and as a graceful-degradation
   fallback when no endpoint has been bound. *)
type publisher = {
  mutable bound_addresses : string list;
  mutable high_water_mark : int;
  mutable tcp_keepalive : bool;
  mutable enabled : bool;
  mutable message_queue : Zmq_notify.zmq_message list;
  (* Real libzmq state. Lazily created on first [bind]; [None] means
     the publisher has not yet wired itself to the network. *)
  mutable zmq_ctx : Zmq_bindings.ctx option;
  mutable zmq_pub : Zmq_bindings.pub_sock option;
  (* Internal mutex for [send_message]: zmq_send is thread-safe per
     socket but the pair (topic, body, seq) must be atomic so that
     concurrent block-connect + tx-accept hooks don't interleave
     frames on the wire. *)
  mutable lock : Mutex.t;
}

(* A TCP-based subscriber for receiving messages (used in tests).
   Kept as a stub: camlcoin only publishes; subscribing would require
   a SUB socket binding which we have not wired yet. *)
type subscriber = {
  mutable sub_connected : bool;
  mutable subscribed_topics : string list;
}

(* Parse address string like "tcp://127.0.0.1:28332".
   Returns (host, port) or [None] if the URL doesn't look like tcp://.
   Note that libzmq accepts ipc:// and inproc:// too — those still bind
   correctly but [parse_address] returns [None] because we only need
   the helper for diagnostics on tcp endpoints. *)
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

(* Create a new publisher. The libzmq context + socket are deferred
   until the first [bind] call so that test cases that never bind
   never touch libzmq at all. *)
let create_publisher ?(high_water_mark = 1000) () : publisher =
  {
    bound_addresses = [];
    high_water_mark;
    tcp_keepalive = true;
    enabled = true;
    message_queue = [];
    zmq_ctx = None;
    zmq_pub = None;
    lock = Mutex.create ();
  }

(* Lazily ensure a libzmq context + PUB socket exist. Idempotent — a
   second call is a no-op. SNDHWM is configured per-socket so it has to
   be in place before [zmq_bind]; ZMQ documents that setsockopt before
   bind is the supported order. *)
let ensure_zmq_socket (pub : publisher) : Zmq_bindings.pub_sock option =
  match pub.zmq_pub with
  | Some _ as s -> s
  | None ->
    if not pub.enabled then None
    else
      try
        let ctx =
          match pub.zmq_ctx with
          | Some c -> c
          | None ->
            let c = Zmq_bindings.ctx_new () in
            pub.zmq_ctx <- Some c;
            c
        in
        let s = Zmq_bindings.pub_socket ctx in
        Zmq_bindings.set_sndhwm s pub.high_water_mark;
        pub.zmq_pub <- Some s;
        Some s
      with
      | Failure msg ->
        Logs.warn (fun m ->
          m "ZMQ: failed to create PUB socket: %s — falling back to in-process queue"
            msg);
        None

(* Bind the publisher to an address. Idempotent: a duplicate bind is
   reported by libzmq as EADDRINUSE; we log and continue rather than
   crashing the daemon. *)
let bind (pub : publisher) (address : string) : unit =
  pub.bound_addresses <- address :: pub.bound_addresses;
  match ensure_zmq_socket pub with
  | None ->
    Logs.warn (fun m ->
      m "ZMQ: publisher disabled or libzmq unavailable — \
         skipping bind on %s; messages will be queued in-process only"
        address)
  | Some s ->
    (try
       Zmq_bindings.bind s address;
       Logs.info (fun m -> m "ZMQ: PUB socket bound to %s" address)
     with Failure msg ->
       Logs.warn (fun m ->
         m "ZMQ: zmq_bind(%s) failed: %s" address msg))

(* Encode a ZMQ-style multi-part frame for the in-process fallback.
   Used by the unit tests; not the wire format libzmq itself uses.
   ZMQ wire format: each part is prefixed with a flag byte and size.
   For simplicity, we use a simpler framing: 4-byte BE count + per-part
   (4-byte BE length + data). *)
let encode_frame (parts : string list) : string =
  let buf = Buffer.create 256 in
  let count = List.length parts in
  let count_buf = Cstruct.create 4 in
  Cstruct.BE.set_uint32 count_buf 0 (Int32.of_int count);
  Buffer.add_string buf (Cstruct.to_string count_buf);
  List.iter (fun part ->
    let len_buf = Cstruct.create 4 in
    Cstruct.BE.set_uint32 len_buf 0 (Int32.of_int (String.length part));
    Buffer.add_string buf (Cstruct.to_string len_buf);
    Buffer.add_string buf part
  ) parts;
  Buffer.contents buf

(* Decode a framed message produced by [encode_frame]. *)
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

(* Send a multi-part message. Always queues for the in-process drain
   API used by tests, AND publishes to libzmq if a socket is wired up.
   Returns [true] iff the in-process accept succeeded; libzmq send
   failures are logged but not surfaced (matches Core's notifier
   semantics: a slow subscriber must not stall the publisher). *)
let send_message (pub : publisher) (msg : Zmq_notify.zmq_message) : bool =
  if not pub.enabled then true
  else begin
    Mutex.lock pub.lock;
    let result =
      try
        (* Queue for in-process consumers / unit tests. *)
        if List.length pub.message_queue < pub.high_water_mark then
          pub.message_queue <- pub.message_queue @ [msg];
        Logs.debug (fun m -> m "ZMQ: Queued message topic=%s" msg.topic);
        (* Also push to the wire if libzmq is up. The 3 frames must be
           sent atomically on the same socket; the publisher mutex
           around this block guarantees ordering across concurrent
           threads. *)
        (match pub.zmq_pub with
         | None -> ()
         | Some sock ->
           let seq_str = Zmq_notify.Encoding.encode_message msg
                         |> (fun parts -> List.nth parts 2) in
           let ok = Zmq_bindings.pub_send3 sock msg.topic msg.data seq_str in
           if not ok then
             Logs.debug (fun m ->
               m "ZMQ: zmq_send(topic=%s) failed (HWM/EAGAIN); \
                  message dropped from wire (queue retains it)"
                 msg.topic));
        true
      with exn ->
        Logs.warn (fun m ->
          m "ZMQ: send_message raised: %s" (Printexc.to_string exn));
        false
    in
    Mutex.unlock pub.lock;
    result
  end

(* Close the publisher: tear down the libzmq socket + context, drop
   the in-process queue, and mark disabled. Idempotent. *)
let close_publisher (pub : publisher) : unit =
  Mutex.lock pub.lock;
  pub.enabled <- false;
  pub.bound_addresses <- [];
  pub.message_queue <- [];
  (match pub.zmq_pub with
   | None -> ()
   | Some s ->
     (try Zmq_bindings.close s with _ -> ());
     pub.zmq_pub <- None);
  (match pub.zmq_ctx with
   | None -> ()
   | Some c ->
     (try Zmq_bindings.ctx_term c with _ -> ());
     pub.zmq_ctx <- None);
  Mutex.unlock pub.lock;
  Logs.info (fun m -> m "ZMQ: Publisher closed")

(* Create a subscriber for testing *)
let create_subscriber () : subscriber =
  {
    sub_connected = false;
    subscribed_topics = [];
  }

(* Connect subscriber to an address (mock). *)
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
  sub.subscribed_topics <- [""];
  Logs.debug (fun m -> m "ZMQ: Subscribed to all topics")

(* Receive a message (blocking) - mock implementation *)
let recv_message (_sub : subscriber) : Zmq_notify.zmq_message option =
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

  type async_publisher = {
    sync_pub : publisher;
  }

  let create_publisher ?(high_water_mark = 1000) () : async_publisher =
    { sync_pub = create_publisher ~high_water_mark () }

  let bind (pub : async_publisher) (address : string) : unit =
    bind pub.sync_pub address

  let send_message (pub : async_publisher) (msg : Zmq_notify.zmq_message)
      : bool Lwt.t =
    Lwt.return (send_message pub.sync_pub msg)

  let close_publisher (pub : async_publisher) : unit Lwt.t =
    close_publisher pub.sync_pub;
    Lwt.return_unit

  type async_subscriber = {
    sync_sub : subscriber;
  }

  let create_subscriber () : async_subscriber =
    { sync_sub = create_subscriber () }

  let connect_subscriber (sub : async_subscriber) (address : string) : unit =
    connect_subscriber sub.sync_sub address

  let subscribe (sub : async_subscriber) (topic : string) : unit =
    subscribe sub.sync_sub topic

  let subscribe_all (sub : async_subscriber) : unit =
    subscribe_all sub.sync_sub

  let recv_message (sub : async_subscriber) : Zmq_notify.zmq_message option Lwt.t =
    Lwt_unix.sleep 0.001 >>= fun () ->
    Lwt.return (recv_message sub.sync_sub)

  let close_subscriber (sub : async_subscriber) : unit Lwt.t =
    close_subscriber sub.sync_sub;
    Lwt.return_unit
end

(* Helper: Create a publisher from Zmq_notify configuration. Calls
   [bind] for every distinct address — each becomes a wire endpoint
   on the same publisher socket. *)
let create_from_config (configs : Zmq_notify.endpoint_config list) : publisher option =
  if configs = [] then None
  else begin
    let pub = create_publisher () in
    let addresses = List.sort_uniq String.compare
      (List.map (fun (c : Zmq_notify.endpoint_config) -> c.address) configs) in
    List.iter (fun addr -> bind pub addr) addresses;
    Some pub
  end

(* Helper: Wire up a notifier to a publisher. *)
let connect_notifier (notifier : Zmq_notify.t) (pub : publisher) : unit =
  Zmq_notify.set_send_callback notifier (send_message pub)

(* Get queued messages from publisher (for testing) *)
let get_queued_messages (pub : publisher) : Zmq_notify.zmq_message list =
  pub.message_queue

(* Clear queued messages *)
let clear_queue (pub : publisher) : unit =
  pub.message_queue <- []
