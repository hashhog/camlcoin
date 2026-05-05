(* Bitcoin P2P peer connection and handshake management using Lwt *)

let log_src = Logs.Src.create "PEER" ~doc:"Peer connection"
module Log = (val Logs.src_log log_src : Logs.LOG)

(* Protocol-level error that should disconnect the peer, not crash the node *)
exception Peer_protocol_error of string

(* Peer connection states *)
type peer_state =
  | Connecting
  | Connected
  | HandshakeInProgress
  | Ready
  | Disconnecting
  | Disconnected

let peer_state_to_string = function
  | Connecting -> "connecting"
  | Connected -> "connected"
  | HandshakeInProgress -> "handshake"
  | Ready -> "ready"
  | Disconnecting -> "disconnecting"
  | Disconnected -> "disconnected"

(* Service flags advertised by peers (BIP-111, BIP-144, etc.) *)
type peer_services = {
  network : bool;           (* NODE_NETWORK = 1 *)
  getutxo : bool;           (* NODE_GETUTXO = 2 *)
  bloom : bool;             (* NODE_BLOOM = 4 *)
  witness : bool;           (* NODE_WITNESS = 8 *)
  compact_filters : bool;   (* NODE_COMPACT_FILTERS = 64 *)
  network_limited : bool;   (* NODE_NETWORK_LIMITED = 1024 *)
}

let services_of_int64 (s : int64) : peer_services =
  { network = Int64.logand s 1L <> 0L;
    getutxo = Int64.logand s 2L <> 0L;
    bloom = Int64.logand s 4L <> 0L;
    witness = Int64.logand s 8L <> 0L;
    compact_filters = Int64.logand s 64L <> 0L;
    network_limited = Int64.logand s 1024L <> 0L }

let services_to_int64 (s : peer_services) : int64 =
  let v = ref 0L in
  if s.network then v := Int64.logor !v 1L;
  if s.getutxo then v := Int64.logor !v 2L;
  if s.bloom then v := Int64.logor !v 4L;
  if s.witness then v := Int64.logor !v 8L;
  if s.compact_filters then v := Int64.logor !v 64L;
  if s.network_limited then v := Int64.logor !v 1024L;
  !v

let empty_services : peer_services =
  { network = false;
    getutxo = false;
    bloom = false;
    witness = false;
    compact_filters = false;
    network_limited = false }

(* Bloom-filter / BIP-35 (NODE_BLOOM) advertisement gate.

   Bitcoin Core sets DEFAULT_PEERBLOOMFILTERS = false in
   src/net_processing.h:44 — i.e. the BIP-35 / BIP-111 NODE_BLOOM bit is
   OFF by default and is only flipped on by passing -peerbloomfilters=1.
   We mirror that exactly: this ref defaults to [false] and is flipped at
   startup by [Cli.run] when the operator passes --peerbloomfilters.  The
   MEMPOOL handler in [Sync.handle_mempool_msg_for] gates on the same bit
   (matches Core's net_processing.cpp guard on
   `peer.m_our_services & NODE_BLOOM`). *)
let peer_bloom_filters : bool ref = ref false

(* Configure the NODE_BLOOM advertisement.  Must be called BEFORE any peer
   is initialised so that [our_services ()] is consistent across the run. *)
let set_peer_bloom_filters (b : bool) : unit =
  peer_bloom_filters := b

(* BIP-159 NODE_NETWORK_LIMITED advertisement gate.  Set at startup by
   [Cli.run] from [config.prune > 0].  When ON, [our_services ()] OR's
   in the [network_limited] flag so the version handshake signals that
   we serve only the recent ~288-block window.  Mirrors Core's
   `init.cpp` (`nLocalServices |= NODE_NETWORK_LIMITED` when
   `IsPruneMode()` is true). *)
let prune_mode_advertise : bool ref = ref false

let set_prune_mode_advertise (b : bool) : unit =
  prune_mode_advertise := b

(* Our node's advertised services: full node with witness support, plus
   NODE_BLOOM iff [peer_bloom_filters] is set, plus NODE_NETWORK_LIMITED
   iff [prune_mode_advertise] is set.  Returns a fresh record on every
   call so callers see the current values of the flags.  Core advertises
   NODE_NETWORK alongside NODE_NETWORK_LIMITED in the auto-prune case
   (the node still has the recent-288 window). *)
let our_services () : peer_services = {
  network = true;
  getutxo = false;
  bloom = !peer_bloom_filters;
  witness = true;
  compact_filters = false;
  network_limited = !prune_mode_advertise;
}

(* Connection and read timeouts *)
let connection_timeout = 10.0  (* seconds *)
let read_timeout = 30.0        (* seconds *)
let ping_interval = 120.0      (* 2 minutes between pings *)
let ping_timeout = 20.0        (* 20 seconds to receive pong *)
let handshake_timeout = 60.0   (* 60 seconds for version/verack handshake *)

(* BIP-324 v2 outbound probe deadline.  Bitcoin Core net.cpp uses ~30s; we
   mirror it so a stalled remote doesn't wedge the dialer for long. *)
let v2_handshake_deadline = 30.0  (* seconds for cipher handshake *)

(* Helper: parse a CAMLCOIN_BIP324_V2* env var as a boolean.  Returns true
   iff the variable is set to a value other than {0, false, off, ""}. *)
let env_flag_on (key : string) : bool =
  match Sys.getenv_opt key with
  | None -> false
  | Some v ->
    let v = String.lowercase_ascii v in
    not (v = "0" || v = "false" || v = "off" || v = "")

(* Returns true iff BIP-324 v2 outbound is enabled. Default OFF (conservative)
   since this code path is brand new — enable per-process via
   CAMLCOIN_BIP324_V2_OUTBOUND=1 (or the umbrella CAMLCOIN_BIP324_V2=1 which
   gates both directions).  Mirrors clearbit's CLEARBIT_BIP324_V2 gate pattern
   (clearbit/src/peer.zig:653). *)
let bip324_v2_outbound_enabled () : bool =
  env_flag_on "CAMLCOIN_BIP324_V2_OUTBOUND" || env_flag_on "CAMLCOIN_BIP324_V2"

(* Returns true iff BIP-324 v2 inbound (responder mode) is enabled.  Default
   OFF — enable per-process via CAMLCOIN_BIP324_V2_INBOUND=1 (or the umbrella
   CAMLCOIN_BIP324_V2=1 which gates both directions).  When OFF the inbound
   listener hands every byte straight to read_message_v1 (legacy behaviour).
   When ON the listener peeks the first 16 bytes of the stream, classifies
   the connection (v1 magic + "version\0\0\0\0\0" → v1; anything else → v2),
   and on v2 detection drives the BIP-324 cipher handshake in responder mode
   before falling through to the application version/verack. *)
let bip324_v2_inbound_enabled () : bool =
  env_flag_on "CAMLCOIN_BIP324_V2_INBOUND" || env_flag_on "CAMLCOIN_BIP324_V2"

(* 12-byte v1 command for VERSION ("version" plus 5 NUL bytes).  Used by the
   inbound peek-classifier to distinguish a v1 VERSION header from a v2
   ElligatorSwift pubkey.  Matches clearbit/src/v2_transport.zig:114. *)
let v1_version_command : bytes =
  let b = Bytes.make 12 '\000' in
  Bytes.blit_string "version" 0 b 0 7;
  b

(* Length of the v1 detection prefix: 4-byte network magic + 12-byte command.
   Mirrors clearbit's V1_PREFIX_LEN (clearbit/src/v2_transport.zig:111). *)
let v1_prefix_len = 16

(* Classify the leading 16 bytes of an inbound TCP stream.  Returns true iff
   they look like the start of a v1 VERSION message (4-byte network magic
   followed by the 12-byte "version" command).  Caller must pass at least
   [v1_prefix_len] bytes; otherwise the function returns false (i.e. "not v1",
   which forces the caller to treat the connection as v2 — same conservative
   choice as Bitcoin Core's V2Transport::ProcessReceivedMaybeV1Bytes). *)
let looks_like_v1_version (peek : bytes) (magic : int32) : bool =
  if Bytes.length peek < v1_prefix_len then false
  else begin
    let m = Cstruct.LE.get_uint32 (Cstruct.of_bytes peek) 0 in
    if m <> magic then false
    else
      let cmd = Bytes.sub peek 4 12 in
      Bytes.equal cmd v1_version_command
  end

(* Per-address LRU cache of addresses that turned out to be v1-only.
   Bounded at 4096 entries (matches clearbit's V2_FALLBACK_CACHE_MAX).
   When full, eviction is "drop the first entry the iterator yields"
   — implementation-defined order, same compromise as clearbit. The cache
   is process-wide / in-memory only (lost on restart, which is fine). *)
module V1OnlyCache : sig
  val mark : addr:string -> port:int -> unit
  val is_v1_only : addr:string -> port:int -> bool
  val size : unit -> int
  val clear : unit -> unit
  val capacity : int
end = struct
  let capacity = 4096
  let table : (string, unit) Hashtbl.t = Hashtbl.create 64
  let key ~addr ~port = Printf.sprintf "%s:%d" addr port
  let mark ~addr ~port =
    let k = key ~addr ~port in
    if not (Hashtbl.mem table k) then begin
      if Hashtbl.length table >= capacity then begin
        (* Drop one arbitrary entry to make room.  Hashtbl.iter visits
           in implementation-defined order; we eject the first key it
           hands us and stop. *)
        let to_drop = ref None in
        (try Hashtbl.iter (fun k' () -> to_drop := Some k'; raise Exit) table
         with Exit -> ());
        Option.iter (Hashtbl.remove table) !to_drop
      end;
      Hashtbl.add table k ()
    end
  let is_v1_only ~addr ~port = Hashtbl.mem table (key ~addr ~port)
  let size () = Hashtbl.length table
  let clear () = Hashtbl.clear table
end

(* Inventory trickling constants - match Bitcoin Core net_processing.cpp *)
let inbound_inv_broadcast_interval = 5.0   (* Average 5 seconds for inbound peers *)
let outbound_inv_broadcast_interval = 2.0  (* Average 2 seconds for outbound peers *)
let max_inv_per_flush = 1000               (* Maximum inventory entries per flush *)

(* Feefilter constants - match Bitcoin Core net_processing.cpp *)
let avg_feefilter_broadcast_interval = 600.0   (* Average 10 minutes between broadcasts *)
let max_feefilter_change_delay = 300.0         (* 5 minutes max delay after significant change *)
let feefilter_version = 70013l                 (* Minimum protocol version for feefilter *)

(* Minimum protocol version required (post-segwit) *)
let min_protocol_version = 70015l

(* Direction of a peer connection *)
type peer_direction = Inbound | Outbound

(* Inventory entry for trickling *)
type inv_entry = {
  inv_type : P2p.inv_type;
  hash : Types.hash256;
  fee_rate : int64 option;  (* Fee rate in sat/kvB for transactions, None for blocks *)
}

(* Peer connection state *)
type peer = {
  id : int;
  addr : string;
  port : int;
  mutable state : peer_state;
  mutable version_msg : Types.version_msg option;
  mutable services : peer_services;
  mutable best_height : int32;
  mutable last_seen : float;
  mutable last_ping : float;
  mutable ping_nonce : int64 option;
  mutable latency : float;
  mutable bytes_sent : int;
  mutable bytes_received : int;
  mutable msgs_sent : int;
  mutable msgs_received : int;
  ic : Lwt_io.input_channel;
  oc : Lwt_io.output_channel;
  fd : Lwt_unix.file_descr;
  network : Consensus.network_config;
  mutable send_headers : bool;   (* Peer requested sendheaders *)
  mutable wtxid_relay : bool;    (* Peer requested wtxidrelay *)
  mutable sendaddrv2 : bool;     (* Peer requested sendaddrv2 *)
  mutable misbehavior_score : int; (* Accumulated misbehavior score; ban at >= 100 *)
  direction : peer_direction;    (* Inbound or outbound connection *)
  mutable feefilter : int64;     (* Minimum fee rate (sat/kvB) advertised by peer *)
  mutable fee_filter_sent : int64;  (* Last feefilter value we sent to this peer *)
  mutable next_send_feefilter : float; (* Next time to send our feefilter to this peer *)
  mutable relay : bool;             (* Peer's relay flag from version message *)
  mutable time_offset : int64;      (* peer_version_timestamp - our_time_at_receipt (seconds) *)
  mutable cmpct_high_bandwidth : bool; (* Peer wants high-bandwidth compact blocks *)
  mutable cmpct_version : int64;    (* Compact block protocol version *)
  mutable block_relay_only : bool;  (* Block-relay-only connection (no tx relay) *)
  (* BIP-331 package relay: peer announced sendpackages support. *)
  mutable sendpackages_received : bool;
  mutable pkg_relay_version : int64;
  mutable pkg_max_count : int32;
  mutable pkg_max_weight : int32;
  mutable msg_count_window : int;   (* Messages received in current window *)
  mutable msg_window_start : float; (* Start time of current rate-limit window *)
  mutable handshake_complete : bool; (* Version/verack handshake completed *)
  mutable version_received : bool;   (* VERSION message has been received *)
  our_nonce : int64;                 (* Our nonce for self-connection detection *)
  (* Inventory trickling state *)
  inv_queue : inv_entry Queue.t;     (* Pending tx inventory to announce *)
  mutable next_inv_send : float;     (* Next time to flush inv queue *)
  mutable trickling_active : bool;   (* Whether the trickle timer is running *)
  mutable pending_read : P2p.message_payload Lwt.t option;  (* In-flight read to prevent concurrent reads *)
  (* BIP-324 v2 transport.  None = legacy v1 path (the default).  Some
     (P2p.V2 state) = encrypted v2 transport; send/read dispatch on this. *)
  mutable transport : P2p.transport option;
}

(* Generate random bytes from /dev/urandom *)
let random_bytes (n : int) : Cstruct.t =
  let buf = Cstruct.create n in
  let ic = open_in_bin "/dev/urandom" in
  let bytes = really_input_string ic n in
  close_in ic;
  Cstruct.blit_from_string bytes 0 buf 0 n;
  buf

(* Generate a random 64-bit nonce *)
let random_nonce () : int64 =
  let nonce_bytes = random_bytes 8 in
  Cstruct.LE.get_uint64 nonce_bytes 0

(* Create a local network address (IPv4-mapped IPv6 for 127.0.0.1) *)
let make_local_addr () : Types.net_addr =
  let addr = Cstruct.create 16 in
  (* IPv4-mapped IPv6: ::ffff:127.0.0.1 *)
  Cstruct.set_uint8 addr 10 0xFF;
  Cstruct.set_uint8 addr 11 0xFF;
  Cstruct.set_uint8 addr 12 127;
  Cstruct.set_uint8 addr 13 0;
  Cstruct.set_uint8 addr 14 0;
  Cstruct.set_uint8 addr 15 1;
  { services = services_to_int64 (our_services ()); addr; port = 0 }

(* Poisson delay: returns exponentially distributed delay with given average.
   Uses the inverse CDF method: -ln(U) * avg where U is uniform (0,1).
   This matches Bitcoin Core's rand_exp_duration / MakeExponentiallyDistributed. *)
let poisson_delay (avg : float) : float =
  let u = Random.float 1.0 in
  (* Avoid log(0) by using max with small epsilon *)
  let u_safe = max u 1e-10 in
  ~-.(Float.log u_safe) *. avg

(* Create a peer from an already-connected fd (used for both outbound and inbound) *)
let make_peer ~(network : Consensus.network_config) ~(addr : string)
    ~(port : int) ~(id : int) ~(direction : peer_direction)
    ~(fd : Lwt_unix.file_descr) : peer =
  let ic = Lwt_io.of_fd ~mode:Lwt_io.Input fd in
  let oc = Lwt_io.of_fd ~mode:Lwt_io.Output fd in
  let avg_interval = match direction with
    | Inbound -> inbound_inv_broadcast_interval
    | Outbound -> outbound_inv_broadcast_interval
  in
  { id; addr; port;
    state = Connected;
    version_msg = None;
    services = empty_services;
    best_height = 0l;
    last_seen = Unix.gettimeofday ();
    last_ping = 0.0;
    ping_nonce = None;
    latency = 0.0;
    bytes_sent = 0;
    bytes_received = 0;
    msgs_sent = 0;
    msgs_received = 0;
    ic; oc; fd; network;
    send_headers = false;
    wtxid_relay = false;
    sendaddrv2 = false;
    misbehavior_score = 0;
    direction;
    feefilter = 0L;
    fee_filter_sent = 0L;
    next_send_feefilter = Unix.gettimeofday () +. poisson_delay avg_feefilter_broadcast_interval;
    relay = true;
    time_offset = 0L;
    cmpct_high_bandwidth = false;
    cmpct_version = 0L;
    block_relay_only = false;
    sendpackages_received = false;
    pkg_relay_version = 0L;
    pkg_max_count = 0l;
    pkg_max_weight = 0l;
    msg_count_window = 0;
    msg_window_start = Unix.gettimeofday ();
    handshake_complete = false;
    version_received = false;
    our_nonce = random_nonce ();  (* Generate nonce for self-connection detection *)
    (* Initialize inventory trickling state *)
    inv_queue = Queue.create ();
    next_inv_send = Unix.gettimeofday () +. poisson_delay avg_interval;
    trickling_active = false;
    pending_read = None;
    (* Default to v1 (= None).  The BIP-324 v2 dialer flips this to
       Some (P2p.V2 state) once the cipher handshake completes. *)
    transport = None;
  }

(* Establish TCP connection to a peer with timeout.
   The socket fd is always closed on any failure path (timeout,
   ECONNREFUSED, EHOSTUNREACH, or make_peer raising) to prevent
   outbound socket fd leaks. See CAMLCOIN-REVIVE-FEASIBILITY.md and
   wave2-2026-04-14/CAMLCOIN-SMALL-PATCH-FIX.md. *)
let connect ~(network : Consensus.network_config) ~(addr : string)
    ~(port : int) ~(id : int) : peer Lwt.t =
  let open Lwt.Syntax in
  let* addresses = Lwt_unix.getaddrinfo addr
    (string_of_int port)
    [Unix.AI_SOCKTYPE Unix.SOCK_STREAM] in
  match addresses with
  | [] -> Lwt.fail_with ("Cannot resolve: " ^ addr)
  | ai :: _ ->
    let fd = Lwt_unix.socket ai.ai_family
      ai.ai_socktype ai.ai_protocol in
    Lwt.catch (fun () ->
      (* Set connection timeout *)
      let timeout =
        let* () = Lwt_unix.sleep connection_timeout in
        Lwt.fail_with "Connection timeout" in
      let do_connect = Lwt_unix.connect fd ai.ai_addr in
      let* () = Lwt.pick [do_connect; timeout] in
      Lwt.return (make_peer ~network ~addr ~port ~id ~direction:Outbound ~fd))
    (fun exn ->
      let* () = Lwt.catch
        (fun () -> Lwt_unix.close fd)
        (fun _ -> Lwt.return_unit) in
      Lwt.fail exn)

(* Establish TCP connection through a proxy (Tor, I2P, or SOCKS5).
   The proxy-produced fd is defensively closed if make_peer ever raises. *)
let connect_with_proxy ~(network : Consensus.network_config) ~(addr : string)
    ~(port : int) ~(id : int) ~(proxy_config : P2p.proxy_config) : peer Lwt.t =
  let open Lwt.Syntax in
  (* Set connection timeout *)
  let timeout =
    let* () = Lwt_unix.sleep connection_timeout in
    Lwt.fail_with "Connection timeout"
  in
  let do_connect =
    let* result = P2p.connect_with_proxy ~config:proxy_config ~host:addr ~port in
    match result with
    | Ok fd -> Lwt.return fd
    | Error msg -> Lwt.fail_with msg
  in
  let* fd = Lwt.pick [do_connect; timeout] in
  Lwt.catch
    (fun () ->
      Lwt.return (make_peer ~network ~addr ~port ~id ~direction:Outbound ~fd))
    (fun exn ->
      let* () = Lwt.catch
        (fun () -> Lwt_unix.close fd)
        (fun _ -> Lwt.return_unit) in
      Lwt.fail exn)

(* Read a v1 message from the peer (legacy plaintext path). *)
let read_message_v1 (peer : peer) : P2p.message_payload Lwt.t =
  let open Lwt.Syntax in
  (* Protect the entire read sequence from cancellation to prevent TCP desync *)
  Lwt.no_cancel begin
    (* Read 24-byte message header *)
    let header_buf = Bytes.create P2p.message_header_size in
    let* () = Lwt_io.read_into_exactly peer.ic
      header_buf 0 P2p.message_header_size in
    let header_cs = Cstruct.of_bytes header_buf in
    let r = Serialize.reader_of_cstruct header_cs in
    let (magic, _cmd, length, expected_checksum) =
      P2p.deserialize_message_header r in
    (* Verify network magic *)
    if magic <> peer.network.magic then begin
      let msg = Printf.sprintf "Bad network magic: expected 0x%08lx, got 0x%08lx"
        peer.network.magic magic in
      Log.warn (fun m -> m "[%s:%d] %s — disconnecting peer" peer.addr peer.port msg);
      Lwt.fail (Peer_protocol_error msg)
    end
    else if length > P2p.max_message_size then
      Lwt.fail (Peer_protocol_error (Printf.sprintf "Message too large: %d bytes" length))
    else begin
      (* Read payload *)
      let payload_buf = Bytes.create length in
      let* () =
        if length > 0 then
          Lwt_io.read_into_exactly peer.ic payload_buf 0 length
        else Lwt.return_unit in
      let payload_cs = Cstruct.of_bytes payload_buf in
      (* Verify checksum *)
      let actual_checksum =
        Cstruct.sub (Crypto.sha256d payload_cs) 0 4 in
      if not (Cstruct.equal expected_checksum actual_checksum) then
        Lwt.fail (Peer_protocol_error "Bad message checksum")
      else begin
        (* Update statistics *)
        peer.bytes_received <-
          peer.bytes_received + P2p.message_header_size + length;
        peer.msgs_received <- peer.msgs_received + 1;
        peer.last_seen <- Unix.gettimeofday ();
        (* Deserialize the payload based on command *)
        let pr = Serialize.reader_of_cstruct payload_cs in
        Lwt.return (P2p.deserialize_payload _cmd pr)
      end
    end
  end

(* Read a v2 (BIP-324) application packet from a peer whose cipher
   handshake has already completed.  Pumps raw bytes through
   [P2p.v2_receive_bytes] until the v2 state machine yields a complete
   message, then returns it.  Leaves any extra bytes in the V2 state's
   recv_buffer for the next call. *)
let read_message_v2 (peer : peer) (state : P2p.v2_state)
    : P2p.message_payload Lwt.t =
  let open Lwt.Syntax in
  Lwt.no_cancel begin
    let chunk_size = 8192 in
    let chunk = Bytes.create chunk_size in
    (* On entry, attempt to drive the state machine on whatever is already
       in [state.recv_buffer] before reading from the socket.  Bitcoin Core
       and clearbit both send VERSION + VERACK back-to-back during the v2
       app handshake; both packets typically arrive in a single TCP segment
       and are concatenated into [recv_buffer] by the previous call's read.
       After [v2_get_message] has consumed the first packet, [recv_state]
       is reset to [V2RecvApp] but the leftover ciphertext for the next
       packet is still in [recv_buffer].  Without an explicit drain the
       responder blocks on a socket that has nothing new to deliver,
       wedging the post-cipher application handshake. *)
    let try_drain_buffer () : bool =
      (* Returns true iff [process()] made progress (either decoded a
         complete message or consumed bytes that advanced [recv_state]).
         Passes an empty chunk so the buffer pointer is unchanged on entry
         and the function call is purely a state-machine pump. *)
      let pre_state = state.recv_state in
      let pre_len = Cstruct.length state.recv_buffer in
      let ok = P2p.v2_receive_bytes state Cstruct.empty in
      if not ok then false
      else
        P2p.v2_message_complete state
        || state.recv_state <> pre_state
        || Cstruct.length state.recv_buffer <> pre_len
    in
    let rec loop () =
      if P2p.v2_message_complete state then begin
        match P2p.v2_get_message state with
        | None ->
          Lwt.fail (Peer_protocol_error "v2: undecodable application packet")
        | Some msg ->
          peer.msgs_received <- peer.msgs_received + 1;
          peer.last_seen <- Unix.gettimeofday ();
          Lwt.return msg.P2p.payload
      end else if Cstruct.length state.recv_buffer > 0
                  && try_drain_buffer () then
        loop ()
      else begin
        let* n = Lwt_io.read_into peer.ic chunk 0 chunk_size in
        if n = 0 then Lwt.fail End_of_file
        else begin
          peer.bytes_received <- peer.bytes_received + n;
          let received = Cstruct.of_bytes ~len:n chunk in
          let ok = P2p.v2_receive_bytes state received in
          if not ok then
            Lwt.fail (Peer_protocol_error "v2: state machine rejected bytes")
          else loop ()
        end
      end
    in
    loop ()
  end

(* Top-level read_message: dispatch on transport.  V1 is the default; V2
   is only set after [perform_v2_handshake] has installed the V2Transport
   on the peer (driven by either the outbound dialer or the inbound
   responder peek-classifier). *)
let read_message (peer : peer) : P2p.message_payload Lwt.t =
  match peer.transport with
  | None | Some (P2p.V1 _) -> read_message_v1 peer
  | Some (P2p.V2 state) -> read_message_v2 peer state

(* Read a message with timeout.
   Uses a pending_read slot to avoid starting concurrent reads on the same
   Lwt_io channel.  When a timeout fires, the in-flight (Lwt.no_cancel)
   read is kept in pending_read so the next call reuses it instead of
   creating a second reader — which would interleave bytes and cause
   stream misalignment ("bad magic bytes"). *)
let read_message_with_timeout (peer : peer) (timeout_sec : float)
    : P2p.message_payload option Lwt.t =
  let open Lwt.Syntax in
  (* W78 fast-path: if the peer is already disconnected, a fresh read_message
     would synchronously reject with Channel_closed, the catch handler would
     run on the current stack, and the caller's recursive loop would grow the
     stack unbounded (Lwt.bind is not tail-recursive on already-resolved
     promises).  Short-circuit with Lwt.pause () to force the scheduler to
     yield between iterations.  Prevents the 1708-warning Stack-overflow seen
     in wave47-2026-04-16/camlcoin-crash-2026-04-19-1455.log.tail. *)
  if peer.state = Disconnected || peer.state = Disconnecting then
    let* () = Lwt.pause () in
    Lwt.return_none
  else
  (* Reuse an existing in-flight read, or start a fresh one *)
  let read_promise = match peer.pending_read with
    | Some p -> p
    | None ->
      let p = read_message peer in
      peer.pending_read <- Some p;
      p
  in
  let timeout =
    let* () = Lwt_unix.sleep timeout_sec in
    Lwt.return `Timeout in
  (* W74: catch read-side exceptions (End_of_file when the peer closes
     mid-message, ECONNRESET, etc.) and report them as a timeout.  Prior
     to this fix, a peer closing its socket during header sync would
     propagate End_of_file past the sync fiber's exception boundary and
     kill the header-sync thread entirely — wedging IBD at the batch
     boundary where the peer dropped (observed at height 162,000, i.e.
     exactly 81 × max_headers_per_message).  Now the dead promise is
     dropped, the peer is marked Disconnected so it won't be re-selected,
     and the caller sees a clean `None` (= timeout) and retries with a
     different peer. *)
  let read =
    Lwt.catch
      (fun () ->
        let* msg = read_promise in
        Lwt.return (`Msg msg))
      (fun exn ->
        Log.warn (fun m ->
          m "[%s:%d] read_message failed: %s — treating as timeout"
            peer.addr peer.port (Printexc.to_string exn));
        peer.pending_read <- None;
        if peer.state <> Disconnected && peer.state <> Disconnecting then begin
          peer.state <- Disconnected;
          Lwt.async (fun () ->
            Lwt.catch
              (fun () -> Lwt_unix.close peer.fd)
              (fun _ -> Lwt.return_unit))
        end;
        Lwt.return `Timeout)
  in
  (* Lwt.choose does NOT cancel the loser, so the read keeps running *)
  let* result = Lwt.choose [read; timeout] in
  match result with
  | `Msg msg ->
    (* Read completed — clear the pending slot *)
    peer.pending_read <- None;
    Lwt.return (Some msg)
  | `Timeout ->
    (* Timeout fired but the read is still in flight in pending_read;
       it will be reused on the next call.  (The read-failure path above
       clears pending_read itself before returning `Timeout.)
       W78: Lwt.pause () before returning so the scheduler yields even when
       the whole Lwt.catch + Lwt.choose chain resolved synchronously (e.g.
       Channel_closed was already raised before this fn was entered).  Breaks
       stack-growing sync recursion in callers that loop on None. *)
    let* () = Lwt.pause () in
    Lwt.return None

(* Send a v1 (legacy plaintext) message to the peer. *)
let send_message_v1 (peer : peer)
    (payload : P2p.message_payload) : unit Lwt.t =
  let open Lwt.Syntax in
  let data = P2p.serialize_message peer.network.magic payload in
  let data_str = Cstruct.to_string data in
  (match payload with
   | P2p.GetheadersMsg _ ->
     let hex = Buffer.create 200 in
     String.iter (fun c -> Buffer.add_string hex (Printf.sprintf "%02x" (Char.code c))) data_str;
     Logs.debug (fun m -> m "RAW getheaders bytes (%d): %s" (String.length data_str) (Buffer.contents hex))
   | _ -> ());
  let* () = Lwt_io.write_from_string_exactly peer.oc
    data_str 0 (String.length data_str) in
  let* () = Lwt_io.flush peer.oc in
  peer.bytes_sent <- peer.bytes_sent + Cstruct.length data;
  peer.msgs_sent <- peer.msgs_sent + 1;
  Lwt.return_unit

(* Send an application message over a v2 (BIP-324) transport whose cipher
   handshake has completed.  Encrypts via [v2_set_message] and flushes the
   resulting ciphertext via [v2_get_bytes_to_send]. *)
let send_message_v2 (peer : peer) (state : P2p.v2_state)
    (payload : P2p.message_payload) : unit Lwt.t =
  let open Lwt.Syntax in
  let queued = P2p.v2_set_message state payload in
  if not queued then
    Lwt.fail (Peer_protocol_error "v2: cannot encrypt before handshake complete")
  else begin
    let bytes = P2p.v2_get_bytes_to_send state in
    let n = Cstruct.length bytes in
    if n = 0 then Lwt.return_unit
    else begin
      let s = Cstruct.to_string bytes in
      let* () = Lwt_io.write_from_string_exactly peer.oc s 0 n in
      let* () = Lwt_io.flush peer.oc in
      peer.bytes_sent <- peer.bytes_sent + n;
      peer.msgs_sent <- peer.msgs_sent + 1;
      Lwt.return_unit
    end
  end

(* Top-level send_message: dispatch on transport.  V1 is the default;
   the v2 path is only active after the cipher handshake completes. *)
let send_message (peer : peer)
    (payload : P2p.message_payload) : unit Lwt.t =
  match peer.transport with
  | None | Some (P2p.V1 _) -> send_message_v1 peer payload
  | Some (P2p.V2 state) -> send_message_v2 peer state payload

(* Helper: process a version message received from the remote peer *)
let process_version_msg (peer : peer) (v : Types.version_msg) : unit Lwt.t =
  (* Check for duplicate VERSION message *)
  if peer.version_received then begin
    (* Bitcoin Core gives 1 point for duplicate version (redundant version message) *)
    peer.misbehavior_score <- peer.misbehavior_score + 1;
    Lwt.fail_with "Duplicate VERSION message received"
  end else begin
    peer.version_received <- true;
    peer.version_msg <- Some v;
    peer.services <- services_of_int64 v.services;
    peer.best_height <- v.start_height;
    peer.relay <- v.relay;
    peer.time_offset <- Int64.sub v.timestamp (Int64.of_float (Unix.gettimeofday ()));
    if v.protocol_version < min_protocol_version then
      Lwt.fail_with (Printf.sprintf
        "Peer protocol version too old: %ld (minimum: %ld)"
        v.protocol_version min_protocol_version)
    else if v.nonce = peer.our_nonce then
      (* Self-connection detection *)
      Lwt.fail_with "Connected to self (nonce collision)"
    else if not peer.services.witness then
      Lwt.fail_with "Peer does not support NODE_WITNESS (required)"
    else if peer.direction = Outbound &&
            not (peer.services.network || peer.services.network_limited) then
      Lwt.fail_with
        "Outbound peer does not support NODE_NETWORK or NODE_NETWORK_LIMITED"
    else
      Lwt.return_unit
  end

(* Build a version message for outgoing handshake *)
let make_version_msg (peer : peer) (our_height : int32) : Types.version_msg =
  { protocol_version = Types.protocol_version;
    services = services_to_int64 (our_services ());
    timestamp = Int64.of_float (Unix.gettimeofday ());
    addr_recv = {
      services = 0L;
      addr = Cstruct.create 16;
      port = peer.port;
    };
    addr_from = make_local_addr ();
    nonce = peer.our_nonce;  (* Use peer's stored nonce for self-connection detection *)
    user_agent = "/CamlCoin:" ^ Types.version ^ "/";
    start_height = our_height;
    relay = true;
  }

(* Send pre-verack feature negotiation messages (BIP-339 wtxidrelay,
   BIP-155 sendaddrv2).  These MUST be sent after version exchange but
   BEFORE verack per the respective BIPs. *)
let send_feature_negotiation (peer : peer) : unit Lwt.t =
  let open Lwt.Syntax in
  (* Send wtxidrelay if peer supports witness (BIP-339) *)
  let* () =
    if peer.services.witness &&
       (match peer.version_msg with
        | Some v -> v.protocol_version >= Consensus.wtxid_relay_version
        | None -> false) then
      send_message peer P2p.WtxidrelayMsg
    else Lwt.return_unit
  in
  (* Send sendaddrv2 (BIP-155) *)
  send_message peer P2p.SendaddrV2Msg

(* Read messages until verack arrives, accepting feature negotiation messages
   (wtxidrelay, sendaddrv2, sendcmpct, feefilter, sendtxrcncl, sendpackages)
   that arrive before verack.  Returns unit on success or fails on timeout /
   unexpected messages.

   sendtxrcncl (BIP-330) and sendpackages (BIP-431) MUST be sent between
   VERSION and VERACK per their respective BIPs (see Bitcoin Core
   net_processing.cpp ProcessMessage(SENDTXRCNCL) which disconnects peers
   that send it after fSuccessfullyConnected).  Camlcoin does not implement
   Erlay reconciliation or package relay, so we silently ignore both —
   matching Core's "ignored, as our node does not have txreconciliation
   enabled" behaviour.  Without this, lunarblock-as-initiator (which sends
   sendtxrcncl right after the peer's VERSION arrives, before its own
   VERACK) trips a spurious "Unexpected message before verack" failure on
   the responder side and the connection is torn down — observed as the
   single remaining v2 divergence in the BIP-324 interop matrix
   (lunarblock → camlcoin = v1, every other initiator → camlcoin = v2). *)
let read_until_verack (peer : peer) : unit Lwt.t =
  let open Lwt.Syntax in
  let deadline = Unix.gettimeofday () +. read_timeout in
  let rec loop () =
    let remaining = deadline -. Unix.gettimeofday () in
    if remaining <= 0.0 then
      Lwt.fail_with "Timeout waiting for verack"
    else begin
      let* msg_opt = read_message_with_timeout peer remaining in
      match msg_opt with
      | None -> Lwt.fail_with "Timeout waiting for verack"
      | Some P2p.VerackMsg -> Lwt.return_unit
      | Some P2p.WtxidrelayMsg ->
        peer.wtxid_relay <- true;
        loop ()
      | Some P2p.SendaddrV2Msg ->
        peer.sendaddrv2 <- true;
        loop ()
      | Some (P2p.SendcmpctMsg { announce; version }) ->
        peer.cmpct_high_bandwidth <- announce;
        peer.cmpct_version <- version;
        loop ()
      | Some (P2p.FeefilterMsg feerate) ->
        (* Accept feefilter during feature negotiation *)
        peer.feefilter <- feerate;
        loop ()
      | Some (P2p.SendtxrcnclMsg _) ->
        (* BIP-330 Erlay tx reconciliation negotiation.  We don't implement
           the Erlay responder, so silently ignore (matches Core when
           m_txreconciliation is null). *)
        loop ()
      | Some (P2p.SendpackagesMsg msg) ->
        (* BIP-331 package relay negotiation.  Capture the peer's announced
           limits so we can clamp our [getpkgtxns] requests later.  Per the
           BIP, sendpackages MUST be sent between VERSION and VERACK; reaching
           here means the peer is offering 1p1c (or richer) package relay. *)
        peer.sendpackages_received <- true;
        peer.pkg_relay_version <- msg.pkg_version;
        peer.pkg_max_count <- msg.pkg_max_count;
        peer.pkg_max_weight <- msg.pkg_max_weight;
        loop ()
      | Some _ -> Lwt.fail_with "Unexpected message before verack"
    end
  in
  loop ()

(* Gracefully disconnect from peer *)
let disconnect (peer : peer) : unit Lwt.t =
  let open Lwt.Syntax in
  peer.state <- Disconnecting;
  (* Close input channel *)
  let* () = Lwt.catch
    (fun () -> Lwt_io.close peer.ic)
    (fun _ -> Lwt.return_unit) in
  (* Close output channel *)
  let* () = Lwt.catch
    (fun () -> Lwt_io.close peer.oc)
    (fun _ -> Lwt.return_unit) in
  (* Close the socket *)
  let* () = Lwt.catch
    (fun () -> Lwt_unix.close peer.fd)
    (fun _ -> Lwt.return_unit) in
  peer.state <- Disconnected;
  Lwt.return_unit

(* ============================================================================
   BIP-324 v2 outbound dialer
   ----------------------------------------------------------------------------
   Mirrors clearbit's [connectOutboundNegotiated] (clearbit/src/peer.zig:1845).
   Try v2 first (gated by [bip324_v2_outbound_enabled] + per-address v1-only
   cache); on failure, mark address v1-only and reconnect on a fresh socket
   in v1 mode (sending v2 garbage is destructive on a v1 peer so the original
   socket cannot be reused).
   ============================================================================ *)

(* Drive the BIP-324 cipher handshake on a peer that already has a V2Transport
   attached.  Direction-agnostic — the v2 state machine handles both initiator
   and responder transitions internally; this function just shuttles bytes.
   Loops until the V2 state machine has:
     1. flushed our staged bytes on the wire (initiator: pubkey+garbage on
        iteration 1, then garbage terminator + version packet after peer's
        pubkey arrives; responder: pubkey + garbage + terminator + version
        all in one shot once peer's pubkey arrives),
     2. received the peer's ellswift pubkey,
     3. derived the shared secret + ciphers,
     4. emitted our garbage terminator + (decoy + ) version packet,
     5. consumed the peer's garbage + garbage terminator + version packet.
   On success [peer.transport] is left set to [Some (V2 state)] and any
   subsequent send/read flows through encrypted dispatch.  Bounded by
   [v2_handshake_deadline].

   Failure modes:
     - V2RecvV1Fallback         → peer is speaking v1 (caller must close socket)
     - v2_receive_bytes = false → cipher decryption failed
     - deadline reached         → stalled remote
     - End_of_file / read err   → peer closed
   In every failure case we raise — caller decides whether to fall back. *)
let perform_v2_handshake (peer : peer)
    (state : P2p.v2_state) : unit Lwt.t =
  let open Lwt.Syntax in
  let chunk_size = 8192 in
  let chunk = Bytes.create chunk_size in
  let start = Unix.gettimeofday () in
  (* Flush whatever the V2 transport has staged for sending (initial pubkey
     + garbage on the first iteration; later, garbage terminator + version
     packet ciphertext after we've received the peer's ellswift pubkey). *)
  let flush_send () =
    let bytes = P2p.v2_get_bytes_to_send state in
    let n = Cstruct.length bytes in
    if n = 0 then Lwt.return_unit
    else begin
      let s = Cstruct.to_string bytes in
      let* () = Lwt_io.write_from_string_exactly peer.oc s 0 n in
      let* () = Lwt_io.flush peer.oc in
      peer.bytes_sent <- peer.bytes_sent + n;
      Lwt.return_unit
    end
  in
  let rec loop () =
    let elapsed = Unix.gettimeofday () -. start in
    if elapsed >= v2_handshake_deadline then
      Lwt.fail_with "BIP-324 v2 handshake timeout"
    else begin
      (* Flush staged bytes (idempotent if buffer is empty). *)
      let* () = flush_send () in
      (* Done?  V2RecvAppReady or recv_state advanced past V2RecvVersion
         (i.e., we've consumed the peer's version packet) AND send_state is
         V2SendReady (we've already emitted our version packet). *)
      let recv_done =
        match state.recv_state with
        | P2p.V2RecvApp | P2p.V2RecvAppReady -> true
        | _ -> false
      in
      let send_done = state.send_state = P2p.V2SendReady in
      if recv_done && send_done && Cstruct.length state.send_buffer = 0 then
        Lwt.return_unit
      else begin
        (* Read more bytes with a deadline-bounded timeout. *)
        let remaining = v2_handshake_deadline -. elapsed in
        let read_task =
          let* n = Lwt_io.read_into peer.ic chunk 0 chunk_size in
          if n = 0 then Lwt.fail End_of_file
          else Lwt.return n
        in
        let timeout_task =
          let* () = Lwt_unix.sleep remaining in
          Lwt.fail_with "BIP-324 v2 handshake timeout"
        in
        let* n = Lwt.pick [read_task; timeout_task] in
        peer.bytes_received <- peer.bytes_received + n;
        let received = Cstruct.of_bytes ~len:n chunk in
        let ok = P2p.v2_receive_bytes state received in
        if not ok then
          Lwt.fail_with "BIP-324 v2 cipher handshake rejected bytes"
        else if state.recv_state = P2p.V2RecvV1Fallback then
          Lwt.fail_with "BIP-324 v2 peer fell back to v1 mid-handshake"
        else loop ()
      end
    end
  in
  loop ()


(* Core handshake logic for OUTBOUND connections (called with timeout wrapper) *)
let perform_handshake_inner (peer : peer) (our_height : int32) : unit Lwt.t =
  let open Lwt.Syntax in
  peer.state <- HandshakeInProgress;
  let version_msg = make_version_msg peer our_height in
  (* Send our version *)
  let* () = send_message peer (P2p.VersionMsg version_msg) in
  (* Read their version with timeout *)
  let* their_msg_opt = read_message_with_timeout peer read_timeout in
  let* () = match their_msg_opt with
    | None -> Lwt.fail_with "Timeout waiting for version message"
    | Some (P2p.VersionMsg v) ->
      process_version_msg peer v
    | Some _ -> Lwt.fail_with "Expected version message"
  in
  (* Send feature negotiation messages BEFORE verack (BIP-339, BIP-155) *)
  let* () = send_feature_negotiation peer in
  (* Send verack *)
  let* () = send_message peer P2p.VerackMsg in
  (* Read messages until their verack, accepting feature negotiation msgs *)
  let* () = read_until_verack peer in
  (* Mark handshake as complete *)
  peer.handshake_complete <- true;
  (* Post-handshake feature negotiation *)
  (* Request headers announcements instead of inv (BIP-130) *)
  let* () = send_message peer P2p.SendheadersMsg in
  (* BIP 152: Send sendcmpct version 2 (segwit-aware) in low-bandwidth mode *)
  let* () = send_message peer (P2p.make_sendcmpct_msg ~high_bandwidth:false) in
  (* BIP 133: Send initial feefilter - 100 sat/vbyte = 100000 sat/kvB *)
  let* () = send_message peer (P2p.FeefilterMsg 100_000L) in
  peer.state <- Ready;
  (* Reset last_ping so the message loop does not immediately fire a ping.
     Without this, last_ping=0.0 triggers needs_ping on the first iteration,
     and the 30-second read timeout causes the 20-second ping_timed_out check
     to disconnect the peer before the pong can be read. *)
  peer.last_ping <- Unix.gettimeofday ();
  Lwt.return_unit

(* Perform the version/verack handshake for OUTBOUND connections.
   Protocol sequence (BIP-339 / BIP-155 compliant):
   1. We send our version message
   2. Peer sends their version message
   3. Send feature negotiation (wtxidrelay, sendaddrv2) BEFORE verack
   4. Send verack
   5. Read messages until peer's verack (accepting feature negotiation msgs)
   6. Post-handshake: sendheaders

   Uses Lwt.pick for 60-second handshake timeout. *)
let perform_handshake (peer : peer) (our_height : int32) : unit Lwt.t =
  let open Lwt.Syntax in
  let handshake = perform_handshake_inner peer our_height in
  let timeout =
    let* () = Lwt_unix.sleep handshake_timeout in
    let* () = disconnect peer in
    Lwt.fail_with "Handshake timeout"
  in
  Lwt.pick [handshake; timeout]

(* Core handshake logic for INBOUND connections (called with timeout wrapper) *)
let perform_inbound_handshake_inner (peer : peer) (our_height : int32) : unit Lwt.t =
  let open Lwt.Syntax in
  peer.state <- HandshakeInProgress;
  (* Read their version first (inbound peer initiates) *)
  let* their_msg_opt = read_message_with_timeout peer read_timeout in
  let* () = match their_msg_opt with
    | None -> Lwt.fail_with "Timeout waiting for version message"
    | Some (P2p.VersionMsg v) ->
      process_version_msg peer v
    | Some _ -> Lwt.fail_with "Expected version message"
  in
  (* Send our version *)
  let version_msg = make_version_msg peer our_height in
  let* () = send_message peer (P2p.VersionMsg version_msg) in
  (* Send feature negotiation messages BEFORE verack (BIP-339, BIP-155) *)
  let* () = send_feature_negotiation peer in
  (* Send verack *)
  let* () = send_message peer P2p.VerackMsg in
  (* Read messages until their verack, accepting feature negotiation msgs *)
  let* () = read_until_verack peer in
  (* Mark handshake as complete *)
  peer.handshake_complete <- true;
  (* Post-handshake feature negotiation *)
  let* () = send_message peer P2p.SendheadersMsg in
  (* BIP 152: Send sendcmpct version 2 (segwit-aware) in low-bandwidth mode *)
  let* () = send_message peer (P2p.make_sendcmpct_msg ~high_bandwidth:false) in
  (* BIP 133: Send initial feefilter - 100 sat/vbyte = 100000 sat/kvB *)
  let* () = send_message peer (P2p.FeefilterMsg 100_000L) in
  peer.state <- Ready;
  peer.last_ping <- Unix.gettimeofday ();
  Lwt.return_unit

(* Perform the version/verack handshake for INBOUND connections.
   For inbound, the remote peer sends version first, then we respond.
   Protocol sequence:
   1. Read their version message
   2. Send our version message
   3. Send feature negotiation (wtxidrelay, sendaddrv2) BEFORE verack
   4. Send verack
   5. Read messages until peer's verack (accepting feature negotiation msgs)
   6. Post-handshake: sendheaders

   Uses Lwt.pick for 60-second handshake timeout. *)
let perform_inbound_handshake (peer : peer) (our_height : int32) : unit Lwt.t =
  let open Lwt.Syntax in
  let handshake = perform_inbound_handshake_inner peer our_height in
  let timeout =
    let* () = Lwt_unix.sleep handshake_timeout in
    let* () = disconnect peer in
    Lwt.fail_with "Handshake timeout"
  in
  Lwt.pick [handshake; timeout]

(* ============================================================================
   BIP-324 v2 outbound dialer (entry point)
   ----------------------------------------------------------------------------
   Try v2 first (gated by env var [CAMLCOIN_BIP324_V2_OUTBOUND] + per-address
   v1-only LRU cache); on cipher failure, mark address v1-only and reconnect
   on a fresh socket in v1.  Sending v2 ellswift garbage is destructive on a
   v1 peer so the original socket cannot be reused.
   ============================================================================ *)
let connect_outbound_negotiated
    ~(network : Consensus.network_config) ~(addr : string) ~(port : int)
    ~(id : int) ~(our_height : int32) : peer Lwt.t =
  let open Lwt.Syntax in
  let try_v2 =
    bip324_v2_outbound_enabled () && not (V1OnlyCache.is_v1_only ~addr ~port)
  in
  if not try_v2 then begin
    (* v1 path: behave exactly as the legacy [connect; perform_handshake]
       sequence used to. *)
    let* peer = connect ~network ~addr ~port ~id in
    Lwt.catch
      (fun () ->
        let* () = perform_handshake peer our_height in
        Lwt.return peer)
      (fun exn ->
        let* () = Lwt.catch (fun () -> disconnect peer) (fun _ -> Lwt.return_unit) in
        Lwt.fail exn)
  end
  else begin
    (* Phase 1: try v2 on a fresh socket. *)
    let* peer = connect ~network ~addr ~port ~id in
    Lwt.catch
      (fun () ->
        (* Attach an initiator V2Transport.  Its send_buffer already
           contains the ellswift pubkey + initial garbage. *)
        let transport = P2p.create_v2_transport ~initiating:true
          ~magic:peer.network.magic in
        let v2_state = match transport with
          | P2p.V2 s -> s
          | P2p.V1 _ -> assert false
        in
        peer.transport <- Some transport;
        let* () = perform_v2_handshake peer v2_state in
        (* Cipher handshake complete — run the application version/verack
           over the encrypted v2 transport.  send_message / read_message
           dispatch on peer.transport so this Just Works. *)
        let* () = perform_handshake peer our_height in
        Log.info (fun m ->
          m "[%s:%d] BIP-324 v2 outbound connected (encrypted)" addr port);
        Lwt.return peer)
      (fun exn ->
        Log.info (fun m ->
          m "[%s:%d] BIP-324 v2 outbound failed: %s — falling back to v1"
            addr port (Printexc.to_string exn));
        V1OnlyCache.mark ~addr ~port;
        let* () = Lwt.catch (fun () -> disconnect peer) (fun _ -> Lwt.return_unit) in
        (* Phase 2: v1 fallback on a brand-new socket. *)
        let* fresh = connect ~network ~addr ~port ~id in
        Lwt.catch
          (fun () ->
            let* () = perform_handshake fresh our_height in
            Lwt.return fresh)
          (fun exn2 ->
            let* () = Lwt.catch
              (fun () -> disconnect fresh)
              (fun _ -> Lwt.return_unit) in
            Lwt.fail exn2))
  end

(* ============================================================================
   BIP-324 v2 inbound (responder mode)
   ----------------------------------------------------------------------------
   Mirrors clearbit's responder path (clearbit/src/peer.zig:899-924).  The
   inbound listener has just accepted a TCP connection; before driving the
   v1 application handshake we peek 16 bytes from the kernel buffer with
   MSG_PEEK and classify:

     - If the bytes match the v1 VERSION header prefix (network magic +
       "version\0\0\0\0\0"), proceed straight to [perform_inbound_handshake]
       (the legacy v1 path).  The peeked bytes remain in the kernel buffer,
       so [Lwt_io.read_into_exactly] in [read_message_v1] picks them up.

     - Otherwise (peer sent a 64-byte ElligatorSwift pubkey), attach a
       responder V2Transport, drive the BIP-324 cipher handshake via
       [perform_v2_handshake], then run the application version/verack on
       top of the encrypted channel.  [send_message] / [read_message]
       dispatch on [peer.transport] so once the cipher handshake completes
       the application messages flow through encrypted dispatch automatically.

   Gated by [bip324_v2_inbound_enabled] (default OFF).  When OFF behaviour
   is identical to calling [perform_inbound_handshake] directly.
   ============================================================================ *)

(* Peek up to [v1_prefix_len] bytes from the underlying TCP socket without
   consuming them from the kernel buffer.  Bounded by [deadline_sec].  Returns
   the number of bytes actually peeked (0 to v1_prefix_len).  May return less
   than v1_prefix_len if the deadline expires with partial data; the caller
   must treat that as inconclusive (we err on the side of "not v1" → v2).

   Lwt_unix.recv with [MSG_PEEK] leaves the bytes in the kernel buffer so a
   subsequent Lwt_io.read_into on peer.ic still sees the full stream.  This
   relies on Lwt_io.of_fd not having pre-pulled any bytes from the kernel,
   which is true at the start of [accept_inbound] (peer.ic has not been read
   from yet). *)
let peek_inbound_prefix (peer : peer) (deadline_sec : float)
    : int Lwt.t =
  let open Lwt.Syntax in
  let buf = Bytes.create v1_prefix_len in
  let start = Unix.gettimeofday () in
  let rec loop total =
    if total >= v1_prefix_len then Lwt.return total
    else
      let elapsed = Unix.gettimeofday () -. start in
      if elapsed >= deadline_sec then Lwt.return total
      else begin
        let remaining = deadline_sec -. elapsed in
        let recv_task =
          let* n = Lwt_unix.recv peer.fd buf total
            (v1_prefix_len - total) [Unix.MSG_PEEK] in
          Lwt.return (`Got n)
        in
        let timeout_task =
          let* () = Lwt_unix.sleep remaining in
          Lwt.return `Timeout
        in
        let* res = Lwt.pick [recv_task; timeout_task] in
        match res with
        | `Timeout -> Lwt.return total
        | `Got 0 -> Lwt.return total  (* EOF — caller will see it on next read *)
        | `Got n ->
          (* recv with MSG_PEEK returns the cumulative bytes available;
             advance our notion of total but stop if it didn't grow
             (kernel has no more data right now). *)
          if n <= total then Lwt.return total
          else loop n
      end
  in
  loop 0

(* Drive the inbound handshake with optional BIP-324 v2 negotiation.  When
   [bip324_v2_inbound_enabled] is OFF this just delegates to
   [perform_inbound_handshake] (legacy v1 path).  When ON it peeks 16 bytes
   from the socket, classifies, and on v2 detection installs a responder
   V2Transport + drives the cipher handshake before the app version/verack. *)
let perform_inbound_handshake_negotiated (peer : peer)
    (our_height : int32) : unit Lwt.t =
  let open Lwt.Syntax in
  if not (bip324_v2_inbound_enabled ()) then
    perform_inbound_handshake peer our_height
  else begin
    (* Phase 1: peek + classify.  Use a short deadline (5s) — a healthy peer
       sends 16+ bytes in the first TCP segment; silence past that means a
       slow/malformed peer and we'd rather fall back to v1 (which has its
       own timeouts) than wedge here. *)
    let* got = peek_inbound_prefix peer 5.0 in
    let peek_buf = Bytes.create v1_prefix_len in
    (* Re-peek into peek_buf so we have the bytes in hand for classification.
       This double-peek is intentional — peek_inbound_prefix returns only
       the count; we need the bytes themselves to inspect the command field.
       MSG_PEEK leaves them in the kernel either way. *)
    let* () =
      if got < v1_prefix_len then Lwt.return_unit
      else
        let* _ = Lwt_unix.recv peer.fd peek_buf 0 v1_prefix_len
          [Unix.MSG_PEEK] in
        Lwt.return_unit
    in
    let is_v1 =
      got >= v1_prefix_len &&
      looks_like_v1_version peek_buf peer.network.magic
    in
    if is_v1 || got < v1_prefix_len then begin
      (* v1 path: bytes remain in kernel (MSG_PEEK is non-destructive),
         Lwt_io.read_into_exactly in read_message_v1 will pick them up.
         We also take this branch on partial peek (got < 16) — the v1
         handshake's read_timeout will fire if the peer is truly silent;
         this preserves graceful degradation when the peek deadline fires
         before classification completes. *)
      perform_inbound_handshake peer our_height
    end
    else begin
      (* Phase 2: v2 responder.  Attach a responder V2Transport; its
         send_buffer starts empty (responders wait for the peer's pubkey
         before sending anything per BIP-324 § "Wire format").  The state
         machine starts in V2RecvKeyMaybeV1 and will advance to V2RecvKey
         on the first chunk because the peeked bytes don't match v1 magic. *)
      let transport = P2p.create_v2_transport ~initiating:false
        ~magic:peer.network.magic in
      let v2_state = match transport with
        | P2p.V2 s -> s
        | P2p.V1 _ -> assert false
      in
      peer.transport <- Some transport;
      Lwt.catch
        (fun () ->
          let* () = perform_v2_handshake peer v2_state in
          (* Cipher handshake complete — run the application version/verack
             over the encrypted v2 transport.  send_message / read_message
             dispatch on peer.transport so this Just Works. *)
          let* () = perform_inbound_handshake peer our_height in
          Log.info (fun m ->
            m "[%s:%d] BIP-324 v2 inbound connected (encrypted)"
              peer.addr peer.port);
          Lwt.return_unit)
        (fun exn ->
          (* Reset transport so the caller's clean-up path doesn't try to
             send a v2 disconnect packet over a half-built cipher. *)
          peer.transport <- None;
          Log.info (fun m ->
            m "[%s:%d] BIP-324 v2 inbound failed: %s"
              peer.addr peer.port (Printexc.to_string exn));
          Lwt.fail exn)
    end
  end

(* Send a ping message and record the nonce (BIP-31) *)
let send_ping (peer : peer) : unit Lwt.t =
  let nonce = random_nonce () in
  peer.ping_nonce <- Some nonce;
  peer.last_ping <- Unix.gettimeofday ();
  send_message peer (P2p.PingMsg nonce)

(* Handle received pong message *)
let handle_pong (peer : peer) (nonce : int64) : unit =
  match peer.ping_nonce with
  | Some expected when expected = nonce ->
    peer.latency <- Unix.gettimeofday () -. peer.last_ping;
    peer.ping_nonce <- None
  | _ ->
    (* Unexpected pong nonce, ignore *)
    ()

(* Check if peer needs a ping (for keepalive/latency measurement) *)
let needs_ping (peer : peer) : bool =
  peer.state = Ready &&
  peer.ping_nonce = None &&
  Unix.gettimeofday () -. peer.last_ping > ping_interval

(* Check if peer ping has timed out *)
let ping_timed_out (peer : peer) : bool =
  match peer.ping_nonce with
  | Some _ ->
    Unix.gettimeofday () -. peer.last_ping > ping_timeout
  | None -> false

(* Record misbehavior for a peer.  Returns `Ban if the accumulated score
   reaches the threshold (>= 100), otherwise `Ok. *)
let record_misbehavior (peer : peer) (score : int)
    : [`Ok | `Ban] =
  peer.misbehavior_score <- peer.misbehavior_score + score;
  if peer.misbehavior_score >= 100 then `Ban else `Ok

(* Misbehavior scoring categories (Gap 14) *)
let misbehavior_invalid_block = 100
let misbehavior_invalid_header = 20
let misbehavior_oversized_message = 20
let misbehavior_bad_tx = 10
let misbehavior_spam = 5
let misbehavior_headers_dont_connect = 20
let misbehavior_block_download_stall = 50
let misbehavior_unrequested_data = 5

let record_misbehavior_for (peer : peer) (infraction : string) : [`Ok | `Ban] =
  let score = match infraction with
    | "invalid_block" -> misbehavior_invalid_block
    | "invalid_header" -> misbehavior_invalid_header
    | "oversized_message" -> misbehavior_oversized_message
    | "bad_tx" -> misbehavior_bad_tx
    | "spam" -> misbehavior_spam
    | "headers_dont_connect" -> misbehavior_headers_dont_connect
    | "block_download_stall" -> misbehavior_block_download_stall
    | "unrequested_data" -> misbehavior_unrequested_data
    | _ -> 1
  in
  record_misbehavior peer score

(* Misbehaving: record misbehavior, log it, and disconnect if score reaches threshold.
   This is the async version that handles disconnection. The ban itself should be
   handled by peer_manager which has access to the ban table. *)
let misbehaving (peer : peer) (score : int) (message : string) : unit Lwt.t =
  let open Lwt.Syntax in
  peer.misbehavior_score <- peer.misbehavior_score + score;
  let message_prefixed = if message = "" then "" else ": " ^ message in
  Log.info (fun m -> m "Misbehaving: peer=%d score=%d total=%d%s"
    peer.id score peer.misbehavior_score message_prefixed);
  if peer.misbehavior_score >= 100 then begin
    Log.info (fun m -> m "Disconnecting misbehaving peer %d (%s) total_score=%d"
      peer.id peer.addr peer.misbehavior_score);
    let* () = disconnect peer in
    Lwt.return_unit
  end else
    Lwt.return_unit

(* Message rate limiting (Gap 15) *)
let check_rate_limit (peer : peer) : bool =
  let now = Unix.gettimeofday () in
  if now -. peer.msg_window_start > 60.0 then begin
    peer.msg_window_start <- now;
    peer.msg_count_window <- 1;
    true
  end else begin
    peer.msg_count_window <- peer.msg_count_window + 1;
    peer.msg_count_window <= 500
  end

(* Getdata handler (Gap 11) — process inventory requests from peers.
   lookup_block and lookup_tx return serialized data as Cstruct.t option;
   the caller (higher-level code) owns storage/mempool access. *)
let handle_getdata (peer : peer) (items : P2p.inv_vector list)
    ~(lookup_block : Types.hash256 -> Cstruct.t option)
    ~(lookup_tx : Types.hash256 -> Cstruct.t option)
    : unit Lwt.t =
  let open Lwt.Syntax in
  let max_getdata_items = 1000 in
  if List.length items > max_getdata_items then begin
    let _result = record_misbehavior_for peer "spam" in
    Lwt.return_unit
  end else
    let not_found = ref [] in
    let* () = Lwt_list.iter_s (fun (iv : P2p.inv_vector) ->
      match iv.inv_type with
      | P2p.InvBlock | P2p.InvWitnessBlock ->
        begin match lookup_block iv.hash with
        | Some data ->
          let r = Serialize.reader_of_cstruct data in
          let block = Serialize.deserialize_block r in
          send_message peer (P2p.BlockMsg block)
        | None ->
          not_found := iv :: !not_found;
          Lwt.return_unit
        end
      | P2p.InvTx | P2p.InvWitnessTx ->
        begin match lookup_tx iv.hash with
        | Some data ->
          let r = Serialize.reader_of_cstruct data in
          let tx = Serialize.deserialize_transaction r in
          send_message peer (P2p.TxMsg tx)
        | None ->
          not_found := iv :: !not_found;
          Lwt.return_unit
        end
      | _ ->
        not_found := iv :: !not_found;
        Lwt.return_unit
    ) items in
    (* Send notfound for items we couldn't provide *)
    if !not_found <> [] then
      send_message peer (P2p.NotfoundMsg (List.rev !not_found))
    else
      Lwt.return_unit

(* Dispatch incoming message based on handshake state.
   Rejects pre-handshake messages per Bitcoin Core net_processing.cpp:
   - Before VERSION received: only VERSION is accepted
   - After VERSION but before VERACK: VERSION, VERACK, and feature negotiation
   - After handshake complete: all messages *)
let dispatch_message (peer : peer) (msg : P2p.message_payload)
    : [`Continue | `Disconnect of string | `PreHandshake of string] Lwt.t =
  let open Lwt.Syntax in
  match msg, peer.handshake_complete with
  (* Pre-handshake: VERSION message *)
  | P2p.VersionMsg v, false ->
    if peer.version_received then begin
      (* Duplicate VERSION: misbehaving (score 1 like Bitcoin Core) *)
      let* () = misbehaving peer 1 "duplicate VERSION message" in
      Lwt.return (`PreHandshake "Duplicate VERSION message")
    end else begin
      (* First VERSION - should be handled by handshake code, not message loop *)
      (* If we receive VERSION in the message loop, it means something went wrong *)
      let _ = peer.version_received <- true in
      let _ = peer.version_msg <- Some v in
      let _ = peer.services <- services_of_int64 v.services in
      let _ = peer.best_height <- v.start_height in
      peer.relay <- v.relay;
      peer.time_offset <- Int64.sub v.timestamp (Int64.of_float (Unix.gettimeofday ()));
      Lwt.return `Continue
    end

  (* Pre-handshake: VERACK message *)
  | P2p.VerackMsg, false ->
    if not peer.version_received then begin
      (* VERACK before VERSION - misbehaving *)
      let* () = misbehaving peer 10 "VERACK before VERSION" in
      Lwt.return (`PreHandshake "VERACK received before VERSION")
    end else begin
      (* VERACK after VERSION - handshake progressing *)
      peer.handshake_complete <- true;
      Lwt.return `Continue
    end

  (* Pre-handshake: Feature negotiation messages (allowed between VERSION and VERACK) *)
  | P2p.WtxidrelayMsg, false ->
    if not peer.version_received then begin
      let* () = misbehaving peer 10 "pre-handshake wtxidrelay" in
      Lwt.return (`PreHandshake "wtxidrelay before VERSION")
    end else begin
      peer.wtxid_relay <- true;
      Lwt.return `Continue
    end

  | P2p.SendaddrV2Msg, false ->
    if not peer.version_received then begin
      let* () = misbehaving peer 10 "pre-handshake sendaddrv2" in
      Lwt.return (`PreHandshake "sendaddrv2 before VERSION")
    end else begin
      peer.sendaddrv2 <- true;
      Lwt.return `Continue
    end

  | P2p.SendcmpctMsg { announce; version }, false ->
    if not peer.version_received then begin
      let* () = misbehaving peer 10 "pre-handshake sendcmpct" in
      Lwt.return (`PreHandshake "sendcmpct before VERSION")
    end else begin
      peer.cmpct_high_bandwidth <- announce;
      peer.cmpct_version <- version;
      Lwt.return `Continue
    end

  | P2p.FeefilterMsg feerate, false ->
    if not peer.version_received then begin
      let* () = misbehaving peer 10 "pre-handshake feefilter" in
      Lwt.return (`PreHandshake "feefilter before VERSION")
    end else begin
      peer.feefilter <- feerate;
      Lwt.return `Continue
    end

  (* BIP-331 sendpackages: announced between VERSION and VERACK.  Capture the
     peer's package-relay limits so the listener-level handler can clamp our
     own [getpkgtxns] requests. *)
  | P2p.SendpackagesMsg msg, false ->
    if not peer.version_received then begin
      let* () = misbehaving peer 10 "pre-handshake sendpackages" in
      Lwt.return (`PreHandshake "sendpackages before VERSION")
    end else begin
      peer.sendpackages_received <- true;
      peer.pkg_relay_version <- msg.pkg_version;
      peer.pkg_max_count <- msg.pkg_max_count;
      peer.pkg_max_weight <- msg.pkg_max_weight;
      Lwt.return `Continue
    end

  (* Pre-handshake: Any other message - reject *)
  | _, false ->
    let* () = misbehaving peer 10 "pre-handshake message" in
    Lwt.return (`PreHandshake "Message received before handshake complete")

  (* Post-handshake: Normal message handling *)
  | P2p.PingMsg nonce, true ->
    let* () = send_message peer (P2p.PongMsg nonce) in
    Lwt.return `Continue

  | P2p.PongMsg nonce, true ->
    handle_pong peer nonce;
    Lwt.return `Continue

  | P2p.SendheadersMsg, true ->
    peer.send_headers <- true;
    Lwt.return `Continue

  | P2p.WtxidrelayMsg, true ->
    (* wtxidrelay after verack is a protocol violation (BIP-339) *)
    let* () = misbehaving peer 1 "wtxidrelay after handshake" in
    Lwt.return (`Disconnect "wtxidrelay received after VERACK")

  | P2p.SendaddrV2Msg, true ->
    (* sendaddrv2 after verack is a protocol violation (BIP-155) *)
    let* () = misbehaving peer 1 "sendaddrv2 after handshake" in
    Lwt.return (`Disconnect "sendaddrv2 received after VERACK")

  | P2p.VerackMsg, true ->
    (* Ignore duplicate verack *)
    Lwt.return `Continue

  | P2p.SendcmpctMsg { announce; version }, true ->
    peer.cmpct_high_bandwidth <- announce;
    peer.cmpct_version <- version;
    Lwt.return `Continue

  | P2p.FeefilterMsg feerate, true ->
    peer.feefilter <- feerate;
    Lwt.return `Continue

  | P2p.VersionMsg _, true ->
    (* Version message after handshake is a protocol violation *)
    let* () = misbehaving peer 1 "VERSION after handshake" in
    Lwt.return (`Disconnect "Unexpected VERSION message after handshake")

  | P2p.SendpackagesMsg _, true ->
    (* BIP-331: sendpackages MUST be sent between VERSION and VERACK; later
       arrival is a protocol violation. *)
    let* () = misbehaving peer 1 "sendpackages after handshake" in
    Lwt.return (`Disconnect "sendpackages received after VERACK")

  | _, true ->
    (* Other messages handled by higher-level code *)
    Lwt.return `Continue

(* Handle incoming message from peer (legacy wrapper for backward compatibility) *)
let handle_message (peer : peer) (msg : P2p.message_payload)
    : [`Continue | `Disconnect of string] Lwt.t =
  let open Lwt.Syntax in
  let* result = dispatch_message peer msg in
  match result with
  | `Continue -> Lwt.return `Continue
  | `Disconnect reason -> Lwt.return (`Disconnect reason)
  | `PreHandshake reason ->
    (* Pre-handshake rejections are treated as continue (message is dropped) *)
    Log.debug (fun m -> m "Dropped pre-handshake message from peer %d: %s"
      peer.id reason);
    Lwt.return `Continue

(* Peer statistics for logging/monitoring *)
type peer_stats = {
  stat_id : int;
  stat_addr : string;
  stat_port : int;
  stat_state : string;
  stat_services : int64;
  stat_best_height : int32;
  stat_latency_ms : float;
  stat_bytes_sent : int;
  stat_bytes_received : int;
  stat_msgs_sent : int;
  stat_msgs_received : int;
  stat_last_seen : float;
  stat_user_agent : string;
  stat_direction : peer_direction;
  stat_misbehavior : int;
  stat_relay : bool;
  stat_protocol_version : int32;
  stat_time_offset : int64;
}

let get_stats (peer : peer) : peer_stats =
  { stat_id = peer.id;
    stat_addr = peer.addr;
    stat_port = peer.port;
    stat_state = peer_state_to_string peer.state;
    stat_services = services_to_int64 peer.services;
    stat_best_height = peer.best_height;
    stat_latency_ms = peer.latency *. 1000.0;
    stat_bytes_sent = peer.bytes_sent;
    stat_bytes_received = peer.bytes_received;
    stat_msgs_sent = peer.msgs_sent;
    stat_msgs_received = peer.msgs_received;
    stat_last_seen = peer.last_seen;
    stat_user_agent = (match peer.version_msg with
      | Some v -> v.user_agent
      | None -> "");
    stat_direction = peer.direction;
    stat_misbehavior = peer.misbehavior_score;
    stat_relay = peer.relay;
    stat_protocol_version = (match peer.version_msg with
      | Some v -> v.protocol_version
      | None -> 0l);
    stat_time_offset = peer.time_offset;
  }

(* Pretty print peer info *)
let peer_info (peer : peer) : string =
  let ua = match peer.version_msg with
    | Some v -> v.user_agent
    | None -> "unknown" in
  let dir = match peer.direction with
    | Inbound -> "in"
    | Outbound -> "out" in
  Printf.sprintf "Peer %d [%s:%d] state=%s height=%ld ua=%s dir=%s misb=%d"
    peer.id peer.addr peer.port
    (peer_state_to_string peer.state)
    peer.best_height
    ua dir peer.misbehavior_score

(* Check if a transaction should be relayed to this peer based on its feefilter.
   Returns true if the tx fee rate is at or above the peer's feefilter threshold.
   Transactions without a fee rate (blocks, errors) always pass. *)
let passes_feefilter (peer : peer) (entry : inv_entry) : bool =
  match entry.fee_rate with
  | None -> true  (* Non-transactions (blocks) always pass *)
  | Some tx_fee_rate ->
    (* Compare tx fee rate against peer's feefilter (both in sat/kvB) *)
    tx_fee_rate >= peer.feefilter

(* Inventory trickling: queue an inventory item for delayed announcement.
   Respects the peer's relay preference: when relay=false, tx inv messages
   are suppressed (the peer opted out of transaction relay).
   Also filters transactions below the peer's feefilter threshold. *)
let queue_inv (peer : peer) (entry : inv_entry) : unit =
  if peer.state = Ready then begin
    let is_tx = match entry.inv_type with
      | P2p.InvTx | P2p.InvWitnessTx -> true
      | _ -> false
    in
    (* Skip if peer opted out of tx relay or if tx is below feefilter *)
    if is_tx && (not peer.relay || peer.block_relay_only) then
      ()
    else if is_tx && not (passes_feefilter peer entry) then
      ()  (* Transaction fee rate below peer's feefilter threshold *)
    else
      Queue.add entry peer.inv_queue
  end

(* Create an inv entry for a block (no fee rate) *)
let make_block_inv (hash : Types.hash256) : inv_entry =
  { inv_type = P2p.InvBlock; hash; fee_rate = None }

(* Create an inv entry for a transaction with its fee rate in sat/kvB *)
let make_tx_inv ~(witness : bool) (hash : Types.hash256) (fee_rate_satkvb : int64) : inv_entry =
  let inv_type = if witness then P2p.InvWitnessTx else P2p.InvTx in
  { inv_type; hash; fee_rate = Some fee_rate_satkvb }

(* Inventory trickling: check how many items are queued *)
let inv_queue_length (peer : peer) : int =
  Queue.length peer.inv_queue

(* Inventory trickling: flush the queue, sending up to max_inv_per_flush items.
   Randomizes the order of announcements for privacy.
   Returns the number of items sent. *)
let flush_inv_queue (peer : peer) : int Lwt.t =
  let open Lwt.Syntax in
  if peer.state <> Ready || Queue.is_empty peer.inv_queue then
    Lwt.return 0
  else begin
    (* Collect up to max_inv_per_flush items *)
    let items = ref [] in
    let count = ref 0 in
    while not (Queue.is_empty peer.inv_queue) && !count < max_inv_per_flush do
      let entry = Queue.pop peer.inv_queue in
      items := entry :: !items;
      incr count
    done;
    if !count = 0 then
      Lwt.return 0
    else begin
      (* Randomize order for privacy using Fisher-Yates shuffle *)
      let arr = Array.of_list !items in
      let n = Array.length arr in
      for i = n - 1 downto 1 do
        let j = Random.int (i + 1) in
        let tmp = arr.(i) in
        arr.(i) <- arr.(j);
        arr.(j) <- tmp
      done;
      let shuffled = Array.to_list arr in
      (* Convert to P2p.inv_vector list *)
      let inv_vectors = List.map (fun entry ->
        { P2p.inv_type = entry.inv_type; hash = entry.hash }
      ) shuffled in
      (* Send the inv message *)
      let* () = Lwt.catch
        (fun () -> send_message peer (P2p.InvMsg inv_vectors))
        (fun _exn -> Lwt.return_unit)
      in
      Lwt.return !count
    end
  end

(* Inventory trickling: schedule the next flush time based on Poisson delay *)
let schedule_next_inv_send (peer : peer) : unit =
  let avg_interval = match peer.direction with
    | Inbound -> inbound_inv_broadcast_interval
    | Outbound -> outbound_inv_broadcast_interval
  in
  peer.next_inv_send <- Unix.gettimeofday () +. poisson_delay avg_interval

(* Inventory trickling: check if it's time to flush *)
let should_flush_inv (peer : peer) : bool =
  peer.state = Ready &&
  not (Queue.is_empty peer.inv_queue) &&
  Unix.gettimeofday () >= peer.next_inv_send

(* Inventory trickling: start the trickle timer loop for a peer.
   This should be called once when the peer enters Ready state.
   The loop runs until the peer disconnects. *)
let start_trickling (peer : peer) : unit Lwt.t =
  let open Lwt.Syntax in
  if peer.trickling_active then
    Lwt.return_unit
  else begin
    peer.trickling_active <- true;
    let rec loop () =
      if peer.state = Disconnected || peer.state = Disconnecting then begin
        peer.trickling_active <- false;
        Lwt.return_unit
      end else begin
        let now = Unix.gettimeofday () in
        let delay = max 0.1 (peer.next_inv_send -. now) in
        let* () = Lwt_unix.sleep delay in
        if peer.state = Ready then begin
          let* _sent = flush_inv_queue peer in
          schedule_next_inv_send peer;
          loop ()
        end else begin
          peer.trickling_active <- false;
          Lwt.return_unit
        end
      end
    in
    loop ()
  end

(* ============================================================================
   BIP-133 FeeFilter
   ============================================================================ *)

(* Fee filter rounder: discretizes fee rates to prevent fingerprinting.
   Uses buckets spaced 1.1x apart with randomized rounding.
   Based on Bitcoin Core's FeeFilterRounder in policy/fees/block_policy_estimator.cpp *)
module FeeFilterRounder = struct
  let max_filter_feerate = 10_000_000L  (* 10 BTC/kvB in sat/kvB *)
  let fee_filter_spacing = 1.1

  (* Generate fee buckets: powers of 1.1 starting from min_relay_fee/2 *)
  let make_fee_set (min_relay_fee : int64) : float array =
    let min_limit = max 1L (Int64.div min_relay_fee 2L) in
    let buckets = ref [0.0] in
    let boundary = ref (Int64.to_float min_limit) in
    while !boundary <= Int64.to_float max_filter_feerate do
      buckets := !boundary :: !buckets;
      boundary := !boundary *. fee_filter_spacing
    done;
    Array.of_list (List.rev !buckets)

  (* Round a fee rate to a bucket with randomization.
     66.67% chance to round down, 33.33% to round up.
     This prevents exact mempool state leakage. *)
  let round (fee_set : float array) (current_fee : int64) : int64 =
    let fee_f = Int64.to_float current_fee in
    (* Binary search for lower_bound *)
    let n = Array.length fee_set in
    let rec find_idx lo hi =
      if lo >= hi then lo
      else
        let mid = (lo + hi) / 2 in
        if fee_set.(mid) < fee_f then find_idx (mid + 1) hi
        else find_idx lo mid
    in
    let idx = find_idx 0 n in
    (* Possibly move to lower bucket (2/3 probability) *)
    let final_idx =
      if idx >= n then n - 1
      else if idx > 0 && Random.int 3 <> 0 then idx - 1
      else idx
    in
    Int64.of_float fee_set.(final_idx)
end

(* Default fee set based on 1000 sat/kvB minimum relay fee *)
let default_fee_set = FeeFilterRounder.make_fee_set 1000L

(* Check if we should send a feefilter to this peer now.
   Returns true if it's time to send based on Poisson schedule. *)
let should_send_feefilter (peer : peer) : bool =
  peer.state = Ready &&
  not peer.block_relay_only &&
  peer.handshake_complete &&
  (match peer.version_msg with
   | Some v -> v.protocol_version >= feefilter_version
   | None -> false) &&
  Unix.gettimeofday () >= peer.next_send_feefilter

(* Check if a significant fee change warrants accelerated sending.
   Returns true if current fee is <75% or >133% of last sent value. *)
let significant_feefilter_change (current_fee : int64) (sent_fee : int64) : bool =
  if sent_fee = 0L then true
  else
    let current = Int64.to_float current_fee in
    let sent = Int64.to_float sent_fee in
    current < sent *. 0.75 || current > sent *. 1.33

(* Schedule the next feefilter send time using Poisson delay *)
let schedule_next_feefilter (peer : peer) : unit =
  peer.next_send_feefilter <- Unix.gettimeofday () +. poisson_delay avg_feefilter_broadcast_interval

(* Reschedule feefilter for sooner sending due to significant change *)
let reschedule_feefilter_soon (peer : peer) : unit =
  let now = Unix.gettimeofday () in
  let soon = now +. Random.float max_feefilter_change_delay in
  if soon < peer.next_send_feefilter then
    peer.next_send_feefilter <- soon

(* Send a feefilter message to the peer with the rounded fee rate.
   Updates tracking state for next send. *)
let send_feefilter (peer : peer) (min_fee : int64) : unit Lwt.t =
  let open Lwt.Syntax in
  if peer.state <> Ready || peer.block_relay_only then
    Lwt.return_unit
  else begin
    let rounded_fee = FeeFilterRounder.round default_fee_set min_fee in
    let* () = Lwt.catch
      (fun () -> send_message peer (P2p.FeefilterMsg rounded_fee))
      (fun _exn -> Lwt.return_unit)
    in
    peer.fee_filter_sent <- rounded_fee;
    schedule_next_feefilter peer;
    Lwt.return_unit
  end

(* Maybe send a feefilter message if conditions are met.
   Called periodically from the peer management loop.
   Returns true if a message was sent. *)
let maybe_send_feefilter (peer : peer) (min_fee : int64) : bool Lwt.t =
  let open Lwt.Syntax in
  if not (should_send_feefilter peer) then
    Lwt.return false
  else begin
    let rounded = FeeFilterRounder.round default_fee_set min_fee in
    (* Only send if the value changed *)
    if rounded = peer.fee_filter_sent then begin
      schedule_next_feefilter peer;
      Lwt.return false
    end else begin
      let* () = send_feefilter peer min_fee in
      Lwt.return true
    end
  end

(* Check and potentially accelerate feefilter sending due to significant change *)
let check_feefilter_change (peer : peer) (current_fee : int64) : unit =
  if peer.state = Ready && not peer.block_relay_only then
    let rounded = FeeFilterRounder.round default_fee_set current_fee in
    if significant_feefilter_change rounded peer.fee_filter_sent then
      reschedule_feefilter_soon peer

(* SOCKS5 proxy connection for Tor/I2P support.
   Implements the SOCKS5 handshake (RFC 1928) over an existing TCP socket. *)
let socks5_connect (fd : Lwt_unix.file_descr) ~(target_host : string) ~(target_port : int) : unit Lwt.t =
  let open Lwt.Syntax in
  let ic = Lwt_io.of_fd ~mode:Lwt_io.input fd in
  let oc = Lwt_io.of_fd ~mode:Lwt_io.output fd in
  (* Step 1: Send greeting - version 5, 1 method (no auth) *)
  let* () = Lwt_io.write_from_exactly oc (Bytes.of_string "\x05\x01\x00") 0 3 in
  let* () = Lwt_io.flush oc in
  (* Step 2: Read server's method selection *)
  let resp = Bytes.create 2 in
  let* () = Lwt_io.read_into_exactly ic resp 0 2 in
  if Bytes.get_uint8 resp 0 <> 5 || Bytes.get_uint8 resp 1 <> 0 then
    Lwt.fail_with "SOCKS5: server rejected no-auth method"
  else begin
    (* Step 3: Send connect request - ATYP=3 (domain name) *)
    let host_len = String.length target_host in
    let req_len = 4 + 1 + host_len + 2 in
    let req = Bytes.create req_len in
    Bytes.set_uint8 req 0 5;      (* version *)
    Bytes.set_uint8 req 1 1;      (* CMD: connect *)
    Bytes.set_uint8 req 2 0;      (* reserved *)
    Bytes.set_uint8 req 3 3;      (* ATYP: domain name *)
    Bytes.set_uint8 req 4 host_len;
    Bytes.blit_string target_host 0 req 5 host_len;
    Bytes.set_uint8 req (5 + host_len) (target_port lsr 8);
    Bytes.set_uint8 req (6 + host_len) (target_port land 0xFF);
    let* () = Lwt_io.write_from_exactly oc req 0 req_len in
    let* () = Lwt_io.flush oc in
    (* Step 4: Read connect response *)
    let resp_hdr = Bytes.create 4 in
    let* () = Lwt_io.read_into_exactly ic resp_hdr 0 4 in
    if Bytes.get_uint8 resp_hdr 1 <> 0 then
      Lwt.fail_with (Printf.sprintf "SOCKS5: connect failed with code %d"
        (Bytes.get_uint8 resp_hdr 1))
    else begin
      (* Skip the bound address based on ATYP *)
      let atyp = Bytes.get_uint8 resp_hdr 3 in
      let skip_len = match atyp with
        | 1 -> 4 + 2  (* IPv4 + port *)
        | 4 -> 16 + 2 (* IPv6 + port *)
        | 3 ->         (* Domain - 1 byte len + domain + port *)
          let len_buf = Bytes.create 1 in
          ignore (Lwt_io.read_into_exactly ic len_buf 0 1);
          Bytes.get_uint8 len_buf 0 + 2
        | _ -> 0
      in
      let skip_buf = Bytes.create skip_len in
      let* () = Lwt_io.read_into_exactly ic skip_buf 0 skip_len in
      Lwt.return_unit
    end
  end
