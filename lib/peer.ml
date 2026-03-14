(* Bitcoin P2P peer connection and handshake management using Lwt *)

let log_src = Logs.Src.create "PEER" ~doc:"Peer connection"
module Log = (val Logs.src_log log_src : Logs.LOG)

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

(* Our node's advertised services: full node with witness support *)
let our_services : peer_services = {
  network = true;
  getutxo = false;
  bloom = false;
  witness = true;
  compact_filters = false;
  network_limited = false;
}

(* Connection and read timeouts *)
let connection_timeout = 10.0  (* seconds *)
let read_timeout = 30.0        (* seconds *)
let ping_interval = 120.0      (* 2 minutes between pings *)
let ping_timeout = 20.0        (* 20 seconds to receive pong *)

(* Direction of a peer connection *)
type peer_direction = Inbound | Outbound

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
  mutable feefilter : int64;     (* Minimum fee rate (sat/kB) advertised by peer *)
  mutable msg_count_window : int;   (* Messages received in current window *)
  mutable msg_window_start : float; (* Start time of current rate-limit window *)
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
  { services = services_to_int64 our_services; addr; port = 0 }

(* Create a peer from an already-connected fd (used for both outbound and inbound) *)
let make_peer ~(network : Consensus.network_config) ~(addr : string)
    ~(port : int) ~(id : int) ~(direction : peer_direction)
    ~(fd : Lwt_unix.file_descr) : peer =
  let ic = Lwt_io.of_fd ~mode:Lwt_io.Input fd in
  let oc = Lwt_io.of_fd ~mode:Lwt_io.Output fd in
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
    msg_count_window = 0;
    msg_window_start = Unix.gettimeofday ();
  }

(* Establish TCP connection to a peer with timeout *)
let connect ~(network : Consensus.network_config) ~(addr : string)
    ~(port : int) ~(id : int) : peer Lwt.t =
  let open Lwt.Syntax in
  let* addresses = Lwt_unix.getaddrinfo addr
    (string_of_int port)
    [Unix.AI_SOCKTYPE Unix.SOCK_STREAM; Unix.AI_FAMILY Unix.PF_INET] in
  match addresses with
  | [] -> Lwt.fail_with ("Cannot resolve: " ^ addr)
  | ai :: _ ->
    let fd = Lwt_unix.socket ai.ai_family
      ai.ai_socktype ai.ai_protocol in
    (* Set connection timeout *)
    let timeout =
      let* () = Lwt_unix.sleep connection_timeout in
      Lwt.fail_with "Connection timeout" in
    let do_connect = Lwt_unix.connect fd ai.ai_addr in
    let* () = Lwt.pick [do_connect; timeout] in
    Lwt.return (make_peer ~network ~addr ~port ~id ~direction:Outbound ~fd)

(* Read a message from the peer with protection against stream desync.
   Uses Lwt.no_cancel to ensure TCP reads complete atomically. *)
let read_message (peer : peer) : P2p.message_payload Lwt.t =
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
    if magic <> peer.network.magic then
      Lwt.fail_with (Printf.sprintf "Bad network magic: expected 0x%08lx, got 0x%08lx"
        peer.network.magic magic)
    else if length > P2p.max_message_size then
      Lwt.fail_with (Printf.sprintf "Message too large: %d bytes" length)
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
        Lwt.fail_with "Bad message checksum"
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

(* Read a message with timeout *)
let read_message_with_timeout (peer : peer) (timeout_sec : float)
    : P2p.message_payload option Lwt.t =
  let open Lwt.Syntax in
  let timeout =
    let* () = Lwt_unix.sleep timeout_sec in
    Lwt.return None in
  let read =
    let* msg = read_message peer in
    Lwt.return (Some msg) in
  Lwt.pick [read; timeout]

(* Send a message to the peer *)
let send_message (peer : peer)
    (payload : P2p.message_payload) : unit Lwt.t =
  let open Lwt.Syntax in
  let data = P2p.serialize_message peer.network.magic payload in
  let data_str = Cstruct.to_string data in
  let* () = Lwt_io.write_from_string_exactly peer.oc
    data_str 0 (String.length data_str) in
  let* () = Lwt_io.flush peer.oc in
  peer.bytes_sent <- peer.bytes_sent + Cstruct.length data;
  peer.msgs_sent <- peer.msgs_sent + 1;
  Lwt.return_unit

(* Helper: process a version message received from the remote peer *)
let process_version_msg (peer : peer) (v : Types.version_msg) (nonce : int64)
    : unit Lwt.t =
  peer.version_msg <- Some v;
  peer.services <- services_of_int64 v.services;
  peer.best_height <- v.start_height;
  if v.protocol_version < Consensus.min_peer_proto_version then
    Lwt.fail_with (Printf.sprintf
      "Peer protocol version too old: %ld (minimum: %ld)"
      v.protocol_version Consensus.min_peer_proto_version)
  else if v.nonce = nonce then
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

(* Build a version message for outgoing handshake *)
let make_version_msg (peer : peer) (our_height : int32) (nonce : int64)
    : Types.version_msg =
  { protocol_version = Types.protocol_version;
    services = services_to_int64 our_services;
    timestamp = Int64.of_float (Unix.gettimeofday ());
    addr_recv = {
      services = 0L;
      addr = Cstruct.create 16;
      port = peer.port;
    };
    addr_from = make_local_addr ();
    nonce;
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
   (wtxidrelay, sendaddrv2, sendcmpct, feefilter) that arrive before verack.
   Returns unit on success or fails on timeout / unexpected messages. *)
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
      | Some (P2p.SendcmpctMsg _) ->
        (* Accept sendcmpct during feature negotiation *)
        loop ()
      | Some (P2p.FeefilterMsg feerate) ->
        (* Accept feefilter during feature negotiation *)
        peer.feefilter <- feerate;
        loop ()
      | Some _ -> Lwt.fail_with "Unexpected message before verack"
    end
  in
  loop ()

(* Perform the version/verack handshake for OUTBOUND connections.
   Protocol sequence (BIP-339 / BIP-155 compliant):
   1. We send our version message
   2. Peer sends their version message
   3. Send feature negotiation (wtxidrelay, sendaddrv2) BEFORE verack
   4. Send verack
   5. Read messages until peer's verack (accepting feature negotiation msgs)
   6. Post-handshake: sendheaders *)
let perform_handshake (peer : peer)
    (our_height : int32) : unit Lwt.t =
  let open Lwt.Syntax in
  peer.state <- HandshakeInProgress;
  let nonce = random_nonce () in
  let version_msg = make_version_msg peer our_height nonce in
  (* Send our version *)
  let* () = send_message peer (P2p.VersionMsg version_msg) in
  (* Read their version with timeout *)
  let* their_msg_opt = read_message_with_timeout peer read_timeout in
  let* () = match their_msg_opt with
    | None -> Lwt.fail_with "Timeout waiting for version message"
    | Some (P2p.VersionMsg v) ->
      process_version_msg peer v nonce
    | Some _ -> Lwt.fail_with "Expected version message"
  in
  (* Send feature negotiation messages BEFORE verack (BIP-339, BIP-155) *)
  let* () = send_feature_negotiation peer in
  (* Send verack *)
  let* () = send_message peer P2p.VerackMsg in
  (* Read messages until their verack, accepting feature negotiation msgs *)
  let* () = read_until_verack peer in
  (* Post-handshake feature negotiation *)
  (* Request headers announcements instead of inv (BIP-130) *)
  let* () = send_message peer P2p.SendheadersMsg in
  peer.state <- Ready;
  Lwt.return_unit

(* Perform the version/verack handshake for INBOUND connections.
   For inbound, the remote peer sends version first, then we respond.
   Protocol sequence:
   1. Read their version message
   2. Send our version message
   3. Send feature negotiation (wtxidrelay, sendaddrv2) BEFORE verack
   4. Send verack
   5. Read messages until peer's verack (accepting feature negotiation msgs)
   6. Post-handshake: sendheaders *)
let perform_inbound_handshake (peer : peer)
    (our_height : int32) : unit Lwt.t =
  let open Lwt.Syntax in
  peer.state <- HandshakeInProgress;
  let nonce = random_nonce () in
  (* Read their version first (inbound peer initiates) *)
  let* their_msg_opt = read_message_with_timeout peer read_timeout in
  let* () = match their_msg_opt with
    | None -> Lwt.fail_with "Timeout waiting for version message"
    | Some (P2p.VersionMsg v) ->
      process_version_msg peer v nonce
    | Some _ -> Lwt.fail_with "Expected version message"
  in
  (* Send our version *)
  let version_msg = make_version_msg peer our_height nonce in
  let* () = send_message peer (P2p.VersionMsg version_msg) in
  (* Send feature negotiation messages BEFORE verack (BIP-339, BIP-155) *)
  let* () = send_feature_negotiation peer in
  (* Send verack *)
  let* () = send_message peer P2p.VerackMsg in
  (* Read messages until their verack, accepting feature negotiation msgs *)
  let* () = read_until_verack peer in
  (* Post-handshake feature negotiation *)
  let* () = send_message peer P2p.SendheadersMsg in
  peer.state <- Ready;
  Lwt.return_unit

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

let record_misbehavior_for (peer : peer) (infraction : string) : [`Ok | `Ban] =
  let score = match infraction with
    | "invalid_block" -> misbehavior_invalid_block
    | "invalid_header" -> misbehavior_invalid_header
    | "oversized_message" -> misbehavior_oversized_message
    | "bad_tx" -> misbehavior_bad_tx
    | "spam" -> misbehavior_spam
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

(* Handle incoming message from peer *)
let handle_message (peer : peer) (msg : P2p.message_payload)
    : [`Continue | `Disconnect of string] Lwt.t =
  let open Lwt.Syntax in
  match msg with
  | P2p.PingMsg nonce ->
    (* Respond to ping with pong *)
    let* () = send_message peer (P2p.PongMsg nonce) in
    Lwt.return `Continue
  | P2p.PongMsg nonce ->
    handle_pong peer nonce;
    Lwt.return `Continue
  | P2p.SendheadersMsg ->
    peer.send_headers <- true;
    Lwt.return `Continue
  | P2p.WtxidrelayMsg ->
    peer.wtxid_relay <- true;
    Lwt.return `Continue
  | P2p.SendaddrV2Msg ->
    peer.sendaddrv2 <- true;
    Lwt.return `Continue
  | P2p.VerackMsg ->
    (* Ignore duplicate verack *)
    Lwt.return `Continue
  | P2p.FeefilterMsg feerate ->
    peer.feefilter <- feerate;
    Lwt.return `Continue
  | P2p.VersionMsg _ ->
    (* Version message after handshake is a protocol violation *)
    Lwt.return (`Disconnect "Unexpected version message")
  | _ ->
    (* Other messages handled by higher-level code *)
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
