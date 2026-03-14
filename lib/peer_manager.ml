(* Peer discovery and connection pool management using Lwt *)

let log_src = Logs.Src.create "NET" ~doc:"P2P networking"
module Log = (val Logs.src_log log_src : Logs.LOG)

(* Source of peer address discovery *)
type addr_source =
  | Dns      (* From DNS seed resolution *)
  | Addr     (* From addr message from peer *)
  | Manual   (* Manually added by user *)

(* Information about a known peer address *)
type peer_info = {
  address : string;
  port : int;
  services : int64;
  last_connected : float;
  last_attempt : float;
  failures : int;
  banned_until : float;
  source : addr_source;
}

(* Peer manager configuration *)
type config = {
  max_outbound : int;    (* Max outbound connections, default 8 *)
  max_inbound : int;     (* Max inbound connections, default 117 *)
  retry_delay : float;   (* Seconds between retry attempts, default 60 *)
  max_failures : int;    (* Max failures before deprioritizing, default 5 *)
  ban_duration : float;  (* Default ban duration in seconds *)
  ping_interval : float; (* Seconds between pings *)
  dead_timeout : float;  (* Seconds before peer considered dead *)
  chain_sync_timeout : float; (* Seconds before evicting outbound peer behind our tip *)
}

let default_config : config = {
  max_outbound = 8;
  max_inbound = 117;
  retry_delay = 60.0;
  max_failures = 5;
  ban_duration = 86400.0;  (* 24 hours *)
  ping_interval = 120.0;   (* 2 minutes *)
  dead_timeout = 600.0;    (* 10 minutes *)
  chain_sync_timeout = 1200.0; (* 20 minutes *)
}

(* Hardcoded fallback peers for testnet4 (DNS seeds are unreliable) *)
let testnet_fallback_peers : (string * int) list = [
  ("seed.testnet.bitcoin.sprovoost.nl", 18333);
  ("testnet-seed.bitcoin.jonasschnelli.ch", 18333);
]

(* Hardcoded fallback peers for mainnet *)
let mainnet_fallback_peers : (string * int) list = [
  ("seed.bitcoin.sipa.be", 8333);
  ("dnsseed.bluematt.me", 8333);
  ("seed.bitcoin.jonasschnelli.ch", 8333);
]

(* Misbehavior handler callback: peer_id -> score -> reason -> unit Lwt.t
   Higher-level code (e.g. sync.ml) calls this to report misbehavior. *)
type misbehavior_handler = int -> int -> string -> unit Lwt.t

(* Peer manager state *)
type t = {
  network : Consensus.network_config;
  config : config;
  mutable peers : Peer.peer list;
  known_addrs : (string, peer_info) Hashtbl.t;
  mutable next_peer_id : int;
  mutable our_height : int32;
  mutable running : bool;
  mutable listeners : (P2p.message_payload -> Peer.peer -> unit Lwt.t) list;
  mutable listener_fd : Lwt_unix.file_descr option;  (* TCP listen socket *)
  mutable last_tip_update : float;           (* Timestamp of last chain tip update *)
  stale_tip_check_interval : float;          (* Default 1800.0 = 30 minutes *)
  addr_rate : (string, int * float) Hashtbl.t;  (* Per-peer addr rate limiting: (count, window_start) *)
  mutable listen_addr : string option;           (* Our own listening address, if known *)
  chain_sync_behind_since : (int, float) Hashtbl.t; (* peer_id -> timestamp when first noticed behind *)
  mutable db : Storage.ChainDB.t option;            (* Chain database for building locators *)
}

(* Create a new peer manager *)
let create ?(config = default_config) (network : Consensus.network_config) : t =
  { network;
    config;
    peers = [];
    known_addrs = Hashtbl.create 1000;
    next_peer_id = 0;
    our_height = 0l;
    running = false;
    listeners = [];
    listener_fd = None;
    last_tip_update = Unix.gettimeofday ();
    stale_tip_check_interval = 1800.0;
    addr_rate = Hashtbl.create 256;
    listen_addr = None;
    chain_sync_behind_since = Hashtbl.create 16;
    db = None;
  }

(* Update our known blockchain height *)
let set_height (pm : t) (height : int32) : unit =
  pm.our_height <- height

let set_db (pm : t) (db : Storage.ChainDB.t) : unit =
  pm.db <- Some db

(* Get current blockchain height *)
let get_height (pm : t) : int32 =
  pm.our_height

(* Notify that the chain tip has been updated *)
let notify_tip_updated (pm : t) : unit =
  pm.last_tip_update <- Unix.gettimeofday ()

(* Add a message listener *)
let add_listener (pm : t) (listener : P2p.message_payload -> Peer.peer -> unit Lwt.t) : unit =
  pm.listeners <- listener :: pm.listeners

(* Get all connected peers in Ready state *)
let get_ready_peers (pm : t) : Peer.peer list =
  List.filter (fun p -> p.Peer.state = Peer.Ready) pm.peers

(* Get peer count *)
let peer_count (pm : t) : int =
  List.length pm.peers

(* Get ready peer count *)
let ready_peer_count (pm : t) : int =
  List.length (get_ready_peers pm)

(* Count outbound peers *)
let outbound_peer_count (pm : t) : int =
  List.length (List.filter (fun p ->
    p.Peer.direction = Peer.Outbound) pm.peers)

(* Count inbound peers *)
let inbound_peer_count (pm : t) : int =
  List.length (List.filter (fun p ->
    p.Peer.direction = Peer.Inbound) pm.peers)

(* Extract /16 netgroup from an IPv4 address string *)
let netgroup_of addr =
  match String.split_on_char '.' addr with
  | a :: b :: _ -> a ^ "." ^ b
  | _ -> addr

(* Evict one low-quality inbound peer to make room for a new connection.
   Protects the best inbound peers from eviction:
   - Top 4 by lowest latency
   - Top 4 by highest bytes_sent (upload contribution)
   - Top 4 by highest bytes_received (download contribution)
   - 1 per unique /16 subnet (up to 4 netgroups)
   - Top 4 by longest connection time (lowest peer id = earliest connection)
   From the remaining unprotected peers, evicts the one with highest latency. *)
let evict_inbound_peer (pm : t) : unit Lwt.t =
  (* Get all inbound peers in Ready state *)
  let inbound_ready = List.filter (fun p ->
    p.Peer.direction = Peer.Inbound && p.Peer.state = Peer.Ready
  ) pm.peers in
  if List.length inbound_ready <= 8 then
    (* Not enough inbound peers to justify eviction *)
    Lwt.return_unit
  else begin
    (* Build a set of protected peer ids *)
    let protected = Hashtbl.create 16 in
    (* Protect top 4 by lowest latency *)
    let by_latency = List.sort (fun a b ->
      compare a.Peer.latency b.Peer.latency
    ) inbound_ready in
    List.iteri (fun i p ->
      if i < 4 then Hashtbl.replace protected p.Peer.id true
    ) by_latency;
    (* Protect top 4 by highest bytes_sent (upload contribution) *)
    let unprotected_for_sent = List.filter (fun p ->
      not (Hashtbl.mem protected p.Peer.id)
    ) inbound_ready in
    let by_bytes_sent = List.sort (fun a b ->
      compare b.Peer.bytes_sent a.Peer.bytes_sent
    ) unprotected_for_sent in
    List.iteri (fun i p ->
      if i < 4 then Hashtbl.replace protected p.Peer.id true
    ) by_bytes_sent;
    (* Protect top 4 by highest bytes_received (download contribution) *)
    let unprotected_for_recv = List.filter (fun p ->
      not (Hashtbl.mem protected p.Peer.id)
    ) inbound_ready in
    let by_bytes_received = List.sort (fun a b ->
      compare b.Peer.bytes_received a.Peer.bytes_received
    ) unprotected_for_recv in
    List.iteri (fun i p ->
      if i < 4 then Hashtbl.replace protected p.Peer.id true
    ) by_bytes_received;
    (* Netgroup diversity: protect 1 peer per unique /16 subnet (up to 4) *)
    let unprotected_for_netgroup = List.filter (fun p ->
      not (Hashtbl.mem protected p.Peer.id)
    ) inbound_ready in
    let seen_netgroups = Hashtbl.create 8 in
    let netgroup_protected = ref 0 in
    List.iter (fun p ->
      if !netgroup_protected < 4 then begin
        let ng = netgroup_of p.Peer.addr in
        if not (Hashtbl.mem seen_netgroups ng) then begin
          Hashtbl.replace seen_netgroups ng true;
          Hashtbl.replace protected p.Peer.id true;
          incr netgroup_protected
        end
      end
    ) unprotected_for_netgroup;
    (* Protect top 4 by longest connection time (lowest id = earliest) *)
    let by_age = List.sort (fun a b ->
      compare a.Peer.id b.Peer.id
    ) inbound_ready in
    List.iteri (fun i p ->
      if i < 4 then Hashtbl.replace protected p.Peer.id true
    ) by_age;
    (* Filter to unprotected peers *)
    let unprotected = List.filter (fun p ->
      not (Hashtbl.mem protected p.Peer.id)
    ) inbound_ready in
    match unprotected with
    | [] -> Lwt.return_unit
    | _ ->
      (* Select the unprotected peer with highest latency *)
      let by_worst_latency = List.sort (fun a b ->
        compare b.Peer.latency a.Peer.latency
      ) unprotected in
      let victim = List.hd by_worst_latency in
      Log.info (fun m -> m "Evicting inbound peer %d (%s) latency=%.3fs"
        victim.Peer.id victim.Peer.addr victim.Peer.latency);
      Peer.disconnect victim |> fun lwt ->
        let open Lwt.Syntax in
        let* () = lwt in
        pm.peers <- List.filter (fun p -> p.Peer.id <> victim.Peer.id) pm.peers;
        Lwt.return_unit
  end

(* Check if address is banned *)
let is_banned (pm : t) (addr : string) : bool =
  match Hashtbl.find_opt pm.known_addrs addr with
  | Some info -> info.banned_until > Unix.gettimeofday ()
  | None -> false

(* Resolve DNS seeds to peer addresses *)
let resolve_dns_seeds (network : Consensus.network_config) : peer_info list Lwt.t =
  let open Lwt.Syntax in
  let* results = Lwt_list.map_p (fun seed ->
    Lwt.catch (fun () ->
      let* addrs = Lwt_unix.getaddrinfo seed
        (string_of_int network.default_port)
        [Unix.AI_SOCKTYPE Unix.SOCK_STREAM; Unix.AI_FAMILY Unix.PF_INET] in
      Lwt.return (List.filter_map (fun ai ->
        match ai.Unix.ai_addr with
        | Unix.ADDR_INET (ip, _) ->
          let addr = Unix.string_of_inet_addr ip in
          Some { address = addr;
                 port = network.default_port;
                 services = 0L;
                 last_connected = 0.0;
                 last_attempt = 0.0;
                 failures = 0;
                 banned_until = 0.0;
                 source = Dns }
        | _ -> None
      ) addrs)
    ) (fun _exn ->
      (* DNS resolution failed, return empty list *)
      Lwt.return []
    )
  ) network.dns_seeds in
  Lwt.return (List.concat results)

(* Get fallback peers for network *)
let get_fallback_peers (network : Consensus.network_config) : peer_info list =
  let peers = match network.name with
    | "mainnet" -> mainnet_fallback_peers
    | "testnet3" | "testnet4" -> testnet_fallback_peers
    | _ -> []
  in
  List.map (fun (addr, port) ->
    { address = addr;
      port;
      services = 0L;
      last_connected = 0.0;
      last_attempt = 0.0;
      failures = 0;
      banned_until = 0.0;
      source = Manual }
  ) peers

(* Add a peer address to known addresses *)
let add_known_addr (pm : t) (info : peer_info) : unit =
  if not (Hashtbl.mem pm.known_addrs info.address) then
    Hashtbl.replace pm.known_addrs info.address info

(* Connect to a peer and add to active peers *)
let add_peer (pm : t) (addr : string) (port : int) : unit Lwt.t =
  let open Lwt.Syntax in
  (* Check connection limits *)
  let outbound_count = outbound_peer_count pm in
  if outbound_count >= pm.config.max_outbound then
    Lwt.return_unit
  (* Check if already connected *)
  else if List.exists (fun p -> p.Peer.addr = addr) pm.peers then
    Lwt.return_unit
  (* Check if banned *)
  else if is_banned pm addr then
    Lwt.return_unit
  else begin
    let id = pm.next_peer_id in
    pm.next_peer_id <- pm.next_peer_id + 1;
    (* Update last_attempt *)
    (match Hashtbl.find_opt pm.known_addrs addr with
     | Some info ->
       Hashtbl.replace pm.known_addrs addr
         { info with last_attempt = Unix.gettimeofday () }
     | None -> ());
    Lwt.catch (fun () ->
      let* peer = Peer.connect ~network:pm.network ~addr ~port ~id in
      let* () = Peer.perform_handshake peer pm.our_height in
      pm.peers <- peer :: pm.peers;
      (* Update known_addrs with successful connection *)
      (match Hashtbl.find_opt pm.known_addrs addr with
       | Some info ->
         Hashtbl.replace pm.known_addrs addr
           { info with
             last_connected = Unix.gettimeofday ();
             failures = 0 }
       | None ->
         Hashtbl.replace pm.known_addrs addr
           { address = addr;
             port;
             services = Peer.services_to_int64 peer.services;
             last_connected = Unix.gettimeofday ();
             last_attempt = Unix.gettimeofday ();
             failures = 0;
             banned_until = 0.0;
             source = Manual });
      Lwt.return_unit
    ) (fun _exn ->
      (* Connection failed, record failure *)
      (match Hashtbl.find_opt pm.known_addrs addr with
       | Some info ->
         Hashtbl.replace pm.known_addrs addr
           { info with
             failures = info.failures + 1;
             last_attempt = Unix.gettimeofday () }
       | None -> ());
      Lwt.return_unit
    )
  end

(* Remove a peer by id *)
let remove_peer (pm : t) (peer_id : int) : unit Lwt.t =
  let open Lwt.Syntax in
  match List.find_opt (fun p -> p.Peer.id = peer_id) pm.peers with
  | None -> Lwt.return_unit
  | Some peer ->
    let* () = Peer.disconnect peer in
    pm.peers <- List.filter (fun p -> p.Peer.id <> peer_id) pm.peers;
    Hashtbl.remove pm.chain_sync_behind_since peer_id;
    Lwt.return_unit

(* Ban a peer *)
let ban_peer (pm : t) (peer_id : int) ?(duration = 86400.0) () : unit Lwt.t =
  match List.find_opt (fun p -> p.Peer.id = peer_id) pm.peers with
  | None -> Lwt.return_unit
  | Some peer ->
    Hashtbl.replace pm.known_addrs peer.addr
      { address = peer.addr;
        port = peer.port;
        services = Peer.services_to_int64 peer.services;
        last_connected = 0.0;
        last_attempt = 0.0;
        failures = 0;
        banned_until = Unix.gettimeofday () +. duration;
        source = Addr };
    remove_peer pm peer_id

(* Ban a peer by address *)
let ban_addr (pm : t) (addr : string) ?(duration = 86400.0) () : unit =
  match Hashtbl.find_opt pm.known_addrs addr with
  | Some info ->
    Hashtbl.replace pm.known_addrs addr
      { info with banned_until = Unix.gettimeofday () +. duration }
  | None ->
    Hashtbl.replace pm.known_addrs addr
      { address = addr;
        port = 0;
        services = 0L;
        last_connected = 0.0;
        last_attempt = 0.0;
        failures = 0;
        banned_until = Unix.gettimeofday () +. duration;
        source = Addr }

(* Unban an address *)
let unban_addr (pm : t) (addr : string) : unit =
  match Hashtbl.find_opt pm.known_addrs addr with
  | Some info ->
    Hashtbl.replace pm.known_addrs addr { info with banned_until = 0.0 }
  | None -> ()

(* Clear all bans *)
let clear_bans (pm : t) : unit =
  Hashtbl.iter (fun addr info ->
    if info.banned_until > 0.0 then
      Hashtbl.replace pm.known_addrs addr { info with banned_until = 0.0 }
  ) pm.known_addrs

(* Get list of all banned addresses with expiry times *)
let get_banned_list (pm : t) : (string * float) list =
  let now = Unix.gettimeofday () in
  Hashtbl.fold (fun addr info acc ->
    if info.banned_until > now then
      (addr, info.banned_until) :: acc
    else
      acc
  ) pm.known_addrs []

(* Record misbehavior for a peer.  Bans the peer if accumulated score >= 100. *)
let record_peer_misbehavior (pm : t) (peer_id : int) (score : int)
    (_reason : string) : unit Lwt.t =
  match List.find_opt (fun p -> p.Peer.id = peer_id) pm.peers with
  | None -> Lwt.return_unit
  | Some peer ->
    (match Peer.record_misbehavior peer score with
     | `Ok -> Lwt.return_unit
     | `Ban -> ban_peer pm peer_id ())

(* Get a misbehavior handler callback suitable for use from sync.ml etc.
   Usage: let handler = get_misbehavior_handler pm in handler peer_id score reason *)
let get_misbehavior_handler (pm : t) : misbehavior_handler =
  fun peer_id score reason ->
    record_peer_misbehavior pm peer_id score reason

(* Get candidate addresses for connection *)
let get_connection_candidates (pm : t) (count : int) : peer_info list =
  let now = Unix.gettimeofday () in
  let candidates = Hashtbl.fold (fun _ info acc ->
    (* Filter: not banned, not too many failures, not recently tried, not connected *)
    if info.banned_until < now &&
       info.failures < pm.config.max_failures &&
       now -. info.last_attempt > pm.config.retry_delay &&
       not (List.exists (fun p -> p.Peer.addr = info.address) pm.peers)
    then info :: acc
    else acc
  ) pm.known_addrs [] in
  (* Sort by: fewer failures first, more recent connections first *)
  let sorted = List.sort (fun a b ->
    let cmp = compare a.failures b.failures in
    if cmp <> 0 then cmp
    else compare b.last_connected a.last_connected
  ) candidates in
  (* Take first 'count' candidates *)
  List.filteri (fun i _ -> i < count) sorted

(* Send a message to all ready peers *)
let broadcast (pm : t) (payload : P2p.message_payload) : unit Lwt.t =
  let ready = get_ready_peers pm in
  Lwt_list.iter_p (fun peer ->
    Lwt.catch
      (fun () -> Peer.send_message peer payload)
      (fun _exn -> Lwt.return_unit)
  ) ready

(* Send a message to a specific peer *)
let send_to_peer (pm : t) (peer_id : int) (payload : P2p.message_payload) : unit Lwt.t =
  match List.find_opt (fun p -> p.Peer.id = peer_id) pm.peers with
  | None -> Lwt.return_unit
  | Some peer ->
    Lwt.catch
      (fun () -> Peer.send_message peer payload)
      (fun _exn -> Lwt.return_unit)

(* Announce a new block to all connected peers, respecting send_headers (BIP-130).
   Peers that opted in via sendheaders receive the header directly;
   others receive an inv containing the block hash. *)
let announce_block (pm : t) (header : Types.block_header) (hash : Types.hash256) : unit Lwt.t =
  let ready = get_ready_peers pm in
  Lwt_list.iter_p (fun peer ->
    Lwt.catch (fun () ->
      if peer.Peer.send_headers then
        Peer.send_message peer (P2p.HeadersMsg [header])
      else
        Peer.send_message peer (P2p.InvMsg [{ P2p.inv_type = P2p.InvBlock; hash }])
    ) (fun _exn -> Lwt.return_unit)
  ) ready

(* Announce a new transaction to all connected peers via inv. *)
let announce_tx (pm : t) ~(txid : Types.hash256) ~(wtxid : Types.hash256)
    ~(fee_rate : int64) : unit Lwt.t =
  let ready = get_ready_peers pm in
  Lwt_list.iter_p (fun peer ->
    Lwt.catch (fun () ->
      (* Skip peers whose feefilter is above this tx's fee rate *)
      if peer.Peer.feefilter > 0L && fee_rate < peer.Peer.feefilter then
        Lwt.return_unit
      else if peer.Peer.wtxid_relay then
        Peer.send_message peer (P2p.InvMsg [{ P2p.inv_type = P2p.InvWitnessTx; hash = wtxid }])
      else
        Peer.send_message peer (P2p.InvMsg [{ P2p.inv_type = P2p.InvTx; hash = txid }])
    ) (fun _exn -> Lwt.return_unit)
  ) ready

(* Check if a 16-byte address is an IPv4-mapped IPv6 address (::ffff:x.x.x.x) *)
let is_ipv4_mapped (addr : Cstruct.t) : bool =
  (* First 10 bytes must be 0x00, bytes 10-11 must be 0xFF *)
  let ok = ref true in
  for i = 0 to 9 do
    if Cstruct.get_uint8 addr i <> 0x00 then ok := false
  done;
  if Cstruct.get_uint8 addr 10 <> 0xFF then ok := false;
  if Cstruct.get_uint8 addr 11 <> 0xFF then ok := false;
  !ok

(* Check if all 16 bytes of the address are zero (unspecified address) *)
let is_unspecified (addr : Cstruct.t) : bool =
  let ok = ref true in
  for i = 0 to 15 do
    if Cstruct.get_uint8 addr i <> 0 then ok := false
  done;
  !ok

(* Format a 16-byte network address field as a string.
   IPv4-mapped -> "x.x.x.x", native IPv6 -> "x:x:x:x:x:x:x:x",
   unspecified (all zeros) -> None *)
let format_address (addr : Cstruct.t) : string option =
  if is_unspecified addr then
    None
  else if is_ipv4_mapped addr then
    Some (Printf.sprintf "%d.%d.%d.%d"
      (Cstruct.get_uint8 addr 12)
      (Cstruct.get_uint8 addr 13)
      (Cstruct.get_uint8 addr 14)
      (Cstruct.get_uint8 addr 15))
  else
    (* Native IPv6: format as 8 groups of 16-bit hex values *)
    let groups = Array.init 8 (fun i ->
      Cstruct.BE.get_uint16 addr (i * 2)
    ) in
    Some (Printf.sprintf "%x:%x:%x:%x:%x:%x:%x:%x"
      groups.(0) groups.(1) groups.(2) groups.(3)
      groups.(4) groups.(5) groups.(6) groups.(7))

(* Handle incoming addr message with rate limiting and validation *)
let handle_addr (pm : t) (peer : Peer.peer) (addrs : (int32 * Types.net_addr) list) : unit =
  let now = Unix.gettimeofday () in
  let peer_key = Printf.sprintf "%s:%d" peer.Peer.addr peer.Peer.port in
  let addr_window = 86400.0 in  (* 24-hour window *)
  let max_addrs_per_day = 1000 in
  (* Get or initialize rate limit state for this peer *)
  let (count, window_start) =
    match Hashtbl.find_opt pm.addr_rate peer_key with
    | Some (c, ws) ->
      if now -. ws > addr_window then
        (* Window expired, reset *)
        (0, now)
      else
        (c, ws)
    | None -> (0, now)
  in
  let remaining = max_addrs_per_day - count in
  if remaining <= 0 then begin
    (* Rate limit exceeded, ignore all addresses *)
    Log.info (fun m -> m "Addr rate limit exceeded for peer %d (%s)"
      peer.Peer.id peer.Peer.addr);
    ()
  end else begin
    (* Only process up to the remaining quota *)
    let to_process = if List.length addrs > remaining then
      List.filteri (fun i _ -> i < remaining) addrs
    else
      addrs
    in
    let processed = ref 0 in
    List.iter (fun (ts, addr) ->
      (* Extract address from 16-byte network address field *)
      match format_address addr.Types.addr with
      | None -> ()  (* Unspecified address, skip *)
      | Some ip_str ->
      (* Timestamp validation: reject addresses > 600 seconds in the future *)
      let ts_float = Int32.to_float ts in
      if ts_float > now +. 600.0 then
        ()  (* Skip future-timestamped addresses *)
      (* Self-address filtering: don't store our own listening address *)
      else if (match pm.listen_addr with
               | Some our_addr -> ip_str = our_addr
               | None -> false) then
        ()  (* Skip our own address *)
      else if not (Hashtbl.mem pm.known_addrs ip_str) then begin
        Hashtbl.replace pm.known_addrs ip_str
          { address = ip_str;
            port = addr.port;
            services = addr.services;
            last_connected = 0.0;
            last_attempt = 0.0;
            failures = 0;
            banned_until = 0.0;
            source = Addr };
        incr processed
      end
    ) to_process;
    (* Update rate limit counter *)
    Hashtbl.replace pm.addr_rate peer_key (count + !processed, window_start)
  end

(* Build block locator hashes for getheaders/getblocks.
   Returns hashes from tip backwards to genesis, using exponential stepping.
   First 10 entries are sequential, then step doubles. Always ends with genesis. *)
let build_locator (db : Storage.ChainDB.t) (tip_height : int) : Types.hash256 list =
  let result = ref [] in
  let step = ref 1 in
  let height = ref tip_height in
  let count = ref 0 in
  (* Walk backwards from tip, collecting hashes *)
  while !height >= 0 do
    (match Storage.ChainDB.get_hash_at_height db !height with
     | Some hash ->
       result := hash :: !result;
       incr count
     | None -> ());
    (* After first 10 entries, double the step *)
    if !count >= 10 then
      step := !step * 2;
    height := !height - !step
  done;
  (* Always include genesis if not already included *)
  (match Storage.ChainDB.get_hash_at_height db 0 with
   | Some hash ->
     if not (List.exists (fun h -> Cstruct.equal h hash) !result) then
       result := hash :: !result
   | None -> ());
  (* Result was built in reverse (prepending), so reverse to get tip first *)
  List.rev !result

(* Peer message handling loop for a single peer *)
let peer_message_loop (pm : t) (peer : Peer.peer) : unit Lwt.t =
  let open Lwt.Syntax in
  let rec loop () =
    if peer.state = Peer.Disconnected || not pm.running then
      Lwt.return_unit
    else begin
      Lwt.catch (fun () ->
        let* msg_opt = Peer.read_message_with_timeout peer 30.0 in
        match msg_opt with
        | None ->
          (* Timeout, check if peer needs ping *)
          if Peer.needs_ping peer then begin
            let* () = Peer.send_ping peer in
            loop ()
          end else if Peer.ping_timed_out peer then begin
            (* Peer not responding, disconnect *)
            let* () = remove_peer pm peer.id in
            Lwt.return_unit
          end else
            loop ()
        | Some msg ->
          (* Handle low-level protocol messages *)
          let* action = Peer.handle_message peer msg in
          (match action with
           | `Disconnect _reason ->
             remove_peer pm peer.id
           | `Continue ->
             (* Pass message to listeners *)
             let* () = Lwt_list.iter_s (fun listener ->
               Lwt.catch
                 (fun () -> listener msg peer)
                 (fun _exn -> Lwt.return_unit)
             ) pm.listeners in
             (* Handle addr messages specially *)
             (match msg with
              | P2p.AddrMsg addrs -> handle_addr pm peer addrs
              | _ -> ());
             loop ())
      ) (fun exn ->
        (* Connection error *)
        let _ = exn in
        remove_peer pm peer.id
      )
    end
  in
  loop ()

(* Check for stale chain tip and take corrective action *)
let check_stale_tip (pm : t) : unit Lwt.t =
  let open Lwt.Syntax in
  let now = Unix.gettimeofday () in
  let time_since_update = now -. pm.last_tip_update in
  let ready_peers = get_ready_peers pm in
  (* Find peers reporting higher block heights than ours *)
  let higher_peers = List.filter (fun p ->
    p.Peer.best_height > pm.our_height
  ) ready_peers in
  if time_since_update > pm.stale_tip_check_interval && higher_peers <> [] then begin
    (* Sort by best_height descending to find the peer with highest reported height *)
    let sorted = List.sort (fun a b ->
      Int32.compare b.Peer.best_height a.Peer.best_height
    ) higher_peers in
    let best_peer = List.hd sorted in
    Log.info (fun m -> m "Stale tip detected (no update for %.0fs), \
      peer %d reports height %ld vs our %ld"
      time_since_update best_peer.Peer.id best_peer.Peer.best_height pm.our_height);
    (* Send getheaders to the peer with the highest reported height *)
    let getheaders = P2p.GetheadersMsg {
      version = 70016l;
      locator_hashes = (match pm.db with
        | Some db -> build_locator db (Int32.to_int pm.our_height)
        | None -> []);
      hash_stop = Types.zero_hash;
    } in
    let* () = Lwt.catch
      (fun () -> Peer.send_message best_peer getheaders)
      (fun _exn -> Lwt.return_unit) in
    (* If tip is very stale (2x interval), disconnect longest-behind peer and try a new one *)
    if time_since_update > 2.0 *. pm.stale_tip_check_interval then begin
      Log.info (fun m -> m "Tip severely stale (%.0fs), rotating longest-behind peer" time_since_update);
      (* Find peer that has been behind the longest *)
      let behind_peers = Hashtbl.fold (fun pid ts acc ->
        (pid, ts) :: acc
      ) pm.chain_sync_behind_since [] in
      let sorted_behind = List.sort (fun (_, ts1) (_, ts2) ->
        compare ts1 ts2  (* oldest timestamp first = behind longest *)
      ) behind_peers in
      match sorted_behind with
      | (pid, _) :: _ ->
        let* () = remove_peer pm pid in
        let candidates = get_connection_candidates pm 1 in
        (match candidates with
         | [] -> Lwt.return_unit
         | c :: _ -> add_peer pm c.address c.port)
      | [] ->
        (* No tracked behind peers; fall back to lowest height *)
        let sorted_asc = List.sort (fun a b ->
          Int32.compare a.Peer.best_height b.Peer.best_height
        ) ready_peers in
        (match sorted_asc with
        | [] -> Lwt.return_unit
        | lowest :: _ ->
          let* () = remove_peer pm lowest.Peer.id in
          let candidates = get_connection_candidates pm 1 in
          (match candidates with
           | [] -> Lwt.return_unit
           | c :: _ -> add_peer pm c.address c.port))
    end else
      Lwt.return_unit
  end else
    Lwt.return_unit

(* Connection maintenance loop *)
let maintain_connections (pm : t) : unit Lwt.t =
  let open Lwt.Syntax in
  let rec loop () =
    if not pm.running then Lwt.return_unit
    else begin
      (* Count active outbound connections *)
      let active_outbound = List.filter (fun p ->
        p.Peer.state = Peer.Ready && p.Peer.direction = Peer.Outbound
      ) pm.peers in
      let needed = pm.config.max_outbound - List.length active_outbound in
      (* Try to connect to more peers if needed *)
      let* () =
        if needed > 0 then begin
          let candidates = get_connection_candidates pm needed in
          Lwt_list.iter_s (fun info ->
            add_peer pm info.address info.port
          ) candidates
        end else
          Lwt.return_unit
      in
      (* Ping idle peers *)
      let* () = Lwt_list.iter_p (fun peer ->
        if Peer.needs_ping peer then
          Peer.send_ping peer
        else
          Lwt.return_unit
      ) pm.peers in
      (* Remove dead peers *)
      let now = Unix.gettimeofday () in
      let dead = List.filter (fun p ->
        p.Peer.state = Peer.Ready &&
        now -. p.last_seen > pm.config.dead_timeout
      ) pm.peers in
      let* () = Lwt_list.iter_s (fun p ->
        remove_peer pm p.Peer.id
      ) dead in
      (* Evict outbound peers behind our chain tip for too long *)
      let* () =
        let our_h = Int32.to_int pm.our_height in
        let behind = List.filter (fun p ->
          p.Peer.state = Peer.Ready &&
          p.Peer.direction = Peer.Outbound &&
          Int32.to_int p.Peer.best_height < our_h - 1
        ) pm.peers in
        (* Track when each outbound peer first fell behind *)
        List.iter (fun p ->
          if not (Hashtbl.mem pm.chain_sync_behind_since p.Peer.id) then
            Hashtbl.replace pm.chain_sync_behind_since p.Peer.id now
        ) behind;
        (* Clear tracking for peers that caught up *)
        let caught_up_ids = Hashtbl.fold (fun pid _ts acc ->
          match List.find_opt (fun p -> p.Peer.id = pid) behind with
          | Some _ -> acc
          | None -> pid :: acc
        ) pm.chain_sync_behind_since [] in
        List.iter (fun pid ->
          Hashtbl.remove pm.chain_sync_behind_since pid
        ) caught_up_ids;
        (* Disconnect peers behind for longer than chain_sync_timeout *)
        let to_evict = Hashtbl.fold (fun pid ts acc ->
          if now -. ts > pm.config.chain_sync_timeout then pid :: acc
          else acc
        ) pm.chain_sync_behind_since [] in
        Lwt_list.iter_s (fun pid ->
          Log.info (fun m -> m "Evicting outbound peer %d: behind our tip for >%.0fs"
            pid pm.config.chain_sync_timeout);
          remove_peer pm pid
        ) to_evict
      in
      (* Check for stale chain tip *)
      let* () = check_stale_tip pm in
      (* Sleep before next iteration *)
      let* () = Lwt_unix.sleep 10.0 in
      loop ()
    end
  in
  loop ()

(* Accept an inbound connection and perform reverse handshake *)
let accept_inbound (pm : t) (client_fd : Lwt_unix.file_descr)
    (client_addr : Unix.sockaddr) : unit Lwt.t =
  let open Lwt.Syntax in
  let addr_str, port = match client_addr with
    | Unix.ADDR_INET (ip, p) -> (Unix.string_of_inet_addr ip, p)
    | Unix.ADDR_UNIX s -> (s, 0) in
  (* Check inbound limits - try eviction before rejecting *)
  let* () =
    if inbound_peer_count pm >= pm.config.max_inbound then
      evict_inbound_peer pm
    else
      Lwt.return_unit
  in
  if inbound_peer_count pm >= pm.config.max_inbound then begin
    let* () = Lwt.catch
      (fun () -> Lwt_unix.close client_fd)
      (fun _ -> Lwt.return_unit) in
    Lwt.return_unit
  end
  (* Check if banned *)
  else if is_banned pm addr_str then begin
    let* () = Lwt.catch
      (fun () -> Lwt_unix.close client_fd)
      (fun _ -> Lwt.return_unit) in
    Lwt.return_unit
  end
  (* Check if already connected *)
  else if List.exists (fun p -> p.Peer.addr = addr_str) pm.peers then begin
    let* () = Lwt.catch
      (fun () -> Lwt_unix.close client_fd)
      (fun _ -> Lwt.return_unit) in
    Lwt.return_unit
  end
  else begin
    let id = pm.next_peer_id in
    pm.next_peer_id <- pm.next_peer_id + 1;
    Lwt.catch (fun () ->
      let peer = Peer.make_peer ~network:pm.network ~addr:addr_str ~port
        ~id ~direction:Peer.Inbound ~fd:client_fd in
      let* () = Peer.perform_inbound_handshake peer pm.our_height in
      pm.peers <- peer :: pm.peers;
      (* Start the message loop for this inbound peer *)
      Lwt.async (fun () -> peer_message_loop pm peer);
      Lwt.return_unit
    ) (fun _exn ->
      (* Handshake failed, clean up *)
      Lwt.catch
        (fun () -> Lwt_unix.close client_fd)
        (fun _ -> Lwt.return_unit)
    )
  end

(* Start a TCP listener for inbound connections *)
let start_listener (pm : t) (port : int) : unit Lwt.t =
  let open Lwt.Syntax in
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Lwt_unix.setsockopt fd Unix.SO_REUSEADDR true;
  let* () = Lwt_unix.bind fd (Unix.ADDR_INET (Unix.inet_addr_any, port)) in
  Lwt_unix.listen fd 128;
  pm.listener_fd <- Some fd;
  let rec accept_loop () =
    if not pm.running then Lwt.return_unit
    else begin
      Lwt.catch (fun () ->
        let* (client_fd, client_addr) = Lwt_unix.accept fd in
        (* Handle inbound connection asynchronously *)
        Lwt.async (fun () -> accept_inbound pm client_fd client_addr);
        accept_loop ()
      ) (fun exn ->
        if pm.running then begin
          (* Log and continue on transient errors *)
          let _ = exn in
          let* () = Lwt_unix.sleep 0.1 in
          accept_loop ()
        end else
          Lwt.return_unit
      )
    end
  in
  Lwt.async (fun () -> accept_loop ());
  Lwt.return_unit

(* Start the peer manager *)
let start (pm : t) : unit Lwt.t =
  let open Lwt.Syntax in
  pm.running <- true;
  (* Resolve DNS seeds *)
  let* seed_addrs = resolve_dns_seeds pm.network in
  List.iter (fun info ->
    Hashtbl.replace pm.known_addrs info.address info
  ) seed_addrs;
  (* Add fallback peers *)
  let fallback = get_fallback_peers pm.network in
  List.iter (add_known_addr pm) fallback;
  (* Start connection maintenance loop *)
  let maintenance = maintain_connections pm in
  (* Return immediately, maintenance runs in background *)
  Lwt.async (fun () -> maintenance);
  Lwt.return_unit

(* Stop the peer manager *)
let stop (pm : t) : unit Lwt.t =
  let open Lwt.Syntax in
  pm.running <- false;
  (* Close the listener socket if open *)
  let* () = match pm.listener_fd with
    | Some fd ->
      pm.listener_fd <- None;
      Lwt.catch (fun () -> Lwt_unix.close fd) (fun _ -> Lwt.return_unit)
    | None -> Lwt.return_unit in
  Lwt_list.iter_s (fun p -> remove_peer pm p.Peer.id) pm.peers

(* Request getaddr from all peers *)
let request_addrs (pm : t) : unit Lwt.t =
  broadcast pm P2p.GetaddrMsg

(* Get statistics about known addresses *)
type addr_stats = {
  total_known : int;
  banned : int;
  tried : int;
  connected : int;
}

let get_addr_stats (pm : t) : addr_stats =
  let now = Unix.gettimeofday () in
  let total = Hashtbl.length pm.known_addrs in
  let banned_count = Hashtbl.fold (fun _ info acc ->
    if info.banned_until > now then acc + 1 else acc
  ) pm.known_addrs 0 in
  let tried_count = Hashtbl.fold (fun _ info acc ->
    if info.last_attempt > 0.0 then acc + 1 else acc
  ) pm.known_addrs 0 in
  let connected_count = List.length pm.peers in
  { total_known = total;
    banned = banned_count;
    tried = tried_count;
    connected = connected_count;
  }

(* Ban persistence key prefix — must not collide with Storage prefixes *)
let ban_prefix = "B"

(* Save currently active bans to the database.
   Each ban is stored with key "B<addr>" and value = 8-byte BE float
   (Int64.bits_of_float banned_until). *)
let save_bans (pm : t) (db : Storage.ChainDB.t) : unit =
  let now = Unix.gettimeofday () in
  (* First, remove stale ban entries from the DB *)
  Storage.LogStorage.iter_prefix db.db ban_prefix (fun key _value ->
    let addr = String.sub key 1 (String.length key - 1) in
    match Hashtbl.find_opt pm.known_addrs addr with
    | Some info when info.banned_until > now -> ()  (* still active, will overwrite *)
    | _ -> Storage.LogStorage.delete db.db key
  );
  (* Write all active bans *)
  Hashtbl.iter (fun addr info ->
    if info.banned_until > now then begin
      let key = ban_prefix ^ addr in
      let cs = Cstruct.create 8 in
      Cstruct.BE.set_uint64 cs 0 (Int64.bits_of_float info.banned_until);
      Storage.LogStorage.put db.db key (Cstruct.to_string cs)
    end
  ) pm.known_addrs

(* Load persisted bans from the database.
   Returns the number of bans that are still active and were loaded. *)
let load_bans (pm : t) (db : Storage.ChainDB.t) : int =
  let now = Unix.gettimeofday () in
  let count = ref 0 in
  Storage.LogStorage.iter_prefix db.db ban_prefix (fun key value ->
    if String.length value >= 8 then begin
      let addr = String.sub key 1 (String.length key - 1) in
      let cs = Cstruct.of_string value in
      let banned_until = Int64.float_of_bits (Cstruct.BE.get_uint64 cs 0) in
      if banned_until > now then begin
        (match Hashtbl.find_opt pm.known_addrs addr with
         | Some info ->
           Hashtbl.replace pm.known_addrs addr
             { info with banned_until }
         | None ->
           Hashtbl.replace pm.known_addrs addr
             { address = addr;
               port = 0;
               services = 0L;
               last_connected = 0.0;
               last_attempt = 0.0;
               failures = 0;
               banned_until;
               source = Addr });
        incr count
      end else
        (* Expired ban — clean up from DB *)
        Storage.LogStorage.delete db.db key
    end
  );
  !count

(* Save bans to JSON file (banlist.json) *)
let save_bans_json (pm : t) (filepath : string) : unit =
  let now = Unix.gettimeofday () in
  let bans = Hashtbl.fold (fun addr info acc ->
    if info.banned_until > now then
      `Assoc [
        ("address", `String addr);
        ("banned_until", `Float info.banned_until);
      ] :: acc
    else
      acc
  ) pm.known_addrs [] in
  let json = `List bans in
  let oc = open_out filepath in
  output_string oc (Yojson.Safe.pretty_to_string json);
  close_out oc

(* Load bans from JSON file (banlist.json) *)
let load_bans_json (pm : t) (filepath : string) : int =
  if not (Sys.file_exists filepath) then
    0
  else begin
    let now = Unix.gettimeofday () in
    let count = ref 0 in
    try
      let ic = open_in filepath in
      let content = really_input_string ic (in_channel_length ic) in
      close_in ic;
      let json = Yojson.Safe.from_string content in
      (match json with
       | `List entries ->
         List.iter (fun entry ->
           match entry with
           | `Assoc fields ->
             let addr = match List.assoc_opt "address" fields with
               | Some (`String a) -> Some a
               | _ -> None
             in
             let banned_until = match List.assoc_opt "banned_until" fields with
               | Some (`Float f) -> Some f
               | Some (`Int i) -> Some (float_of_int i)
               | _ -> None
             in
             (match addr, banned_until with
              | Some a, Some bu when bu > now ->
                (match Hashtbl.find_opt pm.known_addrs a with
                 | Some info ->
                   Hashtbl.replace pm.known_addrs a
                     { info with banned_until = bu }
                 | None ->
                   Hashtbl.replace pm.known_addrs a
                     { address = a;
                       port = 0;
                       services = 0L;
                       last_connected = 0.0;
                       last_attempt = 0.0;
                       failures = 0;
                       banned_until = bu;
                       source = Addr });
                incr count
              | _ -> ())
           | _ -> ()
         ) entries
       | _ -> ());
      !count
    with _ -> 0
  end

(* Find peer by address *)
let find_peer_by_addr (pm : t) (addr : string) : Peer.peer option =
  List.find_opt (fun p -> p.Peer.addr = addr) pm.peers

(* Find peer by id *)
let find_peer_by_id (pm : t) (id : int) : Peer.peer option =
  List.find_opt (fun p -> p.Peer.id = id) pm.peers

(* Get list of all peer statistics *)
let get_peer_stats (pm : t) : Peer.peer_stats list =
  List.map Peer.get_stats pm.peers

(* Handle peer disconnect - re-queue in-flight blocks immediately *)
let on_peer_disconnect (pm : t) (peer_id : int)
    (requeue_blocks : Types.hash256 list -> unit) : unit Lwt.t =
  let open Lwt.Syntax in
  (* This should be called when a peer disconnects to immediately
     re-queue any blocks that were being downloaded from that peer *)
  match find_peer_by_id pm peer_id with
  | None -> Lwt.return_unit
  | Some _peer ->
    (* The caller should track which blocks were in-flight from this peer
       and call requeue_blocks with those hashes *)
    requeue_blocks [];
    let* () = remove_peer pm peer_id in
    Lwt.return_unit
