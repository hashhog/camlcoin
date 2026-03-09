(* Peer discovery and connection pool management using Lwt *)

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
}

let default_config : config = {
  max_outbound = 8;
  max_inbound = 117;
  retry_delay = 60.0;
  max_failures = 5;
  ban_duration = 86400.0;  (* 24 hours *)
  ping_interval = 120.0;   (* 2 minutes *)
  dead_timeout = 600.0;    (* 10 minutes *)
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
  }

(* Update our known blockchain height *)
let set_height (pm : t) (height : int32) : unit =
  pm.our_height <- height

(* Get current blockchain height *)
let get_height (pm : t) : int32 =
  pm.our_height

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
  let outbound_count = List.length (get_ready_peers pm) in
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

(* Handle incoming addr message *)
let handle_addr (pm : t) (addrs : (int32 * Types.net_addr) list) : unit =
  List.iter (fun (_ts, addr) ->
    (* Extract IPv4 address from IPv6-mapped format *)
    let ip_str =
      Printf.sprintf "%d.%d.%d.%d"
        (Cstruct.get_uint8 addr.Types.addr 12)
        (Cstruct.get_uint8 addr.addr 13)
        (Cstruct.get_uint8 addr.addr 14)
        (Cstruct.get_uint8 addr.addr 15) in
    if not (Hashtbl.mem pm.known_addrs ip_str) then
      Hashtbl.replace pm.known_addrs ip_str
        { address = ip_str;
          port = addr.port;
          services = addr.services;
          last_connected = 0.0;
          last_attempt = 0.0;
          failures = 0;
          banned_until = 0.0;
          source = Addr }
  ) addrs

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
              | P2p.AddrMsg addrs -> handle_addr pm addrs
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

(* Connection maintenance loop *)
let maintain_connections (pm : t) : unit Lwt.t =
  let open Lwt.Syntax in
  let rec loop () =
    if not pm.running then Lwt.return_unit
    else begin
      (* Count active connections *)
      let active = List.filter (fun p -> p.Peer.state = Peer.Ready) pm.peers in
      let needed = pm.config.max_outbound - List.length active in
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
      (* Sleep before next iteration *)
      let* () = Lwt_unix.sleep 10.0 in
      loop ()
    end
  in
  loop ()

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
  pm.running <- false;
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
