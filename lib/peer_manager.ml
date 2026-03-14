(* Peer discovery and connection pool management using Lwt *)

let log_src = Logs.Src.create "NET" ~doc:"P2P networking"
module Log = (val Logs.src_log log_src : Logs.LOG)

(* Source of peer address discovery *)
type addr_source =
  | Dns      (* From DNS seed resolution *)
  | Addr     (* From addr message from peer *)
  | Manual   (* Manually added by user *)

(* Address table status (for eclipse protection bucketing) *)
type addr_table_status =
  | InNew of int    (* In new table, bucket index *)
  | InTried of int  (* In tried table, bucket index *)
  | NotInTable      (* Not yet in any table *)

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
  table_status : addr_table_status;  (* Which bucket table this address is in *)
  last_success : float;              (* Last successful outbound connection *)
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
  max_block_relay_only_anchors : int; (* Max anchor connections to persist, default 2 *)
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
  max_block_relay_only_anchors = 2; (* BIP 155: 2 block-relay-only anchors *)
}

(* ========== Stale peer eviction constants ========== *)
(* Reference: Bitcoin Core net_processing.cpp ConsiderEviction() *)

module Stale = struct
  (** Headers timeout: 20 minutes without header from peer behind our tip *)
  let headers_timeout = 1200.0

  (** Headers response time: 2 minutes to respond to getheaders challenge *)
  let headers_response_time = 120.0

  (** Block stalling: 2 seconds per assigned block minimum *)
  let block_stalling_timeout = 2.0

  (** Block stalling absolute max: 10 minutes before disconnect *)
  let block_stalling_max = 600.0

  (** Ping timeout: 20 minutes without pong response *)
  let ping_timeout = 1200.0

  (** Stale check interval: run periodic check every 45 seconds *)
  let stale_check_interval = 45.0
end

(** Chain sync state for tracking headers timeout challenge *)
type chain_sync_state =
  | ChainSynced                     (** Peer is caught up or recently sent headers *)
  | ChainWaitingForHeaders of {
      timeout : float;              (** Absolute deadline for getheaders response *)
      sent_getheaders : bool;       (** Whether we've sent the getheaders challenge *)
    }

(** Block download stalling state per peer *)
type block_stall_state = {
  mutable blocks_in_flight : int;   (** Number of blocks assigned to download *)
  mutable stalling_since : float option; (** When stalling started, if any *)
  mutable last_block_time : float;  (** Last time we received a block from this peer *)
}

(** Per-peer stale tracking state *)
type stale_peer_state = {
  mutable chain_sync : chain_sync_state;
  mutable last_header_time : float;
  block_stall : block_stall_state;
  mutable last_ping_nonce : int64 option;
  mutable last_ping_sent : float;
  mutable last_pong_received : float;
}

(** Create initial stale state for a new peer *)
let create_stale_state () : stale_peer_state =
  let now = Unix.gettimeofday () in
  {
    chain_sync = ChainSynced;
    last_header_time = now;
    block_stall = {
      blocks_in_flight = 0;
      stalling_since = None;
      last_block_time = now;
    };
    last_ping_nonce = None;
    last_ping_sent = now;
    last_pong_received = now;
  }

(** Stale peer disconnect reasons *)
module StaleReason = struct
  let headers_timeout = "headers sync timeout (no response to getheaders challenge)"
  let block_stalling = "block download stalling (10 minutes without progress)"
  let ping_timeout = "ping timeout (20 minutes without pong)"
end

(* Eclipse attack protection constants (from Bitcoin Core addrman_impl.h) *)
let new_bucket_count = 1024        (* 2^10 = 1024 "new" buckets *)
let tried_bucket_count = 256       (* 2^8 = 256 "tried" buckets *)
let bucket_size = 64               (* Max entries per bucket *)
let new_buckets_per_address = 8    (* Max times addr can appear in new table *)

(* Eviction protection constants (from Bitcoin Core eviction.cpp) *)
let protect_by_netgroup = 4        (* Protect 4 peers by distinct netgroup *)
let protect_by_ping = 8            (* Protect 8 peers by lowest ping *)
let protect_by_tx_time = 4         (* Protect 4 peers by recent tx relay *)
let protect_by_block_relay = 8     (* Protect up to 8 block-relay-only peers *)
let protect_by_block_time = 4      (* Protect 4 peers by recent block relay *)

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

(* Eviction candidate info for multi-criteria eviction algorithm *)
type eviction_candidate = {
  ec_peer : Peer.peer;
  ec_connected : float;          (* Connection timestamp *)
  ec_min_ping : float;           (* Minimum ping latency *)
  ec_last_block_time : float;    (* Last block received timestamp *)
  ec_last_tx_time : float;       (* Last tx received timestamp *)
  ec_keyed_netgroup : int;       (* Hashed /16 netgroup *)
  ec_relay_txs : bool;           (* Whether this peer relays txs *)
  ec_prefer_evict : bool;        (* Flagged for eviction preference *)
}

(* Anchor connection info for persistence across restarts *)
type anchor_info = {
  anchor_addr : string;
  anchor_port : int;
  anchor_services : int64;
}

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
  (* Eclipse protection: address bucketing *)
  bucket_key : string;                            (* Random key for bucket hashing *)
  new_table : (int, string list) Hashtbl.t;       (* New address buckets: bucket_id -> addresses *)
  tried_table : (int, string list) Hashtbl.t;     (* Tried address buckets: bucket_id -> addresses *)
  mutable anchors : anchor_info list;             (* Block-relay-only anchor connections *)
  (* Per-peer tracking for eviction *)
  peer_last_tx_time : (int, float) Hashtbl.t;     (* peer_id -> last tx received time *)
  peer_last_block_time : (int, float) Hashtbl.t;  (* peer_id -> last block received time *)
  peer_connected_time : (int, float) Hashtbl.t;   (* peer_id -> connection timestamp *)
  outbound_netgroups : (string, bool) Hashtbl.t;  (* Netgroups of outbound connections *)
  (* Stale peer eviction state *)
  stale_state : (int, stale_peer_state) Hashtbl.t;  (* peer_id -> stale tracking state *)
  mutable stale_check_running : bool;               (* Whether the 45s check timer is running *)
  (* Mempool for feefilter (BIP-133) *)
  mutable mempool : Mempool.mempool option;         (* Mempool for min_relay_fee *)
}

(* Generate a random bucket key for address hashing *)
let generate_bucket_key () : string =
  let buf = Bytes.create 32 in
  for i = 0 to 31 do
    Bytes.set buf i (Char.chr (Random.int 256))
  done;
  Bytes.to_string buf

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
    bucket_key = generate_bucket_key ();
    new_table = Hashtbl.create new_bucket_count;
    tried_table = Hashtbl.create tried_bucket_count;
    anchors = [];
    peer_last_tx_time = Hashtbl.create 64;
    peer_last_block_time = Hashtbl.create 64;
    peer_connected_time = Hashtbl.create 64;
    outbound_netgroups = Hashtbl.create 16;
    stale_state = Hashtbl.create 64;
    stale_check_running = false;
    mempool = None;
  }

(* Set the mempool reference for feefilter (BIP-133) *)
let set_mempool (pm : t) (mp : Mempool.mempool) : unit =
  pm.mempool <- Some mp

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

(* Compute bucket index for an address using SHA256.
   From Bitcoin Core: bucket = SHA256(key ^ addr)[0] *)
let compute_bucket (key : string) (addr : string) (bucket_count : int) : int =
  let input = key ^ addr in
  let hash = Digestif.SHA256.(to_raw_string (digest_string input)) in
  let first_byte = Char.code (String.get hash 0) in
  first_byte mod bucket_count

(* Compute keyed netgroup hash for eviction algorithm *)
let compute_keyed_netgroup (key : string) (addr : string) : int =
  let netgroup = netgroup_of addr in
  let input = key ^ netgroup in
  let hash = Digestif.SHA256.(to_raw_string (digest_string input)) in
  (* Use first 4 bytes as int *)
  (Char.code (String.get hash 0)) lor
  (Char.code (String.get hash 1) lsl 8) lor
  (Char.code (String.get hash 2) lsl 16) lor
  (Char.code (String.get hash 3) lsl 24)

(* Add address to new table bucket *)
let add_to_new_table (pm : t) (addr : string) : int =
  let bucket = compute_bucket pm.bucket_key addr new_bucket_count in
  let current = match Hashtbl.find_opt pm.new_table bucket with
    | Some addrs -> addrs
    | None -> []
  in
  (* Check if address already in bucket *)
  if List.mem addr current then
    bucket
  (* Check bucket capacity *)
  else if List.length current >= bucket_size then begin
    (* Bucket full - try to evict old entry *)
    match current with
    | [] -> bucket  (* Shouldn't happen *)
    | _ :: rest ->
      Hashtbl.replace pm.new_table bucket (addr :: rest);
      bucket
  end else begin
    Hashtbl.replace pm.new_table bucket (addr :: current);
    bucket
  end

(* Move address from new table to tried table (after successful connection) *)
let move_to_tried_table (pm : t) (addr : string) : int =
  let new_bucket = compute_bucket pm.bucket_key addr new_bucket_count in
  let tried_bucket = compute_bucket pm.bucket_key addr tried_bucket_count in
  (* Remove from new table *)
  (match Hashtbl.find_opt pm.new_table new_bucket with
   | Some addrs ->
     let filtered = List.filter (fun a -> a <> addr) addrs in
     if filtered = [] then
       Hashtbl.remove pm.new_table new_bucket
     else
       Hashtbl.replace pm.new_table new_bucket filtered
   | None -> ());
  (* Add to tried table *)
  let current = match Hashtbl.find_opt pm.tried_table tried_bucket with
    | Some addrs -> addrs
    | None -> []
  in
  if not (List.mem addr current) then begin
    if List.length current >= bucket_size then begin
      (* Bucket full - evict oldest entry *)
      match List.rev current with
      | [] -> ()
      | _ :: rest ->
        Hashtbl.replace pm.tried_table tried_bucket (addr :: List.rev rest)
    end else
      Hashtbl.replace pm.tried_table tried_bucket (addr :: current)
  end;
  tried_bucket

(* Check if address is in tried table *)
let is_in_tried_table (pm : t) (addr : string) : bool =
  let bucket = compute_bucket pm.bucket_key addr tried_bucket_count in
  match Hashtbl.find_opt pm.tried_table bucket with
  | Some addrs -> List.mem addr addrs
  | None -> false

(* Get total entries in new table *)
let new_table_size (pm : t) : int =
  Hashtbl.fold (fun _ addrs acc -> acc + List.length addrs) pm.new_table 0

(* Get total entries in tried table *)
let tried_table_size (pm : t) : int =
  Hashtbl.fold (fun _ addrs acc -> acc + List.length addrs) pm.tried_table 0

(* Record peer tx relay time for eviction algorithm *)
let record_peer_tx_time (pm : t) (peer_id : int) : unit =
  Hashtbl.replace pm.peer_last_tx_time peer_id (Unix.gettimeofday ())

(* Record peer block relay time for eviction algorithm *)
let record_peer_block_time (pm : t) (peer_id : int) : unit =
  Hashtbl.replace pm.peer_last_block_time peer_id (Unix.gettimeofday ())

(* Build eviction candidates from inbound peers.
   This matches Bitcoin Core's SelectNodeToEvict algorithm. *)
let build_eviction_candidates (pm : t) : eviction_candidate list =
  let now = Unix.gettimeofday () in
  List.filter_map (fun p ->
    if p.Peer.direction <> Peer.Inbound || p.Peer.state <> Peer.Ready then
      None
    else
      let connected = match Hashtbl.find_opt pm.peer_connected_time p.Peer.id with
        | Some t -> t
        | None -> now
      in
      let last_tx = match Hashtbl.find_opt pm.peer_last_tx_time p.Peer.id with
        | Some t -> t
        | None -> 0.0
      in
      let last_block = match Hashtbl.find_opt pm.peer_last_block_time p.Peer.id with
        | Some t -> t
        | None -> 0.0
      in
      Some {
        ec_peer = p;
        ec_connected = connected;
        ec_min_ping = p.Peer.latency;
        ec_last_block_time = last_block;
        ec_last_tx_time = last_tx;
        ec_keyed_netgroup = compute_keyed_netgroup pm.bucket_key p.Peer.addr;
        ec_relay_txs = true;  (* Assume all relay txs for now *)
        ec_prefer_evict = false;
      }
  ) pm.peers

(* Remove last k elements from sorted list that satisfy predicate.
   Works by reversing the list, removing the first k matches, then reversing back. *)
let erase_last_k_elements (lst : eviction_candidate list)
    (k : int) (pred : eviction_candidate -> bool) : eviction_candidate list =
  let erased = ref 0 in
  let rev = List.rev lst in
  let filtered = List.filter (fun c ->
    if !erased < k && pred c then begin
      incr erased;
      false
    end else
      true
  ) rev in
  List.rev filtered

(* Multi-criteria eviction algorithm matching Bitcoin Core.
   From Bitcoin Core eviction.cpp SelectNodeToEvict:
   1. Protect 4 peers by distinct netgroup
   2. Protect 8 peers by lowest ping
   3. Protect 4 peers by most recent tx relay
   4. Protect up to 8 non-tx-relay peers by most recent block relay
   5. Protect 4 peers by most recent block relay
   6. Protect half of remaining by longest connection time
   7. From remaining, evict peer from largest same-network group *)
let select_node_to_evict (pm : t) : Peer.peer option =
  let candidates = build_eviction_candidates pm in
  if List.length candidates = 0 then None
  else begin
    let candidates = ref candidates in
    (* 1. Protect 4 peers by distinct netgroup (deterministic by keyed hash) *)
    let sorted_by_netgroup = List.sort (fun a b ->
      compare a.ec_keyed_netgroup b.ec_keyed_netgroup
    ) !candidates in
    candidates := erase_last_k_elements sorted_by_netgroup protect_by_netgroup
      (fun _ -> true);
    (* 2. Protect 8 peers by lowest ping *)
    let sorted_by_ping = List.sort (fun a b ->
      compare b.ec_min_ping a.ec_min_ping  (* Reverse: lowest at end *)
    ) !candidates in
    candidates := erase_last_k_elements sorted_by_ping protect_by_ping
      (fun _ -> true);
    (* 3. Protect 4 peers by most recent tx relay *)
    let sorted_by_tx = List.sort (fun a b ->
      compare a.ec_last_tx_time b.ec_last_tx_time  (* Most recent at end *)
    ) !candidates in
    candidates := erase_last_k_elements sorted_by_tx protect_by_tx_time
      (fun _ -> true);
    (* 4. Protect up to 8 non-tx-relay peers by most recent block relay *)
    let sorted_by_block_relay = List.sort (fun a b ->
      compare a.ec_last_block_time b.ec_last_block_time
    ) !candidates in
    candidates := erase_last_k_elements sorted_by_block_relay protect_by_block_relay
      (fun c -> not c.ec_relay_txs);
    (* 5. Protect 4 peers by most recent block relay *)
    let sorted_by_block = List.sort (fun a b ->
      compare a.ec_last_block_time b.ec_last_block_time
    ) !candidates in
    candidates := erase_last_k_elements sorted_by_block protect_by_block_time
      (fun _ -> true);
    (* 6. Protect half of remaining by longest connection time *)
    let half_to_protect = List.length !candidates / 2 in
    let sorted_by_connected = List.sort (fun a b ->
      compare b.ec_connected a.ec_connected  (* Oldest at end *)
    ) !candidates in
    candidates := erase_last_k_elements sorted_by_connected half_to_protect
      (fun _ -> true);
    (* 7. If any remain with prefer_evict, filter to only those *)
    if List.exists (fun c -> c.ec_prefer_evict) !candidates then
      candidates := List.filter (fun c -> c.ec_prefer_evict) !candidates;
    (* 8. Group by netgroup and find largest group *)
    if !candidates = [] then None
    else begin
      let netgroup_map = Hashtbl.create 16 in
      List.iter (fun c ->
        let ng = c.ec_keyed_netgroup in
        let current = match Hashtbl.find_opt netgroup_map ng with
          | Some lst -> lst
          | None -> []
        in
        Hashtbl.replace netgroup_map ng (c :: current)
      ) !candidates;
      (* Find netgroup with most connections and youngest member *)
      let largest_group = ref [] in
      let largest_size = ref 0 in
      let youngest_in_largest = ref max_float in
      Hashtbl.iter (fun _ group ->
        let size = List.length group in
        let youngest = List.fold_left (fun acc c ->
          min acc c.ec_connected
        ) max_float group in
        if size > !largest_size || (size = !largest_size && youngest > !youngest_in_largest) then begin
          largest_size := size;
          largest_group := group;
          youngest_in_largest := youngest
        end
      ) netgroup_map;
      (* Evict the youngest (most recently connected) in largest group *)
      match List.sort (fun a b -> compare b.ec_connected a.ec_connected) !largest_group with
      | c :: _ -> Some c.ec_peer
      | [] -> None
    end
  end

(* Evict one low-quality inbound peer to make room for a new connection.
   Uses multi-criteria algorithm matching Bitcoin Core:
   - Protect peers by netgroup diversity (4)
   - Protect by lowest ping (8)
   - Protect by recent tx relay (4)
   - Protect by recent block relay (8 block-relay-only + 4 general)
   - Protect by longest connection (half of remaining)
   - Evict from largest same-netgroup cluster *)
let evict_inbound_peer (pm : t) : unit Lwt.t =
  let open Lwt.Syntax in
  let inbound_count = List.length (List.filter (fun p ->
    p.Peer.direction = Peer.Inbound && p.Peer.state = Peer.Ready
  ) pm.peers) in
  if inbound_count <= 8 then
    (* Not enough inbound peers to justify eviction *)
    Lwt.return_unit
  else
    match select_node_to_evict pm with
    | None -> Lwt.return_unit
    | Some victim ->
      Log.info (fun m -> m "Evicting inbound peer %d (%s) via multi-criteria algorithm"
        victim.Peer.id victim.Peer.addr);
      let* () = Peer.disconnect victim in
      pm.peers <- List.filter (fun p -> p.Peer.id <> victim.Peer.id) pm.peers;
      Hashtbl.remove pm.peer_last_tx_time victim.Peer.id;
      Hashtbl.remove pm.peer_last_block_time victim.Peer.id;
      Hashtbl.remove pm.peer_connected_time victim.Peer.id;
      Lwt.return_unit

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
                 last_success = 0.0;
                 failures = 0;
                 banned_until = 0.0;
                 source = Dns;
                 table_status = NotInTable }
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
      last_success = 0.0;
      failures = 0;
      banned_until = 0.0;
      source = Manual;
      table_status = NotInTable }
  ) peers

(* Add a peer address to known addresses with bucketing *)
let add_known_addr (pm : t) (info : peer_info) : unit =
  if not (Hashtbl.mem pm.known_addrs info.address) then begin
    (* Add to new table bucket *)
    let bucket = add_to_new_table pm info.address in
    let info_with_bucket = { info with table_status = InNew bucket } in
    Hashtbl.replace pm.known_addrs info.address info_with_bucket
  end

(* Check if connecting to this address would violate outbound netgroup diversity *)
let would_violate_netgroup_diversity (pm : t) (addr : string) : bool =
  let netgroup = netgroup_of addr in
  Hashtbl.mem pm.outbound_netgroups netgroup

(* Connect to a peer and add to active peers.
   Enforces outbound netgroup diversity for eclipse protection. *)
let add_peer (pm : t) (addr : string) (port : int) : unit Lwt.t =
  let open Lwt.Syntax in
  let now = Unix.gettimeofday () in
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
  (* Eclipse protection: enforce /16 netgroup diversity for outbound *)
  else if would_violate_netgroup_diversity pm addr then begin
    Log.debug (fun m -> m "Skipping %s: netgroup %s already connected"
      addr (netgroup_of addr));
    Lwt.return_unit
  end
  else begin
    let id = pm.next_peer_id in
    pm.next_peer_id <- pm.next_peer_id + 1;
    (* Update last_attempt *)
    (match Hashtbl.find_opt pm.known_addrs addr with
     | Some info ->
       Hashtbl.replace pm.known_addrs addr
         { info with last_attempt = now }
     | None -> ());
    Lwt.catch (fun () ->
      let* peer = Peer.connect ~network:pm.network ~addr ~port ~id in
      let* () = Peer.perform_handshake peer pm.our_height in
      pm.peers <- peer :: pm.peers;
      (* Track connection time for eviction algorithm *)
      Hashtbl.replace pm.peer_connected_time peer.Peer.id now;
      (* Initialize stale peer tracking *)
      Hashtbl.replace pm.stale_state peer.Peer.id (create_stale_state ());
      (* Track outbound netgroup for diversity *)
      Hashtbl.replace pm.outbound_netgroups (netgroup_of addr) true;
      (* Start inventory trickling for this peer *)
      Lwt.async (fun () -> Peer.start_trickling peer);
      (* Move address to tried table (successful connection) *)
      let tried_bucket = move_to_tried_table pm addr in
      (* Update known_addrs with successful connection *)
      (match Hashtbl.find_opt pm.known_addrs addr with
       | Some info ->
         Hashtbl.replace pm.known_addrs addr
           { info with
             last_connected = now;
             last_success = now;
             failures = 0;
             table_status = InTried tried_bucket }
       | None ->
         Hashtbl.replace pm.known_addrs addr
           { address = addr;
             port;
             services = Peer.services_to_int64 peer.services;
             last_connected = now;
             last_attempt = now;
             last_success = now;
             failures = 0;
             banned_until = 0.0;
             source = Manual;
             table_status = InTried tried_bucket });
      Lwt.return_unit
    ) (fun _exn ->
      (* Connection failed, record failure *)
      (match Hashtbl.find_opt pm.known_addrs addr with
       | Some info ->
         Hashtbl.replace pm.known_addrs addr
           { info with
             failures = info.failures + 1;
             last_attempt = now }
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
    (* Clean up eviction tracking *)
    Hashtbl.remove pm.peer_last_tx_time peer_id;
    Hashtbl.remove pm.peer_last_block_time peer_id;
    Hashtbl.remove pm.peer_connected_time peer_id;
    (* Clean up stale peer tracking *)
    Hashtbl.remove pm.stale_state peer_id;
    (* Remove from outbound netgroup tracking if outbound peer *)
    if peer.Peer.direction = Peer.Outbound then
      Hashtbl.remove pm.outbound_netgroups (netgroup_of peer.Peer.addr);
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
        last_success = 0.0;
        failures = 0;
        banned_until = Unix.gettimeofday () +. duration;
        source = Addr;
        table_status = NotInTable };
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
        last_success = 0.0;
        failures = 0;
        banned_until = Unix.gettimeofday () +. duration;
        source = Addr;
        table_status = NotInTable }

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

(* ========== Stale peer eviction functions ========== *)
(* Reference: Bitcoin Core net_processing.cpp ConsiderEviction() *)

(** Get or create stale state for a peer *)
let get_stale_state (pm : t) (peer_id : int) : stale_peer_state =
  match Hashtbl.find_opt pm.stale_state peer_id with
  | Some state -> state
  | None ->
    let state = create_stale_state () in
    Hashtbl.replace pm.stale_state peer_id state;
    state

(** Called when we receive headers from a peer *)
let on_headers_received (pm : t) (peer_id : int) ~(new_best_height : int32) : unit =
  let state = get_stale_state pm peer_id in
  let now = Unix.gettimeofday () in
  state.last_header_time <- now;
  (* Reset chain sync state on successful header receipt *)
  state.chain_sync <- ChainSynced;
  (* Update peer's best height if higher *)
  match List.find_opt (fun p -> p.Peer.id = peer_id) pm.peers with
  | Some peer ->
    if new_best_height > peer.Peer.best_height then
      peer.best_height <- new_best_height
  | None -> ()

(** Called when we receive a block from a peer *)
let on_block_received (pm : t) (peer_id : int) : unit =
  let state = get_stale_state pm peer_id in
  let now = Unix.gettimeofday () in
  state.block_stall.blocks_in_flight <- max 0 (state.block_stall.blocks_in_flight - 1);
  state.block_stall.stalling_since <- None;
  state.block_stall.last_block_time <- now;
  (* Also update the eviction tracking *)
  Hashtbl.replace pm.peer_last_block_time peer_id now

(** Assign blocks to download from a peer *)
let assign_blocks_to_peer (pm : t) (peer_id : int) ~(count : int) : unit =
  let state = get_stale_state pm peer_id in
  state.block_stall.blocks_in_flight <- state.block_stall.blocks_in_flight + count

(** Called when we send a ping to a peer *)
let on_ping_sent (pm : t) (peer_id : int) ~(nonce : int64) : unit =
  let state = get_stale_state pm peer_id in
  state.last_ping_nonce <- Some nonce;
  state.last_ping_sent <- Unix.gettimeofday ()

(** Called when we receive a pong from a peer. Returns true if nonce matched. *)
let on_pong_received (pm : t) (peer_id : int) ~(nonce : int64) : bool =
  let state = get_stale_state pm peer_id in
  match state.last_ping_nonce with
  | Some expected when expected = nonce ->
    state.last_ping_nonce <- None;
    state.last_pong_received <- Unix.gettimeofday ();
    true
  | _ -> false

(** Check headers timeout for a single peer. Returns Some reason if should disconnect. *)
let check_headers_timeout (pm : t) (peer : Peer.peer) ~(now : float) : string option =
  let state = get_stale_state pm peer.Peer.id in
  let our_height = Int32.to_int pm.our_height in
  let peer_height = Int32.to_int peer.Peer.best_height in

  (* Only check outbound peers that are behind our tip *)
  if peer.Peer.direction <> Peer.Outbound then
    None
  else if peer_height >= our_height then begin
    (* Peer is caught up, reset chain sync state *)
    state.chain_sync <- ChainSynced;
    None
  end else begin
    let time_since_header = now -. state.last_header_time in
    match state.chain_sync with
    | ChainSynced ->
      if time_since_header > Stale.headers_timeout then begin
        (* Start challenge: set 2-minute timeout for getheaders response *)
        state.chain_sync <- ChainWaitingForHeaders {
          timeout = now +. Stale.headers_response_time;
          sent_getheaders = true;
        };
        None  (* Will send getheaders, don't disconnect yet *)
      end else
        None
    | ChainWaitingForHeaders { timeout; _ } ->
      if now > timeout then
        (* Challenge timeout expired, disconnect *)
        Some StaleReason.headers_timeout
      else
        None
  end

(** Check if we need to send getheaders challenge to a peer *)
let needs_getheaders_challenge (pm : t) (peer_id : int) : bool =
  match Hashtbl.find_opt pm.stale_state peer_id with
  | Some state ->
    (match state.chain_sync with
     | ChainWaitingForHeaders { sent_getheaders = true; _ } -> true
     | _ -> false)
  | None -> false

(** Mark that getheaders was sent (called after sending) *)
let mark_getheaders_sent (pm : t) (peer_id : int) : unit =
  match Hashtbl.find_opt pm.stale_state peer_id with
  | Some state ->
    (match state.chain_sync with
     | ChainWaitingForHeaders s ->
       state.chain_sync <- ChainWaitingForHeaders { s with sent_getheaders = false }
     | _ -> ())
  | None -> ()

(** Check block stalling for a single peer. Returns Some reason if should disconnect. *)
let check_block_stalling (pm : t) (peer : Peer.peer) ~(now : float) : string option =
  let state = get_stale_state pm peer.Peer.id in
  let stall = state.block_stall in

  if stall.blocks_in_flight = 0 then begin
    (* No blocks in flight, clear stalling state *)
    stall.stalling_since <- None;
    None
  end else begin
    (* Calculate expected timeout based on blocks in flight *)
    let expected_time =
      float_of_int stall.blocks_in_flight *. Stale.block_stalling_timeout
    in
    let timeout = max expected_time Stale.block_stalling_timeout in
    let time_since_block = now -. stall.last_block_time in

    match stall.stalling_since with
    | None ->
      (* Check if we should start stalling timer *)
      if time_since_block > timeout then begin
        stall.stalling_since <- Some now;
        None  (* Just started stalling, don't disconnect yet *)
      end else
        None
    | Some stall_start ->
      let stall_duration = now -. stall_start in
      if stall_duration > Stale.block_stalling_max then
        (* Stalled too long, disconnect *)
        Some StaleReason.block_stalling
      else
        None
  end

(** Check ping timeout for a single peer. Returns Some reason if should disconnect. *)
let check_ping_timeout (pm : t) (peer_id : int) ~(now : float) : string option =
  let state = get_stale_state pm peer_id in
  match state.last_ping_nonce with
  | None -> None  (* No ping outstanding *)
  | Some _ ->
    let time_since_ping = now -. state.last_ping_sent in
    if time_since_ping > Stale.ping_timeout then
      Some StaleReason.ping_timeout
    else
      None

(** Get list of peers that are stalling block downloads (for reassignment) *)
let get_stalling_peers (pm : t) : Peer.peer list =
  let now = Unix.gettimeofday () in
  List.filter (fun peer ->
    match Hashtbl.find_opt pm.stale_state peer.Peer.id with
    | Some state ->
      (match state.block_stall.stalling_since with
       | Some stall_start ->
         let stall_duration = now -. stall_start in
         (* Stalling but not yet at max timeout *)
         stall_duration > Stale.block_stalling_timeout &&
         stall_duration < Stale.block_stalling_max
       | None -> false)
    | None -> false
  ) pm.peers

(** Get peers available for block download (not stalling) *)
let get_available_download_peers (pm : t) : Peer.peer list =
  List.filter (fun peer ->
    peer.Peer.state = Peer.Ready &&
    (match Hashtbl.find_opt pm.stale_state peer.Peer.id with
     | Some state -> state.block_stall.stalling_since = None
     | None -> true)
  ) pm.peers

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

(* Announce a new transaction to all connected peers via inv.
   Uses inventory trickling: transactions are queued per-peer and sent
   on a Poisson-distributed schedule (5s average for inbound, 2s for outbound).
   This improves privacy and reduces bandwidth. *)
let announce_tx (pm : t) ~(txid : Types.hash256) ~(wtxid : Types.hash256)
    ~(fee_rate : int64) : unit Lwt.t =
  let ready = get_ready_peers pm in
  List.iter (fun peer ->
    (* Skip peers whose feefilter is above this tx's fee rate *)
    if not (peer.Peer.feefilter > 0L && fee_rate < peer.Peer.feefilter) then begin
      let entry : Peer.inv_entry =
        if peer.Peer.wtxid_relay then
          { inv_type = P2p.InvWitnessTx; hash = wtxid }
        else
          { inv_type = P2p.InvTx; hash = txid }
      in
      Peer.queue_inv peer entry
    end
  ) ready;
  Lwt.return_unit

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
        (* Add to new table bucket *)
        let bucket = add_to_new_table pm ip_str in
        Hashtbl.replace pm.known_addrs ip_str
          { address = ip_str;
            port = addr.port;
            services = addr.services;
            last_connected = 0.0;
            last_attempt = 0.0;
            last_success = 0.0;
            failures = 0;
            banned_until = 0.0;
            source = Addr;
            table_status = InNew bucket };
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

(** Check all peers for staleness and disconnect stale ones.
    Returns list of (peer_id, reason) for peers that were disconnected. *)
let check_stale_peers (pm : t) : (int * string) list Lwt.t =
  let open Lwt.Syntax in
  let now = Unix.gettimeofday () in
  let disconnected = ref [] in

  (* Check each peer for staleness *)
  let* () = Lwt_list.iter_s (fun peer ->
    if peer.Peer.state <> Peer.Ready then
      Lwt.return_unit
    else begin
      let disconnect_reason = ref None in

      (* Check headers timeout (outbound only) *)
      (match check_headers_timeout pm peer ~now with
       | Some reason -> disconnect_reason := Some reason
       | None -> ());

      (* Check block stalling *)
      if !disconnect_reason = None then
        (match check_block_stalling pm peer ~now with
         | Some reason -> disconnect_reason := Some reason
         | None -> ());

      (* Check ping timeout *)
      if !disconnect_reason = None then
        (match check_ping_timeout pm peer.Peer.id ~now with
         | Some reason -> disconnect_reason := Some reason
         | None -> ());

      (* Disconnect if stale *)
      match !disconnect_reason with
      | Some reason ->
        Log.info (fun m -> m "Evicting stale peer %d (%s): %s"
          peer.Peer.id peer.Peer.addr reason);
        disconnected := (peer.Peer.id, reason) :: !disconnected;
        remove_peer pm peer.Peer.id
      | None ->
        (* Send getheaders challenge if needed *)
        if needs_getheaders_challenge pm peer.Peer.id then begin
          let getheaders = P2p.GetheadersMsg {
            version = 70016l;
            locator_hashes = (match pm.db with
              | Some db -> build_locator db (Int32.to_int pm.our_height)
              | None -> []);
            hash_stop = Types.zero_hash;
          } in
          let* () = Lwt.catch
            (fun () -> Peer.send_message peer getheaders)
            (fun _exn -> Lwt.return_unit) in
          mark_getheaders_sent pm peer.Peer.id;
          Lwt.return_unit
        end else
          Lwt.return_unit
    end
  ) pm.peers in

  Lwt.return !disconnected

(** Start the periodic stale peer check timer (every 45 seconds) *)
let start_stale_check_timer (pm : t) : unit =
  if pm.stale_check_running then ()
  else begin
    pm.stale_check_running <- true;
    let rec loop () =
      if not pm.running || not pm.stale_check_running then
        Lwt.return_unit
      else begin
        let open Lwt.Syntax in
        let* () = Lwt_unix.sleep Stale.stale_check_interval in
        let* _disconnected = check_stale_peers pm in
        loop ()
      end
    in
    Lwt.async loop
  end

(** Stop the periodic stale peer check timer *)
let stop_stale_check_timer (pm : t) : unit =
  pm.stale_check_running <- false

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
          (* Timeout - perform periodic maintenance *)
          (* Check if we should send feefilter (BIP-133) *)
          let* () =
            if Peer.should_send_feefilter peer then
              let min_fee = match pm.mempool with
                | Some mp -> mp.Mempool.min_relay_fee
                | None -> 1000L (* default 1 sat/vB *)
              in
              let* _sent = Peer.maybe_send_feefilter peer min_fee in
              Lwt.return_unit
            else
              Lwt.return_unit
          in
          (* Check if peer needs ping *)
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
    let now = Unix.gettimeofday () in
    Lwt.catch (fun () ->
      let peer = Peer.make_peer ~network:pm.network ~addr:addr_str ~port
        ~id ~direction:Peer.Inbound ~fd:client_fd in
      let* () = Peer.perform_inbound_handshake peer pm.our_height in
      pm.peers <- peer :: pm.peers;
      (* Track connection time for eviction algorithm *)
      Hashtbl.replace pm.peer_connected_time peer.Peer.id now;
      (* Initialize stale peer tracking *)
      Hashtbl.replace pm.stale_state peer.Peer.id (create_stale_state ());
      (* Start inventory trickling for this peer *)
      Lwt.async (fun () -> Peer.start_trickling peer);
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
  (* Start the 45-second stale peer check timer *)
  start_stale_check_timer pm;
  (* Return immediately, maintenance runs in background *)
  Lwt.async (fun () -> maintenance);
  Lwt.return_unit

(* Stop the peer manager *)
let stop (pm : t) : unit Lwt.t =
  let open Lwt.Syntax in
  pm.running <- false;
  (* Stop the stale peer check timer *)
  stop_stale_check_timer pm;
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
               last_success = 0.0;
               failures = 0;
               banned_until;
               source = Addr;
               table_status = NotInTable });
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
                       last_success = 0.0;
                       failures = 0;
                       banned_until = bu;
                       source = Addr;
                       table_status = NotInTable });
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

(* ========== Anchor connections for eclipse attack protection ========== *)

(* Anchor connections are block-relay-only outbound connections that persist
   across restarts. They help prevent eclipse attacks by ensuring we maintain
   connections to peers we've successfully connected to before.
   See Bitcoin Core: MAX_BLOCK_RELAY_ONLY_ANCHORS = 2 *)

(* Save anchor connections to anchors.dat *)
let save_anchors (pm : t) (datadir : string) : unit =
  let filepath = Filename.concat datadir "anchors.dat" in
  (* Select up to max_block_relay_only_anchors outbound peers that are ready *)
  let outbound_ready = List.filter (fun p ->
    p.Peer.direction = Peer.Outbound && p.Peer.state = Peer.Ready
  ) pm.peers in
  let anchors = List.filteri (fun i _ ->
    i < pm.config.max_block_relay_only_anchors
  ) outbound_ready in
  let anchor_infos = List.map (fun p ->
    { anchor_addr = p.Peer.addr;
      anchor_port = p.Peer.port;
      anchor_services = Peer.services_to_int64 p.Peer.services }
  ) anchors in
  pm.anchors <- anchor_infos;
  (* Serialize to JSON *)
  let json = `List (List.map (fun a ->
    `Assoc [
      ("addr", `String a.anchor_addr);
      ("port", `Int a.anchor_port);
      ("services", `String (Int64.to_string a.anchor_services))
    ]
  ) anchor_infos) in
  try
    let oc = open_out filepath in
    output_string oc (Yojson.Safe.pretty_to_string json);
    close_out oc;
    Log.info (fun m -> m "Saved %d anchor connections to %s"
      (List.length anchor_infos) filepath)
  with exn ->
    Log.warn (fun m -> m "Failed to save anchors: %s" (Printexc.to_string exn))

(* Load anchor connections from anchors.dat *)
let load_anchors (pm : t) (datadir : string) : int =
  let filepath = Filename.concat datadir "anchors.dat" in
  if not (Sys.file_exists filepath) then
    0
  else begin
    try
      let ic = open_in filepath in
      let content = really_input_string ic (in_channel_length ic) in
      close_in ic;
      let json = Yojson.Safe.from_string content in
      let anchors = match json with
        | `List entries ->
          List.filter_map (fun entry ->
            match entry with
            | `Assoc fields ->
              let addr = match List.assoc_opt "addr" fields with
                | Some (`String a) -> Some a
                | _ -> None
              in
              let port = match List.assoc_opt "port" fields with
                | Some (`Int p) -> Some p
                | _ -> None
              in
              let services = match List.assoc_opt "services" fields with
                | Some (`String s) -> (try Some (Int64.of_string s) with _ -> Some 0L)
                | Some (`Int i) -> Some (Int64.of_int i)
                | _ -> Some 0L
              in
              (match addr, port, services with
               | Some a, Some p, Some s ->
                 Some { anchor_addr = a; anchor_port = p; anchor_services = s }
               | _ -> None)
            | _ -> None
          ) entries
        | _ -> []
      in
      pm.anchors <- anchors;
      Log.info (fun m -> m "Loaded %d anchor connections from %s"
        (List.length anchors) filepath);
      (* Delete the file after loading (anchors are one-time use) *)
      (try Unix.unlink filepath with _ -> ());
      List.length anchors
    with exn ->
      Log.warn (fun m -> m "Failed to load anchors: %s" (Printexc.to_string exn));
      0
  end

(* Get anchor connections to try on startup *)
let get_anchors (pm : t) : anchor_info list =
  pm.anchors

(* Clear anchors after connecting *)
let clear_anchors (pm : t) : unit =
  pm.anchors <- []

(* Connect to anchor peers (called on startup before DNS resolution) *)
let connect_to_anchors (pm : t) : unit Lwt.t =
  let open Lwt.Syntax in
  let anchors = pm.anchors in
  if anchors = [] then
    Lwt.return_unit
  else begin
    Log.info (fun m -> m "Connecting to %d anchor peers" (List.length anchors));
    let* () = Lwt_list.iter_s (fun anchor ->
      add_peer pm anchor.anchor_addr anchor.anchor_port
    ) anchors in
    clear_anchors pm;
    Lwt.return_unit
  end

(* ========== Eclipse protection statistics ========== *)

(* Statistics about address bucket tables *)
type bucket_stats = {
  new_table_entries : int;
  new_table_buckets_used : int;
  tried_table_entries : int;
  tried_table_buckets_used : int;
  outbound_netgroups : int;
  anchor_count : int;
}

let get_bucket_stats (pm : t) : bucket_stats =
  { new_table_entries = new_table_size pm;
    new_table_buckets_used = Hashtbl.length pm.new_table;
    tried_table_entries = tried_table_size pm;
    tried_table_buckets_used = Hashtbl.length pm.tried_table;
    outbound_netgroups = Hashtbl.length pm.outbound_netgroups;
    anchor_count = List.length pm.anchors;
  }

(* Periodic address gossip: relay known addresses to connected peers.
   Selects up to 1000 addresses from the tried table and sends them
   to each peer that has completed the handshake. Called periodically. *)
let gossip_addresses (pm : t) : unit Lwt.t =
  let now = Int32.of_float (Unix.gettimeofday ()) in
  let addrs = Hashtbl.fold (fun _k info acc ->
    if List.length acc >= 1000 then acc
    else begin
      let addr_bytes = Cstruct.create 16 in
      (* Encode IPv4 as IPv4-mapped IPv6 *)
      let parts = String.split_on_char '.' info.address in
      if List.length parts = 4 then begin
        for i = 0 to 9 do Cstruct.set_uint8 addr_bytes i 0 done;
        Cstruct.set_uint8 addr_bytes 10 0xFF;
        Cstruct.set_uint8 addr_bytes 11 0xFF;
        List.iteri (fun i s ->
          try Cstruct.set_uint8 addr_bytes (12 + i) (int_of_string s)
          with _ -> ()
        ) parts;
        let net_addr : Types.net_addr = {
          services = 1L;
          addr = addr_bytes;
          port = info.port;
        } in
        (now, net_addr) :: acc
      end else acc
    end
  ) pm.known_addrs [] in
  if addrs = [] then Lwt.return_unit
  else begin
    let msg = P2p.AddrMsg addrs in
    Lwt_list.iter_p (fun peer ->
      if peer.Peer.state = Peer.Connected then
        Lwt.catch
          (fun () -> Peer.send_message peer msg)
          (fun _exn -> Lwt.return_unit)
      else Lwt.return_unit
    ) pm.peers
  end
