(* Header-first synchronization (BIP-130) *)
(* Downloads all block headers before downloading full blocks,
   verifying the proof-of-work chain and building the header chain. *)

(* Sync state machine *)
type sync_state =
  | Idle
  | SyncingHeaders
  | SyncingBlocks
  | FullySynced

let sync_state_to_string = function
  | Idle -> "idle"
  | SyncingHeaders -> "syncing_headers"
  | SyncingBlocks -> "syncing_blocks"
  | FullySynced -> "fully_synced"

(* Header entry in the chain - tracks header with metadata *)
type header_entry = {
  header : Types.block_header;
  hash : Types.hash256;
  height : int;
  total_work : float;  (* cumulative proof-of-work *)
}

(* Chain state - tracks sync progress and header chain *)
type chain_state = {
  db : Storage.ChainDB.t;
  network : Consensus.network_config;
  mutable headers : (string, header_entry) Hashtbl.t;
  mutable tip : header_entry option;
  mutable sync_state : sync_state;
  mutable sync_peer : int option;
  mutable headers_synced : int;
  mutable blocks_synced : int;
}

(* Compute proof-of-work from compact target (nBits).
   Work = 2^256 / target. Higher work = more difficult. *)
let work_from_bits (bits : int32) : float =
  let target = Consensus.compact_to_target bits in
  let target_f = ref 0.0 in
  for i = 0 to 31 do
    target_f := !target_f +.
      (float_of_int (Cstruct.get_uint8 target i)) *.
      (2.0 ** (float_of_int (8 * (31 - i))))
  done;
  if !target_f = 0.0 then 0.0
  else (2.0 ** 256.0) /. !target_f

(* Create initial chain state with genesis block *)
let create_chain_state (db : Storage.ChainDB.t)
    (network : Consensus.network_config) : chain_state =
  let state = {
    db; network;
    headers = Hashtbl.create 100_000;
    tip = None;
    sync_state = Idle;
    sync_peer = None;
    headers_synced = 0;
    blocks_synced = 0;
  } in
  (* Insert genesis block header *)
  let genesis_hash = Crypto.compute_block_hash network.genesis_header in
  let genesis_entry = {
    header = network.genesis_header;
    hash = genesis_hash;
    height = 0;
    total_work = work_from_bits network.genesis_header.bits;
  } in
  Hashtbl.replace state.headers (Cstruct.to_string genesis_hash) genesis_entry;
  state.tip <- Some genesis_entry;
  (* Store genesis in DB if not already present *)
  if not (Storage.ChainDB.has_block_header state.db genesis_hash) then begin
    Storage.ChainDB.store_block_header state.db genesis_hash network.genesis_header;
    Storage.ChainDB.set_height_hash state.db 0 genesis_hash;
    Storage.ChainDB.set_header_tip state.db genesis_hash 0
  end;
  state

(* Restore chain state from database *)
let restore_chain_state (db : Storage.ChainDB.t)
    (network : Consensus.network_config) : chain_state =
  let state = {
    db; network;
    headers = Hashtbl.create 100_000;
    tip = None;
    sync_state = Idle;
    sync_peer = None;
    headers_synced = 0;
    blocks_synced = 0;
  } in
  (* Check for stored header tip *)
  match Storage.ChainDB.get_header_tip db with
  | Some (_tip_hash, tip_height) ->
    (* Load headers from genesis up to tip into memory *)
    for h = 0 to tip_height do
      match Storage.ChainDB.get_hash_at_height db h with
      | Some hash ->
        (match Storage.ChainDB.get_block_header db hash with
         | Some header ->
           let parent_work = if h = 0 then 0.0 else
             match Hashtbl.find_opt state.headers
                 (Cstruct.to_string header.prev_block) with
             | Some parent -> parent.total_work
             | None -> 0.0
           in
           let entry = {
             header; hash; height = h;
             total_work = parent_work +. work_from_bits header.bits;
           } in
           Hashtbl.replace state.headers (Cstruct.to_string hash) entry;
           if h = tip_height then state.tip <- Some entry
         | None -> ())
      | None -> ()
    done;
    state.headers_synced <- tip_height;
    state
  | None ->
    (* No stored state, create fresh with genesis *)
    create_chain_state db network

(* Validate a header against the current chain state.
   Checks: not duplicate, parent exists, proof-of-work valid, timestamp reasonable *)
let validate_header (state : chain_state) (header : Types.block_header)
    : (header_entry, string) result =
  let hash = Crypto.compute_block_hash header in
  let hash_key = Cstruct.to_string hash in
  (* Check if already known *)
  if Hashtbl.mem state.headers hash_key then
    Error "Header already known"
  else begin
    (* Find parent *)
    let parent_key = Cstruct.to_string header.prev_block in
    match Hashtbl.find_opt state.headers parent_key with
    | None -> Error "Unknown parent header"
    | Some parent ->
      (* Check proof of work *)
      if not (Consensus.hash_meets_target hash header.bits) then
        Error "Insufficient proof of work"
      (* Check timestamp not too far in future (2 hours) *)
      else if Int32.to_float header.timestamp > Unix.gettimeofday () +. 7200.0 then
        Error "Header timestamp too far in future"
      (* Check timestamp greater than median of last 11 blocks (simplified check) *)
      else if Int32.compare header.timestamp parent.header.timestamp < 0 &&
              parent.height > 0 then
        (* Allow same timestamp but not earlier than parent as a basic check *)
        Error "Header timestamp before parent"
      else begin
        let height = parent.height + 1 in
        let work = parent.total_work +. work_from_bits header.bits in
        Ok { header; hash; height; total_work = work }
      end
  end

(* Accept a validated header into the chain state *)
let accept_header (state : chain_state) (entry : header_entry) : unit =
  let hash_key = Cstruct.to_string entry.hash in
  Hashtbl.replace state.headers hash_key entry;
  (* Store to disk *)
  Storage.ChainDB.store_block_header state.db entry.hash entry.header;
  Storage.ChainDB.set_height_hash state.db entry.height entry.hash;
  (* Update tip if this has more cumulative work *)
  let is_new_tip = match state.tip with
    | None -> true
    | Some tip -> entry.total_work > tip.total_work
  in
  if is_new_tip then begin
    state.tip <- Some entry;
    Storage.ChainDB.set_header_tip state.db entry.hash entry.height;
    state.headers_synced <- entry.height
  end

(* Process a list of headers from the network.
   Returns Ok(accepted_count) or Error(reason) if validation fails *)
let process_headers (state : chain_state)
    (headers : Types.block_header list) : (int, string) result =
  let accepted = ref 0 in
  let error = ref None in
  List.iter (fun header ->
    if !error = None then
      match validate_header state header with
      | Ok entry ->
        accept_header state entry;
        incr accepted
      | Error "Header already known" ->
        ()  (* Skip duplicates silently *)
      | Error e ->
        error := Some e
  ) headers;
  match !error with
  | Some e when !accepted = 0 -> Error e
  | _ -> Ok !accepted

(* Build a block locator for getheaders request.
   Returns exponentially spaced block hashes from tip back to genesis. *)
let build_locator (state : chain_state) : Types.hash256 list =
  let tip_height = match state.tip with
    | Some t -> t.height
    | None -> 0
  in
  let rec collect acc step height =
    if height < 0 then
      (* Always include genesis *)
      match Storage.ChainDB.get_hash_at_height state.db 0 with
      | Some h -> List.rev (h :: acc)
      | None -> List.rev acc
    else begin
      match Storage.ChainDB.get_hash_at_height state.db height with
      | Some hash ->
        let next_step = if List.length acc >= 10 then step * 2 else step in
        collect (hash :: acc) next_step (height - next_step)
      | None ->
        collect acc step (height - 1)
    end
  in
  if tip_height <= 0 then
    match Storage.ChainDB.get_hash_at_height state.db 0 with
    | Some h -> [h]
    | None -> []
  else
    collect [] 1 tip_height

(* Get header entry by hash *)
let get_header (state : chain_state) (hash : Types.hash256)
    : header_entry option =
  Hashtbl.find_opt state.headers (Cstruct.to_string hash)

(* Get header entry by height *)
let get_header_at_height (state : chain_state) (height : int)
    : header_entry option =
  match Storage.ChainDB.get_hash_at_height state.db height with
  | Some hash -> Hashtbl.find_opt state.headers (Cstruct.to_string hash)
  | None -> None

(* Request headers from a peer, starting from our current tip *)
let request_headers (state : chain_state) (peer : Peer.peer) : unit Lwt.t =
  let locator = build_locator state in
  Peer.send_message peer
    (P2p.GetheadersMsg {
      version = Types.protocol_version;
      locator_hashes = locator;
      hash_stop = Types.zero_hash;
    })

(* Main header sync loop - requests headers repeatedly until caught up *)
let sync_headers (state : chain_state) (peer : Peer.peer) : unit Lwt.t =
  let open Lwt.Syntax in
  state.sync_state <- SyncingHeaders;
  state.sync_peer <- Some peer.id;
  let rec loop () =
    let* () = request_headers state peer in
    let* msg = Peer.read_message peer in
    match msg with
    | P2p.HeadersMsg headers ->
      let count = List.length headers in
      Logs.info (fun m -> m "Received %d headers" count);
      (match process_headers state headers with
       | Ok accepted ->
         Logs.info (fun m -> m "Accepted %d headers, tip at height %d"
           accepted state.headers_synced);
         if count = P2p.max_headers_count then
           (* Peer may have more headers, continue requesting *)
           loop ()
         else begin
           (* Got fewer than max, we're caught up with this peer *)
           state.sync_state <- SyncingBlocks;
           Lwt.return_unit
         end
       | Error e ->
         Logs.err (fun m -> m "Header validation failed: %s" e);
         state.sync_state <- Idle;
         Lwt.return_unit)
    | _ ->
      Logs.warn (fun m -> m "Unexpected message during header sync: %s"
        (P2p.command_to_string (P2p.payload_to_command msg)));
      loop ()
  in
  loop ()

(* Start header sync with peer (non-blocking) *)
let start_header_sync (state : chain_state) (peer : Peer.peer) : unit Lwt.t =
  if state.sync_state = Idle || state.sync_state = FullySynced then
    sync_headers state peer
  else
    Lwt.return_unit

(* Check if we need to sync headers from a peer *)
let needs_header_sync (state : chain_state) (peer : Peer.peer) : bool =
  state.sync_state = Idle &&
  peer.state = Peer.Ready &&
  Int32.to_int peer.best_height > state.headers_synced

(* Get sync progress info *)
type sync_info = {
  state : string;
  headers_synced : int;
  blocks_synced : int;
  tip_hash : string option;
  sync_peer : int option;
}

let get_sync_info (state : chain_state) : sync_info =
  {
    state = sync_state_to_string state.sync_state;
    headers_synced = state.headers_synced;
    blocks_synced = state.blocks_synced;
    tip_hash = (match state.tip with
      | Some t -> Some (Types.hash256_to_hex_display t.hash)
      | None -> None);
    sync_peer = state.sync_peer;
  }

(* Get tip header entry *)
let get_tip (state : chain_state) : header_entry option =
  state.tip

(* Get total header count in memory *)
let header_count (state : chain_state) : int =
  Hashtbl.length state.headers

(* Check if a block hash is known *)
let has_header (state : chain_state) (hash : Types.hash256) : bool =
  Hashtbl.mem state.headers (Cstruct.to_string hash)
