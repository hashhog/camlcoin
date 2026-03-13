(* Header-first synchronization (BIP-130) *)
(* Downloads all block headers before downloading full blocks,
   verifying the proof-of-work chain and building the header chain. *)

let log_src = Logs.Src.create "VALIDATION" ~doc:"Block validation"
module Log = (val Logs.src_log log_src : Logs.LOG)
let _ = Log.info  (* suppress unused module warning *)

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
  total_work : Cstruct.t;  (* cumulative proof-of-work, 32-byte LE *)
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
  mutable prune_target : int;    (* 0 = no pruning, else keep this many blocks *)
  mutable prune_height : int;    (* last pruned height *)
  headers_from_peer : (int, int) Hashtbl.t;  (* peer_id -> header count from that peer *)
}

(* Header flood prevention: reject new headers when this limit is reached
   and chain work is below the network's minimum_chain_work. *)
let max_headers_in_memory = 1_000_000

(* Header sync timeout constants *)
let headers_download_timeout = 900.0  (* 15 min total for header download *)
let headers_response_timeout = 120.0  (* 2 min per header response *)

(* Per-peer header flood threshold *)
let max_headers_per_peer = 10_000     (* Disconnect if peer sends this many with insufficient work *)

(* Compute proof-of-work from compact target (nBits) as a 256-bit integer.
   Delegates to Consensus.work_from_compact which uses
   (~target / (target + 1)) + 1 to avoid 2^256 overflow. *)
let work_from_bits (bits : int32) : Cstruct.t =
  Consensus.work_from_compact bits

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
    prune_target = 0;
    prune_height = 0;
    headers_from_peer = Hashtbl.create 16;
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
    prune_target = 0;
    prune_height = 0;
    headers_from_peer = Hashtbl.create 16;
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
           let parent_work = if h = 0 then Consensus.zero_work else
             match Hashtbl.find_opt state.headers
                 (Cstruct.to_string header.prev_block) with
             | Some parent -> parent.total_work
             | None -> Consensus.zero_work
           in
           let entry = {
             header; hash; height = h;
             total_work = Consensus.work_add parent_work (work_from_bits header.bits);
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

(* Prune old block data to save disk space.
   Keeps at least min_keep (288) blocks, matching Bitcoin Core MIN_BLOCKS_TO_KEEP.
   Also deletes undo data for very old blocks beyond the keep window + 288. *)
let prune_old_blocks (state : chain_state) (current_height : int) : unit =
  if state.prune_target <= 0 then ()
  else
    let min_keep = 288 in  (* Bitcoin Core MIN_BLOCKS_TO_KEEP *)
    let keep_blocks = max state.prune_target min_keep in
    let prune_below = current_height - keep_blocks in
    if prune_below <= state.prune_height then ()
    else begin
      for h = state.prune_height + 1 to prune_below do
        match Storage.ChainDB.get_hash_at_height state.db h with
        | None -> ()
        | Some hash ->
          Storage.ChainDB.delete_block state.db hash;
          (* Also delete undo data for very old blocks *)
          if h < current_height - keep_blocks - 288 then
            Storage.ChainDB.delete_undo_data state.db hash
      done;
      state.prune_height <- prune_below
    end

(* Collect timestamps of the last n ancestors (including the given entry).
   Walks prev_block links in the in-memory header map. *)
let collect_ancestor_timestamps (state : chain_state)
    (entry : header_entry) (n : int) : int32 list =
  let rec walk acc count cur =
    if count >= n then acc
    else
      let acc = cur.header.timestamp :: acc in
      if cur.height = 0 then acc
      else
        let parent_key = Cstruct.to_string cur.header.prev_block in
        match Hashtbl.find_opt state.headers parent_key with
        | Some parent -> walk acc (count + 1) parent
        | None -> acc
  in
  walk [] 0 entry

(* Validate a header against the current chain state.
   Checks: not duplicate, parent exists, proof-of-work valid, timestamp, MTP *)
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
      else begin
        (* MTP validation: collect timestamps of last 11 ancestors *)
        let ancestor_ts = collect_ancestor_timestamps state parent 11 in
        let mtp = Consensus.median_time_past ancestor_ts in
        if Int32.compare header.timestamp mtp <= 0 then
          Error "Header timestamp not greater than median-time-past"
        else begin
          let height = parent.height + 1 in
          (* Checkpoint enforcement: if this height has a checkpoint,
             the header hash must match the expected checkpoint hash *)
          match Consensus.get_checkpoint_hash height state.network with
          | Some expected_hash when not (Cstruct.equal hash expected_hash) ->
            Error (Printf.sprintf
              "Header at checkpoint height %d does not match expected hash" height)
          | _ ->
          let work = Consensus.work_add parent.total_work
              (work_from_bits header.bits) in
          Ok { header; hash; height; total_work = work }
        end
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
    | Some tip -> Consensus.work_compare entry.total_work tip.total_work > 0
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
  (* Header flood prevention: reject if we already have too many headers
     and chain work is below the minimum *)
  let tip_work = match state.tip with
    | Some t -> t.total_work
    | None -> Consensus.zero_work
  in
  if Hashtbl.length state.headers >= max_headers_in_memory
     && Consensus.work_compare tip_work state.network.minimum_chain_work < 0 then
    Error "Header flood: too many headers with insufficient chain work"
  else begin
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
  end

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

(* Main header sync loop - requests headers repeatedly until caught up.
   Enforces headers_download_timeout (15 min total) and uses
   read_message_with_timeout for per-response timeout (2 min). *)
let sync_headers (state : chain_state) (peer : Peer.peer) : unit Lwt.t =
  let open Lwt.Syntax in
  state.sync_state <- SyncingHeaders;
  state.sync_peer <- Some peer.id;
  let sync_start_time = Unix.gettimeofday () in
  let rec loop () =
    (* Check total header download timeout *)
    let elapsed = Unix.gettimeofday () -. sync_start_time in
    if elapsed > headers_download_timeout then begin
      Logs.err (fun m ->
        m "Header sync timed out after %.0fs (limit: %.0fs)"
          elapsed headers_download_timeout);
      state.sync_state <- Idle;
      Lwt.return_unit
    end else begin
      let* () = request_headers state peer in
      let* msg_opt = Peer.read_message_with_timeout peer headers_response_timeout in
      match msg_opt with
      | None ->
        Logs.err (fun m ->
          m "Header sync: no response from peer %d within %.0fs"
            peer.id headers_response_timeout);
        state.sync_state <- Idle;
        Lwt.return_unit
      | Some (P2p.HeadersMsg headers) ->
        let count = List.length headers in
        Logs.info (fun m -> m "Received %d headers" count);
        (* Track per-peer header count for flood detection *)
        let prev_count =
          match Hashtbl.find_opt state.headers_from_peer peer.id with
          | Some c -> c
          | None -> 0
        in
        let new_count = prev_count + count in
        Hashtbl.replace state.headers_from_peer peer.id new_count;
        (* Per-peer header flood check: if peer has sent > max_headers_per_peer
           headers and total chain work is still below minimum, disconnect *)
        if new_count > max_headers_per_peer then begin
          let tip_work = match state.tip with
            | Some t -> t.total_work
            | None -> Consensus.zero_work
          in
          if Consensus.work_compare tip_work
               state.network.minimum_chain_work < 0 then begin
            Logs.warn (fun m ->
              m "Peer %d sent %d headers with insufficient chain work, \
                 disconnecting (header flood)" peer.id new_count);
            state.sync_state <- Idle;
            Lwt.return_unit
          end else
            process_and_continue state headers count loop
        end else
          process_and_continue state headers count loop
      | Some msg ->
        Logs.warn (fun m -> m "Unexpected message during header sync: %s"
          (P2p.command_to_string (P2p.payload_to_command msg)));
        loop ()
    end
  and process_and_continue state headers count loop_fn =
    match process_headers state headers with
    | Ok accepted ->
      Logs.info (fun m -> m "Accepted %d headers, tip at height %d"
        accepted state.headers_synced);
      if count = P2p.max_headers_count then
        (* Peer may have more headers, continue requesting *)
        loop_fn ()
      else begin
        (* Got fewer than max, we're caught up with this peer.
           Verify tip work >= minimum_chain_work before transitioning
           to block sync (nMinimumChainWork check). *)
        let tip_work = match state.tip with
          | Some t -> t.total_work
          | None -> Consensus.zero_work
        in
        if Consensus.work_compare tip_work
             state.network.minimum_chain_work < 0 then begin
          Logs.warn (fun m ->
            m "Header chain work below minimum_chain_work, \
               not transitioning to block sync");
          state.sync_state <- Idle;
          Lwt.return_unit
        end else begin
          state.sync_state <- SyncingBlocks;
          Lwt.return_unit
        end
      end
    | Error e ->
      Logs.err (fun m -> m "Header validation failed: %s" e);
      state.sync_state <- Idle;
      Lwt.return_unit
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

(* ============================================================================
   Block Download State Machine
   ============================================================================ *)

(* Download state for a single block *)
type block_download_state =
  | NotRequested
  | Requested of { peer_id : int; requested_at : float; timeout : float }
  | Downloaded of Types.block
  | Validated

(* Block queue entry - tracks download progress for each block *)
type block_queue_entry = {
  hash : Types.hash256;
  height : int;
  mutable download_state : block_download_state;
}

(* Per-peer download tracking to avoid blocking on slow peers *)
type peer_download_state = {
  peer_id : int;
  mutable blocks_in_flight : int;
  mutable consecutive_timeouts : int;
  mutable current_timeout : float;
}

(* Check if a block at the given height/hash is at or below the assumevalid
   checkpoint. If assume_valid_hash is set, we look up that hash in our
   header map to find its height; any block at or below that height on the
   best chain is considered assume-valid, so script verification is skipped. *)
let is_assume_valid (state : chain_state) (height : int) : bool =
  match state.network.assume_valid_hash with
  | None -> false
  | Some av_hash ->
    match Hashtbl.find_opt state.headers (Cstruct.to_string av_hash) with
    | None -> false  (* assumevalid block not in our chain yet *)
    | Some av_entry -> height <= av_entry.height

(* IBD configuration constants *)
let max_blocks_per_peer = 16          (* Max in-flight blocks per peer *)
let max_total_blocks_in_flight = 128  (* Global cap on blocks in flight *)
let stall_timeout = 2.0                 (* 2s stall detection — re-request from another peer *)
let base_block_timeout = 60.0           (* 60s base timeout — matches Bitcoin Core's conservative approach *)
let max_block_timeout = 300.0           (* 5 min max timeout per block *)
let max_stall_timeout = 1200.0          (* 20 min max stall — matches Bitcoin Core *)
let max_consecutive_timeouts = 5        (* More forgiving before disconnect *)
let utxo_flush_interval = 2000        (* Flush UTXOs every N blocks *)
let block_download_window = 1024      (* Max blocks ahead to queue (matches Bitcoin Core BLOCK_DOWNLOAD_WINDOW) *)

(* Orphan block pool constants *)
let max_orphan_blocks = 750
let orphan_block_expire_seconds = 1800.0  (* 30 minutes *)

(* Orphan block entry - stores blocks whose parents we haven't seen yet *)
type orphan_block_entry = {
  block : Types.block;
  hash : Types.hash256;
  prev_hash : Types.hash256;
  received_time : float;
}

(* IBD state - tracks the full block download process *)
type ibd_state = {
  chain : chain_state;
  mutable block_queue : block_queue_entry list;
  mutable next_download_height : int;
  mutable next_process_height : int;
  mutable total_blocks_in_flight : int;
  mutable peer_states : (int, peer_download_state) Hashtbl.t;
  mutable blocks_since_flush : int;
  mutable pending_utxo_updates : (Types.hash256 * int * string) list;
  mutable pending_utxo_deletes : (Types.hash256 * int) list;
  utxo_set : Utxo.OptimizedUtxoSet.t option;  (* Wire UTXO flush *)
  mutable mempool : Mempool.mempool option;
  orphan_blocks : (string, orphan_block_entry) Hashtbl.t;
}

(* Create IBD state from existing chain state *)
let create_ibd_state ?(utxo_set : Utxo.OptimizedUtxoSet.t option)
    (chain : chain_state) : ibd_state =
  let start_height = chain.blocks_synced + 1 in
  { chain;
    block_queue = [];
    next_download_height = start_height;
    next_process_height = start_height;
    total_blocks_in_flight = 0;
    peer_states = Hashtbl.create 16;
    blocks_since_flush = 0;
    pending_utxo_updates = [];
    pending_utxo_deletes = [];
    utxo_set;
    mempool = None;
    orphan_blocks = Hashtbl.create 100 }

let set_mempool (ibd : ibd_state) (mp : Mempool.mempool) =
  ibd.mempool <- Some mp

(* Get or create peer download state *)
let get_peer_state (ibd : ibd_state) (peer_id : int) : peer_download_state =
  match Hashtbl.find_opt ibd.peer_states peer_id with
  | Some state -> state
  | None ->
    let state = {
      peer_id;
      blocks_in_flight = 0;
      consecutive_timeouts = 0;
      current_timeout = base_block_timeout;
    } in
    Hashtbl.replace ibd.peer_states peer_id state;
    state

(* ============================================================================
   Download Queue Management
   ============================================================================ *)

(* Fill the download queue from header chain *)
let fill_download_queue (ibd : ibd_state) : unit =
  let tip_height = match ibd.chain.tip with
    | Some t -> t.height
    | None -> 0
  in
  let max_queue_size = block_download_window in
  while ibd.next_download_height <= tip_height &&
        List.length ibd.block_queue < max_queue_size do
    let height = ibd.next_download_height in
    match Storage.ChainDB.get_hash_at_height ibd.chain.db height with
    | Some hash ->
      (* Only add if we don't already have the block *)
      if not (Storage.ChainDB.has_block ibd.chain.db hash) then begin
        ibd.block_queue <- ibd.block_queue @ [{
          hash;
          height;
          download_state = NotRequested;
        }]
      end;
      ibd.next_download_height <- ibd.next_download_height + 1
    | None ->
      (* Missing hash at height - shouldn't happen if headers are synced *)
      ibd.next_download_height <- ibd.next_download_height + 1
  done

(* ============================================================================
   Timeout Management with Adaptive Backoff
   ============================================================================ *)

(* Check for timed out requests and reset them *)
let check_timeouts (ibd : ibd_state) : unit =
  let now = Unix.gettimeofday () in
  List.iter (fun entry ->
    match entry.download_state with
    | Requested { peer_id; requested_at; timeout } ->
      if now -. requested_at > timeout then begin
        (* Timeout occurred - reset block and penalize peer *)
        entry.download_state <- NotRequested;
        ibd.total_blocks_in_flight <- max 0 (ibd.total_blocks_in_flight - 1);
        let peer_state = get_peer_state ibd peer_id in
        peer_state.blocks_in_flight <- max 0 (peer_state.blocks_in_flight - 1);
        (* Double timeout on stall (up to max) *)
        peer_state.consecutive_timeouts <- peer_state.consecutive_timeouts + 1;
        peer_state.current_timeout <- min max_block_timeout
          (peer_state.current_timeout *. 2.0);
        Logs.debug (fun m ->
          m "Block request timeout for height %d from peer %d (new timeout: %.1fs)"
            entry.height peer_id peer_state.current_timeout)
      end
    | _ -> ()
  ) ibd.block_queue

(* Check for stalled block downloads with exponential backoff and peer disconnect.
   Iterates block queue entries in Requested state. If the request has been pending
   for > stall_timeout (2s) with no progress, reset to NotRequested so it can be
   retried from a different peer. If the request has exceeded the full timeout,
   apply exponential backoff and increment the peer's consecutive timeout counter.
   Returns a list of peer IDs that should be disconnected
   (those exceeding max_consecutive_timeouts). *)
let check_stalled_downloads (ibd : ibd_state) : int list =
  let now = Unix.gettimeofday () in
  let peers_to_disconnect = Hashtbl.create 4 in
  List.iter (fun entry ->
    match entry.download_state with
    | Requested { peer_id; requested_at; timeout } ->
      if now > requested_at +. timeout then begin
        (* Hard timeout: reset block to NotRequested for re-download *)
        entry.download_state <- NotRequested;
        ibd.total_blocks_in_flight <- max 0 (ibd.total_blocks_in_flight - 1);
        let peer_state = get_peer_state ibd peer_id in
        peer_state.blocks_in_flight <- max 0 (peer_state.blocks_in_flight - 1);
        (* Increment consecutive timeout counter *)
        peer_state.consecutive_timeouts <- peer_state.consecutive_timeouts + 1;
        (* Exponential backoff: double timeout, cap at max_stall_timeout *)
        peer_state.current_timeout <- min max_stall_timeout
          (peer_state.current_timeout *. 2.0);
        Logs.debug (fun m ->
          m "Stalled download for height %d from peer %d \
             (consecutive timeouts: %d, new timeout: %.1fs)"
            entry.height peer_id
            peer_state.consecutive_timeouts peer_state.current_timeout);
        (* Mark peer for disconnect after base_block_timeout worth of stalls *)
        if peer_state.consecutive_timeouts >= max_consecutive_timeouts then
          Hashtbl.replace peers_to_disconnect peer_id true
      end else if now > requested_at +. stall_timeout then begin
        (* Stall detection: block pending > 2s with no progress.
           Reset to NotRequested so it can be re-requested from another peer.
           Do NOT penalize the peer yet — only the hard timeout does that. *)
        entry.download_state <- NotRequested;
        ibd.total_blocks_in_flight <- max 0 (ibd.total_blocks_in_flight - 1);
        let peer_state = get_peer_state ibd peer_id in
        peer_state.blocks_in_flight <- max 0 (peer_state.blocks_in_flight - 1);
        Logs.debug (fun m ->
          m "Stall detected for height %d from peer %d (%.1fs), \
             re-requesting from another peer"
            entry.height peer_id (now -. requested_at))
      end
    | _ -> ()
  ) ibd.block_queue;
  Hashtbl.fold (fun peer_id _ acc -> peer_id :: acc) peers_to_disconnect []

(* Decay timeout on successful receipt *)
let record_successful_download (ibd : ibd_state) (peer_id : int) : unit =
  let peer_state = get_peer_state ibd peer_id in
  peer_state.blocks_in_flight <- max 0 (peer_state.blocks_in_flight - 1);
  (* Reset timeout on success *)
  peer_state.consecutive_timeouts <- 0;
  peer_state.current_timeout <- base_block_timeout

(* ============================================================================
   Block Request Logic with Per-Peer Tracking
   ============================================================================ *)

(* Request blocks from available peers using batched GetData *)
let request_blocks (ibd : ibd_state) (peers : Peer.peer list)
    : unit Lwt.t =
  let now = Unix.gettimeofday () in
  (* First check for timeouts *)
  check_timeouts ibd;
  (* Filter to ready peers with capacity *)
  let ready_peers = List.filter (fun p ->
    p.Peer.state = Peer.Ready &&
    let ps = get_peer_state ibd p.Peer.id in
    ps.blocks_in_flight < max_blocks_per_peer
  ) peers in
  (* Request from each peer up to their capacity *)
  let%lwt () = Lwt_list.iter_s (fun peer ->
    if ibd.total_blocks_in_flight >= max_total_blocks_in_flight then
      Lwt.return_unit
    else begin
      let peer_state = get_peer_state ibd peer.Peer.id in
      let available = max_blocks_per_peer - peer_state.blocks_in_flight in
      let global_available = max_total_blocks_in_flight - ibd.total_blocks_in_flight in
      let to_request_count = min available global_available in
      if to_request_count <= 0 then
        Lwt.return_unit
      else begin
        (* Find unrequested blocks *)
        let unrequested = List.filter (fun entry ->
          entry.download_state = NotRequested
        ) ibd.block_queue in
        match unrequested with
        | [] -> Lwt.return_unit
        | entries ->
          (* Take up to to_request_count blocks *)
          let batch = List.filteri (fun i _ -> i < to_request_count) entries in
          if batch = [] then
            Lwt.return_unit
          else begin
            (* Mark as requested and build inv vectors *)
            let inv_vectors = List.map (fun entry ->
              entry.download_state <- Requested {
                peer_id = peer.Peer.id;
                requested_at = now;
                timeout = peer_state.current_timeout;
              };
              ibd.total_blocks_in_flight <- ibd.total_blocks_in_flight + 1;
              peer_state.blocks_in_flight <- peer_state.blocks_in_flight + 1;
              P2p.{ inv_type = InvWitnessBlock; hash = entry.hash }
            ) batch in
            Logs.debug (fun m ->
              m "Requesting %d blocks from peer %d (in-flight: %d/%d)"
                (List.length inv_vectors) peer.Peer.id
                peer_state.blocks_in_flight max_blocks_per_peer);
            (* Send batched GetData message *)
            Peer.send_message peer (P2p.GetdataMsg inv_vectors)
          end
      end
    end
  ) ready_peers in
  Lwt.return_unit

(* ============================================================================
   Block Receipt and Processing
   ============================================================================ *)

(* Process a received block *)
let receive_block (ibd : ibd_state) (block : Types.block)
    : (unit, string) result =
  let hash = Crypto.compute_block_hash block.header in
  let hash_key = Cstruct.to_string hash in
  match List.find_opt (fun (e : block_queue_entry) ->
    Cstruct.to_string e.hash = hash_key
  ) ibd.block_queue with
  | None ->
    (* Unrequested block - store as orphan if pool isn't full *)
    let prev_hash = block.header.prev_block in
    let orphan_entry = {
      block;
      hash;
      prev_hash;
      received_time = Unix.gettimeofday ();
    } in
    if Hashtbl.length ibd.orphan_blocks >= max_orphan_blocks then begin
      (* Pool is full - evict the oldest entry *)
      let oldest_key = ref "" in
      let oldest_time = ref infinity in
      Hashtbl.iter (fun key entry ->
        if entry.received_time < !oldest_time then begin
          oldest_time := entry.received_time;
          oldest_key := key
        end
      ) ibd.orphan_blocks;
      if !oldest_key <> "" then
        Hashtbl.remove ibd.orphan_blocks !oldest_key
    end;
    Hashtbl.replace ibd.orphan_blocks hash_key orphan_entry;
    Logs.debug (fun m ->
      m "Stored orphan block %s (pool size: %d)"
        (Types.hash256_to_hex_display hash)
        (Hashtbl.length ibd.orphan_blocks));
    Ok ()
  | Some entry ->
    (* Record which peer sent it for timeout decay *)
    let peer_id = match entry.download_state with
      | Requested { peer_id; _ } -> Some peer_id
      | _ -> None
    in
    entry.download_state <- Downloaded block;
    ibd.total_blocks_in_flight <- max 0 (ibd.total_blocks_in_flight - 1);
    (* Decay timeout for successful download *)
    (match peer_id with
     | Some pid -> record_successful_download ibd pid
     | None -> ());
    Ok ()

(* Handle notfound response — mark blocks as not requested so they can be
   re-requested from a different peer. Score the peer for not having blocks. *)
let handle_notfound (ibd : ibd_state) (peer_id : int)
    (items : P2p.inv_vector list) : unit =
  List.iter (fun (iv : P2p.inv_vector) ->
    (* Find matching block queue entry and reset to NotRequested *)
    List.iter (fun entry ->
      match entry.download_state with
      | Requested req when req.peer_id = peer_id &&
                           Cstruct.equal entry.hash iv.hash ->
        entry.download_state <- NotRequested;
        ibd.total_blocks_in_flight <- max 0 (ibd.total_blocks_in_flight - 1);
        let peer_state = get_peer_state ibd peer_id in
        peer_state.blocks_in_flight <- max 0 (peer_state.blocks_in_flight - 1);
        Logs.debug (fun m ->
          m "Notfound for block at height %d from peer %d, will retry"
            entry.height peer_id)
      | _ -> ()
    ) ibd.block_queue
  ) items

(* Flush pending UTXO updates to database *)
let flush_utxos (ibd : ibd_state) : unit =
  if ibd.pending_utxo_updates <> [] || ibd.pending_utxo_deletes <> [] then begin
    let batch = Storage.ChainDB.batch_create () in
    (* Add new UTXOs *)
    List.iter (fun (txid, vout, data) ->
      Storage.ChainDB.batch_store_utxo batch txid vout data
    ) ibd.pending_utxo_updates;
    (* Delete spent UTXOs *)
    List.iter (fun (txid, vout) ->
      Storage.ChainDB.batch_delete_utxo batch txid vout
    ) ibd.pending_utxo_deletes;
    Storage.ChainDB.batch_write ibd.chain.db batch;
    ibd.pending_utxo_updates <- [];
    ibd.pending_utxo_deletes <- [];
    Logs.debug (fun m -> m "Flushed UTXO updates to disk")
  end;
  (* Also flush the OptimizedUtxoSet dirty entries if one is attached *)
  match ibd.utxo_set with
  | Some utxo -> Utxo.OptimizedUtxoSet.flush utxo
  | None -> ()

(* Encode UTXO data for storage *)
let encode_utxo (value : int64) (script : Cstruct.t) (height : int)
    (is_coinbase : bool) : string =
  let w = Serialize.writer_create () in
  Serialize.write_int64_le w value;
  Serialize.write_compact_size w (Cstruct.length script);
  Serialize.write_bytes w script;
  Serialize.write_int32_le w (Int32.of_int height);
  Serialize.write_uint8 w (if is_coinbase then 1 else 0);
  Cstruct.to_string (Serialize.writer_to_cstruct w)

(* Expire orphan blocks older than orphan_block_expire_seconds *)
let expire_orphan_blocks (ibd : ibd_state) : int =
  let now = Unix.gettimeofday () in
  let to_remove = Hashtbl.fold (fun key entry acc ->
    if now -. entry.received_time > orphan_block_expire_seconds then
      key :: acc
    else
      acc
  ) ibd.orphan_blocks [] in
  List.iter (fun key -> Hashtbl.remove ibd.orphan_blocks key) to_remove;
  let removed = List.length to_remove in
  if removed > 0 then
    Logs.debug (fun m ->
      m "Expired %d orphan blocks (pool size: %d)"
        removed (Hashtbl.length ibd.orphan_blocks));
  removed

(* Process orphan blocks whose parent has arrived.
   After a block with the given hash is successfully connected, check if any
   orphans have prev_hash matching it. If found, add them to the block queue
   and process recursively (an orphan may unblock another orphan). *)
let process_orphan_blocks (ibd : ibd_state) (parent_hash : Types.hash256) : int =
  let processed = ref 0 in
  let rec process_children parent_h =
    let parent_key = Cstruct.to_string parent_h in
    (* Find all orphans whose prev_hash matches parent_h *)
    let children = Hashtbl.fold (fun key entry acc ->
      if Cstruct.to_string entry.prev_hash = parent_key then
        (key, entry) :: acc
      else
        acc
    ) ibd.orphan_blocks [] in
    List.iter (fun (key, orphan) ->
      (* Remove from orphan pool *)
      Hashtbl.remove ibd.orphan_blocks key;
      (* Add to block queue if we know the header *)
      let orphan_hash_key = Cstruct.to_string orphan.hash in
      (match Hashtbl.find_opt ibd.chain.headers orphan_hash_key with
       | Some header_entry ->
         (* Add to block queue as Downloaded so it can be processed *)
         let queue_entry = {
           hash = orphan.hash;
           height = header_entry.height;
           download_state = Downloaded orphan.block;
         } in
         ibd.block_queue <- ibd.block_queue @ [queue_entry];
         incr processed;
         Logs.debug (fun m ->
           m "Moved orphan block %s (height %d) to block queue"
             (Types.hash256_to_hex_display orphan.hash) header_entry.height)
       | None ->
         (* We don't have the header for this orphan - just re-receive it
            via receive_block which will re-orphan it or process it *)
         let result = receive_block ibd orphan.block in
         (match result with
          | Ok () -> incr processed
          | Error _ -> ()));
      (* Recursively process any orphans that depend on this one *)
      process_children orphan.hash
    ) children
  in
  process_children parent_hash;
  if !processed > 0 then
    Logs.debug (fun m ->
      m "Processed %d orphan blocks from parent %s"
        !processed (Types.hash256_to_hex_display parent_hash));
  !processed

(* Compute the median time past (MTP) for a block at the given height.
   MTP is the median of the timestamps of the previous 11 blocks (or fewer
   if near genesis). Returns 0l if no ancestors are available. *)
let compute_median_time_past (state : chain_state) (height : int) : int32 =
  let rec collect acc h count =
    if count <= 0 || h < 0 then acc
    else match get_header_at_height state h with
      | Some entry -> collect (entry.header.timestamp :: acc) (h - 1) (count - 1)
      | None -> acc
  in
  (* Collect up to 11 timestamps from height-1 down to height-11 *)
  let timestamps = collect [] (height - 1) 11 in
  Consensus.median_time_past timestamps

(* Compute the expected difficulty bits for a block at the given height.
   - Genesis block (height 0): use genesis header bits
   - Regtest (pow_no_retargeting): use parent's bits (every block same difficulty)
   - Difficulty adjustment boundary (height mod 2016 = 0): compute retarget
   - Testnet min-difficulty: if block timestamp > 20 min after parent, allow pow_limit
   - Otherwise: use parent's bits *)
let compute_expected_bits (state : chain_state) (height : int)
    (block_header : Types.block_header) : int32 =
  let network = state.network in
  if height = 0 then
    network.genesis_header.bits
  else if network.pow_no_retargeting then
    (* Regtest: no retargeting, use parent's bits *)
    (match get_header_at_height state (height - 1) with
     | Some parent -> parent.header.bits
     | None -> network.pow_limit)
  else if height mod Consensus.difficulty_adjustment_interval = 0 then begin
    (* Difficulty adjustment boundary *)
    let last_retarget_height = height - Consensus.difficulty_adjustment_interval in
    let last_retarget_time =
      match get_header_at_height state last_retarget_height with
      | Some entry -> entry.header.timestamp
      | None -> 0l
    in
    let parent =
      match get_header_at_height state (height - 1) with
      | Some entry -> entry.header
      | None -> network.genesis_header
    in
    let current_bits = parent.bits in
    Consensus.next_work_required
      ~last_retarget_time
      ~current_header:parent
      ~current_bits
      ~network
  end else begin
    (* Non-adjustment block *)
    match get_header_at_height state (height - 1) with
    | Some parent ->
      (* Testnet min-difficulty rule: if block timestamp is > 20 min after
         parent, allow mining at pow_limit *)
      let get_bits h =
        match get_header_at_height state h with
        | Some hdr -> hdr.header.bits
        | None -> network.pow_limit
      in
      (match Consensus.testnet_min_difficulty_bits
               ~prev_block_time:parent.header.timestamp
               ~current_time:block_header.timestamp
               ~network
               ~get_bits_at_height:get_bits
               ~height () with
       | Some min_bits -> min_bits
       | None -> parent.header.bits)
    | None -> network.pow_limit
  end

(* Compute MTP for a given height - used as callback for BIP-68 validation *)
let get_mtp_for_height (state : chain_state) (h : int) : int32 =
  compute_median_time_past state h

(* Process downloaded blocks in height order *)
let process_downloaded_blocks (ibd : ibd_state)
    : (int, string) result =
  let processed = ref 0 in
  let error = ref None in
  let continue = ref true in
  while !continue && !error = None do
    match List.find_opt (fun e ->
      e.height = ibd.next_process_height
    ) ibd.block_queue with
    | Some entry -> begin
      match entry.download_state with
      | Downloaded block ->
        (* Validate the block *)
        let height = entry.height in
        (* Compute expected difficulty from chain state *)
        let expected_bits = compute_expected_bits ibd.chain height block.header in
        (* Compute median time past from last 11 blocks *)
        let median_time = compute_median_time_past ibd.chain height in
        (* Build UTXO lookup function *)
        let lookup outpoint =
          let _txid_key = Cstruct.to_string outpoint.Types.txid in
          let vout = Int32.to_int outpoint.Types.vout in
          match Storage.ChainDB.get_utxo ibd.chain.db outpoint.Types.txid vout with
          | None -> None
          | Some data ->
            let r = Serialize.reader_of_cstruct (Cstruct.of_string data) in
            let value = Serialize.read_int64_le r in
            let script_len = Serialize.read_compact_size r in
            let script = Serialize.read_bytes r script_len in
            let stored_height = Int32.to_int (Serialize.read_int32_le r) in
            let utxo_is_coinbase = Serialize.read_uint8 r = 1 in
            Some Validation.{
              txid = outpoint.Types.txid;
              vout = outpoint.Types.vout;
              value;
              script_pubkey = script;
              height = stored_height;
              is_coinbase = utxo_is_coinbase;
            }
        in
        (* Validate block with UTXO tracking *)
        let skip_scripts = is_assume_valid ibd.chain height in
        let validation_flags =
          if skip_scripts then 0
          else Consensus.get_block_script_flags height ibd.chain.network
        in
        (match Validation.validate_block_with_utxos block height
                 ~expected_bits ~median_time ~base_lookup:lookup
                 ~flags:validation_flags ~skip_scripts
                 ~network:ibd.chain.network
                 ~get_mtp_at_height:(get_mtp_for_height ibd.chain) () with
         | Ok _fees ->
           (* Store block *)
           Storage.ChainDB.store_block ibd.chain.db entry.hash block;
           (* Build and store undo data for chain reorganization *)
           let undo_spent = ref [] in
           List.iteri (fun tx_idx tx ->
             if tx_idx > 0 then  (* Skip coinbase *)
               List.iter (fun inp ->
                 let prev = inp.Types.previous_output in
                 let vout = Int32.to_int prev.Types.vout in
                 match Storage.ChainDB.get_utxo ibd.chain.db prev.Types.txid vout with
                 | None -> ()
                 | Some data ->
                   let r = Serialize.reader_of_cstruct (Cstruct.of_string data) in
                   let entry_utxo = Utxo.deserialize_utxo_entry r in
                   undo_spent := (prev, entry_utxo) :: !undo_spent
               ) tx.Types.inputs
           ) block.transactions;
           let undo : Utxo.undo_data = { height; spent_outputs = !undo_spent } in
           let uw = Serialize.writer_create () in
           Utxo.serialize_undo_data uw undo;
           Storage.ChainDB.store_undo_data ibd.chain.db entry.hash
             (Cstruct.to_string (Serialize.writer_to_cstruct uw));
           (* Update UTXOs - add new outputs, delete spent inputs *)
           List.iteri (fun tx_idx tx ->
             let txid = Crypto.compute_txid tx in
             let is_cb = (tx_idx = 0) in
             (* Add outputs as new UTXOs (skip genesis coinbase) *)
             if not (Consensus.is_genesis_coinbase height txid) then begin
               List.iteri (fun vout out ->
                 let data = encode_utxo out.Types.value out.Types.script_pubkey
                     height is_cb in
                 ibd.pending_utxo_updates <-
                   (txid, vout, data) :: ibd.pending_utxo_updates
               ) tx.Types.outputs
             end;
             (* Delete spent inputs (non-coinbase only) *)
             if not is_cb then begin
               List.iter (fun inp ->
                 ibd.pending_utxo_deletes <-
                   (inp.Types.previous_output.Types.txid,
                    Int32.to_int inp.Types.previous_output.Types.vout)
                   :: ibd.pending_utxo_deletes
               ) tx.Types.inputs
             end
           ) block.transactions;
           (* Update chain state *)
           entry.download_state <- Validated;
           ibd.next_process_height <- ibd.next_process_height + 1;
           ibd.chain.blocks_synced <- height;
           ibd.blocks_since_flush <- ibd.blocks_since_flush + 1;
           incr processed;
           (* Prune old blocks if pruning is enabled *)
           prune_old_blocks ibd.chain height;
           (* Periodic UTXO flush *)
           if ibd.blocks_since_flush >= utxo_flush_interval then begin
             flush_utxos ibd;
             ibd.blocks_since_flush <- 0;
             (* Also update chain tip in DB *)
             Storage.ChainDB.set_chain_tip ibd.chain.db entry.hash height
           end;
           (* Check for orphan blocks that depend on this one *)
           ignore (process_orphan_blocks ibd entry.hash);
           (* Remove validated entries from queue *)
           ibd.block_queue <- List.filter
             (fun e -> e.download_state <> Validated) ibd.block_queue
         | Error e ->
           error := Some (Printf.sprintf
             "Block validation failed at height %d: %s"
             height (Validation.block_error_to_string e)))
      | NotRequested | Requested _ ->
        continue := false  (* Waiting for download *)
      | Validated ->
        (* Already validated, skip *)
        ibd.next_process_height <- ibd.next_process_height + 1
      end
    | None -> continue := false
  done;
  match !error with
  | Some e -> Error e
  | None -> Ok !processed

(* ============================================================================
   Chain Reorganization
   ============================================================================ *)

(* Find fork point between current tip and new tip *)
let find_fork_point (state : chain_state) (current_tip : header_entry)
    (new_tip : header_entry) : (header_entry, string) result =
  let rec find_fork (h1 : header_entry) (h2 : header_entry)
      : (header_entry, string) result =
    if h1.height > h2.height then
      (* Walk h1 back *)
      let parent_key = Cstruct.to_string h1.header.prev_block in
      match Hashtbl.find_opt state.headers parent_key with
      | Some parent -> find_fork parent h2
      | None -> Error "Cannot find fork point (missing parent of current)"
    else if h2.height > h1.height then
      (* Walk h2 back *)
      let parent_key = Cstruct.to_string h2.header.prev_block in
      match Hashtbl.find_opt state.headers parent_key with
      | Some parent -> find_fork h1 parent
      | None -> Error "Cannot find fork point (missing parent of new)"
    else if Cstruct.equal h1.hash h2.hash then
      (* Found common ancestor *)
      Ok h1
    else begin
      (* Same height but different blocks - walk both back *)
      let p1_key = Cstruct.to_string h1.header.prev_block in
      let p2_key = Cstruct.to_string h2.header.prev_block in
      match Hashtbl.find_opt state.headers p1_key,
            Hashtbl.find_opt state.headers p2_key with
      | Some p1, Some p2 -> find_fork p1 p2
      | None, _ -> Error "Cannot find fork point (missing parent)"
      | _, None -> Error "Cannot find fork point (missing parent)"
    end
  in
  find_fork current_tip new_tip

(* Collect blocks from fork point to tip *)
let collect_path (state : chain_state) (from_entry : header_entry)
    (to_entry : header_entry) : header_entry list =
  let rec collect (acc : header_entry list) (current : header_entry)
      : header_entry list =
    if current.height <= from_entry.height then
      acc
    else begin
      let parent_key = Cstruct.to_string current.header.prev_block in
      match Hashtbl.find_opt state.headers parent_key with
      | Some parent -> collect (current :: acc) parent
      | None -> current :: acc  (* Best effort *)
    end
  in
  collect [] to_entry

(* Perform chain reorganization to new tip
   IMPORTANT: This restores UTXOs spent on the old chain and spends
   UTXOs on the new chain. This is critical for UTXO set consistency. *)
let reorganize (ibd : ibd_state) (new_tip : header_entry)
    : (unit, string) result =
  let state = ibd.chain in
  let current_tip = match state.tip with
    | Some t -> t
    | None -> failwith "No current tip"
  in
  (* Avoid reorg if new tip isn't better *)
  if Consensus.work_compare new_tip.total_work current_tip.total_work <= 0 then
    Error "New tip does not have more work"
  else begin
    match find_fork_point state current_tip new_tip with
    | Error e -> Error e
    | Ok fork_point ->
      Logs.info (fun m ->
        m "Reorganizing from height %d to %d (fork at %d)"
          current_tip.height new_tip.height fork_point.height);
      (* Collect blocks to disconnect (current chain from tip to fork) *)
      let to_disconnect = collect_path state fork_point current_tip in
      (* Collect blocks to connect (new chain from fork to new tip) *)
      let to_connect = collect_path state fork_point new_tip in
      (* Disconnect blocks in reverse order (tip back to fork): restore spent UTXOs *)
      let disconnected_txs = ref [] in
      let rec disconnect_blocks = function
        | [] -> Ok ()
        | (entry : header_entry) :: rest ->
          match Storage.ChainDB.get_block state.db entry.hash with
          | None ->
            Error (Printf.sprintf
              "Missing block at height %d during reorg disconnect" entry.height)
          | Some block ->
            (* Collect non-coinbase transactions for mempool re-addition *)
            List.iteri (fun tx_idx tx ->
              if tx_idx > 0 then
                disconnected_txs := tx :: !disconnected_txs
            ) block.transactions;
            match Storage.ChainDB.get_undo_data state.db entry.hash with
            | None ->
              Error (Printf.sprintf
                "Missing undo data at height %d during reorg disconnect" entry.height)
            | Some undo_raw ->
              let r = Serialize.reader_of_cstruct (Cstruct.of_string undo_raw) in
              let undo = Utxo.deserialize_undo_data r in
              (* Remove outputs created by this block (reverse tx order) *)
              let txs = List.rev block.transactions in
              List.iter (fun tx ->
                let txid = Crypto.compute_txid tx in
                List.iteri (fun vout _out ->
                  ibd.pending_utxo_deletes <- (txid, vout) :: ibd.pending_utxo_deletes
                ) tx.Types.outputs
              ) txs;
              (* Restore spent outputs from undo data *)
              List.iter (fun (outpoint, utxo_entry) ->
                let data = encode_utxo utxo_entry.Utxo.value
                    utxo_entry.Utxo.script_pubkey utxo_entry.Utxo.height
                    utxo_entry.Utxo.is_coinbase in
                ibd.pending_utxo_updates <-
                  (outpoint.Types.txid, Int32.to_int outpoint.Types.vout, data)
                  :: ibd.pending_utxo_updates
              ) undo.spent_outputs;
              (* Clean up stored undo data for disconnected block *)
              Storage.ChainDB.delete_undo_data state.db entry.hash;
              Logs.debug (fun m ->
                m "Disconnected block at height %d" entry.height);
              disconnect_blocks rest
      in
      match disconnect_blocks (List.rev to_disconnect) with
      | Error e ->
        Logs.err (fun m -> m "Reorg aborted during disconnect: %s" e);
        ibd.pending_utxo_deletes <- [];
        ibd.pending_utxo_updates <- [];
        Error e
      | Ok () ->
      (* Flush pending UTXO changes from disconnect before connecting *)
      flush_utxos ibd;
      (* Re-add disconnected transactions to mempool if available *)
      (match ibd.mempool with
       | Some mp ->
         List.iter (fun tx ->
           ignore (Mempool.add_transaction mp tx)
         ) !disconnected_txs;
         Logs.debug (fun m ->
           m "Re-added %d disconnected transactions to mempool"
             (List.length !disconnected_txs))
       | None -> ());
      (* Connect blocks on the new chain from fork forward *)
      let connect_error = ref None in
      List.iter (fun (entry : header_entry) ->
        if !connect_error = None then
          match Storage.ChainDB.get_block state.db entry.hash with
          | None ->
            connect_error := Some (Printf.sprintf
              "Missing block at height %d during reorg connect" entry.height)
          | Some block ->
            let height = entry.height in
            (* Compute expected difficulty from chain state *)
            let expected_bits = compute_expected_bits state height block.header in
            (* Compute median time past from last 11 blocks *)
            let median_time = compute_median_time_past state height in
            let lookup outpoint =
              let vout = Int32.to_int outpoint.Types.vout in
              match Storage.ChainDB.get_utxo state.db outpoint.Types.txid vout with
              | None -> None
              | Some data ->
                let r = Serialize.reader_of_cstruct (Cstruct.of_string data) in
                let value = Serialize.read_int64_le r in
                let script_len = Serialize.read_compact_size r in
                let script = Serialize.read_bytes r script_len in
                let stored_height = Int32.to_int (Serialize.read_int32_le r) in
                let utxo_is_coinbase = Serialize.read_uint8 r = 1 in
                Some Validation.{
                  txid = outpoint.Types.txid;
                  vout = outpoint.Types.vout;
                  value;
                  script_pubkey = script;
                  height = stored_height;
                  is_coinbase = utxo_is_coinbase;
                }
            in
            let skip_scripts = is_assume_valid state height in
            let validation_flags =
              if skip_scripts then 0
              else Consensus.get_block_script_flags height state.network
            in
            (match Validation.validate_block_with_utxos block height
                     ~expected_bits ~median_time ~base_lookup:lookup
                     ~flags:validation_flags ~skip_scripts
                     ~network:state.network
                     ~get_mtp_at_height:(get_mtp_for_height state) () with
             | Ok _fees ->
               (* Store block if not already stored *)
               if not (Storage.ChainDB.has_block state.db entry.hash) then
                 Storage.ChainDB.store_block state.db entry.hash block;
               (* Build and store undo data *)
               let undo_spent = ref [] in
               List.iteri (fun tx_idx tx ->
                 if tx_idx > 0 then
                   List.iter (fun inp ->
                     let prev = inp.Types.previous_output in
                     let vout = Int32.to_int prev.Types.vout in
                     match Storage.ChainDB.get_utxo state.db prev.Types.txid vout with
                     | None -> ()
                     | Some data ->
                       let r = Serialize.reader_of_cstruct (Cstruct.of_string data) in
                       let entry_utxo = Utxo.deserialize_utxo_entry r in
                       undo_spent := (prev, entry_utxo) :: !undo_spent
                   ) tx.Types.inputs
               ) block.transactions;
               let undo : Utxo.undo_data = { height; spent_outputs = !undo_spent } in
               let uw = Serialize.writer_create () in
               Utxo.serialize_undo_data uw undo;
               Storage.ChainDB.store_undo_data state.db entry.hash
                 (Cstruct.to_string (Serialize.writer_to_cstruct uw));
               (* Update UTXOs *)
               List.iteri (fun tx_idx tx ->
                 let txid = Crypto.compute_txid tx in
                 let is_cb = (tx_idx = 0) in
                 if not (Consensus.is_genesis_coinbase height txid) then begin
                   List.iteri (fun vout out ->
                     let data = encode_utxo out.Types.value out.Types.script_pubkey
                         height is_cb in
                     ibd.pending_utxo_updates <-
                       (txid, vout, data) :: ibd.pending_utxo_updates
                   ) tx.Types.outputs
                 end;
                 if not is_cb then begin
                   List.iter (fun inp ->
                     ibd.pending_utxo_deletes <-
                       (inp.Types.previous_output.Types.txid,
                        Int32.to_int inp.Types.previous_output.Types.vout)
                       :: ibd.pending_utxo_deletes
                   ) tx.Types.inputs
                 end
               ) block.transactions;
               (* Flush after each connect to keep DB consistent for lookups *)
               flush_utxos ibd;
               (* Prune old blocks if pruning is enabled *)
               prune_old_blocks state height;
               (* Remove connected block's transactions from mempool *)
               (match ibd.mempool with
                | Some mp -> Mempool.remove_for_block mp block height
                | None -> ());
               Logs.debug (fun m ->
                 m "Connected block at height %d during reorg" height)
             | Error e ->
               connect_error := Some (Printf.sprintf
                 "Block validation failed at height %d during reorg: %s"
                 height (Validation.block_error_to_string e)))
      ) to_connect;
      (* Check for connect errors *)
      match !connect_error with
      | Some e -> Error e
      | None ->
        (* Update tip and chain state *)
        state.tip <- Some new_tip;
        state.blocks_synced <- new_tip.height;
        Storage.ChainDB.set_chain_tip state.db new_tip.hash new_tip.height;
        Logs.info (fun m ->
          m "Reorganization complete, new tip at height %d" new_tip.height);
        Ok ()
  end

(* ============================================================================
   Main IBD Loop
   ============================================================================ *)

(* Run initial block download *)
let run_ibd (ibd : ibd_state) (peers : Peer.peer list) : unit Lwt.t =
  let rec loop () =
    fill_download_queue ibd;
    if ibd.block_queue = [] && ibd.total_blocks_in_flight = 0 then begin
      (* Flush any remaining UTXO updates *)
      flush_utxos ibd;
      (* Update chain tip *)
      (match get_header_at_height ibd.chain ibd.chain.blocks_synced with
       | Some entry ->
         Storage.ChainDB.set_chain_tip ibd.chain.db entry.hash entry.height
       | None -> ());
      Logs.info (fun m ->
        m "IBD complete at height %d" ibd.chain.blocks_synced);
      ibd.chain.sync_state <- FullySynced;
      Lwt.return_unit
    end else begin
      (* Expire old orphan blocks *)
      ignore (expire_orphan_blocks ibd);
      (* Check for stalled downloads and disconnect bad peers *)
      let stalled_peers = check_stalled_downloads ibd in
      let active_peers = List.filter (fun p ->
        not (List.mem p.Peer.id stalled_peers)
      ) peers in
      List.iter (fun peer_id ->
        Logs.warn (fun m ->
          m "Disconnecting peer %d after %d consecutive stalled downloads"
            peer_id max_consecutive_timeouts);
        (* Remove peer state so it won't be scheduled again *)
        Hashtbl.remove ibd.peer_states peer_id
      ) stalled_peers;
      let%lwt () = request_blocks ibd active_peers in
      (* Short sleep to allow incoming messages *)
      let%lwt () = Lwt_unix.sleep 0.1 in
      (* Process any completed downloads *)
      (match process_downloaded_blocks ibd with
       | Ok n when n > 0 ->
         Logs.info (fun m ->
           m "Processed %d blocks, height now %d, in-flight: %d"
             n ibd.chain.blocks_synced ibd.total_blocks_in_flight)
       | Ok _ -> ()
       | Error e ->
         Logs.err (fun m -> m "Block processing error: %s" e));
      loop ()
    end
  in
  loop ()

(* Start IBD if headers are synced but blocks aren't *)
let start_ibd ?(utxo_set : Utxo.OptimizedUtxoSet.t option)
    (state : chain_state) (peers : Peer.peer list) : unit Lwt.t =
  if state.sync_state <> SyncingBlocks then
    Lwt.return_unit
  else begin
    let tip_height = match state.tip with
      | Some t -> t.height
      | None -> 0
    in
    if state.blocks_synced >= tip_height then begin
      Logs.info (fun m -> m "Blocks already synced to tip");
      state.sync_state <- FullySynced;
      Lwt.return_unit
    end else begin
      Logs.info (fun m ->
        m "Starting IBD from height %d to %d"
          state.blocks_synced tip_height);
      let ibd = create_ibd_state ?utxo_set state in
      run_ibd ibd peers
    end
  end

(* ============================================================================
   Mempool Request Handler
   ============================================================================ *)

(* Maximum number of inventory items to send in response to a mempool message *)
let max_mempool_inv_items = 50_000

(* Handle a MempoolMsg from a peer: respond with an InvMsg listing
   transaction IDs currently in the mempool. *)
let handle_mempool_msg (ibd : ibd_state) (peer : Peer.peer) : unit Lwt.t =
  match ibd.mempool with
  | None ->
    (* No mempool attached — nothing to advertise *)
    Lwt.return_unit
  | Some mp ->
    let count = ref 0 in
    let inv_items = ref [] in
    let feefilter_rate = Int64.to_float peer.feefilter in
    Hashtbl.iter (fun _k (entry : Mempool.mempool_entry) ->
      if !count < max_mempool_inv_items then begin
        (* Convert fee_rate from sat/WU to sat/kB for feefilter comparison:
           sat/kB = sat/WU * 4 * 1000 = sat/WU * 4000 *)
        let fee_rate_per_kb = entry.fee_rate *. 4000.0 in
        if fee_rate_per_kb >= feefilter_rate then begin
          let inv_entry = if peer.Peer.wtxid_relay then
            P2p.{ inv_type = InvWitnessTx; hash = entry.wtxid }
          else
            P2p.{ inv_type = InvTx; hash = entry.txid }
          in
          inv_items := inv_entry :: !inv_items;
          incr count
        end
      end
    ) mp.entries;
    if !inv_items <> [] then
      Lwt.catch
        (fun () -> Peer.send_message peer (P2p.InvMsg !inv_items))
        (fun _exn -> Lwt.return_unit)
    else
      Lwt.return_unit
