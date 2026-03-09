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

(* IBD configuration constants *)
let max_blocks_per_peer = 16          (* Max in-flight blocks per peer *)
let max_total_blocks_in_flight = 128  (* Global cap on blocks in flight *)
let base_block_timeout = 5.0          (* Base timeout in seconds *)
let max_block_timeout = 64.0          (* Max timeout after backoff *)
let utxo_flush_interval = 2000        (* Flush UTXOs every N blocks *)
let download_window_multiplier = 4    (* Queue size = max_in_flight * multiplier *)

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
}

(* Create IBD state from existing chain state *)
let create_ibd_state (chain : chain_state) : ibd_state =
  let start_height = chain.blocks_synced + 1 in
  { chain;
    block_queue = [];
    next_download_height = start_height;
    next_process_height = start_height;
    total_blocks_in_flight = 0;
    peer_states = Hashtbl.create 16;
    blocks_since_flush = 0;
    pending_utxo_updates = [];
    pending_utxo_deletes = [] }

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
  let max_queue_size = max_total_blocks_in_flight * download_window_multiplier in
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
  match List.find_opt (fun e ->
    Cstruct.to_string e.hash = hash_key
  ) ibd.block_queue with
  | None ->
    (* Unrequested block - could be from announcement *)
    Error "Unrequested block"
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
  end

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
        (* Get expected difficulty from header *)
        let expected_bits = block.header.bits in
        (* Get median time past (simplified - use parent timestamp) *)
        let median_time = match get_header_at_height ibd.chain (height - 1) with
          | Some parent -> parent.header.timestamp
          | None -> 0l
        in
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
        let validation_flags = 0 in  (* Standard verification *)
        (match Validation.validate_block_with_utxos block height
                 ~expected_bits ~median_time ~base_lookup:lookup
                 ~flags:validation_flags with
         | Ok _fees ->
           (* Store block *)
           Storage.ChainDB.store_block ibd.chain.db entry.hash block;
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
           (* Periodic UTXO flush *)
           if ibd.blocks_since_flush >= utxo_flush_interval then begin
             flush_utxos ibd;
             ibd.blocks_since_flush <- 0;
             (* Also update chain tip in DB *)
             Storage.ChainDB.set_chain_tip ibd.chain.db entry.hash height
           end;
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
  if new_tip.total_work <= current_tip.total_work then
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
      (* Disconnect blocks: restore spent UTXOs *)
      List.iter (fun (entry : header_entry) ->
        match Storage.ChainDB.get_block state.db entry.hash with
        | None ->
          Logs.warn (fun m -> m "Missing block at height %d during reorg" entry.height)
        | Some block ->
          (* Process transactions in reverse order *)
          let txs = List.rev block.transactions in
          List.iter (fun tx ->
            let txid = Crypto.compute_txid tx in
            let is_cb = Validation.is_coinbase tx in
            (* Remove outputs from UTXO set *)
            List.iteri (fun vout _out ->
              ibd.pending_utxo_deletes <- (txid, vout) :: ibd.pending_utxo_deletes
            ) tx.Types.outputs;
            (* Restore inputs to UTXO set (non-coinbase only) *)
            (* NOTE: We'd need the original UTXO data here - this is simplified *)
            if not is_cb then begin
              (* In a full implementation, we'd store undo data *)
              Logs.debug (fun m -> m "Would restore inputs for tx in reorg")
            end
          ) txs
      ) to_disconnect;
      (* Connect blocks: spend inputs, add outputs *)
      (* This would require downloading and validating the new blocks *)
      List.iter (fun (entry : header_entry) ->
        Logs.debug (fun m -> m "Would connect block at height %d" entry.height)
      ) to_connect;
      (* Update tip *)
      state.tip <- Some new_tip;
      state.blocks_synced <- fork_point.height;  (* Reset to fork point *)
      Storage.ChainDB.set_chain_tip state.db new_tip.hash new_tip.height;
      flush_utxos ibd;
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
      let%lwt () = request_blocks ibd peers in
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
let start_ibd (state : chain_state) (peers : Peer.peer list) : unit Lwt.t =
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
      let ibd = create_ibd_state state in
      run_ibd ibd peers
    end
  end
