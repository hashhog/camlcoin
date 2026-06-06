(* Header-first synchronization (BIP-130) *)
(* Downloads all block headers before downloading full blocks,
   verifying the proof-of-work chain and building the header chain.

   Anti-DoS: Implements PRESYNC/REDOWNLOAD strategy from Bitcoin Core.
   During PRESYNC, we only track cumulative work without storing headers,
   preventing memory exhaustion from low-work header floods. Once sufficient
   work is demonstrated, we REDOWNLOAD and store headers permanently. *)

let log_src = Logs.Src.create "VALIDATION" ~doc:"Block validation"
module Log = (val Logs.src_log log_src : Logs.LOG)
let _ = Log.info  (* suppress unused module warning *)

(* ============================================================================
   Header Sync Anti-DoS: PRESYNC/REDOWNLOAD State Machine
   ============================================================================

   Bitcoin Core uses a two-phase approach to prevent memory exhaustion attacks
   during header synchronization (see headerssync.cpp):

   Phase 1 - PRESYNC:
   - Accept headers without storing them permanently
   - Only track: cumulative_work (32 bytes), last_hash (32 bytes), count (8 bytes)
   - Total memory per peer: ~100 bytes (constant, regardless of chain length)
   - If cumulative_work >= minimum_chain_work, transition to REDOWNLOAD

   Phase 2 - REDOWNLOAD:
   - Re-request all headers from genesis using getheaders
   - Validate PoW and store headers in the block index
   - This ensures we never store headers for chains with insufficient work

   Why this matters:
   - An attacker could send millions of low-difficulty headers
   - Without PRESYNC, we'd store all headers in memory (gigabytes)
   - With PRESYNC, we only use ~100 bytes until work is proven
   ============================================================================ *)

(* REDOWNLOAD phase data, extracted as a named record so it can be referenced
   via [ref] across pattern-match arms (OCaml inline records may not escape). *)
type redownload_data = {
  target_hash : Types.hash256;   (* Hash we're redownloading to — last hash from PRESYNC *)
  redownload_last_hash : Types.hash256;  (* Hash of last redownloaded header (advances) *)
  redownload_last_height : int;          (* Height of last redownloaded header *)
  redownload_first_prev_hash : Types.hash256; (* hashPrevBlock of first buffered header *)
  redownload_chain_work : Cstruct.t;    (* Accumulated work on redownloaded chain *)
  process_all_remaining : bool;  (* True once redownload work >= minimum_required_work *)
  headers_received : int;        (* Headers received during redownload *)
  (* m_redownloaded_headers buffer — headers not yet released to acceptance *)
  buffer : (Types.block_header * Types.hash256) Queue.t;
}

(* Header sync state for anti-DoS protection (per-peer) *)
type header_sync_state =
  | Presync of {
      cumulative_work : Cstruct.t;  (* 32-byte LE cumulative chain work *)
      last_hash : Types.hash256;     (* Hash of last header seen *)
      last_bits : int32;             (* nBits of last header for difficulty validation *)
      count : int;                   (* Number of headers seen in PRESYNC *)
      current_height : int;          (* Height of last header seen in PRESYNC *)
    }
  | Redownload of redownload_data
  | Synced  (* Header sync complete for this peer *)

(* Convert header sync state to string for logging *)
let header_sync_state_to_string = function
  | Presync { count; _ } -> Printf.sprintf "presync (count=%d)" count
  | Redownload { headers_received; buffer; _ } ->
    Printf.sprintf "redownload (received=%d, buffered=%d)" headers_received (Queue.length buffer)
  | Synced -> "synced"

(* Per-peer low-work header sync tracking.
   This state is maintained for each peer doing header sync, and is
   destroyed when the peer disconnects or completes sync. *)
type peer_header_sync = {
  peer_id : int;
  mutable state : header_sync_state;
  mutable last_getheaders_time : float;  (* Rate limiting *)
  chain_start_hash : Types.hash256;       (* Hash where we started syncing *)
  chain_start_height : int;               (* Height where we started syncing *)
  chain_start_bits : int32;               (* nBits at chain_start, for diff transition checks *)
  chain_start_work : Cstruct.t;           (* Cumulative chain work at chain_start *)
  (* Salted hasher keys for 1-bit commitment generation — secret, per-sync-session.
     Mirrors Core's SaltedUint256Hasher (util/hasher.h).  We use SipHash-2-4. *)
  hasher_k0 : int64;
  hasher_k1 : int64;
  (* Secret offset for commitment heights: commitments are taken at heights h
     where (h % HEADER_COMMITMENT_PERIOD) == commit_offset.
     Mirrors Core's m_commit_offset = randrange(commitment_period). *)
  commit_offset : int;
  (* FIFO queue of 1-bit commitments collected during PRESYNC, consumed in REDOWNLOAD.
     Mirrors Core's bitdeque<> m_header_commitments. *)
  header_commitments : bool Queue.t;
  (* Bound on how many commitments an honest peer's chain could ever produce, given the
     6-blocks-per-second MTP rule.  Mirrors Core's m_max_commitments. *)
  max_commitments : int;
}

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

(* Chain state - tracks sync progress and header chain.

   NOTE on `tip` semantics: [tip] is the best-work *header* entry, updated
   by [accept_header] whenever a new header with more cumulative work is
   accepted. It is NOT necessarily the validated-block tip — post-IBD,
   [tip.height] can lead [blocks_synced] while gap-fill is in flight.

   For the validated-block tip (getblockcount-style queries, block-linkage
   checks in validation), use [block_tip] below, which resolves through
   [blocks_synced] and the height->hash index.

   Historical note (W43): [process_new_block] and [connect_stored_blocks]
   used to overwrite [tip] with the just-connected block entry, making
   the field's meaning flip between "header tip" and "block tip" at
   runtime. That conflation caused the W42 mainnet gap-fill regression
   (blocks shelved but never drained because [tip.hash] was the header
   tip's hash). See W43/W44 reports. *)
type chain_state = {
  db : Storage.ChainDB.t;
  network : Consensus.network_config;
  mutable headers : (string, header_entry) Hashtbl.t;
  mutable tip : header_entry option;
  mutable sync_state : sync_state;
  mutable sync_peer : int option;
  mutable headers_synced : int;
  mutable blocks_synced : int;
  mutable prune_target : int;
    (* Pruning target in BYTES (Bitcoin Core convention; init.cpp:524).
         0           = disabled
         1           = manual mode (CLI sentinel; auto-prune does not fire,
                       only the pruneblockchain RPC triggers a sweep — TODO)
         N >= 550 MiB (in bytes) = automatic target.
       The CLI converts --prune=N (MiB) to bytes before assigning here.
       [prune_old_blocks] derives a block-count keep window from this
       byte target via an average-block-size constant. *)
  mutable prune_height : int;    (* last pruned height *)
  headers_from_peer : (int, int) Hashtbl.t;  (* peer_id -> header count from that peer *)
  unconnecting_headers : (int, int) Hashtbl.t;
    (* peer_id -> count of consecutive unconnecting-headers messages.
       Mirrors Bitcoin Core's [nUnconnectingHeaders] in
       net_processing.cpp::ProcessHeadersMessage.  When the count
       exceeds [max_num_unconnecting_headers_msgs] we hand the peer to
       [misbehavior_handler]; on a connecting batch we reset the entry.
       Pre-fix, camlcoin returned [Error "Unknown parent header"] from
       [process_headers] and dropped the sync_peer to Idle without ever
       penalizing the peer — a malicious peer could keep us in a
       getheaders loop indefinitely.  See
       CORE-PARITY-AUDIT/_header-sync-dos-cross-impl-audit-2026-05-06-part1.md
       (Pattern B). *)
  mutable invalidated_blocks : (string, unit) Hashtbl.t;  (* manually invalidated block hashes *)
  peer_headers_sync : (int, peer_header_sync) Hashtbl.t;
    (* Per-peer PRESYNC/REDOWNLOAD state, mirrors Bitcoin Core's
       [Peer.m_headers_sync] (net_processing.cpp).  Populated when a peer's
       first headers batch arrives on a chain whose [tip.total_work] is below
       [network.minimum_chain_work] (the bare from-genesis re-IBD case), and
       cleaned up on disconnect via [cleanup_peer_headers_sync] or on PRESYNC
       failure / REDOWNLOAD completion via the internal sync loop.

       Prior to the 2026-05-28 PRESYNC unwedge, the per-peer state machinery
       in this module ([create_presync_state], [process_presync_headers],
       [process_redownload_headers], …) existed but was NEVER STORED anywhere
       — the live sync loop called [process_headers ~min_pow_checked:false]
       directly, which rejected every from-genesis batch with
       [too-little-chainwork] because the bare batch's chainwork is far below
       [minimum_chain_work].  On mainnet camlcoin this manifested as 985+
       retries of the same getheaders-then-reject cycle pinning the node at
       h=0.  Mirrors the nimrod PRESYNC unwedge of 2026-05-27/28
       (commits 4deead0 + 1c82891) — see
       CORE-PARITY-AUDIT/_nimrod-presync-part2-2026-05-27.md and
       _nimrod-presync-part3-2026-05-28.md. *)
  mutable block_submission_paused : bool;
  (* NetworkDisable flag (Bitcoin Core
     [src/rpc/blockchain.cpp::NetworkDisable] around [TemporaryRollback]).
     When true, [submitblock] and any P2P block-handler callsite that
     consults this flag must refuse new blocks. Set during
     [dumptxoutset rollback]'s rewind→dump→replay dance so peers cannot
     race a new block into the chain mid-rewind; cleared on every exit
     path. Peers stay connected; only block acceptance is gated. *)
  mutable bip157_index : Block_index.bip157_index option;
  (* BIP-157/158 basic block filter index handle.

     [Some _] when the daemon was started with --blockfilterindex=basic
     (or its boolean-equivalent forms; see [bin/main.ml]); [None]
     otherwise. Every connect-block path in this module calls
     [Block_index.append_block_filter] when this is [Some], in lockstep
     with the validated-tip advance, so the filter index never lags or
     leads the active chain by more than one block. Reorgs call
     [Block_index.rewind_bip157_index] from [reorganize]'s disconnect
     half. The handle is created in [cli.ml] (Cli.run) after
     [restore_chain_state] returns and before any IBD or post-IBD block
     listener is wired; [cli.ml]'s graceful-shutdown phase calls
     [Block_index.close_bip157_index] on the way down. The REST handler
     in [rest.ml] reads through the legacy [Rpc.rpc_context.filter_index]
     pointer which we point at this same [filter_idx] sub-handle; the
     bundle here is just the orchestration sidecar (height->hash + atomic
     append/rewind helpers).

     Mirrors Bitcoin Core's [BlockFilterIndex] singleton attached to
     [ChainstateManager] via [g_indexes_ready_to_sync]
     ([src/index/blockfilterindex.cpp]). *)
  mutable wallet_scan_hook : (Types.block -> int -> unit) option;
  (* Wallet block-connect notification, mirroring Bitcoin Core's
     [CWallet::blockConnected] (wallet/wallet.cpp).  Installed by [cli.ml] /
     [bin/main.ml] right after the wallet is loaded when one is enabled, and
     invoked by every block-connect choke-point (currently [Mining.submit_block]
     for the mining / generate* / submitblock paths) *after* the block has been
     fully validated and the validated tip advanced.  The callback credits
     wallet-owned outputs and debits spent wallet UTXOs (see
     [Wallet.scan_block]).  A generic [Types.block -> int -> unit] callback is
     used (rather than a direct [Wallet.t] reference) so the [Sync] module stays
     independent of [Wallet] and there is no module cycle.  [None] when no
     wallet is loaded.  Best-effort: a wallet-side failure must never roll back
     an already-validated, already-connected block. *)
  mutable wallet_unscan_hook : (Types.block -> int -> unit) option;
  (* Symmetric counterpart to [wallet_scan_hook] for a block being
     disconnected (reorg), mirroring [CWallet::blockDisconnected].  Removes the
     wallet credits the disconnected block created so a reorg cannot leave the
     ledger over-counting coins that no longer exist on the active chain. *)
}

(* Header flood prevention: reject new headers when this limit is reached
   and chain work is below the network's minimum_chain_work. *)
let max_headers_in_memory = 1_000_000

(* Header sync timeout constants *)
let headers_download_timeout = 900.0  (* 15 min total for header download *)
let headers_response_timeout = 120.0  (* 2 min per header response *)

(* Per-peer header flood threshold *)
let max_headers_per_peer = 2_000_000  (* Allow full mainnet header sync from a single peer *)

(* Bitcoin Core's MAX_NUM_UNCONNECTING_HEADERS_MSGS (net_processing.cpp).
   A peer that delivers more than this many successive unconnecting-
   headers messages is misbehavior-scored and disconnected.  Tolerates
   up to 10 transient unlinked batches before taking action — matches
   Core, looser than the legacy "drop sync_peer on first orphan"
   behavior and stricter than "never penalize". *)
let max_num_unconnecting_headers_msgs = 10

(* PRESYNC/REDOWNLOAD constants *)
let max_headers_per_message = 2000    (* Protocol limit on headers per message *)
let getheaders_rate_limit = 2.0       (* Minimum seconds between getheaders requests *)

(* headerssync.cpp HEADER_COMMITMENT_PERIOD = 600 (every 600th block gets a commitment) *)
let header_commitment_period = 600

(* headerssync.cpp REDOWNLOAD_BUFFER_SIZE = 14304 (headers buffered before releasing for
   acceptance; chosen so that buffer holds at least several commitment periods worth) *)
let redownload_buffer_size = 14304

(* Maximum future block time per Bitcoin Core consensus (2 hours = 7200 seconds).
   Used in the max_commitments bound (headerssync.cpp constructor line 42). *)
let max_future_block_time_secs = 7200

(* 6 blocks/second is the fastest physically possible block rate given the MTP rule
   (each block's timestamp must exceed the median of the prior 11, so at most 6
   consecutive blocks can be produced per second against a rolling window).
   Mirrors the constant in headerssync.cpp line 43. *)
let max_blocks_per_second = 6

(* Generate random uint64 from /dev/urandom. *)
let random_uint64 () : int64 =
  let ic = open_in_bin "/dev/urandom" in
  let buf = Bytes.create 8 in
  really_input ic buf 0 8;
  close_in ic;
  (* Read as little-endian int64 *)
  let b i = Int64.of_int (Char.code (Bytes.get buf i)) in
  let ( lsl ) = Int64.shift_left in
  let ( lor ) = Int64.logor in
  (b 0) lor ((b 1) lsl 8) lor ((b 2) lsl 16) lor ((b 3) lsl 24)
  lor ((b 4) lsl 32) lor ((b 5) lsl 40) lor ((b 6) lsl 48) lor ((b 7) lsl 56)

(* Salted 1-bit commitment hash of a block hash.
   Mirrors Core's SaltedUint256Hasher (util/hasher.h) + the "&1" extraction in
   headerssync.cpp:197,263.  We use camlcoin's existing SipHash-2-4 implementation. *)
let commitment_bit ~(k0 : int64) ~(k1 : int64) ~(hash : Types.hash256) : bool =
  let result = Crypto.SipHash.hash_uint256 k0 k1 hash in
  Int64.logand result 1L = 1L

(* ============================================================================
   PRESYNC/REDOWNLOAD Implementation
   ============================================================================ *)

(* Create initial PRESYNC state for a peer.
   chain_start is the header entry where we fork from our known chain.

   Bug fixes vs the original:
   Bug 1/3/4: now creates random hasher keys + commit_offset + max_commitments bound.
   Bug 8: cumulative_work starts from chain_start.total_work not zero. *)
let create_presync_state ~(peer_id : int) ~(chain_start : header_entry)
    : peer_header_sync =
  (* Random salted hasher keys — mirrors Core's m_hasher(SaltedUint256Hasher)
     and m_commit_offset = randrange(commitment_period). *)
  let hasher_k0 = random_uint64 () in
  let hasher_k1 = random_uint64 () in
  let commit_offset =
    let raw = random_uint64 () in
    (* Take absolute value mod commitment_period *)
    let v = Int64.to_int (Int64.logand raw (Int64.of_int (header_commitment_period - 1))) in
    ((v mod header_commitment_period) + header_commitment_period) mod header_commitment_period
  in
  (* m_max_commitments = 6 * max_seconds_since_start / commitment_period.
     max_seconds_since_start = now - chain_start.MTP + max_future_block_time.
     Core uses the MTP of chain_start; we approximate with chain_start timestamp. *)
  let chain_start_ts = Int32.to_int chain_start.header.timestamp in
  let now = int_of_float (Unix.gettimeofday ()) in
  let max_seconds = (now - chain_start_ts) + max_future_block_time_secs in
  let max_commitments =
    if max_seconds <= 0 then 0
    else max_blocks_per_second * max_seconds / header_commitment_period
  in
  {
    peer_id;
    state = Presync {
      cumulative_work = Cstruct.of_string (Cstruct.to_string chain_start.total_work);  (* Bug 8: init from chain_start work *)
      last_hash = chain_start.hash;
      last_bits = chain_start.header.bits;
      count = 0;
      current_height = chain_start.height;
    };
    last_getheaders_time = 0.0;
    chain_start_hash = chain_start.hash;
    chain_start_height = chain_start.height;
    chain_start_bits = chain_start.header.bits;
    chain_start_work = Cstruct.of_string (Cstruct.to_string chain_start.total_work);
    hasher_k0;
    hasher_k1;
    commit_offset;
    header_commitments = Queue.create ();
    max_commitments;
  }

(* Validate a single header during PRESYNC (minimal validation without storage).
   Checks: prev_block continuity, permitted_difficulty_transition, proof-of-work validity.
   Does NOT check: timestamp or MTP.
   Returns: Ok (hash, work, bits) or Error message

   Bug 5 fix: now calls permitted_difficulty_transition (was missing entirely). *)
let validate_presync_header ~(network : Consensus.network_config)
    ~(next_height : int) ~(prev_bits : int32)
    ~(expected_prev : Types.hash256)
    ~(header : Types.block_header) : (Types.hash256 * Cstruct.t * int32, string) result =
  let hash = Crypto.compute_block_hash header in
  (* Check prev_block links to expected *)
  if not (Cstruct.equal header.prev_block expected_prev) then
    Error "PRESYNC: header prev_block mismatch"
  (* Bug 5: check difficulty transition is within permitted bounds.
     Mirrors Core headerssync.cpp:189-193 (ValidateAndProcessSingleHeader). *)
  else if not (Consensus.permitted_difficulty_transition ~network ~height:next_height
                 ~old_nbits:prev_bits ~new_nbits:header.bits) then
    Error (Printf.sprintf "PRESYNC: invalid difficulty transition at height %d" next_height)
  (* Check proof of work *)
  else if not (Consensus.hash_meets_target hash header.bits) then
    Error "PRESYNC: insufficient proof of work"
  else
    let work = Consensus.work_from_compact header.bits in
    Ok (hash, work, header.bits)

(* Process headers during PRESYNC phase.
   Validates each header minimally, checks difficulty transitions, accumulates work,
   and stores 1-bit salted hash commitments for every N-th header.

   Bug 1 fix: now stores commitment bits in ps.header_commitments.
   Bug 3 fix: enforces max_commitments bound.
   Bug 5 fix: calls permitted_difficulty_transition via validate_presync_header.
   Bug 8 fix: cumulative_work was already fixed in create_presync_state. *)
let process_presync_headers ~(ps : peer_header_sync)
    ~(headers : Types.block_header list)
    ~(network : Consensus.network_config)
    : (int, string) result =
  match ps.state with
  | Presync presync_data ->
    let cumulative_work = ref presync_data.cumulative_work in
    let last_hash = ref presync_data.last_hash in
    let last_bits = ref presync_data.last_bits in
    let count = ref presync_data.count in
    let current_height = ref presync_data.current_height in
    let error = ref None in
    List.iter (fun header ->
      if !error = None then begin
        let next_height = !current_height + 1 in
        match validate_presync_header ~network ~next_height ~prev_bits:!last_bits
                ~expected_prev:!last_hash ~header with
        | Error e -> error := Some e
        | Ok (hash, work, bits) ->
          (* Bug 1: store a 1-bit salted commitment at every commitment_period-th block.
             Mirrors Core headerssync.cpp:195-205 (ValidateAndProcessSingleHeader). *)
          if next_height mod header_commitment_period = ps.commit_offset then begin
            let bit = commitment_bit ~k0:ps.hasher_k0 ~k1:ps.hasher_k1 ~hash in
            Queue.push bit ps.header_commitments;
            (* Bug 3: enforce max_commitments memory bound *)
            if Queue.length ps.header_commitments > ps.max_commitments then begin
              error := Some (Printf.sprintf
                "PRESYNC: exceeded max commitments (%d) at height %d (peer %d)"
                ps.max_commitments next_height ps.peer_id)
            end
          end;
          if !error = None then begin
            cumulative_work := Consensus.work_add !cumulative_work work;
            last_hash := hash;
            last_bits := bits;
            current_height := next_height;
            incr count
          end
      end
    ) headers;
    begin match !error with
    | Some e -> Error e
    | None ->
      (* Update PRESYNC state *)
      let new_state = Presync {
        cumulative_work = !cumulative_work;
        last_hash = !last_hash;
        last_bits = !last_bits;
        count = !count;
        current_height = !current_height;
      } in
      ps.state <- new_state;
      (* Check if we should transition to REDOWNLOAD.
         Mirrors Core headerssync.cpp:165-173. *)
      if Consensus.work_compare !cumulative_work network.minimum_chain_work >= 0 then begin
        Logs.info (fun m ->
          m "PRESYNC complete for peer %d: height=%d count=%d, work >= minimum_chain_work"
            ps.peer_id !current_height !count);
        (* Transition to REDOWNLOAD.
           Bug 9 fix: redownload starts from chain_start (not genesis).
           Redownload buffer initially empty; redownload_last_hash = chain_start.hash. *)
        ps.state <- Redownload {
          target_hash = !last_hash;
          redownload_last_hash = ps.chain_start_hash;
          redownload_last_height = ps.chain_start_height;
          redownload_first_prev_hash = ps.chain_start_hash;
          redownload_chain_work = Cstruct.of_string (Cstruct.to_string ps.chain_start_work);
          process_all_remaining = false;
          headers_received = 0;
          buffer = Queue.create ();
        };
      end;
      Ok (List.length headers)
    end
  | Redownload _ | Synced ->
    Error "process_presync_headers called in wrong state"

(* Check if peer should use low-work header sync (PRESYNC/REDOWNLOAD).
   Returns true if the peer's announced work is below minimum_chain_work
   and we should use the anti-DoS mechanism. *)
let needs_lowwork_sync ~(chain_state : chain_state) : bool =
  let tip_work = match chain_state.tip with
    | Some t -> t.total_work
    | None -> Consensus.zero_work
  in
  Consensus.work_compare tip_work chain_state.network.minimum_chain_work < 0


(* Process headers during REDOWNLOAD phase.
   These headers are validated, stored in a buffer, and released to permanent
   storage only once the buffer is deep enough (commitment safety margin).

   Bug 2 fix: now verifies commitment bits against stored PRESYNC commitments.
   Bug 6 fix: calls permitted_difficulty_transition.
   Bug 7 fix: uses redownload_buffer_size before releasing to acceptance.
   Bug 10 fix: implements process_all_remaining flag.
   Bug 9 fix: build_redownload_locator now uses chain_start_hash (see below). *)
let process_redownload_headers ~(ps : peer_header_sync)
    ~(headers : Types.block_header list)
    ~(chain_state : chain_state)
    : (Types.block_header list, string) result =
  match ps.state with
  | Redownload rd_data ->
    let error = ref None in
    let rd = ref rd_data in
    List.iter (fun (header : Types.block_header) ->
      if !error = None then begin
        let next_height = !rd.redownload_last_height + 1 in
        (* Check prev_block continuity — mirrors Core headerssync.cpp:224-227. *)
        if not (Cstruct.equal header.prev_block !rd.redownload_last_hash) then
          error := Some (Printf.sprintf
            "REDOWNLOAD: non-continuous headers at height %d (peer %d)" next_height ps.peer_id)
        else begin
          (* Bug 6: check difficulty transition — mirrors Core headerssync.cpp:230-240.
             previous_nBits = back of buffer's nBits, or chain_start_bits if buffer empty. *)
          let previous_nBits =
            if Queue.is_empty !rd.buffer then ps.chain_start_bits
            else begin
              let last = ref ps.chain_start_bits in
              Queue.iter (fun ((h : Types.block_header), _) -> last := h.bits) !rd.buffer;
              !last
            end
          in
          if not (Consensus.permitted_difficulty_transition ~network:chain_state.network
                    ~height:next_height ~old_nbits:previous_nBits ~new_nbits:header.bits) then
            error := Some (Printf.sprintf
              "REDOWNLOAD: invalid difficulty transition at height %d (peer %d)" next_height ps.peer_id)
          else begin
            (* Track work on redownloaded chain — mirrors Core headerssync.cpp:243-248. *)
            let new_chain_work = Consensus.work_add !rd.redownload_chain_work
                (Consensus.work_from_compact header.bits) in
            let process_all =
              !rd.process_all_remaining ||
              Consensus.work_compare new_chain_work chain_state.network.minimum_chain_work >= 0
            in
            (* Bug 2: verify commitment bit if applicable.
               Mirrors Core headerssync.cpp:256-269.
               Skip commitment check once process_all is set — peer may have
               extended its chain since PRESYNC so commitments can run out. *)
            let hash = Crypto.compute_block_hash header in
            if not process_all &&
               next_height mod header_commitment_period = ps.commit_offset then begin
              if Queue.is_empty ps.header_commitments then
                error := Some (Printf.sprintf
                  "REDOWNLOAD: commitment overrun at height %d (peer %d)" next_height ps.peer_id)
              else begin
                let expected_bit = Queue.pop ps.header_commitments in
                let actual_bit = commitment_bit ~k0:ps.hasher_k0 ~k1:ps.hasher_k1 ~hash in
                if actual_bit <> expected_bit then
                  error := Some (Printf.sprintf
                    "REDOWNLOAD: commitment mismatch at height %d (peer %d)" next_height ps.peer_id)
              end
            end;
            if !error = None then begin
              (* Store in buffer — mirrors Core m_redownloaded_headers.emplace_back *)
              Queue.push (header, hash) !rd.buffer;
              rd := { !rd with
                redownload_last_height = next_height;
                redownload_last_hash = hash;
                redownload_chain_work = new_chain_work;
                process_all_remaining = process_all;
                headers_received = !rd.headers_received + 1;
              }
            end
          end
        end
      end
    ) headers;
    begin match !error with
    | Some e -> Error e
    | None ->
      (* Release headers ready for acceptance (buffer deep enough or process_all).
         Mirrors Core's PopHeadersReadyForAcceptance call in ProcessNextHeaders. *)
      let ready = ref [] in
      let first_prev = ref !rd.redownload_first_prev_hash in
      let keep_going = ref true in
      while !keep_going && not (Queue.is_empty !rd.buffer) do
        if Queue.length !rd.buffer > redownload_buffer_size || !rd.process_all_remaining then begin
          let ((hdr : Types.block_header), _) = Queue.pop !rd.buffer in
          let full_hdr = Types.{ hdr with prev_block = !first_prev } in
          first_prev := Crypto.compute_block_hash full_hdr;
          ready := full_hdr :: !ready
        end else
          keep_going := false
      done;
      (* Update first_prev_hash in rd state *)
      rd := { !rd with redownload_first_prev_hash = !first_prev };
      ps.state <- Redownload !rd;
      let released = List.rev !ready in
      (* Now store all released headers into chain state (permanent storage).
         This is the equivalent of the caller processing pow_validated_headers. *)
      List.iter (fun (header : Types.block_header) ->
        let hash = Crypto.compute_block_hash header in
        let hash_key = Cstruct.to_string hash in
        if not (Hashtbl.mem chain_state.headers hash_key) then begin
          let parent_key = Cstruct.to_string header.prev_block in
          match Hashtbl.find_opt chain_state.headers parent_key with
          | None -> () (* skip if parent not known yet; will be linked later *)
          | Some parent ->
            let height = parent.height + 1 in
            let work = Consensus.work_add parent.total_work
                (Consensus.work_from_compact header.bits) in
            let entry = { header; hash; height; total_work = work } in
            Hashtbl.replace chain_state.headers hash_key entry;
            Storage.ChainDB.store_block_header chain_state.db hash header;
            Storage.ChainDB.set_height_hash chain_state.db height hash;
            let is_new_tip = match chain_state.tip with
              | None -> true
              | Some tip -> Consensus.work_compare work tip.total_work > 0
            in
            if is_new_tip then begin
              chain_state.tip <- Some entry;
              Storage.ChainDB.set_header_tip chain_state.db hash height;
              chain_state.headers_synced <- height
            end
        end
      ) released;
      (* Check if REDOWNLOAD is complete (buffer drained and process_all set,
         or we've hit the target hash). *)
      let final_rd = match ps.state with
        | Redownload r -> r
        | _ -> !rd
      in
      let complete =
        Queue.is_empty final_rd.buffer && final_rd.process_all_remaining
      in
      if complete then begin
        Logs.info (fun m ->
          m "REDOWNLOAD complete for peer %d: height=%d, %d headers stored"
            ps.peer_id final_rd.redownload_last_height final_rd.headers_received);
        ps.state <- Synced
      end;
      Ok released
    end
  | Presync _ | Synced ->
    Error "process_redownload_headers called in wrong state"

(* Determine which state a header sync message should be processed in.
   Used by the sync loop to dispatch to the correct handler. *)
let get_header_sync_phase (ps : peer_header_sync) : [`Presync | `Redownload | `Synced] =
  match ps.state with
  | Presync _ -> `Presync
  | Redownload _ -> `Redownload
  | Synced -> `Synced

(* Build a getheaders locator for REDOWNLOAD phase.
   Returns a locator starting from the redownload cursor (last accepted hash).

   Bug 9 fix: was always returning the genesis hash, forcing a full re-download
   from block 0 even when the chain_start was at height 900k.  Core uses
   m_redownload_buffer_last_hash (initialized to chain_start.GetBlockHash()),
   which starts at chain_start and advances as headers are accepted. *)
let build_redownload_locator (ps : peer_header_sync) (chain_state : chain_state)
    : Types.hash256 list =
  match ps.state with
  | Redownload rd ->
    (* Start from the last accepted redownloaded hash, with chain_start as fallback. *)
    [rd.redownload_last_hash]
    @ (* Append chain_start locator entries as per Core's NextHeadersRequestLocator *)
    (let chain_start_entry_opt = Hashtbl.find_opt chain_state.headers
         (Cstruct.to_string ps.chain_start_hash) in
     match chain_start_entry_opt with
     | None -> [ps.chain_start_hash]
     | Some _ -> [ps.chain_start_hash])
  | _ ->
    (* Fallback: genesis (should not be reached in normal operation) *)
    [Crypto.compute_block_hash chain_state.network.genesis_header]

(* Build a getheaders locator for PRESYNC continuation.
   Returns a locator with just the last known hash.

   NOTE: this is the legacy 1-entry-only locator kept for the existing tests.
   The live sync loop uses [build_presync_locator_full] below, which is the
   Core-parity version that prepends the per-phase continue-from hash and
   then appends the exponential-backoff locator from [chain_start] back to
   genesis (mirrors Core headerssync.cpp:296 NextHeadersRequestLocator). *)
let build_presync_locator (ps : peer_header_sync) : Types.hash256 list =
  match ps.state with
  | Presync { last_hash; _ } -> [last_hash]
  | Redownload { target_hash; _ } -> [target_hash]
  | Synced -> []

(* Forward-declaration site: [build_presync_locator_full] needs
   [build_locator_from_height] which is defined below alongside [build_locator]
   to keep all locator code clustered.  See [build_presync_locator_full] below
   for the full-locator implementation that is wired into the live sync loop.
*)

(* Should we request more headers from this peer?
   Checks rate limiting and whether sync is complete. *)
let should_request_more_headers (ps : peer_header_sync) : bool =
  match ps.state with
  | Synced -> false
  | Presync _ | Redownload _ ->
    let now = Unix.gettimeofday () in
    now -. ps.last_getheaders_time >= getheaders_rate_limit

(* Mark that we sent a getheaders request (for rate limiting) *)
let mark_getheaders_sent (ps : peer_header_sync) : unit =
  ps.last_getheaders_time <- Unix.gettimeofday ()

(* Compute proof-of-work from compact target (nBits) as a 256-bit integer.
   Delegates to Consensus.work_from_compact which uses
   (~target / (target + 1)) + 1 to avoid 2^256 overflow. *)
let work_from_bits (bits : int32) : Cstruct.t =
  Consensus.work_from_compact bits

(* Create initial chain state with genesis block *)
let create_chain_state (db : Storage.ChainDB.t)
    (network : Consensus.network_config) : chain_state =
  (* Defense-in-depth: verify the BIP9 deployment records and the buried
     activation heights on [network_config] agree.  See the comment block
     in consensus.ml above [get_deployment_state] for the full rationale.
     A mismatch is a chainparams misconfiguration and is fatal. *)
  (match Consensus.check_buried_deployment_consistency network with
   | Ok () -> ()
   | Error msg ->
     Logs.err (fun m -> m "Fatal: %s" msg);
     failwith msg);
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
    unconnecting_headers = Hashtbl.create 16;
    invalidated_blocks = Hashtbl.create 16;
    peer_headers_sync = Hashtbl.create 16;
    block_submission_paused = false;
    bip157_index = None;
    wallet_scan_hook = None;
    wallet_unscan_hook = None;
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
  (* Defense-in-depth: same BIP9/buried-deployment parity check as
     [create_chain_state].  Even on the restore path, a mismatch must
     be caught before we resume validating blocks. *)
  (match Consensus.check_buried_deployment_consistency network with
   | Ok () -> ()
   | Error msg ->
     Logs.err (fun m -> m "Fatal: %s" msg);
     failwith msg);
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
    unconnecting_headers = Hashtbl.create 16;
    invalidated_blocks = Hashtbl.create 16;
    peer_headers_sync = Hashtbl.create 16;
    block_submission_paused = false;
    bip157_index = None;
    wallet_scan_hook = None;
    wallet_unscan_hook = None;
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
    (* Restore validated block height from chain_tip (separate from header_tip).
       chain_tip is only written after successful UTXO flush, so it always
       points to a height with consistent UTXO state. *)
    (match Storage.ChainDB.get_chain_tip db with
     | Some (_chain_hash, chain_height) ->
       state.blocks_synced <- chain_height
     | None -> ());
    (* ---- AssumeUTXO snapshot-bootstrap forward-sync repair (3-layer fix) ----
       After [load_snapshot_into_primary], the DB carries:
         - header_tip + chain_tip at the snapshot base (e.g. 944183),
         - a height->hash row for the base,
         - genesis's header (seeded by the loader),
       but NOT the base block's real header bytes (a UTXO snapshot carries no
       headers).  The restore loop above therefore skips the base height
       ([get_block_header] miss at line ~757), so [state.tip] is left = None
       even though [headers_synced]/[blocks_synced] = base height.

       That broken state stalls forward-sync at the base for three reasons,
       the three layers of the assumeUTXO forward-sync bug:

         LAYER 1 (chainwork): with no in-memory tip, every peer-served header
           batch is routed through the PRESYNC/low-work pipeline and its
           cumulative work is computed from ~0, so it never clears
           [minimum_chain_work] cleanly and honest peers risk header-flood
           scoring.
         LAYER 2 (base block-index): block base+1's parent (the base) is absent
           from the connectable in-memory header table, so [get_header_at_height
           base] and the [validate_header] parent lookup both miss -> the base+1
           header never connects and [fill_download_queue] (gated on
           [state.tip.height]) never requests a single forward block.
         LAYER 3 (MTP window): the first ~11 post-base blocks have a
           median-time-past window reaching below the un-indexed base, so
           [compute_median_time_past] returns nothing -> nLockTimeCutoff = 0 ->
           time-locked txs fail bad-txns-nonfinal.

       Fix (nimrod's proven header-persist model, network/sync.nim:1229-1271):
       re-anchor the in-memory tip to genesis and rewind [headers_synced] to 0
       so the from-genesis P2P header sync rebuilds the FULL header chain.
       camlcoin already persists every accepted header to the block-index DB
       (accept_header / process_redownload_headers store header + height->hash
       and advance header_tip), so once header sync passes the base:
         - the base acquires a REAL header row carrying its REAL cumulative
           chainwork (LAYER 1 + LAYER 2 — chainwork accrues header-by-header
           from genesis, exactly as it would on a from-genesis IBD), and
         - heights base-10 .. base are all in memory with their REAL
           timestamps, so the MTP window for base+1 .. base+11 is exact, no
           proxy needed (LAYER 3).
       Block bodies still resume at base+1: [blocks_synced] is intentionally
       LEFT at the snapshot base (the UTXO set is already there); only the
       header chain is rebuilt (headers are the cheap part assumeUTXO does NOT
       skip).  This touches ONLY the forward-sync header bootstrap; the reorg
       path is untouched.

       Detection is conservative: trigger ONLY when the restore left no
       in-memory tip while [headers_synced] claims a non-genesis height AND
       genesis itself is present to re-anchor on.  A normal restart (whose
       header_tip header bytes ARE on disk) sets [state.tip] in the loop and
       never enters this branch. *)
    let genesis_hash = Crypto.compute_block_hash network.genesis_header in
    let genesis_entry =
      Hashtbl.find_opt state.headers (Cstruct.to_string genesis_hash) in
    (match state.tip, genesis_entry with
     | None, Some gen when state.headers_synced > 0 ->
       Logs.warn (fun m ->
         m "Snapshot-bootstrap detected (header_tip at height %d has no header \
            bytes on disk); re-anchoring header sync to genesis to rebuild the \
            header chain forward past the snapshot base. UTXO set + \
            blocks_synced=%d are preserved."
           state.headers_synced state.blocks_synced);
       state.tip <- Some gen;
       state.headers_synced <- 0
       (* blocks_synced intentionally left at the snapshot base. *)
     | _ -> ());
    (* Load invalidated blocks from database *)
    List.iter (fun hash ->
      Hashtbl.replace state.invalidated_blocks (Cstruct.to_string hash) ()
    ) (Storage.ChainDB.get_all_invalidated_blocks db);
    state
  | None ->
    (* No stored state, create fresh with genesis *)
    create_chain_state db network

(* Install / replace the wallet block-connect + block-disconnect notification
   callbacks.  Called once by [cli.ml] / [bin/main.ml] after the wallet is
   loaded.  Both default to [None] (no wallet loaded). *)
let set_wallet_hooks (state : chain_state)
    ?(on_connect : (Types.block -> int -> unit) option)
    ?(on_disconnect : (Types.block -> int -> unit) option) () : unit =
  (match on_connect with Some _ -> state.wallet_scan_hook <- on_connect | None -> ());
  (match on_disconnect with Some _ -> state.wallet_unscan_hook <- on_disconnect | None -> ())

(* Invoke the wallet block-connect hook for a freshly-connected block, if one
   is installed.  Best-effort: a wallet-side exception is logged and swallowed
   so it can never roll back an already-validated, already-connected block
   (mirrors Core's CWallet notifications running off the validation thread). *)
let run_wallet_scan_hook (state : chain_state) (block : Types.block)
    (height : int) : unit =
  match state.wallet_scan_hook with
  | None -> ()
  | Some f ->
    (try f block height with exn ->
      Logs.warn (fun m ->
        m "wallet block-connect scan raised at height %d (ignored): %s"
          height (Printexc.to_string exn)))

(* Invoke the wallet block-disconnect hook for a block being removed on a
   reorg, if one is installed.  Best-effort, same rationale as
   [run_wallet_scan_hook]. *)
let run_wallet_unscan_hook (state : chain_state) (block : Types.block)
    (height : int) : unit =
  match state.wallet_unscan_hook with
  | None -> ()
  | Some f ->
    (try f block height with exn ->
      Logs.warn (fun m ->
        m "wallet block-disconnect unscan raised at height %d (ignored): %s"
          height (Printexc.to_string exn)))

(* Average block size used to convert a byte-denominated [prune_target] into
   a block-count keep window. 1.5 MB matches lunarblock's AVG_BLOCK_SIZE
   (src/prune.lua:41) and is a conservative-on-the-keep-side estimate for
   post-segwit mainnet (avg ~1.3 MB; matters only as a soft target). *)
let avg_block_size_bytes = 1_500_000

(* Prune old block data to save disk space.
   [prune_target] is in BYTES (Bitcoin Core convention), or the literal
   sentinel value [1] for `--prune=1` manual mode (init.cpp:524 /
   blockmanager_args.cpp:27): node is in prune mode but automatic prunes
   do NOT fire — only the pruneblockchain RPC may delete data. Maps to
   Core's unreachable PRUNE_TARGET_MANUAL = uint64::MAX sentinel.

   The keep window for automatic mode is derived as
   [target_bytes / avg_block_size_bytes], floored at 288
   (MIN_BLOCKS_TO_KEEP). Also deletes undo data for very old blocks beyond
   the keep window + 288.
   Reference: bitcoin-core/src/node/blockstorage.cpp FindFilesToPrune. *)
let prune_old_blocks (state : chain_state) (current_height : int) : unit =
  if state.prune_target <= 0 then ()
  else if state.prune_target = 1 then
    (* `--prune=1` manual-mode sentinel: in prune mode, but auto-prune
       trigger never fires. The pruneblockchain RPC (when shipped) is
       the only path that may advance prune_height. *)
    ()
  else
    let min_keep = 288 in  (* Bitcoin Core MIN_BLOCKS_TO_KEEP *)
    let target_blocks = state.prune_target / avg_block_size_bytes in
    let keep_blocks = max target_blocks min_keep in
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
          (* BIP-94 timewarp protection: at retarget boundaries on testnet4,
             the new block's timestamp must not predate the parent's by more
             than MAX_TIMEWARP=600 seconds.
             Reference: bitcoin-core/src/validation.cpp
                        ContextualCheckBlockHeader:4097-4104. *)
          if not (Consensus.check_timewarp_rule
                    ~height
                    ~header_time:header.timestamp
                    ~prev_block_time:parent.header.timestamp
                    ~network:state.network) then
            Error "time-timewarp-attack"
          else
          (* Checkpoint enforcement: if this height has a checkpoint,
             the header hash must match the expected checkpoint hash *)
          match Consensus.verify_checkpoint height hash state.network with
          | Consensus.CheckpointMismatch _ as mismatch ->
            Error (Consensus.checkpoint_result_to_string mismatch)
          | Consensus.CheckpointOk ->
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
(* Record that [peer_id] just sent us a headers message whose first header
   doesn't connect to our chain.  Returns [true] if the per-peer counter
   has exceeded [max_num_unconnecting_headers_msgs] (caller must
   misbehavior-score and disconnect the peer); returns [false] otherwise
   (caller should re-issue getheaders to drive Core's
   FindForkInGlobalIndex behavior).  Mirrors Bitcoin Core's
   [nUnconnectingHeaders] accounting in
   net_processing.cpp::ProcessHeadersMessage. *)
let note_unconnecting_headers (state : chain_state) (peer_id : int) : bool =
  let prev =
    match Hashtbl.find_opt state.unconnecting_headers peer_id with
    | Some n -> n
    | None -> 0
  in
  let next = prev + 1 in
  Hashtbl.replace state.unconnecting_headers peer_id next;
  next > max_num_unconnecting_headers_msgs

(* Reset the unconnecting-headers counter for [peer_id].  Called after
   any successful connecting batch from this peer, mirroring Core's
   [nUnconnectingHeaders = 0] in the success path of
   ProcessHeadersMessage.  Idempotent — no-op if no entry exists. *)
let reset_unconnecting_headers (state : chain_state) (peer_id : int) : unit =
  Hashtbl.remove state.unconnecting_headers peer_id

(* Read the current unconnecting-headers count for [peer_id]; used by tests. *)
let unconnecting_headers_count (state : chain_state) (peer_id : int) : int =
  match Hashtbl.find_opt state.unconnecting_headers peer_id with
  | Some n -> n
  | None -> 0

(* Look up the per-peer PRESYNC/REDOWNLOAD state, if any.  Returns [None] if
   the peer is not currently using the anti-DoS header-sync pipeline (the
   common steady-state case for any peer past the [minimum_chain_work]
   threshold). *)
let get_peer_headers_sync (state : chain_state) (peer_id : int)
    : peer_header_sync option =
  Hashtbl.find_opt state.peer_headers_sync peer_id

(* Drop the per-peer PRESYNC/REDOWNLOAD state for a disconnected peer.
   Mirrors Bitcoin Core's [Peer::m_headers_sync.reset(nullptr)] in
   [net_processing.cpp::ProcessHeadersMessage] error paths and
   [PeerManagerImpl::FinalizeNode].  Idempotent — no-op if no entry exists. *)
let cleanup_peer_headers_sync (state : chain_state) (peer_id : int) : unit =
  Hashtbl.remove state.peer_headers_sync peer_id

let process_headers ?(min_pow_checked = true) (state : chain_state)
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
    let rejected = ref 0 in
    let first_error = ref None in
    let error = ref None in
    List.iter (fun header ->
      if !error = None then
        match validate_header state header with
        | Ok entry ->
          (* G8: per-header minimum-chain-work gate.
             Core: bitcoin-core/src/validation.cpp:4229 —
               if (!min_pow_checked)
                 return state.Invalid(BLOCK_HEADER_LOW_WORK,
                                      "too-little-chainwork");
             When min_pow_checked=false (i.e. headers arrive from an
             untrusted peer that has not yet been verified to be on a
             chain meeting nMinimumChainWork), reject any header whose
             accumulated chain work falls below the network minimum.
             This prevents a peer from feeding us a long low-work fork
             header-by-header to consume memory.  Default true (safe:
             gate skipped) so that submitblock and internal callers are
             unaffected. *)
          if (not min_pow_checked) &&
             not (Consensus.meets_minimum_chain_work
                    entry.total_work state.network) then begin
            if !first_error = None then
              first_error := Some "too-little-chainwork";
            error := Some "too-little-chainwork"
          end else begin
            accept_header state entry;
            incr accepted
          end
        | Error "Header already known" ->
          incr rejected
        | Error e ->
          if !first_error = None then first_error := Some e;
          error := Some e
    ) headers;
    if !rejected > 0 && !accepted = 0 then begin
      Logs.warn (fun m -> m "All %d headers rejected (%d known, first_err=%s)"
        (List.length headers) !rejected
        (match !first_error with Some e -> e | None -> "none"));
      Logs.warn (fun m -> m "All %d headers were duplicates, locator may be stale"
        (List.length headers))
    end;
    match !error with
    | Some e when !accepted = 0 -> Error e
    | _ -> Ok !accepted
  end

(* Build a block locator with exponential backoff starting from [start_height].
   Mirrors Bitcoin Core's [chain.cpp::LocatorEntries(index)]: collect hashes at
   heights [start_height, start_height-1, ..., start_height-9], then doubling
   the step back to 0, always terminating with the genesis hash.

   Used by both [build_locator] (start_height == headers tip) and the
   PRESYNC/REDOWNLOAD locator path ([build_presync_locator_full],
   start_height == chain_start_height).  Prior to the PRESYNC unwedge of
   2026-05-28 the PRESYNC/REDOWNLOAD locator only included two entries
   ([last_hash] + [chain_start_hash]), which on a from-genesis re-IBD where
   tip == 0 meant we sent a SINGLE-ENTRY locator — peers replied with the
   same first 2000 mainnet headers over and over, and [process_headers]
   rejected them with [too-little-chainwork] because the bare-batch chainwork
   gate fires before any PRESYNC commitment-phase amortisation can take place.
   See nimrod commits 4deead0 + 1c82891 for the cross-impl pattern fix and
   CORE-PARITY-AUDIT/_nimrod-presync-part2-2026-05-27.md +
   _nimrod-presync-part3-2026-05-28.md for the upstream investigation. *)
let build_locator_from_height (state : chain_state) (start_height : int)
    : Types.hash256 list =
  let genesis_hash () =
    Storage.ChainDB.get_hash_at_height state.db 0
  in
  let rec collect acc step height =
    if height < 0 then
      (* Always terminate with genesis. *)
      match genesis_hash () with
      | Some h ->
        (match acc with
         | h' :: _ when Cstruct.equal h h' -> List.rev acc
         | _ -> List.rev (h :: acc))
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
  if start_height <= 0 then
    match genesis_hash () with
    | Some h -> [h]
    | None -> []
  else
    collect [] 1 start_height

(* Build a block locator for getheaders request.
   Returns exponentially spaced block hashes from tip back to genesis. *)
let build_locator (state : chain_state) : Types.hash256 list =
  let tip_height = match state.tip with
    | Some t -> t.height
    | None -> 0
  in
  build_locator_from_height state tip_height

(* Build the full getheaders locator for an in-flight PRESYNC/REDOWNLOAD sync.

   Mirrors Bitcoin Core's [HeadersSyncState::NextHeadersRequestLocator]
   ([bitcoin-core/src/headerssync.cpp:296]): the locator starts with the
   per-phase "where to continue from" hash ([last_hash] in PRESYNC,
   [redownload_last_hash] in REDOWNLOAD) and is followed by the
   exponential-backoff locator built from [chain_start_height] back to
   genesis (Core's [chain.cpp::LocatorEntries]).

   Why the original 2-entry locator ([build_presync_locator] +
   [build_redownload_locator]) was buggy: on a from-genesis re-IBD where the
   local tip is height 0, [chain_start_hash] == genesis and [last_hash] in
   PRESYNC is also genesis until any commitment-only header is processed —
   the peer therefore receives a locator with at most ONE hash entry (visible
   in the live restart.log as "Sending getheaders with 1 locators").  A peer
   that has pruned or simply does not recognise [last_hash] (the common case
   during PRESYNC, because commitment-only headers never leave the per-peer
   state machine and are never relayed) falls back to genesis and replies
   with the SAME initial 2000 headers over and over.  The next PRESYNC
   continuity check ([headers[0].prev_block == last_hash]) then fails because
   the peer is sending from genesis+1, not [last_hash]+1, and the PRESYNC
   pipeline tears down on every batch.  See nimrod commits 4deead0 + 1c82891
   and CORE-PARITY-AUDIT/_nimrod-presync-part2-2026-05-27.md for the
   cross-impl pattern. *)
let build_presync_locator_full (ps : peer_header_sync)
    (chain_state : chain_state) : Types.hash256 list =
  let prefix =
    match ps.state with
    | Presync { last_hash; _ } -> [last_hash]
    | Redownload rd -> [rd.redownload_last_hash]
    | Synced -> []
  in
  (* Append the chain_start exponential-backoff locator.  Skip any leading
     entry that duplicates the last hash already in [prefix] so the on-wire
     locator does not repeat the continue-from hash twice. *)
  let chain_start_locator =
    build_locator_from_height chain_state ps.chain_start_height in
  let merged =
    List.fold_left (fun acc h ->
      match acc with
      | last :: _ when Cstruct.equal last h -> acc
      | _ -> h :: acc
    ) (List.rev prefix) chain_start_locator
  in
  List.rev merged

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

(* Look up a block's height via the in-memory header table.  Returns [None]
   if the header is not in memory (the block predates the running process
   and is not in the loaded header set).  Used by the BIP-159 peer-served-
   blocks gate in [Cli.run]: when prune mode is on, we refuse to serve
   blocks below tip - 288 even if [Storage.ChainDB.get_block] could return
   them.  Best-effort only — if we don't know the height, the gate falls
   through to the existing serve-or-notfound path. *)
let lookup_block_height (state : chain_state) (hash : Types.hash256)
    : int option =
  match Hashtbl.find_opt state.headers (Cstruct.to_string hash) with
  | Some entry -> Some entry.height
  | None -> None

(* [get_ancestor state idx height] returns the header_entry that is the
   ancestor of [idx] at [height], walking the parent chain by
   [header.prev_block]. Mirrors Bitcoin Core's
   `CBlockIndex::GetAncestor(int height)` (chain.cpp).  Returns [None]
   when [height] is out of range (negative, above [idx.height], or
   unreachable because a parent header is missing from the in-memory
   table).  Used by the BIP-157 compact-filter request handlers and the
   REST blockfilterheaders endpoint to anchor the height-keyed walk on
   the peer-supplied stop_hash, rather than the active chain.  Without
   this anchor, a peer that supplies a stale/orphan stop_hash receives
   active-chain filters signed with the stale stop_hash — a DoS vector
   + privacy leak about which fork the peer is interested in.  Core
   intentionally serves stale-fork filters here (compact filters are
   stored by block hash regardless of fork membership); we match that
   by walking parent links rather than gating on chain.contains.    *)
let get_ancestor (state : chain_state) (idx : header_entry) (height : int)
    : header_entry option =
  if height < 0 || height > idx.height then None
  else if height = idx.height then Some idx
  else
    let rec walk (e : header_entry) =
      if e.height = height then Some e
      else if e.height < height then None
      else
        let pkey = Cstruct.to_string e.header.prev_block in
        match Hashtbl.find_opt state.headers pkey with
        | Some p -> walk p
        | None -> None
    in
    walk idx

(* The validated-block tip — the header_entry for the highest block that has
   been fully validated and connected (UTXO set updated).  This is distinct
   from [state.tip], which tracks the best-work *header* and may lead
   [blocks_synced] post-IBD while gap-fill is in flight.  Prefer this helper
   over `get_header_at_height state state.blocks_synced` at call sites —
   it falls back to [state.tip] for the fresh-chain case where genesis may
   only be in the in-memory Hashtbl (pre-persistence). *)
let block_tip (state : chain_state) : header_entry option =
  match get_header_at_height state state.blocks_synced with
  | Some _ as x -> x
  | None ->
    (* Fresh chain: genesis may not yet be persisted at height 0 in DB;
       state.tip points directly to the validated tip in that case. *)
    if state.blocks_synced = 0 then state.tip else None

(* W93 Bug 1 fix: provide the hash of the block at the network's
   BIP34Height so Bitcoin Core's BIP-30 skip optimization (Gate 4) can
   be activated.  Without this, [Validation.bip30_should_enforce] falls
   through to "enforce BIP-30 at every height >= bip34_height" on
   mainnet, costing extra UTXO probes per tx for the entire post-BIP34
   range.  Returns [None] when:
     - network has no BIP34 activation hint (bip34_hash = None),
     - the block at BIP34Height is not yet known to the chain state
       (which forces the conservative enforce path until headers reach
       that height — correct safety behaviour).
   Called by [process_new_block], [connect_stored_blocks], the IBD
   per-block validator, [submit_block], the reorg-connect path, and the
   assumeutxo init.  Reference: Bitcoin Core validation.cpp:2460-2462
   (BIP34Hash ancestor check). *)
let bip34_height_hash_for (state : chain_state) : Types.hash256 option =
  match state.network.Consensus.bip34_hash with
  | None -> None
  | Some _ ->
    (match get_header_at_height state state.network.Consensus.bip34_height with
     | None -> None
     | Some entry -> Some entry.hash)

(* Send a getheaders message with [locator].  Common helper used by both
   the main-chain [request_headers] (locator from headers tip) and the
   PRESYNC/REDOWNLOAD path (locator from the per-peer continue-from hash
   appended with the chain_start exponential backoff). *)
let send_getheaders_with_locator (peer : Peer.peer)
    (locator : Types.hash256 list) (tip_height : int) : unit Lwt.t =
  (match locator with
   | first :: _ ->
     Logs.info (fun m -> m "Sending getheaders with %d locators, first=%s (tip=%d)"
       (List.length locator)
       (let buf = Buffer.create 64 in
        for i = 0 to Cstruct.length first - 1 do
          Buffer.add_string buf (Printf.sprintf "%02x" (Cstruct.get_uint8 first i))
        done;
        Buffer.contents buf)
       tip_height)
   | [] -> Logs.info (fun m -> m "Sending getheaders with empty locator"));
  Peer.send_message peer
    (P2p.GetheadersMsg {
      version = Types.protocol_version;
      locator_hashes = locator;
      hash_stop = Types.zero_hash;
    })

(* Request headers from a peer.  When the peer has an active PRESYNC or
   REDOWNLOAD state, the locator is built via [build_presync_locator_full]
   so the per-phase continue-from hash is prepended to the chain_start
   exponential-backoff locator (mirrors Core
   [HeadersSyncState::NextHeadersRequestLocator],
   bitcoin-core/src/headerssync.cpp:296).  Otherwise the locator starts at
   our current headers tip.  Skipping the PRESYNC locator when one is in
   flight (as the pre-2026-05-28 code did) torpedoes the continuity check
   in [process_presync_headers] / [process_redownload_headers] — see the
   commentary on [build_presync_locator_full] above. *)
let request_headers (state : chain_state) (peer : Peer.peer) : unit Lwt.t =
  let locator =
    match get_peer_headers_sync state peer.Peer.id with
    | Some ps when ps.state <> Synced ->
      build_presync_locator_full ps state
    | _ ->
      build_locator state
  in
  send_getheaders_with_locator peer locator state.headers_synced

(* Main header sync loop - requests headers repeatedly until caught up.
   Enforces headers_download_timeout (15 min total) and uses
   read_message_with_timeout for per-response timeout (2 min). *)
let sync_headers (state : chain_state) (peer : Peer.peer) : unit Lwt.t =
  let open Lwt.Syntax in
  state.sync_state <- SyncingHeaders;
  state.sync_peer <- Some peer.id;
  let sync_start_time = Unix.gettimeofday () in

  (* Helper: check if a headers batch contains any NEW headers *)
  let has_new_headers headers =
    List.exists (fun hdr ->
      let hash = Crypto.compute_block_hash hdr in
      not (Hashtbl.mem state.headers (Cstruct.to_string hash))
    ) headers
  in

  (* Helper: read one message, handling ping/pong and non-header messages.
     Returns `Some headers` for a HeadersMsg, or `None` on timeout. *)
  let rec read_next_headers () =
    let* msg_opt = Peer.read_message_with_timeout peer headers_response_timeout in
    match msg_opt with
    | None -> Lwt.return_none
    | Some (P2p.HeadersMsg headers) -> Lwt.return_some headers
    | Some (P2p.PingMsg nonce) ->
      let* () = Peer.send_message peer (P2p.PongMsg nonce) in
      read_next_headers ()
    | Some _msg ->
      read_next_headers ()
  in

  (* Non-blocking read: returns immediately if no message is available.
     Used to drain leftover stale responses without blocking. *)
  let read_next_headers_nonblocking () =
    let* msg_opt = Peer.read_message_with_timeout peer 0.1 in
    match msg_opt with
    | None -> Lwt.return_none
    | Some (P2p.HeadersMsg headers) -> Lwt.return_some headers
    | Some (P2p.PingMsg nonce) ->
      let* () = Peer.send_message peer (P2p.PongMsg nonce) in
      Lwt.return_none
    | Some _msg ->
      Lwt.return_none
  in

  (* Drain any stale headers responses already queued on the socket from
     previous sync attempts.  Uses a very short timeout so it returns
     quickly once the queue is empty. *)
  let rec drain_queued_stale count =
    let* opt = read_next_headers_nonblocking () in
    match opt with
    | None -> begin
      if count > 0 then
        Logs.info (fun m -> m "Pre-drained %d stale header responses from socket" count);
      Lwt.return_unit
    end
    | Some headers ->
      if has_new_headers headers then begin
        (* Oops — this is actually fresh.  Process it immediately. *)
        if count > 0 then
          Logs.info (fun m -> m "Pre-drained %d stale responses, found fresh batch" count);
        let _r = process_headers ~min_pow_checked:false state headers in
        drain_queued_stale count
      end else begin
        Logs.debug (fun m -> m "Pre-drain: discarded stale response (%d headers)" (List.length headers));
        drain_queued_stale (count + 1)
      end
  in

  (* Drain stale responses from previous getheaders before we start. *)
  let* () = drain_queued_stale 0 in

  (* Read the next FRESH headers response, skipping stale responses where
     all headers are already known (leftover from previously queued
     getheaders replies).  Does NOT send a new getheaders — only reads. *)
  let rec drain_stale_responses stale_count =
    if stale_count >= 50 then begin
      Logs.warn (fun m -> m "Peer %d: %d stale responses, switching peers"
        peer.id stale_count);
      Lwt.return_none
    end else begin
      let* headers_opt = read_next_headers () in
      match headers_opt with
      | None -> Lwt.return_none
      | Some headers ->
        let count = List.length headers in
        if count > 0 && not (has_new_headers headers) then begin
          Logs.info (fun m ->
            m "Skipped stale response (%d known headers, %d skipped so far)"
              count (stale_count + 1));
          drain_stale_responses (stale_count + 1)
        end else
          Lwt.return_some headers
    end
  in

  (* Track how many getheaders we have sent without receiving a corresponding
     fresh response.  Each send increments the counter; each fresh response
     resets it to 0.  We only send a NEW getheaders when the counter is 0,
     otherwise we just drain queued responses from earlier sends. *)
  let pending_getheaders = ref 0 in

  (* Main sync iteration: send getheaders (if none pending), drain stale
     responses, process fresh headers, repeat. *)
  let rec sync_iteration () =
    let elapsed = Unix.gettimeofday () -. sync_start_time in
    if elapsed > headers_download_timeout then begin
      Logs.err (fun m -> m "Header sync timed out after %.0fs" elapsed);
      state.sync_state <- Idle;
      Lwt.return_unit
    end else begin
      (* Only send a new getheaders if we have no outstanding request *)
      let* () =
        if !pending_getheaders = 0 then begin
          pending_getheaders := 1;
          request_headers state peer
        end else
          Lwt.return_unit
      in
      let* headers_opt = drain_stale_responses 0 in
      match headers_opt with
      | None ->
        Logs.warn (fun m -> m "Header sync: timeout or too many stale responses from peer %d" peer.id);
        (* Reset pending counter — peer did not respond, so the outstanding
           request is effectively dead. *)
        pending_getheaders := 0;
        state.sync_state <- Idle;
        Lwt.return_unit
      | Some headers ->
        (* Got a fresh response — clear the pending counter so the next
           iteration will send a new getheaders. *)
        pending_getheaders := 0;
        let count = List.length headers in
        Logs.info (fun m -> m "Received %d headers (%d new)"
          count (List.length (List.filter (fun hdr ->
            let hash = Crypto.compute_block_hash hdr in
            not (Hashtbl.mem state.headers (Cstruct.to_string hash))
          ) headers)));
        process_and_continue state headers count
    end

  and process_and_continue state headers count =
    (* Track per-peer header count for flood detection *)
    let prev_count =
      match Hashtbl.find_opt state.headers_from_peer peer.id with
      | Some c -> c | None -> 0 in
    let new_count = prev_count + (List.length headers) in
    Hashtbl.replace state.headers_from_peer peer.id new_count;
    if new_count > max_headers_per_peer then begin
      let tip_work = match state.tip with
        | Some t -> t.total_work | None -> Consensus.zero_work in
      if Consensus.work_compare tip_work
           state.network.minimum_chain_work < 0 then begin
        Logs.warn (fun m ->
          m "Peer %d sent %d headers with insufficient chain work, \
             disconnecting (header flood)" peer.id new_count);
        state.sync_state <- Idle;
        Lwt.return_unit
      end else
        process_headers_and_continue state headers count
    end else
      process_headers_and_continue state headers count
  and process_headers_and_continue state headers count =
    (* PRESYNC anti-DoS routing.
       When our local [tip.total_work] is still below [minimum_chain_work]
       (the bare-from-genesis re-IBD case), every batch of unknown headers is
       a candidate for the PRESYNC pipeline.  The pre-PRESYNC code path
       (calling [process_headers ~min_pow_checked:false] directly) would
       reject every such batch with [too-little-chainwork] because the bare
       batch's accumulated work is far below the threshold and the gate
       fires per-header.  Mirrors Bitcoin Core's
       [PeerManagerImpl::TryLowWorkHeadersSync] / [HeadersSyncState]
       dispatch in [net_processing.cpp::ProcessHeadersMessage], and the
       cross-impl pattern fixed in nimrod 4deead0 + 1c82891 (2026-05-27/28
       — see CORE-PARITY-AUDIT/_nimrod-presync-part{2,3}-2026-05-{27,28}.md).
       Skip the PRESYNC path entirely for empty batches (peer's tip
       reached); those follow the original fall-through below. *)
    let lowwork = needs_lowwork_sync ~chain_state:state in
    if lowwork && headers <> [] then
      process_headers_via_presync state headers count
    else
      process_direct_acceptance state headers count

  and process_headers_via_presync state headers count =
    (* Look up or lazily create per-peer PRESYNC state.  The chain_start is
       the current best-work header tip — the same fork point Core uses
       when constructing [HeadersSyncState] in [TryLowWorkHeadersSync].
       Both branches of the get-or-create are safe at peer.id resolution:
       any previous Synced state for the same peer would have been left in
       place (re-entry is no-op), and a torn-down state will be replaced. *)
    let ps =
      match get_peer_headers_sync state peer.Peer.id with
      | Some existing when existing.state <> Synced -> existing
      | _ ->
        let chain_start =
          match state.tip with
          | Some t -> t
          | None ->
            (* Should never happen — [create_chain_state] inserts genesis.
               If it does, fall through to the direct-acceptance path so the
               original error semantics surface. *)
            failwith "process_headers_via_presync: no tip available"
        in
        let fresh =
          create_presync_state ~peer_id:peer.Peer.id ~chain_start in
        Hashtbl.replace state.peer_headers_sync peer.Peer.id fresh;
        Logs.info (fun m ->
          m "Started PRESYNC for peer %d at chain_start height=%d \
             (tip_work < minimum_chain_work)"
            peer.Peer.id chain_start.height);
        fresh
    in
    let phase = get_header_sync_phase ps in
    let outcome_lwt =
      match phase with
      | `Presync ->
        let r = process_presync_headers ~ps ~headers ~network:state.network in
        (match r with
         | Ok _accepted ->
           (* If PRESYNC just transitioned to REDOWNLOAD inside the call,
              report that for visibility; either way, request the next batch. *)
           let after = get_header_sync_phase ps in
           if after = `Redownload then
             Logs.info (fun m ->
               m "PRESYNC -> REDOWNLOAD for peer %d after batch of %d headers"
                 peer.Peer.id (List.length headers));
           Lwt.return `Continue
         | Error e ->
           Lwt.return (`Failure e))
      | `Redownload ->
        let r = process_redownload_headers
                  ~ps ~headers ~chain_state:state in
        (match r with
         | Ok _released ->
           (* [process_redownload_headers] already wrote any released headers
              into [chain_state.headers] / [tip] / [headers_synced], so we
              just continue to drive the next getheaders batch. *)
           Lwt.return `Continue
         | Error e ->
           Lwt.return (`Failure e))
      | `Synced ->
        (* PRESYNC -> REDOWNLOAD -> Synced fully completed.  Drop the
           per-peer state and re-enter the direct-acceptance path; any
           subsequent batches from this peer go straight through
           [process_headers] as they would for a sufficiently-worked tip. *)
        cleanup_peer_headers_sync state peer.Peer.id;
        Logs.info (fun m ->
          m "PRESYNC/REDOWNLOAD pipeline complete for peer %d, switching to \
             direct-acceptance for subsequent batches" peer.Peer.id);
        Lwt.return `Switch_to_direct
    in
    let* outcome = outcome_lwt in
    (match outcome with
     | `Continue ->
       (* Any progress through PRESYNC/REDOWNLOAD counts as a connecting
          batch for the unconnecting-headers counter purposes (Core's
          [nUnconnectingHeaders = 0] in the success path). *)
       reset_unconnecting_headers state peer.Peer.id;
       if count = P2p.max_headers_count then
         sync_iteration ()
       else begin
         (* Peer's tip reached during low-work sync.  Stay in Idle so the
            outer driver can pick a different peer; do not transition to
            SyncingBlocks while [tip_work < minimum_chain_work]. *)
         state.sync_state <- Idle;
         Lwt.return_unit
       end
     | `Switch_to_direct ->
       process_direct_acceptance state headers count
     | `Failure e ->
       Logs.warn (fun m ->
         m "PRESYNC/REDOWNLOAD failure for peer %d: %s — dropping state"
           peer.Peer.id e);
       cleanup_peer_headers_sync state peer.Peer.id;
       state.sync_state <- Idle;
       Lwt.return_unit)

  and process_direct_acceptance state headers count =
    match process_headers ~min_pow_checked:false state headers with
    | Ok accepted ->
      Logs.info (fun m -> m "Accepted %d headers, tip at height %d"
        accepted state.headers_synced);
      (* Successful connecting batch — reset the unconnecting-headers
         counter for this peer (Core's nUnconnectingHeaders = 0 in the
         success path). *)
      if accepted > 0 then
        reset_unconnecting_headers state peer.Peer.id;
      if count = P2p.max_headers_count then begin
        if accepted = 0 then begin
          Logs.warn (fun m -> m "Full batch but 0 accepted, likely stale — will send fresh getheaders");
          (* Don't loop immediately — the next sync_iteration will send a new
             getheaders with the current (possibly updated) locator. *)
          sync_iteration ()
        end else
          (* More headers available — continue *)
          sync_iteration ()
      end
      else begin
        (* Got fewer than max — peer's tip reached.
           Check minimum_chain_work before transitioning to block sync. *)
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
    | Error e when e = "Unknown parent header" ->
      (* Bitcoin Core (net_processing.cpp::ProcessHeadersMessage)
         tolerates up to MAX_NUM_UNCONNECTING_HEADERS_MSGS=10
         successive unconnecting messages from a peer before
         disconnecting.  Pre-fix, camlcoin silently dropped the
         sync_peer (state.sync_state <- Idle) without ever ban-scoring
         the peer, leaving us in a getheaders loop with a malicious
         peer indefinitely.  See
         CORE-PARITY-AUDIT/_header-sync-dos-cross-impl-audit-2026-05-06-part1.md
         (Pattern B). *)
      let exceeded = note_unconnecting_headers state peer.Peer.id in
      if exceeded then begin
        Logs.warn (fun m ->
          m "Peer %d exceeded MAX_NUM_UNCONNECTING_HEADERS_MSGS=%d, dropping sync_peer"
            peer.Peer.id max_num_unconnecting_headers_msgs);
        reset_unconnecting_headers state peer.Peer.id;
        state.sync_state <- Idle;
        Lwt.return_unit
      end else begin
        let count = unconnecting_headers_count state peer.Peer.id in
        Logs.info (fun m ->
          m "Unconnecting headers from peer %d (#%d/%d), retrying with fresh locator"
            peer.Peer.id count max_num_unconnecting_headers_msgs);
        (* Drive Core's FindForkInGlobalIndex behavior: re-iterate the
           sync loop, which builds a new locator and re-issues
           getheaders.  Counter persists until either a connecting
           batch arrives (resets) or the threshold is exceeded
           (drops). *)
        sync_iteration ()
      end
    | Error e ->
      Logs.err (fun m -> m "Header validation failed: %s" e);
      state.sync_state <- Idle;
      Lwt.return_unit
  in
  sync_iteration ()

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
  | Downloaded of { block : Types.block; peer_id : int option }
  | Validated

(* Block queue entry - tracks download progress for each block.
   W34: tried_peers accumulates peers that were assigned this block and
   failed (timeout, stall).  request_blocks prefers peers not in this list
   to avoid repeatedly re-assigning an unresponsive peer (W31 bug: a block
   could sit in-flight for up to max_stall_timeout=1200s because the same
   peer kept getting picked). *)
type block_queue_entry = {
  hash : Types.hash256;
  height : int;
  mutable download_state : block_download_state;
  mutable tried_peers : int list;
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

(* ============================================================================
   BIP-157 filter index helpers

   Every connect-block path in this module calls [append_filter_if_enabled]
   when [chain.bip157_index] is [Some]. The helper is a no-op when the index
   is disabled, keeping the call sites uniform regardless of whether the
   operator passed --blockfilterindex.

   The [spent_utxos] argument is the [Validation.utxo] list returned from
   [Validation.accept_block] (AB_ok's third element). This is exactly the
   set of outputs that were spent by the block, in iteration order, and is
   already in hand at every connect-block call site — converting it into
   the [Cstruct.t list] expected by [Block_index.append_block_filter] is a
   single [List.map].

   Errors are logged but never escalated. If the parent's filter is
   unexpectedly missing (e.g. a manually-deleted index file), the next
   restart's startup-time backfill will catch up.
   ============================================================================ *)
let append_filter_if_enabled
    (chain : chain_state) ~(block : Types.block) ~(height : int)
    ~(spent_utxos : (Types.outpoint * Validation.utxo) list)
    : unit =
  match chain.bip157_index with
  | None -> ()
  | Some idx ->
    let spent_scripts =
      List.map (fun (_op, (u : Validation.utxo)) -> u.script_pubkey)
        spent_utxos
    in
    (match Block_index.append_block_filter idx
             ~block ~height ~spent_scripts with
     | Ok () -> ()
     | Error msg ->
       Logs.warn (fun m ->
         m "BIP-157: failed to append filter at height %d: %s" height msg))

(* Same shape but for callers (e.g. the reorg connect path) that have the
   spent UTXOs as [Utxo.utxo_entry] rather than [Validation.utxo]. *)
let append_filter_if_enabled_from_entries
    (chain : chain_state) ~(block : Types.block) ~(height : int)
    ~(spent_entries : (Types.outpoint * Utxo.utxo_entry) list)
    : unit =
  match chain.bip157_index with
  | None -> ()
  | Some idx ->
    let spent_scripts =
      List.map (fun (_op, (e : Utxo.utxo_entry)) -> e.script_pubkey)
        spent_entries
    in
    (match Block_index.append_block_filter idx
             ~block ~height ~spent_scripts with
     | Ok () -> ()
     | Error msg ->
       Logs.warn (fun m ->
         m "BIP-157: failed to append filter at height %d: %s" height msg))

(* IBD configuration constants *)
let max_blocks_per_peer = 16           (* Max in-flight blocks per peer, matching Bitcoin Core MAX_BLOCKS_IN_TRANSIT_PER_PEER *)
let max_total_blocks_in_flight = 128   (* Global cap on blocks in flight (8 peers × 16 per peer) *)
let stall_timeout = 2.0                 (* 2s stall detection — re-request from another peer *)
let base_block_timeout = 60.0           (* 60s base timeout — matches Bitcoin Core's conservative approach *)
let max_block_timeout = 300.0           (* 5 min max timeout per block *)
let max_stall_timeout = 1200.0          (* 20 min max stall — matches Bitcoin Core *)
let max_consecutive_timeouts = 5        (* More forgiving before disconnect *)
let utxo_flush_interval = 500          (* Flush UTXOs every N blocks — tuned for IBD throughput *)
let block_download_window = 1024       (* Max blocks ahead to queue, matching Bitcoin Core BLOCK_DOWNLOAD_WINDOW *)

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
  block_queue : block_queue_entry Queue.t;
  queue_by_hash : (string, block_queue_entry) Hashtbl.t;
  queue_by_height : (int, block_queue_entry) Hashtbl.t;
  mutable next_download_height : int;
  mutable next_process_height : int;
  mutable total_blocks_in_flight : int;
  mutable peer_states : (int, peer_download_state) Hashtbl.t;
  mutable blocks_since_flush : int;
  mutable pending_utxo_updates : (Types.hash256 * int * string) list;
  mutable pending_utxo_deletes : (Types.hash256 * int) list;
  utxo_set : Utxo.OptimizedUtxoSet.t option;
  mutable mempool : Mempool.mempool option;
  orphan_blocks : (string, orphan_block_entry) Hashtbl.t;
  misbehavior_handler : (int -> string -> unit) option;
  mutable zmq_notifier : Zmq_notify.t option;  (* ZMQ notification publisher *)
}

(* Create IBD state from existing chain state *)
let create_ibd_state ?(utxo_set : Utxo.OptimizedUtxoSet.t option)
    ?(misbehavior_handler : (int -> string -> unit) option)
    ?(zmq_notifier : Zmq_notify.t option)
    (chain : chain_state) : ibd_state =
  let start_height = chain.blocks_synced + 1 in
  { chain;
    block_queue = Queue.create ();
    queue_by_hash = Hashtbl.create 1024;
    queue_by_height = Hashtbl.create 1024;
    next_download_height = start_height;
    next_process_height = start_height;
    total_blocks_in_flight = 0;
    peer_states = Hashtbl.create 16;
    blocks_since_flush = 0;
    pending_utxo_updates = [];
    pending_utxo_deletes = [];
    utxo_set;
    mempool = None;
    orphan_blocks = Hashtbl.create 100;
    misbehavior_handler;
    zmq_notifier }

let set_mempool (ibd : ibd_state) (mp : Mempool.mempool) =
  ibd.mempool <- Some mp

let set_zmq_notifier (ibd : ibd_state) (notifier : Zmq_notify.t) =
  ibd.zmq_notifier <- Some notifier

(* Notify ZMQ subscribers about a block event *)
let zmq_notify_block (ibd : ibd_state) (block : Types.block)
    (block_hash : Types.hash256) (connect : bool) : unit =
  match ibd.zmq_notifier with
  | None -> ()
  | Some notifier ->
    (* Publish hashblock and rawblock *)
    ignore (Zmq_notify.notify_hashblock notifier block_hash);
    ignore (Zmq_notify.notify_rawblock notifier block);
    (* Publish sequence event *)
    if connect then
      ignore (Zmq_notify.notify_block_connect notifier block_hash)
    else
      ignore (Zmq_notify.notify_block_disconnect notifier block_hash)

(* Add an entry to the block queue with O(1) enqueue and index updates *)
let queue_add (ibd : ibd_state) (entry : block_queue_entry) =
  Queue.push entry ibd.block_queue;
  Hashtbl.replace ibd.queue_by_hash (Cstruct.to_string entry.hash) entry;
  Hashtbl.replace ibd.queue_by_height entry.height entry

(* Remove validated entries from the block queue *)
let queue_remove_validated (ibd : ibd_state) =
  let retained = Queue.create () in
  Queue.iter (fun e ->
    if e.download_state = Validated then begin
      Hashtbl.remove ibd.queue_by_hash (Cstruct.to_string e.hash);
      Hashtbl.remove ibd.queue_by_height e.height
    end else
      Queue.push e retained
  ) ibd.block_queue;
  Queue.clear ibd.block_queue;
  Queue.transfer retained ibd.block_queue

(* O(1) lookup by hash *)
let queue_find_by_hash (ibd : ibd_state) (hash_key : string) : block_queue_entry option =
  Hashtbl.find_opt ibd.queue_by_hash hash_key

(* O(1) lookup by height *)
let queue_find_by_height (ibd : ibd_state) (height : int) : block_queue_entry option =
  Hashtbl.find_opt ibd.queue_by_height height

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
        Queue.length ibd.block_queue < max_queue_size do
    let height = ibd.next_download_height in
    match Storage.ChainDB.get_hash_at_height ibd.chain.db height with
    | Some hash ->
      (* If the block is already stored on disk and is ABOVE blocks_synced
         (i.e. stored from a crashed session but not yet validated with
         consistent UTXO state), load it directly to avoid re-downloading. *)
      if Storage.ChainDB.has_block ibd.chain.db hash then begin
        match Storage.ChainDB.get_block ibd.chain.db hash with
        | Some block ->
          queue_add ibd {
            hash; height;
            download_state = Downloaded { block; peer_id = None };
            tried_peers = [];
          }
        | None ->
          queue_add ibd { hash; height;
                          download_state = NotRequested; tried_peers = [] }
      end else
        queue_add ibd { hash; height;
                        download_state = NotRequested; tried_peers = [] };
      ibd.next_download_height <- ibd.next_download_height + 1
    | None ->
      ibd.next_download_height <- ibd.next_download_height + 1
  done

(* ============================================================================
   Timeout Management with Adaptive Backoff
   ============================================================================ *)

(* Check for timed out requests and reset them *)
let check_timeouts (ibd : ibd_state) : unit =
  let now = Unix.gettimeofday () in
  Queue.iter (fun entry ->
    match entry.download_state with
    | Requested { peer_id; requested_at; timeout } ->
      if now -. requested_at > timeout then begin
        entry.download_state <- NotRequested;
        (* W34: record that this peer failed to serve this block *)
        if not (List.mem peer_id entry.tried_peers) then
          entry.tried_peers <- peer_id :: entry.tried_peers;
        ibd.total_blocks_in_flight <- max 0 (ibd.total_blocks_in_flight - 1);
        let peer_state = get_peer_state ibd peer_id in
        peer_state.blocks_in_flight <- max 0 (peer_state.blocks_in_flight - 1);
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
  Queue.iter (fun entry ->
    match entry.download_state with
    | Requested { peer_id; requested_at; timeout } ->
      if now > requested_at +. timeout then begin
        entry.download_state <- NotRequested;
        (* W34: record that this peer failed — prefer-untried avoids re-pick *)
        if not (List.mem peer_id entry.tried_peers) then
          entry.tried_peers <- peer_id :: entry.tried_peers;
        ibd.total_blocks_in_flight <- max 0 (ibd.total_blocks_in_flight - 1);
        let peer_state = get_peer_state ibd peer_id in
        peer_state.blocks_in_flight <- max 0 (peer_state.blocks_in_flight - 1);
        peer_state.consecutive_timeouts <- peer_state.consecutive_timeouts + 1;
        peer_state.current_timeout <- min max_stall_timeout
          (peer_state.current_timeout *. 2.0);
        Logs.debug (fun m ->
          m "Stalled download for height %d from peer %d \
             (consecutive timeouts: %d, new timeout: %.1fs)"
            entry.height peer_id
            peer_state.consecutive_timeouts peer_state.current_timeout);
        if peer_state.consecutive_timeouts >= max_consecutive_timeouts then
          Hashtbl.replace peers_to_disconnect peer_id true
      end else if now > requested_at +. stall_timeout then begin
        entry.download_state <- NotRequested;
        (* W34: record that this peer failed (stall) *)
        if not (List.mem peer_id entry.tried_peers) then
          entry.tried_peers <- peer_id :: entry.tried_peers;
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

(* Request blocks from available peers using batched GetData.
   Distributes unrequested blocks across all ready peers in parallel,
   giving each peer up to max_blocks_per_peer blocks per round. *)
let request_blocks (ibd : ibd_state) (peers : Peer.peer list)
    : unit Lwt.t =
  let now = Unix.gettimeofday () in
  (* First check for timeouts *)
  check_timeouts ibd;
  (* Mark blocks we already have on disk as validated — but ONLY if their
     height is at or below blocks_synced.  A block above blocks_synced may be
     on disk from a prior session (stored by the "doesn't connect to tip" path
     without UTXO processing), or may have been written with stripped witness
     data.  Marking such a block Validated skips the UTXO update, corrupting
     the UTXO set for all subsequent blocks. *)
  Queue.iter (fun entry ->
    if entry.download_state = NotRequested &&
       entry.height <= ibd.chain.blocks_synced &&
       Storage.ChainDB.has_block ibd.chain.db entry.hash then
      entry.download_state <- Validated
  ) ibd.block_queue;
  (* Filter to ready peers with capacity *)
  let ready_peers = List.filter (fun p ->
    p.Peer.state = Peer.Ready &&
    let ps = get_peer_state ibd p.Peer.id in
    ps.blocks_in_flight < max_blocks_per_peer
  ) peers in
  (* Build a single list of unrequested blocks, then partition across peers *)
  let unrequested = Queue.fold (fun acc entry ->
    if entry.download_state = NotRequested then entry :: acc else acc
  ) [] ibd.block_queue |> List.rev in
  if unrequested = [] then Lwt.return_unit
  else begin
    (* Assign blocks to peers round-robin style for balanced distribution *)
    let peer_batches : (Peer.peer * peer_download_state * block_queue_entry list ref) list =
      List.filter_map (fun peer ->
        let peer_state = get_peer_state ibd peer.Peer.id in
        let available = max_blocks_per_peer - peer_state.blocks_in_flight in
        if available > 0 then Some (peer, peer_state, ref [])
        else None
      ) ready_peers
    in
    if peer_batches = [] then Lwt.return_unit
    else begin
      (* Distribute unrequested blocks to peers *)
      let peer_arr = Array.of_list peer_batches in
      let n_peers = Array.length peer_arr in
      let idx = ref 0 in
      List.iter (fun entry ->
        if ibd.total_blocks_in_flight < max_total_blocks_in_flight then begin
          (* W34: prefer peers that haven't failed this block yet.
             First pass only considers peers NOT in entry.tried_peers.
             If no untried peer has capacity, fall back to any peer with
             capacity (second pass) — this avoids a deadlock when every
             connected peer has already failed on a block.  When the tried
             list gets as long as the peer set, it's effectively reset for
             the purpose of capacity checks. *)
          let try_assign filter_tried =
            let found = ref false in
            let attempts = ref 0 in
            while not !found && !attempts < n_peers do
              let (peer, peer_state, batch_ref) = peer_arr.(!idx mod n_peers) in
              let peer_ok =
                peer_state.blocks_in_flight < max_blocks_per_peer
                && (not filter_tried
                    || not (List.mem peer.Peer.id entry.tried_peers))
              in
              if peer_ok then begin
                entry.download_state <- Requested {
                  peer_id = peer.Peer.id;
                  requested_at = now;
                  timeout = peer_state.current_timeout;
                };
                ibd.total_blocks_in_flight <- ibd.total_blocks_in_flight + 1;
                peer_state.blocks_in_flight <- peer_state.blocks_in_flight + 1;
                batch_ref := entry :: !batch_ref;
                found := true
              end;
              idx := !idx + 1;
              incr attempts
            done;
            !found
          in
          if not (try_assign true) then
            ignore (try_assign false)
        end
      ) unrequested;
      (* Send all GetData messages in parallel *)
      let%lwt () = Lwt_list.iter_p (fun (peer, peer_state, batch_ref) ->
        let batch : block_queue_entry list = List.rev !batch_ref in
        if batch = [] then Lwt.return_unit
        else begin
          let inv_vectors = List.map (fun (entry : block_queue_entry) ->
            P2p.{ inv_type = InvWitnessBlock; hash = entry.hash }
          ) batch in
          Logs.debug (fun m ->
            m "Requesting %d blocks from peer %d (in-flight: %d/%d)"
              (List.length inv_vectors) peer.Peer.id
              peer_state.blocks_in_flight max_blocks_per_peer);
          (* Send batched GetData message — catch broken-pipe / closed
             channel so one dead peer doesn't kill the IBD loop. *)
          Lwt.catch
            (fun () -> Peer.send_message peer (P2p.GetdataMsg inv_vectors))
            (fun _exn ->
               (* Peer socket is dead; un-mark the blocks so they can be
                  re-requested from another peer. *)
               List.iter (fun entry ->
                 entry.download_state <- NotRequested;
                 ibd.total_blocks_in_flight <-
                   max 0 (ibd.total_blocks_in_flight - 1);
                 peer_state.blocks_in_flight <-
                   max 0 (peer_state.blocks_in_flight - 1)
               ) batch;
               Lwt.return_unit)
        end
      ) peer_batches in
      Lwt.return_unit
    end
  end

(* ============================================================================
   Block Receipt and Processing
   ============================================================================ *)

(* Process a received block *)
let receive_block (ibd : ibd_state) (block : Types.block)
    : (unit, string) result =
  let hash = Crypto.compute_block_hash block.header in
  let hash_key = Cstruct.to_string hash in
  match queue_find_by_hash ibd hash_key with
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
    entry.download_state <- Downloaded { block; peer_id };
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
    Queue.iter (fun entry ->
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
  (* Also flush the OptimizedUtxoSet dirty entries if one is attached.
     Pass the current blocks_synced height so RocksDB records it for
     consistency checking on restart. *)
  match ibd.utxo_set with
  | Some utxo ->
    Utxo.OptimizedUtxoSet.flush ~tip_height:ibd.chain.blocks_synced utxo
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
           download_state = Downloaded { block = orphan.block; peer_id = None };
           tried_peers = [];
         } in
         queue_add ibd queue_entry;
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
  (* Collect up to 11 timestamps from height-1 down to height-11.
     Used for block validation (MTP check), which excludes the current block. *)
  let timestamps = collect [] (height - 1) 11 in
  Consensus.median_time_past timestamps

(* Compute the median time past FOR DISPLAY in getblockheader/getblock RPC,
   which mirrors Bitcoin Core's CBlockIndex::GetMedianTimePast() that starts
   at the CURRENT block (inclusive):
     pindex = this; for i = 0..10: collect pindex->time; pindex = pprev
   This differs from [compute_median_time_past] used for validation which
   starts at height-1 (exclusive of the current block). *)
let compute_median_time_for_display (state : chain_state) (height : int) : int32 =
  let rec collect acc h count =
    if count <= 0 || h < 0 then acc
    else match get_header_at_height state h with
      | Some entry -> collect (entry.header.timestamp :: acc) (h - 1) (count - 1)
      | None -> acc
  in
  let timestamps = collect [] height 11 in
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
    let parent =
      match get_header_at_height state (height - 1) with
      | Some entry -> entry.header
      | None -> network.genesis_header
    in
    let get_block_info h =
      match get_header_at_height state h with
      | Some entry -> (entry.header.timestamp, entry.header.bits)
      | None -> (0l, network.pow_limit)
    in
    Consensus.get_next_work_required
      ~height
      ~block_time:block_header.timestamp
      ~prev_block_time:parent.timestamp
      ~prev_bits:parent.bits
      ~get_block_info
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

(* Return the timestamp of the block at height-1 (the parent), used for
   BIP-94 timewarp check.  Returns 0l when height=0 (genesis has no parent).
   Reference: bitcoin-core/src/validation.cpp ContextualCheckBlockHeader:4101. *)
let get_prev_block_time (state : chain_state) (height : int) : int32 =
  if height <= 0 then 0l
  else match get_header_at_height state (height - 1) with
    | Some e -> e.header.timestamp
    | None -> 0l

(* ============================================================================
   Block Validation Worker (wave 11 — Domain.join option B)
   ============================================================================
   A single persistent worker Domain runs block validation
   (Validation.validate_block_with_utxos) off the Lwt main thread.

   Design invariant: the worker never mutates ibd.* Hashtbls.  It only calls
   validate_block_with_utxos with a captured lookup closure; the closure
   reads from ibd.utxo_set / chain DB but the Lwt main thread is parked on
   the response mvar while the worker runs, and no other Lwt callback
   mutates the UTXO set during IBD (peer handlers touch queue/peer_states
   only).  Mutation of ibd.* stays pinned to the Lwt thread, applied AFTER
   the worker returns the validation result.

   IPC: plain Mutex+Condition channels (not Lwt_mvar — those only work on
   the Lwt side).  Lwt side wraps put/take in Lwt_preemptive.detach so the
   scheduler parks rather than blocks. *)
module Validation_worker = struct
  type job = {
    block : Types.block;
    height : int;
    expected_bits : int32;
    median_time : int32;
    prev_block_time : int32;  (* timestamp of block at height-1; BIP-94 timewarp check *)
    lookup : Validation.utxo_lookup;
    flags : int;
    skip_scripts : bool;
    network : Consensus.network_config;
    get_mtp_at_height : (int -> int32) option;
    (* W93 Bug 1 fix: hash of the block at network.bip34_height on the
       canonical chain, if known.  Pass [Some h] to enable Bitcoin Core's
       BIP-30 skip optimization (Gate 4 of [bip30_should_enforce]).
       [None] falls through to the conservative enforce path. *)
    bip34_height_hash : Types.hash256 option;
  }

  type validation_result =
    ((int64 * Types.hash256 array
      * (Types.outpoint * Validation.utxo) list),
     Validation.block_validation_error) result

  type message = Validate of job | Shutdown

  (* Two typed single-slot channels (request + response).  Plain
     Mutex+Condition — works on both the worker Domain and (wrapped in
     Lwt_preemptive.detach) the Lwt side. *)
  type req_chan = {
    rmutex : Mutex.t;
    rcond : Condition.t;
    mutable rmsg : message option;
  }
  type resp_chan = {
    pmutex : Mutex.t;
    pcond : Condition.t;
    mutable presult : (validation_result, exn) result option;
  }

  type t = {
    req : req_chan;
    resp : resp_chan;
    domain : unit Domain.t;
  }

  let put_req (c : req_chan) (m : message) : unit =
    Mutex.lock c.rmutex;
    (* Single-slot: wait until empty *)
    while c.rmsg <> None do Condition.wait c.rcond c.rmutex done;
    c.rmsg <- Some m;
    Condition.broadcast c.rcond;
    Mutex.unlock c.rmutex

  let take_req (c : req_chan) : message =
    Mutex.lock c.rmutex;
    while c.rmsg = None do Condition.wait c.rcond c.rmutex done;
    let m = match c.rmsg with Some v -> v | None -> assert false in
    c.rmsg <- None;
    Condition.broadcast c.rcond;
    Mutex.unlock c.rmutex;
    m

  let put_resp (c : resp_chan) (r : (validation_result, exn) result) : unit =
    Mutex.lock c.pmutex;
    while c.presult <> None do Condition.wait c.pcond c.pmutex done;
    c.presult <- Some r;
    Condition.broadcast c.pcond;
    Mutex.unlock c.pmutex

  let take_resp (c : resp_chan) : (validation_result, exn) result =
    Mutex.lock c.pmutex;
    while c.presult = None do Condition.wait c.pcond c.pmutex done;
    let r = match c.presult with Some v -> v | None -> assert false in
    c.presult <- None;
    Condition.broadcast c.pcond;
    Mutex.unlock c.pmutex;
    r

  let worker_loop (req : req_chan) (resp : resp_chan) : unit =
    let rec loop () =
      match take_req req with
      | Shutdown -> ()
      | Validate j ->
        (* accept_block: unified ProcessNewBlock check pipeline.
           Same sequence as process_new_block, connect_stored_blocks, and
           submit_block. Using accept_block here ensures the IBD worker
           Domain applies identical validation logic to the main-thread paths.
           Reference: bitcoin-core/src/validation.cpp ProcessNewBlock. *)
        let r =
          try
            (match Validation.accept_block
                     ~network:j.network ~block:j.block ~height:j.height
                     ~expected_bits:j.expected_bits
                     ~median_time:j.median_time
                     ~prev_block_time:j.prev_block_time
                     ~base_lookup:j.lookup
                     ~flags:j.flags
                     ~skip_scripts:j.skip_scripts
                     ?get_mtp_at_height:j.get_mtp_at_height
                     ?bip34_height_hash:j.bip34_height_hash
                     () with
             | Validation.AB_ok (fees, txid_arr, spent) ->
               Ok (Ok (fees, txid_arr, spent))
             | Validation.AB_err e ->
               Ok (Error e))
          with exn -> Error exn
        in
        put_resp resp r;
        loop ()
    in
    loop ()

  let create () : t =
    let req = { rmutex = Mutex.create (); rcond = Condition.create ();
                rmsg = None } in
    let resp = { pmutex = Mutex.create (); pcond = Condition.create ();
                 presult = None } in
    let domain = Domain.spawn (fun () -> worker_loop req resp) in
    { req; resp; domain }

  (* Lwt-side submit: enqueue job, park Lwt scheduler (via
     Lwt_preemptive.detach) while the worker Domain runs.
     Crucially, the Lwt main thread is parked on Lwt_preemptive — it does
     not hold the OCaml runtime lock while the worker is running — so
     other Lwt callbacks CAN run, but the IBD invariant is preserved
     because process_downloaded_blocks defers all ibd.* mutation until
     AFTER this call returns and we're back on the Lwt thread. *)
  let submit_lwt (t : t) (j : job) : validation_result Lwt.t =
    let%lwt () = Lwt_preemptive.detach (fun () -> put_req t.req (Validate j)) () in
    let%lwt r = Lwt_preemptive.detach (fun () -> take_resp t.resp) () in
    match r with
    | Ok v -> Lwt.return v
    | Error exn -> Lwt.fail exn

  let shutdown (t : t) : unit =
    put_req t.req Shutdown;
    Domain.join t.domain
end

(* Process downloaded blocks in height order.
   [max_blocks] caps how many blocks are processed in one call.
   When [worker] is provided, block validation (the CPU-heavy
   script/merkle/UTXO check) runs on a persistent worker Domain with the
   Lwt scheduler parked on a Lwt_preemptive.detach await; all ibd.*
   mutation still happens here on the Lwt main thread once the worker
   returns.  When [worker] is None, validation runs inline (legacy path,
   used for tests and post-IBD paths). *)
let process_downloaded_blocks ?(max_blocks = 1)
    ?(worker : Validation_worker.t option)
    (ibd : ibd_state)
    : (int, string) result Lwt.t =
  let processed = ref 0 in
  let error = ref None in
  let continue = ref true in
  let rec step () : unit Lwt.t =
    if not !continue || !error <> None || !processed >= max_blocks then
      Lwt.return_unit
    else
    match queue_find_by_height ibd ibd.next_process_height with
    | Some entry -> begin
      match entry.download_state with
      | Downloaded { block; peer_id } ->
        (* Validate the block *)
        let height = entry.height in
        (* Compute expected difficulty from chain state *)
        let expected_bits = compute_expected_bits ibd.chain height block.header in
        (* Compute median time past from last 11 blocks *)
        let median_time = compute_median_time_past ibd.chain height in
        (* BIP-94: parent block timestamp for timewarp check *)
        let prev_block_time = get_prev_block_time ibd.chain height in
        (* Build UTXO lookup function.  When an OptimizedUtxoSet is
           attached we query it first — it keeps an in-memory dirty set
           that is not yet flushed to the database, so it can resolve
           outputs created earlier in this IBD session.  Fall back to
           the raw DB lookup for entries written in a previous session. *)
        let lookup outpoint =
          let txid = outpoint.Types.txid in
          let vout = Int32.to_int outpoint.Types.vout in
          let entry_opt = match ibd.utxo_set with
            | Some utxo ->
              (match Utxo.OptimizedUtxoSet.get utxo txid vout with
               | Some e -> Some e
               | None -> None)
            | None -> None
          in
          match entry_opt with
          | Some e ->
            Some Validation.{
              txid;
              vout = outpoint.Types.vout;
              value = e.Utxo.value;
              script_pubkey = e.Utxo.script_pubkey;
              height = e.Utxo.height;
              is_coinbase = e.Utxo.is_coinbase;
            }
          | None ->
            (* Fall back to raw DB *)
            (match Storage.ChainDB.get_utxo ibd.chain.db txid vout with
             | None -> None
             | Some data ->
               let r = Serialize.reader_of_cstruct (Cstruct.of_string data) in
               let value = Serialize.read_int64_le r in
               let script_len = Serialize.read_compact_size r in
               let script = Serialize.read_bytes r script_len in
               let stored_height = Int32.to_int (Serialize.read_int32_le r) in
               let utxo_is_coinbase = Serialize.read_uint8 r = 1 in
               Some Validation.{
                 txid;
                 vout = outpoint.Types.vout;
                 value;
                 script_pubkey = script;
                 height = stored_height;
                 is_coinbase = utxo_is_coinbase;
               })
        in
        (* Validate block with UTXO tracking *)
        let skip_scripts = is_assume_valid ibd.chain height in
        let validation_flags =
          if skip_scripts then 0
          else Consensus.get_block_script_flags height ibd.chain.network
        in
        let%lwt vresult =
          match worker with
          | Some w ->
            let job : Validation_worker.job = {
              block; height;
              expected_bits; median_time; prev_block_time;
              lookup;
              flags = validation_flags;
              skip_scripts;
              network = ibd.chain.network;
              get_mtp_at_height = Some (get_mtp_for_height ibd.chain);
              bip34_height_hash = bip34_height_hash_for ibd.chain;
            } in
            Validation_worker.submit_lwt w job
          | None ->
            (* accept_block: same unified pipeline as the worker path.
               This inline branch is used in tests and post-IBD single-block
               connects that don't use the Domain worker. *)
            Lwt.return (
              match Validation.accept_block
                      ~network:ibd.chain.network ~block ~height
                      ~expected_bits ~median_time ~prev_block_time ~base_lookup:lookup
                      ~flags:validation_flags ~skip_scripts
                      ~get_mtp_at_height:(get_mtp_for_height ibd.chain)
                      ?bip34_height_hash:(bip34_height_hash_for ibd.chain) () with
              | Validation.AB_ok (fees, txid_arr, spent) -> Ok (fees, txid_arr, spent)
              | Validation.AB_err e -> Error e)
        in
        (match vresult with
         | Ok (_fees, txid_arr, spent_utxo_list) ->
           let ibd_mode = skip_scripts in
           (* BIP-157 filter index append. Done in BOTH the assume-valid
              fast-path AND the full-validation slow-path because the
              REST blockfilter handler must serve filters for every
              connected block regardless of whether script verification
              was skipped. The spent UTXOs come from validation's
              [spent_utxo_list] (full-validate) or from the upstream
              UTXO lookup (assume-valid path produces them too as long
              as inputs were resolved). *)
           append_filter_if_enabled ibd.chain ~block ~height
             ~spent_utxos:spent_utxo_list;
           (* Fix 3: Skip block/undo storage during assume-valid IBD *)
           if not ibd_mode then begin
             (* Store block *)
             Storage.ChainDB.store_block ibd.chain.db entry.hash block;
             (* Build undo data from validation's spent_utxo_list (Fix 1) *)
             let spent_by_tx : (int, (Types.outpoint * Utxo.utxo_entry) list) Hashtbl.t =
               Hashtbl.create 16 in
             (* Map spent UTXOs back to their transaction index *)
             let tx_input_counts = Array.of_list (List.mapi (fun i tx ->
               if i = 0 then 0  (* coinbase *)
               else List.length tx.Types.inputs
             ) block.transactions) in
             (* Assign spent UTXOs to transactions *)
             let cur_tx = ref 1 in (* start at tx 1, skip coinbase *)
             let cur_inp = ref 0 in
             List.iter (fun (outpoint, utxo) ->
               (* Advance to the right tx *)
               while !cur_tx < Array.length tx_input_counts &&
                     !cur_inp >= tx_input_counts.(!cur_tx) do
                 cur_tx := !cur_tx + 1;
                 cur_inp := 0
               done;
               let entry = Utxo.{
                 value = utxo.Validation.value;
                 script_pubkey = utxo.Validation.script_pubkey;
                 height = utxo.Validation.height;
                 is_coinbase = utxo.Validation.is_coinbase;
               } in
               let existing = match Hashtbl.find_opt spent_by_tx !cur_tx with
                 | Some l -> l | None -> [] in
               Hashtbl.replace spent_by_tx !cur_tx ((outpoint, entry) :: existing);
               cur_inp := !cur_inp + 1
             ) spent_utxo_list;
             let n_txs = List.length block.transactions in
             let tx_undos = List.init (n_txs - 1) (fun i ->
               let tx_idx = i + 1 in
               let spent = match Hashtbl.find_opt spent_by_tx tx_idx with
                 | Some l -> List.rev l | None -> [] in
               Utxo.{ spent_outputs = spent }
             ) in
             let undo : Utxo.undo_data = { height; tx_undos } in
             let uw = Serialize.writer_create () in
             Utxo.serialize_undo_data uw undo;
             Storage.ChainDB.store_undo_data ibd.chain.db entry.hash
               (Cstruct.to_string (Serialize.writer_to_cstruct uw))
           end;
           (* Update UTXOs - add new outputs, delete spent inputs *)
           (* Fix 2: Reuse txids from validation instead of recomputing *)
           (* Fix 5: During IBD, only use OptimizedUtxoSet, skip pending lists *)
           List.iteri (fun tx_idx tx ->
             let txid = txid_arr.(tx_idx) in
             let is_cb = (tx_idx = 0) in
             (* Add outputs as new UTXOs (skip genesis coinbase) *)
             if not (Consensus.is_genesis_coinbase height txid) then begin
               if ibd_mode then begin
                 (* IBD: only OptimizedUtxoSet *)
                 (match ibd.utxo_set with
                  | Some utxo ->
                    List.iteri (fun vout out ->
                      Utxo.OptimizedUtxoSet.add utxo txid vout
                        Utxo.{ value = out.Types.value;
                               script_pubkey = out.Types.script_pubkey;
                               height;
                               is_coinbase = is_cb }
                    ) tx.Types.outputs
                  | None -> ())
               end else begin
                 List.iteri (fun vout out ->
                   let data = encode_utxo out.Types.value out.Types.script_pubkey
                       height is_cb in
                   ibd.pending_utxo_updates <-
                     (txid, vout, data) :: ibd.pending_utxo_updates;
                   (match ibd.utxo_set with
                    | Some utxo ->
                      Utxo.OptimizedUtxoSet.add utxo txid vout
                        Utxo.{ value = out.Types.value;
                               script_pubkey = out.Types.script_pubkey;
                               height;
                               is_coinbase = is_cb }
                    | None -> ())
                 ) tx.Types.outputs
               end
             end;
             (* Delete spent inputs (non-coinbase only) *)
             if not is_cb then begin
               if ibd_mode then begin
                 (* IBD: only OptimizedUtxoSet — use remove_fast since we
                    don't need the old entry value *)
                 (match ibd.utxo_set with
                  | Some utxo ->
                    List.iter (fun inp ->
                      Utxo.OptimizedUtxoSet.remove_fast utxo
                        inp.Types.previous_output.Types.txid
                        (Int32.to_int inp.Types.previous_output.Types.vout)
                    ) tx.Types.inputs
                  | None -> ())
               end else begin
                 List.iter (fun inp ->
                   ibd.pending_utxo_deletes <-
                     (inp.Types.previous_output.Types.txid,
                      Int32.to_int inp.Types.previous_output.Types.vout)
                     :: ibd.pending_utxo_deletes;
                   (match ibd.utxo_set with
                    | Some utxo ->
                      ignore (Utxo.OptimizedUtxoSet.remove utxo
                        inp.Types.previous_output.Types.txid
                        (Int32.to_int inp.Types.previous_output.Types.vout))
                    | None -> ())
                 ) tx.Types.inputs
               end
             end
           ) block.transactions;
           (* Update chain state *)
           entry.download_state <- Validated;
           ibd.next_process_height <- ibd.next_process_height + 1;
           ibd.chain.blocks_synced <- height;
           ibd.blocks_since_flush <- ibd.blocks_since_flush + 1;
           incr processed;
           (* Store nTx for every connected block so getblockheader can
              return the correct count without needing the full block body.
              This fires on both assume-valid and full-validation paths. *)
           Storage.ChainDB.store_block_ntx ibd.chain.db entry.hash
             (List.length block.transactions);
           (* Prune old blocks if pruning is enabled *)
           prune_old_blocks ibd.chain height;
           (* Periodic UTXO flush — by block count or dirty set size.
              The dirty threshold should be high enough that most short-lived
              UTXOs (created and spent within the window) are eliminated by
              remove_fast's FRESH optimisation, never touching disk at all.
              500K accommodates the largest blocks (~4K txs * ~2 outputs)
              without flushing mid-batch. *)
           let dirty_too_large = match ibd.utxo_set with
             | Some utxo -> Utxo.OptimizedUtxoSet.dirty_count utxo > 500_000
             | None -> false
           in
           if ibd.blocks_since_flush >= utxo_flush_interval || dirty_too_large then begin
             flush_utxos ibd;
             ibd.blocks_since_flush <- 0;
             (* Also update chain tip in DB *)
             Storage.ChainDB.set_chain_tip ibd.chain.db entry.hash height;
             (* Run a major GC slice to keep heap from growing unbounded.
                Gc.compact is far too expensive (full heap compaction + scan);
                Gc.major runs one full major cycle which is sufficient to
                reclaim short-lived allocations without pausing for seconds. *)
             Gc.major ()
           end;
           (* Notify ZMQ subscribers about block connect *)
           zmq_notify_block ibd block entry.hash true;
           (* Check for orphan blocks that depend on this one *)
           ignore (process_orphan_blocks ibd entry.hash);
           (* Remove validated entries from queue *)
           queue_remove_validated ibd;
           step ()
         | Error e ->
           let err_str = Validation.block_error_to_string e in
           (* Witness commitment mismatch may mean the peer sent the block
              without witness serialization (stripped by a non-witness peer,
              or data mutated in transit).  This is analogous to Bitcoin
              Core's BLOCK_MUTATED — do NOT ban the peer, just re-request
              the block.  For all other validation errors, score the peer. *)
           let is_mutated_witness = match e with
             | Validation.BlockBadWitnessCommitment
             | Validation.BlockBadWitnessNonceSize
             | Validation.BlockUnexpectedWitness -> true
             | _ -> false
           in
           (* TxMissingInputs during IBD is a LOCAL-state failure, NOT
              peer-supplied bad data: the peer delivered a perfectly valid
              block whose inputs we cannot resolve because our own UTXO set
              is inconsistent (e.g. the apply_block_atomic crash window where
              a later block already deleted a prevout — the bug this branch
              is part of fixing).  Core would not (and could not) attribute a
              local CoinsView miss to the peer.  Re-request without scoring,
              exactly like the is_mutated_witness exemption, so we do not
              disconnect a healthy peer for our own corruption (the ~1033
              Channel_closed drops observed on the wedged mainnet node). *)
           let is_local_missing_inputs = match e with
             | Validation.BlockTxValidationFailed
                 (_, Validation.TxMissingInputs) -> true
             | _ -> false
           in
           let skip_scoring = is_mutated_witness || is_local_missing_inputs in
           if not skip_scoring then
             (match peer_id with
              | Some pid ->
                (match ibd.misbehavior_handler with
                 | Some handler -> handler pid "invalid_block"
                 | None -> ())
              | None -> ());
           Logs.warn (fun m ->
             m "Block validation failed at height %d: %s%s — resetting to re-download"
               height err_str
               (if is_mutated_witness then " (BLOCK_MUTATED — will retry)"
                else if is_local_missing_inputs then
                  " (local UTXO inconsistency — peer not scored, will retry)"
                else ""));
           (* Reset to NotRequested so the block is re-downloaded from a
              different peer.  Leaving it in Downloaded causes an infinite
              retry loop against the same (possibly corrupt/stripped) data. *)
           entry.download_state <- NotRequested;
           continue := false;
           Lwt.return_unit)
      | NotRequested | Requested _ ->
        continue := false;  (* Waiting for download *)
        Lwt.return_unit
      | Validated ->
        (* Already validated, skip *)
        ibd.next_process_height <- ibd.next_process_height + 1;
        step ()
      end
    | None ->
      continue := false;
      Lwt.return_unit
  in
  let%lwt () = step () in
  match !error with
  | Some e -> Lwt.return (Error e)
  | None -> Lwt.return (Ok !processed)

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

(* Disconnect blocks from current tip back to [target] (an ancestor of
   the current tip). Restores UTXOs spent on the disconnected blocks
   from each block's stored undo data and removes the outputs that the
   disconnected blocks created. Block bodies and headers are preserved
   on disk so the chain can be re-applied later via [reorganize].
   Undo data for the disconnected blocks is deleted (matching what
   [reorganize] does on its disconnect path); on re-apply, [reorganize]
   rebuilds undo data fresh from the recovered UTXO set.

   Mirrors Bitcoin Core's [TemporaryRollback] used by [dumptxoutset]
   ([src/rpc/blockchain.cpp:3157]). The caller is responsible for
   re-applying the chain afterwards (e.g. via [reorganize new_tip])
   if it does not want to leave the chainstate at [target]. *)
let disconnect_to_target (state : chain_state) (target : header_entry)
    : (unit, string) result =
  match state.tip with
  | None -> Error "No current tip"
  | Some current_tip when current_tip.height < target.height ->
    Error (Printf.sprintf
             "Target height %d is above current tip %d"
             target.height current_tip.height)
  | Some current_tip when Cstruct.equal current_tip.hash target.hash ->
    Ok ()  (* Already at target — no-op. *)
  | Some current_tip ->
    (* The target must be an ancestor on the active chain. Verify by
       walking back from current_tip until we hit target's height. *)
    let rec walk_back (h : header_entry) : (header_entry, string) result =
      if h.height = target.height then
        if Cstruct.equal h.hash target.hash then Ok h
        else Error "Target is not an ancestor of the current tip"
      else
        let pkey = Cstruct.to_string h.header.prev_block in
        match Hashtbl.find_opt state.headers pkey with
        | Some p -> walk_back p
        | None -> Error "Cannot walk to target (missing parent)"
    in
    (match walk_back current_tip with
     | Error _ as e -> e
     | Ok _ ->
       (* Build the list of blocks to disconnect (between target and
          current tip), tip-first (i.e. disconnect order). *)
       let to_disconnect = collect_path state target current_tip in
       (* Walk tip-first applying undo per block. We collect all UTXO
          mutations into a single batch so the disconnect is atomic
          relative to a crash partway through. *)
       let batch = Storage.ChainDB.batch_create () in
       let rec disconnect = function
         | [] -> Ok ()
         | (entry : header_entry) :: rest ->
           match Storage.ChainDB.get_block state.db entry.hash with
           | None ->
             Error (Printf.sprintf
                      "Missing block at height %d during rollback disconnect"
                      entry.height)
           | Some block ->
             match Storage.ChainDB.get_undo_data state.db entry.hash with
             | None ->
               Error (Printf.sprintf
                        "Missing undo data at height %d during rollback \
                         disconnect"
                        entry.height)
             | Some undo_raw ->
               let r = Serialize.reader_of_cstruct
                         (Cstruct.of_string undo_raw) in
               let undo = Utxo.deserialize_undo_data r in
               (* Remove outputs created by this block. Reverse tx order
                  matches what [reorganize] does. *)
               let txs = List.rev block.transactions in
               List.iter (fun (tx : Types.transaction) ->
                 let txid = Crypto.compute_txid tx in
                 List.iteri (fun vout _out ->
                   Storage.ChainDB.batch_delete_utxo batch txid vout
                 ) tx.Types.outputs
               ) txs;
               (* Restore spent outputs from undo data. *)
               List.iter (fun (tx_undo : Utxo.tx_undo) ->
                 List.iter
                   (fun (outpoint, (utxo_entry : Utxo.utxo_entry)) ->
                     let data = encode_utxo utxo_entry.value
                                  utxo_entry.script_pubkey
                                  utxo_entry.height
                                  utxo_entry.is_coinbase in
                     Storage.ChainDB.batch_store_utxo batch
                       outpoint.Types.txid
                       (Int32.to_int outpoint.Types.vout)
                       data
                   ) tx_undo.spent_outputs
               ) undo.tx_undos;
               (* The undo data for this block is no longer valid:
                  [reorganize] will rebuild it on the connect path
                  when the chain is re-applied. *)
               Storage.ChainDB.delete_undo_data state.db entry.hash;
               disconnect rest
       in
       (match disconnect (List.rev to_disconnect) with
        | Error _ as e -> e
        | Ok () ->
          Storage.ChainDB.batch_write state.db batch;
          (* Clear sig cache: stale validation results from the
             disconnected segment must not leak forward. *)
          Sig_cache.clear_global ();
          (* Update in-memory + on-disk chain tip pointer. *)
          state.tip <- Some target;
          state.blocks_synced <- target.height;
          Storage.ChainDB.set_chain_tip state.db target.hash target.height;
          Logs.info (fun m ->
            m "Rollback complete: tip rewound from height %d to %d"
              current_tip.height target.height);
          Ok ()))

(* Boot-time UTXO-set reconciliation for the apply_block_atomic crash window.

   [apply_block_atomic] commits the rocksdb_utxo (RDB) batch FIRST and the
   cf_chainstate chain_tip SECOND (storage.ml:665-697), so a crash inside that
   window leaves the persisted UTXO set AHEAD of chain_tip:
   [rdb_tip = N, chain_tip = M] with N > M.

   The old boot path (cli.ml) treated this as SAFE on the false premise that
   "forward re-apply is idempotent" (storage.ml:638-641).  That premise is
   FALSE for cross-block spends: re-applying block M+1 from chain_tip+1 runs
   validate_tx_inputs (validation.ml:1136-1182), which READS the UTXO set and
   raises TxMissingInputs because a prevout was already DELETED by an
   already-committed later block (M+2..N) inside the crash window.  The block
   is rejected, re-downloaded forever, and the node wedges at chain_tip
   (the live mainnet camlcoin wedge at 952223/952224).

   This mirrors Bitcoin Core's [Chainstate::ReplayBlocks] / [RollbackBlock]
   (validation.cpp:4773-4858): when the coins DB tip and the block-index tip
   disagree after an interrupted flush, Core ROLLS THE UTXO SET BACK along the
   over-applied branch using each block's undo data (DisconnectBlock) down to
   the last consistent point, then rolls forward.  Both writing and deleting a
   UTXO are idempotent, so a window block whose mutations were only partially
   applied still ends up cleanly undone.

   [reconcile_rdb_to_chain_tip] rolls the RDB UTXO set (and the mirrored CF
   utxo column) DOWN from [rdb_height] to [target_height] (= chain_tip),
   tip-first, restoring spent outputs and removing created outputs from each
   window block's stored undo data.  After it returns Ok, the UTXO set matches
   chain_tip exactly and forward IBD re-applies M+1..N from a consistent base.

   If undo data is MISSING for ANY block in the window (sync.ml:3135-3140 style
   failure — the post-IBD connect paths at apply_block_atomic do not persist
   undo data), reconciliation is impossible, so we return Error and the caller
   falls back to a full resync rather than spinning in the missing-inputs loop. *)
let reconcile_rdb_to_chain_tip (state : chain_state)
    (rocksdb : Rocksdb_store.t) ~(rdb_height : int) ~(target_height : int)
    : (unit, string) result =
  if rdb_height <= target_height then Ok ()
  else begin
    (* Walk window blocks tip-first (rdb_height down to target_height+1).
       Accumulate inverse UTXO ops for ONE atomic RDB WriteBatch + mirror
       them into a CF batch so both backends stay consistent. *)
    let rdb_ops = ref [] in          (* (key, Some data | None) for RDB *)
    let cf_batch = Storage.ChainDB.batch_create () in
    let undo_to_delete = ref [] in   (* block hashes whose undo we invalidate *)
    let error = ref None in
    let h = ref rdb_height in
    while !error = None && !h > target_height do
      let height = !h in
      (match Storage.ChainDB.get_hash_at_height state.db height with
       | None ->
         error := Some (Printf.sprintf
           "reconcile: no height->hash mapping for window block %d" height)
       | Some bhash ->
         (match Storage.ChainDB.get_block state.db bhash with
          | None ->
            error := Some (Printf.sprintf
              "reconcile: missing block body at window height %d" height)
          | Some block ->
            (match Storage.ChainDB.get_undo_data state.db bhash with
             | None ->
               (* No undo data — cannot restore spent outputs. The post-IBD
                  connect paths (connect_stored_blocks / process_new_block)
                  do not write undo data, so this is the common case. Bail
                  to the caller's full-resync fallback. *)
               error := Some (Printf.sprintf
                 "reconcile: missing undo data at window height %d \
                  (post-IBD connect path does not persist undo)" height)
             | Some undo_raw ->
               let r = Serialize.reader_of_cstruct
                         (Cstruct.of_string undo_raw) in
               let undo = Utxo.deserialize_undo_data r in
               (* Remove outputs created by this block (skip provably-
                  unspendable: they were never written to the UTXO set,
                  matching apply_block_atomic's is_unspendable_script filter
                  on the connect path). Deleting an absent UTXO is a no-op,
                  so this is safe even for the partially-applied tip block. *)
               List.iter (fun (tx : Types.transaction) ->
                 let txid = Crypto.compute_txid tx in
                 List.iteri (fun vout (out : Types.tx_out) ->
                   if not (Utxo.is_unspendable_script out.Types.script_pubkey)
                   then begin
                     let key = Storage.ChainDB.rocksdb_utxo_key txid vout in
                     rdb_ops := (key, None) :: !rdb_ops;
                     Storage.ChainDB.batch_delete_utxo cf_batch txid vout
                   end
                 ) tx.Types.outputs
               ) block.transactions;
               (* Restore spent outputs from undo data. Re-adding an existing
                  UTXO is an idempotent overwrite. *)
               List.iter (fun (tx_undo : Utxo.tx_undo) ->
                 List.iter
                   (fun (outpoint, (e : Utxo.utxo_entry)) ->
                     let data = encode_utxo e.Utxo.value e.Utxo.script_pubkey
                                  e.Utxo.height e.Utxo.is_coinbase in
                     let txid = outpoint.Types.txid in
                     let vout = Int32.to_int outpoint.Types.vout in
                     let key = Storage.ChainDB.rocksdb_utxo_key txid vout in
                     rdb_ops := (key, Some data) :: !rdb_ops;
                     Storage.ChainDB.batch_store_utxo cf_batch txid vout data
                   ) tx_undo.spent_outputs
               ) undo.tx_undos;
               undo_to_delete := bhash :: !undo_to_delete)));
      decr h
    done;
    match !error with
    | Some msg -> Error msg
    | None ->
      (* Commit the inverse UTXO ops atomically to RDB, and in the SAME
         WriteBatch lower the RDB tip_height to target_height so the
         backend's recorded tip can never lead chain_tip again.

         ORDER MATTERS: [rdb_ops] is prepended while walking tip-first, so it
         is in reverse disconnect order.  [List.rev] restores disconnect order
         (highest window block first, chain_tip+1 last).  In a RocksDB
         WriteBatch the LAST write to a key wins, so disconnect order makes the
         lower (closer-to-chain_tip) block's op override a higher block's op on
         the same key — exactly Core's sequential cache mutation in
         RollbackBlock.  Concretely, for a spend chain X->Y->Z across the
         window, block N+2 restores Y while block N+1 must then DELETE Y (it
         created Y); applying N+1 after N+2 yields the correct "Y absent at
         chain_tip" result.  Without the rev, N+2's restore would win and leak
         a phantom Y into the rolled-back set. *)
      Rocksdb_store.batch_write ~tip_height:target_height rocksdb
        (List.rev !rdb_ops);
      (* Mirror into the CF utxo column so a CF-side reader sees the same
         rolled-back set. *)
      Storage.ChainDB.batch_write state.db cf_batch;
      (* The undo data for the rolled-back window blocks is no longer valid;
         the connect path rebuilds it fresh when those blocks re-apply. *)
      List.iter (fun bhash ->
        Storage.ChainDB.delete_undo_data state.db bhash) !undo_to_delete;
      (* Stale sig-cache results from the over-applied segment must not leak
         forward into re-validation. *)
      Sig_cache.clear_global ();
      Logs.warn (fun m ->
        m "UTXO reconcile complete: rolled RDB tip back from %d to %d \
           (matches chain_tip); IBD will re-apply forward from a consistent base"
          rdb_height target_height);
      Ok ()
  end

(* ============================================================================
   Tx-index connect/disconnect (Pattern C0 closure 2026-05-05)
   ============================================================================

   Counterpart to Bitcoin Core's [TxIndex] class
   ([bitcoin-core/src/index/txindex.cpp]). Core's [BaseIndex::BlockConnected]
   fires [CustomAppend] which writes (txid -> DiskTxPos) for every tx in
   the connected block; [BaseIndex::BlockDisconnected] fires [CustomRemove]
   which deletes those entries when a block leaves the active chain.

   Pre-fix camlcoin had the storage helpers
   ([Storage.ChainDB.store_transaction] / [store_tx_index]) but no
   production caller — they were exercised only by tests. This left
   [getrawtransaction(txid, true)] returning "No such mempool or
   blockchain transaction" for every IBD-fetched and submitblock-accepted
   tx. The findings doc
   [CORE-PARITY-AUDIT/_txindex-revert-on-reorg-fleet-result-2026-05-05.md]
   recorded the symptom as Pattern C0 — txindex non-functional pre-reorg.

   The [tx_index_*] helpers below are called from every block-connect
   path (process_new_block, connect_stored_blocks, reorganize-connect,
   submit_block, block_import) and from the reorganize-disconnect path.

   Following 22667c2 (Pattern Y closure) which made
   [reorganize] reachable from submitblock, this is the minimum wiring
   to make [getrawtransaction] return a stable result across reorgs. *)
let tx_index_write_for_block (db : Storage.ChainDB.t)
    (block : Types.block) (block_hash : Types.hash256)
    (txid_arr : Types.hash256 array) : unit =
  List.iteri (fun tx_idx tx ->
    let txid =
      if tx_idx < Array.length txid_arr then txid_arr.(tx_idx)
      else Crypto.compute_txid tx
    in
    (* Store the full tx blob and the txid -> (block_hash, tx_idx)
       pointer. Both are needed: [Rpc.lookup_transaction] hits the
       tx_index CF first, then dereferences the pointer to fetch the
       tx blob via [Storage.ChainDB.get_transaction]. *)
    Storage.ChainDB.store_transaction db txid tx;
    Storage.ChainDB.store_tx_index db txid block_hash tx_idx
  ) block.transactions

(* Same as [tx_index_write_for_block] but recomputes txids when the
   caller doesn't have a precomputed array (e.g. reorg-connect path
   when txid_arr from accept_block is not threaded through). *)
let tx_index_write_for_block_recompute (db : Storage.ChainDB.t)
    (block : Types.block) (block_hash : Types.hash256) : unit =
  List.iteri (fun tx_idx tx ->
    let txid = Crypto.compute_txid tx in
    Storage.ChainDB.store_transaction db txid tx;
    Storage.ChainDB.store_tx_index db txid block_hash tx_idx
  ) block.transactions

(* Erase tx_index entries for every tx in a disconnected block.
   Mirrors Bitcoin Core's [TxIndex::CustomRemove] (txindex.cpp:69-83).
   We delete only the txid -> (block_hash, tx_idx) pointer; the raw
   tx blob in the [tx] CF is retained. Core does the same — its
   tx blob lookup goes through [DiskTxPos] read from txindex, so once
   the pointer is gone the raw blob is unreachable. Keeping the blob
   is also Core-consistent because side-branch tx blobs may still be
   reachable via [getrawtransaction(<txid>, <blockhash>)] if the
   blockhash is supplied explicitly (camlcoin's [Rpc.lookup_transaction]
   already supports the explicit-blockhash path independently of the
   tx_index CF). *)
let tx_index_erase_for_block (db : Storage.ChainDB.t)
    (block : Types.block) : unit =
  List.iter (fun tx ->
    let txid = Crypto.compute_txid tx in
    Storage.ChainDB.delete_tx_index db txid
  ) block.transactions

(* ============================================================================
   Multi-block reorg atomicity (Pattern D-FULL closure 2026-05-05)
   ============================================================================

   [reorganize] orchestrates the disconnect-then-reconnect of a chain split.
   Pre-D-FULL (i.e. the [22667c2 / 838de15] state) the disconnect side
   already used an accumulator pattern: outputs to remove and UTXOs to
   restore from undo data piled into [ibd.pending_utxo_updates] /
   [ibd.pending_utxo_deletes], and a single [flush_utxos] commit landed
   them all together (Pattern D-PARTIAL — best of any impl per the
   2026-05-05 fleet audit
   [CORE-PARITY-AUDIT/_post-reorg-consistency-fleet-result-2026-05-05.md]).
   The reconnect side, however, was per-block: every reconnected block
   stored its own block body, undo data, tx_index pointers, and
   per-block UTXO flush in independent batches. A crash partway through
   reconnect left N reconnect-batches plus the disconnect-batch on disk
   and M-N blocks pending — a structurally observable split.

   This refactor extends the accumulator to the reconnect side: ALL
   disk mutations from BOTH halves of the reorg (UTXO puts/deletes +
   undo data + block bodies + tx_index pointers + height-hash mappings
   + tip flip) accumulate into ONE shared [Storage.ChainDB.batch], and
   commit with a single [batch_write]. RocksDB's [WriteBatch] is
   atomic (all-or-nothing on WAL replay), so a crash mid-reorg either
   leaves the chain at the OLD tip with NOTHING applied, or at the
   NEW tip with EVERYTHING applied — never a split.

   Mirrors Bitcoin Core's reorg coordination through
   [CCoinsViewDB::BatchWrite] ([txdb.cpp:100+]) wrapping the active-
   chain pivot in [CChainState::ActivateBestChainStep]
   ([validation.cpp]).

   Side effects deferred until AFTER successful commit (so a rollback
   doesn't leave hanging notifications):
     - ZMQ block-disconnect / block-connect notifications
     - Mempool refill (re-add disconnected txs) + per-connect-block
       [Mempool.remove_for_block]
     - [prune_old_blocks]
     - In-memory [state.tip / blocks_synced / headers_synced] updates
     - [Sig_cache.clear_global]

   The [pending_view] hashtable maintains an O(1) lookup overlay for
   the connect-side validator: a UTXO restored on the disconnect side
   that the new chain spends, or a UTXO created by an earlier connect
   block that a later connect block spends, must both be visible to
   the [base_lookup] passed into [Validation.accept_block]. Without
   the overlay, [accept_block] would read disk-only state (pre-reorg
   UTXOs) and reject the new chain's first spend. *)

(* Cap multi-block reorg depth.  Rolling back more than this many blocks
   is almost certainly a misconfigured peer or a malicious attempt to
   replace deep history; abort rather than burn unbounded I/O.  Bitcoin
   Core has the same conceptual cap via the [-maxreorgdepth] knob (default
   100 in [validation.h]'s [DEFAULT_MAX_REORG_DEPTH]).  *)
let max_reorg_depth = 100

(* O(1) overlay used by the reorg connect-side [base_lookup] and by the
   undo-data construction loop. Mirrors the in-progress UTXO state held
   in [ibd.pending_utxo_updates] / [ibd.pending_utxo_deletes] (which
   carry the disk-batch payload) but in a hashtable form so a single
   block validation doesn't re-scan an unbounded list per input. *)
type reorg_view = {
  view_writes : (string, string) Hashtbl.t;  (* utxo_key -> encoded UTXO *)
  view_deletes : (string, unit) Hashtbl.t;   (* utxo_key marked spent *)
}

let reorg_view_create () : reorg_view = {
  view_writes = Hashtbl.create 1024;
  view_deletes = Hashtbl.create 1024;
}

(* Stable string key for the overlay: 32-byte txid (raw bytes) ++ 4-byte
   little-endian vout. Distinct keys never collide because the txid is
   already a 32-byte hash. *)
let utxo_view_key (txid : Types.hash256) (vout : int) : string =
  let key = Bytes.create 36 in
  Bytes.blit_string (Cstruct.to_string txid) 0 key 0 32;
  Bytes.set_uint8 key 32 (vout land 0xff);
  Bytes.set_uint8 key 33 ((vout lsr 8) land 0xff);
  Bytes.set_uint8 key 34 ((vout lsr 16) land 0xff);
  Bytes.set_uint8 key 35 ((vout lsr 24) land 0xff);
  Bytes.unsafe_to_string key

let reorg_view_put (v : reorg_view) (txid : Types.hash256) (vout : int)
    (data : string) : unit =
  let k = utxo_view_key txid vout in
  Hashtbl.remove v.view_deletes k;
  Hashtbl.replace v.view_writes k data

let reorg_view_delete (v : reorg_view) (txid : Types.hash256) (vout : int)
    : unit =
  let k = utxo_view_key txid vout in
  Hashtbl.remove v.view_writes k;
  Hashtbl.replace v.view_deletes k ()

type view_status =
  | View_present of string  (* encoded UTXO bytes *)
  | View_absent              (* explicitly spent in this reorg *)
  | View_unknown             (* fall back to disk *)

let reorg_view_get (v : reorg_view) (txid : Types.hash256) (vout : int)
    : view_status =
  let k = utxo_view_key txid vout in
  if Hashtbl.mem v.view_deletes k then View_absent
  else
    match Hashtbl.find_opt v.view_writes k with
    | Some data -> View_present data
    | None -> View_unknown

(* Decode the on-disk UTXO blob into a [Validation.utxo].  Layout matches
   [encode_utxo] above and [Storage.ChainDB.get_utxo]'s return value. *)
let decode_utxo_for_lookup (txid : Types.hash256) (vout_le : int32)
    (data : string) : Validation.utxo =
  let r = Serialize.reader_of_cstruct (Cstruct.of_string data) in
  let value = Serialize.read_int64_le r in
  let script_len = Serialize.read_compact_size r in
  let script = Serialize.read_bytes r script_len in
  let stored_height = Int32.to_int (Serialize.read_int32_le r) in
  let utxo_is_coinbase = Serialize.read_uint8 r = 1 in
  Validation.{
    txid;
    vout = vout_le;
    value;
    script_pubkey = script;
    height = stored_height;
    is_coinbase = utxo_is_coinbase;
  }

(* [batch] in this module is [Storage.ChainDB.batch]; the alias keeps the
   reorg helpers below readable without importing the whole module. *)

(* Tri-valued result mirroring Bitcoin Core's [DisconnectResult] enum
   (validation.h:451-455).  [Disconnect_ok] is the clean case; the
   [Disconnect_unclean] case still rolled the UTXO set back but flagged
   that the UTXO state diverged from what the block's outputs would
   produce on a fresh connect (an "overwrite" — a coinbase txid was
   already live in the cache when its output was un-spent, or the
   block's output didn't match the coin we just spent).  [Disconnect_failed]
   is unrecoverable corruption: undo data missing / size-inconsistent,
   or [apply_tx_in_undo] couldn't reconstruct missing metadata.  Callers
   must abort the reorg on [Disconnect_failed]. *)
type disconnect_result =
  | Disconnect_ok       (* clean rollback *)
  | Disconnect_unclean  (* rolled back but UTXO set was inconsistent *)
  | Disconnect_failed   (* unrecoverable corruption *)

(* Overlay-aware [HaveCoin] for the reorg view.  Mirrors Bitcoin Core's
   [CCoinsViewCache::HaveCoin] (coins.cpp:50): returns true iff the
   outpoint resolves to an unspent coin via the overlay (which takes
   priority over disk) or, if absent from the overlay, via disk. *)
let view_have_coin (view : reorg_view) (db : Storage.ChainDB.t)
    (txid : Types.hash256) (vout : int) : bool =
  match reorg_view_get view txid vout with
  | View_present _ -> true
  | View_absent -> false
  | View_unknown ->
    (match Storage.ChainDB.get_utxo db txid vout with
     | Some _ -> true
     | None -> false)

(* Overlay-aware sibling-coin lookup for [apply_tx_in_undo]'s
   missing-metadata recovery.  Bitcoin Core walks [view] for any UTXO
   whose key starts with [txid]; we approximate by scanning the four
   most common output indices (0..3) in the overlay then falling
   through to a disk iteration via [Storage.ChainDB.get_utxo].  Pre-0.10
   undo records that lack metadata are exceedingly rare (mainnet only
   exhibits a handful from the pre-2014 era) and exclusively reference
   the pre-BIP30 91722/91812 era where output counts are tiny; bounding
   the overlay scan keeps the hot path allocation-free without losing
   correctness.  Core reference: validation.cpp:2155-2166
   (AccessByTxid wrapper around CCoinsViewCache::AccessCoin). *)
let access_by_txid_in_view (view : reorg_view) (db : Storage.ChainDB.t)
    (txid : Types.hash256) : (int * Utxo.utxo_entry) option =
  let decode (data : string) : Utxo.utxo_entry =
    let r = Serialize.reader_of_cstruct (Cstruct.of_string data) in
    Utxo.deserialize_utxo_entry r
  in
  let try_v v =
    match reorg_view_get view txid v with
    | View_present data -> Some (v, decode data)
    | View_absent -> None
    | View_unknown ->
      (match Storage.ChainDB.get_utxo db txid v with
       | Some data -> Some (v, decode data)
       | None -> None)
  in
  let rec scan v limit =
    if v >= limit then None
    else match try_v v with
      | Some r -> Some r
      | None -> scan (v + 1) limit
  in
  scan 0 16

(* Apply a single tx-input undo entry to the reorg view.  Mirrors
   Bitcoin Core's [ApplyTxInUndo] (validation.cpp:2149-2175):

   1. If the coin is already present in the cache (overlay or disk),
      flag fClean=false (overwriting an unspent output).
   2. If the undo's height is 0, the record is from a pre-0.10 datadir
      that recorded metadata only on the LAST spend of a tx's outputs.
      Recover height + coinbase flag from a sibling output of the same
      txid via [access_by_txid_in_view].  If no sibling exists, the
      record is unrecoverable — return [Disconnect_failed].
   3. Stage the restored coin into [view] (and the legacy pending-list
      mirror for the disconnect-only path that doesn't run the
      collision-resolving [stage_pending_utxos_into_batch]).

   Returns [Disconnect_ok] on clean restore, [Disconnect_unclean] on
   overwrite, [Disconnect_failed] on unrecoverable corruption. *)
let apply_tx_in_undo (ibd : ibd_state) (view : reorg_view)
    (out : Types.outpoint) (undo_entry : Utxo.utxo_entry)
    : disconnect_result =
  let state = ibd.chain in
  let vout = Int32.to_int out.Types.vout in
  (* Gate 1: HaveCoin → overwrite (fClean=false).  Core validation.cpp:2153 *)
  let is_overwrite = view_have_coin view state.db out.Types.txid vout in
  (* Gate 2: Missing-metadata recovery for pre-0.10 undo records.
     Core validation.cpp:2155-2166. *)
  let recovered_entry =
    if undo_entry.Utxo.height <> 0 then Some undo_entry
    else begin
      match access_by_txid_in_view view state.db out.Types.txid with
      | None -> None  (* No sibling found — unrecoverable *)
      | Some (_, alternate) ->
        (* IsSpent semantics: a coin returned by access_by_txid is by
           definition unspent (we only walked unspent outpoints).  Copy
           height + coinbase flag from the alternate. *)
        Some { undo_entry with
               Utxo.height = alternate.Utxo.height;
               Utxo.is_coinbase = alternate.Utxo.is_coinbase }
    end
  in
  match recovered_entry with
  | None ->
    Logs.err (fun m ->
      m "ApplyTxInUndo: cannot recover metadata for %s:%d"
        (Types.hash256_to_hex_display out.Types.txid) vout);
    Disconnect_failed
  | Some e ->
    let data = encode_utxo e.Utxo.value e.Utxo.script_pubkey
                 e.Utxo.height e.Utxo.is_coinbase in
    (* Core's AddCoin(possible_overwrite=!fClean) — we replicate this
       in the overlay by unconditionally putting (reorg_view_put already
       removes any matching tombstone, so the overlay tolerates
       overwrite).  The legacy flat-list mirror is kept for the
       direct-flush path that doesn't use stage_pending_utxos_into_batch. *)
    ibd.pending_utxo_updates <-
      (out.Types.txid, vout, data) :: ibd.pending_utxo_updates;
    reorg_view_put view out.Types.txid vout data;
    if is_overwrite then Disconnect_unclean else Disconnect_ok

(* Disconnect-side accumulator: stage every disk mutation needed to undo
   one block into the shared [batch] and the [pending_view] overlay.
   Mirrors the existing per-block disconnect pattern but writes through
   a caller-supplied batch instead of via [delete_undo_data] /
   [tx_index_erase_for_block] direct calls. The block body itself is
   retained on disk (Core parity — disconnected blocks remain
   available on side-branches for [getblock <hash>]).

   W92: comprehensive Core-parity audit.  Implements the full
   [Chainstate::DisconnectBlock] + [ApplyTxInUndo] gate set from
   validation.cpp:2149-2248.  Gates:

   G1  Read undo data (was present)
   G2  Block/undo size consistency: vtxundo.size() + 1 == block.vtx.size()
       (validation.cpp:2190)
   G3  fEnforceBIP30 = !IsBIP30Unspendable(height, hash) — the disconnect-
       side BIP-30 exemption (validation.cpp:2201-2202)
   G4  Reverse iteration over block.vtx (validation.cpp:2205) — was present
   G5  Per-tx is_bip30_exception flag (validation.cpp:2209)
   G6  IsUnspendable() skip on output check + UTXO delete (validation.cpp:2214)
       — only outputs that COULD be in the UTXO set are checked/deleted
   G7  SpendCoin verification: is_spent && out matches && height matches &&
       coinbase flag matches (validation.cpp:2218) — clears the per-output
       "missing or mismatched" path
   G8  fClean accumulator across all output mismatches (validation.cpp:2220)
   G9  Skip coinbase txundo (i > 0) (validation.cpp:2227) — was present
   G10 txundo.vprevout.size() == tx.vin.size() (validation.cpp:2229)
   G11 Reverse iteration over tx.vin (validation.cpp:2233-2234) — Core
       processes inputs back-to-front; we mirror that to match the order
       in which apply_tx_in_undo discovers overwrites
   G12 ApplyTxInUndo + DISCONNECT_FAILED short-circuit (validation.cpp:2236-2238)
   G13 Return DISCONNECT_UNCLEAN if any fClean was tripped (validation.cpp:2247)

   The block body itself is RETAINED on disk for side-branch
   [getblock <hash>] queries (Core's policy via [pruneblockchain] /
   [validation.cpp]'s [m_blockman]).  Undo data and tx_index pointers
   are removed.  The chain-tip flip to pprev is done by the caller
   ([reorganize]) after the connect-side stages run — both halves of
   the reorg share a single [batch_write] for atomicity. *)
let disconnect_block_into_batch
    (ibd : ibd_state) (batch : Storage.ChainDB.batch)
    (view : reorg_view)
    (entry : header_entry)
    : (Types.transaction list * disconnect_result, string) result =
  let state = ibd.chain in
  (* G1: read block body *)
  match Storage.ChainDB.get_block state.db entry.hash with
  | None ->
    Error (Printf.sprintf
      "Missing block at height %d during reorg disconnect" entry.height)
  | Some block ->
    (* G1: read undo data *)
    match Storage.ChainDB.get_undo_data state.db entry.hash with
    | None ->
      Error (Printf.sprintf
        "Missing undo data at height %d during reorg disconnect" entry.height)
    | Some undo_raw ->
      let r = Serialize.reader_of_cstruct (Cstruct.of_string undo_raw) in
      let undo = Utxo.deserialize_undo_data r in
      let num_txs = List.length block.transactions in
      let num_tx_undos = List.length undo.tx_undos in
      (* G2: block / undo size consistency check.  Core encodes one
         vtxundo per NON-coinbase tx, so vtxundo.size() + 1 == block.vtx.size().
         validation.cpp:2190-2193. *)
      if num_tx_undos + 1 <> num_txs then
        Error (Printf.sprintf
          "DisconnectBlock: block and undo data inconsistent at height %d \
           (txs=%d undos=%d, expected undos=%d)"
          entry.height num_txs num_tx_undos (num_txs - 1))
      else begin
        let fclean = ref true in
        let fatal = ref None in
        (* G3: fEnforceBIP30 — disconnect-side exemption for the two
           IsBIP30Unspendable blocks (h=91722, h=91812 on mainnet with
           their specific canonical hashes).  These blocks had coinbases
           that were later overwritten by the BIP30Repeat blocks at
           h=91842 / h=91880, so when DISCONNECTING them the SpendCoin
           output check would correctly fail (the outpoint is missing
           from the UTXO set because the repeat block overwrote it).
           Core skips the fclean trip for these blocks.
           validation.cpp:2201-2202. *)
        let f_enforce_bip30 =
          not (Consensus.is_bip30_unspendable entry.height entry.hash)
        in
        (* Collect non-coinbase txs for mempool re-addition (deferred).
           Order matches block tx order. *)
        let txs_for_mempool =
          List.filter_map (fun (i, tx) ->
            if i > 0 then Some tx else None)
          (List.mapi (fun i tx -> (i, tx)) block.transactions)
        in
        let txs_array = Array.of_list block.transactions in
        let tx_undos_array = Array.of_list undo.tx_undos in
        (* G4: reverse iteration over transactions.  Core
           validation.cpp:2205: for (int i = block.vtx.size() - 1; i >= 0; i--). *)
        let i = ref (num_txs - 1) in
        while !i >= 0 && !fatal = None do
          let tx = txs_array.(!i) in
          let txid = Crypto.compute_txid tx in
          let is_coinbase = (!i = 0) in
          (* G5: per-tx BIP-30 exception flag. *)
          let is_bip30_exception = is_coinbase && not f_enforce_bip30 in
          (* G6 + G7: per-output verify+spend.  Walk vout 0..n-1, skip
             IsUnspendable outputs (never in UTXO set), then SpendCoin
             the rest and check value/script/height/coinbase against
             the block's claim.  validation.cpp:2213-2224. *)
          List.iteri (fun vout out ->
            if not (Utxo.is_unspendable_script out.Types.script_pubkey) then begin
              (* Check existing coin matches the output we're about to remove. *)
              let key_present = view_have_coin view state.db txid vout in
              let coin_matches =
                if not key_present then false
                else begin
                  (* Read the coin (overlay first, then disk) and verify
                     all four fields match the block's claim. *)
                  let data_opt =
                    match reorg_view_get view txid vout with
                    | View_present d -> Some d
                    | View_absent -> None
                    | View_unknown -> Storage.ChainDB.get_utxo state.db txid vout
                  in
                  match data_opt with
                  | None -> false
                  | Some data ->
                    let coin = decode_utxo_for_lookup txid
                                 (Int32.of_int vout) data in
                    coin.Validation.value = out.Types.value
                    && Cstruct.equal coin.Validation.script_pubkey
                         out.Types.script_pubkey
                    && coin.Validation.height = entry.height
                    && coin.Validation.is_coinbase = is_coinbase
                end
              in
              if (not key_present) || (not coin_matches) then begin
                (* G7: SpendCoin failure or mismatch.  G8: trip fclean
                   unless this is the BIP-30 exception coinbase. *)
                if not is_bip30_exception then fclean := false
              end;
              (* Stage the delete (the actual coin removal).  Idempotent
                 if the coin was already missing. *)
              ibd.pending_utxo_deletes <-
                (txid, vout) :: ibd.pending_utxo_deletes;
              reorg_view_delete view txid vout
            end
          ) tx.Types.outputs;
          (* G9 + G10 + G11 + G12: restore inputs for non-coinbase txs. *)
          if !i > 0 && !fatal = None then begin
            let tx_undo : Utxo.tx_undo = tx_undos_array.(!i - 1) in
            let inputs = tx.Types.inputs in
            let n_inputs = List.length inputs in
            let n_undos = List.length tx_undo.Utxo.spent_outputs in
            if n_undos <> n_inputs then begin
              fatal := Some (Printf.sprintf
                "DisconnectBlock: tx and undo inconsistent at height %d \
                 tx %d (inputs=%d undos=%d)"
                entry.height !i n_inputs n_undos)
            end else begin
              (* G11: reverse-iterate inputs (validation.cpp:2233-2234). *)
              let inputs_array = Array.of_list inputs in
              let undos_array =
                Array.of_list tx_undo.Utxo.spent_outputs in
              let j = ref (n_inputs - 1) in
              while !j >= 0 && !fatal = None do
                let inp = inputs_array.(!j) in
                let (out_point, undo_entry) = undos_array.(!j) in
                (* The undo's outpoint should match the input's prevout.
                   We trust the undo record's outpoint (Core does the
                   same — it uses txundo.vprevout[j], not tx.vin[j]) but
                   the input's prevout is the canonical address the
                   coin must be restored to. *)
                let _ = out_point in
                let restored_outpoint = inp.Types.previous_output in
                (* G12: ApplyTxInUndo + DISCONNECT_FAILED short-circuit. *)
                (match apply_tx_in_undo ibd view restored_outpoint undo_entry with
                 | Disconnect_failed ->
                   fatal := Some (Printf.sprintf
                     "DisconnectBlock: ApplyTxInUndo failed at height %d \
                      tx %d input %d" entry.height !i !j)
                 | Disconnect_unclean -> fclean := false
                 | Disconnect_ok -> ());
                decr j
              done
            end
          end;
          decr i
        done;
        (match !fatal with
         | Some msg -> Error msg
         | None ->
           (* Stage [delete_undo_data] for the disconnected block (now stale). *)
           Storage.ChainDB.batch_delete_undo_data batch entry.hash;
           (* Stage [tx_index_erase] for every tx in the block (Pattern C0
              counterpart of [TxIndex::CustomRemove]). The raw tx blob in the
              [tx] CF is retained for explicit-blockhash [getrawtransaction]
              lookups, matching [tx_index_erase_for_block]'s on-disk policy. *)
           List.iter (fun tx ->
             let txid = Crypto.compute_txid tx in
             Storage.ChainDB.batch_delete_tx_index batch txid
           ) block.transactions;
           let result =
             if !fclean then Disconnect_ok else Disconnect_unclean
           in
           Logs.debug (fun m ->
             m "Staged disconnect for block at height %d (result=%s)"
               entry.height
               (match result with
                | Disconnect_ok -> "OK"
                | Disconnect_unclean -> "UNCLEAN"
                | Disconnect_failed -> "FAILED"));
           Ok (txs_for_mempool, result))
      end

(* Connect-side accumulator: the symmetric counterpart of
   [disconnect_block_into_batch]. Validates the new chain's block,
   then stages its block body, undo data, tx_index, and UTXO delta
   into the shared [batch] and overlay [view]. The validator's
   [base_lookup] reads through the overlay so an input spent on the
   new chain that resolves to a UTXO restored by an earlier
   disconnect step (or created by an earlier connect step) is found
   without an intermediate disk flush. *)
let connect_block_into_batch
    ?(skip_pow = false)
    (ibd : ibd_state) (batch : Storage.ChainDB.batch)
    (view : reorg_view)
    (entry : header_entry)
    : (Types.block, string) result =
  let state = ibd.chain in
  match Storage.ChainDB.get_block state.db entry.hash with
  | None ->
    Error (Printf.sprintf
      "Missing block at height %d during reorg connect" entry.height)
  | Some block ->
    let height = entry.height in
    let expected_bits = compute_expected_bits state height block.header in
    let median_time = compute_median_time_past state height in
    let prev_block_time = get_prev_block_time state height in
    (* Lookup that reads through the overlay first, then disk. Used by
       [accept_block] for input resolution and below for undo-data
       construction. *)
    let lookup outpoint =
      let vout = Int32.to_int outpoint.Types.vout in
      match reorg_view_get view outpoint.Types.txid vout with
      | View_absent -> None
      | View_present data ->
        Some (decode_utxo_for_lookup outpoint.Types.txid
                outpoint.Types.vout data)
      | View_unknown ->
        (match Storage.ChainDB.get_utxo state.db outpoint.Types.txid vout with
         | None -> None
         | Some data ->
           Some (decode_utxo_for_lookup outpoint.Types.txid
                   outpoint.Types.vout data))
    in
    (* Same overlay-aware reader, but returns a [Utxo.utxo_entry] for the
       undo-data builder.  Both call sites must share the overlay so the
       undo data we write reflects what the connect step actually spent
       (rather than the stale pre-reorg disk image). *)
    let lookup_utxo_entry (prev : Types.outpoint)
        : (Types.outpoint * Utxo.utxo_entry) option =
      let vout = Int32.to_int prev.Types.vout in
      let decode_entry data : Utxo.utxo_entry =
        let r = Serialize.reader_of_cstruct (Cstruct.of_string data) in
        Utxo.deserialize_utxo_entry r
      in
      match reorg_view_get view prev.Types.txid vout with
      | View_absent -> None
      | View_present data -> Some (prev, decode_entry data)
      | View_unknown ->
        (match Storage.ChainDB.get_utxo state.db prev.Types.txid vout with
         | None -> None
         | Some data -> Some (prev, decode_entry data))
    in
    let skip_scripts = is_assume_valid state height in
    let validation_flags =
      if skip_scripts then 0
      else Consensus.get_block_script_flags height state.network
    in
    (* [skip_pow] mirrors Bitcoin Core's CheckBlock(..., fCheckPOW) parameter
       (validation.cpp CheckBlockHeader -> CheckProofOfWork). It gates ONLY the
       block-hash <= target proof-of-work test, NOT the expected_bits
       difficulty-equality rule (which remains enforced via [expected_bits]
       above). Default [false] preserves the production reorg path exactly
       (the live caller [reorganize] never passes it, so PoW stays enforced on
       every real reorg-connected block). It exists so an out-of-band
       differential harness can drive [connect_block_into_batch] over
       crafted-synthetic blocks whose nonce was not mined to the network
       target. *)
    (match Validation.accept_block
             ~network:state.network ~block ~height
             ~expected_bits ~median_time ~prev_block_time ~base_lookup:lookup
             ~flags:validation_flags ~skip_scripts ~skip_pow
             ~get_mtp_at_height:(get_mtp_for_height state)
             ?bip34_height_hash:(bip34_height_hash_for state) () with
     | Validation.AB_err e ->
       (match ibd.misbehavior_handler with
        | Some _handler ->
          Logs.warn (fun m ->
            m "Invalid block at height %d during reorg (no peer to penalize)" height)
        | None -> ());
       Error (Printf.sprintf
         "Block validation failed at height %d during reorg: %s"
         height (Validation.block_error_to_string e))
     | Validation.AB_ok (_fees, _txid_arr, _spent_utxos) ->
       (* Stage block body if not already on disk. The disk write is
          idempotent — the active path that brought us here always
          stored the body when it was first received, but a side-branch
          accepted via [register_side_branch_header] may not have. *)
       if not (Storage.ChainDB.has_block state.db entry.hash) then
         Storage.ChainDB.batch_store_block batch entry.hash block;
       (* Build undo data from overlay-aware lookups. *)
       let tx_undos = List.filter_map (fun (tx_idx, tx) ->
         if tx_idx > 0 then begin
           let spent = List.filter_map (fun inp ->
             lookup_utxo_entry inp.Types.previous_output
           ) tx.Types.inputs in
           Some Utxo.{ spent_outputs = spent }
         end else None
       ) (List.mapi (fun i tx -> (i, tx)) block.transactions) in
       let undo : Utxo.undo_data = { height; tx_undos } in
       let uw = Serialize.writer_create () in
       Utxo.serialize_undo_data uw undo;
       Storage.ChainDB.batch_store_undo_data batch entry.hash
         (Cstruct.to_string (Serialize.writer_to_cstruct uw));
       (* BIP-157 filter index append for the reorg-connect path. We
          flatten [tx_undos] into a single list of (outpoint, entry)
          pairs so [append_filter_if_enabled_from_entries] can extract
          scriptPubKeys without re-computing them.

          Reorg ordering: the disconnect half of the reorg has already
          called [Block_index.rewind_bip157_index] (see [reorganize])
          to roll the index back to the fork point, so this append at
          [height] sees a fresh parent filter header just like a normal
          IBD connect. *)
       let spent_entries =
         List.concat_map (fun (tu : Utxo.tx_undo) -> tu.spent_outputs)
           tx_undos
       in
       append_filter_if_enabled_from_entries state ~block ~height
         ~spent_entries;
       (* Stage tx_index pointers (Pattern C0 counterpart of
          [TxIndex::CustomAppend]). The raw tx blob goes into the
          [tx] CF, the txid->(block_hash, tx_idx) pointer into the
          [tx_index] CF — both via the shared batch. *)
       List.iteri (fun tx_idx tx ->
         let txid = Crypto.compute_txid tx in
         Storage.ChainDB.batch_store_transaction batch txid tx;
         Storage.ChainDB.batch_store_tx_index batch txid entry.hash tx_idx
       ) block.transactions;
       (* Stage UTXO delta. Skip provably-unspendable outputs for
          Core-[AddCoins] parity (see the 22667c2 commit for the
          SegWit OP_RETURN coinbase commitment that motivated this
          filter on the reorg-connect path). *)
       List.iteri (fun tx_idx tx ->
         let txid = Crypto.compute_txid tx in
         let is_cb = (tx_idx = 0) in
         if not (Consensus.is_genesis_coinbase height txid) then begin
           List.iteri (fun vout out ->
             if not (Utxo.is_unspendable_script
                       out.Types.script_pubkey) then begin
               let data = encode_utxo out.Types.value
                   out.Types.script_pubkey height is_cb in
               ibd.pending_utxo_updates <-
                 (txid, vout, data) :: ibd.pending_utxo_updates;
               reorg_view_put view txid vout data
             end
           ) tx.Types.outputs
         end;
         if not is_cb then begin
           List.iter (fun inp ->
             let prev = inp.Types.previous_output in
             let vout = Int32.to_int prev.Types.vout in
             ibd.pending_utxo_deletes <-
               (prev.Types.txid, vout) :: ibd.pending_utxo_deletes;
             reorg_view_delete view prev.Types.txid vout
           ) tx.Types.inputs
         end
       ) block.transactions;
       Logs.debug (fun m ->
         m "Staged connect for block at height %d during reorg" height);
       Ok block)

(* Stage the reorg's net UTXO delta into the shared batch by walking
   the [reorg_view] overlay.  The overlay already represents the
   correctly-resolved final state of every (txid, vout) the reorg
   touched: [reorg_view_put] removes any matching [view_deletes]
   entry, [reorg_view_delete] removes any matching [view_writes]
   entry, so each key lives in at most one of the two tables.  This
   is the source of truth for what we must commit.

   Pre-2026-05-07 this function instead iterated two flat lists
   ([ibd.pending_utxo_updates] / [pending_utxo_deletes]) accumulated
   in append order across all disconnect+connect blocks, then wrote
   "all puts, then all deletes" — meaning a key that was deleted
   on the disconnect side and re-put on the connect side ended up
   DELETED (the trailing delete won).  That is wrong whenever a
   coinbase txid collides between the disconnected chain and the
   reconnected chain — which is exactly what happens in regtest
   reorgs (deterministic mining produces identical coinbase
   serialization at the same height + same address, so A1's
   coinbase txid == B1's coinbase txid; corpus entry
   `reorg-via-submitblock` triggers it).  Bitcoin Core's
   [CCoinsViewCache] handles this naturally because it mutates the
   in-memory cache per-block; we replicate that resolution by
   committing the view's net state, not the raw event log.

   The pending-list mutations in the disconnect/connect helpers are
   left in place but are now ignored by this function and cleared
   here; the overlay is the authoritative source.  IBD's connect
   path has its own [flush_utxos] commit that still uses those
   lists (forward-only path, no put/delete collisions, no view). *)
let stage_pending_utxos_into_batch
    (ibd : ibd_state) (batch : Storage.ChainDB.batch)
    (view : reorg_view) : unit =
  let decode_key (k : string) : Types.hash256 * int =
    let txid = Cstruct.of_string (String.sub k 0 32) in
    let vout =
      (Char.code k.[32])
      lor ((Char.code k.[33]) lsl 8)
      lor ((Char.code k.[34]) lsl 16)
      lor ((Char.code k.[35]) lsl 24)
    in
    (txid, vout)
  in
  Hashtbl.iter (fun k data ->
    let (txid, vout) = decode_key k in
    Storage.ChainDB.batch_store_utxo batch txid vout data
  ) view.view_writes;
  Hashtbl.iter (fun k () ->
    let (txid, vout) = decode_key k in
    Storage.ChainDB.batch_delete_utxo batch txid vout
  ) view.view_deletes;
  ibd.pending_utxo_updates <- [];
  ibd.pending_utxo_deletes <- []

(* Perform chain reorganization to new tip.  D-FULL atomicity: all
   disk writes from BOTH halves of the reorg land in ONE [batch_write].
   See the comment block above [max_reorg_depth] for the rationale. *)
let reorganize (ibd : ibd_state) (new_tip : header_entry)
    : (unit, string) result =
  let state = ibd.chain in
  let current_tip = match state.tip with
    | Some t -> t
    | None -> failwith "No current tip"
  in
  if Consensus.work_compare new_tip.total_work current_tip.total_work <= 0 then
    Error "New tip does not have more work"
  else begin
    match find_fork_point state current_tip new_tip with
    | Error e -> Error e
    | Ok fork_point ->
      (* Cap reorg depth.  Counted from the OLD tip back to the fork
         point — that's how many blocks we'd need to disconnect. *)
      let disconnect_depth = current_tip.height - fork_point.height in
      let connect_depth = new_tip.height - fork_point.height in
      if disconnect_depth > max_reorg_depth
         || connect_depth > max_reorg_depth then
        Error (Printf.sprintf
          "Reorg depth %d exceeds MAX_REORG_DEPTH=%d (disconnect=%d, connect=%d)"
          (max disconnect_depth connect_depth) max_reorg_depth
          disconnect_depth connect_depth)
      else begin
        Logs.info (fun m ->
          m "Reorganizing from height %d to %d (fork at %d)"
            current_tip.height new_tip.height fork_point.height);
        let to_disconnect = collect_path state fork_point current_tip in
        let to_connect = collect_path state fork_point new_tip in
        let batch = Storage.ChainDB.batch_create () in
        let view = reorg_view_create () in
        (* Reset pending lists so we own them for the duration of the
           reorg.  In normal operation the lists are empty here (callers
           hold the chain lock around reorganize); this is a defensive
           clear in case a prior partial run left state behind. *)
        ibd.pending_utxo_updates <- [];
        ibd.pending_utxo_deletes <- [];
        let disconnected_txs = ref [] in
        (* Disconnect side: iterate tip-back-to-fork. *)
        let rec disconnect_blocks = function
          | [] -> Ok ()
          | (entry : header_entry) :: rest ->
            (match disconnect_block_into_batch ibd batch view entry with
             | Error e -> Error e
             | Ok (txs, dres) ->
               (* W92: a DISCONNECT_UNCLEAN here means the block's
                  outputs didn't match the UTXO set we were rolling
                  back from (or an input restore overwrote a still-live
                  coin).  Core continues the reorg in this case
                  (validation.cpp:2247 — UNCLEAN is a soft warning,
                  not a fatal), so we log and proceed.  DISCONNECT_FAILED
                  was already mapped to Error by [disconnect_block_into_batch]. *)
               (match dres with
                | Disconnect_unclean ->
                  Logs.warn (fun m ->
                    m "Reorg: disconnect at height %d returned UNCLEAN \
                       (UTXO/output mismatch; proceeding per Core policy)"
                      entry.height)
                | _ -> ());
               disconnected_txs := txs @ !disconnected_txs;
               disconnect_blocks rest)
        in
        match disconnect_blocks (List.rev to_disconnect) with
        | Error e ->
          Logs.err (fun m -> m "Reorg aborted during disconnect: %s" e);
          ibd.pending_utxo_updates <- [];
          ibd.pending_utxo_deletes <- [];
          Error e
        | Ok () ->
          (* BIP-157 disconnect-half: rewind the filter index to the
             fork point so the connect-half's appender sees a fresh
             parent for [fork_point.height + 1]. We do this once for
             the whole reorg (rather than per-block) because the index
             is in-memory between [batch_write] calls and a single
             [rewind_bip157_index] call is O(disconnect_depth). *)
          (match state.bip157_index with
           | None -> ()
           | Some idx ->
             Block_index.rewind_bip157_index idx
               ~target_height:fork_point.height);
          (* Connect side: iterate fork-forward-to-new-tip. *)
          let connect_error = ref None in
          let connected_blocks = ref [] in
          List.iter (fun (entry : header_entry) ->
            if !connect_error = None then
              match connect_block_into_batch ibd batch view entry with
              | Error e -> connect_error := Some e
              | Ok block ->
                connected_blocks := (entry, block) :: !connected_blocks
          ) to_connect;
          match !connect_error with
          | Some e ->
            Logs.err (fun m -> m "Reorg aborted during connect: %s" e);
            ibd.pending_utxo_updates <- [];
            ibd.pending_utxo_deletes <- [];
            (* No batch_write happened; the on-disk image is unchanged
               from the pre-reorg state. *)
            Error e
          | None ->
            (* Stage UTXO delta + tip flip into the same batch and commit.
               The [view] is the source of truth (it correctly
               resolves put/delete collisions across the reorg's
               disconnect+connect halves). *)
            stage_pending_utxos_into_batch ibd batch view;
            Storage.ChainDB.batch_set_chain_tip batch new_tip.hash
              new_tip.height;
            Storage.ChainDB.batch_write state.db batch;
            (* BIP-157 reorg-fsync. The rewind + per-block appends above
               only mutated the in-memory bundle. Persist them now,
               matching the LSM commit we just performed for the
               chainstate. The flush is best-effort: a crash before this
               point leaves the index recoverable from the next restart's
               backfill (which walks last-indexed-height+1 .. blocks_synced
               and replays). *)
            (match state.bip157_index with
             | None -> ()
             | Some idx ->
               (try Block_index.sync_bip157_index idx
                with exn ->
                  Logs.warn (fun m ->
                    m "BIP-157: reorg sync failed: %s"
                      (Printexc.to_string exn))));
            (* Disk is now durably at the new chain.  Apply in-memory
               state and side effects after the commit so a crash
               between batch_write and these updates leaves only the
               state recoverable from disk on restart. *)
            (* Store nTx for every reorg-connected block so getblockheader
               returns a correct count even if the block body is absent. *)
            List.iter (fun ((entry : header_entry), (block : Types.block)) ->
              Storage.ChainDB.store_block_ntx state.db entry.hash
                (List.length block.transactions)
            ) (List.rev !connected_blocks);
            state.tip <- Some new_tip;
            state.blocks_synced <- new_tip.height;
            if new_tip.height > state.headers_synced then
              state.headers_synced <- new_tip.height;
            (* Clear sig cache so stale results from the abandoned chain
               don't leak into post-reorg validation. *)
            Sig_cache.clear_global ();
            (* Mempool refill: re-add disconnected non-coinbase txs.
               W96 Bug 14: pass ~bypass_fee_check:true and ~bypass_limits:true
               so the refill path matches Core's args.m_bypass_limits=true for
               reorg-driven re-acceptance (validation.cpp ProcessNewBlock →
               UpdateMempoolForReorg).  Without these, txs whose original
               feerate was at or just above floor (now subject to a raised
               dynamic floor due to mempool churn) and TRUC chains valid
               under the old chain but with parents not yet re-accepted would
               be wrongly dropped. *)
            (match ibd.mempool with
             | Some mp ->
               List.iter (fun tx ->
                 ignore (Mempool.add_transaction
                           ~bypass_fee_check:true
                           ~bypass_limits:true
                           mp tx)
               ) !disconnected_txs;
               Logs.debug (fun m ->
                 m "Re-added %d disconnected transactions to mempool"
                   (List.length !disconnected_txs))
             | None -> ());
            (* Per-connect-block side effects: mempool eviction, prune,
               ZMQ notify. [connected_blocks] is in reverse iteration
               order; List.rev_iter style preserves connect order so
               ZMQ subscribers see the disconnect-then-reconnect
               sequence in the right direction. *)
            (* ZMQ disconnect notifies (oldest-disconnected first =
               most-recent-tip first, matching Core's [ChainstateManager]
               which fires [BlockDisconnected] from the tip down). *)
            List.iter (fun (entry : header_entry) ->
              match Storage.ChainDB.get_block state.db entry.hash with
              | None -> ()
              | Some block ->
                zmq_notify_block ibd block entry.hash false
            ) (List.rev to_disconnect);
            (* Connect-side effects (mempool eviction, prune, ZMQ
               connect) iterated in fork-forward order. *)
            List.iter (fun ((entry : header_entry), (block : Types.block)) ->
              (match ibd.mempool with
               | Some mp -> Mempool.remove_for_block mp block entry.height
               | None -> ());
              prune_old_blocks state entry.height;
              zmq_notify_block ibd block entry.hash true
            ) (List.rev !connected_blocks);
            Logs.info (fun m ->
              m "Reorganization complete, new tip at height %d"
                new_tip.height);
            Ok ()
      end
  end

(* ============================================================================
   Side-branch acceptance (Pattern Y closure 2026-05-05)
   ============================================================================

   Counterpart to Bitcoin Core's [BlockManager::AcceptBlock]
   ([validation.cpp]), which writes [pindexNew->nChainWork] and sets
   [BLOCK_HAVE_DATA] on every accepted block regardless of whether it lives
   on the active chain or a side-branch. Storage and best-chain selection
   are decoupled in Core.

   In camlcoin (pre-fix), [Mining.submit_block] only accepted blocks that
   extend the validated tip — a competing fork's first block was rejected
   with "Block does not build on validated tip" even though every prior
   block was on disk. This made [reorganize] unreachable from the
   submitblock RPC: the side-branch could never be stored, so the heavier
   tip could never be selected.

   Counterpart to rustoshi 68a422b (server.rs:2730-2790) which closed the
   same Pattern Y bug: that fix made [submit_block]'s happy path persist
   a [BlockIndexEntry] so the parent-lookup in [try_attach_and_reorg]
   would not return None for a side-branch block whose parent was a
   previously-accepted best-chain block. The shape here is broader because
   camlcoin lacked any side-branch acceptance at all — the corpus entry
   [reorg-via-submitblock] showed [ctx-rej-h113], i.e. B1's submission
   was rejected at the gate.

   Verified pre/post with [tools/diff-test.sh --entry=reorg-via-submitblock]
   (see CORE-PARITY-AUDIT/_reorg-via-submitblock-fleet-result-2026-05-05.md). *)

(* Register a side-branch header in the in-memory map and on-disk header
   store WITHOUT overwriting the active chain's height->hash mapping or
   rewinding the validated tip. This is the side-branch counterpart of
   [accept_header] (which assumes the new entry extends the active
   header chain — calling it for a side-branch would break [block_tip]
   and break getblock-by-height for the active chain). *)
let register_side_branch_header (state : chain_state) (entry : header_entry)
    : unit =
  let hash_key = Cstruct.to_string entry.hash in
  Hashtbl.replace state.headers hash_key entry;
  (* store_block_header is keyed by hash, so it does not interfere with
     the active chain — distinct from set_height_hash which IS active-
     chain-only. *)
  Storage.ChainDB.store_block_header state.db entry.hash entry.header

(* Pattern Y closure: accept a block whose parent is in the index but is
   not the validated tip (side-branch / heavier-fork acceptance via
   [submitblock]). Returns Ok () on stored — with optional reorg if the
   side-branch is now strictly heavier than the active header tip — and
   Error on rejection.

   Mirrors Bitcoin Core's [ProcessNewBlock] -> [AcceptBlock] code path
   for non-best-chain blocks: header chain validation + CheckBlock +
   ContextualCheckBlock, body+header persisted to disk, ConnectBlock
   deferred to a later [ActivateBestChain] call (here:
   [reorganize]). UTXO checks are deferred to [reorganize]'s connect
   path, which is where Core would run them too (ConnectBlock fires
   only on the connect side of a reorg, not at side-branch storage
   time). *)
let try_attach_side_branch_and_reorg
    ?(utxo_set : Utxo.OptimizedUtxoSet.t option)
    ?(mempool : Mempool.mempool option)
    ?(misbehavior_handler : (int -> string -> unit) option)
    (state : chain_state) (block : Types.block) (parent : header_entry)
    : (unit, string) result =
  let hash = Crypto.compute_block_hash block.header in
  (* Idempotency: if we already have this block on disk, don't reprocess. *)
  if Storage.ChainDB.has_block state.db hash then begin
    Logs.debug (fun m ->
      m "submitblock side-branch: block %s already stored — no-op"
        (Types.hash256_to_hex_display hash));
    Ok ()
  end else begin
    let height = parent.height + 1 in
    let header = block.header in
    (* Header validation (PoW, MTP, checkpoint, future-time clamp).
       We cannot reuse [validate_header] directly because it short-circuits
       with "Header already known" for headers already in the in-memory
       map (e.g. when the header arrived ahead of the body via P2P) and
       calls [accept_header] would overwrite the active height->hash
       mapping. So we inline the relevant pieces, indexed against the
       in-memory parent (not the active height->hash mapping which may
       point at the competing chain). *)
    if not (Consensus.hash_meets_target hash header.bits) then
      Error "Insufficient proof of work"
    else if Int32.to_float header.timestamp >
            Unix.gettimeofday () +. 7200.0 then
      Error "Header timestamp too far in future"
    else begin
      let ancestor_ts = collect_ancestor_timestamps state parent 11 in
      let mtp = Consensus.median_time_past ancestor_ts in
      if Int32.compare header.timestamp mtp <= 0 then
        Error "Header timestamp not greater than median-time-past"
      (* BIP-94 timewarp protection for retarget boundary blocks on testnet4.
         Reference: bitcoin-core/src/validation.cpp ContextualCheckBlockHeader:4097-4104. *)
      else if not (Consensus.check_timewarp_rule
                     ~height
                     ~header_time:header.timestamp
                     ~prev_block_time:parent.header.timestamp
                     ~network:state.network) then
        Error "time-timewarp-attack"
      else begin
        match Consensus.verify_checkpoint height hash state.network with
        | Consensus.CheckpointMismatch _ as mismatch ->
          Error (Consensus.checkpoint_result_to_string mismatch)
        | Consensus.CheckpointOk ->
        (* Compute expected difficulty from the parent's bits. For
           regtest/[pow_no_retargeting], parent.bits is authoritative.
           For mainnet retargeting, the difficulty-adjustment boundary
           on a side-branch is intentionally deferred — a future patch
           can wire a side-branch-aware [compute_expected_bits] (the
           current implementation walks the active height->hash
           mapping). For non-boundary heights with retargeting,
           parent.bits is also the right answer. The corpus entry
           [reorg-via-submitblock] runs on regtest, so this path is
           exercised under [pow_no_retargeting]. *)
        let expected_bits =
          if state.network.pow_no_retargeting then parent.header.bits
          else if height mod Consensus.difficulty_adjustment_interval = 0
          then compute_expected_bits state height block.header
          else parent.header.bits
        in
        if header.bits <> expected_bits then
          Error (Printf.sprintf
                   "Header difficulty mismatch (got 0x%lx expected 0x%lx)"
                   header.bits expected_bits)
        else begin
          let total_work =
            Consensus.work_add parent.total_work
              (work_from_bits header.bits)
          in
          let entry =
            { header; hash; height; total_work }
          in
          (* CheckBlock + ContextualCheckBlock — context-free + header-
             chain-context checks, but NOT ConnectBlock (UTXO checks are
             deferred to [reorganize]'s connect path). *)
          let median_time = mtp in
          let prev_block_time = parent.header.timestamp in
          (match Validation.check_block ~network:state.network block height
                   ~expected_bits ~median_time ~prev_block_time () with
           | Error e ->
             Error (Validation.block_error_to_string e)
           | Ok () ->
             (* Persist header and body. UTXO is untouched here; if the
                side-branch becomes the active tip below, [reorganize]
                will re-validate and connect via the IBD pipeline. *)
             register_side_branch_header state entry;
             Storage.ChainDB.store_block state.db hash block;
             Logs.info (fun m ->
               m "submitblock side-branch: stored block %s at height %d \
                  (parent=%s)"
                 (Types.hash256_to_hex_display hash) height
                 (Types.hash256_to_hex_display parent.hash));
             (* If the new chain has strictly more work than the current
                best-work header tip, run [reorganize] to flip the
                validated tip. Use a freshly-built [ibd_state] — the
                same primitive [Sync.run_ibd] uses — so the connect
                path can write undo data and update the UTXO set
                atomically. *)
             let current_tip_work = match state.tip with
               | Some t -> t.total_work
               | None -> Consensus.zero_work
             in
             if Consensus.work_compare total_work current_tip_work > 0
             then begin
               Logs.info (fun m ->
                 m "submitblock side-branch: heavier than active tip \
                    (height %d vs %d), triggering reorganize"
                   height
                   (match state.tip with Some t -> t.height | None -> -1));
               (* Drive [reorganize] with the side-branch entry as the
                  new tip. [reorganize] reads the *current* state.tip as
                  the reorg source — DO NOT overwrite state.tip before
                  the call (an earlier draft did, which made
                  current_tip == new_tip and tripped the
                  "New tip does not have more work" guard at
                  reorganize:2281). [reorganize] updates state.tip /
                  blocks_synced / headers_synced / set_chain_tip on its
                  Ok exit path; it does NOT update set_header_tip on
                  RocksDB, so we do that here on success too so
                  recovery (restore_chain_state) reloads B3 as the
                  header tip. *)
               let ibd =
                 create_ibd_state ?utxo_set ?misbehavior_handler state
               in
               (match mempool with
                | Some mp -> set_mempool ibd mp
                | None -> ());
               match reorganize ibd entry with
               | Ok () ->
                 Storage.ChainDB.set_header_tip state.db entry.hash entry.height;
                 Ok ()
               | Error e ->
                 Logs.err (fun m ->
                   m "submitblock side-branch: reorganize failed: %s" e);
                 Error e
             end else begin
               (* Side-branch stored but not activated — the equivalent
                  of Core's "inconclusive" return from submitblock. *)
               Logs.info (fun m ->
                 m "submitblock side-branch: stored at h=%d but not \
                    heavier than active tip (no reorg)" height);
               Ok ()
             end)
        end
      end
    end
  end

(* ============================================================================
   Main IBD Loop
   ============================================================================ *)

(* Run initial block download.
   The loop aggressively pipelines download and processing:
   1. Fill the download queue from headers
   2. Request blocks from all peers (parallel GetData)
   3. Yield briefly for network I/O
   4. Process completed blocks
   5. Immediately refill + re-request to keep pipeline saturated
   6. Repeat with multiple yield+process cycles per request round *)
let run_ibd ?(shutdown_flag : bool ref option)
    (ibd : ibd_state) (get_peers : unit -> Peer.peer list) : unit Lwt.t =
  let is_shutdown () = match shutdown_flag with
    | Some r -> !r
    | None   -> false
  in
  let last_progress_log = ref (Unix.gettimeofday ()) in
  let ibd_start_time = Unix.gettimeofday () in
  let total_processed = ref 0 in
  (* Spawn the persistent validation worker Domain (wave 11 option B).
     The worker runs block validation off the Lwt main thread; all ibd.*
     mutation remains on the Lwt thread. *)
  let worker = Validation_worker.create () in
  Logs.info (fun m -> m "IBD: spawned persistent validation worker Domain");
  (* Helper: send requests to all active peers *)
  let send_requests () =
    let peers = get_peers () in
    let active_peers = List.filter (fun p ->
      p.Peer.state = Peer.Ready
    ) peers in
    Lwt.catch
      (fun () -> request_blocks ibd active_peers)
      (fun exn ->
         Logs.warn (fun m ->
           m "IBD request_blocks exception: %s" (Printexc.to_string exn));
         Lwt.return_unit)
  in
  let rec loop () =
    if is_shutdown () then begin
      Logs.info (fun m -> m "IBD: shutdown requested, stopping loop");
      (try Validation_worker.shutdown worker with _ -> ());
      Lwt.return_unit
    end else begin
    fill_download_queue ibd;
    let qlen = Queue.length ibd.block_queue in
    if qlen = 0 && ibd.total_blocks_in_flight = 0 then begin
      (* Flush any remaining UTXO updates *)
      flush_utxos ibd;
      (* Update chain tip *)
      (match get_header_at_height ibd.chain ibd.chain.blocks_synced with
       | Some entry ->
         Storage.ChainDB.set_chain_tip ibd.chain.db entry.hash entry.height
       | None -> ());
      let elapsed = Unix.gettimeofday () -. ibd_start_time in
      Logs.info (fun m ->
        m "IBD complete at height %d (%d blocks in %.1fs, %.0f blk/s)"
          ibd.chain.blocks_synced !total_processed elapsed
          (float_of_int !total_processed /. elapsed));
      ibd.chain.sync_state <- FullySynced;
      (* Shut down the persistent validation worker cleanly. *)
      (try Validation_worker.shutdown worker with _ -> ());
      Lwt.return_unit
    end else begin
      (* Periodic orphan expiry (cheap, runs ~once/loop) *)
      ignore (expire_orphan_blocks ibd);
      (* Check for stalled downloads *)
      let stalled_peers = check_stalled_downloads ibd in
      List.iter (fun peer_id ->
        Logs.warn (fun m ->
          m "Disconnecting peer %d after %d consecutive stalled downloads"
            peer_id max_consecutive_timeouts);
        Hashtbl.remove ibd.peer_states peer_id
      ) stalled_peers;
      (* Send initial requests *)
      let%lwt () = send_requests () in
      (* Inner loop: yield, process, re-request.  Run multiple short cycles
         within one outer loop iteration to keep the pipeline full without
         the overhead of orphan expiry, stall checks, etc. *)
      let round_processed = ref 0 in
      let rec inner_loop rounds_left =
        if rounds_left <= 0 || is_shutdown () then Lwt.return_unit
        else begin
          (* Yield to let Lwt schedule network I/O and block receipt *)
          let%lwt () = Lwt_unix.sleep 0.001 in
          (* Process completed blocks — validation runs in the worker Domain *)
          let%lwt result =
            Lwt.catch
              (fun () -> process_downloaded_blocks ~worker ibd)
              (fun exn -> Lwt.return (Error (Printexc.to_string exn)))
          in
          match result with
          | Ok n when n > 0 ->
            round_processed := !round_processed + n;
            total_processed := !total_processed + n;
            (* Refill queue and request more immediately *)
            fill_download_queue ibd;
            let%lwt () = send_requests () in
            inner_loop (rounds_left - 1)
          | Ok _ ->
            (* No blocks ready — if we have blocks in flight, yield once more;
               otherwise break out to outer loop for stall/orphan checks *)
            if ibd.total_blocks_in_flight = 0 then Lwt.return_unit
            else inner_loop (rounds_left - 1)
          | Error e ->
            Logs.err (fun m -> m "Block processing error: %s" e);
            Lwt.return_unit
        end
      in
      let%lwt () = inner_loop 10 in
      (* Log progress *)
      if !round_processed > 0 then begin
        last_progress_log := Unix.gettimeofday ();
        let elapsed = Unix.gettimeofday () -. ibd_start_time in
        let rate = float_of_int !total_processed /. elapsed in
        Logs.info (fun m ->
          m "Processed %d blocks, height now %d, in-flight: %d (avg %.0f blk/s)"
            !round_processed ibd.chain.blocks_synced
            ibd.total_blocks_in_flight rate)
      end else begin
        let now = Unix.gettimeofday () in
        if now -. !last_progress_log > 30.0 then begin
          last_progress_log := now;
          Logs.info (fun m ->
            m "IBD stall: queue=%d in-flight=%d next_dl=%d next_proc=%d"
              qlen ibd.total_blocks_in_flight
              ibd.next_download_height ibd.next_process_height)
        end
      end;
      loop ()
    end
  end  (* closes is_shutdown else begin *)
  in
  loop ()

(* Start IBD if headers are synced but blocks aren't.
   [on_ibd_created] is called with the ibd_state before the download loop
   begins, so the caller can wire up a listener for incoming BlockMsg /
   NotfoundMsg via the peer manager.  Without this callback, GetData
   responses would be silently dropped by the peer message loop. *)
let start_ibd ?(utxo_set : Utxo.OptimizedUtxoSet.t option)
    ?(misbehavior_handler : (int -> string -> unit) option)
    ?(on_ibd_created : (ibd_state -> unit) option)
    ?(shutdown_flag : bool ref option)
    (state : chain_state) (get_peers : unit -> Peer.peer list)
    : unit Lwt.t =
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
      let ibd = create_ibd_state ?utxo_set ?misbehavior_handler state in
      (* Notify caller so it can install the block-message listener *)
      (match on_ibd_created with
       | Some f -> f ibd
       | None -> ());
      run_ibd ?shutdown_flag ibd get_peers
    end
  end

(* ============================================================================
   BIP-157 Startup Backfill

   Reference: Bitcoin Core's [BlockFilterIndex::CustomInit] +
   [BaseIndex::Sync] ([src/index/blockfilterindex.cpp]).

   On every daemon start, if --blockfilterindex is enabled, we walk the
   stored chain from [last_indexed_height + 1] up to [blocks_synced],
   re-reading each block body + undo data and feeding them into
   [Block_index.append_block_filter]. This catches up the index after:
   - fresh-install (last_indexed_height = -1, walks the full chain)
   - cold-restart with --blockfilterindex toggled on for the first time
   - crash mid-block-connect (the chain is durable but the index missed
     the last few entries because the index is flushed less frequently
     than the chainstate)

   The backfill uses the stored undo data when available (post-assume-valid
   blocks) and falls back to an empty spent_scripts list (assume-valid IBD
   path skipped undo storage to save disk; the basic filter degrades to
   "outputs only" for those blocks, matching Core's behaviour when
   running a pruned node with a partially-pruned undo file).

   Logged with progress every 10000 blocks so a fresh-install backfill
   doesn't go silent for hours. Returns the count of blocks that were
   newly indexed. *)
let backfill_bip157_index (state : chain_state) : int =
  match state.bip157_index with
  | None -> 0
  | Some idx ->
    let target = state.blocks_synced in
    let start = Block_index.bip157_best_height idx + 1 in
    if start > target then 0
    else begin
      Logs.info (fun m ->
        m "BIP-157: starting backfill from height %d to %d (%d blocks)"
          start target (target - start + 1));
      let count = ref 0 in
      let progress_step = 10000 in
      (try
        for h = start to target do
          match get_header_at_height state h with
          | None ->
            (* Header gap: stop the backfill so we don't index past a
               hole in the chain. The next restart will retry. *)
            raise Exit
          | Some entry ->
            (match Storage.ChainDB.get_block state.db entry.hash with
             | None when h = 0 ->
               (* Genesis (height 0): camlcoin stores only the genesis HEADER
                  in chainparams, not the full block body, so there is no body
                  to read here. But Bitcoin Core DOES index the genesis filter
                  and every later filter HEADER chains off it. Build the
                  genesis filter directly from the known (network-invariant)
                  genesis coinbase scriptPubKey so the header chain matches
                  Core from height 1 onward. *)
               let genesis_hash =
                 Crypto.compute_block_hash state.network.genesis_header in
               Block_index.append_genesis_filter idx ~genesis_hash;
               incr count
             | None ->
               (* Block body missing (likely pruned). Stop here; the
                  filter index can't be populated for pruned heights. *)
               Logs.warn (fun m ->
                 m "BIP-157: stopping backfill at height %d (block body \
                    not on disk — pruned or missing)" h);
               raise Exit
             | Some block ->
               (* Build spent_scripts from the stored undo data when
                  it's available; fall back to empty (outputs-only
                  filter) when the assume-valid IBD path skipped undo
                  storage. *)
               let spent_scripts =
                 match Storage.ChainDB.get_undo_data state.db entry.hash with
                 | None -> []
                 | Some undo_raw ->
                   (try
                     let r =
                       Serialize.reader_of_cstruct (Cstruct.of_string undo_raw)
                     in
                     let undo = Utxo.deserialize_undo_data r in
                     List.concat_map (fun (tu : Utxo.tx_undo) ->
                       List.map (fun (_op, (e : Utxo.utxo_entry)) ->
                         e.script_pubkey
                       ) tu.spent_outputs
                     ) undo.tx_undos
                   with _ -> [])
               in
               (match Block_index.append_block_filter idx
                        ~block ~height:h ~spent_scripts with
                | Ok () ->
                  incr count;
                  if !count mod progress_step = 0 then
                    Logs.info (fun m ->
                      m "BIP-157: backfill progress: %d/%d (height %d)"
                        !count (target - start + 1) h)
                | Error msg ->
                  Logs.warn (fun m ->
                    m "BIP-157: backfill stopped at height %d: %s" h msg);
                  raise Exit))
        done
      with Exit -> ());
      Block_index.sync_bip157_index idx;
      Logs.info (fun m ->
        m "BIP-157: backfill complete, %d new entries (best_height=%d)"
          !count (Block_index.bip157_best_height idx));
      !count
    end

(* ============================================================================
   Post-IBD Block Processing
   ============================================================================ *)

(* Process a single new block received after IBD is complete (e.g. from an inv
   announcement or unsolicited push).  Validates the block against the current
   UTXO set and, on success, stores it and advances the chain tip.
   Returns Ok () on success or Error msg on failure. *)
(* Try to connect stored blocks starting at state.tip + 1.
   Returns the number of blocks connected.
   W34 fix: after the gap-fill receives blocks out-of-order, later blocks are
   stored on disk but never processed because process_new_block returns Ok ()
   when the block is already on disk.  This helper walks the stored chain
   forward from the current tip, processing each stored block that extends
   the tip.  Called at the end of process_new_block so that out-of-order
   arrivals converge to a consistent tip. *)
let rec connect_stored_blocks (state : chain_state) : int =
  let next_height = state.blocks_synced + 1 in
  match get_header_at_height state next_height with
  | None -> 0
  | Some entry ->
    (* Verify this stored block extends the current BLOCK tip (not the header
       tip — see `chain_state` comment). *)
    let extends_tip =
      if state.blocks_synced = 0 && next_height = 0 then true
      else match block_tip state with
        | None -> false
        | Some bt -> Cstruct.equal entry.header.prev_block bt.hash
    in
    if not extends_tip then 0
    else if not (Storage.ChainDB.has_block state.db entry.hash) then 0
    else match Storage.ChainDB.get_block state.db entry.hash with
      | None -> 0
      | Some stored_block ->
        let expected_bits = compute_expected_bits state next_height stored_block.header in
        let median_time = compute_median_time_past state next_height in
        let prev_block_time = get_prev_block_time state next_height in
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
        let validation_flags =
          Consensus.get_block_script_flags next_height state.network
        in
        (* accept_block: unified ProcessNewBlock check pipeline.
           Same sequence as process_new_block and submit_block.
           Reference: bitcoin-core/src/validation.cpp ProcessNewBlock. *)
        match Validation.accept_block
                ~network:state.network ~block:stored_block ~height:next_height
                ~expected_bits ~median_time ~prev_block_time ~base_lookup:lookup
                ~flags:validation_flags ~skip_scripts:false
                ~get_mtp_at_height:(get_mtp_for_height state)
                ?bip34_height_hash:(bip34_height_hash_for state) () with
        | Validation.AB_ok (_fees, txid_arr, spent_utxos) ->
          (* Write tx_index entries for the connected stored block
             (Pattern C0 closure 2026-05-05). Mirrors process_new_block
             below; the gap-fill catch-up path needs the same wiring or
             [getrawtransaction] returns nothing for any tx whose only
             confirmation arrived via the out-of-order drain. *)
          tx_index_write_for_block state.db stored_block entry.hash txid_arr;
          (* BIP-157 filter index append (no-op when --blockfilterindex
             is off). Mirrors Core's [BlockFilterIndex::CustomAppend]. *)
          append_filter_if_enabled state ~block:stored_block
            ~height:next_height ~spent_utxos;
          let ops = ref [] in
          List.iteri (fun tx_idx tx ->
            let is_cb = (tx_idx = 0) in
            let txid = if tx_idx < Array.length txid_arr
                       then txid_arr.(tx_idx)
                       else Crypto.compute_txid tx in
            if not is_cb then
              List.iter (fun inp ->
                let prev = inp.Types.previous_output in
                ops := (prev.Types.txid, Int32.to_int prev.Types.vout, `Del)
                       :: !ops
              ) tx.Types.inputs;
            List.iteri (fun vout out ->
              (* Skip provably-unspendable outputs to match Core's
                 [AddCoins] semantics; see process_new_block for rationale. *)
              if not (Utxo.is_unspendable_script out.Types.script_pubkey) then
                let data = encode_utxo out.Types.value out.Types.script_pubkey
                    next_height is_cb in
                ops := (txid, vout, `Add data) :: !ops
            ) tx.Types.outputs
          ) stored_block.transactions;
          state.blocks_synced <- next_height;
          state.tip <- Some entry;
          (* Bug 8 fix (2026-04-26): keep in-memory headers_synced in sync
             with state.tip. apply_block_atomic persists header_tip to DB,
             but the locator builder reads the in-memory field; without
             this update, getheaders re-uses a stale locator and peers
             respond with already-known headers in an infinite loop. *)
          if next_height > state.headers_synced then
            state.headers_synced <- next_height;
          Storage.ChainDB.apply_block_atomic state.db
            ~tip_hash:entry.hash ~tip_height:next_height
            ~header_tip_hash:entry.hash ~header_tip_height:next_height
            (List.rev !ops);
          (* Store nTx for this block so getblockheader returns the correct
             count without needing the full block body. *)
          Storage.ChainDB.store_block_ntx state.db entry.hash
            (List.length stored_block.transactions);
          Logs.info (fun m ->
            m "Connected stored block %s at height %d (catch-up from gap-fill)"
              (Types.hash256_to_hex_display entry.hash) next_height);
          1 + connect_stored_blocks state
        | Validation.AB_err e ->
          let msg = Validation.block_error_to_string e in
          Logs.warn (fun m ->
            m "Stored block at height %d failed validation: %s" next_height msg);
          (* B10 fix: mark the stored block BLOCK_FAILED_VALID so that
             gap-fill does not retry the same invalid block indefinitely on
             restart.  Core calls InvalidBlockFound from ConnectBlock which
             sets pindex->nStatus |= BLOCK_FAILED_VALID
             (validation.cpp:1988).  Without this mark the same block is
             retried on every gap-fill round and every restart. *)
          let block_hash_key = Cstruct.to_string entry.hash in
          Hashtbl.replace state.invalidated_blocks block_hash_key ();
          Storage.ChainDB.set_block_invalidated state.db entry.hash;
          0

let process_new_block ?(f_requested = false)
    ?(peer_id : int option)
    ?(misbehavior_handler : (int -> string -> unit) option)
    ?(worker : Validation_worker.t option)
    (state : chain_state)
    (block : Types.block) : (unit, string) result Lwt.t =
  let hash = Crypto.compute_block_hash block.header in
  let hash_key = Cstruct.to_string hash in
  (* Ignore blocks we already have — but still try to advance from stored
     out-of-order blocks in case a recent fill brought us what we needed. *)
  if Storage.ChainDB.has_block state.db hash then begin
    let _ = connect_stored_blocks state in
    Lwt.return (Ok ())
  end else begin
    (* The block's header must already be known (via headers-first sync). If
       not, accept the header first so we know the height. *)
    let header_entry = match Hashtbl.find_opt state.headers hash_key with
      | Some e -> Some e
      | None ->
        (* Try to accept the header on the fly *)
        (match validate_header state block.header with
         | Ok entry -> accept_header state entry; Some entry
         | Error _ -> None)
    in
    match header_entry with
    | None ->
      Lwt.return (Error "Unknown header and failed to validate")
    | Some entry ->
      let height = entry.height in
      (* G19c — fTooFarAhead anti-DoS gate.
         Core: bitcoin-core/src/validation.cpp:4325 — when !fRequested and
         pindex->nHeight > ActiveHeight() + MIN_BLOCKS_TO_KEEP (288), drop
         the block silently.  Without this, a peer can send hundreds of
         future blocks to consume disk I/O and CPU before they are ever
         connectable, since every out-of-order block is stored and later
         re-validated when the chain catches up.
         Reference: bitcoin-core/src/validation.cpp ProcessNewBlock /
         AcceptBlock (W97 G19c). *)
      let min_blocks_to_keep = 288 in
      let f_too_far_ahead = height > state.blocks_synced + min_blocks_to_keep in
      if (not f_requested) && f_too_far_ahead then
        Lwt.return (Error "too-far-ahead")
      else
      (* Only connect blocks that extend the current BLOCK tip (see
         `chain_state` comment on why `state.tip` is not used here). *)
      let connects_to_tip =
        if height <> state.blocks_synced + 1 then false
        else if state.blocks_synced = 0 && height = 0 then true
        else match block_tip state with
          | None -> false
          | Some bt -> Cstruct.equal block.header.prev_block bt.hash
      in
      if not connects_to_tip then begin
        Logs.debug (fun m ->
          m "Received block %s at height %d does not extend tip, storing"
            (Types.hash256_to_hex_display hash) height);
        (* Store block data for later use but don't connect *)
        Storage.ChainDB.store_block state.db hash block;
        (* The incoming block may be the first of a gap-fill batch; even if
           it doesn't extend the tip itself, its arrival means peers are
           responding and earlier stored blocks may now be drainable. *)
        let connected = connect_stored_blocks state in
        if connected > 0 then
          Logs.info (fun m ->
            m "Connected %d stored blocks after gap-fill store, tip now at %d"
              connected state.blocks_synced);
        Lwt.return (Ok ())
      end else begin
        let expected_bits = compute_expected_bits state height block.header in
        let median_time = compute_median_time_past state height in
        let prev_block_time = get_prev_block_time state height in
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
        let validation_flags =
          Consensus.get_block_script_flags height state.network
        in
        (* accept_block: unified ProcessNewBlock check pipeline.
           Mirrors Bitcoin Core's AcceptBlock → CheckBlock →
           ContextualCheckBlock → ConnectBlock validation sequence.
           Both submitblock RPC and this P2P path go through accept_block,
           guaranteeing identical check semantics.
           Reference: bitcoin-core/src/validation.cpp ProcessNewBlock.

           #135 step 3: when [worker] is provided, dispatch validation to
           the Validation_worker Domain so RPC handlers can interleave
           during the 0.5-3s wall-clock window. When [None] (e.g. tests,
           submit_block paths that don't carry a worker), fall back to
           the synchronous accept_block call wrapped in Lwt.return.
           Mirrors the IBD pattern at sync.ml:2402-2429. *)
        let%lwt vresult =
          match worker with
          | Some w ->
            let job : Validation_worker.job = {
              block; height;
              expected_bits; median_time; prev_block_time;
              lookup;
              flags = validation_flags;
              skip_scripts = false;
              network = state.network;
              get_mtp_at_height = Some (get_mtp_for_height state);
              bip34_height_hash = bip34_height_hash_for state;
            } in
            Validation_worker.submit_lwt w job
          | None ->
            Lwt.return (
              match Validation.accept_block
                      ~network:state.network ~block ~height
                      ~expected_bits ~median_time ~prev_block_time ~base_lookup:lookup
                      ~flags:validation_flags ~skip_scripts:false
                      ~get_mtp_at_height:(get_mtp_for_height state)
                      ?bip34_height_hash:(bip34_height_hash_for state) () with
              | Validation.AB_ok (fees, txid_arr, spent) -> Ok (fees, txid_arr, spent)
              | Validation.AB_err e -> Error e)
        in
        match vresult with
        | Ok (_fees, txid_arr, spent_utxos) ->
          (* Store the block *)
          Storage.ChainDB.store_block state.db hash block;
          (* Write tx_index entries for every tx in the new block
             (Pattern C0 closure 2026-05-05). Mirrors Bitcoin Core's
             [TxIndex::CustomAppend] fired from [BaseIndex::BlockConnected]
             ([bitcoin-core/src/index/txindex.cpp]). Without this, every
             post-IBD block-connect leaves [getrawtransaction] returning
             "No such mempool or blockchain transaction" for the just-
             connected txs (findings doc:
             [_txindex-revert-on-reorg-fleet-result-2026-05-05.md]
             Pattern C0). *)
          tx_index_write_for_block state.db block hash txid_arr;
          (* BIP-157 filter index append (no-op when --blockfilterindex
             is off). Mirrors Core's [BlockFilterIndex::CustomAppend]
             fired from [BaseIndex::BlockConnected]. *)
          append_filter_if_enabled state ~block ~height ~spent_utxos;
          (* Collect UTXO mutations for a single atomic block commit *)
          let ops = ref [] in
          List.iteri (fun tx_idx tx ->
            let is_cb = (tx_idx = 0) in
            let txid = if tx_idx < Array.length txid_arr
                       then txid_arr.(tx_idx)
                       else Crypto.compute_txid tx in
            if not is_cb then
              List.iter (fun inp ->
                let prev = inp.Types.previous_output in
                ops := (prev.Types.txid, Int32.to_int prev.Types.vout, `Del)
                       :: !ops
              ) tx.Types.inputs;
            List.iteri (fun vout out ->
              (* Skip provably-unspendable outputs (OP_RETURN, oversized
                 scripts) so the UTXO set matches Core's [AddCoins]
                 semantics.  Without this filter every SegWit coinbase
                 inserts its OP_RETURN witness commitment, doubling the
                 coin count vs Core's chainstate. *)
              if not (Utxo.is_unspendable_script out.Types.script_pubkey) then
                let data = encode_utxo out.Types.value out.Types.script_pubkey
                    height is_cb in
                ops := (txid, vout, `Add data) :: !ops
            ) tx.Types.outputs
          ) block.transactions;
          (* Advance the chain tip atomically with UTXO deltas so that
             rdb_tip never lags chain_tip (the W47 945509 wedge). *)
          state.blocks_synced <- height;
          state.tip <- Some entry;
          (* Bug 8 fix (2026-04-26): mirror apply_block_atomic's
             header_tip_height update into the in-memory field; the
             locator builder reads in-memory state. Without this,
             post-IBD block-connect advances state.tip past
             state.headers_synced, locator becomes stale, getheaders
             re-fetches headers that fail accept_header's work-compare
             check, infinite loop. *)
          if height > state.headers_synced then
            state.headers_synced <- height;
          Storage.ChainDB.apply_block_atomic state.db
            ~tip_hash:hash ~tip_height:height
            ~header_tip_hash:hash ~header_tip_height:height
            (List.rev !ops);
          (* Store nTx for this newly-connected block so getblockheader
             returns the correct count without needing the full block body. *)
          Storage.ChainDB.store_block_ntx state.db hash
            (List.length block.transactions);
          Logs.info (fun m ->
            m "Connected new block %s at height %d"
              (Types.hash256_to_hex_display hash) height);
          (* W34 fix: try to connect any subsequent stored blocks that were
             received out-of-order by the gap-fill but couldn't be processed
             because their parent wasn't yet connected. *)
          let connected = connect_stored_blocks state in
          if connected > 0 then
            Logs.info (fun m ->
              m "Connected %d additional stored blocks, tip now at %d"
                connected state.blocks_synced);
          Lwt.return (Ok ())
        | Error e ->
          let msg = Validation.block_error_to_string e in
          Logs.warn (fun m ->
            m "Block %s at height %d failed validation: %s"
              (Types.hash256_to_hex_display hash) height msg);
          (* B7 fix: mark the block BLOCK_FAILED_VALID so that gap-fill and
             submitblock do not retry the same invalid block on every
             invocation.  Core calls InvalidBlockFound which sets
             pindex->nStatus |= BLOCK_FAILED_VALID
             (validation.cpp:1988).  Without this mark the same invalid
             block is re-submitted via submitblock or gap-fill and will
             re-run full validation every time. *)
          let is_mutated = match e with
            | Validation.BlockBadWitnessCommitment
            | Validation.BlockBadWitnessNonceSize
            | Validation.BlockUnexpectedWitness -> true
            | _ -> false
          in
          if not is_mutated then begin
            Hashtbl.replace state.invalidated_blocks hash_key ();
            Storage.ChainDB.set_block_invalidated state.db hash
          end;
          (* G16/G17 fix: Misbehaving on BLOCK_INVALID_HEADER and BLOCK_FAILED_VALID
             (matching Bitcoin Core's InvalidBlockFound / MaybePunishNodeForBlock).
             BLOCK_MUTATED errors (witness commitment, nonce-size, unexpected-witness)
             are NOT scored — the peer may have received a legitimately stripped block
             and is not at fault.  All other validation failures indicate the peer
             sent a provably invalid block and should be penalised at score 100.
             Reference: bitcoin-core/src/net_processing.cpp MaybePunishNodeForBlock. *)
          if not is_mutated then
            (match peer_id, misbehavior_handler with
             | Some pid, Some handler -> handler pid "invalid_block"
             | _ -> ());
          Lwt.return (Error msg)
      end
  end

(* Respond to a getheaders request from a peer.  Finds the fork point using
   the locator hashes, then returns up to 2000 headers from that point. *)
let handle_getheaders_request (state : chain_state)
    (locator_hashes : Types.hash256 list)
    (hash_stop : Types.hash256) : Types.block_header list =
  (* Find the fork point: walk the locator looking for a hash we know *)
  let tip_height = match state.tip with
    | Some t -> t.height | None -> 0 in
  let fork_height =
    let found = ref (-1) in
    List.iter (fun loc_hash ->
      if !found < 0 then
        let key = Cstruct.to_string loc_hash in
        match Hashtbl.find_opt state.headers key with
        | Some entry -> found := entry.height
        | None -> ()
    ) locator_hashes;
    if !found >= 0 then !found else 0
  in
  (* Collect up to 2000 headers starting after the fork point *)
  let stop_key = Cstruct.to_string hash_stop in
  let zero_stop = (Cstruct.length hash_stop >= 32
                   && Cstruct.for_all (fun b -> b = '\x00') hash_stop) in
  let result = ref [] in
  let h = ref (fork_height + 1) in
  while !h <= tip_height && List.length !result < 2000 do
    (match get_header_at_height state !h with
     | Some entry ->
       result := entry.header :: !result;
       if not zero_stop && Cstruct.to_string entry.hash = stop_key then
         h := tip_height + 1  (* break *)
     | None -> ());
    incr h
  done;
  List.rev !result

(* ============================================================================
   Mempool Request Handler
   ============================================================================ *)

(* Maximum number of inventory items to send in response to a mempool message *)
let max_mempool_inv_items = 50_000

(* Handle a MempoolMsg from a peer: respond with an InvMsg listing
   transaction IDs currently in the mempool.

   BIP-35 / NODE_BLOOM gate (matches Bitcoin Core's
   src/net_processing.cpp `if msg_type == NetMsgType::MEMPOOL` block):
   we serve the request only if *we* advertise NODE_BLOOM.  If we don't,
   we drop the message and disconnect the peer (Core also fDisconnects
   unless the peer has NoBan permission; camlcoin has no permission
   layer, so we just disconnect unconditionally).  Note the gate looks
   at our own advertised services, NOT the peer's. *)
let handle_mempool_msg_for
    (mempool : Mempool.mempool option) (peer : Peer.peer) : unit Lwt.t =
  let open Lwt.Syntax in
  if not (Peer.our_services ()).bloom then begin
    Logs.debug (fun m ->
      m "MEMPOOL request from peer %d but NODE_BLOOM not advertised \
         — disconnecting" peer.Peer.id);
    Lwt.catch (fun () -> Peer.disconnect peer) (fun _ -> Lwt.return_unit)
  end else
  match mempool with
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
            P2p.{ inv_type = InvWtx; hash = entry.wtxid }
          else
            P2p.{ inv_type = InvTx; hash = entry.txid }
          in
          inv_items := inv_entry :: !inv_items;
          incr count
        end
      end
    ) mp.entries;
    (* Send in chunks of MAX_INV_SZ (50 000) to mirror Core's wire limit
       (net_processing.cpp:126 `MAX_INV_SZ`).  Today [max_mempool_inv_items]
       equals MAX_INV_SZ so we never accumulate more than one chunk's
       worth, but the rev+chunk loop here keeps us correct if either
       constant changes in future. *)
    let rec send_chunks items =
      match items with
      | [] -> Lwt.return_unit
      | _ ->
        let rec take n acc = function
          | [] -> (List.rev acc, [])
          | _ as l when n = 0 -> (List.rev acc, l)
          | x :: rest -> take (n - 1) (x :: acc) rest
        in
        let chunk, rest = take max_mempool_inv_items [] items in
        let* () = Lwt.catch
          (fun () -> Peer.send_message peer (P2p.InvMsg chunk))
          (fun _exn -> Lwt.return_unit) in
        send_chunks rest
    in
    if !inv_items <> [] then
      send_chunks (List.rev !inv_items)
    else
      Lwt.return_unit

(* IBD-state convenience wrapper; identical semantics to
   [handle_mempool_msg_for] but reads the mempool out of an ibd_state. *)
let handle_mempool_msg (ibd : ibd_state) (peer : Peer.peer) : unit Lwt.t =
  handle_mempool_msg_for ibd.mempool peer

(* ============================================================================
   Block Invalidation (invalidateblock / reconsiderblock RPCs)
   ============================================================================ *)

(* Check if a block hash is marked as invalid (either directly or as a descendant) *)
let is_block_invalid (state : chain_state) (hash : Types.hash256) : bool =
  Hashtbl.mem state.invalidated_blocks (Cstruct.to_string hash)

(* Find all descendants of a block in the headers table *)
let find_descendants (state : chain_state) (target_hash : Types.hash256)
    : header_entry list =
  let target_key = Cstruct.to_string target_hash in
  let descendants : header_entry list ref = ref [] in
  Hashtbl.iter (fun _key (entry : header_entry) ->
    (* Check if this entry is a descendant by walking back to target *)
    let rec is_descendant (e : header_entry) : bool =
      let parent_key = Cstruct.to_string e.header.prev_block in
      if parent_key = target_key then true
      else if e.height <= 0 then false
      else match Hashtbl.find_opt state.headers parent_key with
        | Some parent -> is_descendant parent
        | None -> false
    in
    if is_descendant entry then
      descendants := entry :: !descendants
  ) state.headers;
  !descendants

(* Find the next best valid chain tip after invalidating a block *)
let find_best_valid_tip (state : chain_state) : header_entry option =
  (* B1 fix: only consider entries that have block data on disk.
     Core gates setBlockIndexCandidates on BLOCK_HAVE_DATA
     (validation.cpp:3140 fMissingData check in FindMostWorkChain).
     Without this guard, header-only entries (headers-first sync, pruned
     nodes) can be selected as the best tip and trigger a reorganize that
     aborts mid-way with "Missing block at height N", leaving the chain
     rewound but not reconnected.
     Genesis (height=0) is special-cased: Core always sets BLOCK_HAVE_DATA
     for genesis in LoadGenesisBlock and it is the chain anchor. *)
  let best : header_entry option ref = ref None in
  Hashtbl.iter (fun key (entry : header_entry) ->
    if not (Hashtbl.mem state.invalidated_blocks key) then begin
      let have_data =
        entry.height = 0 || Storage.ChainDB.has_block state.db entry.hash
      in
      if have_data then begin
        match !best with
        | None -> best := Some entry
        | Some b ->
          if Consensus.work_compare entry.total_work b.total_work > 0 then
            best := Some entry
      end
    end
  ) state.headers;
  !best

(* Invalidate a block and all its descendants.
   If the block is on the active chain, rewind to its parent and switch to
   the next best valid chain. Returns the new chain tip height. *)
let invalidate_block (state : chain_state)
    ?(utxo_set : Utxo.OptimizedUtxoSet.t option)
    (hash : Types.hash256) : (int, string) result =
  let hash_key = Cstruct.to_string hash in
  (* Cannot invalidate genesis block *)
  match Hashtbl.find_opt state.headers hash_key with
  | None -> Error "Block not found"
  | Some entry when entry.height = 0 ->
    Error "Cannot invalidate genesis block"
  | Some entry ->
    Logs.info (fun m ->
      m "Invalidating block at height %d: %s"
        entry.height (Types.hash256_to_hex_display hash));
    (* Mark block and all descendants as invalid *)
    Hashtbl.replace state.invalidated_blocks hash_key ();
    Storage.ChainDB.set_block_invalidated state.db hash;
    let descendants = find_descendants state hash in
    List.iter (fun (d : header_entry) ->
      let d_key = Cstruct.to_string d.hash in
      Hashtbl.replace state.invalidated_blocks d_key ();
      Storage.ChainDB.set_block_invalidated state.db d.hash
    ) descendants;
    Logs.debug (fun m ->
      m "Marked %d descendant blocks as invalid" (List.length descendants));
    (* Check if invalidated block is on the active chain *)
    let on_active_chain =
      match state.tip with
      | None -> false
      | Some tip ->
        (* Check if tip is the invalidated block or one of its descendants *)
        Cstruct.equal tip.hash hash ||
        List.exists (fun (d : header_entry) -> Cstruct.equal d.hash tip.hash) descendants
    in
    if on_active_chain then begin
      Logs.info (fun m -> m "Invalidated block is on active chain, rewinding...");
      (* Find the parent of the invalidated block *)
      let parent_key = Cstruct.to_string entry.header.prev_block in
      match Hashtbl.find_opt state.headers parent_key with
      | None -> Error "Cannot find parent of invalidated block"
      | Some parent_entry ->
        (* We need to disconnect blocks from tip back to the invalidated block.
           This requires the ibd_state machinery for UTXO updates. For now,
           we update the chain state and let the caller handle UTXO updates
           via the utxo_set parameter if provided. *)
        (match utxo_set with
         | Some utxo ->
           (* Disconnect blocks from tip back to parent of invalidated block *)
           let current_tip = match state.tip with
             | Some t -> t
             | None -> failwith "No current tip"
           in
           let rec disconnect_to_height target_height (current : header_entry) =
             if current.height <= target_height then Ok ()
             else begin
               match Storage.ChainDB.get_block state.db current.hash with
               | None ->
                 Error (Printf.sprintf "Missing block at height %d" current.height)
               | Some block ->
                 match Storage.ChainDB.get_undo_data state.db current.hash with
                 | None ->
                   Error (Printf.sprintf "Missing undo data at height %d" current.height)
                 | Some undo_raw ->
                   let r = Serialize.reader_of_cstruct (Cstruct.of_string undo_raw) in
                   let undo = Utxo.deserialize_undo_data r in
                   (* Remove outputs created by this block *)
                   let txs = List.rev block.transactions in
                   List.iter (fun tx ->
                     let txid = Crypto.compute_txid tx in
                     List.iteri (fun vout _out ->
                       ignore (Utxo.OptimizedUtxoSet.remove utxo txid vout)
                     ) tx.Types.outputs
                   ) txs;
                   (* Restore spent outputs from undo data *)
                   List.iter (fun (tx_undo : Utxo.tx_undo) ->
                     List.iter (fun (outpoint, utxo_entry) ->
                       Utxo.OptimizedUtxoSet.add utxo
                         outpoint.Types.txid
                         (Int32.to_int outpoint.Types.vout)
                         utxo_entry
                     ) tx_undo.spent_outputs
                   ) undo.tx_undos;
                   Storage.ChainDB.delete_undo_data state.db current.hash;
                   Logs.debug (fun m ->
                     m "Disconnected block at height %d during invalidation"
                       current.height);
                   let parent_key = Cstruct.to_string current.header.prev_block in
                   match Hashtbl.find_opt state.headers parent_key with
                   | None -> Error "Missing parent during disconnect"
                   | Some parent -> disconnect_to_height target_height parent
             end
           in
           (match disconnect_to_height parent_entry.height current_tip with
            | Error e -> Error e
            | Ok () ->
              (* Update tip to parent of invalidated block *)
              state.tip <- Some parent_entry;
              state.blocks_synced <- parent_entry.height;
              Storage.ChainDB.set_chain_tip state.db parent_entry.hash parent_entry.height;
              (* Find the best valid chain and try to activate it *)
              match find_best_valid_tip state with
              | Some best when Consensus.work_compare best.total_work parent_entry.total_work > 0 ->
                Logs.info (fun m ->
                  m "Found better valid chain at height %d, activating..."
                    best.height);
                (* For now, just set the tip; full reorg would require more work *)
                Ok parent_entry.height
              | _ ->
                Ok parent_entry.height)
         | None ->
           (* No UTXO set provided - just update chain state *)
           state.tip <- Some parent_entry;
           state.blocks_synced <- parent_entry.height;
           Storage.ChainDB.set_chain_tip state.db parent_entry.hash parent_entry.height;
           Ok parent_entry.height)
    end else begin
      (* Block not on active chain, just mark as invalid *)
      match state.tip with
      | Some tip -> Ok tip.height
      | None -> Ok 0
    end

(* ============================================================================
   BIP 152: Compact Block Relay

   Compact blocks reduce block propagation bandwidth by sending just the header,
   a random nonce, short transaction IDs (6 bytes), and prefilled transactions.
   Recipients reconstruct blocks using transactions from their mempool.

   Reference: Bitcoin Core net_processing.cpp, blockencodings.cpp
   ============================================================================ *)

(* State for tracking in-flight compact block requests *)
type compact_block_request = {
  cb_header_hash : Types.hash256;
  cb_compact : P2p.compact_block;
  cb_peer_id : int;
  cb_request_time : float;
  mutable cb_missing_indices : int list;  (* Indices of missing transactions *)
}

(* Pending compact block reconstruction state per block hash *)
let pending_compact_blocks : (string, compact_block_request) Hashtbl.t =
  Hashtbl.create 16

(* Check if we have a header for this compact block *)
let has_compact_block_header (state : chain_state) (hash : Types.hash256) : bool =
  let hash_key = Cstruct.to_string hash in
  Hashtbl.mem state.headers hash_key

(* Handle a received cmpctblock message.
   Attempts to reconstruct the block from mempool. If successful, processes
   the block immediately. If missing transactions, sends getblocktxn request. *)
let handle_cmpctblock (ibd : ibd_state) (cb : P2p.compact_block)
    (peer : Peer.peer) ~(mempool : Mempool.mempool option)
    : [`Reconstructed of Types.block | `NeedTx of int list | `Ignored] Lwt.t =
  let open Lwt.Syntax in
  let header_hash = Crypto.compute_block_hash cb.header in
  let hash_key = Cstruct.to_string header_hash in
  (* Check if we already have this block *)
  if Storage.ChainDB.get_block ibd.chain.db header_hash <> None then begin
    Logs.debug (fun m ->
      m "Ignoring cmpctblock %s (already have block)"
        (Types.hash256_to_hex_display header_hash));
    Lwt.return `Ignored
  end
  (* Check if already processing this compact block *)
  else if Hashtbl.mem pending_compact_blocks hash_key then begin
    Logs.debug (fun m ->
      m "Ignoring duplicate cmpctblock %s"
        (Types.hash256_to_hex_display header_hash));
    Lwt.return `Ignored
  end
  else begin
    (* Derive SipHash keys for short ID computation *)
    let (k0, k1) = Crypto.SipHash.derive_keys cb.header cb.nonce in
    (* Build lookup table from mempool *)
    let lookup_tbl = match mempool with
      | None -> Hashtbl.create 0
      | Some mp -> Mempool.create_short_id_lookup mp ~k0 ~k1
    in
    let lookup = { P2p.by_short_id = lookup_tbl } in
    (* Attempt reconstruction *)
    match P2p.reconstruct_block cb lookup with
    | P2p.ReconstructComplete block ->
      Logs.info (fun m ->
        m "Reconstructed compact block %s from mempool"
          (Types.hash256_to_hex_display header_hash));
      Lwt.return (`Reconstructed block)
    | P2p.ReconstructNeedTxs indices ->
      Logs.debug (fun m ->
        m "Compact block %s missing %d transactions, requesting"
          (Types.hash256_to_hex_display header_hash)
          (List.length indices));
      (* Store pending request *)
      let req = {
        cb_header_hash = header_hash;
        cb_compact = cb;
        cb_peer_id = peer.Peer.id;
        cb_request_time = Unix.gettimeofday ();
        cb_missing_indices = indices;
      } in
      Hashtbl.replace pending_compact_blocks hash_key req;
      (* Send getblocktxn request with differential encoding *)
      let getblocktxn_req = P2p.make_getblocktxn_request header_hash indices in
      let msg = P2p.make_getblocktxn_msg getblocktxn_req in
      let* () = Lwt.catch
        (fun () -> Peer.send_message peer msg)
        (fun _exn -> Lwt.return_unit)
      in
      Lwt.return (`NeedTx indices)
    | P2p.ReconstructFailed msg ->
      Logs.warn (fun m ->
        m "Failed to reconstruct compact block %s: %s"
          (Types.hash256_to_hex_display header_hash) msg);
      Lwt.return `Ignored
  end

(* Handle a received blocktxn message (response to getblocktxn).
   Completes reconstruction of a pending compact block. *)
let handle_blocktxn (ibd : ibd_state) (block_hash : Types.hash256)
    (txns : Types.transaction list) ~(mempool : Mempool.mempool option)
    : (Types.block, string) result =
  let hash_key = Cstruct.to_string block_hash in
  match Hashtbl.find_opt pending_compact_blocks hash_key with
  | None ->
    Logs.debug (fun m ->
      m "Received blocktxn for unknown compact block %s"
        (Types.hash256_to_hex_display block_hash));
    Error "No pending compact block request"
  | Some req ->
    (* Remove from pending set *)
    Hashtbl.remove pending_compact_blocks hash_key;
    let cb = req.cb_compact in
    (* Re-create lookup with received transactions appended.
       We combine mempool transactions with the received missing transactions. *)
    let (k0, k1) = Crypto.SipHash.derive_keys cb.header cb.nonce in
    (* Create lookup from mempool and received transactions *)
    let lookup_tbl = match mempool with
      | None -> Hashtbl.create (List.length txns)
      | Some mp -> Mempool.create_short_id_lookup mp ~k0 ~k1
    in
    (* Add received transactions to lookup *)
    List.iter (fun tx ->
      let wtxid = Crypto.compute_wtxid tx in
      let short_id = Crypto.compute_short_txid k0 k1 wtxid in
      Hashtbl.replace lookup_tbl short_id tx
    ) txns;
    let lookup = { P2p.by_short_id = lookup_tbl } in
    (* Attempt reconstruction again with augmented lookup *)
    match P2p.reconstruct_block cb lookup with
    | P2p.ReconstructComplete block ->
      Logs.info (fun m ->
        m "Completed compact block reconstruction for %s"
          (Types.hash256_to_hex_display block_hash));
      (* Pass to receive_block for normal processing *)
      let _ = receive_block ibd block in
      Ok block
    | P2p.ReconstructNeedTxs _ ->
      Logs.warn (fun m ->
        m "Compact block %s still missing transactions after blocktxn"
          (Types.hash256_to_hex_display block_hash));
      Error "Still missing transactions after blocktxn"
    | P2p.ReconstructFailed msg ->
      Logs.warn (fun m ->
        m "Failed to reconstruct compact block %s: %s"
          (Types.hash256_to_hex_display block_hash) msg);
      Error msg

(* Expire pending compact block requests older than timeout *)
let expire_compact_block_requests (timeout_secs : float) : int =
  let now = Unix.gettimeofday () in
  let to_remove = Hashtbl.fold (fun key req acc ->
    if now -. req.cb_request_time > timeout_secs then
      key :: acc
    else
      acc
  ) pending_compact_blocks [] in
  List.iter (fun key -> Hashtbl.remove pending_compact_blocks key) to_remove;
  let removed = List.length to_remove in
  if removed > 0 then
    Logs.debug (fun m ->
      m "Expired %d pending compact block requests" removed);
  removed

(* Check if a peer has the header for a given block (for HB relay filtering) *)
let peer_has_header (_peer : Peer.peer) (_hash : Types.hash256) : bool =
  (* Simplified check: assume peer has header if handshake complete.
     A more sophisticated implementation would track peer's best header. *)
  true

(* Reconsider a previously invalidated block.
   Clears the invalid flag from the block and all its descendants/ancestors,
   then triggers chain selection to potentially reorg to a better chain. *)
let reconsider_block (state : chain_state) (hash : Types.hash256)
    : (int, string) result =
  let hash_key = Cstruct.to_string hash in
  match Hashtbl.find_opt state.headers hash_key with
  | None -> Error "Block not found"
  | Some entry ->
    Logs.info (fun m ->
      m "Reconsidering block at height %d: %s"
        entry.height (Types.hash256_to_hex_display hash));
    (* Clear invalid flag from this block *)
    Hashtbl.remove state.invalidated_blocks hash_key;
    Storage.ChainDB.clear_block_invalidated state.db hash;
    (* Clear invalid flag from all descendants *)
    let descendants = find_descendants state hash in
    List.iter (fun (d : header_entry) ->
      let d_key = Cstruct.to_string d.hash in
      Hashtbl.remove state.invalidated_blocks d_key;
      Storage.ChainDB.clear_block_invalidated state.db d.hash
    ) descendants;
    (* Also clear invalid flag from ancestors (matching Bitcoin Core behavior) *)
    let rec clear_ancestors (e : header_entry) =
      let parent_key = Cstruct.to_string e.header.prev_block in
      if Hashtbl.mem state.invalidated_blocks parent_key then begin
        Hashtbl.remove state.invalidated_blocks parent_key;
        Storage.ChainDB.clear_block_invalidated state.db e.header.prev_block;
        match Hashtbl.find_opt state.headers parent_key with
        | Some parent -> clear_ancestors parent
        | None -> ()
      end
    in
    clear_ancestors entry;
    Logs.debug (fun m ->
      m "Cleared invalid flags from %d descendant blocks"
        (List.length descendants));
    (* Find the best valid chain - may now include the reconsidered block *)
    match find_best_valid_tip state with
    | Some best when
        (match state.tip with
         | Some tip -> Consensus.work_compare best.total_work tip.total_work > 0
         | None -> true) ->
      Logs.info (fun m ->
        m "Reconsidered chain has more work, new best tip at height %d"
          best.height);
      (* Update tip - caller would need to handle full reorg with UTXO updates *)
      Ok best.height
    | _ ->
      match state.tip with
      | Some tip -> Ok tip.height
      | None -> Ok 0
