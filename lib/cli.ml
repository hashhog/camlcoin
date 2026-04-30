(* CLI Configuration and Application Entry Point

   Provides command-line configuration management and the main application
   run loop that ties together all components: P2P networking, sync, mempool,
   RPC server, and wallet. *)

(* ============================================================================
   CLI Configuration Type
   ============================================================================ *)

type config = {
  network : [`Mainnet | `Testnet | `Regtest];
  data_dir : string;
  rpc_host : string;
  rpc_port : int;
  rpc_user : string;
  rpc_password : string;
  p2p_port : int;
  max_outbound : int;
  max_inbound : int;
  connect : string list;  (* manual peer addresses *)
  debug : bool;
  wallet_enabled : bool;
  prune : int;  (* 0 = no pruning *)
  log_categories : string list;  (* empty = all enabled *)
  metrics_port : int;  (* Prometheus metrics port, 0 = disabled *)
  peer_bloom_filters : bool;
    (* Advertise NODE_BLOOM (BIP-35 / BIP-111).  Defaults to [false] to
       match Bitcoin Core's DEFAULT_PEERBLOOMFILTERS (net_processing.h:44);
       enable with --peerbloomfilters to honour MEMPOOL requests and
       bloom-filter setup messages. *)
  zmq_pub_options : string list;
    (* ZMQ publisher options in Bitcoin Core's "-zmqpub<topic>=<address>"
       syntax (e.g. "-zmqpubrawblock=tcp://127.0.0.1:28332"). Supported
       topics: hashblock, hashtx, rawblock, rawtx, sequence (and the
       "pub*" aliases). Empty list disables the ZMQ notifier. *)
  reindex : bool;
    (* If true, before opening the chainstate, wipe the UTXO + chain_state
       + undo_data CFs and the rocksdb_utxo subdirectory; then after
       opening, replay every stored block from height 0 forward to
       rebuild the UTXO set. Headers + block bodies + height->hash
       are retained. Mirrors Bitcoin Core's -reindex (init.cpp). *)
}

(* ============================================================================
   Default Configuration
   ============================================================================ *)

let default_config : config = {
  network = `Mainnet;
  data_dir = Filename.concat (Sys.getenv "HOME") ".camlcoin";
  rpc_host = "127.0.0.1";
  rpc_port = 8332;
  rpc_user = "camlcoin";
  rpc_password = "camlcoin";
  p2p_port = 8333;
  max_outbound = 8;
  max_inbound = 117;
  connect = [];
  debug = false;
  wallet_enabled = true;
  prune = 0;
  log_categories = [];
  metrics_port = 9332;
  peer_bloom_filters = false;  (* Mirrors Core DEFAULT_PEERBLOOMFILTERS *)
  zmq_pub_options = [];
  reindex = false;
}

(* Network-specific configuration *)
let config_for_network = function
  | `Mainnet -> { default_config with
      rpc_port = 8332; p2p_port = 8333 }
  | `Testnet -> { default_config with
      network = `Testnet;
      data_dir = Filename.concat (Sys.getenv "HOME") ".camlcoin/testnet3";
      rpc_port = 18332; p2p_port = 18333 }
  | `Regtest -> { default_config with
      network = `Regtest;
      data_dir = Filename.concat (Sys.getenv "HOME") ".camlcoin/regtest";
      rpc_port = 18443; p2p_port = 18444 }

(* ============================================================================
   Logging Setup
   ============================================================================ *)

(* When [reporter_already_installed] is true the caller has already wired up
   a custom reporter (e.g. Runtime_config.install_log_file_reporter for
   --logfile output) and we must NOT clobber it with Logs_fmt.reporter. *)
let setup_logging ?(reporter_already_installed : bool = false)
    (debug : bool) ?(categories : string list = []) () : unit =
  Fmt_tty.setup_std_outputs ();
  let default_level = if debug then Logs.Debug else Logs.Info in
  Logs.set_level (Some default_level);
  if not reporter_already_installed then
    Logs.set_reporter (Logs_fmt.reporter ());
  if categories <> [] then
    List.iter (fun src ->
      let name = Logs.Src.name src in
      (* Sentinel "__none__" from Runtime_config.resolve_debug_categories
         means no source matches -> all clamped to Warning. *)
      let cats_uc = List.map String.uppercase_ascii categories in
      if not (List.mem (String.uppercase_ascii name) cats_uc) then
        Logs.Src.set_level src (Some Logs.Warning)
    ) (Logs.Src.list ())

(* ============================================================================
   Main Application Run Loop
   ============================================================================ *)

let run ?(ready_fd : int option) (config : config) : unit Lwt.t =
  let open Lwt.Syntax in

  (* Detect whether bin/main.ml already installed a file-based reporter
     (Runtime_config.install_log_file_reporter); if so, don't clobber it. *)
  let reporter_installed = Runtime_config.log_target_ref <> ref None
                           && !Runtime_config.log_target_ref <> None in
  setup_logging ~reporter_already_installed:reporter_installed
    config.debug ~categories:config.log_categories ();

  Logs.info (fun m ->
    m "CamlCoin v%s starting on %s"
      Types.version
      (match config.network with
       | `Mainnet -> "mainnet"
       | `Testnet -> "testnet"
       | `Regtest -> "regtest"));

  (* Configure NODE_BLOOM advertisement BEFORE any peer/handshake work.
     [Peer.our_services ()] reads this ref, so it must be set before the
     peer manager, P2P listener, or RPC server start consulting it.
     Defaults to [false] (Core parity); flip with --peerbloomfilters. *)
  Peer.set_peer_bloom_filters config.peer_bloom_filters;
  Logs.info (fun m ->
    m "NODE_BLOOM (BIP-35) advertisement: %s"
      (if config.peer_bloom_filters then "enabled (-peerbloomfilters=1)"
       else "disabled (Core default)"));

  (* Ensure data directory exists *)
  (try Unix.mkdir config.data_dir 0o755
   with Unix.Unix_error (Unix.EEXIST, _, _) -> ());

  (* Initialize database *)
  let db_path = Filename.concat config.data_dir "chainstate" in
  (* Option D boot guard (default ON as of the ChainDB → Cf_chainstate
     cutover, see CAMLCOIN-UTXO-DESIGN-MEMO-2026-04-29.md).

     If [data.log] is present but [.migration-complete] is missing the
     legacy LogStorage data has not been migrated; ChainDB is now
     RocksDB-CF-backed and would happily start an empty chain on top of
     the unmigrated dir, silently abandoning the operator's history.
     Refuse the boot instead and direct them to run the migration.

     [CAMLCOIN_ALLOW_LEGACY_LOGSTORAGE=1] downgrades the refuse to a
     loud warning. Intended for emergency rollback only — the daemon
     will still write to RocksDB and ignore the data.log. *)
  let legacy_escape =
    match Sys.getenv_opt "CAMLCOIN_ALLOW_LEGACY_LOGSTORAGE" with
    | Some ("1" | "true" | "yes") -> true
    | _ -> false
  in
  if legacy_escape then begin
    let dl = Filename.concat db_path "data.log" in
    let mc = Filename.concat db_path ".migration-complete" in
    if Sys.file_exists dl && not (Sys.file_exists mc) then begin
      Logs.warn (fun m ->
        m "CAMLCOIN_ALLOW_LEGACY_LOGSTORAGE=1: data.log present at %s \
           but no .migration-complete marker. The daemon will boot \
           against the new RocksDB chainstate and IGNORE data.log; \
           run --migrate-logstorage-to-rocksdb to recover."
          dl);
      Printf.eprintf
        "[boot] WARNING: legacy data.log present, ignored \
         (CAMLCOIN_ALLOW_LEGACY_LOGSTORAGE=1)\n%!"
    end
  end else
    Migration.check_or_refuse_to_boot db_path;

  (* -reindex pre-open phase. MUST run before Storage.ChainDB.create
     (the wipe needs exclusive access to the on-disk RocksDB), and
     before Migration.check_or_refuse_to_boot (the wipe leaves a fresh
     chainstate that the migration guard would otherwise mistake for
     an unmigrated legacy datadir). The post-open replay runs after
     restore_chain_state populates the in-memory header chain. *)
  if config.reindex then begin
    match Reindex.pre_open_wipe ~data_dir:config.data_dir with
    | Ok () ->
      Logs.info (fun m -> m "reindex: pre-open wipe complete")
    | Error msg ->
      Logs.err (fun m -> m "reindex: pre-open wipe FAILED: %s" msg);
      Printf.eprintf "[camlcoin] reindex failed: %s\n%!" msg;
      exit 1
  end;
  let db = Storage.ChainDB.create db_path in

  (* Get network config *)
  let network = match config.network with
    | `Mainnet -> Consensus.mainnet
    | `Testnet -> Consensus.testnet4
    | `Regtest -> Consensus.regtest
  in

  (* Initialize or restore chain state *)
  let chain = Sync.restore_chain_state db network in
  chain.prune_target <- config.prune;
  Logs.info (fun m ->
    m "Chain state initialized, headers at height %d"
      chain.headers_synced);

  (* Initialize UTXO set *)
  let utxo = Utxo.UtxoSet.create db in

  (* Open RocksDB for the UTXO set — replaces LogStorage's lseek+read *)
  let rocksdb_path = Filename.concat config.data_dir "rocksdb_utxo" in
  let rocksdb = Rocksdb_store.open_db rocksdb_path in
  Logs.info (fun m -> m "Opened RocksDB UTXO store at %s" rocksdb_path);

  (* Wire the RocksDB handle into ChainDB so [get_utxo] can fall back to
     RocksDB on a LogStorage miss.  Pre-assume-valid UTXOs live only in
     RocksDB because assume-valid IBD writes through OptimizedUtxoSet;
     without this fallback, any post-IBD block that spends a pre-AV
     output fails validation with TxMissingInputs. *)
  Storage.ChainDB.attach_rocksdb_utxo db rocksdb;

  (* Consistency check: detect when RocksDB was wiped but chainstate still
     has a non-zero chain_tip.  Without this, the node would skip blocks
     whose UTXO outputs are missing from the fresh RocksDB, causing
     "transaction references missing inputs" errors (e.g. at block 16226). *)
  if chain.blocks_synced > 0 then begin
    match Rocksdb_store.get_tip_height rocksdb with
    | None ->
      Logs.warn (fun m ->
        m "RocksDB UTXO store has no tip height but chainstate claims blocks_synced=%d — resetting to 0 (UTXO store was likely wiped)"
          chain.blocks_synced);
      chain.blocks_synced <- 0;
      Storage.ChainDB.set_chain_tip db
        (Cstruct.create 32) 0
    | Some rdb_height when rdb_height < chain.blocks_synced ->
      Logs.warn (fun m ->
        m "RocksDB UTXO tip (%d) is behind chainstate chain_tip (%d) — resetting to RocksDB tip"
          rdb_height chain.blocks_synced);
      chain.blocks_synced <- rdb_height
    | Some _ -> ()  (* Consistent — proceed normally *)
  end;

  (* Optimized UTXO set for IBD – dirty entries are flushed periodically
     during block download and must be flushed on shutdown to avoid loss. *)
  (* LRU cache of 4M entries (~1GB) avoids hammering RocksDB during IBD.
     Without this, every UTXO lookup during block validation is a disk read.
     Reduced from 8M: at 8M the dirty set + LRU + OCaml GC overhead pushed
     RSS to 12+ GB.  4M keeps RSS under control while still caching the
     hot working set. *)
  let optimized_utxo = Utxo.OptimizedUtxoSet.create ~cache_size:4_000_000 ~rocksdb db in

  (* -reindex post-open replay. With cf_chain_state cleared, restore
     above set blocks_synced = 0 (no tip on disk). Headers were
     reloaded from cf_block_header. Walking forward via
     connect_stored_blocks rebuilds UTXOs + the chain_tip pointer
     from the retained block bodies. After this returns, the daemon
     is in the same observable state as a normal restart from a
     valid chainstate, and IBD / FullySynced operation continues. *)
  if config.reindex then begin
    let n = Reindex.replay_stored_blocks chain in
    Logs.info (fun m ->
      m "reindex: replay finished, %d blocks rebuilt, current tip=%d"
        n chain.blocks_synced)
  end;

  (* Initialize mempool *)
  let current_height = match chain.tip with
    | Some t -> t.height
    | None -> 0
  in
  let mempool = Mempool.create ~utxo ~current_height () in

  (* ZMQ notifier setup. Parses Bitcoin-Core-style "-zmqpub<topic>=<addr>"
     options into endpoint configs, opens a real PUB socket per address
     via lib/zmq_socket.ml, and wires the notifier into both the IBD
     pipeline (block-connect / block-disconnect) and the mempool
     (tx-acceptance / tx-removal). The notifier handle stays alive for
     the life of the daemon and is torn down in [graceful_shutdown]. *)
  let zmq_options =
    List.filter_map Zmq_notify.Config.parse_zmq_option config.zmq_pub_options
  in
  let zmq_state =
    if zmq_options = [] then None
    else begin
      let configs = Zmq_notify.Config.build_configs zmq_options in
      let notifier = Zmq_notify.create configs in
      match Zmq_socket.create_from_config configs with
      | None -> None
      | Some publisher ->
        Zmq_socket.connect_notifier notifier publisher;
        Logs.info (fun m ->
          m "ZMQ: notifier active (%d topic(s) on %d endpoint(s))"
            (List.length zmq_options)
            (List.length configs));
        Mempool.set_zmq_notifier mempool notifier;
        Some (notifier, publisher)
    end
  in

  (* Load persisted mempool from previous session *)
  let mempool_path = Filename.concat config.data_dir "mempool.dat" in
  (try
    let loaded = Mempool.load_mempool mempool mempool_path in
    if loaded > 0 then
      Logs.info (fun m -> m "Loaded %d transactions from mempool.dat" loaded)
  with exn ->
    Logs.warn (fun m ->
      m "Failed to load mempool.dat: %s" (Printexc.to_string exn)));

  (* Initialize fee estimator *)
  let fee_estimator = Fee_estimation.create () in

  (* Load persisted fee estimation data *)
  let fee_est_path = Filename.concat config.data_dir "fee_estimates.dat" in
  (try
    if Fee_estimation.load_from_file fee_estimator fee_est_path then
      Logs.info (fun m -> m "Loaded fee estimation data from %s" fee_est_path)
  with exn ->
    Logs.warn (fun m ->
      m "Failed to load fee estimates: %s" (Printexc.to_string exn)));

  (* Initialize peer manager *)
  let peer_manager = Peer_manager.create
    ~config:{ Peer_manager.default_config with
              max_outbound = config.max_outbound;
              max_inbound = config.max_inbound }
    network in

  (* Load persisted peer bans from previous session *)
  (try
    let loaded = Peer_manager.load_bans peer_manager db in
    if loaded > 0 then
      Logs.info (fun m -> m "Loaded %d peer bans from database" loaded)
  with exn ->
    Logs.warn (fun m ->
      m "Failed to load peer bans: %s" (Printexc.to_string exn)));

  (* Set peer manager's DB and initial block height so that the stale-tip
     check can build locators and knows our validated chain height. *)
  Peer_manager.set_db peer_manager db;
  Peer_manager.set_height peer_manager
    (Int32.of_int chain.blocks_synced);

  (* Initialize wallet *)
  let wallet = if config.wallet_enabled then begin
    let wallet_path = Filename.concat config.data_dir "wallet.json" in
    Some (Wallet.load ~network:config.network ~db_path:wallet_path)
  end else None in

  (* Create RPC context *)
  let rpc_ctx = Rpc.create_context
    ~chain ~mempool ~peer_manager
    ~wallet ~fee_estimator ~network
    ~utxo:(Some optimized_utxo)
    ~data_dir:(Some config.data_dir) () in

  (* Set up signal handlers for graceful shutdown.
     We use Lwt_unix.on_signal so that the signal wakes the Lwt event loop
     rather than racing with it from an OCaml signal handler.  A second
     signal during shutdown escalates immediately to a forced exit, matching
     Bitcoin Core init.cpp semantics. *)
  let shutdown_wakener, shutdown_waiter =
    let (w, u) = Lwt.wait () in (u, w) in
  let shutdown = ref false in
  let handle_signal name =
    if not !shutdown then begin
      Logs.info (fun m -> m "received %s" name);
      shutdown := true;
      Lwt.wakeup_later shutdown_wakener ()
    end else begin
      (* Second signal: escalate to immediate forced exit. *)
      Logs.warn (fun m ->
        m "received second %s during shutdown — forcing exit" name);
      Printf.eprintf "[camlcoin] second %s — forcing exit\n%!" name;
      exit 1
    end
  in
  let _sig_int = Lwt_unix.on_signal Sys.sigint (fun _signum ->
    handle_signal "SIGINT") in
  let _sig_term = Lwt_unix.on_signal Sys.sigterm (fun _signum ->
    handle_signal "SIGTERM") in
  (* Ignore SIGPIPE: writes to closed peer sockets must return EPIPE rather
     than killing the process. *)
  (try Sys.set_signal Sys.sigpipe Sys.Signal_ignore with _ -> ());

  (* Generate cookie credentials and write .cookie file *)
  let cookie_password =
    Mirage_crypto_rng_unix.use_default ();
    let raw = Mirage_crypto_rng_unix.getrandom 32 in
    let hex = String.concat "" (
      List.init (String.length raw) (fun i ->
        Printf.sprintf "%02x" (Char.code raw.[i]))) in
    let cookie_path = Filename.concat config.data_dir ".cookie" in
    (try
      let fd = Unix.openfile cookie_path
        [Unix.O_WRONLY; Unix.O_CREAT; Unix.O_TRUNC] 0o600 in
      let content = "__cookie__:" ^ hex in
      let _ = Unix.write_substring fd content 0 (String.length content) in
      Unix.close fd;
      Logs.info (fun m -> m "Wrote RPC cookie to %s" cookie_path)
    with exn ->
      Logs.warn (fun m ->
        m "Failed to write RPC cookie file: %s" (Printexc.to_string exn)));
    hex
  in

  (* Start RPC server *)
  let rpc_thread =
    Logs.info (fun m ->
      m "Starting RPC server on %s:%d" config.rpc_host config.rpc_port);
    Rpc.start_rpc_server
      ~ctx:rpc_ctx
      ~host:config.rpc_host
      ~port:config.rpc_port
      ~rpc_user:config.rpc_user
      ~rpc_password:config.rpc_password
      ~cookie_password:(Some cookie_password)
  in

  (* Start peer manager *)
  let peer_thread =
    Logs.info (fun m -> m "Starting peer manager");
    Peer_manager.start peer_manager
  in

  (* Start P2P listener for inbound connections *)
  let listener_thread =
    Logs.info (fun m -> m "Starting P2P listener on port %d" config.p2p_port);
    Peer_manager.start_listener peer_manager config.p2p_port
  in

  (* Connect to manual peers if specified *)
  let manual_connect_thread =
    if config.connect <> [] then begin
      Logs.info (fun m ->
        m "Connecting to %d manual peers" (List.length config.connect));
      Lwt_list.iter_s (fun addr_port ->
        let parts = String.split_on_char ':' addr_port in
        match parts with
        | [addr; port_str] ->
          (try
            let port = int_of_string port_str in
            Peer_manager.add_peer peer_manager addr port
          with _ ->
            Logs.warn (fun m ->
              m "Invalid peer address format: %s" addr_port);
            Lwt.return_unit)
        | [addr] ->
          (* Use default port for network *)
          Peer_manager.add_peer peer_manager addr network.default_port
        | _ ->
          Logs.warn (fun m ->
            m "Invalid peer address format: %s" addr_port);
          Lwt.return_unit
      ) config.connect
    end else
      Lwt.return_unit
  in

  (* Mutable reference to current IBD state so the block listener can
     route incoming BlockMsg / NotfoundMsg to the download manager. *)
  let ibd_state_ref : Sync.ibd_state option ref = ref None in

  (* Register a listener BEFORE starting sync so that block and notfound
     messages arriving via the peer_message_loop are forwarded to the IBD
     download queue. Without this, GetData responses are silently dropped. *)
  Peer_manager.add_listener peer_manager (fun msg peer ->
    match !ibd_state_ref with
    | None -> Lwt.return_unit
    | Some ibd ->
      (match msg with
       | P2p.BlockMsg block ->
         ignore (Sync.receive_block ibd block);
         Lwt.return_unit
       | P2p.NotfoundMsg items ->
         Sync.handle_notfound ibd peer.Peer.id items;
         Lwt.return_unit
       | _ -> Lwt.return_unit));

  (* BIP-35 mempool dispatch.  Registered as a separate listener so that it
     fires both during IBD (when [ibd_state_ref] is set) and post-IBD (when
     it is [None]); we always consult the live [mempool] handle which is
     valid throughout the node lifetime.  The handler enforces the
     NODE_BLOOM gate (mirrors Bitcoin Core's net_processing.cpp guard) and
     disconnects the requesting peer if we don't advertise NODE_BLOOM. *)
  Peer_manager.add_listener peer_manager (fun msg peer ->
    match msg with
    | P2p.MempoolMsg -> Sync.handle_mempool_msg_for (Some mempool) peer
    | _ -> Lwt.return_unit);

  (* Register a listener for getdata requests so peers can fetch blocks
     we have mined or stored (e.g. after receiving our inv announcement). *)
  Peer_manager.add_listener peer_manager (fun msg peer ->
    match msg with
    | P2p.GetdataMsg items ->
      let lookup_block hash =
        match Storage.ChainDB.get_block db hash with
        | None -> None
        | Some block ->
          let w = Serialize.writer_create () in
          Serialize.serialize_block w block;
          Some (Serialize.writer_to_cstruct w)
      in
      let lookup_tx hash =
        match Mempool.get mempool hash with
        | None -> None
        | Some entry ->
          let w = Serialize.writer_create () in
          Serialize.serialize_transaction w entry.Mempool.tx;
          Some (Serialize.writer_to_cstruct w)
      in
      Peer.handle_getdata peer items ~lookup_block ~lookup_tx
    | _ -> Lwt.return_unit);

  (* Register a listener for inv messages: when a peer announces a new block
     via inv, request it with getdata so we can connect it to our chain. *)
  Peer_manager.add_listener peer_manager (fun msg peer ->
    match msg with
    | P2p.InvMsg items ->
      let block_hashes = List.filter_map (fun (iv : P2p.inv_vector) ->
        if (iv.inv_type = P2p.InvBlock || iv.inv_type = P2p.InvWitnessBlock)
           && not (Storage.ChainDB.has_block db iv.hash) then
          (* Always request with witness data so we can validate the witness
             commitment.  Using InvBlock strips all witness data from the
             response, breaking check_witness_commitment on segwit blocks. *)
          Some { P2p.inv_type = P2p.InvWitnessBlock; hash = iv.hash }
        else
          None
      ) items in
      if block_hashes <> [] then
        Peer.send_message peer (P2p.GetdataMsg block_hashes)
      else
        Lwt.return_unit
    | _ -> Lwt.return_unit);

  (* Register a listener for getheaders: respond with headers from our chain
     so peers can sync from us. *)
  Peer_manager.add_listener peer_manager (fun msg peer ->
    match msg with
    | P2p.GetheadersMsg { locator_hashes; hash_stop; _ } ->
      let headers = Sync.handle_getheaders_request chain
          locator_hashes hash_stop in
      if headers <> [] then
        Peer.send_message peer (P2p.HeadersMsg headers)
      else
        Lwt.return_unit
    | _ -> Lwt.return_unit);

  (* Register a listener for headers received post-IBD.  When new headers
     arrive and extend our chain, process them and request the blocks. *)
  Peer_manager.add_listener peer_manager (fun msg peer ->
    match msg with
    | P2p.HeadersMsg headers when chain.sync_state = Sync.FullySynced ->
      (* W33 post-IBD gap-fill fix:
         Always scan the full [blocks_synced+1 .. tip_height] range, not just
         the newly-accepted headers.  If prior block requests failed silently
         (peer disconnect, notfound, etc.), the gap between blocks_synced and
         the header chain tip persists indefinitely because no retry mechanism
         existed.  Now the stale-tip check's periodic getheaders doubles as a
         gap-fill trigger: any missing block with a known header gets
         re-requested.

         W39 fix: the scan must also run when [process_headers] returns
         non-Ok.  Post-restart, peers frequently reply to our getheaders with
         headers we already have; [process_headers] then returns an error
         ("All N headers rejected / duplicates") and the gap-fill was being
         skipped — so the node stayed stuck at blocks_synced < tip_height
         indefinitely.  The gap-fill target range depends only on
         [chain.tip] and [chain.blocks_synced], both already populated from
         prior IBD, so we run it unconditionally. *)
      let _ = Sync.process_headers chain headers in
      let tip_height = match chain.tip with
        | Some t -> t.height | None -> 0 in
      let start_h = chain.blocks_synced + 1 in
      if start_h <= tip_height then begin
        let block_requests = ref [] in
        for h = start_h to tip_height do
          match Sync.get_header_at_height chain h with
          | Some entry ->
            if not (Storage.ChainDB.has_block db entry.hash) then
              block_requests :=
                { P2p.inv_type = P2p.InvWitnessBlock; hash = entry.hash }
                :: !block_requests
          | None -> ()
        done;
        if !block_requests <> [] then begin
          let n_requests = List.length !block_requests in
          Logs.info (fun m ->
            m "Post-IBD gap-fill: requesting %d missing blocks [%d..%d] from peer %d"
              n_requests start_h tip_height peer.Peer.id);
          Peer.send_message peer (P2p.GetdataMsg (List.rev !block_requests))
        end else
          Lwt.return_unit
      end else
        Lwt.return_unit
    | _ -> Lwt.return_unit);

  (* Register a listener for blocks received post-IBD (when ibd_state is None).
     This handles unsolicited blocks and blocks requested via inv/getdata. *)
  Peer_manager.add_listener peer_manager (fun msg _peer ->
    match msg with
    | P2p.BlockMsg block when !ibd_state_ref = None
                              && chain.sync_state = Sync.FullySynced ->
      let hash = Crypto.compute_block_hash block.Types.header in
      (match Sync.process_new_block chain block with
       | Ok () ->
         (* Feed the fee estimator with confirmed block data *)
         (try Fee_estimation.process_block fee_estimator block chain.blocks_synced
          with _ -> ());
         (* Announce the block to other peers if it advanced the tip *)
         Lwt.async (fun () ->
           Peer_manager.announce_block peer_manager block.Types.header hash);
         Lwt.return_unit
       | Error e ->
         Logs.debug (fun m ->
           m "Post-IBD block rejected: %s" e);
         Lwt.return_unit)
    | _ -> Lwt.return_unit);

  (* Transaction relay: accept incoming tx messages into the mempool and relay
     via inv to other peers. Also handle inv messages for tx announcements
     by requesting unknown transactions via getdata. *)
  Peer_manager.add_listener peer_manager (fun msg peer ->
    match msg with
    | P2p.TxMsg tx when chain.sync_state = Sync.FullySynced ->
      let result = Mempool.accept_to_memory_pool mempool tx in
      if result.Mempool.atmp_accepted then begin
        Logs.info (fun m ->
          m "Accepted tx %s into mempool (fee=%Ld vsize=%d)"
            (Types.hash256_to_hex result.Mempool.atmp_txid)
            result.Mempool.atmp_fee result.Mempool.atmp_vsize);
        (* Convert fee rate to sat/kvB for feefilter comparison *)
        let fee_rate_kvb =
          if result.Mempool.atmp_vsize > 0 then
            Int64.div (Int64.mul result.Mempool.atmp_fee 1000L)
              (Int64.of_int result.Mempool.atmp_vsize)
          else 0L
        in
        (* Relay inv to all ready peers except the sender *)
        let ready = Peer_manager.get_ready_peers peer_manager in
        Lwt_list.iter_p (fun relay_peer ->
          if relay_peer.Peer.id <> peer.Peer.id
             && relay_peer.Peer.relay
             && not relay_peer.Peer.block_relay_only
             && fee_rate_kvb >= relay_peer.Peer.feefilter then
            Lwt.catch (fun () ->
              let inv_type =
                if relay_peer.Peer.wtxid_relay then P2p.InvWitnessTx
                else P2p.InvTx
              in
              Peer.send_message relay_peer
                (P2p.InvMsg [{ P2p.inv_type; hash = result.Mempool.atmp_txid }])
            ) (fun _exn -> Lwt.return_unit)
          else
            Lwt.return_unit
        ) ready
      end else begin
        (match result.Mempool.atmp_reject_reason with
         | Some reason ->
           Logs.debug (fun m ->
             m "Rejected tx %s: %s"
               (Types.hash256_to_hex result.Mempool.atmp_txid) reason)
         | None -> ());
        Lwt.return_unit
      end
    | P2p.InvMsg items when chain.sync_state = Sync.FullySynced ->
      (* Request unknown transactions announced via inv *)
      let tx_requests = List.filter_map (fun (iv : P2p.inv_vector) ->
        if (iv.inv_type = P2p.InvTx || iv.inv_type = P2p.InvWitnessTx)
           && not (Mempool.contains mempool iv.hash) then
          Some { P2p.inv_type = P2p.InvWitnessTx; hash = iv.hash }
        else
          None
      ) items in
      if tx_requests <> [] then
        Peer.send_message peer (P2p.GetdataMsg tx_requests)
      else
        Lwt.return_unit
    | _ -> Lwt.return_unit);

  (* BIP 331: Register a listener for package relay messages.  This handles
     getpkgtxns (peer asks for txs by wtxid) and pkgtxns (peer delivers a
     package for validation).  Sendpackages negotiation is captured in
     Peer.dispatch_message before this listener fires. *)
  Peer_manager.add_listener peer_manager (fun msg peer ->
    Package_relay.dispatch mempool msg peer);

  (* BIP 152: Register a listener for compact block messages.
     When we receive a cmpctblock, attempt reconstruction from our mempool.
     If reconstruction fails (missing transactions), send getblocktxn to the peer.
     When we receive blocktxn, complete the reconstruction and process the block.
     When we receive getblocktxn, respond with the requested transactions. *)
  let compact_pending :
    (Types.hash256, P2p.compact_block * Types.transaction option array * int list) Hashtbl.t =
    Hashtbl.create 16 in
  Peer_manager.add_listener peer_manager (fun msg peer ->
    match msg with
    | P2p.CmpctblockMsg cb when chain.sync_state = Sync.FullySynced ->
      let header_hash = Crypto.compute_block_hash cb.header in
      Logs.info (fun m ->
        m "Received cmpctblock from peer %d: %s (%d short_ids, %d prefilled)"
          peer.Peer.id (Types.hash256_to_hex header_hash)
          (List.length cb.short_ids) (List.length cb.prefilled_txs));
      (* Attempt reconstruction using mempool *)
      let result = Peer_manager.reconstruct_from_mempool peer_manager cb in
      (match result with
       | P2p.ReconstructComplete block ->
         (* All transactions found *)
         Logs.info (fun m ->
           m "Compact block fully reconstructed: %s" (Types.hash256_to_hex header_hash));
         (match Sync.process_new_block chain block with
          | Ok () ->
            (try Fee_estimation.process_block fee_estimator block chain.blocks_synced
             with _ -> ());
            Lwt.async (fun () ->
              Peer_manager.announce_block peer_manager block.Types.header header_hash);
            Lwt.return_unit
          | Error e ->
            Logs.debug (fun m -> m "Reconstructed compact block rejected: %s" e);
            Lwt.return_unit)
       | P2p.ReconstructNeedTxs missing ->
         (* Store partial state and request missing transactions *)
         Logs.info (fun m ->
           m "Compact block %s missing %d txns, sending getblocktxn"
             (Types.hash256_to_hex header_hash) (List.length missing));
         (* Build partial_txs array from reconstruction attempt *)
         let tx_count = P2p.compact_block_tx_count cb in
         let partial_txs = Array.make tx_count None in
         (* Fill in prefilled transactions *)
         let last_idx = ref (-1) in
         List.iter (fun ptx ->
           let abs_idx = !last_idx + ptx.P2p.index + 1 in
           if abs_idx < tx_count then begin
             partial_txs.(abs_idx) <- Some ptx.P2p.tx;
             last_idx := abs_idx
           end
         ) cb.prefilled_txs;
         Hashtbl.replace compact_pending header_hash (cb, partial_txs, missing);
         let req = P2p.make_getblocktxn_request header_hash missing in
         let getblocktxn_msg = P2p.make_getblocktxn_msg req in
         Lwt.catch
           (fun () -> Peer.send_message peer getblocktxn_msg)
           (fun _exn -> Lwt.return_unit)
       | P2p.ReconstructFailed reason ->
         Logs.warn (fun m ->
           m "Compact block reconstruction failed: %s" reason);
         Lwt.return_unit)
    | P2p.BlocktxnMsg resp ->
      let hash_hex = Types.hash256_to_hex resp.block_hash in
      Logs.info (fun m ->
        m "Received blocktxn from peer %d: %s (%d txns)"
          peer.Peer.id hash_hex (List.length resp.txs));
      (match Hashtbl.find_opt compact_pending resp.block_hash with
       | Some (cb, partial_txs, missing_indices) ->
         Hashtbl.remove compact_pending resp.block_hash;
         let fill_result = P2p.fill_missing_txs cb partial_txs missing_indices resp.txs in
         (match fill_result with
          | Ok block ->
            Logs.info (fun m ->
              m "Compact block reconstructed from blocktxn: %s" hash_hex);
            (match Sync.process_new_block chain block with
             | Ok () ->
               (try Fee_estimation.process_block fee_estimator block chain.blocks_synced
                with _ -> ());
               Lwt.async (fun () ->
                 Peer_manager.announce_block peer_manager block.Types.header resp.block_hash);
               Lwt.return_unit
             | Error e ->
               Logs.debug (fun m -> m "Reconstructed block rejected: %s" e);
               Lwt.return_unit)
          | Error reason ->
            Logs.warn (fun m -> m "blocktxn fill failed for %s: %s" hash_hex reason);
            Lwt.return_unit)
       | None ->
         Logs.debug (fun m -> m "Unexpected blocktxn (no pending compact block): %s" hash_hex);
         Lwt.return_unit)
    | P2p.GetblocktxnMsg req ->
      Logs.info (fun m ->
        m "Received getblocktxn from peer %d: %s (%d indexes)"
          peer.Peer.id (Types.hash256_to_hex req.block_hash)
          (List.length req.indexes));
      (* Decode differential indices to absolute indices *)
      let abs_indexes = P2p.decode_differential_indices req.indexes in
      (* Look up the full block and respond with requested transactions *)
      (match Storage.ChainDB.get_block db req.block_hash with
       | Some block ->
         let txs_array = Array.of_list block.Types.transactions in
         let requested_txs = List.filter_map (fun idx ->
           if idx >= 0 && idx < Array.length txs_array then
             Some txs_array.(idx)
           else None
         ) abs_indexes in
         let resp = P2p.make_blocktxn_msg {
           P2p.block_hash = req.block_hash;
           txs = requested_txs;
         } in
         Lwt.catch
           (fun () -> Peer.send_message peer resp)
           (fun _exn -> Lwt.return_unit)
       | None ->
         Logs.debug (fun m -> m "getblocktxn: block not found");
         Lwt.return_unit)
    | _ -> Lwt.return_unit);

  (* Dynamic peer getter so IBD always sees the latest connected peers *)
  let get_peers () = Peer_manager.get_ready_peers peer_manager in

  (* Sync thread - waits for first peer then syncs *)
  let sync_thread =
    (* Poll until at least one peer completes handshake (up to 60s) *)
    let rec wait_for_peer attempts =
      if attempts >= 60 then begin
        Logs.warn (fun m -> m "No peers connected after 60s, will retry via stale-tip check");
        Lwt.return_none
      end else begin
        let* () = Lwt_unix.sleep 1.0 in
        let all_peers = Peer_manager.peer_count peer_manager in
        let ready = Peer_manager.ready_peer_count peer_manager in
        if attempts mod 5 = 0 then
          Logs.info (fun m -> m "Waiting for peers: %d total, %d ready (attempt %d/60)" all_peers ready attempts);
        match get_peers () with
        | [] -> wait_for_peer (attempts + 1)
        | peer :: _ -> Lwt.return_some peer
      end
    in
    (* Retry header sync with unlimited attempts until headers are fully synced.
       Uses a monotonically increasing attempt counter for logging. *)
    let rec try_header_sync attempt =
      let* first_peer = wait_for_peer 0 in
      match first_peer with
      | None -> Lwt.return_unit
      | Some peer ->
        Logs.info (fun m ->
          m "Starting header sync with peer %d (attempt %d)" peer.Peer.id attempt);
        Peer_manager.set_header_sync_active peer_manager true;
        (* W74: defense-in-depth.  sync_headers should now return cleanly on
           any read failure (the underlying peer.ml read_message_with_timeout
           converts I/O exceptions to timeouts), but wrap with Lwt.catch
           anyway so any unexpected exception path lands in the retry loop
           below instead of killing the sync fiber.  See
           wave47-2026-04-16/W74-CAMLCOIN-HEADER-WEDGE.md. *)
        let* () =
          Lwt.catch
            (fun () -> Sync.sync_headers chain peer)
            (fun exn ->
              Logs.err (fun m ->
                m "sync_headers raised unexpected exception: %s — forcing retry"
                  (Printexc.to_string exn));
              chain.sync_state <- Sync.Idle;
              Lwt.return_unit)
        in
        Peer_manager.set_header_sync_active peer_manager false;
        Peer_manager.set_height peer_manager (Int32.of_int chain.headers_synced);
        (* Reset the stale-tip clock after the (potentially multi-hour)
           header sync.  Without this, the very first stale-tip check
           after `set_header_sync_active false` would fire immediately
           against `last_tip_update = peer_manager init time` and rotate
           peers in the 30s window before the status thread's next tick
           calls notify_tip_updated. *)
        Peer_manager.notify_tip_updated peer_manager;
        if chain.sync_state = Sync.Idle then begin
          Logs.warn (fun m -> m "Header sync failed, retrying in 10s (attempt %d)" attempt);
          let* () = Lwt_unix.sleep 10.0 in
          try_header_sync (attempt + 1)
        end else
          Lwt.return_unit
    in
    let* () = try_header_sync 1 in
    let _ = () in
      (* Header sync is done. Now enable message loops for all peers so
         that incoming BlockMsg / NotfoundMsg are read and passed to the
         listener. This must happen AFTER sync_headers because it reads
         from the peer socket directly and would race with the loop. *)
      Peer_manager.enable_message_loops peer_manager;
      (* Start block download if needed *)
      if chain.sync_state = Sync.SyncingBlocks then begin
        Logs.info (fun m -> m "Starting block download");
        let misbehavior_handler peer_id infraction =
          match Peer_manager.find_peer_by_id peer_manager peer_id with
          | Some peer ->
            (match Peer.record_misbehavior_for peer infraction with
             | `Ok -> ()
             | `Ban ->
               Lwt.async (fun () -> Peer_manager.ban_peer peer_manager peer_id ()))
          | None -> ()
        in
        let* () = Sync.start_ibd ~utxo_set:optimized_utxo
          ~misbehavior_handler
          ~on_ibd_created:(fun ibd ->
            ibd_state_ref := Some ibd;
            (* Wire ZMQ notifier into the IBD pipeline so block-connect
               / block-disconnect events publish on rawblock / hashblock
               / sequence topics. Mempool was wired earlier, before the
               IBD started. *)
            (match zmq_state with
             | Some (notifier, _) -> Sync.set_zmq_notifier ibd notifier
             | None -> ()))
          ~shutdown_flag:shutdown
          chain get_peers in
        (* Clear IBD state so post-IBD listeners take over *)
        ibd_state_ref := None;
        Lwt.return_unit
      end else
        Lwt.return_unit
  in

  (* Periodic status logging.  The block-progress observation must be
     tracked against its own ref (not pm.our_height): after header sync
     completes, cli.ml above sets pm.our_height to chain.headers_synced
     so the locator builder uses the header tip.  During block IBD,
     blocks_synced is far below that header tip, so the old condition
     `block_height > pm.our_height` was permanently false — meaning
     notify_tip_updated NEVER fired during block IBD, and the stale-tip
     rotation in peer_manager.ml fired against an apparent multi-hour
     stall, killing every connected peer and wedging IBD entirely. *)
  let last_block_height_observed = ref chain.blocks_synced in
  let status_thread =
    let rec log_status () =
      if !shutdown then Lwt.return_unit
      else begin
        let* () = Lwt_unix.sleep 30.0 in
        (* Action any pending SIGHUP — reopens the log file, no-op if no
           --logfile was configured. Cheap flag check. *)
        Runtime_config.drain_pending_sighup ();
        if not !shutdown then begin
          let peer_count = Peer_manager.peer_count peer_manager in
          let ready_count = Peer_manager.ready_peer_count peer_manager in
          let height = match chain.tip with
            | Some t -> t.height
            | None -> 0
          in
          let (mp_count, mp_weight, _) = Mempool.get_info mempool in
          let block_height = chain.blocks_synced in
          if block_height > !last_block_height_observed then begin
            last_block_height_observed := block_height;
            Peer_manager.notify_tip_updated peer_manager
          end;
          let prev_height = Peer_manager.get_height peer_manager in
          if Int32.of_int block_height > prev_height then
            Peer_manager.set_height peer_manager (Int32.of_int block_height);
          Logs.info (fun m ->
            m "Status: peers=%d/%d height=%d mempool=%d txs (%d weight)"
              ready_count peer_count height mp_count mp_weight);
          log_status ()
        end else
          Lwt.return_unit
      end
    in
    log_status ()
  in

  (* Graceful shutdown procedure: flush all pending state to disk in the
     reverse order of startup.  Each phase is wrapped in a try so that one
     failure does not skip subsequent flushes.  Phased log lines match the
     blockbrew / Bitcoin Core init.cpp shutdown trace. *)
  let graceful_shutdown () =
    (* Phase 1: stop P2P networking (listener + peer manager + outbound). *)
    Logs.info (fun m -> m "stopping P2P");
    let* () =
      Lwt.catch
        (fun () -> Peer_manager.stop peer_manager)
        (fun exn ->
          Logs.warn (fun m ->
            m "Peer_manager.stop raised: %s" (Printexc.to_string exn));
          Lwt.return_unit)
    in
    (* Phase 2: save wallet state. *)
    (try
      (match wallet with
       | Some w -> Wallet.save w
       | None -> ())
    with exn ->
      Logs.warn (fun m ->
        m "Failed to save wallet: %s" (Printexc.to_string exn)));
    (* Phase 3: flush chainstate (mempool, fee estimates, peer bans, UTXO). *)
    Logs.info (fun m -> m "flushing chainstate");
    (try
      let mempool_path = Filename.concat config.data_dir "mempool.dat" in
      Mempool.save_mempool mempool mempool_path;
      let (mp_count, _, _) = Mempool.get_info mempool in
      Logs.info (fun m -> m "Saved %d mempool transactions to disk" mp_count)
    with exn ->
      Logs.warn (fun m ->
        m "Failed to save mempool: %s" (Printexc.to_string exn)));
    (try
      Fee_estimation.save_to_file fee_estimator fee_est_path;
      Logs.info (fun m -> m "Saved fee estimation data to disk")
    with exn ->
      Logs.warn (fun m ->
        m "Failed to save fee estimates: %s" (Printexc.to_string exn)));
    (try
      Peer_manager.save_bans peer_manager db;
      Logs.info (fun m -> m "Saved peer bans to disk")
    with exn ->
      Logs.warn (fun m ->
        m "Failed to save bans: %s" (Printexc.to_string exn)));
    (try
      let dirty = Utxo.OptimizedUtxoSet.dirty_count optimized_utxo in
      if dirty > 0 then begin
        Logs.info (fun m -> m "Flushing %d dirty UTXO entries to disk" dirty);
        Utxo.OptimizedUtxoSet.flush
          ~tip_height:chain.blocks_synced optimized_utxo;
        let bs = chain.blocks_synced in
        (match Sync.get_header_at_height chain bs with
         | Some entry ->
           Storage.ChainDB.set_chain_tip db entry.hash bs
         | None -> ())
      end else begin
        (* W47 fix: in FullySynced mode, dirty is always 0 because
           [process_new_block] bypasses OptimizedUtxoSet.  Without this
           branch the shutdown path leaves rdb_tip frozen at the last IBD
           flush height while chain_tip (in LogStorage) has advanced with
           every post-IBD block — producing the 945509 wedge on next boot.
           Always align rdb_tip with blocks_synced at shutdown. *)
        Rocksdb_store.set_tip_height rocksdb chain.blocks_synced
      end
    with exn ->
      Logs.warn (fun m ->
        m "Failed to flush UTXO: %s" (Printexc.to_string exn)));
    (* Phase 4a: tear down the ZMQ publisher + context so the wire is
       quiet before we close the databases. zmq_ctx_term blocks on
       in-flight sends; LINGER=0 was set on the socket so close returns
       immediately. Best-effort: a hung ZMQ teardown cannot block the
       graceful path beyond this point because the whole shutdown path
       is wrapped by the 30s watchdog. *)
    (match zmq_state with
     | None -> ()
     | Some (notifier, publisher) ->
       (try Zmq_notify.shutdown notifier with _ -> ());
       (try Zmq_socket.close_publisher publisher with _ -> ());
       Logs.info (fun m -> m "ZMQ: notifier shut down"));
    (* Phase 4: close databases. *)
    Logs.info (fun m -> m "closing DB");
    (try Rocksdb_store.close rocksdb
     with exn ->
       Logs.warn (fun m ->
         m "Failed to close RocksDB: %s" (Printexc.to_string exn)));
    (try
      Storage.ChainDB.sync db;
      Storage.ChainDB.close db
    with exn ->
      Logs.warn (fun m ->
        m "Failed to close chainstate DB: %s" (Printexc.to_string exn)));
    (* Phase 5: remove PID file. Done last so a supervisor watching for the
       file's disappearance only sees it after databases are flushed. *)
    Runtime_config.remove_pid_file ();
    Logs.info (fun m -> m "exit");
    Lwt.return_unit
  in

  (* 30-second hard-deadline watchdog.  Armed when the shutdown signal fires.
     If graceful_shutdown has not completed within 30s, we best-effort close
     the databases and call exit(1).  This prevents any single blocking step
     (RocksDB compaction, UTXO flush, peer shutdown) from stranding the
     process and forcing the supervisor to escalate to SIGKILL. *)
  let watchdog () =
    let* () = shutdown_waiter in
    let* () = Lwt_unix.sleep 30.0 in
    Logs.err (fun m ->
      m "shutdown watchdog: graceful shutdown exceeded 30s — forcing exit");
    Printf.eprintf
      "[camlcoin] shutdown watchdog: graceful shutdown exceeded 30s — forcing exit\n%!";
    (* Best-effort close of DBs so the next start isn't stuck on a lock. *)
    (try Rocksdb_store.close rocksdb with _ -> ());
    (try Storage.ChainDB.close db with _ -> ());
    exit 1
  in

  (* Main event loop - waits for shutdown signal, then runs graceful_shutdown
     and returns.  Using Lwt.pick against the watchdog guarantees that
     whichever completes first wins: either graceful returns normally, or
     the watchdog process-exits. *)
  let event_loop () =
    let* () = shutdown_waiter in
    Lwt.pick [ graceful_shutdown (); watchdog () ]
  in

  (* Prevent uncaught Lwt.async exceptions from crashing the process.
     Protocol errors from peers are handled per-connection, but if one
     propagates here, just log it. *)
  Lwt.async_exception_hook := (fun exn ->
    Printf.eprintf "[WARNING] Uncaught async exception: %s\n%!" (Printexc.to_string exn)
  );

  (* Run all services concurrently.  Several of the service threads
     (peer_thread, sync_thread, manual_connect_thread) complete quickly after
     initial setup – they must NOT cause the node to exit.  We use Lwt.async
     for fire-and-forget background work and Lwt.join for the threads that
     should keep running until shutdown. *)
  Lwt.async (fun () -> manual_connect_thread);
  Lwt.async (fun () -> peer_thread);
  Lwt.async (fun () -> listener_thread);
  Lwt.async (fun () -> sync_thread);

  (* Supervisor handshake: now that the RPC, peer manager, and P2P listener
     have been kicked off, signal readiness on the file descriptor passed by
     the launcher (e.g. systemd Type=notify alternative). *)
  Runtime_config.signal_ready ?fd:ready_fd ();

  (* Start Prometheus metrics server *)
  let metrics_thread =
    if config.metrics_port > 0 then begin
      Logs.info (fun m ->
        m "Starting Prometheus metrics server on port %d" config.metrics_port);
      let callback _conn _req _body =
        let height = match rpc_ctx.chain.tip with
          | Some t -> t.height | None -> 0 in
        let peers = Peer_manager.peer_count peer_manager in
        let mp_count = Hashtbl.length rpc_ctx.mempool.entries in
        let body = Printf.sprintf
          "# HELP bitcoin_blocks_total Current block height\n\
           # TYPE bitcoin_blocks_total gauge\n\
           bitcoin_blocks_total %d\n\
           # HELP bitcoin_peers_connected Number of connected peers\n\
           # TYPE bitcoin_peers_connected gauge\n\
           bitcoin_peers_connected %d\n\
           # HELP bitcoin_mempool_size Mempool transaction count\n\
           # TYPE bitcoin_mempool_size gauge\n\
           bitcoin_mempool_size %d\n"
          height peers mp_count in
        let response_headers = Cohttp.Header.init_with
          "Content-Type" "text/plain; version=0.0.4; charset=utf-8" in
        Cohttp_lwt_unix.Server.respond_string
          ~status:`OK ~headers:response_headers ~body ()
      in
      let server = Cohttp_lwt_unix.Server.make ~callback () in
      let mode = `TCP (`Port config.metrics_port) in
      Cohttp_lwt_unix.Server.create ~mode server
    end else
      Lwt.return_unit
  in

  (* Run service threads in the background.  They never terminate on their
     own (the Cohttp-based RPC and metrics servers have no stop hook that
     resolves their promise), so we must not wait on them via Lwt.join — we
     would hang forever on shutdown.  Instead the event_loop promise is the
     single source of truth for when the process should return from
     Lwt_main.run: event_loop resolves when graceful_shutdown finishes, and
     the 30s watchdog inside it guarantees bounded exit time. *)
  Lwt.async (fun () ->
    Lwt.catch
      (fun () -> rpc_thread)
      (fun exn ->
        Logs.warn (fun m ->
          m "rpc_thread exited: %s" (Printexc.to_string exn));
        Lwt.return_unit));
  Lwt.async (fun () ->
    Lwt.catch
      (fun () -> status_thread)
      (fun exn ->
        Logs.warn (fun m ->
          m "status_thread exited: %s" (Printexc.to_string exn));
        Lwt.return_unit));
  Lwt.async (fun () ->
    Lwt.catch
      (fun () -> metrics_thread)
      (fun exn ->
        Logs.warn (fun m ->
          m "metrics_thread exited: %s" (Printexc.to_string exn));
        Lwt.return_unit));
  event_loop ()
