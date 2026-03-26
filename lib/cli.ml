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

let setup_logging (debug : bool) ?(categories : string list = []) () : unit =
  Fmt_tty.setup_std_outputs ();
  let default_level = if debug then Logs.Debug else Logs.Info in
  Logs.set_level (Some default_level);
  Logs.set_reporter (Logs_fmt.reporter ());
  if categories <> [] then
    List.iter (fun src ->
      let name = Logs.Src.name src in
      if not (List.mem (String.uppercase_ascii name)
                (List.map String.uppercase_ascii categories)) then
        Logs.Src.set_level src (Some Logs.Warning)
    ) (Logs.Src.list ())

(* ============================================================================
   Main Application Run Loop
   ============================================================================ *)

let run (config : config) : unit Lwt.t =
  let open Lwt.Syntax in

  setup_logging config.debug ~categories:config.log_categories ();

  Logs.info (fun m ->
    m "CamlCoin v%s starting on %s"
      Types.version
      (match config.network with
       | `Mainnet -> "mainnet"
       | `Testnet -> "testnet"
       | `Regtest -> "regtest"));

  (* Ensure data directory exists *)
  (try Unix.mkdir config.data_dir 0o755
   with Unix.Unix_error (Unix.EEXIST, _, _) -> ());

  (* Initialize database *)
  let db_path = Filename.concat config.data_dir "chainstate" in
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

  (* Optimized UTXO set for IBD – dirty entries are flushed periodically
     during block download and must be flushed on shutdown to avoid loss. *)
  let optimized_utxo = Utxo.OptimizedUtxoSet.create db in

  (* Initialize mempool *)
  let current_height = match chain.tip with
    | Some t -> t.height
    | None -> 0
  in
  let mempool = Mempool.create ~utxo ~current_height () in

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
    ~wallet ~fee_estimator ~network () in

  (* Set up signal handlers for graceful shutdown.
     We use Lwt_unix.on_signal so that the signal wakes the Lwt event loop
     rather than racing with it from an OCaml signal handler. *)
  let shutdown_wakener, shutdown_waiter =
    let (w, u) = Lwt.wait () in (u, w) in
  let shutdown = ref false in
  let _sig_int = Lwt_unix.on_signal Sys.sigint (fun _signum ->
    if not !shutdown then begin
      Logs.info (fun m -> m "Received SIGINT, initiating graceful shutdown");
      shutdown := true;
      Lwt.wakeup_later shutdown_wakener ()
    end) in
  let _sig_term = Lwt_unix.on_signal Sys.sigterm (fun _signum ->
    if not !shutdown then begin
      Logs.info (fun m -> m "Received SIGTERM, initiating graceful shutdown");
      shutdown := true;
      Lwt.wakeup_later shutdown_wakener ()
    end) in

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
  in

  (* Start peer manager *)
  let peer_thread =
    Logs.info (fun m -> m "Starting peer manager");
    Peer_manager.start peer_manager
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
    let* first_peer = wait_for_peer 0 in
    match first_peer with
    | None -> Lwt.return_unit
    | Some peer ->
      Logs.info (fun m ->
        m "Starting header sync with peer %d" peer.Peer.id);
      let* () = Sync.sync_headers chain peer in
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
        Sync.start_ibd ~utxo_set:optimized_utxo
          ~misbehavior_handler
          ~on_ibd_created:(fun ibd -> ibd_state_ref := Some ibd)
          chain get_peers
      end else
        Lwt.return_unit
  in

  (* Periodic status logging *)
  let status_thread =
    let rec log_status () =
      if !shutdown then Lwt.return_unit
      else begin
        let* () = Lwt_unix.sleep 30.0 in
        if not !shutdown then begin
          let peer_count = Peer_manager.peer_count peer_manager in
          let ready_count = Peer_manager.ready_peer_count peer_manager in
          let height = match chain.tip with
            | Some t -> t.height
            | None -> 0
          in
          let (mp_count, mp_weight, _) = Mempool.get_info mempool in
          (* Keep peer_manager's our_height in sync with validated block height
             so that the stale-tip check knows our actual progress. *)
          let block_height = chain.blocks_synced in
          let prev_height = Peer_manager.get_height peer_manager in
          if Int32.of_int block_height > prev_height then begin
            Peer_manager.set_height peer_manager (Int32.of_int block_height);
            Peer_manager.notify_tip_updated peer_manager
          end;
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

  (* Graceful shutdown procedure: flush all pending state to disk *)
  let graceful_shutdown () =
    Logs.info (fun m -> m "Shutting down...");
    let* () = Peer_manager.stop peer_manager in
    (* Save wallet state *)
    (match wallet with
     | Some w -> Wallet.save w
     | None -> ());
    (* Save mempool to disk *)
    (try
      let mempool_path = Filename.concat config.data_dir "mempool.dat" in
      Mempool.save_mempool mempool mempool_path;
      let (mp_count, _, _) = Mempool.get_info mempool in
      Logs.info (fun m -> m "Saved %d mempool transactions to disk" mp_count)
    with exn ->
      Logs.warn (fun m ->
        m "Failed to save mempool: %s" (Printexc.to_string exn)));
    (* Save peer bans to disk *)
    (try
      Peer_manager.save_bans peer_manager db;
      Logs.info (fun m -> m "Saved peer bans to disk")
    with exn ->
      Logs.warn (fun m ->
        m "Failed to save bans: %s" (Printexc.to_string exn)));
    (* Flush pending UTXO updates from OptimizedUtxoSet *)
    let dirty = Utxo.OptimizedUtxoSet.dirty_count optimized_utxo in
    if dirty > 0 then begin
      Logs.info (fun m -> m "Flushing %d dirty UTXO entries to disk" dirty);
      Utxo.OptimizedUtxoSet.flush optimized_utxo;
      (* Also update chain_tip to match blocks_synced so that on restart
         the node resumes from the correct height (matching the flushed
         UTXO state rather than the last periodic flush point). *)
      let bs = chain.blocks_synced in
      (match Sync.get_header_at_height chain bs with
       | Some entry ->
         Storage.ChainDB.set_chain_tip db entry.hash bs
       | None -> ())
    end;
    (* Sync database to ensure all cached data is persisted *)
    Storage.ChainDB.sync db;
    Storage.ChainDB.close db;
    Logs.info (fun m -> m "Shutdown complete");
    Lwt.return_unit
  in

  (* Main event loop - waits for shutdown signal *)
  let event_loop () =
    let* () = shutdown_waiter in
    graceful_shutdown ()
  in

  (* Run all services concurrently.  Several of the service threads
     (peer_thread, sync_thread, manual_connect_thread) complete quickly after
     initial setup – they must NOT cause the node to exit.  We use Lwt.async
     for fire-and-forget background work and Lwt.join for the threads that
     should keep running until shutdown. *)
  Lwt.async (fun () -> manual_connect_thread);
  Lwt.async (fun () -> peer_thread);
  Lwt.async (fun () -> sync_thread);
  Lwt.join [
    rpc_thread;
    status_thread;
    event_loop ();
  ]
