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

  (* Open RocksDB for the UTXO set — replaces LogStorage's lseek+read *)
  let rocksdb_path = Filename.concat config.data_dir "rocksdb_utxo" in
  let rocksdb = Rocksdb_store.open_db rocksdb_path in
  Logs.info (fun m -> m "Opened RocksDB UTXO store at %s" rocksdb_path);

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
    ~utxo:(Some optimized_utxo) () in

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
        if iv.inv_type = P2p.InvBlock
           && not (Storage.ChainDB.has_block db iv.hash) then
          Some { P2p.inv_type = P2p.InvBlock; hash = iv.hash }
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
      (match Sync.process_headers chain headers with
       | Ok n when n > 0 ->
         (* We accepted new headers - request the corresponding blocks *)
         let tip_height = match chain.tip with
           | Some t -> t.height | None -> 0 in
         let start_h = tip_height - n + 1 in
         let block_requests = ref [] in
         for h = start_h to tip_height do
           match Sync.get_header_at_height chain h with
           | Some entry ->
             if not (Storage.ChainDB.has_block db entry.hash) then
               block_requests :=
                 { P2p.inv_type = P2p.InvBlock; hash = entry.hash }
                 :: !block_requests
           | None -> ()
         done;
         if !block_requests <> [] then
           Peer.send_message peer (P2p.GetdataMsg (List.rev !block_requests))
         else
           Lwt.return_unit
       | _ -> Lwt.return_unit)
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
        let* () = Sync.sync_headers chain peer in
        Peer_manager.set_header_sync_active peer_manager false;
        Peer_manager.set_height peer_manager (Int32.of_int chain.headers_synced);
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
          ~on_ibd_created:(fun ibd -> ibd_state_ref := Some ibd)
          chain get_peers in
        (* Clear IBD state so post-IBD listeners take over *)
        ibd_state_ref := None;
        Lwt.return_unit
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
    (* Save fee estimation state *)
    (try
      Fee_estimation.save_to_file fee_estimator fee_est_path;
      Logs.info (fun m -> m "Saved fee estimation data to disk")
    with exn ->
      Logs.warn (fun m ->
        m "Failed to save fee estimates: %s" (Printexc.to_string exn)));
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
      Utxo.OptimizedUtxoSet.flush ~tip_height:chain.blocks_synced optimized_utxo;
      (* Also update chain_tip to match blocks_synced so that on restart
         the node resumes from the correct height (matching the flushed
         UTXO state rather than the last periodic flush point). *)
      let bs = chain.blocks_synced in
      (match Sync.get_header_at_height chain bs with
       | Some entry ->
         Storage.ChainDB.set_chain_tip db entry.hash bs
       | None -> ())
    end;
    (* Close RocksDB UTXO store *)
    Rocksdb_store.close rocksdb;
    Logs.info (fun m -> m "Closed RocksDB UTXO store");
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
  Lwt.join [
    rpc_thread;
    status_thread;
    event_loop ();
  ]
