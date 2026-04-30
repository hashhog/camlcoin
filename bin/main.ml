(* CamlCoin - Bitcoin Full Node in OCaml
   Command-line entry point using Cmdliner for argument parsing *)

open Cmdliner

(* ============================================================================
   Command-Line Arguments
   ============================================================================ *)

let network_arg =
  let doc = "Network to connect to (mainnet, testnet, regtest)." in
  let networks = Arg.enum [
    ("mainnet", `Mainnet);
    ("testnet", `Testnet);
    ("regtest", `Regtest);
  ] in
  Arg.(value & opt networks `Mainnet &
    info ["network"; "n"] ~docv:"NETWORK" ~doc)

let datadir_arg =
  let doc = "Data directory path." in
  Arg.(value & opt (some string) None &
    info ["datadir"; "d"] ~docv:"DIR" ~doc)

let rpc_host_arg =
  let doc = "RPC server host." in
  Arg.(value & opt string "127.0.0.1" &
    info ["rpchost"] ~docv:"HOST" ~doc)

let rpc_port_arg =
  let doc = "RPC server port." in
  Arg.(value & opt (some int) None &
    info ["rpcport"] ~docv:"PORT" ~doc)

let rpc_user_arg =
  let doc = "RPC username." in
  Arg.(value & opt string "camlcoin" &
    info ["rpcuser"] ~docv:"USER" ~doc)

let rpc_password_arg =
  let doc = "RPC password." in
  Arg.(value & opt string "camlcoin" &
    info ["rpcpassword"] ~docv:"PASS" ~doc)

let p2p_port_arg =
  let doc = "P2P network port." in
  Arg.(value & opt (some int) None &
    info ["port"; "p"] ~docv:"PORT" ~doc)

let max_outbound_arg =
  let doc = "Maximum outbound peer connections." in
  Arg.(value & opt int 8 &
    info ["maxoutbound"] ~docv:"N" ~doc)

let max_inbound_arg =
  let doc = "Maximum inbound peer connections." in
  Arg.(value & opt int 117 &
    info ["maxinbound"] ~docv:"N" ~doc)

let connect_arg =
  let doc = "Connect to specific peer (host:port or host). Can be specified multiple times." in
  Arg.(value & opt_all string [] &
    info ["connect"; "c"] ~docv:"ADDR" ~doc)

let debug_arg =
  let doc = "Enable debug logging." in
  Arg.(value & flag & info ["debug"] ~doc)

let no_wallet_arg =
  let doc = "Disable wallet functionality." in
  Arg.(value & flag & info ["disablewallet"] ~doc)

let prune_arg =
  let doc = "Prune old blocks to reduce disk usage. 0 = no pruning." in
  Arg.(value & opt int 0 &
    info ["prune"] ~docv:"SIZE" ~doc)

let benchmark_arg =
  let doc = "Run performance benchmarks and exit." in
  Arg.(value & flag & info ["benchmark"] ~doc)

let import_blocks_arg =
  let doc = "Import blocks from file (use '-' for stdin). Bypasses P2P entirely." in
  Arg.(value & opt (some string) None &
    info ["import-blocks"] ~docv:"PATH" ~doc)

let import_utxo_arg =
  let doc = "Import UTXO snapshot from HDOG file. Replaces existing UTXO set and sets chain tip." in
  Arg.(value & opt (some string) None &
    info ["import-utxo"] ~docv:"PATH" ~doc)

let metrics_port_arg =
  let doc = "Prometheus metrics port (0 to disable)." in
  Arg.(value & opt int 9332 &
    info ["metricsport"] ~docv:"PORT" ~doc)

let peer_bloom_filters_arg =
  let doc = "Advertise NODE_BLOOM (BIP-35 / BIP-111) and serve MEMPOOL \
             requests + bloom-filter setup messages. Defaults to false to \
             match Bitcoin Core's DEFAULT_PEERBLOOMFILTERS." in
  Arg.(value & opt bool false &
    info ["peerbloomfilters"] ~docv:"BOOL" ~doc)

let migrate_logstorage_arg =
  let doc = "Run the LogStorage -> RocksDB CF migration (Option D) and \
             exit. Streams every record from data.log into the RocksDB \
             chainstate-rocks/ column families and renames data.log to \
             data.log.pre-migration-bak on success. Idempotent: safe to \
             re-run after a crash. Operator-driven; never auto-runs." in
  Arg.(value & flag & info ["migrate-logstorage-to-rocksdb"] ~doc)

(* Operational flags: daemon, pid file, conf, debug categories, log file,
   printtoconsole, ready-fd. Mirrors Bitcoin Core's init.cpp surface. *)

let daemon_arg =
  let doc = "Fork to background after initialisation (double-fork + setsid). \
             stdio is redirected to /dev/null; use --logfile to capture log \
             output. PID is written via --pid (default <datadir>/camlcoin.pid)." in
  Arg.(value & flag & info ["daemon"] ~doc)

let pid_arg =
  let doc = "Path to write the camlcoin PID file. Defaults to \
             <datadir>/camlcoin.pid. The file is removed on graceful \
             shutdown. Refuses to start if the file already names a live \
             process." in
  Arg.(value & opt (some string) None &
    info ["pid"] ~docv:"PATH" ~doc)

let conf_arg =
  let doc = "Read additional options from a config file (Bitcoin Core \
             grammar: key=value, # comments, [section] headers). CLI values \
             win over config file values. Default: <datadir>/camlcoin.conf." in
  Arg.(value & opt (some string) None &
    info ["conf"] ~docv:"FILE" ~doc)

let debug_cat_arg =
  let doc = "Enable selective debug logging for one or more categories \
             (comma-separated, repeatable). Categories match the Logs.Src \
             registry (e.g. NET, RPC, MEMPOOL, VALIDATION, PEER, MINING, \
             WALLET, REST, PKG-RELAY). Special values: 'all' / '1' enable \
             everything; 'none' / '0' disable everything." in
  Arg.(value & opt_all string [] &
    info ["debug-cat"] ~docv:"CAT" ~doc)

let logfile_arg =
  let doc = "Write logs to a file in addition to (or instead of) stderr. \
             SIGHUP closes and reopens the file for log rotation." in
  Arg.(value & opt (some string) None &
    info ["logfile"] ~docv:"PATH" ~doc)

let printtoconsole_arg =
  let doc = "Force log output to stderr even when --logfile is set. \
             Without --logfile this is the default and the flag is a no-op. \
             Mirrors Bitcoin Core's -printtoconsole." in
  Arg.(value & opt (some bool) None &
    info ["printtoconsole"] ~docv:"BOOL" ~doc)

let ready_fd_arg =
  let doc = "Write a single byte to file descriptor N once initialisation \
             is complete (RPC bound, peer manager started). The fd is then \
             closed. Useful for systemd-style READY signalling without \
             dbus." in
  Arg.(value & opt (some int) None &
    info ["ready-fd"] ~docv:"N" ~doc)

let zmq_pub_arg =
  let doc = "ZMQ publish endpoint in Bitcoin Core syntax: \
             '-zmqpub<topic>=<addr>'. Topics: hashblock, hashtx, rawblock, \
             rawtx, sequence (and 'pub<topic>' aliases). Address is a ZMQ \
             URL such as 'tcp://127.0.0.1:28332'. Repeatable; each call \
             may target a different topic and/or endpoint. Multiple topics \
             on the same endpoint are bound to one PUB socket." in
  Arg.(value & opt_all string [] &
    info ["zmqpub"] ~docv:"OPT" ~doc)

let reindex_arg =
  let doc = "Wipe and rebuild the chainstate (UTXO + chain_state + \
             undo_data column families plus the rocksdb_utxo store). \
             Headers, block bodies, and the height->hash mapping are \
             retained on disk; every stored block is then re-validated \
             from height 0 forward to rebuild the UTXO set. Use after \
             on-disk corruption of the UTXO set, after a consensus \
             upgrade that requires re-validation, or to recover from a \
             half-written chainstate. The daemon then continues into \
             normal IBD / FullySynced operation. Mirrors Bitcoin Core's \
             '-reindex' (init.cpp + validation.cpp)." in
  Arg.(value & flag & info ["reindex"] ~doc)

(* ============================================================================
   Main Command
   ============================================================================ *)

let run_cmd network datadir rpc_host rpc_port rpc_user rpc_password
    p2p_port max_outbound max_inbound connect debug no_wallet prune benchmark
    import_blocks import_utxo metrics_port peer_bloom_filters
    migrate_logstorage daemon_mode pid_path conf_path debug_cats
    logfile printtoconsole ready_fd zmq_pub reindex =
  (* Resolve datadir early so config-file lookup can default to it. *)
  let base = Camlcoin.Cli.config_for_network network in
  let resolved_datadir = match datadir with
    | Some d -> d
    | None -> base.data_dir in
  (* Load config file. CLI wins over conf, conf wins over hard-coded defaults. *)
  let conf_path_resolved = match conf_path with
    | Some p -> p
    | None -> Filename.concat resolved_datadir "camlcoin.conf" in
  let conf_opts =
    try Camlcoin.Runtime_config.parse_conf_file ~network conf_path_resolved
    with _ -> [] in
  (* Resolve effective values: CLI > conf > hard-coded base defaults. *)
  let eff_rpc_host =
    Camlcoin.Runtime_config.overlay_string
      ~cli:(if rpc_host = "127.0.0.1" then None else Some rpc_host)
      ~conf:(Camlcoin.Runtime_config.get_string conf_opts "rpchost")
      ~default:rpc_host in
  let eff_rpc_user =
    Camlcoin.Runtime_config.overlay_string
      ~cli:(if rpc_user = "camlcoin" then None else Some rpc_user)
      ~conf:(Camlcoin.Runtime_config.get_string conf_opts "rpcuser")
      ~default:rpc_user in
  let eff_rpc_password =
    Camlcoin.Runtime_config.overlay_string
      ~cli:(if rpc_password = "camlcoin" then None else Some rpc_password)
      ~conf:(Camlcoin.Runtime_config.get_string conf_opts "rpcpassword")
      ~default:rpc_password in
  let eff_max_outbound =
    Camlcoin.Runtime_config.overlay_int
      ~cli:(if max_outbound = 8 then None else Some max_outbound)
      ~conf:(Camlcoin.Runtime_config.get_int conf_opts "maxoutbound")
      ~default:max_outbound in
  let eff_max_inbound =
    Camlcoin.Runtime_config.overlay_int
      ~cli:(if max_inbound = 117 then None else Some max_inbound)
      ~conf:(Camlcoin.Runtime_config.get_int conf_opts "maxinbound")
      ~default:max_inbound in
  let eff_prune =
    Camlcoin.Runtime_config.overlay_int
      ~cli:(if prune = 0 then None else Some prune)
      ~conf:(Camlcoin.Runtime_config.get_int conf_opts "prune")
      ~default:prune in
  let eff_metrics_port =
    Camlcoin.Runtime_config.overlay_int
      ~cli:(if metrics_port = 9332 then None else Some metrics_port)
      ~conf:(Camlcoin.Runtime_config.get_int conf_opts "metricsport")
      ~default:metrics_port in
  let eff_peer_bloom =
    Camlcoin.Runtime_config.overlay_bool
      ~cli_set:false ~cli_value:peer_bloom_filters
      ~conf:(Camlcoin.Runtime_config.get_bool conf_opts "peerbloomfilters")
      ~default:peer_bloom_filters in
  let eff_debug_cats =
    let cli = debug_cats in
    let from_conf =
      match Camlcoin.Runtime_config.get_string conf_opts "debug" with
      | Some v -> [v]
      | None -> [] in
    Camlcoin.Runtime_config.resolve_debug_categories (cli @ from_conf) in
  let eff_logfile = match logfile with
    | Some p -> Some p
    | None -> Camlcoin.Runtime_config.get_string conf_opts "logfile" in
  let eff_printtoconsole = match printtoconsole with
    | Some b -> b
    | None ->
      (match Camlcoin.Runtime_config.get_bool conf_opts "printtoconsole" with
       | Some b -> b
       | None -> eff_logfile = None) in
  let eff_pid_path = match pid_path with
    | Some p -> p
    | None ->
      (match Camlcoin.Runtime_config.get_string conf_opts "pid" with
       | Some p -> p
       | None -> Filename.concat resolved_datadir "camlcoin.pid") in
  let eff_daemon =
    daemon_mode
    || (match Camlcoin.Runtime_config.get_bool conf_opts "daemon" with
        | Some b -> b | None -> false) in
  let eff_ready_fd = ready_fd in
  let install_log_reporter () =
    match eff_logfile with
    | None -> () (* default cli.ml setup_logging installs Logs_fmt *)
    | Some path ->
      Camlcoin.Runtime_config.install_log_file_reporter
        ~also_console:eff_printtoconsole path
  in
  (* If migrate-logstorage flag is set, run the migration and exit. *)
  if migrate_logstorage then begin
    Camlcoin.Cli.setup_logging debug ();
    install_log_reporter ();
    let chainstate_dir = Filename.concat resolved_datadir "chainstate" in
    let rc = Camlcoin.Migration.run ~chainstate_dir in
    exit rc
  end else
  (* If benchmark flag is set, run benchmarks and exit *)
  if benchmark then begin
    Camlcoin.Cli.setup_logging debug ();
    Camlcoin.Perf.run_benchmarks ();
    ()
  end else match import_utxo with
  | Some utxo_path ->
    (* UTXO snapshot import mode *)
    Camlcoin.Cli.setup_logging debug ();
    let base = Camlcoin.Cli.config_for_network network in
    let data_dir = match datadir with
      | Some d -> d
      | None -> base.data_dir in
    (try Unix.mkdir data_dir 0o755
     with Unix.Unix_error (Unix.EEXIST, _, _) -> ());
    let network_cfg = match network with
      | `Mainnet -> Camlcoin.Consensus.mainnet
      | `Testnet -> Camlcoin.Consensus.testnet4
      | `Regtest -> Camlcoin.Consensus.regtest
    in
    (match Camlcoin.Utxo_import.run ~snapshot_path:utxo_path
             ~data_dir ~network:network_cfg with
    | Ok count ->
      Printf.eprintf "Successfully imported %d UTXOs\n%!" count
    | Error msg ->
      Printf.eprintf "UTXO import failed: %s\n%!" msg;
      exit 1)
  | None ->
  match import_blocks with
  | Some import_path ->
    (* Block import mode: bypass P2P entirely *)
    Camlcoin.Cli.setup_logging debug ();
    let base = Camlcoin.Cli.config_for_network network in
    let data_dir = match datadir with
      | Some d -> d
      | None -> base.data_dir in
    (try Unix.mkdir data_dir 0o755
     with Unix.Unix_error (Unix.EEXIST, _, _) -> ());
    let network_cfg = match network with
      | `Mainnet -> Camlcoin.Consensus.mainnet
      | `Testnet -> Camlcoin.Consensus.testnet4
      | `Regtest -> Camlcoin.Consensus.regtest
    in
    let db_path = Filename.concat data_dir "chainstate" in
    let db = Camlcoin.Storage.ChainDB.create db_path in
    let chain = Camlcoin.Sync.restore_chain_state db network_cfg in
    let rocksdb_path = Filename.concat data_dir "rocksdb_utxo" in
    let rocksdb = Camlcoin.Rocksdb_store.open_db rocksdb_path in
    (* Consistency check: reset blocks_synced if RocksDB was wiped *)
    if chain.blocks_synced > 0 then begin
      match Camlcoin.Rocksdb_store.get_tip_height rocksdb with
      | None ->
        Printf.eprintf "WARNING: RocksDB has no tip height but chain_tip=%d — resetting to 0\n%!"
          chain.blocks_synced;
        chain.blocks_synced <- 0;
        Camlcoin.Storage.ChainDB.set_chain_tip db (Cstruct.create 32) 0
      | Some rdb_h when rdb_h < chain.blocks_synced ->
        Printf.eprintf "WARNING: RocksDB tip (%d) < chain_tip (%d) — resetting\n%!"
          rdb_h chain.blocks_synced;
        chain.blocks_synced <- rdb_h
      | Some _ -> ()
    end;
    let utxo = Camlcoin.Utxo.OptimizedUtxoSet.create
      ~cache_size:2_000_000 ~rocksdb db in
    let ic = if import_path = "-" then stdin
             else open_in_bin import_path in
    Printf.eprintf "CamlCoin import: reading blocks from %s\n%!"
      (if import_path = "-" then "stdin" else import_path);
    let count = Camlcoin.Block_import.run ~ic ~db ~chain
      ~network:network_cfg ~utxo () in
    if import_path <> "-" then close_in ic;
    Camlcoin.Rocksdb_store.close rocksdb;
    Camlcoin.Storage.ChainDB.close db;
    Printf.eprintf "Done: imported %d blocks\n%!" count
  | None ->
  begin
    let conf_rpc_port = Camlcoin.Runtime_config.get_int conf_opts "rpcport" in
    let conf_p2p_port = Camlcoin.Runtime_config.get_int conf_opts "port" in
    let conf_connect = Camlcoin.Runtime_config.get_all conf_opts "connect" in
    let config : Camlcoin.Cli.config = {
      network;
      data_dir = resolved_datadir;
      rpc_host = eff_rpc_host;
      rpc_port = (match rpc_port with
        | Some p -> p
        | None -> (match conf_rpc_port with
          | Some p -> p | None -> base.rpc_port));
      rpc_user = eff_rpc_user;
      rpc_password = eff_rpc_password;
      p2p_port = (match p2p_port with
        | Some p -> p
        | None -> (match conf_p2p_port with
          | Some p -> p | None -> base.p2p_port));
      max_outbound = eff_max_outbound;
      max_inbound = eff_max_inbound;
      connect = (if connect <> [] then connect else conf_connect);
      debug;
      wallet_enabled = not no_wallet;
      prune = eff_prune;
      log_categories = eff_debug_cats;
      metrics_port = eff_metrics_port;
      peer_bloom_filters = eff_peer_bloom;
      zmq_pub_options = (
        (* The cmdliner option strips the leading flag; users typed
           '--zmqpub=rawblock=tcp://...' so what we see is
           'rawblock=tcp://...'. Re-attach the '-zmqpub' prefix so
           parse_zmq_option (which understands the Bitcoin-Core
           '-zmqpubrawblock=tcp://...' grammar) accepts it. *)
        let cli_norm = List.map (fun s -> "-zmqpub" ^ s) zmq_pub in
        let from_conf =
          Camlcoin.Runtime_config.get_all conf_opts "zmqpub"
          |> List.map (fun s -> "-zmqpub" ^ s)
        in
        cli_norm @ from_conf);
      reindex =
        reindex
        || (match Camlcoin.Runtime_config.get_bool conf_opts "reindex" with
            | Some b -> b | None -> false);
    } in
    (* Ensure datadir exists so we can land the PID file there. *)
    (try Unix.mkdir resolved_datadir 0o755
     with Unix.Unix_error (Unix.EEXIST, _, _) -> ());
    (* Daemonize BEFORE Lwt_main.run; Lwt_engine state does not survive a
       fork. After this returns we are the grandchild, detached from any
       controlling terminal. *)
    if eff_daemon then Camlcoin.Runtime_config.daemonize ();
    (* PID file: write our (post-daemonize) PID. Refuses to start if the
       file already names a live process. *)
    (match Camlcoin.Runtime_config.write_pid_file eff_pid_path with
     | Ok () -> ()
     | Error msg ->
       Printf.eprintf "[camlcoin] %s\n%!" msg;
       exit 1);
    (* Install file-based log reporter if --logfile was set. Must run AFTER
       daemonize so the file descriptor isn't lost across the fork. *)
    (match eff_logfile with
     | None -> ()
     | Some path ->
       Camlcoin.Runtime_config.install_log_file_reporter
         ~also_console:eff_printtoconsole path);
    (* SIGHUP triggers a log reopen on the next status-thread tick. *)
    Camlcoin.Runtime_config.install_sighup_handler ();
    (* W78: install an async-exception hook that logs instead of terminating.
       The default hook calls exit 2 on any exception from an Lwt.async
       continuation — a Stack_overflow in one peer-rotation callback would
       kill the whole node (observed 2026-04-19 17:31 at height 382545).
       We log the exception + backtrace and keep the node running; the
       next scheduled operation will recover.  Add a distinctive prefix so
       these lines are easy to find in post-mortem grep. *)
    Printexc.record_backtrace true;
    Lwt.async_exception_hook := (fun exn ->
      Printf.eprintf "[W78-ASYNC-EXN] uncaught exception in Lwt.async: %s\n%s\n%!"
        (Printexc.to_string exn)
        (Printexc.get_backtrace ())
    );
    Lwt_main.run (Camlcoin.Cli.run ?ready_fd:eff_ready_fd config);
    (* Graceful shutdown complete: exit 0 deterministically.  The 30s
       watchdog inside Cli.run will have already called exit 1 if the
       graceful path stalled, so reaching this point means success. *)
    Camlcoin.Runtime_config.remove_pid_file ();
    exit 0
  end

let cmd =
  let doc = "CamlCoin - Bitcoin full node implemented in OCaml" in
  let man = [
    `S Manpage.s_description;
    `P "CamlCoin is a Bitcoin full node implementation in OCaml. It uses \
        algebraic data types for protocol structures, pattern matching for \
        opcode dispatch, and Lwt for async I/O.";
    `S Manpage.s_examples;
    `P "Run on mainnet:";
    `Pre "  camlcoin";
    `P "Run on testnet with debug logging:";
    `Pre "  camlcoin --network testnet --debug";
    `P "Run on regtest and connect to a specific peer:";
    `Pre "  camlcoin --network regtest --connect 127.0.0.1:18444";
    `P "Run performance benchmarks:";
    `Pre "  camlcoin --benchmark";
    `S Manpage.s_bugs;
    `P "Report bugs at https://github.com/camlcoin/camlcoin/issues";
  ] in
  let info = Cmd.info "camlcoin"
    ~version:Camlcoin.Types.version
    ~doc
    ~man in
  Cmd.v info Term.(const run_cmd
    $ network_arg
    $ datadir_arg
    $ rpc_host_arg
    $ rpc_port_arg
    $ rpc_user_arg
    $ rpc_password_arg
    $ p2p_port_arg
    $ max_outbound_arg
    $ max_inbound_arg
    $ connect_arg
    $ debug_arg
    $ no_wallet_arg
    $ prune_arg
    $ benchmark_arg
    $ import_blocks_arg
    $ import_utxo_arg
    $ metrics_port_arg
    $ peer_bloom_filters_arg
    $ migrate_logstorage_arg
    $ daemon_arg
    $ pid_arg
    $ conf_arg
    $ debug_cat_arg
    $ logfile_arg
    $ printtoconsole_arg
    $ ready_fd_arg
    $ zmq_pub_arg
    $ reindex_arg)

(* ============================================================================
   Entry Point
   ============================================================================ *)

let () =
  (* Tune the OCaml GC for a large-heap server process.
     - minor_heap_size: 4M words (32MB) reduces minor collections during
       block validation which allocates many short-lived Cstruct/string values.
     - space_overhead: 200 (default 120) lets the major heap grow 2x before
       collecting, reducing major GC frequency at the cost of ~2x peak RSS.
       With 128GB RAM this is a good trade.
     - max_overhead: 500 means compaction only triggers when free space exceeds
       5x live data, effectively disabling it (we use Gc.major() explicitly). *)
  let gc = Gc.get () in
  Gc.set { gc with
    minor_heap_size = 4 * 1024 * 1024;
    space_overhead = 200;
    max_overhead = 500;
  };
  exit (Cmd.eval cmd)
