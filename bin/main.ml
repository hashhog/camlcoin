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

(* ============================================================================
   Main Command
   ============================================================================ *)

let run_cmd network datadir rpc_host rpc_port rpc_user rpc_password
    p2p_port max_outbound max_inbound connect debug no_wallet prune benchmark
    import_blocks import_utxo =
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
    let base = Camlcoin.Cli.config_for_network network in
    let config : Camlcoin.Cli.config = {
      network;
      data_dir = (match datadir with
        | Some d -> d
        | None -> base.data_dir);
      rpc_host;
      rpc_port = (match rpc_port with
        | Some p -> p
        | None -> base.rpc_port);
      rpc_user;
      rpc_password;
      p2p_port = (match p2p_port with
        | Some p -> p
        | None -> base.p2p_port);
      max_outbound;
      max_inbound;
      connect;
      debug;
      wallet_enabled = not no_wallet;
      prune;
      log_categories = [];
    } in
    Lwt_main.run (Camlcoin.Cli.run config)
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
    $ import_utxo_arg)

(* ============================================================================
   Entry Point
   ============================================================================ *)

let () = exit (Cmd.eval cmd)
