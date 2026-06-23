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
  let doc = "Connect to specific peer (host:port or host). Can be specified \
             multiple times. Like Bitcoin Core -connect, this pins the node \
             to ONLY these peers and disables DNS-seed resolution and \
             addrman/auto-outbound dialing." in
  Arg.(value & opt_all string [] &
    info ["connect"; "c"] ~docv:"ADDR" ~doc)

let no_dnsseed_arg =
  let doc = "Disable DNS seed resolution (Bitcoin Core -nodnsseed / \
             -dnsseed=0). Independent of --connect: suppresses only DNS \
             while leaving addrman / fallback outbound dialing on." in
  Arg.(value & flag & info ["nodnsseed"] ~doc)

let debug_arg =
  let doc = "Enable debug logging." in
  Arg.(value & flag & info ["debug"] ~doc)

let no_wallet_arg =
  let doc = "Disable wallet functionality." in
  Arg.(value & flag & info ["disablewallet"] ~doc)

let prune_arg =
  (* Bitcoin Core --prune semantics (init.cpp:524):
       0      = pruning disabled
       1      = manual mode (only RPC pruneblockchain triggers; no auto-prune)
       >= 550 = automatic prune target in MiB (550 MiB minimum)
       2..549 = rejected as below floor *)
  let doc = "Reduce storage requirements by enabling pruning (deleting) of \
             old blocks. This allows the pruneblockchain RPC to be called to \
             delete specific blocks and enables automatic pruning of old \
             blocks if a target size in MiB is provided. \
             0 = disable pruning blocks, 1 = allow manual pruning via RPC, \
             >=550 = automatically prune block files to stay under the \
             specified target size in MiB." in
  Arg.(value & opt int 0 &
    info ["prune"] ~docv:"MIB" ~doc)

let benchmark_arg =
  let doc = "Run performance benchmarks and exit." in
  Arg.(value & flag & info ["benchmark"] ~doc)

let import_blocks_arg =
  let doc = "Import blocks from file (use '-' for stdin). Bypasses P2P entirely." in
  Arg.(value & opt (some string) None &
    info ["import-blocks"] ~docv:"PATH" ~doc)

let import_utxo_arg =
  (* cmdliner treats unescaped '$' and '\\' specially in doc strings, so
     the wire-format magic 'utxo<0xff>' and the path '<datadir>/...'
     are written without those characters. *)
  let doc = "Bootstrap from a Bitcoin Core dumptxoutset (UTXO snapshot) and \
             then forward-sync. The file MUST be in Core wire format \
             (magic bytes 'utxo' followed by 0xff, version 2, \
             ScriptCompression-encoded coins). The base blockhash and \
             coin count are checked against camlcoin's hardcoded \
             AssumeUTXO parameters before any coin is loaded; mismatches \
             fail fast. The snapshot UTXO set is written into the PRIMARY \
             chainstate (the running node's UTXO store), the validated \
             chain tip is set to the snapshot base height, and the node \
             then continues into normal P2P header sync + forward block \
             download from the base height onward. Only acted on when the \
             chainstate is fresh (height 0); over an existing tip the flag \
             is ignored and the existing chainstate is used. Without the \
             flag, sync proceeds from genesis as before. The historical \
             alias '--load-snapshot' is also accepted." in
  Arg.(value & opt (some string) None &
    info ["import-utxo"; "load-snapshot"] ~docv:"PATH" ~doc)

let metrics_port_arg =
  let doc = "Prometheus metrics port (0 to disable)." in
  Arg.(value & opt int 9332 &
    info ["metricsport"] ~docv:"PORT" ~doc)

let dbcache_arg =
  (* PERF/config only — NOT consensus. Sizes the in-memory OptimizedUtxoSet
     LRU (entries) that fronts RocksDB during IBD. *)
  let doc = "UTXO LRU cache entries (default 4000000; PERF/IBD-opt-in only \
             — raising it enlarges the heap & GC pauses; camlcoin is \
             loopback-pinned). This is a pure read cache over the \
             authoritative RocksDB UTXO store and changes IBD speed only, \
             never any validation result. Omitting the flag keeps the \
             4000000-entry (~1 GB) default. WARNING: 8000000 has been \
             observed to push RSS past 12 GB; raise only for an IBD run, \
             watch RSS, and return to the default for steady-state." in
  Arg.(value & opt (some int) None &
    info ["dbcache"] ~docv:"ENTRIES" ~doc)

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

let rest_arg =
  let doc = "Enable the public REST HTTP server (read-only \
             /rest/block, /rest/tx, /rest/headers, /rest/chaininfo, \
             /rest/mempool/{info,contents}, /rest/blockhashbyheight, \
             /rest/blockfilter, /rest/blockfilterheaders endpoints). \
             Default: off, matching Bitcoin Core's DEFAULT_REST_ENABLE \
             (init.cpp:153)." in
  Arg.(value & flag & info ["rest"] ~doc)

let rest_port_arg =
  let doc = "Port for the REST HTTP server when --rest is set. \
             Defaults to the same port as --rpcport, mirroring Bitcoin \
             Core's behavior of mounting REST handlers on the JSON-RPC \
             listener. A separate port can be set if a deployment \
             prefers physical isolation between the authenticated RPC \
             surface and the public REST surface." in
  Arg.(value & opt (some int) None &
    info ["restport"] ~docv:"PORT" ~doc)

let rest_bind_arg =
  let doc = "Bind address for the REST HTTP server. Defaults to \
             --rpchost (127.0.0.1). Use 0.0.0.0 to expose REST publicly; \
             never combine that with --rpcallowip-style relaxation." in
  Arg.(value & opt (some string) None &
    info ["restbind"] ~docv:"HOST" ~doc)

let blockfilterindex_arg =
  (* Bitcoin Core's -blockfilterindex flag (init.cpp / index/blockfilterindex.cpp).
     Accepts either a boolean ('1'/'0' / 'true'/'false') or the literal
     filter type 'basic' — both enable the basic (BIP-158) filter index.
     Anything else is rejected at runtime with a clear error. Default is
     off, matching DEFAULT_BLOCKFILTERINDEX in Core. *)
  let doc = "Maintain a BIP-157/158 basic block filter index at \
             <datadir>/indexes/blockfilter/basic. Required for \
             /rest/blockfilter and /rest/blockfilterheaders to serve \
             actual filters; without this flag the REST endpoints \
             return Core's exact 400 'Index is not enabled for \
             filtertype basic'. On startup, any gap between the \
             index's last-known-height and the validated chain tip \
             is back-filled by re-reading stored blocks + undo data. \
             Accepted values: '0' / 'false' (off, default), \
             '1' / 'true' / 'basic' (on)." in
  Arg.(value & opt (some string) None &
    info ["blockfilterindex"] ~docv:"VAL" ~doc)

let coinstatsindex_arg =
  (* Bitcoin Core's -coinstatsindex flag (init.cpp / index/coinstatsindex.cpp).
     Accepts a boolean ('1'/'0' / 'true'/'false'). When on, the daemon
     maintains a per-height running MuHash3072 + UTXO counts index at
     <datadir>/indexes/coinstats, updated on every block
     connect/disconnect/reorg, so [gettxoutsetinfo "hash_type" <height>]
     can answer for a HISTORICAL height byte-exactly versus Core. Default
     off, matching DEFAULT_COINSTATSINDEX. *)
  let doc = "Maintain a per-height UTXO-set MuHash3072 + counts index at \
             <datadir>/indexes/coinstats. Required for \
             gettxoutsetinfo at a historical hash_or_height; without it a \
             non-tip query returns Core's exact -8 'Querying specific block \
             heights requires coinstatsindex'. On startup any gap to the \
             validated tip is back-filled from stored blocks + undo data. \
             Accepted values: '0' / 'false' (off, default), \
             '1' / 'true' (on)." in
  Arg.(value & opt (some string) None &
    info ["coinstatsindex"] ~docv:"VAL" ~doc)

let txindex_arg =
  (* Bitcoin Core's -txindex flag (init.cpp / index/txindex.cpp).
     camlcoin maintains the txid -> (block_hash, index) mapping
     unconditionally on every block connect (Sync.tx_index_write_for_block),
     so there is no separate enable path — this flag is ACCEPTED for CLI
     compatibility (Core operators and tooling pass -txindex=1 alongside
     -coinstatsindex=1) and is otherwise a no-op. Default off (the index is
     present regardless). *)
  let doc = "Accepted for Bitcoin Core CLI compatibility. camlcoin always \
             maintains the transaction index (getrawtransaction works \
             without this flag), so this option is a no-op. \
             Accepted values: '0' / 'false' / '1' / 'true'." in
  Arg.(value & opt (some string) None &
    info ["txindex"] ~docv:"VAL" ~doc)

let txospenderindex_arg =
  (* Bitcoin Core's -txospenderindex flag (init.cpp /
     index/txospenderindex.cpp).  Accepts a boolean ('1'/'0' /
     'true'/'false'). When on, the daemon maintains a [spent outpoint ->
     spending tx] index at <datadir>/indexes/txospender, updated on every
     block connect/disconnect/reorg, so [gettxspendingprevout] can resolve a
     CONFIRMED spend (and report its blockhash) — not only mempool spends.
     Default off, matching DEFAULT_TXOSPENDERINDEX. *)
  let doc = "Maintain a spent-outpoint -> spending-transaction index at \
             <datadir>/indexes/txospender. Required for \
             gettxspendingprevout to resolve a CONFIRMED (on-chain) spend; \
             without it a non-mempool query throws Core's exact 'Mempool \
             lacks a relevant spend, and txospenderindex is unavailable.' \
             On startup any gap to the validated tip is back-filled from \
             stored blocks. Accepted values: '0' / 'false' (off, default), \
             '1' / 'true' (on)." in
  Arg.(value & opt (some string) None &
    info ["txospenderindex"] ~docv:"VAL" ~doc)

let asmap_arg =
  (* Bitcoin Core's -asmap=<file> flag (init.cpp).
     When set, IP addresses are looked up in the ASMap binary trie and
     bucketed by their Autonomous System Number (ASN) in AddrMan instead
     of by /16 netgroup.  Improves eclipse-attack resistance by ensuring
     outbound connections span multiple autonomous systems.
     The file must pass SanityCheckAsmap (128-bit trie validation) or
     the flag is silently ignored (same behaviour as Core). *)
  let doc = "Use a precomputed ASMap binary file (IP-to-ASN mapping) for \
             peer bucketing. When set, AddrMan groups peers by Autonomous \
             System Number (ASN) instead of /16 netgroup, improving eclipse \
             resistance. The file must be a valid 128-bit ASMap binary \
             (as produced by contrib/seeds/makeseeds.py or \
             https://github.com/sipa/asmap). Default: off." in
  Arg.(value & opt (some string) None &
    info ["asmap"] ~docv:"FILE" ~doc)

(* W117 BUG-2 fix (FIX-56): outbound proxy / overlay routing flags. *)
let proxy_arg =
  let doc = "Default SOCKS5 proxy for outbound TCP dials. Accepts either \
             a bare 'host:port' string (Bitcoin Core syntax) or a full \
             'socks5://host:port' / 'socks5://user:pass@host:port' URL. \
             Used for IPv4/IPv6 peers and (when --onion is not set) for \
             .onion peers too. Default: off (direct clearnet \
             connections). Mirrors Bitcoin Core's -proxy flag." in
  Arg.(value & opt (some string) None &
    info ["proxy"] ~docv:"HOST:PORT" ~doc)

let onion_arg =
  let doc = "Dedicated SOCKS5 proxy for .onion (Tor v3) hidden-service \
             dials. When set, overrides --proxy for .onion routing and \
             enables Tor stream-isolation (random SOCKS5 credentials per \
             circuit). Accepts 'host:port' or 'socks5://...'. Default: \
             off (.onion dials use the --proxy default; if neither flag \
             is set, .onion peers are unreachable). Mirrors Bitcoin \
             Core's -onion flag." in
  Arg.(value & opt (some string) None &
    info ["onion"] ~docv:"HOST:PORT" ~doc)

let i2psam_arg =
  let doc = "I2P SAM 3.1 bridge endpoint (host:port) for .b32.i2p dials. \
             When set, outbound dials to I2P destinations go through the \
             SAM session; without this flag, .b32.i2p peers are \
             unreachable. The standard I2P SAM port is 7656. Mirrors \
             Bitcoin Core's -i2psam flag." in
  Arg.(value & opt (some string) None &
    info ["i2psam"] ~docv:"HOST:PORT" ~doc)

let i2p_private_key_arg =
  let doc = "Path to a file holding the persistent I2P destination private \
             key.  When set, the SAM session is created with \
             DESTINATION=<base64-priv-key> (loaded from this file) so the \
             same .b32.i2p inbound address is reused across restarts. \
             On first run the file is created automatically (mode 0600) \
             from the SAM-returned key after a TRANSIENT bootstrap. \
             When unset, every restart creates a fresh transient \
             destination. Closes W117 BUG-7 — see lib/p2p.ml." in
  Arg.(value & opt (some string) None &
    info ["i2p-private-key"] ~docv:"PATH" ~doc)

let cjdnsreachable_arg =
  let doc = "Assert that this host can route directly into the CJDNS \
             overlay (fc00::/8). When set, outbound dials to fc00::/8 \
             addresses are issued as direct TCP connects (the operator \
             is expected to have cjdroute running and a kernel route in \
             place). When unset (default), CJDNS dials are rejected by \
             the proxy layer to avoid leaking the dial intent over the \
             clearnet default route. Mirrors Bitcoin Core's \
             -cjdnsreachable flag." in
  Arg.(value & flag & info ["cjdnsreachable"] ~doc)

(* W119 / FIX-64: HTTPS/TLS termination flags. *)
let rpc_tls_cert_arg =
  let doc = "PEM-encoded X.509 certificate file for the JSON-RPC \
             listener. When set, the listener serves HTTPS instead of \
             plain HTTP; must be paired with --rpc-tls-key. The cert \
             may be self-signed (no chain validation is performed on \
             the server side). Default: off (plain HTTP). \
             Mirrors Bitcoin Core's BIP-78 §\"Protocol\" TLS \
             requirement and the httpserver.cpp option." in
  Arg.(value & opt (some string) None &
    info ["rpc-tls-cert"] ~docv:"PATH" ~doc)

let rpc_tls_key_arg =
  let doc = "PEM-encoded private key file paired with --rpc-tls-cert. \
             Should be mode 0600. Both --rpc-tls-cert and --rpc-tls-key \
             must be supplied together; supplying only one is a startup \
             error." in
  Arg.(value & opt (some string) None &
    info ["rpc-tls-key"] ~docv:"PATH" ~doc)

let rest_tls_cert_arg =
  let doc = "PEM-encoded X.509 certificate for the REST listener \
             (independent of the JSON-RPC cert, so the two listeners \
             may be terminated with different certificates). Requires \
             --rest. Must be paired with --rest-tls-key. Default: off." in
  Arg.(value & opt (some string) None &
    info ["rest-tls-cert"] ~docv:"PATH" ~doc)

let rest_tls_key_arg =
  let doc = "PEM-encoded private key paired with --rest-tls-cert. \
             Both --rest-tls-cert and --rest-tls-key must be supplied \
             together." in
  Arg.(value & opt (some string) None &
    info ["rest-tls-key"] ~docv:"PATH" ~doc)

(* ============================================================================
   Main Command
   ============================================================================ *)

let run_cmd network datadir rpc_host rpc_port rpc_user rpc_password
    p2p_port max_outbound max_inbound connect no_dnsseed debug no_wallet prune benchmark
    import_blocks import_utxo metrics_port peer_bloom_filters
    migrate_logstorage daemon_mode pid_path conf_path debug_cats
    logfile printtoconsole ready_fd zmq_pub reindex
    rest_enabled rest_port rest_bind blockfilterindex asmap
    proxy onion_proxy i2psam i2p_private_key cjdnsreachable
    rpc_tls_cert rpc_tls_key rest_tls_cert rest_tls_key
    coinstatsindex_cli txindex_cli txospenderindex_cli dbcache_cli =
  (* --txindex is accepted for Core CLI compatibility (camlcoin always
     maintains the tx index); validate its value but otherwise ignore it. *)
  ignore txindex_cli;
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
  let eff_prune_mib =
    Camlcoin.Runtime_config.overlay_int
      ~cli:(if prune = 0 then None else Some prune)
      ~conf:(Camlcoin.Runtime_config.get_int conf_opts "prune")
      ~default:prune in
  (* Bitcoin Core --prune floor validation (init.cpp:524-540):
       0      → off
       1      → manual mode (kept; auto-prune gated separately by sync.ml)
       2..549 → rejected (below MIN_DISK_SPACE_FOR_BLOCK_FILES = 550 MiB)
       ≥550   → automatic prune target.
     Convert MiB → bytes per Core convention. The internal
     [chain.prune_target] field carries bytes after this conversion;
     `--prune=1` (manual mode) is kept as a literal 1-byte sentinel,
     since 0 means off. *)
  let eff_prune =
    if eff_prune_mib = 0 then 0
    else if eff_prune_mib = 1 then 1  (* manual-mode sentinel *)
    else if eff_prune_mib < 550 then begin
      Logs.err (fun m ->
        m "Invalid --prune=%d: must be 0 (off), 1 (manual), or \
           >= 550 (target in MiB). Bitcoin Core rejects values below \
           MIN_DISK_SPACE_FOR_BLOCK_FILES (550 MiB) at init.cpp:524."
          eff_prune_mib);
      exit 1
    end else
      eff_prune_mib * 1024 * 1024
  in
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
  end else begin
  (* UTXO snapshot bootstrap: Bitcoin Core dumptxoutset format.

     The HDOG path retired 2026-04-29: the prior bespoke 52-byte header
     + per-coin (txid, vout LE, amount, height, scriptlen, script)
     layout was incompatible with the rest of the fleet and prevented
     camlcoin from consuming snapshots produced by Bitcoin Core or any
     other implementation. We now read Core's wire format byte-for-byte
     (magic 'utxo\xff', VARINT/CompressAmount/ScriptCompression).

     2026-05-29: --load-snapshot/--import-utxo now bootstraps the PRIMARY
     chainstate (the one Cli.run / Sync reads) and FALLS THROUGH into normal
     node-run, instead of writing a dead chainstate_snapshot/ directory and
     exiting. The import streams coins into the primary Rocksdb_store, records
     its tip_height + the CF chain_tip at the snapshot base height, then
     control continues to the node-run branch below where restore_chain_state
     reads chain_tip -> blocks_synced and forward-sync continues
     (accept-then-continue, mirroring rustoshi / blockbrew). When the flag is
     absent this is a no-op and the genesis sync path is unchanged. *)
  (match import_utxo with
   | None -> ()
   | Some utxo_path ->
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
     let rocksdb_path = Filename.concat data_dir "rocksdb_utxo" in
     let on_progress (p : Camlcoin.Assume_utxo.load_progress) =
       if Int64.rem p.coins_loaded 1_000_000L = 0L
          && Int64.compare p.coins_loaded 0L > 0 then
         Printf.eprintf "[utxo-import] %Ld / %Ld coins (%.1f%%)\n%!"
           p.coins_loaded p.total_coins p.pct
     in
     Printf.eprintf "[utxo-import] Loading Core-format snapshot: %s\n%!"
       utxo_path;
     Printf.eprintf
       "[utxo-import] Network: %s | bootstrapping PRIMARY chainstate at %s\n%!"
       network_cfg.Camlcoin.Consensus.name data_dir;
     (* Guard: only bootstrap a fresh chainstate. If a validated tip already
        exists, importing a snapshot over it would corrupt the chain view.
        Mirrors blockbrew main.go:785-789 (-load-snapshot ignored when the
        chainstate is not fresh). *)
     let probe_db = Camlcoin.Storage.ChainDB.create db_path in
     let existing_tip =
       match Camlcoin.Storage.ChainDB.get_chain_tip probe_db with
       | Some (_, h) when h > 0 -> Some h
       | _ -> None
     in
     Camlcoin.Storage.ChainDB.close probe_db;
     (match existing_tip with
      | Some h ->
        Printf.eprintf
          "[utxo-import] chainstate already at height %d — refusing to \
           overwrite; remove %s to re-bootstrap. Continuing with existing \
           chainstate.\n%!" h db_path
      | None ->
        let db = Camlcoin.Storage.ChainDB.create db_path in
        let rocksdb = Camlcoin.Rocksdb_store.open_db rocksdb_path in
        (match Camlcoin.Assume_utxo.load_snapshot_into_primary
                 ~network:network_cfg
                 ~snapshot_path:utxo_path
                 ~db
                 ~rocksdb
                 ~on_progress
                 () with
         | Ok r ->
           Printf.eprintf
             "[utxo-import] Bootstrapped %Ld coins; chain tip set to \
              height %d (%s). Forward-sync will continue from there.\n%!"
             r.coins_loaded r.base_height
             (Camlcoin.Types.hash256_to_hex_display r.base_blockhash)
         | Error msg ->
           Printf.eprintf "[utxo-import] failed: %s\n%!" msg;
           Camlcoin.Rocksdb_store.close rocksdb;
           Camlcoin.Storage.ChainDB.close db;
           exit 1);
        (* Close both stores before falling through: the node-run path
           reopens them, and RocksDB takes an exclusive process lock. *)
        Camlcoin.Rocksdb_store.close rocksdb;
        Camlcoin.Storage.ChainDB.close db));
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
    (* UTXO LRU raised 2M -> 20M coins (~1% -> ~10% of the ~190M-coin set):
       profiling showed the 2M cache served ~1% of lookups, leaving the sync
       disk-I/O bound. Larger LRU cuts random RocksDB reads on the hot set. *)
    let utxo = Camlcoin.Utxo.OptimizedUtxoSet.create
      ~cache_size:20_000_000 ~rocksdb db in
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
    (* DNS seeding: ON by default (Core DEFAULT_DNSSEED). Disabled by
       --nodnsseed on the CLI or dnsseed=0 in the conf file. *)
    let eff_dns_seed =
      if no_dnsseed then false
      else match Camlcoin.Runtime_config.get_bool conf_opts "dnsseed" with
        | Some b -> b
        | None -> true
    in
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
      dns_seed = eff_dns_seed;
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
      (* PERF/config: UTXO LRU entry budget. CLI > conf > base default
         (base.dbcache_lru_entries = 4_000_000, default-preserving). A
         non-positive value is rejected so a typo can't silently disable
         the cache or crash Perf.LRU. *)
      dbcache_lru_entries =
        (let resolved =
           Camlcoin.Runtime_config.overlay_int
             ~cli:dbcache_cli
             ~conf:(Camlcoin.Runtime_config.get_int conf_opts "dbcache")
             ~default:base.dbcache_lru_entries
         in
         if resolved <= 0 then begin
           Printf.eprintf
             "[camlcoin] Invalid --dbcache value: %d (must be a positive number of entries)\n%!"
             resolved;
           exit 1
         end;
         resolved);
      rest_enabled =
        rest_enabled
        || (match Camlcoin.Runtime_config.get_bool conf_opts "rest" with
            | Some b -> b | None -> false);
      rest_port = (match rest_port with
        | Some p -> Some p
        | None -> Camlcoin.Runtime_config.get_int conf_opts "restport");
      rest_bind = (match rest_bind with
        | Some h -> Some h
        | None -> Camlcoin.Runtime_config.get_string conf_opts "restbind");
      blockfilterindex_basic =
        (* Resolve CLI value (string / None) and conf-file value into a
           boolean. Accepted enables: '1', 'true', 'basic'. Accepted
           disables: '0', 'false', missing. Anything else is fatal. *)
        begin
          let parse_one v =
            match String.lowercase_ascii v with
            | "" | "0" | "false" -> Ok false
            | "1" | "true" | "basic" -> Ok true
            | other ->
              Error (Printf.sprintf
                "Invalid --blockfilterindex value: %S (accepted: 0/1/true/false/basic)"
                other)
          in
          let cli_val = blockfilterindex in
          let conf_val = Camlcoin.Runtime_config.get_string conf_opts "blockfilterindex" in
          let chosen = match cli_val with
            | Some v -> Some v
            | None -> conf_val
          in
          match chosen with
          | None -> false
          | Some v ->
            (match parse_one v with
             | Ok b -> b
             | Error msg ->
               Printf.eprintf "[camlcoin] %s\n%!" msg;
               exit 1)
        end;
      coinstatsindex =
        (* Resolve CLI / conf-file value into a boolean. Accepted enables:
           '1', 'true'. Accepted disables: '0', 'false', missing. Anything
           else is fatal (mirrors the --blockfilterindex resolution). *)
        begin
          let parse_one v =
            match String.lowercase_ascii v with
            | "" | "0" | "false" -> Ok false
            | "1" | "true" -> Ok true
            | other ->
              Error (Printf.sprintf
                "Invalid --coinstatsindex value: %S (accepted: 0/1/true/false)"
                other)
          in
          let chosen = match coinstatsindex_cli with
            | Some v -> Some v
            | None -> Camlcoin.Runtime_config.get_string conf_opts "coinstatsindex"
          in
          match chosen with
          | None -> false
          | Some v ->
            (match parse_one v with
             | Ok b -> b
             | Error msg ->
               Printf.eprintf "[camlcoin] %s\n%!" msg;
               exit 1)
        end;
      txospenderindex =
        (* Resolve CLI / conf-file value into a boolean, mirroring the
           --coinstatsindex resolution above. Default off
           (DEFAULT_TXOSPENDERINDEX). *)
        begin
          let parse_one v =
            match String.lowercase_ascii v with
            | "" | "0" | "false" -> Ok false
            | "1" | "true" -> Ok true
            | other ->
              Error (Printf.sprintf
                "Invalid --txospenderindex value: %S (accepted: 0/1/true/false)"
                other)
          in
          let chosen = match txospenderindex_cli with
            | Some v -> Some v
            | None -> Camlcoin.Runtime_config.get_string conf_opts "txospenderindex"
          in
          match chosen with
          | None -> false
          | Some v ->
            (match parse_one v with
             | Ok b -> b
             | Error msg ->
               Printf.eprintf "[camlcoin] %s\n%!" msg;
               exit 1)
        end;
      asmap_path = (match asmap with
        | Some _ -> asmap
        | None -> Camlcoin.Runtime_config.get_string conf_opts "asmap");
      (* W117 BUG-2 fix (FIX-56): outbound proxy / overlay routing.
         CLI flags win over conf-file values, conf wins over [None]. *)
      proxy = (match proxy with
        | Some _ -> proxy
        | None -> Camlcoin.Runtime_config.get_string conf_opts "proxy");
      onion = (match onion_proxy with
        | Some _ -> onion_proxy
        | None -> Camlcoin.Runtime_config.get_string conf_opts "onion");
      i2psam = (match i2psam with
        | Some _ -> i2psam
        | None -> Camlcoin.Runtime_config.get_string conf_opts "i2psam");
      i2p_private_key = (match i2p_private_key with
        | Some _ -> i2p_private_key
        | None -> Camlcoin.Runtime_config.get_string conf_opts "i2pprivatekey");
      cjdns_reachable =
        cjdnsreachable
        || (match Camlcoin.Runtime_config.get_bool conf_opts "cjdnsreachable" with
            | Some b -> b
            | None -> false);
      (* W119 / FIX-64: HTTPS/TLS termination.  CLI wins over conf.  Conf
         keys mirror the CLI long names with hyphens stripped (per the
         bitcoin.conf convention: keys are lowercase, no separators). *)
      rpc_tls_cert = (match rpc_tls_cert with
        | Some _ -> rpc_tls_cert
        | None -> Camlcoin.Runtime_config.get_string conf_opts "rpctlscert");
      rpc_tls_key = (match rpc_tls_key with
        | Some _ -> rpc_tls_key
        | None -> Camlcoin.Runtime_config.get_string conf_opts "rpctlskey");
      rest_tls_cert = (match rest_tls_cert with
        | Some _ -> rest_tls_cert
        | None -> Camlcoin.Runtime_config.get_string conf_opts "resttlscert");
      rest_tls_key = (match rest_tls_key with
        | Some _ -> rest_tls_key
        | None -> Camlcoin.Runtime_config.get_string conf_opts "resttlskey");
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
    $ no_dnsseed_arg
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
    $ reindex_arg
    $ rest_arg
    $ rest_port_arg
    $ rest_bind_arg
    $ blockfilterindex_arg
    $ asmap_arg
    $ proxy_arg
    $ onion_arg
    $ i2psam_arg
    $ i2p_private_key_arg
    $ cjdnsreachable_arg
    $ rpc_tls_cert_arg
    $ rpc_tls_key_arg
    $ rest_tls_cert_arg
    $ rest_tls_key_arg
    $ coinstatsindex_arg
    $ txindex_arg
    $ txospenderindex_arg
    $ dbcache_arg)

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
