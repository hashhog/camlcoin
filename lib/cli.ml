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
  dns_seed : bool;
    (* Mirrors Bitcoin Core -dnsseed (DEFAULT_DNSSEED=true). When [false]
       (--nodnsseed / -dnsseed=0 / conf dnsseed=0) the peer manager skips
       DNS-seed resolution. Note: a non-empty [connect] list also implies
       no DNS seeding (Core -connect semantics), handled in the peer
       manager regardless of this flag. *)
  debug : bool;
  wallet_enabled : bool;
  prune : int;
    (* Pruning target in BYTES (after MiB→bytes conversion at the CLI
       layer in [bin/main.ml]). Bitcoin Core --prune semantics
       (init.cpp:524):
         0           = pruning disabled
         1           = manual mode (auto-prune off; manual RPC only — TODO)
         N * 1MiB    = automatic prune target where N >= 550 MiB
       Values 2..549 are rejected at CLI parse. *)
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
  rest_enabled : bool;
    (* Mirrors Bitcoin Core's -rest (init.cpp:153 DEFAULT_REST_ENABLE).
       When true, a public read-only REST HTTP listener is spawned in
       Cli.run alongside the JSON-RPC listener; when false (default),
       no REST socket is bound and the rest module is silent. *)
  rest_port : int option;
    (* Optional override port for the REST listener. [None] reuses the
       JSON-RPC port, matching Core's "REST handlers mounted on the
       same HTTP server" semantics. Set explicitly to use a separate
       physical socket. *)
  rest_bind : string option;
    (* Optional bind address for the REST listener. [None] reuses
       [rpc_host]. *)
  blockfilterindex_basic : bool;
    (* Mirrors Bitcoin Core's -blockfilterindex=basic
       (init.cpp / index/blockfilterindex.cpp). When [true], the daemon
       maintains a BIP-157/158 basic filter index at
       [<data_dir>/indexes/blockfilter/basic] and serves
       /rest/blockfilter[/headers] from it; when [false] (default), the
       REST endpoints return Core's exact 400 "Index is not enabled for
       filtertype basic". The index is back-filled at startup if it lags
       the validated tip and is updated on every connect/reorg. *)
  asmap_path : string option;
    (* Path to an ASMap binary file for IP-to-ASN mapping (eclipse protection).
       Mirrors Bitcoin Core's -asmap=<file> flag (init.cpp).  When set, peer
       addresses are mapped to their Autonomous System Number and bucketed by
       ASN in AddrMan rather than by /16 netgroup.  [None] (default) uses the
       legacy /16 bucketing. *)
  proxy : string option;
    (* --proxy=<host:port>.  Default SOCKS5 proxy for outbound TCP dials.
       Used for IPv4/IPv6 and (when --onion isn't set) for .onion as well.
       Mirrors Bitcoin Core's -proxy flag (init.cpp).  [None] (default) =
       direct clearnet connections. *)
  onion : string option;
    (* --onion=<host:port>.  Dedicated SOCKS5 proxy for .onion peers.
       When set, overrides --proxy for Tor hidden-service dials and enables
       Tor stream-isolation (random SOCKS5 credentials per circuit).
       Mirrors Bitcoin Core's -onion flag.  [None] = .onion dials use the
       --proxy default (and fail if neither is set). *)
  i2psam : string option;
    (* --i2psam=<host:port>.  I2P SAM 3.1 bridge endpoint for .b32.i2p dials.
       Mirrors Bitcoin Core's -i2psam flag.  [None] = .b32.i2p dials error
       out at [P2p.connect_with_proxy]. *)
  i2p_private_key : string option;
    (* --i2p-private-key=<path>.  Persistent I2P destination identity.

       When set:
         - First run: send DESTINATION=TRANSIENT to SAM, capture the
           returned base64 private key, write it to <path> with 0600.
         - Subsequent runs: read <path> and send DESTINATION=<key> to
           SAM so the destination (and therefore the .b32.i2p inbound
           address) is stable across restarts.
       When unset (default): every restart gets a fresh transient
       destination (matches Bitcoin Core's behaviour when -i2psam is
       set but -i2psam-persistent is left off).
       W117 BUG-7 (FIX-58) — see lib/p2p.ml [I2P.init_session]. *)
  cjdns_reachable : bool;
    (* --cjdnsreachable.  When [true], we permit direct TCP dials to
       fc00::/8 CJDNS overlay addresses (the operator has the CJDNS daemon
       running and a route in the kernel).  Mirrors Bitcoin Core's
       -cjdnsreachable flag.  [false] (default) = refuse all CJDNS dials
       to avoid leaking the intent over the clearnet default route. *)
  rpc_tls_cert : string option;
    (* --rpc-tls-cert=<PATH>.  PEM-encoded X.509 certificate file used by the
       JSON-RPC listener for HTTPS termination.  When [Some _], the matching
       --rpc-tls-key must also be set; otherwise startup aborts.  When [None]
       (default), the RPC listener serves plain HTTP for backward compatibility.
       Mirrors Bitcoin Core's BIP-78 §"Protocol" TLS-only payment requirement
       and the equivalent httpserver.cpp option.  W119 / FIX-64. *)
  rpc_tls_key : string option;
    (* --rpc-tls-key=<PATH>.  PEM-encoded private key file paired with
       --rpc-tls-cert.  Should be mode 0600.  See [rpc_tls_cert]. *)
  rest_tls_cert : string option;
    (* --rest-tls-cert=<PATH>.  PEM cert for the public REST listener.
       Independent from the RPC pair so REST and RPC can be terminated with
       different certs (e.g. RPC under a private CA, REST under a public CA).
       When unset, the REST listener serves plain HTTP. *)
  rest_tls_key : string option;
    (* --rest-tls-key=<PATH>.  PEM private key paired with --rest-tls-cert. *)
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
  dns_seed = true;  (* Core DEFAULT_DNSSEED *)
  debug = false;
  wallet_enabled = true;
  prune = 0;
  log_categories = [];
  metrics_port = 9332;
  peer_bloom_filters = false;  (* Mirrors Core DEFAULT_PEERBLOOMFILTERS *)
  zmq_pub_options = [];
  reindex = false;
  rest_enabled = false;  (* Mirrors Core DEFAULT_REST_ENABLE = false *)
  rest_port = None;
  rest_bind = None;
  blockfilterindex_basic = false;  (* Mirrors Core DEFAULT_BLOCKFILTERINDEX *)
  asmap_path = None;
  proxy = None;
  onion = None;
  i2psam = None;
  i2p_private_key = None;
  cjdns_reachable = false;
  rpc_tls_cert = None;
  rpc_tls_key = None;
  rest_tls_cert = None;
  rest_tls_key = None;
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

  (* BIP-159: advertise NODE_NETWORK_LIMITED when prune mode is on.
     Mirrors Core init.cpp `nLocalServices |= NODE_NETWORK_LIMITED`
     gated on `IsPruneMode()`.  Set BEFORE any peer/handshake work for
     the same reason as the bloom flag. *)
  Peer.set_prune_mode_advertise (config.prune > 0);
  Logs.info (fun m ->
    m "NODE_NETWORK_LIMITED (BIP-159) advertisement: %s"
      (if config.prune > 0 then "enabled (--prune > 0)"
       else "disabled"));

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

  (* BIP-157 basic block filter index.  Mirrors Bitcoin Core's
     [-blockfilterindex=basic] (init.cpp + index/blockfilterindex.cpp).
     Created here so it's attached to [chain] before any IBD or post-IBD
     block listener fires; closed in graceful_shutdown.  When the flag
     is off we leave [chain.bip157_index = None] and every connect-block
     path no-ops via [append_filter_if_enabled]. *)
  let bip157_index =
    if not config.blockfilterindex_basic then None
    else begin
      try
        let idx = Block_index.create_bip157_index ~data_dir:config.data_dir in
        chain.bip157_index <- Some idx;
        Logs.info (fun m ->
          m "BIP-157 index opened at %s (best_height=%d, target=%d)"
            idx.root_dir
            (Block_index.bip157_best_height idx)
            chain.blocks_synced);
        (* Run the startup backfill synchronously so the REST endpoints
           served by the upcoming RPC listener can immediately answer
           filter requests for any indexed height. The walk is bounded
           by [chain.blocks_synced] (validated tip), so it never runs
           past the active chain; stops gracefully on missing block
           bodies (pruned datadirs). *)
        let _ = Sync.backfill_bip157_index chain in
        (* Advertise NODE_COMPACT_FILTERS (bit 6) so peers know we can
           serve getcfilters/getcfheaders/getcfcheckpt.  Mirrors Bitcoin
           Core's init.cpp: NODE_COMPACT_FILTERS is ORed into
           GetLocalServices() iff blockfilterindex is enabled. *)
        Peer.enable_compact_filters ();
        Logs.info (fun m ->
          m "BIP-157: NODE_COMPACT_FILTERS enabled (blockfilterindex=basic)");
        Some idx
      with exn ->
        Logs.err (fun m ->
          m "BIP-157: failed to open filter index at %s: %s"
            (Filename.concat config.data_dir "indexes/blockfilter/basic")
            (Printexc.to_string exn));
        None
    end
  in

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
     "transaction references missing inputs" errors (e.g. at block 16226).

     [apply_block_atomic] commits RDB first, CF second (see
     [Storage.ChainDB.apply_block_atomic] commentary for the crash-window
     analysis).  The expected post-crash invariant is therefore
     [rdb_tip >= chain_tip].  We handle all four combinations:

       1. rdb_tip = None              -> RDB wiped; force chain_tip to 0.
       2. rdb_tip < chain_tip         -> Inverse of the expected window
                                          (legacy data, or a CF-only write
                                          path).  Rewind chain_tip to
                                          rdb_tip AND persist the rewind
                                          to the on-disk CF chain_state
                                          so subsequent readers of
                                          [get_chain_tip] see the rewound
                                          value (this was the latent bug
                                          behind the 950351 stall: the
                                          rewind was in-memory only, the
                                          CF still said the higher height,
                                          and later code paths re-used
                                          the stale on-disk tip).
       3. rdb_tip > chain_tip         -> Expected crash window: RDB
                                          committed, CF didn't.  Leave
                                          chain_tip where it is; IBD will
                                          re-apply the missing block(s)
                                          and the puts/deletes are
                                          idempotent on RDB.
       4. rdb_tip = chain_tip         -> Heights match.  Sample the tip
                                          block's spendable outputs in
                                          RDB to detect content-level
                                          skew (heights agree but
                                          individual UTXOs are missing).
                                          If any missing, rewind one
                                          block and persist.  Bounded
                                          O(N_outputs_at_tip) cost. *)
  let persist_rewind_to_height ?(reason="") (target : int) : unit =
    (* Persist the rewind to the CF chain_state so a subsequent
       [get_chain_tip] reads the rewound value, and update the in-memory
       [chain.blocks_synced] mirror.  Looks up the header for [target]
       from the block_height CF; on lookup failure (extremely unusual —
       implies the height->hash map is also corrupt) we fall back to a
       zero hash + 0 height which forces a full re-sync. *)
    let new_hash, new_height =
      if target <= 0 then (Cstruct.create 32, 0)
      else
        match Storage.ChainDB.get_hash_at_height db target with
        | Some h -> (h, target)
        | None -> (Cstruct.create 32, 0)
    in
    chain.blocks_synced <- new_height;
    Storage.ChainDB.set_chain_tip db new_hash new_height;
    if reason <> "" then
      Logs.warn (fun m ->
        m "chainstate rewind persisted to height=%d (%s)" new_height reason)
  in
  if chain.blocks_synced > 0 then begin
    match Rocksdb_store.get_tip_height rocksdb with
    | None ->
      Logs.warn (fun m ->
        m "RocksDB UTXO store has no tip height but chainstate claims blocks_synced=%d — resetting to 0 (UTXO store was likely wiped)"
          chain.blocks_synced);
      persist_rewind_to_height ~reason:"RDB wiped" 0
    | Some rdb_height when rdb_height < chain.blocks_synced ->
      Logs.warn (fun m ->
        m "RocksDB UTXO tip (%d) is behind chainstate chain_tip (%d) — resetting to RocksDB tip"
          rdb_height chain.blocks_synced);
      persist_rewind_to_height
        ~reason:(Printf.sprintf "rdb_tip=%d < chain_tip=%d" rdb_height chain.blocks_synced)
        rdb_height
    | Some rdb_height when rdb_height > chain.blocks_synced ->
      (* Crash window: apply_block_atomic committed RDB (UTXO set) but not
         CF (chain_tip), leaving the persisted UTXO set AHEAD of chain_tip.

         The OLD behaviour here merely LOGGED and trusted a "forward
         re-apply is idempotent" claim (storage.ml:638-641).  That claim is
         FALSE for cross-block spends: re-applying chain_tip+1 reads the
         UTXO set (validation.ml:1136-1182) and hits TxMissingInputs because
         a prevout was already deleted by an already-committed later block in
         the window -> block rejected -> re-downloaded forever -> permanent
         wedge at chain_tip (the live mainnet wedge at 952223/952224).

         Bitcoin Core does NOT trust forward re-apply here.  Its
         [ReplayBlocks] / [RollbackBlock] (validation.cpp:4773-4858) rolls
         the UTXO set BACK along the over-applied branch using stored undo
         data, down to the consistent point, then rolls forward.  We do the
         same: reconcile the RDB UTXO set DOWN to chain_tip so the UTXO state
         matches the authoritative validated tip, then let IBD re-apply
         forward from a consistent base.

         If undo data for any window block is missing (the post-IBD connect
         paths do not persist undo), reconciliation is impossible — fall back
         to a full resync (persist_rewind_to_height 0) rather than spinning in
         the infinite missing-inputs loop. *)
      Logs.warn (fun m ->
        m "RocksDB UTXO tip (%d) is ahead of chainstate chain_tip (%d) — \
           crash inside apply_block_atomic; reconciling UTXO set down to \
           chain_tip (Core ReplayBlocks/RollbackBlock model)"
          rdb_height chain.blocks_synced);
      (match Sync.reconcile_rdb_to_chain_tip chain rocksdb
               ~rdb_height ~target_height:chain.blocks_synced with
       | Ok () ->
         Logs.info (fun m ->
           m "UTXO reconcile succeeded; UTXO set now matches chain_tip=%d, \
              IBD will re-apply forward from a consistent base"
             chain.blocks_synced)
       | Error msg ->
         Logs.warn (fun m ->
           m "UTXO reconcile FAILED (%s) — undo data unavailable for the \
              crash window; falling back to full resync to avoid the \
              missing-inputs wedge" msg);
         persist_rewind_to_height
           ~reason:(Printf.sprintf
             "reconcile-unavailable (rdb_tip=%d > chain_tip=%d): %s"
             rdb_height chain.blocks_synced msg)
           0)
    | Some _ ->
      (* Heights match.  Per-block content validation: read the tip
         block, sample each non-coinbase spendable output, and verify
         it is present in RDB.  If anything is missing, rewind one
         block and persist; the next IBD step will refill.

         Cost: one block-body read + one RDB get per non-unspendable
         output of the tip block (typically a few thousand for a full
         mainnet block).  Negligible against the cost of re-IBDing
         from scratch when the alternative is a silent missing-UTXO
         stall. *)
      let tip_height = chain.blocks_synced in
      let do_rewind reason =
        Logs.warn (fun m ->
          m "Per-block content check FAILED at height=%d (%s) — rewinding one block"
            tip_height reason);
        persist_rewind_to_height
          ~reason:(Printf.sprintf "content skew at h=%d: %s" tip_height reason)
          (tip_height - 1)
      in
      (match Storage.ChainDB.get_hash_at_height db tip_height with
       | None ->
         Logs.warn (fun m ->
           m "chainstate claims blocks_synced=%d but block_height CF has no entry — rewinding to 0"
             tip_height);
         persist_rewind_to_height ~reason:"missing height->hash map" 0
       | Some tip_hash ->
         (match Storage.ChainDB.get_block db tip_hash with
          | None ->
            (* No body to validate against; safest action is to leave
               state alone.  The body-store could legitimately be
               pruned in a pruned-node configuration. *)
            Logs.info (fun m ->
              m "Per-block content check skipped at height=%d (no block body on disk; pruned?)"
                tip_height)
          | Some block ->
            (* Collect outputs SPENT by any non-coinbase tx in this same
               block — those legitimately do NOT appear in the on-disk
               UTXO set (they were created and destroyed in one block,
               so apply_block_atomic's batch issued Add+Del back-to-back
               and only the Del survives in RDB).  Without this filter
               we would false-positive on every block that includes a
               child-spending-parent tx and trigger a needless rewind. *)
            let spent_in_block : (string, unit) Hashtbl.t =
              Hashtbl.create 32 in
            List.iteri (fun tx_idx (tx : Types.transaction) ->
              (* Coinbase is always tx_idx=0 (Bitcoin invariant) and its
                 inputs do not reference real prior outpoints. *)
              if tx_idx <> 0 then
                List.iter (fun (inp : Types.tx_in) ->
                  let k =
                    Cstruct.to_string inp.Types.previous_output.Types.txid
                    ^ Int32.to_string inp.Types.previous_output.Types.vout
                  in
                  Hashtbl.replace spent_in_block k ()
                ) tx.Types.inputs
            ) block.transactions;
            (* Walk outputs; bail on the FIRST true miss (output that is
               NOT spent-in-block AND not present in RDB). *)
            let missing = ref None in
            (try
               List.iter (fun (tx : Types.transaction) ->
                 let txid = Crypto.compute_txid tx in
                 List.iteri (fun vout (out : Types.tx_out) ->
                   if !missing = None
                      && not (Utxo.is_unspendable_script out.Types.script_pubkey)
                   then begin
                     let spent_key =
                       Cstruct.to_string txid ^ Int32.to_string (Int32.of_int vout)
                     in
                     if Hashtbl.mem spent_in_block spent_key then ()
                     else begin
                       let key =
                         Storage.ChainDB.rocksdb_utxo_key txid vout in
                       match Rocksdb_store.get rocksdb key with
                       | Some _ -> ()
                       | None ->
                         missing := Some (txid, vout);
                         raise Exit
                     end
                   end
                 ) tx.Types.outputs
               ) block.transactions
             with Exit -> ());
            (match !missing with
             | None ->
               Logs.info (fun m ->
                 m "Per-block content check PASSED at height=%d (rdb_tip=chain_tip and tip block's outputs are present in RDB)"
                   tip_height)
             | Some (mtxid, mvout) ->
               do_rewind (Printf.sprintf
                 "tip block output %s:%d missing from RDB"
                 (Types.hash256_to_hex_display mtxid) mvout))))
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

  (* Initialize fee estimator — must be created before the mempool so its
     eviction callback can be captured in the mempool constructor closure.
     Core: CBlockPolicyEstimator is created in node/kernel/chain.cpp and wired
     into CTxMemPool via the TransactionRemovedFromMempool signal. *)
  let fee_estimator = Fee_estimation.create () in

  (* Initialize mempool *)
  let current_height = match chain.tip with
    | Some t -> t.height
    | None -> 0
  in
  (* Wire Fee_estimation.record_eviction as the eviction hook so that every
     tx removed without confirmation (eviction, expiry, RBF) updates the
     fee estimator's leftmempool stats.  Fixes W114 G12 dead-helper. *)
  let mempool = Mempool.create ~utxo ~current_height
    ~on_eviction:(Some (fun txid ->
      Fee_estimation.record_eviction fee_estimator txid))
    () in

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

  (* Load persisted fee estimation data *)
  let fee_est_path = Filename.concat config.data_dir "fee_estimates.dat" in
  (try
    if Fee_estimation.load_from_file fee_estimator fee_est_path then
      Logs.info (fun m -> m "Loaded fee estimation data from %s" fee_est_path)
  with exn ->
    Logs.warn (fun m ->
      m "Failed to load fee estimates: %s" (Printexc.to_string exn)));

  (* Load ASMap for eclipse-resistant bucketing (--asmap flag) *)
  let asmap_data = match config.asmap_path with
    | None -> None
    | Some path ->
      let data = Asmap.load_asmap path in
      (match data with
       | Some bytes ->
         let ver = Asmap.asmap_version bytes in
         let hex = String.concat "" (List.init 8 (fun i ->
           Printf.sprintf "%02x" (Char.code (String.get ver i))))
         in
         Logs.info (fun m -> m "Using asmap version %s... for IP bucketing" hex);
         Some bytes
       | None -> None)
  in

  (* Build the outbound proxy configuration from the CLI flags.
     Mirrors Bitcoin Core init.cpp's mapping from -proxy / -onion /
     -i2psam / -cjdnsreachable into ProxyOptions before the peer
     manager starts.  Invalid host:port strings are reported as a
     warning and treated as if the flag wasn't set, so a typo in
     --proxy doesn't silently strand outbound dials.

     Closes W117 BUG-2 (FIX-56): the wiring exists so
     Peer_manager.add_peer / force_add_peer / add_block_relay_peer
     route every dial through P2p.connect_with_proxy. *)
  let parse_host_port_socks5 raw =
    (* Accept bare "host:port" (Core syntax) or full "socks5://..." URL. *)
    match P2p.parse_proxy_url raw with
    | Some p -> Some p
    | None ->
      let with_scheme = "socks5://" ^ raw in
      P2p.parse_proxy_url with_scheme
  in
  let parsed_proxy = match config.proxy with
    | None -> P2p.NoProxy
    | Some s ->
      (match parse_host_port_socks5 s with
       | Some p -> p
       | None ->
         Logs.warn (fun m ->
           m "ignoring malformed --proxy=%S (expected host:port or socks5://host:port)" s);
         P2p.NoProxy)
  in
  let parsed_onion = match config.onion with
    | None -> P2p.NoProxy
    | Some s ->
      (match parse_host_port_socks5 s with
       | Some (P2p.Socks5Proxy r) ->
         (* Dedicated onion proxy: enable Tor stream isolation by default
            (random SOCKS5 credentials per circuit), matching Bitcoin
            Core's behaviour when -onion is set.  This is independent
            from any credentials already encoded in the URL — we never
            stamp over them. *)
         let tor_iso = r.credentials = None in
         P2p.Socks5Proxy { r with tor_stream_isolation = tor_iso }
       | Some other -> other
       | None ->
         Logs.warn (fun m ->
           m "ignoring malformed --onion=%S (expected host:port)" s);
         P2p.NoProxy)
  in
  let parsed_i2psam = match config.i2psam with
    | None -> P2p.NoProxy
    | Some s ->
      (* W117 BUG-7 (FIX-58): thread --i2p-private-key=<path> through to
         the I2PSam variant so [P2p.connect_with_proxy] can request a
         persistent identity (SAMv3 SESSION CREATE DESTINATION=<key>)
         instead of always sending TRANSIENT. *)
      (match P2p.parse_i2p_sam ~private_key_path:config.i2p_private_key s with
       | Some p -> p
       | None ->
         Logs.warn (fun m ->
           m "ignoring malformed --i2psam=%S (expected host:port)" s);
         P2p.NoProxy)
  in
  let proxy_config : P2p.proxy_config = {
    P2p.default_proxy = parsed_proxy;
    onion_proxy = parsed_onion;
    i2p_sam = parsed_i2psam;
    onlynet = P2p.default_proxy_config.onlynet;
    cjdns_reachable = config.cjdns_reachable;
  } in
  (* Operator visibility: report what's wired and what isn't, since
     "Tor outbound enabled but my .onion peer is unreachable" is the
     first question anyone will ask. *)
  (match parsed_proxy with
   | P2p.NoProxy -> ()
   | P2p.Socks5Proxy { addr; port; _ } ->
     Logs.info (fun m -> m "Outbound proxy: SOCKS5 %s:%d" addr port)
   | _ -> ());
  (match parsed_onion with
   | P2p.NoProxy -> ()
   | P2p.Socks5Proxy { addr; port; tor_stream_isolation; _ } ->
     Logs.info (fun m ->
       m "Outbound Tor proxy: SOCKS5 %s:%d (stream-isolation=%b)"
         addr port tor_stream_isolation)
   | _ -> ());
  (match parsed_i2psam with
   | P2p.NoProxy -> ()
   | P2p.I2PSam { addr; port; private_key_path } ->
     (match private_key_path with
      | None ->
        Logs.info (fun m ->
          m "Outbound I2P SAM: %s:%d (transient identity)" addr port)
      | Some path ->
        Logs.info (fun m ->
          m "Outbound I2P SAM: %s:%d (persistent identity at %s)"
            addr port path))
   | _ -> ());
  if config.cjdns_reachable then
    Logs.info (fun m -> m "CJDNS reachable: outbound fc00::/8 dials enabled");

  (* Initialize peer manager *)
  let peer_manager = Peer_manager.create
    ~config:{ Peer_manager.default_config with
              max_outbound = config.max_outbound;
              max_inbound = config.max_inbound;
              proxy_config;
              dns_seed = config.dns_seed }
    ~asmap:asmap_data
    network in

  (* --connect peer pinning (Bitcoin Core -connect): when manual peers are
     given, pin the node to ONLY those peers. [set_connect_peers] makes
     [Peer_manager.start] skip DNS-seed resolution + addrman/fallback
     bootstrap, and [maintain_connections] only re-dial the pinned peers
     (never auto-fill outbound from addrman). Parse host[:port] the same
     way as the manual-connect dialer below. *)
  (if config.connect <> [] then begin
    let pinned =
      List.filter_map (fun addr_port ->
        match String.split_on_char ':' addr_port with
        | [addr; port_str] ->
          (match int_of_string_opt port_str with
           | Some port -> Some (addr, port)
           | None ->
             Logs.warn (fun m ->
               m "Invalid --connect peer address (bad port): %s" addr_port);
             None)
        | [addr] -> Some (addr, network.default_port)
        | _ ->
          Logs.warn (fun m ->
            m "Invalid --connect peer address format: %s" addr_port);
          None
      ) config.connect
    in
    Peer_manager.set_connect_peers peer_manager pinned
  end);

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

  (* Wire the block-connect -> wallet UTXO ledger hook (mirrors Bitcoin Core's
     CWallet::blockConnected / blockDisconnected).  Every block-connect
     choke-point (Mining.submit_block for the mining / generate* / submitblock
     paths) calls [Sync.run_wallet_scan_hook], which dispatches to this closure
     so the wallet credits coins paid to its addresses and debits coins it
     spends.  Without this the wallet UTXO ledger stays empty and
     getbalance/listunspent/sendtoaddress can never see or spend owned coins.
     A generic closure is installed (not a Wallet.t reference) so the Sync
     module stays free of any dependency on Wallet. *)
  (match wallet with
   | Some w ->
     Sync.set_wallet_hooks chain
       ~on_connect:(fun block height -> Wallet.scan_block w block height)
       ~on_disconnect:(fun block height ->
         Wallet.unscan_block w block height)
       ()
   | None -> ());

  (* Create RPC context. The [filter_index] field of [rpc_context]
     is the inner [Block_index.filter_index] sub-handle (used by
     [rest.ml]'s blockfilter handlers); we extract it from the bundle
     when the operator enabled --blockfilterindex, and otherwise leave
     it [None] so the REST endpoints return Core's exact 400
     "Index is not enabled for filtertype basic". *)
  let filter_index_for_rpc =
    Option.map (fun (idx : Block_index.bip157_index) -> idx.filter_idx)
      bip157_index
  in
  let rpc_ctx = Rpc.create_context
    ~chain ~mempool ~peer_manager
    ~wallet ~fee_estimator ~network
    ~filter_index:filter_index_for_rpc
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
      ~tls_cert_path:config.rpc_tls_cert
      ~tls_key_path:config.rpc_tls_key
      ()
  in


  (* Optionally start REST server. Defaults OFF to match Bitcoin Core's
     DEFAULT_REST_ENABLE=false (init.cpp:153). When enabled, the public
     read-only REST surface (block / tx / headers / chaininfo / mempool /
     blockhashbyheight / blockfilter / blockfilterheaders) is bound to a
     separate Cohttp listener so the JSON-RPC auth path stays untouched.
     The default port is the same as --rpcport (no separate listener
     spawned in that case to avoid double-binding); use --restport to
     pick a distinct socket. The default bind reuses --rpchost. *)
  let rest_host = match config.rest_bind with
    | Some h -> h
    | None -> config.rpc_host in
  let rest_port = match config.rest_port with
    | Some p -> p
    | None -> config.rpc_port in
  let rest_thread =
    if not config.rest_enabled then
      Lwt.return_unit
    else if rest_port = config.rpc_port && rest_host = config.rpc_host then begin
      (* Same host:port as the JSON-RPC server. The Cohttp-based RPC
         listener already routes paths starting with "/" — but the RPC
         dispatcher only honors POST and JSON-RPC bodies. Mounting the
         REST router on the same socket would require teaching the RPC
         server to delegate /rest/* to dispatch_rest. Today we instead
         emit a clear log line and refuse to bind a duplicate listener,
         keeping the cli observable rather than failing silently. *)
      Logs.warn (fun m ->
        m "REST enabled but --restport (%d) matches --rpcport; \
           REST endpoints are NOT served. Set --restport=<distinct \
           port> to enable."
          rest_port);
      Lwt.return_unit
    end else begin
      Logs.info (fun m ->
        m "Starting REST server on %s:%d (--rest)" rest_host rest_port);
      Rest.start_rest_server
        ~ctx:rpc_ctx
        ~host:rest_host
        ~port:rest_port
        ~tls_cert_path:config.rest_tls_cert
        ~tls_key_path:config.rest_tls_key
        ()
    end
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

  (* #135 step 3: persistent Validation_worker Domain for post-IBD block
     validation. The IBD batch path has its own worker (sync.ml:3978) that
     is shut down when IBD completes — for steady-state block validation
     after FullySynced we keep this separate worker alive for the node's
     lifetime so the 0.5-3s per-block validation no longer blocks the Lwt
     main thread / RPC handlers. Lazily created so tests + early startup
     don't pay the cost. Plumbed into Sync.process_new_block as
     ?worker:!post_ibd_worker_ref. *)
  let post_ibd_worker_ref : Sync.Validation_worker.t option ref = ref None in
  let ensure_post_ibd_worker () =
    if !post_ibd_worker_ref = None then begin
      let w = Sync.Validation_worker.create () in
      post_ibd_worker_ref := Some w;
      Logs.info (fun m ->
        m "spawned persistent post-IBD validation worker Domain (#135)")
    end
  in
  (* Spawn the post-IBD worker eagerly if chain_state is ALREADY FullySynced
     at startup (i.e. this is a restart after a previous successful IBD).
     Without this, start_ibd never runs → the worker spawn at IBD-complete
     never fires → post-IBD BlockMsg listener uses the synchronous fallback,
     defeating the whole #135 step 3 win. *)
  if chain.sync_state = Sync.FullySynced then
    ensure_post_ibd_worker ();
  (* #135 step 3: serialize the post-IBD BlockMsg listener with an
     Lwt_mutex. Without this, the new `let%lwt vresult` yield in
     Sync.process_new_block lets a second BlockMsg arrival begin running
     while the first is still mutating chain_state — racing on
     state.blocks_synced / state.tip / Storage.ChainDB writes. The mutex
     queues subsequent BlockMsgs without serializing the underlying
     validation work (that still runs on the worker Domain while we hold
     the mutex — RPC handlers still get scheduled). *)
  let block_listener_mutex = Lwt_mutex.create () in

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
     we have mined or stored (e.g. after receiving our inv announcement).

     BIP-159 peer-served-blocks gate: when prune mode is on, refuse to
     serve blocks below tip - 288 (best-effort via in-memory header
     table).  Honest peers respecting our NODE_NETWORK_LIMITED bit
     should not request these. *)
  let min_blocks_to_keep = 288 in
  Peer_manager.add_listener peer_manager (fun msg peer ->
    match msg with
    | P2p.GetdataMsg items ->
      let prune_horizon =
        if config.prune > 0 then
          match chain.tip with
          | Some t when t.height > min_blocks_to_keep ->
            Some (t.height - min_blocks_to_keep)
          | _ -> None
        else None
      in
      let lookup_block hash =
        match Storage.ChainDB.get_block db hash with
        | None -> None
        | Some block ->
          (match prune_horizon with
           | Some horizon ->
             (match Sync.lookup_block_height chain hash with
              | Some h when h < horizon -> None
              | _ ->
                let w = Serialize.writer_create () in
                Serialize.serialize_block w block;
                Some (Serialize.writer_to_cstruct w))
           | None ->
             let w = Serialize.writer_create () in
             Serialize.serialize_block w block;
             Some (Serialize.writer_to_cstruct w))
      in
      let lookup_tx hash =
        match Mempool.get mempool hash with
        | None -> None
        | Some entry ->
          let w = Serialize.writer_create () in
          Serialize.serialize_transaction w entry.Mempool.tx;
          Some (Serialize.writer_to_cstruct w)
      in
      let tip_height = match chain.tip with
        | Some t -> t.height
        | None   -> 0
      in
      let lookup_block_height hash = Sync.lookup_block_height chain hash in
      Peer.handle_getdata peer items ~lookup_block ~lookup_tx
        ~tip_height ~lookup_block_height
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

  (* BIP-157 compact filter request handler.
     Serves getcfilters / getcfheaders / getcfcheckpt when
     --blockfilterindex=basic is active.  When the index is absent,
     these messages are silently dropped (same as Bitcoin Core when the
     index is disabled: PrepareBlockFilterRequest returns false and the
     function returns early).

     Core constants (net_processing.cpp):
       MAX_GETCFILTERS_SIZE  = 1000
       MAX_GETCFHEADERS_SIZE = 2000
       CFCHECKPT_INTERVAL    = 1000                                        *)
  let max_getcfilters_size = 1000 in
  let max_getcfheaders_size = 2000 in
  let cfcheckpt_interval = 1000 in
  (* FIX-78 (W121 BUG-1): BIP-157 protocol-violation disconnect channel.
     Core net_processing.cpp::PrepareBlockFilterRequest sets
     node.fDisconnect = true unconditionally on five distinct violation
     paths:
       (1) unsupported filter_type (line 3274)
       (2) unknown stop_hash (line 3286)
       (3) start_height > stop_height (line 3296)
       (4) range > max_height_diff (line 3302)
       (5) — for getcfilters / getcfheaders / getcfcheckpt collectively —
            NODE_COMPACT_FILTERS not in m_our_services (line 3274 path,
            because [supported_filter_type] is gated on that bit).
     The listener arms below previously logged "peer should be disconnected"
     but had no wired path to the peer-manager's disconnect API.  We thread
     [Peer.misbehaving peer 100 reason] which (a) increments the misbehavior
     score by 100 — reaching the ban/disconnect threshold immediately —
     and (b) calls [Peer.disconnect peer], which closes the socket
     (peer_message_loop next iteration sees state=Disconnected and exits).
     Score 100 (rather than just disconnect) mirrors how camlcoin elsewhere
     tracks accumulated misbehavior, and is the strongest signal we can
     emit for a single protocol violation.  Reference:
       bitcoin-core/src/net_processing.cpp:3262 PrepareBlockFilterRequest
       lib/peer.ml:1411 misbehaving (score >= 100 → disconnect)              *)
  let bip157_disconnect (peer : Peer.peer) (reason : string) : unit Lwt.t =
    (* FIX-78 disconnect-on-protocol-violation marker. The literal string
       is asserted by test/test_w121_compact_filters.ml's
       Fix78_disconnect_source_guard to forward-regress against accidental
       removal of any of the three listener-arm wirings below. *)
    Logs.info (fun m ->
      m "BIP-157 protocol violation from peer %d (%s): %s — disconnecting"
        peer.Peer.id peer.Peer.addr reason);
    Peer.misbehaving peer 100 reason
  in
  Peer_manager.add_listener peer_manager (fun msg peer ->
    match msg, bip157_index with
    | P2p.GetcfiltersMsg { filter_type = 0; start_height; stop_hash }, Some idx ->
      (* BIP-157 §getcfilters: send one cfilter per height in [start, stop].

         FIX-74: Anchor the height walk on the peer-supplied stop_hash via
         Sync.get_ancestor, mirroring Bitcoin Core's
         net_processing.cpp::PrepareBlockFilterRequest + GetAncestor.  Do
         NOT walk the active chain by height.  When the peer supplies a
         stale/orphan stop_hash, Core deliberately serves filters from
         THAT FORK (compact filters are stored by block hash regardless
         of fork membership) — we match that behaviour. *)
      let start_h = Int32.to_int start_height in
      (match Sync.get_header chain stop_hash with
       | None ->
         (* FIX-78: Core net_processing.cpp:3286 — unknown stop_hash sets
            node.fDisconnect = true. *)
         Lwt.async (fun () ->
           bip157_disconnect peer
             (Printf.sprintf "getcfilters unknown stop_hash %s"
                (Types.hash256_to_hex_display stop_hash)))
       | Some stop_index ->
         let stop_h = stop_index.Sync.height in
         if start_h > stop_h then
           (* FIX-78: Core net_processing.cpp:3296: node.fDisconnect = true *)
           Lwt.async (fun () ->
             bip157_disconnect peer
               (Printf.sprintf "getcfilters invalid range start=%d > stop=%d"
                  start_h stop_h))
         else if stop_h - start_h >= max_getcfilters_size then
           (* FIX-78: Core net_processing.cpp:3302: node.fDisconnect = true *)
           Lwt.async (fun () ->
             bip157_disconnect peer
               (Printf.sprintf "getcfilters range %d too large (max %d)"
                  (stop_h - start_h + 1) max_getcfilters_size))
         else begin
           (* Walk parent chain from stop_index, sending one cfilter per
              height in [start_h..stop_h].  Filter lookup is by the
              ancestor's block_hash, NOT by active-chain block-at-h. *)
           let all_ok = ref true in
           let h = ref start_h in
           while !h <= stop_h && !all_ok do
             (match Sync.get_ancestor chain stop_index !h with
              | None ->
                Logs.debug (fun m ->
                  m "BIP-157 getcfilters: ancestor missing at height %d" !h);
                all_ok := false
              | Some anc ->
                (match Block_index.read_filter idx.Block_index.filter_idx
                         anc.Sync.hash with
                 | None ->
                   Logs.debug (fun m ->
                     m "BIP-157 getcfilters: filter missing at height %d" !h);
                   all_ok := false
                 | Some bf ->
                   let filter_cstruct =
                     Cstruct.of_string bf.Block_index.filter.Block_index.encoded
                   in
                   Lwt.async (fun () ->
                     Peer.send_message peer
                       (P2p.CfilterMsg {
                          filter_type = 0;
                          block_hash = bf.Block_index.block_hash;
                          filter_data = filter_cstruct;
                        }))));
             incr h
           done
         end);
      Lwt.return_unit
    | P2p.GetcfheadersMsg { filter_type = 0; start_height; stop_hash }, Some idx ->
      (* BIP-157 §getcfheaders: send cfheaders for the range.

         FIX-74: anchor walk on stop_hash via Sync.get_ancestor instead of
         walking the active chain by height. *)
      let start_h = Int32.to_int start_height in
      (match Sync.get_header chain stop_hash with
       | None ->
         (* FIX-78: Core net_processing.cpp:3286 — unknown stop_hash sets
            node.fDisconnect = true. *)
         Lwt.async (fun () ->
           bip157_disconnect peer
             (Printf.sprintf "getcfheaders unknown stop_hash %s"
                (Types.hash256_to_hex_display stop_hash)))
       | Some stop_index ->
         let stop_h = stop_index.Sync.height in
         if start_h > stop_h then
           (* FIX-78: Core net_processing.cpp:3296: node.fDisconnect = true *)
           Lwt.async (fun () ->
             bip157_disconnect peer
               (Printf.sprintf "getcfheaders invalid range start=%d > stop=%d"
                  start_h stop_h))
         else if stop_h - start_h >= max_getcfheaders_size then
           (* FIX-78: Core net_processing.cpp:3302: node.fDisconnect = true *)
           Lwt.async (fun () ->
             bip157_disconnect peer
               (Printf.sprintf "getcfheaders range %d too large (max %d)"
                  (stop_h - start_h + 1) max_getcfheaders_size))
         else begin
           (* prev_filter_header is the filter header of the block at
              start_h - 1 along the stop_hash ancestry, or zero for
              genesis.  Walking the stop_hash ancestry — not the active
              chain — is required so that a peer querying an orphan fork
              receives the correct chain anchor for that fork. *)
           let prev_fh =
             if start_h = 0 then Types.zero_hash
             else
               match Sync.get_ancestor chain stop_index (start_h - 1) with
               | None -> Types.zero_hash
               | Some e ->
                 (match Block_index.get_filter_header idx.Block_index.filter_idx e.Sync.hash with
                  | Some h -> h
                  | None -> Types.zero_hash)
           in
           (* Collect filter hashes over [start_h..stop_h] via
              ancestor walk on stop_index. *)
           let hashes = ref [] in
           let all_ok = ref true in
           for h = start_h to stop_h do
             if !all_ok then
               match Sync.get_ancestor chain stop_index h with
               | None -> all_ok := false
               | Some e ->
                 (match Block_index.get_filter_entry idx.Block_index.filter_idx e.Sync.hash with
                  | None -> all_ok := false
                  | Some entry -> hashes := entry.Block_index.filter_hash :: !hashes)
           done;
           if !all_ok then begin
             Lwt.async (fun () ->
               Peer.send_message peer
                 (P2p.CfheadersMsg {
                    filter_type = 0;
                    stop_hash;
                    prev_filter_header = prev_fh;
                    filter_hashes = List.rev !hashes;
                  }))
           end
         end);
      Lwt.return_unit
    | P2p.GetcfcheckptMsg { filter_type = 0; stop_hash }, Some idx ->
      (* BIP-157 §getcfcheckpt: send filter headers at every CFCHECKPT_INTERVAL.

         FIX-74: anchor each checkpoint lookup on stop_index via
         Sync.get_ancestor — mirrors Core net_processing.cpp:3409. *)
      (match Sync.get_header chain stop_hash with
       | None ->
         (* FIX-78: Core net_processing.cpp:3286 — unknown stop_hash sets
            node.fDisconnect = true. *)
         Lwt.async (fun () ->
           bip157_disconnect peer
             (Printf.sprintf "getcfcheckpt unknown stop_hash %s"
                (Types.hash256_to_hex_display stop_hash)))
       | Some stop_index ->
         let stop_h = stop_index.Sync.height in
         let n_checkpts = stop_h / cfcheckpt_interval in
         let headers = ref [] in
         let all_ok = ref true in
         for i = 1 to n_checkpts do
           if !all_ok then begin
             let height = i * cfcheckpt_interval in
             match Sync.get_ancestor chain stop_index height with
             | None -> all_ok := false
             | Some e ->
               (match Block_index.get_filter_header idx.Block_index.filter_idx e.Sync.hash with
                | None -> all_ok := false
                | Some h -> headers := h :: !headers)
           end
         done;
         if !all_ok then
           Lwt.async (fun () ->
             Peer.send_message peer
               (P2p.CfcheckptMsg {
                  filter_type = 0;
                  stop_hash;
                  filter_headers = List.rev !headers;
                })));
      Lwt.return_unit
    | P2p.GetcfiltersMsg { filter_type; _ }, _
    | P2p.GetcfheadersMsg { filter_type; _ }, _
    | P2p.GetcfcheckptMsg { filter_type; _ }, _ ->
      (* FIX-78: Core net_processing.cpp:3271-3274 — when filter_type is not
         supported OR NODE_COMPACT_FILTERS is not in m_our_services, set
         node.fDisconnect = true and return.
         The arms above match filter_type = 0 AND Some idx. Falling
         through to here means either:
           (a) filter_type != 0 (unsupported type) — always a violation; or
           (b) bip157_index = None (NODE_COMPACT_FILTERS not advertised, so
               the peer shouldn't be sending these at all). *)
      let reason =
        if filter_type <> 0 then
          Printf.sprintf "BIP-157 unsupported filter_type=%d" filter_type
        else
          "BIP-157 request received but NODE_COMPACT_FILTERS not advertised"
      in
      bip157_disconnect peer reason
    | _ -> Lwt.return_unit);

  (* Register a listener for blocks received post-IBD (when ibd_state is None).
     This handles unsolicited blocks and blocks requested via inv/getdata. *)
  Peer_manager.add_listener peer_manager (fun msg _peer ->
    match msg with
    | P2p.BlockMsg block when !ibd_state_ref = None
                              && chain.sync_state = Sync.FullySynced ->
      let hash = Crypto.compute_block_hash block.Types.header in
      (* #135 step 3: pass post_ibd_worker so validation runs on its Domain
         and the Lwt main thread can serve RPC during the 0.5-3s window.
         Hold block_listener_mutex so two BlockMsg arrivals can't race on
         chain_state mutations across the worker-await yield. *)
      Lwt_mutex.with_lock block_listener_mutex (fun () ->
        let%lwt pnb_result =
          Sync.process_new_block ?worker:!post_ibd_worker_ref chain block in
        (match pnb_result with
         | Ok () ->
           (* Feed the fee estimator with confirmed block data *)
           (try Fee_estimation.process_block fee_estimator block chain.blocks_synced
            with _ -> ());
           (* W103 BUG-2 fix: expire stale orphans on block connect, mirroring
              Core's TxOrphanageImpl::EraseForBlock() + LimitOrphans() sequence.
              Transactions that are now confirmed or whose parents are still
              missing after 20 min are pruned from the pool. *)
           (let n = Mempool.expire_orphans mempool in
            if n > 0 then
              Logs.debug (fun m -> m "Expired %d stale orphan(s) on block connect" n));
           (* Announce the block to other peers if it advanced the tip *)
           Lwt.async (fun () ->
             Peer_manager.announce_block peer_manager block.Types.header hash);
           Lwt.return_unit
         | Error e ->
           Logs.debug (fun m ->
             m "Post-IBD block rejected: %s" e);
           Lwt.return_unit))
    | _ -> Lwt.return_unit);

  (* Transaction relay: accept incoming tx messages into the mempool and relay
     via inv to other peers. Also handle inv messages for tx announcements
     by requesting unknown transactions via getdata. *)
  Peer_manager.add_listener peer_manager (fun msg peer ->
    match msg with
    | P2p.TxMsg tx when chain.sync_state = Sync.FullySynced ->
      (* let%lwt so the Lwt.pause yields inside accept_to_memory_pool can
         interleave RPC handlers between tx accepts. Bug #134. *)
      let%lwt result = Mempool.accept_to_memory_pool mempool tx in
      if result.Mempool.atmp_accepted then begin
        Logs.info (fun m ->
          m "Accepted tx %s into mempool (fee=%Ld vsize=%d)"
            (Types.hash256_to_hex result.Mempool.atmp_txid)
            result.Mempool.atmp_fee result.Mempool.atmp_vsize);
        (* Wire fee estimator: track the accepted transaction so the estimator
           can observe how many blocks it waits before confirmation.
           fee_rate is in sat/vB (fee / vsize).  Guards out zero-vsize edge case.
           Fixes W114 G10 dead-helper.
           Core: CBlockPolicyEstimator::processTransaction called from
                 TransactionAddedToMempool, block_policy_estimator.cpp:683 *)
        (let fee_rate_sat_per_vb =
           if result.Mempool.atmp_vsize > 0 then
             Int64.to_float result.Mempool.atmp_fee
             /. float_of_int result.Mempool.atmp_vsize
           else 0.0
         in
         if fee_rate_sat_per_vb > 0.0 then
           Fee_estimation.track_transaction fee_estimator
             result.Mempool.atmp_txid fee_rate_sat_per_vb
             (Fee_estimation.current_height fee_estimator));
        (* Convert fee rate to sat/kvB for feefilter comparison *)
        let fee_rate_kvb =
          if result.Mempool.atmp_vsize > 0 then
            Int64.div (Int64.mul result.Mempool.atmp_fee 1000L)
              (Int64.of_int result.Mempool.atmp_vsize)
          else 0L
        in
        (* Compute wtxid once for the relay loop.
           BIP-339 / Core net_processing.cpp RelayTransaction:
             const uint256& hash{peer.m_wtxid_relay ? wtxid.ToUint256() : txid.ToUint256()}
           wtxid-relay peers must receive InvWtx (MSG_WTX=5) with the wtxid;
           legacy peers receive InvTx (MSG_TX=1) with the txid. *)
        let atmp_wtxid =
          (try Crypto.compute_wtxid tx with _ -> result.Mempool.atmp_txid)
        in
        let txid = result.Mempool.atmp_txid in
        (* Relay inv to all ready peers except the sender *)
        let ready = Peer_manager.get_ready_peers peer_manager in
        Lwt_list.iter_p (fun relay_peer ->
          if relay_peer.Peer.id <> peer.Peer.id
             && relay_peer.Peer.relay
             && not relay_peer.Peer.block_relay_only
             && fee_rate_kvb >= relay_peer.Peer.feefilter then
            Lwt.catch (fun () ->
              let (inv_type, hash) =
                if relay_peer.Peer.wtxid_relay then (P2p.InvWtx, atmp_wtxid)
                else (P2p.InvTx, txid)
              in
              Peer.send_message relay_peer
                (P2p.InvMsg [{ P2p.inv_type; hash }])
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
        if (iv.inv_type = P2p.InvTx || iv.inv_type = P2p.InvWtx
            || iv.inv_type = P2p.InvWitnessTx)
           && not (Mempool.contains mempool iv.hash) then
          Some { P2p.inv_type = P2p.InvWtx; hash = iv.hash }
        else
          None
      ) items in
      (* Core: MAX_GETDATA_SZ = 1000 (protocol.h:482) — batch outgoing
         getdata to avoid sending oversized messages when a peer announces
         more than 1000 inventory items in a single inv. *)
      let rec send_batches = function
        | [] -> Lwt.return_unit
        | reqs ->
          let batch = List.filteri (fun i _ -> i < P2p.max_getdata_count) reqs in
          let rest  = List.filteri (fun i _ -> i >= P2p.max_getdata_count) reqs in
          let%lwt () = Peer.send_message peer (P2p.GetdataMsg batch) in
          send_batches rest
      in
      if tx_requests <> [] then
        send_batches tx_requests
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
         Lwt_mutex.with_lock block_listener_mutex (fun () ->
           let%lwt pnb_result =
             Sync.process_new_block ~f_requested:true
               ?worker:!post_ibd_worker_ref chain block in
           (match pnb_result with
            | Ok () ->
              (try Fee_estimation.process_block fee_estimator block chain.blocks_synced
               with _ -> ());
              Lwt.async (fun () ->
                Peer_manager.announce_block peer_manager block.Types.header header_hash);
              Lwt.return_unit
            | Error e ->
              Logs.debug (fun m -> m "Reconstructed compact block rejected: %s" e);
              Lwt.return_unit))
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
            Lwt_mutex.with_lock block_listener_mutex (fun () ->
              let%lwt pnb_result =
                Sync.process_new_block ~f_requested:true
                  ?worker:!post_ibd_worker_ref chain block in
              (match pnb_result with
               | Ok () ->
                 (try Fee_estimation.process_block fee_estimator block chain.blocks_synced
                  with _ -> ());
                 Lwt.async (fun () ->
                   Peer_manager.announce_block peer_manager block.Types.header resp.block_hash);
                 Lwt.return_unit
               | Error e ->
                 Logs.debug (fun m -> m "Reconstructed block rejected: %s" e);
                 Lwt.return_unit))
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
      (* net_processing.cpp:4276-4303: MAX_BLOCKTXN_DEPTH=10 guard.
         If the requested block is within 10 of the tip, respond with a
         blocktxn message.  Otherwise send the full block — this forces the
         peer to receive all block data (anti-DoS: prevents cheap getblocktxn
         spam from triggering expensive disk reads and cheap responses). *)
      let gbt_tip_height = match chain.tip with
        | Some t -> t.height
        | None   -> 0
      in
      let block_height = Sync.lookup_block_height chain req.block_hash in
      let within_blocktxn_depth = match block_height with
        | Some h -> h >= gbt_tip_height - P2p.max_blocktxn_depth
        | None   -> false  (* unknown height → send full block *)
      in
      (* Look up the full block and respond *)
      (match Storage.ChainDB.get_block db req.block_hash with
       | Some block ->
         if within_blocktxn_depth then begin
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
         end else begin
           (* Block is too old; send full block instead of blocktxn *)
           Logs.debug (fun m ->
             m "getblocktxn: block > %d deep, sending full block instead"
               P2p.max_blocktxn_depth);
           Lwt.catch
             (fun () -> Peer.send_message peer (P2p.BlockMsg block))
             (fun _exn -> Lwt.return_unit)
         end
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
               Lwt.async (fun () -> Peer_manager.ban_peer peer_manager peer_id ())
             | `DisconnectOnly ->
               Lwt.async (fun () -> Peer_manager.remove_peer peer_manager peer_id))
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
        (* #135 step 3: spawn the persistent post-IBD validation worker now
           that the IBD worker has shut down. Post-IBD BlockMsg validation
           runs on this Domain so RPC handlers can interleave. *)
        ensure_post_ibd_worker ();
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
          (* W103 BUG-2 fix: expire stale orphans on every status tick (every
             30 s).  Core mirrors this via TxOrphanageImpl::LimitOrphans() which
             is triggered on every AddTx / EraseTx call; a periodic fallback is
             the simplest equivalent for our simpler time-based model.
             ORPHAN_TX_EXPIRE_TIME = 20 * 60 = 1200 s (matches mempool.ml). *)
          (let n = Mempool.expire_orphans mempool in
           if n > 0 then
             Logs.info (fun m -> m "Expired %d stale orphan(s) from pool" n));
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
    (* Phase 4b: flush + close the BIP-157 index. Must run before the
       databases are closed so any in-flight chain mutation has been
       observed; must run after IBD/post-IBD block listeners are
       quiesced (Peer_manager.stop above ensures no further connect
       blocks come in). Best-effort. *)
    (match bip157_index with
     | None -> ()
     | Some idx ->
       (try
         Block_index.close_bip157_index idx;
         Logs.info (fun m -> m "BIP-157: filter index flushed and closed")
       with exn ->
         Logs.warn (fun m ->
           m "BIP-157: close failed: %s" (Printexc.to_string exn))));
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
  Lwt.async (fun () ->
    Lwt.catch
      (fun () -> rest_thread)
      (fun exn ->
        Logs.warn (fun m ->
          m "rest_thread exited: %s" (Printexc.to_string exn));
        Lwt.return_unit));
  event_loop ()
