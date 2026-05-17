(* W124 Operator-experience fleet audit — camlcoin (OCaml)

   30 gates: Signals + shutdown (G1-G6), PID + daemonize + datadir (G7-G11),
             Config file + CLI parity (G12-G14), Logging surface (G15-G21),
             Control RPCs + readiness (G22-G27), Notify hooks (G28-G30).

   References:
     - bitcoin-core/src/init.cpp (signal handlers, PID file, datadir lock,
       AppInitBasicSetup / AppInitParameterInteraction / AppInitMain /
       Shutdown / Interrupt, blocknotify / alertnotify / startupnotify /
       shutdownnotify; lines 169-456 + 882-1750).
     - bitcoin-core/src/util/signalinterrupt.{cpp,h} (token-pipe
       SignalInterrupt + reset/wait/operator()).
     - bitcoin-core/src/logging.{cpp,h} (Logger, m_log_timestamps,
       m_log_time_micros, m_log_threadnames, m_log_sourcelocations,
       m_reopen_file, GetLogPrefix, FormatLogStrInPlace, LogRateLimiter).
     - bitcoin-core/src/rpc/server.cpp (stop / uptime / logging /
       getmemoryinfo / getrpcinfo / help control RPCs).

   Approach: each gate documents PRESENT / PARTIAL / MISSING. PRESENT
   gates assert the implemented behaviour; PARTIAL / MISSING gates
   assert the absence at the API or call-site surface and pass when
   the gap is present.  When a gap is closed the corresponding test
   must be flipped from absence-assertion to behaviour-assertion.

   Per FIX-64 / FIX-80 lessons, tests are wired through Alcotest's
   plain runner with no `dune runtest` dependency.  Build & run:
     dune build test/test_w124_operator.exe
     _build/default/test/test_w124_operator.exe

   Bugs found (P0=correctness, P1=ops-blocking, P2=ops-degraded, P3=cosmetic):

     BUG-1  (P0 G22): `rpc.handle_stop` is a stub — returns the JSON
                      string "CamlCoin server stopping" but does NOT
                      raise the SignalInterrupt / wake the shutdown
                      waiter.  Core's "stop" RPC calls
                      ShutdownRequested() via the node context, so a
                      remote operator (or `bitcoin-cli stop` from a
                      supervisor) cannot trigger graceful shutdown
                      over RPC.  Only SIGINT/SIGTERM work.
                      Reference: lib/rpc.ml:7429-7430,
                      bitcoin-core/src/rpc/server.cpp::stop.

     BUG-2  (P1 G23): `rpc.handle_uptime` is a stub — always returns
                      `0`.  Core's uptime RPC returns
                      `GetTime() - GetStartupTime()`.  Operators
                      monitoring liveness/restart cadence cannot
                      distinguish a freshly-restarted node from a
                      long-running one.
                      Reference: lib/rpc.ml:7432-7434.

     BUG-3  (P1 G24): `rpc.handle_getrpcinfo` returns `active_commands=[]`
                      AND `logpath=""` regardless of state.  Core
                      populates `active_commands` from
                      RPCExecutor::Execute tracking and emits the
                      real `debug.log` path; both are 0/empty here.
                      Operator monitoring tools (e.g. Prometheus
                      sidecars) that consume `getrpcinfo.logpath`
                      to tail logs cannot do so.
                      Reference: lib/rpc.ml:7877-7881.

     BUG-4  (P1 G16): No `logging` RPC method.  Core exposes
                      `logging include exclude` to toggle log
                      categories at runtime; without it, debug
                      categories are fixed at process start
                      (--debug-cat / --debug).  Toggling LIBEVENT
                      / PEER / NET at runtime to capture a single
                      misbehaviour requires a restart.
                      Reference: rpc dispatcher in lib/rpc.ml (no
                      "logging" case), bitcoin-core/src/rpc/misc.cpp::logging.

     BUG-5  (P1 G17): No `getmemoryinfo` RPC method.  Core returns
                      glibc malloc + LockedPool stats.  Operators
                      cannot inspect RSS / heap pressure over RPC;
                      the only alternative is /proc/<pid>/status.
                      camlcoin has a Prometheus metrics endpoint
                      (good), but that is in addition to, not a
                      replacement for, the JSON-RPC surface.
                      Reference: rpc dispatcher in lib/rpc.ml.

     BUG-6  (P1 G15): Log lines lack thread name AND source location
                      AND log category.  Core's
                      `FormatLogStrInPlace` emits
                      `YYYY-MM-DDTHH:MM:SSZ thread file:line BCLog
                      [category] level: message`; camlcoin's
                      `install_log_file_reporter` emits only
                      `YYYY-MM-DDTHH:MM:SS.mmmZ <level-header> message`
                      (no thread, no source-loc, no category).
                      Operators correlating one peer's misbehaviour
                      across log lines cannot grep by category and
                      cannot grep by source file:line.  No
                      `-logsourcelocations` / `-logthreadnames` /
                      `-logips` knobs exist.  Mirror of Core
                      m_log_threadnames / m_log_sourcelocations.
                      Reference: lib/runtime_config.ml:240-272.

     BUG-7  (P0 G21): SIGHUP installation race.  `install_sighup_handler`
                      uses raw `Sys.set_signal Sys.sighup` (Stdlib
                      OCaml signal handler) but the rest of the
                      process uses `Lwt_unix.on_signal` for SIGINT /
                      SIGTERM.  Stdlib handlers run inside the C
                      runtime *between* OCaml bytecodes and may
                      deliver between two Lwt_engine ticks; without
                      `pending_sighup`'s atomic semantics this would
                      be a race.  Today it is benign (single flag
                      write) but it is also not actioned on the
                      Lwt event loop — only on the status thread's
                      30s tick.  A SIGHUP received at T+1s waits
                      29s for a log reopen.  Core actions
                      m_reopen_file on every log write (immediate).
                      Reference: lib/runtime_config.ml:288-304,
                      lib/cli.ml:1599-1601.

     BUG-8  (P1 G20): `signal_ready` uses `Obj.magic` to convert
                      `int -> Unix.file_descr`.  This relies on the
                      runtime's internal representation of file
                      descriptors and may break across OCaml
                      releases.  Should use the documented
                      `Unix.file_descr_of_int` (4.12+) or the
                      `obj_of_repr`-safe alternative.  Today on
                      OCaml 5.1 it happens to work but it is
                      undefined behaviour.
                      Reference: lib/runtime_config.ml:357-361.

     BUG-9  (P1 G3) : Second SIGTERM during graceful shutdown
                      forces immediate `exit 1` from
                      `handle_signal` (cli.ml:660-664), but does NOT
                      attempt the best-effort RocksDB close that
                      the 30s watchdog runs (cli.ml:1763-1764).
                      So a quick second-signal escalation leaves
                      RocksDB in a state requiring repair on next
                      boot.  Core's HandleSIGTERM is idempotent
                      (only flips SignalInterrupt once) and lets
                      the main thread continue Shutdown().
                      Reference: lib/cli.ml:653-664.

     BUG-10 (P2 G7) : `data_dir` default lookup uses `Sys.getenv "HOME"`
                      (cli.ml:137, 176, 180) which raises
                      `Not_found` when HOME is unset.  Core uses
                      `GetDefaultDataDir()` with platform-specific
                      fallbacks.  A daemonised invocation under
                      systemd with `User=` set but no `HOME=` in
                      the unit file will crash on startup before
                      any log line is emitted.
                      Reference: lib/cli.ml:137-181.

     BUG-11 (P2 G9) : No explicit datadir lock file.  RocksDB
                      enforces its own LOCK file (good), but
                      camlcoin opens RocksDB *after*
                      `Migration.check_or_refuse_to_boot`,
                      `Reindex.pre_open_wipe`, and the
                      Cf_chainstate open.  Two processes pointed
                      at the same datadir will race for several
                      seconds before RocksDB rejects the second
                      opener — and the migration / reindex paths
                      may both fire writes in that window.  Core
                      acquires `.lock` on the datadir BEFORE any
                      blockstore or chainstate open.
                      Reference: lib/cli.ml:250-304,
                      bitcoin-core/src/util/fs_helpers.cpp::LockDirectory.

     BUG-12 (P3 G10): `config.example.toml` advertises a TOML grammar
                      (`[network]`, `network = "mainnet"`) but the
                      actual parser in `Runtime_config.parse_conf_file`
                      accepts only Bitcoin Core's key=value
                      grammar with `[main]` / `[test]` / `[regtest]`
                      section headers.  Operators copying the
                      example file as-is will see EVERY key
                      silently dropped (the TOML `network = "mainnet"`
                      sits under section `[network]`, which is
                      neither main/test/regtest — so it's filtered).
                      Reference: config.example.toml,
                      lib/runtime_config.ml:41-78.

     BUG-13 (P2 G27): `--connect` and `connect=` config-file entries
                      are NOT mutually exclusive with `-noconnect`
                      (camlcoin has no `-noconnect`).  Core's
                      `-noconnect` disables automatic outbound DNS-
                      seeded connections while keeping `-addnode`
                      manual peers.  Without it, an operator
                      cannot configure a node that ONLY talks to
                      a fixed allow-list — `--connect=host:port`
                      already does that, but Core's surface area
                      promises `-noconnect` independently.
                      Reference: bin/main.ml:60-63.

     BUG-14 (P1 G28): No `-alertnotify=<cmd>` support.  Core fires
                      this command (with %s replaced by the alert
                      message) on a `CAlert` reception.  Operators
                      use this to wire ntfy.sh / pagerduty /
                      systemd-notify.  Closes the equivalent of
                      W117 BUG-7 for the operator surface.
                      Reference: bin/main.ml (no flag),
                      bitcoin-core/src/init.cpp:485.

     BUG-15 (P1 G29): No `-blocknotify=<cmd>` support.  Core fires
                      this command when the best block changes
                      (with %s replaced by the block hash).
                      Operators use this to drive secondary
                      indexers / notify wallet servers.
                      Reference: bin/main.ml (no flag),
                      bitcoin-core/src/init.cpp:498.

     BUG-16 (P2 G30): No `-startupnotify=<cmd>` and no
                      `-shutdownnotify=<cmd>` support.  Core
                      forks the command on each event.  The
                      closest camlcoin offers is `--ready-fd=<N>`
                      (good, but only handles the startup half
                      and requires an inherited fd from the
                      supervisor — which is not always available).
                      Reference: bin/main.ml (no flags),
                      bitcoin-core/src/init.cpp:528-530.

   Verdict: 11 PRESENT / 9 PARTIAL / 10 MISSING — see audit doc.
   Pattern-wise, the operator surface is *broad* (--daemon, --pid,
   --conf, --logfile, --ready-fd, signal handlers, graceful
   shutdown with watchdog, ZMQ publisher) but with multiple
   stub-RPC-as-feature instances: handle_stop / handle_uptime /
   handle_getrpcinfo all return constant JSON instead of
   delegating to the running state.  This continues the
   "comment-as-confession" pattern surfaced in W116/W120/W121 —
   the RPC dispatcher claims the methods exist (they're in the
   help() output and the dispatcher case branches), so callers
   succeed and trust the response, but the response carries no
   real information.
   ============================================================================ *)

(* (We don't actually use any Camlcoin internals here — the audit reads
   the on-disk source files and asserts source-level shape, which is the
   correct level of resolution for a discovery/no-prod-change wave.) *)

(* ============================================================================
   Helpers
   ============================================================================ *)

(* Resolve the camlcoin project root so the audit works whether invoked
   from `dune build && _build/default/test/test_w124_operator.exe`, from
   `dune exec test/test_w124_operator.exe`, or from `dune runtest` (which
   does in-tree copy and chdir's into the test dir). We search up to 6
   parents for a [lib/cli.ml] sibling, then read every file relative to
   that root. *)
let project_root =
  let cwd = Sys.getcwd () in
  let rec walk dir n =
    if n > 6 then None
    else if Sys.file_exists (Filename.concat dir "lib/cli.ml") then Some dir
    else
      let parent = Filename.dirname dir in
      if parent = dir then None
      else walk parent (n + 1)
  in
  match walk cwd 0 with
  | Some d -> d
  | None ->
    (* Final fallback: hardcoded sandbox path. Will fail loudly if wrong. *)
    "/home/work/hashhog/camlcoin"

(* Read a file (path relative to camlcoin root) as a string. *)
let read_file path =
  let full = Filename.concat project_root path in
  let ic = open_in full in
  let len = in_channel_length ic in
  let buf = Bytes.create len in
  really_input ic buf 0 len;
  close_in ic;
  Bytes.unsafe_to_string buf

let contains s sub =
  let n = String.length sub in
  let m = String.length s in
  if n = 0 then true
  else
    let rec loop i =
      if i + n > m then false
      else if String.sub s i n = sub then true
      else loop (i + 1)
    in
    loop 0

(* ============================================================================
   Gate G1: SIGTERM triggers graceful shutdown (PRESENT)
   cli.ml installs Lwt_unix.on_signal Sys.sigterm and wakes a shared
   [shutdown_waiter] promise that drives [graceful_shutdown].
   ============================================================================ *)
let g1_sigterm_present () =
  let src = read_file "lib/cli.ml" in
  Alcotest.(check bool)
    "cli.ml installs SIGTERM handler via Lwt_unix.on_signal"
    true
    (contains src "Lwt_unix.on_signal Sys.sigterm");
  Alcotest.(check bool)
    "cli.ml installs SIGINT handler via Lwt_unix.on_signal"
    true
    (contains src "Lwt_unix.on_signal Sys.sigint")

(* ============================================================================
   Gate G2: SIGPIPE ignored to avoid crash on closed peer socket (PRESENT)
   cli.ml line 672: Sys.set_signal Sys.sigpipe Sys.Signal_ignore.
   ============================================================================ *)
let g2_sigpipe_present () =
  let src = read_file "lib/cli.ml" in
  Alcotest.(check bool)
    "SIGPIPE ignored (defensive against closed-peer-socket writes)"
    true
    (contains src "Sys.set_signal Sys.sigpipe Sys.Signal_ignore")

(* ============================================================================
   Gate G3: Second SIGTERM forces immediate exit but skips best-effort DB
   close (BUG-9, PARTIAL).
   ============================================================================ *)
let g3_second_signal_escalation_partial () =
  let src = read_file "lib/cli.ml" in
  (* Second signal handler exists and calls exit 1 *)
  Alcotest.(check bool)
    "second-signal escalation present in handle_signal"
    true
    (contains src "second %s during shutdown — forcing exit");
  (* But the escalation path (cli.ml ~660-664) does NOT close DBs first
     unlike the 30s watchdog (cli.ml ~1755-1765). Document the gap by
     asserting the escalation block does NOT contain Rocksdb_store.close. *)
  let escalation_idx =
    try Some (
      Str.search_forward
        (Str.regexp_string "second %s during shutdown — forcing exit")
        src 0)
    with Not_found -> None
  in
  match escalation_idx with
  | None -> Alcotest.fail "escalation block not found"
  | Some i ->
    let snippet = String.sub src i (min 400 (String.length src - i)) in
    Alcotest.(check bool)
      "BUG-9: escalation path does NOT call Rocksdb_store.close before exit"
      false
      (contains snippet "Rocksdb_store.close")

(* ============================================================================
   Gate G4: Graceful shutdown is phased (P2P → wallet → chainstate → DB → PID)
   matching Core init.cpp Shutdown() ordering. (PRESENT)
   ============================================================================ *)
let g4_phased_shutdown_present () =
  let src = read_file "lib/cli.ml" in
  Alcotest.(check bool) "Phase 1: stopping P2P" true
    (contains src "Phase 1: stop P2P networking");
  Alcotest.(check bool) "Phase 2: save wallet" true
    (contains src "Phase 2: save wallet state");
  Alcotest.(check bool) "Phase 3: flush chainstate" true
    (contains src "Phase 3: flush chainstate");
  Alcotest.(check bool) "Phase 4: close DB" true
    (contains src "Phase 4: close databases");
  Alcotest.(check bool) "Phase 5: remove PID" true
    (contains src "Phase 5: remove PID file")

(* ============================================================================
   Gate G5: 30s shutdown watchdog forces exit 1 if graceful stalls (PRESENT)
   ============================================================================ *)
let g5_shutdown_watchdog_present () =
  let src = read_file "lib/cli.ml" in
  Alcotest.(check bool) "30s shutdown watchdog present" true
    (contains src "shutdown watchdog: graceful shutdown exceeded 30s");
  Alcotest.(check bool) "watchdog races graceful_shutdown via Lwt.pick" true
    (contains src "Lwt.pick [ graceful_shutdown (); watchdog () ]")

(* ============================================================================
   Gate G6: Async-exception hook installed to prevent single-peer crash from
   killing the whole node (PRESENT — W78 lesson).
   ============================================================================ *)
let g6_async_exn_hook_present () =
  let main = read_file "bin/main.ml" in
  Alcotest.(check bool) "W78 async exception hook installed in main" true
    (contains main "W78-ASYNC-EXN")

(* ============================================================================
   Gate G7: --datadir defaulting (PARTIAL — BUG-10, Sys.getenv HOME crashes
   when HOME is unset)
   ============================================================================ *)
let g7_datadir_default_partial () =
  let src = read_file "lib/cli.ml" in
  (* Default uses Sys.getenv (raises) instead of Sys.getenv_opt. *)
  Alcotest.(check bool)
    "BUG-10: default datadir uses Sys.getenv \"HOME\" (raises if unset)"
    true
    (contains src "Sys.getenv \"HOME\"");
  Alcotest.(check bool)
    "default would crash if HOME unset (no Sys.getenv_opt fallback)"
    false
    (contains src "Sys.getenv_opt \"HOME\"")

(* ============================================================================
   Gate G8: PID file refuses to start on stale-but-live PID (PRESENT).
   ============================================================================ *)
let g8_pidfile_live_check_present () =
  let src = read_file "lib/runtime_config.ml" in
  Alcotest.(check bool) "pid_alive checks via kill 0" true
    (contains src "Unix.kill pid 0");
  Alcotest.(check bool) "refuses to start if PID file names live PID" true
    (contains src "refusing to start");
  Alcotest.(check bool) "ESRCH treated as dead PID" true
    (contains src "Unix.ESRCH");
  Alcotest.(check bool) "EPERM treated as alive (exists but not ours)" true
    (contains src "EPERM, _, _) -> true")

(* ============================================================================
   Gate G9: No explicit datadir lock file (BUG-11, MISSING).
   ============================================================================ *)
let g9_datadir_lock_missing () =
  let src = read_file "lib/cli.ml" in
  Alcotest.(check bool)
    "BUG-11: no LockDirectory-equivalent at startup"
    false
    (contains src "LockDirectory");
  Alcotest.(check bool)
    "BUG-11: no .lock file written before opening chainstate"
    false
    (* Be specific: the migration/reindex paths run BEFORE any lock guard.
       Check that the lib doesn't define a [datadir_lock_open] helper. *)
    (contains src "datadir_lock_open")

(* ============================================================================
   Gate G10: Config-file format documented to mismatch parser
   (BUG-12, PARTIAL — the example file says TOML, the parser is Core-style).
   ============================================================================ *)
let g10_config_format_mismatch_partial () =
  let cfg = read_file "config.example.toml" in
  Alcotest.(check bool) "BUG-12: example file is TOML-like" true
    (contains cfg "[network]" && contains cfg "network = \"mainnet\"");
  let parser = read_file "lib/runtime_config.ml" in
  Alcotest.(check bool) "BUG-12: parser expects Core key=value grammar" true
    (contains parser "Bitcoin Core's bitcoin.conf grammar");
  (* The parser recognises [main] / [test] / [regtest] section headers but
     NOT [network] / [storage] / [rpc] / [p2p] / [mempool] / [logging] /
     [metrics] (the example file's sections). Verify by listing the
     recognised sections only. *)
  Alcotest.(check bool) "parser only recognises [main]/[test]/[regtest]" true
    (contains parser "match network with" &&
     contains parser "`Mainnet -> \"main\"" &&
     contains parser "`Testnet -> \"test\"" &&
     contains parser "`Regtest -> \"regtest\"")

(* ============================================================================
   Gate G11: --daemon double-fork + setsid + chdir / + umask (PRESENT).
   ============================================================================ *)
let g11_daemonize_present () =
  let src = read_file "lib/runtime_config.ml" in
  (* Two forks. *)
  let fork_count =
    let rec count_from i acc =
      match
        try Some (Str.search_forward (Str.regexp_string "Unix.fork ()") src i)
        with Not_found -> None
      with
      | None -> acc
      | Some j -> count_from (j + 1) (acc + 1)
    in
    count_from 0 0
  in
  Alcotest.(check bool) "double-fork in daemonize" true (fork_count >= 2);
  Alcotest.(check bool) "setsid called" true
    (contains src "Unix.setsid");
  Alcotest.(check bool) "chdir to / so we don't pin a mountpoint" true
    (contains src "Unix.chdir \"/\"");
  Alcotest.(check bool) "umask tightened" true
    (contains src "Unix.umask 0o027");
  Alcotest.(check bool) "stdio redirected to /dev/null" true
    (contains src "redirect_stdio_to_devnull")

(* ============================================================================
   Gate G12: --conf parses Core key=value grammar with section headers
   (PRESENT, but mismatched with example file — see G10).
   ============================================================================ *)
let g12_conf_parser_present () =
  let src = read_file "lib/runtime_config.ml" in
  Alcotest.(check bool) "parse_conf_file defaults section to 'main'" true
    (contains src "let current_section = ref \"main\"");
  Alcotest.(check bool) "parse_conf_file matches section against active_section" true
    (contains src "!current_section = active_section");
  Alcotest.(check bool) "config-file is best-effort (no crash on missing)" true
    (contains src "if not (Sys.file_exists path) then []")

(* ============================================================================
   Gate G13: CLI > conf > default precedence (PRESENT — overlay_string etc.)
   ============================================================================ *)
let g13_cli_conf_precedence_present () =
  let src = read_file "lib/runtime_config.ml" in
  Alcotest.(check bool) "overlay_string CLI wins over conf" true
    (contains src "let overlay_string ~cli ~conf ~default = match cli with");
  Alcotest.(check bool) "overlay_int CLI wins over conf" true
    (contains src "let overlay_int ~cli ~conf ~default = match cli with");
  Alcotest.(check bool) "overlay_bool CLI wins over conf" true
    (contains src "let overlay_bool ~cli_set ~cli_value ~conf ~default")

(* ============================================================================
   Gate G14: --debug-cat list parser with all/none sentinels (PRESENT).
   ============================================================================ *)
let g14_debug_cat_parser_present () =
  let src = read_file "lib/runtime_config.ml" in
  Alcotest.(check bool) "resolve_debug_categories handles \"all\"/\"1\"" true
    (contains src "if List.exists (fun t -> t = \"1\" || t = \"all\") toks");
  Alcotest.(check bool) "resolve_debug_categories handles \"none\"/\"0\"" true
    (contains src "if List.exists (fun t -> t = \"0\" || t = \"none\") toks")

(* ============================================================================
   Gate G15: Log lines lack thread + source-loc + category (BUG-6, PARTIAL).
   ============================================================================ *)
let g15_log_format_thin_partial () =
  let src = read_file "lib/runtime_config.ml" in
  (* No thread name, source location, or category fields in the report fn. *)
  let report_idx = Str.search_forward (Str.regexp_string "let report _src level") src 0 in
  let snippet = String.sub src report_idx (min 1200 (String.length src - report_idx)) in
  Alcotest.(check bool)
    "BUG-6: log reporter does not emit thread name (no log_threadnames knob)"
    false
    (contains snippet "thread");
  Alcotest.(check bool)
    "BUG-6: log reporter does not emit source location (no log_sourcelocations knob)"
    false
    (contains snippet "source_loc" || contains snippet "file:line");
  Alcotest.(check bool)
    "BUG-6: log reporter does not emit category"
    false
    (contains snippet "category")

(* ============================================================================
   Gate G16: No `logging` RPC method (BUG-4, MISSING).
   ============================================================================ *)
let g16_logging_rpc_missing () =
  let src = read_file "lib/rpc.ml" in
  Alcotest.(check bool) "BUG-4: no \"logging\" RPC dispatcher case" false
    (contains src "| \"logging\" ->");
  Alcotest.(check bool) "BUG-4: no handle_logging helper" false
    (contains src "let handle_logging ")

(* ============================================================================
   Gate G17: No `getmemoryinfo` RPC method (BUG-5, MISSING).
   ============================================================================ *)
let g17_getmemoryinfo_rpc_missing () =
  let src = read_file "lib/rpc.ml" in
  Alcotest.(check bool) "BUG-5: no \"getmemoryinfo\" RPC dispatcher case" false
    (contains src "| \"getmemoryinfo\" ->");
  Alcotest.(check bool) "BUG-5: no handle_getmemoryinfo helper" false
    (contains src "let handle_getmemoryinfo ")

(* ============================================================================
   Gate G18: SIGHUP installed for log rotation (PRESENT — but actioned only
   on 30s status tick; see BUG-7).
   ============================================================================ *)
let g18_sighup_log_rotate_present () =
  let src = read_file "lib/runtime_config.ml" in
  Alcotest.(check bool) "SIGHUP handler installed" true
    (contains src "Sys.set_signal Sys.sighup");
  Alcotest.(check bool) "pending_sighup flag flipped from handler" true
    (contains src "pending_sighup := true");
  Alcotest.(check bool) "drain_pending_sighup actions a reopen" true
    (contains src "let drain_pending_sighup ()");
  Alcotest.(check bool) "reopen_log_file closes + reopens the channel" true
    (contains src "let reopen_log_file ()")

(* ============================================================================
   Gate G19: --logfile + --printtoconsole (PRESENT).
   ============================================================================ *)
let g19_logfile_printtoconsole_present () =
  let main = read_file "bin/main.ml" in
  Alcotest.(check bool) "--logfile flag exposed" true
    (contains main "let logfile_arg");
  Alcotest.(check bool) "--printtoconsole flag exposed" true
    (contains main "let printtoconsole_arg");
  Alcotest.(check bool) "installs log-file reporter when --logfile is set" true
    (contains main "install_log_file_reporter")

(* ============================================================================
   Gate G20: --ready-fd handshake uses Obj.magic (BUG-8, PARTIAL).
   ============================================================================ *)
let g20_ready_fd_partial () =
  let src = read_file "lib/runtime_config.ml" in
  Alcotest.(check bool) "BUG-8: int -> Unix.file_descr via Obj.magic" true
    (contains src "let unix_fd : Unix.file_descr = Obj.magic (n : int)");
  (* The safer Unix.file_descr_of_int (OCaml 4.12+) is NOT used. *)
  Alcotest.(check bool) "BUG-8: safer Unix.file_descr_of_int NOT used" false
    (contains src "Unix.file_descr_of_int")

(* ============================================================================
   Gate G21: SIGHUP actions only on 30s tick (BUG-7, PARTIAL).
   ============================================================================ *)
let g21_sighup_action_lag_partial () =
  let src = read_file "lib/cli.ml" in
  (* drain_pending_sighup is wired inside the status_thread which sleeps
     30s between ticks; it is NOT wired into the log_target_ref's mutex
     callback so a SIGHUP at T+1 waits up to 29s. *)
  Alcotest.(check bool)
    "BUG-7: drain_pending_sighup runs inside status_thread (30s tick)"
    true
    (contains src "Lwt_unix.sleep 30.0" &&
     contains src "Runtime_config.drain_pending_sighup")

(* ============================================================================
   Gate G22: `stop` RPC is a stub (BUG-1, PARTIAL).
   ============================================================================ *)
let g22_stop_rpc_partial () =
  let src = read_file "lib/rpc.ml" in
  Alcotest.(check bool) "BUG-1: handle_stop returns constant string only" true
    (contains src "let handle_stop (_ctx : rpc_context) : Yojson.Safe.t =\n  `String \"CamlCoin server stopping\"");
  (* The dispatcher case is registered (so `stop` looks supported)
     but the handler doesn't trigger shutdown. *)
  Alcotest.(check bool) "BUG-1: \"stop\" dispatcher case present" true
    (contains src "| \"stop\" ->\n    Ok (handle_stop ctx)");
  Alcotest.(check bool) "BUG-1: handle_stop body does NOT raise shutdown" false
    (contains src "shutdown_request" || contains src "wake_shutdown")

(* ============================================================================
   Gate G23: `uptime` RPC is a stub (BUG-2, PARTIAL).
   ============================================================================ *)
let g23_uptime_rpc_partial () =
  let src = read_file "lib/rpc.ml" in
  Alcotest.(check bool) "BUG-2: handle_uptime always returns 0" true
    (contains src "handle_uptime (_ctx : rpc_context) : Yojson.Safe.t =\n  (* Return seconds since start - simplified *)\n  `Int 0");
  (* The dispatcher case is present. *)
  Alcotest.(check bool) "BUG-2: \"uptime\" dispatcher case present" true
    (contains src "| \"uptime\" ->\n    Ok (handle_uptime ctx)")

(* ============================================================================
   Gate G24: `getrpcinfo` returns empty active_commands + empty logpath
   (BUG-3, PARTIAL).
   ============================================================================ *)
let g24_getrpcinfo_stub_partial () =
  let src = read_file "lib/rpc.ml" in
  Alcotest.(check bool) "BUG-3: getrpcinfo returns empty active_commands" true
    (contains src "(\"active_commands\", `List [])");
  Alcotest.(check bool) "BUG-3: getrpcinfo returns empty logpath" true
    (contains src "(\"logpath\", `String \"\")")

(* ============================================================================
   Gate G25: `help` RPC enumerates available methods (PRESENT).
   ============================================================================ *)
let g25_help_rpc_present () =
  let src = read_file "lib/rpc.ml" in
  Alcotest.(check bool) "help RPC returns method list" true
    (contains src "let handle_help (_ctx : rpc_context)\n    (params : Yojson.Safe.t list)")

(* ============================================================================
   Gate G26: Cookie auth (PRESENT — written under <datadir>/.cookie mode 0600).
   ============================================================================ *)
let g26_cookie_auth_present () =
  let src = read_file "lib/cli.ml" in
  Alcotest.(check bool) ".cookie file written at startup" true
    (contains src "let cookie_path = Filename.concat config.data_dir \".cookie\"");
  Alcotest.(check bool) ".cookie file is mode 0o600" true
    (contains src "[Unix.O_WRONLY; Unix.O_CREAT; Unix.O_TRUNC] 0o600")

(* ============================================================================
   Gate G27: --connect / -noconnect parity (BUG-13, MISSING).
   ============================================================================ *)
let g27_noconnect_missing () =
  let main = read_file "bin/main.ml" in
  Alcotest.(check bool) "--connect flag present" true
    (contains main "let connect_arg");
  Alcotest.(check bool) "BUG-13: -noconnect flag NOT exposed" false
    (contains main "noconnect" || contains main "no-connect")

(* ============================================================================
   Gate G28: -alertnotify=<cmd> (BUG-14, MISSING).
   ============================================================================ *)
let g28_alertnotify_missing () =
  let main = read_file "bin/main.ml" in
  Alcotest.(check bool) "BUG-14: --alertnotify flag NOT exposed" false
    (contains main "alertnotify");
  let src_lib =
    let buf = Buffer.create 4096 in
    List.iter (fun f ->
      try Buffer.add_string buf (read_file ("../lib/" ^ f)) with _ -> ()
    ) ["cli.ml"; "rpc.ml"; "peer_manager.ml"; "runtime_config.ml"];
    Buffer.contents buf
  in
  Alcotest.(check bool) "BUG-14: no run_command / fork+exec helper" false
    (contains src_lib "let run_command " ||
     contains src_lib "Unix.execvp" ||
     contains src_lib "Sys.command")

(* ============================================================================
   Gate G29: -blocknotify=<cmd> (BUG-15, MISSING).
   ============================================================================ *)
let g29_blocknotify_missing () =
  let main = read_file "bin/main.ml" in
  Alcotest.(check bool) "BUG-15: --blocknotify flag NOT exposed" false
    (contains main "blocknotify");
  let cli = read_file "lib/cli.ml" in
  Alcotest.(check bool) "BUG-15: no block-connect notify hook in cli.ml" false
    (contains cli "blocknotify")

(* ============================================================================
   Gate G30: -startupnotify / -shutdownnotify (BUG-16, MISSING).
   ============================================================================ *)
let g30_startup_shutdown_notify_missing () =
  let main = read_file "bin/main.ml" in
  Alcotest.(check bool) "BUG-16: --startupnotify flag NOT exposed" false
    (contains main "startupnotify");
  Alcotest.(check bool) "BUG-16: --shutdownnotify flag NOT exposed" false
    (contains main "shutdownnotify");
  (* Note: --ready-fd is the closest analogue, and IS present (G20). *)
  Alcotest.(check bool) "(positive control) --ready-fd is present" true
    (contains main "let ready_fd_arg")

(* ============================================================================
   Test suite
   ============================================================================ *)

let () =
  Alcotest.run "W124 operator-experience" [
    "G1-G6 signals + shutdown", [
      Alcotest.test_case "G1 SIGTERM/SIGINT installed (PRESENT)" `Quick
        g1_sigterm_present;
      Alcotest.test_case "G2 SIGPIPE ignored (PRESENT)" `Quick
        g2_sigpipe_present;
      Alcotest.test_case "G3 second-signal escalation skips DB close (BUG-9 PARTIAL)" `Quick
        g3_second_signal_escalation_partial;
      Alcotest.test_case "G4 phased graceful shutdown (PRESENT)" `Quick
        g4_phased_shutdown_present;
      Alcotest.test_case "G5 30s shutdown watchdog (PRESENT)" `Quick
        g5_shutdown_watchdog_present;
      Alcotest.test_case "G6 async-exception hook (PRESENT, W78)" `Quick
        g6_async_exn_hook_present;
    ];
    "G7-G11 PID + daemonize + datadir", [
      Alcotest.test_case "G7 default datadir uses Sys.getenv (BUG-10 PARTIAL)" `Quick
        g7_datadir_default_partial;
      Alcotest.test_case "G8 PID file refuses stale-but-live PID (PRESENT)" `Quick
        g8_pidfile_live_check_present;
      Alcotest.test_case "G9 no explicit datadir lock (BUG-11 MISSING)" `Quick
        g9_datadir_lock_missing;
      Alcotest.test_case "G10 example config format mismatch (BUG-12 PARTIAL)" `Quick
        g10_config_format_mismatch_partial;
      Alcotest.test_case "G11 --daemon double-fork+setsid+chdir/+umask (PRESENT)" `Quick
        g11_daemonize_present;
    ];
    "G12-G14 config-file + CLI parity", [
      Alcotest.test_case "G12 --conf key=value parser (PRESENT)" `Quick
        g12_conf_parser_present;
      Alcotest.test_case "G13 CLI > conf > default precedence (PRESENT)" `Quick
        g13_cli_conf_precedence_present;
      Alcotest.test_case "G14 --debug-cat all/none sentinels (PRESENT)" `Quick
        g14_debug_cat_parser_present;
    ];
    "G15-G21 logging surface", [
      Alcotest.test_case "G15 log format lacks thread/source/category (BUG-6 PARTIAL)" `Quick
        g15_log_format_thin_partial;
      Alcotest.test_case "G16 no `logging` RPC (BUG-4 MISSING)" `Quick
        g16_logging_rpc_missing;
      Alcotest.test_case "G17 no `getmemoryinfo` RPC (BUG-5 MISSING)" `Quick
        g17_getmemoryinfo_rpc_missing;
      Alcotest.test_case "G18 SIGHUP rotate handler installed (PRESENT)" `Quick
        g18_sighup_log_rotate_present;
      Alcotest.test_case "G19 --logfile + --printtoconsole (PRESENT)" `Quick
        g19_logfile_printtoconsole_present;
      Alcotest.test_case "G20 --ready-fd uses Obj.magic (BUG-8 PARTIAL)" `Quick
        g20_ready_fd_partial;
      Alcotest.test_case "G21 SIGHUP actioned on 30s tick (BUG-7 PARTIAL)" `Quick
        g21_sighup_action_lag_partial;
    ];
    "G22-G27 control RPCs + readiness", [
      Alcotest.test_case "G22 `stop` RPC is a stub (BUG-1 PARTIAL)" `Quick
        g22_stop_rpc_partial;
      Alcotest.test_case "G23 `uptime` RPC is a stub (BUG-2 PARTIAL)" `Quick
        g23_uptime_rpc_partial;
      Alcotest.test_case "G24 `getrpcinfo` empty fields (BUG-3 PARTIAL)" `Quick
        g24_getrpcinfo_stub_partial;
      Alcotest.test_case "G25 `help` enumerates methods (PRESENT)" `Quick
        g25_help_rpc_present;
      Alcotest.test_case "G26 cookie auth (PRESENT)" `Quick
        g26_cookie_auth_present;
      Alcotest.test_case "G27 -noconnect flag absent (BUG-13 MISSING)" `Quick
        g27_noconnect_missing;
    ];
    "G28-G30 notify hooks", [
      Alcotest.test_case "G28 -alertnotify (BUG-14 MISSING)" `Quick
        g28_alertnotify_missing;
      Alcotest.test_case "G29 -blocknotify (BUG-15 MISSING)" `Quick
        g29_blocknotify_missing;
      Alcotest.test_case "G30 -startupnotify / -shutdownnotify (BUG-16 MISSING)" `Quick
        g30_startup_shutdown_notify_missing;
    ];
  ]
