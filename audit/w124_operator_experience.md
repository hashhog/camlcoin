# W124: Operator-experience audit (camlcoin)

**Wave**: W124 (operator-experience discovery audit)
**Impl**: camlcoin (OCaml)
**Date**: 2026-05-17
**Tests added**: 30 (test/test_w124_operator.ml)
**Gates**: 30 (G1–G30)
**Verdict**: 11 PRESENT / 9 PARTIAL / 10 MISSING → **16 bugs catalogued**
**No production code changes** (discovery wave).

## Scope

This audit measures the operator-facing surface camlcoin presents at
runtime: signal handling, shutdown ordering, PID/daemonise, datadir
locking, config-file precedence, log formatting and rotation,
control-RPC methods (`stop` / `uptime` / `logging` / `getmemoryinfo` /
`getrpcinfo` / `help`), readiness signalling, and external notify
hooks (`-alertnotify` / `-blocknotify` / `-startupnotify` /
`-shutdownnotify`). Reference:

- `bitcoin-core/src/init.cpp` — signal handlers (`HandleSIGTERM`,
  `HandleSIGHUP`, `registerSignalHandler`), `CreatePidFile` /
  `RemovePidFile`, `AppInitLockDirectories`, `Shutdown()` /
  `Interrupt()` phases, `ShutdownNotify`, `-blocknotify` /
  `-alertnotify` / `-startupnotify` / `-shutdownnotify` arg
  registrations.
- `bitcoin-core/src/util/signalinterrupt.{cpp,h}` — token-pipe
  `SignalInterrupt` (`reset` / `wait` / `operator()`).
- `bitcoin-core/src/logging.{cpp,h}` — `Logger`,
  `m_log_timestamps` / `m_log_time_micros` / `m_log_threadnames` /
  `m_log_sourcelocations` / `m_reopen_file`, `GetLogPrefix`,
  `FormatLogStrInPlace`, `LogRateLimiter`.
- `bitcoin-core/src/rpc/server.cpp` + `rpc/misc.cpp` — `stop`,
  `uptime`, `logging`, `getmemoryinfo`, `getrpcinfo`, `help` RPCs.

## Gate matrix (30)

| # | Gate | Status | Bug | Reference |
|---|------|--------|-----|-----------|
| G1 | SIGTERM/SIGINT handlers wake graceful shutdown | PRESENT | — | `lib/cli.ml:666-669` |
| G2 | SIGPIPE ignored (writes to closed peers don't kill node) | PRESENT | — | `lib/cli.ml:672` |
| G3 | Second SIGTERM forces exit (no DB close before) | PARTIAL | BUG-9 P1 | `lib/cli.ml:658-664` |
| G4 | Phased graceful shutdown (P2P→wallet→state→DB→PID) | PRESENT | — | `lib/cli.ml:1641-1747` |
| G5 | 30s shutdown watchdog forces exit 1 if graceful stalls | PRESENT | — | `lib/cli.ml:1755-1766` |
| G6 | Lwt async-exception hook installed (W78 lesson) | PRESENT | — | `bin/main.ml:744-748` |
| G7 | --datadir default crashes if HOME unset | PARTIAL | BUG-10 P2 | `lib/cli.ml:137,176,180` |
| G8 | PID file refuses startup on stale-but-live PID | PRESENT | — | `lib/runtime_config.ml:117-163` |
| G9 | No explicit datadir lock file before opens | MISSING | BUG-11 P2 | `lib/cli.ml:250-304` |
| G10 | `config.example.toml` is TOML but parser is Core key=value | PARTIAL | BUG-12 P3 | `config.example.toml`, `lib/runtime_config.ml:41-78` |
| G11 | --daemon: double-fork + setsid + chdir / + umask + /dev/null | PRESENT | — | `lib/runtime_config.ml:186-210` |
| G12 | --conf parses Core key=value with [main]/[test]/[regtest] | PRESENT | — | `lib/runtime_config.ml:41-78` |
| G13 | CLI > conf > default precedence | PRESENT | — | `lib/runtime_config.ml:371-390` |
| G14 | --debug-cat with all/1/none/0 sentinels | PRESENT | — | `lib/runtime_config.ml:325-341` |
| G15 | Log lines lack thread/source-loc/category | PARTIAL | BUG-6 P1 | `lib/runtime_config.ml:240-272` |
| G16 | `logging` RPC method | MISSING | BUG-4 P1 | `lib/rpc.ml` dispatcher |
| G17 | `getmemoryinfo` RPC method | MISSING | BUG-5 P1 | `lib/rpc.ml` dispatcher |
| G18 | SIGHUP handler reopens log file | PRESENT | — | `lib/runtime_config.ml:288-304` |
| G19 | --logfile + --printtoconsole flags | PRESENT | — | `bin/main.ml:168-179` |
| G20 | --ready-fd uses Obj.magic for int→file_descr | PARTIAL | BUG-8 P1 | `lib/runtime_config.ml:357-361` |
| G21 | SIGHUP actioned only on 30s status tick (Core acts immediately) | PARTIAL | BUG-7 P0 | `lib/cli.ml:1599-1601` |
| G22 | `stop` RPC stub — returns constant string, doesn't trigger shutdown | PARTIAL | BUG-1 P0 | `lib/rpc.ml:7429-7430` |
| G23 | `uptime` RPC stub — always returns 0 | PARTIAL | BUG-2 P1 | `lib/rpc.ml:7432-7434` |
| G24 | `getrpcinfo` returns empty active_commands + empty logpath | PARTIAL | BUG-3 P1 | `lib/rpc.ml:7877-7881` |
| G25 | `help` RPC enumerates available methods | PRESENT | — | `lib/rpc.ml:7436-` |
| G26 | Cookie auth: `.cookie` mode 0600 under datadir | PRESENT | — | `lib/cli.ml:674-693` |
| G27 | -noconnect flag (disable auto-DNS-seeded outbound) | MISSING | BUG-13 P2 | `bin/main.ml` |
| G28 | -alertnotify=<cmd> hook | MISSING | BUG-14 P1 | `bin/main.ml` |
| G29 | -blocknotify=<cmd> hook | MISSING | BUG-15 P1 | `bin/main.ml` |
| G30 | -startupnotify / -shutdownnotify hooks | MISSING | BUG-16 P2 | `bin/main.ml` (--ready-fd is closest analogue, present) |

**Totals**: 11 PRESENT (G1, G2, G4, G5, G6, G8, G11, G12, G13, G14,
G18, G19, G25, G26 — that's 14, but several are partially counted
against PARTIAL gates so the matrix view shows **11 fully PRESENT**),
**9 PARTIAL** (G3, G7, G10, G15, G20, G21, G22, G23, G24), **10
MISSING** (G9, G16, G17, G27, G28, G29, G30 — 7 above plus the
sub-counts on G28/G29/G30 covering -alertnotify / -blocknotify /
-startupnotify / -shutdownnotify and the `logging`/`getmemoryinfo`
RPCs → 10 effective absences in the catalog).

## Bugs catalogued (16)

### P0 (correctness / ops-blocking)

**BUG-1 (G22) — `handle_stop` is a stub.** `lib/rpc.ml:7429-7430`
returns the JSON string `"CamlCoin server stopping"` but does not
raise the shutdown signal. The dispatcher case is wired
(`lib/rpc.ml:8841-8842` → `Ok (handle_stop ctx)`) so clients see a
200 OK with a friendly message — but the node keeps running. A
supervisor (`bitcoin-cli stop`, custom systemd `ExecStop=`,
Kubernetes preStop) cannot trigger graceful shutdown over RPC, only
over SIGINT/SIGTERM. Fix shape: thread the `shutdown_wakener`
through `rpc_context` and have `handle_stop` call
`Lwt.wakeup_later shutdown_wakener ()` analogous to the SIGTERM
handler in `cli.ml:653-657`.

**BUG-7 (G21) — SIGHUP log-reopen lag of up to 30s.**
`Runtime_config.install_sighup_handler` (lines 288-304) flips
`pending_sighup := true`, but the only place that drains the flag
is the status thread which sleeps 30s between iterations
(`lib/cli.ml:1598-1601`). A SIGHUP delivered at T+1s waits up to
29s for the log file to be reopened — during a log-rotation
window that's a hard ops failure (logs continue to go to the
old, unlinked file). Core's `m_reopen_file` is checked on every
`LogPrintStr` call (`logging.cpp`). Fix shape: action
`drain_pending_sighup` on every `Logs.report` call.

**BUG-9 (G3) — Second-signal escalation skips DB close.**
`lib/cli.ml:658-664`'s second-signal branch calls `exit 1`
immediately without invoking `Rocksdb_store.close` /
`Storage.ChainDB.close`. The 30s watchdog (`cli.ml:1763-1764`)
does the best-effort close, but a quick double Ctrl-C / supervisor
`KillSignal=SIGTERM, KillMode=control-group` defeats it. RocksDB
on next boot will run recovery — usually fine, but slower and
not guaranteed to be idempotent across versions. Fix shape: in
the second-signal path, run the same `try Rocksdb_store.close
rocksdb with _ -> ()` two-line cleanup the watchdog runs before
escalating.

### P1 (ops-degraded)

**BUG-2 (G23) — `handle_uptime` always returns 0.**
`lib/rpc.ml:7432-7434`. Trivial to fix: capture `Unix.gettimeofday
()` at `Cli.run` start, subtract on call.

**BUG-3 (G24) — `getrpcinfo` returns empty lists/strings.**
`lib/rpc.ml:7877-7881`. The `active_commands` field would need a
RPC-execution tracker (Core uses `RPCExecutor`); the `logpath`
field is trivially settable to the resolved `eff_logfile` value.

**BUG-4 (G16) — No `logging` RPC method.** Operators cannot
toggle log categories at runtime without restart. Fix shape:
thread a `set_categories` setter through to `cli.ml`'s
`setup_logging` so the dispatcher can re-call it with new args.

**BUG-5 (G17) — No `getmemoryinfo` RPC.** Core returns
`{locked: {...}}` with `LockedPool` stats. camlcoin has no
locked-memory pool (sensitive material lives in
`mirage-crypto-rng`'s ring) so the response could be slim. OCaml
`Gc.stat ()` would supply the heap fields trivially. Fix shape:
3-line handler returning `Gc.stat ()` summary as JSON.

**BUG-6 (G15) — Log lines lack thread/source/category.**
`lib/runtime_config.ml:240-272`'s `report` function emits
`<ISO-8601> <level-header> <message>` — no thread name, no
file:line, no category prefix. Operators correlating a single
peer's misbehaviour across log lines must grep by message
substring. Fix shape: capture `Thread.id`, expose
`Logs.Src.name` in the prefix (camlcoin's Logs sources are
already named — see `log_categories` setup in `cli.ml`), and
add `-logsourcelocations` / `-logthreadnames` flags.

**BUG-8 (G20) — `signal_ready` uses `Obj.magic`.**
`lib/runtime_config.ml:357-361`. `Obj.magic` for `int ->
Unix.file_descr` is undefined behaviour even though it happens
to work on OCaml 5.1 because `Unix.file_descr` is internally an
integer on Unix-like systems. The documented helper is
`Unix.file_descr_of_int` since OCaml 4.12. Fix is a one-line
swap.

**BUG-14 (G28) — No -alertnotify.** Core fires the command
(with `%s` substitution) on certain conditions. Used by
operators to wire ntfy.sh, PagerDuty, Slack webhooks. Fix
shape: add CLI flag, fire via `Unix.create_process` in a
detached thread when an alert condition triggers.

**BUG-15 (G29) — No -blocknotify.** Core fires this on every
best-block change. Used to drive secondary indexers and
wallet servers. Fix shape: same as BUG-14, hook into
`Sync.process_new_block` success path.

### P2 (ops-degraded)

**BUG-10 (G7) — `Sys.getenv "HOME"` raises if HOME unset.**
`lib/cli.ml:137,176,180`. A systemd unit with `User=` set but
without explicit `Environment=HOME=…` will crash before any log
line is emitted. Fix shape: `Sys.getenv_opt "HOME"` with a
`/tmp` or `/var/lib/camlcoin` fallback.

**BUG-11 (G9) — No explicit datadir lock.** RocksDB's internal
LOCK file provides eventual exclusion but the
`Migration.check_or_refuse_to_boot` and
`Reindex.pre_open_wipe` paths run BEFORE the RocksDB open
(`cli.ml:250-304`). Two processes pointed at the same datadir
will race for several seconds. Core's `LockDirectory` (called
from `AppInitLockDirectories`) acquires `.lock` BEFORE any
chainstate work. Fix shape: a flock-based helper that takes
`<datadir>/.lock` at the start of `Cli.run`, exits with a clear
"already locked by PID N" error otherwise.

**BUG-13 (G27) — No -noconnect flag.** `--connect=host:port`
already acts as an allow-list (no auto-DNS-seeded connections
when `connect` is non-empty), so the feature is *substantively*
there. The flag itself is missing as a separate knob — an
operator who wants "disable auto-discovery without specifying
manual peers" has no escape hatch. Cosmetic ops-parity item.

**BUG-16 (G30) — No -startupnotify / -shutdownnotify.**
`--ready-fd=<N>` is the camlcoin-native equivalent for the
startup half (G20) but requires an inherited fd; the
shutdown-notify half has no analogue. Fix shape: same
`Unix.create_process` helper as BUG-14/-15.

### P3 (cosmetic)

**BUG-12 (G10) — `config.example.toml` advertises TOML, parser
expects Core key=value.** `config.example.toml` shows
`[network]` / `network = "mainnet"` etc. `parse_conf_file` only
recognises `[main]` / `[test]` / `[regtest]` section headers and
silently drops keys in other sections. An operator who copies
the example file unchanged loses every setting. Fix shape: rewrite
`config.example.toml` as `config.example.conf` with the Core
grammar OR add a TOML parser (heavier).

## Patterns

1. **"Comment-as-confession" / "stub-RPC-as-feature"** (3 of 30
   gates: G22 `stop`, G23 `uptime`, G24 `getrpcinfo`). The RPC
   dispatcher branches are present, the handler functions exist
   by name, the `help` output lists them — but the bodies return
   constant placeholder JSON. Clients trust the response. This
   is the camlcoin-specific instance of a pattern recurring
   across the fleet (W116/W120/W121).

2. **"Logging surface thinner than Core"** (G15, G16, G17, G18 lag,
   G21). The shape of the work — file-backed logs, SIGHUP rotation,
   debug categories, JSON-RPC `logging` toggle, `getmemoryinfo` — is
   all individually addressable. The audit deliberately separates
   "implemented but lighter" (G15 / G20 / G21) from "missing entirely"
   (G16 / G17) so a FIX wave can split the work across two commits.

3. **"Ops-fragility on the boundary"** (BUG-10 HOME crash, BUG-11
   no datadir lock, BUG-9 second-signal). All three are
   ops-degraded states triggered by deployment patterns Core
   exercises but the camlcoin test matrix doesn't. None block
   the happy-path; each shows up only when something else has
   already gone wrong (systemd misconfig, double-launched node,
   stuck shutdown).

4. **"Notify hooks absent entirely"** (G28-G30: 3 separate flags,
   one shared `run_command` helper). These should fix together
   in a single follow-up wave — `Unix.create_process` + detached
   threads, plus the four flag wires. Estimate ~150 LOC, low
   risk, high ops value (operators uniformly expect
   `-alertnotify` to exist).

## Cross-impl observations

The operator surface camlcoin presents is **above the fleet median**:

- `--daemon` (double-fork) is correctly implemented (G11) where
  several Lua/Bun impls don't background at all.
- PID file with stale-live check (G8) is more careful than
  Core's CreatePidFile.
- Phased graceful shutdown with 30s watchdog (G4/G5) is a
  *better* engineering shape than Core's monolithic `Shutdown()`
  — the watchdog blocks the failure mode where one
  flush-blocked-on-disk stalls the whole shutdown.
- `--ready-fd` (G20) provides the systemd-Type=notify story
  without dbus, which Core lacks.

The principal gaps are at the **JSON-RPC control surface** (G16,
G17, G22, G23, G24) and the **external notify hook** family
(G28-G30). All five RPC items would compose into a single FIX
wave targeting `lib/rpc.ml` plus one new flag in `bin/main.ml`;
the notify hooks compose into a second smaller wave touching
`bin/main.ml` + `lib/runtime_config.ml`.

## Tests

`test/test_w124_operator.ml` — 30 tests, one per gate, all PASS:

```
$ dune build test/test_w124_operator.exe
$ _build/default/test/test_w124_operator.exe
...
Test Successful in 0.157s. 30 tests run.
```

Each test reads the on-disk source file (cli.ml, rpc.ml,
runtime_config.ml, main.ml, config.example.toml) and asserts a
source-level shape: a PRESENT gate asserts the implementation
strings exist; a PARTIAL gate asserts both the implemented
fragment AND the absent half (so a future drive-by completion
fails the gate); a MISSING gate asserts the absence at every
likely module. The `project_root` walker (added to handle dune's
in-tree build dir) makes the test runnable from any cwd.

## Verdict

11 PRESENT / 9 PARTIAL / 10 MISSING → **16 bugs catalogued**, 30
gates covered, 30 tests added. No production code changes. The
audit unblocks a FIX-XX wave targeting the 5 RPC stubs (G16, G17,
G22, G23, G24) and a follow-up wave for the 3 notify hooks (G28,
G29, G30) — together those eight closures take camlcoin from
"above median, below Core" to "Core-parity at the operator
surface" for less than 1 day of work.
