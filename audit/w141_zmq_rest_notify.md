# W141 ZMQ + REST + Notification scripts — camlcoin (OCaml)

Wave: W141 — three external-eventing surfaces bundled because Core wires
them adjacent in `init.cpp` and they share the same "no on-disk side
effect, side-channel only" footprint:

  1. **ZMQ pub/sub notifier** (`-zmqpub<topic>=<addr>` family,
     `src/zmq/zmqnotificationinterface.cpp` + `zmqpublishnotifier.cpp`)
  2. **REST API** (`-rest`, `src/rest.cpp` + `rest.h`)
  3. **Notification scripts** (`-blocknotify`, `-alertnotify`,
     `-walletnotify`, `-startupnotify`, `-shutdownnotify`)

Bitcoin Core references:

- `bitcoin-core/src/zmq/zmqnotificationinterface.cpp`
  - L44-85: factory map (pubhashblock / pubhashtx / pubrawblock /
    pubrawtx / pubsequence) + `unix://` → `ipc://` rewrite
  - L60: `gArgs.GetArgs("-zmq" + topic)` — one option per CLI arg
  - L62-64: `ADDR_PREFIX_UNIX` → `ADDR_PREFIX_IPC` rewrite
  - L69: `gArgs.GetIntArg(arg + "hwm", DEFAULT_ZMQ_SNDHWM=1000)` —
    per-topic HWM override
  - L151-159: `UpdatedBlockTip` — skips during IBD AND on
    `pindexNew == pindexFork` (reorg without new tip)
  - L161-168: `TransactionAddedToMempool` — fires `NotifyTransaction`
    + `NotifyTransactionAcceptance` together
  - L180-196: `BlockConnected` — fires `NotifyTransaction` for every
    contained tx + `NotifyBlockConnect`; gated on `role.historical`
  - L198-211: `BlockDisconnected` — fires `NotifyTransaction` per tx +
    `NotifyBlockDisconnect`
- `bitcoin-core/src/zmq/zmqpublishnotifier.cpp`
  - L31: `mapPublishNotifiers` keyed by ADDRESS (not topic) — multiple
    notifiers at the same address share one socket
  - L40-80: `zmq_send_multipart` (3-frame: cmd / data / 4-byte LE seq)
  - L82-93: `IsZMQAddressIPV6` heuristic (for `ZMQ_IPV6` socket option)
  - L95-160: per-socket setup — `ZMQ_SNDHWM` + `ZMQ_TCP_KEEPALIVE` +
    `ZMQ_IPV6` + `zmq_bind`; reuses socket on duplicate address
  - L162-191: `Shutdown` sets `ZMQ_LINGER=0` before close (idempotent;
    only closes when last user of the address)
  - L193-208: `SendZmqMessage` — 4-byte LE `nSequence`, increments
    after send
  - L210-219: `NotifyBlock` (hashblock) — 32-byte REVERSED hash
  - L221-230: `NotifyTransaction` (hashtx) — 32-byte REVERSED txid
  - L232-243: `NotifyBlock` (rawblock) — full serialised block
  - L245-252: `NotifyTransaction` (rawtx) — `TX_WITH_WITNESS`
  - L254-265: `SendSequenceMsg` — `<32-byte hash> | <1-byte label> |
    [<8-byte LE mempool_sequence>]` — mempool_sequence ABSENT for
    block connect/disconnect, PRESENT for tx accept/remove
  - L267-272: `NotifyBlockConnect` (`'C'`) / `NotifyBlockDisconnect`
    (`'D'`) — 33-byte payload (no mempool_sequence)
  - L281-293: `NotifyTransactionAcceptance` (`'A'`) /
    `NotifyTransactionRemoval` (`'R'`) — 41-byte payload (8-byte
    mempool_sequence appended)
- `bitcoin-core/src/zmq/zmqpublishnotifier.h`
  - L21: `nSequence` is PER-`CZMQAbstractPublishNotifier` instance —
    one counter per (topic, address) pair, not per topic globally
- `bitcoin-core/src/rest.cpp`
  - L44: `MAX_GETUTXOS_OUTPOINTS = 15` constant
  - L45: `MAX_REST_HEADERS_RESULTS = 2000` constant
  - L71-76: `RESTERR` writes `text/plain` body + `Content-Type` header
    + `\r\n` terminator
  - L129-152: `ParseDataFormat` — strips query string at `?`, then
    finds last `.` for extension; default = `UNDEF` (returns 404)
  - L171-177: `CheckWarmup` — every endpoint returns 503 + warmup
    message during RPC warmup
  - L179-274: `rest_headers` — supports new `?count=` and deprecated
    `<count>/<hash>` paths; count bounded 1..MAX_REST_HEADERS_RESULTS
  - L276-381: `rest_spent_txouts` — `/rest/spenttxouts/<hash>` returns
    block-undo data (per-tx prevout list, coinbase tx omitted as empty)
  - L383-498: `rest_block` + `rest_block_extended` +
    `rest_block_notxdetails` + `rest_block_part` — 4 distinct URIs
    sharing one helper; `rest_block_part` reads `offset` + `size`
    query and rejects JSON
  - L500-620: `rest_filter_header` + `rest_block_filter` — supports
    new `?count=` and deprecated `<filtertype>/<count>/<hash>` paths;
    JSON form for `blockfilter` is `{"filter": "<hex>"}`
  - L716-738: `rest_chaininfo` — JSON only, dispatches to
    `getblockchaininfo`
  - L740-780: `rest_deploymentinfo` — JSON only, optional `<hash>`
    suffix
  - L782-836: `rest_mempool` — `/rest/mempool/<info|contents>.json`;
    `contents` supports `?verbose=` + `?mempool_sequence=` (mutually
    exclusive with `verbose=true`)
  - L838-895: `rest_tx` — JSON form runs `g_txindex->BlockUntilSyncedToCurrentChain()`
    before lookup
  - L897-1089: `rest_getutxos` — BIP-64; supports POST binary/hex
    body + URI path `/checkmempool/<txid-vout>/...`; `MAX_GETUTXOS_OUTPOINTS`
    cap; bitmap output
  - L1091-1139: `rest_blockhash_by_height` — sanitises `height_str`
    via `SanitizeString(...,SAFE_CHARS_URI)` before echoing in error
  - L1141-1159: `uri_prefixes` registration table — 14 prefixes
- `bitcoin-core/src/init.cpp`
  - L256-265 + L737-746: `ShutdownNotify` / `StartupNotify` —
    `runCommand` over `-shutdownnotify` / `-startupnotify`
  - L758: `if (args.GetBoolArg("-rest", DEFAULT_REST_ENABLE)) StartREST(&node)`
  - L2008-2019: `-blocknotify` — `uiInterface.NotifyBlockTip_connect`
    callback that REJECTS during `sync_state != POST_INIT` (i.e.,
    skips during IBD); replaces `%s` with block hash
- `bitcoin-core/src/node/kernel_notifications.cpp`
  - L30-47: `AlertNotify` — `SanitizeString(strMessage)` →
    single-quote wrap → `ReplaceAll(strCmd, "%s", safeStatus)` →
    `runCommand`
  - L80-85: `warningSet` calls `AlertNotify(message.original)`
- `bitcoin-core/src/wallet/wallet.cpp`
  - L1139-1165: `-walletnotify` — replaces `%s` (txid), `%b` (blockhash
    or "unconfirmed"), `%h` (height or -1), and `%w` (wallet name,
    `ShellEscape`d) on non-Windows
- `bitcoin-core/src/common/system.cpp`
  - L40-46: `ShellEscape` — replaces `'` with `'"'"'` and wraps in
    single quotes
  - L49-62: `runCommand` — POSIX: `::system(strCommand.c_str())`;
    logs warning on non-zero return
- `bitcoin-core/src/util/strencodings.h`
  - L31-36: `SAFE_CHARS_DEFAULT` (alert/notify body) vs
    `SAFE_CHARS_URI` (RFC 3986 char set, used by rest)

BIPs: none directly — but BIP-64 governs `/rest/getutxos` wire format,
and BIP-157/158 governs `/rest/blockfilter` + `/rest/blockfilterheaders`.

## Methodology

1. Read Core refs (above).
2. Enumerate 30 audit gates spanning the three subsystems (10 ZMQ +
   12 REST + 8 notification scripts). Each gate either probes
   behavioural parity (API-level), source-level structural parity
   (`grep` against `lib/zmq_notify.ml` + `lib/zmq_socket.ml` +
   `lib/rest.ml` + `bin/main.ml` + `lib/cli.ml`), or constant parity.
3. Classify each gate against camlcoin's de-facto surface:
   - `lib/zmq_notify.ml` — pure-OCaml notifier (topic state +
     in-process queue + libzmq send_callback)
   - `lib/zmq_socket.ml` — libzmq publisher wrapper (PUB socket + ctx
     + lazy bind)
   - `lib/zmq_bindings.ml` — C-stub layer to libzmq.so.5
   - `lib/rest.ml` — Cohttp REST handlers (10 endpoints + 1 POST
     `/payjoin`)
   - `bin/main.ml` — CLI arg parsing (`--zmqpub`, `--rest`,
     `--restport`, `--restbind`, `--rest-tls-{cert,key}`)
   - `lib/cli.ml` — runtime config + notifier wiring + REST listener
     bootstrap + ZMQ shutdown
4. Catalogue BUGs by severity:
   - **P0-CDIV**: protocol-correctness divergence externally visible
     to subscribers/clients (wrong wire bytes, silent message loss
     where Core emits, sequence-number desync that breaks
     ZMQ-based mempool tracking)
   - **P1**: feature-correctness gap (right wire format, wrong
     gating / ordering / coverage)
   - **P2**: privacy / fingerprinting / fairness drift (works but
     leaks info, or accepts non-Core grammar)
   - **P3**: surface / doc / constant drift

Severity legend mirrors W130 / W131 / W132 / W133 / W134 / W135 /
W136 / W137.

## camlcoin de-facto surface

| Concern | Core | camlcoin |
|---------|------|----------|
| ZMQ option grammar | `-zmqpub<topic>=<addr>` (one prefix per topic) | `--zmqpub=<topic>=<addr>` + Core-style after re-prefix in `main.ml:620-631`; ALSO accepts the `pub<topic>=` alias (`zmq_notify.ml:371-375`) |
| per-topic HWM override | `-zmqpub<topic>hwm=<N>` (`zmqnotificationinterface.cpp:69`) | not parsed — single `high_water_mark = 1000` hard-coded in `zmq_notify.ml:121` and `zmq_socket.ml:84` |
| sequence number scope | per-(topic, address) instance (`zmqpublishnotifier.h:21`) | per-TOPIC globally (`zmq_notify.ml:97-114`) — same topic at two addresses shares one counter, and only the first address binds (`zmq_notify.ml:103: if not Hashtbl.mem`) |
| socket-reuse on duplicate address | `mapPublishNotifiers` keyed by address; second notifier at same address shares one socket (`zmqpublishnotifier.cpp:100-159`) | one PUB socket per `publisher`, multi-bind on the same socket; behavioural overlap not identical (subscribers on tcp://A see messages routed to tcp://B too) |
| `unix://` → `ipc://` rewrite | done at registration (`zmqnotificationinterface.cpp:62-64`) | absent — `unix://path` reaches libzmq verbatim and is rejected |
| IBD gate for hashblock/rawblock | `UpdatedBlockTip` skipped when `fInitialDownload \|\| pindexNew == pindexFork` | absent — `zmq_notify_block` (`sync.ml:1584-1596`) fires hashblock + rawblock during IBD |
| historical-chainstate gate | `BlockConnected` skipped when `role.historical` (assumeutxo background validation) | absent — historical role concept exists in `assume_utxo.ml` but no plumbing into ZMQ |
| hashtx/rawtx per-tx on block-connect | `BlockConnected` fires `NotifyTransaction` for every contained tx (`zmqnotificationinterface.cpp:185-190`) | absent — only block-level topics fire on connect; per-tx topics fire only on mempool-add |
| ZMQ shutdown ordering | `ZMQ_LINGER=0` before `zmq_close` (`zmqpublishnotifier.cpp:185-186`) | absent — `Zmq_bindings.close` is called without setsockopt(LINGER=0) preamble (`zmq_socket.ml:244-251`) |
| in-process queue retention | none — Core's notifier is wire-only, drops on HWM | always-queue in-process (`zmq_socket.ml:206-208`) even when libzmq sent the message; queue persists across drains; this changes memory profile |
| `mempool_sequence` field | 8-byte LE, ABSENT for block connect/disconnect, PRESENT for tx accept/remove | optional via labelled arg (`zmq_notify.ml:232-247`); `notify_block_connect` does NOT pass mempool_sequence → 33-byte payload (correct); `notify_tx_acceptance` / `notify_tx_removal` always pass → 41 bytes (correct) |
| mempool sequence increment | global per-mempool counter, increments on every accept AND removal | per-mempool counter (`mempool.ml:322-343`); incremented inside `zmq_notify_tx`; increments are wired to BOTH accept and removal call sites (`remove_transaction` calls `zmq_notify_tx ... false`) |
| `-rest` default | `DEFAULT_REST_ENABLE = false` (`init.cpp:153`) | `rest_enabled = false` in `cli.ml:154` — PARITY |
| REST URI prefixes | 14 (`rest.cpp:1141-1159`) | 10 — missing `/rest/getutxos`, `/rest/blockpart/`, `/rest/spenttxouts/`, `/rest/deploymentinfo`, `/rest/tx/` has-no-`g_txindex` sync |
| REST warmup gate | `CheckWarmup` on every endpoint returns 503 (`rest.cpp:171-177`) | absent — every handler enters body unconditionally |
| REST height sanitisation | `SanitizeString(height_str, SAFE_CHARS_URI)` before error echo (`rest.cpp:1100`) | absent — `respond_error \`Bad_request ("Invalid height: " ^ height_str)` echoes raw user input |
| REST count default | `5` (`rest.cpp:199, 518`) | `5` (`rest.ml:341, 506`) — PARITY |
| REST max headers | `MAX_REST_HEADERS_RESULTS = 2000` (`rest.cpp:45`) | `max_headers_results = 2000` (`rest.ml:24`) — PARITY |
| `-blocknotify` script | substitutes `%s` with block hash, fires post-IBD only (`init.cpp:2010-2018`) | absent — no notify-script wiring in `cli.ml` or `bin/main.ml` |
| `-alertnotify` script | `SanitizeString` + shell-quote + `runCommand`, fires from `warningSet` (`kernel_notifications.cpp:30-47`) | absent — `Logs.warn` is the only warning surface |
| `-walletnotify` script | per-tx, substitutes `%s` (txid) / `%b` (blockhash) / `%h` (height) / `%w` (wallet name) | absent — wallet has no external-script hook |
| `-startupnotify` / `-shutdownnotify` | `runCommand` from `AppInit` + `Interrupt` (`init.cpp:737-746, 256-265`) | absent — only fd-based `signal_ready` (`runtime_config.ml:346-355`) handshake |
| `runCommand` shell escape | `ShellEscape` (`'` → `'"'"'`) for `%w` only (`wallet/wallet.cpp:1160`) | absent — would be needed if any notify-script were added; building it once is a prereq |

## 30-gate matrix (W141)

### G1-G10: ZMQ pub/sub notifier (zmq_notify.ml + zmq_socket.ml)

- **G1: option grammar accepts `-zmqpub<topic>=<addr>`.**
  Core (`zmqnotificationinterface.cpp:58-60`): only the topic-prefixed
  form. camlcoin (`zmq_notify.ml:370-376`) ALSO accepts the
  `pub<topic>=` alias (`pubhashblock`, `pubhashtx`, etc.). For Core's
  CLI grammar a user would type `-zmqpubhashblock=tcp://...`; the
  alias means camlcoin also accepts `-zmqpubpubhashblock=tcp://...`
  (double prefix). Fingerprintable.
  **BUG-W141-1 (P2)**: ZMQ topic-alias grammar accepts a double-prefix
  form Core rejects.

- **G2: per-topic HWM override `-zmqpub<topic>hwm=<N>`.**
  Core (`zmqnotificationinterface.cpp:69`): `gArgs.GetIntArg(arg + "hwm",
  DEFAULT_ZMQ_SNDHWM)` — per-(topic, address) HWM. camlcoin (`zmq_notify.ml:121`
  and `zmq_socket.ml:84`): single `high_water_mark = 1000` hard-coded
  default, no per-topic override parsing.
  **BUG-W141-2 (P1)**: no `-zmqpub<topic>hwm` support — operator cannot
  tune SNDHWM per topic; both bulk topics (rawblock) and lightweight
  topics (hashtx) share one buffer ceiling.

- **G3: sequence-number scope is per-(topic, address).**
  Core (`zmqpublishnotifier.h:21`): `nSequence` is a private field on
  `CZMQAbstractPublishNotifier`, instantiated once per (topic, address)
  via the factory map. So `pubhashblock=tcp://A` and
  `pubhashblock=tcp://B` get TWO independent counters. camlcoin
  (`zmq_notify.ml:96-114`): `publishers` Hashtbl keyed by TOPIC.
  `if not (Hashtbl.mem publishers topic)` means second-address-same-topic
  is SILENTLY DROPPED at registration. A subscriber wired to tcp://B
  would see ZERO messages for that topic.
  **BUG-W141-3 (P0-CDIV)**: sequence-number / state Hashtbl is keyed
  by topic globally — second address for the same topic is silently
  dropped at `Zmq_notify.create`; that endpoint receives no messages.

- **G4: socket-reuse on duplicate address.**
  Core (`zmqpublishnotifier.cpp:100-159`): `mapPublishNotifiers` keyed
  by ADDRESS; a second notifier targeting the same address SHARES the
  underlying socket and adds itself to the multimap. camlcoin
  (`zmq_socket.ml:341-349` `create_from_config`): one `publisher` is
  created and EVERY distinct address is `bind`ed onto the same PUB
  socket via `List.iter (fun addr -> bind pub addr) addresses`. Wire
  effect: a subscriber connected to `tcp://A` will see messages
  whose configured target was `tcp://B`, because they all flow through
  the same socket. Core's design isolates per-address subscriber lists.
  **BUG-W141-4 (P1)**: multi-bind on one socket means subscribers on
  one configured address see cross-talk from other configured
  addresses' topics.

- **G5: `unix://` → `ipc://` address-prefix rewrite.**
  Core (`zmqnotificationinterface.cpp:62-64`): every address registered
  with `unix://` prefix is rewritten to `ipc://` before reaching
  libzmq. camlcoin (`zmq_socket.ml:129-143` `bind`): no rewrite — the
  address is passed through to `Zmq_bindings.bind` verbatim. libzmq
  doesn't understand `unix://` and the bind call fails.
  **BUG-W141-5 (P3)**: no `unix://` → `ipc://` rewrite; operator
  copying a Core config across to camlcoin gets a silent bind failure.

- **G6: IBD gate on hashblock + rawblock.**
  Core (`zmqnotificationinterface.cpp:151-159` `UpdatedBlockTip`):
  `if (fInitialDownload || pindexNew == pindexFork) return;` —
  hashblock / rawblock are SUPPRESSED during IBD. camlcoin
  (`sync.ml:1584-1596` `zmq_notify_block`): no IBD check; every
  validated block during sync emits hashblock + rawblock. Subscribers
  see a 800k-block storm during initial sync that Core would suppress.
  **BUG-W141-6 (P0-CDIV)**: hashblock + rawblock fire during IBD —
  externally observable; subscribers built against Core's quiet-IBD
  behaviour see unexpected traffic.

- **G7: per-block hashtx / rawtx on BlockConnected.**
  Core (`zmqnotificationinterface.cpp:185-190`): for every transaction
  in a connecting block, fires `notifier->NotifyTransaction(tx)` so
  hashtx + rawtx subscribers see EVERY block-confirmed tx. camlcoin
  (`sync.ml:1583-1596`): only block-level topics fire on connect; the
  per-tx loop is absent. A hashtx subscriber sees ONLY mempool tx,
  never confirmed tx.
  **BUG-W141-7 (P0-CDIV)**: no per-tx hashtx/rawtx on block-connect
  — Core fires them, camlcoin doesn't. Externally observable.

- **G8: `historical` chainstate gate.**
  Core (`zmqnotificationinterface.cpp:182-184`): `BlockConnected`
  early-returns when `role.historical` — assumeutxo background
  validation does NOT emit ZMQ. camlcoin has assumeutxo (`assume_utxo.ml`)
  but no chainstate-role concept threaded into ZMQ. If/when the
  background validator connects historical blocks it will spuriously
  emit ZMQ events that re-fire the same hashes as the assumeutxo
  snapshot already published.
  **BUG-W141-8 (P1)**: no `role.historical` gate — duplicate
  block-connect events during assumeutxo background validation.

- **G9: `ZMQ_LINGER=0` ORDERING — set at socket-create vs just-before-close.**
  Core (`zmqpublishnotifier.cpp:185-186`): `int linger = 0;
  zmq_setsockopt(psocket, ZMQ_LINGER, &linger, sizeof(linger));
  zmq_close(psocket);` — defensive teardown right before close.
  camlcoin (`lib/zmq_stubs.c:141-145` `caml_zmq_pub_socket`): sets
  `ZMQ_LINGER=0` at socket-create time, NOT before close.  Net effect
  on close-latency is the same (the option is already in place when
  `zmq_close` is invoked), but Core's pattern lets the operator pre-set
  a nonzero linger and only flip to 0 at shutdown.  camlcoin's pattern
  is permanently linger-0 — every dropped message during normal
  operation is unrecoverable even though Core's design allows a brief
  retry window.
  **BUG-W141-9 (P3)**: `ZMQ_LINGER=0` is set at socket-create
  (linger-0 always) instead of at close-time only.  Operator cannot
  configure a non-zero linger for retry-on-publish.

- **G10: in-process queue retention semantics.**
  Core: notifier is wire-only; if libzmq's SNDHWM is hit, the message
  is silently dropped — no internal buffer beyond ZMQ. camlcoin
  (`zmq_socket.ml:205-209`): EVERY send queues the message in
  `pub.message_queue` (bounded by `high_water_mark`) AND attempts the
  libzmq send. This means a successful libzmq send is followed by a
  redundant in-memory copy that persists until `clear_queue` /
  `drain_queue` is called. Test helper, but in production also
  duplicates memory.
  **BUG-W141-10 (P2)**: in-process queue retains every sent message;
  memory grows up to `high_water_mark * (longest payload)` bytes
  beyond what Core consumes.

### G11-G22: REST API (lib/rest.ml)

- **G11: `-rest` default = false.**
  Core (`init.cpp:153 DEFAULT_REST_ENABLE`): `false`. camlcoin
  (`cli.ml:154`): `rest_enabled = false`. **No bug**; PARITY.

- **G12: REST warmup gate (`CheckWarmup`).**
  Core (`rest.cpp:171-177, 183, 315, 395, 502, 624, 717, 745, 784,
  839, 899, 1094`): EVERY endpoint calls `CheckWarmup` first; during
  RPC warmup returns 503 + "Service temporarily unavailable". camlcoin
  (`rest.ml`): no warmup check on any handler. During the camlcoin
  startup window, a REST request would be served (returning empty /
  zero / stale state) instead of cleanly 503'ing.
  **BUG-W141-11 (P1)**: no warmup gate; clients hammering REST during
  startup get inconsistent results instead of 503.

- **G13: `SanitizeString(SAFE_CHARS_URI)` on error-echo of user input.**
  Core (`rest.cpp:1100`): `RESTERR(req, HTTP_BAD_REQUEST, "Invalid
  height: " + SanitizeString(height_str, SAFE_CHARS_URI))` — strips
  RFC-3986-unsafe chars before echoing in the error body. camlcoin
  (`rest.ml:730`): `respond_error \`Bad_request ("Invalid height: " ^
  height_str)` — echoes user-supplied path component verbatim. Could
  reflect CR/LF or angle-brackets back to a browser victim of an
  XSS-via-error-message style attack.
  **BUG-W141-12 (P2)**: no sanitisation of user-supplied path
  components before reflecting them in HTTP error bodies.

- **G14: `/rest/getutxos` endpoint (BIP-64).**
  Core (`rest.cpp:897-1089`): `/rest/getutxos[/checkmempool]/<txid-vout>/...`
  GET (URI) + POST (binary or hex body). MAX 15 outpoints; returns
  chainHeight + chaintipHash + bitmap + per-utxo `{height, value,
  scriptPubKey}`. Used by SPV clients. camlcoin (`rest.ml`): NOT
  IMPLEMENTED — `/rest/getutxos` returns 404.
  **BUG-W141-13 (P1)**: `/rest/getutxos` endpoint missing — SPV
  clients that probe REST for fast UTXO lookups fall back to RPC
  `gettxout` which is slower and not batched.

- **G15: `/rest/blockpart/<hash>.<format>?offset=<N>&size=<N>`.**
  Core (`rest.cpp:481-498`): partial-block read (offset + size) for
  bandwidth-constrained clients. camlcoin: NOT IMPLEMENTED.
  **BUG-W141-14 (P3)**: `/rest/blockpart/` missing — niche but Core
  supports it for partial fetching.

- **G16: `/rest/spenttxouts/<hash>.<format>`.**
  Core (`rest.cpp:313-381`): per-block undo data — useful for indexers
  rebuilding prevout/script data without scanning the whole chain.
  camlcoin: NOT IMPLEMENTED.
  **BUG-W141-15 (P1)**: `/rest/spenttxouts/` missing — indexers that
  depend on this for backfill cannot use camlcoin as a REST source.

- **G17: `/rest/deploymentinfo[/<hash>]`.**
  Core (`rest.cpp:740-780`): chain deployment info, JSON only, dispatches
  to `getdeploymentinfo` RPC. camlcoin: NOT IMPLEMENTED.
  **BUG-W141-16 (P3)**: `/rest/deploymentinfo` missing.

- **G18: `g_txindex->BlockUntilSyncedToCurrentChain()` before `rest_tx`.**
  Core (`rest.cpp:850-852`): before serving `/rest/tx/<txid>.<fmt>`,
  blocks until the tx-index has caught up to the active chain — so a
  caller that just saw a block-connect on ZMQ can immediately query
  the tx without race. camlcoin (`rest.ml:249-271`): direct lookup
  in mempool then in `ChainDB.get_tx_index` then `ChainDB.get_transaction`;
  no wait-for-sync barrier.
  **BUG-W141-17 (P1)**: `rest_tx` doesn't block on tx-index sync; tx
  added in latest block but not yet indexed returns 404 where Core
  would return the body.

- **G19: query-string stripping in `ParseDataFormat`.**
  Core (`rest.cpp:131-134`): `param = strReq.substr(0, strReq.rfind('?'));`
  — drops `?...` from the parsed string before extension detection.
  camlcoin (`rest.ml:32-36`): does the same. **No bug**; PARITY.

- **G20: deprecated `<count>/<hash>` path for `/rest/headers/`.**
  Core (`rest.cpp:191-194`): accepts both `headers/<count>/<hash>`
  (deprecated) and `headers/<hash>?count=<N>` (new). camlcoin
  (`rest.ml:335-347`): same dual-form. **No bug**; PARITY.

- **G21: `RESTERR` body terminator is `\r\n`.**
  Core (`rest.cpp:71-76`): `req->WriteReply(status, message + "\r\n");`.
  camlcoin (`rest.ml:56-59`): `body:(message ^ "\r\n")`. **No bug**;
  PARITY.

- **G22: max headers constant = 2000.**
  Core (`rest.cpp:45`): `MAX_REST_HEADERS_RESULTS = 2000`. camlcoin
  (`rest.ml:24`): `max_headers_results = 2000`. **No bug**; PARITY.

### G23-G30: Notification scripts (-blocknotify / -alertnotify /
###          -walletnotify / -startupnotify / -shutdownnotify)

- **G23: `-blocknotify=<cmd>` support.**
  Core (`init.cpp:2008-2019`): fires on every block-tip change post-IBD;
  `%s` substituted with new tip block hash; `std::thread t(runCommand,
  command); t.detach()`. camlcoin: NOT IMPLEMENTED — no `--blocknotify`
  CLI arg in `bin/main.ml`, no notify hook in `sync.ml` connect path.
  **BUG-W141-18 (P1)**: no `-blocknotify` script support.

- **G24: `-blocknotify` post-IBD gate.**
  Core (`init.cpp:2012`): `if (sync_state != SynchronizationState::POST_INIT)
  return;` — block-tip changes during IBD do NOT fire the script.
  Follow-on to G23 — even when implemented, the gate must match. **No
  bug yet** (no implementation to drift); document as PRE-REQ-FOR-G23.

- **G25: `-alertnotify=<cmd>` support.**
  Core (`kernel_notifications.cpp:30-47`): fires from `warningSet`
  with the warning message; `SanitizeString(strMessage)` →
  single-quote wrap → `ReplaceAll("%s", safeStatus)` → `runCommand`.
  camlcoin: NOT IMPLEMENTED — warnings are `Logs.warn` only.
  **BUG-W141-19 (P1)**: no `-alertnotify` script support.

- **G26: `-walletnotify=<cmd>` support.**
  Core (`wallet/wallet.cpp:1139-1165`): fires from `AddToWallet` /
  `transactionAddedToMempool`; substitutes `%s` (txid), `%b` (blockhash
  or `unconfirmed`), `%h` (height or `-1`), `%w` (wallet name,
  ShellEscape'd) on non-Windows. camlcoin: NOT IMPLEMENTED — wallet
  has no external-script hook.
  **BUG-W141-20 (P1)**: no `-walletnotify` script support.

- **G27: `-startupnotify=<cmd>` / `-shutdownnotify=<cmd>` support.**
  Core (`init.cpp:256-265, 737-746`): fires once on `AppInit`
  completion and once on `Interrupt`. camlcoin
  (`runtime_config.ml:346-355`): only fd-based `signal_ready`
  one-byte-write handshake.
  **BUG-W141-21 (P3)**: no shell-command notify on
  startup/shutdown.

- **G28: shell-escape primitive.**
  Core (`common/system.cpp:40-46` `ShellEscape`): replaces `'` with
  `'"'"'` and wraps with single quotes — the standard POSIX-safe
  single-arg quoting. camlcoin: no equivalent primitive in any of
  `lib/*.ml`. Building this is a prerequisite for `-walletnotify`'s
  `%w` substitution.
  **BUG-W141-22 (P1)**: no `ShellEscape` helper; precondition for
  any notify-script feature.

- **G29: `SanitizeString` primitive used by `-alertnotify`.**
  Core (`util/strencodings.cpp:31-46` + `kernel_notifications.cpp:40`):
  strips chars outside `SAFE_CHARS_DEFAULT` before injecting into
  the command string. camlcoin: no equivalent. Building this is a
  precondition for `-alertnotify`.
  **BUG-W141-23 (P1)**: no `SanitizeString` helper.

- **G30: `runCommand` wrapper around `system(3)`.**
  Core (`common/system.cpp:49-62`): single-call `::system()` wrapper
  that logs warning on non-zero return. camlcoin: would use
  `Sys.command` or `Unix.system`. Not built.
  **BUG-W141-24 (P3)**: no `runCommand`-equivalent wrapper —
  Sys.command would work but Core's log-on-fail behaviour is missing.

## BUG summary (24 BUGs in 30 gates)

| ID | Sev | Gate | Subsystem | Description |
|----|-----|------|-----------|-------------|
| BUG-W141-1 | P2 | G1 | ZMQ | topic-alias grammar accepts double-prefix `-zmqpubpubhashblock=` |
| BUG-W141-2 | P1 | G2 | ZMQ | no `-zmqpub<topic>hwm` per-topic HWM override |
| BUG-W141-3 | **P0-CDIV** | G3 | ZMQ | sequence/state Hashtbl keyed by topic globally → second address silently dropped |
| BUG-W141-4 | P1 | G4 | ZMQ | multi-bind on one socket → subscribers see cross-address topic spillover |
| BUG-W141-5 | P3 | G5 | ZMQ | no `unix://` → `ipc://` address rewrite |
| BUG-W141-6 | **P0-CDIV** | G6 | ZMQ | hashblock + rawblock fire during IBD (Core suppresses) |
| BUG-W141-7 | **P0-CDIV** | G7 | ZMQ | no per-tx hashtx/rawtx on block-connect |
| BUG-W141-8 | P1 | G8 | ZMQ | no `role.historical` gate — duplicate emits during assumeutxo background validation |
| BUG-W141-9 | P3 | G9 | ZMQ | `ZMQ_LINGER=0` set at socket-create not just-before-close (permanently linger-0; no operator-tunable retry window) |
| BUG-W141-10 | P2 | G10 | ZMQ | in-process queue retains every sent message redundantly |
| BUG-W141-11 | P1 | G12 | REST | no warmup gate on any handler |
| BUG-W141-12 | P2 | G13 | REST | no SAFE_CHARS_URI sanitisation of user-input before error echo |
| BUG-W141-13 | P1 | G14 | REST | `/rest/getutxos` endpoint missing |
| BUG-W141-14 | P3 | G15 | REST | `/rest/blockpart/` endpoint missing |
| BUG-W141-15 | P1 | G16 | REST | `/rest/spenttxouts/` endpoint missing |
| BUG-W141-16 | P3 | G17 | REST | `/rest/deploymentinfo` endpoint missing |
| BUG-W141-17 | P1 | G18 | REST | `rest_tx` doesn't block on tx-index sync |
| BUG-W141-18 | P1 | G23 | NOTIFY | no `-blocknotify` script support |
| BUG-W141-19 | P1 | G25 | NOTIFY | no `-alertnotify` script support |
| BUG-W141-20 | P1 | G26 | NOTIFY | no `-walletnotify` script support |
| BUG-W141-21 | P3 | G27 | NOTIFY | no `-startupnotify` / `-shutdownnotify` |
| BUG-W141-22 | P1 | G28 | NOTIFY | no `ShellEscape` primitive |
| BUG-W141-23 | P1 | G29 | NOTIFY | no `SanitizeString` primitive |
| BUG-W141-24 | P3 | G30 | NOTIFY | no `runCommand`-equivalent wrapper |

**3 P0-CDIV** (G3, G6, G7) all in the ZMQ subsystem. Each is
externally observable to subscribers built against Core's published
behaviour.

## Test plan

`test/test_w141_zmq_rest_notify.ml` covers all 30 gates:

- **API-level / behavioural** where the surface is exposed by
  `Zmq_notify.create`, `Zmq_notify.Config.parse_zmq_option`,
  `Zmq_notify.notify_*`, `Rest.parse_data_format`, etc.
- **Source-level grep** for gates without a probe surface
  (`-zmqpubhwm` parsing absence, `-blocknotify` arg absence, missing
  REST endpoint prefixes, etc.) — same pattern used by W130-W137 /
  W134's `load_source` helper.
- **Numerical / boundary oracles** for things like max-headers
  constant, max-getutxos constant, sequence-event byte layouts.
- **Invariant guards** at the tail — protocol constants, topic
  name strings, sequence event chars (`'C'`/`'D'`/`'A'`/`'R'`).

Total: 30 gates, all expected to PASS as documentary fixtures.
This is discovery only — the test asserts the absence (or presence)
of the audited surface; no production code changes.

## Camlcoin gotcha

Running this test invokes the pre-built `_build/default/test/test_w141_zmq_rest_notify.exe`
if available. `dune runtest` is the canonical invocation; the
`dune-lock-stall` workaround documented in the FIX-64 / FIX-80 era
is to run the executable directly when dune's lockfile is contended
with concurrent agents.
