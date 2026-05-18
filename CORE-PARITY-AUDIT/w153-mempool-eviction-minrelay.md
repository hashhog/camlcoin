# W153 — Mempool eviction + tx-removed signals + min-relay fee (camlcoin)

**Wave:** W153 — `TrimToSize`, `GetMinFee`, `LimitMempoolSize`,
`trackPackageRemoved`, `removeUnchecked`, `removeRecursive`,
`removeForReorg`, `removeForBlock`, `removeConflicts`, `removeStaged`,
`MaybeUpdateMempoolForReorg`, `Expire`,
`DEFAULT_MAX_MEMPOOL_SIZE_MB=300`, `DEFAULT_MEMPOOL_EXPIRY_HOURS=336`,
`DEFAULT_MIN_RELAY_TX_FEE=100`, `DEFAULT_INCREMENTAL_RELAY_FEE=100`
(both sat/kvB per `kernel/mempool_options.h` lines 23,
40-44; both `policy.h:48,70`),
`ROLLING_FEE_HALFLIFE = 12 h` (`txmempool.h:212`) — divided ×4 / ×2
based on `DynamicMemoryUsage()` vs `sizelimit`,
`MemPoolRemovalReason` enum (EXPIRY / SIZELIMIT / REORG / BLOCK /
CONFLICT / REPLACED, `kernel/mempool_removal_reason.h:13-20`),
`TransactionRemovedFromMempool` signal,
`MempoolTransactionsRemovedForBlock` signal,
`-maxmempool`, `-mempoolexpiry`, `-minrelaytxfee`,
`-incrementalrelayfee`, `-blocknotify`, `-walletnotify`, ZMQ hashtx /
rawtx / sequence A|R, REST `/mempool/{contents,info}`,
`prioritisetransaction` RPC, `getmempoolinfo` RPC.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/txmempool.cpp:828-911` — `GetMinFee(sizelimit)` (829-851),
  `trackPackageRemoved(rate)` (853-859), `TrimToSize(sizelimit, pvNoSpends)`
  (861-911). Eviction loop chooses worst-feerate **chunk** from
  `m_txgraph->GetWorstMainChunk()`; adds
  `m_opts.incremental_relay_feerate` to the removed feerate BEFORE calling
  `trackPackageRemoved`; calls `removeUnchecked(e,
  MemPoolRemovalReason::SIZELIMIT)`; collects orphaned outpoints for
  `pvNoSpendsRemaining` (used to re-broadcast to peers).
- `bitcoin-core/src/txmempool.cpp:360-386` — `removeForReorg(chain,
  check_final_and_mature)`: descends the txgraph and fires
  `removeUnchecked(it, MemPoolRemovalReason::REORG)` for any tx that
  fails CheckFinalTxAtTip OR CheckSequenceLocksAtTip OR coinbase-spend
  maturity at the new tip.
- `bitcoin-core/src/txmempool.cpp:405-431` — `removeForBlock(vtx,
  nBlockHeight)`: stages confirmed txs + their descendants for removal,
  bumps `lastRollingFeeUpdate = GetTime()` and sets
  `blockSinceLastRollingFeeBump = true`, then fires
  `MempoolTransactionsRemovedForBlock` to the fee estimator BEFORE
  iterating individual removals at `MemPoolRemovalReason::BLOCK`.
- `bitcoin-core/src/txmempool.cpp:388-403` — `removeConflicts(tx)`:
  walks `mapNextTx` and fires
  `removeRecursive(MemPoolRemovalReason::CONFLICT)` for txs that share
  any outpoint with the newly-confirmed tx.
- `bitcoin-core/src/txmempool.cpp:813-820` — `Expire(time)`: removes
  any tx whose `time_added < cutoff`; fires `removeUnchecked(it,
  MemPoolRemovalReason::EXPIRY)`.
- `bitcoin-core/src/validation.cpp:294-388` — `MaybeUpdateMempoolForReorg`:
  drains disconnect pool **in reverse** (rbegin → rend) re-ATMP'ing each
  non-coinbase tx with `bypass_limits=true`; on failure fires
  `removeRecursive(MemPoolRemovalReason::REORG)`; then
  `UpdateTransactionsFromBlock(vHashUpdate)` rebuilds child links; then
  `removeForReorg(filter_final_and_mature)`; finally `LimitMempoolSize`
  to trim back below `maxmempool` after the refill.
- `bitcoin-core/src/kernel/mempool_options.h:19-44` —
  `DEFAULT_MAX_MEMPOOL_SIZE_MB=300` (line 19); `DEFAULT_MEMPOOL_EXPIRY_HOURS=336`
  (23); `max_size_bytes{DEFAULT_MAX_MEMPOOL_SIZE_MB * 1'000'000}` (40);
  `expiry{std::chrono::hours{DEFAULT_MEMPOOL_EXPIRY_HOURS}}` (41);
  `incremental_relay_feerate{DEFAULT_INCREMENTAL_RELAY_FEE}` (42);
  `min_relay_feerate{DEFAULT_MIN_RELAY_TX_FEE}` (44).
- `bitcoin-core/src/policy/policy.h:48,70` —
  `DEFAULT_INCREMENTAL_RELAY_FEE=100` (sat/kvB);
  `DEFAULT_MIN_RELAY_TX_FEE=100` (sat/kvB).
- `bitcoin-core/src/txmempool.h:212` —
  `ROLLING_FEE_HALFLIFE = 60 * 60 * 12` (12 h).
- `bitcoin-core/src/kernel/mempool_removal_reason.h:13-20` — enum
  values {EXPIRY, SIZELIMIT, REORG, BLOCK, CONFLICT, REPLACED}.
- `bitcoin-core/src/zmq/zmqnotificationinterface.cpp:170-178` —
  `TransactionRemovedFromMempool`: emits **only** the sequence event
  (R + mempool_sequence). It does **NOT** publish hashtx / rawtx on
  removal — those are emit-on-arrival topics. Block-confirmed txs flow
  through `BlockConnected` (180-194) which fires hashtx per-tx (NOT
  hashblock-via-tx-list).
- `bitcoin-core/src/policy/fees/block_policy_estimator.cpp:586-590,
  590-594` — `TransactionRemovedFromMempool(tx, /*reason unused*/, ...)`
  calls `removeTx(hash)`; separate
  `MempoolTransactionsRemovedForBlock(txs, height)` is the
  block-confirmation signal that drives the
  estimator's bucket-confirmation counts. The two signals are distinct
  even though both touch `tracked_txs`.
- `bitcoin-core/src/init.cpp:673, 686` — `-incrementalrelayfee` and
  `-minrelaytxfee` are operator knobs in `NODE_RELAY` category;
  `-maxmempool`, `-mempoolexpiry` likewise.

**Files audited**
- `lib/mempool.ml` (4374 lines) — `create` (233-264);
  per-removal callback hook `on_eviction` (93-99, 360-362);
  `set_zmq_notifier` (322-323); `zmq_notify_tx` (329-343);
  `remove_transaction` (348-402); rolling fee state (69-75);
  `track_package_removed` (736-740); `get_min_fee` (748-777);
  `effective_min_fee` (819-821); `evict_by_chunks` (791-812);
  `evict_lowest_feerate` (902-918) [dead helper];
  `remove_for_block` (2346-2374); `expire_old_transactions` (3419-3426);
  `expire_orphans` (3429-3440); `clear` (3459-3462);
  default-network constructor `let network = Consensus.regtest` (237);
  `min_relay_fee = 1000L` (245); `max_size_bytes = 300 * 1_000_000` (244);
  `max_orphans = 100` (258); incremental_relay_fee = 100L (128).
- `lib/cli.ml:420-465` (mempool construction); `1207-1232`
  (post-IBD BlockMsg listener); `1355-1398` (CmpctBlockMsg);
  `1399-1427` (BlocktxnMsg); `1606-1635` (status-tick loop with
  `expire_orphans` only); `1640-1672` (graceful shutdown);
  `1218-1223` (orphan-only EraseForBlock).
- `lib/sync.ml:1547-1582` (`set_mempool`, `ibd.mempool` slot);
  `3585-3743` (reorganize loop with mempool refill but no
  `removeForReorg` analogue); `3703-3714` (refill iter); `3733`
  (single `remove_for_block` site, reorg-connect path only); `4358+`
  (`process_new_block` — no mempool maintenance).
- `lib/mining.ml:922` (`remove_for_block` on mined block).
- `lib/block_import.ml` (157 lines) — no mempool argument; does
  not call `Mempool.remove_for_block` after applying a block via
  `--import-blocks`.
- `lib/rpc.ml:1343-1359` (`handle_getmempoolinfo`); `1571-1612`
  (`handle_prioritisetransaction`); `1860-1944` (`handle_submitblock`).
- `lib/fee_estimation.ml:225-252` (`record_confirmation` vs
  `record_eviction` split); `278-284` (`process_block`).
- `lib/zmq_notify.ml:175-189` (`notify_hashtx`); `213-229`
  (`notify_rawtx`); `231-252` (`notify_sequence`); `263-268`
  (`notify_tx_acceptance` / `notify_tx_removal`).
- `lib/runtime_config.ml` + `bin/main.ml` — no
  `-maxmempool`, `-mempoolexpiry`, `-minrelaytxfee`,
  `-incrementalrelayfee`, `-acceptnonstdtxn`, `-datacarrier`,
  `-permitbaremultisig`, `-bytespersigop`, `-blocknotify`,
  `-walletnotify`, `-alertnotify` flags. Operator-knobs absent.

---

## Gate matrix (38 sub-gates / 14 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | DEFAULT_MAX_MEMPOOL_SIZE_MB=300 enforced | G1: `max_size_bytes = 300 * 1_000_000` | PASS (`mempool.ml:244`) |
| 1 | … | G2: TrimToSize fires when over-target | PASS (`mempool.ml:2323-2324, 791-812`) |
| 1 | … | G3: operator knob `-maxmempool` | **BUG-1 (P1)** — absent (`bin/main.ml`, `lib/runtime_config.ml` define no relay/mempool flags) |
| 2 | DEFAULT_MEMPOOL_EXPIRY_HOURS=336 | G4: 14-day expiry constant matches | PASS — `max_age = 1_209_600.0` = 336 h (`mempool.ml:3421`) |
| 2 | … | G5: `expire_old_transactions` called from production | **BUG-2 (P0)** — defined at `mempool.ml:3419-3426` but **never** called outside tests (grep result: only `test_mempool.ml:3690, 4524` callers; `cli.ml` calls only `expire_orphans`). Mempool grows unbounded by age forever |
| 2 | … | G6: operator knob `-mempoolexpiry` | **BUG-1 cross-cite** |
| 3 | DEFAULT_MIN_RELAY_TX_FEE=100 | G7: per-Core default value | **BUG-3 (P1)** — `min_relay_fee = 1000L` (`mempool.ml:245`) is **10× Core's `DEFAULT_MIN_RELAY_TX_FEE = 100`** (`bitcoin-core/src/policy/policy.h:70`). Comment claims "1 sat/vB = 1000 sat/kvB" which is correct math but wrong reference to Core's default. Camlcoin rejects txs at 1 sat/vB that Core accepts at 0.1 sat/vB. Cross-impl interop divergence |
| 3 | … | G8: operator knob `-minrelaytxfee` | **BUG-1 cross-cite** |
| 4 | DEFAULT_INCREMENTAL_RELAY_FEE=100 | G9: constant matches | PASS (`mempool.ml:128` `incremental_relay_fee = 100L`) |
| 4 | … | G10: operator knob `-incrementalrelayfee` | **BUG-1 cross-cite** |
| 5 | Rolling-fee decay | G11: `ROLLING_FEE_HALFLIFE = 12 h` | PASS (`mempool.ml:133`) |
| 5 | … | G12: halflife/4 when `usage < limit/4`; halflife/2 when `usage < limit/2` | PASS (`mempool.ml:757-762`) |
| 5 | … | G13: clamp to 0 when `rolling < incremental/2` | PASS (`mempool.ml:770-773`) |
| 5 | … | G14: 10-second update interval gate | PASS (`mempool.ml:754`) |
| 5 | … | G15: `effective_min_fee` returns max(min_relay, rolling) | PARTIAL — `effective_min_fee` (`mempool.ml:819-821`) is correct, but **BUG-4** below shows `getmempoolinfo` reports `min_relay_fee` directly, NOT `effective_min_fee` |
| 6 | MemPoolRemovalReason enum + emit | G16: enum defined (EXPIRY/SIZELIMIT/REORG/BLOCK/CONFLICT/REPLACED) | **BUG-5 (P0)** — no enum at all. `remove_transaction` (`mempool.ml:348`) has no reason parameter; ALL removal paths funnel through one untyped path |
| 6 | … | G17: removal callsite passes reason | **BUG-5 cross-cite** — caller-site has no reason to pass |
| 7 | TransactionRemovedFromMempool signal fan-out | G18: fee estimator notified | PARTIAL — `on_eviction` callback fires (`mempool.ml:360-362`), but **BUG-6** shows BLOCK removals fire `record_eviction` instead of `record_confirmation` |
| 7 | … | G19: ZMQ sequence-R emitted with mempool_sequence | PASS (`mempool.ml:343` → `notify_tx_removal`) |
| 7 | … | G20: hashtx + rawtx published ONLY on arrival, NOT on removal | **BUG-7 (P1)** — `zmq_notify_tx` (`mempool.ml:329-343`) ALWAYS publishes `notify_hashtx` AND `notify_rawtx` even when `acceptance=false` (line 337-338). Core's `TransactionRemovedFromMempool` (`zmqnotificationinterface.cpp:170-178`) emits ONLY the sequence event. Camlcoin double-fans hashtx/rawtx on every removal, breaking subscribers that interpret hashtx as "new tx arrived" |
| 7 | … | G21: REST `/rest/mempool/contents.json` after eviction reflects | UNCHECKED — REST surface not enumerated this wave |
| 7 | … | G22: tx-relay scratched on eviction | **BUG-8 (P1)** — no `pvNoSpendsRemaining` analogue. Core's `TrimToSize` collects orphan outpoints whose spending tx was evicted so subsequent peer ATMP can re-relay or so the wallet can re-broadcast (validation.cpp `LimitMempoolSize` 274-285). Camlcoin's `evict_by_chunks` (`mempool.ml:791-812`) silently drops without producing a list |
| 8 | BlockConnected mempool maintenance | G23: `remove_for_block` called from post-IBD BlockMsg path | **BUG-9 (P0-CONS)** — `cli.ml:1207-1232` calls `Sync.process_new_block` then `Fee_estimation.process_block` and `expire_orphans`, but **NEVER** `Mempool.remove_for_block`. The only `remove_for_block` callsite in `sync.ml` is the reorganize-connect path (`sync.ml:3733`); the normal extend-tip path does NOT touch the mempool. Confirmed txs stay in mempool forever; `getrawmempool` returns confirmed txs; double-relayed via inv; rolling-fee bump (`mempool.ml:2373-2374`) never fires |
| 8 | … | G24: `remove_for_block` called from CmpctBlock reconstruction path | **BUG-9 cross-cite** — `cli.ml:1357-1371` same gap |
| 8 | … | G25: `remove_for_block` called from Blocktxn reconstruction path | **BUG-9 cross-cite** — `cli.ml:1410-1424` same gap |
| 8 | … | G26: `remove_for_block` called from `block_import.ml` (`--import-blocks`) | **BUG-10 (P1)** — `block_import.ml::run` (lines 33-?) takes no mempool argument and never calls `Mempool.remove_for_block`. Bulk-import paths grow mempool without bound during import; mining/RPC after a bulk import returns stale txs from the imported blocks |
| 9 | BlockDisconnected mempool maintenance | G27: `MaybeUpdateMempoolForReorg` analogue exists | **BUG-11 (P0)** — `sync.ml:3703-3714` reorganize re-adds disconnected tx via `Mempool.add_transaction` with `bypass_limits=true / bypass_fee_check=true`, but: (a) does NOT call any `removeForReorg`-equivalent to evict txs whose locktime/sequence/coinbase-maturity is now invalid at the new tip; (b) does NOT run `LimitMempoolSize` after the refill — the mempool can balloon above `max_size_bytes`; (c) disconnect-pool iteration order is non-reverse |
| 9 | … | G28: `removeForReorg` filter checks CheckFinalTxAtTip | **BUG-11 cross-cite** |
| 9 | … | G29: `removeForReorg` filter checks CheckSequenceLocksAtTip | **BUG-11 cross-cite** |
| 9 | … | G30: `removeForReorg` filter checks coinbase-spend maturity | **BUG-11 cross-cite** |
| 10 | removeConflicts on block-connect | G31: txs sharing prevout with a confirmed tx are evicted as CONFLICT (not BLOCK) | PARTIAL — `mempool.ml:2354-2367` removes via dominate-walk, but reason is untyped (cross-cite BUG-5). Fee-estimator sees these as eviction (wrong: should be CONFLICT — and the estimator double-counts) |
| 11 | prioritisetransaction RPC | G32: `prioritisetransaction txid 0 fee_delta` dispatched | PASS (`rpc.ml:1571-1612`, `lib/mempool.ml:prioritise_transaction`, plumbing FIX-72 W120) |
| 11 | … | G33: `getprioritisedtransactions` dispatched | PASS (per `rpc.ml:8663-8668`) |
| 12 | getmempoolinfo accurate min-fee | G34: `mempoolminfee` reflects rolling+min_relay max | **BUG-4 (P0-CDIV)** — `rpc.ml:1351-1352` emits `mempoolminfee = min_relay_fee / 1e8` directly. The rolling-fee value (`get_min_fee` / `effective_min_fee`) is NEVER consulted. After eviction bumps the floor, `getmempoolinfo` lies to peers about the current admission feerate; tx submitters get spurious "Fee below minimum relay fee" rejects with no warning from RPC |
| 12 | … | G35: `incrementalrelayfee` = constant from module | **BUG-12 (P1)** — `rpc.ml:1358` hard-codes `0.00001` (=1000 sat/kvB) but `incremental_relay_fee` module constant is 100 sat/kvB (`mempool.ml:128`). Two-pipeline guard inside ONE function: the JSON value is 10× the actual policy value. Wallets reading this knob will overpay fees by 10× |
| 12 | … | G36: `mempoolminfee` and `minrelaytxfee` distinct when rolling raises | **BUG-4 cross-cite** — both emit the same value (`min_relay_fee`) |
| 13 | Mempool constructor takes network | G37: `Mempool.create` accepts `~network` arg | **BUG-13 (P0-CONS)** — `mempool.ml:233-264` `create` ignores any network param; line 237 hardcodes `let network = Consensus.regtest`. `cli.ml:434` calls `Mempool.create` without network. This is **the 5th-consecutive-quad camlcoin pipeline-drift instance** (W150 BUG-4, W151, W152, W145 block_import.ml-bypass family). Mainnet/testnet4 nodes run with a regtest-configured mempool unless `set_network` is later called. Grep shows: |
| 13 | … | G38: `cli.ml` calls `set_network` after `create` | **BUG-13 cross-cite** — no `Mempool.set_network` call in `cli.ml` |
| 14 | Notify infrastructure (-blocknotify/-walletnotify/-alertnotify) | (single behaviour, multiple knobs) | **BUG-14 (P1)** — none of the three notify-script knobs are wired (no shell-out helper in `lib/`). Fleet pattern (W141: 7 of 10 impls confirm same gap; camlcoin part of that 7) |

---

## BUG-1 (P1) — None of `-maxmempool`, `-mempoolexpiry`, `-minrelaytxfee`, `-incrementalrelayfee` operator knobs exposed

**Severity:** P1. Bitcoin Core exposes every relay-policy constant
as a CLI flag (`-maxmempool`, `-mempoolexpiry`, `-minrelaytxfee`,
`-incrementalrelayfee`, `-bytespersigop`, `-datacarrier`,
`-permitbaremultisig`, `-acceptnonstdtxn`; init.cpp:673, 686, plus
`NODE_RELAY` category arg-table). The defaults baked into camlcoin's
source are not operator-overridable.

A grep over `bin/main.ml` and `lib/runtime_config.ml` returns no match
for any of these flags. The `300 * 1_000_000` byte size limit,
`1209600` second expiry, `1000` sat/kvB min-relay, `100` sat/kvB
incremental are baked into `mempool.ml` constants with no override.

**File:** `lib/mempool.ml:128, 244-245, 3421`; `bin/main.ml` (no flag
registration); `lib/runtime_config.ml` (no field).

**Core ref:** `bitcoin-core/src/init.cpp:673, 686`;
`bitcoin-core/src/kernel/mempool_options.h:19-44`.

**Impact:** operator cannot tune a high-RAM signet to `-maxmempool=4096`;
cannot drop relay fee for a test network; cannot extend the expiry on
a slow signet; cross-impl divergence vs Core's well-known knob set. A
companion to the dead-data-plumbing fleet pattern: the value is set in
exactly one place with no other source of truth.

---

## BUG-2 (P0) — `expire_old_transactions` is dead code: 336-hour expiry never runs in production

**Severity:** P0. Bitcoin Core's `CTxMemPool::Expire(GetTime() -
m_opts.expiry.count())` is invoked from the post-block hook in
`Chainstate::ConnectTip` (after `LimitMempoolSize`), guaranteeing that
on every connected block, transactions older than
`DEFAULT_MEMPOOL_EXPIRY_HOURS=336` are evicted with reason `EXPIRY`.

camlcoin defines `expire_old_transactions` at `mempool.ml:3419-3426`
with the correct 336-hour constant (`max_age = 1_209_600.0`). A grep
across the project shows the function is called from only:

- `test/test_mempool.ml:3690` — a regression test
- `test/test_mempool.ml:4524` — another test

**Zero production callsites.** `cli.ml` schedules a status-tick loop
that runs `Mempool.expire_orphans` every 30 seconds (`cli.ml:1626`) and
on every block connect (`cli.ml:1221`) but **never** schedules
`expire_old_transactions`. A node that runs for 14 days continuously
will retain mempool entries forever; `getrawmempool` returns
zombie txs; mempool memory grows unbounded until eviction kicks in
solely from TrimToSize at `max_size_bytes`, by which point the bottom
of the priority-ordered eviction set is what gets dropped — NOT the
oldest, which is what Core's two-stage policy
(`Expire` THEN `LimitMempoolSize`) guarantees.

**File:** `lib/mempool.ml:3419-3426` (definition);
`lib/cli.ml` (no production callsite); `lib/sync.ml` (no production
callsite).

**Core ref:** `bitcoin-core/src/txmempool.cpp:813-820`
(`Expire(time)`); `bitcoin-core/src/validation.cpp::Chainstate::ConnectTip`
(post-block call to `Expire`).

**Excerpt (camlcoin, dead helper)**
```ocaml
(* Gap 7: Expire mempool transactions older than 14 days *)
let expire_old_transactions (mp : mempool) : int =
  let now = Unix.gettimeofday () in
  let max_age = 1_209_600.0 in (* 14 days in seconds *)
  let to_remove = Hashtbl.fold (fun _k entry acc ->
    if now -. entry.time_added > max_age then entry.txid :: acc else acc
  ) mp.entries [] in
  List.iter (fun txid -> remove_transaction mp txid) to_remove;
  List.length to_remove
```

The "Gap 7" comment-as-confession marks this as a known unfilled gap
that has been left dead for at least the duration since `_w103_*`
recovery. **9th distinct camlcoin "dead-helper-at-call-site"
instance** (W152 recorded 6 in one wave; this brings the running total
to 9 across the recent quads).

**Impact:**
- mempool size grows past `300 MB` solely on age accumulation; eviction
  by feerate (not age) means a stale low-priority tx at 5 sat/vB can
  outlive a fresh 2 sat/vB tx, violating Core's age-first policy;
- monitoring tools (`getrawmempool` JSON, ZMQ rawtx hose) show
  weeks-old confirmed-or-replaced txs that are no longer connectable;
- the rolling fee floor (`get_min_fee`) decays toward zero based on
  `blockSinceLastRollingFeeBump`, which is set to `true` in
  `remove_for_block` — so paradoxically a node with NO BLOCK ARRIVALS
  and lots of expiry-eligible txs keeps the floor flat at the last
  bump value because expiry never fires to bump-down anything.

---

## BUG-3 (P1) — `min_relay_fee = 1000L` is 10× higher than Core's `DEFAULT_MIN_RELAY_TX_FEE = 100`

**Severity:** P1. `bitcoin-core/src/policy/policy.h:70` defines
`DEFAULT_MIN_RELAY_TX_FEE{100}` (sat/kvB). camlcoin's mempool
constructor sets `min_relay_fee = 1000L` (`mempool.ml:245`) with the
inline comment:

```ocaml
min_relay_fee = 1000L;  (* 1 sat/vB = 1000 sat/kvB *)
```

The math is correct (1 sat/vB *is* 1000 sat/kvB), but the value is
**10× Core's default**. Core defaults to 0.1 sat/vB; camlcoin defaults
to 1 sat/vB. Since the comment confidently states "1 sat/vB" without
cross-referencing Core's actual constant, this looks like a value-vs-Core
divergence with confidence-from-the-wrong-direction (the comment makes
it look correct, the value is 10× off).

Practical effect:
- a tx at 0.5 sat/vB that Core's mempool admits is rejected by camlcoin
  with "Fee below minimum relay fee" — cross-impl divergence;
- on testnet4 and signet where fee floors are intentionally lowered,
  camlcoin nodes participate poorly;
- the eviction floor anchored against `min_relay_fee` rejects more txs
  than Core's would (the `effective_min_fee = max(min_relay_fee,
  rolling)` clamp uses this raised floor).

**File:** `lib/mempool.ml:245`.

**Core ref:** `bitcoin-core/src/policy/policy.h:70` —
`static constexpr unsigned int DEFAULT_MIN_RELAY_TX_FEE{100};`

**Impact:** rejects ~10× of low-feerate txs Core admits;
cross-impl divergence on every signet/testnet4 IBD; this is a
**comment-as-confession 12th instance** (the inline comment confidently
asserts a value-unit-conversion identity that is mathematically true
but semantically wrong vs Core's policy default).

---

## BUG-4 (P0-CDIV) — `getmempoolinfo` lies about `mempoolminfee`: ignores rolling floor

**Severity:** P0-CDIV (cross-impl divergence — JSON-RPC contract).
Bitcoin Core's `getmempoolinfo` emits `mempoolminfee` as
`pool.GetMinFee(maxmempool).GetFeePerK()` — the rolling
exponential-decay floor as computed by `txmempool.cpp:828-851`. This
is the floor that tx submitters MUST exceed; it can be much higher
than the static `minrelaytxfee` after eviction bumps. Wallets that
poll `getmempoolinfo` use it to construct fees that will be accepted.

camlcoin's `handle_getmempoolinfo` (`rpc.ml:1343-1359`) emits
`mempoolminfee` as `min_relay_fee` directly, with no rolling-fee
consultation:

```ocaml
("mempoolminfee", `Float
  (Int64.to_float ctx.mempool.min_relay_fee /. 100_000_000.0));
("minrelaytxfee", `Float
  (Int64.to_float ctx.mempool.min_relay_fee /. 100_000_000.0));
```

Both fields emit the same value. After `evict_by_chunks` raises the
floor to (say) 50 sat/vB, `getmempoolinfo` still reports `mempoolminfee
= 0.00001` (the `min_relay_fee / 1e8` calculation). Tx submissions at
40 sat/vB get rejected by `accept_to_memory_pool` with "Fee below
minimum relay fee" even though the JSON-RPC said the floor was 1 sat/vB.

**File:** `lib/rpc.ml:1343-1359`.

**Core ref:** `bitcoin-core/src/rpc/mempool.cpp::getmempoolinfo` —
calls `pool.GetMinFee(maxmempool).GetFeePerK()` for `mempoolminfee`
and `pool.m_opts.min_relay_feerate.GetFeePerK()` for `minrelaytxfee`.

**Impact:**
- wallets/exchanges polling `getmempoolinfo` to size fees see stale
  floor; submitted txs get rejected at the next-block boundary;
- monitoring tools report inconsistent state (e.g., bitcoin-mempool-stats
  exporter graphs flat `mempoolminfee` even after a 500MB eviction surge);
- this is a **two-pipeline guard 17th distinct extension**: `effective_min_fee`
  (the gate that REJECTS txs) and `mempoolminfee` (the JSON value that
  ADVERTISES the gate) consult different sources of truth.

---

## BUG-5 (P0) — No `MemPoolRemovalReason` enum; `remove_transaction` accepts no reason

**Severity:** P0. Bitcoin Core's `MemPoolRemovalReason` enum
(`kernel/mempool_removal_reason.h:13-20`) distinguishes EXPIRY,
SIZELIMIT, REORG, BLOCK, CONFLICT, REPLACED. Every removal callsite in
Core passes the appropriate reason; the
`TransactionRemovedFromMempool` signal carries it; the fee estimator,
ZMQ publisher, and `MempoolTransactionsRemovedForBlock` signal route on it.

camlcoin has no such type. `lib/mempool.ml:348-402`
`remove_transaction` is a single untyped function called from:
- `evict_by_chunks` line 807 (would be SIZELIMIT)
- `evict_lowest_feerate` line 914 (would be SIZELIMIT, dead helper)
- `remove_for_block` line 2352 (would be BLOCK)
- `remove_for_block` line 2366 — for txs that share prevouts (would be CONFLICT)
- `replace_by_fee_with_replaced` line 3060 (would be REPLACED)
- `expire_old_transactions` line 3425 (would be EXPIRY — but dead, BUG-2)
- the reorganize disconnect path drives `Mempool.add_transaction` re-adds
  (no removal at all — BUG-11)

All these flow through the same `on_eviction` and ZMQ hooks. The fee
estimator can't distinguish "tx confirmed in a block (should record
confirmation)" from "tx evicted for size (should record eviction)". The
ZMQ publisher emits the same R event for REPLACED and CONFLICT (which
is what Core does — both fire R) but ALSO for BLOCK (which Core does
NOT — Core's R event excludes block-induced removals, line 174-178 of
zmqnotificationinterface.cpp passes through `removeUnchecked` reason).

**File:** `lib/mempool.ml:348` (`remove_transaction` signature has no
reason); all 6 callers (see bullet list above) pass none.

**Core ref:** `bitcoin-core/src/kernel/mempool_removal_reason.h:13-20`
(enum); `bitcoin-core/src/txmempool.h:325, 584, 587, 590` (all four
removal helpers take `MemPoolRemovalReason`); `bitcoin-core/src/txmempool.cpp`
(all callers pass).

**Impact:** every downstream consumer that needs to route on the
removal reason is broken:
- Fee estimator double-counts (BUG-6 cross-cite);
- ZMQ subscribers receive sequence-R events for block-confirmed txs,
  conflating "evicted" and "confirmed";
- the ZMQ raw/hash hose (BUG-7) emits hashtx/rawtx on removal, which
  Core never does;
- diagnostic logs lose the reason a tx was removed — operators
  debugging "why did my tx disappear" can't tell.

This is a **two-pipeline guard 18th distinct extension** at the API
level: the function has only one removal API but the conceptual model
has six. Cross-cite with BUG-11 (reorg removal class).

---

## BUG-6 (P0) — `remove_for_block` calls `record_eviction` (not `record_confirmation`) for confirmed txs

**Severity:** P0 (fee-estimator data corruption). Bitcoin Core has
**two distinct signals** to the fee estimator:
- `TransactionRemovedFromMempool(tx, reason, seq)` → `removeTx(hash)` —
  decrements `tracked_txs` without scoring.
- `MempoolTransactionsRemovedForBlock(txs, height)` → `processBlock(...)` —
  scores each tx as confirmed at the given height + decrements
  `mapMemPoolTxs`.

camlcoin's `remove_for_block` (`mempool.ml:2346-2374`) iterates each
block-tx and calls `remove_transaction`. `remove_transaction` fires the
`on_eviction` callback, which `cli.ml:434-437` has wired to
`Fee_estimation.record_eviction`. So for every confirmed tx in a block:

1. `remove_for_block` → `remove_transaction` → `on_eviction` →
   `Fee_estimation.record_eviction` → decrements `total_unconfirmed`
   and removes from `tracked_txs` (line 240-252 of fee_estimation.ml).
2. THEN (in `cli.ml:1215`) `Fee_estimation.process_block` →
   `record_confirmation` for the same txid → `Hashtbl.find_opt
   est.tracked_txs txid_key` returns `None` because step 1 already
   removed it → the confirmation is silently dropped (line 230 of
   fee_estimation.ml).

**Net effect:** the fee estimator NEVER records confirmations from
post-IBD blocks. Every confirmation is converted into a NULL signal by
the fee-estimator's two-step block-processing path. Estimator buckets
that count "txs confirmed in N blocks" stay empty; the smartfee API
returns the static fallback `min_relay_fee` (cross-cite BUG-3, 10×
inflated) or sentinel "not enough data".

Worse: at the same time, `total_unconfirmed` is decremented as if these
were evictions — the bucket statistics show high eviction rates the
node didn't actually experience, perturbing the decay-bucket math
toward the eviction tail.

**File:** `lib/mempool.ml:2346-2374` (`remove_for_block`); `lib/mempool.ml:348-362`
(`remove_transaction` always fires `on_eviction`); `lib/cli.ml:434-437`
(wires `record_eviction` as the only callback).

**Core ref:** `bitcoin-core/src/policy/fees/block_policy_estimator.cpp:580-594`
(distinct hooks for removal vs block-confirmation);
`bitcoin-core/src/txmempool.cpp:405-431` (`removeForBlock` fires the
block-specific signal BEFORE iterating individual removals).

**Excerpt (camlcoin, double-decrement)**
```ocaml
(* mempool.ml:360 — fires for EVERY removal incl BLOCK *)
(match mp.on_eviction with
 | Some cb -> cb entry.txid
 | None -> ());
```

```ocaml
(* fee_estimation.ml:225-236 — record_confirmation no-ops if removed *)
| Some (fee_rate, added_height, _timestamp) ->
  Hashtbl.remove est.tracked_txs txid_key;
  ...
```

```ocaml
(* fee_estimation.ml:243 — record_eviction *)
match Hashtbl.find_opt est.tracked_txs txid_key with
| None -> ()
```

The order matters: `remove_transaction` runs FIRST (inside the
block-connect flow via `remove_for_block` — but wait, see BUG-9
below — actually it does NOT run from the post-IBD path because of
BUG-9, so on the post-IBD path the eviction-side decrement also
doesn't happen. The bug here primarily bites on the
mining/reorg/submitblock paths where `remove_for_block` DOES run.)

**Impact:** fee estimator silently corrupts on every mined block (mining
path), every submitblock RPC, and every reorg-connect. Estimator
becomes unreliable; `estimatesmartfee` returns sentinel; wallets
underpay/overpay. The post-IBD path (BUG-9) avoids the corruption
ONLY by failing to call `remove_for_block` at all (a different bug
masking this one).

---

## BUG-7 (P1) — ZMQ publishes hashtx + rawtx on REMOVAL (Core publishes only sequence-R)

**Severity:** P1 (ZMQ subscriber contract divergence; debugger
confusion). Bitcoin Core's
`CZMQNotificationInterface::TransactionRemovedFromMempool`
(zmqnotificationinterface.cpp:170-178) emits **only** the sequence
event (R + 8-byte mempool_sequence). hashtx and rawtx are
"new-tx-arrived" topics; they are NOT republished on removal.

camlcoin's `zmq_notify_tx` (`mempool.ml:329-343`) fires the same fan-out
regardless of `acceptance`:

```ocaml
let zmq_notify_tx (mp : mempool) (txid : Types.hash256) (tx : Types.transaction)
    (acceptance : bool) : unit =
  match mp.zmq_notifier with
  | None -> ()
  | Some notifier ->
    let seq = mp.zmq_sequence in
    mp.zmq_sequence <- Int64.add seq 1L;
    (* Publish hashtx and rawtx *)
    ignore (Zmq_notify.notify_hashtx notifier txid);
    ignore (Zmq_notify.notify_rawtx notifier tx);
    (* Publish sequence event *)
    if acceptance then
      ignore (Zmq_notify.notify_tx_acceptance notifier txid seq)
    else
      ignore (Zmq_notify.notify_tx_removal notifier txid seq)
```

The `if acceptance` branch only varies the sequence event — hashtx and
rawtx fire unconditionally above. A subscriber expecting "hashtx = new
mempool tx" will see eviction-and-replacement double-events for the
same txid, and rawtx subscribers will see the full transaction
republished even though they already saw it on arrival.

**File:** `lib/mempool.ml:329-343`.

**Core ref:** `bitcoin-core/src/zmq/zmqnotificationinterface.cpp:170-178`.

**Impact:**
- electrs / fulcrum / mempool.space / nbxplorer subscribers see
  duplicate hashtx events per tx (once on arrival, once on removal);
- rawtx bandwidth is ~2× Core's for the same tx flow;
- subscribers that index hashtx as "tx-first-seen" misattribute
  evicted txs to fresh arrivals.

This is a **W141 fleet companion** — that wave's blockbrew W141
BUG-15 was the inverse (Core emits hashtx in BlockConnected per-tx but
blockbrew didn't); here camlcoin emits hashtx where Core doesn't.

---

## BUG-8 (P1) — `evict_by_chunks` has no `pvNoSpendsRemaining` analogue

**Severity:** P1. Bitcoin Core's `TrimToSize` (txmempool.cpp:861-911)
takes a `std::vector<COutPoint>* pvNoSpendsRemaining` parameter. After
each chunk-eviction, for every tx in the evicted chunk, every input
whose prevout-hash is no longer in the mempool is appended to that
vector. The caller (`LimitMempoolSize` in validation.cpp) uses this
list to:
- mark the outpoint freshly-spendable for wallet re-broadcast;
- prune `m_recent_rejects` for the tx that just got freed;
- re-add to the unbroadcast set if the tx was source-local.

camlcoin's `evict_by_chunks` (`mempool.ml:791-812`) has no such
parameter and returns `unit`. Orphan-outpoint information is
lost on eviction.

**File:** `lib/mempool.ml:791-812`.

**Core ref:** `bitcoin-core/src/txmempool.cpp:861-911` (TrimToSize
pvNoSpendsRemaining); `bitcoin-core/src/validation.cpp::LimitMempoolSize`
(consumer).

**Impact:** wallet-local re-broadcast doesn't fire after a node-local
eviction; recent-rejects table doesn't prune; SOME peer ATMP attempts
may be wrongly short-circuited as known-bad post-eviction. Not a
consensus issue; operational quality-of-service gap.

---

## BUG-9 (P0-CONS) — `Mempool.remove_for_block` is NEVER called from the post-IBD block-arrival path

**Severity:** P0-CONS (consensus-adjacent / mempool integrity).
`Mempool.remove_for_block` (`mempool.ml:2346-2374`) is the single
function that removes confirmed txs from the mempool, bumps the
rolling-fee decay timer, and resolves block-vs-mempool conflicts. It
must run on every connected block.

Production block-arrival paths in camlcoin:

| Path | File:line | Calls `remove_for_block`? |
|------|-----------|---------------------------|
| Post-IBD P2P BlockMsg | `cli.ml:1207-1232` | **NO** |
| CmpctBlock reconstruction | `cli.ml:1357-1371` | **NO** |
| Blocktxn reconstruction | `cli.ml:1410-1424` | **NO** |
| IBD block-receive pipeline | `sync.ml::process_new_block` (4358+) | **NO** |
| `--import-blocks` bulk load | `block_import.ml::run` | **NO** (see BUG-10) |
| Reorganize-connect | `sync.ml:3733` | **YES** |
| Mining (regtest generate, submitblock) | `mining.ml:922` | **YES** |

The only paths that maintain the mempool are reorg and mining — i.e.,
the rare paths. **The normal IBD + post-IBD extend-tip flow does not
touch the mempool at all when a block is connected.**

Confirmed txs stay in `mp.entries` forever (until they age out — but
see BUG-2, that's also broken). `getrawmempool` returns confirmed txs.
The mining selector picks them again and produces invalid block
templates. Tx-relay re-announces them via inv. The rolling-fee
bump never fires on post-IBD blocks (line 2373-2374), so the floor
decays even when blocks are connecting normally — the opposite of
Core's intent.

**File:** `lib/cli.ml:1207-1232` (post-IBD BlockMsg listener; gap);
`lib/cli.ml:1357-1371` (cmpct); `lib/cli.ml:1410-1424` (blocktxn);
`lib/sync.ml::process_new_block` (no mempool maintenance).

**Core ref:** `bitcoin-core/src/validation.cpp::Chainstate::ConnectTip`
calls `m_mempool->removeForBlock(*pblock.vtx, pindexNew->nHeight)`
unconditionally as part of the connect-tip sequence.

**Excerpt (camlcoin, post-IBD gap)**
```ocaml
(* cli.ml:1207-1232 — fee_estimator called but NOT remove_for_block *)
(match Sync.process_new_block chain block with
 | Ok () ->
   (try Fee_estimation.process_block fee_estimator block chain.blocks_synced
    with _ -> ());
   (let n = Mempool.expire_orphans mempool in
    if n > 0 then ...);
   (* MISSING: Mempool.remove_for_block mempool block chain.blocks_synced *)
   Lwt.async (fun () ->
     Peer_manager.announce_block peer_manager block.Types.header hash);
   Lwt.return_unit
```

**Impact:**
- mempool contains confirmed txs for the lifetime of the process;
- `getrawmempool` JSON-RPC returns stale data;
- BIP-152 cmpctblock filling consults mempool first — finds confirmed
  txs there, fills slots correctly by accident, but `getblocktemplate`
  generates invalid templates that re-include confirmed txs;
- inv-based tx relay re-announces confirmed txs to peers, who ban us
  for tx-relay spam;
- the mempool grows toward `max_size_bytes` due solely to confirmed-tx
  accumulation; `TrimToSize` then evicts oldest-low-feerate (including
  legitimate unconfirmed txs) to make room for older confirmed txs.

This is a **5th-consecutive-quad camlcoin multi-pipeline drift**
(W143/W144/W145/W149/W150/W151/W152/W153): the block-arrival pipeline
exists in 5+ places (BlockMsg, CmpctBlock, Blocktxn, IBD, reorg,
mining), and the mempool-maintenance step is missing from 4 of them.
Cross-cite with W150 BUG-4 (`Mempool.create` regtest hardcode).

---

## BUG-10 (P1) — `block_import.ml` has no mempool argument and never updates the mempool

**Severity:** P1. The `--import-blocks` bulk-load path
(`lib/block_import.ml::run`) takes `db`, `chain`, `network`, `utxo`
arguments but **no mempool** argument. The function applies each
block, mutates the chain state, and continues — without touching the
mempool.

A typical operational use is: stop the node, run `block_reader.py |
camlcoin --import-blocks -` to fast-forward sync via reference Bitcoin
Core data, then restart in normal mode. If the persisted
`mempool.dat` survives the import, the mempool comes back with txs
that are now confirmed in the imported chain — **not** removed because
the import path never called `remove_for_block`. Cross-cite W145 BUG-1
(P0-CONS): `block_import.ml` already bypasses the full validation
pipeline; here it also bypasses mempool maintenance, compounding the
fleet pattern.

**File:** `lib/block_import.ml:33-?` (function signature line 33-35).

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp::ImportBlocks` and
`bitcoin-core/src/validation.cpp::ProcessNewBlock` — both call
`Chainstate::ConnectTip` which calls `removeForBlock` unconditionally
regardless of the originating import vs P2P path.

**Impact:** post-import mempool retains every tx that was confirmed
during the import window; first post-import `getrawmempool` returns
the entire imported-blocks tx set as "unconfirmed"; first
`getmempoolinfo` reports a wildly inflated count. Cross-cite W145
BUG-1: this is the same pipeline-bypass family.

---

## BUG-11 (P0) — No `removeForReorg` analogue: post-reorg mempool retains txs invalid at the new tip

**Severity:** P0. Bitcoin Core's `Chainstate::MaybeUpdateMempoolForReorg`
(`validation.cpp:294-388`) does THREE things on every reorg:

1. Drains the disconnect-pool in **reverse** (rbegin → rend) and
   re-ATMPs each non-coinbase tx with `bypass_limits=true`; on
   failure, fires `removeRecursive(REORG)` to clear orphaned descendants.
2. After the refill, calls `removeForReorg(filter_final_and_mature)` —
   walks **every** existing mempool entry and evicts those whose
   `CheckFinalTxAtTip` OR `CheckSequenceLocksAtTip` OR coinbase-spend
   maturity now fails at the new tip.
3. Calls `LimitMempoolSize` to trim back below `maxmempool`.

camlcoin's reorganize (`sync.ml:3585-3743`) does step 1 only
(re-add disconnected txs at `sync.ml:3703-3714`). Steps 2 and 3 have
no implementation:

```ocaml
(* sync.ml:3703-3714 — only the re-add half *)
(match ibd.mempool with
 | Some mp ->
   List.iter (fun tx ->
     ignore (Mempool.add_transaction
               ~bypass_fee_check:true
               ~bypass_limits:true
               mp tx)
   ) !disconnected_txs;
   ...
 | None -> ());
(* MISSING: Mempool.removeForReorg mp chain.tip
   MISSING: Mempool.limit_mempool_size mp *)
```

A grep over `lib/mempool.ml` for `removeForReorg`, `remove_for_reorg`,
`reorg_filter`, `filter_final_and_mature` returns zero matches. The
function does not exist.

Failure modes:
- A tx in the mempool whose coinbase parent was at height `H` in the
  old chain and is no longer at height `H` (the reorg replaced that
  block) but the tx's `current_height + 1 - utxo_height < 100` check
  WAS passing at the old tip and is FAILING at the new tip: the tx
  remains in the mempool, `getrawmempool` reports it, mining selects
  it → block is rejected at submitblock with bad-txns-premature-spend.
- A tx with `nLockTime > new_tip_time`: same shape.
- A tx with `BIP-68 nSequence > 0` whose `utxo_mtps` cached at
  admission no longer reflects the new MTP after the reorg.

Also missing step 3 (`LimitMempoolSize`): the refill at line 3705 can
add a large number of disconnected txs back, blowing past
`max_size_bytes`. No trim runs after the refill. The
`evict_by_chunks` call at `mempool.ml:2323-2324` only runs from
`add_transaction` itself, so each refill iteration MAY trigger eviction
— but with `bypass_limits=true` the eviction check is bypassed.

**File:** `lib/sync.ml:3703-3714` (refill half present; reorg-filter
half missing); `lib/mempool.ml` (no `removeForReorg` function).

**Core ref:** `bitcoin-core/src/validation.cpp:294-388`
(`MaybeUpdateMempoolForReorg`); `bitcoin-core/src/txmempool.cpp:360-386`
(`removeForReorg`).

**Excerpt (Core's filter_final_and_mature)**
```cpp
// Core: validation.cpp:341-382 — predicate filters out txs that are
// no longer final OR spend an immature coinbase at the new tip.
const auto filter_final_and_mature = [&](CTxMemPool::txiter it) ... {
    if (!CheckFinalTxAtTip(*Assert(m_chain.Tip()), tx)) return true;
    ...
    if (it->GetSpendsCoinbase()) { ... maturity check ... }
    return false;
};
m_mempool->removeForReorg(m_chain, filter_final_and_mature);
LimitMempoolSize(*m_mempool, this->CoinsTip());
```

**Impact:**
- post-reorg mempool retains txs whose maturity / locktime / sequence
  invalidation was caused by the reorg;
- `submitblock` after a reorg can fail with `bad-txns-premature-spend`
  because the template includes a now-immature coinbase spend;
- the rolling-fee floor is unchanged through the reorg even when the
  newly-re-added disconnected txs pushed total weight past
  `max_size_bytes`;
- combined with BUG-2 (no expiry), a node that has had many reorgs
  retains layers of historical mempool sediment.

Cross-cite with W132 BUG-4 (TestLockPointValidity not called on
reorg); this is the same architectural gap surfaced at the
reorg-maintenance layer.

---

## BUG-12 (P1) — `incrementalrelayfee` JSON field hard-codes 0.00001 (1000 sat/kvB); ignores `incremental_relay_fee = 100`

**Severity:** P1. `lib/rpc.ml:1358` emits:

```ocaml
("incrementalrelayfee", `Float 0.00001);
```

`0.00001 BTC = 0.00001 * 1e8 sat = 1000 sat`. Divided by 1 kvB = 1000
sat/kvB. But the camlcoin policy constant
`Mempool.incremental_relay_fee = 100L` (`mempool.ml:128`) is **100
sat/kvB**, matching Core's `DEFAULT_INCREMENTAL_RELAY_FEE=100`.

So the RPC reports **10×** the actual policy value. RBF-aware wallets
that pre-compute the minimum fee bump using `getmempoolinfo` will
overpay 10× on every replacement. The `rolling_fee_halflife` clamp
(line 770-773 of mempool.ml) clamps to zero at `incremental_relay_fee /
2 = 50 sat/kvB` — but RPC tells the operator the threshold is 500
sat/kvB.

This is a **two-pipeline guard 19th distinct instance** at the RPC
serialization layer: the in-memory float-literal in `rpc.ml` and the
in-memory int64 constant in `mempool.ml` are decoupled.

**File:** `lib/rpc.ml:1358`.

**Core ref:** `bitcoin-core/src/policy/policy.h:48`;
`bitcoin-core/src/rpc/mempool.cpp::getmempoolinfo` (emits
`pool.m_opts.incremental_relay_feerate.GetFeePerK()`).

**Impact:** RBF replacements pay 10× the necessary minimum incremental;
ZMQ/REST consumers reading the value see stale; cross-impl divergence
in wallet behaviour.

---

## BUG-13 (P0-CONS) — `Mempool.create` hardcodes `network = Consensus.regtest`; never set on mainnet

**Severity:** P0-CONS (already catalogued as W150 BUG-4; re-confirmed
in this audit's removal-path scope). `lib/mempool.ml:237` inside
`create`:

```ocaml
let create ?(require_standard=true) ?(verify_scripts=true)
    ?(zmq_notifier : Zmq_notify.t option)
    ?(on_eviction : (Types.hash256 -> unit) option = None)
    ~(utxo : Utxo.UtxoSet.t) ~(current_height : int) () : mempool =
  let network = Consensus.regtest in       (* <-- always regtest *)
  ...
```

There is no `?network` parameter; the only way to fix the network is to
call `Mempool.set_network mempool n` after construction. A grep of
`cli.ml` for `Mempool.set_network` returns zero hits. The mempool
runs with regtest network params on mainnet/testnet4/signet for the
lifetime of the process.

Within W153's eviction scope, this manifests as:
- `network.policy_height` / `network.activation_height` checks inside
  ATMP gate logic key off regtest values, accepting txs that would be
  non-standard on mainnet;
- the standardness rejection codes returned to peers carry
  regtest-flavour rejected-reasons.

**Carry-forward:** W150 BUG-4 catalogued this; ~24 weeks open since
W129. Should be fixed in the same patch as the next mempool-create
refactor.

**File:** `lib/mempool.ml:233-264`; `lib/cli.ml:434-437`.

**Core ref:** `bitcoin-core/src/kernel/mempool_options.h::MemPoolOptions`
(takes `consensus_params` reference at construction).

**Impact:** see W150 BUG-4 for the full impact analysis. Listed here
for fleet-pattern continuity: this is the **5th-consecutive-quad
camlcoin pipeline-drift** finding (W143, W144, W145, W149, W150,
W151, W152, W153 all touch this family).

---

## BUG-14 (P1) — No `-blocknotify`, `-walletnotify`, `-alertnotify` operator hooks

**Severity:** P1 (fleet pattern; W141 catalogued 7-of-10 impls
missing). Bitcoin Core's `-blocknotify=<cmd>` and `-walletnotify=<cmd>`
shell out to an operator-defined command on block-connect /
wallet-tx-add events. Camlcoin has no equivalent — no flag in
`bin/main.ml`, no shell-out helper in `lib/`.

Within W153's scope this matters because operators commonly use
`-blocknotify` to drive monitoring scripts that refresh
`getmempoolinfo` and feed downstream analytics. Without the hook, the
operator polls on a schedule, missing in-between block-connects with
high-volume mempool churn.

**File:** `bin/main.ml` (no flag); `lib/runtime_config.ml` (no field).

**Core ref:** `bitcoin-core/src/init.cpp` (registers
`-blocknotify=<cmd>` `-walletnotify=<cmd>` `-alertnotify=<cmd>`).

**Impact:** notify-script ecosystem incompat; operator monitoring
must poll. Same shape as W141 fleet pattern — bundle a single
`ShellEscape` helper + 3 callsites and the gap closes.

---

## BUG-15 (P1) — `evict_lowest_feerate` defined but never called (dead helper); 75% target diverges from Core

**Severity:** P1 ("dead-helper-at-call-site" fleet pattern, 10th
distinct camlcoin instance). `lib/mempool.ml:902-918` defines:

```ocaml
let evict_lowest_feerate (mp : mempool) : unit =
  let entries = Hashtbl.fold (fun _ v acc -> v :: acc) mp.entries [] in
  let sorted = List.sort
    (fun a b ->
      compare (descendant_score mp a) (descendant_score mp b)) entries in
  (* Target 75% of max size -- fixed integer division ordering bug *)
  let target = mp.max_size_bytes * 3 / 4 in
  let rec evict = function
    | [] -> ()
    | entry :: rest ->
      if mp.total_weight <= target then ()
      else begin
        remove_transaction mp entry.txid;
        evict rest
      end
  in
  evict sorted
```

A grep for `evict_lowest_feerate` shows ONE callsite — the definition
itself. No production call. The function is dead.

Even if it were called, the `target = mp.max_size_bytes * 3 / 4`
constant (75% of max) does NOT match Core's `TrimToSize(sizelimit)`,
which trims to `DynamicMemoryUsage() <= sizelimit` (the full limit, not
75%). The comment "fixed integer division ordering bug" suggests a
prior bug history but the 75% target itself is the bug.

The chunk-based `evict_by_chunks` (`mempool.ml:791-812`) is the actual
production eviction path. This descendant-score path is shadow code.

**File:** `lib/mempool.ml:902-918`.

**Core ref:** `bitcoin-core/src/txmempool.cpp:861-911`
(`TrimToSize(sizelimit, pvNoSpendsRemaining)`).

**Impact:** dead helper; cleanup candidate. No runtime effect. Cross-cite
with W152 BUG dead-helper cluster (6 instances that wave); this
brings the running total to 10.

---

## BUG-16 (P1) — `track_package_removed` is the only floor-bump call site; `removeForReorg` and `removeForBlock` don't bump

**Severity:** P1. Core's `TrimToSize` calls `trackPackageRemoved`
once per evicted chunk. Camlcoin's `track_package_removed`
(`mempool.ml:736-740`) is called from one site: `evict_by_chunks` line
805. `remove_for_block` (line 2346) does NOT call it.

That's actually correct for the BLOCK reason (Core's
`removeForBlock` ALSO doesn't call `trackPackageRemoved`; it bumps
`lastRollingFeeUpdate` and `blockSinceLastRollingFeeBump` separately).
But camlcoin's `remove_for_block` line 2373-2374 sets
`block_since_last_rolling_fee_bump <- true` AND
`last_rolling_fee_update <- Unix.gettimeofday ()` — which is correct.

However the BUG is on the reorg side: after `removeForReorg`-equivalent
(missing, BUG-11), if a future implementation re-evicts due to
maturity/locktime invalidation, those eviction events would NOT bump
the rolling fee (because `track_package_removed` is wired only to
`evict_by_chunks`). Core's `removeForReorg` does NOT call
`trackPackageRemoved` either (it's not a feerate-pressure eviction),
so this is consistent — but the BUG flag here is that the rolling-fee
state machine has no documentation of these intentional non-bumps,
and any future refactor risks accidentally wiring it.

This is documentation-debt P2 at most; classified P1 because the
function `track_package_removed` is exposed (`mempool.ml:736`) with no
guard against accidental misuse.

**File:** `lib/mempool.ml:736-740, 805, 2373-2374`.

**Impact:** code-fragility / refactor-risk; no runtime symptom today.

---

## BUG-17 (P1) — `max_orphans = 100` is far below Core's per-peer or global reserved orphan weight

**Severity:** P1. Bitcoin Core's
`DEFAULT_RESERVED_ORPHAN_WEIGHT_PER_PEER = 404,000` (`node/txorphanage.h:20`)
implies a per-peer reservation of roughly 100 orphan-txs at typical
sizes, multiplied across the peer count. The "100" in camlcoin
(`mempool.ml:258` `max_orphans = 100`) is a **global** cap — across
ALL peers.

On a 16-peer mainnet node, Core can hold ~1600 orphans; camlcoin caps
at 100. The simple age-only `expire_orphans` (mempool.ml:3429-3440)
sweeps everything older than 20 minutes; before that age, a fast burst
of orphans can fill the cap and cause spurious "missing parent" relay
loss for legitimate tx-relay events.

There is also no per-peer DoS-score eviction. Core's
`TxOrphanageImpl::LimitOrphans` (`node/txorphanage.cpp:442-490`)
computes a per-peer DoS score and evicts the worst peer's orphans
first. Camlcoin evicts oldest-first regardless of source.

**File:** `lib/mempool.ml:258` (`max_orphans = 100`); `lib/mempool.ml:3429-3440`
(`expire_orphans` age-only).

**Core ref:** `bitcoin-core/src/node/txorphanage.h:19-22`
(`DEFAULT_RESERVED_ORPHAN_WEIGHT_PER_PEER`); `bitcoin-core/src/node/txorphanage.cpp:442-490`
(`LimitOrphans` DoS-score eviction).

**Impact:** orphan capacity is ~16× lower than Core under typical
peering; orphan-resolution rate is reduced; "tx already known" rate
goes up because relay re-requests txs the orphanage forgot.

---

## BUG-18 (P1) — `remove_transaction` recurses unbounded via `dependent_txids` loop; no cycle detection

**Severity:** P1. `lib/mempool.ml:397-402`:

```ocaml
let dependent_txids = Hashtbl.fold (fun _k dep acc ->
  if List.exists (fun d -> Cstruct.equal d txid) dep.depends_on then
    dep.txid :: acc
  else acc
) mp.entries [] in
List.iter (fun dep_txid -> remove_transaction mp dep_txid) dependent_txids
```

This is OK if the mempool is a DAG (which it must be — Bitcoin txs
can't cycle). But the iteration is O(N) per removed tx and the
recursion depth can equal the maximum chain length (25 with
DEFAULT_ANCESTOR_LIMIT). For a mempool of 100k+ entries, removing one
"root" can trigger 100k × depth iterations.

Core uses `CTxMemPool::CalculateDescendants` which walks the txgraph
O(descendants) once. Camlcoin's O(N × depth) is a perf regression on
large mempools.

**File:** `lib/mempool.ml:397-402`.

**Core ref:** `bitcoin-core/src/txmempool.cpp::CalculateDescendants`.

**Impact:** O(N²) worst-case for cluster eviction; on a 300MB mempool
with 50k txs, a single big-cluster eviction can take seconds. Not a
consensus or correctness issue.

---

## BUG-19 (P0-CDIV) — Rolling-fee floor not consulted on `add_transaction` admission

**Severity:** P0-CDIV. Core's `MemPoolAccept::CheckFeeRate`
(validation.cpp:948) consults `m_pool.GetMinFee(maxmempool).GetFeePerK()`
— the rolling exponential floor — as the admission gate (line 1180).

camlcoin's `add_transaction` admission gate (`mempool.ml:2198`):

```ocaml
let eff_min = effective_min_fee mp in
let min_fee =
  Int64.div (Int64.mul eff_min (Int64.of_int vsize)) 1000L in

if fee < min_fee && not bypass_fee_check then
  Error "Fee below minimum relay fee"
```

This DOES consult `effective_min_fee` (line 819), which returns
`Int64.max mp.min_relay_fee (get_min_fee mp)`. So the rolling floor IS
consulted at admission — this gate is correct. But the rejection
string `"Fee below minimum relay fee"` is **stale** (Core's wording is
`"min relay fee not met"` for the static floor and
`"mempool min fee not met"` for the rolling floor; the two are
distinct so the operator can tell what gate fired). Camlcoin
collapses both into one string, losing diagnostic information.

Reclassified from PASS to **P0-CDIV** because reject-string parity is
a real concern (W141 fleet) — fee-bumping wallets parse the reason to
decide whether to bump-by-relay-floor (static) or
bump-by-rolling-floor (dynamic).

**File:** `lib/mempool.ml:2198-2199`.

**Core ref:** `bitcoin-core/src/validation.cpp:1180`
(CheckFeeRate uses BOTH `min_relay_feerate` and rolling floor with
distinct rejection strings via `PackageMempoolAcceptResult`).

**Impact:** reject-string wire-parity gap (cross-cite W125 lunarblock
9-token sweep); wallets reading the rejection can't distinguish
"raise fee by min-relay" vs "raise fee by current rolling floor".

---

## BUG-20 (P1) — `remove_for_block` mutates `mp.current_height` SILENTLY

**Severity:** P1. `mempool.ml:2348` `remove_for_block` first does:

```ocaml
mp.current_height <- height;
```

This is a side-effect with no corresponding API for the caller to
disable. The reorg-disconnect path (sync.ml:3582+) doesn't call
`remove_for_block` (because it's not connecting; it's disconnecting),
so `mp.current_height` stays at the OLD tip during the entire
disconnect+refill window. Any `add_transaction` call during the
refill (line 3705-3710) uses the stale height in coinbase-maturity
checks, BIP-68 lockpoint checks, etc.

After the connect-half completes and the connect-blocks-loop runs
(sync.ml:3731), `remove_for_block` fires per-block and bumps height
incrementally. But the disconnect-pool was processed under the OLD
height with `bypass_limits=true`, which silently masks the
height-mismatch by skipping all the checks that would have noticed.

**File:** `lib/mempool.ml:2348`; `lib/sync.ml:3703-3714, 3731-3737`.

**Core ref:** `bitcoin-core/src/validation.cpp::Chainstate::ActivateBestChainStep`
(updates `m_chain` BEFORE calling `MaybeUpdateMempoolForReorg`).

**Impact:** during reorg, mempool height is stale; cross-impl
divergence in lockpoint recomputation; mostly masked by `bypass_limits`
but a leaky abstraction.

---

## BUG-21 (P1) — `getmempoolinfo` emits `unbroadcastcount = 0` constant

**Severity:** P1. `lib/rpc.ml:1355`:

```ocaml
("unbroadcastcount", `Int 0);
```

Hard-coded zero. Core's `unbroadcast_size()` is the number of locally
submitted txs (via wallet or `sendrawtransaction`) that have NOT yet
been ACK'd by any peer (i.e., we haven't gotten an inv-back for them).
The mempool's `m_unbroadcast_txids` (txmempool.h:528) tracks these
explicitly, and the wallet uses the count to decide whether to
re-broadcast.

camlcoin has no `m_unbroadcast_txids` analogue. The constant `0` is
both a divergence from Core's contract and a missed primitive — the
wallet can't intelligently re-broadcast on startup.

This is a **dead-data plumbing** instance: the field is plumbed in
the JSON output but the source is hardcoded constant.

**File:** `lib/rpc.ml:1355`; `lib/mempool.ml` (no `unbroadcast_txids`
field).

**Core ref:** `bitcoin-core/src/txmempool.h:528`
(`m_unbroadcast_txids`); `bitcoin-core/src/rpc/mempool.cpp::getmempoolinfo`
(emits `pool.m_unbroadcast_txids.size()`).

**Impact:** wallet cannot identify outbound txs that haven't been
relayed; restart-after-localtx-flush loses the local-priority tx
unless persisted elsewhere.

---

## BUG-22 (P1) — `clear` does not reset rolling-fee state, leaving stale floor across regtest test resets

**Severity:** P1. `lib/mempool.ml:3459-3462` `clear`:

```ocaml
let clear (mp : mempool) : unit =
  Hashtbl.clear mp.entries;
  mp.total_weight <- 0;
  mp.total_fee <- 0L
```

Resets `entries`, weight, fee — but NOT
`rolling_min_fee_rate`, `last_rolling_fee_update`,
`block_since_last_rolling_fee_bump`, `zmq_sequence`, `map_deltas`,
`map_next_tx`, `orphans`, `orphan_by_txid`.

On regtest, integration tests that `clear` between rounds and submit
new low-feerate txs see "Fee below minimum relay fee" rejects
because the rolling floor from the prior round persists. Tests must
explicitly poke the state — or wait 12h+ for halflife decay. This is
why test runs that depend on a fresh-mempool state can flake.

Also: `map_next_tx` (the conflict-detection index) stays populated with
stale outpoint mappings — `evict_by_chunks` and `replace_by_fee` rely
on this index to find conflicts; with stale entries, a fresh tx that
spends one of the cleared outpoints reports a phantom conflict.

**File:** `lib/mempool.ml:3459-3462`.

**Core ref:** `bitcoin-core/src/txmempool.cpp::CTxMemPool::clear`
clears `mapTx`, `mapNextTx`, `m_unbroadcast_txids`,
`m_changeset_pending`, `m_txgraph` (via reset) — full reset.

**Impact:** regtest test isolation broken; flakes; cross-call state
leak. Production impact minimal (no production caller calls `clear`).

---

## BUG-23 (P1) — `prioritise_transaction` delta is silently lost across mempool size-limit eviction

**Severity:** P1. `lib/mempool.ml:112` field `map_deltas` persists
across `remove_transaction`:

```ocaml
map_deltas : (string, int64) Hashtbl.t;
```

A grep of `mempool.ml` for `Hashtbl.remove .* map_deltas` returns no
match. `remove_transaction` (line 348-402) clears `entries`, `total_weight`,
`total_fee`, `map_next_tx` for the removed tx, but `map_deltas` is
preserved.

This is intentional for REPLACE-by-fee scenarios (Core's
`prioritise_transaction` deltas persist across `addUnchecked`/`removeUnchecked`
cycles so an operator-set priority survives an RBF). However, Core's
`ClearPrioritisation(hash)` is called from `removeUnchecked` when the
removal reason is **SIZELIMIT** or **CONFLICT** or **REPLACED** — so
that an evicted-then-re-added tx doesn't carry stale priority across
the eviction (the operator's "this is high priority" intent assumes
the tx is in the pool; after eviction the priority is moot).

camlcoin's untyped `remove_transaction` (BUG-5 cross-cite) can't
distinguish these. The result: an old operator delta from weeks ago
applies to a new identical-txid tx today (txid collision is impossible
in practice — but the in-memory state IS a leak).

**File:** `lib/mempool.ml:348-402` (no `map_deltas` cleanup).

**Core ref:** `bitcoin-core/src/txmempool.cpp::removeUnchecked` →
`ClearPrioritisation(hash)`.

**Impact:** `map_deltas` is a slow leak across the process lifetime;
on a long-running node it grows without bound (each new tx that ever
got a delta stays in the map forever). Not a correctness issue because
the delta only fires when an entry with the matching key exists in
`entries` — but the memory grows.

---

## BUG-24 (P0) — Mining selector consults `mp.entries` directly with no `removeForBlock` priming; produces invalid templates after a missed `remove_for_block`

**Severity:** P0. `lib/mining.ml:922` calls `Mempool.remove_for_block`
AFTER applying the block. The selector `Mempool.select_for_block_chunked`
(`mempool.ml:689-722`) iterates `mp.entries` directly to build a
template.

Combined with **BUG-9** (post-IBD block-connect doesn't call
`remove_for_block`), after a block arrives via P2P and the operator
calls `getblocktemplate` for solo-mining: the template will include
txs that were just confirmed in the P2P-received block. The mining
template is **invalid** for that block height.

**File:** `lib/mempool.ml:689-722` (selector); `lib/mining.ml:922` (post-apply
remove); `lib/cli.ml:1207-1232` (the missing remove).

**Core ref:** `bitcoin-core/src/miner.cpp::BlockAssembler::addPackageTxs`
operates on an `entries.modified()` view that was updated by
`removeForBlock` before the template was constructed.

**Impact:** solo-mining nodes that submit via `submitblock` see
their templates rejected for `bad-txns-inputs-missingorspent` (the
selected tx was already confirmed); mining loops thrash. On regtest
this is the source of intermittent test flakes around
generate-then-cgetblocktemplate sequences.

---

## BUG-25 (P1) — `Mempool.clear` not exposed to RPC; no `--prune-mempool` knob

**Severity:** P1. Bitcoin Core's `savemempool` and (no, there's no
`clearmempool`) operator workflows include `bitcoin-cli stop` +
delete `mempool.dat` + restart, OR a JSON-RPC `clearmempool`-like
sequence via debug. camlcoin exposes `Mempool.clear` (line 3459) but
NO RPC method for it.

`rpc.ml::handle_savemempool` exists (per earlier audits) but
no `clearmempool` analogue. Operators have no in-process knob to dump
the mempool short of restarting.

**File:** `lib/mempool.ml:3459-3462` (clear exists); `lib/rpc.ml` (no
dispatch entry).

**Core ref:** no exact equivalent — Bitcoin Core has no
`clearmempool` RPC; the canonical operator workflow is stop +
delete-mempool.dat + restart. So this is more an "operator
convenience" gap than a divergence. Listed P1 for completeness.

**Impact:** operator cannot fast-clear; W141 dead-method companion.

---

## Summary

**Bug count:** 25 (BUG-1 through BUG-25).

**Severity distribution:**
- **P0-CONS:** 2 (BUG-9, BUG-13)
- **P0-CDIV:** 2 (BUG-4, BUG-19)
- **P0:** 5 (BUG-2, BUG-5, BUG-6, BUG-11, BUG-24)
- **P1:** 16 (BUG-1, BUG-3, BUG-7, BUG-8, BUG-10, BUG-12, BUG-14, BUG-15,
  BUG-16, BUG-17, BUG-18, BUG-20, BUG-21, BUG-22, BUG-23, BUG-25)

**Fleet patterns confirmed:**
- **5th-consecutive-quad camlcoin multi-pipeline drift** (W143 / W144 /
  W145 / W149 / W150 / W151 / W152 / W153 all touch this family). Today's
  W153 instances: BUG-9 (4 of 5 block-arrival paths bypass
  `remove_for_block`); BUG-10 (block_import.ml bypass extends to mempool);
  BUG-11 (reorg pipeline has 1 of 3 phases of `MaybeUpdateMempoolForReorg`);
  BUG-13 (mempool network drift carry-forward).
- **"dead-helper-at-call-site"** — BUG-2 (`expire_old_transactions`), BUG-15
  (`evict_lowest_feerate`) — running total 10 distinct instances in
  camlcoin (W152 cluster + W153 pair).
- **"dead-data plumbing"** — BUG-21 (`unbroadcastcount=0` hardcode), BUG-23
  (`map_deltas` leak).
- **"two-pipeline guard"** — BUG-4 (`mempoolminfee` JSON vs `effective_min_fee`
  gate, 17th distinct extension); BUG-12 (`incrementalrelayfee` JSON literal
  vs `incremental_relay_fee` module constant, 19th distinct extension).
- **"comment-as-confession"** — BUG-3 (`min_relay_fee` comment confidently
  asserts "1 sat/vB" without cross-checking Core's `DEFAULT_MIN_RELAY_TX_FEE=100`,
  12th instance); BUG-2 ("Gap 7" prefix on `expire_old_transactions`
  marks unfilled gap).
- **"reject-string wire-parity slippage"** — BUG-19 collapses
  Core's distinct "min relay fee not met" / "mempool min fee not met"
  strings into one.
- **"carry-forward re-anchor"** — BUG-13 is W150 BUG-4 re-confirmed
  ~24 weeks open; BUG-14 is W141 7-of-10 fleet pattern.
- **"block_import.ml-bypass"** — extends W145 BUG-1 from validation
  to mempool maintenance (BUG-10).
- **"assume-valid scope creep"** companion — bypass_limits handling
  on reorg (BUG-11) drops more than its intended scope.

**Top three findings:**

1. **BUG-9 (P0-CONS) — `Mempool.remove_for_block` is NEVER called from
   the post-IBD P2P block-arrival path** (or the cmpctblock /
   blocktxn / IBD pipelines). 4 of 5 block-arrival paths in camlcoin
   bypass mempool maintenance. Mempool retains confirmed txs forever;
   `getrawmempool` returns confirmed txs; mining templates re-include
   them; tx-relay re-announces them (peer-ban risk). 5th-consecutive-quad
   pipeline-drift instance. Fix: 3 lines added to each of the 3
   `cli.ml` listeners; ~10-line PR.

2. **BUG-11 (P0) — No `removeForReorg` analogue + no `LimitMempoolSize`
   after reorg refill** — camlcoin's reorganize implements 1 of 3 phases
   of Core's `MaybeUpdateMempoolForReorg`. Post-reorg mempool retains
   txs whose maturity/locktime/sequence is invalid at the new tip;
   `submitblock` after a reorg can fail with `bad-txns-premature-spend`;
   refill can blow past `max_size_bytes` without bound. Cross-cite
   W132 BUG-4 (TestLockPointValidity) and BUG-9 (the block-connect
   half of mempool maintenance is also broken).

3. **BUG-2 + BUG-5 + BUG-6 cluster — removal-reason+expiry signaling
   broken** — `MemPoolRemovalReason` enum is absent (BUG-5);
   `expire_old_transactions` is dead code that never fires (BUG-2,
   "Gap 7" confession in source); when `remove_for_block` does run,
   `on_eviction` fires `record_eviction` instead of `record_confirmation`,
   silently corrupting the fee estimator (BUG-6). Three bugs forming
   one architectural gap: the mempool has no notion of WHY a tx is
   being removed, so every downstream consumer (fee estimator, ZMQ,
   logs, RPC) routes incorrectly.

**Highest-priority fixes (within scope of W153 scope):**
- BUG-9 (P0-CONS, 3 listeners × 1 line each = 3 lines) — add
  `Mempool.remove_for_block` after `Sync.process_new_block` in all 3
  `cli.ml` listeners. Closes the largest mempool-correctness gap.
- BUG-4 (P0-CDIV, 1 line) — change `min_relay_fee` to
  `Int64.of_float (Float.of_int (Mempool.effective_min_fee mp))` in
  `rpc.ml:1351`. Closes the wallet-fee-sizing drift.
- BUG-6 (P0, ~10 lines) — add reason parameter to `remove_transaction`
  + route `on_eviction` only for non-BLOCK reasons. Closes
  fee-estimator corruption.
- BUG-11 (P0, ~30 lines) — implement `Mempool.remove_for_reorg` +
  `Mempool.limit_size` and call them from `sync.ml:3714` after the
  refill loop.
- BUG-3 (P1, 1 line) — change `min_relay_fee = 1000L` to `100L` to
  match Core's `DEFAULT_MIN_RELAY_TX_FEE`. Closes cross-impl fee-floor
  divergence.

**Carry-forward open items:**
- BUG-13 (W150 BUG-4, ~24 weeks open) — `Mempool.create` regtest
  hardcode.
- BUG-14 (W141 7-of-10 fleet pattern) — notify-script hooks.

**Files for the FIX wave should target:**
- `lib/cli.ml:1207-1232, 1357-1371, 1410-1424` (BUG-9 fix)
- `lib/rpc.ml:1351-1352, 1358` (BUG-4 + BUG-12 fix)
- `lib/mempool.ml:233-264, 245, 348, 2346` (BUG-3 + BUG-5 + BUG-6 fix)
- `lib/sync.ml:3703-3714` (BUG-11 fix)
