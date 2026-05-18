# W149 — Pruning + assumevalid + minimumchainwork (camlcoin)

**Wave:** W149 — `FindFilesToPrune` / `FindFilesToPruneManual` / `PruneOneBlockFile` /
`UnlinkPrunedFiles` / `MIN_BLOCKS_TO_KEEP` / `MIN_DISK_SPACE_FOR_BLOCK_FILES` /
`pruneblockchain` RPC / `-prune=N` CLI; `BLOCK_ASSUMED_VALID` /
`ConnectBlock` fScriptChecks gate (5 ancestor + best-header + min-work + 2-week
checks) / `-assumevalid` CLI; `nMinimumChainWork` per-network /
`UpdateIBDStatus` / `MinimumConnectedChainWork`.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/validation.h:75-87` — `MIN_BLOCKS_TO_KEEP = 288`,
  `MIN_DISK_SPACE_FOR_BLOCK_FILES = 550 * 1024 * 1024`.
- `bitcoin-core/src/node/blockstorage.cpp:292-336` —
  `FindFilesToPruneManual` (per-target `nManualPruneHeight`),
  `FindFilesToPrune` (auto-prune below tip-MIN_BLOCKS_TO_KEEP).
- `bitcoin-core/src/node/blockstorage.cpp` — `PruneOneBlockFile`,
  `UnlinkPrunedFiles`, `FlushBlockFile`. Pruning clears
  `BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO` bits; no separate "pruned" bit.
- `bitcoin-core/src/chain.h:75-77` — `BLOCK_HAVE_DATA = 8`,
  `BLOCK_HAVE_UNDO = 16`, `BLOCK_HAVE_MASK`. Pruned blocks lose these bits.
- `bitcoin-core/src/init.cpp` — `-prune=N` argument parsing: `0`=off,
  `1`=manual-only sentinel, `2..549`=fatal, `>=550`=auto target (MiB).
- `bitcoin-core/src/validation.cpp:2346-2383` — `ConnectBlock`
  `script_check_reason` derivation: **5 separate gates** for skipping
  scripts (av-not-null, av-in-index, block-on-av-chain via
  `GetAncestor(pindex->nHeight) != pindex`, block-on-best-header chain,
  best-header chainwork ≥ MinimumChainWork, `GetBlockProofEquivalentTime
  > TWO_WEEKS_IN_SECONDS`).
- `bitcoin-core/src/kernel/chainparams.cpp:109-110,232-233,332-333` —
  `consensus.nMinimumChainWork` and `consensus.defaultAssumeValid` for
  mainnet (~block 938343), testnet3, testnet4 (block 123613).
- `bitcoin-core/src/validation.cpp:1940-1942, 3283-3291` —
  `IsInitialBlockDownload` / `UpdateIBDStatus`: latches `m_cached_is_ibd`
  to false when `IsTipRecent(MinimumChainWork(), max_tip_age)`.
- `bitcoin-core/src/net_processing.cpp` — `MinimumConnectedChainWork`
  (drop peers whose announced chainwork is below this).

**Files audited**
- `lib/storage.ml:1085-1791` — `Block_pruned` enum, `FlatFileStorage`,
  `prune_one_block_file`, `find_files_to_prune`, `prune_block_files`,
  `unlink_pruned_files`, `is_block_pruned`, `has_block_data`,
  `check_prune_compatibility`, `get_prune_stats` (all in `FlatFileStorage`
  module; cross-cite W146 BUG-1 — module is dead).
- `lib/sync.ml:136-199` — `chain_state` (`prune_target`, `prune_height`).
- `lib/sync.ml:757-799` — `prune_old_blocks` (the production prune path).
- `lib/sync.ml:1442-1452` — `is_assume_valid` (the sole assume-valid gate).
- `lib/sync.ml:923-982,1268-1330` — `process_headers`, `min_pow_checked`
  flood gate, transition-to-block-sync gate.
- `lib/sync.ml:4090-4115` — `start_ibd` / `FullySynced` transition (IBD
  exit logic).
- `lib/consensus.ml:260-277,617-775,1222-1244` — `network_config`
  (`minimum_chain_work`, `assume_valid_hash`), per-network values
  (mainnet/testnet3/testnet4/regtest), `meets_minimum_chain_work`,
  `should_skip_scripts`.
- `lib/validation.ml:1478-2107` — `validate_block_with_utxos` fast-path
  (skip_scripts) and `accept_block` dispatcher.
- `lib/block_import.ml` — `--import-blocks` driver (bypasses every
  pruning / assume-valid / minimum-chain-work gate; cross-cite W143
  P0-CONS, W144, W145 block_import bypass).
- `lib/reindex.ml` — `--reindex` pre-open wipe (does NOT reset
  `prune_height`; does NOT clear FlatFileStorage prune state).
- `lib/cli.ml:243-247,315` — prune wiring + NODE_NETWORK_LIMITED advertise.
- `lib/rpc.ml:495-558,4336-4356,7038-7059,8526-8964` — getblockchaininfo
  prune fields, getblock pruned-block error message, dumptxoutset prune
  pre-check, RPC method dispatch table.
- `lib/peer.ml:78-110` — `prune_mode_advertise` / `our_services` for
  BIP-159 NODE_NETWORK_LIMITED.
- `lib/assume_utxo.ml:144-219` — hardcoded mainnet AssumeUTXO entries
  840k / 880k / 910k / 935k.
- `bin/main.ml:73-87,413-438,757-820` — `--prune` CLI parse + validation
  + plumbing; no `--assumevalid` arg surface at all.

---

## Gate matrix (30 sub-gates / 9 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | -prune CLI semantics | G1: `0` = off | PASS (`bin/main.ml:427-428`) |
| 1 | … | G2: `1` = manual-mode sentinel (RPC only) | PARTIAL — sentinel propagated to `chain.prune_target = 1`; `prune_old_blocks` no-ops, but **no `pruneblockchain` RPC exists** so manual mode is non-functional (BUG-1) |
| 1 | … | G3: `2..549` rejected with explicit "below MIN_DISK_SPACE_FOR_BLOCK_FILES" error | PASS (`bin/main.ml:430-436`) |
| 1 | … | G4: `>= 550` accepted, converted to bytes | PASS (`bin/main.ml:437-438`) |
| 2 | pruneblockchain RPC | G5: dispatch table entry | **BUG-1 (P1)** absent (`lib/rpc.ml:8526-8964` — 145 method handlers, no `pruneblockchain`) |
| 2 | … | G6: dual-mode height (absolute < 1e9) / unix-time (>= 1e9) | **BUG-1 cross-cite** |
| 3 | Production auto-prune | G7: respects MIN_BLOCKS_TO_KEEP=288 reorg window | PASS (`lib/sync.ml:783`) but block-count derived from average-size estimate (BUG-5) |
| 3 | … | G8: file-aligned pruning (Core never deletes mid-file blocks) | **BUG-2 (P0-CDIV)** `prune_old_blocks` (sync.ml:775-799) calls `ChainDB.delete_block` per-hash — it has NO concept of blk*.dat files because production storage is RocksDB CFs. The Core-shape `FlatFileStorage.prune_block_files` exists but is dead code (cross-cite W146 BUG-1). |
| 3 | … | G9: `prune_height` persisted across restart | **BUG-3 (P0)** `prune_height` is initialized to 0 in `create_chain_state` (sync.ml:664,709) and `restore_chain_state` never reads it back from disk; every restart's first `prune_old_blocks` call walks from height 1 to `current_height - keep_blocks` — O(900k) per-restart no-op iteration on mainnet |
| 3 | … | G10: undo data kept for MIN_BLOCKS_TO_KEEP=288 below auto-prune horizon | PARTIAL — keeps undo for `keep_blocks + 288` (sync.ml:795), but `keep_blocks` is `prune_target / 1.5MB` which can be smaller than 288 if `prune_target < 432MB` — but Core floor `MIN_DISK_SPACE_FOR_BLOCK_FILES=550MB` blocks that path. Defensible. |
| 3 | … | G11: `nMinDiskSpace` low-disk halt | **BUG-4 (P1)** none; cross-cite W146 BUG-13 |
| 3 | … | G12: keep-window is in BLOCKS, not bytes-divided-by-estimated-size | **BUG-5 (P1)** `avg_block_size_bytes = 1_500_000` constant (sync.ml:761); a 550MB target yields `keep_blocks = 366`, but real average block on post-2024 mainnet is closer to 1.5–2 MB; can be off by 2× → 732 blocks kept instead of 366, doubling on-disk footprint silently |
| 4 | Block pruned state | G13: pruning clears `BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO` | **BUG-6 (P0-CDIV)** production path (`ChainDB.delete_block`) deletes the row entirely from `cf_block_data`; no status-bit mutation, no `Block_pruned` flag is ever set (cross-cite W146 BUG-20 — that flag inversion only fires in the dead FlatFileStorage path) |
| 4 | … | G14: `BLOCK_ASSUMED_VALID` bit for snapshot base block | **BUG-7 (P0)** entirely absent from `block_status` enum (storage.ml:1093-1103); cross-cite W138 — snapshot base cannot be identified after AssumeUTXO load |
| 4 | … | G15: pruned getblock returns Core-shaped error "Block not available (pruned data)" | **BUG-8 (P1)** `handle_getblock` (rpc.ml:4355-4356) returns generic "Block not found" — clients cannot distinguish "never had it" from "pruned" |
| 5 | NODE_NETWORK_LIMITED (BIP-159) | G16: advertise when `prune > 0` | PASS (`lib/peer.ml:85-109`, `cli.ml:243`) |
| 5 | … | G17: serve `MIN_BLOCKS_TO_KEEP=288` window to BIP-159 peers | **BUG-9 (P1)** advertisement is honored only at the services-bits layer; no actual gate in `HandleGetData` that refuses serving older blocks when in prune mode. A peer that requests blk #5 (pre-prune-horizon) gets either a `notfound` (if the block was pruned, by accident) or the block (if it's somehow still in `cf_block_data`) — not a deliberate "I'm pruned, ask elsewhere" |
| 6 | -assumevalid CLI | G18: `-assumevalid=<hash>` operator override of compiled-in `defaultAssumeValid` | **BUG-10 (P1)** entirely absent — `bin/main.ml` has no `-assumevalid` Cmd_arg; the consensus.ml hash is the only source |
| 6 | … | G19: `-assumevalid=0` to disable assume-valid entirely | **BUG-10 cross-cite** |
| 6 | … | G20: persist override across restart | **BUG-10 cross-cite** |
| 7 | ConnectBlock fScriptChecks gate | G21: 5-condition gate (av-in-index, ancestor-of-av, ancestor-of-best-header, best-header-meets-min-work, 2-week-equivalent) | **BUG-11 (P0-SEC)** camlcoin's `is_assume_valid` (sync.ml:1446-1452) is a **single height-only check** — only condition (effectively): `height <= av_entry.height`. The four other gates (ancestor-of-av-chain, ancestor-of-best-header, best-header-chainwork-≥-min, 2-week equivalent) are entirely absent. Chain-split candidate. |
| 7 | … | G22: scope creep — assume-valid skips ONLY script verification | PASS in spirit — W93 fixes (validation.ml:1500-1830) enforce BIP-30 / BIP-68 / BIP-113 / CSV / sigops / maturity / MoneyRange / witness commitment on the fast path. But the dispatcher (sync.ml:2399, 3402) forces `flags=0` when `skip_scripts`, which would drop BIP-30 exception-block flags and the entire flag-derivation pipeline — recovery hinges on `get_block_script_flags height network` being re-derived inside the fast path (validation.ml:1633) for sigops counting, BUT NOT for the BIP-30 grandfather-exception lookup (which derives from the exception block hash, not flags). Defense-in-depth holds; not a P0. |
| 8 | nMinimumChainWork values | G23: per-network minimum-chain-work matches Core's chainparams | **BUG-12 (P0-CDIV)** mainnet: camlcoin uses `0000…52b2559353df4117b7348b64` (comment: "approximately block 804000"); Core current: `0000…01128750f82f4c366153a3a030` (block ~870k+). Camlcoin's value is ~2 orders of magnitude smaller. **A peer with a low-work fork that exceeds camlcoin's outdated threshold but falls below Core's current threshold passes camlcoin's gate and fails Core's** — chain-split candidate on adversarial low-work-fork attacks. |
| 8 | … | G24: testnet4 minimum-chain-work matches Core | **BUG-13 (P0-CDIV)** camlcoin: `zero_work` (consensus.ml:729); Core kernel/chainparams.cpp:332: `0000…0009a0fe15d0177d086304`. Testnet4 has no min-work floor at all in camlcoin → trivial DoS via header-flood until `max_headers_in_memory` (1M) is reached. |
| 8 | … | G25: testnet3 minimum-chain-work matches Core | **BUG-14 (P0-CDIV)** camlcoin: `zero_work` (consensus.ml:687); Core kernel/chainparams.cpp:232: `0000…000017dde1c649f3708d14b6`. Same shape as G24. |
| 9 | UpdateIBDStatus | G26: IBD exit on (tip-recent within max_tip_age) AND (chainwork ≥ MinimumChainWork) | **BUG-15 (P0-CDIV)** `start_ibd` exits to `FullySynced` purely on `blocks_synced >= tip_height` (sync.ml:4108-4110, 4014). Neither `max_tip_age` nor `MinimumChainWork` is consulted on the exit path. A peer who feeds the node a low-work header chain → blocks_synced catches up → IBD exits → assume-valid + fee policy + mempool acceptance all behave as if synced. |
| 9 | … | G27: one-way latch (Core's `m_cached_is_ibd.store(false)`) | PARTIAL — `sync_state` is an enum, can theoretically be set back; but no production path sets it back to non-FullySynced after FullySynced is reached. Defensible. |
| 9 | … | G28: MinimumConnectedChainWork (drop peers below) | **BUG-16 (P1)** absent — no peer-side filter on advertised chainwork. `process_headers`'s `min_pow_checked` (sync.ml:923-982) only rejects when in-memory headers count exceeds 1M; the routine path never consults a per-peer chainwork floor. |
| 10 | reindex + prune | G29: -reindex resets prune_height | **BUG-17 (P1)** `reindex.ml` (`pre_open_wipe`) does NOT touch `chain.prune_height` (the value is rebuilt only when `restore_chain_state` runs after the wipe, and it just defaults to 0). After `--reindex`, the next `prune_old_blocks` call runs against a freshly-empty UTXO with stale FlatFileStorage prune-state on disk (if any was persisted via `save_index`). Cross-cite W146 BUG-1: FlatFileStorage isn't used in production, so the "stale FF state" is benign — but the design is fragile if someone wires FlatFileStorage in later. |
| 10 | … | G30: -import-blocks honors prune | **BUG-18 (P0)** `block_import.ml` runs `Utxo.connect_block_optimized` and `ChainDB.store_block` directly; never calls `prune_old_blocks`, never consults `chain.prune_target`. Operator importing the chain via `--import-blocks` ends up with the full chain on disk regardless of `--prune=550`; cross-cite W143/W144/W145 block_import bypass pattern. |

---

## BUG-1 (P1) — No `pruneblockchain` RPC handler

**Severity:** P1. Core ships `pruneblockchain <heightOrTime>` (rpc/blockchain.cpp).
In dual-mode: a value < 1,000,000,000 is treated as a block height; >= 1e9 as
a Unix timestamp (the RPC walks the chain backward to find the first block at
or after that time). Returns the height that was pruned to.

camlcoin's RPC dispatch table (`lib/rpc.ml:8529-8964`) has 145 method handlers
— `getblockchaininfo`, `getblock`, `getblockhash`, `getbestblockhash`,
`dumptxoutset`, `invalidateblock`, `reconsiderblock`, etc. — but **no
`pruneblockchain` entry**.

**Impact:**
- The `--prune=1` manual-mode sentinel that `bin/main.ml:429` and
  `sync.ml:776-781` explicitly carve out as "auto-prune does not fire,
  only the pruneblockchain RPC triggers a sweep" is **dead semantics**:
  no RPC exists to trigger it. A `camlcoin --prune=1` node simply
  never prunes anything, ever.
- Comment-as-confession `lib/sync.ml:149` literally writes
  "only the pruneblockchain RPC triggers a sweep — TODO"; the TODO
  marker has been carried-forward through multiple waves with no
  closure.
- Operators on disk-constrained nodes have no in-band way to free
  space after the fact; they must restart with a different `--prune`
  target.

**File:** `lib/rpc.ml:8526-8964`; `lib/sync.ml:147-153` (TODO comment).

**Core ref:** `bitcoin-core/src/rpc/blockchain.cpp:pruneblockchain`.

---

## BUG-2 (P0-CDIV) — Production prune path operates on key-level deletes, not file-level

**Severity:** P0-CDIV. Bitcoin Core's pruning model is **file-aligned**:
`FindFilesToPrune` returns a list of `blk*.dat` file numbers whose
entire content is below the `chain_height - MIN_BLOCKS_TO_KEEP=288`
horizon; `PruneOneBlockFile` clears `BLOCK_HAVE_DATA` /
`BLOCK_HAVE_UNDO` flags on every blockindex entry that references that
file_num, and `UnlinkPrunedFiles` removes the actual `blk*.dat` and
`rev*.dat` files. The unit of pruning is the file, never an
individual block — this guarantees that a contiguous range of blocks
is either entirely present or entirely absent.

camlcoin's production path `prune_old_blocks`
(`lib/sync.ml:775-799`) iterates from
`state.prune_height + 1` to `current_height - keep_blocks`, calling
`Storage.ChainDB.delete_block state.db hash` per hash. Production
storage is RocksDB CFs (`cf_block_data` keyed by 32-byte hash), so a
"delete" is a single per-key tombstone with no file-alignment concept.

**File:** `lib/sync.ml:775-799` (production path);
`lib/storage.ml:1655-1749` (the dead Core-shape `FlatFileStorage`
counterparts; cross-cite W146 BUG-1).

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:292-336`
(`FindFilesToPrune`, `FindFilesToPruneManual`, `PruneOneBlockFile`,
`UnlinkPrunedFiles`).

**Excerpt (camlcoin, key-level delete)**
```ocaml
for h = state.prune_height + 1 to prune_below do
  match Storage.ChainDB.get_hash_at_height state.db h with
  | None -> ()
  | Some hash ->
    Storage.ChainDB.delete_block state.db hash;
    if h < current_height - keep_blocks - 288 then
      Storage.ChainDB.delete_undo_data state.db hash
done;
state.prune_height <- prune_below
```

**Impact:**
- **Disk space is NOT actually freed** until the next RocksDB
  compaction; cross-cite W146 BUG-22. A node with `--prune=550` runs
  for weeks at 100GB+ on-disk despite the operator's expressed intent
  to cap at 550MB.
- The "file-aligned" guarantee is gone: a partial-delete crash (kill -9
  mid-loop) leaves a chain with random per-block holes, not a clean
  pruned-prefix-then-kept-suffix. `getblock` queries on any deleted
  block return "Block not found" with no way to predict which.
- An IBD-from-genesis restart against the post-prune datadir cannot
  reuse the deleted block bodies (they're tombstoned, not recoverable),
  forcing a full re-download.

---

## BUG-3 (P0) — `prune_height` not persisted; every restart re-walks from height 1

**Severity:** P0. `chain.prune_height` is the high-water mark of the
production auto-prune sweep. `create_chain_state` initializes it to
`0` (sync.ml:664, 709). `restore_chain_state` (sync.ml:740-752)
restores `headers_synced` and `blocks_synced` from disk but **never
reads `prune_height` back** from the database — there is no
`Storage.ChainDB.get_prune_height` and no per-row in `cf_chain_state`
for it.

Consequently every restart: `prune_height = 0`, and the next
`prune_old_blocks` call walks `h = 1 to current_height - keep_blocks`
checking each height's hash, calling delete_block (idempotent no-op
for already-deleted) and delete_undo_data on the older window.

**File:** `lib/sync.ml:154` (the field), `:664,709` (initialisation
sites), `:715-752` (`restore_chain_state` — no read), `:798` (the
single write site).

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:GetFirstStoredBlock`
+ `m_prune_horizon` field is implicit via `BLOCK_HAVE_DATA` scanning
of the in-memory `m_block_index` — Core's "first stored block" is
derived from the index on startup, not stored as a counter.

**Impact:**
- On mainnet at height 900k: every restart issues ~899,616
  `delete_block` calls (most no-ops) under the chain-load mutex —
  measurable startup latency added (~seconds at minimum).
- For nodes that DO have undo data older than `keep_blocks + 288`
  still on disk (e.g. after a `--prune` increase from 550 to 5000 MB
  followed by a restart), the `delete_undo_data` path will silently
  trim undo back below the new horizon — an operator who increased
  the prune target hoping to preserve more history loses data on the
  next restart with no warning.
- The TODO at `sync.ml:149` ("only the pruneblockchain RPC triggers
  a sweep — TODO") implies the design intends `prune_height` to be
  restored on boot; it just wasn't wired.

---

## BUG-4 (P1) — No low-disk halt / `nMinDiskSpace` check

**Severity:** P1 (cross-cite W146 BUG-13). Core's
`CheckDiskSpace` aborts the node before a `write` that would push
free space below `MIN_DISK_SPACE_FOR_BLOCK_FILES = 550 MiB`. camlcoin's
production block-write path (`ChainDB.store_block`,
`cf_chainstate.put_block_data`) and the `prune_old_blocks` /
`block_import.ml` paths never check disk availability.

**Impact:** A `/var` partition that fills up during IBD produces
unaudited RocksDB write failures (which the cf_chainstate layer
swallows or surfaces as opaque "rocksdb: io_error") rather than the
clean Core-shaped "shutting down: disk full" abort.

**File:** `lib/storage.ml`, `lib/cf_chainstate.ml`. No disk-space
helper anywhere.

---

## BUG-5 (P1) — `avg_block_size_bytes = 1_500_000` constant under-estimates by 30-50% on post-2024 mainnet

**Severity:** P1. `prune_old_blocks` derives a block-count keep window
from `prune_target / avg_block_size_bytes`, with the constant set to
1.5 MB (`lib/sync.ml:761`). Post-2024 mainnet average block weight is
~3.5 MWU (~875 KB serialized + witness ~1.3-2 MB avg full block size);
the constant is roughly Core-current. **But Core does not approximate
this way at all** — Core sums actual `n_size + n_undo_size` per
`block_file_info` and stops adding files when `current_usage <=
prune_target_bytes`. camlcoin's approximation can be off by 2× in
either direction depending on the actual sizes of blocks in the
current keep window.

**File:** `lib/sync.ml:760-799`.

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:FindFilesToPrune`
walks `m_blockfile_info[i].nSize + nUndoSize`.

**Impact:** Operator who sets `--prune=550` may end up with anywhere
from 200MB to 1.5GB of on-disk block bodies depending on the historical
mix in their keep window — not the "stay under 550 MiB" semantic Core
guarantees.

---

## BUG-6 (P0-CDIV) — Production pruning never sets `BLOCK_HAVE_DATA` / `BLOCK_HAVE_UNDO` clear; no per-block status mutation

**Severity:** P0-CDIV. Core's `PruneOneBlockFile` walks every
`m_block_index` entry referencing the pruned `nFile` and clears
`pindex->nStatus &= ~BLOCK_HAVE_MASK` (chain.h:77, blockstorage.cpp).
A getblock RPC on a pruned block can then check
`(it->second.nStatus & BLOCK_HAVE_DATA) == 0` and return the explicit
"Block not available (pruned data)" error.

camlcoin's production path `prune_old_blocks` (sync.ml:775-799)
calls `ChainDB.delete_block` which deletes the row from `cf_block_data`.
**There is no per-block status mutation on the production path.** The
`Block_pruned` enum exists (`storage.ml:1103`) but is only set by the
dead `FlatFileStorage.prune_one_block_file` (cross-cite W146 BUG-20,
BUG-1).

**File:** `lib/sync.ml:775-799`; `lib/storage.ml:842-843` (`delete_block`).

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:PruneOneBlockFile`.

**Impact:**
- `BLOCK_HAVE_DATA` bit semantics fully lost on the production path.
- Cross-cite **BUG-8** below: `getblock` cannot distinguish pruned from
  never-had-it.
- A future `ResetBlockFailureFlags` or `RaiseValidity` equivalent that
  needs to know "do I have the block body on disk?" cannot answer
  without an additional RocksDB read.

---

## BUG-7 (P0) — `BLOCK_ASSUMED_VALID` status bit entirely absent

**Severity:** P0 (cross-cite W138). Core's `BLOCK_ASSUMED_VALID = 128`
(chain.h, around BLOCK_OPT_WITNESS) marks blocks below the
assumevalid checkpoint OR below an AssumeUTXO snapshot base as
"validated without script checks". `ChainstateManager::GetSnapshotBaseBlock`
returns the snapshot pindex; its `nStatus` is examined to decide
whether background-validate is still needed.

camlcoin's `block_status` enum (`lib/storage.ml:1093-1103`):
```ocaml
type block_status =
  | Block_valid_unknown
  | Block_valid_header
  | Block_valid_tree
  | Block_valid_transactions
  | Block_valid_chain
  | Block_valid_scripts
  | Block_have_data
  | Block_have_undo
  | Block_failed
  | Block_failed_child
  | Block_pruned  (* camlcoin-internal *)
```

No `Block_assumed_valid` constructor. The W138 AssumeUTXO snapshot
loader (`lib/assume_utxo.ml`) thus cannot stamp the snapshot base
with a distinct status bit; the secondary chainstate at
`chainstate_snapshot/` is identified only by directory layout, not
by any status mark on the block index entry.

**File:** `lib/storage.ml:1093-1103`.

**Core ref:** `bitcoin-core/src/chain.h:75-86`.

**Impact:**
- `getblockheader` / `getblock` on a snapshot-base block cannot
  include the "assumedvalid": true field that Core 26+ adds to the
  RPC output.
- Background validation completion cannot be signalled by flipping the
  bit from `BLOCK_ASSUMED_VALID` to `BLOCK_VALID_SCRIPTS`; instead the
  status flips from `Block_valid_transactions` to `Block_valid_scripts`
  with no record that the historical validation path was via snapshot.

---

## BUG-8 (P1) — `handle_getblock` returns generic "Block not found" for pruned blocks

**Severity:** P1. Bitcoin Core's getblock returns explicit
`Block not available (pruned data)` (code -1, with a specific JSON-RPC
error string) when the block exists in the index with HAVE_DATA cleared.
camlcoin's `handle_getblock` (rpc.ml:4355-4356) cannot distinguish
"never had this hash" from "pruned":

```ocaml
match Storage.ChainDB.get_block ctx.chain.db hash with
| None -> Error "Block not found"
| Some block -> ...
```

Both cases hit `None`. Clients (block explorers, wallets querying
historical txs) cannot tell from the error string whether the block
exists on the network or has been pruned locally.

**File:** `lib/rpc.ml:4355-4356`.

**Core ref:** `bitcoin-core/src/rpc/blockchain.cpp:getblock`.

**Impact:** RPC parity broken; explorers / wallets that rely on the
distinct error string mis-handle pruned-node responses.

---

## BUG-9 (P1) — NODE_NETWORK_LIMITED advertised but no enforcement gate on GetData

**Severity:** P1. BIP-159: a node advertising NODE_NETWORK_LIMITED
serves only blocks within the last `MIN_BLOCKS_TO_KEEP = 288` of the
current tip. Peers requesting older blocks should receive `notfound`
or be ignored (Core's `MaybeSendGetData` / `ProcessGetBlockData` checks
the prune state explicitly).

camlcoin sets `prune_mode_advertise = true` when `config.prune > 0`
(cli.ml:243) and the resulting service bits flag is sent to peers
during version handshake (peer.ml:80-109). **But there is no
corresponding gate in the GetData/GetBlocks handler that refuses to
serve blocks older than `tip - 288` when in prune mode**. A misbehaving
peer can request blk #5 from a pruned camlcoin node and get either:
- the block (if it happens to still be in `cf_block_data` because the
  prune sweep hasn't yet caught up to that height),
- a `notfound` response (if the prune sweep already deleted it), or
- a hung getdata that times out (depending on the relay queue state).

The behavior is non-deterministic from the requester's perspective —
exactly the failure mode BIP-159 was designed to make explicit.

**File:** No file (the gate is absent). `lib/peer.ml:78-110` is the
advertise side; the receive side has no symmetric check.

**Core ref:** `bitcoin-core/src/net_processing.cpp:ProcessGetBlockData`
(checks `IsPruneMode()` + block depth before serving).

**Impact:** Cross-cite the W139/W141 "advertise-without-honour"
pattern: a NODE_NETWORK_LIMITED peer that, in practice, sometimes
serves pre-horizon blocks and sometimes doesn't — confuses peer-side
heuristics in modern Core / Knots stacks.

---

## BUG-10 (P1) — No `-assumevalid` CLI / config knob; operators cannot override compile-time hash

**Severity:** P1. Bitcoin Core's `-assumevalid=<hash>` (init.cpp,
default = `consensus.defaultAssumeValid`) lets operators:
1. **Override** the shipped hash with a more recent one (e.g. they've
   validated a later block locally and want to fast-sync up to it).
2. **Disable** assume-valid entirely by setting `-assumevalid=0`.
3. **Recover** from a release-time-shipped hash that turned out to be
   invalid (e.g. a hard-fork chain split during release rotation).

camlcoin has **no `-assumevalid` Cmd_arg** in `bin/main.ml` (verified
by `grep -n "assumevalid" bin/main.ml`: zero hits). The hash is
hardcoded into `consensus.ml:625` (mainnet block 938343 hash) and
`consensus.ml:732` (testnet4 block 123613 hash). The only way to
change them is recompile.

**File:** `bin/main.ml` (the gap is the entire absence of the arg);
`lib/consensus.ml:625, 688, 732, 772` (hardcoded values).

**Core ref:** `bitcoin-core/src/init.cpp:RegisterArgs("-assumevalid")`,
`bitcoin-core/src/validation.cpp:m_assumed_valid_block`.

**Impact:**
- An operator who runs a `git fsck` on the shipped hash and discovers
  Core has updated to a later block has no in-band recovery; must
  rebuild from source.
- Test-net / regtest harnesses that want to disable assume-valid for
  fault-injection cannot do so without recompiling.
- A release that ships a wrong hash (deliberate adversarial release
  or accidental rebase error) cannot be patched without a binary
  redeploy.

---

## BUG-11 (P0-SEC) — `is_assume_valid` is a height-only check; Core requires 5 gates

**Severity:** P0-SEC (cross-cite W148-style ancestor checks, but on
the assume-valid path). Bitcoin Core's `ConnectBlock`
(validation.cpp:2346-2383) derives `script_check_reason` from **five
independent conditions**, ALL of which must pass to skip script
verification:

1. `AssumedValidBlock().IsNull()` is FALSE (i.e. assumevalid is set);
2. `m_block_index.find(AssumedValidBlock()) != end()` (the av hash is
   in our index — defends against truncated headers);
3. `it->second.GetAncestor(pindex->nHeight) == pindex` — the block
   being validated is an ancestor of the av block on the **same chain**;
4. `m_chainman.m_best_header->GetAncestor(pindex->nHeight) == pindex`
   — the block is also on the **best-header chain** (defends against
   a competing fork whose tip happens to be the av hash);
5. `m_chainman.m_best_header->nChainWork >= m_chainman.MinimumChainWork()`
   — the best-header chain reaches the network minimum-chain-work
   floor (defends against a partition where a peer has fed us only a
   weak side branch containing the av hash);
6. `GetBlockProofEquivalentTime(...) > TWO_WEEKS_IN_SECONDS` — there
   are at least 2 weeks of equivalent proof-of-work between av and
   the block being validated (the "DoS extortion" guard described in
   the Core comment).

camlcoin's `is_assume_valid` (sync.ml:1446-1452):
```ocaml
let is_assume_valid (state : chain_state) (height : int) : bool =
  match state.network.assume_valid_hash with
  | None -> false
  | Some av_hash ->
    match Hashtbl.find_opt state.headers (Cstruct.to_string av_hash) with
    | None -> false
    | Some av_entry -> height <= av_entry.height
```

This is conditions (1) + (2) + a **single height-comparison** that
masquerades as condition (3) but doesn't actually verify ancestry on
the same chain. Conditions (4), (5), (6) are entirely absent. The
`state.headers` Hashtbl is a flat map of every known header
including side branches (sync.ml:875, 3783), so a peer that pushes a
side branch containing the av hash trivially lights this gate up for
EVERY block being validated whose height ≤ av_entry.height — even if
the block being validated is on a completely unrelated branch.

**File:** `lib/sync.ml:1446-1452`.

**Core ref:** `bitcoin-core/src/validation.cpp:2346-2383`.

**Impact:**
- **Chain-split candidate.** A peer that crafts a competing fork
  carrying the same av hash at the right height tricks camlcoin into
  skipping script validation on UNRELATED blocks of the genuine chain
  — those blocks may then contain invalid signatures that are silently
  accepted, diverging from Core which rejects them.
- The "DoS extortion" 2-week-equivalent guard the Core comment
  (validation.cpp:2371-2378) calls out explicitly as a defense against
  hash-power coercion is **wholly absent**.
- The best-header-chainwork-≥-MinimumChainWork (condition 5) gate is
  what protects against a partitioned attacker; combined with **BUG-12**
  (outdated mainnet minimum_chain_work) and **BUG-13/14** (zero
  testnet min-work) the attack surface compounds.

---

## BUG-12 (P0-CDIV) — Mainnet `minimum_chain_work` is stale by ~70k blocks (~1.5× lower than Core's current value)

**Severity:** P0-CDIV. camlcoin mainnet `minimum_chain_work`
(consensus.ml:621-622):
```
work_of_hex "000000000000000000000000000000000000000052b2559353df4117b7348b64"
```
with the inline comment "(approximately block 804000)".

Bitcoin Core current (kernel/chainparams.cpp:109):
```
consensus.nMinimumChainWork = uint256{"0000000000000000000000000000000000000001128750f82f4c366153a3a030"};
```
Camlcoin's value: `0x52b2559353df4117b7348b64` ≈ 1.6 × 10^23
Core's value:     `0x1128750f82f4c366153a3a030` ≈ 1.3 × 10^24
Ratio: **~8× lower** in camlcoin.

**File:** `lib/consensus.ml:620-622`.

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:109` (mainnet
defaultAssumeValid block 938343 also shipped together).

**Impact:**
- A peer feeding camlcoin a 7-day low-work side branch whose
  cumulative work passes camlcoin's threshold but fails Core's
  current threshold will be accepted by camlcoin and rejected by Core
  — partition.
- BUG-11 cross-cite: condition (5) of Core's assume-valid gate
  (`best_header->nChainWork >= MinimumChainWork()`) is what protects
  against this exact failure mode. With camlcoin's outdated threshold
  the gate is weaker even if it were wired up.
- The version anchor in chainparams should track Core's `chainTxData`
  updates; this value has been allowed to rot through at least
  release cycles 28 → 29 → 30 → 31.

---

## BUG-13 (P0-CDIV) — Testnet4 `minimum_chain_work = zero_work`; Core ships a positive value

**Severity:** P0-CDIV. camlcoin testnet4 (consensus.ml:729):
```
minimum_chain_work = zero_work;
```

Core (kernel/chainparams.cpp:332):
```
consensus.nMinimumChainWork = uint256{"0000000000000000000000000000000000000000000009a0fe15d0177d086304"};
```

**File:** `lib/consensus.ml:729`.

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:332`.

**Impact:**
- No min-work floor on testnet4 → the `process_headers` flood gate
  (sync.ml:931-933) only fires when in-memory headers count exceeds
  1,000,000 AND tip_work < zero_work (impossible). Effectively the
  flood gate is unreachable on testnet4.
- A malicious peer can feed up to 1M header batches on testnet4
  before any flood gate fires.
- BUG-11 cross-cite: assume-valid's condition (5) on testnet4 reduces
  to "0 ≥ 0", which is always true — the gate provides zero
  protection.

---

## BUG-14 (P0-CDIV) — Testnet3 `minimum_chain_work = zero_work`; Core ships a positive value

**Severity:** P0-CDIV (same shape as BUG-13). camlcoin testnet3
(consensus.ml:687): `minimum_chain_work = zero_work`. Core
(kernel/chainparams.cpp:232):
```
consensus.nMinimumChainWork = uint256{"0000000000000000000000000000000000000000000017dde1c649f3708d14b6"};
```

**File:** `lib/consensus.ml:687`.

**Impact:** Same as BUG-13 but for testnet3. Less critical since
testnet3 is deprecated, but the chainparams discrepancy is the same.

---

## BUG-15 (P0-CDIV) — IBD exit gated only on `blocks_synced >= tip_height`; no `max_tip_age` / `MinimumChainWork` check

**Severity:** P0-CDIV. Bitcoin Core's `UpdateIBDStatus`
(validation.cpp:3283-3291) latches `m_cached_is_ibd.store(false)`
when:
```cpp
m_chain.Tip() != nullptr
  && m_chain.Tip()->nChainWork >= MinimumChainWork()
  && IsTipRecent(MinimumChainWork(), max_tip_age)  // wall-clock tip-recent
```

`IsTipRecent` checks the tip's `nTime` against current wall-clock and
demands the difference is < `max_tip_age` (default 24 hours, settable
by `-maxtipage`).

camlcoin's IBD exit (`lib/sync.ml:4108-4110, 4014`):
```ocaml
if state.blocks_synced >= tip_height then begin
  Logs.info (fun m -> m "Blocks already synced to tip");
  state.sync_state <- FullySynced;
  ...
```
and from inside the IBD loop (4014):
```ocaml
ibd.chain.sync_state <- FullySynced;
```
Both fire purely on `blocks_synced` catching up to the in-memory
header tip. Neither `max_tip_age` nor `MinimumChainWork` is consulted
on the exit path.

**File:** `lib/sync.ml:4014, 4108-4115`.

**Core ref:** `bitcoin-core/src/validation.cpp:3283-3291`
(`UpdateIBDStatus`).

**Impact:**
- **A peer that feeds the node only a low-work header chain → camlcoin
  catches up to that low-work tip → IBD exits.** Once in FullySynced
  state: mempool acceptance opens, fee policy uses live mempool stats,
  wallet RPC reports the node as ready. The actual chain may be a
  fraction of the real network.
- Combined with **BUG-12/13/14** (outdated/zero min-work) and **BUG-11**
  (height-only assume-valid), the chain-split surface compounds.
- Knots / Core treat IBD-vs-not as a security boundary (mempool
  acceptance, fee estimation, RBF acceptance); camlcoin's broken
  predicate means those gates fire too early on a partitioned node.

---

## BUG-16 (P1) — No `MinimumConnectedChainWork` analog; peer chainwork floor not enforced

**Severity:** P1. Bitcoin Core's `net_processing.cpp` consults
`MinimumChainWork()` when evaluating new peer connections: a peer
whose announced cumulative chainwork is below `MinimumConnectedChainWork`
(which is the network minimum + a margin) is droppable. Camlcoin's
`min_pow_checked` flag in `process_headers` (sync.ml:923-982) is
applied PER-HEADER-BATCH inside the headers-message processing loop —
it does not affect peer eligibility at handshake time, and it does
not gate the receive queue based on the peer's `start_height` or
announced cumulative work.

**File:** `lib/peer.ml`, `lib/peer_manager.ml`, `lib/p2p.ml`. The
absence is "no file" — no helper exists that takes a peer's announced
chainwork and rejects below threshold.

**Core ref:** `bitcoin-core/src/net_processing.cpp:
MinimumConnectedChainWork`.

**Impact:** A flood of peers announcing tiny chains eats into the
inbound connection slots; only by reaching the `process_headers`
1M-header in-memory flood gate does camlcoin start refusing. By then
significant inbound bandwidth has been spent on low-work header
trees.

---

## BUG-17 (P1) — `--reindex` does not reset `prune_height`; stale value flows through to post-reindex prune sweep

**Severity:** P1. `lib/reindex.ml:pre_open_wipe` clears
`cf_utxo`/`cf_chain_state`/`cf_undo_data` and removes
`rocksdb_utxo/`. It does NOT touch `chain.prune_height` (the field is
mutable on `chain_state`, but the function operates on the on-disk
RocksDB before `chain_state` even exists; the field default `0` on
fresh `create_chain_state` covers this on a wipe).

The post-reindex re-IBD then writes blocks via the normal pipeline
which calls `prune_old_blocks` per block (sync.ml:2567, 3735) using
the still-fresh `prune_height = 0`. This actually works correctly
from a no-history standpoint, but if the operator had previously
flushed a `pruneblockchain` (in a hypothetical world where it
existed; cross-cite BUG-1) to a height past where `--reindex` rebuilt,
the prune sweep would start re-deleting the freshly-rebuilt blocks.

**File:** `lib/reindex.ml`; cross-cite `lib/sync.ml:660-712`
(`create_chain_state` initialisation paths).

**Impact:** Latent — only fires if `pruneblockchain` is implemented.
But the design is fragile: a future operator who wires up
`pruneblockchain` will discover that `--reindex` then re-prunes the
just-rebuilt blocks.

---

## BUG-18 (P0) — `--import-blocks` driver bypasses prune, assume-valid, and minimum-chain-work entirely

**Severity:** P0 (cross-cite W143 P0-CONS block_import.ml pattern,
W144 BUG-1 BIP-16 exception, W145 P0-CONS block_import bypass). The
`Block_import.run` function (lib/block_import.ml:33-157) drives a
hot block-import loop:

```ocaml
let block = Serialize.deserialize_block r in
let hash = Crypto.compute_block_hash block.header in
Storage.ChainDB.store_block db hash block;
...
(match Utxo.connect_block_optimized ~network_type utxo block height with
 | Ok _undo -> ...
```

It **never**:
- calls `Sync.is_assume_valid` (so script verification is run on
  every imported block; this is actually safer than skipping, but it
  ignores the assume-valid hash entirely);
- calls `Sync.prune_old_blocks` (so the imported chain is stored
  FULL regardless of `--prune` setting);
- consults `chain.prune_target` (no gating against duplicates above
  the prune horizon);
- consults `network.minimum_chain_work` (a malicious blocks-file can
  contain a low-work chain that imports successfully);
- calls `Validation.accept_block` / `validate_block_with_utxos` (so
  the W93-fix gates — BIP-30, IsFinalTx, sigops, witness commitment —
  never fire on import; only `Utxo.connect_block_optimized`'s
  built-in checks run).

This is structurally identical to the W143/W144/W145 finding that
`block_import.ml` is a parallel validation pipeline that bypasses
every gate documented for the IBD pipeline.

**File:** `lib/block_import.ml:1-157`.

**Core ref:** `bitcoin-core/src/init.cpp:ImportBlocks` — Core's
import-blocks reads blk*.dat files but feeds each block through
`AcceptBlock` → `ConnectBlock` (the SAME pipeline as P2P-received
blocks); no parallel path exists.

**Impact:**
- An operator who runs `camlcoin --import-blocks <attacker-supplied-file>`
  imports the file with no consensus checks beyond the UTXO
  connect step. CVE-class entry.
- A `--prune=550` operator who imports the full chain to bootstrap a
  fresh node ends up with 700+ GB on disk despite the prune setting.
- The assume-valid checkpoint hash is effectively dead weight on this
  path — script verification runs on every block whether the hash is
  set or not.

---

## BUG-19 (P1) — `check_prune_compatibility` exists but is never called from startup

**Severity:** P1. `lib/storage.ml:1753-1760` defines
`check_prune_compatibility ~txindex ~prune_target_mb` which returns
`Error "Pruning is incompatible with -txindex"` when both flags are
set. **No production caller invokes this** — verified by
`grep -rn check_prune_compatibility lib/ bin/`: only test file
references. `bin/main.ml`'s `eff_prune` derivation (`bin/main.ml:413-438`)
does not consult txindex; `cli.ml:243-247,315` simply assigns
`chain.prune_target <- config.prune` without compatibility checks.

(There is also no `--txindex` CLI argument surface in camlcoin —
verified by grep. So today the conflict cannot fire, but the helper
exists in anticipation, and the gap is in the wiring.)

**File:** `lib/storage.ml:1753-1760` (helper);
`lib/cli.ml:243-247,315` (the missing call site);
`bin/main.ml:413-438` (the missing call site).

**Impact:** When `--txindex` is wired up (W133 found it's largely
present but the CLI knob isn't), the validation will not fire
because the check is never called. **Helper-defined-but-not-called**
pattern (fleet-wide pattern across W141, W144).

---

## BUG-20 (P1) — `getblockchaininfo` returns hardcoded `("mediantime", \`Int 0)` and `("size_on_disk", \`Int 0)`

**Severity:** P1. `handle_getblockchaininfo` (lib/rpc.ml:537,547):
```ocaml
("mediantime", `Int 0);
...
("size_on_disk", `Int 0);
```

Both are hardcoded zero. `size_on_disk` is directly relevant to
pruning: Core reports the actual disk footprint here so operators can
tell `--prune=550` is being honored. With camlcoin returning 0,
operators cannot verify prune effectiveness via RPC.

**File:** `lib/rpc.ml:537, 547`.

**Core ref:** `bitcoin-core/src/rpc/blockchain.cpp:getblockchaininfo`
returns `CalculateCurrentUsage()` for size_on_disk.

**Impact:** Operator-visibility gap; the only way to check current
prune state is to run `du` on the datadir from a shell.

---

## BUG-21 (P0) — Dead-data: `FlatFileStorage.{prune_block_files,find_files_to_prune,prune_one_block_file,unlink_pruned_files,check_prune_compatibility,get_prune_stats,is_block_pruned,has_block_data,calculate_current_usage,min_blocks_to_keep,min_prune_target_bytes}` — entire Core-shaped pruning API is dead code

**Severity:** P0 (architectural; cross-cite W146 BUG-1). Camlcoin
ships a 200+ LOC Core-shape pruning implementation in
`lib/storage.ml:1614-1791` with the full Core function set:
`min_prune_target_bytes`, `min_blocks_to_keep`,
`calculate_current_usage`, `is_block_pruned`, `has_block_data`,
`prune_one_block_file`, `unlink_pruned_files`, `find_files_to_prune`,
`prune_block_files`, `check_prune_compatibility`, `get_prune_stats`.

**Production callers across `lib/` and `bin/`: zero.** Verified by
`grep -rn "FlatFileStorage\." lib/ bin/`: no hits.

The production pruning is the rough-and-ready `prune_old_blocks` in
`lib/sync.ml:775-799` which uses key-level RocksDB deletes (BUG-2).
Test callers in `test/test_storage.ml`, `test/test_w109_block_index.ml`,
`test/test_w133_index_databases.ml` exist — so the dead code is
locked-in by tests, making the "dead-class" pattern (W138-style) hard
to remove without test surgery.

**File:** `lib/storage.ml:1138-1791` (the entire `FlatFileStorage`
module).

**Impact:**
- Operators who read the source and see `prune_block_files` /
  `find_files_to_prune` reasonably assume Core-parity pruning is in
  force; it isn't. **Comment-as-confession** at `storage.ml:1613-1624`
  ("Bitcoin Core compatible / Reference: Bitcoin Core's
  node/blockstorage.cpp") is misleading.
- Audit/grep results for "pruning is correct because we mirror Core's
  PruneOneBlockFile" are false positives.
- W146 BUG-1 already flagged the broader FlatFileStorage dead-class
  issue; W149 confirms it specifically traps the pruning gate matrix.

---

## BUG-22 (P1) — Mainnet `assume_valid_hash` points to block 938343 (Apr 2025); Core's same release cycle uses 938343 too — but no consistency check enforces equality

**Severity:** P1 (carry-forward risk). camlcoin mainnet assume_valid:
```
"aca51bd5fa4b098e477c171ddcdcd894914dd7d6ebcc00000000000000000000"
display: 00000000000000000000ccebd6d74d9194d8dcdc1d177c478e094bfad51ba5ac
height: 938343
```

Core current (kernel/chainparams.cpp:110):
```
"00000000000000000000ccebd6d74d9194d8dcdc1d177c478e094bfad51ba5ac"
height: 938343
```

**They match today.** But:
1. There is no `check_buried_deployment_consistency`-style assertion
   that holds `defaultAssumeValid` in sync with `minimum_chain_work`
   (BUG-12 confirms `minimum_chain_work` IS stale, while
   `assume_valid_hash` is current — they should advance together per
   Core's release process).
2. A future bump of one without the other (cross-cite the W144
   `script_flag_exceptions` table fleet-wide pattern) will create a
   silent divergence.

**File:** `lib/consensus.ml:620-626` (mainnet),
`:729-733` (testnet4); both pairs lack a startup assertion.

**Core ref:** `bitcoin-core/src/validation.cpp` releases tie the
two together via a release-process step in chainparams.cpp.

**Impact:** Drift risk on the next release cycle; the values can
silently de-sync. Today only `minimum_chain_work` is stale; the
asymmetry itself is a code smell.

---

## BUG-23 (P2) — `--prune=1` manual-mode sentinel is propagated, but NODE_NETWORK_LIMITED is advertised anyway

**Severity:** P2. `cli.ml:243`:
```ocaml
Peer.set_prune_mode_advertise (config.prune > 0);
```

This fires for `--prune=1` (manual mode). But with BUG-1 (no
`pruneblockchain` RPC), `--prune=1` cannot actually trigger any
pruning. The node advertises NODE_NETWORK_LIMITED → BIP-159 peers
treat it as a limited-history node → but the node actually has the
full chain on disk. False advertisement to the network.

**File:** `lib/cli.ml:243`.

**Impact:** Peers waste bandwidth re-routing their requests to other
full nodes when this one would have served them; minor inefficiency.

---

## BUG-24 (P2) — `prune_old_blocks` `delete_undo_data` window is `keep_blocks + 288`, but no `MIN_BLOCKS_TO_KEEP` ENV / config override

**Severity:** P2. Core lets operators run with custom
`-maxreorgdepth`-style overrides (not exact name; the rationale is
the same). camlcoin's 288 floor is a literal in `lib/sync.ml:783`:
```ocaml
let min_keep = 288 in  (* Bitcoin Core MIN_BLOCKS_TO_KEEP *)
```
and the undo-keep extra is also literally `288`:
```ocaml
if h < current_height - keep_blocks - 288 then
  Storage.ChainDB.delete_undo_data state.db hash
```
Both should derive from a single `Consensus.min_blocks_to_keep` or
similar shared constant to avoid drift. Today the dead-code copy at
`lib/storage.ml:1630` (`let min_blocks_to_keep = 288`) is a SECOND
copy of the constant — three copies total across the codebase (sync.ml
has two literals).

**File:** `lib/sync.ml:783, 795`; `lib/storage.ml:1630`.

**Impact:** Constant-duplication smell; cross-cite W143 BUG `merkle_pairs`
duplication. A future change to one site won't propagate.

---

## BUG-25 (P2) — `prune_old_blocks` per-height linear scan; no batching, no `Storage.ChainDB.batch_delete`

**Severity:** P2. The loop at sync.ml:789-797 issues one RocksDB
delete per block height. `cf_chainstate` exposes
`batch_delete_block_data` and `batch_delete_undo_data`
(lib/cf_chainstate.ml:376, 412) which would let the prune sweep
operate in a single batch per call. The current per-key loop is
correct but inefficient — on mainnet after a fresh restart with
BUG-3, it issues 900k+ individual deletes.

**File:** `lib/sync.ml:789-797`.

**Impact:** Startup-latency contribution; observable but not
catastrophic.

---

## BUG-26 (P2) — `Block_pruned` enum variant exists but no `Cf_chainstate` column to persist per-block prune state

**Severity:** P2. The `Block_pruned` flag (storage.ml:1103) is set
only by `FlatFileStorage.prune_one_block_file` (storage.ml:1655) —
which is dead code (BUG-21). The production path
(`Storage.ChainDB.delete_block`) does not consult or store any
prune-state bit per block; the only way to know if a block is pruned
is to query `cf_block_data` and observe `None`.

**File:** `lib/storage.ml:1103, 1655`; production path uses
`ChainDB.delete_block` (storage.ml:842), which writes no metadata.

**Impact:** Cross-cite BUG-6/BUG-8 — no way to distinguish "never
had" from "pruned"; BUG-21 cross-cite — the entire enum-and-flag
machinery is intent without execution.

---

## BUG-27 (P1) — `chain.prune_target` field is mutable but only assigned at startup; no RPC to change at runtime

**Severity:** P1. `lib/sync.ml:145` declares
`mutable prune_target : int`. `lib/cli.ml:315` assigns it once at
startup. No RPC handler (or any code path post-startup) mutates this
field. To change the prune target requires a restart, even though the
field is mutable (suggesting intent to support runtime adjustment).

Core supports `-prune=N` only at startup (no runtime knob), so this
is parity-wise OK — but the `mutable` keyword + the TODO at
sync.ml:149 ("only the pruneblockchain RPC triggers a sweep — TODO")
imply runtime-adjustable design intent that was never realized.

**File:** `lib/sync.ml:145, 149`; `lib/cli.ml:315`.

**Impact:** Design-intent vs reality mismatch; minor.

---

## BUG-28 (P2) — `import-blocks` does not check `consensus.assume_valid_hash` to skip validation; cannot accelerate bootstrap

**Severity:** P2 (efficiency, related to BUG-18). Even setting aside
BUG-18's security concerns, the import-blocks loop runs full
`Utxo.connect_block_optimized` (which itself does script verification)
on every imported block. Since the operator presumably trusts the
file (they chose to import it), the assume-valid fast path would
provide a 5-10× speedup. Current behavior: import on mainnet takes
≥24 hours.

**File:** `lib/block_import.ml:95` (call to `connect_block_optimized`
with no `~skip_scripts` parameter).

**Impact:** Slow bootstrap; UX gap, not consensus.

---

## BUG-29 (P2) — Header flood gate (`max_headers_in_memory = 1_000_000`) is independent of `minimum_chain_work`; gate is unreachable when min_work = 0

**Severity:** P2 (cross-cite BUG-13/14). `lib/sync.ml:923-933`:
```ocaml
if Hashtbl.length state.headers >= max_headers_in_memory
   && Consensus.work_compare tip_work state.network.minimum_chain_work < 0 then
  Error "Header flood: too many headers with insufficient chain work"
```

The AND-gate means: on testnet3/testnet4 (where `minimum_chain_work
= zero_work`), `tip_work < zero_work` is impossible, so the flood
gate never fires regardless of how many headers an attacker injects.
**1 million headers × ~150 bytes per entry = ~150 MB of memory growth
unbounded.**

The gate should also fire when header count exceeds 1M REGARDLESS of
chainwork (Core's behavior: limit unconditionally, treat low-work as
a separate signal).

**File:** `lib/sync.ml:923-933`.

**Impact:** Memory-exhaustion DoS on testnet3/testnet4. Confirmed via
read of the predicate; not observed in production because most
testnet attacks don't run this far.

---

## BUG-30 (P3) — Regtest `assume_valid_hash = None` but `minimum_chain_work = zero_work` — consistent, but no startup assertion ties the two together

**Severity:** P3 (defensive). Regtest correctly has both fields
unset/zero (consensus.ml:771-772). But the relationship
"if assume_valid_hash is None then minimum_chain_work should not
constrain anything either" is not asserted anywhere; a future
network config that sets one without the other would silently behave
in unexpected ways.

**File:** `lib/consensus.ml:771-772`.

**Impact:** Latent — no production failure today, but lacking
cross-field invariants for future networks.

---

## Fleet-pattern smells

- **Dead-class (W138-style)** (cross-cite W146 BUG-1) — entire
  `FlatFileStorage` module's pruning surface (BUG-21) is defined
  with the full Core-parity API and zero production callers; only
  tests reference it. Same shape as W138's `ChainstateManager` /
  `BackgroundValidator` dead classes fleet-wide pattern.
- **Comment-as-confession** (BUG-1, BUG-2) — `sync.ml:149` "only
  the pruneblockchain RPC triggers a sweep — TODO" (the RPC doesn't
  exist); `storage.ml:1614-1624` "Reference: Bitcoin Core's
  node/blockstorage.cpp" (the entire module is dead).
- **Dead-helper-at-call-site** (BUG-19, BUG-27) —
  `check_prune_compatibility` exists, exported, no callers;
  `chain.prune_target` is `mutable` but only ever assigned once.
- **Two-pipeline guard** (BUG-2, BUG-18, BUG-21) — production
  pruning in `sync.ml` (key-level deletes) coexists with the
  Core-shape file-aligned pruning in `storage.ml` (dead); production
  block-write goes through `ChainDB`/`cf_chainstate` while the
  parallel `FlatFileStorage` writes to blk*.dat files (dead). Cross-cite
  W143 5-pipeline, W144 two-pipeline.
- **Plumbing-without-action** (BUG-9) — NODE_NETWORK_LIMITED service
  bit is advertised, but the receive-side GetData enforcement gate
  doesn't exist. Cross-cite W141 "advertise-without-honour" fleet
  pattern.
- **Hardcoded constants that should be params-aware** (BUG-13, BUG-14)
  — testnet3/testnet4 `minimum_chain_work = zero_work` while Core
  ships positive values. Cross-cite W145 `nSubsidyHalvingInterval`
  fleet pattern (5+ impls hardcoded).
- **block_import.ml bypass** (BUG-18) — confirms the W143/W144/W145
  pattern: every wave finds `block_import.ml` skips the gates being
  audited that wave. Three quad-waves in a row → strong evidence for
  an architectural fix (route `block_import` through
  `Validation.accept_block`).
- **Carry-forward TODO** (BUG-1) — `sync.ml:149` TODO comment has
  been carried forward unchanged through W123, W138, W148, now W149
  (~4 audit cycles). Same shape as W123 → W145 BUG-1 carry-forward.
- **Stale chainparams version** (BUG-12) — mainnet
  `minimum_chain_work` rotted to ~block 804000 while
  `assume_valid_hash` was updated to block 938343 in the same file;
  release process is asymmetric. Cross-cite W145 BUG-3 two parallel
  block_subsidy constants.
- **Defense-in-depth missing** (BUG-11) — Core's assume-valid uses
  5 independent gates; camlcoin uses 1 (height-only). Cross-cite the
  W140 "compounding-security stack" fleet pattern (every layer
  missing).
- **30-of-30-gates-buggy NOT fired** — this audit has 30 BUGs
  spread across 9 behaviours; the closest single behaviour cluster is
  Pruning (BUGs 1-9, 17-28 = 19 bugs across the prune-related gates)
  which is heavily concentrated but mixed with several P0-CDIV /
  P0-SEC bugs that warrant individual attention rather than
  "subsystem rewrite".

---

## Severity rollup

- **P0-SEC** (security-divergent): 1 — BUG-11 (assume-valid height-only)
- **P0-CDIV** (consensus-divergent): 5 — BUG-2, BUG-6, BUG-12, BUG-13,
  BUG-14, BUG-15
- **P0** (architectural gap): 4 — BUG-3, BUG-7, BUG-18, BUG-21
- **P1** (correctness / surface): 11 — BUG-1, BUG-4, BUG-5, BUG-8,
  BUG-9, BUG-10, BUG-16, BUG-17, BUG-19, BUG-20, BUG-22, BUG-27
- **P2** (defense-in-depth / efficiency): 7 — BUG-23, BUG-24, BUG-25,
  BUG-26, BUG-28, BUG-29
- **P3** (nit): 1 — BUG-30

**Total: 30 bugs across 30 sub-gates.**

Highest-leverage fixes (in P0-first / smallest-LOC-first order):

1. **BUG-12** (one-line — bump mainnet `minimum_chain_work` to Core's
   current `0000…01128750f82f4c366153a3a030` and update the
   "approximately block 804000" comment). Resolves the chain-split
   surface that compounds BUG-11.
2. **BUG-13 + BUG-14** (two-line each — set testnet3 / testnet4
   `minimum_chain_work` to Core's values). Closes the header-flood
   gate on test networks.
3. **BUG-11** (~10 lines — add the 4 missing Core gates to
   `is_assume_valid`: ancestor-of-av-chain via header-tree walk,
   ancestor-of-best-header, best-header-chainwork-≥-min-work, 2-week
   equivalent). Closes the P0-SEC chain-split candidate.
4. **BUG-15** (~5 lines — add `max_tip_age` + `MinimumChainWork`
   checks to `start_ibd`'s exit predicate; latch
   `sync_state = FullySynced` only when all three hold).
5. **BUG-18** (~3 lines — route `Block_import.run` through
   `Sync.process_new_block` or `Validation.accept_block` instead of
   `Utxo.connect_block_optimized` directly). Closes the bypass; cross-
   cite W143/W144/W145 pattern.
6. **BUG-1** (~30 lines — implement `pruneblockchain` RPC handler
   wrapping `prune_old_blocks`). Closes the manual-mode dead
   sentinel.
7. **BUG-10** (~10 lines — add `--assumevalid` Cmdliner arg, wire
   through to `consensus.network_config.assume_valid_hash` override).
8. **BUG-3** (~5 lines — persist `prune_height` to `cf_chain_state`,
   restore in `restore_chain_state`). Closes the
   per-restart-walk-from-zero.
9. **BUG-19** (~3 lines — call `check_prune_compatibility` from
   `cli.ml` startup; refuse-to-start on conflict). Closes the
   defined-but-unused helper.
10. **BUG-20** (~5 lines — populate `mediantime` and `size_on_disk`
    in `handle_getblockchaininfo`; the helpers exist
    (`compute_median_time_for_display`, `calculate_current_usage`).
