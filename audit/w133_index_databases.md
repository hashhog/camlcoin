# W133 Index Databases (txindex + coinstatsindex) — camlcoin (OCaml)

Wave: W133 — Index databases excluding blockfilterindex (W121 covered that).
Scope: TxIndex (`src/index/txindex.{h,cpp}`), CoinStatsIndex
(`src/index/coinstatsindex.{h,cpp}`), the BaseIndex sync framework
(`src/index/base.{h,cpp}`), CDiskTxPos (`src/index/disktxpos.h`), and the
shared height-vs-hash key infrastructure (`src/index/db_key.h`).

Bitcoin Core references:
- `bitcoin-core/src/index/base.{h,cpp}` — BaseIndex + DB_BEST_BLOCK locator + Sync thread
- `bitcoin-core/src/index/txindex.{h,cpp}` — TxIndex::CustomAppend + FindTx
- `bitcoin-core/src/index/coinstatsindex.{h,cpp}` — CoinStatsIndex (MuHash3072 + per-block DBVal)
- `bitcoin-core/src/index/disktxpos.h` — CDiskTxPos (FlatFilePos + nTxOffset)
- `bitcoin-core/src/index/db_key.h` — DBHeightKey (BE) / DBHashKey / LookUpOne / CopyHeightIndexToHashIndex

Methodology: read Core refs, synthesize a 30-gate audit matrix, classify
against camlcoin's de-facto index surface
(`lib/storage.ml::ChainDB.{store,get,delete}_tx_index`,
`lib/cf_chainstate.ml::cf_tx_index`, `lib/sync.ml::tx_index_*`,
`lib/rpc.ml::handle_gettxoutsetinfo`, `lib/muhash.ml`).
Catalogue BUGs by severity:
- **P0-CDIV**: consensus / RPC-correctness divergence visible to clients
- **P1**: index correctness (wrong/missing data returned, no crash recovery)
- **P2**: performance / resource (slow, O(N) per RPC, etc.)
- **P3**: surface / doc drift

Prior work on the same code path:
- 2026-05-05 Pattern C0 fleet finding closed the **functional** gap: tx_index
  was previously written by tests only, never by production block-connect.
  The fix wired `tx_index_write_for_block` into `process_new_block`,
  `connect_stored_blocks`, the reorg-connect path, `submit_block`, and
  `block_import`, and wired `batch_delete_tx_index` into the
  reorg-disconnect path. W133 audits the STRUCTURAL gaps left after that
  closure landed.
- W121 (BIP-157 compact filters) covered `blockfilterindex` and is
  **explicitly out of scope** here.

## Architectural baseline (what camlcoin has and what it doesn't)

camlcoin **has no equivalent of `class BaseIndex`**. Core's index framework
is a base class providing:

  - separate per-index `CDBWrapper` at `<datadir>/indexes/<name>/`
  - `DB_BEST_BLOCK` locator persistence (so each index knows where it
    stopped, independent of chainstate)
  - dedicated `m_thread_sync` sync thread + `m_synced` latch
  - `m_init` initialization gate
  - `m_best_block_index` atomic pointer
  - `ValidationInterface::RegisterValidationInterface` hookup (so
    `BlockConnected` / `BlockDisconnected` / `ChainStateFlushed` are
    delivered automatically)
  - `Init() / Sync() / Stop() / Interrupt()` lifecycle
  - `Rewind()` on reorg + `CustomRemove` callback
  - `AllowPrune()` virtual + `UpdatePruneLock` integration
  - `GetSummary()` per-index status surface
  - `BlockUntilSyncedToCurrentChain()` synchronization barrier

camlcoin collapses all of this into:
  - `Storage.ChainDB.{store,get,delete}_tx_index` (one CF inside the
    main `chainstate-rocks/` RocksDB; no separate dir, no separate WAL)
  - `Sync.tx_index_{write,erase}_for_block` (called inline from every
    block-connect/disconnect path)
  - No separate sync thread; no DB_BEST_BLOCK locator; no
    `m_best_block_index`; no `m_synced`; no `m_init`; no `Init()` path
    that distinguishes "synced" from "behind"; no `Rewind()` (handled
    inline in `reorganize`'s disconnect path); no `Stop()`; no per-index
    prune lock; no `getindexinfo` RPC; no `BlockUntilSyncedToCurrentChain`.

This collapsed architecture is the source of most W133 findings. It is
not, on its own, a P0-CDIV bug — Core could in principle be implemented
the same way — but it accumulates a number of P1/P2 gaps that **do**
diverge from Core's observable behaviour (most notably: tx_index has no
crash-recovery story, no per-index sync state, and no MuHash3072
incremental index at all).

## 30-gate matrix (W133)

### G1-G5: BaseIndex sync framework

- **G1: separate per-index DB directory.** Core
  (`base.cpp:68-76`): each index has its own `CDBWrapper` rooted at
  `<datadir>/indexes/<name>/`. **camlcoin**: tx_index is one column
  family (`cf_tx_index = "tx_index"`) inside the single
  `chainstate-rocks/` DB — see `lib/cf_chainstate.ml:52,69,85,169`.
  Sharing the LSM + WAL is documented in `cf_chainstate.ml:7-13`. **No
  CoinStatsIndex CF exists at all.** No prune-lock isolation, no
  per-index cache tuning, no per-index repair.

- **G2: DB_BEST_BLOCK locator per index.** Core
  (`base.cpp:47, 78-93`): each index DB stores its own `CBlockLocator`
  under key `'B'` so on restart `ReadBestBlock` returns the last point
  the index synced to. **camlcoin**: NO equivalent. The tx_index has no
  per-index sync-state record at all; it follows the chain tip
  (`tip_hash` / `tip_height` in `cf_chain_state`) by virtue of being
  written in the same `batch_write` as the UTXO/tip mutations. If a
  crash occurs **between** the chainstate batch commit and the tx_index
  CF batch (impossible since they share one batch — but if a future
  refactor split them, this safety is lost), there is no way to detect
  or recover. **P1: no per-index crash recovery surface.**

- **G3: dedicated sync thread.** Core
  (`base.cpp:453-459`): `StartBackgroundSync()` spawns
  `m_thread_sync` running `Sync()` to walk from `m_best_block_index`
  to chain tip with `SYNC_LOG_INTERVAL=30s` and
  `SYNC_LOCATOR_WRITE_INTERVAL=30s`. **camlcoin**: NO. Block-connect
  callers inline `tx_index_write_for_block`, so the index is by
  construction always exactly at chain tip (assuming the
  pre-Pattern-C0 wiring is complete). The cost: no
  "catch up an index that was disabled, now is enabled" pathway. No
  `--reindex-chainstate`-equivalent. No backfill on first-enable of
  tx_index (there is no "first-enable" — it's always on).

- **G4: m_synced atomic latch.** Core
  (`base.h:88-91`): `m_synced` flips false→true exactly once when the
  background sync catches up. `BlockConnected` notifications are
  ignored until `m_synced` is true. **camlcoin**: NO. All block-connect
  paths unconditionally write tx_index entries.

- **G5: ValidationInterface registration.** Core
  (`base.cpp:117`): `validation_signals->RegisterValidationInterface(this)`.
  Indexes receive `BlockConnected` / `BlockDisconnected` /
  `ChainStateFlushed` automatically and asynchronously. **camlcoin**:
  NO publish/subscribe. Inline calls only. **P3**: harder to add a new
  index without editing all five block-connect call sites.

### G6-G10: TxIndex content + on-disk layout

- **G6: CDiskTxPos serialization.** Core (`disktxpos.h:11-23`):
  `CDiskTxPos = FlatFilePos{nFile, nPos} + VARINT(nTxOffset)`. Compact:
  ~6-10 bytes per tx. **camlcoin (`storage.ml:697-712`)**: tx_index
  value is **block_hash(32 bytes) ++ tx_idx (4 bytes LE) = 36 bytes**.
  Different on-disk format — not portable across implementations even
  in principle. **P3: BIP-N/A; per-impl choice but documented divergence.**

- **G7: tx blob lookup path.** Core (`txindex.cpp:93-119`): `FindTx`
  reads `CDiskTxPos`, opens `blk{nFile}.dat`, seeks past the header to
  `nTxOffset`, reads ONE tx (cheap, ~few hundred bytes). **camlcoin
  (`rpc.ml:993-998`)**: tx_index gives `(block_hash, tx_idx)`; lookup
  then calls `Storage.ChainDB.get_transaction db txid` which fetches
  the full tx blob from the SEPARATE `cf_tx` column family. This is
  O(1) but uses **2× the storage** of Core (block body + tx blob
  duplicated in the `cf_tx` CF). For a 200GB block dataset this
  doubles the tx-index disk footprint vs Core's seek-into-blkXXXXX.dat
  approach. **P2: disk-usage regression vs Core.**

- **G8: TxIndex::CustomAppend genesis guard.** Core
  (`txindex.cpp:77`): `if (block.height == 0) return true;` — genesis
  block transactions are NEVER indexed because their outputs are not
  spendable. **camlcoin (`sync.ml:2832-2846`)**:
  `tx_index_write_for_block` has **NO height==0 guard**. If genesis is
  re-connected (fresh-install, regtest reset, restoration test), the
  genesis coinbase is indexed and made queryable via
  `getrawtransaction`. **Observable divergence**: `getrawtransaction
  4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b`
  (mainnet genesis coinbase) returns the tx on camlcoin but
  `"No such mempool or blockchain transaction. Use -txindex..."` on
  Core (even with `-txindex=1`). **P1**: cosmetic-but-real RPC
  divergence; consensus-diff harness may flag this on fresh datadirs.

- **G9: per-block-connect indexing order vs Core.** Core
  (`txindex.cpp:74-89`): walks `block.data->vtx` in order, accumulates
  `pos.nTxOffset += GetSerializeSize(TX_WITH_WITNESS(*tx))` so each
  tx's pos has the EXACT byte offset within blkXXXXX.dat. The
  serialized-size accumulator is the key: a `CDiskTxPos` is a precise
  byte offset, not a list index. **camlcoin**: stores `tx_idx` (the
  ordinal index 0..N-1) instead of a byte offset. **P3**:
  not-Core-portable but no observable consequence given camlcoin uses
  full blob lookup.

- **G10: WriteTxs batch atomicity.** Core
  (`txindex.cpp:59-66`): one `CDBBatch` per block (`WriteTxs` builds
  and commits a single batch). **camlcoin (`sync.ml:2832-2846`,
  `storage.ml:585-589`)**: each tx is stored via TWO separate
  non-batched RocksDB puts (`store_transaction` writes to `cf_tx`;
  `store_tx_index` writes to `cf_tx_index`). Neither is wrapped in a
  batch. **In the non-reorg path** these run in succession but are
  NOT atomic with the chain-tip update — a crash between the
  `apply_block_atomic` chainstate commit (`sync.ml:4331`) and the
  `tx_index_write_for_block` calls (`sync.ml:4475`) leaves chainstate
  advanced but tx_index missing entries. **P1: non-atomic write**.
  The reorg-connect path uses the shared batch correctly
  (`sync.ml:3461-3465`) — only the happy-path block-connect has this
  gap.

### G11-G15: TxIndex lifecycle (Init / Sync / Stop / FindTx error paths)

- **G11: TxIndex::FindTx integrity check.** Core
  (`txindex.cpp:114-117`): re-computes `tx->GetHash()` after
  deserialization and compares to `tx_hash` argument — catches a
  corrupted DB or wrong-tx-at-pos. **camlcoin (`rpc.ml:993-998`)**:
  no recomputation; trusts that the (txid, blob) entry in `cf_tx` is
  correct. If the `cf_tx` CF gets corrupted, lookup silently returns
  wrong data. **P1: no in-band corruption detection.**

- **G12: TxIndex::FindTx I/O error path.** Core
  (`txindex.cpp:100-113`): `try`/`catch` around the file read +
  deserialize, logs `Deserialize or I/O error`, returns false.
  **camlcoin (`rpc.ml:994-998`)**: no try/catch; on deserialization
  failure (corrupted CF entry), an exception escapes to the RPC
  layer and surfaces as HTTP 500 instead of "transaction not found"
  / "DB error". **P2: surface drift on I/O error.**

- **G13: BaseIndex::Init reads locator and rewinds.** Core
  (`base.cpp:104-148`): on Init, reads `DB_BEST_BLOCK`, looks up the
  locator's top block, calls `SetBestBlockIndex`; if that block is
  NOT on the active chain, the subsequent `Sync()` will rewind to the
  fork point. **camlcoin**: NO Init path for tx_index. If camlcoin
  crashes mid-reorg (after apply_block_atomic committed N-1 of M
  reorg blocks but before block N's tx_index_write fired), the
  tx_index is silently stale on restart. There is no startup probe.
  **P0-CDIV in extreme failure mode**: getrawtransaction would
  return stale (pre-reorg) block_hash for txs that survived the
  reorg but whose containing block changed. The Pattern D-FULL
  shared-batch fix at `sync.ml:3461-3465` reduces this window to
  zero for full reorgs, but the happy-path block-connect at
  `sync.ml:4475` is OUTSIDE the atomic batch (see G10).

- **G14: BaseIndex::Stop joins sync thread.** Core
  (`base.cpp:461-470`): `Stop()` unregisters from validation
  signals + joins `m_thread_sync`. **camlcoin**: NO sync thread to
  stop. **P3**: cleaner shutdown path is unnecessary.

- **G15: BaseIndex::Interrupt.** Core (`base.cpp:448-451`):
  `m_interrupt()` sets a flag that `Sync()` polls every iteration.
  **camlcoin**: NO. **P3.**

### G16-G20: CoinStatsIndex existence + invariants

- **G16: CoinStatsIndex class exists.** Core
  (`coinstatsindex.h:30-73`): full BaseIndex subclass with MuHash3072
  field, 11 accumulator fields (transaction_output_count, bogo_size,
  total_amount, total_subsidy, total_prevout_spent_amount,
  total_new_outputs_ex_coinbase_amount, total_coinbase_amount,
  total_unspendables_*), per-block DBVal write under DBHeightKey, and
  `LookUpStats` that returns a `CCoinsStats`. **camlcoin**: NO. No
  `lib/index/coinstatsindex.ml`, no CoinStatsIndex column family in
  `cf_chainstate.ml`, no incremental MuHash3072 accumulator threaded
  through block-connect. **P1: feature absent**.

- **G17: per-block UTXO commitment incrementally maintained.** Core
  (`coinstatsindex.cpp:108-214` `CustomAppend`): on every block-connect,
  applies `ApplyCoinHash` for each new UTXO and `RemoveCoinHash` for
  each spent UTXO, updates `m_total_*` accumulators, finalizes
  `m_muhash` to a 32-byte uint256, writes one `(uint256, DBVal)` pair
  under `DBHeightKey(block.height)`. O(tx_in + tx_out) per block.
  **camlcoin**: NO. `gettxoutsetinfo` (`rpc.ml:7206-7315`) walks
  the **entire UTXO set** on every RPC call to compute the MuHash
  fresh. **P0-CDIV-adjacent (P1)**: for a 100M-coin UTXO set, every
  `gettxoutsetinfo "muhash"` call is O(100M) instead of O(1). Public
  endpoints can be DoS'd by repeated calls. Production explorers /
  audit tools that poll this RPC fail or take minutes to respond
  vs. milliseconds on Core.

- **G18: per-block stats queryable by block_index.** Core
  (`coinstatsindex.h:72`): `LookUpStats(const CBlockIndex& block_index)`
  returns the UTXO-set stats AT THAT HEIGHT. Used by
  `gettxoutsetinfo "muhash" 12345` (query historical height).
  **camlcoin**: NO. `gettxoutsetinfo` only supports tip height; the
  RPC explicitly rejects the second positional `blockhash` argument
  with `Querying specific block heights is not supported`
  (`rpc.ml:7217`) because camlcoin "does not maintain a coinstats
  index" (`rpc.ml:7204`). **P1**: feature absent.

- **G19: hashSerialized (HASH_SERIALIZED) incrementally maintained.**
  Core `kernel/coinstats.cpp` HASH_SERIALIZED computes the same
  preimage as MuHash but feeds it to SHA256d and combines via XOR
  (not multiplicative). CoinStatsIndex's `DBVal.muhash` field
  conflates the namespace label; in fact the index stores MuHash and
  the HASH_SERIALIZED path is computed by `gettxoutsetinfo`
  on-the-fly when no coinstats index is present. **camlcoin
  (`rpc.ml:7235-7311`)**: BOTH hash_serialized_3 and muhash are
  computed on-the-fly per call, both walk all UTXOs. **P1.**

- **G20: total_subsidy + total_unspendables accumulators.** Core
  (`coinstatsindex.cpp:55-58`):
  `m_total_subsidy / m_total_unspendables_genesis_block /
   m_total_unspendables_bip30 / m_total_unspendables_scripts /
   m_total_unspendables_unclaimed_rewards`. Each updated per
  block-connect with the subsidy formula and the BIP-30 / unspendable
  rules. **camlcoin gettxoutsetinfo response shape (`rpc.ml:7286-7314`)**:
  emits ONLY `height`, `bestblock`, `transactions`, `txouts`,
  `bogosize`, `total_amount`, and the requested hash. NONE of
  `total_unspendables_genesis_block`, `total_unspendables_bip30`,
  `total_unspendables_scripts`, `total_unspendables_unclaimed_rewards`,
  `total_subsidy`, `total_prevout_spent_amount`,
  `total_new_outputs_ex_coinbase_amount`, `total_coinbase_amount`
  are present. **P0-CDIV** (RPC shape divergence): clients expecting
  the Core-shape response will not find these fields. **8 missing
  fields.**

### G21-G25: db_key.h shared infrastructure (used by both indexes + blockfilterindex)

- **G21: DBHeightKey big-endian serialization.** Core (`db_key.h:38-41`):
  `ser_writedata8(s, DB_BLOCK_HEIGHT); ser_writedata32be(s, height);`
  — BE so sequential reads-by-height are LSM-sequential. **camlcoin
  block_height CF (`cf_chainstate.ml:?`, `storage.ml:545`):**
  `encode_height` uses BE (matches Core). However the camlcoin
  `tx_index` CF is keyed by **txid** alone (not by height) — there is
  no height-keyed iteration path, so the BE-for-sequential-iteration
  property is moot. **P3: feature absent because architecture differs.**

- **G22: DB_BLOCK_HEIGHT vs DB_BLOCK_HASH key prefixes.** Core
  (`db_key.h:29-30`): `DB_BLOCK_HASH='s'`, `DB_BLOCK_HEIGHT='t'`.
  Note `'t'` collides with the `tx` namespace prefix used by camlcoin's
  legacy LogStorage (`storage.ml:473`). camlcoin's CF backend uses
  named CFs (not prefix bytes) so there's no collision, but a future
  migration that adds a coinstatsindex CF must NOT use prefix-byte
  keys or it will trip Core-shape consumers. **P3: doc-level.**

- **G23: LookUpOne fallback to hash index on reorg.** Core
  (`db_key.h:95-113`): `LookUpOne` first reads `DBHeightKey(height)`;
  if the stored hash doesn't match the requested block's hash (i.e.
  this height is now occupied by a different block due to a reorg),
  falls back to `DBHashKey(hash)`. This preserves queryability of
  stats for blocks that left the main chain. **camlcoin**: NO
  equivalent. Coinstats is absent entirely; for tx_index, the
  reorg-disconnect deletes the entry outright (`sync.ml:3324-3327`),
  so a tx that was on the abandoned chain becomes unfindable by
  txid (even with `getrawtransaction` blockhash hint — see G24).
  **P1**.

- **G24: CopyHeightIndexToHashIndex on reorg.** Core (`db_key.h:71-93`):
  during `CustomRemove`, walks the height-keyed entries for the
  disconnected block and writes them under their hash key so the
  data is still queryable via the hash index. **camlcoin**: NO.
  Side-branch tx_index entries are silently deleted. Operator
  invariant violation: a node that observed a tx at height H, then
  re-orged, then was asked `getrawtransaction <txid>` returns
  "not found" even though the tx still exists in the disconnected
  block body (`cf_block_data` retained). **P1**: silent data loss
  from the RPC surface (the raw block body is still on disk; only
  the lookup path is broken).

- **G25: per-DB obfuscate key.** Core (`base.cpp:69-76`, `dbwrapper.h`):
  index DBs can opt into an obfuscate key (XOR applied at I/O time)
  to make on-disk inspection harder. **camlcoin**: NO. Rocksdb_stubs
  passes raw bytes through. **P3: not a security gap (operator
  controls the host).**

### G26-G30: misc surface (RPC + lifecycle + concurrency)

- **G26: `getindexinfo` RPC.** Core (`rpc/blockchain.cpp`): returns
  per-index `{name: {synced, best_block_height}}` for tx_index,
  coinstatsindex, blockfilterindex. Used by clients to detect
  index-not-ready conditions. **camlcoin**: NO `getindexinfo` handler
  found anywhere in `rpc.ml`. Clients cannot programmatically detect
  whether an index lookup is reliable. **P1: feature absent.**

- **G27: `BlockUntilSyncedToCurrentChain`.** Core (`base.cpp:424-446`):
  test surface + internal sync barrier. Used by RPC handlers that
  need to ensure the index has processed all queued
  `BlockConnected` notifications before reading. **camlcoin**: NO.
  Inline writes mean callers are already synchronous, but a future
  refactor to async indexing must add this. **P3.**

- **G28: `-txindex` / `-coinstatsindex` startup flags.** Core
  (`init.cpp` + `DEFAULT_TXINDEX=false` `DEFAULT_COINSTATSINDEX=false`):
  operator-toggled. **camlcoin**: NO `-txindex` or `-coinstatsindex`
  flags in `lib/runtime_config.ml` or `lib/cli.ml`. The tx_index is
  ALWAYS on (every block-connect writes entries); the coinstats
  index does not exist at all. There IS a `txindex : bool` parameter
  in `Storage.PruneManager.check_prune_compatibility`
  (`storage.ml:1753`) used only to enforce "pruning incompatible
  with txindex" at config-validation time. The flag is plumbed but
  has no effect on whether the index is written. **P1**: surface
  drift; operators expecting `bitcoind -txindex=0` to disable will
  find it has no effect.

- **G29: incremental MuHash3072 invariants.** Core
  (`coinstatsindex.cpp:262-306` `CustomInit`): on every restart,
  reads `DB_MUHASH` and reads the stored DBVal at the index's best
  block; finalizes the in-memory MuHash and asserts it matches the
  stored value (corruption check). **camlcoin**: NO MuHash
  accumulator persisted at all; no corruption check. **P1**: any
  bit-flip in the UTXO CF goes undetected at boot.

- **G30: assume_utxo / snapshot interaction.** Core: when a UTXO
  snapshot is loaded, `BlockConnected` from the background "IBD"
  chainstate is the one indexes follow (`base.h:50-53`); the
  snapshot's foreground chainstate is NOT indexed until the
  background catches up, to avoid out-of-order indexing.
  **camlcoin**: assume_utxo / assume-valid does exist
  (`lib/assume_utxo.ml`, `lib/assume_valid.ml`) but no index-
  framework gating. Assume-valid IBD does skip undo-data storage
  (`sync.ml:4141-4145` comment) which **does** affect the BIP-157
  filter index (covered in W121). For tx_index, the wiring still
  fires every block-connect during assume-valid IBD, indexing every
  txid from genesis upward as expected. **P3**: no observable
  consequence for tx_index; surface drift relative to Core's
  formalism.

## BUG catalogue (NEW in W133)

| ID | Sev | Gate | Description |
|---|---|---|---|
| BUG-W133-1 | P0-CDIV | G20 | `gettxoutsetinfo` response is missing 8 Core fields: `total_unspendables_genesis_block`, `total_unspendables_bip30`, `total_unspendables_scripts`, `total_unspendables_unclaimed_rewards`, `total_subsidy`, `total_prevout_spent_amount`, `total_new_outputs_ex_coinbase_amount`, `total_coinbase_amount`. Clients reading these will see `null`/missing keys. (`rpc.ml:7286-7314`) |
| BUG-W133-2 | P1 | G16 | CoinStatsIndex feature absent entirely. `gettxoutsetinfo` walks the full UTXO set on every call instead of consulting a per-block-incremental index. |
| BUG-W133-3 | P1 | G17 | MuHash3072 commitment NOT maintained incrementally. Every `gettxoutsetinfo "muhash"` is O(UTXO count); on a 100M-coin set, this is minutes per RPC vs ms on Core. |
| BUG-W133-4 | P1 | G18 | `gettxoutsetinfo` rejects historical-height queries with `Querying specific block heights is not supported` instead of returning the stats for that height (`rpc.ml:7216-7217`). |
| BUG-W133-5 | P1 | G8 | `tx_index_write_for_block` lacks `height == 0` guard. Genesis coinbase txid `4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b` is queryable via `getrawtransaction` on camlcoin but NOT on Core (`sync.ml:2832-2846`). |
| BUG-W133-6 | P1 | G2 | No `DB_BEST_BLOCK` locator per index. Crash recovery for index-vs-chainstate drift is impossible to detect on startup. (Mitigated for normal block-connect by inline-batch writes, but the architecture has no recovery surface.) |
| BUG-W133-7 | P1 | G10 | Block-connect happy path writes tx_index entries OUTSIDE the atomic `apply_block_atomic` batch (`sync.ml:4331` vs `sync.ml:4475`). A crash between these two calls leaves chainstate advanced but tx_index entries missing for the latest block. The reorg path is atomic (`sync.ml:3461-3465`), only the IBD/post-IBD happy path has the gap. |
| BUG-W133-8 | P1 | G11 | `lookup_transaction` (camlcoin's FindTx) does NOT recompute and verify `tx->GetHash() == requested_txid` after deserialization. Core (`txindex.cpp:114-117`) does. Silent corruption in `cf_tx` CF returns wrong tx blob. |
| BUG-W133-9 | P1 | G24 | No `CopyHeightIndexToHashIndex` on reorg. A tx on the disconnected chain becomes unfindable via `getrawtransaction <txid>` (no blockhash hint), even though the raw block body is retained in `cf_block_data`. (`sync.ml:3324-3327` deletes outright.) |
| BUG-W133-10 | P1 | G23 | No hash-index fallback on reorg query. Coinstats absent so this is vacuous for coinstats; for tx_index, the equivalent gap is BUG-W133-9. |
| BUG-W133-11 | P1 | G26 | No `getindexinfo` RPC. Clients cannot programmatically detect index sync state. |
| BUG-W133-12 | P1 | G28 | No `-txindex` / `-coinstatsindex` runtime flags. tx_index always-on; coinstatsindex unavailable. The `txindex` boolean in `Storage.PruneManager.check_prune_compatibility` is consulted only by the prune-compat check, not as a write-side gate. |
| BUG-W133-13 | P1 | G29 | No `DB_MUHASH` persistence / corruption check at boot. (Vacuous now because no incremental MuHash exists; reopens when BUG-W133-3 is fixed.) |
| BUG-W133-14 | P2 | G7 | tx blob duplicated across `cf_block_data` (full block) and `cf_tx` (per-tx blob). Core stores tx ONCE in blkXXXXX.dat and uses `CDiskTxPos` (~6 bytes) as the index value. ~2× disk usage for the indexed tx set vs Core. |
| BUG-W133-15 | P2 | G12 | `lookup_transaction` (`rpc.ml:993-998`) has no try/catch around `get_transaction` deserialization. Corrupted `cf_tx` entry surfaces as an OCaml exception → HTTP 500 instead of a structured RPC error. |
| BUG-W133-16 | P3 | G1 | tx_index is a column family inside `chainstate-rocks/` rather than a separate `indexes/txindex/` LSM. Loses per-index cache tuning and per-index repair, but operationally equivalent. |
| BUG-W133-17 | P3 | G3/G4/G5 | No BaseIndex sync framework (no separate sync thread, no `m_synced` latch, no `ValidationInterface`). New indexes require editing every block-connect call site. |
| BUG-W133-18 | P3 | G6/G9 | tx_index value is `block_hash(32) ++ tx_idx_le(4)` instead of Core's `CDiskTxPos` (varint nFile + varint nPos + varint nTxOffset). Larger value (~36B vs ~6-10B), not Core-portable. |
| BUG-W133-19 | P3 | G14/G15 | No `Stop()` / `Interrupt()` per-index lifecycle. Shutdown is a global `Cf_chainstate.close`. |
| BUG-W133-20 | P3 | G27 | No `BlockUntilSyncedToCurrentChain` barrier. Vacuous given inline writes; would matter if any future index moves to async. |
| BUG-W133-21 | P3 | G21/G22 | No DBHeightKey BE encoding for index data (height-keyed iteration absent because tx_index is txid-keyed and coinstats absent). |
| BUG-W133-22 | P3 | G25 | No per-DB obfuscate key. Operator-controlled host, low risk. |
| BUG-W133-23 | P3 | G30 | No assume_utxo / snapshot gating in the index framework (vacuous: no framework). |

Total **NEW in W133**: **23 BUGs** (1 P0-CDIV, 12 P1, 2 P2, 8 P3).

## Universal patterns surfaced (cross-impl candidates)

- **"on-the-fly UTXO walk instead of CoinStatsIndex"** — likely fleet-wide.
  Most impls without dedicated index infrastructure probably collapse
  `gettxoutsetinfo` to a full UTXO scan. Worth a W### sweep:
  haskoin / lunarblock / hotbuns / clearbit / nimrod all probably
  share this pattern.

- **"genesis block tx_index off-by-one"** — Core's txindex.cpp:77 guard
  is one line. Any impl that forgot to copy it indexes genesis. Easy
  cross-impl audit: probe `getrawtransaction <genesis_coinbase_txid>`
  on every fleet member; whichever return non-error are out of Core
  parity.

- **"tx blob duplicated in tx CF + block CF"** — RocksDB-backed impls
  that store both an `(txid -> tx)` namespace and a `(block_hash ->
  full_block)` namespace pay 2× the disk cost. Core's flat-file +
  CDiskTxPos is the disk-optimal design. Worth a survey wave.

- **"`gettxoutsetinfo` response missing fields"** — RPC-shape parity
  audit candidate. Core's response has 14+ fields when
  `hash_type=muhash`; camlcoin emits 7. Other impls likely have
  similar gaps. A specific fleet sweep of `getindexinfo` +
  `gettxoutsetinfo` response shape would surface a lot.

- **"no `getindexinfo` RPC"** — RPC parity gap. Likely fleet-wide.

- **"tx_index write outside atomic block-commit batch"** — happy-path
  gap not visible during reorg-only audits. Architecture-level
  invariant: every per-block index write MUST be batched with the
  chainstate tip update. Cross-impl variance likely.

## Verification

`test/test_w133_index_databases.ml` — 30 gate tests across the 5
G-bands (BaseIndex, TxIndex content, TxIndex lifecycle, CoinStatsIndex
existence, shared infrastructure / misc). Discovery-only; each test
documents the gap and serves as a regression-pin for the current
behaviour.

camlcoin gotcha (per FIX-80 / FIX-77 audit pattern): if
`dune runtest` stalls, run the pre-built
`_build/default/test/test_w133_index_databases.exe` directly.

## Out of scope (for future waves)

- BIP-157 / blockfilterindex (covered by W121, OOS per brief).
- txospenderindex (`bitcoin-core/src/index/txospenderindex.{h,cpp}`)
  exists in Core but is a separate index; defer to a follow-on wave
  if/when camlcoin grows the surface.
- Closure of any BUG above; this audit is discovery-only.
- Pruning interaction beyond G30 (covered by `Storage.PruneManager`,
  separate W-wave).
- AssumeUTXO snapshot loading effects on indexes (covered by
  `lib/assume_utxo.ml`, separate W-wave).
