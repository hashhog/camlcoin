# W139 Fee Estimation Engine (CBlockPolicyEstimator) — camlcoin (OCaml)

Wave: W139 — `CBlockPolicyEstimator`, the historical block-policy fee
estimator that powers `estimatesmartfee` / `estimaterawfee`, plus the
`FeeFilterRounder` (BIP-133 minimum-fee discretization).

Bitcoin Core references:
- `bitcoin-core/src/policy/fees/block_policy_estimator.{h,cpp}` —
  `CBlockPolicyEstimator`, `TxConfirmStats`, `EstimationResult`,
  `FeeCalculation`, `FeeFilterRounder`, constants
  (`SHORT_DECAY`, `MED_DECAY`, `LONG_DECAY`, `SHORT_SCALE`,
  `MED_SCALE`, `LONG_SCALE`, `SHORT_BLOCK_PERIODS`, `MED_BLOCK_PERIODS`,
  `LONG_BLOCK_PERIODS`, `MIN_BUCKET_FEERATE`, `MAX_BUCKET_FEERATE`,
  `FEE_SPACING`, `SUFFICIENT_FEETXS`, `SUFFICIENT_TXS_SHORT`,
  `HALF_SUCCESS_PCT`, `SUCCESS_PCT`, `DOUBLE_SUCCESS_PCT`,
  `CURRENT_FEES_FILE_VERSION` = 309900, `OLDEST_ESTIMATE_HISTORY`,
  `MAX_FILE_AGE`, `FEE_FLUSH_INTERVAL`,
  `DEFAULT_ACCEPT_STALE_FEE_ESTIMATES`).
- `bitcoin-core/src/policy/fees/block_policy_estimator_args.{h,cpp}` —
  fee_estimates.dat path resolution.
- `bitcoin-core/src/policy/feerate.{h,cpp}` — `CFeeRate`,
  `GetFeePerK()`, `GetFee(int32_t vbytes)`, `ToString`.
- `bitcoin-core/src/rpc/fees.cpp` — `estimatesmartfee`,
  `estimaterawfee`; clamping vs `min_mempool_feerate` /
  `min_relay_feerate`; `SyncWithValidationInterfaceQueue` ordering;
  shape of `errors` array vs `blocks` (always present).
- `bitcoin-core/src/util/fees.h` and `bitcoin-core/src/common/messages.{h,cpp}`
  — `FeeEstimateMode { UNSET, ECONOMICAL, CONSERVATIVE }` and
  `FeeModeFromString("economical"/"conservative"/"unset")`,
  `InvalidEstimateModeErrorMessage`.

BIPs: none. (BIP-133 fee filter is enforced by `FeeFilterRounder` in
the same Core source unit, but the BIP itself is the wire-level
"feefilter" P2P message — already covered by W118/W120 audits.)

Methodology:
1. Read Core refs.
2. Synthesize a 30-gate audit matrix.
3. Classify against camlcoin's surface (`lib/fee_estimation.ml`,
   `lib/rpc.ml::handle_estimatesmartfee`,
   `lib/rpc.ml::handle_estimaterawfee`,
   `lib/rpc.ml::handle_sendtoaddress` consumers,
   `lib/cli.ml` startup/shutdown/process_block wiring,
   `lib/peer.ml::FeeFilterRounder`).
4. Catalogue BUGs by severity:
   - **P0-CDIV**: client-observable correctness divergence
     (wrong-units RPC, "blocks" never clamped, estimate ignores
     min-relay floor, etc.).
   - **P1**: feature/field absent that spec/Core mandates.
   - **P2**: performance / DoS surface (unbounded memory, no decay
     of stale data, sample-list growth, etc.).
   - **P3**: surface drift, error-message shape, comment drift.
5. Pin existing W114-era fixes (FIX-47, BUG-1..BUG-5 fixes from prior
   W114) as INV-N regression tests so a future fix wave cannot
   silently regress them.

## Prior work in this area (W114 baseline)

W114 already audited the same module and landed five fixes:
- BUG-1: `short.decay` 0.998 → 0.962 (Core SHORT_DECAY)
- BUG-2: `medium.decay` 0.9995 → 0.9952 (Core MED_DECAY)
- BUG-3: `MIN_BUCKET_FEERATE` 1.0 sat/vB → 0.1 sat/vB
  (Core 100 sat/kvB)
- BUG-4: `estimaterawfee.scale` field = horizon scale 1/2/24 (was
  FEE_SPACING 1.05)
- BUG-5: `min_confirm_target` 1 → 2 (Core estimateSmartFee target=1
  clamp)
- FIX-47: `track_transaction` wired in cli.ml TxMsg path;
  `record_eviction` wired via `mempool.on_eviction` hook.
- FIX-49: `FeeFilterRounder` uses `csprng_int_range 3`, not OCaml
  `Random.int 3` (CSPRNG seeded from /dev/urandom).

W139 is a **deeper** audit, focused on the structural / algorithmic
gaps the W114 audit explicitly documented but did not close:
the three-pass estimator, the `validForFeeEstimation` guard, the
`txHeight == nBestSeenHeight` guard, `FlushUnconfirmed`,
`MaxUsableEstimate`, `SyncWithValidationInterfaceQueue` ordering,
the `min_mempool_feerate` / `min_relay_feerate` clamp, the
`scale` factor in `TxConfirmStats::Record` (period bucketing), the
`unconfTxs` circular buffer (`ClearCurrent`), `oldUnconfTxs`,
`failAvg` decay, the binary `fee_estimates.dat` format (version
309900), MAX_FILE_AGE / DEFAULT_ACCEPT_STALE_FEE_ESTIMATES,
FEE_FLUSH_INTERVAL periodic flush, the `errors` array shape under
the no-data path, and several smaller gaps.

## Architectural baseline (what camlcoin has, what it doesn't)

camlcoin's fee-estimation surface lives in **one 554-LOC file**
(`lib/fee_estimation.ml`) plus a small RPC wrapper in `lib/rpc.ml`
(`handle_estimatesmartfee` 1637–1654, `estimate_raw_horizon` 1663–
1749, `handle_estimaterawfee` 1751–1793) and a wallet-side caller
in `handle_sendtoaddress` (rpc.ml:2237–2253) plus three
production wires in `lib/cli.ml`:

  - `cli.ml:424` — `Fee_estimation.create ()` at startup.
  - `cli.ml:436` — `mempool.on_eviction := Fee_estimation.record_eviction`.
  - `cli.ml:479` — `Fee_estimation.load_from_file` (OCaml Marshal).
  - `cli.ml:1215, 1364, 1414` — `Fee_estimation.process_block` on
    block connect (3 separate call sites — IBD, headers-first, P2P
    block-relay).
  - `cli.ml:1259` — `Fee_estimation.track_transaction` on
    `accept_to_memory_pool`.
  - `cli.ml:1671` — `Fee_estimation.save_to_file` at shutdown.

The module exposes:
  - `type t` with three horizons (short / medium / long), an array of
    fee buckets per horizon, a flat tracked-txs hashtable keyed by
    txid, and a `block_height` cursor.
  - `track_transaction`, `record_confirmation`, `record_eviction`,
    `apply_decay`, `process_block`, `estimate_fee`,
    `compute_percentile`, `compute_median`,
    `get_bucket_stats`, `current_height`, `tracked_count`,
    `clear`, `save_to_file`, `load_from_file`, `bucket_count`,
    `expire_old_transactions`,
    `estimate_high_priority` / `estimate_medium_priority` /
    `estimate_low_priority` (priority-based fallback).
  - Constants `min_samples = 10`, `max_samples_per_bucket = 1000`,
    `default_high_priority = 20.0`, `default_medium_priority = 10.0`,
    `default_low_priority = 1.0`, `default_max_tx_age = 14 days`,
    `min_confirm_target = 2`, `max_confirm_target = 1008`.

What camlcoin **does not** have (the W139 audit surface):

  - The three-pass `estimateSmartFee` algorithm
    (`max(halfEst, actualEst, doubleEst)`); camlcoin uses a single
    median-bucket walk with a horizon-selector.
  - `validForFeeEstimation` guard (no package, no bypass, current
    chainstate, no mempool parents).
  - `txHeight == nBestSeenHeight` guard on `track_transaction`
    (side-chain / reorg safety).
  - `processBlock` discard for `nBlockHeight <= nBestSeenHeight`
    (reorg / side-chain safety).
  - `MaxUsableEstimate()` (= `min(longMax, max(blockSpan,
    histSpan)/2)`); camlcoin never clamps the `blocks` response
    field against estimator coverage.
  - `firstRecordedHeight`, `historicalFirst`, `historicalBest`,
    `BlockSpan`, `HistoricalBlockSpan`, `OLDEST_ESTIMATE_HISTORY`,
    `trackedTxs`, `untrackedTxs` — the entire "how long has the
    estimator been running" book-keeping.
  - The `scale` factor in `TxConfirmStats::Record`
    (`periodsToConfirm = (blocksToConfirm + scale - 1) / scale`).
    `record_confirmation_horizon` records the raw block delta — so
    a 5-block confirmation lands in the **same** "period" as a
    1-block confirmation on the LONG horizon (which Core would
    bucket together as period 1).
  - The `unconfTxs[Y][X]` circular buffer (per-bucket per-block age
    counter) and `oldUnconfTxs[X]` overflow bucket.
    `total_unconfirmed` is the decayed scalar; the per-block
    circular tracking is absent.
  - `ClearCurrent(nBlockHeight)` — the per-block roll of the
    circular buffer; absent.
  - `confAvg[periods][buckets]` (2D) — camlcoin stores a flat
    `blocks_to_confirm: float list` per bucket; no period-indexed
    matrix.
  - `failAvg[periods][buckets]` (2D) — there is **no** failure
    moving-average per period; eviction decrements
    `total_unconfirmed` but never lands in any "failed within Y
    periods" counter.
  - `FlushUnconfirmed()` on shutdown — pending mempool entries are
    NOT recorded as failures before save.
  - `FlushFeeEstimates()` periodic flush every
    `FEE_FLUSH_INTERVAL` (1 hour); camlcoin only writes on
    shutdown.
  - `MAX_FILE_AGE` (60 hours) staleness gate at load time;
    `DEFAULT_ACCEPT_STALE_FEE_ESTIMATES = false` flag. Camlcoin
    accepts any-age save file.
  - `GetFeeEstimatorFileAge` — the file-mtime helper.
  - `CURRENT_FEES_FILE_VERSION = 309900` binary serialization.
    Camlcoin uses `OCaml Marshal` with `s_version = 1`.
  - The `fee_estimates.dat` filename. Camlcoin uses the same
    filename (`cli.ml:477`) — match.
  - `SyncWithValidationInterfaceQueue` call at the top of both
    RPCs — Core flushes pending validation events so the
    estimator's view is consistent with the chain tip before
    estimating.
  - `min_mempool_feerate` / `min_relay_feerate` clamping in
    `estimatesmartfee` — Core does
    `feeRate = max(feeRate, min_mempool_feerate, min_relay_feerate)`.
    Camlcoin emits the raw estimator output.
  - `estimate_mode` parameter parsing (`unset` /
    `economical` / `conservative` strings). The RPC silently drops
    the parameter (`| [`Int n] | [`Int n; _] ->` pattern).
  - `RPC_INVALID_PARAMETER` error on invalid `estimate_mode` —
    Core throws `Invalid estimate_mode parameter, must be one of:
    "unset", "economical", "conservative"`. Camlcoin: no error
    path even reachable.
  - `EstimateMedianVal` high→low traversal with bucket aggregation
    until `sufficientTxVal / (1 - decay)` is reached. Camlcoin's
    `search_up` walks low→high one bucket at a time and uses
    `min_samples=10` as an absolute floor.
  - `SUFFICIENT_FEETXS = 0.1` per-block average — camlcoin uses
    absolute `min_samples = 10`.
  - `SUFFICIENT_TXS_SHORT = 0.5` per-block average for the SHORT
    horizon — camlcoin uses the same `min_samples = 10` across all
    horizons.
  - `HALF_SUCCESS_PCT = 0.60`, `DOUBLE_SUCCESS_PCT = 0.95` — only
    `0.5` (Economical) and `0.85` (Conservative) are present.
  - `estimateRawFee` `errors` array on the bucket-not-found path
    — camlcoin emits errors only when *every* horizon fails to
    pass; per-horizon error reporting drifts from Core.
  - `FeeFilterRounder` `MakeFeeSet` from Core uses
    `min_incremental_fee` (DEFAULT_INCREMENTAL_RELAY_FEE = 1000
    sat/kvB); camlcoin's `make_fee_set` uses `min_relay_fee`
    (also 1000 sat/kvB) — same numeric default but semantically
    different (Core uses incremental relay fee, not min relay
    fee). The default fee-set is also fixed at process-start with
    `default_fee_set = FeeFilterRounder.make_fee_set 1000L`
    (`peer.ml:1939`) — it is never rebuilt when the mempool's
    rolling minimum changes.
  - `FeeFilterRounder` set is an `OCaml float array` — not a
    `std::set<double>`. Lookups use a binary search. Functionally
    equivalent, but the precomputed set is created once at module
    load and is never refreshed.
  - `CFeeRate(0)` sentinel for "no estimate" — camlcoin uses
    `Option<float>` (idiomatic) but the JSON shape diverges:
    Core's "no estimate" returns `{"errors": [...], "blocks": N}`
    *without* a `feerate` key. Camlcoin matches this shape (no
    `feerate` key on the `None` branch) — match.
  - `feeRate.GetFeePerK()` — Core's response is BTC/kvB derived
    from `GetFeePerK()` (which uses `FeeFrac::EvaluateFeeDown`
    — rounds DOWN). Camlcoin emits a float-divide by 100_000 of
    the raw `sat/vB` bucket boundary; rounding differs from Core's
    fee-fraction arithmetic but values are within 1 sat of Core
    for typical feerates.
  - `block_policy_estimator_args::FeeestPath(argsman)` —
    `data_dir/fee_estimates.dat`. Camlcoin uses the same path via
    `cli.ml:477` — match.

## 30-gate matrix (W139)

### G1-G5: Tracking lifecycle / wiring

- **G1: `validForFeeEstimation` guard absent at `track_transaction`.**
  Core (`block_policy_estimator.cpp:619`): only tracks txs that satisfy
  `!m_mempool_limit_bypassed && !m_submitted_in_package &&
  m_chainstate_is_current && m_has_no_mempool_parents`. Camlcoin
  (`fee_estimation.ml:200`): `track_transaction` accepts any tx
  unconditionally. The wired site in `cli.ml:1252-1261` filters on
  `fee_rate_sat_per_vb > 0.0` only — none of the four Core flags is
  consulted. **P0-CDIV (estimator pollution)**: package txs and reorg
  refills inflate confirmation counts at fee rates that wouldn't have
  been chosen by miners independently.

- **G2: `txHeight == nBestSeenHeight` guard absent.** Core
  (`block_policy_estimator.cpp:607`): if `txHeight != nBestSeenHeight`
  return — ignores side-chain / reorg txs and txs received while the
  estimator is lagging the chain tip. Camlcoin: `track_transaction`
  takes a height arg and writes it verbatim to `tracked_txs`. The
  caller in `cli.ml:1261` passes `Fee_estimation.current_height
  fee_estimator` (i.e., the estimator's *own* cached height, not the
  ActiveChain tip), so this check is implicitly always satisfied —
  but the *protection* the check is meant to provide (drop side-chain
  / reorg / lagging-sync txs) is absent. **P1**.

- **G3: `untrackedTxs` / `trackedTxs` counters absent.** Core
  (`block_policy_estimator.h:298-299`): two `unsigned int` counters
  populated by `processTransaction` and reset by `processBlock`.
  Used in `LogDebug` to report the estimator's view of how much
  mempool traffic is being included. Camlcoin: no such counters;
  the wired path in `cli.ml:1259` always calls `track_transaction`
  on success — there is no "skipped because validForFeeEstimation"
  log line. **P3 (observability drift)**.

- **G4: `processBlock` discards `nBlockHeight <= nBestSeenHeight`.**
  Core (`block_policy_estimator.cpp:673-680`): explicit reorg /
  side-chain check before updating any state. Camlcoin
  (`fee_estimation.ml:278-285`): unconditionally sets
  `est.block_height <- height` and decays. A reorg-then-replay or
  a duplicate-process call (e.g., the same block processed via the
  IBD path and again via the P2P block-relay path) would
  double-decay the entire estimator. **P0-CDIV (reorg corruption)**.

- **G5: `processBlock` updates `nBestSeenHeight` BEFORE
  `removeTx`/`processBlockTx` so `removeTx` sees the correct height
  for stale-mempool-tx detection.** Core
  (`block_policy_estimator.cpp:685-702`): the sequence is
  `nBestSeenHeight = nBlockHeight` → `ClearCurrent` → decay →
  per-tx record. Camlcoin (`fee_estimation.ml:278-284`): `est
  .block_height <- height` → `apply_decay` → `record_confirmation`.
  The order is correct, but `ClearCurrent` (G14) is missing
  entirely. **Match** on the ordering, but the missing
  `ClearCurrent` makes the order irrelevant.

### G6-G10: Three-pass estimator + thresholds

- **G6: three-pass `estimateSmartFee`.** Core
  (`block_policy_estimator.cpp:871-955`): computes
  `halfEst = estimateCombinedFee(target/2, HALF_SUCCESS_PCT=0.60,
  checkShorterHorizon=true)`,
  `actualEst = estimateCombinedFee(target, SUCCESS_PCT=0.85,
  checkShorterHorizon=true)`,
  `doubleEst = estimateCombinedFee(2*target, DOUBLE_SUCCESS_PCT=0.95,
  checkShorterHorizon=!conservative)`. Returns the max of the three,
  with reason tag `HALF_ESTIMATE` / `FULL_ESTIMATE` /
  `DOUBLE_ESTIMATE` / `CONSERVATIVE`. Camlcoin
  (`fee_estimation.ml:316-348`): single-pass percentile search
  (`0.5` for Economical, `0.85` for Conservative). No HALF /
  DOUBLE estimate. **P0-CDIV**: the result can be lower than Core's
  for the same data because the DOUBLE leg (95% at 2×target on a
  longer-horizon) is never consulted; an "economical" estimate in
  camlcoin can be materially below what Core would return.

- **G7: `HALF_SUCCESS_PCT = 0.60` constant absent.** Core
  (`block_policy_estimator.h:170`). Camlcoin: only `0.5`
  (Economical) and `0.85` (Conservative). **P1** — depends on G6.

- **G8: `DOUBLE_SUCCESS_PCT = 0.95` constant absent.** Core
  (`block_policy_estimator.h:174`). Camlcoin: only `0.5` and
  `0.85`. **P1** — depends on G6.

- **G9: `SUFFICIENT_FEETXS = 0.1 per block` floor absent.** Core
  (`block_policy_estimator.h:177`): the bucket-aggregation loop in
  `EstimateMedianVal` keeps combining buckets until
  `partialNum >= sufficientTxVal / (1 - decay)`. With
  `decay=.9952` (MED) and `sufficientTxVal=0.1`, the threshold is
  `0.1 / 0.0048 ≈ 20.83` — i.e., ~21 weighted tx-equivalents
  across the bucket-range. Camlcoin: hardcoded `min_samples = 10`
  as an absolute floor on a single bucket; no aggregation across
  buckets; no `1/(1-decay)` scaling. **P0-CDIV**: a fee-rate range
  with sparse data is reported as "no estimate" by Core but as a
  confident estimate (or vice versa) by camlcoin.

- **G10: `SUFFICIENT_TXS_SHORT = 0.5 per block` for SHORT horizon
  absent.** Core (`block_policy_estimator.h:179`): used by
  `estimateCombinedFee` only when the SHORT horizon is consulted
  (block_policy_estimator.cpp:730-735). Camlcoin: identical
  `min_samples = 10` for all three horizons. **P1** — depends on
  G9.

### G11-G15: TxConfirmStats data structures

- **G11: `scale` factor in `Record()` absent.** Core
  (`block_policy_estimator.cpp:217-229`):
  `periodsToConfirm = (blocksToConfirm + scale - 1) / scale`,
  then increments `confAvg[i - 1][bucket]` for `i = periodsToConfirm
  .. confAvg.size()`. With LONG_SCALE=24, a 5-block confirmation
  lands in `(5+23)/24 = 1` so it counts toward periods 1..42
  (all rows). Camlcoin (`fee_estimation.ml:213-222`): records the
  raw block-count in `blocks_to_confirm: float list` — no period
  bucketing. The LONG horizon stores 1008 individual block-grain
  samples instead of 42 24-block period-grain rows. **P1
  (structure)**.

- **G12: `confAvg[periods][buckets]` 2D matrix absent.** Core
  (`block_policy_estimator.cpp:90-92`): exponential moving average
  of "txs confirmed within Y or fewer periods" per bucket.
  Camlcoin: flat `blocks_to_confirm: float list` per bucket, no
  per-period rollup. **P1**.

- **G13: `failAvg[periods][buckets]` 2D matrix absent.** Core
  (`block_policy_estimator.cpp:96`): exponential moving average of
  "txs that left mempool unconfirmed after Y periods". Decayed
  in lock-step with `confAvg` in `UpdateMovingAverages` (line
  236-238). Camlcoin: no per-period failure tracking;
  `record_eviction` decrements `total_unconfirmed` but never
  populates a "failed within N periods" counter — the eviction is
  lost. **P0-CDIV (estimator over-confidence)**: a bucket with 100
  evictions and 10 confirmations is reported by Core as
  10/(10+100)=9% success, but by camlcoin as 100% success because
  failures evaporate. Camlcoin's `compute_percentile` only sees
  the success samples.

- **G14: `unconfTxs[Y][buckets]` circular buffer absent.** Core
  (`block_policy_estimator.cpp:113-114`): per-bucket per-block-age
  counter rolled by `ClearCurrent` once per block. Used by
  `EstimateMedianVal` (line 290-291) to count "still in mempool
  for confTarget or longer" — the `inMempool` field of the result.
  Camlcoin: `total_unconfirmed` scalar (decayed in
  `apply_decay_horizon`) used as a proxy; no circular buffer.
  **P0-CDIV (estimaterawfee `inmempool` field)**.

- **G15: `oldUnconfTxs[buckets]` overflow bucket absent.** Core
  (`block_policy_estimator.cpp:115`): catches txs that have aged
  past `GetMaxConfirms()`. Used by both `removeTx` (when
  `blocksAgo >= unconfTxs.size()`) and `EstimateMedianVal` (line
  292). Camlcoin: absent. **P1**.

### G16-G20: Lifecycle / persistence

- **G16: `FlushUnconfirmed` on shutdown absent.** Core
  (`block_policy_estimator.cpp:1064-1076`): iterates
  `mapMemPoolTxs` and calls `_removeTx(_, false)` so each pending
  tx is recorded as a failure before the file is written.
  Without this, restart-then-estimate over-counts the success
  rate because the unconfirmed txs in
  `mapMemPoolTxs` were "still waiting" when the estimator quit,
  not "successfully confirmed". Camlcoin (`fee_estimation.ml:514-
  531` `save_to_file`): marshals `tracked_txs` as-is.
  `record_eviction` is not invoked on the still-tracked entries
  before the save. **P0-CDIV (estimator over-confidence at
  restart)**.

- **G17: `FlushFeeEstimates` periodic 1-hour flush absent.** Core
  (`block_policy_estimator.h:26`): `FEE_FLUSH_INTERVAL = 1 hour`.
  Run via `node/kernel_notifications.cpp` scheduler. Camlcoin: no
  scheduler hook; `Fee_estimation.save_to_file` is only invoked at
  shutdown (`cli.ml:1671`). **P2 (data loss on crash)**: a crash
  between checkpoints loses up to "as long as the node has run"
  worth of fee-estimation data — Core loses at most 1 hour.

- **G18: `MAX_FILE_AGE` (60 hours) gate at load absent.** Core
  (`block_policy_estimator.h:32`): `MAX_FILE_AGE = 60 hours`. If
  the file is older than that AND `DEFAULT_ACCEPT_STALE_FEE_ESTIMATES`
  (false by default) is not overridden, the file is NOT loaded —
  estimator starts empty rather than serving stale data.
  Camlcoin (`fee_estimation.ml:533-554` `load_from_file`): no age
  check; any-age file is loaded. **P1**: a long-stopped node
  resumes serving 6-month-old estimates as if they were current.

- **G19: `CURRENT_FEES_FILE_VERSION = 309900` binary format absent.**
  Core (`block_policy_estimator.cpp:37`): writes the int32 version
  as the first field of `fee_estimates.dat`, then `nBestSeenHeight`,
  then `firstRecordedHeight` / `nBestSeenHeight` (or `historicalFirst
  / historicalBest`), then `VectorFormatter<EncodedDoubleFormatter>`
  buckets, then three `TxConfirmStats::Write` blobs. Camlcoin
  (`fee_estimation.ml:514-531`): uses `OCaml Marshal` with
  `s_version = 1`. Completely incompatible file format — a Core
  `fee_estimates.dat` cannot be loaded by camlcoin and vice versa.
  This was previously documented in the W114 KNOWN GAPS comment.
  **P1**: cross-impl data portability absent.

- **G20: `firstRecordedHeight`, `historicalFirst`, `historicalBest`,
  `BlockSpan`, `HistoricalBlockSpan`, `OLDEST_ESTIMATE_HISTORY`
  bookkeeping absent.** Core
  (`block_policy_estimator.h:279-281`, `.cpp:780-802`): used by
  `MaxUsableEstimate()` to clamp the response `blocks` field
  against estimator coverage. Camlcoin: none of these fields
  exist; `handle_estimatesmartfee` always returns the requested
  `conf_target` as `blocks` (rpc.ml:1646). **P0-CDIV (RPC shape)**:
  `blocks` lies about the actual target used.

### G21-G25: RPC behaviour

- **G21: `estimatesmartfee` `estimate_mode` parameter dropped.**
  Core (`rpc/fees.cpp:63-94`): the second param is the
  `estimate_mode` string, parsed by `FeeModeFromString`; passes
  `conservative = (mode == CONSERVATIVE)` to `estimateSmartFee`.
  Camlcoin (`rpc.ml:1639-1641`): pattern is
  `| [`Int conf_target] | [`Int conf_target; _]`. The second
  element is bound to wildcard and never inspected.
  `Fee_estimation.estimate_fee` is called without `~mode`, so it
  defaults to `Economical` (`fee_estimation.ml:316`). Conservative
  mode is unreachable through the RPC. **P0-CDIV (silent
  parameter loss)**.

- **G22: `Invalid estimate_mode` error path absent.** Core
  (`rpc/fees.cpp:74`): throws `RPC_INVALID_PARAMETER` with the
  exact message `Invalid estimate_mode parameter, must be one of:
  "unset", "economical", "conservative"`. Camlcoin: not reachable
  (G21). A client submitting `estimatesmartfee 6 "garbage"` gets
  a successful estimate instead of an error. **P1**.

- **G23: `min_mempool_feerate` / `min_relay_feerate` clamp on the
  response absent.** Core (`rpc/fees.cpp:82-86`):
  `feeRate = std::max({feeRate, min_mempool_feerate,
  min_relay_feerate})`. The clamp prevents estimatesmartfee from
  ever suggesting a feerate the node would not relay. Camlcoin
  (`rpc.ml:1644-1647`): emits `rate /. 100_000.0` raw. With
  `min_relay_fee = 1000 sat/kvB = 0.01 BTC/kvB`, camlcoin can emit
  any value the estimator returns, including 0.00001 BTC/kvB —
  below the relay floor. **P0-CDIV**: the suggested feerate
  cannot actually be relayed by the node.

- **G24: `SyncWithValidationInterfaceQueue` flush absent.** Core
  (`rpc/fees.cpp:69, 157`): both RPCs flush pending validation
  events before computing the estimate, so a block that just
  arrived is reflected in the estimator. Camlcoin: no validation
  queue (the estimator is updated synchronously in `cli.ml`), so
  this is technically a non-issue — but the underlying invariant
  ("the estimator's view matches the chain tip") is also not
  documented or asserted anywhere. **P3 (architectural drift)**.

- **G25: `estimaterawfee.errors` array shape drift on the failed-
  horizon path.** Core (`rpc/fees.cpp:204-210`): on the
  no-pass-bucket path emits `decay`, `scale`, `fail` bucket, and
  `errors`; omits `pass`. Camlcoin (`rpc.ml:1728-1734`): emits
  `decay`, `scale`, `fail`, `errors` — matches **as long as
  pass_idx < 0**, but the `fail` shape always has all six fields
  (`startrange`, `endrange`, `withintarget`, `totalconfirmed`,
  `inmempool`, `leftmempool`) including `leftmempool=0.0`
  hardcoded — and `inmempool` is the decayed `total_unconfirmed`
  scalar, not Core's per-bucket live count. The shape is close to
  Core's but the values are wrong (G13 / G14). **P3 (shape close,
  values wrong)**.

### G26-G30: FeeFilterRounder + adjacent

- **G26: `FeeFilterRounder` `min_incremental_fee` vs `min_relay_fee`
  semantic drift.** Core (`block_policy_estimator.cpp:1086`):
  `MakeFeeSet(min_incremental_fee, MAX_FILTER_FEERATE,
  FEE_FILTER_SPACING)` where `min_incremental_fee` is the wallet's
  `DEFAULT_INCREMENTAL_RELAY_FEE` (1000 sat/kvB by default, but
  configurable via `-incrementalrelayfee`). Camlcoin
  (`peer.ml:1904-1912`): `make_fee_set min_relay_fee` is called
  with the mempool's `min_relay_fee`. Numerically the same in the
  default config (both default 1000 sat/kvB) but semantically
  different — there is no `-incrementalrelayfee` plumbing.
  **P3 (semantic drift)**.

- **G27: `FeeFilterRounder` set is built ONCE at module load and
  never refreshed.** Core (`net_processing.cpp:5851-5862`):
  `m_fee_filter_rounder` is constructed once but its
  `MakeFeeSet` uses the live `m_mempool.m_opts.min_relay_feerate`
  at construction; the constant doesn't change at runtime in Core
  either. Camlcoin (`peer.ml:1939`): `default_fee_set =
  FeeFilterRounder.make_fee_set 1000L` is a top-level binding
  evaluated at module init. **Match** — Core also fixes this at
  construction; not a bug. **Pin as INV**.

- **G28: `MAX_FILTER_FEERATE` exposed in module interface.** Core
  (`block_policy_estimator.h:326`): `MAX_FILTER_FEERATE = 1e7`
  (sat/kvB). Camlcoin (`peer.ml:1900`): `max_filter_feerate =
  10_000_000L` — match. **Pin as INV**.

- **G29: `FeeFilterRounder.round` returns float-rounded `int64`.**
  Core (`block_policy_estimator.cpp:1117`): returns
  `static_cast<CAmount>(*it)` — direct cast of double to int64,
  which truncates fractional satoshis toward zero. Camlcoin
  (`peer.ml:1935`): `Int64.of_float fee_set.(final_idx)` — same
  semantics (`Int64.of_float` truncates toward zero). **Match**.

- **G30: `FeeFilterRounder.round` randomization probabilities.**
  Core (`block_policy_estimator.cpp:1115`):
  `(insecure_rand.rand32() % 3 != 0)` → 66.67% round-down,
  33.33% round-up. Camlcoin (`peer.ml:1932`):
  `csprng_int_range 3 <> 0` → 66.67% round-down, 33.33%
  round-up. **Match** in distribution; **mismatch in RNG type**:
  Core uses an `insecure_rand` (FastRandomContext, ChaCha20)
  intentionally pre-seeded once per `FeeFilterRounder` construction
  (so consecutive calls share a stream; lighter weight). Camlcoin
  uses a fresh `/dev/urandom` draw for every call (`csprng_int_range`).
  Functionally equivalent — both unpredictable to peers — but
  camlcoin pays a syscall per round. **P2 (perf)**: at high peer
  count + feefilter cadence, the per-call `/dev/urandom` read is
  measurable.

## Universal patterns surfaced (cross-impl candidates)

- **"`validForFeeEstimation` guard absent fleet-wide"** — G1.
  This guard is subtle: it requires the impl to thread four
  separate flags (`m_mempool_limit_bypassed`,
  `m_submitted_in_package`, `m_chainstate_is_current`,
  `m_has_no_mempool_parents`) from `accept_to_memory_pool` /
  `package_submit` into the fee-estimator. Any impl that wires
  `track_transaction` directly to `accept_to_memory_pool` success
  (without these four flags) has the same gap. Worth a fleet
  sweep: grep for `track_transaction` callers and check whether
  they consult package / bypass / chainstate-current state.

- **"`failAvg` per-period tracking absent fleet-wide"** — G13.
  Bitcoin Core's failure tracking is structurally separate from
  success tracking; impls that only have a "samples confirmed in N
  blocks" list (no parallel "samples evicted after N blocks" list)
  will report inflated success rates after sustained
  mempool-eviction events. Worth a fleet sweep.

- **"`FlushUnconfirmed` on shutdown absent fleet-wide"** — G16.
  Closely related to G13: even an impl that tracks failures only
  records them on actual eviction, never on shutdown. So a node
  with 5000 unconfirmed pending txs at shutdown reports them as
  successes on next startup. Easy unit test: track-N, save,
  load, observe success rate. Worth a fleet sweep.

- **"`estimate_mode` parameter dropped"** — G21. The Yojson
  pattern-match in camlcoin is a tell: `| [`Int t] | [`Int t; _]
  ->` is a wildcard that swallows the second param. Easy fleet
  sweep: every impl with a regex-style RPC handler that doesn't
  named-parse the second positional param has the same gap.

- **"min-relay clamp on RPC fee estimate absent"** — G23. Core
  explicitly clamps the response feerate against the mempool's
  rolling min and the node's min relay fee. Any impl that returns
  the raw estimator output without clamping will recommend feerates
  the node itself wouldn't accept.

- **"file format incompatibility"** — G19. Two impls writing
  different `fee_estimates.dat` formats (one Core-style binary,
  one OCaml Marshal / Bincode / Pickle / etc.) means consensus-
  invariant data cannot be shared across the fleet. Worth a fleet
  sweep against Core's `309900` binary format.

- **"3-pass estimator algorithm absent fleet-wide"** — G6. The
  three-leg algorithm is the *defining* feature of
  `estimateSmartFee`. Impls with single-pass percentile search
  emit different estimates than Core on the same data. Fleet
  sweep: search for `HALF_SUCCESS_PCT` / `DOUBLE_SUCCESS_PCT`
  constants (0.60 / 0.95) — absence indicates the three-pass
  algorithm isn't implemented.

- **"`MaxUsableEstimate` clamp on `blocks` field absent"** — G20.
  Even when the estimator can't reach the requested target, Core
  honestly reports the clamped target. Impls without
  `BlockSpan`/`HistoricalBlockSpan` book-keeping echo the
  requested target unconditionally — clients can't tell whether
  the estimate is "real" or "best we could do with thin data".

## BUG catalogue (NEW in W139)

| ID | Sev | Gate | Description |
|---|---|---|---|
| BUG-W139-1 | P0-CDIV | G1 | `track_transaction` lacks `validForFeeEstimation` guard. Package txs, reorg refills, lagging-sync txs all enter the estimator unfiltered. `fee_estimation.ml:200`, wired in `cli.ml:1252-1261`. |
| BUG-W139-2 | P0-CDIV | G4 | `process_block` does not discard `nBlockHeight <= nBestSeenHeight`. A duplicate-process call (same block via two paths) double-decays the estimator. `fee_estimation.ml:278-285`. |
| BUG-W139-3 | P0-CDIV | G6 | Three-pass `estimateSmartFee` algorithm (`max(half@target/2 @ 60%, full@target @ 85%, double@2*target @ 95%)`) absent. Camlcoin uses single-pass median (or 85th percentile in Conservative). `fee_estimation.ml:316-348`. |
| BUG-W139-4 | P0-CDIV | G9 / G11 | `SUFFICIENT_FEETXS = 0.1 per block / (1-decay)` aggregation threshold absent. Uses absolute `min_samples = 10` floor on a single bucket — no bucket aggregation. `fee_estimation.ml:86, 326-348`. |
| BUG-W139-5 | P0-CDIV | G13 | `failAvg[periods][buckets]` matrix absent. `record_eviction` decrements `total_unconfirmed` but does not increment any "failed within Y periods" counter. Eviction is invisible to subsequent estimates. `fee_estimation.ml:240-252`. |
| BUG-W139-6 | P0-CDIV | G14 | `unconfTxs[Y][buckets]` circular buffer + `ClearCurrent` per-block roll absent. `estimaterawfee.inmempool` reports the decayed scalar `total_unconfirmed`, not Core's live count. `fee_estimation.ml:43-48, 213-222`. |
| BUG-W139-7 | P0-CDIV | G16 | `FlushUnconfirmed` on shutdown absent. Pending tracked txs at quit time are marshaled as-is; on next startup they look like "still confirming" (success-biased) instead of "left unconfirmed" (failed). `fee_estimation.ml:514-531`. |
| BUG-W139-8 | P0-CDIV | G20 | `MaxUsableEstimate` clamp absent. `handle_estimatesmartfee` always echoes the requested `conf_target` as `blocks`. Clients can't distinguish "real answer at target N" from "best we could do, N is fictional". `rpc.ml:1644-1647`. |
| BUG-W139-9 | P0-CDIV | G21 | `estimate_mode` second parameter is silently dropped (`| [`Int t] | [`Int t; _]`). Conservative mode unreachable via RPC. `rpc.ml:1639-1641`. |
| BUG-W139-10 | P0-CDIV | G23 | No `min_mempool_feerate` / `min_relay_feerate` clamp on the returned `feerate` field. Camlcoin can recommend feerates the node itself won't relay. `rpc.ml:1644-1647`. |
| BUG-W139-11 | P1 | G2 | `txHeight == nBestSeenHeight` reorg/side-chain guard absent. Currently masked by caller passing estimator's own height, but the protection is absent. `fee_estimation.ml:200-211`. |
| BUG-W139-12 | P1 | G7 | `HALF_SUCCESS_PCT = 0.60` constant absent. Only `0.5` (Economical) and `0.85` (Conservative). `fee_estimation.ml:321-324`. |
| BUG-W139-13 | P1 | G8 | `DOUBLE_SUCCESS_PCT = 0.95` constant absent. `fee_estimation.ml:321-324`. |
| BUG-W139-14 | P1 | G10 | `SUFFICIENT_TXS_SHORT = 0.5` (SHORT-horizon stricter threshold) absent. Same `min_samples=10` applied across all horizons. `fee_estimation.ml:86, 326-348`. |
| BUG-W139-15 | P1 | G11 | `scale` factor in `Record` not used: `record_confirmation_horizon` stores raw block counts in `blocks_to_confirm`. LONG horizon stores 1008 block-grain samples instead of 42 period-grain rows. `fee_estimation.ml:213-222`. |
| BUG-W139-16 | P1 | G12 | `confAvg[periods][buckets]` 2D matrix absent. Flat `blocks_to_confirm: float list` used per bucket. `fee_estimation.ml:43-48`. |
| BUG-W139-17 | P1 | G15 | `oldUnconfTxs[buckets]` overflow bucket absent. `fee_estimation.ml:43-48`. |
| BUG-W139-18 | P1 | G18 | `MAX_FILE_AGE` (60 hours) gate on load absent. Any-age file is loaded without check. `fee_estimation.ml:533-554`. |
| BUG-W139-19 | P1 | G19 | `fee_estimates.dat` file format is OCaml Marshal `s_version=1`, not Core's binary `CURRENT_FEES_FILE_VERSION=309900`. Cross-impl data portability absent. `fee_estimation.ml:472-554`. |
| BUG-W139-20 | P1 | G20 | `firstRecordedHeight`, `historicalFirst`, `historicalBest`, `BlockSpan`, `HistoricalBlockSpan`, `OLDEST_ESTIMATE_HISTORY`, `trackedTxs`, `untrackedTxs` book-keeping fields absent. `fee_estimation.ml:71-79`. |
| BUG-W139-21 | P1 | G22 | `Invalid estimate_mode parameter` error path absent. A client submitting `estimatesmartfee 6 "garbage"` gets a successful estimate instead of an error. `rpc.ml:1639-1641`. |
| BUG-W139-22 | P2 | G17 | `FEE_FLUSH_INTERVAL` periodic 1-hour flush absent. Save-on-shutdown only — a crash loses up to "node runtime" worth of fee-estimation data. `cli.ml:1671`. |
| BUG-W139-23 | P2 | G30 | `FeeFilterRounder.round` calls `csprng_int_range 3` (per-call `/dev/urandom` read). Core uses a single pre-seeded `FastRandomContext`. Each round = 1 syscall; high-peer + feefilter cadence is observable. `peer.ml:1932`. |
| BUG-W139-24 | P2 | G16 | Even without `FlushUnconfirmed`, `tracked_txs` grows unbounded across shutdown/load cycles when `record_eviction` is never invoked for txs that disappear out-of-band. `fee_estimation.ml:71-79`. |
| BUG-W139-25 | P3 | G3 | `trackedTxs` / `untrackedTxs` counters absent; estimator can't report "how many tx admissions were accepted vs filtered". `cli.ml:1252-1261` always tracks if `fee_rate > 0`. |
| BUG-W139-26 | P3 | G24 | `SyncWithValidationInterfaceQueue` flush at top of both RPCs absent — the underlying invariant ("estimator view matches chain tip") is undocumented and unasserted. `rpc.ml:1637, 1751`. |
| BUG-W139-27 | P3 | G25 | `estimaterawfee` per-horizon `errors` array shape close to Core, but `inmempool` (decayed scalar) and `leftmempool` (hardcoded `0.0`) values diverge. `rpc.ml:1716-1717`. |
| BUG-W139-28 | P3 | G26 | `FeeFilterRounder.make_fee_set` consumes `min_relay_fee` not `min_incremental_fee`; numerically same in default config but semantically different. `peer.ml:1904-1912`. |
| BUG-W139-29 | P3 | G27 | `default_fee_set` evaluated once at module load with hardcoded `1000L` — no plumb-through to the actual configured `-minrelaytxfee` value. Match with Core's "construct once" pattern (so NOT a bug), but the hardcoded `1000L` instead of `Mempool.default_min_relay_fee` is a literal-vs-named-constant drift. `peer.ml:1939`. |
| BUG-W139-30 | P3 | G5 | `processBlock` orders height-update BEFORE decay (Core line 685-695), but `ClearCurrent` (G14) is missing entirely. The correct ordering is irrelevant because the structure it orders is absent. `fee_estimation.ml:278-285`. |

Total **NEW in W139**: **30 BUGs** (10 P0-CDIV, 11 P1, 3 P2, 6 P3).

## What camlcoin gets RIGHT (regression-pin notes)

A discovery audit should also pin the working pieces so future fix
waves don't accidentally regress them:

- **W114 BUG-1 (SHORT_DECAY = 0.962)**: pinned by the existing
  `test_g1_short_decay` test in `test_w114_fee_estimation.ml` —
  W139 re-pins via `test_inv1_short_decay_value`.
- **W114 BUG-2 (MED_DECAY = 0.9952)**: same — re-pinned via INV-2.
- **W114 BUG-3 (MIN_BUCKET_FEERATE = 0.1 sat/vB)**: same — re-pinned
  via INV-3.
- **W114 BUG-4 (estimaterawfee `scale` = 1/2/24)**: re-pinned via INV-4.
- **W114 BUG-5 (`min_confirm_target = 2`)**: re-pinned via INV-5.
- **FIX-47 (`track_transaction` wired via `cli.ml` admission path)**:
  re-pinned via INV-6.
- **FIX-47 (`record_eviction` wired via `mempool.on_eviction` hook)**:
  re-pinned via INV-7.
- **FIX-49 (FeeFilterRounder CSPRNG)**: re-pinned via INV-8.
- **FEE_SPACING = 1.05**: bucket-boundary ratio between consecutive
  buckets — re-pinned via INV-9.
- **LONG_DECAY = 0.99931, max_target 1008**: re-pinned via INV-10.

## Verification

`test/test_w139_fee_estimation.ml` — 30 gate tests across the 6
G-bands (tracking lifecycle, three-pass + thresholds, TxConfirmStats
structures, lifecycle/persistence, RPC behaviour, FeeFilterRounder)
plus 10 INV pins. Discovery-only; each test documents the gap and
serves as a regression-pin for the current behaviour. The "working"
pieces above are pinned with INV-N tests so a future fix wave can't
accidentally regress them.

camlcoin gotcha (per FIX-80 / FIX-77 / W133 audit pattern): if
`dune runtest` stalls, run the pre-built
`_build/default/test/test_w139_fee_estimation.exe` directly.

## Out of scope (for future waves)

- Closure of any BUG above; this audit is discovery-only.
- BIP-133 P2P feefilter wire protocol (covered by W118 / W120).
- `sendrawtransaction` `maxfeerate` parameter (covered by W125 /
  W135).
- `bumpfee` / `psbtbumpfee` RPC fee-bumping (covered by W137 /
  W130).
- Coin selection fee calculation in `walletcreatefundedpsbt`
  (covered by W113 / W129).
- Mempool min-fee floor computation (covered by W120 / W106).
- Network-message fee-rate signaling (`feefilter` msg) — covered by
  W117 BIP-155 networks audit and W120 RBF wave.
- The `sat/vB` vs `BTC/kvB` representation drift across the
  fee_estimation / mempool / wallet boundary; this audit treats the
  units as correct because Bitcoin's RPC ABI is BTC/kvB throughout
  and the conversion is straightforward sat/vB → BTC/kvB (divide
  by 100_000).
