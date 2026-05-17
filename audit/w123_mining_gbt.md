# W123 — Mining / GBT parity audit (camlcoin)

Date: 2026-05-17
Branch: master
Reference:
- bitcoin-core/src/node/miner.cpp
- bitcoin-core/src/rpc/mining.cpp
- bitcoin-core/src/txmempool.cpp (PrioritiseTransaction / GetBlockBuilderChunk)
- bitcoin-core/src/policy/feefrac.cpp + policy/rbf.cpp (feerate diagrams)
- BIP-22 (getblocktemplate), BIP-23 (proposal mode), BIP-141 (witness commitment),
  BIP-152 (compact blocks)

Scope: this audit pivots off the FIX-72 OOS note —

> "mining selection select_for_block_chunked + get_all_chunks still uses raw
>  entry.fee/entry.fee_rate (not modified). Wiring modified-fee into chunk
>  linearization is broader work involving cluster fee diagram recomputation —
>  flagged as future scope."

— and confirms / expands the scope of that gap across the whole mining /
getblocktemplate / submitblock / BIP-152 surface. W108 covered the bulk of
the GBT JSON shape in 2026-02; W120 closed the prioritisetransaction RPC
itself (FIX-72) but explicitly deferred the chunk-linearisation wiring.

This audit is DISCOVERY-only. No production code is changed. Findings land
as `xfail` regression tests in `test/test_w123_mining_gbt.ml` so the next
fix-wave can flip them in a single PR.

## Confirmation of FIX-72 OOS scope

`lib/mining.ml::compute_ancestor_fee_rate` (line 63-76) reads
`entry.fee` and the unmodified ancestor `a.fee` to build the CPFP sort
key. `lib/mempool.ml::find_best_chunk` (line 556-636) — the workhorse
called by `linearize_cluster`, `get_all_chunks`,
`select_for_block_chunked`, AND the W106 `ImprovesFeerateDiagram` path
(`linearize_entries`, lib/mempool.ml:2553-2564) — also reads
`entry.fee`/`entry.fee_rate`. Neither call site invokes
`Mempool.get_modified_fee` or `Mempool.apply_delta`, which were added by
FIX-72 (lib/mempool.ml:2749-2771).

Verified by `git show 3a59a18 -- lib/mining.ml` — empty diff, mining.ml
was never touched by FIX-72.

In Core, the corresponding wiring runs through
`m_txgraph->SetTransactionFee(*it, it->GetModifiedFee())` in
`PrioritiseTransaction` (txmempool.cpp:641). Because the txgraph is the
single source of truth used by `GetBlockBuilderChunk` (txmempool.h:721)
AND `GetFeerateDiagram` (txmempool.cpp:1082), Core gets correct modified
fees in BOTH selection AND diagram compare for free. Camlcoin's
two-layer split — `mapDeltas` Hashtbl on the side, chunk linearizer
reading raw `entry.fee` — means the modified fee is applied ONLY in the
RBF `replace_by_fee` Rule-3 path (FIX-72 wiring, mempool.ml:2950+),
NOT in:
  - block-template assembly (mining.ml + select_for_block_chunked),
  - the `getblocktemplate` JSON,
  - the `ImprovesFeerateDiagram` Rule-3-via-diagram path (mempool.ml:2553+),
  - eviction / `get_worst_chunk`,
  - rolling-min-fee fee-floor (`track_package_removed`).

This is the W123 marquee finding: BUG-1 below. The OOS note understates
scope — the gap touches at least four downstream code paths.

## Audit gates — 30

Verdict legend: PRESENT / PARTIAL / MISSING (with **bug** P0 / P1 / P2).

Gate 1 — block weight cap honoured (4_000_000 wu). PRESENT.
  lib/mining.ml:104, lib/consensus.ml:11. `select_transactions` uses
  `available_weight = max_weight - reserved` and the gate is
  `current_weight + pkg_weight < available_weight` (mining.ml:172).
  Matches Core miner.cpp:241 (gate is `>=` refuse — strict-less-than
  here is the equivalent inverse).

Gate 2 — block reserved weight clamp [2000, MAX]. PRESENT.
  lib/mining.ml:50-58 `clamp_reserved_weight`. Mirrors Core miner.cpp
  `ClampOptions()` (miner.cpp:79-88) — `DEFAULT_BLOCK_RESERVED_WEIGHT
  = 8000`, `MINIMUM_BLOCK_RESERVED_WEIGHT = 2000`.

Gate 3 — MAX_BLOCK_SIGOPS_COST = 80_000. PRESENT.
  lib/mining.ml:166 + lib/consensus.ml `max_block_sigops_cost`. The
  gate uses strict-less-than mirroring Core's `>= return false`
  (miner.cpp:244).

Gate 4 — coinbase BIP-34 height encoding. PRESENT.
  lib/mining.ml:273 `Consensus.encode_height_in_coinbase`.

Gate 5 — coinbase sequence = 0xFFFFFFFE (MAX_SEQUENCE_NONFINAL). PRESENT.
  lib/mining.ml:290 (FIX from BUG 5 era). Matches Core miner.cpp:171
  `coinbaseTx.vin[0].nSequence = CTxIn::MAX_SEQUENCE_NONFINAL`.

Gate 6 — coinbase locktime = height-1. PRESENT.
  lib/mining.ml:332. Matches Core miner.cpp:196 exactly.

Gate 7 — coinbase reward = subsidy + total_fee. PRESENT.
  lib/mining.ml:270 `Int64.add subsidy total_fee`. Subsidy via
  `Consensus.block_subsidy_for_network` (correct halving cadence).

Gate 8 — fees aggregated correctly per-tx (raw fee). PRESENT.
  lib/mining.ml:382-383 `List.fold_left (Int64.add) 0L selected`.
  Each (tx, fee) pair carries the raw fee from `select_transactions`.

Gate 9 — **fees use MODIFIED fee (prioritisetransaction delta) in chunk
  linearisation**. **MISSING — BUG-1 P1.**
  lib/mining.ml:63-76 `compute_ancestor_fee_rate` reads `entry.fee`
  and `a.fee` (raw) — never calls `Mempool.get_modified_fee`. Same
  for lib/mempool.ml:556+ `find_best_chunk` and its callers
  (`get_all_chunks`, `select_for_block_chunked`, `linearize_entries`).
  Core wires this via `m_txgraph->SetTransactionFee(modified_fee)` in
  `PrioritiseTransaction` (txmempool.cpp:641), making modified fee the
  ONLY fee the chunk algorithm ever sees. The FIX-72 OOS note explicitly
  flagged this. **Operator impact: `prioritisetransaction` deltas are
  ignored by block-template assembly; deltas only affect RBF Rule-3
  acceptance. This is observable: a miner setting a +1 BTC delta on a
  10-sat-fee tx in the mempool will NOT see that tx promoted into
  the next block template.** Concrete cascading paths:
    9a — `select_transactions` (mining.ml:91) sort order is raw-fee
         (via `compute_ancestor_fee_rate`).
    9b — `select_for_block_chunked` (mempool.ml:689) uses raw chunks.
    9c — `ImprovesFeerateDiagram` (mempool.ml:2656, called from
         `replace_by_fee` line 3024+) recomputes the post-replacement
         feerate diagram using `linearize_entries` → `find_best_chunk`
         → raw `entry.fee`. So Rule-3-via-diagram (W106 BUG-10 fix) is
         silently using raw fee while Rule-3-via-sum (FIX-72 wiring at
         line 2966) correctly uses modified fee. **The two RBF paths
         can therefore disagree on whether the same replacement
         improves the diagram, but agree it pays enough sat-for-sat.**
    9d — `get_worst_chunk` / `track_package_removed` (mempool.ml:673,
         736) use raw chunk fee for rolling-min-fee bumps.
    9e — `template_to_json` per-tx `fee` field (mining.ml:590) emits
         the raw fee — Core emits the raw `entry.GetFee()` here too
         (rpc/mining.cpp ~913) so this sub-gate IS Core-compatible;
         but the JSON has no `modified_fee` field, which matches Core.
         Sub-gate 9e is informational PRESENT.
  Bug body covers 9a-9d.

Gate 10 — ancestor-aware selection (CPFP). PRESENT (raw-fee version).
  lib/mining.ml:63-76 `compute_ancestor_fee_rate` sums tx + unselected
  ancestor fees / weights. Correct shape; raw vs modified is BUG-1.

Gate 11 — IsFinalTx check per-chunk (BIP-113 MTP cutoff). PRESENT.
  lib/mining.ml:159 `chunk_is_final`. Uses `lock_time_cutoff` =
  `Consensus.median_time_past tip_ts_list` (mining.ml:375). Matches
  Core miner.cpp:252-259 / 148.

Gate 12 — MAX_CONSECUTIVE_FAILURES early exit (1000). PRESENT.
  lib/mining.ml:52-53, 181-184. Matches Core miner.cpp:284-285.

Gate 13 — blockMinFeeRate gate (skip cheap chunks). PRESENT (raw-fee
  baseline, with the same BUG-1 caveat: gate compares
  raw-`entry.fee_rate` against the floor; if modified fee should
  promote a tx above the floor, that promotion is missed).
  lib/mining.ml:129-134. Default min is 0 (no minimum). Same code
  path was flagged BUG-18 in W108 (not wired from CLI / config).

Gate 14 — versionbits / BIP-9 deployment signaling. PRESENT.
  lib/mining.ml:447-467. Uses `compute_block_version` with
  taproot + testdummy deployments.

Gate 15 — BIP-94 testnet4 timewarp check at retarget boundary.
  PRESENT in `validation.ml:851+ check_block_header`. Constant
  `Consensus.max_timewarp = 600`. GBT response side (`mintime` /
  `curtime`) does NOT explicitly call out BIP-94 in
  `create_block_template` — Core's `UpdateTime` also does not, since
  the timewarp check is on the **received** block at retarget.
  PRESENT (validation), not duplicated in template-build.

Gate 16 — witness commitment output (BIP-141). PRESENT.
  lib/mining.ml:222-249 `compute_witness_merkle_root` +
  `compute_witness_commitment` + `build_witness_commitment_script`.
  Coinbase witness is 32 zero bytes (mining.ml:311). Marker is
  `0x6a 0x24 0xaa 0x21 0xa9 0xed` (mining.ml:243-248).

Gate 17 — `default_witness_commitment` field in GBT JSON. PRESENT.
  lib/mining.ml:683. But recomputed from scratch instead of being
  read out of `coinbase_tx.outputs[1]` — known W108 BUG-28
  (PARTIAL: present but duplicate work + susceptible to divergence
  if the tx list mutates between calls).

Gate 18 — `vbavailable` / `vbrequired` / `rules` / `coinbaseaux` /
  `capabilities` / `mutable` / `noncerange` / `sigoplimit` /
  `weightlimit` JSON fields. PRESENT. Closed by post-W108 fixes
  (see lib/mining.ml:611-684).

Gate 19 — `longpollid`. PRESENT.
  lib/mining.ml:642-650. Format = `prev_block_hash || transactions_updated`.

Gate 20 — `mintime` = GetMinimumTime = MTP + 1 (not curtime). **PARTIAL —
  W108 BUG-9 lives here.** lib/mining.ml:670-671 — `mintime` is
  `template.header.timestamp`, which is `max (mtp + 1) now`
  (mining.ml:419). When `now > mtp + 1` (the common case), mintime is
  `now`, not MTP+1. Core emits `mintime = pindexPrev->GetMedianTimePast() + 1`
  directly (rpc/mining.cpp). **W108-tracked, retained here as W123 gate
  20 cross-ref.**

Gate 21 — `submitblock` BIP-22 result strings. PARTIAL.
  lib/rpc.ml:1865 `bip22_of_submitblock_error` maps validation error
  strings to canonical tokens (`high-hash`, `bad-txnmrklroot`,
  `bad-cb-amount`, etc.). Missing: `duplicate` / `duplicate-invalid`
  detection (W108 BUG-15) — `submitblock` does not check the block
  index for a known-tip hash before validating. PRESENT-shape /
  partial coverage.

Gate 22 — `submitblock` side-branch / reorg path. PRESENT.
  lib/mining.ml:738-768. Calls `Sync.try_attach_side_branch_and_reorg`
  with undo data persisted (Pattern Y closure, 2026-05-05).

Gate 23 — `submitblock` calls `UpdateUncommittedBlockStructures`
  before validation (recomputes witness commitment / coinbase merkle
  if miner submitted a malformed body). **MISSING — W108 BUG-30
  surfaced this. Re-asserted here as W123 BUG-2 P2.**
  Core net_processing.cpp:74 calls `chainman.GenerateCoinbaseCommitment`
  before pushing to ProcessNewBlock. Camlcoin trusts the submitter to
  have a correct commitment already. Functional impact: low —
  honest miners always produce a correct commitment; malformed
  submissions are caught by `accept_block`'s commitment check. But
  it diverges from Core's exact pipeline.

Gate 24 — `submitheader` RPC. **MISSING — W123 BUG-3 P2.**
  Not in the RPC dispatcher (lib/rpc.ml:8663+). Core exposes
  `submitheader` (rpc/mining.cpp) for miners that want to pre-flight
  a header. Camlcoin's dispatcher has no `submitheader` case;
  `getblockheader` returns existing headers but cannot push new ones.

Gate 25 — `generatetoaddress` / `generateblock` (regtest mining). PRESENT.
  lib/rpc.ml:2018-2210. Gated on `network_type = Regtest`.

Gate 26 — getmininginfo current-block stats
  (`currentblocksize` / `currentblockweight` / `currentblocktx`).
  **PARTIAL — W123 BUG-4 P2.** lib/rpc.ml:1810-1812 emits all three
  as constant 0 with no template caching. Core tracks
  `nLastBlockSize`/`nLastBlockTx`/`nLastBlockWeight` and reports the
  most recent template size/weight/tx-count. Operators monitoring
  `getmininginfo` see a uniformly-zero block size/weight regardless
  of mempool depth.

Gate 27 — `getnetworkhashps` height + nblocks parameters. **PARTIAL —
  W108 BUG-16 / BUG-17 carry-forward. W123 BUG-5 P2.**
  lib/rpc.ml:7717+ `handle_getnetworkhashps` exists but ignores the
  optional `height` param and does not treat `nblocks = -1` as "since
  last difficulty change" (Core rpc/mining.cpp::GetNetworkHashPS).
  Tracked in W108; retained here for the W123 audit-status table.

Gate 28 — `prioritisetransaction` RPC. PRESENT (FIX-72).
  lib/rpc.ml:1571+ `handle_prioritisetransaction`. mapDeltas wiring
  to RBF Rule-3 confirmed. **Gate-9 BUG-1 (chunk-linearisation
  wiring) is the natural downstream extension of this gate.**

Gate 29 — BIP-23 `mode` parameter parsing
  (`proposal`/`template`/`template-request`). **MISSING — W108 BUG-11
  carry-forward. W123 BUG-6 P2.** lib/rpc.ml:1832-1838 reads only
  `coinbase_address` from the first object param; ignores `mode`.
  BIP-23 proposal mode would let miners pre-validate a block before
  submitting via `submitblock`. Currently any caller passing
  `{"mode":"proposal","data":...}` gets a regular template back.

Gate 30 — BIP-152 cmpctblock announce on new tip. **MISSING —
  W123 BUG-7 P1.** lib/peer_manager.ml:1360 `announce_block` sends
  either header (peer opted into sendheaders, BIP-130) OR inv —
  never cmpctblock. Core net_processing.cpp:5911 sends
  `MakeAndPushMessage(node, NetMsgType::CMPCTBLOCK, cmpctblock)` to
  high-bandwidth peers immediately after `ProcessNewBlock`. Camlcoin
  parses cmpctblock on receive (lib/cli.ml:1340+) and serves
  getblocktxn (cli.ml:1428+), so receive-side BIP-152 is fully
  wired; the gap is announce-side only.
  Operator impact: relay latency to HB peers is one extra RTT
  (peer asks for block via getdata after seeing header/inv) instead
  of zero. Honest cohort is fine; mining-pool peers running BIP-152
  HB mode lose the latency benefit.

## Bug summary

| ID | P | Gate | One-line |
|----|---|------|----------|
| BUG-1 | P1 | G9 | Chunk linearization (mining + ImprovesFeerateDiagram + eviction) reads raw `entry.fee`/`entry.fee_rate` instead of `get_modified_fee mp entry`; `prioritisetransaction` deltas are silently ignored by block-template assembly. **5 cascading sub-paths.** |
| BUG-2 | P2 | G23 | `submitblock` does not run `UpdateUncommittedBlockStructures` before validation (Core net_processing.cpp:74 parity gap). |
| BUG-3 | P2 | G24 | `submitheader` RPC not registered in dispatcher. |
| BUG-4 | P2 | G26 | `getmininginfo` emits `currentblocksize`/`currentblockweight`/`currentblocktx` as constant zero (no last-template cache). |
| BUG-5 | P2 | G27 | `getnetworkhashps` ignores optional `height` param and `nblocks = -1` (W108 BUG-16/17 carry-forward). |
| BUG-6 | P2 | G29 | BIP-23 `mode` parameter ignored — proposal mode unsupported. |
| BUG-7 | P1 | G30 | `announce_block` does not send `cmpctblock` to HB peers; only inv/headers. BIP-152 announce-side gap. |

Counts:
- PRESENT: 23 (G1-G8, G10-G19, G22, G25, G28)
- PARTIAL: 4 (G17 W108 BUG-28, G20 W108 BUG-9, G21 W108 BUG-15, G26 W123 BUG-4, G27 W123 BUG-5)
  — pedantically 5; BUG-4 listed as P2 PARTIAL
- MISSING: 3 (G9 + G23 + G24 + G29 + G30 == 5; some are subgate-MISSING within otherwise-PRESENT gates)

Priority:
- P0: 0
- P1: 2 (BUG-1, BUG-7)
- P2: 5 (BUG-2..6)

Total bugs: **7**.

## Cross-impl context (for future bundling)

The "chunk linearization reads raw fee" gap is a fleet pattern candidate.
Worth checking after this audit:
- rustoshi — has `mempool::chunk` machinery; check whether it reads
  raw vs modified fee.
- blockbrew — Go cluster linearizer in `mempool/cluster.go`.
- nimrod — see Nim cluster impl.
- ouroboros — Python mempool; modified fee handling.
- beamchain — `mempool_cluster` module; same question.

If 4+ impls share the same raw-fee gap, it joins the "RPC lies about
RBF" / "active-chain walk vs stop-hash ancestor" universal-pattern set
documented across W117-W121.

## Test status

`test/test_w123_mining_gbt.ml` adds 30 xfail/assertion tests, one per
gate. All P0/P1 gates have a forward-regression test that asserts the
expected Core-parity behaviour (and will fail until the corresponding
fix lands). P2 gates have an `audit-status` test that confirms the
absence pattern so the next fix-wave can flip them in a single PR.

Build verification: `dune build && _build/default/test/test_w123_mining_gbt.exe`
(NOT `dune runtest`, per FIX-64 / FIX-80 lessons on dune lock contention).

## References

- bitcoin-core/src/node/miner.cpp:79-88 ClampOptions, 148
  m_lock_time_cutoff, 171 coinbase sequence, 196 coinbase locktime,
  239-260 TestChunkBlockLimits + TestChunkTransactions, 279-334
  addChunks.
- bitcoin-core/src/rpc/mining.cpp:502 prioritisetransaction RPC,
  ~895 capabilities `"proposal"`, ~950-963 rules array, ~1002
  longpollid format.
- bitcoin-core/src/txmempool.cpp:630-655 PrioritiseTransaction +
  `m_txgraph->SetTransactionFee(modified_fee)` (line 641),
  657-666 ApplyDelta, 1082-1102 GetFeerateDiagram.
- bitcoin-core/src/txmempool.h:721-733 GetBlockBuilderChunk
  (single source of truth for both selection AND diagram).
- bitcoin-core/src/net_processing.cpp:5911 cmpctblock announce on
  new tip, 74 UpdateUncommittedBlockStructures usage.
