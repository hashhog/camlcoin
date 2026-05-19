# W154 — CreateNewBlock + BlockAssembler + block template construction (camlcoin)

**Wave:** W154 — `BlockAssembler::CreateNewBlock`, `addPackageTxs`
(now `addChunks` in modern Core), `ClampOptions`, `resetBlock`,
`AddToBlock`, `TestChunkBlockLimits`, `TestChunkTransactions`,
`GenerateCoinbaseCommitment` (BIP-141 0xaa21a9ed OP_RETURN marker),
`BlockMerkleRoot` / `BlockWitnessMerkleRoot`, `GetMinimumTime` / BIP-94
boundary, `UpdateTime`, `RegenerateCommitments`,
`IncrementExtraNonce` (legacy), `coinbaseTx` shape (BIP-34 height +
extra-nonce, `MAX_SEQUENCE_NONFINAL`, `nLockTime = height-1`,
scriptSig 2..100 bytes), `ApplyArgsManOptions` (`-blockmaxweight`,
`-blockmintxfee`, `-blockreservedweight`, `-blockversion`),
`DEFAULT_BLOCK_RESERVED_WEIGHT=8000`, `MINIMUM_BLOCK_RESERVED_WEIGHT=2000`,
`MAX_BLOCK_WEIGHT=4_000_000`, `WITNESS_SCALE_FACTOR=4`,
`MAX_BLOCK_SIGOPS_COST=80_000`, `TestBlockValidity` post-build gate,
BIP-22/BIP-23 `getblocktemplate` JSON shape (rules / vbavailable /
vbrequired / coinbasevalue / mintime / sigoplimit / sizelimit /
weightlimit / default_witness_commitment / longpollid / capabilities /
coinbaseaux), `submitblock` BIP-22 result tokens, `generatetoaddress`
/ `generateblock` regtest miners.

**Scope:** discovery only — no production code changes. This is the
miner-side companion of W123 (which covered mining/GBT from a different
angle in 2026-05-17). Several W123 findings are re-anchored here
because they touch the BlockAssembler shape directly (BUG-1, BUG-7,
BUG-12, BUG-18, BUG-19, BUG-23) and several NEW findings surface from
the W154-focused gates.

**Bitcoin Core references**
- `bitcoin-core/src/node/miner.cpp:79-88` — `ClampOptions`:
  `block_reserved_weight` clamped to `[MINIMUM_BLOCK_RESERVED_WEIGHT=2000,
  MAX_BLOCK_WEIGHT]` (default `DEFAULT_BLOCK_RESERVED_WEIGHT=8000`),
  `coinbase_output_max_additional_sigops` clamped to `[0,
  MAX_BLOCK_SIGOPS_COST]`, `nBlockMaxWeight` clamped to
  `[block_reserved_weight, MAX_BLOCK_WEIGHT]`.
- `bitcoin-core/src/node/miner.cpp:111-120` — `resetBlock`: starts
  `nBlockWeight = block_reserved_weight`, sets
  `nBlockSigOpsCost = m_options.coinbase_output_max_additional_sigops`.
- `bitcoin-core/src/node/miner.cpp:122-237` — `CreateNewBlock`:
  ComputeBlockVersion → coinbase scaffolding → addChunks
  → emit coinbase with `block_reward = nFees + GetBlockSubsidy(nHeight, ...)`,
  scriptSig = `CScript() << nHeight`, `nLockTime = nHeight - 1`,
  `nSequence = CTxIn::MAX_SEQUENCE_NONFINAL`, then
  `GenerateCoinbaseCommitment` → `UpdateTime` → `GetNextWorkRequired`
  → `TestBlockValidity` (gated on `options.test_block_validity = true`).
- `bitcoin-core/src/node/miner.cpp:36-47` — `GetMinimumTime`:
  `min_time = pindexPrev->GetMedianTimePast() + 1`; at retarget
  boundary additionally clamped to `≥ pindexPrev->GetBlockTime() -
  MAX_TIMEWARP` (BIP-94, applies on ALL networks per Core).
- `bitcoin-core/src/node/miner.cpp:239-247` — `TestChunkBlockLimits`:
  gate is `nBlockWeight + chunk.size >= nBlockMaxWeight ⟹ refuse`
  AND `nBlockSigOpsCost + chunk_sigops_cost >= MAX_BLOCK_SIGOPS_COST
  ⟹ refuse`.
- `bitcoin-core/src/node/miner.cpp:252-260` — `TestChunkTransactions`:
  `IsFinalTx(tx, nHeight, m_lock_time_cutoff = pindexPrev->GetMedianTimePast())`
  per tx in the chunk.
- `bitcoin-core/src/node/miner.cpp:67-77` — `RegenerateCommitments`:
  removes any existing commitment output, re-derives
  `GenerateCoinbaseCommitment`, recomputes `hashMerkleRoot`.
- `bitcoin-core/src/validation.cpp:3997-4019` —
  `GenerateCoinbaseCommitment` appends OP_RETURN OP_PUSHBYTES_36
  `0xaa21a9ed` + witness root, calls `UpdateUncommittedBlockStructures`.
- `bitcoin-core/src/validation.cpp:3870-3902` — `CheckWitnessMalleation`:
  on receive, asserts witness stack is exactly 1 element of 32 bytes
  (`bad-witness-nonce-size`) and that the recomputed commitment matches
  the OP_RETURN payload (`bad-witness-merkle-match`).
- `bitcoin-core/src/rpc/mining.cpp:684, 694, 1001, 1008-1016` —
  `getblocktemplate` JSON: `coinbasevalue` is `NUM`,
  `sizelimit = MAX_BLOCK_SERIALIZED_SIZE = 4_000_000`,
  `weightlimit = MAX_BLOCK_WEIGHT`, `sigoplimit = MAX_BLOCK_SIGOPS_COST`,
  `mintime = pindexPrev->GetMedianTimePast() + 1` (NOT curtime).
- `bitcoin-core/src/consensus/consensus.h:13, 15` —
  `MAX_BLOCK_SERIALIZED_SIZE = 4_000_000`, `MAX_BLOCK_WEIGHT = 4_000_000`,
  `WITNESS_SCALE_FACTOR = 4` (`consensus.h:21`).
- `bitcoin-core/src/kernel/chainparams.cpp` — per-network
  `consensus.nSubsidyHalvingInterval` (mainnet/testnet3/testnet4 =
  210000, regtest = 150, signet operator-configurable).
- `bitcoin-core/src/consensus/tx_check.cpp:49` — coinbase scriptSig
  length 2..100 bytes (`bad-cb-length`).

**Files audited**
- `lib/mining.ml` — `block_template` type (line 26-37),
  `select_transactions` (line 91-202), `compute_wtxid` (line 211-218),
  `compute_witness_merkle_root` (line 222-228), `compute_witness_commitment`
  (line 233-236), `build_witness_commitment_script` (line 241-249),
  `create_coinbase` (line 264-333), `create_block_template`
  (line 347-494), `mine_block` (line 505-528), `mine_block_extended`
  (line 533-553), `template_to_json` (line 572-684),
  `template_to_json_simple` (line 687-705), `submit_block` (line 716-928).
- `lib/consensus.ml` — `max_block_weight=4_000_000` (line 11),
  `max_block_serialized_size=4_000_000` (line 12),
  `max_block_sigops_cost=80_000` (line 13),
  `witness_scale_factor=4` (line 29),
  `block_subsidy` (line 85-88), `block_subsidy_for_network` (line 93-98),
  `network_config.halving_interval` (line 276) — **dead field**,
  `encode_height_in_coinbase` (line 783-812),
  `median_time_past` (line 815-819),
  `compute_block_version` (line 1580-1608),
  `mainnet_taproot` / `testnet4_taproot` / `regtest_taproot` (line 1614-1645),
  `testdummy_deployment` (line 1648-1656).
- `lib/validation.ml` — `count_sigops` (line 341-355 — `with _ -> 0`),
  `count_p2sh_sigops` (line 358-393 — same shape),
  `count_tx_sigops_cost` (line 523-587),
  `count_tx_sigops_cost_simple` (line 590-593),
  `compute_tx_weight` (line 115-127),
  `is_tx_final` (line 771-799),
  `accept_block` (BIP-30 / coinbase value gate at line 1782-1791,
  2035-2040).
- `lib/mempool.ml` — `get_sorted_transactions` (line 2381-2384),
  `select_for_block` (line 2387-2410 — dead in production),
  `select_for_block_chunked` (line 689-722 — dead in production),
  `count_tx_sigops_cost_for_mempool` (line 1086-1094).
- `lib/rpc.ml` — `handle_getblocktemplate` (line 1829-1858),
  `bip22_of_submitblock_error` (line 1865-1914),
  `handle_submitblock` (line 1916-1944),
  `mine_single_block` (line 1952-1970),
  `handle_generate` (line 1975-2016),
  `handle_generatetoaddress` (line 2021-2053),
  `handle_generateblock` (line 2060-2188).
- `lib/block_import.ml` — full file (157 lines), bypass pipeline.
- `lib/sync.ml` — `compute_median_time_past` (line 2065-2075),
  `compute_median_time_for_display` (line 2083-2091).
- `audit/w123_mining_gbt.md` — prior wave; several findings re-anchored.

---

## Gate matrix (32 gates / 11 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | MAX_BLOCK_WEIGHT semantics | G1: cap value 4_000_000 | PASS (`consensus.ml:11`) |
| 1 | … | G2: weight gate strict-less-than equivalent to Core `>=` refuse | PASS (`mining.ml:172` — `current + pkg < available_weight`) |
| 2 | WITNESS_SCALE_FACTOR | G3: constant 4 | PASS (`consensus.ml:29`) |
| 3 | DEFAULT_BLOCK_RESERVED_WEIGHT | G4: value 8000 | PASS (`mining.ml:50`) |
| 3 | … | G5: ClampOptions to `[2000, MAX_BLOCK_WEIGHT]` | PASS (`mining.ml:57-58`) |
| 3 | … | G6: ApplyArgsManOptions wired from CLI (`-blockmaxweight`, `-blockmintxfee`, `-blockreservedweight`, `-blockversion`) | **BUG-1 (P1)** — no CLI knobs wired anywhere; operator cannot tune block resource limits |
| 4 | addChunks / package-feerate selection | G7: ancestor-feerate sort | PASS (`mining.ml:114-118`) |
| 4 | … | G8: chunks use MODIFIED fee (prioritisetransaction delta) | **BUG-2 (P1)** — W123 BUG-1 carry-forward; `compute_ancestor_fee_rate` reads raw `entry.fee` / `a.fee`; `prioritisetransaction` deltas silently ignored by block-template assembly. 5 cascading sub-paths inherited from W123. |
| 4 | … | G9: MAX_CONSECUTIVE_FAILURES = 1000 + 4000-wu delta exit | PASS (`mining.ml:52-53, 181-184`) |
| 4 | … | G10: IsFinalTx per-chunk with `lock_time_cutoff = MTP(pindexPrev)` | PASS (`mining.ml:159-161`, MTP at `mining.ml:375`) |
| 5 | GenerateCoinbaseCommitment (BIP-141) | G11: 0xaa21a9ed marker bytes | PASS (`mining.ml:241-248`) |
| 5 | … | G12: witness merkle root = merkle of wtxids with coinbase wtxid = 0 | PASS (`mining.ml:211-228`) |
| 5 | … | G13: commitment script length = 6 + 32 (MINIMUM_WITNESS_COMMITMENT) | PASS (`mining.ml:241-249`) |
| 5 | … | G14: only emit commitment when segwit is active for the block height | **BUG-3 (P1)** — `create_block_template` emits commitment **unconditionally** regardless of `network.segwit_height` (`mining.ml:405-407`). Mainnet heights < 481,824 / testnet3 heights < 834,624 would receive a coinbase with an extraneous OP_RETURN output. Mainnet is post-segwit forever now, but a fresh chain restart from genesis (regtest is fine, segwit_height = 0; testnet3 / mainnet are problematic only in archive replay). Cross-cite the `network.segwit_height` field that already exists (`consensus.ml:266, 613, 680, 722, 764`) — present but not consulted by the miner. **dead-data plumbing fleet pattern, 11th camlcoin instance**. |
| 5 | … | G15: RegenerateCommitments helper after submitter mutation | **BUG-4 (P2)** — W123 BUG-2 carry-forward (G23). `handle_submitblock` (`rpc.ml:1916-1944`) does NOT call `RegenerateCommitments` / `UpdateUncommittedBlockStructures` before validation; trusts the submitter's witness commitment. |
| 6 | BlockMerkleRoot / BlockWitnessMerkleRoot | G16: BlockMerkleRoot of [coinbase_with_commitment, ...selected] | PASS (`mining.ml:410-412`) |
| 6 | … | G17: BlockWitnessMerkleRoot uses placeholder-coinbase wtxid=0 | PASS (`mining.ml:398-402`) |
| 6 | … | G18: CVE-2012-2459 `_mutated` flag propagated | **BUG-5 (P0-CONS)** — `merkle_root` returns `(root, _mutated)` (`mining.ml:227, 412`) but `_mutated` is **discarded** (underscore-prefix bound). Mining-side does not refuse to build on a malleated parent merkle; cross-cite W142 (cross-impl fleet pattern: rustoshi 3-merkle, blockbrew etc.). Mining is the OFFENSIVE side, not the defensive side — so the bug is mostly that camlcoin **could** mine a malleated block if it built one itself; consensus risk is low here, but the `_mutated` discard is the same shape Core uses to signal `BLOCK_MUTATED` upstream. Listed for fleet-pattern continuity. |
| 7 | mintime (parent MTP + 1) | G19: GBT JSON `mintime` = MTP(pindexPrev) + 1 | **BUG-6 (P1)** — W123 BUG-2 / W108 BUG-9 carry-forward. `template_to_json` emits `("mintime", Int (template.header.timestamp))` (`mining.ml:670-671`), which is `max (mtp + 1) now`. When `now > mtp + 1` (the common case), mintime is `now`, not MTP+1. Core: `mintime = pindexPrev->GetMedianTimePast() + 1` directly. Miners interpreting `mintime` as the lowest-permitted timestamp may briefly reject Core-canonical timestamps that fall between MTP+1 and now. |
| 7 | … | G20: BIP-94 MAX_TIMEWARP clamp on retarget boundary | **BUG-7 (P0-CDIV)** — `create_block_template` computes `timestamp = max (mtp+1) now` at `mining.ml:419` WITHOUT consulting `Consensus.max_timewarp = 600` (`consensus.ml:26`). At a retarget boundary (`height % 2016 == 0`), Core's `GetMinimumTime` additionally clamps `min_time ≥ pindexPrev->GetBlockTime() - MAX_TIMEWARP` (`miner.cpp:43-44`). On testnet4 (and post-W141 on all networks per Core), camlcoin-mined templates at retarget boundaries that pre-date pindexPrev by > 600 s **would be rejected by Core peers** with `time-too-old` / `timewarp`. Mining-side is the cause; the receive-side check exists (`validation.ml:check_timewarp_rule`, `consensus.ml:836`) but is gated on `network.enforce_bip94` (testnet4 only). Cross-impl risk: a camlcoin testnet4 miner is the ONLY scenario where this fires today, but Core enforces BIP-94 on ALL networks now (`miner.cpp:41-45` comment "on all networks. This makes future activation safer"). |
| 8 | nVersion / BIP-9 / version-rolling | G21: ComputeBlockVersion with BIP-9 deployment signaling | PASS (mainnet/testnet4/regtest only — see BUG-8) |
| 8 | … | G22: per-network deployment selection | **BUG-8 (P1)** — `mining.ml:455-458` dispatches `taproot_dep` on `chain.network.name` with only `"mainnet" / "testnet4"` matched; **everything else falls through to `regtest_taproot`** (period=144, threshold=108). Testnet3 (`name = "testnet3"`, `consensus.ml:647`) is silently treated as regtest for version-bits — wrong period and threshold values produce templates whose version bits would not match Core-mined templates during any active BIP-9 deployment window. Signet (not implemented as a network type at all) is moot here. |
| 8 | … | G23: BIP-9 cache reused across calls | **BUG-9 (P1)** — `mining.ml:461` creates a FRESH `vb_cache` on EVERY call to `create_block_template`. `compute_block_version` walks back from genesis to seed the cache. For an active deployment with `MIN_BIP9_WARNING_HEIGHT = 711,648`, every GBT call O(tip) walks the chain. Comment in `consensus.ml:1267-1275` explicitly mentions buried deployments — taproot is buried, so the walk converges quickly today. **Cross-impl repeat of `BIP9DeploymentCache fresh every call` pattern; cumulative O(tip²) cost over `n` GBT calls during a fresh deployment window.** |
| 9 | coinbase scriptSig length 2..100 | G24: validation enforces (`bad-cb-length`) | PASS (`validation.ml:273-275`) |
| 9 | … | G25: miner-built coinbase never exceeds 100 bytes | **BUG-10 (P1)** — `create_coinbase` builds `coinbase_script = concat [height_bytes; extra_nonce]` (`mining.ml:274`). With `extra_nonce` hardcoded to 8 bytes (`mining.ml:390`) and `height_bytes` of up to 6 bytes (length byte + 5-byte CScriptNum at height up to 2^39), the total is 14 bytes. Safe today, but a future operator-knob that bumps `extra_nonce` to ≥ 95 bytes would silently produce `bad-cb-length` coinbases. No clamp / assertion enforces ≤ 100. Defensive gate absent; risk currently latent. |
| 9 | … | G26: miner-built coinbase never below 2 bytes | **BUG-11 (P1)** — at height 0 (the literal genesis), `encode_height_in_coinbase 0` returns 1 byte (`consensus.ml:786-790`); with the 8-byte `extra_nonce` the total is 9 bytes (safe). But `create_coinbase` is a public helper; a caller passing `extra_nonce = Cstruct.create 0` at height 0 would produce a 1-byte coinbase that violates `bad-cb-length` (camlcoin's own validator at `validation.ml:274` would reject the block). Core's `include_dummy_extranonce` option (`miner.cpp:187-193`) handles this by appending `OP_0` when height ≤ 16; camlcoin has no such mechanism. Risk: regtest harnesses that bypass `create_block_template` and call `create_coinbase` directly with no extra-nonce produce reject-by-self blocks. |
| 10 | coinbase BIP-34 height encoding | G27: BIP-34 height present in scriptSig prefix | PASS (`mining.ml:273` via `Consensus.encode_height_in_coinbase`) |
| 10 | … | G28: encoded height matches Core CScriptNum thresholds (0x7f / 0x7fff / 0x7fffff) | PASS (`consensus.ml:783-812`) |
| 10 | … | G29: coinbase `nLockTime = nHeight - 1` | PASS (`mining.ml:332`) |
| 10 | … | G30: coinbase `nSequence = CTxIn::MAX_SEQUENCE_NONFINAL = 0xFFFFFFFE` | PASS (`mining.ml:290`) |
| 11 | TestBlockValidity post-build | G31: GBT call runs `TestBlockValidity` before returning | **BUG-12 (P0-CDIV)** — Core's `CreateNewBlock` (`miner.cpp:223-227`) runs `TestBlockValidity(state, ..., /*check_pow=*/false, /*check_merkle_root=*/false)` with `options.test_block_validity = true` by default. Failure THROWS, the template is never emitted. Camlcoin's `create_block_template` (`mining.ml:347-494`) builds the template and returns it **without any validation**: no `Validation.check_block_header`, no `Validation.accept_block` dry-run, no coinbase-MAX_MONEY sanity check, no `count_block_sigops_cost` cross-check, no merkle/witness-merkle reconciliation. A bug in `select_transactions` (e.g. a future change that admits an invalid IsFinalTx tx, or BUG-2 modified-fee divergence that promotes a tx with non-final ancestors) results in a template returned to miners that Core peers will reject on submitblock. The fleet-wide canonical-gate-not-wired pattern (cross-cite W144) extends to the mining side. |
| 11 | … | G32: GBT response post-build invariants (`coinbasevalue ≤ MAX_MONEY`, `sigops ≤ 80_000`) | **BUG-13 (P0)** — `template_to_json` (`mining.ml:662-666`) computes `coinbasevalue = subsidy + total_fee` WITHOUT a `Consensus.is_valid_money` clamp. On a future bug where `total_fee` overflows (Int64 wrap on a malicious mempool / chunk-linearizer regression), the value can exceed MAX_MONEY and the JSON would silently advertise an invalid reward. Core relies on `TestBlockValidity` to catch this (cross-cite BUG-12); the GBT JSON itself is the wire payload returned to miners, so an inflated coinbasevalue would be propagated end-to-end. Latent. |

Recount: 32 sub-gates / 13 bugs catalogued in the gate matrix; 9 more
findings (BUG-14..22) are W154-specific or carry-forward / refinement
that do not map 1:1 to a gate.

---

## BUG-1 (P1) — No CLI knobs for block resource limits

**Severity:** P1 ("no operator-knob exists" fleet pattern, ~10th
camlcoin instance — symmetric to W149 BUG-5 blockbrew `-assumevalid`).
Core exposes `-blockmaxweight`, `-blockmintxfee`, `-blockreservedweight`,
`-blockversion`, and `-printpriority` for operator/test tuning of the
BlockAssembler (`miner.cpp:98-109` `ApplyArgsManOptions`). Camlcoin's
miner hardcodes all of these:
- `default_block_reserved_weight = 8000` (`mining.ml:50`) — no CLI flag
- `min_fee_rate_sat_per_kvb = 0` default (`mining.ml:92`) — no CLI flag
- block max weight = `Consensus.max_block_weight` (4_000_000), never lowered
- `-blockversion` for regtest fork-testing scenarios — no analogue

**File:** `lib/cli.ml` (parseFlags, no `-blockmaxweight` /
`-blockmintxfee` / `-blockreservedweight` / `-blockversion` /
`-printpriority` registration); `lib/mining.ml:91-94` (defaults
hardcoded).

**Core ref:** `bitcoin-core/src/node/miner.cpp:98-109`,
`bitcoin-core/src/init.cpp`.

**Impact:** test-ergonomics gap; pool operators tuning block size
upward (post-2017 large-block scenarios) cannot adjust; regtest
scenarios that need to set `-blockversion=4` to test pre-segwit
behaviour cannot do so.

---

## BUG-2 (P1) — Chunk linearization reads raw fee, ignores prioritisetransaction delta

**Severity:** P1 (W123 BUG-1 carry-forward, re-anchored at W154 to
keep visibility). The marquee finding from W123 still lives:
`compute_ancestor_fee_rate` (`mining.ml:63-76`) reads `entry.fee`
and unselected ancestor `a.fee` directly — never calls
`Mempool.get_modified_fee mp entry`. Same for `find_best_chunk`
(`mempool.ml:556+`) and its callers.

**File:** `lib/mining.ml:63-76`; `lib/mempool.ml:556-722`.

**Core ref:** `bitcoin-core/src/txmempool.cpp:641`
`m_txgraph->SetTransactionFee(modified_fee)`.

**Impact:** operator deltas via `prioritisetransaction` are silently
ignored by block-template assembly; cascading through 5 sub-paths
(template selection / chunked-selection / ImprovesFeerateDiagram /
get_worst_chunk / track_package_removed). W123 catalogue still apt.

---

## BUG-3 (P1) — Witness commitment emitted unconditionally; `network.segwit_height` ignored by miner

**Severity:** P1 ("dead-data plumbing", camlcoin 11th instance).
`create_block_template` (`mining.ml:395-407`) builds witness merkle
root and APPENDS the commitment output to coinbase regardless of
height vs `network.segwit_height`. `network.segwit_height` IS defined
per-network (`consensus.ml:266, 613, 680, 722, 764`) but has zero
consumers in `mining.ml`.

On mainnet today, segwit is buried at h=481,824, so post-buried this
is moot. The bug surfaces in:
- archive replays from genesis: mainnet h < 481,824 templates carry
  an extra OP_RETURN coinbase output that pre-segwit nodes / older
  hashhog impls would reject;
- testnet3 (segwit_height=834,624) when running a fresh sync;
- regression-testing tooling that switches a node between pre- and
  post-segwit modes for upgrade-path validation.

The companion `template_to_json` emits `default_witness_commitment`
in the GBT JSON unconditionally (`mining.ml:683`); Core gates emission
on `DeploymentActiveAfter(... DEPLOYMENT_SEGWIT)`.

**File:** `lib/mining.ml:395-407, 600-608, 683`.

**Core ref:** `bitcoin-core/src/validation.cpp:3997-4019`
`GenerateCoinbaseCommitment` (callers gate on `DeploymentActiveAfter`).

**Impact:** archive-replay divergence; cross-fleet incompatibility
during back-fills; cosmetic on a live mainnet node.

---

## BUG-4 (P2) — `submitblock` does not run `UpdateUncommittedBlockStructures` / `RegenerateCommitments` before validating

**Severity:** P2 (W123 BUG-2 carry-forward at G23). Core's
`net_processing.cpp:74` calls `chainman.GenerateCoinbaseCommitment`
before pushing to `ProcessNewBlock`, so a submitter that posted a
block with a stale / wrong commitment has it re-derived first.

Camlcoin's `handle_submitblock` (`rpc.ml:1916-1944`) deserializes the
block and immediately calls `Mining.submit_block`, which calls
`Validation.accept_block`. The commitment check in `accept_block`
will reject mismatched commitments. Honest miners always produce
correct commitments, so impact is low — but Core's exact pipeline
re-generates first.

**File:** `lib/rpc.ml:1916-1944`; `lib/mining.ml:716-928`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:74`,
`bitcoin-core/src/node/miner.cpp:67-77` `RegenerateCommitments`.

**Impact:** cross-cite W123 BUG-2; cosmetic.

---

## BUG-5 (P0-CONS) — `_mutated` discarded in `BlockMerkleRoot` / `BlockWitnessMerkleRoot` callers (mining side)

**Severity:** P0-CONS (mining-side; cross-cite W142 fleet pattern).
`Crypto.merkle_root` returns `(root, mutated)` (see `mining.ml:227, 412`,
both call sites). Mining-side discards the `_mutated` flag via
underscore-prefix binding. Today camlcoin's miner uses honest input
data so `_mutated` is always `false`, but:
- a regression in `select_transactions` that emits the same tx twice
  (the dup-txid CVE-2012-2459 shape) would produce a mutated merkle
  silently, and the miner would build/return a template that Core
  peers would reject with `bad-txns-duplicate`;
- BUG-12 (`TestBlockValidity` not run on the build path) means the
  mining-side has NO cross-check that the merkle-root is well-formed.

This is the offensive-side of the W142 6-impl `_mutated` fleet pattern
(rustoshi 3-copy / blockbrew / etc.). Camlcoin's RECEIVE-side merkle
check is W142-tracked separately; this finding is specifically the
MINING-side instance.

**File:** `lib/mining.ml:227, 412`.

**Core ref:** `bitcoin-core/src/consensus/merkle.cpp::BlockMerkleRoot`
(the mutated flag is propagated to `IsBlockMutated`).

**Impact:** latent; depends on an upstream bug to surface. Listed for
fleet-pattern continuity (cross-cite W142, W143).

---

## BUG-6 (P1) — GBT `mintime` is `header.timestamp`, not MTP+1

**Severity:** P1 (W108 BUG-9 / W123 G20 carry-forward).
`template_to_json` emits `("mintime", Int (template.header.timestamp))`
at `mining.ml:670-671`. `header.timestamp` is `max (mtp + 1) now`
(line 419). When `now > mtp + 1` (typical case), `mintime` = `now`,
not MTP+1. Core: `mintime = pindexPrev->GetMedianTimePast() + 1`.

Miners interpreting `mintime` as the lowest-permitted timestamp lose
the visibility into the (small) window where they could legally lower
the timestamp.

**File:** `lib/mining.ml:419, 670-671`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp` (mintime literal).

**Impact:** GBT JSON divergence; miners that programmatically lower
timestamp from `curtime` toward `mintime` see a smaller window.

---

## BUG-7 (P0-CDIV) — BIP-94 MAX_TIMEWARP clamp absent on miner-side at retarget boundary

**Severity:** P0-CDIV. Bitcoin Core's `GetMinimumTime`
(`miner.cpp:36-47`) clamps `min_time ≥ pindexPrev->GetBlockTime() -
MAX_TIMEWARP` at retarget boundaries on **ALL** networks (comment:
"This makes future activation safer"). Camlcoin's
`create_block_template` (`mining.ml:417-419`) computes:

```ocaml
let mtp = lock_time_cutoff in
let now = Int32.of_float (Unix.gettimeofday ()) in
let timestamp = max (Int32.add mtp 1l) now in
```

There is no MAX_TIMEWARP clamp at the difficulty-adjustment boundary.
Receive-side `check_timewarp_rule` (`consensus.ml:836-843`) is gated
on `network.enforce_bip94 = true`, which is true only for testnet4 in
camlcoin (`consensus.ml:680-695`). A camlcoin testnet4 miner producing
a block at a retarget boundary with `wall_clock_now < parent_time -
600` would have the block rejected by Core peers.

Mainnet impact today: zero (mainnet does not enforce BIP-94 in
camlcoin). Cross-impl-future impact: when (if) BIP-94 is enabled on
mainnet, camlcoin miner-side becomes a chain-split candidate at every
retarget boundary.

**File:** `lib/mining.ml:417-419`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:36-47` `GetMinimumTime`,
`bitcoin-core/src/consensus/consensus.h::MAX_TIMEWARP`.

**Impact:** testnet4 miner-side chain-split candidate at retarget
boundaries when wall-clock < parent_time - 600 s; latent on other
networks until BIP-94 enforcement spreads.

---

## BUG-8 (P1) — Taproot deployment selected by network name, with testnet3 silently falling through to regtest

**Severity:** P1. `mining.ml:455-458`:

```ocaml
let taproot_dep = match chain.network.name with
  | "mainnet" -> Consensus.mainnet_taproot
  | "testnet4" -> Consensus.testnet4_taproot
  | _ -> Consensus.regtest_taproot
in
```

Network names defined in `consensus.ml`: `"mainnet"`, `"testnet3"`,
`"testnet4"`, `"regtest"` (`consensus.ml:583, 647, 695, 740`). The
match arm fails on `"testnet3"` → falls through to `regtest_taproot`
(period=144, threshold=108) instead of using the proper testnet3
taproot config (period=2016, threshold=1815-ish).

For buried deployments (current Core), version-bits signaling is no
longer required, so the impact today is cosmetic — `compute_block_version`
returns `versionbits_top_bits | mask(taproot)` while taproot is
LockedIn/Started, and `Started/LockedIn` resolution depends on the
deployment params. A camlcoin testnet3 miner would compute a slightly
different version field than Core during any non-buried deployment
window.

**File:** `lib/mining.ml:455-458`.

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp` (per-network
DEPLOYMENT_TAPROOT params).

**Impact:** testnet3 version-bit divergence during any non-buried
deployment; cosmetic post-burial.

---

## BUG-9 (P1) — BIP-9 versionbits cache rebuilt on every GBT call (O(tip) walk per template)

**Severity:** P1. `mining.ml:461`:

```ocaml
let vb_cache = Consensus.create_versionbits_cache () in
```

This builds a FRESH cache every call. `compute_block_version` then
walks back through ancestors (`get_block h`) to seed the cache. For
buried deployments (Core today), the walk converges quickly. For a
deployment in `Started` state, the walk extends back to `period_start`
of the active deployment window. Cumulative O(tip²) cost over `n`
sequential GBT calls if any deployment is active.

**File:** `lib/mining.ml:461-466`; cross-cite the cache constructor at
`consensus.ml:1679+`.

**Core ref:** `bitcoin-core/src/versionbits.cpp::VersionBitsCache`
(persisted on the ChainstateManager — single instance per node lifetime).

**Impact:** GBT latency grows O(tip) during active deployments;
cosmetic with buried-only deployments.

---

## BUG-10 (P1) — No clamp on coinbase scriptSig length (latent `bad-cb-length`)

**Severity:** P1. `create_coinbase` (`mining.ml:264-333`) builds
`coinbase_script = concat [height_bytes; extra_nonce]` (line 274)
without enforcing the 2..100 byte cap that `validation.ml:273-275`
checks on receive. Today `extra_nonce` is hardcoded to 8 bytes
(`mining.ml:390`), so total length is 9..14 bytes. Future operator
knobs (BUG-1) that increase extra_nonce would silently produce
self-rejecting coinbases.

Core protects against this with `IncrementExtraNonce`
(legacy) / `CoinbaseTx::script_sig_prefix` (modern) which assert the
clamp.

**File:** `lib/mining.ml:264-333`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:186-194`
(scriptSig construction), `bitcoin-core/src/consensus/tx_check.cpp:49`.

**Impact:** latent defensive gap; defense-in-depth missing.

---

## BUG-11 (P1) — `create_coinbase` allows coinbases below 2 bytes (no `include_dummy_extranonce` analogue)

**Severity:** P1. At height 0, `encode_height_in_coinbase 0` returns
1 byte (`consensus.ml:786-790`). A caller passing `extra_nonce =
Cstruct.create 0` produces a 1-byte coinbase that `validation.ml`
rejects as `bad-cb-length`. Core's `BlockCreateOptions`
(`miner.h::include_dummy_extranonce`) appends `OP_0` when height ≤ 16
so the coinbase is always ≥ 2 bytes (`miner.cpp:187-193`).

In current camlcoin call sites, `extra_nonce` is always 8 bytes
(`mining.ml:390`, `rpc.ml:2123`), so this is latent. But the function
is exported (no `private` modifier in `mining.ml`) and a future
test/harness caller could trigger the failure.

**File:** `lib/mining.ml:264-333`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:187-193`
`include_dummy_extranonce`.

**Impact:** latent harness-only failure; correctness-neutral today.

---

## BUG-12 (P0-CDIV) — `TestBlockValidity` post-build gate absent in `create_block_template`

**Severity:** P0-CDIV ("canonical-gate-not-wired" fleet pattern,
camlcoin's 4th post-W123 instance). Core's `CreateNewBlock`
(`miner.cpp:223-227`):

```cpp
if (m_options.test_block_validity) {
    if (BlockValidationState state{TestBlockValidity(m_chainstate, *pblock,
        /*check_pow=*/false, /*check_merkle_root=*/false)}; !state.IsValid()) {
        throw std::runtime_error(strprintf("TestBlockValidity failed: %s", state.ToString()));
    }
}
```

Default `options.test_block_validity = true`. Failure THROWS — the
template is never returned.

Camlcoin's `create_block_template` (`mining.ml:347-494`) builds the
template and returns it WITHOUT any validation pass. No
`Validation.check_block_header` call, no `Validation.accept_block`
dry-run, no `count_block_sigops_cost` cross-check, no MAX_MONEY
sanity. The only consumer-side validation is in `submit_block`
(`mining.ml:716-928`), which is invoked only on `submitblock` RPC,
NOT on `getblocktemplate`.

Consequences when a bug in selection or coinbase construction slips
through:
- `getblocktemplate` returns the malformed template to the miner;
- the miner builds a block from it and submits via `submitblock`;
- `accept_block` rejects with whatever the underlying gate is —
  but the miner has wasted PoW work, the template returned was
  Core-incompatible, and the operator gets a generic "rejected"
  result without the miner-side log entry that Core would have
  produced.

Cross-cite BUG-2 (modified-fee divergence) and BUG-13 (MAX_MONEY
sanity); both bugs are LATENT today because no upstream bug currently
emits invalid input — but BUG-12 is the **safety net that would catch
either of them and DOES NOT EXIST in camlcoin's mining path**.

**File:** `lib/mining.ml:347-494`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:223-227`
`TestBlockValidity` post-build gate.

**Impact:** miner sees stale/bad templates; PoW wasted; cross-cite
defenses missing.

---

## BUG-13 (P0) — `coinbasevalue` GBT JSON has no MAX_MONEY sanity check

**Severity:** P0. `template_to_json` (`mining.ml:662-666`):

```ocaml
("coinbasevalue",
  `String (Int64.to_string
    (Int64.add
      (Consensus.block_subsidy_for_network template.network_type template.height)
      template.total_fee)));
```

`Int64.add` is unchecked — if `total_fee` (or future bug in fee
aggregation) results in `subsidy + total_fee > Consensus.max_money`
or wraps Int64, the emitted JSON would carry an invalid value.
`Consensus.is_valid_money` (`consensus.ml:822-823`) is the
existing primitive but is NOT called.

In camlcoin's current selection, `total_fee` is a sum of validated
mempool entries' fees, each capped by tx-input MAX_MONEY checks. So
today this is latent. The bug surfaces if (a) fee aggregation ever
overflows in a future regression, (b) a malicious mempool entry with
a forged fee field slips past ATMP, or (c) BUG-12 means the safety net
that would catch this is also missing.

**File:** `lib/mining.ml:662-666`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1001` (Core emits
`block.vtx[0]->vout[0].nValue`, which has already been clamped by
`accept_block`'s coinbase-value check; cross-cite W145 BUG-12
camlcoin instance).

**Impact:** latent inflation-primitive surface; depends on upstream
bug to manifest.

---

## BUG-14 (P0-CDIV) — `coinbasevalue` JSON encoded as `String`, not `NUM` (wire-format divergence)

**Severity:** P0-CDIV ("wire-format divergence" fleet pattern,
camlcoin's 3rd JSON-shape instance). Core's GBT JSON
(`rpc/mining.cpp:684, 1001`):

```cpp
{RPCResult::Type::NUM, "coinbasevalue", "..."},
...
result.pushKV("coinbasevalue", block.vtx[0]->vout[0].nValue);
```

Camlcoin emits it as a JSON string (`mining.ml:663-666`):

```ocaml
("coinbasevalue",
  `String (Int64.to_string ...));
```

Miner clients (bitcoind-cli, ckpool, btcpool, etc.) parse
`coinbasevalue` as integer per BIP-22 / Core schema. A camlcoin GBT
response would fail to parse or be treated as zero.

**File:** `lib/mining.ml:662-666`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1001`.

**Impact:** GBT clients fail or misinterpret coinbasevalue → mining
pool integration breaks day-1.

---

## BUG-15 (P0-CDIV) — `sizelimit` GBT JSON hardcoded to pre-segwit 1_000_000

**Severity:** P0-CDIV. `template_to_json` emits `("sizelimit", `Int
1000000)` at `mining.ml:676`. Core emits `MAX_BLOCK_SERIALIZED_SIZE =
4_000_000` (`rpc/mining.cpp:1008-1016`,
`consensus/consensus.h:13`).

`1_000_000` was the pre-segwit MAX_BLOCK_SIZE (consensus-historical).
Post-segwit, the serialized size cap is `MAX_BLOCK_SERIALIZED_SIZE =
4_000_000`. Miner clients that respect `sizelimit` when packing
transactions would cap their submissions at 1 MB serialized size,
artificially constraining block fullness on camlcoin-served templates.

**File:** `lib/mining.ml:676`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1008-1016`,
`bitcoin-core/src/consensus/consensus.h:13`.

**Impact:** miners see 1 MB serialized cap instead of 4 MB → can pack
fewer / smaller transactions; block reward suboptimal vs Core-served
template.

---

## BUG-16 (P0-CDIV) — Per-tx `sigops` JSON field undercount (no UTXO lookup)

**Severity:** P0-CDIV. `template_to_json` (`mining.ml:592-593`):

```ocaml
("sigops", `Int (Validation.count_tx_sigops_cost_simple tx
                   ~prev_script_pubkey_lookup:(fun _ -> None)));
```

`count_tx_sigops_cost_simple` with a `(fun _ -> None)` lookup returns
ONLY legacy sigops × WITNESS_SCALE_FACTOR (no P2SH, no witness).
Mining selection itself uses `Mempool.count_tx_sigops_cost_for_mempool`
which correctly looks up prevouts (`mempool.ml:1086-1094`) and gets
the proper UTXO-aware cost. But the JSON field returned to miners is
the undercount.

A miner client that consumes GBT and trusts the per-tx `sigops` field
to pack additional transactions up to `sigoplimit` will overshoot the
real sigop cost on P2SH-heavy / witness-heavy templates.

**File:** `lib/mining.ml:592-593`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp::getblocktemplate`
(emits `entry.GetSigOpCost()` which is the cluster-mempool's
UTXO-aware result).

**Impact:** miner-side sigop budgeting incorrect; templates may be
rejected on submitblock for `bad-blk-sigops`.

---

## BUG-17 (P0) — `block_subsidy_for_network` ignores `network_config.halving_interval` (dead-field)

**Severity:** P0 (W145 BUG-2 carry-forward, re-anchored; cumulative
camlcoin 8-CONSECUTIVE-QUAD pattern of `block_import.ml`-style
bypass extending to mining). The
`network_config.halving_interval` field is set per-network
(`consensus.ml:642, 690, 735, 774`) and propagated through
network_config-using code paths in validation. But
`block_subsidy_for_network` (`consensus.ml:93-98`) hardcodes the
match:

```ocaml
let block_subsidy_for_network (network : network) (height : int) : int64 =
  let halving_interval = match network with
    | Regtest -> regtest_halving_interval
    | Mainnet | Testnet3 | Testnet4 -> default_halving_interval
  in
  block_subsidy ~halving_interval height
```

Note the type of `network` here is the bare `Consensus.network` enum
(not `network_config`), so `network_config.halving_interval` is
NEVER consulted. Mining calls this function at:
- `mining.ml:269` (subsidy in `create_coinbase`)
- `mining.ml:665` (coinbasevalue in GBT JSON)
- `mining.ml:700` (coinbasevalue in template_to_json_simple)

Signet support is moot today (network type not defined), but the
broader pattern: `network_config.halving_interval` is a **completely
dead field** that exists across all 4 networks but is read by no
production callsite. cross-cite W145 BUG-2 (originally raised on
camlcoin May-18 quad).

**File:** `lib/consensus.ml:93-98, 276, 642, 690, 735, 774`;
`lib/mining.ml:269, 665, 700`.

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp`
`consensus.nSubsidyHalvingInterval` (per-network configurable).

**Impact:** signet support gap; potential future regtest-variant
support that uses a non-150 halving interval cannot be wired without
changing `block_subsidy_for_network`'s signature.

---

## BUG-18 (P2) — `submitheader` RPC absent (W123 BUG-3 carry-forward)

**Severity:** P2 (W123 BUG-3). The RPC dispatcher
(`rpc.ml:8703-8720` block) does not register `submitheader`. Core
exposes it for pre-flight header validation. Camlcoin's
`getblockheader` returns existing headers; there's no path to push a
new one for pre-validation.

**File:** `lib/rpc.ml:8703-8720`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp::submitheader`.

**Impact:** miner workflow gap; pre-flight header validation requires
a full submitblock dry-run instead.

---

## BUG-19 (P2) — `getmininginfo` emits `currentblocksize` / `currentblockweight` / `currentblocktx` as constant zero (W123 BUG-4 carry-forward)

**Severity:** P2 (W123 BUG-4). `rpc.ml:1810-1812` emits all three as
`0`; there is no `nLastBlockSize`/`nLastBlockTx`/`nLastBlockWeight`
cache. Core tracks the latest template's stats via `BlockAssembler`
static fields (`miner.h:96-98`):

```cpp
inline static std::optional<int64_t> m_last_block_num_txs{};
inline static std::optional<int64_t> m_last_block_weight{};
```

camlcoin has the data inside `block_template` (`mining.ml:32-34`
fields `total_weight`, `tx_fees` length) but does NOT cache them on
a global / module-level slot for `getmininginfo` to read.

**File:** `lib/rpc.ml:1810-1812`; `lib/mining.ml:32-34, 478-481`.

**Core ref:** `bitcoin-core/src/node/miner.h:96-98`,
`bitcoin-core/src/rpc/mining.cpp::getmininginfo`.

**Impact:** operator monitoring gap; cosmetic.

---

## BUG-20 (P1) — `extra_nonce` uses microsecond timestamp; no randomness, no per-call increment

**Severity:** P1 ("dead-data / latent-bug" combination).
`create_block_template` (`mining.ml:389-393`):

```ocaml
let extra_nonce = Cstruct.create 8 in
let ts = Int64.of_float (Unix.gettimeofday () *. 1000000.0) in
Cstruct.LE.set_uint64 extra_nonce 0 ts;
```

The extra_nonce is the wall-clock time in microseconds. Two GBT calls
within the same microsecond produce IDENTICAL coinbases (and thus
identical block hash for the same nonce/timestamp). Core's
`IncrementExtraNonce` (legacy) increments a counter; modern Core
expects the mining client to provide the extra-nonce via the GBT
miner-side replacement path.

Same code path at `rpc.ml:2123-2125` in `handle_generateblock`.

Impact in practice:
- regtest `generate N` calls under load can produce two templates
  with identical coinbase if the OCaml process generates them within
  a single μs (rare on modern hardware but not impossible);
- a miner that doesn't replace the extra_nonce sees deterministic
  templates → if `mintime`/`now` align, the same nonce-search space
  is hashed twice;
- the comment at `mining.ml:391` `(* In production, this would be
  randomized. For now, use timestamp-based *)` is a comment-as-confession
  (**fleet pattern, 12th camlcoin instance, +1 to running total** —
  prior count was 12 fleet-wide per index).

**File:** `lib/mining.ml:389-393`; `lib/rpc.ml:2123-2125`.

**Core ref:** `bitcoin-core/src/node/miner.cpp` legacy
`IncrementExtraNonce` (now replaced by client-side responsibility).

**Impact:** rare duplicate-template risk; less efficient nonce-space
search on regtest tooling that calls `generate` in a hot loop.

---

## BUG-21 (P0-CDIV) — Mining never validates final coinbase `nValue ≤ MAX_MONEY` (defense-in-depth gap)

**Severity:** P0-CDIV. `create_coinbase` (`mining.ml:264-333`) computes:

```ocaml
let subsidy = Consensus.block_subsidy_for_network network_type height in
let reward = Int64.add subsidy total_fee in
...
value = reward;
```

`Int64.add` is unchecked. No `Consensus.is_valid_money reward` check.
Cross-cite BUG-13 (JSON-side) — but this is the **transaction-side**
of the same gap. A 64-bit overflow in `Int64.add subsidy total_fee`
would produce a coinbase with negative `nValue` or a wrap-around to
small positive, and the template would still be constructed and
returned.

camlcoin's mempool ATMP gates fees per-tx with `is_valid_money`
(`consensus.ml:822-823`), so each entry's fee is ≤ MAX_MONEY. The sum
of N fees can exceed MAX_MONEY only if N is large; e.g.
`MAX_MONEY ≈ 2.1e15` sats, sum of 1000 max-fee txs is `≈ 2.1e18` sats
which DOES overflow Int64. Latent on honest mempool, possible on
adversarial-fee mempool entry.

**File:** `lib/mining.ml:267-270, 295-297`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:178-179` (Core uses
`CAmount` which is `int64_t`; same Int64 risk in principle, but Core's
`TestBlockValidity` catches the resulting block, see BUG-12).

**Impact:** latent overflow primitive; chains with BUG-12 (no test
gate) propagate the bad template to miners.

---

## BUG-22 (P1) — `generateblock` constructs a template manually (forks the mining pipeline)

**Severity:** P1 ("two-pipeline guard 17th fleet instance —
mining-side"). `handle_generateblock` (`rpc.ml:2060-2188`) does NOT
call `Mining.create_block_template`. Instead it:
- duplicates the coinbase creation logic (`rpc.ml:2122-2135`),
- duplicates the witness merkle / commitment computation
  (`rpc.ml:2131-2135`),
- duplicates the MTP collection walk (`rpc.ml:2141-2153`),
- hardcodes `version = 0x20000000l` instead of running
  `compute_block_version` (`rpc.ml:2157`),
- hardcodes `bits = ctx.network.pow_limit` (regtest only —
  acceptable),
- builds a `block_template` record manually with `tx_fees = []` and
  `total_weight = 0` (`rpc.ml:2168, 2170`).

This is the classic **two-pipeline drift** pattern. Changes to
`Mining.create_block_template` (e.g. BUG-7 BIP-94 fix when wired) will
NOT propagate to `generateblock`. Both paths funnel into
`Mining.mine_block` + `Mining.submit_block` (line 2177, 2180), but the
template assembly diverges.

Specific divergence consequences:
- `generateblock`-built templates have `tx_fees = []` (line 2168) —
  if downstream code consults `tx_fees`, it sees no entries.
- `generateblock`-built templates have `total_weight = 0` (line 2170)
  — `getmininginfo` would report zero weight for the latest
  regtest-generated block.
- `version` is fixed at `0x20000000` ignoring active BIP-9 signaling
  (taproot etc.), so regtest BIP-9 deployment tests are broken.

Cross-cite the W123 5-cascading-sub-paths shape and the
8-CONSECUTIVE-QUAD camlcoin pipeline drift family (W143/W144/W145/
W149/W150/W151/W152/W153). This is the **mining-side** new occurrence
within that family.

**File:** `lib/rpc.ml:2060-2188`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp::generateblock`
(reuses BlockAssembler::CreateNewBlock, not a parallel pipeline).

**Impact:** regtest BIP-9 deployment tests via `generateblock` see
wrong `version` field; `getmininginfo` reports zero for the latest
regtest block; future mining-side fixes risk skipping the
`generateblock` path.

---

## Summary

**Bug count:** 22 (BUG-1 through BUG-22).

**Severity distribution:**
- **P0-CDIV:** 6 (BUG-7, BUG-12, BUG-14, BUG-15, BUG-16, BUG-21)
- **P0-CONS:** 1 (BUG-5)
- **P0:** 2 (BUG-13, BUG-17)
- **P1:** 11 (BUG-1, BUG-2, BUG-3, BUG-6, BUG-8, BUG-9, BUG-10,
  BUG-11, BUG-20, BUG-22, + half of BUG-19 — listed as P2 below)
- **P2:** 3 (BUG-4, BUG-18, BUG-19)

Recount sanity:
- P0-CDIV: BUG-7, BUG-12, BUG-14, BUG-15, BUG-16, BUG-21 = 6
- P0-CONS: BUG-5 = 1
- P0: BUG-13, BUG-17 = 2
- P1: BUG-1, BUG-2, BUG-3, BUG-6, BUG-8, BUG-9, BUG-10, BUG-11,
  BUG-20, BUG-22 = 10
- P2: BUG-4, BUG-18, BUG-19 = 3
Total: 6 + 1 + 2 + 10 + 3 = 22. ✓

P0-class total (P0-CDIV + P0-CONS + P0): 9.

**Fleet patterns confirmed / extended:**
- **"8-CONSECUTIVE-QUAD camlcoin pipeline drift"** family extends
  to MINING (W143 + W144 + W145 + W149 + W150 + W151 + W152 + W153
  + W154 = 9-CONSECUTIVE-QUAD): BUG-22 `handle_generateblock` is the
  9th distinct site where camlcoin coexists two production code paths
  through consensus-adjacent code.
- **"block_import.ml-bypass family"** extends to mining: BUG-12
  (`TestBlockValidity` not run on the build path) is the canonical-
  gate-not-wired counterpart on the offensive side.
- **"two-pipeline guard 17th distinct fleet extension"** (BUG-22)
  — first mining-side instance.
- **"dead-data plumbing"** (BUG-3 `network.segwit_height`,
  BUG-17 `network_config.halving_interval`) — camlcoin 11th + 12th
  distinct instances.
- **"comment-as-confession"** (BUG-20 line `mining.ml:391`
  `(* In production, this would be randomized. *)`) — camlcoin's
  12th distinct comment-as-confession instance.
- **"wire-format divergence"** (BUG-14 `coinbasevalue` String vs NUM,
  BUG-15 `sizelimit` 1_000_000 vs 4_000_000) — joins the
  W141 ZMQ-hash-byte-order fleet pattern.
- **"canonical-gate-not-wired"** (BUG-12 `TestBlockValidity`) —
  camlcoin's 4th post-W123 instance.
- **"hardcoded constant should be params-aware"** (BUG-15 sizelimit,
  BUG-17 halving_interval consult).
- **"undercount in JSON despite correct internal computation"**
  (BUG-16 sigops) — first instance, candidate for fleet check
  (rustoshi/blockbrew/clearbit etc. may have similar undercount in
  their GBT response).

**Top three findings:**
1. **BUG-12 (P0-CDIV `TestBlockValidity` post-build gate absent)** —
   `create_block_template` returns templates with NO validation pass.
   Any upstream regression (BUG-2 modified-fee, BUG-13 MAX_MONEY,
   future selection bugs) propagates uncaught to the miner. Core's
   safety net does not exist in camlcoin's mining path. Cross-cite
   the W144 canonical-gate-not-wired fleet pattern.
2. **BUG-7 (P0-CDIV BIP-94 MAX_TIMEWARP clamp missing on miner-side
   at retarget boundary)** — camlcoin testnet4 miner-side chain-split
   candidate when wall-clock < parent_time - 600 s at every retarget
   boundary. Latent on other networks until BIP-94 enforcement
   spreads to mainnet.
3. **BUG-14 + BUG-15 (P0-CDIV cluster: GBT JSON wire-format
   divergence)** — `coinbasevalue` emitted as String not NUM,
   `sizelimit` hardcoded to pre-segwit 1_000_000 not 4_000_000.
   Miner clients break day-1 on coinbasevalue parse and silently cap
   blocks at 1 MB serialized size, producing suboptimal block rewards
   vs Core-served templates.

**Carry-forward from prior waves (re-anchored at W154):**
- BUG-2 ← W123 BUG-1 (chunk linearization raw-fee, 5 cascading sub-paths)
- BUG-4 ← W123 BUG-2 (UpdateUncommittedBlockStructures absent)
- BUG-6 ← W108 BUG-9 / W123 G20 (mintime = curtime not MTP+1)
- BUG-17 ← W145 BUG-2 (block_subsidy_for_network ignores network_config.halving_interval)
- BUG-18 ← W123 BUG-3 (submitheader RPC absent)
- BUG-19 ← W123 BUG-4 (getmininginfo current-block stats zero)

**Mining-side W154 NEW findings (first surfaced):**
BUG-3, BUG-5, BUG-7, BUG-8, BUG-9, BUG-10, BUG-11, BUG-12, BUG-13,
BUG-14, BUG-15, BUG-16, BUG-20, BUG-21, BUG-22 = 15 new findings.

---

## References

- `bitcoin-core/src/node/miner.cpp:36-47, 79-88, 111-120, 122-237,
  239-260, 67-77, 90-96, 98-109, 186-194, 195-197, 200, 215`
- `bitcoin-core/src/node/miner.h:42-57, 60-123, 134-145`
- `bitcoin-core/src/validation.cpp:3870-3902, 3987, 3997-4019`
- `bitcoin-core/src/consensus/consensus.h:13, 15, 21, 23`
- `bitcoin-core/src/consensus/tx_check.cpp:49`
- `bitcoin-core/src/rpc/mining.cpp:632, 684-694, 950-963, 1001-1016`
- `bitcoin-core/src/kernel/chainparams.cpp` per-network deployment params
- Prior camlcoin audits: `audit/w123_mining_gbt.md`,
  `CORE-PARITY-AUDIT/w142-segwit-witness-validation.md`,
  `CORE-PARITY-AUDIT/w143-block-validation.md`,
  `CORE-PARITY-AUDIT/w145-subsidy-fees-maxmoney.md`,
  `CORE-PARITY-AUDIT/w149-pruning-assumevalid-minimumchainwork.md`
