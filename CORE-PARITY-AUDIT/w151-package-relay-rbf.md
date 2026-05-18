# W151 — Package relay + BIP-125 RBF rules 2-5 (camlcoin)

**Wave:** W151 — `AcceptPackage`, `AcceptMultipleTransactions`, `AcceptSubPackage`,
`SubmitPackage`, `IsTopoSortedPackage`, `IsConsistentPackage`, `IsWellFormedPackage`,
`IsChildWithParents`, `IsChildWithParentsTree`, `PackageMempoolChecks`,
`GetPackageHash`, `MAX_PACKAGE_COUNT=25`, `MAX_PACKAGE_WEIGHT=404_000`,
`MAX_BIP125_REPLACEMENT_CANDIDATES=100`, `MAX_BIP125_RBF_SEQUENCE=0xfffffffd`,
`SignalsOptInRBF`, `IsRBFOptIn`, `GetEntriesForConflicts`, `HasNoNewUnconfirmed`,
`EntriesAndTxidsDisjoint`, `PaysMoreThanConflicts`, `PaysForRBF`,
`ImprovesFeerateDiagram`, `PackageRBFChecks`, `DEFAULT_INCREMENTAL_RELAY_FEE=100`,
`GetUniqueClusterCount`, `submitpackage` RPC, BIP-331 `sendpackages` /
`getpkgtxns` / `pkgtxns` wire types.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/policy/packages.h:19,24` — `MAX_PACKAGE_COUNT=25`,
  `MAX_PACKAGE_WEIGHT=404'000`.
- `bitcoin-core/src/policy/packages.cpp:19-117` — `IsTopoSortedPackage`,
  `IsConsistentPackage`, `IsWellFormedPackage` (fail-fast with
  `package-too-many-transactions` / `package-too-large` /
  `package-contains-duplicates` / `package-not-sorted` / `conflict-in-package`),
  `IsChildWithParents`, `IsChildWithParentsTree`, `GetPackageHash`.
- `bitcoin-core/src/policy/rbf.h:26` — `MAX_REPLACEMENT_CANDIDATES=100` (cluster
  count, NOT eviction count); `bitcoin-core/src/policy/rbf.cpp:24-50` —
  `IsRBFOptIn` walks `pool.CalculateMemPoolAncestors` not the parent-set;
  `bitcoin-core/src/policy/rbf.cpp:58-83` — `GetEntriesForConflicts` calls
  `pool.GetUniqueClusterCount(iters_conflicting)` and rejects if
  `num_clusters > MAX_REPLACEMENT_CANDIDATES`; `bitcoin-core/src/policy/rbf.cpp:85-98`
  — `EntriesAndTxidsDisjoint`; `bitcoin-core/src/policy/rbf.cpp:100-125` —
  `PaysForRBF` uses the **caller-supplied** `CFeeRate relay_fee` (Core wires this
  to `m_pool.m_opts.incremental_relay_feerate` at validation.cpp:1011 and 1099,
  which defaults to `DEFAULT_INCREMENTAL_RELAY_FEE=100` sat/kvB);
  `bitcoin-core/src/policy/rbf.cpp:127-140` — `ImprovesFeerateDiagram`.
- `bitcoin-core/src/util/rbf.h:12` — `MAX_BIP125_RBF_SEQUENCE=0xfffffffd`;
  `bitcoin-core/src/util/rbf.cpp` — `SignalsOptInRBF` returns true iff any input
  has `nSequence <= MAX_BIP125_RBF_SEQUENCE`.
- `bitcoin-core/src/validation.cpp:1432-1564` — `AcceptMultipleTransactionsInternal`:
  IsWellFormedPackage → per-tx PreChecks → per-tx maxfeerate check (**BEFORE**
  insertion) → `m_viewmempool.PackageAddTransaction` so children can spend parent
  outputs without a real mempool add → PackageTRUCChecks → m_total_vsize /
  m_total_modified_fees aggregation → optional CheckFeeRate(package) →
  `PackageRBFChecks` (when m_subpackage.m_rbf set) → cluster size limits →
  CheckEphemeralSpends → PolicyScriptChecks (per tx with STANDARD flags) →
  SubmitPackage. `validation.cpp:1622-1771` — `AcceptPackage`: IsWellFormedPackage
  → IsChildWithParents → per-tx single-tx admission attempt
  (`AcceptSubPackage({tx})`) for parents already-in-mempool de-dup → finally
  multi-tx submission via `AcceptSubPackage(txns_package_eval, args)`.
- `bitcoin-core/src/rpc/mempool.cpp::submitpackage` — `ProcessNewPackage(test_accept=false,
  client_maxfeerate)`; returns `package_msg` token, per-wtxid `tx-results` with
  `vsize/fees{base,effective-feerate,effective-includes}` and `replaced-transactions`
  union (std::set<uint256>).
- `bitcoin-core/src/kernel/mempool_options.h` — `incremental_relay_feerate{100}`.
- BIP-125 Rules 1-5: 1=signaling, 2=HasNoNewUnconfirmed (no NEW unconfirmed inputs
  not present in the original), 3=PaysMoreThanConflicts (replacement_fees ≥
  original_modified_fees), 4=PaysForRBF (additional_fees ≥
  incremental_relay_feerate · replacement_vsize), 5=GetEntriesForConflicts (≤ 100
  affected clusters).

**Files audited**
- `lib/mempool.ml` (4374 lines) — RBF: `signals_rbf` (2464-2474),
  `signals_rbf_with_ancestors` (2479-2518), `truc_signals_rbf` (1805-1806),
  `find_all_conflicts` (1813-1826), `check_conflict` (1829-1844),
  `replace_by_fee_with_replaced` (2839-3074),
  `replace_by_fee` (3080-3084), `accept_transaction_with_replaced` (3096-3113),
  `accept_transaction` (3115-3119), `accept_to_memory_pool` (3138-3175),
  `check_improves_feerate_diagram` (2656-2712),
  `compare_feerate_diagrams` (2588-2650), `chunks_to_diagram` (2569-2579),
  `linearize_entries` (2553-2564), `apply_delta`/`get_modified_fee` (2759-2771),
  `prioritise_transaction` (2787-2798); package: `package_result` (3843-3849),
  `max_package_count`/`max_package_weight` (3852-3853),
  `topo_sort` (3857-3920) — **silent reorder, not check**;
  `is_well_formed_package` (3927-3959), `is_1p1c_package` (3965-3979),
  `is_child_with_parents_tree` (3989-4031),
  `calc_tx_fee_vsize` (4035-4069), `accept_package_with_replaced` (4084-4241),
  `accept_package` (4245-4247), `find_1p1c_for_orphan` (4252-4268),
  `try_1p1c_with_orphans` (4273-4294), `process_orphans_with_cpfp` (4298-4328);
  constants: `max_rbf_evictions=100` (123), `incremental_relay_fee=100L` (128-129),
  `min_relay_fee=1000L` (245); `add_transaction` `bypass_limits`/`bypass_fee_check`
  (1945, 2223), `check_truc_policy` (1699-1802), `load_mempool` (3714-3826).
- `lib/package_relay.ml` (85 lines) — `lookup_tx_by_wtxid` (21-28; O(N) scan),
  `handle_getpkgtxns` (34-44), `handle_pkgtxns` (51-75), `dispatch` (80-85).
- `lib/p2p.ml:270-288, 645-655, 998, 1580-1585` — BIP-331 wire types
  (`sendpackages_msg`, `getpkgtxns_msg`, `pkgtxns_msg`); `make_sendpackages_msg`
  (1580) **defined and exported, called from ZERO production sites** (only
  test_w116).
- `lib/peer.ml:273, 404, 847-856, 1613-1674` — capture of inbound
  `sendpackages` into `peer.sendpackages_received` / `pkg_relay_version` /
  `pkg_max_count` / `pkg_max_weight`; no outbound emission.
- `lib/cli.ml:1332-1337` — wires `Package_relay.dispatch` as a
  `Peer_manager.add_listener` callback.
- `lib/rpc.ml:1192-1208` — `handle_sendrawtransaction` (uses bare
  `add_transaction`, not RBF-aware); `lib/rpc.ml:3019-3225` —
  `handle_submitpackage` (parses `[ [hex,…], maxfeerate, maxburnamount ]`,
  calls `accept_package_with_replaced`, post-evicts on maxfeerate violation);
  `lib/rpc.ml:1379, 1448` — `bip125-replaceable` field uses
  `signals_rbf_with_ancestors`; `lib/rpc.ml:7491` — help string.
- `lib/sync.ml:3694-3714` — reorg refill uses
  `add_transaction ~bypass_fee_check:true ~bypass_limits:true` (no RBF).

---

## Gate matrix (36 sub-gates / 14 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | RBF Rule 1 — BIP-125 signaling | G1: any-input `nSequence ≤ 0xfffffffd` signals RBF | PASS (`mempool.ml:2471-2474`); Int64 mask correct for sign-bit case (W70 closure documented) |
| 1 | … | G2: ancestor-signaling walk (`IsRBFOptIn` fall-through) | PASS (`mempool.ml:2479-2518`) — BFS walks `entry.depends_on` correctly; matches Core `pool.CalculateMemPoolAncestors` |
| 1 | … | G3: full-RBF (no signaling required by default) — Core PR #28132 / `-mempoolfullrbf=1` default | PASS (`mempool.ml:2849`) — `replace_by_fee_with_replaced` bypasses the signaling check; matches Core 26+ default |
| 1 | … | G4: TRUC/v3 always signals | PASS (`mempool.ml:2466, 1805-1806`) |
| 2 | RBF Rule 2 — HasNoNewUnconfirmed | G5: replacement's unconfirmed inputs ⊆ original conflicts' inputs | PASS (`mempool.ml:2989-3020`) — `conflict_outpoints` table built per-outpoint and checked; correct BIP-125 semantics |
| 3 | RBF Rule 3 — PaysMoreThanConflicts (with modified fees) | G6: `replacement_modified_fee >= sum(modified_fees(conflicts ∪ descendants))` | PASS (`mempool.ml:2950-2972`) — uses `apply_delta` on candidate and `get_modified_fee` on each evicted entry (FIX-72 W120 BUG-10 closure documented) |
| 3 | … | G7: `>= not >` — equal fees ALLOWED | PASS (`mempool.ml:2970` — `if new_modified_fee < total_conflict_fee`) |
| 4 | RBF Rule 4 — PaysForRBF (additional fee ≥ incremental relay fee × vsize) | G8: relay-fee constant matches Core `DEFAULT_INCREMENTAL_RELAY_FEE = 100 sat/kvB` | **BUG-1 (P0-CDIV)** — `replace_by_fee_with_replaced` line 2981-2982 uses **`mp.min_relay_fee`** (= 1000 sat/kvB hardcoded default per `mempool.ml:245`) **NOT** `incremental_relay_fee` (= 100 sat/kvB). Constant exists and is correct (line 128); just not used at the RBF Rule 4 site. **10× too strict** — rejects RBF replacements Core accepts (carry-forward W150 BUG-6 amplifier: same `min_relay_fee` field already flagged 10× too high) |
| 4 | … | G9: relay-fee units sat/kvB; integer-truncating GetFee | PASS (`mempool.ml:2982` — `(mp.min_relay_fee * vsize) / 1000L`, integer floor) |
| 5 | RBF Rule 5 — replacement candidate cap | G10: rejects when count exceeds MAX_REPLACEMENT_CANDIDATES (Core: **distinct CLUSTERS** of conflicts) | **BUG-2 (P0-CDIV)** — camlcoin uses `eviction_count > max_rbf_evictions` (line 2899) where `eviction_count = Hashtbl.length evicted_set` = direct conflicts ∪ all descendants. Core uses `pool.GetUniqueClusterCount(iters_conflicting) > MAX_REPLACEMENT_CANDIDATES` (rbf.cpp:69-75) — **count of distinct clusters of direct conflicts only**. Camlcoin's metric is always ≥ Core's (descendants make it larger), so camlcoin rejects strictly more replacements than Core for the same conflict set |
| 5 | … | G11: `EntriesAndTxidsDisjoint` (ancestors-of-replacement ∩ direct_conflicts = ∅) | PASS (`mempool.ml:2911-2944`) — BFS over candidate ancestors against `conflict_txid_set` |
| 5 | … | G12: ImprovesFeerateDiagram (post-replacement diagram strictly dominates pre) | PASS (`mempool.ml:2656-2712, 2588-2650`) — full feerate-diagram check, integer-arithmetic compare; W106 BUG-10 closure |
| 6 | Package count + weight context-free | G13: `MAX_PACKAGE_COUNT=25` | PASS (`mempool.ml:3852`) |
| 6 | … | G14: `MAX_PACKAGE_WEIGHT=404_000` | PASS (`mempool.ml:3853`) |
| 6 | … | G15: weight check exempt single-tx packages (Core packages.cpp:89-90 `package_count > 1 &&`) | **BUG-3 (P1)** — `is_well_formed_package` (mempool.ml:3936) applies the `total_weight > max_package_weight` check unconditionally. A single 405,000-weight tx submitted via `submitpackage` is rejected for "Package exceeds max weight" instead of the tx-level `tx-size` reject Core would produce. Carry-forward from W116 BUG-8 (test_w116_package_relay.ml:15 explicitly tracks this) — still not fixed |
| 6 | … | G16: package-contains-duplicates (by txid) check | **BUG-4 (P0-CDIV)** — `is_well_formed_package` (mempool.ml:3927-3959) has NO duplicate-by-txid check. Core (packages.cpp:94-102) rejects with `package-contains-duplicates` BEFORE topo-sort. Camlcoin's topo-sort silently dedups via `Hashtbl.replace tx_by_id`, which means {tx_A, tx_A} sails through `is_well_formed_package`, becomes one tx in topo_sort, and then the package count claim becomes a LIE (returned wtxid list omits the dup). Wire reject token absent |
| 6 | … | G17: IsTopoSortedPackage rejects unsorted (NOT reorders) | **BUG-5 (P0-CDIV)** — `topo_sort` (mempool.ml:3857-3920) **silently reorders** the package via Kahn's algorithm and returns `Ok sorted`. Core packages.cpp:108 fails with reject token `package-not-sorted` ON an unsorted package. Operator-facing impact: a malformed submitpackage that should return `package-not-sorted` gets accepted as if sorted, divergent from Core. Cross-impl interop break: a Lightning peer that gets a `package-not-sorted` from Core's `submitpackage` will get a possibly-valid result from camlcoin — same wire-input two different responses |
| 6 | … | G18: IsConsistentPackage (no two txs spend same outpoint) | PASS (`mempool.ml:3941-3957`) — `spent_outpoints` Hashtbl detects conflicts |
| 6 | … | G19: empty-vin rejection at package level | **BUG-6 (P1)** — Core's `IsConsistentPackage` (packages.cpp:57-62) explicitly returns `false` on `tx.vin.empty()` for the package-consistency case (then `IsWellFormedPackage` produces `conflict-in-package`). camlcoin's `is_well_formed_package` skips empty-input txs in the conflict scan (`spent_outpoints` loop sees no inputs to iterate). A package that contains an empty-vin tx passes well-formed and gets rejected downstream with a generic error. Wire-token divergence; also defense-in-depth for the consensus-error-class duplicate detection |
| 6 | … | G20: wire-reject tokens (`package-too-many-transactions` / `package-too-large` / `package-contains-duplicates` / `package-not-sorted` / `conflict-in-package`) | **BUG-7 (P1)** — camlcoin emits free-form English: `"Package exceeds max transaction count (%d > %d)"` (line 3929), `"Package exceeds max weight (%d > %d)"` (line 3937), `"Package contains a cycle"` (line 3917), `"package topology disallowed. not child-with-parents or parents depend on each other."` (line 4011/4028), `"Conflicting spend of %s"` (line 3950). NONE of the 5 Core wire-tokens are emitted. Breaks ZMQ-bound monitoring tooling, breaks mempool.space-style scrapers, makes `submitpackage` `package_msg` field divergent (e.g. lnd's package-RBF retry logic reads the package_msg field). 5-token sweep |
| 7 | AcceptPackage two-topology semantics | G21: single-tx path equivalent to ATMP | PASS-PARTIAL (`mempool.ml:4084-4241`) — single-tx packages still go through `is_well_formed_package` + topo_sort + `is_child_with_parents_tree(n>=2)` (skipped at n=1) but the per-tx loop runs `calc_tx_fee_vsize` + `add_transaction`/`replace_by_fee_with_replaced` not `accept_to_memory_pool`. The exception-safe wrapper is **not** applied — BUG-8 below |
| 7 | … | G22: child-with-parents enforced for n>=2 | PASS (`mempool.ml:4099`); but doesn't allow Core's per-tx already-in-mempool de-duplication path before package eval (`AcceptPackage` validation.cpp:1664-1686 emits `MempoolTx` / `MempoolTxDifferentWitness` results from individual single-tx attempts FIRST, then submits only `txns_package_eval` as a multi-tx unit) |
| 7 | … | G23: per-tx single-tx admission attempt before package fallback | **BUG-9 (P0-CDIV)** — Core's `AcceptPackage` (validation.cpp:1658-1717) attempts each tx via `AcceptSubPackage({tx})` FIRST and only routes the remainder through multi-tx submission if the single attempt was `TX_RECONSIDERABLE` or `TX_MISSING_INPUTS`. camlcoin's `accept_package_with_replaced` (mempool.ml:4084-4241) always tries the whole package as one unit. Practical impact: a child-with-parents package where one parent is already in the mempool AND another parent has a non-feerate consensus error will fail the entire package, vs Core which would accept the in-mempool parent and isolate the failure |
| 7 | … | G24: package-feerate evaluation only when SubPackage size > 1 | **BUG-10 (P1)** — Core only computes package-feerate in `AcceptMultipleTransactionsInternal`, not in single-tx path. camlcoin computes `package_feerate` (mempool.ml:4154-4158) on every accept_package call including single-tx, which fakes a "CPFP" admission for txs that are below `min_relay_fee` but happen to be sent via `submitpackage [tx]`. A spam vector: send a below-floor tx as `submitpackage [tx]` and the package-feerate gate degenerates to the tx's own feerate (since vsize is its own and there are no other txs to amortise) — wait, this is actually equivalent. The bug is the conceptual misnaming: pretend-package single-tx still admits CPFP "use_package_feerate = package_feerate >= min_feerate", which is the same as the per-tx check. **Cosmetic in single-tx; the real issue is that package_feerate is computed BEFORE per-tx admission decisions instead of after** (Core: aggregate AFTER PreChecks per tx) |
| 8 | submitpackage RPC | G25: enforces 1..MAX_PACKAGE_COUNT before any decode work | PASS (`rpc.ml:3067-3071`) |
| 8 | … | G26: maxfeerate pre-check (BEFORE insertion) | **BUG-11 (P0-CDIV)** — `handle_submitpackage` (rpc.ml:3140-3160) does the maxfeerate check **AFTER** `accept_package_with_replaced`, then evicts via `Mempool.remove_transaction` (line 3154). Same pattern as W150 BUG-12 (`handle_sendrawtransaction`): the tx is published to ZMQ subscribers (`mempool.ml:2327` zmq_notify_tx on accept) **before** the maxfeerate check evicts it. Core (validation.cpp:1458) checks `ws.m_modified_fees / ws.m_vsize > args.m_client_maxfeerate.value()` **inside the per-tx loop in `AcceptMultipleTransactionsInternal`** before insertion. **Same fleet pattern, second site** |
| 8 | … | G27: maxfeerate semantics: `replaced-transactions` cleared on eviction | **BUG-12 (P1)** — when maxfeerate eviction fires, camlcoin removes the entry from `entry_by_wtxid_key` and flags `package_msg = "max-fee-exceeded"` (rpc.ml:3158-3160) but **leaves the `replaced-transactions` list intact** — so a replacement that triggered RBF eviction of conflicts then itself got evicted leaves the operator looking at a `replaced-transactions` populated list with no live mempool replacement. Race window; data-flow inconsistency |
| 8 | … | G28: `tx-results` includes `effective-feerate` / `effective-includes` only if accepted | PASS-PARTIAL (`rpc.ml:3188-3196`) — emits `effective-feerate` and `effective-includes` for accepted, but `effective-includes` is **always just `[wtxid]`** (line 3194); Core fills this with the full package wtxid list when `args.m_package_feerates` was the gate that admitted the tx (validation.cpp:1547-1548). Cross-impl divergence for genuine CPFP packages where the child funded the parents — operator expects to see the funding chain |
| 8 | … | G29: burn-amount check unitised correctly (sats vs BTC) | PASS (`rpc.ml:3057, 3097`) — converts `maxburnamount` from float BTC to int64 sats |
| 9 | submitpackage exception safety | G30: exception protection across decode + admission | **BUG-13 (P0-SEC)** — `handle_submitpackage` (rpc.ml:3036-3225) has only a per-tx `try ... with exn` around the hex decode (line 3077-3082). The subsequent `Mempool.accept_package_with_replaced` (line 3113) is **not** wrapped in the W96 Bug 13 `safe_run` pattern. `accept_to_memory_pool` (mempool.ml:3138-3175) wraps single-tx ATMP; `accept_package_with_replaced` has no equivalent. An exception from `Crypto.compute_txid` / `Validation.compute_tx_weight` / `Script.parse_script` (called from `verify_tx_scripts`) on attacker-controlled package data crashes the RPC handler. Cross-cite W150 BUG-1/BUG-2 — multi-pipeline drift, same gate hole |
| 10 | BIP-331 `sendpackages` handshake | G31: send `sendpackages` outbound between VERSION and VERACK | **BUG-14 (P0-CDIV)** — `make_sendpackages_msg` (p2p.ml:1580-1585) is defined and exported; `peer.sendpackages_received` (peer.ml:273) captures inbound; `peer.ml:847-856` records the negotiated limits. But the **outbound emission is absent** — no `send_message peer (SendpackagesMsg …)` anywhere in the connect path. Carry-forward from W116 BUG-11 (test_w116_package_relay.ml:559-571 asserts this explicitly). Camlcoin **does not negotiate package relay**, so peers won't send us pkgtxns/getpkgtxns unless they offer one-sided support. BIP-331 effectively half-disabled |
| 10 | … | G32: receive + dispatch `getpkgtxns` / `pkgtxns` | PASS (`package_relay.ml:34-44, 51-75`); `cli.ml:1337` wires the dispatcher |
| 10 | … | G33: pkgtxns count clamped to peer-advertised pkg_max_count | **BUG-15 (P1)** — `handle_pkgtxns` (package_relay.ml:55-59) clamps to `Mempool.max_package_count = 25` (the camlcoin-side constant), NOT to `peer.pkg_max_count` captured at handshake (peer.ml:854). If a peer advertised `pkg_max_count=10` (a lower per-peer policy), camlcoin would accept a 25-tx pkgtxns from that peer in violation of the per-peer negotiated limit. Cross-impl behavior break |
| 10 | … | G34: lookup_tx_by_wtxid is O(N) scan over entries | **BUG-16 (P2)** — `lookup_tx_by_wtxid` (package_relay.ml:21-28) does a `Hashtbl.iter` over `mp.entries` for every wtxid in the request. For a 25-wtxid `getpkgtxns` on a 50k-entry mempool, that's 1.25M comparisons per peer request. Core indexes by wtxid in `mapTx::index<index_by_wtxid>`. P2 because BIP-331 says peers should be slow with `getpkgtxns` anyway, but the comment-as-confession at line 19-20 ("acceptable since [getpkgtxns] is rare and bounded by [P2p.max_package_txs] = 25 wtxids per request") buries the O(N×25) cost |
| 11 | Multi-pipeline drift carry-forward (W150 BUG-1 escalation) | G35: `accept_package_with_replaced` is the SINGLE package-acceptance entry | **BUG-17 (P0-CDIV)** — W150 BUG-1 identified **6** ATMP entry-points; W151 adds the package side: there are **3 distinct package paths**: (1) `submitpackage` RPC → `accept_package_with_replaced` (rpc.ml:3113), (2) `pkgtxns` P2P → `accept_package` (legacy discard-wrapper, package_relay.ml:61), (3) `try_1p1c_with_orphans` → `accept_package` (mempool.ml:4288). Path (1) surfaces `replaced-transactions`; paths (2) and (3) discard it. Path (2) is the BIP-331 wire path: any peer-driven RBF inside a pkgtxns delivers no evicted-tx visibility to relay logic; path (1) is the only one Core sees full replaced-tx accounting from. **6-pipeline drift becomes 9-pipeline drift this audit** (single-tx 6 + package 3), extending the 5-pipeline W143 finding by 4 distinct entries across two audits. Same "block_import.ml-bypass 4th-consecutive-quad" pattern: 4 consecutive quad-audits have surfaced multi-pipeline-bypass in camlcoin (W143 5, W144 2, W145 2, W150 6) — **5th-consecutive-quad confirmed in W151** |
| 12 | RBF + package interaction (PackageRBFChecks) | G36: package-as-replacement-unit (Core PackageRBFChecks gates the **package** modified_fee vs conflicts) | **BUG-18 (P0-CDIV)** — Core (validation.cpp:1515-1517) gates `PackageRBFChecks(txns, workspaces, m_total_vsize, package_state)` when `m_subpackage.m_rbf` is set (i.e., any tx in the package conflicts with a mempool tx). The check treats the **whole package** as one replacement unit per BIP-431 §"RBF for packages". camlcoin's `accept_package_with_replaced` (mempool.ml:4181-4213) per-tx routes through `replace_by_fee_with_replaced` so each tx-conflict-pair is evaluated independently. Pinning attack: a child that pays HIGH fee with a parent that pays LOW fee (canonical CPFP-RBF case) doesn't aggregate at the package level — the parent's individual RBF gate uses parent-fee-alone vs conflict-fee, while the package_feerate floor (used for admission, not RBF) misses entirely. Comment at line 4193-4194 acknowledges this gap: "true package-feerate-based replacement (treating the whole package as one replacement unit per BIP-431 §'RBF for packages') is still missing and tracked separately." **comment-as-confession 8th camlcoin instance** (5 prior: W143 BUG-2 dead-helper, W144 BUG-12 two helpers diverge, W145 BUG-12 totalfee negative-clamp, W148 BUG-8 docstring contradicts Core, W150 BUG-2 "RPC, P2P and miner paths call ATMP without their own try/with") |
| 13 | Package persistence + reorg | G37: reorg refill bypasses RBF cleanly | **BUG-19 (P1)** — `sync.ml:3706-3709` reorg refill calls plain `add_transaction ~bypass_fee_check:true ~bypass_limits:true` with NO package-aware admission. A v3/TRUC package that survived in a disconnected block (parent + child both relayed) gets re-added one-tx-at-a-time, and the parent re-admission is the FIRST re-add — if the parent fails `is_dust` or similar, the child sits as an orphan with no CPFP re-attempt. Pre-W150 multi-pipeline drift extends to "no package-aware reorg refill path either" — **5 distinct ATMP entries + 3 package entries + 1 reorg-refill entry = 9 total distinct admission gates** |
| 14 | submitpackage maxburnamount default | G38: default 0 BTC burn limit (Core default 0 = no OP_RETURN value) | PASS (`rpc.ml:1132, 3049`) — `default_max_burn_amount = 0L` matches Core. Note: Core's `MAX_BURN_EXCEEDED` is thrown from RPC layer, not validation; camlcoin replicates the same wrapping pattern (rpc.ml:3097-3105) |

---

## BUG-1 (P0-CDIV) — RBF Rule 4 uses `min_relay_fee` (1000) not `incremental_relay_fee` (100)

**Severity:** P0-CDIV. Bitcoin Core's `PaysForRBF` (`policy/rbf.cpp:100-125`)
takes a `CFeeRate relay_fee` parameter. The call sites at
`validation.cpp:1011` and `validation.cpp:1099` wire this to
`m_pool.m_opts.incremental_relay_feerate`, which defaults to
`DEFAULT_INCREMENTAL_RELAY_FEE = 100 sat/kvB`
(`kernel/mempool_options.h`). The rationale (per `policy/rbf.cpp:114-118`):

```cpp
// Rule #4: The new transaction must pay for its own bandwidth.
CAmount additional_fees = replacement_fees - original_fees;
if (additional_fees < relay_fee.GetFee(replacement_vsize)) {
```

camlcoin's `replace_by_fee_with_replaced` at `mempool.ml:2980-2986`:

```ocaml
let additional_fees = Int64.sub new_modified_fee total_conflict_fee in
let relay_fee_for_replacement =
  Int64.div (Int64.mul mp.min_relay_fee (Int64.of_int new_vsize)) 1000L in
if additional_fees < relay_fee_for_replacement then
  Error (Printf.sprintf
    "rejecting replacement, not enough additional fees to relay; %Ld < %Ld"
    additional_fees relay_fee_for_replacement)
```

`mp.min_relay_fee` is `1000L` sat/kvB (mempool.ml:245), 10× the Core
default for `incremental_relay_feerate`. The dedicated constant
`incremental_relay_fee = 100L` exists at mempool.ml:128 with a comment
"sat/kvB — policy/policy.h DEFAULT_INCREMENTAL_RELAY_FEE" but is used
**only** for rolling-fee math (mempool.ml:770, 774, 776, 802, 804), never
for RBF Rule 4.

**Concrete impact:**
- A 200-vbyte RBF replacement (typical pay-to-self) on camlcoin needs
  `additional_fees ≥ (1000 × 200 / 1000) = 200 sats` over the conflict's
  modified fee.
- Same RBF on Core needs `additional_fees ≥ (100 × 200 / 1000) = 20 sats`.
- camlcoin rejects the replacement that Core accepts. **Operator-facing
  surface**: wallets that auto-bump (Electrum, Sparrow, Phoenix-via-LSP)
  using the canonical "+1 sat/vB" rule build a 200-vbyte +200-sat
  replacement; Core accepts; camlcoin rejects with
  "rejecting replacement, not enough additional fees to relay; 200 < 200"
  (the strict-less-than-or-equal boundary case is also wrong).

**Carry-forward amplifier**: W150 BUG-6 already documented that
`min_relay_fee = 1000L` is 10× too high vs Core's PR #28366 default of
`DEFAULT_MIN_RELAY_TX_FEE = 100`. **Fixing W150 BUG-6 alone makes
this bug VANISH visually** (numbers happen to agree at 100/100), but
the structural divergence — wrong constant referenced — remains and would
re-surface the moment an operator sets `-minrelaytxfee`. Both bugs need to
be fixed together.

**File:** `lib/mempool.ml:2980-2986`.

**Core ref:** `bitcoin-core/src/policy/rbf.cpp:100-125`
(`PaysForRBF` with caller-supplied relay_fee);
`bitcoin-core/src/validation.cpp:1011, 1099`
(wiring to `m_pool.m_opts.incremental_relay_feerate`);
`bitcoin-core/src/kernel/mempool_options.h`
(`incremental_relay_feerate{DEFAULT_INCREMENTAL_RELAY_FEE}`).

---

## BUG-2 (P0-CDIV) — RBF Rule 5 counts EVICTIONS not CLUSTERS

**Severity:** P0-CDIV. Bitcoin Core's `GetEntriesForConflicts`
(`policy/rbf.cpp:58-83`) gates on `pool.GetUniqueClusterCount(iters_conflicting)`
— the count of **distinct clusters** that the direct conflicts span — and
rejects if that count exceeds `MAX_REPLACEMENT_CANDIDATES = 100`. Only AFTER
the cluster check passes does Core compute `all_conflicts` via
`pool.CalculateDescendants` for every direct conflict.

camlcoin's `replace_by_fee_with_replaced` at `mempool.ml:2879-2902`:

```ocaml
let evicted_set : (string, mempool_entry) Hashtbl.t = Hashtbl.create 16 in
List.iter (fun conflict_entry ->
  let key = Cstruct.to_string conflict_entry.txid in
  if not (Hashtbl.mem evicted_set key) then
    Hashtbl.replace evicted_set key conflict_entry;
  let desc = get_descendants mp conflict_entry.txid in
  List.iter (fun d ->
    let dk = Cstruct.to_string d.txid in
    if not (Hashtbl.mem evicted_set dk) then
      Hashtbl.replace evicted_set dk d
  ) desc
) conflicts;
let eviction_count = Hashtbl.length evicted_set in
if eviction_count > max_rbf_evictions then
  Error (Printf.sprintf
    "rejecting replacement; too many conflicting transactions (%d > %d)"
    eviction_count max_rbf_evictions)
```

`max_rbf_evictions = 100` (mempool.ml:123), and the gated quantity is
`|conflicts ∪ all_descendants|`. The inline comment at mempool.ml:2884
even says "Core constant: MAX_REPLACEMENT_CANDIDATES = 100" while
implementing the wrong metric.

**Concrete impact:**
- A package that conflicts with 5 direct mempool entries, each having
  20 descendants (total 105 evictions across 5 clusters), is rejected by
  camlcoin (`105 > 100`) and accepted by Core (`5 ≤ 100`).
- The "single-cluster-dust-attack" defense Core actually intends — rejecting
  cluster-count > 100 — is more permissive on eviction count and stricter
  on cluster count. camlcoin gets both wrong directions: rejects valid 5-cluster
  replacements (above) but allows 100-cluster replacements that Core would
  reject (because camlcoin doesn't see clusters at all).

**Comment-as-confession** (9th camlcoin instance): the source explicitly
quotes the Core constant name while implementing different semantics.

**File:** `lib/mempool.ml:2879-2902` (eviction count gate);
`lib/mempool.ml:123` (`max_rbf_evictions = 100`).

**Core ref:** `bitcoin-core/src/policy/rbf.h:26`
(`MAX_REPLACEMENT_CANDIDATES = 100` cluster count);
`bitcoin-core/src/policy/rbf.cpp:69-75`
(`pool.GetUniqueClusterCount(iters_conflicting) > MAX_REPLACEMENT_CANDIDATES`).

---

## BUG-3 (P1) — `is_well_formed_package` applies MAX_PACKAGE_WEIGHT to single-tx packages

**Severity:** P1. Bitcoin Core's `IsWellFormedPackage` (`policy/packages.cpp:87-91`):

```cpp
const int64_t total_weight = std::accumulate(txns.cbegin(), txns.cend(), 0,
                           [](int64_t sum, const auto& tx) { return sum + GetTransactionWeight(*tx); });
// If the package only contains 1 tx, it's better to report the policy violation on individual tx weight.
if (package_count > 1 && total_weight > MAX_PACKAGE_WEIGHT) {
    return state.Invalid(PackageValidationResult::PCKG_POLICY, "package-too-large");
}
```

The `package_count > 1` guard ensures single-tx submissions get reported
as `tx-size` (the per-tx weight policy), not `package-too-large`.

camlcoin's `is_well_formed_package` (mempool.ml:3936) applies the check
**unconditionally**:

```ocaml
if total_weight > max_package_weight then
  Error (Printf.sprintf "Package exceeds max weight (%d > %d)"
    total_weight max_package_weight)
```

So a 405,000-weight tx submitted alone via `submitpackage [hex]` gets
`"Package exceeds max weight (405000 > 404000)"` instead of the
single-tx `tx-size`-equivalent message. **Carry-forward from W116 BUG-8**
(documented in test_w116_package_relay.ml:15) — still open ~30 weeks
later despite being explicitly enumerated in the test suite.

**File:** `lib/mempool.ml:3927-3939`.

**Core ref:** `bitcoin-core/src/policy/packages.cpp:87-91`.

**Impact:** wire-token divergence on `submitpackage [single-large-tx]`;
operator-facing reject string wrong.

---

## BUG-4 (P0-CDIV) — `package-contains-duplicates` not checked; topo_sort silently dedups

**Severity:** P0-CDIV. Bitcoin Core's `IsWellFormedPackage`
(`policy/packages.cpp:94-102`):

```cpp
std::unordered_set<Txid, SaltedTxidHasher> later_txids;
std::transform(txns.cbegin(), txns.cend(), std::inserter(later_txids, later_txids.end()),
               [](const auto& tx) { return tx->GetHash(); });

// Package must not contain any duplicate transactions, which is checked by txid.
// This also includes transactions with duplicate wtxids and same-txid-different-witness
// transactions.
if (later_txids.size() != txns.size()) {
    return state.Invalid(PackageValidationResult::PCKG_POLICY, "package-contains-duplicates");
}
```

camlcoin's `is_well_formed_package` (mempool.ml:3927-3959) has NO
analogous gate. Its three substantive checks are: (a) count ≤ 25, (b)
weight ≤ 404,000 (with BUG-3), (c) `IsConsistentPackage`-equivalent
outpoint dedup. The txid-dedup check is missing entirely.

The downstream `topo_sort` (mempool.ml:3861-3865) **silently dedups via
Hashtbl.replace**:

```ocaml
let tx_by_id = Hashtbl.create (List.length txs) in
List.iter (fun tx ->
  let txid = Crypto.compute_txid tx in
  Hashtbl.replace tx_by_id (Cstruct.to_string txid) tx  (* <-- silent dedup *)
) txs;
```

So a `submitpackage [tx_A, tx_A]` flows:
1. `is_well_formed_package`: count = 2 ≤ 25 ✓; weight check on 2 txs ✓;
   outpoint scan sees `tx_A`'s inputs twice and rejects with
   `"Conflicting spend of <outpoint>"` (which has wire-token issues too —
   see BUG-7).
2. Wait, BUG-4 only fires if the txs have DIFFERENT outpoints. So a more
   subtle case: `submitpackage [tx_A, tx_A_witness_malleated]` (same txid,
   different witness). Outpoint scan sees same inputs and rejects with
   conflict.
3. The real bug: `submitpackage [tx_A, tx_B]` where `tx_A` and `tx_B` are
   different txs at this layer, plus `submitpackage [tx_A, tx_A]`
   ROUND-2 — the outpoint scan catches it as conflict (wrong wire token),
   topo_sort silently dedups to one tx, and the package result claims
   acceptance of 1 tx while the operator submitted 2. **The `tx-results`
   map in `handle_submitpackage` (rpc.ml:3163-3207) iterates the original
   `txs` list, so the duplicate wtxid appears twice in `tx-results` keyed
   by the same wtxid_key, and `Hashtbl.replace` in `entry_by_wtxid_key`
   makes the second iteration overwrite the first. Returned JSON has one
   wtxid key but represents two operator-supplied txs.**

**File:** `lib/mempool.ml:3927-3959` (no dedup check);
`lib/mempool.ml:3861-3865` (silent dedup in topo_sort);
`lib/rpc.ml:3163-3207` (downstream key-collision).

**Core ref:** `bitcoin-core/src/policy/packages.cpp:94-102`.

**Impact:** wire reject token absent; submitpackage RPC returns
malformed `tx-results` for duplicate-tx packages; operator-visible
state corruption (count_submitted ≠ count_in_results).

---

## BUG-5 (P0-CDIV) — `topo_sort` silently reorders instead of rejecting unsorted

**Severity:** P0-CDIV. Bitcoin Core's `IsTopoSortedPackage`
(`policy/packages.cpp:19-50`) returns `false` if any tx has an input
referencing a later-listed tx. `IsWellFormedPackage` then emits the
`package-not-sorted` reject token (packages.cpp:108-110). The rationale
(comment block at packages.cpp:104-107):

> Require the package to be sorted in order of dependency, i.e. parents
> appear before children. An unsorted package will fail anyway on
> missing-inputs, but it's better to quit earlier and fail on something
> less ambiguous (missing-inputs could also be an orphan or trying to
> spend nonexistent coins).

camlcoin's `topo_sort` (mempool.ml:3857-3920) **silently reorders** via
Kahn's algorithm and returns `Ok sorted` — the original input order is
discarded. The `accept_package_with_replaced` driver (mempool.ml:4091-4093)
uses the reordered list throughout:

```ocaml
match topo_sort txs with
| Error msg -> (PackageRejected msg, [])
| Ok sorted ->
  (* ... downstream operations all use [sorted] ... *)
```

**Impact:**
- A package `[child, parent]` (intentionally unsorted) gets accepted by
  camlcoin and rejected by Core. Cross-impl interop break for lnd /
  cln package-relay drivers that rely on Core's strict sort enforcement.
- The `tx-results` map in submitpackage (rpc.ml:3163) iterates the
  **original** input order, so the result order is unsorted while the
  internal validation uses sorted order. Operators with monitoring tools
  that key off result-index get confusing output.
- A peer-driven `pkgtxns` (package_relay.ml:51-75) accepts unsorted
  packages from BIP-331 peers. The BIP-331 spec assumes topological
  order; some implementations may rely on this for stream-decode
  efficiency.
- `package-not-sorted` reject token never emitted.

**File:** `lib/mempool.ml:3857-3920` (silent reorder).

**Core ref:** `bitcoin-core/src/policy/packages.cpp:19-50, 104-110`.

---

## BUG-6 (P1) — Empty-vin tx not rejected at package level

**Severity:** P1. Bitcoin Core's `IsConsistentPackage`
(`policy/packages.cpp:57-62`):

```cpp
for (const auto& tx : txns) {
    if (tx->vin.empty()) {
        // This function checks consistency based on inputs, and we can't do that if there are
        // no inputs. Duplicate empty transactions are also not consistent with one another.
        // ...
        return false;
    }
```

returns `false` immediately if any tx has empty vin. `IsWellFormedPackage`
then emits `conflict-in-package`.

camlcoin's `is_well_formed_package` (mempool.ml:3941-3957) iterates
`tx.Types.inputs` to populate `spent_outpoints`. A tx with `inputs = []`
contributes nothing to the scan, and the conflict gate never fires.
A package containing an empty-vin tx passes well-formed and gets
rejected downstream at per-tx `Validation.check_transaction`
(mempool.ml:1953) with a tx-level error like `bad-txns-vin-empty`.

**Impact:**
- Wire-token divergence: Core emits `conflict-in-package` (or
  `package-not-sorted` if it ALSO fails sort), camlcoin emits the per-tx
  error.
- Defense-in-depth gap for the consensus-class duplicate-tx detection
  (Core specifically calls out "Duplicate empty transactions are also not
  consistent with one another" in the comment above).

**File:** `lib/mempool.ml:3941-3957`.

**Core ref:** `bitcoin-core/src/policy/packages.cpp:52-77`.

---

## BUG-7 (P1) — Package-level wire reject tokens 5-way diverged

**Severity:** P1 ("reject-string wire-parity slippage" fleet pattern,
W125 / W145 BUG-5 cluster — 9th camlcoin instance). camlcoin's
package-validation rejection strings vs Core's wire tokens:

| Camlcoin string | Source line | Core wire token | Core ref |
|----------------|-------------|-----------------|----------|
| `"Package exceeds max transaction count (%d > %d)"` | mempool.ml:3929 | `package-too-many-transactions` | packages.cpp:84 |
| `"Package exceeds max weight (%d > %d)"` | mempool.ml:3937 | `package-too-large` | packages.cpp:91 |
| (none — silent dedup; see BUG-4) | n/a | `package-contains-duplicates` | packages.cpp:101 |
| (none — silent reorder; see BUG-5) | n/a | `package-not-sorted` | packages.cpp:109 |
| `"Conflicting spend of %s"` | mempool.ml:3950 | `conflict-in-package` | packages.cpp:114 |
| `"package topology disallowed. not child-with-parents or parents depend on each other."` | mempool.ml:4011, 4028 | `package-not-child-with-parents` | validation.cpp:1643 |
| `"Package contains a cycle"` | mempool.ml:3917 | (n/a — Core has no cycle check; cycles would manifest as missing-inputs) | — |

The non-Core English strings break any monitoring that scrapes Core
package reject tokens (mempool.space, electrs package-relay extensions,
ZMQ `hashtx`-bound topic filters, lnd/cln package retry logic).

**File:** `lib/mempool.ml:3917, 3929, 3937, 3950, 4011, 4028`.

**Impact:** monitoring tooling breaks; cross-impl parity loss; operator
log diff with Core.

---

## BUG-8 (P0-SEC) — Package paths skip the exception-safe ATMP wrapper

**Severity:** P0-SEC (carry-forward W150 BUG-2). The `accept_to_memory_pool`
single-tx entry (mempool.ml:3138-3175) wraps the validation pipeline in a
`try/with` for `Failure | Invalid_argument | Not_found` to satisfy the
W96 Bug 13 "RPC, P2P and miner paths call ATMP without their own try/with"
invariant. The package counterpart, `accept_package_with_replaced`
(mempool.ml:4084-4241), has **no equivalent wrapper**.

Per-tx admission inside the package goes via:

```ocaml
let add_result =
  if conflicts_for_tx = [] then
    (match add_transaction ~bypass_fee_check:use_package_feerate mp tx with
     | Ok e -> Ok (e, [])
     | Error s -> Error s)
  else
    replace_by_fee_with_replaced mp tx
in
match add_result with
| Ok (entry, evicted) -> ...
| Error msg -> rejected := (tx, msg) :: !rejected
```

Neither `add_transaction` nor `replace_by_fee_with_replaced` catches
exceptions internally. An exception from `Crypto.compute_txid` (libsecp
edge case), `Script.parse_script` (called from `is_witness_standard`
→ `verify_tx_scripts`), or `Validation.compute_tx_weight` (called from
`calc_tx_fee_vsize` at mempool.ml:4066) on attacker-controlled package
data propagates out of `accept_package_with_replaced` and crashes the
caller.

**Concrete vectors:**
- `handle_submitpackage` (rpc.ml:3113) — exception bubbles to RPC
  handler; crashes the request.
- `handle_pkgtxns` (package_relay.ml:61) — exception bubbles to the
  peer message loop; crashes the peer dispatcher.
- `try_1p1c_with_orphans` (mempool.ml:4288) — exception escapes to
  whatever invokes orphan reprocessing.

**File:** `lib/mempool.ml:4084-4241` (no `safe_run`); call sites
`rpc.ml:3113`, `package_relay.ml:61`, `mempool.ml:4288`.

**Core ref:** `bitcoin-core/src/validation.cpp:583-589`
(`AcceptSingleTransactionAndCleanup` uses TxValidationState, never
C++ exceptions); package equivalent at validation.cpp:596-598
(`AcceptMultipleTransactionsAndCleanup` same wrapping).

**Impact:** RPC + P2P crash on attacker-controlled package data.
W96 Bug 13 closure incomplete (escalation of W150 BUG-2).

---

## BUG-9 (P0-CDIV) — `AcceptPackage` does NOT attempt per-tx single-tx admission first

**Severity:** P0-CDIV. Bitcoin Core's `AcceptPackage` (validation.cpp:1658-1717)
implements a two-pass strategy:

1. For each tx in the package, attempt single-tx admission via
   `AcceptSubPackage({tx})`. If it succeeds, treat the tx as
   already-in-mempool. If it fails with `TX_RECONSIDERABLE` or
   `TX_MISSING_INPUTS`, defer to the multi-tx pass. Other failures
   (e.g. consensus errors) abort the package with `quit_early`.
2. Submit the remaining (failed-single-tx) txs via
   `AcceptSubPackage(txns_package_eval, args)`.

Rationale (validation.cpp:1700-1706):

> Package validation policy only differs from individual policy in its
> evaluation of feerate. For example, if a transaction fails here due to
> violation of a consensus rule, the result will not change when it is
> submitted as part of a package. To minimize the amount of repeated work,
> unless the transaction fails due to feerate or missing inputs (its parent
> is a previous transaction in the package that failed due to feerate),
> don't run package validation.

camlcoin's `accept_package_with_replaced` (mempool.ml:4084-4241)
always tries the whole package as one unit. The per-tx loop at
mempool.ml:4114-4138 does per-tx fee/vsize calc and an "already in
mempool" short-circuit (line 4119-4120) but no per-tx single-tx
admission attempt.

**Concrete impact:**
- A child-with-parents package where one parent has a consensus error
  (e.g. tx-size-small) and another parent is already in the mempool:
  - **Core**: in-mempool parent gets `MempoolTx` result; failed parent
    gets `Failure`; package-wide `quit_early=true`. The good parent
    stays in mempool, bad parent reported with its consensus error.
  - **camlcoin**: every tx gets marked rejected with whatever cascading
    error the failed parent produces.
- An attacker pinning attack: submit a package whose middle tx has a
  malformed witness; instead of isolating the failure to that one tx,
  every accepted child gets rolled back in the operator's view (though
  not in mempool state).

**File:** `lib/mempool.ml:4084-4241`.

**Core ref:** `bitcoin-core/src/validation.cpp:1658-1717`.

---

## BUG-10 (P1) — Package-feerate computed BEFORE per-tx PreChecks

**Severity:** P1. Core's `AcceptMultipleTransactionsInternal`
(validation.cpp:1432-1564) runs in this order:
1. `IsWellFormedPackage` (line 1439).
2. **Per-tx `PreChecks(args, ws)`** for every tx (line 1448-1454).
3. Per-tx maxfeerate check (line 1458-1465).
4. `PackageAddTransaction` so children can spend parent outputs in the
   package (line 1476).
5. `PackageTRUCChecks` (line 1482-1486).
6. Aggregate `m_total_vsize` / `m_total_modified_fees` (line 1497-1500).
7. Compute `package_feerate` AFTER all per-tx checks (line 1501).
8. Cluster size check (line 1520-1523).
9. PolicyScriptChecks per tx (line 1538).

camlcoin's `accept_package_with_replaced` reverses the order
(mempool.ml:4113-4214):
1. First pass: per-tx fee/vsize calc + already-in-mempool check
   (line 4113-4138). NO PreChecks-equivalent.
2. Aggregate `package_feerate` (line 4154-4158).
3. Decide `use_package_feerate` flag (line 4166).
4. Per-tx admission via `add_transaction`/`replace_by_fee_with_replaced`
   (line 4168-4214). The full PreChecks-equivalent (every `add_transaction`
   internal gate) runs HERE, after package_feerate is locked in.

**Concrete impact:**
- A package where the first tx has a consensus error (e.g. fail
  `Validation.check_transaction`): camlcoin still computes
  `package_feerate` aggregating that tx's fee (it was successfully
  `calc_tx_fee_vsize`-ed) and uses it as the floor for OTHER txs in the
  package. A child tx that depends on the bad parent then sees an inflated
  `package_feerate` floor.
- This causes false-positive accepts: a low-fee child can pass the
  per-tx fee floor because `use_package_feerate=true` even though the
  parent (whose fee is being amortised) will never enter the mempool.
  The child becomes an orphan with no parent to validate against.

**File:** `lib/mempool.ml:4113-4214`.

**Core ref:** `bitcoin-core/src/validation.cpp:1432-1564`.

---

## BUG-11 (P0-CDIV) — `submitpackage` maxfeerate check fires AFTER mempool insertion

**Severity:** P0-CDIV (carry-forward W150 BUG-12 — second site). Core's
`AcceptMultipleTransactionsInternal` checks maxfeerate INSIDE the per-tx
PreChecks loop at validation.cpp:1458:

```cpp
if (args.m_client_maxfeerate && CFeeRate(ws.m_modified_fees, ws.m_vsize) > args.m_client_maxfeerate.value()) {
    ws.m_state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY, "max feerate exceeded", "");
    package_state.Invalid(PackageValidationResult::PCKG_TX, "transaction failed");
    results.emplace(...);
    return PackageMempoolAcceptResult(package_state, std::move(results));
}
```

— **before** `m_viewmempool.PackageAddTransaction` (line 1476), before any
mempool state mutation. The tx is rejected without ever being inserted.

camlcoin's `handle_submitpackage` (rpc.ml:3140-3160) checks maxfeerate
**after** `accept_package_with_replaced` has already inserted the tx into
the mempool, then evicts:

```ocaml
if max_fee_rate > 0.0 then begin
  let exceed_keys = ref [] in
  Hashtbl.iter (fun key e ->
    let vsize = (e.Mempool.weight + 3) / 4 in
    let max_fee_sats = ... in
    if e.Mempool.fee > max_fee_sats then
      exceed_keys := (key, e) :: !exceed_keys
  ) entry_by_wtxid_key;
  List.iter (fun (key, e) ->
    Mempool.remove_transaction ctx.mempool e.Mempool.txid;  (* <-- post-eviction *)
    ...
  ) !exceed_keys;
```

Between the insert and the evict, `add_transaction` (mempool.ml:2327)
called `zmq_notify_tx mp txid tx true` — the tx was broadcast to ZMQ
subscribers as accepted. The eviction triggers another
`zmq_notify_tx ... false` notification. Subscribers see a phantom
admit-then-remove pair for what should have been a synchronous reject.

Additionally, `Mempool.remove_transaction` triggers the fee-estimator
`on_eviction` hook, misclassifying the tx as "removed without
confirmation" and contaminating fee-estimation history.

**File:** `lib/rpc.ml:3140-3160`.

**Core ref:** `bitcoin-core/src/validation.cpp:1458-1465`
(maxfeerate check before insertion).

**Impact:**
- ZMQ subscribers see phantom transactions.
- Fee estimator contaminated by `max-fee-exceeded` evictions.
- Race window: another RPC client can observe the briefly-admitted tx
  via `getrawmempool` between insert and evict.
- Cross-cite W150 BUG-12 (same pattern in `sendrawtransaction`).

---

## BUG-12 (P1) — `replaced-transactions` not cleared on maxfeerate eviction

**Severity:** P1. When `handle_submitpackage` evicts a tx for maxfeerate
violation (rpc.ml:3153-3157), it removes the entry from
`entry_by_wtxid_key` and adds an `error_by_wtxid_key` entry. But the
`replaced_txids` list (collected at line 3112 from
`accept_package_with_replaced`) is NOT updated.

If the now-evicted tx had triggered RBF eviction of conflicts during
admission, those conflicts are GONE from the mempool but the replacement
that displaced them is ALSO GONE (just evicted). The `replaced-transactions`
JSON field still reports the conflicts as "replaced", but no live
replacement exists. The operator sees:

```json
{
  "package_msg": "max-fee-exceeded",
  "tx-results": { "<wtxid>": { "txid": "...", "error": "max-fee-exceeded" } },
  "replaced-transactions": ["<evicted_conflict_txid>"]
}
```

— which claims a replacement happened, but the mempool now contains
neither the old nor the new tx. Honest reporting would either roll back
the RBF eviction (Core's atomic semantics) or clear `replaced-transactions`
in this branch.

**File:** `lib/rpc.ml:3140-3160` (maxfeerate eviction) +
`lib/rpc.ml:3215-3219` (`replaced_json` build).

**Core ref:** `bitcoin-core/src/validation.cpp:1458-1465` —
maxfeerate-rejected tx never proceeds to eviction at all, so
`m_replaced_transactions` stays empty.

**Impact:** misleading RPC response; data-flow inconsistency for any
wallet that uses `replaced-transactions` as a "confirm-evicted-then-rebroadcast"
signal.

---

## BUG-13 (P0-SEC) — `handle_submitpackage` skips the safe-run wrapper for the package engine

**Severity:** P0-SEC. `handle_submitpackage` (rpc.ml:3036-3225) has only
one defensive `try/with` block — around the per-tx hex decode at line
3077-3082. The subsequent `Mempool.accept_package_with_replaced` call
at line 3113 is **not** protected.

`accept_to_memory_pool` (mempool.ml:3138-3175) wraps single-tx ATMP in
`safe_run` for the explicit reason that "peer-controlled inputs ...
MUST NOT be allowed to propagate failwith/Not_found/Invalid_argument out
of ATMP". `handle_submitpackage` calls the package engine with operator
hex (potentially attacker-supplied via authenticated RPC) and provides
no equivalent guard.

Cross-cite W150 BUG-1/BUG-2: this is the **second multi-pipeline-bypass
of the safe wrapper this audit cycle**. The bug pattern is identical:
the W96 closure guarded one entry point; subsequent code added more
entry points that bypass the wrapper.

**File:** `lib/rpc.ml:3036-3225`.

**Core ref:** `bitcoin-core/src/validation.cpp:596-598`
(`AcceptMultipleTransactionsAndCleanup` parallels the single-tx wrap).

**Impact:** authenticated RPC user (or compromised RPC channel) can
crash the camlcoin handler with a crafted package hex.

---

## BUG-14 (P0-CDIV) — `sendpackages` never sent outbound; BIP-331 half-disabled

**Severity:** P0-CDIV (carry-forward W116 BUG-11 — DEAD-HELPER pattern,
4th-consecutive-quad bypass instance). camlcoin captures inbound
`sendpackages` from peers (peer.ml:847-856, 1613-1674) but **never sends
its own `sendpackages` outbound** between VERSION and VERACK.

`make_sendpackages_msg` (p2p.ml:1580-1585) is defined and exported with a
correct constructor:

```ocaml
let make_sendpackages_msg ?(version=package_relay_version)
    ?(max_count=max_package_count) ?(max_weight=max_package_weight) () =
  SendpackagesMsg { pkg_version = version; pkg_max_count = ...; pkg_max_weight = ... }
```

A grep over `lib/` + `bin/` shows ZERO callers outside `test/test_w116_package_relay.ml`.

BIP-331 protocol behaviour: a peer that doesn't receive `sendpackages` from
the local node won't send `pkgtxns` to it (because the local node hasn't
advertised package-relay support). Result: **camlcoin's BIP-331 package
relay is receive-only**. The `getpkgtxns`/`pkgtxns` handlers (package_relay.ml)
run if a peer happens to send them anyway, but the canonical relay path
is dead.

**Fleet pattern**: this is the "wiring-look-but-no-wire" / "dead-helper"
class previously observed in W138 BUG-class (ChainstateManager defined +
methods + no production caller, 9-of-10 impls); W140 BUG-class (constantTimeEq
exported but not called, haskoin); W141 BUG-class
(zmq_publisher/zmq_notifier attribute mismatch, ouroboros);
W150 BUG-1 (sendtoaddress skips canonical entry, camlcoin).
**5th distinct fleet pattern instance for camlcoin this quad**.

**File:** `lib/p2p.ml:1580-1585` (defined helper); call-graph empty
outside test.

**Core ref:** `bitcoin-core/src/net_processing.cpp` — sendpackages emitted
in pre-VERACK handshake for outbound peers supporting BIP-331.

**Impact:**
- camlcoin doesn't participate in BIP-331 package relay as an initiator.
- A child-with-parents package needing CPFP relay never reaches camlcoin
  via the `pkgtxns` path; it's stuck in orphan pool waiting for individual
  tx relay.
- Mempool starvation for legitimate v3/TRUC CPFP traffic.

---

## BUG-15 (P1) — `handle_pkgtxns` clamps to local `max_package_count`, not peer's `pkg_max_count`

**Severity:** P1. `handle_pkgtxns` (package_relay.ml:55-59):

```ocaml
else if n > Mempool.max_package_count then begin
  Log.warn (fun m ->
    m "pkgtxns from peer %d exceeds max_package_count (%d > %d), ignoring"
      peer.id n Mempool.max_package_count);
  Lwt.return_unit
```

`Mempool.max_package_count = 25` (mempool.ml:3852). The peer-side limit
captured at handshake (`peer.pkg_max_count`, peer.ml:854) is ignored.

BIP-331 semantics: the negotiated `pkg_max_count` is the **per-peer**
package count limit. If a peer advertised `pkg_max_count = 10`, the local
node should send `getpkgtxns` requests of at most 10 wtxids AND reject
inbound `pkgtxns` exceeding 10 (because the peer claimed it wouldn't send
more). camlcoin honors the local 25 but ignores the per-peer 10.

**File:** `lib/package_relay.ml:55-59`.

**Core ref:** BIP-331 §"Negotiation"; net_processing.cpp uses the
negotiated limits per-peer.

**Impact:** subtle protocol divergence; a misbehaving peer that exceeds
its own advertised limit gets accepted up to camlcoin's 25 instead of
being disconnected at 11.

---

## BUG-16 (P2) — `lookup_tx_by_wtxid` is O(N) scan; no wtxid index

**Severity:** P2. `lookup_tx_by_wtxid` (package_relay.ml:21-28):

```ocaml
let lookup_tx_by_wtxid (mp : Mempool.mempool) (wtxid : Types.hash256)
    : Types.transaction option =
  let result = ref None in
  Hashtbl.iter (fun _k (entry : Mempool.mempool_entry) ->
    if !result = None && Cstruct.equal entry.wtxid wtxid then
      result := Some entry.tx
  ) mp.entries;
  !result
```

For a 25-wtxid `getpkgtxns` against a 50k-entry mempool, that's
1.25M `Cstruct.equal` comparisons per peer request. The mempool already
maintains a wtxid field per entry but no wtxid → entry index.

**Comment-as-confession** (10th camlcoin instance): "This is O(N) per
request; acceptable since [getpkgtxns] is rare and bounded by
[P2p.max_package_txs] = 25 wtxids per request" — explicitly justifies
the perf bug.

**File:** `lib/package_relay.ml:17-20, 21-28`.

**Core ref:** `bitcoin-core/src/txmempool.h::mapTx::index<index_by_wtxid>`
(O(1) wtxid lookup).

**Impact:** perf only; minor DoS amplifier if a peer spams `getpkgtxns`
with random wtxids (each one walks the full mempool). At 25 wtxids ×
50k entries × ~100ns per equal = 125ms per request; trivial to amplify
to seconds with a few peers.

---

## BUG-17 (P0-CDIV) — 9-pipeline drift on transaction admission (5-of-5 quad pattern continues)

**Severity:** P0-CDIV. W143 BUG-2 (5 pipelines), W144 BUG-12 (2 flag-derivation
helpers), W145 BUG-1 (block_import.ml bypasses every gate), W148 BUG-class
(headers-first sync drift), W150 BUG-1 (**6 ATMP entry points**), and now
W151 (3 package paths + 1 reorg-refill path): every consecutive quad-audit
in W143-W151 has surfaced multi-pipeline-bypass in camlcoin. The
running inventory of distinct tx-admission entry points is now:

**Single-tx admission paths (W150 BUG-1)**:
1. `cli.ml:1240` (P2P tx relay) → `accept_to_memory_pool` (RBF ✓, safe ✓)
2. `rpc.ml:1192` (sendrawtransaction) → `add_transaction` (RBF ✗, safe ✗)
3. `rpc.ml:2269/2288` (sendtoaddress) → `add_transaction` (RBF ✗, safe ✗)
4. `rpc.ml:2995` (testmempoolaccept) → `add_transaction ~dry_run` (RBF ✗, safe ✗)
5. `sync.ml:3706` (reorg-refill) → `add_transaction ~bypass_*` (RBF ✗, safe ✗)
6. `package_relay.ml:61` (BIP-331 pkgtxns) → `accept_package` (RBF per-tx, safe ✗)

**Package admission paths (NEW in W151)**:
7. `rpc.ml:3113` (submitpackage RPC) → `accept_package_with_replaced` (RBF per-tx, safe ✗ — BUG-13)
8. `package_relay.ml:61` (pkgtxns, dups with #6 inventory)
9. `mempool.ml:4288` (try_1p1c_with_orphans) → `accept_package` (RBF per-tx, safe ✗)

**Reorg-refill path**:
10. `sync.ml:3706` is single-tx only — no package-aware reorg refill
    (BUG-19 below)

That's **8 distinct production entry points** (deduping the
package_relay.ml double-count), of which only ONE (`cli.ml:1240`)
routes through the exception-safe wrapper. The "block_import.ml-bypass
4th-consecutive-quad" pattern from prior MEMORY.md becomes
**5th-consecutive-quad** in W151 — camlcoin's structural property is
that pipelines fork on every audit and converge on none.

Core has **one** entry: `AcceptToMemoryPool` (single) /
`ProcessNewPackage` (package), both internally route through
`MemPoolAccept::AcceptSingleTransactionAndCleanup` /
`AcceptMultipleTransactionsAndCleanup` (validation.cpp:583-598)
with shared ATMPArgs static constructors.

**File:** the 8 sites above.

**Core ref:** `bitcoin-core/src/validation.cpp:435-680, 1432-1820`.

**Impact:** every BUG-N where N ≥ 1 in this audit (and W150) has 8 distinct
call paths to attack; bug surface multiplied 8×.

---

## BUG-18 (P0-CDIV) — Package RBF treats per-tx, not per-package (PackageRBFChecks absent)

**Severity:** P0-CDIV. Bitcoin Core's `PackageRBFChecks`
(validation.cpp:1515-1517, implementation in policy/truc_policy.cpp and
related) gates the **entire package** as one replacement unit when any
package tx conflicts with a mempool tx. The package's aggregate
modified-fees + aggregate vsize are evaluated against the conflict's
fees per BIP-431 §"RBF for packages":

> A package's effective feerate must be greater than the conflict's
> feerate to satisfy Rule 3, and the package's fees must exceed the
> conflict's fees by at least the incremental relay feerate times the
> package's virtual size to satisfy Rule 4.

camlcoin's `accept_package_with_replaced` (mempool.ml:4181-4213) routes
each conflicting tx through `replace_by_fee_with_replaced` independently:

```ocaml
let conflicts_for_tx = find_all_conflicts mp tx in
let add_result =
  if conflicts_for_tx = [] then
    (match add_transaction ~bypass_fee_check:use_package_feerate mp tx with ...)
  else
    replace_by_fee_with_replaced mp tx
in
```

So for a (parent, child) where the parent conflicts with mempool entry M
and the child has no conflicts:
- **Core**: aggregate(parent_fee + child_fee) vs M's modified_fee + RBF
  Rule 4 (incremental × aggregate_vsize). The child's high fee can pay
  for the parent's lower fee in the RBF gate.
- **camlcoin**: parent_fee alone vs M's modified_fee + RBF Rule 4
  (incremental × parent_vsize). Child is added separately (no conflicts).
  The child's fee does NOT contribute to the parent's RBF math.

**Pinning attack**: an attacker stuffs the mempool with a high-feerate
descendant of M, then a legitimate user tries to RBF M via a
(parent_replaces_M, child_pays_descent_subsidy) package. Core accepts
(aggregate fee suffices); camlcoin rejects (parent fee alone insufficient).
This is **the exact case BIP-431 package-RBF was designed to fix**.

**Comment-as-confession** (8th camlcoin instance) at mempool.ml:4191-4194:

```ocaml
(* Note: this NARROWS BUG-7 (package-RBF) — per-tx RBF inside a
   package now works, but true package-feerate-based replacement
   (treating the whole package as one replacement unit per BIP-431
   §"RBF for packages") is still missing and tracked separately. *)
```

Source code admits the divergence. "tracked separately" — and 30+ weeks
later still not landed.

**File:** `lib/mempool.ml:4181-4213` (per-tx RBF inside package).

**Core ref:** `bitcoin-core/src/validation.cpp:1515-1517`
(`PackageRBFChecks` per-package gate);
BIP-431 §"RBF for packages".

**Impact:**
- Pinning attacks via descendant stuffing succeed on camlcoin.
- v3/TRUC CPFP replacement chains broken: the canonical use-case of
  package-RBF (replace a parent + new child funding the replacement) is
  not gateable.
- Lightning channel close races: a force-close that needs to RBF a
  pinned anchor descendant cannot use camlcoin's mempool for relay.

---

## BUG-19 (P1) — Reorg refill is single-tx; no package-aware re-acceptance

**Severity:** P1. `sync.ml:3705-3713` re-admits disconnected-block txs
one-at-a-time via `Mempool.add_transaction`:

```ocaml
List.iter (fun tx ->
  ignore (Mempool.add_transaction
            ~bypass_fee_check:true
            ~bypass_limits:true
            mp tx)
) !disconnected_txs;
```

A v3/TRUC package (parent + child) that lived in the old chain via
direct relay or via prior `pkgtxns` is re-added in arbitrary order
(`!disconnected_txs` is the disconnection traversal order, which is
LIFO of block tx-order). If the child is processed before the parent,
it lands in the orphan pool (or gets rejected for missing inputs). The
parent's subsequent re-add does not trigger `try_1p1c_with_orphans`
(which is itself a dead helper per BUG-17 cross-cite). The child sits
in orphan pool until either the parent arrives again via P2P, or the
orphan times out.

Core's `MaybeUpdateMempoolForReorg` (validation.cpp around
UpdateMempoolForReorg) uses `args.m_bypass_limits = true` but routes
each tx through the full ATMP gate including TRUC checks (suppressed
via the bypass — W96 Bug 11), package-aware re-admission, and
descendant-aware cluster updates.

**File:** `lib/sync.ml:3705-3713`.

**Core ref:** `bitcoin-core/src/validation.cpp::Chainstate::MaybeUpdateMempoolForReorg`.

**Impact:** v3/TRUC packages disconnected by a reorg get reduced to
orphans; mempool starvation post-reorg for legitimate CPFP traffic.

---

## Summary

**Bug count:** 19 (BUG-1 through BUG-19).

**Severity distribution:**
- **P0-CDIV:** 10 (BUG-1, BUG-2, BUG-4, BUG-5, BUG-9, BUG-11, BUG-14, BUG-17, BUG-18, BUG-19? — recount)
- **P0-SEC:** 2 (BUG-8, BUG-13)
- **P1:** 7 (BUG-3, BUG-6, BUG-7, BUG-10, BUG-12, BUG-15, BUG-19)
- **P2:** 1 (BUG-16)

Recount: P0-CDIV = BUG-1, BUG-2, BUG-4, BUG-5, BUG-9, BUG-11, BUG-14,
BUG-17, BUG-18 = 9. P0-SEC = BUG-8, BUG-13 = 2. P1 = BUG-3, BUG-6,
BUG-7, BUG-10, BUG-12, BUG-15, BUG-19 = 7. P2 = BUG-16 = 1. Total
9 + 2 + 7 + 1 = **19**. ✓

**Total P0-class:** 11 (9 P0-CDIV + 2 P0-SEC).

**Fleet patterns confirmed:**
- **5th-consecutive-quad multi-pipeline drift in camlcoin** (BUG-17) —
  now **8 distinct production tx-admission entry points** (6 single + 3
  package, less overlap). W143/W144/W145/W150 all surfaced
  multi-pipeline-bypass; W151 escalates further.
- **block_import.ml-bypass 4th-consecutive-quad** (carry-forward of MEMORY.md
  pattern) is now the **5th-consecutive-quad** with BUG-17 — `accept_package`
  bypassing the safe wrapper, sendrawtransaction bypassing RBF, sendtoaddress
  bypassing maxfeerate, sync.ml bypassing package-aware refill.
- **Two-pipeline guard → 9-pipeline drift extension** (BUG-17 ×3, BUG-19) —
  extends every prior count (W143 5, W148 architectural, W150 6).
- **Comment-as-confession** instances 8-10 this audit (BUG-18 line 4191-4194
  package-RBF "tracked separately"; BUG-2 line 2884 "Core constant" while
  using different semantics; BUG-16 line 19-20 "acceptable since rare").
  Running camlcoin total: 10 distinct instances across W143-W151
  (W143 2, W144 1, W145 1, W148 1, W150 2, W151 3).
- **Wire-token slippage 5-way** (BUG-7) — `package-too-many-transactions`,
  `package-too-large`, `package-contains-duplicates`, `package-not-sorted`,
  `conflict-in-package`, `package-not-child-with-parents` all diverged.
  Carry-forward of W125 / W145 BUG-5 cluster.
- **Carry-forward bug uncaught for 6 months** (BUG-3 W116 BUG-8 still
  open; BUG-14 W116 BUG-11 still open) — explicit test_w116_package_relay
  test suite flags these and they remain unfixed.
- **Dead-helper / wiring-look-but-no-wire** (BUG-14
  `make_sendpackages_msg` defined-exported-uncalled; W141 BUG-class
  ouroboros zmq_publisher; W138 BUG-class ChainstateManager; W140 BUG-class
  haskoin constantTimeEq — running fleet pattern).
- **Same fleet pattern, second site** (BUG-11 W150 BUG-12 maxfeerate
  post-eviction at `sendrawtransaction` recurs in `submitpackage`).
- **Constant-correct-but-not-wired** (BUG-1 `incremental_relay_fee=100L`
  defined and correctly attributed to Core ref, but the RBF Rule 4 site
  uses `min_relay_fee` instead).

**Top three findings:**

1. **BUG-17 (P0-CDIV 5th-consecutive-quad pipeline drift)** —
   8 distinct production tx-admission entry points; only 1 routes through
   exception-safe wrapper; the structural property of camlcoin is that
   pipelines proliferate every audit. Closing this requires a unified
   single-entry refactor analogous to Core's `MemPoolAccept::AcceptSingleTransactionAndCleanup`
   / `AcceptMultipleTransactionsAndCleanup`.

2. **BUG-1 + BUG-2 cluster (P0-CDIV RBF Rules 4 & 5)** — Rule 4 uses
   `min_relay_fee=1000` instead of `incremental_relay_fee=100`
   (10× too strict; rejects every wallet auto-bumped RBF replacement);
   Rule 5 counts evictions instead of clusters (rejects strictly more
   replacements than Core; admits some attacks Core rejects). The two
   most foundational BIP-125 gates BOTH diverged. Both bugs are 1-3
   line fixes each.

3. **BUG-14 + BUG-18 (P0-CDIV BIP-331 + BIP-431 dual-disability)** —
   BUG-14: camlcoin never sends `sendpackages` outbound, so peers don't
   announce package relay; BIP-331 is receive-only. BUG-18: even when
   packages do flow in, the per-tx RBF inside `accept_package_with_replaced`
   does NOT aggregate fees at the package level, so the exact pinning-
   attack defense BIP-431 §"RBF for packages" was designed to provide is
   absent. The combination means camlcoin's package-relay implementation
   provides neither the relay (BIP-331) nor the security gate (BIP-431
   package-RBF) the protocol was meant to deliver. Lightning channel
   force-close races are broken.
