# W150 — AcceptToMemoryPool + PreChecks + PolicyScriptChecks + ConsensusScriptChecks (camlcoin)

**Wave:** W150 — `MemPoolAccept`, `AcceptToMemoryPool`, `AcceptSingleTransaction`, `PreChecks`,
`PolicyScriptChecks`, `ConsensusScriptChecks`, `Finalize`, `ATMPArgs`, `IsStandardTx`,
`AreInputsStandard`, `IsWitnessStandard`, `GetVirtualTransactionSize`,
`DEFAULT_MIN_RELAY_TX_FEE=100`, `DEFAULT_INCREMENTAL_RELAY_FEE=100`, `DUST_RELAY_TX_FEE=3000`,
`MAX_STANDARD_TX_WEIGHT=400000`, `MAX_STANDARD_P2WSH_STACK_ITEMS=100`,
`MAX_STANDARD_P2WSH_STACK_ITEM_SIZE=80`, `MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE=80`,
`MAX_STANDARD_TX_SIGOPS_COST=16000`, `MAX_TX_LEGACY_SIGOPS=2500`,
`MIN_STANDARD_TX_NONWITNESS_SIZE=65`, `TX_MAX_STANDARD_VERSION=3`,
`STANDARD_SCRIPT_VERIFY_FLAGS`, `MANDATORY_SCRIPT_VERIFY_FLAGS`,
`-acceptnonstdtxn`, `-minrelaytxfee`, `-incrementalrelayfee`, `-permitbaremultisig`,
`-datacarrier`, `-datacarriersize`, `-bytespersigop`, `-maxmempool`.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/validation.cpp:435-980` — `MemPoolAccept` class,
  `AcceptSingleTransaction`, `AcceptMultipleTransactions`, `AcceptPackage`,
  `PreChecks` (~782-982). Coinbase rejected at 803-804; `IsStandardTx` at 808;
  `MIN_STANDARD_TX_NONWITNESS_SIZE` at 812-814; `CheckFinalTxAtTip` at 819;
  duplicate-by-wtxid AND-then-txid at 823-829; conflict at 833-843;
  `HaveCoin` + `txn-already-known` at 849-867; `CalculateLockPointsAtTip` /
  `CheckSequenceLocksAtTip` at 887; `CheckTxInputs` at 892;
  `ValidateInputsStandardness` at 897 (guarded by `require_standard`);
  `IsWitnessStandard` at 904; `GetTransactionSigOpCost` w/
  `STANDARD_SCRIPT_VERIFY_FLAGS` at 908; `entry_sequence` at 923-927;
  `PreCheckEphemeralTx` at 935-938; `MAX_STANDARD_TX_SIGOPS_COST` at 941-943;
  `CheckFeeRate` at 948; `SingleTRUCChecks` at 956.
- `bitcoin-core/src/validation.cpp:1135-1156` — `PolicyScriptChecks`:
  ONE script verification pass with `STANDARD_SCRIPT_VERIFY_FLAGS`;
  emits `TX_WITNESS_STRIPPED` on `SpendsNonAnchorWitnessProg`.
- `bitcoin-core/src/validation.cpp:1158-1189` — `ConsensusScriptChecks`:
  SECOND script verification pass with `GetBlockScriptFlags(tip)`;
  caches script flags on success; `Assume(false)` on disagreement
  ("BUG! PLEASE REPORT THIS!" log). Defense-in-depth gate.
- `bitcoin-core/src/policy/policy.h:36-95` — constants:
  `DEFAULT_BLOCK_MIN_TX_FEE=1`, `MAX_STANDARD_TX_WEIGHT=400000`,
  `MIN_STANDARD_TX_NONWITNESS_SIZE=65`, `MAX_P2SH_SIGOPS=15`,
  `MAX_STANDARD_TX_SIGOPS_COST = MAX_BLOCK_SIGOPS_COST/5 = 16000`,
  `MAX_TX_LEGACY_SIGOPS=2500`, `DEFAULT_INCREMENTAL_RELAY_FEE=100`,
  `DEFAULT_BYTES_PER_SIGOP=20`, `DEFAULT_PERMIT_BAREMULTISIG=true`,
  `MAX_STANDARD_P2WSH_STACK_ITEMS=100`, `MAX_STANDARD_P2WSH_STACK_ITEM_SIZE=80`,
  `MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE=80`, `MAX_STANDARD_P2WSH_SCRIPT_SIZE=3600`,
  `MAX_STANDARD_SCRIPTSIG_SIZE=1650`, `DUST_RELAY_TX_FEE=3000`,
  `DEFAULT_MIN_RELAY_TX_FEE=100`, `DEFAULT_CLUSTER_LIMIT=64`,
  `DEFAULT_CLUSTER_SIZE_LIMIT_KVB=101`, `DEFAULT_ANCESTOR_LIMIT=25`,
  `DEFAULT_DESCENDANT_LIMIT=25`, `DEFAULT_ACCEPT_DATACARRIER=true`,
  `MAX_OP_RETURN_RELAY=100000`, `MAX_DUST_OUTPUTS_PER_TX=1`,
  `TX_MIN_STANDARD_VERSION=1`, `TX_MAX_STANDARD_VERSION=3`.
- `bitcoin-core/src/policy/policy.h:105-135` — `MANDATORY_SCRIPT_VERIFY_FLAGS`
  (P2SH, DERSIG, NULLDUMMY, CLTV, CSV, WITNESS, TAPROOT) and
  `STANDARD_SCRIPT_VERIFY_FLAGS` (mandatory + STRICTENC + MINIMALDATA +
  DISCOURAGE_UPGRADABLE_NOPS + CLEANSTACK + MINIMALIF + NULLFAIL + LOW_S +
  DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM + WITNESS_PUBKEYTYPE +
  CONST_SCRIPTCODE + DISCOURAGE_UPGRADABLE_TAPROOT_VERSION +
  DISCOURAGE_OP_SUCCESS + DISCOURAGE_UPGRADABLE_PUBKEYTYPE).
- `bitcoin-core/src/policy/policy.cpp:14-78` — `GetDustThreshold`,
  `IsDust`: uses `DUST_RELAY_TX_FEE` (3000 sat/kvB), formula
  `nSize + 67 (witness)` or `nSize + 148 (legacy)`; multiplied by
  `dustRelayFee.GetFee(nSize)`.
- `bitcoin-core/src/policy/policy.cpp:214-263` — `AreInputsStandard`
  (per-input prevout-type + P2SH-redeem sigops check).
- `bitcoin-core/src/policy/policy.cpp:265-352` — `IsWitnessStandard`
  (per-input witness policy: P2A stuffing, P2WSH limits, Taproot annex,
  tapscript item-size limits).
- `bitcoin-core/src/kernel/mempool_options.h` — `MemPoolOptions` struct:
  `min_relay_feerate{DEFAULT_MIN_RELAY_TX_FEE=100}`,
  `incremental_relay_feerate{DEFAULT_INCREMENTAL_RELAY_FEE=100}`,
  `dust_relay_feerate{DUST_RELAY_TX_FEE=3000}`,
  `max_datacarrier_bytes{MAX_OP_RETURN_RELAY=100000}`,
  `permit_bare_multisig{true}`, `require_standard{true}`.
- `bitcoin-core/src/script/interpreter.h` — script-verify flag definitions.

**Files audited**
- `lib/mempool.ml` (4374 lines) — `add_transaction` (1945-2334),
  `accept_transaction` / `accept_transaction_with_replaced` (3096-3119),
  `accept_to_memory_pool` (3138-3175), `replace_by_fee_with_replaced` (2839-3074),
  `accept_package_with_replaced` (4084-4241), `is_standard_tx` (1498-1585),
  `is_witness_standard` (1264-1470), `validate_inputs_standardness` (1181-1240),
  `verify_tx_scripts` (1873-1936), `is_dust` (943-957), `effective_min_fee` (819-821),
  `check_cluster_size_limit` (839-885), `check_ancestor_descendant_limits` (1596-1663),
  `check_truc_policy` (1699-1802), `pre_check_ephemeral_tx` (3292-3298),
  `check_ephemeral_spends` (3338-3408), `is_p2pk_script` (987-996),
  `decode_bare_multisig` (1003-1050), `is_standard_output` (1058-1073),
  `spending_input_size` (925-934), `compute_tx_nonwitness_size` (1482-1485),
  `count_tx_sigops_cost_for_mempool` (1086-1094), `find_all_conflicts` (1813-1826),
  `check_conflict` (1829-1844), `spends_non_anchor_witness_prog` (1856-1871),
  `create` (233-264), `set_network` (3452-3453), `update_height` (3446-3447),
  `update_median_time` (3449-3450), `load_mempool` (3714-3826),
  constants block (119-146, 1473-1478, 223-227, 245).
- `lib/validation.ml` — `check_transaction` (172-238), `is_coinbase_tx` (241-246),
  `is_tx_final` (771-789), `check_sequence_locks` (1012),
  `count_tx_sigops_cost` (523), `verify_one_input` (1228-1254),
  `verify_scripts_parallel_domain` (1287).
- `lib/consensus.ml` — `get_block_script_flags` (870-917),
  `get_standard_policy_flags` (922-933) — script-flag derivation;
  `regtest` config (lines 715-723) with all activation heights ≤ 1;
  `mainnet` config (lines 605-614) heights.
- `lib/cli.ml:420-437` — mempool construction site (omits network parameter).
- `lib/rpc.ml:1149-1222` — `handle_sendrawtransaction` (uses `add_transaction`
  directly, NOT `accept_to_memory_pool`); 2260-2293
  — `sendtoaddress` (also `add_transaction` directly); 2985-3016
  — `handle_testmempoolaccept` (`add_transaction ~dry_run:true`);
  3036-3325 — `handle_submitpackage` (uses `accept_package_with_replaced`).
- `lib/sync.ml:3705-3713` — reorg refill calls `add_transaction
  ~bypass_fee_check:true ~bypass_limits:true` (5th distinct entry).
- `lib/package_relay.ml:46-75` — `handle_pkgtxns` calls `accept_package` (6th
  distinct entry).

---

## Gate matrix (32 sub-gates / 12 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | ATMP entry-point unification | G1: single canonical ATMP function | **BUG-1 (P0-CDIV)** — **6 distinct entry points**: cli.ml:1240 `accept_to_memory_pool` ✓, rpc.ml:1192 `add_transaction` ✗, rpc.ml:2269/2288 `add_transaction` ✗, rpc.ml:2995 `add_transaction ~dry_run:true` ✗, sync.ml:3706 `add_transaction ~bypass_fee_check ~bypass_limits` ✗, package_relay.ml:61 `accept_package` ✓ |
| 1 | … | G2: exception safety on every entry | **BUG-2 (P0-SEC)** — only `accept_to_memory_pool` runs the W96 Bug 13 try/with wrapper. Five paths leak `failwith`/`Not_found`/`Invalid_argument` to caller, including `handle_sendrawtransaction` (peer-controlled hex) |
| 1 | … | G3: RBF reachable from every entry | **BUG-3 (P0-CDIV)** — only `accept_to_memory_pool` calls `accept_transaction_with_replaced`. `handle_sendrawtransaction` returns the verbatim `txn-mempool-conflict` error from `add_transaction` and never attempts RBF, even though Core's `sendrawtransaction` is the canonical RBF entry-point |
| 2 | Per-network activation heights | G4: mempool uses correct chain's activation heights | **BUG-4 (P0-CONSENSUS)** — `Mempool.create` defaults `network = Consensus.regtest` (mempool.ml:237) and the `~network` argument is **not exposed** at the constructor. `cli.ml:434` builds the mempool with no network override. `Mempool.set_network` (mempool.ml:3452) is **defined and exported but called from ZERO sites in production**. Mainnet mempool runs with regtest's BIP-65 height=1, BIP-66=1, CSV=1, SegWit=0, **Taproot=0** — accepts script-path v1 Taproot spends as non-standard mempool entries from genesis, instead of waiting until h=709,632 |
| 3 | Mempool current_median_time wiring | G5: BIP-113 MTP-based locktime enforced | **BUG-5 (P0)** — `mempool.current_median_time` is initialised to `0l` and `update_median_time` is exported but called from **ZERO sites** (grep confirms no caller in `lib/`). `is_tx_final` compares `block_time` (= 0l) against unsigned-32 locktime; for locktimes ≥ `500_000_000L` (Unix-epoch form) the check `0l > 500M` is always FALSE → every time-locked transaction is "non-final" forever, regardless of actual chain MTP |
| 4 | DEFAULT_MIN_RELAY_TX_FEE | G6: matches Core 100 sat/kvB | **BUG-6 (P1)** — `mempool.ml:245` hardcodes `min_relay_fee = 1000L`. Core changed `DEFAULT_MIN_RELAY_TX_FEE` from 1000 to **100** sat/kvB (PR #28366, 2024). Comment "1 sat/vB = 1000 sat/kvB" is correct math, but the value is 10× the current Core default. Operator txs that pay 100 sat/kvB are silently rejected at mempool, then ALSO never relayed (operator sees opaque `Fee below minimum relay fee`) |
| 5 | DUST_RELAY_TX_FEE distinct constant | G7: dust threshold uses dustRelayFee = 3000 sat/kvB, NOT 3 × minRelayFee | **BUG-7 (P0-CDIV)** — `is_dust` (mempool.ml:943-957) uses `3.0 *. min_relay_fee` as the dust rate. Core uses `dustRelayFee.GetFee(nSize)` with `DUST_RELAY_TX_FEE = 3000` — a **separate constant**, not derived from min-relay. Today the bug happens to compute the same number (3 × 1000 = 3000), but the bug surfaces when (a) operator sets `-minrelaytxfee=100` (Core default!) → camlcoin dust rate becomes 300 sat/kvB instead of 3000 → 90% of would-be dust outputs are accepted as non-dust; (b) when the BUG-6 fix lands, the dust threshold silently drops 10× |
| 5 | … | G8: dust input-size derivation matches Core | **BUG-8 (P1)** — `spending_input_size` (mempool.ml:925-934) returns per-script-type spend sizes (P2PKH=148, P2SH=91, P2WPKH=67, P2WSH=109, P2TR=58, P2A=41, OP_RETURN=0, Nonstandard=148). Core uses ONE of two values: 67 (any witness output) or 148 (legacy output). camlcoin's per-type granularity is a **divergence**: e.g. P2WSH=109 vs Core 67 → P2WSH dust threshold ~63% higher than Core → standard txs Core would accept get rejected as dust at relay |
| 5 | … | G9: dust check is `nValue < threshold` | PASS — `output.value < threshold` (line 956) matches Core (line `IsDust` returns `nValue < GetDustThreshold`) |
| 6 | STANDARD_SCRIPT_VERIFY_FLAGS at PolicyScriptChecks | G10: STRICTENC / DISCOURAGE_UPGRADABLE_NOPS / MINIMALIF / DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM / CONST_SCRIPTCODE / DISCOURAGE_UPGRADABLE_TAPROOT_VERSION / DISCOURAGE_OP_SUCCESS / DISCOURAGE_UPGRADABLE_PUBKEYTYPE in policy set | **BUG-9 (P0-CDIV)** — `get_standard_policy_flags` (consensus.ml:922-933) extends `get_block_script_flags` with only 6 STANDARD bits: CLEANSTACK, SIGPUSHONLY, NULLFAIL, LOW_S, MINIMALDATA, WITNESS_PUBKEYTYPE. Core's STANDARD_SCRIPT_VERIFY_FLAGS adds **14 bits** on top of MANDATORY. **8 STANDARD bits are missing**: STRICTENC, DISCOURAGE_UPGRADABLE_NOPS, MINIMALIF, DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, CONST_SCRIPTCODE, DISCOURAGE_UPGRADABLE_TAPROOT_VERSION, DISCOURAGE_OP_SUCCESS, DISCOURAGE_UPGRADABLE_PUBKEYTYPE. Cross-cite W144 fleet pattern (5+ impls confirm STANDARD flags incomplete) |
| 7 | ConsensusScriptChecks defense-in-depth | G11: second script-check pass with block tip flags | **BUG-10 (P0-CDIV)** — Core runs TWO script-check passes: PolicyScriptChecks (STANDARD flags, validation.cpp:1135) then ConsensusScriptChecks (`GetBlockScriptFlags(tip)`, validation.cpp:1158). The second pass guards against bugs in STANDARD flags admitting txs that block-flag validation would reject. camlcoin has ONE pass (`verify_tx_scripts`, mempool.ml:1873) at policy flags. **The defense-in-depth gate that's specifically meant to catch the kind of bug BUG-9 produces is itself absent** — closely-coupled with BUG-9 |
| 8 | -acceptnonstdtxn / -minrelaytxfee / -incrementalrelayfee / -permitbaremultisig / -datacarrier / -datacarriersize / -bytespersigop operator knobs | G12: any CLI flag wires through | **BUG-11 (P1)** — `bin/main.ml` exposes none of these. `Mempool.create` takes `~require_standard` and `~verify_scripts` but the only callsite (`cli.ml:434`) passes neither (defaults to true/true). No way to relax mempool policy on signet/regtest at runtime. Cross-cite W138/W140 "no operator knob exists" pattern |
| 9 | sendrawtransaction maxfeerate semantics | G13: pre-check fee, reject BEFORE mempool insertion | **BUG-12 (P0)** — `handle_sendrawtransaction` (rpc.ml:1192-1208) does `add_transaction` → only then computes fee → if too high, `remove_transaction` after the fact. Core checks `ws.m_modified_fees / ws.m_vsize < max_fee_rate` BEFORE insertion. camlcoin's order leaks the tx to ZMQ subscribers via the `zmq_notify_tx` call inside `add_transaction` (mempool.ml:2327), then evicts. Mempool sequence increments. Eviction triggers fee-estimator `on_eviction` hook (misclassifying as "removed without confirmation"). Race window where a peer reads the tx before the remove |
| 10 | testmempoolaccept matches sendrawtransaction's gate set | G14: same gates run in test mode | **BUG-13 (P1)** — `handle_testmempoolaccept` (rpc.ml:2995) uses `add_transaction ~dry_run:true` and emits only `{txid, allowed, vsize, fees.base}` or `{txid, allowed, reject-reason}`. Core's testmempoolaccept returns `wtxid`, `package-error`, `fees.{base,effective-feerate,effective-includes}`, `vsize`, `txid`. Notable misses: no `wtxid`, no `package-error`, no `fees.effective-feerate`; reject-reason string is camlcoin-flavoured English (e.g. `"Fee below minimum relay fee"`) not Core wire tokens (`min relay fee not met`) |
| 11 | Reject-token wire-parity with Core | G15: `txn-already-in-mempool`, `txn-same-nonwitness-data-in-mempool`, `txn-already-known`, `bad-txns-inputs-missingorspent`, `non-final`, `non-BIP68-final`, `bad-txns-nonstandard-inputs`, `bad-witness-nonstandard`, `coinbase`, `tx-size-small`, `bad-txns-too-many-sigops`, `mempool min fee not met`, `min relay fee not met`, `insufficient fee`, `replacement-failed`, `bip125-replacement-disallowed`, `TRUC-violation`, `too-large-cluster` etc. | **BUG-14 (P1)** — survey of emitted reject strings shows ~15 tokens DIVERGED: `"coinbase"` ✓, `"txn-already-in-mempool"` ✓, `"txn-same-nonwitness-data-in-mempool"` ✓, `"txn-already-known"` ✓, `"tx-size-small"` ✓, `"bad-witness-nonstandard"` ✓ (sometimes); but: `"Transaction is not final (locktime not reached)"` should be `non-final`; `"Transaction sequence locks not satisfied (BIP68)"` should be `non-BIP68-final`; `"Missing input: ..."` should be `bad-txns-inputs-missingorspent`; `"Spending immature coinbase"` should be `bad-txns-premature-spend-of-coinbase`; `"Output exceeds input"` should be `bad-txns-in-belowout`; `"Fee below minimum relay fee"` should be `min relay fee not met`; `"Transaction exceeds max standard sigops cost"` should be `bad-txns-too-many-sigops`; `"Too many ancestors (%d > %d)"` should be `too-long-mempool-chain`; `"Adding transaction would exceed descendant limit (%d)"` should be `too-long-mempool-chain`; `"rejecting replacement; too many conflicting transactions"` should be `too many potential replacements`; etc. ~12 distinct token-drift cases; breaks any monitoring that scrapes Core token reject strings (mempool.space, electrs, btcdash) |
| 12 | MIN_STANDARD_TX_NONWITNESS_SIZE (CVE-2017-12842) | G16: enforced both with and without require_standard | PASS — `mempool.ml:2010` runs the check independently of `require_standard` (W96 Bug 2 closure). Comment-aware Core ref at line 2005-2008 |
| 13 | `bad-txns-inputs-duplicate` replay at mempool | G17: replayed when same input appears twice in the tx | PASS — `Validation.check_transaction` (called at mempool.ml:1953) emits `TxDuplicateInputs`; the check is in the consensus-class path so mempool reuses it |
| 14 | Two-pass validation for sigops cost | G18: re-count when STANDARD flags differ from block-tip flags | **BUG-15 (P1)** — `count_tx_sigops_cost_for_mempool` (mempool.ml:1086-1094) passes only `script_verify_p2sh lor script_verify_witness` to the sigop counter, regardless of mempool's height-derived flag set. After BIP-141 activated, this is correct, but pre-segwit mempool acceptance (if anyone constructs such a tx) ignores legacy-only sigops; the W143 `GetTransactionSigOpCost` path uses the FULL flag set |
| 15 | Coinbase-spend maturity gate | G19: spend_height = chain.Height() + 1 | PASS — `mempool.ml:2092` uses `current_height + 1` (W96 Bug 5 closure) |
| 16 | sigops-adjusted vsize for fee/cluster | G20: vsize = `max(weight/4, sigops * bytes_per_sigop)` | PASS — `mempool.ml:2160` calls `Validation.get_virtual_transaction_size`. Fee floor uses sigop-adjusted vsize (line 2196). |
| 17 | MAX_TX_LEGACY_SIGOPS=2500 | G21: pre-segwit policy cap on legacy sigops | **BUG-16 (P1)** — Core enforces `MAX_TX_LEGACY_SIGOPS=2500` (policy.h:46) separately from the cost-weighted `MAX_STANDARD_TX_SIGOPS_COST=16000`. camlcoin enforces only the cost-weighted variant (mempool.ml:2056-2058). A standard tx with 16,000 cost-weighted sigops spread across multiple witness/P2SH inputs is accepted; a Core node would reject if the legacy-only count exceeds 2500 |
| 18 | DEFAULT_BYTES_PER_SIGOP plumbing | G22: knob exists | **BUG-17 (P1)** — `Consensus.default_bytes_per_sigop = 20` is hardcoded (consensus.ml:46). No CLI override; tests that want a different value have to patch the source |
| 19 | TX_MAX_STANDARD_VERSION=3 | G23: matches Core (v1/v2/v3 = TRUC) | PASS — `mempool.ml:1502` checks `version < 1 || version > 3` (W120 closure for BIP-431/TRUC) |
| 20 | DEFAULT_PERMIT_BAREMULTISIG=true knob | G24: operator can disable bare multisig | **BUG-18 (P1)** — `is_standard_output` (mempool.ml:1058-1073) always accepts bare multisig up to 3-of-N (n ≤ 3). No `-permitbaremultisig` flag; if operator wanted Core's optional `false` setting, no way to express |
| 21 | DEFAULT_ACCEPT_DATACARRIER / -datacarriersize | G25: per-tx OP_RETURN budget configurable | **BUG-19 (P1)** — `max_datacarrier_bytes = 100_000` is hardcoded (mempool.ml:1476). Core has `-datacarrier=0` to reject OP_RETURN entirely AND `-datacarriersize=<n>` to tune the budget. Neither is exposed |
| 22 | -bypass_limits semantics correctness | G26: reorg-refill skips fee floor + TRUC + size limits | **BUG-20 (P1)** — `bypass_limits` is plumbed (mempool.ml:1945), but `bypass_fee_check` is a SEPARATE parameter and the reorg-refill at sync.ml:3706 has to pass both `~bypass_fee_check:true ~bypass_limits:true`. Core has ONE flag (`args.m_bypass_limits`) that gates fee + TRUC + size + lockpoints recompute. camlcoin's bifurcation means a caller that passes only one of the two will incorrectly enforce or skip; current correct usage is by convention only |
| 23 | LockPoints recompute on reorg-refill | G27: `CalculateLockPointsAtTip` re-runs at admission | **BUG-21 (P0)** — Core uses `lock_points = CalculateLockPointsAtTip(tip, m_view, tx)` (validation.cpp:886) and stores them on the mempool entry, then re-validates after every tip change. camlcoin computes `utxo_heights` per-input at admission (mempool.ml:2072-2113) using `current_median_time` (which BUG-5 establishes is always 0). After a reorg that reduces tip height, the cached `entry.depends_on`/per-input heights are stale; nothing recomputes BIP-68 lockpoints |
| 24 | TX_WITNESS_STRIPPED tag for SpendsNonAnchorWitnessProg | G28: re-tag error on missing-witness rejection | PASS — `mempool.ml:1923-1935` emits `"witness-stripped: <error>"` prefix (W96 Bug 12 closure). String format is camlcoin-flavoured (`witness-stripped:` prefix vs Core's `TX_WITNESS_STRIPPED` state tag); BUG-14 covers the wire-parity |
| 25 | conflict tx vs already-in-mempool ordering | G29: check `mempool.exists(wtxid)` then `mempool.exists(txid)` then conflict | PASS — `mempool.ml:1971-2002` (W96 Bug 3 closure) does wtxid-exact, then txid-different-witness, then mempool-conflict in correct Core order |
| 26 | Mempool persistence loader exception safety | G30: load_mempool catches per-tx exceptions | **BUG-22 (P0-SEC)** — `load_mempool` (mempool.ml:3714-3826) calls `add_transaction mp tx` (line 3780) — NOT `accept_to_memory_pool`. If an attacker-controlled or corrupted mempool.dat contains a tx that triggers a Crypto/Script exception, the outer `try ... with _ -> ()` (line 3824) swallows the error but ALSO stops loading the rest of the file. Core's `LoadMempool` catches per-tx and continues; one bad tx aborts the rest of camlcoin's mempool restore. Cross-cite with BUG-2 |
| 26 | … | G31: `apply_fee_delta_priority` knob for `importmempool` | **BUG-23 (P1)** — Core's `LoadMempool` defaults `apply_fee_delta_priority=true` for auto-restart but the `importmempool` RPC opts it to `false`. camlcoin always applies (mempool.ml:3789, 3813), no knob. Cross-cite W138/W140 "no operator knob exists" |
| 27 | Empty-mempool dust handling on package | G32: dust gate runs per-package on accepted tx subset | PASS — `accept_package_with_replaced` re-runs `check_ephemeral_spends` on accepted subset after partial-accept (mempool.ml:4232-4238) |
| 28 | sendtoaddress path safety | G33: wallet → ATMP routes through canonical entry | **BUG-24 (P0-SEC)** — `handle_sendtoaddress` (rpc.ml:2269/2288) skips both the exception-safe wrapper AND the maxfeerate / maxburnamount checks. A wallet bug that builds an absurdly-high-fee tx is accepted into the local mempool with no relay-side check; relayed to peers; peer rejects per their own maxfeerate. Combined with no `-maxtxfee` wallet knob, the wallet can easily build self-DoS txs |

---

## BUG-1 (P0-CDIV) — Six distinct mempool acceptance entry points with divergent gate sets

**Severity:** P0-CDIV. The hashhog quad-audit running theme of "two-pipeline guard"
escalates here: camlcoin has **six** code paths admitting transactions to the mempool,
and they all skip different gates.

Inventory:

| Caller | Entry point | RBF? | Safe wrapper? | bypass_limits? | bypass_fee_check? | dry_run? |
|--------|-------------|------|----------------|----------------|-------------------|----------|
| `cli.ml:1240` (P2P tx relay) | `accept_to_memory_pool` | ✓ | ✓ | – | – | – |
| `rpc.ml:1192` (`sendrawtransaction`) | `add_transaction` | ✗ | ✗ | – | – | – |
| `rpc.ml:2269/2288` (`sendtoaddress`) | `add_transaction` | ✗ | ✗ | – | – | – |
| `rpc.ml:2995` (`testmempoolaccept`) | `add_transaction ~dry_run:true` | ✗ | ✗ | – | – | ✓ |
| `sync.ml:3706` (reorg-refill) | `add_transaction ~bypass_fee_check ~bypass_limits` | ✗ | ✗ | ✓ | ✓ | – |
| `rpc.ml:3113` (`submitpackage`) | `accept_package_with_replaced` | per-tx | ✗ | – | per-package | – |
| `package_relay.ml:61` (BIP-331 pkgtxns) | `accept_package` | per-tx | ✗ | – | per-package | – |

Six pipelines, each with a slightly different gate set. Core has **one**
entry-point (`AcceptToMemoryPool` → `AcceptSingleTransaction`) that all
public-facing acceptance routes through. Internally Core distinguishes
single-tx vs package via `ATMPArgs::SingleAccept` / `PackageTestAccept` /
`PackageChildWithParents` static constructors that thread the SAME args
type through the SAME pipeline.

This is the **4th-consecutive quad-audit observation** of multi-pipeline drift
in camlcoin (W143 BUG-2 — 5 distinct pipelines including 3 wtxid definitions;
W144 BUG-12 two flag-derivation helpers diverge; W145 BUG-1 block_import.ml
bypasses every validation gate; W149 carry-forward). **It is now a structural
property of camlcoin**: pipelines branch on every audit and converge on none.

**File:** mempool.ml entry points 1873-2334 (add_transaction), 3096-3175
(accept_to_memory_pool); rpc.ml call sites 1192/2269/2288/2995/3113;
sync.ml:3706; package_relay.ml:61; cli.ml:1240.

**Core ref:** `bitcoin-core/src/validation.cpp:435-680` — single `MemPoolAccept`
class with ATMPArgs context; static constructors `SingleAccept`,
`PackageTestAccept`, `PackageChildWithParents`, `PackageChildWithParentsAccept`
all route through `AcceptSingleTransactionInternal` /
`AcceptMultipleTransactions`.

**Impact:** Five of six entry points bypass exception protection (BUG-2),
RBF (BUG-3), and divergent invariant checks. Operator-visible inconsistency:
a tx accepted from peer-relay is rejected from `sendrawtransaction`. Bug
surface multiplied 6×.

---

## BUG-2 (P0-SEC) — Exception protection only on the P2P entry-point

**Severity:** P0-SEC. `accept_to_memory_pool` (mempool.ml:3138-3175) is the
ONLY entry path that catches `Failure` / `Invalid_argument` / `Not_found` from
the validation pipeline. The comment at line 3140-3146 explicitly recognises
the risk:

```ocaml
(* W96 Bug 13: ATMP entry point must catch ALL exceptions.  Matches the
   W95-class hardening — peer-controlled inputs (txid/wtxid computation,
   script eval via libsecp, deeply nested helpers) MUST NOT be allowed to
   propagate failwith/Not_found/Invalid_argument out of ATMP, since RPC,
   P2P and miner paths call ATMP without their own try/with. *)
```

But the comment-as-confession is **wrong about the scope**. Only the P2P
listener (`cli.ml:1240`) routes through this. The RPC paths
(`sendrawtransaction`, `sendtoaddress`, `testmempoolaccept`) skip it, even
though the comment specifically says "RPC, P2P and miner paths call ATMP
without their own try/with".

**Concrete vector**: an attacker submits a hex-encoded tx via
`sendrawtransaction` whose witness data, when parsed, hits a
`List.nth … (-1)` (Invalid_argument) or `Hashtbl.find` (Not_found) inside
nested helpers (e.g. `is_witness_standard` walks scriptSig via
`Script.parse_script` which can raise). The exception bubbles out of
`handle_sendrawtransaction`, hits the OCaml `Lwt` exception handler in
`rpc.ml`'s request dispatcher, and may either (a) crash the request handler,
(b) corrupt RPC state, or (c) leak internal error strings. The wrapper
exists; **it is plumbed-but-not-wired**.

**File:** mempool.ml:3138-3175 (the wrapper); rpc.ml:1192, 2269, 2288, 2995
(callers that skip it); sync.ml:3706 (reorg path); package_relay.ml:61.

**Core ref:** `bitcoin-core/src/validation.cpp:583-589` — `AcceptSingleTransactionAndCleanup`
wraps `AcceptSingleTransactionInternal` and propagates `TxValidationState`
NEVER C++ exceptions. All public entry-points route through this.

**Impact:** RPC and reorg-refill paths can crash on attacker-controlled input.
W96 Bug 13 closure was incomplete.

---

## BUG-3 (P0-CDIV) — `sendrawtransaction` cannot trigger RBF

**Severity:** P0-CDIV. `accept_transaction_with_replaced` (mempool.ml:3096-3113)
is the RBF-aware entry. It walks conflict detection first, then routes
either through plain `add_transaction` (no conflicts) or
`replace_by_fee_with_replaced` (RBF path).

`handle_sendrawtransaction` (rpc.ml:1192) calls `Mempool.add_transaction`
**directly**. The conflict detection runs inside `add_transaction` but the
caller-level branch to RBF does not. So when the user submits an RBF
replacement via `sendrawtransaction`, they get back a verbatim error from
`add_transaction`:

```ocaml
| Some conflict_txid ->
  Error (Printf.sprintf "txn-mempool-conflict: spends same input as %s" ...)
```

instead of the RBF being attempted. Core's `sendrawtransaction` invokes
`AcceptToMemoryPool` which IS the RBF-aware path; an RBF replacement that
meets BIP-125/RBFv3 fee rules succeeds.

Same problem at `handle_sendtoaddress` (rpc.ml:2269, 2288) — wallet-built
RBF replacements always fail with `txn-mempool-conflict` even when the
wallet correctly bumped the fee.

**File:** rpc.ml:1192-1208 (`handle_sendrawtransaction`); rpc.ml:2269, 2288
(`handle_sendtoaddress`).

**Core ref:** `bitcoin-core/src/rpc/mempool.cpp::sendrawtransaction` calls
`AcceptToMemoryPool(*node.chainman, ptx, GetTime(), /*bypass_limits=*/false,
/*test_accept=*/false)`. That routes through `AcceptSingleTransaction` →
`PreChecks` → `ReplacementChecks` (when conflicts detected).

**Impact:** RBF via `sendrawtransaction` non-functional. Operators using
`bitcoin-cli sendrawtransaction <rbf-replacement-hex>` get verbatim conflict
errors. Wallet UI that bumps fees fails. Bitcoin Core compatibility broken
at the RPC layer for a frequent operator workflow.

---

## BUG-4 (P0-CONSENSUS) — `Mempool.create` hardcodes `Consensus.regtest`; `set_network` is dead-data plumbing

**Severity:** **P0-CONSENSUS class divergence**. `mempool.ml:233-264`:

```ocaml
let create ?(require_standard=true) ?(verify_scripts=true)
    ?(zmq_notifier : Zmq_notify.t option)
    ?(on_eviction : (Types.hash256 -> unit) option = None)
    ~(utxo : Utxo.UtxoSet.t) ~(current_height : int) () : mempool =
  let network = Consensus.regtest in            (* <-- HARDCODED *)
  { entries = Hashtbl.create 10_000;
    ...
    network;
    ...
```

The `~network` parameter is **NOT** exposed by the constructor. `cli.ml:434`
builds the mempool with no network argument. `Mempool.set_network`
(mempool.ml:3452-3453) is defined, exported, but called from **zero sites**
in production (grep `set_network` in `lib/` and `bin/` returns only the
definition).

**Concrete consequence on a mainnet node:**

`verify_tx_scripts` at mempool.ml:1878 derives flags via:
```ocaml
let flags = Consensus.get_standard_policy_flags (mp.current_height + 1) mp.network in
```

with `mp.network = Consensus.regtest`. Regtest activation heights are:
- bip65_height = 1, bip66_height = 1, csv_height = 1
- segwit_height = 0, taproot_height = 0 (consensus.ml:761-765)

So on a mainnet node at tip h = 900,000 (post-Taproot anyway), the script
flags are correct for the post-Taproot world. **BUT** for a mainnet node
that restarts mid-IBD at height 600,000 (pre-Taproot, h < 709,632) — the
mempool will set `script_verify_taproot` because
`get_block_script_flags` tests `if height >= network.taproot_height` and
regtest's `taproot_height = 0`. The mempool accepts BIP-341/342 spends
as standard six years before mainnet activation. Same shape for SegWit
on a mainnet node at h < 481,824 — SegWit witnesses validated as standard
in mempool, contradicting consensus.

Reorg / re-IBD scenarios: even on mainnet at tip, if the chain is rewound
below `taproot_height`, the mempool keeps Taproot active.

Additionally, BIP-30 / BIP-34 / BIP-66 / BIP-65 / CSV activation:
mainnet bip66_height = 363725 but mempool's `mp.network.bip66_height = 1`
→ DERSIG enforced in mempool at every height. Currently benign (Core also
enforces post-363725); but the principle is **wrong** — mempool is using
the wrong network's params.

**File:** mempool.ml:237 (hardcoded `Consensus.regtest`);
mempool.ml:3452-3453 (`set_network` defined but not called); cli.ml:434
(constructor call with no network); consensus.ml:715-723 (regtest), 605-614
(mainnet).

**Core ref:** `bitcoin-core/src/validation.cpp` — `MemPoolAccept` ctor takes
`Chainstate&` which contains `m_chainman.GetConsensus()`. Every Core mempool
operates with the network's own consensus params; there is no way to
construct a mempool whose script flags are derived from a different
chain's heights.

**Excerpt (camlcoin, hardcoded + uncalled)**
```ocaml
(* mempool.ml:237 *)
let network = Consensus.regtest in            (* hardcoded; ~network not in sig *)
...
(* mempool.ml:1878 *)
let flags = Consensus.get_standard_policy_flags (mp.current_height + 1) mp.network in
                                                                            (* regtest *)
(* mempool.ml:3452 *)
let set_network (mp : mempool) (network : Consensus.network_config) : unit =
  mp.network <- network                       (* called from zero sites *)
```

**Impact:**
- Mempool accepts pre-activation soft-fork-violating txs as standard on a
  mid-IBD mainnet node.
- BIP-66/65/CSV activation-window logic effectively inert.
- "dead-data plumbing" fleet pattern (8th camlcoin instance per running
  index): `set_network` exists, is exported, never called.
- **Carry-forward of W144 BUG-12 — "two flag-derivation helpers diverge"
  taken one step further: the OTHER (block-side) flag computer correctly
  uses chain-tip network, but mempool's runs on regtest.**

---

## BUG-5 (P0) — `update_median_time` never called; BIP-113 time-based locktimes always rejected

**Severity:** P0. `mempool.current_median_time` is initialised to `int32 0l`
(mempool.ml:253) and the only mutator, `update_median_time` (mempool.ml:3449-3450),
is exported but called from **zero production sites** (grep over `lib/` and
`bin/` returns only the definition).

In `add_transaction`'s locktime gate at mempool.ml:2062-2064:
```ocaml
if not (Validation.is_tx_final tx
          ~block_height:(mp.current_height + 1)
          ~block_time:mp.current_median_time) then
  Error "Transaction is not final (locktime not reached)"
```

`is_tx_final` in validation.ml:773-789 treats locktime ≥ 500_000_000 as
Unix-epoch and checks `block_time > locktime`. With `block_time = 0l`
forever, every Unix-epoch locktime ≥ 500_000_000 satisfies `0l > 500M` = false
→ **every time-based-locktime transaction is non-final forever**, no matter
how long ago the locktime was. A tx locktime'd to 1 Jan 2020 (1577836800)
is rejected today (2026-05-18) with `"Transaction is not final (locktime
not reached)"` because the mempool thinks the chain MTP is 1970-01-01.

Identically broken for `check_sequence_locks` at mempool.ml:2127-2130:
```ocaml
if not (Validation.check_sequence_locks tx
          ~block_height:(mp.current_height + 1)
          ~median_time:mp.current_median_time
          ~utxo_heights ~utxo_mtps ~flags ()) then
  Error "Transaction sequence locks not satisfied (BIP68)"
```

— `median_time` is always 0l, so BIP-68 time-based sequence locks are also
mis-enforced.

**File:** mempool.ml:253 (init to 0l), 3449-3450 (mutator), 2062-2064 +
2127-2130 (consumers); validation.ml:773-789 (`is_tx_final`); grep `lib/`
and `bin/` for `update_median_time` returns only the definition.

**Core ref:** `bitcoin-core/src/validation.cpp:819` — `CheckFinalTxAtTip(tip, tx)`;
`validation.cpp:887` — `CheckSequenceLocksAtTip(tip, lock_points)`. Both
use the chain tip's MTP directly via `tip->GetMedianTimePast()`, not a
mempool-cached value.

**Excerpt (camlcoin, dead mutator)**
```ocaml
(* mempool.ml:253 *)
current_median_time = 0l;       (* initialised to zero *)

(* mempool.ml:3449-3450 *)
let update_median_time (mp : mempool) (mtp : int32) : unit =
  mp.current_median_time <- mtp  (* function defined, exported, never called *)
```

**Impact:**
- ALL transactions with time-based locktime (`nLockTime >= 500_000_000`,
  the common form for wallet-coordinated future spends) are rejected at
  mempool with `"Transaction is not final (locktime not reached)"`.
- ALL BIP-68 time-based sequence locks (CSV/relative time-locks) fail.
- Lightning channel close txs with future-anchored locktimes can't be
  broadcast.
- Cross-cite with BUG-4 (`set_network` also dead) — second `update_*`
  helper that is exported-but-unwired.

---

## BUG-6 (P1) — `min_relay_fee = 1000` is 10× Core's default (which is 100)

**Severity:** P1. Core's `DEFAULT_MIN_RELAY_TX_FEE = 100` sat/kvB
(`bitcoin-core/src/policy/policy.h:70`). Camlcoin (mempool.ml:245)
hardcodes `min_relay_fee = 1000L`. The comment "1 sat/vB = 1000 sat/kvB"
is correct math but applies the wrong base unit — the Core constant is
**100 sat/kvB = 0.1 sat/vB**, not 1 sat/vB.

Core lowered the default from 1000 to 100 in PR #28366 (Sept 2024) to
allow lower-fee txs to relay in low-mempool-pressure regimes. camlcoin
nodes reject 100..999 sat/kvB txs that Core nodes (today) would accept and
relay. The reverse-relay scenario: Core nodes RELAY 200 sat/kvB txs to
camlcoin peers, camlcoin rejects them ("Fee below minimum relay fee"),
camlcoin doesn't gossip them further. camlcoin nodes become **relay
black holes** for low-fee txs.

**File:** mempool.ml:245 (constant); rpc.ml:1219 / mempool.ml:2198 (consumers).

**Core ref:** `bitcoin-core/src/policy/policy.h:70`
`static constexpr unsigned int DEFAULT_MIN_RELAY_TX_FEE{100};`

**Impact:**
- Low-fee txs accepted by Core mempools get rejected at camlcoin mempools.
- Camlcoin nodes effectively black-hole low-fee relays.
- Operator monitoring sees "Fee below minimum relay fee" rejects on txs
  that Core would accept.
- Cross-cite W128 fleet-wide-banman pattern: this is a fleet candidate too
  — likely several impls still on 1000.

---

## BUG-7 (P0-CDIV) — `is_dust` conflates `dust_relay_fee` with `3 × min_relay_fee`

**Severity:** P0-CDIV. Core has **two distinct constants**:
- `DEFAULT_MIN_RELAY_TX_FEE = 100` (sat/kvB) — relay-fee floor
- `DUST_RELAY_TX_FEE = 3000` (sat/kvB) — dust-threshold rate

They are independently configurable via `-minrelaytxfee` and
`-dustrelayfee`. `IsDust` (`policy/policy.cpp`) uses `dustRelayFee.GetFee(nSize)`.

Camlcoin's `is_dust` (mempool.ml:943-957) computes:
```ocaml
let threshold = Int64.of_float (
  3.0 *. Int64.to_float min_relay_fee *.
  float_of_int (output_serialized_size output + spend_size) /. 1000.0) in
output.Types.value < threshold
```

The formula is `3 × min_relay_fee × size / 1000`. Today, with
`min_relay_fee = 1000` (BUG-6), this happens to produce `3000 × size /
1000` which matches Core's dust threshold. But:

- If BUG-6 is fixed (`min_relay_fee → 100`), the dust threshold becomes
  `300 × size / 1000` = 10× too low. P2PKH dust limit drops from 546 sat
  to ~55 sat. The mempool starts accepting outputs Core considers dust.
- If operator sets `-minrelaytxfee=200`, dust becomes `600 × size / 1000`,
  again not the Core 3000-anchored value.

**File:** mempool.ml:943-957 (`is_dust`); compare to
bitcoin-core/src/policy/policy.cpp::GetDustThreshold.

**Core ref:** `bitcoin-core/src/policy/policy.h:68`
`static constexpr unsigned int DUST_RELAY_TX_FEE{3000};`
+ `policy.cpp::GetDustThreshold` uses `dustRelayFee.GetFee(nSize)`,
where `dustRelayFee` is an INDEPENDENT `CFeeRate` from `min_relay_feerate`.

**Excerpt (camlcoin, conflated)**
```ocaml
(* mempool.ml:943-957 *)
let is_dust (min_relay_fee : int64) (output : Types.tx_out) : bool =
  ...
  let threshold = Int64.of_float (
    3.0 *. Int64.to_float min_relay_fee *.   (* SHOULD BE DUST_RELAY_TX_FEE = 3000 *)
    float_of_int (output_serialized_size output + spend_size) /. 1000.0) in
  output.Types.value < threshold
```

**Impact:**
- Today: accidentally produces the right value (3 × 1000 = 3000).
- After BUG-6 fix (which Core has already shipped): dust threshold drops 10×.
- Operator-knob divergence: `-dustrelayfee` cannot be set independently.
- Cross-cite fleet "constant-aliasing": one constant doing two distinct
  jobs, fragile under one-of-two changes.

---

## BUG-8 (P1) — `spending_input_size` uses per-script-type granularity diverging from Core's 2-tier

**Severity:** P1. Core's `GetDustThreshold` (policy.cpp:14-78) uses ONE
of two spend sizes:
- witness output: `nSize + 67`
- legacy output: `nSize + 148`

Camlcoin's `spending_input_size` (mempool.ml:925-934) returns:
- P2PKH = 148
- P2SH = 91
- P2WPKH = 67
- P2WSH = 109
- P2TR = 58
- P2A = 41
- OP_RETURN = 0
- Nonstandard = 148

For an output Core says costs 67 to spend, camlcoin can say 58 (P2TR),
109 (P2WSH), or 67 (P2WPKH). The dust threshold (which scales linearly
in spend size) thus diverges per-type:

| Output type | Core "+spend" | camlcoin | Camlcoin dust = Core × |
|-------------|---------------|----------|-----------------------|
| P2PKH       | 148           | 148      | 1.0                   |
| P2SH        | 148 (legacy)  | 91       | 0.61 (lower threshold)|
| P2WPKH      | 67            | 67       | 1.0                   |
| P2WSH       | 67            | 109      | 1.63                  |
| P2TR        | 67            | 58       | 0.87                  |
| P2A         | 67            | 41       | 0.61                  |

A standard P2WSH output with value just-above-Core's-546-sat threshold but
below-camlcoin's-~890-sat threshold gets rejected at relay as dust by
camlcoin and accepted by Core. Wallet UX: "Bitcoin Core says this output
is fine, camlcoin says it's dust".

**File:** mempool.ml:925-934.

**Core ref:** `bitcoin-core/src/policy/policy.cpp:42-75` —
`if (txout.scriptPubKey.IsWitnessProgram(witnessversion, witnessprogram))
{ nSize += (32 + 4 + 1 + (107 / WITNESS_SCALE_FACTOR) + 4); } else
{ nSize += (32 + 4 + 1 + 107 + 4); }`. Core uses 67 for ALL witness
outputs (any version, any size) and 148 for ALL legacy.

**Impact:** Per-script-type dust threshold divergence. Standard outputs
accepted by Core get rejected by camlcoin as dust on P2WSH / P2A; vice
versa for P2SH / P2A (camlcoin under-rejects).

---

## BUG-9 (P0-CDIV) — `STANDARD_SCRIPT_VERIFY_FLAGS` missing 8 of 14 STANDARD bits

**Severity:** P0-CDIV. Core's STANDARD_SCRIPT_VERIFY_FLAGS adds **14 bits**
on top of MANDATORY (policy.h:119-132):

```cpp
static constexpr script_verify_flags STANDARD_SCRIPT_VERIFY_FLAGS{MANDATORY_SCRIPT_VERIFY_FLAGS |
    SCRIPT_VERIFY_STRICTENC |
    SCRIPT_VERIFY_MINIMALDATA |
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS |
    SCRIPT_VERIFY_CLEANSTACK |
    SCRIPT_VERIFY_MINIMALIF |
    SCRIPT_VERIFY_NULLFAIL |
    SCRIPT_VERIFY_LOW_S |
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM |
    SCRIPT_VERIFY_WITNESS_PUBKEYTYPE |
    SCRIPT_VERIFY_CONST_SCRIPTCODE |
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION |
    SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS |
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE};
```

Camlcoin's `get_standard_policy_flags` (consensus.ml:922-933) adds only
6 bits over the consensus block-script-flags:

```ocaml
let get_standard_policy_flags (height : int) (network : network_config) : int =
  let base = get_block_script_flags height network in
  let extra = ref 0 in
  if height >= network.segwit_height then begin
    extra := !extra lor script_verify_cleanstack;
    extra := !extra lor script_verify_sigpushonly;       (* Core lacks SIGPUSHONLY here *)
    extra := !extra lor script_verify_nullfail;
    extra := !extra lor script_verify_low_s;
    extra := !extra lor script_verify_minimaldata;
    extra := !extra lor script_verify_witness_pubkeytype
  end;
  base lor !extra
```

**Missing 8 bits** compared to Core STANDARD (and one extra that Core does
not have):

| Core flag | camlcoin status |
|-----------|-----------------|
| `STRICTENC` | MISSING |
| `MINIMALDATA` | present |
| `DISCOURAGE_UPGRADABLE_NOPS` | MISSING |
| `CLEANSTACK` | present |
| `MINIMALIF` | MISSING |
| `NULLFAIL` | present |
| `LOW_S` | present |
| `DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM` | MISSING |
| `WITNESS_PUBKEYTYPE` | present |
| `CONST_SCRIPTCODE` | MISSING |
| `DISCOURAGE_UPGRADABLE_TAPROOT_VERSION` | MISSING |
| `DISCOURAGE_OP_SUCCESS` | MISSING |
| `DISCOURAGE_UPGRADABLE_PUBKEYTYPE` | MISSING |
| `SIGPUSHONLY` (camlcoin-only) | extraneous (Core enforces SCRIPT_VERIFY_SIGPUSHONLY via per-input `IsPushOnly` check in IsStandardTx, not via the flag) |

The mempool fails to discourage upgradable NOPs (so old NOP-using txs are
"standard" and may DoS-relay), upgradable witness programs (the entire
forward-compat mechanism), upgradable Taproot versions, upgradable OP_SUCCESS
opcodes, upgradable pubkey types. Soft-fork preparation is broken at the
relay layer.

**File:** consensus.ml:922-933.

**Core ref:** `bitcoin-core/src/policy/policy.h:119-132`.

**Cross-cite:** W144 BUG-3 fleet pattern — 5+ impls confirm STANDARD flags
incomplete; haskoin missing ALL 14; blockbrew missing 9 of 13. **Camlcoin
missing 8 of 14**, plus has an extra (SIGPUSHONLY) that doesn't belong.

**Impact:**
- Tapscript txs that use future leaf versions (which Core would discourage
  with `DISCOURAGE_UPGRADABLE_TAPROOT_VERSION`) are relayed by camlcoin.
- Future witness-version v2+ outputs aren't filtered.
- MINIMALIF rule violations relay (allows non-minimal IF/NOTIF stack
  encoding, which would otherwise be rejected post-Taproot).
- Soft-fork onboarding strategy broken: camlcoin will happily relay txs
  that exploit upgradable behaviour Core specifically discourages.

---

## BUG-10 (P0-CDIV) — ConsensusScriptChecks gate (second-pass with block-tip flags) is entirely absent

**Severity:** P0-CDIV. Core runs **two** script-verification passes during ATMP:

1. `PolicyScriptChecks(args, ws)` at validation.cpp:1135-1156 uses
   `STANDARD_SCRIPT_VERIFY_FLAGS` (the strict policy set).
2. `ConsensusScriptChecks(args, ws)` at validation.cpp:1158-1189 uses
   `GetBlockScriptFlags(*m_active_chainstate.m_chain.Tip(), m_active_chainstate.m_chainman)`
   (the actual current-tip consensus flags).

The two-pass design is explicitly defense-in-depth (comment at 1173-1176):

```cpp
// This is also useful in case of bugs in the standard flags that cause
// transactions to pass as valid when they're actually invalid. For
// instance the STRICTENC flag was incorrectly allowing certain
// CHECKSIG NOT scripts to pass, even though they were invalid.
```

Camlcoin runs ONE pass — `verify_tx_scripts` (mempool.ml:1873-1936) — using
`get_standard_policy_flags` (i.e., policy flags). The block-tip consensus
flags are never re-checked. Combined with BUG-9 (8 STANDARD bits missing)
and BUG-4 (mempool uses regtest activation heights), the precise scenario
Core's two-pass design exists to guard against (a bug in STANDARD flags
admitting a non-consensus tx) is **specifically unprotected in camlcoin**.

Worked example: a transaction that violates `MINIMALDATA` but passes
camlcoin's mempool because MINIMALDATA happens to fire correctly at
policy-flag layer but a bug in mempool-flag derivation accidentally drops
the bit. Core would re-verify against block-tip's
`GetBlockScriptFlags` (which has MINIMALDATA permanently set since BIP-141)
and reject. Camlcoin would let it in.

**File:** mempool.ml:1873-1936 (single pass); compare to
bitcoin-core/src/validation.cpp:1135-1189 (two passes).

**Core ref:** validation.cpp:1158-1189 — ConsensusScriptChecks +
`CheckInputsFromMempoolAndCache` + `Assume(false)` on disagreement.

**Excerpt (camlcoin, single pass)**
```ocaml
(* mempool.ml:1873 *)
let verify_tx_scripts (mp : mempool) (tx : Types.transaction)
    : (unit, string) result =
  let flags = Consensus.get_standard_policy_flags (mp.current_height + 1) mp.network in
  ...
  (* NO SECOND PASS against get_block_script_flags(tip) *)
```

**Impact:**
- Defense-in-depth against STANDARD-flag bugs is missing.
- Cross-cite BUG-9 (STANDARD missing 8 bits) + BUG-4 (wrong network heights)
  — combined with the absent second pass, mempool can admit a tx Core
  would reject at any post-mempool checkpoint.

---

## BUG-11 (P1) — No operator knob for `-acceptnonstdtxn`, `-minrelaytxfee`, `-incrementalrelayfee`, `-permitbaremultisig`, `-datacarrier`, `-datacarriersize`, `-bytespersigop`, `-maxmempool`, `-mempoolexpiry`

**Severity:** P1. `bin/main.ml` and `lib/runtime_config.ml` expose no CLI
flag for any of these mempool tuneables. `Mempool.create` takes
`~require_standard` and `~verify_scripts` arguments but the only caller
(`cli.ml:434`) does not pass either — both default to `true`.

Operators cannot:
- Disable IsStandard checks on signet / regtest / testnet (Core's `-acceptnonstdtxn`).
- Override the min-relay-fee (currently the hardcoded 1000 sat/kvB from BUG-6).
- Override the incremental relay fee (hardcoded 100 sat/kvB).
- Override bare-multisig acceptance.
- Reduce or disable OP_RETURN datacarrier budget.
- Tune bytespersigop or expiry.

Fleet pattern: 4th wave (W138/W140/W148 also recorded "no operator-knob exists").

**File:** bin/main.ml (CLI registration); cli.ml:434 (constructor); mempool.ml:233 (constructor signature).

**Core ref:** `bitcoin-core/src/init.cpp` argument registration of all
`-minrelaytxfee`, `-incrementalrelayfee`, `-acceptnonstdtxn`,
`-permitbaremultisig`, `-datacarrier`, `-datacarriersize`,
`-bytespersigop`, `-maxmempool`, `-mempoolexpiry`. All wire into
`MemPoolOptions` (kernel/mempool_options.h).

**Impact:** Test-net experiments require source patches. Operator UX gap
vs Core.

---

## BUG-12 (P0) — `sendrawtransaction` maxfeerate check INSERTS into mempool first, then evicts

**Severity:** P0. `handle_sendrawtransaction` (rpc.ml:1192-1208):

```ocaml
match Mempool.add_transaction ctx.mempool tx with
| Ok entry ->
  ...
  let max_fee_sats = ...max_fee_rate calc... in
  if entry.fee > max_fee_sats && max_fee_rate > 0.0 then begin
    Mempool.remove_transaction ctx.mempool entry.txid;
    Error (Printf.sprintf "Fee exceeds maximum: ...")
  end
  else ...
```

Side effects observable BETWEEN `add_transaction` and `remove_transaction`:
1. `zmq_notify_tx mp txid tx true` fires inside `add_transaction` (mempool.ml:2327)
   → ZMQ subscribers (block-explorers, fee oracles) see the tx as accepted.
2. `mp.zmq_sequence` increments (mempool.ml:330-345).
3. If the tx caused an eviction via cluster-size or chunk-fee logic, those
   evicted txs are GONE (`evict_by_chunks` called at mempool.ml:2323-2324).
   `remove_transaction` of the new tx does not restore them.
4. The fee estimator's `on_eviction` hook fires on the evicted txs.

Core's `AcceptToMemoryPool` checks fee FIRST. The Core RPC layer (`rpc/mempool.cpp::sendrawtransaction`)
constructs `max_raw_tx_fee_rate` then passes it to `BroadcastTransaction` which
checks BEFORE relay. The insertion+eviction races are not possible.

**File:** rpc.ml:1192-1218.

**Core ref:** `bitcoin-core/src/rpc/mempool.cpp::sendrawtransaction` —
fee-rate check via `args.GetMaxRawTxFee` evaluated before `BroadcastTransaction`.

**Excerpt (camlcoin, insert-then-evict race)**
```ocaml
match Mempool.add_transaction ctx.mempool tx with    (* COMMIT *)
| Ok entry ->
  ...
  if entry.fee > max_fee_sats ... then begin
    Mempool.remove_transaction ctx.mempool entry.txid;  (* UNDO *)
    Error ...
  end
```

**Impact:**
- ZMQ-listening services see the tx as "accepted" briefly, then never see
  a removal notification — sequence numbers drift in subscribers.
- Fee estimator records spurious eviction.
- Cluster-eviction cascade is irreversible — peripheral mempool entries
  may have been kicked.
- Per-vector race window for monitoring tools.

---

## BUG-13 (P1) — `testmempoolaccept` shape diverges from Core (no wtxid, no fees.effective-feerate, no package-error)

**Severity:** P1. Core's `testmempoolaccept` (rpc/mempool.cpp) returns
per-tx:

```json
{
  "txid": "...",
  "wtxid": "...",                       <-- camlcoin: ABSENT
  "package-error": "...",               <-- camlcoin: ABSENT (single-tx mode)
  "allowed": false,
  "vsize": 162,
  "reject-reason": "...",               <-- camlcoin: emits non-Core English strings (BUG-14)
  "fees": {
    "base": 0.0001,
    "effective-feerate": 0.00012,       <-- camlcoin: ABSENT
    "effective-includes": ["..."]       <-- camlcoin: ABSENT
  }
}
```

Camlcoin's emission (rpc.ml:2999-3012):
```ocaml
Ok (`List [`Assoc [
  ("txid", `String hex_txid);
  ("allowed", `Bool true);
  ("vsize", `Int vsize);
  ("fees", `Assoc [
    ("base", `Float fee_btc);
  ]);
]])
```

Missing `wtxid` is the biggest divergence — wtxid is the BIP-339-canonical
ID; tooling that uses `testmempoolaccept` to dry-run RBF replacements keys
on wtxid.

**File:** rpc.ml:2985-3016.

**Core ref:** `bitcoin-core/src/rpc/mempool.cpp::testmempoolaccept`.

**Impact:** Cross-fleet RPC-shape divergence; breaks `testmempoolaccept`-
consuming wallet integrations (BDK, wasabi, sparrow) that expect wtxid.

---

## BUG-14 (P1) — Reject-string wire-parity broken on ~12 distinct tokens

**Severity:** P1 (cross-impl divergence). Core's `TxValidationState` reject
reasons are stable wire tokens (used by RPC `testmempoolaccept`,
`getrawtransaction` and `bitcoind` log scrapers). Camlcoin emits
English sentences instead. Comparison:

| Core token | camlcoin emission |
|------------|-------------------|
| `coinbase` | `"coinbase"` ✓ |
| `tx-size-small` | `"tx-size-small"` ✓ |
| `bad-witness-nonstandard` | `"bad-witness-nonstandard: ..."` ✓ (with appended detail) |
| `txn-already-in-mempool` | `"txn-already-in-mempool"` ✓ |
| `txn-same-nonwitness-data-in-mempool` | `"txn-same-nonwitness-data-in-mempool"` ✓ |
| `txn-already-known` | `"txn-already-known"` ✓ |
| `bad-txns-nonstandard-inputs` | `"bad-txns-nonstandard-inputs: input N script unknown"` ✓ (with appendix) |
| `bad-txns-inputs-missingorspent` | `"Missing input: <hash>:N"` ✗ |
| `non-final` | `"Transaction is not final (locktime not reached)"` ✗ |
| `non-BIP68-final` | `"Transaction sequence locks not satisfied (BIP68)"` ✗ |
| `bad-txns-premature-spend-of-coinbase` | `"Spending immature coinbase"` ✗ |
| `bad-txns-in-belowout` | `"Output exceeds input"` ✗ |
| `bad-txns-fee-outofrange` | `"bad-txns-fee-outofrange"` ✓ |
| `bad-txns-inputvalues-outofrange` | `"bad-txns-inputvalues-outofrange"` ✓ |
| `min relay fee not met` | `"Fee below minimum relay fee"` ✗ |
| `bad-txns-too-many-sigops` | `"Transaction exceeds max standard sigops cost"` ✗ |
| `too-long-mempool-chain` | `"Too many ancestors (X > Y)"` / `"Adding transaction would exceed descendant limit"` ✗ |
| `too many potential replacements` | `"rejecting replacement; too many conflicting transactions (X > Y)"` ✗ |
| `insufficient fee` (RBF Rule 3) | `"rejecting replacement, less fees than conflicting txs; X < Y"` ✗ |
| `insufficient fee` (Rule 4) | `"rejecting replacement, not enough additional fees to relay; X < Y"` ✗ |
| `replacement-adds-unconfirmed` (BIP-125 Rule 2) | `"replacement tx introduces new unconfirmed inputs not in original transactions"` ✗ |
| `TRUC-violation` | `"Non-v3 transaction cannot spend unconfirmed v3 outputs"` / `"TRUC/v3 transaction cannot spend from unconfirmed non-v3 transaction"` ✗ |
| `dust` | `"dust: transaction has X dust outputs (max 1)"` ✓ (prefix), but Core just emits `dust` |
| `scriptpubkey` | `"scriptpubkey: non-standard output script at index N"` ✓ (prefix) |
| `scriptsig-size` | `"scriptsig-size: scriptSig at input N too large"` ✓ (prefix) |
| `scriptsig-not-pushonly` | `"scriptsig-not-pushonly: ..."` ✓ (prefix) |

~12 distinct token-drift cases. Cross-cite lunarblock W145 BUG-5..12 sweep,
fleet pattern.

**File:** mempool.ml — every `Error "..."` call site. Aggregated above.

**Core ref:** `bitcoin-core/src/consensus/validation.h::TxValidationState`
+ `validation.cpp` token constants.

**Impact:**
- Monitoring/alerting tools that match on Core reject tokens silently
  miss camlcoin rejects.
- `testmempoolaccept`-consuming wallets misinterpret reject reasons.
- Operator log-line parity broken.

---

## BUG-15 (P1) — Sigop counter uses hardcoded `P2SH | WITNESS` flag, ignores height-derived consensus flags

**Severity:** P1. `count_tx_sigops_cost_for_mempool` (mempool.ml:1086-1094):

```ocaml
let count_tx_sigops_cost_for_mempool (tx : Types.transaction)
    (mp : mempool) : int =
  ...
  let flags = Script.script_verify_p2sh lor Script.script_verify_witness in
  Validation.count_tx_sigops_cost tx ~prev_script_pubkey_lookup ~flags
```

The flags are HARDCODED to P2SH|WITNESS regardless of mp.current_height
or activation status. Core's `GetTransactionSigOpCost` (consensus/tx_check.cpp)
receives `STANDARD_SCRIPT_VERIFY_FLAGS` from the caller — i.e., the FULL
policy flag set — so that the sigop counter knows which input types to
attribute.

Post-segwit (the only practical case today), this is correct: P2SH and
WITNESS sigops are counted, others aren't. But the **block-side**
`count_tx_sigops_cost` is called with the full block-script-flag set
(validation.ml various sites). So a mempool tx's sigop cost is computed
under DIFFERENT flags than the block-side same tx. The sigop count
can therefore differ between mempool entry and block-template check.

**File:** mempool.ml:1086-1094.

**Core ref:** `bitcoin-core/src/validation.cpp:908` —
`int64_t nSigOpsCost = GetTransactionSigOpCost(tx, m_view, STANDARD_SCRIPT_VERIFY_FLAGS);`

**Impact:** Mempool's MAX_STANDARD_TX_SIGOPS_COST gate (16000) and Core's
block-side check may compute different `nSigOpsCost` for the same tx,
leading to "mempool accepts, block rejects" or vice versa for txs near
the sigop budget edge.

---

## BUG-16 (P1) — `MAX_TX_LEGACY_SIGOPS=2500` policy cap not enforced

**Severity:** P1. Core enforces TWO sigop caps on standard transactions
(policy.h:44-46):
- `MAX_STANDARD_TX_SIGOPS_COST = MAX_BLOCK_SIGOPS_COST/5 = 16000`
  (weighted, includes witness)
- `MAX_TX_LEGACY_SIGOPS = 2500` (legacy/P2SH only, unweighted)

camlcoin only checks the weighted variant (mempool.ml:2056-2058):
```ocaml
if sigops_cost > Consensus.max_standard_tx_sigops_cost then
  Error "Transaction exceeds max standard sigops cost"
```

A standard tx whose legacy sigop count alone exceeds 2500 (e.g. a P2SH
multisig with many CHECKMULTISIG ops + small witnesses to keep the
weighted total ≤ 16000) is accepted at camlcoin and rejected at Core.

**File:** mempool.ml:2056-2058; consensus.ml (no `max_tx_legacy_sigops`).

**Core ref:** `bitcoin-core/src/policy/policy.h:46`
`static constexpr unsigned int MAX_TX_LEGACY_SIGOPS{2'500};`
enforced in `IsStandardTx` via `if (legacy_sigops > MAX_TX_LEGACY_SIGOPS) ...`

**Impact:** Cross-impl divergence on edge-case sigop-heavy txs. Cross-cite
W134 (BIP-54 sigops absent in 5 impls) — adjacent fleet pattern.

---

## BUG-17 (P1) — `Consensus.default_bytes_per_sigop = 20` hardcoded; no `-bytespersigop` knob

**Severity:** P1. Core's `-bytespersigop` (default 20) tunes the
sigop-adjusted vsize formula `vsize = max(weight/4, sigop_cost *
bytes_per_sigop)`. camlcoin hardcodes 20 in `Consensus.default_bytes_per_sigop`
(consensus.ml:46) and `get_virtual_transaction_size` uses it
unconditionally.

**File:** consensus.ml:46.

**Core ref:** `bitcoin-core/src/policy/policy.h:50`
`static constexpr unsigned int DEFAULT_BYTES_PER_SIGOP{20};` +
init.cpp registration of `-bytespersigop`.

**Impact:** Operator test ergonomics; no consensus risk.

---

## BUG-18 (P1) — No `-permitbaremultisig=0` knob

**Severity:** P1. `is_standard_output` (mempool.ml:1058-1073) always
accepts bare-multisig outputs up to n ≤ 3 (via `decode_bare_multisig`).
Core defaults `DEFAULT_PERMIT_BAREMULTISIG=true` but allows operator to
flip to `false` (rejects all bare-multisig outputs as nonstandard).
camlcoin has no such operator knob.

**File:** mempool.ml:1058-1073 (function); no CLI registration in
bin/main.ml.

**Core ref:** policy.h:52 + init.cpp `-permitbaremultisig` arg.

**Impact:** Operator UX divergence.

---

## BUG-19 (P1) — No `-datacarrier=0` / `-datacarriersize=N` knobs

**Severity:** P1. Core defaults `DEFAULT_ACCEPT_DATACARRIER=true` and
`MAX_OP_RETURN_RELAY=100000` (vbytes). Operator can:
- `-datacarrier=0` → reject ALL OP_RETURN outputs at relay.
- `-datacarriersize=N` → tune the per-tx OP_RETURN budget.

camlcoin hardcodes the budget at 100,000 bytes (mempool.ml:1476) and has
no knob for either. Operator running a high-traffic mainnet node that
wants to stop relaying inscriptions cannot do so.

**File:** mempool.ml:1476.

**Core ref:** policy.h:79-84 + init.cpp `-datacarrier` /
`-datacarriersize`.

**Impact:** Operator policy-tuning gap; especially relevant for
ordinals/inscription relay control (a live operator issue in 2024-25).

---

## BUG-20 (P1) — `bypass_limits` and `bypass_fee_check` are TWO separate parameters; Core has ONE

**Severity:** P1. `add_transaction` signature (mempool.ml:1945):
```ocaml
let add_transaction ?(dry_run=false) ?(bypass_fee_check=false) ?(bypass_limits=false)
```

Core has ONE flag: `args.m_bypass_limits` (validation.cpp:792). When true,
it gates ALL of:
- `CheckFeeRate` (validation.cpp:948 `if (!bypass_limits && ...)`)
- `SingleTRUCChecks` (validation.cpp:954)
- ephemeral-tx fee=0 check (PreCheckEphemeralTx — guarded indirectly)
- entry_sequence treatment (923 `bypass_limits ? 0 : m_pool.GetSequence()`)

camlcoin's bifurcation requires callers to pass both flags explicitly. The
reorg-refill site (sync.ml:3706) correctly passes both, BUT a future caller
(e.g. a new RPC or test harness) that passes only `~bypass_limits:true`
will get the bypass for cluster/TRUC/ancestor limits but STILL enforce
the fee floor — inconsistent with Core semantics.

Worse, `bypass_fee_check` alone is plumbed into the mempool.ml:2198 check
but doesn't propagate to `evict_by_chunks` or TRUC logic — so callers can
end up with arbitrary partial-bypass semantics no Core code path produces.

**File:** mempool.ml:1945 (signature), 2198 (fee_check site), 2223 (TRUC
bypass site).

**Core ref:** validation.cpp:792 (single flag), 948 (CheckFeeRate gated),
954 (TRUC gated), 923 (entry_sequence).

**Impact:** API surface designed to be misused; future bugs likely.

---

## BUG-21 (P0) — LockPoints not recomputed after reorg

**Severity:** P0. Core's mempool entry stores `LockPoints` at admission
time (`validation.cpp:886` → `CalculateLockPointsAtTip(tip, m_view, tx)`).
On every chain tip change, `CTxMemPool::removeForReorg` re-evaluates
`CheckSequenceLocksAtTip(new_tip, entry.lock_points)` and evicts entries
whose lockpoints are no longer satisfied.

Camlcoin caches `utxo_heights` and `utxo_mtps` per-input AT ADMISSION
(mempool.ml:2072-2113) — these are used inside `check_sequence_locks` at
line 2127-2130. The per-input arrays are not stored on the mempool entry;
they exist only during the admission call. After a reorg that changes
the height of a parent tx (e.g. a previously-confirmed parent gets
disconnected back to mempool), the child's sequence-lock status is never
re-evaluated.

Combined with BUG-5 (`current_median_time` always 0l), BIP-68 time-based
sequence locks are doubly broken:
- (a) admission-time check uses 0l;
- (b) post-reorg re-eval never happens.

**File:** mempool.ml:2127-2130 (admission-time check); no equivalent of
`removeForReorg` exists.

**Core ref:** `bitcoin-core/src/txmempool.cpp::removeForReorg`,
`validation.cpp:886`.

**Impact:** Post-reorg mempool retains txs whose BIP-68 sequence locks are
no longer satisfied; can confuse block-template construction (miner builds
block with non-final tx) and peer relay (peer rejects, ban score).

---

## BUG-22 (P0-SEC) — `load_mempool` uses `add_transaction` directly; one bad tx aborts the entire restore

**Severity:** P0-SEC. `load_mempool` (mempool.ml:3714-3826) walks the
mempool.dat payload and calls `add_transaction mp tx` per record
(line 3780). On a malformed payload (corrupted bytes, attacker-controlled
restore file via fs access), the per-record loop is wrapped in ONE
outer `try ... with _ -> ()` (line 3824) that handles the whole file.

A single malformed tx that triggers a `Failure`, `Not_found`, or
`Invalid_argument` inside `add_transaction` (or any helper it calls —
script eval via libsecp, Cstruct operations) jumps out of the loop and
aborts the rest of the mempool restore. Core's `LoadMempool`
(`node/mempool_persist.cpp`) wraps EACH tx in its own try/catch, logs the
failure, and continues with the next.

Additionally, `add_transaction` is not the exception-safe wrapper —
`accept_to_memory_pool` is (BUG-2). So even the partial restore that
happens before the bad tx may have silently propagated other exceptions
into other helpers.

**File:** mempool.ml:3714-3826.

**Core ref:** `bitcoin-core/src/node/mempool_persist.cpp::LoadMempool` —
per-tx try-catch + logging + continuation.

**Impact:**
- Mempool restore is brittle: a single bad tx → restore halts → no
  warning to operator about which tx tripped the abort.
- Restart after an unclean shutdown can leave a near-empty mempool.
- Cross-cite W138 "ChainstateManager wiring gap" + W140 "default-install
  fail-modes" fleet pattern.

---

## BUG-23 (P1) — `load_mempool` always applies fee deltas; no `importmempool apply_fee_delta_priority=false` knob

**Severity:** P1. Core's `LoadMempool` (node/mempool_persist.cpp:99-102)
applies per-entry inline `nFeeDelta` only when `apply_fee_delta_priority`
is true. The auto-restart `loadmempool` default is `true`; the
`importmempool` RPC opts to `false` so that imported mempool data is
applied without injecting another operator's prioritisations.

camlcoin always applies (mempool.ml:3789, 3813). Code comment at line
3789 even cites the Core knob:

```ocaml
(* FIX-77: apply the per-entry inline nFeeDelta to map_deltas so
   modified-fee, RBF Rule 3, and getmempoolentry "fees.modified"
   pick it up.  Matches Core node/mempool_persist.cpp:99-102
   (LoadMempool ApplyDelta on per-entry nFeeDelta). *)
```

— but stops short of plumbing the knob through. **Comment-as-confession**:
the implementer knew Core has the knob (`apply_fee_delta_priority`), cited
it, and shipped without it.

**File:** mempool.ml:3780-3814; no `importmempool` RPC handler in rpc.ml.

**Core ref:** node/mempool_persist.cpp `LoadMempool(path,
apply_fee_delta_priority=true)`; rpc/mempool.cpp::importmempool with
`apply_fee_delta_priority=false`.

**Impact:** No `importmempool` RPC exists at all (companion finding: camlcoin
has `loadmempool` semantics built into restart but no RPC handler for the
operator-driven import case).

---

## BUG-24 (P0-SEC) — `sendtoaddress` wallet path skips maxfeerate, maxburn, AND exception-safe wrapper

**Severity:** P0-SEC. `handle_sendtoaddress` (rpc.ml:2260-2293):

```ocaml
match Wallet.create_transaction wallet ~dest_address:address
        ~amount:amount_sats ~fee_rate ?tip_height:current_height () with
| Error e -> Error e
| Ok tx ->
  match Mempool.add_transaction ctx.mempool tx with
  | Ok entry ->
    Ok (`String (Types.hash256_to_hex_display entry.txid))
  | Error msg ->
    Error msg
```

vs `handle_sendrawtransaction` which at least checks burn amount and
post-hoc maxfeerate (BUG-12). `handle_sendtoaddress`:
1. Skips maxfeerate check → wallet bug that builds a tx with absurd fee
   gets accepted.
2. Skips maxburn check → wallet bug that builds tx with large OP_RETURN
   accepted.
3. Skips the W96 Bug 13 exception-safe wrapper (BUG-2).
4. Skips RBF (BUG-3) — wallet RBF replacement always fails with
   `txn-mempool-conflict`.
5. Doesn't compute or report wtxid (RPC return value is just txid).
6. Doesn't apply `-maxtxfee` wallet-side check.

**File:** rpc.ml:2260-2293.

**Core ref:** `bitcoin-core/src/wallet/rpc/spend.cpp::sendtoaddress` —
threads through `wallet.CommitTransaction` which calls `BroadcastTransaction`
with `max_raw_tx_fee_rate` and full ATMP gates.

**Impact:**
- Wallet self-DoS: a buggy or compromised wallet can broadcast huge-fee
  txs from camlcoin's mempool.
- RBF unavailable from wallet → wallet bump-fee broken.
- Exception leak surface on wallet-driven calls.

---

## Summary

**Bug count:** 24 (BUG-1 through BUG-24).

**Severity distribution:**
- **P0-CONSENSUS:** 1 (BUG-4 — mempool runs with regtest activation heights
  on all networks; Taproot active from genesis on a mainnet mempool until
  the unwired `set_network` is called, which never happens)
- **P0-CDIV:** 7 (BUG-1, BUG-3, BUG-7, BUG-9, BUG-10, BUG-12, BUG-21 ⇒
  recount: BUG-1, BUG-3, BUG-7, BUG-9, BUG-10. BUG-12 is P0. BUG-21 is P0.
  ⇒ P0-CDIV = 5: BUG-1, BUG-3, BUG-7, BUG-9, BUG-10)
- **P0-SEC:** 3 (BUG-2, BUG-22, BUG-24)
- **P0:** 3 (BUG-5, BUG-12, BUG-21)
- **P1:** 12 (BUG-6, BUG-8, BUG-11, BUG-13, BUG-14, BUG-15, BUG-16,
  BUG-17, BUG-18, BUG-19, BUG-20, BUG-23)

Recount: 1 + 5 + 3 + 3 + 12 = 24. ✓

**Fleet patterns confirmed:**
- **N-pipeline drift** (BUG-1): **6** distinct mempool acceptance entry
  points — most distinct pipelines in any audit so far (extending W143
  camlcoin's "5 distinct pipelines including 3 wtxids" by one). 4th
  consecutive quad-audit observation of multi-pipeline drift in camlcoin.
- **block_import.ml carry-forward analogue** (BUG-1 + BUG-22):
  `load_mempool` and 5 RPC entry points play the same role as
  `block_import.ml` does on the consensus side — pipelines that route
  around the canonical safe-wrapper / RBF / exception-protection gate.
- **Dead-data plumbing** (BUG-4, BUG-5): `set_network` AND
  `update_median_time` are both defined, exported, and called from zero
  production sites. Two distinct dead-mutator instances in one module —
  highest-density dead-data finding to date.
- **Comment-as-confession** (BUG-23): the implementer cites
  `apply_fee_delta_priority` knob in Core, then ships without it; line
  3789. 7th distinct camlcoin instance.
- **Wiring-look-but-no-wire** (BUG-4, BUG-5, BUG-11): the
  `Mempool.set_network` API exists, the constructor accepts a `network`
  field, but it's hardcoded to `Consensus.regtest`. Operator-facing CLI
  flags are absent for 9+ knobs.
- **Constant-aliasing** (BUG-7): `dust_relay_fee` and `min_relay_fee`
  collapsed into ONE constant (`3 × min_relay_fee`), accidentally produces
  the right value today but breaks under any one-of-two change.
- **Reject-string wire-parity slippage** (BUG-14): ~12 distinct token
  drifts. Cross-cites lunarblock W145 9-token sweep.
- **STANDARD-flags-incomplete** (BUG-9): 8 of 14 STANDARD bits missing,
  plus 1 extraneous bit (SIGPUSHONLY). Cross-cites W144 BUG-3 fleet pattern.
- **insert-then-eviction race** (BUG-12): operation order leaks side
  effects (ZMQ notify, fee-estimator eviction) for the
  ultimately-rejected tx.
- **Two-pipeline guard 18th distinct extension** (BUG-15): mempool sigop
  counter uses hardcoded P2SH|WITNESS flags; block-side counter uses
  height-derived flags. Same tx produces different sigop counts in the
  two pipelines.

**Top three findings:**

1. **BUG-4 (P0-CONSENSUS, mempool runs with `Consensus.regtest`
   activation heights forever)** — `Mempool.create` hardcodes
   `network = Consensus.regtest`; `set_network` mutator is defined,
   exported, and called from ZERO production sites. On a mid-IBD mainnet
   node (h < 709,632 / h < 481,824), the mempool accepts script-path
   Taproot spends and SegWit witnesses as standard. This is the
   **camlcoin 4th-consecutive-quad-audit instance of "block_import.ml
   bypasses every validation gate"** analog: the mempool pipeline has its
   own gates derived from the WRONG network's params, intra-node split
   with block-side validation. Single-line constructor change exposes
   `~network`; second-line wires it through `cli.ml:434`. P0-CONSENSUS
   class because mempool acceptance of pre-activation soft-fork spends is
   a wallet-loss / fund-mis-routing class vulnerability.

2. **BUG-1 + BUG-2 + BUG-3 + BUG-22 + BUG-24 cluster (six-pipeline drift
   on mempool acceptance)** — Six distinct entry points; only one runs
   the exception-safe wrapper (BUG-2); only one supports RBF (BUG-3);
   `sendrawtransaction` inserts-then-evicts on max-fee-rate (BUG-12);
   `sendtoaddress` skips ALL the optional gates (BUG-24); `load_mempool`
   aborts entire restore on one bad tx (BUG-22). This is the
   **W143 camlcoin 5-pipeline finding extended to 6**. The fix is a
   single architectural refactor: route every entry through
   `accept_to_memory_pool` and let it dispatch to single vs package vs
   bypass-limits via its own arg type (mirror Core's ATMPArgs).

3. **BUG-5 (P0 — BIP-113 time-based locktimes all rejected as non-final)**
   — `mempool.current_median_time` is always `0l` because
   `update_median_time` mutator is exported but never called. Every
   transaction with `nLockTime >= 500_000_000` (the Unix-epoch form,
   common for wallet-coordinated future spends) is rejected at mempool
   with `"Transaction is not final (locktime not reached)"` no matter the
   actual chain MTP. Lightning channel close txs, escrow refund txs, and
   any time-based payment automation can't be broadcast. Same shape as
   BUG-4 — a `lib/mempool.ml`-exported mutator that the production wiring
   forgot to call. **Two distinct "dead mutator" instances in the same
   module, both load-bearing for correctness.**
