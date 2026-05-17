# W130 BIP-125 RBF feebumper Rule 1-5 — camlcoin (OCaml)

Wave: W130 — BIP-125 RBF + wallet feebumper Rule 1-5 enforcement, with
emphasis on the **Rule 3 incremental relay fee** invariant
(`new_fee >= old_fee + incrementalRelayFee.GetFee(maxTxSize)`).

This audit FORMALIZES + EXTENDS W129's BUG-W129-1 (P0-CDIV) and
characterises the whole BIP-125 + feebumper surface — both the
mempool admission side (`mempool.ml: replace_by_fee`) and the wallet
construction side (`wallet.ml: bump_fee`).

Bitcoin Core references:
- `bitcoin-core/src/wallet/feebumper.cpp`   (CheckFeeRate, EstimateFeeRate,
  CreateRateBumpTransaction)
- `bitcoin-core/src/policy/rbf.cpp` + `rbf.h` (PaysForRBF, GetEntriesForConflicts,
  EntriesAndTxidsDisjoint, ImprovesFeerateDiagram,
  MAX_REPLACEMENT_CANDIDATES)
- `bitcoin-core/src/policy/feerate.cpp` (CFeeRate::GetFee — sat/kvB)
- `bitcoin-core/src/validation.cpp` (ConsiderReplacement — calls PaysForRBF)
- `bitcoin-core/src/wallet/wallet.h:124` (`WALLET_INCREMENTAL_RELAY_FEE = 5000`)

BIPs: 125 (Rule 1-5).

camlcoin surface:
- `lib/wallet.ml:1886-2084`   `bump_fee` — wallet feebumper equivalent.
- `lib/wallet.ml:1925-1927`   weight estimate + new_fee derivation.
- `lib/wallet.ml:1930`        ★ Rule 3 site — current check is `new_fee > old_fee`.
- `lib/wallet.ml:2009-2014`   nSequence RBF signalling for original inputs.
- `lib/mempool.ml:2839-3075`  `replace_by_fee_with_replaced` — mempool RBF.
- `lib/mempool.ml:128`        `incremental_relay_fee = 100L sat/kvB`.
- `lib/mempool.ml:123`        `max_rbf_evictions = 100` (= MAX_REPLACEMENT_CANDIDATES).
- `lib/mempool.ml:2464-2474`  `signals_rbf` (BIP-125 Rule 1 helper).
- `lib/wallet.ml:25`          `max_bip125_rbf_sequence = 0xFFFFFFFDl`.

Methodology: read Core refs + BIP-125, re-read W129 `BUG-W129-1`
(commit `f163b2a` audit md), enumerate the 30-gate Rule 1-5 surface,
classify against camlcoin's wallet **and** mempool code paths, catalogue
new bugs (W130-N), reference but do not double-count W129-1.

## Confirmation that W129 BUG-W129-1 still PRESENT

Yes. Inspection of `lib/wallet.ml:1930`:

```ocaml
if Int64.compare new_fee old_fee <= 0 then
  Error "New fee rate does not result in higher fee"
```

This is the entire Rule 3 enforcement in `bump_fee`. No
`incremental_relay_fee` constant is referenced anywhere in `wallet.ml`
(grep verified). The mempool-side `replace_by_fee_with_replaced` at
`mempool.ml:2970-2986` does enforce Rule 3 correctly using
`apply_delta + Int64.sub new_modified_fee total_conflict_fee` and Rule
4 using `additional_fees >= mp.min_relay_fee * vsize / 1000` — but the
wallet's own pre-flight rejection in `bump_fee` accepts an under-floor
bump that the mempool will subsequently reject. **BUG-W129-1 confirmed
P0-CDIV, unchanged. Cross-referenced in W130 as BUG-W130-1 (alias).**

## 30-gate audit matrix (W130)

### Rule 1 — BIP-125 signalling

- **G1: SignalsOptInRBF self-check.** Core (`policy/rbf.cpp:29-31`):
  `if (SignalsOptInRBF(tx)) return REPLACEABLE_BIP125;` — any input
  with `nSequence < 0xFFFFFFFE` flags. camlcoin `signals_rbf`
  (`mempool.ml:2464-2474`) matches: `seq_u < 0xFFFFFFFEL` ✓
  **PRESENT and correct.**

- **G2: IsRBFOptIn inheritable from ancestors.** Core lines 41-49 walks
  `pool.CalculateMemPoolAncestors(entry)`. camlcoin
  `signals_rbf_with_ancestors` (`mempool.ml:2479-2518`) does a BFS over
  `mp.entries` via `depends_on`. **PRESENT.**

- **G3: TRUC/v3 unconditional opt-in.** Core (`policy/truc_policy.cpp`):
  v3 (TRUC) txs are always replaceable. camlcoin `signals_rbf` line
  2466 inlines `is_truc_tx tx || ...`. **PRESENT.**

- **G4: Full-RBF default `-mempoolfullrbf=1`.** Core deprecated BIP-125
  signal-required path; camlcoin `replace_by_fee_with_replaced`
  comment `mempool.ml:2820-2828`: "Full RBF: no BIP125 signaling required
  (-mempoolfullrbf=1 default)". **PRESENT (matches Core post-v28).**

- **G5: max_bip125_rbf_sequence constant.** camlcoin `wallet.ml:25`
  defines `0xFFFFFFFDl`. Used in `create_transaction` (line 1733) and
  `bump_fee` extra-inputs (line 1998) + original-input rewrite
  (line 2011). Matches `MAX_BIP125_RBF_SEQUENCE`. **PRESENT.**

### Rule 2 — no new unconfirmed inputs

- **G6: mempool-side HasNoNewUnconfirmed (camlcoin Rule 2).** camlcoin
  `mempool.ml:2989-3020` walks `conflict_outpoints` set and rejects if
  any replacement input is mempool-unconfirmed AND not in the conflict
  outpoint set. Matches BIP-125 Rule 2 phrasing. **PRESENT.**

- **G7: feebumper `new_coin_control.m_min_depth = 1`.** Core
  (`feebumper.cpp:312`): `new_coin_control.m_min_depth = 1;` — wallet
  cannot use any unconfirmed UTXO when bumping. **camlcoin
  `bump_fee` filter at `wallet.ml:1987-1990`**:
  `available = List.filter (fun u -> u.confirmed && ...) w.utxos`.
  Functionally enforces `min_depth >= 1` for new (extra) inputs.
  **PRESENT — but only by the `confirmed` boolean, NOT by an explicit
  depth count.** Equivalent for this wave but documents G9 (no real
  depth tracking). **PRESENT (functionally).**

### Rule 3 — replacement fees ≥ original fees + incremental relay

- **G8: ★ wallet pre-flight Rule 3 (incrementalRelayFee floor).**
  ★ **THE HEART OF THIS AUDIT.** Core `feebumper.cpp:88-99`:
  ```
  CAmount new_total_fee = newFeerate.GetFee(maxTxSize) + combined_bump_fee.value();
  CFeeRate incrementalRelayFee = wallet.chain().relayIncrementalFee();
  CAmount minTotalFee = old_fee + incrementalRelayFee.GetFee(maxTxSize);
  if (new_total_fee < minTotalFee) return INVALID_PARAMETER;
  ```
  **camlcoin `wallet.ml:1930`**:
  `if Int64.compare new_fee old_fee <= 0 then Error`
  → **only `new_fee > old_fee` enforced.** A 1-sat bump passes the
  wallet's check but the mempool's `additional_fees < relay_fee.GetFee(vsize)`
  rejection (`mempool.ml:2983`) silently rejects the tx on broadcast.
  **P0-CDIV. ALIAS of BUG-W129-1.** Catalogued as **BUG-W130-1**.

- **G9: GetMinimumFeeRate floor (Rule 3 supplement).** Core
  `feebumper.cpp:139-140`: `CFeeRate min_feerate(GetMinimumFeeRate(...))`,
  combined with incremental relay via `std::max(feerate, min_feerate)`.
  This is the wallet's "even after applying incremental, you must be
  above network's minimum mempool fee". **camlcoin `bump_fee` does
  NOT consult `mempool.ml:mempoolMinFee` (the rolling-fee floor) at
  all.** **BUG-W130-2 P1**: wallet may build a bumped tx that meets
  Rule 3 against the prior tx's fee but is still below the mempool
  rolling minimum, silently rejected on broadcast.

- **G10: Mempool-side Rule 3 (PaysForRBF replacement_fees ≥ original).**
  Core `policy/rbf.cpp:109`. camlcoin `mempool.ml:2970-2973`:
  `if new_modified_fee < total_conflict_fee then Error`. Uses
  `apply_delta` (= GetModifiedFee) on both sides (FIX-72 W120 BUG-10
  closure). **PRESENT and correct.**

- **G11: WALLET_INCREMENTAL_RELAY_FEE = 5000 sat/kvB wallet-side floor.**
  Core `wallet/wallet.h:124`: `WALLET_INCREMENTAL_RELAY_FEE = 5000;`.
  Used in `EstimateFeeRate` (`feebumper.cpp:136-137`) as
  `feerate += std::max(node_incremental_relay_fee, wallet_incremental_relay_fee);`
  — wallets future-proof their bumps to a 5 sat/vB floor regardless of
  the node's configured `-incrementalrelayfee`. **camlcoin has NO
  `WALLET_INCREMENTAL_RELAY_FEE` constant anywhere. `bump_fee` does
  not call `EstimateFeeRate` at all — it takes `new_fee_rate` directly
  from caller (defeats future-proofing).** **BUG-W130-3 P1.**

### Rule 4 — additional fees pay for replacement bandwidth

- **G12: mempool-side Rule 4 (`additional_fees >= relay_fee.GetFee(vsize)`).**
  Core `policy/rbf.cpp:117-122`:
  ```
  CAmount additional_fees = replacement_fees - original_fees;
  if (additional_fees < relay_fee.GetFee(replacement_vsize)) reject;
  ```
  camlcoin `mempool.ml:2980-2986`:
  ```
  let additional_fees = Int64.sub new_modified_fee total_conflict_fee in
  let relay_fee_for_replacement =
    Int64.div (Int64.mul mp.min_relay_fee (Int64.of_int new_vsize)) 1000L in
  if additional_fees < relay_fee_for_replacement then Error ...
  ```
  ★ **DEVIATION**: Core uses `relay_fee` from the **incremental** relay
  fee (CTxMemPool::m_incremental_relay_feerate from
  `validation.cpp:973`, passed into PaysForRBF). camlcoin substitutes
  **`mp.min_relay_fee`** (the static 1000 sat/kvB floor). Same numeric
  value when the node's `-incrementalrelayfee` is at its default 100
  sat/kvB? NO — `mp.min_relay_fee = 1000L` is 10× larger than
  `incremental_relay_fee = 100L`. camlcoin enforces a **stricter** Rule 4
  than Core: replacement additional fees must clear `min_relay_fee * vsize`
  not `incremental_relay_fee * vsize`. **BUG-W130-4 P0-CDIV** (REJECT
  divergence): camlcoin rejects replacements that Core would accept
  when `additional_fee ∈ [incremental_relay * vsize, min_relay * vsize)`.
  Worked example: 250-vbyte replacement, additional_fee = 50 sat.
  Core: `50 >= 100 * 250 / 1000 = 25` ✓ accept. camlcoin:
  `50 >= 1000 * 250 / 1000 = 250` ✗ reject.

- **G13: GetFee rounding direction.** Core `policy/feerate.cpp:24`:
  `nFee = m_feerate.EvaluateFeeUp(virtual_bytes)` — `EvaluateFeeUp` is
  ceiling (`nSatoshisPerK * vbytes + 999 / 1000`, semantics of
  `FeePerVSize::EvaluateFeeUp`). **camlcoin `mempool.ml:2982`**:
  `Int64.div (Int64.mul mp.min_relay_fee (Int64.of_int new_vsize)) 1000L`
  — `Int64.div` is OCaml truncating division toward zero, equivalent
  to **floor** for positive operands, not ceiling.
  **BUG-W130-5 P1**: Rule 4 floor may underestimate the required
  relay fee by up to 1 sat. Numerically benign (1 sat) but breaks Core
  byte-parity. (Same divergence applies to the
  `relay_fee.GetFee(maxTxSize)` not implemented in `bump_fee` G8 above —
  a future fix MUST use ceiling.)

- **G14: vsize ceiling on weight conversion.** Core `policy/feerate.h:78`
  uses `int32_t` vsize as input; vsize is computed by
  `GetVirtualTransactionSize(tx)` = `(weight + 3) / 4` ceiling. camlcoin
  `mempool.ml:2876`: `let new_vsize = max 1 ((new_weight + 3) / 4)`.
  **PRESENT** (matches Core ceiling). bump_fee path
  `wallet.ml:1925-1927` computes `Int64.of_float (new_fee_rate *. float_of_int new_weight /. 4.0)`
  — this is **`fee_rate * weight / 4`** which is `fee_rate * vsize_floor`,
  NOT `fee_rate * vsize_ceil`. **BUG-W130-6 P2**: bump_fee underestimates
  new_fee by up to `fee_rate * 0.75 sat/vB`, which can later combine with
  G8 to bump a tx below the mempool floor. Independent finding.

### Rule 5 — MAX_REPLACEMENT_CANDIDATES (cluster bound)

- **G15: max_rbf_evictions = 100 constant.** Core `policy/rbf.h:26`:
  `MAX_REPLACEMENT_CANDIDATES = 100`. camlcoin `mempool.ml:123`:
  `max_rbf_evictions = 100`. **PRESENT.**

- **G16: cluster count vs txid count.** Core
  `policy/rbf.cpp:69-75`:
  `pool.GetUniqueClusterCount(iters_conflicting); if (num_clusters > MAX) reject`.
  camlcoin `mempool.ml:2885-2902` collects **direct conflicts + their
  descendants** into `evicted_set` and tests
  `Hashtbl.length evicted_set > max_rbf_evictions`. This counts **txids,
  not clusters**. The implementation is **stricter** than Core post-cluster
  mempool: Core counts distinct conflicting clusters (typically 1 per
  conflict tip if no cluster splits), camlcoin counts every evicted
  descendant. A replacement that conflicts with a 50-tx ancestor chain
  in 1 cluster + its 51-tx descendant set = 101 evicted txids in
  camlcoin (REJECT), but the Core cluster-mempool reading is 1 cluster
  (ACCEPT). **BUG-W130-7 P1** (REJECT divergence vs Core post-cluster-
  mempool semantics).

- **G17: GetUniqueClusterCount implementation.** camlcoin has no
  cluster-mempool / chunking abstraction at the API surface
  `find_all_conflicts` returns; the linearisation lives at
  `mempool.ml:135-141` (`max_cluster_count = 64`,
  `max_cluster_size_vbytes = 101_000`) but the RBF eviction check
  does not consult them. **BUG-W130-8 P2**: missing GetUniqueClusterCount.
  Worked example: replacement conflicts with 80 descendants of a single
  ancestor in one cluster → camlcoin rejects (80 ≤ 100 actually accepts
  if no other conflicts; but with two distinct clusters of 60 each =
  120 evictions, both Core and camlcoin reject — the divergence band
  is narrow). **PRESENT inadvertently** — net behaviour close to Core
  for typical mempools, but a known cosmetic gap.

### Disjoint check + ImprovesFeerateDiagram + max-tx-fee

- **G18: EntriesAndTxidsDisjoint.** Core `policy/rbf.cpp:85-98`:
  replacement's ancestors must NOT overlap with the direct conflict
  txid set. camlcoin `mempool.ml:2911-2944` does a BFS from
  `tx.inputs` parents to mempool ancestors and rejects if any is in
  `conflict_txid_set`. **PRESENT.**

- **G19: ImprovesFeerateDiagram.** Core `policy/rbf.cpp:127-140`:
  `CompareChunks(post, pre)` must be strictly greater (`std::is_gt`).
  camlcoin `mempool.ml:3024-3036` calls
  `check_improves_feerate_diagram` (W106 BUG-10 fix). **PRESENT.**
  (camlcoin's `check_improves_feerate_diagram` semantic correctness
  is OOS for this wave — see W106 audit.)

- **G20: max_tx_fee cap (`-maxtxfee`).** Core `feebumper.cpp:109-113`:
  `if (new_total_fee > max_tx_fee) reject WALLET_ERROR;`. **camlcoin
  has NO `max_tx_fee` or `m_default_max_tx_fee` anywhere** (grep
  verified — zero hits across the project). `bump_fee` has no
  upper-bound on the new fee. **BUG-W130-9 P1**: wallet can bump fee
  arbitrarily high (e.g. accidentally bumping a 0.001-BTC tx to a
  10-BTC fee on a fat-finger typo). Default Core value is 0.1 BTC.

- **G21: mempoolMinFee floor pre-check.** Core `feebumper.cpp:67-75`:
  `if (newFeerate.GetFeePerK() < minMempoolFeeRate.GetFeePerK()) reject;`.
  **camlcoin `bump_fee` doesn't consult `Mempool.get_min_mempool_fee`
  at all.** **BUG-W130-10 P1**: same vector as G9 — wallet can build a
  bumped tx below the rolling mempool floor that the network silently
  drops.

### maxTxSize precise invariant

- **G22: maxTxSize = CalculateMaximumSignedTxSize.** Core
  `feebumper.cpp:289`:
  `int64_t maxTxSize{CalculateMaximumSignedTxSize(CTransaction(temp_mtx), &wallet, &new_coin_control).vsize};`.
  This is the **max signed** vsize, accounting for largest possible
  signatures (per-input). camlcoin uses
  `estimate_tx_weight n_inputs n_outputs` (`wallet.ml:851-862`) which
  hard-codes:
  * 10 vbytes base
  * 68 vbytes + 110 weight per input (P2WPKH-assumed)
  * 31 vbytes per output (P2WPKH-assumed)
  **BUG-W130-11 P1**: maxTxSize for non-P2WPKH (P2PKH = 148 vbytes/input,
  P2SH-P2WPKH = 91 vbytes/input, P2TR keypath = 57.5 vbytes/input,
  multisig variable) is computed wrong. Underestimates → minTotalFee
  underestimates → real broadcast is rejected by mempool.

- **G23: External-signer maxTxSize via SignatureWeightChecker.** Core
  `feebumper.cpp:218-229` runs `VerifyScript` with a special checker
  to record actual signature sizes. **camlcoin has NO external-input
  support in `bump_fee` — no `is_external` path.** **BUG-W130-12 P2**
  (feature gap, not divergence).

- **G24: combined_bump_fee for cluster-shared inputs.** Core
  `feebumper.cpp:83-87`:
  `wallet.chain().calculateCombinedBumpFee(reused_inputs, newFeerate);`
  — when the replacement shares an unconfirmed parent cluster with
  other unconfirmed txs, fees must cover the cluster's incremental
  cost. **camlcoin: no `calculate_combined_bump_fee` helper.**
  **BUG-W130-13 P1**: replacement underestimates the true minimum fee
  in CPFP scenarios.

### incrementalRelayFee value parity

- **G25: DEFAULT_INCREMENTAL_RELAY_FEE = 100 sat/kvB.** Core
  `policy/policy.h:48` (referenced in camlcoin comment at
  `mempool.ml:126-128`). camlcoin `incremental_relay_fee = 100L`. ✓
  **PRESENT and correct.**

- **G26: relayIncrementalFee accessor.** Core
  `interfaces/chain.cpp::relayIncrementalFee()` returns
  `m_mempool.m_opts.incremental_relay_feerate`. **camlcoin has no
  `Mempool.relay_incremental_fee` accessor — the field lives at
  module scope as a `let incremental_relay_fee = 100L`.** **BUG-W130-14
  P3** (architectural gap, not divergence).

- **G27: WALLET_INCREMENTAL_RELAY_FEE = 5000 wallet-side floor.**
  See G11. **BUG-W130-3** alias.

### paysMoreThanConflicts variant + RPC error parity

- **G28: paysMoreThanConflicts: replacement_fees > original_fees.**
  Core BIP-125 phrasing in the original PR was `>`. Modern Core
  `PaysForRBF` (rbf.cpp:109) is `<` (i.e. `>=` accepts). **camlcoin
  matches modern Core: `<` reject (line 2970).** **PRESENT.**

- **G29: error string parity.** Core `policy/rbf.cpp:71`:
  `"rejecting replacement %s; too many conflicting clusters (%u > %d)"`.
  camlcoin `mempool.ml:2900-2902`:
  `"rejecting replacement; too many conflicting transactions (%d > %d)"`
  — uses **transactions** instead of **clusters** (consistent with G16
  divergence) AND omits the txid prefix. **BUG-W130-15 P3**: error
  string drift breaks RPC client log parsers / monitoring tools that
  grep for Core's exact strings.

- **G30: bumpfee RPC + cli surface absent.** Core exposes a `bumpfee`
  RPC (`rpc/wallet.cpp`) and `psbtbumpfee`. **camlcoin grep:
  zero hits for `bumpfee` / `psbtbumpfee` in `rpc.ml` or `cli.ml`.**
  `Wallet.bump_fee` is implemented as a library function but
  unreachable from any operator-facing surface. **BUG-W130-16 P1**:
  the entire Rule 3 P0-CDIV path is dead code from a black-box-testing
  perspective until an RPC handler is added; once added, BUG-W130-1
  will be live.

## BUG catalogue

| ID | Sev | Gate | Description |
|---|---|---|---|
| BUG-W130-1 (alias W129-1) | P0-CDIV | G8 | `bump_fee` enforces `new_fee > old_fee` not `new_fee >= old_fee + incrementalRelayFee.GetFee(maxTxSize)` — 1-sat bumps accepted by wallet, rejected by mempool. `wallet.ml:1930`. |
| BUG-W130-2 | P1 | G9 | `bump_fee` ignores mempool's rolling minimum fee (`min_mempool_fee`). Wallet can build a Rule-3-passing tx below the mempool floor. |
| BUG-W130-3 | P1 | G11/G27 | No `WALLET_INCREMENTAL_RELAY_FEE` constant (Core = 5000 sat/kvB). `EstimateFeeRate` is not implemented; `bump_fee` takes `new_fee_rate` parameter directly with no floor. |
| BUG-W130-4 | P0-CDIV | G12 | Mempool Rule 4 uses `mp.min_relay_fee` (1000 sat/kvB) instead of `incremental_relay_fee` (100 sat/kvB). camlcoin rejects RBFs that Core accepts in the `additional_fee ∈ [25, 249]` sat/250-vbyte band. **REJECT divergence.** |
| BUG-W130-5 | P1 | G13 | `GetFee` rounding direction wrong: camlcoin uses `Int64.div` (floor / truncation) where Core uses `EvaluateFeeUp` (ceiling). Up to 1-sat underestimate of Rule 4 floor. |
| BUG-W130-6 | P2 | G14 | `bump_fee` computes `new_fee = fee_rate * weight / 4` (vsize_floor) not `fee_rate * vsize_ceil`. Underestimates new_fee by up to `fee_rate * 0.75 sat`. Combines with G8 to push below mempool floor. |
| BUG-W130-7 | P1 | G16 | Rule 5 counts evicted txids instead of unique clusters. camlcoin rejects single-cluster 80+ descendant evictions that Core's cluster mempool accepts as 1-cluster. |
| BUG-W130-8 | P2 | G17 | `GetUniqueClusterCount` absent; no cluster-aware Rule 5 counting. Coalesces with BUG-W130-7. |
| BUG-W130-9 | P1 | G20 | No `max_tx_fee` / `-maxtxfee` cap (default Core = 0.1 BTC). Wallet can bump fee to arbitrary amounts on fat-finger typos. |
| BUG-W130-10 | P1 | G21 | `bump_fee` does not pre-check `newFeerate >= mempoolMinFee`. Wallet can build a tx the rolling mempool will drop. |
| BUG-W130-11 | P1 | G22 | `maxTxSize` from `estimate_tx_weight` hard-codes P2WPKH (68 vbytes/input, 31 vbytes/output, 110 witness weight). P2PKH/P2SH/P2TR get wrong maxTxSize → wrong minTotalFee. |
| BUG-W130-12 | P2 | G23 | No external-input support: `SignatureWeightChecker` equivalent is absent. Bumping a tx with non-wallet inputs is impossible. |
| BUG-W130-13 | P1 | G24 | No `calculate_combined_bump_fee` for cluster-shared CPFP. Underestimates true minimum fee in CPFP-cluster scenarios. |
| BUG-W130-14 | P3 | G26 | No `Mempool.relay_incremental_fee` accessor — value is at module scope. Architectural gap, not consensus divergence. |
| BUG-W130-15 | P3 | G29 | Rule 5 error string says "transactions" instead of "clusters", omits txid prefix. RPC log monitors break. |
| BUG-W130-16 | P1 | G30 | No `bumpfee` / `psbtbumpfee` RPC handler. `Wallet.bump_fee` is library-only; no operator-facing surface. Effectively dead code until RPC plumbing exists. |

Total **NEW in W130**: **15 BUGs** (2 P0-CDIV, 8 P1, 3 P2, 2 P3).
Plus 1 confirmed-alias (BUG-W130-1 ≡ BUG-W129-1).

## Universal patterns surfaced (cross-impl candidates)

- **"feebumper Rule 3 missing"** META-PATTERN — likely universal.
  Pattern: a wallet's bump-fee path checks `new_fee > old_fee` but
  not `new_fee >= old_fee + incrementalRelayFee * maxTxSize`.
  Subtle because mempool admission path enforces it correctly, so
  it surfaces only at broadcast time. **W130's BUG-W130-1 is the
  first formal catalogue.** Fleet sweep candidate.
- **"Rule 4 uses wrong feerate constant"** (BUG-W130-4) — `min_relay_fee`
  swapped for `incremental_relay_fee`. **REJECT divergence vs Core**
  (camlcoin too strict). Worth checking other impls' RBF logic for the
  same swap; the symptom is mempool rejecting RBFs that core accepts.
- **"P2WPKH-assumed weight estimator"** — camlcoin's `estimate_tx_weight`
  hard-codes P2WPKH dimensions. Likely fleet-wide; W129 BUG-W129-7
  also surfaced this in the coin-selection context. Universal cause:
  not having a polymorphic weight-by-output-type abstraction.
- **"library function with no RPC plumbing = dead code"** (BUG-W130-16).
  Pattern: a function is implemented in `wallet.ml` but no RPC handler
  wires it through. Audit framework should check both the impl AND the
  RPC dispatch table for completeness. Compare FIX-79 nimrod
  `validateRbfDiagram` (dead helper at call site — same pattern).
- **"ceiling vs floor in fee math"** (BUG-W130-5). OCaml's `Int64.div`
  truncates toward zero (= floor for positive); Core's
  `EvaluateFeeUp` is explicit ceiling. Off-by-1 sat universally;
  benign numerically but breaks byte-parity audits.

## Verification

`test/test_w130_bip125_feebumper_rule3.ml` — 30 gate tests + 4
invariant guards. Passes-as-evidence pattern (discovery-only).
Where W129 BUG-W129-1 is restated as BUG-W130-1 the test asserts the
same structural condition (no `incremental_relay` reference in
`wallet.ml`) plus a numerical worked example.

camlcoin gotcha: if `dune runtest --force` stalls, run
`_build/default/test/test_w130_bip125_feebumper_rule3.exe` directly.

## Out of scope (future waves)

- W131 OutputGroup / avoid_partial_spends fleet audit.
- W132 PSBT wallet roles (Creator/Updater/Signer/Combiner/Finalizer/Extractor).
- W133 mempoolMinFee/rolling-fee semantics fleet audit (touched on G9/G21).
- Fleet sweep: feebumper Rule 3 audit across the other 9 impls
  (rustoshi, blockbrew, clearbit, nimrod, beamchain, hotbuns,
  ouroboros, lunarblock, haskoin).
- `check_improves_feerate_diagram` byte-parity (W106 covers).
- TRUC/v3 RBF interactions (`mempool.ml:truc_signals_rbf` — W120 covers).
