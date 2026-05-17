# W129 Coin Selection (BnB / Knapsack / SRD / CG) — camlcoin (OCaml)

Wave: W129 — Coin selection algorithms (Branch-and-Bound, Knapsack, Single
Random Draw, CoinGrinder), effective_value computation, long-term feerate
plumbing, cost-of-change semantics, SFFO (subtract-fee-from-outputs),
change-output avoidance, anti-fee-sniping and waste-metric ranking.

Bitcoin Core references:
- `bitcoin-core/src/wallet/coinselection.cpp` (BnB, Knapsack, SRD, CG, waste)
- `bitcoin-core/src/wallet/coinselection.h`   (COutput, OutputGroup, CoinSelectionParams)
- `bitcoin-core/src/wallet/spend.cpp`         (AttemptSelection, ChooseSelectionResult, SelectCoins, CreateTransactionInternal)
- `bitcoin-core/src/wallet/feebumper.cpp`     (CreateRateBumpTransaction, EstimateFeeRate)

Scope: BnB, Knapsack, SRD, CG; effective_value; longterm feerate; cost of
change; SFFO; change avoidance.

Methodology: read Core refs, synthesize a 30-gate matrix, classify against
camlcoin code (primarily `lib/wallet.ml` because camlcoin does NOT have
dedicated `lib/wallet/coinselection.ml` or `lib/wallet/spend.ml` files
— the W128 fleet audit would categorize this as "single-file wallet
collapsed architecture"). Catalogue BUGs with severity (P0-CDIV consensus
divergence / P1 wallet correctness / P2 privacy-or-economic / P3 doc).
Build cross-reference test `test/test_w129_coin_selection.ml`.

Prior baseline: W113 (test_w113_coin_selection.ml) catalogued 9 BUGs
covering algorithm presence (BUG-3 Knapsack absent, BUG-4 CoinGrinder
absent), CSPRNG (BUG-7 — already FIXED), and broad-strokes structural
gaps. W129 goes deeper into semantic correctness of the BnB/SRD
implementations that **DO** exist, with byte-exact Core-parity checks
on effective_value computation, cost_of_change formula, waste metric,
SFFO handling, and the CoinControl / fee-bumper surface. Where W113
findings remain applicable, W129 references them by number and does
NOT re-count them.

## 30-gate matrix (W129)

### G1-G5: BnB semantic parity (deeper than W113)

- **G1: BnB explores ALL solutions to minimize waste (not first feasible).**
  Core (`coinselection.cpp:124-186`): the DFS loop continues for
  `TOTAL_TRIES=100000` iterations even after finding a feasible solution,
  updating `best_selection` when `curr_waste <= best_waste`. Each backtrack
  also tries the omission branch. **camlcoin (wallet.ml:951-952)**:
  `if !best = None then search (idx + 1) current_sum selection` — once
  ANY feasible solution found, NO omission branch is explored. The DFS
  collapses to a greedy "first match wins". → see W113 BUG-1, **still
  present**.

- **G2: BnB descending sort ties broken by lower waste.**
  Core's `descending` comparator (`coinselection.cpp:29-38`):
  ```
  if (a.GetSelectionAmount() == b.GetSelectionAmount()) {
      return (a.fee - a.long_term_fee) < (b.fee - b.long_term_fee);
  }
  ```
  camlcoin `wallet.ml:918-920` sorts purely by effective value descending,
  no waste tiebreaker. Without long_term_feerate (BUG-W129-2) this is
  unavoidable but documented.

- **G3: BnB skip-clone optimization.**
  Core (`coinselection.cpp:171-184`): when SHIFTing to omission branch
  after included sibling has been processed, skip if `prev` has the same
  effective_value AND fee, because that branch is equivalent to one
  already evaluated. **camlcoin has NO clone-skip** — every duplicate
  effective_value pair is re-explored.

- **G4: BnB tracks `is_feerate_high`.**
  Core line 120: `bool is_feerate_high = utxo_pool.at(0).fee > utxo_pool.at(0).long_term_fee;`
  Used to early-exit when current waste exceeds best waste (`curr_waste > best_waste && is_feerate_high`). camlcoin has no
  long_term_fee → cannot compute this → no early-exit on waste
  divergence.

- **G5: BnB max_selection_weight enforcement.**
  Core line 131: `curr_selection_weight > max_selection_weight` triggers
  backtrack. **camlcoin has NO weight tracking on wallet_utxo** — only
  `value`, `script_pubkey`, `height`, `is_coinbase`. P2WPKH-assumed
  68 vbytes per input is hard-coded at module level. Different output
  types (P2PKH 148, P2SH 91, P2WSH-multisig variable) are NOT modelled.

### G6-G10: OutputGroup / eligibility filter

- **G6: OutputGroup data structure.**
  Core (`coinselection.h:228-270`) groups UTXOs by scriptPubKey to support
  -avoidpartialspends. **camlcoin has no `output_group` type or grouping
  step**. The wallet operates on a flat `wallet_utxo list`. → W113 BUG-5.

- **G7: OUTPUT_GROUP_MAX_ENTRIES=100 cap.**
  Core (`spend.cpp:46`): after 100 outputs sharing a scriptPubKey,
  start a new OutputGroup. camlcoin has no cap.

- **G8: CoinEligibilityFilter (conf_mine/conf_theirs/max_ancestors/max_cluster).**
  Core (`coinselection.h:201-225`): iterates over a vector of progressively
  more permissive filters during AutomaticCoinSelection (spend.cpp:872+).
  **camlcoin has only one filter: `confirmed = true`** (`wallet.ml:969`).
  No `from_me` distinction → all unconfirmed-from-self UTXOs are
  blanket-excluded.

- **G9: m_from_me and m_depth honoured.**
  Core counts unconfirmed-from-self differently from unconfirmed-from-others.
  camlcoin's `wallet_utxo` has no `from_me` field.

- **G10: include_unsafe / m_include_unsafe_inputs surface.**
  Core (`spend.cpp:916`) wires `coin_selection_params.m_include_unsafe_inputs`
  through `AvailableCoins` filter. camlcoin has no equivalent — all
  unconfirmed UTXOs are filtered out at `select_coins` time, no
  per-call override.

### G11-G14: Knapsack solver

- **G11: KnapsackSolver presence.**
  Core (`coinselection.cpp:652-747`): the classic stochastic-approximation
  fallback. **camlcoin: ABSENT.** → W113 BUG-3, still present.

- **G12: KnapsackSolver lowest_larger heuristic.**
  Core lines 678-680, 715-716: when summed lower-than-target groups
  don't cover the target, return a single "smallest UTXO larger than
  target" coin to avoid overshoot. camlcoin: absent.

- **G13: ApproximateBestSubset 1000-rep stochastic search.**
  Core lines 602-650: random Pass-0 inclusion + Pass-1 exclusion-of-included,
  best `nBest` updated each rep, `iterations=1000` default. camlcoin: absent.

- **G14: Knapsack exact-target short-circuit.**
  Core line 672: `if (group.GetSelectionAmount() == nTargetValue) { AddInput; return; }`
  — a single group that exactly matches target wins immediately. camlcoin:
  not applicable (no Knapsack).

### G15-G17: CoinGrinder

- **G15: CoinGrinder presence.**
  Core (`coinselection.cpp:325-525`): minimum-weight exact-match solver
  for high-feerate environments (3× long-term-feerate threshold,
  spend.cpp:769). **camlcoin: ABSENT.** → W113 BUG-4, still present.

- **G16: CoinGrinder 3×LTF gate.**
  Core (`spend.cpp:769`): CoinGrinder is invoked iff
  `m_effective_feerate > 3 * m_long_term_feerate`. The CoinSelectionParams
  type carries `m_long_term_feerate` as `m_consolidate_feerate`
  (wallet.h:728, default 10 sat/vB). **camlcoin has no consolidate_feerate
  config or wiring.**

- **G17: CoinGrinder min_tail_weight / lookahead arrays.**
  Core lines 329-344: precomputed reverse-cumulative arrays of total
  available value and minimum remaining UTXO weight, used for branch
  pruning. camlcoin: not applicable.

### G18-G21: SRD semantics

- **G18: SRD adds CHANGE_LOWER + change_fee to target.**
  Core (`coinselection.cpp:546`): `target_value += CHANGE_LOWER + change_fee;`
  where `CHANGE_LOWER=50000`. Avoids creating sub-50000-sat change.
  **camlcoin (`wallet.ml:880-899`)**: SRD takes raw target, NO
  CHANGE_LOWER addition, NO change_fee addition. → W113 BUG-9, still
  present.

- **G19: SRD MinOutputGroupComparator priority queue.**
  Core (`coinselection.cpp:527-534, 540`): pushes each picked group into
  a min-heap. When weight exceeds max_selection_weight, pops the lowest
  effective-value group. **camlcoin SRD has NO weight tracking** —
  it accumulates all shuffled UTXOs until total>=target with no
  drop-on-weight-overflow.

- **G20: SRD positive-effective-value filter.**
  Core comment line 463: "the positive effective value OutputGroups
  eligible for selection". Asserted line 558: `Assume(group.GetSelectionAmount() > 0);`.
  **camlcoin SRD (wallet.ml:880)** does NOT filter on effective value
  — it sums raw `utxo.value` not `value - input_cost`. A UTXO whose
  spending fee exceeds its value would be selected and contribute
  negatively to the actual deliverable amount, but the SRD termination
  condition `!total >= target` would not detect this. **P1 bug**.

- **G21: SRD max_selection_weight enforcement.**
  Core lines 567-575: drops lowest-effval entries when over weight cap.
  camlcoin SRD: no weight cap.

### G22-G24: effective_value & cost_of_change

- **G22: effective_value = value - feerate.GetFee(input_bytes).**
  Core (`coinselection.h:87-88`): `fee = feerate.value().GetFee(input_bytes);`
  `effective_value = txout.nValue - fee.value();`. `GetFee` rounds:
  `nSatoshisPerK * nBytes / 1000`. **camlcoin (`wallet.ml:911`)**:
  `let input_cost = Int64.of_float (fee_rate *. float_of_int 68)`.
  Treats fee_rate as sat/vB **directly multiplied** by 68 vbytes — but
  Core's CFeeRate input is sat/kvB and divides by 1000.
  **In camlcoin's call sites (`wallet.ml:973`)**: `Int64.of_float (fee_rate *. weight /. 4.0)` — `weight/4` is vbytes, so `fee_rate` is sat/vB. Internally consistent **as long as everyone agrees fee_rate is sat/vB**, but Core's API surface is sat/kvB. **P3 unit-convention divergence.**

- **G23: cost_of_change = m_discard_feerate.GetFee(change_spend_size) + m_change_fee.**
  Core (`spend.cpp:1175`):
  `cost_of_change = m_discard_feerate.GetFee(change_spend_size) + m_change_fee`.
  Two distinct feerates: m_discard_feerate (for the future spend) and
  m_effective_feerate (for the current change output). camlcoin
  (`wallet.ml:978-979`): `cost_of_change = fee_rate * (34 + 68) / 1.0`
  — uses ONE feerate for both, AND the `/ 1.0` is a no-op. The "34"
  is P2WPKH change_output_size and "68" is P2WPKH change_spend_size —
  hard-coded to P2WPKH. **P1 economic bug** (under-estimates change cost
  if discard_feerate < effective_feerate, the common case).

- **G24: min_viable_change = max(change_spend_fee + 1, dust).**
  Core (`spend.cpp:1182-1184`):
  ```
  const auto dust = GetDustThreshold(change_prototype_txout, m_discard_feerate);
  const auto change_spend_fee = m_discard_feerate.GetFee(change_spend_size);
  min_viable_change = std::max(change_spend_fee + 1, dust);
  ```
  Change-output suppression below `min_viable_change` is feerate-dependent.
  **camlcoin (`wallet.ml:1042, 1717, 1813`)**: `dust_threshold = 546L`
  hard-coded. No discard_feerate, no per-output dust calc. P2PKH
  ≠ P2WPKH ≠ P2TR dust values are NOT distinguished. **P1 economic bug.**

### G25-G27: SFFO, waste metric, anti-fee-sniping

- **G25: m_subtract_fee_outputs (SFFO).**
  Core: when SFFO is true, BnB is skipped (`spend.cpp:751`) and
  `GetSelectionAmount()` returns the raw value instead of effective_value
  (`coinselection.cpp:789-792`). **camlcoin has NO `subtract_fee_outputs`
  flag anywhere** — no SFFO surface. The handle_walletcreatefundedpsbt
  RPC parser does NOT read `subtractFeeFromOutputs` from the options
  object. **P1 wallet bug** for protocols that send the full balance.

- **G26: Waste metric / RecalculateWaste.**
  Core (`coinselection.cpp:827-852`):
  `waste = Σ(coin.fee - coin.long_term_fee) - bump_fee_discount + (change_cost OR excess)`.
  Used to rank BnB vs Knapsack vs CoinGrinder vs SRD results in
  ChooseSelectionResult and AttemptSelection. **camlcoin: no waste
  field, no long_term_feerate, no algorithm ranking.** → W113 BUG-2,
  still present.

- **G27: Anti-fee-sniping randrange(100) backoff.**
  Core: `tx.nLockTime -= rng.randrange(100)` (0-99 blocks back). camlcoin
  (`wallet.ml:1741, 1824`): `max 0 (h - 1)` — exactly 1 block back.
  → W113 BUG-6, still present. **P2 privacy bug.**

### G28-G30: CoinControl + fee bumping

- **G28: CCoinControl preset inputs.**
  Core's CCoinControl supports m_PresetInputs (manually selected UTXOs),
  m_allow_other_inputs, m_min_depth, m_max_depth, m_feerate, m_locktime,
  m_signal_bip125_rbf, m_change_type, destChange, m_avoid_partial_spends,
  m_include_unsafe_inputs, m_max_tx_weight. **camlcoin walletcreatefundedpsbt
  has PARTIAL coin-control (manual inputs, add_inputs, fee_rate,
  changeAddress, changePosition, lockUnspents) but NO m_min_depth,
  m_max_depth, m_signal_bip125_rbf override, m_change_type,
  m_include_unsafe_inputs, m_max_tx_weight.** → W113 BUG-8 (partially
  closed since W113; some surface added).

- **G29: feebumper Rule-3 (incremental relay fee) check.**
  Core (`feebumper.cpp:90-99`):
  ```
  CFeeRate incrementalRelayFee = wallet.chain().relayIncrementalFee();
  CAmount minTotalFee = old_fee + incrementalRelayFee.GetFee(maxTxSize);
  if (new_total_fee < minTotalFee) ERROR;
  ```
  **camlcoin (`wallet.ml:1930-1931`)**: `if Int64.compare new_fee old_fee <= 0`
  — only checks new_fee > old_fee, NOT new_fee ≥ old_fee + incremental_relay.
  **A bump that adds exactly 1 sat passes camlcoin's check but would be
  rejected by mempools enforcing BIP-125 Rule 3 / incremental relay
  fee = 1 sat/vB minimum (~250 sat for typical tx).** **P0-CDIV bug**
  (mempool would silently reject the bump-fee tx).

- **G30: feebumper coin selection vs ad-hoc input append.**
  Core (`feebumper.cpp:314`): `CreateTransaction(wallet, recipients, ...)` —
  runs full coin selection with all algorithms. **camlcoin (`wallet.ml:1986-2003`)**:
  greedy largest-first append, sorts by value descending, takes top N
  until extra_total ≥ extra_inputs_needed. NO BnB, NO SRD, NO waste
  metric, NO Knapsack. Selects suboptimal UTXOs from the wallet for the
  replacement. **P2 economic bug** — bumped tx is needlessly large.

## BUG catalogue (NEW in W129 — not in W113)

| ID | Sev | Gate | Description |
|---|---|---|---|
| BUG-W129-1 | P0-CDIV | G29 | feebumper does not enforce BIP-125 Rule 3 (incremental relay fee). Bump that adds only 1 sat passes camlcoin's `new_fee > old_fee` check but is rejected by network mempools. |
| BUG-W129-2 | P1 | G23 | cost_of_change uses single feerate (effective) for both change-output creation and future change-spend; Core uses m_discard_feerate (separately tunable, typically lower) for the spend portion. |
| BUG-W129-3 | P1 | G24 | min_viable_change is a constant 546 sat dust_threshold, not max(discard_feerate.GetFee(change_spend_size) + 1, dust). High-feerate environments lose change to fees when it should be created; low-feerate environments create sub-economical change. |
| BUG-W129-4 | P1 | G25 | No SFFO (m_subtract_fee_outputs) surface. walletcreatefundedpsbt ignores `subtractFeeFromOutputs` from options. Full-balance transfers fail. |
| BUG-W129-5 | P1 | G20 | SRD does not filter on positive effective_value. Sums raw `utxo.value`, so a UTXO whose spending fee exceeds its value is included and contributes negatively to the actual deliverable amount. |
| BUG-W129-6 | P1 | G8/G9 | CoinEligibilityFilter absent — only `confirmed=true` discrimination, no conf_mine/conf_theirs/max_ancestors/max_cluster_count/m_from_me. Cannot use unconfirmed change. |
| BUG-W129-7 | P2 | G30 | feebumper uses ad-hoc largest-first input append instead of running real coin selection. Bumped tx is needlessly large and wastes fees. |
| BUG-W129-8 | P2 | G5/G21 | No max_selection_weight enforcement in BnB or SRD. A wallet with many UTXOs can produce a tx exceeding MAX_STANDARD_TX_WEIGHT=400000 (rejected by mempool). |
| BUG-W129-9 | P2 | G3 | BnB does not skip-clone (equal effective_value AND equal fee in adjacent positions). Same branches explored twice when wallet has duplicate-valued UTXOs (common after a faucet/airdrop). |
| BUG-W129-10 | P2 | G16 | No 3×long_term_feerate gate for CoinGrinder (because CoinGrinder is absent). m_consolidate_feerate / `-consolidatefeerate=` config not wired. |
| BUG-W129-11 | P3 | G22 | fee_rate unit convention drifts: external API documents BTC/kvB (RPC walletcreatefundedpsbt converts via *100_000), internal call sites assume sat/vB. Documented in code but no asserting unit-test. |
| BUG-W129-12 | P3 | G6/G7 | OutputGroup absent (single-impl architecture: all UTXOs flat). avoid_partial_spends cannot be honoured. |
| BUG-W129-13 | P3 | G14 | Knapsack exact-target short-circuit absent (because Knapsack is absent). |
| BUG-W129-14 | P3 | G12 | Knapsack lowest_larger fallback absent (because Knapsack is absent). |

Total **NEW in W129**: **14 BUGs** (1 P0-CDIV, 5 P1, 4 P2, 4 P3).

Counting overlap with W113: W113's BUG-1/2/3/4/5/6/9 remain present.
W129 references but does not double-count.

## Universal patterns surfaced (cross-impl)

- **"single-file wallet architecture"**: camlcoin has no
  `lib/wallet/coinselection.ml` — coin selection is inlined in
  `lib/wallet.ml` (~2100 lines). Same pattern likely in lunarblock and
  hotbuns. The architecture choice makes Core-parity refactors more
  expensive but doesn't cause direct consensus divergence on its own.
- **"feebumper Rule 3 missing across fleet"** — likely candidate for
  cross-impl audit (W130+?). Rule 3 enforcement (incremental relay)
  is subtle: must apply to the AMOUNT (sat) not the FEERATE (sat/vB)
  and uses `maxTxSize` (not orig size). Easy to get wrong fleet-wide.
- **"hard-coded dust_threshold=546"** is a widespread fleet anti-pattern.
  Real dust is a function of (output_type, discard_feerate). 546 is
  only the P2PKH @ 3000 sat/kvB historical default.
- **"BnB stops at first feasible"** appears in multiple impls (W113
  found this exact pattern in camlcoin). May be universal.

## Verification

`test/test_w129_coin_selection.ml` — 30 gate tests, each documents the
specific gap (passes-as-evidence pattern, since this is discovery-only
audit not a fix wave).

camlcoin gotcha: if dune stalls, run
`_build/default/test/test_w129_coin_selection.exe` directly.

## Out of scope (for future waves)

- W130 Fee bumping fleet audit (BIP-125 Rule 1-5)
- W131 OutputGroup / avoid_partial_spends fleet audit
- W132 PSBT wallet roles fleet audit (Creator/Updater/Signer/Combiner/Finalizer/Extractor)
