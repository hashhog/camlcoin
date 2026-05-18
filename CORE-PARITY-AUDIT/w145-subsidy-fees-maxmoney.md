# W145 Coinbase + subsidy + fees + MAX_MONEY — camlcoin (OCaml)

Wave: W145 — the consensus-critical money/issuance fence: every layer
of code that touches `nValue`, `subsidy`, `fee`, `MAX_MONEY`,
`CheckTransaction`, or coinbase issuance. CVE-2018-17144 (duplicate
input → inflation) and CVE-2010-5139 (output-value overflow → 92-billion
BTC) live under this umbrella.

Bitcoin Core references:

- `bitcoin-core/src/validation.cpp`
  - L1839-1850: `GetBlockSubsidy(int nHeight, const Consensus::Params&)`
    - `int halvings = nHeight / interval`
    - `if (halvings >= 64) return 0;` (avoid C++ UB on `>>=` by 64)
    - `CAmount nSubsidy = 50 * COIN; nSubsidy >>= halvings; return nSubsidy;`
  - L2610-2614: `ConnectBlock` coinbase amount gate
    - `blockReward = nFees + GetBlockSubsidy(...)`
    - `if (block.vtx[0]->GetValueOut() > blockReward) → bad-cb-amount`
  - L2541-2547: `bad-txns-accumulated-fee-outofrange`
- `bitcoin-core/src/consensus/amount.h`
  - L19: `static constexpr CAmount COIN = 100000000;`
  - L26: `static constexpr CAmount MAX_MONEY = 21000000 * COIN;`
  - L27: `inline bool MoneyRange(const CAmount& nValue) { return (nValue >= 0 && nValue <= MAX_MONEY); }`
- `bitcoin-core/src/consensus/consensus.h`
  - L19: `static const int COINBASE_MATURITY = 100;`
- `bitcoin-core/src/consensus/tx_check.cpp` — `CheckTransaction`
  - L14-21: empty-vin / empty-vout / oversize gates (`bad-txns-vin-empty`,
    `bad-txns-vout-empty`, `bad-txns-oversize`)
  - L23-34: CVE-2010-5139 output value range (`bad-txns-vout-negative`,
    `bad-txns-vout-toolarge`, `bad-txns-txouttotal-toolarge`)
  - L36-45: CVE-2018-17144 duplicate-input check via `std::set<COutPoint>`,
    runs **before** UTXO lookup (`bad-txns-inputs-duplicate`)
  - L47-51: coinbase scriptSig length `[2,100]` (`bad-cb-length`)
  - L53-57: non-coinbase null-prevout reject (`bad-txns-prevout-null`)
- `bitcoin-core/src/consensus/tx_verify.cpp` — `CheckTxInputs`
  - L164-213: coinbase-maturity, per-input MoneyRange, cumulative
    `nValueIn` MoneyRange, `nValueIn < value_out`
    (`bad-txns-in-belowout`), final `txfee` MoneyRange
- `bitcoin-core/src/kernel/chainparams.cpp`
  - L84/L209/L310/L454/L535: `consensus.nSubsidyHalvingInterval` —
    mainnet 210000 / testnet3 210000 / testnet4 210000 / signet 210000
    / regtest 150
- `bitcoin-core/src/script/script.h`
  - L433-448: `CScript::push_int64` — emits `OP_1..OP_16` for `n∈[1,16]`,
    `OP_0` for `n=0`, `CScriptNum::serialize` otherwise (used by
    `BlockAssembler::CreateNewBlock` coinbase BIP-34 height encoding)
  - L563-566: `CScript::IsUnspendable` — `(size>0 && first==OP_RETURN) ||
    (size > MAX_SCRIPT_SIZE)` (drives UTXO-set inclusion in `AddCoins`)

camlcoin reference points:

- `lib/consensus.ml:14-18` — `coin`, `max_money`, `coinbase_maturity`
  constants
- `lib/consensus.ml:76-98` — `default_halving_interval`,
  `regtest_halving_interval`, `block_subsidy`,
  `block_subsidy_for_network`
- `lib/consensus.ml:822-823` — `is_valid_money`
- `lib/consensus.ml:250-277` — `network_config` record (includes
  `halving_interval` field) and per-network configs at L617-776
- `lib/validation.ml:172-238` — `check_transaction` (CheckTransaction
  parity)
- `lib/validation.ml:256-295` — `check_coinbase` (cb scriptSig length,
  null-prevout, BIP-34 height encoding)
- `lib/validation.ml:1486-1796` — fast-path (assumevalid) connect-block
- `lib/validation.ml:1801-2043` — full-path connect-block
- `lib/utxo.ml:566-663` — `connect_block_optimized` (UTXO mutation +
  parallel coinbase-value gate)
- `lib/mining.ml:264-337` — `create_coinbase` (subsidy + fees → coinbase
  output)
- `lib/block_import.ml` — `--import-blocks` batch ingestion bypass
- `lib/assume_utxo.ml:531-598, 1086-1093` — snapshot-coin MoneyRange + UTXO
  apply-block helper

The audit framing follows the convention of `w142` and the W84
regression-suite test plan (`test/test_validation.ml:2702-`).

---

## BUG-1 — `block_import.ml` skips `Validation.check_block` and `accept_block`: CVE-2018-17144 / CVE-2010-5139 / bad-cb-amount entry point [P0-CONSENSUS]

- **File:** `lib/block_import.ml:33-150` (`run`)
- **Core ref:** `bitcoin-core/src/validation.cpp` `ProcessNewBlock` →
  `AcceptBlock` → `CheckBlock` → `ContextualCheckBlock` →
  `ConnectBlock`; `consensus/tx_check.cpp` `CheckTransaction`

**Description.** The header comment on `block_import.ml:5-6` advertises
"feeding blocks directly to the validation and UTXO connection pipeline."
In practice `run` does NOT call `Validation.check_block`,
`Validation.validate_block_with_utxos`, or `Validation.accept_block`.
The control flow is:

  1. read framed block from stdin/file
  2. compute block hash
  3. `Storage.ChainDB.store_block`
  4. accept header into chain state (no PoW / timestamp / version /
     timewarp / weight / sigops checks)
  5. `Utxo.connect_block_optimized` (advances UTXO set with no
     duplicate-input / output-MoneyRange / script-verify / sigops /
     BIP-30 / IsFinalTx / coinbase-scriptSig-length / merkle-root /
     witness-commitment checks)

The only money invariants that fire are inside `connect_block_optimized`
itself: `output_sum > input_sum → "Output exceeds input"` (L621) and
`coinbase_out > subsidy + total_fees → "Coinbase too large"` (L658) —
both of which can be silently bypassed by a hostile input file that
omits or weakens its own inputs.

**Excerpt** (`lib/block_import.ml:55-95`):

```ocaml
let cs = Cstruct.of_bytes raw in
let r = Serialize.reader_of_cstruct cs in
let block = Serialize.deserialize_block r in
let hash = Crypto.compute_block_hash block.header in
Storage.ChainDB.store_block db hash block;
(* No Validation.check_block, no accept_block, no CheckTransaction *)
...
(match Utxo.connect_block_optimized ~network_type utxo block height with
 | Ok _undo -> (* commit chain tip *)
```

**Impact.** `--import-blocks` is a documented CLI flag
(`bin/main.ml:96, 586`). An attacker who can write to the import path
or who is trusted to supply a "rebroadcast" file can inflate the UTXO
set by including a block whose coinbase encodes the legitimate
`subsidy + fees` while every contained tx contains duplicate inputs
(CVE-2018-17144), negative outputs (CVE-2010-5139), or
`MAX_MONEY`-violating outputs. The duplicate-input case is the worst:
`connect_block_optimized` calls `OptimizedUtxoSet.remove` once per
duplicate `inp`, but each `remove` after the first is a no-op against
the same UTXO key; `input_sum` is double-counted, so the
`output_sum > !input_sum` gate is satisfied, the fee math accepts a
counterfeit fee, and the UTXO set diverges from every Core-validated
chain on the next reorg. This is the exact dead-path / two-pipeline
hazard the wave-43 audit catalogued for sync.ml → it has now
re-surfaced as `block_import.ml`.

---

## BUG-2 — `Consensus.block_subsidy_for_network` ignores `network_config.halving_interval`: dead field, fork-in-the-road [P0]

- **File:** `lib/consensus.ml:90-98`
- **Core ref:** `bitcoin-core/src/validation.cpp:1841` (Core reads
  `consensusParams.nSubsidyHalvingInterval`)

**Description.** `network_config` (L250-277) carries a
`halving_interval : int` field, and every per-network instance assigns
it correctly: `mainnet=210000` (L642), `testnet=210000` (L690),
`testnet4=210000` (L735), `regtest=150` (L774). But
`block_subsidy_for_network` does NOT read that field. Instead it
pattern-matches the `network` variant directly and falls back to two
module-level constants (`default_halving_interval`,
`regtest_halving_interval`).

**Excerpt** (`lib/consensus.ml:93-98`):

```ocaml
let block_subsidy_for_network (network : network) (height : int) : int64 =
  let halving_interval = match network with
    | Regtest -> regtest_halving_interval
    | Mainnet | Testnet3 | Testnet4 -> default_halving_interval
  in
  block_subsidy ~halving_interval height
```

**Impact.** Classic two-pipeline guard / dead field. Any future
`custom_network` or signet (BUG-3) that legitimately sets a different
`halving_interval` on its `network_config` would emit the wrong
subsidy. The field is also a maintenance trap: someone reading
`mainnet.halving_interval = default_halving_interval` would assume the
chain config drives subsidy, but the subsidy function is hard-wired to
the variant. Equivalent pattern to the fleet-wide "dead helper at
call-site" findings (W141 nimrod, W141 hotbuns).

---

## BUG-3 — No Signet network variant: `Consensus.network` enum is missing the public Core variant [P3]

- **File:** `lib/consensus.ml:3-8` + `lib/consensus.ml:90-98`
- **Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:454`
  (`m_chain_type = ChainType::SIGNET; consensus.nSubsidyHalvingInterval =
  210000;`)

**Description.** `type network = Mainnet | Testnet3 | Testnet4 | Regtest`.
Core also defines `Signet` (`ChainType::SIGNET`). Camlcoin documents
signet in comments (`lib/mempool.ml:2008`,
`lib/mining.ml:612`) but never instantiates it as a runnable chain
config. `Consensus.block_subsidy_for_network` (L96) would either need
a new arm or fall through to "default" if `Signet` is added later.

**Impact.** Cannot run camlcoin on signet. Aside from operator
inconvenience this is also a parity drift: `getblockchaininfo` cannot
report `"chain": "signet"`. Lower-severity because mainnet is
unaffected, but the missing variant is in the W134-class scope (BIP-37
already cross-cites signet config).

---

## BUG-4 — `lib/utxo.ml:621 connect_block_optimized` returns the wrong error string for `bad-txns-in-belowout` [P1]

- **File:** `lib/utxo.ml:618-622`
- **Core ref:** `bitcoin-core/src/consensus/tx_verify.cpp:196-199`
  (`bad-txns-in-belowout`)

**Description.** When `output_sum > input_sum` for any non-coinbase tx
inside `connect_block_optimized`, the function returns:

```ocaml
if output_sum > !input_sum then
  error := Some "Output exceeds input"
```

Core's canonical reject reason is `bad-txns-in-belowout`. Camlcoin's
`mempool.ml:2138` and `validation.ml` use that exact label in their
error formatters. `connect_block_optimized` is invoked from
`block_import.ml:95` and `mining.ml:869`, so any block-replay or
side-branch reorg that re-runs the UTXO apply on a bad block surfaces a
non-canonical reason. (Also note that, because BUG-1 lets bad blocks
through to this codepath in the first place, the error string is the
ONLY signal users get back.)

**Impact.** Test-suite divergence; the cross-impl harness checks
specific reject reasons.

---

## BUG-5 — `lib/utxo.ml:624-626 connect_block_optimized` does not MoneyRange-check accumulated `total_fees` [P0-CDIV]

- **File:** `lib/utxo.ml:616-627`
- **Core ref:** `bitcoin-core/src/validation.cpp:2541-2547`
  (`bad-txns-accumulated-fee-outofrange`),
  `consensus/tx_verify.cpp:202-209` (per-tx fee MoneyRange)

**Description.** `connect_block_optimized` accumulates per-tx fee via
`Int64.add !total_fees (Int64.sub !input_sum output_sum)` with NO bound
check. `total_fees` can over-flow `int64` (silent wraparound in OCaml).
The fast and slow validation paths in `validation.ml` DO have this
guard (`is_valid_money !total_fees`, L1736/L1988), but
`connect_block_optimized` is the second money-touching pipeline and is
hot for `block_import.ml`, `mining.ml`'s `submit_block` reorg path, and
any future replay-driver. Subsequent `Int64.add subsidy !total_fees`
(L653) then computes a corrupted `max_coinbase`, which trivially
satisfies `coinbase_out > max_coinbase` in the wrong direction — a
hostile block could now appear to over-pay coinbase to the *attacker*'s
benefit (i.e., the gate at L658 fires for legitimate blocks instead of
the attacker's).

**Excerpt** (`lib/utxo.ml:622-626`):

```ocaml
else
  total_fees :=
    Int64.add !total_fees
      (Int64.sub !input_sum output_sum)
```

**Impact.** Fee inflation primitive on the import / reorg pipeline.
Combined with BUG-1 (block_import bypasses validation), this becomes
the inflation oracle.

---

## BUG-6 — `lib/utxo.ml:592-614 connect_block_optimized` performs NO duplicate-input check: CVE-2018-17144 class [P0-CONSENSUS]

- **File:** `lib/utxo.ml:592-614`
- **Core ref:** `bitcoin-core/src/consensus/tx_check.cpp:36-45`
  (`bad-txns-inputs-duplicate` via `std::set<COutPoint>`)

**Description.** The UTXO connect loop iterates `tx.inputs` and calls
`OptimizedUtxoSet.get` then `OptimizedUtxoSet.remove`. If two inputs
share the same `(txid, vout)`, the second `get` returns `None` (because
the first `remove` deleted the entry), and the code at L598-602 sets
`error := "Missing UTXO"`. This means in PRACTICE duplicate inputs are
caught when the second is the first repeat. BUT consider the case where
the duplicate input appears in a **different** tx in the same block but
the second tx's first input is the duplicate: now the first tx's
`remove` succeeds, the second tx's lookup sees the missing key, AND the
second tx returns "Missing UTXO" — different reject reason than Core
(`bad-txns-inputs-duplicate` vs `bad-txns-inputs-missingorspent`).

More importantly, this codepath relies ENTIRELY on `remove` being
atomic and visible to the same tx's subsequent lookups. If the
`OptimizedUtxoSet` ever caches reads (it does — see `cache_size` in
`bin/main.ml:580`), a stale cached read between `remove` and the next
`get` could re-deliver the just-removed UTXO. The defense-in-depth
duplicate-input set that Core uses in `CheckTransaction` (BEFORE UTXO
lookup) is the canonical place to catch this; camlcoin's
`validation.ml:215-225` has it, but `utxo.ml` does not, and BUG-1
guarantees there is a path where validation.ml never runs.

**Excerpt** (`lib/utxo.ml:592-614`):

```ocaml
let input_sum = ref 0L in
List.iter (fun inp ->
  if !error = None then begin
    let prev = inp.Types.previous_output in
    match OptimizedUtxoSet.get utxo prev.txid (Int32.to_int prev.vout) with
    | None -> error := Some (Printf.sprintf "Missing UTXO: ..." ...)
    | Some entry -> ...
      input_sum := Int64.add !input_sum entry.value;
      ignore (OptimizedUtxoSet.remove utxo prev.txid (Int32.to_int prev.vout))
  end) tx.inputs;
```

**Impact.** With BUG-1, the import path delivers blocks straight into
this codepath, so an inflation oracle exists for `--import-blocks`.
On the normal sync path the validation.ml check at L214-225 catches it
upstream, so this is import-only — but import is operator-facing and
documented.

---

## BUG-7 — `lib/utxo.ml:592-614 connect_block_optimized` does not validate per-input `MoneyRange` before adding to `input_sum` [P1]

- **File:** `lib/utxo.ml:603-612`
- **Core ref:** `bitcoin-core/src/consensus/tx_verify.cpp:184-188`
  (per-input `MoneyRange(coin.out.nValue)` + cumulative `nValueIn`
  MoneyRange)

**Description.** The loop at L603-612 reads `entry.value` from the UTXO
set, adds it to `input_sum` unchecked, and proceeds. Core requires both
the per-input value AND the running sum to satisfy `MoneyRange`. The
validation pipeline (`validation.ml:1678, 1928, 2102`) has this guard;
`utxo.ml` does not. If a malicious or corrupted UTXO entry has
`value < 0` or `value > MAX_MONEY` (BUG-5 cross-cite: this can be
written into the UTXO set in the first place because `assume_utxo.ml`
verifies on coin import but `connect_block_optimized` does not verify
when it writes outputs into the set), the fee math at L624-626 is
corrupted.

**Impact.** Combined with BUG-5 and BUG-6, an attacker with import
access can establish a poisoned UTXO set whose subsequent reorg path
silently mis-counts the chain's outstanding money supply.

---

## BUG-8 — Coinbase scriptSig length 2..100 only checked by `check_coinbase`; `check_transaction ~is_coinbase:true` accepts a length-1 scriptSig [P2]

- **File:** `lib/validation.ml:170-235` (`check_transaction`),
  `lib/validation.ml:256-275` (`check_coinbase`)
- **Core ref:** `bitcoin-core/src/consensus/tx_check.cpp:47-51`
  (`bad-cb-length` is in `CheckTransaction` itself, not a separate
  helper)

**Description.** Core's `CheckTransaction` performs the cb scriptSig
length check inline (L49). Camlcoin splits this into two helpers:
`check_transaction` (which on `~is_coinbase:true` just skips the
null-prevout check and the duplicate-input check), and `check_coinbase`
(which enforces 2..100). The block-validation pipeline calls BOTH
(L825 `check_coinbase` then L918 `check_transaction`), so on that
codepath both gates fire. However, any other caller of
`check_transaction` with `~is_coinbase:true` (no current callers, but
the API is exported) silently accepts a length-1 scriptSig.

**Impact.** Latent API surface — caller-side discipline required.
Equivalent to the "dead misbehavior arm" finding (W136 hotbuns BUG).

---

## BUG-9 — `check_transaction` does not call `check_coinbase` self-consistently for `~is_coinbase:true`; both must always be invoked [P2]

- **File:** `lib/validation.ml:170-235`
- **Core ref:** `bitcoin-core/src/consensus/tx_check.cpp:11-60`
  (Core's `CheckTransaction` is one function that handles BOTH
  non-coinbase and coinbase cases via the `tx.IsCoinBase()` branch at
  L47)

**Description.** Camlcoin's `check_transaction ~is_coinbase:true`
**skips** the duplicate-input check (L214-225) AND the null-prevout
check (L228-232), but does NOT replace them with the coinbase scriptSig
length check. The caller MUST also invoke `check_coinbase` to catch
`bad-cb-length`. Two separate functions for one Core function = test
matrix has to cover the product, and silent regressions when one
helper is updated but not the other.

**Impact.** Same as BUG-8 — design risk. Recommend folding
`check_coinbase` into `check_transaction` to mirror Core's single
function.

---

## BUG-10 — `mining.ml:264-270 create_coinbase` does not MoneyRange-check `total_fee` or `reward` before stamping the coinbase output [P1]

- **File:** `lib/mining.ml:264-296`
- **Core ref:** `bitcoin-core/src/node/miner.cpp:186-195`
  (Core's coinbase assembly does not perform a MoneyRange check either,
  but every fee accumulated into `nFees` is the per-tx `txfee` from
  `Consensus::CheckTxInputs`, which DOES enforce MoneyRange — see
  `consensus/tx_verify.cpp:202-209`)

**Description.** `create_coinbase` accepts `total_fee : int64` and
computes `let reward = Int64.add subsidy total_fee in` (L270). No
range check on `total_fee`, no check that `reward` is in `MoneyRange`.
OCaml's `Int64.add` wraps silently on overflow. The supplier of
`total_fee` is `mining.ml:382-383`:

```ocaml
let total_fee = List.fold_left
  (fun acc (_, fee) -> Int64.add acc fee) 0L selected in
```

`selected` is fed from `Mempool.get_sorted_transactions`; per-tx fee was
range-checked in `mempool.ml:2147` (`bad-txns-fee-outofrange`) at mempool
admission. But the **sum** can still exceed `MAX_MONEY`. Without a
guard here, a corrupted mempool snapshot could yield a coinbase that
fails its own validation (`coinbase_value > subsidy+total_fees`),
producing a block that the local node refuses to accept after building.

**Impact.** Self-built blocks rejected post-build. Recoverable
operator pain; no consensus break.

---

## BUG-11 — `mining.ml:663 getblocktemplate "coinbasevalue"` returned as JSON string instead of NUM [P1]

- **File:** `lib/mining.ml:662-666, 697-701`
- **Core ref:** `bitcoin-core/src/rpc/mining.cpp:684, 1001`
  (`RPCResult::Type::NUM` and `result.pushKV("coinbasevalue",
  block.vtx[0]->vout[0].nValue)` — an integer)

**Description.** Core's getblocktemplate returns `coinbasevalue` as a
numeric value. Camlcoin emits it as a stringified int64:

```ocaml
("coinbasevalue",
  `String (Int64.to_string
    (Int64.add
      (Consensus.block_subsidy_for_network template.network_type template.height)
      template.total_fee)));
```

The same pattern shows up at `template_to_json_simple` (L697-703) and
for `total_fee` (L703). External miners (Stratum proxies, ckpool) parse
`coinbasevalue` as an integer; bgw clients break on
`"coinbasevalue": "625000000"`.

**Impact.** W125-class RPC parity break; breaks every standards-aware
mining client.

---

## BUG-12 — `rpc.ml getblockstats` derives `totalfee` from `coinbase_output - subsidy` instead of summing per-tx fees [P0-CDIV]

- **File:** `lib/rpc.ml:3464-3471`
- **Core ref:** `bitcoin-core/src/rpc/blockchain.cpp:2057, 2147, 2193`
  (`CAmount totalfee = 0; ... totalfee += txfee; ...
  ret_all.pushKV("totalfee", totalfee)`)

**Description.** Core computes `totalfee` by walking every tx, looking
up prevouts, and summing `nValueIn - nValueOut` per tx. Camlcoin
short-circuits:

```ocaml
let coinbase_output = List.fold_left ... 0L cb.outputs in
let totalfee = Int64.sub coinbase_output subsidy in
let totalfee = if totalfee < 0L then 0L else totalfee in
```

This is incorrect on at least three axes:

  1. If the miner takes less than `subsidy + fees` (legal — miners can
     burn rewards), `totalfee` is reported as `coinbase - subsidy <
     true_fees`, with negative cases clamped to 0.
  2. If the miner over-pays (legal post-halving when subsidy = 0 and
     coinbase = 0 by convention), `totalfee` equals coinbase amount,
     not the actual fee sum.
  3. The clamp at L3470 silently hides the divergence — operator never
     sees that the formula is wrong.

`avgfee = totalfee / (txs - 1)` (L3471) propagates the divergence into
`avgfee` and (by formula) `avgfeerate` if it were exposed.

**Excerpt** (`lib/rpc.ml:3468-3471`):

```ocaml
let totalfee = Int64.sub coinbase_output subsidy in
let totalfee = if totalfee < 0L then 0L else totalfee in
let avgfee = if txs > 1 then Int64.div totalfee (Int64.of_int (txs - 1)) else 0L in
```

**Impact.** Block-stats divergence vs Core on every block where
miner_take ≠ subsidy + fees. RPC-callers (block explorers, fee
oracles) that cross-check against Core will reject camlcoin output.
The `totalfee=0` clamp also masks bugs in fee accounting on the rest
of the codebase.

---

## BUG-13 — `rpc.ml getblockstats` returns only 11 fields; Core returns ~25 [P2]

- **File:** `lib/rpc.ml:3473-3485`
- **Core ref:** `bitcoin-core/src/rpc/blockchain.cpp:1978-2015`
  (avgfeerate, feerate_percentiles, ins, maxfee, maxfeerate, maxtxsize,
  medianfee, medianfeerate, mediantxsize, minfee, minfeerate, mintxsize,
  outs, subsidy, swtotal_size, swtotal_weight, swtxs, time, total_out,
  total_size, total_weight, totalfee, txs, utxo_increase, utxo_size_inc,
  utxo_increase_actual, utxo_size_inc_actual)

**Description.** Camlcoin emits: `avgfee, height, ins, outs, subsidy,
total_out, total_size, total_weight, totalfee, txs, utxo_increase`.
Missing: `avgfeerate, feerate_percentiles, maxfee, maxfeerate, maxtxsize,
medianfee, medianfeerate, mediantxsize, minfee, minfeerate, mintxsize,
swtotal_size, swtotal_weight, swtxs, time, utxo_size_inc,
utxo_increase_actual, utxo_size_inc_actual, blockhash`.

**Impact.** Tooling parity (electrs, fulcrum, mempool.space backends).

---

## BUG-14 — `assume_utxo.ml:537 max_money` is hardcoded literal instead of `Consensus.max_money` [P2]

- **File:** `lib/assume_utxo.ml:536-538`
- **Core ref:** `bitcoin-core/src/validation.cpp:5820-5823`
  (Core uses the `MoneyRange()` inline helper from `consensus/amount.h`,
  which references `MAX_MONEY`)

**Description.** The snapshot-coin iterator inlines its own MoneyRange
literal:

```ocaml
(* B2: MAX_MONEY = 21_000_000 BTC in satoshis *)
let max_money = 2_100_000_000_000_000L in
```

instead of using `Consensus.max_money` (defined identically at
`lib/consensus.ml:17`). Two sources of truth for the same constant
means if anyone changes `consensus.ml` (e.g., for a fork or unit-test
fixture), the snapshot loader silently desyncs.

**Impact.** Maintenance hazard / parity-drift risk. Same finding class
as W134 nimrod BUG-01 (constants duplicated at 2 sites).

---

## BUG-15 — `lib/utxo.ml:30 height` serialised as `int32` but Core packs it with `IsCoinBase` flag via `nCode = (height<<1) | coinbase` VARINT [P2]

- **File:** `lib/utxo.ml:25-40`
- **Core ref:** `bitcoin-core/src/coins.cpp` Coin::Serialize (CompactInt
  encoding of `nCode = (nHeight << 1) | fCoinBase`)

**Description.** Camlcoin's UTXO serialisation is:

```ocaml
let serialize_utxo_entry w (e : utxo_entry) =
  Serialize.write_int64_le w e.value;
  Serialize.write_compact_size w (Cstruct.length e.script_pubkey);
  Serialize.write_bytes w e.script_pubkey;
  Serialize.write_int32_le w (Int32.of_int e.height);
  Serialize.write_uint8 w (if e.is_coinbase then 1 else 0)
```

This is incompatible with Core's `chainstate/` directory layout (and
with `dumptxoutset` snapshot format which packs height+coinbase into a
single VARINT). The compressor module `lib/compressor.ml` exists
(W138-class parity surface for assumeUTXO), but the in-DB UTXO record
remains divergent. assumeUTXO load uses `compressor.ml` for coin
deserialisation (correct), but the local UTXO record uses
`serialize_utxo_entry` (divergent). Two-format hazard.

**Impact.** No consensus break (camlcoin's UTXO set is internal), but
forensic operator workflows like "swap UTXO dirs between Core and
camlcoin" or "dump and re-import" cannot work without a translation
layer.

---

## BUG-16 — `lib/consensus.ml:88 Int64.shift_right` is arithmetic-shift on a positive value; correct in result but semantically misleading [P3]

- **File:** `lib/consensus.ml:85-88`
- **Core ref:** `bitcoin-core/src/validation.cpp:1848`
  (`nSubsidy >>= halvings;` on `int64_t` — well-defined for non-negative
  shift counts < 64, undefined for >= 64)

**Description.** OCaml's `Int64.shift_right` is **arithmetic** (sign-
preserving). For a positive value like `5_000_000_000L`, the result is
identical to `Int64.shift_right_logical`. But the OCaml manual states
that the shift count must be in `[0, 64)` — `Int64.shift_right 50L 64`
is undefined behaviour. Camlcoin's guard at L87 (`if halvings >= 64
then 0L`) handles this correctly; the result is right. But:

  1. Documentation parity — Core's comment says "Force block reward to
     zero when right shift is undefined." Camlcoin's comment says
     "50 BTC initial." Missing the rationale.
  2. `Int64.shift_right_logical` would express intent better; the
     value is unsigned in meaning.

**Impact.** Cosmetic / latent-maintenance hazard; not exploitable.

---

## BUG-17 — `mining.ml:269 block_subsidy_for_network` invocation passes `Mainnet` as the default in `create_coinbase`'s optional arg [P2]

- **File:** `lib/mining.ml:264-270`
- **Core ref:** none (this is a defensive question — Core does not have
  a "default network = mainnet" anywhere in its mining path)

**Description.** `create_coinbase` signature:

```ocaml
?(network_type : Consensus.network = Consensus.Mainnet) () : Types.transaction
```

If a caller forgets to pass `~network_type`, regtest blocks are minted
with mainnet subsidy. The 150-vs-210000 halving difference means a
regtest block at height 150 should pay 25 BTC (regtest halved once),
but with the default it pays 50 BTC. The default is a footgun.

**Impact.** Test-harness/regtest correctness footgun.

---

## BUG-18 — `lib/utxo.ml:621 fee` invariant: `output_sum > !input_sum → error`. Core uses `nValueIn < value_out`, but the canonical reject reason is `bad-txns-in-belowout`, NOT the camlcoin string "Output exceeds input" [P2 — duplicate of BUG-4 framed for the in-belowout reject reason]

(See BUG-4. Not a separate finding; cross-cite.)

---

## BUG-19 — `lib/validation.ml:1731-1737` fast-path accumulated-fee MoneyRange check uses the wrong error variant (`TxOutputOverflow` instead of a fee-specific reject) [P2]

- **File:** `lib/validation.ml:1736-1737, 1988-1989`
- **Core ref:** `bitcoin-core/src/validation.cpp:2541-2547`
  (`bad-txns-accumulated-fee-outofrange`)

**Description.** When `total_fees` overflows `MoneyRange`, camlcoin
maps it to `TxOutputOverflow`, the same variant used for per-tx output
overflow. Core uses a distinct reject reason
`bad-txns-accumulated-fee-outofrange`. The error-name table at
`lib/validation.ml:tx_error_to_string` accordingly reports
"output sum overflow" for both kinds of overflow.

**Impact.** Cross-impl test-harness reject-reason match fails. Same
class as BUG-4.

---

## BUG-20 — `lib/consensus.ml:783-812 encode_height_in_coinbase` rejects negative height with `failwith`; Core's `CScript() << nHeight` would emit `OP_1NEGATE` for `nHeight = -1` [P3]

- **File:** `lib/consensus.ml:783-812`
- **Core ref:** `bitcoin-core/src/script/script.h:433-448`
  (`push_int64(-1)` emits `OP_1NEGATE` via `(n + (OP_1 - 1))` where
  `OP_1 = 0x51`, so `-1 + 0x50 = 0x4f = OP_1NEGATE`)

**Description.** Negative heights cannot occur in practice (chain
heights start at 0 with genesis). But the `failwith` at L784-785 is a
crash rather than a graceful Error. The mining path doesn't expose
this — BIP-34 only kicks in at `height >= bip34_height` which is at
least 1 on every camlcoin chain. Latent only if `nHeight` ever becomes
negative (impossible). Mostly hygiene.

**Impact.** None in practice. Filed for completeness.

---

## BUG-21 — `lib/mining.ml:703 "total_fee"` field also serialised as JSON string [P2]

- **File:** `lib/mining.ml:703`
- **Core ref:** Core does not expose `total_fee` in `getblocktemplate`
  at all; this is a camlcoin-specific extension. But the related
  `coinbasevalue` is `NUM`. Consistency.

**Description.** `template_to_json_simple` emits:

```ocaml
("total_fee", `String (Int64.to_string template.total_fee));
```

Mining clients that consume the simplified template parse this as an
integer.

**Impact.** Same class as BUG-11. Affects only the "simple" variant.

---

## BUG-22 — `lib/assume_utxo.ml:1087 max_coinbase` allows fee overflow [P1]

- **File:** `lib/assume_utxo.ml:1086-1093`
- **Core ref:** `bitcoin-core/src/validation.cpp:2541-2547,
  2610-2613`

**Description.** assumeUTXO's apply-block helper at L1086-1093
computes `max_coinbase = Int64.add subsidy !total_fees` without
MoneyRange-checking `!total_fees` first. Same shape as BUG-5 but on
the snapshot/background-validation pipeline. Combined with BUG-5
gives camlcoin THREE block-apply pipelines (validation.ml fast path,
validation.ml slow path, utxo.ml connect_block_optimized, plus
assume_utxo.ml apply_block) — only two of the four enforce
accumulated-fee MoneyRange.

**Impact.** Same as BUG-5 but on the assumeUTXO background validator.

---

## BUG-23 — `lib/consensus.ml:644, 690, 735` checkpoints are mainnet-only; testnet3/testnet4 carry empty checkpoint lists [P3]

- **File:** `lib/consensus.ml:627-641` vs L689 / L734
- **Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:181-204`
  (testnet3 has 14 checkpoints in Core; testnet4 has 1)

**Description.** Camlcoin's mainnet config carries 13 checkpoints
(11111…295000). Testnet3 has `checkpoints = []`. Testnet4 has
`checkpoints = []`. This means a malicious peer feeding a long
low-difficulty alternative testnet history would not get rejected
until the chain reaches `assume_valid_hash` (testnet4 only) or the
minimum-chain-work threshold. Tangential to W145's monetary focus
but checkpoints are part of the issuance/finality fence — they prevent
a peer from feeding an early-history fork that would issue different
subsidy at intermediate heights.

**Impact.** Slower IBD on testnet on adversarial network conditions;
no consensus break.

---

## BUG-24 — `lib/validation.ml:1786-1789, 2037-2038` coinbase-value gate fires AFTER fee accumulation but does NOT subtract any "burned" amount; latent if a future fork introduces fee-burning [P3]

- **File:** `lib/validation.ml:1786-1791, 2037-2040`
- **Core ref:** `bitcoin-core/src/validation.cpp:2610-2614`

**Description.** The gate `coinbase_value > max_coinbase` where
`max_coinbase = subsidy + total_fees` is exact parity with Core. But
if a future soft fork ever introduces fee-burning (BIP-1559 style),
the gate would need adjustment. Filed for completeness; no current
fork demands this.

**Impact.** None today.

---

## BUG-25 — `lib/block_import.ml` does NOT call `Storage.ChainDB.set_height_hash` until AFTER `connect_block_optimized` succeeds, but the block itself is stored unconditionally at L63 [P2]

- **File:** `lib/block_import.ml:63, 89-90`
- **Core ref:** `bitcoin-core/src/validation.cpp:5050-5100`
  (Core stores blocks via `BlockManager::SaveBlockToDisk` ONLY after
  `CheckBlock` succeeds; storing then validating leaves block file with
  unvalidated content)

**Description.** The import driver writes the raw block at L63
unconditionally before any check runs. The header → height mapping at
L89-90 IS gated by `connect_block_optimized` success, but the block
bytes are already on disk by then. A later replay/re-scan could find a
block file that no header points to, or worse, a block file whose
content was already-stored-unvalidated and is now consulted by a
restart path that trusts on-disk blocks.

**Impact.** Disk-state corruption window; recoverable by full re-IBD
but not by simple restart.

---

## BUG-26 — `lib/mining.ml:69-74 average_fee_rate` divides Int64 fee by Int weight via float coercion: precision drift vs Core [P3]

- **File:** `lib/mining.ml:67-76`
- **Core ref:** `bitcoin-core/src/rpc/blockchain.cpp:2169`
  (`(totalfee * WITNESS_SCALE_FACTOR) / total_weight` — integer
  division, no float)

**Description.** Camlcoin's `average_fee_rate`:

```ocaml
else Int64.to_float total_fee /. float_of_int total_weight
```

Core uses integer division. Float precision drift is small for typical
values but non-zero, and it's a latent test-harness mismatch.

**Impact.** Negligible value-wise; latent comparison-test risk.

---

## Fleet-pattern smell

- **Two-pipeline guard, 4th camlcoin instance.** `validation.ml`
  enforces `total_fees MoneyRange`; `utxo.ml:connect_block_optimized`
  does NOT (BUG-5, BUG-7). `assume_utxo.ml:apply_block` partially does
  (BUG-22). `block_import.ml` invokes the unguarded one (BUG-1). The
  pattern matches the fleet-wide "dead-helper-at-call-site / inline vs
  helper" archetype catalogued in W139–W141.
- **Comment-as-confession, 5th instance** (`block_import.ml:5-6` —
  comment claims "feeding blocks directly to the validation and UTXO
  connection pipeline" but the code skips validation entirely). Joins
  the W141 rustoshi/clearbit/nimrod/haskoin lineage.
- **Dead field, 2nd camlcoin instance.** `network_config.halving_interval`
  is a defined-but-unread field (BUG-2). First camlcoin instance was
  W141 BUG-3-class. Pattern echoes the W140 ouroboros `-rpcallowip
  config-plumbed-but-never-read` finding.
- **30-of-30-gates-buggy variant: import-pipeline-bypasses-all-gates.**
  BUG-1 is a single-bug-but-bypasses-everything finding rather than a
  per-gate divergence list. Distinct from the W138-W141 "every gate
  divergent" pattern; same severity end-state.
- **`coinbasevalue` JSON-int → JSON-string** (BUG-11, BUG-21) is the
  4th camlcoin RPC-type drift in the W124/W125 family.

## Test coverage notes

- `test/test_validation.ml:2702-2860` (W84) covers GetBlockSubsidy
  halvings, `CheckTransaction` empty-vin/vout, output overflow, and
  duplicate-input cases at the **library function** level. The W84
  suite does NOT cover the `block_import.ml` bypass (BUG-1), the
  `utxo.ml:connect_block_optimized` money-invariant gaps (BUGs 5/6/7),
  or any RPC-shape parity (BUGs 11/12/13). Recommend adding a
  `test_block_import_bypass.ml` that constructs a duplicate-input
  block and confirms `--import-blocks` rejects it.
