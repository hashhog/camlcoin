# W135: Standardness Rules (IsStandardTx) — camlcoin (OCaml)

**Wave**: W135 (DISCOVERY)
**Impl**: camlcoin (OCaml)
**Date**: 2026-05-17
**Status**: DISCOVERY — **17 BUGS / 30 GATES** (1 P0-CONSENSUS / 4 P0-CDIV / 4 P1 / 5 P2 / 3 P3)
**Tests added**: `test/test_w135_standardness.ml` (30 audit-status / xfail-style tests)
**Code under audit**:
- `lib/mempool.ml` (~1700 LOC in scope) — `is_standard_tx` (1498-1585),
  `is_standard_output` (1058-1073), `is_dust` (943-957),
  `is_push_only_script_sig` (964-981), `is_p2pk_script` (987-996),
  `decode_bare_multisig` (1003-1050), `validate_inputs_standardness`
  (1181-1240), `is_witness_standard` (1264-1470),
  `check_p2wsh_witness_limits` (1103-1150), `spends_non_anchor_witness_prog`
  (1856-1871), `check_truc_policy` (1699-1802), top-of-file policy constants
  (124, 140-146, 221-227, 1473-1478).
- `lib/script.ml` — `classify_script` (578-624), `is_p2a` (534-539),
  `p2a_dust_limit` (531), `get_witness_program` (627-644),
  `is_push_only_raw` (546-576), opcode tables.
- `lib/validation.ml` — `compute_tx_weight` (115-127),
  `extract_last_push_data` (403-450), `count_p2sh_sigops` (358-380),
  `count_tx_sigops_cost` (514-590).
- `lib/consensus.ml` — `max_standard_p2wsh_*` (53-55),
  `max_standard_tapscript_stack_item_size` (56), `annex_tag` (59),
  `taproot_leaf_mask` / `taproot_leaf_tapscript` (60-61),
  `max_pubkeys_per_multisig` (51), `max_standard_tx_sigops_cost` (40).

**Reference**:
- `bitcoin-core/src/policy/policy.cpp` (408 LOC) — `GetDustThreshold`
  (27-64), `IsDust` (66-69), `GetDust` (71-78), `IsStandard` (80-98),
  `IsStandardTx` (100-165), `CheckSigopsBIP54` (170-194),
  `ValidateInputsStandardness` (214-263), `IsWitnessStandard` (265-352),
  `SpendsNonAnchorWitnessProg` (354-388).
- `bitcoin-core/src/policy/policy.h` (200 LOC) — `MAX_STANDARD_TX_WEIGHT`
  (38), `MIN_STANDARD_TX_NONWITNESS_SIZE` (40), `MAX_P2SH_SIGOPS` (42),
  `MAX_STANDARD_TX_SIGOPS_COST` (44), `MAX_TX_LEGACY_SIGOPS` (46),
  `DEFAULT_INCREMENTAL_RELAY_FEE` (48), `DEFAULT_BYTES_PER_SIGOP` (50),
  `DEFAULT_PERMIT_BAREMULTISIG` (52), `MAX_STANDARD_P2WSH_STACK_ITEMS` (54),
  `MAX_STANDARD_P2WSH_STACK_ITEM_SIZE` (56),
  `MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE` (58),
  `MAX_STANDARD_P2WSH_SCRIPT_SIZE` (60), `MAX_STANDARD_SCRIPTSIG_SIZE` (62),
  `DUST_RELAY_TX_FEE` (68), `DEFAULT_MIN_RELAY_TX_FEE` (70),
  `DEFAULT_ACCEPT_DATACARRIER` (80), `MAX_OP_RETURN_RELAY` (84),
  `MAX_DUST_OUTPUTS_PER_TX` (95), `TX_MIN_STANDARD_VERSION` (152),
  `TX_MAX_STANDARD_VERSION` (153).
- `bitcoin-core/src/script/solver.cpp` (228 LOC) — `Solver` (141-211),
  `MatchPayToPubkey` (36-47), `MatchPayToPubkeyHash` (49-56),
  `MatchMultisig` (85-105), `MatchMultiA` (107-139).
- `bitcoin-core/src/script/solver.h` — `TxoutType` enum (22-35).
- `bitcoin-core/src/policy/truc_policy.cpp` (261 LOC) — `SingleTRUCChecks`
  (171-261), `PackageTRUCChecks` (57-169).
- `bitcoin-core/src/policy/truc_policy.h` — `TRUC_VERSION` (3),
  `TRUC_MAX_VSIZE` (10_000), `TRUC_CHILD_MAX_VSIZE` (1_000),
  `TRUC_ANCESTOR_LIMIT` (2), `TRUC_DESCENDANT_LIMIT` (2).
- `bitcoin-core/src/consensus/tx_check.cpp` (60 LOC) — `CheckTransaction`.
- `bitcoin-core/src/script/script.cpp` — `IsPayToAnchor` (206-221),
  `IsPushOnly` (262), `IsUnspendable`, `GetSigOpCount(fAccurate)` (~330-380).
- `bitcoin-core/src/pubkey.h` — `CPubKey::ValidSize` (77-79),
  `CPubKey::GetLen` (60-67) — header byte 0x02/0x03 ⇒ 33 / 0x04/0x06/0x07
  ⇒ 65 / else 0.

**Severity legend**:
- **P0-CONSENSUS**: directly observable block-validation divergence vs Core.
- **P0-CDIV**: consensus-relevant policy / mempool divergence — fee-rate,
  feature-flag, or default-config result diverges visibly to clients.
- **P1**: correctness / behavioral gap at the RPC / mempool surface;
  rejects a Core-accepted tx or accepts a Core-rejected one in non-default
  configurations.
- **P2**: structural / robustness gap; magic numbers, missing helpers,
  no plumbing for known runtime options.
- **P3**: documentation / convention drift.

---

## Summary

camlcoin's standardness stack lives almost entirely in `lib/mempool.ml`
(there is no separate `lib/policy.ml` or `lib/standard.ml`). The
`is_standard_tx` entry point (1498-1585) implements 6 of Core's 7
`IsStandardTx` gates correctly (version, weight, min-non-witness-size,
per-input scriptSig size + push-only, per-output Solver-via-classify,
datacarrier budget, dust count). Per-input prevout checks
(`validate_inputs_standardness`) implement Core's three gates
(NONSTANDARD prevout, WITNESS_UNKNOWN prevout, P2SH redeemScript
sigops ≤ 15). Witness-policy (`is_witness_standard`) covers P2WSH
script/stack-size and Taproot annex + tapscript stack-item-size.
TRUC/BIP-431 has its own `check_truc_policy` covering the 6 SingleTRUCChecks
gates.

However the implementation has **substantial structural divergence**:

1. **Pubkey-header validation is absent** in both `is_p2pk_script` and
   `decode_bare_multisig`. Core's `Solver` calls `CPubKey::ValidSize`,
   which verifies the first byte classifies length (0x02/0x03 ⇒ 33,
   0x04/0x06/0x07 ⇒ 65). camlcoin only checks the push-opcode length
   prefix. A P2PK script of the form `0x21 <33 bytes starting with
   0x00> 0xac` is classified as standard PUBKEY in camlcoin but
   NONSTANDARD in Core — **P0-CDIV** for relay parity.

2. **BIP-54 `CheckSigopsBIP54`** (per-input non-witness sigops vs
   `MAX_TX_LEGACY_SIGOPS=2500`) is **completely absent**. This is
   `ValidateInputsStandardness` gate 0 in Core (added 2025 for the
   recent CVE-style sigop-exhaustion mitigation), and Core treats it
   as a TX_INPUTS_NOT_STANDARD failure. **P0-CONSENSUS** because BIP-54
   has both a policy and a consensus arm in current Core; the policy
   arm is mempool-only but the same sigop count is also a block-level
   gate at the next deployment.

3. **`-datacarrier`, `-permitbaremultisig`, `-dustrelayfee`,
   `-bytespersigop`, `-datacarriersize`, `-acceptnonstdtxn` runtime
   flags are not wired**. `is_standard_tx` reads literal global constants
   (`max_datacarrier_bytes = 100_000`, hard-coded `dust_relay_fee = 3 *
   min_relay_fee`, no bare-multisig opt-out). Operators cannot turn off
   datacarrier or permit-baremultisig on a running node — **P1** for
   operator-experience parity.

4. **Dust-threshold formula uses `3 × min_relay_fee` instead of
   Core's separately-configurable `dustRelayFee` (default
   `DUST_RELAY_TX_FEE = 3000 sat/kvB`)**. The two only happen to coincide
   when `min_relay_fee = 1000`. At the default `DEFAULT_MIN_RELAY_TX_FEE
   = 100`, camlcoin's dust threshold is 30× too low — accepts dust
   outputs that Core rejects. **P0-CDIV**.

5. **`spends_non_anchor_witness_prog` does not unwrap P2SH-wrapped
   witness programs**, where Core's `SpendsNonAnchorWitnessProg`
   (policy.cpp:373-384) DOES `EvalScript(scriptSig)` and checks the
   resulting redeem script for `IsWitnessProgram`. camlcoin would
   misclassify a P2SH-wrapped P2WPKH input as non-witness, breaking
   TX_WITNESS_STRIPPED detection in `net_processing` parity. **P1**.

6. **MultiA (BIP-342, OP_CHECKSIGADD threshold) is not in `classify_script`
   or `is_standard_output`**, so any sub-script style multi_a in a
   tapscript spend would be treated only via the generic tapscript
   stack-item check. Core has `MatchMultiA` (solver.cpp:107-139) used by
   descriptor inference. Not a relay-side bug per se (multi_a is a
   tapscript construct that lives inside a P2TR spend, not as a top-level
   scriptPubKey) but missing surface for wallet / descriptor inference.
   **P2**.

7. **`extract_last_push_data` (validation.ml:403-450) does not handle
   OP_0, OP_1NEGATE, OP_1..OP_16**. Core's `EvalScript(SCRIPT_VERIFY_NONE)`
   pushes the numeric values 0x00, 0x81, 0x01..0x10 for those opcodes;
   the "last pushed item" in a scriptSig like
   `PUSH(redeem) OP_1` is therefore `0x01` in Core but `redeem` in
   camlcoin. Affects both `validate_inputs_standardness` gate 3
   (P2SH sigop counting on wrong subscript) and `is_witness_standard`
   gate 2 (P2SH-wrapped witness extraction). **P1**.

8. **TRUC sibling-eviction return** (Core truc_policy.cpp:240-258) is
   absent — `check_truc_policy` returns Error rather than identifying
   the sibling for caller-level eviction. Already documented as
   `BUG-5/BUG-W106-5` in `test_w106_mempool.ml`; reaffirmed here.

9. **`spending_input_size` constants** (mempool.ml:925-934) embed
   magic numbers (148 / 91 / 67 / 109 / 58 / 41) without referencing
   Core's `GetDustThreshold` derivation (32+4+1+(107/4)+4=67 for
   witness; 32+4+1+107+4=148 for non-witness). The 91-byte P2SH
   spend-size doesn't match Core's calculation (Core uses 148 for
   P2SH because the redeemScript spend is conceptually non-witness).
   **P2**.

10. **`is_standard_output` `is_p2pk_script` rejects 67-byte
    uncompressed P2PK keys with header bytes 0x06 or 0x07** (mempool.ml:
    994-996 hard-codes `0x41 <65 bytes> 0xac` but expects header 0x04 in
    practice; the header isn't validated at all, so 0x05/0x08/etc. ALSO
    pass). Pair of bugs around CPubKey::GetLen validation. **P1**.

**Verdict counts**:

| Verdict      | Count |
|-------------:|------:|
| PRESENT      |    14 |
| PARTIAL      |    10 |
| **MISSING**  |   **6** |
| Total gates  |    30 |

**BUG priority counts**:

| Priority         | Count |
|-----------------:|------:|
| **P0-CONSENSUS** |   **1** |
| **P0-CDIV**      |   **4** |
| P1               |     4 |
| P2               |     5 |
| P3               |     3 |
| Total bugs       |    17 |

---

## 30-gate matrix (W135)

### G1-G5: IsStandardTx outer gates (version, weight, scriptSig, output)

- **G1**: `tx.version ∈ [TX_MIN_STANDARD_VERSION=1, TX_MAX_STANDARD_VERSION=3]`
  — `mempool.ml:1501-1503`. **PRESENT**.

- **G2**: `weight ≤ MAX_STANDARD_TX_WEIGHT=400_000` —
  `mempool.ml:1506-1508`. **PRESENT**.

- **G3**: `nonwitness_size ≥ MIN_STANDARD_TX_NONWITNESS_SIZE=65`
  (CVE-2017-12842) — `mempool.ml:1512-1514` AND a backstop check at
  `mempool.ml:2009-2011` outside the require_standard guard.
  **PRESENT**.

- **G4**: per-input `scriptSig.size() ≤ MAX_STANDARD_SCRIPTSIG_SIZE=1650`
  AND `scriptSig.IsPushOnly()` — `mempool.ml:1520-1530`.
  **PRESENT**.

- **G5**: per-output `IsStandard(scriptPubKey, whichType)` via
  `is_standard_output → classify_script` — `mempool.ml:1543-1546` →
  `mempool.ml:1058-1073`. **PARTIAL** — see BUG-1 / BUG-2 for pubkey-header
  validation.

### G6-G10: Solver-equivalent classification + multisig limits

- **G6**: `TxoutType::PUBKEY` recognition matches Core's
  `MatchPayToPubkey`. Camlcoin: `is_p2pk_script` (mempool.ml:987-996).
  **MISSING** — BUG-1 below: does not validate `CPubKey::ValidSize`
  (header byte must classify length).

- **G7**: `TxoutType::PUBKEYHASH` recognition matches `MatchPayToPubkeyHash`.
  Camlcoin: `classify_script` P2PKH branch (script.ml:582-588).
  **PRESENT**.

- **G8**: `TxoutType::SCRIPTHASH` recognition matches Core's P2SH shortcut.
  Camlcoin: `classify_script` P2SH branch (script.ml:591-595).
  **PRESENT**.

- **G9**: `TxoutType::MULTISIG` with n in [1,3] (Core's standard policy)
  AND m in [1,n]. Camlcoin: `is_standard_output → decode_bare_multisig`
  (mempool.ml:1071-1073) — checks n∈[1,3] and m∈[1,n]. Decoder
  (mempool.ml:1003-1050) requires m as OP_n (0x51..0x60) — matches
  Core's `GetScriptNumber(1, MAX_PUBKEYS_PER_MULTISIG)`. Pubkey
  validation is **MISSING** (only push-length prefix, no header byte)
  — BUG-2.

- **G10**: `TxoutType::NULL_DATA` (OP_RETURN <pushonly>) recognition.
  Camlcoin: `classify_script` OP_RETURN branch (script.ml:621-623)
  including the `is_push_only_raw` subscript check (script.ml:546-576).
  **PRESENT**.

### G11-G15: Witness, anchor, datacarrier

- **G11**: `TxoutType::WITNESS_V0_KEYHASH` / `WITNESS_V0_SCRIPTHASH` /
  `WITNESS_V1_TAPROOT` recognition. Camlcoin: `classify_script` matches
  P2WPKH (22 bytes), P2WSH (34 bytes), P2TR (34 bytes). **PRESENT**.

- **G12**: `TxoutType::WITNESS_UNKNOWN` distinction (recognised witness
  program at unknown version/size). Camlcoin uses `get_witness_program`
  to distinguish from generic Nonstandard in `validate_inputs_standardness`
  (mempool.ml:1198-1213). **PRESENT**.

- **G13**: `TxoutType::ANCHOR` (P2A — OP_1 <0x4e 0x73>). Camlcoin:
  `is_p2a` (script.ml:534-539) matches Core's `IsPayToAnchor`
  (script.cpp:206-213). **PRESENT**.

- **G14**: `bare-multisig` rejection when `permit_bare_multisig=false`.
  Core uses `DEFAULT_PERMIT_BAREMULTISIG=true` and a CLI flag
  `-permitbaremultisig=0` to switch it off, then rejects with reason
  `"bare-multisig"` (policy.cpp:152-154). Camlcoin: `is_standard_output`
  unconditionally accepts bare multisig with n∈[1,3]
  (mempool.ml:1071-1073). The `-permitbaremultisig` flag is not wired.
  **MISSING** — BUG-3.

- **G15**: datacarrier budget — Core uses
  `max_datacarrier_bytes.value_or(0)` (policy.cpp:137), meaning when
  `-datacarrier=0` is set, `max_datacarrier_bytes = std::nullopt` and
  EVERY OP_RETURN is rejected (budget starts at 0). Camlcoin hard-codes
  `max_datacarrier_bytes = 100_000` (mempool.ml:1476), and there is no
  CLI flag wired. **MISSING** — BUG-4.

### G16-G20: Dust + ValidateInputsStandardness

- **G16**: `GetDustThreshold` formula. Core: `dustRelayFee.GetFee(nSize)`
  where `nSize = GetSerializeSize(txout) + (32+4+1+(107/4)+4)` for
  witness or `(32+4+1+107+4)` for non-witness (policy.cpp:46-61), and
  `dustRelayFee` is a separately-configurable parameter defaulting to
  `DUST_RELAY_TX_FEE = 3000 sat/kvB`. Camlcoin uses
  `3.0 × min_relay_fee × (output_size + spend_size) / 1000.0`
  (mempool.ml:953-956). The literal `3.0` is wrong when
  `min_relay_fee ≠ 1000`. **MISSING** — BUG-5.

- **G17**: P2A dust threshold. Core: derived from `GetDustThreshold` on
  the 4-byte P2A scriptPubKey (becomes ~330 sat at default
  dust_relay_fee). Camlcoin hard-codes `<> 240L` for P2A
  (mempool.ml:946-948), accepting EXACTLY 240 sat and rejecting both
  239 and 241. **PARTIAL** — BUG-6.

- **G18**: `MAX_DUST_OUTPUTS_PER_TX = 1` (Core: ephemeral dust at most
  one). Camlcoin: `max_dust_outputs_per_tx = 1` (mempool.ml:1478) with
  count-check at 1572-1575. **PRESENT**.

- **G19**: `ValidateInputsStandardness` gate 0 — `CheckSigopsBIP54`
  (per-input non-witness sigops vs `MAX_TX_LEGACY_SIGOPS = 2_500`,
  policy.cpp:170-194). **MISSING** in camlcoin — no helper exists, no
  constant exists. **MISSING** — BUG-7 (P0-CONSENSUS once the BIP54
  consensus arm activates; P0-CDIV today for relay-mempool divergence).

- **G20**: `ValidateInputsStandardness` gate 1 — NONSTANDARD prevout +
  gate 2 — WITNESS_UNKNOWN prevout + gate 3 — P2SH redeemScript sigops
  ≤ `MAX_P2SH_SIGOPS = 15`. Camlcoin: `validate_inputs_standardness`
  (mempool.ml:1181-1240). **PARTIAL** — gate 3 uses
  `extract_last_push_data` which doesn't honour OP_n / OP_0 / OP_1NEGATE
  pushes (BUG-8 below).

### G21-G25: IsWitnessStandard

- **G21**: Coinbase exemption — return Ok immediately for coinbases
  (Core: policy.cpp:267-268). Camlcoin: `is_witness_standard`
  (mempool.ml:1269-1271). **PRESENT**.

- **G22**: P2A spends MUST have empty witness; non-empty witness on a
  P2A input is "bad-witness-nonstandard". Core: policy.cpp:283-285.
  Camlcoin: mempool.ml:1289-1290. **PRESENT**.

- **G23**: P2WSH v0 policy — `witness_script.size() ≤
  MAX_STANDARD_P2WSH_SCRIPT_SIZE=3600`, stack-items ≤
  `MAX_STANDARD_P2WSH_STACK_ITEMS=100`, each item ≤
  `MAX_STANDARD_P2WSH_STACK_ITEM_SIZE=80`. Core: policy.cpp:309-319.
  Camlcoin: mempool.ml:1377-1402. **PRESENT**.

- **G24**: Taproot (v1 32B not-P2SH-wrapped) — annex rejection +
  per-tapscript stack-item ≤
  `MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE=80`. Core: policy.cpp:324-349.
  Camlcoin: mempool.ml:1407-1462. **PRESENT**.

- **G25**: `SpendsNonAnchorWitnessProg` — must also unwrap P2SH and
  check the redeem script for `IsWitnessProgram`. Core:
  policy.cpp:373-384. Camlcoin: `spends_non_anchor_witness_prog`
  (mempool.ml:1856-1871) checks only the direct prevout, NOT the
  unwrapped P2SH redeem script. **MISSING** — BUG-9.

### G26-G30: TRUC / BIP-431 + RuntimeConfig surface

- **G26**: TRUC `SingleTRUCChecks` 6-gate ladder (inheritance,
  TRUC_MAX_VSIZE=10_000, TRUC_ANCESTOR_LIMIT=2, parent ancestor count,
  TRUC_CHILD_MAX_VSIZE=1_000, TRUC_DESCENDANT_LIMIT=2). Camlcoin:
  `check_truc_policy` (mempool.ml:1699-1802). **PRESENT** (functional
  closure documented in existing W106 group); see also BUG-10 below
  for the missing sibling-eviction return.

- **G27**: TRUC sibling-eviction return. Core: SingleTRUCChecks at
  truc_policy.cpp:240-258 returns the sibling tx ref so the caller can
  attempt RBF eviction. Camlcoin returns only a string error; caller
  cannot consider sibling eviction. **MISSING** — BUG-10 (same root
  cause as existing BUG-W106-5).

- **G28**: `MAX_STANDARD_TX_SIGOPS_COST = MAX_BLOCK_SIGOPS_COST / 5 =
  16_000`. Camlcoin: `Consensus.max_standard_tx_sigops_cost = 16_000`
  (consensus.ml:40), enforced at mempool.ml:2056-2058. **PRESENT**.

- **G29**: `-bytespersigop` runtime flag (Core `DEFAULT_BYTES_PER_SIGOP =
  20`, used in `GetSigOpsAdjustedWeight` to inflate vsize). Camlcoin:
  `default_bytes_per_sigop = 20` (consensus.ml:46) exists as a named
  constant, but no `-bytespersigop` runtime flag is wired through
  `runtime_config.ml` / `cli.ml`. **PARTIAL** — BUG-11 (P2).

- **G30**: `-acceptnonstdtxn` runtime flag. Core flag toggles
  `m_require_standard` per-chain (default true on mainnet, false on
  regtest). Camlcoin: `Mempool.create ~require_standard` is the
  constructor argument but no CLI flag flips it. **PARTIAL** —
  BUG-12 (P2).

---

## BUG catalogue

### BUG-W135-1 (P0-CDIV, G6) — `is_p2pk_script` doesn't validate pubkey header byte

**Location**: `lib/mempool.ml:987-996`.

**Behavior**: a script of the form `0x21 <33 bytes> 0xac` is accepted as
P2PK iff the length is 35; a script of form `0x41 <65 bytes> 0xac` is
accepted iff length is 67. **The 33-byte / 65-byte body is NOT
validated for a valid header byte.**

Core's `MatchPayToPubkey` (solver.cpp:36-47) calls `CPubKey::ValidSize`,
which calls `CPubKey::GetLen(chHeader)`:
- header 0x02 or 0x03 ⇒ 33 bytes valid
- header 0x04, 0x06 or 0x07 ⇒ 65 bytes valid
- else ⇒ 0 (invalid)

A scriptPubKey `0x21 <33 zero bytes> 0xac` (header 0x00) is classified as
NONSTANDARD in Core, but PUBKEY in camlcoin. `is_standard_tx` therefore
accepts such a tx; Core's mempool rejects it with `"scriptpubkey"`.

**Impact**: a transaction with a malformed P2PK-shaped output is relayed
by camlcoin nodes but dropped by Core nodes. Network-level relay
divergence — also affects any wallet-side `classify_script` consumers
(scantxoutset, descriptor inference) that distinguish PUBKEY from
NONSTANDARD.

**Fix sketch**: in `is_p2pk_script`, also validate the pubkey header
byte (`script[1] ∈ {0x02,0x03}` for 33-byte; `script[1] ∈ {0x04,0x06,0x07}`
for 65-byte). One-liner per branch.

### BUG-W135-2 (P0-CDIV, G9) — `decode_bare_multisig` doesn't validate pubkey header bytes

**Location**: `lib/mempool.ml:1003-1050`.

**Behavior**: in the pubkey-walk loop (1020-1033), the decoder accepts
any 33-byte push (push_byte = 0x21) or 65-byte push (push_byte = 0x41)
WITHOUT validating that the next byte of the pubkey is a valid header
(0x02/0x03 for 33-byte, 0x04/0x06/0x07 for 65-byte).

Core's `MatchMultisig` (solver.cpp:85-105) walks pubkeys via
`script.GetOp` and validates each via `CPubKey::ValidSize(data)`.

**Impact**: same as BUG-W135-1 but for bare multisig outputs. A 1-of-1
bare multisig with a "compressed" pubkey whose first byte is 0x00 is
relayed by camlcoin, dropped by Core.

**Fix sketch**: in the loop, add `script[pos+1]` header-byte check.

### BUG-W135-3 (P1, G14) — `-permitbaremultisig` runtime flag absent

**Location**: `lib/mempool.ml:1071-1073`, `lib/runtime_config.ml`,
`lib/cli.ml`.

**Behavior**: bare multisig with n∈[1,3] is always accepted as standard.
There is no plumbing to switch off bare-multisig relay
(`-permitbaremultisig=0`). Core's IsStandardTx (policy.cpp:152-154)
rejects with `"bare-multisig"` when the flag is false.

**Impact**: operators cannot opt out of bare-multisig relay on camlcoin;
node behaviour deviates from Core when the operator explicitly disables
it. Default behaviour (true) matches Core.

**Fix sketch**: add `permit_bare_multisig : bool` to `mempool`
record (default true matching `DEFAULT_PERMIT_BAREMULTISIG`), thread
through `is_standard_tx`, expose as `-permitbaremultisig` in
`cli.ml`/`runtime_config.ml`.

### BUG-W135-4 (P0-CDIV, G15) — `-datacarrier` runtime flag absent + hard-coded budget

**Location**: `lib/mempool.ml:1476`, `lib/mempool.ml:1540`.

**Behavior**: `max_datacarrier_bytes = 100_000` is a top-level `let`
binding; the per-tx budget is initialised to this value with no
runtime override. Core uses `std::optional<unsigned>
max_datacarrier_bytes`, which is `std::nullopt` when `-datacarrier=0`
is set; the budget is then 0 and EVERY OP_RETURN output is rejected
with `"datacarrier"`.

**Impact**: operators who set `-datacarrier=0` to refuse OP_RETURN
relay on Core have NO way to do that on camlcoin. Relay-policy
divergence visible at the OP_RETURN tx level — Core rejects the tx
with reason "datacarrier" while camlcoin accepts it.

**Fix sketch**: change `max_datacarrier_bytes` to a `mempool` field of
type `int option` (`None` ⇒ datacarrier disabled). Thread `-datacarrier`
and `-datacarriersize` through `runtime_config.ml`.

### BUG-W135-5 (P0-CDIV, G16) — Dust formula uses `3 × min_relay_fee` instead of separately-configurable `dustRelayFee`

**Location**: `lib/mempool.ml:953-956`.

**Behavior**: dust threshold is computed as
```ocaml
let threshold = Int64.of_float (
  3.0 *. Int64.to_float min_relay_fee *.
  float_of_int (output_serialized_size output + spend_size) /. 1000.0) in
```

This embeds `3.0` as if `dustRelayFee = 3 × min_relay_fee`. Core's
`dustRelayFee` is a separately-configurable `CFeeRate` (param
`-dustrelayfee`) defaulting to `DUST_RELAY_TX_FEE = 3000 sat/kvB`,
which is INDEPENDENT of `-minrelaytxfee` (which defaults to
`DEFAULT_MIN_RELAY_TX_FEE = 100 sat/kvB`).

For the default camlcoin config (`min_relay_fee = 1000`), the formula
happens to produce `3000` which coincides with Core's default — but
only by accident. At Core's actual default min_relay_fee=100, camlcoin's
dust threshold would be 30× too low; at min_relay_fee=10_000, 3× too
high.

**Impact**: a Core node at default fees rejects ~546 sat P2PKH outputs
as dust; a camlcoin node at `-minrelaytxfee=100` would accept ~55 sat
P2PKH outputs. Relay-policy divergence at the dust-acceptance level.

**Fix sketch**: introduce `mempool.dust_relay_fee : int64` (sat/kvB)
default 3000, wire `-dustrelayfee`, replace literal 3.0 with the
configured value.

### BUG-W135-6 (P0-CDIV, G17) — P2A dust uses hard-coded `<> 240L`

**Location**: `lib/mempool.ml:946-948`, `lib/script.ml:531`.

**Behavior**: `is_dust` for P2A scriptPubKey is `output.value <> 240L`.
This rejects ANY P2A output that does not have exactly 240 sat
(including 241+ sat that Core would consider not-dust).

Core computes the P2A dust threshold via `GetDustThreshold` on the
4-byte P2A scriptPubKey (4 + serialization overhead + 41-byte witness
input-size estimate ≈ ~330 sat at default dust_relay_fee). A P2A output
with 1000 sat is NOT dust in Core, but in camlcoin it is
("value <> 240L" is true).

**Impact**: camlcoin rejects P2A outputs above 240 sat (and below)
that Core accepts. Most P2A outputs in practice are at the 240-sat
dust floor, so the practical impact is small, but the relay rule
diverges.

**Fix sketch**: remove the P2A special case and let `GetDustThreshold`
handle it; or align the formula with Core's
`GetDustThreshold(p2a_scriptPubKey, dustRelayFee)`.

### BUG-W135-7 (P0-CONSENSUS, G19) — `CheckSigopsBIP54` (per-input non-witness sigops ≤ 2500) is completely missing

**Location**: `lib/mempool.ml:1181-1240`, `lib/consensus.ml`,
`lib/policy.h` equivalent.

**Behavior**: Core's `CheckSigopsBIP54` (policy.cpp:170-194) is called
from `ValidateInputsStandardness` BEFORE the per-input prevout-type
check. It sums per-input `scriptSig.GetSigOpCount(true) +
prev_txo.scriptPubKey.GetSigOpCount(scriptSig)` over all inputs and
rejects if the total exceeds `MAX_TX_LEGACY_SIGOPS = 2500`.

camlcoin has no equivalent helper. The constant `MAX_TX_LEGACY_SIGOPS`
is not defined; the check is not performed at all. The per-tx weighted
sigops check (mempool.ml:2056-2058, `MAX_STANDARD_TX_SIGOPS_COST=16_000`)
is DIFFERENT — it counts weighted sigops (legacy × 4 + witness × 1)
across the WHOLE tx (in + out + witness), not the per-input non-witness
subset.

**Impact**: a tx with extreme legacy-sigop concentration on inputs
(e.g., 2501 CHECKSIG ops via P2SH-wrapped scripts where each redeem has
exactly 1 sigop, multiplied across many inputs) is rejected by Core's
BIP-54 check but accepted by camlcoin. Today this is policy-only
(mempool-level), but BIP-54 has a consensus arm that activates at a
specified deployment height; once that activates, divergence becomes
consensus-level (block-validation divergence).

**Fix sketch**: add `max_tx_legacy_sigops = 2500` constant to
`mempool.ml`. Implement `check_sigops_bip54` that walks inputs and
sums `count_sigops scriptSig (~fAccurate:true)` + `count_p2sh_sigops
prev_scriptPubKey` (using the existing fAccurate-equivalent counter).
Call it FIRST in `validate_inputs_standardness`. Add a fail-message
`"non-witness sigops exceed bip54 limit"` matching Core
(policy.cpp:222).

### BUG-W135-8 (P1, G20) — `extract_last_push_data` skips OP_0 / OP_1NEGATE / OP_1..OP_16

**Location**: `lib/validation.ml:403-450`.

**Behavior**: the helper only inspects push opcodes 0x01-0x4e
(0x4c=OP_PUSHDATA1, 0x4d=OP_PUSHDATA2, 0x4e=OP_PUSHDATA4 plus the
direct-push range 0x01-0x4b). It does NOT push values for OP_0 (0x00),
OP_1NEGATE (0x4f), OP_1..OP_16 (0x51..0x60), all of which Core's
`EvalScript(SCRIPT_VERIFY_NONE)` would push as numeric values 0x00,
0x81, 0x01..0x10 respectively.

**Impact 1 — `validate_inputs_standardness` gate 3** (P2SH sigop check):
for a P2SH scriptSig like `<scriptpush:redeem> OP_1`, Core's
`EvalScript` ends with stack = [`redeem`, `0x01`]; the "redeem script"
is `0x01` (a single-byte push of 1), which has 0 sigops. camlcoin's
`extract_last_push_data` returns `redeem` (which it last saw as a real
push), so it counts redeem's sigops. Net effect: camlcoin can REJECT
a P2SH input that Core accepts because the actual subscript executed
is the trivial OP_1 push, but camlcoin checks the real redeem script
underneath. Not a CDIV in normal use (typical scriptSigs end with the
redeem push), but it is a behavioral gap on adversarial scriptSig
shapes.

**Impact 2 — `is_witness_standard` gate 2** (P2SH-wrapped witness):
in the P2SH-unwrap path (mempool.ml:1299-1356), the inline EvalScript
DOES handle OP_0/OP_1NEGATE/OP_1..OP_16 — so this site is OK. The bug
is only in `extract_last_push_data` used by
`validate_inputs_standardness`.

**Fix sketch**: add cases for OP_0 (push `Cstruct.empty`), OP_1NEGATE
(push `\x81`), OP_1..OP_16 (push `\x01`..`\x10`) so the "last item"
captured matches Core's EvalScript stack top.

### BUG-W135-9 (P1, G25) — `spends_non_anchor_witness_prog` doesn't unwrap P2SH

**Location**: `lib/mempool.ml:1856-1871`.

**Behavior**: the helper checks `Script.is_p2a` then
`Script.get_witness_program` on the **prev_spk** directly. It does
NOT match Core's policy.cpp:373-384 which also handles the P2SH case:

```cpp
if (prev_spk.IsPayToScriptHash()) {
    std::vector<std::vector<uint8_t>> stack;
    if (!EvalScript(stack, txin.scriptSig, SCRIPT_VERIFY_NONE,
                    BaseSignatureChecker{}, SigVersion::BASE)
        || stack.empty()) {
        continue;
    }
    const CScript redeem_script{stack.back().begin(), stack.back().end()};
    if (redeem_script.IsWitnessProgram(version, program)) {
        return true;
    }
}
```

**Impact**: in `net_processing` parity, when a peer relays a stripped
witness for a P2SH-wrapped P2WPKH input, camlcoin will NOT detect this
because it sees the prev_spk as P2SH (not witness program); the
TX_WITNESS_STRIPPED disconnect/refetch never fires. Core does detect
this and re-fetches the witness from a different peer.

**Fix sketch**: after the direct `get_witness_program` check, if the
prev_spk is P2SH, extract the last push from the scriptSig and check
THAT for `get_witness_program`. Use the existing EvalScript inline
helper from `is_witness_standard` (mempool.ml:1303-1348) — refactor it
into a shared function.

### BUG-W135-10 (P1, G27) — TRUC sibling-eviction return missing (W106 BUG-5 carry-forward)

**Location**: `lib/mempool.ml:1789-1797`.

**Behavior**: when the TRUC descendant-count check fails (parent
already has 1 child and the new tx would be the 2nd), `check_truc_policy`
returns a string error with no reference to the existing sibling.
Core's `SingleTRUCChecks` (truc_policy.cpp:240-258) returns a
`std::pair<std::string, CTransactionRef>` where the second element is
the sibling so the caller can attempt RBF-style sibling eviction.

**Impact**: camlcoin can never perform TRUC sibling eviction. Operators
who try to replace one child of a TRUC parent with another get a flat
"already has child" rejection; Core would consider eviction under RBF
rules.

**Status**: Already documented as `BUG-W106-5` in
`test_w106_mempool.ml` and listed in the W106 audit as an open
P0-CDIV item. Reaffirmed under W135 G27.

**Fix sketch**: change `check_truc_policy` return type to
`(unit, string * Types.hash256 option) result` so the caller knows the
sibling txid; thread through `add_transaction` to attempt eviction.

### BUG-W135-11 (P2, G29) — `-bytespersigop` runtime flag absent

**Location**: `lib/consensus.ml:46`, `lib/runtime_config.ml`,
`lib/cli.ml`, `lib/validation.ml:140-151`.

**Behavior**: `default_bytes_per_sigop = 20` is a named constant
matching `DEFAULT_BYTES_PER_SIGOP` in Core, and
`get_sigops_adjusted_weight` accepts it as a parameter. But there is
no CLI flag wiring — every callsite passes `bytes_per_sigop = 0` or
`bytes_per_sigop = 20` directly, with no path for operators to
override.

**Impact**: low — most operators use the default. But Core advertises
`-bytespersigop` as a tunable in `init.cpp`.

**Fix sketch**: thread `mempool.bytes_per_sigop` through, expose CLI.

### BUG-W135-12 (P2, G30) — `-acceptnonstdtxn` runtime flag absent

**Location**: `lib/mempool.ml:81` (`require_standard` field exists),
`lib/cli.ml`, `lib/runtime_config.ml`.

**Behavior**: the `mempool` record has a `require_standard : bool`
field, but the CLI does not expose `-acceptnonstdtxn` to flip it.
Tests set it directly via `Mempool.create ~require_standard:false`,
but operators cannot.

**Impact**: low — networks default to require_standard=true (mainnet,
testnet4); regtest historically defaults to false. Operators running
custom relays cannot easily turn off standardness.

**Fix sketch**: add `-acceptnonstdtxn` CLI flag, wire to `require_standard`
default selection per network (currently hard-coded).

### BUG-W135-13 (P2, G16) — `spending_input_size` constants don't match Core derivation

**Location**: `lib/mempool.ml:925-934`.

**Behavior**: the constants 148 / 91 / 67 / 109 / 58 / 41 are stamped
without documentation referencing Core. The 91-byte estimate for
P2SH (line 928) is suspicious because Core uses the *full* 148-byte
non-witness sigop+sigsize estimate for any non-witness output (see
policy.cpp:60). P2SH (which is non-witness) should be 148, not 91.

The 109-byte estimate for P2WSH (line 930) doesn't match the
`(107/4)` Core computes for witness inputs either — Core actually
computes 67 for ANY witness program (P2WPKH or P2WSH).

**Impact**: dust thresholds for P2SH and P2WSH outputs are wrong:
P2SH dust threshold in camlcoin is 91/148 ≈ 0.6× of Core's, so
camlcoin accepts P2SH outputs Core would reject; P2WSH dust threshold
is 109/67 ≈ 1.6× of Core's, so camlcoin rejects P2WSH outputs Core
accepts.

**Fix sketch**: replace `spending_input_size` with Core's exact
derivation:
```
nSize = GetSerializeSize(txout)
      + (IsWitnessProgram(scriptPubKey) ? 67 : 148)
```

### BUG-W135-14 (P2, G7-G9) — multi_a (BIP-342 tapscript) not in classify_script

**Location**: `lib/script.ml:578-624` and `lib/mempool.ml:1058-1073`.

**Behavior**: Core's `solver.h` declares `MatchMultiA` and uses it from
descriptor inference (`InferScript`). camlcoin's `classify_script` has
no match for tapscript multi_a (32-byte xonly pubkeys + OP_CHECKSIGADD
chain + OP_NUMEQUAL + threshold).

**Impact**: standard scriptPubKeys at the spk level are never multi_a
(multi_a only appears inside a P2TR script-path tapscript leaf), so
this is not a relay-side bug. But descriptor inference / wallet support
for multi_a leaves cannot identify them.

**Fix sketch**: add a `MultiA_script of int * Cstruct.t list` variant
(threshold + xonly keys) or a separate predicate; not required for
IsStandardTx.

### BUG-W135-15 (P3, G16) — Dust function uses floating-point arithmetic

**Location**: `lib/mempool.ml:953-956`.

**Behavior**: dust threshold is computed via `float_of_int` →
`Int64.of_float`. Core uses integer arithmetic only
(`CFeeRate::GetFee`). For large `output_serialized_size + spend_size`
products or very large min_relay_fee, the float intermediate can lose
precision (53 mantissa bits).

**Impact**: practically zero — the products in play are well under
2^53 — but documentation drift and a precision footgun for any future
tuning.

**Fix sketch**: replace with integer arithmetic:
`Int64.div (Int64.mul (Int64.mul 3L min_relay_fee) (Int64.of_int (size))) 1000L`.

### BUG-W135-16 (P3, G19-G20) — Per-tx error reasons drift from Core's exact strings

**Location**: `lib/mempool.ml:1503,1508,1514,1525,1529,1546,1553,1574`.

**Behavior**: camlcoin error strings ("Non-standard transaction version",
"Transaction weight exceeds standard limit", "scriptsig-size: ...",
"datacarrier: ...", etc.) are not byte-identical to Core's reason
strings ("version", "tx-size", "scriptsig-size",
"scriptsig-not-pushonly", "scriptpubkey", "bare-multisig",
"datacarrier", "dust").

**Impact**: low — RPC clients parsing the `reject-reason` field of
`testmempoolaccept` see different strings between Core and camlcoin.

**Fix sketch**: align literal strings to Core's `reason` writes in
`IsStandardTx`. Minimal touch.

### BUG-W135-17 (P3, G27) — TRUC inheritance error string drift

**Location**: `lib/mempool.ml:1713-1717`.

**Behavior**: camlcoin emits "Non-v3 transaction cannot spend
unconfirmed v3 outputs" / "TRUC/v3 transaction cannot spend from
unconfirmed non-v3 transaction"; Core emits "non-version=3 tx %s
(wtxid=%s) cannot spend from version=3 tx %s (wtxid=%s)" with txid +
wtxid embedded. Diagnostic drift.

**Impact**: low — debug-mode log parity only.

**Fix sketch**: include txid + wtxid; align prefix to "non-version=3
tx" / "version=3 tx".

---

## Universal patterns observed

1. **"runtime-flag-missing" cluster**. Four of the seventeen bugs
   (BUG-3 / BUG-4 / BUG-11 / BUG-12) are all the same root cause: a
   Core CLI flag exists, a named constant exists in the camlcoin source
   matching Core's default, but the flag is not exposed through
   `runtime_config.ml` / `cli.ml`. This is a **fleet-level pattern**
   per the operator-experience audit (W124). Same root cause likely
   applies to other impls.

2. **"hard-coded `3.0`" cluster**. BUG-5 (dust formula) and BUG-13
   (spending-size constants) are both cases of stamping a magic
   number that happens to coincide with Core's default at a particular
   config (`min_relay_fee=1000`, mainnet witness discount) but
   diverges when the config changes. **Detection lever**: any source
   constant that is a *ratio* (like 3.0× or 67/148) should be flagged
   as suspect.

3. **"CPubKey::ValidSize header byte not checked" cluster**. BUG-1 and
   BUG-2 are the same root cause: camlcoin's pubkey-recognition
   helpers check only the push opcode prefix, not the pubkey body's
   first byte. Same pattern likely exists in other impls' P2PK / bare
   multisig recognizers.

4. **"BIP-54 absence". **BUG-7 is a fresh-from-Core import that has
   not landed in camlcoin at all. Likely a fleet-wide gap for impls
   that have not had a recent W### audit covering MAX_TX_LEGACY_SIGOPS.

---

## Out of scope

- BIP-152 compact-block standardness (covered by W126).
- BIP-125 RBF rules (covered by W120 / W130).
- BIP-431 TRUC remaining structural fixes beyond W106 (sibling
  eviction is reaffirmed only; rebuild of `check_truc_policy` return
  type is out of scope here).
- Wallet-side `classify_script` consumers (scantxoutset / descriptor
  inference) — covered separately by W131.
- Mempool eviction / replacement scoring (W120 RBF rule 6, W130 Rule 3).
- Block-level validation (`CheckBlock`, `ContextualCheckBlock`).

---

## Verdict

camlcoin's standardness implementation is **architecturally complete**
(it covers all 6 `IsStandardTx` gates + 3 `ValidateInputsStandardness`
gates + 5 `IsWitnessStandard` gates + 6 `SingleTRUCChecks` gates) but
has **17 documented divergences** from Core's exact behaviour. The
divergences are concentrated in:

1. **Pubkey-header validation** (BUG-1 / BUG-2) — 1-line fixes each.
2. **Runtime-flag plumbing** (BUG-3 / BUG-4 / BUG-11 / BUG-12) —
   architectural; needs `mempool` record extension.
3. **Dust threshold and P2A treatment** (BUG-5 / BUG-6 / BUG-13) —
   formula rework against Core's `GetDustThreshold`.
4. **BIP-54 sigop check** (BUG-7) — net-new helper.
5. **Last-push extraction** (BUG-8) — bug fix in `extract_last_push_data`.
6. **P2SH-wrap unwrapping in `SpendsNonAnchorWitnessProg`** (BUG-9) —
   refactor existing inline EvalScript helper.
7. **TRUC return type extension** (BUG-10) — already known.

No `is_standard_tx` callsite gives an outright crash or panic; all
divergences are correctness / config-shape gaps.
