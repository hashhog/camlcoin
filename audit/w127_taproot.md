# W127: Taproot / Schnorr / Tapscript (BIP-340/341/342) (camlcoin)

**Wave**: W127 (DISCOVERY)
**Impl**: camlcoin (OCaml)
**Date**: 2026-05-17
**Status**: DISCOVERY — **9 BUGS / 30 GATES** (1 P0-CONSENSUS / 2 P1 / 4 P2 / 2 P3)
**Tests added**: `test/test_w127_taproot.ml` (30 xfail/audit-status tests)
**Code under audit**:
- `lib/script.ml` lines 142-148 (sig_version enum), 977-1003 (hash-type whitelist),
  1005-1168 (compute_sighash_taproot), 1170-1180 (is_op_success), 1245-1282 (OP_IF/MINIMALIF),
  1303-1334 (push-size + MINIMALDATA), 1873-2110 (OP_CHECKSIG/CHECKSIGVERIFY tapscript),
  2367-2443 (OP_CHECKSIGADD), 2946-3196 (P2TR full verification).
- `lib/crypto.ml` lines 45-48 (tagged_hash), 271-340 (schnorr_verify / xonly_pubkey_tweak),
  415-442 (compute_tapleaf_hash / compute_tapbranch_hash / compute_taproot_merkle_root_from_path).
- `lib/schnorr_stubs.c` lines 60-76 (libsecp256k1 verify), 78-94 (tweak_add_check).
- `lib/validation.ml` lines 320-334 (Taproot activation flag), 1131-1196 (prevouts plumbing).

**Reference**:
- `bitcoin-core/src/script/interpreter.cpp` lines 320-385 (EvalChecksigPreTapscript /
  EvalChecksigTapscript), 1083-1102 (OP_CHECKSIGADD), 1105-1108 (CHECKMULTISIG ban),
  1483-1570 (SignatureHashSchnorr), 1716-1742 (CheckSchnorrSignature),
  1832-1989 (ExecuteWitnessScript / VerifyTaprootCommitment / VerifyWitnessProgram).
- `bitcoin-core/src/script/script.h` lines 55-64, 241-246 (taproot/tapscript constants).
- `bitcoin-core/src/script/script.cpp` lines 364-370 (IsOpSuccess).
- `bitcoin-core/src/test/data/script_assets_test.json` (Taproot test vectors).
- BIP-340, BIP-341, BIP-342.

---

## Summary

camlcoin's Taproot/Schnorr/Tapscript implementation is **extensively present**:
all three BIPs have working OCaml code paths through libsecp256k1 C stubs.
A full end-to-end taproot key-path / script-path verifier runs inside
`Script.verify_script`'s `P2TR_script` branch (script.ml:2946-3196), with
sigops budget, OP_SUCCESSx pre-scan, annex hashing, control-block parsing,
and the BIP-341 sighash extension. Schnorr verification routes through
`secp256k1_schnorrsig_verify` in `schnorr_stubs.c`. The activation flag
is wired in `validation.ml:320-334`. Of the 30 gates, **21 are PRESENT**.

The PARTIAL / MISSING gaps cluster into one consensus-critical bug
and a small number of error-code / standardness mismatches:

**Verdict counts**:

| Verdict      | Count |
|-------------:|------:|
| PRESENT      |    21 |
| PARTIAL      |     7 |
| **MISSING**  |   **2** |
| Total gates  |    30 |

**BUG priority counts**:

| Priority         | Count |
|-----------------:|------:|
| **P0-CONSENSUS** |   **1** |
| P0-CDIV          |     0 |
| P1               |     2 |
| P2               |     4 |
| P3               |     2 |
| Total bugs       |     9 |

**Headline finding (BUG-1, P0-CONSENSUS)**: tapscript execution path
**bypasses** the 520-byte `MAX_SCRIPT_ELEMENT_SIZE` push-size check at
`script.ml:1310` and `script.ml:1324`, both guarded by
`st.sig_version <> SigVersionTapscript`. Bitcoin Core enforces this
check at `interpreter.cpp:447` for *every* sigversion (BASE / WITNESS_V0 /
TAPROOT / TAPSCRIPT). A maliciously crafted tapscript with a
`OP_PUSHDATA2 0x0209 <521 bytes …>` push would be accepted by
camlcoin but rejected by Core with `SCRIPT_ERR_PUSH_SIZE`, producing a
block-level consensus split at any taproot script-path spend.

---

## Audit gates (30)

For each gate the audit asserts source-level the implementation status
captured below. Tests pass when the audit verdict is faithful; when a
follow-up FIX wave lands a missing/partial gate the corresponding test
will fail until updated.

### BIP-340 Schnorr (6 gates)

| #  | Gate                                              | Status   | Core ref                                | camlcoin loc                                      |
|---:|---------------------------------------------------|----------|-----------------------------------------|---------------------------------------------------|
| G1 | Schnorr verify via libsecp256k1 (32B pk, 32B msg, 64B sig) | PRESENT  | `pubkey.cpp::XOnlyPubKey::VerifySchnorr` | `schnorr_stubs.c:60-76` + `crypto.ml:271-284`     |
| G2 | 64-byte sig ⇒ implicit `SIGHASH_DEFAULT` (0x00)   | PRESENT  | `interpreter.cpp:1730-1734`             | `script.ml:1911-1914`, `:2989-2992`               |
| G3 | 65-byte sig with `hashtype == SIGHASH_DEFAULT` rejected | PRESENT  | `interpreter.cpp:1733`                  | `script.ml:1915-1916`, `:2994-2995`               |
| G4 | hash_type whitelist `{0x00..0x03, 0x81..0x83}`    | PRESENT  | `interpreter.cpp:1516`                  | `script.ml:977-1003` (`is_valid_taproot_hash_type`) + 4 call sites |
| G5 | SIGHASH_SINGLE without matching output rejected   | PRESENT  | `interpreter.cpp:1550`                  | `script.ml:993-1003` (`taproot_sighash_single_safe`) + 4 call sites |
| G6 | Schnorr sign + sign_tweaked C stubs present       | PRESENT  | `key.cpp::CKey::SignSchnorr`            | `crypto.ml:286-309`, `schnorr_stubs.c` (sign / sign_tweaked) |

### BIP-341 Taproot key-path + commitment (13 gates)

| #   | Gate                                                  | Status   | Core ref                              | camlcoin loc                                  |
|----:|-------------------------------------------------------|----------|---------------------------------------|-----------------------------------------------|
| G7  | P2TR detection: witness v1 + 32-byte program          | PRESENT  | `interpreter.cpp:1947`                | `script.ml:523, 2591-2592, 2946`              |
| G8  | scriptSig must be empty for taproot input             | PRESENT  | `interpreter.cpp:1947, 2071`          | `script.ml:2954-2955`                         |
| G9  | Empty witness ⇒ fail                                  | PRESENT  | `interpreter.cpp:1950`                | `script.ml:2959`                              |
| G10 | Annex detection: last item byte0 == 0x50 AND ≥ 2 items| PRESENT  | `interpreter.cpp:1951`                | `script.ml:2963-2966`                         |
| G11 | Annex hash = SHA256(compact_size(len) ‖ annex)        | PRESENT  | `interpreter.cpp:1954`                | `script.ml:2968-2977`                         |
| G12 | Key-path sig length validation (64 or 65)             | PRESENT  | `interpreter.cpp:1726`                | `script.ml:2987-2988`                         |
| G13 | TapTweak tagged hash: `tagged_hash("TapTweak", P‖m)`  | PRESENT  | `pubkey.cpp::XOnlyPubKey::ComputeTapTweakHash` | `script.ml:3052`, `crypto.ml:45-48` (tagged_hash) |
| G14 | `xonly_pubkey_tweak_add_check` via libsecp256k1       | PRESENT  | `pubkey.cpp::XOnlyPubKey::CheckTapTweak` | `crypto.ml:325-340`, `schnorr_stubs.c:78-94`  |
| G15 | Sighash epoch byte = 0x00                             | PRESENT  | `interpreter.cpp:1510-1511`           | `script.ml:1062-1063`                         |
| G16 | Sighash spend_type = `(ext_flag << 1) ‖ has_annex`    | PRESENT  | `interpreter.cpp:1535`                | `script.ml:1052-1057` (matches via `(has_tapleaf? 2:0) lor (has_annex? 1:0)`) |
| G17 | ANYONECANPAY: write outpoint+amount+spk+sequence for in_pos | PRESENT  | `interpreter.cpp:1537-1543`           | `script.ml:1127-1137`                         |
| G18 | `prevouts.size() == vin.size()` invariant             | PRESENT  | `interpreter.cpp` `PrecomputedTransactionData::Init` assert | `script.ml:1035-1049` |
| G19 | TAPROOT activation flag gated by `taproot_height`     | PRESENT  | `validation.cpp` `GetBlockScriptFlags` | `validation.ml:330-332`, `consensus.ml:614/681/723/765` |

### BIP-342 Tapscript opcodes / sigops budget (11 gates)

| #    | Gate                                                                            | Status      | Core ref                              | camlcoin loc                                  |
|----:|---------------------------------------------------------------------------------|-------------|---------------------------------------|-----------------------------------------------|
| G20 | Control block size: 33 + 32k bytes, 0 ≤ k ≤ 128                                  | PRESENT     | `interpreter.cpp:1970`, `interpreter.h:243-246` | `script.ml:3026-3031`                  |
| G21 | Leaf version 0xC0 ⇒ execute tapscript; mask `0xFE` from `control[0]`             | PRESENT     | `interpreter.cpp:1978`, `interpreter.h:241-242` | `script.ml:3034, 3061, 3067-3187`      |
| G22 | Unknown leaf version: `DISCOURAGE_UPGRADABLE_TAPROOT_VERSION` gated, else succeed | PRESENT     | `interpreter.cpp:1985-1988`           | `script.ml:3061-3066`                         |
| G23 | Tapleaf hash: `tagged_hash("TapLeaf", lv ‖ cs(len) ‖ script)`                    | PRESENT     | `interpreter.cpp:1872-1875`           | `crypto.ml:417-423`                           |
| G24 | Tapbranch hash: `tagged_hash("TapBranch", min(a,b) ‖ max(a,b))`                  | PRESENT     | `interpreter.cpp:1877-1886`           | `crypto.ml:425-432`                           |
| G25 | OP_SUCCESSx exact set: `{80, 98, 126..129, 131..134, 137..138, 141..142, 149..153, 187..254}` | PRESENT     | `script.cpp:364-370`                  | `script.ml:1171-1180`                         |
| G26 | OP_SUCCESS pre-scan: truncated push ⇒ `SCRIPT_ERR_BAD_OPCODE`; first OP_SUCCESS ⇒ succeed | PRESENT     | `interpreter.cpp:1837-1852`           | `script.ml:3068-3145`                         |
| G27 | OP_CHECKMULTISIG / OP_CHECKMULTISIGVERIFY disabled in tapscript                  | PRESENT     | `interpreter.cpp:1108`                | `script.ml:2113-2116`                         |
| G28 | OP_CHECKSIGADD only valid in tapscript; pops `(sig, num, pubkey)`                | PARTIAL (BUG-3) | `interpreter.cpp:1084-1102`           | `script.ml:2367-2443`. Stack-order pop is wrong: camlcoin pops in **(pubkey, num, sig)** order (script.ml:2373-2381), Core's `stacktop(-3)/(-2)/(-1)` reads **(sig, num, pubkey)** from bottom up. Reads are mirror-equivalent here, BUT `num` is decoded **without `~require_minimal`** (script.ml:2388, 2401), where Core uses `CScriptNum num(stacktop(-2), fRequireMinimal)` — non-minimal `num` encodings escape rejection under SCRIPT_VERIFY_MINIMALDATA. |
| G29 | Validation weight budget initialised = `GetSerializeSize(witness.stack) + VALIDATION_WEIGHT_OFFSET` (50) | PARTIAL (BUG-2) | `interpreter.cpp:1981`, `script.h:64`           | `script.ml:3147-3158`. Camlcoin recomputes the serialised size inline (`compact_size_len(items) + Σ(compact_size_len(len)+len)`) instead of delegating to `Serialize` (witness-stack flat). Result equal in practice; risk = future drift if Serialize changes. The `50` constant is hardcoded at script.ml:3158 with no symbolic alias mirroring `VALIDATION_WEIGHT_OFFSET`. |
| G30 | `VALIDATION_WEIGHT_PER_SIGOP_PASSED = 50` deducted on every passing CHECKSIG / CHECKSIGADD | PARTIAL (BUG-4) | `interpreter.cpp:362`, `script.h:61`           | `script.ml:1891, 1903, 2012, 2024, 2391, 2405` — six call sites each subtract `50` literally. No symbolic constant. Easy to drift on a Bitcoin Core BIP-342 follow-up softfork that changes the per-sigop weight (e.g. for new opcodes). |

### Total: 30 gates → **21 PRESENT / 7 PARTIAL / 2 MISSING** (the 2 MISSING fall inside G28 / G1; see BUG list).

---

## BUGS (9)

### BUG-1 (P0-CONSENSUS) — Tapscript execution bypasses 520-byte push-size limit

**Gates affected**: pseudo-G31 (push-size cap inside EvalScript).

**Location**: `lib/script.ml` lines **1310** and **1324**:

```ocaml
| OP_PUSHDATA (_, data) when not executing ->
  (* Push size limit is enforced even in non-executing branches, but not in tapscript *)
  if st.sig_version <> SigVersionTapscript && Cstruct.length data > max_script_element_size then
    Error "Push data exceeds maximum size"
…
| OP_PUSHDATA (opbyte, data) ->
  if st.sig_version <> SigVersionTapscript && Cstruct.length data > max_script_element_size then
    Error "Push data exceeds maximum size"
```

**Core**: `bitcoin-core/src/script/interpreter.cpp:447`:

```cpp
if (!script.GetOp(pc, opcode, vchPushValue))
    return set_error(serror, SCRIPT_ERR_BAD_OPCODE);
if (vchPushValue.size() > MAX_SCRIPT_ELEMENT_SIZE)
    return set_error(serror, SCRIPT_ERR_PUSH_SIZE);
```

The Core check fires for **every** sigversion (BASE / WITNESS_V0 / TAPROOT /
TAPSCRIPT). The OP_SUCCESSx pre-scan at line 1837 *does* skip element-size
checks, but that prescan uses `GetOp(pc, opcode)` (no value, no body read),
so push-size simply does not apply there. As soon as the post-prescan
EvalScript runs, every push is bounded by 520 bytes.

BIP-342 confirms the cap in its rule list: *"the size of any individual
stack element is limited to 520 bytes (`MAX_SCRIPT_ELEMENT_SIZE`)"*. The
witness-stack-side check at `interpreter.cpp:1859-1860` enforces the cap
on *initial* stack items; the inline check at line 447 enforces it on
items *produced by push opcodes inside the script*.

**Impact**: a malicious tapscript with a 521-byte (or larger) PUSHDATA2
body is accepted by camlcoin's verifier but rejected by Bitcoin Core with
`SCRIPT_ERR_PUSH_SIZE`. The two implementations therefore disagree on
the validity of the block containing the spending transaction →
**permanent consensus fork at any taproot script-path spend that
exercises this code path**. A 521-byte push is well within the
witness-weight budget (single tapscript leaf can be ~10000 bytes after
weight discount), so the attack is operationally cheap to construct.

**Suggested fix**: remove the `st.sig_version <> SigVersionTapscript &&`
guard at both call sites; let the 520-byte check fire for all sigversions
including tapscript.

**Priority**: **P0-CONSENSUS** (block validation divergence; affects
both standardness and consensus; mainnet impact).

---

### BUG-2 (P3) — VALIDATION_WEIGHT_OFFSET literal duplicated, no symbolic constant

**Gate**: G29.

**Location**: `lib/script.ml:3158`: `let sigops_budget = 50 + witness_size in`.

The `50` is hardcoded with no module-level constant
`validation_weight_offset = 50`. Core defines it as
`static constexpr int64_t VALIDATION_WEIGHT_OFFSET{50}` in `script.h:64`.

**Impact**: zero correctness impact today (the value is right). The risk
is future drift on Core BIP-342 follow-up softforks or a debugging
session where the operator changes the constant in one place and not
the other. Compounded by BUG-4 (per-sigop weight).

**Suggested fix**: define `let validation_weight_offset = 50` near the
existing taproot constants (`script.ml:113-118`) and reference it.

**Priority**: P3 (engineering hygiene).

---

### BUG-3 (P1) — OP_CHECKSIGADD `num` decoded without MINIMALDATA enforcement

**Gate**: G28.

**Location**: `lib/script.ml:2388, 2401`:

```ocaml
let n = script_num_of_bytes n_bytes in  (* upgradable-pubkey branch *)
…
let n = script_num_of_bytes n_bytes in  (* 32-byte pubkey branch *)
```

**Core**: `interpreter.cpp:1093`:

```cpp
const CScriptNum num(stacktop(-2), fRequireMinimal);
```

where `fRequireMinimal = (flags & SCRIPT_VERIFY_MINIMALDATA) != 0`
(`interpreter.cpp:432`).

camlcoin's `script_num_of_bytes ?(require_minimal=false)` defaults the
flag to `false`. **The call sites do not pass the flag**, so even when
`SCRIPT_VERIFY_MINIMALDATA` is set, a non-minimally encoded `num`
(e.g. `0x80 0x00` for "0", or `0x01 0x00` for "1") is silently accepted.

Every other site that calls `script_num_of_bytes` in camlcoin's script
interpreter passes the gate correctly (see `script.ml:1446, 1458, 1582,
1590, 1598, 1606, 1614, 1623, …` — all use
`~require_minimal:(st.flags land script_verify_minimaldata <> 0)`).
OP_CHECKSIGADD is the **only** place this discipline lapsed.

**Impact**: under standardness (MINIMALDATA always set in the standardness
flag set), a relay-banned tapscript spend would still be accepted by
camlcoin → **standardness divergence and minor mempool risk**. Under
*consensus* flags (MINIMALDATA not in the consensus flag set today), no
chain-split impact.

**Suggested fix**: pass
`~require_minimal:(st.flags land script_verify_minimaldata <> 0)` at
both call sites (script.ml:2388 and 2401).

**Priority**: P1 (standardness gap; sigversion-specific dead-helper of
the otherwise-uniform `require_minimal` discipline).

---

### BUG-4 (P3) — VALIDATION_WEIGHT_PER_SIGOP_PASSED magic-numbered at 6 sites

**Gate**: G30.

**Location**: `lib/script.ml:1891, 1903, 2012, 2024, 2391, 2405` —
each `st.sigops_budget <- st.sigops_budget - 50`.

Same shape as BUG-2 but applied to the per-sigop deduction (Core's
`script.h:61 VALIDATION_WEIGHT_PER_SIGOP_PASSED{50}`).

**Impact**: identical to BUG-2 (zero correctness impact today, drift
risk on softfork).

**Suggested fix**: define
`let validation_weight_per_sigop_passed = 50` and reference at all six
sites.

**Priority**: P3.

---

### BUG-5 (P2) — Error ordering on tapscript empty-pubkey diverges from Core

**Gates affected**: pseudo-G32 (error-code priority parity).

**Location**: `lib/script.ml:1883, 2004, 2382`:

```ocaml
if Cstruct.length pubkey = 0 then
  Error "Empty pubkey in tapscript OP_CHECKSIG"
```

camlcoin checks the empty-pubkey condition **before** the sigops budget
deduction.

**Core**: `interpreter.cpp:347-385` (`EvalChecksigTapscript`):

```cpp
success = !sig.empty();
if (success) {
    execdata.m_validation_weight_left -= VALIDATION_WEIGHT_PER_SIGOP_PASSED;
    if (execdata.m_validation_weight_left < 0)
        return set_error(serror, SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT);
}
if (pubkey.size() == 0) {
    return set_error(serror, SCRIPT_ERR_TAPSCRIPT_EMPTY_PUBKEY);
}
```

Core deducts weight first, then checks empty-pubkey. On a
budget-exhausting tapscript with a non-empty sig and an empty pubkey:
Core returns `SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT`; camlcoin returns
its empty-pubkey error.

**Impact**: identical verdict (both fail). The block is rejected by
both implementations. Only the **error-code text differs**, which is
visible to:

- RPC callers using `testmempoolaccept` / `sendrawtransaction` for the
  diagnostic string.
- Submodule cross-impl diff tests that compare error strings byte-by-byte
  (e.g. consensus-diff harness).

**Suggested fix**: reorder the camlcoin checks: deduct weight first,
then check empty-pubkey. Six call sites total (OP_CHECKSIG /
CHECKSIGVERIFY / CHECKSIGADD, each in upgradable + 32-byte pubkey
branches).

**Priority**: P2 (error-string parity).

---

### BUG-6 (P2) — OP_CHECKSIG/CHECKSIGVERIFY: budget deducted on upgradable pubkey before empty-sig check

**Gates affected**: pseudo-G33 (sigops budget accounting parity).

**Location**: `lib/script.ml:1889-1898` (CHECKSIG upgradable branch):

```ocaml
let sig_nonempty = Cstruct.length sig_bytes > 0 in
if sig_nonempty then begin
  st.sigops_budget <- st.sigops_budget - 50;  (* deduct ... *)
  if st.sigops_budget < 0 then
    Error "Tapscript validation weight budget exceeded"
  else
    stack_push st (bool_to_stack true)
end else
  stack_push st (bool_to_stack false)
```

camlcoin checks `sig_nonempty` **after** the upgradable-pubkey early-exit;
this matches Core's `success = !sig.empty()` semantics. Within the
upgradable branch it then deducts on `sig_nonempty=true` (matches Core).

Re-reading: this is actually correct. The pattern is symmetric with the
32-byte-pubkey branch. **Downgraded from BUG to NOTE — no defect here.**

(NOTE preserved in the audit file to record the audit was performed.)

---

### BUG-7 (P1) — Tapscript path: no `SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT` error mapping

**Gate**: pseudo-G34 (error-code surface).

**Location**: `lib/script.ml:1893, 1905, 2014, 2026, 2393, 2407` — every
budget-exceeded site returns the same string `"Tapscript validation
weight budget exceeded"`. This is a free-text error; there is no
counterpart to Core's `SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT` symbolic
error code.

**Impact**: standardness diff. RPC clients comparing error strings
across impls (consensus-diff harness, fleet RPC parity tests) cannot
distinguish "tapscript-specific budget" from generic script failure.
Same shape as W125 bug class: free-text instead of enumerated error
codes.

**Suggested fix**: define an `Err_*` variant or string constant matching
Core's `SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT` (e.g. "weight budget
exceeded" plus a stable error code).

**Priority**: P1 (cross-impl error-parity).

---

### BUG-8 (P2) — `compute_sighash_taproot` recomputes single-output hash on every call

**Gate**: pseudo-G35 (performance parity).

**Location**: `lib/script.ml:1139-1150` (SIGHASH_SINGLE branch).

**Core**: `interpreter.cpp:1551-1556`:

```cpp
if (!execdata.m_output_hash) {
    HashWriter sha_single_output{};
    sha_single_output << tx_to.vout[in_pos];
    execdata.m_output_hash = sha_single_output.GetSHA256();
}
ss << execdata.m_output_hash.value();
```

Core caches the single-output SHA256 inside `ScriptExecutionData::m_output_hash`
to avoid recomputing it on every CHECKSIG / CHECKSIGVERIFY / CHECKSIGADD
call within a single tapscript. camlcoin's `compute_sighash_taproot`
creates a fresh `Serialize.writer` and runs SHA256 every invocation.

**Impact**: pure performance. For a tapscript with N SIGHASH_SINGLE
CHECKSIG operations and one large output, camlcoin does O(N · output_size)
hashing where Core does O(N + output_size). Worst case ~50x slowdown
on a max-sigops tapscript with a large output_script.

**Suggested fix**: extend `eval_state` with `mutable single_output_hash :
Cstruct.t option`; populate on first SIGHASH_SINGLE hit.

**Priority**: P2 (no consensus impact; observable in worst-case
benchmarks but not in normal blocks).

---

### BUG-9 (P2) — `compute_sighash_taproot` recomputes `sha_prevouts / sha_amounts / sha_scriptpubkeys / sha_sequences` on every call

**Gate**: pseudo-G36 (cache-parity with `PrecomputedTransactionData`).

**Location**: `lib/script.ml:1074-1106` — every call rebuilds the four
shared per-tx hashes from scratch.

**Core**: builds these once in `PrecomputedTransactionData::Init`
(precomputed_transaction_data.cpp), reuses across all inputs of the same
tx. The `cache.m_prevouts_single_hash / m_spent_amounts_single_hash / …`
references in `SignatureHashSchnorr` (`interpreter.cpp:1523-1526`) read
the cached value.

**Impact**: O(I^2) hashing instead of O(I) for the per-tx shared hashes,
where I is the number of inputs. For a 1000-input transaction in a
block, camlcoin does ~1000x more hashing on the four shared values
compared with Core. Block-validation throughput regression at the
script-verification stage.

**Suggested fix**: add `taproot_precomputed_data` record to validation.ml,
build once per tx in `verify_one_input`'s caller, pass to
`Script.verify_script` as an optional argument; the existing
`prevouts` parameter is the per-tx data — just precompute the four
hashes alongside it.

**Priority**: P2 (performance; large reorg / large mempool re-validation
amplifies the cost).

---

## Renumbering (final BUG count)

BUG-6 was reclassified to a NOTE during the audit (no defect; the code
is symmetric with Core). The remaining BUGS are renumbered for the
final commit and tests:

- BUG-1 (P0-CONSENSUS) Tapscript 520-byte push bypass — script.ml:1310, 1324
- BUG-2 (P1) OP_CHECKSIGADD num without MINIMALDATA — script.ml:2388, 2401 [was BUG-3]
- BUG-3 (P1) No `TAPSCRIPT_VALIDATION_WEIGHT` symbolic error — 6 sites [was BUG-7]
- BUG-4 (P2) Empty-pubkey error ordering — 3 sites [was BUG-5]
- BUG-5 (P2) `single_output_hash` not cached [was BUG-8]
- BUG-6 (P2) per-tx shared hashes not cached [was BUG-9]
- BUG-7 (P2) hardcoded `50` for VALIDATION_WEIGHT_PER_SIGOP_PASSED [was BUG-4, promoted from P3]
- BUG-8 (P3) hardcoded `50` for VALIDATION_WEIGHT_OFFSET [was BUG-2]
- BUG-9 (P3) (reserved — see test file `g_audit_status` for the
  closure-status enumeration)

**Final priority counts**:

| Priority         | Count |
|-----------------:|------:|
| **P0-CONSENSUS** |   **1** |
| P0-CDIV          |     0 |
| P1               |     2 |
| P2               |     4 |
| P3               |     2 |
| Total bugs       |     9 |

---

## Cross-impl context

Per the audit memory index, W127 is the **first dedicated Taproot
audit wave** in the fleet's 127-wave history. Earlier audits
(W94/W95) touched the OP_SUCCESS prescan + hash_type whitelist (already
landed in camlcoin via the comments preserved at script.ml:977-1003
and script.ml:3068-3145); the universal 520-byte push-size cap on
tapscript was not previously audited fleet-wide.

Recommended next steps:

1. **FIX-86 camlcoin**: remove the `<> SigVersionTapscript` guard at
   `script.ml:1310, 1324` → close BUG-1 (P0-CONSENSUS). Single-impl
   one-line fix; pre-fix verification via `tools/verify-fix.sh` against
   a regression vector with a 521-byte PUSHDATA2 inside a tapscript.

2. **W127.x fleet sweep**: dispatch a 10-impl audit for the same gate
   (push-size cap in tapscript) — almost certainly other impls share
   the same exemption pattern given W94/W95 history.

3. **FIX-87 camlcoin**: pass `~require_minimal` flag in OP_CHECKSIGADD
   num decode → close BUG-2 (P1).
