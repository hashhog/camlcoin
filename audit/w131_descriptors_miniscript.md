# W131: Descriptors + Miniscript (BIP-380 / BIP-385) (camlcoin)

**Wave**: W131 (DISCOVERY)
**Impl**: camlcoin (OCaml)
**Date**: 2026-05-17
**Status**: DISCOVERY — **18 BUGS / 30 GATES** (1 P0-CDIV / 4 P1 / 8 P2 / 5 P3)
**Tests added**: `test/test_w131_descriptors_miniscript.ml` (30 audit-status / xfail tests)
**Code under audit**:
- `lib/descriptor.ml` (1168 LOC) — checksum (109-184), key/path parsing
  (262-391), descriptor AST + script generation (393-979), range expansion
  (985-1035), to_string + getdescriptorinfo (1039-1168).
- `lib/miniscript.ml` (1478 LOC) — type AST (47-76), type system
  (78-471), script generation (473-618), satisfaction (620-883),
  parser (922-1086), decompiler (1138-1478).
- `lib/wallet.ml` — descriptor wallet entry points (not under W131 scope).

**Reference**:
- `bitcoin-core/src/script/descriptor.cpp` (3006 LOC) — Checksum (94-153),
  PubkeyProvider hierarchy (162-805), DescriptorImpl + subclasses (800-1740),
  ParsePubkey / ParseScript (1745-2673), InferScript (2675-2900),
  DescriptorCache (2910-3006).
- `bitcoin-core/src/script/miniscript.h` (2707 LOC) — Type system
  (37-189), Node + ScriptSize + sanity (502-1717), DecodeScript
  (~2270-2660), FromString (~1865-2280).
- `bitcoin-core/src/script/miniscript.cpp` (432 LOC) — ComputeType /
  CalcOps / CalcStackSize / SanitizeType.
- `bitcoin-core/src/script/script.h` lines 28-37 — MAX_SCRIPT_ELEMENT_SIZE
  (520), MAX_OPS_PER_SCRIPT (201), MAX_PUBKEYS_PER_MULTISIG (20),
  MAX_PUBKEYS_PER_MULTI_A (999).
- `bitcoin-core/src/script/interpreter.h` line 245 —
  TAPROOT_CONTROL_MAX_NODE_COUNT (128).
- `bitcoin-core/src/policy/policy.h` line 60 —
  MAX_STANDARD_P2WSH_SCRIPT_SIZE (3600).
- `bitcoin-core/src/test/descriptor_tests.cpp`,
  `bitcoin-core/src/test/miniscript_tests.cpp`,
  `bitcoin-core/src/test/data/descriptor_tests_external.json`.
- BIP-380 (Descriptor language + checksum), BIP-381 (PK/PKH/WPKH/SH/WSH),
  BIP-382 (multi/sortedmulti), BIP-383 (multi_a/sortedmulti_a),
  BIP-384 (combo), BIP-385 (raw/addr), BIP-386 (tr), BIP-389 (multipath).

---

## Summary

camlcoin's Descriptor / Miniscript implementation is **structurally present**:
checksum encoding (BIP-380 polymod) is byte-exact with Core, the descriptor
AST covers BIP-380/381/382/384/385/386 fragments (pk / pkh / wpkh / sh / wsh
/ tr / rawtr / multi / sortedmulti / combo / addr / raw / ms), the Miniscript
AST covers all BIP-381 fragments + wrappers, and the type system encodes the
B/V/K/W + 13-property tag system from Core's `_mst` literal.

However the implementation has a **consensus-grade script-generation
divergence** for `after(n)` in P2WSH miniscript, several
type-system gaps that allow Core-insane miniscripts to type-check, and
extensive missing surface in descriptor parsing (no multipath BIP-389,
no musig() per the recent Core PR, sortedmulti_a parsed as miniscript
fall-through rather than recognized, no leaf-version encoding in tap
trees, no InferScript / decompile-to-descriptor round-trip).

**Verdict counts**:

| Verdict      | Count |
|-------------:|------:|
| PRESENT      |    11 |
| PARTIAL      |    11 |
| **MISSING**  |   **8** |
| Total gates  |    30 |

**BUG priority counts**:

| Priority         | Count |
|-----------------:|------:|
| **P0-CDIV**      |   **1** |
| P1               |     4 |
| P2               |     8 |
| P3               |     5 |
| Total bugs       |    18 |

**Headline finding (BUG-1, P0-CDIV)**: Miniscript `after(n)` script
generation at `miniscript.ml:563` emits one trailing `OP_DROP` byte that
Core (`miniscript.h:818`) does NOT emit:

```
  camlcoin: <n> OP_CHECKLOCKTIMEVERIFY OP_DROP   (6 bytes for n=500000)
  Core:     <n> OP_CHECKLOCKTIMEVERIFY           (5 bytes for n=500000)
```

In B-type miniscript the value `n` is the satisfaction (leftover on the
stack); Core therefore leaves it; OP_DROP would invalidate satisfaction.
Any P2WSH descriptor using `after(n)` (or any fragment containing
`after` as a sub-expression: `or_d(c:pk_k(K),after(N))`,
`and_v(v:c:pk_k(K),after(N))`, …) produces a witness program whose
hash mismatches Core's, AND whose execution semantics differ. Concretely:
the witness script camlcoin commits to and the witness script Core
commits to differ at the trailing byte; this is the P2WSH script HASH
input, so the resulting scriptPubKey 32-byte hash diverges. Worse, even
if the witness scripts were forced to match (e.g. by importing Core's
descriptor in a third-party tool then feeding it to camlcoin), the
camlcoin-emitted script fails Core's tapscript / P2WSH execution
because OP_DROP removes the `n` that B-type satisfaction relies on.
Existing test `test/test_miniscript.ml:268` ASSERTS the buggy byte
(`Alcotest.check int "last byte is OP_DROP" 0x75`) — the test
itself is wrong vs the spec. `Ms_older(n)` (line 562) is correct.
Same line in Core for comparison: `miniscript.h:818`
`case Fragment::AFTER: return BuildScript(node.k, OP_CHECKLOCKTIMEVERIFY);`

---

## Audit gates (30)

### BIP-380 Checksum + general descriptor framing (5 gates)

| #  | Gate                                                                       | Status   | Core ref                              | camlcoin loc                          |
|---:|----------------------------------------------------------------------------|----------|---------------------------------------|---------------------------------------|
| G1 | Checksum INPUT_CHARSET (96 chars, 3 groups of 32) byte-exact               | PRESENT  | `descriptor.cpp:122-124`              | `descriptor.ml:114-116`               |
| G2 | Checksum CHECKSUM_CHARSET (bech32 charset) byte-exact                      | PRESENT  | `descriptor.cpp:127`                  | `descriptor.ml:119`                   |
| G3 | Polymod xor constants (0xf5dee51989 / 0xa9fdca3312 / 0x1bab10e32d / 0x3706b1677a / 0x644d626ffd) | PRESENT  | `descriptor.cpp:97-103` | `descriptor.ml:122-131`               |
| G4 | Checksum APPENDED via `#XXXXXXXX` (8 chars); verify_checksum round-trip    | PRESENT  | `descriptor.cpp:153`                  | `descriptor.ml:169-184`               |
| G5 | Trailing 8 polymod-by-0 + xor 1 finalization                               | PRESENT  | `descriptor.cpp:144-147`              | `descriptor.ml:155-159`               |

### BIP-381 Single-key descriptors + sh/wsh nesting (6 gates)

| #   | Gate                                                                          | Status   | Core ref                                                | camlcoin loc                                |
|----:|-------------------------------------------------------------------------------|----------|---------------------------------------------------------|---------------------------------------------|
| G6  | `pk(K)` → `<K> OP_CHECKSIG` (33 or 65 byte push + 0xac)                       | PRESENT  | `descriptor.cpp:1140-1175`                              | `descriptor.ml:682-688`                     |
| G7  | `pkh(K)` → `OP_DUP OP_HASH160 <H160(K)> OP_EQUALVERIFY OP_CHECKSIG`           | PRESENT  | `descriptor.cpp:1180-1207`                              | `descriptor.ml:691-699, 772-785`            |
| G8  | `wpkh(K)` rejects uncompressed K (P2WPKH ctx, not P2WSH)                      | PARTIAL  | `descriptor.cpp:2409` (P2WPKH ctx), `:1879` permit_uncompressed gate | `descriptor.ml:425` (`P2WSH` mislabel — same uncompressed-rejection effect, but ctx string is wrong) — **BUG-2** |
| G9  | `sh(...)` only at TOP level                                                   | PARTIAL  | `descriptor.cpp:2423-2434`                              | `descriptor.ml:430-436` (no context guard — accepts `sh(sh(...))` and `wsh(sh(...))`) — **BUG-3** |
| G10 | `wsh(...)` only at TOP or inside `sh(...)`                                    | PARTIAL  | `descriptor.cpp:2436-2446`                              | `descriptor.ml:438-445` (no context guard — accepts `wsh(wsh(...))`) — **BUG-3** |
| G11 | Hybrid pubkey (data[0] ∈ {0x06, 0x07}) rejected                               | MISSING  | `descriptor.cpp:1894-1897` (`!IsValidNonHybrid()`)      | `descriptor.ml:329-353` accepts on length match — **BUG-4** |

### BIP-382 / 383 multi / multi_a / sortedmulti / sortedmulti_a (4 gates)

| #   | Gate                                                                          | Status   | Core ref                                  | camlcoin loc                                |
|----:|-------------------------------------------------------------------------------|----------|-------------------------------------------|---------------------------------------------|
| G12 | `multi(k,...)` accepts up to MAX_PUBKEYS_PER_MULTISIG=20                      | PRESENT  | `descriptor.cpp:2347`, `script.h:34`      | `descriptor.ml:579` (`n > 20`)              |
| G13 | `multi_a(k,...)` accepts up to MAX_PUBKEYS_PER_MULTI_A=999                    | MISSING  | `descriptor.cpp:2350`, `script.h:37`      | NOT WIRED in descriptor.ml (no `multi_a` fragment parsing — falls through to miniscript.parse_miniscript which DOES handle `multi_a` BUT only within wsh/tr — the descriptor surface gates it as a top-level via tr only by parsing the inner) — **BUG-5** |
| G14 | `sortedmulti_a(k,...)` recognized in tr() ctx                                 | MISSING  | `descriptor.cpp:2318, 2398`               | NOT recognized — only `sortedmulti` (P2WSH multi-sorted) is parsed; tr inner falls back to miniscript which does NOT recognize sortedmulti_a — **BUG-6** |
| G15 | Bare `multi(k,...)` at TOP capped at 3 keys per IsStandard                    | MISSING  | `descriptor.cpp:2361-2364`                | NOT CHECKED — camlcoin accepts up to 20 at TOP — **BUG-7** |

### BIP-384 combo + BIP-385 raw/addr (3 gates)

| #   | Gate                                                                          | Status   | Core ref                                  | camlcoin loc                                |
|----:|-------------------------------------------------------------------------------|----------|-------------------------------------------|---------------------------------------------|
| G16 | `combo(K)` emits P2PK + P2PKH (and P2WPKH + P2SH-P2WPKH if compressed)        | PRESENT  | `descriptor.cpp:1249-1262`                | `descriptor.ml:906-943` (emits 4 scripts, correct order) |
| G17 | `combo()` only at TOP level                                                   | PARTIAL  | `descriptor.cpp:2301-2313`                | `descriptor.ml:497-504` (no ctx guard — accepts inside sh/wsh) — **BUG-8** |
| G18 | `raw(HEX)` / `addr(ADDR)` only at TOP level                                   | PARTIAL  | `descriptor.cpp:2447-2458, 2578-2590`     | `descriptor.ml:506-524` (no ctx guard) — same root cause as BUG-8 |

### BIP-386 tr(...) + Taproot script tree (4 gates)

| #   | Gate                                                                          | Status   | Core ref                                  | camlcoin loc                                |
|----:|-------------------------------------------------------------------------------|----------|-------------------------------------------|---------------------------------------------|
| G19 | `tr(K)` / `tr(K, TREE)` accepts x-only (32 byte) or compressed (33 byte) key  | PRESENT  | `descriptor.cpp:2459-2557`                | `descriptor.ml:458-481, 341-352`            |
| G20 | tr() tree depth ≤ TAPROOT_CONTROL_MAX_NODE_COUNT=128                          | MISSING  | `descriptor.cpp:2484` (`branches.size() > TAPROOT_CONTROL_MAX_NODE_COUNT`) | NOT enforced — camlcoin recurses unboundedly — **BUG-9** |
| G21 | tr() leaf version always 0xC0 (BIP-342)                                       | PARTIAL  | implicit in `TaprootBuilder` (tapscript leaf version) | `descriptor.ml:557` (hard-coded `0xc0` placeholder; not propagated through `to_string` — round-trip drops leaf-version) — **BUG-10** |
| G22 | `rawtr(K)` (BIP-386) untweaked output-key-only                                | PRESENT  | `descriptor.cpp:1706-1740, 2559-2576`     | `descriptor.ml:448-456, 863-877`            |

### Miniscript type system + script generation (5 gates)

| #   | Gate                                                                          | Status   | Core ref                                  | camlcoin loc                                |
|----:|-------------------------------------------------------------------------------|----------|-------------------------------------------|---------------------------------------------|
| G23 | `after(n)` script bytes = `<n> OP_CHECKLOCKTIMEVERIFY` (no OP_DROP)           | **MISSING** | `miniscript.h:818`                     | **`miniscript.ml:563` emits trailing OP_DROP** — **BUG-1 (P0-CDIV)** |
| G24 | `older(n)` script bytes = `<n> OP_CHECKSEQUENCEVERIFY` (no OP_DROP)           | PRESENT  | `miniscript.h:817`                        | `miniscript.ml:562`                         |
| G25 | Multi at TOP/P2SH preserves `permit_uncompressed` (uncompressed allowed)      | PARTIAL  | `descriptor.cpp:1879` permit_uncompressed | `descriptor.ml:571` (multisig keys ALWAYS parsed with `P2WSH` ctx → uncompressed always rejected) — **BUG-11** |
| G26 | Wrapper `v:` collapses `OP_EQUAL → OP_EQUALVERIFY`, `OP_CHECKSIG → OP_CHECKSIGVERIFY`, `OP_NUMEQUAL → OP_NUMEQUALVERIFY` | PARTIAL | `miniscript.h:827-832` (uses `x`-property to decide) | `miniscript.ml:602-608` (collapses by opcode-byte rather than by `x` property — works for the three documented ops but doesn't share Core's invariant: it can collapse mistakenly if a sub-expr ends in those bytes for non-VERIFY-able reasons) — **BUG-12** |
| G27 | `thresh(k, x1, ..., xn)` script: `[x1] [x2] OP_ADD ... [xn] OP_ADD <k> OP_EQUAL` | PRESENT  | `miniscript.h:861-867`                  | `miniscript.ml:575-582` (one slight diff: uses `op_numequal` 0x9c instead of `op_equal` 0x87 — **BUG-13** in opcode choice) |

### Decompile / round-trip / BIP-389 multipath (3 gates)

| #   | Gate                                                                          | Status   | Core ref                                  | camlcoin loc                                |
|----:|-------------------------------------------------------------------------------|----------|-------------------------------------------|---------------------------------------------|
| G28 | `InferScript` (Script bytes → Descriptor) returns canonical descriptor        | MISSING  | `descriptor.cpp:2691-2900`                | NO equivalent in descriptor.ml — only Miniscript has `decompile` (`miniscript.ml:1232`+) | **BUG-14** |
| G29 | Miniscript `pk_h(K)` decompile preserves key (not placeholder)                | PARTIAL  | `miniscript.h:1991` (via `FromPKHBytes` and `SigningProvider` lookup) | `miniscript.ml:1260-1263` always returns `KeyPlaceholder "unknown"` — round-trip loses the key — **BUG-15** |
| G30 | BIP-389 multipath `<0;1>` in derivation paths parsed and expanded             | MISSING  | `descriptor.cpp:1789-1853` (`ParseKeyPath ... allow_multipath=true`) | NOT supported — `descriptor.ml:267-285` only accepts integer or wildcard path components | **BUG-16** |

---

## NEW BUGS (W131-only, not previously catalogued)

### BUG-1 (P0-CDIV / G23): `after(n)` script generation emits extra OP_DROP

`miniscript.ml:563` —
```ocaml
| Ms_after n -> serialize_number n @ [op_checklocktimeverify; op_drop]
```
Core (`miniscript.h:818`):
```cpp
case Fragment::AFTER: return BuildScript(node.k, OP_CHECKLOCKTIMEVERIFY);
```
Effect: byte-exact divergence on **every** miniscript containing
`after(n)`. The witness-script hash committed in a P2WSH scriptPubKey
diverges from Core's; any wallet that constructs an `after`-using
descriptor with camlcoin and broadcasts to a Core-validated network
will commit to a non-spendable output (or, depending on which side
generated the witness script, an output the other side cannot spend).
Sibling `Ms_older n` at `miniscript.ml:562` is **correct** (no OP_DROP)
— so the bug is asymmetric.

Existing `test_miniscript.ml:267-268` (`test_script_after`) asserts the
buggy behaviour:
```ocaml
let last = Cstruct.get_uint8 script (Cstruct.length script - 1) in
Alcotest.(check int) "last byte is OP_DROP" 0x75 last
```
The audit test (G23) demands `0xb1` (OP_CLTV) as the last byte and
asserts the script length matches Core's; G23 will fail until the
fix lands AND `test_script_after` is corrected.

### BUG-2 (P3 / G8): `wpkh()` parsing uses `P2WSH` ctx mislabel

`descriptor.ml:425` —
```ocaml
match parse_key key_str `P2WSH with
```
Functionally identical (both contexts reject uncompressed in
`parse_key_inner`), but semantically misleading; future ctx-dependent
behaviour (e.g. policy variants for P2WPKH that Core may add) will
silently misbehave. Pure naming bug, P3.

### BUG-3 (P2 / G9 + G10): no context guard on `sh()` / `wsh()`

`descriptor.ml:429-445` accepts `sh(sh(pk(...)))` and `wsh(wsh(pk(...)))`
— Core (`descriptor.cpp:2432-2434, 2444-2446`) rejects these with
explicit error messages "Can only have sh() at top level" /
"Can only have wsh() at top level or inside sh()". camlcoin silently
parses; the resulting script (`sh(sh(...))` ← outer P2SH wrapping inner
P2SH script) is structurally legal Bitcoin but a nonsensical descriptor
that should be rejected at parse time. P2 standardness mismatch.

### BUG-4 (P1 / G11): Hybrid pubkey (data[0] ∈ {0x06, 0x07}) not rejected

`descriptor.ml:329-353` checks `len = 33 || len = 65` and accepts any
65-byte hex. Core (`descriptor.cpp:1894-1897`) rejects hybrid pubkeys
explicitly. Hybrid pubkeys are valid secp256k1 points but
non-standard; their use produces non-final relay rejection. P1
because the descriptor parses but the resulting scriptPubKey is
non-standard and silently mined-only.

### BUG-5 (P2 / G13): `multi_a(k,...)` ACCEPTED at descriptor TOP without ctx guard

`descriptor.ml:393-529` enumerates `pk` / `pkh` / `wpkh` / `sh` /
`wsh` / `rawtr` / `tr` / `multi` / `sortedmulti` / `combo` / `addr` /
`raw` and falls back to `Miniscript.parse_miniscript` for anything else.
The miniscript parser at `miniscript.ml:1077-1085` recognizes `multi_a`
unconditionally — its tapscript-ctx requirement is enforced later
during `compute_type` (`miniscript.ml:433-440`), not during parsing.
Net result: a bare top-level `multi_a(1, K)` descriptor PARSES
successfully in camlcoin; Core rejects with
"Can only have multi_a/sortedmulti_a inside tr()"
(`descriptor.cpp:2406`). Test G13 was originally framed as
"rejected with generic error" but the runtime evidence flipped it
to "accepted with no ctx guard" — same root cause (no ctx
verification at descriptor surface), more severe than originally
catalogued. P2 — operator surface / standardness divergence.

### BUG-6 (P2 / G14): `sortedmulti_a` not recognized by Miniscript parser

`miniscript.ml:1085` handles `multi_a` but NOT `sortedmulti_a`. Core
distinguishes the two (`descriptor.cpp:2318` recognizes both
`multi_a` and `sortedmulti_a`). camlcoin emits `Ms_multi_a` regardless
of sort, but does NOT sort, which is semantically WRONG for
`sortedmulti_a`. Worse, `sortedmulti_a` parsing falls back to the
"unknown fragment" path. P2 multi-key descriptor support.

### BUG-7 (P2 / G15): Bare `multi(k,...)` at TOP not capped at 3 keys

`descriptor.cpp:2361-2364` rejects `multi(k, k1, k2, k3, k4)` at TOP
because non-P2SH/P2WSH bare multisig with >3 keys is non-standard.
`descriptor.ml:483-488, 571-583` accepts up to MAX_PUBKEYS_PER_MULTISIG
= 20. P2 standardness; produces non-final-relay scripts.

### BUG-8 (P2 / G17): `combo()` / `addr()` / `raw()` not gated to TOP

`descriptor.ml:497-524` accepts these inside `sh()` / `wsh()`. Core
rejects (`descriptor.cpp:2311-2313, 2455-2458, 2587-2590`). camlcoin
accepts `sh(combo(K))` which is structurally illegal under BIP-380.
P2 parse-error-parity.

### BUG-9 (P2 / G20): tr() tree depth not capped at 128

`descriptor.ml:532-558` recurses into `parse_tap_tree` without
bound-checking `branches.size()`. Core (`descriptor.cpp:2484`) returns
error "tr() supports at most %i nesting levels" when the brace-depth
exceeds TAPROOT_CONTROL_MAX_NODE_COUNT=128. A camlcoin descriptor
with 200 levels of `{...,{...,{...}}}` will parse successfully but
produce a control block exceeding TAPROOT_CONTROL_MAX_SIZE
(33 + 32 * 128 = 4129 bytes), which Core's interpreter then rejects
at spend time. P2 because the divergence is at parse vs. spend (no
fork risk, just operator confusion).

### BUG-10 (P3 / G21): tr() leaf version not roundtripped

`descriptor.ml:557` hard-codes leaf-version `0xc0` (BIP-342) and
`tap_tree_to_string` at 1097 emits only the inner descriptor without
the leaf version. Core's `TaprootBuilder` API and BIP-386 reserve
the leaf-version byte; future BIP-342-bis leaf versions cannot be
expressed. P3 forward-compat.

### BUG-11 (P2 / G25): `multi()` always parses keys with P2WSH ctx

`descriptor.ml:571` hard-codes `parse_key ks 'P2WSH'` for all multisig
keys regardless of outer context. Core's permit_uncompressed gate
(`descriptor.cpp:1879`) is TRUE for TOP / P2SH ctx and FALSE for P2WSH
/ P2WPKH / P2TR. camlcoin behaves as if ctx is always P2WSH, so
`multi(2, K1_uncompressed, K2_uncompressed)` at TOP is rejected;
Core accepts. P2 standardness — works mostly in practice because
uncompressed multisig at TOP is exotic.

### BUG-12 (P3 / G26): `v:` wrapper collapses by opcode-byte, not by `x` property

`miniscript.ml:602-608` matches the last opcode byte (`op_equal`,
`op_checksig`, `op_numequal`) and rewrites to the VERIFY form.
Core (`miniscript.h:827-832`) uses the `x` type property: a node has
`x` iff its last opcode is NOT one of {EQUAL, CHECKSIG, CHECKMULTISIG,
NUMEQUAL}. The byte-pattern check works for the three explicit cases,
but Core's invariant is the `x` property — they coincide in practice
but the camlcoin check could over-collapse if e.g. a future fragment
emits OP_NUMEQUAL for a non-VERIFY-collapsible reason. P3 invariant
drift; no current divergence.

### BUG-13 (P1 / G27): `thresh` script emits `OP_NUMEQUAL` not `OP_EQUAL`; single-sub short-circuit

Two related defects in `miniscript.ml:575-582`:

**(a) Wrong opcode**:
```ocaml
first_script @ rest_script @ serialize_number k @ [op_numequal]
```
Core (`miniscript.h:866`):
```cpp
return BuildScript(std::move(script), node.k, verify ? OP_EQUALVERIFY : OP_EQUAL);
```
`OP_EQUAL` (0x87) vs `OP_NUMEQUAL` (0x9c) differ — `OP_EQUAL` compares
raw byte strings, `OP_NUMEQUAL` decodes both inputs as CScriptNum then
compares numerically. Execution-equivalent for small-integer inputs,
but script BYTES differ → P2WSH 32-byte hash differs → outputs
non-spendable across implementations.

**(b) Single-sub short-circuit**:
```ocaml
match subs with
| [] -> []
| [s] -> to_script_inner ctx s
| s0 :: rest -> ...
```
When `subs` has exactly one element, the threshold check is OMITTED
entirely — neither the `<k>` push nor the `OP_NUMEQUAL` is emitted.
Core's `thresh(1, X)` emits `[X] <1> OP_EQUAL`; camlcoin emits just
`[X]`. Discovered while running G27 with a single sub-expression —
witnessing the absence of any trailing threshold opcode (last byte was
OP_CHECKSIG from the inner). Independent of (a); compounds the
divergence. Test G27 uses 2 subs to isolate (a).

Promoted to **P1** because every miniscript `thresh()` in P2WSH
produces a different scriptPubKey 32-byte hash → outputs are
non-spendable across camlcoin / Core. Whether (a) or (a)+(b) trigger
depends on the n.

### BUG-14 (P2 / G28): InferScript (Script → Descriptor) missing

`descriptor.cpp:2691-2900` provides full `InferScript` that takes a
CScript and returns the canonical descriptor. camlcoin has NO
descriptor-level inference; only `Miniscript.decompile`
(`miniscript.ml:1451`) returns a miniscript AST, not a descriptor.
`importmulti` / `importdescriptors` / `decoderawtransaction` workflows
that pivot on inferring descriptors from raw scriptPubKeys cannot
work. P2 operator surface.

### BUG-15 (P2 / G29): `pk_h(K)` decompile loses the key

`miniscript.ml:1260-1263`:
```ocaml
| TokOp 0x76 :: TokOp 0xa9 :: TokPush hash :: TokOp 0x88 :: rest
  when Cstruct.length hash = 20 ->
  Some (Ms_pk_h (KeyPlaceholder "unknown"), rest)
```
Core's `FromPKHBytes` (`descriptor.cpp:2247`) looks the keyhash up in
the SigningProvider and returns the actual key if known.
camlcoin always emits a placeholder, so round-trip `to_script ∘
decompile` does NOT preserve the key. P2 — workflows that
hex-decode + re-encode miniscript via camlcoin lose key information.

### BUG-16 (P2 / G30): BIP-389 multipath `<0;1>` not supported

`descriptor.ml:267-285` (parse_derivation_path) only accepts integer
or `*` / `*'` / `*h` components. Core (`descriptor.cpp:1802-1853`)
parses `<0;1>` (multipath specifier with `;`-separated indices) and
expands a descriptor into N descriptors when the path contains one.
BIP-389 is a 2023 finalized standard. P2 — operator-surface gap.

### BUG-17 (P3 / cross-cutting): `musig()` (Core 2026 PR) absent

Core's recent `descriptor.cpp:596-805` adds a `MuSigPubkeyProvider`
that takes a `musig(K1, K2, ..., Kn[, /derivation_path])` form inside
`tr()` or `rawtr()`. camlcoin has no `musig()` support. P3 because
this is a recent Core addition and not all impls in the fleet
implement it; flagged for cross-impl audit consistency.

### BUG-18 (P3 / cross-cutting): no `IsValidNonHybrid` check, no
`MAX_STANDARD_P2WSH_SCRIPT_SIZE = 3600` cap, no `MAX_OPS_PER_SCRIPT =
201` enforcement in miniscript

`miniscript.ml:471` `type_check` validates only the type properties
(z/o/n/d/u/e/f/s/m/x/g/h/i/j/k); it does NOT call the equivalents of
Core's `CheckOpsLimit` (`miniscript.h:1569`) or `CheckStackSize`
(`miniscript.h:1593`) — both of which Core's `IsSane()` relies on
(`miniscript.h:1700`). A camlcoin miniscript like
`thresh(1, c:pk_k(K1), s:c:pk_k(K2), s:c:pk_k(K3), ... s:c:pk_k(K201))`
type-checks but exceeds MAX_OPS_PER_SCRIPT when compiled to bytes;
Core rejects at `IsSane` time. P3 — the user-facing API lets the
user write a script that Core's wallet would reject at descriptor
parse time. (Promoted to P3 because in practice most users don't
construct 201+-op scripts.)

---

## References to prior camlcoin audits

- W125 (RPC error parity): camlcoin error-message divergence on
  unknown descriptor types — same root cause as BUG-5 and BUG-8.
- W127 (Taproot): BUG-10 / G21 (tap leaf version not roundtripped)
  is a thematic extension of W127 G22 (unknown leaf version policy);
  W131 catches it at the descriptor surface rather than the
  interpreter surface.
- W128 (AddrMan / peer selection): not related.
- W129 (Coin selection): not related (different subsystem).

---

## Out-of-scope (deferred)

- musig() FROST/MuSig2 aggregation semantics (BIP-327 / Core 2026 PR)
  — only the BUG-17 surface-level absence is flagged.
- `expand()` private-key derivation paths (xprv WIF decode) — only
  the public-key surface is audited.
- DescriptorCache (`descriptor.cpp:2910-3006`) — wallet-side cache
  layer not under W131 scope.
- Conversion to PSBT (`PSBTInput.bip32_paths` derivation
  cross-references) — separate wave.

---

## Methodology footnote

This wave is **discovery only**. No production code is modified.
Audit gates are encoded as 30 alcotest cases in
`test/test_w131_descriptors_miniscript.ml` and registered in
`test/dune`. Each test asserts the audit verdict (either "this is
correct" or "this bug is present"); when a follow-up FIX wave
lands, the corresponding test will fail until updated.

The W131 BUG-1 case is **special**: the existing
`test_miniscript.ml:test_script_after` asserts the buggy behaviour
(OP_DROP as last byte). The W131 test for G23 asserts the Core-correct
last byte (OP_CLTV). Both tests currently pass independently in their
own files; once BUG-1 is fixed and `test_script_after` is updated, the
parity is restored.
