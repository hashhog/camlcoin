# W144 Script-verify flag mux — camlcoin (OCaml)

Wave: W144 — `SCRIPT_VERIFY_*` flag derivation in `GetBlockScriptFlags`,
application inside `EvalScript` / `VerifyScript`, buried-vs-versionbits
activation, BIP-16 + Taproot `script_flag_exceptions`, and the
consensus-vs-policy split (`MANDATORY_SCRIPT_VERIFY_FLAGS` vs.
`STANDARD_SCRIPT_VERIFY_FLAGS`).

Bitcoin Core references:

- `bitcoin-core/src/script/interpreter.h:47-160` — `script_verify_flags`
  enum, all 23 `SCRIPT_VERIFY_*` bits (`P2SH`, `STRICTENC`, `DERSIG`,
  `LOW_S`, `NULLDUMMY`, `SIGPUSHONLY`, `MINIMALDATA`,
  `DISCOURAGE_UPGRADABLE_NOPS`, `CLEANSTACK`, `CHECKLOCKTIMEVERIFY`,
  `CHECKSEQUENCEVERIFY`, `WITNESS`, `DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM`,
  `MINIMALIF`, `NULLFAIL`, `WITNESS_PUBKEYTYPE`, `CONST_SCRIPTCODE`,
  `TAPROOT`, `DISCOURAGE_UPGRADABLE_TAPROOT_VERSION`,
  `DISCOURAGE_OP_SUCCESS`, `DISCOURAGE_UPGRADABLE_PUBKEYTYPE`).
  Note: the enum positions in Core are *contiguous* (0..21) but camlcoin
  copies the *bit indices* from a legacy bitmask layout — see BUG-3.
- `bitcoin-core/src/validation.cpp:2250-2289` — `GetBlockScriptFlags`:
  starts with `flags = P2SH | WITNESS | TAPROOT`, applies
  `script_flag_exceptions` lookup by block hash, then ORs DERSIG / CLTV
  / CSV / NULLDUMMY based on `DeploymentActiveAt`. (Modern Core has
  these as buried; the version-bits state machine is only consulted for
  active deployments, currently none.)
- `bitcoin-core/src/kernel/chainparams.cpp:85-88` — mainnet exceptions:
  - block `00000000…ac4f9c22` (h≈170060) → `SCRIPT_VERIFY_NONE` (BIP16
    exception)
  - block `00000000…1e395ad` (h≈692,201) → `P2SH | WITNESS` (Taproot
    exception, Taproot disabled)
- `bitcoin-core/src/kernel/chainparams.cpp:210-211` — testnet3 exception
  (h≈21111 / block `0000000000000000…74e02f`) → `SCRIPT_VERIFY_NONE`
  (BIP16 violator on testnet3).
- `bitcoin-core/src/policy/policy.h:99-138` — `MANDATORY_SCRIPT_VERIFY_FLAGS`
  (consensus subset) and `STANDARD_SCRIPT_VERIFY_FLAGS` (policy
  superset). Crucially: `STANDARD` adds `STRICTENC`, `MINIMALDATA`,
  `DISCOURAGE_UPGRADABLE_NOPS`, `CLEANSTACK`, `MINIMALIF`, `NULLFAIL`,
  `LOW_S`, `DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM`, `WITNESS_PUBKEYTYPE`,
  `CONST_SCRIPTCODE`, `DISCOURAGE_UPGRADABLE_TAPROOT_VERSION`,
  `DISCOURAGE_OP_SUCCESS`, `DISCOURAGE_UPGRADABLE_PUBKEYTYPE`.
  `SIGPUSHONLY` is *not* in `STANDARD` (it is enforced separately for
  P2SH at consensus level via `VerifyScript`).
- `bitcoin-core/src/script/interpreter.cpp:522-600` — `EvalScript`
  flag-gated opcodes: CLTV (522), CSV (561), upgradable NOPs (595).
  Critical: when CLTV / CSV are not enabled, the opcode is treated as a
  `break` *without* checking `DISCOURAGE_UPGRADABLE_NOPS`.
- `bitcoin-core/src/script/interpreter.cpp:2002-2121` — `VerifyScript`
  dispatch: `SIGPUSHONLY` gate (2012), P2SH evaluation (2030-2095),
  `CLEANSTACK` assertion that P2SH and WITNESS are both set
  (2103-2104), and the `WITNESS_UNEXPECTED` final guard (2110-2118).

BIPs: BIP-16 (P2SH), BIP-66 (DERSIG), BIP-65 (CLTV), BIP-68/112/113
(CSV), BIP-141 (WITNESS), BIP-143 (segwit sighash), BIP-147
(NULLDUMMY), BIP-341/342 (Taproot/Tapscript), BIP-9 (versionbits
state machine).

## Methodology

1. Read Core refs (above).
2. Enumerate 30 audit gates spanning the 8 behaviours plus adjacent
   surfaces (consensus-vs-policy flag derivation, the four call sites
   of `Consensus.get_block_script_flags`, the fifth call site of
   `Validation.get_script_flags_for_height`, exception block lookup,
   `EvalScript` opcode application, `VerifyScript` dispatch, MINIMALIF
   gating, MINIMALDATA push enforcement, WITNESS final guard).
3. Classify each gate against camlcoin's de-facto surface:
   - `lib/script.ml:115-139` — `script_verify_*` 23 constants
     (consensus-only and extended).
   - `lib/script.ml:2569-3260` — `verify_script` (top-level dispatch)
     and `eval_script` (single-opcode evaluator).
   - `lib/validation.ml:305-334` — `Validation.get_script_flags_for_height`
     (assume_utxo path).
   - `lib/consensus.ml:853-933` — `Consensus.get_block_script_flags`
     (main sync path) + `get_standard_policy_flags` (mempool path) +
     duplicate `script_verify_*` constants (lines 853-865).
   - `lib/consensus.ml:1281-1745` — BIP-9 deployment state machine
     (`get_deployment_state`, `is_deployment_active`, only used by
     Taproot which is also buried by height).
   - `lib/sync.ml:2398-3403, 4278-4449` — four call sites that pass
     `Consensus.get_block_script_flags` to `accept_block` /
     `validate_block`.
   - `lib/assume_utxo.ml:1159` — fifth call site (uses the *other*
     flag-derivation helper, `Validation.get_script_flags_for_height`).
   - `lib/mempool.ml:1878, 2126` — mempool uses both helpers.
4. Catalogue BUGs by severity:
   - **P0-CONSENSUS**: known mainnet/testnet block today (or trivially
     constructible) would diverge between camlcoin and Core.
   - **P0-CDIV**: protocol-correctness divergence (accepts a block
     Core rejects, or rejects one Core accepts) on an
     adversarially-crafted block.
   - **P0-SEC**: exploitable defect (DoS, fund theft, auth bypass).
   - **P1**: feature-correctness gap (right idea, wrong gating /
     ordering / coverage).
   - **P2**: malleability surface / fingerprinting / fairness drift.
   - **P3**: surface / constant / cosmetic drift.

Severity legend mirrors W130 / W131 / W132 / W133 / W134 / W135 /
W136 / W137 / W138 / W139 / W140 / W141 / W142.

## camlcoin de-facto surface

| Concern | Core | camlcoin |
|---------|------|----------|
| `SCRIPT_VERIFY_*` definitions | one canonical enum (`interpreter.h:49-151`) | TWO copies: `script.ml:115-139` (23 flags, all bits) and `consensus.ml:853-865` (13 flags, subset, dropped MINIMALIF/DISCOURAGE_*/CONST_SCRIPTCODE/SIGPUSHONLY/STRICTENC) |
| Mandatory base set | `P2SH \| WITNESS \| TAPROOT` (`validation.cpp:2262`) | starts with `P2SH` *only*; WITNESS and TAPROOT folded in by separate height gates (`consensus.ml:883, 905-911, 913-916`) |
| Exception block lookup | `unordered_map<uint256, flags>` keyed by *block hash* (`validation.cpp:2263`) | hardcoded `height = 170060 && (block_hash = "00…f9c22" \|\| block_hash = "")` AND `network.name = "mainnet"` (`consensus.ml:874-879`) |
| Taproot exception block | block hash `0000…1e395ad` → `P2SH \| WITNESS` only (`kernel/chainparams.cpp:87-88`) | **MISSING** — camlcoin has no Taproot exception |
| Testnet3 exception block | block hash `0000…74e02f` → `SCRIPT_VERIFY_NONE` (`kernel/chainparams.cpp:210-211`) | **MISSING** — `network.name = "mainnet"` gate skips testnet3 exception |
| Default `block_hash` | always passed (no default in Core; uses `block_index.phashBlock`) | optional, defaults to `""`; **all four sync.ml callers omit it** (`sync.ml:2400, 3403, 4279, 4449`); empty-string match triggers exception for *any* block at height 170060 |
| Two flag-derivation helpers | one (`GetBlockScriptFlags`) | two: `Consensus.get_block_script_flags` (sync, mempool consensus, mining) and `Validation.get_script_flags_for_height` (assume_utxo, lacks exception handling) — they DIFFER |
| Standard policy flags | 12 extra bits (`policy.h:119-132`) | 6 extra bits (`consensus.ml:925-931`): missing STRICTENC, DISCOURAGE_UPGRADABLE_NOPS, MINIMALIF, DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, CONST_SCRIPTCODE, DISCOURAGE_UPGRADABLE_TAPROOT_VERSION, DISCOURAGE_OP_SUCCESS, DISCOURAGE_UPGRADABLE_PUBKEYTYPE; *adds* SIGPUSHONLY (which Core does NOT put in STANDARD) |
| CLTV-not-active behaviour | `break` without DISCOURAGE check (`interpreter.cpp:524-527`) | DISCOURAGE_UPGRADABLE_NOPS check fires when CLTV inactive (`script.ml:2268-2274`) |
| CSV-not-active behaviour | `break` without DISCOURAGE check (`interpreter.cpp:563-566`) | DISCOURAGE_UPGRADABLE_NOPS check fires when CSV inactive (`script.ml:2307-2313`) |
| `CLEANSTACK` invariant | `assert(P2SH && WITNESS)` (`interpreter.cpp:2103-2104`) | no assertion; CLEANSTACK can be set without P2SH/WITNESS |
| `WITNESS` invariant | `assert(P2SH)` (`interpreter.cpp:2114`) | no assertion |
| `WITNESS_UNEXPECTED` guard | unconditional tail-check (`interpreter.cpp:2110-2118`) | sprinkled in P2PKH and Nonstandard branches only (already booked W142 BUG-10); P2SH non-witness branch still missing |
| `MINIMALIF` for witness v0 | flag-gated policy only (`interpreter.cpp:464-475`) | only triggers when `script_verify_minimalif` flag set — *but the inline comment claims "unconditionally enforce for witness v0"* (`script.ml:1251-1258`) |

## 30-gate matrix (W144)

### G1-G8: behavioural gates from the wave brief

- **G1: flag derivation per height (`GetBlockScriptFlags`).**
  Core (`validation.cpp:2250-2289`): single canonical helper; takes a
  `CBlockIndex` (hash + height) and chainman; returns bitmask.
  camlcoin: TWO helpers (`Consensus.get_block_script_flags` at
  `consensus.ml:870` and `Validation.get_script_flags_for_height` at
  `validation.ml:305`). The former takes `?block_hash`, height, and
  network; the latter takes only network + height (no hash, no
  exception logic). The assume_utxo background validator calls the
  latter; the main sync path calls the former. They produce *different*
  output for the same height when an exception block is involved.
  **PARTIAL PARITY** on shape; **DIVERGENCE** on existence of two
  helpers. See BUG-1, BUG-2, BUG-12.

- **G2: SCRIPT_VERIFY_P2SH (BIP-16).**
  Core: P2SH is in the base set (`validation.cpp:2262`); the BIP-16
  *enforcement* height was 173,805 historically but mainnet has been
  past that since 2012. Modern Core treats P2SH as *always-on* except
  for the one exception block. camlcoin: in `Consensus.get_block_script_flags`,
  `P2SH` is added for all blocks (line 883); in
  `Validation.get_script_flags_for_height`, `if height >= 1` (line
  309). On regtest with block height 0 (genesis), the latter would
  NOT set P2SH (height 0 < 1) while Core (regtest, BIP16Height = 1)
  would also not set it at height 0 — so this is incidentally OK on
  regtest. But on mainnet there is no height-1 protection: P2SH is on
  for every block except the exception. **PARITY** on enforcement,
  **DIVERGENCE** on assumption. See BUG-1 below for the exception
  block divergence.

- **G3: SCRIPT_VERIFY_DERSIG (BIP-66).**
  Core (`validation.cpp:2269-2271`): `if DeploymentActiveAt(DERSIG) then
  flags |= DERSIG`. Mainnet `BIP66Height = 363,725` (buried). camlcoin
  (`consensus.ml:885-888`): `if height >= network.bip66_height then
  flags lor script_verify_dersig else flags`. Mainnet `bip66_height =
  363725` matches Core. **PARITY**.

- **G4: SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY (BIP-65).**
  Core (`validation.cpp:2273-2276`): `if DeploymentActiveAt(CLTV)
  then flags |= CLTV`. Mainnet `BIP65Height = 388,381`. camlcoin
  (`consensus.ml:890-893`): `if height >= network.bip65_height then
  flags lor script_verify_checklocktimeverify else flags`. Mainnet
  `bip65_height = 388381` matches Core. **PARITY** on activation
  height; **DIVERGENCE** on opcode behaviour when inactive — see
  BUG-4.

- **G5: SCRIPT_VERIFY_CHECKSEQUENCEVERIFY (BIP-112).**
  Core (`validation.cpp:2278-2281`): `if DeploymentActiveAt(CSV) then
  flags |= CSV`. Mainnet `CSVHeight = 419,328`. camlcoin
  (`consensus.ml:895-898`): same shape. Mainnet `csv_height = 419328`
  matches Core. **PARITY** on activation height; **DIVERGENCE** on
  opcode behaviour when inactive — see BUG-4 (CLTV) and BUG-5 (CSV).

- **G6: SCRIPT_VERIFY_WITNESS (BIP-141).**
  Core (`validation.cpp:2262`): WITNESS in base set; off only for
  the BIP16 exception block (which is pre-segwit anyway). camlcoin
  (`consensus.ml:905-911`): added when `height >= segwit_height`.
  Mainnet `segwit_height = 481824` matches Core's `SegwitHeight =
  481824`. **PARITY** on activation height. Core treats WITNESS as
  always-on; camlcoin gates it. The mainnet result is identical for
  heights ≥ 481,824, but for a regtest run started below height
  segwit_height (impossible because regtest segwit_height = 0)
  divergence is possible. **PARITY**.

- **G7: SCRIPT_VERIFY_NULLDUMMY (BIP-147).**
  Core (`validation.cpp:2283-2286`): `if DeploymentActiveAt(SEGWIT)
  then flags |= NULLDUMMY` (NULLDUMMY activated simultaneously with
  SegWit at mainnet h=481,824). camlcoin (`consensus.ml:905-910`):
  `if height >= segwit_height then flags |= WITNESS lor NULLDUMMY`.
  **PARITY** on activation height. Application inside `EvalScript`
  is a single site (`script.ml:2157` inside `OP_CHECKMULTISIG`).
  **PARITY** on application.

- **G8: SCRIPT_VERIFY_TAPROOT (BIP-341/342).**
  Core (`validation.cpp:2262`): TAPROOT in base set, gated only by
  the Taproot exception block. camlcoin (`consensus.ml:913-916`):
  `if height >= network.taproot_height then flags |= TAPROOT`.
  Mainnet `taproot_height = 709632` matches Core's actual activation.
  Pre-709632 / pre-exception scenarios behave identically *except*
  Core does not include the Taproot exception. See BUG-2. **PARITY**
  on activation height; **DIVERGENCE** on exception block.

### G9-G15: derived gates from META questions

- **G9: are flags ACTUALLY CHECKED in EvalScript?**
  All 23 camlcoin `script_verify_*` constants are exported. Grep of
  `script.ml` for `st.flags land script_verify_*` finds 30 callsites.
  Cross-reference: P2SH (verify_script L2669, L2689), WITNESS
  (L2592/L2601/L2630/L2643/L2725/L2851/L2903/L2948/L3213), DERSIG/LOW_S/STRICTENC
  composite (L1949, L2067, L2189), MINIMALDATA (L1326 + many
  arithmetic), SIGPUSHONLY (L2580), CLEANSTACK (L2624, L2659, L2683,
  L2836, L3229), CLTV (L2268), CSV (L2307), DISCOURAGE_UPGRADABLE_NOPS
  (L2270/L2309/L2448), DISCOURAGE_UPGRADABLE_WITNESS (L2596/L2605/L2824),
  MINIMALIF (L1258), NULLFAIL (L2103/L2251), NULLDUMMY (L2157),
  WITNESS_PUBKEYTYPE (L789/L799), CONST_SCRIPTCODE (L1304/L2087/L2177),
  TAPROOT (L2948). **Three flags have NO callsite**:
  `script_verify_discourage_op_success` (`script.ml:137` only),
  `script_verify_discourage_upgradable_taproot_version` (`script.ml:138`
  only), `script_verify_discourage_upgradable_pubkeytype` (`script.ml:139`
  only). See BUG-6.

- **G10: consensus-vs-policy split.**
  Core: `MANDATORY_SCRIPT_VERIFY_FLAGS` = 7 bits (consensus-relevant
  subset); `STANDARD_SCRIPT_VERIFY_FLAGS` = `MANDATORY |` 12 more
  bits. camlcoin: `Consensus.get_block_script_flags` returns up to 6
  bits (P2SH, DERSIG, CLTV, CSV, WITNESS, NULLDUMMY, TAPROOT);
  `Consensus.get_standard_policy_flags` adds 6 more bits. Camlcoin's
  policy set is **half the size** of Core's. See BUG-7.

- **G11: SIGPUSHONLY in policy set.**
  Core `STANDARD_SCRIPT_VERIFY_FLAGS` does *not* include
  `SCRIPT_VERIFY_SIGPUSHONLY` (it is enforced separately for P2SH at
  consensus level inside `VerifyScript` at line 2012 — gated only by
  the SIGPUSHONLY flag itself, which is set by callers only for
  policy-rejection paths). camlcoin (`consensus.ml:927`):
  `extra := !extra lor script_verify_sigpushonly`. Camlcoin's mempool
  therefore rejects non-push scriptSig transactions that Core's
  mempool would relay (modulo other rules). See BUG-8.

- **G12: buried vs versionbits — Taproot.**
  Core: Taproot is *buried* by `consensus.script_flag_exceptions` for
  the exception block (block hash `0000…1e395ad`) and otherwise always
  on in the base flags set; the BIP-9 deployment record is retained
  for `getdeploymentinfo` RPC parity but consensus does not call it.
  camlcoin: BIP-9 state machine (`consensus.ml:1281-1745`) is fully
  implemented including `is_deployment_active`. Validation path uses
  `taproot_height` gate; mining/RPC paths call `get_deployment_state`.
  See BUG-13.

- **G13: buried vs versionbits — DERSIG, CLTV, CSV, SegWit.**
  Core: all four are buried (height-only); the BIP-9 records were
  retired from chainparams. camlcoin: all four buried (height-only)
  through `bip66_height` / `bip65_height` / `csv_height` /
  `segwit_height`. **PARITY**.

- **G14: STANDARD_SCRIPT_VERIFY_FLAGS missing 8 bits.**
  Camlcoin's `get_standard_policy_flags` is missing:
  `STRICTENC` (BIP-62 rule 1), `DISCOURAGE_UPGRADABLE_NOPS`,
  `MINIMALIF`, `DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM`,
  `CONST_SCRIPTCODE`, `DISCOURAGE_UPGRADABLE_TAPROOT_VERSION`,
  `DISCOURAGE_OP_SUCCESS`, `DISCOURAGE_UPGRADABLE_PUBKEYTYPE`. See
  BUG-7.

- **G15: dual flag definitions in different modules.**
  `script.ml:115-139` defines all 23 bits. `consensus.ml:853-865`
  defines a subset of 13 bits with an in-source comment that reads
  *"duplicated from Script to avoid dependency"*. Both copies use the
  same bit indices, but they are not enforced by the type system —
  drift between the two modules is a textbook fleet-pattern hazard
  (re-anchor, divergent re-implementation). See BUG-3.

### G16-G22: opcode-application gates

- **G16: OP_CLTV when CLTV flag NOT set.**
  Core (`interpreter.cpp:522-527`): `if (!(flags &
  SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY)) { break; }` — bare `break`, NO
  DISCOURAGE check. camlcoin (`script.ml:2267-2274`):
  ```ocaml
  if st.flags land script_verify_checklocktimeverify = 0 then begin
    if st.flags land script_verify_discourage_upgradable_nops <> 0 then
      Error "Upgradable NOP used"
    else
      Ok ()
  ```
  See BUG-4.

- **G17: OP_CSV when CSV flag NOT set.**
  Core (`interpreter.cpp:561-566`): bare `break`, NO DISCOURAGE check.
  camlcoin (`script.ml:2306-2313`): DISCOURAGE check fires. See
  BUG-5.

- **G18: NULLDUMMY enforcement site.**
  Core: inside `EvalScript` `OP_CHECKMULTISIG` (`interpreter.cpp` —
  the dummy-element zero-length check). camlcoin (`script.ml:2155-2159`):
  same; dummy element is popped, then if NULLDUMMY flag set and
  `Cstruct.length dummy <> 0`, return error. **PARITY**. NOTE:
  `OP_CHECKMULTISIGVERIFY` and `OP_CHECKMULTISIG` share the same arm
  in camlcoin via `op = OP_CHECKMULTISIGVERIFY -> is_verify = true`,
  so both are covered.

- **G19: WITNESS_PUBKEYTYPE enforcement.**
  Core (`interpreter.cpp:286-296`): in `CheckPubKeyEncoding`, when
  `flags & WITNESS_PUBKEYTYPE` and `sigversion == WITNESS_V0`, reject
  if not compressed. camlcoin (`script.ml:777-805`):
  `check_pubkey_encoding` mirrors. **PARITY**.

- **G20: WITNESS_UNEXPECTED tail-guard.**
  Core: unconditional, after all dispatch (`interpreter.cpp:2110-2118`).
  camlcoin: only in `P2PKH_script` and `Nonstandard` arms
  (`script.ml:2643, 3213`); P2SH non-witness redeem branch
  (`script.ml:2828-2841`) does NOT check witness emptiness. Already
  booked under W142 BUG-W142-10; cited here for cross-reference. See
  BUG-W144-15.

- **G21: SIGPUSHONLY for P2SH (BIP-16 rule).**
  Core (`interpreter.cpp:2031-2034`): when P2SH flag set, `if
  (!scriptSig.IsPushOnly())` → `SCRIPT_ERR_SIG_PUSHONLY`. This is
  *consensus*, not policy. camlcoin (`script.ml:2692-2693`):
  `if not (is_push_only script_sig) then Error "SigPushOnly"`.
  **PARITY**.

- **G22: CLEANSTACK / WITNESS implies P2SH assertion.**
  Core (`interpreter.cpp:2103-2104, 2114`): runtime assertions that
  P2SH is set when CLEANSTACK or WITNESS is requested. Camlcoin: no
  such assertion. A caller could pass `flags = WITNESS` without P2SH
  and observe undefined behaviour (the verify_script witness branch at
  line 2592 happily fires). See BUG-10.

### G23-G30: ecosystem gates

- **G23: assume_utxo path uses a DIFFERENT flag-derivation helper.**
  `assume_utxo.ml:1159`:
  ```ocaml
  let flags = Validation.get_script_flags_for_height ~network next_height in
  ```
  which is the helper at `validation.ml:305-334` (no exception
  handling, no `?block_hash` parameter). The main sync path uses
  `Consensus.get_block_script_flags` which DOES handle the exception
  block. On mainnet, an assume_utxo IBD that passes through height
  170,060 would compute different flags than a sync-from-genesis IBD.
  See BUG-12.

- **G24: mempool uses both helpers.**
  `mempool.ml:1878`: `Consensus.get_standard_policy_flags
  (mp.current_height + 1) mp.network` for script verification.
  `mempool.ml:2126`: `Consensus.get_block_script_flags
  (mp.current_height + 1) mp.network` for BIP-68 sequence locks.
  This is intentional (policy vs consensus split for different
  checks) but underscores the dual-helper hazard. **NO BUG**.

- **G25: sigops uses get_block_script_flags.**
  `validation.ml:1632-1637`: sigops flag derivation uses
  `Consensus.get_block_script_flags`. Same divergence on exception
  block. **PARITY** with Core (Core uses the same `flags` for
  sigops and scripts).

- **G26: BIP-9 deployment vs buried-height drift detector.**
  `consensus.ml:1721-1744`: `check_buried_deployment_consistency`
  cross-checks `network.taproot_height` against
  `mainnet_taproot.min_activation_height`. Returns `Ok` on agreement,
  `Error` on mismatch. **GOOD HYGIENE** — only Taproot is checked
  because only Taproot has both buried + BIP-9 records in camlcoin.
  No bug, but the function is missing a callsite check that it is
  actually invoked at startup; grep finds no production caller. See
  BUG-14.

- **G27: BIP-9 cache is regtest/mainnet/testnet4 only.**
  `consensus.ml:1723-1727`: testnet3 → `None` (no taproot deployment).
  Camlcoin testnet3 still has `taproot_height = 2_032_291`, so the
  height-based path activates Taproot, but `is_deployment_active` for
  testnet3 returns `false` always (the deployment record does not
  exist). RPC `getdeploymentinfo` for testnet3 will report Taproot as
  defined/failed when it is in fact active. See BUG-11.

- **G28: signet missing from network_type.**
  `consensus.ml:271` (and elsewhere): `network_type =
  Mainnet | Testnet3 | Testnet4 | Regtest`. No `Signet` variant.
  Consensus rules differ on signet (BIP-325). Camlcoin cannot run
  signet. See BUG-16.

- **G29: assumevalid forces flags=0.**
  `sync.ml:2398-2400`:
  ```ocaml
  let skip_scripts = is_assume_valid ibd.chain height in
  let validation_flags =
    if skip_scripts then 0
    else Consensus.get_block_script_flags height ibd.chain.network
  in
  ```
  When `skip_scripts` is true (assumevalid range), flags are forced to
  0 and passed downstream. The sig-cache key includes `flags` (see
  `validation.ml:1162`), so cached entries from `flags=0` cannot be
  reused after assumevalid ends. This is correct but is a missed
  optimisation. See BUG-17.

- **G30: dual flag bit-index drift potential.**
  Both `script.ml:115-139` and `consensus.ml:853-865` use `1 lsl 0..20`
  to assign bits. The same bit positions are reused. If a developer
  adds a new flag in `script.ml` (e.g. `script_verify_simplicity = 1
  lsl 21`) but forgets to mirror it to `consensus.ml`, the
  derivation in `Consensus.get_block_script_flags` cannot set the new
  flag. **POTENTIAL DRIFT HAZARD**. See BUG-3.

## Bugs

### BUG-W144-1 (P0-CDIV): BIP-16 exception block falls through on `block_hash = ""`

**File**: `lib/consensus.ml:870-879`
**Core ref**: `bitcoin-core/src/kernel/chainparams.cpp:85-88`, `src/validation.cpp:2263-2266`
**Description**: The exception lookup is `height = 170060 &&
(block_hash = "00…f9c22" || block_hash = "") && network.name =
"mainnet"`. The `block_hash = ""` arm is a fallback for callers that
do not pass a hash. ALL FOUR sync.ml callers (line 2400, 3403, 4279,
4449) and one mempool.ml caller (line 2126) omit the optional
`?block_hash` parameter. Therefore on mainnet at height 170,060,
camlcoin disables ALL script flags for *any* block that arrives at
that height — not just the historical BIP16 exception block.
**Excerpt** (consensus.ml:870-880):
```ocaml
let get_block_script_flags ?(block_hash="") (height : int) (network : network_config) : int =
  let is_bip16_exception =
    height = 170060 && (
      block_hash = "00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22"
      || block_hash = ""  (* If hash not provided, use height-only check on mainnet *)
    ) && network.name = "mainnet"
  in
  if is_bip16_exception then 0
```
**Impact**: An attacker building a competing chain that forks at
height 170,060 (impossible today but trivially constructible in test
harness or future mainnet reorg scenarios) sees ALL script flags
DROPPED for any block at that height in camlcoin. Core only drops
flags for the *specific* exception block hash. Camlcoin therefore
accepts a chain Core rejects (and vice versa). The "if hash not
provided" comment is **comment-as-confession**: the developer knew the
right answer requires the hash, then made it optional, then made all
callers omit it.

### BUG-W144-2 (P0-CDIV): Taproot exception block (mainnet) MISSING

**File**: `lib/consensus.ml:870-917` (entire function)
**Core ref**: `bitcoin-core/src/kernel/chainparams.cpp:87-88`,
`src/validation.cpp:2263-2266`
**Description**: Core's mainnet `script_flag_exceptions` has TWO
entries: the BIP16 exception (h≈170060, `SCRIPT_VERIFY_NONE`) and the
Taproot exception (block `0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad`,
which is at h≈692,201 well after Taproot activation at 709,632 —
wait, this is actually the post-activation enforcement). Camlcoin has
only the BIP16 exception (and even that incorrectly). The Taproot
exception relaxes flags to `P2SH | WITNESS` (Taproot OFF) for that
one block.
**Excerpt** (Core kernel/chainparams.cpp:87-88):
```cpp
consensus.script_flag_exceptions.emplace( // Taproot exception
    uint256{"0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad"},
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS);
```
**Impact**: If the Taproot exception block is part of the canonical
mainnet chain (it is, per Core chainparams), camlcoin enforces
Taproot validation on it where Core does not — meaning camlcoin
would REJECT the historical mainnet block that Core accepts. This is
a hard chain-split at the exception block. Note: the exception block
hash is identified in Core but the height is not annotated in
chainparams; this requires a chain-tip lookup to confirm impact on
camlcoin reindex. **Verified consensus-divergence on a known mainnet
block.**

### BUG-W144-3 (P1): TWO parallel `script_verify_*` flag definition tables

**File**: `lib/script.ml:115-139` (23 flags) and `lib/consensus.ml:853-865`
(13 flags)
**Core ref**: `bitcoin-core/src/script/interpreter.h:49-151` (one
canonical enum)
**Description**: Two separate copies of the flag bit-index constants.
Both copies use the same bits (e.g., `1 lsl 5` for `MINIMALDATA` in
both). The consensus.ml copy is a strict subset: it drops MINIMALIF,
DISCOURAGE_UPGRADABLE_NOPS, DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
DISCOURAGE_OP_SUCCESS, DISCOURAGE_UPGRADABLE_TAPROOT_VERSION,
DISCOURAGE_UPGRADABLE_PUBKEYTYPE, CONST_SCRIPTCODE, STRICTENC,
SIGPUSHONLY, NULLFAIL (some are present, some not). The inline
comment reads:
**Excerpt** (consensus.ml:849-851):
```ocaml
(* ============================================================================
   Script verification flags (duplicated from Script to avoid dependency)
   ============================================================================ *)
```
**Comment-as-confession**: the developer documents the duplication
as a feature, not the bug it is. This is the textbook
"two-pipeline guard" pattern: any new flag added in `script.ml` and
referenced from `consensus.ml` will mis-link unless updated in both
places. **Impact**: refactor hazard; today, harmless if both copies
are identical. Today's `get_standard_policy_flags` (consensus.ml:925-931)
references `script_verify_low_s` from consensus.ml — if the bit
indices ever drift, mempool policy will become inconsistent with
script execution.

### BUG-W144-4 (P1): OP_CLTV-as-NOP2 path checks DISCOURAGE_UPGRADABLE_NOPS

**File**: `lib/script.ml:2267-2274`
**Core ref**: `bitcoin-core/src/script/interpreter.cpp:522-527`
**Description**: When `SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY` is NOT set,
Core treats the opcode as NOP2 and `break`s without any further
check. Camlcoin checks `script_verify_discourage_upgradable_nops`
in this case and returns `Error "Upgradable NOP used"`.
**Excerpt** (script.ml:2267-2274):
```ocaml
| OP_CHECKLOCKTIMEVERIFY ->
  if st.flags land script_verify_checklocktimeverify = 0 then begin
    (* Treat as NOP2 if CLTV not enabled *)
    if st.flags land script_verify_discourage_upgradable_nops <> 0 then
      Error "Upgradable NOP used"
    else
      Ok ()
```
Core (interpreter.cpp:522-527):
```cpp
case OP_CHECKLOCKTIMEVERIFY:
{
    if (!(flags & SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY)) {
        // not enabled; treat as a NOP2
        break;
    }
```
**Impact**: This is reachable only with policy flags (which include
DISCOURAGE_UPGRADABLE_NOPS) and CLTV disabled. In practice CLTV is
always on for mainnet today (h>388,381) so the bug is latent. But on a
forked test chain where CLTV is bit-flipped off, camlcoin rejects
scripts containing OP_NOP2 (CLTV) that Core would accept under
the same flags. Re-mempool scripts that use OP_NOP2 in a non-CLTV
context for forward-compat are also impacted. **DIVERGENT
ADMITTANCE**.

### BUG-W144-5 (P1): OP_CSV-as-NOP3 path checks DISCOURAGE_UPGRADABLE_NOPS

**File**: `lib/script.ml:2306-2313`
**Core ref**: `bitcoin-core/src/script/interpreter.cpp:561-566`
**Description**: Symmetric to BUG-4 but for CSV / OP_NOP3. When
`SCRIPT_VERIFY_CHECKSEQUENCEVERIFY` is NOT set, Core bare-`break`s;
camlcoin checks DISCOURAGE_UPGRADABLE_NOPS.
**Excerpt** (script.ml:2306-2313):
```ocaml
| OP_CHECKSEQUENCEVERIFY ->
  if st.flags land script_verify_checksequenceverify = 0 then begin
    (* Treat as NOP3 if CSV not enabled *)
    if st.flags land script_verify_discourage_upgradable_nops <> 0 then
      Error "Upgradable NOP used"
    else
      Ok ()
```
**Impact**: same divergence class as BUG-4; latent on mainnet
(CSV-on for all heights since 419,328) but constructible.

### BUG-W144-6 (P1): Three flag constants defined but NEVER read

**File**: `lib/script.ml:137-139`
**Core ref**: `bitcoin-core/src/script/interpreter.cpp:1100-1150,
1900-1990` (all three flags drive Tapscript opcode rejection)
**Description**: `script_verify_discourage_op_success` (bit 18),
`script_verify_discourage_upgradable_taproot_version` (bit 19),
`script_verify_discourage_upgradable_pubkeytype` (bit 20) are
defined in script.ml but appear in NO `if st.flags land …` guard.
Grep confirms zero readers.
**Excerpt** (script.ml:137-139):
```ocaml
let script_verify_discourage_op_success = 1 lsl 18  (* Discourage OP_SUCCESSx in tapscript *)
let script_verify_discourage_upgradable_taproot_version = 1 lsl 19  (* Discourage unknown taproot leaf versions *)
let script_verify_discourage_upgradable_pubkeytype = 1 lsl 20  (* Discourage unknown pubkey types in tapscript *)
```
**Impact**: dead constants. Camlcoin's mempool cannot reject:
- Tapscripts using `OP_SUCCESS192..OP_SUCCESS254` (BIP-342 forward-compat).
- Tapscripts with unknown leaf versions (Core: leaf_version `0xc0` =
  tapscript; others should be discouraged via flag).
- Tapscripts with unknown pubkey types in `OP_CHECKSIG`/`OP_CHECKSIGADD`.

These are all policy-level discourage flags that should be in
`STANDARD_SCRIPT_VERIFY_FLAGS`. Their absence weakens camlcoin's
mempool: a relay-then-redeem attack vector for a future tapscript
soft-fork. **Fleet pattern: defined-but-not-called**.

### BUG-W144-7 (P0-CDIV): `STANDARD_SCRIPT_VERIFY_FLAGS` missing 8 bits

**File**: `lib/consensus.ml:922-933` (`get_standard_policy_flags`)
**Core ref**: `bitcoin-core/src/policy/policy.h:119-132`
**Description**: Core's STANDARD set has 12 extra bits beyond
MANDATORY. Camlcoin's `get_standard_policy_flags` adds 6 bits
(cleanstack, sigpushonly, nullfail, low_s, minimaldata,
witness_pubkeytype). Missing:
- STRICTENC (BIP-62 rule 1) — strict signature encoding (sig must be
  DER + valid hash_type byte)
- DISCOURAGE_UPGRADABLE_NOPS — discourage scripts using NOP1, NOP4-10
- MINIMALIF — IF arg must be empty or 0x01
- DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM — unknown witness versions
- CONST_SCRIPTCODE — reject scripts where find_and_delete modifies
  scriptCode (CVE 2010-5141 class)
- DISCOURAGE_UPGRADABLE_TAPROOT_VERSION — unknown taproot leaf version
- DISCOURAGE_OP_SUCCESS — unknown OP_SUCCESSx in tapscript
- DISCOURAGE_UPGRADABLE_PUBKEYTYPE — unknown tapscript pubkey types
Also INCORRECT inclusion: `script_verify_sigpushonly` — Core does not
include this in STANDARD (it is checked separately as a consensus rule
for P2SH).
**Excerpt** (consensus.ml:922-933):
```ocaml
let get_standard_policy_flags (height : int) (network : network_config) : int =
  let base = get_block_script_flags height network in
  let extra = ref 0 in
  if height >= network.segwit_height then begin
    extra := !extra lor script_verify_cleanstack;
    extra := !extra lor script_verify_sigpushonly;
    extra := !extra lor script_verify_nullfail;
    extra := !extra lor script_verify_low_s;
    extra := !extra lor script_verify_minimaldata;
    extra := !extra lor script_verify_witness_pubkeytype
  end;
  base lor !extra
```
**Impact**: Camlcoin's mempool admits transactions Core's mempool
rejects (and vice versa for the sigpushonly case): unknown OP_SUCCESS,
unknown tapscript pubkeys, malleable IFs, non-strict-enc sigs, etc.
Cross-impl relay between camlcoin and Core produces persistent
re-flooding loops (camlcoin accepts, sends to Core; Core rejects but
re-requests later because the txid is known; etc.). This also impacts
RPC `testmempoolaccept` correctness — camlcoin's verdict diverges
from Core's. **Policy split must converge or fleet diverges**.

### BUG-W144-8 (P2): `STANDARD` adds SIGPUSHONLY incorrectly

**File**: `lib/consensus.ml:927`
**Core ref**: `bitcoin-core/src/policy/policy.h:119-132` (NOT in
STANDARD); `src/script/interpreter.cpp:2011-2014` (only checked when
flag is explicitly passed; the SIGPUSHONLY consensus rule for P2SH
fires via a different path)
**Description**: Camlcoin's mempool sets `SIGPUSHONLY` in the policy
flag set. Core does NOT include this in `STANDARD_SCRIPT_VERIFY_FLAGS`.
Including it means any tx whose scriptSig contains a non-push opcode
is rejected by mempool — but Core accepts such transactions in the
mempool (they are nonstandard if the scriptSig is not push-only, but
the rejection happens via a different policy gate
`AreInputsStandard`, not via the script-verify flag).
**Excerpt** (consensus.ml:927):
```ocaml
extra := !extra lor script_verify_sigpushonly;
```
**Impact**: Camlcoin rejects scriptSigs Core accepts (and vice versa
post-routing). Crossover mempool divergence. **Diverges from Core's
mempool policy by *extra* strictness**.

### BUG-W144-9 (P1): MINIMALIF comment-as-confession

**File**: `lib/script.ml:1251-1278`
**Core ref**: `bitcoin-core/src/script/interpreter.cpp:464-475`
(MINIMALIF is policy-only when flag is set; tapscript ALWAYS enforces
via `SCRIPT_VERIFY_TAPSCRIPT_IF_BYTE` semantics)
**Description**: The inline comment claims MINIMALIF is enforced
unconditionally for witness v0, but the code only enforces when the
flag is set.
**Excerpt** (script.ml:1251-1258):
```ocaml
(* MINIMALIF: unconditionally enforce for witness v0/v1 (tapscript).
   For tapscript it's a consensus rule. For witness v0, while Bitcoin Core
   treats it as policy-only with flag, we enable unconditionally for
   witness programs per BIP 141 best practices.
   Also enforce when the explicit flag is set for legacy scripts. *)
let enforce_minimalif =
  st.sig_version = SigVersionTapscript ||
  (st.sig_version = SigVersionWitnessV0 && st.flags land script_verify_minimalif <> 0)
in
```
The condition `SigVersionWitnessV0 && st.flags land script_verify_minimalif <> 0`
requires the flag to be set — directly contradicting the comment
above. Since `script_verify_minimalif` is NOT in camlcoin's
`get_standard_policy_flags` (BUG-7), this is effectively
"never enforced for witness v0". **Comment-as-confession**: the
comment describes the intent; the code does not match.
**Impact**: malleability surface. Witness v0 IF arguments are not
canonical; a witness v0 P2WSH transaction can be malleated by
replacing the IF arg with any non-zero byte. Both Core (default mempool)
and camlcoin (when flag is added to STANDARD) would reject.

### BUG-W144-10 (P0-CDIV): Missing CLEANSTACK ⇒ P2SH ∧ WITNESS assertion

**File**: `lib/script.ml:2569-2700` (verify_script, throughout)
**Core ref**: `bitcoin-core/src/script/interpreter.cpp:2100-2118`
**Description**: Core asserts at runtime that if CLEANSTACK is in the
flags, P2SH AND WITNESS are also set; and if WITNESS is set, P2SH is
also set. Camlcoin has no such assertion. A caller could pass
`flags = SCRIPT_VERIFY_CLEANSTACK` without P2SH or WITNESS, and
camlcoin would happily evaluate the script with CLEANSTACK but
without the prerequisite gates. This causes a slow-path script
evaluation that Core would `assert`-abort on.
**Excerpt** (Core interpreter.cpp:2100-2104):
```cpp
if ((flags & SCRIPT_VERIFY_CLEANSTACK) != 0) {
    assert((flags & SCRIPT_VERIFY_P2SH) != 0);
    assert((flags & SCRIPT_VERIFY_WITNESS) != 0);
```
**Impact**: latent today — no caller passes such an inconsistent
combination — but the missing invariant is a soft-fork hazard: a
future soft-fork that adds CLEANSTACK without P2SH (as Core's design
note says: "would be possible, which is not a softfork") would
silently diverge.

### BUG-W144-11 (P2): Testnet3 missing Taproot BIP-9 record

**File**: `lib/consensus.ml:1722-1728`
**Core ref**: `bitcoin-core/src/kernel/chainparams.cpp:236-241`
(testnet3 has its own DEPLOYMENT_TAPROOT block in vDeployments)
**Description**: `check_buried_deployment_consistency` skips
testnet3 entirely (`Testnet3 -> None`). But testnet3's
`taproot_height = 2_032_291` is set, so Taproot is buried-active for
testnet3. The drift detector therefore cannot catch a mistake in
testnet3 chainparams. The RPC `getdeploymentinfo` on testnet3 has no
BIP-9 record to return — Core's testnet3 still emits one for
backward compat.
**Excerpt** (consensus.ml:1722-1728):
```ocaml
let taproot_dep = match network.network_type with
  | Mainnet  -> Some mainnet_taproot
  | Testnet4 -> Some testnet4_taproot
  | Regtest  -> Some regtest_taproot
  | Testnet3 -> None  (* No dedicated testnet3 deployment; height-gated only *)
in
```
**Impact**: testnet3 RPC parity break. Operators using
`getdeploymentinfo` on a camlcoin testnet3 node receive an empty
list; Core's emits 1 record. No consensus impact.

### BUG-W144-12 (P0-CDIV): Two flag-derivation helpers used by different code paths

**File**: `lib/consensus.ml:870` (`Consensus.get_block_script_flags`)
vs. `lib/validation.ml:305` (`Validation.get_script_flags_for_height`)
**Core ref**: `bitcoin-core/src/validation.cpp:2250` (single
`GetBlockScriptFlags`)
**Description**: Two helpers compute the consensus script flags from
a height. The main sync (sync.ml × 4), mempool (mempool.ml × 1),
sigops (validation.ml:1633), and mining (mining.ml:826) paths use
`Consensus.get_block_script_flags` (with the BIP16 exception logic).
The assume_utxo background validator (assume_utxo.ml:1159) uses
`Validation.get_script_flags_for_height` (NO exception logic). On
mainnet at height 170,060, the two helpers produce **different
flags**: the consensus.ml helper returns 0 (BIP16 exception); the
validation.ml helper returns `P2SH` (no exception).
**Excerpt** (validation.ml:305-334, abbreviated):
```ocaml
let get_script_flags_for_height ~(network : Consensus.network_config) (height : int) : int =
  let flags = ref 0 in
  if height >= 1 then  (* P2SH is active from genesis in practice *)
    flags := !flags lor Script.script_verify_p2sh;
  if height >= network.bip66_height then
    flags := !flags lor Script.script_verify_dersig;
  …
```
**Impact**: assume_utxo IBD validates the BIP16 exception block under
stricter rules than sync-from-genesis IBD. If the historical block at
h=170060 contains a P2SH-violating transaction (it does — that is
why the exception exists), assume_utxo would REJECT the block while
the main path ACCEPTS. **Direct consensus divergence between two
modes of the same node** — the worst kind of two-pipeline failure.
**Fleet pattern: two-pipeline guard, 15th distinct extension since
W76**.

### BUG-W144-13 (P3): Taproot BIP-9 state machine retained but consensus uses buried height

**File**: `lib/consensus.ml:1281-1745`
**Core ref**: `bitcoin-core/src/validation.cpp:2250-2289` (Taproot is
in base set; deployment record retained only for RPC parity)
**Description**: Camlcoin implements the full BIP-9 state machine
including periods, cache, `get_deployment_state`, and
`is_deployment_active`. None of these are consulted by the validation
path — `consensus.ml:913` uses the buried height. The state machine
is used by `rpc.ml:131` for `getdeploymentinfo` and by
`mining.ml:463` for block version bits. **This is OK** but the dead
deployment code adds maintenance burden and a path for divergence if
the buried height and the BIP-9 `min_activation_height` ever drift.
**Mitigation already in place**: `check_buried_deployment_consistency`
(consensus.ml:1721-1744) cross-checks the two; but it has no
production caller (BUG-14).
**Impact**: P3 cosmetic / hygiene drift.

### BUG-W144-14 (P1): `check_buried_deployment_consistency` defined but never called

**File**: `lib/consensus.ml:1721-1744`
**Description**: Function is defined and exported but has no
production caller. `git grep check_buried_deployment_consistency`
finds only the definition. The inline comment says:
*"Callers (sync.ml chain_state setup) should treat any error as fatal"*
— but sync.ml does not call it.
**Excerpt** (consensus.ml:1717-1720):
```ocaml
(* Returns Ok () on agreement, Error msg with the specific mismatch otherwise.
   Callers (sync.ml chain_state setup) should treat any error as fatal: a
   misconfigured chainparams file is not a recoverable condition. *)
let check_buried_deployment_consistency (network : network_config)
```
**Impact**: drift detector is dead code. A future developer who
updates `network.taproot_height` (say from 709632 to 710000 for a
test fork) without updating `mainnet_taproot.min_activation_height`
will produce silently divergent consensus: validation path activates
at 710,000; RPC reports activation at 709,632. **Fleet pattern:
defined-but-not-called drift detector**.

### BUG-W144-15 (P0-CDIV): WITNESS_UNEXPECTED missing on P2SH non-witness redeem path

**File**: `lib/script.ml:2828-2841`
**Core ref**: `bitcoin-core/src/script/interpreter.cpp:2110-2118`
**Description**: Already booked under W142 BUG-W142-10. Re-cited here
because the bug is *within the script-verify flag mux*: the
`SCRIPT_VERIFY_WITNESS` flag drives the tail-guard, and the camlcoin
P2SH-regular-redeem branch (line 2828-2841) does NOT check
`witness.items <> []`. Cross-cite for completeness; no additional fix
needed beyond W142.

### BUG-W144-16 (P2): Signet not supported

**File**: `lib/consensus.ml:271` (`network_type`) and throughout
**Core ref**: `bitcoin-core/src/kernel/chainparams.cpp:336-457`
(`SigNetParams`)
**Description**: Camlcoin's `network_type` enum has no `Signet`
variant. Therefore signet (BIP-325) cannot be run; consensus rules
specific to signet (e.g., signet challenge block validation) cannot
be enforced. Signet is the recommended test network for soft-fork
trials post-2021.
**Impact**: feature gap for testing. No consensus impact on existing
networks.

### BUG-W144-17 (P3): assumevalid forces flags=0; sig-cache key invalidated

**File**: `lib/sync.ml:2398-2400, 3400-3403`
**Core ref**: `bitcoin-core/src/validation.cpp:2475-2483`
(assumevalid: `fScriptChecks = false`)
**Description**: When `skip_scripts` is true (assumevalid range),
camlcoin sets `validation_flags = 0`. The sig-cache key
(`Sig_cache.cache_key` at `validation.ml:1161-1165`) includes
`flags`. Therefore any sig-cache entry written during assumevalid IBD
has `flags = 0` and cannot be reused after assumevalid ends (when
`flags` switches to the consensus mask). This is correct (no false
positives) but a missed optimisation: every signature must be
re-cached after assumevalid.
**Excerpt** (sync.ml:2398-2400):
```ocaml
let skip_scripts = is_assume_valid ibd.chain height in
let validation_flags =
  if skip_scripts then 0
  else Consensus.get_block_script_flags height ibd.chain.network
```
**Impact**: P3 performance hint. Re-cache cost ≈ O(N) signatures
post-assumevalid; not a correctness bug.

### BUG-W144-18 (P1): mempool computes flags for `current_height + 1`

**File**: `lib/mempool.ml:1878, 2126`
**Core ref**: `bitcoin-core/src/validation.cpp:1181` (uses
`m_chain.Tip()` directly — NOT `tip+1`)
**Description**: Camlcoin's mempool computes script flags as
`Consensus.get_standard_policy_flags (mp.current_height + 1)` —
i.e., one height past the tip. Core computes flags at the tip itself
(`GetBlockScriptFlags(*m_active_chainstate.m_chain.Tip(), …)`). At
activation-boundary heights, this difference matters: if tip = h
where h+1 is the activation height, camlcoin's mempool enforces
post-activation rules; Core's mempool enforces pre-activation rules.
**Excerpt** (mempool.ml:1878):
```ocaml
let flags = Consensus.get_standard_policy_flags (mp.current_height + 1) mp.network in
```
**Impact**: at the exact activation height boundary (e.g., mainnet
h=419328 for CSV, h=481824 for SegWit), camlcoin pre-emptively
rejects mempool transactions Core accepts (because Core treats h as
"still pre-activation"). After the boundary block is mined the two
re-converge. Latent on mainnet today (all softforks already
activated); reachable on a fresh testnet or after a future
softfork.

### BUG-W144-19 (P1): BIP16 exception height-only fallback fires on any reorg-target block

**File**: `lib/consensus.ml:870-880` (cross-ref BUG-1)
**Description**: Independent restatement of BUG-1 in the reorg
context. Sync.ml's reorg path (`sync.ml:3403`) calls
`Consensus.get_block_script_flags height state.network` *without*
the block hash. If a reorg disconnects + reconnects through height
170,060, the exception logic fires for *every* candidate block at
that height — not just the canonical mainnet exception block.
**Impact**: in any reorg scenario at h=170060, camlcoin disables
script flags for ALL competing chains' blocks at that height. This is
a soft fork hazard: an attacker could craft a competing chain whose
h=170,060 block contains transactions that would be rejected under
P2SH rules, knowing camlcoin will accept them. Core (which keys on
the historical hash) would NOT accept the attacker's competing
block. Practically impossible to exploit today (mainnet has 14+
years of proof-of-work since h=170060) but the design is wrong.

### BUG-W144-20 (P3): `script_verify_none` constant is redundant

**File**: `lib/script.ml:116`
**Description**: `let script_verify_none = 0`. There is no read of
this constant; callers use the literal `0` (e.g.
`sync.ml:2400, 3402`). Cosmetic.
**Impact**: none.

### BUG-W144-21 (P2): No script_flag_exceptions table on testnet3

**File**: `lib/consensus.ml` (mainnet exception only)
**Core ref**: `bitcoin-core/src/kernel/chainparams.cpp:209-211`
(testnet3 also has BIP16 exception)
**Description**: Core's testnet3 chainparams has its own
`script_flag_exceptions` entry. Camlcoin's exception gate is
hardcoded as `network.name = "mainnet"`, so testnet3 has no
exception lookup at all. If a camlcoin testnet3 reindex traverses
the historical testnet3 BIP16 exception block, validation would
diverge from Core's testnet3 behaviour.
**Impact**: testnet3 chain-split possibility on the historical
BIP16 exception block. Testnet3 is approaching deprecation but the
historical chain history is fixed.

### BUG-W144-22 (P1): Mining path uses buried-height path but flag bits hardcoded

**File**: `lib/mining.ml:826`
**Core ref**: `bitcoin-core/src/validation.cpp:2250`
**Description**: Mining path
`Consensus.get_block_script_flags height chain.network` returns the
consensus flag set (no policy bits). This is correct. But the
mining flag derivation does NOT consult
`script_verify_discourage_upgradable_*` bits (i.e., does not put
discourage policy into mined blocks). This is correct (consensus
only) but a developer reading the code might assume mining uses the
same flags as mempool. The split is undocumented.
**Impact**: documentation gap; no consensus impact.

### BUG-W144-23 (P3): `script_verify_*` constants have non-contiguous bits

**File**: `lib/script.ml:115-139` and `lib/consensus.ml:853-865`
**Core ref**: `bitcoin-core/src/script/interpreter.h:49-151` (Core
uses an *enum class* with contiguous indices 0..21; bit positions
come from `1 << static_cast<int>(name)`)
**Description**: Camlcoin uses bit positions that match a *legacy*
Bitcoin Core bitmask layout (P2SH=bit 0, STRICTENC=bit 1, DERSIG=bit
2, …). Modern Core has reorganised internally to use a strongly-
typed `script_verify_flags` class with contiguous flag indices.
Camlcoin's bit layout matches the *pre-#28201* Core layout. Not a
consensus bug — the bits are not serialised — but a parity hazard
for future cross-impl tooling that introspects flags.
**Impact**: cosmetic / forensic.

## Fleet patterns

- **two-pipeline-guard 15th extension** (BUG-12): two distinct
  flag-derivation helpers (`Consensus.get_block_script_flags` vs.
  `Validation.get_script_flags_for_height`), used by different code
  paths (sync vs. assume_utxo), with divergent semantics on the BIP16
  exception block. Cross-cites: W76 (banman), W124 (rpcauth), W138
  (assumeutxo), W141 (HTTP+rpcauth). Now W144.
- **comment-as-confession 5th instance** (BUG-1 + BUG-9): in BUG-1,
  the comment `(* If hash not provided, use height-only check on
  mainnet *)` documents the dangerous fall-through path as a feature;
  in BUG-9, the inline comment claims MINIMALIF is enforced
  unconditionally for witness v0, but the code requires the flag.
  Cross-cites: W126 (banman), W137 (PSBT), W139 (haskoin Consensus.hs
  literal "in a full implementation"), W141 (rustoshi/clearbit ZMQ).
- **dead-helper-at-call-site** (BUG-14): `check_buried_deployment_consistency`
  exists, is exported, but has no caller. Cross-cite: W141
  beamchain `chumak:stop` paired no-op; W140 haskoin
  `constantTimeEq` exported never called.
- **carry-forward re-anchor 3rd instance** (BUG-3): the duplicate
  flag definitions in `consensus.ml:853-865` exist because at some
  prior wave (probably W122 or earlier), a developer broke a circular
  module dependency by copying constants. The fix has carried
  forward without consolidation. Cross-cite: W140 clearbit BUG-13.
- **defined-but-not-called 4th instance** (BUG-6): three discourage
  flags defined but zero readers. Cross-cite: W141 nimrod
  `RelayManager`, W138 fleet-wide `ChainstateManager`.
- **standardness-rules subset of Core** (BUG-7): camlcoin's
  `STANDARD_SCRIPT_VERIFY_FLAGS` is half the size of Core's.
  Cross-cite: W135 fleet pattern (operator-knob absence in 6+ impls).
- **fallback-default = wrong-default** (BUG-1, BUG-19): the optional
  `?block_hash=""` parameter creates a silent path-dependent flag
  divergence. Cross-cite: W128 (banman two-channel split fleet
  pattern).
- **buried + versionbits dual machinery** (BUG-13, BUG-14): camlcoin
  keeps both the buried height and the BIP-9 deployment record, and
  has a cross-check that is not wired up. Cross-cite: W137 (PSBT v2
  vs v0 framing in Core).
- **plumb-gate-then-flip** — would have been the pattern if any
  caller passed the hash, but here all callers omit it (BUG-1).

## Summary

23 BUGs catalogued across 30 audit gates. Severity breakdown:

| Severity | Count | Examples |
|----------|-------|----------|
| P0-CDIV  | 6 | BUG-1 (BIP16 exception fall-through), BUG-2 (Taproot exception missing), BUG-7 (STANDARD missing 8 bits), BUG-10 (no CLEANSTACK invariant), BUG-12 (two flag helpers diverge), BUG-15 (WITNESS_UNEXPECTED gap, W142 cross-cite) |
| P1       | 9 | BUG-3 (dual flag tables), BUG-4 (CLTV→NOP2 DISCOURAGE), BUG-5 (CSV→NOP3 DISCOURAGE), BUG-6 (3 dead constants), BUG-9 (MINIMALIF comment lies), BUG-14 (drift detector dead), BUG-18 (mempool flags one-too-high), BUG-19 (reorg-time exception fallthrough), BUG-22 (mining flag doc gap) |
| P2       | 4 | BUG-8 (SIGPUSHONLY in STANDARD), BUG-11 (testnet3 BIP-9), BUG-16 (no signet), BUG-21 (testnet3 exception missing) |
| P3       | 4 | BUG-13 (versionbits dead), BUG-17 (sig-cache flush on assumevalid), BUG-20 (script_verify_none redundant), BUG-23 (non-contiguous bits) |

The single most consequential finding is **BUG-12** — two
flag-derivation helpers used by different code paths. The
**assume_utxo** background validator would reject the BIP16
exception block that the **main sync** path accepts. This is a hard
intra-node split: depending on whether a user boots from genesis or
from a UTXO snapshot, they reach DIFFERENT consensus on mainnet
historical heights. The two helpers must be unified.

The second most consequential finding is **BUG-2** — the Taproot
exception block is missing entirely. This is a real mainnet
chain-split candidate that surfaces on any reindex that touches the
post-activation Taproot exception block. The fix is a single map
entry mirroring Core's `kernel/chainparams.cpp:87-88`.

The third is **BUG-1 + BUG-19** — the BIP16 exception fall-through
on `block_hash=""`. The fix is to remove the fallback and force all
callers to pass the hash (compile-error rather than silent
misbehaviour).
