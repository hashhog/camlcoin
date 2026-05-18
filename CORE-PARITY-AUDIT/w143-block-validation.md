# W143 Block-level validation (CheckBlock + ContextualCheckBlock + ConnectBlock) — camlcoin (OCaml)

Wave: W143 — the eight behaviours that span CheckBlock context-free
checks, ContextualCheckBlock contextual checks, and ConnectBlock UTXO-
aware checks: MAX_BLOCK_SIGOPS_COST + scale factor, BIP-34 coinbase
height (CScriptNum), BIP-30 + duplicate-coinbase exemption, merkle
root + CVE-2012-2459 mutation, MoneyRange invariant, vin/vout non-empty
+ exactly one coinbase, MAX_BLOCK_SERIALIZED_SIZE, block timestamp
future/MTP guards.

Bitcoin Core references:

- `bitcoin-core/src/validation.cpp`
  - L3918-3982: `CheckBlock` — `CheckBlockHeader`, `CheckMerkleRoot`,
    `bad-blk-length` (vtx.empty / `vtx.size()*WSF > MAX_BLOCK_WEIGHT` /
    `GetSerializeSize(TX_NO_WITNESS(block))*WSF > MAX_BLOCK_WEIGHT`),
    `bad-cb-missing` + `bad-cb-multiple`, per-tx `CheckTransaction`,
    legacy sigops `nSigOps * WITNESS_SCALE_FACTOR > MAX_BLOCK_SIGOPS_COST`
  - L3837-3862: `CheckMerkleRoot` — `bad-txnmrklroot` AND CVE-2012-2459
    `bad-txns-duplicate` (mutated flag) classified as
    `BLOCK_MUTATED` not `BLOCK_CONSENSUS` — recoverability semantics
  - L3870-3916: `CheckWitnessMalleation` (handed off to W142)
  - L4080-4121: `ContextualCheckBlockHeader` — `bad-diffbits`,
    `time-too-old` (`block.GetBlockTime() <= pindexPrev->GetMedianTimePast()`),
    BIP-94 timewarp at retarget boundary
    (`time-timewarp-attack`), `time-too-new`
    (`block.Time() > NodeClock::now() + MAX_FUTURE_BLOCK_TIME` /
    7200 s), `bad-version(...)` BIP-9 deployment-state version gate
  - L4129-4184: `ContextualCheckBlock` — `bad-txns-nonfinal`
    (`IsFinalTx` with locktime cutoff = `pprev->GetMedianTimePast()`
    when CSV active else `block.GetBlockTime()`), `bad-cb-height`
    (`CScript() << nHeight` byte-equal prefix), `CheckWitnessMalleation`
    + `bad-blk-weight` (`GetBlockWeight(block) > MAX_BLOCK_WEIGHT`)
  - L2295-2700: `ConnectBlock` — recheck CheckBlock, BIP-30
    (`bad-txns-BIP30`) under `fEnforceBIP30 || pindex->nHeight >=
    BIP34_IMPLIES_BIP30_LIMIT (1983702)`, BIP-68 sequence locks
    (`bad-txns-nonfinal`), `Consensus::CheckTxInputs`, sigops cost
    (`GetTransactionSigOpCost`, `nSigOpsCost > MAX_BLOCK_SIGOPS_COST`),
    `CheckInputScripts`, accumulated-fee MoneyRange
    (`bad-txns-accumulated-fee-outofrange`), `bad-cb-amount`
    (`block.vtx[0]->GetValueOut() > nFees + GetBlockSubsidy(height,...)`)
- `bitcoin-core/src/consensus/tx_check.cpp`
  - L11-60: `CheckTransaction` — `bad-txns-vin-empty`,
    `bad-txns-vout-empty`, `bad-txns-oversize`
    (`GetSerializeSize(TX_NO_WITNESS(tx))*WSF > MAX_BLOCK_WEIGHT`),
    `bad-txns-vout-negative`, `bad-txns-vout-toolarge`,
    `bad-txns-txouttotal-toolarge` (cumulative MoneyRange),
    `bad-txns-inputs-duplicate` (CVE-2018-17144),
    `bad-cb-length` (coinbase scriptSig 2..100 bytes),
    `bad-txns-prevout-null` (non-coinbase only)
- `bitcoin-core/src/consensus/tx_verify.cpp`
  - L17-37: `IsFinalTx` — `nLockTime < (LOCKTIME_THRESHOLD ? height :
    blocktime)` final criterion plus `vin[*].nSequence ==
    SEQUENCE_FINAL` override
  - L107-110: `SequenceLocks` — BIP-68 wrapper
  - L112-124: `GetLegacySigOpCount` — `txin.scriptSig.GetSigOpCount(false)
    + txout.scriptPubKey.GetSigOpCount(false)` summed across ALL vin/vout
  - L143-162: `GetTransactionSigOpCost` — `legacy * WSF` + `p2sh * WSF`
    + `CountWitnessSigOps`
  - L164-214: `Consensus::CheckTxInputs` — `bad-txns-inputs-missingorspent`,
    `bad-txns-premature-spend-of-coinbase`, per-input + cumulative input
    MoneyRange (`bad-txns-inputvalues-outofrange`),
    `bad-txns-in-belowout`, `bad-txns-fee-outofrange`
- `bitcoin-core/src/consensus/merkle.cpp`
  - L46-63: `ComputeMerkleRoot` — `mutated=true` SET iff any
    adjacent pair `hashes[pos]==hashes[pos+1]` (pos+1<size, i.e.
    BEFORE the odd-tail self-duplication)
  - L66-74: `BlockMerkleRoot` — leaves = `vtx[s]->GetHash()` for ALL s
- `bitcoin-core/src/consensus/consensus.h`
  - L13: `MAX_BLOCK_SERIALIZED_SIZE = 4000000`
  - L15: `MAX_BLOCK_WEIGHT = 4000000`
  - L17: `MAX_BLOCK_SIGOPS_COST = 80000`
  - L21: `WITNESS_SCALE_FACTOR = 4`
  - L23-24: `MIN_TRANSACTION_WEIGHT = 240`,
    `MIN_SERIALIZABLE_TRANSACTION_WEIGHT = 40`
- `bitcoin-core/src/script/script.h`
  - L341-372: `CScriptNum::serialize` — sign-magnitude little-endian
    with explicit sign byte appended if MSB of magnitude is set
  - L433-448: `push_int64` — `OP_0` for 0, `OP_1NEGATE`/`OP_1..OP_16`
    for -1 / 1..16, else `*this << CScriptNum::serialize(n)` (length-
    prefixed push)
- `bitcoin-core/src/script/script.cpp`
  - L158-180: `GetSigOpCount(fAccurate)` — best-effort COUNTS up to
    parse failure point (`break`), does NOT zero on truncation
  - L182-204: `GetSigOpCount(scriptSig)` — returns 0 if scriptSig is
    not entirely push-only (any opcode > OP_16 zeroes the count)

BIPs: BIP-30 (CVE-2012-1909 dup-tx), BIP-34 (height in coinbase),
BIP-65 (CLTV), BIP-66 (DERSIG), BIP-94 (testnet timewarp).

## Methodology

1. Read Core refs above.
2. Enumerate 30 audit gates spanning the eight W143 behaviours plus
   adjacent surfaces (parse-failure semantics for `GetSigOpCount`,
   CScriptNum encoding edge cases, BIP-30 exempt block lookup,
   merkle mutation plumbing, MoneyRange invariant breadth,
   BLOCK_MUTATED vs BLOCK_CONSENSUS classification, ordering of
   structural vs contextual checks vs UTXO checks, magic-number
   duplication across files, genesis special-case).
3. Classify each gate against camlcoin's de-facto surface:
   - `lib/validation.ml` — `check_block`, `check_transaction`,
     `check_coinbase`, `check_witness_commitment`, `is_coinbase_tx`,
     `count_sigops`, `count_p2sh_sigops`, `count_tx_sigops_cost`,
     `count_tx_sigops`, `compute_tx_weight`, `check_bip30`,
     `bip30_should_enforce`, `is_tx_final`, `validate_block_with_utxos`,
     `accept_block`
   - `lib/consensus.ml` — `max_block_weight`, `max_block_serialized_size`,
     `max_block_sigops_cost`, `max_money`, `witness_scale_factor`,
     `coinbase_maturity`, `max_pubkeys_per_multisig`,
     `encode_height_in_coinbase`, `bip30_repeat_blocks`,
     `is_bip30_repeat`, `block_subsidy`, `check_timewarp_rule`,
     `max_timewarp`
   - `lib/crypto.ml` — `merkle_root`, `compute_wtxid`,
     `witness_merkle_root` (THREE-deep duplication with `lib/mining.ml`
     and `lib/validation.ml`)
   - `lib/script.ml` — `parse_script`, `is_push_only_raw`,
     `get_witness_program`, `bytes_of_script_num`
   - `lib/sync.ml` — `validate_header` (future-time gate,
     BIP-94 timewarp, MTP gate, checkpoint)
   - `lib/mining.ml` — `submit_block` (`check_block_header` then
     `accept_block`)
4. Catalogue BUGs by severity:
   - **P0-CONSENSUS**: known mainnet/testnet block today (or trivially
     constructible) would diverge between camlcoin and Core
   - **P0-CDIV**: protocol-correctness divergence (accepts a block
     Core rejects, or rejects one Core accepts) on an
     adversarially-crafted block
   - **P1**: feature-correctness gap (right formula, wrong gating /
     ordering / coverage)
   - **P2**: malleability surface / fingerprinting / fairness drift /
     code-quality/two-pipeline guard
   - **P3**: surface / constant / cosmetic drift

Severity legend mirrors W130 / W131 / W132 / W133 / W134 / W135 /
W136 / W137 / W138 / W139 / W140 / W141 / W142.

## camlcoin de-facto surface

| Concern | Core | camlcoin |
|---------|------|----------|
| `CheckBlock` entry | `CheckBlock(block, state, params, fCheckPOW, fCheckMerkleRoot)` (`validation.cpp:3918`) | `check_block ~network block height ~expected_bits ~median_time ?prev_block_time ()` (`validation.ml:808`) |
| `ContextualCheckBlockHeader` entry | separate function (`validation.cpp:4080`) | inlined into `check_block` (version, difficulty, MTP, BIP-94) AND duplicated in `Sync.validate_header` (future-time, MTP, BIP-94, checkpoint) |
| `ContextualCheckBlock` entry | separate function (`validation.cpp:4129`) | inlined into `check_block` (BIP-34 via `check_coinbase`, BIP-113 IsFinalTx, witness commitment, weight) |
| `ConnectBlock` entry | `Chainstate::ConnectBlock(...)` (`validation.cpp:2295`) | `validate_block_with_utxos ~network ~base_lookup ~flags ~skip_scripts ...` (`validation.ml:1478`) |
| `time-too-new` gate (`MAX_FUTURE_BLOCK_TIME`) | inside `ContextualCheckBlockHeader` (`validation.cpp:4108`) | inside `Sync.validate_header` (`sync.ml:837`) AND `Validation.check_block_header` (`validation.ml:984`) — NOT inside `check_block` or `validate_block_with_utxos` |
| `MAX_FUTURE_BLOCK_TIME` constant | `consensus/consensus.h` (header lookup unverified) — referenced as `MAX_FUTURE_BLOCK_TIME` | hardcoded `7200`/`7200l`/`7200.0` literal in `validation.ml:984`, `sync.ml:837`, `sync.ml:3830`, AND named `max_future_block_time_secs = 7200` (`sync.ml:233`) — FOUR drift sites |
| `MAX_PUBKEYS_PER_MULTISIG` | single definition (`script.h`) | TWO definitions: `consensus.ml:51` and `script.ml:106`, plus hardcoded `20` in `validation.ml:350` |
| `bad-blk-length` upper bound | `GetSerializeSize(TX_NO_WITNESS(block))*WSF > MAX_BLOCK_WEIGHT` (`validation.cpp:3947`) | `Serialize.serialize_block` (WITH witness) bytes `> max_block_serialized_size (4_000_000)` (`validation.ml:887-891`) — different sum, different cap semantics |
| `bad-blk-weight` formula | `GetSerializeSize(TX_NO_WITNESS(block))*3 + GetSerializeSize(TX_WITH_WITNESS(block))` (consensus/validation.h:136-139) | `Σ compute_tx_weight tx for tx in txs` (`validation.ml:896-898`) — header*4 + tx-count varint*4 missing (W142 BUG-1, restated under W143) |
| `GetSigOpCount` parse-failure semantics | best-effort COUNT to break point (`script.cpp:158-180`) | `try parse_script ... with _ -> 0` (`validation.ml:341-355`) — silently zeroes on truncated push |
| `GetSigOpCount(scriptSig)` P2SH push-only gate | `if (opcode > OP_16) return 0;` (`script.cpp:197-198`) | `extract_last_push_data` runs unconditionally, no push-only gate (`validation.ml:553-562`) |
| BIP-34 height encoding | `CScriptNum::serialize` with explicit sign byte if MSB set (`script.h:341-372`) | `encode_height_in_coinbase` (`consensus.ml:783-812`) — handles 1..0x7fffff correctly via aliased byte-count windows; `>= 0x80000000` writes 4 bytes vs Core 5 bytes (out-of-range for practical heights but observable on adversarial input via OCaml 63-bit int) |
| `BIP30_IMPLIES_BIP30_LIMIT` | `1983702` (`validation.cpp:2430`) | `1983702` (`validation.ml:1440`) ✓ |
| IsBIP30Repeat exempt heights | `91842` + `91880` with canonical hashes (`validation.cpp:6189-6192`) | `91842` + `91880` with canonical hashes (`consensus.ml:1111-1118`) ✓ |
| Merkle mutation flag | `bool mutated` plumbed through `ComputeMerkleRoot` (`consensus/merkle.cpp:46-63`) and `BlockMerkleRoot` (`consensus/merkle.cpp:66-74`); classified `BLOCK_MUTATED` not `BLOCK_CONSENSUS` in `CheckMerkleRoot` (`validation.cpp:3853-3858`) | `merkle_root` returns `(root, mutated)` ✓ but error variant `BlockMutatedMerkle` is a member of `block_validation_error` and is NOT classified separately from other consensus errors — recoverability semantics lost |
| Merkle leaves for witness root | `leaves[0] = empty`, `leaves[s>=1] = vtx[s]->GetWitnessHash()` (POSITIONAL) (`merkle.cpp:76-85`) | `validation.ml:660-666` uses POSITIONAL (`i = 0`) ✓; `crypto.ml:411-413` uses STRUCTURAL (per-tx `compute_wtxid` consults `IsCoinBase()` shape) — STRUCTURAL variant is dead code with zero callers |
| `bad-cb-length` (coinbase scriptSig 2..100) | `CheckTransaction` (`tx_check.cpp:49-50`) | `check_coinbase` only (`validation.ml:274-275`) — called once for vtx[0]; never as part of `check_transaction` for `is_coinbase=true`. Position-dependent (not structurally bound) |
| `bad-cb-amount` overflow | `block.vtx[0]->GetValueOut() > nFees + GetBlockSubsidy(...)` (`validation.cpp:2611-2613`) | `coinbase_value > Int64.add subsidy total_fees` (`validation.ml:2038-2040`) — relies on upstream `is_valid_money` gates on outputs + fees to prevent Int64 overflow; safe in production, fragile under invariant break |
| Genesis special-case | `if (block_hash == hashGenesisBlock) return true;` (`validation.cpp:2339-2343`) skips ALL UTXO/script checks | NO genesis bypass (`validation.ml` ~1478 has no equivalent) — production paths happen to work by coincidence (genesis has no inputs, BIP-30 lookup returns None) |

## 30-gate matrix (W143)

### G1-G8: behavioural gates from the wave brief

- **G1: `MAX_BLOCK_SIGOPS_COST = 80_000`, scaled by `WITNESS_SCALE_FACTOR
  = 4` for the unified cost.**
  Core (`consensus/consensus.h:17,21` + `validation.cpp:2569`):
  constants `80000` and `4` respectively; legacy gate
  `nSigOps * WSF > 80_000`; weighted gate `nSigOpsCost > 80_000`.
  camlcoin (`consensus.ml:11,29` + `validation.ml:881,1639,1866`):
  identical constants `max_block_sigops_cost = 80_000`,
  `witness_scale_factor = 4`. Legacy gate `legacy_sigops * WSF >
  max_block_sigops_cost` (line 881) and weighted gate
  `total_sigops_cost > max_block_sigops_cost` (lines 1639/1866).
  **PARITY** on constants and gate formulae. **No bug**.

- **G2: BIP-34 coinbase height (CScriptNum push, NOT raw varint).**
  Core (`validation.cpp:4154-4156` + `script.h:341-372`): `CScript()
  << nHeight` invokes `push_int64(nHeight)` which uses `OP_1NEGATE`,
  `OP_0`, `OP_1..OP_16`, or `CScriptNum::serialize(n)` (sign-
  magnitude little-endian with explicit sign byte appended if
  magnitude MSB is set). camlcoin (`consensus.ml:783-812`):
  bespoke `encode_height_in_coinbase` — emits `OP_0` for 0,
  `OP_1..OP_16` for 1..16, length-prefixed magnitude LE for
  `17..0x7fffffff`. For heights 17..2^31-1 the byte-count windows
  `<=0x7f`/`<=0x7fff`/`<=0x7fffff`/`else 4` happen to match what
  Core's CScriptNum::serialize produces when the explicit sign-byte
  is needed — verified by hand for 17, 100_000, 128, 32767, 32768,
  8388607, 8388608, 2147483647, 2147483648. **PARITY** for all
  realistic Bitcoin heights. **BUG-W143-1 (P3)** for `height >=
  0x80000000` (2_147_483_648; never reachable in practice but
  technically observable on adversarial input given OCaml 63-bit
  int): Core writes 5 bytes (4 magnitude + 1 sign), camlcoin writes
  4 bytes — see BUG-W143-1.

- **G3: BIP-30 duplicate-coinbase exception — prohibit duplicate-txid
  coinbases EXCEPT heights `91842` + `91880`. BIP-34 makes
  redundant for future blocks; check still runs.**
  Core (`validation.cpp:2402-2476` + `validation.cpp:6189-6192`):
  `fEnforceBIP30 = !IsBIP30Repeat(*pindex)` AND BIP34Hash skip
  optimization AND `BIP34_IMPLIES_BIP30_LIMIT = 1983702` re-enable.
  camlcoin (`validation.ml:1434-1466` + `consensus.ml:1111-1118,
  1136-1139`): full IsBIP30Repeat table with canonical hashes,
  BIP34Hash skip optimization, and `BIP34_IMPLIES_BIP30_LIMIT =
  1983702`. **PARITY**. **No bug** on the gating logic.

- **G4: Merkle root recompute + CVE-2012-2459 mutated-tree detection.**
  Core (`consensus/merkle.cpp:46-63` + `validation.cpp:3837-3862`):
  `mutated` flag set BEFORE odd-tail self-duplication, ONLY for
  adjacent pairs `hashes[pos]==hashes[pos+1]` (pos+1<size); on
  `mutated`, `CheckMerkleRoot` returns `BLOCK_MUTATED` (a distinct
  `BlockValidationResult` enum value from `BLOCK_CONSENSUS`).
  camlcoin (`crypto.ml:359-386`): `merkle_root` returns `(root,
  mutated)` ✓; mutation check runs BEFORE duplication ✓;
  positional adjacent-pair semantics ✓. **But** the error variant
  `BlockMutatedMerkle` in `block_validation_error` is NOT classified
  separately from other consensus errors — see BUG-W143-2.

- **G5: MoneyRange invariant — every `CTxOut::nValue ∈ [0, MAX_MONEY]`
  AND sum of outputs also bounded.**
  Core (`consensus/tx_check.cpp:23-34`): per-output negative + over-
  MAX_MONEY + cumulative MoneyRange. camlcoin (`validation.ml:191-209`):
  identical per-output and cumulative checks against
  `Consensus.max_money = 2_100_000_000_000_000`. **PARITY**.
  **No bug** on MoneyRange.

- **G6: vin/vout non-empty AND exactly one coinbase.**
  Core (`tx_check.cpp:14-17` for empty, `validation.cpp:3951-3955`
  for first/only coinbase). camlcoin (`validation.ml:175-178` for
  empty, `validation.ml:820-822` for first-is-coinbase, `validation.ml:912`
  for no-second-coinbase). **PARITY**. **No bug**.

- **G7: Block size — serialized (with witness) ≤
  `MAX_BLOCK_SERIALIZED_SIZE` (4_000_000 weight post-segwit). Pre-
  segwit 1MB base size check still applies.**
  Core (`validation.cpp:3947`): `GetSerializeSize(TX_NO_WITNESS(block))
  * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT` — checks BASE size
  (stripped) × 4 against weight. There is NO separate "raw serialized
  size with witness" gate in CheckBlock; the P2P-layer cap of
  `MAX_BLOCK_SERIALIZED_SIZE` is enforced at message parse, not in
  consensus. camlcoin (`validation.ml:887-891`): `Serialize.serialize_block
  w_block block` (WITH witness) and gate `block_size >
  max_block_serialized_size (4_000_000)` — see BUG-W143-3.

- **G8: Block timestamp — `≤ GetAdjustedTime() + MAX_FUTURE_BLOCK_TIME
  (7200s)` AND `> MTP of last 11`.**
  Core (`validation.cpp:4108`): `block.Time() > NodeClock::now() +
  MAX_FUTURE_BLOCK_TIME (7200s)` → `time-too-new`. Core
  (`validation.cpp:4092-4093`): `block.GetBlockTime() <=
  pindexPrev->GetMedianTimePast()` → `time-too-old`.
  camlcoin: split between `Sync.validate_header` (sync.ml:837 for
  future, sync.ml:843 for MTP, sync.ml:852 for BIP-94),
  `Validation.check_block_header` (validation.ml:984 for future, no
  MTP, no BIP-94, no checkpoint), AND `Validation.check_block`
  (validation.ml:849 for MTP, validation.ml:855 for BIP-94, no
  future-time check). See BUG-W143-4 (`check_block` does not gate
  future-time at all), BUG-W143-5 (`check_block_header` and
  `Sync.validate_header` are two-pipeline guards on the same rule).

### G9-G15: derived gates from the 8 behaviours

- **G9: `GetSigOpCount` must be best-effort to parse-failure point,
  not zero on truncation.**
  Core (`script.cpp:158-180`): the loop `while (pc < end()) { if
  (!GetOp(pc, opcode)) break; ... lastOpcode = opcode; }` retains
  every sigop counted BEFORE the truncation point — so a script
  `OP_CHECKSIG OP_PUSHDATA1 0xff` counts 1 sigop (CHECKSIG before
  the truncated PUSHDATA1). camlcoin (`validation.ml:341-355`):
  `let count_sigops (script : Cstruct.t) : int = try let ops =
  Script.parse_script script in List.fold_left (... OP_CHECKSIG /
  OP_CHECKSIGVERIFY → +1 ; OP_CHECKMULTISIG / CHECKMULTISIGVERIFY →
  +20 ; _ → 0 ...) 0 ops with _ -> 0`. `parse_script`
  (`script.ml:152-228`) RAISES on truncated PUSHDATA / PUSHDATA1 /
  PUSHDATA2 / PUSHDATA4 (`failwith "Truncated PUSHDATA1"` etc.),
  and `count_sigops`'s `with _ -> 0` catches and ZEROES the
  count. Same try/with → 0 pattern in `count_p2sh_sigops`
  (`validation.ml:357-393`).
  **BUG-W143-6 (P0-CDIV)**: a tx with `OP_CHECKSIG` followed by a
  truncated push has 1 legacy sigop in Core, 0 in camlcoin. An
  attacker chains 20_001 such opcodes in a single block — Core's
  `legacy_sigops * 4 = 80_004 > 80_000` → REJECTS `bad-blk-sigops`.
  camlcoin's `legacy_sigops = 0` → ACCEPTS. Camlcoin permanently
  forks off the canonical chain at the first such block.

- **G10: `GetSigOpCount(scriptSig)` for P2SH must zero unless the
  entire scriptSig is push-only (every opcode ≤ OP_16).**
  Core (`script.cpp:182-204`): `while (pc < scriptSig.end()) { if
  (!GetOp(pc, opcode, vData)) return 0; if (opcode > OP_16) return
  0; } ... return subscript.GetSigOpCount(true);`. A P2SH spend
  with a non-push-only scriptSig (e.g. `OP_CHECKSIG <push>`) gets
  ZERO P2SH sigops. camlcoin (`validation.ml:543-565`): the loop
  `match Script.classify_script prev_spk with Script.P2SH_script _
  -> begin match extract_last_push_data inp.Types.script_sig with
  Some redeem_script -> ... acc + count_p2sh_sigops redeem_script *
  wsf ; None -> acc end | _ -> acc`. NO `is_push_only` gate before
  `extract_last_push_data` (`extract_last_push_data` happily skips
  non-push opcodes with `i := !i + 1` at line 456 of validation.ml).
  See BUG-W143-7.

- **G11: BIP-34 height — coinbase scriptSig starts with serialized
  `CScript() << nHeight` byte-for-byte.**
  Core (`validation.cpp:4154-4156`): `CScript expect = CScript() <<
  nHeight; if (block.vtx[0]->vin[0].scriptSig.size() < expect.size()
  || !std::equal(expect.begin(), expect.end(), block.vtx[0]->vin[0].scriptSig.begin())) return ...`.
  camlcoin (`validation.ml:279-292`): `Consensus.encode_height_in_coinbase
  height` produces the expected bytes; check `script_len <
  expected_len` then `Cstruct.equal expected actual`. **PARITY** for
  realistic heights (1..2^31-1); see G2 and BUG-W143-1.

- **G12: `CheckTransaction` called from per-tx AND per-block (flag if
  only one).**
  Core (`validation.cpp:3959-3967`): `CheckBlock` runs
  `CheckTransaction` on EVERY tx in the block. ALSO Core's
  `MemPoolAccept::PreChecks` runs `CheckTransaction` on the tx
  before mempool admission. camlcoin (`validation.ml:909-924`):
  `check_block` runs `check_transaction` on every tx in the block
  (line 918) with `~is_coinbase:(i = 0)`. `Mempool.accept_to_mempool`
  also calls `check_transaction` (verified via grep). **PARITY**.
  **No bug** on coverage.

- **G13: `bad-cb-amount` — coinbase value ≤ subsidy + fees.**
  Core (`validation.cpp:2610-2613`): `if (block.vtx[0]->GetValueOut() >
  blockReward && state.IsValid()) state.Invalid(...
  "bad-cb-amount" ...)`. camlcoin (`validation.ml:1781-1791` for
  fast path, `validation.ml:2034-2040` for full path): identical
  check. **PARITY**. **No bug** — see BUG-W143-8 for the related
  arithmetic-overflow latent issue.

- **G14: `bMutated` flag plumbing across hashing chain.**
  Core (`merkle.cpp:46-63` → `validation.cpp:3842-3858`): the
  mutated bool is plumbed from `ComputeMerkleRoot` through
  `BlockMerkleRoot` into `CheckMerkleRoot` where it triggers
  `BlockValidationResult::BLOCK_MUTATED` (a distinct enum value).
  camlcoin (`crypto.ml:359-386` → `validation.ml:864-866`): the
  flag is plumbed correctly, BUT see BUG-W143-2 on the loss of the
  BLOCK_MUTATED vs BLOCK_CONSENSUS distinction at the error-handling
  layer.

- **G15: BIP-30 / BIP-34 implies BIP-30 limit.**
  See G3. **No bug**.

### G16-G22: cross-cutting structural gates

- **G16: First-tx-is-coinbase, no-second-coinbase, vtx-non-empty
  ordering.**
  Core (`validation.cpp:3951-3955`): `if (block.vtx.empty() ||
  !block.vtx[0]->IsCoinBase()) return ... "bad-cb-missing"; for (i
  = 1; i < block.vtx.size(); i++) if (block.vtx[i]->IsCoinBase())
  return ... "bad-cb-multiple"`. camlcoin (`validation.ml:816-822`
  for empty + coinbase-first, `validation.ml:912` for no-second-coinbase):
  identical semantics. **PARITY**.

- **G17: `nSpendHeight` semantics for coinbase maturity (`COINBASE_MATURITY
  = 100`).**
  Core (`tx_verify.cpp:179`): `if (coin.IsCoinBase() && nSpendHeight
  - coin.nHeight < COINBASE_MATURITY)`. camlcoin
  (`validation.ml:1119`, `validation.ml:1672`, `validation.ml:1899`):
  `if utxo.is_coinbase && height - utxo.height <
  Consensus.coinbase_maturity` (= 100). **PARITY**.

- **G18: `IsFinalTx` cutoff selection.**
  Core (`validation.cpp:4140-4142`): `nLockTimeCutoff =
  enforce_locktime_median_time_past ? pindexPrev->GetMedianTimePast()
  : block.GetBlockTime();` — gated on `DEPLOYMENT_CSV`. camlcoin
  (`validation.ml:945-949`): `if csv_active then median_time else
  block.header.timestamp` — gated on `height >= network.csv_height`.
  Core's check is BIP-9 deployment-state (height of activation by
  signaling), camlcoin's is buried activation. For buried-activation
  networks (post-CSV), parity. **PARITY**.

- **G19: BIP-9 deployment-state vs buried-height for version gate.**
  Core (`validation.cpp:4113-4117`): `block.nVersion < 2 &&
  DeploymentActiveAfter(pindexPrev, chainman, DEPLOYMENT_HEIGHTINCB)`
  etc. camlcoin (`validation.ml:830-835`): `height >=
  network.bip34_height && Int32.compare block.header.version 2l < 0`.
  See BUG-W143-9 (subtle: post-buried-activation parity; for
  signaling-period blocks Core honours actual deployment state).

- **G20: Accumulated-fee MoneyRange (`bad-txns-accumulated-fee-outofrange`).**
  Core (`validation.cpp:2543-2547`): `if (!MoneyRange(nFees))
  state.Invalid(... "bad-txns-accumulated-fee-outofrange" ...)`.
  camlcoin (`validation.ml:1736-1737`, `validation.ml:1988-1989`):
  `if not (Consensus.is_valid_money !total_fees) then ...`. **PARITY**.

- **G21: Genesis special-case skip in `ConnectBlock`.**
  Core (`validation.cpp:2337-2343`): `if (block_hash ==
  params.GetConsensus().hashGenesisBlock) ... return true;` — skips
  ALL UTXO/script checks. camlcoin (`validation.ml:1478`): no
  genesis bypass. Production paths happen to work by coincidence
  (genesis has no inputs to look up; BIP-30 returns "not found";
  coinbase value 50 BTC ≤ subsidy(0)+0). See BUG-W143-10.

- **G22: Intra-block UTXO visibility for BIP-30.**
  Core (`validation.cpp:2467-2476`): `view.HaveCoin` sees outputs
  from earlier txs in the same block (because `UpdateCoins` runs as
  part of the loop). camlcoin (`validation.ml:1601`, `validation.ml:1852`):
  `check_bip30 ~lookup:base_lookup` — uses `base_lookup`, NOT the
  intra-block overlay. See BUG-W143-11.

### G23-G30: code-quality / drift / observability

- **G23: `MAX_FUTURE_BLOCK_TIME = 7200` duplicated.**
  Core: single constant. camlcoin: FOUR sites (validation.ml:984,
  sync.ml:233 named, sync.ml:837 literal, sync.ml:3830 literal).
  See BUG-W143-12.

- **G24: `MAX_PUBKEYS_PER_MULTISIG = 20` duplicated.**
  Core: `script.h`. camlcoin: `consensus.ml:51` + `script.ml:106`
  PLUS hardcoded `20` in `validation.ml:350`. See BUG-W143-13.

- **G25: `compute_wtxid` / `witness_merkle_root` triple-defined.**
  Core: single definition in `consensus/merkle.cpp`. camlcoin:
  `crypto.ml:392`, `mining.ml:211`, `validation.ml:649` (all three
  define `compute_wtxid` with slightly different signatures), AND
  `crypto.ml:411`, `mining.ml:222`, `validation.ml:660` for
  `compute_witness_merkle_root`. See BUG-W143-14.

- **G26: `Crypto.witness_merkle_root` is dead code (zero callers).**
  Grep confirms zero callers across `lib/` and `bin/`. See
  BUG-W143-15.

- **G27: `Validation.compute_wtxid` and `Validation.compute_witness_merkle_root`
  semantics differ from `Crypto.witness_merkle_root`.**
  `Validation.compute_wtxid` (`validation.ml:649`) takes an
  explicit `is_cb` boolean (POSITIONAL). `Crypto.compute_wtxid`
  (`crypto.ml:392`) determines coinbase-ness STRUCTURALLY via prevout-
  null check. The functions produce different results on a malformed
  block where vtx[0] is NOT a coinbase (e.g. constructed with vtx
  reordered). Core uses POSITIONAL (`merkle.cpp:80-82`); camlcoin's
  `Validation` (production) matches Core; camlcoin's `Crypto`
  (dead) does not. See BUG-W143-16.

- **G28: BLOCK_MUTATED vs BLOCK_CONSENSUS classification.**
  Core (`validation.cpp:3853-3858`):
  `state.Invalid(BLOCK_MUTATED, "bad-txns-duplicate" ...)`. The
  `BlockValidationResult` enum distinguishes
  `BLOCK_MUTATED` (potentially-recoverable corruption — block
  should NOT be marked permanently invalid) from
  `BLOCK_CONSENSUS` (deterministic consensus failure — mark
  permanently invalid). camlcoin: `BlockMutatedMerkle` is a
  `block_validation_error` variant alongside `BlockBadMerkleRoot`
  and others; there is no separate `BLOCK_MUTATED`-class signal to
  the caller. See BUG-W143-2.

- **G29: `block.fChecked` caching (CheckBlock idempotence).**
  Core (`validation.cpp:3922-3923,3979-3980`): `if (block.fChecked)
  return true;` plus `if (fCheckPOW && fCheckMerkleRoot)
  block.fChecked = true;` — avoids re-running structural checks on
  the same block. camlcoin: no equivalent caching. **P3** (perf
  only).

- **G30: `prev_block_time = 0l` fallback in BIP-94 timewarp check.**
  Core (`validation.cpp:4101`): `if (block.GetBlockTime() <
  pindexPrev->GetBlockTime() - MAX_TIMEWARP)` — `pindexPrev` is
  asserted non-null. camlcoin (`consensus.ml:837-843`): `header_time
  >= prev_block_time - max_timewarp`; callers default
  `prev_block_time = 0l` (`validation.ml:810`,
  `sync.ml:2157-2161`). For height=0 (genesis) this is fine; for
  non-genesis with unavailable parent the check becomes a no-op
  (since `0l - 600l = -600l` and any positive timestamp ≥ -600l).
  See BUG-W143-17.

## Bugs

### BUG-W143-1 (P3): `encode_height_in_coinbase` truncates at `height >= 0x80000000`

- **File**: `consensus.ml:783-812`
- **Core ref**: `script.h:341-372` (`CScriptNum::serialize`)
- **Description**: Core's `CScriptNum::serialize(n)` for positive `n`
  with magnitude MSB set appends an explicit 0x00 sign byte.
  camlcoin's `encode_height_in_coinbase` covers byte-counts 1..4 via
  fixed thresholds `<= 0x7f` / `<= 0x7fff` / `<= 0x7fffff` / `else 4`.
  These thresholds happen to match what Core needs for heights
  1..2^31-1 (verified by hand for 17, 128, 32767, 32768, 8388607,
  8388608, 2147483647). But for `height >= 0x80000000` (2_147_483_648),
  Core writes 5 bytes (4 magnitude + 1 explicit sign), camlcoin
  writes only 4 bytes. OCaml int is 63-bit on 64-bit systems, so
  this is technically reachable via adversarial test inputs; in
  practice no Bitcoin chain will reach height 2^31 in our lifetime.
- **Excerpt** (consensus.ml:798-812):
  ```ocaml
  else begin
    (* CScriptNum: length-prefixed sign-magnitude little-endian *)
    let bytes_needed =
      if height <= 0x7f then 1           (* 1 byte: 0x01-0x7f *)
      else if height <= 0x7fff then 2    (* 2 bytes: 0x80-0x7fff *)
      else if height <= 0x7fffff then 3  (* 3 bytes: 0x8000-0x7fffff *)
      else 4                             (* 4 bytes: larger values *)
    in
    let cs = Cstruct.create (1 + bytes_needed) in
    Cstruct.set_uint8 cs 0 bytes_needed;
    for i = 0 to bytes_needed - 1 do
      Cstruct.set_uint8 cs (1 + i) ((height lsr (8 * i)) land 0xFF)
    done;
    cs
  end
  ```
- **Impact**: cosmetic for realistic blockchains; adversarial test
  vectors that probe height=2^31 expose the divergence. The fix is
  trivial — extend the if-chain to `<= 0x7fffffff -> 4` else `5`
  (matching Core's explicit sign-byte append), or replace the
  bespoke encoder with a call to `Script.bytes_of_script_num`
  followed by length-prefixing. **The fact that two CScriptNum
  encoders coexist (`consensus.ml:783` and `script.ml:390`) is a
  two-pipeline guard pattern in itself.**

### BUG-W143-2 (P0-CDIV): `BlockMutatedMerkle` is not classified as recoverable / not-permanently-invalid

- **File**: `validation.ml:44,98,864-866,1543-1544`
- **Core ref**: `validation.cpp:3853-3858`,
  `consensus/validation.h` (`BlockValidationResult` enum)
- **Description**: Core's `CheckMerkleRoot` sets
  `BlockValidationResult::BLOCK_MUTATED` (a distinct enum value
  from `BLOCK_CONSENSUS`) when CVE-2012-2459 mutation is detected.
  The Chainstate caller (`validation.cpp:2321-2326`)
  ALSO treats CheckBlock-with-BLOCK_MUTATED as a `FatalError("Corrupt
  block found indicating potential hardware failure.")` — meaning
  the block is NOT marked permanently invalid, because it could be
  re-mined identically (its block hash is unchanged) once the
  malleation is cleared. camlcoin's `block_validation_error` is a
  flat sum type — `BlockMutatedMerkle` is just another variant
  alongside `BlockBadMerkleRoot`, `BlockBadDifficulty`, etc. The
  caller path treats them all the same: the block is marked
  permanently invalid via `BLOCK_FAILED_VALID` (`sync.ml:4347`
  references "B10 fix"). On a mutated block, camlcoin marks it
  permanently invalid; Core does NOT. A peer that re-mines the
  same block hash with the un-mutated transaction order can deliver
  the SAME block hash to Core (accepts) and camlcoin (rejects as
  `duplicate-invalid`).
- **Excerpt** (validation.ml:864-866):
  ```ocaml
  let (computed_merkle, mutated) = Crypto.merkle_root txids in
  if mutated then
    Error BlockMutatedMerkle
  ```
  And on the caller side at sync.ml:4347-4356 (paraphrased): on any
  Error from accept_block, the block is marked `BLOCK_FAILED_VALID`.
  No special-case for `BlockMutatedMerkle`.
- **Impact**: a malicious peer sends a CVE-2012-2459-mutated block
  whose un-mutated form is the canonical block; camlcoin marks the
  block hash permanently invalid, then refuses to accept the
  un-mutated form when re-served by another peer (`duplicate-invalid`
  in Core terminology). camlcoin is stuck off-chain until human
  intervention clears the block-failed entry. Core's BLOCK_MUTATED
  classification exists precisely to prevent this DoS vector.

### BUG-W143-3 (P2): `bad-blk-length` size check uses with-witness bytes against the wrong cap

- **File**: `validation.ml:884-891`
- **Core ref**: `validation.cpp:3947`,
  `consensus/consensus.h:13,15`
- **Description**: Core's `CheckBlock` size-limit check is
  `GetSerializeSize(TX_NO_WITNESS(block)) * WITNESS_SCALE_FACTOR >
  MAX_BLOCK_WEIGHT` — i.e., base (stripped) bytes × 4 against the
  4-million-weight cap. There is NO separate consensus gate against
  the raw with-witness serialized size; `MAX_BLOCK_SERIALIZED_SIZE`
  (4_000_000) is a P2P-message-size cap, not a CheckBlock gate.
  camlcoin (`validation.ml:884-891`) computes `Serialize.serialize_block`
  WITH witness data and gates `block_size > max_block_serialized_size
  (4_000_000)` as a separate check, BEFORE the per-tx-weight
  aggregate at line 896-900.
- **Excerpt** (validation.ml:884-891):
  ```ocaml
  (* Check raw serialized block size against the 4MB limit.
     This is separate from the weight limit and matches
     Bitcoin Core's MAX_BLOCK_SERIALIZED_SIZE check. *)
  let w_block = Serialize.writer_create () in
  Serialize.serialize_block w_block block;
  let block_size = Cstruct.length (Serialize.writer_to_cstruct w_block) in
  if block_size > Consensus.max_block_serialized_size then
    Error (BlockOversized block_size)
  ```
  The in-source comment is misleading: Core's `MAX_BLOCK_SERIALIZED_SIZE`
  is referenced in `validation.cpp` only for `BufferedFile` capacity
  (`validation.cpp:4969,4991`) — not as a CheckBlock gate.
- **Impact**: in MOST cases the camlcoin check and Core's
  base-size×4 check both reject the same blocks, but with different
  rejection reasons. Edge case: a block with base_size = 0.99 MB
  AND with-witness total = 4.01 MB (heavy witness, light base):
  - Core: base*4 = 3.96 MB ≤ 4 MB → passes G7. The weight check at
    L4179 catches it: 0.99*3 + 4.01 = 6.98 MB > 4 MB → `bad-blk-weight`.
  - camlcoin: 4.01 MB > 4 MB → camlcoin rejects with `BlockOversized`
    BEFORE running the weight check. Different rejection class
    but block rejected in both. **No consensus-divergent accept**.

  But this WRONG-cap pattern is a code-quality liability — if the
  hardcoded 4_000_000 ever needs to change (e.g. for a future
  hardfork), camlcoin would update one constant while Core uses a
  different one (or there is none). **Two-pipeline guard pattern**
  superimposed: a `MAX_BLOCK_SERIALIZED_SIZE` gate exists in
  camlcoin and not in Core; mind the drift.

### BUG-W143-4 (P0-CDIV): `check_block` does not enforce `time-too-new` (`MAX_FUTURE_BLOCK_TIME`)

- **File**: `validation.ml:808-975` (`check_block`),
  `validation.ml:1478-2042` (`validate_block_with_utxos`)
- **Core ref**: `validation.cpp:4108-4110`
- **Description**: Core's `ContextualCheckBlockHeader` enforces
  `block.Time() > NodeClock::now() + MAX_FUTURE_BLOCK_TIME (7200s)
  → time-too-new`. camlcoin's `check_block` does NOT enforce this —
  inspection of `validation.ml:808-975` shows only MTP and BIP-94
  timewarp; the future-time check lives in
  `Sync.validate_header` (sync.ml:837) and
  `Validation.check_block_header` (validation.ml:984), both called
  from upstream paths (P2P `process_new_block` calls
  `validate_header`; `submit_block` calls `check_block_header`).
- **Excerpt** (validation.ml:847-861, no future-time check):
  ```ocaml
  (* Check timestamp is after median time past (time-too-old).
     Reference: bitcoin-core/src/validation.cpp ContextualCheckBlockHeader:4092-4093. *)
  if block.header.timestamp <= median_time then
    Error BlockBadTimestamp
  (* BIP-94 timewarp protection: ... *)
  else if not (Consensus.check_timewarp_rule
                 ~height
                 ~header_time:block.header.timestamp
                 ~prev_block_time
                 ~network) then
    Error BlockTimeWarpAttack
  else begin
    (* Verify merkle root *)
  ```
- **Impact**: a block that passes the upstream header-check path
  (e.g. one constructed in unit tests, or processed via
  `Sync.try_attach_side_branch_and_reorg` whose path I have not
  traced, or any future caller of `accept_block` /
  `validate_block_with_utxos` that did not first call
  `Sync.validate_header`) silently bypasses the future-time gate.
  The defence-in-depth that Core provides by repeating the
  future-time check inside the `CheckBlock` family is missing.
  Easy fix: add a `time-too-new` check to `check_block` using
  `Consensus.max_future_block_time` (which does not yet exist —
  see BUG-W143-12).

### BUG-W143-5 (P2): `Sync.validate_header` and `Validation.check_block_header` are two-pipeline guards on the future-time rule

- **File**: `sync.ml:820-870`, `validation.ml:982-994`
- **Core ref**: `validation.cpp:4080-4121`
- **Description**: Core has ONE `ContextualCheckBlockHeader`
  function that gates `bad-diffbits`, `time-too-old`, BIP-94
  `time-timewarp-attack`, `time-too-new`, and `bad-version(...)`.
  camlcoin has TWO header-level gates with DIFFERENT coverage:
  - `Sync.validate_header` (sync.ml:820): PoW + future-time + MTP +
    BIP-94 timewarp + checkpoint.
  - `Validation.check_block_header` (validation.ml:982): future-time
    + PoW only. NO MTP, NO BIP-94, NO checkpoint.

  The submitblock path (`mining.ml:716-769`) calls
  `Validation.check_block_header` first, then `accept_block`. Since
  `accept_block` → `validate_block_with_utxos` → `check_block`
  DOES check MTP and BIP-94 (but NOT future-time per BUG-W143-4),
  the submitblock path effectively covers all rules — but split
  across multiple call sites.
- **Excerpt** (validation.ml:982-994):
  ```ocaml
  let check_block_header (header : Types.block_header) : (unit, string) result =
    (* Check that timestamp is not too far in the future *)
    let max_future_time = Int32.add (Int32.of_float (Unix.time ())) 7200l in  (* 2 hours *)
    if header.timestamp > max_future_time then
      Error "Block timestamp too far in future"
    else begin
      (* Check proof of work *)
      let block_hash = Crypto.compute_block_hash header in
      if not (Consensus.hash_meets_target block_hash header.bits) then
        Error "Block does not meet difficulty target"
      else
        Ok ()
    end
  ```
- **Impact**: pattern-recognition: two distinct functions both
  claim to validate "the header" but each implements a different
  subset of Core's `ContextualCheckBlockHeader` rules. Adding a
  new header-level rule (e.g. a future soft-fork's version
  signaling) requires updating BOTH paths. Drift risk → consensus
  divergence at the next protocol change. **Two-pipeline guard
  pattern** — fits the fleet-wide observation.

### BUG-W143-6 (P0-CDIV): `count_sigops` / `count_p2sh_sigops` zero on truncated-push parse failure

- **File**: `validation.ml:341-355` (`count_sigops`), `validation.ml:357-393`
  (`count_p2sh_sigops`), `script.ml:152-228` (`parse_script`)
- **Core ref**: `script.cpp:158-180` (`GetSigOpCount(fAccurate)`),
  `validation.cpp:3971-3977` (legacy block sigops gate)
- **Description**: Core's `CScript::GetSigOpCount` is best-effort —
  it `break`s at the first parse failure (`GetOp` returns false on
  truncated pushdata) but RETAINS all sigops counted before that
  point. camlcoin's `count_sigops` calls `Script.parse_script`,
  which RAISES `Failure "Truncated PUSHDATA"` on any truncated push;
  the surrounding `try ... with _ -> 0` then ZEROES the count for
  the whole script. The same pattern repeats in `count_p2sh_sigops`.
  Both `count_tx_sigops` (line 605, called by the legacy `CheckBlock`
  sigops gate at line 878-882) and `count_tx_sigops_cost` (line 523,
  called by the weighted ConnectBlock gate at lines 1635 / 1864)
  use `count_sigops` and `count_p2sh_sigops` internally.
- **Excerpt** (validation.ml:341-355):
  ```ocaml
  let count_sigops (script : Cstruct.t) : int =
    try
      let ops = Script.parse_script script in
      List.fold_left (fun count op ->
        match op with
        | Script.OP_CHECKSIG | Script.OP_CHECKSIGVERIFY ->
          count + 1
        | Script.OP_CHECKMULTISIG | Script.OP_CHECKMULTISIGVERIFY ->
          (* Worst case: 20 pubkeys *)
          count + 20
        | _ -> count
      ) 0 ops
    with _ ->
      (* If parsing fails, return 0 (unparseable scripts have no sigops) *)
      0
  ```
  Excerpt of `parse_script` (script.ml:163-168):
  ```ocaml
  | n when n >= 0x01 && n <= 0x4b ->
    if r.pos + n > len then failwith "Truncated PUSHDATA";
  ```
- **Impact**: an adversarial miner crafts a block that contains
  many transactions whose scriptSig or scriptPubKey is `OP_CHECKSIG`
  followed by a truncated push (e.g. `0xac 0x4c 0xff` — CHECKSIG +
  PUSHDATA1 with a length byte 0xff but zero data bytes remaining).
  Each such opcode is counted as 1 sigop by Core, 0 by camlcoin.
  - With 20_001 such opcodes in a block: Core's
    `legacy_sigops * 4 = 80_004 > 80_000` → REJECT `bad-blk-sigops`.
    camlcoin: 0 sigops → ACCEPT.
  - The weighted sigops gate at validation.ml:1639 / 1866 ALSO
    undercounts (`count_tx_sigops_cost` shares the broken counters).
  Result: camlcoin permanently forks off the canonical Bitcoin
  network at the first such block. **P0-CDIV — consensus divergence
  on adversarially-crafted block**.

### BUG-W143-7 (P2): `count_tx_sigops_cost` P2SH branch does not gate `is_push_only(scriptSig)`

- **File**: `validation.ml:543-565`
- **Core ref**: `script.cpp:182-204` (`CScript::GetSigOpCount(const
  CScript& scriptSig)`)
- **Description**: Core's `GetSigOpCount(scriptSig)` for a P2SH
  scriptPubKey iterates over the entire scriptSig; if ANY opcode
  has value > OP_16, the function returns 0 (no P2SH sigops
  counted). Only when scriptSig is entirely push-only does Core
  call `subscript.GetSigOpCount(true)` on the last push (the
  redeem script). camlcoin (`count_tx_sigops_cost` lines 552-562)
  unconditionally calls `extract_last_push_data inp.script_sig` —
  which skips non-push opcodes with `i := !i + 1` (validation.ml:456)
  — and then `count_p2sh_sigops redeem_script * wsf`. **No
  is_push_only gate.**
- **Excerpt** (validation.ml:550-562):
  ```ocaml
  match Script.classify_script prev_spk with
  | Script.P2SH_script _ ->
    begin match extract_last_push_data inp.Types.script_sig with
    | Some redeem_script ->
      (* Don't count P2SH sigops for P2SH-wrapped witness programs;
         those are counted separately via CountWitnessSigOps *)
      begin match Script.get_witness_program redeem_script with
      | Some _ -> acc  (* Witness program, skip P2SH count *)
      | None -> acc + count_p2sh_sigops redeem_script * wsf
      end
    | None -> acc
    end
  | _ -> acc
  ```
- **Impact**: a tx with a non-push-only P2SH scriptSig (e.g.
  `OP_CHECKSIG <push>`) is itself going to FAIL script verification
  in both Core and camlcoin (Core's `VerifyScript` line 2055
  enforces `scriptSig.IsPushOnly()` for P2SH). But the sigops
  gates run BEFORE script verification:
  - Core counts 0 P2SH sigops on this scriptSig.
  - camlcoin counts `count_p2sh_sigops redeem_script * 4` P2SH
    sigops.

  If a single such tx has a 20_001-sigop redeem-script-shaped
  blob as its "last push", camlcoin's accumulator hits
  `total_sigops_cost = 80_004 > 80_000` → rejects the block with
  `BlockTooManySigops`. Core would NOT reject for sigops (counts 0)
  but instead reject at script verification with
  `block-script-verify-flag-failed (SCRIPT_ERR_SIG_PUSHONLY)`.
  Same outcome (rejection), different reject_reason. **P2** —
  observable via reject-reason fingerprinting on regtest probes;
  same final acceptance.

### BUG-W143-8 (P2): `bad-cb-amount` arithmetic chain relies on upstream invariants for Int64 safety

- **File**: `validation.ml:2034-2040`, `validation.ml:1781-1791`
- **Core ref**: `validation.cpp:2611-2613` (`bad-cb-amount`)
- **Description**: camlcoin's `bad-cb-amount` check computes
  `max_coinbase = Int64.add (Consensus.block_subsidy_for_network
  ... height) !total_fees` and `coinbase_value = List.fold_left
  (fun acc out -> Int64.add acc out.Types.value) 0L coinbase.outputs`.
  Neither is overflow-guarded. In production, upstream
  `check_transaction` (line 197-208) gates per-output and
  cumulative-output MoneyRange, and `is_valid_money !total_fees`
  is checked (line 1736, 1988) — so the inputs to this `Int64.add`
  are guaranteed `<= MAX_MONEY < INT64_MAX/4`, no overflow can
  occur. But the invariant is implicit — a refactor that
  reorders the validation pipeline (e.g. moving the coinbase
  value check before `check_transaction`) would silently introduce
  an unsigned-wrap vulnerability.
- **Excerpt** (validation.ml:2034-2040):
  ```ocaml
  let coinbase = List.hd block.transactions in
  let coinbase_value = List.fold_left (fun acc out ->
    Int64.add acc out.Types.value
  ) 0L coinbase.outputs in
  let max_coinbase = Int64.add (Consensus.block_subsidy_for_network network.network_type height) !total_fees in
  if coinbase_value > max_coinbase then
    Error (BlockBadCoinbaseValue (coinbase_value, max_coinbase))
  ```
- **Impact**: production-safe today; latent fragility if the
  validation pipeline order changes. Better: use
  `tx.GetValueOut()` equivalent (with explicit MoneyRange enforcement
  inline) or assert `is_valid_money coinbase_value` and
  `is_valid_money max_coinbase` before the comparison.

### BUG-W143-9 (P2): version-bits gate uses buried height instead of BIP-9 deployment state

- **File**: `validation.ml:830-835`
- **Core ref**: `validation.cpp:4112-4118`
- **Description**: Core's version gate uses BIP-9
  `DeploymentActiveAfter(pindexPrev, chainman, DEPLOYMENT_HEIGHTINCB /
  DERSIG / CLTV)` — the *deployment* status as of the parent block,
  which on mainnet is buried by activation height but on historical
  signaling-period blocks is determined by MTP-window signaling.
  camlcoin's check uses `height >= network.bip34_height` — buried
  activation only. For all modern blocks, both give identical
  answers (since BIP-9 long-since flipped to ACTIVE). For
  historical replay of signaling-period blocks (before BIP-34 was
  buried in Bitcoin Core kernel 0.21), camlcoin could disagree.
  Practically, this matters only for historical reindex of an
  archived chain that includes the signaling window. **P2**.
- **Excerpt** (validation.ml:830-835):
  ```ocaml
  if height >= network.bip34_height && Int32.compare block.header.version 2l < 0 then
    Error BlockBadVersion
  else if height >= network.bip66_height && Int32.compare block.header.version 3l < 0 then
    Error BlockBadVersion
  else if height >= network.bip65_height && Int32.compare block.header.version 4l < 0 then
    Error BlockBadVersion
  ```
- **Impact**: historic reindex of pre-buried-activation blocks
  could diverge. Production IBD using shipped buried-activation
  heights is parity.

### BUG-W143-10 (P3): no genesis-block bypass in `validate_block_with_utxos`

- **File**: `validation.ml:1478-2042`
- **Core ref**: `validation.cpp:2337-2343`
- **Description**: Core's `ConnectBlock` short-circuits genesis:
  `if (block_hash == hashGenesisBlock) { view.SetBestBlock(...);
  return true; }` — skips all UTXO checks. camlcoin's
  `validate_block_with_utxos` runs the full validation pipeline
  on genesis. Production paths happen to "work" by coincidence:
  - Genesis has 0 inputs, so the BIP-30 / sigops / script /
    sequence-lock loops do nothing.
  - The single coinbase has value 50 BTC == subsidy(0), passes
    `bad-cb-amount`.
  - BIP-30 `check_bip30 ~lookup:base_lookup` on the coinbase txid
    returns true (not found in pre-genesis UTXO set).
- **Impact**: no consensus divergence today; fragile under future
  refactors (e.g., if `block_subsidy(0)` is changed to 0 for some
  reason). Better hygiene: explicit `if height = 0 then return Ok
  ...` short-circuit mirroring Core.

### BUG-W143-11 (P3): BIP-30 lookup uses `base_lookup`, not the intra-block overlay

- **File**: `validation.ml:1601-1603`, `validation.ml:1852-1854`
- **Core ref**: `validation.cpp:2467-2476`
- **Description**: Core's BIP-30 check uses `view.HaveCoin(COutPoint(tx->GetHash(),
  o))` where `view` is the running `CCoinsViewCache` that has had
  `UpdateCoins` applied for every preceding tx in the current
  block. So a tx-N within the same block that shares a txid with
  an earlier tx-M's output WILL be caught by Core's BIP-30 check.
  camlcoin's check at lines 1601-1603 / 1852-1854 uses
  `base_lookup`, NOT the intra-block-aware `lookup`. So a same-block
  txid collision is missed. This is so extreme an edge case that
  it requires sha256d collision (effectively impossible).
- **Excerpt** (validation.ml:1601-1603):
  ```ocaml
  if bip30_should_enforce ~network ~height ... then begin
    let n_outputs = List.length tx.outputs in
    if not (check_bip30 ~lookup:base_lookup ~txid ~n_outputs) then
      error := Some (BlockTxValidationFailed (i, TxDuplicateTxid))
  end
  ```
- **Impact**: theoretical only (would require sha256d collision
  within a single block). Negligible. **P3**.

### BUG-W143-12 (P2): `MAX_FUTURE_BLOCK_TIME = 7200` is hardcoded in 4 sites with no canonical constant

- **File**: `validation.ml:984`, `sync.ml:233` (named),
  `sync.ml:837` (literal `7200.0`), `sync.ml:3830` (literal
  `7200.0`)
- **Core ref**: Bitcoin Core's `MAX_FUTURE_BLOCK_TIME` is a single
  named constant in `consensus/consensus.h` (or `validation.h`).
- **Description**: camlcoin duplicates the literal `7200`
  representation across FOUR sites:
  - `validation.ml:984`: `let max_future_time = Int32.add
    (Int32.of_float (Unix.time ())) 7200l` — `int32` form.
  - `sync.ml:233`: `let max_future_block_time_secs = 7200` —
    named, but only used inside sync.ml.
  - `sync.ml:837`: `Int32.to_float header.timestamp >
    Unix.gettimeofday () +. 7200.0` — `float` literal.
  - `sync.ml:3830`: `... Unix.gettimeofday () +. 7200.0` — `float`
    literal again.

  There is no canonical `Consensus.max_future_block_time` constant
  binding these together.
- **Impact**: if Bitcoin ever changes the future-time bound (it
  has been a consensus parameter since 2009), camlcoin would need
  to update 4 places — easy to miss one, causing inconsistent
  behaviour between submitblock (uses validation.ml:984) and P2P
  (uses sync.ml:837). **Drift risk → consensus drift.** Fix: add
  `let max_future_block_time = 7200` to `consensus.ml`, reference
  everywhere.

### BUG-W143-13 (P2): `MAX_PUBKEYS_PER_MULTISIG = 20` is defined twice and hardcoded once

- **File**: `consensus.ml:51` + `script.ml:106` (both define
  `max_pubkeys_per_multisig = 20`), AND `validation.ml:350`
  hardcodes `count + 20`.
- **Core ref**: single definition in `script.h`.
- **Description**: same drift pattern as BUG-W143-12 but on
  multisig pubkey count. `consensus.ml:51` and `script.ml:106`
  agree (`20`), but `validation.ml:350` uses the literal `20`
  for OP_CHECKMULTISIG sigop counting in `count_sigops`:
  ```ocaml
  | Script.OP_CHECKMULTISIG | Script.OP_CHECKMULTISIGVERIFY ->
    (* Worst case: 20 pubkeys *)
    count + 20
  ```
- **Impact**: if Bitcoin ever raises or lowers
  `MAX_PUBKEYS_PER_MULTISIG`, all three sites need updating.
  **Drift risk**. Fix: reference `Consensus.max_pubkeys_per_multisig`
  from `validation.ml:350`.

### BUG-W143-14 (P2): `compute_wtxid` defined three times, `witness_merkle_root` defined three times

- **File**: `crypto.ml:392`, `mining.ml:211`, `validation.ml:649`
  for `compute_wtxid`; `crypto.ml:411`, `mining.ml:222`,
  `validation.ml:660` for `(compute_)witness_merkle_root`.
- **Core ref**: single definitions in
  `consensus/merkle.cpp:76-85` for `BlockWitnessMerkleRoot`, and
  `primitives/transaction.h::GetWitnessHash` for the per-tx wtxid.
- **Description**: triple-duplicated logic. All three versions
  produce identical results for production-shape blocks, but
  semantics differ on malformed input (see BUG-W143-16). **Two-
  (here three-) pipeline guard pattern**.
- **Impact**: drift risk on any future BIP-witness-protocol
  change (e.g. a hypothetical wtxid-format upgrade for cross-input
  signatures). Three definitions to update; easy to miss one.
  Fix: extract a single canonical helper to `crypto.ml` (positional
  semantics), retire the others.

### BUG-W143-15 (P3): `Crypto.witness_merkle_root` is dead code (zero callers)

- **File**: `crypto.ml:411-413`
- **Core ref**: N/A (Core has only one definition).
- **Description**: `grep -rn "Crypto.witness_merkle_root"` in
  `lib/` and `bin/` returns zero matches. The function is exported
  but unused. **Dead module pattern**.
- **Impact**: dead code accretion; future contributors may resurrect
  it unintentionally and inherit the structural-coinbase-detection
  bug at BUG-W143-16. Fix: delete it; route any future callers to
  `Validation.compute_witness_merkle_root`.

### BUG-W143-16 (P2): `Crypto.witness_merkle_root` uses structural coinbase detection (would diverge on malformed blocks if it had any caller)

- **File**: `crypto.ml:392-413`
- **Core ref**: `consensus/merkle.cpp:76-85` —
  `BlockWitnessMerkleRoot` uses POSITIONAL leaf zero (`leaves.emplace_back()`
  before the `for (s = 1; ...)` loop).
- **Description**: `Crypto.witness_merkle_root` calls
  `List.map compute_wtxid txs`, and `Crypto.compute_wtxid`
  (`crypto.ml:392-406`) determines is_coinbase STRUCTURALLY (vin
  single null-prevout shape). For a malformed block where vtx[0]
  is not a coinbase but vtx[3] IS, `Crypto.witness_merkle_root`
  would compute leaf 0 from vtx[0]'s real wtxid and leaf 3 as
  zero — diverging from Core's POSITIONAL "leaf 0 is zero,
  leaves 1..n are real wtxids".
- **Excerpt** (crypto.ml:392-413):
  ```ocaml
  let compute_wtxid (tx : Types.transaction) : Types.hash256 =
    let is_coinbase = match tx.inputs with
      | [inp] ->
        Cstruct.equal inp.previous_output.txid Types.zero_hash
        && inp.previous_output.vout = 0xFFFFFFFFl
      | _ -> false
    in
    if is_coinbase then
      Types.zero_hash
    else ...

  let witness_merkle_root (txs : Types.transaction list) : Types.hash256 =
    let wtxids = List.map compute_wtxid txs in
    fst (merkle_root wtxids)
  ```
- **Impact**: latent. If any future caller wires this in instead
  of `Validation.compute_witness_merkle_root` (which IS positional
  at validation.ml:662-664), the block-acceptance pipeline would
  silently accept malformed blocks that Core rejects.

### BUG-W143-17 (P3): `prev_block_time = 0l` default makes BIP-94 timewarp check a no-op when parent is unknown

- **File**: `validation.ml:810` (default param),
  `sync.ml:2157-2161` (`get_prev_block_time` returns `0l` on
  missing parent), `consensus.ml:836-843`
- **Core ref**: `validation.cpp:4097-4104`,
  `validation.cpp:4083` (`assert(pindexPrev != nullptr)`)
- **Description**: Core asserts non-null `pindexPrev` in
  `ContextualCheckBlockHeader`; the assertion holds by construction
  because `AcceptBlockHeader` rejects unknown-prev with
  `prev-blk-not-found` before this check runs. camlcoin's
  `check_block` accepts `prev_block_time = 0l` as a default
  argument and falls back to it whenever the caller cannot supply
  a value (e.g. `Sync.get_prev_block_time` returns `0l` if the
  parent header is missing). The BIP-94 timewarp check
  (`consensus.ml:842-843`) then becomes:
  `Int32.compare header_time (Int32.sub 0l 600l) >= 0` =
  `Int32.compare header_time (-600l) >= 0` — true for any positive
  timestamp. **The check effectively turns into a no-op when
  prev_block_time is unknown.**
- **Excerpt** (consensus.ml:836-843):
  ```ocaml
  let check_timewarp_rule ~(height : int) ~(header_time : int32)
      ~(prev_block_time : int32) ~(network : network_config) : bool =
    if not network.enforce_bip94 then true
    else if height mod difficulty_adjustment_interval <> 0 then true
    else
      Int32.compare header_time
        (Int32.sub prev_block_time (Int32.of_int max_timewarp)) >= 0
  ```
- **Impact**: in normal operation the parent is always known and
  `prev_block_time` is real. But if a caller path is added in the
  future that runs `check_block` before the parent is available,
  BIP-94 silently disables. Fix: change the signature to `?(prev_block_time
  : int32 option = None)` and `Error _` (or `assert`) when
  height > 0 and parent_time is None.

### BUG-W143-18 (P2): `bytes_of_script_num` and `encode_height_in_coinbase` are two separate CScriptNum encoders

- **File**: `consensus.ml:783` (`encode_height_in_coinbase`),
  `script.ml:390` (`bytes_of_script_num`)
- **Core ref**: single `CScriptNum::serialize` in `script.h:341-372`.
- **Description**: camlcoin has two distinct encoders for CScriptNum:
  - `bytes_of_script_num` (script.ml:390-419) — generic, used by
    OP_*-evaluation paths.
  - `encode_height_in_coinbase` (consensus.ml:783-812) — specialized
    for BIP-34 coinbase height encoding, returns the LENGTH-PREFIXED
    push form.

  The two encoders agree by accident (verified by hand for several
  heights in G2 above) but their byte-count windows are coded
  separately. Drift risk: a future change to one without the other.
- **Impact**: subtle parity-preserving redundancy that, if
  decohered, would produce divergent BIP-34 height encodings.
  Fix: implement `encode_height_in_coinbase` as `let cs =
  bytes_of_script_num (Int64.of_int height) in let result =
  Cstruct.create (1 + Cstruct.length cs) in ... write length byte,
  then bytes`. Single source of truth.

### BUG-W143-19 (P2): `count_block_sigops_cost` is dead code on the consensus path

- **File**: `validation.ml:596-601`
- **Core ref**: `validation.cpp:2522,2568` —
  `nSigOpsCost` is accumulated per-tx inside the ConnectBlock loop
  with early break, not via a separate "compute block sigops cost"
  helper.
- **Description**: `count_block_sigops_cost` (validation.ml:596)
  computes the sum across all txs in a block. Grep for callers
  shows the function is exported but its only call site is inside
  test code (and possibly mining template). The production path
  in `validate_block_with_utxos` accumulates per-tx into
  `total_sigops_cost` with early-break (mirroring Core's
  short-circuit at validation.cpp:2569). **Dead-helper-at-call-site**
  pattern (fits W141's archetype: function exists, exported,
  perhaps called by tests, but absent from the canonical production
  path).
- **Impact**: drift risk — if `count_block_sigops_cost` is ever
  wired into the production path it would lose the short-circuit
  optimization Core has. Fix: delete it, or document that it is
  for testing/RPC only.

### BUG-W143-20 (P1): ordering of `check_coinbase` BIP-34 height check vs `CheckMerkleRoot`

- **File**: `validation.ml:825,864`
- **Core ref**: `validation.cpp:3935-3938,4151-4159`
- **Description**: Core's ordering inside the
  CheckBlock + ContextualCheckBlock pipeline is:
  1. `CheckMerkleRoot` (BLOCK_MUTATED-distinguishing)
  2. structural (vtx-empty, coinbase-first, no-second-coinbase)
  3. per-tx `CheckTransaction`
  4. legacy sigops
  5. `ContextualCheckBlock`'s BIP-34 height check (`bad-cb-height`).

  camlcoin's `check_block` ordering:
  1. vtx-empty
  2. coinbase-first
  3. `check_coinbase` (which CONTAINS the BIP-34 height check)
  4. version bits
  5. difficulty
  6. MTP / BIP-94
  7. merkle root
  8. dup-txids
  9. legacy sigops
  10. size
  11. weight
  12. per-tx `check_transaction`
  13. witness commitment
  14. per-tx IsFinalTx (post-CSV: MTP locktime cutoff).

  Notice camlcoin runs the BIP-34 height check (inside `check_coinbase`
  at validation.ml:825) BEFORE `CheckMerkleRoot` (validation.ml:864).
  Core runs them the other way round. If a block has BOTH a
  malformed coinbase height encoding AND a mutated merkle tree,
  Core returns `BLOCK_MUTATED` (recoverable); camlcoin returns
  `BlockTxValidationFailed(0, TxBadCoinbase)` (permanent invalid).
- **Excerpt** (validation.ml:824-826):
  ```ocaml
  (* Validate coinbase structure *)
  match check_coinbase ~network coinbase height with
  | Error e -> Error (BlockTxValidationFailed (0, e))
  | Ok () ->
  ```
- **Impact**: stacks with BUG-W143-2 (BLOCK_MUTATED classification).
  A peer crafts a block whose un-mutated form has the correct BIP-34
  height and merkle root; the mutated form has the same merkle
  root (CVE-2012-2459) AND camlcoin's check_coinbase sees the
  un-mutated coinbase script first → passes → moves to merkle →
  detects mutation → marks permanent-invalid. Re-served by another
  peer, camlcoin refuses with `duplicate-invalid`. Same overall
  DoS as BUG-W143-2.

### BUG-W143-21 (P2): `is_coinbase` parameter to `check_transaction` is positional, not structural

- **File**: `validation.ml:172-238`, `validation.ml:909-918`
  (call site)
- **Core ref**: `consensus/tx_check.cpp:47-57` —
  `CheckTransaction` uses `tx.IsCoinBase()` (structural: vin
  single null-prevout) to decide whether to skip the
  `bad-txns-prevout-null` check.
- **Description**: Core's `CheckTransaction` uses
  `tx.IsCoinBase()` (structural) to decide whether to:
  - apply the 2..100 byte scriptSig length check
    (`bad-cb-length`).
  - skip the null-prevout check for the inputs.

  camlcoin's `check_transaction` takes an `~is_coinbase` boolean
  parameter and the caller at validation.ml:918 passes
  `~is_coinbase:(i = 0)` (POSITIONAL). For vtx[0] that is
  structurally a non-coinbase (e.g. vin.size() != 1, or vin[0]
  has non-null prevout), `check_block`'s prior gate at line
  821 (`if not (is_coinbase coinbase) then BlockNoCoinbase`)
  catches this — so by the time `check_transaction ~is_coinbase:true`
  is called on vtx[0], it IS structurally a coinbase. **Parity in
  practice**, but fragile: a future refactor that removes the
  vtx[0]-is-coinbase precondition (e.g., calling check_transaction
  in a different context) would silently accept a non-coinbase
  with null prevout because the `~is_coinbase:true` parameter
  skips the null-prevout check. **Defense-in-depth missing**.
- **Impact**: code-quality / refactor-safety. Fix: have
  `check_transaction` consult `is_coinbase_tx tx` internally
  instead of accepting the parameter.

### BUG-W143-22 (P3): comment-as-confession: `check_block` weight aggregator omits header + tx-count varint

- **File**: `validation.ml:893-900`
- **Core ref**: `validation.cpp:4179`, `consensus/validation.h:136-139`
- **Description**: Restated from W142 BUG-1 — the comment at
  validation.ml:893-895 says *"Bitcoin Core's CheckBlock does NOT
  include the block header or txcount varint in the weight."*
  This is INCORRECT. Core's `GetBlockWeight` (consensus/validation.h:136-139)
  is `GetSerializeSize(TX_NO_WITNESS(block))*3 +
  GetSerializeSize(TX_WITH_WITNESS(block))` — and `GetSerializeSize`
  of a CBlock serialises header (80 bytes) + tx-count varint +
  every tx. Camlcoin's aggregator omits header*4 (=320) and
  tx-count varint*4 (=4..36). **Comment-as-confession pattern**
  (W142 BUG-1 already catalogued).
- **Excerpt** (validation.ml:893-900):
  ```ocaml
  (* Check total block weight: sum of individual transaction
     weights only. Bitcoin Core's CheckBlock does NOT include
     the block header or txcount varint in the weight. *)
  let total_weight = List.fold_left (fun acc tx ->
    acc + compute_tx_weight tx
  ) 0 txs in
  if total_weight > Consensus.max_block_weight then
    Error (BlockOverweight total_weight)
  ```
- **Impact**: same as W142 BUG-1 — adversarial block with Σ
  tx_weight = 4_000_000 accepts in camlcoin, rejects in Core
  (since header+txcount adds ~324..356 weight).

### BUG-W143-23 (P2): `check_witness_commitment` and `check_block` weight check are split across two helper functions

- **File**: `validation.ml:690-734`, `validation.ml:893-900`
- **Core ref**: `validation.cpp:4169,4179` — both inside
  `ContextualCheckBlock`, in the order `CheckWitnessMalleation`
  then `GetBlockWeight`.
- **Description**: Core runs `CheckWitnessMalleation` BEFORE the
  `bad-blk-weight` check because the witness commitment is part
  of the coinbase output AND the coinbase scriptWitness — both of
  which contribute to weight. Specifically, the comment at
  Core's validation.cpp:4173-4178 notes: *"After the coinbase
  witness reserved value and commitment are verified, we can
  check if the block weight passes (before we've checked the
  coinbase witness, it would be possible for the weight to be too
  large by filling up the coinbase witness, which doesn't change
  the block hash, so we couldn't mark the block as permanently
  failed)."* camlcoin (`check_block`:884-935) runs the weight
  check at line 896-900 BEFORE `check_witness_commitment` at line
  935. **Ordering inverted relative to Core.**
- **Excerpt** (validation.ml ordering):
  ```
  line 884-891: serialized size check (BUG-W143-3)
  line 893-900: total weight check (BUG-W143-22)
  line 908-924: per-tx check_transaction
  line 934-936: check_witness_commitment   ← runs AFTER weight
  ```
- **Impact**: a malicious peer crafts a block whose body weight
  is at the cap, then balloons the coinbase scriptWitness with
  arbitrary bytes to push weight just over the cap. Core's
  ordering means the block fails `bad-blk-weight` AFTER the
  witness commitment passes — Core marks BLOCK_CONSENSUS
  (permanent invalid) because the block hash is fixed and
  re-mining yields the same hash. camlcoin's ordering means the
  block fails `BlockOverweight` BEFORE the witness commitment is
  checked — but the block hash doesn't change with witness
  malleability, so the permanent-invalid mark applies the same
  way. Practically equivalent outcome, but Core's comment
  explicitly justifies this ordering for hash-stability under
  witness malleation. camlcoin loses this guarantee. **P2**.

### BUG-W143-24 (P3): `Validation.check_block_header` uses `Unix.time ()` directly instead of a network-time-adjusted clock

- **File**: `validation.ml:984`
- **Core ref**: `validation.cpp:4108` — `NodeClock::now()` (a
  mockable wall clock, not network-adjusted in modern Core; the
  old `GetAdjustedTime()` was removed).
- **Description**: camlcoin uses `Unix.time ()` directly. Core
  uses `NodeClock::now()` which is mockable via system-clock
  facilities for testing. The functional behaviour matches
  modern Core (no peer-time-offset adjustment); the difference
  is purely the testability surface. **P3**.
- **Impact**: tests cannot mock the system clock to validate
  future-time edge cases. Fix: thread a `~now` callback through
  the check.

### BUG-W143-25 (P2): coinbase value summation re-runs per tx loop, separately from CheckTransaction's cumulative check

- **File**: `validation.ml:2035-2037`, `validation.ml:2034`
- **Core ref**: `validation.cpp:2611` — `block.vtx[0]->GetValueOut()`
  is a single method call returning a cached `nValueOut`.
- **Description**: camlcoin iterates over `coinbase.outputs` twice:
  once in `check_transaction` (line 191-209, for MoneyRange) and
  again in `validate_block_with_utxos` (line 2035-2037, for the
  `bad-cb-amount` comparison). For Core the per-tx
  CheckTransaction already runs `GetValueOut()` internally and
  caches `nValueOut`. **Performance**, not consensus. **P2 perf**.
- **Impact**: negligible (coinbase has 1-2 outputs typically);
  symptom of the broader two-pipeline-guard pattern.

### BUG-W143-26 (P3): no separate `BLOCK_TIME_FUTURE` classification for future-time rejects

- **File**: `validation.ml:982-994` returns generic `string` Error;
  `sync.ml:837` returns generic `string` Error.
- **Core ref**: `validation.cpp:4109` —
  `BlockValidationResult::BLOCK_TIME_FUTURE` is a distinct enum
  value, allowing peers to be banned differently for
  `time-too-new` (transient — peer's clock may be wrong) vs
  `bad-version` (deterministic — peer's software is wrong).
- **Description**: camlcoin returns a string-typed `Error _`
  from both header check functions, losing the classification.
  Mirrors W141 / earlier audits' pattern: error reasons are
  flattened to strings instead of typed enums. **P3**.
- **Impact**: peer-banning policy loses precision; `time-too-new`
  peers get banned identically to `bad-version` peers.

### BUG-W143-27 (P3): `bip30_should_enforce` Gate 4 silently skips BIP-30 when `bip34_hash = None`

- **File**: `validation.ml:1460-1464`
- **Core ref**: `validation.cpp:2460-2462` —
  `pindexBIP34height = pindex->pprev->GetAncestor(params.GetConsensus().BIP34Height)`,
  then `fEnforceBIP30 = fEnforceBIP30 && (!pindexBIP34height ||
  !(pindexBIP34height->GetBlockHash() == params.GetConsensus().BIP34Hash))`.
- **Description**: camlcoin's gate skips BIP-30 when
  `bip34_hash = None` *because* the network is testnet4 / regtest
  where BIP-34 is active from genesis. This matches Core's
  intent for those networks (where the ancestor lookup at
  BIP34Height=1 returns the parent or genesis itself, and the
  hash check trivially evaluates to "BIP-34 active"). But the
  fallback "BIP-30 silently skipped" assumes the network has no
  pre-BIP34 window — which is encoded in the `bip34_hash = None`
  state alone. A future network config that sets
  `bip34_hash = None` for a network WITH a pre-BIP34 window
  would silently disable BIP-30. **Defense-in-depth missing**.
- **Excerpt** (validation.ml:1460-1465):
  ```ocaml
  else if height >= network.Consensus.bip34_height
          && height < bip34_implies_bip30_limit
          && network.Consensus.bip34_hash = None then
    false  (* bip34_hash=None means BIP34 active from genesis (testnet4/regtest);
              no pre-BIP34 window exists, so BIP30 violations are impossible *)
  ```
- **Impact**: latent fragility; current network configs are safe.
  Fix: explicit `bip34_active_from_genesis : bool` flag instead of
  inferring from `bip34_hash = None`.

### BUG-W143-28 (P2): coinbase BIP-34 height check does not re-encode the height precisely as Core does for non-canonical height representations

- **File**: `validation.ml:279-292`,
  `consensus.ml:783-812`
- **Core ref**: `validation.cpp:4154-4156` — `CScript() <<
  nHeight` produces THE canonical encoding via `push_int64`.
  Any deviation (e.g. non-minimal CScriptNum) means the
  byte-equality `std::equal(expect.begin(), expect.end(),
  block.vtx[0]->vin[0].scriptSig.begin())` fails.
- **Description**: camlcoin's `encode_height_in_coinbase` produces
  the canonical encoding only. If a block's coinbase scriptSig has
  a NON-CANONICAL height representation (e.g. extra leading zero
  bytes, or magnitude with explicit sign byte when not needed),
  camlcoin's byte-equality check correctly rejects it. **PARITY**.
  *However*, the `encode_height_in_coinbase` for heights up to
  16 emits `OP_1..OP_16` (`0x51 + height`); Core's `push_int64`
  for height 17 falls to `CScriptNum::serialize(17)` which
  produces `[0x11]`, then the surrounding `operator<<` adds the
  push prefix `0x01` → `[0x01, 0x11]`. camlcoin's encoder for
  17 produces `[0x01, 0x11]`. ✓. **No bug** on this gate.

  But: for height **0** (only possible for the genesis block,
  which Core does NOT subject to BIP-34), camlcoin's encoder
  produces `[0x00]` (OP_0). camlcoin's caller gates on
  `height >= network.bip34_height`, which for mainnet is 227931,
  so this branch is never taken for genesis on mainnet. On
  testnet4/regtest where `bip34_height = 1`, genesis is height 0
  and the gate `height >= 1` is FALSE → check skipped. ✓.

  Conclusion: **encoding-side parity verified**. **No bug**.

### BUG-W143-29 (P3): `count_witness_sigops` delegates to `count_p2sh_sigops`, sharing the malformed-script bug

- **File**: `validation.ml:395-398`
- **Core ref**: `interpreter.cpp:2129-2132` —
  `subscript.GetSigOpCount(true)` for P2WSH witness scripts.
- **Description**: `count_witness_sigops` is a one-line delegate
  to `count_p2sh_sigops` — which means the BUG-W143-6 zero-on-
  parse-failure semantics also apply to P2WSH witness-script
  sigops counting. A P2WSH spend whose witness script has a
  truncated push undercounts in camlcoin. Same class of P0-CDIV
  as BUG-W143-6. **Folded into BUG-W143-6** rather than re-
  catalogued.
- **Impact**: same as BUG-W143-6.

### BUG-W143-30 (P2): `is_coinbase` global alias (`validation.ml:249`) shadows the parameter name

- **File**: `validation.ml:172,241,249`
- **Core ref**: N/A (style).
- **Description**: `let is_coinbase = is_coinbase_tx` at line 249
  creates a global alias. The same identifier `is_coinbase` is
  also used as a labelled parameter name in `check_transaction`
  (line 172). OCaml's lexical scoping handles this correctly,
  but the shadowing is confusing and error-prone — a reader
  might assume `is_coinbase` inside `check_transaction` refers
  to the global structural detector rather than the boolean
  parameter. **P2 readability**.
- **Impact**: cosmetic / style.

## Summary

### Severity tally

| Severity | Count | BUGs |
|----------|-------|------|
| P0-CONSENSUS | 0 | — |
| P0-CDIV | 3 | W143-2 (BLOCK_MUTATED classification), W143-4 (`check_block` does not gate time-too-new), W143-6 (sigops zero-on-parse-failure) |
| P0-SEC | 0 | — |
| P1 | 1 | W143-20 (ordering of BIP-34 vs merkle) |
| P2 | 14 | W143-3, W143-5, W143-7, W143-8, W143-9, W143-12, W143-13, W143-14, W143-19, W143-21, W143-23, W143-25, W143-27, W143-30 |
| P3 | 9 | W143-1, W143-10, W143-11, W143-15, W143-16, W143-17, W143-22, W143-24, W143-26, W143-29 (folded) |

### Top-3 representative findings

1. **BUG-W143-6 (P0-CDIV)**: `count_sigops` zeroes on parse failure
   — `try parse_script ... with _ -> 0`. A block with 20_001
   `OP_CHECKSIG`+truncated-push opcodes legacy-sigops to 0 in
   camlcoin (passes the 80_000-cost gate) and 20_001 in Core
   (rejects `bad-blk-sigops`). Permanent fork at the first such
   block.

2. **BUG-W143-2 (P0-CDIV)**: `BlockMutatedMerkle` is classified
   alongside other consensus errors instead of as a
   recoverable-corruption signal — Core's `BLOCK_MUTATED` vs
   `BLOCK_CONSENSUS` enum distinction is lost. Mutated blocks
   are marked permanently invalid in camlcoin; subsequent un-
   mutated re-serves are then refused as `duplicate-invalid` →
   DoS vector.

3. **BUG-W143-4 (P0-CDIV)**: `check_block` does not gate
   `time-too-new` (`MAX_FUTURE_BLOCK_TIME`). The check lives only
   in `Sync.validate_header` and `Validation.check_block_header`
   — any future caller of `accept_block` that bypasses these
   (e.g. a refactored reorg path) silently accepts future-dated
   blocks. Defense-in-depth missing.

### Fleet-pattern smells

- **Two-pipeline guard (fleet-wide 14th-15th instance)**: ~5 distinct
  pipelines split across `check_block_header` / `validate_header`
  for header rules; `check_block` / `validate_block_with_utxos`
  for block rules; `count_sigops` / `count_p2sh_sigops` for legacy
  vs P2SH; `count_tx_sigops` / `count_tx_sigops_cost` for non-
  weighted vs weighted; `Validation.compute_wtxid` /
  `Crypto.compute_wtxid` / `Mining.compute_wtxid` for wtxid.
- **Constant duplication**: `7200` (MAX_FUTURE_BLOCK_TIME) in 4
  sites; `20` (MAX_PUBKEYS_PER_MULTISIG) in 3 sites; `1983702`
  (BIP34_IMPLIES_BIP30_LIMIT) in 1 site (good).
- **Dead module pattern**: `Crypto.witness_merkle_root` (zero
  callers); `count_block_sigops_cost` (only test / mining callers
  — not on the production path).
- **Comment-as-confession (3rd instance in camlcoin)**: 
  validation.ml:893-895 documents the bug (block weight excludes
  header + tx-count) as if it were correct Core behaviour. The W142
  audit already catalogued this as BUG-W142-1.
- **Structural-vs-positional coinbase detection diverges between
  the dead `Crypto.witness_merkle_root` and the live
  `Validation.compute_witness_merkle_root`** — if the dead one is
  ever resurrected, malformed-block divergence.
- **Defense-in-depth missing**: `check_block` doesn't repeat
  the future-time check (relying on upstream `validate_header`);
  `bip30_should_enforce` infers "BIP-34 active from genesis" from
  `bip34_hash = None` instead of an explicit flag;
  `bytes_of_script_num` / `encode_height_in_coinbase` are two
  separate CScriptNum encoders coincidentally agreeing.
