# W142 BIP-141 / BIP-143 SegWit witness validation — camlcoin (OCaml)

Wave: W142 — SegWit + BIP-143 sighash witness validation, the eight
behaviours that span block-level witness commitment, witness merkle
root, BIP-143 v0 sighash, witness program parsing, weight/vsize,
MAX_BLOCK_WEIGHT, and CheckWitnessMalleation.

Bitcoin Core references:

- `bitcoin-core/src/validation.cpp`
  - L3864-3916: `CheckWitnessMalleation` — `bad-witness-nonce-size`,
    `bad-witness-merkle-match`, `unexpected-witness`
  - L3947: `CheckBlock` size limits — `block.vtx.size() *
    WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT` AND
    `GetSerializeSize(TX_NO_WITNESS(block)) * WITNESS_SCALE_FACTOR >
    MAX_BLOCK_WEIGHT` (stripped-block-size gate)
  - L3997-4019: `GenerateCoinbaseCommitment` — emit `OP_RETURN 0x24
    0xaa21a9ed <32-byte commitment>` + `UpdateUncommittedBlockStructures`
    sets coinbase scriptWitness[0] = 32 zero bytes when SEGWIT is
    DeploymentActiveAfter
  - L4169: `ContextualCheckBlock` calls `CheckWitnessMalleation` with
    `expect_witness_commitment = DeploymentActiveAfter(pindexPrev,
    chainman, Consensus::DEPLOYMENT_SEGWIT)`
  - L4179-4181: `GetBlockWeight(block) > MAX_BLOCK_WEIGHT` →
    `bad-blk-weight`
- `bitcoin-core/src/consensus/validation.h`
  - L18: `MINIMUM_WITNESS_COMMITMENT = 38`
  - L132-144: `GetTransactionWeight` / `GetBlockWeight` /
    `GetTransactionInputWeight` formulas
  - L147-165: `GetWitnessCommitmentIndex` — scans EVERY vout of
    `vtx[0]` and returns the LAST matching offset
- `bitcoin-core/src/consensus/consensus.h`
  - L15: `MAX_BLOCK_WEIGHT = 4000000`
  - L21: `WITNESS_SCALE_FACTOR = 4`
  - L23-24: `MIN_TRANSACTION_WEIGHT = 240`,
    `MIN_SERIALIZABLE_TRANSACTION_WEIGHT = 40`
- `bitcoin-core/src/consensus/merkle.cpp`
  - L76-85: `BlockWitnessMerkleRoot` — leaves[0] = empty hash (NOT
    real wtxid of coinbase); leaves[s>=1] = `vtx[s]->GetWitnessHash()`
- `bitcoin-core/src/script/interpreter.cpp`
  - L1348-1377: `GetPrevoutsSHA256` / `GetSequencesSHA256` /
    `GetOutputsSHA256` — single-SHA256 of concatenation (compose with
    `SHA256Uint256` at call site for the double-SHA256)
  - L1600-1677: `SignatureHash` — BIP-143 preimage for
    `SigVersion::WITNESS_V0` branch
  - L1917-1999: `VerifyWitnessProgram` — v0 must be exactly 20 or 32
    bytes; v1 32-byte P2TR; future versions return success unless
    `DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM`
  - L2002-2121: `VerifyScript` — BIP-141 witness dispatch, P2SH-P2W*
    wrap, `WITNESS_UNEXPECTED` final guard for non-witness paths with
    non-empty witness
- `bitcoin-core/src/primitives/transaction.h`
  - L98-127: `CTxIn::scriptWitness` is per-input (carried on
    `CTxIn`, NOT a separate parallel list on `CTransaction`)
  - L260-298: `CTransaction::SerializeWith` — emits 0x00/0x01
    marker/flag only when `HasWitness()` (any `scriptWitness` is
    non-empty)
- `bitcoin-core/src/script/script.cpp`
  - L249-263: `IsWitnessProgram` — size 4..42, opcode 0..16 at byte 0,
    `script[1] + 2 == size`

BIPs: BIP-141 (segwit), BIP-143 (segwit v0 sighash), BIP-144 (segwit
serialisation), BIP-147 (NULLDUMMY), BIP-173/BIP-350 (bech32/bech32m).

## Methodology

1. Read Core refs (above).
2. Enumerate 30 audit gates spanning the eight W142 behaviours plus
   adjacent surfaces (segwit activation gating, IBD parity, intra-
   block witness merkle round-trip, scriptCode P2WPKH derivation,
   BIP-143 helper hash composition, witness program length matrix,
   P2SH-P2W* wrap dispatch, `WITNESS_UNEXPECTED` placement, weight
   formula divergence, marker/flag emission).
3. Classify each gate against camlcoin's de-facto surface:
   - `lib/types.ml` — `tx_witness = { items : Cstruct.t list }`,
     `transaction.witnesses : tx_witness list` (parallel list, NOT
     per-input field as in Core)
   - `lib/serialize.ml` — `serialize_transaction` /
     `deserialize_transaction` / `serialize_transaction_no_witness`
   - `lib/crypto.ml` — `compute_wtxid` / `witness_merkle_root` /
     `merkle_root`
   - `lib/validation.ml` — `compute_tx_weight` / `compute_tx_vsize` /
     `check_witness_commitment` / `find_witness_commitment` /
     `check_block`
   - `lib/script.ml` — `get_witness_program` / `compute_sighash_segwit`
     / `verify_script` (witness-program dispatch + P2SH-P2W* wrap)
   - `lib/mining.ml` — `compute_witness_commitment` /
     `build_witness_commitment_script` / `create_coinbase`
4. Catalogue BUGs by severity:
   - **P0-CONSENSUS**: known mainnet/testnet block today (or trivially
     constructible) would diverge between camlcoin and Core
   - **P0-CDIV**: protocol-correctness divergence (accepts a block
     Core rejects, or rejects one Core accepts) on an
     adversarially-crafted block
   - **P1**: feature-correctness gap (right formula, wrong gating /
     ordering / coverage)
   - **P2**: malleability surface / fingerprinting / fairness drift
   - **P3**: surface / constant / cosmetic drift

Severity legend mirrors W130 / W131 / W132 / W133 / W134 / W135 /
W136 / W137 / W138 / W139 / W140 / W141.

## camlcoin de-facto surface

| Concern | Core | camlcoin |
|---------|------|----------|
| witness storage shape | `CTxIn::scriptWitness` per-input | `transaction.witnesses : tx_witness list` parallel list (`types.ml:69`) |
| `HasWitness()` definition | any `scriptWitness` non-empty | `tx.witnesses <> []` (list non-emptiness, NOT item non-emptiness) (`serialize.ml:234`) |
| segwit marker emission | iff `HasWitness()` (items-level) | iff `tx.witnesses <> []` (list-level) (`serialize.ml:236-239`) |
| segwit marker parse | conditional on first byte after nVersion being 0x00 with input-count fallback | first-byte = 0x00 → witness path; ELSE legacy; superfluous-witness re-check (`serialize.ml:248-271`) |
| witness program parsing | `len in [4..42]`, opcode 0..16 at byte 0, `script[1]+2 == size` | `len in [4..42]`, OP_0 or OP_1..OP_16 at byte 0, `push_len in [2..40] && len = push_len + 2` (`script.ml:627-644`) |
| witness commitment scan | scan ALL vouts of vtx[0], return LAST match | scan in REVERSE (List.rev), return first match — equivalent to LAST in original (`validation.ml:628-644`) |
| commitment magic | OP_RETURN(0x6a) 0x24 0xaa21a9ed | identical (`validation.ml:629`) |
| `MINIMUM_WITNESS_COMMITMENT` | 38 | 38 (`validation.ml:635`) |
| witness merkle root | leaves[0] = 0; leaves[s>=1] = wtxid (Core merkle.cpp:76-85) | leaves[i] = `compute_wtxid tx (i = 0)` — coinbase always 0 (`validation.ml:660-666`) |
| BIP-143 sighash | `SHA256Uint256(GetPrevoutsSHA256(...))` = double-SHA256 | `Crypto.sha256d` (double-SHA256) (`script.ml:922-944`) |
| BIP-143 SIGHASH_SINGLE oob | hashOutputs = uint256(0) | hashOutputs = `Types.zero_hash` (`script.ml:958`) |
| MAX_BLOCK_WEIGHT | 4_000_000 | 4_000_000 (`consensus.ml:11`) |
| WITNESS_SCALE_FACTOR | 4 | 4 (`consensus.ml:29`) |
| `GetBlockWeight` formula | `GetSerializeSize(TX_NO_WITNESS(block))*3 + GetSerializeSize(TX_WITH_WITNESS(block))` (includes header + tx-count varint) | `sum(compute_tx_weight tx)` for tx in block (DOES NOT include header + tx-count varint) (`validation.ml:896-898`) |
| segwit activation height | mainnet 481824, testnet3 834624, testnet4 1, signet 1, regtest 0 | mainnet 481824, testnet3 834624, testnet4 1, regtest 0 (`consensus.ml:613, 680, 722, 764`) |
| `WITNESS_UNEXPECTED` final guard | runs at tail of `VerifyScript` for ALL non-witness paths (interpreter.cpp:2110-2116) | only enforced inside `P2PKH_script` and `Nonstandard` arms of `verify_script`; P2SH non-witness redeem arm DOES NOT check (`script.ml:2643, 3213`, see BUG-W142-10) |
| Taproot key-path sighash dispatch | `SignatureHashSchnorr` only | `verify_script` calls `compute_sighash_taproot` directly (`script.ml:3011`); BUT `OP_CHECKSIG` branch line 1976 has `SigVersionTaproot ->` arm that calls `compute_sighash_segwit` (BIP-143) — only reachable if a future caller mis-sets `sig_version` |

## 30-gate matrix (W142)

### G1-G8: behavioural gates from the wave brief

- **G1: coinbase witness commitment magic prefix.**
  Core (`validation.cpp:3997-4019` / `consensus/validation.h:147-165`):
  scriptPubKey starts with `OP_RETURN 0x24 0xaa21a9ed` (6 bytes) +
  32-byte commitment + optional trailing bytes (any output >= 38
  bytes whose first 6 bytes match is treated as the commitment;
  trailing bytes are ignored). camlcoin (`validation.ml:629`):
  `prefix = "\x6a\x24\xaa\x21\xa9\xed"`, `if length spk >= 38 &&
  spk[0..6] = prefix then Some (spk[6..38])`. **PARITY** on
  detection. **No bug**.

- **G2: coinbase witness reserved value (nonce) shape.**
  Core (`validation.cpp:3878-3884`): `block.vtx[0]->vin[0].scriptWitness.stack`;
  must be exactly 1 stack item of exactly 32 bytes. camlcoin
  (`validation.ml:699-705`): `coinbase.witnesses` → first witness →
  `items` must be `[item] when length item = 32`. **PARITY**.

- **G3: BIP-143 sighash double-SHA256 composition.**
  Core (`script/interpreter.cpp:1630-1638`): `SHA256Uint256(GetPrevoutsSHA256(txTo))`
  — outer-SHA256 wraps an inner-SHA256, total = SHA256d. camlcoin
  (`script.ml:929`): `Crypto.sha256d (...prevouts concatenated...)`
  — direct double-SHA256. **PARITY** (numerically identical
  composition because `SHA256(SHA256(x)) = sha256d(x)`).

- **G4: witness program length matrix.**
  Core (`script/interpreter.cpp:1924-1946`): v0 must be 20 (P2WPKH)
  or 32 (P2WSH) bytes; any other v0 length →
  `SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH`. camlcoin
  (`script.ml:2630-2637`): same; explicit reject when v0 program
  length not in {20, 32}. **PARITY**.

- **G5: empty witness for non-witness txs (WITNESS_UNEXPECTED).**
  Core (`script/interpreter.cpp:2110-2116`): at the very end of
  `VerifyScript`, if `flags & SCRIPT_VERIFY_WITNESS` and
  `!hadWitness && !witness->IsNull()` → `SCRIPT_ERR_WITNESS_UNEXPECTED`.
  This is the FINAL guard, fires for ALL non-witness execution paths
  (legacy P2PKH, P2PK, P2SH non-witness, Multisig, OP_RETURN,
  Nonstandard). camlcoin (`script.ml:2643, 3213`): the check is
  duplicated only inside `P2PKH_script` and `Nonstandard` branches;
  the P2SH branch (regular non-witness redeem) does NOT enforce it.
  See BUG-W142-10.

- **G6: weight = base_size*3 + total_size; vsize = (weight+3)/4.**
  Core (`consensus/validation.h:132-135`): `GetTransactionWeight =
  GetSerializeSize(TX_NO_WITNESS(tx))*(WITNESS_SCALE_FACTOR-1) +
  GetSerializeSize(TX_WITH_WITNESS(tx))`. camlcoin
  (`validation.ml:115-127`): identical formula `base_size*(scale-1) +
  total_size`. **PARITY** at tx level.

- **G7: MAX_BLOCK_WEIGHT = 4_000_000.**
  Core (`consensus/consensus.h:15`): `4000000`. camlcoin
  (`consensus.ml:11`): `4_000_000`. **PARITY** on constant.
  Enforcement BUG: see BUG-W142-9 (camlcoin's weight aggregator
  omits header + tx-count varint contribution that Core's
  `GetBlockWeight` includes).

- **G8: `CheckWitnessMalleation` — commitment required if any
  witness data exists.**
  Core (`validation.cpp:4169`): in `ContextualCheckBlock`,
  `CheckWitnessMalleation(block, expect_witness_commitment =
  DeploymentActiveAfter(pindexPrev, chainman, DEPLOYMENT_SEGWIT))`.
  Inside, `if expect_witness_commitment` and commitment is found, run
  the malleation check; if no commitment (NO_WITNESS_COMMITMENT) and
  any tx has witness → `unexpected-witness`. camlcoin
  (`validation.ml:690-734`): if `segwit_active` and
  `find_witness_commitment = Some`, run the malleation check;
  otherwise if `block_has_witness` → `BlockUnexpectedWitness`.
  **PARITY**. NOTE: pre-segwit blocks also check `block_has_witness`
  and reject if any tx has witness — matches Core's
  `expect_witness_commitment=false` arm (`validation.cpp:3905-3913`).

### G9-G15: derived gates from the 8 behaviours

- **G9: GetBlockWeight aggregate must include header + tx-count
  varint.**
  Core (`consensus/validation.h:136-139`): `GetBlockWeight =
  GetSerializeSize(TX_NO_WITNESS(block))*3 +
  GetSerializeSize(TX_WITH_WITNESS(block))`. The block serialisation
  includes the 80-byte header + the tx-count varint + each tx.
  Therefore the block weight ≈ 80*4 + varint(n)*4 + Σ tx_weight.
  camlcoin (`validation.ml:896-898`): `let total_weight = List.fold_left
  (fun acc tx -> acc + compute_tx_weight tx) 0 txs in if total_weight
  > Consensus.max_block_weight then ...`. The aggregator omits the
  header*4 (= 320) and tx-count varint *4 (= 4..36) terms.
  **BUG-W142-1 (P0-CDIV)**: `check_block`'s weight aggregator omits
  `(80 + varint(n_txs)) * WITNESS_SCALE_FACTOR ≈ 324..356` of weight
  Core's `GetBlockWeight` includes. A block at Σ tx_weight =
  4_000_000 passes camlcoin; Core rejects with `bad-blk-weight`.
  Excerpt (validation.ml:894-900):
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
  The in-source comment is WRONG: Core's `ContextualCheckBlock`
  (`validation.cpp:4179`) calls `GetBlockWeight(block)` which
  serialises the whole CBlock (header + tx-count + txs both
  stripped and full). Impact: an adversarial peer can craft a block
  whose Σ tx_weight is exactly 4_000_000 and camlcoin accepts it
  while every Core node on the network rejects with `bad-blk-weight`
  — camlcoin permanently forks off the canonical chain at the first
  such block. **Comment-as-confession pattern**: the comment
  documents the bug rather than the actual Core behaviour.

- **G10: `WITNESS_UNEXPECTED` final guard must fire on regular P2SH
  non-witness redeem path.**
  Core (`script/interpreter.cpp:2110-2116`): the unconditional
  tail-guard `if !hadWitness && !witness->IsNull()` → error fires
  AFTER all P2SH dispatch including the non-witness P2SH branch.
  Therefore a P2SH spend whose redeem script is NOT a witness
  program but whose `CTxIn::scriptWitness` is non-empty fails with
  `SCRIPT_ERR_WITNESS_UNEXPECTED`. camlcoin (`script.ml:2667-2847`):
  the regular P2SH "no witness program in redeem" branch (line
  2828-2841) does NOT check `witness.items <> []`. A consensus
  spender on mainnet sends a regular P2SH tx with a redeem script
  that is not a witness program but with a non-empty witness stack;
  camlcoin accepts, Core rejects.
  Excerpt (script.ml:2828-2840):
  ```ocaml
  | _ ->
    (* Regular P2SH: run redeem script with remaining stack *)
    let st2 = create_eval_state ~tx ~input_index ~amount ~flags
                ~sig_version:SigVersionBase () in
    st2.stack <- List.tl stack_copy;
    begin match run_script st2 redeem_script with
    | Error e -> Error e
    | Ok () ->
      if flags land script_verify_cleanstack <> 0 && stack_size st2 <> 1 then
        Error "Stack not clean after execution"
      else
        check_stack_top st2
    end
  ```
  No `if flags land script_verify_witness <> 0 && witness.items <> []`
  guard before/after — Core's `SCRIPT_ERR_WITNESS_UNEXPECTED` is the
  block-level guard that catches this since segwit activation.
  **BUG-W142-2 (P0-CDIV)**: regular P2SH non-witness redeem accepts
  spends with non-empty witness on camlcoin where Core rejects with
  `SCRIPT_ERR_WITNESS_UNEXPECTED`.

- **G11: `serialize_transaction` segwit marker emission semantics.**
  Core (`primitives/transaction.h:260-298`): `SerializeWith` emits
  the 0x00/0x01 marker/flag iff `HasWitness()` returns true, where
  `HasWitness()` is `any CTxIn::scriptWitness is non-empty` (i.e.,
  per-item check). camlcoin (`serialize.ml:233-246`): `has_witness =
  tx.witnesses <> []` — list-level emptiness, NOT item-level.
  Therefore a tx with `witnesses = [{items=[]}; {items=[]}]` (non-
  empty list of all-empty witness stacks) serialises WITH marker/flag
  in camlcoin and WITHOUT in Core.
  Excerpt (serialize.ml:233-239):
  ```ocaml
  let serialize_transaction w (tx : Types.transaction) =
    let has_witness = tx.witnesses <> [] in
    write_int32_le w tx.version;
    if has_witness then begin
      write_uint8 w 0x00;  (* marker *)
      write_uint8 w 0x01;  (* flag *)
    end;
  ```
  Wire effect: an in-memory tx constructed programmatically (e.g.
  via `payjoin.ml:321: witnesses = tx.witnesses @ [{ items = [] }]`,
  or any other construction that pads the parallel list with empty
  witness stacks to match input count) serialises to a wire form
  Core rejects on parse with `Superfluous witness record`. Round-
  trip via camlcoin's own `deserialize_transaction` ALSO rejects
  (line 264-267: `if List.for_all (fun wit -> wit.Types.items = [])
  w then failwith "Superfluous witness record"`).
  **BUG-W142-3 (P0-CDIV)**: `serialize_transaction` writes marker/
  flag based on list non-emptiness rather than item non-emptiness;
  diverges from Core's BIP-141 `SerializeWith` shape for any tx with
  non-empty witnesses list whose every item-list is empty. wtxid
  divergence cascades into a divergent `BlockWitnessMerkleRoot` and
  therefore a divergent coinbase commitment match.

- **G12: `compute_wtxid` re-uses divergent serialisation from G11.**
  Core (`primitives/transaction.h:333`): `GetWitnessHash() =
  SerializeHash(*this, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS_INVERTED)`
  — uses `TX_WITH_WITNESS` which respects `HasWitness()`. camlcoin
  (`validation.ml:649-656` / `crypto.ml:388-406`): calls
  `Serialize.serialize_transaction` which has the G11 bug.
  Therefore any non-coinbase tx in a block, if its in-memory
  representation has a parallel `witnesses` list with all-empty
  items, produces a wtxid that differs from Core's. This propagates
  into the witness merkle root, the coinbase commitment hash, and
  ultimately whether `CheckWitnessMalleation` returns
  `bad-witness-merkle-match` or `Ok`.
  **BUG-W142-4 (P0-CDIV — cascade of BUG-W142-3)**: a mining-side
  caller (or RPC `submitblock` path) that constructs a non-coinbase
  tx with `tx.witnesses = List.map (fun _ -> {items=[]}) tx.inputs`
  to "match the input count" will produce a block whose witness
  merkle root differs from Core's. Compounds with BUG-W142-13
  because validation paths use the SAME divergent
  `compute_witness_merkle_root` for the commitment check —
  consistent within camlcoin, divergent against the network. Block
  fails Core's `bad-witness-merkle-match` while camlcoin's local
  validation passes.

- **G13: witness merkle root mutation flag is discarded.**
  Core (`validation.cpp:3887-3890`): explicitly comments
  "malleation check is ignored; as the transaction tree itself
  already does not permit it, it is impossible to trigger in the
  witness tree". So Core does NOT propagate the merkle mutated
  flag from `ComputeMerkleRoot` to the validator. camlcoin
  (`validation.ml:665`): `let (root, _mutated) = Crypto.merkle_root
  wtxids in root` — also discards.
  **PARITY**, by mutual blessing of the same CVE-2012-2459-style
  weakness. **No bug**, but **comment-as-omission pattern**:
  camlcoin silently discards the flag without the in-source citation
  Core has — a future code-reader has no anchor to know this is
  intentional.

- **G14: BIP-143 `compute_sighash_segwit` input_index bounds check.**
  Core (`script/interpreter.cpp:1602`): `assert(nIn < txTo.vin.size())`
  — fatal-asserts on out-of-range input index; the caller is
  responsible (typically `CheckInputScripts` guards via iteration).
  camlcoin (`script.ml:917-975`): `let inp = List.nth tx.inputs
  input_index in ...` — raises `Failure "nth"` on out-of-range,
  unhandled at call site.
  **BUG-W142-5 (P1)**: `compute_sighash_segwit` has no defensive
  bounds check; an internal caller bug (e.g. a future refactor that
  iterates over `tx.witnesses` length rather than `tx.inputs`
  length) panics with `Failure "nth"` rather than a clean script
  verification error. Defense-in-depth gap on the BIP-143 entry
  point. Compare with `compute_sighash_taproot` at `script.ml:1040-
  1049` which DOES bounds-check both `n_prevouts = n_inputs` and
  `input_index ∈ [0, n_inputs)`; the same pattern is missing on the
  v0 hot path. **Two-pipeline guard pattern (15th distinct
  extension)**: defensive bounds checks present on the BIP-341
  (newer) path are absent on the BIP-143 (older) path within the
  same module.

- **G15: stale `SigVersionTaproot` branch in `OP_CHECKSIG` calls
  BIP-143 instead of BIP-341.**
  Core (`script/interpreter.cpp:1737-1741`): Taproot key-path is
  NEVER dispatched through `OP_CHECKSIG` evaluation; it goes
  through `CheckSchnorrSignature` directly. The script-eval CHECKSIG
  path is ONLY reached for `BASE`, `WITNESS_V0`, and `TAPSCRIPT` sig
  versions. camlcoin (`script.ml:1976-1977`):
  ```ocaml
  | SigVersionTaproot | SigVersionTapscript ->
    Ok (compute_sighash_segwit st.tx st.input_index effective_script_code st.amount hash_type)
  ```
  The `SigVersionTaproot` arm calls `compute_sighash_segwit` —
  BIP-143 — not `compute_sighash_taproot` — BIP-341. If ANY caller
  ever sets `sig_version = SigVersionTaproot` before invoking
  `eval_script`, the produced sighash is silently the wrong one and
  every Schnorr verification returns the wrong yes/no answer. Today
  this branch is dead (only Tapscript runs `eval_script` for
  Taproot spends), but it is a latent foot-gun.
  **BUG-W142-6 (P2 — latent)**: dead `SigVersionTaproot` arm in
  `OP_CHECKSIG` calls BIP-143 (`compute_sighash_segwit`) instead of
  BIP-341 (`compute_sighash_taproot`); silently wrong if ever
  reached, no compile-time guard preventing the future caller.

### G16-G22: witness merkle / commitment / serialization parity

- **G16: `block_has_witness` includes coinbase reserved-nonce witness.**
  Core (`validation.cpp:3906-3913`): in the `no-commitment` arm,
  iterates `for (const auto& tx : block.vtx)` — INCLUDES the
  coinbase — and calls `tx->HasWitness()`. camlcoin
  (`validation.ml:619-622`): `List.exists (fun tx -> List.exists ...
  tx.Types.witnesses) block.transactions` — also includes
  coinbase. **PARITY**.
  Edge case: a SEGWIT-active block with no commitment vout would
  fall through to the `block_has_witness` check; if the coinbase
  has its reserved-nonce witness (32 zero bytes), this counts as
  witness data. Core treats it identically. **No bug**.

- **G17: scan direction of `find_witness_commitment`.**
  Core (`consensus/validation.h:147-165`): forward scan, keeps
  overwriting `commitpos` — returns the LAST matching output's
  index. camlcoin (`validation.ml:630-644`): `List.rev outputs` +
  recursive `scan` returns FIRST match in the reversed list, i.e.
  LAST in original order. **PARITY**.
  Observation: this is **logically equivalent to Core** but
  structurally inverted (Core: "keep latest"; camlcoin: "reverse
  + take first"). A subtle parity gotcha for any future reader who
  expects forward scan.

- **G18: witness program parsing accepts/rejects exact same byte
  patterns as Core's `IsWitnessProgram`.**
  Core (`script/script.cpp:249-263`): size 4..42; byte 0 is OP_0
  or in [OP_1, OP_16]; `(script[1] + 2) == size`. NO explicit cap
  on `script[1]`'s value (the `size <= 42` cap implicitly bounds
  it to 40). camlcoin (`script.ml:627-644`): identical bounds plus
  an explicit `push_len >= 2 && push_len <= 40` cap. The explicit
  cap is redundant with the size cap and ADD-only, doesn't reject
  anything Core accepts. **PARITY**.

- **G19: P2WPKH must have exactly 2 witness items.**
  Core (`script/interpreter.cpp:1939-1941`): `if (stack.size() !=
  2) return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);`
  camlcoin (`script.ml:2862-2863, 2735-2736`): `if List.length
  wit_items <> 2 then Error ...`. **PARITY**.
  NOTE: this is checked in TWO places — native P2WPKH branch and
  P2SH-wrapped P2WPKH branch — duplicated logic that could drift.

- **G20: P2WSH non-empty witness requirement.**
  Core (`script/interpreter.cpp:1926-1928`): `if (stack.size() ==
  0) return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY);`
  camlcoin (`script.ml:2913-2914, 2780-2781`): `if List.length
  wit_items = 0 then Error "Empty witness for P2WSH"`. **PARITY**.
  Same two-site duplication risk as G19.

- **G21: WITNESS_PUBKEYTYPE compressed-pubkey policy gate.**
  Core (`script/interpreter.cpp:CheckPubKey` via
  `CPubKey::IsCompressedOrUncompressed`): SCRIPT_VERIFY_WITNESS_PUBKEYTYPE
  rejects non-compressed pubkeys in P2WPKH/P2SH-P2WPKH witness.
  camlcoin (`script.ml:2872-2874, 2744-2746`): same gate
  `is_compressed_pubkey wit_pubkey`. **PARITY**.

- **G22: `count_witness_sigops` for v0 P2WSH uses subscript.GetSigOpCount(true)**.
  Core (`script/interpreter.cpp:2129-2131`): `CScript subscript =
  witness.stack.back(); return subscript.GetSigOpCount(true);` —
  `fAccurate=true` walks ops with their preceding push for
  OP_CHECKMULTISIG (counts actual N pubkeys, not max 20). camlcoin
  (`validation.ml:476, 396-398`): `count_witness_sigops witness_script
  = count_p2sh_sigops witness_script`; `count_p2sh_sigops` uses
  the last-push value to estimate N for CHECKMULTISIG. **PARITY in
  the OP_N-prefix case**; **near-parity in the non-OP_N case** —
  Core's `GetSigOpCount(true)` returns `MAX_PUBKEYS_PER_MULTISIG=20`
  when prior op is not OP_N; camlcoin same. **No bug**.

### G23-G30: surface / activation / propagation gates

- **G23: segwit activation heights — mainnet 481824, testnet3
  834624, testnet4 1, regtest 0.**
  Core (`kernel/chainparams.cpp:94, 217, 460, 541`): mainnet=481824,
  testnet3=834624, testnet4=1, regtest=0 (always active).
  camlcoin (`consensus.ml:613, 680, 722, 764`): identical. **PARITY**.

- **G24: scripted flag derivation — SegWit + NULLDUMMY together at
  segwit_height.**
  Core (`validation.cpp:GetBlockScriptFlags`): both
  `SCRIPT_VERIFY_WITNESS` and `SCRIPT_VERIFY_NULLDUMMY` activate at
  the same SEGWIT deployment height. camlcoin (`validation.ml:324-
  328`): identical: `if height >= network.segwit_height then begin
  flags := !flags lor witness; flags := !flags lor nulldummy end`.
  **PARITY**.

- **G25: BIP-143 amount field width = int64 LE.**
  Core (`script/interpreter.cpp:1655`): `ss << amount` — `CAmount`
  is `int64_t`, serialised LE. camlcoin (`script.ml:970`):
  `Serialize.write_int64_le w amount`. **PARITY**.

- **G26: BIP-143 hashSequence omitted for ANYONECANPAY or SINGLE/NONE.**
  Core (`script/interpreter.cpp:1633-1635`):
  `if (!ANYONECANPAY && base!=SINGLE && base!=NONE) hashSequence = ...
  else hashSequence = 0`. camlcoin (`script.ml:934-944`): identical.
  **PARITY**.

- **G27: scriptCode for P2WPKH is implicit P2PKH (BIP-143).**
  Core (`script/interpreter.cpp:1942`): `exec_script << OP_DUP <<
  OP_HASH160 << program << OP_EQUALVERIFY << OP_CHECKSIG`. camlcoin
  (`script.ml:1197-1205, 2882, 2752`): `build_p2pkh_script program`
  emits `0x76 0xa9 0x14 <hash> 0x88 0xac` (25 bytes). **PARITY**.

- **G28: `MIN_TRANSACTION_WEIGHT = 240` (i.e., 4 * 60).**
  Core (`consensus/consensus.h:23`): `MIN_TRANSACTION_WEIGHT = 4*60
  = 240`. camlcoin (`consensus.ml:35`): comment cites but
  constant is NOT exposed by name. Search confirms no
  `min_transaction_weight` identifier.
  **BUG-W142-7 (P3)**: `MIN_TRANSACTION_WEIGHT` constant
  documented in comment but not exposed; mempool / mining /
  validation code uses ad-hoc integer literals instead of a
  named constant. Easy to drift if Core's spec changes.

- **G29: `block.vtx.size() * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT`
  early-out.**
  Core (`validation.cpp:3947`): one of three disjunctions in the
  CheckBlock size-limits gate — reject if number of txs exceeds
  weight ceiling (each tx is at least 1 weight unit; the disjunction
  catches a million-tx block before computing serialisation size).
  camlcoin (`validation.ml:181-189`): single `check_transaction`-
  level base-weight ceiling; no equivalent of the cheap `vtx.size()
  * 4` early-out in `check_block`.
  **BUG-W142-8 (P2)**: cheap `n_txs * 4 > MAX_BLOCK_WEIGHT` early-out
  missing in `check_block`; a hostile peer can force camlcoin into
  per-tx serialisation loops over a 1M+ tx block before any limit
  fires. DoS amplification on the validate-then-reject path.

- **G30: marker/flag emission discipline — `HasWitness()` correctness.**
  Core (`primitives/transaction.h:283-289`): `HasWitness()` iterates
  every input and tests `!vin[i].scriptWitness.IsNull()` — returns
  true iff ANY input has at least one stack item. camlcoin
  (`serialize.ml:234`): `has_witness = tx.witnesses <> []` — list
  non-emptiness, NOT item non-emptiness.
  This is the wire-level companion to BUG-W142-3 and is the
  ROOT CAUSE of the divergent wtxid in BUG-W142-4. The shape-mismatch
  is structural (camlcoin uses a parallel `witnesses` list instead
  of per-input `scriptWitness`); the bug surfaces every time the
  list is non-empty but every item is empty.
  **BUG-W142-9 (P0-CDIV — same root as BUG-W142-3, separate
  observation site)**: serializer marker/flag emission is keyed on
  the OCaml list non-emptiness rather than per-item witness non-
  emptiness, an artifact of the parallel-list encoding diverging
  from Core's per-input scriptWitness.

### G31-G38: additional witness-validation parity gates

- **G31: superfluous-witness rejection on deserialize.**
  Core (`primitives/transaction.h:UnserializeTransaction`): if
  marker+flag are present but every input has empty
  `scriptWitness`, the parse returns successfully (no
  `superfluous-witness` reject — Core silently accepts this shape,
  though it is non-canonical and would not be relayed by a
  well-behaved peer; CVE/security context: post-segwit only).
  camlcoin (`serialize.ml:264-267`): `if List.for_all (fun wit ->
  wit.Types.items = []) w then failwith "Superfluous witness record"`
  — REJECTS the parse with a `Failure` (raises an exception,
  unhandled at most call sites).
  **BUG-W142-10 (P1)**: deserialize rejects a wire shape Core
  accepts. Network peers transmitting (incidentally or
  maliciously) a marker-flag-with-all-empty-stacks transaction
  cause an unhandled `Failure` in the camlcoin parser. Defense-in-
  depth: this should be a soft-error (return None / Error variant)
  not an exception, AND the policy decision matches Core's
  permissive read.

- **G32: `WITNESS_UNEXPECTED` guard on raw P2PK (legacy bare
  public key script).**
  Core (`script/interpreter.cpp:2110-2116`): final guard fires for
  P2PK as well (script doesn't reach P2WPKH/P2WSH path so
  hadWitness=false; non-empty witness → error). camlcoin
  (`script.ml:3211-3214`): P2PK falls into `Nonstandard ->` arm,
  which DOES check witness emptiness. **PARITY** (covered by the
  Nonstandard arm). **No bug**.

- **G33: P2SH-P2WPKH (BIP-141 P2SH wrap) duplicates the 2-item
  witness check and the compressed-pubkey check.**
  Core (`script/interpreter.cpp`): single `VerifyWitnessProgram`
  entry handles both bare-P2W* and P2SH-P2W*. camlcoin
  (`script.ml:2735-2766` AND `script.ml:2862-2894`): duplicated
  blocks for native vs P2SH-wrapped. Behaviour identical today,
  drift risk if either block is updated without the other.
  **BUG-W142-11 (P2)**: P2WPKH validation logic is duplicated
  between native (`script.ml:2849-2899`) and P2SH-wrapped
  (`script.ml:2724-2768`) call sites; a future invariant change
  must be applied in two places.

- **G34: P2WSH witness stack reversal correctness.**
  Core's stack convention (LIFO via vector back). camlcoin's
  stack convention (head = top of stack). Witness items 0..n-2
  go onto stack; item n-1 is the script (popped). Stack-list
  shape: top at head → `[item(n-2); ...; item(0)]`. camlcoin
  (`script.ml:2789, 2925`): `List.rev (List.filteri (fun i _ -> i
  < n-1) wit_items)`. **PARITY** with Core's eval order.

- **G35: SIGHASH_DEFAULT (0x00) is Taproot-only; rejected in
  BIP-143 v0.**
  Core (`script/interpreter.cpp:194-195`): in BASE/WITNESS_V0
  `CheckSignatureEncoding`, hash_type `0x00` is invalid (must be
  in `[SIGHASH_ALL, SIGHASH_SINGLE]` after masking ANYONECANPAY).
  camlcoin: `compute_sighash_segwit` does NOT pre-validate
  hash_type; the SIGHASH_DEFAULT case (0x00) silently goes into
  base_type = 0 (not ALL=1, not NONE=2, not SINGLE=3) and falls
  to the "all outputs" arm (line 947-952). On Core, a SegWit v0
  ECDSA signature with hash_type=0x00 fails `CheckSignatureEncoding`;
  on camlcoin, the sighash is computed (incorrectly as if it were
  SIGHASH_ALL) and only the upstream `is_defined_hash_type` check
  in `OP_CHECKSIG` filters it out — but only when
  `SCRIPT_VERIFY_STRICTENC` is set.
  **BUG-W142-12 (P1)**: `compute_sighash_segwit` does not pre-
  validate hash_type whitelist; relies on caller's STRICTENC
  gate. A future caller skipping STRICTENC (e.g., in mempool
  policy disabling) would compute a silently-wrong sighash for
  hash_type ∈ {0x00, 0x04..0x7f, 0x84..0xfe} treating them as
  SIGHASH_ALL/SIGHASH_ALL|ACP.

- **G36: BIP-143 hashOutputs for SIGHASH_SINGLE oob.**
  Core (`script/interpreter.cpp:1637-1643`): if base = SINGLE and
  `nIn < vout.size()`, hashOutputs = SHA256d of that single
  vout; ELSE hashOutputs = uint256(0). camlcoin (`script.ml:947-
  959`): identical. **PARITY**.

- **G37: BlockWitnessMerkleRoot leaves[0] = empty (not real wtxid
  of coinbase).**
  Core (`consensus/merkle.cpp:80`): `leaves.emplace_back()` —
  default-constructed `uint256` = zero. camlcoin
  (`validation.ml:660-666`, `crypto.ml:411-413`):
  `compute_wtxid tx (i = 0)` returns `Types.zero_hash` for i=0.
  **PARITY**.

- **G38: weight check at `check_transaction`-level uses
  `base_size * 4` not `base_size * 3 + total_size`.**
  Core (`consensus/tx_check.cpp`): `CheckTransaction` doesn't have
  a weight check; the per-tx weight check is in mempool policy
  / `IsStandardTx`. camlcoin (`validation.ml:181-189`): in
  `check_transaction`, `base_weight = base_size *
  WITNESS_SCALE_FACTOR; if base_weight > max_block_weight then
  ...`. This is the **stripped-size-times-4** gate, equivalent to
  Core's CheckBlock-level `GetSerializeSize(TX_NO_WITNESS(tx)) *
  4 > MAX_BLOCK_WEIGHT` per-tx-applied. The variable name
  `base_weight` is misleading — it is NOT the true tx weight
  (`base*3+total`). The comment on line 181-183 is correct ("base
  serialization size limit") but the variable name confuses future
  readers.
  **BUG-W142-13 (P3)**: `base_weight` is `base_size * 4`, NOT
  `base*3 + total`; the variable is correctly used but mis-named.
  This is the per-tx stripped-size ceiling; calling it "weight"
  invites a future refactor to compare it to weight-typed values
  elsewhere.

## BUG summary (13 BUGs in 38 gates)

| ID | Sev | Gate | Subsystem | Description |
|----|-----|------|-----------|-------------|
| BUG-W142-1 | **P0-CDIV** | G9 | block weight | `check_block` weight aggregator sums per-tx weights only — omits 80*4 + varint(n)*4 ≈ 324..356 of weight Core's `GetBlockWeight` includes; comment-as-confession documents the divergence in source |
| BUG-W142-2 | **P0-CDIV** | G10 | script verify | regular P2SH non-witness redeem path missing `WITNESS_UNEXPECTED` guard; accepts spends with non-empty witness Core rejects |
| BUG-W142-3 | **P0-CDIV** | G11 | serialize | `serialize_transaction` writes marker/flag iff `tx.witnesses <> []` (list-level) rather than item-level; diverges from Core's `HasWitness()` |
| BUG-W142-4 | **P0-CDIV** | G12 | wtxid | wtxid cascades the BUG-W142-3 divergence — non-coinbase tx with all-empty witnesses list produces wrong wtxid; witness merkle root and commitment diverge |
| BUG-W142-5 | P1 | G14 | sighash | `compute_sighash_segwit` lacks defensive `input_index` bounds check (BIP-341 path has it; BIP-143 path doesn't — two-pipeline guard 15th extension) |
| BUG-W142-6 | P2 | G15 | sighash | dead `SigVersionTaproot` arm in `OP_CHECKSIG` calls BIP-143 instead of BIP-341 — latent foot-gun |
| BUG-W142-7 | P3 | G28 | constants | `MIN_TRANSACTION_WEIGHT = 240` documented in comment, not exposed as named constant |
| BUG-W142-8 | P2 | G29 | DoS | cheap `n_txs * 4 > MAX_BLOCK_WEIGHT` early-out missing in `check_block` |
| BUG-W142-9 | **P0-CDIV** | G30 | serialize | (same root as BUG-W142-3, separate observation site) marker/flag emission keyed on list non-emptiness |
| BUG-W142-10 | P1 | G31 | deserialize | parser raises `Failure "Superfluous witness record"` on a wire shape Core accepts |
| BUG-W142-11 | P2 | G33 | duplication | P2WPKH/P2WSH validation logic duplicated between native and P2SH-wrapped branches |
| BUG-W142-12 | P1 | G35 | sighash | `compute_sighash_segwit` doesn't pre-validate hash_type whitelist; relies on caller's STRICTENC |
| BUG-W142-13 | P3 | G38 | naming | `base_weight` variable in `check_transaction` is `base_size * 4` (stripped-size ceiling), NOT a true weight value; mis-named |

### Severity breakdown

- **P0-CDIV** ×4: BUG-W142-1 (block weight off-by-~320), -2 (P2SH
  WITNESS_UNEXPECTED), -3 (marker on list-non-empty), -4 (wtxid
  cascade), -9 (same root as -3, separate site). Effectively three
  distinct root-cause clusters: weight aggregator (1), unexpected-
  witness placement (2), and marker/flag emission shape (3+4+9).
- **P1** ×3: BUG-W142-5 (input_index bounds), -10 (parser raises),
  -12 (hash_type whitelist).
- **P2** ×3: BUG-W142-6 (dead Taproot arm), -8 (DoS amplifier), -11
  (duplicated branch).
- **P3** ×2: BUG-W142-7 (named constant), -13 (variable naming).

## Most representative findings

1. **BUG-W142-1 (P0-CDIV)** — `check_block` weight aggregator
   under-counts vs Core's `GetBlockWeight` by ~320+. The in-source
   comment EXPLICITLY claims Core's CheckBlock omits header +
   tx-count varint from the weight; Core's `ContextualCheckBlock`
   actually calls `GetBlockWeight(block)` which serialises the
   FULL block. This is the **5th instance of comment-as-confession
   pattern** crystallised across the consensus-parity campaign
   (W137 BUG-7 / W138 BUG-3 / W139 BUG-7 / W141 BUG-13 / **W142
   BUG-1**) — a comment that documents the bug as if it were the
   spec. Adversarial block boundary: Σ tx_weight ∈ [4_000_001 -
   320, 4_000_000]. Camlcoin accepts, Core rejects.
2. **BUG-W142-2 (P0-CDIV)** — `WITNESS_UNEXPECTED` not enforced
   on regular P2SH non-witness redeem. The Core invariant ("no
   witness data on a non-witness execution path") is a final guard
   at the tail of `VerifyScript`. Camlcoin duplicates the check in
   `P2PKH_script` and `Nonstandard` branches but the P2SH non-
   witness redeem branch silently allows witness data. Any
   adversarial peer relaying a regular P2SH spend with a non-empty
   witness causes camlcoin to accept and Core to reject —
   permanent fork at the first such tx-in-block.
3. **BUG-W142-3 / -4 / -9 (P0-CDIV cluster)** — segwit marker/flag
   emission and wtxid both key on OCaml list-level non-emptiness
   rather than Core's per-input `scriptWitness` non-emptiness.
   This is **direct fallout of the parallel-list witness encoding
   in `types.ml:69`** — camlcoin stores `transaction.witnesses :
   tx_witness list` instead of Core's `CTxIn.scriptWitness`. The
   shape-mismatch is structural; the bug is the canonicalisation
   choice. Any in-memory constructor that pads `tx.witnesses` to
   `len(tx.inputs)` with empty items (the most natural OCaml-
   idiomatic pattern, used by `payjoin.ml:321`) creates a tx that
   serialises divergently from Core.

## Fleet patterns

- **Parallel-list witness encoding** — only impl in the fleet that
  detaches witness from input. Cross-cite: W137 BUG-12 (rustoshi
  `Witness` separate type), W141 BUG-15 (beamchain socket-per-topic
  vs Core multimap). camlcoin's `transaction.witnesses :
  tx_witness list` IS a structural divergence from Core's per-input
  field that surfaces as BUG-W142-3/-4/-9.
- **Comment-as-confession 5th instance** — BUG-W142-1's in-source
  comment claims Core's CheckBlock omits header + tx-count varint
  from the weight. Compare: W137 BUG-7 (clearbit), W138 BUG-3
  (haskoin), W139 BUG-7 (camlcoin again — same impl!), W141 BUG-13
  (rustoshi). camlcoin has now produced **two instances** of
  comment-as-confession across consecutive waves.
- **Two-pipeline guard 15th distinct extension** — BUG-W142-5:
  defensive `input_index` bounds check exists on the BIP-341
  pipeline (`compute_sighash_taproot`, `script.ml:1040-1049`) but
  not on the BIP-143 pipeline (`compute_sighash_segwit`,
  `script.ml:917`). Same module, two sighash entry points, only
  one guarded.
- **Duplicated branch hazard** — BUG-W142-11: P2WPKH validation
  logic appears at `script.ml:2735-2766` (P2SH-wrapped) AND
  `script.ml:2849-2899` (native). Cross-impl pattern: identified
  in nimrod W135 BUG-01 ("bug duplicated at 2 sites"). A consensus
  change that updates one half but not the other is a future
  P0-CDIV-in-waiting.
- **Dead-arm-with-wrong-formula** — BUG-W142-6: `OP_CHECKSIG`'s
  `SigVersionTaproot` branch calls `compute_sighash_segwit` (BIP-
  143) instead of `compute_sighash_taproot` (BIP-341). Today this
  branch is unreachable because Taproot key-path bypasses script
  evaluation; tomorrow's refactor that wires it up gets silently
  wrong sighashes.

## Test plan

`test/test_w142_segwit_witness_validation.ml` covers all 38 gates:

- **Behavioural / API-level**: round-trip a tx with `witnesses =
  [{items=[]}; {items=[]}]` through `serialize_transaction` and
  compare bytes against the no-marker form Core produces.
- **Numerical**: construct a block whose Σ tx_weight = 4_000_000
  exactly and confirm `check_block` accepts (BUG-W142-1
  documentary); separately confirm Core's behaviour via cross-
  impl probe.
- **Source-level grep**: confirm `script.ml:2828-2840` lacks any
  reference to `witness.items` (BUG-W142-2 documentary); confirm
  `compute_sighash_segwit` lacks `n_inputs`/`n_prevouts` bounds
  guard analogous to lines 1040-1049 (BUG-W142-5 documentary).
- **Invariant guards** at the tail — protocol constants,
  `MAX_BLOCK_WEIGHT = 4_000_000`, `WITNESS_SCALE_FACTOR = 4`,
  `MINIMUM_WITNESS_COMMITMENT = 38`, segwit activation heights.

Total: 38 gates, 13 BUGs, 4 P0-CDIV across 3 root-cause clusters.
This is discovery only — the test asserts the absence (or
presence) of the audited surface; no production code changes.
