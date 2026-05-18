# W137 PSBT v0/v2 (BIP-174 / BIP-370) — camlcoin (OCaml)

Wave: W137 — Partially Signed Bitcoin Transactions, BIP-174 (PSBT v0)
plus the taproot extensions (BIP-371) and MuSig2 extensions (BIP-373).
BIP-370 (PSBTv2) is **explicitly out of scope** because Bitcoin Core does
not implement PSBTv2 (`PSBT_HIGHEST_VERSION = 0` in `psbt.h:80`); the
audit treats absence of PSBTv2 as a NON-finding when both Core and
camlcoin lack it.

Bitcoin Core references:
- `bitcoin-core/src/psbt.h`   — magic, type constants, `PSBTInput` /
  `PSBTOutput` / `PartiallySignedTransaction`, Serialize/Unserialize
  templates, helpers (`SerializeToVector`, `UnserializeFromVector`,
  `DeserializeHDKeypath{s}`, `DeserializeMuSig2*`), free functions
  (`PSBTInputSigned`, `PSBTInputSignedAndVerified`, `SignPSBTInput`,
  `FinalizePSBT`, `FinalizeAndExtractPSBT`, `CombinePSBTs`,
  `DecodeBase64PSBT`, `DecodeRawPSBT`, `RemoveUnnecessaryTransactions`,
  `CountPSBTUnsignedInputs`, `UpdatePSBTOutput`, `PrecomputePSBTData`).
- `bitcoin-core/src/psbt.cpp` — implementations of the above.
- `bitcoin-core/src/node/psbt.{h,cpp}` — `AnalyzePSBT` /
  `PSBTAnalysis` / `PSBTInputAnalysis` (next-role / fee /
  estimated_vsize).
- `bitcoin-core/src/wallet/rpc/psbt.cpp` (referenced in brief; in the
  shallow clone the wallet PSBT RPC code is split across
  `src/wallet/rpc/spend.cpp` for `walletcreatefundedpsbt` /
  `walletprocesspsbt` / `descriptorprocesspsbt` and
  `src/rpc/rawtransaction.cpp` for `createpsbt` / `decodepsbt` /
  `combinepsbt` / `finalizepsbt` / `analyzepsbt` / `joinpsbts` /
  `utxoupdatepsbt` / `converttopsbt`).
- `bitcoin-core/src/test/fuzz/psbt.cpp` and
  `bitcoin-core/src/wallet/test/psbt_wallet_tests.cpp` — exercise
  loops that would surface most gaps below.

BIPs:
- BIP-174 — base PSBTv0 spec.
- BIP-370 — PSBTv2 (NOT implemented by Core or camlcoin; not a finding).
- BIP-371 — Taproot fields (`PSBT_IN_TAP_*` 0x13..0x18,
  `PSBT_OUT_TAP_*` 0x05..0x07).
- BIP-373 — MuSig2 fields (`PSBT_{IN,OUT}_MUSIG2_PARTICIPANT_PUBKEYS`
  0x1a / 0x08, `PSBT_IN_MUSIG2_PUB_NONCE` 0x1b,
  `PSBT_IN_MUSIG2_PARTIAL_SIG` 0x1c).

Methodology: read Core refs, synthesize a 30-gate audit matrix,
classify against camlcoin's PSBT surface (`lib/psbt.ml`,
`lib/wallet.ml::process_psbt`, `lib/rpc.ml::handle_{createpsbt,
decodepsbt, combinepsbt, finalizepsbt, analyzepsbt, utxoupdatepsbt,
walletcreatefundedpsbt, walletprocesspsbt, converttopsbt}`).
Catalogue BUGs by severity:
- **P0-CDIV**: client-observable correctness divergence
  (round-trip mutation, accept-when-Core-rejects, reject-when-Core-
  accepts on a valid PSBT, RPC response shape that breaks tooling)
- **P1**: feature/field absent that the spec mandates and clients use
- **P2**: performance / DoS surface (size-limit unenforced, O(N) ops)
- **P3**: surface drift, error-message shape, comments

Prior camlcoin work in this area (preserved as the starting baseline):
- W47 — combine() idempotency: deduped `bip32_derivations`, `tap_*`,
  `unknown`, `global_xpubs`. Also list-reversal on deserialize so that
  re-serialize is byte-identical to source. **Excellent prior art.**
- W41 — `analyzepsbt` per-input next-role classification corrected to
  surface FINALIZER when all required sigs are present but the input
  hasn't been finalized yet.
- FIX-70 / W120 — `walletcreatefundedpsbt` defaults nSequence to
  `MAX_BIP125_RBF_SEQUENCE` (0xFFFFFFFD).

## Architectural baseline (what camlcoin has, what it doesn't)

camlcoin's PSBT surface lives in **one 1664-LOC file** (`lib/psbt.ml`)
and covers:

  - magic check (`Cstruct.equal magic "psbt\xff"`)
  - global map: `PSBT_GLOBAL_UNSIGNED_TX` (0x00), `PSBT_GLOBAL_XPUB`
    (0x01), `PSBT_GLOBAL_VERSION` (0xFB)
  - input map: 0x00..0x08 + 0x13..0x18 (taproot inputs)
  - output map: 0x00..0x02 + 0x05..0x08 (taproot outputs + musig2
    participants)
  - per-input duplicate-key detection (keyed by full key bytes including
    type — matches Core)
  - per-input list-reversal fix (W47) so round-trips are byte-stable
  - combine() with dedup over the W47-list-typed fields
  - finalize_input_p2wpkh / p2pkh / p2sh_p2wpkh / p2sh_multisig /
    p2sh_p2wsh_multisig / p2wsh_multisig / taproot
  - base64 encode/decode
  - RPC bindings: `createpsbt`, `decodepsbt`, `combinepsbt`,
    `finalizepsbt`, `analyzepsbt`, `utxoupdatepsbt`, `converttopsbt`,
    `walletcreatefundedpsbt`, `walletprocesspsbt`.

What camlcoin **does not** have (the audit surface):

  - 4 hash-preimage input fields (`PSBT_IN_{RIPEMD160,SHA256,HASH160,
    HASH256}` 0x0A..0x0D)
  - 3 MuSig2 input fields (`PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS` 0x1a,
    `PSBT_IN_MUSIG2_PUB_NONCE` 0x1b, `PSBT_IN_MUSIG2_PARTIAL_SIG` 0x1c)
  - 3 proprietary fields (`PSBT_{IN,OUT,GLOBAL}_PROPRIETARY` 0xFC) —
    they fall through to the `unknown` bucket, which approximates the
    spec but loses subtype/identifier semantics
  - `joinpsbts` RPC (PSBT-of-different-txs merge)
  - `descriptorprocesspsbt` RPC (descriptor-driven signer)
  - `psbtbumpfee` RPC (BIP-125 fee bump returning a PSBT)
  - `RemoveUnnecessaryTransactions` (drop non_witness_utxo for taproot
    inputs once signed)
  - `MAX_FILE_SIZE_PSBT` cap (100 MB) — the constant `max_psbt_size`
    exists at `psbt.ml:56` but is never consulted by `deserialize` or
    `of_base64`
  - `non_witness_utxo->GetHash() == prevout.hash` check at
    deserialize time (`psbt.h:1371-1378`)
  - Most per-type **key-length validation** on input/output records
    (Core checks `key.size() != 1` for unique-key types and the exact
    size for prefix-key types like 0x0A..0x0D; camlcoin silently
    treats over-long keys as the same key as the singleton type)
  - `CheckSignatureEncoding` pass on partial sigs (DER-strict-encoding
    + non-empty check — `psbt.h:544-547`)
  - `m_tap_key_sig.size() in [64,65]` validation
  - `m_tap_script_sig.size() in [64,65]` validation
  - `TaprootBuilder::IsComplete()` validation on
    `PSBT_OUT_TAP_TREE` (`psbt.h:1062-1064`)
  - Tap leaf-script control-block size sanity: Core enforces
    `key.size() >= 34 && (key.size() - 2) % 32 == 0`
    (`psbt.h:732-735`); camlcoin accepts any control-block length
    (`psbt.ml:591-597`)
  - Tap BIP32 hashes-vs-origin length check (Core:
    `hashes_len > value_len` rejection)
  - Hex-PSBT decode path: only base64 is supported via
    `of_base64`; `DecodeRawPSBT(std::span<const std::byte>)` has no
    OCaml analog (`decodepsbt` accepts only base64 in `rpc.ml:5411`,
    Core accepts either)

This audit catalogues **NEW** structural / behavioural gaps between
camlcoin's PSBT and Core's, on top of the W41 / W47 baseline.

## 30-gate matrix (W137)

### G1-G5: Magic, global map, version handling

- **G1: PSBT magic byte read.** Core (`psbt.h:1228-1232`): reads exactly
  5 bytes and `std::equal`-compares to `{'p','s','b','t',0xff}`; if
  the stream is shorter, `s >> magic` throws. **camlcoin**
  (`psbt.ml:707-716`): explicitly probes `Cstruct.length data < 5` and
  returns `Invalid_magic`; otherwise reads 5 bytes and compares to
  `psbt_magic`. **Functionally equivalent** but the error shape
  differs (camlcoin returns `Invalid_magic`, Core throws
  `Invalid PSBT magic bytes`).

- **G2: PSBT_GLOBAL_UNSIGNED_TX duplicate / non-singleton key.** Core
  (`psbt.h:1265-1269`): `key.size() != 1` throws "Global unsigned tx
  key is more than one byte type". **camlcoin** (`psbt.ml:741`):
  matches on `key_type` byte but does **NOT** check
  `Cstruct.length key = 1`. A malformed PSBT with key bytes like
  `0x00 0xff 0xff` (type 0x00 + spurious 2 bytes of key data) is
  silently accepted as the unsigned-tx field. **P1: malformed-PSBT
  accept-when-Core-rejects.**

- **G3: PSBT_GLOBAL_UNSIGNED_TX scriptSig / scriptWitness emptiness
  check.** Core (`psbt.h:1274-1279`): for every input of the parsed
  tx, throws if `scriptSig.empty() || scriptWitness.IsNull()` is
  false. **camlcoin** (`psbt.ml:744-754`): does the equivalent check
  via `Invalid_tx_scriptSig_not_empty` /
  `Invalid_tx_witness_not_empty`. **Match.**

- **G4: PSBT_GLOBAL_VERSION key-size + duplicate check.** Core
  (`psbt.h:1313-1318`): rejects when `m_version` already set (duplicate)
  AND when `key.size() != 1`. **camlcoin** (`psbt.ml:767-775`): the
  outer duplicate-key bookkeeping catches the dup case, but there is
  no `Cstruct.length key = 1` check on this type; key
  `0xFB 0xff 0xff` followed by a 4-byte LE value is accepted. **P1**.

- **G5: PSBT_HIGHEST_VERSION enforcement.** Core
  (`psbt.h:1322-1324`): rejects `*m_version > PSBT_HIGHEST_VERSION`
  (which is 0). **camlcoin** (`psbt.ml:770-771`): same check,
  `if v > psbt_highest_version then Error (Unsupported_version v)`.
  **Match.**

### G6-G10: Per-input duplicate-key / size validation

- **G6: PSBT_IN_NON_WITNESS_UTXO key-size check.** Core
  (`psbt.h:507-511`): rejects `key.size() != 1`. **camlcoin**
  (`psbt.ml:532-535`): no size check; over-long key with type=0x00
  is accepted as `non_witness_utxo`. The duplicate-key check at
  `psbt.ml:522` keys by full key bytes, so a single such over-long
  key passes through. **P1**.

- **G7: PSBT_IN_PARTIAL_SIG pubkey size + validity.** Core
  (`psbt.h:526-547`): rejects key.size other than 34 (compressed+1)
  or 66 (uncompressed+1), and additionally rejects via
  `CPubKey::IsFullyValid` + `CheckSignatureEncoding(SCRIPT_VERIFY_DERSIG
  | SCRIPT_VERIFY_STRICTENC)`. **camlcoin** (`psbt.ml:542-548`):
  rejects key sizes other than 33 or 65 by **silently skipping the
  entry** (no error returned), and does NOT verify pubkey validity or
  signature DER encoding. **P1: silent skip on bad pubkey size.**
  **P0-CDIV-adjacent on malformed sig**: a non-DER sig is happily
  serialized back out by `serialize`, so camlcoin can produce PSBTs
  that Core will reject on read.

- **G8: PSBT_IN_RIPEMD160 / SHA256 / HASH160 / HASH256 preimage fields
  (0x0A..0x0D).** Core (`psbt.h:607-690`): four full case arms with
  per-hash-size key validation, duplicate detection, and preimage
  bucket maps. **camlcoin**: **NONE.** Falls through the default arm
  (`psbt.ml:617-618`) into the `unknown` bucket. A PSBT that uses
  hash160 preimages for a HTLC-style script is round-tripped via the
  `unknown` list, so byte-stability is preserved, but the structured
  semantics (validation, signer integration) are absent. **P1: four
  spec'd input fields absent.**

- **G9: PSBT_IN_TAP_KEY_SIG length validation.** Core
  (`psbt.h:698-704`): rejects size < 64 or > 65. **camlcoin**
  (`psbt.ml:580-581`): assigns `value` to `tap_key_sig` with no
  length check. A taproot key sig of length 0, 32, 100 etc. is
  accepted. **P1**.

- **G10: PSBT_IN_TAP_SCRIPT_SIG signature length validation.** Core
  (`psbt.h:720-724`): rejects sig size < 64 or > 65. **camlcoin**
  (`psbt.ml:583-589`): assigns `value` to `tss.signature` with no
  length check. **P1**.

### G11-G15: Per-input taproot / MuSig2 / proprietary surface

- **G11: PSBT_IN_TAP_LEAF_SCRIPT control-block sanity.** Core
  (`psbt.h:728-746`): rejects `key.size() < 34`, rejects
  `(key.size() - 2) % 32 != 0` (control block must be control-byte +
  internal-key + k×32 merkle path), rejects empty `script_v`.
  **camlcoin** (`psbt.ml:591-597`): only checks
  `Cstruct.length value >= 1` for the script; the **control_block**
  (in `key_data`) has zero length validation. A 1-byte control block
  is accepted. **P1**.

- **G12: PSBT_IN_TAP_BIP32_DERIVATION value-length sanity.** Core
  (`psbt.h:748-768`): reads compact-size value-len, then leaf hashes,
  then asserts `hashes_len <= value_len`, then reads the origin from
  the remaining `value_len - hashes_len` bytes. **camlcoin**
  (`psbt.ml:599-608`): reads N leaf hashes then a key-origin from
  the remainder of the cstruct **without** checking that the compact-
  size value-length boundary is respected. The pos pointer can run
  past the stated length without an error. **P1**.

- **G13: PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS (0x1a).** Core
  (`psbt.h:791-799`): rejects `key.size() != 34`, validates the
  aggregate-pubkey, parses N 33-byte participants from value.
  **camlcoin**: **NOT IMPLEMENTED on the INPUT side.** Falls through
  to `unknown`. The OUTPUT side (`psbt_out_musig2_participants =
  0x08`) is implemented, but BIP-373 specifies the field on BOTH
  input and output maps. **P1: input-side MuSig2 participants
  unsupported.**

- **G14: PSBT_IN_MUSIG2_PUB_NONCE (0x1b).** Core
  (`psbt.h:801-820`): pubnonce key is `[type][part_pubkey(33)]
  [agg_pubkey(33)] [optional leaf_hash(32)]` — 67 or 99 bytes.
  Value must be `MUSIG2_PUBNONCE_SIZE` (66 bytes). **camlcoin**: not
  implemented; falls through to `unknown`. **P1**.

- **G15: PSBT_IN_MUSIG2_PARTIAL_SIG (0x1c).** Core
  (`psbt.h:821-836`): same key shape as 0x1b; value is `uint256`
  (32 bytes). **camlcoin**: not implemented; falls through to
  `unknown`. **P1**.

### G16-G20: Per-output validation + tap tree + proprietary

- **G16: PSBT_OUT_REDEEMSCRIPT / PSBT_OUT_WITNESSSCRIPT key-size.**
  Core (`psbt.h:1001-1015`): rejects `key.size() != 1` on both.
  **camlcoin** (`psbt.ml:655-660`): no size check. **P1**.

- **G17: PSBT_OUT_TAP_TREE TaprootBuilder validation.** Core
  (`psbt.h:1032-1065`): de-serializes the tree, asserts each depth
  ≤ `TAPROOT_CONTROL_MAX_NODE_COUNT` (128) and leaf_ver masked by
  `TAPROOT_LEAF_MASK`, then runs `TaprootBuilder builder; builder.Add
  ...; if (!builder.IsComplete()) throw`. **camlcoin** (`psbt.ml:672-
  674`): stores the raw value blob with no structural checks at all.
  An ill-formed tap tree round-trips silently. **P0-CDIV-adjacent
  (P1)**: a wallet relying on Core to reject malformed tap trees
  during decodepsbt will see camlcoin accept the PSBT and then fail
  later at signing time. Tooling that decode-and-display-only would
  silently render garbage.

- **G18: PSBT_OUT_TAP_BIP32_DERIVATION key+value sanity.** Core
  (`psbt.h:1067-1086`): rejects `key.size() != 33`, asserts
  `hashes_len <= value_len`. **camlcoin** (`psbt.ml:675-684`):
  rejects key_data != 32 (post-stripped, equivalent to key != 33 —
  match), but has the same value-length-not-asserted issue as G12.
  **P1: G12-style boundary unchecked.**

- **G19: PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS (0x08) validation.**
  Core (`psbt.h:1088-1096`): rejects `key.size() != 34`, validates
  agg pubkey, parses N×33 participants and validates each pubkey via
  `CPubKey::IsFullyValid`. **camlcoin** (`psbt.ml:686-696`): checks
  `key_data length = 33`, slices value into 33-byte chunks with no
  pubkey validity check. **P1**.

- **G20: PSBT_{IN,OUT,GLOBAL}_PROPRIETARY (0xFC) handling.** Core
  (`psbt.h:838-851, 1098-1111, 1327-1340`): reads identifier (length-
  prefixed bytes), reads subtype (compact-size), then value; deposits
  into `m_proprietary` set with `PSBTProprietary{subtype, identifier,
  key, value}` shape. Duplicate detection by `key`. **camlcoin**: no
  proprietary type implemented; everything falls into the `unknown`
  bucket. Lossy on the structured fields. **P1**.

### G21-G25: Top-level / lifecycle / size-limit

- **G21: MAX_FILE_SIZE_PSBT (100 MB) cap.** Core
  (`psbt.h:75-77`): defines `MAX_FILE_SIZE_PSBT = 100000000`. This is
  enforced by callers via stream-size limits (the dataspan handed to
  `DecodeRawPSBT` is capped at this size in `DecodeBase64PSBT`'s
  consumer via `MakeByteSpan`-bounded inputs). **camlcoin** defines
  `max_psbt_size = 100_000_000` at `psbt.ml:56` and **NEVER
  REFERENCES IT.** A multi-GB base64 PSBT submitted to
  `decodepsbt` would attempt to allocate and parse the entire thing.
  **P2: DoS surface — no size cap on PSBT input.**

- **G22: Extra-data-after-PSBT rejection.** Core
  (`psbt.cpp:617-630` `DecodeRawPSBT`): `ss_data >> psbt; if
  (!ss_data.empty()) { error = "extra data after PSBT"; return
  false; }`. **camlcoin** (`psbt.ml:707-829` `deserialize`): consumes
  the global + input + output maps but does NOT check that the reader
  is empty after the last output map. Trailing garbage is silently
  ignored. A serialize→deserialize→serialize cycle with appended
  junk produces a "valid" canonical PSBT, losing the trailing data
  semantics (and silently accepting PSBTs that Core rejects).
  **P1**.

- **G23: non_witness_utxo hash matches prevout at parse time.** Core
  (`psbt.h:1371-1378`): for each input, asserts
  `input.non_witness_utxo->GetHash() == tx->vin[i].prevout.hash` and
  `tx->vin[i].prevout.n < input.non_witness_utxo->vout.size()` at
  deserialize time. **camlcoin** (`psbt.ml:707-829`): no such check.
  A mismatched non_witness_utxo (e.g. wrong tx provided for the input)
  survives `deserialize` and only fails later at signing time, if at
  all. **P0-CDIV-adjacent (P1)**: a wallet relying on Core for
  "input N's prevout hash matches its non_witness_utxo" will not get
  the same guarantee from camlcoin's `decodepsbt` / `analyzepsbt`.

- **G24: Inputs / outputs count vs tx vin / vout.** Core
  (`psbt.h:1381-1397`): explicitly checks
  `inputs.size() != tx->vin.size()` and the analogous for outputs.
  **camlcoin** (`psbt.ml:790-829`): reads exactly `num_inputs` /
  `num_outputs` then `Ok` — same effect but no explicit "wrong
  count" rejection path. If `deserialize_input` returns
  `Error _` on a malformed input map BEFORE all N are read, the
  remaining unread bytes are silently ignored. **P3: error path
  shape drift.**

- **G25: PSBTInputSigned / PSBTInputSignedAndVerified.** Core
  (`psbt.cpp:320-352`): `PSBTInputSigned` is non-empty
  `final_script_sig` OR non-null `final_script_witness`.
  `PSBTInputSignedAndVerified` additionally calls
  `VerifyScript(final_script_sig, scriptPubKey, &final_script_witness,
   STANDARD_SCRIPT_VERIFY_FLAGS, MutableTransactionSignatureChecker)`.
  **camlcoin**: `is_input_finalized` is implemented
  (`psbt.ml:1447-1449`) and matches `PSBTInputSigned`. There is **NO
  equivalent of PSBTInputSignedAndVerified** — no actual script
  evaluation of the finalized scriptSig/witness happens before
  `extract` produces the final tx. **P1: finalized-but-invalid
  scripts pass through.** A combiner that aggregates a malformed
  final_script_sig and a malformed final_script_witness gets a
  "finalized" PSBT that `extract`s a tx Core would reject at
  `verifytxoutproof` / `sendrawtransaction`.

### G26-G30: RPC surface gaps + analyzepsbt fidelity

- **G26: `joinpsbts` RPC.** Core (`src/rpc/rawtransaction.cpp` —
  see `joinpsbts` handler): concatenates PSBTs into a single PSBT
  that combines the inputs and outputs of each. Used by Lightning
  channel coordination and CoinJoin protocols. **camlcoin**: NO
  handler. Search for `"joinpsbts"` / `"join_psbts"` in
  `lib/rpc.ml` returns empty. **P1: RPC absent.**

- **G27: `descriptorprocesspsbt` RPC.** Core
  (`src/wallet/rpc/spend.cpp`): signs a PSBT using an externally-
  supplied descriptor (descriptor-driven Updater + Signer). **camlcoin**:
  NO handler. **P1: RPC absent**.

- **G28: `psbtbumpfee` RPC.** Core (`src/wallet/rpc/coins.cpp`):
  fee-bump variant of `bumpfee` returning a PSBT rather than a
  fully signed tx. **camlcoin**: NO handler. **P1**.

- **G29: `analyzepsbt` `estimated_vsize` / `estimated_feerate`
  fidelity.** Core (`node/psbt.cpp:118-145`): when every input is
  signable, runs the dummy signer for each input, builds a
  CMutableTransaction with the dummy final_script_sig /
  final_script_witness, calls
  `GetVirtualTransactionSize(ctx, GetTransactionSigOpCost(...))`,
  divides fee by vsize for `CFeeRate`. **camlcoin**
  (`rpc.ml:5740-5744`): `estimated_vsize` is **hard-coded `0`** with
  a `(* Would need weight calculation *)` comment;
  `estimated_feerate` is the fee divided by 100_000_000 (BTC/byte
  conversion error — see below). **P0-CDIV (RPC shape)**: clients
  inspecting `estimated_vsize` for fee-rate display will see
  0 vs Core's real vsize. **Also P0-CDIV**: the units are wrong
  — Core's `feerate` is BTC/kvB and camlcoin emits
  `fee /. 100_000_000.0` which is BTC (not BTC/kvB; missing the
  vsize divisor).

- **G30: `RemoveUnnecessaryTransactions` for taproot inputs.** Core
  (`psbt.cpp:514-549`): walks every PSBT input; if every input is
  segwit-v1 (taproot) and the sighash type does not include
  `SIGHASH_ANYONECANPAY`, the non_witness_utxo is dropped (since
  taproot sighashes do not need the full prev tx). Standard
  hygiene after `walletcreatefundedpsbt`. **camlcoin**: NO
  equivalent helper; `handle_walletcreatefundedpsbt` produces PSBTs
  carrying non_witness_utxo even for taproot-only inputs. **P2:
  PSBTs are larger than they need to be (full prev-tx blob per
  input vs just the 8-byte witness_utxo amount + script).**

## Universal patterns surfaced (cross-impl candidates)

- **"PSBT key-size validation absent on singleton-key types"** —
  cross-impl risk. Every impl must enforce `key.size() == 1` for the
  ~15 input/output/global types that BIP-174 specifies as singleton.
  Camlcoin lacks this on at least 8 of them (G2, G4, G6, G9, G10,
  G16, plus the BIP-371 types). Worth a fleet sweep — any impl that
  matches only on `key_type byte` without bounding `key.length()`
  has the same gap.

- **"BIP-373 input-side MuSig2 fields absent fleet-wide?"** —
  G13/G14/G15. Most non-Core impls likely lack PSBT_IN_MUSIG2_*
  support; the field IDs are recent (0x1a/0x1b/0x1c added in
  2024-2025). Worth a fleet sweep of "does decode/serialize PSBT
  preserve these structured fields, or do they round-trip as
  unknown KVs?"

- **"PSBT extra-data-after-tail not rejected"** — G22. Easy unit
  test: serialize a valid PSBT, append `\xff\xff\xff\xff`, ask
  decodepsbt. Core rejects; many impls silently accept. Likely
  fleet-wide.

- **"PSBT non_witness_utxo prevout-hash check at decode"** — G23.
  BIP-174 explicitly mandates this. Cross-impl audit could submit a
  PSBT with mismatched non_witness_utxo and check rejection.

- **"`analyzepsbt.estimated_vsize` is stubbed to 0"** — G29.
  Pattern: when an impl has no internal weight calculator, it
  zeroes out the vsize-derived fields rather than dropping them.
  Tools that use `estimated_feerate` for display will silently
  show 0 sat/vB. Worth a fleet sweep.

- **"PSBT size-cap constant defined but never enforced"** — G21.
  Defensive constants stand alone in some impls; ungated. Easy
  fleet sweep: grep for `MAX_FILE_SIZE_PSBT` / `max_psbt_size` /
  `100_000_000` and check whether the value reaches a guard.

- **"`finalize_*` skipped a `verify_script` step"** — G25. Closely
  related to the absence of a CHECKSIG-evaluating interpreter
  outside the script module. Cross-impl: which impls' finalizers
  actually evaluate the final scriptSig/witness against the
  scriptPubKey before claiming "complete"?

## BUG catalogue (NEW in W137)

| ID | Sev | Gate | Description |
|---|---|---|---|
| BUG-W137-1 | P0-CDIV | G29 | `analyzepsbt` `estimated_vsize` hard-coded to `0` (`rpc.ml:5742`). Tools relying on this for fee-rate display get 0 sat/vB. |
| BUG-W137-2 | P0-CDIV | G29 | `analyzepsbt` `estimated_feerate` is `fee /. 100_000_000.0` (`rpc.ml:5737`) — that's BTC, not BTC/kvB. Off by the (missing) vsize factor; for a 200-vbyte tx with 1000 sat fee, Core returns `0.00005` BTC/kvB and camlcoin returns `0.00001` BTC (off by ~5× and wrong-units). |
| BUG-W137-3 | P0-CDIV | G17 | `PSBT_OUT_TAP_TREE` stored as opaque blob (`psbt.ml:672-674`); no TaprootBuilder validation. Malformed tap trees survive decodepsbt — Core rejects them. |
| BUG-W137-4 | P0-CDIV | G25 | No `PSBTInputSignedAndVerified` equivalent. A combined PSBT with malformed `final_script_sig` / `final_script_witness` is reported as "complete" by `is_finalized` and `extract`s to a tx Core rejects. |
| BUG-W137-5 | P1 | G7 | `PSBT_IN_PARTIAL_SIG` does no `CheckSignatureEncoding` (DER-strict) and no `CPubKey::IsFullyValid`. (`psbt.ml:542-548`). |
| BUG-W137-6 | P1 | G7 | Invalid pubkey-key-size partial-sig entries are **silently skipped** rather than errored. (`psbt.ml:544` returns `()`.) Symptom: parsing succeeds with mute data loss. |
| BUG-W137-7 | P1 | G2 / G4 / G6 / G9 / G10 / G16 | No `Cstruct.length key = 1` check on 8 singleton-key types (`PSBT_GLOBAL_UNSIGNED_TX`, `PSBT_GLOBAL_VERSION`, `PSBT_IN_NON_WITNESS_UTXO`, `PSBT_IN_WITNESS_UTXO`, `PSBT_IN_SIGHASH_TYPE`, `PSBT_IN_REDEEMSCRIPT`, `PSBT_IN_WITNESSSCRIPT`, `PSBT_IN_TAP_KEY_SIG`, `PSBT_IN_TAP_INTERNAL_KEY`, `PSBT_IN_TAP_MERKLE_ROOT`, `PSBT_OUT_REDEEMSCRIPT`, `PSBT_OUT_WITNESSSCRIPT`, `PSBT_OUT_TAP_INTERNAL_KEY`, `PSBT_OUT_TAP_TREE`). |
| BUG-W137-8 | P1 | G8 | Four input hash-preimage fields (`PSBT_IN_RIPEMD160` 0x0A, `SHA256` 0x0B, `HASH160` 0x0C, `HASH256` 0x0D) not implemented; fall through to `unknown` bucket. |
| BUG-W137-9 | P1 | G9 | `PSBT_IN_TAP_KEY_SIG` accepts any value length (`psbt.ml:580-581`); Core enforces 64..65 bytes. |
| BUG-W137-10 | P1 | G10 | `PSBT_IN_TAP_SCRIPT_SIG` signature value has no 64..65 length check (`psbt.ml:584-589`). |
| BUG-W137-11 | P1 | G11 | `PSBT_IN_TAP_LEAF_SCRIPT` control-block has no `len >= 33 && (len - 1) % 32 == 0` check (Core: `key.size() >= 34 && (key.size() - 2) % 32 == 0`). (`psbt.ml:591-597`.) |
| BUG-W137-12 | P1 | G12 / G18 | `PSBT_{IN,OUT}_TAP_BIP32_DERIVATION` does not verify the compact-size value-length boundary; reader can advance past the stated length. (`psbt.ml:599-608, 675-684`.) |
| BUG-W137-13 | P1 | G13 | `PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS` (0x1a) input-side not implemented (only the output-side 0x08 is). |
| BUG-W137-14 | P1 | G14 | `PSBT_IN_MUSIG2_PUB_NONCE` (0x1b) not implemented. |
| BUG-W137-15 | P1 | G15 | `PSBT_IN_MUSIG2_PARTIAL_SIG` (0x1c) not implemented. |
| BUG-W137-16 | P1 | G19 | `PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS` (0x08) skips `CPubKey::IsFullyValid` on aggregate and per-participant. (`psbt.ml:686-696`.) |
| BUG-W137-17 | P1 | G20 | `PSBT_{IN,OUT,GLOBAL}_PROPRIETARY` (0xFC) structured handling absent; falls through to `unknown`. Lossy on subtype / identifier semantics. |
| BUG-W137-18 | P1 | G22 | No "extra data after PSBT" rejection. Trailing bytes after final output map silently ignored. (`psbt.ml:822-829`.) |
| BUG-W137-19 | P1 | G23 | No `non_witness_utxo->GetHash() == prevout.hash` check at deserialize time. Mismatched non_witness_utxo survives. (`psbt.ml:790-803`.) |
| BUG-W137-20 | P1 | G26 | `joinpsbts` RPC absent. |
| BUG-W137-21 | P1 | G27 | `descriptorprocesspsbt` RPC absent. |
| BUG-W137-22 | P1 | G28 | `psbtbumpfee` RPC absent. |
| BUG-W137-23 | P2 | G21 | `max_psbt_size = 100_000_000` defined at `psbt.ml:56` but **never referenced**. No size cap on `deserialize` / `of_base64` — multi-GB base64 PSBTs accepted. DoS surface. |
| BUG-W137-24 | P2 | G30 | No `RemoveUnnecessaryTransactions` analog. PSBTs from `walletcreatefundedpsbt` carry redundant non_witness_utxo blobs for segwit-v1 (taproot) inputs that only need witness_utxo. |
| BUG-W137-25 | P3 | G1 | Magic-byte read returns `Invalid_magic` for a short stream rather than throwing the Core-shape stream-failure exception. Surface drift only — clients see a structured error either way. |
| BUG-W137-26 | P3 | G24 | Inputs/outputs count mismatch error path: if `deserialize_input` errors mid-stream, the remaining unread bytes are silently dropped rather than surfacing as a count mismatch. Cosmetic. |

Total **NEW in W137**: **26 BUGs** (4 P0-CDIV, 18 P1, 2 P2, 2 P3).

## What camlcoin gets RIGHT (regression-pin notes)

A discovery audit should also pin the working pieces so future fix
waves don't accidentally regress them:

- **W47 list-reversal on deserialize**: the W47 commit was correct.
  Re-serialize of a deserialize is byte-identical (modulo dedup).
- **W47 combine() idempotency**: `combine(p, p)` yields a PSBT
  byte-identical to `p` for the 7 list-typed fields it dedups.
- **W41 analyzepsbt next-role classification**: correctly distinguishes
  signer / finalizer / extractor based on `required_sig_count` (via
  `parse_multisig_threshold` for M-of-N).
- **FIX-70 nSequence default**: `walletcreatefundedpsbt` correctly
  emits MAX_BIP125_RBF_SEQUENCE (0xFFFFFFFD) by default.
- **Duplicate-key detection at all three map levels** (global,
  input, output) — keyed by full key bytes (type + keydata) matches
  Core semantics.
- **Magic byte check** (5 bytes including 0xff trailer) is correct.
- **Multisig pubkey ordering on finalize** — `parse_multisig_pubkeys`
  + the `List.filter_map (fun pk -> List.find_opt …)` pattern
  ensures sigs are emitted in CHECKMULTISIG-expected pubkey-listed
  order, regardless of partial_sigs arrival order.

## Verification

`test/test_w137_psbt.ml` — 30 gate tests across the 6 G-bands
(magic + global, per-input dup/size, taproot input/MuSig2 + proprietary,
per-output validation + tap tree, top-level / size limit / lifecycle,
RPC surface). Discovery-only; each test documents the gap and serves
as a regression-pin for the current behaviour. The "working" pieces
above are pinned with INV-N tests so a future fix wave can't
accidentally regress W47 / W41 / FIX-70 in passing.

camlcoin gotcha (per FIX-80 / FIX-77 / W133 audit pattern): if
`dune runtest` stalls, run the pre-built
`_build/default/test/test_w137_psbt.exe` directly.

## Out of scope (for future waves)

- BIP-370 (PSBTv2) — Core does not implement it; non-finding.
- Closure of any BUG above; this audit is discovery-only.
- BIP-78 PayJoin (covered by W119 / FIX-65/66/67).
- BIP-21 URI parsing (covered by W118 / FIX-62 / W133-adjacent).
- Wallet HD-key derivation correctness (covered by W118).
- Descriptor / Miniscript surface (covered by W131).
- Coin selection inside `walletcreatefundedpsbt` (covered by W113 /
  W129).
- Sighash computation correctness (covered by `test_sighash_vectors`).
- Schnorr / taproot signing primitives (covered by W127).
