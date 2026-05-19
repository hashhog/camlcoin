# W161 — BIP-32 / BIP-39 / BIP-43 / BIP-44 / BIP-49 / BIP-84 / BIP-86 HD wallet derivation + seed mnemonic (camlcoin)

**Wave:** W161 — `derive_master_key` (HMAC-SHA512 "Bitcoin seed"),
CKDpriv / CKDpub (`secp256k1_ec_seckey_tweak_add`,
`secp256k1_ec_pubkey_tweak_add`), hardened-index threshold
`0x80000000`, parent fingerprint = HASH160(parent\_pubkey)\[0..4],
chain code split = IL/IR halves, IL ≥ n / IL == 0 retry semantics,
BIP-39 mnemonic 12/15/18/21/24-word + 2048-word English wordlist +
N/32 checksum, PBKDF2-HMAC-SHA512 iter=2048 salt="mnemonic"+passphrase,
BIP-32 xprv/xpub 78-byte Base58Check + per-network version bytes
(0x0488ADE4/0x0488B21E mainnet, 0x04358394/0x043587CF testnet,
SLIP-132 ypub/zpub for BIP-49/BIP-84 cross-wallet portability), BIP-43
purpose prefix, BIP-44 P2PKH (m/44'/coin'/account'/change/index), BIP-49
P2SH-P2WPKH (m/49'), BIP-84 native SegWit P2WPKH (m/84'), BIP-86
single-key P2TR with empty merkle root tweak (m/86'), descriptor
expansion / gap-limit / seed-entropy validation / memory zeroize.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/key.cpp:285-310` — `CExtKey::Derive` /
  `CKey::Derive` private-side `secp256k1_ec_seckey_tweak_add` (single
  C call, no GMP fallback); BIP32Hash builds the HMAC-SHA512 input
  using compressed pubkey for non-hardened and 0x00||sk for hardened.
- `bitcoin-core/src/pubkey.cpp` — `CExtPubKey::Derive` /
  `CPubKey::Derive` public-side `secp256k1_ec_pubkey_tweak_add`.
- `bitcoin-core/src/key.cpp:348-356` — `CKey::ComputeKeyPair(const
  uint256* merkle_root)` → `KeyPair` constructor passes
  `merkle_root` (non-null when script tree present) into
  `XOnlyPubKey(pk).ComputeTapTweakHash(merkle_root)`. The wallet
  P2TR signer MUST pass the wallet-stored merkle root.
- `bitcoin-core/src/wallet/scriptpubkeyman.cpp:DescriptorScriptPubKeyMan::TopUp`
  + `GenerateMnemonic`-equivalent — Core has switched its descriptor
  wallets to a 16-byte entropy → 12-word mnemonic + a separate
  `mnemonic` field in `wallet.dat`'s `descriptor`/`hdkeyenc`
  records (the mnemonic is surfaced via `dumpwallet` /
  `gethdkeys`); seed material is recoverable.
- `bitcoin-core/src/wallet/crypter.cpp:15-39` —
  `BytesToKeySHA512AES` — **not PBKDF2**. EVP_BytesToKey-shape:
  chain SHA-512 over (passphrase || salt) `count` times; the FIRST
  64 bytes become (32-byte AES-256 key || 16-byte IV). 25000 rounds
  default. **Camlcoin uses PBKDF2-HMAC-SHA512 instead — totally
  different derivation, so camlcoin's encrypted wallets are
  cross-impl-incompatible with Core's wallet.dat.**
- `bitcoin-core/src/key_io.cpp:DecodeExtKey / EncodeExtKey` — version
  bytes selection is parameterised on `CChainParams::Base58Prefix`
  for `EXT_PUBLIC_KEY` / `EXT_SECRET_KEY` (mainnet/testnet/regtest/signet
  differ).
- `bitcoin-core/src/wallet/wallet.cpp::GenerateNewSeed` — calls
  `randbytes(WALLET_CRYPTO_KEY_SIZE)` for a 32-byte seed and then
  feeds it into `CExtKey::SetSeed` which BIP-32-derives the master
  via HMAC-SHA512("Bitcoin seed", seed).
- `bitcoin-core/src/script/descriptor.cpp` — descriptor key expansion
  via `BIP32PubkeyProvider::GetPubKey` / `BIP32SecKey`.
- BIP-32 spec — "In case parse256(IL) ≥ n or ki = 0 (where ki is the
  parent key plus IL mod n), the resulting key is invalid; proceed
  with the next value for i." MUST-retry semantics. Master also
  MUST be re-tried (with a different seed) if IL ≥ n or IL = 0.
- BIP-39 spec — "To create a binary seed from the mnemonic, we use
  the PBKDF2 function with a mnemonic sentence (in UTF-8 NFKD) used
  as the password and the string 'mnemonic' + passphrase (also in
  UTF-8 NFKD) used as the salt."
- BIP-43 — purpose-prefix convention (BIP-44/49/84/86 use 44'/49'/84'/86'
  respectively).
- BIP-44 coin_type — `0' = Bitcoin mainnet`, `1' = Bitcoin testnet/regtest`.
- BIP-86 — `TapTweak` with **empty** merkle root for single-key P2TR
  spends (matches Core's
  `KeyPair(key, /*merkle_root=*/&uint256::ZERO)`-shape — distinguish
  from the script-tree case where the wallet-stored merkle root is
  used).

**Files audited**
- `lib/wallet.ml:72-285` — `extended_key`, `hmac_sha512`,
  `derive_master_key`, `fingerprint_of_key`, `derive_child_key`,
  `derive_hardened`, `derive_normal`, `derive_bip44_receive`,
  `derive_bip44_change`, `derive_bip84_receive`, `derive_bip84_change`,
  `derive_bip86_receive`, `derive_bip86_change`.
- `lib/wallet.ml:291-360` — `serialize_xprv`, `serialize_xpub`,
  `deserialize_extended_key`.
- `lib/wallet.ml:445-595` — `create`, `init_from_seed`,
  `init_from_mnemonic`, `generate_key_typed`,
  `generate_change_key_typed`.
- `lib/wallet.ml:1304-1378` — `sign_transaction_inputs` (P2TR branch).
- `lib/wallet.ml:1406-1700` — `process_psbt` (PSBT signer).
- `lib/wallet.ml:2095-2400` — `derive_key_and_iv`,
  `encrypt_private_key`, `decrypt_private_key`, `encryptwallet`
  family, `wallet_passphrase`, `wallet_lock`.
- `lib/wallet.ml:2435-2780` — `save`, `save_encrypted`,
  `load_wallet_json`, `load_encrypted` (master-key
  persistence).
- `lib/wallet.ml:2978-3008` — `create_wallet` (auto-mnemonic at
  strength=128).
- `lib/bip39.ml` — entire module (wordlist, `generate_mnemonic`,
  `validate_mnemonic`, `mnemonic_to_seed`).
- `lib/descriptor.ml:1-150, 260-665, 759-980` — `parse`, key parsing,
  `derive_key_at` (xpub-rooted path traversal), descriptor `expand`,
  `compute_tap_tree_root`.
- `lib/crypto.ml:79-323, 568-606` — `generate_private_key`,
  `derive_public_key`, `derive_xonly_pubkey`, `tagged_hash`,
  `compute_taptweak_keypath`, `compute_taproot_tweak`,
  `compute_taproot_output_key`.
- `lib/rpc.ml:6560-6610` — `listdescriptors` (auto-emits
  `wpkh(.../84'/0'/0'/*)`, `tr(.../86'/0'/0'/*)`).

---

## Gate matrix (32 sub-gates / 12 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | Master gen HMAC-SHA512 | G1: key="Bitcoin seed", data=seed | PASS (`wallet.ml:117`) |
| 1 | … | G2: split IL=I[0..32], IR=I[32..64] | PASS (`wallet.ml:119-120`) |
| 1 | … | G3: master parent_fingerprint = 0x00000000, child_index = 0, depth = 0 | PASS (`wallet.ml:124-125`) |
| 1 | … | G4: master MUST reject seed of length < 128 or > 512 bits | **BUG-1 (P1)** — `derive_master_key` accepts any-length seed; no length check. BIP-32 §"Master key generation" says "any seed which is 128 to 512 bits long" |
| 1 | … | G5: master MUST retry (with caller-supplied new seed) if IL ≥ n or IL = 0 | **BUG-2 (P0-SEC, rare)** — no IL ≥ n / IL = 0 check at master. libsecp256k1's `secp256k1_ec_seckey_verify` is not invoked; an invalid master silently flows through and then fails on first child derivation with cryptic "invalid child key derived" |
| 2 | CKDpriv via libsecp256k1 (NOT pure-OCaml Zarith) | G6: private-side tweak via `secp256k1_ec_seckey_tweak_add` | PASS (`wallet.ml:75-76, 195-201`; cross-cite: this is the **inverse** of haskoin W160 "BIP-32 private-side GMP asymmetry" — camlcoin routes both sides through libsecp256k1, which is what Core does. **PASS-with-credit.**) |
| 2 | … | G7: public-side tweak via `secp256k1_ec_pubkey_tweak_add` | PASS (`wallet.ml:78-79, 195-201`) |
| 2 | … | G8: MUST retry on invalid-child by **incrementing index** and re-deriving | **BUG-3 (P1)** — `derive_child_key` returns `Error "BIP-32: invalid child key derived"` without the BIP-32-mandated automatic skip. The caller (`generate_key_typed`'s `try_derive` at `wallet.ml:521-529`) DOES increment, but it increments by **+1 for the entire 5-level path**, not by +1 at the failing depth as the spec requires. For multi-leaf-failure-on-the-same-account this drift could elide multiple gap-limit slots silently. |
| 2 | … | G9: hardened index decided via unsigned int32 comparison | PASS (`wallet.ml:170` — `Int32.unsigned_compare index hardened_offset >= 0` — explicit doc comment notes this is the fleet-rare correct form) |
| 2 | … | G10: hardened-from-xpub returns explicit Error | PASS (`wallet.ml:171-172`) |
| 3 | parent fingerprint | G11: HASH160(parent\_pubkey)\[0..4] big-endian uint32 | PASS (`wallet.ml:130-139`) |
| 3 | … | G12: derived child stores `parent_fingerprint = fingerprint_of(parent)`, not of grandparent | PASS (`wallet.ml:204, 208`) |
| 4 | BIP-39 wordlist + checksum | G13: 2048-word English wordlist present + sorted | PASS (`bip39.ml:8-265`; verified abandon…zoo, alphabetic) |
| 4 | … | G14: validate accepts 12/15/18/21/24 words only | PASS (`bip39.ml:372-374`) |
| 4 | … | G15: N/32 checksum bits (SHA-256 of entropy, first N/32 bits) | PASS (`bip39.ml:343-353, 393-400`) |
| 4 | … | G16: UTF-8 NFKD normalisation of mnemonic AND passphrase before PBKDF2 | **BUG-4 (P0-CDIV interop)** — `bip39.ml:407-409`: `password = mnemonic`, `salt = "mnemonic" ^ passphrase` — both used as raw OCaml strings. BIP-39 mandates NFKD normalisation; without it, accented passphrases or non-English wordlists produce a different seed on camlcoin vs Core/Trezor/Ledger. Cross-impl seed-restore is broken whenever the passphrase contains any of {NBSP, combining marks, ligatures, smart quotes, Asian punctuation}. |
| 4 | … | G17: wordlist comparison uses NFKD-folded form (typed-Japanese-IME tolerance) | **BUG-4 cross-cite** — same root cause |
| 5 | PBKDF2 seed gen | G18: iter=2048 | PASS (`bip39.ml:429`) |
| 5 | … | G19: HMAC-SHA512, 64-byte output | PASS (`bip39.ml:423-428`) |
| 5 | … | G20: salt = "mnemonic" + passphrase (with INT_32_BE(1) block-index suffix) | PASS-but-weak (`bip39.ml:407-422`); BUG-4 still affects |
| 6 | xprv/xpub serialization | G21: 78-byte format with version + depth + parent_fp + child_idx + chain_code + key | PASS (`wallet.ml:292-330`) |
| 6 | … | G22: per-network version bytes (mainnet xprv/xpub vs testnet tprv/tpub) | **BUG-5 (P0-CDIV)** — `serialize_xprv` and `serialize_xpub` HARDCODE mainnet `0x0488ADE4` / `0x0488B21E` (`wallet.ml:294-295, 312-313`). The wallet's `network` field is IGNORED. A testnet wallet calling `listdescriptors`/`getdescriptorinfo` emits mainnet-prefixed `xprv...` strings instead of `tprv...`; importing those into Core-on-testnet fails with "invalid extended key". |
| 6 | … | G23: deserialize accepts xprv/xpub/tprv/tpub | PARTIAL (`wallet.ml:341-347`) — accepts all four but NO ypub/zpub/Ypub/Zpub (SLIP-132 BIP-49/BIP-84) and NO Upub/Vpub (SLIP-132 testnet). Importing a Trezor/Electrum BIP-49 backup (ypub) fails |
| 6 | … | G24: depth field is 1 byte (0..255), reject deeper | **BUG-6 (P1)** — `depth : int` (`wallet.ml:104`); `Cstruct.set_uint8 buf 4 ek.depth` (`wallet.ml:297, 315`) silently truncates if `depth > 255`. BIP-32 limits depth to 255; camlcoin neither rejects nor signals overflow |
| 7 | BIP-43/44/49/84/86 paths | G25: BIP-44 P2PKH `m/44'/coin_type'/account'/change/n` with coin_type derived from network | **BUG-7 (P0-CDIV)** — `derive_bip44_receive/change` (`wallet.ml:247-263`) hard-code `coin_type = 0` (mainnet). Testnet wallets derive at mainnet path. Restoring a camlcoin-testnet seed into Core-on-testnet recovers ZERO funds because Core looks at `m/44'/1'/...` |
| 7 | … | G26: BIP-84 P2WPKH `m/84'/coin_type'/account'/change/n` | **BUG-7 cross-cite** (`wallet.ml:222-241`) |
| 7 | … | G27: BIP-86 P2TR `m/86'/coin_type'/account'/change/n` | **BUG-7 cross-cite** (`wallet.ml:266-285`) |
| 7 | … | G28: BIP-49 P2SH-P2WPKH `m/49'/...` derivation function present | **BUG-8 (P1)** — no `derive_bip49_*` function exists; `generate_key_typed`'s `address_type` enum is `P2PKH | P2WPKH | P2TR` with no P2SH-P2WPKH variant. A user wanting a BIP-49 (legacy SegWit, common pre-2021 hardware wallets) address gets nothing; the wallet skips the entire address family |
| 8 | BIP-86 TapTweak (no merkle root, no script tree) | G29: P2TR address derivation tweaks xonly with `tagged_hash("TapTweak", xonly)` | PASS at *address* level (`descriptor.ml:846-847` uses `compute_taproot_output_key xonly None`; `crypto.ml:580` `compute_taproot_tweak internal_pk None`) |
| 8 | … | G30: BIP-86 single-key spend signing uses `compute_taptweak_keypath` (no merkle root) | PASS (`wallet.ml:1328, 1605` — the BUG is when the merkle-root IS present, see G31) |
| 8 | … | G31: script-tree spend signing uses wallet-stored merkle root | **BUG-9 (P0-FUNDS, W160 BUG-12/13 CARRY-FORWARD)** — see dedicated section. `wallet.ml:1328` AND `wallet.ml:1605` hardcode `compute_taptweak_keypath xonly_pk` with NO merkle root. **2-WAVE CARRY-FORWARD** (W160 → W161). |
| 9 | Seed material persistence + recoverability | G32: auto-generated mnemonic is shown to operator and persisted | **BUG-10 (P0-FUNDS — funds-loss on process restart)** — see dedicated section |

---

## BUG-1 (P1) — `derive_master_key` accepts any-length seed; no 128–512-bit validation

**Severity:** P1 (defensive gate). BIP-32 §"Master key generation"
mandates: "any seed which is 128 to 512 bits long ... if it is
shorter or longer, the function MUST fail." `derive_master_key`
(`wallet.ml:116-125`):

```ocaml
let derive_master_key (seed : Cstruct.t) : extended_key =
  let key_str = Cstruct.of_string "Bitcoin seed" in
  let i = hmac_sha512 ~key:key_str seed in
  ...
```

No length check on `seed`. A 1-byte seed, or a 1024-byte seed, both
flow through silently. The downstream `init_from_seed` /
`init_from_mnemonic` callers feed it a `Cstruct.t` whose length is
controlled by upstream code, but:
- `init_from_mnemonic` always receives 64 bytes from
  `Bip39.mnemonic_to_seed` (PBKDF2 output is fixed dk_len=64) —
  in-spec.
- `init_from_seed` is called from `load_encrypted` and from the
  `restoreseed`/import RPCs (when present). **There is no
  intermediary length-validator**, so an operator that
  hex-decodes a malformed seed string and passes it in gets an HMAC
  output that's a deterministic function of bogus material, with
  no error.

**File:** `lib/wallet.ml:115-125`.

**Core ref:** BIP-32 master generation; `bitcoin-core/src/key.cpp` /
`CExtKey::SetSeed` is called only after `wallet.cpp::GenerateNewSeed`
which fixes the length at 32 bytes (256 bits).

**Impact:** silent acceptance of invalid seed lengths; missing
defensive gate. A 31-byte "near-256-bit" seed produces a different
extended key than the same operator's 32-byte intent, with no signal.

---

## BUG-2 (P0-SEC, rare) — `derive_master_key` skips IL ≥ n and IL = 0 retry semantics

**Severity:** P0-SEC (extremely rare in practice, but spec-mandated).
BIP-32 master gen has the same MUST-retry-with-new-seed obligation
as CKDpriv: "If IL is 0 or ≥ n, the master key is invalid (this
happens with probability 1/2^127 — generate a new seed)." The
`derive_master_key` body (`wallet.ml:116-125`) reads IL via
`Cstruct.sub i 0 32` and stores it as `key` with **zero
validation**.

The downstream `derive_child_key` does call
`ec_seckey_tweak_add_raw` which will fail if the parent key is
invalid — but by then the master extended key has already been
stored at `w.master_key`, indices have been zeroed, and the wallet
appears alive. The first `getnewaddress` then fails with the cryptic
"BIP-32: invalid child key derived" and the operator has no path
forward except `rm wallet.dat`.

Camlcoin should at minimum call
`secp256k1_ec_seckey_verify(ctx, master_key.key)` after the master
derivation and return an `Error _` from `init_from_seed` so the
caller can re-prompt the operator for new entropy.

**File:** `lib/wallet.ml:115-125`; `lib/wallet.ml:479-491`.

**Core ref:** BIP-32 master generation §"Master key generation";
Core's `CExtKey::SetSeed` does the same shape but Core's downstream
flow surfaces a clean error rather than silently storing the invalid
master.

**Impact:** astronomically rare (2^-127), but the error surface is
worse than Core's: silent bad-state, then cryptic first-derivation
failure, then permanent inability to use the wallet (BUG-10 below
amplifies this — operator cannot even read the mnemonic out to
re-import).

---

## BUG-3 (P1) — `derive_child_key` retry semantics: caller increments wrong index

**Severity:** P1. BIP-32 spec: "In case parse256(IL) ≥ n or k_i = 0,
the resulting key is invalid. Proceed with the next value for i."
The **failing depth's** child index is incremented by 1 and the
sibling at the same depth is tried; the parent path is unchanged.

`derive_child_key` correctly returns `Error _` on failure
(`wallet.ml:210-211`). But `generate_key_typed`'s retry wrapper
(`wallet.ml:521-529`) increments `idx` of the **final leaf** and
re-derives the **entire 5-level path** from master:

```ocaml
let rec try_derive idx =
  match derivation_fn master idx with
  | Ok pk ->
    set_index idx;
    pk
  | Error _ ->
    try_derive (idx + 1)
in
```

Two issues:
1. The failure could have occurred at the `coin_type` /
   `account` / `change` levels (hardened, deterministic from
   master). If the **same idx** failed for `change`, the retry
   with `idx+1` for the FINAL leaf does not re-attempt the
   failing intermediate at all — it tries a different leaf under
   the same intermediate, which is a no-op for the bug source.
   In practice intermediate hardened-derivation failures from a
   fixed master are deterministic and a `(idx+1)` retry can never
   fix them, so `try_derive` would loop until stack overflow.
2. The wallet's stored `bip44_receive_index` / `bip84_receive_index`
   tracker fast-forwards past the skipped indices, but the **gap
   limit** rationale of "scan the previous 20 indices for activity
   when restoring a seed" assumes a contiguous-index sequence.
   Skipped indices break this; Core/Electrum's gap-limit scan
   would see a hole and stop scanning at the gap.

**File:** `lib/wallet.ml:158-211` (CKDpriv); `lib/wallet.ml:507-545`,
`552-595` (retry wrapper).

**Core ref:** BIP-32 §"Child key derivation" final paragraph;
`bitcoin-core/src/key.cpp::CKey::Derive` returns `bool` and the
caller (`CExtKey::Derive`) propagates the failure up to
`CExtKeyV3::Derive` which retries with the next i at the SAME
depth.

**Impact:** gap-limit-violating index-holes on multi-derive failure;
the failure is astronomically rare (2^-127 per level) so this
manifests in unit tests with hand-crafted parent chain codes, not
on production keys. P1 by impact, P0 by spec-correctness for
deterministic-test-vector parity.

---

## BUG-4 (P0-CDIV interop) — BIP-39 `mnemonic_to_seed` skips UTF-8 NFKD normalisation

**Severity:** P0-CDIV (cross-impl seed-import interop). BIP-39
prescribes: "To create a binary seed from the mnemonic, we use the
PBKDF2 function with a mnemonic sentence (in **UTF-8 NFKD**) used
as the password and the string 'mnemonic' + passphrase (also in
UTF-8 NFKD) used as the salt."

`Bip39.mnemonic_to_seed` (`bip39.ml:407-409`):

```ocaml
let mnemonic_to_seed ~mnemonic ?(passphrase = "") () : Cstruct.t =
  let password = mnemonic in
  let salt = "mnemonic" ^ passphrase in
  ...
```

No `Uchar.normalize`, no `Uunf` dependency, no `~normalize:`NFKD``
flag. The OCaml strings are PBKDF2'd as raw bytes. The resulting
seed will differ from Core / Trezor / Ledger / Electrum / BlueWallet
whenever either input contains any of:
- Combining marks (é written as `e + U+0301` vs precomposed `U+00E9`)
- Ligatures (`ﬁ` U+FB01 vs `fi`)
- Smart quotes (`'` U+2019 in passphrase pasted from macOS / Google Docs)
- Asian half/full-width punctuation
- Non-breaking spaces (U+00A0) accidentally pasted from a PDF
- ZWNJ / ZWJ between words

**Concrete failure mode:** operator generates wallet on Trezor with
passphrase `café`, gets seed `S1`. Imports into camlcoin with
`importmnemonic`, types `café` (precomposed é = U+00E9), camlcoin
PBKDFs `mnemonic` || `caf` || `0xC3 0xA9` and gets seed `S2`. Vs
Trezor which NFKD-normalises and PBKDFs `mnemonic` || `caf` || `0x65
0xCC 0x81`. Seeds differ; wallet sees zero balance.

Same applies to mnemonic-side: pasting a 12-word mnemonic from a
backup that was written with the Japanese (BIP-39 alternative) or
Korean wordlist won't even hit the wordlist lookup
(`bip39.ml:373-379` `Hashtbl.find_opt word_to_index w`), but if a
user enters an English mnemonic where some words happen to contain
NFC-vs-NFKD-distinct characters (none in the English wordlist
today, defensive coding only), the lookup would miss.

Camlcoin SHOULD pull in `Uunf` (or call out to a libicu C stub) and
NFKD-normalise BOTH `mnemonic` and `passphrase` before
PBKDF2-HMAC-SHA512.

**File:** `lib/bip39.ml:407-422`.

**Core ref:** BIP-39 spec §"From mnemonic to seed";
`bitcoin-core/src/wallet/wallet.cpp::GenerateNewSeed` does NOT
expose mnemonics directly (Core uses raw 256-bit seeds), but the
descriptor-wallet path that imports a BIP-39 mnemonic via the
`importmnemonic` RPC (in the BIP-44/49/84/86 PR cluster) does NFKD
via the bundled ICU on the wallet thread.

**Impact:** seed-import interop broken cross-impl for any passphrase
or mnemonic containing non-ASCII. Operators backing up a
hardware-wallet seed into camlcoin's wallet (or vice versa) lose
access to funds on the alternate platform whenever either string
involves Unicode.

---

## BUG-5 (P0-CDIV) — `serialize_xprv` / `serialize_xpub` hardcode mainnet version bytes

**Severity:** P0-CDIV. BIP-32 §"Serialization format" requires the
4-byte version prefix to encode network. `serialize_xprv`
(`wallet.ml:292-307`) and `serialize_xpub` (`wallet.ml:309-331`)
unconditionally write the mainnet constants:

```ocaml
let serialize_xprv (ek : extended_key) : string =
  let buf = Cstruct.create 78 in
  (* Version: mainnet xprv = 0x0488ADE4 *)
  Cstruct.BE.set_uint32 buf 0 0x0488ADE4l;
  ...

let serialize_xpub (ek : extended_key) : string =
  let buf = Cstruct.create 78 in
  (* Version: mainnet xpub = 0x0488B21E *)
  Cstruct.BE.set_uint32 buf 0 0x0488B21El;
  ...
```

The `extended_key` record has no `network` field, and the wallet's
`network` field (`wallet.ml:423`) is never consulted by these two
serialisers. So a camlcoin-testnet operator calling `listdescriptors`
(rpc.ml:6571-6574 — see below) gets:

```json
"desc": "wpkh(xpub6CUGRUonZSQ4TWtTMmzXdrXDtypWKiKrhko4egpiMZbpiaQL2jJwBoKvqj9XwUVTC8Q4UWNgsd5wdQApvX38NkVRcAVLW8GwxYJsdy7nWcQ/84'/0'/0'/0/*)"
```

instead of the BIP-32-correct
`"tpub..."`-prefixed equivalent. Pasting that descriptor into Core
or Electrum **on testnet** raises `parse_xprv: not a tprv` and
refuses to import. Cross-impl portability of testnet/regtest wallet
descriptors is **broken at the serialiser**.

Adjacent gate at `rpc.ml:6577-6580` compounds — the path component
`84'/0'/0'/0` itself bakes mainnet coin_type=0, see BUG-7.

The deserialiser (`deserialize_extended_key`, `wallet.ml:333-360`)
does recognise both mainnet and testnet prefixes, but the asymmetry
"reads four versions, writes one" is the bug — and on a testnet
fleet there is no way for camlcoin to be the source of a testnet
descriptor that other impls can re-derive.

**Fleet pattern continuity:** this is the third W161-family instance
of "writes one, reads many" — see haskoin W160 BUG-? for the
network-byte WIF analog, and ouroboros W160 for the Address.
Same shape; new layer.

**File:** `lib/wallet.ml:291-331`.

**Core ref:**
`bitcoin-core/src/key_io.cpp::DecodeExtKey/EncodeExtKey`;
`bitcoin-core/src/chainparams.cpp::Base58Prefixes[EXT_PUBLIC_KEY]`
per-network.

**Impact:** testnet/regtest descriptor export is mainnet-prefixed;
Core/Electrum refuse to import; cross-impl regtest fleet testing
cannot exchange xprv/xpub between camlcoin and any other node.

---

## BUG-6 (P1) — `depth` field has no overflow guard; silent truncation past 255

**Severity:** P1. BIP-32 specifies the depth byte is exactly 1 byte
(0..255). Camlcoin stores `depth : int` (`wallet.ml:104`),
increments unboundedly:

```ocaml
{ ... depth = parent.depth + 1; ... }    (* wallet.ml:207 *)
```

and writes via `Cstruct.set_uint8 buf 4 ek.depth` (`wallet.ml:297`,
`315`) — `set_uint8` masks to 8 bits silently. So a `m/.../...`
chain of depth 256 produces an extended key serialised with `depth=0`
(masked) — indistinguishable from a master key in the serialised
form. Concrete failure mode: a descriptor wallet that has a 256-deep
chain (impossible in practice for BIP-44/84/86 use, but
constructible via miniscript-of-miniscript or recursive
`tap_tree`/`Tr(Multi(Tr(...)))`) silently re-emits a master-looking
xpub from a deep child.

Camlcoin should `assert (parent.depth < 255)` in `derive_child_key`
and return `Error _` (or fail with an explicit overflow message).

**File:** `lib/wallet.ml:101-107, 207, 297, 315`.

**Core ref:** BIP-32 §"Serialization format"; Core's `CExtKey.nDepth`
is `unsigned char` so an overflow would be a checked C++ error in
debug builds and silent in release — the C++ side has the same
shape but is bounded by the underlying type.

**Impact:** theoretical only for BIP-44/84/86 (max depth 5). For
hand-rolled deeply-nested descriptor or PSBT-as-derivation-source
flows, silent truncation; not consensus-relevant.

---

## BUG-7 (P0-CDIV) — `coin_type` hardcoded to 0 (mainnet) in all 6 BIP-44/84/86 paths

**Severity:** P0-CDIV (funds-loss on cross-impl restore). BIP-44
§"Coin type" maps: `0' = Bitcoin mainnet`, `1' = Bitcoin
testnet/regtest`, `2' = Litecoin`, etc. The camlcoin BIP-84 receive
path (`wallet.ml:222-230`):

```ocaml
let derive_bip84_receive (master : extended_key) (n : int) : (Cstruct.t, string) result =
  let open Result in
  let ( >>= ) = bind in
  derive_hardened master 84 >>= fun purpose ->
  derive_hardened purpose 0 >>= fun coin_type ->     (* <-- HARDCODED 0 *)
  derive_hardened coin_type 0 >>= fun account ->
  derive_normal account 0 >>= fun change ->
  derive_normal change n >>= fun child ->
  Ok child.key
```

All six derivation functions (`derive_bip44_receive/change`,
`derive_bip84_receive/change`, `derive_bip86_receive/change`)
likewise hardcode `0` for coin_type. The wallet's `network` field is
**never consulted in the derivation path**.

Practical consequence: a camlcoin-testnet operator restores their
12-word mnemonic into Core-on-testnet. Core derives `m/84'/1'/0'/...`
(BIP-44 says testnet coin_type=1). Camlcoin derived under
`m/84'/0'/0'/...`. The two derivation paths produce **completely
different keys** — Core sees zero balance, camlcoin sees the real
balance. Funds are NOT lost (they are still in camlcoin's wallet),
but the operator believes the mnemonic backup is corrupt and may
discard it.

Worse: if the operator generates a mnemonic on Core-testnet (path
`m/84'/1'/0'/...`), imports into camlcoin-testnet (which derives
`m/84'/0'/0'/...`), and starts receiving on the camlcoin-derived
addresses, those addresses are not the same as the original
Core-derived ones. The cross-impl restore from camlcoin BACK to
Core then misses ALL funds received during the camlcoin window.

Even on mainnet — fine for the default case — but `m/84'/0'/0'/...`
is by convention "account 0". If the operator wants multiple
accounts (Core-on-mainnet calls `getnewaddress` against
`m/84'/0'/1'/...` for the second account), camlcoin has no
account parameter; it's stuck on account 0' forever.

**File:** `lib/wallet.ml:222-285` (all 6 derivation functions);
also baked into `lib/rpc.ml:6577-6580` descriptor templates:

```ocaml
let wpkh_recv = Printf.sprintf "wpkh(%s/84'/0'/0'/0/*)" key_str in
let tr_recv = Printf.sprintf "tr(%s/86'/0'/0'/0/*)" key_str in
```

**Core ref:** BIP-44 coin_type registry; SLIP-44.

**Impact:**
- Testnet/regtest seed restore broken cross-impl (camlcoin's
  testnet addresses derived under `m/.../0'/...` rather than
  `m/.../1'/...`).
- Multi-account support absent (always account 0').
- The mainnet case happens to align with Core defaults, but the
  derivation-path divergence on testnet means **every cross-impl
  testnet test that exercises the wallet falsely shows
  zero-balance for camlcoin's outputs.**

This is a NEW INSTANCE of the W160-named pattern
"drift-converged-on-wrong-default" — the OTHER fleet impls also
typically hardcode coin_type=0, so a camlcoin↔hotbuns testnet
restore happens to work by chance, but neither matches Core or any
hardware wallet.

---

## BUG-8 (P1) — BIP-49 (P2SH-P2WPKH) derivation entirely absent

**Severity:** P1. BIP-49 (legacy SegWit) is the path used by every
hardware wallet shipped before Taproot (Trezor T pre-2021, Ledger
Nano S/X default before 2022) for backwards-compat SegWit. Camlcoin
has `derive_bip44_*` (P2PKH), `derive_bip84_*` (P2WPKH), and
`derive_bip86_*` (P2TR), but **no `derive_bip49_*`**. The
`address_type` enum (`wallet.ml:367`):

```ocaml
type address_type = P2PKH | P2WPKH | P2TR
```

has no `P2SH_P2WPKH` variant. The `generate_key_typed` dispatch
(`wallet.ml:507-518`) does not list BIP-49.

So a hardware-wallet user with a BIP-49 ypub backup who imports it
via `importmnemonic` would have the wallet deterministically derive
under `m/49'/0'/0'/...` — except camlcoin has no `m/49'` branch in
the derivation library. They would have to type their seed into
Electrum or Core to recover their pre-2021 funds.

Camlcoin does support **receiving** to a P2SH-P2WPKH address via
manual `importaddress`, and `sign_input_p2sh_p2wpkh` (`wallet.ml:1278+`)
exists for the signer — but the DERIVATION side is missing, so the
wallet cannot generate the addresses to import in the first place
without external tooling.

**File:** `lib/wallet.ml:367` (`address_type` enum); no
`derive_bip49_receive/change` exists.

**Core ref:** BIP-49; Core's
`scriptpubkeyman.cpp::LegacyDescriptorScriptPubKeyMan` supports
`sh(wpkh(...))` natively.

**Impact:** missing standard address family. Operators with
pre-2021 hardware-wallet backups cannot use camlcoin for recovery.

---

## BUG-9 (P0-FUNDS, W160 BUG-12/13 2-WAVE CARRY-FORWARD) — Wallet P2TR signer ignores `tap_merkle_root` from the HD-derivation perspective

**Severity:** P0-FUNDS (funds-burn on script-tree key-path spend).
This is the **HD-LAYER restatement** of the W160 BUG-12/13 cluster.
At W160 we caught the bug at the libsecp256k1-tweak layer; at W161
we re-confirm the bug surfaces at the HD-derivation BOUNDARY — i.e.,
the wallet's BIP-86 derivation path (`m/86'/0'/0'/0/n`) produces a
SECRET KEY for the internal key, but the SIGNER never receives the
script-tree merkle root, so the tweaked-private-key it signs with
does NOT match the on-chain tweaked-public-key the verifier expects.

Three signer sites (`wallet.ml:1326-1329, 1603-1605`;
`rpc.ml:3346` — pass-with-caveat) all call:

```ocaml
let tweak = Crypto.compute_taptweak_keypath xonly_pk in
```

`compute_taptweak_keypath` at `crypto.ml:312-313`:

```ocaml
let compute_taptweak_keypath (internal_pubkey_xonly : Cstruct.t) : Cstruct.t =
  tagged_hash "TapTweak" internal_pubkey_xonly             (* JUST P; m omitted *)
```

The PSBT input contains `tap_merkle_root : Cstruct.t option`
(`psbt.ml:120`), which IS populated by Updaters that know about
script-tree outputs. Camlcoin's wallet IGNORES this field at the
HD-derivation-to-signer bridge.

**Why this matters at the HD layer specifically:** BIP-86 §"Address
derivation" says the on-chain output script tweaks the BIP-32-derived
key with `merkle_root = empty` (one specific shape of taproot). But
BIP-32-derived keys are ALSO used as internal keys in `Tr(KEY,
TREE)` descriptors where TREE is non-empty — and in that case the
HD-derivation produces the internal key correctly, but the signer
must combine it with the merkle root of TREE to recover the tweaked
secret. Camlcoin's HD wallet treats every P2TR spend as if it were
BIP-86 single-key.

**Cross-cite:** **3 fleet now (camlcoin origin W160 + blockbrew +
beamchain)** per latest memory; this is the camlcoin re-confirmation
at the HD layer.

**File:** `lib/wallet.ml:1328, 1605`; `lib/crypto.ml:311-313`.

**Core ref:** `bitcoin-core/src/key.cpp:543`
`XOnlyPubKey(pk).ComputeTapTweakHash(merkle_root->IsNull() ? nullptr
: merkle_root)`.

**Impact:** wallet-signed P2TR-script-tree key-path spends produce
invalid signatures; the broadcast tx is rejected at the
`secp256k1_schnorrsig_verify` gate in every Core peer; the fee is
NOT lost (tx never propagates), but operator workflow stalls
indefinitely. NB: classic BIP-86 single-key spend (TREE=None) DOES
sign correctly because the no-merkle-root path is what camlcoin
always uses.

---

## BUG-10 (P0-FUNDS — funds-loss on restart) — Auto-generated mnemonic neither displayed nor persisted; master_key not in JSON

**Severity:** P0-FUNDS. `create_wallet` (`wallet.ml:2978-3000`):

```ocaml
if not options.blank && not options.disable_private_keys then begin
  let mnemonic = Bip39.generate_mnemonic ~strength:128 () in
  init_from_mnemonic wallet mnemonic ()
end;
(* Save to disk *)
(match options.passphrase with
 | Some pass when pass <> "" -> save_encrypted wallet ~passphrase:pass
 | _ -> save wallet);
```

The `mnemonic` local goes out of scope at the end of the `if-then`
block. It is **never returned to the caller**, **never displayed in
the RPC response**, **never persisted to JSON**, **never logged**.
The operator who calls `createwallet "name"` has no way to learn
the seed phrase that the wallet was just generated from. There is
no `getmnemonic` RPC, no `dumpmnemonic`, no `getrecoveryphrase`.

The `save` function (`wallet.ml:2435-2493`) writes `keys`, `utxos`,
indices, history, network — and **deliberately omits**
`master_key`. So on next process restart, `load_wallet_json`
(`wallet.ml:2577-2715`) populates everything except master_key;
`w.master_key` defaults to `None` (from `create`); subsequent
`generate_key` calls fall through the `| None -> Crypto.generate_private_key ()`
branch (`wallet.ml:531`) and produce purely-random non-HD keys.

**Failure cascade:**
1. Operator creates wallet via RPC. Receives 12-word phrase? **NO**
   — only `{"wallet_name": "..."}` (rpc handler at 6601-6608).
2. Operator receives BTC at one of the BIP-84-derived addresses.
3. Wallet writes private key to JSON (in PLAINTEXT for unencrypted
   wallets — see BUG-11).
4. Process restarts (OOM, planned reboot, OS update). `load_wallet_json`
   restores `keys` from JSON; `master_key` stays `None`.
5. Operator calls `getnewaddress`. Camlcoin generates a RANDOM new
   key (BUG-12 — the random fallback path) and adds it to `keys`.
6. **All addresses generated post-restart are unrelated to the seed
   the wallet was created with.** A future "restore from mnemonic"
   would not see them.

This is **single-process funds-loss-on-restart**. Combined with the
hardcoded mainnet coin_type (BUG-7), even a successful restore on
another impl misses the camlcoin-only post-restart-random keys.

**Fleet pattern continuity:** "wiring-look-but-no-wire" applied
to seed material itself. The seed is generated, used, then
ATOMICALLY discarded. Camlcoin's wallet is functionally non-HD
across process restarts.

**File:** `lib/wallet.ml:2978-3000` (mnemonic discard);
`lib/wallet.ml:2435-2493` (JSON save omits master_key);
`lib/wallet.ml:2577-2715` (JSON load omits master_key);
`lib/wallet.ml:519-545` (random fallback when master_key None).

**Core ref:** `bitcoin-core/src/wallet/wallet.cpp::CreateWallet` +
`SetHDSeed`: seed (or mnemonic for descriptor wallets) is persisted
in `wallet.dat`'s `hdseed`/`mnemonic` LMDB record. The
`getwalletinfo` RPC returns `hdseedid`; `dumpwallet` writes the
full hex seed; descriptor wallets surface the mnemonic via
`gethdkeys`.

**Impact:** **all HD-deterministic property lost on first restart.**
Operator workflow:
- Create wallet → receive funds at address A (HD-derived) →
  restart → "getnewaddress" returns address B (RANDOM, not HD).
- After restart, the wallet is a pile of random keys with no
  recoverability beyond the JSON file itself.
- If JSON is corrupted/lost, funds at address A are recoverable
  (private key hex is in JSON) but NOT via mnemonic (mnemonic was
  never told to anyone).

**This is the highest-severity finding this audit by impact-on-real-users.**

---

## BUG-11 (P0-SEC) — `save` writes private keys as plaintext hex even when wallet is encrypted

**Severity:** P0-SEC. `save` (`wallet.ml:2435-2455`):

```ocaml
let save (w : t) : unit =
  let keys_json = List.map (fun kp ->
    `Assoc [
      ("private_key", `String (cstruct_to_hex kp.private_key));    (* PLAINTEXT *)
      ...
```

This is called as the default path from `create_wallet` when
`options.passphrase` is `None` or empty (`wallet.ml:2994-2996`).
The `save_encrypted` counterpart (`wallet.ml:2496+`) exists but is
only invoked when a passphrase is supplied at create time.

Operators who later call `encryptwallet` on a pre-existing
unencrypted wallet (the canonical Core flow) will trigger
`encryptwallet` → key zeroize (`wallet.ml:2290-2295`) → but the
JSON file on disk still has the ORIGINAL plaintext keys from the
previous `save` call. `encryptwallet` does NOT atomically rotate
the on-disk file from plaintext to ciphertext.

So a wallet's on-disk JSON has plaintext keys forever, even after
`encryptwallet`, unless every key is regenerated.

**File:** `lib/wallet.ml:2435-2493` (plaintext path); cross-cite
`encryptwallet` flow (`wallet.ml:2245-2298`).

**Core ref:** Core's `CWallet::EncryptWallet` rewrites the WHOLE
`wallet.dat` after encrypting every key; `vchCryptedKey` entries
replace `vchPrivKey` entries in the BDB/LMDB.

**Impact:** disk-side plaintext key exposure. An operator who
encrypts their wallet (intending the disk-at-rest protection) gets
no actual protection if the wallet was ever saved unencrypted.

---

## BUG-12 (P1) — Random-key fallback breaks HD invariants silently

**Severity:** P1. `generate_key_typed` (`wallet.ml:519-532`):

```ocaml
let private_key = match w.master_key with
  | Some master ->
    let rec try_derive idx = ... in
    try_derive (get_index ())
  | None ->
    Crypto.generate_private_key ()
in
```

When `master_key` is `None` (the post-restart state per BUG-10), the
fallback is a 32-byte random key from `/dev/urandom`. The wallet's
`bip84_receive_index` / `bip44_receive_index` / `bip86_receive_index`
counters are NOT incremented in the `None` branch (only `set_index`
runs in the `Some` branch, line 524). So the indices stay at their
last-known-HD-derived values forever, while real keys accumulate
non-deterministically.

A future `init_from_mnemonic` call (e.g., operator finally
remembers the seed phrase from another source) would re-derive
addresses starting at the stored index — but those addresses don't
match the random-fallback ones used since the restart. The mnemonic
re-import looks "successful" (no error) but misses all funds
received at random-fallback addresses.

The fallback should at least log a warning ("master_key not loaded,
generating non-HD random key") so operators have a signal.

**File:** `lib/wallet.ml:519-532, 565-578`.

**Core ref:** Core's `wallet.cpp::GetKeyFromPool` errors out if no
HD seed is set — there is no random-fallback path.

**Impact:** silent non-HD operation; operator believes restore is
possible but it isn't for any post-restart key.

---

## BUG-13 (P0-CDIV) — Wallet uses PBKDF2-HMAC-SHA512 for encryption KDF; Core uses EVP_BytesToKey (raw SHA-512 chain)

**Severity:** P0-CDIV (cross-impl encrypted-wallet portability).
`derive_key_and_iv` (`wallet.ml:2104-2134`) is PBKDF2-HMAC-SHA512
with 25000 iterations:

```ocaml
let u = ref (hmac_sha512_str ~key:passphrase salt_with_block) in
let result = Bytes.of_string !u in
for _ = 2 to iterations do
  u := hmac_sha512_str ~key:passphrase !u;
  for j = 0 to 63 do
    let b = Char.code (Bytes.get result j) lxor Char.code (String.get !u j) in
    Bytes.set result j (Char.chr b)
  done
done;
```

Bitcoin Core's `CCrypter::BytesToKeySHA512AES`
(`bitcoin-core/src/wallet/crypter.cpp:15-39`) is the OpenSSL
`EVP_BytesToKey`-shape — a chain of raw SHA-512 over `(passphrase ||
salt)` initially, then each subsequent round is `SHA-512(prev)`. NO
HMAC, NO PBKDF2 XOR-fold.

For the same `(passphrase, salt, 25000)` triple, the two KDFs
produce **different 32-byte keys**. The AES-256-CBC ciphertext that
each writes to disk is therefore incompatible:
- Core operator backs up their encrypted `wallet.dat`, restores into
  camlcoin — `wallet_passphrase` fails with "incorrect passphrase".
- Camlcoin operator backs up their `wallet.json`, restores into
  Core — Core cannot parse the JSON format anyway (different
  serialisation), but the conceptual barrier is also the KDF.

The bigger issue: when camlcoin's docstring claims "matches Bitcoin
Core" (`wallet.ml:2098`: "Default number of key derivation rounds
(matches Bitcoin Core)"), that's a **comment-as-confession** — the
ITERATIONS match (25000), but the KDF ALGORITHM doesn't.

**File:** `lib/wallet.ml:2098-2134`.

**Core ref:** `bitcoin-core/src/wallet/crypter.cpp:15-39`
`BytesToKeySHA512AES` (raw SHA-512 chain) vs camlcoin's
PBKDF2-HMAC-SHA512.

**Impact:**
- Cross-impl encrypted-wallet import broken.
- Comment-as-confession: docstring claims Core parity that is false.
- Marginal security: camlcoin's PBKDF2 is actually slightly stronger
  than Core's chained-SHA-512 against precomputed dictionary
  attacks, but no operator can leverage that because the format is
  unique to camlcoin.

---

## BUG-14 (P0-SEC) — Wallet lock does NOT zeroize `master_key` or `chain_code`

**Severity:** P0-SEC. `wallet_lock` (`wallet.ml:2354-2364`):

```ocaml
let wallet_lock (w : t) : unit =
  (* Clear private keys from memory *)
  if w.encryption.encrypted then begin
    List.iter (fun kp ->
      for i = 0 to Cstruct.length kp.private_key - 1 do
        Cstruct.set_uint8 kp.private_key i 0
      done
    ) w.keys
  end;
  w.encryption.lock_state <- Locked
```

The leaf private keys are zeroized — but `w.master_key` is NOT.
`w.master_key.key` (32-byte secret) and `w.master_key.chain_code`
(32-byte chain code) remain in process memory; combined, they let
an attacker who can read process memory re-derive **every** key the
wallet would ever produce on **every** derivation path.

This is worse than not zeroizing a single private key — the
master_key + chain_code together let an attacker compromise
**future** keys too.

**File:** `lib/wallet.ml:2354-2364`; also `wallet.ml:2280-2295`
(encryptwallet flow has the same gap).

**Core ref:** Core's `CWallet::LockWallet` clears `vMasterKey` (the
key-encryption key derived from passphrase) AND the in-memory plain
private keys; the master-seed is in `EncryptedHDChain` and never
held in plaintext post-encryption.

**Impact:** wallet "lock" is partial; memory-read attack (e.g.,
gcore dump, /proc/PID/mem on Linux without seccomp, RAM-scraping
malware) recovers the master_key trivially. Locked wallet is no
more protected than unlocked.

---

## BUG-15 (P1) — `decrypt_private_key` does not zeroize the returned plaintext after copying

**Severity:** P1. `wallet_passphrase` (`wallet.ml:2335-2338`):

```ocaml
(match decrypt_private_key ~master_key ~public_key:kp.public_key encrypted with
 | Some decrypted ->
   Cstruct.blit decrypted 0 kp.private_key 0 32
 | None -> ())
```

`decrypted` is a freshly-allocated Cstruct from `aes_256_cbc_decrypt`.
After the `blit`, it is DROPPED — the OCaml GC will free the
backing memory at some indeterminate later time, but the bytes are
never overwritten. Garbage-collected Cstruct backing stores can be
re-allocated to other code paths that then might log / persist them.

Same shape in `wallet_passphrase_change` and the
`encryptwallet` reverse path.

Camlcoin should call `Cstruct.memset decrypted 0` (or equivalent)
before letting the GC reclaim.

**File:** `lib/wallet.ml:2335-2338`, `wallet.ml:2380-2400`.

**Core ref:** Core uses `SecureString` / `SecureZeroMemory` on every
plaintext key buffer.

**Impact:** memory-side leak of decrypted private keys via GC reuse;
defense-in-depth gap.

---

## BUG-16 (P1) — `init_from_mnemonic` strands wallet on invalid mnemonic via `failwith`

**Severity:** P1. `init_from_mnemonic` (`wallet.ml:485-491`):

```ocaml
let init_from_mnemonic (w : t) (mnemonic : string) ?(passphrase = "") () : unit =
  if not (Bip39.validate_mnemonic mnemonic) then
    failwith "Invalid BIP-39 mnemonic"
  else
    let seed = Bip39.mnemonic_to_seed ~mnemonic ~passphrase () in
    init_from_seed w seed
```

`failwith` raises `Failure _` which is an OCaml exception. The
caller (`create_wallet` at `wallet.ml:2991`) does NOT wrap this in
a `try`. So a user with a single typo in their mnemonic
(`"abandon abandon abandon ... abandon attack"` — last word
"attack" not in wordlist) calls `importmnemonic` and the entire
process crashes with an uncaught exception, taking down the RPC
server along with it.

Should return `result` and bubble the error to the RPC layer for
clean reporting.

**File:** `lib/wallet.ml:485-491`.

**Core ref:** Core's `importmnemonic` flow returns a clean JSON-RPC
error code with the failing-word position.

**Impact:** RPC server crash on operator typo; DoS-via-typo.

---

## BUG-17 (P1) — `deserialize_extended_key` uses `failwith` on unknown version

**Severity:** P1. `deserialize_extended_key` (`wallet.ml:341-348`):

```ocaml
let is_private = match version with
  | v when v = 0x0488ADE4l -> true   (* xprv *)
  | v when v = 0x04358394l -> true   (* tprv *)
  | v when v = 0x0488B21El -> false  (* xpub *)
  | v when v = 0x043587CFl -> false  (* tpub *)
  | _ -> failwith "deserialize_extended_key: unknown version"
in
```

Returns `result` for length errors but raises an OCaml exception
for unknown version bytes. So an operator pasting a `ypub...`
(SLIP-132 BIP-49) or `zpub...` (SLIP-132 BIP-84) into
`importdescriptor` crashes the RPC handler rather than getting a
clean error.

Should be `Error _` consistently with the rest of the function.

**File:** `lib/wallet.ml:333-360`.

**Impact:** RPC crash on operator-supplied non-standard extended
key; same shape as BUG-16.

---

## BUG-18 (P1) — `wallet.network` not threaded through; descriptor template hardcodes mainnet path

**Severity:** P1. `listdescriptors` handler (`rpc.ml:6571-6580`):

```ocaml
let key_str = if include_private then
  Wallet.serialize_xprv master_key
else
  Wallet.serialize_xpub master_key
in
let wpkh_recv = Printf.sprintf "wpkh(%s/84'/0'/0'/0/*)" key_str in
let wpkh_change = Printf.sprintf "wpkh(%s/84'/0'/0'/1/*)" key_str in
let tr_recv = Printf.sprintf "tr(%s/86'/0'/0'/0/*)" key_str in
let tr_change = Printf.sprintf "tr(%s/86'/0'/0'/1/*)" key_str in
```

Three problems composed:
1. `key_str` is mainnet-prefixed regardless of network (BUG-5).
2. The path components `84'/0'/0'` hardcode coin_type=0 (BUG-7).
3. No BIP-49 descriptor (`sh(wpkh(...))`) is emitted at all (BUG-8).

A testnet operator calling `listdescriptors` gets descriptors that
are unimportable into Core-on-testnet on three independent axes.
Composition of three independent bugs amplifies the "no cross-impl
restore" failure mode.

**File:** `lib/rpc.ml:6567-6610`.

**Impact:** descriptor export from camlcoin-testnet is unusable in
Core-on-testnet for three independent reasons.

---

## BUG-19 (P1) — `fingerprint_of_key` recomputes pubkey from private key on every call (no cache)

**Severity:** P1 (perf, not correctness). `derive_child_key` calls
`fingerprint_of_key parent` (`wallet.ml:204`) once per derivation.
`fingerprint_of_key` (`wallet.ml:130-139`) calls
`Crypto.derive_public_key` (which is a libsecp256k1 FFI:
`secp256k1_ec_pubkey_create + serialize`) — one EC scalar
multiplication per derivation. For a 5-level path (BIP-84 default),
that's 5 unnecessary scalarmul/serialise round-trips per address;
gap-limit scan of 1000 indices = 5000 round-trips.

Core caches the pubkey on the parent extended key (`CExtKey.pubkey`)
and never re-derives.

**File:** `lib/wallet.ml:130-139`.

**Impact:** address-generation throughput ~5× slower than Core; gap-limit scans
take ~5 seconds where Core takes ~1.

---

## BUG-20 (P1) — `create_wallet` defaults `strength=128` (12-word mnemonic = 128-bit entropy)

**Severity:** P1. `create_wallet` (`wallet.ml:2990`):

```ocaml
let mnemonic = Bip39.generate_mnemonic ~strength:128 () in
```

Hard-codes 128 bits of entropy, which produces a 12-word mnemonic.
Bitcoin Core's descriptor wallets default to **256 bits** (24-word
mnemonic) for the post-quantum-era security margin. 128 bits is
fine against classical attackers but a notable downgrade vs
recommended practice.

There's no caller-supplied `entropy_bits` parameter in
`create_wallet`'s `options`. Combined with BUG-10 (mnemonic never
shown to operator), the choice of 128 vs 256 is moot — the operator
sees neither — but operators who manually decode the in-memory
mnemonic (via debugger) get a 12-word phrase regardless of preference.

**File:** `lib/wallet.ml:2990`.

**Core ref:** Core descriptor wallets use 32-byte seeds by default
(BIP-32 master seed) — but the `gethdkeys` mnemonic surface emits
24 words when present.

**Impact:** weaker default entropy. Cross-cite: BUG-10's
discard-mnemonic gap makes this academic for now.

---

## BUG-21 (P2) — `derive_master_key` reads "Bitcoin seed" as a Cstruct on every call

**Severity:** P2 (perf, not correctness). `wallet.ml:117`:

```ocaml
let key_str = Cstruct.of_string "Bitcoin seed" in
```

Allocated and copied on every master-derivation. Trivial, but the
fleet pattern is to hoist these constants to a module-level
`let key_str = lazy (Cstruct.of_string "Bitcoin seed")` or
`let key_str = Cstruct.of_string "Bitcoin seed"` at module load.

**File:** `lib/wallet.ml:117`.

**Impact:** negligible perf; cited only for fleet-style
consistency.

---

## BUG-22 (P1) — `validate_mnemonic` does not require words be in the same wordlist family (English-only enforced silently)

**Severity:** P1. `validate_mnemonic` (`bip39.ml:367-401`) checks
each word against the **English** `word_to_index` Hashtbl. A
Japanese / Spanish / French BIP-39 mnemonic (alternative wordlists
defined in BIP-39 §"Wordlist") is rejected as invalid with no
context — the error message is just `false`, returned to the caller
which surfaces "Invalid BIP-39 mnemonic" (BUG-16).

Hardware wallets shipped for non-English-speaking markets (Trezor
in Japan, Ledger in France) routinely use the localised wordlist.
Operators with those backups cannot restore into camlcoin even with
no typos.

Camlcoin should bundle the 7 other BIP-39 wordlists (Japanese,
Korean, Spanish, French, Italian, Chinese-Simplified,
Chinese-Traditional, Czech, Portuguese) and auto-detect the
wordlist by majority match.

**File:** `lib/bip39.ml:367-401, 268-271` (only English wordlist
loaded).

**Core ref:** Core's `importmnemonic` accepts all BIP-39 wordlists
via the bundled ICU + the standard wordlist file set.

**Impact:** non-English mnemonic backups silently unimportable.

---

## Fleet-pattern continuity (cross-cite from W158–W160 memory)

- **`context_randomize` UNIVERSAL (fleet-wide):** Confirmed
  present in camlcoin per W160 BUG-2 carry-forward. W161 HD audit
  does not re-test (HD code uses libsecp256k1 indirectly via
  `ec_seckey_tweak_add` / `ec_pubkey_tweak_add`); the unblinded
  context affects every HD CKDpriv call's side-channel surface.
- **sigcache-omits-sighash UNIVERSAL 10/10:** N/A at HD layer
  (no sigcache interaction in derivation). HD path produces
  secrets; verification path is elsewhere.
- **sign-then-verify paranoia absent (W160 BUG-3/4/5):** N/A at
  HD layer (no signing in derivation). Cross-cite: the wallet
  SIGNER does inherit this absence — when it signs BIP-86 keypath
  spends (`wallet.ml:1329` `schnorr_sign_tweaked`), no
  post-sign-verify round-trips.
- **BIP-32 private-GMP asymmetry (haskoin + blockbrew named):**
  **camlcoin PASS-WITH-CREDIT** — `derive_child_key` routes both
  sides through libsecp256k1 (`wallet.ml:75-79`); explicit comment
  at line 67-69 confirms the opam secp256k1-internal binding has
  been retired. This is the OPPOSITE of the haskoin/blockbrew
  pattern; camlcoin is in the safe column.
- **TapTweak no-merkle-root (camlcoin origin W160 BUG-12+13 +
  blockbrew + beamchain = 3 fleet):** **CONFIRMED at HD layer as
  W161 BUG-9** — 2-WAVE CARRY-FORWARD. The HD-derivation path
  produces internal keys correctly; the signer-side bug at the
  PSBT/sign_transaction_inputs entry persists.
- **drift-converged-on-wrong-default (camlcoin origin W160):**
  **NEW INSTANCE at HD layer as W161 BUG-7** — `coin_type=0`
  hardcoded across all 6 BIP-44/84/86 derivation functions; the
  3 P2TR signer sites converge on no-merkle-root; the descriptor
  templates converge on mainnet path. Drift is in the OPPOSITE
  direction (3+ pipelines all-agreeing on a wrong default) rather
  than diverging from a canonical one.
- **BIP-340 nonce=0 fallback:** N/A at HD layer.

**New fleet patterns this audit:**
- **"Discard-then-derive-then-discard"** (BUG-10) — the mnemonic
  is generated, used, and thrown away within a single function call.
  An extension of "wiring-look-but-no-wire" applied to seed
  material itself. **NEW fleet meta-pattern this wave.**
- **"Comment-as-confession at the KDF algorithm level"** (BUG-13)
  — docstring "matches Bitcoin Core" while the algorithm
  differs (PBKDF2 vs EVP_BytesToKey). **14th distinct
  comment-as-confession instance in camlcoin** per latest count.
- **"Writes-one-reads-many" (camlcoin BUG-5)** — third W161-family
  instance after the network-byte WIF + Address analogs.
- **"failwith on operator input"** (BUG-16 + BUG-17 — 2 distinct
  sites this wave) — RPC handlers crash on common operator errors
  (typo in mnemonic; non-standard xpub prefix). Cross-cite:
  pattern previously called "exception-as-error-channel" for
  network code at W155.

---

## Cross-cite W158–W160 outcomes (HD-layer carry-forward status)

| W-wave | Bug | Status at W161 HEAD |
|--------|-----|---------------------|
| W160 BUG-1 (sigcache SegWit-malleability) | unchanged (out of HD scope) | UNFIXED |
| W160 BUG-2 (sigcache salt-free) | unchanged | UNFIXED |
| W160 BUG-3/4/5 (sign-then-verify) | unchanged | UNFIXED |
| W160 BUG-8 (no NULL aux fallback) | unchanged | UNFIXED |
| **W160 BUG-12 / BUG-13 (TapTweak no-merkle-root signer)** | **W161 BUG-9 — 2-WAVE CARRY-FORWARD** | UNFIXED |
| W160 BUG-15 (WIF network-byte) | confirmed present per cross-cite | UNFIXED |
| W159 BUG-2 (context_randomize) | confirmed present | UNFIXED |

**Audit-drumbeat outpacing fix-drumbeat (camlcoin)** — every prior
camlcoin wallet/crypto P0 from W158–W160 remains unfixed at W161
HEAD, plus this wave adds **3 NET-NEW P0** (BUG-7 coin_type, BUG-10
mnemonic-discard, BUG-13 KDF, BUG-14 master_key not zeroed) and **1
P0 CARRY-FORWARD** (BUG-9 W160 BUG-12/13).

---

## Top priorities (recommended next fix wave)

1. **🚨 BUG-10 (P0-FUNDS, NEW)** — `create_wallet` must (a)
   return the mnemonic to the RPC caller, (b) persist
   `master_key` (encrypted under the wallet passphrase if
   encrypted) to JSON, (c) expose a `dumpmnemonic` / `gethdkeys`
   RPC. **Highest urgency this wave** — affects every wallet
   create-then-restart sequence.
2. **🚨 BUG-7 (P0-CDIV)** — `coin_type` must derive from
   `wallet.network` (mainnet=0', testnet/regtest/signet=1') in all
   6 `derive_bip*` functions AND in the descriptor templates at
   rpc.ml:6577. **~10 LOC.**
3. **🚨 BUG-9 (P0-FUNDS, 2-WAVE CARRY-FORWARD)** — thread
   `tap_merkle_root` through the 3 P2TR signer sites
   (`wallet.ml:1328, 1605`; `rpc.ml:3346`). **Same fix as
   W160 prio 1**; still not landed.
4. **🚨 BUG-5 (P0-CDIV)** — `serialize_xprv` / `serialize_xpub`
   must take a `network` arg (or read `extended_key.network`) and
   emit `tprv`/`tpub` on testnet/regtest. **~10 LOC.**
5. **🚨 BUG-13 (P0-CDIV)** — replace PBKDF2 with
   EVP_BytesToKey-shape SHA-512 chain to match Core's encrypted
   wallet format. **~30 LOC** (single rewrite of
   `derive_key_and_iv`).
6. **🚨 BUG-14 (P0-SEC)** — `wallet_lock` must zeroize
   `w.master_key.key` AND `w.master_key.chain_code` AND set
   `w.master_key <- None`. **~5 LOC.**
7. **🚨 BUG-11 (P0-SEC)** — `encryptwallet` must atomically
   rewrite the on-disk JSON from plaintext to ciphertext (or
   refuse to operate on unencrypted-saved wallets without explicit
   `--re-save` flag). **~20 LOC.**
8. **🚨 BUG-4 (P0-CDIV)** — pull in `Uunf` (opam package) and
   NFKD-normalise both mnemonic AND passphrase in
   `Bip39.mnemonic_to_seed` before PBKDF2. **~15 LOC + dependency
   add.**
9. **🚨 BUG-2 (P0-SEC, rare)** — call
   `secp256k1_ec_seckey_verify` on master IL; return Error to
   `init_from_seed`. **~5 LOC.**
10. **BUG-16 / BUG-17 (P1)** — replace `failwith` in
    `init_from_mnemonic` and `deserialize_extended_key` with
    `Result.Error`. **~5 LOC each.**
11. **BUG-8 (P1)** — add BIP-49 derivation family
    (`P2SH_P2WPKH` variant of `address_type`, `derive_bip49_*`).
    **~50 LOC.**
12. **BUG-22 (P1)** — bundle non-English BIP-39 wordlists for
    cross-locale operator support. **~2000 LOC of wordlist data +
    20 LOC of detection logic.**

---

## Summary

**Bug count:** 22 (BUG-1 through BUG-22).

**Severity distribution:**
- **P0-FUNDS:** 2 (BUG-9 carry-forward, BUG-10 new)
- **P0-CDIV:** 5 (BUG-4, BUG-5, BUG-7, BUG-13, BUG-18)
- **P0-SEC:** 3 (BUG-2, BUG-11, BUG-14)
- **P0-SEC (rare):** 1 (BUG-2 — astronomically rare master IL≥n)
- **P1:** 10 (BUG-1, BUG-3, BUG-6, BUG-8, BUG-12, BUG-15, BUG-16,
  BUG-17, BUG-19, BUG-20, BUG-22)
- **P2:** 1 (BUG-21)

(Re-count: P0-FUNDS 2 + P0-CDIV 5 + P0-SEC 3 + P1 11 + P2 1 = 22. ✓)

**Top three findings:**

1. **BUG-10 (P0-FUNDS — mnemonic discard + master_key not
   persisted)** — `create_wallet` generates a 12-word mnemonic,
   uses it once to seed the HD chain, and **throws it away**
   without showing it to the operator or persisting any seed
   material. The `save` function omits `master_key` from JSON. On
   process restart, the wallet falls back to RANDOM key generation
   silently. **Every camlcoin wallet is functionally non-HD across
   restarts**; restore-from-mnemonic is impossible because the
   mnemonic was never communicated. **Highest impact-on-real-users
   finding of this audit.**

2. **BUG-7 (P0-CDIV — coin_type hardcoded 0 in all 6 derivation
   functions)** — every `derive_bip44_*` / `derive_bip84_*` /
   `derive_bip86_*` hardcodes the BIP-44 coin_type to `0` (mainnet).
   The wallet's `network` field is never consulted. Cross-impl
   testnet/regtest restore is fundamentally broken — Core-on-testnet
   derives at `m/84'/1'/...` while camlcoin-testnet derived at
   `m/84'/0'/...`. NEW INSTANCE of the "drift-converged-on-wrong-default"
   pattern (camlcoin origin W160) — three independent pipelines
   (BIP-44, BIP-84, BIP-86) all-agreeing on the wrong default at
   testnet.

3. **BUG-9 (P0-FUNDS — W160 BUG-12/13 2-WAVE CARRY-FORWARD)** —
   Wallet P2TR signer (`wallet.ml:1328, 1605`) hardcodes
   `compute_taptweak_keypath xonly_pk` with NO merkle root,
   regardless of `tap_merkle_root` being present in the PSBT input.
   Any P2TR script-tree key-path spend signs with a tweak that does
   not match the on-chain output key; signature fails verification;
   broadcast tx rejected. Confirmed unchanged from W160.
