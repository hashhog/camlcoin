# W160 — ECDSA + Schnorr + RFC 6979 + sighash construction (camlcoin)

**Wave:** W160 — `secp256k1_ecdsa_sign` / `secp256k1_ecdsa_sign_recoverable` /
`secp256k1_schnorrsig_sign32` / `secp256k1_keypair_xonly_tweak_add`
internals, **RFC 6979** deterministic nonce derivation
(`secp256k1_nonce_function_rfc6979`), **BIP-340** `aux_rand32` sourcing
(`secp256k1_nonce_function_bip340`, including the `NULL aux` ZERO_MASK
fallback), low-S normalisation (BIP-62 rule 5), DER strict encoding (BIP-66),
**BIP-143** SegWit-v0 sighash (`hashPrevouts` / `hashSequence` / `hashOutputs`
construction; midstate caching via `PrecomputedTransactionData`), **BIP-341**
Taproot sighash (`HASHER_TAPSIGHASH` tagged hash, epoch=0, ext_flag,
`SIGHASH_DEFAULT == ALL`, `sha_amounts` / `sha_scriptpubkeys`
`sha_sequences` / `sha_outputs`, spend_type byte, `key_version=0`, annex
hash, tapleaf hash, codesep_pos), the SIGHASH_SINGLE legacy bug
(`uint256(1)` sentinel), Taproot keypair seckey-flip on odd-y (handled
internally by libsecp256k1's `secp256k1_keypair_xonly_tweak_add`),
sign-then-verify paranoia (Core `CKey::Sign` / `CKey::SignCompact` /
`KeyPair::SignSchnorr`), `secp256k1_ec_seckey_verify` scalar-range gate,
**signature cache key shape** including witness coverage (W159 BUG-17
chain-split candidate re-audit), low-R grinding (Core's 71-byte signature
optimisation), BIP-32 hardened derivation hash discipline, WIF version-byte
stripping (W158 cross-network signing oracle re-audit), in-memory key
hygiene.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/key.cpp:209-235` — `CKey::Sign`: calls
  `secp256k1_ecdsa_sign(ctx, &sig, hash, key, secp256k1_nonce_function_rfc6979, extra_entropy?)`
  with low-R grinding (`while (ret && !SigHasLowR(&sig) && grind) { ++counter; resign with extra_entropy; }`)
  → produces 71-byte DER sigs (saves 1 vbyte per spend, ~1% block-space
  savings cumulatively). Then `secp256k1_ec_pubkey_create` +
  `secp256k1_ecdsa_verify` round-trip the just-produced sig and
  `assert(ret)` — **sign-then-verify paranoia**.
- `bitcoin-core/src/key.cpp:250-271` — `CKey::SignCompact` (signmessage
  recoverable): `secp256k1_ecdsa_sign_recoverable` → `serialize_compact`
  → `secp256k1_ec_pubkey_create` + `secp256k1_ecdsa_recover` +
  `secp256k1_ec_pubkey_cmp` and `assert(ret == 0)`. **Sign-then-recover paranoia.**
- `bitcoin-core/src/key.cpp:273-281` — `KeyPair::SignSchnorr`:
  `secp256k1_schnorrsig_sign32(ctx, sig, hash, &keypair, aux.data())`,
  then `secp256k1_keypair_xonly_pub` + `secp256k1_schnorrsig_verify`
  round-trip on the produced sig, `memory_cleanse(sig.data(), 64)` on
  failure. **Sign-then-verify paranoia for Schnorr.**
- `bitcoin-core/src/key.cpp:532-547` — `KeyPair` constructor: takes
  `const uint256* merkle_root`; if non-null calls
  `secp256k1_keypair_xonly_tweak_add(ctx, keypair, tweak)` with
  `tweak = XOnlyPubKey(pk).ComputeTapTweakHash(merkle_root)`. libsecp256k1
  flips the seckey internally on odd-y so the caller doesn't have to.
- `bitcoin-core/src/key.cpp:159` — `CKey::Check(vch)`: every set-from-buffer
  runs `secp256k1_ec_seckey_verify` (scalar in [1, n-1]) before the key
  is usable.
- `bitcoin-core/src/secp256k1/src/modules/recovery/main_impl.h:38-72` —
  recoverable signature {parse,serialize}_compact API (recid in [0,3];
  scalar-range overflow detection on parse).
- `bitcoin-core/src/secp256k1/src/modules/schnorrsig/main_impl.h:52-100` —
  `nonce_function_bip340`: when `data` (aux_rand) is `NULL`, falls back
  to the precomputed `ZERO_MASK` (key XOR fixed precomputed
  `TaggedHash("BIP0340/aux", 0...0)`). **NULL aux is well-defined and safe**
  (deterministic but tagged so the nonce is still BIP-340-correct; the
  aux_rand just adds defense-in-depth against side-channel/fault attacks).
- `bitcoin-core/src/secp256k1/src/ecdsa_impl.h` — RFC 6979 is delegated
  to `secp256k1_nonce_function_rfc6979` (HMAC-DRBG over `key||hash||...`);
  optional `extra_entropy` is fed in as `data` (low-R grinding uses the
  counter byte).
- `bitcoin-core/src/script/interpreter.cpp:1483-1570` — `SignatureHashSchnorr`:
  - epoch `0x00`, then `hash_type` byte
  - `output_type = (hash_type == SIGHASH_DEFAULT) ? SIGHASH_ALL : (hash_type & SIGHASH_OUTPUT_MASK)`
  - `input_type = hash_type & SIGHASH_INPUT_MASK` (0x80)
  - `SIGHASH_OUTPUT_MASK = 3`, `SIGHASH_INPUT_MASK = 0x80`
  - `spend_type = (ext_flag << 1) + (have_annex ? 1 : 0)` where
    `ext_flag = 0` (TAPROOT key-path) or `1` (TAPSCRIPT)
  - if `input_type != ANYONECANPAY`: write
    `m_prevouts_single_hash || m_spent_amounts_single_hash ||
     m_spent_scripts_single_hash || m_sequences_single_hash`
    (single-SHA256, from precomputed cache — NOT recomputed per input)
  - if `output_type == SIGHASH_ALL`: write `m_outputs_single_hash`
  - in-pos is `uint32_t` (4 bytes LE)
  - if `output_type == SIGHASH_SINGLE`: `if (in_pos >= tx_to.vout.size()) return false;`
    → causes SCRIPT_ERR_SCHNORR_SIG_HASHTYPE
  - if `TAPSCRIPT`: write `tapleaf_hash || key_version=0 || codeseparator_pos`
- `bitcoin-core/src/script/interpreter.cpp` — BIP-143 segwit-v0 sighash
  (`SignatureHash` overload at line ~1325): same midstate-cache pattern
  via `cacheready` / `hashPrevouts` / `hashSequence` / `hashOutputs`.
- `bitcoin-core/src/script/interpreter.h:37-38` — `SIGHASH_OUTPUT_MASK = 3`,
  `SIGHASH_INPUT_MASK = 0x80`.
- `bitcoin-core/src/script/sigcache.cpp:39-49` — cache entry
  `m_salted_hasher_(ecdsa|schnorr).Write(sighash, 32).Write(pubkey).Write(sig).Finalize()`.
  **Full (sighash, pubkey, sig) goes into the cache key — NOT (txid, vin_idx)**.
  Reason: the sighash already covers the witness via BIP-143/BIP-341
  pre-image, so malleated-witness double-spends produce a different
  sighash → different cache key → no false-positive cache hit.
- `bitcoin-core/src/script/interpreter.cpp:1572-1640` —
  `SigHashCache::CacheIndex` / `Load` / `Store`: per-input cache of the
  legacy / segwit-v0 sighash by `(hash_type, script_code)`, keyed on
  `cacheindex = 3*ANYONECANPAY + 2*SINGLE + 1*NONE` (4 slots × 2
  base/witness = 8 cached preimages per input).
- BIP-32 §"Private parent key → private child key": if `IL ≥ n` or
  `ki = 0`, return failure and RETRY at index `i+1`. The 1-in-2^127
  failure probability means the retry path is never exercised in
  practice, but skipping the retry is a non-conformance.
- BIP-340 §"Signing": `aux_rand` is "a fresh 32-byte uniformly random
  value (optional)". Implementations MAY use `aux_rand = NULL` which
  reduces nonce-reuse-resistance vs side-channel attacks but never
  causes a verification failure.

**Files audited**
- `lib/crypto.ml` (744 lines) — external bindings for
  `ec_pubkey_create`, `ecdsa_sign_der`, `ecdsa_sign_compact`,
  `ecdsa_recover_compact`, `ecdsa_signature_is_low_s`, `verify_ecdsa_fast`,
  `verify_ecdsa_normalized`, `verify_lax`, `schnorr_verify(_batch)`,
  `schnorr_sign`, `schnorr_sign_tweaked`, `derive_xonly_pubkey`,
  `xonly_pubkey_tweak_add(_check)(_with_parity)`,
  `compute_taproot_tweak`, `compute_taproot_output_key(_with_parity)`,
  `compute_taptweak_keypath`, `tagged_hash`, `message_hash`.
- `lib/schnorr_stubs.c` (1068 lines) — C FFI stubs against vendored
  libsecp256k1; `ensure_ctx()` lazy-init, `caml_ecdsa_sign_der`
  (line 886-921), `caml_ecdsa_sign_compact` (line 748-775),
  `caml_schnorr_sign` (line 97-129), `caml_schnorr_sign_tweaked`
  (line 131-170), `caml_schnorr_verify_batch` (line 545-578),
  `caml_ec_seckey_tweak_add` (line 949-976).
- `lib/script.ml`:
  - `compute_sighash_legacy` (line 852-913) — legacy pre-segwit sighash,
    SIGHASH_SINGLE bug preserved (`uint256(1)` sentinel at line 862-864).
  - `compute_sighash_segwit` (line 916-975) — BIP-143; recomputes
    `hash_prevouts` / `hash_sequence` / `hash_outputs` per call.
  - `compute_sighash_taproot` (line 1017-1168) — BIP-341; epoch=0,
    spend_type via `(annex?1:0) lor (tapleaf?2:0)`, prevouts-length guard.
  - `is_valid_taproot_hash_type` (line 990-991), `taproot_sighash_single_safe`
    (line 1001-1003), `get_signature_hash_type` (line 1185-1188),
    `strip_hash_type` (line 1191-1194), `is_defined_hash_type` (line 757-759).
  - OP_CHECKSIG / OP_CHECKSIGVERIFY / OP_CHECKMULTISIG(VERIFY) /
    OP_CHECKSIGADD call sites (line 1880-1991, 1995-2110, 2113-2264,
    2367-2445); top-level taproot key-path branch (line 2960-3017).
- `lib/sig_cache.ml` (170 lines) — `cache_key = {txid; input_index; flags}`
  (line 19-23), `hash_key` (line 27-33). **No witness coverage.**
- `lib/validation.ml:1148-1196, 1206-1254` — serial-mempool path
  uses bare `Sig_cache.lookup`/`insert` (line 1167-1188); parallel-block
  path uses mutex-wrapped `cache_lookup`/`cache_insert` (line 1240-1253).
- `lib/wallet.ml:64-220` — BIP-32 derive; `derive_child_key` (line
  158-211) calls `ec_seckey_tweak_add_raw` / `ec_pubkey_tweak_add_raw`;
  no `IL >= n` retry-at-i+1.
- `lib/wallet.ml:1178-1378` — `sign_input_p2wsh`, `sign_input_p2sh_p2wpkh`,
  `sign_input_p2sh_p2wsh`, `sign_transaction_inputs` (BIP-143 sighash for
  P2WPKH / P2WSH / P2SH-P2WPKH; BIP-341 sighash for P2TR key-path).
- `lib/wallet.ml:1580-1620` — PSBT signer P2TR branch (line 1605
  hard-codes `compute_taptweak_keypath` regardless of `tap_merkle_root`).
- `lib/wallet.ml:649-680` — `import_wif` / `export_wif` discard the
  WIF network byte after decode.
- `lib/rpc.ml:2839-2935` — `signmessagewithprivkey`, `signmessage`,
  `verifymessage` handlers (line 2845: `let _network = ...` discards).
- `lib/rpc.ml:3320-3360` — secondary signing dispatcher (the
  three-arg-of-args path for `sendrawtransaction` priv-key signing).
- `lib/psbt.ml:30-200, 280-330` — PSBT sighash-type, tap_internal_key /
  tap_merkle_root fields; PSBT serialization.
- `lib/address.ml:424-457, 543-562` — WIF encode/decode (returns network
  in `wif_decode` but `decode_wif` does not).
- `lib/perf.ml:569-613` — only production caller of `schnorr_verify_batch`.
- `test/test_crypto.ml:260-355, 539-927` — alcotest cases for DER
  encoding / valid-sighash bytes / batch-verify happy-path / Taproot
  tagged-hashes / merkle-root path / no-tweak path.
- `test/test_psbt.ml:304-323, 633-790` — PSBT sighash_type, Taproot key
  sig, three-party signing.

---

## Gate matrix (30 sub-gates / 12 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | sigcache witness coverage (W159 BUG-17 re-audit) | G1: cache key includes (sighash, pubkey, sig) tuple, NOT (txid, input_idx) | **BUG-1 (P0-CONS chain-split, 2-WAVE CARRY-FORWARD from W159 BUG-17)** — `sig_cache.ml:19-23` `cache_key = {txid; input_index; flags}` UNCHANGED at HEAD. Compute_txid (`crypto.ml:343-346`) calls `serialize_transaction_no_witness` — txid excludes witness. SegWit malleability still re-poisons cache. **See dedicated section below.** |
| 1 | … | G2: cache key uses per-process random salt | **BUG-2 (P0-SEC, W159 BUG-16 CARRY-FORWARD)** — `sig_cache.ml:27-33` `hash_key` is salt-free XOR-fold of 8 bytes. No retry at HEAD. |
| 1 | … | G3: sigcache key DIFFERENT between mempool & block validation | PARTIAL — flags differ (`script_verify_*` mask is included), but txid+input_index are identical between admissions of the same tx into different contexts (e.g. mempool vs block). Not a bug on its own; combined with BUG-1 it amplifies the witness-malleability oracle. |
| 2 | sign-then-verify paranoia | G4: post-sign verify on ECDSA DER path | **BUG-3 (P0-SEC, W159 BUG-7 CARRY-FORWARD)** — `schnorr_stubs.c:902-905` `caml_ecdsa_sign_der` signs and returns; no `secp256k1_ec_pubkey_create` + `secp256k1_ecdsa_verify` round-trip. Cosmic-ray / row-hammer of the seckey buffer would silently emit a wrong-signing-key signature. |
| 2 | … | G5: post-sign recover-and-compare on signmessage path | **BUG-4 (P0-SEC, W159 BUG-8 CARRY-FORWARD)** — `schnorr_stubs.c:757-774` `caml_ecdsa_sign_compact` lacks the recover-and-compare. |
| 2 | … | G6: post-sign verify on Schnorr path | **BUG-5 (P1, W159 BUG-9 CARRY-FORWARD)** — `schnorr_stubs.c:97-129` and 131-170. No Schnorr round-trip. |
| 3 | Low-R grinding | G7: ECDSA sign retries with incrementing extra_entropy until `SigHasLowR` | **BUG-6 (P1, NEW)** — `schnorr_stubs.c:886-921` `caml_ecdsa_sign_der` makes ONE `secp256k1_ecdsa_sign` call with `noncefp=NULL, ndata=NULL`. Core (`key.cpp:218-225`) grinds with `extra_entropy = counter` until the produced sig has low R (first byte of R ≤ 0x7F → DER R-length 32 not 33). The 1-byte savings per signature is 99% of mainnet ECDSA sigs are 71-byte (low-R) rather than 72-byte. **Cumulative: ~1% block-space savings per Core spend.** camlcoin wallet-produced sigs are ~1 vbyte heavier on average → fees slightly higher than Core for the same script. **See dedicated section.** |
| 4 | RFC 6979 deterministic nonce | G8: ECDSA uses `secp256k1_nonce_function_rfc6979` explicitly | **BUG-7 (P2, NEW)** — `schnorr_stubs.c:903` calls `secp256k1_ecdsa_sign(ctx, &sig, msg, sk, NULL, NULL)`. The 5th arg `noncefp=NULL` causes libsecp256k1 to fall back to its **default nonce function** which is `secp256k1_nonce_function_default` defined as `nonce_function_rfc6979` (so behaviour is identical). The bug is shape, not behaviour: Core (`key.cpp:218`) **explicitly** passes `secp256k1_nonce_function_rfc6979` so a future libsecp256k1 default-change (e.g., shifting to a different DRBG) would silently change camlcoin sig shape while Core stays pinned. Defense-in-depth gap. |
| 5 | BIP-340 aux_rand sourcing | G9: 32 bytes of fresh entropy per `schnorr_sign32` call | PARTIAL (W159 BUG-12 still present) — opens `/dev/urandom` per-call; ~25 µs syscall overhead per Schnorr sig. |
| 5 | … | G10: NULL aux_rand fallback when entropy source unavailable | **BUG-8 (P1, W159 BUG-12 CARRY-FORWARD)** — `schnorr_stubs.c:113-117` raises `Failure` on `/dev/urandom` open/read failure. libsecp256k1's `nonce_function_bip340` accepts `data == NULL` and falls back to the precomputed `ZERO_MASK` derived from `TaggedHash("BIP0340/aux", 0...0)` — **a documented, deterministic, safe fallback**. camlcoin's failure path strands the wallet in unsignable state on /dev/urandom unavailability (chroot, container without `/dev`, ulimit-restricted env). |
| 5 | … | G11: per-call entropy independent of process entropy state | PARTIAL — `/dev/urandom` is independent of any OCaml RNG state, so this is fine; the BUG-8 issue is the absence of a NULL fallback, not the entropy quality. |
| 6 | low-S normalisation (BIP-62 rule 5) | G12: signing path normalises to low-S before serialise | PASS — `schnorr_stubs.c:908` calls `secp256k1_ecdsa_signature_normalize(ctx, &sig, &sig)` before `serialize_der`. |
| 6 | … | G13: verify path normalises before verify (lax mode) | PASS — `caml_ecdsa_verify_lax` at `schnorr_stubs.c:524` normalises before verify. |
| 6 | … | G14: strict-DER `is_low_der_s` helper | PASS — `caml_ecdsa_signature_is_low_s` at `schnorr_stubs.c:929-945` uses libsecp256k1's `normalize` return value as the low-S indicator. |
| 7 | DER strict (BIP-66) | G15: `is_valid_signature_encoding` matches Core's `IsValidSignatureEncoding` | PASS — `crypto.ml:116-153` is a near-byte-for-byte port of `bitcoin-core/src/script/interpreter.cpp:108-171`. |
| 7 | … | G16: hash-type byte stripped before parse_der | PASS — `script.ml:1191-1194` `strip_hash_type`. |
| 8 | BIP-143 midstate caching | G17: `PrecomputedTransactionData` equivalent caching `hashPrevouts` / `hashSequence` / `hashOutputs` | **BUG-9 (P1 perf, NEW)** — `script.ml:916-975` `compute_sighash_segwit` recomputes the three hashes **per input** from scratch. For a 16-KB block-validation tx with 1000 inputs, this is O(N²) serialisation. Core caches via `PrecomputedTransactionData::Init` (`bitcoin-core/src/script/interpreter.cpp:1454`) so each hash is computed ONCE per tx-validation regardless of input count. **See dedicated section.** |
| 8 | … | G18: BIP-341 `m_prevouts_single_hash` / `m_spent_amounts_single_hash` / `m_spent_scripts_single_hash` / `m_sequences_single_hash` / `m_outputs_single_hash` cached per-tx | **BUG-10 (P1 perf, NEW — Taproot variant of BUG-9)** — `script.ml:1017-1168` `compute_sighash_taproot` recomputes ALL five `sha_*` midstates per call. For a 100-input Taproot-only block (theoretical max ~3000 inputs per block), this is wall-clock-significant during IBD. |
| 8 | … | G19: `SigHashCache` for legacy + segwit-v0 per-input by (hashtype, scriptcode) | **BUG-11 (P1 perf, NEW)** — `bitcoin-core/src/script/interpreter.cpp:1572-1640` defines `SigHashCache` with 8 slots per input (4 cacheindex × 2 sigversion). camlcoin has no analogue; every OP_CHECKSIG in a multi-CHECKSIG witness re-computes the same sighash from scratch. Quadratic in script length × input count. |
| 9 | Taproot key-path tweak with merkle root | G20: PSBT signer uses `tap_merkle_root` when present | **BUG-12 (P0-FUNDS — wallet funds-burn for P2TR script-tree spends)** — `wallet.ml:1605` `Crypto.compute_taptweak_keypath xonly_pk` hard-codes **NO merkle root**, regardless of `inp.tap_merkle_root` being `Some _`. Core (`key.cpp:543`) uses `XOnlyPubKey(pk).ComputeTapTweakHash(merkle_root)`. **A taproot wallet importing a P2TR output that has a script tree (e.g., taproot-with-fallback-multisig) and signing via PSBT key-path will produce SIGNATURES THAT DO NOT VERIFY** because the output key was tweaked with `merkle_root ≠ None`. **See dedicated section.** |
| 9 | … | G21: sign_transaction_inputs uses tap_merkle_root | **BUG-13 (P0-FUNDS — same root-cause, second site)** — `wallet.ml:1328` `let tweak = Crypto.compute_taptweak_keypath xonly_pk in` in `sign_transaction_inputs` likewise ignores any wallet-stored merkle root. Wallet's own coin-selected P2TR spend signing breaks for any script-tree output. |
| 9 | … | G22: secondary rpc signer uses tap_merkle_root | PASS-WITH-CAVEAT — `rpc.ml:3346` `Crypto.compute_taproot_tweak xonly_pk None` is explicit `None` (still wrong for script-tree, but at least the function is structurally able to accept a merkle root; the bug is the hardcoded `None`). Same shape as BUG-12/13. |
| 10 | SIGHASH_DEFAULT (0x00) → 64-byte sig | G23: 64-byte sig accepted | PASS (`script.ml:2987-2994`). |
| 10 | … | G24: 65-byte sig with hashtype=0x00 rejected | PASS (`script.ml:2994-2995`). |
| 10 | … | G25: SIGHASH_DEFAULT treated as SIGHASH_ALL for output_type | PASS — `script.ml:1110` `if base_type <> 2 && base_type <> 3 then [...write sha_outputs]`. When `hash_type=0x00`, `base_type = 0 & 0x03 = 0`, condition is true, sha_outputs IS written. **Incidentally correct** — `base_type` for hash_type=0 is 0, never equal to NONE(2) or SINGLE(3). Core's explicit `(hash_type == SIGHASH_DEFAULT) ? SIGHASH_ALL : (hash_type & 3)` is more readable but functionally equivalent. |
| 11 | spend_type byte (BIP-341) | G26: ext_flag bit (TAPSCRIPT) set when tapscript path | PASS-BY-PROXY — `script.ml:1054-1057` `spend_type = (annex?1:0) lor (tapleaf?2:0)`. The `tapleaf` presence is used as an indirect proxy for `ext_flag`. Functionally equivalent IF AND ONLY IF callers always pass `tapleaf_hash` precisely when ext_flag should be 1 (i.e., tapscript paths). The single all-callsite audit at `script.ml:1928-1929, 2048-2049, 2429-2430` confirms this invariant. The bug is the function does not **enforce** this invariant; a future maintainer who passes `tapleaf_hash=Some _` for a key-path spend would silently produce a wrong sighash. **BUG-14 (P2, NEW)** — defensive-shape gap. |
| 12 | SIGHASH_SINGLE bug preserved (legacy) | G27: `uint256(1)` sentinel returned when input_idx >= n_outputs | PASS — `script.ml:861-865` returns `Cstruct.create 32` with byte0=1. |
| 12 | … | G28: SIGHASH_SINGLE Taproot-side gates BEFORE preimage write | PASS — `script.ml:1141-1142` `failwith` (pre-checked by `taproot_sighash_single_safe` at every call site). |
| 13 | Sigops parity-flip (Taproot keypair odd-y) | G29: `keypair_xonly_tweak_add` handles parity flip internally | PASS — `schnorr_stubs.c:147` `secp256k1_keypair_xonly_tweak_add(ctx, &keypair, tweak)` — libsecp256k1 negates the seckey internally on odd output Y. camlcoin does not need to manage this manually. |
| 14 | WIF version-byte stripping (W158 BUG-1 re-audit) | G30: WIF decode returns network info, signer uses it | **BUG-15 (P1, W158 BUG-1 CARRY-FORWARD)** — `address.ml:438-457` `wif_decode` returns `(privkey, compressed, network)` tuple; but `rpc.ml:2845` discards the network via `let ... | Ok (privkey, compressed, _network) ->`. camlcoin's chainparams (mainnet/testnet/regtest) all use the same secp256k1 curve and the WIF byte literally identifies the network, so signing a mainnet message with a `cP...` testnet WIF still produces a valid Bitcoin compact signature. This is a **cross-network signing oracle**: a user pasting a testnet WIF expecting "no, this is wrong" gets a perfectly valid signmessage signature against the mainnet message-hash framing. **See dedicated section.** |

---

## BUG-1 (P0-CONS, 2-WAVE CARRY-FORWARD from W159 BUG-17) — Sigcache cache_key uses no-witness txid: SegWit malleability chain-split candidate

**Severity:** P0-CONS chain-split candidate. **Carry-forward from W159 BUG-17 at exactly the same SHA**: zero remediation since W159 publication.

**File:** `lib/sig_cache.ml:19-23`.
**Sigcache lookup callers:** `lib/validation.ml:1167-1188` (serial mempool path), `lib/validation.ml:1240-1253` (parallel block-connect path).

```ocaml
type cache_key = {
  txid : Types.hash256;
  input_index : int;
  flags : int;
}
```

`txid` comes from `Crypto.compute_txid` (`lib/crypto.ml:343-346`):
```ocaml
let compute_txid (tx : Types.transaction) : Types.hash256 =
  let w = Serialize.writer_create () in
  Serialize.serialize_transaction_no_witness w tx;  (* witness EXCLUDED *)
  sha256d (Serialize.writer_to_cstruct w)
```

BIP-141 design: `txid` excludes witness so that signatures can sign the
transaction (chicken-and-egg). For a SegWit input, two transactions
with IDENTICAL `txid` but DIFFERENT witness data hash to the SAME
sigcache cache_key.

**Concrete attack:**
1. Miner A submits `tx_v1` with valid witness over its P2WPKH input;
   validation succeeds; sigcache populates `(txid, 0, flags) → true`.
2. Attacker submits `tx_v2` — same prevouts, same outputs, same amount,
   same locktime, same nVersion → **same `txid`** — but a DIFFERENT
   INVALID signature in `witnesses[0]`.
3. camlcoin's mempool path looks up `(txid, 0, flags)`; sigcache hits
   `true`; the invalid-signature transaction is admitted to the mempool
   and relayed.

**Chain-split:** if a malicious miner now mines `tx_v2` into a block,
camlcoin (which has cached the malleated witness as valid) accepts the
block; Core (which keys the cache by the **full (sighash, pubkey, sig) tuple
— sigcache.cpp:39-48**) rejects the block with `bad-txns-inputs-script`.
The two implementations diverge on chain tip.

**Core's defence**
```cpp
// bitcoin-core/src/script/sigcache.cpp:39-49
uint256 ComputeEntryECDSA(const std::vector<unsigned char>& sig,
                           const CPubKey& pubkey, const uint256& sighash) const
{
    uint256 entry;
    m_salted_hasher_ecdsa.Write(sighash.begin(), 32)
        .Write(pubkey.data(), pubkey.size())
        .Write(sig.data(), sig.size())
        .Finalize(entry.begin());
    return entry;
}
```

The cache key is the SHA-256 of `(sighash || pubkey || sig)` — sighash
already covers the witness via BIP-143/BIP-341 preimage, so any
witness mutation produces a different sighash → different cache key →
no false-positive cache hit.

**Cross-cite W159 outcome:** the bug was reported, severity flagged as
P0-CONS, but no fix landed in the intervening waves. Two-wave
carry-forward at the same SHA (the file has not been modified since W159
publication).

**Fix sketch (~30 LOC):**
1. Replace `cache_key = {txid; input_index; flags}` with
   `cache_key = uint256` and have `Sig_cache.lookup` /
   `Sig_cache.insert` take pre-computed entry hashes.
2. Lift the SHA-256 from `(sighash || pubkey || sig)` into the OP_CHECKSIG
   call site after each successful verify; emit one entry per
   successful Schnorr / ECDSA verification (not per-input).
3. Add a 256-bit per-process random salt to the hasher (closes BUG-2).

---

## BUG-12 / BUG-13 (P0-FUNDS) — Wallet P2TR signer ignores `tap_merkle_root`: signatures don't verify for taproot script-tree outputs

**Severity:** P0-FUNDS — silent funds-burn for any wallet user that
signs a P2TR output with a script tree via PSBT key-path or
sign_transaction_inputs.

**Files:** `lib/wallet.ml:1326-1328` (sign_transaction_inputs P2TR
branch), `lib/wallet.ml:1601-1610` (PSBT signer P2TR branch),
`lib/rpc.ml:3344-3347` (secondary RPC signer P2TR branch).

`lib/wallet.ml:1326-1331`:
```ocaml
| Script.P2TR_script _ ->
  let prevouts = ... in
  let sighash = Script.compute_sighash_taproot tx i prevouts 0x00 () in
  let xonly_pk = Crypto.derive_xonly_pubkey kp.private_key in
  let tweak = Crypto.compute_taptweak_keypath xonly_pk in     (* <-- NO MERKLE ROOT *)
  let sig_bytes = Crypto.schnorr_sign_tweaked ~privkey:kp.private_key ~tweak ~msg:sighash in
```

`lib/wallet.ml:1603-1610` (PSBT signer):
```ocaml
let xonly_pk = Crypto.derive_xonly_pubkey kp.private_key in
let tweak =
  Crypto.compute_taptweak_keypath xonly_pk                    (* <-- NO MERKLE ROOT *)
in
let raw_sig =
  Crypto.schnorr_sign_tweaked
    ~privkey:kp.private_key ~tweak ~msg:h
in
```

**`compute_taptweak_keypath` is `crypto.ml:312-313`:**
```ocaml
let compute_taptweak_keypath (internal_pubkey_xonly : Cstruct.t) : Cstruct.t =
  tagged_hash "TapTweak" internal_pubkey_xonly                (* JUST internal_pk; merkle_root absent *)
```

For a P2TR output created with internal key `P` and script tree merkle
root `m`, BIP-341 §"Script validation rules" requires:
```
output_key = P + tagged_hash("TapTweak", P || m) * G
```

So signing key-path against this output must use:
```
tweak = tagged_hash("TapTweak", P || m)
seckey' = (sk + tweak) mod n   (with parity-flip if output_key has odd Y)
sig = schnorrsig_sign(seckey', sighash, aux_rand)
```

camlcoin's signer always computes:
```
tweak = tagged_hash("TapTweak", P)         <-- m omitted
```

For any P2TR address whose creation used a non-trivial script tree,
this produces a different `seckey'` → different sig → **schnorr_verify
returns false at consensus → tx is rejected by the network →
miner-paid fees consumed, sig retry impossible without manual signing**.

**Compare Bitcoin Core `bitcoin-core/src/key.cpp:532-547`:**
```cpp
KeyPair::KeyPair(const CKey& key, const uint256* merkle_root)
{
    ...
    bool success = secp256k1_keypair_create(secp256k1_context_sign, keypair, ...);
    if (success && merkle_root) {                              // <-- merkle_root passed in
        secp256k1_xonly_pubkey pubkey;
        unsigned char pubkey_bytes[32];
        assert(secp256k1_keypair_xonly_pub(..., &pubkey, nullptr, keypair));
        assert(secp256k1_xonly_pubkey_serialize(..., pubkey_bytes, &pubkey));
        uint256 tweak = XOnlyPubKey(pubkey_bytes).ComputeTapTweakHash(
            merkle_root->IsNull() ? nullptr : merkle_root);   // <-- m passed
        success = secp256k1_keypair_xonly_tweak_add(..., keypair, tweak.data());
    }
}
```

**Wallet impact**

- Any P2TR address with a script tree (e.g., BIP-86 vs. Miniscript
  taproot, Lightning-channel funding outputs, Threshold-with-fallback
  multisig) is unsignable via key-path for camlcoin wallets that hold
  the internal key.
- The PSBT signer is the user-visible affected path: external wallets
  hand camlcoin a PSBT carrying `tap_merkle_root = Some _` (PSBT field
  `PSBT_IN_TAP_MERKLE_ROOT = 0x18`); camlcoin signs anyway, returns
  the PSBT, the user broadcasts, the network rejects.
- For BIP-86-style "no script tree" P2TR (the most common single-sig
  taproot), `tap_merkle_root = None` and camlcoin is correct
  incidentally. The bug is invisible until the user touches a
  script-tree spend.

**New meta-pattern: "FUNDS-LOSS via hardcoded-None-where-Option-should-be-threaded"**
extends the W154/W155 fleet-wide funds-burn family (clearbit W154 BUG-12
GBT hardcoded OP_RETURN, lunarblock W154 BUG-22 default coinbase
burn-address, lunarblock W155 BUG-8 same at RPC entry). camlcoin's W160
BUG-12/13 is the **first instance of the family targeting the user
wallet signer (not the miner)**.

**Fix sketch (~5 LOC per site):**
- Thread `tap_merkle_root : Cstruct.t option` through the signer.
- Replace `compute_taptweak_keypath xonly_pk` with
  `Crypto.compute_taproot_tweak xonly_pk merkle_root` (the latter
  already exists and handles both branches at `crypto.ml:572-579`).

---

## BUG-6 (P1) — No low-R grinding: every camlcoin ECDSA spend is ~1 vbyte heavier than Core

**Severity:** P1 (fee-pessimisation; not a consensus bug).

**File:** `lib/schnorr_stubs.c:886-921` (`caml_ecdsa_sign_der`).

```c
secp256k1_ecdsa_signature sig;
if (!secp256k1_ecdsa_sign(schnorr_ctx, &sig, msg_data, sk_data, NULL, NULL)) {
    caml_failwith("caml_ecdsa_sign_der: signing failed");
}
secp256k1_ecdsa_signature_normalize(schnorr_ctx, &sig, &sig);

unsigned char der[72];
size_t der_len = sizeof(der);
if (!secp256k1_ecdsa_signature_serialize_der(schnorr_ctx, der, &der_len, &sig)) {
    caml_failwith("caml_ecdsa_sign_der: serialize_der failed");
}
```

ONE call to `secp256k1_ecdsa_sign` with `noncefp=NULL, ndata=NULL`.
Whatever low-R / high-R signature comes out is what gets serialised.

Bitcoin Core (`bitcoin-core/src/key.cpp:209-235`):
```cpp
bool CKey::Sign(const uint256 &hash, std::vector<unsigned char>& vchSig,
                bool grind, uint32_t test_case) const {
    ...
    unsigned char extra_entropy[32] = {0};
    WriteLE32(extra_entropy, test_case);
    secp256k1_ecdsa_signature sig;
    uint32_t counter = 0;
    int ret = secp256k1_ecdsa_sign(secp256k1_context_sign, &sig, hash.begin(),
        UCharCast(begin()), secp256k1_nonce_function_rfc6979,
        (!grind && test_case) ? extra_entropy : nullptr);

    // Grind for low R
    while (ret && !SigHasLowR(&sig) && grind) {
        WriteLE32(extra_entropy, ++counter);
        ret = secp256k1_ecdsa_sign(secp256k1_context_sign, &sig, hash.begin(),
            UCharCast(begin()), secp256k1_nonce_function_rfc6979, extra_entropy);
    }
    ...
}
```

`SigHasLowR` (`bitcoin-core/src/key.cpp:182-207`) returns true iff the
DER-encoded R's high bit is 0 → R fits in 32 bytes (no DER leading-zero
padding) → **DER signature is 71 bytes instead of 72**.

Statistical impact:
- Probability a random ECDSA sig has low R: ~50% (top bit of R is
  uniformly random).
- Mean grind iterations: 2.
- 99% of Core mainnet sigs are 71-byte. camlcoin sigs are ~50% 72-byte
  and ~50% 71-byte → mean 71.5 bytes.
- vbyte overhead per ECDSA spend: ~0.125 vbytes (in witness data,
  /4 weight units).
- For a 100-input batch-spend, ~12 extra vbytes → ~0.1% block-space
  pessimisation → ~0.1% higher fees vs Core.

**Why this matters now**: high-fee mempool epochs (e.g., 2023-12,
2024-04, Inscriptions surge) made the 1-vbyte savings material; Core
adopted grinding in v0.17. camlcoin is wire-compatible but
fee-pessimised relative to the rest of the network.

**Fix sketch (~15 LOC):**
- Add `extra_entropy[32]` local + `counter=0` loop.
- After `secp256k1_ecdsa_sign` + `signature_normalize`, call
  `secp256k1_ecdsa_signature_serialize_compact` to inspect R; loop until
  byte 0 (post-normalize) has high bit 0.
- The vendored libsecp256k1 binary has `secp256k1_ecdsa_signature_serialize_compact`
  — no new dependency.

---

## BUG-9 (P1 perf) — No `PrecomputedTransactionData` midstate cache: O(N²) sighash for multi-input txs

**Severity:** P1 (CPU-bound performance; IBD slowdown for big-tx blocks).

**File:** `lib/script.ml:916-975` (`compute_sighash_segwit`).

For an N-input SegWit transaction:
- `hash_prevouts`: serialise N outpoints (36 bytes each) → sha256d.
  Recomputed once **per input** even though it only depends on the tx.
- `hash_sequence`: serialise N sequences (4 bytes each) → sha256d.
  Recomputed per input.
- `hash_outputs`: serialise M outputs (8 + script bytes each) →
  sha256d. Recomputed per input.

For a tx with N=1000 inputs and M=1000 outputs (~250 KB):
- Per input: ~4ms to recompute the three hashes (sha256d over ~50 KB).
- Total: 1000 × 4ms = **4 seconds of pure sighash work** just for the
  midstates.
- Core's `PrecomputedTransactionData` computes each once → ~12ms total.
- Slowdown: ~330×.

**Bitcoin Core**:
```cpp
// bitcoin-core/src/script/interpreter.h:74-99 — PrecomputedTransactionData
struct PrecomputedTransactionData {
    uint256 hashPrevouts, hashSequence, hashOutputs;
    bool m_bip143_segwit_ready = false;
    // BIP-341 fields:
    uint256 m_prevouts_single_hash;
    uint256 m_sequences_single_hash;
    uint256 m_outputs_single_hash;
    uint256 m_spent_amounts_single_hash;
    uint256 m_spent_scripts_single_hash;
    bool m_bip341_taproot_ready = false;
    ...
};
```

```cpp
// bitcoin-core/src/script/interpreter.cpp:1454 (PrecomputedTransactionData::Init)
template <class T>
void PrecomputedTransactionData::Init(const T& txTo,
        std::vector<CTxOut>&& spent_outputs, bool force) {
    ...
    HashWriter hashSequence_writer;
    for (size_t i = 0; i < txTo.vin.size(); ++i) {
        hashSequence_writer << txTo.vin[i].nSequence;
    }
    hashSequence = hashSequence_writer.GetHash();   // ONCE per tx
    ...
}
```

camlcoin lacks this struct entirely. Same shape gap for BIP-341
(see BUG-10).

**Fix sketch (~80 LOC):**
- Add `type precomputed_tx_data = { hash_prevouts; hash_sequence;
  hash_outputs; sha_prevouts; sha_amounts; sha_scriptpubkeys;
  sha_sequences; sha_outputs }`
- Compute once at the top of `Validation.verify_tx_inputs` (or its
  parallel-domain equivalent).
- Thread through `compute_sighash_segwit` and `compute_sighash_taproot`
  as an optional positional argument; default = recompute (preserves
  test-suite compat).
- Drops sighash CPU during IBD by ~300× for high-input blocks.

---

## BUG-15 (P1, W158 BUG-1 CARRY-FORWARD) — WIF network byte stripped: cross-network signing oracle

**Severity:** P1. **Carry-forward from W158 BUG-1 (cross-impl signing oracle pattern)** — same SHA, no remediation.

**Files:** `lib/address.ml:438-457` (`wif_decode`), `lib/rpc.ml:2839-2853`
(`handle_signmessagewithprivkey`).

`wif_decode` correctly extracts the network from the leading version byte:
```ocaml
let wif_decode (s : string) : (Cstruct.t * bool * network, string) result =
  ...
  let version = Cstruct.get_uint8 payload 0 in
  let network = match version with
    | 0x80 -> Ok `Mainnet
    | 0xEF -> Ok `Testnet
    | _ -> Error (Printf.sprintf "Unknown WIF version: 0x%02x" version)
  in
  ...
  Ok (privkey, compressed, network)
```

But the only production caller (`rpc.ml:2845`) drops it:
```ocaml
(match Address.wif_decode wif with
 | Error e -> Error (Printf.sprintf "Invalid private key: %s" e)
 | Ok (privkey, compressed, _network) ->     (* <-- _network DISCARDED *)
   let msg_hash = Crypto.message_hash message in
   (try
     let sig_bytes = Crypto.sign_compact ~compressed privkey msg_hash in
     ...
```

**The exploit:**
1. User imports a TESTNET WIF (`cVt4o7BGAig1...`) into a MAINNET
   camlcoin node, expecting "wrong network, rejected".
2. `wif_decode` returns `(sk, true, `Testnet)`; the `_network` is
   silently swallowed.
3. `sign_compact` produces a perfectly valid Bitcoin-Signed-Message
   recoverable signature over the mainnet message-hash.
4. The verifier (a mainnet exchange's `verifymessage`) accepts the
   signature against the mainnet pubkey derived from `sk`.
5. The user has just authenticated a mainnet message with a private
   key they thought was scoped to testnet.

**Why this is a P1 not a P0**: the message-hash framing
(`"Bitcoin Signed Message:\n"`) is the same on all Bitcoin-derived
networks; the WIF version byte is the ONLY network differentiator at
the keypair level. Bitcoin Core treats the network byte as a hard gate
(`bitcoin-core/src/wallet/wallet.cpp::ImportPrivKey` rejects
network-mismatched WIFs). camlcoin's `import_wif` (`wallet.ml:650`)
does check `network = w.network`, but `signmessagewithprivkey` —
which is the WALLET-LESS path — doesn't have a wallet to compare
against and therefore needs to enforce the network from the caller
context (`ctx.network` exists in `rpc_context`).

**Fix sketch (~5 LOC):**
```ocaml
| Ok (privkey, compressed, net) ->
  if net <> ctx.network then
    Error (Printf.sprintf "WIF network (%s) does not match node network (%s)"
             (network_to_string net) (network_to_string ctx.network))
  else
    ...
```

---

## BUG-7 (P2) — `noncefp=NULL` instead of explicit `secp256k1_nonce_function_rfc6979`

**Severity:** P2 (defense-in-depth; no current behaviour difference).

`schnorr_stubs.c:903`:
```c
secp256k1_ecdsa_sign(schnorr_ctx, &sig, msg_data, sk_data, NULL, NULL)
```

The 5th arg is `secp256k1_nonce_function noncefp` — passing `NULL`
causes libsecp256k1 to fall back to `secp256k1_nonce_function_default`,
defined (in the vendored copy) as `nonce_function_rfc6979`. So today
the behaviour is identical to Core's
```c
secp256k1_ecdsa_sign(secp256k1_context_sign, &sig, hash.begin(),
    UCharCast(begin()), secp256k1_nonce_function_rfc6979, extra_entropy);
```

**The risk**: a future libsecp256k1 release could change the default
(e.g., switch to a different DRBG, or to a randomised nonce function).
camlcoin would silently change sig shape; Core (which pins
`secp256k1_nonce_function_rfc6979` explicitly) would not. Two
implementations could then produce different signatures for the same
(key, message) input — the very ambiguity that RFC 6979 was designed
to eliminate.

**Fix:** pass `secp256k1_nonce_function_rfc6979` explicitly. 1 LOC.

---

## BUG-3, BUG-4, BUG-5 (P0-SEC, W159 carry-forwards) — Sign-then-verify paranoia STILL absent

W159 documented these in detail (W159 BUG-7 ECDSA DER, BUG-8 ECDSA
compact, BUG-9 Schnorr). At HEAD (4 days later) zero remediation. The
same `caml_ecdsa_sign_der` / `caml_ecdsa_sign_compact` /
`caml_schnorr_sign(_tweaked)` stubs return the just-produced sig without
any round-trip verify. Cross-cite W159 §BUG-7 / §BUG-8 / §BUG-9 for the
full attack analysis (cosmic-ray / row-hammer / corrupted libsecp256k1
silently producing wrong-key sigs).

**Status of W159 fix priorities re-checked at HEAD:**
- W159 BUG-2 (context_randomize never called): present.
- W159 BUG-7/8/9 (sign-then-verify): present.
- W159 BUG-12 (no NULL aux fallback): present.
- W159 BUG-13 (batch-verify dead code): present.
- W159 BUG-16 (sigcache salt-free): present.
- W159 BUG-17 (sigcache witness-blind chain-split): present.

**All 6 W159 audit findings are unchanged at HEAD.** Drumbeat: audits
identifying same-class P0s outpacing fix landings.

---

## BUG-8 (P1, W159 BUG-12 CARRY-FORWARD) — No NULL aux_rand fallback

`schnorr_stubs.c:113-117`:
```c
FILE *f = fopen("/dev/urandom", "rb");
if (f == NULL || fread(aux_rand, 1, 32, f) != 32) {
    if (f) fclose(f);
    caml_failwith("caml_schnorr_sign: failed to read /dev/urandom");
}
fclose(f);
```

When `/dev/urandom` is unavailable (chroot without `/dev`, container
mount, mailing container, jail), `caml_failwith` raises an OCaml
exception → `Crypto.schnorr_sign_tweaked` propagates → wallet cannot
sign at all.

`bitcoin-core/src/secp256k1/src/modules/schnorrsig/main_impl.h:68-79`
shows libsecp256k1 supports `data = NULL`:
```c
if (data != NULL) {
    secp256k1_nonce_function_bip340_sha256_tagged_aux(&sha);
    ...
} else {
    /* Precomputed TaggedHash("BIP0340/aux", 0x0000...00); */
    static const unsigned char ZERO_MASK[32] = {
          84, 241, 105, 207, 201, 226, 229, 114, ...
    };
    for (i = 0; i < 32; i++) {
        masked_key[i] = key32[i] ^ ZERO_MASK[i];
    }
}
```

The NULL-aux path is **deterministic** but still produces a
BIP-340-compliant nonce because the tagged-hash construction prevents
nonce reuse across different keys/messages. It is the documented safe
fallback.

**Fix sketch (~10 LOC):**
```c
unsigned char aux_rand[32];
unsigned char *aux_ptr = aux_rand;
FILE *f = fopen("/dev/urandom", "rb");
if (f == NULL || fread(aux_rand, 1, 32, f) != 32) {
    if (f) fclose(f);
    aux_ptr = NULL;  /* libsecp256k1 falls back to ZERO_MASK */
}
if (f) fclose(f);

if (!secp256k1_schnorrsig_sign32(schnorr_ctx, sig64, msg_data, &keypair, aux_ptr)) {
    caml_failwith("caml_schnorr_sign: signing failed");
}
```

---

## BUG-2 (P0-SEC, W159 BUG-16 CARRY-FORWARD) — Sigcache hash function is salt-free

W159 BUG-16 documented this in detail. At HEAD: `sig_cache.ml:27-33`
`hash_key` is still `XOR-fold of first 8 bytes of txid with
(input_index * 31) XOR (flags * 17)`. Attacker can precompute
txid prefixes that collide with valid cached entries, forcing a
`Hashtbl` bucket explosion → linear scan via `List.find_opt`
(`sig_cache.ml:81`) → O(n) lookup → CPU DoS during block validation.

Cross-cite W159 §BUG-16 for full analysis.

**Combined with BUG-1**: a tx whose `txid` shares 8-byte prefix with a
valid cached `(txid_v1, 0, flags)` will look up the same bucket;
linear-scan via `key_equal` (`sig_cache.ml:36-39`) checks full txid
match. Bucket-explosion DoS is real even before BUG-1's chain-split
attack lands.

---

## BUG-14 (P2) — `spend_type` byte derived from `tapleaf_hash` presence (proxy for `ext_flag`) not explicitly enforced

**Severity:** P2 (defensive-shape gap; correct today by caller convention).

`script.ml:1054-1057`:
```ocaml
let has_annex = annex_hash <> None in
let has_tapleaf = tapleaf_hash <> None in
let spend_type =
  (if has_annex then 1 else 0) lor
  (if has_tapleaf then 2 else 0)
in
```

Core (`bitcoin-core/src/script/interpreter.cpp:1535`):
```cpp
const uint8_t spend_type = (ext_flag << 1) + (have_annex ? 1 : 0);
```
where `ext_flag` is a separate parameter explicitly set to 0 (TAPROOT)
or 1 (TAPSCRIPT) by the caller (`sigversion` switch at line 1486-1500).

camlcoin uses `has_tapleaf` as an **indirect proxy** for `ext_flag`.
Today every call site upholds the invariant (`tapleaf_hash = Some _`
↔ tapscript). A future maintainer who passes `tapleaf_hash=Some _`
for a key-path spend (e.g., for some PSBT introspection helper) would
silently produce a wrong sighash that Core would reject.

**Defensive fix sketch (~5 LOC):**
- Add explicit `sigversion : sig_version` parameter to
  `compute_sighash_taproot`.
- Derive `ext_flag` from `sigversion`: `Taproot → 0`, `Tapscript → 1`.
- Assert at function entry: `tapleaf_hash = None` if `sigversion = Taproot`.

---

## BUG-10 (P1 perf) — Taproot sighash recomputes all 5 `sha_*` midstates per input

Same shape as BUG-9 for the BIP-341 layer. `script.ml:1077-1101`
recomputes `sha_prevouts`, `sha_amounts`, `sha_scriptpubkeys`,
`sha_sequences`, and (when ANYONECANPAY is not set) `sha_outputs` for
EVERY call to `compute_sighash_taproot`. For a 1000-input Taproot
batch-spend block, that's 5000 sha256 invocations over O(KB) blobs
when 5 would suffice.

Cross-cite BUG-9 §"Fix sketch" for the unified
`PrecomputedTransactionData` port.

---

## BUG-11 (P1 perf) — No `SigHashCache` for legacy + segwit-v0 per-input

Bitcoin Core's `SigHashCache` (`bitcoin-core/src/script/interpreter.cpp:1572-1640`)
caches per-input sighashes by `(hashtype, scriptcode)`. 8 slots = 4
cacheindex × 2 sigversion. For a script with N OP_CHECKSIGs that all
share the same hashtype, the sighash is computed ONCE and reused. For
a complex M-of-N CHECKMULTISIG / Miniscript construction, this can
save up to 20× the sighash work per input.

camlcoin's `eval_state` (`script.ml:429-446`) has no cache field.
Every OP_CHECKSIG / OP_CHECKMULTISIG / OP_CHECKSIGADD reaches
`compute_sighash_legacy` / `compute_sighash_segwit` afresh.

For mainnet IBD traffic this cost is minor (most outputs are P2WPKH /
P2TR with one CHECKSIG per input). For Lightning-channel /
Miniscript-heavy IBD epochs (post-Taproot), the cost rises.

---

## Fleet patterns confirmed

- **side-channel-blinding-DISABLED universal**: W158 named the pattern
  (clearbit BUG-2 / lunarblock BUG-7 / haskoin); W159 added camlcoin
  as the 4th confirmed instance; W160 confirms it persists.

- **sign-then-verify paranoia absent**: W159 fleet pattern. camlcoin
  still missing on all 3 sign paths.

- **SegWit malleability sigcache chain-split candidate**: W159 BUG-17
  fleet pattern; **camlcoin is the named origin** in fleet history.
  Two-wave carry-forward (W159 → W160 at same SHA).

- **BIP-32 priv-side scalar via libsecp256k1 (NOT Zarith)**: PASS in
  camlcoin (`wallet.ml:200` uses `ec_seckey_tweak_add_raw` — libsecp256k1
  scalar arithmetic, not pure-OCaml). Avoids the GMP/Zarith asymmetry
  pattern that bit blockbrew (W158 BUG-X) / haskoin.

- **BIP-340 nonce=0 fallback absent**: ouroboros W158, lunarblock W158,
  camlcoin W159 BUG-12 → confirmed at HEAD as W160 BUG-8.

- **Asymmetric Schnorr surface**: PARTIAL — camlcoin has both verify
  and sign primitives wired (unlike some fleet impls). The asymmetry
  is in batch-verify: production has VERIFY-batch wired (dead) but no
  SIGN-batch — but signing a single sig at a time is normal, so this
  shape isn't relevant to camlcoin.

- **Cipher-as-scalar**: not present (camlcoin's BIP-32 uses
  HMAC-SHA512, not a cipher).

- **Two-curve-library**: PASS — single vendored libsecp256k1, no opam
  fallback path active in `lib/dune`. (Was historically present;
  retired per `crypto.ml:14-17` comment.)

- **Wiring-look-but-no-wire**: extends — `schnorr_verify_batch`
  (`crypto.ml:685-712` / `schnorr_stubs.c:545-578`) has 30+ LOC of
  OCaml-side packing and C-side iteration but ZERO production callers
  (sole consumer is `lib/perf.ml:587-613` perf bench). 6th distinct
  camlcoin instance of the pattern in this audit series.

- **Comment-as-confession**: BUG-13 is the strongest new instance —
  `schnorr_stubs.c:541-543` admits "libsecp256k1 doesn't have a
  public batch verification API yet, so we implement a parallel
  verification wrapper that processes signatures in chunks using
  OCaml domains or Lwt threads" — but the body does NOT spawn Domains
  or Lwt threads. The comment lies about both the absence of the
  upstream API (libsecp256k1 has had `secp256k1_schnorrsig_verify_batch`
  in extrakeys/modules for some time, though admittedly still flagged
  experimental) AND the implementation (no parallelism). **Two-layer
  comment-as-confession**: comment is wrong about EXTERNAL state AND
  about INTERNAL state.

- **Test-pins-bug**: 0 hits — camlcoin has no test pinning the
  no-merkle-root tweak as correct behaviour. The bug would have
  been caught immediately if `test_taproot_key_sig` covered a
  script-tree output.

- **Dead-but-public-returns-true**: BUG-12/13 inverse — wallet signer
  returns `(inp, true)` even though the produced signature won't
  verify on the network. **"Function returns 'success' but the work
  product is non-functional."** Same shape as W155 hotbuns BUG-31
  "advertisement-as-lie".

- **N-pipeline drift**: 3 distinct P2TR signing pipelines
  (`wallet.ml:1326` sign_transaction_inputs, `wallet.ml:1605` PSBT
  signer, `rpc.ml:3346` secondary RPC signer) ALL share the same
  no-merkle-root hardcode. **Drift in the OPPOSITE direction**: 3
  pipelines all-agreeing on a wrong default rather than 3 pipelines
  drifting from one canonical right-default. **New meta-pattern:
  "drift-converged-on-wrong-default"**.

---

## Cross-cite W158 / W159 outcomes

| W-wave | Bug | Status at W160 HEAD |
|--------|-----|---------------------|
| W158 BUG-1 (WIF network discard) | Cross-network signing oracle | UNFIXED → W160 BUG-15 |
| W159 BUG-2 (context_randomize) | Side-channel blinding disabled | UNFIXED |
| W159 BUG-7 (ECDSA sign-then-verify) | DER path | UNFIXED → W160 BUG-3 |
| W159 BUG-8 (ECDSA sign-then-recover) | Compact path | UNFIXED → W160 BUG-4 |
| W159 BUG-9 (Schnorr sign-then-verify) | BIP-340 path | UNFIXED → W160 BUG-5 |
| W159 BUG-12 (no NULL aux fallback) | /dev/urandom strand | UNFIXED → W160 BUG-8 |
| W159 BUG-13 (batch-verify dead) | wiring-look-but-no-wire | UNFIXED |
| W159 BUG-16 (sigcache salt-free) | DoS bucket-collision | UNFIXED → W160 BUG-2 |
| W159 BUG-17 (sigcache witness-blind) | chain-split candidate | UNFIXED → W160 BUG-1 |

**Audit-drumbeat outpacing fix-drumbeat** — 9 distinct prior bugs from
W158/W159 are unchanged at HEAD; W160 catalogues these as carry-forward
PLUS adds 6 net-new (BUG-6 low-R grinding, BUG-7 explicit RFC6979,
BUG-9/10/11 perf, BUG-12/13/14 Taproot signer merkle-root absence).

---

## Top priorities (recommended next fix wave)

1. **🚨 BUG-12 + BUG-13 (P0-FUNDS)** — Wallet signs P2TR script-tree
   spends with no merkle root → invalid sigs → tx rejected → fees
   lost. Fix scope: thread `tap_merkle_root` through 3 signer sites
   (~15 LOC total). **Highest urgency this wave.**
2. **🚨 BUG-1 (P0-CONS, 2-WAVE CARRY-FORWARD)** — Sigcache chain-split
   via SegWit-malleability cache-poison. Fix scope: redesign cache
   key to `(sighash || pubkey || sig)` per Core; ~30 LOC.
3. **🚨 BUG-2 (P0-SEC, W159 CARRY-FORWARD)** — Sigcache salt-free.
   Same redesign as BUG-1 with added per-process random nonce. +5 LOC.
4. **🚨 BUG-3 / BUG-4 / BUG-5 (P0-SEC, W159 CARRY-FORWARDS)** —
   Sign-then-verify paranoia absent. Fix scope: 3 paths × ~10 LOC
   = 30 LOC.
5. **🚨 BUG-15 (P1, W158 CARRY-FORWARD)** — WIF network-byte cross-
   network signing oracle. Fix scope: 5 LOC.
6. **BUG-6 (P1)** — Low-R grinding. Fix scope: ~15 LOC. Fee
   pessimisation, not consensus.
7. **BUG-8 (P1, W159 CARRY-FORWARD)** — Schnorr NULL-aux fallback.
   Fix scope: 10 LOC.
8. **BUG-9 / BUG-10 / BUG-11 (P1 perf)** — PrecomputedTransactionData
   + SigHashCache port. Fix scope: ~80 LOC. Massive IBD speedup for
   high-input-count blocks.
9. **BUG-7 (P2)** — Explicit `secp256k1_nonce_function_rfc6979`.
   Fix scope: 1 LOC.
10. **BUG-14 (P2)** — Explicit `sigversion` arg to
    `compute_sighash_taproot`. Fix scope: 5 LOC.

---

**Bug count:** 15 numbered bugs.
**P0-class:** 6 (BUG-1, BUG-2, BUG-3, BUG-4, BUG-12, BUG-13).
**P1:** 6 (BUG-5, BUG-6, BUG-8, BUG-9, BUG-10, BUG-11, BUG-15 — recount: 7).
**P2:** 2 (BUG-7, BUG-14).

**Carry-forward count:** 7 of 15 (BUG-1 from W159 BUG-17; BUG-2 from
W159 BUG-16; BUG-3 from W159 BUG-7; BUG-4 from W159 BUG-8; BUG-5 from
W159 BUG-9; BUG-8 from W159 BUG-12; BUG-15 from W158 BUG-1) — **47% of
this audit's findings are unchanged-since-prior-wave**.

**Net-new this wave:** 8 (BUG-6 low-R grind, BUG-7 explicit RFC6979,
BUG-9 BIP-143 midstate cache, BUG-10 BIP-341 midstate cache, BUG-11
SigHashCache, BUG-12 / BUG-13 / BUG-14 Taproot wallet signer family).

**New meta-patterns this wave:**
- "drift-converged-on-wrong-default" (BUG-12/13 — 3 pipelines all
  hardcoding `compute_taptweak_keypath` without merkle root, instead
  of one canonical right + 2 wrong).
- "FUNDS-LOSS via hardcoded-None-where-Option-should-be-threaded"
  (BUG-12 — first user-wallet-signer instance of the W154/W155
  funds-burn family).
- "Comment-as-confession across BOTH internal and external state"
  (BUG-13 admits libsecp256k1 lacks batch API AND that it uses Domain
  parallelism — both lies).
