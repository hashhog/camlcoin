# W159 — libsecp256k1 FFI wrapping + batch verification (camlcoin)

**Wave:** W159 — `secp256k1_context_create` flags / lifecycle (process-singleton
vs per-thread; `SECP256K1_CONTEXT_NONE` post-v0.4.0 vs deprecated
`SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY`), `secp256k1_context_randomize`
side-channel-blinding seed, `secp256k1_selftest`, sign-then-verify paranoia,
`secp256k1_ec_seckey_verify` scalar-range gate, `secp256k1_schnorrsig_verify`
+ batch variant, ECDSA recoverable signatures, BIP-340 Schnorr aux-rand
sourcing, `XOnlyPubKey` Taproot tweak / parity, ECDH (ellswift /
BIP-324), CONST scriptcode + low-S normalize, memory hygiene
(`memory_cleanse` / `secure_allocator` / `LockedPool` / mlock), tagged-hash
("TapTweak", "TapLeaf", "TapBranch", BIP-340 "BIP0340/aux/nonce/challenge"),
constant-time scalar ops, OCaml-side `Gc.finalise` for context cleanup,
pure-OCaml fallback paths (zarith / mirage-crypto) vs C FFI.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/key.cpp:571-587` — `ECC_Start`: `secp256k1_context_create(SECP256K1_CONTEXT_NONE)`
  → `GetRandBytes(vseed)` → `secp256k1_context_randomize(ctx, vseed.data())`
  (assert(ret)). Pattern: create ONCE, randomize ONCE, destroy ONCE.
- `bitcoin-core/src/key.cpp:589-597` — `ECC_Stop`: `secp256k1_context_destroy`
  on shutdown. `ECC_Context` RAII wrapper at `key.cpp:599-607` and
  `bitcoind.cpp:200` (`node.ecc_context = std::make_unique<ECC_Context>();`).
- `bitcoin-core/src/key.cpp:209-235` — `CKey::Sign`: after `secp256k1_ecdsa_sign`
  + `serialize_der`, runs `secp256k1_ec_pubkey_create` + `secp256k1_ecdsa_verify`
  on the just-produced sig and `assert(ret)`. **Sign-then-verify paranoia.**
- `bitcoin-core/src/key.cpp:250-271` — `CKey::SignCompact`: after
  `secp256k1_ecdsa_sign_recoverable` + `serialize_compact`, runs
  `secp256k1_ec_pubkey_create` + `secp256k1_ecdsa_recover` +
  `secp256k1_ec_pubkey_cmp` and `assert(ret == 0)`. **Sign-then-recover paranoia.**
- `bitcoin-core/src/key.cpp:561` — `if (!ret) memory_cleanse(sig.data(), sig.size());`
  zeroes the failed-sign output buffer.
- `bitcoin-core/src/key.cpp:159` — `CKey::Check`: `secp256k1_ec_seckey_verify(...)`
  on every set-from-buffer (scalar in [1, n-1]).
- `bitcoin-core/src/key.h:24` — `typedef std::vector<unsigned char, secure_allocator<unsigned char>> CPrivKey;`
  — secure_allocator → LockedPool / mlock so private keys don't swap.
- `bitcoin-core/src/support/cleanse.cpp:14` — `memory_cleanse(void *ptr, size_t len)`
  — explicit_bzero wrapper for compile-barrier-resistant zeroing.
- `bitcoin-core/src/secp256k1/include/secp256k1.h` (context docs) — "Always set
  to SECP256K1_CONTEXT_NONE … All other (deprecated) flags will be treated as
  equivalent." "Highly recommended to call secp256k1_context_randomize on the
  context before calling those API functions" (side-channel mitigation).
  "A constructed context can safely be used from multiple threads simultaneously,
  but API calls that take a non-const pointer … need exclusive access" —
  context_randomize / destroy require exclusive lock.
- `bitcoin-core/src/secp256k1/src/secp256k1.c:86` — `secp256k1_selftest()`:
  endian-mismatch + library-compile-validity self-test (separate from context
  creation; called from `pubkey.cpp:29` once).
- `bitcoin-core/src/script/sigcache.cpp:20-37` — `SignatureCache::SignatureCache`:
  per-process random `nonce = GetRandHash()` mixed via SHA-256 padding bytes
  `'E'`/`'S'` into separate ECDSA / Schnorr salted-hashers. **Process-secret
  salt prevents cache-key collision attacks.**
- `bitcoin-core/src/script/sigcache.cpp:39-49` — cache entry =
  `m_salted_hasher_(ecdsa|schnorr).Write(sighash, 32).Write(pubkey).Write(sig).Finalize()`
  — full (sighash, pubkey, sig) tuple goes into the hash, NOT just (txid, vin_idx, flags).
- `bitcoin-core/src/script/sigcache.cpp:51-61` — `Get` uses `std::shared_lock`
  (multi-reader) and `Set` uses `std::unique_lock` (exclusive) on
  `cs_sigcache`. **R/W mutex on every cache touch.**
- BIP-340 — Schnorr `sign32(sk, msg, aux_rand)`: aux_rand MUST be 32 bytes
  of fresh entropy (RECOMMENDED), zeroes is a safe fallback for tests but
  reduces nonce-reuse resistance.

**Files audited**
- `lib/schnorr_stubs.c` (1068 lines) — vendored libsecp256k1 amalgamation
  + 30 OCaml/C FFI stubs (schnorr_verify, schnorr_sign, schnorr_sign_tweaked,
  derive_xonly_pubkey, xonly_pubkey_tweak_add(_with_parity)(_check),
  ecdsa_verify/_normalized/_lax, ec_pubkey_create, ec_pubkey_decompress,
  ec_seckey_tweak_add, ec_pubkey_tweak_add, ecdsa_sign_der,
  ecdsa_signature_is_low_s, ecdsa_sign_compact, ecdsa_recover_compact,
  schnorr_verify_batch, pubkey_parse_check, pubkey_serialize_compressed,
  ellswift_create, ellswift_xdh).
- `lib/crypto.ml` (744 lines) — OCaml-side `external` bindings + helpers
  (sha256/sha256d, hash160, tagged_hash, generate_private_key,
  derive_public_key, sign/verify/verify_lax, schnorr_verify(_batch),
  message_hash, compute_taproot_*).
- `lib/wallet.ml:64-200, 510-590, 2090-2400` — BIP-32 derive
  (`ec_seckey_tweak_add_raw` / `ec_pubkey_tweak_add_raw`), key generation
  (`Crypto.generate_private_key`), AES-256-CBC wallet encryption, key
  zeroing on lock.
- `lib/sig_cache.ml` (170 lines) — process-wide `Sig_cache` (cache_key =
  `{txid; input_index; flags}`, `hash_key` mixes first 8 bytes of txid,
  no per-process salt, no mutex).
- `lib/validation.ml:1148-1349` — parallel-script-verification path
  (`verify_scripts_parallel_domain` spawns OCaml 5 `Domain.spawn`
  workers, uses `sig_cache_mutex` for parallel cache access);
  serial-mempool path at line 1167-1188 calls `Sig_cache.lookup` /
  `Sig_cache.insert` directly WITHOUT the mutex.
- `lib/script.ml:1930, 1982, 2050, 2100, 2238, 2431, 3013` — script
  verification call sites (`Crypto.schnorr_verify`, `Crypto.verify_lax`).
- `lib/p2p.ml:2026-2055, 2229-2280` — BIP-324 cipher init using
  `ellswift_create_raw` / `ellswift_xdh_raw`.
- `lib/rpc.ml:2830-2935` — message sign/verify (signmessage,
  signmessagewithprivkey, verifymessage RPCs) using
  `Crypto.sign_compact` / `Crypto.recover_compact`.
- `lib/perf.ml:580-620` — `bench_schnorr_verify_batch` (ONLY production
  caller of `schnorr_verify_batch`; not used inside script eval).
- `lib/dune` — `(foreign_stubs (language c) (names schnorr_stubs …))`,
  `(c_library_flags (-lcrypto -lrocksdb …))`. No `(libraries secp256k1)`
  — the vendored libsecp256k1 is the only secp256k1 source linked.
- `test/test_crypto.ml:260-355` — alcotest cases incl. four
  `schnorr_verify_batch` tests (empty / single / multiple / one-invalid).
- `test/test_sig_cache.ml`, `test/test_validation.ml` — no Domain /
  concurrent-access tests (grep `Mutex|Domain|parallel|race` = 0 hits).

---

## Gate matrix (32 sub-gates / 11 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | secp256k1 context lifecycle | G1: process-singleton (one ctx for whole binary) | PASS (`schnorr_stubs.c:52` `static secp256k1_context *schnorr_ctx = NULL;` + `ensure_ctx()` at line 54) |
| 1 | … | G2: `SECP256K1_CONTEXT_NONE` (post-v0.4.0 only valid flag) | **BUG-1 (P2)** — `schnorr_stubs.c:56` uses `SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY`. Vendored libsecp256k1 treats these as equivalent to NONE so no functional effect, but Core docs say "Always set to SECP256K1_CONTEXT_NONE" → diverges from upstream pattern |
| 1 | … | G3: `secp256k1_context_randomize` called before any signing | **BUG-2 (P0-SEC)** — `ensure_ctx()` at `schnorr_stubs.c:54-58` ONLY calls `context_create`; NEVER calls `context_randomize`. **Side-channel blinding is DISABLED.** libsecp256k1 docs: "If the context is intended to be used for API functions that perform computations involving secret keys … it is highly recommended to call secp256k1_context_randomize." Core does this at `key.cpp:578-584` (random 32-byte seed via `GetRandBytes`). Cross-cite W158: **THE fleet-wide pattern** — clearbit lunarblock haskoin and now camlcoin all miss this |
| 1 | … | G4: `secp256k1_selftest()` called before first use of static ctx | **BUG-3 (P2)** — `schnorr_stubs.c` never calls `secp256k1_selftest`. Core calls it once at `pubkey.cpp:29`. Without selftest, an endian-mismatch / wrong-compile of libsecp256k1 would silently produce wrong signatures rather than abort at startup |
| 1 | … | G5: `secp256k1_context_destroy` on shutdown | **BUG-4 (P2)** — `schnorr_ctx` is never destroyed. Process-singleton implies leak-at-exit is harmless, but combined with OCaml `Gc.finalise` absence (BUG-15), the FFI module has no graceful cleanup hook |
| 1 | … | G6: thread-safe init (race on first `ensure_ctx`) | **BUG-5 (P1)** — `ensure_ctx()` at `schnorr_stubs.c:54-58` is a NULL-check-then-assign with no mutex / atomic / pthread_once. If two OCaml Domain workers (`verify_scripts_parallel_domain` at `validation.ml:1287`) make their FIRST call simultaneously, both see `schnorr_ctx == NULL`, both call `secp256k1_context_create`, the second `secp256k1_context_create` allocates a new ctx, the first store wins, the second ctx leaks. Worse: between create-and-assign one worker may see `schnorr_ctx` pointing at a half-initialised context. Core's `ECC_Start` is called once from the single-threaded init path (`bitcoind.cpp:200`) before any worker thread spawns; camlcoin lazy-inits from the verifier hot path |
| 2 | side-channel blinding mitigation | G7: rerandomize ctx periodically (e.g., after every block) | **BUG-6 (P2)** — no rerandomize call ANYWHERE. Core does not currently rerandomize after init either, but recommends a one-time call at init. Cross-cite BUG-2 |
| 3 | sign-then-verify paranoia | G8: post-sign verify in `caml_ecdsa_sign_der` | **BUG-7 (P0-SEC)** — `schnorr_stubs.c:886-921` calls `secp256k1_ecdsa_sign` + `signature_normalize` + `signature_serialize_der`, then returns the bigarray. **No `secp256k1_ec_pubkey_create` + `secp256k1_ecdsa_verify` round-trip.** Core asserts the sig verifies before returning (`key.cpp:228-233`) — this catches RAM-bit-flip / cosmic-ray corruption of the seckey buffer between read and use, and a faulty libsecp256k1 build. Without it, a corrupted seckey would silently emit a wrong-signing-key signature. Same shape as Core's "Additional verification step to prevent using a potentially corrupted signature" comment |
| 3 | … | G9: post-sign recover-and-compare in `caml_ecdsa_sign_compact` | **BUG-8 (P0-SEC)** — `schnorr_stubs.c:748-775` calls `secp256k1_ecdsa_sign_recoverable` + `serialize_compact`, returns bigarray. **No `secp256k1_ec_pubkey_create` + `secp256k1_ecdsa_recover` + `secp256k1_ec_pubkey_cmp` round-trip.** Core does this at `key.cpp:262-269` and asserts the recovered pubkey matches the expected. Combined with BUG-7, every signing path in the binary lacks the paranoia gate |
| 3 | … | G10: post-sign verify in `caml_schnorr_sign` / `_tweaked` | **BUG-9 (P1)** — `schnorr_stubs.c:97-129` and 131-170 call `secp256k1_schnorrsig_sign32` and return. Core's `KeyPair::SignSchnorr` does verify the produced sig before returning (via `BIP340::VerifyImpl` at `key.cpp:549-563` — sign-then-verify is integral). camlcoin returns raw output |
| 4 | seckey scalar-range validation | G11: `secp256k1_ec_seckey_verify` called on imported seckeys | **BUG-10 (P1)** — neither `caml_ec_pubkey_create` (`schnorr_stubs.c:852-881`) nor `caml_ecdsa_sign_der` (`886-921`) nor `caml_ecdsa_sign_compact` (`748-775`) nor `caml_schnorr_sign(_tweaked)` calls `secp256k1_ec_seckey_verify` upfront. They rely on the implicit "if pubkey_create / keypair_create / sign returns 0, the seckey was invalid" check, which works for the simple cases but: (a) the failure path is `caml_failwith` which raises an OCaml exception with a vague "invalid secret key" message instead of returning a structured error, (b) `Crypto.generate_private_key` at `crypto.ml:79-86` reads 32 bytes from `/dev/urandom` and returns them unvetted — the 1-in-2^128 chance of an invalid scalar (≥ n) is practical only as a theoretical concern but Core gates it (`key.cpp:159` `CKey::Check`) |
| 4 | … | G12: returned `kp.private_key` after `derive_child_key` is scalar-range-checked | **BUG-11 (P1)** — BIP-32 derive (`wallet.ml:158-200` calling `ec_seckey_tweak_add_raw`) relies on libsecp256k1's tweak-add returning 0 on overflow. The 0-return is mapped to `caml_failwith "tweak overflow / invalid result"` (`schnorr_stubs.c:968`) which is caught with `try ... with _ -> Error ...` upstream — but for hardened-derive (random-tweak-add) this is the right gate. The bug is the OCaml-side absence of an `is_valid_seckey` API; consumers cannot pre-validate an imported BIP-32 xprv child key without attempting a sign that may fail mid-tx-construction |
| 5 | Schnorr aux-rand sourcing (BIP-340) | G13: 32 bytes of fresh entropy per `schnorr_sign32` call | PARTIAL — `schnorr_stubs.c:110-117` (and `:151-158`) does `fopen("/dev/urandom", "rb"); fread(aux_rand, 1, 32, f);`. This works but: (a) opens + fread + close per call (`schnorr_stubs.c:112-117`) is ~25 µs of syscall overhead per signature; (b) if `/dev/urandom` ever fails — e.g., chroot without `/dev`, container without `urandom`, or early-boot before entropy seeded — the C stub `caml_failwith`s, which means `wallet.ml` cannot sign at all rather than degrading to `aux_rand = NULL` (which BIP-340 allows). Core uses `GetRandBytes` which has multi-source entropy + `RAND_bytes` fallback. See **BUG-12** |
| 5 | … | G14: NULL aux_rand fallback when entropy source unavailable | **BUG-12 (P1)** — `caml_schnorr_sign` (`schnorr_stubs.c:97-129`) raises Failure on `/dev/urandom` open failure rather than falling back to `aux_rand = NULL` (which BIP-340 explicitly allows: "aux_rand is a fresh 32-byte uniformly random value (optional)"). A test or sandboxed deployment without `/dev/urandom` (e.g., Docker `--no-new-privileges` with restrictive seccomp, mailing-it-out container) cannot sign at all |
| 6 | Schnorr batch verify (BIP-340) | G15: `schnorr_verify_batch` actually batches (multi-scalar mult) | **BUG-13 (P0-CDIV "wiring-look-but-no-wire")** — `caml_schnorr_verify_batch` (`schnorr_stubs.c:545-578`) is named "batch" but the inner loop calls `secp256k1_schnorrsig_verify` SEQUENTIALLY (line 562-575). The function header comment at line 541-543 admits this: "libsecp256k1 doesn't have a public batch verification API yet, so we implement a parallel verification wrapper that processes signatures in chunks using OCaml domains or Lwt threads" — but the body does NOT spawn Domains either. So the function is **strictly slower** than the single-call path because it pays the extra OCaml-side packing cost (`crypto.ml:686-712`) for zero parallelism gain. **comment-as-confession** + **wiring-look-but-no-wire** double instance |
| 6 | … | G16: production call sites use batch verify | **BUG-14 (P1)** — `grep schnorr_verify_batch lib/` shows the **only** non-test caller is `lib/perf.ml:587-613` (perf bench). `lib/script.ml` and `lib/validation.ml` use the per-input `Crypto.schnorr_verify` (`script.ml:1930, 2050, 2431, 3013`). For a block full of P2TR spends — Core's primary justification for batch — camlcoin pays neither the theoretical batch speedup nor the implementation. Cross-cite BUG-13: the function is dead production code (3rd-or-later "wiring-look-but-no-wire" instance in camlcoin this audit series) |
| 6 | … | G17: batch verify error-path identifies WHICH sig failed | **BUG-15 (P2)** — `caml_schnorr_verify_batch` returns a single bool. Core's planned API will return a vector of bools or the index of the first failure. With camlcoin's design, a failing block-validation cannot point at the specific input that failed to verify when batch was used (which it isn't — see BUG-14 — but if it ever is wired, the error path is opaque) |
| 7 | Sig_cache process-secret salt | G18: per-process random nonce mixed into cache key | **BUG-16 (P0-SEC)** — `lib/sig_cache.ml:25-33` `hash_key` uses ONLY first 8 bytes of `txid` XOR `(input_index * 31)` XOR `(flags * 17)`. **No per-process random salt.** Core's `SignatureCache::SignatureCache` (`sigcache.cpp:20-37`) generates a 256-bit random nonce at construction and mixes it into every cache key via a salted SHA-256 hasher. Without the salt, an attacker can pre-compute txid prefixes that collide with valid cached entries and trigger a `Hashtbl` bucket explosion, or in the worst case force a hash-collision attack on the bucket chain (the bucket is `(int, cache_entry list) Hashtbl.t` at `sig_cache.ml:52` — colliding entries are linear-scanned via `List.find_opt` at line 81) |
| 7 | … | G19: cache_key includes the witness / signature bytes, not just (txid, vin) | **BUG-17 (P0-CONS chain-split candidate)** — `sig_cache.ml:19-23` `cache_key = {txid; input_index; flags}`. **txid does NOT cover witness** (BIP-141 design: `compute_txid` at `crypto.ml:343-346` calls `serialize_transaction_no_witness`). For a SegWit input, two transactions with IDENTICAL txid but DIFFERENT witness data hash to the SAME cache_key. **Attack:** miner A submits `tx_v1` with valid witness, gets `(txid, 0, flags) → true` cached; attacker submits `tx_v2` with same txid (same prevouts + outputs + amount) but a DIFFERENT INVALID signature in the witness; mempool/validation cache lookup hits the cached `true` and admits the invalid-signature transaction. Core's `ComputeEntryECDSA` / `ComputeEntrySchnorr` (`sigcache.cpp:39-48`) hash the **full (sighash, pubkey, sig)** tuple — never the txid. **chain-split risk: a chain that accepts the malleated tx into a block diverges from Core which rejects it.** |
| 7 | … | G20: cache mutex on every read/write | **BUG-18 (P0-SEC race)** — serial mempool path at `validation.ml:1167-1188` calls `Sig_cache.lookup` (line 1169) and `Sig_cache.insert` (line 1188) **DIRECTLY**, bypassing the `sig_cache_mutex` defined at line 1211. The parallel path (`validation.ml:1287-1349`) DOES use `cache_lookup` / `cache_insert` (line 1213-1224) which take the mutex. The serial path is reached from mempool admission; the parallel path is reached from block-connect. If a block-connect runs concurrently with a mempool admit (which happens normally — Lwt + Domain) the two access patterns race on `Hashtbl.replace` (`sig_cache.ml:136`) and `Hashtbl.filter_map_inplace` (`evict_random` at line 92). OCaml 5 `Hashtbl` is NOT Domain-safe (the comment at `validation.ml:1206-1210` says so). **Data race on the validation cache.** |
| 8 | XOnlyPubKey / Taproot tweak | G21: `keypair_xonly_tweak_add` for BIP-341 key-path signing | PASS (`schnorr_stubs.c:147` calls `secp256k1_keypair_xonly_tweak_add`; `crypto.ml:298-310` exposes `schnorr_sign_tweaked`) |
| 8 | … | G22: `xonly_pubkey_tweak_add_check` for output-key verification | PASS (`schnorr_stubs.c:78-95`); script-side caller at `script.ml:3013` uses `compute_taproot_output_key` (`crypto.ml:598-606`) which DOES NOT call check (it calls `xonly_tweak_add_raw` which is non-verifying) — but the verifying-side `xonly_pubkey_tweak_add_check` IS wired |
| 8 | … | G23: tagged-hash uses the BIP-340 4-byte tags ("TapTweak", "TapLeaf", "TapBranch", "BIP0340/aux", "BIP0340/nonce", "BIP0340/challenge") | PASS (`crypto.ml:45-48` `tagged_hash` + `compute_taptweak_keypath` `compute_tapleaf_hash` `compute_tapbranch_hash`) |
| 9 | ECDSA recoverable / signmessage | G24: header byte ∈ [27, 34] validated | PASS (`schnorr_stubs.c:799-803`) |
| 9 | … | G25: `MESSAGE_MAGIC` byte-exact match Core | PASS (`crypto.ml:235`) |
| 9 | … | G26: BIP-322 implementation present | **BUG-19 (P1, fleet-wide pattern)** — grep `BIP-322|bip322` in `lib/` returns ZERO hits (only the W158 audit md mentions it). Fleet-wide: clearbit / lunarblock / camlcoin / others all miss BIP-322 (cross-cite W158 universal-absent). The `signmessage` legacy path remains the only signing primitive |
| 10 | Memory hygiene / LockedPool | G27: `memory_cleanse` (explicit_bzero) on failed-sign output | **BUG-20 (P1)** — `schnorr_stubs.c` lacks `memory_cleanse` / `explicit_bzero` ANYWHERE. When `secp256k1_ecdsa_sign` returns 0 (e.g., from `caml_ecdsa_sign_der` at line 903) the local `secp256k1_ecdsa_signature sig` on the C stack contains an unspecified-but-possibly-partial state; Core's `key.cpp:561` zeroes the failed-sign output buffer explicitly. With OCaml's GC potentially relocating the surrounding bigarray, stale signature material can persist on a free'd page |
| 10 | … | G28: private keys allocated from LockedPool / mlock'd region | **BUG-21 (P1)** — `Crypto.generate_private_key` at `crypto.ml:79-86` allocates an ordinary OCaml `Cstruct.t` for the seckey — managed by the OCaml GC and the OS page allocator, NEITHER `mlock`'d nor `madvise(MADV_DONTDUMP)`'d. Core's `CPrivKey = std::vector<unsigned char, secure_allocator<unsigned char>>` (`key.h:24`) uses a LockedPool that mlocks page-aligned blocks so private keys never reach swap. On a swap-enabled host (default on Debian/maxbox prior to ZRAM), camlcoin private keys CAN be swapped to disk. Combined with no `memory_cleanse` (BUG-20), an attacker who recovers swap can find both live and historical key material |
| 10 | … | G29: bigstring round-trip clears intermediate buffers | **BUG-22 (P1)** — `cstruct_to_bigstring` at `crypto.ml:62-68` allocates a fresh `Bigstring.create len` on EVERY FFI call (sign, verify, tweak_add, etc.). When the bigstring is GC'd, no zeroing occurs (OCaml does not zero on free). For every signature the binary produces over its lifetime, a copy of the seckey, msg, and DER-sig live on the heap until the next major GC, then become free pages that may end up in another allocation (or in swap) verbatim. Same shape as `wallet.ml:81-87` |
| 11 | OCaml-side context / FFI hygiene | G30: `Gc.finalise` on context handle | **BUG-23 (P2)** — `crypto.ml` exposes `external` bindings against `caml_*` stubs; the `schnorr_ctx` is held entirely on the C side. There is no OCaml-visible `context` value, no `Gc.finalise` hook to call `secp256k1_context_destroy` at module-unload (OCaml never unloads modules at runtime, so this is a graceful-shutdown gap rather than a leak). If the OCaml process exec's another binary post-fork, the context survives but cannot be reused; if the user reloads camlcoin in a long-running tool, two contexts can co-exist (BUG-5 race window) |
| 11 | … | G31: pure-OCaml fallback (zarith / mirage-crypto) absent | INTENTIONAL (`crypto.ml:14-17` comment: "All secp256k1 operations route through the vendored libsecp256k1 via thin C stubs"). Fallback would mean two implementations and a divergence vector — Core takes the same approach |
| 11 | … | G32: schnorr ctx is `const` (only `_destroy` / `_randomize` need exclusive) | **BUG-24 (P2)** — `schnorr_ctx` is declared `secp256k1_context *` (non-const, `schnorr_stubs.c:52`). After init it is only used in verify / sign / derive APIs which take `const secp256k1_context *`. Declaring it `const secp256k1_context *` post-init (or via a separate const view) would make the threading invariant ("read-only after init") explicit at the C type level and would catch a future call to `secp256k1_context_randomize` from a verify path |

---

## BUG-1 (P2) — Deprecated context flags `SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY`

**Severity:** P2 (cosmetic — flags are treated as equivalent to `_NONE`).

`schnorr_stubs.c:56` constructs the singleton context as:
```c
schnorr_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
```
The vendored libsecp256k1 header `secp256k1.h` documents:
> The only valid non-deprecated flag in recent library versions is
> `SECP256K1_CONTEXT_NONE`, which will create a context sufficient for all
> functionality offered by the library. All other (deprecated) flags will be
> treated as equivalent to the `SECP256K1_CONTEXT_NONE` flag.

Bitcoin Core (`key.cpp:575`) uses `secp256k1_context_create(SECP256K1_CONTEXT_NONE)`. No functional divergence; surfaces as a deprecation-warning at compile time on the next libsecp256k1 minor bump.

**File:** `lib/schnorr_stubs.c:56`.
**Core ref:** `bitcoin-core/src/key.cpp:575`.
**Impact:** Future-deprecation breakage; no current functional impact.

---

## BUG-2 (P0-SEC) — `secp256k1_context_randomize` NEVER called: side-channel blinding DISABLED

**Severity:** P0-SEC. **Fleet-wide W158 pattern** (clearbit BUG-2 / lunarblock BUG-7 / haskoin all share this shape; camlcoin is the 4th confirmed instance).

`schnorr_stubs.c:54-58`:
```c
static void ensure_ctx(void) {
    if (schnorr_ctx == NULL) {
        schnorr_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    }
}
```
There is NO `secp256k1_context_randomize(schnorr_ctx, seed32)` call AT ALL in the file (grep confirms 0 hits). The libsecp256k1 docs in the vendored header are unambiguous:
> If the context is intended to be used for API functions that perform
> computations involving secret keys, e.g., signing and public key generation,
> then it is **highly recommended** to call `secp256k1_context_randomize` on
> the context before calling those API functions. This will provide enhanced
> protection against side-channel leakage, see `secp256k1_context_randomize`
> for details.

Core does this at `key.cpp:578-584`:
```cpp
std::vector<unsigned char, secure_allocator<unsigned char>> vseed(32);
GetRandBytes(vseed);
bool ret = secp256k1_context_randomize(ctx, vseed.data());
assert(ret);
```

**What is being defended against:** the secp256k1 multi-scalar-multiplication
inner loops use the seckey as an index into precomputed tables; without
blinding, an attacker who can measure the CPU side-channel (cache-timing /
branch-prediction / EM emanation) can recover the seckey bit-by-bit. The
blinding seed is XOR'd into every scalar multiplication so the timing /
power signature is decorrelated from the seckey.

**Affected paths in camlcoin:**
- `caml_ecdsa_sign_der` (`schnorr_stubs.c:886-921`) — every wallet ECDSA sign.
- `caml_ecdsa_sign_compact` (`schnorr_stubs.c:748-775`) — every `signmessage`.
- `caml_schnorr_sign` / `_tweaked` (`97-170`) — every taproot key-path sign.
- `caml_ec_pubkey_create` (`852-881`) — every pubkey derivation
  (because pubkey-create also does a scalar multiplication using the seckey).
- `caml_ec_seckey_tweak_add` (`949-976`) — every BIP-32 derive.
- `caml_keypair_xonly_tweak_add` chain (via `caml_schnorr_sign_tweaked`).
- `caml_ellswift_create` (`652-680`) — every BIP-324 v2 handshake (uses
  the local seckey to derive the ellswift encoding).

**File:** `lib/schnorr_stubs.c:54-58`.
**Core ref:** `bitcoin-core/src/key.cpp:578-584` (`ECC_Start::context_randomize`).

**Impact:** every signing operation in camlcoin executes with side-channel
blinding DISABLED. An attacker with co-located code-execution (rowhammer,
cache-timing across a hyperthread, malicious browser tab on the same host)
or physical access (EM probe) can extract wallet private keys. The attack
surface widens dramatically for any hashhog impl deployed as a hot wallet
or signing oracle. This is the **NEW W158 pattern** "side-channel-blinding-
disabled" extended to camlcoin.

**Fix sketch:**
```c
static void ensure_ctx(void) {
    if (schnorr_ctx == NULL) {
        schnorr_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
        unsigned char seed[32];
        FILE *f = fopen("/dev/urandom", "rb");
        if (f && fread(seed, 1, 32, f) == 32) {
            secp256k1_context_randomize(schnorr_ctx, seed);
        }
        if (f) fclose(f);
        explicit_bzero(seed, 32);
    }
}
```

---

## BUG-3 (P2) — `secp256k1_selftest` never called

**Severity:** P2.

`schnorr_stubs.c` never calls `secp256k1_selftest()` (CHANGELOG.md
documents it as "to be used in conjunction with `secp256k1_context_static`"
and Core calls it at `pubkey.cpp:29`). The self-test catches:
- endian-mismatched compile (built for little-endian but running on big-endian),
- precomputed-table corruption (the `precomputed_ecmult*.c` files were not
  regenerated after a curve-equation tweak),
- linker reordering producing wrong basepoint constants.

camlcoin's `schnorr_stubs.c:34-35` includes the precomputed tables
inline (`#include "precomputed_ecmult.c"; #include
"precomputed_ecmult_gen.c";`) so a build-system error that strips them
would surface as a link failure rather than a runtime bad-sig — but a
miscompile of the precomputed code itself would silently produce wrong
signatures.

**File:** `lib/schnorr_stubs.c:54-58` (`ensure_ctx` body, no `secp256k1_selftest()`).
**Core ref:** `bitcoin-core/src/pubkey.cpp:29`.
**Impact:** an internally-corrupted libsecp256k1 build runs to completion
producing wrong signatures.

---

## BUG-4 (P2) — `secp256k1_context_destroy` never called

**Severity:** P2.

`schnorr_ctx` is allocated on first use and NEVER destroyed. Process-singleton
+ leak-at-exit is harmless, but combined with BUG-23 (no `Gc.finalise`)
this is a "no graceful shutdown" gap. A long-running tool that imports the
camlcoin library, finishes work, and then re-imports (rare but possible
in REPL / Lwt-based test runners) accumulates contexts.

**File:** `lib/schnorr_stubs.c:52` (no `at_exit` / destructor).
**Core ref:** `bitcoin-core/src/key.cpp:589-597` (`ECC_Stop`).
**Impact:** test-time / dev-tool memory leak; no production impact.

---

## BUG-5 (P1) — `ensure_ctx()` is not thread-safe; double-init race between Domain workers

**Severity:** P1 race.

```c
static secp256k1_context *schnorr_ctx = NULL;
static void ensure_ctx(void) {
    if (schnorr_ctx == NULL) {
        schnorr_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    }
}
```
This is a textbook "check-then-act" race. `validation.ml:1287-1349`
spawns `Domain.spawn` workers (`Domain.recommended_domain_count`, e.g., 16
on the maxbox 5900XT), each of which immediately calls
`Crypto.schnorr_verify` / `Crypto.verify_lax` on their assigned input.
On a cold-boot at block 0, the FIRST verification request from each
worker hits `ensure_ctx()` simultaneously:

1. Worker A: `schnorr_ctx == NULL` → enters branch.
2. Worker B: `schnorr_ctx == NULL` (A hasn't stored yet) → enters branch.
3. Worker A: `secp256k1_context_create(...)` → returns ptr_A.
4. Worker B: `secp256k1_context_create(...)` → returns ptr_B.
5. One store wins, the other ctx is orphaned (leak).
6. **Worse:** if Worker C does `schnorr_ctx` read between step 3 and step 4
   (e.g., a verify call that happened to arrive in between), it may see
   the OLD value (NULL) since there's no memory barrier — the OCaml runtime
   provides the GC barrier but C-level globals are not synchronised by it.

Core avoids the race by calling `ECC_Start` ONCE from
`bitcoind.cpp:200` on the main thread before any worker thread spawns
(`ECC_Context` constructor at `key.cpp:599-602`).

**File:** `lib/schnorr_stubs.c:52-58`.
**Core ref:** `bitcoin-core/src/key.cpp:599-607` (RAII wrapper init in
single-threaded path).
**Impact:** with N Domain workers and N first-verify requests simultaneous,
expected leak is N-1 contexts (~5 KB each at libsecp256k1's compile
options, so ~75 KB on a 16-core box). More importantly, the "second
ctx visible to one worker for one call" path can produce a verify against
a half-initialised context — libsecp256k1 doesn't guarantee what happens.

**Fix sketch:** wrap `ensure_ctx` in `pthread_once_t` (or initialise from
an OCaml main-thread call before any Domain spawn).

---

## BUG-6 (P2) — No periodic rerandomization of context

**Severity:** P2 (cosmetic — Core also doesn't rerandomize after init in the current code path).

Discussion: libsecp256k1's `secp256k1_context_randomize` accepts a new
seed at any time; some hardened deployments rerandomize on a schedule
(e.g., once per block, or once per N signatures) to defend against a
side-channel attacker who has accumulated partial seed information over
time. Core does the init-time randomize but not periodic. camlcoin does
neither (BUG-2).

**File:** `lib/schnorr_stubs.c:54-58`.
**Core ref:** none — pattern is forward-looking.
**Impact:** if BUG-2 is fixed, this becomes a hardening opportunity.

---

## BUG-7 (P0-SEC) — `caml_ecdsa_sign_der` lacks Core's sign-then-verify paranoia

**Severity:** P0-SEC.

`schnorr_stubs.c:886-921`:
```c
CAMLprim value caml_ecdsa_sign_der(value v_seckey, value v_msg) {
    ...
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
    // RETURN immediately — no verify-after-sign
    ...
}
```

Core's `CKey::Sign` at `bitcoin-core/src/key.cpp:228-234`:
```cpp
// Additional verification step to prevent using a potentially corrupted signature
secp256k1_pubkey pk;
ret = secp256k1_ec_pubkey_create(secp256k1_context_sign, &pk, UCharCast(begin()));
assert(ret);
ret = secp256k1_ecdsa_verify(secp256k1_context_static, &sig, hash.begin(), &pk);
assert(ret);
```

The comment on the Core path is explicit: "Additional verification step to
prevent using a potentially corrupted signature". The scenarios this
catches:
- RAM bit-flip / cosmic-ray hit on the seckey buffer between read and use.
- A faulty / hostile libsecp256k1 build that produces wrong sigs.
- A CPU instruction-cache flip producing wrong scalar mult output.

For a hot wallet that signs thousands of txs per day, a single corrupted
sig that goes out on the wire reveals the seckey via classic ECDSA-with-
biased-nonce extraction.

**File:** `lib/schnorr_stubs.c:886-921`.
**Core ref:** `bitcoin-core/src/key.cpp:228-234`.
**Impact:** corrupted signatures emitted from camlcoin without detection;
on a recurring corruption (e.g., bad RAM that flips one specific bit
periodically) the seckey is recoverable via Bleichenbacher-style attacks
on the biased nonce.

---

## BUG-8 (P0-SEC) — `caml_ecdsa_sign_compact` lacks sign-then-recover paranoia

**Severity:** P0-SEC. Same shape as BUG-7 but on the recoverable-ECDSA path.

`schnorr_stubs.c:748-775`:
```c
CAMLprim value caml_ecdsa_sign_compact(value v_seckey, value v_msg, value v_compressed) {
    ...
    secp256k1_ecdsa_recoverable_signature rsig;
    if (!secp256k1_ecdsa_sign_recoverable(schnorr_ctx, &rsig, msg_data, sk_data, NULL, NULL)) {
        caml_failwith("caml_ecdsa_sign_compact: signing failed");
    }
    unsigned char rs[64];
    int recid = -1;
    if (!secp256k1_ecdsa_recoverable_signature_serialize_compact(schnorr_ctx, rs, &recid, &rsig)) {
        caml_failwith("caml_ecdsa_sign_compact: serialize_compact failed");
    }
    // RETURN — no recover-and-compare
    ...
}
```

Core's `CKey::SignCompact` at `bitcoin-core/src/key.cpp:262-269`:
```cpp
// Additional verification step to prevent using a potentially corrupted signature
secp256k1_pubkey epk, rpk;
ret = secp256k1_ec_pubkey_create(secp256k1_context_sign, &epk, UCharCast(begin()));
assert(ret);
ret = secp256k1_ecdsa_recover(secp256k1_context_static, &rpk, &rsig, hash.begin());
assert(ret);
ret = secp256k1_ec_pubkey_cmp(secp256k1_context_static, &epk, &rpk);
assert(ret == 0);
```

The recoverable path needs the EXTRA `pubkey_cmp` because a corrupted
recid byte would route the recovered pubkey to the wrong attacker-chosen
pubkey rather than the operator's expected pubkey.

**File:** `lib/schnorr_stubs.c:748-775`.
**Core ref:** `bitcoin-core/src/key.cpp:262-269`.
**Impact:** signmessage / signmessagewithprivkey can emit a sig that
recovers to an unrelated pubkey under hardware corruption; the verifier
will return false but the seckey is leaked.

---

## BUG-9 (P1) — Schnorr sign paths lack sign-then-verify

**Severity:** P1. Same shape as BUG-7/8 on `caml_schnorr_sign` and
`caml_schnorr_sign_tweaked` (`schnorr_stubs.c:97-170`).

```c
if (!secp256k1_schnorrsig_sign32(schnorr_ctx, sig64, msg_data, &keypair, aux_rand)) {
    caml_failwith("caml_schnorr_sign: signing failed");
}
// RETURN — no verify-after-sign
```

Core's `KeyPair::SignSchnorr` (`key.cpp:549-563`) does NOT have an explicit
verify-after-sign on the Schnorr path either (the BIP-340 verify is at
the caller side via `BIP340::VerifyImpl`), so this is a lower-severity
parity gap than BUG-7. Still, fleet-wide adoption of a verify-after-sign
on all sign paths is the safer choice.

**File:** `lib/schnorr_stubs.c:97-170`.
**Core ref:** `bitcoin-core/src/key.cpp:549-563`.
**Impact:** corrupted Schnorr sigs emitted without detection.

---

## BUG-10 (P1) — `secp256k1_ec_seckey_verify` not called on imported seckeys

**Severity:** P1.

camlcoin's sign / pubkey-derive paths rely on the implicit
"keypair_create returns 0 on invalid seckey" check. This works but:

1. The failure path is `caml_failwith` (raises an OCaml exception with
   message "invalid secret key" — `schnorr_stubs.c:107, 143, 263, 866`).
   The OCaml caller catches the exception with `try ... with _ -> ...`
   and produces a generic Error. Core's `CKey::Check` (`key.cpp:159`)
   returns a bool, allowing the caller to handle invalid seckeys
   without exception-stack overhead.

2. `Crypto.generate_private_key` at `crypto.ml:79-86` reads 32 bytes
   from `/dev/urandom` and returns them unvetted:
   ```ocaml
   let generate_private_key () : private_key =
     let buf = Cstruct.create 32 in
     let ic = open_in_bin "/dev/urandom" in
     let bytes = really_input_string ic 32 in
     close_in ic;
     Cstruct.blit_from_string bytes 0 buf 0 32;
     buf
   ```
   The 1-in-2^128 chance of a scalar ≥ n is impractical to hit by
   accident BUT a maliciously-seeded `/dev/urandom` (compromised init)
   could feed a known-bad seed. Core's `CKey::Set` calls
   `secp256k1_ec_seckey_verify` and rejects.

3. WIF-decoded seckeys (`wallet.ml:649-672`) are passed straight to
   `derive_public_key` without an `is_valid_seckey` precheck. The user
   gets a Failure exception instead of a clean Error.

**File:** `lib/crypto.ml:79-86, 91-97`; `lib/schnorr_stubs.c:97-170, 852-881`.
**Core ref:** `bitcoin-core/src/key.cpp:159` (`CKey::Check`).
**Impact:** invalid-seckey rejection surfaces as raised exceptions
rather than structured errors, complicating wallet UX.

---

## BUG-11 (P1) — No public `is_valid_seckey` API for BIP-32 derive validation

**Severity:** P1. Companion to BUG-10.

After `derive_child_key` (`wallet.ml:158-200`), the caller has no way to
pre-validate the derived seckey is in [1, n-1] without attempting a sign.
For a wallet that derives 100 child keys at startup and discovers one is
invalid mid-sign, the partial state is awkward to roll back.

**File:** `lib/crypto.ml` (no `is_valid_seckey` exposed); `lib/wallet.ml:158-200`.
**Core ref:** `bitcoin-core/src/key.cpp:159`.
**Impact:** programmatic seckey validation requires try/catch.

---

## BUG-12 (P1) — Schnorr signing aborts when `/dev/urandom` unavailable instead of NULL aux_rand fallback

**Severity:** P1.

`schnorr_stubs.c:111-117`:
```c
unsigned char aux_rand[32];
FILE *f = fopen("/dev/urandom", "rb");
if (f == NULL || fread(aux_rand, 1, 32, f) != 32) {
    if (f) fclose(f);
    caml_failwith("caml_schnorr_sign: failed to read /dev/urandom");
}
fclose(f);
```

BIP-340 §3.3 says:
> The auxiliary random data is OPTIONAL. … If random data is not
> available, this argument may be omitted (set to NULL or zero).

`secp256k1_schnorrsig_sign32(ctx, sig64, msg, keypair, NULL)` is a legal
call. camlcoin instead aborts with `caml_failwith`, which propagates
to the OCaml caller as a Failure exception. A sandboxed deployment
without `/dev/urandom` (Docker with `--read-only` and no mounted `/dev`,
chroot for fuzz testing, container with seccomp filtering `getrandom`)
cannot sign at all.

Same shape on `caml_schnorr_sign_tweaked` (`schnorr_stubs.c:153-158`).

The ECDSA sign paths (`caml_ecdsa_sign_der`, `caml_ecdsa_sign_compact`)
correctly pass `NULL` for the nonce-function (using rfc6979 deterministic
default), so they don't have this problem.

**File:** `lib/schnorr_stubs.c:110-117, 151-158`.
**Core ref:** BIP-340 §3.3; `bitcoin-core/src/secp256k1/include/secp256k1_schnorrsig.h`.
**Impact:** Schnorr signing fails outright in sandboxed deployments where
ECDSA signing would succeed.

---

## BUG-13 (P0-CDIV "wiring-look-but-no-wire") — `caml_schnorr_verify_batch` is sequential, not batched

**Severity:** P0-CDIV. **"wiring-look-but-no-wire" + "comment-as-confession"
double instance.**

`schnorr_stubs.c:541-578`:
```c
/* Batch verification allows verifying multiple Schnorr signatures in parallel,
   which is faster than verifying them one by one due to amortized costs in the
   multi-scalar multiplication. This is particularly useful for validating
   taproot transactions in a block.

   Note: libsecp256k1 doesn't have a public batch verification API yet, so we
   implement a parallel verification wrapper that processes signatures in chunks
   using OCaml domains or Lwt threads. */

CAMLprim value caml_schnorr_verify_batch(value v_pubkeys, value v_msgs, value v_sigs, value v_count) {
    ...
    /* Verify each signature sequentially (libsecp256k1 lacks public batch API) */
    for (int i = 0; i < count; i++) {
        ...
        if (!secp256k1_schnorrsig_verify(schnorr_ctx, sig_data, msg_data, 32, &xonly_pk)) {
            CAMLreturn(Val_false);
        }
    }
    CAMLreturn(Val_true);
}
```

The doc-comment promises "parallel verification wrapper that processes
signatures in chunks using OCaml domains or Lwt threads"; the body does
NEITHER. It's a serial loop over `secp256k1_schnorrsig_verify`, identical
to calling `caml_schnorr_verify` in a loop on the OCaml side, but with
the EXTRA cost of packing+unpacking three contiguous bigarrays
(`crypto.ml:696-706` `Bigstring.create` x3 + `Bigstring.blit` x3 per item).

For a 1000-Taproot-input block, this is a 6x heap-alloc penalty for zero
parallelism gain.

**The "comment-as-confession" instance is explicit:** the comment in the
C body at line 561 admits "Verify each signature sequentially
(libsecp256k1 lacks public batch API)" — directly contradicting the
header comment at line 537-543 which sells the parallelism story.

**The "wiring-look-but-no-wire" instance is dual:** (a) the function
exists with a "batch" name and is exported; (b) it is reached only from
`lib/perf.ml:587-613` (perf bench) and `test/test_crypto.ml:264-304`
(unit tests). NO production caller uses it. (See BUG-14.)

**File:** `lib/schnorr_stubs.c:541-578`; `lib/crypto.ml:679-712`.
**Core ref:** libsecp256k1 has no `_batch` API yet (Core also does not
use batch on its hot path); when a public batch API ships, camlcoin's
wrapper will need a complete rewrite to be useful.

**Impact:** the "batch verify" code path is a marketing artifact, not a
performance feature. Performance benches at `perf.ml` will report it as
"approximately the same as serial verify" (which is the truth) but
labelled as a successful batch.

---

## BUG-14 (P1) — `schnorr_verify_batch` has zero production callers

**Severity:** P1. Companion to BUG-13.

Cross-grep `lib/`:
```
$ grep -rn "schnorr_verify_batch\|verify_batch" lib/ bin/ test/
lib/crypto.ml:685, 709
lib/schnorr_stubs.c:541-578
lib/perf.ml:587-613   <-- only OCaml caller (perf bench)
test/test_crypto.ml:264-355  <-- test only
```

`lib/script.ml` (the actual block-validation hot path) calls
`Crypto.schnorr_verify` PER-INPUT at lines 1930, 2050, 2431, 3013. A
block full of 200 P2TR spends pays 200 individual FFI hops + 200
serialise-x3 cstruct_to_bigstring copies (BUG-22) rather than a single
batched call.

When a real libsecp256k1 batch API ships (in-progress at upstream), the
already-broken-but-dead-code wrapper will need re-architecting — but
the cost-benefit is also zero today because the OCaml-side aggregation
infrastructure (collect-all-Schnorr-sigs-in-a-block-then-verify-once)
does not exist in `validation.ml` either.

**File:** all `lib/script.ml` Schnorr verify call sites; `lib/perf.ml` is
the lone caller.
**Core ref:** N/A — Core would similarly need an aggregation pass.
**Impact:** the batch-verify performance opportunity is left on the table
fleet-wide for impls that wired the FFI but not the aggregation; for
camlcoin specifically, the wired FFI is also broken (BUG-13).

---

## BUG-15 (P2) — Batch verify error path opaque

**Severity:** P2.

`caml_schnorr_verify_batch` returns `bool`. When a block fails Schnorr
verification, the caller cannot identify WHICH input(s) failed. For
mempool / RPC error messages this is OK; for block-rejection logging
it would matter — but BUG-14 means it doesn't get reached anyway.

**File:** `lib/schnorr_stubs.c:548-578` (signature is `value -> value -> value -> value -> value`, return is `Val_bool`).
**Core ref:** N/A.
**Impact:** opaque error path; cosmetic until BUG-13/14 fixed.

---

## BUG-16 (P0-SEC) — `Sig_cache.hash_key` lacks per-process random salt

**Severity:** P0-SEC.

`lib/sig_cache.ml:25-33`:
```ocaml
let hash_key (key : cache_key) : int =
  let h = ref 0 in
  for i = 0 to min 7 (Cstruct.length key.txid - 1) do
    h := (!h lsl 8) lxor (Cstruct.get_uint8 key.txid i)
  done;
  !h lxor (key.input_index * 31) lxor (key.flags * 17)
```

Just XOR-mixing of the first 8 bytes of `txid` with `input_index * 31`
and `flags * 17`. **The function is deterministic across all camlcoin
processes** (no per-process salt; no `Random.self_init`-driven seed
mixed in).

Core's `SignatureCache::SignatureCache` (`sigcache.cpp:20-32`):
```cpp
uint256 nonce = GetRandHash();
static constexpr unsigned char PADDING_ECDSA[32] = {'E'};
static constexpr unsigned char PADDING_SCHNORR[32] = {'S'};
m_salted_hasher_ecdsa.Write(nonce.begin(), 32);
m_salted_hasher_ecdsa.Write(PADDING_ECDSA, 32);
m_salted_hasher_schnorr.Write(nonce.begin(), 32);
m_salted_hasher_schnorr.Write(PADDING_SCHNORR, 32);
```

A 256-bit random nonce mixed via SHA-256 padding bytes into separate
hashers for ECDSA / Schnorr cache entries. **The salt prevents an
attacker from pre-computing cache-key collisions.**

**Attack on camlcoin's hash:** the attacker pre-computes 8-byte txid
prefix collisions by mining many txids and picking those that match.
With ~2^32 work the attacker can produce ~2^32 txids whose first 8
bytes XOR-collide on a chosen value (e.g., a value that bucket-maps to
zero). Submitting all these txids forces every cache lookup to walk a
linear list (the bucket is `(int, cache_entry list) Hashtbl.t` at
`sig_cache.ml:52`; `List.find_opt` at line 81 is O(n) per bucket). The
DoS amplification is the bucket size.

**File:** `lib/sig_cache.ml:25-33, 52, 81`.
**Core ref:** `bitcoin-core/src/script/sigcache.cpp:20-37`.
**Impact:** memmpool / block-connect cache lookups can be slowed to a
crawl by an attacker who mines collision-prefix txids and floods them
via P2P.

---

## BUG-17 (P0-CONS, chain-split candidate) — `cache_key` missing witness; cached `true` for SegWit (txid, vin, flags) is reused with DIFFERENT witness

**Severity:** P0-CONS — chain-split candidate via SegWit malleability.

`lib/sig_cache.ml:19-23`:
```ocaml
type cache_key = {
  txid : Types.hash256;
  input_index : int;
  flags : int;
}
```

`Crypto.compute_txid` at `lib/crypto.ml:343-346`:
```ocaml
let compute_txid (tx : Types.transaction) : Types.hash256 =
  let w = Serialize.writer_create () in
  Serialize.serialize_transaction_no_witness w tx;
  sha256d (Serialize.writer_to_cstruct w)
```

**txid does NOT cover witness data.** This is BIP-141's design intent
(SegWit fixes second-party malleability). The consequence for camlcoin's
cache is:

1. `tx_v1` is submitted with a valid Schnorr/ECDSA witness signature.
2. `Sig_cache.lookup` misses → verification runs → SUCCESS → cache stores
   `{txid=H1; input_index=0; flags=F} → true`.
3. Attacker constructs `tx_v2` with the SAME `version, locktime,
   inputs (prevouts+nSequence+scriptSig), outputs` (so same txid H1)
   but a DIFFERENT witness (different sig).
4. `Sig_cache.lookup({H1; 0; F})` HITS → returns true → witness is
   never verified.
5. `tx_v2`'s invalid witness signature is accepted.

Core's `ComputeEntryECDSA` / `ComputeEntrySchnorr` (`sigcache.cpp:39-48`)
hash the **full (sighash, pubkey, sig)** tuple. The sighash includes
the witness-relevant context; the pubkey and sig are part of the
cached identity.

**Chain-split scenario:** a miner running camlcoin includes `tx_v2`
in a block. Core nodes reject the block (invalid signature on input 0).
camlcoin nodes accept it. The two chains fork.

**Note on `script_sig` being part of txid:** for legacy (non-SegWit)
inputs the signature DOES live in `script_sig` which IS part of the
serialised tx and thus the txid — so the legacy path is incidentally
safe. The bug is specifically for SegWit v0 / Taproot witnesses.

**File:** `lib/sig_cache.ml:19-23`; `lib/crypto.ml:343-346`;
caller pattern at `lib/validation.ml:1161-1188` and `1239`.

**Core ref:** `bitcoin-core/src/script/sigcache.cpp:39-49`.

**Impact:** SegWit signature-replacement attack on the sigcache;
chain-split when camlcoin nodes process the malleated tx and Core
rejects it. **This is a CONSENSUS-DIVERGING bug.** It would require a
crafted block (the attacker needs to be a miner OR a block-relayer
who can mutate witness data en route), but the chain-split outcome is
immediate.

**Fix sketch:** change `cache_key` to use `(wtxid, input_index, flags)`
where `wtxid` DOES cover witness data; OR hash the actual sighash +
pubkey + sig tuple per Core.

---

## BUG-18 (P0-SEC race) — Serial mempool path uses raw `Sig_cache.lookup`/`insert` without `sig_cache_mutex`

**Severity:** P0-SEC race.

`lib/validation.ml:1167-1188` (serial mempool path):
```ocaml
let cache = Sig_cache.get_global () in
match Sig_cache.lookup cache cache_key with     (* <-- NO MUTEX *)
| Some true -> ()
| _ ->
  ...
  Sig_cache.insert cache cache_key true          (* <-- NO MUTEX *)
```

`lib/validation.ml:1211-1224` (parallel path's helpers):
```ocaml
let sig_cache_mutex : Mutex.t = Mutex.create ()
let cache_lookup ...
  Mutex.lock sig_cache_mutex;
  let r = Sig_cache.lookup cache key in
  Mutex.unlock sig_cache_mutex;
  r
let cache_insert ...
  Mutex.lock sig_cache_mutex;
  Sig_cache.insert cache key v;
  Mutex.unlock sig_cache_mutex
```

The header comment at `validation.ml:1206-1210` is explicit:
> OCaml 5 Hashtbl is NOT Domain-safe; we serialise access around a single
> Mutex so that cache lookups from worker domains do not race with inserts
> from the main domain.

But the serial path at line 1167-1188 BYPASSES the mutex. This is fine
when only the serial path runs (mempool admission is single-threaded
within itself), but the parallel block-connect runs CONCURRENTLY with
mempool admission in normal operation (Lwt for incoming RPC + Domain for
block validation). The two access patterns race on `Hashtbl.replace`
(`sig_cache.ml:136`) and `Hashtbl.filter_map_inplace` (`evict_random` at
line 92).

**File:** `lib/validation.ml:1167-1188` (serial path); `1211-1224`
(parallel helpers); `lib/sig_cache.ml:76-146` (no internal locking).
**Core ref:** `bitcoin-core/src/script/sigcache.cpp:51-61` (`shared_mutex`
on every Get/Set).

**Impact:** OCaml `Hashtbl` is documented as NOT Domain-safe. A concurrent
`Hashtbl.replace` + `Hashtbl.filter_map_inplace` can produce: (a) a
silently lost insert, (b) a segfault on the underlying bucket array
realloc, (c) a stale entry resurrected after eviction. The most likely
failure mode is process crash under load; the worst case is a stale
cache hit that bypasses signature verification on a real block.

**Fix sketch:** route ALL `Sig_cache.lookup` / `Sig_cache.insert` calls
through the mutex helpers; OR push the mutex INTO `lib/sig_cache.ml`
itself so the API is automatically safe.

---

## BUG-19 (P1, fleet-wide) — BIP-322 message signing entirely absent

**Severity:** P1. Cross-cite W158 BUG-class "BIP-322 universal absent" —
camlcoin / clearbit / lunarblock / haskoin / etc. all missing.

`grep -rin 'BIP-322\|bip322' lib/ bin/` returns ZERO production hits
(only the W158 audit md mentions it). The current message-signing path
in `lib/rpc.ml:2830-2935` is the LEGACY P2PKH-only Bitcoin Core
`signmessage` / `signmessagewithprivkey` / `verifymessage`. Modern
wallets (Sparrow, BlueWallet, etc.) sign with BIP-322 over P2WPKH /
P2TR addresses; camlcoin cannot verify those.

**File:** `lib/rpc.ml:2830-2935`; no BIP-322 module.
**Core ref:** Core also has not yet shipped BIP-322; fleet-wide deferral.
**Impact:** modern wallet interop gap; cross-impl wave-58 pattern.

---

## BUG-20 (P1) — No `memory_cleanse` / `explicit_bzero` ANYWHERE in stubs

**Severity:** P1.

`grep memset|explicit_bzero|memory_cleanse lib/schnorr_stubs.c`:
```
schnorr_stubs.c:493 memset(tmpsig, 0, 64);     <-- lax-der parser fallback, NOT key material
schnorr_stubs.c:127, 168, 472, 484 memcpy(...)  <-- copies, no zeroing
```

The only zeroing call is the lax-DER parser's fallback (overwrites the
working buffer with zeroes on parse failure). No call site zeroes:
- The local `aux_rand[32]` on the C stack after `secp256k1_schnorrsig_sign32`
  (lines 119, 160).
- The local `der[72]` buffer in `caml_ecdsa_sign_der` (line 910) after
  the bigarray is allocated and the contents copied (line 919). The
  buffer goes out of scope, but C stack pages can be re-used un-zeroed.
- The local `rs[64]` in `caml_ecdsa_sign_compact` (line 762) holding
  the compact ECDSA r||s (the SIG component, paired with `sk_data` it
  reveals the seckey via Bleichenbacher).
- The local `pub[65]` in `caml_ecdsa_recover_compact` (line 822) — public
  data so less critical.
- `seed[32]` if BUG-2 is fixed via the fix sketch I provided — that
  fix sketch DOES include `explicit_bzero(seed, 32);`.

Core's `key.cpp:561` zeroes the failed-sign output explicitly:
`if (!ret) memory_cleanse(sig.data(), sig.size());`.

**File:** `lib/schnorr_stubs.c:97-170, 748-775, 886-921` (all sign paths).
**Core ref:** `bitcoin-core/src/key.cpp:561`;
`bitcoin-core/src/support/cleanse.cpp:14`.

**Impact:** C-stack pages containing recent signing material can be
recycled by a later allocation (e.g., the OCaml runtime's heap-extension
syscall). On a core-dump or rowhammer-style read, this material is
exposed.

---

## BUG-21 (P1) — Private keys not allocated from LockedPool / mlock'd region

**Severity:** P1.

`crypto.ml:79-86`:
```ocaml
let generate_private_key () : private_key =
  let buf = Cstruct.create 32 in
  let ic = open_in_bin "/dev/urandom" in
  let bytes = really_input_string ic 32 in
  close_in ic;
  Cstruct.blit_from_string bytes 0 buf 0 32;
  buf
```

`Cstruct.create 32` is an ordinary OCaml-heap allocation managed by the
GC. The page CAN be swapped to disk by the OS. Core's `CPrivKey`
(`key.h:24`):
```cpp
typedef std::vector<unsigned char, secure_allocator<unsigned char>> CPrivKey;
```
uses `secure_allocator` which routes through `LockedPool`
(`support/lockedpool.cpp`), which `mlock`s the page so it never swaps
AND `madvise(MADV_DONTDUMP)`s it so it doesn't appear in core dumps.

camlcoin's wallet on a default Debian / maxbox install (which has swap
enabled, see ~/.config/swap configuration) CAN write private keys to
swap under memory pressure. Once on disk, even after the seckey-buffer
is zeroed in memory (which camlcoin does on lock — `wallet.ml:2290-2295,
2356-2363`), the swap copy remains until that disk block is overwritten
by another swap-out.

**File:** `lib/crypto.ml:79-86`; `lib/wallet.ml:2244-2256` (decrypted
seckey is `Cstruct.blit`'d into a key_pair record, also ordinary heap).
**Core ref:** `bitcoin-core/src/key.h:24`;
`bitcoin-core/src/support/lockedpool.cpp`.

**Impact:** wallet private keys can be exfiltrated from swap on a hot
wallet host. The "wallet encryption" feature gives a false sense of
security: encryption protects on-disk wallet.dat, but the in-memory
plaintext seckey (during signed period) is unmlocked.

---

## BUG-22 (P1) — Bigstring round-trip copies leave seckey/sig material on the heap

**Severity:** P1.

`crypto.ml:62-77`:
```ocaml
let cstruct_to_bigstring cs =
  let len = Cstruct.length cs in
  let bs = Bigstring.create len in
  for i = 0 to len - 1 do
    Bigstring.set bs i (Char.chr (Cstruct.get_uint8 cs i))
  done;
  bs

let bigstring_to_cstruct bs =
  let len = Bigstring.length bs in
  let cs = Cstruct.create len in
  for i = 0 to len - 1 do
    Cstruct.set_uint8 cs i (Char.code (Bigstring.get bs i))
  done;
  cs
```

EVERY FFI call (sign, verify, tweak_add, ...) goes through
`cstruct_to_bigstring` on the way in and `bigstring_to_cstruct` on the
way out. EACH call allocates a fresh bigstring. OCaml does NOT zero
allocations on free. When the GC reclaims a bigstring containing seckey
material, the bytes persist in the underlying heap region until the
next allocation overwrites them.

`derive_public_key`'s round-trip alone (`crypto.ml:94-97`) makes two
copies of the seckey. `sign` (line 105-109) makes one copy. `verify`
(line 174-180) makes copies of pubkey + msg + sig.

**File:** `lib/crypto.ml:62-77, 94-97, 105-109, 174-180`; same pattern
duplicated at `lib/wallet.ml:81-95`.
**Core ref:** Core uses contiguous `std::vector<unsigned char,
secure_allocator>` for private material and passes raw `.data()`
pointers to libsecp256k1 — no intermediate copies.

**Impact:** every wallet operation leaves a stale copy of private
material on the OCaml heap. Combined with BUG-21 (un-mlocked heap),
this is the practical leak path.

**Fix sketch:** pass raw bytes through `Bytes.t` directly (mirage-crypto
already supports this) and use `Bytes.unsafe_blit` + explicit zero.

---

## BUG-23 (P2) — No `Gc.finalise` on the secp256k1 context handle

**Severity:** P2.

The `schnorr_ctx` lives entirely C-side; there is no OCaml-visible
"context" value, so `Gc.finalise` has nothing to hook onto. This means:

1. No way to register an at-exit destroy (BUG-4 cross-cite).
2. If a long-running OCaml process imports the camlcoin library, runs
   awhile, and detaches (e.g., a fuzz-tester that forks new test
   harnesses per case), each child inherits the C-side context but
   cannot share OCaml-side state — leading to N orphaned contexts in
   the parent's memory map.
3. The hashhog test harness (`test_*.ml` in `test/`) imports camlcoin
   in each Alcotest run; in CI this is process-isolated so harmless,
   but in `dune runtest` with `-j 16` parallel test processes there
   are 16 independent contexts (which is fine functionally, just memory
   overhead).

**File:** `lib/crypto.ml` (no `Gc.finalise` registration);
`lib/schnorr_stubs.c:52` (no OCaml-side wrapper value).
**Core ref:** Core's `ECC_Context` RAII wrapper (`key.cpp:599-607`)
provides the same lifecycle.
**Impact:** lifecycle hook absent; minor.

---

## BUG-24 (P2) — `schnorr_ctx` should be `const secp256k1_context *` post-init

**Severity:** P2.

`schnorr_stubs.c:52`:
```c
static secp256k1_context *schnorr_ctx = NULL;
```

After `secp256k1_context_create`, every subsequent use is a verify /
sign / derive call that takes `const secp256k1_context *`. Declaring the
post-init pointer `const` would enforce at the C type level that no
verify / sign path accidentally calls `secp256k1_context_randomize` or
`secp256k1_context_destroy` (both of which would require dropping
const). libsecp256k1's docs explicitly call this out:
> A constructed context can safely be used from multiple threads
> simultaneously, but API calls that take a non-const pointer to a
> context need exclusive access to it.

By keeping `schnorr_ctx` non-const, camlcoin loses the type-level
enforcement.

**File:** `lib/schnorr_stubs.c:52`.
**Core ref:** libsecp256k1 `secp256k1.h` thread-safety comment.
**Impact:** future-maintenance: a developer adding `context_randomize`
from a verify path would not be caught by the compiler.

---

## Cross-cite: W158 patterns extended

- **side-channel-blinding-disabled (W158 NEW)** — BUG-2. camlcoin
  becomes the 4th confirmed fleet instance (after clearbit BUG-2,
  lunarblock BUG-7, haskoin in W158).
- **BIP-322 universal absent (W158)** — BUG-19. Camlcoin matches.
- **encrypted-wallet-cipher-as-scalar (W158 NEW)** — NOT present in
  camlcoin. The signmessage handler at `rpc.ml:2864-2905` looks up the
  key via `Wallet.find_by_address`; on an encrypted+LOCKED wallet, the
  in-memory `kp.private_key` is 32 ZERO BYTES (zeroed at
  `wallet.ml:2290-2295` on encrypt and `2356-2363` on lock), so
  `secp256k1_ecdsa_sign_recoverable` returns 0 (32-zero is not a valid
  scalar), and `caml_ecdsa_sign_compact` raises Failure. The handler at
  `rpc.ml:2898-2903` catches the exception and returns "Sign failed"
  — degraded UX, but NOT a key-leak. This is functionally safe but
  still a UX gap: Core returns `RPC_WALLET_UNLOCK_NEEDED` (-13) cleanly,
  camlcoin returns a generic "Sign failed".
- **test-pins-bug (W158 NEW)** — `test/test_crypto.ml:288-304`
  (`test_schnorr_verify_batch_one_invalid`) deliberately tests the
  CURRENT (broken — see BUG-13/14) sequential implementation as
  acceptable behaviour. The test does NOT verify that the batch is
  faster than serial; it does NOT verify that one invalid sig DOESN'T
  short-circuit (returning false on the first failure is correct, but
  the test would PASS even if the implementation were a no-op
  `Val_false` for any input). Combined with the docstring at
  `crypto.ml:682-684` ("Batch-verify multiple Schnorr signatures") this
  is a **test-pinning of the broken state**.

---

## Fleet-pattern recurrences in this audit

| Pattern | Instances this wave |
|---------|---------------------|
| side-channel-blinding-disabled (W158 NEW) | BUG-2 (4th fleet instance) |
| wiring-look-but-no-wire | BUG-13 (batch-verify dead+wrong), BUG-14 (no production callers) |
| comment-as-confession | BUG-13 (header says "parallel … using OCaml domains or Lwt threads", body says "Verify each signature sequentially") — 1 new camlcoin-side instance |
| BIP-322 universal absent (W158) | BUG-19 (fleet-wide) |
| two-pipeline guard at consensus boundary | BUG-18 (serial-mempool / parallel-block-connect drift on `sig_cache_mutex` usage) |
| chain-split candidate via SegWit malleability | BUG-17 (sigcache key omits witness) |
| missing process-secret salt on caching primitive | BUG-16 (Hashtbl bucket DoS via crafted prefix collisions) |
| no `memory_cleanse` / `LockedPool` | BUG-20, BUG-21, BUG-22 (3 distinct hygiene failures) |
| no sign-then-verify paranoia on signing paths | BUG-7, BUG-8, BUG-9 (3 paths) |
| no `secp256k1_ec_seckey_verify` precheck | BUG-10, BUG-11 |
| process-singleton init race | BUG-5 (`pthread_once` absent) |

---

## Summary

24 bugs catalogued.

**P0-class (5):** BUG-2 (side-channel-blinding disabled — P0-SEC,
fleet-wide pattern), BUG-7 (sign-then-verify paranoia missing on
ecdsa_sign_der — P0-SEC), BUG-8 (sign-then-recover paranoia missing on
ecdsa_sign_compact — P0-SEC), BUG-13 (`schnorr_verify_batch` is
sequential not batched — P0-CDIV "wiring-look-but-no-wire" +
"comment-as-confession"), BUG-16 (Sig_cache lacks per-process salt —
P0-SEC), BUG-17 (Sig_cache cache_key omits witness, chain-split via
SegWit malleability — P0-CONS), BUG-18 (serial mempool path races on
unsynchronised Hashtbl — P0-SEC).

**P1-class (12):** BUG-5 (`ensure_ctx` race), BUG-9 (Schnorr sign no
verify-after), BUG-10/11 (no seckey_verify precheck), BUG-12 (Schnorr
sign aborts without `/dev/urandom`), BUG-14 (batch-verify has zero
production callers), BUG-19 (BIP-322 absent), BUG-20 (no
memory_cleanse), BUG-21 (no LockedPool / mlock), BUG-22 (Bigstring
round-trip leaves heap residue).

**P2-class (7):** BUG-1 (deprecated `SIGN|VERIFY` flags), BUG-3 (no
`secp256k1_selftest`), BUG-4 (no context_destroy), BUG-6 (no periodic
rerandomize), BUG-15 (batch-verify opaque error), BUG-23 (no
`Gc.finalise`), BUG-24 (ctx not const post-init).
