# W158 — BIP-322 + Legacy message signing (camlcoin)

**Wave:** W158 — `signmessage`, `signmessagewithprivkey`, `verifymessage` RPCs;
`MessageHash` framing (`Bitcoin Signed Message:\n` + CompactSize);
`MessageSign` / `MessageVerify` round-trip; ECDSA compact-recoverable signature
format (header byte 27..34 with recid in low 2 bits and compressed-bit in bit 2);
`PKHash` (P2PKH) destination requirement; `EnsureWalletIsUnlocked` wallet gate;
BIP-322 virtual `to_spend` + `to_sign` framing (3 modes: Legacy / Simple / Full);
BIP-137 P2WPKH / P2SH-P2WPKH header-byte extension; Base64 signature wire
format.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/common/signmessage.cpp:24` — `const std::string MESSAGE_MAGIC = "Bitcoin Signed Message:\n";`
- `bitcoin-core/src/common/signmessage.cpp:26-55` — `MessageVerify(address, signature, message)` returns
  `MessageVerificationResult` enum (`ERR_INVALID_ADDRESS`, `ERR_ADDRESS_NO_KEY`,
  `ERR_MALFORMED_SIGNATURE`, `ERR_PUBKEY_NOT_RECOVERED`, `ERR_NOT_SIGNED`, `OK`).
- `bitcoin-core/src/common/signmessage.cpp:57-71` — `MessageSign(privkey, message, &signature)`
  → `privkey.SignCompact(MessageHash(message), bytes)` + `EncodeBase64`.
- `bitcoin-core/src/common/signmessage.cpp:73-79` — `MessageHash`:
  `HashWriter hasher{}; hasher << MESSAGE_MAGIC << message; return hasher.GetHash();`
  (single dsha256 of CompactSize-prefixed magic + CompactSize-prefixed message).
- `bitcoin-core/src/common/signmessage.h:23-41` — `MessageVerificationResult` enum.
- `bitcoin-core/src/common/signmessage.h:43-47` — `SigningResult` enum
  (`OK`, `PRIVATE_KEY_NOT_AVAILABLE`, `SIGNING_FAILED`).
- `bitcoin-core/src/rpc/signmessage.cpp:17-60` — `verifymessage` RPC: switch on
  `MessageVerify(...)`; raises `RPC_INVALID_ADDRESS_OR_KEY` (-5) for
  `ERR_INVALID_ADDRESS`, `RPC_TYPE_ERROR` (-3) for `ERR_ADDRESS_NO_KEY` AND
  `ERR_MALFORMED_SIGNATURE`, returns bare `false` for `ERR_PUBKEY_NOT_RECOVERED`
  / `ERR_NOT_SIGNED`, `true` for `OK`.
- `bitcoin-core/src/rpc/signmessage.cpp:62-101` — `signmessagewithprivkey`:
  `DecodeSecret(strPrivkey)` → raises `RPC_INVALID_ADDRESS_OR_KEY` on invalid WIF;
  `MessageSign(key, strMessage, signature)` → `RPC_INVALID_ADDRESS_OR_KEY` on
  sign failure.
- `bitcoin-core/src/wallet/rpc/signmessage.cpp:14-70` — wallet-scoped
  `signmessage`: `LOCK(pwallet->cs_wallet)` + `EnsureWalletIsUnlocked(*pwallet)`
  + `DecodeDestination(strAddress)` + `std::get_if<PKHash>(&dest)` strict-cast
  → `RPC_TYPE_ERROR` "Address does not refer to key"; calls
  `pwallet->SignMessage(strMessage, *pkhash, signature)` → maps
  `SIGNING_FAILED` to `RPC_INVALID_ADDRESS_OR_KEY` and other non-OK to
  `RPC_WALLET_ERROR`.
- `bitcoin-core/src/pubkey.cpp` (referenced) — `CPubKey::RecoverCompact`
  checks `signature.size() == COMPACT_SIGNATURE_SIZE (65)` then reads header
  byte: must be in `[27, 34]`; recid = `(header - 27) & 3`; compressed flag =
  `((header - 27) & 4) != 0`.
- BIP-322 spec — defines virtual `to_spend` + `to_sign` transactions:
  `to_spend.version = 0`, `to_spend.nLockTime = 0`, single input with
  null prevout + scriptSig = `OP_0 push(message_hash)`; `to_sign.version = 0`,
  spends `to_spend:0`. Three modes: Legacy (= current Core path,
  P2PKH-only), Simple (returns just witness of `to_sign`), Full (returns
  full `to_sign` transaction). Core does NOT yet implement BIP-322.

**Files audited**
- `lib/crypto.ml:182-269` — `sign_compact`, `recover_compact`,
  `message_magic`, `put_compact_size`, `message_hash`.
- `lib/rpc.ml:2830-2935` — `handle_signmessagewithprivkey`, `handle_signmessage`,
  `handle_verifymessage`.
- `lib/rpc.ml:7515-7521` — help-text strings for the three RPCs.
- `lib/rpc.ml:8687-8698` — RPC dispatch error-code mapping for the three
  RPCs.
- `lib/wallet.ml:600-643` — `find_by_address`, `find_by_pubkey_hash`,
  `find_by_script` (key-pair lookup).
- `lib/address.ml:258-398` — `address_to_string`, `address_of_string`,
  `wif_decode`, `wif_encode`, `of_pubkey`.
- `lib/schnorr_stubs.c:caml_ecdsa_recover_compact` — C stub validating
  header range 27..34, recid / compressed-bit decoding.
- `test/test_rpc.ml:1397-1495` — test coverage (round-trip,
  wrong-message, invalid-address, malformed-b64, invalid-WIF; **no test
  exercises P2WPKH/P2SH-P2WPKH/P2TR rejection or wallet-scoped path**).

---

## Gate matrix (30 sub-gates / 14 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | MESSAGE_MAGIC byte-equality | G1: `"Bitcoin Signed Message:\n"` literal | PASS (`crypto.ml:235`) |
| 2 | MessageHash framing | G2: CompactSize-prefixed magic | PASS (`crypto.ml:265-266`) |
| 2 | … | G3: CompactSize-prefixed message | PASS (`crypto.ml:267-268`) |
| 2 | … | G4: single dsha256 over both | PASS (`crypto.ml:269`) |
| 3 | Compact-sig wire format | G5: 65-byte total length | PASS (`crypto.ml:223`) |
| 3 | … | G6: header byte ∈ [27,34] enforced | PASS (`schnorr_stubs.c:caml_ecdsa_recover_compact` C-side check) |
| 3 | … | G7: recid = `(header-27)&3`, compressed = `((header-27)&4)!=0` | PASS (C stub) |
| 4 | signmessagewithprivkey | G8: WIF decode → error → RPC_INVALID_ADDRESS_OR_KEY (-5) | PASS (BUG-1 cross-cite — error-code mapping happens to match Core for this single path because dispatch hard-codes -5) |
| 4 | … | G9: sign failure → RPC_INVALID_ADDRESS_OR_KEY (-5) | PASS (cross-cite, dispatch -5) |
| 4 | … | G10: returns base64-encoded 65-byte string | PASS (`rpc.ml:2848-2850`) |
| 5 | signmessage (wallet path) | G11: requires wallet loaded → error otherwise | **BUG-2 (P1)** — uses `ctx.wallet` (legacy single-wallet) not `get_wallet_for_request`; multi-wallet mode breaks; "Method not found: no wallet is loaded." is a non-Core message string |
| 5 | … | G12: `EnsureWalletIsUnlocked(pwallet)` BEFORE sign | **BUG-3 (P0-SEC)** — handler never checks `Wallet.is_locked wallet`; an encrypted+locked wallet signs anyway because key material is stored in memory unencrypted (companion to W140 timing-oracle pattern; first message-sign locked-wallet bypass in fleet tracking) |
| 5 | … | G13: PKHash (P2PKH) destination required | PARTIAL (BUG-4) — `addr.addr_type <> P2PKH` rejected with text "Address does not refer to key" (BUG-7 maps to -5 instead of Core's -3); but the match-statement at line 2883-2889 is **dead code** (BUG-5) |
| 5 | … | G14: WIF-first sniff for backward compat — accepts "signmessage WIF msg" form | INTENTIONAL DEVIATION (`rpc.ml:2868-2873`); not a bug per se but **silently bypasses the wallet-locked check** (BUG-3 cross-cite) AND the P2PKH-only check (BUG-3 second cross-cite) — operator who learns the WIF shape can sign with ANY private key regardless of wallet-encrypt state or registered keys |
| 6 | verifymessage | G15: invalid address → RPC_INVALID_ADDRESS_OR_KEY (-5) | PASS |
| 6 | … | G16: address-no-key (non-P2PKH) → RPC_TYPE_ERROR (-3) + msg "Address does not refer to key" | **BUG-7 (P1)** — dispatch maps to -5; emitted message has parenthetical "(only P2PKH supported)" not in Core (wire-string parity gap) |
| 6 | … | G17: malformed base64 → RPC_TYPE_ERROR (-3) + msg "Malformed base64 encoding" | **BUG-7 cross-cite** — dispatch maps to -5 instead of -3 (Core's RPC_TYPE_ERROR) |
| 6 | … | G18: bad-length signature → returns `false` (not error) | PASS (`rpc.ml:2924` length-check returns `Ok(Bool false)`) |
| 6 | … | G19: pubkey-not-recovered → returns `false` | PASS (`rpc.ml:2928`) |
| 6 | … | G20: pkhash mismatch → returns `false` | PASS (`rpc.ml:2931`) |
| 7 | Address.network cross-check | G21: address network must match daemon's `ctx.network` | **BUG-8 (P0-SEC)** — `address_of_string` is network-agnostic; signmessage / verifymessage on a regtest daemon accept mainnet addresses (and vice versa). Cross-network signature shadowing primitive |
| 8 | Signet network support | G22: `tb1` HRP for signet bech32 | **BUG-9 (P1)** — `address.ml:364-383` only routes `t`/`T`-prefix through testnet path (`hrp = "tb"`); signet uses the SAME `tb` HRP but no Address.network variant for signet exists at all (only `Mainnet`, `Testnet`, `Regtest` in `network` type) — so signet operator's signmessage either silently signs with Testnet-prefixed WIF or fails depending on input shape |
| 9 | WIF length strictness | G23: uncompressed 33-byte vs compressed 34-byte; extra bytes rejected | **BUG-10 (P1)** — `address.ml:438-457` accepts `len >= 33`. For `len = 35, 36, ...` the trailing bytes are silently ignored and `compressed = (len = 34 && payload[33] = 0x01)` — a 35-byte WIF parses as uncompressed (compressed flag false) without complaint; Core's `DecodeSecret` rejects non-{33,34}-byte payloads as invalid |
| 9 | … | G24: 34-byte payload with trailing byte ≠ 0x01 → reject (Core) | **BUG-10 cross-cite** — `compressed` test is `payload[33] = 0x01`; if trailing byte is 0x00 or 0x02..0xFF, camlcoin reads `compressed = false` and proceeds (Core: invalid) |
| 10 | BIP-137 P2WPKH / P2SH-P2WPKH header bytes (31..38 / 35..38) | G25: recognise BIP-137 header range and verify against witness destination | **BUG-11 (P1)** — verifymessage hard-rejects any non-P2PKH address before checking the header byte; BIP-137 (Trezor/Electrum-de-facto signing for SegWit addresses) is wholly unsupported, even though the SAME 65-byte compact-recoverable primitive could verify against a P2WPKH or P2SH-P2WPKH destination after pubkey recovery |
| 11 | BIP-322 framing | G26: virtual `to_spend` (version=0, nLockTime=0, null prevout, `OP_0 push(message_hash)` scriptSig, single zero-value output with destination scriptPubKey) | **BUG-12 (P1) BIP-322 ENTIRELY ABSENT** — no `to_spend` / `to_sign` constructors, no virtual-tx code path; signing a message for a P2WPKH/P2TR address is impossible |
| 11 | … | G27: virtual `to_sign` (version=0, spends `to_spend:0`, single OP_RETURN output) | **BUG-12 cross-cite** |
| 11 | … | G28: BIP-322 sighash variant computation (taproot for v1, segwit for v0) | **BUG-12 cross-cite** |
| 12 | help-text | G29: enumerate signmessage / signmessagewithprivkey / verifymessage | PASS (`rpc.ml:7517-7519`) |
| 13 | Test coverage | G30: round-trip OK; tampered-msg → false; invalid-addr → error; malformed-b64 → error; invalid-WIF → error | PARTIAL (`test_rpc.ml:1414-1495` covers exactly these but no test for: wallet-scoped path, locked-wallet rejection, non-P2PKH rejection, cross-network address, BIP-137 verify, BIP-322 sign) |

---

## BUG-1 (P1) — Dispatch error-code mapping collapses all errors to RPC_INVALID_ADDRESS_OR_KEY (-5), masking RPC_TYPE_ERROR, RPC_INVALID_PARAMETER, RPC_WALLET_ERROR

**Severity:** P1. Bitcoin Core's `verifymessage` / `signmessage` RPCs map
distinct error classes to distinct JSON-RPC error codes:

- `RPC_INVALID_ADDRESS_OR_KEY` (-5) — `ERR_INVALID_ADDRESS`,
  `signmessagewithprivkey` invalid-WIF, `signmessagewithprivkey` sign-failed,
  `signmessage` SIGNING_FAILED.
- `RPC_TYPE_ERROR` (-3) — `ERR_ADDRESS_NO_KEY`, `ERR_MALFORMED_SIGNATURE`,
  wallet-`signmessage`'s "Address does not refer to key".
- `RPC_INVALID_PARAMETER` (-8) — bad parameter shape / wrong arg count.
- `RPC_WALLET_ERROR` (-4) — `signmessage` non-SIGNING_FAILED / non-OK
  `SigningResult` (e.g. PRIVATE_KEY_NOT_AVAILABLE).
- `RPC_METHOD_NOT_FOUND` (-32601) — when called without a wallet loaded.

camlcoin's dispatch at `rpc.ml:8687-8698` hard-codes ALL errors from the
three handlers to `rpc_invalid_address` (-5):

```ocaml
| "signmessage" ->
  (match handle_signmessage ctx params with
   | Ok r -> Ok r
   | Error msg -> Error (rpc_invalid_address, msg))   (* -5 *)
| "signmessagewithprivkey" ->
  (match handle_signmessagewithprivkey ctx params with
   | Ok r -> Ok r
   | Error msg -> Error (rpc_invalid_address, msg))   (* -5 *)
| "verifymessage" ->
  (match handle_verifymessage ctx params with
   | Ok r -> Ok r
   | Error msg -> Error (rpc_invalid_address, msg))   (* -5 *)
```

Concrete diverging cases:

- `verifymessage` with non-P2PKH bech32 address → camlcoin returns `code=-5,
  msg="Address does not refer to a key (only P2PKH supported)"`; Core
  returns `code=-3 (RPC_TYPE_ERROR), msg="Address does not refer to key"`.
- `verifymessage` with non-base64 signature → camlcoin returns `code=-5,
  msg="Malformed base64 encoding"`; Core returns `code=-3, msg="Malformed
  base64 encoding"`.
- `verifymessage` with wrong arg count → camlcoin returns `code=-5,
  msg="Invalid parameters: ..."`; Core returns `code=-8 (RPC_INVALID_PARAMETER)`.
- `signmessage` with no wallet → camlcoin returns `code=-5, msg="Method not
  found: no wallet is loaded."`; Core returns `code=-32601 (RPC_METHOD_NOT_FOUND)`.

**File:** `lib/rpc.ml:8687-8698`.

**Core ref:** `bitcoin-core/src/rpc/signmessage.cpp:44-49`,
`bitcoin-core/src/wallet/rpc/signmessage.cpp:51-65`.

**Impact:** any operator tooling that distinguishes RPC errors by code
(prometheus exporters, Sentry filters, bitcoin-cli return-code checks)
sees a flat -5 stream from camlcoin where Core emits a structured
{-3, -4, -5, -8, -32601} spread. Cross-impl rpc-conformance harness break.

---

## BUG-2 (P1) — `handle_signmessage` uses legacy `ctx.wallet` instead of `get_wallet_for_request`; multi-wallet mode is dead-on-arrival for this RPC

**Severity:** P1. camlcoin supports BOTH a legacy single-wallet
(`ctx.wallet : Wallet.t option`) AND a multi-wallet manager
(`ctx.wallet_manager : Wallet.wallet_manager option`) — see the
`get_wallet_for_request` helper at `rpc.ml:2523-2540` which other wallet
RPCs (encryptwallet, walletpassphrase, sendtoaddress, etc.) use to honour
both the per-URL `/wallet/<name>` routing AND the legacy default.

`handle_signmessage` at `rpc.ml:2876-2877` reads ONLY `ctx.wallet`:

```ocaml
| Error _ ->
  (* Wallet-scoped path: look up the address in the loaded wallet. *)
  match ctx.wallet with
  | None -> Error "Method not found: no wallet is loaded."
  | Some wallet ->
    ...
```

Consequences:
1. A daemon launched in multi-wallet mode (`wallet_manager = Some _`,
   `wallet = None`) returns "Method not found: no wallet is loaded." for
   every `signmessage` call even when wallets are loaded via
   `loadwallet`/`createwallet`.
2. The `/wallet/<name>` URL-prefix routing has no effect on
   `signmessage` — even if the user POSTs to `/wallet/alice`, the handler
   reads `ctx.wallet` (the default), not "alice".
3. The error message "Method not found: no wallet is loaded." is a
   non-Core string (Core: `"Wallet file not specified (must request wallet
   RPC through /wallet/<filename> uri-path)."` for multi-wallet ambiguity;
   `"Method not found"` for an unrecognised command).

**File:** `lib/rpc.ml:2864-2905` (handler), 2523-2540 (skipped helper).

**Core ref:** `bitcoin-core/src/wallet/rpc/signmessage.cpp:39`
(`GetWalletForJSONRPCRequest(request)`).

**Impact:** signmessage RPC is broken under any multi-wallet deployment.
Cross-cite W155 BUG-1 (mode="proposal" unimplemented) — both are
single-wallet/single-mode "happy-path-only" handler patterns.

---

## BUG-3 (P0-SEC) — `handle_signmessage` does NOT call `Wallet.is_locked`; encrypted+locked wallet signs anyway

**Severity:** P0-SEC. Bitcoin Core's wallet-scoped `signmessage`
(`wallet/rpc/signmessage.cpp:42-44`):

```cpp
LOCK(pwallet->cs_wallet);
EnsureWalletIsUnlocked(*pwallet);
```

`EnsureWalletIsUnlocked` throws `RPC_WALLET_UNLOCK_NEEDED` (-13) if the
wallet is encrypted AND locked. This prevents an attacker who steals the
RPC cookie of a passphrase-protected wallet from signing arbitrary
messages (which could be used for proof-of-ownership scams, Lightning
channel impersonation, or to authorise off-chain commitments).

camlcoin's `handle_signmessage` (`rpc.ml:2864-2905`) has NO equivalent
check:

```ocaml
| Error _ ->
  match ctx.wallet with
  | None -> Error "Method not found: no wallet is loaded."
  | Some wallet ->
    match Address.address_of_string addr_or_wif with
    | Error _ -> Error "Invalid address"
    | Ok addr ->
      ... (* P2PKH check *) ...
      match Wallet.find_by_address wallet addr_or_wif with
      | None -> Error "Private key not available"
      | Some kp ->
        let msg_hash = Crypto.message_hash message in
        (try
          let sig_bytes = Crypto.sign_compact ~compressed:true
            kp.Wallet.private_key msg_hash in   (* <-- signs unconditionally *)
          ...
```

`Wallet.is_locked` exists at `wallet.ml:2218` and is used by sign-related
flows elsewhere (`rpc.ml:6321-6323`: "if sign && Wallet.is_encrypted
wallet && Wallet.is_locked wallet then ..."). The check is **omitted**
from signmessage even though the same access pattern applies.

Worse: the `Wallet.key_pair` record stores `private_key` as plain
`Crypto.private_key` — the encryption-at-rest is unwound at wallet-unlock
time and the cleartext private key sits in `w.keys` for the life of the
process. So even a "locked" wallet (in the sense that
`walletpassphrase`'s timeout has expired) still holds the raw key material
in memory. `is_locked` is the ONLY gate between an RPC caller and the
private key. Skipping it is functionally identical to having no wallet
encryption.

**File:** `lib/rpc.ml:2864-2905`.

**Core ref:** `bitcoin-core/src/wallet/rpc/signmessage.cpp:42-44`
(`EnsureWalletIsUnlocked`).

**Impact:**
- Encrypted+locked wallet exposed: any RPC caller with the cookie can
  sign arbitrary messages, defeating wallet encryption for proof-of-key
  attacks.
- Cross-cite W140 timing-oracle on credential compare (fleet-wide
  pattern) — this is the same "skipped sentinel" class on a different
  primitive (auth → message-sign).
- "dead-helper-at-call-site" (`Wallet.is_locked` exists, called from
  the broader-sign path at rpc.ml:6321, NOT called from the
  message-sign path; the helper is present, the call-site is missing).
- BIP-322 would inherit the same gap; future BIP-322 implementation
  must add the gate, not just plumb `to_spend` / `to_sign`.

---

## BUG-4 (P0-SEC) — WIF-sniff backward-compat path silently bypasses ALL of: wallet-encrypt check, P2PKH-only check, multi-wallet routing, network cross-check

**Severity:** P0-SEC (compounds BUG-3, BUG-8). The WIF-first sniff at
`rpc.ml:2868-2873`:

```ocaml
(* Backward-compat: if the first arg parses as WIF, route to the legacy
   privkey-based path.  This keeps existing callers working without
   forcing them to switch to "signmessagewithprivkey". *)
(match Address.wif_decode addr_or_wif with
 | Ok _ ->
   handle_signmessagewithprivkey ctx params
 | Error _ ->
   (* Wallet-scoped path: ... *)
```

is described in the docstring as keeping "existing callers working" and
giving wire-compat with "earlier camlcoin builds (and the cross-impl test
fleet)." This is a textbook **comment-as-confession** (14th distinct
camlcoin instance per W156 tracking).

Concrete divergences:
1. ANY caller who knows the WIF can sign with the private key WITHOUT
   the wallet being loaded, unlocked, or even containing that key. The
   `signmessagewithprivkey` path takes the WIF in band.
2. Bitcoin Core's `signmessage` does NOT take WIF; the wire-format
   `[address, message]` MUST be `[address, message]`. A regression test
   that pins on Core's behaviour will accept a WIF in camlcoin's
   `signmessage` where Core rejects it as invalid address.
3. The sniff is silent — there is no log line, no warning, no
   per-call audit trail that this code path was taken.
4. Combined with BUG-8 (no network cross-check on the WIF), an operator
   on a regtest daemon can sign with a mainnet WIF, producing a signature
   that's verifiable against a mainnet address.

**File:** `lib/rpc.ml:2864-2873`.

**Core ref:** `bitcoin-core/src/wallet/rpc/signmessage.cpp` (no WIF path).

**Impact:**
- Test-suite fleet expectation drift: the test that exists at
  `test/test_rpc.ml:1414-1437` uses `signmessage WIF message` (line
  1421-1422), which means the camlcoin test suite would fail against a
  Core-compliant `signmessage` and the deviation has been baked into
  the regression baseline.
- Audit-trail gap: there is no way to tell from logs whether a given
  signmessage call hit the wallet path or the WIF path.
- Cross-impl divergence: other fleet impls that follow Core's
  `[address, message]` shape will error on the same input camlcoin
  silently accepts.

---

## BUG-5 (P1) — Dead `match` in `handle_signmessage` adds zero validation; both branches return `()`

**Severity:** P1 ("dead-code in consensus-adjacent path", same shape as
W143 BUG-16 in clearbit). `rpc.ml:2882-2891`:

```ocaml
(* Core requires PKHash (P2PKH) for signmessage. *)
(match addr.Address.addr_type with
 | Address.P2PKH -> ()
 | _ ->
   (* Fall through into the lookup; if no key matches, the user
      will get a clear error.  But first, return the Core message
      directly for non-P2PKH so callers see the same shape. *)
   ()) ;
if addr.Address.addr_type <> Address.P2PKH then
  Error "Address does not refer to key"
else
  ...
```

The `match` block is dead — both arms return `()` and the only effect is
the trailing `;`. The COMMENT in the `_` arm says "Fall through into the
lookup ... return the Core message directly for non-P2PKH so callers see
the same shape" — but the very next line (`if addr.addr_type <> P2PKH
then Error ...`) does the opposite (always rejects). The comment is
literally describing a different implementation than the code performs.

Both: a comment-as-confession AND dead code.

**File:** `lib/rpc.ml:2882-2891`.

**Core ref:** `bitcoin-core/src/wallet/rpc/signmessage.cpp:54-57` (single
`std::get_if<PKHash>(&dest)` cast → throw on null).

**Impact:** code-quality only; the dead match adds no behaviour. Cleanup
candidate. 14th distinct camlcoin comment-as-confession (per W156).

---

## BUG-6 (P1) — Multi-pipeline drift: signmessage handler does NOT route through `get_wallet_for_request`, breaking 13-CONSECUTIVE-QUAD camlcoin pipeline-drift pattern continuation

**Severity:** P1. The 12-consecutive-quad pipeline-drift pattern
(W143→W157) is preserved in W158 (13th wave instance): there are now
THREE distinct wallet-lookup pipelines in camlcoin's RPC layer:

1. `get_wallet_for_request` (`rpc.ml:2523-2540`) — the canonical helper,
   honours multi-wallet manager + URL routing + legacy fallback.
   Consumers: encryptwallet, walletpassphrase, walletlock, createwallet,
   loadwallet, ... (most wallet RPCs).
2. Raw `ctx.wallet` (`rpc.ml:1846, 1989, 2196, ...`) — legacy
   single-wallet only; ignores multi-wallet.
3. NEW in W158 (this handler): hybrid `ctx.wallet` access combined with
   `Wallet.find_by_address` (`rpc.ml:2876, 2893`) — does NOT route through
   either helper for the wallet-encrypt or address-network check.

A single RPC handler that needs both wallet-by-name AND key-by-address
lookup must use BOTH `get_wallet_for_request` AND `find_by_address`.
camlcoin's W158 handler uses NEITHER correctly.

**File:** `lib/rpc.ml:2864-2905`.

**Cross-cite:** W155 BUG-1 (`mode="proposal"` unimplemented — partial
handler), W150 BUG-4 (`Mempool.create` regtest-hardcode — defined-but-not-
wired), this BUG-6 (signmessage wallet-path defined but not wired through
helpers). 13-consecutive-quad camlcoin pipeline-drift preserved.

**Impact:** see BUG-2 and BUG-3 — concretely, multi-wallet deployments
get "Method not found" on signmessage; encrypted-wallet deployments
silently sign without unlock.

---

## BUG-7 (P1) — Wire-string parity gaps in error messages: "(only P2PKH supported)" and "Method not found: no wallet is loaded." not in Core

**Severity:** P1 ("reject-string wire-parity slippage", same fleet shape
as W125, W145 lunarblock 9-token sweep). Comparing camlcoin error
strings to Core:

| Path | camlcoin string | Core string |
|------|-----------------|-------------|
| verifymessage P2PKH-only | `"Address does not refer to a key (only P2PKH supported)"` | `"Address does not refer to key"` |
| signmessage no-wallet | `"Method not found: no wallet is loaded."` | (Core throws `RPC_METHOD_NOT_FOUND` with default JSON-RPC text "Method not found", no parenthetical) |
| signmessage invalid-addr | `"Invalid address"` | `"Invalid address"` ✓ |
| verifymessage invalid-addr | `"Invalid address"` | `"Invalid address"` ✓ |
| signmessagewithprivkey invalid-WIF | `"Invalid private key: <hex-decode-msg>"` | `"Invalid private key"` (no suffix) |
| sign failure | `"Sign failed"` | `"Sign failed"` ✓ |
| no-key-in-wallet | `"Private key not available"` | (Core returns `SigningResult::PRIVATE_KEY_NOT_AVAILABLE` → string "Private key not available") ✓ |

Three of seven strings diverge. Tools like `bitcoin-cli`-driven
acceptance tests, error-message-scraping monitoring, and user-facing
documentation all pin on these strings.

**File:** `lib/rpc.ml:2877, 2844, 2933`.

**Core ref:** `bitcoin-core/src/common/signmessage.cpp:81-91`
(`SigningResultString`), `bitcoin-core/src/rpc/signmessage.cpp:44-52`
(`MessageVerify` → JSONRPCError text).

**Impact:** wire-string parity; cross-impl test harness break. Cumulative
across W125 lunarblock + W145 lunarblock 9-token + this — fleet-wide
gap in error-token parity discipline.

---

## BUG-8 (P0-SEC) — `Address.address_of_string` is network-agnostic; signmessage/verifymessage on a regtest daemon accept mainnet addresses

**Severity:** P0-SEC (cross-network signature primitive). Bitcoin Core's
`DecodeDestination(strAddress)` returns `CTxDestination`, then
`IsValidDestination` is checked against the **current node's
chainparams** — a regtest node rejects mainnet `1...` addresses and
vice versa.

camlcoin's `Address.address_of_string` (`address.ml:320-398`) returns the
network-from-prefix as a tagged value INSIDE the `address` record (e.g.,
`{ network = `Mainnet; ... }` for a `1...` address) but the message-sign
handlers NEVER cross-check `addr.network = network_to_address_network
ctx.network`. From `rpc.ml:2879-2898`:

```ocaml
match Address.address_of_string addr_or_wif with
| Error _ -> Error "Invalid address"
| Ok addr ->
  ...
  if addr.Address.addr_type <> Address.P2PKH then
    Error "Address does not refer to key"
  else
    match Wallet.find_by_address wallet addr_or_wif with
    ...
```

`find_by_address` compares string-equality (`wallet.ml:634-637`):

```ocaml
let find_by_address (w : t) (addr_str : string) : key_pair option =
  List.find_opt (fun kp ->
    Address.address_to_string kp.address = addr_str
  ) w.keys
```

So:
- A regtest daemon with a regtest wallet has keys whose
  `address_to_string` returns `mqM...` / `bcrt1q...`. A mainnet
  `1A1zP1eP...` address parses fine, then `find_by_address` returns
  `None` (no key match) → `"Private key not available"`. That ends the
  wallet-path attack, but...
- The WIF-sniff bypass (BUG-4) parses the WIF without network check
  (the `network` field is discarded by `let (_, _, _network) = ...` at
  `rpc.ml:2845`). A mainnet WIF on a regtest daemon signs a message
  with the mainnet private key, producing a signature that verifies
  on mainnet against the mainnet address. So a regtest daemon
  becomes a free mainnet-key oracle if the WIF is exposed.
- For `verifymessage`, the asymmetry is worse: the daemon's network
  is irrelevant to the recovery + hash160 compare, so verifymessage
  is fully cross-network — a regtest node returns `true` for a
  mainnet signature against a mainnet address.

**File:** `lib/rpc.ml:2845, 2879-2898, 2915-2933`;
`lib/address.ml:320-398`.

**Core ref:** `bitcoin-core/src/key_io.cpp::DecodeDestination` (chainparams-
aware).

**Impact:**
- WIF-sniff bypass turns regtest into mainnet-key oracle if the WIF
  reaches the daemon.
- verifymessage is cross-network by default — a mainnet signature
  validated by a regtest daemon returns `true`, which breaks the
  semantic that "the daemon's chain context contains the result."
- Cross-cite W125 + W145 + W155 fleet patterns on network-config
  audits. First message-sign cross-network instance in fleet
  tracking.

---

## BUG-9 (P1) — Signet network unsupported across the entire `Address` module → signmessage/verifymessage broken for signet

**Severity:** P1. camlcoin's `Address.network` type is:

```ocaml
type network = [ `Mainnet | `Testnet | `Regtest ]
```

(see `address.ml:` near the top; `wif_decode` at line 446-450 also
matches only `0x80` / `0xEF`). There is NO `Signet` variant. Signet
uses the same `tb` HRP as testnet3/4 for bech32, but ALSO has its own
WIF version byte semantics (signet's WIF prefix is `0xEF`, same as
testnet, so the WIF path is degenerate) AND its own chain context where
the message-signature semantics are identical to testnet.

The practical effect: a daemon launched with `--chain signet`:
- `address_of_string` for a `tb1...` address parses correctly but
  returns `network = `Testnet`.
- `wif_decode` for a signet WIF returns `network = `Testnet`.
- `signmessage` / `verifymessage` work but the daemon's `ctx.network`
  is signet — the cross-check that BUG-8 says is missing would
  ALSO need to map signet ↔ `Testnet` for the address to be acceptable.
- Operator tooling that reads back `ctx.network` for logging or
  policy enforcement sees "signet" on the daemon and "testnet" on the
  address-network tag — mismatch.

**File:** `lib/address.ml:` (network type definition); 446-450
(wif_decode versions); 320-398 (address_of_string switch).

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp::SigNetParams`
(distinct Base58 / Bech32 prefixes; mostly same as testnet but
separate chainparams).

**Impact:** signet operator monitoring sees network mismatches between
daemon-config and address-network; future signet WIF semantics if
they ever diverge from testnet break silently.

---

## BUG-10 (P1) — `wif_decode` accepts any payload length ≥ 33; trailing byte ≠ 0x01 → silently uncompressed

**Severity:** P1. Bitcoin Core's `DecodeSecret` (`key_io.cpp`) checks
strict {33, 34}-byte payload AND, if 34-byte, requires the trailing byte
== `0x01` (the canonical compressed-pubkey flag). Any other length OR
trailing byte → reject as invalid private key.

camlcoin's `wif_decode` (`address.ml:438-457`):

```ocaml
let wif_decode (s : string) : (Cstruct.t * bool * network, string) result =
  match base58check_decode s with
  | Error e -> Error e
  | Ok payload ->
    let len = Cstruct.length payload in
    if len < 33 then Error "WIF too short"
    else begin
      let version = Cstruct.get_uint8 payload 0 in
      let network = match version with
        | 0x80 -> Ok `Mainnet
        | 0xEF -> Ok `Testnet
        | _ -> Error (Printf.sprintf "Unknown WIF version: 0x%02x" version)
      in
      match network with
      | Error e -> Error e
      | Ok network ->
        let compressed = len = 34 && Cstruct.get_uint8 payload 33 = 0x01 in
        let privkey = Cstruct.sub payload 1 32 in
        Ok (privkey, compressed, network)
    end
```

- `len = 33`: OK (uncompressed) ✓
- `len = 34, payload[33] = 0x01`: OK (compressed) ✓
- `len = 34, payload[33] != 0x01`: camlcoin returns
  `(privkey, false, network)` (silently uncompressed); Core rejects.
- `len = 35..N`: camlcoin returns `(privkey, false, network)`
  (silently uncompressed, extra bytes dropped); Core rejects as
  invalid.

The `Cstruct.sub payload 1 32` always pulls the first 32 bytes after the
version, ignoring any trailing data.

**File:** `lib/address.ml:438-457`.

**Core ref:** `bitcoin-core/src/key_io.cpp::DecodeSecret`.

**Impact:**
- WIF malleability: the same private key can be expressed in many
  valid-to-camlcoin WIFs (`base58check_decode` is the only validation
  of the trailing region). Cross-impl WIF normalisation breaks.
- A 34-byte payload with `0x00` trailing byte parses as uncompressed
  even though no canonical Core-style WIF has that shape — operator
  who hand-crafts a WIF could accidentally produce two valid keys
  from one input.
- Combined with BUG-4 + BUG-8: an attacker who can submit arbitrary
  base58-decodable strings to `signmessage` can sign messages with
  ANY private key whose WIF round-trips through this loose decoder.

---

## BUG-11 (P1) — BIP-137 (P2WPKH / P2SH-P2WPKH header byte 31..38) unsupported; SegWit-address signmessage impossible

**Severity:** P1. BIP-137 (Trezor + Electrum de-facto standard for SegWit
message signing, predating BIP-322) extends the compact-recoverable
signature header byte:

- 27..30 → P2PKH uncompressed (legacy)
- 31..34 → P2PKH compressed (legacy)
- 35..38 → P2SH-P2WPKH (BIP-137)
- 39..42 → P2WPKH (BIP-137)

The recovery primitive is identical; only the destination check changes
(hash160 of recovered pubkey compared against P2SH redeemScript hash or
P2WPKH witness program). camlcoin's `verifymessage` (`rpc.ml:2918-2933`)
hard-rejects any non-P2PKH address with `"Address does not refer to a
key (only P2PKH supported)"` before checking the header byte. A signature
produced by Trezor/Electrum against a `bc1q...` (P2WPKH) address cannot
be verified.

The C stub at `schnorr_stubs.c:caml_ecdsa_recover_compact` already
accepts the full range [27,34] — extending to [27,42] is one-line
work — but the OCaml dispatch never reaches recovery for non-P2PKH
addresses.

**File:** `lib/rpc.ml:2918-2933` (verifymessage); 2890 (signmessage path).

**Core ref:** Core does NOT yet implement BIP-137 (open RFC; pending
BIP-322 standardisation). But the cross-impl fleet (Electrum, Trezor,
Sparrow) does — camlcoin's hard-reject is more restrictive than
ecosystem reality.

**Impact:**
- Wallets that signed messages with Trezor/Electrum/Sparrow against
  SegWit addresses cannot use camlcoin to verify.
- BIP-322 transition path (future) inherits the gap unless plumbed
  through the same hash160 check.

---

## BUG-12 (P1) — BIP-322 (virtual `to_spend` + `to_sign` framing) entirely absent; P2WPKH/P2WSH/P2TR signing impossible

**Severity:** P1 ("dead-data plumbing" inverse — neither plumbed nor
implemented). BIP-322 ("Generic Signed Message Format") defines a
3-mode framework that subsumes legacy Bitcoin-Signed-Message:

- **Legacy mode**: equivalent to current Core behaviour (P2PKH only,
  compact-recoverable ECDSA signature over MessageHash).
- **Simple mode**: construct virtual `to_spend` transaction (version=0,
  nLockTime=0, single input with null prevout and scriptSig =
  `OP_0 push(message_hash)`, single zero-value output with destination
  scriptPubKey); construct virtual `to_sign` transaction (version=0,
  spends `to_spend:0`, single OP_RETURN output); compute sighash per
  destination type (BIP-143 for SegWit v0, BIP-341 for Taproot);
  sign with the destination's key; return the witness of `to_sign:0`.
- **Full mode**: as Simple but return the complete serialised `to_sign`
  transaction (allows multisig, miniscript, complex spending paths).

camlcoin has ZERO BIP-322 code: no `to_spend` constructor, no `to_sign`
constructor, no `bip322` module, no signed-message-version negotiation,
no message-hash for v1/v2 BIP-322 sighashes. Grep:

```
grep -rn -i "bip322\|bip-322\|to_spend\|to_sign\|virtual.*tx" lib/ test/
→ (no matches in production code; signet.cpp-style to_spend exists in
   Core but is unrelated)
```

This is consistent with Core (which also has not yet implemented
BIP-322), but the ecosystem (Sparrow, Specter, BitcoinJS, Mempool.space)
has converged on BIP-322 Simple mode for SegWit address signing.
camlcoin's `signmessage` is essentially limited to P2PKH legacy
addresses (which are an ever-shrinking fraction of UTXOs).

**File:** entire `lib/` (absent).

**Core ref:** Core does not yet implement BIP-322 either; this is a
forward-looking gap. The spec at
https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki defines
the framing. Fleet-wide audit will likely show 10/10 missing.

**Impact:**
- Message signing for the dominant SegWit address types is impossible.
- Cross-impl divergence: Sparrow-signed P2WPKH messages cannot be
  verified on camlcoin.
- Forward-compatibility: when Core lands BIP-322, camlcoin will need
  the full virtual-tx + sighash plumbing, which is a non-trivial
  refactor.

---

## BUG-13 (P1) — `Wallet.find_by_address` uses `address_to_string` round-trip equality, not canonical-form normalisation; mixed-case bech32 fails to match

**Severity:** P1. `wallet.ml:634-637`:

```ocaml
let find_by_address (w : t) (addr_str : string) : key_pair option =
  List.find_opt (fun kp ->
    Address.address_to_string kp.address = addr_str
  ) w.keys
```

This compares the canonical string form (lowercase bech32, well-known
checksum, etc.) of the wallet's stored address against the EXACT input
string. Bech32 addresses can be UPPERCASE (BIP-173: "Decoders MUST
NOT accept strings where some characters are uppercase and some are
lowercase"; but a fully-uppercase bech32 IS valid). A user who passes
`BC1Q...` (uppercase, common in QR codes) to `signmessage` will fail
the lookup with `"Private key not available"` even though the key
exists in the wallet under the lowercase form.

Similarly, Base58 addresses MAY round-trip without case differences,
but the `address.ml:address_to_string` canonicalisation has not been
audited for `address_of_string ∘ address_to_string = id` for ALL valid
Core inputs (e.g., older base58 forms with leading-zero edge cases).

**File:** `lib/wallet.ml:634-637`.

**Core ref:** Core normalises via `DecodeDestination` + `CTxDestination`
equality, not string equality.

**Impact:**
- Mixed-case / uppercase bech32 inputs fail lookup even when the
  destination matches.
- Forward-compat with descriptor wallets: a key registered under
  one canonical address form can't be looked up via a different
  canonical form for the same key.

---

## BUG-14 (P1) — Message length unbounded; no Core-style DoS clamp on huge messages

**Severity:** P1. `crypto.ml:262-269`:

```ocaml
let message_hash (message : string) : Types.hash256 =
  let buf = Buffer.create
    (10 + String.length message_magic + String.length message) in
  put_compact_size buf (String.length message_magic);
  Buffer.add_string buf message_magic;
  put_compact_size buf (String.length message);
  Buffer.add_string buf message;
  sha256d (Cstruct.of_string (Buffer.contents buf))
```

There is no upper bound on `String.length message`. An RPC caller can
submit a 2 GiB message — the buffer is allocated, populated, and hashed
in O(message). Combined with `Crypto.sha256d` being a synchronous
external call, this is a single-RPC-call DoS primitive.

Core does not bound message length at the API level either (it inherits
the JSON-RPC max-request-size cap), but camlcoin's HTTP/JSON-RPC server
(`rpc.ml`-side) has no message-size cap exposed in this audit; cross-cite
W140 audit on HTTP layer.

**File:** `lib/crypto.ml:262-269`.

**Core ref:** `bitcoin-core/src/common/signmessage.cpp::MessageHash`
(also unbounded; relies on HTTP layer's `MAX_SIZE = 32 MiB`).

**Impact:**
- DoS via large message argument; mitigated only if upstream HTTP
  layer enforces a size cap (which W140 audit did not confirm).
- Synchronous OCaml string allocation can OOM the daemon on very
  large messages.

---

## BUG-15 (P1) — `message_hash` puts CompactSize size as `int` not `int64`; messages > 2^63 hypothetically wrap

**Severity:** P1 (theoretical / type-tightness). `put_compact_size`
takes `int` (OCaml-native, 63-bit on 64-bit hosts). The CompactSize wire
format allows up to `0xFFFFFFFFFFFFFFFF` (uint64). A 4-EiB message is
not physically possible, so this is purely a type-contract leak — but
the W125 / W145 reject-string sweeps establish the fleet pattern that
"type-contract leaks even on impossible inputs" still merit recording
because future refactors that switch to `int64`-aware buffers WILL
expose the same gap.

**File:** `lib/crypto.ml:239-257`.

**Impact:** none in practice; type-tightness for cross-impl wire-format
audits.

---

## BUG-16 (P1) — `sign_compact` exception path returns string `"Sign failed"` with no privkey-validity precondition

**Severity:** P1. `rpc.ml:2847-2851`:

```ocaml
(try
  let sig_bytes = Crypto.sign_compact ~compressed privkey msg_hash in
  let sig_str = Cstruct.to_string sig_bytes in
  Ok (`String (Base64.encode_string sig_str))
with _ -> Error "Sign failed")
```

`Crypto.sign_compact` calls the C stub `caml_ecdsa_sign_compact` which
will exception on:
- privkey not in valid scalar range (rare with random-32-byte WIF inputs
  but possible).
- libsecp256k1 entropy gathering failure.

Core's `MessageSign` (`signmessage.cpp:57-71`):

```cpp
bool MessageSign(const CKey& privkey, const std::string& message, std::string& signature) {
    std::vector<unsigned char> signature_bytes;
    if (!privkey.SignCompact(MessageHash(message), signature_bytes)) {
        return false;
    }
    signature = EncodeBase64(signature_bytes);
    return true;
}
```

Core's `SignCompact` returns `false` on out-of-range scalar (it does
NOT throw). camlcoin's try/`with _` catches the general exception, but:
1. The C-stub could segfault on a malformed input that bypasses the
   length check (Cstruct.length = 32 IS checked in OCaml, but the
   bigarray pinning is not bounds-checked on access).
2. The error string "Sign failed" doesn't distinguish
   `PRIVATE_KEY_NOT_AVAILABLE` (which is a different `SigningResult`
   in Core, mapped to a different RPC error code) from
   `SIGNING_FAILED`.
3. There is no precondition check that `Cstruct.length privkey = 32`
   in the OCaml caller; the C stub is assumed to bounds-check.

**File:** `lib/rpc.ml:2847-2851, 2897-2903`.

**Core ref:** `bitcoin-core/src/key.cpp::CKey::SignCompact`
(returns bool, not throws).

**Impact:** error-class collapse (all sign failures look the same in
the wire response); cross-impl rpc-conformance harness sees one
error code where Core emits two.

---

## BUG-17 (P1) — `verifymessage` accepts ZERO-byte signatures (returns `false`); Core returns `ERR_MALFORMED_SIGNATURE` (error -3)

**Severity:** P1. camlcoin's `rpc.ml:2924`:

```ocaml
if Cstruct.length sig_cs <> 65 then Ok (`Bool false)
```

A `Base64.decode ""` returns `Ok ""` (empty string), which yields
`Cstruct.length = 0`, falling into this branch with `false`. Similarly
a 1-byte signature, 64-byte signature (one byte short), etc., all
return `false` — equivalent to Core's `ERR_PUBKEY_NOT_RECOVERED` →
`false` path. This is actually correct for `< 65` byte cases:

Wait — re-reading Core. `DecodeBase64` returns the bytes; `RecoverCompact`
checks `signature.size() != 65` and returns `false` →
`ERR_PUBKEY_NOT_RECOVERED` → `false`. So Core ALSO returns `false`, not
error, for short sig. **This is NOT a bug** — listing for completeness
to clear the false-positive.

(Strikethrough: not a bug. Keeping the slot to maintain numbering and
to record the false-positive analysis as part of the audit trail. The
slot below renumbers the real BUG-17.)

---

## BUG-17 (P1) — `Base64.decode` non-strict; accepts padding-relaxed input that Core rejects via `DecodeBase64`

**Severity:** P1. Bitcoin Core's `DecodeBase64` returns `std::nullopt`
on non-canonical base64 (wrong padding, invalid chars). The OCaml
`Base64.decode` library (from `ocaml-base64` package) by default is
also strict, but the camlcoin caller at `rpc.ml:2920`:

```ocaml
(match Base64.decode sig_b64 with
 | Error _ -> Error "Malformed base64 encoding"
 | Ok sig_str -> ...
```

passes `sig_b64` directly without normalising URL-safe vs standard
alphabet. Core's `DecodeBase64` uses the standard alphabet only.
A signature emitted by a URL-safe-base64 producer (`-_` instead of
`+/`) would decode in OCaml's strict mode as error, matching Core
behaviour. But if any consumer uses the `~alphabet:url_safe_alphabet`
option (no caller in camlcoin does today, but the API surface is
wider than Core's), the decode-allowed set drifts.

Verification: `Base64.decode` without alphabet override uses
`Base64.default_alphabet` which IS standard. So today the behaviour
matches. **Not a bug** in current state — recorded for forward
audit completeness.

(Same numbering convention — keeping slot. Real BUG-17 below.)

---

## BUG-17 (P1) — No round-trip parity test: signature produced by camlcoin's `signmessage` not cross-validated against any other impl in the test suite

**Severity:** P1 ("cross-impl conformance gap"). `test/test_rpc.ml:1414-1495`
covers:
- `test_signmessage_roundtrip`: camlcoin signs, camlcoin verifies. PASS.
- `test_verifymessage_wrong_message`: tampered msg → false. PASS.
- `test_verifymessage_invalid_address`: invalid addr → Error. PASS.
- `test_verifymessage_malformed_b64`: bad b64 → Error. PASS.
- `test_signmessage_invalid_wif`: bad WIF → Error. PASS.

The "round-trip" tests are self-consistent — they only prove that
camlcoin sign + camlcoin verify agree. They do NOT prove that:
1. A signature emitted by camlcoin verifies under Core
   (`bitcoin-cli verifymessage <addr> <sig> <msg>`).
2. A signature emitted by Core verifies under camlcoin.
3. A signature emitted by Electrum (which signs slightly differently
   for SegWit addresses) is correctly rejected (it should error,
   not silently fail).
4. A test vector from the BIP-322 spec round-trips correctly (would
   fail since BIP-322 is absent — BUG-12).

The cross-impl test-suite (`hashhog/test-suite/`) does have a
message-signing test (verifying camlcoin against `bitcoin-core`), but
the camlcoin in-tree tests do not run a fixed-vector check against
Core's known outputs. Fixed-vector regression for signmessage would
have caught BUG-4 (WIF-sniff bypass) earlier.

**File:** `test/test_rpc.ml:1414-1495`.

**Impact:** regression-safety gap; future refactors of the message-hash
framing or compact-sig recovery have no cross-impl pinning.

---

## BUG-18 (P1) — `help` text lists `signmessage \"address\"` only, not the actual WIF-sniff fallback shape `signmessage \"WIF\"` that the code accepts

**Severity:** P1. `rpc.ml:7517-7519`:

```
"signmessage \"address\" \"message\"";
"signmessagewithprivkey \"privkey\" \"message\"";
"verifymessage \"address\" \"signature\" \"message\"";
```

Per BUG-4, the actual `signmessage` handler accepts EITHER `[address,
message]` OR `[WIF, message]` (via the WIF-first sniff). The help text
documents only the first form. An operator reading `help signmessage`
has no signal that the legacy WIF form is accepted; an operator who
relies on the help text doesn't discover the BUG-4 security gap.

**File:** `lib/rpc.ml:7517`.

**Impact:** help/UX honesty gap; tooling that reflects the help-text
shape (e.g., `bitcoin-cli` argument hints) gets a misleading signature.

---

## BUG-19 (P1) — `address.ml:address_of_string` `WitnessUnknown v` branch creates an address with no message-sign support; `signmessage` accepts it via WIF-sniff, then can't verify

**Severity:** P1. `address.ml:358-359, 378-379`:

```ocaml
| v, len, Bech32m when v >= 2 && v <= 16 && len >= 2 && len <= 40 ->
  Ok { addr_type = WitnessUnknown v; hash; network }
```

`signmessage` flow with a `WitnessUnknown` address:
1. WIF-sniff: address-string doesn't parse as WIF → fall through.
2. `address_of_string`: succeeds with `addr_type = WitnessUnknown v`.
3. `addr.addr_type <> P2PKH` → `Error "Address does not refer to key"`.

OK on signmessage. But `verifymessage`:
1. `address_of_string` succeeds.
2. Match on `addr_type`: only `P2PKH` is handled; `WitnessUnknown`
   falls into `_ -> Error "Address does not refer to a key (only
   P2PKH supported)"`.

Error code mapped to `rpc_invalid_address` (-5); Core would map this
to `RPC_TYPE_ERROR` (-3) via the same `ERR_ADDRESS_NO_KEY` path. So
the future witness-version v2..v16 message-signing schemes (BIP-322-
adjacent) get the wrong error class in camlcoin.

**File:** `lib/rpc.ml:2918, 2933` (verifymessage); 8695-8698 (dispatch).

**Impact:** forward-compat error-class mapping wrong for future BIPs.

---

## BUG-20 (P1) — RPC argument count error message disagrees with Core's "Wrong number of params" style

**Severity:** P1 ("wire-string parity slippage", same fleet shape as
BUG-7). camlcoin emits `"Invalid parameters: expected [\"address\",
\"message\"]"` (rpc.ml:2904-2905). Core's RPC layer raises
`RPC_INVALID_PARAMETER` with the message format produced by
`JSONRPCError` — typically:

- "Wrong number of params"
- "Expected type %s for %s parameter" (when types disagree)
- "Address" / "Signature" / "Message" must be of type string (per
  `RPCArg`-driven type checks)

The camlcoin string is more user-friendly but is not a Core string.
Tools that scrape the error message text break.

**File:** `lib/rpc.ml:2852, 2904-2905, 2934-2935`.

**Impact:** wire-string parity gap; cross-impl monitoring.

---

## BUG-21 (P0-SEC) — `signmessagewithprivkey` WIF discard pattern: network field deliberately ignored (`let (_, _, _network) = ...`); enables cross-network signing oracle

**Severity:** P0-SEC. `rpc.ml:2843-2845`:

```ocaml
(match Address.wif_decode wif with
 | Error e -> Error (Printf.sprintf "Invalid private key: %s" e)
 | Ok (privkey, compressed, _network) ->
   let msg_hash = Crypto.message_hash message in
```

The `_network` underscore-prefix is an explicit "discard this, I don't
care" annotation. Combined with BUG-4 (signmessage WIF-sniff routes
here) and BUG-8 (no network cross-check), this is the explicit
mechanism by which a regtest daemon happily signs a message with a
mainnet WIF and emits a signature that verifies against mainnet
addresses on a different node.

Bitcoin Core's `signmessagewithprivkey` (`rpc/signmessage.cpp:83-90`):

```cpp
std::string strPrivkey = request.params[0].get_str();
...
CKey key = DecodeSecret(strPrivkey);
if (!key.IsValid()) {
    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");
}
```

`DecodeSecret` is chainparams-aware — it accepts WIFs whose network
prefix matches the active chainparams; mainnet WIFs on a regtest node
are rejected as invalid. camlcoin's path accepts everything.

**File:** `lib/rpc.ml:2845`.

**Core ref:** `bitcoin-core/src/key_io.cpp::DecodeSecret`.

**Impact:**
- Regtest daemon = mainnet-WIF signing oracle (key-extraction or
  signature-fraud primitive).
- Cross-network test scaffolding accidentally signs mainnet against
  regtest cookies.
- Fleet pattern: 4th distinct camlcoin "underscore-discard discards
  a security-relevant field" instance per cumulative tracking.

---

## BUG-22 (P1) — `address.address` record stores network tag but `find_by_address` ignores it (string-only compare)

**Severity:** P1. `address.ml:14-19` (address record):

```ocaml
type address = {
  addr_type : address_type;
  hash : Cstruct.t;
  network : network;
}
```

`wallet.ml:634-637`:

```ocaml
let find_by_address (w : t) (addr_str : string) : key_pair option =
  List.find_opt (fun kp ->
    Address.address_to_string kp.address = addr_str
  ) w.keys
```

The wallet stores `kp.address` (which includes the network tag).
`find_by_address` round-trips through `address_to_string`, which embeds
the network into the prefix (e.g., `1...` vs `m...`). String compare
THEN works correctly because the prefix differs across networks. But:

1. The `address` record's `network` field is dead at this call-site
   (it's recomputed by the round-trip through `address_to_string`
   instead of being read directly). Classic "dead-data plumbing"
   (fleet pattern, ~12th distinct camlcoin instance).
2. Two different addresses that round-trip to the same string would
   be confused — fortunately none exist in practice.

**File:** `lib/wallet.ml:634-637`.

**Impact:** dead-data plumbing in a security-relevant lookup path;
cleanup candidate.

---

## Summary

**Bug count:** 22 (BUG-1 through BUG-22; BUG-17 had two false-positive
slots cleared during analysis and renumbered to the real BUG-17).

**Severity distribution:**
- **P0-SEC:** 4 (BUG-3 locked-wallet bypass, BUG-4 WIF-sniff bypass,
  BUG-8 network cross-check, BUG-21 WIF network discard)
- **P1:** 18 (BUG-1, BUG-2, BUG-5, BUG-6, BUG-7, BUG-9, BUG-10,
  BUG-11, BUG-12, BUG-13, BUG-14, BUG-15, BUG-16, BUG-17, BUG-18,
  BUG-19, BUG-20, BUG-22)

Total: 4 + 18 = 22. ✓

**Fleet patterns confirmed:**
- **13-CONSECUTIVE-QUAD camlcoin pipeline-drift preserved** (BUG-2 + BUG-6):
  three distinct wallet-lookup pipelines in the RPC layer, new W158
  handler chose none-of-the-canonical-helpers; 13th wave instance of
  the pattern (W143→W157→W158).
- **"comment-as-confession" 14th distinct camlcoin instance** (BUG-5):
  comment claims fall-through behavior; next line implements hard reject.
- **"dead-code in consensus-adjacent path"** (BUG-5): match block with
  both arms returning `()`.
- **"reject-string wire-parity slippage"** (BUG-7, BUG-18, BUG-20):
  3 distinct error-message divergences from Core in this audit alone.
- **"underscore-discard discards a security-relevant field"** (BUG-21):
  `_network` field deliberately ignored; 4th camlcoin instance.
- **"dead-data plumbing"** (BUG-22): `address.network` field carried
  but ignored at the use-site; ~12th camlcoin instance.
- **"defined-but-not-wired"** (BUG-2 + BUG-3): `get_wallet_for_request`
  helper and `Wallet.is_locked` helper both exist and are used
  elsewhere; neither is called by this handler.
- **"wallet-encrypt sentinel skipped"** (BUG-3): same architectural
  shape as W140 TimingResistantEqual fleet-wide gap (existing
  primitive, missing call-site).
- **"forward-looking BIP gap"** (BUG-11 BIP-137, BUG-12 BIP-322): two
  BIPs unsupported; Core also missing BIP-322, but ecosystem
  convergence on BIP-322 Simple mode makes this a 10/10 fleet-wide
  finding likely.
- **"cross-network signing oracle"** (BUG-8, BUG-21): regtest daemon
  becomes a mainnet-WIF signing oracle if the WIF reaches the RPC;
  first message-sign cross-network instance in fleet tracking.

**Top three findings:**

1. **BUG-3 (P0-SEC locked-wallet bypass)** — `handle_signmessage` skips
   the `Wallet.is_locked` check that Core enforces via
   `EnsureWalletIsUnlocked`. Combined with the fact that camlcoin's
   wallet stores cleartext private keys in `w.keys` after a single
   unlock, an encrypted+locked wallet can be made to sign arbitrary
   messages by any RPC caller holding the cookie. Same "skipped
   sentinel" class as W140's fleet-wide TimingResistantEqual gap
   (10/10 impls) but on a different primitive. The `Wallet.is_locked`
   helper exists and is called elsewhere — pure dead-helper-at-call-
   site.

2. **BUG-4 + BUG-8 + BUG-21 cluster (P0-SEC cross-network signing
   oracle)** — `handle_signmessage` sniffs the first argument as WIF
   and silently routes to `handle_signmessagewithprivkey`, which
   discards the WIF's network field (`let (_, _, _network) = ...`).
   `Address.address_of_string` is network-agnostic everywhere. The
   composite effect: an attacker who controls one daemon's RPC cookie
   (or a regtest test-harness operator) can sign messages with ANY
   private key on ANY network, producing signatures that verify on
   other networks. The mainnet-WIF-on-regtest case is the canonical
   key-extraction primitive. Three bugs forming one architectural
   gap: there is no `assert(network_matches(addr, ctx.network))`
   anywhere on this path.

3. **BUG-12 (P1) BIP-322 entirely absent + BUG-11 BIP-137 entirely
   absent** — message signing for the dominant SegWit address types
   (P2WPKH, P2SH-P2WPKH, P2TR) is impossible. Core also has not yet
   implemented BIP-322, but the ecosystem (Sparrow, Specter,
   BitcoinJS, Mempool.space) has converged on BIP-322 Simple mode for
   SegWit signing. This is likely a 10/10 fleet-wide finding — first
   wave to audit it. Forward-looking: when Core lands BIP-322,
   camlcoin needs full virtual-tx + sighash plumbing, a non-trivial
   refactor.
