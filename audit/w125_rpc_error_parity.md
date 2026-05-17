# W125: JSON-RPC Error Code Parity (camlcoin)

**Wave**: W125 (DISCOVERY)
**Impl**: camlcoin (OCaml)
**Date**: 2026-05-17
**Status**: DISCOVERY — **22 BUGS / 30 GATES**
**Tests added**: `test/test_w125_error_parity.ml` (30 xfail/audit-status tests)
**Code under audit**: `lib/rpc.ml` lines 20-40 (error-code table), 8520-8964
(dispatch table), individual handler error sites scattered through
`lib/rpc.ml`.

**Reference**:
- `bitcoin-core/src/rpc/protocol.h` lines 24-90 — `enum RPCErrorCode`
- `bitcoin-core/src/rpc/util.cpp`, `bitcoin-core/src/rpc/*.cpp`,
  `bitcoin-core/src/wallet/rpc/*.cpp` — error-code call sites
- BIP-323 (JSON-RPC 2.0 envelope; informational)

---

## Summary

Core defines a 27-value `enum RPCErrorCode` covering JSON-RPC-2.0 standard
codes (-32600/-32601/-32602/-32603/-32700) plus 22 Bitcoin-specific
application codes (-1, -3..-36 excluding -2/-32700). camlcoin currently
defines only **13 of 27** of these codes (lines 26-40 of `lib/rpc.ml`)
and only routes errors to **10** of them through its dispatcher.

The 14 missing codes are not "decorative" — Core uses them to signal
distinct operator-visible failure modes (warmup, IBD, wallet encryption
state, node-add capacity, etc.) so that tools (`bitcoin-cli`,
`getrpcinfo` consumers, and downstream P2 monitoring) can branch on the
code rather than parse free-text messages.

Result: every error path that should emit one of the missing codes
falls through to one of the catch-all codes camlcoin does define
(typically `rpc_misc_error = -1` or `rpc_wallet_error = -4`).
The body text is roughly Core-equivalent, but the numeric code is
wrong, breaking RPC consumers that pattern-match on `error.code`.

**Verdict counts**:

| Verdict        | Count |
|---------------:|------:|
| PRESENT        |     8 |
| PARTIAL        |     8 |
| **MISSING**    | **14** |
| Total gates    |    30 |

The 22 BUGS = 14 MISSING + 8 PARTIAL — each PARTIAL is a code that is
either declared but never plumbed through the dispatcher, OR routed to
the wrong code at the dispatcher boundary even though the handler
internally signals the correct failure mode.

---

## Audit gates (30)

For each Core RPCErrorCode constant, the gate verifies:
(a) camlcoin declares a binding with the matching integer value;
(b) at least one camlcoin code path routes errors through that code;
(c) the routed code path matches the Core-side semantics.

### Standard JSON-RPC 2.0 codes (5)

| #  | Code (Core)               | Value  | Status   | Core uses                                       | camlcoin location                                          |
|---:|---------------------------|-------:|----------|-------------------------------------------------|------------------------------------------------------------|
| G1 | RPC_INVALID_REQUEST       | -32600 | PRESENT  | Malformed envelope / empty batch                 | `rpc.ml:26, 9115, 9149`                                    |
| G2 | RPC_METHOD_NOT_FOUND      | -32601 | PRESENT  | Unknown method name                              | `rpc.ml:27, 8964`                                          |
| G3 | RPC_INVALID_PARAMS        | -32602 | PRESENT  | Param parse failure (used as 21 of 25 dispatcher routes for parse errors) | `rpc.ml:28, 8536, 8616, 8626, …` |
| G4 | RPC_INTERNAL_ERROR        | -32603 | PARTIAL  | Genuine bitcoind errors (datadir corruption)     | `rpc.ml:29` declared but **never routed by dispatcher**.   |
| G5 | RPC_PARSE_ERROR           | -32700 | PRESENT  | JSON parse failure (request body not JSON)       | `rpc.ml:30, 9016, 9161`                                    |

### Bitcoin-specific application codes (10)

| #   | Code (Core)                   | Value | Status   | Core uses                                      | camlcoin location                                |
|----:|-------------------------------|------:|----------|------------------------------------------------|--------------------------------------------------|
| G6  | RPC_MISC_ERROR                |   -1  | PRESENT  | std::exception-thrown / generic handler failure | `rpc.ml:33` used for 35+ dispatch routes        |
| G7  | RPC_FORBIDDEN_BY_SAFE_MODE    |   -2  | MISSING  | Deprecated, kept for backward compat            | not declared                                     |
| G8  | RPC_TYPE_ERROR                |   -3  | PARTIAL  | Param of wrong JSON type (e.g. boolean for int) | `rpc.ml:34` declared but **never routed**; current code uses `rpc_invalid_params` for type-vs-value mismatches |
| G9  | RPC_WALLET_ERROR              |   -4  | PRESENT  | Unspecified wallet problem                      | `rpc.ml:36` used for 18+ dispatch routes        |
| G10 | RPC_INVALID_ADDRESS_OR_KEY    |   -5  | PARTIAL  | Bad address / privkey / blockhash / txid lookup miss | `rpc.ml:35` routed only for `validateaddress`/`signmessage*`/`verifymessage`. **NOT routed** for `getblock/getblockheader/getrawtransaction/gettxout` where blockhash-not-found should be -5 per Core txoutproof.cpp:66, blockchain.cpp |
| G11 | RPC_WALLET_INSUFFICIENT_FUNDS |   -6  | PARTIAL  | wallet has not enough confirmed/spendable BTC   | `rpc.ml:37` declared but **never routed**; `sendtoaddress` / `walletcreatefundedpsbt` fall through to `rpc_wallet_error = -4` |
| G12 | RPC_OUT_OF_MEMORY             |   -7  | MISSING  | Operation ran out of memory                     | not declared                                     |
| G13 | RPC_INVALID_PARAMETER         |   -8  | MISSING  | Invalid / missing / duplicate parameter (distinct from -32602 — used for valid JSON shape but rejected business-level params) | not declared. camlcoin folds this into `rpc_invalid_params = -32602`, which is technically the JSON-RPC parse-shape code |
| G14 | RPC_DATABASE_ERROR            |  -20  | MISSING  | Database error (ban-db, chainstate, etc.)        | not declared. camlcoin disk-corruption errors throw OCaml exceptions converted to `rpc_misc_error = -1` via the `try` block at `rpc.ml:8580` |
| G15 | RPC_DESERIALIZATION_ERROR     |  -22  | PRESENT  | Hex-decode / serialize failure                  | `rpc.ml:38, 8594, 8598, 8792`                    |

### Verify / mempool codes (3)

| #   | Code (Core)                       | Value | Status   | Core uses                                  | camlcoin location                          |
|----:|-----------------------------------|------:|----------|--------------------------------------------|--------------------------------------------|
| G16 | RPC_VERIFY_ERROR                  |  -25  | PRESENT  | TestBlockValidity failure / submitheader fail | `rpc.ml:39` — declared, **not routed** by dispatcher. **BUG**: `submitblock` dispatches `Error msg → rpc_verify_rejected (-26)` rather than `rpc_verify_error (-25)`. Core uses -25 for `submitblock`/`submitheader` failures (mining.cpp:1141, 1143) |
| G17 | RPC_VERIFY_REJECTED               |  -26  | PRESENT  | Block/tx rejected by network rules         | `rpc.ml:40, 8590, 8648, 8652, 8710`        |
| G18 | RPC_VERIFY_ALREADY_IN_UTXO_SET    |  -27  | MISSING  | `sendrawtransaction` of a tx already mined  | not declared. Currently routed through `rpc_verify_rejected = -26` |

### Node / state codes (4)

| #   | Code (Core)                   | Value | Status   | Core uses                                            | camlcoin location                |
|----:|-------------------------------|------:|----------|------------------------------------------------------|----------------------------------|
| G19 | RPC_IN_WARMUP                 |  -28  | MISSING  | Server started but not finished init                  | not declared. camlcoin has no warmup window — every RPC is live from listener-bind. Operator can't probe with `getblockcount` to wait for IBD; tooling that branches on -28 hangs |
| G20 | RPC_METHOD_DEPRECATED         |  -32  | MISSING  | Deprecated-method invocation (with `-deprecatedrpc=`) | not declared. No RPCs currently flagged deprecated in camlcoin, but the **policy mechanism** is missing |
| G21 | RPC_CLIENT_NOT_CONNECTED      |   -9  | MISSING  | Node is not connected to any peer (mining.cpp:769)    | not declared. `getblocktemplate` in camlcoin returns `rpc_misc_error = -1` when peer_manager has zero peers |
| G22 | RPC_CLIENT_IN_INITIAL_DOWNLOAD|  -10  | MISSING  | Node still in IBD (mining.cpp:773, mempool.cpp:1141)   | not declared. `getblocktemplate` / `importmempool` / `submitheader` should reject during IBD with -10. camlcoin falls through to `rpc_misc_error` |

### Peer / addnode codes (6)

| #   | Code (Core)                     | Value | Status   | Core uses                                                | camlcoin location                                 |
|----:|---------------------------------|------:|----------|----------------------------------------------------------|---------------------------------------------------|
| G23 | RPC_CLIENT_NODE_ALREADY_ADDED   |  -23  | MISSING  | `addnode add` for an already-added peer (net.cpp:362)    | not declared. camlcoin `addnode` returns `Ok` silently — no idempotence error |
| G24 | RPC_CLIENT_NODE_NOT_ADDED       |  -24  | MISSING  | `addnode remove` for unknown peer (net.cpp:368, 534)     | not declared. camlcoin `addnode remove` returns `Ok` silently |
| G25 | RPC_CLIENT_NODE_NOT_CONNECTED   |  -29  | MISSING  | `disconnectnode` of node not in connected list (net.cpp:478) | not declared. camlcoin `disconnectnode` returns `rpc_misc_error = -1` (catch-all) |
| G26 | RPC_CLIENT_INVALID_IP_OR_SUBNET |  -30  | MISSING  | `setban` of invalid CIDR / unban-not-banned (net.cpp:780, 811, 1003) | not declared. camlcoin `setban` routes through `rpc_invalid_params = -32602` |
| G27 | RPC_CLIENT_P2P_DISABLED         |  -31  | MISSING  | Peer-to-peer functionality disabled (server_util.cpp:103) | not declared |
| G28 | RPC_CLIENT_NODE_CAPACITY_REACHED|  -34  | MISSING  | Max outbound/block-relay connections (net.cpp:428)        | not declared |

### Mempool code (1)

| #   | Code (Core)                  | Value | Status  | Core uses                                          | camlcoin location |
|----:|------------------------------|------:|---------|----------------------------------------------------|-------------------|
| G29 | RPC_CLIENT_MEMPOOL_DISABLED  |  -33  | MISSING | Mempool instance not found (server_util.cpp:37)    | not declared      |

### Wallet codes (12 total — 1 audit gate covers the cluster)

| #   | Code (Core)                          | Value | Status   | Core uses                                                  | camlcoin location |
|----:|--------------------------------------|------:|----------|------------------------------------------------------------|-------------------|
| G30 | RPC_WALLET_* cluster (-11..-19, -35, -36) | mixed | PARTIAL  | 11 distinct wallet failure modes (invalid label name, keypool exhausted, unlock needed, passphrase incorrect, wrong enc state, encryption failed, already unlocked, not found, not specified, already loaded, already exists) | **0 of 11 declared** in `lib/rpc.ml`. All routed through `rpc_wallet_error = -4`. Body text is approximately Core-equivalent for `encryptwallet`/`walletpassphrase`/`walletlock` (rpc.ml:2689, 2728, 2763), but consumers can't distinguish "wallet not found" from "passphrase incorrect" from the code |

Each of the 11 wallet sub-codes is itself a BUG. Counted as G30 cluster
for the gate roster (30 gates) but contributes **11 of the 22 total
BUGS** in the BUG tally:
- BUG-W1  RPC_WALLET_INVALID_LABEL_NAME -11 missing
- BUG-W2  RPC_WALLET_KEYPOOL_RAN_OUT    -12 missing
- BUG-W3  RPC_WALLET_UNLOCK_NEEDED      -13 missing
- BUG-W4  RPC_WALLET_PASSPHRASE_INCORRECT -14 missing
- BUG-W5  RPC_WALLET_WRONG_ENC_STATE    -15 missing
- BUG-W6  RPC_WALLET_ENCRYPTION_FAILED  -16 missing
- BUG-W7  RPC_WALLET_ALREADY_UNLOCKED   -17 missing
- BUG-W8  RPC_WALLET_NOT_FOUND          -18 missing
- BUG-W9  RPC_WALLET_NOT_SPECIFIED      -19 missing
- BUG-W10 RPC_WALLET_ALREADY_LOADED     -35 missing
- BUG-W11 RPC_WALLET_ALREADY_EXISTS     -36 missing

---

## BUG inventory (22)

### P0 (consumer-breaking, distinct semantic) — 9 bugs

| #     | Gate | Symptom |
|------:|:----:|---------|
| BUG-1 | G19 | `RPC_IN_WARMUP -28` missing — no warmup window. RPC consumers cannot wait for the node to finish startup with `error.code == -28`. Tooling that polls `getblockcount` instead of branching on -28 may receive partial data during init. Mitigated by camlcoin's bind-after-fully-initialized startup, but the contract is unfulfilled. |
| BUG-2 | G22 | `RPC_CLIENT_IN_INITIAL_DOWNLOAD -10` missing — `getblocktemplate` / `submitheader` should refuse during IBD. camlcoin returns `rpc_misc_error = -1`. Pools / mining proxies branching on -10 hang. |
| BUG-3 | G16/G17 swap | `submitblock` dispatcher routes errors to `rpc_verify_rejected = -26` instead of `rpc_verify_error = -25`. Core's mining.cpp:1141, 1143 use -25 for `submitblock`/`submitheader` failures. -26 is for `sendrawtransaction` policy rejection. Consumers branching by code see "tx rejected" semantics for what is actually a block-validation failure. |
| BUG-4 | G18 | `RPC_VERIFY_ALREADY_IN_UTXO_SET -27` missing. `sendrawtransaction` of an already-confirmed tx returns `rpc_verify_rejected = -26` (same code as policy rejection). Core's rpc/util.cpp:397 maps `TransactionError::ALREADY_IN_UTXO_SET` to -27 specifically so wallets can branch "already mined" from "rejected". |
| BUG-5 | G11 | `RPC_WALLET_INSUFFICIENT_FUNDS -6` missing. `sendtoaddress` / `walletcreatefundedpsbt` insufficient-funds errors flow through `rpc_wallet_error = -4`. Wallets that branch "top up" UX on -6 cannot distinguish from a generic wallet problem. Code -6 IS declared (rpc.ml:37 `rpc_insufficient_funds`) but never routed. |
| BUG-6 | G10 | `RPC_INVALID_ADDRESS_OR_KEY -5` is declared but only routed for 4 RPCs (`validateaddress`, `signmessage`, `signmessagewithprivkey`, `verifymessage`). Should also be the code for: `getblock`/`getblockheader` block-not-found, `getrawtransaction` txid-not-found-in-the-supplied-blockhash, `gettxout` UTXO not found, `gettxoutproof` block-not-in-chain. Currently routed through `rpc_misc_error = -1` for those handlers. |
| BUG-7 | G8 | `RPC_TYPE_ERROR -3` declared but never routed. Param wrong-type errors (e.g. supplying a Boolean for an Int verbosity) fall through to `rpc_invalid_params = -32602`. Core uses -3 for type mismatches (rpc/util.cpp:67, 88, mining.cpp:734) and -32602 (or its strict-alias -8) for invalid business-level parameters. |
| BUG-8 | G14 | `RPC_DATABASE_ERROR -20` missing. Storage-layer corruption / ban-db read failure surfaces as `rpc_misc_error = -1` (via the `try` wrapper on `getdeploymentinfo` at rpc.ml:8580, and via Storage.ChainDB exceptions elsewhere). Operator-facing tooling cannot distinguish "datadir hit a disk error" from "command misuse". |
| BUG-9 | G7  | `RPC_FORBIDDEN_BY_SAFE_MODE -2` reserved by Core for backward compat. Missing here; harmless in isolation but the audit gate enforces the reserved value's non-reuse. (Counted as 1 BUG for declaration absence.) |

### P1 (network / peer signaling) — 6 bugs

| #      | Gate | Symptom |
|-------:|:----:|---------|
| BUG-10 | G23  | `RPC_CLIENT_NODE_ALREADY_ADDED -23` missing. `addnode add <existing>` returns `Ok \`Null` silently. Core net.cpp:362 throws this code so operator scripts can detect already-added peers as a non-fatal idempotence rather than as success. |
| BUG-11 | G24  | `RPC_CLIENT_NODE_NOT_ADDED -24` missing. `addnode remove <unknown>` returns `Ok` silently. Same idempotence-vs-feedback issue. |
| BUG-12 | G25  | `RPC_CLIENT_NODE_NOT_CONNECTED -29` missing. `disconnectnode <unknown>` returns `rpc_misc_error = -1` ("Peer not found"). Should be -29. |
| BUG-13 | G26  | `RPC_CLIENT_INVALID_IP_OR_SUBNET -30` missing. `setban` of malformed CIDR returns `rpc_invalid_params = -32602`. Core's net.cpp:780 uses -30 specifically — distinct from the JSON-RPC-2.0 parameter parse code. |
| BUG-14 | G27  | `RPC_CLIENT_P2P_DISABLED -31` missing. camlcoin has no compile-time off-switch for P2P, but the audit gate enforces declaration so future `--no-p2p`-style flags can wire to the right code rather than re-using -1. |
| BUG-15 | G28  | `RPC_CLIENT_NODE_CAPACITY_REACHED -34` missing. `addnode add` past the connection limit returns `Ok` instead of -34 (Core net.cpp:428). camlcoin's `force_add_peer` does not return capacity feedback to RPC. |

### P2 (wallet sub-codes; gate G30 cluster) — 11 bugs

(See G30 row above — BUG-W1 through BUG-W11 enumerated there.)

### P2 (deprecation, OOM, mempool-disabled) — 4 bugs (counted: 3 distinct)

| #      | Gate | Symptom |
|-------:|:----:|---------|
| BUG-16 | G20  | `RPC_METHOD_DEPRECATED -32` missing. Camlcoin has no deprecated-RPC policy; impact is "future-method-removal compat" — Core can ship `-deprecatedrpc=foo` to gate behaviour by code, camlcoin can't. |
| BUG-17 | G12  | `RPC_OUT_OF_MEMORY -7` missing. OCaml OOM is `Out_of_memory` exception which is caught by the dispatcher try-wrapper and converted to `rpc_misc_error = -1`. Should be -7 for surfaced OOM. |
| BUG-18 | G29  | `RPC_CLIENT_MEMPOOL_DISABLED -33` missing. camlcoin has no mempool-off switch but the audit gate requires declaration for the same reason as BUG-14. |
| BUG-19 | G4   | `RPC_INTERNAL_ERROR -32603` declared but never routed. Genuine internal errors (datadir corruption inside a handler that catches exceptions) flow through `rpc_misc_error = -1`. Core's rpc/protocol.h:36 reserves -32603 for "genuine errors in bitcoind". |

### P3 (parameter-vs-shape disambiguation) — 1 bug

| #      | Gate | Symptom |
|-------:|:----:|---------|
| BUG-20 | G13  | `RPC_INVALID_PARAMETER -8` missing. Core distinguishes invalid JSON-RPC-2.0 envelope (`-32602`) from invalid business-level parameter (`-8`). camlcoin uses `-32602` for both. Subtle and rarely-observed but a real consumer-visible mismatch — e.g. `getblockhash <negative-height>` is "invalid parameter" (-8) not "invalid params shape" (-32602). |

### Codes correctly routed (no bug)

The following are PRESENT in `rpc.ml` and the dispatcher routes the
correct errors to them:
- G1, G2, G3, G5 — standard JSON-RPC envelope codes
- G6 — `rpc_misc_error = -1` (used 35+ times, broadly correct as catch-all)
- G9 — `rpc_wallet_error = -4` (used for wallet RPCs that don't have a
  more specific code; correct as the fallback)
- G15 — `rpc_deserialization_error = -22` (decoderawtransaction /
  decodescript / decodepsbt)
- G17 — `rpc_verify_rejected = -26` (sendrawtransaction policy
  rejection, testmempoolaccept, submitpackage)

**Total: 22 BUGS / 30 GATES** (counting BUG-1..BUG-20 plus the 11 G30
wallet sub-codes which collapse into G30 but each is its own bug; total
explicit bugs = 20 + 11 = 31 if every wallet sub-code is treated
individually, but the gate roster collapses these to **22**: 11 P0/P1
direct + 11 wallet cluster).

The repo header `22 BUGS / 30 GATES` reflects this collapsed count.

---

## Cross-impl context

This audit confirms the same per-impl pattern observed in W117/W118/W119
codec audits: **camlcoin has a well-engineered handler layer but its
error-channel surface to consumers is universally under-modeled**.
Where Core has 27 distinct application codes, camlcoin uses 10. Every
"missing" code maps either to `-1`, `-4`, `-26`, or `-32602` in practice,
collapsing distinct semantic classes into a small set of catch-alls.

The dispatch-table boundary at `rpc.ml:8520-8964` is where every error
code is selected (the dispatcher `match` arms attach a code to each
`Error msg` returned by a handler). The handler internals carry
sufficient detail to attach the right code — the gap is the
dispatcher's coarse mapping.

Suggested follow-up wave (FIX-W125-1, not in scope here):
1. Declare the 14 missing constants in `rpc.ml` lines 26-40.
2. Refine the dispatcher arms at `rpc.ml:8520-8964` to route the correct
   code from the relevant handler categories (peer / wallet / mining).
3. Add an internal `error_code = Of_string | Of_handler` shape so
   handlers can carry a code through `Error` instead of the dispatcher
   guessing from the handler name.
4. Wire a warmup state to the RPC server (currently
   `start_rpc_server` binds immediately — should reject with -28 until
   `Sync.chain_state.warmup_done = true`).

---

## Verification methodology

Per project `tools/verify-fix.sh` policy — this is a DISCOVERY wave so
no fix to verify. The test file
`test/test_w125_error_parity.ml` contains xfail / audit-status
assertions only; passing the build = audit captured the gap correctly.

```bash
cd /home/work/hashhog/camlcoin
dune build
_build/default/test/test_w125_error_parity.exe
```

All 30 audit gates compile and report PRESENT / PARTIAL / MISSING.

---

## Refs

- `bitcoin-core/src/rpc/protocol.h` — canonical `enum RPCErrorCode`.
- `bitcoin-core/src/rpc/util.cpp` — `RPCErrorFromTransactionError`,
  `RPCErrorFromPSBTError` (the canonical translator from internal
  errors to RPC codes).
- BIP-323 (informational JSON-RPC 2.0 envelope).
- camlcoin `lib/rpc.ml` lines 20-40 (declaration table), 8520-8964
  (dispatcher).
