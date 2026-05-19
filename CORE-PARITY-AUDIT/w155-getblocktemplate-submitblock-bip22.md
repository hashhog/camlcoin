
# W155 — getblocktemplate + submitblock + BIP-22/BIP-23 (camlcoin)

**Wave:** W155 — BIP-22 / BIP-23 / BIP-9 / BIP-145 RPC surface:
`getblocktemplate` (mode = template | proposal), `submitblock`,
`submitheader`, `getmininginfo`, `getnetworkhashps`, `prioritisetransaction`,
`getprioritisedtransactions`, `generate*` family. Specifically: the JSON
wire shape returned to miner clients (`coinbasevalue` NUM, per-tx
`txid`/`hash`/`depends`/`fee`/`sigops`/`weight`, `longpollid` semantics,
`mintime`/`curtime`, `mutable[]`, `rules[]`, `vbavailable{}`,
`vbrequired`, `noncerange`, `sigoplimit`, `sizelimit`, `weightlimit`,
`coinbaseaux`, `signet_challenge`, `default_witness_commitment`); the
BIP-22 result-token map (`BIP22ValidationResult` → "duplicate" /
"duplicate-invalid" / "duplicate-inconclusive" / "inconclusive" /
`<reject-reason>`); BIP-23 proposal mode; BIP-9 client-rule contract
("must include `segwit` in rules", signet rule); the
`UpdateUncommittedBlockStructures` + `RegisterSharedValidationInterface`
+ `StateCatcher` plumbing on `submitblock`; the IBD / connectivity
preconditions on `getblocktemplate` (`isInitialBlockDownload` +
`connman.GetNodeCount(Both) == 0` gates); the longpoll loop
(`waitTipChanged` + `GetTransactionsUpdated`).

**Scope:** discovery only — no production code changes. Sibling of
W154 (`createnewblock-blockassembler`); several W154 findings are
re-anchored here because they affect the wire surface emitted by these
RPCs (BUG-1, BUG-2, BUG-3, BUG-7). Many NEW findings surface from the
RPC-specific gates that W154 did not exercise (mode=proposal, the
client-rule contract, the `BIP22ValidationResult` token map, the
`submitheader` RPC, the `submitblock` plumbing, the
`getmininginfo` next/blockmintxfee fields, etc.).

**Bitcoin Core references**
- `bitcoin-core/src/rpc/mining.cpp:615-1036` — `getblocktemplate`:
  RPCHelpMan shape (rules / capabilities / mode / longpollid / data),
  proposal-mode dispatch (BIP-23), longpoll loop (`waitTipChanged` +
  `nTransactionsUpdatedLast` recheck at 60s/10s), IBD + zero-peers
  gates, `setClientRules` contract (must include "segwit"; signet
  network requires "signet"), per-tx fields
  (`data`/`txid`/`hash`/`depends`/`fee`/`sigops`/`weight`),
  `coinbasevalue` emitted as `NUM` (`pushKV("coinbasevalue",
  block.vtx[0]->vout[0].nValue)`), `longpollid = tip.GetHex() +
  ToString(nTransactionsUpdatedLast)`, `mintime =
  GetMinimumTime(pindexPrev, ...)`, `mutable = ["time","transactions",
  "prevblock"]`, `noncerange = "00000000ffffffff"`,
  `sigoplimit = MAX_BLOCK_SIGOPS_COST` (÷4 if pre-segwit),
  `sizelimit = MAX_BLOCK_SERIALIZED_SIZE` (÷4 if pre-segwit),
  `weightlimit = MAX_BLOCK_WEIGHT` (omitted if pre-segwit),
  `signet_challenge` only on signet, `default_witness_commitment`
  only when block_template emits a required output for it.
- `bitcoin-core/src/rpc/mining.cpp:587-603` — `BIP22ValidationResult`:
  valid → `VNULL`, error → `JSONRPCError(RPC_VERIFY_ERROR)` (THROWS),
  invalid → reject-reason string or "rejected" if empty, fallback
  "valid?".
- `bitcoin-core/src/rpc/mining.cpp:1056-1106` — `submitblock`:
  `DecodeHexBlk` → `chainman.UpdateUncommittedBlockStructures(block,
  pindex)` BEFORE `ProcessNewBlock` (re-derives witness commitment from
  the block's tx set so a submitter that posted with a stale
  commitment has it regenerated), registers a
  `submitblock_StateCatcher` `CValidationInterface`,
  `ProcessNewBlock(... force_processing=true, min_pow_checked=true)`,
  result distinguishes "duplicate" (already known + valid) /
  "inconclusive" (catcher never fired) / `BIP22ValidationResult` (state
  reject reason) / `VNULL` (accepted as new block).
- `bitcoin-core/src/rpc/mining.cpp:1108-1146` — `submitheader`:
  `DecodeHexBlockHeader`, refuses if parent unknown (`Must submit
  previous header (<hash>) first`), `ProcessNewBlockHeaders`,
  throws `RPC_VERIFY_ERROR` on failure (NOT a BIP-22 result string).
- `bitcoin-core/src/rpc/mining.cpp:416-498` — `getmininginfo`:
  `blocks = active_chain.Height()`,
  `currentblockweight`/`currentblocktx` only present when a template
  has been built (`BlockAssembler::m_last_block_weight` static),
  `bits` strprintf("%08x", tip.nBits), `difficulty =
  GetDifficulty(tip)`, `target = GetTarget(tip,
  consensus.powLimit).GetHex()`, `networkhashps =
  getnetworkhashps().HandleRequest(request)` (re-dispatches with same
  params), `pooledtx = mempool.size()`, `blockmintxfee =
  ValueFromAmount(assembler_options.blockMinFeeRate.GetFeePerK())`
  (BTC/kvB), `chain` via `GetChainTypeString`, `next` object
  (height/bits/difficulty/target),
  `signet_challenge` only on signet, `warnings` array.
- `bitcoin-core/src/rpc/mining.cpp:111-262` — `getnetworkhashps`:
  default nblocks = 120, height -1 → blockstats span;
  `height = -1 || pb == nullptr` shortcut.
- `bitcoin-core/src/rpc/mining.cpp:502-583` —
  `prioritisetransaction` / `getprioritisedtransactions`: 3-arg
  contract (txid, dummy, fee_delta), dummy must be 0, fee_delta is
  satoshis (int64), refuses prioritise when tx is in mempool and has
  dust outputs (`require_standard`), returns `true`.
- `bitcoin-core/src/rpc/mining.cpp:1148-1163` — RPC register table:
  `getnetworkhashps`, `getmininginfo`, `prioritisetransaction`,
  `getprioritisedtransactions`, `getblocktemplate`, `submitblock`,
  `submitheader`, `generatetoaddress`, `generateblock`,
  `getblockfromtemplate` (new in master).
- `bitcoin-core/src/txmempool.h:189` —
  `std::atomic<unsigned int> nTransactionsUpdated{0}` "Used by
  getblocktemplate to trigger CreateNewBlock() invocation" — monotonic
  counter incremented on add/remove/prioritise (`txmempool.cpp:203,
  249, 305, 642`), NOT the entry count.
- `bitcoin-core/src/rpc/mining.cpp:264-303` — `generatetoaddress`:
  3-arg (`nblocks`, `address`, `maxtries`).
- `bitcoin-core/src/rpc/mining.cpp:305-414` — `generateblock`:
  3-arg (`output`, `transactions`, `submit=true`); builds via
  `BlockAssembler::createNewBlock({.use_mempool = false,
  .coinbase_output_script = ..., .include_dummy_extranonce = true})`
  → `block.vtx.insert(block.vtx.end(), txs)` → `RegenerateCommitments`
  → `TestBlockValidity(... check_pow=false, check_merkle_root=false)`
  → `GenerateBlock`; `submit=false` returns hex.
- `bitcoin-core/src/consensus/consensus.h:13, 15, 21` —
  `MAX_BLOCK_SERIALIZED_SIZE = 4_000_000`, `MAX_BLOCK_WEIGHT =
  4_000_000`, `WITNESS_SCALE_FACTOR = 4`.
- `bitcoin-core/src/policy/policy.h` — `DEFAULT_BLOCK_MIN_TX_FEE_KVB =
  1000` sats (1 sat/vB; the `blockmintxfee` `getmininginfo` field).

**Files audited**
- `lib/rpc.ml` — `handle_getmininginfo` (line 1799-1827),
  `handle_getblocktemplate` (line 1829-1858),
  `bip22_of_submitblock_error` (line 1860-1914),
  `handle_submitblock` (line 1916-1944),
  `mine_single_block` (line 1952-1970),
  `handle_generate` (line 1975-2016),
  `handle_generatetoaddress` (line 2021-2053),
  `handle_generateblock` (line 2060-2188),
  `handle_prioritisetransaction` (line 1571-1613),
  `handle_getprioritisedtransactions` (line 1618-1631),
  `handle_getnetworkhashps` (line 7717-7754),
  `core_chain_name` (line 54-59),
  RPC dispatch (line 8700-8722; `getmininginfo`, `getblocktemplate`,
  `submitblock`, `generate`, `generatetoaddress`, `generateblock`;
  no `submitheader`, no `getblockfromtemplate`).
- `lib/mining.ml` — `block_template` (line 26-37),
  `template_to_json` (line 572-684),
  `template_to_json_simple` (line 687-705),
  `submit_block` (line 716-928, dual-path: extends validated tip OR
  side-branch attach via `try_attach_side_branch_and_reorg`),
  `create_block_template` (line 347-494),
  `create_coinbase` (line 264-333),
  `compute_witness_commitment` (line 233-236),
  `build_witness_commitment_script` (line 241-249),
  `compute_wtxid` (line 211-218),
  `mine_block` (line 505-528).
- `lib/mempool.ml` — `entries : (string, mempool_entry) Hashtbl.t`,
  `prioritise_transaction`, `get_prioritised_transactions`.
- `lib/consensus.ml` — `max_block_weight = 4_000_000` (line 11),
  `max_block_serialized_size = 4_000_000` (line 12),
  `max_block_sigops_cost = 80_000` (line 13),
  `signet_blocks`/`signet_challenge` (NOT present in
  `network_config`).
- `CORE-PARITY-AUDIT/w154-createnewblock-blockassembler.md` —
  immediate sibling; carry-forward anchors documented in summary.
- `audit/w123_mining_gbt.md` (if present) — older mining audit.

---

## Gate matrix (30 sub-gates / 11 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | GBT mode dispatch | G1: mode = "template" default | PASS (implicit; `handle_getblocktemplate` ignores `mode` field entirely) |
| 1 | … | G2: mode = "proposal" dispatches to `TestBlockValidity(check_pow=false, check_merkle_root=true)` and returns `BIP22ValidationResult` | **BUG-1 (P0-CDIV)** — mode="proposal" not implemented at all. Falls through to the template path; BIP-23 proposal validation surface is absent. |
| 1 | … | G3: mode = "<anything else>" throws RPC_INVALID_PARAMETER | **BUG-2 (P1)** — invalid mode silently ignored; passes through to template-build path. |
| 2 | Client-rule contract | G4: refuse if rules[] does not contain "segwit" (post-segwit-activation hard fail) | **BUG-3 (P0-CDIV)** — `handle_getblocktemplate` never parses `rules`; client can request a template without acknowledging segwit and still get a template carrying `default_witness_commitment` it cannot use, OR (more concerning) without acknowledging BIP-9 deployments it should refuse. Core: `mining.cpp:854-857` throws `RPC_INVALID_PARAMETER` with explicit message instructing miner to call with `{"rules":["segwit"]}`. |
| 2 | … | G5: refuse on signet network if rules[] does not contain "signet" | N/A (signet not supported as a network type in camlcoin — see BUG-13) |
| 3 | IBD / connectivity gates | G6: throw RPC_CLIENT_IN_INITIAL_DOWNLOAD if `isInitialBlockDownload()` and not a test chain | **BUG-4 (P0-CDIV)** — no IBD gate in `handle_getblocktemplate`. A miner connected to a syncing camlcoin would build a template against the partially-validated tip and submit a block that is rejected by Core peers on submission (PoW + work wasted; chain-split risk if many camlcoin nodes accept that block while Core rejects). |
| 3 | … | G7: throw RPC_CLIENT_NOT_CONNECTED if `connman.GetNodeCount(Both) == 0` and not a test chain | **BUG-5 (P0-SEC)** — no zero-peer gate. An isolated camlcoin node serves templates as if it were on the chain; an attacker who network-partitions the miner gets it to build on a fork. Core's gate (`mining.cpp:766-774`) is the canonical defense. |
| 4 | Longpoll (BIP-22) | G8: wait until tip changes OR mempool transactions-updated counter increments | **BUG-6 (P0-CDIV)** — `handle_getblocktemplate` ignores the `longpollid` request parameter entirely (line 1829-1858 parses ONLY `coinbase_address`). Long polling is the canonical miner-throttling mechanism; without it, miners must busy-poll. |
| 4 | … | G9: longpoll `nTransactionsUpdatedLast` is a monotonic counter, not entry count | **BUG-7 (P0-CDIV)** — `template_to_json` emits `longpollid = prev_block_hash + string_of_int (Hashtbl.length mp.entries)` (`mining.ml:493, 647-649`). `Hashtbl.length mp.entries` is the CURRENT size, which DECREASES when entries are removed. Core's `nTransactionsUpdated` (`txmempool.h:189`) is a monotonic atomic that increments on every add/remove/prioritise. A miner that caches the longpollid sees identical values across distinct mempool states (e.g. a tx is added then removed; entry count returns to N; tip unchanged; longpollid = same string but the mempool changed). False-negative on longpoll detection. |
| 5 | per-tx JSON fields | G10: `data` (raw hex of tx) present | PASS (`mining.ml:588`) |
| 5 | … | G11: `txid` (no-witness hash, byte-reversed display) present | PASS (`mining.ml:589`, `compute_txid` is the no-witness hash) |
| 5 | … | G12: `hash` (witness hash, byte-reversed display) present per Core BIP-145 / `getblocktemplate` schema (`mining.cpp:670, 915`) | **BUG-8 (P0-CDIV)** — `template_to_json` (line 587-595) does NOT emit a `hash` field. Core emits `entry.pushKV("hash", tx.GetWitnessHash().GetHex())` — required by BIP-145 + the Core RPC schema. Miner clients that consume `hash` to do witness-commitment recomputation lose the field. |
| 5 | … | G13: `depends` list of 1-based indices to ancestor txs in the template | PASS (`mining.ml:584-586, 591`) — note the `i + 1` indexing matches Core (`mining.cpp:921`). |
| 5 | … | G14: `fee` per Core is `NUM` (satoshis as integer) | PASS (`mining.ml:590`); but `Int64.to_int` (line 590) truncates on 32-bit OCaml and saturates at `Int.max_int` on 64-bit (~9.2e18), which exceeds MAX_MONEY (2.1e15) so no practical truncation. However, `Yojson.Safe.t` `Int` may be emitted as JSON NUM with platform-dependent precision; flagged in BUG-19. |
| 5 | … | G15: `sigops` is the UTXO-aware sigop cost (P2SH-aware + witness-aware) | **BUG-9 (P0-CDIV)** — W154 BUG-16 carry-forward, re-anchored at W155 because this is the RPC-side field. `count_tx_sigops_cost_simple ~prev_script_pubkey_lookup:(fun _ -> None)` (`mining.ml:592-593`) returns ONLY legacy sigops × WITNESS_SCALE_FACTOR — no P2SH lookup, no witness-program lookup. The internal selector (`Mempool.count_tx_sigops_cost_for_mempool`) correctly handles all three classes but the JSON field served to miners is the undercount. |
| 5 | … | G16: `weight` matches `GetTransactionWeight` | PASS (`mining.ml:594` via `Validation.compute_tx_weight`) |
| 6 | top-level wire-format constants | G17: `coinbasevalue` = JSON NUM, not String | **BUG-10 (P0-CDIV)** — W154 BUG-14 carry-forward, re-anchored at W155. `template_to_json` (`mining.ml:662-666`) emits `Int64.to_string` wrapped in `\`String`. Core: `result.pushKV("coinbasevalue", block.vtx[0]->vout[0].nValue)` is a JSON integer. Miner clients (ckpool, btcpool, bitcoin-cli decoders) `JSON.parse` into an integer; a string is rejected or returns 0. |
| 6 | … | G18: `sizelimit` = MAX_BLOCK_SERIALIZED_SIZE = 4_000_000 (or ÷4 if pre-segwit) | **BUG-11 (P0-CDIV)** — W154 BUG-15 carry-forward, re-anchored at W155. `template_to_json` (`mining.ml:676`) hardcodes `1000000`. Miner clients silently cap their submissions at 1 MB serialized size — block reward is suboptimal relative to a Core-served template. |
| 6 | … | G19: `weightlimit` = MAX_BLOCK_WEIGHT (or omitted if pre-segwit) | PASS (`mining.ml:677`); but unconditional emission would be a divergence on an archive replay of mainnet h < 481,824 — see W154 BUG-3 fleet pattern. |
| 6 | … | G20: `sigoplimit` = MAX_BLOCK_SIGOPS_COST = 80_000 (or ÷4 if pre-segwit) | PASS (`mining.ml:675`); pre-segwit ÷4 not modelled (would emit 80_000 in archive replay). |
| 6 | … | G21: `noncerange` = `"00000000ffffffff"` | PASS (`mining.ml:674`) |
| 6 | … | G22: `mintime` = MTP(prev) + 1 (NOT curtime) | **BUG-12 (P1)** — W154 BUG-6 carry-forward, re-anchored at W155 because this is the JSON-emitting site. `template_to_json` (`mining.ml:670-671`) emits `template.header.timestamp` which is `max(MTP+1, now)`. Core emits `GetMinimumTime(pindexPrev, ...)` which is MTP+1 strictly. Miners that lower `nTime` toward `mintime` lose visibility into the gap. |
| 6 | … | G23: `curtime` = block.GetBlockTime() (clock NOW, before nTime adjust) | **BUG-13 (P1)** — `template_to_json` emits `curtime = template.header.timestamp` (`mining.ml:678-679`), same as `mintime` (BUG-12). Core: `result.pushKV("curtime", block.GetBlockTime())` is `max(MTP+1, GetTime())` AFTER `UpdateTime` adjustment — so curtime can be > mintime. Camlcoin emits them identically → miners think the clock is frozen at MTP+1. |
| 6 | … | G24: `mutable[]` = `["time","transactions","prevblock"]` | PASS (`mining.ml:672-673`) |
| 6 | … | G25: `capabilities` includes `proposal` | PASS (`mining.ml:622-624`); but `proposal` is advertised while mode=proposal is not implemented (cross-cite BUG-1). |
| 7 | signet support | G26: signet network emits `signet_challenge` in GBT JSON | **BUG-14 (P1)** — signet not present as a network type (`network_config` has no `signet_blocks`/`signet_challenge` field). `core_chain_name "signet" -> "signet"` is plumbed (line 50) but no `Consensus.Signet` enum variant exists. cross-cite W143 BUG-9 (`CheckSignetBlockSolution` absent fleet pattern). |
| 8 | submitblock plumbing | G27: `UpdateUncommittedBlockStructures` called before validation (re-derives commitment for stale-witness submitters) | **BUG-15 (P2)** — W154 BUG-4 carry-forward, re-anchored at W155. `handle_submitblock` (`rpc.ml:1916-1944`) deserializes block and calls `submit_block` directly with no re-derivation. Honest miners produce correct commitments → low impact, but Core's exact pipeline does the re-derivation defensively. |
| 8 | … | G28: distinguish "duplicate" (already valid) vs "duplicate-invalid" vs "duplicate-inconclusive" vs "inconclusive" vs valid (null) vs reject-reason | **BUG-16 (P0-CDIV)** — `handle_submitblock` (`rpc.ml:1916-1944`) returns only `null` (accepted) OR `bip22_of_submitblock_error` result string. Core has FIVE distinct outcomes (`mining.cpp:1097-1103`): (a) `VNULL` on accept-as-new; (b) `"duplicate"` on `!new_block && accepted`; (c) `"inconclusive"` when the catcher never fired (the block was accepted but `BlockChecked` wasn't called for this hash within scope); (d) `BIP22ValidationResult(state)` on reject; (e) the `BlockChecked`-derived state. Camlcoin loses (b) and (c) entirely. Re-submitting an already-known valid block returns `null` instead of `"duplicate"` — miner clients that diff "new block found" vs "duplicate" see false positives. Re-submitting an already-failed block returns the canonical reject-reason via `bip22_of_submitblock_error` rather than `"duplicate-invalid"`. |
| 9 | submitheader RPC | G29: register `submitheader` RPC for pre-flight header validation | **BUG-17 (P2)** — W154 BUG-18 carry-forward; the RPC dispatcher (`rpc.ml:8700-8722`) does not include a `"submitheader"` case. Core exposes it for pool-side / monitoring use. |
| 10 | getmininginfo fields | G30: `currentblockweight` / `currentblocktx` reflect the latest assembled template (optional fields; only present if a block has ever been assembled) | **BUG-18 (P2)** — W154 BUG-19 carry-forward, re-anchored at W155. `handle_getmininginfo` (`rpc.ml:1810-1812`) emits `currentblocksize`/`currentblockweight`/`currentblocktx` as constant `0` regardless of template state. Core conditionally pushes them ONLY when `m_last_block_weight`/`m_last_block_num_txs` are populated (`mining.cpp:467-468`). Camlcoin's variant: always-present zero → operator dashboards distinguish "no block built yet" from "block built but empty"? They cannot. |

30 gates / 18 bugs catalogued in matrix; 9 more findings (BUG-19..27)
are W155-specific or refinement that do not map 1:1 to a gate.

---

## BUG-1 (P0-CDIV) — `mode="proposal"` (BIP-23) entirely unimplemented

**Severity:** P0-CDIV. BIP-23 mandates that `getblocktemplate` with
`{"mode":"proposal","data":"<hex>"}` runs `TestBlockValidity(check_pow=false,
check_merkle_root=true)` on the supplied block and returns the
`BIP22ValidationResult` (null if valid, string reject-reason otherwise).
This is the canonical mechanism for a pool's "test this block before
the miner commits hashpower" workflow.

`handle_getblocktemplate` (`rpc.ml:1829-1858`) extracts ONLY
`coinbase_address` from the first param object — `mode`, `data`, and
`rules` are not parsed at all:

```ocaml
let coinbase_address_opt = match params with
  | (`Assoc fields) :: _ ->
    (match List.assoc_opt "coinbase_address" fields with
     | Some (`String addr) -> Some addr
     | _ -> None)
  | _ -> None
in
...
let template = Mining.create_block_template ... in
Ok (Mining.template_to_json template)
```

A `proposal`-mode request silently returns a fresh template instead of
validating the submitted block. Pools depending on the proposal flow
get incorrect results.

**File:** `lib/rpc.ml:1829-1858`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:730-752` (proposal
dispatch), `bitcoin-core/src/rpc/mining.cpp:587-603` (BIP22ValidationResult).

**Impact:** BIP-23 surface unusable; pools relying on test-block
proposal workflow are silently broken; symptom mimics a miner-side bug.

---

## BUG-2 (P1) — Invalid `mode` value silently ignored

**Severity:** P1. Core: `if (strMode != "template") throw
JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode")` (`mining.cpp:763-764`).
Camlcoin: `mode` parameter never consulted → any value is treated as
template. Clients passing `mode="foo"` (typo, future mode) get a
template back without an error.

**File:** `lib/rpc.ml:1829-1858`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:719-727, 763-764`.

**Impact:** silent miscommunication; future BIP-23 extension modes
would not surface as RPC errors.

---

## BUG-3 (P0-CDIV) — Client-rule contract not enforced: GBT does not require `rules=["segwit"]`

**Severity:** P0-CDIV. Core (`mining.cpp:854-857`) explicitly throws:

```cpp
if (!setClientRules.contains("segwit")) {
    throw JSONRPCError(RPC_INVALID_PARAMETER,
        "getblocktemplate must be called with the segwit rule set "
        "(call with {\"rules\": [\"segwit\"]})");
}
```

This is the GBT contract: a client that does NOT advertise segwit
awareness is not entitled to a segwit-template (and post-segwit the
ONLY template Core builds is segwit). Camlcoin's
`handle_getblocktemplate` never parses `rules`, so:
- a pre-segwit-aware client gets a segwit template (with
  `default_witness_commitment` it cannot use, signaling bits it
  doesn't understand);
- Core's signet-rule gate (`mining.cpp:850-852`) — refuse signet
  network without `"signet"` in rules — is moot today (BUG-14
  no-signet) but the architectural gap persists.

The companion `block.nVersion &= ~info.mask` logic
(`mining.cpp:970-982`) — strip the BIP-9 signaling bits for
deployments the client does NOT advertise — is also entirely absent.
A camlcoin GBT returns the FULL signaling version regardless of
client capability, so miners that can't handle a deployment get the
template signaling for it.

**File:** `lib/rpc.ml:1829-1858`; `lib/mining.ml:611-618` (rules JSON
emitted unconditionally as `["csv","!segwit","taproot"]`).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:754-761, 854-857,
965-991`.

**Impact:** miner clients that mis-advertise capability get templates
they cannot serve; chain-split risk if a client mines on a template it
doesn't understand and submits a block the network rejects.

---

## BUG-4 (P0-CDIV) — No IBD gate on `getblocktemplate`

**Severity:** P0-CDIV. Core (`mining.cpp:766-774`):

```cpp
if (!miner.isTestChain()) {
    if (miner.isInitialBlockDownload()) {
        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD,
            CLIENT_NAME " is in initial sync and waiting for blocks...");
    }
}
```

Camlcoin: `handle_getblocktemplate` does NOT check IBD state. A miner
attached to a syncing camlcoin node will:
1. Receive a template built against the partially-validated tip;
2. Build a block on top of that header;
3. Submit it via `submitblock`;
4. The block may be valid against the camlcoin-IBD view but
   the WIDER network's tip is far ahead → the block is orphaned by
   Core peers, PoW is wasted, the miner doesn't see this failure
   mode in their RPC response.

Worse, on chain-split scenarios (camlcoin IBD takes a wrong fork),
miner builds on top of a fork that Core rejects → camlcoin gives the
miner a chain-split candidate to extend.

The `Sync.chain_state` has an `is_ibd` notion (cf. `chain.blocks_synced`
vs header tip height), but `handle_getblocktemplate` doesn't consult it.

**File:** `lib/rpc.ml:1829-1858`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:766-774`.

**Impact:** PoW wasted, fleet-fork primitive on chain-split, miner
sees opaque success → reject loop.

---

## BUG-5 (P0-SEC) — No connectivity gate on `getblocktemplate`

**Severity:** P0-SEC. Core (`mining.cpp:767-770`):

```cpp
const CConnman& connman = EnsureConnman(node);
if (connman.GetNodeCount(ConnectionDirection::Both) == 0) {
    throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED,
        CLIENT_NAME " is not connected!");
}
```

Camlcoin: no peer-count check. An isolated camlcoin node (firewall
misconfig, network partition, all peers disconnected) cheerfully serves
templates against its own stale tip. If an attacker isolates a miner's
node and feeds it a fake parent, the miner extends the wrong chain.
This is exactly the eclipse-attack primitive the connectivity gate
defends against.

Camlcoin's `Peer_manager.peer_count ctx.peer_manager` is the
primitive (consulted by `handle_getconnectioncount` and
`handle_getnetworkinfo`) — the GBT handler just never calls it.

**File:** `lib/rpc.ml:1829-1858`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:766-770`.

**Impact:** eclipse-attack amplifier; isolated miner mines on attacker-
provided fork.

---

## BUG-6 (P0-CDIV) — Long polling (BIP-22) entirely absent

**Severity:** P0-CDIV. BIP-22 long polling lets a miner POST GBT
with `longpollid=<prev>` and BLOCK until either (a) the tip changes
OR (b) the mempool has had enough updates that a refreshed template
would be materially different. Core implements this with a
`waitTipChanged` wait + periodic mempool re-check at 60s/10s
(`mining.cpp:783-845`).

Camlcoin `handle_getblocktemplate`:
- Does NOT parse the `longpollid` parameter from the request;
- Does NOT block at all — returns the template immediately;
- The longpollid IS emitted in the response (BUG-7) but the request-
  side machinery to consume it is absent.

Miners that depend on long polling for low-latency template refresh
(every pool implementation does) must fall back to busy-polling, which
on mainnet at 1 GBT/sec is a 10x CPU/RPC load increase.

**File:** `lib/rpc.ml:1829-1858`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:783-845`.

**Impact:** miner workflow gap; busy-poll cost; miss-window between
tip change and miner refresh.

---

## BUG-7 (P0-CDIV) — `longpollid` counter is mempool entry count, not monotonic transactions-updated counter

**Severity:** P0-CDIV. Core encodes `longpollid = tip.GetHex() +
ToString(nTransactionsUpdatedLast)` where `nTransactionsUpdatedLast`
is the value of `CTxMemPool::nTransactionsUpdated` at template
creation time — a monotonic atomic counter (`txmempool.h:189`)
incremented on every:
- `addUnchecked` (`txmempool.cpp:249`),
- `removeUnchecked` (`txmempool.cpp:305`),
- `addTransactionsUpdated(n)` (`txmempool.cpp:203`),
- `PrioritiseTransaction` (`txmempool.cpp:642`).

Camlcoin: `template.transactions_updated = Hashtbl.length mp.entries`
(`mining.ml:493`), emitted as `longpollid = prev_block_hash +
string_of_int N` (`mining.ml:647-649`).

The hash-table size is the CURRENT count, which decreases on
eviction / mining. A miner caching the longpollid sees `N=5000`,
five txs come in (`N=5005`), five eviction txs go out (`N=5000`) — the
longpollid is the same string, but the mempool composition is entirely
different. False-equality on the comparison; the longpoll wakeup
short-circuits.

The comment at `mining.ml:646` says "captured at template creation
time as a proxy for nTransactionsUpdatedLast" — this is a
**comment-as-confession** (the comment explicitly acknowledges the
proxy is inadequate; camlcoin's **13th instance** of this fleet
pattern, +1 over W154's count).

**File:** `lib/mining.ml:36, 493, 647-649`.

**Core ref:** `bitcoin-core/src/txmempool.h:189`,
`bitcoin-core/src/rpc/mining.cpp:1002`.

**Impact:** false-equality on longpoll; miner can miss tip-changes
that coincide with mempool churn; degrades hashrate efficiency
on a busy mempool.

---

## BUG-8 (P0-CDIV) — Per-tx `hash` field (wtxid) missing from GBT JSON

**Severity:** P0-CDIV. Core's per-tx entry in the `transactions[]`
array (`mining.cpp:914-915`):

```cpp
entry.pushKV("txid", txHash.GetHex());
entry.pushKV("hash", tx.GetWitnessHash().GetHex());
```

`hash` is the WITNESS HASH (wtxid), required by BIP-145 / the Core
RPC schema. Camlcoin's `template_to_json` per-tx entry
(`mining.ml:587-595`) emits only `data`, `txid`, `fee`, `depends`,
`sigops`, `weight` — `hash` is absent.

Miner clients that compute the witness merkle root by streaming
wtxids from this field (instead of recomputing from `data`) get a
parse failure or fall back to bytewise re-derivation, which is wasteful.

**File:** `lib/mining.ml:587-595`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:914-915`,
BIP-145 / BIP-141.

**Impact:** schema-divergence; client-side witness-merkle computation
forced to recompute from raw data; pools using `hash` for fast wtxid
emission see undefined behavior.

---

## BUG-9 (P0-CDIV) — Per-tx `sigops` is the legacy-only undercount (no P2SH, no witness)

**Severity:** P0-CDIV. W154 BUG-16 carry-forward, re-anchored at
W155 because this is the RPC-side field. `template_to_json` per-tx
sigops (`mining.ml:592-593`):

```ocaml
("sigops", `Int (Validation.count_tx_sigops_cost_simple tx
                   ~prev_script_pubkey_lookup:(fun _ -> None)));
```

With a `(fun _ -> None)` lookup, `count_tx_sigops_cost_simple`
returns ONLY the legacy sigop count × `WITNESS_SCALE_FACTOR=4`. P2SH
sigops are skipped (no prev script lookup), witness-program sigops are
skipped (witness items not inspected). Mining selection
(`Mempool.count_tx_sigops_cost_for_mempool`, `mempool.ml:1086-1094`)
correctly does the full UTXO-aware count, but the JSON field served
to miners is the undercount.

A miner that consumes the per-tx `sigops` and packs additional
transactions up to `sigoplimit = 80_000` will overshoot the real
sigop cost on a P2SH-heavy or witness-heavy template, producing a
block that gets `bad-blk-sigops` on submission.

**File:** `lib/mining.ml:592-593`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp` per-tx sigops field
(emits `entry.GetSigOpCost()` from cluster mempool, UTXO-aware).

**Impact:** miner-side sigop budgeting wrong; templates rejected on
submission; carry-forward from W154.

---

## BUG-10 (P0-CDIV) — `coinbasevalue` JSON encoded as `String`, not `NUM`

**Severity:** P0-CDIV. W154 BUG-14 carry-forward, re-anchored at
W155. `template_to_json` (`mining.ml:662-666`):

```ocaml
("coinbasevalue",
  `String (Int64.to_string
    (Int64.add
      (Consensus.block_subsidy_for_network template.network_type template.height)
      template.total_fee)));
```

Core (`mining.cpp:1001`):

```cpp
result.pushKV("coinbasevalue", block.vtx[0]->vout[0].nValue);
```

The Core schema declares `{RPCResult::Type::NUM, "coinbasevalue", ...}`
(`mining.cpp:684`). Miner clients parse `coinbasevalue` as integer per
BIP-22 → a String fails parse OR defaults to 0 (in which case the
miner reserves zero satoshis for the coinbase reward → wrong coinbase
amount → reject on submission).

**File:** `lib/mining.ml:662-666` (and `template_to_json_simple` at
`mining.ml:697-701`).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:684, 1001`.

**Impact:** GBT clients fail or misinterpret coinbasevalue → mining
pool integration breaks day-1. Same shape as W141 ZMQ byte-order
fleet pattern (wire-format divergence).

---

## BUG-11 (P0-CDIV) — `sizelimit` hardcoded to pre-segwit 1_000_000

**Severity:** P0-CDIV. W154 BUG-15 carry-forward, re-anchored at
W155. `template_to_json` (`mining.ml:676`):

```ocaml
("sizelimit", `Int 1000000);
```

Core (`mining.cpp:1008-1016`):

```cpp
int64_t nSizeLimit = MAX_BLOCK_SERIALIZED_SIZE;  // 4_000_000
if (fPreSegWit) {
    nSizeLimit /= WITNESS_SCALE_FACTOR;
}
result.pushKV("sizelimit", nSizeLimit);
```

Miner clients that respect `sizelimit` when packing transactions cap
serialized submissions at 1 MB → ~25% of post-segwit MAX_BLOCK_SERIALIZED_SIZE.
Block reward suboptimal vs Core-served templates by up to 4×.

**File:** `lib/mining.ml:676`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1008-1016`,
`bitcoin-core/src/consensus/consensus.h:13`.

**Impact:** pools see 1 MB cap; significant fee revenue loss; same
shape as BUG-10 (wire-format divergence cluster).

---

## BUG-12 (P1) — `mintime` is `header.timestamp` not MTP+1

**Severity:** P1. W154 BUG-6 / W108 BUG-9 carry-forward, re-anchored
at W155. `template_to_json` emits `mintime = template.header.timestamp`
(`mining.ml:670-671`). When `now > MTP+1` (common case), `timestamp =
now`, so `mintime = now` rather than the MTP+1 floor Core emits.
Miners that want to lower `nTime` toward `mintime` for nonce-search
flexibility see a smaller window.

**File:** `lib/mining.ml:670-671`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1004` —
`GetMinimumTime(pindexPrev, consensusParams.DifficultyAdjustmentInterval())`.

**Impact:** miner nonce-search window slightly compressed; cosmetic
on a high-hash chain.

---

## BUG-13 (P1) — `curtime` is `header.timestamp` (same as mintime), not block.GetBlockTime() after UpdateTime

**Severity:** P1. `template_to_json` (`mining.ml:678-679`):

```ocaml
("curtime", `Int (Int32.to_int template.header.timestamp));
```

Same expression as `mintime` (BUG-12) → they emit IDENTICAL values.
Core emits `curtime = block.GetBlockTime()` (`mining.cpp:1020`),
which is `max(MTP+1, GetTime())` AFTER the `UpdateTime` adjustment
(`mining.cpp:889`). Specifically curtime should be AT LEAST mintime
but typically strictly GREATER (the wall-clock time).

Miner-side behavior: clients that compare `curtime` and `mintime` to
infer "how much room is there to lower the timestamp" see "zero
room" → can't lower; effectively no clock-skew tolerance.

**File:** `lib/mining.ml:678-679`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1020`,
`bitcoin-core/src/node/miner.cpp:189` `UpdateTime`.

**Impact:** miner timestamp-flexibility gone; cosmetic on a fast
chain.

---

## BUG-14 (P1) — Signet not present as a network type; `signet_challenge` GBT field cannot be emitted

**Severity:** P1. `Consensus.network` (the enum) is
`Mainnet | Testnet3 | Testnet4 | Regtest` only — `Signet` is missing.
The translation `core_chain_name "signet" -> "signet"` (`rpc.ml:50`)
is plumbed in the helper but no network_config / chainparams entry
exists for signet, and no `signet_challenge` consumer exists in
mining.

Core's GBT response includes `signet_challenge` ONLY on signet
(`mining.cpp:1024-1026`):

```cpp
if (consensusParams.signet_blocks) {
    result.pushKV("signet_challenge", HexStr(consensusParams.signet_challenge));
}
```

Plus the "must include 'signet' in rules" gate (`mining.cpp:850-852`).
Camlcoin: zero signet support across the entire mining stack.
Cross-cite W143 BUG-9 (`CheckSignetBlockSolution` absent fleet
pattern); cross-cite the 9-CONSECUTIVE-QUAD camlcoin pipeline drift
family.

**File:** `lib/consensus.ml` (no `Signet` variant); `lib/mining.ml`
(no signet_challenge emission).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:849-852, 1024-1026`,
`bitcoin-core/src/kernel/chainparams.cpp` signet params.

**Impact:** signet completely unsupported as a mining target;
operators on signet cannot use camlcoin to assemble templates or
serve to miners.

---

## BUG-15 (P2) — `submitblock` does not call `UpdateUncommittedBlockStructures` before validation

**Severity:** P2. W154 BUG-4 carry-forward, re-anchored at W155.
Core (`mining.cpp:1086-1089`):

```cpp
const CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(block.hashPrevBlock);
if (pindex) {
    chainman.UpdateUncommittedBlockStructures(block, pindex);
}
```

This re-derives the witness commitment from the block's actual tx set
so a submitter that posted with a stale commitment (e.g. modified the
template's tx list but forgot to update the coinbase OP_RETURN) gets
the corrected commitment before `ProcessNewBlock` runs.

Camlcoin's `handle_submitblock` (`rpc.ml:1916-1944`) → `submit_block`
→ `accept_block` — no re-derivation. Honest miners always emit
correct commitments → low impact. Adversarial / debugging submitters
get a hard reject where Core would silently fix-up. Defense-in-depth
gap.

**File:** `lib/rpc.ml:1916-1944`; `lib/mining.ml:716-928`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1086-1089`.

**Impact:** cosmetic; W154 BUG-4 / W123 BUG-2 carry-forward.

---

## BUG-16 (P0-CDIV) — `submitblock` result token set incomplete (missing "duplicate", "duplicate-invalid", "duplicate-inconclusive", "inconclusive")

**Severity:** P0-CDIV. Core's `submitblock` (`mining.cpp:1093-1103`):

```cpp
auto sc = std::make_shared<submitblock_StateCatcher>(block.GetHash());
CHECK_NONFATAL(chainman.m_options.signals)->RegisterSharedValidationInterface(sc);
bool accepted = chainman.ProcessNewBlock(blockptr, /*force_processing=*/true,
                                         /*min_pow_checked=*/true,
                                         /*new_block=*/&new_block);
CHECK_NONFATAL(chainman.m_options.signals)->UnregisterSharedValidationInterface(sc);
if (!new_block && accepted) {
    return "duplicate";
}
if (!sc->found) {
    return "inconclusive";
}
return BIP22ValidationResult(sc->state);
```

Five distinct outcomes are encoded in three return paths:
1. **`"duplicate"`** — block already known + valid (`!new_block && accepted`).
2. **`"inconclusive"`** — `ProcessNewBlock` returned but the
   `BlockChecked` callback never fired for this hash.
3. **`VNULL`** — `state.IsValid()` (accepted as new).
4. **`<reject-reason>`** — `state.IsInvalid()` + non-empty reject.
5. **`"rejected"`** — `state.IsInvalid()` + empty reject (Core fallback).

Plus the BIP-23 proposal mode adds **`"duplicate-invalid"`** /
**`"duplicate-inconclusive"`** (`mining.cpp:743-748`).

Camlcoin's `handle_submitblock` (`rpc.ml:1916-1944`):
- `Ok ()` → `\`Null` (matches Core path 3 ONLY for new accept);
- `Error msg` → `bip22_of_submitblock_error msg` (matches Core path 4
  reject-reason string only).

Lost outcomes:
- **`"duplicate"`** — re-submitting a known valid block returns
  `\`Null` instead of `"duplicate"`. Miner clients tracking "first
  found vs already known" lose the signal. Pools that re-submit the
  same hash within seconds get false "new block found" notifications.
- **`"inconclusive"`** — Core's distinction between "processing
  occurred but I don't know the outcome" vs "processing rejected"
  vanishes; camlcoin always says one or the other.
- **`"duplicate-invalid"` / `"duplicate-inconclusive"`** — moot today
  because mode=proposal isn't implemented (BUG-1), but the result
  tokens are missing from `bip22_of_submitblock_error` regardless.

Additionally: the side-branch / heavier-fork accept path in
`Mining.submit_block` (line 763-768) returns `Ok ()` for a stored-
but-inactive side-branch. Per BIP-22, this is the canonical
"inconclusive" case — the block was structurally valid and stored,
but the active chain did not change. Camlcoin returns `null` =
"accept as new block" wire-equivalent. False positive: the miner
thinks they extended the tip; they didn't.

**File:** `lib/rpc.ml:1916-1944`; `lib/mining.ml:716-768`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1093-1103, 743-748,
587-603`.

**Impact:** wire-protocol divergence on the BIP-22 result token; pool
software depending on the exact token set sees broken behavior in
deduplication / reorg-detection logic.

---

## BUG-17 (P2) — `submitheader` RPC not registered

**Severity:** P2. W154 BUG-18 carry-forward. The RPC dispatcher
(`rpc.ml:8700-8722`) registers `getmininginfo`, `getblocktemplate`,
`submitblock`, `generate`, `generatetoaddress`, `generateblock` but
NOT `submitheader`. Core exposes it for monitoring and pre-flight
header validation (typically a pool admin sanity-checking a
candidate header before allocating hashrate).

**File:** `lib/rpc.ml:8700-8722`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1108-1146`.

**Impact:** miner workflow gap; pool tooling that uses `submitheader`
falls back to full `submitblock` dry-run.

---

## BUG-18 (P2) — `getmininginfo` emits `currentblocksize`/`currentblockweight`/`currentblocktx` as constant zero

**Severity:** P2. W154 BUG-19 carry-forward, re-anchored at W155.
`handle_getmininginfo` (`rpc.ml:1810-1812`):

```ocaml
("currentblocksize", `Int 0);
("currentblockweight", `Int 0);
("currentblocktx", `Int 0);
```

Core (`mining.cpp:467-468`) emits these conditionally (`if
(BlockAssembler::m_last_block_weight) obj.pushKV(...)`); when no
template has ever been built, the fields are ABSENT, not zero.
Camlcoin's always-zero distinguishes "no block built yet" from "block
built and was empty" indistinguishably.

Additionally, `currentblocksize` is NOT in Core's schema at all (Core
emits `currentblockweight` and `currentblocktx` only) — camlcoin's
extra `currentblocksize` field is schema-superset divergence.

**File:** `lib/rpc.ml:1810-1812`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:467-468`,
`bitcoin-core/src/node/miner.h:96-98`.

**Impact:** operator monitoring gap; schema superset; cosmetic.

---

## BUG-19 (P1) — `getmininginfo.blockmintxfee` hardcoded float; not the operator-knob value, not in BTC/kvB units

**Severity:** P1. Core (`mining.cpp:474-476`):

```cpp
BlockAssembler::Options assembler_options;
ApplyArgsManOptions(*node.args, assembler_options);
obj.pushKV("blockmintxfee", ValueFromAmount(assembler_options.blockMinFeeRate.GetFeePerK()));
```

`ValueFromAmount` returns BTC (8-decimal). `blockMinFeeRate.GetFeePerK()`
is sats/kvB. So the field is BTC/kvB.

Camlcoin (`rpc.ml:1816`):

```ocaml
("blockmintxfee", `Float 0.00001000);
```

Two divergences:
- Hardcoded constant (0.00001000 BTC/kvB = 1000 sats/kvB = 1 sat/vB)
  rather than the operator-configured value (cross-cite W154 BUG-1
  "no CLI knobs for block resource limits" — there's nothing to
  configure here anyway because the underlying knob isn't wired).
- The value is correct for Core's default
  (`DEFAULT_BLOCK_MIN_TX_FEE = 1000` sats/kvB) but doesn't reflect
  the active mining configuration; a future operator-knob (BUG-1
  carry-forward) lands here last.

**File:** `lib/rpc.ml:1816`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:474-476`,
`bitcoin-core/src/policy/policy.h::DEFAULT_BLOCK_MIN_TX_FEE`.

**Impact:** operator dashboards see stale value; future block-min-tx-fee
knob has no consumer in getmininginfo.

---

## BUG-20 (P1) — `getmininginfo.networkhashps` hardcoded zero instead of computing

**Severity:** P1. `handle_getmininginfo` (`rpc.ml:1817`):

```ocaml
("networkhashps", `Float 0.0);
```

Core (`mining.cpp:472`):

```cpp
obj.pushKV("networkhashps", getnetworkhashps().HandleRequest(request));
```

Core re-dispatches to the `getnetworkhashps` handler. Camlcoin HAS a
`handle_getnetworkhashps` (`rpc.ml:7717-7754`) but `handle_getmininginfo`
doesn't call it. Operator dashboards see hashrate = 0 in
`getmininginfo` but a correct value from direct `getnetworkhashps`
calls.

The fix is one line:
```ocaml
("networkhashps", (match handle_getnetworkhashps ctx [] with Ok j -> j | _ -> `Int 0));
```

**File:** `lib/rpc.ml:1817`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:472`.

**Impact:** operator monitoring gap; cross-cite the "dead helper at
call site" fleet pattern.

---

## BUG-21 (P1) — `getmininginfo.next.{height,bits,difficulty,target}` is just the CURRENT tip's values, not `NextEmptyBlockIndex`

**Severity:** P1. Core (`mining.cpp:479-487`):

```cpp
CBlockIndex next_index;
NextEmptyBlockIndex(tip, chainman.GetConsensus(), next_index);
next.pushKV("height", next_index.nHeight);
next.pushKV("bits", strprintf("%08x", next_index.nBits));
next.pushKV("difficulty", GetDifficulty(next_index));
next.pushKV("target", GetTarget(next_index, chainman.GetConsensus().powLimit).GetHex());
```

`NextEmptyBlockIndex` advances `nHeight`, recomputes `nBits` via
`GetNextWorkRequired`, and recomputes derived difficulty/target. So
when a retarget boundary is approaching, `next.bits` is the NEW
target.

Camlcoin (`rpc.ml:1820-1825`):

```ocaml
("next", `Assoc [
  ("height", `Int next_height);
  ("bits", `String bits_hex);
  ("difficulty", `Float difficulty);
  ("target", `String target_hex);
]);
```

`bits_hex`, `difficulty`, `target_hex` are all derived from `tip.header.bits`
(`rpc.ml:1800-1806`) — the CURRENT block's bits, not the next block's
recomputed bits. At every retarget boundary (every 2016 blocks on
mainnet/testnet4) the `next.bits` value is wrong; operators
monitoring difficulty-adjustment transitions see no change.

**File:** `lib/rpc.ml:1799-1827`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:479-487`,
`bitcoin-core/src/node/miner.cpp::NextEmptyBlockIndex`.

**Impact:** operator monitoring gap at retarget boundaries (every
2016 blocks); cosmetic.

---

## BUG-22 (P1) — `prioritisetransaction` deltas have no effect on chunk selection

**Severity:** P1. Carry-forward of W120 BUG-10 / W123 BUG-1 /
W154 BUG-2, re-anchored AT THE RPC SIDE for W155 visibility. The
`prioritisetransaction` handler (`rpc.ml:1571-1613`) correctly:
- Parses the 3-arg contract (txid, dummy=0, fee_delta);
- Calls `Mempool.prioritise_transaction ctx.mempool txid delta_sats`.

But the chunk-linearization in `Mining.compute_ancestor_fee_rate`
(`mining.ml:63-76`) reads `entry.fee` (raw fee) NOT
`Mempool.get_modified_fee mp entry`. So the delta is stored in the
mempool but never consumed by block-template assembly.

End-to-end: a pool operator who runs
`prioritisetransaction <txid> 0 100000000` (priorities the tx by 1
BTC) sees zero effect on the next `getblocktemplate` response — the
tx is NOT lifted to the top of the chunk-feerate ordering. The
`getprioritisedtransactions` RPC (correctly) reports the modified
fee, so a debugging operator sees the delta in flight but no
template effect. False-confirmation.

**File:** `lib/rpc.ml:1571-1631`; `lib/mining.ml:63-76`.

**Core ref:** `bitcoin-core/src/txmempool.cpp:641-642`
`m_txgraph->SetTransactionFee(modified_fee)` then re-linearize.

**Impact:** pool prioritisation deltas inert; operator confusion;
cascading through 5 sub-paths (W123 catalogue).

---

## BUG-23 (P1) — `bip22_of_submitblock_error` substring-matching loses several Core reject tokens

**Severity:** P1. `bip22_of_submitblock_error` (`rpc.ml:1865-1914`)
is a substring-match table from validation.ml's English error strings
to Core's canonical reject-reason tokens. The table covers:
high-hash, bad-txnmrklroot, bad-witness-merkle-match, bad-cb-amount,
bad-blk-sigops, bad-txns-BIP30, bad-txns-inputs-missingorspent,
bad-txns-nonfinal, bad-cb-length, bad-cb-height, time-too-new,
time-too-old, block-script-verify-flag-failed,
bad-txns-premature-spend-of-coinbase, bad-txns-vout-negative,
bad-txns-vout-toolarge, bad-txns-in-belowout, plus "rejected" fallback.

Missing from the table (Core tokens that camlcoin will never emit):
- **`"bad-blk-length"`** — block size exceeds MAX_BLOCK_SERIALIZED_SIZE.
- **`"bad-blk-weight"`** — block weight exceeds MAX_BLOCK_WEIGHT.
- **`"bad-prevblk"`** — parent block unknown (orphan).
- **`"bad-fork-prior-to-checkpoint"`** — fork below a checkpoint.
- **`"bad-version"`** — block version too low (BIP-34 etc.).
- **`"bad-diffbits"`** — bits != expected.
- **`"high-hash"`** is mapped from "difficulty target" — but if
  validation.ml ever emits a different English wording (e.g. "PoW
  below target"), the substring match misses and falls to "rejected".
- **`"bad-txnmrklroot"`** — covered, but the witness merkle root
  emits the same English ("merkle root") → both classes collapse to
  one token. Distinguishing class is lost.
- **`"bad-witness-nonce-size"`** — coinbase witness stack must be
  exactly 1 element of 32 bytes. No substring match.
- **`"unexpected-witness"`** — witness data present on a tx that
  shouldn't have it.
- **`"bad-cb-multiple"`** — multiple coinbase tx in a block.

A miner whose block hits any of these Core-defined classes gets the
generic `"rejected"` token from camlcoin → pool / monitoring tooling
that branches on the token sees the catch-all instead of the
specific class.

The whole substring-matching architecture is fragile compared to
Core's design (validation emits the token directly into `state`, then
`BIP22ValidationResult` extracts it via `state.GetRejectReason()`).
A future change to a validation.ml message that drops "merkle root"
in favor of "Merkle root" (capitalized) silently breaks the match
and downgrades to "rejected".

**File:** `lib/rpc.ml:1865-1914`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:587-603`
`BIP22ValidationResult` reads `state.GetRejectReason()` directly.

**Impact:** pool tooling sees lossy classification; the architecture
itself is a brittle proxy for Core's direct token emission.

---

## BUG-24 (P1) — `submitblock` returns `\`Null` on side-branch attach instead of `"inconclusive"`

**Severity:** P1. Closely related to BUG-16 but distinct enough to
warrant its own entry. `Mining.submit_block` (`mining.ml:763-768`)
handles the side-branch / heavier-fork case by calling
`Sync.try_attach_side_branch_and_reorg` and returning `Ok ()`. Per
BIP-22, this is canonically an **inconclusive** result — the block
was structurally valid + stored, but the active chain did NOT advance
to include it (or did, but the result is uncertain at the RPC layer).

The comment at `mining.ml:744-745` is explicit:
```
otherwise the side-branch is stored-but-inactive and the
BIP-22 result is "inconclusive" (rendered as Ok () here;
[bip22_of_submitblock_error] is not consulted on the
accept path).
```

This is a **comment-as-confession** — the documentation acknowledges
the BIP-22 result should be "inconclusive" but the code returns
"accept" (`Ok ()` → `\`Null`). camlcoin's **14th** comment-as-confession
fleet instance, +1 over BUG-7's count for this audit's running total.

Miner clients distinguishing "tip extended" vs "side-branch stored"
see false positives.

**File:** `lib/mining.ml:744-745, 763-768`; `lib/rpc.ml:1916-1944`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1100-1101` —
`"inconclusive"` is returned when the catcher never fired (which
is exactly the side-branch / reorg-deferred case in Core's
architecture too).

**Impact:** miner client sees "accept" for a side-branch that didn't
extend the tip; pool reorg-detection logic miscounts.

---

## BUG-25 (P0-CDIV) — `getblockfromtemplate` RPC not registered (BIP-22 modern extension)

**Severity:** P0-CDIV. Core master added
`getblockfromtemplate` as a server-side helper that takes the same
arguments as `getblocktemplate` and returns the full block (with
coinbase) as hex — used by light pools that want the wire-format
block immediately rather than re-assembling it client-side.

`bitcoin-core/src/rpc/mining.cpp:1148-1163` register table includes
`getblockfromtemplate`. Camlcoin: not in the dispatch table.

Cross-cite the W138 ChainstateManager fleet pattern (defined-but-not-
wired) — `getblockfromtemplate` is a different shape (not-defined-
at-all) but the family is the same: a modern Core RPC that's missing
on camlcoin and so degrades the operator surface.

**File:** `lib/rpc.ml:8700-8722` (no entry); `lib/mining.ml` (no
`getblockfromtemplate`-shaped emitter).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:1148-1163`.

**Impact:** modern pool tooling that expects `getblockfromtemplate`
falls back to GBT + manual assembly; cosmetic.

---

## BUG-26 (P1) — `handle_generate` payout fallback uses unspendable P2SH placeholder; spends to dead address

**Severity:** P1. `handle_generate` (`rpc.ml:1989-2001`):

```ocaml
let payout_script = match ctx.wallet with
  | Some wallet -> ...
  | None ->
    (* Fallback: P2SH output to dummy script hash *)
    let script = Cstruct.create 23 in
    Cstruct.set_uint8 script 0 0xa9;  (* OP_HASH160 *)
    Cstruct.set_uint8 script 1 0x14;  (* 20 bytes *)
    (* Fill with zeros - valid but unspendable *)
    ...
```

The fallback is a P2SH of `HASH160 == 20 zero bytes`. The preimage
that produces 20-zero-byte HASH160 is computationally infeasible to
find → the coinbase reward is permanently destroyed.

Core's `generatetoaddress` (`mining.cpp:264-302`) REQUIRES an address
argument; `generate` is deprecated and removed entirely. Camlcoin's
fallback is a foot-gun: an operator running `generate 100` on a
no-wallet node burns the subsidy + fees for 100 blocks.

The dispatcher fallback should refuse rather than mint to dead.

**File:** `lib/rpc.ml:1989-2001`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:264-302` —
`generatetoaddress` requires `address` arg; `generate` removed.

**Impact:** funds-loss primitive on regtest tooling without wallet
config; opaque to the operator.

---

## BUG-27 (P1) — `handle_generateblock` does NOT honour the `submit` parameter (Core 3-arg contract)

**Severity:** P1. Core's `generateblock` accepts 3 args: `output`,
`transactions`, `submit=true` (`mining.cpp:319, 373`). When
`submit=false`, the block is built but NOT broadcast; instead Core
returns `{hash, hex}` where `hex` is the serialized block. This is
the canonical "build a block but don't broadcast" workflow used by
test harnesses (Bitcoin Core's `feature_generateblock.py`,
external testing tooling, third-party reorg-construction harnesses).

Camlcoin's `handle_generateblock` (`rpc.ml:2060-2188`):
- Accepts only 2 args (`output`, `transactions?`);
- ALWAYS calls `Mining.submit_block`;
- ALWAYS returns `{hash}` (no `hex`).

A test harness that requests `generateblock <addr> <txs> false` gets
either a parse error (third arg unparsed) or the block is built AND
broadcast regardless. The "build but don't submit" branch is
unreachable.

**File:** `lib/rpc.ml:2060-2188`.

**Core ref:** `bitcoin-core/src/rpc/mining.cpp:319-410`.

**Impact:** Core-compatible test harnesses that use `submit=false`
get unexpected broadcast; reorg-construction tooling forced into a
different code path.

---

## Summary

**Bug count:** 27 (BUG-1 through BUG-27).

**Severity distribution:**
- **P0-CDIV:** 11 (BUG-1, BUG-3, BUG-4, BUG-6, BUG-7, BUG-8,
  BUG-9, BUG-10, BUG-11, BUG-16, BUG-25)
- **P0-SEC:** 1 (BUG-5)
- **P1:** 12 (BUG-2, BUG-12, BUG-13, BUG-14, BUG-19, BUG-20,
  BUG-21, BUG-22, BUG-23, BUG-24, BUG-26, BUG-27)
- **P2:** 3 (BUG-15, BUG-17, BUG-18)

Recount: P0-CDIV 11 + P0-SEC 1 + P1 12 + P2 3 = 27. Let me
re-verify:
- P0-CDIV: 1, 3, 4, 6, 7, 8, 9, 10, 11, 16, 25 = 11.
- P0-SEC: 5 = 1.
- P1: 2, 12, 13, 14, 19, 20, 21, 22, 23, 24, 26, 27 = 12.
- P2: 15, 17, 18 = 3.
- Total = 11 + 1 + 12 + 3 = **27.** ✓

**P0-class total** (P0-CDIV + P0-SEC): **12.**

---

**Fleet patterns confirmed / extended:**

- **"9-CONSECUTIVE-QUAD camlcoin pipeline drift"** family extends to
  **10 (W155)**: W143 + W144 + W145 + W149 + W150 + W151 + W152 +
  W153 + W154 + W155 = **10-CONSECUTIVE-QUAD**. New site this wave:
  the GBT RPC layer + the BIP-22 result token map (BUG-1 mode=proposal
  absent, BUG-16 result-token set incomplete, BUG-25
  `getblockfromtemplate` absent).
- **"block_import.ml-bypass family"** extends to the RPC entrypoint:
  BUG-4 (no IBD gate) + BUG-5 (no connectivity gate) + BUG-6 (no
  longpoll) — three distinct canonical-gates-not-wired on the same
  RPC. Cross-cite W144's fleet `script_flag_exceptions` family (9 of
  10 impls) — the same "perimeter audit missing" shape.
- **"two-pipeline guard"** extends to its **18th** distinct fleet
  instance (W154 was 17th, mining-side first): BUG-22
  `prioritisetransaction` delta is stored in mempool but consumed by
  zero callers — `getprioritisedtransactions` reads it (read-side
  works), chunk-linearization doesn't (block-assembly side doesn't).
  **First instance where the divergence is INSIDE a single feature**
  (operator sets delta → read returns it → block-builder ignores it).
- **"wire-format divergence"** cluster joins W141 / W154 fleet
  patterns: BUG-7 (longpollid counter semantic), BUG-8 (`hash`
  field absent), BUG-9 (sigops undercount), BUG-10 (coinbasevalue
  String not NUM), BUG-11 (sizelimit 1_000_000), BUG-13 (curtime
  == mintime), BUG-16 (submitblock result token set), BUG-18
  (currentblocksize schema superset), BUG-23 (substring-match
  reject token table). **9 wire-format divergences in one wave.**
- **"comment-as-confession"** fleet pattern: 13th instance (BUG-7
  `mining.ml:646` "proxy for nTransactionsUpdatedLast") + 14th
  (BUG-24 `mining.ml:744-745` "BIP-22 result is 'inconclusive'
  (rendered as Ok () here)"). Camlcoin **13th** and **14th**
  distinct comment-as-confession instances. (Prior count was 12
  fleet-wide after W154.)
- **"dead-helper-at-call-site"** fleet pattern (W141 instance):
  BUG-20 `getmininginfo.networkhashps = 0.0` while
  `handle_getnetworkhashps` is fully implemented and dispatched on
  a different RPC. The fix is one line; the helper exists, is
  callable, and just isn't called from this site.
- **"canonical-gate-not-wired"** fleet pattern (W144 family):
  BUG-4 (no IBD gate), BUG-5 (no connectivity gate), BUG-6 (no
  longpoll loop), BUG-1 (no proposal mode), BUG-3 (no client-rule
  contract). Camlcoin's **5th** post-W144 instance, clustered on a
  single RPC.
- **"funds-loss primitive on regtest tooling"** new pattern: BUG-26
  `handle_generate` no-wallet fallback mints to unspendable P2SH
  20-zero HASH160. Symmetric to the W129 lunarblock per-input
  effective_value funds-loss but in regtest tooling rather than wallet
  coin-selection.
- **"hardcoded constant should be operator-knob"**: BUG-19 (block-min-
  tx-fee hardcoded), BUG-20 (networkhashps hardcoded 0), BUG-18
  (currentblock* hardcoded 0).
- **"3-distinct-coexisting-pipelines"** extends: W154 BUG-22 noted
  `handle_generateblock` as the 17th two-pipeline guard. This wave
  surfaces that on the GBT side, `template_to_json` and
  `template_to_json_simple` (`mining.ml:687-705`) ALSO duplicate
  the wire-emission logic — `coinbasevalue`, `transactions`,
  `total_fee` emitted by both, but `_simple` skips per-tx data,
  rules, vbavailable, longpollid, mintime, mutable, noncerange,
  sigoplimit, sizelimit, weightlimit, default_witness_commitment.
  Three pipelines: `template_to_json`, `template_to_json_simple`,
  `handle_generateblock`'s inline manual construction. Cross-cite
  W143 ouroboros "three-pipeline drift" pattern.
- **"P0-SEC concentrations"** on GBT: BUG-4 + BUG-5 + BUG-6 are
  three separate canonical-defense gaps on the same RPC. Cross-cite
  W140 ouroboros 6 P0-SEC concentration on a single auth surface.

---

**Top three findings:**

1. **BUG-1 (P0-CDIV `mode="proposal"` entirely unimplemented)** —
   BIP-23 proposal validation is the canonical pool pre-flight
   workflow. Camlcoin silently returns a fresh template for any
   request mode → pool tooling depending on proposal mode is
   silently broken with no error surface. Cross-cite the W144
   canonical-gate-not-wired fleet pattern.

2. **BUG-4 + BUG-5 + BUG-6 cluster (P0-class — IBD + connectivity
   + longpoll absent on GBT)** — three canonical-defense gaps on
   the same RPC. A miner attached to a syncing OR isolated camlcoin
   node mines on a stale / fork tip and wastes PoW. The eclipse-
   attack defense (BUG-5) is the most security-critical
   missing-gate. The longpoll absence (BUG-6) forces miners into
   busy-poll mode, 10× CPU cost on mainnet. Cross-cite W141 + W144
   fleet patterns of stacked-defense missing-every-layer.

3. **BUG-10 + BUG-11 + BUG-7 + BUG-8 cluster (P0-CDIV wire-format
   divergence quad)** — `coinbasevalue` emitted as String (not NUM,
   miners parse-fail day-1); `sizelimit` hardcoded pre-segwit
   1_000_000 (miners cap at 1 MB, 4× revenue gap); `longpollid`
   counter uses entry count (false-equality on longpoll); per-tx
   `hash` field absent (BIP-145 wtxid not served). Four wire-shape
   gaps in the same JSON payload; every miner client breaks. Joins
   the W141 ZMQ-byte-order fleet wire-format-divergence family.

---

**Carry-forward from prior waves (re-anchored at W155):**

- BUG-9 ← W154 BUG-16 (per-tx sigops undercount)
- BUG-10 ← W154 BUG-14 (coinbasevalue String not NUM)
- BUG-11 ← W154 BUG-15 (sizelimit 1_000_000)
- BUG-12 ← W154 BUG-6 / W108 BUG-9 (mintime ≠ MTP+1)
- BUG-15 ← W154 BUG-4 / W123 BUG-2 (UpdateUncommittedBlockStructures
  absent on submitblock)
- BUG-17 ← W154 BUG-18 / W123 BUG-3 (submitheader RPC absent)
- BUG-18 ← W154 BUG-19 / W123 BUG-4 (getmininginfo current-block
  stats zero)
- BUG-22 ← W154 BUG-2 / W123 BUG-1 / W120 BUG-10 (prioritisetransaction
  delta unconsumed) — **4th-wave carry-forward, anchored across 4
  distinct audits** (oldest open camlcoin carry-forward).

**W155-NEW findings (first surfaced):**

BUG-1, BUG-2, BUG-3, BUG-4, BUG-5, BUG-6, BUG-7, BUG-8, BUG-13,
BUG-14, BUG-16, BUG-19, BUG-20, BUG-21, BUG-23, BUG-24, BUG-25,
BUG-26, BUG-27 = **19 new findings.**

---

## References

- `bitcoin-core/src/rpc/mining.cpp:111-262` getnetworkhashps
- `bitcoin-core/src/rpc/mining.cpp:264-303` generatetoaddress
- `bitcoin-core/src/rpc/mining.cpp:305-414` generateblock
- `bitcoin-core/src/rpc/mining.cpp:416-498` getmininginfo
- `bitcoin-core/src/rpc/mining.cpp:502-545` prioritisetransaction
- `bitcoin-core/src/rpc/mining.cpp:547-583` getprioritisedtransactions
- `bitcoin-core/src/rpc/mining.cpp:587-603` BIP22ValidationResult
- `bitcoin-core/src/rpc/mining.cpp:615-1036` getblocktemplate
- `bitcoin-core/src/rpc/mining.cpp:1038-1106` submitblock
- `bitcoin-core/src/rpc/mining.cpp:1108-1146` submitheader
- `bitcoin-core/src/rpc/mining.cpp:1148-1163` RegisterMiningRPCCommands
- `bitcoin-core/src/txmempool.h:189` `nTransactionsUpdated` counter
- `bitcoin-core/src/txmempool.cpp:196-205, 249, 305, 642`
  counter increments
- `bitcoin-core/src/consensus/consensus.h:13, 15, 21`
  MAX_BLOCK_SERIALIZED_SIZE / MAX_BLOCK_WEIGHT / WITNESS_SCALE_FACTOR
- `bitcoin-core/src/policy/policy.h` DEFAULT_BLOCK_MIN_TX_FEE
- BIP-22: https://github.com/bitcoin/bips/blob/master/bip-0022.mediawiki
- BIP-23: https://github.com/bitcoin/bips/blob/master/bip-0023.mediawiki
- BIP-9: https://github.com/bitcoin/bips/blob/master/bip-0009.mediawiki
- BIP-145: https://github.com/bitcoin/bips/blob/master/bip-0145.mediawiki
- Prior camlcoin audits (carry-forward chain):
  `CORE-PARITY-AUDIT/w154-createnewblock-blockassembler.md`,
  `CORE-PARITY-AUDIT/w153-mempool-eviction-minrelay.md`,
  `CORE-PARITY-AUDIT/w152-tx-relay-inv-orphan.md`,
  `CORE-PARITY-AUDIT/w151-package-relay-rbf.md`,
  `CORE-PARITY-AUDIT/w150-atmp-prechecks-policychecks.md`,
  `CORE-PARITY-AUDIT/w149-pruning-assumevalid-minimumchainwork.md`,
  `CORE-PARITY-AUDIT/w145-subsidy-fees-maxmoney.md`,
  `CORE-PARITY-AUDIT/w144-script-verify-flags.md`,
  `CORE-PARITY-AUDIT/w143-block-validation.md`,
  `audit/w123_mining_gbt.md` (if present).
