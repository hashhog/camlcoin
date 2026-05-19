# W157 — Signet block solution + BIP-94 timewarp + miner-side header constants (camlcoin)

**Wave:** W157 — signet support (`CheckSignetBlockSolution`,
`SignetTxs::Create`, `FetchAndClearCommitmentSection`,
`ComputeModifiedMerkleRoot`, `SIGNET_HEADER = 0xecc7daa2`,
`BLOCK_SCRIPT_VERIFY_FLAGS = P2SH|WITNESS|DERSIG|NULLDUMMY`,
default-signet challenge `512103ad5e0e…52ae`, default-signet magic
`pchMessageStart` derived from `HashWriter(consensus.signet_challenge).first4()`,
default-signet `nMinimumChainWork`, `defaultAssumeValid`, network
genesis `00000008819873e9…ef6`, signet default `pow_limit =
0x1e0377ae`); BIP-94 timewarp wiring (`MAX_TIMEWARP = 600`,
`enforce_BIP94` consensus param,
`ContextualCheckBlockHeader` retarget-boundary clamp,
miner-side `GetMinimumTime(pindexPrev, difficulty_adjustment_interval)`
clamp that runs ON ALL NETWORKS since v25 per `miner.cpp:41-45`); and
miner-side header constants (`UpdateTime`, `MAX_FUTURE_BLOCK_TIME`,
`BIP9 base 0x20000000`, `bad-version` reject-string parity,
`MinBIP9WarningHeight`).

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/signet.h:1-42` — `CheckSignetBlockSolution(block,
  consensusParams)`; `SignetTxs::Create(block, challenge) → optional`;
  ctor takes `to_spend` (challenge → modified-merkle commitment) +
  `to_sign` (witness-stack carrying the solution).
- `bitcoin-core/src/signet.cpp:28` —
  `static constexpr uint8_t SIGNET_HEADER[4] = {0xec, 0xc7, 0xda, 0xa2}`.
- `bitcoin-core/src/signet.cpp:30` —
  `BLOCK_SCRIPT_VERIFY_FLAGS = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS |
  SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_NULLDUMMY` (the exact 4-flag mask
  passed to `VerifyScript` when validating the signet solution).
- `bitcoin-core/src/signet.cpp:32-57` — `FetchAndClearCommitmentSection`:
  walks the witness commitment scriptPubKey looking for a pushdata that
  starts with `SIGNET_HEADER`; on hit, stores the data AFTER the header in
  `result`, **truncates the original pushdata back to the header** (so
  the modified merkle root is computed against a commitment that NO
  LONGER carries the solution), and returns true. Without this, the
  signet solution would alter the merkle root and the signature
  computed against the modified-merkle-root would never round-trip.
- `bitcoin-core/src/signet.cpp:59-68` — `ComputeModifiedMerkleRoot(cb,
  block)`: replaces `vtx[0]` with the modified coinbase (commitment
  truncated) and recomputes the merkle root over (modified_cb,
  block.vtx[1..]).
- `bitcoin-core/src/signet.cpp:70-123` — `SignetTxs::Create`:
  builds `to_spend` (version=0, vout = challenge), then `to_sign`
  (version=0, vin[0].prevout = (to_spend.hash, 0)). If the coinbase
  has NO signet pushdata, allow the block (this is the "trivial
  OP_TRUE challenge" support path). On parse failure of the pushed
  signet_solution → `nullopt`.
- `bitcoin-core/src/signet.cpp:126-153` — `CheckSignetBlockSolution`:
  genesis is always valid; otherwise build `SignetTxs`, then
  `VerifyScript(scriptSig, scriptPubKey=challenge, &witness,
  BLOCK_SCRIPT_VERIFY_FLAGS, sigcheck)`.
- `bitcoin-core/src/validation.cpp:3931-3933` —
  `if (consensusParams.signet_blocks && fCheckPOW &&
  !CheckSignetBlockSolution(block, consensusParams))
  return state.Invalid(BLOCK_CONSENSUS, "bad-signet-blksig", "...");`
  invoked from inside `CheckBlock()`.
- `bitcoin-core/src/kernel/chainparams.cpp:409-521` —
  `SigNetParams` class: derives `pchMessageStart` from
  `HashWriter() << consensus.signet_challenge`'s first 4 bytes
  (line 475-479), `signet_blocks = true`, `signet_challenge.assign(...)`
  set from the default `512103ad5e0e…52ae` or `-signetchallenge=hex`,
  `nSubsidyHalvingInterval = 210000`, `BIP34/BIP65/BIP66/CSV/Segwit
  Height = 1`, `nPowTargetTimespan = 14 days`,
  `nPowTargetSpacing = 600`, `fPowAllowMinDifficultyBlocks = false`,
  `enforce_BIP94 = false` (line 464), `fPowNoRetargeting = false`,
  `MinBIP9WarningHeight = 0`, `powLimit = 0x1e0377ae`,
  default `defaultAssumeValid = 00000008414a…f329` (height 293175),
  `nMinimumChainWork = 0x0b463ea0a4b8`, genesis
  `00000008819873e9…bee1ef6` at `nTime=1598918400`.
- `bitcoin-core/src/consensus/params.h:139-140` —
  `bool signet_blocks{false}; std::vector<uint8_t> signet_challenge;`
  on the consensus struct.
- `bitcoin-core/src/consensus/consensus.h:35` —
  `static constexpr int64_t MAX_TIMEWARP = 600`.
- `bitcoin-core/src/consensus/params.h:117-121` —
  `bool enforce_BIP94;` comment "On testnet4 this also enforces the
  block storm mitigation".
- `bitcoin-core/src/validation.cpp:4097-4105` —
  `ContextualCheckBlockHeader` BIP-94 receive-side clamp:
  `if (consensusParams.enforce_BIP94 && nHeight % DAI == 0 &&
  block.GetBlockTime() < pindexPrev->GetBlockTime() - MAX_TIMEWARP)
  → "time-timewarp-attack"`.
- `bitcoin-core/src/node/miner.cpp:36-47` — `GetMinimumTime(pindexPrev,
  difficulty_adjustment_interval)` MINER-SIDE clamp:
  `min_time = pindexPrev->GetMedianTimePast() + 1`;
  `if (height % difficulty_adjustment_interval == 0) min_time =
  max(min_time, pindexPrev->GetBlockTime() - MAX_TIMEWARP);`
  Comment line 41-42: **"Account for BIP94 timewarp rule on all
  networks. This makes future activation safer."**
  This is unconditional; it is NOT gated on `enforce_BIP94`.
- `bitcoin-core/src/node/miner.cpp:49-65` — `UpdateTime`:
  `nNewTime = max(GetMinimumTime(...), NodeClock::now())`. On
  `fPowAllowMinDifficultyBlocks` nets it recomputes `pblock->nBits`
  via `GetNextWorkRequired`.
- `bitcoin-core/src/validation.cpp:4108-4118` —
  `ContextualCheckBlockHeader` other gates: timestamp ≤ now+
  `MAX_FUTURE_BLOCK_TIME` (2 hours via NodeClock), reject
  `nVersion < 2/3/4` post-BIP34/BIP66/BIP65 with the wire-string
  `bad-version(0x%08x)`.
- `bitcoin-core/src/chainparams.cpp` — `-signetchallenge=hex`
  CLI parse path; refuses `<0x20` or `>0xffff` bytes;
  changes the network magic and disables fixed seeds.

**Files audited**
- `lib/consensus.ml:1-24, 26, 246-277, 326-441, 491-505, 581-642,
  645-691, 693-735, 738-775, 829-844, 1283-1294, 1574-1608, 1614-1645,
  1721-1745` — `network_config` (NO `signet_blocks` / `signet_challenge`
  fields), `enforce_bip94` field, `max_timewarp = 600`,
  `calculate_next_work_required`, `get_next_work_required`,
  `check_timewarp_rule` (consensus.ml:836-843), `mainnet`/`testnet`
  (= testnet3, dead)/`testnet4`/`regtest` configs (NO `signet` config),
  `mainnet_taproot`/`testnet4_taproot`/`regtest_taproot` (NO signet
  variant), `check_buried_deployment_consistency` (NO signet case).
- `lib/validation.ml:45-99, 800-975, 982-994, 1500-1577, 1803, 2086-2113`
  — `BlockTimeWarpAttack` (consensus error type +
  `"time-timewarp-attack"` string), `check_block` BIP-94 receive-side
  call site (validation.ml:855-860), `check_block_header` (line 982-994
  — uses Unix clock, no NodeClock equivalent),
  `accept_block` (line 2091-2113 — no
  `CheckSignetBlockSolution` step), `validate_block_with_utxos`
  assume-valid fast path (line 1506-1577 — runs check_block but no
  signet hook).
- `lib/sync.ml:837-869, 2154-2161, 3827-3848` —
  `validate_header` BIP-94 call site (line 850-857),
  `get_prev_block_time` helper, in-line PoW + MTP + BIP-94 checks
  for the side-branch path (line 3833-3844).
- `lib/mining.ml:347-494, 580-684, 716-769, 686-705` —
  `create_block_template` (no `GetMinimumTime` clamp; no
  `check_timewarp_rule` on the miner-side; mintime emitted equals
  template.header.timestamp), `template_to_json` (BIP-22 wire shape),
  `submit_block` (calls `Validation.check_block_header` only — no
  signet hook).
- `lib/p2p.ml:21, 2029, 2181, 2304, 2342-2347` — `signet_magic =
  0x40CF030Al` constant (matches default-signet challenge first-4
  bytes), `network_magic` plumbing for BIP-324; the `signet_magic`
  constant is NEVER referenced anywhere as a sourceable network.
- `lib/rpc.ml:43-59, 220-225, 495-558, 1287-1799, 9244-9251` —
  `core_chain_name` mapping (line 50 documents `signet → signet` as a
  branch even though no internal name `signet` exists),
  `Consensus.Testnet3 → mainnet_taproot` (line 225 — wrong; should be
  testnet/test-network taproot), `handle_getblockchaininfo` (no
  `signet_challenge` field, no per-network signet handling),
  `handle_getmininginfo`, default-port mapping for testnet (line 9251
  groups testnet3 and testnet4 onto 18332; signet absent).
- `lib/cli.ml:171-181, 305-311` — `config_for_network` enum (no
  `Signet` variant), data_dir for `Testnet` → `~/.camlcoin/testnet3`
  (label says testnet3, but `Consensus.testnet4` is what is wired —
  data_dir/consensus mismatch).
- `bin/main.ml:10-18, 514-518, 556-560` — `network_arg` Cmdliner
  enum `[("mainnet", Mainnet); ("testnet", Testnet); ("regtest",
  Regtest)]` — `signet` AND `testnet4` are entirely absent from the
  CLI surface; `Testnet` is wired to `Consensus.testnet4` (the
  testnet3 enum value `Consensus.Testnet3` is reachable only inside
  `consensus.ml` itself, never selected via CLI/config).

---

## Gate matrix (33 sub-gates / 11 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | CheckSignetBlockSolution present | G1: function defined (in any module) | **BUG-1 (P0-CONS)** — no `check_signet_block_solution` / `SignetTxs` / `FetchAndClearCommitmentSection` / `ComputeModifiedMerkleRoot` anywhere in `lib/`. `grep` over the entire codebase returns ZERO hits for `CheckSignet`, `SignetTxs`, `FetchAndClearCommitmentSection`, or `signet_solution`. |
| 1 | … | G2: invoked from CheckBlock for `consensusParams.signet_blocks && fCheckPOW` | N/A (function absent) — even on a hypothetical `--network=signet` run, no consensus enforcement of the signet signature exists |
| 2 | SIGNET_HEADER `0xecc7daa2` | G3: byte literal present | **BUG-2 (P0-CONS)** — constant entirely absent. Default `bitcoin-cli getblockheader` from a Core signet node carries the `0xecc7daa2` magic in the witness commitment; camlcoin's coinbase parser cannot find it, cannot extract the solution, cannot validate the block |
| 3 | signet_challenge chain param | G4: `network_config.signet_blocks : bool` field exists | **BUG-3 (P0-CONS)** — `network_config` (consensus.ml:250-277) has NO `signet_blocks` or `signet_challenge` field. Carry-forward of W155 BUG-14 (P1) and W143 BUG-9 fleet pattern. Re-anchored at W157 with elevated severity — at W155 the consequence was only RPC; at W157 the consequence is consensus-validation absence |
| 3 | … | G5: default-signet challenge `512103ad5e0e…52ae` hardcoded for use when no `-signetchallenge=` provided | **BUG-4 (P0-CONS)** — default-signet challenge not present anywhere; cross-cite G4 |
| 3 | … | G6: `-signetchallenge=hex` CLI flag | **BUG-5 (P0)** — no CLI hook; `bin/main.ml:10-18` only accepts `mainnet/testnet/regtest`. A hypothetical "custom signet" deployment is impossible |
| 4 | Signet network selectable | G7: `--network=signet` accepted by CLI | **BUG-6 (P0)** — Cmdliner enum (`bin/main.ml:13-15`) rejects "signet". A user passing `--network=signet` gets `Invalid argument 'signet'` and the process exits before any chain init. |
| 4 | … | G8: `Consensus.network` enum includes `Signet` variant | **BUG-7 (P0)** — `type network = Mainnet | Testnet3 | Testnet4 | Regtest` (consensus.ml:4-8) is missing `Signet`. Cross-cite W155 BUG-14 |
| 4 | … | G9: `Consensus.signet` network_config record exists | **BUG-8 (P0)** — no top-level `signet : network_config` binding in consensus.ml; cross-cite G4/G7 |
| 5 | FetchAndClearCommitmentSection semantics | G10: walks the witness commitment scriptPubKey for the SIGNET_HEADER prefix and truncates the pushdata back to the header so the modified-merkle reconciles | **BUG-9 (P0-CONS)** — function absent. The "truncate the pushdata back to the header" step is what makes the signet signature commit to a deterministic merkle root; absence means signet coinbase commitments would never round-trip. Cross-cite G1 |
| 6 | ComputeModifiedMerkleRoot | G11: separate merkle helper that takes the modified CB and recomputes the merkle root over (modified_cb, vtx[1..]) | **BUG-10 (P0-CONS)** — function absent. Existing `Crypto.merkle_root` is the unmodified path; no helper accepts a "replace vtx[0]" input |
| 7 | BIP-94 MAX_TIMEWARP receive-side | G12: `consensus.max_timewarp = 600` constant exists | PASS (`consensus.ml:26`) |
| 7 | … | G13: `enforce_bip94` field on network_config | PASS (`consensus.ml:271`) |
| 7 | … | G14: testnet4 sets `enforce_bip94 = true` | PASS (`consensus.ml:727`) |
| 7 | … | G15: mainnet / testnet3 / regtest set `enforce_bip94 = false` | PASS (`consensus.ml:618, 685, 769`) |
| 7 | … | G16: receive-side check at retarget boundary | PASS (`validation.ml:855-860`, `sync.ml:847-857`, `sync.ml:3837-3844`) |
| 8 | BIP-94 MAX_TIMEWARP MINER-side | G17: `GetMinimumTime` equivalent applies the `max(MTP+1, pindexPrev_time - 600)` clamp at retarget boundaries on ALL networks per `miner.cpp:41-45` ("Account for BIP94 timewarp rule on all networks. This makes future activation safer.") | **BUG-11 (P0-CDIV)** — `mining.ml:419` computes `timestamp = max (mtp+1) now` WITHOUT consulting `max_timewarp` at all. Cross-cite W154 BUG-7 (carry-forward, re-anchored at W157). On testnet4 today + on mainnet/regtest the day BIP-94 is universalized, camlcoin-mined retarget-boundary templates with `now < pindexPrev_time - 600` would be rejected by Core peers with `"time-timewarp-attack"` |
| 8 | … | G18: even if a `check_timewarp_rule` call were grafted in, it would be no-op on mainnet/regtest because it short-circuits when `enforce_bip94 = false` (consensus.ml:838) | **BUG-12 (P0-CDIV)** — `Consensus.check_timewarp_rule` (consensus.ml:836-843) bails out on `not network.enforce_bip94` — the function CANNOT be used as the miner-side clamp Core describes because Core's miner-side rule is unconditional. A separate `miner_min_time` helper is required, and the current callers (validation.ml:855 / sync.ml:847,3839) are gated on the receive-side semantics |
| 9 | UpdateTime | G19: `UpdateTime` equivalent recomputes `nNewTime = max(GetMinimumTime, NodeClock::now())` after assembling a template | **BUG-13 (P0)** — no `update_time` equivalent in mining.ml. After `create_block_template` returns, a template that sits in a miner's cache for >1s drifts from real time and submitblock-side `time-too-new`/`MAX_FUTURE_BLOCK_TIME` checks fail. Combined with BUG-11, a long-poll wait can leave the template with a retarget-boundary timestamp that ALSO violates BIP-94 |
| 9 | … | G20: `UpdateTime` on `fPowAllowMinDifficultyBlocks` networks recomputes `pblock->nBits` via `GetNextWorkRequired` to reflect the new time | **BUG-14 (P0)** — no nBits-recompute path; testnet4/regtest templates ship the bits captured at create-time. A 20-min idle template on testnet4 retains the non-min-difficulty bits even when Core would have dropped to pow_limit |
| 10 | MAX_FUTURE_BLOCK_TIME | G21: `MAX_FUTURE_BLOCK_TIME = 2 * 60 * 60` named constant in consensus module | PARTIAL — value is hard-coded as `7200l` in three places (`validation.ml:984`, `sync.ml:837`, `sync.ml:3830`), `sync.ml:233` defines `max_future_block_time_secs = 7200`. **BUG-15 (P2)** — constant scattered across 4 callsites with 2 different forms (`7200l` int32 + `7200` int), no shared `consensus.max_future_block_time` binding |
| 10 | … | G22: `NodeClock::now()`-equivalent (with adjusted time offset) used as the comparison reference | **BUG-16 (P1)** — every call uses `Unix.gettimeofday()` (or `Unix.time()`) directly. Core uses `NodeClock::now()` which honours the `nTimeOffset` median computed from peer version messages. A camlcoin node that sees a +5min skew on every peer would accept blocks Core would reject (or reject blocks Core would accept) |
| 10 | … | G23: `time-too-new` reject-string matches Core wire token `time-too-new` | **BUG-17 (P1)** — strings are free-form English (`"Block timestamp too far in future"`, `"Header timestamp too far in future"`) — Core's tokens are `time-too-new`, `time-too-old`, `time-timewarp-attack`. BIP-94 token `time-timewarp-attack` IS correctly emitted (validation.ml:99). 2 of 3 timestamp tokens drift |
| 11 | nVersion BIP-9 + version-bits | G24: `versionbits_top_bits = 0x20000000` | PASS (`consensus.ml:64-66`) |
| 11 | … | G25: `versionbits_top_mask = 0xE0000000` for state-machine signaling-bit detection | PASS (`consensus.ml:64`) |
| 11 | … | G26: nVersion enforcement post-BIP34/BIP66/BIP65 uses Core's `bad-version(0x%08x)` token | **BUG-18 (P1)** — `validation.ml:97` emits `"block version too low for active soft forks"`; Core token is `bad-version(0x%08x)`. RPC consumers parsing rejection reasons see a totally different string |
| 11 | … | G27: signet `mainnet_taproot` / `signet_taproot` deployment record exists with appropriate threshold | **BUG-19 (P1)** — `Consensus.compute_block_version`'s deployment list in `mining.ml:456-460` matches `network_type` against `Mainnet`/`Testnet4`/`_ → Regtest`, falling back to `regtest_taproot` for anything unknown. A hypothetical Signet/Testnet3 path silently mines with regtest's `threshold=108 / period=144` — wrong signaling cadence |
| 11 | … | G28: `rpc.ml:225` `Consensus.Testnet3 -> Consensus.mainnet_taproot` | **BUG-20 (P1)** — testnet3 should not use mainnet's taproot deployment record (different start_time/timeout/min_activation_height in Core). On a hypothetical testnet3 path the BIP-9 state machine would mis-report the deployment status |
| 12 | Signet on regtest interaction | G29: `-signetchallenge=` accepted on `--network=regtest` (Core's `RegTestOptions` does NOT take signet challenges; signet has its own params class) | N/A (signet not implemented) |
| 13 | default-signet vs custom-signet split | G30: `signet_challenge` set → `pchMessageStart` derived from `HashWriter(challenge).first4()` | **BUG-21 (P0-CONS)** — camlcoin hardcodes `p2p.ml:21 signet_magic = 0x40CF030Al`. This matches **default-signet only**. Bitcoin Core derives the magic from the challenge bytes (`chainparams.cpp:475-479`), so a `-signetchallenge=hex` custom-signet deployment uses a DIFFERENT magic. Even if signet were wired up here, custom-signet peers would be rejected as wrong-network |
| 14 | Network selection parity | G31: `--network=testnet4` accepted | **BUG-22 (P0)** — Cmdliner enum (`bin/main.ml:13-15`) does NOT include `("testnet4", `Testnet4)`. The label `testnet` IS wired to `Consensus.testnet4` (lines 516, 558), so a user gets testnet4 by saying "testnet". This is a label-mismatch (cf. core CLI accepts `-testnet4` flag explicitly since v28). Cross-cite W155 BUG-14 |
| 14 | … | G32: data_dir for testnet4 uses `testnet4` subdir per Core convention | **BUG-23 (P1)** — `cli.ml:176` sets `data_dir = ~/.camlcoin/testnet3` for `Testnet`, but the actual consensus is testnet4. This causes a UTXO/chainstate created on this binary to be put in a directory called `testnet3` even though the data is from testnet4 — operator-confusion + interop break (Core's `~/.bitcoin/testnet4/`) |
| 15 | Reject-string parity (overall) | G33: signet-specific reject `"bad-signet-blksig"` emitted when `CheckSignetBlockSolution` fails | N/A (function absent — cross-cite G1) |

---

## BUG-1 (P0-CONS) — `CheckSignetBlockSolution` entirely absent

**Severity:** P0-CONS. Bitcoin Core's `CheckBlock` (validation.cpp:3931-3933)
unconditionally fires `CheckSignetBlockSolution` on any chain whose
`consensus.signet_blocks` is true. The function (signet.cpp:126-153)
extracts the signet pushdata from the coinbase commitment, builds the
`to_spend`/`to_sign` transaction pair, computes the modified merkle root
with the solution truncated out, and calls `VerifyScript(scriptSig,
challenge, &witness, P2SH|WITNESS|DERSIG|NULLDUMMY, sigcheck)`. Without
this check, ANY block whose PoW satisfies `pow_limit = 0x1e0377ae` is
accepted regardless of whether its signet signature is valid — i.e., the
signet protection model (one or more trusted signers gated by a 2-of-2 /
multisig challenge) is unenforced.

`grep -rn 'check_signet\|CheckSignet\|SignetTxs\|FetchAndClearCommitmentSection'
/home/work/hashhog/camlcoin/lib/` returns **zero** matches. The only
signet trace anywhere is `lib/p2p.ml:21 signet_magic = 0x40CF030Al` (a
P2P magic constant, no consumer), `lib/mining.ml:612` (a comment about
non-signet rules), and `lib/rpc.ml:50` (a documentation comment about
the `core_chain_name "signet" -> "signet"` mapping that never fires).

**File:** entire `lib/` tree is missing the signet validation module.

**Core ref:** `bitcoin-core/src/signet.cpp:126-153`,
`bitcoin-core/src/validation.cpp:3931-3933`.

**Impact:** signet network is **fundamentally non-functional** at the
consensus layer — even if the network were selectable (BUG-6, BUG-7,
BUG-8), camlcoin would accept arbitrary PoW-valid blocks as the signet
tip, silently divergent from every Core peer. The "signet" reject
string `bad-signet-blksig` is never emitted; `getblockchaininfo
.chain="signet"` would lie about the validation regime.

---

## BUG-2 (P0-CONS) — `SIGNET_HEADER = 0xecc7daa2` constant absent

**Severity:** P0-CONS. The signet protocol depends on a 4-byte tag
prefix `{0xec, 0xc7, 0xda, 0xa2}` (signet.cpp:28) embedded in the
witness commitment output's pushdata. Miners must include it in their
template, and validators must scan for it in `FetchAndClearCommitmentSection`.
Without the constant, neither the miner-side nor the validator-side
can interoperate with Core signet nodes.

**File:** no constant exists; the entire integer literal `0xecc7daa2` and
the byte sequence `0xec, 0xc7, 0xda, 0xa2` does not appear in `lib/`.

**Core ref:** `bitcoin-core/src/signet.cpp:28` — the canonical
constant `SIGNET_HEADER[4] = {0xec, 0xc7, 0xda, 0xa2}`.

**Impact:** cross-cite BUG-1. Pure code-existence finding.

---

## BUG-3 (P0-CONS) — `network_config.signet_blocks` and `signet_challenge` fields absent

**Severity:** P0-CONS. The `network_config` record (consensus.ml:250-277)
has 28 fields but neither `signet_blocks : bool` nor
`signet_challenge : bytes` is among them. Core's `Consensus::Params`
(consensus/params.h:139-140) carries both, and `CheckBlock` reads
`consensusParams.signet_blocks` to decide whether to fire the signet
solution check.

This is carry-forward of:
- **W155 BUG-14** (P1, "Signet not present as a network type"). At
  W155 the consequence was reported as GBT RPC absence
  (`signet_challenge` field not emitted); the severity was P1 because
  the RPC surface was the apparent affected layer.
- **W143 BUG-9 fleet pattern** ("CheckSignetBlockSolution absent fleet
  pattern" — 2 impls confirmed at W143). At W157 the full consensus
  consequence is visible: without the field, even if the function
  were grafted in, no chain would actually enable signet enforcement.

**Re-anchored at W157 with severity elevated P1 → P0-CONS** because the
consequence reaches consensus validation, not just RPC reporting.

**File:** `lib/consensus.ml:250-277` (record def, missing two fields).

**Core ref:** `bitcoin-core/src/consensus/params.h:139-140` —
`bool signet_blocks{false}; std::vector<uint8_t> signet_challenge;`.

**Impact:** every downstream signet-conditional code path (validator,
RPC, network-magic derivation) cannot exist because the discriminating
field is absent from the record they would consult.

---

## BUG-4 (P0-CONS) — Default-signet challenge bytes not hardcoded

**Severity:** P0-CONS. Core's `SigNetParams` (chainparams.cpp:418)
hardcodes the default-signet challenge:
`512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae`
(a 2-of-2 OP_CHECKMULTISIG between Ava Chow's and another signer's
keys). Used when `-signetchallenge=` is not passed. Without this
hardcoded value, even a hypothetical signet-enabled camlcoin
deployment would not know which signature to validate against.

**File:** no occurrence of the byte sequence anywhere in `lib/`.

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:418`.

**Impact:** cross-cite BUG-1.

---

## BUG-5 (P0) — `-signetchallenge=hex` CLI flag absent

**Severity:** P0. Custom-signet deployments (commonly used by L2/dev
networks like Mutinynet, alpha-net, etc.) pass `-signetchallenge=hex`
to override the default. camlcoin's `bin/main.ml:10-18` enum-typed
`network_arg` only accepts `mainnet/testnet/regtest`, and no
`signetchallenge_arg` exists.

**File:** `bin/main.ml:10-18` (Cmdliner enum), `lib/cli.ml:171-181`
(config_for_network).

**Core ref:** `bitcoin-core/src/chainparams.cpp` —
`-signetchallenge=hex` parsing in `SigNetOptions`.

**Impact:** custom-signet operator-knob is unavailable; only mainnet
challenge would ever work (and even that doesn't work, see BUG-1).

---

## BUG-6 (P0) — `--network=signet` rejected by Cmdliner enum

**Severity:** P0. `bin/main.ml:12-16`:

```ocaml
let networks = Arg.enum [
  ("mainnet", `Mainnet);
  ("testnet", `Testnet);
  ("regtest", `Regtest);
] in
```

A user passing `--network=signet` gets a Cmdliner error
("invalid argument 'signet'") and the process exits. There is no
escape hatch — no `--testnet4`, no `--signet`, no `--signetchallenge`.

**File:** `bin/main.ml:10-18`.

**Core ref:** `bitcoin-core/src/init.cpp` — `-signet`, `-signetchallenge=`,
`-testnet4` CLI flags.

**Impact:** signet network entirely unreachable from the camlcoin
binary CLI surface; cross-cite BUG-22 for the testnet4 label drift.

---

## BUG-7 (P0) — `Consensus.network` enum missing `Signet` variant

**Severity:** P0. `consensus.ml:4-8`:

```ocaml
type network =
  | Mainnet
  | Testnet3
  | Testnet4
  | Regtest
```

Four variants, no Signet. Every downstream pattern-match that consumes
`network_type` (subsidy halving interval, taproot deployment selection,
BIP-9 state-machine cache) has no `Signet` branch to extend.

Specifically:
- `consensus.ml:94-97` `block_subsidy_for_network` — `Mainnet | Testnet3
  | Testnet4` use default halving interval (210,000); a Signet branch
  would need to follow Core's `consensus.nSubsidyHalvingInterval = 210000`
  + `-signetchallenge` operator override semantics. Currently a future
  Signet branch would fall through `Regtest` (or get a compile error).
- `consensus.ml:1721-1727` `check_buried_deployment_consistency` —
  three branches (`Mainnet`/`Testnet4`/`Regtest`) + `Testnet3 -> None`.
  Adding `Signet` triggers an exhaustiveness warning (OCaml is total).
- `rpc.ml:220-225` `Consensus.Mainnet/Testnet4/Regtest` map to taproot
  deployment records; `Testnet3 -> Consensus.mainnet_taproot` is
  already wrong (BUG-20). Adding Signet would extend the wrongness.

**File:** `lib/consensus.ml:4-8`.

**Core ref:** `bitcoin-core/src/util/chaintype.h::ChainType` enum
includes `SIGNET` since BIP-325.

**Impact:** even a partial signet patch (e.g., adding the network_config
record without the enum variant) would fail to compile because the
existing pattern-matches are exhaustive.

---

## BUG-8 (P0) — `Consensus.signet : network_config` binding absent

**Severity:** P0. Cross-cite BUG-3 (record def lacks fields) and BUG-7
(enum lacks variant). Even the empty shell of a Signet `network_config`
binding does not exist in `consensus.ml`. The four bindings
`mainnet : network_config` (line 582), `testnet : network_config`
(line 646), `testnet4 : network_config` (line 694),
`regtest : network_config` (line 739) — none for signet.

**File:** `lib/consensus.ml`.

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:409-521`
(`class SigNetParams : public CChainParams`).

**Impact:** cross-cite BUG-1, BUG-6, BUG-7.

---

## BUG-9 (P0-CONS) — `FetchAndClearCommitmentSection` semantics absent

**Severity:** P0-CONS. Core's `FetchAndClearCommitmentSection`
(signet.cpp:32-57) is what makes the signet solution wire-format work:
the witness commitment scriptPubKey carries one pushdata that begins
with the 4-byte SIGNET_HEADER, and the rest of the bytes ARE the signet
signature. The function:

1. Iterates the script's opcodes,
2. On finding a pushdata whose first 4 bytes match SIGNET_HEADER, stores
   the data AFTER the header in `result` (the actual signature payload),
3. **Truncates the original pushdata back to the 4-byte header**,
4. Builds a `replacement` script with the truncated commitment,
5. Returns the replacement (which is the script that the modified merkle
   root is then computed over).

Step 3 is the key: the signet signature commits to a modified merkle
root that itself does NOT include the signature — otherwise the
signature could not be embedded recursively into the commitment without
breaking the root. Removing this step would force the signature to be
non-deterministically discoverable, breaking the protocol.

**File:** absent entirely from `lib/`.

**Core ref:** `bitcoin-core/src/signet.cpp:32-57`.

**Impact:** cross-cite BUG-1. Pure code-existence finding.

---

## BUG-10 (P0-CONS) — `ComputeModifiedMerkleRoot` semantics absent

**Severity:** P0-CONS. Core's `ComputeModifiedMerkleRoot`
(signet.cpp:59-68) computes the merkle root of `(modified_cb,
vtx[1..])` after the coinbase has been rewritten by
`FetchAndClearCommitmentSection`. This is the merkle root committed to
inside `to_spend`'s pushed block-data:

```cpp
writer << block.nVersion;
writer << block.hashPrevBlock;
writer << signet_merkle;       // <-- THIS is the modified merkle root
writer << block.nTime;
tx_to_spend.vin[0].scriptSig << block_data;
```

Without this helper, a signet validator would have to either re-derive
the modified root inline or use the unmodified `Crypto.merkle_root` (which
includes the signature in the commitment — a fixed-point breakdown).

**File:** absent entirely from `lib/`.

**Core ref:** `bitcoin-core/src/signet.cpp:59-68`.

**Impact:** cross-cite BUG-1, BUG-9.

---

## BUG-11 (P0-CDIV) — BIP-94 MAX_TIMEWARP clamp absent on miner-side at retarget boundary

**Severity:** P0-CDIV. **CARRY-FORWARD of W154 BUG-7, re-anchored at W157**.

Bitcoin Core's `GetMinimumTime` (miner.cpp:36-47) applies the
`max(MTP+1, pindexPrev->GetBlockTime() - MAX_TIMEWARP)` clamp at every
difficulty-adjustment boundary, on **all networks** — the comment is
explicit:

```cpp
// Account for BIP94 timewarp rule on all networks. This makes future
// activation safer.
if (height % difficulty_adjustment_interval == 0) {
    min_time = std::max<int64_t>(min_time, pindexPrev->GetBlockTime() - MAX_TIMEWARP);
}
```

camlcoin's `mining.ml:418-419`:

```ocaml
let now = Int32.of_float (Unix.gettimeofday ()) in
let timestamp = max (Int32.add mtp 1l) now in
```

NO `max_timewarp` consultation. NO retarget-boundary special case. The
template's timestamp is `max(MTP+1, now)`. On testnet4 today (where the
RECEIVE side has the BIP-94 check) a camlcoin miner that builds at a
retarget boundary with `now < pindexPrev_time - 600` (e.g. a node with
a backward-skewed wall clock or a long-running miner whose lab
NodeClock has drifted) would emit a template whose `nTime` violates
BIP-94. The block would be rejected by every Core peer with
`"time-timewarp-attack"`.

The fix is a 5-line addition modeled on Core's GetMinimumTime, applied
at all retarget boundaries unconditionally (Core's "on all networks"
comment is forward-looking — universalizing BIP-94 across mainnet is
the long-term plan; emitting timewarp-resistant templates today is
strictly more conservative).

**File:** `lib/mining.ml:418-419`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:36-47`.

**Excerpt (camlcoin, missing clamp)**
```ocaml
(* tip_ts_list was computed above for lock_time_cutoff; reuse for MTP.
   Current timestamp — must exceed MTP of previous block (GetMinimumTime).
   Core miner.cpp:52: nNewTime = max(GetMinimumTime(pindexPrev, ...), now) *)
let mtp = lock_time_cutoff in  (* MTP = median_time_past tip_ts_list, already computed *)
let now = Int32.of_float (Unix.gettimeofday ()) in
let timestamp = max (Int32.add mtp 1l) now in
(* MISSING: if height mod DAI == 0 then
            timestamp = max timestamp (parent_time - 600) *)
```

The comment ON THE SAME LINES correctly cites Core miner.cpp:52 (a
truncated quote from the surrounding `UpdateTime` body) but stops short
of citing line 41-45 where the BIP-94 clamp lives — a textbook
**comment-as-confession** (fleet pattern, 14th+ camlcoin instance).
The code-comment KNEW it was implementing GetMinimumTime but
implemented only the MTP+1 half.

**Impact:**
- Testnet4 retarget-boundary blocks from a camlcoin miner with wall-clock
  drift are rejected fleet-wide. Cross-impl divergence on a wave-12
  scenario (camlcoin in the lab mining onto a Core-led fork).
- The day BIP-94 ships on mainnet (Core PR pending per the "makes future
  activation safer" comment), camlcoin miners stop producing valid
  retarget-boundary blocks across the entire fleet without a binary
  update.
- Forward-incompatibility window: every Core release since v25 has the
  miner-side clamp; camlcoin still does not, ~9 months later.

---

## BUG-12 (P0-CDIV) — `Consensus.check_timewarp_rule` cannot be used as the miner-side clamp because it short-circuits on `enforce_bip94=false`

**Severity:** P0-CDIV. Companion to BUG-11. A reader/maintainer who
sees BUG-11 may naively wire `Consensus.check_timewarp_rule` into the
miner path, since the function name is suggestive. But:

```ocaml
let check_timewarp_rule ~(height : int) ~(header_time : int32)
    ~(prev_block_time : int32) ~(network : network_config) : bool =
  if not network.enforce_bip94 then true  (* Only enforced on testnet4 *)
  else if height mod difficulty_adjustment_interval <> 0 then true
  else
    Int32.compare header_time
      (Int32.sub prev_block_time (Int32.of_int max_timewarp)) >= 0
```

The first line short-circuits to `true` on every network where
`enforce_bip94 = false` (mainnet, testnet3, regtest, signet). This
matches Core's **receive-side** semantics (validation.cpp:4097-4105)
but is wrong for the **miner-side** clamp (miner.cpp:41-45, "on all
networks").

Two separate helpers are required:
1. `check_timewarp_rule_recv` — the existing predicate (gated on
   `enforce_bip94`). Used by validation.ml + sync.ml.
2. `miner_min_time` — Core's `GetMinimumTime`. Applied unconditionally
   at retarget boundaries.

Failing to make this distinction is what allows BUG-11 to persist: the
existing receive-side predicate cannot just be called from
mining.ml without breaking on the mainnet path (since the receive-side
predicate is correctly gated and would no-op on mainnet, leaving the
miner-side clamp unimplemented).

**File:** `lib/consensus.ml:836-843` (receive-side predicate, correctly
gated); `lib/mining.ml:418-419` (the call site that should use a
DIFFERENT, unconditional helper).

**Core ref:** `bitcoin-core/src/validation.cpp:4097-4105` (receive-side,
gated on enforce_BIP94); `bitcoin-core/src/node/miner.cpp:41-45`
(miner-side, unconditional).

**Impact:** design-level guidance on the BUG-11 fix. A naive 1-line
graft of `check_timewarp_rule` into mining.ml fails closed (no-op on
mainnet) instead of failing open with a clear error.

---

## BUG-13 (P0) — `UpdateTime` equivalent absent

**Severity:** P0. Bitcoin Core's `UpdateTime` (miner.cpp:49-65) is
called by `BlockAssembler::CreateNewBlock` after the template is built
and refreshes the template's `nTime` to `max(GetMinimumTime, NodeClock::now())`.
This is what keeps a template that sits in a miner's cache for >1s
ticking forward — without it, the template's timestamp is frozen at
create-time, and submitblock-side `time-too-old` (timestamp < MTP) /
`time-too-new` (timestamp > now + 2h) checks would fail on a stale
template.

camlcoin's `mining.ml` has NO `update_time` equivalent. The template
returned by `create_block_template` has `header.timestamp` fixed at
template-creation time. A miner that:
1. calls `getblocktemplate` at T,
2. searches for a nonce for 60s,
3. sends `submitblock` at T+60,

ships a block with `nTime = T`. If wall-clock has advanced past
`T + MAX_FUTURE_BLOCK_TIME` on a long-poll wait (rare, but a 1.5h
search on regtest hits this), the submit succeeds because the
camlcoin-side `check_block_header` also uses Unix wall-clock at the
moment of submit (validation.ml:984) — so submit-side and Core peers
might disagree. A peer that receives the block at T+60 with `nTime=T`
sees a timestamp 60s in the past — fine. But the receive-side BIP-94
check at a retarget boundary sees a timestamp 60s in the past of the
miner's local view, which compounds BUG-11.

Combined with BUG-11, a long-poll wait on a retarget-boundary template
locks in a `nTime` that violates BIP-94 — the camlcoin miner has no
opportunity to refresh.

**File:** `lib/mining.ml` (entire module, no `update_time` function).

**Core ref:** `bitcoin-core/src/node/miner.cpp:49-65`.

**Impact:** stale-template windows; cross-cite BUG-11; cross-impl
divergence on long-poll mining.

---

## BUG-14 (P0) — `UpdateTime` would need to recompute `nBits` on min-difficulty networks; that path is also missing

**Severity:** P0. Core's `UpdateTime` (miner.cpp:60-62):

```cpp
// Updating time can change work required on testnet:
if (consensusParams.fPowAllowMinDifficultyBlocks) {
    pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, consensusParams);
}
```

On `fPowAllowMinDifficultyBlocks = true` networks (testnet3, testnet4,
regtest), the difficulty itself can change when the timestamp crosses a
certain threshold (Core's `>2 * 10 minutes after previous` testnet
special rule). camlcoin's miner emits the bits captured at
template-create time (mining.ml:421-444 via `Consensus.get_next_work_required`)
and never refreshes them. A 25-min long-poll wait on testnet4 with a
miner that originally had non-min-difficulty bits would ship a template
with stale bits; Core peers would recompute and reject as `bad-diffbits`.

**File:** `lib/mining.ml` (entire module, no `UpdateTime`-equivalent
nBits recompute).

**Core ref:** `bitcoin-core/src/node/miner.cpp:60-62`.

**Impact:** stale-bits long-poll window on testnet4; cross-impl
divergence.

---

## BUG-15 (P2) — `MAX_FUTURE_BLOCK_TIME = 7200` scattered with no shared constant

**Severity:** P2 (cosmetic / consistency). The 2-hour future-time
allowance appears in 4 places with 2 forms:
- `lib/validation.ml:984` — `Int32.add (...) 7200l` (int32)
- `lib/sync.ml:233` — `let max_future_block_time_secs = 7200` (named int)
- `lib/sync.ml:288` — uses `max_future_block_time_secs`
- `lib/sync.ml:837` — `Unix.gettimeofday () +. 7200.0` (float)
- `lib/sync.ml:3830` — `Unix.gettimeofday () +. 7200.0` (float)

The named constant in `sync.ml:233` is not reused by validation.ml or
the other sync.ml call sites. Should be one named constant in
`consensus.ml` (cf. `max_timewarp = 600` at consensus.ml:26).

**File:** `lib/validation.ml:984`, `lib/sync.ml:233/288/837/3830`.

**Core ref:** `bitcoin-core/src/chain.h::MAX_FUTURE_BLOCK_TIME = 2 * 60 * 60`.

**Impact:** future BIP-revisions to this constant (unlikely, but
possible) require 4 separate edits; risk of one being missed.

---

## BUG-16 (P1) — `NodeClock::now()`-equivalent missing; uses raw `Unix.gettimeofday`

**Severity:** P1. Bitcoin Core uses `NodeClock::now()` (`util/time.cpp`)
which honors the median time offset accumulated from peer version
messages (the `nTimeOffset` field in CNode). A node that sees a +5min
median peer skew adjusts its `now` reference accordingly, ensuring
consistent timestamp validation across the network.

camlcoin's timestamp checks all use raw `Unix.gettimeofday ()`:
- `validation.ml:984` — `Int32.add (Int32.of_float (Unix.time ())) 7200l`
- `sync.ml:837` — `Unix.gettimeofday () +. 7200.0`
- `sync.ml:3830` — same
- `mining.ml:418` — `let now = Int32.of_float (Unix.gettimeofday ()) in`

There is no `peer_manager.median_time_offset` accumulator, no
adjustment, no `node_clock` module. A camlcoin node with a 5-min
forward-skewed clock would accept blocks Core would reject (since Core
sees `now` as 5min earlier via peer-median); a camlcoin node with a
5-min backward-skewed clock would reject blocks Core would accept. On
mainnet this is a defense-in-depth gap (since timestamps are not
consensus); on signet/testnet the practical effect is larger.

**File:** `lib/validation.ml:984`, `lib/sync.ml:837/3830`,
`lib/mining.ml:418`; `lib/peer_manager.ml` (no `median_time_offset`).

**Core ref:** `bitcoin-core/src/util/time.cpp::NodeClock`,
`bitcoin-core/src/net.cpp::CNode::nTimeOffset`.

**Impact:** node-clock divergence; defense-in-depth gap.

---

## BUG-17 (P1) — Reject-string parity: `time-too-new` / `time-too-old` tokens diverge

**Severity:** P1. Core emits short, machine-parseable reject tokens:
- `time-too-new`
- `time-too-old`
- `time-timewarp-attack` (BIP-94)
- `bad-diffbits`
- `bad-version(0x%08x)`
- `bad-signet-blksig`

camlcoin emits free-form English for some, Core tokens for others:
- `time-timewarp-attack` ✓ (validation.ml:99 emits Core token)
- `"Block timestamp too far in future"` ✗ (validation.ml:986 — should
  be `time-too-new`)
- `"Header timestamp too far in future"` ✗ (sync.ml:838, 3831 — same)
- `"Header timestamp not greater than median-time-past"` ✗
  (sync.ml:843, 3836 — should be `time-too-old`)

Reject-token parity matters for RPC consumers that parse the reject
reason from `submitblock` / `getrawmempool` rejections, plus
operator-tooling (`logger | grep 'time-too-'` alerts). The fleet
pattern observed in W155/W156 — wire-format reject-string drift — is
a fleet-wide governance gap.

**File:** `lib/validation.ml:986`, `lib/sync.ml:838/843/3831/3836`.

**Core ref:** `bitcoin-core/src/validation.cpp:4093, 4108-4110`.

**Impact:** wire-format reject-string drift; operator tooling /
log-grep alerts that match Core tokens never fire on camlcoin.

---

## BUG-18 (P1) — `bad-version(0x%08x)` reject-token absent

**Severity:** P1. Continuation of BUG-17. Core emits
`strprintf("bad-version(0x%08x)", block.nVersion)` for the BIP-34/66/65
version-floor rejects (validation.cpp:4116). camlcoin emits:

```ocaml
| BlockBadVersion -> "block version too low for active soft forks"
```

This is one consequence-blanket string for THREE distinct rejection
causes (BIP-34, BIP-66, BIP-65). Wallet authors / pool operators that
parse the reject reason to identify whether the issue is "version 1
block past BIP-34", "version 2 block past BIP-66", or "version 3 block
past BIP-65" cannot.

**File:** `lib/validation.ml:97` (string), `lib/validation.ml:830-835`
(three branches all funneling to one error variant).

**Core ref:** `bitcoin-core/src/validation.cpp:4116`.

**Impact:** wire-format reject-string parity; cross-cite BUG-17.

---

## BUG-19 (P1) — `compute_block_version` deployment selection has no Signet branch

**Severity:** P1. `mining.ml:455-459`:

```ocaml
let taproot_dep = match chain.network.name with
  | "mainnet" -> Consensus.mainnet_taproot
  | "testnet4" -> Consensus.testnet4_taproot
  | _ -> Consensus.regtest_taproot
in
```

The fall-through `_ -> regtest_taproot` means any future Signet path
mines templates signaling Taproot with regtest's parameters
(`threshold=108, period=144`, `start_time=always_active`). On signet,
Taproot has been active from block 1 (cf. core chainparams.cpp:460
`SegwitHeight = 1`), so the SIGNALING does not actually matter for
activation; but the BIP-9 `vbavailable` JSON field emitted to
miners (mining.ml:626-630) would mis-report deployment metadata.

Same gap for testnet3 — `Testnet3` falls through to regtest's
deployment record.

**File:** `lib/mining.ml:455-460`.

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:468-473`
(signet's BIP-9 testdummy deployment uses signet-specific bit/threshold).

**Impact:** GBT JSON `vbavailable` metadata divergence on
signet/testnet3; benign on the activation side (Taproot already buried
on all five Core networks).

---

## BUG-20 (P1) — `rpc.ml:225 Consensus.Testnet3 -> Consensus.mainnet_taproot` is wrong

**Severity:** P1. `lib/rpc.ml:222-225`:

```ocaml
| Consensus.Mainnet  -> Consensus.mainnet_taproot
| Consensus.Testnet4 -> Consensus.testnet4_taproot
| Consensus.Regtest  -> Consensus.regtest_taproot
| Consensus.Testnet3 -> Consensus.mainnet_taproot
```

The `Testnet3 -> mainnet_taproot` branch is incorrect. Testnet3's
Taproot deployment in Core (chainparams.cpp:233-237) has different
`start_time/timeout/min_activation_height` from mainnet (testnet3
activated Taproot far earlier than mainnet). Using mainnet's taproot
record on a hypothetical testnet3 path would cause the BIP-9 state
machine to mis-report the deployment status (e.g., `getdeploymentinfo
.taproot.status` would say "active" with mainnet's height instead of
testnet3's actual activation height).

Testnet3 is currently unreachable via CLI (see BUG-22), but
`Consensus.Testnet3` is a public enum variant and could be reached via
direct API consumers (the wallet module wires `Consensus.network`
directly).

**File:** `lib/rpc.ml:225`.

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:233-237`
(testnet3 BIP9 dep records).

**Impact:** wrong BIP-9 deployment-info on hypothetical testnet3 RPC
calls; latent.

---

## BUG-21 (P0-CONS) — Signet magic hardcoded; custom-signet `pchMessageStart` derivation absent

**Severity:** P0-CONS (if signet were wired). `lib/p2p.ml:21`:

```ocaml
let signet_magic = 0x40CF030Al
```

This matches default-signet (the magic derived from
`HashWriter(default_challenge).first4()`). But Core (chainparams.cpp:475-479):

```cpp
HashWriter h{};
h << consensus.signet_challenge;
uint256 hash = h.GetHash();
std::copy_n(hash.begin(), 4, pchMessageStart.begin());
```

Derives the message-start bytes from the (possibly operator-supplied)
challenge. Custom-signet deployments (Mutinynet, alpha-net,
hash-signet etc.) all have different challenges and therefore different
magics. camlcoin's hardcoded `signet_magic` only matches the default;
peers on a custom-signet network would be banned for sending
"wrong-magic" P2P frames, and camlcoin's outbound frames to a
custom-signet peer would be banned in return.

**File:** `lib/p2p.ml:21` (hardcoded constant); no
`derive_signet_magic` helper anywhere.

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:475-479`.

**Impact:** even if BUG-1..10 were fixed, custom-signet support would
not work because the wire-protocol magic is wrong.

---

## BUG-22 (P0) — `--network=testnet4` not accepted; the label `testnet` silently maps to testnet4

**Severity:** P0. `bin/main.ml:10-18`:

```ocaml
let network_arg =
  let networks = Arg.enum [
    ("mainnet", `Mainnet);
    ("testnet", `Testnet);
    ("regtest", `Regtest);
  ] in
  ...
```

There is no `("testnet4", ...)` mapping. Users passing `--network=testnet4`
get an "invalid argument" error. Meanwhile, users passing
`--network=testnet` get **testnet4 consensus parameters** silently —
`main.ml:516, 558`:

```ocaml
let network_cfg = match network with
  | `Mainnet -> Camlcoin.Consensus.mainnet
  | `Testnet -> Camlcoin.Consensus.testnet4
  | `Regtest -> Camlcoin.Consensus.regtest
in
```

The flag-label drift causes two distinct UX failures:
1. Users who explicitly want testnet4 (the active Bitcoin test
   network) can't say so. The Core convention since v28 is `-testnet4`.
2. Users who expect `--network=testnet` to mean testnet3 (the
   legacy convention from Core v27 and earlier) get testnet4 silently.
   Cross-cite W155 BUG-14: the data_dir for this path is
   `~/.camlcoin/testnet3` (cli.ml:176), which labels the directory as
   testnet3 even though the chain inside is testnet4.

**File:** `bin/main.ml:10-18` (enum), `bin/main.ml:516, 558`
(wiring), `lib/cli.ml:174-177` (data_dir for `Testnet`).

**Core ref:** `bitcoin-core/src/init.cpp::-testnet` (= testnet3) +
`-testnet4` (since v28).

**Impact:** silent network mis-selection; data_dir / chain mismatch;
cross-impl operator confusion.

---

## BUG-23 (P1) — `data_dir = ~/.camlcoin/testnet3` for `--network=testnet`, but the actual chain is testnet4

**Severity:** P1. `lib/cli.ml:174-177`:

```ocaml
| `Testnet -> { default_config with
    network = `Testnet;
    data_dir = Filename.concat (Sys.getenv "HOME") ".camlcoin/testnet3";
    rpc_port = 18332; p2p_port = 18333 }
```

The data_dir is labeled `testnet3` but the consensus is `testnet4`
(see BUG-22). The RPC port `18332` matches Core's `testnet3` default;
`testnet4` Core uses port `48332`/`48333` per
camlcoin's own `start_testnet4.sh`. A user who:
1. Runs `camlcoin --network=testnet`,
2. Sees files appear under `~/.camlcoin/testnet3/`,
3. Concludes they are syncing testnet3,
4. Loads testnet3 wallet files,

ends up with a UTXO snapshot that has nothing to do with testnet3 (the
testnet4 genesis hash is different — consensus.ml:702-703 vs
consensus.ml:656-657). The wallet derivation paths still resolve, but
no on-chain matches occur.

**File:** `lib/cli.ml:171-181`.

**Core ref:** Core convention `~/.bitcoin/testnet4/` for testnet4.

**Impact:** operator confusion; data_dir / chain interop break with
Core (cannot move the camlcoin datadir to a Core node and expect Core
to recognize it as testnet4).

---

## Summary

**Bug count:** 23 (BUG-1 through BUG-23).

**Severity distribution:**
- **P0-CONS:** 7 (BUG-1, BUG-2, BUG-3, BUG-4, BUG-9, BUG-10, BUG-21)
- **P0-CDIV:** 2 (BUG-11, BUG-12)
- **P0:** 7 (BUG-5, BUG-6, BUG-7, BUG-8, BUG-13, BUG-14, BUG-22)
- **P1:** 6 (BUG-16, BUG-17, BUG-18, BUG-19, BUG-20, BUG-23)
- **P2:** 1 (BUG-15)

Total: 7 + 2 + 7 + 6 + 1 = 23. ✓

**Fleet patterns confirmed:**
- **12-CONSECUTIVE-QUAD camlcoin pipeline drift** (W143-W156, now W157):
  block_import.ml-bypass at W143 → assume-valid scope creep / no
  TestBlockValidity at W154 → mode="proposal" absent at W155 → signet
  consensus enforcement absent at W157. Each successive audit finds a
  fresh "Core-side gate present, camlcoin-side absent" instance.
- **Carry-forward re-anchored**: W155 BUG-14 (P1 RPC) → W157 BUG-3
  (P0-CONS consensus). Severity elevated because the consequence now
  reaches the consensus layer, not just RPC.
- **Two-pipeline guard 17th distinct extension** (BUG-12): the
  miner-side and receive-side BIP-94 timewarp checks need to be
  DIFFERENT predicates (receive-side gated on `enforce_bip94`,
  miner-side unconditional). Existing `check_timewarp_rule` is correctly
  receive-side, but the miner-side helper is absent and the natural
  graft-in fails closed.
- **Comment-as-confession 14th+ camlcoin instance** (BUG-11): inline
  `(* Core miner.cpp:52: nNewTime = max(GetMinimumTime(pindexPrev,
  ...), now) *)` — the comment cites Core's UpdateTime line 52 but
  stops short of citing line 41-45 where the BIP-94 clamp lives. Code
  KNEW it was implementing GetMinimumTime, implemented only half.
- **Fleet-wide CheckSignetBlockSolution absent** (W143 fleet pattern,
  re-anchored at W157): camlcoin is the 8th+ confirmed fleet instance.
  blockbrew (W143 BUG-9), haskoin (W142 BUG-1 cross-cite), rustoshi
  (W143 BUG-7), ... — pattern crystallizing as fleet-wide.
- **Wire-format reject-string parity slippage** (BUG-17, BUG-18):
  free-form English vs Core tokens. 9 of camlcoin's reject strings
  diverge across this audit alone; W155 BUG-9 + W125 sweep already
  reported the same.
- **Wiring-look-but-no-wire** (BUG-7, BUG-8, BUG-21): `signet_magic`
  defined but never sourced; `Consensus.Testnet3` enum-variant exists
  but no CLI path; `core_chain_name "signet" -> "signet"` documented
  in rpc.ml but no internal name "signet" can ever exist. ~5 instances
  in this audit.
- **Label drift** (BUG-22, BUG-23): CLI label `testnet` → consensus
  `testnet4` → data_dir `testnet3`. Three-way naming inconsistency.

**Top three findings:**

1. **BUG-1 + BUG-2 + BUG-3 + BUG-4 + BUG-9 + BUG-10 cluster
   (P0-CONS, signet consensus enforcement entirely absent)** —
   `CheckSignetBlockSolution`, `SignetTxs`, `FetchAndClearCommitmentSection`,
   `ComputeModifiedMerkleRoot`, `SIGNET_HEADER = 0xecc7daa2`, the
   default-signet challenge bytes, and the `signet_blocks`/`signet_challenge`
   chainparam fields ALL absent. Even if BUG-6/BUG-7/BUG-8 were fixed
   (network selectable), every signet block with arbitrary signet
   signature would be accepted. **Carry-forward of W155 BUG-14
   elevated P1 → P0-CONS** — the W155 audit reported the RPC-surface
   consequence; W157 surfaces the consensus-validation consequence.
   First instance of an 8th-impl fleet pattern reaching the consensus
   layer in camlcoin.

2. **BUG-11 + BUG-12 cluster (P0-CDIV, BIP-94 MAX_TIMEWARP clamp
   absent on miner-side)** — Core's `GetMinimumTime` (miner.cpp:41-45)
   applies the clamp on ALL networks per the explicit "makes future
   activation safer" comment; camlcoin's `mining.ml:418-419` skips it
   entirely. The natural graft `Consensus.check_timewarp_rule` is
   gated on `enforce_bip94` and would no-op on mainnet (BUG-12), so
   the fix requires a SEPARATE miner-side helper. Carry-forward of
   W154 BUG-7, **re-anchored at W157 with the BUG-12 design
   constraint** to guide a clean fix. Testnet4 retarget-boundary
   templates from a clock-skewed camlcoin miner are wire-DoS today;
   the day BIP-94 universalizes, camlcoin miners stop producing
   valid retarget blocks fleet-wide.

3. **BUG-21 (P0-CONS, signet magic hardcoded, custom-signet
   pchMessageStart derivation absent)** — `p2p.ml:21
   signet_magic = 0x40CF030Al` matches only default-signet. Core
   derives `pchMessageStart` from `HashWriter(challenge).first4()`,
   so custom-signet deployments (Mutinynet, alpha-net,
   hash-signet) all have different magics. Even if BUG-1..10 were
   fixed, custom-signet support would not work because the wire
   magic is wrong. Combined with BUG-5 (`-signetchallenge=` flag
   absent), camlcoin is locked to default-signet-only — a regression
   from Core's flexible signet design.

**Recommended fix priority:**
1. BUG-11 + BUG-12 (1-day fix; miner-side timewarp clamp; closes
   the testnet4 wire-DoS today, future-proofs for mainnet BIP-94
   universalization).
2. BUG-1..10 + BUG-21 cluster (1-2-week fix; full signet support;
   ~600 LOC mirror of Core's signet.cpp + signet.h + SigNetParams).
3. BUG-22 + BUG-23 (15-min cosmetic fix; CLI/data-dir label parity).
4. BUG-17 + BUG-18 (1-hour reject-string sweep).
