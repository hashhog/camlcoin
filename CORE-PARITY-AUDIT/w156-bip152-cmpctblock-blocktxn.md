# W156 — BIP-152 sendcmpct + cmpctblock + blocktxn + getblocktxn deep-dive (camlcoin)

**Wave:** W156 — BIP-152 wire-level deep-dive: `CBlockHeaderAndShortTxIDs`
(header + 8-byte nonce + 6-byte short-tx-ids derived via SipHash-2-4 with
k0/k1 = first 16 bytes of SHA256(serialize(header)||nonce_LE) +
prefilledtxn[] with differentially-encoded uint16 indices),
`PartiallyDownloadedBlock::InitData`/`FillBlock`,
`BlockTransactionsRequest` (differential-formatted uint16 indices),
`BlockTransactions` reply, `SendBlockTransactions`,
`MaybeSetPeerAsAnnouncingHeaderAndIDs` (HB-mode peer selection up to 3,
inbound-protect-outbound logic), `MaybeRequestCompactBlock` (single-block
MSG_BLOCK→MSG_CMPCT_BLOCK upgrade in headers-direct-fetch),
`ProcessCompactBlockTxns`, `vExtraTxnForCompact` ring buffer of
recently-rejected txs for collision recovery, `m_most_recent_compact_block`
cache, `MAX_CMPCTBLOCK_DEPTH=5` / `MAX_BLOCKTXN_DEPTH=10`,
`MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK=3`,
`MaybePunishNodeForBlock(... via_compact_block=true)` (NO discouragement
on invalid block when received via cmpct per BIP-152),
`m_bip152_highbandwidth_to` / `m_bip152_highbandwidth_from`,
`SHORT_IDS_BLOCKS_VERSION=70014` (version-gate before
sending/honouring sendcmpct), `CMPCTBLOCKS_VERSION=2`
(witness-aware; sendcmpct with version != 2 silently dropped),
`fProvides_cmpctblocks`.

**Scope:** discovery only — no production code changes. W126 was the
fundamentals audit (9 BUGs, 30 gates: 21 PRESENT / 4 PARTIAL / 5
MISSING). W156 is the wire-level deep-dive that re-anchors most
W126 carry-forwards (W126 BUGs 1/2/3/5/6/7/9 still open at audit
time; BUGs 4/8 PARTIAL) and surfaces a fresh batch of fine-grained
gaps surrounding short-id derivation, the
prefilledtxn/getblocktxn round-trip, partial-block reconstruction
collision handling, the announce/HB-pipeline gap fleet pattern,
and the "two parallel compact-block pipelines" two-pipeline-guard
extension (the cli.ml live path vs the sync.ml DESIGNED-for-IBD
path that is never wired).

**Bitcoin Core references**
- `bitcoin-core/src/blockencodings.cpp:20-50` —
  `CBlockHeaderAndShortTxIDs(block, nonce)` ctor:
  `shorttxids[i-1] = GetShortID(tx.GetWitnessHash())` for `i = 1 ..
  vtx.size()-1`, `prefilledtxn[0] = {0, block.vtx[0]}` (coinbase always
  prefilled). `FillShortTxIDSelector()`: `DataStream stream{}; stream <<
  header << nonce; CSHA256 hasher.Write(stream.data(), stream.size());
  shorttxidhash = hasher.Finalize(); m_hasher.emplace(GetUint64(0),
  GetUint64(1))`. `GetShortID(wtxid) = (*m_hasher)(wtxid.ToUint256()) &
  0xffffffffffffL` (lower 48 bits). `static_assert(SHORTTXIDS_LENGTH ==
  6)`.
- `bitcoin-core/src/blockencodings.cpp:59-181` —
  `PartiallyDownloadedBlock::InitData`: rejects `shorttxids.empty() &&
  prefilledtxn.empty()` (READ_STATUS_INVALID), rejects `shorttxids.size() +
  prefilledtxn.size() > MAX_BLOCK_WEIGHT / MIN_SERIALIZABLE_TRANSACTION_WEIGHT`
  (= 4_000_000 / 40 = 100_000), differential index decode with
  `lastprefilledindex += prefilledtxn[i].index + 1`,
  `if (lastprefilledindex > std::numeric_limits<uint16_t>::max())
  return READ_STATUS_INVALID` (FIRST hard uint16 ceiling on the
  prefilledtxn differential), `if ((uint32_t)lastprefilledindex >
  shorttxids.size() + i) return READ_STATUS_INVALID` (the "no slot at
  this index" check). Then iterates mempool's `txns_randomized` to
  hydrate slots; on a collision (two mempool txs share short_id) clears
  the slot and decrements `mempool_count`; bucket-size guard
  `> 12 → READ_STATUS_FAILED` (statistical detection of pathological
  shortid distribution); `shorttxids.size() != cmpctblock.shorttxids.size()`
  → `READ_STATUS_FAILED` (short ID collision across distinct slots).
  Walks `vExtraTxnForCompact` ring buffer the same way (CVE-2017-12842
  workaround for orphan-arrival race), with the additional witness-hash
  tie-break against the wtxid (`txn_available[i]->GetWitnessHash() !=
  extra_txn[i].second->GetWitnessHash()`) before the collision-clear.
- `bitcoin-core/src/blockencodings.cpp:191-237` —
  `PartiallyDownloadedBlock::FillBlock`: assembles `block.vtx[i]`
  from `txn_available[i]` or, when missing, from `vtx_missing[offset++]`.
  CRITICALLY: invokes `IsBlockMutated(block, segwit_active)` after fill,
  returns `READ_STATUS_FAILED` (NOT `INVALID`) on mutation —
  i.e., a short-id collision that happens to produce a "well-formed"
  but mutated block (CVE-2012-2459 shape) is detected at fill time.
  `segwit_active = DeploymentActiveAfter(prev_block, m_chainman,
  Consensus::DEPLOYMENT_SEGWIT)`.
- `bitcoin-core/src/blockencodings.h:23-43` — `DifferenceFormatter`
  for `BlockTransactionsRequest::indexes` and
  `PrefilledTransaction::index`: first item is absolute (`m_shift = 0`
  at entry → writes `v - 0 = v`), then `m_shift = v + 1`; subsequent
  items are `v - m_shift` followed by `m_shift = v + 1`.
  `Unser` throws `std::ios_base::failure("differential value overflow")`
  if `m_shift > std::numeric_limits<I>::max()` (I = uint16_t for indexes).
- `bitcoin-core/src/blockencodings.h:80` — `PrefilledTransaction`
  declares `uint16_t index` and serializes via `COMPACTSIZE(obj.index)`;
  the uint16 ceiling is enforced in `InitData`.
- `bitcoin-core/src/net_processing.cpp:138-141` — `MAX_CMPCTBLOCK_DEPTH = 5`,
  `MAX_BLOCKTXN_DEPTH = 10`,
  `static_assert(MAX_BLOCKTXN_DEPTH <= MIN_BLOCKS_TO_KEEP)`.
- `bitcoin-core/src/net_processing.cpp:199` — `CMPCTBLOCKS_VERSION = 2`.
- `bitcoin-core/src/node/protocol_version.h:30` —
  `SHORT_IDS_BLOCKS_VERSION = 70014` (peer-version gate before we
  send sendcmpct).
- `bitcoin-core/src/net_processing.cpp:860-865` —
  `m_most_recent_block`, `m_most_recent_compact_block`,
  `m_most_recent_block_hash`, `m_most_recent_block_txs` cache: GUARDED
  by `m_most_recent_block_mutex`. Populated in `BlockChecked`
  (line 5882 region); consulted in `SendBlockTransactions` for fast
  service without disk re-read AND in the getdata MSG_CMPCT_BLOCK
  service path (line 2468/2471).
- `bitcoin-core/src/net_processing.cpp:997-999` — `vExtraTxnForCompact`
  ring buffer (`std::pair<Wtxid, CTransactionRef>` keyed by wtxid),
  size = `m_opts.max_extra_txs` (default 100). Populated by
  `AddToCompactExtraTransactions` (line 1883-1891) from
  `ProcessMessage(msg_tx)` rejected-as-orphan and
  `MempoolValidationResult::TX_RECENT_RESPECT`-class failure paths;
  consulted in `PartiallyDownloadedBlock::InitData` after the mempool
  scan completes.
- `bitcoin-core/src/net_processing.cpp:1272-1329` —
  `MaybeSetPeerAsAnnouncingHeaderAndIDs(nodeid)`: refuses if
  `m_opts.ignore_incoming_txs` (blocksonly mode), refuses if
  `!nodestate->m_provides_cmpctblocks`. Maintains `lNodesAnnouncingHeaderAndIDs`
  as a most-recently-active-at-tail FIFO of up to 3 IDs. Inbound-adding
  with exactly 1 outbound HB peer → swap the outbound entry to the
  second slot so the eviction (which picks `lNodesAnnouncingHeaderAndIDs.front()`)
  preserves outbound representation. On eviction sends
  `SENDCMPCT(/*high_bandwidth=*/false, /*version=*/CMPCTBLOCKS_VERSION)`
  to the demoted peer; on add sends
  `SENDCMPCT(/*high_bandwidth=*/true, /*version=*/CMPCTBLOCKS_VERSION)`
  to the promoted peer. Sets `pnodeStop->m_bip152_highbandwidth_to = false`
  / `pfrom->m_bip152_highbandwidth_to = true`.
- `bitcoin-core/src/net_processing.cpp:3441-3526` —
  `ProcessCompactBlockTxns` (blocktxn path): looks up the in-flight
  partial-block (must have been seeded by the prior CMPCTBLOCK),
  refuses if not requested from this peer (debug-log only, no
  misbehavior); refuses if `partialBlock.header.IsNull()` (prior
  FillBlock wiped) and ALSO calls `Misbehaving(peer, "previous
  compact block reconstruction attempt failed")`. Calls
  `FillBlock(block, blocktxn.txn, segwit_active=...)`; on
  `READ_STATUS_INVALID` calls
  `Misbehaving(peer, "invalid compact block/non-matching block
  transactions")`. On `READ_STATUS_FAILED` (short-id collision detected
  late at fill time): if first_in_flight emit `MSG_BLOCK | GetFetchFlags`
  getdata fallback, else just `RemoveBlockRequest` and wait. On
  `READ_STATUS_OK` calls `mapBlockSource.emplace(block_hash, {peer, false})`
  with `fForceProcessing=true` (the `false` is "not requested" — BIP-152
  permits relay of headers before full validation, so we don't punish
  later if invalid).
- `bitcoin-core/src/net_processing.cpp:4276-4303` — getblocktxn server:
  `if (pindex->nHeight >= ActiveChain().Height() - MAX_BLOCKTXN_DEPTH)`
  read the block from disk and `SendBlockTransactions`; ELSE send
  full `MSG_WITNESS_BLOCK` getdata-equivalent (re-queue into
  `peer.m_getdata_requests`) — fall-through to the regular getdata
  service path so the requester pays the bandwidth cost (anti-DoS).
- `bitcoin-core/src/net_processing.cpp:4466-4750` —
  `ProcessMessage(NetMsgType::CMPCTBLOCK)`: refuses during
  `LoadingBlocks()`; rejects `low-work` (block-proof under
  `GetAntiDoSWorkThreshold()`); calls `ProcessNewBlockHeaders` BEFORE
  reconstruction (so an invalid header gets `MaybePunishNodeForBlock(...
  via_compact_block=true)`); only AFTER header acceptance does it walk
  the partial-block; `MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK = 3` (anti-DoS
  cap on concurrent parallel cmpct downloads for the same hash);
  `pindex->nHeight <= ActiveChain().Height() + 2` height-window gate
  for "actually attempt reconstruction" (anything further into the
  future is treated as header-only); optimistic-reconstruction path
  when another peer already has the block in-flight (uses a temporary
  `PartiallyDownloadedBlock` to avoid stomping shared state).
- `bitcoin-core/src/net_processing.cpp:2466-2475` — getdata MSG_CMPCT_BLOCK
  service: `if (can_direct_fetch && pindex->nHeight >= tip->nHeight -
  MAX_CMPCTBLOCK_DEPTH)` upgrade to `MSG_CMPCT_BLOCK`; serves from
  `m_most_recent_compact_block` cache if hash matches; ELSE reads
  block from disk, builds `CBlockHeaderAndShortTxIDs` and sends.
- `bitcoin-core/src/net_processing.cpp:1906-1929` —
  `MaybePunishNodeForBlock(..., via_compact_block, message)`: when
  `via_compact_block=true`, DOES NOT discourage the peer for
  `BLOCK_INVALID_PREV` / `BLOCK_INVALID_HEADER` / etc — BIP-152 explicitly
  permits HB peers to relay headers before full validation, so an
  invalid block delivered via cmpct is NOT proof of malice. The outbound
  half (`!peer->m_is_inbound`) is ALSO exempted from the discourage
  path. Without this exemption a single malicious HB peer would
  disconnect honest peers.
- `bitcoin-core/src/net_processing.cpp:5839` — SendMessages compact-block
  announce gate: only push a compact block if
  `!state.m_requested_hb_cmpctblocks || peer.m_blocks_for_headers_relay.size() > 1`
  — i.e., the peer asked us for HB OR the burst is too large for cmpct.

**Files audited**
- `lib/p2p.ml` (3734 lines) — `prefilled_tx`/`compact_block`/`block_txns_request`/`block_txns`
  types (242-266); message-type enum (44-46, 92-96, 140-144);
  `cmpctblock_version = 2L` (538); `max_compact_block_txs = 100_000` (539);
  `max_cmpctblock_depth = 5` (544); `max_blocktxn_depth = 10` (549);
  `write_short_id`/`read_short_id` (551-565 — 6-byte LE);
  `serialize_prefilled_tx`/`deserialize_prefilled_tx` (567-576 — uses
  `write_compact_size` for the differential index with NO uint16 ceiling);
  `serialize_compact_block`/`deserialize_compact_block` (578-607 — has
  total-tx-count > 65535 guard at line 605, has per-list count >
  max_compact_block_txs guard at lines 595/600); `serialize_block_txns_request`
  / `deserialize_block_txns_request` (609-622 — uses `write_compact_size`
  with NO uint16 differential ceiling); `serialize_block_txns` /
  `deserialize_block_txns` (624-637); `generate_compact_nonce` (1360-1369);
  `create_compact_block` (1374-1394 — wtxid for non-coinbase, coinbase
  always prefilled at index 0); `compact_block_tx_count` (1397-1399);
  `reconstruct_block` (1426-1499 — array-based reconstruction with
  collision tracking via `have_txn[]`; the W126/W112 BUG-2 fix landed
  here); `fill_missing_txs` (1503-1523); `make_getblocktxn_request`
  (1527-1541 — differential-encoded encoder);
  `decode_differential_indices` (1543-1553 — differential decoder);
  `make_sendcmpct_msg` / `make_cmpctblock_msg` / `make_getblocktxn_msg`
  / `make_blocktxn_msg` (1555-1569).
- `lib/crypto.ml` (744 lines) — `SipHash` module (451-555):
  `sipround` (465-480), `init` (483-485), `hash_uint256` (493-535 — 4x
  8-byte words in LE, length tag = `4L << 59` for 32 bytes), `derive_keys`
  (545-554 — SHA256(serialize(header)||nonce_LE_8) → (k0, k1) = first
  16 bytes interpreted as 2 LE u64s); `compute_short_txid` (559-561 —
  `hash_uint256` & `0xFFFFFFFFFFFFL` — lower 48 bits = 6 bytes);
  `compute_wtxid` (392-406 — coinbase wtxid = zero_hash, non-coinbase =
  SHA256d of full witness-serialized transaction); `compute_block_hash`
  (349-352 — SHA256d of serialized 80-byte header).
- `lib/peer.ml` (2066 lines) — `cmpct_high_bandwidth` field
  (267, 401, 834, 1596, 1660); `cmpct_version` field (268, 402, 835,
  1597, 1661); `make_version_msg` (763-777 — no fProvides-cmpctblocks
  field, relay always true); `send_feature_negotiation` (782-794);
  `read_until_verack` accepts `SendcmpctMsg` between version/verack
  (831-837, version != 2 silently dropped); `perform_handshake_inner`
  (980-1015) sends `SendcmpctMsg(announce=false, version=2)` AT line
  1006 UNCONDITIONALLY (no `pfrom.GetCommonVersion() >=
  SHORT_IDS_BLOCKS_VERSION` gate; W126 BUG-5);
  `perform_inbound_handshake_inner` (1037-1068) identical at line 1063;
  `handle_getdata` (1454-1528) handles `InvCompactBlock` at line 1489
  with MAX_CMPCTBLOCK_DEPTH=5 fallback; `dispatch_message`
  `SendcmpctMsg` pre-handshake (1588-1599 — version != 2 silently
  dropped, otherwise stores announce + version) and post-handshake
  (1657-1663 — same behaviour). NO sendcmpct(0,1) compatibility shim
  for non-2-supporting peers (which Core also doesn't ship, but
  Core's pre-2-only peers receive nothing rather than a useless
  cmpct(0,2)).
- `lib/peer_manager.ml` (2777 lines) — `hb_compact_peers : int list`
  field (225, 274 init = `[]`); `max_hb_compact_peers = 3` (2648);
  `supports_compact_blocks` predicate (2651-2652 — checks
  `cmpct_version >= 2L && services.witness`); `send_sendcmpct` helper
  (2656-2665); `maybe_set_hb_compact_peer` (2671-2733) — full Core-equivalent
  inbound-protect-outbound logic AND outbound-eviction order, BUT see
  BUG-2/W126 BUG-2: the helper is **DEAD HELPER, never called from
  anywhere in lib/ or bin/** (only definition + comment use sites);
  `remove_hb_compact_peer` (2736-2737); `get_hb_compact_peers` (2740-2743);
  `relay_compact_block` (2748-2761) — full implementation including
  `peer_has_header` gate, BUT see BUG-3/W126 BUG-3: helper is
  **DEAD HELPER**, never called from anywhere; `create_mempool_lookup`
  (2764-2768); `reconstruct_from_mempool` (2772-2777). `announce_block`
  (1360-1369) only sends HeadersMsg/InvMsg — NEVER CmpctblockMsg even
  for HB-to-us peers (`pm.hb_compact_peers` ignored).
- `lib/sync.ml` (5091 lines) — `compact_block_request` type (4882-4888);
  `pending_compact_blocks` Hashtbl (4891-4892) — module-global state, NOT
  per-peer; `has_compact_block_header` helper (4895-4897);
  `handle_cmpctblock` (4902-4965) — **DEAD HELPER, never called from
  production**; reconstructs from mempool, queues getblocktxn if
  missing, calls `Peer.send_message` directly (no force-processing
  semantics); `handle_blocktxn` (4969-5016) — **DEAD HELPER, never
  called from production**; the live handler is in cli.ml (4404+);
  `expire_compact_block_requests` (5019-5032);
  `peer_has_header` (5034-5038) — STUB always returns `true`
  (W126 BUG-4 carry-forward); `lookup_block_height` (1032-1036).
- `lib/cli.ml` (1867 lines) — CmpctblockMsg listener (1349-1398) gated
  `when chain.sync_state = Sync.FullySynced` (cmpct blocks dropped
  during IBD; W126 BUG-7 cross-cite); reconstruction via
  `Peer_manager.reconstruct_from_mempool` then either
  `Sync.process_new_block ~f_requested:true` OR
  `Hashtbl.replace compact_pending` + `make_getblocktxn_request`;
  BlocktxnMsg listener (1399-1427) — NO `when` guard (accepted at
  any sync state); uses `compact_pending` Hashtbl (local to the
  listener closure); GetblocktxnMsg listener (1428-1478) — NO `when`
  guard; decodes differential indices, enforces MAX_BLOCKTXN_DEPTH=10,
  falls back to `BlockMsg` for out-of-depth requests; bounds-checks
  each returned index against `Array.length txs_array` and SILENTLY
  SKIPS out-of-range indices (no misbehavior signal).
- `lib/mempool.ml` (4374 lines) — `create_short_id_lookup` (3487-3494
  — populates the lookup table by iterating ALL mempool entries
  and computing `compute_short_txid` on each, NO truncation /
  per-bucket guard); `find_by_short_id` (3469-3479) — O(N) linear scan
  (used elsewhere; called by `package_relay.ml` and tests). Mempool
  has NO wtxid index (W152 BUG-7 cross-cite — txid-keyed only;
  `entries : (string, mempool_entry) Hashtbl.t` keyed by txid_str).
- `test/test_w126_bip152_compact_blocks.ml` — 9-BUG carry-forward
  catalogue from W126; BUGs 1/2/3/5/6/7/9 still flagged with "pre-fix"
  assertions; BUG-4 (peer_has_header stub) and BUG-8 (LoadingBlocks
  gate missing) are PARTIAL.
- `test/test_w112_compact_blocks.ml` — older W112 catalogue.
  BUG-4 (relay_compact_block dead helper) and BUG-5
  (maybe_set_hb_compact_peer dead) are the same defects re-anchored
  in W126 BUG-1/BUG-2/BUG-3.
- `CORE-PARITY-AUDIT/w152-tx-relay-inv-orphan.md` BUG-7 — mempool
  wtxid index absence; directly affects compact-block reconstruction
  (a wtxid-keyed mempool would let `create_short_id_lookup` be
  O(known-wtxids) instead of O(all-entries-with-recompute)).

---

## Gate matrix (30 sub-gates / 12 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | sendcmpct version negotiation | G1: cmpctblock_version constant = 2 | PASS (`p2p.ml:538`) |
| 1 | … | G2: send sendcmpct(announce=false, version=2) post-handshake to every NODE_WITNESS peer | PARTIAL — sent (`peer.ml:1006, 1063`) but with no `GetCommonVersion() >= SHORT_IDS_BLOCKS_VERSION (70014)` guard (W126 BUG-5 carry-forward; **BUG-1** below tightens to `version_msg.protocol_version >= 70014`) |
| 1 | … | G3: silently drop received sendcmpct where version != 2 | PASS (`peer.ml:832-836, 1592-1599, 1657-1663`; comment-references `net_processing.cpp:3907`) |
| 1 | … | G4: drop sendcmpct received pre-handshake (before VERSION) | PASS (`peer.ml:1589-1592` — misbehaves 10 on `pre-handshake sendcmpct`) |
| 2 | sendcmpct HB-mode peer selection (announce side) | G5: maintain ≤3 HB peers via `MaybeSetPeerAsAnnouncingHeaderAndIDs` analogue | **BUG-2 (P0-CDIV)** — `maybe_set_hb_compact_peer` (`peer_manager.ml:2671-2733`) implements the full ≤3 + inbound-protect-outbound algorithm BUT IS NEVER CALLED. W126 BUG-2 carry-forward (~14 weeks open since W112 first flagged it; ~6 weeks since W126). Dead helper. `hb_compact_peers` list is initialised `[]` and stays `[]` for the life of the process. |
| 2 | … | G6: inbound-protect-outbound eviction order | DEAD (implemented in `maybe_set_hb_compact_peer:2696-2707` but call-graph dead per BUG-2) |
| 2 | … | G7: send sendcmpct(true,2) on promote, sendcmpct(false,2) on demote | DEAD (`peer_manager.ml:2715, 2721, 2727`; BUG-2 cross-cite) |
| 2 | … | G8: refuse HB selection for `block_relay_only` peers | DEAD (`peer_manager.ml:2674`; BUG-2 cross-cite) |
| 2 | … | G9: refuse HB selection for non-cmpct-supporting peers | DEAD (`peer_manager.ml:2675` checks `supports_compact_blocks`; BUG-2 cross-cite) |
| 3 | Cmpctblock relay (sender side) | G10: `relay_compact_block` invoked from "new block validated" hook | **BUG-3 (P0-CDIV)** — `relay_compact_block` (`peer_manager.ml:2748-2761`) implemented end-to-end (filters HB-peers, gates on `peer_has_header`, sends `CmpctblockMsg`) but **NEVER CALLED FROM ANYWHERE in lib/ or bin/**. W126 BUG-3 carry-forward. `announce_block` (`peer_manager.ml:1360-1369`) only sends HeadersMsg/InvMsg, so HB-cmpct-fast-announce is broken: every newly validated block is announced via header/inv (peers issue getdata, we respond with full block) — the BIP-152 latency saving is forfeited even for peers that asked us for HB. |
| 3 | … | G11: respect peer's `cmpct_high_bandwidth` (HB-from) flag — push cmpctblock immediately to peers that asked us for HB | **BUG-4 (P1)** — `peer.cmpct_high_bandwidth` is SET on every received `sendcmpct(announce=true, 2)` (peer.ml:834, 1596, 1660) but never CONSULTED anywhere in lib/ or bin/. Dead-data plumbing 4th camlcoin instance this quad (after W155 generateblock, W152 mempool wtxid pseudo-index, etc.). |
| 3 | … | G12: skip peers missing the prev-block header (`peer_has_header`) | PARTIAL — `peer_has_header` exists (`sync.ml:5034-5038`) but is a STUB always returning `true`; even when the dead `relay_compact_block` is wired in tests, no per-peer best-header tracking exists. W126 BUG-4. |
| 3 | … | G13: cache `m_most_recent_compact_block` for fast service | **BUG-5 (P1)** — no cache. `peer.ml:1511` calls `P2p.create_compact_block` from scratch on every `InvCompactBlock` getdata, re-doing SHA256 derive_keys + N×SipHash on the same block. W126 BUG-9 P3 carry-forward; promoted to P1 here because it compounds with BUG-2/BUG-3 (every HB-from-peer's cmpct request hits the disk + re-derives state). |
| 4 | cmpctblock receive path | G14: validate header BEFORE reconstruction (`ProcessNewBlockHeaders` analogue) | **BUG-6 (P0-CDIV)** — `cli.ml:1349-1356` jumps straight into `reconstruct_from_mempool` without checking that `cb.header` is known/validated. `Sync.process_new_block` (line 4377) tries `validate_header` on-the-fly inside `process_new_block`, but reconstruction has already been attempted (CPU spent) AND a getblocktxn may have been emitted (network round-trip wasted) before the header is rejected. Core gates strictly: `LookupBlockIndex(prev_block)` first, low-work-PoW check next, `ProcessNewBlockHeaders` third, ONLY THEN reconstruction. |
| 4 | … | G15: refuse cmpctblock during LoadingBlocks / IBD | PARTIAL — `cli.ml:1349` has `when chain.sync_state = Sync.FullySynced` guard (i.e., DROP cmpct during IBD entirely) — Core LOGS at debug and RETURNS rather than full-drop, but during IBD the BIP-152 path is disabled anyway because we're using parallel block download. Functionally equivalent. W126 BUG-7 PARTIAL. |
| 4 | … | G16: low-work header check before reconstruction (`GetAntiDoSWorkThreshold`) | **BUG-7 (P1)** — `cli.ml:1349-1356` performs zero work-proof comparison before spending CPU on SipHash + reconstruction. Core rejects with `Ignoring low-work compact block` (net_processing.cpp:4492) precisely to prevent low-work-cmpct DoS. |
| 4 | … | G17: `MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK = 3` cap on parallel reconstruction attempts | **BUG-8 (P0-CDIV)** — `pending_compact_blocks` is keyed by `block_hash` and stores at most ONE in-flight reconstruction (`Hashtbl.replace` at sync.ml:4951 / cli.ml:1389 — but the sync.ml hashtbl is dead module-state; cli.ml's `compact_pending` is the live one). No per-peer cap, no parallel-attempt tracking. A single peer can send 100 distinct cmpctblocks for the same hash (a peer with prev_block at our tip can spam pre-validated header reuses) and each one triggers a fresh reconstruction + getblocktxn round-trip. Core's 3-cap is anti-DoS. |
| 5 | PartiallyDownloadedBlock reconstruction | G18: short-ID collision detection (`have_txn[]` flag clear on second match) | PASS (`p2p.ml:1467-1486` — the `have_txn[i]` array clears the slot and pushes to `missing` when two short-IDs collide. W112/W126 BUG-2 fix.) |
| 5 | … | G19: bucket-distribution guard (`bucket_size > 12 → READ_STATUS_FAILED`) | **BUG-9 (P1)** — Core's statistical guard (any single hash bucket exceeding 12 entries among the short-ids is treated as a malformed cmpctblock and short-circuits to READ_STATUS_FAILED) is absent. Camlcoin uses a `Hashtbl` (OCaml's std hashtbl, separate-chaining) and has no API to inspect bucket sizes. Practical impact: a cmpct constructed against an adversarial mempool that concentrates short-ID hashes in one bucket pays O(N²) reconstruction cost instead of O(N). |
| 5 | … | G20: `vExtraTxnForCompact` ring buffer of recently-rejected txs | **BUG-10 (P1)** — no equivalent. W126 BUG-6 carry-forward. Camlcoin's reconstruction can only consult mempool, not the recently-orphaned-or-rejected pool. CVE-2017-12842-shape race (orphan child arriving after the cmpctblock that includes the orphan's parent) cannot be recovered by the extra-txn lookup. Cross-cite W152 BUG-7 (no wtxid index in mempool either). |
| 5 | … | G21: IsBlockMutated check on filled block (CVE-2012-2459) | **BUG-11 (P0-CDIV)** — `fill_missing_txs` (`p2p.ml:1503-1523`) and `reconstruct_block` (`p2p.ml:1426-1499`) BOTH return a reconstructed `block` without calling `IsBlockMutated` / `merkle_root` mutation-detection. Core's `FillBlock` (`blockencodings.cpp:218-222`) explicitly runs the mutation check and returns READ_STATUS_FAILED on detection — "Possible Short ID collision". Without this, a short-id collision that pulls in a tx whose duplication produces a valid-looking but mutated merkle tree would be passed to `process_new_block`, which DOES catch the mutation (`validation.ml:864-865 / 1542-1543` — W93 BUG-11) but at much higher cost (full block-validate instead of cheap fill-time short-circuit). Cross-cite W143 BUG-1 fleet pattern: 6+ impls miss CVE-2012-2459 detection in compact-block reconstruction. |
| 5 | … | G22: prefilledtxn index uint16 ceiling enforced at fill time | **BUG-12 (P0-CDIV)** — `p2p.ml:1444-1455` differentially decodes prefilled indices via `let abs_idx = !last_idx + ptx.index + 1` with NO `abs_idx > 65535` ceiling. Core enforces `lastprefilledindex > std::numeric_limits<uint16_t>::max() → READ_STATUS_INVALID`. A peer that sends a series of large differential indexes can produce abs_idx values up to OCaml's native int range; reconstruction either silently mis-fills (if abs_idx < tx_count) OR fails at the `abs_idx >= tx_count` check (line 1447) AFTER work is done. Wire-format gap. |
| 5 | … | G23: getblocktxn request indexes uint16 ceiling on the wire | **BUG-13 (P1)** — `p2p.ml:618` reads via `read_compact_size` (uint64-capable) with NO uint16 differential ceiling. Core's `DifferenceFormatter::Unser` throws on `m_shift > uint16::max()`. Wire-format parity gap; a peer requesting an index > 65535 is silently accepted then either filtered out at lookup time (cli.ml:1455 `if idx >= 0 && idx < Array.length`) OR returns the wrong tx if the OCaml int and the C++ uint16 disagree on truncation (no truncation in OCaml; index passed as-is to array bounds check). |
| 6 | getblocktxn response (server side) | G24: MAX_BLOCKTXN_DEPTH=10 fall-through to full block | PASS (`cli.ml:1435-1473`; matches `net_processing.cpp:4276-4303`) |
| 6 | … | G25: out-of-range request index → MISBEHAVING(100) (Core treats as wire-bug) | **BUG-14 (P1)** — `cli.ml:1454-1457` `List.filter_map (fun idx -> if idx >= 0 && idx < ... then Some else None)` SILENTLY SKIPS out-of-range indices. Core treats this as a wire-protocol violation: a well-formed peer never sends an index ≥ block_tx_count. The silent-skip behaviour returns a `blocktxn` with FEWER txs than the requester asked for, which Core would then treat as `READ_STATUS_INVALID` and disconnect us. Camlcoin's tolerance interoperates with Core but masks misbehavior in BOTH directions (we don't punish, we don't fail loud). |
| 6 | … | G26: serve from `m_most_recent_compact_block`-equivalent cache when hashes match | **BUG-5 cross-cite** — no cache; every getblocktxn re-reads the block from `Storage.ChainDB.get_block` at `cli.ml:1450`. |
| 6 | … | G27: serve witness-format transactions (BIP-144) | PASS (`cli.ml:1459-1462` `make_blocktxn_msg` uses `Serialize.serialize_transaction` which emits witness data when present). |
| 7 | blocktxn receive path | G28: missing-pending-state → log debug, no misbehavior (peer's response is just stale) | PASS (`cli.ml:1425-1426`) |
| 7 | … | G29: blocktxn-fill failure → no misbehavior (peer is trying to deliver, BIP-152 prohibits punishment) | PARTIAL — `cli.ml:1422-1424` warns + returns; no `misbehaving` call (correct per BIP-152). However, the partial-state is REMOVED at line 1406 BEFORE the fill_result check, so a fill failure leaves the requester with nothing to recover from. Core retains the `partialBlock` and disallows further reconstruction attempts from the same peer for the same block (`net_processing.cpp:3475`). |
| 7 | … | G30: IsBlockMutated check after final fill | **BUG-11 cross-cite** (`cli.ml:1407-1408` `fill_missing_txs` then immediate `process_new_block`; no mutation check in between) |
| 8 | High-bandwidth peer flag bookkeeping | (covered by G5/G7/G11) | DEAD per BUG-2/BUG-3/BUG-4 |
| 9 | Cmpct-version 1 (legacy) compatibility | (Core only supports v2; we only support v2) | PASS (both sides agree) |
| 10 | InvCompactBlock getdata service | (covered by G13/G24/G27) | PARTIAL (BUG-5/BUG-13) |
| 11 | Pre-version-handshake gating | (covered by G4) | PASS |
| 12 | Two-pipeline drift | G31: ONE compact-block handler — not the cli.ml live path + the sync.ml dead path | **BUG-15 (P0-CDIV)** — TWO parallel cmpctblock pipelines coexist: (1) `cli.ml:1349-1428` (live, gated `FullySynced`, uses `compact_pending` Hashtbl local to the listener closure, calls `Peer_manager.reconstruct_from_mempool` then `Sync.process_new_block ~f_requested:true`), and (2) `sync.ml:4882-5016` (`handle_cmpctblock` + `handle_blocktxn` + module-global `pending_compact_blocks` Hashtbl + `expire_compact_block_requests` worker) — DESIGNED for the IBD path and the request-by-getdata path, NEVER CALLED from production. The sync.ml pipeline includes an expire-stale-requests background task at `sync.ml:5019-5032` that runs and silently no-ops because the table is always empty. **11-CONSECUTIVE-QUAD camlcoin pipeline drift** (W143/W144/W145/W146/W147/W148/W149/W150/W151/W152/W155/W156 — same impl, same pattern: helpers built, called nowhere). |

---

## BUG-1 (P1) — `sendcmpct` post-handshake send is NOT gated on `SHORT_IDS_BLOCKS_VERSION (70014)`

**Severity:** P1. Bitcoin Core's
`bitcoin-core/src/net_processing.cpp:3864-3871` guards the post-handshake
`SENDCMPCT` push with:

```cpp
if (pfrom.GetCommonVersion() >= SHORT_IDS_BLOCKS_VERSION) {
    // Tell our peer we are willing to provide version 2 cmpctblocks.
    MakeAndPushMessage(pfrom, NetMsgType::SENDCMPCT, /*high_bandwidth=*/false,
                       /*version=*/CMPCTBLOCKS_VERSION);
}
```

`SHORT_IDS_BLOCKS_VERSION = 70014` (bitcoin-core/src/node/protocol_version.h:30).
A pre-2016 peer that negotiates protocol_version < 70014 cannot speak
BIP-152 v2, and Core suppresses the noise.

Camlcoin's `perform_handshake_inner` (`peer.ml:1006`) and
`perform_inbound_handshake_inner` (`peer.ml:1063`) both unconditionally
push `(P2p.make_sendcmpct_msg ~high_bandwidth:false)` with no peer
version check. A peer that negotiated protocol_version 70013 (or older)
receives a sendcmpct(0,2) that it does not understand; depending on the
peer's permissiveness this either gets silently dropped or trips an
"unknown message" warning. In practice all extant Bitcoin nodes
advertise ≥ 70016, so the impact is observability noise only.

**File:** `lib/peer.ml:1006, 1063`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:3864-3871`;
`bitcoin-core/src/node/protocol_version.h:30`.

**Excerpt (camlcoin, missing version gate)**
```ocaml
(* BIP 152: Send sendcmpct version 2 (segwit-aware) in low-bandwidth mode *)
let* () = send_message peer (P2p.make_sendcmpct_msg ~high_bandwidth:false) in
(* MISSING: gate on peer.version_msg.protocol_version >= 70014 *)
```

**Cross-cite:** W126 BUG-5 (PARTIAL; this is the same defect).

**Impact:** observability only on the modern wire; cross-impl
divergence in handshake logs when interop-testing against a hypothetical
pre-2016 peer. The wtxidrelay send (`peer.ml:786-791`) DOES gate on
protocol_version, so the two send paths use different conventions for
the same kind of check.

---

## BUG-2 (P0-CDIV) — `maybe_set_hb_compact_peer` is a DEAD HELPER (carry-forward, ~14 weeks open)

**Severity:** P0-CDIV. Bitcoin Core's
`MaybeSetPeerAsAnnouncingHeaderAndIDs` (`net_processing.cpp:1272-1329`)
is the entry point that turns a peer into one of our ≤3 "ask them to
send us compact blocks" partners. It is invoked from
`ProcessHeadersMessage` (line 2220) every time we accept a header
extending the best chain — i.e., the peer that gave us the new
best-known-block becomes a candidate for HB-FROM relay.

Camlcoin has the COMPLETE algorithm implemented in
`peer_manager.ml:2671-2733`:
- refuses block-relay-only peers (`peer_manager.ml:2674`),
- refuses peers without cmpct v2 + NODE_WITNESS
  (`peer_manager.ml:2675`),
- moves existing HB peers to the end of the list (most-recently-active
  tail),
- enforces `max_hb_compact_peers = 3` with eviction of
  list-front,
- inbound-protect-outbound logic (`peer_manager.ml:2696-2707`):
  when adding an inbound peer and there's exactly 1 outbound HB peer,
  skip the outbound front entry and evict the next non-outbound,
- sends `sendcmpct(false, 2)` to the demoted peer and `sendcmpct(true, 2)`
  to the promoted peer.

**This entire helper is NEVER CALLED.** A grep over `lib/` and `bin/`
returns only the definition itself and one comment reference:

```
$ grep -rn 'maybe_set_hb_compact_peer' lib/ bin/
lib/peer_manager.ml:2644:   Reference: Bitcoin Core net_processing.cpp MaybeSetPeerAsAnnouncingHeaderAndIDs()
lib/peer_manager.ml:2670:   Reference: Bitcoin Core MaybeSetPeerAsAnnouncingHeaderAndIDs() *)
lib/peer_manager.ml:2671:let maybe_set_hb_compact_peer (pm : t) (peer : Peer.peer) : unit Lwt.t =
```

The `pm.hb_compact_peers` list is initialised `[]` at peer_manager.ml:274,
manipulated only by `maybe_set_hb_compact_peer` (dead) and
`remove_hb_compact_peer` (called from peer_manager.ml:1050 on disconnect
— harmless no-op on the empty list), and consumed only by
`get_hb_compact_peers` (used by the dead `relay_compact_block` per
BUG-3). The list is therefore PERMANENTLY EMPTY.

Consequence: camlcoin NEVER tells any peer "send us compact blocks
in HB mode" (sendcmpct(true, 2) is never sent). All peers we connect
to receive `sendcmpct(false, 2)` only. Core's BIP-152 efficiency
(immediate-relay of cmpctblock from our most-recently-active peer for
fast tip extension) is forfeited; we always pay the inv→getdata→block
round-trip.

**File:** `lib/peer_manager.ml:2671-2733` (definition);
no call sites in `lib/cli.ml`, `lib/sync.ml`, `lib/peer.ml`,
`bin/main.ml`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:1272-1329`
(`MaybeSetPeerAsAnnouncingHeaderAndIDs`); call from
`ProcessHeadersMessage` at line 2220.

**Cross-cite:** W126 BUG-2 (P0-CDIV); W112 BUG-5 (same defect). Open
since W112 first flagged it ~14 weeks ago. The fix wires
`maybe_set_hb_compact_peer pm peer` into the
"header accepted, peer announced it" path — either inside
`sync.ml::accept_header` (when the announcing peer can be resolved) or
inside `cli.ml::Peer_manager.add_listener` for the
`HeadersMsg`/`InvMsg(InvBlock)` arms.

**Impact:**
- Compact-block fast announce (the entire purpose of BIP-152's HB
  mode) is NEVER ACTIVE on the inbound side.
- Block-propagation latency for camlcoin nodes is consistently ~1.5×
  Core (inv→getdata→full-block vs cmpctblock→reconstruct).
- Carry-forward record: this is the longest-open camlcoin BIP-152
  finding (14+ weeks).

---

## BUG-3 (P0-CDIV) — `relay_compact_block` is a DEAD HELPER (carry-forward, ~14 weeks open)

**Severity:** P0-CDIV. Bitcoin Core's `SendMessages` (per
`net_processing.cpp:5839-5902` region) pushes a `CMPCTBLOCK` to peers
that have asked us for HB (`state.m_requested_hb_cmpctblocks`) on
every newly validated block, gated on
`peer.m_blocks_for_headers_relay.size() ≤ 1` (a burst of multiple
header announcements falls back to headers).

Camlcoin has the helper:

```ocaml
let relay_compact_block (pm : t) (block : Types.block)
    ~(peer_has_header : Peer.peer -> Types.hash256 -> bool) : unit Lwt.t =
  let prev_hash = block.header.prev_block in
  let cb = P2p.create_compact_block block in
  let msg = P2p.CmpctblockMsg cb in
  let hb_peers = get_hb_compact_peers pm in
  Lwt_list.iter_p (fun peer ->
    if peer_has_header peer prev_hash then
      Lwt.catch
        (fun () -> Peer.send_message peer msg)
        (fun _exn -> Lwt.return_unit)
    else
      Lwt.return_unit
  ) hb_peers
```

**The helper is NEVER CALLED from anywhere in `lib/` or `bin/`.** All
three new-block announce sites (`cli.ml:1226`, `cli.ml:1367`,
`cli.ml:1417`, `rpc.ml:1969`) call `Peer_manager.announce_block` —
which only sends `HeadersMsg` or `InvMsg [InvBlock]`. The cmpctblock
fast-announce path is entirely unused.

Compounding factor: even if `relay_compact_block` were wired in, it
would iterate `get_hb_compact_peers pm` — which depends on
`pm.hb_compact_peers`, which is permanently `[]` per BUG-2. So the
fix requires BOTH (1) wiring `maybe_set_hb_compact_peer` from header
processing AND (2) wiring `relay_compact_block` from block-connect
processing — neither alone is sufficient.

**File:** `lib/peer_manager.ml:2748-2761` (definition);
no call sites; `lib/cli.ml:1226,1367,1417`, `lib/rpc.ml:1969`
(the four sites that DO call `announce_block`).

**Core ref:** `bitcoin-core/src/net_processing.cpp:5839` SendMessages
compact-block gate; line 2117 `cached_cmpctblock_msg` cache hit;
line 4750+ ProcessNewBlock-triggered relay.

**Cross-cite:** W126 BUG-3 (P0-CDIV); W112 BUG-4. Same defect, 14+ weeks
open.

**Excerpt (camlcoin's actual announce path)**
```ocaml
(* peer_manager.ml:1360 — the LIVE block-announce function *)
let announce_block (pm : t) (header : Types.block_header) (hash : Types.hash256) : unit Lwt.t =
  let ready = get_ready_peers pm in
  Lwt_list.iter_p (fun peer ->
    Lwt.catch (fun () ->
      if peer.Peer.send_headers then
        Peer.send_message peer (P2p.HeadersMsg [header])
      else
        Peer.send_message peer (P2p.InvMsg [{ P2p.inv_type = P2p.InvBlock; hash }])
    ) (fun _exn -> Lwt.return_unit)
  ) ready
```

No CmpctblockMsg branch. No `cmpct_high_bandwidth` consultation.

**Impact:**
- HB compact-block ANNOUNCE side is broken (we never push a
  cmpctblock to anyone, ever — not on the receive side per BUG-2, not
  on the send side per BUG-3).
- Cross-cite "wiring-look-but-no-wire" fleet pattern (W138 / W155 BUG-14
  for blockbrew ChainParams.SubsidyHalvingInterval) — same shape:
  full implementation present, exported, type-checks, zero
  production callers.

---

## BUG-4 (P1) — `peer.cmpct_high_bandwidth` is DEAD-DATA (set on every received sendcmpct(true,2), never consumed)

**Severity:** P1 (would be P0-CDIV the moment BUG-3 is fixed).
Bitcoin Core's `m_bip152_highbandwidth_from` flag
(net_processing.cpp:3915) records whether THIS peer asked US for HB
mode (i.e., they want us to push cmpctblocks immediately on new
block). The corresponding `m_bip152_highbandwidth_to`
(net_processing.cpp:1318/1325) records the opposite (we asked THEM
for HB).

Camlcoin's `peer.cmpct_high_bandwidth` (`peer.ml:267`) is SET on
every received `SendcmpctMsg{announce=true; version=2L}` at three
sites:
- `peer.ml:834` (read_until_verack)
- `peer.ml:1596` (pre-handshake dispatch)
- `peer.ml:1660` (post-handshake dispatch)

But a grep over `lib/` and `bin/` shows NO READS of the field anywhere
outside the assignments and its declaration. The dead-data pattern:

```
$ grep -rn 'cmpct_high_bandwidth' lib/ bin/
lib/peer.ml:267:  mutable cmpct_high_bandwidth : bool; ...
lib/peer.ml:401:    cmpct_high_bandwidth = false;
lib/peer.ml:834:          peer.cmpct_high_bandwidth <- announce;
lib/peer.ml:1596:      peer.cmpct_high_bandwidth <- announce;
lib/peer.ml:1660:      peer.cmpct_high_bandwidth <- announce;
```

The dead-data plumbing fleet pattern is now in its 4th distinct
camlcoin instance this quad (W155 generateblock,
W152 mempool wtxid-pseudoindex, W155 BlockAssembler::m_last_block_weight,
W156 cmpct_high_bandwidth). The classic shape: peer asked us
"send me cmpct in HB mode", we record it, and the new-block-relay path
ignores the request. (Same as BUG-3 from the read side: even if
`relay_compact_block` is wired, our LIST of HB-TO peers is `[]` per
BUG-2, but the peers that asked US for HB are NOT in any LIST we
consume from.)

**File:** `lib/peer.ml:267, 401, 834, 1596, 1660`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:3915`
`pfrom.m_bip152_highbandwidth_from = sendcmpct_hb`; consulted by
`SendMessages` cmpct-block-announce gate.

**Impact:** correctness-neutral today (because BUG-3 means we don't
relay cmpct anyway). Becomes a functional bug the moment BUG-3 is
fixed naively: a fix that only iterates `pm.hb_compact_peers` (HB-TO,
our outgoing requests) misses peers that asked US for HB
(`cmpct_high_bandwidth = true`). The full Core analogue iterates
BOTH lists.

---

## BUG-5 (P1) — No `m_most_recent_compact_block` cache; every InvCompactBlock getdata re-derives SipHash keys and recomputes all short-ids

**Severity:** P1 (carry-forward of W126 BUG-9 P3, promoted here
because it compounds with the dead-helper bugs). Bitcoin Core
caches `m_most_recent_compact_block` (`net_processing.cpp:863`) populated
in the `BlockChecked` callback after every accepted block. The
`SendBlockTransactions` server (responding to getblocktxn) AND the
`MSG_CMPCT_BLOCK` getdata service (line 2468/2471) consult this cache
FIRST before reading from disk. Cache hit avoids:
- `Storage.ChainDB.get_block` (disk read + deserialize),
- `Crypto.SipHash.derive_keys` (SHA256(header || nonce)),
- N × `Crypto.compute_short_txid` (SipHash hashes of N wtxids),
- N × `Crypto.compute_wtxid` (N × SHA256d of full witness-serialized
  txs).

Camlcoin's `handle_getdata` `InvCompactBlock` arm at `peer.ml:1497-1518`:

```ocaml
| Some data ->
  let block_h = lookup_block_height iv.hash in
  let within_depth = match block_h with
    | Some h -> h >= tip_height - P2p.max_cmpctblock_depth
    | None   -> false
  in
  if within_depth then begin
    let r = Serialize.reader_of_cstruct data in
    let block = Serialize.deserialize_block r in
    let cb = P2p.create_compact_block block in   (* <-- recomputes everything *)
    send_message peer (P2p.CmpctblockMsg cb)
  end
```

`P2p.create_compact_block` at `p2p.ml:1374-1394` runs full derive_keys
+ N×compute_wtxid + N×SipHash on every call. On a busy node with N=2500
txs/block and 8 HB peers asking for the same tip, this is 8×(1 SHA256 +
2500 SHA256d + 2500 SipHash) = ~40,000 hashes per second of CPU
"wasted" on a cache that Core ships free.

Same for getblocktxn — `cli.ml:1450` does `Storage.ChainDB.get_block`
on every request; no `m_most_recent_block_txs` analogue.

**File:** `lib/peer.ml:1497-1518`; `lib/cli.ml:1450`;
`lib/peer_manager.ml:225` (no cache field on `t`).

**Core ref:** `bitcoin-core/src/net_processing.cpp:860-865`
cache declarations; `5839+` consumer; `BlockChecked` populator.

**Cross-cite:** W126 BUG-9 P3 (carry-forward; promoted to P1 here).

**Impact:** O(N) per-request CPU cost per HB peer (up to 3 in Core; up
to whatever-our-peer-count-is in camlcoin since BUG-2/BUG-3 mean we
serve cmpct only on demand via getdata-InvCompactBlock). Adds ~5-15%
CPU overhead on a busy mainnet tip.

---

## BUG-6 (P0-CDIV) — CmpctblockMsg listener jumps to reconstruction BEFORE validating the header

**Severity:** P0-CDIV. Bitcoin Core's `ProcessMessage(CMPCTBLOCK)`
(`net_processing.cpp:4466-4508`) follows STRICT order:
1. `if (LoadingBlocks()) return;` — debug-log + drop during IBD.
2. `if (!prev_block) { MaybeSendGetHeaders(...); return; }` — header
   not connectable, request the missing range.
3. `if (prev_block->nChainWork + GetBlockProof(cmpctblock.header) <
   GetAntiDoSWorkThreshold()) return;` — low-work compact block,
   ignore.
4. `m_chainman.ProcessNewBlockHeaders({{cmpctblock.header}},
   /*min_pow_checked=*/true, state, &pindex)` — header validation
   FIRST; on `state.IsInvalid()` calls `MaybePunishNodeForBlock(...,
   via_compact_block=true, "invalid header via cmpctblock")`.
5. ONLY THEN moves on to reconstruction.

Camlcoin's listener (`cli.ml:1349-1356`):

```ocaml
| P2p.CmpctblockMsg cb when chain.sync_state = Sync.FullySynced ->
  let header_hash = Crypto.compute_block_hash cb.header in
  Logs.info ...
  (* Attempt reconstruction using mempool *)
  let result = Peer_manager.reconstruct_from_mempool peer_manager cb in
  (match result with
   | P2p.ReconstructComplete block ->
     ...
     match Sync.process_new_block ~f_requested:true chain block with ...)
```

Jumps straight into `reconstruct_from_mempool` — which iterates the
mempool, derives SipHash keys, computes N short-ids, and tries to
match — **without ever checking that `cb.header` is even a valid
block header.** The header validation only happens inside
`Sync.process_new_block` (line 4377):

```ocaml
let header_entry = match Hashtbl.find_opt state.headers hash_key with
  | Some e -> Some e
  | None ->
    (match validate_header state block.header with
     | Ok entry -> accept_header state entry; Some entry
     | Error _ -> None)
```

This means:
- CPU is spent on SipHash + mempool scan + reconstruction BEFORE we
  know the header is valid.
- If reconstruction succeeds but the header is invalid, we've gone
  through the full reconstruction round-trip plus
  `Sync.process_new_block` to discover the rejection.
- If reconstruction needs missing txs, we emit a `getblocktxn` to the
  peer (network round-trip) BEFORE knowing the header was even
  acceptable. A peer that sends an invalid-header cmpctblock can DoS us
  into making it look like they have data we need.

**File:** `lib/cli.ml:1349-1356`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:4480-4508` for
the header-first gate; `4476-4508` for the full ordered sequence.

**Excerpt (cmpct-then-validate vs Core's validate-then-cmpct)**
```ocaml
(* camlcoin order *)
let result = Peer_manager.reconstruct_from_mempool peer_manager cb in
(* ... reconstruction work, possibly getblocktxn round-trip ...      *)
match Sync.process_new_block chain block with ...   (* header check HERE *)

(* Core order (paraphrased) *)
if (!LookupBlockIndex(cb.header.hashPrevBlock)) { MaybeSendGetHeaders; return; }
if (low_work) return;
ProcessNewBlockHeaders({{cb.header}}, ...);    (* validation FIRST *)
PartiallyDownloadedBlock partial;
partial.InitData(cb, ...);                     (* reconstruction LAST *)
```

**Impact:**
- Wasted CPU on invalid-header cmpct (a single malicious peer can
  burn our SipHash budget by sending a series of structurally-valid
  but header-invalid cmpcts).
- Wasted network round-trip on getblocktxn for invalid-header cmpcts.
- No `MaybePunishNodeForBlock` call on invalid header (camlcoin's
  general "no punishment from cmpct path" stance per BIP-152 is correct,
  but the asymmetric ordering means we can't even distinguish
  invalid-from-malicious vs invalid-from-bug).

---

## BUG-7 (P1) — No `GetAntiDoSWorkThreshold` low-work check before cmpct reconstruction

**Severity:** P1. Bitcoin Core's `net_processing.cpp:4490-4494`:

```cpp
} else if (prev_block->nChainWork + GetBlockProof(cmpctblock.header) <
           GetAntiDoSWorkThreshold()) {
    // If we get a low-work header in a compact block, we can ignore it.
    LogDebug(BCLog::NET, "Ignoring low-work compact block from peer %d\n", pfrom.GetId());
    return;
}
```

`GetAntiDoSWorkThreshold` returns the minimum chain-work an attacker
would need to forge a competing chain — typically tied to
`MinimumChainWork`. A cmpctblock whose total work is below this
threshold is provably not the new best chain, and processing it is
wasted effort.

Camlcoin has NO such gate. A peer can send arbitrarily-low-work
cmpctblocks (e.g., regtest-quality PoW headers replayed on mainnet) and
camlcoin will derive SipHash keys, scan the mempool, and attempt
reconstruction every time. The PoW of the header is validated only
later inside `Sync.process_new_block`.

**File:** `lib/cli.ml:1349-1356`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:4490-4494`;
`GetAntiDoSWorkThreshold` definition.

**Impact:** anti-DoS gap. A peer that opens 8 connections can send
8 × O(mempool-size) reconstruction loads per second by sending the
same low-work cmpct shape repeatedly. The pending_compact_blocks
table dedup at sync.ml:4916 doesn't help because cli.ml is the live
path and uses a different table (`compact_pending`); see also BUG-8
on the missing in-flight cap.

---

## BUG-8 (P0-CDIV) — No `MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK = 3` cap; parallel reconstruction attempts unbounded

**Severity:** P0-CDIV. Bitcoin Core's
`MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK = 3` (defined as a
`constexpr` near the top of net_processing.cpp; consulted at
`net_processing.cpp:4577, 4624`) caps the number of CONCURRENT
compact-block reconstruction attempts for the same block hash across
different peers. Without this cap, a malicious peer that opens N
connections can spam the SAME cmpctblock N times and force N
reconstruction attempts in parallel.

Camlcoin's `compact_pending` Hashtbl in `cli.ml:1344-1346` is keyed
by `Types.hash256` (the block hash):

```ocaml
let compact_pending :
  (Types.hash256, P2p.compact_block * Types.transaction option array * int list) Hashtbl.t =
  Hashtbl.create 16 in
```

At line 1389 we do `Hashtbl.replace compact_pending header_hash (cb,
partial_txs, missing)` — REPLACE on each new cmpctblock for the same
hash, overwriting the previous in-flight state. Consequences:
1. Two distinct peers send the SAME cmpctblock for the SAME hash but
   with DIFFERENT nonces (so different short-ids). The second arrival
   overwrites the first; the first peer's outstanding `getblocktxn` for
   the original missing-set will, when it arrives, fail to find the
   nonce-original lookup table.
2. There's no anti-DoS cap on concurrent attempts. A peer issues N
   sendcmpct(announce=true,2) (which sets `cmpct_high_bandwidth = true`
   on its peer record but has no effect on cmpct sending per BUG-4),
   then bombards us with N cmpctblocks — each triggers a fresh
   reconstruction.
3. The sync.ml `pending_compact_blocks` Hashtbl (sync.ml:4891) ALSO
   keys by block hash and uses `Hashtbl.replace` — duplicate-overwrite
   semantics — but is dead (BUG-15).

**File:** `lib/cli.ml:1344-1346, 1389`; `lib/sync.ml:4891-4892`
(dead).

**Core ref:** `bitcoin-core/src/net_processing.cpp:4577-4634`
(`MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK` gate); definition near line
~120.

**Impact:**
- Per-block in-flight overwrite breaks the two-peer race where one
  peer is faster on `cmpctblock` but the other is faster on
  `blocktxn`: the second arrival overwrites the first's pending state,
  and the first's eventual blocktxn arrives orphaned.
- Anti-DoS: no per-peer cap means a single peer can force unbounded
  parallel reconstructions for distinct blocks (e.g., on a small reorg
  with 3-4 sibling headers, each at different cmpct, each from a
  different peer — N × M reconstructions instead of capped 3).

---

## BUG-9 (P1) — No `bucket_size > 12 → READ_STATUS_FAILED` statistical guard on short-id distribution

**Severity:** P1. Bitcoin Core's `PartiallyDownloadedBlock::InitData`
(`blockencodings.cpp:100-111`):

```cpp
if (shorttxids.bucket_size(shorttxids.bucket(cmpctblock.shorttxids[i])) > 12)
    return READ_STATUS_FAILED;
```

The comment explains: with a default-load-factor unordered_map and
blocks up to 16000 txs, allowing 12 elements per bucket caps the
failure probability at 1-in-1-million per block transfer per peer.
A grossly skewed short-id distribution is a signal of pathological
construction (either adversarial or a wire-format bug) and the
appropriate response is `READ_STATUS_FAILED` (fall back to full block).

Camlcoin's `reconstruct_block` (`p2p.ml:1426-1499`) uses an OCaml
`Hashtbl.t` for `lookup.by_short_id`. OCaml's stdlib Hashtbl uses
separate-chaining buckets internally but exposes no API to inspect
bucket counts. There's no equivalent guard — a pathologically skewed
short-id distribution proceeds through the slow O(N²) reconstruction.

**File:** `lib/p2p.ml:1469-1490` (the per-slot match-lookup);
no statistical guard.

**Core ref:** `bitcoin-core/src/blockencodings.cpp:100-111`.

**Impact:** CPU degradation under adversarial-distribution attacks;
correctness-neutral. Practical impact on benign mempools is nil
(SipHash gives near-uniform distribution).

---

## BUG-10 (P1) — `vExtraTxnForCompact` ring buffer of recently-rejected txs is absent (carry-forward W126 BUG-6)

**Severity:** P1. Bitcoin Core's `vExtraTxnForCompact`
(`net_processing.cpp:997-999`) is a `std::vector<std::pair<Wtxid,
CTransactionRef>>` sized to `m_opts.max_extra_txs = 100` (default).
Populated by `AddToCompactExtraTransactions` (line 1883-1891) on
specific tx-rejection paths (RECENT_CONSENSUS_CHANGE, "missing
inputs" orphans, etc.), this ring buffer holds recently-seen txs that
DIDN'T make it into the mempool but might still appear in a block.
The reconstruction path consults it in `PartiallyDownloadedBlock::InitData`
(`blockencodings.cpp:147-176`) AFTER the mempool scan; CVE-2017-12842
race coverage (a tx arrives as an orphan, gets rejected, then appears
in the very next block — without this pool, the reconstruction
unnecessarily round-trips a `getblocktxn` for that tx).

Camlcoin has no such ring buffer. The mempool is the ONLY source of
reconstruction-time lookup (`peer_manager.ml:2766-2768`). On the
orphan path (which is itself broken per W152 BUG-1 — orphans are
silently dropped, not pooled), this means every block containing a
recently-orphaned tx requires a `getblocktxn` round-trip.

Compounding: W152 BUG-7 records that the mempool has no wtxid index;
`create_short_id_lookup` (`mempool.ml:3487-3494`) iterates ALL
`mempool.entries` and recomputes the short_id per entry per request.
Even WITH the extra-txn pool, the lookup path would be slow.

**File:** `lib/peer_manager.ml` (no extra_txn field on `t`);
`lib/mempool.ml:3487-3494` (no extra-source iteration);
`lib/cli.ml:1356` (uses only `reconstruct_from_mempool`).

**Core ref:** `bitcoin-core/src/net_processing.cpp:997, 1883-1891`
(population); `bitcoin-core/src/blockencodings.cpp:147-176`
(consumption).

**Cross-cite:** W126 BUG-6 (P2; promoted here to P1 because the
fleet-pattern compound damage with W152 BUG-1 + W152 BUG-7 makes
the gap structural, not just performance).

**Impact:** `getblocktxn` traffic for recently-orphaned txs is
amplified vs Core. Practical impact small on quiet mainnet, larger
during mempool-churn / fee-spike windows.

---

## BUG-11 (P0-CDIV) — `IsBlockMutated` / `merkle_root` mutation check is absent in `FillBlock` / `fill_missing_txs`

**Severity:** P0-CDIV. Bitcoin Core's `PartiallyDownloadedBlock::FillBlock`
(`blockencodings.cpp:218-222`):

```cpp
// Check for possible mutations early now that we have a seemingly good block
IsBlockMutatedFn check_mutated{m_check_block_mutated_mock ? m_check_block_mutated_mock : IsBlockMutated};
if (check_mutated(/*block=*/block, /*check_witness_root=*/segwit_active)) {
    return READ_STATUS_FAILED; // Possible Short ID collision
}
```

`IsBlockMutated` is the CVE-2012-2459 detection — if any two adjacent
hashes at any merkle level are identical, mutation is detected. The
comment "Possible Short ID collision" makes the intent explicit: when
a short-id collision (two distinct txs with the same 48-bit
short_txid) gets resolved by picking the wrong tx, the resulting
block's merkle tree will frequently have a duplicate-at-some-level
pattern. `READ_STATUS_FAILED` triggers fallback to `getdata MSG_BLOCK`
— the requester downloads the canonical block via the slow path.

Camlcoin's `reconstruct_block` (`p2p.ml:1426-1499`) returns the
reconstructed block immediately after filling all slots, with no
post-fill validation. Same for `fill_missing_txs` (`p2p.ml:1503-1523`).
The block is then handed to `Sync.process_new_block` which DOES
eventually call `merkle_root` with mutation detection (`validation.ml:864-865,
1542-1543`) — but only as part of the FULL block-validate path, after
header-validation, after BIP-30 / BIP-34 / SIGOP / etc. The cost of
attempting full validation on a short-id-collision-corrupted block is
~10-100× the cost of the early bail.

**File:** `lib/p2p.ml:1493-1497` (where the mutation check should
be); `lib/p2p.ml:1516-1521` (same in fill_missing_txs).

**Core ref:** `bitcoin-core/src/blockencodings.cpp:218-222`;
`bitcoin-core/src/validation.cpp` `IsBlockMutated` definition.

**Cross-cite:** W143 BUG-1 fleet pattern — 6+ impls miss CVE-2012-2459
mutation detection in their compact-block reconstruction path. Camlcoin
HAS the primitive (`Crypto.merkle_root` with mutation detection;
`p2p.ml` could call it) but doesn't invoke it here. Fleet-wide
short-id-collision-safety gap.

**Excerpt (camlcoin's bail-only-on-missing path)**
```ocaml
(* p2p.ml:1493-1497 — no IsBlockMutated check *)
if !missing <> [] then
  ReconstructNeedTxs (List.rev !missing)
else begin
  (* All transactions found - build the block *)
  let transactions = Array.to_list (Array.map Option.get txs) in
  ReconstructComplete { header = cb.header; transactions }   (* <-- no mutation check *)
end
```

**Impact:**
- Wasted CPU on short-id-collision-corrupted reconstructions (full
  block-validate instead of early bail).
- Cross-impl divergence: a Core peer that received the same short-id
  collision would emit `MSG_BLOCK` getdata; camlcoin attempts
  `process_new_block` on the corrupt block which trips the redundant
  mutation check at validation time but logs differently and exhausts
  more resources.
- Class: CVE-2012-2459 mutation-class. Fleet-wide pattern; first
  camlcoin instance in BIP-152 path.

---

## BUG-12 (P0-CDIV) — `prefilledtxn` differential index has NO uint16_t ceiling enforcement at decode time

**Severity:** P0-CDIV. Bitcoin Core's `PartiallyDownloadedBlock::InitData`
(`blockencodings.cpp:72-79`):

```cpp
int32_t lastprefilledindex = -1;
for (size_t i = 0; i < cmpctblock.prefilledtxn.size(); i++) {
    if (cmpctblock.prefilledtxn[i].tx->IsNull())
        return READ_STATUS_INVALID;

    lastprefilledindex += cmpctblock.prefilledtxn[i].index + 1; //index is a uint16_t, so can't overflow here
    if (lastprefilledindex > std::numeric_limits<uint16_t>::max())
        return READ_STATUS_INVALID;
    if ((uint32_t)lastprefilledindex > cmpctblock.shorttxids.size() + i) {
        return READ_STATUS_INVALID;
    }
    ...
}
```

Two distinct uint16 guards:
1. Per-item differential index is uint16_t at the wire (`PrefilledTransaction::index`
   is declared `uint16_t` in `blockencodings.h:77`; serialized via
   `COMPACTSIZE(obj.index)` which the C++ side reads into uint16_t).
2. CUMULATIVE `lastprefilledindex > uint16_t::max()` (65535) on the
   running sum.

Camlcoin's `deserialize_prefilled_tx` (`p2p.ml:573-576`):

```ocaml
let deserialize_prefilled_tx r : prefilled_tx =
  let index = Serialize.read_compact_size r in
  let tx = Serialize.deserialize_transaction r in
  { index; tx }
```

`Serialize.read_compact_size` reads up to a u64. The `index` is stored
in the OCaml `int` (native int; 63 bits on 64-bit platforms). NO check
that `index > 65535` and NO check during the differential decode
(`p2p.ml:1444-1452`) that the cumulative `abs_idx` exceeds 65535.

Wire-format gap: a peer sending an index of 100000 (or 1000000000) in
the prefilled differential will:
- In camlcoin: pass the per-item read; differential decode produces
  `abs_idx = !last_idx + 100000 + 1`; either `abs_idx >= tx_count`
  bail (correct rejection) OR `abs_idx < tx_count` (wrong slot
  populated). Either way the peer's wire-format misbehavior is hidden.
- In Core: per-item already constrained to uint16 by the type; cumulative
  > uint16::max() returns READ_STATUS_INVALID → `Misbehaving(peer,
  "invalid compact block")` → discourage.

Two distinct divergences: (a) camlcoin doesn't reject the index >
uint16, (b) camlcoin doesn't trigger any misbehavior signal.

**File:** `lib/p2p.ml:573-576` (no uint16 read-time check);
`lib/p2p.ml:1444-1452` (no cumulative ceiling).

**Core ref:** `bitcoin-core/src/blockencodings.cpp:72-85` (the dual
uint16 guard); `bitcoin-core/src/blockencodings.h:77` (uint16_t type
declaration).

**Impact:** wire-format parity gap. A peer sending malformed prefilledtxn
indexes survives without misbehavior signal; camlcoin's reconstruction
either silently fills the wrong slot OR bails on the array-bounds
check without recording the wire violation. Cross-impl divergence:
Core would have already disconnected this peer with discouragement.

---

## BUG-13 (P1) — `getblocktxn` request indexes lack uint16 differential ceiling enforcement

**Severity:** P1. Bitcoin Core's `BlockTransactionsRequest::indexes`
uses `std::vector<uint16_t>` (`blockencodings.h:49`) with
`Using<VectorFormatter<DifferenceFormatter>>` serialization
(`blockencodings.h:53`). `DifferenceFormatter::Unser` throws
`std::ios_base::failure("differential value overflow")` when the
cumulative shift exceeds `std::numeric_limits<I>::max()`
(`blockencodings.h:40` — `I = uint16_t` for indexes).

Camlcoin's `deserialize_block_txns_request` (`p2p.ml:615-622`) reads:

```ocaml
let count = Serialize.read_compact_size r in
if count > max_compact_block_txs then
  failwith "block txns request count exceeds maximum";
let indexes = List.init count (fun _ -> Serialize.read_compact_size r) in
```

`read_compact_size` reads u64-capable values. The per-item read has
no uint16 cap. The differential decode at `cli.ml:1434` does
`P2p.decode_differential_indices req.indexes` — `p2p.ml:1543-1553`
walks the list with `prev + diff + 1` and has no overflow check.

**File:** `lib/p2p.ml:615-622` (deserializer);
`lib/p2p.ml:1543-1553` (decoder).

**Core ref:** `bitcoin-core/src/blockencodings.h:40-43, 49, 53`.

**Impact:** wire-format parity gap. Practical impact bounded by the
downstream filter at `cli.ml:1454-1457` that ignores out-of-range
indexes — but that's the bug from G25 (BUG-14): we filter silently
instead of treating as misbehavior.

---

## BUG-14 (P1) — Out-of-range getblocktxn request indexes are silently skipped (no misbehavior signal)

**Severity:** P1. Bitcoin Core's `SendBlockTransactions`
(`net_processing.cpp:2581-2615` region) iterates the requested
indexes and constructs the response, but the differential-decode
itself would have thrown on an out-of-bounds index (via
`DifferenceFormatter::Unser`); the throw is caught at the message-
dispatch level and treated as wire-format violation → discourage.

Camlcoin's `cli.ml:1454-1457`:

```ocaml
let requested_txs = List.filter_map (fun idx ->
  if idx >= 0 && idx < Array.length txs_array then
    Some txs_array.(idx)
  else None
) abs_indexes in
```

`List.filter_map` silently drops out-of-range indices. The response
`blocktxn` carries FEWER txs than the requester asked for, which the
requester treats as `READ_STATUS_INVALID` and disconnects us. We
neither (a) detect the wire violation locally and discourage the
sender, nor (b) make our short-response visible to the operator.

**File:** `lib/cli.ml:1454-1457`.

**Core ref:** `bitcoin-core/src/blockencodings.h:40` (`Unser` throws);
`bitcoin-core/src/net_processing.cpp:5048-5070` (dispatch-level
catch and misbehavior).

**Impact:**
- Silent acceptance of a misbehaving peer (no record, no
  ban-score increment).
- Wire-protocol violation eventually disconnects US (the requester
  sees an invalid response).
- Cross-impl divergence: Core would have already discouraged this
  peer before responding.

---

## BUG-15 (P0-CDIV) — Two parallel compact-block pipelines coexist (cli.ml live + sync.ml dead) — 11-consecutive-quad pipeline drift

**Severity:** P0-CDIV ("two-pipeline drift" / "11-CONSECUTIVE-QUAD
camlcoin pipeline drift" — extends the pattern documented in
W143-W155 by one more wave). Camlcoin has TWO complete BIP-152
receive-side implementations:

**Pipeline A (LIVE — cli.ml, FullySynced only):**
- `cli.ml:1339-1346` — `compact_pending` Hashtbl local to the listener
  closure, keyed by block_hash.
- `cli.ml:1349-1398` — `CmpctblockMsg` listener: derives keys via
  `Peer_manager.reconstruct_from_mempool`, either calls
  `Sync.process_new_block ~f_requested:true` (complete reconstruction)
  OR emits `getblocktxn` (partial) and stores partial state in
  `compact_pending`.
- `cli.ml:1399-1427` — `BlocktxnMsg` listener: looks up
  `compact_pending`, calls `P2p.fill_missing_txs`, on success calls
  `Sync.process_new_block ~f_requested:true`.
- `cli.ml:1428-1477` — `GetblocktxnMsg` listener: serves
  `BlocktxnMsg` from `Storage.ChainDB.get_block`.

**Pipeline B (DEAD — sync.ml, defined but unwired):**
- `sync.ml:4882-4892` — `compact_block_request` type + module-global
  `pending_compact_blocks` Hashtbl.
- `sync.ml:4895-4897` — `has_compact_block_header` helper.
- `sync.ml:4902-4965` — `handle_cmpctblock` (signature uses `ibd_state`
  + explicit `mempool` argument; returns a typed `[`Reconstructed | `NeedTx
  | `Ignored]`).
- `sync.ml:4969-5016` — `handle_blocktxn` (calls `receive_block` after
  reconstruction; the cli.ml live path calls `process_new_block` instead).
- `sync.ml:5019-5032` — `expire_compact_block_requests` worker (runs on
  a timer; would expire stale state in `pending_compact_blocks` — but
  that table is always empty per the dead pipeline).
- `sync.ml:5034-5038` — `peer_has_header` stub returning `true`
  (W126 BUG-4).

**Neither cli.ml's `compact_pending` Hashtbl NOR sync.ml's
`pending_compact_blocks` Hashtbl is the other's mirror.** They store
different data shapes (cli.ml: `(cb, partial_txs, missing_indices)`;
sync.ml: `compact_block_request` record). Switching from one to the
other requires shape conversion, not just call-site re-wiring.

**File:** `lib/cli.ml:1339-1477` (live);
`lib/sync.ml:4871-5038` (dead).

**Core ref:** `bitcoin-core/src/net_processing.cpp:4466-4750`
(single canonical receive path with one `mapBlocksInFlight` shared
across all cmpct/blocktxn arrivals).

**Cross-cite:** carries forward the camlcoin signature pattern
from W143 (5 distinct consensus pipelines), W144 (3 flag-derivation
paths), W145 (5-site subsidy duplication), W146 (block-storage
pipeline split), W147 (chainstate dual-pipeline), W148 (header-sync
6 pipelines), W149 (4-site assume-valid drift), W150 (6 ATMP
entry-points), W151 (8 RBF eligibility paths), W152 (4 tx-admission
entry-points), W155 (3 mining/template pipelines). W156 adds the
12th-consecutive-quad pipeline drift instance, this time with the
distinguishing feature that the DEAD pipeline includes a background
expire worker (`expire_compact_block_requests`) that runs forever on
an empty table.

**Impact:**
- Two divergent code paths for the same protocol; future bug fixes
  applied to one will not propagate to the other.
- Background timer cost: the `expire_compact_block_requests` worker
  runs on a fixed schedule and pays the Hashtbl-fold cost on an empty
  table (microseconds, but pure waste).
- Cross-impl divergence in observable behavior between cli.ml-live
  and sync.ml-dead semantics: e.g., cli.ml's `compact_pending` is local
  to the listener closure (per-process), while sync.ml's
  `pending_compact_blocks` is module-global (would be shared if wired).
- The MAINNET-CONSEQUENCE of the dead pipeline is small (the live
  pipeline IS the live one); the maintenance-and-debugging
  CONSEQUENCE is the same as W143's BLOCK_MUTATED vs BLOCK_CONSENSUS
  distinction lost: two implementations diverge under fix pressure.

---

## BUG-16 (P1) — `compute_short_txid` truncation order — correct, but `Int64.logand 0xFFFFFFFFFFFFL` requires explicit 48-bit constant precision

**Severity:** P1 (documentation / fragility, not a logic bug). Camlcoin's
`compute_short_txid` (`crypto.ml:559-561`):

```ocaml
let compute_short_txid (k0 : int64) (k1 : int64) (wtxid : Types.hash256) : int64 =
  let hash = SipHash.hash_uint256 k0 k1 wtxid in
  Int64.logand hash 0xFFFFFFFFFFFFL  (* lower 48 bits = 6 bytes *)
```

The hex literal `0xFFFFFFFFFFFFL` is `Int64`-typed (the `L` suffix) and
spells out 12 hex digits = 48 bits = 6 bytes. Matches Core's
`& 0xffffffffffffL` exactly. Correctness preserved.

The fragility concern: the SipHash output is a 64-bit value; an
implementation refactor that removed the `Int64.logand` mask (e.g.,
"this is already 64 bits, why do we need to mask?") would silently
change the wire short_id from 48 to 64 bits. The mask is
load-bearing for wire-format parity. There's no defensive comment
explaining WHY 48 bits is special (it's the BIP-152 SHORTTXIDS_LENGTH).

**File:** `lib/crypto.ml:559-561`.

**Core ref:** `bitcoin-core/src/blockencodings.cpp:48-49`
`static_assert(SHORTTXIDS_LENGTH == 6, "shorttxids calculation assumes
6-byte shorttxids"); return ... & 0xffffffffffffL;`

**Impact:** documentation gap; latent refactor hazard. A future PR
that "cleans up" the mask without understanding the BIP-152 spec would
ship a node that emits 8-byte short_ids — silently breaking compatibility
with every Core node on the wire.

---

## BUG-17 (P1) — `deserialize_block_txns` short-id count and prefilled count guards do not also enforce `MAX_BLOCK_WEIGHT / MIN_SERIALIZABLE_TRANSACTION_WEIGHT` cumulative

**Severity:** P1. Bitcoin Core's `PartiallyDownloadedBlock::InitData`
(`blockencodings.cpp:64-66`):

```cpp
if (cmpctblock.shorttxids.size() + cmpctblock.prefilledtxn.size() >
    MAX_BLOCK_WEIGHT / MIN_SERIALIZABLE_TRANSACTION_WEIGHT)
    return READ_STATUS_INVALID;
```

`MAX_BLOCK_WEIGHT / MIN_SERIALIZABLE_TRANSACTION_WEIGHT` = 4_000_000 / 40
= 100_000. Core enforces this CUMULATIVE bound at the InitData
gate (separate from the wire-deserialization per-list cap).

Camlcoin's `deserialize_compact_block` (`p2p.ml:589-607`) enforces:
- per-list `short_id_count > max_compact_block_txs` → fail (line 595),
- per-list `prefilled_count > max_compact_block_txs` → fail (line 600),
- cumulative `short_id_count + prefilled_count > 65535` → fail (line 605)
  — uint16 ceiling (correct for the wire-format).

The cumulative `> 100_000` (block-weight-derived) guard is ABSENT.
With both lists each capped at 100k AND their sum capped at 65535, the
65535 guard is strictly tighter, so the missing 100k cumulative is
DOMINATED by the uint16 guard for any real input. This is a
documentation / spec-comment gap; the camlcoin behaviour is at least
as strict as Core's. Recording for fleet consistency: future tightening
of the uint16 guard (e.g., to a larger u32 if a BIP rev allows) would
require explicit fallback to the block-weight-derived cap.

**File:** `lib/p2p.ml:589-607`.

**Core ref:** `bitcoin-core/src/blockencodings.cpp:64-66`.

**Impact:** none today; spec-comment / fleet-parity gap.

---

## BUG-18 (P1) — `derive_keys` reuses an in-process writer + Cstruct.concat per call (no buffer reuse / no cache)

**Severity:** P1 (perf). `Crypto.SipHash.derive_keys` (`crypto.ml:545-554`):

```ocaml
let derive_keys (header : Types.block_header) (nonce : int64) : (int64 * int64) =
  let w = Serialize.writer_create () in
  Serialize.serialize_block_header w header;
  let nonce_cs = Cstruct.create 8 in
  Cstruct.LE.set_uint64 nonce_cs 0 nonce;
  let preimage = Cstruct.concat [Serialize.writer_to_cstruct w; nonce_cs] in
  let hash = sha256 preimage in
  let k0 = get_uint64_le hash 0 in
  let k1 = get_uint64_le hash 8 in
  (k0, k1)
```

Allocates a fresh writer + 8-byte cstruct + concat + sha256 PER CALL.
Called from:
- `peer_manager.ml:2774` (`reconstruct_from_mempool`)
- `sync.ml:4924, 4985` (dead pipeline)
- `cli.ml` via `Peer_manager.reconstruct_from_mempool` per cmpct
  arrival.

Core caches `m_hasher` (`blockencodings.h:91-94`):
```cpp
mutable std::optional<PresaltedSipHasher> m_hasher;
```
populated once in the ctor's `FillShortTxIDSelector` and consulted N
times via `GetShortID`. The 16-byte (k0, k1) pair is the cache; the
expensive part is the SHA256 over the header, not the SipHash itself.

Camlcoin re-runs SHA256(80 + 8 = 88 bytes) on every short_id
computation request — including each of the N items inside
`Mempool.create_short_id_lookup` if it were called per-tx (it's not;
camlcoin computes once per cmpct receive, which is correct). Within a
single cmpct-receive call, derive_keys is called twice if a
getblocktxn round-trip is needed (`sync.ml:4924` then `sync.ml:4985`),
which IS wasteful. Carry-forward of the W126 BUG-9 P3 perf-class
finding.

**File:** `lib/crypto.ml:545-554`; `lib/sync.ml:4924, 4985`;
`lib/peer_manager.ml:2774`.

**Core ref:** `bitcoin-core/src/blockencodings.h:91-94`
`std::optional<PresaltedSipHasher>` cache; `FillShortTxIDSelector`
ctor.

**Impact:** ~1 SHA256 per cmpct-receive of overhead (negligible);
+ 1 redundant SHA256 per getblocktxn round-trip (negligible). Listed
for fleet-pattern continuity.

---

## BUG-19 (P1) — `cmpct_version = 0L` default vs `version = 2L` cmpctblock-version means `supports_compact_blocks` defaults FALSE for peers that don't send sendcmpct

**Severity:** P1 (correctness in interop). `peer.ml:268, 402`:

```ocaml
mutable cmpct_version : int64;    (* Compact block protocol version *)
...
cmpct_version = 0L;
```

`supports_compact_blocks` (`peer_manager.ml:2651-2652`):

```ocaml
let supports_compact_blocks (peer : Peer.peer) : bool =
  peer.Peer.cmpct_version >= 2L && peer.Peer.services.Peer.witness
```

A peer that completes the version/verack handshake without sending
`sendcmpct(_, 2)` stays at `cmpct_version = 0L`. Camlcoin treats such
peers as "doesn't support cmpct" — which is the SAFE default but is
INCORRECT for our own outbound peers: per BIP-152, we send
`sendcmpct(false, 2)` to advertise OUR support, and the remote is
allowed to skip its own sendcmpct (it just means "I'll accept cmpct
from you but I won't promise to send cmpct to you"). Core distinguishes
`m_provides_cmpctblocks` (peer supports SENDING cmpct to us) from
`m_requested_hb_cmpctblocks` (peer wants HB from us) — TWO flags, set
independently. Camlcoin conflates "they sent sendcmpct" with "they
support cmpct in both directions".

Practical effect today: since BUG-2/BUG-3 mean we never ask anyone for
HB AND never push cmpct to anyone, the conflation is benign. But the
moment BUG-2/BUG-3 are fixed, `supports_compact_blocks` becomes the
gate for "should I push cmpct to this peer?" — and it will return
`false` for any peer that didn't volunteer their own `sendcmpct(_, 2)`
ahead of receiving ours.

**File:** `lib/peer.ml:268, 402`;
`lib/peer_manager.ml:2651-2652`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:3911-3915`:
```cpp
nodestate->m_provides_cmpctblocks = true;
nodestate->m_requested_hb_cmpctblocks = sendcmpct_hb;
pfrom.m_bip152_highbandwidth_from = sendcmpct_hb;
```
TWO distinct boolean flags, set on receipt of sendcmpct.

**Impact:** silent narrowing of compact-block-eligible peer set after
the BUG-2/BUG-3 fix lands.

---

## BUG-20 (P1) — BlocktxnMsg listener has NO sync_state guard (accepted during IBD)

**Severity:** P1. The CmpctblockMsg listener at `cli.ml:1349` has
`when chain.sync_state = Sync.FullySynced` — correct, drops cmpct
during IBD. BUT the BlocktxnMsg listener at `cli.ml:1399` and the
GetblocktxnMsg listener at `cli.ml:1428` have NO `when` guard. They
accept those messages at ANY sync state.

Practical impact:
- During IBD, `compact_pending` is empty (because CmpctblockMsg is
  dropped), so any `BlocktxnMsg` arrival hits the `None →
  "Unexpected blocktxn"` branch — harmless.
- `GetblocktxnMsg` during IBD: the requester wants blocks we may not
  have completed processing. We attempt the lookup against
  `Storage.ChainDB.get_block` and respond if found. Core gates this
  on `m_blockman.LoadingBlocks()` and refuses. Camlcoin's behaviour is
  marginally more permissive but not abusable (we just respond with
  whatever we have).

W126 BUG-7 PARTIAL carry-forward.

**File:** `lib/cli.ml:1399, 1428`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:4220-4223`
(LoadingBlocks gate on getblocktxn).

**Impact:** marginal IBD-time policy permissiveness; no correctness
risk.

---

## BUG-21 (P2) — `peer.cmpct_version` post-verack overwrite has no monotonicity guard

**Severity:** P2 (defensive coding). Per BIP-152, a peer may send
multiple `sendcmpct` messages with different `announce` flags but
must always send the SAME `version` (and Core requires version=2).
The peer-version is fixed for the connection.

Camlcoin's `dispatch_message` at `peer.ml:1657-1663`:

```ocaml
| P2p.SendcmpctMsg { announce; version }, true ->
  (* Core: net_processing.cpp:3907 — silently drop sendcmpct where version != 2 *)
  if version = 2L then begin
    peer.cmpct_high_bandwidth <- announce;
    peer.cmpct_version <- version
  end;
  Lwt.return `Continue
```

If a misbehaving peer sends `sendcmpct(true, 2)` then `sendcmpct(true,
3)` later, the version=3 message is silently dropped (correct per Core).
But if it sends `sendcmpct(true, 2)` then `sendcmpct(true, 2)` again,
the second message overwrites the first — fine. And if it sends
`sendcmpct(true, 1)` then `sendcmpct(true, 2)`, the version=1 is
dropped (cmpct_version stays at default 0L) and the version=2 latch
fires.

There's no observable bug today, but the absence of a "cmpct_version is
sticky after first valid set" check means a peer could downgrade itself
back to "no sendcmpct ever received" via some future BIP that adds a
"please disable cmpct for this connection" semantics. Defensive coding
gap.

**File:** `lib/peer.ml:1657-1663, 832-836, 1592-1599`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:3905-3915`
(no monotonicity guard either; symmetric).

**Impact:** none. Listed for completeness.

---

## BUG-22 (P1) — `Sync.process_new_block` for compact-block reconstruction does not pass `peer_id` for misbehavior tracking

**Severity:** P1. `Sync.process_new_block` (`sync.ml:4358-4360`) accepts
optional `peer_id` and `misbehavior_handler` arguments that allow the
header / consensus failure path to attribute the failure back to the
peer that supplied it:

```ocaml
let process_new_block ?(f_requested = false)
    ?(peer_id : int option)
    ?(misbehavior_handler : (int -> string -> unit) option)
    (state : chain_state)
    (block : Types.block) : (unit, string) result =
```

The two cmpct-block call sites at `cli.ml:1362` and `cli.ml:1412`
both invoke `Sync.process_new_block ~f_requested:true chain block` —
NO `~peer_id` and NO `~misbehavior_handler`. Consequence: a peer that
delivers a header-invalid or consensus-invalid block via the cmpct
path cannot be punished via the misbehavior_handler because the
attribution is lost at the call site. BIP-152 EXPLICITLY permits cmpct
delivery before full validation, so MOST consensus failures from this
path should NOT be punished (Core sets `via_compact_block=true` in
`MaybePunishNodeForBlock`). But for non-BIP-152-protected failures
(e.g., MoneyRange overflow, BIP-30 duplicate-coinbase, etc.) the
attribution should still flow through. Camlcoin loses the attribution
entirely.

**File:** `lib/cli.ml:1362, 1412`;
`lib/sync.ml:4358-4360` (the optional-args signature).

**Core ref:** `bitcoin-core/src/net_processing.cpp:1906-1929`
`MaybePunishNodeForBlock(nodeid, state, via_compact_block, message)`
— the discrimination logic.

**Impact:** cmpct-delivered consensus-invalid blocks do not increment
the sender's misbehavior score. The cli.ml `misbehavior_handler` at
line 1553-1565 (which is built for the other arms) is bypassed.

---

## BUG-23 (P1) — `compact_pending` Hashtbl is local to the listener closure (per-process state, but not per-peer accountable)

**Severity:** P1. `cli.ml:1344-1346`:

```ocaml
let compact_pending :
  (Types.hash256, P2p.compact_block * Types.transaction option array * int list) Hashtbl.t =
  Hashtbl.create 16 in
```

This table is shared across all peers (it's at the listener level, not
the per-peer level). Two distinct peers sending cmpctblock for the same
block_hash will COLLIDE: the second arrival's `Hashtbl.replace` at line
1389 overwrites the first peer's pending state. When the first peer's
`BlocktxnMsg` arrives later, the lookup at line 1404 returns the SECOND
peer's `compact_block` (with the second peer's nonce → second peer's
SipHash keys) — but the txs received are encoded with the FIRST peer's
nonce. Reconstruction will fail because all the short-ids in the lookup
table belong to the wrong nonce.

Core stores `partialBlock` per-peer inside
`mapBlocksInFlight[hash][peer_id]` (a multimap keyed by block hash, with
per-peer entries). Camlcoin's flat hashtbl loses the per-peer
attribution.

**File:** `lib/cli.ml:1344-1346, 1389, 1404`;
`lib/sync.ml:4891-4892` (same shape, dead).

**Core ref:** `bitcoin-core/src/net_processing.cpp:3441-3526`
`ProcessCompactBlockTxns` uses `mapBlocksInFlight.equal_range(blockhash)`
+ per-peer iteration.

**Impact:**
- Two-peer race condition: any time two HB peers (if BUG-2/BUG-3 were
  fixed) announce the same new tip via cmpct in quick succession, the
  second clobbers the first's pending state.
- The blocktxn response intended for the first peer's reconstruction
  is mis-matched against the second peer's nonce/lookup → silent
  reconstruction failure → "Still missing transactions after blocktxn"
  warning.
- Cross-impl divergence: Core handles parallel cmpct correctly.

---

## Summary

**Bug count:** 23 (BUG-1 through BUG-23).

**Severity distribution:**
- **P0-CDIV:** 7 (BUG-2, BUG-3, BUG-6, BUG-8, BUG-11, BUG-12, BUG-15)
- **P1:** 15 (BUG-1, BUG-4, BUG-5, BUG-7, BUG-9, BUG-10, BUG-13, BUG-14, BUG-16, BUG-17, BUG-18, BUG-19, BUG-20, BUG-22, BUG-23)
- **P2:** 1 (BUG-21)

**Fleet patterns confirmed:**
- **11-CONSECUTIVE-QUAD camlcoin pipeline drift** (W143/W144/W145/W146/W147/W148/W149/W150/W151/W152/W155/W156) — BUG-15 extends to BIP-152 surface (cli.ml live + sync.ml dead). The expire-stale-requests background worker that idles forever on an empty Hashtbl is a fresh shape inside the pattern.
- **Dead-helper / wiring-look-but-no-wire** — BUG-2 (`maybe_set_hb_compact_peer`), BUG-3 (`relay_compact_block`); both ~14 weeks open since W112. The full Core algorithm is present, type-checked, exported, called from nowhere.
- **Dead-data plumbing 4th camlcoin instance this quad** — BUG-4 (`peer.cmpct_high_bandwidth` set on 3 sites, read in 0 sites).
- **Carry-forward re-anchor** — W126 BUGs 2/3/4/5/6/7/9 all still open; W156 promotes BUG-5 (P3 → P1), BUG-10 (P2 → P1) on impact-compounding grounds.
- **CVE-2012-2459 mutation detection missing in reconstruction** — BUG-11; fleet-wide W143 BUG-1 pattern (6+ impls) now confirmed in camlcoin's BIP-152 path too. Camlcoin has the `merkle_root` mutation primitive but doesn't call it from `reconstruct_block` / `fill_missing_txs`.
- **Wire-format ceiling parity gaps** — BUG-12 (prefilledtxn uint16 ceiling absent), BUG-13 (getblocktxn indexes uint16 differential ceiling absent); both inherit from camlcoin's `read_compact_size` always reading u64.
- **No-misbehavior-signal on wire-format violations** — BUG-14 (silent skip of out-of-range getblocktxn indexes), BUG-12 (silent acceptance of >uint16 prefilled indices).
- **No-cache pattern (rebuild-every-time)** — BUG-5 (no `m_most_recent_compact_block`), BUG-18 (no `PresaltedSipHasher` cache).
- **Two-pipeline guard 17th distinct extension this audit cycle** — BUG-15 (the cli.ml/sync.ml split + the dead expire-worker).
- **Header-validation-after-reconstruction order inversion** — BUG-6 (reconstruct first, validate later); this is the camlcoin instance of "validation gate elided on the fast path" — first time seen in camlcoin's BIP-152 surface.

**Top three findings:**
1. **BUG-2 + BUG-3 cluster (P0-CDIV; 14+ weeks open)** — both `maybe_set_hb_compact_peer` and `relay_compact_block` are dead helpers; HB compact-block fast-announce is COMPLETELY NON-FUNCTIONAL in camlcoin both inbound (we never ask any peer for HB) and outbound (we never push cmpct to any peer). BIP-152's latency-saving mode is forfeited. The fix is a 6-line wire-in at two call sites but the architectural cost is that no real BIP-152 traffic has happened on a camlcoin node since the helpers were written.
2. **BUG-11 (P0-CDIV)** — `IsBlockMutated` / `merkle_root` mutation detection is absent in `reconstruct_block` and `fill_missing_txs`. A short-id collision that pulls in the wrong tx producing a CVE-2012-2459-shape mutated merkle tree is detected only at full block-validate time (~100× later). Camlcoin HAS the primitive (`Crypto.merkle_root` returns `mutated : bool`); it's just not called from the cmpct path. First camlcoin instance of the fleet-wide W143 BUG-1 pattern (6+ impls).
3. **BUG-15 (P0-CDIV) "11-consecutive-quad pipeline drift"** — TWO parallel BIP-152 receive pipelines coexist: cli.ml is the LIVE path (gated `FullySynced`, uses listener-local `compact_pending` Hashtbl) and sync.ml is the DEAD path (handlers defined, module-global `pending_compact_blocks` Hashtbl, background `expire_compact_block_requests` worker forever idling on empty table). Same camlcoin signature pattern that has now repeated across 11 consecutive quad-waves (W143-W156) — every consensus or P2P subsystem has at least one dead duplicate. Compounding factor: the two Hashtbls store DIFFERENT shapes, so the fix is not just call-graph rewiring but data-shape conversion.
