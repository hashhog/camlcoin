# W152 — Tx relay + inv batching + orphan handling (camlcoin)

**Wave:** W152 — `RelayTransaction`, `AddTxAnnouncement`, `ProcessMessage(msg_tx)`,
`ProcessMessage(msg_inv)`, `SendMessages` inv-batching loop,
`m_recently_announced_invs`, `m_tx_inventory_to_send`, `m_next_inv_send_time`,
`MaybeSendMessage` cadence, `TxOrphanage::AddTx`, `EraseTx`, `EraseForBlock`,
`EraseForPeer`, `LimitOrphans`, `OrphanByParent`, `TxDownloadManager`,
`TxRequestTracker`, `MAX_PEER_TX_REQUEST_IN_FLIGHT=100`, `GETDATA_TX_INTERVAL=60s`,
`TXID_RELAY_DELAY=2s` (BIP-339), `NONPREF_PEER_TX_DELAY=2s`,
`OVERLOADED_PEER_TX_DELAY=2s`, `DEFAULT_MAX_ORPHAN_TRANSACTIONS=100`,
`MAX_PEER_TX_ANNOUNCEMENTS=5000`, `INVENTORY_BROADCAST_PER_SECOND=7`,
`INVENTORY_BROADCAST_MAX_PER_MB=7000`, `MAX_INV_SZ=50000`, `MSG_TX=1`, `MSG_WTX=5`,
`MSG_WITNESS_TX=0x40000001`, `MSG_FILTERED_BLOCK=3`, BIP-37 mempool-on-inv,
BIP-37 IsRelevantAndUpdate per-relay, BIP-339 wtxidrelay handshake,
`AddKnownTx`, `m_recent_rejects`, `RejectIncomingTxs`.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/net_processing.cpp:2243-2287` —
  `RelayTransaction(txid, wtxid)`: for every peer with `m_tx_relay` AND
  `!pfrom.IsBlockOnlyConn()` (i.e., NOT block-relay-only), pushes the txid OR
  wtxid (depending on `peer.m_wtxid_relay`) into `tx_relay->m_tx_inventory_to_send`.
  The per-peer inventory queue is flushed on the Poisson-scheduled tick.
- `bitcoin-core/src/net_processing.cpp:140-148` (constants):
  `INVENTORY_BROADCAST_PER_SECOND = 7`, `INVENTORY_BROADCAST_MAX_PER_MB = 7000`,
  `INVENTORY_BROADCAST_INTERVAL = 5s (inbound)` / `2s (outbound)` (Poisson),
  `MAX_PEER_TX_ANNOUNCEMENTS = 5000`, `MAX_PEER_TX_REQUEST_IN_FLIGHT = 100`,
  `MAX_TXID_RELAY_DELAY = 2s` (BIP-339), `NONPREF_PEER_TX_DELAY = 2s`,
  `OVERLOADED_PEER_TX_DELAY = 2s`, `GETDATA_TX_INTERVAL = 60s`, `MAX_INV_SZ = 50_000`.
- `bitcoin-core/src/txorphanage.h:60-79`, `txorphanage.cpp` —
  `DEFAULT_MAX_ORPHAN_TRANSACTIONS = 100`, `TxOrphanageImpl::AddTx` indexes by
  (wtxid → OrphanTx) AND maintains `OrphanByParent` map keyed by **parent
  outpoint** (so when a parent arrives the children spendng it are resolved
  O(children-of-parent), not O(orphan-pool-size)). `EraseTx(wtxid)` removes
  from both. `EraseForBlock(block)` walks each tx in the block and removes
  any orphan whose parent set intersects with the block's tx-outpoints (i.e.,
  newly confirmed). `EraseForPeer(peer)` removes all orphans submitted by that
  peer. `LimitOrphans(max_orphans, rng)` enforces the cap by random eviction.
- `bitcoin-core/src/net_processing.cpp:3835-4047` — `ProcessMessage(msg_inv)`:
  per-INV vector: `AddKnownTx(peer, hash)` is called first (always — both for
  txs we'll accept AND txs we already have, so the peer is recorded as
  knowing); skip if `m_recently_announced_invs.contains(hash)`; if blocks-only
  connection → MISBEHAVING(100); reject if `m_lazy_recent_rejects.contains(hash)`;
  otherwise `txrequest.ReceivedInv(peer, GenTxid::{Wtxid,Txid}(hash), ...)` which
  schedules the request with delay = `peer.IsPreferredDownloadPeer() ? 0 : NONPREF_PEER_TX_DELAY`
  + `wtxid_relay ? 0 : TXID_RELAY_DELAY`.
- `bitcoin-core/src/net_processing.cpp:3590-3725` — `ProcessMessage(msg_tx)`:
  refuses tx if `IsBlockOnlyConn()`; computes `gtxid = wtxid_relay ?
  GenTxid::Wtxid(wtxid) : GenTxid::Txid(txid)`; calls `txrequest.ReceivedResponse(gtxid)`;
  calls `m_chainman.ProcessTransaction(tx)` which dispatches to
  `MemPoolAccept::AcceptSingleTransaction`. On `TX_MISSING_INPUTS` the tx is
  handed to `TxDownloadManager` which calls `m_orphanage.AddTx(tx, peer.id)`
  AND queues a getdata for each unique parent txid.
- `bitcoin-core/src/net_processing.cpp:2289-2347` — `SendMessages`
  inv-batching loop: per-peer, while `now >= peer.m_next_inv_send_time` AND
  `!peer.m_tx_inventory_to_send.empty()`, drain up to
  `INVENTORY_BROADCAST_TARGET = INVENTORY_BROADCAST_PER_SECOND × interval`
  items, intersection-filter against the peer's bloom_filter (BIP-37), append
  to inv message, then schedule next via Poisson with rate
  `1 / INVENTORY_BROADCAST_INTERVAL`. Also: `m_recently_announced_invs.insert(hash)`
  for every announced item (24-hour rolling); on a future `getdata` for that
  hash, `m_recently_announced_invs.contains(hash)` bypasses the
  `m_lazy_recent_rejects` filter so we can serve a tx we just announced.
- `bitcoin-core/src/net_processing.cpp:4189-4259` — `ProcessMessage(msg_getdata)`:
  per item, gates on `m_recently_announced_invs` AND on
  `MAX_PEER_TX_REQUEST_IN_FLIGHT`; serves from mempool (`pool->get(GenTxid::Wtxid(hash))`
  OR `pool->get(GenTxid::Txid(hash))`); witness inclusion is gated on
  `iv.type == MSG_WITNESS_TX || iv.type == MSG_WTX` (legacy `MSG_TX` strips
  the witness via `tx.ToString(serialize_flags = TX_NO_WITNESS)`); for
  `MSG_FILTERED_BLOCK` the bloom filter is consulted to send a `merkleblock`
  with only the matching tx/proofs.
- `bitcoin-core/src/net_processing.cpp:4451-4502` — BIP-35 `msg_mempool`:
  iterate mempool; for each entry, if peer has bloom_filter AND
  `!IsRelevantAndUpdate(tx)` → skip; if `entry.GetFee() / entry.GetTxSize() <
  peer.m_fee_filter` → skip; push `CInv{wtxid_relay ? MSG_WTX : MSG_TX, hash}`
  into the per-peer inv queue (NOT the wire directly — so the cadence /
  Poisson timer still applies).
- `bitcoin-core/src/net_processing.cpp:5455-5478` — `MaybeSendInv` flow,
  `m_fee_filter_rounder` privacy (FeeFilterRounder spaces buckets 1.1× apart
  with randomized rounding).

**Files audited**
- `lib/p2p.ml` (3734 lines) — `inv_type` enum (170-201); `inv_vector` type
  (203-209); `deserialize_inv_list` cap (492-496); `max_inv_count = 50_000` (11);
  `max_getdata_count = 1000` (12); `serialize_message`/`deserialize_message`
  dispatch (774-973); `Erlay` `handle_reconcildiff` (1321-1345).
- `lib/peer.ml` (2066 lines) — `inv_entry` (229-234); `inv_queue` field
  (283-285), `next_inv_send` Poisson tick (284, 415, 1854); `start_trickling`
  loop (1865-1890); `queue_inv` enqueue gate (1775-1788); `make_block_inv` /
  `make_tx_inv` (1791-1800); `flush_inv_queue` (1809-1846 — Fisher-Yates
  shuffle); `inbound_inv_broadcast_interval = 5.0` / `outbound_inv_broadcast_interval = 2.0`
  (214-215); `max_inv_per_flush = 1000` (216); `poisson_delay` (345-348);
  `block_relay_only` field (269, 403); `wtxid_relay` field (258, 390, 826,
  1575); `peer.relay` field (265, 743, 1552); `handle_getdata` (1454-1528 —
  serves any InvTx/InvWtx/InvWitnessTx identically via `lookup_tx`; falls
  through `MSG_FILTERED_BLOCK` as `_ → not_found`); `dispatch_message` for
  post-handshake (1535-1697 — the `| _, true → Continue` catchall at line
  1680 means InvMsg/TxMsg/GetdataMsg are silently routed to listeners with
  no built-in misbehavior gate); `read_message_with_timeout` exception
  swallow (609-661 — `failwith` from `deserialize_inv_list` is treated as
  `Timeout` rather than misbehavior).
- `lib/peer_manager.ml` (2777 lines) — `add_listener` (301); message-loop
  fan-out (1795-2010); `announce_tx` (1375-1403 — honors `bloom_filter` via
  `IsRelevantAndUpdate`, queues via `Peer.queue_inv`); `announce_block`
  (1367); `remove_peer` (1032-1051 — no orphan-erase, no `EraseForPeer`);
  `MempoolMsg` self-documenting no-op case (1821-1829); BIP-37 bloom gates
  for FilterLoad/FilterAdd (1837-1900).
- `lib/cli.ml` (3000+ lines) — P2P TxMsg listener (1237-1330 — drops orphan
  txs, immediate-send-without-trickle, no bloom-filter check, no
  block_relay_only check on receive, no peer.relay check on receive,
  hardcodes InvWtx for ALL inv-receive→getdata regardless of peer
  capability); GetdataMsg listener (835-878 — `lookup_tx` uses
  `Mempool.get` which is txid-only, so any InvWtx for a segwit tx whose
  wtxid != txid fails); InvMsg listener for block-only (882-899); BIP-35
  MempoolMsg dispatch via Sync.handle_mempool_msg_for (816-825).
- `lib/sync.ml` (5000+ lines) — `handle_mempool_msg_for` (4628-4684 —
  enforces NODE_BLOOM service but IGNORES peer bloom filter on response);
  `handle_notfound` for blocks only (1936-1969); `max_mempool_inv_items = 50_000`
  (4616).
- `lib/mempool.ml` (4374 lines) — `orphan_entry` type (51-56); `orphans`
  hashtbl wtxid_str → entry (85); `orphan_by_txid` SECONDARY index txid_str
  → wtxid_str for self-dedup (NOT parent-keyed) (86); `max_orphans = 100`
  (87, 258); `add_orphan` (3185-3221); `remove_orphan` (3225-3228);
  `process_orphans` (3233-3260); `expire_orphans` (3429-3441); `orphan_count`
  (3411-3412); `find_1p1c_for_orphan` (4252-4268 — explicit `None` stub);
  `try_1p1c_with_orphans` (4273-4294); `process_orphans_with_cpfp` (4298-4328);
  `Mempool.create` regtest-hardcode (233-237, W150 BUG-4 carry-forward);
  `set_network` (3452 — dead-helper).
- `lib/package_relay.ml` — `lookup_tx_by_wtxid` O(N) scan because mempool has
  no wtxid index (21-28).
- `lib/rpc.ml` — `sendrawtransaction` (1149-1222 — calls `add_transaction` not
  `accept_to_memory_pool`; bypasses the exception wrapper, doesn't trigger
  process_orphans on success; same W150 BUG-2 shape).
- `test/test_w103_tx_relay.ml` — 13-bug carry-forward record from prior wave;
  BUG-2 (expire_orphans) reported as FIXED, others open.
- `test/test_w116_package_relay.ml` — BUG-9 (find_1p1c_for_orphan stub),
  BUG-10 (process_orphans_with_cpfp dead), BUG-15 (try_1p1c_with_orphans
  call-site missing).

---

## Gate matrix (28 sub-gates / 10 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | Orphan pool admission | G1: `add_orphan` is wired to ATMP "missing inputs" path | **BUG-1 (P0-CDIV)** — dead helper, never called from production. Cross-cite W103 BUG-1, ~24 weeks open |
| 1 | … | G2: `orphan_by_parent` map exists (parent outpoint → children) | **BUG-2 (P1)** — only `orphan_by_txid` (self-keyed for dedup); parent-arrival resolution is O(orphan-pool-size) |
| 1 | … | G3: parent-getdata sent when orphan added | **BUG-3 (P1)** — moot today because add_orphan dead, but no code anywhere emits a parent-fetch getdata. Cross-cite W103 BUG-13 |
| 2 | Orphan lifecycle | G4: `process_orphans` called on every accepted tx | **BUG-4 (P0-CDIV)** — `process_orphans` and `process_orphans_with_cpfp` both defined, both never called from production. Cross-cite test_w116_package_relay BUG-10 |
| 2 | … | G5: `EraseForBlock` called on block-connect | **BUG-5 (P1)** — cli.ml:1218-1223 calls `expire_orphans` on block-connect (age-based GC, fixed W103 BUG-2) but NOT the per-block conflict-erasure that Core's `EraseForBlock` provides |
| 2 | … | G6: `EraseForPeer` called on peer disconnect | **BUG-6 (P1)** — `Peer_manager.remove_peer` (1032-1051) clears 6 per-peer hashtables but never touches the orphan pool |
| 2 | … | G7: `DEFAULT_MAX_ORPHAN_TRANSACTIONS=100` enforced | PASS in number (`max_orphans = 100` line 258); but G1/G4 mean the cap is exercised only by tests, not production. PARTIAL |
| 3 | wtxid-keyed mempool lookup | G8: mempool has wtxid → entry index | **BUG-7 (P0-CDIV)** — mempool is txid-keyed only; `lookup_tx` (cli.ml:863) and `Mempool.contains` (mempool.ml:275) operate on `entries[txid_str]`. Any InvWtx getdata for a segwit tx whose wtxid ≠ txid fails to find the tx. Cross-cite `package_relay.ml:21-28` self-documents the gap |
| 4 | Inv ingest scheduling | G9: `m_recently_announced_invs` filter | **BUG-8 (P0-CDIV)** — no `m_recently_announced_invs` analogue; a peer that just sent us an inv can have a different peer immediately re-announce the same wtxid and we'll emit a second getdata (no cross-peer dedup) |
| 4 | … | G10: `TXID_RELAY_DELAY=2s` BIP-339 delay for legacy peers | **BUG-9 (P0-CDIV)** — getdata is sent **immediately** on InvMsg arrival (cli.ml:1318-1327). No delay distinguishes wtxid-relay from legacy peers; BIP-339 sec. "tx receive priority" violated |
| 4 | … | G11: `NONPREF_PEER_TX_DELAY=2s` for non-preferred-download peers | **BUG-9 cross-cite** — no priority sort, no delay |
| 4 | … | G12: `OVERLOADED_PEER_TX_DELAY=2s` for overloaded peers | **BUG-9 cross-cite** |
| 4 | … | G13: `GETDATA_TX_INTERVAL=60s` reschedule on no-response | **BUG-10 (P0-CDIV)** — no in-flight tracking, no reschedule timer; if a peer ignores our getdata, the tx is silently lost |
| 4 | … | G14: `MAX_PEER_TX_REQUEST_IN_FLIGHT=100` cap | **BUG-10 cross-cite** — no per-peer in-flight cap |
| 5 | Tx admission DoS gates | G15: `RejectIncomingTxs` on block-relay-only peers | **BUG-11 (P0-SEC)** — cli.ml:1239 P2P TxMsg path does not check `peer.block_relay_only`; a BRO peer can spam txs. Cross-cite W103 BUG-4 still open |
| 5 | … | G16: `peer.relay = false` from version → reject incoming tx | **BUG-12 (P0-SEC)** — cli.ml:1239 also doesn't check `peer.relay`; a peer that said "don't send me txs" can still send us txs unchecked |
| 5 | … | G17: outbound BRO version sets `fRelay = false` | **BUG-13 (P1)** — `make_version_msg` (peer.ml:763-777) hardcodes `relay = true` for all directions. Cross-cite W103 BUG-6. The remote peer cannot honor our BRO intent |
| 5 | … | G18: `m_recent_rejects` cache for replayed-invalid txs | **BUG-14 (P1)** — no rejects cache; same invalid tx triggers full ATMP every time. Cross-cite W103 BUG-11 |
| 6 | Inv batching cadence | G19: Poisson timer per peer (5s/2s avg) | PASS (`peer.ml:214-215, 345-348, 1854`) |
| 6 | … | G20: `INVENTORY_BROADCAST_PER_SECOND=7` rate cap | **BUG-15 (P1)** — no per-second rate cap; trickle drains up to `max_inv_per_flush=1000` per Poisson interval per peer. Core caps at 7 × interval, scaled by `INVENTORY_BROADCAST_MAX_PER_MB=7000` |
| 6 | … | G21: P2P-arrived tx routes through trickle queue | **BUG-16 (P0-CDIV)** — cli.ml:1280-1295 bypasses the trickle queue entirely: immediate `Peer.send_message ... (InvMsg [single_item])`. Breaks privacy (no shuffle, no Poisson) and floods the wire with one-tx-per-inv-msg |
| 7 | inv→getdata GetData policy | G22: getdata batched at `MAX_GETDATA_SZ=1000` | PASS (cli.ml:1318-1327) |
| 7 | … | G23: incoming-getdata serves `MSG_TX` with witness STRIPPED | **BUG-17 (P0-CDIV)** — `handle_getdata` (peer.ml:1479-1488) serializes all tx-inv types via `Serialize.serialize_transaction` (with witness). Core strips witness for legacy MSG_TX. Cross-cite W103 BUG-12 still open |
| 7 | … | G24: getdata uses InvWtx for wtxidrelay peers, InvWitnessTx for legacy | **BUG-18 (P0-CDIV)** — cli.ml:1311 hardcodes `InvWtx` for ALL inv-receive→getdata coercion. If a legacy peer sent InvTx with a txid, our getdata's InvWtx-with-that-hash is treated as a wtxid lookup on the remote and fails |
| 7 | … | G25: `MSG_FILTERED_BLOCK` dispatch when peer has bloom filter | **BUG-19 (P1)** — `handle_getdata` falls through `InvFilteredBlock` to the `_` arm → emits notfound. No `merkleblock` ever served. Cross-cite W134 fleet-wide gap |
| 8 | BIP-37 / BIP-339 receive-side | G26: `AddKnownTx(peer, hash)` per-peer "knows tx" filter | **BUG-20 (P1)** — no per-peer known-tx filter; same wtxid can be re-announced to the same peer N times. Cross-cite W103 BUG-10 |
| 8 | … | G27: NotfoundMsg routes to tx-request scheduler for reschedule | **BUG-21 (P1)** — `NotfoundMsg` is only handled for BLOCKS (cli.ml:811-813 calls `Sync.handle_notfound`); tx-notfound items are silently dropped (no path to retry from a different peer) |
| 9 | BIP-37 mempool dump | G28: `IsRelevantAndUpdate` filter on BIP-35 response | **BUG-22 (P0-CDIV)** — `Sync.handle_mempool_msg_for` (sync.ml:4641-4660) iterates all mempool entries and applies ONLY the feefilter gate; `peer.bloom_filter` is never consulted. Peers that filterload+mempool get the entire mempool back, not the filtered subset |
| 9 | … | G29: announce_tx (sendrawtransaction) honors peer bloom filter | PASS (peer_manager.ml:1384-1391); two-pipeline drift — see BUG-23 |
| 10 | Multi-pipeline drift | G30: single canonical tx-admission entry point | **BUG-23 (P0-CDIV)** — at least 4 distinct entry points: (1) cli.ml:1240 `accept_to_memory_pool` (P2P TxMsg, with safe_run exception wrapper, immediate-send relay), (2) rpc.ml:1192 `add_transaction` (sendrawtransaction; bypasses exception wrapper, uses `Peer_manager.announce_tx` Poisson trickle), (3) package_relay.ml:61 `accept_package` (BIP-331 pkgtxns), (4) test/RPC test paths. **5th-consecutive-quad camlcoin pipeline drift** (W143 5 pipelines, W148 6, W150 6, W151 8, W152 4 distinct tx-relay paths) |

---

## BUG-1 (P0-CDIV) — `add_orphan` is dead-helper; ATMP "missing inputs" silently drops the tx

**Severity:** P0-CDIV. Bitcoin Core's `PeerManagerImpl::ProcessMessage(msg_tx)`
at net_processing.cpp:3625-3655 routes the result of
`ProcessTransaction(tx)` based on `TxValidationState`. On
`TxValidationResult::TX_MISSING_INPUTS`, the tx is handed to
`TxDownloadManager::HandleTxMissingInputs` which:
1. Calls `m_orphanage.AddTx(tx, pfrom.GetId())` to enter the orphan pool.
2. Iterates `tx.vin` to compute `unique_parents` (set of parent txids).
3. For each unique parent, calls `txrequest.ReceivedInv(peer,
   GenTxid::Txid(parent_txid), ...)` to schedule parent fetch.

camlcoin's P2P TxMsg listener (`cli.ml:1237-1304`) calls
`Mempool.accept_to_memory_pool` and inspects `result.atmp_accepted`. On
failure, it logs `Rejected tx X: <reason>` at debug level and **drops the
tx**. The orphan pool is never populated from the receive path.
`Mempool.add_orphan` is defined (mempool.ml:3185-3221) but a grep over
`lib/` and `bin/` shows **zero call sites**.

**Failure scenarios:**
- Two-tx chain (parent + child) arrives child-first (legitimate on a
  reorg or under packet reordering): child is rejected with
  `"Missing input"`, dropped; parent arrives later, no resolution
  loop fires (BUG-4); child must be re-announced by a peer.
- 1p1c (parent rejected for low fee, child willing to CPFP): the
  whole CPFP package admission path (`try_1p1c_with_orphans`,
  `process_orphans_with_cpfp`) cannot trigger because the orphan
  is never recorded. Cross-cite test_w116_package_relay BUG-15.

**File:** `lib/cli.ml:1297-1303` (the drop), `lib/mempool.ml:3185-3221`
(`add_orphan` defined, never called).

**Core ref:** `bitcoin-core/src/net_processing.cpp:3625-3655` ProcessMessage(msg_tx)
on missing-inputs; `bitcoin-core/src/node/txdownloadman_impl.cpp` HandleTxMissingInputs;
`bitcoin-core/src/txorphanage.cpp::TxOrphanageImpl::AddTx`.

**Cross-cite:** W103 BUG-1 (open since W103 ~24 weeks ago, never fixed).
test_w103_tx_relay.ml:7-11 explicitly catalogues this gap. test_w99
G13 covers "process_orphans is callable in isolation" — i.e., the test
itself only verifies the function compiles, not that it is wired.

**Impact:** orphan-handling subsystem is **architecturally non-functional**
from the P2P receive path. The pool is only ever populated by direct test
code calling `add_orphan` (tests in test_w103, test_w116). Production
nodes pay the full N×ATMP cost for every re-announced orphan rather than
the O(1) "already an orphan" short-circuit Core gets.

---

## BUG-2 (P1) — `OrphanByParent` map absent; resolution is O(orphan-pool-size)

**Severity:** P1. Bitcoin Core's `TxOrphanageImpl` maintains TWO indices:
1. Primary: `m_orphans` keyed by `wtxid` → `OrphanTx`.
2. Secondary: `m_outpoint_to_orphan_it` keyed by `(parent_txid, parent_vout)` →
   set of orphan-iterators. Built at `AddTx` time from `tx.vin`, used at
   `EraseForBlock` to find all orphans whose parent set intersects with
   the block's outputs, AND at parent-arrival to find children to retry.

camlcoin's `mempool` has `orphans : wtxid_str → orphan_entry` AND
`orphan_by_txid : txid_str → wtxid_str` (mempool.ml:85-86), but the
secondary index is **self-keyed** (the orphan's own txid for dedup —
useful when a parent arrives whose txid was previously announced),
NOT **parent-outpoint-keyed**. Consequence: `process_orphans` (mempool.ml:3233-3260)
scans the ENTIRE orphan pool on every accepted tx and iterates
`orphan.orphan_tx.inputs` per orphan. O(N) where N = max_orphans = 100,
which is small today but scales linearly if the cap is ever raised.

**File:** `lib/mempool.ml:83-87` (the wrong-shape secondary index),
`lib/mempool.ml:3233-3260` (O(N) resolution loop),
`lib/mempool.ml:4252-4268, 4273-4294, 4298-4328` (all O(N) scans).

**Core ref:** `bitcoin-core/src/txorphanage.h:71-79` two-index design;
`bitcoin-core/src/txorphanage.cpp::AddTx` populates both indices.

**Impact:** correctness-neutral at max_orphans=100, but the design is
locked into O(N) parent-arrival resolution. If `add_orphan` is ever
wired (BUG-1 fix), this becomes a hot path. Also: the secondary index
serves a fundamentally different purpose than Core's, so future
refactors that "raise max_orphans for testing" will introduce
non-trivial regression risk.

---

## BUG-3 (P1) — No parent-getdata sent when orphan is recorded

**Severity:** P1 (moot today because BUG-1 means `add_orphan` is dead;
becomes P0-CDIV the moment BUG-1 is fixed). Core's `HandleTxMissingInputs`
emits a getdata for each unique parent txid of the orphan immediately
after `m_orphanage.AddTx`. camlcoin has no production code that emits
parent-fetch getdata anywhere — even if `add_orphan` were wired, the
orphan would sit in the pool until a parent arrives spontaneously
(typically from a different peer's relay).

**File:** `lib/cli.ml:1237-1330` (TxMsg listener; no parent-getdata path),
`lib/mempool.ml:3185-3221` (add_orphan; no callback to emit getdata).

**Core ref:** `bitcoin-core/src/node/txdownloadman_impl.cpp::HandleTxMissingInputs`
emits `MSG_TX` getdata for parent txids; `MSG_WTX` is NOT used here
because we don't know the parent's wtxid at orphan-record time.

**Cross-cite:** W103 BUG-13 still open.

**Impact:** orphan resolution waits for organic parent relay rather than
actively requesting; effectively a no-op orphan pool. Same chain
admission probability as "just drop the orphan" since we never
proactively fetch parents.

---

## BUG-4 (P0-CDIV) — `process_orphans` / `process_orphans_with_cpfp` are dead helpers

**Severity:** P0-CDIV. Core's `MemPoolAccept::Finalize` (validation.cpp:1100-1110)
hands off accepted txs to `TxDownloadManager::HandleAcceptedTx` which calls
`m_orphanage.AddChildrenToWorkSet(tx_hash)` to schedule any orphan whose
parent set intersects with the newly accepted txid for re-evaluation.
The worker loop then re-runs each orphan through ATMP.

camlcoin has three implementations of this loop:
1. `process_orphans` (mempool.ml:3233-3260) — basic re-try via `add_transaction`.
2. `try_1p1c_with_orphans` (mempool.ml:4273-4294) — 1p1c CPFP via `accept_package`.
3. `process_orphans_with_cpfp` (mempool.ml:4298-4328) — enhanced version.

A grep over `lib/`, `bin/`, and `test/` shows **zero production
callers** for all three:
```
$ grep -rn "process_orphans\b" lib/ bin/
lib/mempool.ml:3233:let process_orphans (mp : mempool) (new_txid : Types.hash256)
$ grep -rn "process_orphans_with_cpfp" lib/ bin/
lib/mempool.ml:4298:let process_orphans_with_cpfp ...
```
(All other matches are test files: test_w99_net_processing.ml,
test_w116_package_relay.ml.)

**File:** `lib/mempool.ml:3233, 4252, 4273, 4298` (all four orphan-resolution
helpers defined; none called from production).

**Core ref:** `bitcoin-core/src/node/txdownloadman_impl.cpp::HandleAcceptedTx`
calls `AddChildrenToWorkSet` to queue children; per-iter ATMP retry.

**Cross-cite:** test_w116_package_relay.ml BUG-9, BUG-10, BUG-15 all
flag this. Test names verbatim: "G22/BUG-10: process_orphans_with_cpfp
dead", "G23/BUG-9: find_1p1c_for_orphan stub", "G24/BUG-15:
try_1p1c_with_orphans not called from single-tx rejection path".
**Carry-forward** ~25 weeks, ignored across W116 → W150 → W152.

**Impact:** orphan resolution is fully inert. Even if BUG-1 were fixed
(orphans recorded), there is no production loop to retry them on
parent arrival. Mempool throughput suffers under any non-trivial
reorg or packet-reordering scenario.

---

## BUG-5 (P1) — No per-block conflict-driven orphan erasure (`EraseForBlock` missing)

**Severity:** P1. Core's `TxOrphanageImpl::EraseForBlock(block)`
(txorphanage.cpp:96-126) walks each tx in the connected block, and for
each `vout_index`, removes any orphan whose `OrphanByParent[(tx.GetHash(),
vout_index)]` set has an entry — i.e., orphans whose parent was just
mined (and thus the orphan is either confirmed already or doublespent).
This prevents the orphan pool from accumulating txs that conflict with
confirmed blockchain state.

camlcoin's block-connect hook (cli.ml:1207-1232) calls
`Mempool.expire_orphans` which removes orphans **only by age > 20 minutes**.
There is no `EraseForBlock` analogue that walks block txs against
orphan parents. An orphan whose parent was confirmed via a block sits
in the pool until age-expires.

**File:** `lib/cli.ml:1217-1223` (only expire_orphans call), `lib/mempool.ml`
(no per-block-tx eraser defined).

**Core ref:** `bitcoin-core/src/txorphanage.cpp::TxOrphanageImpl::EraseForBlock`.

**Impact:** orphan pool retains confirmed-or-conflicted entries up to
20 minutes, contributing to the 100-entry cap pressure (when BUG-1 is
fixed). Also: orphan that doublespent against a confirmed tx will be
re-validated when its parent is "found" via a future relay — wasted CPU.

---

## BUG-6 (P1) — `remove_peer` does not erase orphans submitted by that peer (`EraseForPeer` missing)

**Severity:** P1 (becomes P0-DoS when BUG-1 is fixed). Core's
`TxOrphanageImpl::EraseForPeer(peer_id)` removes every orphan whose
`m_announcers` set contains only that peer (orphans introduced by other
peers stay). This is critical: a malicious peer that disconnects after
spamming orphans must not leave the pool full.

camlcoin's `Peer_manager.remove_peer` (peer_manager.ml:1032-1051) cleans
six per-peer hashtables (`chain_sync_behind_since`, `peer_last_tx_time`,
`peer_last_block_time`, `peer_connected_time`, `stale_state`,
`outbound_netgroups`, `hb_compact_peers`) but never touches the orphan
pool. The orphan_entry type (`mempool.ml:51-56`) lacks a `peer_id`
field, so even if `EraseForPeer` were implemented today, there is no
provenance to filter on.

**File:** `lib/peer_manager.ml:1032-1051` (no orphan-erase),
`lib/mempool.ml:51-56` (no peer_id in orphan_entry).

**Core ref:** `bitcoin-core/src/txorphanage.cpp::TxOrphanageImpl::EraseForPeer`.

**Cross-cite:** W103 BUG-8 still open.

**Impact:** moot today (BUG-1 keeps the pool empty); **immediate
P0-DoS** the moment BUG-1 lands, because a malicious peer can connect,
spam 100 orphans, and disconnect — the pool stays full for 20 minutes,
displacing legitimate orphans.

---

## BUG-7 (P0-CDIV) — Mempool has no wtxid index; InvWtx getdata for segwit tx never matches

**Severity:** P0-CDIV. Bitcoin Core's `CTxMemPool` is indexed by BOTH
`txiter` (txid-keyed) AND a separate wtxid-keyed multi-index, so
`pool->get(GenTxid::Wtxid(hash))` and `pool->get(GenTxid::Txid(hash))`
both return the entry in O(log n).

camlcoin's `Mempool.entries` is a `(string → mempool_entry) Hashtbl.t`
keyed by `Cstruct.to_string txid` (mempool.ml:62-63, 275-279). There is
no wtxid index. Consequences:

1. **`Mempool.contains` (mempool.ml:275-276)** — called by
   `cli.ml:1310` on every inv item — checks
   `Hashtbl.mem mp.entries (Cstruct.to_string iv.hash)`. When `iv` is an
   `InvWtx` and the local mempool has a segwit tx with wtxid==iv.hash
   but a different txid, `contains` returns FALSE → spurious getdata.
2. **`Mempool.get` (mempool.ml:279)** — called via cli.ml:864 `lookup_tx`
   in the getdata handler — never finds a tx by wtxid. A peer that
   requests `(MSG_WTX, wtxid)` for a segwit tx in our mempool gets
   `notfound`.
3. **`package_relay.ml::lookup_tx_by_wtxid` (line 21-28)** — self-documents
   the gap with `"O(N) per request"` and walks `Hashtbl.iter` over
   all entries. **Comment-as-confession**, 11th distinct camlcoin
   instance.

**File:** `lib/mempool.ml:62-87` (no wtxid index), `lib/cli.ml:863-869`
(lookup_tx by txid only), `lib/package_relay.ml:21-28` (self-document).

**Core ref:** `bitcoin-core/src/txmempool.h:170-180` boost::multi_index
`indexed_by` with separate `by_wtxid` view; `bitcoin-core/src/txmempool.cpp::get`
overload on `GenTxid::Wtxid`.

**Impact:**
- Every InvWtx getdata for a segwit tx (i.e., the common case post-BIP-339
  on the mainnet) fails to be served. The peer that asked for the tx
  gets notfound, then has to re-request from another peer — wasted
  round-trip.
- camlcoin's mempool is effectively a one-way relay for the wtxid-relay
  half of the network: we ACCEPT segwit txs but cannot SERVE them by
  wtxid.
- Cross-cite BUG-18: cli.ml:1311 hardcodes InvWtx on the outbound
  getdata, which COMBINED with this bug means a non-segwit InvTx
  announcement is converted to a malformed InvWtx getdata that the
  REMOTE peer cannot serve (their wtxid-index won't find it either,
  because for a non-segwit tx wtxid == txid but their getdata-handler
  may route by inv_type).

---

## BUG-8 (P0-CDIV) — No `m_recently_announced_invs`; cross-peer inv dedup absent

**Severity:** P0-CDIV. Core's per-peer `m_recently_announced_invs`
(`net_processing.h::Peer::TxRelay::m_recently_announced_invs`) is a
24-hour-rolling Bloom-filter (size 5000) that tracks every inv hash
*we have announced to this peer*. Three uses:
1. Inv-receive dedup: when peer announces hash X to us, skip
   `txrequest.ReceivedInv` if we recently announced X to that same peer
   (avoid asking a peer for something we just told them about).
2. Getdata-serve allowance: when peer requests X via getdata, bypass
   the `m_lazy_recent_rejects` filter if X is in `m_recently_announced_invs`
   (so we can serve a tx we publicly committed to relaying).
3. Cross-peer dedup is implicit because txrequest tracks in-flight
   requests across peers.

camlcoin has no equivalent. The inv-receive listener (cli.ml:1305-1330)
checks ONLY `Mempool.contains` (already-in-mempool dedup) before emitting
a getdata. Three failure modes:
- Same peer announces X twice → we send two getdata.
- Two peers announce X simultaneously → we send two getdata (one to
  each).
- Peer announces X right after we announced X to it → we send getdata
  for our own tx (wasted RTT, possible loop with malicious peer).

**File:** `lib/cli.ml:1305-1330` (only check is `Mempool.contains`); no
recently-announced-invs structure anywhere in `lib/peer.ml` or
`lib/peer_manager.ml`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:2289-2347` SendMessages
inv loop populates `m_recently_announced_invs`; check at
net_processing.cpp:4194-4197 in getdata handler.

**Impact:**
- 2× to N× extra getdata traffic per popular tx (one per announcing
  peer).
- No serve-allowance for our own announced txs — combined with
  BUG-14 (no recent_rejects), our getdata-serve for a recently-rejected
  tx would also fire ATMP unnecessarily.

---

## BUG-9 (P0-CDIV) — No `TXID_RELAY_DELAY` / `NONPREF_PEER_TX_DELAY` / `OVERLOADED_PEER_TX_DELAY`

**Severity:** P0-CDIV. Core's `TxRequestTracker::ReceivedInv` computes
the request-emit time as:
```
reqtime = now
        + (preferred ? 0 : NONPREF_PEER_TX_DELAY[2s])
        + (overloaded ? OVERLOADED_PEER_TX_DELAY[2s] : 0)
        + (wtxid_relay ? 0 : TXID_RELAY_DELAY[2s])  // BIP-339 prioritises wtxid
```
The delay window allows multiple peers' announcements to land first,
deduplicating before any getdata is emitted, and biases load toward
wtxidrelay peers + preferred-download peers. The reqtime is also
randomized within a small window to defeat fingerprinting.

camlcoin's getdata-on-inv (cli.ml:1318-1327) fires `send_message` IMMEDIATELY
upon InvMsg receive. No delay, no priority sort, no jitter. Every inv-handler
firing produces a getdata directly on the wire.

**File:** `lib/cli.ml:1305-1330`.

**Core ref:** `bitcoin-core/src/txrequest.cpp::TxRequestTracker::ReceivedInv`;
constants at `bitcoin-core/src/net_processing.cpp:140-148`.

**Cross-cite:** W103 BUG-9 still open.

**Impact:**
- Privacy: a peer can ping-test camlcoin's mempool by spraying invs and
  observing immediate getdata for unknown items. Cross-peer dedup
  windows are exactly the privacy primitive BIP-133/BIP-339 build on.
- Bandwidth: under inv-flood from N peers, camlcoin emits N getdata for
  the same tx; Core emits ONE getdata after the 2s window.
- BIP-339 wtxid priority is violated — legacy txid-relay peers get
  served at the same priority as wtxid-relay peers, undermining the BIP's
  incentive to upgrade.

---

## BUG-10 (P0-CDIV) — No tx-request reschedule timer; no `MAX_PEER_TX_REQUEST_IN_FLIGHT` cap

**Severity:** P0-CDIV. Core's `TxRequestTracker` tracks
**(peer, gtxid) → reqtime** entries. When a getdata is emitted,
the entry moves to `m_in_flight` with `expiry = now + GETDATA_TX_INTERVAL[60s]`.
On expiry without a tx-or-notfound response, the entry is moved BACK to
`m_candidates` and re-scheduled to a different peer. Also: per-peer
`MAX_PEER_TX_REQUEST_IN_FLIGHT = 100` cap prevents one slow peer from
exhausting our request slots.

camlcoin has neither. The getdata is fired on inv-receive (BUG-9) and
forgotten. Failure modes:
- Peer ignores our getdata → tx is silently lost.
- Peer is slow/dead → 100 outstanding requests pile up with no cap.
- NotfoundMsg for a tx is silently dropped (BUG-21) → no reschedule
  to a different peer.

**File:** `lib/cli.ml:1305-1330` (no scheduler), `lib/peer.ml`
(no per-peer tx-request in-flight count), `lib/sync.ml:1936-1969`
(handle_notfound for blocks only).

**Core ref:** `bitcoin-core/src/txrequest.cpp` request scheduler.

**Cross-cite:** W103 BUG-9.

**Impact:** under packet loss or peer churn, txs go missing rather than
being re-requested from a backup peer. Reorg / partition recovery is
slow because the only mechanism for re-fetching a tx is "wait for some
other peer to inv it again".

---

## BUG-11 (P0-SEC) — P2P TxMsg accepted from `block_relay_only` peer (no `RejectIncomingTxs`)

**Severity:** P0-SEC. Core's `PeerManagerImpl::ProcessMessage(msg_tx)` at
net_processing.cpp:3601 immediately disconnects if
`RejectIncomingTxs(pfrom)` returns true:
```cpp
if (RejectIncomingTxs(pfrom)) {
    LogPrint(BCLog::NET, "transaction sent in violation of protocol peer=%d\n", pfrom.GetId());
    pfrom.fDisconnect = true;
    return;
}
```
`RejectIncomingTxs` returns true for block-relay-only OR feeler peers
OR if the peer set `relay=false` in version (it doesn't want txs and
we shouldn't be receiving txs over a no-relay channel).

camlcoin's P2P TxMsg listener (`cli.ml:1237-1304`) starts with
`P2p.TxMsg tx when chain.sync_state = Sync.FullySynced` — no check on
`peer.block_relay_only` or `peer.relay`. A BRO peer can spam txs and
camlcoin will run full ATMP on every one of them.

**File:** `lib/cli.ml:1237-1239`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:3601-3611,
RejectIncomingTxs definition at net_processing.cpp::RejectIncomingTxs`.

**Cross-cite:** W103 BUG-4 still open.

**Impact:** DoS surface. BRO peers (Tor / privacy connections, feeler
probes) can use a single TCP socket to drown ATMP. A malicious peer
that opens N BRO connections amplifies the attack N×.

---

## BUG-12 (P0-SEC) — P2P TxMsg accepted from peer that set `relay=false`

**Severity:** P0-SEC. Twin to BUG-11. Core's `RejectIncomingTxs` returns
true if `peer.relay = false` (the peer told us in version "do not send
me txs"). A no-relay peer is by convention a non-relay one — we
shouldn't be receiving txs over the channel and shouldn't be sending
them. camlcoin checks `peer.relay` only on the SEND side
(cli.ml:1282 `&& relay_peer.Peer.relay`), never on receive.

**File:** `lib/cli.ml:1237-1239` (no peer.relay check on receive).

**Core ref:** `bitcoin-core/src/net_processing.cpp::RejectIncomingTxs`.

**Impact:** same DoS amplification as BUG-11. A peer that wants to
hide its identity (e.g., post-handshake relay=false) can still
saturate our ATMP CPU by sending txs.

---

## BUG-13 (P1) — Outbound block-relay-only version still sets `relay=true`

**Severity:** P1. Core's `PeerManagerImpl::PushNodeVersion` sets
`fRelay = m_opts.ignore_incoming_txs ? false : (!pfrom.IsBlockOnlyConn())`
so a BRO outbound advertises `relay=false`, and the remote peer
correctly refrains from sending us txs.

camlcoin's `make_version_msg` (peer.ml:763-777) hardcodes:
```ocaml
{ ...
  relay = true;
}
```
Every VERSION we emit advertises `relay=true`, regardless of whether
the peer is BRO/outbound-only. The remote peer cannot honor our
no-tx-traffic intent.

**File:** `lib/peer.ml:776`.

**Core ref:** `bitcoin-core/src/net_processing.cpp::PushNodeVersion`.

**Cross-cite:** W103 BUG-6 still open.

**Impact:** BRO outbound connections still get tx traffic from the
remote peer. Combined with BUG-11 (we don't reject incoming on BRO),
the BRO mode is **functionally indistinguishable** from a regular
outbound connection — defeating the privacy-mode hardening that BRO
is supposed to deliver.

---

## BUG-14 (P1) — No `m_recent_rejects` cache; same invalid tx triggers full ATMP every replay

**Severity:** P1. Core's `m_lazy_recent_rejects` (rolling-Bloom-filter,
120,000 entries / 24 h) caches every tx hash that ATMP has rejected.
On inv-receive, the hash is checked against this cache before
emitting a getdata; on tx-receive, before re-running ATMP. Defends
against a peer replaying the same invalid tx in a tight loop.

camlcoin has no such cache. cli.ml:1305-1330 only checks `Mempool.contains`
(positive cache); a tx that was rejected by ATMP last second can be
re-announced and the full ATMP pipeline runs again. Cross-cite W103 BUG-11.

**File:** `lib/cli.ml:1237-1330` (no rejects cache); no equivalent in
`lib/mempool.ml` or `lib/peer.ml`.

**Core ref:** `bitcoin-core/src/net_processing.h::m_lazy_recent_rejects`,
`bitcoin-core/src/node/txdownloadman_impl.cpp::RecentRejectsFilter`.

**Impact:** CPU-amplification DoS. A peer can saturate ATMP cycles by
re-announcing the same invalid tx. Mitigated in practice by the misbehavior
scoring (peer.ml:1387 `misbehavior_bad_tx = 10` per rejection, 10
rejections → disconnect at score 100), but the per-tx CPU cost is paid
10× before the disconnect fires.

---

## BUG-15 (P1) — No `INVENTORY_BROADCAST_PER_SECOND=7` rate cap / `_MAX_PER_MB=7000` scaling

**Severity:** P1. Core's `MaybeSendMessage` computes the per-peer inv
budget as `(now - last_send) * INVENTORY_BROADCAST_PER_SECOND = 7 invs/sec
average`, scaled up to a peak of
`(now - last_send) * INVENTORY_BROADCAST_MAX_PER_MB * tx_size_per_MB =
~7000 invs/sec at 1 MB/sec throughput`. The Poisson timer determines
WHEN to flush; the budget determines HOW MANY.

camlcoin's `flush_inv_queue` (peer.ml:1809-1846) drains up to
`max_inv_per_flush = 1000` items per Poisson tick, with NO per-second
rate cap. With the default 2s outbound interval, that's a peak of
500 invs/sec per peer (well above Core's 7) — and bursts to 1000
invs in one inv message during catch-up.

**File:** `lib/peer.ml:216` (`max_inv_per_flush = 1000`), `peer.ml:1814-1821`
(unbounded drain loop).

**Core ref:** `bitcoin-core/src/net_processing.cpp:140-141`
`INVENTORY_BROADCAST_PER_SECOND`, `INVENTORY_BROADCAST_MAX_PER_MB`.

**Impact:** under mempool spike (e.g., post-fee-event), camlcoin
broadcasts an order of magnitude more invs than Core. May not be
visible at small mempool but interacts badly with BUG-16 (immediate
P2P-relay) — the trickle queue can be empty most of the time precisely
because every P2P-arrived tx is sent immediately bypassing the
queue, with no rate-control whatsoever.

---

## BUG-16 (P0-CDIV) — P2P-arrived tx bypasses trickle queue; immediate one-tx-per-inv-msg relay

**Severity:** P0-CDIV. Bitcoin Core's `RelayTransaction`
(net_processing.cpp:2243-2287) ALWAYS pushes the tx hash into
`tx_relay->m_tx_inventory_to_send`. The actual wire send happens later
in `SendMessages`, which drains the queue under the Poisson + rate-cap
discipline (BUG-15 ref). There is no "immediate-send" path.

camlcoin's P2P TxMsg listener at cli.ml:1280-1295 does the opposite:
```ocaml
Lwt_list.iter_p (fun relay_peer ->
  ...
  Peer.send_message relay_peer
    (P2p.InvMsg [{ P2p.inv_type; hash }])
) ready
```
This:
1. Bypasses the Poisson timer (`peer.next_inv_send`).
2. Bypasses the Fisher-Yates shuffle (privacy primitive).
3. Bypasses the rate cap (BUG-15).
4. Sends an inv message containing exactly ONE hash, vs Core's
   batched-up-to-MAX_INV_SZ sends.
5. Bypasses the bloom filter check (BIP-37; only the
   `Peer_manager.announce_tx` RPC path honors it — see BUG-22 +
   cross-cite to peer_manager.ml:1384-1391).

The RPC path (`sendrawtransaction` → `Peer_manager.announce_tx` →
`Peer.queue_inv` → trickle) is correct. The P2P path is the buggy one,
which is the OPPOSITE of typical refactors — usually the high-throughput
P2P path gets the careful trickle treatment first.

**File:** `lib/cli.ml:1280-1295`.

**Core ref:** `bitcoin-core/src/net_processing.cpp::RelayTransaction`.

**Impact:**
- Privacy: an observer that times tx-arrival at our P2P port can infer
  WHICH peer announced a tx by watching the immediate one-tx inv we send
  to every other peer microseconds later. Core's trickle deliberately
  decorrelates these.
- Wire efficiency: one tx → N inv messages of size 1 vs Core's
  batched flush.
- BIP-37: bloom-filter peers receive tx invs they didn't subscribe to.
- **Cross-pipeline drift**: the two relay paths (P2P-receive vs
  RPC-sendrawtransaction) use different relay primitives.

---

## BUG-17 (P0-CDIV) — `handle_getdata` always serializes tx with witness; MSG_TX should strip

**Severity:** P0-CDIV. Bitcoin Core's `ProcessGetData` handles
`MSG_TX` (legacy, no witness) and `MSG_WITNESS_TX` / `MSG_WTX` (witness
included) distinctly. For `MSG_TX`, the serialization uses
`TX_NO_WITNESS` flags so the response is a stripped-witness encoding.
This preserves the wire-level meaning of `MSG_TX` vs `MSG_WITNESS_TX`
(introduced for the BIP-144 segwit upgrade).

camlcoin's `handle_getdata` (peer.ml:1479-1488) treats all three inv
types (`InvTx | InvWtx | InvWitnessTx`) identically and serializes via
`Serialize.serialize_transaction` (WITH witness):
```ocaml
| P2p.InvTx | P2p.InvWtx | P2p.InvWitnessTx ->
  begin match lookup_tx iv.hash with
  | Some data ->
    let r = Serialize.reader_of_cstruct data in
    let tx = Serialize.deserialize_transaction r in
    send_message peer (P2p.TxMsg tx)
  ...
```
`p2p.ml:783` `TxMsg tx -> Serialize.serialize_transaction w tx` — always
with witness. There is `Serialize.serialize_transaction_no_witness`
(serialize.ml:274) defined but only used by crypto.ml:345, psbt.ml:252,
mempool.ml:1484, rpc.ml:4314, script.ml:910, validation.ml:118 — never
by the getdata response path.

**File:** `lib/peer.ml:1479-1488` (no inv_type branching),
`lib/p2p.ml:783` (TxMsg always full-witness).

**Core ref:** `bitcoin-core/src/net_processing.cpp:4189-4259`
ProcessGetData; `bitcoin-core/src/protocol.h::TX_NO_WITNESS` flag.

**Cross-cite:** W103 BUG-12 still open.

**Impact:** a peer expecting BIP-144 wire-format compliance receives
an extended (witness-included) serialization in response to legacy
MSG_TX. Wire-protocol divergence. Most peers tolerate this (they parse
the witness flag bytes and consume them), but a strict parser per BIP-144
would treat the response as malformed.

---

## BUG-18 (P0-CDIV) — Inv-receive→getdata coercion hardcodes `InvWtx` regardless of peer wtxid_relay state

**Severity:** P0-CDIV. Core's getdata-emit code on inv-receive uses
`gtxid = peer.wtxid_relay ? GenTxid::Wtxid(hash) : GenTxid::Txid(hash)` —
the LOCAL peer's wtxid_relay setting determines the inv_type. For a
non-wtxidrelay peer (legacy), Core uses `MSG_WITNESS_TX = 0x40000001`
to request witness data.

camlcoin's cli.ml:1311 hardcodes:
```ocaml
Some { P2p.inv_type = P2p.InvWtx; hash = iv.hash }
```
Three failure cases:
1. Peer announced `InvTx` (legacy MSG_TX) with a TXID; our getdata
   sends back `InvWtx` (MSG_WTX) with the same hash but the remote
   peer's getdata-handler dispatches by inv_type → tries to find by
   wtxid → fails (the hash is a txid).
2. Peer announced `InvWitnessTx` (legacy witness MSG_WITNESS_TX) with
   a txid; same shape as case 1.
3. Even if we WANT to coerce all to wtxid-relay, BUG-7 means our local
   mempool has no wtxid index, so the round-trip can't be served on
   the response either.

**File:** `lib/cli.ml:1311`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:2278` (cited verbatim
in cli.ml:1271 as a Core ref but the implementation diverges).

**Impact:** every InvTx/InvWitnessTx inv from a legacy peer produces a
malformed getdata. The remote peer responds with notfound or
silently drops; camlcoin then has no reschedule (BUG-10), so the tx
is permanently lost from camlcoin's view until some wtxidrelay peer
re-announces it as InvWtx.

---

## BUG-19 (P1) — `InvFilteredBlock` (MSG_FILTERED_BLOCK) never dispatched

**Severity:** P1. Core's getdata-handler for `MSG_FILTERED_BLOCK = 3`
builds a `merkleblock` containing only the tx + Merkle proofs that match
the peer's loaded bloom filter (BIP-37 §filteredblock).

camlcoin's `handle_getdata` (peer.ml:1479-1522) has explicit cases for
`InvBlock | InvWitnessBlock` and `InvTx | InvWtx | InvWitnessTx` and
`InvCompactBlock`. The catchall `| _ → not_found := ...` (line 1520-1522)
matches `InvFilteredBlock`. Result: a peer that loads a bloom filter
and requests a filtered block via getdata receives `notfound`, breaking
BIP-37 for the filtered-block path.

**File:** `lib/peer.ml:1479-1522`.

**Core ref:** `bitcoin-core/src/net_processing.cpp::ProcessGetData`
MSG_FILTERED_BLOCK case.

**Cross-cite:** fleet-wide W134 finding "MSG_FILTERED_BLOCK dispatch gap (7 impls)".

**Impact:** BIP-37 light clients that rely on filtered blocks cannot
sync from camlcoin (they fall back to full blocks, defeating the
bandwidth optimisation BIP-37 exists for). Practical fallout limited
because BIP-37 is largely deprecated in favour of BIP-157 compact filters,
but the gap is real.

---

## BUG-20 (P1) — No per-peer `AddKnownTx` set; duplicate announcements to same peer

**Severity:** P1. Core maintains a per-peer `m_recently_announced_invs`
(BUG-8 ref) AND a `m_inv_to_send` queue that is filtered against
the incoming `addr-known` Bloom filter to avoid announcing the same
hash twice to the same peer. The two filters together enforce
"announce at most once per 24 h per peer".

camlcoin's per-peer state (peer.ml:236-307) has no known-tx filter.
The trickle queue at `peer.inv_queue` doesn't dedupe — repeated
`Peer.queue_inv peer entry` with the same hash adds the same entry N
times.

**File:** `lib/peer.ml:236-307, 1775-1788`.

**Core ref:** `bitcoin-core/src/net_processing.h::Peer::TxRelay::m_addr_known`,
`m_recently_announced_invs`.

**Cross-cite:** W103 BUG-10 still open.

**Impact:** under mempool churn (RBF, packet loss, mempool replacement),
the same tx hash can be announced to the same peer multiple times,
inflating bandwidth and giving fingerprinting signal.

---

## BUG-21 (P1) — `NotfoundMsg` for tx items silently dropped (no reschedule)

**Severity:** P1. Core's `ProcessMessage(msg_notfound)` removes each
notfound tx from `txrequest` in-flight and **re-schedules** the request
to a different peer (the txrequest scheduler walks its candidate set
and picks a different peer with the same announcement).

camlcoin's `NotfoundMsg` handler (cli.ml:803-814) only dispatches blocks
to `Sync.handle_notfound`. Non-block notfound items are silently
dropped — they don't trigger any retry, don't decrement an in-flight
counter (because BUG-10 means there is no counter), don't surface in
metrics.

**File:** `lib/cli.ml:803-814`, `lib/sync.ml:1936-1969` (block-only
handle_notfound).

**Core ref:** `bitcoin-core/src/net_processing.cpp::ProcessMessage`
msg_notfound case; `txrequest.cpp::ReceivedResponse` with `failed=true`.

**Impact:** tx-relay reliability degrades under packet loss. A tx that
a peer initially announced but cannot serve when we getdata is
permanently lost from camlcoin's view (no other peer will be tried).

---

## BUG-22 (P0-CDIV) — BIP-35 mempool response ignores peer bloom filter

**Severity:** P0-CDIV. Bitcoin Core's `MempoolMsg` handler at
net_processing.cpp:4451-4502 iterates the mempool, computes
`bool fee_pass = entry.GetFee() / entry.GetTxSize() >= peer.m_fee_filter`
AND `bool filter_pass = (peer.bloom_filter == nullptr) || peer.bloom_filter->IsRelevantAndUpdate(tx)`,
and skips the inv push if EITHER fails. This is the BIP-37 contract:
a peer that loads a bloom filter expects BIP-35 responses to honor it.

camlcoin's `Sync.handle_mempool_msg_for` (sync.ml:4628-4684) iterates
`mp.entries` and applies ONLY the feefilter gate. The `peer.bloom_filter`
is never consulted. A peer that does `filterload(F) → mempool` receives
the entire mempool back (modulo feefilter), defeating BIP-37's
bandwidth-saving promise.

**File:** `lib/sync.ml:4645-4660` (no `Bloom.is_relevant_and_update`
call); `lib/peer_manager.ml:1384-1391` (`announce_tx` DOES honor
bloom — two-pipeline drift extension).

**Core ref:** `bitcoin-core/src/net_processing.cpp:4451-4502`
ProcessMessage(msg_mempool); BIP-37 §filtering, §mempool.

**Impact:**
- Bandwidth: a BIP-37 client that filtered for, say, 5 addresses sees
  the entire mempool — typically MBs of inv data.
- Privacy: the client's bloom filter intent is leaked to no one
  (because we just send everything back), but the bandwidth cost
  effectively forces clients to disconnect or rate-limit.
- BIP-37 contract violation.
- **Two-pipeline drift**: the same node honors bloom filter on the
  RPC-driven announce_tx path (peer_manager.ml:1384-1391) but not the
  BIP-35 dump path. Same shape as the BUG-16 dual-path tx relay.

---

## BUG-23 (P0-CDIV) — 5th-consecutive-quad camlcoin multi-pipeline drift; 4 distinct tx-relay entry points

**Severity:** P0-CDIV ("5th-consecutive-quad camlcoin pipeline drift",
extending the W143 → W148 → W150 → W151 streak). The tx-relay subsystem
has at least four distinct entry points with divergent behaviour:

| # | Entry point | ATMP call | Relay primitive | Bloom check | Exception wrap |
|---|-------------|-----------|-----------------|-------------|----------------|
| 1 | `cli.ml:1240` P2P TxMsg listener | `accept_to_memory_pool` | **immediate** `send_message`, one-tx-per-inv | NO | YES (safe_run) |
| 2 | `rpc.ml:1192` sendrawtransaction | `add_transaction` (bypass!) | `Peer_manager.announce_tx` → trickle | YES | NO |
| 3 | `package_relay.ml:61` pkgtxns (BIP-331) | `accept_package` | none ("relay is driven by existing TxMsg listener") | N/A | per-tx in inner loop |
| 4 | `rpc.ml:3113` submitpackage | `accept_package_with_replaced` | as #3 | N/A | partial |

Behavior divergences observed:
- **Bloom-filter compliance** (BUG-22): pipeline 1 ignores filter; pipeline
  2 honors it.
- **Relay timing** (BUG-16): pipeline 1 immediate; pipeline 2 trickle.
- **Exception safety** (W150 BUG-2): pipeline 1 wraps every failure;
  pipeline 2 lets Failure/Not_found escape.
- **Orphan registration** (BUG-1): NEITHER pipeline calls `add_orphan` on
  missing-inputs.
- **Orphan resolution** (BUG-4): NEITHER pipeline calls `process_orphans`
  on success — only test code does.

This is a strict extension of the W151 finding (sendpackages
defined/exported/never-called outbound) — the same shape of "feature
defined in one pipeline, missing in another". Carry-forward over
camlcoin W143 → W148 → W150 → W151 → W152 = **5 consecutive quad-audits**
all confirming multi-pipeline drift inside camlcoin.

**File:** `lib/cli.ml:1237-1330`, `lib/rpc.ml:1149-1222, 3023-3300`,
`lib/package_relay.ml:51-75`.

**Core ref:** `bitcoin-core/src/net_processing.cpp::RelayTransaction` is
THE relay primitive; ALL acceptance paths route through it.

**Impact:** the tx-relay subsystem behaves differently depending on
HOW a tx entered the node. Operators cannot reason about "what
mainnet sees" from a single test case, because the bloom-filter +
relay-cadence + exception-safety + orphan-registration matrix
differs across paths.

---

## BUG-24 (P1) — `Mempool.create` hardcodes `Consensus.regtest`; tx-relay also broken (W150 BUG-4 carry-forward)

**Severity:** P1 (W150 BUG-4 carry-forward; called out here because it
intersects tx-relay). `Mempool.create` (mempool.ml:233-237) sets
`network = Consensus.regtest` regardless of CLI args; `set_network`
(mempool.ml:3452) is defined but never called.

The intersection with tx-relay: `peer.feefilter` comparison in cli.ml:1284
and the BIP-35 dump fee filter in sync.ml:4644-4650 use the mempool's
`min_relay_fee` which is per-network. With network hardcoded to regtest,
the relay fee thresholds are regtest-floor values (typically zero),
not mainnet's `min_relay_fee = 1000` sat/kvB. Result: on a mainnet
deployment, the feefilter advertised to peers is wrong, and peers
that respect our feefilter route low-fee txs to us that we should
have suppressed.

**File:** `lib/mempool.ml:233-237, 3452` (W150 BUG-4 — still open
~2 days after W150 audit).

**Core ref:** `bitcoin-core/src/kernel/mempool_options.h`
`incremental_relay_feerate`, `min_relay_feerate` per-network.

**Impact:** tx-relay correctness is degraded across the fleet
boundary; BIP-133 advertised feefilter is the wrong value for the
running network.

---

## BUG-25 (P1) — Oversized inv message disconnects without misbehavior score

**Severity:** P1. Core's `ProcessMessage` deserialization layer in
`net_processing.cpp::ReadMessage` increments
`Misbehaving(peer, 100, "oversized message")` on protocol-violating
sizes before disconnecting. The score-then-disconnect pattern is
asymmetric on purpose: a peer that legitimately reconnects after a
spurious oversized-msg disconnect should still be addr-known, but a
peer that repeatedly hits the gate should be banned via the
score-tracking layer.

camlcoin's `deserialize_inv_list` (p2p.ml:494-495):
```ocaml
if count > max_inv_count then
  failwith "inv count exceeds maximum";
```
`failwith` raises `Failure`, which propagates up to
`read_message_with_timeout` (peer.ml:609-662) which catches ANY
exception and treats it as `Timeout`, marking the peer
`Disconnected` and closing the fd — no misbehavior score increment,
no ban, no addr-blacklist:
```ocaml
(fun exn ->
  Log.warn (fun m ->
    m "[%s:%d] read_message failed: %s — treating as timeout"
      peer.addr peer.port (Printexc.to_string exn));
  ...
  peer.state <- Disconnected;
  ...
  Lwt.return `Timeout)
```
A peer that floods us with oversized invs disconnects cleanly each
time; the addr-manager doesn't learn to avoid them.

**File:** `lib/p2p.ml:492-496`, `lib/peer.ml:644-661`.

**Core ref:** `bitcoin-core/src/net_processing.cpp` `Misbehaving` calls
in deserialization paths; `misbehavior_oversized_message = 20` exists in
camlcoin at peer.ml:1385 but is never invoked for inv-list overflow.

**Impact:** repeat-offender peers stay in the addr table and get
re-dialled. Mild adversarial-environment annoyance, not a P0.

---

## BUG-26 (P1) — `inv_queue` has no per-peer cap (`MAX_PEER_TX_ANNOUNCEMENTS=5000`)

**Severity:** P1. Core's per-peer `m_tx_inventory_to_send` is bounded
by `MAX_PEER_TX_ANNOUNCEMENTS = 5000` (net_processing.cpp:147). When
the trickle drains slower than insertions (e.g., very slow inbound
peer), the queue silently drops old entries rather than growing
unboundedly.

camlcoin's `Peer.queue_inv` (peer.ml:1775-1788) does
`Queue.add entry peer.inv_queue` with NO size check. A peer that never
acks (slow read on remote, or malicious slowloris) will accumulate inv
entries until the OCaml process OOMs.

**File:** `lib/peer.ml:1775-1788`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:147`
`MAX_PEER_TX_ANNOUNCEMENTS = 5000`.

**Cross-cite:** W103 BUG-7 still open.

**Impact:** memory-exhaustion DoS surface. Bounded in practice by Lwt
backpressure (the slow read on the remote pushes back on our writes
eventually), but the inv_queue itself has no cap. Combined with
BUG-15 (no rate cap), a single slow peer can grow the queue
megabytes deep.

---

## BUG-27 (P1) — `expire_orphans` runs on age-only, no `LimitOrphans` random eviction

**Severity:** P1. Core's `TxOrphanageImpl::LimitOrphans(max, rng)` runs
on every `AddTx` AND on every `EraseForBlock`. It removes:
1. Orphans whose creation time exceeded `ORPHAN_TX_EXPIRE_TIME = 1200s`.
2. Random orphans (sampled via rng to defeat timing attacks) until
   `m_orphans.size() <= max`.

The random-eviction step matters: a peer that fills the orphan pool to
the cap with sub-1200-second-old orphans (BUG-1 + BUG-6 attack surface
when fixed) would not be evicted by age-only expiry. Core's random
eviction guarantees eventual flush regardless of age.

camlcoin's `expire_orphans` (mempool.ml:3429-3441) removes by age only:
```ocaml
let max_age = 20.0 *. 60.0 in  (* 1200 s *)
let to_remove = Hashtbl.fold ...
  if now -. entry.orphan_time > max_age then ...
```
`add_orphan` (mempool.ml:3185-3210) evicts the OLDEST entry when
the cap is hit (not random). This is a separate gap.

**File:** `lib/mempool.ml:3429-3441` (age-only),
`lib/mempool.ml:3191-3210` (oldest-not-random eviction).

**Core ref:** `bitcoin-core/src/txorphanage.cpp::LimitOrphans` two-step
age + random eviction.

**Impact:** when BUG-1 is fixed, an attacker can keep the orphan pool
at-cap with fresh-but-doomed orphans, blocking legitimate orphans from
admission for the full 20-minute window.

---

## BUG-28 (P1) — `wtxidrelay` post-handshake handling sends correct misbehavior score but the deserializer-failure path bypasses it

**Severity:** P1. peer.ml:1644-1646 correctly disconnects a peer that
sends `wtxidrelay` after VERACK with misbehavior 1. Good. But that
gate fires inside `dispatch_message`, which is called AFTER
`read_message` has already succeeded. A peer that sends a malformed
wtxidrelay-shaped message (zero-length wtxidrelay is the canonical
form, but a peer could send unexpected bytes that decode to
`WtxidrelayMsg` via the parser) gets the misbehavior treatment.

The asymmetry: most other post-handshake protocol violations
(BUG-25 ref) get the silent-disconnect path because the failure happens
at deserialization. Consistency would say: route deserialization
failures THROUGH `record_misbehavior_for peer "oversized_message"`
or similar before disconnecting. This is sub-finding of BUG-25 but
worth flagging separately because the path through
`Lwt.catch ... fun exn -> peer.state <- Disconnected` (peer.ml:651-661)
silently bypasses an entire protocol-violation accounting layer that
exists for normal-flow violations.

**File:** `lib/peer.ml:651-661, 1644-1646`.

**Impact:** internal-consistency. Network behaviour is roughly Core-equivalent
because the disconnect happens either way, but the addr-manager
score-tracking model has a gap.

---

## Summary

**Bug count:** 28 (BUG-1 through BUG-28).

**Severity distribution:**
- **P0-CDIV:** 11 (BUG-1, BUG-4, BUG-7, BUG-8, BUG-9, BUG-10, BUG-16, BUG-17, BUG-18, BUG-22, BUG-23)
- **P0-SEC:** 2 (BUG-11, BUG-12)
- **P1:** 15 (BUG-2, BUG-3, BUG-5, BUG-6, BUG-13, BUG-14, BUG-15, BUG-19, BUG-20, BUG-21, BUG-24, BUG-25, BUG-26, BUG-27, BUG-28)

11 + 2 + 15 = 28. ✓

**Fleet patterns confirmed:**
- **"5th-consecutive-quad camlcoin pipeline drift"** (BUG-23) — extends
  W143 (5 block-validation pipelines), W148 (6 sync pipelines), W150
  (6 ATMP entry points), W151 (8 mempool acceptance entry points),
  W152 (4 distinct tx-relay entry points).
- **"dead-helper-at-call-site"** (BUG-1, BUG-4) — `add_orphan`,
  `process_orphans`, `process_orphans_with_cpfp`, `find_1p1c_for_orphan`,
  `try_1p1c_with_orphans`, `set_network` (W150 BUG-4 ref) all defined
  + exported + never-called-from-production. Six distinct dead helpers
  in the tx-relay/orphan subsystem alone.
- **"comment-as-confession"** (BUG-7 in package_relay.ml:21-28 "O(N) per
  request") — 11th distinct camlcoin instance.
- **"two-pipeline guard extension"** (BUG-16, BUG-22) — RPC-path
  vs P2P-path divergence on relay primitive AND bloom-filter compliance.
  Both extend the cross-impl two-pipeline pattern tracked since W74.
- **"carry-forward re-anchor"** — W103 (~24 weeks open): BUG-1, BUG-3,
  BUG-4, BUG-6 (W103 BUG-7), BUG-9, BUG-10 (BUG-11/14), BUG-13, BUG-17,
  BUG-20. **9 of 13 W103 bugs still open** at W152 re-audit.
- **"defense-in-depth missing every layer"** (BUG-11, BUG-12, BUG-13,
  BUG-25, BUG-26) — the BRO + relay-false + version-relay + inv-overflow
  + queue-cap layers ALL miss the corresponding misbehavior scoring /
  rejection paths.

**Top three findings:**
1. **BUG-1 + BUG-4 cluster (orphan-pool architecturally non-functional)** —
   `add_orphan` is dead, `process_orphans` family is dead, `EraseForBlock`
   missing, `EraseForPeer` missing, parent-getdata missing. Every component
   of the orphan-handling subsystem is defined-but-not-wired. This is the
   single biggest functional gap in camlcoin's tx-relay stack and has
   been open ~24 weeks since W103. Production nodes pay full N×ATMP cost
   for every re-announced orphan rather than the O(1) "already an
   orphan" short-circuit.
2. **BUG-9 + BUG-10 + BUG-21 cluster (no TxRequestTracker)** — no
   `TXID_RELAY_DELAY` / `NONPREF_PEER_TX_DELAY` / `OVERLOADED_PEER_TX_DELAY`
   delay window, no `GETDATA_TX_INTERVAL=60s` reschedule, no
   `MAX_PEER_TX_REQUEST_IN_FLIGHT=100` cap, no `NotfoundMsg` retry for
   txs. The entire BIP-339 priority + cross-peer-dedup + reliability
   architecture is absent; getdata fires immediately on inv-receive
   and forgets. Cross-cite W103 BUG-9.
3. **BUG-7 + BUG-18 + BUG-22 cluster (BIP-339 wtxid + BIP-37 bloom +
   pipeline drift)** — mempool has no wtxid index so InvWtx getdata for
   segwit txs cannot be served; inv-receive→getdata hardcodes InvWtx
   regardless of peer capability; BIP-35 mempool dump ignores bloom
   filter. Three orthogonal correctness bugs in the receive-vs-serve
   axis, each P0-CDIV in its own right, and intersecting with BUG-23's
   multi-pipeline drift (cli.ml P2P-relay path vs peer_manager.ml RPC
   path).
