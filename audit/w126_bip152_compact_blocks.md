# W126: BIP-152 Compact Block Relay (camlcoin)

**Wave**: W126 (DISCOVERY)
**Impl**: camlcoin (OCaml)
**Date**: 2026-05-17
**Status**: DISCOVERY — **9 BUGS / 30 GATES**
**Tests added**: `test/test_w126_bip152_compact_blocks.ml`
  (30 audit-status tests: PRESENT gates assert positive shape; PARTIAL/MISSING
  gates assert the bug-pre-fix shape — flip when the BUG is fixed).
**Code under audit** (camlcoin):
- `lib/p2p.ml` lines 41-50 (message-type enum), 175-200 (inv-type 4), 242-262
  (compact-block / block-txns types), 379-382 (message variants), 537-549
  (depth constants), 551-642 (serialization + 65535 cap), 786-791 / 891-893
  / 967-971 (codec wiring), 1351-1569 (BIP-152 helpers: nonce, create,
  reconstruct, fill, request-builder, msg constructors), 1556-1569.
- `lib/peer.ml` lines 267-268 / 401-402 (peer state fields),
  831-837 / 1006 / 1063 / 1588-1599 / 1657-1663 (sendcmpct send + recv),
  1489-1519 (handle_getdata InvCompactBlock + MAX_CMPCTBLOCK_DEPTH guard).
- `lib/peer_manager.ml` lines 224-225 / 274 / 1049-1050 (HB-peer list field +
  on-disconnect cleanup), 1360-1369 (announce_block — HB-relay gap),
  2637-2761 (HB-relay helpers — DEAD), 2763-2777 (mempool lookup).
- `lib/sync.ml` lines 5034-5038 (peer_has_header stub).
- `lib/cli.ml` lines 1344-1478 (incoming cmpctblock / blocktxn / getblocktxn
  dispatch arms; LoadingBlocks / IBD gating analysis).
- `lib/crypto.ml` lines 444-561 (SipHash-2-4 + short-txid).

**Reference**:
- `bitcoin-core/src/blockencodings.h` + `blockencodings.cpp` —
  `CBlockHeaderAndShortTxIDs`, `PrefilledTransaction`,
  `PartiallyDownloadedBlock` (`InitData`, `IsTxAvailable`, `FillBlock`).
- `bitcoin-core/src/net_processing.cpp` lines 138 (`MAX_CMPCTBLOCK_DEPTH=5`),
  140 (`MAX_BLOCKTXN_DEPTH=10`), 199 (`CMPCTBLOCKS_VERSION=2`),
  1272-1329 (`MaybeSetPeerAsAnnouncingHeaderAndIDs`), 2103-2152
  (`NewPoWValidBlock` fast-announce of cmpctblock to HB peers),
  3864-3917 (handshake SHORT_IDS_BLOCKS_VERSION gate + SENDCMPCT recv),
  4245-4304 (GETBLOCKTXN handler + MAX_BLOCKTXN_DEPTH fallback),
  4466-4711 (CMPCTBLOCK handler — InitData + GETBLOCKTXN round-trip +
  optimistic reconstruct), 4714-4726 (BLOCKTXN -> ProcessCompactBlockTxns).
- `bitcoin-core/src/node/protocol_version.h:30` —
  `SHORT_IDS_BLOCKS_VERSION = 70014`.
- `bitcoin-core/src/protocol.h` — `MSG_CMPCT_BLOCK = 4`.
- BIP-152 (`HB`, "high-bandwidth", "low-bandwidth", `cmpctblock`,
  `getblocktxn`, `blocktxn`, short-id derivation).

**Prior wave context**:
- W112 (2026-03-XX, `2b3d056`) found 9 BUGS on this surface.  Subsequent
  fixes: **FIX-42** (`0ca99dd`) closed BUG-6 (depth guards); **FIX-43**
  (`1d25c7c`) closed BUG-2 (sendcmpct v!=2 drop); **FIX-49** (`94f7ef4`)
  closed BUG-8 (nonce CSPRNG: `/dev/urandom`).  The remaining 6 W112 BUGS
  (BUG-1, -3, -4, -5, -7, -9) are still open and the surface has grown
  (announce-side path is now wired through `announce_block` at
  peer_manager.ml:1360, but it routes HeadersMsg/InvMsg and never
  CmpctblockMsg — W123 G30 BUG-7 cross-confirms).
- W123 (2026-05-17, `b310df4`) BUG-7 at G30 flagged the
  `announce_block` HB-relay gap from the mining-pipeline angle.  W126
  re-audits the same defect from the BIP-152 angle and catalogues it
  as **BUG-2 (P0-CDIV)** plus 4 supporting structural bugs (BUG-3..6).

---

## Summary

camlcoin implements BIP-152 wire types and the receive-side reconstruction
correctly (FIX-42 + FIX-43 + FIX-49 closed 3 of the W112 P1 gaps).  The
**incoming** message handlers for `cmpctblock` / `getblocktxn` / `blocktxn`
are wired through `cli.ml` listeners + `peer.ml` `handle_getdata` and
behave Core-equivalently for the round-trip.

The **outgoing / HB-announce side** is broken at three layers and the HB
relay pipeline is structurally dead:

1.  `peer_manager.ml` `maybe_set_hb_compact_peer` (line 2671) is **never
    called** from any code path.  `pm.hb_compact_peers` is initialised to
    `[]` (line 274) and only ever shrinks (via the disconnect cleanup at
    line 1050) — it never grows.  The 3-slot HB list mandated by BIP-152
    is permanently empty.
2.  `peer_manager.ml` `relay_compact_block` (line 2748) is **never
    called** from any code path.  Even if `pm.hb_compact_peers` were
    non-empty, the only function that pushes CmpctblockMsg into the
    network is dead.
3.  `peer_manager.ml` `announce_block` (line 1360) — the one outbound
    block-announce path used by `cli.ml` block listeners (1225, 1367,
    1417) — only sends `HeadersMsg` (when `peer.send_headers`) or
    `InvMsg`.  It never consults `pm.hb_compact_peers` and never sends
    `CmpctblockMsg`.  This is the Core `NewPoWValidBlock` /
    `MaybeSetPeerAsAnnouncingHeaderAndIDs` pipeline (net_processing.cpp
    lines 2103-2152 + 1272-1329) with the cmpctblock branch ripped out.

Net effect: every camlcoin node operates as a **receive-only BIP-152
peer**.  It will accept and reconstruct cmpctblock from peers willing to
serve it, but it will never volunteer cmpctblock as an announcement and
will never appear in any peer's HB list.  On block discovery (mined
locally or relayed), the camlcoin node degrades to BIP-130 headers
announcement, which costs an extra round-trip vs. the fast-announce
cmpctblock pipeline.

This is a P0-CDIV finding because **the divergence is observable from
the network**: a Core node connected to camlcoin will never see a
`cmpctblock` message and will never select camlcoin as an HB-relay
peer (Core's `MaybeSetPeerAsAnnouncingHeaderAndIDs` is driven by
`m_provides_cmpctblocks`, which IS set on a SENDCMPCT — and camlcoin
does send SENDCMPCT to all peers on handshake — but the **flow from
peer-side to local block-relay** is broken on camlcoin's side, not on
the Core peer's accounting).  A fleet-bisection differential
(consensus-monitor + mempool-diff harness) would observe slower
camlcoin block propagation vs. peers that do HB-relay.

**Verdict counts**:

| Verdict        | Count |
|---------------:|------:|
| PRESENT        |    21 |
| PARTIAL        |     4 |
| **MISSING**    |  **5** |
| Total gates    |    30 |

The 9 BUGS = 4 PARTIAL + 5 MISSING.

| BUG-#  | Pri        | Gate(s)    | Code reference                                                        | Description                                                                                                  |
|-------:|:-----------|:-----------|:----------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------|
| BUG-1  | **P0-CDIV**| G29        | `peer_manager.ml:1360-1369` (announce_block)                          | announce_block never sends CmpctblockMsg — only HeadersMsg + InvMsg.  HB fast-announce pipeline is broken.   |
| BUG-2  | **P1**     | G28        | `peer_manager.ml:2671-2733` (maybe_set_hb_compact_peer)               | Helper is well-engineered but **never called**.  `hb_compact_peers` list never grows past `[]`.               |
| BUG-3  | **P1**     | G29        | `peer_manager.ml:2748-2761` (relay_compact_block)                     | Helper is well-engineered but **never called**.  Even if HB list were populated, this push is unreachable.    |
| BUG-4  | **P1**     | G30        | `sync.ml:5034-5038` (peer_has_header)                                 | Stub always returns true.  Core PeerHasHeader checks `state.pindexBestKnownBlock` + `pindexBestHeaderSent`. |
| BUG-5  | **P2**     | G6         | `peer.ml:1004-1006`, `peer.ml:1061-1063` (perform_handshake)          | SENDCMPCT sent unconditionally — no SHORT_IDS_BLOCKS_VERSION (70014) gate.  Core: `net_processing.cpp:3864`. |
| BUG-6  | **P2**     | G22        | `peer_manager.ml:2763-2777`, `cli.ml:1356`                            | No `vExtraTxnForCompact` pool (Core blockencodings.cpp:147-176).  Reconstruction only consults live mempool. |
| BUG-7  | **P2**     | G19, G20   | `cli.ml:1399-1427` (BlocktxnMsg + GetblocktxnMsg listener arms)       | No `LoadingBlocks` / IBD gate.  Core ignores cmpctblock/blocktxn during block import.                         |
| BUG-8  | **P3**     | G24        | `p2p.ml:603-606` (total-tx-count cap)                                 | Cap is `>65535` instead of Core's `>MAX_BLOCK_WEIGHT/MIN_SERIALIZABLE_TRANSACTION_WEIGHT=100000`.             |
| BUG-9  | **P3**     | G25        | `peer.ml:1489-1519` (handle_getdata InvCompactBlock)                  | InvCompactBlock served with a freshly-generated nonce per request — Core caches `m_most_recent_compact_block`.|

(BUG-1 is W123 BUG-7 / W123 G30 re-catalogued from BIP-152 angle.)

---

## Audit gates (30)

Reference patterns: **`PRESENT`** — camlcoin matches Core semantics for
this gate; gate test asserts present-shape. **`PARTIAL`** — the gate is
implemented but with a measurable divergence from Core; gate test
asserts the divergent shape that BUG-N would flip. **`MISSING`** — the
gate has no implementation; gate test asserts absence.

### Wire-message shape (5 gates)

| #  | Gate                                | Status   | Core ref                                       | camlcoin ref                                                |
|---:|-------------------------------------|----------|------------------------------------------------|-------------------------------------------------------------|
| G1 | Inv-type MSG_CMPCT_BLOCK = 4        | PRESENT  | `protocol.h` (MSG_CMPCT_BLOCK = 4)              | `p2p.ml:175-200` (`InvCompactBlock -> 4l`)                  |
| G2 | message-type wire names             | PRESENT  | net_processing.cpp `NetMsgType::{...}`         | `p2p.ml:41-50, 92-96, 140-144`                              |
| G3 | CmpctblockMsg / GetblocktxnMsg / BlocktxnMsg variants exist + serialize | PRESENT | blockencodings.h `CBlockHeaderAndShortTxIDs`/`BlockTransactionsRequest`/`BlockTransactions` | `p2p.ml:242-262, 379-382, 786-791, 967-971` |
| G4 | prefilled-tx differential encoding (uint16 index)| PARTIAL  | blockencodings.h:77 `uint16_t index`            | `p2p.ml:568-576` — uses OCaml `int`, range not enforced (no 16-bit overflow check on serialize, only on `last_idx > uint16_max` on deserialize via reconstruct path).  Soft P3 — no observable Core divergence on well-formed blocks. |
| G5 | short-id 6-byte (48-bit) lower-bits | PRESENT  | blockencodings.cpp:48 `SHORTTXIDS_LENGTH=6`     | `p2p.ml:551-565, crypto.ml:557-561` (lower 48 bits)         |

### SipHash key derivation + short-id construction (5 gates)

| #  | Gate                                | Status   | Core ref                                       | camlcoin ref                                                |
|---:|-------------------------------------|----------|------------------------------------------------|-------------------------------------------------------------|
| G6 | sendcmpct SENT on handshake completion + SHORT_IDS_BLOCKS_VERSION gate | PARTIAL | net_processing.cpp:3864-3870 (`GetCommonVersion() >= SHORT_IDS_BLOCKS_VERSION`) | `peer.ml:1004-1006, 1061-1063` — SENDCMPCT sent unconditionally; no protocol-version gate. **BUG-5 P2**.                |
| G7 | sendcmpct RECEIVED with v != 2 silently dropped | PRESENT  | net_processing.cpp:3907                         | `peer.ml:831-837, 1588-1599, 1657-1663` (FIX-43)            |
| G8 | nonce uses CSPRNG (not Random.int64) | PRESENT  | "FastRandomContext().rand64()" (net_processing.cpp:2105) | `p2p.ml:1355-1369` (`/dev/urandom`, FIX-49)             |
| G9 | SipHash-2-4 keys derived from `single-SHA256(header || nonce_le)`, k0/k1 = first/second 8 bytes | PRESENT | blockencodings.cpp:35-44 (`FillShortTxIDSelector`) | `crypto.ml:537-554` (Bug #1 fix per comment: 80-byte raw header preimage, NOT SHA256d) |
| G10| short-id COMPUTED over wtxid (not txid) | PRESENT | blockencodings.cpp:31 (`tx.GetWitnessHash()`)   | `p2p.ml:1383-1392` (`Crypto.compute_wtxid`)                 |

### CmpctblockMsg construction + serialization (5 gates)

| #   | Gate                                | Status   | Core ref                                       | camlcoin ref                                                |
|----:|-------------------------------------|----------|------------------------------------------------|-------------------------------------------------------------|
| G11 | coinbase always prefilled at index 0 | PRESENT  | blockencodings.cpp:28 (`prefilledtxn[0] = {0, block.vtx[0]}`) | `p2p.ml:1379-1381`                                  |
| G12 | short_ids covers non-coinbase txs    | PRESENT  | blockencodings.cpp:29-32                       | `p2p.ml:1383-1392`                                          |
| G13 | total-tx-count = short_ids + prefilled (cmpct.BlockTxCount) | PRESENT | blockencodings.h:119 | `p2p.ml:1397-1399` (compact_block_tx_count)        |
| G14 | reconstruct InitData prefilled-index strictly increasing, abs_idx < tx_count | PRESENT | blockencodings.cpp:72-87 (`READ_STATUS_INVALID` if `(uint32_t)lastprefilledindex > shorttxids.size() + i`) | `p2p.ml:1442-1456` (W112 Bug #4 fix)             |
| G15 | reconstruct collision: two mempool txns matching same short-id → request both | PRESENT | blockencodings.cpp:118-144 (`have_txn[]` clear-on-second-hit) | `p2p.ml:1467-1489` (W112 Bug #2 fix)             |

### GetblocktxnMsg + BlocktxnMsg + reconstruction (5 gates)

| #   | Gate                                | Status   | Core ref                                       | camlcoin ref                                                |
|----:|-------------------------------------|----------|------------------------------------------------|-------------------------------------------------------------|
| G16 | getblocktxn indexes use Core DifferenceFormatter (differential, strictly increasing) | PRESENT | blockencodings.h:23-43 | `p2p.ml:1525-1553` (make_getblocktxn_request + decode_differential_indices)  |
| G17 | getblocktxn responds with BLOCKTXN if block within MAX_BLOCKTXN_DEPTH=10 of tip | PRESENT | net_processing.cpp:4276 | `cli.ml:1428-1474` (FIX-42; falls back to full BlockMsg outside depth) |
| G18 | blocktxn fill_missing fills slots, sealed by checking all-Some | PRESENT | blockencodings.cpp:191-237 (`FillBlock`) | `p2p.ml:1501-1523`                                |
| G19 | blocktxn arm ignored during LoadingBlocks/IBD | MISSING  | net_processing.cpp:4717 (`if (LoadingBlocks()) return`) | `cli.ml:1399` — no LoadingBlocks gate; only `chain.sync_state = FullySynced` would be the equivalent and BlocktxnMsg has no such gate at all. **BUG-7 P2**. |
| G20 | getblocktxn arm ignored during LoadingBlocks/IBD | MISSING  | Core doesn't gate GETBLOCKTXN explicitly during LoadingBlocks (only CMPCTBLOCK + BLOCKTXN) so this is mainly about consistent IBD-state behaviour | `cli.ml:1428` — no IBD gate; serves getblocktxn even pre-IBD-complete.  **BUG-7 P2** (same finding as G19).   |

### CMPCTBLOCK incoming handling (3 gates)

| #   | Gate                                | Status   | Core ref                                       | camlcoin ref                                                |
|----:|-------------------------------------|----------|------------------------------------------------|-------------------------------------------------------------|
| G21 | cmpctblock arm gates on FullySynced (camlcoin proxy for "not-IBD-and-not-LoadingBlocks") | PRESENT | net_processing.cpp:4469 (LoadingBlocks)  + IBD on header-prev-unknown handling | `cli.ml:1349` (`sync_state = FullySynced`)              |
| G22 | reconstruct consults extra_txn pool in addition to mempool | MISSING | blockencodings.cpp:147-176 (`extra_txn` loop) | `peer_manager.ml:2763-2777`, `cli.ml:1356` — only mempool. **BUG-6 P2**.   |
| G23 | reconstruct → GETBLOCKTXN round-trip on missing indices | PRESENT | net_processing.cpp:4609-4634 | `cli.ml:1372-1394` (missing → `make_getblocktxn_request`)   |

### Outbound / HB-announce side (4 gates)

| #   | Gate                                | Status   | Core ref                                       | camlcoin ref                                                |
|----:|-------------------------------------|----------|------------------------------------------------|-------------------------------------------------------------|
| G24 | InvCompactBlock served from getdata within MAX_CMPCTBLOCK_DEPTH=5 | PRESENT | net_processing.cpp:2466-2475 | `peer.ml:1489-1519` (FIX-42)                                |
| G25 | recent-block cache for serving subsequent getblocktxn (Core `m_most_recent_compact_block`) | PARTIAL | net_processing.cpp:863 + 2129 + 4257 | None — every getdata-InvCompactBlock re-runs `create_compact_block` with a fresh nonce.  Functionally correct (peer will reconstruct), but Core caches to avoid re-running siphash for every requesting peer.  **BUG-9 P3**. |
| G26 | maybe_set_hb_compact_peer (3-slot list, outbound-preference, evict-front) | PARTIAL | net_processing.cpp:1272-1329 | `peer_manager.ml:2671-2733` — IMPLEMENTED but **never called**.  `pm.hb_compact_peers` list never grows. **BUG-2 P1**. |
| G27 | maybe_set_hb_compact_peer call-site at "block successfully validated by this peer" hook | MISSING | net_processing.cpp:2103-2152 (NewPoWValidBlock) + 2220 (MaybeSetPeerAsAnnouncingHeaderAndIDs called from `BlockChecked`/`MapBlockSource`) | No such hook anywhere in camlcoin: no `Sync.process_new_block` callout, no `mapBlockSource` equivalent, no NewPoWValidBlock-style fast-announce. **BUG-2 P1**. |

### HB-announce-side block push (3 gates)

| #   | Gate                                | Status   | Core ref                                       | camlcoin ref                                                |
|----:|-------------------------------------|----------|------------------------------------------------|-------------------------------------------------------------|
| G28 | HB-announce CmpctblockMsg sent on local block discovery (mined OR validated reorg-extending) | MISSING | net_processing.cpp:2103-2152 (NewPoWValidBlock) | `peer_manager.ml:1360-1369` (announce_block) — does NOT call `relay_compact_block` and does NOT push CmpctblockMsg.  **BUG-1 P0-CDIV**. |
| G29 | relay_compact_block called from new-block hook | MISSING  | (Core path: NewPoWValidBlock → ForEachNode → CmpctblockMsg) | `peer_manager.ml:2748-2761` — **never called**.  **BUG-3 P1**. |
| G30 | peer_has_header consulted before HB-relay (skip peers missing parent header) | PARTIAL | net_processing.cpp:2142 (`PeerHasHeader(&state, pindex->pprev)`) | `sync.ml:5034-5038` — STUB always returns true.  Even if relay_compact_block were wired, the skip-on-missing-parent invariant would be violated. **BUG-4 P1**. |

---

## Bugs catalogue

### BUG-1 (P0-CDIV, G29) — announce_block never sends CmpctblockMsg

**Location**: `lib/peer_manager.ml:1360-1369`

```ocaml
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

The W123 G30 finding from the mining angle.  This is the **one** outbound
announce path used by `cli.ml` block listeners (lines 1225, 1367, 1417).
It only sends `HeadersMsg` (BIP-130) or `InvMsg`.  It does not consult
`pm.hb_compact_peers` (which is, per BUG-2 / BUG-3, also empty) and does
not call `relay_compact_block` (which is dead per BUG-3).

The fix is conceptually small (~10 LOC) — at the top of `announce_block`,
build a `compact_block` once via `P2p.create_compact_block block`, then
for each peer in `pm.hb_compact_peers ∩ ready` (and where
`peer_has_header peer header.prev_block` returns true — see BUG-4),
push `CmpctblockMsg cb`; for all other ready peers, fall back to the
existing headers/inv branches.  But it requires the input to be a full
`block` (currently the call sites pass only the header), which means
either (a) widening the API to `announce_block ~block`, or (b) reading
the just-stored block from `Storage.ChainDB.get_block` at announce
time.

### BUG-2 (P1, G26+G27) — maybe_set_hb_compact_peer never called

**Location**: `lib/peer_manager.ml:2671-2733`

The helper is well-engineered: it correctly enforces the 3-slot cap,
prefers outbound peers, emits `sendcmpct(1)` to the new HB peer and
`sendcmpct(0)` to the evicted one.  It mirrors Core
`MaybeSetPeerAsAnnouncingHeaderAndIDs` (net_processing.cpp:1272-1329)
faithfully.

But `grep -rn "maybe_set_hb_compact_peer" lib/ bin/` reveals no call
sites except its own definition.  The Core call-graph is:
`PeerManagerImpl::BlockChecked` (validation feedback) → `mapBlockSource`
look-up → `MaybeSetPeerAsAnnouncingHeaderAndIDs`.  camlcoin has no
`mapBlockSource` analogue and no validation-feedback hook calling this
helper.

The 34-wave streak of "dead-helper-at-call-site" continues (W107 BUG-1,
W109 BUG-3, W111 BUG-6, W113 BUG-9, W114 G10, W116 BUG-3 + BUG-5, W120
BUG-12 + BUG-13, W120 nimrod validateRbfDiagram = FIX-79, W123 BUG-1,
W125 BUG-N, …).

### BUG-3 (P1, G29) — relay_compact_block never called

**Location**: `lib/peer_manager.ml:2748-2761`

Same pattern as BUG-2: well-engineered helper, no call sites.  The
function correctly builds a `CompactBlockMsg` once and broadcasts it to
all `hb_compact_peers` whose `peer_has_header peer prev_hash` returns
true.  But because `pm.hb_compact_peers` is permanently empty (BUG-2)
and `announce_block` never calls this function (BUG-1), it is doubly
unreachable.

### BUG-4 (P1, G30) — peer_has_header stub

**Location**: `lib/sync.ml:5034-5038`

```ocaml
let peer_has_header (_peer : Peer.peer) (_hash : Types.hash256) : bool =
  (* Simplified check: assume peer has header if handshake complete.
     A more sophisticated implementation would track peer's best header. *)
  true
```

W112 BUG-7 unfixed.  Core `PeerHasHeader` uses per-peer
`state.pindexBestKnownBlock` + `pindexBestHeaderSent` (the headers we've
either learned the peer has via `inv`/`headers` or pushed to them).
camlcoin does not maintain either field, so the stub is forced.

Combined with BUG-3 (which is dead anyway), the consequence is benign
today.  But once BUG-1/2/3 are fixed, this stub would have us push
`cmpctblock` to peers that have not yet seen the parent header, and
those peers would respond with the BIP-152-mandated "didn't follow"
behaviour (request via `headers`, etc.) instead of fast-relaying.

### BUG-5 (P2, G6) — SENDCMPCT not gated on SHORT_IDS_BLOCKS_VERSION

**Location**: `lib/peer.ml:1004-1006`, `1061-1063`

camlcoin sends `SendcmpctMsg{announce=false; version=2}` to every peer
post-handshake (both inbound and outbound).  Core gates this on
`pfrom.GetCommonVersion() >= SHORT_IDS_BLOCKS_VERSION` (= 70014, per
`node/protocol_version.h:30`); see net_processing.cpp:3864-3870.

In practice, peers running pre-70014 protocol versions either don't
parse the `sendcmpct` message (and may misbehaviour-score us) or simply
ignore it.  The Core behaviour is to suppress the message entirely when
the peer's negotiated version is below 70014.  camlcoin has access to
the peer's version (`peer.version_msg` is set during handshake) so the
gate is implementable in ~3 lines.

### BUG-6 (P2, G22) — no vExtraTxnForCompact pool

**Location**: `lib/peer_manager.ml:2763-2777`, `lib/cli.ml:1356`

```ocaml
let reconstruct_from_mempool (pm : t) (cb : P2p.compact_block) =
  let (k0, k1) = Crypto.SipHash.derive_keys cb.header cb.nonce in
  let lookup_tbl = create_mempool_lookup pm ~k0 ~k1 in
  let lookup = { P2p.by_short_id = lookup_tbl } in
  P2p.reconstruct_block cb lookup
```

Core (blockencodings.cpp:147-176) walks both the mempool and a
`vExtraTxnForCompact` pool of recently-replaced / recently-evicted
transactions.  The extra-pool is small (Core: ~100 entries) but
catches the common case of a transaction that was replaced (RBF) in the
mempool moments before the block arrives.  Without it, RBF'd
transactions force a `getblocktxn` round-trip on receipt of the
cmpctblock that includes the original (replacement-rejected) tx.

camlcoin does not maintain any equivalent.  Soft P2 because the
behaviour is "extra round-trip on RBF'd transactions" — no
network-observable consensus divergence.

### BUG-7 (P2, G19+G20) — no LoadingBlocks gate on blocktxn/getblocktxn arms

**Location**: `lib/cli.ml:1399-1427`, `1428-1478`

```ocaml
| P2p.BlocktxnMsg resp -> ...                (* no IBD/LoadingBlocks gate *)
| P2p.GetblocktxnMsg req -> ...              (* no IBD/LoadingBlocks gate *)
```

Compare to Core net_processing.cpp:4717:

```cpp
if (msg_type == NetMsgType::BLOCKTXN) {
    // Ignore blocktxn received while importing
    if (m_chainman.m_blockman.LoadingBlocks()) { ... return; }
    ...
}
```

camlcoin has no `LoadingBlocks` equivalent, but does have
`chain.sync_state = FullySynced` (used to gate `CmpctblockMsg` at
cli.ml:1349).  The minimal fix is to add the same gate to the blocktxn
and getblocktxn arms.

Soft P2 because the only state during which this matters is reindex /
initial block download, and the behavioural difference is "respond to
queries during IBD" (camlcoin) vs. "silently ignore" (Core) — at
worst this is bandwidth waste.

### BUG-8 (P3, G24/G13) — total-tx-count cap is 65535, Core is 100000

**Location**: `lib/p2p.ml:603-606`

```ocaml
(* Short IDs use uint16_t indices; a combined count > 65535 overflows them. *)
if short_id_count + prefilled_count > 65535 then
  failwith "compact block total tx count overflows 16 bits";
```

Core's `InitData` (blockencodings.cpp:64) rejects on
`> MAX_BLOCK_WEIGHT / MIN_SERIALIZABLE_TRANSACTION_WEIGHT = 100000`
(consensus.h:15+24).  Core's `BlockTxCount()` per-message cap is also
65535 because the type for `indexes` is `std::vector<uint16_t>`
(blockencodings.h:125-127 throws on read), so practically the limits
coincide.  Soft P3 — the camlcoin cap is stricter but never observable
in practice (no block can have > 100000 transactions either).

### BUG-9 (P3, G25) — InvCompactBlock served without recent-block cache

**Location**: `lib/peer.ml:1497-1519`

camlcoin's `handle_getdata` for `InvCompactBlock` calls
`P2p.create_compact_block block` (which runs SipHash over every wtxid)
every time a peer requests the same block.  Core caches one compact
block in `m_most_recent_compact_block` (net_processing.cpp:863, set at
line 2129 in `NewPoWValidBlock`).  When multiple peers `getdata` the
tip simultaneously, Core hands them the cached encoding; camlcoin
recomputes per request.

P3: performance only.  Each call is O(N_txs * SipHash), which on a
filled mainnet block (~3000 txs) is ~50-100 µs — not material at
camlcoin's current throughput.

---

## Concurrent-agent note

This audit lands alongside W124 / W125 / W123 audits (all merged earlier
on master) and is one of 4 parallel audits dispatched simultaneously.
The only shared file is `test/dune` (test target registration);
`test_w126_bip152_compact_blocks` is added as the sole new entry.
On `push --rejected`: `git pull --rebase`, then re-push.  On `test/dune`
conflict: `git reset HEAD~1 --soft`, re-stage `audit/w126_*.md`,
`test/test_w126_bip152_compact_blocks.ml`, and the `dune` line containing
`test_w126_bip152_compact_blocks` only, then re-commit.

## Methodology checklist

- [x] Read `bitcoin-core/src/blockencodings.h` + `blockencodings.cpp` in full.
- [x] Read `bitcoin-core/src/net_processing.cpp` SENDCMPCT/CMPCTBLOCK/
      GETBLOCKTXN/BLOCKTXN handlers (lines 1272-1329, 2103-2152, 3864-3917,
      4245-4304, 4466-4711, 4714-4726).
- [x] Read BIP-152 — short-ID derivation, HB-mode protocol, version bump.
- [x] Synthesise 30-gate matrix covering wire-shape + SipHash + cmpctblock
      reconstruction + getblocktxn/blocktxn + HB-peer mgmt + announce-side
      block push.
- [x] Classify gates against camlcoin source.
- [x] Catalogue 9 BUGS with priority + camlcoin code refs.
- [x] Write 30 audit-status tests in `test/test_w126_bip152_compact_blocks.ml`.
- [x] Append exactly one entry to `test/dune` for the new test target.
- [x] Document parallel-agent merge protocol.
- [x] Avoid `dune runtest` (FIX-64 / FIX-80 dune-lock-contention lessons);
      run pre-built `_build/default/test/test_w126_bip152_compact_blocks.exe`.
