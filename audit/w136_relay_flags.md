# W136 BIP-130 sendheaders + BIP-133 feefilter + BIP-339 wtxidrelay — camlcoin (OCaml)

Wave: W136 — Post-handshake relay-feature flags. Three BIPs covered together
because they share the version-handshake surface area, the same per-peer
state struct (`peer.ml :: type peer`), and the same send paths
(handshake-completion + `peer_message_loop`).

Bitcoin Core references:

- `bitcoin-core/src/net_processing.cpp`
  - L283: `m_wtxid_relay`
  - L287: `m_fee_filter_sent`
  - L321: `m_fee_filter_received`
  - L405-406: `m_sent_sendheaders`
  - L412: `m_prefers_headers`
  - L740-741: `MaybeSendSendHeaders`
  - L757: `FeeFilterRounder m_fee_filter_rounder`
  - L837: `m_wtxid_relay_peers` (per-node counter)
  - L1688-1689, 1727: enforce `--m_wtxid_relay_peers` on disconnect /
    final assertion-zero
  - L1819-1825: `getpeerinfo` exposes `m_fee_filter_received`
  - L2259, 4403: per-INV wtxid-vs-txid selection
  - L3710-3712: send WTXIDRELAY at VERSION-receive time (greatest-common
    >= WTXID_RELAY_VERSION)
  - L3897: `peer.m_prefers_headers = true` on receive
  - L3919-3939: BIP-339 wtxidrelay state machine: must be between
    VERSION and VERACK; post-VERACK = disconnect; duplicate = ignore;
    common-version below 70016 = log + ignore
  - L4056-4063: ignore INVs that don't match wtxidrelay setting
  - L5035-5044: receive FEEFILTER: `MoneyRange(newFeeFilter)` gate
    before storing
  - L5519-5538: `MaybeSendSendHeaders` — gates on
    `m_sent_sendheaders == false`, GetCommonVersion >= 70012, and
    `pindexBestKnownBlock->nChainWork > MinimumChainWork()`
  - L5540-5580: `MaybeSendFeefilter` — gates, `IsBlockOnlyConn()`,
    `ForceRelay` permission, `IsInitialBlockDownload()` ⇒ MAX_MONEY,
    Poisson schedule, MAX_FEEFILTER_CHANGE_DELAY accel
  - L5763: `MaybeSendSendHeaders(node, peer)` called every send loop
  - L5838-5840: block-announce coalescing: `m_prefers_headers` vs inv,
    `MAX_BLOCKS_TO_ANNOUNCE` revert-to-inv
  - L5915, 5928: per-peer block announce branch on `m_prefers_headers`

- `bitcoin-core/src/net.h` + `net.cpp` — `CNode`, `GetCommonVersion`,
  `IsBlockOnlyConn`, `IsFeelerConn`, `HasPermission`,
  `NetPermissionFlags::ForceRelay`

- `bitcoin-core/src/policy/feerate.cpp` + `policy/fees/block_policy_estimator.{h,cpp}`
  - `CFeeRate`, `MakeFeeSet`, `FeeFilterRounder::FeeFilterRounder`,
    `FeeFilterRounder::round`
  - Spacing 1.1x, max 1e7, 2/3 round-down probability
  - Random source: `FastRandomContext` (Core's CSPRNG wrapper)

- `bitcoin-core/src/node/protocol_version.h`
  - `SENDHEADERS_VERSION = 70012`
  - `FEEFILTER_VERSION = 70013`
  - `WTXID_RELAY_VERSION = 70016`

BIPs:
- BIP-130: post-handshake sendheaders for direct block-header announcements
- BIP-133: feefilter for mempool-feerate-floor advertisement
- BIP-339: wtxidrelay feature negotiation (pre-VERACK, witness-tx-id-only INV)

## Methodology

1. Read Core refs (above).
2. Enumerate 30 audit gates spanning send-side, receive-side, state,
   timing, and end-to-end semantics (Section "30-gate matrix").
3. Classify each gate against camlcoin's de-facto surface
   (`peer.ml` for state + send/recv; `peer_manager.ml` for periodic /
   loop integration; `consensus.ml` for protocol-version constants).
4. Catalogue BUGs by severity:
   - **P0-CDIV**: protocol-correctness divergence externally visible to
     peers (silent message loss, malformed wire, missing required field)
   - **P1**: feature-correctness gap (right wire format but wrong
     gating / ordering)
   - **P2**: privacy / fingerprinting / fairness drift (works but leaks
     information)
   - **P3**: surface / doc / constant drift

Severity legend mirrors W130 / W131 / W132 / W133.

## camlcoin de-facto surface

| Concern | Core | camlcoin |
|---------|------|----------|
| send-side sendheaders | `MaybeSendSendHeaders` after MinimumChainWork | unconditional, inline in `perform_handshake_inner` (`peer.ml:1004`, `1061`) |
| recv-side sendheaders | `peer.m_prefers_headers = true` (post-handshake only) | `peer.send_headers <- true` only post-handshake (`peer.ml:1639-1641`) |
| send-side feefilter | `MaybeSendFeefilter` from `SendMessages` loop | `maybe_send_feefilter` from `peer_message_loop` on every read timeout (`peer_manager.ml:1773-1784`) |
| recv-side feefilter | MoneyRange-validated, peer-state stored | unconditional `peer.feefilter <- feerate` (`peer.ml:1601-1607`, `peer.ml:1665-1667`, `peer.ml:838-841`) |
| send-side wtxidrelay | pre-VERACK if greatest-common >= 70016 | gated on `peer.services.witness` AND peer-advertised version >= 70016 (`peer.ml:786-791`) |
| recv-side wtxidrelay | pre-VERACK gating + duplicate-ignore + common-version-skip | pre-VERACK gating present + post-VERACK = misbehave + disconnect (`peer.ml:1570-1577`, `1643-1646`); no duplicate-ignore; no common-version-skip |
| per-peer relay-state struct | `Peer.m_sent_sendheaders`, `m_prefers_headers`, `m_fee_filter_sent`, `m_fee_filter_received`, `m_next_send_feefilter`, `m_wtxid_relay` | `peer.send_headers`, `peer.feefilter` (received), `peer.fee_filter_sent`, `peer.next_send_feefilter`, `peer.wtxid_relay` (received) — **no `sent_sendheaders` latch** |
| per-node wtxid-relay counter | `m_wtxid_relay_peers` atomic | absent |
| FeeFilterRounder PRNG | `FastRandomContext` (CSPRNG/GetStrongRandBytes) | `csprng_int_range` via `/dev/urandom` (`peer.ml:316-331`) — semantically identical |
| MAX_FILTER (IBD-out reset) | `m_fee_filter_rounder.round(MAX_MONEY)` static, used to reset next-send on IBD exit | absent — no IBD-aware reset, no MAX_MONEY ceiling injection during IBD |
| getpeerinfo `minfeefilter` / `feefilter_received` | reported | reported as `peer.feefilter` only (received side); `fee_filter_sent` is NOT in `peer_stats` (`peer.ml:1721-1745`) |
| block-announce coalescing | per-peer `m_blocks_for_headers_relay` deque + `MAX_BLOCKS_TO_ANNOUNCE` revert-to-inv | none — `announce_block` is single-shot, no deque, no MAX_BLOCKS_TO_ANNOUNCE constant (`peer_manager.ml:1360-1369`) |
| inbound-mismatch (wtxidrelay) INV filter | `if (peer.m_wtxid_relay && inv.type == MSG_TX) drop` | not enforced (camlcoin queues INVs in `queue_inv` without re-checking the peer's wtxidrelay setting against an incoming MSG_TX) |

## 30-gate matrix (W136)

### G1-G6: BIP-130 sendheaders — send side

- **G1: send-side sendheaders gated on MinimumChainWork.**
  Core (`net_processing.cpp:5525-5536`): `MaybeSendSendHeaders` only
  emits if `state.pindexBestKnownBlock != nullptr &&
  state.pindexBestKnownBlock->nChainWork > MinimumChainWork`. camlcoin
  (`peer.ml:1003-1004`, `1060-1061`): unconditional inline send in
  `perform_handshake_inner` / `perform_inbound_handshake_inner`.
  **BUG-W136-1 (P1)**: camlcoin announces "send me headers" before it has
  seen enough chainwork from this peer to know they're worth following
  — sends sendheaders even to a peer whose advertised tip is lower than
  our nMinimumChainWork. Externally observable: spy peers can detect
  camlcoin from this missing gate.

- **G2: send-once latch (`m_sent_sendheaders`).** Core
  (`net_processing.cpp:405-406, 5535`): atomic latch flipped exactly
  once per peer. camlcoin (`peer.ml`): no `sent_sendheaders` field on
  `type peer`. The single inline send happens in handshake — so duplicate
  emission can't currently happen — but if a future refactor adds a
  periodic call (mirroring Core's `MaybeSendSendHeaders` from
  `SendMessages`), there's no latch to prevent retransmission.
  **BUG-W136-2 (P3)**: no `sent_sendheaders` latch field. Architectural
  drift from Core; not externally observable today but encodes a latent
  duplicate-send risk if any agent later wires periodic `MaybeSendSendHeaders`.

- **G3: send-side version gate `>= SENDHEADERS_VERSION (70012)`.**
  Core (`net_processing.cpp:5525`): gated on `GetCommonVersion() >= 70012`.
  camlcoin: `min_protocol_version = 70015l` (`peer.ml:224`) means
  camlcoin disconnects any peer below 70015 — so SENDHEADERS_VERSION
  (70012) is structurally satisfied. **No bug**; document as PASS.

- **G4: post-handshake-only emission.** Core gates on `m_sent_sendheaders == false`
  AND state allows; the send actually happens in `SendMessages` AFTER
  the version exchange completes (line 5763). camlcoin sends inline
  in `perform_handshake_inner` (lines 1003-1004, 1060-1061), which is
  AFTER `peer.handshake_complete <- true` (line 1001, 1059) — so
  technically post-handshake. **No bug.**

- **G5: send-side opt-out for outbound block-relay-only.**
  Core does not separately gate sendheaders on block-relay-only — Core
  is OK with header-based announcement even for block-relay-only peers.
  camlcoin's `perform_handshake_inner` sends sendheaders BEFORE
  `peer.block_relay_only` is set (`peer_manager.ml:986-990`: the
  handshake completes first, then `block_relay_only <- true` is set).
  So both Core and camlcoin send sendheaders to block-relay-only outbound
  peers (camlcoin "accidentally", Core deliberately). **No bug** —
  behavioural parity.

- **G6: revert-to-inv if MAX_BLOCKS_TO_ANNOUNCE exceeded.**
  Core (`net_processing.cpp:5838-5840`): when our queue has more than
  `MAX_BLOCKS_TO_ANNOUNCE` (8) headers to send, fall back to inv.
  Constant `MAX_BLOCKS_TO_ANNOUNCE = 8` per Core. camlcoin's
  `announce_block` (`peer_manager.ml:1360-1369`) takes a single header
  per call — no batching, no deque, no revert-to-inv path. Catching up
  on >8 blocks at once is impossible to express. **BUG-W136-3 (P1)**:
  No `MAX_BLOCKS_TO_ANNOUNCE` constant. No revert-to-inv. Wire-compatible
  but cannot announce multiple headers in one HEADERS message even when
  the peer prefers headers.

### G7-G12: BIP-130 sendheaders — receive side + announcement

- **G7: post-VERACK sendheaders sets `m_prefers_headers`.**
  Core (`net_processing.cpp:3896-3899`): receive SENDHEADERS, set
  `peer.m_prefers_headers = true`. camlcoin (`peer.ml:1639-1641`):
  receive `SendheadersMsg` post-handshake, set `peer.send_headers <- true`.
  **No bug**; structural parity.

- **G8: pre-VERACK SENDHEADERS handling.**
  Core (`net_processing.cpp:3896`): SENDHEADERS isn't gated to
  pre/post-VERACK — Core silently accepts SENDHEADERS at any state
  (because it's just a flag flip). camlcoin: SENDHEADERS only matches
  the `, true` post-handshake arm. The pre-handshake arm falls into the
  catch-all (`peer.ml:1626-1628`) which **misbehavior-scores 10 and
  returns PreHandshake "Message received before handshake complete"**.
  Per Core, pre-VERACK SENDHEADERS is benign and silently accepted (set
  the flag, return). **BUG-W136-4 (P2)**: pre-VERACK SENDHEADERS earns
  a 10-point misbehavior penalty in camlcoin where Core silently accepts
  it. Externally observable: a peer that legitimately sends SENDHEADERS
  early (as some implementations do) accrues misbehavior with camlcoin.
  10 points per peer is below the 100-point ban threshold but contributes
  to fingerprinting (camlcoin's misbehaviour score becomes higher than
  Core's for the same wire trace).

- **G9: announce_block honours `send_headers`.**
  camlcoin (`peer_manager.ml:1360-1369`): `if peer.send_headers then
  HeadersMsg [header] else InvMsg [{InvBlock; hash}]`. Matches Core's
  per-peer branch. **No bug.**

- **G10: peer-has-header tracking.**
  Core (`net_processing.cpp:5876-5879`): `PeerHasHeader(&state, pindex)`
  / `m_blocks_known` — Core does not re-announce headers the peer has
  already inv'd to us OR that we've already announced to them. camlcoin:
  no equivalent — every `announce_block` call sends to every Ready peer
  regardless of whether the peer has already seen the header. Cumulative
  redundant wire traffic during fast catch-up. **BUG-W136-5 (P2)**: no
  per-peer known-headers set; redundant HEADERS / INV traffic during
  multi-block catchup waves. Privacy: minor — doesn't leak our chain
  state beyond what's already public. Fairness: minor cost of duplicate
  bandwidth.

- **G11: best-header-sent tracking (`pindexBestHeaderSent`).**
  Core (`net_processing.cpp:5914, 5926`): tracks the highest header we
  announced to this peer so the next call only sends incremental headers.
  camlcoin: no equivalent. Same root cause as G10. **BUG-W136-6 (P2)**:
  no per-peer best-header-sent tracking. Subsumed by G10 in practice
  but worth a separate gate because the fix shape differs (a single
  int32 vs a hashset).

- **G12: chain-not-on-active fallback.**
  Core (`net_processing.cpp:5852-5854`): if the header to announce is
  not on `m_chainman.ActiveChain()`, revert to inv. camlcoin: no
  equivalent — `announce_block` happily sends a HEADERS message for any
  header passed in. Caller (`Sync.connect_tip` / similar) is expected
  to only pass active-chain tips, but there's no defensive guard.
  **BUG-W136-7 (P3)**: no defensive active-chain guard in
  `announce_block`; relies on every caller being correct.

### G13-G18: BIP-133 feefilter — send side

- **G13: send-side feefilter gated on common-version >= FEEFILTER_VERSION.**
  Core (`net_processing.cpp:5543`): `if (pto.GetCommonVersion() <
  FEEFILTER_VERSION) return;`. camlcoin (`peer.ml:1947-1949`):
  `should_send_feefilter` checks `v.protocol_version >= feefilter_version`.
  Note: camlcoin checks PEER's advertised version, NOT
  `min(ours, peers) = common version`. Since camlcoin's
  `min_protocol_version = 70015` (and feefilter is 70013), this works
  out the same in practice. **No bug.**

- **G14: skip feefilter for outbound block-relay-only peers.**
  Core (`net_processing.cpp:5548`): `if (pto.IsBlockOnlyConn()) return;`.
  camlcoin: `should_send_feefilter` (`peer.ml:1945`) checks
  `not peer.block_relay_only`. **No bug.**

- **G15: skip feefilter when ignore_incoming_txs (blocksonly mode).**
  Core (`net_processing.cpp:5542`): `if (m_opts.ignore_incoming_txs)
  return;`. camlcoin: no `ignore_incoming_txs` / `--blocksonly` flag
  exists; node always relays tx. **BUG-W136-8 (P3)**: no -blocksonly
  mode. Operationally observable: camlcoin always sends feefilter (and
  always accepts tx INV) where Core operators expect a -blocksonly mode
  to suppress feefilter emission.

- **G16: skip feefilter for ForceRelay-permission peers.**
  Core (`net_processing.cpp:5544-5545`): `if (pto.HasPermission(ForceRelay))
  return;`. camlcoin: no NetPermissionFlags layer; `no_ban` is the only
  permission flag and it covers ban-immunity, not force-relay.
  **BUG-W136-9 (P3)**: no ForceRelay permission. Whitebound peers
  expected to bypass our feerate floor (e.g., a known-good local relay)
  will not in fact bypass it.

- **G17: IBD-aware MAX_MONEY ceiling.**
  Core (`net_processing.cpp:5552-5555`): `if (m_chainman.IsInitialBlockDownload())
  { currentFilter = MAX_MONEY; }`. During IBD, Core tells peers we want
  zero tx (filter at MAX_MONEY). camlcoin (`peer.ml:1992-2006`,
  `peer_manager.ml:1773-1784`): always uses `mp.min_relay_fee` (1000)
  regardless of IBD state. **BUG-W136-10 (P0-CDIV)**: during IBD,
  camlcoin advertises a 1 sat/vB feefilter (the static min-relay floor)
  when Core advertises MAX_MONEY (21M BTC * 1e8 = 2.1e15 sat/kvB).
  Externally observable on the wire — camlcoin will receive tx
  announcements during IBD (and waste bandwidth processing them) where
  Core would not.

- **G18: post-IBD reset of next-send.**
  Core (`net_processing.cpp:5557-5562`): `static const CAmount MAX_FILTER
  = m_fee_filter_rounder.round(MAX_MONEY);` then `if (peer.m_fee_filter_sent
  == MAX_FILTER) peer.m_next_send_feefilter = 0us;` — when leaving IBD,
  immediately schedule a new feefilter announcement to the real value.
  camlcoin: no such reset. **BUG-W136-11 (P1)**: depends on G17; if
  G17 is closed (so IBD-MAX-MONEY is sent), G18 is also required so the
  peer is told the real feerate floor immediately on IBD exit instead of
  waiting up to 10 minutes (the Poisson average).

### G19-G24: BIP-133 feefilter — receive side + state + timing

- **G19: MoneyRange-validate received feefilter.**
  Core (`net_processing.cpp:5037-5043`): `vRecv >> newFeeFilter; if
  (MoneyRange(newFeeFilter)) { tx_relay->m_fee_filter_received = newFeeFilter; }`.
  i.e., reject negative or > MAX_MONEY values. camlcoin
  (`peer.ml:1601-1607`, `1665-1667`, `838-841`): unconditional
  `peer.feefilter <- feerate`. **BUG-W136-12 (P0-CDIV)**: camlcoin
  accepts a negative or > MAX_MONEY feefilter where Core silently drops
  it. Externally observable: a malicious peer can set our local
  `peer.feefilter` for them to any int64 value (including INT64_MIN),
  which then enters `passes_feefilter` (`peer.ml:1764-1769`) as the
  threshold. tx_fee_rate >= INT64_MIN is always true, so this is just
  bandwidth waste; tx_fee_rate >= INT64_MAX is always false, which is
  the wire-effect of a peer setting feefilter to MAX_INT64. The real
  privacy concern is that camlcoin lets the peer probe whether the
  value-clamp is active. Document as P0 because it's a textual wire-spec
  deviation, not just policy.

- **G20: per-peer `m_fee_filter_received` (separate from sent).**
  Core: two separate fields, `m_fee_filter_sent` (what we told them)
  and `m_fee_filter_received` (what they told us). camlcoin: `peer.feefilter`
  is the received value; `peer.fee_filter_sent` is the sent value. **No bug.**

- **G21: per-peer `next_send_feefilter` Poisson schedule.**
  Core (`net_processing.cpp:5572`): `peer.m_next_send_feefilter =
  current_time + m_rng.rand_exp_duration(AVG_FEEFILTER_BROADCAST_INTERVAL);`.
  camlcoin (`peer.ml:398, 1962-1963, 1985-1986`): `peer.next_send_feefilter
  <- Unix.gettimeofday () +. poisson_delay avg_feefilter_broadcast_interval`.
  `poisson_delay` (`peer.ml:348-352`) uses `Random.float` (the OCaml
  stdlib PRNG, not the CSPRNG). **BUG-W136-13 (P2)**: `poisson_delay`
  uses `Random.float` (deterministic from the initial seed) instead of
  `csprng_int_range`-equivalent. Per the comment on `csprng_int_range`
  (`peer.ml:312-315`), this is exactly the leak the CSPRNG was introduced
  to avoid for FeeFilterRounder. The feefilter timing leaks similarly —
  if the seed is predictable, the schedule is predictable. Fingerprintable.

- **G22: significant-change-accel within MAX_FEEFILTER_CHANGE_DELAY.**
  Core (`net_processing.cpp:5576-5578`): `if (current_time +
  MAX_FEEFILTER_CHANGE_DELAY < peer.m_next_send_feefilter &&
  (currentFilter < 3 * peer.m_fee_filter_sent / 4 || currentFilter
  > 4 * peer.m_fee_filter_sent / 3))`. camlcoin
  (`peer.ml:1954-1959, 2008-2013`): `significant_feefilter_change`
  checks `< 0.75 || > 1.33`. Note: `1.33` vs `4/3 = 1.3333...` —
  camlcoin's float threshold is **truncated** by one decimal place.
  **BUG-W136-14 (P3)**: `1.33` is not `4/3`; minor numerical drift in
  the trigger band. For sent_fee = 1000, Core triggers at >1333; camlcoin
  triggers at >1330. 3-sat-per-kvB window where camlcoin accelerates and
  Core does not. Fingerprintable in principle.

- **G23: `reschedule_feefilter_soon` uses CSPRNG.**
  Core (`net_processing.cpp:5577-5578`): `peer.m_next_send_feefilter =
  current_time + m_rng.randrange<std::chrono::microseconds>(MAX_FEEFILTER_CHANGE_DELAY);`.
  Uses `FastRandomContext` (CSPRNG). camlcoin (`peer.ml:1968`):
  `Random.float max_feefilter_change_delay`. **BUG-W136-15 (P2)**: same
  root cause as G21 (Random.float vs CSPRNG). Same fingerprinting risk.

- **G24: avoid resending when value unchanged.**
  Core (`net_processing.cpp:5568`): `if (filterToSend != peer.m_fee_filter_sent)`.
  camlcoin (`peer.ml:1999-2005`): `if rounded = peer.fee_filter_sent
  then ... return false else send`. **No bug.**

### G25-G27: BIP-339 wtxidrelay — send + recv + state

- **G25: send-side wtxidrelay sent between VERSION and VERACK.**
  Core (`net_processing.cpp:3710-3712`): in VERSION receive handler,
  after greatest-common version is set, if `>= WTXID_RELAY_VERSION`
  send WTXIDRELAY before SENDADDRV2 and VERACK. camlcoin
  (`peer.ml:782-791`): `send_feature_negotiation` called from
  `perform_handshake_inner` (line 994) and
  `perform_inbound_handshake_inner` (line 1052), AFTER our VERSION but
  BEFORE our VERACK. **No bug** for sequencing.

  BUT: camlcoin gates wtxidrelay-send on `peer.services.witness &&
  v.protocol_version >= Consensus.wtxid_relay_version`. The
  `services.witness` gate is NOT present in Core. Core's gate is purely
  `greatest_common_version >= WTXID_RELAY_VERSION`. Per BIP-339 the
  WITNESS service bit is irrelevant — wtxidrelay is a transport
  feature, not a witness-storage one. **BUG-W136-16 (P0-CDIV)**: a peer
  that advertises NODE_NETWORK_LIMITED (no NODE_WITNESS) but protocol
  version 70016+ will NOT receive WTXIDRELAY from camlcoin. Per
  BIP-339 these peers should receive it. Side-effect: such peers will
  send camlcoin MSG_TX INVs and camlcoin will not relay tx via MSG_WTX.
  Wire-observable.

- **G26: receive-side post-VERACK WTXIDRELAY = disconnect.**
  Core (`net_processing.cpp:3922-3926`): if `fSuccessfullyConnected`
  when WTXIDRELAY arrives, set `fDisconnect = true`. camlcoin
  (`peer.ml:1643-1646`): receives WTXIDRELAY post-handshake → misbehave
  1 + `Disconnect`. **No bug** for end-result; minor cosmetic that
  Core gives 0 points and camlcoin gives 1 (subsumed by the disconnect).

- **G27: duplicate WTXIDRELAY pre-VERACK = ignore (don't double-increment counter).**
  Core (`net_processing.cpp:3928-3934`): explicit `if (!peer.m_wtxid_relay)
  { peer.m_wtxid_relay = true; m_wtxid_relay_peers++; } else { ignore-log; }`.
  camlcoin (`peer.ml:1570-1577`): unconditional `peer.wtxid_relay <- true`.
  camlcoin has no `m_wtxid_relay_peers` counter so there's no integer
  to double-increment, but the wire-observable cost is: duplicate
  pre-VERACK wtxidrelay should be quiet (Core logs at debug); camlcoin
  doesn't log at all and doesn't increment a counter, so this is not a
  bug per se but it IS an information-loss: camlcoin cannot tell you
  "this peer sent wtxidrelay twice". **BUG-W136-17 (P3)**: no duplicate
  wtxidrelay detection. Doc/instrumentation drift only.

### G28-G30: state, integration, end-to-end

- **G28: INV-type matches wtxidrelay setting on send.**
  Core (`net_processing.cpp:6007-6009, 4403`): when announcing tx INVs,
  uses `peer.m_wtxid_relay ? MSG_WTX : MSG_TX`. camlcoin
  (`peer_manager.ml:1393-1399`): in `announce_tx`, branches
  `if peer.Peer.wtxid_relay then make_tx_inv ~witness:true wtxid
  else make_tx_inv ~witness:false txid`. **No bug** for outbound INV.

- **G29: INV-type mismatch on receive = ignore.**
  Core (`net_processing.cpp:4056-4063`): "Ignore INVs that don't match
  wtxidrelay setting." If peer is wtxid-relay and sends MSG_TX, ignore.
  If peer is non-wtxid-relay and sends MSG_WTX, ignore. camlcoin: no
  equivalent. Whatever the peer sends is queued via the standard
  GETDATA flow. **BUG-W136-18 (P1)**: no INV-type-mismatch filter.
  A wtxid-relay peer that mistakenly sends MSG_TX gets serviced. Per
  Core: this is a protocol-conformance gate, not just optimisation.

- **G30: post-VERACK wtxidrelay-counter delta is enforced on disconnect.**
  Core (`net_processing.cpp:1688-1689`): on FinalizeNode, decrement
  `m_wtxid_relay_peers` if the peer had it set. camlcoin: no
  `m_wtxid_relay_peers` counter at all (G27 lookback). **BUG-W136-19 (P3)**:
  no per-node aggregate count of wtxid-relay peers. No `getpeerinfo`
  or `getnetinfo` surface exposes it. Operator visibility loss.

### Invariant guards (INV-)

- **INV-1: protocol-version constants.** `sendheaders_version = 70012l`,
  `feefilter_version = 70013l`, `wtxid_relay_version = 70016l` —
  all match Core `protocol_version.h`. **No bug.**

- **INV-2: AVG_FEEFILTER_BROADCAST_INTERVAL = 600s** (10 min). Matches
  Core. **No bug.**

- **INV-3: MAX_FEEFILTER_CHANGE_DELAY = 300s** (5 min). Matches Core. **No bug.**

- **INV-4: FeeFilterRounder buckets = powers of 1.1 from min/2 to 1e7.**
  Matches Core `FEE_FILTER_SPACING = 1.1`, `MAX_FILTER_FEERATE = 1e7`. **No bug.**

## Summary — bug catalogue

| # | Sev | Gate | Description |
|---|-----|------|-------------|
| BUG-W136-1 | P1 | G1 | sendheaders not gated on MinimumChainWork; sent unconditionally in handshake. |
| BUG-W136-2 | P3 | G2 | no `sent_sendheaders` latch on `type peer`; encodes a duplicate-send risk for any future refactor. |
| BUG-W136-3 | P1 | G6 | no `MAX_BLOCKS_TO_ANNOUNCE` (=8) constant; no revert-to-inv fallback in announce_block. |
| BUG-W136-4 | P2 | G8 | pre-VERACK SENDHEADERS earns 10 misbehavior points where Core accepts silently. |
| BUG-W136-5 | P2 | G10 | no per-peer known-headers set; redundant HEADERS / INV traffic on catchup. |
| BUG-W136-6 | P2 | G11 | no per-peer `pindexBestHeaderSent` tracking; same root cause as G10. |
| BUG-W136-7 | P3 | G12 | no defensive active-chain guard in announce_block. |
| BUG-W136-8 | P3 | G15 | no -blocksonly mode; feefilter always emitted. |
| BUG-W136-9 | P3 | G16 | no ForceRelay permission; bypass-relay peers unsupported. |
| BUG-W136-10 | P0-CDIV | G17 | no IBD-aware MAX_MONEY ceiling; tx INVs accepted during IBD. |
| BUG-W136-11 | P1 | G18 | no post-IBD-exit feefilter reset; peers see stale floor for up to 10 min. |
| BUG-W136-12 | P0-CDIV | G19 | no MoneyRange validation on received FEEFILTER; arbitrary int64 stored. |
| BUG-W136-13 | P2 | G21 | `poisson_delay` uses `Random.float` (stdlib PRNG) instead of CSPRNG; fingerprintable. |
| BUG-W136-14 | P3 | G22 | significant-change threshold is `1.33` instead of `4/3 ≈ 1.3333...`; minor numerical drift. |
| BUG-W136-15 | P2 | G23 | `reschedule_feefilter_soon` uses `Random.float` instead of CSPRNG. |
| BUG-W136-16 | P0-CDIV | G25 | wtxidrelay-send gated on `services.witness`; Core gates only on common-version. |
| BUG-W136-17 | P3 | G27 | no duplicate-wtxidrelay detection / log. |
| BUG-W136-18 | P1 | G29 | no INV-type-mismatch filter on receive; wtxid-relay peer sending MSG_TX is serviced. |
| BUG-W136-19 | P3 | G30 | no `m_wtxid_relay_peers` aggregate counter; no operator visibility. |

Severity breakdown:
- **P0-CDIV**: 3 (G17 IBD MAX_MONEY, G19 MoneyRange, G25 wtxidrelay witness-gate)
- **P1**: 4 (G1, G6, G18, G29)
- **P2**: 5 (G8, G10, G11, G21, G23)
- **P3**: 7 (G2, G12, G15, G16, G22, G27, G30)

Total: **19 BUGs / 30 gates**.

## Top-3 universal patterns surfaced

1. **"protocol-flag receive without value-range validation"** (G19): same
   pattern as W117 BIP-155 BUG-1 (no service-flag range check) and W128
   addrman BUG-3 (no nServices clamp). The MoneyRange check is a
   one-line defensive gate that camlcoin universally omits on
   wire-received numeric fields. PRomote as a fleet-wide audit pattern:
   every `peer.* <- value` of a uint64/int64 deserialised from wire MUST
   verify `value ∈ [0, MAX_MONEY]` (or the field-specific range)
   BEFORE store.

2. **"feature-gate confusion between protocol-version and service-bit"** (G25):
   wtxidrelay is a TRANSPORT feature (protocol-version-gated) but
   camlcoin gates it on the WITNESS service bit. Same shape as the
   recurring "SENDADDRV2 on protocol-version-only" check. Cross-impl
   pattern: every protocol-version-gated feature MUST be gated on
   GetCommonVersion (or its language equivalent), NEVER on service-bit
   advertising; the two are orthogonal axes per BIP-130/133/339.

3. **"IBD-aware send-loop reset for advertised limits"** (G17 + G18):
   camlcoin announces wire-state (feefilter floor, possibly compact-block
   high-bandwidth) without IBD awareness. Pattern: every wire-advertised
   policy floor that exists "to tell the network what we will accept"
   MUST be ceiled-to-rejecting-everything during IBD. Likely fleet
   regression because the IBD-special branch is documented in BIPs but
   not implemented universally.

## Out-of-scope deferrals

- Compact-blocks high-bandwidth (BIP-152) — covered by W112 / W126.
- BIP-152 SENDCMPCT — out of scope; this audit is only feature-flag
  send/recv, not block-encoding.
- ZMQ feefilter exposure — covered by `zmq_notify.ml` test.
- `getpeerinfo` JSON shape — covered by W115 / W124 surface audits.

## Verification methodology

Tests in `test_w136_relay_flags.ml`: 30 alcotest cases (one per gate) +
4 invariant guards. Most BUGs are documented by source-grep over
`peer.ml` / `peer_manager.ml`. Numerical examples (G14 1.33-vs-4/3,
G19 MoneyRange clamp boundary) use Core-canonical reference values.

The audit deliberately does NOT propose fixes — that work belongs to
a downstream FIX-### wave.
