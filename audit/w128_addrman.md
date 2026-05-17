# W128 AddrMan + connman + peer selection audit — camlcoin (OCaml)

Discovery-only audit. NO production code changes.

References:
- `bitcoin-core/src/addrman.cpp`, `addrman.h`, `addrman_impl.h`
- `bitcoin-core/src/net.cpp` (`ThreadOpenConnections`, `CreateNodeFromAcceptedSocket`,
  `AttemptToEvictConnection`)
- `bitcoin-core/src/node/eviction.cpp` (`SelectNodeToEvict`,
  `ProtectEvictionCandidatesByRatio`, `ProtectOutboundConnections`,
  `ProtectNoBanConnections`)
- `bitcoin-core/src/banman.cpp` + `banman.h` (`BanMan::Ban`,
  `Discourage`, `IsBanned`, `IsDiscouraged`, `SweepBanned`, `DumpBanlist`)
- `bitcoin-core/src/util/asmap.cpp`

## Scope

This wave is the **second** AddrMan-area audit (W104 covered AddrMan
internals — bucket hash, IsTerrible, GetChance, GetAddr, persistence,
addrv2 timestamp / rate-limit). To avoid duplication W128 focuses on the
**ConnMan + BanMan + outbound-peer-selection** boundary:

- `ThreadOpenConnections`-equivalent loop semantics (anchor/full/
  block-relay/feeler/preferred-net branching)
- Inbound accept path (eviction, discouraged-vs-full, `prefer_evict`)
- BanMan separation from AddrMan (`m_banned` vs `m_discouraged`,
  subnet bans, on-disk format, sweep-on-load)
- Outbound `count_failures` gating, retry timing, `AddedNodesContain`,
  `IsBadPort`, `HasAllDesirableServiceFlags`
- Block-relay-only outbound type (separate from full-relay slot)
- Eviction ratio-protection by disadvantaged network

W104 gates are not re-asserted here. Where a W128 finding is adjacent to
a W104 finding, the audit text says so explicitly.

## Files inspected

- `lib/peer_manager.ml` (2777 lines) — known_addrs, ban table, anchors,
  eviction algo, ThreadOpen-equivalent (`maintain_connections`),
  `get_connection_candidates`, `add_peer` / `force_add_peer` /
  `add_block_relay_peer`, `evict_inbound_peer`, `ban_peer` / `ban_addr`
- `lib/peer.ml` (2066 lines) — peer struct, `no_ban`, `is_manual`,
  `is_addr_local`, `record_misbehavior`
- `lib/p2p.ml` (3734 lines) — wire protocol & proxy plumbing
- `lib/rpc.ml` (relevant handlers: `getpeerinfo`, `listbanned`,
  `setban`, `clearbanned`, `addnode`, `disconnectnode`)
- `lib/cli.ml` — `save_bans` / `load_bans` boot hooks

## 30-gate audit matrix

Severity legend:
- **P0** — eclipse / partition exposure or silent DoS
- **P1** — Core-divergent peer-selection behaviour, observable from peers
- **P2** — robustness / persistence / RPC-shape; not silently exploitable
- **P3** — cosmetic / API-shape only

| # | Gate                                       | Status   | Severity | Notes |
|--:|--------------------------------------------|----------|----------|-------|
| G1  | thread_open_connection_types               | PARTIAL  | P1       | `maintain_connections` only opens full-relay + block-relay-only; no FEELER / EXTRA_BLOCK_RELAY / EXTRA_NETWORK_PEER branches (Core net.cpp:2705-2771). See BUG-1, BUG-2, BUG-3. |
| G2  | anchor_two_cap                             | PRESENT  | —        | `max_block_relay_only_anchors = 2` matches Core `MAX_BLOCK_RELAY_ONLY_ANCHORS`. peer_manager.ml:66. |
| G3  | anchor_save_only_on_clean_shutdown         | PARTIAL  | P2       | `save_anchors` is callable any time; Core only dumps anchors on clean shutdown (net.cpp:3651). camlcoin will overwrite on every save. BUG-4. |
| G4  | anchor_delete_on_load                      | PRESENT  | —        | `load_anchors` unlinks the file after read (peer_manager.ml:2546), matching Core's one-shot semantics. |
| G5  | anchor_format_core_compatible              | MISSING  | P2       | Anchors stored as Yojson `anchors.dat`, not Core's binary `SER_DISK | CLIENT_VERSION` `CAddress` vector (net.cpp:3495). Non-interop with `bitcoin-cli`-managed datadirs. BUG-5. |
| G6  | banman_separate_from_addrman               | MISSING  | P1       | Bans live inside the unified `known_addrs` table (peer_manager.ml:1058-1088). Core keeps `BanMan::m_banned` (subnet→entry) separate from `AddrMan` (banman.h:90). BUG-6. |
| G7  | banman_discouraged_set                     | MISSING  | P0       | No `m_discouraged` ring-buffer / set. Discouraged != banned in Core (banman.cpp:83-87; banman.h:34: "rolling Bloom filter"). camlcoin treats every misbehaving peer as a hard ban. BUG-7. |
| G8  | banman_subnet_bans                         | MISSING  | P1       | `ban_addr` accepts only single IP strings; no `CSubNet` analog. `setban` "1.2.3.0/24" silently fails or treats "/24" as part of the string. BUG-8. |
| G9  | banman_dump_after_set                      | PARTIAL  | P2       | `Ban` in Core triggers `DumpBanlist()` (banman.cpp:152). camlcoin's `ban_addr` / `ban_peer` write to `known_addrs` only — disk write deferred to shutdown via `save_bans`. BUG-9. |
| G10 | banman_sweep_expired_on_load               | PARTIAL  | P2       | `load_bans` skips entries `banned_until <= now` and deletes them from the CF — partially matches Core `SweepBanned`. No periodic mid-run sweep though; Core sweeps before each `GetBanned` call. BUG-10. |
| G11 | inbound_discouraged_filter_only_when_full  | MISSING  | P0       | Core only drops discouraged inbound when `nInbound + 1 >= m_max_inbound` (net.cpp:1814), letting a healthy node still accept them otherwise. camlcoin uses one flag `banned_until` for both, so discouraged peers are *always* rejected. BUG-11. |
| G12 | inbound_prefer_evict_flag                  | MISSING  | P0       | `CNode::m_prefer_evict` is set to `discouraged` at accept time (net.cpp:1854) and consumed by `SelectNodeToEvict` (eviction.cpp:212). camlcoin's `eviction_candidate.ec_prefer_evict` is hard-coded `false` (peer_manager.ml:567). BUG-12. |
| G13 | eviction_protect_outbound                  | MISSING  | P1       | `ProtectOutboundConnections` (eviction.cpp:96) strips all non-INBOUND candidates before selection. camlcoin filters inbound at `build_eviction_candidates` (peer_manager.ml:543) — direction-equivalent, but no manual / addnode / feeler protection: a manually-added outbound peer wrongly counted as inbound would still be evicted. Partial via the direction filter; full Core `m_conn_type` partition absent. BUG-13. |
| G14 | eviction_protect_noban                     | MISSING  | P1       | `ProtectNoBanConnections` (eviction.cpp:86-93) strips `m_noban` peers from candidates. camlcoin: `Peer.no_ban` exists but `build_eviction_candidates` does **not** filter by it; a `NoBan`-permissioned inbound can still be evicted. BUG-14. |
| G15 | eviction_ratio_protect_disadvantaged_nets  | MISSING  | P1       | `ProtectEvictionCandidatesByRatio` (eviction.cpp:105) reserves up to 25% of protected slots for Tor / I2P / CJDNS / localhost. camlcoin uses a plain "protect oldest half" + netgroup-most cluster — no per-network ratio reservation. Eclipse-via-IPv4-flood becomes cheaper. BUG-15. |
| G16 | eviction_protect_block_relay_only_8        | PRESENT  | —        | `erase_last_k_elements protect_by_block_relay 8` with `(fun c -> not c.ec_relay_txs)` mirrors Core eviction.cpp:196. peer_manager.ml:621-623. |
| G17 | eviction_protect_min_ping_8                | PRESENT  | —        | `protect_by_ping = 8` with reverse-sort by `ec_min_ping` matches Core eviction.cpp:191. peer_manager.ml:607-611. |
| G18 | eviction_protect_netgroup_4                | PRESENT  | —        | `protect_by_netgroup = 4` with keyed-netgroup sort matches Core eviction.cpp:188. peer_manager.ml:600-605. |
| G19 | outbound_count_failures_gating             | MISSING  | P1       | Core only counts a failed connection toward `addrman.Attempt` when `(outbound_ipv46_peer_netgroups.size + privacy_peers) >= min(max_auto-1, 2)` (net.cpp:2893). camlcoin always increments `info.failures` on every catch-block (peer_manager.ml:880). Offline nodes will burn through `max_failures=5` on every known address before noticing. BUG-16. |
| G20 | outbound_select_10min_30tries_gate         | MISSING  | P1       | Core skips an address when `current_time - addr_last_try < 10min` AND `nTries < 30` (net.cpp:2845). camlcoin's `get_connection_candidates` uses a single `retry_delay = 60.0s` cap (peer_manager.ml:1325), much shorter than Core's 10-minute floor. BUG-17. |
| G21 | outbound_skip_addnode                      | MISSING  | P1       | Core's `AddedNodesContain(addr)` skip (net.cpp:2866) prevents automatic outbound slot usage on addnode-targeted peers. camlcoin has no parallel set — same peer can occupy both the addnode slot and an automatic outbound slot. BUG-18. |
| G22 | outbound_is_bad_port_filter                | MISSING  | P1       | Core rejects `IsBadPort(addr.GetPort())` for IPv4/IPv6 within first 50 tries (net.cpp:2859; chainparamsbase.cpp BAD_PORTS list 25, 110, 465, 1080…). camlcoin does no port check on outbound. BUG-19. |
| G23 | outbound_skip_local                        | PARTIAL  | P2       | Core `IsLocal(addr)` skip (net.cpp:2836); camlcoin has `Peer.is_addr_local` and `is_routable` (peer_manager.ml:350) but **only** rejects RFC1918/loopback at AddSingle time; the outbound selector itself does not re-check `IsLocal`. If a routable address were demoted to local later, no re-check. BUG-20. |
| G24 | outbound_seed_threshold_addr_fetch         | MISSING  | P2       | Core: when `nOutboundFullRelay < SEED_OUTBOUND_CONNECTION_THRESHOLD` (=2) AND seed_nodes given, queue an `addrfetch` every 10s (net.cpp:2696). camlcoin has no `ADD_NEXT_SEEDNODE` timer; once `dns_seeds` resolve, no further seed-node addrfetch. BUG-21. |
| G25 | outbound_fixed_seeds_60s_fallback          | MISSING  | P1       | Core falls back to baked-in fixed seeds only after **60s** of empty AddrMan on a reachable network (net.cpp:2614). camlcoin's `mainnet_fallback_peers` / `testnet_fallback_peers` are used directly with no 60-second backoff and no reachable-network gate. BUG-22. |
| G26 | outbound_use_v2_transport_decision         | PARTIAL  | P2       | `Peer.connect_outbound_negotiated` consumes `CAMLCOIN_BIP324_V2_OUTBOUND` env var (peer.ml). Core uses `addr.nServices & GetLocalServices() & NODE_P2P_V2` (net.cpp:2895). camlcoin's gate is operator-only, not per-peer service-flag based, so a peer advertising NODE_P2P_V2 can still be downgraded to v1. BUG-23. |
| G27 | outbound_attempt_addrman_recording         | PARTIAL  | P1       | camlcoin updates `info.last_attempt` (peer_manager.ml:806). Core also calls `addrman.Attempt(addr, fCountFailures, ...)` with the count-failures gate (net.cpp:2896 → OpenNetworkConnection → addrman.Attempt). camlcoin omits `count_failures` boolean entirely — see BUG-16. |
| G28 | banman_iface_changed_notification          | MISSING  | P3       | Core fires `BannedListChanged()` UI signal on every Ban/Unban/Clear/Sweep with `notify_ui = true` (banman.cpp:80, 150, 169, 203). camlcoin emits no such signal — no `BannedListChanged` RPC notification surface. BUG-24. |
| G29 | sweep_on_get_banned                        | MISSING  | P2       | `BanMan::GetBanned` calls `SweepBanned()` so expired entries never appear in `listbanned` (banman.cpp:174-180). camlcoin `get_banned_list` filters at read-time but never removes the expired entries from `known_addrs` — they continue to occupy the address slot. BUG-25. |
| G30 | feeler_jitter_sleep                        | MISSING  | P2       | Core sleeps a uniform random duration in `FEELER_SLEEP_WINDOW` (net.cpp:2881) before opening a feeler, to defeat connection-arrival fingerprinting. camlcoin has no feeler connection at all (BUG-1), so no jitter. BUG-26 (covered by BUG-1 closure). |

## Bug catalogue

P0 (eclipse / partition) — 4:
- **BUG-7** banman_discouraged_set missing
- **BUG-11** discouraged peers always rejected (no near-full gate)
- **BUG-12** prefer_evict flag absent
- **BUG-15** eviction ratio-protect for disadvantaged nets missing

P1 (Core-divergent peer selection / DoS) — 13:
- **BUG-1** No FEELER connection type
- **BUG-2** No EXTRA_BLOCK_RELAY periodic peer
- **BUG-3** No EXTRA_NETWORK_PEER / preferred_net branch
- **BUG-6** Bans co-mingled with addrman in `known_addrs`
- **BUG-8** No subnet ban support
- **BUG-13** Outbound / addnode peers not partitioned out of eviction by conn_type
- **BUG-14** `NoBan` permission not consulted in eviction
- **BUG-16** count_failures gate missing (always counts)
- **BUG-17** 10-minute / 30-try selector gate replaced with 60s `retry_delay`
- **BUG-18** No AddedNodesContain skip
- **BUG-19** No IsBadPort filter
- **BUG-22** Fixed seeds applied immediately, no 60s reachable-empty gate
- **BUG-23** v2-transport decision based on env, not peer service flag

P2 — 8:
- **BUG-4** save_anchors callable any time (Core: only on clean shutdown)
- **BUG-5** anchors.dat is JSON, not Core's binary format
- **BUG-9** ban set does not eagerly DumpBanlist (lost across crash)
- **BUG-10** No periodic mid-run ban sweep
- **BUG-20** Outbound selector doesn't re-check IsLocal
- **BUG-21** No SEED_OUTBOUND_CONNECTION_THRESHOLD / 10s addrfetch timer
- **BUG-25** GetBanned does not sweep before returning
- **BUG-26** (covered by BUG-1)

P3 — 1:
- **BUG-24** No `BannedListChanged` notification surface

Total: **22 bugs** across 30 gates.

## Universal patterns observed

1. **"audit-spec uses prose, code uses two-tier"** — Core's discouraged
   set is a separate Bloom filter; camlcoin folds it into the ban
   timestamp. Same shape as the W125 audit's "all wallet errors route
   to -4" pattern (PARTIAL via collapse-to-single-tier).
2. **"missing concurrency gate"** — count_failures, IsBadPort, 10min/30
   tries, AddedNodesContain are each independent gates in Core's
   selector loop. camlcoin's `get_connection_candidates` flattens them
   into one filter; this is the same "missing-gate-set" pattern W104
   surfaced for the AddrMan `GetChance` / `IsTerrible` gates.
3. **"feature-not-implemented vs implemented-wrong"** — FEELER /
   EXTRA_BLOCK_RELAY / EXTRA_NETWORK_PEER / preferred_net are entire
   connection types missing, not just buggy. The audit treats these as
   PARTIAL (not MISSING) because outbound _does_ open full-relay and
   block-relay-only — just not the 4 specialised types.

## Out of scope for this wave

- BIP-155 message encoding (W117 closed this for camlcoin in FIX-58).
- AddrMan bucket hashing, IsTerrible, GetChance (W104 covered these).
- BIP-324 cipher negotiation internals (FIX-58 / FIX-64 territory).
- Source-level FIX-74 / FIX-78 BIP-157 disconnect guards in
  `test_w121_compact_filters.ml` (this audit does not touch cli.ml).

## Verdict

22 bugs / 30 gates. No production code change in this audit — the test
file `test/test_w128_addrman.ml` pins each gate's status so future fix
waves can drop them off the matrix one at a time without regressing
the others.
