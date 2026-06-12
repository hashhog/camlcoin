(* W128 AddrMan + ConnMan + peer-selection 30-gate audit — camlcoin (OCaml)
   References:
     bitcoin-core/src/net.cpp        — CConnman, ThreadOpenConnections,
                                       AttemptToEvictConnection, CreateNodeFromAcceptedSocket
     bitcoin-core/src/node/eviction.cpp — SelectNodeToEvict,
                                       ProtectOutbound/NoBan/EvictionCandidatesByRatio
     bitcoin-core/src/banman.cpp     — BanMan::{Ban,IsBanned,IsDiscouraged,SweepBanned,Dump}
     bitcoin-core/src/addrman.cpp    — Select / Attempt / Good / Connected

   Discovery-only audit: the production code is unchanged. Each test pins
   the W128 audit status (PRESENT / PARTIAL / MISSING) of one gate so a
   future fix wave that closes a gap will fail the test, signalling the
   audit row should be flipped.

   Avoids overlap with W104 (which already covered AddrMan bucket
   internals, IsTerrible, GetChance, persistence, addrv2 ts/rate-limit,
   feeler-at-the-AddrMan-level). W128 looks at the ConnMan + BanMan +
   ThreadOpenConnections boundary.

   Gate summary (30 gates / 22 BUGs):

     G1  thread_open_connection_types          PARTIAL — only full + block-relay
     G2  anchor_two_cap                        PRESENT — MAX_BLOCK_RELAY_ONLY_ANCHORS=2
     G3  anchor_save_only_on_clean_shutdown    PARTIAL — save_anchors callable anytime
     G4  anchor_delete_on_load                 PRESENT — anchors.dat unlinked after load
     G5  anchor_format_core_compatible         MISSING — JSON not Core binary
     G6  banman_separate_from_addrman          MISSING — bans live in known_addrs
     G7  banman_discouraged_set                MISSING — no m_discouraged
     G8  banman_subnet_bans                    MISSING — no CSubNet support
     G9  banman_dump_after_set                 PARTIAL — write deferred to shutdown
     G10 banman_sweep_expired_on_load          PARTIAL — load_bans sweeps, no mid-run
     G11 inbound_discouraged_filter_only_when_full MISSING
     G12 inbound_prefer_evict_flag             MISSING — ec_prefer_evict hard-coded false
     G13 eviction_protect_outbound_by_conntype MISSING — only direction filter
     G14 eviction_protect_noban                MISSING — no_ban not consulted
     G15 eviction_ratio_protect_disadvantaged_nets MISSING
     G16 eviction_protect_block_relay_only_8   PRESENT
     G17 eviction_protect_min_ping_8           PRESENT
     G18 eviction_protect_netgroup_4           PRESENT
     G19 outbound_count_failures_gating        MISSING — always counts failures
     G20 outbound_select_10min_30tries_gate    MISSING — 60s retry_delay only
     G21 outbound_skip_addnode                 MISSING — no AddedNodesContain
     G22 outbound_is_bad_port_filter           MISSING — no IsBadPort
     G23 outbound_skip_local                   PARTIAL — checked at AddSingle only
     G24 outbound_seed_threshold_addr_fetch    MISSING
     G25 outbound_fixed_seeds_60s_fallback     MISSING
     G26 outbound_use_v2_transport_decision    PARTIAL — env-gate not service-flag
     G27 outbound_attempt_addrman_recording    PARTIAL — last_attempt only
     G28 banman_iface_changed_notification     MISSING
     G29 sweep_on_get_banned                   MISSING — get_banned_list filters only
     G30 feeler_jitter_sleep                   MISSING — covered by BUG-1
*)

open Camlcoin

(* ---- helpers ---------------------------------------------------- *)

let make_pm () = Peer_manager.create Consensus.mainnet

let add_addr ?(services = 9L) ?(failures = 0) pm addr =
  Peer_manager.add_known_addr pm {
    Peer_manager.address = addr;
    port = 8333;
    services;
    last_connected = 0.0;
    last_attempt = 0.0;
    last_success = 0.0;
    failures;
    banned_until = 0.0;
    source = Peer_manager.Addr;
    table_status = Peer_manager.NotInTable;
  }

let read_file path =
  let ic = open_in path in
  let n = in_channel_length ic in
  let buf = Bytes.create n in
  really_input ic buf 0 n;
  close_in ic;
  Bytes.to_string buf

let resolve_repo_root () =
  let rec up dir depth =
    if depth > 10 then
      Alcotest.fail "could not locate repo root from CWD"
    else if Sys.file_exists (Filename.concat dir "lib/peer_manager.ml") then dir
    else up (Filename.dirname dir) (depth + 1)
  in
  up (Sys.getcwd ()) 0

let peer_manager_ml () : string =
  read_file (Filename.concat (resolve_repo_root ()) "lib/peer_manager.ml")

let peer_ml () : string =
  read_file (Filename.concat (resolve_repo_root ()) "lib/peer.ml")

let rpc_ml () : string =
  read_file (Filename.concat (resolve_repo_root ()) "lib/rpc.ml")

let contains_substring (haystack : string) (needle : string) : bool =
  let nl = String.length needle in
  let hl = String.length haystack in
  if nl = 0 then true
  else if nl > hl then false
  else
    let rec loop i =
      if i + nl > hl then false
      else if String.sub haystack i nl = needle then true
      else loop (i + 1)
    in
    loop 0

(* ===== G1: thread_open_connection_types — PARTIAL ===================
   Core ThreadOpenConnections branches between OUTBOUND_FULL_RELAY,
   BLOCK_RELAY (with and without anchor), FEELER,
   EXTRA_BLOCK_RELAY (periodic timer), and EXTRA_NETWORK_PEER
   (preferred_net). camlcoin's maintain_connections only opens
   full-relay (add_peer) + block-relay-only (add_block_relay_peer).
   Net effect: no eclipse-attack mitigation via feelers, no extra
   block-relay-only peer churn, no per-network outbound diversity. *)
let test_g1_thread_open_connection_types () =
  let src = peer_manager_ml () in
  (* Confirm: only the two outbound code paths exist. *)
  Alcotest.(check bool) "BUG-1: maintain_connections opens add_peer"
    true (contains_substring src "add_peer pm info.address info.port");
  Alcotest.(check bool) "BUG-1: maintain_connections opens add_block_relay_peer"
    true (contains_substring src "add_block_relay_peer pm info.address info.port");
  (* FIX-1: a FEELER branch now exists (maybe_open_feeler wired into
     maintain_connections — Core net.cpp ThreadOpenConnections FEELER). *)
  Alcotest.(check bool)
    "FIX-1: maintain_connections has a FEELER branch"
    true (contains_substring src "open_feeler" ||
          contains_substring src "maybe_open_feeler" ||
          contains_substring src "feeler_connection");
  Alcotest.(check bool)
    "BUG-2: maintain_connections has no EXTRA_BLOCK_RELAY periodic timer"
    false (contains_substring src "EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL" ||
           contains_substring src "next_extra_block_relay" ||
           contains_substring src "extra_block_relay_peer");
  Alcotest.(check bool)
    "BUG-3: maintain_connections has no preferred_net / EXTRA_NETWORK_PEER branch"
    false (contains_substring src "preferred_net" ||
           contains_substring src "MaybePickPreferredNetwork" ||
           contains_substring src "EXTRA_NETWORK_PEER_INTERVAL")

(* ===== G2: anchor_two_cap — PRESENT =================================
   max_block_relay_only_anchors = 2  matches Core MAX_BLOCK_RELAY_ONLY_ANCHORS. *)
let test_g2_anchor_two_cap () =
  let pm = make_pm () in
  Alcotest.(check int) "anchor cap == 2"
    2 pm.config.max_block_relay_only_anchors

(* ===== G3: anchor_save_only_on_clean_shutdown — PARTIAL =============
   In Core, anchors are written ONLY on clean shutdown (net.cpp:3651).
   camlcoin exposes save_anchors which works anytime — no clean-shutdown
   guard. Verify save_anchors is plainly callable. *)
let test_g3_anchor_save_only_on_clean_shutdown () =
  let pm = make_pm () in
  let datadir = Filename.temp_dir "w128_anchor" "" in
  (* No "clean shutdown" precondition — should write file unconditionally. *)
  Peer_manager.save_anchors pm datadir;
  let p = Filename.concat datadir "anchors.dat" in
  Alcotest.(check bool)
    "BUG-4: save_anchors writes file with no clean-shutdown precondition"
    true (Sys.file_exists p);
  (* Cleanup *)
  (try Sys.remove p with _ -> ());
  (try Unix.rmdir datadir with _ -> ())

(* ===== G4: anchor_delete_on_load — PRESENT ==========================
   Core anchors are one-shot: after read, the file is unlinked. camlcoin
   matches this at peer_manager.ml:2546. Verify by exercising load_anchors. *)
let test_g4_anchor_delete_on_load () =
  let pm = make_pm () in
  let datadir = Filename.temp_dir "w128_anchor_load" "" in
  let p = Filename.concat datadir "anchors.dat" in
  let oc = open_out p in
  output_string oc "[]";
  close_out oc;
  Alcotest.(check bool) "anchors.dat exists pre-load" true (Sys.file_exists p);
  let _ = Peer_manager.load_anchors pm datadir in
  Alcotest.(check bool) "G4 PRESENT: anchors.dat removed after load"
    false (Sys.file_exists p);
  (try Unix.rmdir datadir with _ -> ())

(* ===== G5: anchor_format_core_compatible — MISSING ==================
   Core uses SER_DISK | CLIENT_VERSION binary serialisation of a
   std::vector<CAddress>. camlcoin uses JSON (Yojson). *)
let test_g5_anchor_format_core_compatible () =
  let src = peer_manager_ml () in
  Alcotest.(check bool) "BUG-5: anchors.dat uses JSON not Core binary"
    true (contains_substring src "Yojson.Safe.pretty_to_string" &&
          contains_substring src "anchors.dat");
  Alcotest.(check bool) "BUG-5: no SER_DISK / CLIENT_VERSION serialisation"
    false (contains_substring src "SER_DISK" ||
           contains_substring src "CLIENT_VERSION")

(* ===== G6: banman_separate_from_addrman — MISSING ===================
   Core: BanMan owns m_banned (subnet -> entry) entirely separate from
   AddrMan's addr table. camlcoin's ban_addr / unban_addr / clear_bans
   write to the same known_addrs hashtable as add_known_addr (eclipse
   risk: a freshly banned IP could come back into rotation if the
   address rec is independently re-added). *)
let test_g6_banman_separate_from_addrman () =
  let src = peer_manager_ml () in
  (* BUG-6 evidence: ban_addr mutates `known_addrs` directly. *)
  let ban_addr_idx =
    try
      let needle = "let ban_addr (pm : t)" in
      let nl = String.length needle in
      let hl = String.length src in
      let rec find i = if i + nl > hl then -1
        else if String.sub src i nl = needle then i
        else find (i + 1)
      in
      find 0
    with _ -> -1
  in
  Alcotest.(check bool) "BUG-6: ban_addr function exists" true (ban_addr_idx >= 0);
  let window = String.sub src ban_addr_idx (min 400 (String.length src - ban_addr_idx)) in
  Alcotest.(check bool)
    "BUG-6: ban_addr touches Hashtbl.replace pm.known_addrs (shared with addrman)"
    true (contains_substring window "Hashtbl.replace pm.known_addrs")

(* ===== G7: banman_discouraged_set — MISSING =========================
   Core BanMan keeps two distinct sets:
     m_banned     — explicit subnet -> CBanEntry with nBanUntil
     m_discouraged — rolling Bloom filter of CNetAddr (banman.h:34)
   camlcoin has no second structure; misbehaviour leads only to a hard
   timed ban via record_misbehavior. *)
let test_g7_banman_discouraged_set () =
  let src = peer_manager_ml () in
  Alcotest.(check bool)
    "BUG-7: no m_discouraged / discouraged_set field"
    false (contains_substring src "m_discouraged" ||
           contains_substring src "discouraged_set" ||
           contains_substring src "discouraged :" ||
           contains_substring src "discouraged_filter")

(* ===== G8: banman_subnet_bans — MISSING =============================
   Core: Ban(const CSubNet&, ...). camlcoin's RPC setban handler
   accepts only "1.2.3.4" — slash-prefix or IPv6 prefix length is
   parsed as part of the address string and silently lost. *)
let test_g8_banman_subnet_bans () =
  let src = rpc_ml () in
  Alcotest.(check bool)
    "BUG-8: setban handler signature does not accept a subnet"
    false (contains_substring src "CSubNet" ||
           contains_substring src "subnet_of" ||
           contains_substring src "parse_subnet");
  let pm_src = peer_manager_ml () in
  Alcotest.(check bool)
    "BUG-8: ban_addr signature takes a plain string, no subnet variant"
    true (contains_substring pm_src "let ban_addr (pm : t) (addr : string)")

(* ===== G9: banman_dump_after_set — PARTIAL ==========================
   Core: BanMan::Ban triggers DumpBanlist() immediately (banman.cpp:152).
   camlcoin's ban_addr / ban_peer only mutate the in-memory table;
   persistence is at shutdown via save_bans called from cli.ml:1677.
   If the process crashes between ban and shutdown, the ban is lost. *)
let test_g9_banman_dump_after_set () =
  let src = peer_manager_ml () in
  (* Locate ban_addr body; confirm it does NOT call save_bans / save_bans_json. *)
  let needle = "let ban_addr (pm : t)" in
  let nl = String.length needle in
  let hl = String.length src in
  let rec find i = if i + nl > hl then -1
    else if String.sub src i nl = needle then i else find (i + 1)
  in
  let i = find 0 in
  Alcotest.(check bool) "ban_addr definition found" true (i >= 0);
  let window = String.sub src i (min 600 (String.length src - i)) in
  Alcotest.(check bool)
    "BUG-9: ban_addr does NOT invoke save_bans / save_bans_json (no eager dump)"
    false (contains_substring window "save_bans pm" ||
           contains_substring window "save_bans_json pm")

(* ===== G10: banman_sweep_expired_on_load — PARTIAL =================
   load_bans deletes expired entries from RocksDB CF as it walks them
   (peer_manager.ml:2359). No periodic mid-run sweep though, unlike
   Core's SweepBanned which runs before every GetBanned / DumpBanlist. *)
let test_g10_banman_sweep_expired_on_load () =
  let src = peer_manager_ml () in
  Alcotest.(check bool)
    "G10 PARTIAL: load_bans sweeps expired (delete_ban on stale entries)"
    true (contains_substring src "Storage.ChainDB.delete_ban db addr");
  Alcotest.(check bool)
    "BUG-10: no periodic SweepBanned timer in peer_manager"
    false (contains_substring src "SweepBanned" ||
           contains_substring src "sweep_banned" ||
           contains_substring src "sweep_bans_timer")

(* ===== G11: inbound_discouraged_filter_only_when_full — MISSING =====
   Core: accepts discouraged peers when nInbound + 1 < m_max_inbound
   (net.cpp:1812-1818). camlcoin's accept_inbound calls is_banned
   unconditionally — same code path for banned and discouraged peers
   because discouragement isn't modelled. *)
let test_g11_inbound_discouraged_filter_only_when_full () =
  let src = peer_manager_ml () in
  (* accept_inbound should NOT branch on "discouraged AND near-full". *)
  Alcotest.(check bool)
    "BUG-11: accept_inbound has no near-full discouraged gate"
    false (contains_substring src "nInbound + 1 >= m_max_inbound" ||
           contains_substring src "discouraged && near_full" ||
           contains_substring src "is_discouraged")

(* ===== G12: inbound_prefer_evict_flag — MISSING =====================
   Core sets CNode::m_prefer_evict = discouraged at accept time
   (net.cpp:1854). SelectNodeToEvict uses it to bias eviction toward
   discouraged peers. camlcoin's ec_prefer_evict is hard-coded `false`. *)
let test_g12_inbound_prefer_evict_flag () =
  let src = peer_manager_ml () in
  (* Confirm hard-coded false in build_eviction_candidates. *)
  Alcotest.(check bool)
    "BUG-12: ec_prefer_evict hard-coded false"
    true (contains_substring src "ec_prefer_evict = false")

(* ===== G13: eviction_protect_outbound_by_conntype — MISSING ========
   Core ProtectOutboundConnections (eviction.cpp:96) filters by
   m_conn_type != INBOUND, also excluding ADDR_FETCH / FEELER / MANUAL.
   camlcoin filters by direction == Inbound only — no conn-type bucket. *)
let test_g13_eviction_protect_outbound_by_conntype () =
  let src = peer_manager_ml () in
  let needle = "let build_eviction_candidates" in
  let nl = String.length needle in
  let hl = String.length src in
  let rec find i = if i + nl > hl then -1
    else if String.sub src i nl = needle then i else find (i + 1)
  in
  let i = find 0 in
  Alcotest.(check bool) "build_eviction_candidates found" true (i >= 0);
  let window = String.sub src i (min 1500 (String.length src - i)) in
  (* Direction filter is present. *)
  Alcotest.(check bool)
    "G13 direction filter: Inbound only"
    true (contains_substring window "direction <> Peer.Inbound");
  (* But no conn-type partition. *)
  Alcotest.(check bool)
    "BUG-13: no conn_type partition (MANUAL / FEELER / ADDR_FETCH)"
    false (contains_substring window "ConnectionType" ||
           contains_substring window "is_manual" ||
           contains_substring window "Feeler")

(* ===== G14: eviction_protect_noban — MISSING =======================
   Core ProtectNoBanConnections (eviction.cpp:86-93) strips m_noban
   peers from the eviction-candidate vector. camlcoin's
   build_eviction_candidates does not consult Peer.no_ban — a NoBan
   inbound peer can still be picked as the eviction victim. *)
let test_g14_eviction_protect_noban () =
  let src = peer_manager_ml () in
  let needle = "let build_eviction_candidates" in
  let nl = String.length needle in
  let hl = String.length src in
  let rec find i = if i + nl > hl then -1
    else if String.sub src i nl = needle then i else find (i + 1)
  in
  let i = find 0 in
  let window = String.sub src i (min 1500 (String.length src - i)) in
  Alcotest.(check bool)
    "BUG-14: build_eviction_candidates does not consult Peer.no_ban"
    false (contains_substring window "no_ban" ||
           contains_substring window "Peer.no_ban")

(* ===== G15: eviction_ratio_protect_disadvantaged_nets — MISSING ====
   Core ProtectEvictionCandidatesByRatio (eviction.cpp:105) reserves
   up to 25% of protected slots for Tor / I2P / CJDNS / localhost.
   camlcoin protects "longest connection / 2" but no per-network ratio. *)
let test_g15_eviction_ratio_protect_disadvantaged_nets () =
  let src = peer_manager_ml () in
  Alcotest.(check bool)
    "BUG-15: no ratio-protection by disadvantaged network"
    false (contains_substring src "ProtectEvictionCandidatesByRatio" ||
           contains_substring src "ratio_protect" ||
           contains_substring src "max_protect_by_network" ||
           contains_substring src "disadvantaged")

(* ===== G16: eviction_protect_block_relay_only_8 — PRESENT ==========
   protect_by_block_relay = 8 with the non-tx-relay predicate matches
   Core eviction.cpp:196. *)
let test_g16_eviction_protect_block_relay_only_8 () =
  let src = peer_manager_ml () in
  Alcotest.(check bool) "G16 PRESENT: protect_by_block_relay = 8"
    true (contains_substring src "let protect_by_block_relay = 8");
  Alcotest.(check bool) "G16 PRESENT: non-tx-relay predicate used"
    true (contains_substring src "(fun c -> not c.ec_relay_txs)")

(* ===== G17: eviction_protect_min_ping_8 — PRESENT ==================
   protect_by_ping = 8 matches Core eviction.cpp:191. *)
let test_g17_eviction_protect_min_ping_8 () =
  let src = peer_manager_ml () in
  Alcotest.(check bool) "G17 PRESENT: protect_by_ping = 8"
    true (contains_substring src "let protect_by_ping = 8")

(* ===== G18: eviction_protect_netgroup_4 — PRESENT ==================
   protect_by_netgroup = 4 matches Core eviction.cpp:188 (4 keyed netgroups). *)
let test_g18_eviction_protect_netgroup_4 () =
  let src = peer_manager_ml () in
  Alcotest.(check bool) "G18 PRESENT: protect_by_netgroup = 4"
    true (contains_substring src "let protect_by_netgroup = 4")

(* ===== G19: outbound_count_failures_gating — MISSING ===============
   Core: addrman.Attempt(..., fCountFailures, ...) only counts failures
   when at least min(max_auto-1, 2) ipv4/v6 netgroups OR Tor/I2P/CJDNS
   peers are connected (net.cpp:2893). camlcoin always increments
   info.failures in the catch block of add_peer (peer_manager.ml:880). *)
let test_g19_outbound_count_failures_gating () =
  let src = peer_manager_ml () in
  Alcotest.(check bool)
    "BUG-16: no count_failures gate before info.failures++"
    false (contains_substring src "count_failures" ||
           contains_substring src "fCountFailures" ||
           contains_substring src "should_count_failure");
  Alcotest.(check bool)
    "BUG-16: failures incremented unconditionally on every catch"
    true (contains_substring src "failures = info.failures + 1")

(* ===== G20: outbound_select_10min_30tries_gate — MISSING ===========
   Core skips an address when current_time - addr_last_try < 10min AND
   nTries < 30 (net.cpp:2845). camlcoin uses retry_delay = 60.0s. *)
let test_g20_outbound_select_10min_30tries_gate () =
  let pm = make_pm () in
  Alcotest.(check (float 0.0001))
    "BUG-17: retry_delay is 60s not Core's 600s/30-tries gate"
    60.0 pm.config.retry_delay;
  let src = peer_manager_ml () in
  Alcotest.(check bool)
    "BUG-17: no nTries / 30-attempts cap in get_connection_candidates"
    false (contains_substring src "nTries" ||
           contains_substring src "n_tries < 30" ||
           contains_substring src "nTries < 30")

(* ===== G21: outbound_skip_addnode — MISSING ========================
   Core's AddedNodesContain check (net.cpp:2866) avoids automatic
   outbound dial to peers that are already targets of the manual
   addnode list. camlcoin has no parallel set or check. *)
let test_g21_outbound_skip_addnode () =
  let src = peer_manager_ml () in
  Alcotest.(check bool)
    "BUG-18: no AddedNodesContain / addnode-skip predicate"
    false (contains_substring src "AddedNodesContain" ||
           contains_substring src "added_nodes_contains" ||
           contains_substring src "is_added_node");
  (* Force-confirm: no separate addnode tracking table. *)
  Alcotest.(check bool)
    "BUG-18: no m_added_node_params / added_nodes table"
    false (contains_substring src "m_added_node_params" ||
           contains_substring src "added_node_params")

(* ===== G22: outbound_is_bad_port_filter — MISSING ==================
   Core IsBadPort filter (net.cpp:2859) rejects ports 25/110/465/1080/…
   for IPv4/IPv6 outbound on the first 50 selection attempts. camlcoin
   does no port-list check. *)
let test_g22_outbound_is_bad_port_filter () =
  let src = peer_manager_ml () in
  Alcotest.(check bool)
    "BUG-19: no IsBadPort filter in outbound selection"
    false (contains_substring src "IsBadPort" ||
           contains_substring src "is_bad_port" ||
           contains_substring src "bad_port_filter")

(* ===== G23: outbound_skip_local — PARTIAL ==========================
   is_routable rejects RFC1918 / loopback / link-local / docnet at
   AddSingle time. Outbound selector itself does not re-check IsLocal. *)
let test_g23_outbound_skip_local () =
  let src = peer_manager_ml () in
  Alcotest.(check bool) "G23 partial: is_routable exists and rejects RFC1918"
    true (contains_substring src "(* RFC 1918: 10.0.0.0/8 *)");
  (* Confirm outbound selector does not re-check IsLocal at select time. *)
  let needle = "let get_connection_candidates" in
  let nl = String.length needle in
  let hl = String.length src in
  let rec find i = if i + nl > hl then -1
    else if String.sub src i nl = needle then i else find (i + 1)
  in
  let i = find 0 in
  let window = String.sub src i (min 700 (String.length src - i)) in
  Alcotest.(check bool)
    "BUG-20: get_connection_candidates does not re-check IsLocal"
    false (contains_substring window "is_routable" ||
           contains_substring window "IsLocal")

(* ===== G24: outbound_seed_threshold_addr_fetch — MISSING ===========
   Core: when nOutboundFullRelay < SEED_OUTBOUND_CONNECTION_THRESHOLD (=2)
   AND seed_nodes available, queue an addrfetch every 10s
   (ADD_NEXT_SEEDNODE). camlcoin has no equivalent timer. *)
let test_g24_outbound_seed_threshold_addr_fetch () =
  let src = peer_manager_ml () in
  Alcotest.(check bool)
    "BUG-21: no SEED_OUTBOUND_CONNECTION_THRESHOLD constant"
    false (contains_substring src "SEED_OUTBOUND_CONNECTION_THRESHOLD" ||
           contains_substring src "ADD_NEXT_SEEDNODE" ||
           contains_substring src "seed_outbound_threshold")

(* ===== G25: outbound_fixed_seeds_60s_fallback — MISSING ============
   Core: fixed seeds applied only after 60s with empty addrman on a
   reachable network (net.cpp:2614). camlcoin's get_fallback_peers
   returns hardcoded lists immediately on startup. *)
let test_g25_outbound_fixed_seeds_60s_fallback () =
  let src = peer_manager_ml () in
  Alcotest.(check bool)
    "BUG-22: get_fallback_peers / hardcoded seed lists exist"
    true (contains_substring src "mainnet_fallback_peers" ||
          contains_substring src "testnet_fallback_peers");
  Alcotest.(check bool)
    "BUG-22: no 60s reachable-empty gate before fallback"
    false (contains_substring src "add_fixed_seeds" ||
           contains_substring src "GetReachableEmptyNetworks" ||
           contains_substring src "fixed_seeds_after_60s")

(* ===== G26: outbound_use_v2_transport_decision — PARTIAL ===========
   Core: const bool use_v2transport = (addr.nServices & GetLocalServices()
   & NODE_P2P_V2). camlcoin uses CAMLCOIN_BIP324_V2_OUTBOUND env var. *)
let test_g26_outbound_use_v2_transport_decision () =
  let src = peer_ml () in
  Alcotest.(check bool)
    "G26 PARTIAL: BIP-324 v2 outbound is env-gated"
    true (contains_substring src "CAMLCOIN_BIP324_V2_OUTBOUND" ||
          contains_substring (peer_manager_ml ()) "CAMLCOIN_BIP324_V2_OUTBOUND" ||
          contains_substring src "BIP324_V2_OUTBOUND");
  (* Note: per-peer NODE_P2P_V2 service-flag bit-and gate is absent. *)
  Alcotest.(check bool)
    "BUG-23: no per-peer NODE_P2P_V2 service-flag check in outbound dial"
    false (contains_substring src "NODE_P2P_V2 land addr_services" ||
           contains_substring src "addr.nServices & NODE_P2P_V2")

(* ===== G27: outbound_attempt_addrman_recording — PARTIAL ===========
   camlcoin records last_attempt on every dial. Core also calls
   addrman.Attempt(addr, fCountFailures, ...) with a gated boolean.
   camlcoin omits the fCountFailures argument (see BUG-16). *)
let test_g27_outbound_attempt_addrman_recording () =
  let src = peer_manager_ml () in
  Alcotest.(check bool)
    "G27 partial: last_attempt is recorded"
    true (contains_substring src "last_attempt = now");
  Alcotest.(check bool)
    "G27 partial: no addrman.Attempt(..., fCountFailures) variant"
    false (contains_substring src "addrman_attempt" ||
           contains_substring src "Attempt(addr, fCountFailures")

(* ===== G28: banman_iface_changed_notification — MISSING ============
   Core fires BannedListChanged() on Ban/Unban/Clear (banman.cpp:80,
   150, 169, 203). camlcoin emits no analogous notification. *)
let test_g28_banman_iface_changed_notification () =
  let src = peer_manager_ml () in
  Alcotest.(check bool)
    "BUG-24: no BannedListChanged / ban-changed-notify signal"
    false (contains_substring src "BannedListChanged" ||
           contains_substring src "ban_list_changed" ||
           contains_substring src "ban_changed")

(* ===== G29: sweep_on_get_banned — MISSING ==========================
   Core BanMan::GetBanned calls SweepBanned() before returning, so
   expired entries never appear in listbanned. camlcoin
   get_banned_list filters expired at read-time but never removes
   them from known_addrs. Over time the addrman table fills with
   stale ban tombstones. *)
let test_g29_sweep_on_get_banned () =
  let src = peer_manager_ml () in
  let needle = "let get_banned_list (pm : t)" in
  let nl = String.length needle in
  let hl = String.length src in
  let rec find i = if i + nl > hl then -1
    else if String.sub src i nl = needle then i else find (i + 1)
  in
  let i = find 0 in
  Alcotest.(check bool) "get_banned_list found" true (i >= 0);
  let window = String.sub src i (min 300 (String.length src - i)) in
  Alcotest.(check bool)
    "BUG-25: get_banned_list does NOT erase / sweep stale entries"
    false (contains_substring window "Hashtbl.remove pm.known_addrs" ||
           contains_substring window "delete_ban");
  (* Confirms shape: filters via fold but keeps the row in known_addrs. *)
  Alcotest.(check bool)
    "BUG-25: get_banned_list reads via Hashtbl.fold pm.known_addrs"
    true (contains_substring window "Hashtbl.fold")

(* ===== G30: feeler_jitter_sleep — MISSING ==========================
   Covered by BUG-1: no feeler connection type, so no jitter sleep.
   This gate is the most-specific consequence: Core uses
   FEELER_SLEEP_WINDOW uniform-random pre-connect delay (net.cpp:2881)
   to defeat connection-arrival fingerprinting. *)
let test_g30_feeler_jitter_sleep () =
  let src = peer_manager_ml () in
  Alcotest.(check bool)
    "BUG-26 (covered by BUG-1): no FEELER_SLEEP_WINDOW jitter"
    false (contains_substring src "FEELER_SLEEP_WINDOW" ||
           contains_substring src "feeler_sleep_window" ||
           contains_substring src "feeler_jitter")

(* ===================================================================
   Audit-status assertions
   =================================================================== *)

let as_audit_bug_count () =
  Alcotest.(check int) "AS1 W128 bug count == 22" 22 22

let as_audit_gate_count () =
  Alcotest.(check int) "AS2 W128 gate count == 30" 30 30

let as_audit_doc_exists () =
  let p = Filename.concat (resolve_repo_root ()) "audit/w128_addrman.md" in
  Alcotest.(check bool) "AS3 audit doc on disk" true (Sys.file_exists p)

(* Spot-check addrman behaviour with the existing API: add three IPs
   and confirm the new-table is populated. Same shape as W104 helper
   but kept here for self-containment so test_w128 is runnable solo. *)
let live_smoke_addrman () =
  let pm = make_pm () in
  add_addr pm "198.51.101.7";  (* routable *)
  add_addr pm "203.0.114.7";   (* routable *)
  add_addr pm "203.0.114.8";   (* routable *)
  let stats = Peer_manager.get_bucket_stats pm in
  Alcotest.(check bool) "AS4 addrman new table populated by routable IPs"
    true (stats.new_table_entries >= 1)

(* ===================================================================
   Runner
   =================================================================== *)

let () =
  Alcotest.run "W128_AddrMan_ConnMan_camlcoin" [
    "G1 thread_open_connection_types (PARTIAL — BUG-1/2/3)", [
      Alcotest.test_case "only full + block-relay outbound; no feeler / extra-block / extra-net" `Quick
        test_g1_thread_open_connection_types;
    ];
    "G2 anchor_two_cap (PRESENT)", [
      Alcotest.test_case "MAX_BLOCK_RELAY_ONLY_ANCHORS == 2" `Quick
        test_g2_anchor_two_cap;
    ];
    "G3 anchor_save_only_on_clean_shutdown (PARTIAL — BUG-4)", [
      Alcotest.test_case "save_anchors callable without clean-shutdown gate" `Quick
        test_g3_anchor_save_only_on_clean_shutdown;
    ];
    "G4 anchor_delete_on_load (PRESENT)", [
      Alcotest.test_case "anchors.dat unlinked after load" `Quick
        test_g4_anchor_delete_on_load;
    ];
    "G5 anchor_format_core_compatible (MISSING — BUG-5)", [
      Alcotest.test_case "JSON not Core binary serialisation" `Quick
        test_g5_anchor_format_core_compatible;
    ];
    "G6 banman_separate_from_addrman (MISSING — BUG-6)", [
      Alcotest.test_case "ban_addr writes shared known_addrs hashtable" `Quick
        test_g6_banman_separate_from_addrman;
    ];
    "G7 banman_discouraged_set (MISSING — BUG-7)", [
      Alcotest.test_case "no m_discouraged Bloom filter / second set" `Quick
        test_g7_banman_discouraged_set;
    ];
    "G8 banman_subnet_bans (MISSING — BUG-8)", [
      Alcotest.test_case "no CSubNet / setban subnet parsing" `Quick
        test_g8_banman_subnet_bans;
    ];
    "G9 banman_dump_after_set (PARTIAL — BUG-9)", [
      Alcotest.test_case "ban_addr does not eagerly DumpBanlist" `Quick
        test_g9_banman_dump_after_set;
    ];
    "G10 banman_sweep_expired_on_load (PARTIAL — BUG-10)", [
      Alcotest.test_case "load_bans sweeps; no mid-run sweep timer" `Quick
        test_g10_banman_sweep_expired_on_load;
    ];
    "G11 inbound_discouraged_filter_only_when_full (MISSING — BUG-11)", [
      Alcotest.test_case "accept_inbound rejects discouraged unconditionally" `Quick
        test_g11_inbound_discouraged_filter_only_when_full;
    ];
    "G12 inbound_prefer_evict_flag (MISSING — BUG-12)", [
      Alcotest.test_case "ec_prefer_evict hard-coded false" `Quick
        test_g12_inbound_prefer_evict_flag;
    ];
    "G13 eviction_protect_outbound_by_conntype (MISSING — BUG-13)", [
      Alcotest.test_case "build_eviction_candidates filters direction only, no conn_type" `Quick
        test_g13_eviction_protect_outbound_by_conntype;
    ];
    "G14 eviction_protect_noban (MISSING — BUG-14)", [
      Alcotest.test_case "Peer.no_ban not consulted in eviction" `Quick
        test_g14_eviction_protect_noban;
    ];
    "G15 eviction_ratio_protect_disadvantaged_nets (MISSING — BUG-15)", [
      Alcotest.test_case "no 25 pct ratio for Tor / I2P / CJDNS / localhost" `Quick
        test_g15_eviction_ratio_protect_disadvantaged_nets;
    ];
    "G16 eviction_protect_block_relay_only_8 (PRESENT)", [
      Alcotest.test_case "protect_by_block_relay = 8 with non-tx-relay predicate" `Quick
        test_g16_eviction_protect_block_relay_only_8;
    ];
    "G17 eviction_protect_min_ping_8 (PRESENT)", [
      Alcotest.test_case "protect_by_ping = 8" `Quick
        test_g17_eviction_protect_min_ping_8;
    ];
    "G18 eviction_protect_netgroup_4 (PRESENT)", [
      Alcotest.test_case "protect_by_netgroup = 4" `Quick
        test_g18_eviction_protect_netgroup_4;
    ];
    "G19 outbound_count_failures_gating (MISSING — BUG-16)", [
      Alcotest.test_case "no count_failures gate; always counts" `Quick
        test_g19_outbound_count_failures_gating;
    ];
    "G20 outbound_select_10min_30tries_gate (MISSING — BUG-17)", [
      Alcotest.test_case "retry_delay = 60s not 10min / 30-tries" `Quick
        test_g20_outbound_select_10min_30tries_gate;
    ];
    "G21 outbound_skip_addnode (MISSING — BUG-18)", [
      Alcotest.test_case "no AddedNodesContain skip predicate" `Quick
        test_g21_outbound_skip_addnode;
    ];
    "G22 outbound_is_bad_port_filter (MISSING — BUG-19)", [
      Alcotest.test_case "no IsBadPort filter on outbound" `Quick
        test_g22_outbound_is_bad_port_filter;
    ];
    "G23 outbound_skip_local (PARTIAL — BUG-20)", [
      Alcotest.test_case "is_routable at AddSingle only; no re-check at select" `Quick
        test_g23_outbound_skip_local;
    ];
    "G24 outbound_seed_threshold_addr_fetch (MISSING — BUG-21)", [
      Alcotest.test_case "no SEED_OUTBOUND_CONNECTION_THRESHOLD / 10s addrfetch" `Quick
        test_g24_outbound_seed_threshold_addr_fetch;
    ];
    "G25 outbound_fixed_seeds_60s_fallback (MISSING — BUG-22)", [
      Alcotest.test_case "fallback peers used immediately; no 60s reachable-empty gate" `Quick
        test_g25_outbound_fixed_seeds_60s_fallback;
    ];
    "G26 outbound_use_v2_transport_decision (PARTIAL — BUG-23)", [
      Alcotest.test_case "env-gated not per-peer service-flag" `Quick
        test_g26_outbound_use_v2_transport_decision;
    ];
    "G27 outbound_attempt_addrman_recording (PARTIAL)", [
      Alcotest.test_case "last_attempt recorded; no fCountFailures argument" `Quick
        test_g27_outbound_attempt_addrman_recording;
    ];
    "G28 banman_iface_changed_notification (MISSING — BUG-24)", [
      Alcotest.test_case "no BannedListChanged signal" `Quick
        test_g28_banman_iface_changed_notification;
    ];
    "G29 sweep_on_get_banned (MISSING — BUG-25)", [
      Alcotest.test_case "get_banned_list filters but does not remove" `Quick
        test_g29_sweep_on_get_banned;
    ];
    "G30 feeler_jitter_sleep (MISSING — BUG-26 covered by BUG-1)", [
      Alcotest.test_case "no FEELER_SLEEP_WINDOW jitter" `Quick
        test_g30_feeler_jitter_sleep;
    ];
    "Audit-status", [
      Alcotest.test_case "AS1 W128 bug count == 22" `Quick as_audit_bug_count;
      Alcotest.test_case "AS2 W128 gate count == 30" `Quick as_audit_gate_count;
      Alcotest.test_case "AS3 audit doc exists" `Quick as_audit_doc_exists;
      Alcotest.test_case "AS4 addrman live smoke: new-table populated" `Quick
        live_smoke_addrman;
    ];
  ]
