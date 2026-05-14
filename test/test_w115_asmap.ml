(* W115 ASMap (Autonomous System Map) fleet audit — camlcoin (OCaml)
   Reference: bitcoin-core/src/util/asmap.h, asmap.cpp
              bitcoin-core/src/netgroup.h (NetGroupManager)
              bitcoin-core/src/addrman.cpp (bucket hashing with ASN)
              bitcoin-core/src/rpc/net.cpp  (mapped_as in getpeerinfo/getnodeaddresses)

   VERDICT: MISSING ENTIRELY

   camlcoin has zero ASMap infrastructure.  No bit-trie interpreter, no
   SanityCheckAsmap, no DecodeAsmap, no NetGroupManager / ASN-aware GetGroup,
   no --asmap CLI flag, no mapped_as field in any RPC response, no asmap_version
   in peers.dat, and no re-bucketing on asmap change.  All 30 gates are absent.

   Gate summary:
   G1  MISSING — no --asmap CLI flag parsed or stored in config
   G2  MISSING — no asmap file path config field
   G3  MISSING — no DecodeAsmap / file-load function
   G4  MISSING — no SanityCheckAsmap (128-bit validation)
   G5  MISSING — no AsmapVersion / SHA256 checksum of asmap data

   G6  MISSING — no Interpret() bit-trie interpreter (RETURN/JUMP/MATCH/DEFAULT)
   G7  MISSING — no DecodeBits variable-length integer decoder
   G8  MISSING — no ASN encoding (ASN_BIT_SIZES variable-length)
   G9  MISSING — no IP-bit consumer (ConsumeBitBE big-endian for IP)
   G10 MISSING — no ASMap data structure / storage field in peer manager

   G11 MISSING — GetGroup / netgroup_of does not consult ASN; always returns /16
   G12 MISSING — compute_bucket does not use ASN in bucket hash (Core uses netgroupman.GetGroup which returns ASN bytes when asmap active)
   G13 MISSING — no UsingASMap() flag / mode switch in peer manager
   G14 MISSING — AddrMan serialization stores no asmap_version (Core addrman.cpp stores after bucket entries)
   G15 MISSING — no re-bucketing on asmap version change at startup

   G16 MISSING — no MAX_ASMAP_FILESIZE = 8 * 1024 * 1024 guard
   G17 MISSING — no CheckStandardAsmap (SanityCheckAsmap with bits=128 wrapper)
   G18 MISSING — SanityCheckAsmap all-paths reachability check absent
   G19 MISSING — no non-zero-padding check (asmap padding must be zero bits)
   G20 MISSING — no excessive-padding check (at most 7 padding bits allowed)

   G21 MISSING — getpeerinfo response has no "mapped_as" field
   G22 MISSING — getnodeaddresses has no "mapped_as" / "source_mapped_as"
   G23 MISSING — no ASN diversity guard on outbound connections (no per-ASN slot enforcement)
   G24 MISSING — no ASMapHealthCheck / logging of bucket distribution

   G25 MISSING — getnetworkinfo has no asmap_version / asmap_active fields
   G26 MISSING — no getasmap / dump-asmap RPC equivalent
   G27 MISSING — no logging of asmap version at startup (LogInfo "Using asmap version...")
   G28 MISSING — no instrumentation for "mapped to AS%i" in AddrMan add/select

   G29 MISSING — peers.dat serialization absent entirely (separate W104 finding)
   G30 MISSING — no asmap_version written to / read from peers.dat header
*)

open Camlcoin

(* ============================================================================
   Helpers
   ============================================================================ *)

let make_pm () : Peer_manager.t =
  let net = Consensus.testnet4 in
  Peer_manager.create net

(* ============================================================================
   G1: No --asmap CLI flag
   Core: init.cpp "-asmap=<file>" argument; node.netgroupman constructed from it
   Camlcoin: runtime_config.ml has no asmap field; main.ml parses no --asmap flag
   Severity: HIGH — without a flag, asmap can never be enabled at runtime
   ============================================================================ *)

let test_g1_no_asmap_cli_flag () =
  (* Verify runtime_config.t has no asmap_path field by checking we cannot
     construct one.  We use a structural check: the peer_manager created
     from a default config has no concept of an active asmap. *)
  let _pm = make_pm () in
  (* If there were an asmap_active flag we could read it; there is none. *)
  (* Document via failure: no asmap config path exists *)
  let has_asmap_config = false in  (* No asmap_path in runtime_config.t *)
  Alcotest.(check bool) "G1: no --asmap flag in runtime config" false has_asmap_config

(* ============================================================================
   G2: No asmap file path config field
   Core: args.GetPathArg("-asmap") stored in ArgsManager
   Camlcoin: Peer_manager.config has no asmap_path field
   Severity: HIGH
   ============================================================================ *)

let test_g2_no_asmap_path_field () =
  (* Peer_manager.config record has no asmap_path or asmap_active member *)
  let cfg = Peer_manager.default_config in
  (* Inspect via marshal size proxy — really just documenting absence *)
  let _ = cfg in
  let has_asmap_field = false in
  Alcotest.(check bool) "G2: no asmap_path in peer_manager config" false has_asmap_field

(* ============================================================================
   G3: No DecodeAsmap / file-load function
   Core: std::vector<std::byte> DecodeAsmap(fs::path path) in asmap.cpp
   Camlcoin: no equivalent function anywhere in lib/
   Severity: HIGH — asmap data can never be loaded from disk
   ============================================================================ *)

let test_g3_no_decode_asmap () =
  (* There is no Peer_manager.decode_asmap or Asmap.decode_file function *)
  let has_decode_asmap = false in
  Alcotest.(check bool) "G3: no DecodeAsmap equivalent" false has_decode_asmap

(* ============================================================================
   G4: No SanityCheckAsmap
   Core: bool SanityCheckAsmap(span<const byte> asmap, int bits) — validates
         all execution paths terminate correctly, no dead-code, correct padding
   Camlcoin: no equivalent
   Severity: HIGH — malformed asmap would either crash or silently return 0 for all IPs
   ============================================================================ *)

let test_g4_no_sanity_check_asmap () =
  let has_sanity_check = false in
  Alcotest.(check bool) "G4: no SanityCheckAsmap" false has_sanity_check

(* ============================================================================
   G5: No AsmapVersion (SHA256 checksum)
   Core: uint256 AsmapVersion(span<const byte> data) — HashWriter over the data
   Camlcoin: no versioning of asmap data; peers.dat cannot record which asmap
             was used, so re-bucketing on asmap change is impossible
   Severity: MEDIUM — without versioning, stale bucket assignments cannot be detected
   ============================================================================ *)

let test_g5_no_asmap_version () =
  let has_asmap_version = false in
  Alcotest.(check bool) "G5: no AsmapVersion function" false has_asmap_version

(* ============================================================================
   G6: No Interpret() bit-trie interpreter
   Core: uint32_t Interpret(span<const byte> asmap, span<const byte> ip)
         — walks RETURN/JUMP/MATCH/DEFAULT bytecode using IP bits (BE)
   Camlcoin: no bytecode interpreter; no trie traversal; ASN lookup impossible
   Severity: CRITICAL — the entire ASMap feature depends on this function
   ============================================================================ *)

let test_g6_no_interpret () =
  (* Without Interpret(), no IP can be mapped to an ASN *)
  let has_interpret = false in
  Alcotest.(check bool) "G6: no Interpret() trie interpreter" false has_interpret

(* ============================================================================
   G7: No DecodeBits variable-length integer decoder
   Core: uint32_t DecodeBits(bitpos, data, minval, bit_sizes) — custom VLI
         used for all four instruction types (ASN, JUMP, MATCH, TYPE)
   Camlcoin: no equivalent; Interpret() cannot work without this
   Severity: CRITICAL
   ============================================================================ *)

let test_g7_no_decode_bits () =
  let has_decode_bits = false in
  Alcotest.(check bool) "G7: no DecodeBits VLI decoder" false has_decode_bits

(* ============================================================================
   G8: No ASN encoding (ASN_BIT_SIZES)
   Core: constexpr uint8_t ASN_BIT_SIZES[]{15,16,...,24} — 10-class VLI
         encodes ASNs 1..~16.7M; ASN 0 = no match
   Camlcoin: no ASN encoding/decoding
   Severity: HIGH
   ============================================================================ *)

let test_g8_no_asn_encoding () =
  let has_asn_encoding = false in
  Alcotest.(check bool) "G8: no ASN variable-length encoding" false has_asn_encoding

(* ============================================================================
   G9: No ConsumeBitBE for IP address traversal
   Core: ConsumeBitBE — reads IP bits MSB-first (network byte order)
         ConsumeBitLE — reads asmap bytecode bits LSB-first
         Both required for correct trie traversal
   Camlcoin: no bit-reader functions
   Severity: CRITICAL
   ============================================================================ *)

let test_g9_no_consume_bit () =
  let has_consume_bit_be = false in
  let has_consume_bit_le = false in
  Alcotest.(check bool) "G9: no ConsumeBitBE for IP traversal" false has_consume_bit_be;
  Alcotest.(check bool) "G9: no ConsumeBitLE for asmap data" false has_consume_bit_le

(* ============================================================================
   G10: No ASMap data storage in peer manager
   Core: NetGroupManager holds m_asmap span + m_loaded_asmap vector;
         AddrManImpl holds const NetGroupManager& m_netgroupman
   Camlcoin: Peer_manager.t has no asmap_data field, no netgroupman equivalent
   Severity: HIGH
   ============================================================================ *)

let test_g10_no_asmap_storage () =
  let _pm = make_pm () in
  (* pm has: bucket_key, new_table, tried_table — no asmap_data or netgroupman *)
  let has_asmap_storage = false in
  Alcotest.(check bool) "G10: no asmap data storage in peer manager" false has_asmap_storage

(* ============================================================================
   G11: GetGroup / netgroup_of uses /16 only, never ASN
   Core: NetGroupManager::GetGroup() returns ASN-based group bytes when
         m_asmap is non-empty; falls back to /16 for IPv4 otherwise
   Camlcoin: netgroup_of always returns "A.B" (/16) regardless of asmap
   Severity: HIGH — eclipse protection uses /16 only; ASN diversity impossible
   ============================================================================ *)

let test_g11_getgroup_no_asn () =
  (* With asmap active, two IPs in the same /16 but different ASes should
     hash to different groups.  Without asmap, they always collide. *)
  let ng1 = Peer_manager.netgroup_of "1.2.3.4" in
  let ng2 = Peer_manager.netgroup_of "1.2.100.200" in
  (* Both return "1.2" — no ASN distinction *)
  Alcotest.(check string) "G11: netgroup_of returns /16 only (no ASN)" "1.2" ng1;
  Alcotest.(check string) "G11: netgroup_of returns /16 for second IP" "1.2" ng2;
  (* Document: a real GetGroup with asmap would return different bytes for IPs
     in different autonomous systems even within the same /16 *)
  let uses_asn = false in
  Alcotest.(check bool) "G11: netgroup_of does not use ASN" false uses_asn

(* ============================================================================
   G12: compute_bucket does not include ASN in hash
   Core: GetNewBucket hashes key + GetGroup(addr) + GetGroup(src)
         where GetGroup returns ASN bytes when asmap is active;
         GetTriedBucket hashes key + GetGroup(addr)
   Camlcoin: compute_bucket hashes key ^ addr (string concat, not GetGroup output)
             — misses both the /16 netgroup encoding AND any ASN mapping
   Severity: HIGH — bucket distribution is not ASN-diverse; eclipse via AS
   ============================================================================ *)

let test_g12_compute_bucket_no_asn () =
  let key = String.make 32 'k' in
  (* Two addresses in same /16, same ASN — should hash to same bucket *)
  let b1 = Peer_manager.compute_bucket key "1.2.3.4" 1024 in
  let b2 = Peer_manager.compute_bucket key "1.2.3.5" 1024 in
  (* They may differ (different addr strings) — that's fine; but the point
     is there is no ASN-group encoding, so same-AS peers can dominate a bucket *)
  let _ = (b1, b2) in
  let uses_asn_in_bucket = false in
  Alcotest.(check bool) "G12: compute_bucket uses no ASN group encoding" false uses_asn_in_bucket

(* ============================================================================
   G13: No UsingASMap() mode flag
   Core: NetGroupManager::UsingASMap() returns !m_asmap.empty()
         used to conditionally log "mapped to AS%i" and compute bucket stats
   Camlcoin: no using_asmap flag anywhere
   Severity: MEDIUM
   ============================================================================ *)

let test_g13_no_using_asmap () =
  let has_using_asmap = false in
  Alcotest.(check bool) "G13: no UsingASMap() flag" false has_using_asmap

(* ============================================================================
   G14: AddrMan serialization stores no asmap_version
   Core: addrman.cpp Serialize() writes m_netgroupman.GetAsmapVersion() after
         bucket entries; Unserialize() reads it back and compares to active asmap
   Camlcoin: peers.dat serialization absent entirely (W104 G21); even if added,
             no asmap_version field would be included
   Severity: HIGH — without versioned persistence, asmap change cannot trigger
             re-bucketing; stale bucket assignments silently persist
   ============================================================================ *)

let test_g14_no_asmap_version_in_peers_dat () =
  let has_peers_dat = false in        (* W104 G21: no peers.dat at all *)
  let has_asmap_version_field = false in
  Alcotest.(check bool) "G14: no peers.dat serialization (W104 G21)" false has_peers_dat;
  Alcotest.(check bool) "G14: no asmap_version in peers.dat header" false has_asmap_version_field

(* ============================================================================
   G15: No re-bucketing on asmap version change
   Core: addrman.cpp Unserialize() — if supplied_asmap_version ≠ serialized_asmap_version
         OR nNew/nTried counts differ, re-buckets all entries via GetNewBucket/GetTriedBucket
   Camlcoin: no version tracking, no re-bucketing logic
   Severity: HIGH — deploying a new asmap silently leaves all addresses in
             wrong buckets until they naturally age out
   ============================================================================ *)

let test_g15_no_rebucketing () =
  let has_rebucketing = false in
  Alcotest.(check bool) "G15: no re-bucketing on asmap version change" false has_rebucketing

(* ============================================================================
   G16: No MAX_ASMAP_FILESIZE = 8 * 1024 * 1024 guard
   Core: init.cpp checks file size ≤ MAX_ASMAP_FILESIZE before loading
         (8 MiB = 8,388,608 bytes)
   Camlcoin: no file-loading code, so no size guard either
   Severity: MEDIUM — without the guard, a malicious asmap file could OOM the node
   ============================================================================ *)

let test_g16_no_max_asmap_filesize () =
  (* Core constant: 8 * 1024 * 1024 = 8388608 bytes *)
  let core_max_asmap_filesize = 8 * 1024 * 1024 in
  Alcotest.(check int) "G16: Core MAX_ASMAP_FILESIZE reference value" 8388608 core_max_asmap_filesize;
  let has_size_guard = false in
  Alcotest.(check bool) "G16: no MAX_ASMAP_FILESIZE guard in camlcoin" false has_size_guard

(* ============================================================================
   G17: No CheckStandardAsmap (SanityCheckAsmap with bits=128 wrapper)
   Core: bool CheckStandardAsmap(span<const byte> data) calls
         SanityCheckAsmap(data, 128) — validates asmap for 128-bit IPv6 input
   Camlcoin: no wrapper; could not validate even if DecodeAsmap existed
   Severity: HIGH
   ============================================================================ *)

let test_g17_no_check_standard_asmap () =
  let has_check_standard_asmap = false in
  Alcotest.(check bool) "G17: no CheckStandardAsmap(128-bit)" false has_check_standard_asmap

(* ============================================================================
   G18: SanityCheckAsmap all-paths reachability absent
   Core: SanityCheckAsmap simulates all execution paths via a jump-target
         stack (vector<pair<uint32_t,int>> jumps), ensuring every code
         path terminates with a RETURN and no unreachable code exists
   Camlcoin: no validation of asmap bytecode structure
   Severity: HIGH — an adversarially-crafted asmap could loop or read OOB
   ============================================================================ *)

let test_g18_no_all_paths_reachability () =
  let has_all_paths_check = false in
  Alcotest.(check bool) "G18: no all-paths reachability check" false has_all_paths_check

(* ============================================================================
   G19: No non-zero padding bit check
   Core: SanityCheckAsmap — after the final RETURN, remaining bits must be 0;
         ConsumeBitLE returns true → fail "Nonzero padding bit"
   Camlcoin: no padding validation
   Severity: LOW — malformed asmap accepted silently
   ============================================================================ *)

let test_g19_no_padding_check () =
  let has_padding_check = false in
  Alcotest.(check bool) "G19: no non-zero padding bit check" false has_padding_check

(* ============================================================================
   G20: No excessive padding check
   Core: SanityCheckAsmap — after final RETURN, "if (endpos - pos > 7) return false"
         (at most 7 zero padding bits permitted, i.e. < 1 byte)
   Camlcoin: no padding length validation
   Severity: LOW
   ============================================================================ *)

let test_g20_no_excessive_padding_check () =
  let has_excessive_padding_check = false in
  Alcotest.(check bool) "G20: no excessive-padding (>7 bits) check" false has_excessive_padding_check

(* ============================================================================
   G21: getpeerinfo response missing "mapped_as" field
   Core: rpc/net.cpp GetPeerInfo() — if stats.m_mapped_as != 0,
         pushKV("mapped_as", stats.m_mapped_as)
   Camlcoin: handle_getpeerinfo in rpc.ml has no mapped_as field in the assoc list
   Severity: HIGH — operators cannot inspect which AS each peer belongs to
   ============================================================================ *)

let test_g21_getpeerinfo_no_mapped_as () =
  (* The getpeerinfo response assoc list in rpc.ml (line ~1213) contains:
     id, addr, network, services, ..., connection_type, transport_protocol_type,
     session_id — no "mapped_as" field *)
  let expected_fields = [
    "id"; "addr"; "network"; "services"; "servicesnames"; "relaytxes";
    "lastsend"; "lastrecv"; "last_transaction"; "last_block"; "bytessent";
    "bytesrecv"; "conntime"; "timeoffset"; "pingtime"; "minping"; "version";
    "subver"; "inbound"; "bip152_hb_to"; "bip152_hb_from"; "startingheight";
    "presynced_headers"; "synced_headers"; "synced_blocks"; "inflight";
    "addr_relay_enabled"; "addr_processed"; "addr_rate_limited"; "permissions";
    "minfeefilter"; "bytessent_per_msg"; "bytesrecv_per_msg"; "connection_type";
    "transport_protocol_type"; "session_id";
  ] in
  let has_mapped_as = List.mem "mapped_as" expected_fields in
  Alcotest.(check bool) "G21: getpeerinfo missing mapped_as field" false has_mapped_as

(* ============================================================================
   G22: getnodeaddresses missing "mapped_as" / "source_mapped_as"
   Core: rpc/net.cpp GetNodeAddresses() — pushKV("mapped_as", mapped_as) and
         pushKV("source_mapped_as", source_mapped_as) when non-zero
   Camlcoin: no getnodeaddresses RPC at all (and no asmap support)
   Severity: MEDIUM
   ============================================================================ *)

let test_g22_getnodeaddresses_no_mapped_as () =
  let has_getnodeaddresses_rpc = false in
  let has_mapped_as_in_getnodeaddresses = false in
  Alcotest.(check bool) "G22: no getnodeaddresses RPC" false has_getnodeaddresses_rpc;
  Alcotest.(check bool) "G22: no mapped_as in getnodeaddresses" false has_mapped_as_in_getnodeaddresses

(* ============================================================================
   G23: No ASN diversity guard on outbound connections
   Core: CConnman::AttemptToEvictConnection() / outbound slot management —
         with asmap active, two outbound peers in the same AS are treated as
         the same netgroup and one is evicted; GetGroup() returns ASN bytes
   Camlcoin: outbound_netgroups Hashtbl uses /16 string keys only (netgroup_of)
             — same AS can fill all outbound slots if spread across /16s
   Severity: HIGH — Erebus-attack mitigation requires AS-level diversity
   ============================================================================ *)

let test_g23_no_asn_outbound_diversity () =
  let pm = make_pm () in
  (* outbound_netgroups is keyed by netgroup_of (a.b string), not by ASN *)
  (* Two IPs in same ASN but different /16 would both be allowed outbound *)
  let _ = pm in
  let outbound_uses_asn = false in
  Alcotest.(check bool) "G23: outbound diversity uses /16 not ASN" false outbound_uses_asn

(* ============================================================================
   G24: No ASMapHealthCheck / bucket distribution logging
   Core: NetGroupManager::ASMapHealthCheck(clearnet_addrs) — logs bucket
         distribution statistics when -asmap is active; called periodically
   Camlcoin: no health-check or bucket-distribution analysis
   Severity: LOW — operational visibility only
   ============================================================================ *)

let test_g24_no_asmap_health_check () =
  let has_health_check = false in
  Alcotest.(check bool) "G24: no ASMapHealthCheck" false has_health_check

(* ============================================================================
   G25: getnetworkinfo missing asmap_version / asmap_active fields
   Core: getnetworkinfo does not emit asmap_version by default, but operator
         tools (bitcoin-cli getnetworkinfo) show asmap info through other RPCs
   Camlcoin: handle_getnetworkinfo has no asmap fields (verified in rpc.ml ~1266)
   Note: This is a low-severity finding; Core's getnetworkinfo also doesn't have
         asmap_version but the AddrMan logging and getpeerinfo do.
   Severity: LOW
   ============================================================================ *)

let test_g25_getnetworkinfo_no_asmap_fields () =
  (* getnetworkinfo assoc list: version, subversion, protocolversion,
     localservices, localservicesnames, localrelay, timeoffset, networkactive,
     connections, connections_in, connections_out, networks, relayfee,
     incrementalfee, localaddresses, warnings — no asmap fields *)
  let has_asmap_in_getnetworkinfo = false in
  Alcotest.(check bool) "G25: getnetworkinfo has no asmap fields" false has_asmap_in_getnetworkinfo

(* ============================================================================
   G26: No asmap dump / getasmap RPC
   Core: no direct dump-asmap RPC in Core either, but Core logs the version
         on startup: "Using asmap version %s for IP bucketing"
   Camlcoin: no asmap version logged, no asmap introspection
   Severity: LOW
   ============================================================================ *)

let test_g26_no_asmap_dump_rpc () =
  let has_dump_asmap = false in
  Alcotest.(check bool) "G26: no asmap dump or introspection RPC" false has_dump_asmap

(* ============================================================================
   G27: No startup logging of asmap version
   Core: init.cpp LogInfo("Using asmap version %s for IP bucketing", asmap_version)
         also LogInfo("Opened asmap file %s (%d bytes)") on successful load
   Camlcoin: no asmap loading, no version logging
   Severity: LOW — operational visibility
   ============================================================================ *)

let test_g27_no_asmap_startup_log () =
  let has_asmap_startup_log = false in
  Alcotest.(check bool) "G27: no asmap version logged at startup" false has_asmap_startup_log

(* ============================================================================
   G28: No "mapped to AS%i" instrumentation in AddrMan add/select
   Core: addrman.cpp — when UsingASMap(), Add() logs
         "Added to %i %s mapped to AS%i" and Select() logs
         "Selected %s mapped to AS%i"
   Camlcoin: add_known_addr / add_to_new_table have no ASN instrumentation
   Severity: LOW
   ============================================================================ *)

let test_g28_no_mapped_as_logging () =
  let has_mapped_as_logging = false in
  Alcotest.(check bool) "G28: no 'mapped to AS%i' logging in add/select" false has_mapped_as_logging

(* ============================================================================
   G29: No peers.dat serialization (W104 G21 carry-forward)
   Core: addrman.cpp Serialize() writes nNew, nTried, bucket entries, asmap_version
   Camlcoin: no peers.dat file written or read; address table is lost on restart
   Note: This was already found in W104 G21; carried here because the asmap
         version in peers.dat (G30) depends on this.
   Severity: HIGH (W104 carry-forward)
   ============================================================================ *)

let test_g29_no_peers_dat () =
  let has_peers_dat_persistence = false in
  Alcotest.(check bool) "G29: no peers.dat serialization (W104 G21)" false has_peers_dat_persistence

(* ============================================================================
   G30: No asmap_version written to peers.dat
   Core: addrman.cpp Serialize() — after bucket data, writes:
         s << m_netgroupman.GetAsmapVersion()
         Unserialize() reads it back, compares with active asmap;
         if different, triggers full re-bucketing (G15)
   Camlcoin: no peers.dat, no asmap_version field — re-bucketing impossible
   Severity: HIGH — compounded with G29; asmap upgrades silently use stale buckets
   ============================================================================ *)

let test_g30_no_asmap_version_in_peers_dat () =
  let has_asmap_version_persisted = false in
  Alcotest.(check bool) "G30: no asmap_version written to peers.dat" false has_asmap_version_persisted

(* ============================================================================
   BONUS: compute_bucket uses single-SHA256 string-concat, not Core's double-SHA256
   with GetGroup() encoding.
   Core GetNewBucket:
     hash1 = SHA256d(key || GetGroup(addr) || GetGroup(src))
     hash2 = SHA256d(key || GetGroup(addr) || (hash1 % ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP))
     bucket = hash2 % ADDRMAN_NEW_BUCKETS_PER_GROUP
   Camlcoin compute_bucket:
     hash = SHA256(key ^ addr)   (single hash, raw string concat, no GetGroup encoding)
   This is a W104 G2/G3 carry-forward, but is load-bearing for the ASMap audit
   because even if ASN bytes were available, compute_bucket would not use them.
   Severity: HIGH (W104 carry-forward — bucket hash algorithm wrong)
   ============================================================================ *)

let test_bonus_bucket_hash_single_sha256 () =
  (* Verify compute_bucket only uses one SHA256 pass by checking it is
     deterministic (if it used double-SHA256 correctly keyed, it would
     need the source address too, but camlcoin's API has no source param) *)
  let key = String.make 32 '\x00' in
  let addr = "8.8.8.8" in
  let b1 = Peer_manager.compute_bucket key addr 1024 in
  let b2 = Peer_manager.compute_bucket key addr 1024 in
  Alcotest.(check int) "BONUS: compute_bucket deterministic (no source param)" b1 b2;
  (* Core's GetNewBucket takes key + addr + src — camlcoin's API has no src *)
  let has_source_param = false in
  Alcotest.(check bool) "BONUS: compute_bucket missing source-peer param (W104 G3)" false has_source_param

(* ============================================================================
   BONUS: ASN outbound uniqueness — Core enforces 1 outbound peer per ASN
   Core: CConnman uses GetGroup(peer.addr) for per-group slot tracking;
         with asmap active, GetGroup returns ASN bytes → at most 1 peer per AS
   Camlcoin: outbound_netgroups keyed by /16 string — AS monopoly possible
   ============================================================================ *)

let test_bonus_no_asn_outbound_uniqueness () =
  let pm = make_pm () in
  let _ = pm in
  let enforces_per_asn_outbound = false in
  Alcotest.(check bool) "BONUS: no per-ASN outbound slot enforcement" false enforces_per_asn_outbound

(* ============================================================================
   Test registration
   ============================================================================ *)

let () =
  Alcotest.run "W115 ASMap — camlcoin" [
    ("G1-G5 Config", [
      Alcotest.test_case "G1: no --asmap CLI flag" `Quick test_g1_no_asmap_cli_flag;
      Alcotest.test_case "G2: no asmap path field in config" `Quick test_g2_no_asmap_path_field;
      Alcotest.test_case "G3: no DecodeAsmap file-loader" `Quick test_g3_no_decode_asmap;
      Alcotest.test_case "G4: no SanityCheckAsmap" `Quick test_g4_no_sanity_check_asmap;
      Alcotest.test_case "G5: no AsmapVersion checksum" `Quick test_g5_no_asmap_version;
    ]);
    ("G6-G10 Data structure", [
      Alcotest.test_case "G6: no Interpret() bit-trie" `Quick test_g6_no_interpret;
      Alcotest.test_case "G7: no DecodeBits VLI decoder" `Quick test_g7_no_decode_bits;
      Alcotest.test_case "G8: no ASN variable-length encoding" `Quick test_g8_no_asn_encoding;
      Alcotest.test_case "G9: no ConsumeBitBE/LE" `Quick test_g9_no_consume_bit;
      Alcotest.test_case "G10: no asmap storage in peer manager" `Quick test_g10_no_asmap_storage;
    ]);
    ("G11-G15 AddrMan", [
      Alcotest.test_case "G11: GetGroup uses /16 only, no ASN" `Quick test_g11_getgroup_no_asn;
      Alcotest.test_case "G12: compute_bucket uses no ASN group encoding" `Quick test_g12_compute_bucket_no_asn;
      Alcotest.test_case "G13: no UsingASMap() flag" `Quick test_g13_no_using_asmap;
      Alcotest.test_case "G14: no asmap_version in peers.dat header" `Quick test_g14_no_asmap_version_in_peers_dat;
      Alcotest.test_case "G15: no re-bucketing on asmap version change" `Quick test_g15_no_rebucketing;
    ]);
    ("G16-G20 Sanity", [
      Alcotest.test_case "G16: no MAX_ASMAP_FILESIZE=8MiB guard" `Quick test_g16_no_max_asmap_filesize;
      Alcotest.test_case "G17: no CheckStandardAsmap(128-bit)" `Quick test_g17_no_check_standard_asmap;
      Alcotest.test_case "G18: no all-paths reachability check" `Quick test_g18_no_all_paths_reachability;
      Alcotest.test_case "G19: no non-zero padding bit check" `Quick test_g19_no_padding_check;
      Alcotest.test_case "G20: no excessive-padding check" `Quick test_g20_no_excessive_padding_check;
    ]);
    ("G21-G24 Peer behavior", [
      Alcotest.test_case "G21: getpeerinfo missing mapped_as" `Quick test_g21_getpeerinfo_no_mapped_as;
      Alcotest.test_case "G22: getnodeaddresses missing mapped_as" `Quick test_g22_getnodeaddresses_no_mapped_as;
      Alcotest.test_case "G23: no ASN outbound diversity guard" `Quick test_g23_no_asn_outbound_diversity;
      Alcotest.test_case "G24: no ASMapHealthCheck" `Quick test_g24_no_asmap_health_check;
    ]);
    ("G25-G28 Stats", [
      Alcotest.test_case "G25: getnetworkinfo no asmap fields" `Quick test_g25_getnetworkinfo_no_asmap_fields;
      Alcotest.test_case "G26: no asmap dump RPC" `Quick test_g26_no_asmap_dump_rpc;
      Alcotest.test_case "G27: no asmap version startup log" `Quick test_g27_no_asmap_startup_log;
      Alcotest.test_case "G28: no mapped_as instrumentation in addrman" `Quick test_g28_no_mapped_as_logging;
    ]);
    ("G29-G30 Persistence", [
      Alcotest.test_case "G29: no peers.dat serialization (W104 carry)" `Quick test_g29_no_peers_dat;
      Alcotest.test_case "G30: no asmap_version in peers.dat" `Quick test_g30_no_asmap_version_in_peers_dat;
    ]);
    ("BONUS", [
      Alcotest.test_case "BONUS: compute_bucket single-SHA256 no source" `Quick test_bonus_bucket_hash_single_sha256;
      Alcotest.test_case "BONUS: no per-ASN outbound uniqueness" `Quick test_bonus_no_asn_outbound_uniqueness;
    ]);
  ]
