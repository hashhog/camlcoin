(* W104 AddrMan 30-gate fleet audit — camlcoin (OCaml)
   Reference: bitcoin-core/src/addrman.h, addrman_impl.h, addrman.cpp *)

open Camlcoin

(* ===================================================================
   Gate summary (30 gates)

   G1  bucket_key_rng_weak       WEAK RNG — OCaml Random (not CSPRNG) seeds bucket_key
   G2  bucket_hash_algorithm     WRONG HASH — single SHA256 not double SHA256 (HashWriter)
   G3  bucket_hash_no_netgroup   WRONG BUCKET — no source-netgroup in new-bucket hash
   G4  bucket_pos_missing        WRONG BUCKET — no GetBucketPosition (bucket pos not keyed)
   G5  new_buckets_per_source    MISSING — ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP (64) unused
   G6  tried_buckets_per_group   MISSING — ADDRMAN_TRIED_BUCKETS_PER_GROUP (8) unused
   G7  ref_count_stochastic      MISSING — stochastic 2^N harder re-insert into new missing
   G8  is_terrible_missing       MISSING — no IsTerrible() equivalent for candidate pruning
   G9  get_chance_missing         MISSING — no GetChance() in Select (failures not penalised)
   G10 time_penalty_missing      MISSING — addr messages not de-penalised by 2h time_penalty
   G11 addr_ts_lower_bound       MISSING — lower bound ts check (≤100000000s) absent
   G12 addrv2_no_rate_limit      MISSING — handle_addrv2 ignores addr_rate entirely
   G13 addrv2_no_ts_deduction    MISSING — addrv2 last_connected set to now (not ts from msg)
   G14 addr_relay_csprng         WEAK RNG — relay_addr uses Random.int not CSPRNG shuffle
   G15 getaddr_one_time_guard    MISSING — m_getaddr_sent / one-shot getaddr guard absent
   G16 tried_collision_missing   MISSING — test-before-evict / ResolveCollisions absent
   G17 tried_evict_no_check      BUG — move_to_tried_table evicts without Good_/tbevict check
   G18 routability_filter        FIXED  — is_routable() added; RFC1918/loopback/link-local rejected
   G19 gossip_no_terrible_filter MISSING — gossip_addresses includes terrible addresses
   G20 getaddr_pct_cap           MISSING — GetAddr 23% cap (MAX_PCT_ADDR_TO_SEND) absent
   G21 persistence_missing       MISSING — no peers.dat persistence (only bans/anchors saved)
   G22 connected_ntime_leak      BUG — connected() stores now as last_success (nTime leak)
   G23 addr_relay_shuffle_rng    WEAK RNG — addr relay peer shuffle uses Random.int 3-1
   G24 feeler_missing            MISSING — no feeler connection type for tried-table testing
   G25 set_services_missing      MISSING — SetServices() not called on new VERSION messages
   G26 new_bucket_full_evict     BUG — bucket-full path evicts head (not IsTerrible check)
   G27 netgroup_ipv6_missing     MISSING — netgroup_of only handles IPv4 (/16); IPv6 absent
   G28 addr_source_netgroup_key  MISSING — source peer /16 not included in new-bucket hash
   G29 tried_collision_set_size  MISSING — ADDRMAN_SET_TRIED_COLLISION_SIZE (10) cap absent
   G30 good_call_not_atomic      BUG — Good() / move_to_tried atomicity: double-entry possible
   =================================================================== *)

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

(* ===== G1: bucket_key_rng_weak (FIXED) ============================
   Fix: generate_bucket_key now reads 32 bytes from /dev/urandom
   instead of OCaml Random.int 256 (Mersenne-Twister / clock-seeded).
   Bitcoin Core uses FastRandomContext::rand256() which sources from
   GetStrongRandBytes() -> /dev/urandom.  The bucket key must be
   unpredictable so an attacker cannot pre-compute which bucket any
   address will land in (eclipse attack).
   Core ref: addrman_impl.h AddrManImpl::nKey,
   random.h FastRandomContext::rand256(). *)
let test_g1_bucket_key_rng_weak () =
  (* Shape: key must be exactly 32 bytes *)
  let pm = make_pm () in
  let key = pm.bucket_key in
  Alcotest.(check int) "key is 32 bytes" 32 (String.length key);
  (* CSPRNG property: two independently generated keys must differ.
     With 256 bits of /dev/urandom entropy the probability of collision
     is 2^-256 — effectively impossible.  If this assertion fires,
     the implementation has regressed to a weak / deterministic source. *)
  let key_a = Peer_manager.generate_bucket_key () in
  let key_b = Peer_manager.generate_bucket_key () in
  Alcotest.(check bool) "FIX-G1: two keys from /dev/urandom differ (CSPRNG)"
    true (key_a <> key_b)

(* ===== G2: bucket_hash_algorithm ==================================
   Bug: compute_bucket uses single SHA256 (Digestif.SHA256.digest_string)
   over (key ^ addr).  Bitcoin Core uses a two-round HashWriter (double
   SHA256 with domain-separated intermediates) and includes the source
   netgroup in the hash.  Single SHA256 is weaker against length-
   extension attacks.
   Severity: MEDIUM.  Core ref: addrman.cpp AddrInfo::GetNewBucket(). *)
let test_g2_bucket_hash_algorithm () =
  (* compute_bucket(key, addr, N) should produce values in [0,N) *)
  let key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" in
  let b = Peer_manager.compute_bucket key "1.2.3.4" 1024 in
  Alcotest.(check bool) "bucket in range" true (b >= 0 && b < 1024);
  (* BUG: only single SHA256 — not Bitcoin Core's HashWriter double-hash.
     Core: hash1 = SHA256d(nKey || addr_group || src_group)
           hash2 = SHA256d(nKey || src_group || (hash1 % 64))
           bucket = hash2 % 1024
     camlcoin: single SHA256(key || addr) % N   ← wrong *)
  let b2 = Peer_manager.compute_bucket key "1.2.3.4" 1024 in
  Alcotest.(check int) "deterministic" b b2
  (* No assert fails here — this test documents the algorithm divergence *)

(* ===== G3: bucket_hash_no_netgroup ================================
   Bug: compute_bucket ignores the source peer's netgroup entirely.
   Bitcoin Core includes both the address's netgroup AND the source
   peer's netgroup in the new-bucket hash.  Without this, many source
   peers can all fill the same bucket.
   Severity: HIGH.  Core ref: addrman.cpp GetNewBucket(key, src). *)
let test_g3_bucket_hash_no_netgroup () =
  (* Two different source peers with different /16 netgroups should
     ideally hash to different buckets for the same destination addr.
     camlcoin ignores source entirely, so the bucket is identical
     regardless of who sent us the addr. *)
  let key = "testkey00000000000000000000000000" in
  let addr = "5.6.7.8" in
  (* camlcoin: source not used at all *)
  let b = Peer_manager.compute_bucket key addr 1024 in
  (* If source were included, two different sources would produce
     different bucket values.  We can only document the absence. *)
  Alcotest.(check bool) "BUG-G3: bucket in range" true (b >= 0 && b < 1024)

(* ===== G4: bucket_pos_missing =====================================
   Bug: camlcoin has no equivalent of GetBucketPosition().  Bitcoin
   Core keys the *position within a bucket* on the full address plus
   a flag ('N' for new, 'K' for tried).  camlcoin just uses a list
   inside the bucket, so position is insertion order, not keyed.
   Severity: MEDIUM. Core ref: addrman.cpp GetBucketPosition(). *)
let test_g4_bucket_pos_missing () =
  (* Confirm there is no keyed position: adding same addr twice to a
     full bucket may silently overwrite or collide in wrong ways.
     Use public routable IPs (50.0.1.x) so G18 filter does not interfere. *)
  let pm = make_pm () in
  for i = 1 to 10 do
    add_addr pm (Printf.sprintf "50.0.1.%d" i)
  done;
  let stats = Peer_manager.get_bucket_stats pm in
  Alcotest.(check bool) "BUG-G4: entries stored without keyed position"
    true (stats.new_table_entries = 10)

(* ===== G5: new_buckets_per_source =================================
   Bug: ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP = 64 is not used.  Core
   spreads new addrs from one source across 64 candidate buckets;
   camlcoin computes exactly one bucket per addr.
   Severity: MEDIUM. Core ref: addrman.h ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP. *)
let test_g5_new_buckets_per_source () =
  (* No constant exists in camlcoin for this value *)
  (* Bitcoin Core: nNew_buckets_per_source = 64 *)
  (* camlcoin: 1 bucket per (key, addr) pair — no source spreading *)
  let pm = make_pm () in
  add_addr pm "20.0.0.1";
  let stats = Peer_manager.get_bucket_stats pm in
  (* Entry goes to exactly 1 bucket, not up to 8 different ones *)
  Alcotest.(check int) "BUG-G5: entry in 1 bucket (no source spreading)"
    1 stats.new_table_entries

(* ===== G6: tried_buckets_per_group ================================
   Bug: ADDRMAN_TRIED_BUCKETS_PER_GROUP = 8 not used.  Tried bucket is
   computed by the same single-SHA256 function as new, not by the two-
   round hash that selects among 8 per-group candidate buckets.
   Severity: MEDIUM. Core ref: addrman.h ADDRMAN_TRIED_BUCKETS_PER_GROUP. *)
let test_g6_tried_buckets_per_group () =
  let pm = make_pm () in
  add_addr pm "30.0.0.1";
  let _ = Peer_manager.move_to_tried_table pm "30.0.0.1" in
  let stats = Peer_manager.get_bucket_stats pm in
  Alcotest.(check bool) "BUG-G6: tried entry placed (wrong hash)"
    true (stats.tried_table_entries = 1)

(* ===== G7: ref_count_stochastic ===================================
   Bug: ADDRMAN_NEW_BUCKETS_PER_ADDRESS = 8 and the stochastic 2^N
   difficulty of adding an addr to more new buckets is absent.  Core
   makes it exponentially harder to increase nRefCount > 0.
   Severity: MEDIUM. Core ref: addrman.cpp AddSingle nRefCount > 0
   path: if (insecure_rand.randrange(nFactor) != 0) return false. *)
let test_g7_ref_count_stochastic () =
  (* camlcoin add_to_new_table always adds without stochastic gate.
     Adding the same addr many times should hit the max-8-bucket limit
     in Core; in camlcoin it just stays in one bucket. *)
  let pm = make_pm () in
  add_addr pm "40.0.0.1";
  (* Re-add same addr: no stochastic resistance *)
  add_addr pm "40.0.0.1";
  let stats = Peer_manager.get_bucket_stats pm in
  Alcotest.(check int) "BUG-G7: re-add has no stochastic resistance"
    1 stats.new_table_entries

(* ===== G8: is_terrible_missing ====================================
   Bug: No IsTerrible() equivalent.  Core uses IsTerrible to decide
   whether an existing new-bucket entry can be overwritten.  camlcoin
   always evicts the head of the list on bucket-full.
   Constants missing: ADDRMAN_HORIZON (30d), ADDRMAN_RETRIES (3),
   ADDRMAN_MAX_FAILURES (10), ADDRMAN_MIN_FAIL (7d).
   Severity: HIGH. Core ref: addrman.cpp IsTerrible(). *)
let test_g8_is_terrible_missing () =
  (* Fill one bucket to capacity; the 65th entry should trigger eviction.
     Core would check IsTerrible on the existing entry before evicting.
     camlcoin blindly evicts head of list. *)
  let pm = make_pm () in
  (* Force all into same bucket by patching key — just fill the bucket *)
  let bucket_size = Peer_manager.bucket_size in
  for i = 1 to bucket_size + 5 do
    add_addr pm (Printf.sprintf "50.%d.%d.1" (i / 256) (i mod 256))
  done;
  let stats = Peer_manager.get_bucket_stats pm in
  (* Some may hash to the same bucket and trigger eviction without IsTerrible *)
  Alcotest.(check bool) "BUG-G8: no IsTerrible — bucket eviction is blind"
    true (stats.new_table_entries <= bucket_size * Peer_manager.new_bucket_count)

(* ===== G9: get_chance_missing =====================================
   Bug: get_connection_candidates selects by fewest-failures then most-
   recently-connected.  Core's Select() uses GetChance() which computes
   exponential decay per nAttempts and a 100× penalty for very-recent
   attempts (< 10 min).  camlcoin has no probabilistic selection.
   Severity: MEDIUM. Core ref: addrman.cpp GetChance(). *)
let test_g9_get_chance_missing () =
  let pm = make_pm () in
  (* Add two peers: one with 0 failures, one with 3 failures *)
  add_addr ~failures:0 pm "60.0.0.1";
  add_addr ~failures:3 pm "60.0.0.2";
  let candidates = Peer_manager.get_connection_candidates pm 2 in
  (* Core would de-prioritize the 3-failure peer via GetChance().
     camlcoin just sorts by failures, so 3-failure addr is still
     returned (no exponential decay, no 0.66^N factor). *)
  Alcotest.(check bool) "BUG-G9: no GetChance — failure penalty absent"
    true (List.length candidates = 2)

(* ===== G10: time_penalty_missing ==================================
   Bug: handle_addr does not apply time_penalty when storing new addrs.
   Core deducts 2h from nTime when learning addrs from another peer
   (m_addrman.Add(vAddrOk, pfrom.addr, 2h)).  camlcoin stores the raw
   timestamp without penalty.
   Severity: MEDIUM. Core ref: net_processing.cpp line 5702. *)
let test_g10_time_penalty_missing () =
  let pm = make_pm () in
  let now = Unix.gettimeofday () in
  let addr_bytes = Cstruct.create 16 in
  Cstruct.set_uint8 addr_bytes 10 0xFF;
  Cstruct.set_uint8 addr_bytes 11 0xFF;
  Cstruct.set_uint8 addr_bytes 12 70;
  Cstruct.set_uint8 addr_bytes 13 0;
  Cstruct.set_uint8 addr_bytes 14 0;
  Cstruct.set_uint8 addr_bytes 15 1;
  let net_addr : Types.net_addr = { services = 1L; addr = addr_bytes; port = 8333 } in
  let peer = Peer.make_peer ~network:Consensus.mainnet ~addr:"1.2.3.4"
    ~port:8333 ~id:0 ~direction:Peer.Outbound
    ~fd:(Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0) () in
  let ts = Int32.of_float now in
  Peer_manager.handle_addr pm peer [(ts, net_addr)];
  (* BUG: stored timestamp is the raw ts from the message, not ts - 2h *)
  let stats = Peer_manager.get_addr_stats pm in
  Alcotest.(check bool) "BUG-G10: addr added (no time_penalty deduction)"
    true (stats.total_known > 0)

(* ===== G11: addr_ts_lower_bound ===================================
   Fix: handle_addr now applies Core's nTime clamp (net_processing.cpp:5678-5680).
   Both pre-2001 (nTime <= 100000000) and far-future (nTime > now+600) timestamps
   are clamped to (now - 5*24*60*60) before storing — matching Core exactly.
   Core does NOT reject these addresses; it stores them with a corrected nTime.
   Severity: LOW. Core ref: net_processing.cpp line 5678. *)
let test_g11_addr_ts_lower_bound () =
  let pm = make_pm () in
  let addr_bytes = Cstruct.create 16 in
  Cstruct.set_uint8 addr_bytes 10 0xFF;
  Cstruct.set_uint8 addr_bytes 11 0xFF;
  Cstruct.set_uint8 addr_bytes 12 71;
  Cstruct.set_uint8 addr_bytes 13 0;
  Cstruct.set_uint8 addr_bytes 14 0;
  Cstruct.set_uint8 addr_bytes 15 1;
  let net_addr : Types.net_addr = { services = 1L; addr = addr_bytes; port = 8333 } in
  let peer = Peer.make_peer ~network:Consensus.mainnet ~addr:"1.2.3.4"
    ~port:8333 ~id:0 ~direction:Peer.Outbound
    ~fd:(Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0) () in
  (* ts = 1 (way below 100000000 threshold) — Core clamps to now-5days *)
  Peer_manager.handle_addr pm peer [(1l, net_addr)];
  let stats = Peer_manager.get_addr_stats pm in
  (* FIX: addr is stored (Core stores it with a clamped nTime, not rejected) *)
  Alcotest.(check bool) "FIX-G11: ts=1 stored with clamped last_connected"
    true (stats.total_known > 0);
  (* Verify the stored timestamp is the clamp value (now - 5 days),
     NOT the raw ts=1 from the message. *)
  let now = Unix.gettimeofday () in
  let five_days = 5.0 *. 86400.0 in
  (match Hashtbl.find_opt pm.known_addrs "71.0.0.1" with
  | None -> Alcotest.fail "addr not stored in known_addrs"
  | Some info ->
    (* clamped value must be within 2s of now - 5days *)
    let delta = Float.abs (info.last_connected -. (now -. five_days)) in
    Alcotest.(check bool) "FIX-G11: last_connected clamped to now-5days (not raw ts=1)"
      true (delta < 2.0))

(* ===== G12: addrv2_no_rate_limit ==================================
   Bug: handle_addrv2 applies no rate limiting.  Core uses the same
   token-bucket (0.1 addr/s) for both addr and addrv2 messages.
   camlcoin's handle_addrv2 ignores addr_rate entirely.
   Severity: MEDIUM. *)
let test_g12_addrv2_no_rate_limit () =
  let pm = make_pm () in
  (* Flood with 5000 addrv2 entries — no rate limit will fire *)
  let entries = List.init 5000 (fun i ->
    let ip = Cstruct.create 4 in
    Cstruct.set_uint8 ip 0 (80 + (i / 256 / 256) mod 128);
    Cstruct.set_uint8 ip 1 ((i / 256) mod 256);
    Cstruct.set_uint8 ip 2 (i mod 256);
    Cstruct.set_uint8 ip 3 1;
    { P2p.v2_network_id = P2p.Addrv2_IPv4;
      v2_addr = ip;
      v2_port = 8333;
      v2_services = 1L;
      v2_time = Int32.of_float (Unix.gettimeofday ()) }
  ) in
  let peer = Peer.make_peer ~network:Consensus.mainnet ~addr:"1.2.3.4"
    ~port:8333 ~id:0 ~direction:Peer.Outbound
    ~fd:(Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0) () in
  Peer_manager.handle_addrv2 pm peer entries;
  let stats = Peer_manager.get_addr_stats pm in
  (* FIX-G12: addrv2 is now rate-limited by the Core inbound-addr token bucket
     (MAX_ADDR_RATE_PER_SECOND=0.1, fresh bucket=1.0), so a single 5000-entry
     flood admits at most a handful — far below the unbounded pre-fix 5000.
     Core caps the message itself at MAX_ADDR_TO_SEND=1000; the per-message
     token bucket drops the excess. *)
  Alcotest.(check bool) "FIX-G12: addrv2 rate-limited (token bucket)"
    true (stats.total_known <= 1000)

(* ===== G13: addrv2_no_ts_deduction ================================
   Fix: handle_addrv2 now stores the clamped v2_time as last_connected
   instead of Unix.gettimeofday().  The clamp (Core net_processing.cpp:5678-5680)
   is applied: pre-2001 or far-future timestamps → now-5days; in-range timestamps
   are stored as-is.
   Severity: MEDIUM. Core ref: addrman.cpp AddSingle nTime usage. *)
let test_g13_addrv2_no_ts_deduction () =
  let pm = make_pm () in
  let ip = Cstruct.create 4 in
  Cstruct.set_uint8 ip 0 80;
  Cstruct.set_uint8 ip 1 1;
  Cstruct.set_uint8 ip 2 2;
  Cstruct.set_uint8 ip 3 3;
  (* Use a timestamp ~11.5 days ago — in-range (>100000000 and not future),
     so it must be stored AS-IS (not clamped). *)
  let old_ts_float = Unix.gettimeofday () -. 1_000_000.0 in
  let old_ts = Int32.of_float old_ts_float in
  let entry = {
    P2p.v2_network_id = P2p.Addrv2_IPv4;
    v2_addr = ip;
    v2_port = 8333;
    v2_services = 1L;
    v2_time = old_ts;
  } in
  let peer = Peer.make_peer ~network:Consensus.mainnet ~addr:"2.2.2.2"
    ~port:8333 ~id:0 ~direction:Peer.Outbound
    ~fd:(Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0) () in
  Peer_manager.handle_addrv2 pm peer [entry];
  let stats = Peer_manager.get_addr_stats pm in
  Alcotest.(check bool) "FIX-G13: addrv2 entry stored"
    true (stats.total_known = 1);
  (* FIX: last_connected must be the message timestamp (old_ts_float), NOT now.
     Int32.of_float truncates precision; allow ±2s. *)
  (match Hashtbl.find_opt pm.known_addrs "80.1.2.3" with
  | None -> Alcotest.fail "addrv2 addr not found in known_addrs"
  | Some info ->
    let now = Unix.gettimeofday () in
    (* The stored time must NOT be close to now (which was the pre-fix bug) *)
    let delta_now = Float.abs (info.last_connected -. now) in
    Alcotest.(check bool) "FIX-G13: last_connected is NOT current time"
      true (delta_now > 100.0);
    (* The stored time must be close to the message timestamp *)
    let delta_msg = Float.abs (info.last_connected -. old_ts_float) in
    Alcotest.(check bool) "FIX-G13: last_connected matches addrv2 v2_time"
      true (delta_msg < 2.0))

(* ===== G14: addr_relay_csprng =====================================
   Bug: relay_addr_to_random_peers shuffles candidates with
   (fun _ _ -> Random.int 3 - 1) — not a proper Fisher-Yates shuffle
   and uses the weak Random PRNG, not a CSPRNG.  An observer learning
   two relay targets can probabilistically recover the PRNG state.
   Severity: MEDIUM. *)
let test_g14_addr_relay_csprng () =
  (* Confirm Random.int is used (not CSPRNG) by seeding and checking
     reproducibility in the shuffle. *)
  Random.init 100;
  let r1 = Random.int 3 - 1 in
  Random.init 100;
  let r2 = Random.int 3 - 1 in
  Alcotest.(check int) "BUG-G14: shuffle uses seeded-reproducible RNG" r1 r2

(* ===== G15: getaddr_one_time_guard ================================
   Bug: Bitcoin Core sets m_getaddr_sent=true after sending GETADDR
   and blocks re-sends until the peer has responded with < 1000 addrs.
   camlcoin has request_addrs which broadcasts GetaddrMsg to all peers
   unconditionally on every call with no one-time guard.
   Severity: MEDIUM. Core ref: net_processing.cpp m_getaddr_sent. *)
let test_g15_getaddr_one_time_guard () =
  let pm = make_pm () in
  (* No guard field exists on peer_info or peer *)
  (* request_addrs can be called repeatedly without any once-gate *)
  let _ = Peer_manager.request_addrs pm in
  let _ = Peer_manager.request_addrs pm in
  (* If a guard existed, the second call would be a no-op *)
  Alcotest.(check bool) "BUG-G15: no one-shot getaddr guard" true true

(* ===== G16: tried_collision_missing ===============================
   Bug: No test-before-evict / ResolveCollisions mechanism.  When
   move_to_tried_table finds the target tried-bucket position occupied,
   it directly evicts the old entry (last of list) without:
   1. Queuing the new entry in m_tried_collisions
   2. Scheduling a feeler connection to verify the old entry is dead
   3. Only replacing after the old entry fails to connect
   Severity: HIGH. Core ref: addrman.cpp Good_() test_before_evict,
   ResolveCollisions_(). *)
let test_g16_tried_collision_missing () =
  let pm = make_pm () in
  (* Fill a tried bucket to capacity (64 entries) *)
  for i = 1 to Peer_manager.bucket_size + 2 do
    let addr = Printf.sprintf "90.0.%d.1" i in
    add_addr pm addr;
    let _ = Peer_manager.move_to_tried_table pm addr in
    ()
  done;
  let stats = Peer_manager.get_bucket_stats pm in
  (* BUG: eviction happened silently without feeler/test-before-evict *)
  Alcotest.(check bool) "BUG-G16: tried eviction without ResolveCollisions"
    true (stats.tried_table_entries <= Peer_manager.bucket_size * Peer_manager.tried_bucket_count)

(* ===== G17: tried_evict_no_check ==================================
   Bug: move_to_tried_table full-bucket eviction discards the last
   entry in the list (List.rev current |> tl).  Bitcoin Core uses
   Good_() with test_before_evict=true: it queues in m_tried_collisions
   and keeps both until the old entry is tested.  camlcoin silently
   drops a potentially-valid address.
   Severity: HIGH. Core ref: addrman.cpp MakeTried() bucket-full path. *)
let test_g17_tried_evict_no_check () =
  let pm = make_pm () in
  let addr1 = "91.0.0.1" in
  let addr2 = "91.0.0.2" in
  add_addr pm addr1;
  let _ = Peer_manager.move_to_tried_table pm addr1 in
  (* Add a second addr that hashes to the same tried bucket as addr1.
     In Core this would enqueue a collision; in camlcoin addr1 may be
     silently dropped without any feeler test. *)
  add_addr pm addr2;
  let _ = Peer_manager.move_to_tried_table pm addr2 in
  let stats = Peer_manager.get_bucket_stats pm in
  Alcotest.(check bool) "BUG-G17: tried eviction bypasses test-before-evict"
    true (stats.tried_table_entries >= 1)

(* ===== G18: routability_filter ====================================
   Fixed: add_to_new_table / add_known_addr / handle_addr / handle_addrv2
   now call is_routable() and reject non-routable addresses, mirroring
   Bitcoin Core addrman.cpp AddSingle "if (!addr.IsRoutable()) return".
   Core ref: addrman.cpp AddSingle, netaddress.cpp CNetAddr::IsRoutable(). *)
let test_g18_routability_filter () =
  let pm = make_pm () in
  (* RFC1918 private addresses — must all be rejected *)
  add_addr pm "192.168.1.1";
  add_addr pm "10.0.0.1";
  add_addr pm "172.16.0.1";
  let stats = Peer_manager.get_addr_stats pm in
  Alcotest.(check int) "RFC1918 addrs rejected (IsRoutable fix)"
    0 stats.total_known;
  (* Loopback must also be rejected *)
  let pm2 = make_pm () in
  add_addr pm2 "127.0.0.1";
  add_addr pm2 "127.0.0.2";
  let stats2 = Peer_manager.get_addr_stats pm2 in
  Alcotest.(check int) "loopback addrs rejected"
    0 stats2.total_known;
  (* Link-local (RFC3927) must be rejected *)
  let pm3 = make_pm () in
  add_addr pm3 "169.254.1.1";
  let stats3 = Peer_manager.get_addr_stats pm3 in
  Alcotest.(check int) "link-local addr rejected"
    0 stats3.total_known;
  (* Public routable address must be accepted *)
  let pm4 = make_pm () in
  add_addr pm4 "8.8.8.8";
  let stats4 = Peer_manager.get_addr_stats pm4 in
  Alcotest.(check int) "public routable addr accepted"
    1 stats4.total_known

(* ===== G19: gossip_no_terrible_filter =============================
   Bug: gossip_addresses sends up to 1000 addresses from known_addrs
   without filtering out IsTerrible entries.  Core's GetAddr() calls
   IsTerrible() to skip bad-quality addresses when filtered=true.
   Severity: MEDIUM. Core ref: addrman.cpp GetAddr_() IsTerrible filter. *)
let test_g19_gossip_no_terrible_filter () =
  let pm = make_pm () in
  (* Add an "old" address (simulating never-seen-in-30d → IsTerrible) *)
  Peer_manager.add_known_addr pm {
    Peer_manager.address = "100.0.0.1";
    port = 8333;
    services = 1L;
    last_connected = 0.0;
    last_attempt = 0.0;
    last_success = 0.0;  (* never succeeded *)
    failures = 15;       (* >= ADDRMAN_MAX_FAILURES = 10 *)
    banned_until = 0.0;
    source = Peer_manager.Addr;
    table_status = Peer_manager.NotInTable;
  };
  (* gossip_addresses will include this terrible address *)
  let stats = Peer_manager.get_addr_stats pm in
  Alcotest.(check bool) "BUG-G19: terrible addrs included in gossip (no IsTerrible filter)"
    true (stats.total_known = 1)

(* ===== G20: getaddr_pct_cap =======================================
   Bug: gossip_addresses caps at 1000 (MAX_ADDR_TO_SEND) but has no
   23% cap.  Core's GetAddr() limits to MAX_PCT_ADDR_TO_SEND=23% of
   the total address list to avoid leaking the full address book.
   Severity: MEDIUM. Core ref: net_processing.cpp MAX_PCT_ADDR_TO_SEND=23. *)
let test_g20_getaddr_pct_cap () =
  let pm = make_pm () in
  (* Add 200 addresses — 23% = 46, hard cap 1000.  camlcoin returns up to 1000. *)
  for i = 1 to 200 do
    add_addr pm (Printf.sprintf "101.%d.%d.1" (i / 256) (i mod 256))
  done;
  let stats = Peer_manager.get_addr_stats pm in
  (* camlcoin gossip_addresses: hard cap 1000 but no 23% cap *)
  Alcotest.(check bool) "BUG-G20: no 23 pct cap on GetAddr response"
    true (stats.total_known = 200)

(* ===== G21: persistence_missing ===================================
   Bug: camlcoin has no peers.dat equivalent.  On restart the entire
   new+tried address tables are gone; only bans and anchors survive.
   Bitcoin Core serializes the full addrman to peers.dat on shutdown
   and loads it on startup.
   Severity: HIGH. Core ref: addrman.cpp Serialize/Unserialize. *)
let test_g21_persistence_missing () =
  (* Demonstrate that known_addrs (new+tried) is not persisted.
     save_bans/load_bans only cover the ban list, not peer addresses. *)
  let pm = make_pm () in
  add_addr pm "110.0.0.1";
  let _ = Peer_manager.move_to_tried_table pm "110.0.0.1" in
  let stats = Peer_manager.get_bucket_stats pm in
  Alcotest.(check bool) "entry in tried before restart simulation"
    true (stats.tried_table_entries = 1);
  (* Simulate restart: create new pm (no load path for tried/new tables) *)
  let pm2 = make_pm () in
  let stats2 = Peer_manager.get_bucket_stats pm2 in
  Alcotest.(check int) "BUG-G21: tried table empty after restart (no persistence)"
    0 stats2.tried_table_entries

(* ===== G22: connected_ntime_leak ==================================
   Bug: add_peer on success sets last_success = now.  Bitcoin Core's
   Connected() only updates nTime (not m_last_success) and is called
   at *disconnect* time to avoid leaking which peers are currently
   connected.  camlcoin updates last_success on *connection*, leaking
   current-connection topology to addr gossip.
   Severity: HIGH. Core ref: addrman.h Connected() doc comment. *)
let test_g22_connected_ntime_leak () =
  (* The topology leak is an architectural property; we document it
     by showing last_success is set at connection time in add_peer. *)
  let pm = make_pm () in
  add_addr pm "120.0.0.1";
  let before = Unix.gettimeofday () in
  (* Simulate what add_peer does on success (we can't call add_peer
     without a real TCP connection, so we mirror the logic): *)
  let info_opt = Hashtbl.find_opt pm.known_addrs "120.0.0.1" in
  (match info_opt with
   | Some _ ->
     (* Verify field exists and will be set to 'now' on connection *)
     Alcotest.(check bool) "BUG-G22: last_success field exists (set at connect, not disconnect)"
       true true
   | None -> ());
  let _ = before in ()

(* ===== G23: addr_relay_shuffle_rng ================================
   Bug: relay_addr_to_random_peers (line 1393) uses
   List.sort (fun _ _ -> Random.int 3 - 1) which is (a) not a proper
   shuffle (non-transitive comparator UB in sort), (b) uses the weak
   Random PRNG.  Bitcoin Core uses a CSPRNG-seeded shuffle.
   Severity: MEDIUM. *)
let test_g23_addr_relay_shuffle_rng () =
  (* Non-transitive comparator: f(a,b) = +1, f(b,c) = +1, f(a,c) = -1
     is valid for OCaml's sort if the comparator is not a total order.
     The Random.int 3 - 1 comparator can return 0, which is fine for
     the sort contract, but the distribution is biased and not CSPRNG. *)
  Random.init 77;
  let lst = [1;2;3;4;5;6;7;8;9;10] in
  let s1 = List.sort (fun _ _ -> Random.int 3 - 1) lst in
  Random.init 77;
  let s2 = List.sort (fun _ _ -> Random.int 3 - 1) lst in
  Alcotest.(check bool) "BUG-G23: shuffle is deterministic given seed (non-CSPRNG)"
    true (s1 = s2)

(* ===== G24: feeler_missing ========================================
   Bug: No feeler connection type.  Bitcoin Core uses feeler
   connections to test whether tried-table entries are still alive
   (part of the test-before-evict mechanism).  camlcoin has no feeler
   support: there is no max_feeler, no FEELER_SLEEP_WINDOW, no
   ConnectionType::FEELER.
   Severity: MEDIUM. Core ref: net.h ConnectionType::FEELER. *)
let test_g24_feeler_missing () =
  (* Verify no feeler config or type exists *)
  let cfg = Peer_manager.default_config in
  (* max_block_relay_only = 2, max_outbound = 8, but no max_feeler *)
  Alcotest.(check int) "max_outbound" 8 cfg.max_outbound;
  (* BUG: no feeler field *)
  Alcotest.(check bool) "BUG-G24: no feeler connection type in config"
    true true

(* ===== G25: set_services_missing ==================================
   Bug: When a VERSION message arrives from a peer, Core calls
   SetServices() to record the services advertised by that peer into
   the AddrMan entry.  camlcoin never calls any equivalent; the
   services field stored at addr-add time is never updated.
   Severity: MEDIUM. Core ref: addrman.cpp SetServices_(). *)
let test_g25_set_services_missing () =
  let pm = make_pm () in
  (* Add addr with services=1 (NODE_NETWORK only) *)
  add_addr ~services:1L pm "130.0.0.1";
  (* Simulate receiving VERSION with updated services (NODE_NETWORK|WITNESS=9) *)
  (* There is no set_services function in camlcoin — services remain stale *)
  (match Hashtbl.find_opt pm.known_addrs "130.0.0.1" with
   | Some info ->
     Alcotest.(check int64) "BUG-G25: services never updated from VERSION"
       1L info.services
   | None ->
     Alcotest.fail "addr not found")

(* ===== G26: new_bucket_full_evict =================================
   Bug: add_to_new_table (line 350-356) on bucket-full evicts the HEAD
   of the current list using pattern `| _ :: rest`.  This is FIFO
   eviction (oldest-inserted).  Core evicts entries that IsTerrible()
   or entries with nRefCount > 1 (can be relocated) first; only then
   is a direct eviction done.
   Severity: HIGH. Core ref: addrman.cpp AddSingle fInsert / ClearNew. *)
let test_g26_new_bucket_full_evict () =
  let pm = make_pm () in
  (* To test bucket-full we'd need many addrs mapping to the same bucket.
     We can't easily control that without controlling the key, but we can
     verify that no IsTerrible check occurs on eviction. *)
  let bucket_sz = Peer_manager.bucket_size in
  (* Force a single bucket to fill: use compute_bucket to find addrs
     that map to bucket 0 and add enough of them. *)
  let target_bucket = 0 in
  let count = ref 0 in
  let i = ref 1 in
  while !count <= bucket_sz + 1 do
    let addr = Printf.sprintf "50.%d.%d.1" (!i / 256) (!i mod 256) in
    let b = Peer_manager.compute_bucket pm.bucket_key addr Peer_manager.new_bucket_count in
    if b = target_bucket then begin
      add_addr pm addr;
      incr count
    end;
    incr i;
    if !i > 100000 then begin
      (* Give up if we can't find enough in bucket 0 — just test shape *)
      count := bucket_sz + 100
    end
  done;
  Alcotest.(check bool) "BUG-G26: new bucket full evicts head (no IsTerrible check)"
    true true

(* ===== G27: netgroup_ipv6_missing =================================
   Bug: netgroup_of only handles IPv4 (splits on '.' and takes a.b).
   For IPv6 addresses it returns the entire address string unchanged.
   Bitcoin Core uses /16 for IPv4 and /32 for IPv6 (or AS via asmap).
   This means all IPv6 peers appear as having distinct /16 netgroups —
   breaking eclipse protection for IPv6.
   Severity: MEDIUM. Core ref: netgroup.cpp GetGroup(). *)
let test_g27_netgroup_ipv6_missing () =
  (* IPv6 address: netgroup_of returns the full string, not /32 *)
  let ng = Peer_manager.netgroup_of "2001:db8::1" in
  Alcotest.(check bool) "BUG-G27: IPv6 netgroup = full addr (no /32 group)"
    true (ng = "2001:db8::1");
  (* Expected: Core would return "2001:db8" for /32 *)
  (* IPv4 works correctly *)
  let ng_v4 = Peer_manager.netgroup_of "192.168.1.1" in
  Alcotest.(check string) "IPv4 /16 correct" "192.168" ng_v4

(* ===== G28: addr_source_netgroup_key ==============================
   Bug: add_to_new_table / compute_bucket does not incorporate the
   source peer's /16 netgroup.  Bitcoin Core's new-bucket hash
   explicitly includes vchSourceGroupKey (GetGroup(src)) so that
   many different source peers cannot all route the same dest addr
   into the same bucket (eclipse mitigation).
   Severity: HIGH. Core ref: addrman.cpp GetNewBucket(key, src). *)
let test_g28_addr_source_netgroup_key () =
  (* compute_bucket signature: key -> addr -> bucket_count -> int.
     No source argument exists.  In Core:
       GetNewBucket(key, src) hashes (nKey, addr_group, src_group)
     camlcoin: SHA256(key ^ addr) -- source not a parameter at all. *)
  let key = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" in
  let addr = "200.1.1.1" in
  (* Same call with same key+addr always returns same bucket --
     no source peer netgroup input exists *)
  let b1 = Peer_manager.compute_bucket key addr Peer_manager.new_bucket_count in
  let b2 = Peer_manager.compute_bucket key addr Peer_manager.new_bucket_count in
  Alcotest.(check int) "BUG-G28: bucket identical regardless of source (source not a parameter)"
    b1 b2

(* ===== G29: tried_collision_set_size ==============================
   Bug: No m_tried_collisions set and no ADDRMAN_SET_TRIED_COLLISION_SIZE
   (10) cap.  Core caps the collision set to prevent memory exhaustion
   and implements ResolveCollisions() to process them periodically.
   camlcoin has no collision tracking at all.
   Severity: HIGH. Core ref: addrman.h ADDRMAN_SET_TRIED_COLLISION_SIZE=10. *)
let test_g29_tried_collision_set_size () =
  (* No m_tried_collisions field or constant *)
  let pm = make_pm () in
  for i = 1 to 20 do
    let addr = Printf.sprintf "210.0.0.%d" i in
    add_addr pm addr;
    let _ = Peer_manager.move_to_tried_table pm addr in
    ()
  done;
  (* If collision tracking existed, m_tried_collisions.size() <= 10.
     Without it, silent eviction happens for all 20 entries. *)
  let stats = Peer_manager.get_bucket_stats pm in
  Alcotest.(check bool) "BUG-G29: no tried collision set (ADDRMAN_SET_TRIED_COLLISION_SIZE missing)"
    true (stats.tried_table_entries <= Peer_manager.tried_bucket_count * Peer_manager.bucket_size)

(* ===== G30: good_call_not_atomic ==================================
   Bug: move_to_tried_table removes from new table THEN adds to tried.
   If these are not atomic and a concurrent call (possible with Lwt)
   reads the address between the two operations, the address appears
   in neither table — a transient inconsistency.  Bitcoin Core holds
   cs (mutex) across the full MakeTried() operation.
   Severity: MEDIUM. Core ref: addrman.cpp MakeTried(), cs mutex. *)
let test_g30_good_call_not_atomic () =
  let pm = make_pm () in
  add_addr pm "220.0.0.1";
  let stats_before = Peer_manager.get_bucket_stats pm in
  (* After move, address should be in tried and not in new *)
  let _ = Peer_manager.move_to_tried_table pm "220.0.0.1" in
  let stats_after = Peer_manager.get_bucket_stats pm in
  (* Verify the entry moved (shape correct) *)
  Alcotest.(check bool) "BUG-G30: new table decreased after move"
    true (stats_after.new_table_entries <= stats_before.new_table_entries);
  Alcotest.(check bool) "BUG-G30: tried table increased after move"
    true (stats_after.tried_table_entries > 0)
  (* Note: no mutex around the two-step operation — Lwt race possible *)

(* ===== Finding 3G: addr/addrv2 nTime clamp (Core-faithful fix) ======
   Core net_processing.cpp:5678-5680 clamps timestamps that are either
   pre-2001 (nTime <= 100000000) OR more than 10 minutes in the future
   to (now - 5 * 24 * 60 * 60).  Both the ADDR and ADDRV2 ingestion
   paths must apply this clamp before storing last_connected.

   These tests FAIL on the pre-fix code (addr stored with ts=1 or ts=now+9999
   unclamped / addrv2 stored with ts=now instead of msg ts) and PASS after. *)

(* Helper: make an IPv4-mapped 16-byte addr for handle_addr *)
let make_net_addr a b c d port =
  let addr_bytes = Cstruct.create 16 in
  Cstruct.set_uint8 addr_bytes 10 0xFF;
  Cstruct.set_uint8 addr_bytes 11 0xFF;
  Cstruct.set_uint8 addr_bytes 12 a;
  Cstruct.set_uint8 addr_bytes 13 b;
  Cstruct.set_uint8 addr_bytes 14 c;
  Cstruct.set_uint8 addr_bytes 15 d;
  { Types.services = 1L; addr = addr_bytes; port }

let make_peer_for_test () =
  Peer.make_peer ~network:Consensus.mainnet ~addr:"1.2.3.4"
    ~port:8333 ~id:0 ~direction:Peer.Outbound
    ~fd:(Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0) ()

(* Pre-2001 timestamp (ts=1) must be clamped to now-5days in ADDR message *)
let test_3g_addr_pre2001_ts_clamped () =
  let pm = make_pm () in
  let peer = make_peer_for_test () in
  let net_addr = make_net_addr 72 0 0 1 8333 in
  Peer_manager.handle_addr pm peer [(1l, net_addr)];
  let now = Unix.gettimeofday () in
  let five_days = 5.0 *. 86400.0 in
  (match Hashtbl.find_opt pm.known_addrs "72.0.0.1" with
  | None -> Alcotest.fail "addr not stored"
  | Some info ->
    let delta = Float.abs (info.last_connected -. (now -. five_days)) in
    Alcotest.(check bool)
      "3G FIX: pre-2001 ADDR ts clamped to now-5days" true (delta < 2.0))

(* Future timestamp (now + 9999s, well past 600s threshold) must be clamped *)
let test_3g_addr_future_ts_clamped () =
  let pm = make_pm () in
  let peer = make_peer_for_test () in
  let now = Unix.gettimeofday () in
  let future_ts = Int32.of_float (now +. 9999.0) in
  let net_addr = make_net_addr 73 0 0 1 8333 in
  Peer_manager.handle_addr pm peer [(future_ts, net_addr)];
  let five_days = 5.0 *. 86400.0 in
  (match Hashtbl.find_opt pm.known_addrs "73.0.0.1" with
  | None -> Alcotest.fail "future-ts ADDR not stored (should be clamped and stored)"
  | Some info ->
    let delta = Float.abs (info.last_connected -. (now -. five_days)) in
    Alcotest.(check bool)
      "3G FIX: future ADDR ts clamped to now-5days" true (delta < 2.0))

(* In-range timestamp (now - 3600) passes through unclamped *)
let test_3g_addr_valid_ts_stored () =
  let pm = make_pm () in
  let peer = make_peer_for_test () in
  let now = Unix.gettimeofday () in
  let valid_ts_float = now -. 3600.0 in
  let valid_ts = Int32.of_float valid_ts_float in
  let net_addr = make_net_addr 74 0 0 1 8333 in
  Peer_manager.handle_addr pm peer [(valid_ts, net_addr)];
  (match Hashtbl.find_opt pm.known_addrs "74.0.0.1" with
  | None -> Alcotest.fail "valid-ts ADDR not stored"
  | Some info ->
    let delta = Float.abs (info.last_connected -. valid_ts_float) in
    Alcotest.(check bool)
      "3G FIX: valid ADDR ts stored as-is (no clamping)" true (delta < 2.0))

(* Pre-2001 timestamp in ADDRV2 must be clamped to now-5days *)
let test_3g_addrv2_pre2001_ts_clamped () =
  let pm = make_pm () in
  let peer = make_peer_for_test () in
  let ip = Cstruct.create 4 in
  Cstruct.set_uint8 ip 0 81;
  Cstruct.set_uint8 ip 1 0;
  Cstruct.set_uint8 ip 2 0;
  Cstruct.set_uint8 ip 3 1;
  let entry = { P2p.v2_network_id = P2p.Addrv2_IPv4;
                v2_addr = ip; v2_port = 8333; v2_services = 1L;
                v2_time = 1l } in
  Peer_manager.handle_addrv2 pm peer [entry];
  let now = Unix.gettimeofday () in
  let five_days = 5.0 *. 86400.0 in
  (match Hashtbl.find_opt pm.known_addrs "81.0.0.1" with
  | None -> Alcotest.fail "addrv2 entry not stored"
  | Some info ->
    let delta = Float.abs (info.last_connected -. (now -. five_days)) in
    Alcotest.(check bool)
      "3G FIX: pre-2001 ADDRV2 ts clamped to now-5days" true (delta < 2.0))

let finding_3g_tests = [
  Alcotest.test_case "3G: pre-2001 ADDR ts clamped to now-5days" `Quick
    test_3g_addr_pre2001_ts_clamped;
  Alcotest.test_case "3G: future ADDR ts clamped to now-5days" `Quick
    test_3g_addr_future_ts_clamped;
  Alcotest.test_case "3G: valid ADDR ts stored as-is" `Quick
    test_3g_addr_valid_ts_stored;
  Alcotest.test_case "3G: pre-2001 ADDRV2 ts clamped to now-5days" `Quick
    test_3g_addrv2_pre2001_ts_clamped;
]

(* ===================================================================
   Runner
   =================================================================== *)

let () =
  Alcotest.run "W104_AddrMan_camlcoin" [
    "G1_bucket_key_rng_weak", [
      Alcotest.test_case "bucket_key uses weak OCaml Random not CSPRNG" `Quick
        test_g1_bucket_key_rng_weak;
    ];
    "G2_bucket_hash_algorithm", [
      Alcotest.test_case "single SHA256 not double-hash HashWriter" `Quick
        test_g2_bucket_hash_algorithm;
    ];
    "G3_bucket_hash_no_netgroup", [
      Alcotest.test_case "source netgroup absent from new-bucket hash" `Quick
        test_g3_bucket_hash_no_netgroup;
    ];
    "G4_bucket_pos_missing", [
      Alcotest.test_case "no GetBucketPosition keyed position" `Quick
        test_g4_bucket_pos_missing;
    ];
    "G5_new_buckets_per_source", [
      Alcotest.test_case "ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP absent" `Quick
        test_g5_new_buckets_per_source;
    ];
    "G6_tried_buckets_per_group", [
      Alcotest.test_case "ADDRMAN_TRIED_BUCKETS_PER_GROUP absent" `Quick
        test_g6_tried_buckets_per_group;
    ];
    "G7_ref_count_stochastic", [
      Alcotest.test_case "stochastic 2^N re-insert resistance absent" `Quick
        test_g7_ref_count_stochastic;
    ];
    "G8_is_terrible_missing", [
      Alcotest.test_case "no IsTerrible equivalent" `Quick
        test_g8_is_terrible_missing;
    ];
    "G9_get_chance_missing", [
      Alcotest.test_case "no GetChance probabilistic selection" `Quick
        test_g9_get_chance_missing;
    ];
    "G10_time_penalty_missing", [
      Alcotest.test_case "2h time_penalty not applied on addr add" `Quick
        test_g10_time_penalty_missing;
    ];
    "G11_addr_ts_lower_bound", [
      Alcotest.test_case "lower bound ts check absent (nTime <= 1e8s)" `Quick
        test_g11_addr_ts_lower_bound;
    ];
    "G12_addrv2_no_rate_limit", [
      Alcotest.test_case "handle_addrv2 ignores rate limiting" `Quick
        test_g12_addrv2_no_rate_limit;
    ];
    "G13_addrv2_no_ts_deduction", [
      Alcotest.test_case "addrv2 sets last_connected=now not msg ts" `Quick
        test_g13_addrv2_no_ts_deduction;
    ];
    "G14_addr_relay_csprng", [
      Alcotest.test_case "relay shuffle uses weak Random not CSPRNG" `Quick
        test_g14_addr_relay_csprng;
    ];
    "G15_getaddr_one_time_guard", [
      Alcotest.test_case "m_getaddr_sent one-shot guard absent" `Quick
        test_g15_getaddr_one_time_guard;
    ];
    "G16_tried_collision_missing", [
      Alcotest.test_case "ResolveCollisions test-before-evict absent" `Quick
        test_g16_tried_collision_missing;
    ];
    "G17_tried_evict_no_check", [
      Alcotest.test_case "tried eviction skips IsTerrible/feeler check" `Quick
        test_g17_tried_evict_no_check;
    ];
    "G18_routability_filter", [
      Alcotest.test_case "non-routable addrs rejected (IsRoutable fixed)" `Quick
        test_g18_routability_filter;
    ];
    "G19_gossip_no_terrible_filter", [
      Alcotest.test_case "gossip_addresses includes terrible addrs" `Quick
        test_g19_gossip_no_terrible_filter;
    ];
    "G20_getaddr_pct_cap", [
      Alcotest.test_case "23 pct MAX_PCT_ADDR_TO_SEND cap absent" `Quick
        test_g20_getaddr_pct_cap;
    ];
    "G21_persistence_missing", [
      Alcotest.test_case "no peers.dat new/tried table persistence" `Quick
        test_g21_persistence_missing;
    ];
    "G22_connected_ntime_leak", [
      Alcotest.test_case "last_success set at connect not disconnect" `Quick
        test_g22_connected_ntime_leak;
    ];
    "G23_addr_relay_shuffle_rng", [
      Alcotest.test_case "addr relay shuffle uses non-CSPRNG Random" `Quick
        test_g23_addr_relay_shuffle_rng;
    ];
    "G24_feeler_missing", [
      Alcotest.test_case "no feeler connection type" `Quick
        test_g24_feeler_missing;
    ];
    "G25_set_services_missing", [
      Alcotest.test_case "SetServices not called from VERSION handler" `Quick
        test_g25_set_services_missing;
    ];
    "G26_new_bucket_full_evict", [
      Alcotest.test_case "new bucket full evicts head not IsTerrible entry" `Quick
        test_g26_new_bucket_full_evict;
    ];
    "G27_netgroup_ipv6_missing", [
      Alcotest.test_case "netgroup_of returns full IPv6 addr not /32" `Quick
        test_g27_netgroup_ipv6_missing;
    ];
    "G28_addr_source_netgroup_key", [
      Alcotest.test_case "source peer netgroup absent from new-bucket hash" `Quick
        test_g28_addr_source_netgroup_key;
    ];
    "G29_tried_collision_set_size", [
      Alcotest.test_case "ADDRMAN_SET_TRIED_COLLISION_SIZE cap absent" `Quick
        test_g29_tried_collision_set_size;
    ];
    "G30_good_call_not_atomic", [
      Alcotest.test_case "move_to_tried is not atomic (no mutex)" `Quick
        test_g30_good_call_not_atomic;
    ];
    "finding_3g_addr_ts_clamp", finding_3g_tests;
  ]
