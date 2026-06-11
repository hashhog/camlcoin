(* Fixed-seed last-resort fallback — camlcoin (OCaml)

   Regression test for the Core-faithful fixed-IP fallback wired into
   Peer_manager (see Consensus.network_config.fixed_seeds +
   Peer_manager.add_fixed_seeds / maybe_add_fixed_seeds).

   Reference: bitcoin-core/src/net.cpp:2607-2643 (ThreadOpenConnections
   add_fixed_seeds trigger).  The curated IPs are dialed ONLY as a last
   resort — after the normal DNS bootstrap — when ALL hold:
     (1) ENABLED: not --connect AND a non-empty fixedSeeds list (mainnet only);
     (2) BOOK EMPTY: the address book has no addresses;
     (3) EITHER >60s elapsed since the loop start, OR DNS is disabled
         (-nodnsseed) so there is nothing to wait for.
   One-shot: after firing, the guard makes subsequent ticks no-ops.

   Verified properties:
     - all 40 mainnet seeds parse to routable IPv4 host : port 8333;
     - testnet/regtest carry NO fixed seeds (Core clears vFixedSeeds);
     - predicate FIRES on empty-book + DNS-disabled (immediate);
     - predicate does NOT fire on a non-empty book;
     - predicate does NOT fire under --connect;
     - one-shot guard: the second call is a no-op. *)

open Camlcoin

(* ---- the 40 verbatim seed IPs from the spec (independent oracle) ------- *)
let expected_seed_ips = [
  "2.121.116.198:8333"; "3.86.179.235:8333"; "4.2.51.251:8333";
  "5.2.23.226:8333"; "12.11.29.34:8333"; "14.49.142.41:8333";
  "18.27.125.103:8333"; "23.93.18.82:8333"; "24.16.202.74:8333";
  "27.83.109.113:8333"; "31.41.23.249:8333"; "34.65.45.157:8333";
  "35.78.97.86:8333"; "37.15.61.236:8333"; "38.52.3.192:8333";
  "40.160.1.232:8333"; "44.223.26.178:8333"; "45.19.130.200:8333";
  "46.126.216.3:8333"; "47.90.137.13:8333"; "50.4.123.66:8333";
  "51.154.0.142:8333"; "52.182.185.242:8333"; "60.241.1.72:8333";
  "62.34.57.141:8333"; "63.247.147.166:8333"; "64.23.97.128:8333";
  "65.94.134.253:8333"; "66.35.84.14:8333"; "67.4.139.122:8333";
  "68.61.69.53:8333"; "69.4.94.226:8333"; "70.44.20.24:8333";
  "71.56.178.136:8333"; "72.88.192.74:8333"; "73.42.33.255:8333";
  "74.48.195.218:8333"; "75.80.3.4:8333"; "76.124.35.108:8333";
  "77.38.72.37:8333";
]

(* ===================================================================
   Case 1: mainnet carries EXACTLY the 40 spec seed IPs, verbatim.
   =================================================================== *)
let test_mainnet_seed_list_verbatim () =
  Alcotest.(check int) "mainnet has exactly 40 fixed seeds"
    40 (List.length Consensus.mainnet.Consensus.fixed_seeds);
  Alcotest.(check (list string)) "fixed seeds match the spec verbatim + order"
    expected_seed_ips Consensus.mainnet.Consensus.fixed_seeds

(* ===================================================================
   Case 2: every seed parses to a ROUTABLE IPv4 with port 8333.
   =================================================================== *)
let test_seeds_parse_routable_ipv4_8333 () =
  List.iter (fun entry ->
    match Peer_manager.parse_fixed_seed entry with
    | None -> Alcotest.failf "seed %S failed to parse as ip:port" entry
    | Some (ip, port) ->
      Alcotest.(check int) (Printf.sprintf "%s port is 8333" entry) 8333 port;
      Alcotest.(check bool)
        (Printf.sprintf "%s host %S is routable IPv4" entry ip)
        true (Peer_manager.is_routable ip);
      (* dotted-quad shape: four integer octets *)
      (match String.split_on_char '.' ip with
       | [_; _; _; _] -> ()
       | _ -> Alcotest.failf "%s host %S is not dotted-quad IPv4" entry ip)
  ) Consensus.mainnet.Consensus.fixed_seeds

(* ===================================================================
   Case 3: non-mainnet networks carry NO fixed seeds.
   =================================================================== *)
let test_non_mainnet_have_no_fixed_seeds () =
  Alcotest.(check (list string)) "testnet3 has no fixed seeds"
    [] Consensus.testnet.Consensus.fixed_seeds;
  Alcotest.(check (list string)) "testnet4 has no fixed seeds"
    [] Consensus.testnet4.Consensus.fixed_seeds;
  Alcotest.(check (list string)) "regtest has no fixed seeds"
    [] Consensus.regtest.Consensus.fixed_seeds

(* ===================================================================
   Case 4: predicate FIRES on empty-book + DNS-disabled (immediate path).
   Injects all 40 routable IPs and sets the one-shot guard.
   =================================================================== *)
let test_fires_on_empty_book_dns_off () =
  let config = { Peer_manager.default_config with dns_seed = false } in
  let pm = Peer_manager.create ~config Consensus.mainnet in
  (* Pre-condition: book empty, guard clear *)
  Alcotest.(check int) "book starts empty"
    0 (Hashtbl.length pm.Peer_manager.known_addrs);
  let fired = Peer_manager.maybe_add_fixed_seeds pm in
  Alcotest.(check bool) "predicate fires (DNS off + empty book)" true fired;
  Alcotest.(check int) "all 40 routable seeds added to the book"
    40 (Hashtbl.length pm.Peer_manager.known_addrs);
  Alcotest.(check bool) "one-shot guard is now set"
    true pm.Peer_manager.fixed_seeds_added;
  (* every added entry carries the FixedSeed source tag *)
  Hashtbl.iter (fun _addr info ->
    Alcotest.(check bool) "entry source is FixedSeed"
      true (info.Peer_manager.source = Peer_manager.FixedSeed)
  ) pm.Peer_manager.known_addrs

(* ===================================================================
   Case 5: one-shot guard — a second call after firing is a no-op.
   =================================================================== *)
let test_one_shot_guard () =
  let config = { Peer_manager.default_config with dns_seed = false } in
  let pm = Peer_manager.create ~config Consensus.mainnet in
  let first = Peer_manager.maybe_add_fixed_seeds pm in
  Alcotest.(check bool) "first call fires" true first;
  let count_after_first = Hashtbl.length pm.Peer_manager.known_addrs in
  let second = Peer_manager.maybe_add_fixed_seeds pm in
  Alcotest.(check bool) "second call is a no-op (guard set)" false second;
  Alcotest.(check int) "book unchanged on the second call"
    count_after_first (Hashtbl.length pm.Peer_manager.known_addrs)

(* ===================================================================
   Case 6: does NOT fire on a NON-EMPTY book (DNS / addr already populated).
   =================================================================== *)
let test_no_fire_on_non_empty_book () =
  (* DNS disabled so only the book-empty predicate can hold it back *)
  let config = { Peer_manager.default_config with dns_seed = false } in
  let pm = Peer_manager.create ~config Consensus.mainnet in
  (* Simulate a DNS-resolved address already in the book *)
  Peer_manager.add_known_addr pm {
    Peer_manager.address = "8.8.8.8";
    port = 8333;
    services = 1L;
    last_connected = 0.0;
    last_attempt = 0.0;
    last_success = 0.0;
    failures = 0;
    banned_until = 0.0;
    source = Peer_manager.Dns;
    table_status = Peer_manager.NotInTable;
  };
  Alcotest.(check bool) "pre-condition: book is non-empty"
    true (Hashtbl.length pm.Peer_manager.known_addrs > 0);
  let fired = Peer_manager.maybe_add_fixed_seeds pm in
  Alcotest.(check bool) "predicate does NOT fire on a non-empty book"
    false fired;
  Alcotest.(check int) "book still holds only the pre-existing entry"
    1 (Hashtbl.length pm.Peer_manager.known_addrs);
  Alcotest.(check bool) "guard NOT set when it did not fire"
    false pm.Peer_manager.fixed_seeds_added

(* ===================================================================
   Case 7: does NOT fire under --connect (pinned peer set).
   =================================================================== *)
let test_no_fire_under_connect () =
  (* DNS off + empty book would otherwise fire immediately; --connect must
     veto it (Core folds -connect into the fixed-seed-off path). *)
  let config = { Peer_manager.default_config with dns_seed = false } in
  let pm = Peer_manager.create ~config Consensus.mainnet in
  Peer_manager.set_connect_peers pm [("203.0.113.7", 8333)];
  Alcotest.(check bool) "pre-condition: connect_only is true"
    true (Peer_manager.connect_only pm);
  let fired = Peer_manager.maybe_add_fixed_seeds pm in
  Alcotest.(check bool) "predicate does NOT fire under --connect" false fired;
  Alcotest.(check int) "no fixed seeds injected under --connect"
    0 (Hashtbl.length pm.Peer_manager.known_addrs)

(* ===================================================================
   Case 8: does NOT fire within the 60s grace window when DNS is enabled
            (gives DNS / -addnode / -seednode time to populate addrman).
   =================================================================== *)
let test_no_fire_within_grace_when_dns_on () =
  (* DNS enabled (default) + empty book + fresh start_ts ⇒ grace not elapsed
     ⇒ must not fire yet. *)
  let pm = Peer_manager.create Consensus.mainnet in
  pm.Peer_manager.start_ts <- Unix.gettimeofday ();  (* clock just started *)
  Alcotest.(check bool) "DNS is enabled by default"
    true pm.Peer_manager.config.Peer_manager.dns_seed;
  let fired = Peer_manager.maybe_add_fixed_seeds pm in
  Alcotest.(check bool)
    "no fire within 60s grace when DNS is on" false fired;
  Alcotest.(check int) "book stays empty during grace"
    0 (Hashtbl.length pm.Peer_manager.known_addrs);
  (* Now backdate start_ts past the 60s window: it must fire. *)
  pm.Peer_manager.start_ts <- Unix.gettimeofday () -. 61.0;
  let fired2 = Peer_manager.maybe_add_fixed_seeds pm in
  Alcotest.(check bool) "fires after 60s grace elapses" true fired2;
  Alcotest.(check int) "all 40 seeds added after grace"
    40 (Hashtbl.length pm.Peer_manager.known_addrs)

(* ===================================================================
   Case 9: non-mainnet does NOT fire even with empty book + DNS off
            (empty fixedSeeds list ⇒ disabled).
   =================================================================== *)
let test_no_fire_on_testnet () =
  let config = { Peer_manager.default_config with dns_seed = false } in
  let pm = Peer_manager.create ~config Consensus.testnet4 in
  let fired = Peer_manager.maybe_add_fixed_seeds pm in
  Alcotest.(check bool) "testnet4 has no fixed-seed fallback" false fired;
  Alcotest.(check int) "no seeds injected on testnet4"
    0 (Hashtbl.length pm.Peer_manager.known_addrs)

(* ===================================================================
   Case 10: PRODUCTION-ORDERING replay (the dead-code regression test).

   Reproduces the EXACT sequence the wired start() path runs on mainnet
   with --nodnsseed (peer_manager.ml ~2451-2481):
     (a) DNS resolution is skipped (dns_seed = false);
     (b) the hostname-fallback block runs FIRST and parks the curated
         DNS-seed HOSTNAMES ("seed.bitcoin.sipa.be", ...) in known_addrs
         via add_known_addr (is_routable returns true for any non-dotted
         string, so the hostnames are admitted);
     (c) maybe_add_fixed_seeds runs AFTER, against that already-populated
         book.

   The OLD gate was `Hashtbl.length pm.known_addrs <> 0`.  After step (b)
   the book holds >=1 admitted hostname placeholder (e.g.
   "dnsseed.bluematt.me" survives the routable filter; the 4-dot hostnames
   are dropped by is_routable's dotted-quad branch), so the old predicate
   is ALWAYS non-empty here → returns false → the 40 fixed seeds NEVER
   inject in production (dead code).  This test therefore FAILS on the unfixed
   gating ("fixed seeds DID inject" = false) and PASSES only with the
   IP-literal-only emptiness check (routable_ip_addr_count), which sees
   zero usable IP peers among the parked hostnames and fires.

   This exercises the WIRED path: same call sequence, same functions
   (get_fallback_peers + add_known_addr + maybe_add_fixed_seeds) that
   start() invokes.
   =================================================================== *)
let test_production_ordering_hostname_fallback_then_fixed_seeds () =
  let config = { Peer_manager.default_config with dns_seed = false } in
  let pm = Peer_manager.create ~config Consensus.mainnet in
  (* (a) DNS skipped (dns_seed=false): start() adds nothing here. *)
  Alcotest.(check int) "book empty before hostname fallback"
    0 (Hashtbl.length pm.Peer_manager.known_addrs);
  (* (b) hostname-fallback block — EXACTLY as start() ~2472-2474. *)
  let fallback = Peer_manager.get_fallback_peers pm.Peer_manager.network in
  Alcotest.(check int) "mainnet hostname fallback yields 3 placeholders"
    (List.length Peer_manager.mainnet_fallback_peers) (List.length fallback);
  List.iter (Peer_manager.add_known_addr pm) fallback;
  (* At least one hostname placeholder is admitted (is_routable returns true
     for a non-dotted-quad string; e.g. "dnsseed.bluematt.me" has 3 dot-parts
     so it survives the routable filter), so the raw book is now NON-empty.
     This is the exact state that defeated the old empty-book gate. *)
  let parked = Hashtbl.length pm.Peer_manager.known_addrs in
  Alcotest.(check bool) "raw book is NON-empty after hostname fallback"
    true (parked > 0);
  (* ...but every parked entry is a hostname, NOT a usable IP literal, so
     the Core-faithful emptiness check sees zero usable IP peers. *)
  Hashtbl.iter (fun addr _info ->
    Alcotest.(check bool)
      (Printf.sprintf "%S is a hostname placeholder, not an IP literal" addr)
      false (Peer_manager.is_ip_literal addr)
  ) pm.Peer_manager.known_addrs;
  Alcotest.(check int)
    "zero usable IP peers in the book (only hostname placeholders)"
    0 (Peer_manager.routable_ip_addr_count pm);
  (* (c) maybe_add_fixed_seeds AFTER the hostname fallback — must FIRE.
     Under the OLD gate (`Hashtbl.length known_addrs <> 0`) this returns
     false here because the book already holds >=1 hostname placeholder —
     that is the dead-code defect this case reproduces. *)
  let fired = Peer_manager.maybe_add_fixed_seeds pm in
  Alcotest.(check bool)
    "fixed seeds DID inject after the hostname fallback (production order)"
    true fired;
  (* All 40 IP seeds are now present, on TOP of the parked hostname(s). *)
  Alcotest.(check int)
    "40 fixed-seed IPs added on top of the hostname placeholder(s)"
    40 (Peer_manager.routable_ip_addr_count pm);
  Alcotest.(check int)
    "book now holds the parked hostname(s) + 40 IP seeds"
    (parked + 40)
    (Hashtbl.length pm.Peer_manager.known_addrs);
  Alcotest.(check bool) "one-shot guard set after firing"
    true pm.Peer_manager.fixed_seeds_added

(* ===================================================================
   Case 11: DNS-FIRST preserved — when DNS resolves REAL IP peers first,
            the fixed-seed fallback must NOT fire (Core never falls back
            while addrman holds usable IPs).  Guards against a naive
            "reorder before fallback" fix that would clobber DNS-first.
   =================================================================== *)
let test_dns_first_preserved_real_ip_suppresses_fixed_seeds () =
  let config = { Peer_manager.default_config with dns_seed = false } in
  let pm = Peer_manager.create ~config Consensus.mainnet in
  (* Simulate DNS having resolved a real routable IP into the book first
     (start() does Hashtbl.replace for resolved seed_addrs). *)
  Peer_manager.add_known_addr pm {
    Peer_manager.address = "8.8.8.8";
    port = 8333;
    services = 1L;
    last_connected = 0.0;
    last_attempt = 0.0;
    last_success = 0.0;
    failures = 0;
    banned_until = 0.0;
    source = Peer_manager.Dns;
    table_status = Peer_manager.NotInTable;
  };
  (* Also park the hostname fallbacks (production runs both). *)
  List.iter (Peer_manager.add_known_addr pm)
    (Peer_manager.get_fallback_peers pm.Peer_manager.network);
  Alcotest.(check int) "one real IP peer counted (hostnames excluded)"
    1 (Peer_manager.routable_ip_addr_count pm);
  let fired = Peer_manager.maybe_add_fixed_seeds pm in
  Alcotest.(check bool)
    "fixed seeds do NOT fire while a real IP peer is present (DNS-first)"
    false fired;
  let any_fixed_seed =
    Hashtbl.fold (fun _ info acc ->
      acc || info.Peer_manager.source = Peer_manager.FixedSeed)
      pm.Peer_manager.known_addrs false
  in
  Alcotest.(check bool) "no fixed seeds injected when a real IP exists"
    false any_fixed_seed

let () =
  Alcotest.run "fixedseeds_fallback" [
    "fixed_seeds", [
      Alcotest.test_case "mainnet 40 seeds verbatim"        `Quick test_mainnet_seed_list_verbatim;
      Alcotest.test_case "seeds parse routable IPv4:8333"   `Quick test_seeds_parse_routable_ipv4_8333;
      Alcotest.test_case "non-mainnet have none"            `Quick test_non_mainnet_have_no_fixed_seeds;
      Alcotest.test_case "fires on empty-book + DNS off"    `Quick test_fires_on_empty_book_dns_off;
      Alcotest.test_case "one-shot guard"                   `Quick test_one_shot_guard;
      Alcotest.test_case "no fire on non-empty book"        `Quick test_no_fire_on_non_empty_book;
      Alcotest.test_case "no fire under --connect"          `Quick test_no_fire_under_connect;
      Alcotest.test_case "no fire within grace (DNS on)"    `Quick test_no_fire_within_grace_when_dns_on;
      Alcotest.test_case "no fire on testnet4"              `Quick test_no_fire_on_testnet;
      Alcotest.test_case "PROD-ORDER: hostname fallback then fixed seeds inject" `Quick test_production_ordering_hostname_fallback_then_fixed_seeds;
      Alcotest.test_case "DNS-first preserved: real IP suppresses fixed seeds"   `Quick test_dns_first_preserved_real_ip_suppresses_fixed_seeds;
    ];
  ]
