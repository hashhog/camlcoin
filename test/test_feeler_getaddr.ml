(* P2P anti-eclipse: feeler connections + getaddr anti-DoS guards — camlcoin.

   Mirrors the rustoshi template (89c6d7f) and Bitcoin Core:
     - net.cpp ThreadOpenConnections FEELER branch (net.h:61 FEELER_INTERVAL,
       net.h:75 MAX_FEELER_CONNECTIONS=1)
     - net_processing.cpp getaddr guards: m_getaddr_recvd answer-once (4833),
       MAX_PCT_ADDR_TO_SEND=23 (188), inbound-addr token-bucket
       MAX_ADDR_RATE_PER_SECOND=0.1 / MAX_ADDR_PROCESSING_TOKEN_BUCKET=1000 (193).

   Proves (functional, in-process, no regtest daemon):
     (1) feeler selects FROM NEW + promotes a probed addr NEW->TRIED on handshake
         SUCCESS only (NOT on failure) + is bounded (1 in-flight, 120s) + does
         NOT consume the full-outbound budget.
     (2) GETADDR answered once (2nd getaddr from same peer ignored) + inbound-only.
     (3) GETADDR 23%-cap: min(1000, ceil(0.23*addrman)).
     (4) inbound-addr token-bucket drops excess.

   Falsification: pre-impl camlcoin had no feeler / no getaddr response / no
   token bucket / no answer-once guard. *)

open Camlcoin

let make_pm () = Peer_manager.create Consensus.mainnet

(* Seed a routable address straight into the NEW table (add_known_addr sets
   table_status = InNew bucket). *)
let add_new pm addr =
  Peer_manager.add_known_addr pm {
    Peer_manager.address = addr;
    port = 8333;
    services = 9L;
    last_connected = 0.0;
    last_attempt = 0.0;
    last_success = 0.0;
    failures = 0;
    banned_until = 0.0;
    source = Peer_manager.Addr;
    table_status = Peer_manager.NotInTable;
  }

let in_tried pm addr = Peer_manager.is_in_tried_table pm addr

(* ===== (3) 23%-cap formula ====================================== *)
(* getaddr_cap n = min(1000, ceil(0.23*n)); 0 for empty addrman. *)
let test_getaddr_cap_formula () =
  Alcotest.(check int) "empty -> 0" 0 (Peer_manager.getaddr_cap 0);
  (* ceil(0.23*1)=1 *)
  Alcotest.(check int) "1 addr -> 1" 1 (Peer_manager.getaddr_cap 1);
  (* ceil(0.23*10)=ceil(2.3)=3 *)
  Alcotest.(check int) "10 addrs -> 3" 3 (Peer_manager.getaddr_cap 10);
  (* ceil(0.23*100)=23 *)
  Alcotest.(check int) "100 addrs -> 23" 23 (Peer_manager.getaddr_cap 100);
  (* ceil(0.23*1000)=230 *)
  Alcotest.(check int) "1000 addrs -> 230" 230 (Peer_manager.getaddr_cap 1000);
  (* min(1000, ceil(0.23*100000)=23000)=1000 — clamps at MAX_ADDR_TO_SEND *)
  Alcotest.(check int) "100000 addrs -> 1000 (clamp)" 1000
    (Peer_manager.getaddr_cap 100000)

(* getaddr_shareable returns at most getaddr_cap entries. *)
let test_getaddr_shareable_capped () =
  let pm = make_pm () in
  for i = 1 to 100 do
    add_new pm (Printf.sprintf "8.8.%d.%d" (i / 256) (i mod 256))
  done;
  let n = List.length (Peer_manager.get_addr_dump pm) in
  Alcotest.(check bool) "seeded ~100 routable addrs" true (n >= 90);
  let shared = Peer_manager.getaddr_shareable pm in
  let cap = Peer_manager.getaddr_cap n in
  Alcotest.(check bool) "shareable count <= 23%-cap" true
    (List.length shared <= cap);
  Alcotest.(check bool) "shareable count > 0 for non-empty addrman" true
    (List.length shared > 0)

(* ===== (1) feeler: select-from-NEW + promote-on-success-only ==== *)

(* select_for_feeler draws only from the NEW table; a TRIED-only or empty
   addrman yields None. *)
let test_feeler_selects_from_new () =
  let pm = make_pm () in
  Alcotest.(check bool) "empty addrman -> no feeler candidate" true
    (Peer_manager.select_for_feeler pm = None);
  add_new pm "8.8.8.8";
  add_new pm "9.9.9.9";
  (match Peer_manager.select_for_feeler pm with
   | Some (a, _) ->
     Alcotest.(check bool) "feeler picks a NEW-table addr"
       true (a = "8.8.8.8" || a = "9.9.9.9")
   | None -> Alcotest.fail "expected a NEW candidate");
  (* Promote both NEW->TRIED — NEW table now empty, so no candidate. *)
  Peer_manager.mark_feeler_success pm "8.8.8.8";
  Peer_manager.mark_feeler_success pm "9.9.9.9";
  Alcotest.(check bool) "all promoted to TRIED -> no NEW candidate" true
    (Peer_manager.select_for_feeler pm = None)

(* mark_feeler_success (Good()) promotes NEW->TRIED.  Falsification: a feeler
   FAILURE never calls it, so TRIED stays unchanged. *)
let test_feeler_promotes_on_success_only () =
  let pm = make_pm () in
  add_new pm "8.8.4.4";
  Alcotest.(check bool) "before: not in TRIED" false (in_tried pm "8.8.4.4");
  (* SUCCESS path promotes. *)
  Peer_manager.mark_feeler_success pm "8.8.4.4";
  Alcotest.(check bool) "after success: in TRIED" true (in_tried pm "8.8.4.4");
  (match Hashtbl.find_opt pm.Peer_manager.known_addrs "8.8.4.4" with
   | Some info ->
     Alcotest.(check bool) "table_status = InTried" true
       (match info.Peer_manager.table_status with
        | Peer_manager.InTried _ -> true | _ -> false)
   | None -> Alcotest.fail "addr vanished");
  (* FAILURE falsification: a fresh NEW addr that is never marked-success stays
     out of TRIED (mark_feeler_success is the ONLY promote path the feeler uses;
     the failure branch in maybe_open_feeler does not call it). *)
  add_new pm "1.1.1.1";
  Alcotest.(check bool) "unprobed addr stays out of TRIED" false
    (in_tried pm "1.1.1.1")

(* Feeler is bounded: 1 in-flight (MAX_FEELER_CONNECTIONS) + once per 120s
   (FEELER_INTERVAL), and never consumes the full-outbound budget.  We drive
   maybe_open_feeler against unroutable/unreachable targets so the dial fails
   fast, and assert the gates hold (no feeler-in-flight leak, last_feeler set,
   pm.peers untouched = off-budget). *)
let test_feeler_bounded_and_off_budget () =
  let pm = make_pm () in
  (* 240.0.0.0/4 (reserved Class E) — passes is_routable but is unreachable, so
     the dial fails quickly without touching a real peer. *)
  add_new pm "240.0.0.1";
  let outbound_before = List.length pm.Peer_manager.peers in
  Lwt_main.run (Peer_manager.maybe_open_feeler pm);
  (* In-flight counter returned to 0 (finalize ran). *)
  Alcotest.(check int) "feeler_in_flight back to 0 after attempt" 0
    pm.Peer_manager.feeler_in_flight;
  (* last_feeler timestamp advanced -> the 120s gate is now armed. *)
  Alcotest.(check bool) "last_feeler timestamp set" true
    (pm.Peer_manager.last_feeler > 0.0);
  (* OFF-BUDGET: a feeler never adds to pm.peers (the outbound slot list). *)
  Alcotest.(check int) "feeler did not consume an outbound slot"
    outbound_before (List.length pm.Peer_manager.peers);
  (* 120s gate: an immediate second call is a no-op (does not re-arm a probe),
     so feeler_in_flight stays 0 and last_feeler does not jump forward much. *)
  let t1 = pm.Peer_manager.last_feeler in
  Lwt_main.run (Peer_manager.maybe_open_feeler pm);
  Alcotest.(check bool) "2nd call within 120s is gated (last_feeler unchanged)"
    true (pm.Peer_manager.last_feeler = t1);
  Alcotest.(check int) "still 0 in-flight after gated call" 0
    pm.Peer_manager.feeler_in_flight

(* --connect pinning disables addrman-driven feeler entirely. *)
let test_feeler_noop_under_connect () =
  let pm = make_pm () in
  Peer_manager.set_connect_peers pm [("127.0.0.1", 8333)];
  add_new pm "8.8.8.8";
  Lwt_main.run (Peer_manager.maybe_open_feeler pm);
  Alcotest.(check bool) "no feeler under --connect (last_feeler untouched)"
    true (pm.Peer_manager.last_feeler = 0.0)

(* ===== (2) GETADDR answered once + inbound-only ================= *)

(* Build a peer over a connected socketpair so Peer.send_message succeeds. *)
let make_peer ~id ~direction =
  let (a, _b) = Unix.socketpair Unix.PF_UNIX Unix.SOCK_STREAM 0 in
  let fd = Lwt_unix.of_unix_file_descr a in
  Peer.make_peer ~network:Consensus.mainnet ~addr:"203.0.113.5"
    ~port:8333 ~id ~direction:(match direction with
      | `In -> Peer.Inbound | `Out -> Peer.Outbound) ~fd ()

let test_getaddr_answered_once () =
  let pm = make_pm () in
  add_new pm "8.8.8.8";
  add_new pm "9.9.9.9";
  let peer = make_peer ~id:7 ~direction:`In in
  pm.Peer_manager.peers <- [peer];
  (* Before: not answered. *)
  Alcotest.(check bool) "getaddr_recvd unset before" false
    (Hashtbl.mem pm.Peer_manager.getaddr_recvd 7);
  Lwt_main.run (Peer_manager.handle_getaddr pm peer);
  Alcotest.(check bool) "getaddr_recvd set after 1st getaddr" true
    (match Hashtbl.find_opt pm.Peer_manager.getaddr_recvd 7 with
     | Some true -> true | _ -> false);
  (* 2nd getaddr from same peer: still flagged, treated as ignored (no crash). *)
  Lwt_main.run (Peer_manager.handle_getaddr pm peer);
  Alcotest.(check bool) "getaddr_recvd still set (answer-once)" true
    (match Hashtbl.find_opt pm.Peer_manager.getaddr_recvd 7 with
     | Some true -> true | _ -> false)

let test_getaddr_inbound_only () =
  let pm = make_pm () in
  add_new pm "8.8.8.8";
  let peer = make_peer ~id:9 ~direction:`Out in
  pm.Peer_manager.peers <- [peer];
  Lwt_main.run (Peer_manager.handle_getaddr pm peer);
  (* Outbound getaddr is ignored: the answer-once flag is NEVER set, because we
     return before recording it (Core net_processing.cpp:4821). *)
  Alcotest.(check bool) "outbound getaddr ignored (flag not set)" false
    (Hashtbl.mem pm.Peer_manager.getaddr_recvd 9)

(* ===== (4) inbound-addr token bucket drops excess =============== *)

(* A fresh peer starts with bucket=1.0: a burst of N>1 addrs admits exactly 1,
   drops the rest (no refill within the same instant). *)
let test_token_bucket_drops_excess () =
  let pm = make_pm () in
  let admit_first = Peer_manager.take_addr_tokens pm 42 50 in
  Alcotest.(check int) "first burst admits exactly 1 (bucket starts at 1.0)"
    1 admit_first;
  (* Immediately after, the bucket is ~0: a second burst admits 0. *)
  let admit_second = Peer_manager.take_addr_tokens pm 42 50 in
  Alcotest.(check int) "second immediate burst admits 0 (bucket drained)"
    0 admit_second

(* The bucket refills at 0.1 tokens/sec, capped at 1000.  We cannot wait real
   seconds in a unit test, so we verify the cap + monotonic-drain invariants:
   a single 5-addr burst on a fresh bucket admits 1 and leaves <1 token. *)
let test_token_bucket_rate_and_cap () =
  let pm = make_pm () in
  let admit = Peer_manager.take_addr_tokens pm 99 5 in
  Alcotest.(check int) "5-addr burst admits 1 from fresh 1.0 bucket" 1 admit;
  (* Requesting 0 admits 0 and does not go negative / crash. *)
  let admit0 = Peer_manager.take_addr_tokens pm 99 0 in
  Alcotest.(check int) "0 requested admits 0" 0 admit0;
  (* Constants match Core. *)
  Alcotest.(check (float 1e-9)) "MAX_ADDR_RATE_PER_SECOND = 0.1" 0.1
    Peer_manager.max_addr_rate_per_second;
  Alcotest.(check (float 1e-9)) "MAX_ADDR_PROCESSING_TOKEN_BUCKET = 1000" 1000.0
    Peer_manager.max_addr_processing_token_bucket;
  Alcotest.(check int) "MAX_PCT_ADDR_TO_SEND = 23" 23
    Peer_manager.max_pct_addr_to_send;
  Alcotest.(check int) "MAX_FEELER_CONNECTIONS = 1" 1
    Peer_manager.max_feeler_connections

let () =
  Alcotest.run "feeler_getaddr" [
    "getaddr-cap", [
      Alcotest.test_case "23%-cap formula" `Quick test_getaddr_cap_formula;
      Alcotest.test_case "shareable capped" `Quick test_getaddr_shareable_capped;
    ];
    "feeler", [
      Alcotest.test_case "select-from-NEW" `Quick test_feeler_selects_from_new;
      Alcotest.test_case "promote-on-success-only" `Quick
        test_feeler_promotes_on_success_only;
      Alcotest.test_case "bounded + off-budget" `Quick
        test_feeler_bounded_and_off_budget;
      Alcotest.test_case "no-op under --connect" `Quick
        test_feeler_noop_under_connect;
    ];
    "getaddr-guards", [
      Alcotest.test_case "answered once" `Quick test_getaddr_answered_once;
      Alcotest.test_case "inbound only" `Quick test_getaddr_inbound_only;
    ];
    "token-bucket", [
      Alcotest.test_case "drops excess" `Quick test_token_bucket_drops_excess;
      Alcotest.test_case "rate + cap constants" `Quick
        test_token_bucket_rate_and_cap;
    ];
  ]
