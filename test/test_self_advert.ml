(* Self-address advertisement (Bitcoin Core parity):
   --externalip / --discover / MaybeSendAddr / getnetworkinfo.localaddresses.

   Covers the four pieces the port has to get right:
     1. the routable filter (Core CNetAddr::IsRoutable) + IP parsing,
     2. discovery from an outbound peer's VERSION addr_recv (distinct-netgroup
        scoring, >= 2 before use, inbound only scores, 3h expiry, cap 8),
     3. the addr / addrv2 message contents, including the LISTEN port — both
        as a built payload and as bytes read back off a real socket,
     4. the gates: IBD (timer untouched so the first send happens after IBD),
        block-relay-only, not-listening, the per-peer Poisson timer. *)

open Camlcoin

let listen_port = 18555

let make_pm () =
  let pm = Peer_manager.create Consensus.mainnet in
  pm.Peer_manager.listen_port <- listen_port;
  pm

let ip s = match Peer_manager.ip16_of_string s with
  | Some b -> b
  | None -> Alcotest.failf "unparseable test IP %s" s

(* A peer over a connected socketpair; the other end is returned so a test
   can read what we sent.  [addr_recv] is what the peer says it sees us at. *)
let make_peer ?(addr_recv : (string * int) option) ~id ~addr ~direction () =
  let (a, b) = Unix.socketpair Unix.PF_UNIX Unix.SOCK_STREAM 0 in
  let peer = Peer.make_peer ~network:Consensus.mainnet ~addr ~port:8333 ~id
      ~direction ~fd:(Lwt_unix.of_unix_file_descr a) () in
  (match addr_recv with
   | None -> ()
   | Some (s, port) ->
     peer.Peer.version_msg <- Some {
       Types.protocol_version = 70016l; services = 0x409L;
       timestamp = Int64.of_float (Unix.gettimeofday ());
       addr_recv = { Types.services = 0L; addr = Cstruct.of_string (ip s); port };
       addr_from = Peer.make_local_addr ();
       nonce = 42L; user_agent = "/test/"; start_height = 0l; relay = true });
  peer.Peer.handshake_complete <- true;
  peer.Peer.state <- Peer.Ready;
  (peer, b)

(* ---- 1. routable filter + parsing ---- *)

let test_routable_filter () =
  let r s = Peer_manager.is_routable_ip16 (ip s) in
  List.iter (fun s -> Alcotest.(check bool) (s ^ " routable") true (r s))
    [ "1.2.3.4"; "8.8.8.8"; "76.38.7.169"; "2600:1f18::1"; "2a01:4f8::1" ];
  List.iter (fun s -> Alcotest.(check bool) (s ^ " NOT routable") false (r s))
    [ "127.0.0.1"; "10.1.2.3"; "192.168.1.128"; "172.16.0.1"; "169.254.1.1";
      "100.64.0.1"; "0.0.0.0"; "192.0.2.1"; "198.51.100.7"; "203.0.113.5";
      "::"; "::1"; "fe80::1"; "fd00::1"; "fc00::5"; "2001:db8::1";
      "2001:10::1"; "ff02::1"; "::ffff:127.0.0.1"; "::ffff:10.0.0.1" ];
  (* the string-level predicate used on peer addresses *)
  Alcotest.(check bool) "hostname is not routable" false
    (Peer_manager.is_routable_ip_string "seed.bitcoin.sipa.be");
  Alcotest.(check bool) "8.8.8.8 string routable" true
    (Peer_manager.is_routable_ip_string "8.8.8.8")

let test_ip_parse_roundtrip () =
  let rt s = Peer_manager.ip16_to_string (ip s) in
  Alcotest.(check string) "v4" "1.2.3.4" (rt "1.2.3.4");
  Alcotest.(check string) "v4-mapped prints as v4" "1.2.3.4" (rt "::ffff:1.2.3.4");
  Alcotest.(check string) "v6 compressed" "2001:db8::1" (rt "2001:0db8:0:0:0:0:0:1");
  Alcotest.(check string) "v6 bracketed" "2600:1f18::1" (rt "[2600:1f18::1]");
  Alcotest.(check bool) "v4-mapped wire form" true
    (Peer_manager.ip16_is_v4 (ip "1.2.3.4"));
  List.iter (fun s ->
    Alcotest.(check bool) (s ^ " rejected") true
      (Peer_manager.ip16_of_string s = None))
    [ "1.2.3"; "1.2.3.256"; "host.example"; "1::2::3"; "12345::1"; "" ];
  (* --externalip parsing *)
  (match Cli.parse_externalip "1.2.3.4" with
   | Ok (b, 0) -> Alcotest.(check string) "bare ip" "1.2.3.4" (Peer_manager.ip16_to_string b)
   | _ -> Alcotest.fail "bare IP must parse with port 0 (= listen port)");
  (match Cli.parse_externalip "1.2.3.4:9999" with
   | Ok (_, 9999) -> ()
   | _ -> Alcotest.fail "ip:port must parse");
  (match Cli.parse_externalip "[2600:1f18::1]:8333" with
   | Ok (_, 8333) -> ()
   | _ -> Alcotest.fail "[v6]:port must parse");
  (match Cli.parse_externalip "2600:1f18::1" with
   | Ok (_, 0) -> ()
   | _ -> Alcotest.fail "bare v6 must parse");
  Alcotest.(check bool) "bad port rejected" true
    (Result.is_error (Cli.parse_externalip "1.2.3.4:0"));
  Alcotest.(check bool) "hostname rejected" true
    (Result.is_error (Cli.parse_externalip "example.com:8333"));
  (* -discover soft-default *)
  let c = Cli.default_config in
  Alcotest.(check bool) "discover default on" true (Cli.effective_discover c);
  Alcotest.(check bool) "externalip turns discover off" false
    (Cli.effective_discover { c with Cli.externalip = ["1.2.3.4"] });
  Alcotest.(check bool) "explicit --discover wins" true
    (Cli.effective_discover { c with Cli.externalip = ["1.2.3.4"]; discover = Some true })

let test_externalip_manual () =
  let pm = make_pm () in
  Alcotest.(check bool) "routable accepted" true
    (Peer_manager.add_external_ip pm (ip "1.2.3.4") 0);
  Alcotest.(check bool) "private refused" false
    (Peer_manager.add_external_ip pm (ip "192.168.1.128") 0);
  Alcotest.(check (list (triple string int int))) "localaddresses"
    [ ("1.2.3.4", listen_port, 4) ] (Peer_manager.local_addresses pm);
  ignore (Peer_manager.add_external_ip pm (ip "5.6.7.8") 9999);
  Alcotest.(check (list (triple string int int))) "explicit port kept"
    [ ("1.2.3.4", listen_port, 4); ("5.6.7.8", 9999, 4) ]
    (Peer_manager.local_addresses pm)

(* ---- 2. discovery ---- *)

let test_discovery_from_addr_recv () =
  let pm = make_pm () in
  let now = Unix.gettimeofday () in
  (* outbound peer 8.8.8.8 says it sees us at 1.2.3.4 (with its view of our
     EPHEMERAL port, 51234 — must be replaced by our listen port) *)
  let (p1, _) = make_peer ~addr_recv:("1.2.3.4", 51234) ~id:1 ~addr:"8.8.8.8"
      ~direction:Peer.Outbound () in
  Peer_manager.note_version_addr_recv pm p1 now;
  Alcotest.(check (list (triple string int int))) "stored with LISTEN port, score 1"
    [ ("1.2.3.4", listen_port, 1) ] (Peer_manager.local_addresses pm);
  Alcotest.(check bool) "score 1 is not yet usable" true
    (Peer_manager.local_addr_best pm now = None);
  (* same /16 again: no extra score *)
  let (p2, _) = make_peer ~addr_recv:("1.2.3.4", 1) ~id:2 ~addr:"8.8.4.4"
      ~direction:Peer.Outbound () in
  Peer_manager.note_version_addr_recv pm p2 now;
  Alcotest.(check (list (triple string int int))) "same netgroup does not add score"
    [ ("1.2.3.4", listen_port, 1) ] (Peer_manager.local_addresses pm);
  (* a second, distinct netgroup confirms -> score 2 -> usable *)
  let (p3, _) = make_peer ~addr_recv:("1.2.3.4", 2) ~id:3 ~addr:"9.9.9.9"
      ~direction:Peer.Outbound () in
  Peer_manager.note_version_addr_recv pm p3 now;
  (match Peer_manager.local_addr_best pm now with
   | Some (b, port, 2) ->
     Alcotest.(check string) "best ip" "1.2.3.4" (Peer_manager.ip16_to_string b);
     Alcotest.(check int) "best port = listen port" listen_port port
   | _ -> Alcotest.fail "score-2 discovered address must be usable");
  (* expiry: 3h without confirmation drops it *)
  Alcotest.(check (list (triple string int int))) "expired after 3h" []
    (Peer_manager.local_addrs_expire pm (now +. 3.0 *. 3600.0 +. 1.0);
     Peer_manager.local_addresses pm)

let test_discovery_filters () =
  let now = Unix.gettimeofday () in
  let pm = make_pm () in
  (* inbound peers never create an entry (Core SeenLocal) *)
  let (pin, _) = make_peer ~addr_recv:("1.2.3.4", listen_port) ~id:1
      ~addr:"8.8.8.8" ~direction:Peer.Inbound () in
  Peer_manager.note_version_addr_recv pm pin now;
  Alcotest.(check int) "inbound does not create" 0
    (List.length (Peer_manager.local_addresses pm));
  (* non-routable addr_recv *)
  let (p, _) = make_peer ~addr_recv:("192.168.1.128", 1) ~id:2 ~addr:"8.8.8.8"
      ~direction:Peer.Outbound () in
  Peer_manager.note_version_addr_recv pm p now;
  Alcotest.(check int) "private addr_recv ignored" 0
    (List.length (Peer_manager.local_addresses pm));
  (* non-routable PEER (e.g. a local bitcoind) *)
  let (p, _) = make_peer ~addr_recv:("1.2.3.4", 1) ~id:3 ~addr:"127.0.0.1"
      ~direction:Peer.Outbound () in
  Peer_manager.note_version_addr_recv pm p now;
  Alcotest.(check int) "loopback peer ignored" 0
    (List.length (Peer_manager.local_addresses pm));
  (* --discover=0 *)
  pm.Peer_manager.discover <- false;
  let (p, _) = make_peer ~addr_recv:("1.2.3.4", 1) ~id:4 ~addr:"8.8.8.8"
      ~direction:Peer.Outbound () in
  Peer_manager.note_version_addr_recv pm p now;
  Alcotest.(check int) "discover=0 ignores addr_recv" 0
    (List.length (Peer_manager.local_addresses pm));
  pm.Peer_manager.discover <- true;
  (* once an entry exists, an inbound peer DOES score it *)
  Peer_manager.note_version_addr_recv pm p now;
  Peer_manager.note_version_addr_recv pm pin now;
  Alcotest.(check (list (triple string int int))) "inbound scores existing"
    [ ("1.2.3.4", listen_port, 1) ] (Peer_manager.local_addresses pm);
  let (pin2, _) = make_peer ~addr_recv:("1.2.3.4", listen_port) ~id:5
      ~addr:"9.9.9.9" ~direction:Peer.Inbound () in
  Peer_manager.note_version_addr_recv pm pin2 now;
  Alcotest.(check (list (triple string int int))) "inbound from new group scores"
    [ ("1.2.3.4", listen_port, 2) ] (Peer_manager.local_addresses pm)

let test_discovery_cap () =
  let pm = make_pm () in
  let now = Unix.gettimeofday () in
  for i = 1 to 20 do
    ignore (Peer_manager.local_addr_confirm pm ~ip16:(ip (Printf.sprintf "5.5.5.%d" i))
              ~port:listen_port ~group:(string_of_int i) ~create:true now)
  done;
  ignore (Peer_manager.add_external_ip pm (ip "1.2.3.4") 0);
  let l = Peer_manager.local_addresses pm in
  Alcotest.(check int) "8 discovered + 1 manual" 9 (List.length l);
  Alcotest.(check bool) "manual survives" true
    (List.exists (fun (a, _, _) -> a = "1.2.3.4") l)

(* ---- 3. message contents ---- *)

let our_services () = Peer.services_to_int64 (Peer.our_services ())

let check_addr_v1 msg ~ip_s ~port =
  match msg with
  | P2p.AddrMsg [ (ts, na) ] ->
    Alcotest.(check string) "addr ip" (ip ip_s) (Cstruct.to_string na.Types.addr);
    Alcotest.(check int) "addr port" port na.Types.port;
    Alcotest.(check int64) "addr services = our VERSION services"
      (our_services ()) na.Types.services;
    let age = Unix.gettimeofday () -. Int32.to_float ts in
    Alcotest.(check bool) "addr time = now" true (age >= -1.0 && age < 60.0)
  | _ -> Alcotest.fail "expected a ONE-entry addr"

let check_addr_v2 msg ~ip_s ~port =
  match msg with
  | P2p.Addrv2Msg [ e ] ->
    Alcotest.(check bool) "addrv2 network = IPv4" true
      (e.P2p.v2_network_id = P2p.Addrv2_IPv4);
    Alcotest.(check string) "addrv2 4-byte ip" (String.sub (ip ip_s) 12 4)
      (Cstruct.to_string e.P2p.v2_addr);
    Alcotest.(check int) "addrv2 port" port e.P2p.v2_port;
    Alcotest.(check int64) "addrv2 services" (our_services ()) e.P2p.v2_services;
    let age = Unix.gettimeofday () -. Int32.to_float e.P2p.v2_time in
    Alcotest.(check bool) "addrv2 time = now" true (age >= -1.0 && age < 60.0)
  | _ -> Alcotest.fail "expected a ONE-entry addrv2"

let test_message_contents () =
  let pm = make_pm () in
  ignore (Peer_manager.add_external_ip pm (ip "1.2.3.4") 0);
  let now = Unix.gettimeofday () in
  (* legacy peer, outbound, peer at a loopback address (like a local
     bitcoind): its addr_recv is not "good", so the table entry is used *)
  let (p, _) = make_peer ~addr_recv:("127.0.0.1", 40000) ~id:1
      ~addr:"127.0.0.1" ~direction:Peer.Outbound () in
  (match Peer_manager.local_addr_msg_for_peer pm p now with
   | Some m -> check_addr_v1 m ~ip_s:"1.2.3.4" ~port:listen_port
   | None -> Alcotest.fail "must advertise to a full-relay peer out of IBD");
  (* sendaddrv2 peer gets addrv2 *)
  let (p2, _) = make_peer ~id:2 ~addr:"8.8.8.8" ~direction:Peer.Inbound () in
  p2.Peer.sendaddrv2 <- true;
  (match Peer_manager.local_addr_msg_for_peer pm p2 now with
   | Some m -> check_addr_v2 m ~ip_s:"1.2.3.4" ~port:listen_port
   | None -> Alcotest.fail "must advertise to an addrv2 peer");
  (* IPv6 addrv2 *)
  (match Peer_manager.build_local_addr_msg ~sendaddrv2:true
           ~ip16:(ip "2600:1f18::1") ~port:8333 ~services:1L ~now with
   | P2p.Addrv2Msg [ e ] ->
     Alcotest.(check bool) "v6 network id" true (e.P2p.v2_network_id = P2p.Addrv2_IPv6);
     Alcotest.(check int) "v6 16 bytes" 16 (Cstruct.length e.P2p.v2_addr)
   | _ -> Alcotest.fail "expected addrv2")

(* Bytes on the wire: send through the real Peer.send_message and read the
   message back from the other end of the socket. *)
let test_message_on_the_wire () =
  let pm = make_pm () in
  ignore (Peer_manager.add_external_ip pm (ip "1.2.3.4") 0);
  let (p, other) = make_peer ~id:1 ~addr:"127.0.0.1" ~direction:Peer.Outbound () in
  let reader = Peer.make_peer ~network:Consensus.mainnet ~addr:"127.0.0.1"
      ~port:1 ~id:99 ~direction:Peer.Inbound
      ~fd:(Lwt_unix.of_unix_file_descr other) () in
  let sent = Lwt_main.run
      (Peer_manager.maybe_send_local_addr pm p (Unix.gettimeofday ())) in
  Alcotest.(check bool) "sent" true sent;
  (match Lwt_main.run (Peer.read_message_with_timeout reader 5.0) with
   | Some m -> check_addr_v1 m ~ip_s:"1.2.3.4" ~port:listen_port
   | None -> Alcotest.fail "nothing arrived on the wire");
  (* second call: not due again (24h Poisson timer) *)
  Alcotest.(check bool) "not re-sent before the timer" false
    (Lwt_main.run (Peer_manager.maybe_send_local_addr pm p (Unix.gettimeofday ())))

(* ---- 4. gates ---- *)

let test_ibd_gate () =
  let pm = make_pm () in
  ignore (Peer_manager.add_external_ip pm (ip "1.2.3.4") 0);
  let (p, _) = make_peer ~id:1 ~addr:"8.8.8.8" ~direction:Peer.Outbound () in
  let ibd = ref true in
  pm.Peer_manager.is_ibd <- (fun () -> !ibd);
  let now = Unix.gettimeofday () in
  Alcotest.(check bool) "nothing during IBD" true
    (Peer_manager.local_addr_msg_for_peer pm p now = None);
  Alcotest.(check bool) "IBD leaves the timer untouched" false
    (Hashtbl.mem pm.Peer_manager.next_local_addr_send p.Peer.id);
  ibd := false;
  (* the next timer tick after IBD delivers the held-back first send *)
  Alcotest.(check bool) "sent on first tick after IBD" true
    (Peer_manager.local_addr_msg_for_peer pm p (now +. 60.0) <> None);
  (match Hashtbl.find_opt pm.Peer_manager.next_local_addr_send p.Peer.id with
   | Some t -> Alcotest.(check bool) "next send scheduled in the future" true (t > now +. 60.0)
   | None -> Alcotest.fail "timer not armed after send");
  (* due again once the timer passes *)
  Hashtbl.replace pm.Peer_manager.next_local_addr_send p.Peer.id (now -. 1.0);
  Alcotest.(check bool) "re-sent when the Poisson timer fires" true
    (Peer_manager.local_addr_msg_for_peer pm p now <> None)

let test_other_gates () =
  let pm = make_pm () in
  ignore (Peer_manager.add_external_ip pm (ip "1.2.3.4") 0);
  let now = Unix.gettimeofday () in
  let (brop, _) = make_peer ~id:1 ~addr:"8.8.8.8" ~direction:Peer.Outbound () in
  brop.Peer.block_relay_only <- true;
  Alcotest.(check bool) "never to block-relay-only" true
    (Peer_manager.local_addr_msg_for_peer pm brop now = None);
  let (hs, _) = make_peer ~id:2 ~addr:"8.8.8.8" ~direction:Peer.Outbound () in
  hs.Peer.handshake_complete <- false;
  Alcotest.(check bool) "not before handshake" true
    (Peer_manager.local_addr_msg_for_peer pm hs now = None);
  let (p, _) = make_peer ~id:3 ~addr:"8.8.8.8" ~direction:Peer.Outbound () in
  pm.Peer_manager.listen_port <- 0;
  Alcotest.(check bool) "not when not listening" true
    (Peer_manager.local_addr_msg_for_peer pm p now = None);
  pm.Peer_manager.listen_port <- listen_port;
  (* nothing usable at all -> nothing sent (but no crash) *)
  let pm2 = make_pm () in
  let (p, _) = make_peer ~id:4 ~addr:"8.8.8.8" ~direction:Peer.Outbound () in
  Alcotest.(check bool) "no local address -> nothing" true
    (Peer_manager.local_addr_msg_for_peer pm2 p now = None)

(* GetLocalAddrForPeer: with nothing in the table, a good peer view is used;
   outbound -> IP only (our listen port), inbound -> IP+port. *)
let test_addr_for_peer_uses_peer_view () =
  let pm = make_pm () in
  let now = Unix.gettimeofday () in
  let (pout, _) = make_peer ~addr_recv:("1.2.3.4", 51234) ~id:1
      ~addr:"8.8.8.8" ~direction:Peer.Outbound () in
  (match Peer_manager.local_addr_for_peer pm pout now with
   | Some (b, port) ->
     Alcotest.(check string) "outbound view ip" "1.2.3.4" (Peer_manager.ip16_to_string b);
     Alcotest.(check int) "outbound: our listen port, not the ephemeral" listen_port port
   | None -> Alcotest.fail "good peer view must be used");
  let (pin, _) = make_peer ~addr_recv:("1.2.3.4", 7777) ~id:2
      ~addr:"8.8.8.8" ~direction:Peer.Inbound () in
  (match Peer_manager.local_addr_for_peer pm pin now with
   | Some (_, port) -> Alcotest.(check int) "inbound: the port it dialed" 7777 port
   | None -> Alcotest.fail "good inbound view must be used");
  pm.Peer_manager.discover <- false;
  Alcotest.(check bool) "discover=0: peer view not used" true
    (Peer_manager.local_addr_for_peer pm pout now = None)

let () =
  Alcotest.run "self_advert" [
    ("routable", [
       Alcotest.test_case "routable filter" `Quick test_routable_filter;
       Alcotest.test_case "ip parse / externalip / discover" `Quick test_ip_parse_roundtrip;
       Alcotest.test_case "externalip manual entries" `Quick test_externalip_manual ]);
    ("discovery", [
       Alcotest.test_case "addr_recv discovery + scoring + expiry" `Quick test_discovery_from_addr_recv;
       Alcotest.test_case "discovery filters" `Quick test_discovery_filters;
       Alcotest.test_case "discovered cap" `Quick test_discovery_cap;
       Alcotest.test_case "GetLocalAddrForPeer peer view" `Quick test_addr_for_peer_uses_peer_view ]);
    ("message", [
       Alcotest.test_case "addr/addrv2 contents" `Quick test_message_contents;
       Alcotest.test_case "addr on the wire" `Quick test_message_on_the_wire ]);
    ("gates", [
       Alcotest.test_case "IBD gate" `Quick test_ibd_gate;
       Alcotest.test_case "block-relay / handshake / listen gates" `Quick test_other_gates ]);
  ]
