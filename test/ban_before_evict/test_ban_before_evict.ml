(* A banned address must not trigger inbound eviction.

   Core CConnman::CreateNodeFromAcceptedSocket (net.cpp:1804-1810) drops a
   connection from a banned address before it looks at the inbound count, so
   AttemptToEvictConnection (net.cpp:1820-1827) only ever runs for a
   connection Core is going to keep.  accept_inbound ran evict_inbound_peer
   first and checked is_banned afterwards, so a banned host that reconnected
   while inbound slots were full cost us one good peer per attempt and was
   then refused anyway.

   The eviction selector protects up to 20 candidates (4 netgroup, 8 ping,
   4 tx relay, 4 block relay; the 8 block-relay-only slots apply to peers
   that do not relay txs, and every candidate relays txs today), then half
   of the rest.  With 20 or fewer inbound peers it never picks a victim,
   so the full-slots scenario needs at least 21: these tests use 24. *)

open Camlcoin

let n_inbound = 24
let banned_ip = "203.0.113.9"

(* [n_inbound] Ready inbound peers on socketpairs; the remote ends are kept
   so the peers' fds stay valid until the test closes them. *)
let make_full_pm () =
  let config =
    { Peer_manager.default_config with max_inbound = n_inbound } in
  let pm = Peer_manager.create ~config Consensus.regtest in
  let remotes = ref [] in
  let now = Unix.gettimeofday () in
  for i = 1 to n_inbound do
    let a, b = Unix.socketpair Unix.PF_UNIX Unix.SOCK_STREAM 0 in
    remotes := b :: !remotes;
    let p =
      Peer.make_peer ~network:Consensus.regtest
        ~addr:(Printf.sprintf "198.51.%d.%d" (i mod 7) (10 + i))
        ~port:(40000 + i) ~id:i ~direction:Peer.Inbound
        ~fd:(Lwt_unix.of_unix_file_descr a) () in
    p.Peer.state <- Peer.Ready;
    p.Peer.latency <- 0.01 *. float_of_int i;
    Hashtbl.replace pm.Peer_manager.peer_connected_time i
      (now -. float_of_int (1000 - i));
    pm.Peer_manager.peers <- p :: pm.Peer_manager.peers
  done;
  pm.Peer_manager.next_peer_id <- n_inbound + 1;
  (pm, !remotes)

let close_all = List.iter (fun s -> try Unix.close s with _ -> ())

(* Close the remote ends and the local fd of every peer still in [pm]
   (an evicted peer's fd was already closed by Peer.disconnect). *)
let cleanup pm remotes =
  close_all remotes;
  List.iter (fun p ->
    try Unix.close (Lwt_unix.unix_file_descr p.Peer.fd) with _ -> ())
    pm.Peer_manager.peers

(* Hand accept_inbound one socket from [ip]; the client end is closed
   first so a handshake (if one starts) ends at once on EOF. *)
let accept_from pm ip =
  let a, b = Unix.socketpair Unix.PF_UNIX Unix.SOCK_STREAM 0 in
  Unix.close b;
  Lwt_main.run
    (Lwt_unix.with_timeout 10.0 (fun () ->
       Peer_manager.accept_inbound pm (Lwt_unix.of_unix_file_descr a)
         (Unix.ADDR_INET (Unix.inet_addr_of_string ip, 51000))))

let inbound_count pm =
  List.length
    (List.filter (fun p -> p.Peer.direction = Peer.Inbound)
       pm.Peer_manager.peers)

let test_banned_does_not_evict () =
  let pm, remotes = make_full_pm () in
  Fun.protect ~finally:(fun () -> cleanup pm remotes) (fun () ->
    Peer_manager.ban_addr pm banned_ip ();
    Alcotest.(check bool) "address is banned" true
      (Peer_manager.is_banned pm banned_ip);
    Alcotest.(check int) "inbound slots full before the accept" n_inbound
      (inbound_count pm);
    accept_from pm banned_ip;
    Alcotest.(check int)
      "a banned connection is refused without evicting an inbound peer \
       (Core net.cpp:1805 ban check before AttemptToEvictConnection)"
      n_inbound (inbound_count pm);
    Alcotest.(check bool) "banned address still not connected" false
      (List.exists (fun p -> p.Peer.addr = banned_ip) pm.Peer_manager.peers))

(* Control: the same full-slots setup does evict for an address that is
   not banned, so the test above measures the ban ordering and not an
   eviction selector that never picks anyone. *)
let test_unbanned_does_evict () =
  let pm, remotes = make_full_pm () in
  Fun.protect ~finally:(fun () -> cleanup pm remotes) (fun () ->
    accept_from pm "203.0.113.10";
    Alcotest.(check int)
      "control: full slots + unbanned connection evicts one inbound peer"
      (n_inbound - 1) (inbound_count pm))

let () =
  Alcotest.run "ban_before_evict" [
    "accept_inbound", [
      Alcotest.test_case "banned address does not trigger eviction" `Quick
        test_banned_does_not_evict;
      Alcotest.test_case "control: unbanned address does trigger eviction"
        `Quick test_unbanned_does_evict;
    ];
  ]
