(* ConsiderEviction must not evict an outbound peer that is at our tip.

   Mainnet 2026-11-07/08 (DONE criterion 3b: 17 of 24 hours below 8
   full-relay outbound): 75 outbound peers were dropped in 24 h with
   "Evicting stale peer N: headers sync timeout (no response to getheaders
   challenge)", in 20 bursts of up to 10 peers, each burst a few minutes
   after a new block.  Those peers were at our tip.

   camlcoin raises a peer's best height only from a headers message.  A
   peer that announced the new block by inv or cmpctblock still looks one
   block behind, so the challenge fires.  The challenge getheaders used a
   locator headed by OUR TIP.  A peer with the same tip finds the fork at
   that tip and answers with an EMPTY headers message (Core
   ProcessGetHeaders always replies, possibly empty), which carries no
   height, so two minutes later the peer was evicted.

   Core (net_processing.cpp PeerManagerImpl::ConsiderEviction) sends
   GetLocator(m_chain_sync.m_work_header->pprev): the reply from a peer at
   our tip then contains at least the tip header, which proves it is in
   sync and clears the challenge.

   The test drives the real Peer_manager.check_stale_peers over a
   socketpair, reads the getheaders it sends, answers it the way a Core
   peer does (FindForkInGlobalIndex on the locator, then the headers after
   the fork), hands a non-empty reply to on_headers_received as
   cli.ml's HeadersMsg listener does, and checks whether the peer is
   evicted when the 2-minute response window has passed.

   Command:
     dune build @test/considereviction_challenge/runtest --force *)

open Camlcoin

let genesis_ts = Consensus.regtest.genesis_header.Types.timestamp

let mine_header ~prev ~height : Types.block_header * Types.hash256 =
  let rec grind nonce =
    let hdr =
      Types.
        {
          version = 1l;
          prev_block = prev;
          merkle_root = Types.zero_hash;
          timestamp = Int32.add genesis_ts (Int32.of_int (height * 600));
          bits = 0x207fffffl;
          nonce;
        }
    in
    let hash = Crypto.compute_block_hash hdr in
    if Consensus.check_proof_of_work hash hdr.Types.bits Consensus.regtest
    then (hdr, hash)
    else grind (Int32.succ nonce)
  in
  grind 0l

(* One chain of [n] headers after regtest genesis, mined once and shared:
   the node holds all of it, a peer holds a prefix. *)
let chain_headers n =
  let genesis_hash =
    Crypto.compute_block_hash Consensus.regtest.genesis_header
  in
  let arr = Array.make (n + 1) (Consensus.regtest.genesis_header, genesis_hash) in
  for h = 1 to n do
    let _, prev = arr.(h - 1) in
    arr.(h) <- mine_header ~prev ~height:h
  done;
  arr

(* A chain_state holding headers [1..upto] in memory (blocks_synced = upto). *)
let with_state ~label (chain : (Types.block_header * Types.hash256) array)
    ~upto f =
  Test_tmp.with_dir ~label (fun path ->
      let db = Storage.ChainDB.create path in
      Fun.protect
        ~finally:(fun () -> Storage.ChainDB.close db)
        (fun () ->
          let st = Sync.create_chain_state db Consensus.regtest in
          let prev = ref (Option.get st.Sync.tip) in
          for h = 1 to upto do
            let hdr, hash = chain.(h) in
            let work =
              Consensus.work_add !prev.Sync.total_work
                (Consensus.work_from_compact hdr.Types.bits)
            in
            let e : Sync.header_entry =
              { header = hdr; hash; height = h; total_work = work }
            in
            Hashtbl.replace st.Sync.headers (Cstruct.to_string hash) e;
            Storage.ChainDB.set_height_hash db h hash;
            st.Sync.tip <- Some e;
            st.Sync.headers_synced <- h;
            prev := e
          done;
          st.Sync.blocks_synced <- upto;
          f st))

(* Core ProcessGetHeaders: FindForkInGlobalIndex (first locator hash we
   know, else genesis), then up to 2000 headers after the fork. A peer
   at the fork point answers with an empty list. *)
let core_respond (peer : Sync.chain_state) (locator : Types.hash256 list) =
  let rec find = function
    | [] -> 0
    | h :: rest -> (
      match Sync.get_header peer h with
      | Some e -> e.Sync.height
      | None -> find rest)
  in
  let fork = find locator in
  let tip = Option.get peer.Sync.tip in
  List.filter_map
    (fun h ->
      Option.map (fun e -> e.Sync.header) (Sync.get_ancestor peer tip h))
    (List.init (max 0 (tip.Sync.height - fork)) (fun i -> fork + 1 + i))

(* cli.ml HeadersMsg listener: a non-empty batch raises the sender's best
   height to the height of its last header; an empty one does nothing. *)
let deliver_headers pm (node : Sync.chain_state) peer_id headers =
  match List.rev headers with
  | [] -> ()
  | h :: _ -> (
    match Sync.get_header node (Crypto.compute_block_hash h) with
    | Some e ->
      Peer_manager.on_headers_received pm peer_id
        ~new_best_height:(Int32.of_int e.Sync.height)
    | None -> ())

let n = 30

(* The node is at [n]; the outbound peer last sent headers 21+ minutes ago
   and its recorded best height is n-1 (it announced block n by inv /
   cmpctblock, which does not touch best_height). The peer really holds
   headers up to [peer_upto]. Returns (getheaders locator sent, evicted?). *)
let run_challenge ~peer_upto =
  let chain = chain_headers n in
  with_state ~label:"ce_node" chain ~upto:n (fun node ->
      with_state ~label:"ce_peer" chain ~upto:peer_upto (fun peer_chain ->
          let pm = Peer_manager.create Consensus.regtest in
          Peer_manager.set_locator_builder pm (fun () ->
              Sync.build_locator node);
          Peer_manager.set_height pm (Int32.of_int n);
          Peer_manager.set_header_height pm (Int32.of_int n);
          let a, b = Unix.socketpair Unix.PF_UNIX Unix.SOCK_STREAM 0 in
          let ours =
            Peer.make_peer ~network:Consensus.regtest ~addr:"198.51.100.7"
              ~port:18444 ~id:7 ~direction:Peer.Outbound
              ~fd:(Lwt_unix.of_unix_file_descr a) ()
          in
          ours.Peer.state <- Peer.Ready;
          ours.Peer.best_height <- Int32.of_int (n - 1);
          let remote =
            Peer.make_peer ~network:Consensus.regtest ~addr:"198.51.100.8"
              ~port:18444 ~id:8 ~direction:Peer.Inbound
              ~fd:(Lwt_unix.of_unix_file_descr b) ()
          in
          pm.Peer_manager.peers <- [ ours ];
          let st = Peer_manager.get_stale_state pm 7 in
          st.Peer_manager.last_header_time <- Unix.gettimeofday () -. 1300.0;
          Lwt_main.run
            (let%lwt evicted_now = Peer_manager.check_stale_peers pm in
             Alcotest.(check int) "challenge armed, nobody evicted yet" 0
               (List.length evicted_now);
             let%lwt msg =
               Lwt_unix.with_timeout 5.0 (fun () -> Peer.read_message remote)
             in
             let locator =
               match msg with
               | P2p.GetheadersMsg { locator_hashes; _ } -> locator_hashes
               | _ -> Alcotest.fail "expected a getheaders challenge"
             in
             deliver_headers pm node 7 (core_respond peer_chain locator);
             let later =
               Unix.gettimeofday () +. Peer_manager.Stale.headers_response_time
               +. 1.0
             in
             let evicted =
               Peer_manager.check_headers_timeout pm ours ~now:later <> None
             in
             Lwt.return (locator, evicted, chain))))

let test_locator_starts_at_tip_parent () =
  let locator, _, chain = run_challenge ~peer_upto:n in
  match locator with
  | [] -> Alcotest.fail "empty locator"
  | head :: _ ->
    Alcotest.(check bool)
      "challenge locator starts at our tip's parent (Core GetLocator(pprev))"
      true
      (Cstruct.equal head (snd chain.(n - 1)))

let test_peer_at_our_tip_is_not_evicted () =
  let _, evicted, _ = run_challenge ~peer_upto:n in
  Alcotest.(check bool)
    "a Core peer at our tip answers the challenge with our tip header and is \
     kept"
    false evicted

(* Negative control: a peer that really is behind (3 blocks) and stays
   behind must still be evicted once the response window has passed. *)
let test_peer_behind_is_still_evicted () =
  let _, evicted, _ = run_challenge ~peer_upto:(n - 3) in
  Alcotest.(check bool) "a peer 3 blocks behind is still evicted" true evicted

let () =
  Alcotest.run "considereviction_challenge"
    [
      ( "challenge",
        [
          Alcotest.test_case "locator starts at tip parent" `Quick
            test_locator_starts_at_tip_parent;
          Alcotest.test_case "peer at our tip is not evicted" `Quick
            test_peer_at_our_tip_is_not_evicted;
          Alcotest.test_case "peer behind is still evicted" `Quick
            test_peer_behind_is_still_evicted;
        ] );
    ]
