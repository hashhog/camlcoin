(* pkgtxns after sendpackages was negotiated both ways (security audit
   2026-10-31 H8).

   camlcoin does not announce sendpackages, so in production no peer is
   negotiated and test_pkgtxns_gating covers what a peer can reach.  These
   cases pin what the handler does once [Peer.sendpackages_sent] is set by
   whatever change starts announcing it: the package is accepted, it counts
   against the tx listener's per-peer rate limit, and it waits for a slot in
   the ATMP gate instead of running beside every other accept.

     dune build @test/pkgtxns_gating/runtest *)

open Camlcoin

let test_db_path = Test_tmp.register "/tmp/camlcoin_test_pkgtxns_gating_db"

let script = Cstruct.of_string "\x76\xa9\x14test\x88\xac"

let funding =
  "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"

let spend (prev : Types.hash256) : Types.transaction =
  { Types.version = 1l;
    inputs = [ { Types.previous_output = { Types.txid = prev; vout = 0l };
                 script_sig = Cstruct.of_string "\x00";
                 sequence = 0xFFFFFFFFl } ];
    outputs = [ { Types.value = 999_000L; script_pubkey = script } ];
    witnesses = []; locktime = 0l }

(* [with_mempool f] runs [f mp pkg] on a fresh pool; [pkg] is a parent
   and the child spending it, a package accept_package takes. *)
let with_mempool f =
  Test_tmp.rm_rf test_db_path;
  let db = Storage.ChainDB.create test_db_path in
  let utxo = Utxo.UtxoSet.create db in
  Utxo.UtxoSet.add utxo (Types.hash256_of_hex funding) 0
    Utxo.{ value = 1_000_000L; script_pubkey = script; height = 0;
           is_coinbase = false };
  let mp = Mempool.create ~network:Consensus.regtest ~require_standard:false
      ~verify_scripts:false ~utxo ~current_height:100 () in
  let parent = spend (Types.hash256_of_hex funding) in
  let child = { (spend (Crypto.compute_txid parent)) with
                Types.outputs = [ { Types.value = 998_000L;
                                    script_pubkey = script } ] } in
  Fun.protect
    ~finally:(fun () -> Storage.ChainDB.close db; Test_tmp.rm_rf test_db_path)
    (fun () -> f mp [ parent; child ])

(* A peer that never touches its socket, negotiated both ways. *)
let with_negotiated_peer f =
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let peer = Peer.make_peer ~network:Consensus.regtest ~addr:"127.0.0.1"
      ~port:18444 ~id:7 ~direction:Peer.Inbound ~fd () in
  peer.Peer.sendpackages_received <- true;
  peer.Peer.sendpackages_sent <- true;
  Fun.protect ~finally:(fun () -> Lwt_main.run (Lwt_unix.close fd))
    (fun () -> f peer)

let in_pool mp pkg =
  List.length
    (List.filter (fun tx -> Mempool.contains mp (Crypto.compute_txid tx)) pkg)

let pkgtxns pkg = P2p.PkgtxnsMsg { P2p.pkg_txs = pkg }

(* Control: the fixture package is one the mempool accepts, so the
   "nothing accepted" checks below can see an accepted package. *)
let test_control_package_valid () =
  with_mempool (fun mp pkg ->
    (match Mempool.accept_package mp pkg with
     | Mempool.PackageAccepted _ -> ()
     | Mempool.PackagePartial _ -> Alcotest.fail "fixture: partial accept"
     | Mempool.PackageRejected r -> Alcotest.failf "fixture rejected: %s" r);
    Alcotest.(check int) "control: both txs in pool" 2 (in_pool mp pkg))

let test_negotiated_accepted () =
  with_mempool (fun mp pkg ->
    with_negotiated_peer (fun peer ->
      Alcotest.(check bool) "negotiated" true (Package_relay.negotiated peer);
      Lwt_main.run (Package_relay.dispatch mp (pkgtxns pkg) peer);
      Alcotest.(check int) "negotiated pkgtxns is accepted" 2 (in_pool mp pkg)))

let test_one_sided_not_negotiated () =
  with_negotiated_peer (fun peer ->
    peer.Peer.sendpackages_sent <- false;
    Alcotest.(check bool) "peer-only sendpackages" false
      (Package_relay.negotiated peer);
    peer.Peer.sendpackages_sent <- true;
    peer.Peer.sendpackages_received <- false;
    Alcotest.(check bool) "our-only sendpackages" false
      (Package_relay.negotiated peer))

(* The peer already spent its 500-message window on tx messages. *)
let test_rate_limited () =
  with_mempool (fun mp pkg ->
    with_negotiated_peer (fun peer ->
      peer.Peer.msg_window_start <- Unix.gettimeofday ();
      peer.Peer.msg_count_window <- 500;
      Lwt_main.run (Package_relay.dispatch mp (pkgtxns pkg) peer);
      Alcotest.(check int) "over-rate pkgtxns is dropped" 0 (in_pool mp pkg)))

(* Every gate slot is taken: the package waits, then runs once one frees. *)
let test_waits_for_gate () =
  with_mempool (fun mp pkg ->
    with_negotiated_peer (fun peer ->
      let gate = Lwt_pool.create 1 (fun () -> Lwt.return_unit) in
      let held, release = Lwt.wait () in
      Lwt_main.run (
        let holder = Lwt_pool.use gate (fun () -> held) in
        let p = Package_relay.dispatch ~gate mp (pkgtxns pkg) peer in
        let%lwt () = Lwt.pause () in
        let%lwt () = Lwt.pause () in
        Alcotest.(check bool) "still waiting for the gate" true
          (Lwt.state p = Lwt.Sleep);
        Alcotest.(check int) "nothing accepted while the gate is full"
          0 (in_pool mp pkg);
        Lwt.wakeup release ();
        let%lwt () = holder in
        p);
      Alcotest.(check int) "accepted once the gate frees" 2 (in_pool mp pkg)))

let () =
  Alcotest.run "pkgtxns_gating_negotiated" [
    "pkgtxns_gating_negotiated", [
      Alcotest.test_case "control: fixture package is valid" `Quick
        test_control_package_valid;
      Alcotest.test_case "negotiated pkgtxns is accepted" `Quick
        test_negotiated_accepted;
      Alcotest.test_case "negotiation needs both sendpackages" `Quick
        test_one_sided_not_negotiated;
      Alcotest.test_case "pkgtxns shares the per-peer rate limit" `Quick
        test_rate_limited;
      Alcotest.test_case "pkgtxns waits for the ATMP gate" `Quick
        test_waits_for_gate;
    ]
  ]
