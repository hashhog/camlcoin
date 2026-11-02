(* Sync.receive_block binds a body to the peer its slot is in flight with
   (security audit 2026-10-31 H6).  The end-to-end attack is in
   test/ibd_block_sender; these pin the slot-state rules.

     dune build @test/ibd_block_sender_unit/runtest *)

open Camlcoin

let db_path = Test_tmp.register "/tmp/camlcoin_test_ibd_block_sender_unit_db"

let block = Types.{ header = Consensus.regtest.genesis_header; transactions = [] }

let with_ibd state f =
  Test_tmp.rm_rf db_path;
  let db = Storage.ChainDB.create db_path in
  Fun.protect ~finally:(fun () -> Storage.ChainDB.close db; Test_tmp.rm_rf db_path)
  @@ fun () ->
  let chain = Sync.create_chain_state db Consensus.regtest in
  let ibd = Sync.create_ibd_state chain in
  let hash = Crypto.compute_block_hash block.Types.header in
  let entry = Sync.{ hash; height = 0; download_state = state; tried_peers = [] } in
  Queue.clear ibd.block_queue;
  Queue.push entry ibd.block_queue;
  Hashtbl.replace ibd.queue_by_hash (Cstruct.to_string hash) entry;
  (match state with
   | Sync.Requested { peer_id; _ } ->
     ibd.total_blocks_in_flight <- 1;
     (Sync.get_peer_state ibd peer_id).blocks_in_flight <- 1
   | _ -> ());
  f ibd entry

let requested_from p =
  Sync.Requested { peer_id = p; requested_at = Unix.gettimeofday (); timeout = 5.0 }

let downloaded_by entry = match entry.Sync.download_state with
  | Sync.Downloaded { peer_id; _ } -> Some peer_id
  | _ -> None

(* The attack: peer 2 answers a getdata sent to peer 1.  The slot stays in
   flight with peer 1 and nothing is charged to peer 1. *)
let test_other_peer_ignored () =
  with_ibd (requested_from 1) @@ fun ibd entry ->
  Alcotest.(check bool) "Ok" true (Result.is_ok (Sync.receive_block ~sender:2 ibd block));
  Alcotest.(check bool) "slot still in flight with peer 1" true
    (match entry.download_state with
     | Sync.Requested { peer_id = 1; _ } -> true | _ -> false);
  Alcotest.(check int) "total in flight unchanged" 1 ibd.total_blocks_in_flight;
  Alcotest.(check int) "peer 1 in flight unchanged" 1
    (Sync.get_peer_state ibd 1).blocks_in_flight;
  (* and peer 1 can still fill it *)
  ignore (Sync.receive_block ~sender:1 ibd block);
  Alcotest.(check (option (option int))) "then filled by peer 1" (Some (Some 1))
    (downloaded_by entry);
  Alcotest.(check int) "total in flight released" 0 ibd.total_blocks_in_flight

let test_requested_peer_accepted () =
  with_ibd (requested_from 1) @@ fun ibd entry ->
  ignore (Sync.receive_block ~sender:1 ibd block);
  Alcotest.(check (option (option int))) "downloaded, blamed on peer 1"
    (Some (Some 1)) (downloaded_by entry);
  Alcotest.(check int) "peer 1 in flight released" 0
    (Sync.get_peer_state ibd 1).blocks_in_flight

(* A slot nobody has in flight is filled as before, but a bad body is now
   charged to the peer that actually sent it rather than to no one. *)
let test_not_requested_blames_sender () =
  with_ibd Sync.NotRequested @@ fun ibd entry ->
  ignore (Sync.receive_block ~sender:3 ibd block);
  Alcotest.(check (option (option int))) "downloaded, blamed on sender 3"
    (Some (Some 3)) (downloaded_by entry);
  Alcotest.(check int) "in-flight count untouched" 0 ibd.total_blocks_in_flight

(* Callers with no peer (compact-block reconstruction, orphan replay) keep
   the old hash-only behaviour. *)
let test_no_sender_legacy () =
  with_ibd (requested_from 1) @@ fun ibd entry ->
  ignore (Sync.receive_block ibd block);
  Alcotest.(check (option (option int))) "downloaded, blamed on requested peer"
    (Some (Some 1)) (downloaded_by entry)

let () =
  Alcotest.run "ibd_block_sender_unit"
    [ "h6",
      [ Alcotest.test_case "body from a non-requested peer is ignored" `Quick
          test_other_peer_ignored;
        Alcotest.test_case "body from the requested peer is accepted" `Quick
          test_requested_peer_accepted;
        Alcotest.test_case "not-requested slot blames the actual sender" `Quick
          test_not_requested_blames_sender;
        Alcotest.test_case "no sender: hash-only (compact block, orphan)" `Quick
          test_no_sender_legacy ] ]
