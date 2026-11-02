(* Unrequested blocks during IBD are dropped, not pooled (security audit
   2026-10-31 H7).

   Sync.receive_block stored any block whose hash was not in the download
   queue in [ibd.orphan_blocks]: up to 750 entries, each up to a 4 MB wire
   message, with no header, PoW or size check, so one peer could pin ~3 GB
   of heap.  Core keeps no orphan blocks: a block it did not request and
   cannot connect to a known header is not stored (net_processing.cpp
   ProcessMessage BLOCK -> ProcessBlock -> AcceptBlock returns early for an
   unrequested block without a known, more-work header).

     dune build @test/ibd_orphan_blocks/runtest *)

open Camlcoin

let db_path = Test_tmp.register "/tmp/camlcoin_test_ibd_orphan_blocks_db"

let with_ibd f =
  Test_tmp.rm_rf db_path;
  let db = Storage.ChainDB.create db_path in
  Fun.protect ~finally:(fun () -> Storage.ChainDB.close db; Test_tmp.rm_rf db_path)
  @@ fun () ->
  let chain = Sync.create_chain_state db Consensus.regtest in
  f (Sync.create_ibd_state chain)

(* A block nobody asked for: arbitrary parent, no valid PoW, distinct hash
   per [n]. *)
let stray ?(prev = Cstruct.create 32) n : Types.block =
  let g = Consensus.regtest.Consensus.genesis_header in
  Types.{ header = { g with prev_block = prev; nonce = Int32.of_int n };
          transactions = [] }

let test_unrequested_not_retained () =
  with_ibd @@ fun ibd ->
  Alcotest.(check bool) "Ok" true (Result.is_ok (Sync.receive_block ibd (stray 1)));
  Alcotest.(check int) "orphan pool empty" 0 (Hashtbl.length ibd.Sync.orphan_blocks);
  Alcotest.(check int) "queue untouched" 0 (Queue.length ibd.Sync.block_queue)

let test_flood_not_retained () =
  with_ibd @@ fun ibd ->
  for n = 1 to 1000 do ignore (Sync.receive_block ibd (stray n)) done;
  Alcotest.(check int) "orphan pool empty after 1000 strays" 0
    (Hashtbl.length ibd.Sync.orphan_blocks)

(* The pooled body used to be replayed into the queue as Downloaded once its
   parent connected, so a peer could plant a body for a later block.  With
   nothing pooled, connecting the parent replays nothing. *)
let test_parent_connect_replays_nothing () =
  with_ibd @@ fun ibd ->
  let parent = Crypto.compute_block_hash (stray 7).Types.header in
  ignore (Sync.receive_block ibd (stray ~prev:parent 8));
  Alcotest.(check int) "nothing replayed on parent connect" 0
    (Sync.process_orphan_blocks ibd parent);
  Alcotest.(check int) "queue untouched" 0 (Queue.length ibd.Sync.block_queue)

(* Control: a block the queue is waiting for is still accepted. *)
let test_requested_still_accepted () =
  with_ibd @@ fun ibd ->
  let block = stray 9 in
  let hash = Crypto.compute_block_hash block.Types.header in
  let entry = Sync.{ hash; height = 1;
                     download_state = Requested { peer_id = 1;
                                                  requested_at = Unix.gettimeofday ();
                                                  timeout = 5.0 };
                     tried_peers = [] } in
  Sync.queue_add ibd entry;
  ibd.Sync.total_blocks_in_flight <- 1;
  ignore (Sync.receive_block ibd block);
  Alcotest.(check bool) "slot filled" true
    (match entry.Sync.download_state with Sync.Downloaded _ -> true | _ -> false);
  Alcotest.(check int) "in flight released" 0 ibd.Sync.total_blocks_in_flight

let () =
  Alcotest.run "ibd_orphan_blocks"
    [ "h7",
      [ Alcotest.test_case "an unrequested block during IBD is not retained" `Quick
          test_unrequested_not_retained;
        Alcotest.test_case "a flood of unrequested blocks retains nothing" `Quick
          test_flood_not_retained;
        Alcotest.test_case "an unrequested child is not replayed when its parent connects" `Quick
          test_parent_connect_replays_nothing;
        Alcotest.test_case "a requested block is still accepted" `Quick
          test_requested_still_accepted ] ]
