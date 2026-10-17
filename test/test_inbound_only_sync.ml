(* INSYNC: a node whose only peer is INBOUND must still take headers from it.

   tools/conformance-scenarios.py INSYNC (nightly fleet-conformance failed on
   camlcoin 2026-10-08..14: "inbound-only peer: stuck at 0 (want 20), 1
   getdata").  The blocking header-sync loop only reads from a peer without a
   message loop, and inbound peers get their loop at accept time, so it never
   runs for an inbound-only node.  The cli HeadersMsg listener was gated on
   FullySynced, so the headers the peer sent were dropped.  Core handles
   HEADERS from any handshaked peer (net_processing.cpp).

   The end-to-end proof is the INSYNC scenario; this pins the routing rule.

     dune exec --no-buffer test/test_inbound_only_sync.exe
*)

open Camlcoin

let accepts s l = Sync.accepts_looped_peer_headers ~sync_state:s ~msg_loop_started:l

let test_idle_inbound_peer () =
  Alcotest.(check bool) "Idle + looped (inbound) peer: headers handled"
    true (accepts Sync.Idle true)

let test_idle_unlooped_peer () =
  (* The blocking loop reads this socket directly; the listener never sees it. *)
  Alcotest.(check bool) "Idle + unlooped peer: left to sync_headers"
    false (accepts Sync.Idle false)

let test_syncing_headers_not_raced () =
  Alcotest.(check bool) "SyncingHeaders: no second consumer"
    false (accepts Sync.SyncingHeaders true)

(* Review of #11: the full first batch flips Idle -> SyncingBlocks, and the
   reply to the follow-up getheaders arrives in SyncingBlocks.  Dropping it
   stalled an inbound-only peer more than 2000 blocks ahead.  sync_headers
   holds SyncingHeaders while it runs, so SyncingBlocks has no other
   header consumer. *)
let test_syncing_blocks () =
  Alcotest.(check bool) "SyncingBlocks + looped peer: follow-up batch handled"
    true (accepts Sync.SyncingBlocks true);
  Alcotest.(check bool) "SyncingBlocks + unlooped peer: not ours"
    false (accepts Sync.SyncingBlocks false)

(* --- process_looped_peer_headers: the routing behind the listener --- *)

let db_path = Test_tmp.register "/tmp/camlcoin_test_inbound_only_sync_db"

let rm_rf path =
  let rec go p =
    if Sys.file_exists p then
      if Sys.is_directory p then begin
        Array.iter (fun f -> go (Filename.concat p f)) (Sys.readdir p);
        Unix.rmdir p
      end else Unix.unlink p
  in
  go path

let mine ~prev_block ~ts =
  let rec loop nonce =
    let h = { Types.version = 1l; prev_block; merkle_root = Types.zero_hash;
              timestamp = ts; bits = Consensus.regtest.genesis_header.bits;
              nonce } in
    if Consensus.hash_meets_target (Crypto.compute_block_hash h) h.bits then h
    else loop (Int32.add nonce 1l)
  in
  loop 0l

(* [n] valid regtest headers on top of genesis. *)
let chain_of n =
  let g = Consensus.regtest.genesis_header in
  let rec go i prev ts acc =
    if i = n then List.rev acc
    else
      let h = mine ~prev_block:prev ~ts in
      go (i + 1) (Crypto.compute_block_hash h) (Int32.add ts 600l) (h :: acc)
  in
  go 0 (Crypto.compute_block_hash g) (Int32.add g.timestamp 600l) []

let with_chain net f =
  rm_rf db_path;
  let db = Storage.ChainDB.create db_path in
  let chain = Sync.create_chain_state db net in
  Fun.protect ~finally:(fun () -> Storage.ChainDB.close db; rm_rf db_path)
    (fun () -> f chain)

let stored chain h =
  Sync.get_header chain (Crypto.compute_block_hash h) <> None

(* Review of #11: the Idle branch called process_headers with the default
   min_pow_checked=true and no PRESYNC, so an inbound peer could make a fresh
   node (blocks_synced=0, tip_work < minimum_chain_work) store a cheap chain.
   The blocking loop routes that case through PRESYNC; so must this. *)
let test_idle_lowwork_not_stored () =
  let net = { Consensus.regtest with
              minimum_chain_work = Consensus.mainnet.minimum_chain_work } in
  with_chain net (fun chain ->
    Alcotest.(check bool) "precondition: needs low-work sync" true
      (Sync.needs_lowwork_sync ~chain_state:chain);
    let batch = chain_of 50 in
    let o = Sync.process_looped_peer_headers chain ~peer_id:7 batch in
    Alcotest.(check bool) "first header not stored" false
      (stored chain (List.hd batch));
    Alcotest.(check bool) "last header not stored" false
      (stored chain (List.nth batch 49));
    Alcotest.(check int) "header tip unchanged" 0 chain.Sync.headers_synced;
    Alcotest.(check bool) "routed to PRESYNC" true o.Sync.via_lowwork;
    Alcotest.(check bool) "per-peer PRESYNC state created" true
      (Sync.get_peer_headers_sync chain 7 <> None);
    Alcotest.(check bool) "short PRESYNC batch: no follow-up" false
      o.Sync.request_more)

(* The other direction: a looped peer's chain that DOES carry the work must
   still reach the header tree.  minimum_chain_work = 40 regtest headers; the
   peer has 50.  PRESYNC proves the work and starts REDOWNLOAD (and asks for
   it even though the batch was short); the redownloaded batch is stored. *)
let test_idle_enough_work_presync_then_stored () =
  let one = Sync.work_from_bits Consensus.regtest.genesis_header.bits in
  let rec times n acc = if n = 0 then acc else times (n - 1) (Consensus.work_add acc one) in
  let net = { Consensus.regtest with minimum_chain_work = times 41 Consensus.zero_work } in
  with_chain net (fun chain ->
    let batch = chain_of 50 in
    let o1 = Sync.process_looped_peer_headers chain ~peer_id:7 batch in
    Alcotest.(check bool) "PRESYNC: nothing stored yet" false
      (stored chain (List.hd batch));
    Alcotest.(check bool) "work proven: ask for REDOWNLOAD" true
      o1.Sync.request_more;
    let o2 = Sync.process_looped_peer_headers chain ~peer_id:7 batch in
    Alcotest.(check bool) "REDOWNLOAD path" true o2.Sync.via_lowwork;
    Alcotest.(check bool) "redownloaded chain stored" true
      (stored chain (List.nth batch 49));
    Alcotest.(check int) "header tip at peer's tip" 50 chain.Sync.headers_synced)

(* Above the work threshold the batch is stored, and a full batch asks for
   the next one -- in Idle and in SyncingBlocks alike. *)
let test_full_batch_stored_and_continued () =
  with_chain Consensus.regtest (fun chain ->
    let all = chain_of (P2p.max_headers_count + 5) in
    let first = List.filteri (fun i _ -> i < P2p.max_headers_count) all in
    let rest = List.filteri (fun i _ -> i >= P2p.max_headers_count) all in
    let o1 = Sync.process_looped_peer_headers chain ~peer_id:7 first in
    Alcotest.(check bool) "direct path" false o1.Sync.via_lowwork;
    Alcotest.(check (result int string)) "full batch stored"
      (Ok P2p.max_headers_count) o1.Sync.looped_result;
    Alcotest.(check bool) "full batch: request next" true o1.Sync.request_more;
    chain.Sync.sync_state <- Sync.SyncingBlocks;
    Alcotest.(check bool) "follow-up reply accepted in SyncingBlocks" true
      (Sync.accepts_looped_peer_headers ~sync_state:chain.Sync.sync_state
         ~msg_loop_started:true);
    let o2 = Sync.process_looped_peer_headers chain ~peer_id:7 rest in
    Alcotest.(check (result int string)) "follow-up batch stored" (Ok 5)
      o2.Sync.looped_result;
    Alcotest.(check int) "header tip past the first batch"
      (P2p.max_headers_count + 5) chain.Sync.headers_synced;
    Alcotest.(check bool) "short batch: stop" false o2.Sync.request_more)

let test_fully_synced_any_peer () =
  Alcotest.(check bool) "FullySynced looped" true (accepts Sync.FullySynced true);
  Alcotest.(check bool) "FullySynced unlooped" true (accepts Sync.FullySynced false)

let () =
  Alcotest.run "inbound_only_sync"
    [ "routing",
      [ Alcotest.test_case "idle inbound" `Quick test_idle_inbound_peer;
        Alcotest.test_case "idle unlooped" `Quick test_idle_unlooped_peer;
        Alcotest.test_case "syncing headers" `Quick test_syncing_headers_not_raced;
        Alcotest.test_case "syncing blocks" `Quick test_syncing_blocks;
        Alcotest.test_case "fully synced" `Quick test_fully_synced_any_peer ];
      "looped_headers",
      [ Alcotest.test_case "idle low-work batch not stored" `Quick
          test_idle_lowwork_not_stored;
        Alcotest.test_case "idle enough work: presync then stored" `Quick
          test_idle_enough_work_presync_then_stored;
        Alcotest.test_case "full batch stored and continued" `Quick
          test_full_batch_stored_and_continued ] ]
