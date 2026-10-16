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

let test_syncing_blocks () =
  Alcotest.(check bool) "SyncingBlocks: catch-up IBD owns it"
    false (accepts Sync.SyncingBlocks true)

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
        Alcotest.test_case "fully synced" `Quick test_fully_synced_any_peer ] ]
