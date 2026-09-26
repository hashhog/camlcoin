(* --connect peers are MANUAL connections (Core ConnectionType::MANUAL):
   exempt from the netgroup-diversity rule and the outbound-slot limit.

   Regtest relay test 2026-09-26: camlcoin --connect 127.0.0.1:A
   --connect 127.0.0.1:B dialed A and silently never dialed B, because both
   the startup dial loop and the pinned-peer re-dial went through add_peer,
   which applies would_violate_netgroup_diversity (same /16 as A). Source pin:
   both paths must use force_add_peer. *)

let read_file path =
  let ic = open_in_bin path in
  let n = in_channel_length ic in
  let s = really_input_string ic n in
  close_in ic;
  s

let rec find_root dir =
  if Sys.file_exists (Filename.concat dir "lib/cli.ml") then dir
  else
    let parent = Filename.dirname dir in
    if parent = dir then failwith "project root not found" else find_root parent

let contains hay needle =
  let re = Str.regexp_string needle in
  try ignore (Str.search_forward re hay 0); true with Not_found -> false

let test_startup_dial_is_manual () =
  let root = find_root (Sys.getcwd ()) in
  let cli = read_file (Filename.concat root "lib/cli.ml") in
  Alcotest.(check bool) "startup --connect dial uses force_add_peer" true
    (contains cli "Peer_manager.force_add_peer peer_manager addr port");
  Alcotest.(check bool) "no add_peer on the --connect path" false
    (contains cli "Peer_manager.add_peer peer_manager addr port")

let test_pinned_redial_is_manual () =
  let root = find_root (Sys.getcwd ()) in
  let pm = read_file (Filename.concat root "lib/peer_manager.ml") in
  Alcotest.(check bool) "pinned re-dial uses force_add_peer" true
    (contains pm "else force_add_peer pm addr port\n            ) pm.connect_peers")

let () =
  Alcotest.run "manual_connect_netgroup"
    [ ("connect", [
        Alcotest.test_case "startup dial" `Quick test_startup_dial_is_manual;
        Alcotest.test_case "pinned re-dial" `Quick test_pinned_redial_is_manual ]) ]
