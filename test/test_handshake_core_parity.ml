(* Handshake Core-parity tests (inbound + outbound).

   Core reference (bitcoin-core/src/net_processing.cpp):
     :3609  desirable services (NODE_WITNESS + NODE_NETWORK[_LIMITED]) are
            required only of connections we chose (outbound)
     :3619  MIN_PEER_PROTO_VERSION = 31800 for every peer
     :3710  wtxidrelay / sendaddrv2 sent only at common version >= 70016
     :3896  SENDHEADERS is processed before verack
     :4010  every other message before verack is logged and ignored

   Each test drives the REAL handshake functions over a socketpair: the node
   under test is one end, a scripted remote (a second Peer used only for
   raw send/recv) is the other.  These tests use only APIs that exist on
   master, so they compile there and demonstrate the pre-fix failures. *)

open Camlcoin

let () = Sys.set_signal Sys.sigpipe Sys.Signal_ignore

let node_network = 1L
let node_witness = 8L

let make_pair ~direction =
  let a, b = Lwt_unix.socketpair Unix.PF_UNIX Unix.SOCK_STREAM 0 in
  let net = Consensus.regtest in
  let local = Peer.make_peer ~network:net ~addr:"127.0.0.1" ~port:18444
      ~id:1 ~direction ~fd:a () in
  let remote = Peer.make_peer ~network:net ~addr:"127.0.0.1" ~port:18444
      ~id:2 ~direction:Peer.Outbound ~fd:b () in
  (local, remote)

let remote_version remote ~version ~services : P2p.message_payload =
  let v = Peer.make_version_msg remote 0l in
  P2p.VersionMsg { v with protocol_version = version; services;
                          nonce = 0x1234_5678_9abcL }

let cmd_of m = P2p.command_to_string (P2p.payload_to_command m)

(* Read every message the node sends until it has been quiet for [quiet]. *)
let drain remote ~quiet =
  let open Lwt.Syntax in
  let rec go acc =
    let* m = Lwt.catch
        (fun () -> Peer.read_message_with_timeout remote quiet)
        (fun _ -> Lwt.return None) in
    match m with
    | None -> Lwt.return (List.rev acc)
    | Some m -> go (cmd_of m :: acc)
  in
  go []

(* Read until the node's verack; returns commands seen (incl. "verack"). *)
let read_to_verack remote =
  let open Lwt.Syntax in
  let rec go acc =
    let* m = Peer.read_message_with_timeout remote 10.0 in
    match m with
    | None -> Lwt.fail_with "remote: no verack from node"
    | Some P2p.VerackMsg -> Lwt.return (List.rev ("verack" :: acc))
    | Some m -> go (cmd_of m :: acc)
  in
  go []

type outcome = Completed | Failed of string

(* On failure the node's socket is closed (as the peer manager does), so the
   scripted remote sees EOF instead of waiting out its read timeout. *)
let run_handshake local handshake =
  Lwt.catch
    (fun () -> Lwt.map (fun () -> Completed) (handshake local))
    (fun e ->
       Lwt.bind
         (Lwt.catch (fun () -> Lwt_unix.close local.Peer.fd)
            (fun _ -> Lwt.return_unit))
         (fun () -> Lwt.return (Failed (Printexc.to_string e))))

(* Remote dials the node: VERSION first, then [pre_verack] extras, then
   VERACK.  Returns (node outcome, commands the node sent). *)
let inbound_scenario ~version ~services ~pre_verack =
  let open Lwt.Syntax in
  let local, remote = make_pair ~direction:Peer.Inbound in
  let node = run_handshake local
      (fun p -> Peer.perform_inbound_handshake p 0l) in
  let script =
    Lwt.catch (fun () ->
      let* () = Peer.send_message remote (remote_version remote ~version ~services) in
      let* seen = read_to_verack remote in
      let* () = Lwt_list.iter_s (Peer.send_message remote) pre_verack in
      let* () = Peer.send_message remote P2p.VerackMsg in
      let* after = drain remote ~quiet:0.5 in
      Lwt.return (seen @ after))
      (fun _ -> Lwt.return [])
  in
  let r = Lwt_main.run (Lwt.both node script) in
  (r, local)

let outcome_str = function Completed -> "completed" | Failed s -> "FAILED: " ^ s

let check_completed name o =
  Alcotest.(check string) name "completed" (outcome_str o)

(* 1. Inbound VERSION(70002), no NODE_WITNESS: Core keeps it.  The node must
   complete the handshake and must not send it messages a 70002 peer cannot
   parse (wtxidrelay, sendaddrv2, sendheaders, sendcmpct, feefilter). *)
let test_inbound_70002_completes () =
  let ((o, sent), local) =
    inbound_scenario ~version:70002l ~services:0L ~pre_verack:[] in
  check_completed "inbound 70002 handshake" o;
  Alcotest.(check bool) "peer Ready" true (local.Peer.state = Peer.Ready);
  Alcotest.(check (list string)) "only version+verack sent to a 70002 peer"
    ["version"; "verack"] sent

(* 1b. Below MIN_PEER_PROTO_VERSION (31800) is still refused. *)
let test_inbound_below_min_rejected () =
  let ((o, _), _) =
    inbound_scenario ~version:31799l ~services:(Int64.logor node_network node_witness)
      ~pre_verack:[] in
  Alcotest.(check bool) "31799 rejected" true (o <> Completed)

(* 1c. Modern inbound peer still gets the full feature set. *)
let test_inbound_70016_features () =
  let ((o, sent), _) =
    inbound_scenario ~version:70016l
      ~services:(Int64.logor node_network node_witness) ~pre_verack:[] in
  check_completed "inbound 70016 handshake" o;
  List.iter (fun c ->
    Alcotest.(check bool) ("70016 peer is sent " ^ c) true (List.mem c sent))
    ["wtxidrelay"; "sendaddrv2"; "verack"; "sendheaders"; "sendcmpct"; "feefilter"]

(* 2. Pre-verack SENDHEADERS is recorded, not a disconnect (Core :3896). *)
let test_pre_verack_sendheaders_recorded () =
  let ((o, _), local) =
    inbound_scenario ~version:70016l
      ~services:(Int64.logor node_network node_witness)
      ~pre_verack:[P2p.SendheadersMsg] in
  check_completed "handshake with pre-verack sendheaders" o;
  Alcotest.(check bool) "send_headers recorded" true local.Peer.send_headers

(* 3. Pre-verack ping / inv / feefilter / getheaders are ignored (Core :4010):
   no disconnect, no misbehaviour, and the feefilter is NOT applied. *)
let test_pre_verack_ping_inv_ignored () =
  let inv = P2p.InvMsg [{ P2p.inv_type = P2p.InvTx;
                          hash = Types.zero_hash }] in
  let getheaders = P2p.GetheadersMsg {
      version = 70016l; locator_hashes = []; hash_stop = Types.zero_hash } in
  let ((o, _), local) =
    inbound_scenario ~version:70016l
      ~services:(Int64.logor node_network node_witness)
      ~pre_verack:[P2p.PingMsg 42L; inv; P2p.FeefilterMsg 5000L; getheaders;
                   P2p.PingMsg 43L] in
  check_completed "handshake with pre-verack ping/inv" o;
  Alcotest.(check int) "no misbehaviour" 0 local.Peer.misbehavior_score;
  Alcotest.(check int64) "pre-verack feefilter ignored" 0L local.Peer.feefilter

(* 4. Outbound: the stricter service requirement stays. *)
let outbound_scenario ~version ~services =
  let open Lwt.Syntax in
  let local, remote = make_pair ~direction:Peer.Outbound in
  let node = run_handshake local (fun p -> Peer.perform_handshake p 0l) in
  let script =
    Lwt.catch (fun () ->
      let* _ = Peer.read_message_with_timeout remote 10.0 in  (* node's version *)
      let* () = Peer.send_message remote (remote_version remote ~version ~services) in
      let* () = Peer.send_message remote P2p.VerackMsg in
      let* _ = drain remote ~quiet:0.5 in
      Lwt.return_unit)
      (fun _ -> Lwt.return_unit)
  in
  fst (Lwt_main.run (Lwt.both node script))

let test_outbound_no_witness_rejected () =
  let o = outbound_scenario ~version:70016l ~services:node_network in
  Alcotest.(check bool) "outbound without NODE_WITNESS rejected" true
    (o <> Completed)

let test_outbound_old_version_with_services_ok () =
  let o = outbound_scenario ~version:70002l
      ~services:(Int64.logor node_network node_witness) in
  check_completed "outbound 70002 with NETWORK|WITNESS" o

(* 5. dispatch_message (message-loop path) mirrors the same rules. *)
let fresh_version_received () =
  let local, _ = make_pair ~direction:Peer.Inbound in
  local.Peer.version_received <- true;
  local

let test_dispatch_sendheaders_pre_verack () =
  let p = fresh_version_received () in
  let r = Lwt_main.run (Peer.dispatch_message p P2p.SendheadersMsg) in
  Alcotest.(check bool) "Continue" true (r = `Continue);
  Alcotest.(check bool) "send_headers recorded" true p.Peer.send_headers;
  Alcotest.(check int) "no misbehaviour" 0 p.Peer.misbehavior_score

let test_dispatch_ping_pre_verack_no_score () =
  let p = fresh_version_received () in
  let r = Lwt_main.run (Peer.dispatch_message p (P2p.PingMsg 7L)) in
  Alcotest.(check bool) "not a disconnect" true
    (match r with `Disconnect _ -> false | _ -> true);
  Alcotest.(check int) "no misbehaviour" 0 p.Peer.misbehavior_score

(* 6. VERSION payload with the optional trailing fields omitted (Core reads
   them only "if (!vRecv.empty())"; fRelay defaults to true). *)
let test_version_without_relay_byte () =
  let w = Serialize.writer_create () in
  Serialize.write_int32_le w 60002l;
  Serialize.write_int64_le w 1L;
  Serialize.write_int64_le w 0L;
  Serialize.serialize_net_addr w
    { Types.services = 0L; addr = Cstruct.create 16; port = 0 };
  Serialize.serialize_net_addr w
    { Types.services = 0L; addr = Cstruct.create 16; port = 0 };
  Serialize.write_int64_le w 99L;
  Serialize.write_string w "/old:0.1/";
  Serialize.write_int32_le w 5l;
  let r = Serialize.reader_of_cstruct (Serialize.writer_to_cstruct w) in
  let v = Serialize.deserialize_version_msg r in
  Alcotest.(check int32) "version" 60002l v.Types.protocol_version;
  Alcotest.(check int32) "start_height" 5l v.Types.start_height;
  Alcotest.(check bool) "relay defaults true" true v.Types.relay

let () =
  Alcotest.run "handshake_core_parity" [
    "inbound", [
      Alcotest.test_case "VERSION(70002) no-witness completes" `Quick
        test_inbound_70002_completes;
      Alcotest.test_case "below 31800 rejected" `Quick
        test_inbound_below_min_rejected;
      Alcotest.test_case "70016 gets full feature set" `Quick
        test_inbound_70016_features;
    ];
    "pre-verack", [
      Alcotest.test_case "sendheaders recorded, no disconnect" `Quick
        test_pre_verack_sendheaders_recorded;
      Alcotest.test_case "ping/inv/feefilter/getheaders ignored" `Quick
        test_pre_verack_ping_inv_ignored;
      Alcotest.test_case "dispatch: sendheaders recorded" `Quick
        test_dispatch_sendheaders_pre_verack;
      Alcotest.test_case "dispatch: ping not scored" `Quick
        test_dispatch_ping_pre_verack_no_score;
    ];
    "outbound", [
      Alcotest.test_case "no NODE_WITNESS rejected" `Quick
        test_outbound_no_witness_rejected;
      Alcotest.test_case "70002 with services completes" `Quick
        test_outbound_old_version_with_services_ok;
    ];
    "version-msg", [
      Alcotest.test_case "optional trailing fields" `Quick
        test_version_without_relay_byte;
    ];
  ]
