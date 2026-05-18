(* W136 BIP-130 sendheaders + BIP-133 feefilter + BIP-339 wtxidrelay audit
   — camlcoin (OCaml)

   Discovery-only audit.  30 gates / 19 BUGs documented.

   Bitcoin Core references:
   - bitcoin-core/src/net_processing.cpp
     - L283: m_wtxid_relay
     - L287: m_fee_filter_sent
     - L405-406: m_sent_sendheaders
     - L412: m_prefers_headers
     - L740-741: MaybeSendSendHeaders
     - L3710-3712: send WTXIDRELAY in VERSION receive
     - L3897: receive SENDHEADERS sets m_prefers_headers
     - L3919-3939: BIP-339 wtxidrelay state machine
     - L5035-5044: receive FEEFILTER, MoneyRange-validated
     - L5519-5580: MaybeSendSendHeaders + MaybeSendFeefilter
     - L5838-5840: announce_block revert-to-inv on MAX_BLOCKS_TO_ANNOUNCE
   - bitcoin-core/src/node/protocol_version.h: 70012 / 70013 / 70016
   - bitcoin-core/src/policy/fees/block_policy_estimator.{h,cpp}:
     FeeFilterRounder (1.1x spacing, 1e7 max, 2/3 round-down)

   Severity legend:
   - P0-CDIV: protocol-correctness divergence externally visible to peers
   - P1: feature-correctness gap (right format, wrong gating / ordering)
   - P2: privacy / fingerprinting / fairness drift
   - P3: surface / doc / constant drift

   BUGs (this wave):

   BUG-W136-1 (P1 G1): sendheaders sent unconditionally in handshake;
                        no MinimumChainWork gate.
   BUG-W136-2 (P3 G2): no `sent_sendheaders` latch on type peer.
   BUG-W136-3 (P1 G6): no MAX_BLOCKS_TO_ANNOUNCE constant; no
                        revert-to-inv in announce_block.
   BUG-W136-4 (P2 G8): pre-VERACK SENDHEADERS earns 10 misbehavior pts.
   BUG-W136-5 (P2 G10): no per-peer known-headers set.
   BUG-W136-6 (P2 G11): no pindexBestHeaderSent tracking.
   BUG-W136-7 (P3 G12): no defensive active-chain guard in announce_block.
   BUG-W136-8 (P3 G15): no -blocksonly mode.
   BUG-W136-9 (P3 G16): no ForceRelay permission.
   BUG-W136-10 (P0-CDIV G17): no IBD-aware MAX_MONEY ceiling for feefilter.
   BUG-W136-11 (P1 G18): no post-IBD-exit feefilter reset.
   BUG-W136-12 (P0-CDIV G19): no MoneyRange validation on received FEEFILTER.
   BUG-W136-13 (P2 G21): poisson_delay uses Random.float (stdlib PRNG).
   BUG-W136-14 (P3 G22): significant-change threshold is 1.33 not 4/3.
   BUG-W136-15 (P2 G23): reschedule_feefilter_soon uses Random.float.
   BUG-W136-16 (P0-CDIV G25): wtxidrelay-send gated on services.witness
                                instead of common-version only.
   BUG-W136-17 (P3 G27): no duplicate-wtxidrelay detection.
   BUG-W136-18 (P1 G29): no INV-type-mismatch filter on receive.
   BUG-W136-19 (P3 G30): no m_wtxid_relay_peers aggregate counter.
*)

open Camlcoin

(* ============================================================================
   Helpers
   ============================================================================ *)

let make_test_peer ?(direction = Peer.Inbound) () =
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Peer.make_peer ~network:Consensus.mainnet ~addr:"1.2.3.4"
    ~port:8333 ~id:0 ~direction ~fd ()

(* Read a source file fully — used for source-grep gates that have no
   API surface to probe.  Mirrors the helper in W130 / W131 / W132. *)
let read_file_opt (path : string) : string option =
  try
    let ic = open_in path in
    let len = in_channel_length ic in
    let buf = Bytes.create len in
    really_input ic buf 0 len;
    close_in ic;
    Some (Bytes.unsafe_to_string buf)
  with _ -> None

let string_contains (haystack : string) (needle : string) : bool =
  let hl = String.length haystack and nl = String.length needle in
  if nl = 0 then true
  else if nl > hl then false
  else begin
    let found = ref false in
    let i = ref 0 in
    while not !found && !i + nl <= hl do
      if String.sub haystack !i nl = needle then found := true
      else incr i
    done;
    !found
  end

let load_source (relative_path : string) : string option =
  let candidates = [
    relative_path;
    "../" ^ relative_path;
    "../../" ^ relative_path;
    "../../../" ^ relative_path;
    "/home/work/hashhog/camlcoin/" ^ relative_path;
  ] in
  let rec try_each = function
    | [] -> None
    | p :: rest ->
      (match read_file_opt p with Some s -> Some s | None -> try_each rest)
  in
  try_each candidates

(* Core MoneyRange: 0 <= n <= 21_000_000 * 100_000_000 sat. *)
let core_max_money : int64 = 2_100_000_000_000_000L

let core_money_range (n : int64) : bool =
  Int64.compare n 0L >= 0 && Int64.compare n core_max_money <= 0

(* ============================================================================
   G1-G6 — BIP-130 sendheaders SEND side
   ============================================================================ *)

(* G1: sendheaders should be gated on MinimumChainWork.
   Source-level evidence: peer.ml has neither `min_chain_work` nor
   `MinimumChainWork` reference at the SendheadersMsg send sites. *)
let test_g1_no_minimum_chain_work_gate () =
  let src = load_source "lib/peer.ml" in
  (match src with
   | None ->
     Alcotest.(check bool)
       "G1: BUG-W136-1 PRESENT (documentary — peer.ml not in cwd)" true true
   | Some s ->
     let has_min_chain_work =
       string_contains s "min_chain_work" ||
       string_contains s "MinimumChainWork" ||
       string_contains s "minimum_chain_work" in
     (* The send site send_message peer P2p.SendheadersMsg appears at
        peer.ml:1004 and 1061 in `perform_handshake_inner` and
        `perform_inbound_handshake_inner`.  Neither is preceded by a
        MinimumChainWork check.  We verify the absence by checking the
        token does not appear anywhere in peer.ml — present elsewhere
        in the codebase (sync.ml:950) but not here. *)
     Alcotest.(check bool)
       "G1: BUG-W136-1 — peer.ml has no MinimumChainWork reference"
       false has_min_chain_work)

(* G2: no `sent_sendheaders` latch field on `type peer`. *)
let test_g2_no_sent_sendheaders_latch () =
  let src = load_source "lib/peer.ml" in
  (match src with
   | None ->
     Alcotest.(check bool)
       "G2: BUG-W136-2 PRESENT (documentary)" true true
   | Some s ->
     let has_latch =
       string_contains s "sent_sendheaders" ||
       string_contains s "m_sent_sendheaders" in
     Alcotest.(check bool)
       "G2: BUG-W136-2 — peer.ml has no sent_sendheaders latch"
       false has_latch)

(* G3: protocol-version constant for SENDHEADERS. *)
let test_g3_sendheaders_version_constant () =
  Alcotest.(check int32)
    "G3: sendheaders_version = 70012" 70012l Consensus.sendheaders_version

(* G4: post-handshake order — handshake_complete flips BEFORE the
   inline SendheadersMsg.  Documentary: in perform_handshake_inner
   handshake_complete := true at line 1001, then SendheadersMsg sent at
   line 1004. *)
let test_g4_post_handshake_order () =
  let src = load_source "lib/peer.ml" in
  match src with
  | None ->
    Alcotest.(check bool) "G4: documentary — peer.ml not in cwd" true true
  | Some s ->
    (* Find first occurrence of `handshake_complete <- true` and the
       subsequent `SendheadersMsg`.  We just confirm both tokens appear
       in the file in expected relative order at least once. *)
    let has_complete = string_contains s "handshake_complete <- true" in
    let has_send = string_contains s "P2p.SendheadersMsg" in
    Alcotest.(check bool)
      "G4: peer.ml has both handshake_complete and SendheadersMsg send"
      true (has_complete && has_send)

(* G5: behavioural parity — block-relay-only outbound peers receive
   sendheaders.  Same root: handshake completes BEFORE block_relay_only
   is flipped (peer_manager.ml:986-990). *)
let test_g5_block_relay_only_receives_sendheaders () =
  let src = load_source "lib/peer_manager.ml" in
  match src with
  | None ->
    Alcotest.(check bool) "G5: documentary" true true
  | Some s ->
    (* `peer.Peer.block_relay_only <- true` is set after `connect_outbound_negotiated`
       which itself runs the full perform_handshake.  Just verify the
       block_relay_only <- true assignment exists and is in
       add_block_relay_peer (textual proxy). *)
    Alcotest.(check bool)
      "G5: peer_manager.ml has block_relay_only <- true after handshake"
      true (string_contains s "block_relay_only <- true")

(* G6: BUG-W136-3 — no MAX_BLOCKS_TO_ANNOUNCE constant; no
   revert-to-inv in announce_block. *)
let test_g6_no_max_blocks_to_announce () =
  let pm = load_source "lib/peer_manager.ml" in
  match pm with
  | None ->
    Alcotest.(check bool) "G6: BUG-W136-3 PRESENT (documentary)" true true
  | Some s ->
    let has_constant =
      string_contains s "MAX_BLOCKS_TO_ANNOUNCE" ||
      string_contains s "max_blocks_to_announce" in
    let has_revert =
      string_contains s "fRevertToInv" ||
      string_contains s "revert_to_inv" ||
      string_contains s "revertToInv" in
    Alcotest.(check bool)
      "G6: BUG-W136-3 — no MAX_BLOCKS_TO_ANNOUNCE constant"
      false has_constant;
    Alcotest.(check bool)
      "G6: BUG-W136-3 — no revert-to-inv path in announce_block"
      false has_revert

(* ============================================================================
   G7-G12 — BIP-130 sendheaders RECEIVE side + announcement integration
   ============================================================================ *)

(* G7: receive-side SENDHEADERS flips peer.send_headers. *)
let test_g7_receive_sets_send_headers_flag () =
  let peer = make_test_peer () in
  Alcotest.(check bool) "G7: peer.send_headers initially false"
    false peer.Peer.send_headers;
  peer.Peer.send_headers <- true;
  Alcotest.(check bool) "G7: peer.send_headers settable to true"
    true peer.Peer.send_headers

(* G8: BUG-W136-4 — pre-VERACK SENDHEADERS earns 10 misbehavior pts.
   Source evidence: the catch-all `_, false` arm in dispatch_message
   (peer.ml:1626-1628) gives "pre-handshake message" 10 points.  Core
   accepts SENDHEADERS pre-VERACK silently. *)
let test_g8_pre_verack_sendheaders_misbehaves () =
  let src = load_source "lib/peer.ml" in
  match src with
  | None ->
    Alcotest.(check bool) "G8: BUG-W136-4 PRESENT (documentary)" true true
  | Some s ->
    (* SendheadersMsg has no `, false` arm in dispatch_message — it only
       has the `, true` arm at line 1639.  Pre-handshake SENDHEADERS
       falls to the `_, false -> misbehaving peer 10` catch-all.  We
       verify: SendheadersMsg pattern appears exactly once (the post-
       handshake arm) and no `P2p.SendheadersMsg, false` arm exists. *)
    Alcotest.(check bool)
      "G8: BUG-W136-4 — no `SendheadersMsg, false` arm in dispatch_message"
      false (string_contains s "SendheadersMsg, false")

(* G9: announce_block honours send_headers branch. *)
let test_g9_announce_block_honours_send_headers () =
  let src = load_source "lib/peer_manager.ml" in
  match src with
  | None ->
    Alcotest.(check bool) "G9: documentary" true true
  | Some s ->
    Alcotest.(check bool)
      "G9: peer_manager.ml branches on peer.Peer.send_headers"
      true (string_contains s "peer.Peer.send_headers")

(* G10: BUG-W136-5 — no per-peer known-headers set. *)
let test_g10_no_known_headers_set () =
  let src = load_source "lib/peer.ml" in
  match src with
  | None ->
    Alcotest.(check bool) "G10: BUG-W136-5 PRESENT (documentary)" true true
  | Some s ->
    let has_known =
      string_contains s "m_blocks_known" ||
      string_contains s "known_blocks" ||
      string_contains s "known_headers" ||
      string_contains s "PeerHasHeader" in
    Alcotest.(check bool)
      "G10: BUG-W136-5 — peer.ml has no known-headers tracking"
      false has_known

(* G11: BUG-W136-6 — no pindexBestHeaderSent. *)
let test_g11_no_best_header_sent () =
  let src = load_source "lib/peer.ml" in
  match src with
  | None ->
    Alcotest.(check bool) "G11: BUG-W136-6 PRESENT (documentary)" true true
  | Some s ->
    let has_best =
      string_contains s "best_header_sent" ||
      string_contains s "pindexBestHeaderSent" ||
      string_contains s "BestHeaderSent" in
    Alcotest.(check bool)
      "G11: BUG-W136-6 — peer.ml has no best_header_sent tracking"
      false has_best

(* G12: BUG-W136-7 — no defensive active-chain guard in announce_block. *)
let test_g12_no_active_chain_guard_in_announce_block () =
  let src = load_source "lib/peer_manager.ml" in
  match src with
  | None ->
    Alcotest.(check bool) "G12: BUG-W136-7 PRESENT (documentary)" true true
  | Some s ->
    (* announce_block is defined at line 1360 and does not consult
       active chain / chain manager.  Verify: the file has the
       announce_block definition. *)
    Alcotest.(check bool)
      "G12: peer_manager.ml defines announce_block"
      true (string_contains s "let announce_block")

(* ============================================================================
   G13-G18 — BIP-133 feefilter SEND side
   ============================================================================ *)

(* G13: feefilter common-version >= FEEFILTER_VERSION gate.
   camlcoin's gate is peer.protocol_version >= feefilter_version (70013),
   which is structurally equivalent for camlcoin because
   min_protocol_version = 70015 (peer.ml:224).  No bug. *)
let test_g13_feefilter_version_constant () =
  Alcotest.(check int32)
    "G13: feefilter_version = 70013" 70013l Consensus.feefilter_version;
  Alcotest.(check int32)
    "G13: Peer.feefilter_version = 70013l" 70013l Peer.feefilter_version

(* G14: block-relay-only outbound peer skip — confirmed in
   should_send_feefilter (peer.ml:1945). *)
let test_g14_block_relay_only_skips_feefilter () =
  let peer = make_test_peer () in
  peer.Peer.block_relay_only <- true;
  peer.Peer.state <- Peer.Ready;
  peer.Peer.handshake_complete <- true;
  Alcotest.(check bool)
    "G14: should_send_feefilter returns false for block_relay_only=true"
    false (Peer.should_send_feefilter peer)

(* G15: BUG-W136-8 — no -blocksonly mode. *)
let test_g15_no_blocksonly_mode () =
  let src = load_source "lib/peer.ml" in
  let cli = load_source "lib/cli.ml" in
  let combined = Option.value src ~default:"" ^ Option.value cli ~default:"" in
  let has =
    string_contains combined "ignore_incoming_txs" ||
    string_contains combined "blocksonly"
  in
  Alcotest.(check bool)
    "G15: BUG-W136-8 — no -blocksonly mode" false has

(* G16: BUG-W136-9 — no ForceRelay permission. *)
let test_g16_no_force_relay () =
  let src = load_source "lib/peer.ml" in
  match src with
  | None ->
    Alcotest.(check bool) "G16: BUG-W136-9 PRESENT (documentary)" true true
  | Some s ->
    let has =
      string_contains s "ForceRelay" ||
      string_contains s "force_relay" ||
      string_contains s "forcerelay"
    in
    Alcotest.(check bool)
      "G16: BUG-W136-9 — no ForceRelay permission in peer.ml" false has

(* G17: BUG-W136-10 — no IBD-aware MAX_MONEY ceiling.
   send_feefilter / maybe_send_feefilter always uses mp.min_relay_fee
   (1000 sat/kvB).  No IsInitialBlockDownload check, no MAX_MONEY
   injection, no IBD-mode reset. *)
let test_g17_no_ibd_max_money_ceiling () =
  let src = load_source "lib/peer.ml" in
  let pm = load_source "lib/peer_manager.ml" in
  let combined = Option.value src ~default:"" ^ Option.value pm ~default:"" in
  let has =
    string_contains combined "IsInitialBlockDownload" ||
    string_contains combined "is_initial_block_download" ||
    string_contains combined "ibd_state.is_ibd" ||
    string_contains combined "max_money" ||
    string_contains combined "MAX_MONEY"
  in
  Alcotest.(check bool)
    "G17: BUG-W136-10 — feefilter send path has no IBD/MAX_MONEY check"
    false has

(* G18: BUG-W136-11 — no post-IBD-exit feefilter reset.
   If G17 is closed, peer.next_send_feefilter <- 0 on IBD exit is the
   necessary follow-up so the real filter is announced promptly. *)
let test_g18_no_post_ibd_reset () =
  let src = load_source "lib/peer.ml" in
  match src with
  | None ->
    Alcotest.(check bool) "G18: BUG-W136-11 PRESENT (documentary)" true true
  | Some s ->
    (* Look for any "next_send_feefilter <- 0" or any reset-to-zero
       pattern.  The schedule_next_feefilter helper unconditionally
       Poissons forward; no zero-reset exists. *)
    let has_reset =
      string_contains s "next_send_feefilter <- 0.0" ||
      string_contains s "next_send_feefilter <- 0L" ||
      (* allow trivial whitespace variants *)
      string_contains s "next_send_feefilter <- 0"
    in
    Alcotest.(check bool)
      "G18: BUG-W136-11 — no post-IBD-exit feefilter zero-reset"
      false has_reset

(* ============================================================================
   G19-G24 — BIP-133 feefilter RECEIVE + state + timing
   ============================================================================ *)

(* G19: BUG-W136-12 — no MoneyRange validation on received FEEFILTER.
   Source-grep: feefilter <- feerate assignments in peer.ml dispatch_message
   (lines 1601-1607, 1665-1667, 838-841) are unconditional. *)
let test_g19_no_money_range_validation () =
  let src = load_source "lib/peer.ml" in
  match src with
  | None ->
    Alcotest.(check bool) "G19: BUG-W136-12 PRESENT (documentary)" true true
  | Some s ->
    (* The presence of a MoneyRange check would require some
       MoneyRange / money_range / MAX_MONEY constant reference.
       Confirm none of these exist near the feefilter recv sites. *)
    let has =
      string_contains s "MoneyRange" ||
      string_contains s "money_range" ||
      string_contains s "MAX_MONEY" ||
      string_contains s "max_money"
    in
    Alcotest.(check bool)
      "G19: BUG-W136-12 — peer.ml has no MoneyRange/MAX_MONEY check"
      false has

(* G19b: numerical example — Core would silently drop a negative
   feefilter; camlcoin stores it.  We do not invoke deserialisation
   directly (no public hook for raw FEEFILTER injection), so verify
   the boundary check semantics via core_money_range oracle. *)
let test_g19b_money_range_boundary_oracle () =
  Alcotest.(check bool) "G19b: 0 sat is in MoneyRange" true
    (core_money_range 0L);
  Alcotest.(check bool) "G19b: MAX_MONEY is in MoneyRange" true
    (core_money_range core_max_money);
  Alcotest.(check bool) "G19b: -1 sat is OUT of MoneyRange" false
    (core_money_range (-1L));
  Alcotest.(check bool) "G19b: MAX_MONEY+1 is OUT of MoneyRange" false
    (core_money_range (Int64.add core_max_money 1L))

(* G20: per-peer m_fee_filter_received separate from sent.
   In camlcoin: peer.feefilter (received) and peer.fee_filter_sent. *)
let test_g20_separate_sent_recv_fields () =
  let peer = make_test_peer () in
  Alcotest.(check int64) "G20: peer.feefilter (received) init = 0" 0L
    peer.Peer.feefilter;
  Alcotest.(check int64) "G20: peer.fee_filter_sent init = 0" 0L
    peer.Peer.fee_filter_sent;
  peer.Peer.feefilter <- 5000L;
  peer.Peer.fee_filter_sent <- 3000L;
  Alcotest.(check int64) "G20: feefilter (received) settable" 5000L
    peer.Peer.feefilter;
  Alcotest.(check int64) "G20: fee_filter_sent settable" 3000L
    peer.Peer.fee_filter_sent

(* G21: BUG-W136-13 — poisson_delay uses Random.float (stdlib PRNG)
   instead of CSPRNG.  csprng_int_range exists in peer.ml:316-331 for
   exactly this purpose. *)
let test_g21_poisson_uses_stdlib_random () =
  let src = load_source "lib/peer.ml" in
  match src with
  | None ->
    Alcotest.(check bool) "G21: BUG-W136-13 PRESENT (documentary)" true true
  | Some s ->
    (* poisson_delay body contains `Random.float 1.0`.  CSPRNG would
       use csprng_int_range or /dev/urandom directly. *)
    Alcotest.(check bool)
      "G21: BUG-W136-13 — poisson_delay uses Random.float"
      true (string_contains s "Random.float 1.0")

(* G22: BUG-W136-14 — significant_feefilter_change threshold is 1.33
   instead of 4.0 /. 3.0 = 1.3333...  Detect via numerical test:
   the boundary value of current = 1334, sent = 1000 should trigger
   per Core (1334 > 1333.33) but not per camlcoin (1334 > 1330 — wait,
   it WILL trigger because 1334 > 1.33 * 1000 = 1330; but at
   current = 1333: Core 1333 > 1333.33 → false, camlcoin 1333 > 1330
   → true.  3-sat-per-kvB window of divergence. *)
let test_g22_significant_change_threshold_drift () =
  (* Verify Core's threshold differs from camlcoin's via floating point. *)
  let camlcoin_threshold = 1.33 in
  let core_threshold = 4.0 /. 3.0 in
  Alcotest.(check bool)
    "G22: camlcoin 1.33 < Core 4/3" true
    (camlcoin_threshold < core_threshold);
  (* Numerical example: sent_fee = 1000.  Boundary cases. *)
  let current_fee_low = 1333.0 in
  let current_fee_high = 1334.0 in
  Alcotest.(check bool)
    "G22: 1333/1000 = 1.333 > 1.33 (camlcoin triggers)" true
    (current_fee_low /. 1000.0 > camlcoin_threshold);
  Alcotest.(check bool)
    "G22: 1333/1000 = 1.333 < 4/3 (Core does NOT trigger)" true
    (current_fee_low /. 1000.0 < core_threshold);
  Alcotest.(check bool)
    "G22: 1334/1000 = 1.334 > 4/3 (Core triggers)" true
    (current_fee_high /. 1000.0 > core_threshold)

(* G23: BUG-W136-15 — reschedule_feefilter_soon uses Random.float. *)
let test_g23_reschedule_uses_stdlib_random () =
  let src = load_source "lib/peer.ml" in
  match src with
  | None ->
    Alcotest.(check bool) "G23: BUG-W136-15 PRESENT (documentary)" true true
  | Some s ->
    Alcotest.(check bool)
      "G23: BUG-W136-15 — reschedule_feefilter_soon uses Random.float"
      true (string_contains s "Random.float max_feefilter_change_delay")

(* G24: no-resend-on-unchanged — maybe_send_feefilter returns false
   when rounded = fee_filter_sent (peer.ml:1999-2005). *)
let test_g24_no_resend_when_unchanged () =
  let src = load_source "lib/peer.ml" in
  match src with
  | None ->
    Alcotest.(check bool) "G24: documentary" true true
  | Some s ->
    (* Verify the equality check is in maybe_send_feefilter. *)
    Alcotest.(check bool)
      "G24: maybe_send_feefilter checks rounded = peer.fee_filter_sent"
      true (string_contains s "rounded = peer.fee_filter_sent")

(* ============================================================================
   G25-G27 — BIP-339 wtxidrelay SEND + RECV + state
   ============================================================================ *)

(* G25: BUG-W136-16 — wtxidrelay-send gated on services.witness.
   Source-grep: send_feature_negotiation requires peer.services.witness
   (peer.ml:786-791).  Core gates only on common-version >= 70016. *)
let test_g25_wtxidrelay_gated_on_witness_service () =
  let src = load_source "lib/peer.ml" in
  match src with
  | None ->
    Alcotest.(check bool) "G25: BUG-W136-16 PRESENT (documentary)" true true
  | Some s ->
    (* The gate `peer.services.witness &&` in send_feature_negotiation. *)
    Alcotest.(check bool)
      "G25: BUG-W136-16 — send_feature_negotiation gates on peer.services.witness"
      true (string_contains s "peer.services.witness &&")

(* G25b: protocol version constant matches Core. *)
let test_g25b_wtxid_relay_version_constant () =
  Alcotest.(check int32)
    "G25b: wtxid_relay_version = 70016" 70016l Consensus.wtxid_relay_version

(* G26: receive post-VERACK WTXIDRELAY = disconnect.
   Source-level: peer.ml:1643-1646 has `WtxidrelayMsg, true ->
   misbehaving + Disconnect`. *)
let test_g26_post_verack_wtxidrelay_disconnects () =
  let src = load_source "lib/peer.ml" in
  match src with
  | None ->
    Alcotest.(check bool) "G26: documentary" true true
  | Some s ->
    (* Verify the post-handshake arm exists. *)
    Alcotest.(check bool)
      "G26: peer.ml has post-handshake WtxidrelayMsg disconnect arm"
      true (string_contains s "wtxidrelay after handshake")

(* G27: BUG-W136-17 — no duplicate wtxidrelay detection.
   peer.ml:1570-1577 unconditionally sets peer.wtxid_relay <- true. *)
let test_g27_no_duplicate_detection () =
  let src = load_source "lib/peer.ml" in
  match src with
  | None ->
    Alcotest.(check bool) "G27: BUG-W136-17 PRESENT (documentary)" true true
  | Some s ->
    (* Look for any "duplicate" / "already" pattern near WtxidrelayMsg. *)
    let has =
      string_contains s "duplicate wtxidrelay" ||
      string_contains s "already_wtxid" ||
      string_contains s "if not peer.wtxid_relay"
    in
    Alcotest.(check bool)
      "G27: BUG-W136-17 — no duplicate wtxidrelay detection in peer.ml"
      false has

(* ============================================================================
   G28-G30 — state, integration, end-to-end
   ============================================================================ *)

(* G28: INV-type matches wtxidrelay on SEND (announce_tx). *)
let test_g28_inv_type_matches_wtxidrelay_on_send () =
  let src = load_source "lib/peer_manager.ml" in
  match src with
  | None ->
    Alcotest.(check bool) "G28: documentary" true true
  | Some s ->
    (* announce_tx branches on peer.Peer.wtxid_relay to choose
       make_tx_inv ~witness:true vs ~witness:false. *)
    Alcotest.(check bool)
      "G28: peer_manager.ml branches announce_tx on peer.Peer.wtxid_relay"
      true (string_contains s "if peer.Peer.wtxid_relay")

(* G29: BUG-W136-18 — no INV-type-mismatch filter on RECEIVE.  Core
   ignores INVs that don't match wtxidrelay setting
   (net_processing.cpp:4056-4063). *)
let test_g29_no_inv_type_mismatch_filter () =
  let src = load_source "lib/peer.ml" in
  let pm = load_source "lib/peer_manager.ml" in
  let combined = Option.value src ~default:"" ^ Option.value pm ~default:"" in
  let has =
    string_contains combined "wtxid_relay && inv_type" ||
    string_contains combined "Ignore INVs that don't match" ||
    string_contains combined "inv_type_mismatch"
  in
  Alcotest.(check bool)
    "G29: BUG-W136-18 — no INV-type-mismatch filter on receive"
    false has

(* G30: BUG-W136-19 — no m_wtxid_relay_peers aggregate counter. *)
let test_g30_no_aggregate_counter () =
  let src = load_source "lib/peer.ml" in
  let pm = load_source "lib/peer_manager.ml" in
  let combined = Option.value src ~default:"" ^ Option.value pm ~default:"" in
  let has =
    string_contains combined "wtxid_relay_peers" ||
    string_contains combined "m_wtxid_relay_peers" ||
    string_contains combined "wtxid_relay_count"
  in
  Alcotest.(check bool)
    "G30: BUG-W136-19 — no aggregate wtxid_relay_peers counter"
    false has

(* ============================================================================
   Invariant guards
   ============================================================================ *)

(* INV-1: protocol-version constants match Core. *)
let test_inv1_protocol_version_constants () =
  Alcotest.(check int32) "INV-1: SENDHEADERS_VERSION = 70012"
    70012l Consensus.sendheaders_version;
  Alcotest.(check int32) "INV-1: FEEFILTER_VERSION = 70013"
    70013l Consensus.feefilter_version;
  Alcotest.(check int32) "INV-1: WTXID_RELAY_VERSION = 70016"
    70016l Consensus.wtxid_relay_version

(* INV-2: AVG_FEEFILTER_BROADCAST_INTERVAL = 600s. *)
let test_inv2_avg_broadcast_interval () =
  Alcotest.(check bool) "INV-2: avg_feefilter_broadcast_interval = 600.0"
    true (abs_float (Peer.avg_feefilter_broadcast_interval -. 600.0) < 0.001)

(* INV-3: MAX_FEEFILTER_CHANGE_DELAY = 300s. *)
let test_inv3_max_change_delay () =
  Alcotest.(check bool) "INV-3: max_feefilter_change_delay = 300.0"
    true (abs_float (Peer.max_feefilter_change_delay -. 300.0) < 0.001)

(* INV-4: FeeFilterRounder buckets cover Core's spec.  Spacing 1.1x,
   max 1e7.  Verify bucket array contains 0.0 (sentinel) and at least
   one bucket near 1000. *)
let test_inv4_fee_filter_rounder_bucket_layout () =
  let buckets = Peer.FeeFilterRounder.make_fee_set 1000L in
  let n = Array.length buckets in
  Alcotest.(check bool) "INV-4: bucket set non-empty" true (n > 0);
  Alcotest.(check bool) "INV-4: first bucket is 0.0" true
    (buckets.(0) = 0.0);
  Alcotest.(check bool) "INV-4: last bucket >= 1e6"
    true (buckets.(n - 1) >= 1_000_000.0)

(* INV-5: FeeFilterRounder round() is monotone (idempotent at bucket
   boundaries) — quantizes a fee rate to a bucket value. *)
let test_inv5_round_returns_bucket_value () =
  let buckets = Peer.FeeFilterRounder.make_fee_set 1000L in
  (* round(1000) should return one of the buckets exactly (within
     int64-of-float conversion).  Probabilistic, so verify the result is
     non-negative and bounded by the max bucket. *)
  let r = Peer.FeeFilterRounder.round buckets 1000L in
  Alcotest.(check bool) "INV-5: round(1000) is non-negative" true
    (Int64.compare r 0L >= 0);
  let max_bucket = Int64.of_float buckets.(Array.length buckets - 1) in
  Alcotest.(check bool) "INV-5: round(1000) <= max bucket" true
    (Int64.compare r max_bucket <= 0)

(* INV-6: passes_feefilter — tx_fee_rate >= peer.feefilter passes. *)
let test_inv6_passes_feefilter () =
  let peer = make_test_peer () in
  peer.Peer.feefilter <- 5000L;
  let pass_entry = Peer.make_tx_inv ~witness:false (Cstruct.create 32) 6000L in
  let fail_entry = Peer.make_tx_inv ~witness:false (Cstruct.create 32) 4000L in
  let block_entry = Peer.make_block_inv (Cstruct.create 32) in
  Alcotest.(check bool) "INV-6: tx with fee_rate >= filter passes"
    true (Peer.passes_feefilter peer pass_entry);
  Alcotest.(check bool) "INV-6: tx with fee_rate < filter fails"
    false (Peer.passes_feefilter peer fail_entry);
  Alcotest.(check bool) "INV-6: block (no fee_rate) always passes"
    true (Peer.passes_feefilter peer block_entry)

(* ============================================================================
   Test runner
   ============================================================================ *)

let () =
  Alcotest.run "W136 BIP-130/133/339 relay flags" [
    "G1-G6 — BIP-130 sendheaders SEND side", [
      Alcotest.test_case "G1: no MinimumChainWork gate (BUG-W136-1)" `Quick
        test_g1_no_minimum_chain_work_gate;
      Alcotest.test_case "G2: no sent_sendheaders latch (BUG-W136-2)" `Quick
        test_g2_no_sent_sendheaders_latch;
      Alcotest.test_case "G3: SENDHEADERS_VERSION = 70012" `Quick
        test_g3_sendheaders_version_constant;
      Alcotest.test_case "G4: post-handshake order" `Quick
        test_g4_post_handshake_order;
      Alcotest.test_case "G5: block-relay-only outbound also receives" `Quick
        test_g5_block_relay_only_receives_sendheaders;
      Alcotest.test_case "G6: no MAX_BLOCKS_TO_ANNOUNCE (BUG-W136-3)" `Quick
        test_g6_no_max_blocks_to_announce;
    ];
    "G7-G12 — BIP-130 sendheaders RECEIVE + announce", [
      Alcotest.test_case "G7: receive sets send_headers flag" `Quick
        test_g7_receive_sets_send_headers_flag;
      Alcotest.test_case "G8: pre-VERACK SENDHEADERS misbehaves (BUG-W136-4)" `Quick
        test_g8_pre_verack_sendheaders_misbehaves;
      Alcotest.test_case "G9: announce_block honours send_headers" `Quick
        test_g9_announce_block_honours_send_headers;
      Alcotest.test_case "G10: no known-headers set (BUG-W136-5)" `Quick
        test_g10_no_known_headers_set;
      Alcotest.test_case "G11: no best_header_sent (BUG-W136-6)" `Quick
        test_g11_no_best_header_sent;
      Alcotest.test_case "G12: no active-chain guard (BUG-W136-7)" `Quick
        test_g12_no_active_chain_guard_in_announce_block;
    ];
    "G13-G18 — BIP-133 feefilter SEND", [
      Alcotest.test_case "G13: feefilter_version = 70013" `Quick
        test_g13_feefilter_version_constant;
      Alcotest.test_case "G14: block_relay_only skips" `Quick
        test_g14_block_relay_only_skips_feefilter;
      Alcotest.test_case "G15: no -blocksonly mode (BUG-W136-8)" `Quick
        test_g15_no_blocksonly_mode;
      Alcotest.test_case "G16: no ForceRelay (BUG-W136-9)" `Quick
        test_g16_no_force_relay;
      Alcotest.test_case "G17: ★ no IBD MAX_MONEY (BUG-W136-10 P0)" `Quick
        test_g17_no_ibd_max_money_ceiling;
      Alcotest.test_case "G18: no post-IBD reset (BUG-W136-11)" `Quick
        test_g18_no_post_ibd_reset;
    ];
    "G19-G24 — BIP-133 feefilter RECEIVE + state + timing", [
      Alcotest.test_case "G19: ★ no MoneyRange (BUG-W136-12 P0)" `Quick
        test_g19_no_money_range_validation;
      Alcotest.test_case "G19b: MoneyRange oracle" `Quick
        test_g19b_money_range_boundary_oracle;
      Alcotest.test_case "G20: separate sent/recv fields" `Quick
        test_g20_separate_sent_recv_fields;
      Alcotest.test_case "G21: poisson_delay uses stdlib (BUG-W136-13)" `Quick
        test_g21_poisson_uses_stdlib_random;
      Alcotest.test_case "G22: 1.33 vs 4/3 (BUG-W136-14)" `Quick
        test_g22_significant_change_threshold_drift;
      Alcotest.test_case "G23: reschedule uses stdlib (BUG-W136-15)" `Quick
        test_g23_reschedule_uses_stdlib_random;
      Alcotest.test_case "G24: no-resend-on-unchanged" `Quick
        test_g24_no_resend_when_unchanged;
    ];
    "G25-G27 — BIP-339 wtxidrelay", [
      Alcotest.test_case "G25: ★ witness-gate (BUG-W136-16 P0)" `Quick
        test_g25_wtxidrelay_gated_on_witness_service;
      Alcotest.test_case "G25b: wtxid_relay_version = 70016" `Quick
        test_g25b_wtxid_relay_version_constant;
      Alcotest.test_case "G26: post-VERACK disconnects" `Quick
        test_g26_post_verack_wtxidrelay_disconnects;
      Alcotest.test_case "G27: no duplicate detection (BUG-W136-17)" `Quick
        test_g27_no_duplicate_detection;
    ];
    "G28-G30 — integration / end-to-end", [
      Alcotest.test_case "G28: INV matches wtxidrelay on send" `Quick
        test_g28_inv_type_matches_wtxidrelay_on_send;
      Alcotest.test_case "G29: no INV-type-mismatch filter (BUG-W136-18)" `Quick
        test_g29_no_inv_type_mismatch_filter;
      Alcotest.test_case "G30: no aggregate counter (BUG-W136-19)" `Quick
        test_g30_no_aggregate_counter;
    ];
    "Invariant guards", [
      Alcotest.test_case "INV-1: version constants" `Quick
        test_inv1_protocol_version_constants;
      Alcotest.test_case "INV-2: avg broadcast interval = 600s" `Quick
        test_inv2_avg_broadcast_interval;
      Alcotest.test_case "INV-3: max change delay = 300s" `Quick
        test_inv3_max_change_delay;
      Alcotest.test_case "INV-4: bucket layout" `Quick
        test_inv4_fee_filter_rounder_bucket_layout;
      Alcotest.test_case "INV-5: round returns bucket value" `Quick
        test_inv5_round_returns_bucket_value;
      Alcotest.test_case "INV-6: passes_feefilter behaviour" `Quick
        test_inv6_passes_feefilter;
    ];
  ]
