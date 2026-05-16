(* FIX-67 — W119 PayJoin receiver-cleanup.

   Direct unit tests for the new pure helpers added to
   [Payjoin] in this fix-wave:

     G18 — session TTL Map     (open_session / lookup / expire /
                                list_sessions / record_session_spent_utxos)
     G19 — double-spend check  (check_no_double_spend)
     G20 — anti-fingerprint    (select_anti_fp_utxo)
     G30 — replay protection   (check_and_record_replay)

   And exercises the RPC dispatch wrappers for the same 4 gates plus
   the trivially-wired G3/G4/G5/G6/G7/G8/G9/G17 envelopes.

   References:
     - BIP-78 (Serverless PayJoin)
     - W119 audit a744e62 (30 gates)
     - FIX-65 272a73c, FIX-66 3794c51 — prior receiver / sender pieces
*)

open Camlcoin

(* ============================================================================
   Test fixtures
   ============================================================================ *)

let make_p2wpkh_script ?(byte = 0x00) pkh =
  let s = Cstruct.create 22 in
  Cstruct.set_uint8 s 0 0x00;
  Cstruct.set_uint8 s 1 0x14;
  Cstruct.blit pkh 0 s 2 20;
  Cstruct.set_uint8 s 5 byte;
  s

let make_orig_psbt
    ~(sender_outpoints : (Types.outpoint * Types.tx_out) list)
    ~(outputs : Types.tx_out list)
    : Psbt.psbt =
  let tx : Types.transaction = {
    version = 2l;
    inputs = List.map (fun (op, _) ->
      { Types.previous_output = op;
        script_sig = Cstruct.create 0;
        sequence = 0xFFFFFFFDl;
      }
    ) sender_outpoints;
    outputs;
    witnesses = [];
    locktime = 0l;
  } in
  let psbt = Psbt.create tx in
  let inputs =
    List.map (fun (_, prevout) ->
      { Psbt.empty_input with
        witness_utxo = Some prevout;
        final_scriptwitness = Some [Cstruct.of_string "\x00"];
      }
    ) sender_outpoints
  in
  { psbt with inputs }

let _outpoint_with_byte (b : int) (vout : int32) : Types.outpoint =
  let t = Cstruct.create 32 in
  Cstruct.set_uint8 t 0 b;
  { Types.txid = t; vout }

(* ============================================================================
   G18 — TTL session map
   ============================================================================ *)

let test_g18_open_lookup () =
  Payjoin._reset_all_state ();
  let s = Payjoin.open_session
    ~ttl_sec:60.0 ~orig_psbt_b64:"abc" () in
  match Payjoin.lookup_session s.session_id with
  | Some s' ->
    Alcotest.(check string) "session_id round-trips"
      s.session_id s'.session_id;
    Alcotest.(check string) "psbt digest stable"
      s.orig_psbt_digest s'.orig_psbt_digest
  | None ->
    Alcotest.fail "G18: just-opened session must look up"

let test_g18_ttl_expiry () =
  Payjoin._reset_all_state ();
  (* Fast-forward the clock so the session expires. *)
  let now_ref = ref 1000.0 in
  Payjoin.override_clock (fun () -> !now_ref);
  let s = Payjoin.open_session
    ~ttl_sec:5.0 ~orig_psbt_b64:"ttl-test" () in
  Alcotest.(check bool) "alive @ open"
    true (Payjoin.lookup_session s.session_id <> None);
  now_ref := 1010.0;  (* +10s — past 5s TTL *)
  Alcotest.(check bool) "expired @ +10s"
    true (Payjoin.lookup_session s.session_id = None);
  Payjoin.override_clock Unix.gettimeofday

let test_g18_expire_explicit () =
  Payjoin._reset_all_state ();
  let s = Payjoin.open_session ~orig_psbt_b64:"x" () in
  let removed = Payjoin.expire_session s.session_id in
  Alcotest.(check bool) "explicit expire removes" true removed;
  Alcotest.(check bool) "explicit expire idempotent"
    false (Payjoin.expire_session s.session_id);
  Alcotest.(check bool) "lookup-after-expire returns None"
    true (Payjoin.lookup_session s.session_id = None)

let test_g18_list_sessions () =
  Payjoin._reset_all_state ();
  let s1 = Payjoin.open_session ~orig_psbt_b64:"a" () in
  let s2 = Payjoin.open_session ~orig_psbt_b64:"b" () in
  let listed = Payjoin.list_sessions () in
  Alcotest.(check int) "two sessions listed" 2 (List.length listed);
  let ids = List.map (fun s -> s.Payjoin.session_id) listed in
  Alcotest.(check bool) "session 1 listed" true (List.mem s1.session_id ids);
  Alcotest.(check bool) "session 2 listed" true (List.mem s2.session_id ids)

let test_g18_record_spent () =
  Payjoin._reset_all_state ();
  let s = Payjoin.open_session ~orig_psbt_b64:"r" () in
  let op = _outpoint_with_byte 0x01 0l in
  match Payjoin.record_session_spent_utxos
          ~session_id:s.session_id ~outpoints:[op] with
  | Ok () ->
    let s' = (match Payjoin.lookup_session s.session_id with
              | Some s' -> s'
              | None -> Alcotest.fail "G18: session gone after record") in
    Alcotest.(check int) "1 outpoint recorded" 1
      (List.length s'.claimed_outpoints)
  | Error e -> Alcotest.failf "G18 record_spent: %s" e

(* ============================================================================
   G19 — Double-spend across sessions
   ============================================================================ *)

let test_g19_no_conflict () =
  Payjoin._reset_all_state ();
  let _ = Payjoin.open_session ~orig_psbt_b64:"empty" () in
  let candidates = [_outpoint_with_byte 0xAA 0l] in
  match Payjoin.check_no_double_spend
          ~session_id:"unrelated-id" ~candidates with
  | Ok () -> ()
  | Error e -> Alcotest.failf "G19 spurious conflict: %s" e

let test_g19_conflict_detected () =
  Payjoin._reset_all_state ();
  let s1 = Payjoin.open_session ~orig_psbt_b64:"s1" () in
  let op = _outpoint_with_byte 0x42 1l in
  let _ = Payjoin.record_session_spent_utxos
            ~session_id:s1.session_id ~outpoints:[op] in
  let s2 = Payjoin.open_session ~orig_psbt_b64:"s2" () in
  match Payjoin.check_no_double_spend
          ~session_id:s2.session_id ~candidates:[op] with
  | Ok () -> Alcotest.fail "G19: conflict missed"
  | Error _ -> ()

let test_g19_self_session_exempt () =
  Payjoin._reset_all_state ();
  let s = Payjoin.open_session ~orig_psbt_b64:"self" () in
  let op = _outpoint_with_byte 0x55 0l in
  let _ = Payjoin.record_session_spent_utxos
            ~session_id:s.session_id ~outpoints:[op] in
  match Payjoin.check_no_double_spend
          ~session_id:s.session_id ~candidates:[op] with
  | Ok () -> ()
  | Error e -> Alcotest.failf "G19: same-session must NOT conflict: %s" e

(* ============================================================================
   G20 — Anti-fingerprint UTXO selection
   ============================================================================ *)

let _wallet_utxo_of (script : Cstruct.t) (value : int64)
    : Wallet.wallet_utxo =
  { outpoint = _outpoint_with_byte 0xFE 0l;
    utxo = { Utxo.value; script_pubkey = script;
             height = 100; is_coinbase = false };
    key_index = 0;
    confirmed = true; }

let test_g20_prefer_matching_script_type () =
  let pkh = Cstruct.create 20 in
  let send_spk = make_p2wpkh_script ~byte:0x11 pkh in
  let outs = [
    { Types.value = 50_000L; script_pubkey = send_spk };
    { Types.value = 40_000L; script_pubkey = send_spk };
  ] in
  let op = _outpoint_with_byte 0x10 0l in
  let prev = { Types.value = 100_000L; script_pubkey = send_spk } in
  let orig = make_orig_psbt ~sender_outpoints:[(op, prev)] ~outputs:outs in
  (* Candidate A: p2wpkh (matching) ; Candidate B: legacy P2PKH-shaped
     bytes (mismatch).  We use an obviously-wrong byte pattern for B
     so the classifier maps it to "unknown" — still NOT "p2wpkh". *)
  let cand_a = _wallet_utxo_of send_spk 10_000L in
  let bad_script = Cstruct.of_string "\x76\xa9\x14abcdefghij1234567890\x88\xac" in
  let cand_b = _wallet_utxo_of bad_script 10_000L in
  let utxos = [cand_b; cand_a] in
  match Payjoin.select_anti_fp_utxo ~orig_psbt:orig ~utxos with
  | None -> Alcotest.fail "G20: must select a UTXO"
  | Some score ->
    Alcotest.(check bool) "G20: chose script-type match"
      true score.script_type_match

let test_g20_input_lt_output_heuristic () =
  let pkh = Cstruct.create 20 in
  let send_spk = make_p2wpkh_script pkh in
  let outs = [
    { Types.value = 50_000L; script_pubkey = send_spk };
    { Types.value = 5_000L; script_pubkey =
        make_p2wpkh_script ~byte:0x22 pkh };
  ] in
  let op = _outpoint_with_byte 0x20 0l in
  let prev = { Types.value = 60_000L; script_pubkey = send_spk } in
  let orig = make_orig_psbt ~sender_outpoints:[(op, prev)] ~outputs:outs in
  (* small (40k <= 50k max-output → passes) vs huge (200k > 50k → fails). *)
  let cand_small = _wallet_utxo_of send_spk 40_000L in
  let cand_huge = _wallet_utxo_of send_spk 200_000L in
  match Payjoin.select_anti_fp_utxo ~orig_psbt:orig
          ~utxos:[cand_huge; cand_small] with
  | None -> Alcotest.fail "G20: must select"
  | Some score ->
    Alcotest.(check bool) "G20: heuristic passes"
      true score.passes_input_lt_output_heuristic

let test_g20_empty_utxo_list () =
  let pkh = Cstruct.create 20 in
  let spk = make_p2wpkh_script pkh in
  let op = _outpoint_with_byte 0x33 0l in
  let prev = { Types.value = 1L; script_pubkey = spk } in
  let orig = make_orig_psbt ~sender_outpoints:[(op, prev)]
              ~outputs:[{ Types.value = 1L; script_pubkey = spk }] in
  Alcotest.(check bool) "G20: empty UTXOs → None"
    true (Payjoin.select_anti_fp_utxo ~orig_psbt:orig ~utxos:[] = None)

(* ============================================================================
   G30 — Replay protection
   ============================================================================ *)

let test_g30_first_sight_ok () =
  Payjoin._reset_all_state ();
  match Payjoin.check_and_record_replay "unique-payload-g30" with
  | Ok () -> ()
  | Error e -> Alcotest.failf "G30 first sight: %s" e

let test_g30_replay_rejected () =
  Payjoin._reset_all_state ();
  let payload = "replay-payload-g30" in
  (match Payjoin.check_and_record_replay payload with
   | Ok () -> ()
   | Error e -> Alcotest.failf "G30 first sight: %s" e);
  match Payjoin.check_and_record_replay payload with
  | Ok () -> Alcotest.fail "G30: identical payload must be rejected"
  | Error _ -> ()

let test_g30_distinct_payloads_independent () =
  Payjoin._reset_all_state ();
  Alcotest.(check bool) "first"  true
    (Payjoin.check_and_record_replay "a" = Ok ());
  Alcotest.(check bool) "second-distinct" true
    (Payjoin.check_and_record_replay "b" = Ok ())

(* ============================================================================
   G17 — Wire error code enumeration
   ============================================================================ *)

let test_g17_error_codes_enumerated () =
  match Payjoin.all_error_codes_json () with
  | `List items ->
    Alcotest.(check int) "4 BIP-78 error codes" 4 (List.length items);
    let codes =
      List.filter_map (function
        | `Assoc fields ->
          (match List.assoc_opt "code" fields with
           | Some (`String s) -> Some s
           | _ -> None)
        | _ -> None) items
    in
    Alcotest.(check bool) "unavailable present"
      true (List.mem "unavailable" codes);
    Alcotest.(check bool) "not-enough-money present"
      true (List.mem "not-enough-money" codes);
    Alcotest.(check bool) "version-unsupported present"
      true (List.mem "version-unsupported" codes);
    Alcotest.(check bool) "original-psbt-rejected present"
      true (List.mem "original-psbt-rejected" codes)
  | _ -> Alcotest.fail "G17: error code enumeration wrong shape"

(* ============================================================================
   G3 — TLS info surface
   ============================================================================ *)

let test_g3_tls_info_surface () =
  match Payjoin.tls_info_json () with
  | `Assoc fields ->
    (match List.assoc_opt "tls_available" fields with
     | Some (`Bool true) -> ()
     | _ -> Alcotest.fail "G3: tls_available must be true")
  | _ -> Alcotest.fail "G3: tls_info_json wrong shape"

(* ============================================================================
   RPC dispatch smoke tests for the FIX-67 RPCs
   ============================================================================ *)

let test_db_root = "/tmp/camlcoin_fix67_test_db"

let rec rm_rf path =
  if Sys.file_exists path then begin
    if Sys.is_directory path then begin
      Array.iter (fun f -> rm_rf (Filename.concat path f)) (Sys.readdir path);
      try Unix.rmdir path with _ -> ()
    end else
      try Unix.unlink path with _ -> ()
  end

let make_rpc_ctx () : Rpc.rpc_context =
  rm_rf test_db_root;
  let db = Storage.ChainDB.create test_db_root in
  let utxo = Utxo.UtxoSet.create db in
  let mp = Mempool.create
    ~require_standard:false
    ~verify_scripts:false
    ~utxo
    ~current_height:0
    () in
  let chain = Sync.create_chain_state db Consensus.mainnet in
  let pm = Peer_manager.create Consensus.mainnet in
  let fe = Fee_estimation.create () in
  { Rpc.chain; mempool = mp; peer_manager = pm;
    wallet = None; wallet_manager = None;
    fee_estimator = fe; network = Consensus.mainnet;
    filter_index = None; utxo = None; data_dir = None; }

let _shared_ctx : Rpc.rpc_context option ref = ref None
let shared_ctx () =
  match !_shared_ctx with
  | Some c -> c
  | None ->
    let c = make_rpc_ctx () in
    _shared_ctx := Some c;
    c

let _assert_dispatches ctx method_name params =
  match Rpc.dispatch_rpc ctx method_name params with
  | Error (-32601, _) ->
    Alcotest.failf "%s: must dispatch (got method-not-found)" method_name
  | Error _ | Ok _ -> ()

let test_rpc_dispatch_all () =
  Payjoin._reset_all_state ();
  let ctx = shared_ctx () in
  _assert_dispatches ctx "getpayjointlsinfo" [];
  _assert_dispatches ctx "decodeoriginalpsbt" [`String "x"];
  _assert_dispatches ctx "validateoriginalpsbt" [`String "x"];
  _assert_dispatches ctx "validatefeeoutputindex" [`String "x"; `Int 0];
  _assert_dispatches ctx "payjoinaddinput" [];
  _assert_dispatches ctx "receiveraddinputs" [];
  _assert_dispatches ctx "payjoinmodifyoutput" [];
  _assert_dispatches ctx "payjoinadjustfee" [];
  _assert_dispatches ctx "getpayjoinerror" [];
  _assert_dispatches ctx "expirepayjoinrequest" [`String "deadbeef"];
  _assert_dispatches ctx "listpayjoinsessions" [];
  _assert_dispatches ctx "verifypayjoinnodouble" [`String "id"; `List []];
  _assert_dispatches ctx "selectpayjoinutxos" [`String "x"];
  _assert_dispatches ctx "checkpayjoinreplay" [`String "x"]

let test_rpc_checkpayjoinreplay_round_trip () =
  Payjoin._reset_all_state ();
  let ctx = shared_ctx () in
  let payload = `String "rpc-replay-fixture" in
  (match Rpc.dispatch_rpc ctx "checkpayjoinreplay" [payload] with
   | Ok (`Assoc fields) ->
     (match List.assoc_opt "replay" fields with
      | Some (`Bool false) -> ()
      | _ -> Alcotest.fail "first call: replay must be false")
   | _ -> Alcotest.fail "first call: dispatch shape unexpected");
  match Rpc.dispatch_rpc ctx "checkpayjoinreplay" [payload] with
  | Ok (`Assoc fields) ->
    (match List.assoc_opt "replay" fields with
     | Some (`Bool true) -> ()
     | _ -> Alcotest.fail "second call: replay must be true")
  | _ -> Alcotest.fail "second call: dispatch shape unexpected"

let test_rpc_listpayjoinsessions_shape () =
  Payjoin._reset_all_state ();
  let ctx = shared_ctx () in
  let _ = Payjoin.open_session ~orig_psbt_b64:"rpc-list" () in
  match Rpc.dispatch_rpc ctx "listpayjoinsessions" [] with
  | Ok (`Assoc fields) ->
    (match List.assoc_opt "count" fields, List.assoc_opt "sessions" fields with
     | Some (`Int n), Some (`List _) ->
       Alcotest.(check bool) "count >= 1" true (n >= 1)
     | _ ->
       Alcotest.fail "listpayjoinsessions: shape unexpected")
  | _ -> Alcotest.fail "listpayjoinsessions: not Ok"

(* ============================================================================
   Test registration
   ============================================================================ *)

let g18_tests = [
  Alcotest.test_case "G18 open+lookup" `Quick test_g18_open_lookup;
  Alcotest.test_case "G18 TTL expiry"  `Quick test_g18_ttl_expiry;
  Alcotest.test_case "G18 explicit expire" `Quick test_g18_expire_explicit;
  Alcotest.test_case "G18 list_sessions" `Quick test_g18_list_sessions;
  Alcotest.test_case "G18 record_session_spent_utxos" `Quick test_g18_record_spent;
]

let g19_tests = [
  Alcotest.test_case "G19 no conflict" `Quick test_g19_no_conflict;
  Alcotest.test_case "G19 conflict detected" `Quick test_g19_conflict_detected;
  Alcotest.test_case "G19 self-session exempt" `Quick test_g19_self_session_exempt;
]

let g20_tests = [
  Alcotest.test_case "G20 prefer matching script type"
    `Quick test_g20_prefer_matching_script_type;
  Alcotest.test_case "G20 input-lt-output heuristic"
    `Quick test_g20_input_lt_output_heuristic;
  Alcotest.test_case "G20 empty UTXO list" `Quick test_g20_empty_utxo_list;
]

let g30_tests = [
  Alcotest.test_case "G30 first sight ok" `Quick test_g30_first_sight_ok;
  Alcotest.test_case "G30 replay rejected" `Quick test_g30_replay_rejected;
  Alcotest.test_case "G30 distinct payloads independent"
    `Quick test_g30_distinct_payloads_independent;
]

let surface_tests = [
  Alcotest.test_case "G17 error codes enumerated"
    `Quick test_g17_error_codes_enumerated;
  Alcotest.test_case "G3 TLS info surface" `Quick test_g3_tls_info_surface;
]

let rpc_tests = [
  Alcotest.test_case "RPC dispatch (all FIX-67 methods)"
    `Quick test_rpc_dispatch_all;
  Alcotest.test_case "RPC checkpayjoinreplay round-trip"
    `Quick test_rpc_checkpayjoinreplay_round_trip;
  Alcotest.test_case "RPC listpayjoinsessions shape"
    `Quick test_rpc_listpayjoinsessions_shape;
]

let () =
  Alcotest.run "FIX-67_payjoin_cleanup" [
    ("G18 — TTL", g18_tests);
    ("G19 — double-spend", g19_tests);
    ("G20 — anti-fingerprint", g20_tests);
    ("G30 — replay", g30_tests);
    ("G3/G17 — surface", surface_tests);
    ("RPC dispatch", rpc_tests);
  ]
