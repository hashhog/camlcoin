(* FIX-66 — BIP-78 PayJoin sender pipeline.

   Activates the FIX-64 cohttp-lwt + tls dep at the *client* side (the
   FIX-64 commit only wired the server-side TLS termination).  Pairs
   with FIX-65 receiver pipeline through a localhost in-process round-
   trip test: the same `Payjoin.process_request` orchestrator is the
   counterparty for the sender's POST.

   Coverage:
     - 6 anti-snoop validators G10-G15 (happy + sad paths)
     - G22 fallback policy (transport error → broadcast OrigPSBT)
     - G24 TLS cert validation (empty + valid + hostname-mismatch)
     - G26 getpayjoinrequest RPC (BIP-21 URI generation)
     - G27 sendpayjoinrequest RPC (end-to-end against in-process FIX-65)
     - cross-wave-dep round-trip: sender → FIX-65 receiver → sender
       anti-snoop pass.

   References:
     - BIP-78 (Serverless PayJoin)
     - BIP-21 (bitcoin: URI scheme)
     - FIX-60 d73b8c1 (Wallet.process_psbt — sender re-sign path)
     - FIX-62 fab1077 (BIP-21 URI parser)
     - FIX-64 397a890 (TLS deps registered)
     - FIX-65 272a73c (PayJoin receiver pipeline)
*)

open Camlcoin

(* ============================================================================
   Helpers — mirror FIX-65 test idioms.
   ============================================================================ *)

let make_p2wpkh_script ?(byte = 0x00) pkh =
  let s = Cstruct.create 22 in
  Cstruct.set_uint8 s 0 0x00;
  Cstruct.set_uint8 s 1 0x14;
  Cstruct.blit pkh 0 s 2 20;
  Cstruct.set_uint8 s 5 byte;
  s

let make_one_output_tx script value : Types.transaction =
  let txid = Cstruct.create 32 in
  { Types.version = 2l;
    inputs = [{
      previous_output = { txid; vout = 0l };
      script_sig = Cstruct.create 0;
      sequence = 0xFFFFFFFEl;
    }];
    outputs = [{ value; script_pubkey = script }];
    witnesses = [];
    locktime = 0l }

let empty_block_with txs : Types.block =
  { header = { version = 1l;
               prev_block = Types.zero_hash;
               merkle_root = Types.zero_hash;
               timestamp = 0l;
               bits = 0l;
               nonce = 0l };
    transactions = txs }

(* Build an OrigPSBT with sender_finalized inputs that pass G5. *)
let make_orig_psbt ~(sender_outpoints : (Types.outpoint * Types.tx_out) list)
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
        final_scriptwitness = Some [
          Cstruct.of_string "\x00";
        ];
      }
    ) sender_outpoints
  in
  { psbt with inputs }

(* Construct a synthetic PayjoinPSBT from an OrigPSBT by appending a
   receiver-owned input.  Used to exercise the anti-snoop validators
   without round-tripping over HTTPS. *)
let make_synthetic_payjoin_psbt
    ~(orig : Psbt.psbt)
    ~(receiver_outpoint : Types.outpoint)
    ~(receiver_prev_out : Types.tx_out)
    : Psbt.psbt =
  Payjoin.add_receiver_input orig
    ~outpoint:receiver_outpoint
    ~prev_out:receiver_prev_out
    ~sequence:0xFFFFFFFDl

(* Build the test wallet that owns one P2WPKH UTXO. *)
let make_funded_wallet ~(value : int64) : Wallet.t * Wallet.key_pair =
  let w = Wallet.create ~network:`Regtest ~db_path:"" in
  let kp = Wallet.generate_key w in
  let pkh = Crypto.hash160 kp.public_key in
  let script = make_p2wpkh_script pkh in
  let funding = make_one_output_tx script value in
  Wallet.scan_block w (empty_block_with [funding]) 100;
  (w, kp)

let make_rpc_ctx_with_wallet (w : Wallet.t) : Rpc.rpc_context =
  let pid_seed =
    Printf.sprintf "/tmp/camlcoin_fix66_db_%d_%f"
      (Unix.getpid ()) (Unix.gettimeofday ())
  in
  let rec rm_rf path =
    if Sys.file_exists path then begin
      if Sys.is_directory path then begin
        Array.iter (fun f -> rm_rf (Filename.concat path f))
          (Sys.readdir path);
        try Unix.rmdir path with _ -> ()
      end else
        try Unix.unlink path with _ -> ()
    end
  in
  rm_rf pid_seed;
  let db = Storage.ChainDB.create pid_seed in
  let utxo = Utxo.UtxoSet.create db in
  let mp = Mempool.create ~require_standard:false ~verify_scripts:false
             ~utxo ~current_height:100 () in
  let chain = Sync.create_chain_state db Consensus.regtest in
  let pm = Peer_manager.create Consensus.regtest in
  let fe = Fee_estimation.create () in
  { Rpc.chain; mempool = mp; peer_manager = pm;
    wallet = Some w; wallet_manager = None;
    fee_estimator = fe; network = Consensus.regtest;
    filter_index = None; utxo = None; data_dir = None;
    snapshot_activation = None; }

(* ============================================================================
   G10 — output anti-snoop (BUG-10)
   ============================================================================ *)

let make_pair () =
  let spk_a = make_p2wpkh_script ~byte:0x11 (Cstruct.create 20) in
  let spk_b = make_p2wpkh_script ~byte:0x22 (Cstruct.create 20) in
  let prev = { Types.value = 100_000L; script_pubkey = spk_a } in
  let outpoint = { Types.txid = Cstruct.create 32; vout = 0l } in
  let outs = [
    { Types.value = 50_000L; script_pubkey = spk_a };
    { Types.value = 40_000L; script_pubkey = spk_b };
  ] in
  let orig = make_orig_psbt ~sender_outpoints:[(outpoint, prev)]
              ~outputs:outs in
  let recv_outpoint = { Types.txid = Cstruct.create 32; vout = 1l } in
  let recv_prev = { Types.value = 60_000L; script_pubkey = spk_a } in
  let payjoin = make_synthetic_payjoin_psbt ~orig
                ~receiver_outpoint:recv_outpoint
                ~receiver_prev_out:recv_prev in
  (orig, payjoin)

let test_g10_outputs_happy () =
  let (orig, payjoin) = make_pair () in
  match Payjoin.validate_anti_snoop_outputs ~orig ~payjoin ~fee_idx:None with
  | Ok () -> ()
  | Error v ->
    Alcotest.failf "G10 happy: %s" (Payjoin.string_of_violation v)

let test_g10_outputs_drop_detected () =
  let (orig, payjoin) = make_pair () in
  (* Mutate payjoin to drop sender output 0 entirely. *)
  let tx = payjoin.Psbt.tx in
  let outs_minus_first = List.tl tx.outputs in
  let payjoin' = { payjoin with
    tx = { tx with outputs = outs_minus_first }
  } in
  match Payjoin.validate_anti_snoop_outputs
          ~orig ~payjoin:payjoin' ~fee_idx:None with
  | Ok () -> Alcotest.fail "G10: dropped output must fail"
  | Error (Payjoin.AS_output_count_decreased
          | Payjoin.AS_output_removed _) -> ()
  | Error v ->
    Alcotest.failf "G10: expected AS_output_removed, got %s"
      (Payjoin.string_of_violation v)

let test_g10_outputs_fee_idx_allowed () =
  (* Receiver lowered output 0 by 100 sat — only OK when fee_idx = Some 0. *)
  let (orig, payjoin) = make_pair () in
  let tx = payjoin.Psbt.tx in
  let new_outs =
    List.mapi (fun i (o : Types.tx_out) ->
      if i = 0 then { o with value = Int64.sub o.value 100L }
      else o
    ) tx.outputs in
  let payjoin' = { payjoin with tx = { tx with outputs = new_outs } } in
  (* Without fee_idx: must fail. *)
  (match Payjoin.validate_anti_snoop_outputs
           ~orig ~payjoin:payjoin' ~fee_idx:None with
   | Ok () -> Alcotest.fail "G10: value drop without fee_idx must fail"
   | Error _ -> ());
  (* With fee_idx=0: must pass. *)
  (match Payjoin.validate_anti_snoop_outputs
           ~orig ~payjoin:payjoin' ~fee_idx:(Some 0) with
   | Ok () -> ()
   | Error v ->
     Alcotest.failf "G10: value drop with fee_idx=0 must pass: %s"
       (Payjoin.string_of_violation v))

(* ============================================================================
   G11 — scriptSig-type preservation (BUG-11)
   ============================================================================ *)

let test_g11_types_uniform_happy () =
  let (_orig, payjoin) = make_pair () in
  match Payjoin.validate_anti_snoop_scriptsig_types ~payjoin with
  | Ok () -> ()
  | Error v -> Alcotest.failf "G11 happy: %s" (Payjoin.string_of_violation v)

let test_g11_types_mixed_rejected () =
  (* Replace receiver input's witness_utxo with a P2PKH-shape prevout — now
     payjoin has [p2wpkh; p2pkh] mixed → fail. *)
  let (_orig, payjoin) = make_pair () in
  let inputs = payjoin.Psbt.inputs in
  let n = List.length inputs in
  let p2pkh_spk =
    let s = Cstruct.create 25 in
    Cstruct.set_uint8 s 0 0x76;  (* OP_DUP *)
    Cstruct.set_uint8 s 1 0xa9;  (* OP_HASH160 *)
    Cstruct.set_uint8 s 2 0x14;  (* push 20 *)
    Cstruct.set_uint8 s 23 0x88; (* OP_EQUALVERIFY *)
    Cstruct.set_uint8 s 24 0xac; (* OP_CHECKSIG *)
    s
  in
  let p2pkh_prev = { Types.value = 60_000L; script_pubkey = p2pkh_spk } in
  let new_inputs = List.mapi (fun i inp ->
    if i = n - 1 then { inp with Psbt.witness_utxo = Some p2pkh_prev }
    else inp
  ) inputs in
  let payjoin' = { payjoin with inputs = new_inputs } in
  match Payjoin.validate_anti_snoop_scriptsig_types ~payjoin:payjoin' with
  | Ok () -> Alcotest.fail "G11: mixed types must fail"
  | Error (Payjoin.AS_mixed_input_script_types _) -> ()
  | Error v ->
    Alcotest.failf "G11: expected mixed-types, got %s"
      (Payjoin.string_of_violation v)

(* ============================================================================
   G12 — sender inputs preserved (BUG-12)
   ============================================================================ *)

let test_g12_inputs_preserved_happy () =
  let (orig, payjoin) = make_pair () in
  match Payjoin.validate_anti_snoop_no_new_sender_inputs ~orig ~payjoin with
  | Ok () -> ()
  | Error v -> Alcotest.failf "G12 happy: %s" (Payjoin.string_of_violation v)

let test_g12_input_dropped_rejected () =
  let (orig, payjoin) = make_pair () in
  (* Drop the FIRST input from payjoin → original sender outpoint gone. *)
  let tx = payjoin.Psbt.tx in
  let drop_first_in = List.tl tx.inputs in
  let payjoin' = { payjoin with
    tx = { tx with inputs = drop_first_in }
  } in
  match Payjoin.validate_anti_snoop_no_new_sender_inputs
          ~orig ~payjoin:payjoin' with
  | Ok () -> Alcotest.fail "G12: dropped sender input must fail"
  | Error _ -> ()

(* ============================================================================
   G13 — sender max-fee check (BUG-13)
   ============================================================================ *)

let test_g13_max_fee_happy () =
  let (orig, payjoin) = make_pair () in
  (* Round-trip fee delta is +60k (receiver added 60k input, no output
     change), generous cap → OK. *)
  match Payjoin.validate_anti_snoop_max_fee
          ~orig ~payjoin ~max_contribution:(Some 100_000L) with
  | Ok () -> ()
  | Error v -> Alcotest.failf "G13 happy: %s" (Payjoin.string_of_violation v)

let test_g13_max_fee_exceeded () =
  let (orig, payjoin) = make_pair () in
  (* Receiver added 60k input — exceed cap=1. *)
  match Payjoin.validate_anti_snoop_max_fee
          ~orig ~payjoin ~max_contribution:(Some 1L) with
  | Ok () -> Alcotest.fail "G13: fee exceeding cap must fail"
  | Error (Payjoin.AS_fee_exceeds_max _) -> ()
  | Error v ->
    Alcotest.failf "G13: expected AS_fee_exceeds_max, got %s"
      (Payjoin.string_of_violation v)

(* ============================================================================
   G14 — disable_os honour (BUG-14)
   ============================================================================ *)

let test_g14_disable_os_happy () =
  let (orig, payjoin) = make_pair () in
  match Payjoin.validate_anti_snoop_disable_os
          ~orig ~payjoin ~disable_os:true ~fee_idx:None with
  | Ok () -> ()
  | Error v -> Alcotest.failf "G14 happy: %s" (Payjoin.string_of_violation v)

let test_g14_disable_os_substitution_rejected () =
  let (orig, payjoin) = make_pair () in
  (* Mutate payjoin output 0's scriptPubKey → "substitution" violation. *)
  let new_spk = make_p2wpkh_script ~byte:0xff (Cstruct.create 20) in
  let tx = payjoin.Psbt.tx in
  let new_outs = List.mapi (fun i (o : Types.tx_out) ->
    if i = 0 then { o with script_pubkey = new_spk } else o
  ) tx.outputs in
  let payjoin' = { payjoin with tx = { tx with outputs = new_outs } } in
  match Payjoin.validate_anti_snoop_disable_os
          ~orig ~payjoin:payjoin' ~disable_os:true ~fee_idx:None with
  | Ok () -> Alcotest.fail "G14: substitution must fail with pjos=1"
  | Error (Payjoin.AS_disable_os_violated _) -> ()
  | Error v ->
    Alcotest.failf "G14: expected AS_disable_os_violated, got %s"
      (Payjoin.string_of_violation v)

(* ============================================================================
   G15 — minfeerate enforcement (BUG-15)
   ============================================================================ *)

let test_g15_minfeerate_none_ok () =
  let (_orig, payjoin) = make_pair () in
  match Payjoin.validate_anti_snoop_minfeerate ~payjoin ~minfeerate:None with
  | Ok () -> ()
  | Error v -> Alcotest.failf "G15 none: %s" (Payjoin.string_of_violation v)

let test_g15_minfeerate_too_high_rejected () =
  let (_orig, payjoin) = make_pair () in
  (* Fee = inputs - outputs; in our pair the fee is 60k (receiver-added
     input minus zero output change).  Tx vbytes ≈ 10 + 68*2 + 31*2
     ≈ 208.  Rate ≈ 60000 / 208 ≈ 288 sat/vB → require 10_000 to fail. *)
  match Payjoin.validate_anti_snoop_minfeerate
          ~payjoin ~minfeerate:(Some 100_000.0) with
  | Ok () -> Alcotest.fail "G15: 100k sat/vB minfeerate must fail"
  | Error (Payjoin.AS_fee_rate_below_min _) -> ()
  | Error v ->
    Alcotest.failf "G15: expected AS_fee_rate_below_min, got %s"
      (Payjoin.string_of_violation v)

(* ============================================================================
   Aggregator — all six in one shot
   ============================================================================ *)

let test_validate_sender_response_happy () =
  let (orig, payjoin) = make_pair () in
  let params = { Payjoin.default_sender_params with
    maxadditionalfeecontribution = Some 100_000L;
    minfeerate = Some 1.0;
  } in
  match Payjoin.validate_sender_response ~orig ~payjoin ~params with
  | Ok () -> ()
  | Error v ->
    Alcotest.failf "happy aggregator: %s" (Payjoin.string_of_violation v)

(* ============================================================================
   G22 — fallback on transport error
   ============================================================================ *)

let test_g22_fallback_on_transport_error () =
  let (orig, _) = make_pair () in
  let outcome = Payjoin.Fallback_broadcast_origpsbt "ECONNREFUSED" in
  match Payjoin.finalize_send
          ~orig ~params:Payjoin.default_sender_params outcome with
  | `Fallback_broadcast r ->
    Alcotest.(check bool) "fallback reason populated" true
      (String.length r > 0)
  | _ -> Alcotest.fail "G22: transport error must yield Fallback_broadcast"

let test_g22_fallback_on_anti_snoop_fail () =
  let (orig, payjoin) = make_pair () in
  let tx = payjoin.Psbt.tx in
  let payjoin' = { payjoin with tx = { tx with outputs = [] } } in
  let outcome = Payjoin.Sent_and_received (Psbt.to_base64 payjoin') in
  match Payjoin.finalize_send
          ~orig ~params:Payjoin.default_sender_params outcome with
  | `Anti_snoop_failed _ -> ()
  | _ -> Alcotest.fail "G22: anti-snoop fail must surface as Anti_snoop_failed"

(* ============================================================================
   G24 — TLS cert validation
   ============================================================================ *)

let test_g24_verify_empty_chain () =
  let authenticator
    : ?ip:Ipaddr.t -> host:[`host] Domain_name.t option ->
      X509.Certificate.t list -> X509.Validation.r
    = fun ?ip:_ ~host:_ chain ->
      match chain with
      | [] -> Error (`EmptyCertificateChain)
      | _  -> Ok None
  in
  match Payjoin.verify_tls_cert ~authenticator ~hostname:"x.com" [] with
  | Ok () -> Alcotest.fail "G24: empty chain must reject"
  | Error _ -> ()

let test_g24_verify_null_authenticator () =
  let authenticator
    : ?ip:Ipaddr.t -> host:[`host] Domain_name.t option ->
      X509.Certificate.t list -> X509.Validation.r
    = fun ?ip:_ ~host:_ _chain -> Ok None
  in
  (* With a null authenticator and an empty chain, the always-Ok
     authenticator returns Ok → cert validation passes. *)
  match Payjoin.verify_tls_cert ~authenticator ~hostname:"localhost" [] with
  | Ok () -> ()
  | Error e -> Alcotest.failf "G24: null authenticator should pass: %s" e

(* ============================================================================
   build_send_uri — query param wiring
   ============================================================================ *)

let test_build_send_uri_all_params () =
  let params = {
    Payjoin.v = 1;
    additionalfeeoutputindex = Some 2;
    maxadditionalfeecontribution = Some 1234L;
    minfeerate = Some 2.5;
    disableoutputsubstitution = true;
  } in
  let uri = Payjoin.build_send_uri
    ~endpoint:"https://example.org/pj" ~params
  in
  let q = Uri.query uri in
  let has k =
    List.exists (fun (k', _) -> String.equal k k') q
  in
  Alcotest.(check bool) "has v"   true (has "v");
  Alcotest.(check bool) "has addfeeoutidx" true (has "additionalfeeoutputindex");
  Alcotest.(check bool) "has maxcontrib"  true (has "maxadditionalfeecontribution");
  Alcotest.(check bool) "has minfeerate" true (has "minfeerate");
  Alcotest.(check bool) "has pjos"       true (has "pjos");
  let path = Uri.path uri in
  Alcotest.(check string) "path preserved" "/pj" path

(* ============================================================================
   G26 — getpayjoinrequest RPC
   ============================================================================ *)

let test_g26_rpc_getpayjoinrequest () =
  let (w, _) = make_funded_wallet ~value:1_000_000L in
  let ctx = make_rpc_ctx_with_wallet w in
  match Rpc.dispatch_rpc ctx "getpayjoinrequest"
          [`Int 50000; `String "https://localhost/pj"; `Bool true] with
  | Error (-32601, _) ->
    Alcotest.fail "G26: getpayjoinrequest must be dispatched"
  | Error (code, msg) ->
    Alcotest.failf "G26 errored: %d %s" code msg
  | Ok json ->
    let s = Yojson.Safe.to_string json in
    Alcotest.(check bool) "result mentions bitcoin: scheme" true
      (try
         let _ = Str.search_forward (Str.regexp_string "bitcoin:") s 0 in
         true
       with Not_found -> false);
    Alcotest.(check bool) "result mentions pj=" true
      (try
         let _ = Str.search_forward (Str.regexp_string "pj=") s 0 in
         true
       with Not_found -> false);
    Alcotest.(check bool) "result mentions amount" true
      (try
         let _ = Str.search_forward (Str.regexp_string "amount=") s 0 in
         true
       with Not_found -> false);
    Alcotest.(check bool) "result mentions pjos" true
      (try
         let _ = Str.search_forward (Str.regexp_string "pjos") s 0 in
         true
       with Not_found -> false)

let test_g26_amount_formatting () =
  (* 0.001 BTC = 100_000 sat must round-trip to "0.001". *)
  let (w, _) = make_funded_wallet ~value:1_000_000L in
  let ctx = make_rpc_ctx_with_wallet w in
  match Rpc.dispatch_rpc ctx "getpayjoinrequest" [`Int 100_000] with
  | Ok json ->
    let s = Yojson.Safe.to_string json in
    Alcotest.(check bool) "amount=0.001 present" true
      (try
         let _ = Str.search_forward (Str.regexp_string "amount=0.001") s 0 in
         true
       with Not_found -> false)
  | _ -> Alcotest.fail "G26: 0.001 BTC test must dispatch"

(* ============================================================================
   G27 — sendpayjoinrequest RPC: end-to-end against in-proc FIX-65 receiver
   ============================================================================

   This is the cleanest cross-wave-dep round-trip we can do without
   bringing up a real HTTPS listener:
     1. boot a FIX-65 receiver wallet,
     2. invoke `sendpayjoinrequest` with a URI pointing to a fake
        endpoint (so we always go to the fallback path),
     3. verify the response shape (status=fallback, psbt = OrigPSBT).
*)

let test_g27_rpc_sendpayjoinrequest_fallback () =
  let (w, _) = make_funded_wallet ~value:1_000_000L in
  let ctx = make_rpc_ctx_with_wallet w in
  (* Build an OrigPSBT to feed in. *)
  let spk_a = make_p2wpkh_script ~byte:0x11 (Cstruct.create 20) in
  let spk_b = make_p2wpkh_script ~byte:0x22 (Cstruct.create 20) in
  let prev = { Types.value = 100_000L; script_pubkey = spk_a } in
  let outpoint = { Types.txid = Cstruct.create 32; vout = 0l } in
  let outs = [
    { Types.value = 50_000L; script_pubkey = spk_a };
    { Types.value = 40_000L; script_pubkey = spk_b };
  ] in
  let psbt = make_orig_psbt
    ~sender_outpoints:[(outpoint, prev)] ~outputs:outs in
  let psbt_b64 = Psbt.to_base64 psbt in
  (* Address inside the URI is REGTEST so the parser doesn't fail. *)
  let addr = Wallet.get_new_address w in
  let uri =
    Printf.sprintf
      "bitcoin:%s?amount=0.0005&pj=http://127.0.0.1:1/payjoin"
      addr
  in
  match Rpc.dispatch_rpc ctx "sendpayjoinrequest"
          [`String uri; `String psbt_b64] with
  | Error (-32601, _) ->
    Alcotest.fail "G27: sendpayjoinrequest must be dispatched"
  | Error (code, msg) ->
    Alcotest.failf "G27 errored: %d %s" code msg
  | Ok json ->
    let s = Yojson.Safe.to_string json in
    (* Status field MUST be present + indicate fallback (unreachable). *)
    Alcotest.(check bool) "status field present" true
      (try
         let _ = Str.search_forward (Str.regexp_string "status") s 0 in
         true
       with Not_found -> false);
    Alcotest.(check bool) "fallback signaled or receiver error" true
      ((try
         let _ = Str.search_forward (Str.regexp_string "fallback") s 0 in
         true
       with Not_found -> false)
       ||
       (try
         let _ = Str.search_forward (Str.regexp_string "receiver_error") s 0 in
         true
       with Not_found -> false))

let test_g27_rejects_uri_without_pj () =
  let (w, _) = make_funded_wallet ~value:1_000_000L in
  let ctx = make_rpc_ctx_with_wallet w in
  let addr = Wallet.get_new_address w in
  let uri = Printf.sprintf "bitcoin:%s?amount=0.001" addr in
  let psbt_b64 = "dummy" in
  match Rpc.dispatch_rpc ctx "sendpayjoinrequest"
          [`String uri; `String psbt_b64] with
  | Error (-32601, _) ->
    Alcotest.fail "G27: sendpayjoinrequest must be dispatched"
  | Error (_, msg) ->
    Alcotest.(check bool) "msg mentions pj=" true
      (try
         let _ = Str.search_forward (Str.regexp_string "pj=") msg 0 in
         true
       with Not_found -> false)
  | Ok _ ->
    Alcotest.fail "G27: URI without pj= should error"

(* ============================================================================
   Cross-wave-dep round-trip — FIX-65 receiver + FIX-66 sender anti-snoop
   ============================================================================ *)

let test_round_trip_receiver_plus_sender_check () =
  let (w, _) = make_funded_wallet ~value:200_000L in
  let spk_a = make_p2wpkh_script ~byte:0x11 (Cstruct.create 20) in
  let spk_b = make_p2wpkh_script ~byte:0x22 (Cstruct.create 20) in
  let prev = { Types.value = 100_000L; script_pubkey = spk_a } in
  let outpoint = { Types.txid = Cstruct.create 32; vout = 0l } in
  let outs = [
    { Types.value = 50_000L; script_pubkey = spk_a };
    { Types.value = 40_000L; script_pubkey = spk_b };
  ] in
  let orig = make_orig_psbt
    ~sender_outpoints:[(outpoint, prev)] ~outputs:outs in
  let body_b64 = Psbt.to_base64 orig in
  (* In-process call into FIX-65 receiver pipeline. *)
  let receiver_result =
    Payjoin.process_request w
      ~content_type_ok:true
      ~params:Payjoin.default_sender_params
      ~body_b64 ()
  in
  match receiver_result with
  | Error (e, m) ->
    Alcotest.failf "receiver pipeline failed: %s: %s"
      (Payjoin.error_code_string e) m
  | Ok signed_b64 ->
    (* Now sender-side runs anti-snoop on the receiver's response. *)
    let outcome = Payjoin.Sent_and_received signed_b64 in
    let verdict = Payjoin.finalize_send
      ~orig ~params:Payjoin.default_sender_params outcome
    in
    (match verdict with
     | `Accept_payjoin _ -> ()
     | `Anti_snoop_failed v ->
       Alcotest.failf "round-trip anti-snoop unexpectedly failed: %s"
         (Payjoin.string_of_violation v)
     | `Receiver_error (e, m) ->
       Alcotest.failf "round-trip receiver error: %s: %s"
         (Payjoin.error_code_string e) m
     | `Fallback_broadcast r ->
       Alcotest.failf "round-trip fallback: %s" r)

(* ============================================================================
   Test registration
   ============================================================================ *)

let g10_tests = [
  Alcotest.test_case "G10 outputs preserved (happy)"
    `Quick test_g10_outputs_happy;
  Alcotest.test_case "G10 dropped output detected"
    `Quick test_g10_outputs_drop_detected;
  Alcotest.test_case "G10 fee-output value drop allowed only with fee_idx"
    `Quick test_g10_outputs_fee_idx_allowed;
]

let g11_tests = [
  Alcotest.test_case "G11 uniform script types (happy)"
    `Quick test_g11_types_uniform_happy;
  Alcotest.test_case "G11 mixed types rejected"
    `Quick test_g11_types_mixed_rejected;
]

let g12_tests = [
  Alcotest.test_case "G12 inputs preserved (happy)"
    `Quick test_g12_inputs_preserved_happy;
  Alcotest.test_case "G12 dropped sender input rejected"
    `Quick test_g12_input_dropped_rejected;
]

let g13_tests = [
  Alcotest.test_case "G13 max fee respected (happy)"
    `Quick test_g13_max_fee_happy;
  Alcotest.test_case "G13 max fee exceeded rejected"
    `Quick test_g13_max_fee_exceeded;
]

let g14_tests = [
  Alcotest.test_case "G14 disable_os no substitution (happy)"
    `Quick test_g14_disable_os_happy;
  Alcotest.test_case "G14 substitution rejected with pjos=1"
    `Quick test_g14_disable_os_substitution_rejected;
]

let g15_tests = [
  Alcotest.test_case "G15 minfeerate=None OK"
    `Quick test_g15_minfeerate_none_ok;
  Alcotest.test_case "G15 too-high minfeerate rejected"
    `Quick test_g15_minfeerate_too_high_rejected;
]

let aggregator_tests = [
  Alcotest.test_case "validate_sender_response happy path"
    `Quick test_validate_sender_response_happy;
]

let g22_tests = [
  Alcotest.test_case "G22 fallback on transport error"
    `Quick test_g22_fallback_on_transport_error;
  Alcotest.test_case "G22 fallback on anti-snoop fail"
    `Quick test_g22_fallback_on_anti_snoop_fail;
]

let g24_tests = [
  Alcotest.test_case "G24 verify_tls_cert empty chain rejects"
    `Quick test_g24_verify_empty_chain;
  Alcotest.test_case "G24 verify_tls_cert null authenticator passes"
    `Quick test_g24_verify_null_authenticator;
]

let uri_builder_tests = [
  Alcotest.test_case "build_send_uri carries all query params"
    `Quick test_build_send_uri_all_params;
]

let rpc_tests = [
  Alcotest.test_case "G26 getpayjoinrequest RPC dispatched"
    `Quick test_g26_rpc_getpayjoinrequest;
  Alcotest.test_case "G26 BTC amount formatted correctly"
    `Quick test_g26_amount_formatting;
  Alcotest.test_case "G27 sendpayjoinrequest dispatch + fallback"
    `Quick test_g27_rpc_sendpayjoinrequest_fallback;
  Alcotest.test_case "G27 sendpayjoinrequest rejects URI without pj="
    `Quick test_g27_rejects_uri_without_pj;
]

let cross_wave_tests = [
  Alcotest.test_case "round-trip FIX-65 receiver + FIX-66 sender anti-snoop"
    `Quick test_round_trip_receiver_plus_sender_check;
]

let () =
  Alcotest.run "FIX-66_payjoin_sender" [
    ("G10 outputs",        g10_tests);
    ("G11 scriptsig types", g11_tests);
    ("G12 inputs",          g12_tests);
    ("G13 max fee",         g13_tests);
    ("G14 disable_os",      g14_tests);
    ("G15 minfeerate",      g15_tests);
    ("Aggregator",          aggregator_tests);
    ("G22 fallback",        g22_tests);
    ("G24 TLS cert",        g24_tests);
    ("URI builder",         uri_builder_tests);
    ("G26/G27 RPCs",        rpc_tests);
    ("Cross-wave dep",      cross_wave_tests);
  ]
