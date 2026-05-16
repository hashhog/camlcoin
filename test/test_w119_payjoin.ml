(* W119 BIP-78 PayJoin fleet audit — camlcoin (OCaml)

   30 gates: Receiver HTTP (G1, G3, G18, G19, G20, G23, G24, G30),
             Sender HTTP (G2, G22, G25, G26, G27),
             OrigPSBT pipeline (G4, G5, G7, G8, G9),
             Sender anti-snoop (G10, G11, G12, G13, G14, G15),
             Wire / URI / errors (G6, G16, G17, G21, G28, G29).

   References:
     - BIP-78 (Serverless PayJoin),
       https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki
     - payjoin.org spec, btcpayserver/payjoin reference impl.
     - Bitcoin Core: NONE — Core does not implement PayJoin (FYI).

   Approach: every test documents a MISSING gate.  Each test asserts the
   absence of the feature at the API surface (RPC method-not-found,
   no BIP-21 URI parser, no `pj=` query handler, no fee-output-index
   validator, etc.).  Tests pass when the gap is *present*.  When the
   gap is eventually closed, the test must be flipped to assert the
   working behaviour.

   Bugs found (all P0=consensus-divergent receiver, P1=privacy/sender,
   P2=ecosystem-compat, P3=quality):

     BUG-1  (P0 G1)   : No receiver HTTP endpoint (POST /payjoin).
                        No code path serves the BIP-78 receiver role —
                        the REST server in `Rest` is read-only and the
                        RPC server in `Rpc` has no PayJoin handler.
     BUG-2  (P1 G2)   : No sender HTTP client.  Sender role is the
                        critical step where the wallet POSTs OrigPSBT
                        to the receiver and accepts a PayjoinPSBT
                        back.  `Cohttp_lwt_unix.Client` is linked but
                        never used for outbound POSTs.
     BUG-3  (P0 G3)   : No HTTPS/TLS endpoint termination.  BIP-78
                        requires TLS for non-onion endpoints (the
                        receiver may not be a hidden service).
                        camlcoin has Cohttp + Lwt but no TLS plumbing
                        (no `Cohttp_lwt_unix.Server.create_ssl`).
     BUG-4  (P0 G4)   : OrigPSBT deserialization on the wire path is
                        absent.  `Psbt.deserialize` exists (used by
                        walletprocesspsbt — see FIX-60) but there is
                        no HTTP body→PSBT decoder respecting BIP-78
                        Content-Type=text/plain + base64.
     BUG-5  (P0 G5)   : Receiver-side OrigPSBT validation absent.
                        BIP-78 §"Receiver's Original PSBT checks":
                        unique scriptPubKey per output, sender inputs
                        all finalized, sender inputs all same type,
                        fee within bounds.  None of these checks
                        exist as functions.
     BUG-6  (P1 G6)   : `additionalfeeoutputindex` validator absent.
                        Sender may tell the receiver which output the
                        receiver may take fee from; receiver must
                        validate the index lies in [0, n_outputs).
     BUG-7  (P0 G7)   : Receiver-side `add_input` absent.  Receiver
                        must select its own UTXOs and append to the
                        PSBT — wallet exposes UTXO selection (W113)
                        but no PayJoin-specific selector exists.
     BUG-8  (P1 G8)   : Receiver-side `modify_output` absent.
                        Receiver may bump the original output it
                        controls; no such helper.
     BUG-9  (P1 G9)   : Receiver-side fee adjustment absent.
                        Receiver subtracts its added-fee contribution
                        from the sender-specified output per
                        `additionalfeeoutputindex`; logic missing.
     BUG-10 (P0 G10)  : Sender anti-snoop output check absent.
                        Sender must verify all original outputs are
                        preserved unless pjos=1 AND the substituted
                        output has same script type.
     BUG-11 (P0 G11)  : Sender scriptSig-type preservation check
                        absent.  Sender must reject if receiver
                        mixed scriptSig types (e.g. wpkh + pkh).
     BUG-12 (P0 G12)  : Sender "no new sender inputs" check absent.
                        Sender's original inputs must all still be
                        present in PayjoinPSBT.
     BUG-13 (P0 G13)  : Sender max-fee check absent.
                        Sender must reject if PayjoinPSBT fee exceeds
                        `maxadditionalfeecontribution`.
     BUG-14 (P1 G14)  : Sender `disableoutputsubstitution` honour
                        absent.  If sender sends pjos=1, receiver
                        MUST NOT substitute outputs; sender MUST
                        re-verify.
     BUG-15 (P1 G15)  : Sender `minfeerate` enforcement absent.
                        Sender must reject PayjoinPSBT below the
                        agreed minimum fee rate.
     BUG-16 (P0 G16)  : Query-param parser absent.  No `pj=`,
                        `pjos=`, `v=`, `additionalfeeoutputindex=`,
                        `maxadditionalfeecontribution=`, `minfeerate=`
                        query-param handler in `Rest` or anywhere
                        else.
     BUG-17 (P0 G17)  : The 4 BIP-78 error codes (unavailable,
                        not-enough-money, version-unsupported,
                        original-psbt-rejected) absent — no enum,
                        no JSON error envelope, no producer.
     BUG-18 (P1 G18)  : Receiver TTL absent.  The receiver session
                        must time out per the spec; no session
                        management exists.
     BUG-19 (P0 G19)  : Receiver no-double-spend check absent.
                        Receiver must ensure the PayjoinPSBT does not
                        double-spend a UTXO from a previous PayJoin
                        session for the same OrigPSBT.
     BUG-20 (P1 G20)  : Receiver anti-fingerprint UTXO selection
                        absent.  BIP-78 recommends selecting UTXOs
                        that, together with sender's, would still be
                        a plausible non-PayJoin transaction.
     BUG-21 (P0 G21)  : `v=1` version header absent.  Receiver must
                        accept only v=1 (current spec) and return
                        version-unsupported otherwise.
     BUG-22 (P1 G22)  : Sender fallback-to-non-PayJoin absent.
                        BIP-78 §"Receiver does not reply": on
                        timeout / error sender must broadcast the
                        OrigPSBT as a plain transaction.  No code
                        for this fallback exists.
     BUG-23 (P0 G23)  : Receiver Content-Type validation absent.
                        BIP-78: request body MUST be text/plain with
                        a base64 PSBT.  No validator.
     BUG-24 (P0 G24)  : HTTPS cert / hostname check absent on
                        sender.  Sender posting to wallet of receiver
                        over TLS must verify cert.
     BUG-25 (P1 G25)  : Tor .onion receiver wiring absent.
                        W117 FIX-58 (commit 16fee07) wired persistent
                        I2P session and added Tor outbound — but no
                        inbound .onion hidden-service publishing for
                        the receiver endpoint.
     BUG-26 (P1 G26)  : RPC `getpayjoinrequest` missing.
                        Wallet should be able to construct a PayJoin
                        request (URI + bip21) for sender consumption.
     BUG-27 (P1 G27)  : RPC `sendpayjoinrequest` missing.  Wallet
                        should be able to perform the sender-side
                        protocol from a bitcoin: URI input.
     BUG-28 (P0 G28)  : BIP-21 `bitcoin:` URI parser missing.
                        Without BIP-21, `pj=` query param cannot be
                        extracted from a URI given by the recipient.
     BUG-29 (P0 G29)  : BIP-21 `pjos=` flag parser missing.
                        Companion to BUG-28; even if BIP-21 existed,
                        the PayJoin-specific extension query params
                        would need a dedicated extractor.
     BUG-30 (P1 G30)  : Receiver-side request replay protection
                        absent.  Receiver must reject identical
                        OrigPSBT submitted twice (idempotency token).

   Summary: 30 missing-gate bugs.  PayJoin is MISSING ENTIRELY in
   camlcoin.  All scaffolding (PSBT serialize/deserialize, base64,
   walletprocesspsbt, Cohttp HTTP server + client) exists and is
   reusable — FIX-60 `Wallet.process_psbt` is a particularly direct
   building block for the receiver-side signer step.
*)

open Camlcoin

(* ============================================================================
   Test infrastructure
   ============================================================================ *)

let test_db_root = "/tmp/camlcoin_w119_test_db"

let rec rm_rf path =
  if Sys.file_exists path then begin
    if Sys.is_directory path then begin
      Array.iter (fun f -> rm_rf (Filename.concat path f)) (Sys.readdir path);
      try Unix.rmdir path with _ -> ()
    end else
      try Unix.unlink path with _ -> ()
  end

(* Shared RPC context for all tests.  All 30 W119 tests exercise the
   dispatch_rpc unknown-method path, which doesn't mutate any of the
   context fields — so a single shared context is safe and avoids the
   "rocksdb leftover SST file" flakiness from per-test re-creation. *)
let rpc_ctx_cache : Rpc.rpc_context option ref = ref None

let make_rpc_ctx () : Rpc.rpc_context =
  match !rpc_ctx_cache with
  | Some ctx -> ctx
  | None ->
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
    let ctx : Rpc.rpc_context = {
      Rpc.chain;
      mempool = mp;
      peer_manager = pm;
      wallet = None;
      wallet_manager = None;
      fee_estimator = fe;
      network = Consensus.mainnet;
      filter_index = None;
      utxo = None;
      data_dir = None;
    } in
    rpc_ctx_cache := Some ctx;
    ctx

(* Helper: assert a method name yields method-not-found on dispatch_rpc.  *)
let assert_rpc_unknown ctx method_name =
  match Rpc.dispatch_rpc ctx method_name [] with
  | Error (-32601, _) -> ()  (* Expected: method not found *)
  | Error (code, msg) ->
    Alcotest.failf "expected method-not-found for %s, got error %d: %s"
      method_name code msg
  | Ok _ ->
    Alcotest.failf "expected method-not-found for %s, but got Ok" method_name

(* ============================================================================
   G1-G3: HTTP / TLS endpoint absence
   ============================================================================ *)

let test_g1_no_receiver_http_endpoint () =
  (* FIX-65 (FIX-60 → FIX-65 cleanest-cross-wave-dep): the REST server
     now handles POST /payjoin AND the payjoinreceive RPC is registered.
     `getpayjoinendpoint` remains unimplemented; this assertion is now
     ONE-of-two — payjoinreceive is the closed half. *)
  let ctx = make_rpc_ctx () in
  assert_rpc_unknown ctx "getpayjoinendpoint";
  (* G1 flipped: payjoinreceive MUST now dispatch (not method-not-found). *)
  match Rpc.dispatch_rpc ctx "payjoinreceive" [] with
  | Error (-32601, _) ->
    Alcotest.fail "G1 FIX-65 flip: payjoinreceive should now be dispatched"
  | Error _ | Ok _ -> ()

let test_g2_no_sender_http_client () =
  (* No `Cohttp_lwt_unix.Client.post` call to a PayJoin endpoint
     exists anywhere in the codebase.  Absence is asserted by the
     absence of a sender RPC. *)
  let ctx = make_rpc_ctx () in
  assert_rpc_unknown ctx "payjoinsend";
  assert_rpc_unknown ctx "sendpayjoin"

let test_g3_no_https_tls_termination () =
  (* No TLS termination for the REST/RPC server.
     `Cohttp_lwt_unix.Server.create_ssl` not used. *)
  let ctx = make_rpc_ctx () in
  assert_rpc_unknown ctx "getpayjointlsinfo"

(* ============================================================================
   G4-G6: OrigPSBT pipeline absence
   ============================================================================ *)

let test_g4_no_origpsbt_http_decoder () =
  (* `Psbt.of_base64` exists (FIX-60), but no wire-side HTTP-body
     decoder applies BIP-78 Content-Type rules.  We confirm via the
     absent RPC. *)
  let ctx = make_rpc_ctx () in
  assert_rpc_unknown ctx "decodeoriginalpsbt"

let test_g5_no_receiver_origpsbt_validation () =
  let ctx = make_rpc_ctx () in
  assert_rpc_unknown ctx "validateoriginalpsbt"

let test_g6_no_additionalfeeoutputindex_validator () =
  let ctx = make_rpc_ctx () in
  assert_rpc_unknown ctx "validatefeeoutputindex"

(* ============================================================================
   G7-G9: Receiver-side PSBT mutation absence
   ============================================================================ *)

let test_g7_no_receiver_add_input () =
  let ctx = make_rpc_ctx () in
  assert_rpc_unknown ctx "payjoinaddinput";
  assert_rpc_unknown ctx "receiveraddinputs"

let test_g8_no_receiver_modify_output () =
  let ctx = make_rpc_ctx () in
  assert_rpc_unknown ctx "payjoinmodifyoutput"

let test_g9_no_receiver_fee_adjustment () =
  let ctx = make_rpc_ctx () in
  assert_rpc_unknown ctx "payjoinadjustfee"

(* ============================================================================
   G10-G15: Sender anti-snoop checks — FIX-66 flips ALL six.
   ============================================================================

   The six BIP-78 sender-side anti-snoop validators are now available as
   pure functions in `Payjoin` (validate_anti_snoop_outputs,
   validate_anti_snoop_scriptsig_types, validate_anti_snoop_no_new_sender_inputs,
   validate_anti_snoop_max_fee, validate_anti_snoop_disable_os,
   validate_anti_snoop_minfeerate).  We verify presence + correct happy-
   path behaviour against a tiny synthetic round-trip PSBT pair.
*)

(* Minimal helpers — local to keep this audit file self-contained. *)
let _spk_v ~(byte : int) : Cstruct.t =
  let s = Cstruct.create 22 in
  Cstruct.set_uint8 s 0 0x00;
  Cstruct.set_uint8 s 1 0x14;
  Cstruct.set_uint8 s 5 byte;
  s

let _make_orig_payjoin_pair () =
  let spk_a = _spk_v ~byte:0x11 in
  let spk_b = _spk_v ~byte:0x22 in
  let prev = { Types.value = 100_000L; script_pubkey = spk_a } in
  let tx_orig : Types.transaction = {
    version = 2l;
    inputs = [{
      previous_output = { txid = Cstruct.create 32; vout = 0l };
      script_sig = Cstruct.empty;
      sequence = 0xFFFFFFFDl;
    }];
    outputs = [
      { value = 50_000L; script_pubkey = spk_a };
      { value = 40_000L; script_pubkey = spk_b };
    ];
    witnesses = [];
    locktime = 0l;
  } in
  let psbt_orig = Psbt.create tx_orig in
  let psbt_orig =
    { psbt_orig with inputs = [
        { Psbt.empty_input with
          witness_utxo = Some prev;
          final_scriptwitness = Some [Cstruct.of_string "\x00"]; };
      ] }
  in
  (* PayjoinPSBT: receiver appended its own input (60k) and bumped no
     outputs.  Fee delta = receiver_value (60k) since the outputs
     are unchanged — the test compares "happy path" (no fee cap).  *)
  let recv_prev = { Types.value = 60_000L; script_pubkey = spk_a } in
  let tx_pj : Types.transaction = {
    tx_orig with
    inputs = tx_orig.inputs @ [{
      previous_output = { txid = Cstruct.create 32; vout = 1l };
      script_sig = Cstruct.empty;
      sequence = 0xFFFFFFFDl;
    }];
  } in
  let psbt_pj = Psbt.create tx_pj in
  let psbt_pj =
    { psbt_pj with inputs = [
        { Psbt.empty_input with
          witness_utxo = Some prev;
          final_scriptwitness = Some [Cstruct.of_string "\x00"]; };
        { Psbt.empty_input with
          witness_utxo = Some recv_prev; };
      ] }
  in
  (psbt_orig, psbt_pj)

let test_g10_no_sender_output_anti_snoop () =
  (* FIX-66 flip: validate_anti_snoop_outputs is now a present pure
     function on Payjoin.  On the happy-path round-trip pair it returns
     Ok (). *)
  let (orig, pj) = _make_orig_payjoin_pair () in
  match Payjoin.validate_anti_snoop_outputs
          ~orig ~payjoin:pj ~fee_idx:None with
  | Ok () -> ()
  | Error v ->
    Alcotest.failf "G10 FIX-66 flip: output anti-snoop should pass: %s"
      (Payjoin.string_of_violation v)

let test_g11_no_sender_scriptsig_type_check () =
  (* FIX-66 flip: validate_anti_snoop_scriptsig_types is now present.
     Round-trip pair uses uniformly p2wpkh-shape outputs, so the check
     returns Ok (). *)
  let (_orig, pj) = _make_orig_payjoin_pair () in
  match Payjoin.validate_anti_snoop_scriptsig_types ~payjoin:pj with
  | Ok () -> ()
  | Error v ->
    Alcotest.failf "G11 FIX-66 flip: scriptsig-type check should pass: %s"
      (Payjoin.string_of_violation v)

let test_g12_no_sender_no_new_inputs_check () =
  (* FIX-66 flip: validate_anti_snoop_no_new_sender_inputs is now present.
     Receiver appended an input but did NOT remove the sender's — Ok. *)
  let (orig, pj) = _make_orig_payjoin_pair () in
  match Payjoin.validate_anti_snoop_no_new_sender_inputs ~orig ~payjoin:pj with
  | Ok () -> ()
  | Error v ->
    Alcotest.failf "G12 FIX-66 flip: input-preservation check should pass: %s"
      (Payjoin.string_of_violation v)

let test_g13_no_sender_max_fee_check () =
  (* FIX-66 flip: validate_anti_snoop_max_fee is now present.  Round-trip
     pair has fee delta = -60k (receiver added a 60k input, no output
     bump), which is < cap=infinity → Ok. *)
  let (orig, pj) = _make_orig_payjoin_pair () in
  match Payjoin.validate_anti_snoop_max_fee
          ~orig ~payjoin:pj ~max_contribution:(Some 100_000L) with
  | Ok () -> ()
  | Error v ->
    Alcotest.failf "G13 FIX-66 flip: max-fee check should pass: %s"
      (Payjoin.string_of_violation v)

let test_g14_no_sender_disableos_honour () =
  (* FIX-66 flip: validate_anti_snoop_disable_os is now present.
     disable_os=true + no output substitution → Ok. *)
  let (orig, pj) = _make_orig_payjoin_pair () in
  match Payjoin.validate_anti_snoop_disable_os
          ~orig ~payjoin:pj ~disable_os:true ~fee_idx:None with
  | Ok () -> ()
  | Error v ->
    Alcotest.failf "G14 FIX-66 flip: disable_os check should pass: %s"
      (Payjoin.string_of_violation v)

let test_g15_no_sender_minfeerate_enforcement () =
  (* FIX-66 flip: validate_anti_snoop_minfeerate is now present.
     No minfeerate set → returns Ok () (vacuous). *)
  let (_orig, pj) = _make_orig_payjoin_pair () in
  match Payjoin.validate_anti_snoop_minfeerate
          ~payjoin:pj ~minfeerate:None with
  | Ok () -> ()
  | Error v ->
    Alcotest.failf "G15 FIX-66 flip: minfeerate check should pass: %s"
      (Payjoin.string_of_violation v)

(* ============================================================================
   G16-G17: URI / wire-error absence
   ============================================================================ *)

(* Probe: try to parse a BIP-21 URI containing a `pj=` query parameter.
   camlcoin has no BIP-21 parser, so the string passes through to
   Address.address_of_string which rejects it as not-an-address.  This
   documents the gap *and* the surface we'd need to extend. *)
let test_g16_no_query_param_parser () =
  let uri =
    "bitcoin:bc1qaddress?pj=https://example.com/pj&pjos=0\
     &additionalfeeoutputindex=1&maxadditionalfeecontribution=1000\
     &minfeerate=2.0&v=1" in
  (* If a BIP-21 parser existed, it would extract the address and
     query params.  Absence: Address.address_of_string rejects the whole
     string. *)
  match Address.address_of_string uri with
  | Ok _ ->
    Alcotest.fail "BIP-21 URI was accepted by Address.address_of_string — \
                   that's surprising, please review G16"
  | Error _ ->
    ()  (* expected: no BIP-21 awareness *)

let test_g17_no_payjoin_error_codes () =
  (* BIP-78 defines 4 wire errors: unavailable, not-enough-money,
     version-unsupported, original-psbt-rejected.  These would surface
     as RPC errors with specific codes (BIP-78 uses HTTP 4xx + a JSON
     `errorCode` field).  We assert no such RPC exists to emit them. *)
  let ctx = make_rpc_ctx () in
  assert_rpc_unknown ctx "getpayjoinerror"

(* ============================================================================
   G18-G20: Receiver session/UTXO management absence
   ============================================================================ *)

let test_g18_no_receiver_session_ttl () =
  let ctx = make_rpc_ctx () in
  assert_rpc_unknown ctx "expirepayjoinrequest";
  assert_rpc_unknown ctx "listpayjoinsessions"

let test_g19_no_receiver_double_spend_check () =
  let ctx = make_rpc_ctx () in
  assert_rpc_unknown ctx "verifypayjoinnodouble"

let test_g20_no_anti_fp_utxo_selection () =
  (* Wallet has W113 coin selection but no PayJoin-aware variant
     that produces a plausible-non-PayJoin output mix. *)
  let ctx = make_rpc_ctx () in
  assert_rpc_unknown ctx "selectpayjoinutxos"

(* ============================================================================
   G21-G22: Protocol version / fallback
   ============================================================================ *)

let test_g21_no_v1_header_handling () =
  (* G21 FIX-65 flip: getpayjoinversion now registered (returns v=1). *)
  let ctx = make_rpc_ctx () in
  match Rpc.dispatch_rpc ctx "getpayjoinversion" [] with
  | Error (-32601, _) ->
    Alcotest.fail "G21 FIX-65 flip: getpayjoinversion should now be dispatched"
  | Error (code, msg) ->
    Alcotest.failf "G21 dispatched but errored: %d %s" code msg
  | Ok _ -> ()

let test_g22_no_sender_fallback () =
  (* FIX-66 flip: the fallback policy lives in [Payjoin.finalize_send]:
     when the receiver does NOT reply ([send_outcome] =
     [Fallback_broadcast_origpsbt]) the verdict is [`Fallback_broadcast]
     and the operator broadcasts the OrigPSBT.  We assert presence by
     exercising the function on a transport-error outcome. *)
  let spk = _spk_v ~byte:0x33 in
  let tx : Types.transaction = {
    version = 2l;
    inputs = [{
      previous_output = { txid = Cstruct.create 32; vout = 0l };
      script_sig = Cstruct.empty;
      sequence = 0xFFFFFFFDl;
    }];
    outputs = [{ value = 100L; script_pubkey = spk }];
    witnesses = [];
    locktime = 0l;
  } in
  let orig = Psbt.create tx in
  let verdict = Payjoin.finalize_send
    ~orig ~params:Payjoin.default_sender_params
    (Payjoin.Fallback_broadcast_origpsbt "receiver unreachable")
  in
  match verdict with
  | `Fallback_broadcast _ -> ()
  | _ -> Alcotest.fail "G22 FIX-66 flip: transport-error must yield Fallback_broadcast"

(* ============================================================================
   G23-G25: Wire / transport guards
   ============================================================================ *)

let test_g23_no_content_type_validator () =
  (* G23 FIX-65 flip: validatepayjoincontenttype now registered.  The
     wire-side Content-Type guard also runs inside Rest.handle_payjoin
     before any PSBT decode is attempted. *)
  let ctx = make_rpc_ctx () in
  match Rpc.dispatch_rpc ctx
          "validatepayjoincontenttype" [`String "text/plain"] with
  | Error (-32601, _) ->
    Alcotest.fail "G23 FIX-65 flip: validatepayjoincontenttype should now be dispatched"
  | Error (code, msg) ->
    Alcotest.failf "G23 dispatched but errored: %d %s" code msg
  | Ok _ -> ()

let test_g24_no_https_cert_check () =
  (* FIX-66 flip: Payjoin.verify_tls_cert is now present.  We exercise
     it with a deliberately-empty cert chain — the validator MUST
     reject (verify_chain returns `EmptyCertificateChain). *)
  let authenticator
    : ?ip:Ipaddr.t -> host:[`host] Domain_name.t option ->
      X509.Certificate.t list -> X509.Validation.r
    = fun ?ip:_ ~host:_ chain ->
      match chain with
      | [] -> Error (`EmptyCertificateChain)
      | _  -> Ok None
  in
  match Payjoin.verify_tls_cert
          ~authenticator ~hostname:"example.com" [] with
  | Ok () ->
    Alcotest.fail "G24 FIX-66 flip: empty chain must be rejected"
  | Error _ -> ()

let test_g25_no_tor_onion_inbound_for_receiver () =
  (* W117 FIX-58 wired persistent I2P session AND added Tor outbound,
     but BIP-78 requires the *receiver* publish a hidden service
     for sender→receiver POSTs.  This is a separate inbound .onion
     publication step that's not yet wired anywhere. *)
  let ctx = make_rpc_ctx () in
  assert_rpc_unknown ctx "createpayjoinhiddenservice"

(* ============================================================================
   G26-G27: Top-level RPC methods absence
   ============================================================================ *)

let test_g26_no_getpayjoinrequest_rpc () =
  (* FIX-66 flip: getpayjoinrequest is now a registered RPC.  The
     wallet-less ctx in this audit harness causes the handler to
     return its own error ("wallet not loaded") — both Ok and
     Error-other-than-method-not-found are acceptable presence
     signals. *)
  let ctx = make_rpc_ctx () in
  match Rpc.dispatch_rpc ctx "getpayjoinrequest" [`Int 50000] with
  | Error (-32601, _) ->
    Alcotest.fail "G26 FIX-66 flip: getpayjoinrequest should now dispatch"
  | Error _ | Ok _ -> ()

let test_g27_no_sendpayjoinrequest_rpc () =
  (* FIX-66 flip: sendpayjoinrequest is now a registered RPC.  Same
     wallet-less acceptance criterion as G26. *)
  let ctx = make_rpc_ctx () in
  match Rpc.dispatch_rpc ctx "sendpayjoinrequest" [`String "bitcoin:bc1q"] with
  | Error (-32601, _) ->
    Alcotest.fail "G27 FIX-66 flip: sendpayjoinrequest should now dispatch"
  | Error _ | Ok _ -> ()

(* ============================================================================
   G28-G29: BIP-21 URI parser absence (covers `pj=` + `pjos=`)
   ============================================================================ *)

let test_g28_no_bip21_uri_parser () =
  (* Address.address_of_string is the canonical "decode an address-y
     string" entry point.  With no BIP-21 awareness it must return
     Error for a `bitcoin:` URI (we already proved this in G16; G28
     documents the architectural gap of the missing parser). *)
  let uri = "bitcoin:bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4?amount=0.1" in
  match Address.address_of_string uri with
  | Ok _ -> Alcotest.fail "Address.address_of_string unexpectedly accepted BIP-21 URI"
  | Error _ -> ()

let test_g29_no_pjos_flag_parser () =
  (* `pjos=0` / `pjos=1` is the disable-output-substitution flag.
     Confirms BIP-21 parser absence for this *specific* extension
     param.  Same surface as G28 but documents the BIP-78 extension. *)
  let uri = "bitcoin:bc1qaddr?pj=https://x/pj&pjos=1" in
  match Address.address_of_string uri with
  | Ok _ -> Alcotest.fail "Address.address_of_string accepted pjos= URI"
  | Error _ -> ()

(* ============================================================================
   G30: Receiver replay protection absence
   ============================================================================ *)

let test_g30_no_receiver_replay_protection () =
  let ctx = make_rpc_ctx () in
  assert_rpc_unknown ctx "checkpayjoinreplay"

(* ============================================================================
   Cross-cutting: confirm FIX-60 walletprocesspsbt RPC IS present
   (this is the building block the missing receiver pipeline will use)
   ============================================================================ *)

let test_walletprocesspsbt_is_present_baseline () =
  (* Positive baseline: assert walletprocesspsbt IS registered.
     If this fails, FIX-60 has regressed. *)
  let ctx = make_rpc_ctx () in
  match Rpc.dispatch_rpc ctx "walletprocesspsbt" [] with
  | Error (-32601, _) ->
    Alcotest.fail "walletprocesspsbt is unexpectedly absent — FIX-60 \
                   regression — PayJoin receiver building block is gone"
  | Error _ | Ok _ ->
    (* Error from missing params is fine — we only care that the
       method itself is dispatched (not method-not-found). *)
    ()

(* ============================================================================
   Test registration
   ============================================================================ *)

let receiver_http_tests = [
  Alcotest.test_case "G1  receiver HTTP endpoint CLOSED (FIX-65) — flipped"
    `Quick test_g1_no_receiver_http_endpoint;
  Alcotest.test_case "G3  no HTTPS/TLS endpoint (BUG-3, P0)"
    `Quick test_g3_no_https_tls_termination;
  Alcotest.test_case "G18 no receiver session TTL (BUG-18, P1)"
    `Quick test_g18_no_receiver_session_ttl;
  Alcotest.test_case "G19 no receiver no-double-spend check (BUG-19, P0)"
    `Quick test_g19_no_receiver_double_spend_check;
  Alcotest.test_case "G20 no anti-fp UTXO selection (BUG-20, P1)"
    `Quick test_g20_no_anti_fp_utxo_selection;
  Alcotest.test_case "G23 Content-Type validator CLOSED (FIX-65) — flipped"
    `Quick test_g23_no_content_type_validator;
  Alcotest.test_case "G24 HTTPS cert/hostname check CLOSED (FIX-66) — flipped"
    `Quick test_g24_no_https_cert_check;
  Alcotest.test_case "G30 no receiver replay protection (BUG-30, P1)"
    `Quick test_g30_no_receiver_replay_protection;
]

let sender_http_tests = [
  Alcotest.test_case "G2  no sender HTTP client (BUG-2, P1)"
    `Quick test_g2_no_sender_http_client;
  Alcotest.test_case "G22 sender fallback CLOSED (FIX-66) — flipped"
    `Quick test_g22_no_sender_fallback;
  Alcotest.test_case "G25 no Tor .onion inbound for receiver (BUG-25, P1)"
    `Quick test_g25_no_tor_onion_inbound_for_receiver;
  Alcotest.test_case "G26 getpayjoinrequest RPC CLOSED (FIX-66) — flipped"
    `Quick test_g26_no_getpayjoinrequest_rpc;
  Alcotest.test_case "G27 sendpayjoinrequest RPC CLOSED (FIX-66) — flipped"
    `Quick test_g27_no_sendpayjoinrequest_rpc;
]

let origpsbt_tests = [
  Alcotest.test_case "G4  no OrigPSBT HTTP-body decoder (BUG-4, P0)"
    `Quick test_g4_no_origpsbt_http_decoder;
  Alcotest.test_case "G5  no receiver OrigPSBT validation (BUG-5, P0)"
    `Quick test_g5_no_receiver_origpsbt_validation;
  Alcotest.test_case "G7  no receiver add-input helper (BUG-7, P0)"
    `Quick test_g7_no_receiver_add_input;
  Alcotest.test_case "G8  no receiver modify-output helper (BUG-8, P1)"
    `Quick test_g8_no_receiver_modify_output;
  Alcotest.test_case "G9  no receiver fee adjustment (BUG-9, P1)"
    `Quick test_g9_no_receiver_fee_adjustment;
]

let anti_snoop_tests = [
  Alcotest.test_case "G10 sender output anti-snoop CLOSED (FIX-66) — flipped"
    `Quick test_g10_no_sender_output_anti_snoop;
  Alcotest.test_case "G11 sender scriptSig-type check CLOSED (FIX-66) — flipped"
    `Quick test_g11_no_sender_scriptsig_type_check;
  Alcotest.test_case "G12 sender no-new-inputs check CLOSED (FIX-66) — flipped"
    `Quick test_g12_no_sender_no_new_inputs_check;
  Alcotest.test_case "G13 sender max-fee check CLOSED (FIX-66) — flipped"
    `Quick test_g13_no_sender_max_fee_check;
  Alcotest.test_case "G14 sender disable_os honour CLOSED (FIX-66) — flipped"
    `Quick test_g14_no_sender_disableos_honour;
  Alcotest.test_case "G15 sender minfeerate enforcement CLOSED (FIX-66) — flipped"
    `Quick test_g15_no_sender_minfeerate_enforcement;
]

let uri_wire_tests = [
  Alcotest.test_case "G6  no additionalfeeoutputindex validator (BUG-6, P1)"
    `Quick test_g6_no_additionalfeeoutputindex_validator;
  Alcotest.test_case "G16 no query-param parser (BUG-16, P0)"
    `Quick test_g16_no_query_param_parser;
  Alcotest.test_case "G17 no PayJoin wire-error codes (BUG-17, P0)"
    `Quick test_g17_no_payjoin_error_codes;
  Alcotest.test_case "G21 v=1 version handling CLOSED (FIX-65) — flipped"
    `Quick test_g21_no_v1_header_handling;
  Alcotest.test_case "G28 no BIP-21 bitcoin: URI parser (BUG-28, P0)"
    `Quick test_g28_no_bip21_uri_parser;
  Alcotest.test_case "G29 no pjos= flag parser (BUG-29, P0)"
    `Quick test_g29_no_pjos_flag_parser;
]

let cross_cutting_tests = [
  Alcotest.test_case "walletprocesspsbt baseline (FIX-60 building block)"
    `Quick test_walletprocesspsbt_is_present_baseline;
]

let () =
  Alcotest.run "W119_payjoin" [
    ("Receiver HTTP",  receiver_http_tests);
    ("Sender HTTP",    sender_http_tests);
    ("OrigPSBT",       origpsbt_tests);
    ("Sender anti-snoop", anti_snoop_tests);
    ("URI / wire",     uri_wire_tests);
    ("Cross-cutting",  cross_cutting_tests);
  ]
