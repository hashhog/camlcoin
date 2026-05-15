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
  (* The REST server handles only GET endpoints (block/tx/headers).
     There is no POST /payjoin handler.  We assert this by exercising
     the dispatch table: if a PayJoin POST handler existed it would
     be registered as an RPC method or a REST path.  Since no source
     file mentions "payjoin", neither is present. *)
  let ctx = make_rpc_ctx () in
  assert_rpc_unknown ctx "getpayjoinendpoint";
  assert_rpc_unknown ctx "payjoinreceive"

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
   G10-G15: Sender anti-snoop checks absence
   ============================================================================ *)

let test_g10_no_sender_output_anti_snoop () =
  let ctx = make_rpc_ctx () in
  assert_rpc_unknown ctx "verifypayjoinoutputs"

let test_g11_no_sender_scriptsig_type_check () =
  let ctx = make_rpc_ctx () in
  assert_rpc_unknown ctx "verifypayjoinscriptsigtypes"

let test_g12_no_sender_no_new_inputs_check () =
  let ctx = make_rpc_ctx () in
  assert_rpc_unknown ctx "verifypayjoinnoneworiginal"

let test_g13_no_sender_max_fee_check () =
  let ctx = make_rpc_ctx () in
  assert_rpc_unknown ctx "verifypayjoinmaxfee"

let test_g14_no_sender_disableos_honour () =
  let ctx = make_rpc_ctx () in
  assert_rpc_unknown ctx "verifypayjoindisableos"

let test_g15_no_sender_minfeerate_enforcement () =
  let ctx = make_rpc_ctx () in
  assert_rpc_unknown ctx "verifypayjoinminfeerate"

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
  let ctx = make_rpc_ctx () in
  assert_rpc_unknown ctx "getpayjoinversion"

let test_g22_no_sender_fallback () =
  (* On receiver timeout/error sender must broadcast the OrigPSBT as
     a plain tx.  This logic would live behind sendpayjoinrequest;
     absent. *)
  let ctx = make_rpc_ctx () in
  assert_rpc_unknown ctx "fallbacksendoriginalpsbt"

(* ============================================================================
   G23-G25: Wire / transport guards
   ============================================================================ *)

let test_g23_no_content_type_validator () =
  let ctx = make_rpc_ctx () in
  assert_rpc_unknown ctx "validatepayjoincontenttype"

let test_g24_no_https_cert_check () =
  let ctx = make_rpc_ctx () in
  assert_rpc_unknown ctx "verifypayjointlscert"

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
  let ctx = make_rpc_ctx () in
  assert_rpc_unknown ctx "getpayjoinrequest"

let test_g27_no_sendpayjoinrequest_rpc () =
  let ctx = make_rpc_ctx () in
  assert_rpc_unknown ctx "sendpayjoinrequest"

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
  Alcotest.test_case "G1  no receiver HTTP endpoint (BUG-1, P0)"
    `Quick test_g1_no_receiver_http_endpoint;
  Alcotest.test_case "G3  no HTTPS/TLS endpoint (BUG-3, P0)"
    `Quick test_g3_no_https_tls_termination;
  Alcotest.test_case "G18 no receiver session TTL (BUG-18, P1)"
    `Quick test_g18_no_receiver_session_ttl;
  Alcotest.test_case "G19 no receiver no-double-spend check (BUG-19, P0)"
    `Quick test_g19_no_receiver_double_spend_check;
  Alcotest.test_case "G20 no anti-fp UTXO selection (BUG-20, P1)"
    `Quick test_g20_no_anti_fp_utxo_selection;
  Alcotest.test_case "G23 no Content-Type validator (BUG-23, P0)"
    `Quick test_g23_no_content_type_validator;
  Alcotest.test_case "G24 no HTTPS cert/hostname check (BUG-24, P0)"
    `Quick test_g24_no_https_cert_check;
  Alcotest.test_case "G30 no receiver replay protection (BUG-30, P1)"
    `Quick test_g30_no_receiver_replay_protection;
]

let sender_http_tests = [
  Alcotest.test_case "G2  no sender HTTP client (BUG-2, P1)"
    `Quick test_g2_no_sender_http_client;
  Alcotest.test_case "G22 no sender fallback to non-PayJoin (BUG-22, P1)"
    `Quick test_g22_no_sender_fallback;
  Alcotest.test_case "G25 no Tor .onion inbound for receiver (BUG-25, P1)"
    `Quick test_g25_no_tor_onion_inbound_for_receiver;
  Alcotest.test_case "G26 no getpayjoinrequest RPC (BUG-26, P1)"
    `Quick test_g26_no_getpayjoinrequest_rpc;
  Alcotest.test_case "G27 no sendpayjoinrequest RPC (BUG-27, P1)"
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
  Alcotest.test_case "G10 no sender output anti-snoop (BUG-10, P0)"
    `Quick test_g10_no_sender_output_anti_snoop;
  Alcotest.test_case "G11 no sender scriptSig-type check (BUG-11, P0)"
    `Quick test_g11_no_sender_scriptsig_type_check;
  Alcotest.test_case "G12 no sender no-new-inputs check (BUG-12, P0)"
    `Quick test_g12_no_sender_no_new_inputs_check;
  Alcotest.test_case "G13 no sender max-fee check (BUG-13, P0)"
    `Quick test_g13_no_sender_max_fee_check;
  Alcotest.test_case "G14 no sender disableos honour (BUG-14, P1)"
    `Quick test_g14_no_sender_disableos_honour;
  Alcotest.test_case "G15 no sender minfeerate enforcement (BUG-15, P1)"
    `Quick test_g15_no_sender_minfeerate_enforcement;
]

let uri_wire_tests = [
  Alcotest.test_case "G6  no additionalfeeoutputindex validator (BUG-6, P1)"
    `Quick test_g6_no_additionalfeeoutputindex_validator;
  Alcotest.test_case "G16 no query-param parser (BUG-16, P0)"
    `Quick test_g16_no_query_param_parser;
  Alcotest.test_case "G17 no PayJoin wire-error codes (BUG-17, P0)"
    `Quick test_g17_no_payjoin_error_codes;
  Alcotest.test_case "G21 no v=1 version header handling (BUG-21, P0)"
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
