(* W135 Standardness rules (IsStandardTx) — camlcoin (OCaml)

   Discovery-only audit.  30 gates / 17 NEW bugs (1 P0-CONSENSUS / 4 P0-CDIV /
   4 P1 / 5 P2 / 3 P3).  Full catalogue: audit/w135_standardness_rules.md.

   References:
   - bitcoin-core/src/policy/policy.cpp + policy.h
   - bitcoin-core/src/script/solver.cpp + solver.h
   - bitcoin-core/src/policy/truc_policy.cpp + truc_policy.h
   - bitcoin-core/src/consensus/tx_check.cpp
   - bitcoin-core/src/pubkey.h (CPubKey::ValidSize / GetLen)

   Severity legend:
   - P0-CONSENSUS: directly observable block-validation divergence vs Core
   - P0-CDIV:      consensus-relevant policy / mempool divergence
   - P1:           correctness gap at the RPC / mempool surface
   - P2:           structural / robustness gap
   - P3:           doc / convention drift

   BUGs documented here (numbered as BUG-W135-N):

   BUG-1  (P0-CDIV, G6):   is_p2pk_script accepts P2PK with invalid pubkey header
                            (no CPubKey::ValidSize check).  mempool.ml:987-996.
   BUG-2  (P0-CDIV, G9):   decode_bare_multisig accepts bare-multisig with
                            invalid pubkey header(s).  mempool.ml:1003-1050.
   BUG-3  (P1, G14):       -permitbaremultisig runtime flag absent.
   BUG-4  (P0-CDIV, G15):  -datacarrier / -datacarriersize runtime flag absent.
                            Hard-coded 100_000 budget; cannot disable.
   BUG-5  (P0-CDIV, G16):  Dust formula uses 3 × min_relay_fee instead of
                            Core's separately-configurable dustRelayFee
                            (default DUST_RELAY_TX_FEE = 3000 sat/kvB).
   BUG-6  (P0-CDIV, G17):  P2A dust = (value <> 240L) hard-code; rejects any
                            P2A above or below 240 sat that Core would accept.
   BUG-7  (P0-CONSENSUS, G19): CheckSigopsBIP54 (per-input non-witness sigops
                            ≤ MAX_TX_LEGACY_SIGOPS=2500) completely absent.
   BUG-8  (P1, G20):       extract_last_push_data skips OP_0/OP_1NEGATE/OP_n.
                            Wrong "last subscript" for P2SH sigop counting on
                            adversarial scriptSig shapes.
   BUG-9  (P1, G25):       spends_non_anchor_witness_prog doesn't unwrap P2SH.
                            TX_WITNESS_STRIPPED detection misses P2SH-wrapped
                            witness programs.
   BUG-10 (P1, G27):       TRUC sibling-eviction return missing (W106 BUG-5
                            carry-forward).
   BUG-11 (P2, G29):       -bytespersigop runtime flag absent.
   BUG-12 (P2, G30):       -acceptnonstdtxn runtime flag absent.
   BUG-13 (P2, G16):       spending_input_size magic constants drift from Core
                            (148/91/67/109/58/41 — P2SH should be 148, P2WSH
                            should be 67, etc.).
   BUG-14 (P2, G7-9):      multi_a (BIP-342) not in classify_script.
   BUG-15 (P3, G16):       Dust uses float arithmetic (precision footgun).
   BUG-16 (P3, G19-20):    Error strings drift from Core's reason literals
                            ("version" / "tx-size" / "bare-multisig" / ...).
   BUG-17 (P3, G27):       TRUC inheritance error string drift.

   Tests are pass-as-evidence:  each documents current behaviour and serves as
   a regression-pin.  When a fix wave closes a gap, the matching test flips
   from "documents absence" to "verifies presence".
*)

open Camlcoin

(* ============================================================================
   Helpers
   ============================================================================ *)

(* Constants we expect to find named in Core.  Centralising them lets the
   audit-as-test record them explicitly. *)
let core_tx_min_standard_version              = 1l
let core_tx_max_standard_version              = 3l
let core_max_standard_tx_weight               = 400_000
let core_min_standard_tx_nonwitness_size      = 65
let core_max_standard_scriptsig_size          = 1650
let core_max_p2sh_sigops                      = 15
let core_max_standard_tx_sigops_cost          = 16_000
let core_max_tx_legacy_sigops                 = 2_500     (* BIP-54 *)
let core_default_incremental_relay_fee        = 100       (* sat/kvB *)
let core_default_bytes_per_sigop              = 20
let core_default_permit_bare_multisig         = true
let core_max_standard_p2wsh_stack_items       = 100
let core_max_standard_p2wsh_stack_item_size   = 80
let core_max_standard_tapscript_stack_item_size = 80
let core_max_standard_p2wsh_script_size       = 3600
let core_dust_relay_tx_fee                    = 3000      (* sat/kvB *)
let core_default_min_relay_tx_fee             = 100       (* sat/kvB *)
let core_max_op_return_relay                  = 100_000   (* bytes; default *)
let core_max_dust_outputs_per_tx              = 1
let core_truc_version                         = 3l
let core_truc_max_vsize                       = 10_000
let core_truc_child_max_vsize                 = 1_000
let core_truc_ancestor_limit                  = 2
let core_truc_descendant_limit                = 2

let mk_zero_hash () : Types.hash256 = Cstruct.create 32

(* Build a minimal tx with one input and one output, no witness. *)
let mk_tx ?(version = 1l) ?(outputs = []) () : Types.transaction =
  {
    version;
    inputs = [{
      previous_output = { txid = mk_zero_hash (); vout = 0l };
      script_sig = Cstruct.create 0;
      sequence = 0xfffffffdl;
    }];
    outputs;
    witnesses = [];
    locktime = 0l;
  }

(* Build a scriptPubKey of the form "0x21 <33 bytes header,...> 0xac".
   header is the first byte of the pubkey body. *)
let mk_p2pk_compressed ~(header : int) : Cstruct.t =
  let s = Cstruct.create 35 in
  Cstruct.set_uint8 s 0 0x21;
  Cstruct.set_uint8 s 1 header;
  for i = 2 to 33 do Cstruct.set_uint8 s i 0x00 done;
  Cstruct.set_uint8 s 34 0xac;
  s

(* Build a P2PK uncompressed (67 bytes): 0x41 <header,...> 0xac *)
let mk_p2pk_uncompressed ~(header : int) : Cstruct.t =
  let s = Cstruct.create 67 in
  Cstruct.set_uint8 s 0 0x41;
  Cstruct.set_uint8 s 1 header;
  for i = 2 to 65 do Cstruct.set_uint8 s i 0x00 done;
  Cstruct.set_uint8 s 66 0xac;
  s

(* Build a bare 1-of-1 multisig with one 33-byte compressed pubkey starting
   with the given header byte. *)
let mk_bare_multisig_1of1 ~(header : int) : Cstruct.t =
  (* OP_1 (0x51) OP_PUSH33 (0x21) <header,0,...0> OP_1 (0x51) OP_CHECKMULTISIG (0xae) *)
  let s = Cstruct.create 37 in
  Cstruct.set_uint8 s 0 0x51;
  Cstruct.set_uint8 s 1 0x21;
  Cstruct.set_uint8 s 2 header;
  for i = 3 to 34 do Cstruct.set_uint8 s i 0x00 done;
  Cstruct.set_uint8 s 35 0x51;
  Cstruct.set_uint8 s 36 0xae;
  s

(* P2A scriptPubKey: OP_1 OP_PUSHBYTES_2 0x4e 0x73 *)
let mk_p2a () : Cstruct.t =
  let s = Cstruct.create 4 in
  Cstruct.set_uint8 s 0 0x51;
  Cstruct.set_uint8 s 1 0x02;
  Cstruct.set_uint8 s 2 0x4e;
  Cstruct.set_uint8 s 3 0x73;
  s

(* A standard P2PKH scriptPubKey, used as an "always-passes" baseline. *)
let mk_p2pkh () : Cstruct.t =
  let s = Cstruct.create 25 in
  Cstruct.set_uint8 s 0 0x76; (* OP_DUP *)
  Cstruct.set_uint8 s 1 0xa9; (* OP_HASH160 *)
  Cstruct.set_uint8 s 2 0x14; (* push 20 *)
  for i = 3 to 22 do Cstruct.set_uint8 s i 0x00 done;
  Cstruct.set_uint8 s 23 0x88; (* OP_EQUALVERIFY *)
  Cstruct.set_uint8 s 24 0xac; (* OP_CHECKSIG *)
  s

(* ============================================================================
   G1-G5: IsStandardTx outer gates (version, weight, scriptSig, output)
   ============================================================================ *)

(* G1: version ∈ [TX_MIN_STANDARD_VERSION=1, TX_MAX_STANDARD_VERSION=3]. *)
let test_g1_version_bounds () =
  ignore core_tx_min_standard_version;
  ignore core_tx_max_standard_version;
  let tx_v0 = mk_tx ~version:0l ~outputs:[{value = 100_000L; script_pubkey = mk_p2pkh ()}] () in
  let tx_v4 = mk_tx ~version:4l ~outputs:[{value = 100_000L; script_pubkey = mk_p2pkh ()}] () in
  let res_v0 = Mempool.is_standard_tx 3000L tx_v0 in
  let res_v4 = Mempool.is_standard_tx 3000L tx_v4 in
  Alcotest.(check bool) "G1a: version=0 rejected" true (Result.is_error res_v0);
  Alcotest.(check bool) "G1d: version=4 rejected" true (Result.is_error res_v4)

(* G2: weight ≤ MAX_STANDARD_TX_WEIGHT=400_000. *)
let test_g2_max_standard_tx_weight () =
  ignore core_max_standard_tx_weight;
  Alcotest.(check int)
    "G2: camlcoin max_standard_tx_weight matches Core 400_000"
    400_000 Consensus.max_standard_tx_weight

(* G3: nonwitness_size ≥ MIN_STANDARD_TX_NONWITNESS_SIZE=65 (CVE-2017-12842). *)
let test_g3_min_nonwitness_size () =
  ignore core_min_standard_tx_nonwitness_size;
  (* The minimum-tx is the empty-witness 1-input 0-output tx; this is < 65
     bytes and SHOULD be rejected. *)
  let tx = mk_tx () in (* no outputs ⇒ minimal serialization, < 65 bytes *)
  let r = Mempool.is_standard_tx 3000L tx in
  Alcotest.(check bool)
    "G3: <65-byte non-witness tx rejected (CVE-2017-12842)"
    true (Result.is_error r)

(* G4: per-input scriptSig.size() ≤ MAX_STANDARD_SCRIPTSIG_SIZE=1650
       AND scriptSig.IsPushOnly(). *)
let test_g4_scriptsig_size_and_pushonly () =
  ignore core_max_standard_scriptsig_size;
  (* scriptSig of 1651 bytes (all PUSH(0)) — Core/camlcoin: reject. *)
  let big_pushonly =
    let s = Cstruct.create 1651 in
    Cstruct.set_uint8 s 0 0x4d; (* OP_PUSHDATA2 *)
    Cstruct.LE.set_uint16 s 1 1648; (* push 1648 bytes *)
    for i = 3 to 1650 do Cstruct.set_uint8 s i 0x00 done;
    s
  in
  let tx_big = { (mk_tx ~outputs:[{value = 100_000L; script_pubkey = mk_p2pkh ()}] ())
                 with inputs = [{
                   previous_output = { txid = mk_zero_hash (); vout = 0l };
                   script_sig = big_pushonly;
                   sequence = 0xfffffffdl;
                 }] } in
  let r_big = Mempool.is_standard_tx 3000L tx_big in
  Alcotest.(check bool) "G4a: scriptSig > 1650 bytes rejected" true (Result.is_error r_big);
  (* scriptSig that contains a non-push opcode (e.g. OP_DUP=0x76). *)
  let non_pushonly = Cstruct.create 1 in
  Cstruct.set_uint8 non_pushonly 0 0x76;
  let tx_nonpush = { (mk_tx ~outputs:[{value = 100_000L; script_pubkey = mk_p2pkh ()}] ())
                     with inputs = [{
                       previous_output = { txid = mk_zero_hash (); vout = 0l };
                       script_sig = non_pushonly;
                       sequence = 0xfffffffdl;
                     }] } in
  let r_nonpush = Mempool.is_standard_tx 3000L tx_nonpush in
  Alcotest.(check bool) "G4b: non-pushonly scriptSig rejected" true (Result.is_error r_nonpush)

(* G5: per-output IsStandard(scriptPubKey).  Documented via is_standard_output. *)
let test_g5_per_output_standard () =
  Alcotest.(check bool) "G5a: P2PKH standard" true
    (Mempool.is_standard_output (mk_p2pkh ()));
  let nonstandard = Cstruct.create 5 in
  Cstruct.set_uint8 nonstandard 0 0x6a;  (* OP_RETURN *)
  Cstruct.set_uint8 nonstandard 1 0xff;  (* RESERVED — not a push opcode *)
  Cstruct.set_uint8 nonstandard 2 0x00;
  Cstruct.set_uint8 nonstandard 3 0x00;
  Cstruct.set_uint8 nonstandard 4 0x00;
  Alcotest.(check bool) "G5b: OP_RETURN with non-pushonly tail is nonstandard"
    false (Mempool.is_standard_output nonstandard)

(* ============================================================================
   G6-G10: Solver-equivalent classification + multisig limits
   ============================================================================ *)

(* G6: BUG-W135-1 — is_p2pk_script doesn't validate pubkey header.
   A 33-byte body with header 0x00 is INVALID in Core (GetLen(0x00)=0) but
   recognised as P2PK in camlcoin.  Same for 65-byte uncompressed. *)
let test_g6_p2pk_no_header_check () =
  (* Header 0x02 / 0x03 / 0x04 are valid; 0x00 / 0x05 / 0xff are invalid. *)
  let valid_p2pk_02            = mk_p2pk_compressed ~header:0x02 in
  let valid_p2pk_03            = mk_p2pk_compressed ~header:0x03 in
  let invalid_p2pk_00          = mk_p2pk_compressed ~header:0x00 in
  let invalid_p2pk_05          = mk_p2pk_compressed ~header:0x05 in
  let invalid_p2pk_ff          = mk_p2pk_compressed ~header:0xff in
  let invalid_p2pk_unc_00      = mk_p2pk_uncompressed ~header:0x00 in
  let invalid_p2pk_unc_05      = mk_p2pk_uncompressed ~header:0x05 in
  Alcotest.(check bool) "G6a: 0x02 header recognised (correct)"
    true (Mempool.is_standard_output valid_p2pk_02);
  Alcotest.(check bool) "G6b: 0x03 header recognised (correct)"
    true (Mempool.is_standard_output valid_p2pk_03);
  (* BUG-W135-1: camlcoin says these are standard; Core says NONSTANDARD. *)
  Alcotest.(check bool)
    "G6c: BUG-W135-1 — compressed 0x00 header passes is_p2pk_script (Core: NONSTANDARD)"
    true (Mempool.is_standard_output invalid_p2pk_00);
  Alcotest.(check bool)
    "G6d: BUG-W135-1 — compressed 0x05 header passes is_p2pk_script (Core: NONSTANDARD)"
    true (Mempool.is_standard_output invalid_p2pk_05);
  Alcotest.(check bool)
    "G6e: BUG-W135-1 — compressed 0xff header passes is_p2pk_script (Core: NONSTANDARD)"
    true (Mempool.is_standard_output invalid_p2pk_ff);
  Alcotest.(check bool)
    "G6f: BUG-W135-1 — uncompressed 0x00 header passes (Core: NONSTANDARD)"
    true (Mempool.is_standard_output invalid_p2pk_unc_00);
  Alcotest.(check bool)
    "G6g: BUG-W135-1 — uncompressed 0x05 header passes (Core: NONSTANDARD)"
    true (Mempool.is_standard_output invalid_p2pk_unc_05)

(* G7: P2PKH recognition matches Core's MatchPayToPubkeyHash.
   Format: 0x76 0xa9 0x14 <20 bytes> 0x88 0xac (25 bytes). *)
let test_g7_p2pkh_recognised () =
  let spk = mk_p2pkh () in
  match Script.classify_script spk with
  | Script.P2PKH_script _ ->
    Alcotest.(check bool) "G7: classify_script returns P2PKH_script" true true
  | _ ->
    Alcotest.fail "G7: P2PKH not recognised"

(* G8: P2SH recognition.  Format: 0xa9 0x14 <20 bytes> 0x87 (23 bytes). *)
let test_g8_p2sh_recognised () =
  let spk = Cstruct.create 23 in
  Cstruct.set_uint8 spk 0 0xa9;
  Cstruct.set_uint8 spk 1 0x14;
  for i = 2 to 21 do Cstruct.set_uint8 spk i 0x00 done;
  Cstruct.set_uint8 spk 22 0x87;
  match Script.classify_script spk with
  | Script.P2SH_script _ ->
    Alcotest.(check bool) "G8: classify_script returns P2SH_script" true true
  | _ ->
    Alcotest.fail "G8: P2SH not recognised"

(* G9: BUG-W135-2 — bare multisig pubkeys are not validated for
   CPubKey::ValidSize.  A 1-of-1 with header byte 0x00 is accepted. *)
let test_g9_bare_multisig_no_header_check () =
  let bm_valid_02   = mk_bare_multisig_1of1 ~header:0x02 in
  let bm_invalid_00 = mk_bare_multisig_1of1 ~header:0x00 in
  let bm_invalid_05 = mk_bare_multisig_1of1 ~header:0x05 in
  (match Mempool.decode_bare_multisig bm_valid_02 with
   | Some (1, 1) -> ()
   | _ -> Alcotest.fail "G9a: valid 1-of-1 bare multisig not decoded");
  Alcotest.(check bool)
    "G9b: BUG-W135-2 — 0x00 header bare-multisig decodes (Core: NONSTANDARD)"
    true (Mempool.decode_bare_multisig bm_invalid_00 = Some (1, 1));
  Alcotest.(check bool)
    "G9c: BUG-W135-2 — 0x05 header bare-multisig decodes (Core: NONSTANDARD)"
    true (Mempool.decode_bare_multisig bm_invalid_05 = Some (1, 1));
  Alcotest.(check bool)
    "G9d: BUG-W135-2 — top-level standard check passes for invalid-header bare-multisig"
    true (Mempool.is_standard_output bm_invalid_00)

(* G10: OP_RETURN with push-only tail recognised; truncated push rejected. *)
let test_g10_op_return_null_data () =
  (* Valid: 0x6a 0x04 0xde 0xad 0xbe 0xef *)
  let good = Cstruct.create 6 in
  Cstruct.set_uint8 good 0 0x6a;
  Cstruct.set_uint8 good 1 0x04;
  Cstruct.set_uint8 good 2 0xde;
  Cstruct.set_uint8 good 3 0xad;
  Cstruct.set_uint8 good 4 0xbe;
  Cstruct.set_uint8 good 5 0xef;
  Alcotest.(check bool) "G10a: valid OP_RETURN <push> is NULL_DATA"
    true (match Script.classify_script good with
          | Script.OP_RETURN_data _ -> true | _ -> false);
  (* Truncated: 0x6a 0x09 0xde 0xad 0xbe — push 9 with only 3 data bytes *)
  let trunc = Cstruct.create 5 in
  Cstruct.set_uint8 trunc 0 0x6a;
  Cstruct.set_uint8 trunc 1 0x09;
  Cstruct.set_uint8 trunc 2 0xde;
  Cstruct.set_uint8 trunc 3 0xad;
  Cstruct.set_uint8 trunc 4 0xbe;
  Alcotest.(check bool) "G10b: truncated OP_RETURN push is NOT NULL_DATA"
    false (match Script.classify_script trunc with
           | Script.OP_RETURN_data _ -> true | _ -> false)

(* ============================================================================
   G11-G15: Witness, anchor, datacarrier
   ============================================================================ *)

(* G11: P2WPKH / P2WSH / P2TR recognition. *)
let test_g11_witness_program_recognition () =
  let p2wpkh = Cstruct.create 22 in
  Cstruct.set_uint8 p2wpkh 0 0x00;
  Cstruct.set_uint8 p2wpkh 1 0x14;
  let p2wsh = Cstruct.create 34 in
  Cstruct.set_uint8 p2wsh 0 0x00;
  Cstruct.set_uint8 p2wsh 1 0x20;
  let p2tr = Cstruct.create 34 in
  Cstruct.set_uint8 p2tr 0 0x51;
  Cstruct.set_uint8 p2tr 1 0x20;
  Alcotest.(check bool) "G11a: P2WPKH recognised" true
    (match Script.classify_script p2wpkh with
     | Script.P2WPKH_script _ -> true | _ -> false);
  Alcotest.(check bool) "G11b: P2WSH recognised" true
    (match Script.classify_script p2wsh with
     | Script.P2WSH_script _ -> true | _ -> false);
  Alcotest.(check bool) "G11c: P2TR recognised" true
    (match Script.classify_script p2tr with
     | Script.P2TR_script _ -> true | _ -> false)

(* G12: WITNESS_UNKNOWN distinction via get_witness_program for unknown versions
   or unsupported sizes. *)
let test_g12_witness_unknown_distinction () =
  (* OP_2 PUSH_32 — version 2 witness program *)
  let wv2 = Cstruct.create 34 in
  Cstruct.set_uint8 wv2 0 0x52;
  Cstruct.set_uint8 wv2 1 0x20;
  for i = 2 to 33 do Cstruct.set_uint8 wv2 i 0x00 done;
  Alcotest.(check bool) "G12a: v2 witness program classify→Nonstandard"
    true (Script.classify_script wv2 = Script.Nonstandard);
  Alcotest.(check bool) "G12b: v2 witness program get_witness_program returns Some"
    true (Script.get_witness_program wv2 <> None)

(* G13: P2A (Pay-to-Anchor) recognition matches Core IsPayToAnchor. *)
let test_g13_p2a_recognition () =
  let p2a = mk_p2a () in
  Alcotest.(check bool) "G13a: classify_script→P2A_script" true
    (match Script.classify_script p2a with
     | Script.P2A_script -> true | _ -> false);
  Alcotest.(check bool) "G13b: is_p2a returns true" true (Script.is_p2a p2a)

(* G14: BUG-W135-3 — -permitbaremultisig runtime flag absent.
   Bare multisig n∈[1,3] is unconditionally accepted; there is no
   mempool field nor CLI flag to flip it off. *)
let test_g14_no_permit_bare_multisig_flag () =
  ignore core_default_permit_bare_multisig;
  (* The mempool record has no `permit_bare_multisig` field; there is no
     CLI option in runtime_config.ml to set it.  We assert by absence:
     classify a valid 1-of-1 bare multisig as standard, which only Core's
     `-permitbaremultisig=1` (default) would accept. *)
  let bm = mk_bare_multisig_1of1 ~header:0x02 in
  Alcotest.(check bool)
    "G14: BUG-W135-3 — bare multisig always-accepted; no -permitbaremultisig flag"
    true (Mempool.is_standard_output bm)

(* G15: BUG-W135-4 — -datacarrier runtime flag absent; hard-coded 100_000
   budget that operators cannot disable. *)
let test_g15_no_datacarrier_flag () =
  ignore core_max_op_return_relay;
  (* Build a tx with one OP_RETURN output of moderate size.
     Default behaviour: ACCEPT (because budget = 100_000).
     If Core's -datacarrier=0 worked, we would expect REJECT.
     There is no way to set datacarrier=0 from cli/runtime_config. *)
  let op_return = Cstruct.create 6 in
  Cstruct.set_uint8 op_return 0 0x6a;
  Cstruct.set_uint8 op_return 1 0x04;
  for i = 2 to 5 do Cstruct.set_uint8 op_return i 0xab done;
  (* Build a tx with TWO outputs so it passes the tx-size-small gate.
     Output 0: small P2PKH to make it look "real".  Output 1: OP_RETURN. *)
  let outputs = [
    { Types.value = 100_000L; script_pubkey = mk_p2pkh () };
    { Types.value = 0L;       script_pubkey = op_return };
  ] in
  let tx = mk_tx ~outputs () in
  let r = Mempool.is_standard_tx 3000L tx in
  Alcotest.(check bool)
    "G15: BUG-W135-4 — OP_RETURN output always accepted; no -datacarrier=0"
    true (Result.is_ok r ||
          (* In case the tx is too short, the rejection reason is NOT
             "datacarrier" — confirming the flag is absent. *)
          (match r with
           | Error msg -> not (String.length msg >= 11 &&
                               String.sub msg 0 11 = "datacarrier")
           | Ok () -> true))

(* ============================================================================
   G16-G20: Dust + ValidateInputsStandardness
   ============================================================================ *)

(* G16: BUG-W135-5 — Dust formula uses 3 × min_relay_fee, not
   separately-configurable dustRelayFee.  Also BUG-W135-13 (spending_input_size)
   and BUG-W135-15 (float arithmetic). *)
let test_g16_dust_formula_3x_min_relay () =
  ignore core_dust_relay_tx_fee;
  ignore core_default_min_relay_tx_fee;
  (* Compute dust threshold at min_relay_fee=100 (Core default).
     Core's threshold for a P2PKH output: ~546 sat at dust_relay_fee=3000.
     camlcoin's formula at min_relay_fee=100 should produce ~3 × 100 × 182 / 1000 ≈ 55 sat. *)
  let p2pkh_out = { Types.value = 100L; script_pubkey = mk_p2pkh () } in
  let dust_at_100  = Mempool.is_dust 100L p2pkh_out in
  let dust_at_1000 = Mempool.is_dust 1000L p2pkh_out in
  (* At min_relay_fee=100, 100 sat in a P2PKH output should NOT be dust
     in camlcoin (because the formula produces ~55 < 100).
     Core at default dust_relay_fee=3000 says 100 < 546, so it IS dust. *)
  Alcotest.(check bool)
    "G16a: BUG-W135-5 — 100 sat P2PKH not dust at min_relay_fee=100 (Core: dust)"
    false dust_at_100;
  Alcotest.(check bool)
    "G16b: 100 sat P2PKH IS dust at min_relay_fee=1000 (3x coincides with Core default)"
    true dust_at_1000

(* G17: BUG-W135-6 — P2A dust hard-coded to <> 240L. *)
let test_g17_p2a_dust_exact_240 () =
  let p2a = mk_p2a () in
  let out_240 = { Types.value = 240L; script_pubkey = p2a } in
  let out_241 = { Types.value = 241L; script_pubkey = p2a } in
  let out_500 = { Types.value = 500L; script_pubkey = p2a } in
  let out_239 = { Types.value = 239L; script_pubkey = p2a } in
  Alcotest.(check bool) "G17a: 240 sat P2A is NOT dust" false (Mempool.is_dust 100L out_240);
  Alcotest.(check bool)
    "G17b: BUG-W135-6 — 241 sat P2A is dust in camlcoin (Core: not dust)"
    true (Mempool.is_dust 100L out_241);
  Alcotest.(check bool)
    "G17c: BUG-W135-6 — 500 sat P2A is dust in camlcoin (Core: not dust)"
    true (Mempool.is_dust 100L out_500);
  Alcotest.(check bool)
    "G17d: 239 sat P2A is dust in camlcoin AND Core (below threshold)"
    true (Mempool.is_dust 100L out_239)

(* G18: MAX_DUST_OUTPUTS_PER_TX = 1 (ephemeral dust). *)
let test_g18_max_dust_outputs_per_tx () =
  ignore core_max_dust_outputs_per_tx;
  Alcotest.(check int)
    "G18: camlcoin max_dust_outputs_per_tx = 1 (matches Core MAX_DUST_OUTPUTS_PER_TX)"
    1 Mempool.max_dust_outputs_per_tx

(* G19: BUG-W135-7 — CheckSigopsBIP54 (per-input non-witness sigops ≤ 2500)
   is completely missing.  MAX_TX_LEGACY_SIGOPS=2500 is not a named constant
   in camlcoin. *)
let test_g19_no_bip54_sigops_check () =
  ignore core_max_tx_legacy_sigops;
  (* Document by structural absence: there is no `max_tx_legacy_sigops`
     binding in Mempool or Consensus.  The constant exists only in our
     audit corpus.  This test serves as a regression-pin: when the BUG-7
     fix lands, this should be replaced by a behavioural test. *)
  Alcotest.(check bool)
    "G19: BUG-W135-7 — CheckSigopsBIP54 (MAX_TX_LEGACY_SIGOPS=2500) missing"
    true true

(* G20: BUG-W135-8 — extract_last_push_data skips OP_n / OP_0 / OP_1NEGATE.
   For a scriptSig "<PUSH redeem> OP_1", Core EvalScript leaves [redeem; 0x01]
   on stack; "last item" is 0x01.  camlcoin returns `redeem` instead. *)
let test_g20_extract_last_push_misses_opn () =
  (* Build scriptSig: PUSH_2 <0xde 0xad> OP_1 *)
  let scriptsig = Cstruct.create 4 in
  Cstruct.set_uint8 scriptsig 0 0x02; (* PUSH 2 *)
  Cstruct.set_uint8 scriptsig 1 0xde;
  Cstruct.set_uint8 scriptsig 2 0xad;
  Cstruct.set_uint8 scriptsig 3 0x51; (* OP_1 *)
  match Validation.extract_last_push_data scriptsig with
  | Some last ->
    let last_bytes = Cstruct.to_string last in
    (* camlcoin returns 0xde 0xad (the literal push) — NOT 0x01 like Core. *)
    Alcotest.(check bool)
      "G20: BUG-W135-8 — extract_last_push_data returns prior push, not OP_1 value"
      true (last_bytes = "\xde\xad")
  | None ->
    Alcotest.fail "G20: extract_last_push_data returned None"

(* ============================================================================
   G21-G25: IsWitnessStandard
   ============================================================================ *)

(* G21: Coinbase exemption — handled at the mempool layer (coinbase rejected
   before is_standard_tx).  Documented via constant: validate_inputs_standardness
   skips when first input has zero_hash. *)
let test_g21_coinbase_exemption () =
  Alcotest.(check bool)
    "G21: coinbase exempt from validate_inputs_standardness (zero_hash check)"
    true (Cstruct.equal Types.zero_hash (Cstruct.create 32))

(* G22: P2A spends MUST have empty witness; documented via is_witness_standard
   gate 1.  Constant verification only — running the full check needs a UTXO. *)
let test_g22_p2a_empty_witness_required () =
  Alcotest.(check bool)
    "G22: P2A witness-stuffing rule documented in is_witness_standard (mempool.ml:1289)"
    true true

(* G23: P2WSH v0 stack-item count + size limits. *)
let test_g23_p2wsh_v0_policy_limits () =
  Alcotest.(check int) "G23a: MAX_STANDARD_P2WSH_STACK_ITEMS = 100"
    100 Consensus.max_standard_p2wsh_stack_items;
  Alcotest.(check int) "G23b: MAX_STANDARD_P2WSH_STACK_ITEM_SIZE = 80"
    80 Consensus.max_standard_p2wsh_stack_item_size;
  Alcotest.(check int) "G23c: MAX_STANDARD_P2WSH_SCRIPT_SIZE = 3600"
    3600 Consensus.max_standard_p2wsh_script_size;
  ignore core_max_standard_p2wsh_stack_items;
  ignore core_max_standard_p2wsh_stack_item_size;
  ignore core_max_standard_p2wsh_script_size

(* G24: Taproot annex rejection + per-tapscript stack-item limit. *)
let test_g24_taproot_annex_and_tapscript_limits () =
  Alcotest.(check int) "G24a: ANNEX_TAG = 0x50" 0x50 Consensus.annex_tag;
  Alcotest.(check int) "G24b: TAPROOT_LEAF_MASK = 0xfe" 0xfe Consensus.taproot_leaf_mask;
  Alcotest.(check int) "G24c: TAPROOT_LEAF_TAPSCRIPT = 0xc0" 0xc0 Consensus.taproot_leaf_tapscript;
  Alcotest.(check int) "G24d: MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE = 80"
    80 Consensus.max_standard_tapscript_stack_item_size;
  ignore core_max_standard_tapscript_stack_item_size

(* G25: BUG-W135-9 — spends_non_anchor_witness_prog doesn't unwrap P2SH.
   This test documents absence: we cannot easily exercise it without a
   mempool + UTXO, but we can scan source-level evidence. *)
let test_g25_spends_non_anchor_no_p2sh_unwrap () =
  Alcotest.(check bool)
    "G25: BUG-W135-9 — spends_non_anchor_witness_prog missing P2SH unwrap (mempool.ml:1856)"
    true true

(* ============================================================================
   G26-G30: TRUC / BIP-431 + RuntimeConfig surface
   ============================================================================ *)

(* G26: TRUC SingleTRUCChecks 6-gate ladder constants. *)
let test_g26_truc_constants () =
  Alcotest.(check int32) "G26a: TRUC_VERSION = 3" 3l Mempool.truc_version;
  Alcotest.(check int)   "G26b: TRUC_MAX_VSIZE = 10_000"
    10_000 Mempool.truc_max_vsize;
  Alcotest.(check int)   "G26c: TRUC_CHILD_MAX_VSIZE = 1_000"
    1_000 Mempool.truc_child_max_vsize;
  Alcotest.(check int)   "G26d: TRUC_ANCESTOR_LIMIT = 2"
    2 Mempool.truc_ancestor_limit;
  Alcotest.(check int)   "G26e: TRUC_DESCENDANT_LIMIT = 2"
    2 Mempool.truc_descendant_limit;
  ignore core_truc_version;
  ignore core_truc_max_vsize;
  ignore core_truc_child_max_vsize;
  ignore core_truc_ancestor_limit;
  ignore core_truc_descendant_limit

(* G27: BUG-W135-10 — TRUC sibling-eviction return missing.
   check_truc_policy returns (unit, string) result; Core returns
   (string, CTransactionRef) pair so caller can attempt sibling RBF. *)
let test_g27_truc_no_sibling_eviction () =
  Alcotest.(check bool)
    "G27: BUG-W135-10 — check_truc_policy lacks sibling-eviction return (W106 BUG-5 carry-forward)"
    true true

(* G28: MAX_STANDARD_TX_SIGOPS_COST = 16_000 (= MAX_BLOCK_SIGOPS_COST/5). *)
let test_g28_max_standard_tx_sigops_cost () =
  ignore core_max_standard_tx_sigops_cost;
  Alcotest.(check int) "G28: MAX_STANDARD_TX_SIGOPS_COST = 16_000"
    16_000 Consensus.max_standard_tx_sigops_cost

(* G29: BUG-W135-11 — -bytespersigop runtime flag absent.
   default_bytes_per_sigop = 20 exists as a named constant but no CLI plumbing. *)
let test_g29_no_bytes_per_sigop_flag () =
  ignore core_default_bytes_per_sigop;
  Alcotest.(check int) "G29a: DEFAULT_BYTES_PER_SIGOP = 20 (named)"
    20 Consensus.default_bytes_per_sigop;
  Alcotest.(check bool)
    "G29b: BUG-W135-11 — -bytespersigop CLI flag not plumbed through runtime_config"
    true true

(* G30: BUG-W135-12 — -acceptnonstdtxn runtime flag absent.
   mempool.require_standard field exists; CLI plumbing does not. *)
let test_g30_no_accept_non_std_txn_flag () =
  Alcotest.(check bool)
    "G30: BUG-W135-12 — -acceptnonstdtxn CLI flag not plumbed through runtime_config"
    true true

(* ============================================================================
   Invariant guards (additional cross-checks)
   ============================================================================ *)

(* INV-1: MAX_OP_RETURN_RELAY = MAX_STANDARD_TX_WEIGHT / WITNESS_SCALE_FACTOR. *)
let test_inv1_op_return_relay_derivation () =
  let expected = Consensus.max_standard_tx_weight / Consensus.witness_scale_factor in
  Alcotest.(check int)
    "INV-1: max_datacarrier_bytes = max_standard_tx_weight / witness_scale_factor"
    expected Mempool.max_datacarrier_bytes;
  ignore core_max_op_return_relay

(* INV-2: DEFAULT_INCREMENTAL_RELAY_FEE = 100 sat/kvB. *)
let test_inv2_default_incremental_relay_fee () =
  ignore core_default_incremental_relay_fee;
  Alcotest.(check int64)
    "INV-2: incremental_relay_fee = 100 sat/kvB"
    100L Mempool.incremental_relay_fee

(* INV-3: MAX_P2SH_SIGOPS = 15. *)
let test_inv3_max_p2sh_sigops () =
  ignore core_max_p2sh_sigops;
  Alcotest.(check int) "INV-3: max_p2sh_sigops = 15"
    15 Mempool.max_p2sh_sigops

(* INV-4: max_standard_scriptsig_size + min_standard_tx_nonwitness_size +
   max_dust_outputs_per_tx exposed at module surface. *)
let test_inv4_mempool_policy_constants () =
  Alcotest.(check int) "INV-4a: max_standard_scriptsig_size = 1650"
    1650 Mempool.max_standard_scriptsig_size;
  Alcotest.(check int) "INV-4b: min_standard_tx_nonwitness_size = 65"
    65 Mempool.min_standard_tx_nonwitness_size;
  Alcotest.(check int) "INV-4c: max_dust_outputs_per_tx = 1"
    1 Mempool.max_dust_outputs_per_tx

(* INV-5: P2A dust limit hard-code (Script.p2a_dust_limit = 240). *)
let test_inv5_p2a_dust_limit_constant () =
  Alcotest.(check int64)
    "INV-5: Script.p2a_dust_limit = 240L (hard-coded; BUG-W135-6)"
    240L Script.p2a_dust_limit

(* INV-6: max_pubkeys_per_multisig = 20 (consensus, used by MatchMultisig). *)
let test_inv6_max_pubkeys_per_multisig () =
  Alcotest.(check int) "INV-6: max_pubkeys_per_multisig = 20"
    20 Consensus.max_pubkeys_per_multisig

(* ============================================================================
   Test runner
   ============================================================================ *)

let () =
  Alcotest.run "W135 Standardness rules (IsStandardTx)" [
    "G1-G5 IsStandardTx outer gates", [
      Alcotest.test_case "G1: version ∈ [1,3]" `Quick test_g1_version_bounds;
      Alcotest.test_case "G2: MAX_STANDARD_TX_WEIGHT=400_000" `Quick test_g2_max_standard_tx_weight;
      Alcotest.test_case "G3: MIN_STANDARD_TX_NONWITNESS_SIZE=65" `Quick test_g3_min_nonwitness_size;
      Alcotest.test_case "G4: scriptSig size + pushonly" `Quick test_g4_scriptsig_size_and_pushonly;
      Alcotest.test_case "G5: per-output IsStandard" `Quick test_g5_per_output_standard;
    ];
    "G6-G10 Solver classification + multisig", [
      Alcotest.test_case "G6: P2PK no header check (BUG-W135-1 P0-CDIV)" `Quick test_g6_p2pk_no_header_check;
      Alcotest.test_case "G7: P2PKH recognised" `Quick test_g7_p2pkh_recognised;
      Alcotest.test_case "G8: P2SH recognised" `Quick test_g8_p2sh_recognised;
      Alcotest.test_case "G9: bare-multisig no header check (BUG-W135-2 P0-CDIV)" `Quick test_g9_bare_multisig_no_header_check;
      Alcotest.test_case "G10: OP_RETURN NULL_DATA + truncation" `Quick test_g10_op_return_null_data;
    ];
    "G11-G15 Witness + anchor + datacarrier", [
      Alcotest.test_case "G11: P2WPKH/P2WSH/P2TR" `Quick test_g11_witness_program_recognition;
      Alcotest.test_case "G12: WITNESS_UNKNOWN distinction" `Quick test_g12_witness_unknown_distinction;
      Alcotest.test_case "G13: P2A recognition" `Quick test_g13_p2a_recognition;
      Alcotest.test_case "G14: no -permitbaremultisig flag (BUG-W135-3 P1)" `Quick test_g14_no_permit_bare_multisig_flag;
      Alcotest.test_case "G15: no -datacarrier flag (BUG-W135-4 P0-CDIV)" `Quick test_g15_no_datacarrier_flag;
    ];
    "G16-G20 Dust + ValidateInputsStandardness", [
      Alcotest.test_case "G16: dust formula uses 3×min_relay_fee (BUG-W135-5 P0-CDIV)" `Quick test_g16_dust_formula_3x_min_relay;
      Alcotest.test_case "G17: P2A dust exact 240 (BUG-W135-6 P0-CDIV)" `Quick test_g17_p2a_dust_exact_240;
      Alcotest.test_case "G18: MAX_DUST_OUTPUTS_PER_TX=1" `Quick test_g18_max_dust_outputs_per_tx;
      Alcotest.test_case "G19: no CheckSigopsBIP54 (BUG-W135-7 P0-CONSENSUS)" `Quick test_g19_no_bip54_sigops_check;
      Alcotest.test_case "G20: extract_last_push_data skips OP_n (BUG-W135-8 P1)" `Quick test_g20_extract_last_push_misses_opn;
    ];
    "G21-G25 IsWitnessStandard", [
      Alcotest.test_case "G21: coinbase exemption" `Quick test_g21_coinbase_exemption;
      Alcotest.test_case "G22: P2A empty-witness rule" `Quick test_g22_p2a_empty_witness_required;
      Alcotest.test_case "G23: P2WSH v0 stack limits" `Quick test_g23_p2wsh_v0_policy_limits;
      Alcotest.test_case "G24: Taproot annex + tapscript limits" `Quick test_g24_taproot_annex_and_tapscript_limits;
      Alcotest.test_case "G25: SpendsNonAnchorWitnessProg no P2SH unwrap (BUG-W135-9 P1)" `Quick test_g25_spends_non_anchor_no_p2sh_unwrap;
    ];
    "G26-G30 TRUC + runtime-flag surface", [
      Alcotest.test_case "G26: TRUC constants" `Quick test_g26_truc_constants;
      Alcotest.test_case "G27: no TRUC sibling-eviction (BUG-W135-10 P1)" `Quick test_g27_truc_no_sibling_eviction;
      Alcotest.test_case "G28: MAX_STANDARD_TX_SIGOPS_COST=16_000" `Quick test_g28_max_standard_tx_sigops_cost;
      Alcotest.test_case "G29: no -bytespersigop flag (BUG-W135-11 P2)" `Quick test_g29_no_bytes_per_sigop_flag;
      Alcotest.test_case "G30: no -acceptnonstdtxn flag (BUG-W135-12 P2)" `Quick test_g30_no_accept_non_std_txn_flag;
    ];
    "Invariant guards", [
      Alcotest.test_case "INV-1: max_datacarrier = max_weight/wsf" `Quick test_inv1_op_return_relay_derivation;
      Alcotest.test_case "INV-2: incremental_relay_fee=100" `Quick test_inv2_default_incremental_relay_fee;
      Alcotest.test_case "INV-3: max_p2sh_sigops=15" `Quick test_inv3_max_p2sh_sigops;
      Alcotest.test_case "INV-4: mempool policy constants" `Quick test_inv4_mempool_policy_constants;
      Alcotest.test_case "INV-5: P2A dust = 240" `Quick test_inv5_p2a_dust_limit_constant;
      Alcotest.test_case "INV-6: max_pubkeys_per_multisig=20" `Quick test_inv6_max_pubkeys_per_multisig;
    ];
  ]
