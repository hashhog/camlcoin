(* verify-neon-camlcoin-findings, script-flag group (Neon audit 2026-11-24,
   findings 6, 7, 8 and 9; camlcoin 482c676).

   Each case is one input checked with [Script.verify_script] under the flags
   named in the case, and the expected answer is Core v31.1's
   (src/script/interpreter.cpp, src/pubkey.cpp):

   F6  OP_CHECKMULTISIG: Core runs CheckSignatureEncoding AND
       CheckPubKeyEncoding on every (sig, key) pair it tries, also when the
       signature is empty:
         while (fSuccess && nSigsCount > 0) {
           if (!CheckSignatureEncoding(vchSig, ...) ||
               !CheckPubKeyEncoding(vchPubKey, flags, sigversion, serror))
             return false;
           ...
       camlcoin returned "false" for an empty signature before looking at any
       key, so STRICTENC / WITNESS_PUBKEYTYPE never fired.

   F7  OP_CHECKSIGADD: "const CScriptNum num(stacktop(-2), fRequireMinimal);"
       camlcoin parsed n without require_minimal, so a non-minimal n passed
       under MINIMALDATA.

   F8  OP_CHECKLOCKTIMEVERIFY / OP_CHECKSEQUENCEVERIFY with their flag unset:
         if (!(flags & SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY)) break;  // NOP2
       Core does not consult DISCOURAGE_UPGRADABLE_NOPS for them (only for
       NOP1, NOP4..NOP10).  camlcoin failed "Upgradable NOP used".

   F9  LOW_S: IsLowDERSignature -> CPubKey::CheckLowS parses with
       ecdsa_signature_parse_der_lax, which zeroes the WHOLE signature when R
       or S overflows, so a strict-DER signature with R >= N passes the low-S
       check.  camlcoin used the strict parser, which zeroes only R and keeps
       a high S, so it failed "Non-low-S signature".

   The controls pin that nothing that Core rejects became accepted: a bad key
   that Core never reaches stays accepted, valid keys stay accepted, a
   non-minimal n stays accepted without MINIMALDATA, NOP1 stays discouraged,
   an enabled CLTV still checks the locktime, and an ordinary high-S
   signature still fails LOW_S. *)

open Camlcoin

let hex s =
  let n = String.length s / 2 in
  let c = Cstruct.create n in
  for i = 0 to n - 1 do
    Cstruct.set_uint8 c i (int_of_string ("0x" ^ String.sub s (2 * i) 2))
  done;
  c

let byte n = Cstruct.of_string (String.make 1 (Char.chr n))

let push (d : Cstruct.t) =
  let n = Cstruct.length d in
  if n < 0x4c then Cstruct.append (byte n) d
  else Cstruct.concat [ byte 0x4c; byte n; d ]

let crediting_tx spk : Types.transaction =
  { version = 1l;
    inputs = [ { previous_output = { txid = Cstruct.create 32; vout = 0xFFFFFFFFl };
                 script_sig = hex "0000"; sequence = 0xFFFFFFFFl } ];
    outputs = [ { value = 1000L; script_pubkey = spk } ];
    witnesses = []; locktime = 0l }

let spending_tx ?(sequence = 0xFFFFFFFEl) ?(locktime = 0l) ~spk ~script_sig ~wit ()
  : Types.transaction =
  let credit = crediting_tx spk in
  { version = 2l;
    inputs = [ { previous_output = { txid = Crypto.compute_txid credit; vout = 0l };
                 script_sig; sequence } ];
    outputs = [ { value = 1000L; script_pubkey = Cstruct.empty } ];
    witnesses = (if wit = [] then [] else [ Types.{ items = wit } ]); locktime }

let verify ?sequence ?locktime ~flags ~spk ~script_sig ~wit () =
  let tx = spending_tx ?sequence ?locktime ~spk ~script_sig ~wit () in
  let witness = match tx.witnesses with w :: _ -> w | [] -> Types.{ items = [] } in
  Script.verify_script ~tx ~input_index:0 ~script_pubkey:spk
    ~script_sig ~witness ~amount:1000L ~flags
    ~prevouts:[ (1000L, spk) ] ()

let show = function
  | Ok b -> Printf.sprintf "Ok %b" b
  | Error e -> "Error " ^ e

let must_accept name f () =
  let r = f () in
  Printf.printf "%s -> %s\n%!" name (show r);
  Alcotest.(check string) (name ^ ": Core accepts") "Ok true" (show r)

let must_reject name f () =
  let r = f () in
  Printf.printf "%s -> %s\n%!" name (show r);
  Alcotest.(check bool) (name ^ ": Core rejects, node must not accept")
    false (r = Ok true)

(* ---- keys ---- *)
let g_compressed =
  hex "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
let g_uncompressed =
  hex ("0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
       ^ "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
(* 33 bytes, prefix 0x05: neither compressed nor uncompressed (STRICTENC) *)
let bad_prefix_key =
  hex "0579be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

let op_0 = byte 0x00
let op_checkmultisig = byte 0xae
let op_not = byte 0x91

let base_flags = Script.script_verify_p2sh lor Script.script_verify_witness
let strictenc = base_flags lor Script.script_verify_strictenc
let wpkt = base_flags lor Script.script_verify_witness_pubkeytype

(* "<dummy> <sigs...> m <keys...> n CHECKMULTISIG NOT", every sig empty.
   Keys are listed in push order; Core tries the LAST pushed key first. *)
let multisig_not ~m ~keys =
  let sigs = List.init m (fun _ -> op_0) in
  Cstruct.concat
    ([ op_0 ] @ sigs @ [ byte (0x50 + m) ] @ List.map push keys
     @ [ byte (0x50 + List.length keys); op_checkmultisig; op_not ])

(* bare script: everything in the scriptPubKey, empty scriptSig *)
let bare ~flags script () = verify ~flags ~spk:script ~script_sig:Cstruct.empty ~wit:[] ()

(* P2WSH: witness = [witnessScript] *)
let p2wsh ~flags script () =
  let spk = Cstruct.append (hex "0020") (Crypto.sha256 script) in
  verify ~flags ~spk ~script_sig:Cstruct.empty ~wit:[ script ] ()

let f6_cases = [
  (* Core: empty sig vs the uncompressed key -> CheckPubKeyEncoding ->
     WITNESS_PUBKEYTYPE. *)
  `Reject, "p2wsh_1of1_uncompressed_witness_pubkeytype",
    p2wsh ~flags:wpkt (multisig_not ~m:1 ~keys:[ g_uncompressed ]);
  (* Core: bad prefix key -> STRICTENC PUBKEYTYPE. *)
  `Reject, "bare_1of1_badprefix_strictenc",
    bare ~flags:strictenc (multisig_not ~m:1 ~keys:[ bad_prefix_key ]);
  (* 1-of-2, bad key pushed first: Core tries the good key, then (1 sig, 1
     key left) the bad key -> PUBKEYTYPE. *)
  `Reject, "bare_1of2_badkey_tried_second_strictenc",
    bare ~flags:strictenc (multisig_not ~m:1 ~keys:[ bad_prefix_key; g_compressed ]);
  (* 2-of-2, bad key pushed last: the first key Core tries -> PUBKEYTYPE. *)
  `Reject, "bare_2of2_badkey_tried_first_strictenc",
    bare ~flags:strictenc (multisig_not ~m:2 ~keys:[ g_compressed; bad_prefix_key ]);
  (* controls *)
  (* 2-of-2, bad key pushed first: after the first empty sig fails, 2 sigs
     > 1 key left, so Core stops before ever reaching the bad key. *)
  `Accept, "control_2of2_badkey_never_reached_strictenc",
    bare ~flags:strictenc (multisig_not ~m:2 ~keys:[ bad_prefix_key; g_compressed ]);
  `Accept, "control_p2wsh_1of1_compressed_witness_pubkeytype",
    p2wsh ~flags:wpkt (multisig_not ~m:1 ~keys:[ g_compressed ]);
  `Accept, "control_bare_1of1_uncompressed_strictenc",
    bare ~flags:strictenc (multisig_not ~m:1 ~keys:[ g_uncompressed ]);
  `Accept, "control_bare_1of1_badprefix_no_strictenc",
    bare ~flags:base_flags (multisig_not ~m:1 ~keys:[ bad_prefix_key ]);
]

(* ---- F7: tapscript "<pk> CHECKSIGADD 0 EQUAL", witness [sig="" ; n] ---- *)
let internal_key =
  hex "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"

let tapscript_spend ~flags ~n () =
  let leaf = Cstruct.concat [ push (Cstruct.sub g_compressed 1 32); byte 0xba;
                              op_0; byte 0x87 ] in
  let leaf_hash = Crypto.compute_tapleaf_hash 0xc0 leaf in
  let (out_key, parity) =
    Crypto.compute_taproot_output_key_with_parity internal_key (Some leaf_hash) in
  let control = Cstruct.append (byte (0xc0 lor parity)) internal_key in
  let spk = Cstruct.append (hex "5120") out_key in
  verify ~flags ~spk ~script_sig:Cstruct.empty
    ~wit:[ Cstruct.empty; n; leaf; control ] ()

let tap_flags = base_flags lor Script.script_verify_taproot
let tap_minimal = tap_flags lor Script.script_verify_minimaldata

let f7_cases = [
  `Reject, "checksigadd_n_0x00_minimaldata",
    tapscript_spend ~flags:tap_minimal ~n:(hex "00");
  `Reject, "checksigadd_n_0x0080_minimaldata",
    tapscript_spend ~flags:tap_minimal ~n:(hex "0080");
  (* controls *)
  `Accept, "control_checksigadd_n_empty_minimaldata",
    tapscript_spend ~flags:tap_minimal ~n:Cstruct.empty;
  `Accept, "control_checksigadd_n_0x00_no_minimaldata",
    tapscript_spend ~flags:tap_flags ~n:(hex "00");
]

(* ---- F8: disabled CLTV / CSV are plain NOPs, even with DISCOURAGE ---- *)
let discourage = Script.script_verify_discourage_upgradable_nops

let f8_cases = [
  `Accept, "cltv_disabled_discourage_nops",
    bare ~flags:discourage (hex "51b1");
  `Accept, "csv_disabled_discourage_nops",
    bare ~flags:discourage (hex "51b2");
  (* controls *)
  `Reject, "control_nop1_discourage_nops",
    bare ~flags:discourage (hex "51b0");
  `Reject, "control_nop10_discourage_nops",
    bare ~flags:discourage (hex "51b9");
  (* CLTV enabled: locktime 10 > tx locktime 0 -> UNSATISFIED_LOCKTIME *)
  `Reject, "control_cltv_enabled_unsatisfied",
    bare ~flags:(discourage lor Script.script_verify_checklocktimeverify) (hex "5ab1");
]

(* ---- F9: LOW_S on a strict-DER signature with R = N ---- *)
let order_n = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
let high_s = "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1"
let sig_r_eq_n_high_s = hex ("3045022100" ^ order_n ^ "0220" ^ high_s ^ "01")
let sig_r_1_high_s = hex ("3025020101" ^ "0220" ^ high_s ^ "01")

(* "<sig> <pk> CHECKSIG NOT" *)
let checksig_not sig_ =
  Cstruct.concat [ push sig_; push g_compressed; byte 0xac; op_not ]

let low_s = Script.script_verify_dersig lor Script.script_verify_low_s

let f9_cases = [
  `Accept, "low_s_r_eq_n_high_s_lax_parse",
    bare ~flags:low_s (checksig_not sig_r_eq_n_high_s);
  (* controls *)
  `Reject, "control_low_s_r_1_high_s",
    bare ~flags:low_s (checksig_not sig_r_1_high_s);
  `Reject, "control_low_s_r_eq_n_nullfail",
    bare ~flags:(low_s lor Script.script_verify_nullfail) (checksig_not sig_r_eq_n_high_s);
  `Accept, "control_r_1_high_s_without_low_s",
    bare ~flags:Script.script_verify_dersig (checksig_not sig_r_1_high_s);
]

let to_tests cases =
  List.map (fun (expect, name, f) ->
    let run = match expect with
      | `Accept -> must_accept name f
      | `Reject -> must_reject name f in
    Alcotest.test_case name `Quick run) cases

let () =
  Alcotest.run "verify_neon_script_flags" [
    "f6_multisig_empty_sig_pubkey_encoding", to_tests f6_cases;
    "f7_checksigadd_minimaldata", to_tests f7_cases;
    "f8_disabled_cltv_csv_nop", to_tests f8_cases;
    "f9_low_s_lax_der", to_tests f9_cases;
  ]
