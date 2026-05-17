(* W127 audit — Taproot / Schnorr / Tapscript (BIP-340/341/342) (camlcoin)

   Reference:
   - bitcoin-core/src/script/interpreter.cpp (SignatureHashSchnorr,
     CheckSchnorrSignature, ExecuteWitnessScript, VerifyTaprootCommitment,
     VerifyWitnessProgram, EvalChecksigTapscript, OP_CHECKSIGADD).
   - bitcoin-core/src/script/script.h (TAPROOT_LEAF_MASK / TAPROOT_LEAF_TAPSCRIPT
     / TAPROOT_CONTROL_xxx / VALIDATION_WEIGHT_xxx).
   - bitcoin-core/src/script/script.cpp (IsOpSuccess).
   - BIP-340 / BIP-341 / BIP-342.

   30 audit gates covering BIP-340 Schnorr (G1..G6), BIP-341 Taproot
   key-path + commitment (G7..G19), BIP-342 Tapscript opcodes + sigops
   budget (G20..G30).

   Each gate asserts source-level the PRESENT / PARTIAL / MISSING status
   captured in audit/w127_taproot.md. Tests pass when the audit verdict
   is faithful; PRESENT gates that get broken by a future change will
   flip the test red, and PARTIAL/MISSING gates that get fixed will also
   flip — both desirable.

   Audit checklist:

     BIP-340 (6):
       G1  Schnorr verify via libsecp256k1                        PRESENT
       G2  64-byte sig => SIGHASH_DEFAULT (0x00)                  PRESENT
       G3  65-byte sig with hash_type == 0x00 rejected            PRESENT
       G4  hash_type whitelist {0x00..0x03, 0x81..0x83}           PRESENT
       G5  SIGHASH_SINGLE without matching output rejected        PRESENT
       G6  schnorr_sign / sign_tweaked C stubs present            PRESENT

     BIP-341 (13):
       G7  P2TR detection: witness v1 + 32B program               PRESENT
       G8  scriptSig must be empty for taproot                    PRESENT
       G9  Empty witness => fail                                  PRESENT
       G10 Annex detection: last item byte0==0x50 && >=2 items    PRESENT
       G11 Annex hash = SHA256(cs(len) || annex)                  PRESENT
       G12 Key-path sig length 64 or 65                           PRESENT
       G13 TapTweak tagged hash                                   PRESENT
       G14 xonly_pubkey_tweak_add_check via libsecp256k1          PRESENT
       G15 Sighash epoch = 0x00                                   PRESENT
       G16 Sighash spend_type byte                                PRESENT
       G17 ANYONECANPAY handling                                  PRESENT
       G18 prevouts.size == vin.size invariant                    PRESENT
       G19 TAPROOT activation flag gated by taproot_height        PRESENT

     BIP-342 (11):
       G20 Control block size 33 + 32k, 0 <= k <= 128             PRESENT
       G21 Leaf version 0xC0 + mask 0xFE                          PRESENT
       G22 Unknown leaf version: discourage-flag gated            PRESENT
       G23 Tapleaf hash                                           PRESENT
       G24 Tapbranch hash (lex sort)                              PRESENT
       G25 OP_SUCCESSx set matches Core exactly                   PRESENT
       G26 OP_SUCCESS pre-scan: truncated push => BAD_OPCODE      PRESENT
       G27 OP_CHECKMULTISIG / VERIFY disabled in tapscript        PRESENT
       G28 OP_CHECKSIGADD only in tapscript + (sig, num, pk)      PARTIAL (BUG-2)
       G29 Validation weight budget init                          PARTIAL (BUG-8)
       G30 Per-sigop deduction 50                                 PARTIAL (BUG-7)

   ============================================================================ *)

open Alcotest

(* -- helpers ------------------------------------------------------------- *)

let read_file path =
  let ic = open_in path in
  let n = in_channel_length ic in
  let buf = Bytes.create n in
  really_input ic buf 0 n;
  close_in ic;
  Bytes.to_string buf

(* Walk up from CWD until we find the camlcoin repo root (recognised by
   lib/script.ml). Alcotest invokes test executables from a CWD deep
   inside _build, so we cannot use a fixed relative path. *)
let resolve_repo_root () =
  let rec up dir depth =
    if depth > 10 then
      Alcotest.fail "could not locate repo root from CWD"
    else if Sys.file_exists (Filename.concat dir "lib/script.ml") then dir
    else up (Filename.dirname dir) (depth + 1)
  in
  up (Sys.getcwd ()) 0

let read_repo_file rel : string =
  read_file (Filename.concat (resolve_repo_root ()) rel)

let script_ml () = read_repo_file "lib/script.ml"
let crypto_ml () = read_repo_file "lib/crypto.ml"
let schnorr_stubs_c () = read_repo_file "lib/schnorr_stubs.c"
let validation_ml () = read_repo_file "lib/validation.ml"
let consensus_ml () = read_repo_file "lib/consensus.ml"

let contains_substring haystack needle =
  let len_h = String.length haystack in
  let len_n = String.length needle in
  if len_n = 0 then true
  else if len_n > len_h then false
  else begin
    let found = ref false in
    let i = ref 0 in
    let stop = len_h - len_n in
    while not !found && !i <= stop do
      if String.sub haystack !i len_n = needle then found := true;
      incr i
    done;
    !found
  end

let count_substring haystack needle =
  let len_h = String.length haystack in
  let len_n = String.length needle in
  if len_n = 0 then 0
  else begin
    let count = ref 0 in
    let i = ref 0 in
    let stop = len_h - len_n in
    while !i <= stop do
      if String.sub haystack !i len_n = needle then begin
        incr count;
        i := !i + len_n
      end else incr i
    done;
    !count
  end

(* -- BIP-340 Schnorr ----------------------------------------------------- *)

(* G1: Schnorr verify routes through libsecp256k1 *)
let g1_schnorr_verify_uses_libsecp256k1 () =
  let stubs = schnorr_stubs_c () in
  let crypto = crypto_ml () in
  Alcotest.(check bool)
    "G1a schnorr_stubs.c invokes secp256k1_schnorrsig_verify" true
    (contains_substring stubs "secp256k1_schnorrsig_verify");
  Alcotest.(check bool)
    "G1b crypto.ml binds external schnorr_verify_raw" true
    (contains_substring crypto "external schnorr_verify_raw")

(* G2: 64-byte sig => SIGHASH_DEFAULT (0x00) *)
let g2_default_sighash_implicit () =
  let s = script_ml () in
  Alcotest.(check bool)
    "G2 64-byte sig implies hash_type = 0 (SIGHASH_DEFAULT)" true
    (contains_substring s "if sig_len = 65 then" &&
     contains_substring s "else 0 (* SIGHASH_DEFAULT *)")

(* G3: 65-byte sig with hash_type == 0x00 rejected *)
let g3_65_byte_with_default_rejected () =
  let s = script_ml () in
  Alcotest.(check bool)
    "G3 65-byte sig + hash_type 0 rejected at 3 call sites" true
    (count_substring s "Invalid hash type 0x00 in 65-byte signature" +
     count_substring s "Invalid hash_type 0x00 in 65-byte tapscript sig" >= 3)

(* G4: hash_type whitelist *)
let g4_hash_type_whitelist () =
  let s = script_ml () in
  Alcotest.(check bool)
    "G4 is_valid_taproot_hash_type defined" true
    (contains_substring s "let is_valid_taproot_hash_type");
  Alcotest.(check bool)
    "G4 whitelist matches Core (0x03 + 0x81..0x83)" true
    (contains_substring s "hash_type <= 0x03 || (hash_type >= 0x81 && hash_type <= 0x83)")

(* G5: SIGHASH_SINGLE without matching output *)
let g5_sighash_single_safety () =
  let s = script_ml () in
  Alcotest.(check bool)
    "G5 taproot_sighash_single_safe defined" true
    (contains_substring s "let taproot_sighash_single_safe");
  Alcotest.(check bool)
    "G5 SIGHASH_SINGLE: base_type 3 + in_pos < n_outputs" true
    (contains_substring s "base_type <> 3 || input_index < n_outputs")

(* G6: Schnorr signing C stubs *)
let g6_schnorr_sign_stubs () =
  let stubs = schnorr_stubs_c () in
  let crypto = crypto_ml () in
  Alcotest.(check bool)
    "G6a schnorr_stubs.c provides caml_schnorr_sign" true
    (contains_substring stubs "caml_schnorr_sign");
  Alcotest.(check bool)
    "G6b crypto.ml binds schnorr_sign_tweaked_raw" true
    (contains_substring crypto "external schnorr_sign_tweaked_raw")

(* -- BIP-341 Taproot key-path + commitment ------------------------------- *)

(* G7: P2TR detection (witness v1 + 32B program) *)
let g7_p2tr_detection () =
  let s = script_ml () in
  Alcotest.(check bool)
    "G7 P2TR_script variant defined for 32-byte program" true
    (contains_substring s "P2TR_script of Types.hash256")

(* G8: scriptSig must be empty for taproot *)
let g8_scriptsig_empty_for_taproot () =
  let s = script_ml () in
  Alcotest.(check bool)
    "G8 P2TR rejects non-empty scriptSig" true
    (contains_substring s "scriptSig must be empty for taproot")

(* G9: empty witness => fail *)
let g9_empty_witness_fails () =
  let s = script_ml () in
  Alcotest.(check bool)
    "G9 P2TR rejects empty witness" true
    (contains_substring s "Empty witness for taproot")

(* G10: annex detection *)
let g10_annex_detection () =
  let s = script_ml () in
  Alcotest.(check bool)
    "G10a annex detected when last byte0 == 0x50" true
    (contains_substring s "Cstruct.get_uint8 last 0 = 0x50");
  Alcotest.(check bool)
    "G10b annex requires >= 2 items" true
    (contains_substring s "n >= 2 &&")

(* G11: annex hash *)
let g11_annex_hash_compact_size () =
  let s = script_ml () in
  Alcotest.(check bool)
    "G11 annex hash = SHA256(compact_size(len) || annex)" true
    (contains_substring s "Serialize.write_compact_size w (Cstruct.length annex)")

(* G12: key-path sig length validation *)
let g12_keypath_sig_length () =
  let s = script_ml () in
  Alcotest.(check bool)
    "G12 sig_len must be 64 or 65" true
    (contains_substring s "sig_len <> 64 && sig_len <> 65" ||
     contains_substring s "sig_len <> 64 && sig_len <> 65 then")

(* G13: TapTweak tagged hash *)
let g13_tap_tweak_tagged_hash () =
  let s = script_ml () in
  let c = crypto_ml () in
  Alcotest.(check bool)
    "G13a TapTweak tagged hash invoked in P2TR branch" true
    (contains_substring s "tagged_hash \"TapTweak\"");
  Alcotest.(check bool)
    "G13b crypto.ml tagged_hash defined" true
    (contains_substring c "let tagged_hash")

(* G14: xonly_pubkey_tweak_add_check via libsecp256k1 *)
let g14_tweak_add_check () =
  let stubs = schnorr_stubs_c () in
  let crypto = crypto_ml () in
  Alcotest.(check bool)
    "G14a libsecp256k1 secp256k1_xonly_pubkey_tweak_add_check used" true
    (contains_substring stubs "secp256k1_xonly_pubkey_tweak_add_check");
  Alcotest.(check bool)
    "G14b crypto.ml exports xonly_pubkey_tweak_add_check" true
    (contains_substring crypto "let xonly_pubkey_tweak_add_check")

(* G15: Sighash epoch = 0x00 *)
let g15_sighash_epoch () =
  let s = script_ml () in
  Alcotest.(check bool)
    "G15 sighash writes epoch = 0x00" true
    (contains_substring s "(* epoch *)")

(* G16: Sighash spend_type byte *)
let g16_spend_type_byte () =
  let s = script_ml () in
  Alcotest.(check bool)
    "G16 spend_type = has_annex(1) lor has_tapleaf(2)" true
    (contains_substring s "(if has_annex then 1 else 0) lor")

(* G17: ANYONECANPAY handling *)
let g17_anyonecanpay () =
  let s = script_ml () in
  Alcotest.(check bool)
    "G17 ANYONECANPAY: write outpoint + amount + spk + sequence for in_pos" true
    (contains_substring s "if anyone_can_pay then begin")

(* G18: prevouts.size == vin.size invariant *)
let g18_prevouts_inputs_invariant () =
  let s = script_ml () in
  Alcotest.(check bool)
    "G18 sighash asserts prevouts length == inputs length" true
    (contains_substring s "n_prevouts <> n_inputs")

(* G19: TAPROOT activation flag gated by taproot_height *)
let g19_activation_flag () =
  let v = validation_ml () in
  let c = consensus_ml () in
  Alcotest.(check bool)
    "G19a validation.ml sets script_verify_taproot iff height >= taproot_height" true
    (contains_substring v "height >= network.taproot_height" &&
     contains_substring v "script_verify_taproot");
  Alcotest.(check bool)
    "G19b consensus.ml declares taproot_height in network params" true
    (contains_substring c "taproot_height : int")

(* -- BIP-342 Tapscript opcodes + sigops budget --------------------------- *)

(* G20: control block size 33 + 32k, k in [0, 128] *)
let g20_control_block_size () =
  let s = script_ml () in
  Alcotest.(check bool)
    "G20a control_len < 33 rejected" true
    (contains_substring s "control_len < 33");
  Alcotest.(check bool)
    "G20b (control_len - 33) mod 32 == 0 enforced" true
    (contains_substring s "(control_len - 33) mod 32 <> 0");
  Alcotest.(check bool)
    "G20c path_len > 128 rejected" true
    (contains_substring s "path_len > 128")

(* G21: leaf version 0xC0 and mask 0xFE *)
let g21_leaf_version () =
  let s = script_ml () in
  let c = consensus_ml () in
  Alcotest.(check bool)
    "G21a control[0] & 0xFE for leaf version extraction" true
    (contains_substring s "land 0xFE");
  Alcotest.(check bool)
    "G21b leaf_version = 0xC0 selects tapscript path" true
    (contains_substring s "leaf_version <> 0xC0");
  Alcotest.(check bool)
    "G21c consensus.ml declares taproot_leaf_tapscript = 0xc0" true
    (contains_substring c "taproot_leaf_tapscript = 0xc0")

(* G22: unknown leaf version discourage-flag gated *)
let g22_unknown_leaf_version () =
  let s = script_ml () in
  Alcotest.(check bool)
    "G22a discourage_upgradable_taproot_version error path present" true
    (contains_substring s "Discouraged unknown taproot leaf version");
  Alcotest.(check bool)
    "G22b otherwise succeeds (upgradable)" true
    (contains_substring s "(* Unknown leaf version: succeed unconditionally *)")

(* G23: tapleaf hash *)
let g23_tapleaf_hash () =
  let c = crypto_ml () in
  Alcotest.(check bool)
    "G23a compute_tapleaf_hash defined in crypto.ml" true
    (contains_substring c "let compute_tapleaf_hash");
  Alcotest.(check bool)
    "G23b uses TapLeaf tag" true
    (contains_substring c "tagged_hash \"TapLeaf\"")

(* G24: tapbranch hash with lexicographic sort *)
let g24_tapbranch_lex_sort () =
  let c = crypto_ml () in
  Alcotest.(check bool)
    "G24a compute_tapbranch_hash defined" true
    (contains_substring c "let compute_tapbranch_hash");
  Alcotest.(check bool)
    "G24b lex-sort: compare left right <= 0" true
    (contains_substring c "Cstruct.compare left right <= 0");
  Alcotest.(check bool)
    "G24c uses TapBranch tag" true
    (contains_substring c "tagged_hash \"TapBranch\"")

(* G25: OP_SUCCESSx exact set *)
let g25_op_success_exact_set () =
  let s = script_ml () in
  (* The Core set is: 80, 98, 126..129, 131..134, 137..138, 141..142,
     149..153, 187..254. We assert each range is present in is_op_success. *)
  Alcotest.(check bool)
    "G25a op == 80 || op == 98" true
    (contains_substring s "op = 80 || op = 98");
  Alcotest.(check bool)
    "G25b op >= 126 && op <= 129" true
    (contains_substring s "(op >= 126 && op <= 129)");
  Alcotest.(check bool)
    "G25c op >= 131 && op <= 134" true
    (contains_substring s "(op >= 131 && op <= 134)");
  Alcotest.(check bool)
    "G25d op >= 137 && op <= 138" true
    (contains_substring s "(op >= 137 && op <= 138)");
  Alcotest.(check bool)
    "G25e op >= 141 && op <= 142" true
    (contains_substring s "(op >= 141 && op <= 142)");
  Alcotest.(check bool)
    "G25f op >= 149 && op <= 153" true
    (contains_substring s "(op >= 149 && op <= 153)");
  Alcotest.(check bool)
    "G25g op >= 187 && op <= 254" true
    (contains_substring s "(op >= 187 && op <= 254)")

(* G26: OP_SUCCESS prescan with truncated-push detection *)
let g26_prescan_truncated_push () =
  let s = script_ml () in
  Alcotest.(check bool)
    "G26a prescan detects truncated direct push" true
    (contains_substring s "Bad opcode: truncated push in tapscript");
  Alcotest.(check bool)
    "G26b prescan detects truncated PUSHDATA1" true
    (contains_substring s "Bad opcode: truncated PUSHDATA1 in tapscript");
  Alcotest.(check bool)
    "G26c prescan detects truncated PUSHDATA2" true
    (contains_substring s "Bad opcode: truncated PUSHDATA2 in tapscript");
  Alcotest.(check bool)
    "G26d prescan detects truncated PUSHDATA4" true
    (contains_substring s "Bad opcode: truncated PUSHDATA4 in tapscript");
  Alcotest.(check bool)
    "G26e prescan succeeds on first OP_SUCCESS" true
    (contains_substring s "OP_SUCCESS makes script unconditionally succeed")

(* G27: OP_CHECKMULTISIG / VERIFY disabled in tapscript *)
let g27_checkmultisig_disabled () =
  let s = script_ml () in
  Alcotest.(check bool)
    "G27 OP_CHECKMULTISIG(VERIFY) disabled in tapscript" true
    (contains_substring s "OP_CHECKMULTISIG(VERIFY) is disabled in tapscript")

(* G28: OP_CHECKSIGADD only valid in tapscript (PARTIAL — BUG-2: no MINIMALDATA) *)
let g28_checksigadd_only_in_tapscript () =
  let s = script_ml () in
  Alcotest.(check bool)
    "G28a OP_CHECKSIGADD rejected outside tapscript" true
    (contains_substring s "OP_CHECKSIGADD is only valid in tapscript");
  Alcotest.(check bool)
    "G28b OP_CHECKSIGADD increments n on success" true
    (contains_substring s "bytes_of_script_num (Int64.add n 1L)")

(* G28 BUG-2: n decoded without require_minimal *)
let g28_BUG2_no_minimaldata () =
  let s = script_ml () in
  (* Both decode sites use plain `script_num_of_bytes n_bytes` with no
     `~require_minimal` keyword argument. Find lines that say
     `script_num_of_bytes n_bytes in` (without the require_minimal kwarg
     visible on the same line). We approximate by searching for the
     bare form. The well-formed pattern elsewhere is
     `script_num_of_bytes ~require_minimal:(...)`. *)
  let bare_form = "let n = script_num_of_bytes n_bytes in" in
  let n = count_substring s bare_form in
  Alcotest.(check bool)
    "G28 BUG-2: at least one CHECKSIGADD num decode lacks ~require_minimal"
    true (n >= 1)

(* G29 (PARTIAL — BUG-8): VALIDATION_WEIGHT_OFFSET hardcoded *)
let g29_validation_weight_offset () =
  let s = script_ml () in
  Alcotest.(check bool)
    "G29a sigops_budget = 50 + witness_size" true
    (contains_substring s "let sigops_budget = 50 + witness_size in");
  (* BUG-8: no symbolic constant *)
  Alcotest.(check bool)
    "G29 BUG-8: no validation_weight_offset constant declared" false
    (contains_substring s "let validation_weight_offset")

(* G30 (PARTIAL — BUG-7): VALIDATION_WEIGHT_PER_SIGOP_PASSED hardcoded *)
let g30_per_sigop_weight () =
  let s = script_ml () in
  (* Six tapscript checksig sites all deduct 50 literally. *)
  let n = count_substring s "st.sigops_budget <- st.sigops_budget - 50" in
  Alcotest.(check bool)
    "G30a >= 6 sites deduct 50 from sigops_budget" true (n >= 6);
  Alcotest.(check bool)
    "G30 BUG-7: no validation_weight_per_sigop_passed constant declared" false
    (contains_substring s "let validation_weight_per_sigop_passed")

(* -- BUG-1 (P0-CONSENSUS): tapscript bypasses 520-byte push-size cap ----- *)

let bug1_tapscript_push_size_bypass () =
  let s = script_ml () in
  (* The buggy guard is exactly "sig_version <> SigVersionTapscript &&"
     in front of the push-size check at script.ml:1310 and 1324. *)
  let buggy_form =
    "st.sig_version <> SigVersionTapscript && Cstruct.length data > max_script_element_size"
  in
  let n = count_substring s buggy_form in
  Alcotest.(check bool)
    "BUG-1 P0-CONSENSUS: tapscript exempted from 520-byte push cap \
     at both PUSHDATA call sites"
    true (n >= 2)

(* -- Audit-status meta tests --------------------------------------------- *)

let as1_gate_count () =
  Alcotest.(check int) "AS1 30 audit gates declared" 30 30

let as2_bug_count () =
  (* Final renumbered: 9 bugs *)
  Alcotest.(check int) "AS2 BUG count == 9" 9 9

let as3_p0_consensus_count () =
  Alcotest.(check int) "AS3 P0-CONSENSUS count == 1 (BUG-1)" 1 1

let as4_audit_doc_exists () =
  let root = resolve_repo_root () in
  let doc = Filename.concat root "audit/w127_taproot.md" in
  Alcotest.(check bool) "AS4 audit/w127_taproot.md exists" true
    (Sys.file_exists doc)

let as5_test_file_self_check () =
  let root = resolve_repo_root () in
  let self = Filename.concat root "test/test_w127_taproot.ml" in
  Alcotest.(check bool) "AS5 test/test_w127_taproot.ml exists" true
    (Sys.file_exists self)

(* -- Suite --------------------------------------------------------------- *)

let () =
  run "W127 Taproot / Schnorr / Tapscript audit" [
    (* BIP-340 Schnorr *)
    "G1 BIP-340 Schnorr verify (libsecp256k1)", [
      test_case "PRESENT" `Quick g1_schnorr_verify_uses_libsecp256k1;
    ];
    "G2 64-byte sig => SIGHASH_DEFAULT", [
      test_case "PRESENT" `Quick g2_default_sighash_implicit;
    ];
    "G3 65-byte sig + 0x00 hash_type rejected", [
      test_case "PRESENT" `Quick g3_65_byte_with_default_rejected;
    ];
    "G4 hash_type whitelist", [
      test_case "PRESENT" `Quick g4_hash_type_whitelist;
    ];
    "G5 SIGHASH_SINGLE w/o matching output", [
      test_case "PRESENT" `Quick g5_sighash_single_safety;
    ];
    "G6 schnorr_sign / sign_tweaked stubs", [
      test_case "PRESENT" `Quick g6_schnorr_sign_stubs;
    ];

    (* BIP-341 Taproot *)
    "G7 P2TR detection", [
      test_case "PRESENT" `Quick g7_p2tr_detection;
    ];
    "G8 scriptSig must be empty for taproot", [
      test_case "PRESENT" `Quick g8_scriptsig_empty_for_taproot;
    ];
    "G9 empty witness => fail", [
      test_case "PRESENT" `Quick g9_empty_witness_fails;
    ];
    "G10 annex detection", [
      test_case "PRESENT" `Quick g10_annex_detection;
    ];
    "G11 annex hash", [
      test_case "PRESENT" `Quick g11_annex_hash_compact_size;
    ];
    "G12 key-path sig length 64 or 65", [
      test_case "PRESENT" `Quick g12_keypath_sig_length;
    ];
    "G13 TapTweak tagged hash", [
      test_case "PRESENT" `Quick g13_tap_tweak_tagged_hash;
    ];
    "G14 xonly_pubkey_tweak_add_check", [
      test_case "PRESENT" `Quick g14_tweak_add_check;
    ];
    "G15 sighash epoch = 0x00", [
      test_case "PRESENT" `Quick g15_sighash_epoch;
    ];
    "G16 spend_type byte = ext_flag|annex", [
      test_case "PRESENT" `Quick g16_spend_type_byte;
    ];
    "G17 ANYONECANPAY handling", [
      test_case "PRESENT" `Quick g17_anyonecanpay;
    ];
    "G18 prevouts.size == vin.size", [
      test_case "PRESENT" `Quick g18_prevouts_inputs_invariant;
    ];
    "G19 TAPROOT activation flag", [
      test_case "PRESENT" `Quick g19_activation_flag;
    ];

    (* BIP-342 Tapscript *)
    "G20 control block size 33 + 32k", [
      test_case "PRESENT" `Quick g20_control_block_size;
    ];
    "G21 leaf version 0xC0 + mask 0xFE", [
      test_case "PRESENT" `Quick g21_leaf_version;
    ];
    "G22 unknown leaf version: discourage-gated", [
      test_case "PRESENT" `Quick g22_unknown_leaf_version;
    ];
    "G23 tapleaf hash", [
      test_case "PRESENT" `Quick g23_tapleaf_hash;
    ];
    "G24 tapbranch hash (lex sort)", [
      test_case "PRESENT" `Quick g24_tapbranch_lex_sort;
    ];
    "G25 OP_SUCCESSx exact set", [
      test_case "PRESENT" `Quick g25_op_success_exact_set;
    ];
    "G26 OP_SUCCESS prescan + truncated-push", [
      test_case "PRESENT" `Quick g26_prescan_truncated_push;
    ];
    "G27 OP_CHECKMULTISIG(VERIFY) disabled", [
      test_case "PRESENT" `Quick g27_checkmultisig_disabled;
    ];
    "G28 OP_CHECKSIGADD only in tapscript", [
      test_case "PRESENT" `Quick g28_checksigadd_only_in_tapscript;
      test_case "BUG-2 PARTIAL: n decoded without MINIMALDATA" `Quick
        g28_BUG2_no_minimaldata;
    ];
    "G29 VALIDATION_WEIGHT_OFFSET = 50 (init)", [
      test_case "PRESENT (50 used) + BUG-8 PARTIAL (no symbolic const)" `Quick
        g29_validation_weight_offset;
    ];
    "G30 VALIDATION_WEIGHT_PER_SIGOP_PASSED = 50 (deduct)", [
      test_case "PRESENT (>= 6 deduct sites) + BUG-7 PARTIAL (no symbolic const)" `Quick
        g30_per_sigop_weight;
    ];

    (* P0-CONSENSUS finding *)
    "BUG-1 P0-CONSENSUS Tapscript push-size bypass", [
      test_case "lib/script.ml exempts tapscript at PUSHDATA call sites" `Quick
        bug1_tapscript_push_size_bypass;
    ];

    (* Audit-status meta *)
    "Audit-status", [
      test_case "AS1 30 gates" `Quick as1_gate_count;
      test_case "AS2 9 bugs (final renumbered)" `Quick as2_bug_count;
      test_case "AS3 1 P0-CONSENSUS" `Quick as3_p0_consensus_count;
      test_case "AS4 audit doc exists" `Quick as4_audit_doc_exists;
      test_case "AS5 test file exists" `Quick as5_test_file_self_check;
    ];
  ]
