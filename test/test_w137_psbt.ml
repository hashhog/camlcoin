(* W137 PSBT v0/v2 (BIP-174 / BIP-370) — camlcoin (OCaml)

   Discovery-only audit. 30 gates / 26 NEW bugs.

   Scope: BIP-174 (PSBTv0) + BIP-371 (taproot) + BIP-373 (MuSig2).
   BIP-370 (PSBTv2) is explicitly out of scope — Core does not
   implement PSBTv2 (PSBT_HIGHEST_VERSION=0), so absence of v2
   support is a non-finding.

   References:
   - bitcoin-core/src/psbt.h         — structure + Serialize/Unserialize
   - bitcoin-core/src/psbt.cpp       — free functions
   - bitcoin-core/src/node/psbt.{h,cpp} — AnalyzePSBT (fee/vsize/next-role)

   Severity legend:
   - P0-CDIV: client-observable correctness divergence
   - P1: feature/field absent that spec mandates and clients use
   - P2: performance / DoS surface (size limit unenforced, redundant data)
   - P3: surface drift, error-message shape

   NEW BUGs (full catalogue in audit/w137_psbt.md):

   BUG-W137-1  (P0-CDIV G29): analyzepsbt estimated_vsize hard-coded 0
                              (rpc.ml:5742).
   BUG-W137-2  (P0-CDIV G29): analyzepsbt estimated_feerate is BTC, not
                              BTC/kvB; missing vsize divisor. rpc.ml:5737.
   BUG-W137-3  (P0-CDIV G17): PSBT_OUT_TAP_TREE stored as opaque blob;
                              no TaprootBuilder validation. psbt.ml:672-674.
   BUG-W137-4  (P0-CDIV G25): No PSBTInputSignedAndVerified analog;
                              malformed final_* round-trips as "complete".
   BUG-W137-5  (P1 G7):  PSBT_IN_PARTIAL_SIG no DER-strict check.
   BUG-W137-6  (P1 G7):  Invalid pubkey-key-size partial_sig SILENTLY
                          SKIPPED rather than errored. psbt.ml:544.
   BUG-W137-7  (P1 G2/4/6/9/10/16): no key.size()==1 check on 8+ singleton
                                     types. psbt.ml various.
   BUG-W137-8  (P1 G8):  PSBT_IN_RIPEMD160/SHA256/HASH160/HASH256
                          (0x0A..0x0D) preimage fields absent.
   BUG-W137-9  (P1 G9):  PSBT_IN_TAP_KEY_SIG no 64..65 length check.
   BUG-W137-10 (P1 G10): PSBT_IN_TAP_SCRIPT_SIG sig no 64..65 length check.
   BUG-W137-11 (P1 G11): PSBT_IN_TAP_LEAF_SCRIPT control-block no
                          len>=33 && (len-1)%32==0 check.
   BUG-W137-12 (P1 G12/18): PSBT_{IN,OUT}_TAP_BIP32_DERIVATION value-length
                             boundary unchecked.
   BUG-W137-13 (P1 G13): PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS (0x1a) absent
                          (only output-side 0x08 implemented).
   BUG-W137-14 (P1 G14): PSBT_IN_MUSIG2_PUB_NONCE (0x1b) absent.
   BUG-W137-15 (P1 G15): PSBT_IN_MUSIG2_PARTIAL_SIG (0x1c) absent.
   BUG-W137-16 (P1 G19): PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS missing
                          CPubKey::IsFullyValid pass.
   BUG-W137-17 (P1 G20): PSBT_{IN,OUT,GLOBAL}_PROPRIETARY (0xFC) absent;
                          falls into 'unknown' bucket.
   BUG-W137-18 (P1 G22): No 'extra data after PSBT' rejection.
   BUG-W137-19 (P1 G23): No non_witness_utxo->GetHash() == prevout.hash
                          check at deserialize.
   BUG-W137-20 (P1 G26): joinpsbts RPC absent.
   BUG-W137-21 (P1 G27): descriptorprocesspsbt RPC absent.
   BUG-W137-22 (P1 G28): psbtbumpfee RPC absent.
   BUG-W137-23 (P2 G21): max_psbt_size defined but NEVER referenced.
                          No 100MB cap on decodepsbt input.
   BUG-W137-24 (P2 G30): No RemoveUnnecessaryTransactions analog.
   BUG-W137-25 (P3 G1):  Magic-byte read returns Invalid_magic for short
                          stream rather than throwing a stream-failure.
   BUG-W137-26 (P3 G24): Mid-stream input-parse errors silently truncate.

   Tests below are pass-as-evidence: each documents the current behaviour
   and serves as a regression-pin. When a future fix wave closes a gap, the
   matching test should flip from "documents absence" to "verifies presence".
*)

open Camlcoin

(* ============================================================================
   Helpers
   ============================================================================ *)

(* Build a minimal Types.transaction with a single input + output.  The
   txid is a synthetic 32-byte sentinel; the script_pubkey is a 1-byte
   placeholder.  Sufficient for a PSBT round-trip test. *)
let mk_dummy_txid (b : int) : Types.hash256 =
  let h = Cstruct.create 32 in
  Cstruct.set_uint8 h 0 b;
  h

let mk_simple_tx () : Types.transaction =
  let txin : Types.tx_in = {
    previous_output = { txid = mk_dummy_txid 0xaa; vout = 0l };
    script_sig = Cstruct.empty;
    sequence = 0xFFFFFFFDl;  (* RBF default *)
  } in
  let spk = Cstruct.create 2 in
  Cstruct.set_uint8 spk 0 0x51;  (* OP_1 — trivial spendable *)
  Cstruct.set_uint8 spk 1 0x00;
  let txout : Types.tx_out = {
    value = 100_000_000L;
    script_pubkey = spk;
  } in
  {
    version = 2l;
    inputs = [txin];
    outputs = [txout];
    witnesses = [];
    locktime = 0l;
  }

(* Read source file and check whether a substring is present.  Used for
   "feature-absent" gates that are easier to verify by inspecting source
   than by exercising the API. *)
let source_contains ~path ~needle =
  let ic = open_in path in
  let n = in_channel_length ic in
  let s = really_input_string ic n in
  close_in ic;
  try ignore (Str.search_forward (Str.regexp_string needle) s 0); true
  with Not_found -> false

(* Path lookup that works from either dune runtest cwd or _build cwd. *)
let find_source filename =
  let candidates = [
    Filename.concat "lib" filename;
    Filename.concat "../lib" filename;
    Filename.concat "../../lib" filename;
    Filename.concat "../../../lib" filename;
    Filename.concat "../../camlcoin/lib" filename;
    Filename.concat "../../../camlcoin/lib" filename;
  ] in
  try List.find Sys.file_exists candidates
  with Not_found ->
    (* Fall back to the absolute sandbox path so the test runs even
       when dune's cwd is unexpected. *)
    Filename.concat "/home/work/hashhog/camlcoin/lib" filename

let psbt_ml () = find_source "psbt.ml"
let rpc_ml () = find_source "rpc.ml"

(* ============================================================================
   G1-G5: Magic, global map, version handling
   ============================================================================ *)

(* G1: PSBT magic byte read.  Core: throws on short stream.  camlcoin:
   returns Invalid_magic on length < 5 — different error surface but
   structurally equivalent client-visible failure. *)
let test_g1_magic_short_stream_returns_error () =
  let short = Cstruct.of_string "psb" in
  match Psbt.deserialize short with
  | Error Invalid_magic ->
    Alcotest.(check bool) "G1: short stream rejected with Invalid_magic \
                           (surface-drift vs Core throw — BUG-W137-25)" true true
  | Error _ ->
    Alcotest.(check bool) "G1: short stream rejected" true true
  | Ok _ ->
    Alcotest.fail "G1: short PSBT must not parse"

(* Same gate, bad magic body. *)
let test_g1_magic_bad_bytes_returns_error () =
  let bad = Cstruct.of_string "XSBT\xff" in
  match Psbt.deserialize bad with
  | Error Invalid_magic -> Alcotest.(check bool) "G1: bad magic rejected" true true
  | _ -> Alcotest.fail "G1: malformed magic must produce Invalid_magic"

(* G2: PSBT_GLOBAL_UNSIGNED_TX accepts over-long key bytes (BUG-W137-7).
   Core: rejects key.size() != 1.  camlcoin: silently accepts.

   We exercise this by hand-crafting a PSBT with a 3-byte key for type
   0x00 instead of the canonical 1-byte key. *)
let test_g2_global_unsigned_tx_no_key_size_check () =
  (* This is a structural source-level assertion: psbt.ml's match on
     key_type 0x00 has no length check.  A behavioural check would
     require deep tx-stream surgery; we pin the gap via grep. *)
  let src_has_size_check =
    source_contains ~path:(psbt_ml ())
      ~needle:"Global unsigned tx key is more than one byte"
  in
  Alcotest.(check bool)
    "G2: psbt.ml has no 'key size != 1' check on PSBT_GLOBAL_UNSIGNED_TX \
     (BUG-W137-7)"
    false src_has_size_check

(* G3: scriptSig / scriptWitness emptiness check — Core/camlcoin agree. *)
let test_g3_unsigned_tx_emptiness_check () =
  (* Construct a tx with a non-empty script_sig and ensure round-trip
     rejection.  We do this by manually creating a psbt with a non-clean
     tx (bypass the create() cleaner). *)
  let tx = mk_simple_tx () in
  let dirty_tx = {
    tx with
    inputs = List.map (fun (i : Types.tx_in) ->
      let s = Cstruct.create 1 in
      Cstruct.set_uint8 s 0 0xff;
      { i with script_sig = s }
    ) tx.inputs;
  } in
  let psbt : Psbt.psbt = {
    tx = dirty_tx;
    global_xpubs = [];
    version = None;
    inputs = List.map (fun _ -> Psbt.empty_input) dirty_tx.inputs;
    outputs = List.map (fun _ -> Psbt.empty_output) dirty_tx.outputs;
    unknown = [];
  } in
  let b64 = Psbt.to_base64 psbt in
  match Psbt.of_base64 b64 with
  | Error (Psbt.Invalid_tx_scriptSig_not_empty) ->
    Alcotest.(check bool) "G3: non-empty scriptSig rejected (Core-parity)" true true
  | Ok _ -> Alcotest.fail "G3: dirty tx must be rejected at deserialize"
  | Error e ->
    Alcotest.failf "G3: expected Invalid_tx_scriptSig_not_empty, got %s"
      (Psbt.string_of_error e)

(* G4: PSBT_GLOBAL_VERSION key-size + dup check.  Source-level pin. *)
let test_g4_global_version_no_key_size_check () =
  let src_has = source_contains ~path:(psbt_ml ())
                  ~needle:"Global version key is more than one byte"
  in
  Alcotest.(check bool)
    "G4: psbt.ml has no 'key size != 1' check on PSBT_GLOBAL_VERSION \
     (BUG-W137-7)"
    false src_has

(* G5: PSBT_HIGHEST_VERSION enforcement.  Match — both reject v > 0. *)
let test_g5_unsupported_version_rejected () =
  (* Construct a PSBT with version = 1 (PSBTv2) and confirm rejection. *)
  let tx = mk_simple_tx () in
  let psbt = {
    (Psbt.create tx) with
    Psbt.version = Some 1l;
  } in
  let b64 = Psbt.to_base64 psbt in
  match Psbt.of_base64 b64 with
  | Error (Unsupported_version v) when v = 1l ->
    Alcotest.(check bool) "G5: version=1 rejected (PSBTv2 not implemented \
                           by Core or camlcoin)" true true
  | Ok _ -> Alcotest.fail "G5: version=1 PSBT must be rejected"
  | Error e ->
    Alcotest.failf "G5: expected Unsupported_version, got %s"
      (Psbt.string_of_error e)

(* ============================================================================
   G6-G10: Per-input duplicate-key / size validation
   ============================================================================ *)

(* G6: PSBT_IN_NON_WITNESS_UTXO key-size check absent. *)
let test_g6_in_non_witness_utxo_no_key_size_check () =
  let src_has = source_contains ~path:(psbt_ml ())
                  ~needle:"Non-witness utxo key is more than one byte"
  in
  Alcotest.(check bool)
    "G6: PSBT_IN_NON_WITNESS_UTXO accepts any key length (BUG-W137-7)"
    false src_has

(* G7: PSBT_IN_PARTIAL_SIG no DER-strict / pubkey-validity check
   (BUG-W137-5).  Source-level pin. *)
let test_g7_partial_sig_no_der_check () =
  let src_has = source_contains ~path:(psbt_ml ())
                  ~needle:"CheckSignatureEncoding"
  in
  Alcotest.(check bool)
    "G7: psbt.ml does not call CheckSignatureEncoding on PSBT_IN_PARTIAL_SIG \
     (BUG-W137-5)"
    false src_has

(* G7-bis: invalid pubkey-key-size partial_sig SILENTLY skipped
   (BUG-W137-6).  Behavioural check via constructed PSBT.

   We build a minimal PSBT by hand with one partial_sig key of length 5
   (illegal — must be 34 or 66 with the type byte) and confirm
   deserialize succeeds without storing the entry. *)
let test_g7_partial_sig_invalid_pubkey_size_silent_skip () =
  (* Build PSBT bytes by hand. *)
  let w = Serialize.writer_create () in
  Serialize.write_bytes w (Cstruct.of_string "psbt\xff");
  (* Global UNSIGNED_TX *)
  let tx = mk_simple_tx () in
  let tx_bytes = Psbt.serialize_tx_no_witness tx in
  Serialize.write_compact_size w 1; Serialize.write_uint8 w 0x00;
  Serialize.write_compact_size w (Cstruct.length tx_bytes);
  Serialize.write_bytes w tx_bytes;
  Serialize.write_uint8 w 0x00;  (* global separator *)
  (* Input map with one bogus partial-sig key (5-byte total, 4-byte key data) *)
  Serialize.write_compact_size w 5;
  Serialize.write_uint8 w 0x02;  (* PSBT_IN_PARTIAL_SIG *)
  Serialize.write_uint8 w 0xaa; Serialize.write_uint8 w 0xbb;
  Serialize.write_uint8 w 0xcc; Serialize.write_uint8 w 0xdd;
  (* sig value (would-be DER) *)
  Serialize.write_compact_size w 3;
  Serialize.write_uint8 w 0x30; Serialize.write_uint8 w 0x01;
  Serialize.write_uint8 w 0x00;
  Serialize.write_uint8 w 0x00;  (* input separator *)
  (* Output map separator *)
  Serialize.write_uint8 w 0x00;
  let data = Serialize.writer_to_cstruct w in
  match Psbt.deserialize data with
  | Ok psbt ->
    let inp = List.hd psbt.inputs in
    Alcotest.(check int)
      "G7-bis: invalid pubkey-size partial_sig silently skipped, not stored \
       (BUG-W137-6)"
      0 (List.length inp.partial_sigs)
  | Error e ->
    (* If a different error fires first, the test still documents the gap:
       we expected silent-skip behaviour and got a different surface. *)
    Alcotest.failf "G7-bis: expected silent skip + Ok parse, got %s"
      (Psbt.string_of_error e)

(* G8: PSBT_IN_RIPEMD160 / SHA256 / HASH160 / HASH256 (0x0A..0x0D) absent
   (BUG-W137-8).  These types are defined in psbt.h but NOT in
   lib/psbt.ml.  Source-level pin. *)
let test_g8_hash_preimage_fields_absent () =
  let src = psbt_ml () in
  let has_ripemd160 = source_contains ~path:src
                        ~needle:"psbt_in_ripemd160" in
  let has_sha256 = source_contains ~path:src
                     ~needle:"psbt_in_sha256" in
  let has_hash160 = source_contains ~path:src
                      ~needle:"psbt_in_hash160" in
  let has_hash256 = source_contains ~path:src
                      ~needle:"psbt_in_hash256" in
  Alcotest.(check bool)
    "G8: 4 hash-preimage input fields (0x0A..0x0D) absent (BUG-W137-8)"
    false (has_ripemd160 || has_sha256 || has_hash160 || has_hash256)

(* G9: PSBT_IN_TAP_KEY_SIG no 64..65 length check (BUG-W137-9). *)
let test_g9_tap_key_sig_no_length_check () =
  let src_has = source_contains ~path:(psbt_ml ())
                  ~needle:"Taproot key path signature is shorter than 64"
  in
  Alcotest.(check bool)
    "G9: PSBT_IN_TAP_KEY_SIG accepts any value length (BUG-W137-9)"
    false src_has

(* G10: PSBT_IN_TAP_SCRIPT_SIG sig no 64..65 length check (BUG-W137-10). *)
let test_g10_tap_script_sig_no_length_check () =
  let src_has = source_contains ~path:(psbt_ml ())
                  ~needle:"Taproot script path signature is shorter than 64"
  in
  Alcotest.(check bool)
    "G10: PSBT_IN_TAP_SCRIPT_SIG accepts any value length (BUG-W137-10)"
    false src_has

(* ============================================================================
   G11-G15: Per-input taproot / MuSig2 / proprietary surface
   ============================================================================ *)

(* G11: PSBT_IN_TAP_LEAF_SCRIPT control-block sanity (BUG-W137-11). *)
let test_g11_tap_leaf_script_no_control_block_check () =
  let src = psbt_ml () in
  let has_ctrl_check =
    source_contains ~path:src
      ~needle:"control block size is not valid"
    || source_contains ~path:src
         ~needle:"(key.size() - 2) % 32"
    || source_contains ~path:src
         ~needle:"(Cstruct.length key_data - 1) mod 32"
  in
  Alcotest.(check bool)
    "G11: PSBT_IN_TAP_LEAF_SCRIPT has no control-block size check \
     (BUG-W137-11)"
    false has_ctrl_check

(* G12: PSBT_IN_TAP_BIP32_DERIVATION value-length boundary not verified
   (BUG-W137-12). *)
let test_g12_tap_bip32_no_value_length_check () =
  let src = psbt_ml () in
  let has_check =
    source_contains ~path:src
      ~needle:"Input Taproot BIP32 keypath has an invalid length"
    || source_contains ~path:src
         ~needle:"hashes_len > value_len"
  in
  Alcotest.(check bool)
    "G12: PSBT_IN_TAP_BIP32_DERIVATION value-length boundary unchecked \
     (BUG-W137-12)"
    false has_check

(* G13: PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS (0x1a) absent (BUG-W137-13).
   Only the OUTPUT-side (0x08) is implemented. *)
let test_g13_in_musig2_participants_absent () =
  let src = psbt_ml () in
  let has_in_participants =
    source_contains ~path:src ~needle:"psbt_in_musig2_participant"
    || source_contains ~path:src ~needle:"PSBT_IN_MUSIG2_PARTICIPANT"
  in
  let has_out_participants =
    source_contains ~path:src ~needle:"psbt_out_musig2_participants"
  in
  Alcotest.(check bool)
    "G13: input-side MuSig2 participants (0x1a) not implemented; \
     only output-side (0x08) (BUG-W137-13)"
    true ((not has_in_participants) && has_out_participants)

(* G14: PSBT_IN_MUSIG2_PUB_NONCE (0x1b) absent (BUG-W137-14). *)
let test_g14_in_musig2_pub_nonce_absent () =
  let src = psbt_ml () in
  let has =
    source_contains ~path:src ~needle:"psbt_in_musig2_pub_nonce"
    || source_contains ~path:src ~needle:"PSBT_IN_MUSIG2_PUB_NONCE"
    || source_contains ~path:src ~needle:"0x1b"
  in
  Alcotest.(check bool)
    "G14: PSBT_IN_MUSIG2_PUB_NONCE (0x1b) not implemented (BUG-W137-14)"
    false has

(* G15: PSBT_IN_MUSIG2_PARTIAL_SIG (0x1c) absent (BUG-W137-15). *)
let test_g15_in_musig2_partial_sig_absent () =
  let src = psbt_ml () in
  let has =
    source_contains ~path:src ~needle:"psbt_in_musig2_partial_sig"
    || source_contains ~path:src ~needle:"PSBT_IN_MUSIG2_PARTIAL_SIG"
    || source_contains ~path:src ~needle:"0x1c"
  in
  Alcotest.(check bool)
    "G15: PSBT_IN_MUSIG2_PARTIAL_SIG (0x1c) not implemented (BUG-W137-15)"
    false has

(* ============================================================================
   G16-G20: Per-output validation + tap tree + proprietary
   ============================================================================ *)

(* G16: PSBT_OUT_REDEEMSCRIPT / WITNESSSCRIPT no key.size()==1 check
   (subset of BUG-W137-7). *)
let test_g16_out_redeem_witness_no_key_size_check () =
  let src = psbt_ml () in
  let has_check =
    source_contains ~path:src
      ~needle:"Output redeemScript key is more than one byte"
    || source_contains ~path:src
         ~needle:"Output witnessScript key is more than one byte"
  in
  Alcotest.(check bool)
    "G16: PSBT_OUT_REDEEMSCRIPT/WITNESSSCRIPT accept any key length \
     (BUG-W137-7)"
    false has_check

(* G17: PSBT_OUT_TAP_TREE TaprootBuilder.IsComplete() not enforced
   (BUG-W137-3 P0-CDIV). *)
let test_g17_tap_tree_no_builder_validation () =
  let src = psbt_ml () in
  let has_validation =
    source_contains ~path:src ~needle:"TaprootBuilder"
    || source_contains ~path:src ~needle:"builder.IsComplete"
    || source_contains ~path:src ~needle:"is_complete"
    || source_contains ~path:src ~needle:"tap_tree is malformed"
    || source_contains ~path:src ~needle:"TAPROOT_CONTROL_MAX_NODE_COUNT"
    || source_contains ~path:src ~needle:"TAPROOT_LEAF_MASK"
  in
  Alcotest.(check bool)
    "G17: PSBT_OUT_TAP_TREE stored as opaque blob; no TaprootBuilder \
     validation (BUG-W137-3 P0-CDIV)"
    false has_validation

(* G18: PSBT_OUT_TAP_BIP32_DERIVATION value-length boundary unchecked
   (BUG-W137-12 — same as G12 on the output side). *)
let test_g18_out_tap_bip32_no_value_length_check () =
  let src = psbt_ml () in
  let has_check =
    source_contains ~path:src
      ~needle:"Output Taproot BIP32 keypath has an invalid length"
  in
  Alcotest.(check bool)
    "G18: PSBT_OUT_TAP_BIP32_DERIVATION value-length boundary unchecked \
     (BUG-W137-12)"
    false has_check

(* G19: PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS missing pubkey-validity check
   (BUG-W137-16). *)
let test_g19_out_musig2_no_pubkey_validity_check () =
  let src = psbt_ml () in
  (* Look for IsFullyValid or a Crypto.pubkey_valid call.  Pre-fix, the
     output-side parser slices key_data into 33-byte chunks without
     calling any validity primitive. *)
  let has_check =
    source_contains ~path:src ~needle:"IsFullyValid"
    || source_contains ~path:src ~needle:"musig2 participant pubkey is invalid"
    || source_contains ~path:src ~needle:"musig2 aggregate pubkey is invalid"
  in
  Alcotest.(check bool)
    "G19: PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS missing pubkey-validity check \
     (BUG-W137-16)"
    false has_check

(* G20: PSBT_{IN,OUT,GLOBAL}_PROPRIETARY (0xFC) absent (BUG-W137-17). *)
let test_g20_proprietary_fields_absent () =
  let src = psbt_ml () in
  let in_def = source_contains ~path:src ~needle:"psbt_in_proprietary" in
  let out_def = source_contains ~path:src ~needle:"psbt_out_proprietary" in
  (* Note: psbt_global_proprietary IS defined as a constant but not
     handled in deserialize_global, so we ask for the deserialize-side
     case arm rather than the constant. *)
  let global_handled =
    source_contains ~path:src ~needle:"t = psbt_global_proprietary"
  in
  Alcotest.(check bool)
    "G20: PSBT_{IN,OUT,GLOBAL}_PROPRIETARY (0xFC) structured handling absent \
     (BUG-W137-17)"
    false (in_def || out_def || global_handled)

(* ============================================================================
   G21-G25: Top-level / lifecycle / size-limit
   ============================================================================ *)

(* G21: MAX_FILE_SIZE_PSBT (100 MB) cap defined but UNUSED (BUG-W137-23). *)
let test_g21_max_psbt_size_unenforced () =
  let src = psbt_ml () in
  let defined = source_contains ~path:src ~needle:"max_psbt_size" in
  (* The constant is defined; the question is whether it is referenced
     anywhere ELSE (a comparison guard).  Count occurrences. *)
  let ic = open_in src in
  let n = in_channel_length ic in
  let buf = really_input_string ic n in
  close_in ic;
  let count = ref 0 in
  (try
     let pos = ref 0 in
     while true do
       let p = Str.search_forward (Str.regexp_string "max_psbt_size") buf !pos in
       incr count;
       pos := p + 1
     done
   with Not_found -> ());
  (* Expect exactly 1 occurrence (the definition).  If > 1 then it is
     consulted somewhere — fix has landed. *)
  Alcotest.(check bool)
    "G21: max_psbt_size defined but never consulted (BUG-W137-23 P2 DoS)"
    true (defined && !count = 1)

(* G22: No 'extra data after PSBT' rejection (BUG-W137-18).

   Construct a valid PSBT, append trailing junk bytes, confirm
   deserialize returns Ok rather than an error. *)
let test_g22_no_extra_data_after_psbt_rejection () =
  let tx = mk_simple_tx () in
  let psbt = Psbt.create tx in
  let bytes = Psbt.serialize psbt in
  (* Append 4 bytes of junk *)
  let junk = Cstruct.of_string "\xff\xff\xff\xff" in
  let polluted = Cstruct.concat [bytes; junk] in
  match Psbt.deserialize polluted with
  | Ok _ ->
    Alcotest.(check bool)
      "G22: trailing-junk PSBT silently accepted (Core: 'extra data after \
       PSBT') (BUG-W137-18)"
      true true
  | Error e ->
    (* If it errors, the fix has landed; flip the assertion. *)
    Alcotest.failf "G22: expected silent accept, got %s"
      (Psbt.string_of_error e)

(* G23: No non_witness_utxo->GetHash() == prevout.hash check at
   deserialize (BUG-W137-19).  Source-level pin. *)
let test_g23_no_non_witness_utxo_hash_check () =
  let src = psbt_ml () in
  let has_check =
    source_contains ~path:src
      ~needle:"Non-witness UTXO does not match outpoint hash"
    || source_contains ~path:src
         ~needle:"non_witness_utxo->GetHash"
    || source_contains ~path:src
         ~needle:"compute_txid prev_tx"
  in
  Alcotest.(check bool)
    "G23: deserialize does not assert non_witness_utxo hash matches \
     prevout.hash (BUG-W137-19)"
    false has_check

(* G24: Inputs/outputs count vs tx vin/vout — error path drift.
   camlcoin uses List.init to consume exactly N records; on mid-stream
   error, the remaining unread bytes are silently dropped. *)
let test_g24_count_mismatch_error_path_drift () =
  let src = psbt_ml () in
  let has_explicit_count_error =
    source_contains ~path:src
      ~needle:"Inputs provided does not match the number of inputs"
    || source_contains ~path:src
         ~needle:"Outputs provided does not match the number of outputs"
  in
  Alcotest.(check bool)
    "G24: no explicit count-mismatch error path; consume-N approach \
     (BUG-W137-26 surface drift)"
    false has_explicit_count_error

(* G25: No PSBTInputSignedAndVerified analog (BUG-W137-4 P0-CDIV).

   Source-level pin: there is no VerifyScript / interpret pass over
   final_script_sig + final_script_witness in psbt.ml. *)
let test_g25_no_signed_and_verified_check () =
  let src = psbt_ml () in
  let has_verify =
    source_contains ~path:src ~needle:"VerifyScript"
    || source_contains ~path:src ~needle:"Script.verify"
    || source_contains ~path:src ~needle:"PSBTInputSignedAndVerified"
    || source_contains ~path:src ~needle:"is_input_signed_and_verified"
  in
  Alcotest.(check bool)
    "G25: no PSBTInputSignedAndVerified analog in psbt.ml \
     (BUG-W137-4 P0-CDIV)"
    false has_verify

(* ============================================================================
   G26-G30: RPC surface gaps + analyzepsbt fidelity
   ============================================================================ *)

(* G26: joinpsbts RPC absent (BUG-W137-20). *)
let test_g26_no_joinpsbts_rpc () =
  let src = rpc_ml () in
  let has =
    source_contains ~path:src ~needle:"handle_joinpsbts"
    || source_contains ~path:src ~needle:"\"joinpsbts\""
    || source_contains ~path:src ~needle:"join_psbts"
  in
  Alcotest.(check bool) "G26: joinpsbts RPC absent (BUG-W137-20)" false has

(* G27: descriptorprocesspsbt RPC absent (BUG-W137-21). *)
let test_g27_no_descriptorprocesspsbt_rpc () =
  let src = rpc_ml () in
  let has =
    source_contains ~path:src ~needle:"handle_descriptorprocesspsbt"
    || source_contains ~path:src ~needle:"\"descriptorprocesspsbt\""
  in
  Alcotest.(check bool)
    "G27: descriptorprocesspsbt RPC absent (BUG-W137-21)"
    false has

(* G28: psbtbumpfee RPC absent (BUG-W137-22). *)
let test_g28_no_psbtbumpfee_rpc () =
  let src = rpc_ml () in
  let has =
    source_contains ~path:src ~needle:"handle_psbtbumpfee"
    || source_contains ~path:src ~needle:"\"psbtbumpfee\""
  in
  Alcotest.(check bool) "G28: psbtbumpfee RPC absent (BUG-W137-22)" false has

(* G29: analyzepsbt estimated_vsize hard-coded 0; estimated_feerate
   units wrong (BUG-W137-1 / BUG-W137-2 P0-CDIV). *)
let test_g29_analyzepsbt_estimated_vsize_stubbed () =
  let src = rpc_ml () in
  (* estimated_vsize is the literal `Int 0 — pin via source. *)
  let has_zero =
    source_contains ~path:src
      ~needle:"estimated_vsize\", `Int 0"
    || source_contains ~path:src
         ~needle:"\"estimated_vsize\", `Int 0"
  in
  Alcotest.(check bool)
    "G29: analyzepsbt estimated_vsize hard-coded 0 (BUG-W137-1 P0-CDIV)"
    true has_zero

(* G29-bis: estimated_feerate units — BTC, not BTC/kvB.  Pin the source
   formula. *)
let test_g29_analyzepsbt_estimated_feerate_units_wrong () =
  let src = rpc_ml () in
  (* The current formula divides only by 100_000_000.0 (BTC, no vsize
     factor).  A Core-correct version would multiply by 1000 / vsize. *)
  let has_naive =
    source_contains ~path:src
      ~needle:"Int64.to_float fee /. 100_000_000.0"
  in
  Alcotest.(check bool)
    "G29-bis: estimated_feerate is `fee / 1e8` (BTC) not BTC/kvB \
     (BUG-W137-2 P0-CDIV)"
    true has_naive

(* G30: No RemoveUnnecessaryTransactions analog (BUG-W137-24). *)
let test_g30_no_remove_unnecessary_transactions () =
  let src = psbt_ml () in
  let src_rpc = rpc_ml () in
  let src_w = find_source "wallet.ml" in
  let has =
    source_contains ~path:src ~needle:"RemoveUnnecessaryTransactions"
    || source_contains ~path:src ~needle:"remove_unnecessary_transactions"
    || source_contains ~path:src_rpc ~needle:"remove_unnecessary_transactions"
    || source_contains ~path:src_w ~needle:"remove_unnecessary_transactions"
  in
  Alcotest.(check bool)
    "G30: no RemoveUnnecessaryTransactions helper (BUG-W137-24 P2)"
    false has

(* ============================================================================
   Invariant pins (regression-guard against accidental fixes)
   ============================================================================ *)

(* INV-1: PSBT round-trip is byte-identical on a clean PSBT.  W47 pin. *)
let test_inv1_round_trip_byte_identical () =
  let tx = mk_simple_tx () in
  let psbt = Psbt.create tx in
  let bytes = Psbt.serialize psbt in
  match Psbt.deserialize bytes with
  | Ok psbt2 ->
    let bytes2 = Psbt.serialize psbt2 in
    Alcotest.(check bool)
      "INV-1: PSBT round-trip is byte-identical (W47 pin)"
      true (Cstruct.equal bytes bytes2)
  | Error e ->
    Alcotest.failf "INV-1: round-trip deserialize failed: %s"
      (Psbt.string_of_error e)

(* INV-2: combine(p, p) is byte-identical to p — W47 idempotency pin. *)
let test_inv2_combine_idempotent () =
  let tx = mk_simple_tx () in
  let psbt = Psbt.create tx in
  let bytes = Psbt.serialize psbt in
  match Psbt.combine psbt psbt with
  | Ok combined ->
    let bytes2 = Psbt.serialize combined in
    Alcotest.(check bool)
      "INV-2: combine(p, p) is byte-identical to p (W47 idempotency pin)"
      true (Cstruct.equal bytes bytes2)
  | Error msg ->
    Alcotest.failf "INV-2: combine(p, p) failed: %s" msg

(* INV-3: PSBT magic bytes are exactly "psbt\xff" (4 ASCII + 0xff). *)
let test_inv3_magic_bytes () =
  let m = Cstruct.to_string Psbt.psbt_magic in
  Alcotest.(check string)
    "INV-3: PSBT magic = 'psbt' + 0xff (BIP-174 pin)"
    "psbt\xff" m

(* INV-4: PSBT highest version is 0 (Core-parity; PSBTv2 not supported). *)
let test_inv4_highest_version_is_zero () =
  Alcotest.(check int32)
    "INV-4: PSBT highest version = 0 (Core parity; PSBTv2 not implemented)"
    0l Psbt.psbt_highest_version

(* INV-5: empty_input / empty_output have all None / [] fields.  Used as
   a regression-pin against accidental field additions that forget to
   zero-init. *)
let test_inv5_empty_constructors_are_clean () =
  let i = Psbt.empty_input in
  let o = Psbt.empty_output in
  let i_clean =
    i.non_witness_utxo = None
    && i.witness_utxo = None
    && i.partial_sigs = []
    && i.sighash_type = None
    && i.redeem_script = None
    && i.witness_script = None
    && i.bip32_derivations = []
    && i.final_scriptsig = None
    && i.final_scriptwitness = None
    && i.tap_key_sig = None
    && i.tap_script_sigs = []
    && i.tap_leaf_scripts = []
    && i.tap_bip32_derivations = []
    && i.tap_internal_key = None
    && i.tap_merkle_root = None
    && i.unknown = []
  in
  let o_clean =
    o.redeem_script = None
    && o.witness_script = None
    && o.bip32_derivations = []
    && o.tap_internal_key = None
    && o.tap_tree = None
    && o.tap_bip32_derivations = []
    && o.musig2_participants = []
    && o.unknown = []
  in
  Alcotest.(check bool)
    "INV-5: empty_input / empty_output are clean (W47 pin)"
    true (i_clean && o_clean)

(* INV-6: create() strips scriptSig and witness from the unsigned tx so
   that round-trip cannot accidentally carry signatures (BIP-174 §
   "Unsigned transaction"). *)
let test_inv6_create_strips_signatures () =
  let tx = mk_simple_tx () in
  let dirty_tx = {
    tx with
    inputs = List.map (fun (i : Types.tx_in) ->
      let s = Cstruct.create 1 in
      Cstruct.set_uint8 s 0 0xff;
      { i with script_sig = s }
    ) tx.inputs;
  } in
  let psbt = Psbt.create dirty_tx in
  let inp = List.hd psbt.tx.inputs in
  Alcotest.(check int)
    "INV-6: Psbt.create strips scriptSig (BIP-174 pin)"
    0 (Cstruct.length inp.script_sig)

(* INV-7: W41 next-role classification surfaces "finalizer" when all
   required sigs are present but the input hasn't been finalized.
   Smoke-test via a synthesized P2WPKH input with one partial sig and
   witness_utxo present. *)
let test_inv7_next_role_finalizer_for_complete_sig () =
  let spk = Cstruct.create 22 in
  Cstruct.set_uint8 spk 0 0x00; Cstruct.set_uint8 spk 1 0x14;
  let utxo : Types.tx_out = { value = 1L; script_pubkey = spk } in
  let pk = Cstruct.create 33 in
  Cstruct.set_uint8 pk 0 0x02;
  let sg = Cstruct.create 71 in
  let ps : Psbt.partial_sig = { pubkey = pk; signature = sg } in
  let inp = { Psbt.empty_input with
              witness_utxo = Some utxo;
              partial_sigs = [ps] } in
  let role = Psbt.input_next_role inp in
  Alcotest.(check string)
    "INV-7: per-input next-role = 'finalizer' when all sigs present \
     (W41 pin)"
    "finalizer" role

(* INV-8: FIX-70 default RBF sequence is preserved by serialize/deserialize. *)
let test_inv8_rbf_sequence_round_trip () =
  let tx = mk_simple_tx () in
  let psbt = Psbt.create tx in
  let bytes = Psbt.serialize psbt in
  match Psbt.deserialize bytes with
  | Ok p2 ->
    let s = (List.hd p2.tx.inputs).sequence in
    Alcotest.(check int32)
      "INV-8: nSequence MAX_BIP125_RBF_SEQUENCE round-trips (FIX-70 pin)"
      0xFFFFFFFDl s
  | Error e ->
    Alcotest.failf "INV-8: deserialize failed: %s" (Psbt.string_of_error e)

(* ============================================================================
   Test runner
   ============================================================================ *)

let () =
  Random.self_init ();
  Alcotest.run "W137 PSBT v0/v2 (BIP-174 / BIP-371 / BIP-373)" [
    "G1-G5 Magic + global map + version", [
      Alcotest.test_case "G1: magic short stream rejected (BUG-W137-25)" `Quick test_g1_magic_short_stream_returns_error;
      Alcotest.test_case "G1: magic bad bytes rejected" `Quick test_g1_magic_bad_bytes_returns_error;
      Alcotest.test_case "G2: PSBT_GLOBAL_UNSIGNED_TX no key-size check (BUG-W137-7)" `Quick test_g2_global_unsigned_tx_no_key_size_check;
      Alcotest.test_case "G3: unsigned tx scriptSig emptiness enforced (Core-parity)" `Quick test_g3_unsigned_tx_emptiness_check;
      Alcotest.test_case "G4: PSBT_GLOBAL_VERSION no key-size check (BUG-W137-7)" `Quick test_g4_global_version_no_key_size_check;
      Alcotest.test_case "G5: version > 0 rejected (Core-parity)" `Quick test_g5_unsupported_version_rejected;
    ];
    "G6-G10 Per-input dup/size validation", [
      Alcotest.test_case "G6: PSBT_IN_NON_WITNESS_UTXO no key-size check (BUG-W137-7)" `Quick test_g6_in_non_witness_utxo_no_key_size_check;
      Alcotest.test_case "G7: PSBT_IN_PARTIAL_SIG no DER-strict check (BUG-W137-5)" `Quick test_g7_partial_sig_no_der_check;
      Alcotest.test_case "G7-bis: invalid pubkey-size partial_sig silently skipped (BUG-W137-6)" `Quick test_g7_partial_sig_invalid_pubkey_size_silent_skip;
      Alcotest.test_case "G8: 4 hash-preimage fields absent (BUG-W137-8)" `Quick test_g8_hash_preimage_fields_absent;
      Alcotest.test_case "G9: PSBT_IN_TAP_KEY_SIG no length check (BUG-W137-9)" `Quick test_g9_tap_key_sig_no_length_check;
      Alcotest.test_case "G10: PSBT_IN_TAP_SCRIPT_SIG no length check (BUG-W137-10)" `Quick test_g10_tap_script_sig_no_length_check;
    ];
    "G11-G15 Tap input / MuSig2 / proprietary", [
      Alcotest.test_case "G11: TAP_LEAF_SCRIPT no control-block check (BUG-W137-11)" `Quick test_g11_tap_leaf_script_no_control_block_check;
      Alcotest.test_case "G12: TAP_BIP32_DERIVATION no value-length check (BUG-W137-12)" `Quick test_g12_tap_bip32_no_value_length_check;
      Alcotest.test_case "G13: IN_MUSIG2_PARTICIPANT_PUBKEYS absent (BUG-W137-13)" `Quick test_g13_in_musig2_participants_absent;
      Alcotest.test_case "G14: IN_MUSIG2_PUB_NONCE absent (BUG-W137-14)" `Quick test_g14_in_musig2_pub_nonce_absent;
      Alcotest.test_case "G15: IN_MUSIG2_PARTIAL_SIG absent (BUG-W137-15)" `Quick test_g15_in_musig2_partial_sig_absent;
    ];
    "G16-G20 Per-output validation + tap tree", [
      Alcotest.test_case "G16: OUT_REDEEM/WITNESSSCRIPT no key-size check (BUG-W137-7)" `Quick test_g16_out_redeem_witness_no_key_size_check;
      Alcotest.test_case "G17: OUT_TAP_TREE no TaprootBuilder validation (P0-CDIV BUG-W137-3)" `Quick test_g17_tap_tree_no_builder_validation;
      Alcotest.test_case "G18: OUT_TAP_BIP32_DERIVATION no length check (BUG-W137-12)" `Quick test_g18_out_tap_bip32_no_value_length_check;
      Alcotest.test_case "G19: OUT_MUSIG2_PARTICIPANT no pubkey check (BUG-W137-16)" `Quick test_g19_out_musig2_no_pubkey_validity_check;
      Alcotest.test_case "G20: PROPRIETARY (0xFC) fields absent (BUG-W137-17)" `Quick test_g20_proprietary_fields_absent;
    ];
    "G21-G25 Top-level / size limit / lifecycle", [
      Alcotest.test_case "G21: max_psbt_size defined but unused (P2 BUG-W137-23)" `Quick test_g21_max_psbt_size_unenforced;
      Alcotest.test_case "G22: trailing-junk PSBT accepted (BUG-W137-18)" `Quick test_g22_no_extra_data_after_psbt_rejection;
      Alcotest.test_case "G23: non_witness_utxo hash check absent (BUG-W137-19)" `Quick test_g23_no_non_witness_utxo_hash_check;
      Alcotest.test_case "G24: count-mismatch error path drift (BUG-W137-26)" `Quick test_g24_count_mismatch_error_path_drift;
      Alcotest.test_case "G25: no PSBTInputSignedAndVerified (P0-CDIV BUG-W137-4)" `Quick test_g25_no_signed_and_verified_check;
    ];
    "G26-G30 RPC surface + analyzepsbt fidelity", [
      Alcotest.test_case "G26: joinpsbts RPC absent (BUG-W137-20)" `Quick test_g26_no_joinpsbts_rpc;
      Alcotest.test_case "G27: descriptorprocesspsbt RPC absent (BUG-W137-21)" `Quick test_g27_no_descriptorprocesspsbt_rpc;
      Alcotest.test_case "G28: psbtbumpfee RPC absent (BUG-W137-22)" `Quick test_g28_no_psbtbumpfee_rpc;
      Alcotest.test_case "G29: estimated_vsize hard-coded 0 (P0-CDIV BUG-W137-1)" `Quick test_g29_analyzepsbt_estimated_vsize_stubbed;
      Alcotest.test_case "G29-bis: estimated_feerate units wrong (P0-CDIV BUG-W137-2)" `Quick test_g29_analyzepsbt_estimated_feerate_units_wrong;
      Alcotest.test_case "G30: no RemoveUnnecessaryTransactions (P2 BUG-W137-24)" `Quick test_g30_no_remove_unnecessary_transactions;
    ];
    "Invariant pins (preserve W47 / W41 / FIX-70)", [
      Alcotest.test_case "INV-1: PSBT round-trip byte-identical (W47)" `Quick test_inv1_round_trip_byte_identical;
      Alcotest.test_case "INV-2: combine(p, p) byte-identical to p (W47)" `Quick test_inv2_combine_idempotent;
      Alcotest.test_case "INV-3: PSBT magic = 'psbt' + 0xff" `Quick test_inv3_magic_bytes;
      Alcotest.test_case "INV-4: PSBT highest version = 0" `Quick test_inv4_highest_version_is_zero;
      Alcotest.test_case "INV-5: empty_input/output clean (W47)" `Quick test_inv5_empty_constructors_are_clean;
      Alcotest.test_case "INV-6: create() strips scriptSig (BIP-174)" `Quick test_inv6_create_strips_signatures;
      Alcotest.test_case "INV-7: next_role = 'finalizer' for complete sig (W41)" `Quick test_inv7_next_role_finalizer_for_complete_sig;
      Alcotest.test_case "INV-8: nSequence 0xfffffffd round-trips (FIX-70)" `Quick test_inv8_rbf_sequence_round_trip;
    ];
  ]
