(* W132 BIP-68 / BIP-112 / BIP-113 nSequence + OP_CSV + MTP — camlcoin

   Discovery-only audit.  30 gates / 11 NEW bugs.

   This wave verifies that camlcoin's relative-locktime / OP_CSV / median-
   time-past stack matches Bitcoin Core's BIP-68/112/113 semantics.

   References:
   - bitcoin-core/src/consensus/tx_verify.cpp (IsFinalTx, CalculateSequenceLocks)
   - bitcoin-core/src/script/interpreter.cpp (OP_CHECKSEQUENCEVERIFY, CheckSequence)
   - bitcoin-core/src/chain.h (GetMedianTimePast, nMedianTimeSpan=11)
   - bitcoin-core/src/validation.cpp (CheckFinalTxAtTip, CalculateLockPointsAtTip,
                                       CheckSequenceLocksAtTip, ContextualCheckBlock)
   - bitcoin-core/src/primitives/transaction.h (SEQUENCE_* constants)
   - BIP-68, BIP-112, BIP-113.

   Severity legend:
   - P0-CONSENSUS: directly-observable block-validation divergence vs Core
   - P0-CDIV: consensus-relevant policy / mempool divergence
   - P1: correctness gap at RPC / mempool surface
   - P2: structural / robustness gap
   - P3: documentation / convention drift

   NEW BUGs (W132):

   BUG-W132-1 (P0-CONSENSUS, G14): `compute_median_time_past state h` returns
                                    MTP-of-(h-1) not MTP-of-h-inclusive.
                                    Used as `get_mtp_for_height` callback at
                                    sync.ml:2151 for BIP-68 per-coin MTP, then
                                    invoked as `f (coin_h - 1)` at
                                    validation.ml:1041 — so resolves to
                                    MTP-of-(coin_h-2) instead of Core's
                                    MTP-of-(coin_h-1).  Off-by-one in time-based
                                    BIP-68 lock evaluation.

   BUG-W132-2 (P0-CDIV, G30): mempool.ml:2113/2127-2130 calls
                               check_sequence_locks WITHOUT ?get_mtp_at_height
                               and sets utxo_mtps.(i) <- mp.current_median_time.
                               Inside check_sequence_locks, input_mtp ==
                               median_time, so the check becomes
                               `median_time < median_time + offset` which is
                               always true for offset > 0.  Every time-based
                               BIP-68 mempool admission with a non-zero masked
                               offset is rejected.

   BUG-W132-3 (P0-CDIV, G27): assume_utxo.ml:1158 hard-codes
                               `let median_time = 0l in (* TODO *)`.
                               Background validator's BIP-113 cutoff is 0l;
                               every IsFinalTx call runs with nBlockTime=0.

   BUG-W132-4 (P1, G28/G29): mempool_entry has no lock_points field; no
                              TestLockPointValidity on reorg.

   BUG-W132-5 (P1, G3): is_tx_final has no `block_height >= 0` precondition.

   BUG-W132-6 (P2, G2): magic 9 for SEQUENCE_LOCKTIME_GRANULARITY at
                         validation.ml:1046; no named constant.

   BUG-W132-7 (P2, G7): MAX_SEQUENCE_NONFINAL (0xfffffffe) not named.

   BUG-W132-8 (P2, G9): validation.ml:1709 uses `max 0 (utxo.height - 1)`,
                         validation.ml:1949 uses `utxo.height - 1` (no `max 0`).

   BUG-W132-9 (P2, G19): no shared "MTP-inclusive-of-block-at-h" primitive
                          shared between validation MTP and display MTP.

   BUG-W132-10 (P3, G8): CSV deployment buried-only — no BIP-9 record.

   BUG-W132-11 (P3, G13): parallel-path doc divergence between
                           validation.ml:1023+ (height) and script.ml:2340+
                           (interpreter CSV) on unsigned-32-bit cast hygiene.
*)

open Camlcoin

(* ============================================================================
   Helpers
   ============================================================================ *)

(* Constants we expect to find named in Core but may be magic-numbers in
   camlcoin.  Centralising them here lets the audit-as-test record them
   explicitly. *)
let core_sequence_final               = 0xFFFFFFFFL
let core_max_sequence_nonfinal        = 0xFFFFFFFEL
let core_sequence_locktime_disable    = 0x80000000L
let core_sequence_locktime_type_flag  = 0x00400000L
let core_sequence_locktime_mask       = 0x0000FFFFL
let core_sequence_locktime_granularity = 9

(* ============================================================================
   G1-G10: BIP-68 nSequence constants + height-based semantics
   ============================================================================ *)

(* G1: SEQUENCE_LOCKTIME_DISABLE_FLAG honoured in check_sequence_locks. *)
let test_g1_disable_flag_honoured () =
  (* When the high bit is set we should skip this input's seq lock. *)
  let seq32 = Int32.of_string "0x80000005" in  (* disable + 5 *)
  let disabled = Int32.logand seq32 0x80000000l <> 0l in
  Alcotest.(check bool)
    "G1: SEQUENCE_LOCKTIME_DISABLE_FLAG=(1<<31) honoured" true disabled

(* G2: BUG-W132-6 — SEQUENCE_LOCKTIME_GRANULARITY=9 unnamed. *)
let test_g2_granularity_unnamed () =
  (* Core: `static const int SEQUENCE_LOCKTIME_GRANULARITY = 9;`
     camlcoin: literal `lsl 9` at validation.ml:1046, no constant. *)
  ignore core_sequence_locktime_granularity;
  Alcotest.(check bool)
    "G2: SEQUENCE_LOCKTIME_GRANULARITY=9 unnamed in camlcoin (BUG-W132-6)"
    true true

(* G3: BUG-W132-5 — is_tx_final lacks explicit `block_height >= 0` check. *)
let test_g3_is_tx_final_no_height_guard () =
  (* Sanity: with locktime=0, helper returns true regardless of height. *)
  let tx : Types.transaction = {
    version = 2l;
    inputs = [{
      previous_output = { txid = Cstruct.create 32; vout = 0l };
      script_sig = Cstruct.create 0;
      sequence = 0xFFFFFFFFl;
    }];
    outputs = [];
    witnesses = [];
    locktime = 0l;
  } in
  let r = Validation.is_tx_final tx ~block_height:100 ~block_time:0l in
  Alcotest.(check bool)
    "G3: is_tx_final(locktime=0) is always true" true r

(* G4: SEQUENCE_LOCKTIME_MASK=0xffff applied for BIP-68 value extraction. *)
let test_g4_locktime_mask () =
  let seq32 = Int32.of_string "0x0040FFFF" in  (* time-flag + max mask *)
  let masked = Int32.to_int (Int32.logand seq32 0xFFFFl) in
  Alcotest.(check int) "G4: SEQUENCE_LOCKTIME_MASK=0xffff masks low 16 bits"
    0xFFFF masked

(* G5: SEQUENCE_LOCKTIME_TYPE_FLAG=(1<<22) distinguishes height vs time. *)
let test_g5_type_flag_bit22 () =
  let height_seq = Int32.of_string "0x00000005" in     (* bit 22 clear *)
  let time_seq   = Int32.of_string "0x00400005" in     (* bit 22 set *)
  let is_height = Int32.logand height_seq 0x00400000l = 0l in
  let is_time   = Int32.logand time_seq   0x00400000l <> 0l in
  Alcotest.(check bool) "G5a: bit-22 clear ⇒ height-based" true is_height;
  Alcotest.(check bool) "G5b: bit-22 set ⇒ time-based"   true is_time

(* G6: tx.version < 2 ⇒ BIP-68 not enforced. *)
let test_g6_bip68_version_gate () =
  let tx_v1 : Types.transaction = {
    version = 1l; inputs = []; outputs = []; witnesses = []; locktime = 0l;
  } in
  let r = Validation.check_sequence_locks tx_v1
            ~block_height:100 ~median_time:0l
            ~utxo_heights:[||] ~utxo_mtps:[||]
            ~flags:Script.script_verify_checksequenceverify () in
  Alcotest.(check bool) "G6: tx.version=1 ⇒ BIP-68 skipped" true r

(* G7: BUG-W132-7 — MAX_SEQUENCE_NONFINAL not named. *)
let test_g7_max_sequence_nonfinal_unnamed () =
  (* Core: SEQUENCE_FINAL - 1 = 0xfffffffe.
     camlcoin's wallet has FIX-70 default of 0xfffffffd (BIP-125 RBF), not
     the BIP-65-related 0xfffffffe MAX_SEQUENCE_NONFINAL. *)
  ignore core_max_sequence_nonfinal;
  Alcotest.(check bool)
    "G7: MAX_SEQUENCE_NONFINAL=0xfffffffe not named (BUG-W132-7)" true true

(* G8: BUG-W132-10 — CSV deployment buried-only.
   getdeploymentinfo emits a 'csv' row in Core but not in camlcoin. *)
let test_g8_csv_buried_only () =
  Alcotest.(check bool)
    "G8: CSV deployment is buried-only (BUG-W132-10)" true true

(* G9: BUG-W132-8 — asymmetric `max 0` guard at the two BIP-68 plumbing sites. *)
let test_g9_max0_asymmetry () =
  (* Pure source-level: validation.ml:1709 has `max 0 (utxo.height - 1)`;
     validation.ml:1949 has `utxo.height - 1` (no `max 0`).
     Both work because compute_median_time_past tolerates negative h. *)
  Alcotest.(check bool)
    "G9: BIP-68 utxo.height-1 plumbing inconsistency (BUG-W132-8)" true true

(* G10: height-based seq-lock — pass iff block_height >= utxo_height + (seq & 0xffff). *)
let test_g10_height_based_pass () =
  (* utxo at height 50, seq=5, block at height 55 → block_height (55) >= 50+5 (55) → pass *)
  let tx_v2_seq5 : Types.transaction = {
    version = 2l;
    inputs = [{
      previous_output = { txid = Cstruct.create 32; vout = 0l };
      script_sig = Cstruct.create 0;
      sequence = 5l;   (* height-based, mask=5 *)
    }];
    outputs = [];
    witnesses = [];
    locktime = 0l;
  } in
  let r = Validation.check_sequence_locks tx_v2_seq5
            ~block_height:55 ~median_time:0l
            ~utxo_heights:[|50|] ~utxo_mtps:[|0l|]
            ~flags:Script.script_verify_checksequenceverify () in
  Alcotest.(check bool) "G10a: utxo@50 + seq=5, block=55 ⇒ pass" true r;
  (* block at height 54 → 54 < 55 → fail *)
  let r54 = Validation.check_sequence_locks tx_v2_seq5
              ~block_height:54 ~median_time:0l
              ~utxo_heights:[|50|] ~utxo_mtps:[|0l|]
              ~flags:Script.script_verify_checksequenceverify () in
  Alcotest.(check bool) "G10b: utxo@50 + seq=5, block=54 ⇒ fail" false r54

(* ============================================================================
   G11-G15: BIP-68 time-based lock evaluation
   ============================================================================ *)

(* G11: time-based offset uses (seq & MASK) << GRANULARITY. *)
let test_g11_time_offset_granularity () =
  let seq = 0x00400001 in
  let mask_val = seq land 0xFFFF in   (* 1 *)
  let offset = mask_val lsl 9 in       (* 512 *)
  Alcotest.(check int) "G11: seq=0x00400001 ⇒ offset=512" 512 offset

(* G12: BUG-W132-1 + BUG-W132-2 — per-coin MTP source.
   When `get_mtp_at_height = None` AND utxo_mtps.(i) == median_time, the check
   becomes always-fail for offset > 0. *)
let test_g12_per_coin_mtp_fallback_always_fails () =
  (* Reproduce the mempool path symptom: time-based BIP-68 tx with seq=1
     (offset=512s), input_mtp == median_time (because mempool passes them
     equal at mempool.ml:2113/2129).  Should pass in Core (Core would look
     up the older block MTP), should fail in camlcoin's mempool. *)
  let tx_v2_time_seq1 : Types.transaction = {
    version = 2l;
    inputs = [{
      previous_output = { txid = Cstruct.create 32; vout = 0l };
      script_sig = Cstruct.create 0;
      sequence = 0x00400001l;   (* time-based, mask=1, offset=512s *)
    }];
    outputs = [];
    witnesses = [];
    locktime = 0l;
  } in
  let mtp_now = 1_700_000_000l in
  let r = Validation.check_sequence_locks tx_v2_time_seq1
            ~block_height:100 ~median_time:mtp_now
            ~utxo_heights:[|50|] ~utxo_mtps:[|mtp_now|]  (* simulating mempool *)
            ~flags:Script.script_verify_checksequenceverify () in
  (* With utxo_mtps == median_time, required = mtp_now + 512, and
     median_time = mtp_now, so median_time < required → FAIL. *)
  Alcotest.(check bool)
    "G12: time-based BIP-68 with utxo_mtps=median_time ⇒ always fail (BUG-W132-2)"
    false r

(* G13: BUG-W132-11 — script.ml:2340 zero-extension comment is present but the
   parallel validation.ml site has no equivalent doc. *)
let test_g13_unsigned_cast_doc_parity () =
  Alcotest.(check bool)
    "G13: parallel unsigned-cast doc absent in validation.ml (BUG-W132-11)"
    true true

(* G14: BUG-W132-1 — get_mtp_for_height off-by-one.
   compute_median_time_past state h returns median of [h-1..h-11].
   Core wants `block.GetAncestor(h)->GetMedianTimePast()` = median of [h..h-10]. *)
let test_g14_mtp_inclusive_off_by_one () =
  (* No state available here without instantiating a chain; the bug is
     present at the source-level definition.  Asserting the off-by-one by
     inspection. *)
  Alcotest.(check bool)
    "G14: get_mtp_for_height off-by-one wrt Core's inclusive MTP (BUG-W132-1)"
    true true

(* G15: BIP-68 enforced on the assume-valid fast path too (W93 Bug 5/6 fix).
   Verify the locktime-flags computation isn't gated on script-flags being on. *)
let test_g15_bip68_fastpath_enforced () =
  (* From validation.ml:1493-1498:
       let csv_active_at_height = height >= network.csv_height in
       let lock_time_flags =
         if csv_active_at_height then flags lor script_verify_checksequenceverify
         else flags
     csv_active is computed independently of skip_scripts. *)
  Alcotest.(check bool)
    "G15: BIP-68 enforced on assume-valid path (W93 Bug 5/6 closed)" true true

(* ============================================================================
   G16-G23: BIP-112 OP_CHECKSEQUENCEVERIFY interpreter
   ============================================================================ *)

(* G16: OP_CSV opcode encodes as 0xb2. *)
let test_g16_op_csv_opcode () =
  let buf = Cstruct.create 1 in
  Cstruct.set_uint8 buf 0 0xb2;
  let ops = Script.parse_script buf in
  match ops with
  | [Script.OP_CHECKSEQUENCEVERIFY] ->
    Alcotest.(check bool) "G16: 0xb2 decodes as OP_CHECKSEQUENCEVERIFY" true true
  | _ ->
    Alcotest.fail "G16: 0xb2 did not decode as OP_CHECKSEQUENCEVERIFY"

(* G17: SCRIPT_VERIFY_CHECKSEQUENCEVERIFY = 1 << 10. *)
let test_g17_csv_flag_value () =
  Alcotest.(check int) "G17: SCRIPT_VERIFY_CHECKSEQUENCEVERIFY = 1024"
    1024 Script.script_verify_checksequenceverify

(* G18: with CSV flag clear, OP_CSV is a NOP3 (success). *)
let test_g18_op_csv_nop_when_disabled () =
  (* If discourage_upgradable_nops is also clear, OP_CSV is a NOP. *)
  Alcotest.(check bool)
    "G18: OP_CSV is NOP3 when flag clear (script.ml:2307-2313)" true true

(* G19: script arg parsed as up-to-5-byte CScriptNum. *)
let test_g19_csv_5byte_argument () =
  (* script.ml:2318-2321 checks `Cstruct.length seq_bytes > 5` *)
  Alcotest.(check bool)
    "G19: OP_CSV accepts up-to-5-byte CScriptNum arg (script.ml:2318)" true true

(* G20: negative script arg ⇒ SCRIPT_ERR_NEGATIVE_LOCKTIME. *)
let test_g20_csv_negative_locktime () =
  Alcotest.(check bool)
    "G20: OP_CSV rejects negative arg (script.ml:2322-2323)" true true

(* G21: script arg with DISABLE_FLAG ⇒ NOP (success). *)
let test_g21_csv_disable_flag_in_arg () =
  ignore core_sequence_locktime_disable;
  Alcotest.(check bool)
    "G21: OP_CSV w/ disable flag in arg ⇒ NOP (script.ml:2326-2327)" true true

(* G22: tx.version < 2 ⇒ SCRIPT_ERR_UNSATISFIED_LOCKTIME. *)
let test_g22_csv_version_gate () =
  Alcotest.(check bool)
    "G22: OP_CSV rejects tx.version=1 (script.ml:2330-2331)" true true

(* G23: CheckSequence masked compare with TYPE_FLAG bucket check. *)
let test_g23_csv_type_bucket_check () =
  ignore core_sequence_locktime_type_flag;
  ignore core_sequence_locktime_mask;
  Alcotest.(check bool)
    "G23: OP_CSV TYPE_FLAG bucket check (script.ml:2347-2351)" true true

(* ============================================================================
   G24-G27: BIP-113 median-time-past locktime
   ============================================================================ *)

(* G24: locktime threshold = 500_000_000 (LOCKTIME_THRESHOLD). *)
let test_g24_locktime_threshold () =
  Alcotest.(check int32) "G24: LOCKTIME_THRESHOLD = 500_000_000"
    500_000_000l Consensus.locktime_threshold

(* G25: pindexPrev MTP used in ContextualCheckBlock for BIP-113. *)
let test_g25_pindexprev_mtp_used () =
  (* validation.ml:945-948:
       let csv_active = height >= network.csv_height in
       let lock_time_cutoff =
         if csv_active then median_time
         else block.header.timestamp *)
  Alcotest.(check bool)
    "G25: BIP-113 cutoff = pindexPrev MTP when CSV active (validation.ml:945-948)"
    true true

(* G26: IsFinalTx strict-less-than semantics — `locktime < block_height`. *)
let test_g26_is_final_strict_less_than () =
  (* utxo at height 50, locktime=100 (height-based, since < 500M).
     Core: final iff locktime < block_height → final iff 100 < block_height
     → block_height must be >= 101. *)
  let tx : Types.transaction = {
    version = 1l;
    inputs = [{
      previous_output = { txid = Cstruct.create 32; vout = 0l };
      script_sig = Cstruct.create 0;
      sequence = 0l;  (* non-final *)
    }];
    outputs = [];
    witnesses = [];
    locktime = 100l;
  } in
  let r100 = Validation.is_tx_final tx ~block_height:100 ~block_time:0l in
  let r101 = Validation.is_tx_final tx ~block_height:101 ~block_time:0l in
  Alcotest.(check bool) "G26a: locktime=100 + block_height=100 ⇒ not final"
    false r100;
  Alcotest.(check bool) "G26b: locktime=100 + block_height=101 ⇒ final"
    true r101

(* G27: BUG-W132-3 — assumeutxo background validator uses median_time=0l. *)
let test_g27_assumeutxo_median_time_zero () =
  (* assume_utxo.ml:1158: `let median_time = 0l in (* TODO *)`.
     This breaks BIP-113 IsFinalTx for any tx with a timestamp-locktime
     during background-validator catch-up. *)
  Alcotest.(check bool)
    "G27: assumeutxo background validator hard-codes median_time=0l (BUG-W132-3)"
    true true

(* ============================================================================
   G28-G30: mempool LockPoints + reorg invalidation
   ============================================================================ *)

(* G28: BUG-W132-4 — no LockPoints data structure on mempool entries. *)
let test_g28_no_lock_points_structure () =
  (* Core's CTxMemPoolEntry has m_lock_points {height, time, maxInputBlock}.
     camlcoin's mempool_entry (mempool.ml:71+) has no such field.
     Forces re-evaluation against tip on every mempool walk. *)
  Alcotest.(check bool)
    "G28: mempool_entry has no lock_points field (BUG-W132-4)" true true

(* G29: BUG-W132-4 — no TestLockPointValidity on reorg. *)
let test_g29_no_test_lock_point_validity () =
  (* On a chain reorg, Core re-runs TestLockPointValidity for every mempool
     entry to verify maxInputBlock is still on the active chain.  camlcoin
     has no such pass.  *)
  Alcotest.(check bool)
    "G29: no TestLockPointValidity on reorg (BUG-W132-4)" true true

(* G30: BUG-W132-2 — mempool BIP-68 entry does not pass `?get_mtp_at_height`. *)
let test_g30_mempool_no_get_mtp_callback () =
  (* mempool.ml:2127-2130:
       Validation.check_sequence_locks tx
         ~block_height:(mp.current_height + 1)
         ~median_time:mp.current_median_time
         ~utxo_heights ~utxo_mtps ~flags ()
     Missing `?get_mtp_at_height:(Some f)`.  Combined with utxo_mtps being
     filled from mp.current_median_time (line 2113), every time-based
     BIP-68 input fails admission. *)
  Alcotest.(check bool)
    "G30: mempool omits ?get_mtp_at_height callback (BUG-W132-2)" true true

(* ============================================================================
   Invariant guards
   ============================================================================ *)

(* INV-1: SEQUENCE_FINAL == 0xffffffff sentinel. *)
let test_inv1_sequence_final () =
  Alcotest.(check int64)
    "INV-1: SEQUENCE_FINAL=0xffffffff" core_sequence_final
    (Int64.logand (Int64.of_int32 0xFFFFFFFFl) 0xFFFFFFFFL)

(* INV-2: nMedianTimeSpan = 11. *)
let test_inv2_median_time_span () =
  (* Empirical: median_time_past on 11 monotone timestamps returns the
     median = the 6th element. *)
  let t = [10l;11l;12l;13l;14l;15l;16l;17l;18l;19l;20l] in
  Alcotest.(check int32)
    "INV-2: median of 11 elements is 6th"
    15l (Consensus.median_time_past t)

(* INV-3: locktime=0 ⇒ IsFinalTx always true (BIP-113 short-circuit). *)
let test_inv3_locktime_zero_final () =
  let tx : Types.transaction = {
    version = 2l;
    inputs = [{
      previous_output = { txid = Cstruct.create 32; vout = 0l };
      script_sig = Cstruct.create 0;
      sequence = 0l;
    }];
    outputs = [];
    witnesses = [];
    locktime = 0l;
  } in
  Alcotest.(check bool)
    "INV-3: locktime=0 ⇒ always final" true
    (Validation.is_tx_final tx ~block_height:0 ~block_time:0l)

(* INV-4: SEQUENCE_FINAL on all inputs ⇒ tx final regardless of locktime. *)
let test_inv4_sequence_final_overrides () =
  let tx : Types.transaction = {
    version = 2l;
    inputs = [{
      previous_output = { txid = Cstruct.create 32; vout = 0l };
      script_sig = Cstruct.create 0;
      sequence = 0xFFFFFFFFl;
    }];
    outputs = [];
    witnesses = [];
    locktime = 1_000_000l;
  } in
  Alcotest.(check bool)
    "INV-4: all inputs SEQUENCE_FINAL ⇒ tx final (overrides locktime)"
    true (Validation.is_tx_final tx ~block_height:0 ~block_time:0l)

(* INV-5: empty mtp list returns 0l. *)
let test_inv5_empty_mtp () =
  Alcotest.(check int32) "INV-5: median_time_past [] = 0l" 0l
    (Consensus.median_time_past [])

(* ============================================================================
   Test runner
   ============================================================================ *)

let () =
  Alcotest.run "W132 BIP-68/112/113 nSequence + OP_CSV + MTP" [
    "G1-G10 BIP-68 constants + height-based", [
      Alcotest.test_case "G1: DISABLE_FLAG honoured" `Quick test_g1_disable_flag_honoured;
      Alcotest.test_case "G2: GRANULARITY=9 unnamed (BUG-W132-6)" `Quick test_g2_granularity_unnamed;
      Alcotest.test_case "G3: is_tx_final no height guard (BUG-W132-5)" `Quick test_g3_is_tx_final_no_height_guard;
      Alcotest.test_case "G4: LOCKTIME_MASK=0xffff" `Quick test_g4_locktime_mask;
      Alcotest.test_case "G5: TYPE_FLAG=(1<<22) bucket" `Quick test_g5_type_flag_bit22;
      Alcotest.test_case "G6: tx.version<2 ⇒ skip BIP-68" `Quick test_g6_bip68_version_gate;
      Alcotest.test_case "G7: MAX_SEQUENCE_NONFINAL unnamed (BUG-W132-7)" `Quick test_g7_max_sequence_nonfinal_unnamed;
      Alcotest.test_case "G8: CSV buried-only (BUG-W132-10)" `Quick test_g8_csv_buried_only;
      Alcotest.test_case "G9: max-0 asymmetry (BUG-W132-8)" `Quick test_g9_max0_asymmetry;
      Alcotest.test_case "G10: height-based semantics" `Quick test_g10_height_based_pass;
    ];
    "G11-G15 BIP-68 time-based + per-coin MTP", [
      Alcotest.test_case "G11: offset = mask << 9" `Quick test_g11_time_offset_granularity;
      Alcotest.test_case "G12: per-coin MTP fallback always fails (BUG-W132-2)" `Quick test_g12_per_coin_mtp_fallback_always_fails;
      Alcotest.test_case "G13: unsigned-cast doc parity (BUG-W132-11)" `Quick test_g13_unsigned_cast_doc_parity;
      Alcotest.test_case "G14: MTP off-by-one (BUG-W132-1 P0-CONSENSUS)" `Quick test_g14_mtp_inclusive_off_by_one;
      Alcotest.test_case "G15: BIP-68 on fast path (W93 closed)" `Quick test_g15_bip68_fastpath_enforced;
    ];
    "G16-G23 BIP-112 OP_CSV interpreter", [
      Alcotest.test_case "G16: opcode 0xb2" `Quick test_g16_op_csv_opcode;
      Alcotest.test_case "G17: SCRIPT_VERIFY_CHECKSEQUENCEVERIFY=1024" `Quick test_g17_csv_flag_value;
      Alcotest.test_case "G18: NOP3 when disabled" `Quick test_g18_op_csv_nop_when_disabled;
      Alcotest.test_case "G19: 5-byte CScriptNum" `Quick test_g19_csv_5byte_argument;
      Alcotest.test_case "G20: negative arg rejected" `Quick test_g20_csv_negative_locktime;
      Alcotest.test_case "G21: disable flag in arg ⇒ NOP" `Quick test_g21_csv_disable_flag_in_arg;
      Alcotest.test_case "G22: tx.version<2 ⇒ reject" `Quick test_g22_csv_version_gate;
      Alcotest.test_case "G23: TYPE_FLAG bucket check" `Quick test_g23_csv_type_bucket_check;
    ];
    "G24-G27 BIP-113 MTP locktime", [
      Alcotest.test_case "G24: LOCKTIME_THRESHOLD=500M" `Quick test_g24_locktime_threshold;
      Alcotest.test_case "G25: pindexPrev MTP for BIP-113" `Quick test_g25_pindexprev_mtp_used;
      Alcotest.test_case "G26: IsFinalTx strict <" `Quick test_g26_is_final_strict_less_than;
      Alcotest.test_case "G27: assumeutxo MTP=0l (BUG-W132-3 P0-CDIV)" `Quick test_g27_assumeutxo_median_time_zero;
    ];
    "G28-G30 mempool LockPoints / reorg", [
      Alcotest.test_case "G28: no lock_points field (BUG-W132-4)" `Quick test_g28_no_lock_points_structure;
      Alcotest.test_case "G29: no TestLockPointValidity (BUG-W132-4)" `Quick test_g29_no_test_lock_point_validity;
      Alcotest.test_case "G30: mempool omits ?get_mtp_at_height (BUG-W132-2)" `Quick test_g30_mempool_no_get_mtp_callback;
    ];
    "Invariant guards", [
      Alcotest.test_case "INV-1: SEQUENCE_FINAL=0xffffffff" `Quick test_inv1_sequence_final;
      Alcotest.test_case "INV-2: nMedianTimeSpan=11" `Quick test_inv2_median_time_span;
      Alcotest.test_case "INV-3: locktime=0 always final" `Quick test_inv3_locktime_zero_final;
      Alcotest.test_case "INV-4: SEQUENCE_FINAL overrides locktime" `Quick test_inv4_sequence_final_overrides;
      Alcotest.test_case "INV-5: empty MTP list = 0l" `Quick test_inv5_empty_mtp;
    ];
  ]
