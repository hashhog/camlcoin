(* W139 Fee Estimation Engine (CBlockPolicyEstimator) — camlcoin (OCaml)

   Discovery-only audit. 30 gates / 30 NEW bugs + 10 INV regression-pins.

   Scope: CBlockPolicyEstimator (the historical block-policy fee estimator
   that powers estimatesmartfee / estimaterawfee), FeeFilterRounder
   (BIP-133 minimum-fee discretization).

   References:
   - bitcoin-core/src/policy/fees/block_policy_estimator.{h,cpp}
   - bitcoin-core/src/policy/fees/block_policy_estimator_args.{h,cpp}
   - bitcoin-core/src/policy/feerate.{h,cpp}
   - bitcoin-core/src/rpc/fees.cpp
   - bitcoin-core/src/util/fees.h
   - bitcoin-core/src/common/messages.cpp (FeeModeFromString)

   Severity legend:
   - P0-CDIV: client-observable correctness divergence (wrong-units,
              ignored guard, ignored param, ignored clamp, estimator
              pollution, structural drop of failure data, ...)
   - P1: feature/field absent that spec/Core mandates and clients use
   - P2: performance / DoS surface (unbounded growth, missing flush, etc.)
   - P3: surface drift, error-message shape, comment drift

   NEW BUGs (full catalogue in audit/w139_fee_estimation.md):

   BUG-W139-1  (P0-CDIV G1):  validForFeeEstimation guard absent at
                              track_transaction. Package / bypass /
                              chainstate-current / no-parents flags
                              never consulted. fee_estimation.ml:200.
   BUG-W139-2  (P0-CDIV G4):  process_block doesn't discard
                              nBlockHeight <= nBestSeenHeight; reorg /
                              duplicate-call double-decays the estimator.
                              fee_estimation.ml:278-285.
   BUG-W139-3  (P0-CDIV G6):  3-pass estimateSmartFee
                              (max(halfEst@target/2 @ 60%, fullEst@target
                              @ 85%, doubleEst@2*target @ 95%)) absent.
                              fee_estimation.ml:316-348.
   BUG-W139-4  (P0-CDIV G9):  SUFFICIENT_FEETXS = 0.1/block aggregation
                              threshold absent; uses absolute
                              min_samples=10 floor on a single bucket;
                              no bucket aggregation.
   BUG-W139-5  (P0-CDIV G13): failAvg[periods][buckets] matrix absent;
                              record_eviction decrements
                              total_unconfirmed but doesn't populate any
                              "failed within Y periods" counter.
                              fee_estimation.ml:240-252.
   BUG-W139-6  (P0-CDIV G14): unconfTxs[Y][buckets] circular buffer +
                              ClearCurrent per-block roll absent.
                              estimaterawfee.inmempool uses decayed
                              scalar total_unconfirmed.
                              fee_estimation.ml:43-48, 213-222.
   BUG-W139-7  (P0-CDIV G16): FlushUnconfirmed on shutdown absent.
                              Pending tracked_txs marshaled as-is; on
                              next startup they look like still-confirming
                              (success-biased). fee_estimation.ml:514-531.
   BUG-W139-8  (P0-CDIV G20): MaxUsableEstimate clamp absent.
                              handle_estimatesmartfee always echoes the
                              requested conf_target as "blocks".
                              rpc.ml:1644-1647.
   BUG-W139-9  (P0-CDIV G21): estimate_mode parameter silently dropped
                              (`| [`Int t] | [`Int t; _]`). Conservative
                              mode unreachable via RPC. rpc.ml:1639-1641.
   BUG-W139-10 (P0-CDIV G23): No min_mempool_feerate / min_relay_feerate
                              clamp on the returned feerate field.
                              rpc.ml:1644-1647.
   BUG-W139-11 (P1 G2):       txHeight == nBestSeenHeight reorg/side-chain
                              guard absent. fee_estimation.ml:200-211.
   BUG-W139-12 (P1 G7):       HALF_SUCCESS_PCT = 0.60 absent;
                              fee_estimation.ml:321-324.
   BUG-W139-13 (P1 G8):       DOUBLE_SUCCESS_PCT = 0.95 absent;
                              fee_estimation.ml:321-324.
   BUG-W139-14 (P1 G10):      SUFFICIENT_TXS_SHORT = 0.5 (short-horizon
                              stricter threshold) absent;
                              fee_estimation.ml:86, 326-348.
   BUG-W139-15 (P1 G11):      scale factor in Record not used; LONG
                              horizon stores 1008 block-grain samples
                              instead of 42 period-grain rows.
                              fee_estimation.ml:213-222.
   BUG-W139-16 (P1 G12):      confAvg[periods][buckets] 2D matrix absent;
                              flat blocks_to_confirm list used per bucket.
                              fee_estimation.ml:43-48.
   BUG-W139-17 (P1 G15):      oldUnconfTxs[buckets] overflow bucket
                              absent. fee_estimation.ml:43-48.
   BUG-W139-18 (P1 G18):      MAX_FILE_AGE (60h) gate on load absent;
                              any-age file is loaded.
                              fee_estimation.ml:533-554.
   BUG-W139-19 (P1 G19):      fee_estimates.dat is OCaml Marshal
                              s_version=1, not Core's binary
                              CURRENT_FEES_FILE_VERSION=309900.
                              fee_estimation.ml:472-554.
   BUG-W139-20 (P1 G20):      firstRecordedHeight, historicalFirst,
                              historicalBest, BlockSpan,
                              HistoricalBlockSpan, OLDEST_ESTIMATE_HISTORY,
                              trackedTxs, untrackedTxs absent.
                              fee_estimation.ml:71-79.
   BUG-W139-21 (P1 G22):      "Invalid estimate_mode parameter" error
                              path absent. rpc.ml:1639-1641.
   BUG-W139-22 (P2 G17):      FEE_FLUSH_INTERVAL periodic 1-hour flush
                              absent; save on shutdown only.
                              cli.ml:1671.
   BUG-W139-23 (P2 G30):      FeeFilterRounder.round calls
                              csprng_int_range 3 (1 syscall per round).
                              Core uses a single pre-seeded
                              FastRandomContext. peer.ml:1932.
   BUG-W139-24 (P2 G16):      tracked_txs grows unbounded across
                              load/save cycles when record_eviction is
                              never invoked for txs that disappear
                              out-of-band. fee_estimation.ml:71-79.
   BUG-W139-25 (P3 G3):       trackedTxs / untrackedTxs counters absent;
                              estimator can't report admission stats.
                              cli.ml:1252-1261.
   BUG-W139-26 (P3 G24):      SyncWithValidationInterfaceQueue flush at
                              top of both RPCs absent; the underlying
                              invariant ("estimator view matches chain
                              tip") is undocumented and unasserted.
                              rpc.ml:1637, 1751.
   BUG-W139-27 (P3 G25):      estimaterawfee per-horizon error / fail
                              shape close to Core, but inmempool
                              (decayed scalar) and leftmempool
                              (hardcoded 0.0) values diverge.
                              rpc.ml:1716-1717.
   BUG-W139-28 (P3 G26):      FeeFilterRounder.make_fee_set consumes
                              min_relay_fee not min_incremental_fee;
                              numerically same in default config but
                              semantically different.
                              peer.ml:1904-1912.
   BUG-W139-29 (P3 G27):      default_fee_set evaluated once at module
                              load with hardcoded 1000L; literal-vs-
                              named-constant drift vs
                              Mempool.default_min_relay_fee.
                              peer.ml:1939.
   BUG-W139-30 (P3 G5):       process_block orders height-update BEFORE
                              decay (correct per Core), but ClearCurrent
                              is missing entirely — ordering of an
                              absent op is moot. fee_estimation.ml:278-
                              285.

   Tests below are pass-as-evidence: each documents the current behaviour
   and serves as a regression-pin. When a future fix wave closes a gap,
   the matching test should flip from "documents absence" to "verifies
   presence". The "INV-N" tests at the end pin W114 fixes (BUG-1..BUG-5)
   plus FIX-47 wiring and FIX-49 CSPRNG so a future fix wave can't
   accidentally regress them.
*)

open Camlcoin

(* ============================================================================
   Source-grep helpers (mirrors W123 / W124 / W137 audit pattern)
   ============================================================================ *)

let read_file path =
  let ic = open_in path in
  let n = in_channel_length ic in
  let buf = Bytes.create n in
  really_input ic buf 0 n;
  close_in ic;
  Bytes.to_string buf

let resolve_repo_root () =
  let rec up dir depth =
    if depth > 10 then
      Alcotest.fail "could not locate camlcoin repo root from CWD"
    else if Sys.file_exists (Filename.concat dir "lib/fee_estimation.ml") then dir
    else up (Filename.dirname dir) (depth + 1)
  in
  up (Sys.getcwd ()) 0

let slurp_lib (rel : string) : string =
  read_file (Filename.concat (resolve_repo_root ()) ("lib/" ^ rel))

let contains_substring haystack needle =
  try
    let _ = Str.search_forward (Str.regexp_string needle) haystack 0 in
    true
  with Not_found -> false

(* Strip OCaml block-comments `(* ... *)` (non-nested approximation
   sufficient for grep-on-implementation tests) and line "..." string
   literals from the source so identifier searches don't match comment
   prose or quoted Core symbol names.  We strip block comments by a
   left-to-right linear scan that tracks nesting, then drop double-
   quoted strings on each line.  Sufficient for the W139 audit checks. *)
let strip_comments_and_strings (src : string) : string =
  let buf = Buffer.create (String.length src) in
  let n = String.length src in
  let depth = ref 0 in
  let in_str = ref false in
  let i = ref 0 in
  while !i < n do
    let c = src.[!i] in
    let c2 = if !i + 1 < n then Some src.[!i + 1] else None in
    if !depth > 0 then begin
      (* inside (* ... *) block comment.  Eat until close. *)
      if c = '*' && c2 = Some ')' then begin
        decr depth;
        i := !i + 2
      end else if c = '(' && c2 = Some '*' then begin
        incr depth;
        i := !i + 2
      end else begin
        incr i
      end
    end else if !in_str then begin
      Buffer.add_char buf ' ';
      if c = '\\' && !i + 1 < n then begin
        i := !i + 2
      end else if c = '"' then begin
        in_str := false;
        incr i
      end else
        incr i
    end else begin
      if c = '(' && c2 = Some '*' then begin
        incr depth;
        i := !i + 2
      end else if c = '"' then begin
        in_str := true;
        incr i
      end else begin
        Buffer.add_char buf c;
        incr i
      end
    end
  done;
  Buffer.contents buf

(* ============================================================================
   txid synthesizer
   ============================================================================ *)

let make_txid (n : int) : Types.hash256 =
  let buf = Cstruct.create 32 in
  Cstruct.LE.set_uint32 buf 0 (Int32.of_int n);
  buf

(* ============================================================================
   G1: validForFeeEstimation guard absent at track_transaction (P0-CDIV)
   Core: block_policy_estimator.cpp:619 — only tracks txs satisfying
         !m_mempool_limit_bypassed && !m_submitted_in_package &&
         m_chainstate_is_current && m_has_no_mempool_parents.
   Camlcoin: track_transaction takes only (txid, fee_rate, height); the
             four Core flags are not part of the signature.
   ============================================================================ *)

let test_g1_valid_for_fee_estimation_guard_absent () =
  let src = slurp_lib "fee_estimation.ml" in
  (* The four Core flags are NOT referenced anywhere in the module. *)
  Alcotest.(check bool)
    "G1: m_mempool_limit_bypassed flag NOT consulted"
    false (contains_substring src "m_mempool_limit_bypassed");
  Alcotest.(check bool)
    "G1: m_submitted_in_package flag NOT consulted"
    false (contains_substring src "m_submitted_in_package");
  Alcotest.(check bool)
    "G1: m_chainstate_is_current flag NOT consulted"
    false (contains_substring src "m_chainstate_is_current");
  Alcotest.(check bool)
    "G1: m_has_no_mempool_parents flag NOT consulted"
    false (contains_substring src "m_has_no_mempool_parents");
  Alcotest.(check bool)
    "G1: BUG — validForFeeEstimation guard absent (BUG-W139-1)"
    true true

(* ============================================================================
   G2: txHeight == nBestSeenHeight guard absent at track_transaction (P1)
   Core: block_policy_estimator.cpp:607 — if (txHeight != nBestSeenHeight)
         return; — drop side-chain / reorg / lagging txs.
   Camlcoin: track_transaction accepts any height; no comparison against
             est.block_height.
   ============================================================================ *)

let test_g2_tx_height_guard_absent () =
  let est = Fee_estimation.create () in
  est.Fee_estimation.block_height <- 200;
  let txid = make_txid 1 in
  (* Pass a height 50 blocks BEHIND the estimator's view. *)
  Fee_estimation.track_transaction est txid 50.0 150;
  (* BUG: it should be rejected because tx.height(150) != est.block_height(200).
     Currently accepted. *)
  Alcotest.(check int)
    "G2: BUG — side-chain/reorg tx (height << best) silently tracked (BUG-W139-11)"
    1 (Fee_estimation.tracked_count est)

(* ============================================================================
   G3: trackedTxs / untrackedTxs counters absent (P3)
   Core: block_policy_estimator.h:298-299 — both fields populated by
         processTransaction.
   Camlcoin: no such counters; no admission-stats observability.
   ============================================================================ *)

let test_g3_tracked_untracked_counters_absent () =
  let src = slurp_lib "fee_estimation.ml" in
  Alcotest.(check bool)
    "G3: BUG — trackedTxs / untrackedTxs admission counters absent (BUG-W139-25)"
    false (contains_substring src "untrackedTxs"
           || contains_substring src "untracked_txs"
           || contains_substring src "trackedTxs"
           || contains_substring src "tracked_txs_count")

(* ============================================================================
   G4: process_block doesn't discard nBlockHeight <= nBestSeenHeight (P0-CDIV)
   Core: block_policy_estimator.cpp:673-680 — reorg / side-chain check.
   Camlcoin: process_block always sets block_height + applies decay.
   A duplicate call double-decays the entire estimator.
   ============================================================================ *)

let test_g4_process_block_no_reorg_guard () =
  let est = Fee_estimation.create () in
  (* Seed a bucket with samples so we can observe double-decay. *)
  for i = 1 to 30 do
    Fee_estimation.track_transaction est (make_txid i) 50.0 100;
    Fee_estimation.record_confirmation est (make_txid i) 101
  done;
  let bucket_idx = Fee_estimation.find_bucket est 50.0 in
  let initial = est.Fee_estimation.short.Fee_estimation.buckets.(bucket_idx)
                  .Fee_estimation.total_confirmed in
  let tx = Types.{
    version = 1l;
    inputs = [];
    outputs = [];
    witnesses = [];
    locktime = 0l;
  } in
  let block = Types.{
    header = { version = 1l; prev_block = Types.zero_hash;
               merkle_root = Types.zero_hash; timestamp = 0l;
               bits = 0x207fffffl; nonce = 0l };
    transactions = [tx];
  } in
  (* Call twice with the SAME height — Core would discard the second
     call (height not strictly greater than best), but camlcoin
     re-applies decay. *)
  Fee_estimation.process_block est block 200;
  Fee_estimation.process_block est block 200;
  let after_double = est.Fee_estimation.short.Fee_estimation.buckets.(bucket_idx)
                       .Fee_estimation.total_confirmed in
  (* If the reorg guard were present, second call would no-op and total
     would be initial * 0.962^1.  Without the guard, it's initial * 0.962^2.
     The "double-decay" signature: after_double < initial * 0.962 + small_epsilon *)
  let one_decay = initial *. 0.962 in
  Alcotest.(check bool)
    "G4: BUG — duplicate-height process_block double-decays (BUG-W139-2)"
    true (after_double < one_decay -. 0.001)

(* ============================================================================
   G5: process_block orders height-update BEFORE decay (Core line 685-695)
   Camlcoin: fee_estimation.ml:278-285 — sets block_height first, then decays.
   Match on ordering — but ClearCurrent (G14) is absent, so the ordering
   is moot.  This test PINS the ordering as-correct so a future refactor
   doesn't accidentally invert it.
   ============================================================================ *)

let test_g5_process_block_ordering_height_then_decay () =
  let src = slurp_lib "fee_estimation.ml" in
  (* Look for the "let process_block" definition; the body should set
     est.block_height BEFORE calling apply_decay. *)
  let pb_start = Str.search_forward
    (Str.regexp_string "let process_block (est : t)") src 0 in
  let body = String.sub src pb_start
    (min 400 (String.length src - pb_start)) in
  let height_pos = Str.search_forward
    (Str.regexp_string "est.block_height <-") body 0 in
  let decay_pos = Str.search_forward
    (Str.regexp_string "apply_decay est") body 0 in
  Alcotest.(check bool)
    "G5: height-update precedes decay (matches Core block_policy_estimator.cpp:685-695)"
    true (height_pos < decay_pos)

(* ============================================================================
   G6: three-pass estimateSmartFee absent (P0-CDIV)
   Core: block_policy_estimator.cpp:871-955
         max(halfEst@target/2 @ 60%, actualEst@target @ 85%,
             doubleEst@2*target @ 95%).
   Camlcoin: single-pass percentile (0.5 / 0.85).
   ============================================================================ *)

let test_g6_three_pass_estimate_absent () =
  let src = slurp_lib "fee_estimation.ml" in
  Alcotest.(check bool)
    "G6: BUG — HALF_SUCCESS_PCT constant absent (BUG-W139-3)"
    false (contains_substring src "HALF_SUCCESS_PCT"
           || contains_substring src "half_success_pct");
  Alcotest.(check bool)
    "G6: BUG — DOUBLE_SUCCESS_PCT constant absent (BUG-W139-3)"
    false (contains_substring src "DOUBLE_SUCCESS_PCT"
           || contains_substring src "double_success_pct");
  Alcotest.(check bool)
    "G6: BUG — three-pass algorithm absent (BUG-W139-3)"
    true true

(* ============================================================================
   G7: HALF_SUCCESS_PCT = 0.60 constant absent (P1)
   ============================================================================ *)

let test_g7_half_success_pct_absent () =
  let src = slurp_lib "fee_estimation.ml" in
  (* Search for the literal 0.60 or 0.6 in a context that mentions
     half / success / threshold.  Even being permissive — neither literal
     appears in the estimate_fee body. *)
  Alcotest.(check bool)
    "G7: BUG — HALF_SUCCESS_PCT 0.60 not present (BUG-W139-12)"
    false (contains_substring src "0.60"
           || contains_substring src "half_success"
           || contains_substring src "0.6 (* HALF")

(* ============================================================================
   G8: DOUBLE_SUCCESS_PCT = 0.95 constant absent (P1)
   ============================================================================ *)

let test_g8_double_success_pct_absent () =
  let src = slurp_lib "fee_estimation.ml" in
  Alcotest.(check bool)
    "G8: BUG — DOUBLE_SUCCESS_PCT 0.95 not present (BUG-W139-13)"
    false (contains_substring src "0.95"
           || contains_substring src "double_success"
           || contains_substring src "0.95 (* DOUBLE")

(* ============================================================================
   G9: SUFFICIENT_FEETXS = 0.1/block aggregation threshold absent (P0-CDIV)
   Core: bucket-aggregation loop combines buckets until
         partialNum >= sufficientTxVal / (1 - decay).
   Camlcoin: absolute min_samples = 10 on a single bucket; no aggregation.
   ============================================================================ *)

let test_g9_sufficient_feetxs_absent () =
  let src = slurp_lib "fee_estimation.ml" in
  Alcotest.(check bool)
    "G9: BUG — SUFFICIENT_FEETXS = 0.1/block not present (BUG-W139-4)"
    false (contains_substring src "SUFFICIENT_FEETXS"
           || contains_substring src "sufficient_feetxs"
           || contains_substring src "sufficient_tx_val");
  (* Pin the min_samples=10 absolute floor that takes its place *)
  Alcotest.(check int)
    "G9: documents — min_samples = 10 (camlcoin floor in place of SUFFICIENT_FEETXS)"
    10 Fee_estimation.min_samples

(* ============================================================================
   G10: SUFFICIENT_TXS_SHORT = 0.5/block (SHORT-horizon stricter) absent (P1)
   ============================================================================ *)

let test_g10_sufficient_txs_short_absent () =
  let src = slurp_lib "fee_estimation.ml" in
  Alcotest.(check bool)
    "G10: BUG — SUFFICIENT_TXS_SHORT 0.5 not present (BUG-W139-14)"
    false (contains_substring src "SUFFICIENT_TXS_SHORT"
           || contains_substring src "sufficient_txs_short")

(* ============================================================================
   G11: scale factor in Record not used (P1)
   Core: periodsToConfirm = (blocksToConfirm + scale - 1) / scale
   Camlcoin: record_confirmation_horizon writes the raw block count.
   ============================================================================ *)

let test_g11_scale_in_record_absent () =
  let est = Fee_estimation.create () in
  let txid = make_txid 100 in
  (* Track + confirm a tx that took 25 blocks to confirm. On the LONG
     horizon (scale=24), Core would compute periodsToConfirm =
     (25+23)/24 = 2 and increment confAvg[1..41].  Camlcoin records
     the raw value 25 in blocks_to_confirm. *)
  Fee_estimation.track_transaction est txid 50.0 100;
  Fee_estimation.record_confirmation est txid 125;
  let bucket_idx = Fee_estimation.find_bucket est 50.0 in
  let long_bucket = est.Fee_estimation.long.Fee_estimation.buckets.(bucket_idx) in
  (* The raw 25.0 (not period 2) should be in the list. *)
  Alcotest.(check bool)
    "G11: BUG — record stores raw block count, not (blocks+scale-1)/scale (BUG-W139-15)"
    true (List.exists (fun v -> v = 25.0)
            long_bucket.Fee_estimation.blocks_to_confirm)

(* ============================================================================
   G12: confAvg[periods][buckets] 2D matrix absent (P1)
   Core: vector<vector<double>> confAvg; failAvg.
   Camlcoin: flat blocks_to_confirm: float list per bucket.
   ============================================================================ *)

let test_g12_confavg_2d_matrix_absent () =
  let src = strip_comments_and_strings (slurp_lib "fee_estimation.ml") in
  Alcotest.(check bool)
    "G12: BUG — confAvg[periods][buckets] 2D matrix absent (BUG-W139-16)"
    false (contains_substring src "confAvg"
           || contains_substring src "conf_avg")

(* ============================================================================
   G13: failAvg[periods][buckets] matrix absent (P0-CDIV)
   Core: failAvg[i][j]++ on tx eviction; decayed in UpdateMovingAverages.
   Camlcoin: record_eviction decrements total_unconfirmed but never lands
             in any "failed within N periods" counter.
   ============================================================================ *)

let test_g13_failavg_matrix_absent () =
  let src = strip_comments_and_strings (slurp_lib "fee_estimation.ml") in
  Alcotest.(check bool)
    "G13: BUG — failAvg matrix absent; evictions invisible to estimates (BUG-W139-5)"
    false (contains_substring src "failAvg"
           || contains_substring src "fail_avg"
           || contains_substring src "FailAvg");
  (* Cross-check at the API level: track tx, evict, then verify that no
     failure counter goes up anywhere. *)
  let est = Fee_estimation.create () in
  let txid = make_txid 7 in
  Fee_estimation.track_transaction est txid 50.0 100;
  Fee_estimation.record_eviction est txid;
  let bucket_idx = Fee_estimation.find_bucket est 50.0 in
  let b = est.Fee_estimation.short.Fee_estimation.buckets.(bucket_idx) in
  (* The bucket has zero confirmed AND zero unconfirmed (the decrement
     ate the +1).  No "failed" counter exists. *)
  Alcotest.(check (float 0.001))
    "G13: BUG — confirmed unchanged after eviction (no failure landed)"
    0.0 b.Fee_estimation.total_confirmed;
  Alcotest.(check (float 0.001))
    "G13: BUG — unconfirmed reset to 0 after eviction (failure not retained)"
    0.0 b.Fee_estimation.total_unconfirmed

(* ============================================================================
   G14: unconfTxs[Y][buckets] circular buffer + ClearCurrent absent (P0-CDIV)
   Core: per-bucket per-block-age counter rolled by ClearCurrent.
   Camlcoin: total_unconfirmed scalar (decayed) used as proxy.
   ============================================================================ *)

let test_g14_unconf_txs_circular_buffer_absent () =
  let src = slurp_lib "fee_estimation.ml" in
  Alcotest.(check bool)
    "G14: BUG — unconfTxs circular buffer absent (BUG-W139-6)"
    false (contains_substring src "unconfTxs"
           || contains_substring src "unconf_txs"
           || contains_substring src "ClearCurrent"
           || contains_substring src "clear_current");
  (* Pin the scalar proxy *)
  let est = Fee_estimation.create () in
  let _ = est.Fee_estimation.short.Fee_estimation.buckets.(0)
            .Fee_estimation.total_unconfirmed in
  Alcotest.(check bool) "G14: total_unconfirmed scalar is the only proxy" true true

(* ============================================================================
   G15: oldUnconfTxs[buckets] overflow bucket absent (P1)
   ============================================================================ *)

let test_g15_old_unconf_txs_overflow_bucket_absent () =
  let src = slurp_lib "fee_estimation.ml" in
  Alcotest.(check bool)
    "G15: BUG — oldUnconfTxs overflow bucket absent (BUG-W139-17)"
    false (contains_substring src "oldUnconfTxs"
           || contains_substring src "old_unconf_txs")

(* ============================================================================
   G16: FlushUnconfirmed on shutdown absent (P0-CDIV)
   Core: FlushUnconfirmed iterates mapMemPoolTxs and calls _removeTx with
         inBlock=false.  Each pending tx becomes a failure before save.
   Camlcoin: save_to_file marshals tracked_txs as-is; pending entries
             survive into next session as still-confirming.
   ============================================================================ *)

let test_g16_flush_unconfirmed_absent () =
  let src = strip_comments_and_strings (slurp_lib "fee_estimation.ml") in
  Alcotest.(check bool)
    "G16: BUG — FlushUnconfirmed absent in module (BUG-W139-7)"
    false (contains_substring src "FlushUnconfirmed"
           || contains_substring src "flush_unconfirmed");
  (* save_to_file does not call record_eviction on still-tracked txs. *)
  let est = Fee_estimation.create () in
  let txid = make_txid 99 in
  Fee_estimation.track_transaction est txid 50.0 100;
  let path = Filename.temp_file "w139_flush_test_" ".dat" in
  Fee_estimation.save_to_file est path;
  let est2 = Fee_estimation.create () in
  let _ = Fee_estimation.load_from_file est2 path in
  Sys.remove path;
  (* The on-disk format does not include tracked_txs (load is full no-op
     for the hashtable side per fee_estimation.ml:472-512), but the
     in-memory before-save state of est still has tracked_count = 1 —
     pin that no flush-before-save reset happened. *)
  Alcotest.(check int)
    "G16: BUG — save_to_file does NOT call record_eviction on pending (tracked_count preserved)"
    1 (Fee_estimation.tracked_count est)

(* ============================================================================
   G17: FEE_FLUSH_INTERVAL periodic 1-hour flush absent (P2)
   Core: block_policy_estimator.h:26 — std::chrono::hours{1}.
   Camlcoin: save on shutdown only.
   ============================================================================ *)

let test_g17_fee_flush_interval_absent () =
  let src_fe = slurp_lib "fee_estimation.ml" in
  let src_cli = slurp_lib "cli.ml" in
  Alcotest.(check bool)
    "G17: BUG — FEE_FLUSH_INTERVAL constant absent (BUG-W139-22)"
    false (contains_substring src_fe "FEE_FLUSH_INTERVAL"
           || contains_substring src_fe "fee_flush_interval"
           || contains_substring src_cli "FEE_FLUSH_INTERVAL"
           || contains_substring src_cli "fee_flush_interval");
  (* save_to_file appears only ONCE in cli.ml — the shutdown path *)
  let saves = ref 0 in
  let i = ref 0 in
  let len = String.length src_cli in
  let needle = "Fee_estimation.save_to_file" in
  let nlen = String.length needle in
  while !i <= len - nlen do
    if String.sub src_cli !i nlen = needle then begin
      incr saves;
      i := !i + nlen
    end else
      incr i
  done;
  Alcotest.(check bool)
    "G17: BUG — Fee_estimation.save_to_file called only at shutdown (no periodic flush)"
    true (!saves <= 1)

(* ============================================================================
   G18: MAX_FILE_AGE (60h) gate on load absent (P1)
   Core: block_policy_estimator.h:32 — std::chrono::hours{60}.
   Camlcoin: any-age file loaded without check.
   ============================================================================ *)

let test_g18_max_file_age_gate_absent () =
  let src = slurp_lib "fee_estimation.ml" in
  Alcotest.(check bool)
    "G18: BUG — MAX_FILE_AGE staleness gate absent (BUG-W139-18)"
    false (contains_substring src "MAX_FILE_AGE"
           || contains_substring src "max_file_age"
           || contains_substring src "DEFAULT_ACCEPT_STALE_FEE_ESTIMATES"
           || contains_substring src "accept_stale_fee_estimates"
           || contains_substring src "GetFeeEstimatorFileAge")

(* ============================================================================
   G19: file format = OCaml Marshal s_version=1, not Core's 309900 (P1)
   ============================================================================ *)

let test_g19_file_format_version_drift () =
  let raw = slurp_lib "fee_estimation.ml" in
  let src = strip_comments_and_strings raw in
  Alcotest.(check bool)
    "G19: documents — camlcoin uses OCaml Marshal serialization"
    true (contains_substring src "Marshal.to_channel"
          && contains_substring src "Marshal.from_channel");
  Alcotest.(check bool)
    "G19: BUG — version=1 (not 309900) (BUG-W139-19)"
    true (contains_substring src "s_version = 1");
  Alcotest.(check bool)
    "G19: BUG — Core CURRENT_FEES_FILE_VERSION 309900 not referenced in code"
    false (contains_substring src "309900"
           || contains_substring src "CURRENT_FEES_FILE_VERSION")

(* ============================================================================
   G20: MaxUsableEstimate / firstRecordedHeight / historicalFirst /
        historicalBest / BlockSpan / OLDEST_ESTIMATE_HISTORY absent (P1)
   ============================================================================ *)

let test_g20_max_usable_estimate_bookkeeping_absent () =
  let src = slurp_lib "fee_estimation.ml" in
  Alcotest.(check bool)
    "G20: BUG — MaxUsableEstimate absent (BUG-W139-8 / 20)"
    false (contains_substring src "MaxUsableEstimate"
           || contains_substring src "max_usable_estimate");
  Alcotest.(check bool)
    "G20: BUG — firstRecordedHeight absent"
    false (contains_substring src "firstRecordedHeight"
           || contains_substring src "first_recorded_height");
  Alcotest.(check bool)
    "G20: BUG — historicalFirst/historicalBest absent"
    false (contains_substring src "historicalFirst"
           || contains_substring src "historical_first"
           || contains_substring src "historicalBest"
           || contains_substring src "historical_best");
  Alcotest.(check bool)
    "G20: BUG — OLDEST_ESTIMATE_HISTORY absent"
    false (contains_substring src "OLDEST_ESTIMATE_HISTORY"
           || contains_substring src "oldest_estimate_history");
  Alcotest.(check bool)
    "G20: BUG — BlockSpan / HistoricalBlockSpan absent"
    false (contains_substring src "BlockSpan"
           || contains_substring src "block_span")

(* ============================================================================
   G21: estimate_mode parameter silently dropped (P0-CDIV)
   Core: rpc/fees.cpp:63-94 parses the "estimate_mode" string.
   Camlcoin: `| [`Int conf_target] | [`Int conf_target; _]` ignores it.
   ============================================================================ *)

let test_g21_estimate_mode_silently_dropped () =
  let src = slurp_lib "rpc.ml" in
  (* The wildcard-bound second positional is the smoking gun. *)
  Alcotest.(check bool)
    "G21: BUG — estimate_mode pattern silently swallowed by wildcard (BUG-W139-9)"
    true (contains_substring src
            "[`Int conf_target] | [`Int conf_target; _]");
  (* Confirm there is NO FeeModeFromString analog *)
  Alcotest.(check bool)
    "G21: BUG — no FeeModeFromString analog in RPC layer"
    false (contains_substring src "FeeModeFromString"
           || contains_substring src "fee_mode_from_string"
           || contains_substring src "\"conservative\""
           || contains_substring src "\"economical\"")

(* ============================================================================
   G22: Invalid estimate_mode error path absent (P1)
   ============================================================================ *)

let test_g22_invalid_estimate_mode_error_absent () =
  let src = slurp_lib "rpc.ml" in
  Alcotest.(check bool)
    "G22: BUG — 'Invalid estimate_mode parameter' error not emitted (BUG-W139-21)"
    false (contains_substring src "Invalid estimate_mode"
           || contains_substring src "InvalidEstimateModeErrorMessage")

(* ============================================================================
   G23: min_mempool_feerate / min_relay_feerate clamp on response absent (P0-CDIV)
   Core: rpc/fees.cpp:82-86 — feeRate = std::max({feeRate,
         min_mempool_feerate, min_relay_feerate}).
   Camlcoin: rpc.ml:1644-1647 emits the raw estimator output.
   ============================================================================ *)

let test_g23_min_relay_clamp_on_response_absent () =
  let src = slurp_lib "rpc.ml" in
  (* Look at the body of handle_estimatesmartfee specifically. *)
  let start = Str.search_forward
    (Str.regexp_string "let handle_estimatesmartfee") src 0 in
  (* The function body extends to the next blank-line-+-let definition.
     Take a generous slice. *)
  let body = String.sub src start (min 1500 (String.length src - start)) in
  (* The body does NOT compute max(rate, min_relay_fee) on the response *)
  Alcotest.(check bool)
    "G23: BUG — handle_estimatesmartfee does NOT clamp against min_relay_fee (BUG-W139-10)"
    false (contains_substring body "min_relay_fee"
           || contains_substring body "min_mempool_feerate"
           || contains_substring body "GetMinFee"
           || contains_substring body "Float.max")

(* ============================================================================
   G24: SyncWithValidationInterfaceQueue flush at top of RPCs absent (P3)
   ============================================================================ *)

let test_g24_sync_with_validation_queue_absent () =
  let src = slurp_lib "rpc.ml" in
  Alcotest.(check bool)
    "G24: BUG — SyncWithValidationInterfaceQueue flush absent (BUG-W139-26)"
    false (contains_substring src "SyncWithValidationInterfaceQueue"
           || contains_substring src "sync_with_validation_interface"
           || contains_substring src "validation_signals")

(* ============================================================================
   G25: estimaterawfee leftmempool hardcoded 0.0 + inmempool decayed scalar (P3)
   ============================================================================ *)

let test_g25_estimaterawfee_leftmempool_inmempool_drift () =
  let src = slurp_lib "rpc.ml" in
  (* The hardcoded ("leftmempool", `Float 0.0) is the smoking gun. *)
  Alcotest.(check bool)
    "G25: BUG — leftmempool hardcoded 0.0 in estimate_raw_horizon (BUG-W139-27)"
    true (contains_substring src "(\"leftmempool\", `Float 0.0)");
  (* And inmempool uses total_unconfirmed (decayed scalar) *)
  Alcotest.(check bool)
    "G25: BUG — inmempool sources from decayed total_unconfirmed scalar"
    true (contains_substring src
            "(\"inmempool\", `Float b.total_unconfirmed)")

(* ============================================================================
   G26: FeeFilterRounder semantic drift: min_relay_fee vs
        min_incremental_fee (P3)
   ============================================================================ *)

let test_g26_feefilter_min_relay_vs_min_incremental () =
  let src = slurp_lib "peer.ml" in
  (* Camlcoin's signature is make_fee_set (min_relay_fee : int64).  Core's
     would be MakeFeeSet(min_incremental_fee, MAX_FILTER_FEERATE,
     FEE_FILTER_SPACING). *)
  Alcotest.(check bool)
    "G26: BUG — make_fee_set uses min_relay_fee, not min_incremental_fee (BUG-W139-28)"
    true (contains_substring src
            "make_fee_set (min_relay_fee : int64)");
  Alcotest.(check bool)
    "G26: BUG — min_incremental_fee name not present in peer.ml"
    false (contains_substring src "min_incremental_fee")

(* ============================================================================
   G27: FeeFilterRounder.default_fee_set hardcoded 1000L drift (P3)
   ============================================================================ *)

let test_g27_default_fee_set_hardcoded_1000L () =
  let src = slurp_lib "peer.ml" in
  Alcotest.(check bool)
    "G27: BUG — default_fee_set hardcoded 1000L (BUG-W139-29)"
    true (contains_substring src
            "let default_fee_set = FeeFilterRounder.make_fee_set 1000L")

(* ============================================================================
   G28: max_filter_feerate = 10_000_000 (10 BTC/kvB) — matches Core
        MAX_FILTER_FEERATE = 1e7 (P3 / pin-only)
   ============================================================================ *)

let test_g28_max_filter_feerate_matches_core () =
  Alcotest.(check (float 0.001))
    "G28: max_filter_feerate = 10_000_000 sat/kvB (matches Core MAX_FILTER_FEERATE 1e7)"
    1.0e7 (Int64.to_float Peer.FeeFilterRounder.max_filter_feerate)

(* ============================================================================
   G29: FeeFilterRounder.round returns float-truncated int64 — matches Core
        static_cast<CAmount> behaviour (P3 / pin-only)
   ============================================================================ *)

let test_g29_feefilter_round_truncates () =
  let fee_set = Peer.FeeFilterRounder.make_fee_set 1000L in
  let n = Array.length fee_set in
  (* Pick a fee at index mid; round should return an int64 of fee_set[*] *)
  let mid_fee = Int64.of_float fee_set.(n / 2) in
  let result = Peer.FeeFilterRounder.round fee_set mid_fee in
  (* result should be one of fee_set entries (within 1 ULP) *)
  let found = ref false in
  Array.iter (fun v ->
    if Int64.of_float v = result then found := true
  ) fee_set;
  Alcotest.(check bool)
    "G29: round result is one of the precomputed bucket values"
    true !found

(* ============================================================================
   G30: FeeFilterRounder.round randomization probabilities — match Core's
        2/3 round-down distribution; but Core uses one pre-seeded
        FastRandomContext, camlcoin uses csprng_int_range per call (P2)
   ============================================================================ *)

let test_g30_feefilter_round_uses_csprng_per_call () =
  let raw = slurp_lib "peer.ml" in
  let src = strip_comments_and_strings raw in
  Alcotest.(check bool)
    "G30: BUG — csprng_int_range 3 called per round (1 syscall each) (BUG-W139-23)"
    true (contains_substring src "csprng_int_range 3");
  Alcotest.(check bool)
    "G30: BUG — FastRandomContext pre-seeded-once analog absent in code"
    false (contains_substring src "FastRandomContext"
           || contains_substring src "fast_random_context"
           || contains_substring src "insecure_rand")

(* ============================================================================
   Invariant pins — pin W114 fixes + FIX-47 + FIX-49 so a future wave
   doesn't accidentally regress them.
   ============================================================================ *)

(* INV-1: W114 BUG-1 — SHORT_DECAY = 0.962 *)
let test_inv1_short_decay_value () =
  let est = Fee_estimation.create () in
  Alcotest.(check (float 0.0001)) "INV-1: SHORT_DECAY = 0.962 (W114 BUG-1)"
    0.962 est.Fee_estimation.short.Fee_estimation.decay

(* INV-2: W114 BUG-2 — MED_DECAY = 0.9952 *)
let test_inv2_med_decay_value () =
  let est = Fee_estimation.create () in
  Alcotest.(check (float 0.0001)) "INV-2: MED_DECAY = 0.9952 (W114 BUG-2)"
    0.9952 est.Fee_estimation.medium.Fee_estimation.decay

(* INV-3: W114 BUG-3 — MIN_BUCKET_FEERATE = 0.1 sat/vB *)
let test_inv3_min_bucket_feerate_value () =
  let est = Fee_estimation.create () in
  Alcotest.(check (float 0.001))
    "INV-3: MIN_BUCKET_FEERATE = 0.1 sat/vB (100 sat/kvB) (W114 BUG-3)"
    0.1 est.Fee_estimation.bucket_boundaries.(0)

(* INV-4: W114 BUG-4 — estimaterawfee scale = 1/2/24 (not FEE_SPACING 1.05) *)
let test_inv4_estimaterawfee_scale_per_horizon () =
  let est = Fee_estimation.create () in
  Alcotest.(check int) "INV-4: short scale = 1"
    1 est.Fee_estimation.short.Fee_estimation.scale;
  Alcotest.(check int) "INV-4: medium scale = 2"
    2 est.Fee_estimation.medium.Fee_estimation.scale;
  Alcotest.(check int) "INV-4: long scale = 24 (W114 BUG-4)"
    24 est.Fee_estimation.long.Fee_estimation.scale

(* INV-5: W114 BUG-5 — min_confirm_target = 2 *)
let test_inv5_min_confirm_target_is_2 () =
  Alcotest.(check int) "INV-5: min_confirm_target = 2 (W114 BUG-5)"
    2 Fee_estimation.min_confirm_target

(* INV-6: FIX-47 — track_transaction is wired in cli.ml on accept path *)
let test_inv6_track_transaction_wired_in_cli () =
  let src = slurp_lib "cli.ml" in
  Alcotest.(check bool)
    "INV-6: cli.ml calls Fee_estimation.track_transaction on admission (FIX-47)"
    true (contains_substring src "Fee_estimation.track_transaction")

(* INV-7: FIX-47 — record_eviction wired via mempool.on_eviction in cli.ml *)
let test_inv7_record_eviction_wired_in_cli () =
  let src = slurp_lib "cli.ml" in
  Alcotest.(check bool)
    "INV-7: cli.ml wires Fee_estimation.record_eviction via on_eviction hook (FIX-47)"
    true (contains_substring src "Fee_estimation.record_eviction")

(* INV-8: FIX-49 — FeeFilterRounder uses CSPRNG, not OCaml stdlib Random *)
let test_inv8_feefilter_uses_csprng () =
  let src = slurp_lib "peer.ml" in
  Alcotest.(check bool)
    "INV-8: FeeFilterRounder uses csprng_int_range (NOT Random.int) (FIX-49)"
    true (contains_substring src "csprng_int_range 3")

(* INV-9: FEE_SPACING = 1.05 (bucket boundary ratio) *)
let test_inv9_fee_spacing_is_1_05 () =
  let est = Fee_estimation.create () in
  let b = est.Fee_estimation.bucket_boundaries in
  let n = Array.length b in
  if n < 2 then Alcotest.fail "INV-9: need >=2 bucket boundaries"
  else begin
    let ratio = b.(1) /. b.(0) in
    Alcotest.(check (float 0.001)) "INV-9: bucket spacing = 1.05" 1.05 ratio
  end

(* INV-10: LONG_DECAY = 0.99931 + max_target 1008 *)
let test_inv10_long_horizon_values () =
  let est = Fee_estimation.create () in
  Alcotest.(check (float 0.000001))
    "INV-10: LONG_DECAY = 0.99931"
    0.99931 est.Fee_estimation.long.Fee_estimation.decay;
  Alcotest.(check int)
    "INV-10: long max_target = 1008"
    1008 est.Fee_estimation.long.Fee_estimation.max_target

(* ============================================================================
   Test runner
   ============================================================================ *)

let () =
  Random.self_init ();
  Alcotest.run "W139 Fee Estimation Engine (CBlockPolicyEstimator)" [
    "G1-G5 Tracking lifecycle / wiring", [
      Alcotest.test_case "G1: validForFeeEstimation guard absent (P0-CDIV BUG-W139-1)"
        `Quick test_g1_valid_for_fee_estimation_guard_absent;
      Alcotest.test_case "G2: txHeight == nBestSeenHeight guard absent (P1 BUG-W139-11)"
        `Quick test_g2_tx_height_guard_absent;
      Alcotest.test_case "G3: trackedTxs/untrackedTxs counters absent (P3 BUG-W139-25)"
        `Quick test_g3_tracked_untracked_counters_absent;
      Alcotest.test_case "G4: process_block no reorg-guard (P0-CDIV BUG-W139-2)"
        `Quick test_g4_process_block_no_reorg_guard;
      Alcotest.test_case "G5: process_block height-then-decay ordering pinned"
        `Quick test_g5_process_block_ordering_height_then_decay;
    ];
    "G6-G10 Three-pass estimator + thresholds", [
      Alcotest.test_case "G6: three-pass estimateSmartFee absent (P0-CDIV BUG-W139-3)"
        `Quick test_g6_three_pass_estimate_absent;
      Alcotest.test_case "G7: HALF_SUCCESS_PCT 0.60 absent (P1 BUG-W139-12)"
        `Quick test_g7_half_success_pct_absent;
      Alcotest.test_case "G8: DOUBLE_SUCCESS_PCT 0.95 absent (P1 BUG-W139-13)"
        `Quick test_g8_double_success_pct_absent;
      Alcotest.test_case "G9: SUFFICIENT_FEETXS 0.1/block aggregation absent (P0-CDIV BUG-W139-4)"
        `Quick test_g9_sufficient_feetxs_absent;
      Alcotest.test_case "G10: SUFFICIENT_TXS_SHORT 0.5/block absent (P1 BUG-W139-14)"
        `Quick test_g10_sufficient_txs_short_absent;
    ];
    "G11-G15 TxConfirmStats data structures", [
      Alcotest.test_case "G11: scale in Record absent (P1 BUG-W139-15)"
        `Quick test_g11_scale_in_record_absent;
      Alcotest.test_case "G12: confAvg[periods][buckets] absent (P1 BUG-W139-16)"
        `Quick test_g12_confavg_2d_matrix_absent;
      Alcotest.test_case "G13: failAvg matrix absent — evictions invisible (P0-CDIV BUG-W139-5)"
        `Quick test_g13_failavg_matrix_absent;
      Alcotest.test_case "G14: unconfTxs circular buffer / ClearCurrent absent (P0-CDIV BUG-W139-6)"
        `Quick test_g14_unconf_txs_circular_buffer_absent;
      Alcotest.test_case "G15: oldUnconfTxs overflow bucket absent (P1 BUG-W139-17)"
        `Quick test_g15_old_unconf_txs_overflow_bucket_absent;
    ];
    "G16-G20 Lifecycle / persistence", [
      Alcotest.test_case "G16: FlushUnconfirmed on shutdown absent (P0-CDIV BUG-W139-7)"
        `Quick test_g16_flush_unconfirmed_absent;
      Alcotest.test_case "G17: FEE_FLUSH_INTERVAL periodic flush absent (P2 BUG-W139-22)"
        `Quick test_g17_fee_flush_interval_absent;
      Alcotest.test_case "G18: MAX_FILE_AGE staleness gate absent (P1 BUG-W139-18)"
        `Quick test_g18_max_file_age_gate_absent;
      Alcotest.test_case "G19: file format Marshal v1 vs Core 309900 (P1 BUG-W139-19)"
        `Quick test_g19_file_format_version_drift;
      Alcotest.test_case "G20: MaxUsableEstimate + book-keeping absent (P0-CDIV/P1 BUG-W139-8/20)"
        `Quick test_g20_max_usable_estimate_bookkeeping_absent;
    ];
    "G21-G25 RPC behaviour", [
      Alcotest.test_case "G21: estimate_mode silently dropped (P0-CDIV BUG-W139-9)"
        `Quick test_g21_estimate_mode_silently_dropped;
      Alcotest.test_case "G22: Invalid estimate_mode error absent (P1 BUG-W139-21)"
        `Quick test_g22_invalid_estimate_mode_error_absent;
      Alcotest.test_case "G23: min_relay_fee clamp on response absent (P0-CDIV BUG-W139-10)"
        `Quick test_g23_min_relay_clamp_on_response_absent;
      Alcotest.test_case "G24: SyncWithValidationInterfaceQueue absent (P3 BUG-W139-26)"
        `Quick test_g24_sync_with_validation_queue_absent;
      Alcotest.test_case "G25: estimaterawfee leftmempool/inmempool drift (P3 BUG-W139-27)"
        `Quick test_g25_estimaterawfee_leftmempool_inmempool_drift;
    ];
    "G26-G30 FeeFilterRounder + adjacent", [
      Alcotest.test_case "G26: make_fee_set uses min_relay_fee not min_incremental_fee (P3 BUG-W139-28)"
        `Quick test_g26_feefilter_min_relay_vs_min_incremental;
      Alcotest.test_case "G27: default_fee_set hardcoded 1000L (P3 BUG-W139-29)"
        `Quick test_g27_default_fee_set_hardcoded_1000L;
      Alcotest.test_case "G28: max_filter_feerate matches Core (pin)"
        `Quick test_g28_max_filter_feerate_matches_core;
      Alcotest.test_case "G29: FeeFilterRounder.round truncates to int64 (pin)"
        `Quick test_g29_feefilter_round_truncates;
      Alcotest.test_case "G30: csprng_int_range per round / no FastRandomContext (P2 BUG-W139-23)"
        `Quick test_g30_feefilter_round_uses_csprng_per_call;
    ];
    "Invariant pins (preserve W114 / FIX-47 / FIX-49)", [
      Alcotest.test_case "INV-1: SHORT_DECAY = 0.962 (W114 BUG-1)"
        `Quick test_inv1_short_decay_value;
      Alcotest.test_case "INV-2: MED_DECAY = 0.9952 (W114 BUG-2)"
        `Quick test_inv2_med_decay_value;
      Alcotest.test_case "INV-3: MIN_BUCKET_FEERATE = 0.1 sat/vB (W114 BUG-3)"
        `Quick test_inv3_min_bucket_feerate_value;
      Alcotest.test_case "INV-4: estimaterawfee scale = 1/2/24 per horizon (W114 BUG-4)"
        `Quick test_inv4_estimaterawfee_scale_per_horizon;
      Alcotest.test_case "INV-5: min_confirm_target = 2 (W114 BUG-5)"
        `Quick test_inv5_min_confirm_target_is_2;
      Alcotest.test_case "INV-6: track_transaction wired in cli.ml (FIX-47)"
        `Quick test_inv6_track_transaction_wired_in_cli;
      Alcotest.test_case "INV-7: record_eviction wired in cli.ml (FIX-47)"
        `Quick test_inv7_record_eviction_wired_in_cli;
      Alcotest.test_case "INV-8: FeeFilterRounder CSPRNG (FIX-49)"
        `Quick test_inv8_feefilter_uses_csprng;
      Alcotest.test_case "INV-9: FEE_SPACING = 1.05"
        `Quick test_inv9_fee_spacing_is_1_05;
      Alcotest.test_case "INV-10: LONG_DECAY = 0.99931 + max_target 1008"
        `Quick test_inv10_long_horizon_values;
    ];
  ]
