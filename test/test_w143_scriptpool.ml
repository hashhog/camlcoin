(* W143 — Persistent IBD-scoped script-check pool: determinism + correctness.

   Reference: bitcoin-core/src/checkqueue.h (CCheckQueue), validation.h:90
   (MAX_SCRIPTCHECK_THREADS = 15).

   The W143 fix replaced the per-transaction Domain.spawn in
   verify_scripts_parallel_domain with submission to a persistent, fixed-size,
   IBD-scoped worker pool (Validation.create_pool / shutdown_pool, handle
   Validation.script_check_pool).

   The consensus-load-bearing property is that the accept/reject DECISION is
   bit-identical whether the pool is active (Some) or absent (None ⇒ pure serial
   in-thread fold).  This suite asserts, over a corpus of synthetic
   (tx, flags, prevouts, utxos) cases (including multi-input txs), that
   verify_scripts_parallel_domain returns IDENTICAL results — same Ok/Error AND
   same error index — under [script_check_pool := Some (create_pool ())] and
   under [script_check_pool := None].  It also asserts a deliberately-invalid
   input is rejected under both. *)

open Camlcoin

(* ----------------------------------------------------------------------------
   Synthetic script helpers.

   We avoid real signatures (not needed to test pool-vs-serial determinism):
   - OP_TRUE  (0x51): scriptPubKey leaves 1 on the stack ⇒ Script.verify_script
     returns Ok true ⇒ verify_one_input ⇒ Ok ().
   - OP_RETURN (0x6a): aborts ⇒ Error ⇒ rejected input.
   - empty scriptPubKey: leaves an empty stack ⇒ Ok false ⇒ rejected input.
   Each is deterministic and independent of crypto, so the pool and serial
   paths must agree exactly.
   ---------------------------------------------------------------------------- *)

let op_true_spk () =
  let c = Cstruct.create 1 in
  Cstruct.set_uint8 c 0 0x51;  (* OP_1 / OP_TRUE *)
  c

let op_return_spk () =
  let c = Cstruct.create 1 in
  Cstruct.set_uint8 c 0 0x6a;  (* OP_RETURN *)
  c

let empty_spk () = Cstruct.create 0

let make_txid byte =
  let t = Cstruct.create 32 in
  Cstruct.set_uint8 t 0 byte;
  t

(* Build a transaction with [n] inputs, plus the matching utxo array.
   The per-input kind decides which scriptPubKey (and thus accept/reject) the
   resolved UTXO carries: `Valid -> OP_TRUE, `Return -> OP_RETURN,
   `Empty -> empty (false), `Missing -> the utxo slot is None.

   [uid] is woven into the locktime so every distinct case has a DISTINCT
   wtxid (Crypto.compute_wtxid covers the locktime).  This mirrors reality —
   every transaction in a block has a unique wtxid — and keeps the global
   sig-cache (which is keyed by wtxid) from carrying a verified-true entry from
   one case into a structurally-identical-but-different case.  Without distinct
   wtxids a prior case's cached `true` would mask the script result here for
   BOTH the pool and serial paths (they agree, but on a polluted answer), which
   is a test artefact, not a property of real block validation. *)
let make_case ?(uid = 0) (kinds : [ `Valid | `Return | `Empty | `Missing ] list) =
  let n = List.length kinds in
  let inputs =
    List.mapi (fun i _ ->
      { Types.previous_output = { Types.txid = make_txid (i + 1);
                                  vout = Int32.of_int i };
        script_sig = Cstruct.create 0;
        sequence = 0xffffffffl }) kinds
  in
  let outputs = [ { Types.value = 1000L; script_pubkey = op_true_spk () } ] in
  let tx = { Types.version = 1l; inputs; outputs;
             witnesses = []; locktime = Int32.of_int uid } in
  let utxos =
    Array.of_list (List.mapi (fun i k ->
      match k with
      | `Missing -> None
      | _ ->
        let spk = match k with
          | `Valid -> op_true_spk ()
          | `Return -> op_return_spk ()
          | `Empty -> empty_spk ()
          | `Missing -> assert false
        in
        Some { Validation.txid = make_txid (100 + i);
               vout = Int32.of_int i;
               value = 5000L;
               script_pubkey = spk;
               height = 1;
               is_coinbase = false })
      kinds)
  in
  let _ = n in
  (tx, utxos)

(* Corpus: a spread of single- and multi-input cases.  Several exceed the
   min_inputs_for_parallel threshold (16) so the pool's partition path is
   actually exercised, not only the serial sub-threshold branch. *)
let rep k n = List.init n (fun _ -> k)

let corpus : (string * [ `Valid | `Return | `Empty | `Missing ] list) list = [
  "single valid",            [ `Valid ];
  "single invalid (return)", [ `Return ];
  "single invalid (empty)",  [ `Empty ];
  "single missing",          [ `Missing ];
  "two valid",               [ `Valid; `Valid ];
  "valid then invalid",      [ `Valid; `Return ];
  "invalid then valid",      [ `Return; `Valid ];
  "missing first",           [ `Missing; `Valid ];
  "valid then missing",      [ `Valid; `Missing ];
  "16 valid (threshold)",    rep `Valid 16;
  "20 valid (above thresh)", rep `Valid 20;
  "20 valid, bad at 13",     (rep `Valid 13 @ [ `Return ] @ rep `Valid 6);
  "31 valid",                rep `Valid 31;
  "40 valid, bad at 0",      (`Return :: rep `Valid 39);
  "40 valid, bad at 39",     (rep `Valid 39 @ [ `Return ]);
  "40 valid, two bad (7,22)",
    (List.mapi (fun i _ -> if i = 7 || i = 22 then `Return else `Valid)
       (rep `Valid 40));
  "50 empty-script (reject)", rep `Empty 50;
]

let flags = Script.script_verify_p2sh

(* Run one case under the current script_check_pool setting. *)
let run_case (tx, utxos) =
  Validation.verify_scripts_parallel_domain ~tx ~flags ~prevouts:[] ~utxos

(* Normalise a result to (is_ok, error_index option) for comparison.  We do NOT
   compare the error *message* — Core's failure-reason among several is not
   deterministic either, only the accept/reject decision (and the index, which
   we additionally assert for stronger coverage). *)
let normalise = function
  | Ok () -> (true, None)
  | Error (Validation.TxScriptFailed (idx, _)) -> (false, Some idx)
  | Error _ -> (false, Some (-99))  (* any other tx_validation_error *)

let pp_norm (ok, idx) =
  Printf.sprintf "(ok=%b, idx=%s)" ok
    (match idx with None -> "-" | Some i -> string_of_int i)

(* ----------------------------------------------------------------------------
   Test 1 — pool (Some) and serial (None) give IDENTICAL results.
   ---------------------------------------------------------------------------- *)
let run_corpus () =
  List.mapi (fun uid (name, kinds) ->
    (* Distinct wtxid per case (uid) + cache clear before each case ⇒ each case
       is evaluated against a clean cache, isolating the pool-vs-serial
       comparison from any cross-case cache carryover. *)
    Sig_cache.clear_global ();
    (name, normalise (run_case (make_case ~uid kinds)))) corpus

let test_pool_equals_serial () =
  Sig_cache.init_global ~max_entries:100_000 ();
  (* Serial pass: no pool. *)
  Validation.script_check_pool := None;
  let serial = run_corpus () in
  (* Pool pass: real Domain-backed pool. *)
  let pool = Validation.create_pool () in
  Validation.script_check_pool := Some pool;
  let parallel = run_corpus () in
  Validation.shutdown_pool pool;
  Validation.script_check_pool := None;
  List.iter2 (fun (name, s) (_, p) ->
    Alcotest.(check string)
      (Printf.sprintf "%s: pool result == serial result" name)
      (pp_norm s) (pp_norm p)
  ) serial parallel

(* ----------------------------------------------------------------------------
   Test 2 — a deliberately-invalid-script input is rejected under BOTH modes,
   and a fully-valid multi-input tx is accepted under BOTH modes.
   ---------------------------------------------------------------------------- *)
let test_invalid_rejected_both () =
  Sig_cache.init_global ~max_entries:100_000 ();
  let bad = make_case ~uid:1 (rep `Valid 20 @ [ `Return ] @ rep `Valid 5) in
  let good = make_case ~uid:2 (rep `Valid 25) in

  (* Serial *)
  Validation.script_check_pool := None;
  Sig_cache.clear_global ();
  let bad_serial = normalise (run_case bad) in
  Sig_cache.clear_global ();
  let good_serial = normalise (run_case good) in

  (* Pool *)
  let pool = Validation.create_pool () in
  Validation.script_check_pool := Some pool;
  Sig_cache.clear_global ();
  let bad_pool = normalise (run_case bad) in
  Sig_cache.clear_global ();
  let good_pool = normalise (run_case good) in
  Validation.shutdown_pool pool;
  Validation.script_check_pool := None;

  Alcotest.(check bool) "invalid rejected (serial)" false (fst bad_serial);
  Alcotest.(check bool) "invalid rejected (pool)"   false (fst bad_pool);
  Alcotest.(check string) "invalid: same decision+index"
    (pp_norm bad_serial) (pp_norm bad_pool);
  Alcotest.(check (option int)) "invalid index is 20 (serial)" (Some 20) (snd bad_serial);
  Alcotest.(check (option int)) "invalid index is 20 (pool)"   (Some 20) (snd bad_pool);

  Alcotest.(check bool) "valid accepted (serial)" true (fst good_serial);
  Alcotest.(check bool) "valid accepted (pool)"   true (fst good_pool)

(* ----------------------------------------------------------------------------
   Test 3 — the FIRST error (lowest input index) is reported deterministically
   under both modes, even when there are multiple failing inputs that land in
   different worker slices.  This asserts the pool's first-error scan order
   (worker-index, then in-slice) collapses to input-index order, matching a
   pure serial left-to-right fold.
   ---------------------------------------------------------------------------- *)
let test_first_error_is_deterministic () =
  Sig_cache.init_global ~max_entries:100_000 ();
  (* Two bad inputs; the FIRST (lowest index) must be reported under both. *)
  let kinds =
    List.mapi (fun i _ -> if i = 9 || i = 25 then `Return else `Valid)
      (rep `Valid 32)
  in
  Validation.script_check_pool := None;
  Sig_cache.clear_global ();
  let serial = normalise (run_case (make_case ~uid:3 kinds)) in
  let pool = Validation.create_pool () in
  Validation.script_check_pool := Some pool;
  Sig_cache.clear_global ();
  let parallel = normalise (run_case (make_case ~uid:3 kinds)) in
  Validation.shutdown_pool pool;
  Validation.script_check_pool := None;
  Alcotest.(check (option int)) "first error index = 9 (serial)" (Some 9) (snd serial);
  Alcotest.(check (option int)) "first error index = 9 (pool)"   (Some 9) (snd parallel);
  Alcotest.(check string) "same decision" (pp_norm serial) (pp_norm parallel)

let () =
  let open Alcotest in
  run "W143 script-check pool" [
    "determinism", [
      test_case "pool result == serial result (corpus)" `Quick test_pool_equals_serial;
      test_case "invalid rejected + valid accepted under both" `Quick test_invalid_rejected_both;
      test_case "first error is deterministic (lowest index)" `Quick test_first_error_is_deterministic;
    ];
  ]
