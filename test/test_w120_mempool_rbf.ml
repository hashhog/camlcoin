(* W120 mempool strict RBF (BIP-125 rules 1-5) fleet audit — camlcoin (OCaml)

   30 gates covering BIP-125 strict-RBF and surrounding wire/RPC/wallet
   semantics:

     G1-G5    BIP-125 rules 1-5 (Core: src/policy/rbf.cpp)
     G6       ancestor walk (IsRBFOptIn ancestor inheritance)
     G7       descendant tracking on conflict eviction
     G8       package-RBF (BIP-431 §"RBF for packages") — MISSING
     G9       conflicts-then-eviction ordering
     G10      replaceability evaluation surface
     G11      original-feerate comparison
     G12      replacement-feerate signal (>= conflict_feerate)
     G13      conflicts list emission
     G14      MAX_REPLACEMENT_CANDIDATES = 100 cap
     G15      getmempoolentry bip125-replaceable reporting
     G16      RPC surface for RBF-aware reject + replaces
     G17      error strings match Core (reject reason mnemonics)
     G18      "replaces" field on submitpackage / sendrawtransaction
     G19      testmempoolaccept must route RBF replacements
     G20      fee-estimator must skip txs evicted by RBF replacement
     G21      TRUC v3 unconditional replaceability
     G22      `fullrbf` getmempoolinfo flag
     G23      -mempoolfullrbf CLI flag
     G24      wallet default sequence opts into RBF (0xFFFFFFFD)
     G25      bumpfee / psbtbumpfee RPC surface
     G26      prioritisetransaction RPC surface
     G27      sendrawtransaction error envelope for RBF cases
     G28      logging on conflict eviction
     G29      mempool stats — `replaced_count` / similar counter
     G30      ZMQ "replaced" / "removed (rbf-conflict)" event

   References:
     - bitcoin-core/src/policy/rbf.{cpp,h}
     - bitcoin-core/src/validation.cpp MemPoolAccept::PreChecks /
       ConsiderReplacement / Finalize
     - BIP-125:  https://github.com/bitcoin/bips/blob/master/bip-0125.mediawiki
     - BIP-431:  v3 / TRUC rules — `bitcoin-core/src/policy/truc_policy.cpp`

   Approach
   ========
   camlcoin has the bulk of strict-RBF wired in `replace_by_fee`:
   ImprovesFeerateDiagram + EntriesAndTxidsDisjoint + PaysForRBF +
   incremental-relay + HasNoNewUnconfirmed + 100-cap.  This audit looks at
   the SURFACE around that core algorithm — sendrawtransaction wiring,
   testmempoolaccept wiring, RPC reporting fields, fee-estimator
   eviction-reason discrimination, wallet sequence default, the missing
   bumpfee surface, and the missing -mempoolfullrbf CLI flag.

   Each test documents a specific bug.  Some assert that the BUG is
   present (e.g. sendrawtransaction does not invoke RBF), some assert
   working behaviour for parts that ARE wired (G1-G5 rules 1-5).
   When a gap is closed in a later FIX-N, the corresponding test must
   be flipped.

   Bugs found
   ==========
   BUG-1  (P0 G19) : `handle_testmempoolaccept` calls
                     [Mempool.add_transaction ~dry_run:true] instead of
                     [Mempool.accept_transaction ~dry_run:true].  Any
                     replacement candidate is rejected with
                     "txn-mempool-conflict" instead of being routed
                     through RBF.  rpc.ml:2887.

   BUG-2  (P0 G24) : `Wallet.create_transaction` and `create_transaction_multi`
                     default `nSequence = 0xFFFFFFFE` — NON-replaceable.
                     Core's CWallet defaults to 0xFFFFFFFD (m_signal_rbf=true)
                     since v23.0.  wallet.ml:1718, wallet.ml:1818.
                     Practical impact: every send produced by camlcoin
                     is unreplaceable and cannot be fee-bumped.

   BUG-3  (P1 G16) : `sendrawtransaction` calls `Mempool.add_transaction`
                     instead of `Mempool.accept_transaction`.  When a
                     submitted tx conflicts with mempool entries the
                     reject reason is "txn-mempool-conflict" rather
                     than attempting RBF.  rpc.ml:1177.

   BUG-4  (P0 G18) : `submitpackage` hard-codes
                     `("replaced-transactions", `List [])` (rpc.ml:3098)
                     even when the package execution removed conflicting
                     txs via RBF.  Core fills the list with evicted
                     txids.  Wallets relying on this field will be
                     blind to the eviction.

   BUG-5  (P0 G15) : `bip125-replaceable` reporting in
                     `mempool_entry_to_json` calls `Mempool.signals_rbf`
                     (rpc.ml:1416) — only the tx itself.  Core's
                     `entryToJSON` calls `IsRBFOptIn(it, mp)` which walks
                     ancestors (BIP-125 inheritable opt-in).
                     `Mempool.signals_rbf_with_ancestors` already exists
                     and would be the correct call.

   BUG-6  (P0 G23) : No `-mempoolfullrbf` CLI flag exists in cli.ml.
                     The runtime-config plumbing exists for many flags
                     but this one is missing.  RPC fullrbf=true is
                     hard-coded (rpc.ml:1341, rest.ml:647) regardless of
                     CLI input — confusing because BIP-125 strict-RBF
                     would be the legacy fallback (when the flag is off).

   BUG-7  (P0 G8)  : Package-level RBF is missing.  `accept_package`
                     (mempool.ml:3836) topologically sorts and runs
                     standard ATMP per-tx but does not implement the
                     BIP-431 §"Package RBF" rule set (rule 5 enforced
                     across the package, not per-tx).  A package that
                     evicts a single tx because tx-A in the package
                     conflicts will use per-tx fee math even though
                     Core uses the package effective feerate.

   BUG-8  (P1 G20) : `Fee_estimation.record_eviction` decrements
                     `total_unconfirmed` for every removal reason.  Core
                     differentiates eviction reasons (BLOCK / REPLACED
                     / EXPIRY / SIZELIMIT / REORG / CONFLICT) and only
                     decrements stats when the tx is *not* replaced
                     in-pool — RBF replacements pull the replacement
                     back into the unconfirmed pool in the same step,
                     so net-effect should be no decrement.
                     fee_estimation.ml:240.

   BUG-9  (P2 G25) : No bumpfee / psbtbumpfee RPC handlers.  Wallet has
                     `bumpfee_transaction` (wallet.ml:1993) but it is
                     not wired into the RPC dispatcher.  The `--wallet`
                     RPC surface is missing the standard
                     bumpfee/psbtbumpfee API.

   BUG-10 (P2 G26) : No `prioritisetransaction` RPC.  Core uses
                     `prioritisetransaction` to bias miners' selection
                     and override RBF math.  Comment at mempool.ml:3439
                     explicitly admits "camlcoin does not (yet) track
                     prioritisetransaction".  Absent at RPC surface.

   BUG-11 (P1 G29) : No mempool counters expose
                     `replacement_count` / `replaced_count` /
                     `evictions_rbf`.  getmempoolinfo returns count,
                     bytes, fees, fullrbf — but no historical totals.

   BUG-12 (P1 G30) : No ZMQ "replaced" event distinct from
                     "removed".  `zmq_notify_tx ... acceptance:false`
                     fires generic removal for all reasons including
                     RBF conflict eviction.  Core's ZMQ
                     `pubmempooltrace` carries a reason — camlcoin
                     does not.

   BUG-13 (P2 G28) : No log line on RBF conflict eviction — at minimum
                     Core emits "replacing tx <old> with <new> for
                     <delta> additional fees, <delta_feerate> delta
                     feerate, <vsize_change> vsize".  Grep across
                     mempool.ml shows no "replacing" log statement.

   Scoreboard
   ==========
     P0 : BUG-1, BUG-2, BUG-4, BUG-5, BUG-6, BUG-7
     P1 : BUG-3, BUG-8, BUG-11, BUG-12
     P2 : BUG-9, BUG-10, BUG-13

   Implemented & correct (no bug):
     - signals_rbf (mempool.ml:2449) — unsigned-int32 BIP-125 check
     - signals_rbf_with_ancestors (mempool.ml:2464) — BIP-125
       inheritable opt-in
     - find_all_conflicts (mempool.ml:1798) — O(1) via map_next_tx
     - EntriesAndTxidsDisjoint (mempool.ml:2777)
     - PaysForRBF: new_fee >= total_conflict_fee (mempool.ml:2823)
       with the >= (not >) correctness note
     - PaysForRBF incremental: additional_fees >= relay_fee_for_vsize
       (mempool.ml:2836)
     - HasNoNewUnconfirmed (mempool.ml:2842)
     - MAX_REPLACEMENT_CANDIDATES = 100 cap (mempool.ml:110+2765)
     - ImprovesFeerateDiagram via linearize_entries +
       compare_feerate_diagrams (mempool.ml:2641)
     - pre-check then commit (dry_run before remove+add)
       (mempool.ml:2899) — atomicity per FIX-24 pattern
     - TRUC v3 unconditional replaceability (mempool.ml:1790, 2451)

   Summary: 13 bugs (6 P0 / 4 P1 / 3 P2).  10 / 30 gates exercise
   working behaviour; 13 / 30 document a bug; 7 / 30 mark
   pending-implementation surface (CLI flag, log line, etc.).
*)

open Camlcoin

(* ============================================================================
   Test infrastructure
   ============================================================================ *)

let test_db_root = "/tmp/camlcoin_w120_test_db"

let rec rm_rf path =
  if Sys.file_exists path then begin
    if Sys.is_directory path then begin
      Array.iter (fun f -> rm_rf (Filename.concat path f)) (Sys.readdir path);
      try Unix.rmdir path with _ -> ()
    end else
      try Unix.unlink path with _ -> ()
  end

(* Shared RPC context (read-only methods, no mutation) for tests that only
   exercise the dispatch_rpc unknown-method surface.  Mirrors test_w119. *)
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

let assert_rpc_unknown ctx method_name =
  match Rpc.dispatch_rpc ctx method_name [] with
  | Error (-32601, _) -> ()
  | Error (code, msg) ->
    Alcotest.failf "expected method-not-found for %s, got error %d: %s"
      method_name code msg
  | Ok _ ->
    Alcotest.failf "expected method-not-found for %s, but got Ok" method_name

(* Locate a project-relative file by walking parent directories until we find
   a `lib/` peer.  Necessary because dune test sandbox changes cwd to a
   tmpdir; running the .exe directly puts cwd at the project root.  Walking
   from cwd upward handles both. *)
let find_project_file (rel : string) : string =
  let rec walk dir depth =
    if depth > 8 then
      failwith (Printf.sprintf "could not locate %s from cwd" rel);
    let candidate = Filename.concat dir rel in
    if Sys.file_exists candidate then candidate
    else
      let parent = Filename.dirname dir in
      if parent = dir then
        failwith (Printf.sprintf "could not locate %s walking up from cwd" rel)
      else walk parent (depth + 1)
  in
  walk (Sys.getcwd ()) 0

let slurp_file (rel : string) : string =
  let path = find_project_file rel in
  let ic = open_in path in
  let buf = Buffer.create 8192 in
  (try
    while true do
      Buffer.add_string buf (input_line ic); Buffer.add_char buf '\n'
    done
  with End_of_file -> ());
  close_in ic;
  Buffer.contents buf

let file_has_marker (rel : string) (marker : string) : bool =
  let text = slurp_file rel in
  try ignore (Str.search_forward (Str.regexp_string marker) text 0); true
  with Not_found -> false

(* Make a single-input tx whose only purpose is to be RBF-sequence checked.
   Sequence is a uint32; we accept an OCaml int and cast to int32 explicitly. *)
let mk_tx_with_sequence ~seq : Types.transaction =
  let txid = Cstruct.create 32 in
  Cstruct.set_uint8 txid 0 0xaa;
  { Types.version = 2l;
    inputs = [ { Types.previous_output = { Types.txid; vout = 0l };
                 script_sig = Cstruct.create 0;
                 sequence = Int32.of_int seq } ];
    outputs = [];
    witnesses = [];
    locktime = 0l }

(* ============================================================================
   G1-G5 — BIP-125 rules 1-5: the strict-RBF algorithm itself
   ============================================================================ *)

(* G1.  Rule 1: the replacement transaction must signal replaceability.
   `signals_rbf` returns true for any input sequence < 0xFFFFFFFE.
   FullRBF is on by default in camlcoin (no signaling required), but the
   underlying BIP-125 detector is still required for `bip125-replaceable`
   reporting.  Test: sequence boundary handling. *)
let test_g1_rule1_signals_rbf_boundary () =
  (* Sequences that DO signal RBF (BIP-125): 0..0xFFFFFFFD *)
  Alcotest.(check bool) "seq=0x00000000 signals RBF" true
    (Mempool.signals_rbf (mk_tx_with_sequence ~seq:0));
  Alcotest.(check bool) "seq=0xFFFFFFFD signals RBF" true
    (Mempool.signals_rbf (mk_tx_with_sequence ~seq:(Int32.to_int 0xFFFFFFFDl)));
  (* Sequences that do NOT signal RBF: 0xFFFFFFFE and 0xFFFFFFFF *)
  Alcotest.(check bool) "seq=0xFFFFFFFE does NOT signal RBF" false
    (Mempool.signals_rbf (mk_tx_with_sequence ~seq:(Int32.to_int 0xFFFFFFFEl)));
  Alcotest.(check bool) "seq=0xFFFFFFFF does NOT signal RBF" false
    (Mempool.signals_rbf (mk_tx_with_sequence ~seq:(Int32.to_int 0xFFFFFFFFl)))

(* G2.  Rule 2 (HasNoNewUnconfirmed): the replacement may not pull in new
   unconfirmed inputs that weren't present in the original conflict cluster.
   Asserted by code inspection of mempool.ml:2842-2873. *)
let test_g2_rule2_no_new_unconfirmed_present () =
  Alcotest.(check bool) "rule 2: 'new_unconfirmed' present" true
    (file_has_marker "lib/mempool.ml" "new_unconfirmed");
  Alcotest.(check bool) "rule 2: 'conflict_outpoints' present" true
    (file_has_marker "lib/mempool.ml" "conflict_outpoints")

(* G3.  Rule 3 (PaysForRBF: replacement_fees >= original_fees).
   The comparison is `if new_fee < total_conflict_fee` then reject.
   Equal-fee replacements MUST be allowed (Core: rbf.cpp PaysForRBF). *)
let test_g3_rule3_pays_for_rbf_present () =
  Alcotest.(check bool) "rule 3: PaysForRBF uses '<' not '<='" true
    (file_has_marker "lib/mempool.ml" "new_fee < total_conflict_fee")

(* G4.  Rule 4 (PaysForRBF incremental fee).
   additional_fees >= relay_fee.GetFee(replacement_vsize). *)
let test_g4_rule4_incremental_fee_present () =
  Alcotest.(check bool) "rule 4: 'relay_fee_for_replacement' present" true
    (file_has_marker "lib/mempool.ml" "relay_fee_for_replacement")

(* G5.  Rule 5 (MAX_REPLACEMENT_CANDIDATES = 100). *)
let test_g5_rule5_100_cap_present () =
  Alcotest.(check int) "rule 5: max_rbf_evictions = 100" 100
    Mempool.max_rbf_evictions

(* ============================================================================
   G6-G7 — ancestor walk + descendant tracking
   ============================================================================ *)

(* G6.  BIP-125 inheritable opt-in (ancestor walk).
   `signals_rbf_with_ancestors` walks the ancestor graph and returns true
   if any mempool ancestor signals RBF — even if the tx itself doesn't.
   The function is exported and callable.  Empty-mempool case: a tx with
   non-RBF sequence should return false (no ancestors to inherit from). *)
let test_g6_ancestor_walk_present () =
  rm_rf "/tmp/camlcoin_w120_g6";
  let db = Storage.ChainDB.create "/tmp/camlcoin_w120_g6" in
  let utxo = Utxo.UtxoSet.create db in
  let mp = Mempool.create
    ~require_standard:false ~verify_scripts:false
    ~utxo ~current_height:0 () in
  let tx_non_rbf = mk_tx_with_sequence ~seq:(Int32.to_int 0xFFFFFFFEl) in
  (* Empty mempool: no ancestors to inherit from. *)
  Alcotest.(check bool) "non-RBF tx, empty mempool → no inherited RBF" false
    (Mempool.signals_rbf_with_ancestors mp tx_non_rbf);
  (* RBF-signaling tx returns true directly. *)
  let tx_rbf = mk_tx_with_sequence ~seq:0 in
  Alcotest.(check bool) "direct RBF signal short-circuits ancestor walk" true
    (Mempool.signals_rbf_with_ancestors mp tx_rbf)

(* G7.  Descendant tracking on eviction.
   `replace_by_fee` collects descendants of every conflict into the
   eviction set (mempool.ml:2745+). *)
let test_g7_descendant_eviction_present () =
  Alcotest.(check bool) "rule 5: descendants pulled into evicted_set" true
    (file_has_marker "lib/mempool.ml" "get_descendants mp conflict_entry.txid")

(* ============================================================================
   G8 — Package-RBF (BIP-431) — MISSING
   ============================================================================ *)

let test_g8_package_rbf_missing () =
  (* BUG-7 P0.  accept_package runs per-tx ATMP but has no package-effective-
     feerate replacement check (BIP-431 §"Package RBF"). *)
  Alcotest.(check bool) "BUG-7: no 'PackageRBF' symbol in mempool.ml" false
    (file_has_marker "lib/mempool.ml" "PackageRBF");
  Alcotest.(check bool) "BUG-7: no 'package_rbf' helper in mempool.ml" false
    (file_has_marker "lib/mempool.ml" "package_rbf")

(* ============================================================================
   G9-G10 — conflicts order + replaceability surface
   ============================================================================ *)

(* G9.  Conflicts then eviction order: replace_by_fee MUST run every
   validation gate BEFORE removing conflicts (FIX-24 atomicity).  The
   `add_transaction ~dry_run:true` pre-check at mempool.ml:2899 enforces this. *)
let test_g9_conflicts_before_eviction () =
  Alcotest.(check bool) "dry_run pre-check before commit" true
    (file_has_marker "lib/mempool.ml" "add_transaction ~dry_run:true mp tx")

(* G10.  Replaceability surface — find_all_conflicts.  This is the
   O(1)-per-input map_next_tx lookup that drives RBF.  Hand a tx with no
   inputs whose spends overlap mempool → empty conflict list. *)
let test_g10_no_conflicts_when_disjoint () =
  rm_rf "/tmp/camlcoin_w120_g10";
  let db = Storage.ChainDB.create "/tmp/camlcoin_w120_g10" in
  let utxo = Utxo.UtxoSet.create db in
  let mp = Mempool.create
    ~require_standard:false ~verify_scripts:false
    ~utxo ~current_height:0 () in
  let tx = mk_tx_with_sequence ~seq:0 in
  Alcotest.(check int) "empty mempool → no conflicts" 0
    (List.length (Mempool.find_all_conflicts mp tx))

(* ============================================================================
   G11-G14 — feerate math + cap
   ============================================================================ *)

(* G11.  Original-feerate comparison: replace_by_fee sums `total_conflict_fee`
   across the evicted_set (mempool.ml:2820). *)
let test_g11_original_feerate_sum_present () =
  Alcotest.(check bool) "total_conflict_fee sum over evicted_set" true
    (file_has_marker "lib/mempool.ml" "total_conflict_fee")

(* G12.  Replacement-feerate: ImprovesFeerateDiagram.  The chunk-diagram
   linearisation + cumulative comparison lives at mempool.ml:2641. *)
let test_g12_improves_feerate_diagram_present () =
  Alcotest.(check bool) "ImprovesFeerateDiagram function present" true
    (file_has_marker "lib/mempool.ml" "check_improves_feerate_diagram");
  Alcotest.(check bool) "linearize_entries helper present" true
    (file_has_marker "lib/mempool.ml" "linearize_entries");
  Alcotest.(check bool) "compare_feerate_diagrams helper present" true
    (file_has_marker "lib/mempool.ml" "compare_feerate_diagrams")

(* G13.  Conflicts list emission — find_all_conflicts returns a list,
   not a set/option.  Exposed via the public API. *)
let test_g13_find_all_conflicts_is_public () =
  (* Compile-time check: the function exists and returns a list. *)
  let f : Mempool.mempool -> Types.transaction -> Mempool.mempool_entry list
    = Mempool.find_all_conflicts in
  ignore f;
  Alcotest.(check bool) "find_all_conflicts exported with list type" true true

(* G14.  100-cap (MAX_REPLACEMENT_CANDIDATES).  Already exercised by G5;
   here we also pin the rejection-string format. *)
let test_g14_100_cap_error_format () =
  (* Core: "rejecting replacement %s; too many potential replacements (%d > %d)" *)
  Alcotest.(check bool) "100-cap error: 'too many conflicting transactions'" true
    (file_has_marker "lib/mempool.ml" "too many conflicting transactions")

(* ============================================================================
   G15-G18 — RPC surface
   ============================================================================ *)

(* G15.  BUG-5 P0 (FIX-68 W120 BUG-5).  `bip125-replaceable` in
   `mempool_entry_to_json` MUST use `Mempool.signals_rbf_with_ancestors`
   (BIP-125 inheritable opt-in) rather than `Mempool.signals_rbf`
   (only this tx).  Core: src/rpc/mempool.cpp entryToJSON calls
   IsRBFOptIn(it, mp) which walks the in-mempool ancestor set. *)
let test_g15_bip125_replaceable_no_ancestor_walk () =
  (* Self-only call form must NOT appear at the rpc.ml call site any more. *)
  Alcotest.(check bool)
    "FIX-68: bip125-replaceable no longer uses signals_rbf alone at call site"
    false
    (file_has_marker "lib/rpc.ml"
       "(\"bip125-replaceable\", `Bool (Mempool.signals_rbf entry.tx))");
  (* Ancestor-walking call form is present. *)
  Alcotest.(check bool)
    "FIX-68: rpc.ml now calls signals_rbf_with_ancestors"
    true
    (file_has_marker "lib/rpc.ml" "signals_rbf_with_ancestors")

(* G15-A.  FIX-68 positive runtime tests for `bip125-replaceable` ancestor walk.
   These exercise `Rpc.mempool_entry_to_json` directly — the same helper used
   by getrawmempool (verbose), getmempoolentry, getmempoolancestors (verbose),
   getmempooldescendants (verbose) — to confirm the BIP-125 inheritable opt-in
   behaviour now appears at the JSON surface, not just in the marker file. *)

let g15_make_output value : Types.tx_out =
  { Types.value;
    script_pubkey = Cstruct.of_string "\x76\xa9\x14g15_replaceable_test\x88\xac" }

let g15_make_input ?(sequence = 0xFFFFFFFFl) txid vout : Types.tx_in =
  { Types.previous_output = { Types.txid; vout };
    script_sig = Cstruct.of_string "\x00";
    sequence }

let g15_make_tx ?(version = 2l) inputs outputs : Types.transaction =
  { Types.version; inputs; outputs; witnesses = []; locktime = 0l }

let g15_add_seed_utxo utxo txid_hex value =
  let txid = Types.hash256_of_hex txid_hex in
  Utxo.UtxoSet.add utxo txid 0 Utxo.{
    value;
    script_pubkey = Cstruct.of_string "\x76\xa9\x14g15_seed_aaaa\x88\xac";
    height = 100;
    is_coinbase = false;
  };
  txid

let g15_make_mempool path =
  rm_rf path;
  let db = Storage.ChainDB.create path in
  let utxo = Utxo.UtxoSet.create db in
  let mp = Mempool.create
    ~require_standard:false ~verify_scripts:false
    ~utxo ~current_height:100 () in
  (mp, db, utxo)

(* Locate a mempool_entry whose JSON bip125-replaceable field we want to
   inspect.  Looks up by txid in the live mempool table. *)
let g15_lookup_entry mp txid =
  match Mempool.get mp txid with
  | Some e -> e
  | None -> Alcotest.failf "expected mempool entry for txid; not found"

let g15_bip125_flag_of_json json =
  match json with
  | `Assoc kvs ->
    (match List.assoc_opt "bip125-replaceable" kvs with
     | Some (`Bool b) -> b
     | _ -> Alcotest.failf "bip125-replaceable not present in entry json")
  | _ -> Alcotest.failf "expected `Assoc for mempool_entry_to_json result"

(* G15-A.1: self-signaling tx → bip125-replaceable = true. *)
let test_g15a_self_signaling_true () =
  let (mp, db, utxo) = g15_make_mempool "/tmp/camlcoin_w120_g15a1" in
  let seed = g15_add_seed_utxo utxo
    "1111111111111111111111111111111111111111111111111111111111111111"
    1_000_000L in
  let tx = g15_make_tx
    [g15_make_input ~sequence:0xFFFFFFFDl seed 0l]
    [g15_make_output 990_000L] in
  let entry = Result.get_ok (Mempool.add_transaction mp tx) in
  let j = Rpc.mempool_entry_to_json mp entry in
  Alcotest.(check bool) "self-signaling tx reports bip125-replaceable=true"
    true (g15_bip125_flag_of_json j);
  Storage.ChainDB.close db

(* G15-A.2: non-signaling tx with NO ancestors → bip125-replaceable = false. *)
let test_g15a_non_signaling_no_ancestor_false () =
  let (mp, db, utxo) = g15_make_mempool "/tmp/camlcoin_w120_g15a2" in
  let seed = g15_add_seed_utxo utxo
    "2222222222222222222222222222222222222222222222222222222222222222"
    1_000_000L in
  let tx = g15_make_tx
    [g15_make_input ~sequence:0xFFFFFFFFl seed 0l]
    [g15_make_output 990_000L] in
  let entry = Result.get_ok (Mempool.add_transaction mp tx) in
  let j = Rpc.mempool_entry_to_json mp entry in
  Alcotest.(check bool)
    "non-signaling tx with no mempool ancestor reports bip125-replaceable=false"
    false (g15_bip125_flag_of_json j);
  Storage.ChainDB.close db

(* G15-A.3: non-signaling child of a signaling parent → bip125-replaceable = true.
   This is the BUG-5 demonstration test — pre-FIX-68 the call site uses
   `signals_rbf` (self-only) so this returns false; post-FIX-68 it walks
   ancestors via `signals_rbf_with_ancestors` and returns true. *)
let test_g15a_non_signaling_child_of_signaling_parent_true () =
  let (mp, db, utxo) = g15_make_mempool "/tmp/camlcoin_w120_g15a3" in
  let seed = g15_add_seed_utxo utxo
    "3333333333333333333333333333333333333333333333333333333333333333"
    1_000_000L in
  (* Parent: signals RBF via nSequence = 0xFFFFFFFD. *)
  let parent_tx = g15_make_tx
    [g15_make_input ~sequence:0xFFFFFFFDl seed 0l]
    [g15_make_output 990_000L] in
  let parent_entry = Result.get_ok (Mempool.add_transaction mp parent_tx) in
  (* Child: spends parent's output, nSequence = final → does NOT signal itself. *)
  let child_tx = g15_make_tx
    [g15_make_input ~sequence:0xFFFFFFFFl parent_entry.txid 0l]
    [g15_make_output 980_000L] in
  let child_entry = Result.get_ok (Mempool.add_transaction mp child_tx) in
  let child_entry = g15_lookup_entry mp child_entry.txid in
  let j_child = Rpc.mempool_entry_to_json mp child_entry in
  Alcotest.(check bool)
    "non-signaling child of signaling parent reports bip125-replaceable=true \
     (BIP-125 inheritable opt-in)"
    true (g15_bip125_flag_of_json j_child);
  (* Sanity: parent itself reports true. *)
  let j_parent = Rpc.mempool_entry_to_json mp parent_entry in
  Alcotest.(check bool) "self-signaling parent reports bip125-replaceable=true"
    true (g15_bip125_flag_of_json j_parent);
  Storage.ChainDB.close db

(* G16.  BUG-3 P1.  sendrawtransaction does not route through accept_transaction. *)
let test_g16_sendrawtransaction_bypasses_rbf () =
  Alcotest.(check bool) "BUG-3: sendrawtransaction still calls add_transaction" true
    (file_has_marker "lib/rpc.ml" "match Mempool.add_transaction ctx.mempool tx with");
  Alcotest.(check bool) "BUG-3: sendrawtransaction does not call accept_transaction" false
    (file_has_marker "lib/rpc.ml" "Mempool.accept_transaction ctx.mempool tx")

(* G17.  Error reject reasons.  Core emits:
     "txn-mempool-conflict", "insufficient fee, rejecting replacement",
     "replacement-adds-unconfirmed", "too many potential replacements",
     "replacement-spends-conflicting-tx".
   camlcoin emits different strings — verify the current shape so we
   can flip the test when error mnemonics are aligned to Core. *)
let test_g17_error_strings_not_aligned_to_core () =
  (* Core mnemonics that camlcoin SHOULD use but does not: *)
  Alcotest.(check bool) "BUG-13: 'replacement-adds-unconfirmed' missing" false
    (file_has_marker "lib/mempool.ml" "replacement-adds-unconfirmed");
  Alcotest.(check bool) "BUG-13: 'too many potential replacements' missing" false
    (file_has_marker "lib/mempool.ml" "too many potential replacements");
  Alcotest.(check bool) "BUG-13: 'replacement-spends-conflicting-tx' missing" false
    (file_has_marker "lib/mempool.ml" "replacement-spends-conflicting-tx")

(* G18.  BUG-4 P0.  submitpackage hard-codes ("replaced-transactions", `List []).
   Even when RBF replacement happened in the package, the field stays empty. *)
let test_g18_submitpackage_replaces_field_hardcoded_empty () =
  Alcotest.(check bool) "BUG-4: 'replaced-transactions', `List []' is hard-coded" true
    (file_has_marker "lib/rpc.ml" "(\"replaced-transactions\", `List [])")

(* ============================================================================
   G19-G20 — RBF routing through validators + fee-estimator skip
   ============================================================================ *)

(* G19.  BUG-1 P0.  testmempoolaccept uses add_transaction (no RBF). *)
let test_g19_testmempoolaccept_bypasses_rbf () =
  Alcotest.(check bool)
    "BUG-1: testmempoolaccept still uses Mempool.add_transaction ~dry_run:true" true
    (file_has_marker "lib/rpc.ml" "match Mempool.add_transaction ~dry_run:true ctx.mempool tx with");
  Alcotest.(check bool)
    "BUG-1: testmempoolaccept does NOT call accept_transaction" false
    (file_has_marker "lib/rpc.ml" "Mempool.accept_transaction ~dry_run:true ctx.mempool tx")

(* G20.  BUG-8 P1.  Fee estimator does not differentiate eviction reasons.
   record_eviction at fee_estimation.ml:240 always decrements
   total_unconfirmed.  Core's TxConfirmStats::removeTx takes a
   `bool inBlock` and ALSO treats REPLACED specially (no decrement when
   the replacement is added back). *)
let test_g20_fee_estimator_no_reason_discrimination () =
  Alcotest.(check bool) "BUG-8: record_eviction has no reason param" true
    (file_has_marker "lib/fee_estimation.ml" "let record_eviction (est : t) (txid : Types.hash256) : unit");
  Alcotest.(check bool) "BUG-8: no 'inBlock' / 'reason' discrimination" false
    (file_has_marker "lib/fee_estimation.ml" "MEMPOOL_REMOVE_REASON")

(* ============================================================================
   G21 — TRUC (BIP-431 v3) unconditional replaceability
   ============================================================================ *)

let test_g21_truc_unconditional_replaceability () =
  (* TRUC = version 3.  truc_signals_rbf returns true unconditionally for v3.
     Verified by handing a v3 tx with non-RBF sequence. *)
  let txid = Cstruct.create 32 in
  Cstruct.set_uint8 txid 0 0xbb;
  let tx_v3_nonrbf : Types.transaction =
    { version = 3l;
      inputs = [ { Types.previous_output = { Types.txid; vout = 0l };
                   script_sig = Cstruct.create 0;
                   sequence = 0xFFFFFFFFl } ];
      outputs = [];
      witnesses = [];
      locktime = 0l } in
  Alcotest.(check bool) "v3 tx signals RBF even with seq=0xFFFFFFFF" true
    (Mempool.signals_rbf tx_v3_nonrbf);
  Alcotest.(check bool) "v3 truc_signals_rbf returns true" true
    (Mempool.truc_signals_rbf tx_v3_nonrbf);
  let tx_v2_nonrbf = mk_tx_with_sequence ~seq:(Int32.to_int 0xFFFFFFFFl) in
  Alcotest.(check bool) "v2 tx with seq=0xFFFFFFFF does NOT signal" false
    (Mempool.signals_rbf tx_v2_nonrbf)

(* ============================================================================
   G22-G23 — fullrbf surface
   ============================================================================ *)

(* G22.  getmempoolinfo fullrbf flag is hard-coded true (rpc.ml:1341).  This is
   not strictly wrong — fullrbf has been Core's default since 28.0 — but a
   `-mempoolfullrbf=0` CLI flag is missing entirely (G23). *)
let test_g22_getmempoolinfo_fullrbf_hardcoded_true () =
  let ctx = make_rpc_ctx () in
  match Rpc.dispatch_rpc ctx "getmempoolinfo" [] with
  | Ok (`Assoc fields) ->
    (match List.assoc_opt "fullrbf" fields with
     | Some (`Bool true) -> ()
     | Some other ->
       Alcotest.failf "getmempoolinfo.fullrbf must be true, got %s"
         (Yojson.Safe.to_string other)
     | None ->
       Alcotest.fail "getmempoolinfo.fullrbf field missing")
  | _ -> Alcotest.fail "getmempoolinfo dispatch failed"

(* G23.  BUG-6 P0.  No -mempoolfullrbf CLI flag. *)
let test_g23_mempoolfullrbf_cli_flag_missing () =
  Alcotest.(check bool) "BUG-6: -mempoolfullrbf CLI flag absent" false
    (file_has_marker "lib/cli.ml" "mempoolfullrbf");
  Alcotest.(check bool) "BUG-6: --mempool-fullrbf alternative absent too" false
    (file_has_marker "lib/cli.ml" "mempool-fullrbf")

(* ============================================================================
   G24 — wallet default sequence
   ============================================================================ *)

(* G24.  BUG-2 P0 — FIX-70 FLIPPED.  Wallet now defaults to
   MAX_BIP125_RBF_SEQUENCE (0xFFFFFFFD), matching Core CWallet v23+.
   This test now ASSERTS the fix: create_transaction (+ multi variant +
   walletcreatefundedpsbt + createpsbt) emit `max_bip125_rbf_sequence`
   on wallet-built inputs.  The bumpfee path already used 0xFFFFFFFDl. *)
let test_g24_wallet_default_sequence_not_rbf () =
  (* Post-FIX-70: the buggy literal `sequence = 0xFFFFFFFEl;` is gone
     from wallet.ml.  (The coinbase mining path lives in mining.ml and
     correctly keeps 0xFFFFFFFEl as MAX_SEQUENCE_NONFINAL.) *)
  Alcotest.(check bool) "FIX-70: wallet.ml no longer hardcodes 0xFFFFFFFEl for default sends" false
    (file_has_marker "lib/wallet.ml" "sequence = 0xFFFFFFFEl;");
  (* New default constant is named MAX_BIP125_RBF_SEQUENCE. *)
  Alcotest.(check bool) "FIX-70: wallet.ml defines max_bip125_rbf_sequence" true
    (file_has_marker "lib/wallet.ml" "max_bip125_rbf_sequence");
  (* Wallet defaults to the constant, not a magic literal. *)
  Alcotest.(check bool) "FIX-70: create_transaction uses max_bip125_rbf_sequence" true
    (file_has_marker "lib/wallet.ml" "sequence = max_bip125_rbf_sequence");
  (* The bumpfee path correctly uses 0xFFFFFFFDl — unchanged. *)
  Alcotest.(check bool) "bumpfee path uses 0xFFFFFFFDl correctly" true
    (file_has_marker "lib/wallet.ml" "sequence = 0xFFFFFFFDl")

(* FIX-70 FORWARD REGRESSION GUARD: behavioural check that the wallet
   actually emits 0xFFFFFFFD on freshly-built tx inputs.  Catches the
   future drive-by revert that re-introduces 0xFFFFFFFE in the create
   path even if the file_has_marker text-greps still pass.

   The setup mirrors W118 G19 (create_transaction with a funded wallet)
   but asserts the OPPOSITE outcome: every input.sequence == 0xFFFFFFFD. *)
let test_g24_create_transaction_emits_rbf_sequence () =
  let open Camlcoin in
  (* Same in-memory minimal funding pattern used by test_w118_wallet:
     a one-output funding tx to the wallet's first key, scanned at
     block height 100, then create a 0.5 BTC send to a fresh dest. *)
  let make_p2wpkh_script pkh =
    let s = Cstruct.create 22 in
    Cstruct.set_uint8 s 0 0x00;
    Cstruct.set_uint8 s 1 0x14;
    Cstruct.blit pkh 0 s 2 20;
    s
  in
  let make_one_output_tx script value : Types.transaction =
    let txid = Cstruct.create 32 in
    { Types.version = 2l;
      inputs = [{
        previous_output = { txid; vout = 0l };
        script_sig = Cstruct.create 0;
        sequence = 0xFFFFFFFEl;  (* synthetic parent — unrelated to wallet *)
      }];
      outputs = [{ value; script_pubkey = script }];
      witnesses = [];
      locktime = 0l }
  in
  let empty_block_with txs : Types.block =
    { header = { version = 1l;
                 prev_block = Types.zero_hash;
                 merkle_root = Types.zero_hash;
                 timestamp = 0l;
                 bits = 0x1d00ffffl;
                 nonce = 0l };
      transactions = txs }
  in
  let w = Wallet.create ~network:`Regtest ~db_path:"" in
  let kp = Wallet.generate_key w in
  let pkh = Crypto.hash160 kp.public_key in
  let script = make_p2wpkh_script pkh in
  let funding_tx = make_one_output_tx script 1_000_000L in
  Wallet.scan_block w (empty_block_with [funding_tx]) 100;
  let dest_w = Wallet.create ~network:`Regtest ~db_path:"" in
  let dest = Wallet.get_new_address dest_w in
  (* create_transaction *)
  (match Wallet.create_transaction w ~dest_address:dest ~amount:500_000L
           ~fee_rate:1.0 () with
   | Error e -> Alcotest.fail ("FIX-70 G24 create_transaction: " ^ e)
   | Ok tx ->
     List.iter (fun inp ->
       Alcotest.(check int32)
         "FIX-70: create_transaction emits 0xFFFFFFFD on every input"
         0xFFFFFFFDl inp.Types.sequence
     ) tx.inputs);
  (* create_transaction_multi — same invariant *)
  let w2 = Wallet.create ~network:`Regtest ~db_path:"" in
  let kp2 = Wallet.generate_key w2 in
  let pkh2 = Crypto.hash160 kp2.public_key in
  let script2 = make_p2wpkh_script pkh2 in
  let funding_tx2 = make_one_output_tx script2 1_000_000L in
  Wallet.scan_block w2 (empty_block_with [funding_tx2]) 100;
  (match Wallet.create_transaction_multi w2
           ~outputs:[(dest, 400_000L)] ~fee_rate:1.0 () with
   | Error e -> Alcotest.fail ("FIX-70 G24 create_transaction_multi: " ^ e)
   | Ok tx ->
     List.iter (fun inp ->
       Alcotest.(check int32)
         "FIX-70: create_transaction_multi emits 0xFFFFFFFD on every input"
         0xFFFFFFFDl inp.Types.sequence
     ) tx.inputs);
  (* The named constant is the canonical source of truth. *)
  Alcotest.(check int32) "FIX-70: max_bip125_rbf_sequence = 0xFFFFFFFDl"
    0xFFFFFFFDl Wallet.max_bip125_rbf_sequence

(* ============================================================================
   G25-G27 — wallet / RPC surface for fee bumping + prioritisation
   ============================================================================ *)

(* G25.  BUG-9 P2.  bumpfee / psbtbumpfee RPCs missing. *)
let test_g25_no_bumpfee_rpc () =
  let ctx = make_rpc_ctx () in
  assert_rpc_unknown ctx "bumpfee";
  assert_rpc_unknown ctx "psbtbumpfee"

(* G26.  BUG-10 P2.  prioritisetransaction RPC missing. *)
let test_g26_no_prioritisetransaction_rpc () =
  let ctx = make_rpc_ctx () in
  assert_rpc_unknown ctx "prioritisetransaction"

(* G27.  sendrawtransaction error envelope for RBF cases — collateral of
   BUG-3.  When an RBF replacement would succeed in Core's pipeline,
   camlcoin will return "txn-mempool-conflict" because of BUG-3.
   Test pins the existence of the parameter-decode error envelope as a
   placeholder so it can be flipped when BUG-3 is closed. *)
let test_g27_sendraw_decode_envelope_present () =
  let ctx = make_rpc_ctx () in
  match Rpc.dispatch_rpc ctx "sendrawtransaction" [`String "not-hex"] with
  | Error (_, _) -> ()  (* Any error is acceptable — RPC method dispatches *)
  | Ok _ -> Alcotest.fail "sendrawtransaction with invalid hex should error"

(* ============================================================================
   G28-G30 — logging / stats / ZMQ
   ============================================================================ *)

(* G28.  BUG-13 P2.  No log line on RBF eviction.  Core emits
   "replacing tx <a> with <b> ..." when ConsiderReplacement succeeds.  *)
let test_g28_no_rbf_eviction_log_line () =
  Alcotest.(check bool) "BUG-13: no 'replacing tx' log on RBF success" false
    (file_has_marker "lib/mempool.ml" "replacing tx")

(* G29.  BUG-11 P1.  No replacement_count / evictions_rbf counter exposed. *)
let test_g29_no_rbf_stats_counter () =
  let ctx = make_rpc_ctx () in
  match Rpc.dispatch_rpc ctx "getmempoolinfo" [] with
  | Ok (`Assoc fields) ->
    Alcotest.(check bool) "BUG-11: getmempoolinfo has no 'replacement_count'" false
      (List.mem_assoc "replacement_count" fields);
    Alcotest.(check bool) "BUG-11: getmempoolinfo has no 'evictions_rbf'" false
      (List.mem_assoc "evictions_rbf" fields);
    Alcotest.(check bool) "BUG-11: getmempoolinfo has no 'replaced_count'" false
      (List.mem_assoc "replaced_count" fields)
  | _ -> Alcotest.fail "getmempoolinfo dispatch failed"

(* G30.  BUG-12 P1.  ZMQ does not emit a distinct "replaced" event vs the
   generic "removed".  zmq_notify_tx (mempool.ml:319) takes a single
   `acceptance` boolean; there is no reason carrier. *)
let test_g30_zmq_no_replaced_event () =
  Alcotest.(check bool) "BUG-12: no 'notify_tx_replaced' helper in mempool.ml" false
    (file_has_marker "lib/mempool.ml" "notify_tx_replaced");
  Alcotest.(check bool) "BUG-12: no distinct 'replaced' reason carrier" false
    (file_has_marker "lib/mempool.ml" "MEMPOOL_REMOVE_REPLACED")

(* ============================================================================
   Test runner
   ============================================================================ *)

let bip125_rule_tests = [
  Alcotest.test_case "G1  rule 1 — signals_rbf boundary"  `Quick test_g1_rule1_signals_rbf_boundary;
  Alcotest.test_case "G2  rule 2 — HasNoNewUnconfirmed present" `Quick test_g2_rule2_no_new_unconfirmed_present;
  Alcotest.test_case "G3  rule 3 — PaysForRBF '<' not '<='"  `Quick test_g3_rule3_pays_for_rbf_present;
  Alcotest.test_case "G4  rule 4 — incremental relay fee"   `Quick test_g4_rule4_incremental_fee_present;
  Alcotest.test_case "G5  rule 5 — MAX_REPLACEMENT_CANDIDATES = 100" `Quick test_g5_rule5_100_cap_present;
]

let graph_tests = [
  Alcotest.test_case "G6  ancestor walk — signals_rbf_with_ancestors" `Quick test_g6_ancestor_walk_present;
  Alcotest.test_case "G7  descendant tracking on eviction"  `Quick test_g7_descendant_eviction_present;
]

let package_tests = [
  Alcotest.test_case "G8  package-RBF (BIP-431) MISSING (BUG-7, P0)" `Quick test_g8_package_rbf_missing;
]

let conflicts_tests = [
  Alcotest.test_case "G9  conflicts validated before eviction (FIX-24)" `Quick test_g9_conflicts_before_eviction;
  Alcotest.test_case "G10 find_all_conflicts disjoint-mempool case"  `Quick test_g10_no_conflicts_when_disjoint;
]

let feerate_tests = [
  Alcotest.test_case "G11 original-feerate sum present"    `Quick test_g11_original_feerate_sum_present;
  Alcotest.test_case "G12 ImprovesFeerateDiagram present"  `Quick test_g12_improves_feerate_diagram_present;
  Alcotest.test_case "G13 find_all_conflicts public/list"  `Quick test_g13_find_all_conflicts_is_public;
  Alcotest.test_case "G14 100-cap error string format"     `Quick test_g14_100_cap_error_format;
]

let rpc_surface_tests = [
  Alcotest.test_case "G15  bip125-replaceable ancestor walk (FIX-68 BUG-5, P0)" `Quick test_g15_bip125_replaceable_no_ancestor_walk;
  Alcotest.test_case "G15a self-signaling tx → bip125-replaceable=true"        `Quick test_g15a_self_signaling_true;
  Alcotest.test_case "G15a non-signaling, no ancestor → false"                 `Quick test_g15a_non_signaling_no_ancestor_false;
  Alcotest.test_case "G15a non-signaling child of signaling parent → true (BIP-125)" `Quick test_g15a_non_signaling_child_of_signaling_parent_true;
  Alcotest.test_case "G16 sendrawtransaction bypasses RBF (BUG-3, P1)"         `Quick test_g16_sendrawtransaction_bypasses_rbf;
  Alcotest.test_case "G17 error strings not Core-aligned (BUG-13, P2)"         `Quick test_g17_error_strings_not_aligned_to_core;
  Alcotest.test_case "G18 submitpackage replaced-transactions hardcoded [] (BUG-4, P0)" `Quick test_g18_submitpackage_replaces_field_hardcoded_empty;
]

let routing_tests = [
  Alcotest.test_case "G19 testmempoolaccept bypasses RBF (BUG-1, P0)" `Quick test_g19_testmempoolaccept_bypasses_rbf;
  Alcotest.test_case "G20 fee-estimator no reason discrimination (BUG-8, P1)" `Quick test_g20_fee_estimator_no_reason_discrimination;
]

let truc_tests = [
  Alcotest.test_case "G21 TRUC v3 unconditional RBF"  `Quick test_g21_truc_unconditional_replaceability;
]

let fullrbf_tests = [
  Alcotest.test_case "G22 getmempoolinfo.fullrbf=true (hardcoded)"   `Quick test_g22_getmempoolinfo_fullrbf_hardcoded_true;
  Alcotest.test_case "G23 -mempoolfullrbf CLI flag missing (BUG-6, P0)" `Quick test_g23_mempoolfullrbf_cli_flag_missing;
]

let wallet_tests = [
  Alcotest.test_case "G24 wallet default 0xFFFFFFFD RBF (FIX-70, was BUG-2)" `Quick test_g24_wallet_default_sequence_not_rbf;
  Alcotest.test_case "G24 forward-regression: create_tx emits 0xFFFFFFFD (FIX-70)" `Quick test_g24_create_transaction_emits_rbf_sequence;
  Alcotest.test_case "G25 no bumpfee/psbtbumpfee RPC (BUG-9, P2)"        `Quick test_g25_no_bumpfee_rpc;
  Alcotest.test_case "G26 no prioritisetransaction RPC (BUG-10, P2)"    `Quick test_g26_no_prioritisetransaction_rpc;
  Alcotest.test_case "G27 sendrawtransaction error envelope present"   `Quick test_g27_sendraw_decode_envelope_present;
]

let log_stats_zmq_tests = [
  Alcotest.test_case "G28 no 'replacing tx' log on RBF (BUG-13, P2)" `Quick test_g28_no_rbf_eviction_log_line;
  Alcotest.test_case "G29 no replacement_count stats (BUG-11, P1)"  `Quick test_g29_no_rbf_stats_counter;
  Alcotest.test_case "G30 no ZMQ 'replaced' reason (BUG-12, P1)"    `Quick test_g30_zmq_no_replaced_event;
]

let () =
  Alcotest.run "W120_mempool_rbf" [
    ("BIP-125 rules 1-5",  bip125_rule_tests);
    ("Graph / inheritance", graph_tests);
    ("Package-RBF",         package_tests);
    ("Conflicts",           conflicts_tests);
    ("Feerate math",        feerate_tests);
    ("RPC surface",         rpc_surface_tests);
    ("Routing",             routing_tests);
    ("TRUC",                truc_tests);
    ("fullrbf",             fullrbf_tests);
    ("Wallet / bumpfee",    wallet_tests);
    ("Log / stats / ZMQ",   log_stats_zmq_tests);
  ]
