(* W123 — Mining / GBT parity audit (camlcoin)
   See audit/w123_mining_gbt.md for the full write-up.

   Audit pivots off the FIX-72 OOS note:
     "select_for_block_chunked + get_all_chunks still uses raw entry.fee /
      entry.fee_rate (not modified). Wiring modified-fee into chunk
      linearisation is broader work involving cluster fee diagram
      recomputation — flagged as future scope."

   This test file confirms + expands that scope across the
   mining / getblocktemplate / submitblock / BIP-152 surface.
   Tests are STRUCTURAL / source-marker style — no full chain spin-up is
   needed.  Tests for present-correct gates use the same `make_template`
   helper as W108 and only assert the absence-pattern that BUG-N would
   flip.

   Gate verdict legend in audit/w123_mining_gbt.md:
     PRESENT / PARTIAL / MISSING + P0 / P1 / P2.

   Build:
     dune build && _build/default/test/test_w123_mining_gbt.exe

   (Avoid `dune runtest` per FIX-64 / FIX-80 dune-lock-contention lessons.)
   ============================================================================ *)

open Camlcoin

(* ============================================================================
   Source-marker helpers (no chain state needed for most tests)
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
    else if Sys.file_exists (Filename.concat dir "lib/mining.ml") then dir
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

let count_occurrences haystack needle =
  let nlen = String.length needle in
  let hlen = String.length haystack in
  let rec go i n =
    if i > hlen - nlen then n
    else if String.sub haystack i nlen = needle then go (i + nlen) (n + 1)
    else go (i + 1) n
  in
  if nlen = 0 then 0 else go 0 0

(* Light template helper, mirrors the W108 pattern. *)
let test_db_path = "/tmp/camlcoin_test_w123_mining_db"

let cleanup_test_db () =
  let rec rm_rf path =
    if Sys.file_exists path then begin
      if Sys.is_directory path then begin
        Array.iter (fun f -> rm_rf (Filename.concat path f)) (Sys.readdir path);
        Unix.rmdir path
      end else
        Unix.unlink path
    end
  in
  rm_rf test_db_path

let create_test_chain_state () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let chain = Sync.create_chain_state db Consensus.regtest in
  (chain, db)

let make_template () =
  let (chain, db) = create_test_chain_state () in
  let utxo = Utxo.UtxoSet.create db in
  let mp = Mempool.create ~require_standard:false ~verify_scripts:false
             ~utxo ~current_height:0 () in
  let payout_script = Cstruct.of_string "\x76\xa9\x14test_w123\x88\xac" in
  let template = Mining.create_block_template ~chain ~mp ~payout_script in
  (template, db)

let get_assoc (json : Yojson.Safe.t) key : Yojson.Safe.t option =
  match json with
  | `Assoc fields -> List.assoc_opt key fields
  | _ -> None

let has_field json key =
  match get_assoc json key with
  | Some _ -> true
  | None -> false

(* ============================================================================
   PRESENT-gate assertions (G1-G8, G10-G19, G22, G25, G28).
   These confirm camlcoin matches Core where it does — they catch regressions
   if a future refactor removes a wiring that this audit currently observes
   as correct.  Each test mirrors the source-marker style of the W120 audit.
   ============================================================================ *)

let test_g1_max_block_weight_4M () =
  Alcotest.(check int)
    "G1: Consensus.max_block_weight = 4_000_000"
    4_000_000 Consensus.max_block_weight

let test_g2_reserved_weight_clamp_constants () =
  let src = slurp_lib "mining.ml" in
  Alcotest.(check bool)
    "G2: default_block_reserved_weight = 8000 source marker"
    true (contains_substring src "default_block_reserved_weight = 8000");
  Alcotest.(check bool)
    "G2: minimum_block_reserved_weight = 2000 source marker"
    true (contains_substring src "minimum_block_reserved_weight = 2000");
  Alcotest.(check bool)
    "G2: clamp_reserved_weight helper present"
    true (contains_substring src "let clamp_reserved_weight w =")

let test_g3_max_block_sigops_80k () =
  Alcotest.(check int)
    "G3: Consensus.max_block_sigops_cost = 80_000"
    80_000 Consensus.max_block_sigops_cost;
  let src = slurp_lib "mining.ml" in
  Alcotest.(check bool)
    "G3: sigops gate strict-less-than (mirrors Core's >= refuse)"
    true (contains_substring src
            "!total_sigops_cost + pkg_sigops < Consensus.max_block_sigops_cost")

let test_g4_coinbase_bip34_height () =
  let src = slurp_lib "mining.ml" in
  Alcotest.(check bool)
    "G4: BIP-34 height encoding via Consensus.encode_height_in_coinbase"
    true (contains_substring src "Consensus.encode_height_in_coinbase")

let test_g5_coinbase_sequence_nonfinal () =
  let src = slurp_lib "mining.ml" in
  Alcotest.(check bool)
    "G5: coinbase sequence = 0xFFFFFFFE source marker"
    true (contains_substring src "sequence = 0xFFFFFFFEl")

let test_g6_coinbase_locktime_height_minus_one () =
  let src = slurp_lib "mining.ml" in
  Alcotest.(check bool)
    "G6: coinbase locktime = max 0 (height - 1)"
    true (contains_substring src
            "locktime = Int32.of_int (max 0 (height - 1));")

let test_g7_subsidy_plus_fees () =
  let src = slurp_lib "mining.ml" in
  Alcotest.(check bool)
    "G7: reward = subsidy + total_fee"
    true (contains_substring src "Int64.add subsidy total_fee")

let test_g8_per_tx_fees_aggregated () =
  let src = slurp_lib "mining.ml" in
  Alcotest.(check bool)
    "G8: total_fee sums per-tx fees via List.fold_left Int64.add"
    true (contains_substring src
            "Int64.add acc fee) 0L selected")

(* ============================================================================
   G9 — BUG-1 P1 : chunk linearisation reads RAW fee, not modified fee.
   FIX-72 OOS scope.  Five cascading sub-paths.
   ============================================================================ *)

(* 9a — compute_ancestor_fee_rate in mining.ml reads entry.fee (raw). *)
let test_g9a_compute_ancestor_fee_rate_reads_raw_fee () =
  let src = slurp_lib "mining.ml" in
  (* Pre-fix marker: the helper reads entry.fee and a.fee (raw fields)
     and does NOT call Mempool.get_modified_fee.  When the fix lands, the
     fee-summation will use get_modified_fee and this assertion must be
     inverted. *)
  Alcotest.(check bool)
    "BUG-1.9a (pre-fix): compute_ancestor_fee_rate sums raw entry.fee"
    true (contains_substring src
            "entry.fee unselected_ancestors");
  Alcotest.(check bool)
    "BUG-1.9a (pre-fix): mining.ml does NOT call Mempool.get_modified_fee \
                          anywhere"
    false (contains_substring src "Mempool.get_modified_fee")

(* 9b — find_best_chunk in mempool.ml uses entry.fee / entry.fee_rate. *)
let test_g9b_find_best_chunk_reads_raw_fee_rate () =
  let src = slurp_lib "mempool.ml" in
  Alcotest.(check bool)
    "BUG-1.9b (pre-fix): find_best_chunk sums raw entry.fee"
    true (contains_substring src
            "let chunk_fee = List.fold_left (fun acc e -> \
             Int64.add acc e.fee) 0L chunk_txs");
  Alcotest.(check bool)
    "BUG-1.9b (pre-fix): find_best_chunk single-tx fallback uses raw \
                         best_root.fee_rate"
    true (contains_substring src
            "chunk_fee_rate = best_root.fee_rate;")

(* 9c — ImprovesFeerateDiagram (linearize_entries → find_best_chunk) is
   downstream of the same raw-fee chunker.  We grep for the call chain
   marker rather than reproduce the full Rule-3 setup. *)
let test_g9c_improves_diagram_uses_raw_fee_chunker () =
  let src = slurp_lib "mempool.ml" in
  Alcotest.(check bool)
    "BUG-1.9c (pre-fix): linearize_entries uses find_best_chunk \
                         (which reads raw fee)"
    true (contains_substring src
            "let best = find_best_chunk remaining mp in");
  Alcotest.(check bool)
    "BUG-1.9c (pre-fix): check_improves_feerate_diagram calls \
                         linearize_entries"
    true (contains_substring src
            "linearize_entries mp after_entries")

(* 9d — get_worst_chunk / track_package_removed use chunk_fee_rate from
   find_best_chunk → raw fee. *)
let test_g9d_eviction_uses_raw_chunk_fee_rate () =
  let src = slurp_lib "mempool.ml" in
  Alcotest.(check bool)
    "BUG-1.9d (pre-fix): get_worst_chunk reads chunks from get_all_chunks \
                          (raw fee)"
    true (contains_substring src
            "let chunks = get_all_chunks mp in");
  Alcotest.(check bool)
    "BUG-1.9d (pre-fix): rolling-min-fee bump reads worst_chunk.chunk_fee_rate"
    true (contains_substring src "worst_chunk.chunk_fee_rate")

(* 9e — informational: template_to_json per-tx `fee` field IS raw fee,
   which matches Core's behaviour (Core also emits entry.GetFee() not
   GetModifiedFee() in the per-tx `fee` field).  This sub-gate is
   PRESENT for Core-parity and is NOT part of BUG-1. *)
let test_g9e_template_json_per_tx_fee_is_raw_core_parity () =
  let src = slurp_lib "mining.ml" in
  Alcotest.(check bool)
    "G9e: template_to_json reads template.tx_fees (raw, Core-parity)"
    true (contains_substring src "List.nth template.tx_fees")

(* 9-forward-regression : assert that Mempool.get_modified_fee exists as
   a *function* so the fix has a target to wire in.  This guards against
   regression of FIX-72's surface. *)
let test_g9_modified_fee_helper_available () =
  let src = slurp_lib "mempool.ml" in
  Alcotest.(check bool)
    "G9 forward-regression: Mempool.get_modified_fee defined (FIX-72 surface)"
    true (contains_substring src "let get_modified_fee (mp : mempool)");
  Alcotest.(check bool)
    "G9 forward-regression: Mempool.apply_delta defined (FIX-72 surface)"
    true (contains_substring src
            "let apply_delta (mp : mempool) (txid : Types.hash256)")

(* G10 — ancestor-aware selection (shape PRESENT). *)
let test_g10_compute_ancestor_fee_rate_present () =
  let src = slurp_lib "mining.ml" in
  Alcotest.(check bool)
    "G10: compute_ancestor_fee_rate helper present"
    true (contains_substring src
            "let compute_ancestor_fee_rate (entry : Mempool.mempool_entry)")

(* G11 — IsFinalTx per chunk. *)
let test_g11_isfinal_tx_per_chunk () =
  let src = slurp_lib "mining.ml" in
  Alcotest.(check bool)
    "G11: chunk_is_final calls Validation.is_tx_final"
    true (contains_substring src "Validation.is_tx_final e.tx ~block_height")

(* G12 — MAX_CONSECUTIVE_FAILURES constant. *)
let test_g12_max_consecutive_failures_constants () =
  let src = slurp_lib "mining.ml" in
  Alcotest.(check bool)
    "G12: max_consecutive_failures = 1000"
    true (contains_substring src "max_consecutive_failures = 1000");
  Alcotest.(check bool)
    "G12: block_full_enough_weight_delta = 4000"
    true (contains_substring src "block_full_enough_weight_delta = 4000")

(* G13 — blockMinFeeRate gate. *)
let test_g13_block_min_fee_rate_gate () =
  let src = slurp_lib "mining.ml" in
  Alcotest.(check bool)
    "G13: min_fee_rate_sat_per_kvb gate exists"
    true (contains_substring src "min_fee_rate_sat_per_kvb")

(* G14 — versionbits / BIP-9 deployment signaling. *)
let test_g14_versionbits_signaling () =
  let src = slurp_lib "mining.ml" in
  Alcotest.(check bool)
    "G14: compute_block_version called with deployments+caches"
    true (contains_substring src "Consensus.compute_block_version")

(* G15 — BIP-94 timewarp constant. *)
let test_g15_bip94_max_timewarp () =
  Alcotest.(check int) "G15: Consensus.max_timewarp = 600"
    600 Consensus.max_timewarp

(* G16 — witness commitment computation (BIP-141). *)
let test_g16_witness_commitment_present () =
  let (template, db) = make_template () in
  let json = Mining.template_to_json template in
  Alcotest.(check bool) "G16: default_witness_commitment field present"
    true (has_field json "default_witness_commitment");
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* G17 PARTIAL — witness commitment is recomputed instead of being read
   from coinbase_tx.outputs[1].  This is W108 BUG-28 carry-forward. *)
let test_g17_witness_commitment_recomputed_in_json () =
  let src = slurp_lib "mining.ml" in
  Alcotest.(check bool)
    "G17 (pre-fix): template_to_json recomputes witness commitment from scratch \
                    (W108 BUG-28 carry)"
    true (contains_substring src
            "let witness_root = compute_witness_merkle_root all_txs in\n\
             \  let commitment = compute_witness_commitment witness_root in")

(* G18 — all major GBT JSON fields PRESENT. *)
let test_g18_gbt_json_fields_present () =
  let (template, db) = make_template () in
  let json = Mining.template_to_json template in
  let required_fields = [
    "capabilities"; "rules"; "vbavailable"; "vbrequired"; "version";
    "previousblockhash"; "transactions"; "coinbaseaux"; "coinbasevalue";
    "longpollid"; "target"; "mintime"; "mutable"; "noncerange";
    "sigoplimit"; "weightlimit"; "curtime"; "bits"; "height";
    "default_witness_commitment";
  ] in
  List.iter (fun f ->
    Alcotest.(check bool)
      (Printf.sprintf "G18: field %s present in GBT" f) true (has_field json f)
  ) required_fields;
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* G19 — longpollid format = prev_block_hash || transactions_updated. *)
let test_g19_longpollid_format () =
  let src = slurp_lib "mining.ml" in
  Alcotest.(check bool)
    "G19: longpollid = prev_block_hex ^ transactions_updated"
    true (contains_substring src
            "Types.hash256_to_hex_display template.header.prev_block\n\
             \             ^ string_of_int template.transactions_updated")

(* G20 PARTIAL — mintime is the (already-clamped) header timestamp, not
   strictly MTP+1.  W108 BUG-9 carry-forward. *)
let test_g20_mintime_partial () =
  let src = slurp_lib "mining.ml" in
  Alcotest.(check bool)
    "G20 (pre-fix): mintime emitted from template.header.timestamp \
                     (not pindexPrev.GetMTP() + 1).  W108 BUG-9."
    true (contains_substring src
            "(\"mintime\",\n\
             \      `Int (Int32.to_int template.header.timestamp));")

(* G21 PARTIAL — submitblock BIP-22 result strings present-shape. *)
let test_g21_bip22_result_strings () =
  let src = slurp_lib "rpc.ml" in
  Alcotest.(check bool)
    "G21: bip22_of_submitblock_error exists"
    true (contains_substring src "let bip22_of_submitblock_error");
  Alcotest.(check bool)
    "G21: maps to high-hash / bad-txnmrklroot / bad-cb-amount / sigops"
    true (contains_substring src "\"high-hash\"" &&
          contains_substring src "\"bad-txnmrklroot\"" &&
          contains_substring src "\"bad-cb-amount\"");
  (* W108 BUG-15 carry: no duplicate / duplicate-invalid arm. *)
  Alcotest.(check bool)
    "G21 (pre-fix): no `duplicate` BIP-22 token (W108 BUG-15)"
    false (contains_substring src "\"duplicate\"" &&
           contains_substring src "\"duplicate-invalid\"")

(* G22 — submitblock side-branch / reorg path. *)
let test_g22_submitblock_side_branch_path () =
  let src = slurp_lib "mining.ml" in
  Alcotest.(check bool)
    "G22: submit_block calls Sync.try_attach_side_branch_and_reorg"
    true (contains_substring src
            "Sync.try_attach_side_branch_and_reorg")

(* G23 — BUG-2 P2 : UpdateUncommittedBlockStructures missing in submit_block.
   Core net_processing.cpp:74 calls chainman.GenerateCoinbaseCommitment
   before validation.  Camlcoin trusts the submitter to have a correct
   commitment already. *)
let test_g23_submitblock_no_update_uncommitted_pre_fix () =
  let src = slurp_lib "mining.ml" in
  Alcotest.(check bool)
    "BUG-2 (pre-fix): submit_block does NOT call GenerateCoinbaseCommitment / \
                       UpdateUncommittedBlockStructures"
    false (contains_substring src "GenerateCoinbaseCommitment" ||
           contains_substring src "UpdateUncommittedBlockStructures")

(* G24 — BUG-3 P2 : submitheader RPC not registered. *)
let test_g24_submitheader_rpc_missing () =
  let src = slurp_lib "rpc.ml" in
  Alcotest.(check bool)
    "BUG-3 (pre-fix): no handle_submitheader function defined"
    false (contains_substring src "handle_submitheader");
  Alcotest.(check bool)
    "BUG-3 (pre-fix): \"submitheader\" not in dispatcher switch"
    false (contains_substring src "| \"submitheader\" ->")

(* G25 — generatetoaddress / generateblock present, regtest-gated. *)
let test_g25_regtest_mining_rpcs () =
  let src = slurp_lib "rpc.ml" in
  Alcotest.(check bool)
    "G25: handle_generatetoaddress present"
    true (contains_substring src "let handle_generatetoaddress");
  Alcotest.(check bool)
    "G25: handle_generateblock present"
    true (contains_substring src "let handle_generateblock");
  Alcotest.(check bool)
    "G25: regtest gate `network_type <> Consensus.Regtest` present"
    true (contains_substring src
            "ctx.network.network_type <> Consensus.Regtest")

(* G26 — BUG-4 P2 : getmininginfo emits constant-zero current-block stats. *)
let test_g26_getmininginfo_currentblock_constant_zero () =
  let src = slurp_lib "rpc.ml" in
  Alcotest.(check bool)
    "BUG-4 (pre-fix): currentblocksize emitted as `Int 0"
    true (contains_substring src "(\"currentblocksize\", `Int 0);");
  Alcotest.(check bool)
    "BUG-4 (pre-fix): currentblockweight emitted as `Int 0"
    true (contains_substring src "(\"currentblockweight\", `Int 0);");
  Alcotest.(check bool)
    "BUG-4 (pre-fix): currentblocktx emitted as `Int 0"
    true (contains_substring src "(\"currentblocktx\", `Int 0);")

(* G27 — BUG-5 P2 : getnetworkhashps ignores height + nblocks=-1. *)
let test_g27_getnetworkhashps_param_handling () =
  let src = slurp_lib "rpc.ml" in
  Alcotest.(check bool)
    "G27: handle_getnetworkhashps defined"
    true (contains_substring src "let handle_getnetworkhashps");
  (* Pre-fix marker: no explicit -1 sentinel handling, no height resolution
     from a Yojson `Int param.  Hard to assert exhaustively in a source-
     marker test; the absence of a sentinel-handling branch is the best
     proxy. *)
  let getnetworkhashps_block =
    try
      let i = Str.search_forward
                (Str.regexp_string "let handle_getnetworkhashps") src 0 in
      String.sub src i (min 2048 (String.length src - i))
    with Not_found -> ""
  in
  Alcotest.(check bool)
    "BUG-5 (pre-fix): handle_getnetworkhashps body has no `-1` sentinel branch"
    false (contains_substring getnetworkhashps_block "= -1" ||
           contains_substring getnetworkhashps_block "nblocks_neg_one")

(* G28 — prioritisetransaction RPC PRESENT (FIX-72). *)
let test_g28_prioritisetransaction_rpc_present () =
  let src = slurp_lib "rpc.ml" in
  Alcotest.(check bool)
    "G28: handle_prioritisetransaction present"
    true (contains_substring src "let handle_prioritisetransaction");
  Alcotest.(check bool)
    "G28: dispatcher entry for prioritisetransaction"
    true (contains_substring src "| \"prioritisetransaction\" ->")

(* G29 — BUG-6 P2 : BIP-23 `mode` param not parsed. *)
let test_g29_bip23_mode_param_not_parsed () =
  let src = slurp_lib "rpc.ml" in
  (* handle_getblocktemplate only reads coinbase_address; it never reads
     a "mode" key from the params object. *)
  let gbt_block =
    try
      let i = Str.search_forward
                (Str.regexp_string "let handle_getblocktemplate") src 0 in
      String.sub src i (min 4096 (String.length src - i))
    with Not_found -> ""
  in
  Alcotest.(check bool)
    "BUG-6 (pre-fix): getblocktemplate handler reads `coinbase_address` only"
    true (contains_substring gbt_block "coinbase_address");
  Alcotest.(check bool)
    "BUG-6 (pre-fix): getblocktemplate handler does NOT read `mode` param"
    false (contains_substring gbt_block "\"mode\"")

(* G30 — BUG-7 P1 : announce_block does NOT push cmpctblock to HB peers. *)
let test_g30_announce_block_no_cmpctblock () =
  let src = slurp_lib "peer_manager.ml" in
  let announce_block_block =
    try
      let i = Str.search_forward
                (Str.regexp_string "let announce_block (pm : t)") src 0 in
      String.sub src i (min 2048 (String.length src - i))
    with Not_found -> ""
  in
  (* Confirm headers/inv paths are present so the test is meaningful. *)
  Alcotest.(check bool)
    "G30 baseline: announce_block sends HeadersMsg path"
    true (contains_substring announce_block_block "P2p.HeadersMsg");
  Alcotest.(check bool)
    "G30 baseline: announce_block sends InvMsg path"
    true (contains_substring announce_block_block "P2p.InvMsg");
  (* The bug: no CmpctblockMsg / cmpctblock send. *)
  Alcotest.(check bool)
    "BUG-7 (pre-fix): announce_block does NOT push CmpctblockMsg \
                       (BIP-152 HB announce gap)"
    false (contains_substring announce_block_block "CmpctblockMsg" ||
           contains_substring announce_block_block "make_cmpctblock_msg" ||
           contains_substring announce_block_block "P2p.Cmpctblock")

(* ============================================================================
   Cross-impact assertions: FIX-72 OOS scope summary.
   Asserts the overall shape of BUG-1 — that NEITHER mining.ml NOR mempool.ml
   call get_modified_fee from any chunk-linearisation path.  If a future
   fix lands that call, the assertions invert and the test must be updated
   to assert the post-fix behaviour.
   ============================================================================ *)

let test_oos_summary_fix72_chunk_modified_fee () =
  let mining_src = slurp_lib "mining.ml" in
  let mempool_src = slurp_lib "mempool.ml" in
  (* The mining module has zero references to get_modified_fee
     (the FIX-72 surface) — confirms the gap end-to-end. *)
  Alcotest.(check int)
    "OOS: mining.ml has 0 references to get_modified_fee"
    0 (count_occurrences mining_src "get_modified_fee");
  (* Mempool has the helper + uses it inside replace_by_fee only.  Count
     occurrences and assert there are SOME (FIX-72 wiring proof) but the
     chunk-linearizer find_best_chunk / linearize_cluster / get_all_chunks
     do not reference it. *)
  let mempool_uses = count_occurrences mempool_src "get_modified_fee" in
  Alcotest.(check bool)
    "OOS: mempool.ml DOES reference get_modified_fee at least once (FIX-72)"
    true (mempool_uses > 0);
  (* find_best_chunk body itself: extract a window around the definition
     and assert the helper is not invoked inside. *)
  let fbc_idx =
    try Str.search_forward
          (Str.regexp_string "let find_best_chunk (remaining") mempool_src 0
    with Not_found -> -1
  in
  Alcotest.(check bool)
    "OOS: find_best_chunk definition located"
    true (fbc_idx >= 0);
  if fbc_idx >= 0 then begin
    let window_end =
      try Str.search_forward (Str.regexp_string "let remove_chunk")
            mempool_src fbc_idx
      with Not_found -> min (fbc_idx + 4096) (String.length mempool_src)
    in
    let fbc_body = String.sub mempool_src fbc_idx (window_end - fbc_idx) in
    Alcotest.(check bool)
      "OOS: find_best_chunk body does NOT call get_modified_fee \
              (FIX-72 OOS gap confirmed)"
      false (contains_substring fbc_body "get_modified_fee")
  end

(* ============================================================================
   Test runner
   ============================================================================ *)

let () =
  cleanup_test_db ();
  let open Alcotest in
  run "W123 Mining/GBT" [
    "G1-G8 present", [
      test_case "G1 max_block_weight = 4M" `Quick test_g1_max_block_weight_4M;
      test_case "G2 reserved_weight clamp constants" `Quick
        test_g2_reserved_weight_clamp_constants;
      test_case "G3 max_block_sigops_cost = 80k" `Quick
        test_g3_max_block_sigops_80k;
      test_case "G4 coinbase BIP-34 height encoding" `Quick
        test_g4_coinbase_bip34_height;
      test_case "G5 coinbase sequence = 0xFFFFFFFE" `Quick
        test_g5_coinbase_sequence_nonfinal;
      test_case "G6 coinbase locktime = height - 1" `Quick
        test_g6_coinbase_locktime_height_minus_one;
      test_case "G7 reward = subsidy + fees" `Quick test_g7_subsidy_plus_fees;
      test_case "G8 per-tx fees aggregated" `Quick
        test_g8_per_tx_fees_aggregated;
    ];
    "G9 BUG-1 chunk modified-fee gap", [
      test_case "G9a compute_ancestor_fee_rate reads raw entry.fee" `Quick
        test_g9a_compute_ancestor_fee_rate_reads_raw_fee;
      test_case "G9b find_best_chunk reads raw fee" `Quick
        test_g9b_find_best_chunk_reads_raw_fee_rate;
      test_case "G9c ImprovesFeerateDiagram uses raw chunker" `Quick
        test_g9c_improves_diagram_uses_raw_fee_chunker;
      test_case "G9d eviction uses raw chunk_fee_rate" `Quick
        test_g9d_eviction_uses_raw_chunk_fee_rate;
      test_case "G9e per-tx fee field is raw (Core-parity)" `Quick
        test_g9e_template_json_per_tx_fee_is_raw_core_parity;
      test_case "G9 forward-regression: get_modified_fee helper present" `Quick
        test_g9_modified_fee_helper_available;
    ];
    "G10-G19 present", [
      test_case "G10 compute_ancestor_fee_rate helper" `Quick
        test_g10_compute_ancestor_fee_rate_present;
      test_case "G11 IsFinalTx per chunk" `Quick test_g11_isfinal_tx_per_chunk;
      test_case "G12 MAX_CONSECUTIVE_FAILURES constants" `Quick
        test_g12_max_consecutive_failures_constants;
      test_case "G13 blockMinFeeRate gate" `Quick
        test_g13_block_min_fee_rate_gate;
      test_case "G14 versionbits / BIP-9 signaling" `Quick
        test_g14_versionbits_signaling;
      test_case "G15 BIP-94 max_timewarp = 600" `Quick
        test_g15_bip94_max_timewarp;
      test_case "G16 witness commitment field present" `Quick
        test_g16_witness_commitment_present;
      test_case "G17 (W108 BUG-28) witness commitment recomputed" `Quick
        test_g17_witness_commitment_recomputed_in_json;
      test_case "G18 GBT JSON fields present" `Quick
        test_g18_gbt_json_fields_present;
      test_case "G19 longpollid format" `Quick test_g19_longpollid_format;
    ];
    "G20-G25 mixed", [
      test_case "G20 (W108 BUG-9) mintime is header.timestamp" `Quick
        test_g20_mintime_partial;
      test_case "G21 BIP-22 result strings (W108 BUG-15 carry)" `Quick
        test_g21_bip22_result_strings;
      test_case "G22 submitblock side-branch path" `Quick
        test_g22_submitblock_side_branch_path;
      test_case "G23 BUG-2 UpdateUncommittedBlockStructures missing" `Quick
        test_g23_submitblock_no_update_uncommitted_pre_fix;
      test_case "G24 BUG-3 submitheader RPC missing" `Quick
        test_g24_submitheader_rpc_missing;
      test_case "G25 generatetoaddress / generateblock present" `Quick
        test_g25_regtest_mining_rpcs;
    ];
    "G26-G30 bugs", [
      test_case "G26 BUG-4 getmininginfo current-block zero" `Quick
        test_g26_getmininginfo_currentblock_constant_zero;
      test_case "G27 BUG-5 getnetworkhashps param handling" `Quick
        test_g27_getnetworkhashps_param_handling;
      test_case "G28 prioritisetransaction RPC present (FIX-72)" `Quick
        test_g28_prioritisetransaction_rpc_present;
      test_case "G29 BUG-6 BIP-23 mode param not parsed" `Quick
        test_g29_bip23_mode_param_not_parsed;
      test_case "G30 BUG-7 cmpctblock announce missing" `Quick
        test_g30_announce_block_no_cmpctblock;
    ];
    "OOS summary", [
      test_case "FIX-72 OOS: chunk linearisation has zero modified-fee \
                 references"
        `Quick test_oos_summary_fix72_chunk_modified_fee;
    ];
  ]
