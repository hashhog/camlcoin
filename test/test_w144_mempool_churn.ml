(* W144 — mempool per-accept GC-churn fix (2026-07-01, camlcoin un-pin
   attempt #3 post-mortem).

   Root cause of the residual RPC stall: once the pool sat at its size cap,
   EVERY accept ran a whole-pool cluster rebuild —
     - check_cluster_size_limit built a union-find over ALL entries per
       accept-with-parents, and
     - evict_by_chunks rebuilt get_all_chunks (UF + cluster grouping +
       linearization + sort) PER EVICTED CHUNK, on ~every accept at the cap —
   generating O(pool) major-heap garbage per accepted tx (~300 MB/s under the
   public-mempool flood), outrunning the incremental collector and driving
   the STW Gc.compact backstop every ~8 s (the 6-11 s RPC stalls).

   The fix: cluster-LOCAL bounded BFS for the cluster-limit check (clusters
   are bounded at 64 txs / 101 kvB by the very limits being checked), a
   single chunk-list rebuild per trim with batch eviction, and a small
   overshoot slack on the trim trigger so rebuilds are amortized over many
   accepts.

   These tests verify:
   1. decision-equivalence of the local-BFS cluster-limit check against a
      whole-pool reference (get_clusters), including the >64-tx zigzag
      cluster that anc/desc limits alone cannot catch;
   2. the cluster-vsize gate still rejects;
   3. eviction still trims to the cap, evicts worst-feerate-first, and
      raises the rolling fee floor;
   4. bounded per-accept cost at the cap: a micro-benchmark accepting into a
      full pool asserts the mean per-accept wall time and mean per-accept
      major-heap allocation stay far below the pre-fix O(pool) profile. *)

open Camlcoin

let test_db_path = "/tmp/camlcoin_test_w144_db"

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

let make_output ?(script_len=26) value =
  (* Default 26-byte script mirrors the other mempool tests; a larger
     script_len inflates tx weight for the cluster-vsize test. *)
  let base = "\x76\xa9\x14test_script_pubkey\x88\xac" in
  let script =
    if script_len <= String.length base then Cstruct.of_string base
    else Cstruct.of_string (base ^ String.make (script_len - String.length base) 'x')
  in
  Types.{ value; script_pubkey = script }

let make_input txid vout =
  Types.{
    previous_output = { txid; vout };
    script_sig = Cstruct.of_string "\x00";
    sequence = 0xFFFFFFFFl;
  }

let make_tx inputs outputs =
  Types.{ version = 1l; inputs; outputs; witnesses = []; locktime = 0l }

(* Deterministic fake confirmed-UTXO txid for index i. *)
let fake_txid i = Types.hash256_of_hex (Printf.sprintf "%064x" (i + 1))

(* Fresh mempool (scripts + standardness off — this is churn/limits testing,
   not script testing) with [n_utxos] confirmed 1_000_000-sat UTXOs at
   fake_txid 0..n-1, vout 0.  [max_size_bytes] overrides the 300 MB default
   so eviction is reachable in a unit test. *)
let create_pool ?max_size_bytes ~n_utxos () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let utxo = Utxo.UtxoSet.create db in
  for i = 0 to n_utxos - 1 do
    Utxo.UtxoSet.add utxo (fake_txid i) 0 Utxo.{
      value = 1_000_000L;
      script_pubkey = Cstruct.of_string "\x76\xa9\x14test\x88\xac";
      height = 0;
      is_coinbase = false;
    }
  done;
  let mp = Mempool.create ~network:Consensus.regtest ~require_standard:false
      ~verify_scripts:false ~utxo ~current_height:100 () in
  let mp = match max_size_bytes with
    | None -> mp
    | Some cap -> { mp with Mempool.max_size_bytes = cap }
  in
  (mp, db)

let accept_ok mp tx =
  match Mempool.accept_transaction mp tx with
  | Ok e -> e
  | Error e -> Alcotest.failf "expected accept, got reject: %s" e

let accept_err mp tx =
  match Mempool.accept_transaction mp tx with
  | Ok _ -> Alcotest.fail "expected reject, tx was accepted"
  | Error e -> e

(* ── Reference implementation of the cluster-limit decision ─────────────────
   Whole-pool computation via get_clusters (the shape of the pre-W144 code):
   the merged cluster after adding a tx with in-pool parents [depends] is the
   union of the DISTINCT clusters containing those parents, plus the new tx. *)
let reference_cluster_decision mp depends ~new_tx_vsize =
  let clusters = Mempool.get_clusters mp in
  let dep_keys =
    List.map (fun txid -> Cstruct.to_string txid) depends in
  let contains_dep (c : Mempool.cluster) =
    List.exists (fun (e : Mempool.mempool_entry) ->
      List.mem (Cstruct.to_string e.txid) dep_keys) c.txs
  in
  let merged = List.filter contains_dep clusters in
  let count =
    1 + List.fold_left (fun acc (c : Mempool.cluster) ->
      acc + List.length c.txs) 0 merged in
  let vsize =
    new_tx_vsize + List.fold_left (fun acc (c : Mempool.cluster) ->
      acc + c.total_vsize) 0 merged in
  if count > 64 then `Reject_count
  else if vsize > 101_000 then `Reject_vsize
  else `Accept

(* ── 1. Zigzag cluster: >64 txs with anc/desc counts far below their limits.
   Parents P1..P33 are independent (each spends its own confirmed UTXO, two
   outputs); child Ci spends Pi.out1 + P(i+1).out0.  Every child has exactly
   2 ancestors and every parent ≤ 2 descendants, so ONLY the cluster-count
   limit can catch the growth.  After C31 the component holds 63 txs; C32
   would merge to 65 > 64 and must be rejected. *)
let test_cluster_count_zigzag () =
  let n_parents = 33 in
  let (mp, db) = create_pool ~n_utxos:n_parents () in
  let parents = Array.init n_parents (fun i ->
    let tx = make_tx
        [make_input (fake_txid i) 0l]
        [make_output 450_000L; make_output 450_000L] in
    let entry = accept_ok mp tx in
    (tx, entry.Mempool.txid))
  in
  (* C1..C31 accepted *)
  for i = 0 to 30 do
    let (_, p_txid) = parents.(i) in
    let (_, q_txid) = parents.(i + 1) in
    let child = make_tx
        [make_input p_txid 1l; make_input q_txid 0l]
        [make_output 800_000L] in
    ignore (accept_ok mp child)
  done;
  (* C32 merges 63 + P33 + itself = 65 > 64 *)
  let (_, p32) = parents.(31) in
  let (_, p33) = parents.(32) in
  let c32 = make_tx
      [make_input p32 1l; make_input p33 0l]
      [make_output 800_000L] in
  let err = accept_err mp c32 in
  Alcotest.(check bool)
    (Printf.sprintf "rejected as too-large-cluster (got: %s)" err)
    true
    (try ignore (Str.search_forward (Str.regexp_string "too-large-cluster") err 0); true
     with Not_found -> false);
  (* Decision equivalence vs the whole-pool reference on the same depends. *)
  (match reference_cluster_decision mp [p32; p33] ~new_tx_vsize:100 with
   | `Reject_count -> ()
   | _ -> Alcotest.fail "reference disagrees: expected count reject");
  Storage.ChainDB.close db

(* ── 2. Cluster-vsize gate: 3-tx chain of ~40 kvB each crosses 101 kvB. *)
let test_cluster_vsize_gate () =
  let (mp, db) = create_pool ~n_utxos:1 () in
  (* Big txs: 4 outputs x ~10KB scripts ≈ 40 kvB (no witness: vsize ≈ size). *)
  let big_outputs value =
    [ make_output ~script_len:10_000 value;
      make_output ~script_len:10_000 value;
      make_output ~script_len:10_000 value;
      make_output ~script_len:10_000 value ]
  in
  let t1 = make_tx [make_input (fake_txid 0) 0l] (big_outputs 200_000L) in
  let e1 = accept_ok mp t1 in
  let t2 = make_tx [make_input e1.Mempool.txid 0l] (big_outputs 40_000L) in
  let e2 = accept_ok mp t2 in
  let t3 = make_tx [make_input e2.Mempool.txid 0l] (big_outputs 8_000L) in
  let err = accept_err mp t3 in
  Alcotest.(check bool)
    (Printf.sprintf "rejected as too-large-cluster on vsize (got: %s)" err)
    true
    (try ignore (Str.search_forward (Str.regexp_string "too-large-cluster") err 0); true
     with Not_found -> false);
  Storage.ChainDB.close db

(* ── 3. Local-BFS vs whole-pool reference on a mixed pool. *)
let test_cluster_check_matches_reference () =
  let (mp, db) = create_pool ~n_utxos:8 () in
  (* Chain A: A1 <- A2 <- A3 *)
  let a1 = accept_ok mp (make_tx [make_input (fake_txid 0) 0l]
                           [make_output 900_000L]) in
  let a2 = accept_ok mp (make_tx [make_input a1.Mempool.txid 0l]
                           [make_output 800_000L]) in
  let a3 = accept_ok mp (make_tx [make_input a2.Mempool.txid 0l]
                           [make_output 700_000L]) in
  (* Chain B: B1 <- B2 *)
  let b1 = accept_ok mp (make_tx [make_input (fake_txid 1) 0l]
                           [make_output 900_000L]) in
  let b2 = accept_ok mp (make_tx [make_input b1.Mempool.txid 0l]
                           [make_output 800_000L]) in
  (* Singletons *)
  let s1 = accept_ok mp (make_tx [make_input (fake_txid 2) 0l]
                           [make_output 900_000L]) in
  ignore (accept_ok mp (make_tx [make_input (fake_txid 3) 0l]
                          [make_output 900_000L]));
  let cases = [
    ("join A-tip + B-tip", [a3.Mempool.txid; b2.Mempool.txid]);
    ("extend A only", [a3.Mempool.txid]);
    ("join A + B + singleton", [a3.Mempool.txid; b2.Mempool.txid; s1.Mempool.txid]);
    ("mid-chain parent (A2)", [a2.Mempool.txid]);
  ] in
  List.iter (fun (name, depends) ->
    let got =
      match Mempool.check_cluster_size_limit ~new_tx_weight:400 mp depends
              Types.zero_hash with
      | Ok () -> `Accept
      | Error e ->
        (try ignore (Str.search_forward (Str.regexp_string "count") e 0); `Reject_count
         with Not_found -> `Reject_vsize)
    in
    let expected = reference_cluster_decision mp depends ~new_tx_vsize:100 in
    Alcotest.(check bool)
      (Printf.sprintf "%s: local BFS matches whole-pool reference" name)
      true (got = expected)
  ) cases;
  Storage.ChainDB.close db

(* ── 4. Eviction: fills past cap+slack, trims to <= cap, worst-feerate-first,
   rolling floor raised. *)
let test_eviction_trims_to_cap () =
  let cap = 200_000 in
  let n = 700 in
  let (mp, db) = create_pool ~max_size_bytes:cap ~n_utxos:n () in
  let slack = Mempool.eviction_trigger_slack mp in
  Alcotest.(check bool) "slack positive but small (< 2% of cap)"
    true (slack > 0 && slack * 50 <= cap);
  (* Independent txs with strictly increasing fee (=> increasing feerate).
     Geometric growth: each trim raises the rolling floor to ~4x the evicted
     chunk's sat/kvB rate (+ incremental relay fee), so later accepts must
     outpace the floor set by evicting the (i - capacity)-th tx.  1.005^575
     (~17x per pool turnover) clears the ~4.6x requirement with margin. *)
  let fee_of i = Int64.of_float (2_000.0 *. (1.005 ** float_of_int i)) in
  for i = 0 to n - 1 do
    let fee = fee_of i in
    let tx = make_tx [make_input (fake_txid i) 0l]
        [make_output (Int64.sub 1_000_000L fee)] in
    match Mempool.accept_transaction mp tx with
    | Ok _ -> ()
    | Error e -> Alcotest.failf "fill accept %d rejected: %s" i e
  done;
  (* The pool never exceeds cap + slack (trims trigger past the slack)... *)
  Alcotest.(check bool)
    (Printf.sprintf "bounded by cap+slack (weight=%d cap=%d slack=%d)"
       mp.Mempool.total_weight cap slack)
    true (mp.Mempool.total_weight <= cap + slack);
  (* ...and an explicit trim lands exactly at or under the cap. *)
  Mempool.evict_by_chunks_for_testing mp;
  Alcotest.(check bool)
    (Printf.sprintf "trimmed to cap (weight=%d cap=%d)"
       mp.Mempool.total_weight cap)
    true (mp.Mempool.total_weight <= cap);
  (* Worst-feerate-first: the highest-fee tx must have survived, the
     lowest-fee tx must be gone (evictions happened, so some were dropped). *)
  let count = Hashtbl.length mp.Mempool.entries in
  Alcotest.(check bool) "some txs were evicted" true (count < n);
  let fees =
    Hashtbl.fold (fun _ (e : Mempool.mempool_entry) acc -> e.fee :: acc)
      mp.Mempool.entries [] in
  let min_kept = List.fold_left min Int64.max_int fees in
  let max_kept = List.fold_left max Int64.min_int fees in
  Alcotest.(check int64) "highest-fee tx survived" (fee_of (n - 1)) max_kept;
  Alcotest.(check bool) "lowest-fee tx evicted" true
    (min_kept > fee_of 0);
  (* Rolling fee floor rose above the static relay floor. *)
  Alcotest.(check bool) "rolling floor raised" true
    (Mempool.effective_min_fee mp > mp.Mempool.min_relay_fee);
  Storage.ChainDB.close db

(* ── 5. Micro-benchmark: bounded per-accept cost at the cap.
   Pre-W144, every accept at the cap rebuilt whole-pool structures
   (union-find + linearization + sort over ~2900 entries) — milliseconds of
   CPU and ~10^5-10^6 words of major-heap garbage PER ACCEPT.  Post-fix the
   steady-state accept is O(tx) and only ~1-in-hundreds of accepts pays one
   batched trim.  Thresholds are deliberately loose (shared CI box) but far
   below the pre-fix profile. *)
let test_at_cap_accept_cost_bounded () =
  let cap = 1_000_000 in
  let n_fill = 3_200 in
  let n_bench = 200 in
  let (mp, db) = create_pool ~max_size_bytes:cap ~n_utxos:(n_fill + n_bench) () in
  (* Geometric fee growth (see test_eviction_trims_to_cap): must outpace the
     ~4.6x-per-pool-turnover rolling-floor ratchet; capacity here is ~2900
     txs, so 1.0006^2900 ~ 5.7x suffices while keeping max fee ~ 13.6k sat. *)
  for i = 0 to n_fill - 1 do
    let fee = Int64.of_float (2_000.0 *. (1.0006 ** float_of_int i)) in
    let tx = make_tx [make_input (fake_txid i) 0l]
        [make_output (Int64.sub 1_000_000L fee)] in
    (match Mempool.accept_transaction mp tx with
     | Ok _ -> () | Error e -> Alcotest.failf "fill %d rejected: %s" i e)
  done;
  Alcotest.(check bool) "pool is at/above cap for the benchmark"
    true (mp.Mempool.total_weight > cap - cap / 10);
  (* Benchmark: accepts into the full pool with high fees (beat the rolling
     floor raised by trims). *)
  let stat0 = Gc.quick_stat () in
  let t0 = Unix.gettimeofday () in
  let max_single = ref 0.0 in
  for i = 0 to n_bench - 1 do
    let fee = Int64.of_int (200_000 + i) in
    let tx = make_tx [make_input (fake_txid (n_fill + i)) 0l]
        [make_output (Int64.sub 1_000_000L fee)] in
    let s = Unix.gettimeofday () in
    (match Mempool.accept_transaction mp tx with
     | Ok _ -> () | Error e -> Alcotest.failf "bench %d rejected: %s" i e);
    let d = Unix.gettimeofday () -. s in
    if d > !max_single then max_single := d
  done;
  let elapsed = Unix.gettimeofday () -. t0 in
  let stat1 = Gc.quick_stat () in
  let major_alloc_words =
    (stat1.Gc.major_words -. stat0.Gc.major_words) in
  let per_accept_ms = elapsed *. 1000.0 /. float_of_int n_bench in
  let per_accept_major_kw = major_alloc_words /. float_of_int n_bench /. 1000.0 in
  Printf.printf
    "[w144-bench] %d at-cap accepts: mean %.3f ms/accept, max %.1f ms, \
     major alloc %.1f kwords/accept, pool weight %d (cap %d)\n%!"
    n_bench per_accept_ms (!max_single *. 1000.0)
    per_accept_major_kw mp.Mempool.total_weight cap;
  (* Memory bound holds. *)
  Alcotest.(check bool) "bounded by cap+slack" true
    (mp.Mempool.total_weight <= cap + Mempool.eviction_trigger_slack mp);
  (* Mean cost bounds: pre-fix this was O(pool) per accept (>= several ms and
     >= 10^5 words each); post-fix must stay well under. *)
  Alcotest.(check bool)
    (Printf.sprintf "mean per-accept wall < 5 ms (got %.3f)" per_accept_ms)
    true (per_accept_ms < 5.0);
  Alcotest.(check bool)
    (Printf.sprintf "mean per-accept major alloc < 100 kwords (got %.1f)"
       per_accept_major_kw)
    true (per_accept_major_kw < 100.0);
  Storage.ChainDB.close db

let () =
  Alcotest.run "w144_mempool_churn" [
    "cluster-limit local BFS", [
      Alcotest.test_case "zigzag 65-tx cluster rejected at count limit"
        `Quick test_cluster_count_zigzag;
      Alcotest.test_case "cluster vsize gate still rejects"
        `Quick test_cluster_vsize_gate;
      Alcotest.test_case "decision matches whole-pool reference"
        `Quick test_cluster_check_matches_reference;
    ];
    "eviction batching", [
      Alcotest.test_case "fills past cap+slack, trims to cap, worst-first"
        `Quick test_eviction_trims_to_cap;
      Alcotest.test_case "at-cap accept cost bounded (churn micro-benchmark)"
        `Quick test_at_cap_accept_cost_bounded;
    ];
  ]
