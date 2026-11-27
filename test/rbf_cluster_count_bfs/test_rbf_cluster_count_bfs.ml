(* RBF rule 5 must not scan the whole mempool
   (item cffix-camlcoin-rbf-cluster-count-bfs; record
   camlcoin:mempool:rbf-conflict-whole-pool-union-find).

   Core: GetEntriesForConflicts (policy/rbf.cpp:69) asks
   CTxMemPool::GetUniqueClusterCount (txmempool.h:413), which hands only the
   direct conflicts to TxGraph::CountDistinctClusters: the work is
   O(conflicts), independent of the pool size.

   camlcoin built a union-find over EVERY pool entry (build_clusters_uf) for
   each conflicting tx before it looked at the fee rules, so a peer resending
   a cheap conflicting tx made every attempt cost O(pool).

   The rbf-rule5-cost tests measure that work through the runtime's own
   allocation counter (Gc.allocated_bytes): the same rule-3-rejected
   replacement (single tx, and a package through Mempool.package_rbf) is
   evaluated against a pool of 1 and of 10_001 entries.  A union-find over the
   pool allocates two hashtables with one binding per entry, so the
   difference grows with the pool (1.6 MB at 10k on the parent commit); an
   O(conflicts) count leaves it flat.  This is a counter the test can read on
   the parent commit too, so it fails there on its assertion, not on a
   missing symbol.

   The rbf-rule5-count tests pin the decision the count feeds, so a faster
   count that gives a different answer is caught: conflicts joined through a
   shared child or a parent chain are ONE cluster, unrelated conflicts are
   one cluster each, and rule 5 rejects only above
   MAX_REPLACEMENT_CANDIDATES (100) clusters, with the unchanged reject
   reason.  Each sits at the limit (100 or 101 clusters) so that a walk
   missing either direction of the parent/child graph over-counts across the
   line. *)

open Camlcoin

let with_mp f =
  Test_tmp.with_chaindb (fun db ->
      let utxo = Utxo.UtxoSet.create db in
      let mp =
        Mempool.create ~network:Consensus.regtest ~require_standard:false
          ~verify_scripts:false ~utxo ~current_height:0 ()
      in
      f db mp)

let coin_value = 5_000_000_000L
let coin_txid n =
  Cstruct.of_string
    (String.make 30 '\xc0'
     ^ String.make 1 (Char.chr (n lsr 8)) ^ String.make 1 (Char.chr (n land 0xff)))

(* A confirmed OP_TRUE coin (coin_txid n, vout 0). *)
let put_coin db n =
  let e : Utxo.utxo_entry =
    { value = coin_value; script_pubkey = Cstruct.of_string "\x51";
      height = 1; is_coinbase = false } in
  let w = Serialize.writer_create () in
  Utxo.serialize_utxo_entry w e;
  Storage.ChainDB.store_utxo db (coin_txid n) 0 (Serialize.writer_to_string w)

let op_true = Cstruct.of_string "\x51"

(* Every tx carries a zero-value OP_RETURN so the non-witness size stays above
   MIN_STANDARD_TX_NONWITNESS_SIZE. *)
let mk ~(ins : (Types.hash256 * int) list) ~(outs : int64 list)
    : Types.transaction =
  { Types.version = 2l;
    inputs = List.map (fun (txid, vout) ->
        { Types.previous_output = { Types.txid; vout = Int32.of_int vout };
          script_sig = Cstruct.create 0; sequence = 0xFFFFFFFDl }) ins;
    outputs =
      List.map (fun v -> { Types.value = v; script_pubkey = op_true }) outs
      @ [ { Types.value = 0L;
            script_pubkey =
              Cstruct.of_string ("\x6a\x14" ^ String.make 20 'x') } ];
    witnesses = [];
    locktime = 0l }

let txid = Crypto.compute_txid

let send mp t =
  match Mempool.accept_transaction mp t with
  | Ok _ -> ()
  | Error e -> Alcotest.failf "setup tx rejected: %s" e

let starts_with ~prefix s =
  String.length s >= String.length prefix
  && String.sub s 0 (String.length prefix) = prefix

let rule3_prefix = "rejecting replacement, less fees than conflicting txs"
let rule5_prefix = "rejecting replacement; too many conflicting clusters"

let replace mp t =
  match Mempool.replace_by_fee_with_replaced ~dry_run:true mp t with
  | Ok _ -> "accepted"
  | Error e -> e

(* ---------------------------------------------------------------------------
   Test 1: the rule-3-rejected conflict costs O(conflicts), not O(pool).
   --------------------------------------------------------------------------- *)

let conflict_fee = 10_000L
let filler_count = 10_000

(* Pads the pool with [n] unrelated singleton entries.  They are copies of
   [template] under fresh txids, inserted straight into [mp.entries]: they
   spend nothing the replacement touches and nothing points at them, so the
   only code that can reach them is code that walks the whole pool.
   Accepting 10_000 real transactions would make the test take minutes for
   no extra coverage. *)
let pad_pool (mp : Mempool.mempool) (template : Mempool.mempool_entry) n =
  for i = 1 to n do
    let k = Cstruct.of_string (Printf.sprintf "filler-%026d" i) in
    Hashtbl.replace mp.entries (Cstruct.to_string k)
      { template with Mempool.txid = k; wtxid = k; depends_on = [] }
  done

let package_rule3_prefix = "package RBF failed: insufficient anti-DoS fees"

(* Single-tx path: same input as O, lower fee — rule 3 rejects it. *)
let single_attempt mp =
  let r = mk ~ins:[ (coin_txid 1, 0) ]
      ~outs:[ Int64.sub coin_value 1_000L ] in
  ((fun () -> replace mp r), rule3_prefix)

(* Package path (Mempool.package_rbf, PackageRBFChecks): parent P
   double-spends O's input, child C spends P:0; together they pay 1_500 sat,
   above the package feerate floor but below O's 10_000, so rule 3 (PaysForRBF)
   rejects the package. *)
let package_attempt mp =
  let p_change = Int64.sub coin_value 1_000L in
  let p = mk ~ins:[ (coin_txid 1, 0) ] ~outs:[ p_change ] in
  let c = mk ~ins:[ (txid p, 0) ] ~outs:[ Int64.sub p_change 500L ] in
  ((fun () ->
      match Mempool.package_rbf mp [ p; c ] with
      | Mempool.Package_rbf_accepted _ -> "accepted"
      | Mempool.Package_rbf_failed e -> e),
   package_rule3_prefix)

(* Allocation (bytes) of one rule-3-rejected replacement of a single
   conflict, in a pool padded with [fillers] unrelated entries. *)
let rule3_reject_alloc ~attempt ~fillers =
  with_mp (fun db mp ->
      put_coin db 1;
      let o = mk ~ins:[ (coin_txid 1, 0) ]
          ~outs:[ Int64.sub coin_value conflict_fee ] in
      send mp o;
      let o_entry = Hashtbl.find mp.entries (Cstruct.to_string (txid o)) in
      pad_pool mp o_entry fillers;
      Alcotest.(check int) "pool size" (fillers + 1) (Hashtbl.length mp.entries);
      let run, prefix = attempt mp in
      (* Warm-up: first-call allocations (lazy tables, caches) are not part
         of the per-attempt cost being measured. *)
      ignore (run ());
      Gc.full_major ();
      let before = Gc.allocated_bytes () in
      let reason = run () in
      let after = Gc.allocated_bytes () in
      if not (starts_with ~prefix reason) then
        Alcotest.failf "expected %S..., got %S" prefix reason;
      Alcotest.(check int) "pool untouched" (fillers + 1)
        (Hashtbl.length mp.entries);
      after -. before)

let check_flat ~what attempt =
  let small = rule3_reject_alloc ~attempt ~fillers:0 in
  let big = rule3_reject_alloc ~attempt ~fillers:filler_count in
  let extra = big -. small in
  Printf.printf
    "%s rule-3 reject alloc: pool=1 -> %.0f B, pool=%d -> %.0f B, \
     extra=%.0f B (%.1f B per added entry)\n%!"
    what small (filler_count + 1) big extra
    (extra /. float_of_int filler_count);
  (* An O(conflicts) evaluation allocates the same with or without the 10k
     unrelated entries.  64 KiB of slack is below 7 bytes per added entry —
     a single hashtable binding per entry is 32+ bytes. *)
  if extra > 65_536. then
    Alcotest.failf
      "%s rule-3 reject of 1 conflict allocates %.0f B more in a pool of %d \
       than in a pool of 1: the RBF path walks the whole mempool"
      what extra (filler_count + 1)

let test_rule3_reject_does_not_scan_pool () =
  check_flat ~what:"single-tx" single_attempt

let test_package_rule3_reject_does_not_scan_pool () =
  check_flat ~what:"package" package_attempt

(* ---------------------------------------------------------------------------
   Tests 2-4: the cluster count the rule-5 gate compares.
   --------------------------------------------------------------------------- *)

let o_fee = 1_000L

(* [n] conflicts O_1..O_n, O_i spending coin i (two outputs: change, and a
   second output a child can spend).  [link] decides how they are joined:
   - `None: unrelated, n clusters;
   - `Child_pairs: a child spends O_{2k-1}:1 and O_{2k}:1, ceil(n/2) clusters;
   - `Chain len: O_i also spends O_{i-1}:1 inside chains of [len],
     ceil(n/len) clusters.
   The replacement spends the n coins and pays less than the conflicts, so
   once rule 5 passes it fails rule 3. *)
let build_conflicts mp db ~n ~link =
  for i = 1 to n do put_coin db i done;
  let os = Array.make (n + 1) None in
  for i = 1 to n do
    let chain_parent =
      match link with
      | `Chain len when (i - 1) mod len <> 0 ->
        (match os.(i - 1) with Some p -> [ (txid p, 1) ] | None -> [])
      | _ -> [] in
    let in_value =
      Int64.add coin_value (if chain_parent = [] then 0L else 10_000L) in
    let o = mk ~ins:((coin_txid i, 0) :: chain_parent)
        ~outs:[ Int64.sub in_value (Int64.add o_fee 10_000L); 10_000L ] in
    send mp o;
    os.(i) <- Some o
  done;
  (match link with
   | `Child_pairs ->
     let k = ref 1 in
     while !k + 1 <= n do
       match os.(!k), os.(!k + 1) with
       | Some a, Some b ->
         send mp (mk ~ins:[ (txid a, 1); (txid b, 1) ] ~outs:[ 19_000L ]);
         k := !k + 2
       | _ -> assert false
     done
   | _ -> ());
  mk ~ins:(List.init n (fun i -> (coin_txid (i + 1), 0)))
    ~outs:[ Int64.sub (Int64.mul (Int64.of_int n) coin_value) 100L ]

let check_reason ~what ~prefix reason =
  if not (starts_with ~prefix reason) then
    Alcotest.failf "%s: expected %S..., got %S" what prefix reason

let test_unrelated_conflicts_over_limit () =
  (* 101 unrelated conflicts = 101 clusters > 100: rule 5, Core text. *)
  with_mp (fun db mp ->
      let r = build_conflicts mp db ~n:101 ~link:`None in
      let reason = replace mp r in
      check_reason ~what:"101 clusters" ~prefix:rule5_prefix reason;
      Alcotest.(check string) "rule-5 reason unchanged"
        "rejecting replacement; too many conflicting clusters (101 > 100)"
        reason)

let test_unrelated_conflicts_at_limit () =
  (* 100 unrelated conflicts = 100 clusters, not > 100: rule 5 passes and
     the replacement fails rule 3 instead. *)
  with_mp (fun db mp ->
      let r = build_conflicts mp db ~n:100 ~link:`None in
      check_reason ~what:"100 clusters" ~prefix:rule3_prefix (replace mp r))

let test_conflicts_joined_by_child () =
  (* 101 conflicts joined in pairs through a shared child: 51 clusters.  A
     count of conflicts (or a walk that ignores children) says 101 and
     rejects on rule 5; the cluster count passes it to rule 3. *)
  with_mp (fun db mp ->
      let r = build_conflicts mp db ~n:101 ~link:`Child_pairs in
      check_reason ~what:"101 conflicts / 51 clusters" ~prefix:rule3_prefix
        (replace mp r))

let test_conflicts_joined_by_parent_chain () =
  (* 300 conflicts in chains of 3 (O_i spends O_{i-1}:1): exactly 100
     clusters, so rule 5 passes and rule 3 rejects.  The conflicts reach the
     count in hashtable order, so a walk that misses one direction (parents
     or children) counts a chain more than once whenever it meets a later
     member before an earlier one — about 1.8 per chain, well over 100. *)
  with_mp (fun db mp ->
      let r = build_conflicts mp db ~n:300 ~link:(`Chain 3) in
      check_reason ~what:"300 conflicts / 100 clusters" ~prefix:rule3_prefix
        (replace mp r))

let test_chains_over_limit () =
  (* 202 conflicts in chains of 2: 101 clusters > 100 → rule 5. *)
  with_mp (fun db mp ->
      let r = build_conflicts mp db ~n:202 ~link:(`Chain 2) in
      Alcotest.(check string) "rule-5 reason unchanged"
        "rejecting replacement; too many conflicting clusters (101 > 100)"
        (replace mp r))

let () =
  Alcotest.run "rbf_cluster_count_bfs"
    [ ( "rbf-rule5-cost",
        [ Alcotest.test_case "rule-3 reject does not scan the pool (10k)"
            `Quick test_rule3_reject_does_not_scan_pool;
          Alcotest.test_case
            "package rule-3 reject does not scan the pool (10k)" `Quick
            test_package_rule3_reject_does_not_scan_pool ] );
      ( "rbf-rule5-count",
        [ Alcotest.test_case "101 unrelated conflicts: rule 5" `Quick
            test_unrelated_conflicts_over_limit;
          Alcotest.test_case "100 unrelated conflicts: rule 3" `Quick
            test_unrelated_conflicts_at_limit;
          Alcotest.test_case "conflicts joined by a child are one cluster"
            `Quick test_conflicts_joined_by_child;
          Alcotest.test_case "100 three-tx chains: rule 3"
            `Quick test_conflicts_joined_by_parent_chain;
          Alcotest.test_case "101 two-tx chains: rule 5" `Quick
            test_chains_over_limit ] ) ]
