(* submitpackage package RBF (item done-camlcoin-package-rbf; Core-regtest
   group package_rbf, class rule "submitpackage package RBF").

   Core v31 AcceptPackage tries each tx alone first.  A parent that conflicts
   with the pool but pays less than the conflicts (RBF rule 3, a
   TX_RECONSIDERABLE failure) and its child (missing input) are then
   evaluated together, and PackageRBFChecks (validation.cpp) judges the pair
   as one replacement: 1-parent-1-child, no mempool ancestors, rule 5, rules
   3/4 on the package's fees and sigop-adjusted vsize, package feerate above
   the parent's, the cluster limit on the post-eviction cluster
   (too-large-cluster), and the feerate diagram.

   Each scenario puts a conflict O and its descendant D in the pool, then
   submits a parent P double-spending O's input and P's child C.  P and C
   carry bare 1-of-1 multisig outputs (20 legacy sigops each, so the
   sigop-adjusted weight is 1_600 per output), mirroring the harness group. *)

open Camlcoin

let with_ctx ?(verify_scripts = false) ?cap f =
  Test_tmp.with_chaindb (fun db ->
      let utxo = Utxo.UtxoSet.create db in
      let mp =
        Mempool.create ~network:Consensus.regtest ~require_standard:false
          ~verify_scripts ~utxo ~current_height:0 ()
      in
      (* -maxmempool in bytes (the create argument is whole MB). *)
      let mp = match cap with
        | Some c -> { mp with Mempool.max_size_bytes = c }
        | None -> mp in
      let chain = Sync.create_chain_state db Consensus.regtest in
      let ctx : Rpc.rpc_context =
        {
          chain;
          mempool = mp;
          peer_manager = Peer_manager.create Consensus.regtest;
          wallet = None;
          wallet_manager = None;
          fee_estimator = Fee_estimation.create ();
          network = Consensus.regtest;
          filter_index = None;
          utxo = None;
          data_dir = None;
          snapshot_activation = None;
        }
      in
      f ctx)

let coin_value = 5_000_000_000L

let coin_txid n = Cstruct.of_string (String.make 32 (Char.chr n))

(* A confirmed OP_TRUE coin (txid n n .., vout 0). *)
let put_coin (ctx : Rpc.rpc_context) n =
  let e : Utxo.utxo_entry =
    { value = coin_value; script_pubkey = Cstruct.of_string "\x51";
      height = 1; is_coinbase = false } in
  let w = Serialize.writer_create () in
  Utxo.serialize_utxo_entry w e;
  Storage.ChainDB.store_utxo ctx.chain.db (coin_txid n) 0
    (Serialize.writer_to_string w)

let op_true = Cstruct.of_string "\x51"

(* OP_1 <G> OP_1 OP_CHECKMULTISIG: 20 legacy sigops (inaccurate count). *)
let multisig =
  Cstruct.of_hex
    "51210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179851ae"

let output_sats = 1_000L

let tx ~(ins : (Types.hash256 * int) list) ~change ~spk ~n : Types.transaction =
  { Types.version = 2l;
    inputs = List.map (fun (txid, vout) ->
        { Types.previous_output = { Types.txid; vout = Int32.of_int vout };
          script_sig = Cstruct.create 0; sequence = 0xFFFFFFFDl }) ins;
    (* the zero-value OP_RETURN keeps the non-witness size above
       MIN_STANDARD_TX_NONWITNESS_SIZE *)
    outputs = ({ Types.value = change; script_pubkey = op_true }
               :: List.init n (fun _ ->
                   { Types.value = output_sats; script_pubkey = spk }))
              @ [ { Types.value = 0L;
                    script_pubkey =
                      Cstruct.of_string ("\x6a\x14" ^ String.make 20 'x') } ];
    witnesses = [];
    locktime = 0l }

let txid t = Crypto.compute_txid t
let txid_hex t = Types.hash256_to_hex_display (txid t)
let wtxid_hex t = Types.hash256_to_hex_display (Crypto.compute_wtxid t)

let tx_hex (t : Types.transaction) =
  let w = Serialize.writer_create () in
  Serialize.serialize_transaction w t;
  let s = Serialize.writer_to_string w in
  String.concat "" (List.init (String.length s)
                      (fun i -> Printf.sprintf "%02x" (Char.code s.[i])))

let conflict_fee = 20_000L
let descendant_fee = 1_000L

(* OP_HASH160 <20 bytes> OP_EQUAL: the harness pays O's outputs to a P2SH
   script, 32 bytes per output, which sets O's feerate (~1.04 sat/vB). *)
let p2sh =
  Cstruct.of_string ("\xa9\x14" ^ String.make 20 '\x00' ^ "\x87")

(* O (600 cheap P2SH outputs, fee 20_000) and D (O's child, fee 1_000). *)
let conflict_pair ~coin =
  let o_change = Int64.sub coin_value
      (Int64.add conflict_fee (Int64.mul 600L output_sats)) in
  let o = tx ~ins:[ (coin, 0) ] ~change:o_change ~spk:p2sh ~n:600 in
  let d = tx ~ins:[ (txid o, 0) ] ~change:(Int64.sub o_change descendant_fee)
      ~spk:op_true ~n:0 in
  (o, d)

(* P double-spends O's input; C spends P:0 (plus [extra_ins]). *)
let replacement ~coin ~p_fee ~p_outs ~p_spk ~c_fee ~c_outs ?(extra_ins = [])
    ?(extra_in_value = 0L) () =
  let p_change = Int64.sub coin_value
      (Int64.add p_fee (Int64.mul (Int64.of_int p_outs) output_sats)) in
  let p = tx ~ins:[ (coin, 0) ] ~change:p_change ~spk:p_spk ~n:p_outs in
  let c_change = Int64.sub (Int64.add p_change extra_in_value)
      (Int64.add c_fee (Int64.mul (Int64.of_int c_outs) output_sats)) in
  let c = tx ~ins:((txid p, 0) :: extra_ins) ~change:c_change ~spk:multisig
      ~n:c_outs in
  (p, c)

let send (ctx : Rpc.rpc_context) t =
  match Mempool.accept_transaction ctx.mempool t with
  | Ok _ -> ()
  | Error e -> Alcotest.failf "setup tx rejected: %s" e

let submitpackage ctx txs =
  match Rpc.dispatch_rpc ctx "submitpackage"
          [ `List (List.map (fun t -> `String (tx_hex t)) txs) ] with
  | Ok j -> j
  | Error (c, m) -> Alcotest.failf "submitpackage: error (%d) %s" c m

let pool (ctx : Rpc.rpc_context) =
  match Rpc.dispatch_rpc ctx "getrawmempool" [] with
  | Ok (`List l) -> List.sort compare (List.map Yojson.Safe.Util.to_string l)
  | _ -> Alcotest.fail "getrawmempool"

let ids txs = List.sort compare (List.map txid_hex txs)

open Yojson.Safe.Util

let package_msg j = j |> member "package_msg" |> to_string
let result j t = j |> member "tx-results" |> member (wtxid_hex t)
let error j t = result j t |> member "error" |> to_string

(* package_rbf/at-limit: 126 + 126 multisig outputs, cluster 403_200 adjusted
   weight.  Core accepts, replaces O and D, and reports both txs with the
   sigop-adjusted vsize and the package feerate. *)
let test_at_limit_replaces () =
  with_ctx (fun ctx ->
      put_coin ctx 1;
      let coin = coin_txid 1 in
      let o, d = conflict_pair ~coin in
      send ctx o; send ctx d;
      let p, c = replacement ~coin ~p_fee:6_000L ~p_outs:126 ~p_spk:multisig
          ~c_fee:200_000L ~c_outs:126 () in
      let j = submitpackage ctx [ p; c ] in
      Alcotest.(check string) "package_msg" "success" (package_msg j);
      let sorted_internal =
        List.sort (fun a b -> compare (Cstruct.to_string a) (Cstruct.to_string b))
          [ txid o; txid d ] |> List.map Types.hash256_to_hex_display in
      Alcotest.(check (list string)) "replaced-transactions (std::set order)"
        sorted_internal
        (j |> member "replaced-transactions" |> to_list |> List.map to_string);
      List.iter (fun (t, base) ->
          let r = result j t in
          Alcotest.(check bool) "no error" true (r |> member "error" = `Null);
          Alcotest.(check int) "sigop-adjusted vsize" 50_400
            (r |> member "vsize" |> to_int);
          let fees = r |> member "fees" in
          Alcotest.(check (float 1e-12)) "fees.base" base
            (fees |> member "base" |> to_number);
          Alcotest.(check (float 1e-12)) "effective-feerate = package feerate"
            2.043e-05 (fees |> member "effective-feerate" |> to_number);
          Alcotest.(check (list string)) "effective-includes = package"
            [ wtxid_hex p; wtxid_hex c ]
            (fees |> member "effective-includes" |> to_list
             |> List.map to_string))
        [ (p, 0.00006); (c, 0.002) ];
      Alcotest.(check (list string)) "pool = P, C" (ids [ p; c ]) (pool ctx))

(* The feerate diagram must size each tx by its sigop-adjusted weight, as
   Core's ImprovesFeerateDiagram does (GetSigOpsAdjustedWeight).  Same shape
   as at-limit but the child pays 40_000: by raw weight the package (~11.6k
   vB, 46_000 sat) beats O + D (~6.1k vB, 21_000 sat) at every point, but by
   adjusted weight it is 100_800 vB and falls below O + D's diagram.  Core
   v31.1: "package RBF failed: insufficient feerate: does not improve feerate
   diagram"; O and D stay. *)
let test_diagram_uses_adjusted_weight () =
  with_ctx (fun ctx ->
      put_coin ctx 1;
      let coin = coin_txid 1 in
      let o, d = conflict_pair ~coin in
      send ctx o; send ctx d;
      let p, c = replacement ~coin ~p_fee:6_000L ~p_outs:126 ~p_spk:multisig
          ~c_fee:40_000L ~c_outs:126 () in
      let j = submitpackage ctx [ p; c ] in
      Alcotest.(check string) "package_msg"
        "package RBF failed: insufficient feerate: does not improve feerate \
         diagram"
        (package_msg j);
      Alcotest.(check (list string)) "nothing replaced" []
        (j |> member "replaced-transactions" |> to_list |> List.map to_string);
      Alcotest.(check (list string)) "pool = O, D" (ids [ o; d ]) (pool ctx))

(* package_rbf/over: 127 + 126 outputs, 404_800 > 404_000.  Core:
   too-large-cluster; each tx reports its individual failure; O and D stay. *)
let test_over_too_large_cluster () =
  with_ctx (fun ctx ->
      put_coin ctx 1;
      let coin = coin_txid 1 in
      let o, d = conflict_pair ~coin in
      send ctx o; send ctx d;
      let p, c = replacement ~coin ~p_fee:6_000L ~p_outs:127 ~p_spk:multisig
          ~c_fee:200_000L ~c_outs:126 () in
      let j = submitpackage ctx [ p; c ] in
      Alcotest.(check string) "package_msg" "too-large-cluster" (package_msg j);
      Alcotest.(check string) "parent: individual rule-3 failure"
        (Printf.sprintf
           "insufficient fee, rejecting replacement %s, less fees than \
            conflicting txs; 0.00006 < 0.00021" (txid_hex p))
        (error j p);
      Alcotest.(check string) "child: missing input"
        "bad-txns-inputs-missingorspent" (error j c);
      Alcotest.(check (list string)) "nothing replaced" []
        (j |> member "replaced-transactions" |> to_list |> List.map to_string);
      Alcotest.(check (list string)) "pool = O, D" (ids [ o; d ]) (pool ctx))

(* The package must pay for what it evicts plus its own relay (rules 3/4 on
   the package, attributed to the child).  A package short of O + D is
   refused and the pool is unchanged. *)
let test_insufficient_package_fees () =
  with_ctx (fun ctx ->
      put_coin ctx 1;
      let coin = coin_txid 1 in
      let o, d = conflict_pair ~coin in
      send ctx o; send ctx d;
      let p, c = replacement ~coin ~p_fee:6_000L ~p_outs:2 ~p_spk:op_true
          ~c_fee:10_000L ~c_outs:0 () in
      let j = submitpackage ctx [ p; c ] in
      Alcotest.(check string) "package_msg"
        (Printf.sprintf
           "package RBF failed: insufficient anti-DoS fees, rejecting \
            replacement %s, less fees than conflicting txs; 0.00016 < 0.00021"
           (txid_hex c))
        (package_msg j);
      Alcotest.(check (list string)) "pool = O, D" (ids [ o; d ]) (pool ctx))

(* The pair must be a chunk of its own: a child below its parent's feerate
   (the child only pays anti-DoS fees) is refused. *)
let test_child_below_parent_feerate () =
  with_ctx (fun ctx ->
      put_coin ctx 1;
      let coin = coin_txid 1 in
      let o, d = conflict_pair ~coin in
      send ctx o; send ctx d;
      let p, c = replacement ~coin ~p_fee:20_500L ~p_outs:0 ~p_spk:op_true
          ~c_fee:3_000L ~c_outs:40 () in
      let j = submitpackage ctx [ p; c ] in
      let msg = package_msg j in
      let prefix =
        "package RBF failed: package feerate is less than or equal to parent \
         feerate, package feerate " in
      Alcotest.(check string) "package_msg prefix" prefix
        (String.sub msg 0 (min (String.length msg) (String.length prefix)));
      Alcotest.(check (list string)) "pool = O, D" (ids [ o; d ]) (pool ctx))

(* A package RBF whose child also spends an in-mempool tx is refused. *)
let test_mempool_ancestor_refused () =
  with_ctx (fun ctx ->
      put_coin ctx 1;
      put_coin ctx 2;
      let coin = coin_txid 1 in
      let o, d = conflict_pair ~coin in
      send ctx o; send ctx d;
      let m = tx ~ins:[ (coin_txid 2, 0) ]
          ~change:(Int64.sub coin_value 10_000L) ~spk:op_true ~n:0 in
      send ctx m;
      let p, c = replacement ~coin ~p_fee:6_000L ~p_outs:2 ~p_spk:op_true
          ~c_fee:200_000L ~c_outs:0 ~extra_ins:[ (txid m, 0) ]
          ~extra_in_value:(Int64.sub coin_value 10_000L) () in
      let j = submitpackage ctx [ p; c ] in
      Alcotest.(check string) "package_msg"
        "package RBF failed: new transaction cannot have mempool ancestors"
        (package_msg j);
      Alcotest.(check (list string)) "pool = O, D, M" (ids [ o; d; m ])
        (pool ctx))

(* A parent that pays for the replacement on its own is accepted individually
   (no package evaluation); the child then joins on its own feerate. *)
let test_parent_alone_replaces () =
  with_ctx (fun ctx ->
      put_coin ctx 1;
      let coin = coin_txid 1 in
      let o, d = conflict_pair ~coin in
      send ctx o; send ctx d;
      let p, c = replacement ~coin ~p_fee:50_000L ~p_outs:0 ~p_spk:op_true
          ~c_fee:20_000L ~c_outs:0 () in
      let j = submitpackage ctx [ p; c ] in
      Alcotest.(check string) "package_msg" "success" (package_msg j);
      Alcotest.(check (list string)) "effective-includes = own wtxid"
        [ wtxid_hex c ]
        (result j c |> member "fees" |> member "effective-includes" |> to_list
         |> List.map to_string);
      Alcotest.(check (list string)) "pool = P, C" (ids [ p; c ]) (pool ctx))

(* ---- Review points on camlcoin#26 (Warden, attempt 4) ---- *)

(* A small conflict S (92 vB, fee 2_000) and 80 unrelated fillers F1..F80
   (92 vB each, fees 1_020..2_600, ~11-28 sat/vB).  The package parent P
   double-spends S with 20 outputs (292 vB) and pays 1_000 (~3.4 sat/vB,
   below every filler); its child C (92 vB) pays 60_000, so the package
   (~159 sat/vB) ranks above every filler. *)
let n_fillers = 80

let small_conflict ~coin =
  tx ~ins:[ (coin, 0) ] ~change:(Int64.sub coin_value 2_000L) ~spk:op_true ~n:0

let filler i =
  tx ~ins:[ (coin_txid (i + 1), 0) ]
    ~change:(Int64.sub coin_value (Int64.of_int (1_000 + (20 * i))))
    ~spk:op_true ~n:0

let slack_band_package () =
  replacement ~coin:(coin_txid 1) ~p_fee:1_000L ~p_outs:20 ~p_spk:op_true
    ~c_fee:60_000L ~c_outs:0 ()

let usage = Mempool.tx_dynamic_usage

(* -maxmempool chosen so that S + fillers sit inside the 1/64 overshoot slack
   (no trim while the pool is filled) but the pool with P in place of S is
   past the trigger: a trim after the parent alone would rank P on its own
   feerate. *)
let slack_band_cap ~p =
  let s = small_conflict ~coin:(coin_txid 1) in
  let u0 = usage s
           + List.fold_left (fun a i -> a + usage (filler i)) 0
               (List.init n_fillers (fun i -> i + 1)) in
  let trigger = u0 - usage s + usage p - 1 in
  let cap = trigger * 64 / 65 in
  assert (cap + (cap / 64) <= trigger);
  assert (u0 <= cap + (cap / 64));
  assert (u0 > cap);
  cap

let fill (ctx : Rpc.rpc_context) =
  for i = 1 to n_fillers + 1 do put_coin ctx i done;
  let s = small_conflict ~coin:(coin_txid 1) in
  send ctx s;
  let fillers = List.init n_fillers (fun i -> filler (i + 1)) in
  List.iter (send ctx) fillers;
  Alcotest.(check int) "setup: nothing trimmed while filling"
    (n_fillers + 1) (Hashtbl.length ctx.mempool.Mempool.entries);
  (s, fillers)

(* Point 1: the trim waits for the whole package.  Core's AcceptPackage calls
   LimitMempoolSize only after both txs are in (validation.cpp:1731), where
   P and C form one ~159 sat/vB chunk.  The package is accepted, S is
   replaced, and the trim back to -maxmempool removes only the lowest
   fillers, no more than it needs: the remaining pool fits and putting back
   the last filler it removed would not.  The rolling floor follows that
   filler (> 11 sat/vB), not P's own ~3.4 sat/vB. *)
let test_trim_waits_for_package () =
  let p, c = slack_band_package () in
  let cap = slack_band_cap ~p in
  with_ctx ~cap (fun ctx ->
      let s, fillers = fill ctx in
      let j = submitpackage ctx [ p; c ] in
      Alcotest.(check string) "package_msg" "success" (package_msg j);
      let in_pool = pool ctx in
      Alcotest.(check bool) "P stays" true (List.mem (txid_hex p) in_pool);
      Alcotest.(check bool) "C stays" true (List.mem (txid_hex c) in_pool);
      Alcotest.(check bool) "S replaced" false (List.mem (txid_hex s) in_pool);
      let evicted =
        List.filter (fun f -> not (List.mem (txid_hex f) in_pool)) fillers in
      let k = List.length evicted in
      Alcotest.(check bool) "the post-package trim ran" true (k > 0);
      Alcotest.(check (list string)) "only the lowest-fee fillers go"
        (ids (List.filteri (fun i _ -> i < k) fillers)) (ids evicted);
      Alcotest.(check int) "pool = P + C + kept fillers" (2 + n_fillers - k)
        (List.length in_pool);
      let mp = ctx.mempool in
      Alcotest.(check bool) "trimmed to -maxmempool" true
        (mp.Mempool.total_usage <= cap);
      if k > 0 then
        Alcotest.(check bool) "no more than needed" true
          (mp.Mempool.total_usage + usage (List.nth fillers (k - 1)) > cap);
      Alcotest.(check bool) "rolling floor follows the fillers, not P" true
        (Mempool.get_rolling_min_fee_rate mp > 10_000.0))

(* Point 1, failing child: the same package with a child whose scriptSig
   fails (OP_RETURN).  The parent is added, the child is refused, the parent
   comes out and S goes back: the pool and the rolling floor are exactly as
   before the attempt. *)
let test_failed_child_leaves_pool_and_floor () =
  let p, c = slack_band_package () in
  let c =
    { c with
      Types.inputs =
        List.map (fun (i : Types.tx_in) ->
            { i with Types.script_sig = Cstruct.of_string "\x6a" })
          c.Types.inputs } in
  let cap = slack_band_cap ~p in
  with_ctx ~verify_scripts:true ~cap (fun ctx ->
      let _s, _fillers = fill ctx in
      let before = pool ctx in
      let floor_before = Mempool.get_rolling_min_fee_rate ctx.mempool in
      let usage_before = ctx.mempool.Mempool.total_usage in
      let j = submitpackage ctx [ p; c ] in
      Alcotest.(check bool) "package refused" true (package_msg j <> "success");
      Alcotest.(check (list string)) "pool unchanged" before (pool ctx);
      Alcotest.(check (float 0.0)) "rolling floor unchanged" floor_before
        (Mempool.get_rolling_min_fee_rate ctx.mempool);
      Alcotest.(check int) "usage unchanged" usage_before
        ctx.mempool.Mempool.total_usage)

(* Point 2: the package feerate of the individual pass is taken over the
   sigop-adjusted vsize.  No conflicts.  P pays 0; C pays 200 and carries 10
   bare multisig outputs (800 sigop cost, adjusted vsize 4_000).  By raw
   weight the package is ~650 vB, ~0.3 sat/vB, over the 0.1 sat/vB floor; by
   adjusted vsize it is ~4_100 vB, ~0.05 sat/vB, under it.  Core (and this
   node's testmempoolaccept) refuses P below the floor; nothing enters. *)
let test_package_floor_uses_adjusted_vsize () =
  with_ctx (fun ctx ->
      put_coin ctx 1;
      let p = tx ~ins:[ (coin_txid 1, 0) ] ~change:coin_value ~spk:op_true ~n:0 in
      let c_change =
        Int64.sub coin_value (Int64.add 200L (Int64.mul 10L output_sats)) in
      let c = tx ~ins:[ (txid p, 0) ] ~change:c_change ~spk:multisig ~n:10 in
      let j = submitpackage ctx [ p; c ] in
      Alcotest.(check bool) "package refused" true (package_msg j <> "success");
      Alcotest.(check (list string)) "pool unchanged" [] (pool ctx))

(* Point 3: a package RBF whose child leaves the parent's ephemeral dust
   unspent.  CheckEphemeralSpends runs before anything is committed
   (validation.cpp AcceptMultipleTransactionsInternal): the package is
   refused, the conflict S stays and neither package tx enters. *)
let test_unspent_dust_restores_conflict () =
  with_ctx (fun ctx ->
      put_coin ctx 1;
      let coin = coin_txid 1 in
      let s = small_conflict ~coin in
      send ctx s;
      let p0 = tx ~ins:[ (coin, 0) ] ~change:coin_value ~spk:op_true ~n:0 in
      (* P pays 0 and carries a zero-value OP_TRUE output: ephemeral dust. *)
      let p =
        { p0 with
          Types.outputs =
            p0.Types.outputs @ [ { Types.value = 0L; script_pubkey = op_true } ] }
      in
      let c = tx ~ins:[ (txid p, 0) ]
          ~change:(Int64.sub coin_value 50_000L) ~spk:op_true ~n:0 in
      let j = submitpackage ctx [ p; c ] in
      let msg = package_msg j in
      let prefix = "missing-ephemeral-spends" in
      Alcotest.(check string) "package_msg prefix" prefix
        (String.sub msg 0 (min (String.length msg) (String.length prefix)));
      Alcotest.(check (list string)) "pool = S" (ids [ s ]) (pool ctx))

let () =
  Alcotest.run "package_rbf"
    [ ( "package-rbf",
        [ Alcotest.test_case "at-limit replaces" `Quick test_at_limit_replaces;
          Alcotest.test_case "diagram uses adjusted weight" `Quick
            test_diagram_uses_adjusted_weight;
          Alcotest.test_case "over too-large-cluster" `Quick
            test_over_too_large_cluster;
          Alcotest.test_case "insufficient package fees" `Quick
            test_insufficient_package_fees;
          Alcotest.test_case "child below parent feerate" `Quick
            test_child_below_parent_feerate;
          Alcotest.test_case "mempool ancestor refused" `Quick
            test_mempool_ancestor_refused;
          Alcotest.test_case "parent alone replaces" `Quick
            test_parent_alone_replaces;
          Alcotest.test_case "trim waits for package" `Quick
            test_trim_waits_for_package;
          Alcotest.test_case "failed child leaves pool and floor" `Quick
            test_failed_child_leaves_pool_and_floor;
          Alcotest.test_case "package floor uses adjusted vsize" `Quick
            test_package_floor_uses_adjusted_vsize;
          Alcotest.test_case "unspent dust restores conflict" `Quick
            test_unspent_dust_restores_conflict ] ) ]
