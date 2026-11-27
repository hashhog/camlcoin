(* submitpackage must not commit a below-floor parent on the strength of a
   child that is then rejected (cffix-camlcoin-package-atomic-commit; audit
   record camlcoin:mempool:package-feerate-bypass-partial-commit).

   Core v31 AcceptPackage (validation.cpp) tries each tx alone first.  A
   parent paying nothing fails there with TX_RECONSIDERABLE ("min relay fee
   not met") and its child with TX_MISSING_INPUTS; the two are then
   evaluated together by AcceptMultipleTransactionsInternal, which runs
   PreChecks and the script checks for every member before SubmitPackage
   writes any of them.  A child whose script fails therefore leaves the pool
   exactly as it was: the parent is not admitted, and it reports its own
   individual failure.  A package member that passes on its own fee is
   admitted in the individual pass and is not undone.

   camlcoin computed the package feerate from fees and sizes alone, then
   added each member with ~bypass_fee_check and kept whatever went in, so a
   zero-fee parent stayed in the pool after its child's script failed. *)

open Camlcoin

let with_ctx f =
  Test_tmp.with_chaindb (fun db ->
      let utxo = Utxo.UtxoSet.create db in
      let mp =
        Mempool.create ~network:Consensus.regtest ~require_standard:false
          ~verify_scripts:true ~utxo ~current_height:0 ()
      in
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

let op_true = Cstruct.of_string "\x51"

(* A confirmed OP_TRUE coin (txid n n .., vout 0). *)
let put_coin (ctx : Rpc.rpc_context) n =
  let e : Utxo.utxo_entry =
    { value = coin_value; script_pubkey = op_true; height = 1;
      is_coinbase = false } in
  let w = Serialize.writer_create () in
  Utxo.serialize_utxo_entry w e;
  Storage.ChainDB.store_utxo ctx.chain.db (coin_txid n) 0
    (Serialize.writer_to_string w)

(* <G> OP_CHECKSIG: pay-to-pubkey to the secp256k1 generator. *)
let p2pk =
  Cstruct.of_hex
    "210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac"

(* The zero-value OP_RETURN keeps the non-witness size above
   MIN_STANDARD_TX_NONWITNESS_SIZE. *)
let filler =
  { Types.value = 0L;
    script_pubkey = Cstruct.of_string ("\x6a\x14" ^ String.make 20 'x') }

let tx ~(ins : (Types.hash256 * int) list) ?(script_sig = Cstruct.create 0)
    ~value ~spk () : Types.transaction =
  { Types.version = 2l;
    inputs = List.map (fun (txid, vout) ->
        { Types.previous_output = { Types.txid; vout = Int32.of_int vout };
          script_sig; sequence = 0xFFFFFFFDl }) ins;
    outputs = [ { Types.value; script_pubkey = spk }; filler ];
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

let in_pool (ctx : Rpc.rpc_context) t =
  Hashtbl.mem ctx.mempool.Mempool.entries (Cstruct.to_string (txid t))

open Yojson.Safe.Util

let package_msg j = j |> member "package_msg" |> to_string
let result j t = j |> member "tx-results" |> member (wtxid_hex t)
let error j t =
  match result j t |> member "error" with
  | `String s -> s
  | _ -> "<no error>"

let starts_with ~prefix s =
  String.length s >= String.length prefix
  && String.sub s 0 (String.length prefix) = prefix

let child_fee = 100_000L

(* Parent P spends a confirmed OP_TRUE coin and pays nothing, its output
   locked to <G> OP_CHECKSIG.  Child C spends P:0 with an empty signature
   (CHECKSIG returns false, so the script fails) and pays [child_fee]. *)
let zero_fee_parent_bad_child ~coin =
  let p = tx ~ins:[ (coin, 0) ] ~value:coin_value ~spk:p2pk () in
  let c = tx ~ins:[ (txid p, 0) ]
      ~script_sig:(Cstruct.of_string "\x00")
      ~value:(Int64.sub coin_value child_fee) ~spk:op_true () in
  (p, c)

(* The finding's repro: [parent fee 0, child with a big fee and an invalid
   signature].  Core: package_msg "transaction failed", the child carries
   its script failure, the parent its individual "min relay fee not met",
   and neither is in the pool. *)
let test_bad_child_does_not_commit_parent () =
  with_ctx (fun ctx ->
      put_coin ctx 1;
      let p, c = zero_fee_parent_bad_child ~coin:(coin_txid 1) in
      let j = submitpackage ctx [ p; c ] in
      Alcotest.(check bool) "zero-fee parent is not in the mempool" false
        (in_pool ctx p);
      Alcotest.(check (list string)) "pool is empty" [] (pool ctx);
      Alcotest.(check string) "package_msg" "transaction failed"
        (package_msg j);
      Alcotest.(check bool)
        (Printf.sprintf "parent reports its own fee failure (got %S)"
           (error j p))
        true (starts_with ~prefix:"min relay fee not met" (error j p));
      Alcotest.(check bool)
        (Printf.sprintf "child reports a script failure (got %S)" (error j c))
        true (error j c <> "<no error>"
              && not (starts_with ~prefix:"min relay fee" (error j c))))

(* Same failure through the mempool entry point the RPC and pkgtxns relay
   share: nothing is accepted, both txs are rejected. *)
let test_accept_package_full_rejects_both () =
  with_ctx (fun ctx ->
      put_coin ctx 1;
      let p, c = zero_fee_parent_bad_child ~coin:(coin_txid 1) in
      let o = Mempool.accept_package_full ctx.mempool [ p; c ] in
      Alcotest.(check bool) "parent not in the mempool" false (in_pool ctx p);
      Alcotest.(check bool) "child not in the mempool" false (in_pool ctx c);
      (match o.Mempool.pkg_result with
       | Mempool.PackageRejected _ -> ()
       | Mempool.PackagePartial _ ->
         Alcotest.fail "PackagePartial: a member stayed in the pool"
       | Mempool.PackageAccepted _ -> Alcotest.fail "PackageAccepted");
      Alcotest.(check (list string)) "every member reports a failure"
        (ids [ p; c ])
        (List.map (fun (t, _) -> txid_hex t) o.Mempool.pkg_all_failed
         |> List.sort compare);
      Alcotest.(check (float 0.)) "pool fee total untouched" 0.
        (Int64.to_float ctx.mempool.Mempool.total_fee))

(* Control: the same shape with a child whose script passes.  CPFP still
   works, both are admitted at the package feerate. *)
let test_good_child_still_cpfp () =
  with_ctx (fun ctx ->
      put_coin ctx 1;
      let coin = coin_txid 1 in
      let p = tx ~ins:[ (coin, 0) ] ~value:coin_value ~spk:op_true () in
      let c = tx ~ins:[ (txid p, 0) ]
          ~value:(Int64.sub coin_value child_fee) ~spk:op_true () in
      let j = submitpackage ctx [ p; c ] in
      Alcotest.(check string) "package_msg" "success" (package_msg j);
      Alcotest.(check (list string)) "pool = P, C" (ids [ p; c ]) (pool ctx);
      List.iter (fun t ->
          Alcotest.(check (list string)) "effective-includes = package"
            [ wtxid_hex p; wtxid_hex c ]
            (result j t |> member "fees" |> member "effective-includes"
             |> to_list |> List.map to_string))
        [ p; c ])

(* A parent that pays its own way is admitted in Core's individual pass and
   is not undone when the package evaluation fails; only the members that
   needed the package feerate (the zero-fee parent and the child) are
   refused. *)
let test_self_paying_parent_kept () =
  with_ctx (fun ctx ->
      put_coin ctx 1;
      put_coin ctx 2;
      let p0 = tx ~ins:[ (coin_txid 1, 0) ] ~value:coin_value ~spk:p2pk () in
      let p1 = tx ~ins:[ (coin_txid 2, 0) ]
          ~value:(Int64.sub coin_value 10_000L) ~spk:op_true () in
      let c = tx ~ins:[ (txid p0, 0); (txid p1, 0) ]
          ~script_sig:(Cstruct.of_string "\x00")
          ~value:(Int64.sub (Int64.add coin_value
                               (Int64.sub coin_value 10_000L)) child_fee)
          ~spk:op_true () in
      let j = submitpackage ctx [ p0; p1; c ] in
      Alcotest.(check string) "package_msg" "transaction failed"
        (package_msg j);
      Alcotest.(check (list string)) "pool = the self-paying parent only"
        (ids [ p1 ]) (pool ctx);
      Alcotest.(check bool) "zero-fee parent not in the mempool" false
        (in_pool ctx p0);
      Alcotest.(check bool)
        (Printf.sprintf "zero-fee parent reports its fee failure (got %S)"
           (error j p0))
        true (starts_with ~prefix:"min relay fee not met" (error j p0));
      Alcotest.(check bool) "self-paying parent has no error" true
        (result j p1 |> member "error" = `Null))

let () =
  Alcotest.run "package_atomic_commit"
    [ ( "submitpackage",
        [ Alcotest.test_case "bad child does not commit zero-fee parent"
            `Quick test_bad_child_does_not_commit_parent;
          Alcotest.test_case "accept_package_full rejects both" `Quick
            test_accept_package_full_rejects_both;
          Alcotest.test_case "good child still CPFPs (control)" `Quick
            test_good_child_still_cpfp;
          Alcotest.test_case "self-paying parent kept" `Quick
            test_self_paying_parent_kept ] ) ]
