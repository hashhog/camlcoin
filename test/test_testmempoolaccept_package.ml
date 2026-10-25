(* testmempoolaccept with 2+ transactions, and submitpackage script-failure
   text (item done-camlcoin-testmempoolaccept-package; Core-regtest rows
   package/accept/parent-child, seed_submitpackage/*/accept and
   seed_submitpackage/invalid-sig-*/submit).

   Core rpc/mempool.cpp testmempoolaccept: an array of more than one tx goes
   to ProcessNewPackage(test_accept=true) — AcceptMultipleTransactions with
   ATMPArgs::PackageTestAccept (validation.cpp): every PreChecks first, then
   every PolicyScriptChecks, stopping at the first failure; each tx pays its
   own fee; a tx with no result reports only txid and wtxid.  A script failure
   is "mempool-script-verify-flag-failed (<ScriptErrorString>)" with the
   CScriptCheck debug text "input N of <txid> (wtxid <wtxid>), spending
   <prevtxid>:<n>" (validation.cpp CheckInputScripts). *)

open Camlcoin

let with_ctx ?(verify_scripts = true) f =
  Test_tmp.with_chaindb (fun db ->
      let utxo = Utxo.UtxoSet.create db in
      let mp =
        Mempool.create ~network:Consensus.regtest ~require_standard:false
          ~verify_scripts ~utxo ~current_height:0 ()
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

let coin_txid = Cstruct.of_string (String.make 32 '\x07')
let coin_value = 5_000_000_000L

(* An OP_TRUE confirmed coin (txid 0x07.., [vout]). *)
let put_coin (ctx : Rpc.rpc_context) ~vout =
  let e : Utxo.utxo_entry =
    { value = coin_value; script_pubkey = Cstruct.of_string "\x51";
      height = 1; is_coinbase = false } in
  let w = Serialize.writer_create () in
  Utxo.serialize_utxo_entry w e;
  Storage.ChainDB.store_utxo ctx.chain.db coin_txid vout
    (Serialize.writer_to_string w)

let op_true = Cstruct.of_string "\x51"

(* P2PK to the secp256k1 generator.  Spent with a strict-DER, low-S, non-empty
   signature (r = s = 1) that does not verify: OP_CHECKSIG fails and the
   standard NULLFAIL flag turns that into a script error, as in the regtest
   rows (the harness corrupts a real signature the same way). *)
let p2pk_g =
  Cstruct.of_hex
    "210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac"

let bad_sig_push = Cstruct.of_hex "09300602010102010101"

let null_fail_text =
  "mempool-script-verify-flag-failed (Signature must be zero for failed \
   CHECK(MULTI)SIG operation)"

let tx_hex (tx : Types.transaction) =
  let w = Serialize.writer_create () in
  Serialize.serialize_transaction w tx;
  let s = Serialize.writer_to_string w in
  String.concat "" (List.init (String.length s)
                      (fun i -> Printf.sprintf "%02x" (Char.code s.[i])))

(* One input, one value output plus a zero-value OP_RETURN so the
   non-witness size clears MIN_STANDARD_TX_NONWITNESS_SIZE. *)
let spend ~(prev_txid : Types.hash256) ~prev_vout ~value ~spk
    ?(script_sig = Cstruct.create 0) () : Types.transaction =
  { Types.version = 2l;
    inputs = [ { Types.previous_output =
                   { Types.txid = prev_txid; vout = Int32.of_int prev_vout };
                 script_sig; sequence = 0xFFFFFFFFl } ];
    outputs = [ { Types.value = value; script_pubkey = spk };
                { Types.value = 0L;
                  script_pubkey = Cstruct.of_string ("\x6a\x14" ^ String.make 20 'x') } ];
    witnesses = [];
    locktime = 0l }

let txid_hex tx = Types.hash256_to_hex_display (Crypto.compute_txid tx)
let wtxid_hex tx = Types.hash256_to_hex_display (Crypto.compute_wtxid tx)

let tma ctx txs =
  match Rpc.dispatch_rpc ctx "testmempoolaccept"
          [ `List (List.map (fun t -> `String (tx_hex t)) txs) ] with
  | Ok (`List l) -> l
  | Ok j -> Alcotest.failf "testmempoolaccept: not an array: %s"
              (Yojson.Safe.to_string j)
  | Error (c, m) -> Alcotest.failf "testmempoolaccept: error (%d) %s" c m

let submitpackage ctx txs =
  match Rpc.dispatch_rpc ctx "submitpackage"
          [ `List (List.map (fun t -> `String (tx_hex t)) txs) ] with
  | Ok j -> j
  | Error (c, m) -> Alcotest.failf "submitpackage: error (%d) %s" c m

let keys (j : Yojson.Safe.t) =
  match j with `Assoc kv -> List.map fst kv | _ -> []

let str j k = Yojson.Safe.Util.(j |> member k |> to_string)
let bool_ j k = Yojson.Safe.Util.(j |> member k |> to_bool)

let mempool_size ctx =
  match Rpc.dispatch_rpc ctx "getrawmempool" [] with
  | Ok (`List l) -> List.length l
  | _ -> Alcotest.fail "getrawmempool"

let script_details ~reason tx ~(prev : Types.transaction option) ~prev_vout =
  let prev_hex =
    match prev with
    | Some p -> txid_hex p
    | None -> Types.hash256_to_hex_display coin_txid in
  Printf.sprintf "%s, input 0 of %s (wtxid %s), spending %s:%d"
    reason (txid_hex tx) (wtxid_hex tx) prev_hex prev_vout

(* package/accept/parent-child: a child spending an unconfirmed parent in the
   same array.  Core answers one result per tx, both allowed, each with its own
   fee and feerate (PackageTestAccept has no package feerates).  The pool is
   not changed. *)
let test_parent_child_allowed () =
  with_ctx ~verify_scripts:false (fun ctx ->
      put_coin ctx ~vout:0;
      let parent = spend ~prev_txid:coin_txid ~prev_vout:0
          ~value:(Int64.sub coin_value 10_000L) ~spk:op_true () in
      let child = spend ~prev_txid:(Crypto.compute_txid parent) ~prev_vout:0
          ~value:(Int64.sub coin_value 30_000L) ~spk:op_true () in
      let res = tma ctx [ parent; child ] in
      Alcotest.(check int) "one result per tx" 2 (List.length res);
      List.iter2 (fun (tx, fee) r ->
          Alcotest.(check string) "txid" (txid_hex tx) (str r "txid");
          Alcotest.(check bool) "allowed" true (bool_ r "allowed");
          let open Yojson.Safe.Util in
          let fees = r |> member "fees" in
          Alcotest.(check (float 1e-12)) "fees.base" fee
            (fees |> member "base" |> to_number);
          Alcotest.(check (list string)) "effective-includes own wtxid"
            [ wtxid_hex tx ]
            (fees |> member "effective-includes" |> to_list
             |> List.map to_string))
        [ (parent, 0.0001); (child, 0.0002) ] res;
      Alcotest.(check int) "pool untouched" 0 (mempool_size ctx);
      (* the package's coins do not outlive the call *)
      match tma ctx [ child ] with
      | [ r ] ->
        Alcotest.(check string) "child alone" "missing-inputs"
          (str r "reject-reason")
      | _ -> Alcotest.fail "single result")

(* seed_submitpackage/valid-cpfp/accept: the parent pays no fee.  Core fails
   it in PreChecks ("min relay fee not met, <fee> < <min>") and the child,
   never evaluated, reports only txid and wtxid. *)
let test_low_fee_parent_stops_package () =
  with_ctx ~verify_scripts:false (fun ctx ->
      put_coin ctx ~vout:0;
      let parent = spend ~prev_txid:coin_txid ~prev_vout:0
          ~value:coin_value ~spk:op_true () in
      let child = spend ~prev_txid:(Crypto.compute_txid parent) ~prev_vout:0
          ~value:(Int64.sub coin_value 20_000L) ~spk:op_true () in
      let vsize = (Validation.compute_tx_weight parent + 3) / 4 in
      let min_fee =
        Int64.div (Int64.mul ctx.mempool.min_relay_fee (Int64.of_int vsize))
          1000L in
      match tma ctx [ parent; child ] with
      | [ p; c ] ->
        Alcotest.(check bool) "parent allowed" false (bool_ p "allowed");
        Alcotest.(check string) "parent reject-reason" "min relay fee not met"
          (str p "reject-reason");
        Alcotest.(check string) "parent reject-details"
          (Printf.sprintf "min relay fee not met, 0 < %Ld" min_fee)
          (str p "reject-details");
        Alcotest.(check (list string)) "child unfinished" [ "txid"; "wtxid" ]
          (keys c)
      | _ -> Alcotest.fail "two results")

(* seed_submitpackage/invalid-sig-child/accept: the parent passes, the child's
   script fails.  Core reports the parent allowed and the child with the
   mempool-script-verify-flag-failed form. *)
let test_bad_child_script () =
  with_ctx (fun ctx ->
      put_coin ctx ~vout:0;
      let parent = spend ~prev_txid:coin_txid ~prev_vout:0
          ~value:(Int64.sub coin_value 10_000L) ~spk:p2pk_g () in
      let child = spend ~prev_txid:(Crypto.compute_txid parent) ~prev_vout:0
          ~value:(Int64.sub coin_value 20_000L) ~spk:op_true
          ~script_sig:bad_sig_push () in
      match tma ctx [ parent; child ] with
      | [ p; c ] ->
        Alcotest.(check bool) "parent allowed" true (bool_ p "allowed");
        Alcotest.(check bool) "child allowed" false (bool_ c "allowed");
        Alcotest.(check string) "child reject-reason" null_fail_text
          (str c "reject-reason");
        Alcotest.(check string) "child reject-details"
          (script_details ~reason:null_fail_text child ~prev:(Some parent)
             ~prev_vout:0)
          (str c "reject-details")
      | _ -> Alcotest.fail "two results")

(* seed_submitpackage/invalid-sig-parent/accept: the parent's script fails.
   Core stops there: the child reports only txid and wtxid. *)
let test_bad_parent_script () =
  with_ctx (fun ctx ->
      Storage.ChainDB.store_utxo ctx.chain.db coin_txid 0
        (let w = Serialize.writer_create () in
         Utxo.serialize_utxo_entry w
           { value = coin_value; script_pubkey = p2pk_g; height = 1;
             is_coinbase = false };
         Serialize.writer_to_string w);
      let parent = spend ~prev_txid:coin_txid ~prev_vout:0
          ~value:(Int64.sub coin_value 10_000L) ~spk:op_true
          ~script_sig:bad_sig_push () in
      let child = spend ~prev_txid:(Crypto.compute_txid parent) ~prev_vout:0
          ~value:(Int64.sub coin_value 20_000L) ~spk:op_true () in
      match tma ctx [ parent; child ] with
      | [ p; c ] ->
        Alcotest.(check bool) "parent allowed" false (bool_ p "allowed");
        Alcotest.(check string) "parent reject-reason" null_fail_text
          (str p "reject-reason");
        Alcotest.(check string) "parent reject-details"
          (script_details ~reason:null_fail_text parent ~prev:None ~prev_vout:0)
          (str p "reject-details");
        Alcotest.(check (list string)) "child unfinished" [ "txid"; "wtxid" ]
          (keys c)
      | _ -> Alcotest.fail "two results")

(* IsWellFormedPackage: a child listed before its parent is a package-wide
   PCKG_POLICY failure.  Every entry carries "package-error" and nothing
   else is evaluated. *)
let test_unsorted_package_error () =
  with_ctx ~verify_scripts:false (fun ctx ->
      put_coin ctx ~vout:0;
      let parent = spend ~prev_txid:coin_txid ~prev_vout:0
          ~value:(Int64.sub coin_value 10_000L) ~spk:op_true () in
      let child = spend ~prev_txid:(Crypto.compute_txid parent) ~prev_vout:0
          ~value:(Int64.sub coin_value 20_000L) ~spk:op_true () in
      let res = tma ctx [ child; parent ] in
      Alcotest.(check int) "two results" 2 (List.length res);
      List.iter (fun r ->
          Alcotest.(check (list string)) "keys"
            [ "txid"; "wtxid"; "package-error" ] (keys r);
          Alcotest.(check string) "package-error" "package-not-sorted"
            (str r "package-error"))
        res)

(* PackageTestAccept does not allow replacement: a package tx that spends an
   input already spent in the pool is "bip125-replacement-disallowed". *)
let test_conflict_not_replaced () =
  with_ctx ~verify_scripts:false (fun ctx ->
      put_coin ctx ~vout:0;
      put_coin ctx ~vout:1;
      let in_pool = spend ~prev_txid:coin_txid ~prev_vout:0
          ~value:(Int64.sub coin_value 1_000L) ~spk:op_true () in
      (match Rpc.dispatch_rpc ctx "sendrawtransaction"
               [ `String (tx_hex in_pool) ] with
       | Ok _ -> ()
       | Error (c, m) -> Alcotest.failf "sendrawtransaction: (%d) %s" c m);
      let other = spend ~prev_txid:coin_txid ~prev_vout:1
          ~value:(Int64.sub coin_value 10_000L) ~spk:op_true () in
      let conflicting = spend ~prev_txid:coin_txid ~prev_vout:0
          ~value:(Int64.sub coin_value 900_000L) ~spk:op_true () in
      match tma ctx [ other; conflicting ] with
      | [ _; c ] ->
        Alcotest.(check bool) "allowed" false (bool_ c "allowed");
        Alcotest.(check string) "reject-reason" "bip125-replacement-disallowed"
          (str c "reject-reason");
        Alcotest.(check int) "pool unchanged" 1 (mempool_size ctx)
      | _ -> Alcotest.fail "two results")

let tx_result j tx =
  Yojson.Safe.Util.(j |> member "tx-results" |> member (wtxid_hex tx))

(* seed_submitpackage/invalid-sig-child/submit: the child's error is Core's
   state.ToString() of the script failure. *)
let test_submitpackage_bad_child_text () =
  with_ctx (fun ctx ->
      put_coin ctx ~vout:0;
      let parent = spend ~prev_txid:coin_txid ~prev_vout:0
          ~value:(Int64.sub coin_value 10_000L) ~spk:p2pk_g () in
      let child = spend ~prev_txid:(Crypto.compute_txid parent) ~prev_vout:0
          ~value:(Int64.sub coin_value 20_000L) ~spk:op_true
          ~script_sig:bad_sig_push () in
      let j = submitpackage ctx [ parent; child ] in
      Alcotest.(check string) "package_msg" "transaction failed"
        (str j "package_msg");
      Alcotest.(check string) "child error"
        (script_details ~reason:null_fail_text child ~prev:(Some parent)
           ~prev_vout:0)
        (str (tx_result j child) "error"))

(* seed_submitpackage/invalid-sig-parent/submit: every tx failed.  Core:
   package_msg "transaction failed", the parent's script error, and the child
   (whose parent never entered the pool) bad-txns-inputs-missingorspent. *)
let test_submitpackage_bad_parent_text () =
  with_ctx (fun ctx ->
      Storage.ChainDB.store_utxo ctx.chain.db coin_txid 0
        (let w = Serialize.writer_create () in
         Utxo.serialize_utxo_entry w
           { value = coin_value; script_pubkey = p2pk_g; height = 1;
             is_coinbase = false };
         Serialize.writer_to_string w);
      let parent = spend ~prev_txid:coin_txid ~prev_vout:0
          ~value:(Int64.sub coin_value 10_000L) ~spk:op_true
          ~script_sig:bad_sig_push () in
      let child = spend ~prev_txid:(Crypto.compute_txid parent) ~prev_vout:0
          ~value:(Int64.sub coin_value 20_000L) ~spk:op_true () in
      let j = submitpackage ctx [ parent; child ] in
      Alcotest.(check string) "package_msg" "transaction failed"
        (str j "package_msg");
      Alcotest.(check string) "parent error"
        (script_details ~reason:null_fail_text parent ~prev:None ~prev_vout:0)
        (str (tx_result j parent) "error");
      Alcotest.(check string) "child error" "bad-txns-inputs-missingorspent"
        (str (tx_result j child) "error");
      Alcotest.(check int) "nothing entered the pool" 0 (mempool_size ctx))

let () =
  Alcotest.run "testmempoolaccept_package"
    [
      ( "testmempoolaccept-package",
        [
          Alcotest.test_case "parent-child both allowed" `Quick
            test_parent_child_allowed;
          Alcotest.test_case "low-fee parent stops the package" `Quick
            test_low_fee_parent_stops_package;
          Alcotest.test_case "bad child script" `Quick test_bad_child_script;
          Alcotest.test_case "bad parent script" `Quick test_bad_parent_script;
          Alcotest.test_case "unsorted package-error" `Quick
            test_unsorted_package_error;
          Alcotest.test_case "mempool conflict not replaced" `Quick
            test_conflict_not_replaced;
        ] );
      ( "submitpackage-script-text",
        [
          Alcotest.test_case "bad child error text" `Quick
            test_submitpackage_bad_child_text;
          Alcotest.test_case "bad parent error text" `Quick
            test_submitpackage_bad_parent_text;
        ] );
    ]
