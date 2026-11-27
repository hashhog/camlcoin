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



let tx_ok ctx =
  put_coin ctx ~vout:0;
  spend ~prev_txid:coin_txid ~prev_vout:0
    ~value:(Int64.sub coin_value 10_000L) ~spk:op_true ()

let tmpa ctx params = Rpc.dispatch_rpc ctx "testmempoolaccept" params

let field name = function
  | `List [ `Assoc kv ] -> (try Some (List.assoc name kv) with Not_found -> None)
  | _ -> None

let str_opt = function Some (`String s) -> Some s | _ -> None

let check_reject what ~reason r =
  match r with
  | Error (_, m) -> Alcotest.failf "%s: unexpected error %s" what m
  | Ok j ->
    Alcotest.(check (option bool)) (what ^ " allowed") (Some false)
      (match field "allowed" j with Some (`Bool b) -> Some b | _ -> None);
    Alcotest.(check (option string)) (what ^ " reject-reason") (Some reason)
      (str_opt (field "reject-reason" j));
    Alcotest.(check (option string)) (what ^ " reject-details") (Some reason)
      (str_opt (field "reject-details" j))

(* Core PreChecks: a tx already pooled is TX_CONFLICT "txn-already-in-mempool",
   checked before any conflict/RBF logic (operator/testmempoolaccept/in-mempool). *)
let test_in_mempool () =
  with_ctx ~verify_scripts:false (fun ctx ->
      let tx = tx_ok ctx in
      (match Mempool.accept_transaction ctx.mempool tx with
       | Ok _ -> ()
       | Error e -> Alcotest.failf "setup: %s" e);
      check_reject "in-mempool" ~reason:"txn-already-in-mempool"
        (tmpa ctx [ `List [ `String (tx_hex tx) ] ]))

(* Core: an output already in the coins cache is "txn-already-known"
   (operator/testmempoolaccept/confirmed).  Core probes the outputs only
   once an input is missing, so the tx is confirmed by a connected block
   that spent its input (validation.cpp:855-866). *)
let test_confirmed () =
  with_ctx ~verify_scripts:false (fun ctx ->
      let tx = spend ~prev_txid:coin_txid ~prev_vout:0
          ~value:(Int64.sub coin_value 10_000L) ~spk:op_true () in
      let coinbase : Types.transaction =
        { Types.version = 2l;
          inputs = [ { Types.previous_output =
                         { Types.txid = Types.zero_hash; vout = -1l };
                       script_sig = Cstruct.of_string "\x01\x01\x00";
                       sequence = 0xFFFFFFFFl } ];
          outputs = [ { Types.value = 0L; script_pubkey = op_true } ];
          witnesses = []; locktime = 0l } in
      Mempool.remove_for_block ctx.mempool
        { Types.header = { Types.version = 0x20000000l;
                           prev_block = Types.zero_hash;
                           merkle_root = Types.zero_hash; timestamp = 0l;
                           bits = 0x207fffffl; nonce = 0l };
          transactions = [ coinbase; tx ] }
        1;
      check_reject "confirmed" ~reason:"txn-already-known"
        (tmpa ctx [ `List [ `String (tx_hex tx) ] ]))

(* Control: a fresh valid tx is still allowed. *)
let test_fresh_allowed () =
  with_ctx ~verify_scripts:false (fun ctx ->
      let tx = tx_ok ctx in
      match tmpa ctx [ `List [ `String (tx_hex tx) ] ] with
      | Ok j ->
        Alcotest.(check bool) "allowed" true
          (field "allowed" j = Some (`Bool true))
      | Error (_, m) -> Alcotest.failf "unexpected error %s" m)

let () =
  Alcotest.run "testmempoolaccept_known"
    [ ("testmempoolaccept", [
          Alcotest.test_case "already in mempool" `Quick test_in_mempool;
          Alcotest.test_case "already known (confirmed)" `Quick test_confirmed;
          Alcotest.test_case "fresh tx allowed" `Quick test_fresh_allowed ]) ]
