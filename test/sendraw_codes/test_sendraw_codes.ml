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

let send ctx params = Rpc.dispatch_rpc ctx "sendrawtransaction" params

let check_err what (c, m) = function
  | Error (c', m') ->
    Alcotest.(check int) (what ^ " code") c c';
    Alcotest.(check string) (what ^ " message") m m'
  | Ok j -> Alcotest.failf "%s: expected error, got %s" what (Yojson.Safe.to_string j)

(* Core: ALREADY_IN_UTXO_SET -> RPC_VERIFY_ALREADY_IN_UTXO_SET (-27),
   "Transaction outputs already in utxo set"
   (operator/sendrawtransaction/confirmed). *)
let test_confirmed () =
  with_ctx ~verify_scripts:false (fun ctx ->
      let tx = tx_ok ctx in
      let txid = Crypto.compute_txid tx in
      (* the tx's own output 0 is already a confirmed coin *)
      let e : Utxo.utxo_entry =
        { value = 1L; script_pubkey = op_true; height = 1; is_coinbase = false } in
      let w = Serialize.writer_create () in
      Utxo.serialize_utxo_entry w e;
      Storage.ChainDB.store_utxo ctx.chain.db txid 0 (Serialize.writer_to_string w);
      check_err "confirmed" (-27, "Transaction outputs already in utxo set")
        (send ctx [ `String (tx_hex tx) ]))

(* Core: MISSING_INPUTS -> RPC_TRANSACTION_ERROR (-25)
   (operator/sendrawtransaction/missing-inputs). *)
let test_missing_inputs () =
  with_ctx ~verify_scripts:false (fun ctx ->
      let tx = spend ~prev_txid:(Cstruct.of_string (String.make 32 '\x09'))
          ~prev_vout:0 ~value:1000L ~spk:op_true () in
      check_err "missing-inputs" (-25, "bad-txns-inputs-missingorspent")
        (send ctx [ `String (tx_hex tx) ]))

(* Core ParseFeeRate -> AmountFromValue: -3 "Invalid amount"
   (operator/sendrawtransaction/bad-maxfeerate). *)
let test_bad_maxfeerate () =
  with_ctx ~verify_scripts:false (fun ctx ->
      let tx = tx_ok ctx in
      check_err "bad-maxfeerate" (-3, "Invalid amount")
        (send ctx [ `String (tx_hex tx); `String "abc" ]))

let () =
  Alcotest.run "sendraw_codes"
    [ ("sendrawtransaction", [
          Alcotest.test_case "confirmed -27" `Quick test_confirmed;
          Alcotest.test_case "missing-inputs -25" `Quick test_missing_inputs;
          Alcotest.test_case "bad maxfeerate -3" `Quick test_bad_maxfeerate ]) ]
