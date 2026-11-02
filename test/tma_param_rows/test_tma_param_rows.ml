open Camlcoin

let with_ctx f =
  Test_tmp.with_chaindb (fun db ->
      let utxo = Utxo.UtxoSet.create db in
      let mp =
        Mempool.create ~network:Consensus.regtest ~require_standard:false
          ~verify_scripts:false ~utxo ~current_height:0 ()
      in
      let chain = Sync.create_chain_state db Consensus.regtest in
      f ({ chain; mempool = mp; peer_manager = Peer_manager.create Consensus.regtest;
           wallet = None; wallet_manager = None;
           fee_estimator = Fee_estimation.create (); network = Consensus.regtest;
           filter_index = None; utxo = None; data_dir = None;
           snapshot_activation = None } : Rpc.rpc_context))

let tx_hex (tx : Types.transaction) =
  let w = Serialize.writer_create () in
  Serialize.serialize_transaction w tx;
  let s = Serialize.writer_to_string w in
  String.concat "" (List.init (String.length s)
                      (fun i -> Printf.sprintf "%02x" (Char.code s.[i])))

let a_tx_hex =
  tx_hex
    { Types.version = 2l;
      inputs = [ { Types.previous_output =
                     { Types.txid = Cstruct.of_string (String.make 32 '\x07'); vout = 0l };
                   script_sig = Cstruct.create 0; sequence = 0xFFFFFFFFl } ];
      outputs = [ { Types.value = 1000L; script_pubkey = Cstruct.of_string "\x51" } ];
      witnesses = []; locktime = 0l }

let decode_msg hex =
  "TX decode failed: " ^ hex ^ " Make sure the tx has at least one input."

let expect ?(params = fun x -> [ x ]) arg code msg () =
  with_ctx (fun ctx ->
      match Rpc.dispatch_rpc ctx "testmempoolaccept" (params arg) with
      | Error (c, m) ->
        Alcotest.(check int) "code" code c;
        Alcotest.(check string) "message" msg m
      | Ok j -> Alcotest.failf "expected error, got %s" (Yojson.Safe.to_string j))

let l hexes = `List (List.map (fun h -> `String h) hexes)
let n = String.length a_tx_hex

let () =
  Alcotest.run "tma_param_rows"
    [ ("decode", [
          Alcotest.test_case "not-hex" `Quick (expect (l [ "zz" ]) (-22) (decode_msg "zz"));
          Alcotest.test_case "empty string" `Quick (expect (l [ "" ]) (-22) (decode_msg ""));
          Alcotest.test_case "truncated" `Quick
            (let h = String.sub a_tx_hex 0 (n - 1 - ((n - 1) land 1) ) in
             expect (l [ h ]) (-22) (decode_msg h));
          Alcotest.test_case "trailing byte" `Quick
            (let h = a_tx_hex ^ "00" in expect (l [ h ]) (-22) (decode_msg h));
          Alcotest.test_case "package trailing byte" `Quick
            (let h = a_tx_hex ^ "00" in expect (l [ a_tx_hex; h ]) (-22) (decode_msg h)) ]);
      ("params", [
          Alcotest.test_case "empty array" `Quick
            (expect (`List []) (-8) "Array must contain between 1 and 25 transactions.");
          Alcotest.test_case "26 txs" `Quick
            (expect (l (List.init 26 (fun _ -> a_tx_hex))) (-8)
               "Array must contain between 1 and 25 transactions.");
          Alcotest.test_case "string not array" `Quick
            (expect (`String a_tx_hex) (-3)
               "Wrong type passed:\n{\n    \"Position 1 (rawtxs)\": \"JSON value of type string is not of expected type array\"\n}") ]) ]
