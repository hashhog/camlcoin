(* getaddressinfo isscript and labels.

   Core getaddressinfo (wallet/rpc/addresses.cpp) pushes, after
   iswatchonly, DescribeWalletAddress -> DescribeAddress (rpc/util.cpp):
   isscript false for PKHash / WitnessV0KeyHash, true for ScriptHash /
   WitnessV0ScriptHash / WitnessV1Taproot, then iswitness, witness_version,
   witness_program; then ischange; last, labels holds the address-book
   entry's label.  getnewaddress writes that entry for every receive address
   (label "" by default, CWallet::GetNewDestination -> SetAddressBook), so a
   fresh receive address reports labels [""].  camlcoin emitted no isscript
   and always labels [] (core-regtest rows wallet/address/info:isscript and
   wallet/address/info:labels[0]). *)

open Camlcoin

let with_ctx f =
  Test_tmp.with_chaindb (fun db ->
      let utxo = Utxo.UtxoSet.create db in
      let mp = Mempool.create ~network:Consensus.regtest
          ~require_standard:false ~verify_scripts:false ~utxo
          ~current_height:6 () in
      let chain = Sync.create_chain_state db Consensus.regtest in
      let wallet = Wallet.create ~network:`Regtest ~db_path:"" in
      Wallet.init_from_seed wallet (Cstruct.create 32);
      let ctx : Rpc.rpc_context = {
        chain; mempool = mp;
        peer_manager = Peer_manager.create Consensus.regtest;
        wallet = Some wallet; wallet_manager = None;
        fee_estimator = Fee_estimation.create ();
        network = Consensus.regtest; filter_index = None; utxo = None;
        data_dir = None; snapshot_activation = None;
      } in
      f ctx wallet)

let ok label = function
  | Ok j -> j
  | Error (c, m) -> Alcotest.failf "%s: (%d) %s" label c m

let fields = function
  | `Assoc kv -> kv
  | j -> Alcotest.failf "expected object, got %s" (Yojson.Safe.to_string j)

let info ctx addr = fields (ok "getaddressinfo"
                              (Rpc.dispatch_rpc ctx "getaddressinfo" [`String addr]))

let new_address ctx params =
  match ok "getnewaddress" (Rpc.dispatch_rpc ctx "getnewaddress" params) with
  | `String a -> a
  | j -> Alcotest.failf "getnewaddress: %s" (Yojson.Safe.to_string j)

let labels fs =
  match List.assoc_opt "labels" fs with
  | Some (`List l) -> List.map (function `String s -> s | j -> Yojson.Safe.to_string j) l
  | _ -> Alcotest.fail "labels missing or not an array"

let isscript fs =
  match List.assoc_opt "isscript" fs with
  | Some (`Bool b) -> Some b
  | None -> None
  | Some j -> Alcotest.failf "isscript: %s" (Yojson.Safe.to_string j)

let foreign addr_type len =
  Address.address_to_string
    { Address.addr_type; hash = Cstruct.create len; network = `Regtest }

let slist = Alcotest.(list string)
let obool = Alcotest.(option bool)

(* The harness row: a default getnewaddress (bech32) address. *)
let test_new_address_label_and_isscript () =
  with_ctx (fun ctx _w ->
      let fs = info ctx (new_address ctx []) in
      Alcotest.check slist "labels of a new receive address" [""] (labels fs);
      Alcotest.check obool "isscript p2wpkh" (Some false) (isscript fs))

let test_named_label () =
  with_ctx (fun ctx _w ->
      let fs = info ctx (new_address ctx [`String "rent"]) in
      Alcotest.check slist "labels carry the given label" ["rent"] (labels fs);
      let fs = info ctx (new_address ctx [`Null; `String "legacy"]) in
      Alcotest.check slist "null label is the empty label" [""] (labels fs);
      Alcotest.check obool "isscript p2pkh" (Some false) (isscript fs))

let test_isscript_per_type () =
  with_ctx (fun ctx _w ->
      let cases = [
        "p2pkh", foreign Address.P2PKH 20, Some false;
        "p2sh", foreign Address.P2SH 20, Some true;
        "p2wpkh", foreign Address.P2WPKH 20, Some false;
        "p2wsh", foreign Address.P2WSH 32, Some true;
        "p2tr", foreign Address.P2TR 32, Some true;
      ] in
      List.iter (fun (name, addr, want) ->
          let fs = info ctx addr in
          Alcotest.check obool ("isscript " ^ name) want (isscript fs);
          Alcotest.check slist ("labels of foreign " ^ name) [] (labels fs))
        cases)

(* Change addresses get no address-book entry in Core.  camlcoin has no
   getrawchangeaddress RPC; its send paths mint change with
   Wallet.generate_change_key, so check an address minted that way. *)
let test_change_address_unlabelled () =
  with_ctx (fun ctx w ->
      let kp = Wallet.generate_change_key w in
      let a = Address.address_to_string kp.Wallet.address in
      Alcotest.check slist "labels of a change address" [] (labels (info ctx a)))

(* Core's field order: iswatchonly, isscript, iswitness, witness_version,
   witness_program, ischange, labels. *)
let test_field_order () =
  with_ctx (fun ctx _w ->
      let fs = info ctx (new_address ctx []) in
      let want = ["iswatchonly"; "isscript"; "iswitness"; "witness_version";
                  "witness_program"; "ischange"; "labels"] in
      let got = List.filter (fun k -> List.mem k want) (List.map fst fs) in
      Alcotest.check slist "field order" want got)

(* The address book survives a save/load round trip of the wallet file. *)
let test_label_persists () =
  with_ctx (fun ctx w ->
      let a = new_address ctx [`String "kept"] in
      let json = Wallet.wallet_to_json w in
      let w2 = Wallet.create ~network:`Regtest ~db_path:"" in
      Wallet.load_wallet_json w2 `Regtest json;
      let ctx2 = { ctx with Rpc.wallet = Some w2 } in
      Alcotest.check slist "label after reload" ["kept"] (labels (info ctx2 a)))

let () =
  Alcotest.run "getaddressinfo_labels_isscript" [
    "getaddressinfo", [
      Alcotest.test_case "new receive address: labels [\"\"], isscript false"
        `Quick test_new_address_label_and_isscript;
      Alcotest.test_case "getnewaddress label argument is recorded"
        `Quick test_named_label;
      Alcotest.test_case "isscript per address type" `Quick test_isscript_per_type;
      Alcotest.test_case "change address has no label" `Quick
        test_change_address_unlabelled;
      Alcotest.test_case "field order follows Core" `Quick test_field_order;
      Alcotest.test_case "label persists across save/load" `Quick
        test_label_persists;
    ];
  ]
