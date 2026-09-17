(* R5 T3 listunspent — Core-validated probe vectors.

   CONTROL: `dune exec --no-buffer test/test_r5_listunspent.exe`

   tools/r5-probes.d/wallet.jsonl listunspent (lane_order 60), Core
   bitcoin-core/src/wallet/rpc/coins.cpp:456-690:

     invalid-address     [1, 9999999, ["notanaddress"]]              -> -5
     duplicate-address   [1, 9999999, [bcrt1q…080, bcrt1q…080]]     -> -8
     minconf-excludes-all [9999999]  on 6-conf coins                 -> []
     filter-by-own-address [1, 9999999, [own]]                       -> 3 coins
     success-funded      []  fields label/desc/parent_descs/safe

   Dispatch goes through [Rpc.dispatch_rpc] so a handler that ignores
   params (the pre-fix behaviour) fails these. *)

open Camlcoin

let dup_addr = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"

let dummy_tip (height : int) : Sync.header_entry =
  { header = { version = 1l; prev_block = Types.zero_hash;
               merkle_root = Types.zero_hash; timestamp = 0l;
               bits = 0l; nonce = 0l };
    hash = Types.zero_hash;
    height;
    total_work = Cstruct.create 32 }

let with_ctx ?(height = 6) f =
  Test_tmp.with_chaindb (fun db ->
      let utxo = Utxo.UtxoSet.create db in
      let mp = Mempool.create ~network:Consensus.regtest
          ~require_standard:false ~verify_scripts:false ~utxo
          ~current_height:height () in
      let chain = Sync.create_chain_state db Consensus.regtest in
      chain.tip <- Some (dummy_tip height);
      let wallet = Wallet.create ~network:`Regtest ~db_path:"" in
      let ctx : Rpc.rpc_context = {
        chain; mempool = mp;
        peer_manager = Peer_manager.create Consensus.regtest;
        wallet = Some wallet; wallet_manager = None;
        fee_estimator = Fee_estimation.create ();
        network = Consensus.regtest; filter_index = None; utxo = None;
        data_dir = None; snapshot_activation = None;
      } in
      f ctx wallet)

let fund_three (w : Wallet.t) : string =
  let kp = Wallet.generate_key w in
  let script = Wallet.build_p2wpkh_script (Crypto.hash160 kp.Wallet.public_key) in
  let mk i =
    let txid = Cstruct.create 32 in
    Cstruct.set_uint8 txid 0 (i + 1);
    { Wallet.outpoint = { Types.txid; vout = 0l };
      utxo = { Utxo.value = 250_000_000L; script_pubkey = script;
               height = 1; is_coinbase = false };
      key_index = 0; confirmed = true; watch_only = false }
  in
  w.utxos <- [mk 0; mk 1; mk 2];
  Address.address_to_string kp.Wallet.address

let check_err ~label ~code ?msg result =
  match result with
  | Error (c, m) ->
    Alcotest.(check int) (label ^ ": code") code c;
    (match msg with
     | Some expected -> Alcotest.(check string) (label ^ ": message") expected m
     | None -> ())
  | Ok j ->
    Alcotest.failf "%s: expected error (%d) but got Ok %s"
      label code (Yojson.Safe.to_string j)

let assoc_keys (j : Yojson.Safe.t) : string list =
  match j with
  | `Assoc fs -> List.map fst fs
  | _ -> []

let has_key keys name = List.mem name keys

(* ============================================================================
   invalid-address -> -5  (coins.cpp:542)
   ============================================================================ *)

let test_invalid_address () =
  with_ctx (fun ctx _w ->
      check_err ~label:"listunspent invalid-address"
        ~code:(-5) ~msg:"Invalid Bitcoin address: notanaddress"
        (Rpc.dispatch_rpc ctx "listunspent"
           [`Int 1; `Int 9_999_999; `List [`String "notanaddress"]]))

(* ============================================================================
   duplicate-address -> -8  (coins.cpp:545)
   ============================================================================ *)

let test_duplicate_address () =
  with_ctx (fun ctx _w ->
      check_err ~label:"listunspent duplicate-address"
        ~code:(-8)
        ~msg:("Invalid parameter, duplicated address: " ^ dup_addr)
        (Rpc.dispatch_rpc ctx "listunspent"
           [`Int 1; `Int 9_999_999;
            `List [`String dup_addr; `String dup_addr]]))

(* ============================================================================
   minconf-excludes-all: 6-conf coins vs minconf=9999999 -> []
   ============================================================================ *)

let test_minconf_excludes_all () =
  with_ctx ~height:6 (fun ctx w ->
      let _addr = fund_three w in
      match Rpc.dispatch_rpc ctx "listunspent" [`Int 9_999_999] with
      | Error (c, m) ->
        Alcotest.failf "minconf-excludes-all: error (%d) %s" c m
      | Ok (`List []) -> ()
      | Ok j ->
        Alcotest.failf "minconf-excludes-all: expected [], got %s"
          (Yojson.Safe.to_string j))

(* ============================================================================
   filter-by-own-address: 3 coins at own address
   ============================================================================ *)

let test_filter_by_own_address () =
  with_ctx ~height:6 (fun ctx w ->
      let addr = fund_three w in
      match Rpc.dispatch_rpc ctx "listunspent"
              [`Int 1; `Int 9_999_999; `List [`String addr]] with
      | Error (c, m) ->
        Alcotest.failf "filter-by-own-address: error (%d) %s" c m
      | Ok (`List items) ->
        Alcotest.(check int) "filter-by-own-address len" 3 (List.length items)
      | Ok j ->
        Alcotest.failf "filter-by-own-address: expected array, got %s"
          (Yojson.Safe.to_string j))

(* ============================================================================
   success-funded: 3 coins, Core-required fields, elem address/spendable/solvable/safe
   ============================================================================ *)

let test_success_funded () =
  with_ctx ~height:6 (fun ctx w ->
      let addr = fund_three w in
      match Rpc.dispatch_rpc ctx "listunspent" [] with
      | Error (c, m) ->
        Alcotest.failf "success-funded: error (%d) %s" c m
      | Ok (`List items) ->
        Alcotest.(check int) "success-funded len" 3 (List.length items);
        List.iteri (fun i j ->
            let keys = assoc_keys j in
            List.iter (fun name ->
                if not (has_key keys name) then
                  Alcotest.failf "elem[%d]: missing field %s" i name)
              ["txid"; "vout"; "address"; "label"; "scriptPubKey"; "amount";
               "confirmations"; "spendable"; "solvable"; "desc";
               "parent_descs"; "safe"];
            match j with
            | `Assoc fs ->
              let get k = List.assoc k fs in
              Alcotest.(check string) "address" addr
                (match get "address" with `String s -> s | _ -> "");
              Alcotest.(check bool) "spendable" true
                (match get "spendable" with `Bool b -> b | _ -> false);
              Alcotest.(check bool) "solvable" true
                (match get "solvable" with `Bool b -> b | _ -> false);
              Alcotest.(check bool) "safe" true
                (match get "safe" with `Bool b -> b | _ -> false);
              Alcotest.(check int) "confirmations" 6
                (match get "confirmations" with `Int n -> n | _ -> -1)
            | _ -> Alcotest.fail "elem is not an object")
          items
      | Ok j ->
        Alcotest.failf "success-funded: expected array, got %s"
          (Yojson.Safe.to_string j))

let () =
  let open Alcotest in
  run "R5 listunspent (Core probe vectors)" [
    "listunspent", [
      test_case "invalid-address -> -5" `Quick test_invalid_address;
      test_case "duplicate-address -> -8" `Quick test_duplicate_address;
      test_case "minconf-excludes-all -> []" `Quick test_minconf_excludes_all;
      test_case "filter-by-own-address -> 3" `Quick test_filter_by_own_address;
      test_case "success-funded fields" `Quick test_success_funded;
    ];
  ]
