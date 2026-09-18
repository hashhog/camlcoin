(* R5 T3 remaining — listtransactions / listwallets accepts-invalid,
   getaddressinfo shape, and -4 error mapping.

   CONTROL: `dune exec --no-buffer test/test_r5_t3_remaining.exe`

   tools/r5-probes.d/wallet.jsonl (lane_order 10/40/70/80/100/130/140/150)
   against a wallet-enabled Core. The 2026-09-18T02:17Z harness on parent
   77abe69 scored T3 8/16; these are the eight FAIL rows:

     listtransactions  abandoned missing; negative count/skip accepted
     listwallets       wrong-arity accepted
     getaddressinfo    missing desc / ischange
     createwallet      no-name -4 vs Core -1
     walletcreatefundedpsbt  no-outputs -4 vs -8; invalid-address -4 vs -5
     sendtoaddress     -4 vs -5/-3/-6
     unloadwallet      not-loaded -4 vs -18
     loadwallet        not-found -4 vs -18; already-loaded -4 vs -35

   Dispatch goes through [Rpc.dispatch_rpc] so a handler that maps every
   error to -4, or that ignores surplus/negative args, fails these. *)

open Camlcoin

let dest_addr = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"

let dummy_tip (height : int) : Sync.header_entry =
  { header = { version = 1l; prev_block = Types.zero_hash;
               merkle_root = Types.zero_hash; timestamp = 0l;
               bits = 0l; nonce = 0l };
    hash = Types.zero_hash;
    height;
    total_work = Cstruct.create 32 }

let with_ctx ?(height = 6) f =
  Test_tmp.with_dir ~label:"wallets" ~mkdir:true (fun dir ->
      Test_tmp.with_chaindb (fun db ->
          let utxo = Utxo.UtxoSet.create db in
          let mp = Mempool.create ~network:Consensus.regtest
              ~require_standard:false ~verify_scripts:false ~utxo
              ~current_height:height () in
          let chain = Sync.create_chain_state db Consensus.regtest in
          chain.tip <- Some (dummy_tip height);
          let wm = Wallet.create_wallet_manager ~wallets_dir:dir
              ~network:`Regtest in
          let wallet =
            match Wallet.create_wallet wm "r5" () with
            | Error e -> Alcotest.fail ("create_wallet r5: " ^ e)
            | Ok w -> w
          in
          Hashtbl.replace wm.Wallet.wallets "" wallet;
          let ctx : Rpc.rpc_context = {
            chain; mempool = mp;
            peer_manager = Peer_manager.create Consensus.regtest;
            wallet = Some wallet; wallet_manager = Some wm;
            fee_estimator = Fee_estimation.create ();
            network = Consensus.regtest; filter_index = None; utxo = None;
            data_dir = None; snapshot_activation = None;
          } in
          f ctx wallet))

let check_err ~label ~code result =
  match result with
  | Error (c, _m) ->
    Alcotest.(check int) (label ^ ": code") code c
  | Ok j ->
    Alcotest.failf "%s: expected error (%d) but got Ok %s"
      label code (Yojson.Safe.to_string j)

let assoc_of = function
  | `Assoc fs -> fs
  | j -> Alcotest.failf "expected object, got %s" (Yojson.Safe.to_string j)

let require_field fs name =
  match List.assoc_opt name fs with
  | Some v -> v
  | None -> Alcotest.fail ("missing field " ^ name)

let require_bool fs name =
  match require_field fs name with
  | `Bool b -> b
  | v -> Alcotest.failf "%s: expected bool, got %s" name
           (Yojson.Safe.to_string v)

let require_string fs name =
  match require_field fs name with
  | `String s -> s
  | v -> Alcotest.failf "%s: expected string, got %s" name
           (Yojson.Safe.to_string v)

let require_int fs name =
  match require_field fs name with
  | `Int n -> n
  | v -> Alcotest.failf "%s: expected int, got %s" name
           (Yojson.Safe.to_string v)

let require_arr fs name =
  match require_field fs name with
  | `List xs -> xs
  | v -> Alcotest.failf "%s: expected array, got %s" name
           (Yojson.Safe.to_string v)

let help_lists ctx name =
  match Rpc.dispatch_rpc ctx "help" [] with
  | Error (c, m) -> Alcotest.failf "help: error (%d) %s" c m
  | Ok (`String s) ->
    let found = ref false in
    List.iter (fun line ->
        let line = String.trim line in
        if line <> "" && line.[0] <> '=' then
          let tok =
            match String.split_on_char ' ' line with
            | t :: _ ->
              (match String.split_on_char '(' t with
               | h :: _ -> h | [] -> t)
            | [] -> ""
          in
          if tok = name then found := true)
      (String.split_on_char '\n' s);
    !found
  | Ok j ->
    Alcotest.failf "help: expected string, got %s" (Yojson.Safe.to_string j)

let mk_hist ~addr ~i : Wallet.tx_history_entry =
  { Wallet.hist_txid = Printf.sprintf "%064x" i;
    hist_category = `Receive;
    hist_amount = 250_000_000L;
    hist_fee = 0L;
    hist_address = addr;
    hist_vout = 0;
    hist_is_coinbase = false;
    hist_confirmations = 6;
    hist_block_hash = String.make 64 'a';
    hist_block_height = i;
    hist_timestamp = float_of_int i }

(* ============================================================================
   createwallet no-name -> -1  (arity; wallet.cpp wallet_name required)
   already-exists stays -4 (HandleWalletError FAILED_VERIFY).
   ============================================================================ *)

let test_createwallet_no_name () =
  with_ctx (fun ctx _w ->
      check_err ~label:"createwallet no-name" ~code:(-1)
        (Rpc.dispatch_rpc ctx "createwallet" []))

let test_createwallet_already_exists_stays_minus4 () =
  with_ctx (fun ctx _w ->
      check_err ~label:"createwallet already-exists" ~code:(-4)
        (Rpc.dispatch_rpc ctx "createwallet" [`String "r5"]))

(* ============================================================================
   listwallets wrong-arity -> -1; contains "r5"
   ============================================================================ *)

let test_listwallets_wrong_arity () =
  with_ctx (fun ctx _w ->
      check_err ~label:"listwallets wrong-arity" ~code:(-1)
        (Rpc.dispatch_rpc ctx "listwallets" [`String "unexpected"]))

let test_listwallets_contains_r5 () =
  with_ctx (fun ctx _w ->
      match Rpc.dispatch_rpc ctx "listwallets" [] with
      | Error (c, m) -> Alcotest.failf "listwallets: (%d) %s" c m
      | Ok (`List names) ->
        let has_r5 =
          List.exists (function `String "r5" -> true | _ -> false) names
        in
        Alcotest.(check bool) "listwallets contains r5" true has_r5
      | Ok j ->
        Alcotest.failf "listwallets: expected array, got %s"
          (Yojson.Safe.to_string j))

(* ============================================================================
   listtransactions: abandoned field, count-limits, negative count/skip -8
   ============================================================================ *)

let test_listtransactions_negative () =
  with_ctx (fun ctx _w ->
      check_err ~label:"listtransactions negative-count" ~code:(-8)
        (Rpc.dispatch_rpc ctx "listtransactions" [`String "*"; `Int (-1)]);
      check_err ~label:"listtransactions negative-skip" ~code:(-8)
        (Rpc.dispatch_rpc ctx "listtransactions"
           [`String "*"; `Int 10; `Int (-1)]))

let test_listtransactions_abandoned_and_count () =
  with_ctx (fun ctx w ->
      let kp = Wallet.generate_key w in
      let addr = Address.address_to_string kp.Wallet.address in
      w.Wallet.tx_history <-
        [mk_hist ~addr ~i:1; mk_hist ~addr ~i:2; mk_hist ~addr ~i:3];
      (match Rpc.dispatch_rpc ctx "listtransactions" [`String "*"; `Int 10] with
       | Error (c, m) ->
         Alcotest.failf "listtransactions success: (%d) %s" c m
       | Ok (`List items) ->
         Alcotest.(check int) "listtransactions len" 3 (List.length items);
         List.iter (fun item ->
             let fs = assoc_of item in
             Alcotest.(check bool) "abandoned" false
               (require_bool fs "abandoned");
             Alcotest.(check string) "category" "receive"
               (require_string fs "category");
             Alcotest.(check string) "address" addr
               (require_string fs "address"))
           items
       | Ok j ->
         Alcotest.failf "listtransactions: expected array, got %s"
           (Yojson.Safe.to_string j));
      match Rpc.dispatch_rpc ctx "listtransactions" [`String "*"; `Int 1] with
      | Error (c, m) -> Alcotest.failf "count-limits: (%d) %s" c m
      | Ok (`List items) ->
        Alcotest.(check int) "count-limits max_len 1" 1 (List.length items)
      | Ok j ->
        Alcotest.failf "count-limits: expected array, got %s"
          (Yojson.Safe.to_string j))

(* ============================================================================
   getaddressinfo: desc + ischange + witness fields + labels
   ============================================================================ *)

let test_getaddressinfo_shape_mine () =
  with_ctx (fun ctx w ->
      let kp = Wallet.generate_key w in
      let addr = Address.address_to_string kp.Wallet.address in
      match Rpc.dispatch_rpc ctx "getaddressinfo" [`String addr] with
      | Error (c, m) -> Alcotest.failf "shape-mine: (%d) %s" c m
      | Ok j ->
        let fs = assoc_of j in
        Alcotest.(check bool) "ismine" true (require_bool fs "ismine");
        Alcotest.(check bool) "solvable" true (require_bool fs "solvable");
        Alcotest.(check bool) "iswatchonly" false
          (require_bool fs "iswatchonly");
        Alcotest.(check bool) "ischange" false (require_bool fs "ischange");
        Alcotest.(check bool) "iswitness" true (require_bool fs "iswitness");
        Alcotest.(check int) "witness_version" 0
          (require_int fs "witness_version");
        ignore (require_string fs "desc");
        ignore (require_string fs "parent_desc");
        ignore (require_string fs "witness_program");
        ignore (require_arr fs "labels"))

let test_getaddressinfo_shape_notmine () =
  with_ctx (fun ctx _w ->
      match Rpc.dispatch_rpc ctx "getaddressinfo" [`String dest_addr] with
      | Error (c, m) -> Alcotest.failf "shape-notmine: (%d) %s" c m
      | Ok j ->
        let fs = assoc_of j in
        Alcotest.(check bool) "ismine" false (require_bool fs "ismine");
        Alcotest.(check bool) "solvable" false (require_bool fs "solvable");
        Alcotest.(check bool) "ischange" false (require_bool fs "ischange");
        Alcotest.(check bool) "iswitness" true (require_bool fs "iswitness");
        Alcotest.(check int) "witness_version" 0
          (require_int fs "witness_version");
        Alcotest.(check string) "witness_program"
          "751e76e8199196d454941c45d1b3a323f1433bd6"
          (require_string fs "witness_program");
        ignore (require_arr fs "labels");
        Alcotest.(check bool) "no desc on unsolvable"
          false (List.mem_assoc "desc" fs))

let test_getaddressinfo_invalid () =
  with_ctx (fun ctx _w ->
      check_err ~label:"getaddressinfo invalid-address" ~code:(-5)
        (Rpc.dispatch_rpc ctx "getaddressinfo" [`String "notanaddress"]))

(* ============================================================================
   sendtoaddress error codes
   ============================================================================ *)

let test_sendtoaddress_errors () =
  with_ctx (fun ctx _w ->
      check_err ~label:"sendtoaddress invalid-address" ~code:(-5)
        (Rpc.dispatch_rpc ctx "sendtoaddress"
           [`String "notanaddress"; `Float 0.001]);
      check_err ~label:"sendtoaddress invalid-amount" ~code:(-3)
        (Rpc.dispatch_rpc ctx "sendtoaddress"
           [`String dest_addr; `Int (-1)]);
      check_err ~label:"sendtoaddress insufficient-funds" ~code:(-6)
        (Rpc.dispatch_rpc ctx "sendtoaddress"
           [`String dest_addr; `Int 1_000_000]))

(* ============================================================================
   walletcreatefundedpsbt no-outputs -8; invalid-address -5
   ============================================================================ *)

let test_walletcreatefundedpsbt_errors () =
  with_ctx (fun ctx _w ->
      check_err ~label:"walletcreatefundedpsbt no-outputs" ~code:(-8)
        (Rpc.dispatch_rpc ctx "walletcreatefundedpsbt"
           [`List []; `List []]);
      check_err ~label:"walletcreatefundedpsbt invalid-address" ~code:(-5)
        (Rpc.dispatch_rpc ctx "walletcreatefundedpsbt"
           [`List []; `List [`Assoc [("notanaddress", `Float 0.001)]]]))

(* ============================================================================
   loadwallet / unloadwallet
   ============================================================================ *)

let test_unloadwallet_not_loaded () =
  with_ctx (fun ctx _w ->
      check_err ~label:"unloadwallet not-loaded" ~code:(-18)
        (Rpc.dispatch_rpc ctx "unloadwallet" [`String "r5probe_missing"]))

let test_loadwallet_not_found_and_already_loaded () =
  with_ctx (fun ctx _w ->
      check_err ~label:"loadwallet not-found" ~code:(-18)
        (Rpc.dispatch_rpc ctx "loadwallet" [`String "r5probe_missing"]);
      check_err ~label:"loadwallet already-loaded" ~code:(-35)
        (Rpc.dispatch_rpc ctx "loadwallet" [`String "r5"]))

(* ============================================================================
   help-parity for the methods this round lists
   ============================================================================ *)

let test_stop_wrong_type () =
  with_ctx (fun ctx _w ->
      check_err ~label:"stop wrong-type" ~code:(-3)
        (Rpc.dispatch_rpc ctx "stop" [`String "notanumber"]);
      match Rpc.dispatch_rpc ctx "stop" [] with
      | Error (c, m) -> Alcotest.failf "stop success: (%d) %s" c m
      | Ok (`String s) ->
        Alcotest.(check bool) "stop returns a string" true
          (String.length s > 0)
      | Ok j ->
        Alcotest.failf "stop: expected string, got %s"
          (Yojson.Safe.to_string j))

let test_help_lists_remaining () =
  with_ctx (fun ctx _w ->
      List.iter (fun name ->
          Alcotest.(check bool) ("help lists " ^ name) true
            (help_lists ctx name))
        [ "listtransactions"; "listwallets"; "getaddressinfo";
          "createwallet"; "loadwallet"; "unloadwallet";
          "sendtoaddress"; "walletcreatefundedpsbt" ])

let () =
  let open Alcotest in
  run "R5 T3 remaining (Core probe vectors)" [
    "createwallet", [
      test_case "no-name -> -1" `Quick test_createwallet_no_name;
      test_case "already-exists stays -4"
        `Quick test_createwallet_already_exists_stays_minus4;
    ];
    "listwallets", [
      test_case "wrong-arity -> -1" `Quick test_listwallets_wrong_arity;
      test_case "contains r5" `Quick test_listwallets_contains_r5;
    ];
    "listtransactions", [
      test_case "negative count/skip -> -8"
        `Quick test_listtransactions_negative;
      test_case "abandoned field + count-limits"
        `Quick test_listtransactions_abandoned_and_count;
    ];
    "getaddressinfo", [
      test_case "shape-mine desc/ischange/witness"
        `Quick test_getaddressinfo_shape_mine;
      test_case "shape-notmine ischange/witness"
        `Quick test_getaddressinfo_shape_notmine;
      test_case "invalid-address -> -5"
        `Quick test_getaddressinfo_invalid;
    ];
    "sendtoaddress", [
      test_case "invalid-address -5 / amount -3 / funds -6"
        `Quick test_sendtoaddress_errors;
    ];
    "walletcreatefundedpsbt", [
      test_case "no-outputs -8 / invalid-address -5"
        `Quick test_walletcreatefundedpsbt_errors;
    ];
    "load_unload", [
      test_case "unloadwallet not-loaded -> -18"
        `Quick test_unloadwallet_not_loaded;
      test_case "loadwallet not-found -18 / already-loaded -35"
        `Quick test_loadwallet_not_found_and_already_loaded;
    ];
    "stop", [
      test_case "wrong-type -> -3" `Quick test_stop_wrong_type;
    ];
    "help", [
      test_case "lists remaining T3 methods"
        `Quick test_help_lists_remaining;
    ];
  ]
