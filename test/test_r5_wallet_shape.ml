(* R5 T3 shape — getwalletinfo blank/flags/lastprocessedblock and
   getbalances lastprocessedblock.

   CONTROL: `dune exec --no-buffer test/test_r5_wallet_shape.exe`

   tools/r5-probes.d/wallet.jsonl (lane_order 20/50), Core
   bitcoin-core/src/wallet/rpc/wallet.cpp getwalletinfo and
   coins.cpp getbalances + util.cpp AppendLastProcessedBlock:

     getwalletinfo shape     []  fields include blank, flags,
                                 lastprocessedblock.{hash,height};
                                 equals walletname=r5, descriptors=true,
                                 private_keys_enabled=true, blank=false
     getwalletinfo wrong-arity ["unexpected"] -> -1
     getbalances shape       []  mine.{trusted,untrusted_pending,immature}
                                 + lastprocessedblock.{hash,height}
     getbalances wrong-arity ["unexpected"] -> -1
     help lists both methods

   Dispatch goes through [Rpc.dispatch_rpc] so a handler that omits fields
   or ignores surplus args (the pre-fix behaviour) fails these. *)

open Camlcoin

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

let require_obj fs name =
  match require_field fs name with
  | `Assoc inner -> inner
  | v -> Alcotest.failf "%s: expected object, got %s" name
           (Yojson.Safe.to_string v)

let require_arr fs name =
  match require_field fs name with
  | `List xs -> xs
  | v -> Alcotest.failf "%s: expected array, got %s" name
           (Yojson.Safe.to_string v)

let check_lastprocessedblock ~label ~height fs =
  let lpb = require_obj fs "lastprocessedblock" in
  let hash = require_string lpb "hash" in
  Alcotest.(check int) (label ^ " lastprocessedblock.hash len") 64
    (String.length hash);
  Alcotest.(check int) (label ^ " lastprocessedblock.height") height
    (require_int lpb "height")

(* ============================================================================
   getwalletinfo shape — Core wallet.cpp:83-131
   ============================================================================ *)

let test_getwalletinfo_shape () =
  with_ctx ~height:6 (fun ctx _w ->
      match Rpc.dispatch_rpc ctx "getwalletinfo" [] with
      | Error (c, m) ->
        Alcotest.failf "getwalletinfo shape: error (%d) %s" c m
      | Ok j ->
        let fs = assoc_of j in
        Alcotest.(check string) "walletname" "r5" (require_string fs "walletname");
        ignore (require_int fs "walletversion");
        ignore (require_string fs "format");
        ignore (require_int fs "txcount");
        ignore (require_int fs "keypoolsize");
        Alcotest.(check bool) "private_keys_enabled" true
          (require_bool fs "private_keys_enabled");
        ignore (require_bool fs "avoid_reuse");
        ignore (require_field fs "scanning");
        Alcotest.(check bool) "descriptors" true (require_bool fs "descriptors");
        ignore (require_bool fs "external_signer");
        Alcotest.(check bool) "blank" false (require_bool fs "blank");
        ignore (require_arr fs "flags");
        check_lastprocessedblock ~label:"getwalletinfo" ~height:6 fs)

(* ============================================================================
   getwalletinfo wrong-arity -> -1  (rpc/util.cpp HelpResult)
   ============================================================================ *)

let test_getwalletinfo_wrong_arity () =
  with_ctx (fun ctx _w ->
      check_err ~label:"getwalletinfo wrong-arity"
        ~code:(-1)
        (Rpc.dispatch_rpc ctx "getwalletinfo" [`String "unexpected"]))

(* ============================================================================
   createwallet blank=true -> getwalletinfo.blank=true
   ============================================================================ *)

let test_getwalletinfo_blank_true () =
  with_ctx (fun ctx _w ->
      (match Rpc.dispatch_rpc ctx "createwallet"
               [`String "blankw"; `Bool false; `Bool true] with
       | Error (c, m) ->
         Alcotest.failf "createwallet blank: (%d) %s" c m
       | Ok _ -> ());
      match Rpc.dispatch_rpc ctx "getwalletinfo" [] with
      | Error (c, m) ->
        Alcotest.failf "getwalletinfo blank-true: error (%d) %s" c m
      | Ok j ->
        let fs = assoc_of j in
        Alcotest.(check bool) "blank" true (require_bool fs "blank");
        Alcotest.(check string) "walletname" "blankw"
          (require_string fs "walletname"))

(* ============================================================================
   getbalances shape — Core coins.cpp:401-451
   ============================================================================ *)

let test_getbalances_shape () =
  with_ctx ~height:6 (fun ctx _w ->
      match Rpc.dispatch_rpc ctx "getbalances" [] with
      | Error (c, m) ->
        Alcotest.failf "getbalances shape: error (%d) %s" c m
      | Ok j ->
        let fs = assoc_of j in
        let mine = require_obj fs "mine" in
        ignore (require_field mine "trusted");
        ignore (require_field mine "untrusted_pending");
        ignore (require_field mine "immature");
        check_lastprocessedblock ~label:"getbalances" ~height:6 fs)

(* ============================================================================
   getbalances wrong-arity -> -1
   ============================================================================ *)

let test_getbalances_wrong_arity () =
  with_ctx (fun ctx _w ->
      check_err ~label:"getbalances wrong-arity"
        ~code:(-1)
        (Rpc.dispatch_rpc ctx "getbalances" [`String "unexpected"]))

(* ============================================================================
   help-parity
   ============================================================================ *)

let test_help_lists_methods () =
  with_ctx (fun ctx _w ->
      match Rpc.dispatch_rpc ctx "help" [] with
      | Error (c, m) -> Alcotest.failf "help: error (%d) %s" c m
      | Ok (`String s) ->
        let listed name =
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
        in
        Alcotest.(check bool) "help lists getwalletinfo" true
          (listed "getwalletinfo");
        Alcotest.(check bool) "help lists getbalances" true
          (listed "getbalances")
      | Ok j ->
        Alcotest.failf "help: expected string, got %s"
          (Yojson.Safe.to_string j))

let () =
  let open Alcotest in
  run "R5 getwalletinfo/getbalances shape (Core probe vectors)" [
    "getwalletinfo", [
      test_case "shape blank/flags/lastprocessedblock" `Quick
        test_getwalletinfo_shape;
      test_case "wrong-arity -> -1" `Quick test_getwalletinfo_wrong_arity;
      test_case "blank wallet reports blank=true" `Quick
        test_getwalletinfo_blank_true;
    ];
    "getbalances", [
      test_case "shape lastprocessedblock" `Quick test_getbalances_shape;
      test_case "wrong-arity -> -1" `Quick test_getbalances_wrong_arity;
    ];
    "help", [
      test_case "lists getwalletinfo/getbalances" `Quick
        test_help_lists_methods;
    ];
  ]
