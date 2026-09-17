(* R5 T3 getnewaddress — Core-validated probe vectors.

   CONTROL: `dune exec --no-buffer test/test_r5_getnewaddress.exe`

   tools/r5-probes.d/wallet.jsonl getnewaddress (lane_order 30), Core
   bitcoin-core/src/wallet/rpc/addresses.cpp getnewaddress +
   src/outputtype.cpp ParseOutputType:

     success-default-bech32  []                    -> bcrt1q… (P2WPKH)
     success-bech32m         ["", "bech32m"]       -> bcrt1p… (P2TR)
     success-p2sh-segwit     ["", "p2sh-segwit"]   -> 2…      (P2SH-P2WPKH)
     success-legacy          ["", "legacy"]        -> m/n…    (P2PKH)
     bad-address-type        ["", "bogustype"]     -> -5
       "Unknown address type 'bogustype'"
       (RPC_INVALID_ADDRESS_OR_KEY; addresses.cpp:57)

   Dispatch goes through [Rpc.dispatch_rpc] so a handler that maps every
   error to RPC_WALLET_ERROR (-4) or that refuses p2sh-segwit (the pre-fix
   behaviour) fails these. *)

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

(* OCaml Str has no {n,m} counts; check prefix + exact rest length against
   the same shapes tools/r5-probes.d/wallet.jsonl uses (Python regex). *)
let require_addr ~label ~prefix ~rest_len result =
  match result with
  | Error (c, m) ->
    Alcotest.failf "%s: error (%d) %s" label c m
  | Ok (`String addr) ->
    let plen = String.length prefix in
    let want = plen + rest_len in
    if String.length addr <> want then
      Alcotest.failf "%s: %S length %d, want %d" label addr
        (String.length addr) want;
    if String.sub addr 0 plen <> prefix then
      Alcotest.failf "%s: %S missing prefix %S" label addr prefix;
    addr
  | Ok j ->
    Alcotest.failf "%s: expected string, got %s" label
      (Yojson.Safe.to_string j)

let require_b58 ~label ~prefix_ok ~min_len ~max_len result =
  match result with
  | Error (c, m) ->
    Alcotest.failf "%s: error (%d) %s" label c m
  | Ok (`String addr) ->
    let n = String.length addr in
    if n < min_len || n > max_len then
      Alcotest.failf "%s: %S length %d, want %d..%d" label addr n min_len max_len;
    if n = 0 || not (prefix_ok addr.[0]) then
      Alcotest.failf "%s: %S bad prefix" label addr;
    addr
  | Ok j ->
    Alcotest.failf "%s: expected string, got %s" label
      (Yojson.Safe.to_string j)

(* ============================================================================
   success-default-bech32 -> bcrt1q…  (wallet.h DEFAULT_ADDRESS_TYPE BECH32)
   ============================================================================ *)

let test_success_default_bech32 () =
  with_ctx (fun ctx _w ->
      ignore (require_addr ~label:"success-default-bech32"
                ~prefix:"bcrt1q" ~rest_len:38
                (Rpc.dispatch_rpc ctx "getnewaddress" [])))

(* ============================================================================
   success-bech32m -> bcrt1p…  (OutputType::BECH32M / BIP-86 P2TR)
   ============================================================================ *)

let test_success_bech32m () =
  with_ctx (fun ctx _w ->
      ignore (require_addr ~label:"success-bech32m"
                ~prefix:"bcrt1p" ~rest_len:58
                (Rpc.dispatch_rpc ctx "getnewaddress"
                   [`String ""; `String "bech32m"])))

(* ============================================================================
   success-p2sh-segwit -> 2…  (OutputType::P2SH_SEGWIT / BIP-49 P2SH-P2WPKH)
   ============================================================================ *)

let test_success_p2sh_segwit () =
  with_ctx (fun ctx w ->
      let addr = require_b58 ~label:"success-p2sh-segwit"
                   ~prefix_ok:(fun c -> c = '2') ~min_len:26 ~max_len:40
                   (Rpc.dispatch_rpc ctx "getnewaddress"
                      [`String ""; `String "p2sh-segwit"]) in
      match Address.address_of_string addr with
      | Error e -> Alcotest.fail ("p2sh-segwit decode: " ^ e)
      | Ok decoded ->
        Alcotest.(check bool) "p2sh-segwit is P2SH" true
          (decoded.Address.addr_type = Address.P2SH);
        let script = Wallet.build_output_script decoded in
        (match Wallet.is_mine w script with
         | None -> Alcotest.fail "p2sh-segwit scriptPubKey is not is_mine"
         | Some _ -> ()))

(* ============================================================================
   success-legacy -> m/n…  (OutputType::LEGACY / BIP-44 P2PKH)
   ============================================================================ *)

let test_success_legacy () =
  with_ctx (fun ctx _w ->
      ignore (require_b58 ~label:"success-legacy"
                ~prefix_ok:(fun c -> c = 'm' || c = 'n')
                ~min_len:26 ~max_len:40
                (Rpc.dispatch_rpc ctx "getnewaddress"
                   [`String ""; `String "legacy"])))

(* ============================================================================
   bad-address-type -> -5  (addresses.cpp:57 RPC_INVALID_ADDRESS_OR_KEY)
   ============================================================================ *)

let test_bad_address_type () =
  with_ctx (fun ctx _w ->
      check_err ~label:"bad-address-type"
        ~code:(-5) ~msg:"Unknown address type 'bogustype'"
        (Rpc.dispatch_rpc ctx "getnewaddress"
           [`String ""; `String "bogustype"]))

(* ============================================================================
   help-parity
   ============================================================================ *)

let test_help_lists_getnewaddress () =
  with_ctx (fun ctx _w ->
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
              if tok = "getnewaddress" then found := true)
          (String.split_on_char '\n' s);
        Alcotest.(check bool) "help lists getnewaddress" true !found
      | Ok j ->
        Alcotest.failf "help: expected string, got %s"
          (Yojson.Safe.to_string j))

let () =
  let open Alcotest in
  run "R5 getnewaddress (Core probe vectors)" [
    "getnewaddress", [
      test_case "success-default-bech32" `Quick test_success_default_bech32;
      test_case "success-bech32m" `Quick test_success_bech32m;
      test_case "success-p2sh-segwit" `Quick test_success_p2sh_segwit;
      test_case "success-legacy" `Quick test_success_legacy;
      test_case "bad-address-type -> -5" `Quick test_bad_address_type;
    ];
    "help", [
      test_case "lists getnewaddress" `Quick test_help_lists_getnewaddress;
    ];
  ]
