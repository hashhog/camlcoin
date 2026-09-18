(* R5 T3 walletprocesspsbt — Core-validated probe vectors.

   CONTROL: `dune exec --no-buffer test/test_r5_walletprocesspsbt.exe`

   tools/r5-probes.d/wallet.jsonl walletprocesspsbt (lane_order 90), Core
   bitcoin-core/src/wallet/rpc/spend.cpp::walletprocesspsbt +
   CWallet::FillPSBT (wallet.cpp:2200):

     success-sign-own  ["%OWNPSBT%", true]  -> {psbt, complete:true, hex}
       %OWNPSBT% is Core createpsbt of one of OUR coins: unsigned, NO
       witness_utxo / non_witness_utxo. FillPSBT must pull the prevout
       from the wallet, sign, finalize, and emit network hex.
     fill-only-not-complete  ["%OWNPSBT%", false] -> complete:false
     decode-error            ["not-a-psbt"]       -> -22
       DecodeBase64PSBT failure is RPC_DESERIALIZATION_ERROR
       (spend.cpp:1614), not RPC_WALLET_ERROR (-4).

   Dispatch goes through [Rpc.dispatch_rpc] so a handler that maps every
   error to -4, or that refuses to sign a PSBT that lacks UTXO maps
   (the pre-fix behaviour), fails these. *)

open Camlcoin

let dummy_tip (height : int) : Sync.header_entry =
  { header = { version = 1l; prev_block = Types.zero_hash;
               merkle_root = Types.zero_hash; timestamp = 0l;
               bits = 0l; nonce = 0l };
    hash = Types.zero_hash;
    height;
    total_work = Cstruct.create 32 }

let with_ctx ?(height = 200) f =
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

let dest_spk () =
  match Address.address_of_string
          "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080" with
  | Ok a -> Wallet.build_output_script a
  | Error e -> Alcotest.fail ("dest address: " ^ e)

let fund_p2wpkh (w : Wallet.t) : Wallet.wallet_utxo =
  let kp = Wallet.generate_key w in
  let script =
    Wallet.build_p2wpkh_script (Crypto.hash160 kp.Wallet.public_key)
  in
  let txid = Cstruct.create 32 in
  Cstruct.set_uint8 txid 0 0xa1;
  let wutxo =
    { Wallet.outpoint = { Types.txid; vout = 0l };
      utxo = { Utxo.value = 100_000L; script_pubkey = script;
               height = 100; is_coinbase = false };
      key_index = 0; confirmed = true; watch_only = false }
  in
  w.Wallet.utxos <- [wutxo];
  wutxo

(* Unsigned PSBT with EMPTY input maps — the createpsbt shape. *)
let unsigned_psbt_spending (owned : Wallet.wallet_utxo) : string =
  let fee = 2_000L in
  let tx : Types.transaction = {
    version = 2l;
    inputs = [{
      previous_output = owned.Wallet.outpoint;
      script_sig = Cstruct.create 0;
      sequence = 0xFFFFFFFDl;
    }];
    outputs = [{
      value = Int64.sub owned.Wallet.utxo.Utxo.value fee;
      script_pubkey = dest_spk ();
    }];
    witnesses = [];
    locktime = 0l;
  } in
  Psbt.to_base64 (Psbt.create tx)

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

let hex_to_cstruct hex =
  let len = String.length hex in
  if len mod 2 <> 0 then Alcotest.failf "odd hex length %d" len;
  let cs = Cstruct.create (len / 2) in
  for i = 0 to (len / 2) - 1 do
    Cstruct.set_uint8 cs i
      (int_of_string ("0x" ^ String.sub hex (i * 2) 2))
  done;
  cs

let standard_flags =
  Script.script_verify_p2sh
  lor Script.script_verify_dersig
  lor Script.script_verify_nulldummy
  lor Script.script_verify_witness
  lor Script.script_verify_witness_pubkeytype

(* ============================================================================
   success-sign-own: unsigned PSBT of a wallet coin, no UTXO maps.
   Core FillPSBT fills the prevout from mapWallet, signs, finalizes,
   and returns hex. Pre-fix: complete=false, no hex.
   ============================================================================ *)

let test_success_sign_own () =
  with_ctx (fun ctx w ->
      let owned = fund_p2wpkh w in
      let b64 = unsigned_psbt_spending owned in
      match Rpc.dispatch_rpc ctx "walletprocesspsbt"
              [`String b64; `Bool true] with
      | Error (c, m) ->
        Alcotest.failf "success-sign-own: error (%d) %s" c m
      | Ok j ->
        let fs = assoc_of j in
        (match List.assoc_opt "complete" fs with
         | Some (`Bool true) -> ()
         | Some v ->
           Alcotest.failf "success-sign-own: complete=%s, want true"
             (Yojson.Safe.to_string v)
         | None -> Alcotest.fail "success-sign-own: missing field complete");
        let hex =
          match List.assoc_opt "hex" fs with
          | Some (`String s) when String.length s > 0 -> s
          | Some v ->
            Alcotest.failf "success-sign-own: hex=%s"
              (Yojson.Safe.to_string v)
          | None ->
            Alcotest.fail "success-sign-own: missing field hex"
        in
        let tx =
          Serialize.deserialize_transaction
            (Serialize.reader_of_cstruct (hex_to_cstruct hex))
        in
        Alcotest.(check int) "success-sign-own: one input"
          1 (List.length tx.Types.inputs);
        let input = List.hd tx.Types.inputs in
        Alcotest.(check int) "success-sign-own: empty scriptSig"
          0 (Cstruct.length input.Types.script_sig);
        let witness =
          match tx.Types.witnesses with
          | w :: _ -> w.Types.items
          | [] -> []
        in
        Alcotest.(check int) "success-sign-own: P2WPKH witness [sig,pubkey]"
          2 (List.length witness);
        (match Script.verify_script
                 ~tx ~input_index:0
                 ~script_pubkey:owned.Wallet.utxo.Utxo.script_pubkey
                 ~script_sig:input.Types.script_sig
                 ~witness:{ Types.items = witness }
                 ~amount:owned.Wallet.utxo.Utxo.value
                 ~flags:standard_flags () with
         | Ok true -> ()
         | Ok false ->
           Alcotest.fail "success-sign-own: verify_script returned false"
         | Error e ->
           Alcotest.failf "success-sign-own: verify_script: %s" e);
        (* Non-vacuity: flip a signature byte and the same verifier must
           reject. Proves verify_script is a real check, not a no-op. *)
        let bad_items =
          match witness with
          | sigb :: rest ->
            let flipped = Cstruct.of_string (Cstruct.to_string sigb) in
            let mid = Cstruct.length flipped / 2 in
            Cstruct.set_uint8 flipped mid
              (Cstruct.get_uint8 flipped mid lxor 0xff);
            flipped :: rest
          | [] -> assert false
        in
        (match Script.verify_script
                 ~tx ~input_index:0
                 ~script_pubkey:owned.Wallet.utxo.Utxo.script_pubkey
                 ~script_sig:input.Types.script_sig
                 ~witness:{ Types.items = bad_items }
                 ~amount:owned.Wallet.utxo.Utxo.value
                 ~flags:standard_flags () with
         | Ok true ->
           Alcotest.fail
             "success-sign-own: tampered sig must FAIL verify_script"
         | Ok false | Error _ -> ()))

(* ============================================================================
   fill-only-not-complete: sign=false -> complete=false, no hex
   ============================================================================ *)

let test_fill_only_not_complete () =
  with_ctx (fun ctx w ->
      let owned = fund_p2wpkh w in
      let b64 = unsigned_psbt_spending owned in
      match Rpc.dispatch_rpc ctx "walletprocesspsbt"
              [`String b64; `Bool false] with
      | Error (c, m) ->
        Alcotest.failf "fill-only-not-complete: error (%d) %s" c m
      | Ok j ->
        let fs = assoc_of j in
        (match List.assoc_opt "complete" fs with
         | Some (`Bool false) -> ()
         | Some v ->
           Alcotest.failf "fill-only-not-complete: complete=%s, want false"
             (Yojson.Safe.to_string v)
         | None -> Alcotest.fail "fill-only-not-complete: missing complete");
        Alcotest.(check bool) "fill-only-not-complete: no hex"
          false (List.mem_assoc "hex" fs))

(* ============================================================================
   decode-error: "not-a-psbt" -> -22  (spend.cpp:1614)
   ============================================================================ *)

let test_decode_error () =
  with_ctx (fun ctx _w ->
      check_err ~label:"decode-error"
        ~code:(-22)
        (Rpc.dispatch_rpc ctx "walletprocesspsbt"
           [`String "not-a-psbt"]))

(* ============================================================================
   foreign input: a UTXO the wallet does not own cannot be signed.
   ============================================================================ *)

let test_foreign_input_not_complete () =
  with_ctx (fun ctx w ->
      let _ours = fund_p2wpkh w in
      let foreign_txid = Cstruct.create 32 in
      Cstruct.set_uint8 foreign_txid 0 0xee;
      let foreign : Wallet.wallet_utxo =
        { Wallet.outpoint = { Types.txid = foreign_txid; vout = 3l };
          utxo = { Utxo.value = 100_000L;
                   script_pubkey = dest_spk ();
                   height = 50; is_coinbase = false };
          key_index = -1; confirmed = true; watch_only = false }
      in
      let b64 = unsigned_psbt_spending foreign in
      match Rpc.dispatch_rpc ctx "walletprocesspsbt" [`String b64] with
      | Error (c, m) ->
        Alcotest.failf "foreign-input: error (%d) %s" c m
      | Ok j ->
        let fs = assoc_of j in
        (match List.assoc_opt "complete" fs with
         | Some (`Bool false) -> ()
         | Some v ->
           Alcotest.failf "foreign-input: complete=%s, want false"
             (Yojson.Safe.to_string v)
         | None -> Alcotest.fail "foreign-input: missing complete");
        Alcotest.(check bool) "foreign-input: no hex"
          false (List.mem_assoc "hex" fs))

(* ============================================================================
   help-parity
   ============================================================================ *)

let test_help_lists_walletprocesspsbt () =
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
              if tok = "walletprocesspsbt" then found := true)
          (String.split_on_char '\n' s);
        Alcotest.(check bool) "help lists walletprocesspsbt" true !found
      | Ok j ->
        Alcotest.failf "help: expected string, got %s"
          (Yojson.Safe.to_string j))

let () =
  let open Alcotest in
  run "R5 walletprocesspsbt (Core probe vectors)" [
    "walletprocesspsbt", [
      test_case "success-sign-own (unsigned PSBT, wallet fills UTXO)"
        `Quick test_success_sign_own;
      test_case "fill-only-not-complete (sign=false)"
        `Quick test_fill_only_not_complete;
      test_case "decode-error -> -22" `Quick test_decode_error;
      test_case "foreign input -> complete=false"
        `Quick test_foreign_input_not_complete;
    ];
    "help", [
      test_case "lists walletprocesspsbt"
        `Quick test_help_lists_walletprocesspsbt;
    ];
  ]
