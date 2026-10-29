(* -fallbackfee: sendtoaddress / send must not sign at a hardcoded rate.

   Core wallet/fees.cpp GetMinimumFeeRate: estimator answer for conf_target,
   else -fallbackfee, else (wallet/spend.cpp CreateTransactionInternal) the
   spend fails with "Fee estimation failed. Fallbackfee is disabled. Wait a
   few blocks or enable -fallbackfee."; SendMoney (sendtoaddress) maps every
   such failure to RPC_WALLET_INSUFFICIENT_FUNDS (-6), while the send RPC
   (wallet/rpc/spend.cpp) throws RPC_WALLET_ERROR (-4) itself.  A non-zero
   estimate or fallback is raised to the mempool minimum fee, then to the
   required fee (max of -mintxfee 1 sat/vB and the relay minimum).  -fallbackfee
   is parsed by ParseMoney (util/moneystr.cpp).  camlcoin used a literal
   1.0 sat/vB. *)

open Camlcoin

let dest_addr = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"

let core_msg =
  "Fee estimation failed. Fallbackfee is disabled. \
   Wait a few blocks or enable -fallbackfee."

let dummy_tip (height : int) : Sync.header_entry =
  { header = { version = 1l; prev_block = Types.zero_hash;
               merkle_root = Types.zero_hash; timestamp = 0l;
               bits = 0l; nonce = 0l };
    hash = Types.zero_hash; height; total_work = Cstruct.create 32 }

let with_ctx f =
  Test_tmp.with_chaindb (fun db ->
      let utxo = Utxo.UtxoSet.create db in
      let mp = Mempool.create ~network:Consensus.regtest
          ~require_standard:false ~verify_scripts:false ~utxo
          ~current_height:6 () in
      let chain = Sync.create_chain_state db Consensus.regtest in
      chain.tip <- Some (dummy_tip 6);
      let wallet = Wallet.create ~network:`Regtest ~db_path:"" in
      let ctx : Rpc.rpc_context = {
        chain; mempool = mp;
        peer_manager = Peer_manager.create Consensus.regtest;
        wallet = Some wallet; wallet_manager = None;
        fee_estimator = Fee_estimation.create ();
        network = Consensus.regtest; filter_index = None; utxo = None;
        data_dir = None; snapshot_activation = None;
      } in
      let kp = Wallet.generate_key wallet in
      let script =
        Wallet.build_p2wpkh_script (Crypto.hash160 kp.Wallet.public_key) in
      let txid = Cstruct.create 32 in
      Cstruct.set_uint8 txid 0 1;
      let entry = { Utxo.value = 250_000_000L; script_pubkey = script;
                    height = 1; is_coinbase = false } in
      Utxo.UtxoSet.add utxo txid 0 entry;
      wallet.utxos <-
        [{ Wallet.outpoint = { Types.txid; vout = 0l }; utxo = entry;
           key_index = 0; confirmed = true; watch_only = false }];
      f ctx)

let with_fallback v f =
  let saved = !Fee_estimation.fallback_fee_sat_per_vb in
  Fee_estimation.fallback_fee_sat_per_vb := v;
  Fun.protect ~finally:(fun () ->
      Fee_estimation.fallback_fee_sat_per_vb := saved) f

let check_fee_err ?(code = -6) label = function
  | Error (c, m) ->
    Alcotest.(check int) (label ^ ": code") code c;
    Alcotest.(check string) (label ^ ": message") core_msg m
  | Ok j ->
    Alcotest.failf "%s: spent with no estimate and no -fallbackfee: %s"
      label (Yojson.Safe.to_string j)

let test_default_is_disabled () =
  Alcotest.(check (float 0.0)) "default fallback" 0.0
    !Fee_estimation.fallback_fee_sat_per_vb

let test_sendtoaddress_without_fallbackfee () =
  with_fallback 0.0 (fun () ->
      with_ctx (fun ctx ->
          check_fee_err "sendtoaddress"
            (Rpc.dispatch_rpc ctx "sendtoaddress"
               [`String dest_addr; `Float 0.5]);
          Alcotest.(check int) "nothing in mempool" 0
            (Hashtbl.length ctx.mempool.Mempool.entries)))

let test_send_without_fallbackfee () =
  with_fallback 0.0 (fun () ->
      with_ctx (fun ctx ->
          check_fee_err ~code:(-4) "send"
            (Rpc.dispatch_rpc ctx "send"
               [`List [`Assoc [(dest_addr, `Float 0.5)]]]);
          (* an explicit fee_rate never consults the fallback *)
          match Rpc.dispatch_rpc ctx "send"
                  [`List [`Assoc [(dest_addr, `Float 0.5)]];
                   `Null; `Null; `Int 10] with
          | Ok _ -> ()
          | Error (c, m) -> Alcotest.failf "send fee_rate=10: (%d) %s" c m))

let test_sendtoaddress_pays_fallbackfee () =
  with_fallback 20.0 (fun () ->
      with_ctx (fun ctx ->
          match Rpc.dispatch_rpc ctx "sendtoaddress"
                  [`String dest_addr; `Float 0.5] with
          | Error (c, m) -> Alcotest.failf "sendtoaddress: (%d) %s" c m
          | Ok _ ->
            let fees = Hashtbl.fold (fun _ (e : Mempool.mempool_entry) acc ->
                (Int64.to_float e.fee /. (float_of_int e.weight /. 4.0)) :: acc)
                ctx.mempool.Mempool.entries [] in
            match fees with
            | [r] ->
              if r < 19.5 || r > 25.0 then
                Alcotest.failf "fee rate %.2f sat/vB, want ~20" r
            | l -> Alcotest.failf "want 1 mempool entry, got %d"
                     (List.length l)))

(* Fee rate (sat/vB) of the single mempool entry. *)
let only_mempool_rate (ctx : Rpc.rpc_context) =
  let fees = Hashtbl.fold (fun _ (e : Mempool.mempool_entry) acc ->
      (Int64.to_float e.fee /. (float_of_int e.weight /. 4.0)) :: acc)
      ctx.mempool.Mempool.entries [] in
  match fees with
  | [r] -> r
  | l -> Alcotest.failf "want 1 mempool entry, got %d" (List.length l)

let send_rate (ctx : Rpc.rpc_context) meth =
  let params = match meth with
    | "send" -> [`List [`Assoc [(dest_addr, `Float 0.5)]]]
    | _ -> [`String dest_addr; `Float 0.5] in
  match Rpc.dispatch_rpc ctx meth params with
  | Error (c, m) -> Alcotest.failf "%s: (%d) %s" meth c m
  | Ok _ -> only_mempool_rate ctx

let check_rate label ~lo ~hi r =
  if r < lo || r > hi then
    Alcotest.failf "%s: fee rate %.3f sat/vB, want in [%.2f, %.2f]"
      label r lo hi

(* Core: "Obey mempool min fee when using smart fee estimation" — a
   fallback below the mempool minimum is raised to it. *)
let test_mempool_min_fee_wins () =
  List.iter (fun meth ->
      with_fallback 2.0 (fun () ->
          with_ctx (fun ctx ->
              ctx.mempool.Mempool.rolling_min_fee_rate <- 5000.0;
              ctx.mempool.Mempool.block_since_last_rolling_fee_bump <- false;
              check_rate meth ~lo:4.9 ~hi:6.5 (send_rate ctx meth))))
    ["sendtoaddress"; "send"]

(* Required fee: max(-mintxfee 1000 sat/kvB, relay min) raises a small
   fallback; it is a floor, not a clamp of larger rates. *)
let test_required_fee_floor () =
  with_fallback 0.2 (fun () ->
      with_ctx (fun ctx ->
          check_rate "fallback 0.2" ~lo:0.98 ~hi:1.3
            (send_rate ctx "sendtoaddress")));
  with_fallback 3.0 (fun () ->
      with_ctx (fun ctx ->
          check_rate "fallback 3" ~lo:2.95 ~hi:3.9
            (send_rate ctx "sendtoaddress")))

(* A disabled (0) fallback still fails; the mempool minimum is not used. *)
let test_zero_fallback_not_raised () =
  with_fallback 0.0 (fun () ->
      with_ctx (fun ctx ->
          ctx.mempool.Mempool.rolling_min_fee_rate <- 5000.0;
          ctx.mempool.Mempool.block_since_last_rolling_fee_bump <- false;
          check_fee_err "sendtoaddress"
            (Rpc.dispatch_rpc ctx "sendtoaddress"
               [`String dest_addr; `Float 0.5]);
          check_fee_err ~code:(-4) "send"
            (Rpc.dispatch_rpc ctx "send"
               [`List [`Assoc [(dest_addr, `Float 0.5)]]])))

(* -fallbackfee is parsed like Core ParseMoney (util/moneystr.cpp). *)
let invalid_msg raw =
  Printf.sprintf "Invalid amount for -fallbackfee=<amount>: '%s'" raw

let test_parse_valid () =
  List.iter (fun (raw, want) ->
      match Fee_estimation.parse_fallbackfee raw with
      | Ok (v, _) -> Alcotest.(check int64) ("value of " ^ raw) want v
      | Error e -> Alcotest.failf "%S rejected: %s" raw e)
    [ ("0.0002", 20_000L); ("  0.0002\t", 20_000L); ("0", 0L);
      ("1.", 100_000_000L); (".5", 50_000_000L);
      ("21000000", 2_100_000_000_000_000L);
      ("0.00000001", 1L) ]

let test_parse_invalid () =
  List.iter (fun raw ->
      match Fee_estimation.parse_fallbackfee raw with
      | Ok (v, _) -> Alcotest.failf "%S accepted as %Ld" raw v
      | Error e -> Alcotest.(check string) ("error for " ^ raw)
                     (invalid_msg raw) e)
    [ ""; "   "; "-0.0002"; "+0.0002"; "0. 0002"; "0 .1"; "abc"; "0.0002x";
      "1e-4"; "0.000000001"; "21000000.00000001"; "99999999";
      "1.2.3"; "0x10" ]

let test_parse_high_warns () =
  (match Fee_estimation.parse_fallbackfee "0.02" with
   | Ok (v, Some w) ->
     Alcotest.(check int64) "stored" 2_000_000L v;
     Alcotest.(check string) "warning"
       "-fallbackfee is set very high! This is the transaction fee you may \
        pay when fee estimates are not available." w
   | Ok (_, None) -> Alcotest.fail "0.02 BTC/kvB: no high-fee warning"
   | Error e -> Alcotest.failf "0.02 rejected: %s" e);
  (match Fee_estimation.parse_fallbackfee "0.01" with
   | Ok (_, None) -> ()
   | Ok (_, Some w) -> Alcotest.failf "0.01 (= HIGH_TX_FEE_PER_KB) warned: %s" w
   | Error e -> Alcotest.failf "0.01 rejected: %s" e)

let () =
  Alcotest.run "fallbackfee" [
    "fallbackfee", [
      Alcotest.test_case "default disabled" `Quick test_default_is_disabled;
      Alcotest.test_case "sendtoaddress without fallbackfee -> -6" `Quick
        test_sendtoaddress_without_fallbackfee;
      Alcotest.test_case "send without fallbackfee -> -4" `Quick
        test_send_without_fallbackfee;
      Alcotest.test_case "sendtoaddress pays fallbackfee" `Quick
        test_sendtoaddress_pays_fallbackfee;
      Alcotest.test_case "mempool min fee wins over fallback" `Quick
        test_mempool_min_fee_wins;
      Alcotest.test_case "required fee is a floor, not a clamp" `Quick
        test_required_fee_floor;
      Alcotest.test_case "zero fallback still fails" `Quick
        test_zero_fallback_not_raised;
      Alcotest.test_case "parse valid amounts" `Quick test_parse_valid;
      Alcotest.test_case "parse rejects like ParseMoney" `Quick
        test_parse_invalid;
      Alcotest.test_case "parse high amount warns" `Quick
        test_parse_high_warns;
    ]]
