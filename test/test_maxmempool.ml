(* -maxmempool: the mempool size limit is configurable and enforced.

   Core: init.cpp sets max_size_bytes = -maxmempool (MB, SI) * 1_000_000;
   CTxMemPool::TrimToSize (txmempool.cpp) evicts the lowest-feerate chunks
   once usage passes it and raises the rolling minimum fee (GetMinFee).
   Before this, camlcoin hard-coded 300 MB, so the core-regtest adapter could
   not give it Core's -maxmempool=5 and the pressure rows never evicted. *)

open Camlcoin

let test_db_path = Test_tmp.register "/tmp/camlcoin_test_maxmempool_db"

let rec rm_rf path =
  if Sys.file_exists path then begin
    if Sys.is_directory path then begin
      Array.iter (fun f -> rm_rf (Filename.concat path f)) (Sys.readdir path);
      Unix.rmdir path
    end else Unix.unlink path
  end

let n_coins = 40
let spk = Cstruct.of_string "\x76\xa9\x14test_script_pubkey\x88\xac"
let fat_spk = Cstruct.of_string ("\x6a" ^ String.make 40_000 'x')
let coin i = Crypto.sha256 (Cstruct.of_string (Printf.sprintf "maxmempool-coin-%d" i))

(* Tx i spends coin i and pays a fee that rises 15% per step, so tx 0 is the
   lowest-feerate and the first to go, and each newcomer clears the rolling
   floor raised by the evictions before it. *)
let tx_of i =
  let fee = Int64.of_float (100_000. *. (1.15 ** float_of_int i)) in
  Types.{ version = 2l;
          inputs = [{ previous_output = { txid = coin i; vout = 0l };
                      script_sig = Cstruct.of_string "\x00";
                      sequence = 0xFFFFFFFFl }];
          outputs = [{ value = Int64.sub 10_000_000_000L fee; script_pubkey = fat_spk }];
          witnesses = []; locktime = 0l }

let with_mempool ?max_size_mb f =
  rm_rf test_db_path;
  let db = Storage.ChainDB.create test_db_path in
  let utxo = Utxo.UtxoSet.create db in
  for i = 0 to n_coins - 1 do
    Utxo.UtxoSet.add utxo (coin i) 0
      Utxo.{ value = 10_000_000_000L; script_pubkey = spk; height = 1;
             is_coinbase = false }
  done;
  let mp = match max_size_mb with
    | Some m -> Mempool.create ~network:Consensus.regtest ~require_standard:false
                  ~verify_scripts:false ~utxo ~current_height:200 ~max_size_mb:m ()
    | None -> Mempool.create ~network:Consensus.regtest ~require_standard:false
                ~verify_scripts:false ~utxo ~current_height:200 () in
  Fun.protect ~finally:(fun () -> Storage.ChainDB.close db; rm_rf test_db_path)
    (fun () -> f mp)

let fill mp =
  for i = 0 to n_coins - 1 do
    match Mempool.add_transaction mp (tx_of i) with
    | Ok _ -> ()
    | Error e ->
      Alcotest.failf "tx %d rejected: %s (min fee %Ld sat/kvB, weight %d)" i e
        (Mempool.effective_min_fee mp) mp.Mempool.total_usage
  done

let has mp i =
  Hashtbl.mem mp.Mempool.entries
    (Cstruct.to_string (Crypto.compute_txid (tx_of i)))

let test_limit_is_configurable () =
  with_mempool ~max_size_mb:5 (fun mp ->
    Alcotest.(check int) "5 MB -> 5_000_000" 5_000_000 mp.Mempool.max_size_bytes);
  with_mempool (fun mp ->
    Alcotest.(check int) "default stays 300 MB" 300_000_000
      mp.Mempool.max_size_bytes);
  Alcotest.(check int) "Cli default_config" 300 Cli.default_config.maxmempool_mb

(* Core v31.1 getmempoolinfo "usage" for the core-regtest P2WSH-drop spend
   (witness items 80, 80, 3 bytes; one 22-byte output): 1272 with 1 input,
   397512 with 800. *)
let drop_spend n_in =
  Types.{ version = 2l;
          inputs = List.init n_in (fun i ->
            { previous_output = { txid = coin i; vout = 0l };
              script_sig = Cstruct.empty; sequence = 0xFFFFFFFDl });
          outputs = [{ value = 1L; script_pubkey = Cstruct.of_string (String.make 22 'a') }];
          witnesses = List.init n_in (fun _ ->
            { items = [ Cstruct.of_string (String.make 80 'a');
                        Cstruct.of_string (String.make 80 'b');
                        Cstruct.of_string "uQu" ] });
          locktime = 0l }

let test_usage_matches_core () =
  let close name want got tol =
    Alcotest.(check bool) (Printf.sprintf "%s: want %d got %d" name want got)
      true (abs (want - got) <= tol) in
  close "1 input" 1272 (Mempool.tx_dynamic_usage (drop_spend 1)) 5;
  close "800 inputs" 397_512 (Mempool.tx_dynamic_usage (drop_spend 800)) 100

let test_eviction_at_limit () =
  with_mempool ~max_size_mb:1 (fun mp ->
    fill mp;
    Alcotest.(check bool) "pool within the limit" true
      (mp.Mempool.total_usage <= mp.Mempool.max_size_bytes);
    Alcotest.(check bool) "lowest-feerate tx evicted" false (has mp 0);
    Alcotest.(check bool) "highest-feerate tx kept" true (has mp (n_coins - 1));
    Alcotest.(check bool) "rolling min fee above the relay floor" true
      (Int64.compare (Mempool.effective_min_fee mp) mp.Mempool.min_relay_fee > 0);
    (* Core TrimToSize: floor = evicted chunk feerate (sat/kvB) + incremental
       relay fee (100).  The highest evicted tx sets it. *)
    let last_evicted =
      List.fold_left (fun acc i -> if has mp i then acc else i) (-1)
        (List.init n_coins Fun.id) in
    let tx = tx_of last_evicted in
    let fee = Int64.sub 10_000_000_000L (List.hd tx.Types.outputs).Types.value in
    let vsize = (Validation.compute_tx_weight tx + 3) / 4 in
    let want = Int64.to_float fee *. 1000.0 /. float_of_int vsize +. 100.0 in
    Alcotest.(check bool)
      (Printf.sprintf "floor is evicted sat/kvB + 100 (want %.0f got %Ld)" want
         (Mempool.effective_min_fee mp))
      true (abs_float (Int64.to_float (Mempool.effective_min_fee mp) -. want) <= 1.0))

let test_no_eviction_at_default () =
  with_mempool (fun mp ->
    fill mp;
    Alcotest.(check bool) "CONTROL: tx 0 kept at 300 MB" true (has mp 0);
    Alcotest.(check bool) "CONTROL: last tx kept" true (has mp (n_coins - 1));
    Alcotest.(check int64) "CONTROL: floor stays at relay fee"
      mp.Mempool.min_relay_fee (Mempool.effective_min_fee mp))

let () =
  Alcotest.run "maxmempool" [
    "maxmempool", [
      Alcotest.test_case "limit is configurable" `Quick test_limit_is_configurable;
      Alcotest.test_case "usage estimate matches Core" `Quick test_usage_matches_core;
      Alcotest.test_case "evicts lowest feerate past the limit" `Quick
        test_eviction_at_limit;
      Alcotest.test_case "CONTROL no eviction at default size" `Quick
        test_no_eviction_at_default;
    ];
  ]
