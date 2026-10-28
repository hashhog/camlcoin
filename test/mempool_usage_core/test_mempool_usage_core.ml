(* getmempoolinfo "usage" must equal Core v31.1 CTxMemPool::DynamicMemoryUsage()
   (txmempool.cpp:778) for the pools the core-regtest harness builds.

   Every expected value below is the number Core v31.1 itself returned in the
   warden_invalidated_submit scenario (tools/core-regtest, rows
   warden_invalidated_submit/{maturity,usage,pressure}/...:usage and their
   /rest/mempool/info twins).  The transactions here have the same shape as
   the harness's: the same input/output counts, witness item sizes and
   scriptPubKey lengths, which is all DynamicMemoryUsage depends on. *)

open Camlcoin

let test_db_path = Test_tmp.register "/tmp/camlcoin_test_mempool_usage_core_db"

let rec rm_rf path =
  if Sys.file_exists path then begin
    if Sys.is_directory path then begin
      Array.iter (fun f -> rm_rf (Filename.concat path f)) (Sys.readdir path);
      Unix.rmdir path
    end else Unix.unlink path
  end

let coin_value = 5_000_000_000L
let coin i = Crypto.sha256 (Cstruct.of_string (Printf.sprintf "usage-coin-%d" i))
let n_coins = 12_000

let bytes n c = Cstruct.of_string (String.make n c)
let p2wpkh = Cstruct.of_string ("\x00\x14" ^ String.make 20 '\x11')   (* 22 bytes *)
let p2wsh = Cstruct.of_string ("\x00\x20" ^ String.make 32 '\x22')    (* 34 bytes *)

let input txid vout =
  Types.{ previous_output = { txid; vout = Int32.of_int vout };
          script_sig = Cstruct.empty; sequence = 0xFFFFFFFDl }

(* P2WPKH spend witness: a 71-byte signature and a 33-byte pubkey. *)
let wpkh_witness () = Types.{ items = [ bytes 71 's'; bytes 33 'p' ] }

(* P2WSH(OP_DROP OP_TRUE OP_DROP) spend witness: 80, 80 and the 3-byte script. *)
let drop_witness () =
  Types.{ items = [ bytes 80 'a'; bytes 80 'b'; Cstruct.of_string "\x75\x51\x75" ] }

let tx ~ins ~outs ~wit =
  Types.{ version = 2l;
          inputs = List.map (fun (t, v) -> input t v) ins;
          outputs = List.map (fun (value, script_pubkey) -> { value; script_pubkey }) outs;
          witnesses = List.map (fun _ -> wit ()) ins;
          locktime = 0l }

let with_mempool f =
  rm_rf test_db_path;
  let db = Storage.ChainDB.create test_db_path in
  let utxo = Utxo.UtxoSet.create db in
  for i = 0 to n_coins - 1 do
    Utxo.UtxoSet.add utxo (coin i) 0
      Utxo.{ value = coin_value; script_pubkey = p2wpkh; height = 1;
             is_coinbase = false }
  done;
  let mp = Mempool.create ~network:Consensus.regtest ~require_standard:false
             ~verify_scripts:false ~utxo ~current_height:200 () in
  Fun.protect ~finally:(fun () -> Storage.ChainDB.close db; rm_rf test_db_path)
    (fun () -> f mp)

let add mp t =
  match Mempool.add_transaction mp t with
  | Ok _ -> ()
  | Error e -> Alcotest.failf "setup: tx rejected: %s" e

let usage name want mp =
  Alcotest.(check int) name want (Mempool.get_usage mp)

(* rows .../maturity/tip100-info:usage and rest/tip100-info:usage *)
let test_tip100 () =
  with_mempool (fun mp ->
    add mp (tx ~ins:[ (coin 0, 0) ] ~outs:[ (4_999_000_000L, p2wpkh) ] ~wit:wpkh_witness);
    usage "1-in 1-out P2WPKH spend" 1176 mp)

(* rows usage/usage-2in2out:usage and rest/usage-2in2out-info:usage; the
   34-byte P2WSH output fits Core's 36-byte inline prevector *)
let test_2in2out () =
  with_mempool (fun mp ->
    add mp (tx ~ins:[ (coin 0, 0); (coin 1, 0) ]
              ~outs:[ (4_999_950_000L, p2wpkh); (4_999_950_000L, p2wsh) ]
              ~wit:wpkh_witness);
    usage "2-in 2-out" 1624 mp)

(* row usage/usage-heavy:usage *)
let test_heavy () =
  with_mempool (fun mp ->
    add mp (tx ~ins:[ (coin 0, 0) ] ~outs:[ (4_999_800_000L, p2wpkh) ] ~wit:drop_witness);
    usage "1-in P2WSH drop spend" 1272 mp)

let parent () =
  tx ~ins:[ (coin 0, 0) ] ~outs:[ (4_999_800_000L, p2wpkh) ] ~wit:wpkh_witness

let child () =
  tx ~ins:[ (Crypto.compute_txid (parent ()), 0) ] ~outs:[ (4_999_700_000L, p2wsh) ]
    ~wit:wpkh_witness

(* rows usage/usage-chain:usage and rest/usage-chain-info:usage: a parent and
   child form one two-transaction cluster (GenericClusterImpl) of two chunks *)
let test_chain () =
  with_mempool (fun mp ->
    add mp (parent ());
    add mp (child ());
    usage "parent + child cluster" 2456 mp)

(* row usage/usage-drained:usage: txns_randomized keeps its capacity when the
   last transaction leaves (txmempool.cpp:298 clear()) *)
let test_drained () =
  with_mempool (fun mp ->
    usage "empty pool" 0 mp;
    let t = parent () in
    add mp t;
    Mempool.remove_transaction mp (Crypto.compute_txid t);
    usage "drained pool" 64 mp)

(* rows pressure/info:usage and rest/pressure-info:usage: the parent/child
   cluster, then 14 800-input drop spends of which 2 leave again; the
   txns_randomized vector grew to 16 and does not shrink at 14 *)
let test_pressure () =
  with_mempool (fun mp ->
    add mp (parent ());
    add mp (child ());
    let heavy k =
      tx ~ins:(List.init 800 (fun i -> (coin (1 + (k * 800) + i), 0)))
        ~outs:[ (Int64.sub (Int64.mul 800L coin_value) 100_000L, p2wpkh) ]
        ~wit:drop_witness in
    let txs = List.init 14 heavy in
    List.iter (add mp) txs;
    List.iter (fun t -> Mempool.remove_transaction mp (Crypto.compute_txid t))
      [ List.nth txs 0; List.nth txs 1 ];
    Alcotest.(check int) "pool size" 14 (Hashtbl.length mp.Mempool.entries);
    usage "12 heavy + cluster" 4_773_160 mp)

let () =
  Alcotest.run "mempool_usage_core" [
    "usage", [
      Alcotest.test_case "tip100 spend matches Core" `Quick test_tip100;
      Alcotest.test_case "2-in 2-out matches Core" `Quick test_2in2out;
      Alcotest.test_case "heavy drop spend matches Core" `Quick test_heavy;
      Alcotest.test_case "parent/child cluster matches Core" `Quick test_chain;
      Alcotest.test_case "drained pool matches Core" `Quick test_drained;
      Alcotest.test_case "pressure pool matches Core" `Quick test_pressure;
    ]
  ]
