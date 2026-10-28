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

let with_mempool_utxo f =
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
    (fun () -> f mp utxo)

let with_mempool f = with_mempool_utxo (fun mp _ -> f mp)

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

(* warden_e / seed_warden_e: a confirmed parent's 64 outputs are spent by 64
   in-pool children, then invalidateblock returns the parent.  Core's refill
   puts all 65 in one cluster, trims the cheapest child (child 0) to the
   64-transaction limit, and is left with one 64-transaction cluster.  It
   chunks that cluster's linearization (parent, then the children by
   descending feerate) with ChunkLinearization, so the parent absorbs every
   child whose feerate beats the chunk so far: 30 chunks for warden_e's fees
   and 19 for seed_warden_e's, each one m_main_chunkindex node.
   txns_randomized grew to 128 at 65 entries and does not shrink at 64. *)
let fan_out ~parent_outs ~parent_fee ~child_fee ~script ~script_sig ~wit k =
  with_mempool_utxo (fun mp utxo ->
    let with_sig t =
      { t with Types.inputs =
          List.map (fun i -> { i with Types.script_sig }) t.Types.inputs } in
    let parent_tx =
      with_sig (tx ~ins:[ (coin 0, 0) ]
                  ~outs:(List.map (fun v -> (v, script)) parent_outs) ~wit) in
    assert (Int64.add (List.fold_left Int64.add 0L parent_outs) parent_fee = coin_value);
    let ptxid = Crypto.compute_txid parent_tx in
    (* the parent is confirmed: its outputs are coins *)
    List.iteri (fun i value ->
      Utxo.UtxoSet.add utxo ptxid i
        Utxo.{ value; script_pubkey = script; height = 2; is_coinbase = false })
      parent_outs;
    let children = List.init 64 (fun i ->
      with_sig (tx ~ins:[ (ptxid, i) ]
                  ~outs:[ (Int64.sub (List.nth parent_outs i) (child_fee i), script) ]
                  ~wit)) in
    List.iter (add mp) children;
    (* invalidateblock: the parent's coins go away and it is re-accepted *)
    List.iteri (fun i _ -> ignore (Utxo.UtxoSet.remove utxo ptxid i)) parent_outs;
    let readded =
      Mempool.update_for_reorg mp ~disconnected:[ parent_tx ] ~dropped:[] in
    Alcotest.(check int) "parent re-accepted" 1 readded;
    Alcotest.(check int) "pool size" 64 (Hashtbl.length mp.Mempool.entries);
    Alcotest.(check bool) "parent in pool" true (Mempool.contains mp ptxid);
    Alcotest.(check bool) "child 0 trimmed" false
      (Mempool.contains mp (Crypto.compute_txid (List.hd children)));
    k mp)

(* row warden_e/e-invalidate/info:usage: P2WPKH parent into 64 P2WPKH
   outputs, fee 10000; child i pays (i + 1) * 1000 *)
let test_warden_e () =
  let spendable = Int64.sub coin_value 10_000L in
  let each = Int64.div spendable 64L in
  let rem = Int64.sub spendable (Int64.mul each 64L) in
  let outs = List.init 64 (fun i -> if i = 0 then Int64.add each rem else each) in
  fan_out ~parent_outs:outs ~parent_fee:10_000L
    ~child_fee:(fun i -> Int64.of_int ((i + 1) * 1000))
    ~script:p2wpkh ~script_sig:Cstruct.empty ~wit:wpkh_witness
    (usage "64-tx fan-out cluster, 30 chunks" 75_288)

(* row seed_warden_e/invalidate/info:usage: P2SH(OP_TRUE) parent into 64
   outputs of 200000 plus change, fee 10000; child i pays 5000 + 200 * i *)
let test_seed_warden_e () =
  let p2sh = Cstruct.of_string ("\xa9\x14" ^ String.make 20 '\x33' ^ "\x87") in
  let change = Int64.sub coin_value (Int64.of_int ((64 * 200_000) + 10_000)) in
  let outs = List.init 64 (fun _ -> 200_000L) @ [ change ] in
  fan_out ~parent_outs:outs ~parent_fee:10_000L
    ~child_fee:(fun i -> Int64.of_int (5_000 + (i * 200)))
    ~script:p2sh ~script_sig:(Cstruct.of_string "\x01\x51")
    ~wit:(fun () -> Types.{ items = [] })
    (usage "64-tx P2SH fan-out cluster, 19 chunks" 60_296)

let () =
  Alcotest.run "mempool_usage_core" [
    "usage", [
      Alcotest.test_case "tip100 spend matches Core" `Quick test_tip100;
      Alcotest.test_case "2-in 2-out matches Core" `Quick test_2in2out;
      Alcotest.test_case "heavy drop spend matches Core" `Quick test_heavy;
      Alcotest.test_case "parent/child cluster matches Core" `Quick test_chain;
      Alcotest.test_case "drained pool matches Core" `Quick test_drained;
      Alcotest.test_case "pressure pool matches Core" `Quick test_pressure;
      Alcotest.test_case "warden_e fan-out cluster matches Core" `Quick test_warden_e;
      Alcotest.test_case "seed_warden_e fan-out cluster matches Core" `Quick test_seed_warden_e;
    ]
  ]
