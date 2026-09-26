(* gettxoutsetinfo.transactions: exact count, bounded memory.

   Core (kernel/coinstats.cpp ComputeUTXOStats) counts a transaction each
   time the cursor's key.hash differs from prevkey — the cursor is in
   outpoint order, so a txid's outputs are contiguous and no set of txids
   is ever held.  camlcoin kept a Hashtbl of 64-char hex keys for every
   txid for the whole scan: ~10^8 live strings on mainnet, >10 GB of
   OCaml heap on the Lwt main thread of a unit capped at 48G.

   (1) correctness across the committed overlay (disk CF + dirty), with
       multi-output txids split between disk and dirty;
   (2) the scan must not retain per-txid state: words promoted to the
       major heap over a 200k-txid scan stay far below what one retained
       key per txid costs.  Negative control: restoring the Hashtbl makes
       (2) fail (see the commit message for the measured figure).

   Command:
     dune exec --no-buffer test/test_gettxoutsetinfo_transactions.exe
*)

open Camlcoin

let p2pkh tag =
  let script = Cstruct.create 25 in
  Cstruct.set_uint8 script 0 0x76;
  Cstruct.set_uint8 script 1 0xa9;
  Cstruct.set_uint8 script 2 0x14;
  Cstruct.set_uint8 script 3 (tag land 0xff);
  Cstruct.set_uint8 script 23 0x88;
  Cstruct.set_uint8 script 24 0xac;
  script

let entry ~tag ~value ~height : Utxo.utxo_entry =
  { value; script_pubkey = p2pkh tag; height; is_coinbase = false }

let txid_of_int n =
  let buf = Cstruct.create 32 in
  Cstruct.BE.set_uint32 buf 0 (Int32.of_int n);
  Cstruct.set_uint8 buf 31 0x5a;
  buf

let make_ctx db ~utxo =
  let legacy = Utxo.UtxoSet.create db in
  let mp =
    Mempool.create ~network:Consensus.regtest ~require_standard:false
      ~verify_scripts:false ~utxo:legacy ~current_height:100 ()
  in
  let chain = Sync.create_chain_state db Consensus.mainnet in
  let pm = Peer_manager.create Consensus.mainnet in
  let fe = Fee_estimation.create () in
  Rpc.create_context ~chain ~mempool:mp ~peer_manager:pm ~wallet:None
    ~fee_estimator:fe ~network:Consensus.mainnet ~utxo ()

let setinfo ctx =
  match Rpc.handle_gettxoutsetinfo ctx [`String "none"] with
  | Error msg -> Alcotest.fail ("gettxoutsetinfo: " ^ msg)
  | Ok (`Assoc fields) -> fields
  | Ok _ -> Alcotest.fail "gettxoutsetinfo: expected object"

let field_int fields name =
  match List.assoc_opt name fields with
  | Some (`Int n) -> n
  | _ -> Alcotest.fail ("missing int field " ^ name)

let with_db name f =
  Test_tmp.with_dir ~label:name ~mkdir:true (fun root ->
    let path = Filename.concat root "chain" in
    Unix.mkdir path 0o755;
    let db = Storage.ChainDB.create path in
    Fun.protect
      ~finally:(fun () -> Storage.ChainDB.close db)
      (fun () -> f db))

(* Disk: A:0 A:1 C:0.  Dirty: +A:2 +B:0 +B:1 -C:0 +D:5.
   Committed: A:{0,1,2} B:{0,1} D:{5} -> txouts 6, transactions 3. *)
let test_overlay_counts () =
  with_db "txcount-overlay" (fun db ->
    let a = txid_of_int 1 and b = txid_of_int 2
    and c = txid_of_int 3 and d = txid_of_int 4 in
    let cache = Utxo.OptimizedUtxoSet.create db in
    let add t v tag = Utxo.OptimizedUtxoSet.add cache t v
        (entry ~tag ~value:1000L ~height:5) in
    add a 0 1; add a 1 2; add c 0 3;
    Utxo.OptimizedUtxoSet.flush cache;
    add a 2 4; add b 0 5; add b 1 6; add d 5 7;
    ignore (Utxo.OptimizedUtxoSet.remove cache c 0);
    let info = setinfo (make_ctx db ~utxo:(Some cache)) in
    let txouts = field_int info "txouts" in
    let txs = field_int info "transactions" in
    Printf.printf "overlay: txouts=%d transactions=%d\n%!" txouts txs;
    Alcotest.(check int) "txouts" 6 txouts;
    Alcotest.(check int) "transactions (distinct txids)" 3 txs)

let n_big = 200_000

let test_scan_retains_no_per_txid_state () =
  with_db "txcount-mem" (fun db ->
    let cache = Utxo.OptimizedUtxoSet.create db in
    for i = 1 to n_big do
      Utxo.OptimizedUtxoSet.add cache (txid_of_int i) 0
        (entry ~tag:i ~value:1L ~height:1);
      if i mod 2 = 0 then
        Utxo.OptimizedUtxoSet.add cache (txid_of_int i) 1
          (entry ~tag:i ~value:1L ~height:1)
    done;
    Utxo.OptimizedUtxoSet.flush cache;
    let ctx = make_ctx db ~utxo:(Some cache) in
    Gc.compact ();
    (* Words promoted to the major heap during the scan: anything held
       across minor collections (a per-txid key, the table's buckets and
       resized arrays) is promoted; per-coin transients die young. *)
    let before = (Gc.quick_stat ()).Gc.promoted_words in
    let info = setinfo ctx in
    let after = (Gc.quick_stat ()).Gc.promoted_words in
    let grew_mb = (after -. before) *. 8.0 /. 1_048_576.0 in
    let txs = field_int info "transactions" in
    Printf.printf "scan: txouts=%d transactions=%d promoted=%.1fMB\n%!"
      (field_int info "txouts") txs grew_mb;
    Alcotest.(check int) "transactions" n_big txs;
    Alcotest.(check int) "txouts" (n_big + n_big / 2) (field_int info "txouts");
    (* one retained 64-char key + bucket per txid is >=13 words = 104 B,
       i.e. >=20 MB for 200k txids; allow 4 MB of scan transients. *)
    Alcotest.(check bool)
      (Printf.sprintf "promoted %.1f MB during scan (< 4 MB)" grew_mb)
      true (grew_mb < 4.0))

let () =
  Alcotest.run "gettxoutsetinfo_transactions"
    [ ("transactions",
       [ Alcotest.test_case "overlay distinct-txid count" `Quick
           test_overlay_counts;
         Alcotest.test_case "scan retains no per-txid state" `Quick
           test_scan_retains_no_per_txid_state ]) ]
