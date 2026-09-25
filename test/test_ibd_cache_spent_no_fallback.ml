(* Control: a coin spent earlier in the current UTXO flush window must be
   MISSING to every later block — no fall-through to the on-disk store.

   QUEUES.md 2026-09-24 "CONSENSUS CANDIDATE — cross-block double spend
   during IBD".  process_downloaded_blocks resolved inputs through
   OptimizedUtxoSet.get and, on [None], fell back to Storage.ChainDB.get_utxo.
   [get] also answers [None] for a coin the cache holds as spent (dirty
   `Removed), and the store still holds that coin until the next flush
   (every 500 blocks), so a later block in the same window could spend it
   AGAIN and be connected.  The worker's prefetch (f90bd03) mapped
   Mem_removed to the same raw-store read.  Reproduced end-to-end on regtest
   over P2P (block 512 re-spending the coin block 511 spent: Core
   bad-txns-inputs-missingorspent, camlcoin connected it as its tip).

   Core: CCoinsViewCache::FetchCoin (coins.cpp) only asks [base] when the
   outpoint has no cache entry; SpendCoin leaves a spent-and-dirty entry,
   HaveCoin reports it absent, and CheckTxInputs (consensus/tx_verify.cpp)
   rejects bad-txns-inputs-missingorspent.

   Shape: 101 coinbase-only blocks through process_downloaded_blocks, a
   flush (what the 500-block cadence does), then block 102 spends the
   height-1 coinbase C and block 103 spends C again.  Both the inline
   accept_block path (serial [lookup]) and the Validation_worker path
   (prefetch_base) are driven.  Control: 103 spending the height-2 coinbase
   instead must connect, so a red "rejected" is not a harness that rejects
   everything.

   Command (red on f90bd03, green after):
     dune exec --no-buffer test/test_ibd_cache_spent_no_fallback.exe
*)

open Camlcoin

let op_true = Cstruct.of_string "\x51"

let remine (block : Types.block) : Types.block =
  let h = ref block.Types.header in
  let n = ref 0l in
  let found = ref false in
  while (not !found) && Int32.compare !n 5_000_000l < 0 do
    h := { !h with Types.nonce = !n };
    if Consensus.hash_meets_target (Crypto.compute_block_hash !h) !h.Types.bits
    then found := true
    else n := Int32.add !n 1l
  done;
  if not !found then failwith "remine: no nonce found";
  { block with Types.header = !h }

let make_block ~prev_hash ~prev_time ~height ?(fee = 0L) ?(tag = 0)
    (txs : Types.transaction list) : Types.block =
  let extra_nonce = Cstruct.create 8 in
  Cstruct.LE.set_uint64 extra_nonce 0 (Int64.of_int (height + (tag lsl 32)));
  let mk wr =
    Mining.create_coinbase ~height ~total_fee:fee ~payout_script:op_true
      ~extra_nonce ~witness_root:wr ~network_type:Consensus.Regtest ()
  in
  let placeholder = mk None in
  let wr = Mining.compute_witness_merkle_root (placeholder :: txs) in
  let coinbase = mk (Some wr) in
  let all = coinbase :: txs in
  let merkle_root, _ = Crypto.merkle_root (List.map Crypto.compute_txid all) in
  remine { Types.header = { version = 4l; prev_block = prev_hash; merkle_root;
                            timestamp = Int32.add prev_time 600l;
                            bits = Consensus.regtest.pow_limit; nonce = 0l };
           transactions = all }

let spend ?(fee = 1000L) ?(tag = 0) (prev : Types.hash256) (value : int64) =
  let pad = Cstruct.create 22 in
  Cstruct.set_uint8 pad 0 0x6a; Cstruct.set_uint8 pad 1 0x14;
  Cstruct.set_uint8 pad 2 tag;
  { Types.version = 2l;
    inputs = [ { Types.previous_output = { Types.txid = prev; vout = 0l };
                 script_sig = Cstruct.create 0; sequence = 0xFFFFFFFFl } ];
    outputs = [ { Types.value = Int64.sub value fee; script_pubkey = op_true };
                { Types.value = 0L; script_pubkey = pad } ];
    witnesses = []; locktime = 0l }

let queue ibd (b : Types.block) h =
  Sync.queue_add ibd
    { Sync.hash = Crypto.compute_block_hash b.Types.header; height = h;
      download_state = Sync.Downloaded { block = b; peer_id = None };
      tried_peers = [] }

let accept state (b : Types.block) =
  match Sync.validate_header state b.Types.header with
  | Ok entry -> Sync.accept_header state entry
  | Error e -> Alcotest.failf "validate_header: %s" e

(* Returns (tip after 101+flush, tip after feeding 102+103, C still on
   disk while spent in cache?). *)
let run ~use_worker ~double_spend =
  Test_tmp.with_dir ~label:"ibd_spent_nofallback" ~mkdir:true (fun path ->
    let db = Storage.ChainDB.create path in
    Fun.protect ~finally:(fun () -> try Storage.ChainDB.close db with _ -> ())
      (fun () ->
        let state = Sync.create_chain_state db Consensus.regtest in
        let genesis = Option.get state.Sync.tip in
        let utxo = Utxo.OptimizedUtxoSet.create ~cache_size:10_000 db in
        let prev_hash = ref genesis.Sync.hash in
        let prev_time = ref genesis.Sync.header.Types.timestamp in
        let cb = Array.make 104 Types.zero_hash in
        let next ?fee ?tag h txs =
          let b = make_block ~prev_hash:!prev_hash ~prev_time:!prev_time
                    ~height:h ?fee ?tag txs in
          accept state b;
          prev_hash := Crypto.compute_block_hash b.Types.header;
          prev_time := b.Types.header.Types.timestamp;
          cb.(h) <- Crypto.compute_txid (List.hd b.Types.transactions);
          b
        in
        let prefix = List.init 101 (fun i -> next (i + 1) []) in
        state.Sync.blocks_synced <- 0;
        state.Sync.sync_state <- Sync.SyncingBlocks;
        let ibd = Sync.create_ibd_state ~utxo_set:utxo state in
        List.iteri (fun i b -> queue ibd b (i + 1)) prefix;
        let worker = if use_worker then Some (Sync.Validation_worker.create ())
                     else None in
        Fun.protect
          ~finally:(fun () ->
            Option.iter Sync.Validation_worker.shutdown worker)
          (fun () ->
            let go n =
              match Lwt_main.run
                      (Sync.process_downloaded_blocks ?worker ~max_blocks:n ibd)
              with Ok n -> n | Error e -> Alcotest.failf "process: %s" e
            in
            ignore (go 101);
            let tip101 = state.Sync.blocks_synced in
            (* The periodic (500-block) flush: C is now on disk and the
               dirty set is empty. *)
            Sync.flush_utxos ibd;
            let subsidy = Consensus.block_subsidy_for_network
                            Consensus.Regtest 1 in
            let c = cb.(1) in
            let b102 = next ~fee:1000L 102 [ spend ~tag:1 c subsidy ] in
            let b103 =
              if double_spend
              then next ~fee:2000L ~tag:1 103 [ spend ~fee:2000L ~tag:2 c subsidy ]
              else next ~fee:2000L ~tag:2 103
                     [ spend ~fee:2000L ~tag:3 cb.(2) subsidy ] in
            queue ibd b102 102;
            queue ibd b103 103;
            ignore (go 2);
            let on_disk_while_spent =
              Storage.ChainDB.get_utxo db c 0 <> None
              && Utxo.OptimizedUtxoSet.get_mem utxo c 0
                 = Utxo.OptimizedUtxoSet.Mem_removed
            in
            (tip101, state.Sync.blocks_synced, on_disk_while_spent))))

let check ~use_worker () =
  let label = if use_worker then "worker+prefetch" else "inline" in
  let t101, tip, window = run ~use_worker ~double_spend:true in
  Printf.printf "  %s double-spend: tip101=%d tip=%d C-on-disk-but-spent=%b\n%!"
    label t101 tip window;
  Alcotest.(check int) "prefix connected" 101 t101;
  Alcotest.(check bool)
    "precondition: C is still in the store while the cache holds it spent \
     (the window the bug needs)" true window;
  Alcotest.(check int)
    "block 103 re-spends C (spent by 102, same flush window): rejected, tip \
     stays 102 (Core bad-txns-inputs-missingorspent)" 102 tip;
  let t101c, tipc, _ = run ~use_worker ~double_spend:false in
  Printf.printf "  %s control: tip101=%d tip=%d\n%!" label t101c tipc;
  Alcotest.(check int) "control: 103 spending a different coin connects" 103
    tipc

let () =
  Alcotest.run "ibd_cache_spent_no_fallback" [
    "cross-block double spend", [
      Alcotest.test_case "inline accept_block path" `Quick
        (check ~use_worker:false);
      Alcotest.test_case "Validation_worker prefetch path" `Quick
        (check ~use_worker:true);
    ];
  ]
