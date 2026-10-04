(* P0 2026-10-04 (QUEUES camlcoin item 0): TWO COIN VIEWS.

   The catch-up IBD connects through the node's shared OptimizedUtxoSet
   (LRU -> dirty -> store).  The at-tip path [process_new_block] reads coins
   from the store (Storage.ChainDB.get_utxo) and commits its delta with
   Storage.ChainDB.apply_block_atomic straight to the store — it never
   touches the OptimizedUtxoSet.  A coin the LRU still holds as a CLEAN
   entry (read or flushed by an earlier catch-up session) and that the
   at-tip path then spends stays "unspent" in the LRU.  The next catch-up
   session reads the LRU first and never reaches the store.

   Shape: 101 blocks through process_downloaded_blocks (catch-up session 1)
   + its end-of-session flush; block 102 spends the height-1 coinbase C via
   process_new_block (at tip); a second catch-up session is handed block
   103 that spends C AGAIN.  Core: one CCoinsViewCache (CoinsTip) over the
   DB for every connect path; 103 fails bad-txns-inputs-missingorspent.

   Control: 103 spending the height-2 coinbase instead must connect, so a
   red "rejected" is not a harness that rejects everything.  Also a
   mirror case: a coin CREATED at tip and spent by catch-up session 2.

     dune exec --no-buffer test/test_two_coin_views.exe
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


let run ~use_worker ~double_spend =
  Test_tmp.with_dir ~label:"two_coin_views" ~mkdir:true (fun path ->
    let db = Storage.ChainDB.create path in
    Fun.protect ~finally:(fun () ->
        Sync.shared_utxo_set := None;
        try Storage.ChainDB.close db with _ -> ())
      (fun () ->
        let state = Sync.create_chain_state db Consensus.regtest in
        let genesis = Option.get state.Sync.tip in
        let utxo = Utxo.OptimizedUtxoSet.create ~cache_size:10_000 db in
        (* production wiring (cli.ml): one shared set *)
        Sync.shared_utxo_set := Some utxo;
        let prev_hash = ref genesis.Sync.hash in
        let prev_time = ref genesis.Sync.header.Types.timestamp in
        let cb = Array.make 105 Types.zero_hash in
        let next ?fee ?tag h txs =
          let b = make_block ~prev_hash:!prev_hash ~prev_time:!prev_time
                    ~height:h ?fee ?tag txs in
          accept state b;
          prev_hash := Crypto.compute_block_hash b.Types.header;
          prev_time := b.Types.header.Types.timestamp;
          cb.(h) <- Crypto.compute_txid (List.hd b.Types.transactions);
          b
        in
        let worker = if use_worker then Some (Sync.Validation_worker.create ())
                     else None in
        Fun.protect
          ~finally:(fun () -> Option.iter Sync.Validation_worker.shutdown worker)
          (fun () ->
            let go ibd n =
              match Lwt_main.run
                      (Sync.process_downloaded_blocks ?worker ~max_blocks:n ibd)
              with Ok n -> n | Error e -> Alcotest.failf "process: %s" e
            in
            (* catch-up session 1: 1..101, then its flush *)
            let prefix = List.init 101 (fun i -> next (i + 1) []) in
            state.Sync.blocks_synced <- 0;
            state.Sync.sync_state <- Sync.SyncingBlocks;
            let ibd1 = Sync.create_ibd_state ~utxo_set:utxo state in
            List.iteri (fun i b -> queue ibd1 b (i + 1)) prefix;
            ignore (go ibd1 101);
            Sync.flush_utxos ibd1;
            let tip101 = state.Sync.blocks_synced in
            (* at tip: 102 spends C through process_new_block *)
            state.Sync.sync_state <- Sync.FullySynced;
            let subsidy = Consensus.block_subsidy_for_network
                            Consensus.Regtest 1 in
            let c = cb.(1) in
            let b102 = next ~fee:1000L 102 [ spend ~tag:1 c subsidy ] in
            (match Lwt_main.run
                     (Sync.process_new_block ~f_requested:true state b102) with
             | Ok () -> ()
             | Error e -> Alcotest.failf "at-tip 102: %s" e);
            let tip102 = state.Sync.blocks_synced in
            let store_has_c = Storage.ChainDB.get_utxo db c 0 <> None in
            let lru_has_c =
              match Utxo.OptimizedUtxoSet.get_mem utxo c 0 with
              | Utxo.OptimizedUtxoSet.Mem_hit _ -> true
              | _ -> false
            in
            (* catch-up session 2: 103 *)
            let b103 =
              if double_spend
              then next ~fee:2000L ~tag:1 103 [ spend ~fee:2000L ~tag:2 c subsidy ]
              else next ~fee:2000L ~tag:2 103
                     [ spend ~fee:2000L ~tag:3 cb.(2) subsidy ] in
            state.Sync.sync_state <- Sync.SyncingBlocks;
            let ibd2 = Sync.create_ibd_state ~utxo_set:utxo state in
            queue ibd2 b103 103;
            ignore (go ibd2 1);
            Sync.flush_utxos ibd2;
            (tip101, tip102, store_has_c, lru_has_c,
             state.Sync.blocks_synced))))

(* Reverse direction: catch-up session spends C in block 102 and has NOT
   flushed (the store still holds C, the cache holds it `Removed); the
   at-tip path then gets block 103 spending C again. *)
let run_reverse ~use_worker ~double_spend =
  Test_tmp.with_dir ~label:"two_coin_views_rev" ~mkdir:true (fun path ->
    let db = Storage.ChainDB.create path in
    Fun.protect ~finally:(fun () ->
        Sync.shared_utxo_set := None;
        try Storage.ChainDB.close db with _ -> ())
      (fun () ->
        let state = Sync.create_chain_state db Consensus.regtest in
        let genesis = Option.get state.Sync.tip in
        let utxo = Utxo.OptimizedUtxoSet.create ~cache_size:10_000 db in
        Sync.shared_utxo_set := Some utxo;
        let prev_hash = ref genesis.Sync.hash in
        let prev_time = ref genesis.Sync.header.Types.timestamp in
        let cb = Array.make 105 Types.zero_hash in
        let next ?fee ?tag h txs =
          let b = make_block ~prev_hash:!prev_hash ~prev_time:!prev_time
                    ~height:h ?fee ?tag txs in
          accept state b;
          prev_hash := Crypto.compute_block_hash b.Types.header;
          prev_time := b.Types.header.Types.timestamp;
          cb.(h) <- Crypto.compute_txid (List.hd b.Types.transactions);
          b
        in
        let worker = if use_worker then Some (Sync.Validation_worker.create ())
                     else None in
        Fun.protect
          ~finally:(fun () -> Option.iter Sync.Validation_worker.shutdown worker)
          (fun () ->
            let go ibd n =
              match Lwt_main.run
                      (Sync.process_downloaded_blocks ?worker ~max_blocks:n ibd)
              with Ok n -> n | Error e -> Alcotest.failf "process: %s" e
            in
            let subsidy = Consensus.block_subsidy_for_network
                            Consensus.Regtest 1 in
            let prefix = List.init 101 (fun i -> next (i + 1) []) in
            state.Sync.blocks_synced <- 0;
            state.Sync.sync_state <- Sync.SyncingBlocks;
            let ibd = Sync.create_ibd_state ~utxo_set:utxo state in
            List.iteri (fun i b -> queue ibd b (i + 1)) prefix;
            ignore (go ibd 101);
            Sync.flush_utxos ibd;
            let c = cb.(1) in
            let b102 = next ~fee:1000L 102 [ spend ~tag:1 c subsidy ] in
            queue ibd b102 102;
            ignore (go ibd 1);          (* no flush: C `Removed in cache *)
            let window =
              Storage.ChainDB.get_utxo db c 0 <> None
              && Utxo.OptimizedUtxoSet.get_mem utxo c 0
                 = Utxo.OptimizedUtxoSet.Mem_removed in
            state.Sync.sync_state <- Sync.FullySynced;
            let b103 =
              if double_spend
              then next ~fee:2000L ~tag:1 103 [ spend ~fee:2000L ~tag:2 c subsidy ]
              else next ~fee:2000L ~tag:2 103
                     [ spend ~fee:2000L ~tag:3 cb.(2) subsidy ] in
            ignore (Lwt_main.run
                      (Sync.process_new_block ?worker ~f_requested:true
                         state b103));
            (window, state.Sync.blocks_synced))))

let check_reverse ~use_worker () =
  let label = if use_worker then "worker" else "inline" in
  let window, tip = run_reverse ~use_worker ~double_spend:true in
  Printf.printf "  %s reverse: window=%b tip=%d\n%!" label window tip;
  Alcotest.(check bool)
    "precondition: C still in the store, spent in the shared cache" true window;
  Alcotest.(check int)
    "at-tip 103 re-spends C (spent by catch-up 102, unflushed): rejected, \
     tip stays 102" 102 tip;
  let _, tipc = run_reverse ~use_worker ~double_spend:false in
  Printf.printf "  %s reverse control: tip=%d\n%!" label tipc;
  Alcotest.(check int) "control: at-tip 103 spending a different coin connects"
    103 tipc

let check ~use_worker () =
  let label = if use_worker then "worker+prefetch" else "inline" in
  let t101, t102, store_c, lru_c, tip = run ~use_worker ~double_spend:true in
  Printf.printf
    "  %s double-spend: tip101=%d tip102=%d store-has-C=%b lru-has-C=%b \
     tip=%d\n%!" label t101 t102 store_c lru_c tip;
  Alcotest.(check int) "session 1 connected" 101 t101;
  Alcotest.(check int) "102 connected at tip" 102 t102;
  Alcotest.(check bool) "C spent in the store by the at-tip path" false store_c;
  Alcotest.(check int)
    "catch-up session 2: 103 re-spends C (spent at tip by 102): rejected, \
     tip stays 102 (Core bad-txns-inputs-missingorspent)" 102 tip;
  Alcotest.(check bool) "the shared view does not still hold C as unspent"
    false lru_c;
  let _, _, _, _, tipc = run ~use_worker ~double_spend:false in
  Printf.printf "  %s control: tip=%d\n%!" label tipc;
  Alcotest.(check int) "control: 103 spending a different coin connects" 103
    tipc

let () =
  Alcotest.run "two_coin_views" [
    "at-tip spend then catch-up re-spend", [
      Alcotest.test_case "inline accept_block path" `Quick
        (check ~use_worker:false);
      Alcotest.test_case "Validation_worker prefetch path" `Quick
        (check ~use_worker:true);
    ];
    "catch-up spend (unflushed) then at-tip re-spend", [
      Alcotest.test_case "inline" `Quick (check_reverse ~use_worker:false);
      Alcotest.test_case "Validation_worker" `Quick
        (check_reverse ~use_worker:true);
    ];
  ]
