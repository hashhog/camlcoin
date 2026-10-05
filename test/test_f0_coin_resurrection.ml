(* F0 coin-cache RESURRECTION (receipts/arch-f6-f7-design-2026-10-05.md §0,
   invariant I5).

   The catch-up IBD resolves a block's inputs on the Validation_worker
   domain through the shared OptimizedUtxoSet: get_mem (miss) -> read_db
   (store read) -> note_db_result (installs the coin CLEAN in the LRU).
   While the worker runs, the Lwt main thread is free and the at-tip path
   (process_new_block / connect_stored_blocks / submitblock) can connect
   and COMMIT a block: apply_block_atomic deletes the coin from the store,
   then at_tip_commit_invalidate forgets it in the shared cache.  If that
   commit lands between the worker's store read and its install, the
   install puts the PRE-spend coin back into the cache as clean/unspent,
   and the next catch-up block that spends it again is ACCEPTED.  This is
   the live 969874 shape (the catch-up and the at-tip listener connecting
   the SAME block concurrently), arriving at the cache instead of the
   verdict.

   Core: one CCoinsViewCache under cs_main; FetchCoin (coins.cpp) never
   installs a base read that a spend or flush raced, because nothing can
   run between them.  Here: a read result is installed only if no
   mutation of the view happened since the read began (epoch).

   Determinism: OptimizedUtxoSet.after_db_read_hook parks the worker right
   after its store read of coin C; the main thread then runs the real
   at-tip process_new_block for block 102 (spends C) and only then lets the
   worker continue.  No timing, no luck.

   Shape: 101 blocks + flush (C = height-1 coinbase, evicted from a
   50-entry LRU).  Catch-up session 2 is queued 102 (spends C) and 103
   (spends C AGAIN); its worker parks on the read of C for 102; at tip,
   102 connects; the worker resumes, 102's catch-up result is discarded
   ("connected by another path"), then 103 is processed.  Core: 103 fails
   bad-txns-inputs-missingorspent, tip stays 102.  Control: 103 spending
   the height-2 coinbase instead connects (tip 103).

     dune exec --no-buffer test/test_f0_coin_resurrection.exe
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

(* A one-shot barrier the worker domain parks on. *)
type gate = {
  m : Mutex.t;
  mutable reached : bool;
  mutable released : bool;
}

let new_gate () = { m = Mutex.create (); reached = false; released = false }

let wait_until ~what (g : gate) (pred : gate -> bool) =
  let deadline = Unix.gettimeofday () +. 60.0 in
  let rec loop () =
    Mutex.lock g.m;
    let ok = pred g in
    Mutex.unlock g.m;
    if ok then ()
    else if Unix.gettimeofday () > deadline then
      failwith ("f0 test: timed out waiting for " ^ what)
    else (Unix.sleepf 0.005; loop ())
  in
  loop ()

type outcome = {
  hook_fired : bool;
  tip_after_at_tip : int;   (* blocks_synced right after the at-tip connect *)
  store_has_c : bool;       (* after the at-tip commit *)
  cache_has_c : bool;       (* after the race, before 103 *)
  final_tip : int;
}

let run ~double_spend =
  Test_tmp.with_dir ~label:"f0_resurrection" ~mkdir:true (fun path ->
    let db = Storage.ChainDB.create path in
    Fun.protect ~finally:(fun () ->
        Atomic.set Utxo.OptimizedUtxoSet.after_db_read_hook (fun _ -> ());
        Sync.shared_utxo_set := None;
        try Storage.ChainDB.close db with _ -> ())
      (fun () ->
        let state = Sync.create_chain_state db Consensus.regtest in
        let genesis = Option.get state.Sync.tip in
        (* 50-entry LRU: after 101 blocks the height-1 coinbase is evicted,
           so the next read of it is a genuine miss -> store read. *)
        let utxo = Utxo.OptimizedUtxoSet.create ~cache_size:50 db in
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
        (* session 1 (inline): 1..101, then its flush *)
        let prefix = List.init 101 (fun i -> next (i + 1) []) in
        state.Sync.blocks_synced <- 0;
        state.Sync.sync_state <- Sync.SyncingBlocks;
        let ibd1 = Sync.create_ibd_state ~utxo_set:utxo state in
        List.iteri (fun i b -> queue ibd1 b (i + 1)) prefix;
        (match Lwt_main.run
                 (Sync.process_downloaded_blocks ~max_blocks:101 ibd1) with
         | Ok _ -> () | Error e -> Alcotest.failf "session 1: %s" e);
        Sync.flush_utxos ibd1;
        Alcotest.(check int) "session 1 connected" 101 state.Sync.blocks_synced;
        let c = cb.(1) in
        let c_key = Utxo.OptimizedUtxoSet.utxo_key c 0 in
        Alcotest.(check bool) "precondition: C evicted from the LRU (miss)" true
          (Utxo.OptimizedUtxoSet.peek_mem utxo c 0
           = Utxo.OptimizedUtxoSet.Mem_miss);
        let subsidy = Consensus.block_subsidy_for_network Consensus.Regtest 1 in
        let b102 = next ~fee:1000L 102 [ spend ~tag:1 c subsidy ] in
        let b103 =
          if double_spend
          then next ~fee:2000L ~tag:1 103 [ spend ~fee:2000L ~tag:2 c subsidy ]
          else next ~fee:2000L ~tag:2 103
                 [ spend ~fee:2000L ~tag:3 cb.(2) subsidy ] in
        (* catch-up session 2 on the worker domain: 102 and 103 *)
        state.Sync.sync_state <- Sync.FullySynced;
        let ibd2 = Sync.create_ibd_state ~utxo_set:utxo state in
        queue ibd2 b102 102;
        queue ibd2 b103 103;
        let g = new_gate () in
        Atomic.set Utxo.OptimizedUtxoSet.after_db_read_hook (fun key ->
          if String.equal key c_key then begin
            Mutex.lock g.m;
            let first = not g.reached in
            if first then g.reached <- true;
            Mutex.unlock g.m;
            if first then wait_until ~what:"release" g (fun g -> g.released)
          end);
        let worker = Sync.Validation_worker.create () in
        let tip_after = ref (-1) in
        let store_c = ref true in
        let cache_c = ref false in
        Fun.protect
          ~finally:(fun () -> Sync.Validation_worker.shutdown worker)
          (fun () ->
            let catchup =
              let%lwt r =
                Sync.process_downloaded_blocks ~worker ~max_blocks:2 ibd2 in
              (match r with
               | Ok _ -> () | Error e -> Printf.printf "  catch-up: %s\n%!" e);
              Lwt.return_unit
            in
            let at_tip =
              (* wait (off the Lwt thread) until the worker has read C *)
              let%lwt () = Lwt_preemptive.detach
                  (fun () -> wait_until ~what:"worker read of C" g
                      (fun g -> g.reached)) () in
              let%lwt r =
                Sync.process_new_block ~f_requested:true state b102 in
              (match r with
               | Ok () -> () | Error e -> Alcotest.failf "at-tip 102: %s" e);
              tip_after := state.Sync.blocks_synced;
              store_c := Storage.ChainDB.get_utxo db c 0 <> None;
              Mutex.lock g.m; g.released <- true; Mutex.unlock g.m;
              Lwt.return_unit
            in
            Lwt_main.run (Lwt.join [ catchup; at_tip ]));
        (* What the shared view now says about C (no side effects). *)
        cache_c :=
          (match Utxo.OptimizedUtxoSet.peek_mem utxo c 0 with
           | Utxo.OptimizedUtxoSet.Mem_hit _ -> true
           | _ -> false);
        { hook_fired = g.reached; tip_after_at_tip = !tip_after;
          store_has_c = !store_c; cache_has_c = !cache_c;
          final_tip = state.Sync.blocks_synced }))

let check_double_spend () =
  let o = run ~double_spend:true in
  Printf.printf
    "  double-spend: hook=%b tip-after-at-tip=%d store-has-C=%b \
     cache-has-C=%b final-tip=%d\n%!"
    o.hook_fired o.tip_after_at_tip o.store_has_c o.cache_has_c o.final_tip;
  Alcotest.(check bool) "worker parked on its store read of C" true
    o.hook_fired;
  Alcotest.(check int) "at tip: 102 connected while the read was in flight"
    102 o.tip_after_at_tip;
  Alcotest.(check bool) "at-tip commit deleted C from the store" false
    o.store_has_c;
  Alcotest.(check bool)
    "the raced read did not resurrect C as an unspent cache entry" false
    o.cache_has_c;
  Alcotest.(check int)
    "103 re-spends C (spent by 102): rejected, tip stays 102 \
     (Core bad-txns-inputs-missingorspent)" 102 o.final_tip

let check_control () =
  let o = run ~double_spend:false in
  Printf.printf "  control: hook=%b tip-after-at-tip=%d final-tip=%d\n%!"
    o.hook_fired o.tip_after_at_tip o.final_tip;
  Alcotest.(check bool) "worker parked on its store read of C" true
    o.hook_fired;
  Alcotest.(check int) "at tip: 102 connected" 102 o.tip_after_at_tip;
  Alcotest.(check int) "control: 103 spending a different coin connects" 103
    o.final_tip

let () =
  Alcotest.run "f0_coin_resurrection" [
    "worker store read raced by an at-tip commit", [
      Alcotest.test_case "double spend of the raced coin" `Quick
        check_double_spend;
      Alcotest.test_case "control: different coin" `Quick check_control;
    ];
  ]
