(* ARCH-2 2026-10-05 (roadmap §3.5-1): the scripts-on IBD connect path uses
   the same coin-view path as the assume-valid one — the shared
   OptimizedUtxoSet only, spends via [remove_fast].  Core: ConnectBlock ->
   UpdateCoins (validation.cpp) on one CCoinsViewCache; SpendCoin
   (coins.cpp) erases a FRESH entry, so a coin created and spent inside one
   flush window is never written to, nor deleted from, the DB.

   Shape (regtest, no assumevalid => scripts on): 101 coinbase-only blocks
   + flush; then block 102 spends cb(1) creating X, block 103 spends X
   creating Y — no flush in between.

   Pins, each run with the fast path AND with [force_slow_utxo_path] (the
   pre-change path; the negative control — the "fast" assertions must fail
   there, so they can see the old path):
   1. X leaves no dirty entry (fast) / a [`Removed] (slow); the pending CF
      lists stay empty (fast) / non-empty (slow).
   2. After flush both arms leave the SAME store: cb(1) gone, X gone, Y
      present (no consensus change).
   3. Crash between cache and flush: drop the cache unflushed; the store
      is exactly the last flush (cb(1) present, X and Y absent — nothing
      lost, nothing resurrected); replaying 102..103 on a fresh cache
      reaches the same final store as 2.

     dune exec --no-buffer test/test_ibd_fresh_elision.exe
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

let make_block ~prev_hash ~prev_time ~height ?(fee = 0L)
    (txs : Types.transaction list) : Types.block =
  let extra_nonce = Cstruct.create 8 in
  Cstruct.LE.set_uint64 extra_nonce 0 (Int64.of_int height);
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

let spend ?(fee = 1000L) (prev : Types.hash256) (value : int64) =
  { Types.version = 2l;
    inputs = [ { Types.previous_output = { Types.txid = prev; vout = 0l };
                 script_sig = Cstruct.create 0; sequence = 0xFFFFFFFFl } ];
    outputs = [ { Types.value = Int64.sub value fee; script_pubkey = op_true } ];
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

type obs = {
  x_dirty : [ `None | `Added | `Updated | `Removed ];
  pending : int;              (* pending_utxo_updates + deletes *)
  final : bool * bool * bool; (* store has cb1, X, Y after flush *)
  crash : bool * bool * bool; (* store has cb1, X, Y after crash *)
  tip : int;
}

let run ~slow =
  Sync.force_slow_utxo_path := slow;
  Fun.protect ~finally:(fun () -> Sync.force_slow_utxo_path := false)
  @@ fun () ->
  Test_tmp.with_dir ~label:"ibd_fresh_elision" ~mkdir:true (fun path ->
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
        let cb = Array.make 110 Types.zero_hash in
        let next ?fee h txs =
          let b = make_block ~prev_hash:!prev_hash ~prev_time:!prev_time
                    ~height:h ?fee txs in
          accept state b;
          prev_hash := Crypto.compute_block_hash b.Types.header;
          prev_time := b.Types.header.Types.timestamp;
          cb.(h) <- Crypto.compute_txid (List.hd b.Types.transactions);
          b
        in
        let go ibd n =
          match Lwt_main.run (Sync.process_downloaded_blocks ~max_blocks:n ibd)
          with Ok n -> n | Error e -> Alcotest.failf "process: %s" e
        in
        let prefix = List.init 101 (fun i -> next (i + 1) []) in
        state.Sync.blocks_synced <- 0;
        state.Sync.sync_state <- Sync.SyncingBlocks;
        let ibd1 = Sync.create_ibd_state ~utxo_set:utxo state in
        List.iteri (fun i b -> queue ibd1 b (i + 1)) prefix;
        ignore (go ibd1 101);
        Sync.flush_utxos ibd1;
        Alcotest.(check int) "prefix connected" 101 state.Sync.blocks_synced;
        let subsidy = Consensus.block_subsidy_for_network Consensus.Regtest 1 in
        let c1 = cb.(1) in
        let t1 = spend c1 subsidy in
        let x = Crypto.compute_txid t1 in
        let t2 = spend ~fee:1000L x (Int64.sub subsidy 1000L) in
        let y = Crypto.compute_txid t2 in
        let b102 = next ~fee:1000L 102 [ t1 ] in
        let b103 = next ~fee:1000L 103 [ t2 ] in
        let has h = Storage.ChainDB.get_utxo db h 0 <> None in
        let store () = (has c1, has x, has y) in
        (* session 2: 102 + 103, no flush *)
        let ibd2 = Sync.create_ibd_state ~utxo_set:utxo state in
        queue ibd2 b102 102; queue ibd2 b103 103;
        ignore (go ibd2 2);
        Alcotest.(check int) "102..103 connected" 103 state.Sync.blocks_synced;
        let x_dirty =
          match Hashtbl.find_opt utxo.Utxo.OptimizedUtxoSet.dirty
                  (Utxo.OptimizedUtxoSet.utxo_key x 0) with
          | None -> `None | Some (`Added _) -> `Added
          | Some (`Updated _) -> `Updated | Some `Removed -> `Removed
        in
        let pending = List.length ibd2.Sync.pending_utxo_updates
                      + List.length ibd2.Sync.pending_utxo_deletes in
        (* what a crash right now would leave on disk *)
        let crash = store () in
        Sync.flush_utxos ibd2;
        let final = store () in
        { x_dirty; pending; final; crash; tip = state.Sync.blocks_synced }))

(* The crash-and-replay arm on its own datadir: connect 102..103 into a
   cache, DROP it unflushed, re-open a cache, rewind the in-memory tip to
   the last flush (101), replay, flush. *)
let run_crash_replay ~slow =
  Sync.force_slow_utxo_path := slow;
  Fun.protect ~finally:(fun () -> Sync.force_slow_utxo_path := false)
  @@ fun () ->
  Test_tmp.with_dir ~label:"ibd_fresh_elision_crash" ~mkdir:true (fun path ->
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
        let cb = Array.make 110 Types.zero_hash in
        let next ?fee h txs =
          let b = make_block ~prev_hash:!prev_hash ~prev_time:!prev_time
                    ~height:h ?fee txs in
          accept state b;
          prev_hash := Crypto.compute_block_hash b.Types.header;
          prev_time := b.Types.header.Types.timestamp;
          cb.(h) <- Crypto.compute_txid (List.hd b.Types.transactions);
          b
        in
        let go ibd n =
          match Lwt_main.run (Sync.process_downloaded_blocks ~max_blocks:n ibd)
          with Ok n -> n | Error e -> Alcotest.failf "process: %s" e
        in
        let prefix = List.init 101 (fun i -> next (i + 1) []) in
        state.Sync.blocks_synced <- 0;
        state.Sync.sync_state <- Sync.SyncingBlocks;
        let ibd1 = Sync.create_ibd_state ~utxo_set:utxo state in
        List.iteri (fun i b -> queue ibd1 b (i + 1)) prefix;
        ignore (go ibd1 101);
        Sync.flush_utxos ibd1;
        let subsidy = Consensus.block_subsidy_for_network Consensus.Regtest 1 in
        let c1 = cb.(1) in
        let t1 = spend c1 subsidy in
        let x = Crypto.compute_txid t1 in
        let t2 = spend ~fee:1000L x (Int64.sub subsidy 1000L) in
        let y = Crypto.compute_txid t2 in
        let b102 = next ~fee:1000L 102 [ t1 ] in
        let b103 = next ~fee:1000L 103 [ t2 ] in
        let has h = Storage.ChainDB.get_utxo db h 0 <> None in
        let ibd2 = Sync.create_ibd_state ~utxo_set:utxo state in
        queue ibd2 b102 102; queue ibd2 b103 103;
        ignore (go ibd2 2);
        (* crash: cache + pending lists lost, nothing flushed *)
        let after_crash = (has c1, has x, has y) in
        let utxo' = Utxo.OptimizedUtxoSet.create ~cache_size:10_000 db in
        Sync.shared_utxo_set := Some utxo';
        state.Sync.blocks_synced <- 101;
        let ibd3 = Sync.create_ibd_state ~utxo_set:utxo' state in
        queue ibd3 b102 102; queue ibd3 b103 103;
        ignore (go ibd3 2);
        Sync.flush_utxos ibd3;
        (after_crash, (has c1, has x, has y), state.Sync.blocks_synced)))

let triple = Alcotest.(triple bool bool bool)

let test_fast () =
  let o = run ~slow:false in
  Alcotest.(check int) "tip" 103 o.tip;
  Alcotest.(check bool) "X (created+spent in window) has NO dirty entry"
    true (o.x_dirty = `None);
  Alcotest.(check int) "no pending CF-list entries" 0 o.pending;
  Alcotest.check triple "store before flush = last flush (cb1 only)"
    (true, false, false) o.crash;
  Alcotest.check triple "store after flush: cb1 spent, X never, Y present"
    (false, false, true) o.final

(* Negative control: the pre-change path is observably different on the
   SAME assertions (so they can see a regression) and leaves the same
   final store (so the change is not a consensus change). *)
let test_slow_control () =
  let o = run ~slow:true in
  Alcotest.(check int) "tip" 103 o.tip;
  Alcotest.(check bool) "slow path records X `Removed (no FRESH elision)"
    true (o.x_dirty = `Removed);
  Alcotest.(check bool) "slow path queues pending CF-list entries"
    true (o.pending > 0);
  Alcotest.check triple "same final store as the fast path"
    (false, false, true) o.final

let test_crash_replay slow () =
  let after_crash, after_replay, tip = run_crash_replay ~slow in
  Alcotest.check triple "crash before flush: nothing lost, nothing resurrected"
    (true, false, false) after_crash;
  Alcotest.(check int) "replay reconnects 102..103" 103 tip;
  Alcotest.check triple "replay + flush = uninterrupted final store"
    (false, false, true) after_replay

let () =
  Alcotest.run "ibd_fresh_elision"
    [ "scripts-on fast path",
      [ Alcotest.test_case "FRESH elision, single store" `Quick test_fast;
        Alcotest.test_case "negative control: old path" `Quick test_slow_control;
        Alcotest.test_case "crash between cache and flush (fast)" `Quick
          (test_crash_replay false);
        Alcotest.test_case "crash between cache and flush (slow)" `Quick
          (test_crash_replay true) ] ]
