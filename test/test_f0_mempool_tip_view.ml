(* F0 second road: the MEMPOOL and gettxout read the coin STORE, not the
   chain's coin view (receipts/arch-f6-f7-design-2026-10-05.md §2.5
   landmine "Mempool and gettxout read the stores directly, up to 500
   blocks stale").

   The catch-up IBD connects through the shared OptimizedUtxoSet and
   flushes to the store every 500 blocks / at session end.  Until then a
   coin a connected block SPENT is still in the store (the cache holds it
   [`Removed]) and a coin it CREATED is not.  Mempool.lookup_utxo and
   gettxout (rpc.ml) read Utxo.UtxoSet.get = Storage.ChainDB.get_utxo, the
   store, so inside that window:
     - a transaction spending a coin the active chain already spent is
       ACCEPTED into the mempool (and stays there after the flush — nothing
       re-checks it — so getblocktemplate builds an invalid block);
     - gettxout reports the spent coin as unspent;
     - a transaction spending a coin the active chain created is refused.
   The relay listener accepts txs whenever sync_state = FullySynced, which
   is the state during an at-tip catch-up session.

   Core: the mempool's CCoinsViewMemPool sits on CoinsTip() and gettxout
   reads CoinsTip() under cs_main — the cache, including its DIRTY-spent
   entries — never the bare DB.

   Shape: 101 blocks + flush; catch-up connects 102 (spends C = height-1
   coinbase, creates D) and does NOT flush.  Then:
     double spend  — mempool tx spending C must be rejected (Core
                     bad-txns-inputs-missingorspent);
     gettxout      — UtxoSet.get C must be None;
     created coin  — mempool tx spending D must be accepted;
     control       — mempool tx spending the height-2 coinbase is accepted.

     dune exec --no-buffer test/test_f0_mempool_tip_view.exe
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

let show = function Ok _ -> "accepted" | Error e -> "rejected: " ^ e

(* Runs [f] with the chain at 102 connected by catch-up and NOT flushed. *)
let with_unflushed_window f =
  Test_tmp.with_dir ~label:"f0_mempool_tip_view" ~mkdir:true (fun path ->
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
        let go ibd n =
          match Lwt_main.run (Sync.process_downloaded_blocks ~max_blocks:n ibd)
          with Ok n -> n | Error e -> Alcotest.failf "process: %s" e
        in
        let subsidy = Consensus.block_subsidy_for_network Consensus.Regtest 1 in
        let prefix = List.init 101 (fun i -> next (i + 1) []) in
        state.Sync.blocks_synced <- 0;
        state.Sync.sync_state <- Sync.SyncingBlocks;
        let ibd = Sync.create_ibd_state ~utxo_set:utxo state in
        List.iteri (fun i b -> queue ibd b (i + 1)) prefix;
        ignore (go ibd 101);
        Sync.flush_utxos ibd;
        let c = cb.(1) in
        let tx_d = spend ~tag:1 c subsidy in
        let d = Crypto.compute_txid tx_d in
        let b102 = next ~fee:1000L 102 [ tx_d ] in
        queue ibd b102 102;
        ignore (go ibd 1);                       (* no flush *)
        Alcotest.(check int) "catch-up connected 102" 102
          state.Sync.blocks_synced;
        let window =
          Storage.ChainDB.get_utxo db c 0 <> None
          && Utxo.OptimizedUtxoSet.peek_mem utxo c 0
             = Utxo.OptimizedUtxoSet.Mem_removed in
        Alcotest.(check bool)
          "precondition: C still in the store, spent in the chain's view"
          true window;
        state.Sync.sync_state <- Sync.FullySynced;
        let mp_utxo = Utxo.UtxoSet.create db in
        let mp = Mempool.create ~network:Consensus.regtest
            ~require_standard:false ~verify_scripts:false
            ~utxo:mp_utxo ~current_height:102 () in
        f ~c ~d ~cb2:cb.(2) ~subsidy ~mp ~mp_utxo))

let test_double_spend_rejected () =
  with_unflushed_window (fun ~c ~d:_ ~cb2:_ ~subsidy ~mp ~mp_utxo:_ ->
    let r = Mempool.add_transaction mp (spend ~fee:5000L ~tag:7 c subsidy) in
    Printf.printf "  mempool tx spending C (spent by 102): %s\n%!" (show r);
    Alcotest.(check bool)
      "a tx spending a coin the active chain spent is rejected \
       (Core bad-txns-inputs-missingorspent)" true (Result.is_error r))

let test_gettxout_spent () =
  with_unflushed_window (fun ~c ~d:_ ~cb2:_ ~subsidy:_ ~mp:_ ~mp_utxo ->
    let r = Utxo.UtxoSet.get mp_utxo c 0 in
    Printf.printf "  gettxout read of C: %s\n%!"
      (if r = None then "none" else "UNSPENT");
    Alcotest.(check bool) "gettxout's read of a spent coin returns nothing"
      true (r = None))

let test_created_coin_visible () =
  with_unflushed_window (fun ~c:_ ~d ~cb2:_ ~subsidy ~mp ~mp_utxo:_ ->
    let value = Int64.sub subsidy 1000L in
    let r = Mempool.add_transaction mp (spend ~fee:5000L ~tag:8 d value) in
    Printf.printf "  mempool tx spending D (created by 102): %s\n%!" (show r);
    Alcotest.(check bool)
      "a tx spending a coin the active chain created is accepted" true
      (Result.is_ok r))

let test_control () =
  with_unflushed_window (fun ~c:_ ~d:_ ~cb2 ~subsidy ~mp ~mp_utxo:_ ->
    let r = Mempool.add_transaction mp (spend ~fee:5000L ~tag:9 cb2 subsidy) in
    Printf.printf "  control (height-2 coinbase): %s\n%!" (show r);
    Alcotest.(check bool) "control: an unspent flushed coin is accepted" true
      (Result.is_ok r))

let () =
  Alcotest.run "f0_mempool_tip_view" [
    "unflushed catch-up window", [
      Alcotest.test_case "mempool double spend rejected" `Quick
        test_double_spend_rejected;
      Alcotest.test_case "gettxout read of a spent coin" `Quick
        test_gettxout_spent;
      Alcotest.test_case "coin created by the window is visible" `Quick
        test_created_coin_visible;
      Alcotest.test_case "control" `Quick test_control;
    ];
  ]
