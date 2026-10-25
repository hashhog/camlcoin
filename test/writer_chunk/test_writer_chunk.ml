(* A long writer RPC must not monopolise the Lwt main thread.

   Writer RPCs run ON the main thread (chain lock, 1d582b1) so they are
   atomic w.r.t. every connect path.  A writer that walks the whole chain in
   one synchronous loop (rescanblockchain) therefore starves P2P message
   handling, validation and the monitoring RPCs for its full duration
   (QUEUES: 0.6-2.2 s RPC latency bursts).  These cases run the writer
   through Rpc.handle_single_request_lwt -- the HTTP server's entry point --
   with a stand-in per-block cost (Rpc.test_rescan_block_cost_s) and assert:

     LAT   the longest gap between two wakeups of a 5 ms Lwt ticker stays
           under [gap_bound_s] while the writer runs for far longer;
     EQ    the chunked scan credits exactly what the unchunked handler does;
     CONN  a P2P block connect issued mid-rescan completes within
           [connect_bound_s] and the rescan still returns its original range;
     REORG a scanned height changing under the rescan between slices is
           reported, not silently scanned across.

     dune exec --no-buffer test/writer_chunk/test_writer_chunk.exe
*)

open Camlcoin

let gap_bound_s = 0.15
let connect_bound_s = 0.30
let n_blocks = 300
let cost_s = 0.002

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

let make_block ?(txs = []) ?(fee = 0L) ~payout ~prev_hash ~prev_time ~height
    () : Types.block =
  let extra_nonce = Cstruct.create 8 in
  Cstruct.LE.set_uint64 extra_nonce 0 (Int64.of_int height);
  let mk wr =
    Mining.create_coinbase ~height ~total_fee:fee ~payout_script:payout
      ~extra_nonce ~witness_root:wr ~network_type:Consensus.Regtest ()
  in
  let wr = Mining.compute_witness_merkle_root (mk None :: txs) in
  let coinbase = mk (Some wr) in
  let all = coinbase :: txs in
  let merkle_root, _ = Crypto.merkle_root (List.map Crypto.compute_txid all) in
  remine { Types.header = { version = 4l; prev_block = prev_hash; merkle_root;
                            timestamp = Int32.add prev_time 600l;
                            bits = Consensus.regtest.pow_limit; nonce = 0l };
           transactions = all }

let json_req m params : Yojson.Safe.t =
  `Assoc [ ("jsonrpc", `String "1.0"); ("id", `String "t");
           ("method", `String m); ("params", `List params) ]

type fx = {
  state : Sync.chain_state;
  ctx : Rpc.rpc_context;
  wallet : Wallet.t;
  payout : Cstruct.t;
  path : string;
  blocks : Types.block option array;   (* fixture block by height *)
  mutable prev_hash : Types.hash256;
  mutable prev_time : int32;
  mutable height : int;
}

let next_block ?txs ?fee ?payout fx =
  let payout = Option.value payout ~default:fx.payout in
  let b = make_block ?txs ?fee ~payout ~prev_hash:fx.prev_hash
      ~prev_time:fx.prev_time ~height:(fx.height + 1) () in
  fx.prev_hash <- Crypto.compute_block_hash b.Types.header;
  fx.prev_time <- b.Types.header.Types.timestamp;
  fx.height <- fx.height + 1;
  b

(* [n_blocks] blocks whose coinbase pays the wallet, connected through the
   catch-up path, then FullySynced. *)
let with_fx ?(n = n_blocks) f =
  Test_tmp.with_dir ~label:"wchunk" ~mkdir:true (fun path ->
    let db = Storage.ChainDB.create (Filename.concat path "chain") in
    Fun.protect ~finally:(fun () ->
        Rpc.test_rescan_block_cost_s := 0.0;
        Sync.shared_utxo_set := None;
        try Storage.ChainDB.close db with _ -> ())
      (fun () ->
        let network = Consensus.regtest in
        let state = Sync.create_chain_state db network in
        let genesis = Option.get state.Sync.tip in
        let utxo = Utxo.OptimizedUtxoSet.create ~cache_size:10_000 db in
        Sync.shared_utxo_set := Some utxo;
        let mp = Mempool.create ~network ~require_standard:false
            ~verify_scripts:false ~utxo:(Utxo.UtxoSet.create db)
            ~current_height:0 () in
        let wallet = Wallet.create ~network:`Regtest
            ~db_path:(Filename.concat path "wallet.db") in
        let payout =
          match Address.address_of_string (Wallet.get_new_address wallet) with
          | Ok a -> Wallet.build_output_script a
          | Error e -> failwith e in
        let ctx : Rpc.rpc_context =
          { chain = state; mempool = mp;
            peer_manager = Peer_manager.create network;
            wallet = Some wallet; wallet_manager = None;
            fee_estimator = Fee_estimation.create ();
            network; filter_index = None; utxo = Some utxo; data_dir = None;
            snapshot_activation = None } in
        let fx = { state; ctx; wallet; payout; path;
                   blocks = Array.make (n + 64) None;
                   prev_hash = genesis.Sync.hash;
                   prev_time = genesis.Sync.header.Types.timestamp;
                   height = 0 } in
        let blocks = List.init n (fun _ -> next_block fx) in
        List.iteri (fun i b -> fx.blocks.(i + 1) <- Some b) blocks;
        List.iter (fun b ->
            match Sync.validate_header state b.Types.header with
            | Ok e -> Sync.accept_header state e
            | Error e -> Alcotest.failf "validate_header: %s" e) blocks;
        state.Sync.blocks_synced <- 0;
        state.Sync.sync_state <- Sync.SyncingBlocks;
        let ibd = Sync.create_ibd_state ~utxo_set:utxo state in
        List.iteri (fun i b ->
            Sync.queue_add ibd
              { Sync.hash = Crypto.compute_block_hash b.Types.header;
                height = i + 1;
                download_state = Sync.Downloaded { block = b; peer_id = None };
                tried_peers = [] }) blocks;
        (match Lwt_main.run
                 (Sync.process_downloaded_blocks ~max_blocks:n ibd)
         with Ok _ -> () | Error e -> Alcotest.failf "prefix: %s" e);
        Sync.flush_utxos ibd;
        Storage.ChainDB.set_chain_tip db fx.prev_hash n;
        Alcotest.(check int) "fixture connected" n
          state.Sync.blocks_synced;
        state.Sync.sync_state <- Sync.FullySynced;
        f fx))

let max_gap_of_ticker ~stop =
  let open Lwt.Syntax in
  let max_gap = ref 0.0 in
  let rec loop last =
    if !stop then Lwt.return_unit
    else
      let* () = Lwt_unix.sleep 0.005 in
      let now = Unix.gettimeofday () in
      max_gap := Float.max !max_gap (now -. last);
      loop now in
  (max_gap, loop (Unix.gettimeofday ()))

let rescan_json ?(start = 0) () =
  json_req "rescanblockchain" [ `Int start ]

let result_of (j : Yojson.Safe.t) =
  match j with
  | `Assoc f -> (match List.assoc_opt "result" f with Some r -> r | None -> `Null)
  | _ -> `Null

let test_rescan_latency () =
  with_fx (fun fx ->
    Rpc.test_rescan_block_cost_s := cost_s;
    let stop = ref false in
    let max_gap, ticker = max_gap_of_ticker ~stop in
    let t0 = Unix.gettimeofday () in
    let resp = ref `Null in
    Lwt_main.run (
      Lwt.join [
        ticker;
        Lwt.map (fun r -> resp := r; stop := true)
          (Rpc.handle_single_request_lwt fx.ctx (rescan_json ()))]);
    let dt = Unix.gettimeofday () -. t0 in
    Printf.printf "  rescan %d blocks: %.3fs total, longest Lwt stall %.3fs\n%!"
      n_blocks dt !max_gap;
    Alcotest.(check string) "rescan answered with its range"
      (Printf.sprintf "{\"start_height\":0,\"stop_height\":%d}" n_blocks)
      (Yojson.Safe.to_string (result_of !resp));
    Alcotest.(check bool)
      (Printf.sprintf "rescan ran long enough to matter (%.3fs)" dt) true
      (dt > 4. *. gap_bound_s);
    Alcotest.(check bool)
      (Printf.sprintf "longest Lwt stall < %.2fs during rescanblockchain (%.3fs)"
         gap_bound_s !max_gap) true (!max_gap < gap_bound_s))

let wallet_summary (w : Wallet.t) =
  let conf, unconf = Wallet.get_balance w in
  (List.length w.Wallet.utxos, conf, unconf)

let test_rescan_equivalence () =
  with_fx (fun fx ->
    (* reference: the unchunked synchronous handler *)
    ignore (Rpc.handle_rescanblockchain fx.ctx [ `Int 0 ]);
    let want = wallet_summary fx.wallet in
    Wallet.clear_for_rescan fx.wallet;
    Rpc.test_rescan_block_cost_s := 0.0005;
    let r = Lwt_main.run
        (Rpc.handle_single_request_lwt fx.ctx (rescan_json ())) in
    ignore r;
    let got = wallet_summary fx.wallet in
    let n, _, _ = got in
    Alcotest.(check int) "every block's coinbase credited" n_blocks n;
    Alcotest.(check bool) "chunked scan == unchunked scan" true (got = want);
    (* partial range, partial rescan keeps the ledger (idempotent) *)
    ignore (Lwt_main.run
              (Rpc.handle_single_request_lwt fx.ctx
                 (json_req "rescanblockchain" [ `Int 100; `Int 200 ])));
    Alcotest.(check bool) "partial rescan idempotent" true
      (wallet_summary fx.wallet = want))

let test_connect_mid_rescan () =
  with_fx (fun fx ->
    Rpc.test_rescan_block_cost_s := cost_s;
    let b = next_block fx in
    (match Sync.validate_header fx.state b.Types.header with
     | Ok e -> Sync.accept_header fx.state e
     | Error e -> Alcotest.failf "validate_header: %s" e);
    let connect_dt = ref infinity in
    let resp = ref `Null in
    Lwt_main.run (
      let open Lwt.Syntax in
      (* The connect's timer is armed BEFORE the rescan is started: the
         rescan call runs synchronously up to its first yield, so on a build
         that never yields it holds the loop past the due time.  Latency is
         counted from when the connect was DUE. *)
      let t_due = Unix.gettimeofday () +. 0.1 in
      let connect =
        let* () = Lwt_unix.sleep 0.1 in
        let* r = Sync.process_new_block ~f_requested:true fx.state b in
        connect_dt := Unix.gettimeofday () -. t_due;
        (match r with Ok () -> () | Error e -> Alcotest.failf "connect: %s" e);
        Lwt.return_unit in
      let rescan =
        Lwt.map (fun r -> resp := r)
          (Rpc.handle_single_request_lwt fx.ctx (rescan_json ())) in
      Lwt.join [ connect; rescan ]);
    Printf.printf "  P2P connect mid-rescan: %.3fs\n%!" !connect_dt;
    Alcotest.(check int) "block connected" (n_blocks + 1)
      fx.state.Sync.blocks_synced;
    Alcotest.(check string) "rescan kept its original range"
      (Printf.sprintf "{\"start_height\":0,\"stop_height\":%d}" n_blocks)
      (Yojson.Safe.to_string (result_of !resp));
    Alcotest.(check bool)
      (Printf.sprintf "connect < %.2fs mid-rescan (%.3fs)" connect_bound_s
         !connect_dt) true (!connect_dt < connect_bound_s))

let test_reorg_mid_rescan () =
  with_fx (fun fx ->
    Rpc.test_rescan_block_cost_s := cost_s;
    let resp = ref `Null in
    Lwt_main.run (
      let open Lwt.Syntax in
      let rescan =
        Lwt.map (fun r -> resp := r)
          (Rpc.handle_single_request_lwt fx.ctx (rescan_json ())) in
      let reorg =
        let* () = Lwt_unix.sleep 0.1 in
        (* the active block at an already-scanned height changes *)
        for h = 5 to n_blocks do
          Storage.ChainDB.set_height_hash fx.state.Sync.db h
            (Crypto.sha256 (Cstruct.of_string "other branch"))
        done;
        Lwt.return_unit in
      Lwt.join [ rescan; reorg ]);
    let s = Yojson.Safe.to_string !resp in
    let has sub =
      let n = String.length sub in
      let rec go i = i + n <= String.length s
                     && (String.sub s i n = sub || go (i + 1)) in go 0 in
    Alcotest.(check bool) ("reorg during rescan is reported: " ^ s) true
      (has "reorganiz"))

(* ---------------------------------------------------------------------
   Live wallet hooks during a sliced rescan.

   The node installs Wallet.scan_block_and_persist / unscan_block_and_persist
   as the block-connect hooks (cli.ml); these run between rescan slices.  The
   finished wallet must match a rescan that ran with nothing concurrent, and
   the file the hooks persist mid-rescan must never be a partial ledger
   marked caught-up.
   --------------------------------------------------------------------- *)

let hook_cost_s = 0.004

let blk fx h = Option.get fx.blocks.(h)
let hash_of (b : Types.block) = Crypto.compute_block_hash b.Types.header

let accept_hdr fx (b : Types.block) =
  match Sync.validate_header fx.state b.Types.header with
  | Ok e -> Sync.accept_header fx.state e
  | Error e -> Alcotest.failf "validate_header: %s" e

let connect_now fx (b : Types.block) =
  accept_hdr fx b;
  match Lwt_main.run (Sync.process_new_block ~f_requested:true fx.state b) with
  | Ok () -> ()
  | Error e -> Alcotest.failf "connect: %s" e

let install_hooks fx (ws : Wallet.t list) =
  Sync.set_wallet_hooks fx.state
    ~on_connect:(fun b h ->
      List.iter (fun w -> Wallet.scan_block_and_persist w b h) ws)
    ~on_disconnect:(fun b h ->
      List.iter (fun w -> Wallet.unscan_block_and_persist w b h) ws)
    ()

(* A synced wallet: every fixture block folded in, caught up, on disk. *)
let populate fx =
  ignore (Rpc.handle_rescanblockchain fx.ctx [ `Int 0 ]);
  fx.wallet.Wallet.last_synced_height <- fx.state.Sync.blocks_synced;
  Wallet.save fx.wallet

let new_script (w : Wallet.t) =
  match Address.address_of_string (Wallet.get_new_address w) with
  | Ok a -> Wallet.build_output_script a
  | Error e -> failwith e

let spend_fee = 1000L

(* Spend the wallet's coinbase from block [h] to [dest], signed by the
   wallet. *)
let spend_coinbase fx h ~dest : Types.transaction =
  let cb = List.hd (blk fx h).Types.transactions in
  let out = List.hd cb.Types.outputs in
  let prev = { Types.txid = Crypto.compute_txid cb; vout = 0l } in
  let unsigned =
    { Types.version = 2l;
      inputs = [ { Types.previous_output = prev; script_sig = Cstruct.create 0;
                   sequence = 0xFFFFFFFFl } ];
      outputs = [ { Types.value = Int64.sub out.Types.value spend_fee;
                    script_pubkey = dest } ];
      witnesses = []; locktime = 0l } in
  let wu = { Wallet.outpoint = prev;
             utxo = { Utxo.value = out.Types.value;
                      script_pubkey = out.Types.script_pubkey;
                      height = h; is_coinbase = true };
             key_index = 0; confirmed = true; watch_only = false } in
  Wallet.sign_transaction_inputs fx.wallet unsigned [ wu ]

type ledger = {
  coins : (string * int32 * int64 * bool) list;
  conf : int64;
  unconf : int64;
  history : Wallet.tx_history_entry list;
}

let ledger_of (w : Wallet.t) =
  { coins = List.sort compare
        (List.map (fun (u : Wallet.wallet_utxo) ->
             (Cstruct.to_string u.outpoint.Types.txid, u.outpoint.Types.vout,
              u.utxo.Utxo.value, u.confirmed)) w.Wallet.utxos);
    conf = w.Wallet.balance_confirmed;
    unconf = w.Wallet.balance_unconfirmed;
    history = List.sort compare w.Wallet.tx_history }

(* What the wallet must hold: the synchronous handler over the active chain,
   nothing running beside it.  Overwrites the wallet (and its file). *)
let reference fx =
  Wallet.clear_for_rescan fx.wallet;
  ignore (Rpc.handle_rescanblockchain fx.ctx [ `Int 0 ]);
  ledger_of fx.wallet

let has_coin (l : ledger) (txid : Types.hash256) vout =
  List.length (List.filter (fun (t, v, _, _) ->
      t = Cstruct.to_string txid && v = vout) l.coins)

let check_ledger what (want : ledger) (got : ledger) =
  Alcotest.(check int) (what ^ ": coin count") (List.length want.coins)
    (List.length got.coins);
  Alcotest.(check bool) (what ^ ": coins == no-concurrency rescan") true
    (want.coins = got.coins);
  Alcotest.(check int64) (what ^ ": confirmed balance") want.conf got.conf;
  Alcotest.(check int64) (what ^ ": unconfirmed balance") want.unconf
    got.unconf;
  Alcotest.(check bool) (what ^ ": history == no-concurrency rescan") true
    (want.history = got.history)

(* Start a from-genesis rescan through the HTTP entry point and, [delay]
   seconds in, run [mid] (a P2P connect).  [mid_done] runs right after [mid]
   returns, while the rescan must still be in flight.  Returns the rescan's
   response and how long after the rescan started [mid] had finished. *)
let rescan_with_mid fx ~delay ~(mid : unit -> unit Lwt.t)
    ~(mid_done : unit -> unit) =
  let resp = ref `Null in
  let mid_at = ref infinity in
  Lwt_main.run (
    let open Lwt.Syntax in
    let t0 = Unix.gettimeofday () in
    let side =
      let* () = Lwt_unix.sleep delay in
      let* () = mid () in
      mid_at := Unix.gettimeofday () -. t0;
      Alcotest.(check bool) "rescan still running when the connect returned"
        true (!resp = `Null);
      mid_done ();
      Lwt.return_unit in
    let rescan =
      Lwt.map (fun r -> resp := r)
        (Rpc.handle_single_request_lwt fx.ctx (rescan_json ())) in
    Lwt.join [ side; rescan ]);
  (!resp, !mid_at)

let process fx b () =
  accept_hdr fx b;
  Lwt.map (function Ok () -> () | Error e -> Alcotest.failf "connect: %s" e)
    (Sync.process_new_block ~f_requested:true fx.state b)

(* The spend of the height-[spent_h] coinbase landed while the rescan had not
   yet reached height [spent_h]: each block costs [hook_cost_s] of blocking
   time, so by [mid_at] at most mid_at / cost blocks were scanned. *)
let check_before_creator ~spent_h mid_at =
  Alcotest.(check bool)
    (Printf.sprintf "connect finished before the rescan reached %d (%.3fs)"
       spent_h mid_at) true
    (mid_at < float_of_int spent_h *. hook_cost_s)

let spent_h = 200

(* A start-0 rescan; mid-scan, block n+1 spends the wallet's height-200
   coinbase (not yet rescanned) to a second wallet address.  [mid_done]
   sees the state at that yield. *)
let run_spend_mid_rescan ?(mid_done = fun _ _ -> ()) fx =
  install_hooks fx [ fx.wallet ];
  populate fx;
  let pay = new_script fx.wallet in
  let tx = spend_coinbase fx spent_h ~dest:pay in
  let b = next_block ~txs:[ tx ] ~fee:spend_fee fx in
  Rpc.test_rescan_block_cost_s := hook_cost_s;
  let resp, mid_at =
    rescan_with_mid fx ~delay:0.02 ~mid:(process fx b)
      ~mid_done:(fun () -> mid_done tx b) in
  Rpc.test_rescan_block_cost_s := 0.0;
  check_before_creator ~spent_h mid_at;
  (resp, tx)

let check_spend_outcome fx ~resp ~(tx : Types.transaction) ~stop =
  Alcotest.(check string) "rescan answered with its original range"
    (Printf.sprintf "{\"start_height\":0,\"stop_height\":%d}" stop)
    (Yojson.Safe.to_string (result_of resp));
  let lsh = fx.wallet.Wallet.last_synced_height in
  let got = ledger_of fx.wallet in
  let spent = Crypto.compute_txid (List.hd (blk fx spent_h).Types.transactions) in
  let paid = Crypto.compute_txid tx in
  Alcotest.(check int) "spent coinbase is gone" 0 (has_coin got spent 0l);
  Alcotest.(check int) "payment credited exactly once" 1 (has_coin got paid 0l);
  let want = reference fx in
  check_ledger "after the rescan" want got;
  Alcotest.(check int) "last_synced_height == tip the ledger covers"
    fx.state.Sync.blocks_synced lsh

let test_hook_spend_mid_rescan () =
  with_fx (fun fx ->
    let resp, tx = run_spend_mid_rescan fx in
    check_spend_outcome fx ~resp ~tx ~stop:n_blocks)

(* The connect hook save_safe's the wallet at the yield.  Reloading that file
   must give a wallet that is either behind (and so reconciled on restart) or
   complete -- never caught up with coins missing. *)
let test_hook_save_reload_mid_rescan () =
  with_fx (fun fx ->
    let loaded = ref None in
    let resp, tx =
      run_spend_mid_rescan fx ~mid_done:(fun _ _ ->
          let db_path = Filename.concat fx.path "wallet.db" in
          let w = Wallet.load ~network:`Regtest ~db_path in
          loaded := Some (w.Wallet.last_synced_height, ledger_of w)) in
    ignore resp;
    let lsh, on_disk = Option.get !loaded in
    let spent = Crypto.compute_txid (List.hd (blk fx spent_h).Types.transactions) in
    let want = reference fx in
    Alcotest.(check int) "reloaded wallet marked synced to the new tip"
      fx.state.Sync.blocks_synced lsh;
    Alcotest.(check int) "reloaded: spent coinbase is gone" 0
      (has_coin on_disk spent 0l);
    Alcotest.(check int) "reloaded: payment present once" 1
      (has_coin on_disk (Crypto.compute_txid tx) 0l);
    check_ledger "wallet file at the yield" want on_disk)

(* Reorg between slices, above the scanned part: block n is replaced by n'
   (stored first, equal work) and n+1' -- which spends the height-200
   coinbase -- makes the switch while the rescan is still below 200. *)
let test_hook_reorg_tip_mid_rescan () =
  with_fx (fun fx ->
    install_hooks fx [ fx.wallet ];
    populate fx;
    let other = new_script fx.wallet and pay = new_script fx.wallet in
    fx.prev_hash <- hash_of (blk fx (n_blocks - 1));
    fx.prev_time <- (blk fx (n_blocks - 1)).Types.header.Types.timestamp;
    fx.height <- n_blocks - 1;
    let b_n' = next_block ~payout:other fx in
    connect_now fx b_n';
    Alcotest.(check bool) "n' stored as a side branch" true
      (Storage.ChainDB.get_hash_at_height fx.state.Sync.db n_blocks
       = Some (hash_of (blk fx n_blocks)));
    let tx = spend_coinbase fx spent_h ~dest:pay in
    let b_n1' = next_block ~txs:[ tx ] ~fee:spend_fee fx in
    Rpc.test_rescan_block_cost_s := hook_cost_s;
    let resp, mid_at =
      rescan_with_mid fx ~delay:0.02 ~mid:(process fx b_n1')
        ~mid_done:(fun () -> ()) in
    Rpc.test_rescan_block_cost_s := 0.0;
    check_before_creator ~spent_h mid_at;
    Alcotest.(check bool) "reorged onto n'" true
      (Storage.ChainDB.get_hash_at_height fx.state.Sync.db n_blocks
       = Some (hash_of b_n'));
    check_spend_outcome fx ~resp ~tx ~stop:n_blocks)

(* Reorg between slices INTO the scanned part: the branch forks at height 3,
   below what the rescan has already scanned.  The rescan must report it and
   leave the live wallet exactly as the hooks moved it -- the same as a
   control wallet that saw the same hooks and no rescan -- not a partial
   rebuild. *)
let reorg_n = 40
let reorg_cost_s = 0.02

let test_hook_reorg_scanned_mid_rescan () =
  with_fx ~n:reorg_n (fun fx ->
    populate fx;
    let other = new_script fx.wallet in
    (* Copied after every key exists: the control owns what the wallet owns. *)
    let control =
      { fx.wallet with Wallet.db_path = Filename.concat fx.path "control.db";
                       utxos = fx.wallet.Wallet.utxos } in
    install_hooks fx [ fx.wallet; control ];
    let fork = 3 in
    fx.prev_hash <- hash_of (blk fx fork);
    fx.prev_time <- (blk fx fork).Types.header.Types.timestamp;
    fx.height <- fork;
    for _ = fork + 1 to reorg_n do connect_now fx (next_block ~payout:other fx) done;
    Alcotest.(check int) "equal-work branch stored, no reorg yet" reorg_n
      fx.state.Sync.blocks_synced;
    Alcotest.(check bool) "main chain still active" true
      (Storage.ChainDB.get_hash_at_height fx.state.Sync.db reorg_n
       = Some (hash_of (blk fx reorg_n)));
    let tip' = next_block ~payout:other fx in
    Rpc.test_rescan_block_cost_s := reorg_cost_s;
    let resp, mid_at =
      rescan_with_mid fx ~delay:0.2 ~mid:(process fx tip')
        ~mid_done:(fun () -> ()) in
    Rpc.test_rescan_block_cost_s := 0.0;
    Printf.printf "  reorg landed %.3fs into the rescan\n%!" mid_at;
    Alcotest.(check int) "reorged onto the branch" (reorg_n + 1)
      fx.state.Sync.blocks_synced;
    let s = Yojson.Safe.to_string resp in
    let has sub =
      let n = String.length sub in
      let rec go i = i + n <= String.length s
                     && (String.sub s i n = sub || go (i + 1)) in go 0 in
    Alcotest.(check bool) ("reorg into scanned heights is reported: " ^ s) true
      (has "reorganiz");
    let got = ledger_of fx.wallet in
    let lsh = fx.wallet.Wallet.last_synced_height in
    check_ledger "live wallet == control (hooks only, no rescan)"
      (ledger_of control) got;
    Alcotest.(check int) "last_synced_height == control's"
      control.Wallet.last_synced_height lsh;
    Alcotest.(check int) "last_synced_height == tip" (reorg_n + 1) lsh;
    let want = reference fx in
    Alcotest.(check bool) "coins == no-concurrency rescan" true
      (want.coins = got.coins);
    Alcotest.(check int64) "confirmed balance == no-concurrency rescan"
      want.conf got.conf)

let () =
  Alcotest.run "writer_chunk" [
    "rescanblockchain", [
      Alcotest.test_case "does not starve the Lwt loop" `Quick
        test_rescan_latency;
      Alcotest.test_case "chunked == unchunked" `Quick test_rescan_equivalence;
      Alcotest.test_case "P2P connect mid-rescan" `Quick
        test_connect_mid_rescan;
      Alcotest.test_case "reorg between slices is reported" `Quick
        test_reorg_mid_rescan;
    ];
    "rescanblockchain + live wallet hooks", [
      Alcotest.test_case "spend connected before its creator is rescanned"
        `Quick test_hook_spend_mid_rescan;
      Alcotest.test_case "wallet file saved at a yield is never partial"
        `Quick test_hook_save_reload_mid_rescan;
      Alcotest.test_case "reorg at the tip, spend, between slices" `Quick
        test_hook_reorg_tip_mid_rescan;
      Alcotest.test_case "reorg into scanned heights between slices" `Quick
        test_hook_reorg_scanned_mid_rescan;
    ];
  ]
