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

let make_block ~payout ~prev_hash ~prev_time ~height : Types.block =
  let extra_nonce = Cstruct.create 8 in
  Cstruct.LE.set_uint64 extra_nonce 0 (Int64.of_int height);
  let mk wr =
    Mining.create_coinbase ~height ~total_fee:0L ~payout_script:payout
      ~extra_nonce ~witness_root:wr ~network_type:Consensus.Regtest ()
  in
  let wr = Mining.compute_witness_merkle_root [ mk None ] in
  let coinbase = mk (Some wr) in
  let merkle_root, _ = Crypto.merkle_root [ Crypto.compute_txid coinbase ] in
  remine { Types.header = { version = 4l; prev_block = prev_hash; merkle_root;
                            timestamp = Int32.add prev_time 600l;
                            bits = Consensus.regtest.pow_limit; nonce = 0l };
           transactions = [ coinbase ] }

let json_req m params : Yojson.Safe.t =
  `Assoc [ ("jsonrpc", `String "1.0"); ("id", `String "t");
           ("method", `String m); ("params", `List params) ]

type fx = {
  state : Sync.chain_state;
  ctx : Rpc.rpc_context;
  wallet : Wallet.t;
  payout : Cstruct.t;
  mutable prev_hash : Types.hash256;
  mutable prev_time : int32;
  mutable height : int;
}

let next_block fx =
  let b = make_block ~payout:fx.payout ~prev_hash:fx.prev_hash
      ~prev_time:fx.prev_time ~height:(fx.height + 1) in
  fx.prev_hash <- Crypto.compute_block_hash b.Types.header;
  fx.prev_time <- b.Types.header.Types.timestamp;
  fx.height <- fx.height + 1;
  b

(* [n_blocks] blocks whose coinbase pays the wallet, connected through the
   catch-up path, then FullySynced. *)
let with_fx f =
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
        let fx = { state; ctx; wallet; payout;
                   prev_hash = genesis.Sync.hash;
                   prev_time = genesis.Sync.header.Types.timestamp;
                   height = 0 } in
        let blocks = List.init n_blocks (fun _ -> next_block fx) in
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
                 (Sync.process_downloaded_blocks ~max_blocks:n_blocks ibd)
         with Ok _ -> () | Error e -> Alcotest.failf "prefix: %s" e);
        Sync.flush_utxos ibd;
        Storage.ChainDB.set_chain_tip db fx.prev_hash n_blocks;
        Alcotest.(check int) "fixture connected" n_blocks
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
      let rescan =
        Lwt.map (fun r -> resp := r)
          (Rpc.handle_single_request_lwt fx.ctx (rescan_json ())) in
      let connect =
        let* () = Lwt_unix.sleep 0.1 in   (* rescan is under way *)
        let t0 = Unix.gettimeofday () in
        let* r = Sync.process_new_block ~f_requested:true fx.state b in
        connect_dt := Unix.gettimeofday () -. t0;
        (match r with Ok () -> () | Error e -> Alcotest.failf "connect: %s" e);
        Lwt.return_unit in
      Lwt.join [ rescan; connect ]);
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
        Storage.ChainDB.set_height_hash fx.state.Sync.db 5
          (Crypto.sha256 (Cstruct.of_string "other branch"));
        Lwt.return_unit in
      Lwt.join [ rescan; reorg ]);
    let s = Yojson.Safe.to_string !resp in
    let has sub =
      let n = String.length sub in
      let rec go i = i + n <= String.length s
                     && (String.sub s i n = sub || go (i + 1)) in go 0 in
    Alcotest.(check bool) ("reorg during rescan is reported: " ^ s) true
      (has "reorganiz"))

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
  ]
