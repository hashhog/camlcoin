(* RPC latency under a sync-connect loop (chain-lock receipt instrument).

   The Lwt thread connects a stream of pre-mined blocks through
   Sync.process_new_block with the post-IBD Validation_worker, the way the
   P2P BlockMsg listener does.  Meanwhile three client streams issue RPCs
   through Rpc.handle_single_request_lwt (the HTTP server's entry point, no
   socket):
     monitoring  getblockcount            (Lwt loop on every build)
     reader      getblockheader <tip>     (pool thread on every build)
     writer      testmempoolaccept <tx>   (pool on d4e6f77, main thread on
                                           the chain-lock fix)
   Reports p50 / p99 / max per stream, blocks/s, heap and RSS.  Not part of
   the default test run:
     dune exec --no-buffer test/bench_rpc_latency.exe -- [blocks] [txs/block]
*)

open Camlcoin
open Lwt.Syntax

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

(* a 1-in, [n_out]-out OP_TRUE spend *)
let spend ?(fee = 1000L) ~n_out (prev : Types.hash256) vout (value : int64) =
  let each = Int64.div (Int64.sub value fee) (Int64.of_int n_out) in
  { Types.version = 2l;
    inputs = [ { Types.previous_output = { Types.txid = prev; vout = Int32.of_int vout };
                 script_sig = Cstruct.create 0; sequence = 0xFFFFFFFFl } ];
    outputs = List.init n_out (fun _ -> { Types.value = each; script_pubkey = op_true });
    witnesses = []; locktime = 0l }

let hex s =
  String.concat "" (List.init (String.length s)
                      (fun i -> Printf.sprintf "%02x" (Char.code s.[i])))

let tx_hex tx =
  let w = Serialize.writer_create () in
  Serialize.serialize_transaction w tx; hex (Serialize.writer_to_string w)

let pct (l : float list) p =
  match List.sort compare l with
  | [] -> nan
  | s -> let a = Array.of_list s in
    a.(min (Array.length a - 1) (int_of_float (p *. float (Array.length a))))

let rss_mb () =
  try
    let ic = open_in "/proc/self/status" in
    let rec go () =
      match input_line ic with
      | l when String.length l > 6 && String.sub l 0 6 = "VmRSS:" ->
        close_in ic; Scanf.sscanf (String.sub l 6 (String.length l - 6)) " %d" (fun k -> float k /. 1024.)
      | _ -> go ()
      | exception End_of_file -> close_in ic; nan
    in go ()
  with _ -> nan

let () =
  let n_blocks = try int_of_string Sys.argv.(1) with _ -> 300 in
  let txs_per_block = try int_of_string Sys.argv.(2) with _ -> 20 in
  Test_tmp.with_dir ~label:"bench_rpc" ~mkdir:true (fun path ->
    let db = Storage.ChainDB.create path in
    let state = Sync.create_chain_state db Consensus.regtest in
    let genesis = Option.get state.Sync.tip in
    let utxo = Utxo.OptimizedUtxoSet.create ~cache_size:100_000 db in
    Sync.shared_utxo_set := Some utxo;
    let mp = Mempool.create ~network:Consensus.regtest ~require_standard:false
        ~verify_scripts:false ~utxo:(Utxo.UtxoSet.create db)
        ~current_height:0 () in
    let ctx : Rpc.rpc_context =
      { chain = state; mempool = mp;
        peer_manager = Peer_manager.create Consensus.regtest;
        wallet = None; wallet_manager = None;
        fee_estimator = Fee_estimation.create ();
        network = Consensus.regtest; filter_index = None; utxo = Some utxo;
        data_dir = None; snapshot_activation = None } in
    (* Pre-mine: 110 maturing blocks, then [n_blocks] blocks each carrying
       [txs_per_block] spends of a fan-out created at 101. *)
    let prev = ref genesis.Sync.hash and time = ref genesis.Sync.header.Types.timestamp in
    let cb = Hashtbl.create 1024 in
    let mk h ?fee txs =
      let b = make_block ~prev_hash:!prev ~prev_time:!time ~height:h ?fee txs in
      prev := Crypto.compute_block_hash b.Types.header;
      time := b.Types.header.Types.timestamp;
      Hashtbl.replace cb h (Crypto.compute_txid (List.hd b.Types.transactions));
      b in
    let subsidy = Consensus.block_subsidy_for_network Consensus.Regtest 1 in
    let warm = List.init 110 (fun i -> mk (i + 1) []) in
    let need = n_blocks * txs_per_block + 1 in
    let fan_n = (need / 10) + 1 in
    (* fan-out: block 111 spends coinbase 1 into [fan_n] outputs, each of
       which block 112 splits into 10 *)
    let fan = spend ~n_out:fan_n (Hashtbl.find cb 1) 0 subsidy in
    let fan_id = Crypto.compute_txid fan in
    let b111 = mk 111 ~fee:1000L [ fan ] in
    let each = Int64.div (Int64.sub subsidy 1000L) (Int64.of_int fan_n) in
    let splits = List.init fan_n (fun i -> spend ~fee:100L ~n_out:10 fan_id i each) in
    let b112 = mk 112 ~fee:(Int64.mul 100L (Int64.of_int fan_n)) splits in
    let coins = Queue.create () in
    List.iter (fun t ->
        let id = Crypto.compute_txid t in
        for v = 0 to 9 do Queue.add (id, v) coins done) splits;
    let each2 = Int64.div (Int64.sub each 100L) 10L in
    let stream = List.init n_blocks (fun i ->
        let txs = List.init txs_per_block (fun _ ->
            let (id, v) = Queue.pop coins in
            spend ~fee:100L ~n_out:1 id v each2) in
        mk (113 + i) ~fee:(Int64.mul 100L (Int64.of_int txs_per_block)) txs) in
    (* a tx for testmempoolaccept: spends a coin no block in the stream uses *)
    let (tid, tv) = Queue.pop coins in
    let probe_tx = tx_hex (spend ~fee:500L ~n_out:1 tid tv each2) in
    state.Sync.sync_state <- Sync.FullySynced;
    List.iter (fun b ->
        match Lwt_main.run (Sync.process_new_block ~f_requested:true state b) with
        | Ok () -> () | Error e -> failwith ("warm: " ^ e))
      (warm @ [ b111; b112 ]);
    let worker = Sync.Validation_worker.create () in
    Sync.Validation_worker.ensure_tip_script_pool ();
    let req m params = `Assoc [ ("jsonrpc", `String "1.0"); ("id", `Int 1);
                                ("method", `String m); ("params", `List params) ] in
    let lat = Hashtbl.create 3 in
    let note k dt = Hashtbl.replace lat k (dt :: (try Hashtbl.find lat k with Not_found -> [])) in
    let done_ = ref false in
    let client name mk_req =
      let rec loop () =
        if !done_ then Lwt.return_unit
        else begin
          let t0 = Unix.gettimeofday () in
          let* _ = Rpc.handle_single_request_lwt ctx (mk_req ()) in
          note name (Unix.gettimeofday () -. t0);
          let* () = Lwt_unix.sleep 0.002 in
          loop ()
        end in
      loop () in
    let t_start = Unix.gettimeofday () in
    let connect_loop =
      let* () = Lwt_list.iter_s (fun b ->
          let* r = Sync.process_new_block ~f_requested:true ~worker state b in
          (match r with Ok () -> () | Error e -> failwith ("stream: " ^ e));
          Lwt.pause ()) stream in
      done_ := true; Lwt.return_unit in
    let tip_hex () =
      match Sync.block_tip state with
      | Some t -> `String (Types.hash256_to_hex_display t.Sync.hash)
      | None -> `Null in
    Lwt_main.run (Lwt.join [
        connect_loop;
        client "monitoring getblockcount" (fun () -> req "getblockcount" []);
        client "reader getblockheader" (fun () -> req "getblockheader" [ tip_hex () ]);
        client "writer testmempoolaccept" (fun () ->
            req "testmempoolaccept" [ `List [ `String probe_tx ] ]);
      ]);
    let elapsed = Unix.gettimeofday () -. t_start in
    Sync.Validation_worker.shutdown worker;
    Printf.printf "blocks=%d txs/block=%d elapsed=%.2fs (%.1f blk/s) tip=%d\n"
      n_blocks txs_per_block elapsed (float n_blocks /. elapsed)
      state.Sync.blocks_synced;
    Hashtbl.iter (fun k l ->
        let ms x = 1000. *. x in
        Printf.printf "%-28s n=%5d p50=%7.2fms p99=%7.2fms max=%7.2fms\n" k
          (List.length l) (ms (pct l 0.5)) (ms (pct l 0.99))
          (ms (List.fold_left max 0. l))) lat;
    let st = Gc.quick_stat () in
    Printf.printf "heap=%.1fMB top_heap=%.1fMB rss=%.1fMB major_collections=%d\n"
      (float st.Gc.heap_words *. 8. /. 1048576.)
      (float st.Gc.top_heap_words *. 8. /. 1048576.) (rss_mb ())
      st.Gc.major_collections;
    Sync.shared_utxo_set := None;
    Storage.ChainDB.close db)
