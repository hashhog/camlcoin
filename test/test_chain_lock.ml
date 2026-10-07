(* Chain lock: RPC chain/mempool writers vs the sync connect path
   (receipts/arch-concurrency-liveness-audit-2026-10-07.md, camlcoin CC-1,
   CC-1a, CC-1b, CC-1d, CC-2).

   Since 34cd72c every non-monitoring RPC runs on an Lwt_preemptive
   systhread.  Systhreads of the main domain are preempted at every
   allocation once the 50 ms tick fires and at every blocking section, so
   the Lwt event loop is NOT an implicit lock for them: a handler that
   mutates the chain, the coin cache or the mempool interleaves with the
   P2P connect path at arbitrary points.  Core serialises all of these
   under cs_main (validation.cpp ProcessNewBlock / ActivateBestChain /
   InvalidateBlock; rpc/blockchain.cpp dumptxoutset holds NetworkDisable
   + TemporaryRollback around the rewind).

   Every case is DETERMINISTIC on the deployed build: the RPC thread is
   parked at an interleaving point that already exists in d4e6f77
   (Utxo.OptimizedUtxoSet.after_db_read_hook, Utxo.UtxoSet.tip_view,
   Fatal.write_fault_hook) and only on a NON-main thread, while the test
   runs a real P2P connect (Sync.process_new_block) on the Lwt thread.
   When the handler runs on the main thread (the fix) the hook never
   parks; the cases then assert the end state is one Core could reach.

     dune exec --no-buffer test/test_chain_lock.exe
*)

open Camlcoin

let main_tid = Thread.id (Thread.self ())
let on_main () = Thread.id (Thread.self ()) = main_tid

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

let hex_of_string s =
  String.concat "" (List.init (String.length s)
                      (fun i -> Printf.sprintf "%02x" (Char.code s.[i])))

let block_hex (b : Types.block) =
  let w = Serialize.writer_create () in
  Serialize.serialize_block w b;
  hex_of_string (Serialize.writer_to_string w)

let tx_hex (tx : Types.transaction) =
  let w = Serialize.writer_create () in
  Serialize.serialize_transaction w tx;
  hex_of_string (Serialize.writer_to_string w)

let hash_of (b : Types.block) = Crypto.compute_block_hash b.Types.header
let cb_txid (b : Types.block) = Crypto.compute_txid (List.hd b.Types.transactions)

let queue ibd (b : Types.block) h =
  Sync.queue_add ibd
    { Sync.hash = hash_of b; height = h;
      download_state = Sync.Downloaded { block = b; peer_id = None };
      tried_peers = [] }

let json_req method_name params : Yojson.Safe.t =
  `Assoc [ ("jsonrpc", `String "1.0"); ("id", `String "t");
           ("method", `String method_name); ("params", `List params) ]

let show_resp (j : Yojson.Safe.t) = Yojson.Safe.to_string j

(* ------------------------------------------------------------------ gate *)

(* A one-shot barrier a NON-main thread parks on. *)
type gate = {
  m : Mutex.t;
  mutable reached : bool;
  mutable released : bool;
  mutable fired_on_main : int;
}

let new_gate () =
  { m = Mutex.create (); reached = false; released = false; fired_on_main = 0 }

let poll ~what ?(timeout = 60.0) (pred : unit -> bool) =
  let deadline = Unix.gettimeofday () +. timeout in
  let rec loop () =
    if pred () then ()
    else if Unix.gettimeofday () > deadline then
      failwith ("chain-lock test: timed out waiting for " ^ what)
    else (Unix.sleepf 0.002; loop ())
  in
  loop ()

let gate_get g f = Mutex.lock g.m; let v = f g in Mutex.unlock g.m; v

(* Park the calling thread if it is not the main thread and the gate has
   not been used yet.  On the main thread only count the event. *)
let park_here g =
  if on_main () then
    gate_get g (fun g -> g.fired_on_main <- g.fired_on_main + 1)
  else begin
    let first = gate_get g (fun g ->
        let first = not g.reached in
        if first then g.reached <- true; first) in
    if first then
      poll ~what:"release" (fun () -> gate_get g (fun g -> g.released))
  end

let release g = gate_get g (fun g -> g.released <- true)

(* --------------------------------------------------------------- fixture *)

type fx = {
  db : Storage.ChainDB.t;
  state : Sync.chain_state;
  utxo : Utxo.OptimizedUtxoSet.t;
  mp : Mempool.mempool;
  ctx : Rpc.rpc_context;
  cb : Types.hash256 array;            (* coinbase txid by height *)
  blocks : (int, Types.block) Hashtbl.t;   (* block by height *)
  mutable prev_hash : Types.hash256;
  mutable prev_time : int32;
}

let subsidy = Consensus.block_subsidy_for_network Consensus.Regtest 1

(* Build a block on the fixture's current build tip (no connect). *)
let build fx ?fee ?tag h txs =
  let b = make_block ~prev_hash:fx.prev_hash ~prev_time:fx.prev_time
      ~height:h ?fee ?tag txs in
  fx.prev_hash <- hash_of b;
  fx.prev_time <- b.Types.header.Types.timestamp;
  fx.cb.(h) <- cb_txid b;
  Hashtbl.replace fx.blocks h b;
  b

(* 101 blocks through the catch-up path, flushed; then FullySynced.  The
   coin cache holds 50 entries so the low coinbases are store-only. *)
let with_fx ~label ?(cache = 50) f =
  Test_tmp.with_dir ~label ~mkdir:true (fun path ->
    let db = Storage.ChainDB.create path in
    Fun.protect ~finally:(fun () ->
        Atomic.set Utxo.OptimizedUtxoSet.after_db_read_hook (fun _ -> ());
        Fatal.write_fault_hook := None;
        Rpc.test_sync_sleep_s := 0.0;
        Sync.shared_utxo_set := None;
        try Storage.ChainDB.close db with _ -> ())
      (fun () ->
        let state = Sync.create_chain_state db Consensus.regtest in
        let genesis = Option.get state.Sync.tip in
        let utxo = Utxo.OptimizedUtxoSet.create ~cache_size:cache db in
        Sync.shared_utxo_set := Some utxo;
        let mp_utxo = Utxo.UtxoSet.create db in
        let network = Consensus.regtest in
        let mp = Mempool.create ~network ~require_standard:false
            ~verify_scripts:false ~utxo:mp_utxo ~current_height:101 () in
        let ctx : Rpc.rpc_context =
          { chain = state; mempool = mp;
            peer_manager = Peer_manager.create network;
            wallet = None; wallet_manager = None;
            fee_estimator = Fee_estimation.create ();
            network; filter_index = None; utxo = Some utxo; data_dir = None;
            snapshot_activation = None } in
        let fx = { db; state; utxo; mp; ctx;
                   cb = Array.make 200 Types.zero_hash;
                   blocks = Hashtbl.create 256;
                   prev_hash = genesis.Sync.hash;
                   prev_time = genesis.Sync.header.Types.timestamp } in
        let prefix = List.init 101 (fun i ->
            let b = build fx (i + 1) [] in
            (match Sync.validate_header state b.Types.header with
             | Ok e -> Sync.accept_header state e
             | Error e -> Alcotest.failf "validate_header: %s" e);
            b) in
        state.Sync.blocks_synced <- 0;
        state.Sync.sync_state <- Sync.SyncingBlocks;
        let ibd = Sync.create_ibd_state ~utxo_set:utxo state in
        List.iteri (fun i b -> queue ibd b (i + 1)) prefix;
        (match Lwt_main.run (Sync.process_downloaded_blocks ~max_blocks:101 ibd)
         with Ok _ -> () | Error e -> Alcotest.failf "prefix: %s" e);
        Sync.flush_utxos ibd;
        Storage.ChainDB.set_chain_tip db fx.prev_hash 101;
        Alcotest.(check int) "fixture: 101 connected" 101 state.Sync.blocks_synced;
        state.Sync.sync_state <- Sync.FullySynced;
        Sync.set_mempool_remove_hook state
          (Some (fun b h -> Mempool.remove_for_block mp b h));
        f fx))

(* The chain's coin view: the shared cache over the store. *)
let coin fx txid vout =
  match Utxo.OptimizedUtxoSet.peek_mem fx.utxo txid vout with
  | Utxo.OptimizedUtxoSet.Mem_hit _ -> true
  | Utxo.OptimizedUtxoSet.Mem_removed -> false
  | Utxo.OptimizedUtxoSet.Mem_miss ->
    Storage.ChainDB.get_utxo fx.db txid vout <> None

let active_at fx h =
  if h > fx.state.Sync.blocks_synced then None
  else Storage.ChainDB.get_hash_at_height fx.db h

let pnb fx b =
  Sync.process_new_block ~f_requested:true fx.state b

let connect_now fx b =
  match Lwt_main.run (pnb fx b) with
  | Ok () -> ()
  | Error e -> Alcotest.failf "connect %d: %s" fx.state.Sync.blocks_synced e

(* --------------------------------------------- CC-1 / CC-1a: submitblock *)

(* H and H' are siblings at 102 (disjoint inputs).  The RPC submits H and
   is parked right after its store read of H's input C; the P2P path
   connects H' meanwhile.  Core: one of them is the tip and the coin set
   is exactly that block's.  Deployed: submit_block never re-checks the
   tip after validation, so H is applied ON TOP of H' (tip H, coins of
   both). *)
let submitblock_race ~direct =
  with_fx ~label:"cl_submitblock" (fun fx ->
    let c = fx.cb.(1) and d = fx.cb.(2) in
    let save_prev = fx.prev_hash and save_time = fx.prev_time in
    let h = build fx ~fee:1000L ~tag:1 102 [ spend ~tag:1 c subsidy ] in
    fx.prev_hash <- save_prev; fx.prev_time <- save_time;
    let h' = build fx ~fee:1000L ~tag:2 102 [ spend ~tag:2 d subsidy ] in
    Alcotest.(check bool) "precondition: C is a store read (cache miss)" true
      (Utxo.OptimizedUtxoSet.peek_mem fx.utxo c 0
       = Utxo.OptimizedUtxoSet.Mem_miss);
    let g = new_gate () in
    let c_key = Utxo.OptimizedUtxoSet.utxo_key c 0 in
    Atomic.set Utxo.OptimizedUtxoSet.after_db_read_hook (fun key ->
        if String.equal key c_key then park_here g);
    let rpc_done = Atomic.make false in
    let rpc_resp = ref `Null in
    let competitor_r = ref "not run" in
    Lwt_main.run (
      let rpc =
        if direct then
          (* Mining.submit_block called from a non-main thread: the
             defensive tip re-check is the only guard left. *)
          Lwt.map (fun r ->
              rpc_resp := (match r with
                  | Ok () -> `String "accepted"
                  | Error e -> `String ("error: " ^ e));
              Atomic.set rpc_done true)
            (Lwt_preemptive.detach (fun () ->
                 Mining.submit_block ~utxo:fx.utxo
                   ~network_type:Consensus.Regtest h fx.state fx.mp) ())
        else
        Lwt.map (fun r -> rpc_resp := r; Atomic.set rpc_done true)
          (Rpc.handle_single_request_lwt fx.ctx
             (json_req "submitblock" [ `String (block_hex h) ])) in
      let competitor =
        let%lwt () = Lwt_preemptive.detach (fun () ->
            poll ~what:"rpc parked or done" (fun () ->
                gate_get g (fun g -> g.reached) || Atomic.get rpc_done)) () in
        let%lwt r = pnb fx h' in
        competitor_r := (match r with Ok () -> "ok" | Error e -> e);
        release g;
        Lwt.return_unit
      in
      Lwt.join [ rpc; competitor ]);
    let tip = active_at fx 102 in
    let is x = match tip with Some t -> Cstruct.equal t (hash_of x) | None -> false in
    let hc = coin fx (cb_txid h) 0 and hc' = coin fx (cb_txid h') 0 in
    let cs = not (coin fx c 0) and ds = not (coin fx d 0) in
    Printf.printf
      "  submitblock race: parked=%b fired-on-main=%d rpc=%s competitor=%s\n\
      \  tip102=%s blocks_synced=%d  H.cb=%b H'.cb=%b C-spent=%b D-spent=%b\n%!"
      g.reached g.fired_on_main (show_resp !rpc_resp) !competitor_r
      (if is h then "H" else if is h' then "H'" else "none")
      fx.state.Sync.blocks_synced hc hc' cs ds;
    Alcotest.(check int) "one block at 102" 102 fx.state.Sync.blocks_synced;
    let consistent =
      (is h && hc && cs && (not hc') && not ds)
      || (is h' && hc' && ds && (not hc) && not cs) in
    Alcotest.(check bool)
      "coin view is exactly the active block's (no block applied on top of \
       its sibling)" true consistent)

let test_submitblock_race () = submitblock_race ~direct:false
let test_submit_block_recheck () = submitblock_race ~direct:true

(* --------------------------------------- CC-1d: sendrawtransaction race *)

(* C is cached (a Tip_hit through the mempool coin view).  The RPC
   accepts tx T spending C; it is parked after its last coin read of
   C while the P2P path connects block B that also spends C.  Core
   (ATMP and ConnectTip under cs_main): T is either rejected (C spent) or
   evicted by removeForBlock.  Deployed: T enters the mempool AFTER B's
   eviction pass, spending a coin the active chain has spent. *)
(* How many times does a sendrawtransaction of [t] read coin C through the
   mempool's coin view?  Measured on an undisturbed fixture so the race
   below can park the RPC at the LAST read (after it, nothing re-checks
   C before the tx is inserted). *)
let count_c_reads () =
  with_fx ~label:"cl_sendraw_cal" ~cache:10_000 (fun fx ->
    let c = fx.cb.(1) in
    let t = spend ~fee:5000L ~tag:7 c subsidy in
    let n = ref 0 in
    let orig = Atomic.get Utxo.UtxoSet.tip_view in
    let orig_f = Option.get orig in
    Fun.protect ~finally:(fun () -> Atomic.set Utxo.UtxoSet.tip_view orig)
      (fun () ->
        Atomic.set Utxo.UtxoSet.tip_view (Some (fun txid vout ->
            if Cstruct.equal txid c && vout = 0 then incr n;
            orig_f txid vout));
        let r = Lwt_main.run (Rpc.handle_single_request_lwt fx.ctx
                                (json_req "sendrawtransaction"
                                   [ `String (tx_hex t) ])) in
        Printf.printf "  calibration: %d reads of C; rpc=%s\n%!" !n (show_resp r);
        if not (Mempool.contains fx.mp (Crypto.compute_txid t)) then
          Alcotest.fail "calibration: tx was not accepted undisturbed";
        !n))

let test_sendraw_race () =
  let reads = count_c_reads () in
  Alcotest.(check bool) "calibration saw reads of C" true (reads > 0);
  with_fx ~label:"cl_sendraw" ~cache:10_000 (fun fx ->
    let c = fx.cb.(1) in
    let t = spend ~fee:5000L ~tag:7 c subsidy in
    let b = build fx ~fee:1000L ~tag:1 102 [ spend ~tag:1 c subsidy ] in
    let g = new_gate () in
    let seen = Atomic.make 0 in
    let orig = Atomic.get Utxo.UtxoSet.tip_view in
    let orig_f = match orig with Some f -> f | None ->
      Alcotest.fail "tip_view not installed" in
    Fun.protect ~finally:(fun () -> Atomic.set Utxo.UtxoSet.tip_view orig)
      (fun () ->
        Atomic.set Utxo.UtxoSet.tip_view (Some (fun txid vout ->
            let r = orig_f txid vout in
            if Cstruct.equal txid c && vout = 0
               && Atomic.fetch_and_add seen 1 + 1 = reads then park_here g;
            r));
        let rpc_done = Atomic.make false in
        let rpc_resp = ref `Null in
        Lwt_main.run (
          let rpc =
            Lwt.map (fun r -> rpc_resp := r; Atomic.set rpc_done true)
              (Rpc.handle_single_request_lwt fx.ctx
                 (json_req "sendrawtransaction" [ `String (tx_hex t) ])) in
          let competitor =
            let%lwt () = Lwt_preemptive.detach (fun () ->
                poll ~what:"rpc parked or done" (fun () ->
                    gate_get g (fun g -> g.reached) || Atomic.get rpc_done)) () in
            let%lwt _ = pnb fx b in
            release g;
            Lwt.return_unit
          in
          Lwt.join [ rpc; competitor ]);
        let in_mp = Mempool.contains fx.mp (Crypto.compute_txid t) in
        Printf.printf
          "  sendraw race: parked=%b (at read %d of %d) fired-on-main=%d rpc=%s \
           tip=%d C-spent-by-chain=%b T-in-mempool=%b\n%!"
          g.reached reads (Atomic.get seen) g.fired_on_main (show_resp !rpc_resp)
          fx.state.Sync.blocks_synced (not (coin fx c 0)) in_mp;
        Alcotest.(check int) "B connected" 102 fx.state.Sync.blocks_synced;
        Alcotest.(check bool)
          "mempool holds no tx spending a coin the active chain spent" false
          in_mp))

(* ------------------------------------- CC-1: which thread commits a write *)

(* Every chain/mempool writer's commit runs on the main (Lwt) thread.
   Probes: Fatal.write_fault_hook (every chainstate batch) and the
   mempool's coin view (Utxo.UtxoSet.tip_view).  A case that recorded no
   event at all fails: a sweep that measured nothing is not a pass. *)
let test_writer_thread_sweep () =
  with_fx ~label:"cl_sweep" ~cache:10_000 (fun fx ->
    let events = ref [] in
    let note what = events := (what, on_main ()) :: !events in
    Fatal.write_fault_hook := Some (fun what -> note what);
    let orig = Atomic.get Utxo.UtxoSet.tip_view in
    let orig_f = Option.get orig in
    Fun.protect ~finally:(fun () -> Atomic.set Utxo.UtxoSet.tip_view orig;
                           Fatal.write_fault_hook := None)
      (fun () ->
        Atomic.set Utxo.UtxoSet.tip_view (Some (fun txid vout ->
            note "coin-view"; orig_f txid vout));
        let call m params =
          events := [];
          let r = Lwt_main.run
              (Rpc.handle_single_request_lwt fx.ctx (json_req m params)) in
          let n = List.length !events in
          let off = List.length (List.filter (fun (_, main) -> not main) !events) in
          Printf.printf "  %-20s events=%d off-main=%d resp=%s\n%!" m n off
            (let s = show_resp r in
             if String.length s > 90 then String.sub s 0 90 else s);
          (m, n, off)
        in
        let b102 = build fx ~fee:0L ~tag:1 102 [] in
        let b103 = build fx ~fee:0L ~tag:1 103 [] in
        let hx b = `String (Types.hash256_to_hex_display (hash_of b)) in
        let t = spend ~fee:5000L ~tag:9 fx.cb.(1) subsidy in
        let t2 = spend ~fee:5000L ~tag:9 fx.cb.(2) subsidy in
        (* OCaml evaluates list literals right to left: sequence explicitly. *)
        let r1 = call "submitblock" [ `String (block_hex b102) ] in
        let r2 = call "submitblock" [ `String (block_hex b103) ] in
        Alcotest.(check int) "submitblock x2 connected" 103
          fx.state.Sync.blocks_synced;
        let r3 = call "invalidateblock" [ hx b103 ] in
        let r4 = call "reconsiderblock" [ hx b103 ] in
        let r5 = call "testmempoolaccept" [ `List [ `String (tx_hex t2) ] ] in
        let r6 = call "sendrawtransaction" [ `String (tx_hex t) ] in
        (* reconsiderblock only clears the failure flags here: camlcoin's
           reconsider_block does not run ActivateBestChain (a separate,
           pre-existing gap: Core reconnects the block).  It writes nothing
           the probes can see, so it is reported but not counted. *)
        ignore r4;
        let rows = [ r1; r2; r3; r5; r6 ] in
        Printf.printf "  rows counted: %d (each must show >= 1 event)\n%!"
          (List.length rows);
        List.iter (fun (m, n, off) ->
            Alcotest.(check bool) (m ^ ": the probe saw the write") true (n > 0);
            Alcotest.(check int) (m ^ ": every write on the main thread") 0 off)
          rows))

(* ----------------------------- CC-1b: dumptxoutset rollback vs P2P connect *)

(* Reference coin set: the CF a fresh chain holds after connecting
   [blocks] 1..n at tip with nothing else running. *)
let cf_set db =
  let l = ref [] in
  Storage.ChainDB.iter_utxos db (fun txid vout data ->
      l := (Cstruct.to_string txid, vout, data) :: !l);
  List.sort compare !l

let reference_set (blocks : (int, Types.block) Hashtbl.t) n =
  Test_tmp.with_dir ~label:"cl_ref" ~mkdir:true (fun path ->
    let db = Storage.ChainDB.create path in
    Fun.protect ~finally:(fun () -> try Storage.ChainDB.close db with _ -> ())
      (fun () ->
        let state = Sync.create_chain_state db Consensus.regtest in
        state.Sync.sync_state <- Sync.FullySynced;
        for h = 1 to n do
          match Lwt_main.run (Sync.process_new_block ~f_requested:true state (Hashtbl.find blocks h)) with
          | Ok () -> ()
          | Error e -> Alcotest.failf "reference %d: %s" h e
        done;
        Alcotest.(check int) "reference tip" n state.Sync.blocks_synced;
        cf_set db))

let set_hash (s : (string * int * string) list) =
  Digest.to_hex (Digest.string (String.concat "|" (List.map (fun (t, v, d) ->
      Printf.sprintf "%s:%d:%s" t v d) s)))

(* Blocks 102..105 at tip; the RPC rolls back to 103 and dumps.  Block
   106 (spending the height-3 coinbase E) arrives over P2P mid-rollback,
   the RPC thread parked at the rollback's chainstate batch.  Afterwards
   106 is re-delivered as gap fill would.  Core (NetworkDisable +
   TemporaryRollback; every connect under cs_main): the dump is the set
   at 103 labelled 103, and the node ends at 106 with exactly the coin
   set of 1..106. *)
let test_dump_rollback_race () =
  with_fx ~label:"cl_dump" ~cache:10_000 (fun fx ->
    for h = 102 to 105 do
      connect_now fx (build fx ~tag:1 h [])
    done;
    let e = fx.cb.(3) in
    let b106 = build fx ~fee:1000L ~tag:1 106 [ spend ~tag:6 e subsidy ] in
    let ref103 = reference_set fx.blocks 103 in
    let ref106 = reference_set fx.blocks 106 in
    Test_tmp.with_dir ~label:"cl_dumpfile" ~mkdir:true (fun dir ->
      let path = Filename.concat dir "utxo.dat" in
      let g = new_gate () in
      let rpc_done = Atomic.make false in
      let rpc_resp = ref `Null in
      let competitor_r = ref "not run" in
      let paused_at_delivery = ref false in
      (* The P2P delivery of 106, run once on the Lwt thread. *)
      let started = Atomic.make false in
      let finished, finish = Lwt.wait () in
      let run_competitor () =
        if Atomic.compare_and_set started false true then
          Lwt.async (fun () ->
            paused_at_delivery := fx.state.Sync.block_submission_paused;
            let%lwt r = pnb fx b106 in
            competitor_r := (match r with Ok () -> "ok" | Error e -> e);
            release g;
            Lwt.wakeup_later finish ();
            Lwt.return_unit)
      in
      (* The rollback's chainstate batch: deployed, it runs on the RPC
         thread -> park it there and deliver 106 meanwhile.  When it runs on
         the main thread (the fix) it cannot be parked; deliver 106 on the
         loop's next turn, i.e. while the pool thread walks the dump. *)
      Fatal.write_fault_hook := Some (fun what ->
          if what = "batch_write" then begin
            if on_main () then begin
              park_here g;
              Lwt.async (fun () ->
                let%lwt () = Lwt.pause () in
                run_competitor (); Lwt.return_unit)
            end else park_here g
          end);
      Lwt_main.run (
        let rpc =
          Lwt.map (fun r -> rpc_resp := r; Atomic.set rpc_done true;
                    run_competitor ())
            (Rpc.handle_single_request_lwt fx.ctx
               (json_req "dumptxoutset"
                  [ `String path; `String "";
                    `Assoc [ ("rollback", `Int 103) ] ])) in
        let watcher =
          let%lwt () = Lwt_preemptive.detach (fun () ->
              poll ~what:"rollback parked or rpc done" (fun () ->
                  gate_get g (fun g -> g.reached || g.fired_on_main > 0)
                  || Atomic.get rpc_done)) () in
          if gate_get g (fun g -> g.reached) then run_competitor ();
          Lwt.return_unit
        in
        Lwt.join [ rpc; watcher; finished ]);
      let paused_seen = ref !paused_at_delivery in
      Fatal.write_fault_hook := None;
      (* gap fill re-delivers 106 *)
      let redeliver =
        match Lwt_main.run (pnb fx b106) with Ok () -> "ok" | Error e -> e in
      let dumped =
        match !rpc_resp with
        | `Assoc fs ->
          (match List.assoc_opt "result" fs with
           | Some (`Assoc r) ->
             let i k = match List.assoc_opt k r with Some (`Int n) -> n | _ -> -1 in
             Some (i "base_height", i "coins_written")
           | _ -> None)
        | _ -> None in
      let live = cf_set fx.db in
      let tip = fx.state.Sync.blocks_synced in
      let tip_is_106 = active_at fx 106 = Some (hash_of b106) in
      Printf.printf
        "  dump race: parked=%b fired-on-main=%d paused-seen=%b competitor=%s \
         redeliver=%s\n  rpc=%s\n  final tip=%d (106 active=%b) live-set=%d \
         ref106=%d same=%b  ref103=%d invalid106=%b\n%!"
        g.reached g.fired_on_main !paused_seen !competitor_r redeliver
        (let s = show_resp !rpc_resp in
         if String.length s > 220 then String.sub s 0 220 else s)
        tip tip_is_106 (List.length live) (List.length ref106)
        (set_hash live = set_hash ref106) (List.length ref103)
        (Sync.is_block_invalid fx.state (hash_of b106));
      (match dumped with
       | Some (bh, n) ->
         Alcotest.(check int) "dump labelled 103" 103 bh;
         Alcotest.(check int) "dump holds exactly the set at 103"
           (List.length ref103) n
       | None -> Alcotest.failf "dumptxoutset failed: %s" (show_resp !rpc_resp));
      Alcotest.(check bool) "106 not marked invalid" false
        (Sync.is_block_invalid fx.state (hash_of b106));
      Alcotest.(check bool) "106 is the active tip" true tip_is_106;
      let ref_tip = if tip = 106 then ref106 else reference_set fx.blocks tip in
      Alcotest.(check bool) "coin set == reference set at the final tip" true
        (set_hash live = set_hash ref_tip)))

(* Every connect path honours the NetworkDisable flag (deterministic: the
   flag is set directly, no race).  Core: network activity is disabled
   for the whole rollback, so no block connects. *)
let test_pause_honoured () =
  with_fx ~label:"cl_pause" ~cache:10_000 (fun fx ->
    let b102 = build fx ~tag:1 102 [] in
    let b103 = build fx ~tag:1 103 [] in
    fx.state.Sync.block_submission_paused <- true;
    let r = Lwt_main.run (pnb fx b102) in
    let after_pnb = fx.state.Sync.blocks_synced in
    let drained = Sync.connect_stored_blocks fx.state in
    let ibd = Sync.create_ibd_state ~utxo_set:fx.utxo fx.state in
    queue ibd b102 102; queue ibd b103 103;
    let n = match Lwt_main.run (Sync.process_downloaded_blocks ~max_blocks:2 ibd)
      with Ok n -> n | Error _ -> -1 in
    Printf.printf
      "  paused: process_new_block=%s tip=%d drain=%d catch-up=%d tip=%d\n%!"
      (match r with Ok () -> "ok" | Error e -> e) after_pnb drained n
      fx.state.Sync.blocks_synced;
    Alcotest.(check int) "process_new_block did not connect" 101 after_pnb;
    Alcotest.(check int) "stored-block drain did not connect" 0 drained;
    Alcotest.(check int) "catch-up did not connect" 101
      fx.state.Sync.blocks_synced;
    fx.state.Sync.block_submission_paused <- false;
    let n2 = match Lwt_main.run (Sync.process_downloaded_blocks ~max_blocks:2 ibd)
      with Ok n -> n | Error e -> Alcotest.failf "resume: %s" e in
    Printf.printf "  unpaused: catch-up=%d tip=%d\n%!" n2
      fx.state.Sync.blocks_synced;
    Alcotest.(check int) "after the pause the chain advances" 103
      fx.state.Sync.blocks_synced)

(* -------------------------------------------------- CC-2: pool starvation *)

(* Four slow RPCs, then a block delivered to the at-tip path with the
   post-IBD validation worker.  Deployed: each queued RPC holds one of
   Lwt_preemptive's 4 threads while it waits for rpc_worker_mutex, and the
   worker handoff needs two more detach calls, so the block waits for the
   first RPC to finish.  Core: -rpcthreads never share validation. *)
let connect_latency fx ~slow_rpcs =
  let b = build fx ~tag:1 (fx.state.Sync.blocks_synced + 1) [] in
  let worker = Sync.Validation_worker.create () in
  Fun.protect ~finally:(fun () -> Sync.Validation_worker.shutdown worker)
    (fun () ->
      Rpc.test_sync_sleep_s := (if slow_rpcs > 0 then 3.0 else 0.0);
      let answered = ref 0 in
      let dt = ref 0.0 in
      Lwt_main.run (
        let rpcs = List.init slow_rpcs (fun _ ->
            Lwt.map (fun _ -> incr answered)
              (Rpc.handle_single_request_lwt fx.ctx (json_req "help" []))) in
        let t0 = Unix.gettimeofday () in
        let connect =
          let%lwt r = Sync.process_new_block ~f_requested:true ~worker fx.state b in
          dt := Unix.gettimeofday () -. t0;
          (match r with Ok () -> () | Error e -> Alcotest.failf "connect: %s" e);
          Lwt.return_unit in
        Lwt.join (connect :: rpcs));
      Rpc.test_sync_sleep_s := 0.0;
      (!dt, !answered))

let test_pool_starvation () =
  with_fx ~label:"cl_starve" ~cache:10_000 (fun fx ->
    let base, _ = connect_latency fx ~slow_rpcs:0 in
    let loaded, answered = connect_latency fx ~slow_rpcs:4 in
    Printf.printf
      "  block connect: idle %.3fs, behind 4 slow RPCs %.3fs (%d/4 answered) \
       pool=%d threads\n%!"
      base loaded answered (Lwt_preemptive.nbthreads ());
    Alcotest.(check int) "all 4 slow RPCs answered" 4 answered;
    Alcotest.(check int) "both blocks connected" 103 fx.state.Sync.blocks_synced;
    Alcotest.(check bool)
      (Printf.sprintf "block connects in < 2 s behind 4 slow RPCs (took %.3fs)"
         loaded) true (loaded < 2.0))

let () =
  Alcotest.run "chain_lock" [
    "CC-1 writers vs connect", [
      Alcotest.test_case "submitblock vs competing P2P connect" `Quick
        test_submitblock_race;
      Alcotest.test_case "Mining.submit_block off-main re-checks the tip"
        `Quick test_submit_block_recheck;
      Alcotest.test_case "sendrawtransaction vs P2P connect" `Quick
        test_sendraw_race;
      Alcotest.test_case "writer commits run on the main thread" `Quick
        test_writer_thread_sweep;
    ];
    "CC-1b dumptxoutset rollback", [
      Alcotest.test_case "P2P block mid-rollback" `Quick
        test_dump_rollback_race;
      Alcotest.test_case "every connect path honours the pause" `Quick
        test_pause_honoured;
    ];
    "CC-2 pool", [
      Alcotest.test_case "4 slow RPCs do not starve block connect" `Slow
        test_pool_starvation;
    ];
  ]
