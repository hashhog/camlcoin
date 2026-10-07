(* LIVE 2026-10-04 header wedge at 969874 (deployed a8e8f30).

   OBSERVED (restart.log): the post-IBD gap-fill and a catch-up IBD both
   fetched block 969874.  The catch-up IBD connected it (UpdateTip 969874),
   then the post-IBD [process_new_block] validation of the SAME block — in
   flight on its own worker Domain across the Lwt await — returned
   "transaction 3305 ... missing inputs" (its coin view now had the block
   applied) and its Error arm marked the CONNECTED tip BLOCK_FAILED
   (persisted).  The best header fell back to 969873; every child header was
   "bad-prevblk"; a restart reloaded the mark.

   test_race: reproduces the interleaving deterministically.  The worker
   Domain is held busy (a blocker job whose UTXO lookup waits on a mutex),
   process_new_block #1 submits B and parks on the worker, a second
   (inline) process_new_block connects B, then the worker is released.
     before: B marked failed, best header below the block tip, child header
             bad-prevblk, peer punished.
     after:  result discarded; B not marked; child header accepted.

   test_boot_repair: a datadir persisted in the wedged state (active tip
   marked failed, header tip below block tip) is repaired by
   restore_chain_state; a genuinely failed side-branch block stays marked
   (negative control); a second restore is a no-op.

     dune exec --no-buffer test/test_header_wedge_race.exe *)

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

let build_block ?(fee = 0L) ?(tag = 0) ?(txs = []) ~(prev_hash : Types.hash256)
    ~(height : int) ~(prev_time : int32) () : Types.block =
  let extra_nonce = Cstruct.create 8 in
  Cstruct.LE.set_uint64 extra_nonce 0 (Int64.of_int ((tag * 1_000_000) + height));
  let mk wr =
    Mining.create_coinbase ~height ~total_fee:fee ~payout_script:op_true
      ~extra_nonce ~witness_root:wr ~network_type:Consensus.Regtest ()
  in
  let witness_root = Mining.compute_witness_merkle_root (mk None :: txs) in
  let coinbase = mk (Some witness_root) in
  let all = coinbase :: txs in
  let merkle_root, _ = Crypto.merkle_root (List.map Crypto.compute_txid all) in
  remine
    { Types.header =
        { version = 4l; prev_block = prev_hash; merkle_root;
          timestamp = Int32.add prev_time 600l;
          bits = Consensus.regtest.pow_limit; nonce = 0l };
      transactions = all }

let hash_of (b : Types.block) = Crypto.compute_block_hash b.Types.header

let accept_hdr state (b : Types.block) =
  match Sync.validate_header state b.Types.header with
  | Ok e -> Sync.accept_header state e
  | Error "Header already known" -> ()
  | Error e -> Alcotest.failf "validate_header: %s" e

let tip_hash state =
  match state.Sync.tip with Some t -> t.Sync.hash | None -> Types.zero_hash

(* genesis..101 connected (FullySynced); returns the tip, its time and the
   height-1 coinbase (mature at 102). *)
let build_prefix state =
  let genesis = Option.get state.Sync.tip in
  let prev = ref (genesis.Sync.hash, genesis.Sync.header.Types.timestamp) in
  let cb1 = ref None in
  for h = 1 to 101 do
    let b = build_block ~prev_hash:(fst !prev) ~height:h
        ~prev_time:(snd !prev) () in
    if h = 1 then cb1 := Some (List.hd b.Types.transactions);
    accept_hdr state b;
    (match Lwt_main.run (Sync.process_new_block ~f_requested:true state b) with
     | Ok () -> ()
     | Error e -> Alcotest.failf "prefix block %d: %s" h e);
    prev := (hash_of b, b.Types.header.Types.timestamp)
  done;
  Alcotest.(check int) "prefix connected" 101 state.Sync.blocks_synced;
  (fst !prev, snd !prev, Option.get !cb1)

let spend_of cb : Types.transaction = {
  Types.version = 2l;
  inputs = [ { Types.previous_output =
                 { Types.txid = Crypto.compute_txid cb; vout = 0l };
               script_sig = Cstruct.empty; sequence = 0xffffffffl } ];
  outputs = [ { Types.value = 49_00000000L; script_pubkey = op_true } ];
  witnesses = []; locktime = 0l }

let with_db label f =
  Test_tmp.with_dir ~label ~mkdir:true (fun path -> f path)

let test_race () =
  with_db "hdrwedge_race" (fun path ->
    let db = Storage.ChainDB.create path in
    Fun.protect ~finally:(fun () -> try Storage.ChainDB.close db with _ -> ())
      (fun () ->
        let state = Sync.create_chain_state db Consensus.regtest in
        state.Sync.sync_state <- Sync.FullySynced;
        let tip101, t101, cb1 = build_prefix state in
        let b = build_block ~txs:[ spend_of cb1 ] ~prev_hash:tip101
            ~height:102 ~prev_time:t101 () in
        accept_hdr state b;
        let w = Sync.Validation_worker.create () in
        Fun.protect ~finally:(fun () -> Sync.Validation_worker.shutdown w)
          (fun () ->
            (* 1. hold the worker busy: its lookup waits on [gate]. *)
            let gate = Mutex.create () in
            Mutex.lock gate;
            let entered = Atomic.make false in
            let blocker : Sync.Validation_worker.job = {
              block = b; height = 102;
              expected_bits = b.Types.header.Types.bits;
              median_time = 0l; prev_block_time = t101;
              lookup = (fun _ ->
                Atomic.set entered true;
                Mutex.lock gate; Mutex.unlock gate; None);
              flags = 0; skip_scripts = true;
              network = Consensus.regtest;
              get_mtp_at_height = None; bip34_height_hash = None;
              prefetch_base = None } in
            Sync.Validation_worker.put_req w.Sync.Validation_worker.req
              (Sync.Validation_worker.Validate (blocker, None));
            let deadline = Unix.gettimeofday () +. 30.0 in
            while not (Atomic.get entered) && Unix.gettimeofday () < deadline do
              Unix.sleepf 0.005
            done;
            Alcotest.(check bool) "worker is parked inside the blocker" true
              (Atomic.get entered);
            (* 2. process_new_block #1 (the gap-fill copy) parks on the worker. *)
            let punished = ref [] in
            let handler pid reason = punished := (pid, reason) :: !punished in
            let p1 =
              Sync.process_new_block ~f_requested:true ~peer_id:7
                ~misbehavior_handler:handler ~worker:w state b in
            Alcotest.(check bool) "#1 is in flight" true
              (Lwt.state p1 = Lwt.Sleep);
            (* 3. the other path connects the SAME block meanwhile. *)
            (match Lwt.state (Sync.process_new_block ~f_requested:true state b) with
             | Lwt.Return (Ok ()) -> ()
             | Lwt.Return (Error e) -> Alcotest.failf "inline connect: %s" e
             | _ -> Alcotest.fail "inline connect did not complete synchronously");
            Alcotest.(check int) "block 102 connected by the other path" 102
              state.Sync.blocks_synced;
            (* 4. release the worker; drain the blocker's own response. *)
            Mutex.unlock gate;
            ignore (Sync.Validation_worker.take_resp w.Sync.Validation_worker.resp);
            (* 5. #1 completes against a coin view that already has B. *)
            let r1 = Lwt_main.run p1 in
            (match r1 with
             | Ok () -> ()
             | Error e -> Printf.printf "  #1 returned Error %s\n%!" e);
            Alcotest.(check bool) "connected block 102 is NOT marked failed" false
              (Sync.is_block_invalid state (hash_of b));
            Alcotest.(check bool) "best header is still block 102" true
              (Cstruct.equal (tip_hash state) (hash_of b));
            Alcotest.(check (list (pair int string))) "peer not punished" []
              !punished;
            let child = build_block ~prev_hash:(hash_of b) ~height:103
                ~prev_time:b.Types.header.Types.timestamp () in
            (match Sync.validate_header state child.Types.header with
             | Ok _ -> ()
             | Error e -> Alcotest.failf "child header of the tip rejected: %s" e);
            accept_hdr state child;
            (match Lwt_main.run
                     (Sync.process_new_block ~f_requested:true state child) with
             | Ok () -> ()
             | Error e -> Alcotest.failf "child block: %s" e);
            Alcotest.(check int) "chain advances past the race" 103
              state.Sync.blocks_synced)))

let test_boot_repair () =
  with_db "hdrwedge_boot" (fun path ->
    let tip_hash_v = ref Types.zero_hash and tip_time = ref 0l in
    let side_hash = ref Types.zero_hash in
    (* Phase 1: chain to 101 + a genuinely failed side-branch block at 101;
       then persist the wedged state exactly as mark_block_failed did live. *)
    (let db = Storage.ChainDB.create path in
     Fun.protect ~finally:(fun () -> try Storage.ChainDB.close db with _ -> ())
       (fun () ->
         let state = Sync.create_chain_state db Consensus.regtest in
         state.Sync.sync_state <- Sync.FullySynced;
         let tip101, t101, _ = build_prefix state in
         tip_hash_v := tip101; tip_time := t101;
         let e100 = Option.get (Sync.get_ancestor state
                                  (Option.get (Sync.get_header state tip101)) 100) in
         let side = build_block ~fee:1L ~tag:5 ~prev_hash:e100.Sync.hash
             ~height:101 ~prev_time:e100.Sync.header.Types.timestamp () in
         accept_hdr state side;
         side_hash := hash_of side;
         (match Lwt_main.run (Sync.process_new_block ~f_requested:true state side) with
          | _ -> ());
         let side_e = Option.get (Sync.get_header state (hash_of side)) in
         ignore (Sync.mark_block_failed state side_e);
         (* the wedge: the connected tip marked failed *)
         let tip_e = Option.get (Sync.get_header state tip101) in
         ignore (Sync.mark_block_failed state tip_e);
         Alcotest.(check bool) "wedged: best header fell below the block tip" true
           (state.Sync.headers_synced < state.Sync.blocks_synced)));
    (* Phase 2: restart.  The datadir must come back un-wedged. *)
    let restore () =
      let db = Storage.ChainDB.create path in
      let state = Sync.restore_chain_state db Consensus.regtest in
      (db, state)
    in
    let db, state = restore () in
    Fun.protect ~finally:(fun () -> try Storage.ChainDB.close db with _ -> ())
      (fun () ->
        Alcotest.(check int) "block tip restored" 101 state.Sync.blocks_synced;
        Alcotest.(check bool) "active tip no longer marked failed" false
          (Sync.is_block_invalid state !tip_hash_v);
        Alcotest.(check bool) "side-branch failed block STAYS marked" true
          (Sync.is_block_invalid state !side_hash);
        Alcotest.(check bool) "best header == block tip" true
          (Cstruct.equal (tip_hash state) !tip_hash_v);
        Alcotest.(check int) "header tip >= block tip" 101
          state.Sync.headers_synced;
        let child = build_block ~prev_hash:!tip_hash_v ~height:102
            ~prev_time:!tip_time () in
        (match Sync.validate_header state child.Types.header with
         | Ok _ -> ()
         | Error e -> Alcotest.failf "child header after restart: %s" e));
    (* Phase 3: idempotent — a second restart finds nothing to repair. *)
    let db, state = restore () in
    Fun.protect ~finally:(fun () -> try Storage.ChainDB.close db with _ -> ())
      (fun () ->
        Alcotest.(check bool) "still unmarked" false
          (Sync.is_block_invalid state !tip_hash_v);
        Alcotest.(check bool) "side branch still marked" true
          (Sync.is_block_invalid state !side_hash);
        Alcotest.(check int) "header tip stable" 101 state.Sync.headers_synced))

let () =
  Alcotest.run "header_wedge_race"
    [ ("header-wedge",
       [ Alcotest.test_case "stale concurrent validation never marks the \
                             connected tip" `Quick test_race;
         Alcotest.test_case "boot repairs a persisted active-chain failed \
                             mark" `Quick test_boot_repair ]) ]
