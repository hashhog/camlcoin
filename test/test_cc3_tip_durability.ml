(* CC-3: an at-tip commit must not make the tip durable ahead of the
   catch-up's unflushed coin changes
   (receipts/arch-concurrency-liveness-audit-2026-10-07.md, camlcoin CC-3).

   Catch-up IBD keeps up to 500 blocks of coin changes in the shared
   OptimizedUtxoSet's dirty set (and, on the scripts-on path, in the
   session's pending lists) and writes the coins + the chain_tip marker
   together every 500 blocks.  The at-tip paths (process_new_block, used by
   BlockMsg / cmpctblock / blocktxn, and the stored-block drain) commit
   their block's ops with apply_block_atomic, which writes tip_height=H+1
   to BOTH stores.  If that happens while catch-up blocks F+1..H are still
   unflushed, the durable marker says H+1 while the durable coins are
   F's plus H+1's.  A crash (kill -9, OOM, AbortNode) in that window is
   undetectable at boot: both markers agree.

   Core: one CCoinsViewCache; FlushStateToDisk writes the coins and then
   DB_BEST_BLOCK in the same CCoinsViewDB::BatchWrite (txdb.cpp), so the
   best-block marker is never ahead of the coins.

   This test is a REAL kill -9: a forked child connects 1..101 (flushed),
   catch-up 102..110 (unflushed; 105 spends coinbase C and creates O1),
   then 111 through process_new_block, and SIGKILLs itself.  The parent
   reopens the datadir through the boot path (restore_chain_state) and
   checks: the durable coin set equals a reference chain's set at the
   durable tip; a block spending O1 connects; a block re-spending C is
   rejected.

     dune exec --no-buffer test/test_cc3_tip_durability.exe
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

let hash_of (b : Types.block) = Crypto.compute_block_hash b.Types.header
let subsidy = Consensus.block_subsidy_for_network Consensus.Regtest 1

(* The fixed chain 1..111 (deterministic: same bytes in child, parent and
   reference). *)
let chain () =
  let net = Consensus.regtest in
  let blocks = Hashtbl.create 128 in
  let cb = Hashtbl.create 128 in
  let prev = ref net.Consensus.genesis_hash
  and time = ref net.Consensus.genesis_header.Types.timestamp in
  let add h txs ?fee () =
    let b = make_block ~prev_hash:!prev ~prev_time:!time ~height:h ?fee ~tag:1 txs in
    prev := hash_of b; time := b.Types.header.Types.timestamp;
    Hashtbl.replace blocks h b;
    Hashtbl.replace cb h (Crypto.compute_txid (List.hd b.Types.transactions));
    b in
  for h = 1 to 104 do ignore (add h [] ()) done;
  let t1 = spend ~tag:5 (Hashtbl.find cb 1) subsidy in
  ignore (add 105 [ t1 ] ~fee:1000L ());
  ignore (add 106 [] ());
  ignore (add 107 [ spend ~tag:7 (Hashtbl.find cb 2) subsidy ] ~fee:1000L ());
  for h = 108 to 111 do ignore (add h [] ()) done;
  (blocks, cb, Crypto.compute_txid t1)

let queue ibd (b : Types.block) h =
  Sync.queue_add ibd
    { Sync.hash = hash_of b; height = h;
      download_state = Sync.Downloaded { block = b; peer_id = None };
      tried_peers = [] }

let accept state (b : Types.block) =
  match Sync.validate_header state b.Types.header with
  | Ok entry -> Sync.accept_header state entry
  | Error e -> failwith ("validate_header: " ^ e)

(* Child: runs the scenario, then SIGKILLs itself right after the at-tip
   commit returned.  Never returns. *)
let child path blocks =
  let db = Storage.ChainDB.create path in
  let state = Sync.create_chain_state db Consensus.regtest in
  let utxo = Utxo.OptimizedUtxoSet.create ~cache_size:10_000 db in
  Sync.shared_utxo_set := Some utxo;
  for h = 1 to 111 do accept state (Hashtbl.find blocks h) done;
  state.Sync.blocks_synced <- 0;
  state.Sync.sync_state <- Sync.SyncingBlocks;
  let ibd = Sync.create_ibd_state ~utxo_set:utxo state in
  for h = 1 to 101 do queue ibd (Hashtbl.find blocks h) h done;
  (match Lwt_main.run (Sync.process_downloaded_blocks ~max_blocks:101 ibd) with
   | Ok 101 -> () | Ok n -> failwith (Printf.sprintf "prefix %d" n)
   | Error e -> failwith e);
  Sync.flush_utxos ibd;
  Storage.ChainDB.set_chain_tip db (hash_of (Hashtbl.find blocks 101)) 101;
  (* catch-up 102..110, NOT flushed (interval 500) *)
  let ibd2 = Sync.create_ibd_state ~utxo_set:utxo state in
  for h = 102 to 110 do queue ibd2 (Hashtbl.find blocks h) h done;
  (match Lwt_main.run (Sync.process_downloaded_blocks ~max_blocks:9 ibd2) with
   | Ok 9 -> () | Ok n -> failwith (Printf.sprintf "catch-up %d" n)
   | Error e -> failwith e);
  Printf.printf "  child: catch-up at %d, dirty=%d, durable tip=%s\n%!"
    state.Sync.blocks_synced (Utxo.OptimizedUtxoSet.dirty_count utxo)
    (match Storage.ChainDB.get_chain_tip db with
     | Some (_, h) -> string_of_int h | None -> "none");
  (* at-tip: the cmpctblock / BlockMsg path *)
  state.Sync.sync_state <- Sync.FullySynced;
  (match Lwt_main.run
           (Sync.process_new_block ~f_requested:true state
              (Hashtbl.find blocks 111)) with
   | Ok () -> () | Error e -> failwith ("at-tip 111: " ^ e));
  Printf.printf "  child: at-tip 111 committed (tip %d); kill -9\n%!"
    state.Sync.blocks_synced;
  Unix.kill (Unix.getpid ()) Sys.sigkill;
  exit 99

let cf_set db =
  let l = ref [] in
  Storage.ChainDB.iter_utxos db (fun txid vout data ->
      l := (Cstruct.to_string txid, vout, data) :: !l);
  List.sort compare !l

let reference_set blocks n =
  Test_tmp.with_dir ~label:"cc3_ref" ~mkdir:true (fun path ->
    let db = Storage.ChainDB.create path in
    Fun.protect ~finally:(fun () -> try Storage.ChainDB.close db with _ -> ())
      (fun () ->
        let state = Sync.create_chain_state db Consensus.regtest in
        state.Sync.sync_state <- Sync.FullySynced;
        for h = 1 to n do
          match Lwt_main.run (Sync.process_new_block ~f_requested:true state
                                (Hashtbl.find blocks h)) with
          | Ok () -> ()
          | Error e -> Alcotest.failf "reference %d: %s" h e
        done;
        cf_set db))

let test_kill9_after_at_tip_commit () =
  let blocks, cb, o1 = chain () in
  Test_tmp.with_dir ~label:"cc3_node" ~mkdir:true (fun path ->
    (match Unix.fork () with
     | 0 -> (try child path blocks with e ->
         Printf.printf "  child raised: %s\n%!" (Printexc.to_string e);
         Unix._exit 3)
     | pid ->
       (match snd (Unix.waitpid [] pid) with
        | Unix.WSIGNALED s when s = Sys.sigkill -> ()
        | Unix.WEXITED n -> Alcotest.failf "child exited %d (no kill -9)" n
        | _ -> Alcotest.fail "child: unexpected status"));
    (* boot *)
    let db = Storage.ChainDB.create path in
    Fun.protect ~finally:(fun () -> try Storage.ChainDB.close db with _ -> ())
      (fun () ->
        let durable = match Storage.ChainDB.get_chain_tip db with
          | Some (_, h) -> h | None -> -1 in
        let state = Sync.restore_chain_state db Consensus.regtest in
        let live = cf_set db in
        let reference = reference_set blocks durable in
        let missing = List.filter (fun x -> not (List.mem x live)) reference in
        let extra = List.filter (fun x -> not (List.mem x reference)) live in
        Printf.printf
          "  after kill -9: durable tip %d, restored blocks_synced %d; coin set \
           %d vs reference %d (missing %d, extra %d)\n%!"
          durable state.Sync.blocks_synced (List.length live)
          (List.length reference) (List.length missing) (List.length extra);
        (* post-restart behaviour *)
        state.Sync.sync_state <- Sync.FullySynced;
        let tip = Option.get (Sync.block_tip state) in
        let o1_value = Int64.sub subsidy 1000L in
        let y = make_block ~prev_hash:tip.Sync.hash
            ~prev_time:tip.Sync.header.Types.timestamp ~height:(tip.Sync.height + 1)
            ~fee:1000L ~tag:21 [ spend ~tag:21 o1 o1_value ] in
        let ry = Lwt_main.run (Sync.process_new_block ~f_requested:true state y) in
        let tip2 = Option.get (Sync.block_tip state) in
        let x = make_block ~prev_hash:tip2.Sync.hash
            ~prev_time:tip2.Sync.header.Types.timestamp ~height:(tip2.Sync.height + 1)
            ~fee:2000L ~tag:22 [ spend ~fee:2000L ~tag:22 (Hashtbl.find cb 1) subsidy ] in
        let rx = Lwt_main.run (Sync.process_new_block ~f_requested:true state x) in
        let show = function Ok () -> "connected" | Error e -> "rejected: " ^ e in
        Printf.printf
          "  block spending O1 (created at 105): %s\n\
          \  block re-spending C (spent at 105): %s (tip now %d)\n%!"
          (show ry) (show rx) state.Sync.blocks_synced;
        Alcotest.(check bool) "durable tip >= 101" true (durable >= 101);
        Alcotest.(check int) "no coin missing at the durable tip" 0
          (List.length missing);
        Alcotest.(check int) "no extra coin at the durable tip" 0
          (List.length extra);
        Alcotest.(check bool) "a block spending O1 connects" true (Result.is_ok ry);
        Alcotest.(check bool)
          "a block re-spending C is rejected (Core bad-txns-inputs-missingorspent)"
          true (Result.is_error rx)))

let () =
  Alcotest.run "cc3_tip_durability" [
    "at-tip commit during unflushed catch-up", [
      Alcotest.test_case "kill -9 right after the at-tip commit" `Quick
        test_kill9_after_at_tip_commit;
    ];
  ]
