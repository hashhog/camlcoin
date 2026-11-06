(* fix-camlcoin-stuck-on-orphan-974400.

   Mainnet 2026-11-03: camlcoin connected 000…5c1f…be6c at 974400 through the
   catch-up IBD session.  Core's active chain has 000…8b7c…a823 there (Core
   getchaintips lists 5c1f…be6c as a branchlen-1 valid-fork), and the header
   chain followed Core to 974401+.  camlcoin then logged, for hours and across
   every hourly restart,

     Block at height 974401 (…569ad12e…): validated tip moved to 974400
     during validation; result discarded

   and never reorged.  The catch-up session queues heights above the validated
   tip only, so Core's 974400 was never fetched (an unrequested copy is dropped
   by [receive_block]) and 974401, whose parent it is, could never connect.

   Core: FindNextBlocksToDownload starts from the last common ancestor of the
   best header chain and the active chain (net_processing.cpp,
   pindexLastCommonBlock), and ActivateBestChain -> FindMostWorkChain ->
   ActivateBestChainStep disconnects to the fork and connects the heavier
   branch (validation.cpp).

   Shape (regtest): A1..A3, then O4 (the orphan) connected by a catch-up
   session; then headers B4 (child of A3, equal work to O4) and B5.  A
   catch-up session with a peer that serves every block it is asked for must
   end at B5 with B4 on the active chain, O4's coinbase gone and B4's present.

     live      the session that runs right after B4/B5 headers arrive
     restart   the node is closed while on O4 and reopened from disk first

   Controls (consensus safety of the fix):
     equal_work      only B4 arrives: first-seen O4 stays the tip
     invalid_tip     B5 overpays its coinbase: no reorg, O4 stays, B5 failed
     invalid_below   B4 overpays (B5 valid on top): no reorg, O4 stays

   Mutated bodies (Warden on camlcoin#59): a body that does not match its
   header (bad merkle root, or a witness-only change that breaks the witness
   commitment) must be refused BEFORE it is stored (Core: ProcessNewBlock runs
   CheckBlock, and AcceptBlock runs CheckBlock + ContextualCheckBlock, before
   WriteBlock; validation.cpp), must not mark the header failed (BLOCK_MUTATED
   never reaches InvalidBlockFound), and must not stop the honest branch from
   connecting later.
     mutated_merkle    first delivery of B4 is a coinbase that does not match
                       B4's merkle root; a later session gets the real B4
     mutated_witness   same with a witness-only mutation of B4
     stored_mutated    a mutated B4 body is already on disk when the
                       session starts (an older binary stored it)
     reorg_mutated     [reorganize] to B5 over a stored mutated B4 fails and
                       drops that body, without marking B4 failed
     nonfinal_below    B4 matches its header but its coinbase is non-final
                       (ContextualCheckBlock): marked failed, never stored

     dune exec --no-buffer test/catchup_fork_reorg/test_catchup_fork_reorg.exe
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

(* Coinbase-only block.  [overpay] adds that many sats to the coinbase with
   no fees to cover it: bad-cb-amount. *)
let make_block ~prev_hash ~prev_time ~height ?(overpay = 0L)
    ?(nonfinal = false) ~tag () : Types.block =
  let extra_nonce = Cstruct.create 8 in
  Cstruct.LE.set_uint64 extra_nonce 0 (Int64.of_int (height + (tag lsl 32)));
  let mk wr =
    Mining.create_coinbase ~height ~total_fee:overpay ~payout_script:op_true
      ~extra_nonce ~witness_root:wr ~network_type:Consensus.Regtest ()
  in
  let wr = Mining.compute_witness_merkle_root [ mk None ] in
  let coinbase = mk (Some wr) in
  (* [nonfinal]: nLockTime at a far height with a non-final sequence, so
     IsFinalTx fails (ContextualCheckBlock bad-txns-nonfinal, a verdict
     Core records). *)
  let coinbase =
    if not nonfinal then coinbase
    else { coinbase with
           Types.locktime = 1_000_000l;
           inputs = List.map (fun (i : Types.tx_in) ->
               { i with Types.sequence = 0l }) coinbase.Types.inputs }
  in
  let merkle_root, _ = Crypto.merkle_root [ Crypto.compute_txid coinbase ] in
  remine { Types.header = { version = 4l; prev_block = prev_hash; merkle_root;
                            timestamp = Int32.add prev_time 600l;
                            bits = Consensus.regtest.pow_limit; nonce = 0l };
           transactions = [ coinbase ] }

let bhash (b : Types.block) = Crypto.compute_block_hash b.Types.header
let cbtxid (b : Types.block) = Crypto.compute_txid (List.hd b.Types.transactions)
let hex = Types.hash256_to_hex_display

let accept state (b : Types.block) =
  match Sync.validate_header state b.Types.header with
  | Ok entry -> Sync.accept_header state entry
  | Error e -> Alcotest.failf "validate_header: %s" e

(* A peer that serves every block it is asked for: each round fills the
   session's queue from the best header chain, delivers every queued block
   it has, and processes. *)
let run_session ?(rounds = 12) (state : Sync.chain_state) utxo
    (served : (string, Types.block) Hashtbl.t) ~(stray : Types.block list) =
  state.Sync.sync_state <- Sync.SyncingBlocks;
  let ibd = Sync.create_ibd_state ~utxo_set:utxo state in
  (* What the live node saw first: blocks of the other branch arriving while
     the session runs.  Unrequested, so the session drops them. *)
  List.iter (fun b -> ignore (Sync.receive_block ibd b)) stray;
  for _ = 1 to rounds do
    Sync.fill_download_queue ibd;
    Queue.iter (fun (e : Sync.block_queue_entry) ->
      match e.Sync.download_state with
      | Sync.NotRequested ->
        (match Hashtbl.find_opt served (Cstruct.to_string e.Sync.hash) with
         | Some b -> ignore (Sync.receive_block ibd b)
         | None -> ())
      | _ -> ()) ibd.Sync.block_queue;
    (match Lwt_main.run (Sync.process_downloaded_blocks ~max_blocks:64 ibd) with
     | Ok _ -> ()
     | Error e -> Alcotest.failf "process_downloaded_blocks: %s" e)
  done;
  (* Session end, as [Sync.run_ibd] does it: coins + chain tip to disk. *)
  let tip = Option.map (fun h -> (h, state.Sync.blocks_synced))
              (Sync.validated_tip_hash state) in
  Sync.flush_utxos ?tip ibd;
  Option.iter (fun (h, n) -> Storage.ChainDB.set_chain_tip state.Sync.db h n) tip

let genesis_block_placeholder : Types.block =
  { Types.header = Consensus.regtest.genesis_header; transactions = [] }

type world = {
  a : Types.block array;   (* a.(1..3) *)
  o4 : Types.block;
  b4 : Types.block;
  b5 : Types.block;
}

let build ?(b4_overpay = 0L) ?(b5_overpay = 0L) ?(b4_nonfinal = false) state =
  let genesis = Option.get state.Sync.tip in
  let prev = ref genesis.Sync.hash
  and ptime = ref genesis.Sync.header.Types.timestamp in
  let a = Array.init 4 (fun h ->
    if h = 0 then genesis_block_placeholder
    else begin
      let b = make_block ~prev_hash:!prev ~prev_time:!ptime ~height:h ~tag:0 () in
      prev := bhash b; ptime := b.Types.header.Types.timestamp; b
    end) in
  let o4 = make_block ~prev_hash:!prev ~prev_time:!ptime ~height:4 ~tag:1 () in
  let b4 = make_block ~prev_hash:!prev ~prev_time:!ptime ~height:4 ~tag:2
             ~overpay:b4_overpay ~nonfinal:b4_nonfinal () in
  let b5 = make_block ~prev_hash:(bhash b4)
             ~prev_time:b4.Types.header.Types.timestamp ~height:5 ~tag:2
             ~overpay:b5_overpay () in
  { a; o4; b4; b5 }

let table blocks =
  let t = Hashtbl.create 8 in
  List.iter (fun b -> Hashtbl.replace t (Cstruct.to_string (bhash b)) b) blocks;
  t

(* Phase 1, common to every case: the node follows A1..A3 + O4 through a
   catch-up session (what mainnet did at 974400). *)
let follow_orphan state utxo w =
  for h = 1 to 3 do accept state w.a.(h) done;
  accept state w.o4;
  run_session state utxo
    (table [ w.a.(1); w.a.(2); w.a.(3); w.o4 ]) ~stray:[];
  Alcotest.(check int) "precondition: following O4 at height 4" 4
    state.Sync.blocks_synced;
  Alcotest.(check string) "precondition: validated tip is O4"
    (hex (bhash w.o4))
    (match Sync.validated_tip_hash state with Some h -> hex h | None -> "none")

let tip_hash state =
  match Sync.validated_tip_hash state with Some h -> hex h | None -> "none"

let with_db label f =
  Test_tmp.with_dir ~label ~mkdir:true (fun path ->
    Fun.protect ~finally:(fun () -> Sync.shared_utxo_set := None)
      (fun () -> f path))

let open_node path =
  let db = Storage.ChainDB.create path in
  let utxo = Utxo.OptimizedUtxoSet.create ~cache_size:10_000 db in
  Sync.shared_utxo_set := Some utxo;
  (db, utxo)

let check_on_b5 db state w =
  Alcotest.(check string) "validated tip is B5 (Core's branch)"
    (hex (bhash w.b5)) (tip_hash state);
  Alcotest.(check int) "blocks_synced = 5" 5 state.Sync.blocks_synced;
  Alcotest.(check string) "active chain at 4 is B4, not the orphan O4"
    (hex (bhash w.b4))
    (match Storage.ChainDB.get_hash_at_height db 4 with
     | Some h -> hex h | None -> "none");
  Alcotest.(check bool) "O4's coinbase left the UTXO set" true
    (Storage.ChainDB.get_utxo db (cbtxid w.o4) 0 = None);
  Alcotest.(check bool) "B4's coinbase is in the UTXO set" true
    (Storage.ChainDB.get_utxo db (cbtxid w.b4) 0 <> None);
  Alcotest.(check bool) "B5's coinbase is in the UTXO set" true
    (Storage.ChainDB.get_utxo db (cbtxid w.b5) 0 <> None)

let test_live_reorg () =
  with_db "catchup_fork_live" (fun path ->
    let db, utxo = open_node path in
    Fun.protect ~finally:(fun () -> try Storage.ChainDB.close db with _ -> ())
      (fun () ->
        let state = Sync.create_chain_state db Consensus.regtest in
        let w = build state in
        follow_orphan state utxo w;
        accept state w.b4; accept state w.b5;
        run_session state utxo (table [ w.b4; w.b5 ]) ~stray:[ w.b4 ];
        check_on_b5 db state w))

let test_restart_reorg () =
  with_db "catchup_fork_restart" (fun path ->
    let w =
      let db, utxo = open_node path in
      Fun.protect ~finally:(fun () -> Storage.ChainDB.close db)
        (fun () ->
          let state = Sync.create_chain_state db Consensus.regtest in
          let w = build state in
          follow_orphan state utxo w;
          (* Headers of Core's branch arrive and the session that would
             have handled them never runs: the node is stopped on O4. *)
          accept state w.b4; accept state w.b5;
          Sync.flush_coins_before_tip_commit state;
          w)
    in
    Sync.shared_utxo_set := None;
    let db, utxo = open_node path in
    Fun.protect ~finally:(fun () -> try Storage.ChainDB.close db with _ -> ())
      (fun () ->
        let state = Sync.restore_chain_state db Consensus.regtest in
        Alcotest.(check int) "restart: restored on O4 (height 4)" 4
          state.Sync.blocks_synced;
        Alcotest.(check string) "restart: restored validated tip is O4"
          (hex (bhash w.o4)) (tip_hash state);
        Alcotest.(check int) "restart: header tip is B5 (height 5)" 5
          (match state.Sync.tip with Some t -> t.Sync.height | None -> -1);
        run_session state utxo (table [ w.b4; w.b5 ]) ~stray:[];
        check_on_b5 db state w))

let stays_on_o4 ?(b4_overpay = 0L) ?(b5_overpay = 0L) ?(b4_nonfinal = false)
    ?(while_open = fun _ _ _ -> ()) ~with_b5 label =
  with_db label (fun path ->
    let db, utxo = open_node path in
    Fun.protect ~finally:(fun () -> try Storage.ChainDB.close db with _ -> ())
      (fun () ->
        let state = Sync.create_chain_state db Consensus.regtest in
        let w = build ~b4_overpay ~b5_overpay ~b4_nonfinal state in
        follow_orphan state utxo w;
        accept state w.b4;
        if with_b5 then accept state w.b5;
        run_session state utxo
          (table (if with_b5 then [ w.b4; w.b5 ] else [ w.b4 ])) ~stray:[];
        Alcotest.(check string) "validated tip stays O4" (hex (bhash w.o4))
          (tip_hash state);
        Alcotest.(check int) "blocks_synced stays 4" 4 state.Sync.blocks_synced;
        Alcotest.(check bool) "O4's coinbase is still unspent" true
          (Storage.ChainDB.get_utxo db (cbtxid w.o4) 0 <> None);
        Alcotest.(check bool) "B4's coinbase was never applied" true
          (Storage.ChainDB.get_utxo db (cbtxid w.b4) 0 = None);
        while_open db state w;
        (state, w)))

(* A body under B4's header that is not B4: the coinbase pays one satoshi
   less, so its txid (and the merkle root) no longer match the header. *)
let mutate_merkle (b : Types.block) : Types.block =
  match b.Types.transactions with
  | cb :: rest ->
    let outs = match cb.Types.outputs with
      | o :: os -> { o with Types.value = Int64.sub o.Types.value 1L } :: os
      | [] -> []
    in
    { b with Types.transactions = { cb with Types.outputs = outs } :: rest }
  | [] -> b

(* Witness-only mutation: the coinbase witness reserved value changes, the
   txid (and so the merkle root) does not, the witness commitment fails. *)
let mutate_witness (b : Types.block) : Types.block =
  match b.Types.transactions with
  | cb :: rest ->
    let w = { Types.items = [ Cstruct.of_string (String.make 32 '\x01') ] } in
    { b with Types.transactions = { cb with Types.witnesses = [ w ] } :: rest }
  | [] -> b

let is_marked state (b : Types.block) =
  Hashtbl.mem state.Sync.invalidated_blocks (Cstruct.to_string (bhash b))

let mutated_then_honest ~mutate label =
  with_db label (fun path ->
    let db, utxo = open_node path in
    Fun.protect ~finally:(fun () -> try Storage.ChainDB.close db with _ -> ())
      (fun () ->
        let state = Sync.create_chain_state db Consensus.regtest in
        let w = build state in
        follow_orphan state utxo w;
        accept state w.b4; accept state w.b5;
        let bad = mutate w.b4 in
        Alcotest.(check string) "precondition: mutated body keeps B4's header"
          (hex (bhash w.b4)) (hex (bhash bad));
        (* First session: the peer answers B4 with the mutated body. *)
        run_session state utxo (table [ bad; w.b5 ]) ~stray:[];
        Alcotest.(check string) "mutated B4: validated tip stays O4"
          (hex (bhash w.o4)) (tip_hash state);
        Alcotest.(check bool) "mutated B4 body was not stored" false
          (Storage.ChainDB.has_block db (bhash w.b4));
        Alcotest.(check bool) "B4 is not marked failed (mutation is no verdict)"
          false (is_marked state w.b4);
        (* A later session is offered the real B4 and B5. *)
        run_session state utxo (table [ w.b4; w.b5 ]) ~stray:[];
        check_on_b5 db state w;
        Alcotest.(check bool) "B4 not marked failed after connecting" false
          (is_marked state w.b4)))

let test_mutated_merkle_then_honest () =
  mutated_then_honest ~mutate:mutate_merkle "catchup_fork_mut_merkle"

let test_mutated_witness_then_honest () =
  mutated_then_honest ~mutate:mutate_witness "catchup_fork_mut_witness"

let test_stored_mutated_body () =
  with_db "catchup_fork_stored_mut" (fun path ->
    let db, utxo = open_node path in
    Fun.protect ~finally:(fun () -> try Storage.ChainDB.close db with _ -> ())
      (fun () ->
        let state = Sync.create_chain_state db Consensus.regtest in
        let w = build state in
        follow_orphan state utxo w;
        accept state w.b4; accept state w.b5;
        Storage.ChainDB.store_block db (bhash w.b4) (mutate_merkle w.b4);
        run_session state utxo (table [ w.b4; w.b5 ]) ~stray:[];
        check_on_b5 db state w))

(* A B4 body that matches its header but is invalid by ContextualCheckBlock
   (non-final coinbase): Core's AcceptBlock refuses it before WriteBlock and
   InvalidBlockFound marks it.  No reorg, B4 (and B5 on it) marked failed,
   and the body is never written. *)
let test_nonfinal_below_not_stored () =
  let state, w =
    stays_on_o4 ~b4_nonfinal:true ~with_b5:true "catchup_fork_nonfinal"
      ~while_open:(fun db _ w ->
        Alcotest.(check bool) "nonfinal B4 body was not stored" false
          (Storage.ChainDB.has_block db (bhash w.b4)))
  in
  Alcotest.(check bool) "nonfinal B4 is marked failed" true (is_marked state w.b4)

let test_reorganize_drops_mutated_body () =
  with_db "catchup_fork_reorg_mut" (fun path ->
    let db, utxo = open_node path in
    Fun.protect ~finally:(fun () -> try Storage.ChainDB.close db with _ -> ())
      (fun () ->
        let state = Sync.create_chain_state db Consensus.regtest in
        let w = build state in
        follow_orphan state utxo w;
        accept state w.b4; accept state w.b5;
        Storage.ChainDB.store_block db (bhash w.b4) (mutate_merkle w.b4);
        Storage.ChainDB.store_block db (bhash w.b5) w.b5;
        let b5e = Option.get (Sync.get_header state (bhash w.b5)) in
        let ibd = Sync.create_ibd_state ~utxo_set:utxo state in
        (match Sync.reorganize ibd b5e with
         | Ok () -> Alcotest.fail "reorganize over a mutated B4 succeeded"
         | Error _ -> ());
        Alcotest.(check string) "failed reorg: validated tip stays O4"
          (hex (bhash w.o4)) (tip_hash state);
        Alcotest.(check bool) "failed reorg dropped the mutated B4 body" false
          (Storage.ChainDB.has_block db (bhash w.b4));
        Alcotest.(check bool) "B4 is not marked failed" false
          (is_marked state w.b4);
        Alcotest.(check bool) "B5 is not marked failed" false
          (is_marked state w.b5);
        run_session state utxo (table [ w.b4; w.b5 ]) ~stray:[];
        check_on_b5 db state w))

let test_equal_work_keeps_first_seen () =
  ignore (stays_on_o4 ~with_b5:false "catchup_fork_equal")

let test_invalid_tip_no_reorg () =
  let state, w =
    stays_on_o4 ~b5_overpay:100_000_000L ~with_b5:true "catchup_fork_badtip"
  in
  Alcotest.(check bool) "B5 is marked failed" true
    (Hashtbl.mem state.Sync.invalidated_blocks
       (Cstruct.to_string (bhash w.b5)))

let test_invalid_below_no_reorg () =
  let state, w =
    stays_on_o4 ~b4_overpay:100_000_000L ~with_b5:true "catchup_fork_badbelow"
  in
  Alcotest.(check bool) "B4 is marked failed" true
    (Hashtbl.mem state.Sync.invalidated_blocks
       (Cstruct.to_string (bhash w.b4)))

let () =
  (* Node log lines go to the per-test output files as evidence of the path
     taken (rewind to the fork point, then reorganize). *)
  Logs.set_reporter (Logs.format_reporter ());
  Logs.set_level (Some Logs.Info);
  Alcotest.run "catchup_fork_reorg"
    [ ( "catch-up session reorgs off an orphaned tip",
        [ Alcotest.test_case "live: heavier branch forking below the tip" `Quick
            test_live_reorg;
          Alcotest.test_case "restart: reopened on the orphan, still reorgs"
            `Quick test_restart_reorg ] );
      ( "controls",
        [ Alcotest.test_case "equal work: first-seen tip kept" `Quick
            test_equal_work_keeps_first_seen;
          Alcotest.test_case "invalid branch tip: no reorg" `Quick
            test_invalid_tip_no_reorg;
          Alcotest.test_case "invalid fork-below block: no reorg" `Quick
            test_invalid_below_no_reorg ] );
      ( "mutated bodies",
        [ Alcotest.test_case "bad merkle B4 refused, honest B4+B5 connect"
            `Quick test_mutated_merkle_then_honest;
          Alcotest.test_case "bad witness B4 refused, honest B4+B5 connect"
            `Quick test_mutated_witness_then_honest;
          Alcotest.test_case "stored mutated B4 does not block the reorg"
            `Quick test_stored_mutated_body;
          Alcotest.test_case "reorganize drops a mutated stored body"
            `Quick test_reorganize_drops_mutated_body;
          Alcotest.test_case "nonfinal B4 marked failed and not stored"
            `Quick test_nonfinal_below_not_stored ] ) ]
