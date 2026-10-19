(* A failed reorg after invalidateblock must keep the best valid chain.

   Core regtest failed_reorg scenario B (KB-176 shape):

       a1-a2-x3-x4-x5            (active)
             \-s3-s4-s5bad      (stored, never validated; s5bad pays 51 BTC)

   invalidateblock x4 leaves s5bad as the most-work candidate.  Core's
   ActivateBestChain connects s3 and s4, ConnectBlock fails s5bad
   (bad-cb-amount), InvalidBlockFound marks it failed, and the loop goes on
   with the next most-work candidate: the tip ends on s4, which has more
   work than x3 (validation.cpp ActivateBestChain / ActivateBestChainStep).

   camlcoin's post-invalidate reorg is all-or-nothing: when the connect of
   s5bad failed it gave up and stayed on x3, one block short of Core.

     dune exec --no-buffer test/test_failed_reorg_prefix.exe
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

let make_block ?(overpay = 0L) ~prev_hash ~prev_time ~height ~tag () : Types.block =
  let extra_nonce = Cstruct.create 8 in
  Cstruct.LE.set_uint64 extra_nonce 0 (Int64.of_int (height + (tag lsl 32)));
  let mk wr =
    Mining.create_coinbase ~height ~total_fee:overpay ~payout_script:op_true
      ~extra_nonce ~witness_root:wr ~network_type:Consensus.Regtest ()
  in
  let placeholder = mk None in
  let wr = Mining.compute_witness_merkle_root [placeholder] in
  let coinbase = mk (Some wr) in
  let merkle_root, _ = Crypto.merkle_root [Crypto.compute_txid coinbase] in
  remine { Types.header = { version = 4l; prev_block = prev_hash; merkle_root;
                            timestamp = Int32.add prev_time 600l;
                            bits = Consensus.regtest.pow_limit; nonce = 0l };
           transactions = [coinbase] }

let hash_of (b : Types.block) = Crypto.compute_block_hash b.Types.header
let hex = Types.hash256_to_hex_display

(* A node on a fresh datadir: chain state, live UTXO set, mempool. *)
let with_node path f =
  let db = Storage.ChainDB.create path in
  Fun.protect ~finally:(fun () -> try Storage.ChainDB.close db with _ -> ())
    (fun () ->
      let state = Sync.create_chain_state db Consensus.regtest in
      state.Sync.sync_state <- Sync.FullySynced;
      let utxo = Utxo.OptimizedUtxoSet.create ~cache_size:10_000 db in
      Sync.shared_utxo_set := Some utxo;
      let mp = Mempool.create ~network:Consensus.regtest ~require_standard:false
          ~verify_scripts:false ~utxo:(Utxo.UtxoSet.create db)
          ~current_height:0 () in
      let submit b =
        match Mining.submit_block ~utxo ~network_type:Consensus.Regtest
                b state mp with
        | Ok () -> ()
        | Error e -> Alcotest.failf "submitblock %s: %s" (hex (hash_of b)) e
      in
      Fun.protect ~finally:(fun () -> Sync.shared_utxo_set := None)
        (fun () -> f db state utxo submit))

let active_tip state =
  match Sync.block_tip state with
  | Some (e : Sync.header_entry) -> Printf.sprintf "%s@%d" (hex e.hash) e.height
  | None -> "none"

let chain () =
  let g = Consensus.regtest.Consensus.genesis_header in
  let ghash = Consensus.regtest.Consensus.genesis_hash in
  let next ?overpay (prev : Types.block option) height tag =
    let prev_hash, prev_time = match prev with
      | None -> ghash, g.Types.timestamp
      | Some p -> hash_of p, p.Types.header.Types.timestamp in
    make_block ?overpay ~prev_hash ~prev_time ~height ~tag () in
  let a1 = next None 1 1 in
  let a2 = next (Some a1) 2 1 in
  let x3 = next (Some a2) 3 1 in
  let x4 = next (Some x3) 4 1 in
  let x5 = next (Some x4) 5 1 in
  let s3 = next (Some a2) 3 2 in
  let s4 = next (Some s3) 4 2 in
  let s5bad = next ~overpay:Consensus.coin (Some s4) 5 2 in
  (a1, a2, x3, x4, x5, s3, s4, s5bad)

let test_invalidate_keeps_valid_side_prefix () =
  let a1, a2, x3, x4, x5, s3, s4, s5bad = chain () in
  Test_tmp.with_dir ~label:"frp_b" ~mkdir:true (fun path ->
    with_node path (fun _db state utxo submit ->
      List.iter submit [a1; a2; x3; x4; x5; s3; s4; s5bad];
      Alcotest.(check string) "x5 active before invalidate"
        (Printf.sprintf "%s@5" (hex (hash_of x5))) (active_tip state);
      (match Sync.invalidate_block state ~utxo_set:utxo (hash_of x4) with
       | Ok _ -> () | Error e -> Alcotest.failf "invalidateblock: %s" e);
      Alcotest.(check bool) "s5bad marked failed" true
        (Sync.is_block_invalid state (hash_of s5bad));
      Alcotest.(check string) "tip is s4 (Core), not x3"
        (Printf.sprintf "%s@4" (hex (hash_of s4))) (active_tip state)))

(* Negative control: with no valid side prefix heavier than x3 (s4 also
   pays 51 BTC), the node stays on x3 and both side blocks are failed. *)
let test_invalidate_no_valid_prefix_stays () =
  let a1, a2, x3, x4, x5, s3, _, _ = chain () in
  let s4bad = make_block ~overpay:Consensus.coin ~prev_hash:(hash_of s3)
      ~prev_time:s3.Types.header.Types.timestamp ~height:4 ~tag:3 () in
  let s5 = make_block ~prev_hash:(hash_of s4bad)
      ~prev_time:s4bad.Types.header.Types.timestamp ~height:5 ~tag:3 () in
  Test_tmp.with_dir ~label:"frp_neg" ~mkdir:true (fun path ->
    with_node path (fun _db state utxo submit ->
      List.iter submit [a1; a2; x3; x4; x5; s3; s4bad; s5];
      (match Sync.invalidate_block state ~utxo_set:utxo (hash_of x4) with
       | Ok _ -> () | Error e -> Alcotest.failf "invalidateblock: %s" e);
      Alcotest.(check bool) "s4bad marked failed" true
        (Sync.is_block_invalid state (hash_of s4bad));
      Alcotest.(check string) "tip stays on x3"
        (Printf.sprintf "%s@3" (hex (hash_of x3))) (active_tip state)))

(* Core failed_reorg b-restart and scenario C: the tip found by the retry
   survives a restart, and a block extending it connects.  Before the best
   header was kept with the active tip, the retry left the persisted best
   header below the new tip, the restarted node had no validated tip, and
   every later submitblock was rejected. *)
let test_retry_tip_survives_restart () =
  let a1, a2, x3, x4, x5, s3, s4, s5bad = chain () in
  let c1 = make_block ~prev_hash:(hash_of s4)
      ~prev_time:s4.Types.header.Types.timestamp ~height:5 ~tag:4 () in
  Test_tmp.with_dir ~label:"frp_restart" ~mkdir:true (fun path ->
    with_node path (fun _db state utxo submit ->
      List.iter submit [a1; a2; x3; x4; x5; s3; s4; s5bad];
      (match Sync.invalidate_block state ~utxo_set:utxo (hash_of x4) with
       | Ok _ -> () | Error e -> Alcotest.failf "invalidateblock: %s" e));
    let db = Storage.ChainDB.create path in
    Fun.protect ~finally:(fun () -> try Storage.ChainDB.close db with _ -> ())
      (fun () ->
        let state = Sync.restore_chain_state db Consensus.regtest in
        state.Sync.sync_state <- Sync.FullySynced;
        Alcotest.(check string) "tip after restart is s4"
          (Printf.sprintf "%s@4" (hex (hash_of s4))) (active_tip state);
        let utxo = Utxo.OptimizedUtxoSet.create ~cache_size:10_000 db in
        Sync.shared_utxo_set := Some utxo;
        Fun.protect ~finally:(fun () -> Sync.shared_utxo_set := None)
          (fun () ->
            let mp = Mempool.create ~network:Consensus.regtest
                ~require_standard:false ~verify_scripts:false
                ~utxo:(Utxo.UtxoSet.create db) ~current_height:4 () in
            (match Mining.submit_block ~utxo ~network_type:Consensus.Regtest
                     c1 state mp with
             | Ok () -> ()
             | Error e -> Alcotest.failf "child of s4 after restart: %s" e);
            Alcotest.(check string) "child of s4 connects"
              (Printf.sprintf "%s@5" (hex (hash_of c1))) (active_tip state))))

let () =
  Alcotest.run "failed_reorg_prefix" [
    "activate_best_chain", [
      Alcotest.test_case "invalidate keeps the valid side prefix" `Quick
        test_invalidate_keeps_valid_side_prefix;
      Alcotest.test_case "no valid prefix: stays on the parent" `Quick
        test_invalidate_no_valid_prefix_stays;
      Alcotest.test_case "retry tip survives restart" `Quick
        test_retry_tip_survives_restart;
    ];
  ]
