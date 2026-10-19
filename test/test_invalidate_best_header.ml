(* invalidateblock must recompute the best header, and a restart must find
   the active tip again.

   Core: InvalidateBlock -> InvalidChainFound (validation.cpp) calls
   ChainstateManager::RecalculateBestHeader when m_best_header descends
   from the block just marked failed.  RecalculateBestHeader starts at
   ActiveChain().Tip() and takes any header in the block index with more
   work that is not BLOCK_FAILED_VALID.  getblockchaininfo "headers" is
   that header's height.

   camlcoin's rewind set the best header to the PARENT of the invalidated
   block (in memory and in the persisted header_tip record) and nothing
   raised it again when the post-invalidate ActivateBestChain reorganized
   onto an equal-work side branch.  The persisted best header then sat one
   block below the active tip, a restart loaded headers only up to it, the
   active tip was missing from the header table, and getchaintips answered
   [] (Core regtest failed_reorg e-restart rows).  With no side branch, the
   in-memory headers count stayed at the invalidated block's height
   (Core regtest chain/invalidate/info:headers 109 vs 110).

     dune exec --no-buffer test/test_invalidate_best_header.exe
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

(* a1-a2-a3 on genesis, and s3 off a2 (same work as a3, a different
   coinbase so a different hash). *)
let blocks () =
  let g = Consensus.regtest.Consensus.genesis_header in
  let ghash = Consensus.regtest.Consensus.genesis_hash in
  let a1 = make_block ~prev_hash:ghash ~prev_time:g.Types.timestamp ~height:1 ~tag:1 () in
  let a2 = make_block ~prev_hash:(hash_of a1)
      ~prev_time:a1.Types.header.Types.timestamp ~height:2 ~tag:1 () in
  let a3 = make_block ~prev_hash:(hash_of a2)
      ~prev_time:a2.Types.header.Types.timestamp ~height:3 ~tag:1 () in
  let s3 = make_block ~prev_hash:(hash_of a2)
      ~prev_time:a2.Types.header.Types.timestamp ~height:3 ~tag:2 () in
  (a1, a2, a3, s3)

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

let persisted_header_tip db =
  match Storage.ChainDB.get_header_tip db with
  | Some (h, height) -> Printf.sprintf "%s@%d" (hex h) height
  | None -> "none"

let active_tip state =
  match Sync.block_tip state with
  | Some (e : Sync.header_entry) -> Printf.sprintf "%s@%d" (hex e.hash) e.height
  | None -> "none"

(* Core chain/invalidate: invalidate the tip with no other branch; the best
   header is the new active tip (its parent), headers = 2. *)
let test_invalidate_tip_lowers_best_header () =
  let a1, a2, a3, _ = blocks () in
  Test_tmp.with_dir ~label:"invbh_tip" ~mkdir:true (fun path ->
    with_node path (fun db state utxo submit ->
      List.iter submit [a1; a2; a3];
      (match Sync.invalidate_block state ~utxo_set:utxo (hash_of a3) with
       | Ok _ -> () | Error e -> Alcotest.failf "invalidateblock: %s" e);
      Alcotest.(check string) "active tip is a2"
        (Printf.sprintf "%s@2" (hex (hash_of a2))) (active_tip state);
      Alcotest.(check int) "getblockchaininfo headers (Core 2)" 2
        state.Sync.headers_synced;
      Alcotest.(check string) "persisted best header is a2"
        (Printf.sprintf "%s@2" (hex (hash_of a2))) (persisted_header_tip db)))

(* Core failed_reorg e-invalidate / e-restart-invalidated: invalidate a3
   while an equal-work s3 is stored; ActivateBestChain moves to s3 and the
   best header is s3.  After a restart the active tip is still s3. *)
let test_invalidate_onto_side_branch_survives_restart () =
  let a1, a2, a3, s3 = blocks () in
  Test_tmp.with_dir ~label:"invbh_side" ~mkdir:true (fun path ->
    with_node path (fun db state utxo submit ->
      List.iter submit [a1; a2; a3; s3];
      Alcotest.(check string) "a3 stays active (first seen)"
        (Printf.sprintf "%s@3" (hex (hash_of a3))) (active_tip state);
      (match Sync.invalidate_block state ~utxo_set:utxo (hash_of a3) with
       | Ok _ -> () | Error e -> Alcotest.failf "invalidateblock: %s" e);
      Alcotest.(check string) "active tip moved to s3"
        (Printf.sprintf "%s@3" (hex (hash_of s3))) (active_tip state);
      Alcotest.(check int) "getblockchaininfo headers (Core 3)" 3
        state.Sync.headers_synced;
      Alcotest.(check string) "persisted best header is s3"
        (Printf.sprintf "%s@3" (hex (hash_of s3))) (persisted_header_tip db));
    (* restart on the same datadir *)
    let db = Storage.ChainDB.create path in
    Fun.protect ~finally:(fun () -> try Storage.ChainDB.close db with _ -> ())
      (fun () ->
        let state = Sync.restore_chain_state db Consensus.regtest in
        Alcotest.(check string) "after restart the active tip is s3"
          (Printf.sprintf "%s@3" (hex (hash_of s3))) (active_tip state);
        Alcotest.(check int) "after restart headers = 3" 3
          state.Sync.headers_synced))

(* Negative side: invalidating a block that is NOT under the best header
   leaves the best header where it was (Core only recalculates when
   m_best_header descends from the failed block). *)
let test_invalidate_side_block_keeps_best_header () =
  let a1, a2, a3, s3 = blocks () in
  Test_tmp.with_dir ~label:"invbh_keep" ~mkdir:true (fun path ->
    with_node path (fun db state utxo submit ->
      List.iter submit [a1; a2; a3; s3];
      (match Sync.invalidate_block state ~utxo_set:utxo (hash_of s3) with
       | Ok _ -> () | Error e -> Alcotest.failf "invalidateblock: %s" e);
      Alcotest.(check string) "active tip stays a3"
        (Printf.sprintf "%s@3" (hex (hash_of a3))) (active_tip state);
      Alcotest.(check int) "headers stays 3" 3 state.Sync.headers_synced;
      Alcotest.(check string) "persisted best header stays a3"
        (Printf.sprintf "%s@3" (hex (hash_of a3))) (persisted_header_tip db)))

(* Core failed_reorg b-invalidate / b-restart (KB-176 shape):
     a1-a2-x3-x4-x5, and s3-s4-s5bad off a2 (s5bad pays 51 BTC).
   invalidateblock x4: the post-invalidate reorg towards s5bad fails, s5bad
   is marked failed and the best header is s4, above the active chain.  A
   restart must never put the invalidated x4 back on the active chain: its
   old height row must be gone, so restore cannot read it as the block at
   height 4. *)
let test_invalidated_block_not_active_after_restart () =
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
  Test_tmp.with_dir ~label:"invbh_b" ~mkdir:true (fun path ->
    with_node path (fun db state utxo submit ->
      List.iter submit [a1; a2; x3; x4; x5; s3; s4; s5bad];
      (match Sync.invalidate_block state ~utxo_set:utxo (hash_of x4) with
       | Ok _ -> () | Error e -> Alcotest.failf "invalidateblock: %s" e);
      Alcotest.(check bool) "no height row above the active tip" true
        (Storage.ChainDB.get_hash_at_height db (state.Sync.blocks_synced + 1)
         = None));
    let db = Storage.ChainDB.create path in
    Fun.protect ~finally:(fun () -> try Storage.ChainDB.close db with _ -> ())
      (fun () ->
        let state = Sync.restore_chain_state db Consensus.regtest in
        Alcotest.(check bool) "x4 still marked invalid" true
          (Sync.is_block_invalid state (hash_of x4));
        Alcotest.(check bool) "x4 is not the header at height 4" true
          (match Sync.get_header_at_height state 4 with
           | Some (e : Sync.header_entry) -> not (Cstruct.equal e.hash (hash_of x4))
           | None -> true);
        Alcotest.(check bool) "active tip is not x4 or above" true
          (match Sync.block_tip state with
           | Some (e : Sync.header_entry) ->
             e.height <= 4 && not (Cstruct.equal e.hash (hash_of x4))
           | None -> false)))

let () =
  Alcotest.run "invalidate_best_header" [
    "recalculate_best_header", [
      Alcotest.test_case "invalidate tip lowers the best header" `Quick
        test_invalidate_tip_lowers_best_header;
      Alcotest.test_case "invalidate onto a side branch survives restart" `Quick
        test_invalidate_onto_side_branch_survives_restart;
      Alcotest.test_case "invalidate a side block keeps the best header" `Quick
        test_invalidate_side_block_keeps_best_header;
      Alcotest.test_case "invalidated block not active after restart" `Quick
        test_invalidated_block_not_active_after_restart;
    ];
  ]
