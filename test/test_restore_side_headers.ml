(* A restart must reload every stored header, not only the active chain.

   Core: LoadBlockIndex (node/blockstorage.cpp) rebuilds the whole block
   tree from the block index, side branches and failed blocks included, so
   reconsiderblock, getblockheader and getchaintips see the same blocks
   after a restart as before it.

   camlcoin's restore loaded headers through the height->hash index, which
   holds only the active chain (plus the walk from the persisted best
   header).  A side-branch block stored by submitblock, or a block that
   invalidateblock had displaced from the active chain, was in the header
   table before the restart and gone after it: reconsiderblock answered
   "Block not found" and getblockheader returned the stored bytes with
   height 0 and chainwork 0 (Core regtest failed_reorg e-reconsider,
   e-restart-invalidated and e-restart displaced-header rows).

     dune exec --no-buffer test/test_restore_side_headers.exe
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

let make_block ~prev_hash ~prev_time ~height ~tag : Types.block =
  let extra_nonce = Cstruct.create 8 in
  Cstruct.LE.set_uint64 extra_nonce 0 (Int64.of_int (height + (tag lsl 32)));
  let mk wr =
    Mining.create_coinbase ~height ~total_fee:0L ~payout_script:op_true
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
  let a1 = make_block ~prev_hash:ghash ~prev_time:g.Types.timestamp ~height:1 ~tag:1 in
  let a2 = make_block ~prev_hash:(hash_of a1)
      ~prev_time:a1.Types.header.Types.timestamp ~height:2 ~tag:1 in
  let a3 = make_block ~prev_hash:(hash_of a2)
      ~prev_time:a2.Types.header.Types.timestamp ~height:3 ~tag:1 in
  let s3 = make_block ~prev_hash:(hash_of a2)
      ~prev_time:a2.Types.header.Types.timestamp ~height:3 ~tag:2 in
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

let active_tip state =
  match Sync.block_tip state with
  | Some (e : Sync.header_entry) -> Printf.sprintf "%s@%d" (hex e.hash) e.height
  | None -> "none"

let entry state (b : Types.block) =
  Hashtbl.find_opt state.Sync.headers (Cstruct.to_string (hash_of b))

let restart path f =
  let db = Storage.ChainDB.create path in
  Fun.protect ~finally:(fun () -> try Storage.ChainDB.close db with _ -> ())
    (fun () -> f (Sync.restore_chain_state db Consensus.regtest))

let check_entry state name (b : Types.block) height =
  match entry state b with
  | None -> Alcotest.failf "%s missing from the header table after restart" name
  | Some (e : Sync.header_entry) ->
    Alcotest.(check int) (name ^ " height") height e.height

(* Core getblockheader / getchaintips after restart: the equal-work side
   block s3 and the two-block lesser-work branch t2-t3 off a1 are still
   known with their real height and chainwork. *)
let test_side_branch_headers_survive_restart () =
  let a1, a2, a3, s3 = blocks () in
  let t2 = make_block ~prev_hash:(hash_of a1)
      ~prev_time:a1.Types.header.Types.timestamp ~height:2 ~tag:3 in
  let t3 = make_block ~prev_hash:(hash_of t2)
      ~prev_time:t2.Types.header.Types.timestamp ~height:3 ~tag:3 in
  Test_tmp.with_dir ~label:"rsh_side" ~mkdir:true (fun path ->
    let before = ref [] in
    with_node path (fun _db state _utxo submit ->
      List.iter submit [a1; a2; a3; s3; t2; t3];
      before := List.map (fun b ->
          match entry state b with
          | Some (e : Sync.header_entry) -> (e.height, Cstruct.to_string e.total_work)
          | None -> Alcotest.fail "side header missing before restart")
          [s3; t2; t3]);
    restart path (fun state ->
      Alcotest.(check string) "active tip is still a3"
        (Printf.sprintf "%s@3" (hex (hash_of a3))) (active_tip state);
      check_entry state "s3" s3 3;
      check_entry state "t2" t2 2;
      check_entry state "t3" t3 3;
      let after = List.map (fun b ->
          match entry state b with
          | Some (e : Sync.header_entry) -> (e.height, Cstruct.to_string e.total_work)
          | None -> (-1, "")) [s3; t2; t3] in
      Alcotest.(check bool) "height and chainwork as before the restart" true
        (after = !before)))

(* Core failed_reorg e-reconsider: invalidateblock a3 (the node moves to
   s3), restart, reconsiderblock a3 succeeds and the tip stays on s3 (equal
   work, s3 is active). *)
let test_reconsider_displaced_block_after_restart () =
  let a1, a2, a3, s3 = blocks () in
  Test_tmp.with_dir ~label:"rsh_recon" ~mkdir:true (fun path ->
    with_node path (fun _db state utxo submit ->
      List.iter submit [a1; a2; a3; s3];
      (match Sync.invalidate_block state ~utxo_set:utxo (hash_of a3) with
       | Ok _ -> () | Error e -> Alcotest.failf "invalidateblock: %s" e);
      Alcotest.(check string) "active tip moved to s3"
        (Printf.sprintf "%s@3" (hex (hash_of s3))) (active_tip state));
    restart path (fun state ->
      check_entry state "a3 (invalidated, displaced)" a3 3;
      Alcotest.(check bool) "a3 still marked invalid after restart" true
        (Sync.is_block_invalid state (hash_of a3));
      (match Sync.reconsider_block state (hash_of a3) with
       | Ok _ -> ()
       | Error e -> Alcotest.failf "reconsiderblock a3 after restart: %s" e);
      Alcotest.(check bool) "a3 no longer marked invalid" false
        (Sync.is_block_invalid state (hash_of a3));
      Alcotest.(check string) "tip stays on s3"
        (Printf.sprintf "%s@3" (hex (hash_of s3))) (active_tip state)))

(* A stored header whose parent was never stored has no place in the tree
   and must stay out of it (no height can be given to it). *)
let test_orphan_header_not_loaded () =
  let a1, a2, a3, _ = blocks () in
  let missing_parent = make_block ~prev_hash:(hash_of a3)
      ~prev_time:a3.Types.header.Types.timestamp ~height:4 ~tag:9 in
  let orphan = make_block ~prev_hash:(hash_of missing_parent)
      ~prev_time:missing_parent.Types.header.Types.timestamp ~height:5 ~tag:9 in
  Test_tmp.with_dir ~label:"rsh_orphan" ~mkdir:true (fun path ->
    with_node path (fun db _state _utxo submit ->
      List.iter submit [a1; a2; a3];
      Storage.ChainDB.store_block_header db (hash_of orphan) orphan.Types.header);
    restart path (fun state ->
      Alcotest.(check bool) "orphan header not in the table" true
        (entry state orphan = None);
      Alcotest.(check string) "active tip is a3"
        (Printf.sprintf "%s@3" (hex (hash_of a3))) (active_tip state)))

let () =
  Alcotest.run "restore_side_headers" [
    "restore", [
      Alcotest.test_case "side-branch headers survive restart" `Quick
        test_side_branch_headers_survive_restart;
      Alcotest.test_case "reconsider a displaced block after restart" `Quick
        test_reconsider_displaced_block_after_restart;
      Alcotest.test_case "orphan header is not loaded" `Quick
        test_orphan_header_not_loaded;
    ];
  ]
