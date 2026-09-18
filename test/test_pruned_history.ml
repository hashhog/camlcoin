(* Snapshot-boot / missing-history honesty for getblockchaininfo + getblockhash.

   Live mainnet 2026-09-17T22:50Z: getblock on Core's real hash misses at
   1 / 500000 / 900000 / 940000 and HAVEs from 960000, while
   getblockchaininfo claimed pruned:false with no pruneheight.
   getblockhash(1) still answered — that only exercises the height→hash
   index, never a body (receipt
   receipts/CORRECTION-historical-bodies-fleet-wide-2026-09-17.md).

   Core (rpc/blockchain.cpp): pruned is true when the node does not hold
   the full chain; pruneheight is the first height with complete data.
   getblockhash -8 is only for height < 0 or height > tip. An in-range
   height the node does not retain is -1 "Block not available (pruned
   data)" (same string Core's getblock uses for a pruned body).

   This commit reports the truth. It does not backfill genesis→floor.

   CONTROL: dune exec --no-buffer test/test_pruned_history.exe
*)

open Camlcoin

let pruned_msg = "Block not available (pruned data)"
let oor_msg = "Block height out of range"

let with_ctx f =
  Test_tmp.with_chaindb (fun db ->
      let utxo = Utxo.UtxoSet.create db in
      let mp =
        Mempool.create ~network:Consensus.regtest ~require_standard:false
          ~verify_scripts:false ~utxo ~current_height:0 ()
      in
      let chain = Sync.create_chain_state db Consensus.regtest in
      let ctx : Rpc.rpc_context =
        {
          chain;
          mempool = mp;
          peer_manager = Peer_manager.create Consensus.regtest;
          wallet = None;
          wallet_manager = None;
          fee_estimator = Fee_estimation.create ();
          network = Consensus.regtest;
          filter_index = None;
          utxo = None;
          data_dir = None;
          snapshot_activation = None;
        }
      in
      f ctx)

let genesis_entry ctx =
  match Sync.get_header_at_height ctx.Rpc.chain 0 with
  | Some e -> e
  | None -> (
    match ctx.chain.Sync.tip with
    | Some e -> e
    | None -> Alcotest.fail "no genesis")

let make_block ~prev ~height =
  let header =
    {
      Types.version = 1l;
      prev_block = prev;
      merkle_root = Types.zero_hash;
      timestamp = Int32.add 1296688602l (Int32.of_int (height * 600));
      bits = 0x207fffffl;
      nonce = Int32.of_int height;
    }
  in
  let hash = Crypto.compute_block_hash header in
  let block = { Types.header; transactions = [] } in
  (hash, header, block)

type plant = Complete | IndexAndBodyHole | DenseIndexBodyHole

let plant ctx ~floor ~tip mode =
  let genesis = genesis_entry ctx in
  let genesis_block =
    { Types.header = genesis.header; transactions = [] }
  in
  Storage.ChainDB.store_block ctx.chain.db genesis.hash genesis_block;
  let hashes = Array.make (tip + 1) genesis.hash in
  let prev = ref genesis.hash in
  for h = 1 to tip do
    let hash, header, block = make_block ~prev:!prev ~height:h in
    hashes.(h) <- hash;
    let in_tail = h >= floor in
    (match mode with
    | Complete ->
      Storage.ChainDB.store_block_header ctx.chain.db hash header;
      Storage.ChainDB.set_height_hash ctx.chain.db h hash;
      Storage.ChainDB.store_block ctx.chain.db hash block
    | IndexAndBodyHole ->
      if in_tail then begin
        Storage.ChainDB.store_block_header ctx.chain.db hash header;
        Storage.ChainDB.set_height_hash ctx.chain.db h hash;
        Storage.ChainDB.store_block ctx.chain.db hash block
      end
    | DenseIndexBodyHole ->
      Storage.ChainDB.store_block_header ctx.chain.db hash header;
      Storage.ChainDB.set_height_hash ctx.chain.db h hash;
      if in_tail then Storage.ChainDB.store_block ctx.chain.db hash block);
    prev := hash
  done;
  ctx.chain.Sync.blocks_synced <- tip;
  ctx.chain.Sync.headers_synced <- tip;
  ctx.chain.Sync.sync_state <- Sync.FullySynced;
  Storage.ChainDB.set_chain_tip ctx.chain.db hashes.(tip) tip;
  hashes

let info ctx =
  match Rpc.dispatch_rpc ctx "getblockchaininfo" [] with
  | Ok (`Assoc fields) -> fields
  | Ok j ->
    Alcotest.failf "getblockchaininfo: %s" (Yojson.Safe.to_string j)
  | Error (c, m) -> Alcotest.failf "getblockchaininfo error (%d) %s" c m

let bool_field fields name =
  match List.assoc_opt name fields with
  | Some (`Bool b) -> b
  | Some j ->
    Alcotest.failf "%s: expected bool, got %s" name (Yojson.Safe.to_string j)
  | None -> Alcotest.failf "missing field %s" name

let int_field_opt fields name =
  match List.assoc_opt name fields with
  | Some (`Int n) -> Some n
  | Some (`Intlit s) -> Some (int_of_string s)
  | Some j ->
    Alcotest.failf "%s: expected int, got %s" name (Yojson.Safe.to_string j)
  | None -> None

let check_err ~label ~code ~msg result =
  match result with
  | Error (c, m) ->
    Alcotest.(check int) (label ^ ": code") code c;
    Alcotest.(check string) (label ^ ": message") msg m
  | Ok j ->
    Alcotest.failf "%s: expected error (%d) %s but got Ok %s" label code msg
      (Yojson.Safe.to_string j)

let check_hash ~label result =
  match result with
  | Ok (`String s) when String.length s = 64 -> s
  | Ok j ->
    Alcotest.failf "%s: expected 64-hex, got %s" label
      (Yojson.Safe.to_string j)
  | Error (c, m) -> Alcotest.failf "%s: error (%d) %s" label c m

let test_complete_chain_reports_pruned_false () =
  with_ctx (fun ctx ->
      ignore (plant ctx ~floor:1 ~tip:10 Complete);
      let fields = info ctx in
      Alcotest.(check bool) "pruned" false (bool_field fields "pruned");
      Alcotest.(check bool)
        "no pruneheight" true
        (int_field_opt fields "pruneheight" = None);
      Alcotest.(check bool)
        "no prune_target_size" true
        (int_field_opt fields "prune_target_size" = None))

let test_snapshot_hole_reports_pruned_true_and_pruneheight () =
  with_ctx (fun ctx ->
      let floor = 10 and tip = 20 in
      ignore (plant ctx ~floor ~tip IndexAndBodyHole);
      let fields = info ctx in
      Alcotest.(check bool) "pruned" true (bool_field fields "pruned");
      Alcotest.(check (option int))
        "pruneheight is first complete height" (Some floor)
        (int_field_opt fields "pruneheight");
      Alcotest.(check bool)
        "do not invent prune_target_size when -prune is off" true
        (int_field_opt fields "prune_target_size" = None))

let test_dense_index_missing_bodies_reports_pruned_true () =
  with_ctx (fun ctx ->
      let floor = 10 and tip = 20 in
      ignore (plant ctx ~floor ~tip DenseIndexBodyHole);
      let fields = info ctx in
      Alcotest.(check bool) "pruned" true (bool_field fields "pruned");
      Alcotest.(check (option int))
        "pruneheight is first complete body" (Some floor)
        (int_field_opt fields "pruneheight");
      (* Index is dense: getblockhash of an in-range indexed height still
         returns the hash (Core getblockhash is index-only). *)
      ignore
        (check_hash ~label:"getblockhash(5) still answers"
           (Rpc.dispatch_rpc ctx "getblockhash" [ `Int 5 ])))

let test_getblockhash_below_floor_is_minus1_not_minus8 () =
  with_ctx (fun ctx ->
      ignore (plant ctx ~floor:10 ~tip:20 IndexAndBodyHole);
      check_err ~label:"getblockhash(1)" ~code:(-1) ~msg:pruned_msg
        (Rpc.dispatch_rpc ctx "getblockhash" [ `Int 1 ]);
      check_err ~label:"getblockhash(5)" ~code:(-1) ~msg:pruned_msg
        (Rpc.dispatch_rpc ctx "getblockhash" [ `Int 5 ]))

let test_getblockhash_at_floor_and_genesis_return_hash () =
  with_ctx (fun ctx ->
      ignore (plant ctx ~floor:10 ~tip:20 IndexAndBodyHole);
      ignore
        (check_hash ~label:"getblockhash(0)"
           (Rpc.dispatch_rpc ctx "getblockhash" [ `Int 0 ]));
      ignore
        (check_hash ~label:"getblockhash(10)"
           (Rpc.dispatch_rpc ctx "getblockhash" [ `Int 10 ]));
      ignore
        (check_hash ~label:"getblockhash(20)"
           (Rpc.dispatch_rpc ctx "getblockhash" [ `Int 20 ])))

let test_getblockhash_above_tip_is_still_minus8 () =
  with_ctx (fun ctx ->
      ignore (plant ctx ~floor:10 ~tip:20 IndexAndBodyHole);
      check_err ~label:"getblockhash(21)" ~code:(-8) ~msg:oor_msg
        (Rpc.dispatch_rpc ctx "getblockhash" [ `Int 21 ]);
      check_err ~label:"getblockhash(999999)" ~code:(-8) ~msg:oor_msg
        (Rpc.dispatch_rpc ctx "getblockhash" [ `Int 999999 ]))

let test_getblockhash_negative_is_still_minus8 () =
  with_ctx (fun ctx ->
      ignore (plant ctx ~floor:10 ~tip:20 IndexAndBodyHole);
      check_err ~label:"getblockhash(-1)" ~code:(-8) ~msg:oor_msg
        (Rpc.dispatch_rpc ctx "getblockhash" [ `Int (-1) ]))

let test_getblock_missing_body_with_index_is_pruned_data () =
  with_ctx (fun ctx ->
      ignore (plant ctx ~floor:10 ~tip:20 DenseIndexBodyHole);
      let h =
        check_hash ~label:"getblockhash(5)"
          (Rpc.dispatch_rpc ctx "getblockhash" [ `Int 5 ])
      in
      check_err ~label:"getblock missing body" ~code:(-1) ~msg:pruned_msg
        (Rpc.dispatch_rpc ctx "getblock" [ `String h ]);
      let at_floor =
        check_hash ~label:"getblockhash(10)"
          (Rpc.dispatch_rpc ctx "getblockhash" [ `Int 10 ])
      in
      (match Rpc.dispatch_rpc ctx "getblock" [ `String at_floor; `Int 0 ] with
      | Ok (`String _) -> ()
      | Ok j ->
        Alcotest.failf "getblock(floor) expected hex, got %s"
          (Yojson.Safe.to_string j)
      | Error (c, m) ->
        Alcotest.failf "getblock(floor) error (%d) %s" c m))

let test_history_floor_none_when_complete () =
  with_ctx (fun ctx ->
      ignore (plant ctx ~floor:1 ~tip:10 Complete);
      Alcotest.(check (option int))
        "complete chain has no history floor" None
        (Storage.ChainDB.history_floor ctx.chain.db ~tip:10);
      Alcotest.(check (option int))
        "genesis-only tip is not a hole" None
        (Storage.ChainDB.history_floor ctx.chain.db ~tip:0))

let test_history_floor_finds_first_body () =
  with_ctx (fun ctx ->
      ignore (plant ctx ~floor:10 ~tip:20 IndexAndBodyHole);
      Alcotest.(check (option int))
        "index+body hole floor" (Some 10)
        (Storage.ChainDB.history_floor ctx.chain.db ~tip:20))

let test_history_floor_finds_body_hole_behind_dense_index () =
  with_ctx (fun ctx ->
      ignore (plant ctx ~floor:10 ~tip:20 DenseIndexBodyHole);
      Alcotest.(check (option int))
        "dense-index body hole floor" (Some 10)
        (Storage.ChainDB.history_floor ctx.chain.db ~tip:20))

let () =
  let open Alcotest in
  run "pruned history honesty"
    [
      ( "getblockchaininfo",
        [
          test_case "complete chain reports pruned false" `Quick
            test_complete_chain_reports_pruned_false;
          test_case "snapshot hole reports pruned true and pruneheight" `Quick
            test_snapshot_hole_reports_pruned_true_and_pruneheight;
          test_case "dense index missing bodies reports pruned true" `Quick
            test_dense_index_missing_bodies_reports_pruned_true;
        ] );
      ( "getblockhash",
        [
          test_case "below floor is -1 not -8" `Quick
            test_getblockhash_below_floor_is_minus1_not_minus8;
          test_case "floor and genesis return hash" `Quick
            test_getblockhash_at_floor_and_genesis_return_hash;
          test_case "above tip is still -8" `Quick
            test_getblockhash_above_tip_is_still_minus8;
          test_case "negative is still -8" `Quick
            test_getblockhash_negative_is_still_minus8;
        ] );
      ( "getblock",
        [
          test_case "missing body with index is pruned data" `Quick
            test_getblock_missing_body_with_index_is_pruned_data;
        ] );
      ( "history_floor",
        [
          test_case "none when complete" `Quick
            test_history_floor_none_when_complete;
          test_case "finds first body" `Quick test_history_floor_finds_first_body;
          test_case "finds body hole behind dense index" `Quick
            test_history_floor_finds_body_hole_behind_dense_index;
        ] );
    ]
