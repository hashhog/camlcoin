(* getchaintips reports every tip of the block tree, as Core does.

   Core rpc/blockchain.cpp getchaintips: a tip is every block-index entry
   that is not on the active chain and has no child, plus the active tip.
   branchlen is the distance to the fork point with the active chain;
   status is active / invalid (a BLOCK_FAILED flag) / headers-only (nChainTx 0:
   the block or an ancestor has no data) / valid-fork (BLOCK_VALID_SCRIPTS:
   the block was connected once) / valid-headers (data, never connected).

   camlcoin answered only the active tip (plus the best header when it was
   ahead), so every side branch, every invalidated or failed block and
   every block a reorg displaced was missing: Core regtest getchaintips
   rows in chain, reorg, failed_reorg, seed_invalidated_submit and
   warden_invalidated_submit (fleet item done-fleet-regtest-getchaintips).

     dune exec --no-buffer test/test_getchaintips_fleet/test_getchaintips_fleet.exe
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

(* [overpay] adds to the coinbase value: a 1 BTC overpay fails ConnectBlock
   with bad-cb-amount but passes CheckBlock. *)
let make_block ?(overpay = 0L) ~(prev : Types.block option) ~height ~tag ()
    : Types.block =
  let prev_hash, prev_time = match prev with
    | None -> Consensus.regtest.Consensus.genesis_hash,
              Consensus.regtest.Consensus.genesis_header.Types.timestamp
    | Some p -> Crypto.compute_block_hash p.Types.header,
                p.Types.header.Types.timestamp in
  let extra_nonce = Cstruct.create 8 in
  Cstruct.LE.set_uint64 extra_nonce 0 (Int64.of_int (height + (tag lsl 32)));
  let mk wr =
    Mining.create_coinbase ~height ~total_fee:overpay ~payout_script:op_true
      ~extra_nonce ~witness_root:wr ~network_type:Consensus.Regtest ()
  in
  let wr = Mining.compute_witness_merkle_root [mk None] in
  let coinbase = mk (Some wr) in
  let merkle_root, _ = Crypto.merkle_root [Crypto.compute_txid coinbase] in
  remine { Types.header = { version = 4l; prev_block = prev_hash; merkle_root;
                            timestamp = Int32.add prev_time 600l;
                            bits = Consensus.regtest.pow_limit; nonce = 0l };
           transactions = [coinbase] }

let hash_of (b : Types.block) = Crypto.compute_block_hash b.Types.header
let hex_of (b : Types.block) = Types.hash256_to_hex_display (hash_of b)

let block_hex (b : Types.block) =
  let w = Serialize.writer_create () in
  Serialize.serialize_block w b;
  let cs = Serialize.writer_to_cstruct w in
  let buf = Buffer.create (Cstruct.length cs * 2) in
  for i = 0 to Cstruct.length cs - 1 do
    Buffer.add_string buf (Printf.sprintf "%02x" (Cstruct.get_uint8 cs i))
  done;
  Buffer.contents buf

let ctx_of db chain : Rpc.rpc_context =
  let utxo = Utxo.OptimizedUtxoSet.create ~cache_size:10_000 db in
  Sync.shared_utxo_set := Some utxo;
  let mempool = Mempool.create ~network:Consensus.regtest
      ~require_standard:false ~verify_scripts:false
      ~utxo:(Utxo.UtxoSet.create db) ~current_height:0 () in
  { chain; mempool;
    peer_manager = Peer_manager.create Consensus.regtest;
    wallet = None; wallet_manager = None;
    fee_estimator = Fee_estimation.create ();
    network = Consensus.regtest;
    filter_index = None; utxo = Some utxo; data_dir = None;
    snapshot_activation = None }

let open_db path f =
  let db = Storage.ChainDB.create path in
  Fun.protect
    ~finally:(fun () ->
      Sync.shared_utxo_set := None;
      try Storage.ChainDB.close db with _ -> ())
    (fun () -> f db)

(* A regtest node on a fresh datadir behind the real RPC handlers. *)
let fresh_node path f =
  open_db path (fun db ->
    let chain = Sync.create_chain_state db Consensus.regtest in
    chain.Sync.sync_state <- Sync.FullySynced;
    f (ctx_of db chain))

(* The same datadir after a restart (Core LoadBlockIndex). *)
let restarted_node path f =
  open_db path (fun db ->
    let chain = Sync.restore_chain_state db Consensus.regtest in
    chain.Sync.sync_state <- Sync.FullySynced;
    f (ctx_of db chain))

let submit ctx b =
  match Rpc.handle_submitblock ctx [`String (block_hex b)] with
  | Ok `Null -> "null"
  | Ok (`String s) -> s
  | Ok j -> "unexpected:" ^ Yojson.Safe.to_string j
  | Error e -> "rpc-error:" ^ e

let submit_ok ctx b =
  match submit ctx b with
  | "null" -> ()
  | r -> Alcotest.failf "submitblock %s: %s" (hex_of b) r

let submitheader ctx b =
  match Rpc.handle_submitheader ctx [`String (String.sub (block_hex b) 0 160)] with
  | Ok _ -> ()
  | Error (_, e) -> Alcotest.failf "submitheader %s: %s" (hex_of b) e

let rpc_ok what = function
  | Ok _ -> ()
  | Error e -> Alcotest.failf "%s: %s" what e

(* getchaintips as a sorted "hash height branchlen status" list, the set
   the Core regtest harness compares (keyed by hash). *)
let tips ctx =
  match Rpc.handle_getchaintips ctx with
  | `List l ->
    List.map (function
      | `Assoc kv ->
        let s k = match List.assoc_opt k kv with
          | Some (`String v) -> v
          | Some (`Int i) -> string_of_int i
          | _ -> "?" in
        String.concat " " [s "hash"; s "height"; s "branchlen"; s "status"]
      | j -> "bad:" ^ Yojson.Safe.to_string j) l
    |> List.sort compare
  | j -> ["not a list: " ^ Yojson.Safe.to_string j]

let tip b height branchlen status =
  String.concat " " [hex_of b; string_of_int height; string_of_int branchlen;
                     status]

let check_tips msg expected ctx =
  Alcotest.(check (list string)) msg (List.sort compare expected) (tips ctx)

let chain3 () =
  let a1 = make_block ~prev:None ~height:1 ~tag:1 () in
  let a2 = make_block ~prev:(Some a1) ~height:2 ~tag:1 () in
  let a3 = make_block ~prev:(Some a2) ~height:3 ~tag:1 () in
  (a1, a2, a3)

(* Core chain/tips/final 7c898bd0: a stored side block that was never
   connected is "valid-headers". *)
let test_stored_side_block_valid_headers () =
  Test_tmp.with_dir ~label:"gct_side" ~mkdir:true (fun path ->
    fresh_node path (fun ctx ->
      let a1, a2, a3 = chain3 () in
      List.iter (submit_ok ctx) [a1; a2; a3];
      let s3 = make_block ~prev:(Some a2) ~height:3 ~tag:2 () in
      let g1 = make_block ~prev:None ~height:1 ~tag:3 () in
      Alcotest.(check string) "s3 stored" "inconclusive" (submit ctx s3);
      Alcotest.(check string) "g1 stored" "inconclusive" (submit ctx g1);
      check_tips "active tip + two stored side blocks"
        [tip a3 3 0 "active"; tip s3 3 1 "valid-headers";
         tip g1 1 1 "valid-headers"] ctx))

(* Core failed_reorg d/e 795f067e: a block a reorg displaced was connected
   once, so it is "valid-fork"; and it stays so across a restart. *)
let test_displaced_block_valid_fork_survives_restart () =
  Test_tmp.with_dir ~label:"gct_fork" ~mkdir:true (fun path ->
    let a1, a2, a3 = chain3 () in
    let s3 = make_block ~prev:(Some a2) ~height:3 ~tag:2 () in
    let s4 = make_block ~prev:(Some s3) ~height:4 ~tag:2 () in
    let expected = [tip s4 4 0 "active"; tip a3 3 1 "valid-fork"] in
    fresh_node path (fun ctx ->
      List.iter (submit_ok ctx) [a1; a2; a3];
      Alcotest.(check string) "s3 stored" "inconclusive" (submit ctx s3);
      submit_ok ctx s4;
      check_tips "a3 displaced by the reorg to s4" expected ctx);
    restarted_node path (fun ctx ->
      check_tips "same tips after a restart" expected ctx))

(* Core chain/invalidate 2452e2dd and seed/warden after-invalidate-100: an
   invalidated block and its descendants stay in the index; the childless
   leaf is the tip, "invalid", branchlen from the fork. *)
let test_invalidated_blocks_invalid () =
  Test_tmp.with_dir ~label:"gct_inv" ~mkdir:true (fun path ->
    fresh_node path (fun ctx ->
      let a1, a2, a3 = chain3 () in
      List.iter (submit_ok ctx) [a1; a2; a3];
      rpc_ok "invalidateblock a3"
        (Rpc.handle_invalidateblock ctx [`String (hex_of a3)]);
      check_tips "invalidated tip" [tip a2 2 0 "active"; tip a3 3 1 "invalid"] ctx;
      rpc_ok "invalidateblock a2"
        (Rpc.handle_invalidateblock ctx [`String (hex_of a2)]);
      check_tips "invalidated ancestor: one leaf, branchlen 2"
        [tip a1 1 0 "active"; tip a3 3 2 "invalid"] ctx;
      rpc_ok "reconsiderblock a2"
        (Rpc.handle_reconsiderblock ctx [`String (hex_of a2)]);
      check_tips "reconsidered: back to one active tip" [tip a3 3 0 "active"] ctx))

(* Core failed_reorg a (KB-165): s4bad outweighs a3, fails ConnectBlock,
   and the node returns to a3; the failed leaf is "invalid" with branchlen
   2 and its valid parent s3 is not a tip. *)
let test_failed_side_block_invalid () =
  Test_tmp.with_dir ~label:"gct_fail" ~mkdir:true (fun path ->
    fresh_node path (fun ctx ->
      let a1, a2, a3 = chain3 () in
      List.iter (submit_ok ctx) [a1; a2; a3];
      let s3 = make_block ~prev:(Some a2) ~height:3 ~tag:2 () in
      let s4bad = make_block ~overpay:Consensus.coin ~prev:(Some s3)
          ~height:4 ~tag:2 () in
      Alcotest.(check string) "s3 stored" "inconclusive" (submit ctx s3);
      Alcotest.(check string) "s4bad rejected" "bad-cb-amount" (submit ctx s4bad);
      check_tips "failed leaf is invalid"
        [tip a3 3 0 "active"; tip s4bad 4 2 "invalid"] ctx))

(* Core warden headers-only / p2p-header: a header without data is
   "headers-only", whether it extends the tip or a side branch. *)
let test_headers_without_data_headers_only () =
  Test_tmp.with_dir ~label:"gct_hdr" ~mkdir:true (fun path ->
    fresh_node path (fun ctx ->
      let a1, a2, _ = chain3 () in
      List.iter (submit_ok ctx) [a1; a2];
      let x2 = make_block ~prev:(Some a1) ~height:2 ~tag:4 () in
      submitheader ctx x2;
      check_tips "side header without data"
        [tip a2 2 0 "active"; tip x2 2 1 "headers-only"] ctx;
      (* A header chain ahead of the tip (h3-h4-h5, the IBD shape) with a
         fork x4 off h3: two leaves, each measured from the active tip. *)
      let h3 = make_block ~prev:(Some a2) ~height:3 ~tag:5 () in
      let h4 = make_block ~prev:(Some h3) ~height:4 ~tag:5 () in
      let h5 = make_block ~prev:(Some h4) ~height:5 ~tag:5 () in
      let x4 = make_block ~prev:(Some h3) ~height:4 ~tag:6 () in
      List.iter (submitheader ctx) [h3; h4; h5; x4];
      check_tips "header chain ahead of the tip, with a fork"
        [tip a2 2 0 "active"; tip x2 2 1 "headers-only";
         tip h5 5 3 "headers-only"; tip x4 4 2 "headers-only"] ctx))

let () =
  Alcotest.run "getchaintips_fleet" [
    "getchaintips", [
      Alcotest.test_case "stored side block is valid-headers" `Quick
        test_stored_side_block_valid_headers;
      Alcotest.test_case "displaced block is valid-fork, survives restart"
        `Quick test_displaced_block_valid_fork_survives_restart;
      Alcotest.test_case "invalidated blocks are invalid" `Quick
        test_invalidated_blocks_invalid;
      Alcotest.test_case "failed side block is invalid" `Quick
        test_failed_side_block_invalid;
      Alcotest.test_case "header without data is headers-only" `Quick
        test_headers_without_data_headers_only;
    ];
  ]
