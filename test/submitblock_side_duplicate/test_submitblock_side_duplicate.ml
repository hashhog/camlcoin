(* submitblock of a side-branch block that is already stored answers
   "duplicate", as Core does.

   Core rpc/mining.cpp submitblock (v31.1, lines 1092-1099):
     bool accepted = chainman.ProcessNewBlock(..., &new_block);
     if (!new_block && accepted) return "duplicate";
   ChainstateManager::AcceptBlock (validation.cpp:4302-4329) clears
   *fNewBlock first and returns true at "if (fAlreadyHave) return true;"
   when the index entry already has BLOCK_HAVE_DATA, so a resubmitted
   side block that was stored (and never connected or failed) is
   accepted && !new_block -> "duplicate".

   camlcoin's Sync.try_attach_side_branch_and_reorg answered such a
   resubmission with Ok Side_accepted, which the RPC rendered as null --
   BIP-22 "accepted", a validity claim about a block nobody connected.
   Core regtest row warden_invalidated_submit/submit/inconclusive-resubmit:$
   (core "duplicate", camlcoin null).

     dune exec --no-buffer test/submitblock_side_duplicate/test_submitblock_side_duplicate.exe
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

(* [overpay] adds to the coinbase value, so a 1 BTC overpay fails
   ConnectBlock with bad-cb-amount but passes CheckBlock. *)
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
let hex = Types.hash256_to_hex_display

let block_hex (b : Types.block) =
  let w = Serialize.writer_create () in
  Serialize.serialize_block w b;
  let cs = Serialize.writer_to_cstruct w in
  let buf = Buffer.create (Cstruct.length cs * 2) in
  for i = 0 to Cstruct.length cs - 1 do
    Buffer.add_string buf (Printf.sprintf "%02x" (Cstruct.get_uint8 cs i))
  done;
  Buffer.contents buf

(* A regtest node on a fresh datadir behind the real RPC handler. *)
let with_node label f =
  Test_tmp.with_dir ~label ~mkdir:true (fun path ->
    let db = Storage.ChainDB.create path in
    Fun.protect ~finally:(fun () -> try Storage.ChainDB.close db with _ -> ())
      (fun () ->
        let chain = Sync.create_chain_state db Consensus.regtest in
        chain.Sync.sync_state <- Sync.FullySynced;
        let utxo = Utxo.OptimizedUtxoSet.create ~cache_size:10_000 db in
        Sync.shared_utxo_set := Some utxo;
        let mempool = Mempool.create ~network:Consensus.regtest
            ~require_standard:false ~verify_scripts:false
            ~utxo:(Utxo.UtxoSet.create db) ~current_height:0 () in
        let ctx : Rpc.rpc_context = {
          chain; mempool;
          peer_manager = Peer_manager.create Consensus.regtest;
          wallet = None; wallet_manager = None;
          fee_estimator = Fee_estimation.create ();
          network = Consensus.regtest;
          filter_index = None; utxo = Some utxo; data_dir = None;
          snapshot_activation = None;
        } in
        Fun.protect ~finally:(fun () -> Sync.shared_utxo_set := None)
          (fun () -> f ctx)))

(* The BIP-22 answer as the harness sees it: null, a string, or an error. *)
let submit ctx b =
  match Rpc.handle_submitblock ctx [`String (block_hex b)] with
  | Ok `Null -> "null"
  | Ok (`String s) -> s
  | Ok j -> "unexpected:" ^ Yojson.Safe.to_string j
  | Error e -> "rpc-error:" ^ e

let tip (ctx : Rpc.rpc_context) =
  match Sync.block_tip ctx.chain with
  | Some (e : Sync.header_entry) -> Printf.sprintf "%s@%d" (hex e.hash) e.height
  | None -> "none"

let at b h = Printf.sprintf "%s@%d" (hex (hash_of b)) h

(* The harness case: a height-1 sibling of the active chain, submitted
   twice.  First answer inconclusive (stored, not connected), second
   duplicate. *)
let test_resubmit_stored_side_block_duplicate () =
  with_node "sbd_resubmit" (fun ctx ->
    let a1 = make_block ~prev:None ~height:1 ~tag:1 () in
    let a2 = make_block ~prev:(Some a1) ~height:2 ~tag:1 () in
    let s1 = make_block ~prev:None ~height:1 ~tag:2 () in
    List.iter (fun b ->
      Alcotest.(check string) "active-chain block accepted" "null" (submit ctx b))
      [a1; a2];
    Alcotest.(check string) "first submit of side block" "inconclusive"
      (submit ctx s1);
    Alcotest.(check string) "resubmit of stored side block" "duplicate"
      (submit ctx s1);
    Alcotest.(check string) "tip stays on 2" (at a2 2) (tip ctx))

(* A stored side block that would fail ConnectBlock (overpays) was never
   connected, so it is not marked failed: Core still answers "duplicate"
   (AcceptBlock's fAlreadyHave runs before any connect), never null. *)
let test_resubmit_stored_bad_side_block_duplicate () =
  with_node "sbd_bad" (fun ctx ->
    let a1 = make_block ~prev:None ~height:1 ~tag:1 () in
    let a2 = make_block ~prev:(Some a1) ~height:2 ~tag:1 () in
    let a3 = make_block ~prev:(Some a2) ~height:3 ~tag:1 () in
    let s2 = make_block ~prev:(Some a1) ~height:2 ~tag:2 () in
    let s3bad = make_block ~overpay:Consensus.coin ~prev:(Some s2)
        ~height:3 ~tag:2 () in
    List.iter (fun b -> ignore (submit ctx b)) [a1; a2; a3];
    Alcotest.(check string) "2' inconclusive" "inconclusive" (submit ctx s2);
    Alcotest.(check string) "bad 3' at equal work" "inconclusive"
      (submit ctx s3bad);
    Alcotest.(check string) "resubmit bad 3'" "duplicate" (submit ctx s3bad);
    Alcotest.(check string) "tip stays on 3" (at a3 3) (tip ctx))

(* Consensus guard: answering "duplicate" must not stop a stored side block
   from becoming active later.  After the duplicate answer, a heavier child
   on that branch still reorgs onto it (null, tip moves), and an invalid
   heavier child is still rejected with its reason. *)
let test_duplicate_side_block_still_reorgs () =
  with_node "sbd_reorg" (fun ctx ->
    let a1 = make_block ~prev:None ~height:1 ~tag:1 () in
    let a2 = make_block ~prev:(Some a1) ~height:2 ~tag:1 () in
    let s2 = make_block ~prev:(Some a1) ~height:2 ~tag:2 () in
    let s3 = make_block ~prev:(Some s2) ~height:3 ~tag:2 () in
    let s3bad = make_block ~overpay:Consensus.coin ~prev:(Some s2)
        ~height:3 ~tag:3 () in
    List.iter (fun b -> ignore (submit ctx b)) [a1; a2];
    Alcotest.(check string) "2' inconclusive" "inconclusive" (submit ctx s2);
    Alcotest.(check string) "2' resubmit duplicate" "duplicate" (submit ctx s2);
    Alcotest.(check string) "tip still 2" (at a2 2) (tip ctx);
    Alcotest.(check string) "heavier bad 3' rejected with its reason"
      "bad-cb-amount" (submit ctx s3bad);
    Alcotest.(check string) "heavier valid 3' accepted" "null" (submit ctx s3);
    Alcotest.(check string) "tip moved to 3'" (at s3 3) (tip ctx);
    Alcotest.(check string) "2' now active: duplicate" "duplicate"
      (submit ctx s2))

(* Control: resubmitting an active-chain block was already "duplicate". *)
let test_resubmit_active_block_duplicate () =
  with_node "sbd_active" (fun ctx ->
    let a1 = make_block ~prev:None ~height:1 ~tag:1 () in
    Alcotest.(check string) "a1 accepted" "null" (submit ctx a1);
    Alcotest.(check string) "a1 resubmit" "duplicate" (submit ctx a1))

let () =
  Alcotest.run "submitblock_side_duplicate" [
    "submitblock", [
      Alcotest.test_case "resubmit stored side block answers duplicate" `Quick
        test_resubmit_stored_side_block_duplicate;
      Alcotest.test_case "resubmit stored unconnected bad side block answers duplicate"
        `Quick test_resubmit_stored_bad_side_block_duplicate;
      Alcotest.test_case "duplicate side block still reorgs when outweighed"
        `Quick test_duplicate_side_block_still_reorgs;
      Alcotest.test_case "resubmit active block answers duplicate (control)"
        `Quick test_resubmit_active_block_duplicate;
    ];
  ]
