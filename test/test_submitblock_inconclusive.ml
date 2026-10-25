(* submitblock of a side-branch block that is stored but not connected
   answers "inconclusive", as Core does.

   Core rpc/mining.cpp submitblock registers a submitblock_StateCatcher for
   the block's hash around ProcessNewBlock.  The catcher only fires when
   BlockChecked is signalled for that hash, i.e. when the block was judged
   (CheckBlock / AcceptBlock failed, or ConnectBlock ran on it).  A block
   that AcceptBlock stores on a branch with no more work than the tip is
   never connected, so nothing is caught and Core returns "inconclusive".

   camlcoin answered null for that case, which BIP-22 defines as "accepted":
   a client was told a block it had not validated was valid.  Core regtest
   rows chain/submit/side-branch, failed_reorg/*/{sibling-3s,b3s,b4s,b5s_bad,
   c3s,c4s,d3s,e3s,e4s} and {seed,warden}_invalidated_submit/submit/
   {inconclusive,failed-connect-sibling}.

     dune exec --no-buffer test/test_submitblock_inconclusive.exe
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

(* G-1-2-3 active; 3' (same work as 3) is stored and not connected. *)
let test_equal_work_sibling_inconclusive () =
  with_node "sbi_sib" (fun ctx ->
    let a1 = make_block ~prev:None ~height:1 ~tag:1 () in
    let a2 = make_block ~prev:(Some a1) ~height:2 ~tag:1 () in
    let a3 = make_block ~prev:(Some a2) ~height:3 ~tag:1 () in
    let s3 = make_block ~prev:(Some a2) ~height:3 ~tag:2 () in
    List.iter (fun b ->
      Alcotest.(check string) "active-chain block accepted" "null" (submit ctx b))
      [a1; a2; a3];
    Alcotest.(check string) "stored side block is inconclusive"
      "inconclusive" (submit ctx s3);
    Alcotest.(check string) "tip stays on 3" (at a3 3) (tip ctx))

(* The side block is invalid in ConnectBlock (pays 51 BTC), but it is never
   connected, so neither Core nor camlcoin can judge it: "inconclusive",
   never null (which would claim it is valid). *)
let test_unconnected_bad_side_block_inconclusive () =
  with_node "sbi_bad" (fun ctx ->
    let a1 = make_block ~prev:None ~height:1 ~tag:1 () in
    let a2 = make_block ~prev:(Some a1) ~height:2 ~tag:1 () in
    let a3 = make_block ~prev:(Some a2) ~height:3 ~tag:1 () in
    let a4 = make_block ~prev:(Some a3) ~height:4 ~tag:1 () in
    let s3 = make_block ~prev:(Some a2) ~height:3 ~tag:2 () in
    let s4bad = make_block ~overpay:Consensus.coin ~prev:(Some s3)
        ~height:4 ~tag:2 () in
    List.iter (fun b -> ignore (submit ctx b)) [a1; a2; a3; a4];
    Alcotest.(check string) "3' below the tip" "inconclusive" (submit ctx s3);
    Alcotest.(check string) "bad 4' at equal work" "inconclusive"
      (submit ctx s4bad);
    Alcotest.(check string) "tip stays on 4" (at a4 4) (tip ctx))

(* Control: a side block that outweighs the tip is connected by the reorg,
   so it IS judged — valid is null, invalid is its reason. *)
let test_heavier_side_block_is_judged () =
  with_node "sbi_heavy" (fun ctx ->
    let a1 = make_block ~prev:None ~height:1 ~tag:1 () in
    let a2 = make_block ~prev:(Some a1) ~height:2 ~tag:1 () in
    let a3 = make_block ~prev:(Some a2) ~height:3 ~tag:1 () in
    let s3 = make_block ~prev:(Some a2) ~height:3 ~tag:2 () in
    let s4 = make_block ~prev:(Some s3) ~height:4 ~tag:2 () in
    let s4bad = make_block ~overpay:Consensus.coin ~prev:(Some s3)
        ~height:4 ~tag:3 () in
    List.iter (fun b -> ignore (submit ctx b)) [a1; a2; a3];
    Alcotest.(check string) "3' inconclusive" "inconclusive" (submit ctx s3);
    Alcotest.(check string) "heavier bad 4' is rejected with its reason"
      "bad-cb-amount" (submit ctx s4bad);
    Alcotest.(check string) "heavier valid 4' is accepted" "null"
      (submit ctx s4);
    Alcotest.(check string) "tip moved to 4'" (at s4 4) (tip ctx))

let () =
  Alcotest.run "submitblock_inconclusive" [
    "submitblock", [
      Alcotest.test_case "equal-work sibling answers inconclusive" `Quick
        test_equal_work_sibling_inconclusive;
      Alcotest.test_case "unconnected bad side block answers inconclusive"
        `Quick test_unconnected_bad_side_block_inconclusive;
      Alcotest.test_case "heavier side block is judged (control)" `Quick
        test_heavier_side_block_is_judged;
    ];
  ]
