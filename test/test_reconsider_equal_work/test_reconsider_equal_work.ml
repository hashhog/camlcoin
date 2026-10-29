(* reconsiderblock breaks equal-work ties the way Core does.

   Core ReconsiderBlock (validation.cpp) clears the failure flags and the
   RPC runs ActivateBestChain, which picks the most-work candidate under
   CBlockIndexWorkComparator: more chainwork, then the LOWER nSequenceId,
   i.e. the block whose data arrived first.  Blocks loaded from disk get 1,
   or 0 on the chain loaded as active, so after a restart the tip keeps a
   tie.

   camlcoin only switched on strictly more work, so in Core regtest
   failed_reorg C (invalidateblock 4a moves to the equal-height side tip
   4'; reconsiderblock 4a) it stayed on 4' while Core went back to 4a:
   rows failed_reorg/c-reconsider/tips:36ee4cd0....branchlen and .status
   (Core 0 / active, camlcoin 2 / valid-fork).

     dune exec --no-buffer test/test_reconsider_equal_work/test_reconsider_equal_work.exe
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

let best ctx =
  match Rpc.handle_getbestblockhash ctx with
  | `String s -> s
  | j -> "unexpected:" ^ Yojson.Safe.to_string j

let invalidate ctx b =
  rpc_ok ("invalidateblock " ^ hex_of b)
    (Rpc.handle_invalidateblock ctx [`String (hex_of b)])

let reconsider ctx b =
  rpc_ok ("reconsiderblock " ^ hex_of b)
    (Rpc.handle_reconsiderblock ctx [`String (hex_of b)])

(* G-1-2-3a-4a with the side branch 3s-4s off 2, submitted while 4a is the
   tip (so they stay off it); the shape of failed_reorg C and E. *)
let round_trip_blocks () =
  let a1 = make_block ~prev:None ~height:1 ~tag:1 () in
  let a2 = make_block ~prev:(Some a1) ~height:2 ~tag:1 () in
  let a3 = make_block ~prev:(Some a2) ~height:3 ~tag:1 () in
  let a4 = make_block ~prev:(Some a3) ~height:4 ~tag:1 () in
  let s3 = make_block ~prev:(Some a2) ~height:3 ~tag:2 () in
  let s4 = make_block ~prev:(Some s3) ~height:4 ~tag:2 () in
  (a1, a2, a3, a4, s3, s4)

let submit_round_trip ctx (a1, a2, a3, a4, s3, s4) =
  List.iter (submit_ok ctx) [a1; a2; a3; a4];
  Alcotest.(check string) "s3 stored" "inconclusive" (submit ctx s3);
  Alcotest.(check string) "s4 stored" "inconclusive" (submit ctx s4);
  Alcotest.(check string) "4a stays the tip" (hex_of a4) (best ctx)

(* failed_reorg C (Core c-reconsider, tip 36ee4cd0): 4a and 4s have equal
   work and 4a was received first, so reconsiderblock 4a goes back to 4a
   and 4s is displaced (valid-fork, branchlen 2). *)
let test_reconsider_equal_work_returns_to_first_received () =
  Test_tmp.with_dir ~label:"rcw_c" ~mkdir:true (fun path ->
    fresh_node path (fun ctx ->
      let (_, _, _, a4, _, s4) as blocks = round_trip_blocks () in
      submit_round_trip ctx blocks;
      invalidate ctx a4;
      Alcotest.(check string) "invalidate 4a: on 4s" (hex_of s4) (best ctx);
      reconsider ctx a4;
      Alcotest.(check string) "reconsider 4a: back on 4a" (hex_of a4) (best ctx);
      check_tips "c-reconsider tips"
        [tip a4 4 0 "active"; tip s4 4 2 "valid-fork"] ctx))

(* failed_reorg D: a side branch with MORE work than the reconsidered block
   keeps the tip. *)
let test_reconsider_heavier_side_branch_stays () =
  Test_tmp.with_dir ~label:"rcw_d" ~mkdir:true (fun path ->
    fresh_node path (fun ctx ->
      let a1 = make_block ~prev:None ~height:1 ~tag:1 () in
      let a2 = make_block ~prev:(Some a1) ~height:2 ~tag:1 () in
      let a3 = make_block ~prev:(Some a2) ~height:3 ~tag:1 () in
      let a4 = make_block ~prev:(Some a3) ~height:4 ~tag:1 () in
      List.iter (submit_ok ctx) [a1; a2; a3; a4];
      invalidate ctx a4;
      Alcotest.(check string) "invalidate 4a: on 3a" (hex_of a3) (best ctx);
      let s3 = make_block ~prev:(Some a2) ~height:3 ~tag:2 () in
      let s4 = make_block ~prev:(Some s3) ~height:4 ~tag:2 () in
      let s5 = make_block ~prev:(Some s4) ~height:5 ~tag:2 () in
      ignore (submit ctx s3);
      List.iter (submit_ok ctx) [s4; s5];
      Alcotest.(check string) "side branch is the tip" (hex_of s5) (best ctx);
      reconsider ctx a4;
      Alcotest.(check string) "reconsider 4a: stays on 5s" (hex_of s5) (best ctx);
      check_tips "d-reconsider tips"
        [tip s5 5 0 "active"; tip a4 4 2 "valid-fork"] ctx))

(* failed_reorg E: a restart between the two calls resets the received
   order.  4s is the tip loaded from disk (sequence 0), 4a only on disk
   (1), so reconsiderblock 4a keeps 4s, and so does a second restart. *)
let test_reconsider_after_restart_keeps_loaded_tip () =
  Test_tmp.with_dir ~label:"rcw_e" ~mkdir:true (fun path ->
    let (_, _, _, a4, _, s4) as blocks = round_trip_blocks () in
    let expected = [tip s4 4 0 "active"; tip a4 4 2 "valid-fork"] in
    fresh_node path (fun ctx ->
      submit_round_trip ctx blocks;
      invalidate ctx a4;
      Alcotest.(check string) "invalidate 4a: on 4s" (hex_of s4) (best ctx));
    restarted_node path (fun ctx ->
      Alcotest.(check string) "restart: on 4s" (hex_of s4) (best ctx);
      reconsider ctx a4;
      Alcotest.(check string) "reconsider 4a after restart: stays on 4s"
        (hex_of s4) (best ctx);
      check_tips "e-reconsider tips" expected ctx);
    restarted_node path (fun ctx ->
      Alcotest.(check string) "second restart: on 4s" (hex_of s4) (best ctx);
      check_tips "e-restart tips" expected ctx))

(* The equal-work switch must not turn an invalid block valid.  s4bad pays
   too much (bad-cb-amount) and was received BEFORE a4, which has the same
   work.  reconsiderblock 2 clears every failure flag below 2, s4bad
   included, so s4bad now sorts ahead of the tip; Core tries it, fails it
   again in ConnectBlock and returns to a4.  The node must end on a4 with
   s4bad invalid, never with s4bad as the tip. *)
let test_reconsider_never_activates_failed_equal_work_block () =
  Test_tmp.with_dir ~label:"rcw_bad" ~mkdir:true (fun path ->
    fresh_node path (fun ctx ->
      let a1 = make_block ~prev:None ~height:1 ~tag:1 () in
      let a2 = make_block ~prev:(Some a1) ~height:2 ~tag:1 () in
      let a3 = make_block ~prev:(Some a2) ~height:3 ~tag:1 () in
      let s3 = make_block ~prev:(Some a2) ~height:3 ~tag:2 () in
      let s4bad = make_block ~overpay:Consensus.coin ~prev:(Some s3)
          ~height:4 ~tag:2 () in
      let a4 = make_block ~prev:(Some a3) ~height:4 ~tag:1 () in
      List.iter (submit_ok ctx) [a1; a2; a3];
      Alcotest.(check string) "s3 stored" "inconclusive" (submit ctx s3);
      Alcotest.(check string) "s4bad rejected" "bad-cb-amount" (submit ctx s4bad);
      submit_ok ctx a4;
      Alcotest.(check string) "a4 is the tip" (hex_of a4) (best ctx);
      reconsider ctx a2;
      Alcotest.(check string) "reconsider 2: still on a4" (hex_of a4) (best ctx);
      Alcotest.(check int) "height 4" 4
        (match Rpc.handle_getblockcount ctx with `Int n -> n | _ -> -1);
      check_tips "s4bad failed again"
        [tip a4 4 0 "active"; tip s4bad 4 2 "invalid"] ctx))

(* After a failed equal-work attempt, chain selection must try the next
   candidate (Core ActivateBestChain loops after InvalidBlockFound).  Same
   blocks as above, then: invalidateblock a4 falls back to a3 (s4bad still
   failed), and reconsiderblock 2 clears both flags.  s4bad and a4 tie on
   work and s4bad was received first, so s4bad is tried first: s3 connects,
   s4bad fails bad-cb-amount again.  The next candidate, a4, sorts ahead of
   a3 and must become the tip, with s4bad invalid. *)
let test_reconsider_tries_next_candidate_after_failure () =
  Test_tmp.with_dir ~label:"rcw_next" ~mkdir:true (fun path ->
    fresh_node path (fun ctx ->
      let a1 = make_block ~prev:None ~height:1 ~tag:1 () in
      let a2 = make_block ~prev:(Some a1) ~height:2 ~tag:1 () in
      let a3 = make_block ~prev:(Some a2) ~height:3 ~tag:1 () in
      let s3 = make_block ~prev:(Some a2) ~height:3 ~tag:2 () in
      let s4bad = make_block ~overpay:Consensus.coin ~prev:(Some s3)
          ~height:4 ~tag:2 () in
      let a4 = make_block ~prev:(Some a3) ~height:4 ~tag:1 () in
      List.iter (submit_ok ctx) [a1; a2; a3];
      Alcotest.(check string) "s3 stored" "inconclusive" (submit ctx s3);
      Alcotest.(check string) "s4bad rejected" "bad-cb-amount" (submit ctx s4bad);
      submit_ok ctx a4;
      Alcotest.(check string) "a4 is the tip" (hex_of a4) (best ctx);
      invalidate ctx a4;
      Alcotest.(check string) "invalidate a4: on a3" (hex_of a3) (best ctx);
      reconsider ctx a2;
      Alcotest.(check string) "reconsider 2: a4 restored" (hex_of a4) (best ctx);
      Alcotest.(check int) "height 4" 4
        (match Rpc.handle_getblockcount ctx with `Int n -> n | _ -> -1);
      check_tips "s4bad failed, a4 active"
        [tip a4 4 0 "active"; tip s4bad 4 2 "invalid"] ctx))

let () =
  Alcotest.run "reconsider_equal_work" [
    "reconsiderblock", [
      Alcotest.test_case "equal work: back to the block received first"
        `Quick test_reconsider_equal_work_returns_to_first_received;
      Alcotest.test_case "heavier side branch keeps the tip" `Quick
        test_reconsider_heavier_side_branch_stays;
      Alcotest.test_case "after a restart the loaded tip keeps a tie" `Quick
        test_reconsider_after_restart_keeps_loaded_tip;
      Alcotest.test_case "never activates a failed equal-work block" `Quick
        test_reconsider_never_activates_failed_equal_work_block;
      Alcotest.test_case "tries the next candidate after a failed attempt"
        `Quick test_reconsider_tries_next_candidate_after_failure;
    ];
  ]
