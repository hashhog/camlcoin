(* A submitted block that extends the tip and fails ContextualCheckBlock or
   ConnectBlock stays in the block index, marked failed, as Core keeps it.

   Core validation.cpp ChainstateManager::AcceptBlock: AcceptBlockHeader adds
   the header to m_block_index first; a ContextualCheckBlock failure then calls
   InvalidBlockFound (BLOCK_FAILED_VALID unless BLOCK_MUTATED), and so does a
   ConnectBlock failure during ActivateBestChain (ConnectTip ->
   InvalidBlockFound, validation.cpp:1988).  The entry stays, so getchaintips
   lists it as "invalid", a resubmit answers "duplicate-invalid"
   (AcceptBlockHeader on a BLOCK_FAILED_MASK entry) and a child answers
   "bad-prevblk".  A header failure (AcceptBlockHeader) or a context-free
   CheckBlock failure (ProcessNewBlock runs CheckBlock before AcceptBlock)
   leaves no entry.

   camlcoin dropped the block on the tip-extending submitblock path, so the
   failed tip was missing from getchaintips: Core regtest rows
   seed_invalidated_submit/<step>/tips:375bb166 and
   warden_invalidated_submit/<step>/tips:6646aead (premature-block,
   bad-txns-premature-spend-of-coinbase), chain/tips/final:341edf7a
   (bad-cb-amount), and each step's tips:$keys.

     dune exec --no-buffer \
       test/submitblock_failed_tip_retained/test_submitblock_failed_tip_retained.exe
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

(* [overpay] adds to the coinbase value (bad-cb-amount, ConnectBlock);
   [txs] follow the coinbase and pay [fee] to it; [time] overrides the
   header timestamp. *)
let make_block ?(overpay = 0L) ?(txs = []) ?(fee = 0L) ?time
    ~(prev : Types.block option) ~height ~tag () : Types.block =
  let prev_hash, prev_time = match prev with
    | None -> Consensus.regtest.Consensus.genesis_hash,
              Consensus.regtest.Consensus.genesis_header.Types.timestamp
    | Some p -> Crypto.compute_block_hash p.Types.header,
                p.Types.header.Types.timestamp in
  let extra_nonce = Cstruct.create 8 in
  Cstruct.LE.set_uint64 extra_nonce 0 (Int64.of_int (height + (tag lsl 32)));
  let mk wr =
    Mining.create_coinbase ~height ~total_fee:(Int64.add fee overpay)
      ~payout_script:op_true ~extra_nonce ~witness_root:wr
      ~network_type:Consensus.Regtest ()
  in
  let wr = Mining.compute_witness_merkle_root (mk None :: txs) in
  let all = mk (Some wr) :: txs in
  let merkle_root, _ = Crypto.merkle_root (List.map Crypto.compute_txid all) in
  let timestamp = match time with
    | Some t -> t
    | None -> Int32.add prev_time 600l in
  remine { Types.header = { version = 4l; prev_block = prev_hash; merkle_root;
                            timestamp; bits = Consensus.regtest.pow_limit;
                            nonce = 0l };
           transactions = all }

(* Spend output 0 of [b]'s coinbase (an OP_TRUE output, so an empty
   scriptSig satisfies it), paying [fee] back to the miner. *)
let spend_coinbase (b : Types.block) ~(value : int64) ~(fee : int64)
    : Types.transaction =
  let cb = List.hd b.Types.transactions in
  { Types.version = 2l;
    inputs = [{ Types.previous_output =
                  { Types.txid = Crypto.compute_txid cb; vout = 0l };
                script_sig = Cstruct.empty; sequence = 0xffffffffl }];
    outputs = [{ Types.value = Int64.sub value fee; script_pubkey = op_true }];
    witnesses = []; locktime = 0l }

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

let fresh_node path f =
  open_db path (fun db ->
    let chain = Sync.create_chain_state db Consensus.regtest in
    chain.Sync.sync_state <- Sync.FullySynced;
    f (ctx_of db chain))

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
  | j -> Yojson.Safe.to_string j

let chain3 () =
  let a1 = make_block ~prev:None ~height:1 ~tag:1 () in
  let a2 = make_block ~prev:(Some a1) ~height:2 ~tag:1 () in
  let a3 = make_block ~prev:(Some a2) ~height:3 ~tag:1 () in
  (a1, a2, a3)

(* Core chain/tips/final 341edf7a: a tip-extending bad-cb-amount block fails
   ConnectBlock and stays in the index as "invalid", branchlen 1.  It stays
   so across a restart, a resubmit is "duplicate-invalid" and a child is
   "bad-prevblk"; a valid sibling at the same height still connects. *)
let test_connect_failure_retained_invalid () =
  Test_tmp.with_dir ~label:"sfr_cb" ~mkdir:true (fun path ->
    let a1, a2, a3 = chain3 () in
    let bad4 = make_block ~overpay:Consensus.coin ~prev:(Some a3) ~height:4
        ~tag:2 () in
    let child5 = make_block ~prev:(Some bad4) ~height:5 ~tag:2 () in
    let good4 = make_block ~prev:(Some a3) ~height:4 ~tag:3 () in
    let expected = [tip a3 3 0 "active"; tip bad4 4 1 "invalid"] in
    fresh_node path (fun ctx ->
      List.iter (submit_ok ctx) [a1; a2; a3];
      Alcotest.(check string) "bad4 rejected" "bad-cb-amount" (submit ctx bad4);
      Alcotest.(check string) "tip unchanged" (hex_of a3) (best ctx);
      check_tips "failed tip-extending block is an invalid tip" expected ctx;
      Alcotest.(check string) "resubmit" "duplicate-invalid" (submit ctx bad4);
      Alcotest.(check string) "child of the failed block" "bad-prevblk"
        (submit ctx child5);
      check_tips "child rejected: tips unchanged" expected ctx);
    restarted_node path (fun ctx ->
      check_tips "same tips after a restart" expected ctx;
      Alcotest.(check string) "resubmit after restart" "duplicate-invalid"
        (submit ctx bad4);
      (* Control: only the failed block is marked, not its parent or a
         valid sibling. *)
      submit_ok ctx good4;
      Alcotest.(check string) "valid sibling is the tip" (hex_of good4)
        (best ctx);
      check_tips "valid sibling active, failed block a side tip"
        [tip good4 4 0 "active"; tip bad4 4 1 "invalid"] ctx))

(* Core seed/warden_invalidated_submit premature-block: spending a coinbase
   two blocks deep fails ConnectBlock (bad-txns-premature-spend-of-coinbase)
   and the block is listed "invalid". *)
let test_premature_spend_retained_invalid () =
  Test_tmp.with_dir ~label:"sfr_mat" ~mkdir:true (fun path ->
    fresh_node path (fun ctx ->
      let a1, a2, a3 = chain3 () in
      List.iter (submit_ok ctx) [a1; a2; a3];
      let fee = 1_000L in
      let spend = spend_coinbase a1
          ~value:(Consensus.block_subsidy ~halving_interval:150 1) ~fee in
      let premature = make_block ~txs:[spend] ~fee ~prev:(Some a3) ~height:4
          ~tag:4 () in
      Alcotest.(check string) "premature rejected"
        "bad-txns-premature-spend-of-coinbase" (submit ctx premature);
      check_tips "premature block is an invalid tip"
        [tip a3 3 0 "active"; tip premature 4 1 "invalid"] ctx))

(* Negative control: a header failure (time-too-old, AcceptBlockHeader)
   leaves no index entry in Core, so no tip is added, and resubmitting gives
   the same verdict, not "duplicate-invalid". *)
let test_header_failure_not_retained () =
  Test_tmp.with_dir ~label:"sfr_hdr" ~mkdir:true (fun path ->
    fresh_node path (fun ctx ->
      let a1, a2, a3 = chain3 () in
      List.iter (submit_ok ctx) [a1; a2; a3];
      let old = make_block
          ~time:Consensus.regtest.Consensus.genesis_header.Types.timestamp
          ~prev:(Some a3) ~height:4 ~tag:5 () in
      let first = submit ctx old in
      Alcotest.(check string) "time-too-old" "time-too-old" first;
      check_tips "no tip for a header failure" [tip a3 3 0 "active"] ctx;
      Alcotest.(check string) "resubmit: same verdict" first (submit ctx old)))

let () =
  Alcotest.run "submitblock_failed_tip_retained" [
    "submitblock", [
      Alcotest.test_case "connect failure retained as invalid tip" `Quick
        test_connect_failure_retained_invalid;
      Alcotest.test_case "premature coinbase spend retained as invalid tip"
        `Quick test_premature_spend_retained_invalid;
      Alcotest.test_case "header failure leaves no index entry" `Quick
        test_header_failure_not_retained;
    ];
  ]
