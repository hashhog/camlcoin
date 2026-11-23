(* BIP-94 timewarp check on a REORG-connected retarget block must compare the
   block with ITS OWN PARENT, not with the abandoned branch's block at the
   same height (cffix-camlcoin-bip94-reorg-prev-time).

   Core: ContextualCheckBlockHeader (validation.cpp:4097-4104) compares
   block.GetBlockTime() with pindexPrev->GetBlockTime() - MAX_TIMEWARP, where
   pindexPrev is the block's parent by hash.

   camlcoin's reorg connect half ([Sync.connect_block_into_batch]) resolved
   expected_bits and MTP through hash links but took [prev_block_time] from
   [get_prev_block_time state height] -> the height->hash index.  [reorganize]
   rewrites that index for the new branch only AFTER the connect loop, so a
   retarget-boundary block C at height H on the incoming branch was compared
   with the OLD branch's block at H-1.

   Chain shape (all three cases):
       genesis .. P(2014)  -- A(2015)                  active branch
                           \- B(2015) -- C(2016)        heavier branch
   2016 is a retarget boundary, so BIP-94 applies to C.  B is C's parent.

   The network is regtest with [enforce_bip94 = true]: testnet4's BIP-94 rule
   with a PoW limit cheap enough to mine 2,016 blocks in a unit test.  The
   timewarp rule and its height gate ([Consensus.check_timewarp_rule]) are
   exactly the ones testnet4 runs.

   Cases (T = B.time):
     1. valid_not_rejected   A.time = T+1200, C.time = T.
        Core: T >= T-600 -> valid.  Old code compared with A: T < T+600 ->
        BlockTimeWarpAttack, and marked C failed.  Must reorg to C.
     2. control_rejected     A.time = T+1200, C.time = T-601.
        Invalid against B and against A: must be rejected on both trees.
     3. invalid_not_accepted A.time = T-1200, C.time = T-601.
        Core: T-601 < T-600 -> invalid.  Old code compared with A:
        T-601 >= T-1800 -> accepted (false accept).  Must be rejected.

   B and C are placed straight into the header table and block store (what
   submitblock's side-branch path does after its own header checks) so that
   [Sync.reorganize] — the code under test — is the only judge of C. *)

open Camlcoin

let network = { Consensus.regtest with Consensus.enforce_bip94 = true }

let op_true = Cstruct.of_string "\x51"

let remine (block : Types.block) : Types.block =
  let h = ref block.Types.header in
  let n = ref 0l in
  let found = ref false in
  while not !found && Int32.compare !n 5_000_000l < 0 do
    h := { !h with Types.nonce = !n };
    if Consensus.hash_meets_target (Crypto.compute_block_hash !h) !h.Types.bits
    then found := true
    else n := Int32.add !n 1l
  done;
  if not !found then failwith "remine: no nonce found";
  { block with Types.header = !h }

let build_block ~(prev_hash : Types.hash256) ~(height : int) ~(tag : int)
    ~(timestamp : int32) : Types.block =
  let extra_nonce = Cstruct.create 8 in
  Cstruct.LE.set_uint64 extra_nonce 0 (Int64.of_int ((height lsl 4) lor tag));
  let placeholder_cb =
    Mining.create_coinbase ~height ~total_fee:0L ~payout_script:op_true
      ~extra_nonce ~witness_root:None ~network_type:Consensus.Regtest () in
  let witness_root = Mining.compute_witness_merkle_root [ placeholder_cb ] in
  let coinbase =
    Mining.create_coinbase ~height ~total_fee:0L ~payout_script:op_true
      ~extra_nonce ~witness_root:(Some witness_root)
      ~network_type:Consensus.Regtest () in
  let (merkle_root, _) = Crypto.merkle_root [ Crypto.compute_txid coinbase ] in
  let header : Types.block_header =
    { version = 4l; prev_block = prev_hash; merkle_root; timestamp;
      bits = network.pow_limit; nonce = 0l } in
  remine { Types.header; transactions = [ coinbase ] }

let boundary = Consensus.difficulty_adjustment_interval   (* 2016 *)
let genesis_ts = network.genesis_header.Types.timestamp
let ts_at h = Int32.add genesis_ts (Int32.of_int (600 * h))
let t_b = ts_at (boundary - 1)   (* T: B's time *)

type outcome = {
  result : (unit, string) result;
  tip_is_c : bool;
  c_invalid : bool;
}

(* Build the shape above with the given A and C times and run the reorg. *)
let run ~(a_time : int32) ~(c_time : int32) : outcome =
  Test_tmp.with_dir ~label:"bip94_reorg" (fun db_path ->
    let rocksdb_path = db_path ^ "_rocksdb_utxo" in
    ignore (Test_tmp.register rocksdb_path);
    let db = Storage.ChainDB.create db_path in
    Fun.protect ~finally:(fun () -> try Storage.ChainDB.close db with _ -> ())
    @@ fun () ->
    let chain = Sync.create_chain_state db network in
    let rocksdb = Rocksdb_store.open_db rocksdb_path in
    Storage.ChainDB.attach_rocksdb_utxo db rocksdb;
    let optimized = Utxo.OptimizedUtxoSet.create ~cache_size:65536 ~rocksdb db in
    let utxo = Utxo.UtxoSet.create db in
    let mp = Mempool.create ~network ~require_standard:false
        ~verify_scripts:false ~utxo ~current_height:0 () in
    let submit_ok what (b : Types.block) =
      match Mining.submit_block ~utxo:optimized ~network_type:Consensus.Regtest
              b chain mp with
      | Ok () -> ()
      | Error e -> failwith (Printf.sprintf "submit_block(%s): %s" what e)
    in
    (* Active chain: genesis .. P(2014), then A(2015). *)
    let prev = ref (Crypto.compute_block_hash network.genesis_header) in
    for h = 1 to boundary - 2 do
      let b = build_block ~prev_hash:!prev ~height:h ~tag:0xA ~timestamp:(ts_at h) in
      submit_ok (Printf.sprintf "h=%d" h) b;
      prev := Crypto.compute_block_hash b.Types.header
    done;
    let p_hash = !prev in
    let a = build_block ~prev_hash:p_hash ~height:(boundary - 1) ~tag:0xA
        ~timestamp:a_time in
    submit_ok "A" a;
    let a_hash = Crypto.compute_block_hash a.Types.header in
    (match chain.Sync.tip with
     | Some t when Cstruct.equal t.Sync.hash a_hash -> ()
     | _ -> failwith "A is not the active tip");
    (* Heavier branch B(2015) -> C(2016), stored without connecting. *)
    let store (parent : Sync.header_entry) (blk : Types.block) =
      let hash = Crypto.compute_block_hash blk.Types.header in
      let entry = Sync.{
        header = blk.Types.header; hash; height = parent.height + 1;
        total_work = Consensus.work_add parent.total_work
            (Sync.work_from_bits blk.Types.header.bits) } in
      Sync.register_side_branch_header chain entry;
      Storage.ChainDB.store_block chain.Sync.db hash blk;
      entry
    in
    let p_entry = match Sync.get_header chain p_hash with
      | Some e -> e | None -> failwith "P missing" in
    let b = build_block ~prev_hash:p_hash ~height:(boundary - 1) ~tag:0xB
        ~timestamp:t_b in
    let b_entry = store p_entry b in
    let c = build_block ~prev_hash:b_entry.Sync.hash ~height:boundary ~tag:0xB
        ~timestamp:c_time in
    let c_entry = store b_entry c in
    let ibd = Sync.create_ibd_state ~utxo_set:optimized chain in
    let result = Sync.reorganize ibd c_entry in
    let tip_is_c = match chain.Sync.tip with
      | Some t -> Cstruct.equal t.Sync.hash c_entry.Sync.hash
      | None -> false in
    let c_invalid = Hashtbl.mem chain.Sync.invalidated_blocks
        (Cstruct.to_string c_entry.Sync.hash) in
    { result; tip_is_c; c_invalid })

let pp_result = function Ok () -> "Ok" | Error e -> "Error: " ^ e

let test_valid_not_rejected () =
  let o = run ~a_time:(Int32.add t_b 1200l) ~c_time:t_b in
  Alcotest.(check bool)
    (Printf.sprintf "reorganize to C returns Ok (got %s)" (pp_result o.result))
    true (Result.is_ok o.result);
  Alcotest.(check bool) "C is the active tip" true o.tip_is_c;
  Alcotest.(check bool) "C is not marked invalid" false o.c_invalid

let test_control_rejected () =
  let o = run ~a_time:(Int32.add t_b 1200l) ~c_time:(Int32.sub t_b 601l) in
  Alcotest.(check bool)
    (Printf.sprintf "reorganize to C is refused (got %s)" (pp_result o.result))
    true (Result.is_error o.result);
  Alcotest.(check bool) "C is not the active tip" false o.tip_is_c;
  Alcotest.(check bool) "C is marked invalid" true o.c_invalid

let test_invalid_not_accepted () =
  let o = run ~a_time:(Int32.sub t_b 1200l) ~c_time:(Int32.sub t_b 601l) in
  Alcotest.(check bool)
    (Printf.sprintf "reorganize to C is refused (got %s)" (pp_result o.result))
    true (Result.is_error o.result);
  Alcotest.(check bool) "C is not the active tip" false o.tip_is_c;
  Alcotest.(check bool) "C is marked invalid" true o.c_invalid

let () =
  Logs.set_level (Some Logs.Error);
  Alcotest.run "bip94_reorg_prev_time"
    [ ("reorg_connect_timewarp",
       [ Alcotest.test_case "valid_not_rejected" `Slow test_valid_not_rejected;
         Alcotest.test_case "control_rejected" `Slow test_control_rejected;
         Alcotest.test_case "invalid_not_accepted" `Slow test_invalid_not_accepted ]) ]
