(* Core: ProcessNewBlock -> AcceptBlockHeader on a header whose parent is not in
   the block index returns Invalid(BLOCK_MISSING_PREV, "prev-blk-not-found"),
   which rpc/mining.cpp BIP22ValidationResult() renders as the result string
   "prev-blk-not-found".  camlcoin answered the generic "rejected". *)

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

let orphan_block () : Types.block =
  let extra_nonce = Cstruct.create 8 in
  Cstruct.LE.set_uint64 extra_nonce 0 7L;
  let mk wr =
    Mining.create_coinbase ~height:1 ~total_fee:0L ~payout_script:op_true
      ~extra_nonce ~witness_root:wr ~network_type:Consensus.Regtest ()
  in
  let placeholder = mk None in
  let wr = Mining.compute_witness_merkle_root [placeholder] in
  let coinbase = mk (Some wr) in
  let merkle_root, _ = Crypto.merkle_root [Crypto.compute_txid coinbase] in
  let g = Consensus.regtest.Consensus.genesis_header in
  remine { Types.header = { version = 4l;
                            prev_block = Cstruct.of_string (String.make 32 '\x11');
                            merkle_root;
                            timestamp = Int32.add g.Types.timestamp 600l;
                            bits = Consensus.regtest.pow_limit; nonce = 0l };
           transactions = [coinbase] }

let test_orphan_is_prev_blk_not_found () =
  Test_tmp.with_dir ~label:"sb_prevnf" ~mkdir:true (fun path ->
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
        Fun.protect ~finally:(fun () -> Sync.shared_utxo_set := None)
          (fun () ->
            match Mining.submit_block_outcome ~utxo ~network_type:Consensus.Regtest
                    (orphan_block ()) state mp with
            | Ok _ -> Alcotest.fail "orphan block must be rejected"
            | Error msg ->
              Alcotest.(check string) "BIP-22 token" "prev-blk-not-found"
                (Rpc.bip22_of_submitblock_error msg))))

let () =
  Alcotest.run "submitblock_prev_not_found"
    [ "prev-blk-not-found",
      [ Alcotest.test_case "orphan block -> prev-blk-not-found" `Quick
          test_orphan_is_prev_blk_not_found ] ]
