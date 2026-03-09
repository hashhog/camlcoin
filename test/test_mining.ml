(* Tests for mining module *)

open Camlcoin

(* Test directory that gets cleaned up *)
let test_db_path = "/tmp/camlcoin_test_mining_db"

let cleanup_test_db () =
  let rec rm_rf path =
    if Sys.file_exists path then begin
      if Sys.is_directory path then begin
        Array.iter (fun f -> rm_rf (Filename.concat path f)) (Sys.readdir path);
        Unix.rmdir path
      end else
        Unix.unlink path
    end
  in
  rm_rf test_db_path

(* Helper to create a test transaction output *)
let make_test_output value =
  Types.{
    value;
    script_pubkey = Cstruct.of_string "\x76\xa9\x14test_script_pubkey\x88\xac";
  }

(* Helper to create a test transaction input *)
let make_test_input txid vout =
  Types.{
    previous_output = { txid; vout };
    script_sig = Cstruct.of_string "\x00";
    sequence = 0xFFFFFFFFl;
  }

(* Helper to create a regular transaction *)
let make_regular_tx inputs outputs =
  Types.{
    version = 1l;
    inputs;
    outputs;
    witnesses = [];
    locktime = 0l;
  }

(* Create a test mempool with some spendable outputs *)
let create_test_mempool () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let utxo = Utxo.UtxoSet.create db in
  (* Add some spendable UTXOs *)
  let txid1 = Types.hash256_of_hex
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b" in
  let txid2 = Types.hash256_of_hex
    "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098" in
  let txid3 = Types.hash256_of_hex
    "9b0fc92260312ce44e74ef369f5c66bbb85848f2eddd5a7a1cde251e54ccfdd5" in
  Utxo.UtxoSet.add utxo txid1 0 Utxo.{
    value = 1_000_000L;  (* 0.01 BTC *)
    script_pubkey = Cstruct.of_string "\x76\xa9\x14test\x88\xac";
    height = 0;
    is_coinbase = false;
  };
  Utxo.UtxoSet.add utxo txid2 0 Utxo.{
    value = 2_000_000L;  (* 0.02 BTC *)
    script_pubkey = Cstruct.of_string "\x76\xa9\x14test\x88\xac";
    height = 0;
    is_coinbase = false;
  };
  Utxo.UtxoSet.add utxo txid3 0 Utxo.{
    value = 500_000L;
    script_pubkey = Cstruct.of_string "\x76\xa9\x14test\x88\xac";
    height = 0;
    is_coinbase = false;
  };
  let mp = Mempool.create ~utxo ~current_height:100 in
  (mp, utxo, db, txid1, txid2, txid3)

(* Create a test chain state *)
let create_test_chain_state () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let chain = Sync.create_chain_state db Consensus.regtest in
  (chain, db)

(* ============================================================================
   Coinbase Creation Tests
   ============================================================================ *)

let test_create_coinbase_basic () =
  let height = 100 in
  let total_fee = 10_000L in
  let payout_script = Cstruct.of_string "\x76\xa9\x14test\x88\xac" in
  let extra_nonce = Cstruct.of_string "\x01\x02\x03\x04\x05\x06\x07\x08" in

  let coinbase = Mining.create_coinbase ~height ~total_fee
    ~payout_script ~extra_nonce ~witness_root:None in

  (* Check it's a valid coinbase structure *)
  Alcotest.(check int) "one input" 1 (List.length coinbase.inputs);
  Alcotest.(check bool) "null outpoint txid" true
    (Cstruct.equal (List.hd coinbase.inputs).previous_output.txid Types.zero_hash);
  Alcotest.(check int32) "null outpoint vout" 0xFFFFFFFFl
    (List.hd coinbase.inputs).previous_output.vout;

  (* Check reward value *)
  let subsidy = Consensus.block_subsidy height in
  let expected_reward = Int64.add subsidy total_fee in
  let actual_reward = (List.hd coinbase.outputs).value in
  Alcotest.(check int64) "reward value" expected_reward actual_reward;

  (* Check version *)
  Alcotest.(check int32) "version is 2" 2l coinbase.version

let test_create_coinbase_with_witness () =
  let height = 100 in
  let total_fee = 10_000L in
  let payout_script = Cstruct.of_string "\x76\xa9\x14test\x88\xac" in
  let extra_nonce = Cstruct.of_string "\x01\x02\x03\x04\x05\x06\x07\x08" in
  let witness_root = Types.hash256_of_hex
    "0000000000000000000000000000000000000000000000000000000000000000" in

  let coinbase = Mining.create_coinbase ~height ~total_fee
    ~payout_script ~extra_nonce ~witness_root:(Some witness_root) in

  (* Should have 2 outputs (payout + witness commitment) *)
  Alcotest.(check int) "two outputs" 2 (List.length coinbase.outputs);

  (* Second output should be the witness commitment (value = 0) *)
  let commitment_output = List.nth coinbase.outputs 1 in
  Alcotest.(check int64) "commitment value is 0" 0L commitment_output.value;

  (* Commitment script should start with OP_RETURN 0x6a *)
  let script = commitment_output.script_pubkey in
  Alcotest.(check int) "OP_RETURN" 0x6a (Cstruct.get_uint8 script 0);

  (* Should have witness data *)
  Alcotest.(check int) "has witness" 1 (List.length coinbase.witnesses);
  let witness = List.hd coinbase.witnesses in
  Alcotest.(check int) "witness has one item" 1 (List.length witness.items);
  Alcotest.(check int) "witness item is 32 bytes" 32
    (Cstruct.length (List.hd witness.items))

let test_create_coinbase_height_encoding () =
  (* Test that height is properly encoded in coinbase script *)
  let heights = [0; 1; 16; 17; 127; 128; 255; 256; 500] in

  List.iter (fun height ->
    let payout_script = Cstruct.of_string "\x76\xa9\x14test\x88\xac" in
    let extra_nonce = Cstruct.create 8 in
    let coinbase = Mining.create_coinbase ~height ~total_fee:0L
      ~payout_script ~extra_nonce ~witness_root:None in

    let script = (List.hd coinbase.inputs).script_sig in
    let expected_prefix = Consensus.encode_height_in_coinbase height in

    (* Check that script starts with expected height encoding *)
    let actual_prefix = Cstruct.sub script 0 (Cstruct.length expected_prefix) in
    Alcotest.(check bool) (Printf.sprintf "height %d encoded" height) true
      (Cstruct.equal expected_prefix actual_prefix)
  ) heights

(* ============================================================================
   Transaction Selection Tests
   ============================================================================ *)

let test_select_transactions_empty () =
  let (mp, _utxo, db, _, _, _) = create_test_mempool () in
  let selected = Mining.select_transactions mp Consensus.max_block_weight in
  Alcotest.(check int) "no transactions selected" 0 (List.length selected);
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_select_transactions_basic () =
  let (mp, _utxo, db, txid1, txid2, _) = create_test_mempool () in

  (* Add some transactions *)
  let tx1 = make_regular_tx
    [make_test_input txid1 0l]
    [make_test_output 990_000L]  (* 10k fee *)
  in
  let tx2 = make_regular_tx
    [make_test_input txid2 0l]
    [make_test_output 1_990_000L]  (* 10k fee *)
  in
  let _ = Mempool.add_transaction mp tx1 in
  let _ = Mempool.add_transaction mp tx2 in

  let selected = Mining.select_transactions mp Consensus.max_block_weight in
  Alcotest.(check int) "both selected" 2 (List.length selected);

  (* Check total fee *)
  let total_fee = List.fold_left (fun acc (_, fee) -> Int64.add acc fee) 0L selected in
  Alcotest.(check int64) "total fee" 20_000L total_fee;

  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_select_transactions_respects_weight () =
  let (mp, _utxo, db, txid1, _, _) = create_test_mempool () in

  let tx = make_regular_tx
    [make_test_input txid1 0l]
    [make_test_output 990_000L]
  in
  let _ = Mempool.add_transaction mp tx in

  (* Select with very low weight limit *)
  let selected = Mining.select_transactions mp 100 in
  Alcotest.(check int) "none selected (weight limit)" 0 (List.length selected);

  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_select_transactions_fee_ordering () =
  let (mp, _utxo, db, txid1, txid2, txid3) = create_test_mempool () in

  (* Add transactions with different fee rates *)
  let tx_low = make_regular_tx
    [make_test_input txid3 0l]  (* 500k input *)
    [make_test_output 499_000L]  (* 1000 sat fee *)
  in
  let tx_high = make_regular_tx
    [make_test_input txid1 0l]  (* 1M input *)
    [make_test_output 900_000L]  (* 100k sat fee *)
  in
  let tx_mid = make_regular_tx
    [make_test_input txid2 0l]  (* 2M input *)
    [make_test_output 1_950_000L]  (* 50k sat fee *)
  in
  let _ = Mempool.add_transaction mp tx_low in
  let _ = Mempool.add_transaction mp tx_high in
  let _ = Mempool.add_transaction mp tx_mid in

  let selected = Mining.select_transactions mp Consensus.max_block_weight in
  Alcotest.(check int) "all selected" 3 (List.length selected);

  (* Should be sorted by fee rate (high to low) *)
  let fees : int64 list = List.map snd selected in
  Alcotest.(check int64) "first has highest fee" 100_000L (List.hd fees);

  Storage.ChainDB.close db;
  cleanup_test_db ()

(* ============================================================================
   Block Template Tests
   ============================================================================ *)

let test_create_block_template_empty_mempool () =
  let (chain, db) = create_test_chain_state () in
  let utxo = Utxo.UtxoSet.create db in
  let mp = Mempool.create ~utxo ~current_height:0 in
  let payout_script = Cstruct.of_string "\x76\xa9\x14test\x88\xac" in

  let template = Mining.create_block_template ~chain ~mp ~payout_script in

  (* Check basic template properties *)
  Alcotest.(check int) "height is 1" 1 template.height;
  Alcotest.(check int) "no mempool transactions" 0
    (List.length template.transactions);

  (* Check coinbase is valid *)
  let coinbase = template.coinbase_tx in
  Alcotest.(check bool) "coinbase has outputs" true
    (List.length coinbase.outputs > 0);

  (* Coinbase should have subsidy only (no fees) *)
  let subsidy = Consensus.block_subsidy 1 in
  Alcotest.(check int64) "total fee is 0" 0L template.total_fee;
  let coinbase_value = (List.hd coinbase.outputs).value in
  Alcotest.(check int64) "coinbase value is subsidy" subsidy coinbase_value;

  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_create_block_template_with_transactions () =
  let (chain, db) = create_test_chain_state () in
  let utxo = Utxo.UtxoSet.create db in
  let txid1 = Types.hash256_of_hex
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b" in
  Utxo.UtxoSet.add utxo txid1 0 Utxo.{
    value = 1_000_000L;
    script_pubkey = Cstruct.of_string "\x76\xa9\x14test\x88\xac";
    height = 0;
    is_coinbase = false;
  };

  let mp = Mempool.create ~utxo ~current_height:0 in
  let tx = make_regular_tx
    [make_test_input txid1 0l]
    [make_test_output 990_000L]  (* 10k fee *)
  in
  let _ = Mempool.add_transaction mp tx in

  let payout_script = Cstruct.of_string "\x76\xa9\x14test\x88\xac" in
  let template = Mining.create_block_template ~chain ~mp ~payout_script in

  (* Should include the transaction *)
  Alcotest.(check int) "one transaction selected" 1
    (List.length template.transactions);
  Alcotest.(check int64) "total fee is 10k" 10_000L template.total_fee;

  (* Coinbase should include subsidy + fees *)
  let subsidy = Consensus.block_subsidy 1 in
  let expected_reward = Int64.add subsidy 10_000L in
  let coinbase_value = (List.hd template.coinbase_tx.outputs).value in
  Alcotest.(check int64) "coinbase includes fees" expected_reward coinbase_value;

  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_block_template_header_valid () =
  let (chain, db) = create_test_chain_state () in
  let utxo = Utxo.UtxoSet.create db in
  let mp = Mempool.create ~utxo ~current_height:0 in
  let payout_script = Cstruct.of_string "\x76\xa9\x14test\x88\xac" in

  let template = Mining.create_block_template ~chain ~mp ~payout_script in

  (* Header should reference genesis as previous block *)
  let genesis_hash = Consensus.regtest.genesis_hash in
  Alcotest.(check bool) "prev_block is genesis" true
    (Cstruct.equal template.header.prev_block genesis_hash);

  (* Version should have BIP-9 bits set *)
  Alcotest.(check bool) "version has BIP-9 bits" true
    (Int32.logand template.header.version 0x20000000l = 0x20000000l);

  Storage.ChainDB.close db;
  cleanup_test_db ()

(* ============================================================================
   Mining Tests
   ============================================================================ *)

let test_mine_block_regtest () =
  let (chain, db) = create_test_chain_state () in
  let utxo = Utxo.UtxoSet.create db in
  let mp = Mempool.create ~utxo ~current_height:0 in
  let payout_script = Cstruct.of_string "\x76\xa9\x14test\x88\xac" in

  let template = Mining.create_block_template ~chain ~mp ~payout_script in

  (* Regtest has very low difficulty, should find block quickly *)
  let result = Mining.mine_block template 10_000_000l in

  Alcotest.(check bool) "found a block" true (Option.is_some result);

  let block = Option.get result in

  (* Verify the block meets target *)
  let block_hash = Crypto.compute_block_hash block.header in
  Alcotest.(check bool) "hash meets target" true
    (Consensus.hash_meets_target block_hash block.header.bits);

  (* Block should have coinbase as first transaction *)
  Alcotest.(check bool) "has transactions" true
    (List.length block.transactions > 0);

  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_mine_block_no_solution () =
  let (chain, db) = create_test_chain_state () in
  let utxo = Utxo.UtxoSet.create db in
  let mp = Mempool.create ~utxo ~current_height:0 in
  let payout_script = Cstruct.of_string "\x76\xa9\x14test\x88\xac" in

  let template = Mining.create_block_template ~chain ~mp ~payout_script in

  (* Artificially set mainnet difficulty (very hard) *)
  let hard_template = {
    template with
    header = { template.header with bits = 0x1d00ffffl }
  } in

  (* Should not find solution with only 100 attempts *)
  let result = Mining.mine_block hard_template 100l in

  Alcotest.(check bool) "no block found" true (Option.is_none result);

  Storage.ChainDB.close db;
  cleanup_test_db ()

(* ============================================================================
   JSON Conversion Tests
   ============================================================================ *)

let test_template_to_json () =
  let (chain, db) = create_test_chain_state () in
  let utxo = Utxo.UtxoSet.create db in
  let mp = Mempool.create ~utxo ~current_height:0 in
  let payout_script = Cstruct.of_string "\x76\xa9\x14test\x88\xac" in

  let template = Mining.create_block_template ~chain ~mp ~payout_script in
  let json = Mining.template_to_json template in

  (* Check required fields exist *)
  let assoc = match json with
    | `Assoc a -> a
    | _ -> Alcotest.fail "expected assoc"
  in

  Alcotest.(check bool) "has version" true (List.mem_assoc "version" assoc);
  Alcotest.(check bool) "has previousblockhash" true
    (List.mem_assoc "previousblockhash" assoc);
  Alcotest.(check bool) "has transactions" true
    (List.mem_assoc "transactions" assoc);
  Alcotest.(check bool) "has coinbasevalue" true
    (List.mem_assoc "coinbasevalue" assoc);
  Alcotest.(check bool) "has target" true (List.mem_assoc "target" assoc);
  Alcotest.(check bool) "has bits" true (List.mem_assoc "bits" assoc);
  Alcotest.(check bool) "has height" true (List.mem_assoc "height" assoc);

  (* Check height value *)
  let height = List.assoc "height" assoc in
  Alcotest.(check int) "height is 1" 1 (match height with `Int n -> n | _ -> -1);

  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_template_to_json_simple () =
  let (chain, db) = create_test_chain_state () in
  let utxo = Utxo.UtxoSet.create db in
  let mp = Mempool.create ~utxo ~current_height:0 in
  let payout_script = Cstruct.of_string "\x76\xa9\x14test\x88\xac" in

  let template = Mining.create_block_template ~chain ~mp ~payout_script in
  let json = Mining.template_to_json_simple template in

  let assoc = match json with
    | `Assoc a -> a
    | _ -> Alcotest.fail "expected assoc"
  in

  (* Check merkle root is present *)
  Alcotest.(check bool) "has merkleroot" true
    (List.mem_assoc "merkleroot" assoc);

  Storage.ChainDB.close db;
  cleanup_test_db ()

(* ============================================================================
   Witness Commitment Tests
   ============================================================================ *)

let test_witness_merkle_root () =
  (* Create a simple transaction *)
  let tx = make_regular_tx
    [make_test_input Types.zero_hash 0l]
    [make_test_output 100_000L]
  in

  (* Compute wtxid for non-coinbase (should hash entire tx including witness) *)
  let wtxid = Mining.compute_wtxid tx false in
  Alcotest.(check int) "wtxid is 32 bytes" 32 (Cstruct.length wtxid);

  (* Compute wtxid for coinbase (should be zero) *)
  let coinbase_wtxid = Mining.compute_wtxid tx true in
  Alcotest.(check bool) "coinbase wtxid is zero" true
    (Cstruct.equal coinbase_wtxid Types.zero_hash)

let test_witness_commitment_script () =
  let commitment = Types.hash256_of_hex
    "0000000000000000000000000000000000000000000000000000000000000000" in
  let script = Mining.build_witness_commitment_script commitment in

  (* Should be 38 bytes (6 prefix + 32 commitment) *)
  Alcotest.(check int) "script length" 38 (Cstruct.length script);

  (* Should start with OP_RETURN *)
  Alcotest.(check int) "starts with OP_RETURN" 0x6a (Cstruct.get_uint8 script 0);

  (* Should have witness marker bytes *)
  Alcotest.(check int) "marker byte 1" 0xaa (Cstruct.get_uint8 script 2);
  Alcotest.(check int) "marker byte 2" 0x21 (Cstruct.get_uint8 script 3);
  Alcotest.(check int) "marker byte 3" 0xa9 (Cstruct.get_uint8 script 4);
  Alcotest.(check int) "marker byte 4" 0xed (Cstruct.get_uint8 script 5)

(* ============================================================================
   Test Runner
   ============================================================================ *)

let () =
  cleanup_test_db ();
  let open Alcotest in
  run "Mining" [
    "coinbase", [
      test_case "create basic coinbase" `Quick test_create_coinbase_basic;
      test_case "create coinbase with witness" `Quick test_create_coinbase_with_witness;
      test_case "coinbase height encoding" `Quick test_create_coinbase_height_encoding;
    ];
    "selection", [
      test_case "empty mempool" `Quick test_select_transactions_empty;
      test_case "basic selection" `Quick test_select_transactions_basic;
      test_case "respects weight limit" `Quick test_select_transactions_respects_weight;
      test_case "fee ordering" `Quick test_select_transactions_fee_ordering;
    ];
    "template", [
      test_case "empty mempool template" `Quick test_create_block_template_empty_mempool;
      test_case "template with transactions" `Quick test_create_block_template_with_transactions;
      test_case "header valid" `Quick test_block_template_header_valid;
    ];
    "mining", [
      test_case "mine regtest block" `Slow test_mine_block_regtest;
      test_case "no solution found" `Quick test_mine_block_no_solution;
    ];
    "json", [
      test_case "template to json" `Quick test_template_to_json;
      test_case "template to json simple" `Quick test_template_to_json_simple;
    ];
    "witness", [
      test_case "witness merkle root" `Quick test_witness_merkle_root;
      test_case "witness commitment script" `Quick test_witness_commitment_script;
    ];
  ]
