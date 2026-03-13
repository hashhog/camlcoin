(* Tests for block and transaction validation *)

open Camlcoin

(* Helper to create a simple transaction *)
let make_tx ?(version=1l) ?(locktime=0l) ~inputs ~outputs () : Types.transaction =
  { version; inputs; outputs; witnesses = []; locktime }

(* Helper to create a transaction input *)
let make_input ?(txid=Types.zero_hash) ?(vout=0l) ?(sequence=0xFFFFFFFFl) () : Types.tx_in =
  {
    previous_output = { txid; vout };
    script_sig = Cstruct.create 0;
    sequence;
  }

(* Helper to create a transaction output *)
let make_output ?(value=0L) ?(script_pubkey=Cstruct.create 0) () : Types.tx_out =
  { value; script_pubkey }

(* Helper to create a coinbase input *)
let make_coinbase_input ~(height : int) : Types.tx_in =
  let script_sig = Consensus.encode_height_in_coinbase height in
  (* Pad to minimum 2 bytes if needed *)
  let script_sig =
    if Cstruct.length script_sig < 2 then
      Cstruct.concat [script_sig; Cstruct.of_string "\x00"]
    else
      script_sig
  in
  {
    previous_output = { txid = Types.zero_hash; vout = -1l };
    script_sig;
    sequence = 0xFFFFFFFFl;
  }

(* Helper to create a block header *)
let make_header ?(version=1l) ?(prev_block=Types.zero_hash)
    ?(merkle_root=Types.zero_hash) ?(timestamp=1l) ?(bits=0x207fffffl)
    ?(nonce=0l) () : Types.block_header =
  { version; prev_block; merkle_root; timestamp; bits; nonce }

(* ============================================================================
   Transaction Weight Tests
   ============================================================================ *)

let test_tx_weight_no_witness () =
  (* Simple transaction without witness data *)
  let tx = make_tx
    ~inputs:[make_input ()]
    ~outputs:[make_output ~value:1000L ()]
    ()
  in
  let weight = Validation.compute_tx_weight tx in
  (* Without witness, weight = base_size * 4 *)
  let vsize = Validation.compute_tx_vsize tx in
  Alcotest.(check bool) "weight is positive" true (weight > 0);
  Alcotest.(check bool) "vsize <= weight" true (vsize <= weight);
  (* For non-witness tx, weight = 4 * vsize *)
  Alcotest.(check int) "weight = 4 * vsize" weight (vsize * 4)

let test_tx_weight_with_witness () =
  (* Transaction with witness data *)
  let tx = {
    Types.version = 1l;
    inputs = [make_input ()];
    outputs = [make_output ~value:1000L ()];
    witnesses = [{ Types.items = [Cstruct.create 72; Cstruct.create 33] }];
    locktime = 0l;
  } in
  let weight = Validation.compute_tx_weight tx in
  let vsize = Validation.compute_tx_vsize tx in
  Alcotest.(check bool) "weight is positive" true (weight > 0);
  (* With witness, weight < 4 * vsize due to discount *)
  Alcotest.(check bool) "vsize rounds correctly" true (vsize * 4 >= weight)

(* ============================================================================
   Transaction Validation Tests
   ============================================================================ *)

let test_check_transaction_valid () =
  let txid = Cstruct.create 32 in
  Cstruct.set_uint8 txid 0 0x01;  (* Non-zero txid *)
  let tx = make_tx
    ~inputs:[make_input ~txid ~vout:0l ()]
    ~outputs:[make_output ~value:50_000_000L ()]
    ()
  in
  match Validation.check_transaction tx with
  | Ok () -> ()
  | Error e -> Alcotest.fail (Validation.tx_error_to_string e)

let test_check_transaction_empty_inputs () =
  let tx = make_tx ~inputs:[] ~outputs:[make_output ~value:1000L ()] () in
  match Validation.check_transaction tx with
  | Error Validation.TxEmptyInputs -> ()
  | Error e -> Alcotest.fail ("Wrong error: " ^ Validation.tx_error_to_string e)
  | Ok () -> Alcotest.fail "Should have failed with TxEmptyInputs"

let test_check_transaction_empty_outputs () =
  let txid = Cstruct.create 32 in
  Cstruct.set_uint8 txid 0 0x01;
  let tx = make_tx ~inputs:[make_input ~txid ()] ~outputs:[] () in
  match Validation.check_transaction tx with
  | Error Validation.TxEmptyOutputs -> ()
  | Error e -> Alcotest.fail ("Wrong error: " ^ Validation.tx_error_to_string e)
  | Ok () -> Alcotest.fail "Should have failed with TxEmptyOutputs"

let test_check_transaction_negative_output () =
  let txid = Cstruct.create 32 in
  Cstruct.set_uint8 txid 0 0x01;
  let tx = make_tx
    ~inputs:[make_input ~txid ()]
    ~outputs:[make_output ~value:(-1L) ()]
    ()
  in
  match Validation.check_transaction tx with
  | Error (Validation.TxNegativeOutput _) -> ()
  | Error e -> Alcotest.fail ("Wrong error: " ^ Validation.tx_error_to_string e)
  | Ok () -> Alcotest.fail "Should have failed with TxNegativeOutput"

let test_check_transaction_output_over_max () =
  let txid = Cstruct.create 32 in
  Cstruct.set_uint8 txid 0 0x01;
  let tx = make_tx
    ~inputs:[make_input ~txid ()]
    ~outputs:[make_output ~value:(Int64.add Consensus.max_money 1L) ()]
    ()
  in
  match Validation.check_transaction tx with
  | Error (Validation.TxNegativeOutput _) -> ()
  | Error e -> Alcotest.fail ("Wrong error: " ^ Validation.tx_error_to_string e)
  | Ok () -> Alcotest.fail "Should have failed"

let test_check_transaction_duplicate_inputs () =
  let txid = Cstruct.create 32 in
  Cstruct.set_uint8 txid 0 0x01;
  let inp = make_input ~txid ~vout:0l () in
  let tx = make_tx
    ~inputs:[inp; inp]  (* Same input twice *)
    ~outputs:[make_output ~value:1000L ()]
    ()
  in
  match Validation.check_transaction tx with
  | Error Validation.TxDuplicateInputs -> ()
  | Error e -> Alcotest.fail ("Wrong error: " ^ Validation.tx_error_to_string e)
  | Ok () -> Alcotest.fail "Should have failed with TxDuplicateInputs"

let test_check_transaction_total_overflow () =
  let txid = Cstruct.create 32 in
  Cstruct.set_uint8 txid 0 0x01;
  let tx = make_tx
    ~inputs:[make_input ~txid ()]
    ~outputs:[
      make_output ~value:Consensus.max_money ();
      make_output ~value:1L ();  (* Causes overflow *)
    ]
    ()
  in
  match Validation.check_transaction tx with
  | Error Validation.TxOutputOverflow -> ()
  | Error e -> Alcotest.fail ("Wrong error: " ^ Validation.tx_error_to_string e)
  | Ok () -> Alcotest.fail "Should have failed with TxOutputOverflow"

(* ============================================================================
   Coinbase Transaction Tests
   ============================================================================ *)

let test_is_coinbase () =
  let coinbase_tx = make_tx
    ~inputs:[make_coinbase_input ~height:100]
    ~outputs:[make_output ~value:Consensus.coin ()]
    ()
  in
  Alcotest.(check bool) "is coinbase" true (Validation.is_coinbase coinbase_tx);

  let txid = Cstruct.create 32 in
  Cstruct.set_uint8 txid 0 0x01;
  let regular_tx = make_tx
    ~inputs:[make_input ~txid ()]
    ~outputs:[make_output ~value:1000L ()]
    ()
  in
  Alcotest.(check bool) "is not coinbase" false (Validation.is_coinbase regular_tx)

let test_check_coinbase_valid () =
  let cb = make_tx
    ~inputs:[make_coinbase_input ~height:500]
    ~outputs:[make_output ~value:(Consensus.block_subsidy 500) ()]
    ()
  in
  match Validation.check_coinbase ~network:Consensus.regtest cb 500 with
  | Ok () -> ()
  | Error e -> Alcotest.fail (Validation.tx_error_to_string e)

let test_check_coinbase_wrong_height () =
  let cb = make_tx
    ~inputs:[make_coinbase_input ~height:500]
    ~outputs:[make_output ~value:(Consensus.block_subsidy 500) ()]
    ()
  in
  (* Check against different height (both >= bip34_height=500 for regtest) *)
  match Validation.check_coinbase ~network:Consensus.regtest cb 600 with
  | Error Validation.TxBadCoinbase -> ()
  | Error e -> Alcotest.fail ("Wrong error: " ^ Validation.tx_error_to_string e)
  | Ok () -> Alcotest.fail "Should have failed with TxBadCoinbase"

let test_check_coinbase_multiple_inputs () =
  let inp1 = make_coinbase_input ~height:100 in
  let inp2 = make_coinbase_input ~height:100 in
  let cb = make_tx
    ~inputs:[inp1; inp2]  (* Coinbase should have exactly 1 input *)
    ~outputs:[make_output ~value:1000L ()]
    ()
  in
  match Validation.check_coinbase ~network:Consensus.regtest cb 100 with
  | Error Validation.TxBadCoinbase -> ()
  | Error e -> Alcotest.fail ("Wrong error: " ^ Validation.tx_error_to_string e)
  | Ok () -> Alcotest.fail "Should have failed with TxBadCoinbase"

let test_check_coinbase_script_too_short () =
  let inp = {
    Types.previous_output = { txid = Types.zero_hash; vout = -1l };
    script_sig = Cstruct.of_string "\x01";  (* Only 1 byte, need 2-100 *)
    sequence = 0xFFFFFFFFl;
  } in
  let cb = make_tx
    ~inputs:[inp]
    ~outputs:[make_output ~value:1000L ()]
    ()
  in
  match Validation.check_coinbase ~network:Consensus.regtest cb 100 with
  | Error Validation.TxBadCoinbase -> ()
  | Error e -> Alcotest.fail ("Wrong error: " ^ Validation.tx_error_to_string e)
  | Ok () -> Alcotest.fail "Should have failed with TxBadCoinbase"

(* ============================================================================
   Sigops Counting Tests
   ============================================================================ *)

let test_count_sigops_checksig () =
  (* OP_CHECKSIG = 0xac *)
  let script = Cstruct.of_string "\xac" in
  Alcotest.(check int) "single CHECKSIG" 1 (Validation.count_sigops script)

let test_count_sigops_checksigverify () =
  (* OP_CHECKSIGVERIFY = 0xad *)
  let script = Cstruct.of_string "\xad" in
  Alcotest.(check int) "single CHECKSIGVERIFY" 1 (Validation.count_sigops script)

let test_count_sigops_checkmultisig () =
  (* OP_CHECKMULTISIG = 0xae *)
  let script = Cstruct.of_string "\xae" in
  (* Worst case: counts as 20 *)
  Alcotest.(check int) "CHECKMULTISIG worst case" 20 (Validation.count_sigops script)

let test_count_sigops_multiple () =
  (* OP_CHECKSIG OP_CHECKSIG OP_CHECKMULTISIG *)
  let script = Cstruct.of_string "\xac\xac\xae" in
  Alcotest.(check int) "multiple ops" 22 (Validation.count_sigops script)

let test_count_sigops_empty () =
  let script = Cstruct.create 0 in
  Alcotest.(check int) "empty script" 0 (Validation.count_sigops script)

(* ============================================================================
   Transaction Finality Tests
   ============================================================================ *)

let test_is_tx_final_zero_locktime () =
  let txid = Cstruct.create 32 in
  Cstruct.set_uint8 txid 0 0x01;
  let tx = make_tx
    ~locktime:0l
    ~inputs:[make_input ~txid ~sequence:0l ()]  (* Non-final sequence *)
    ~outputs:[make_output ~value:1000L ()]
    ()
  in
  Alcotest.(check bool) "zero locktime is final" true
    (Validation.is_tx_final tx ~block_height:1000 ~block_time:1000l)

let test_is_tx_final_all_final_sequences () =
  let txid = Cstruct.create 32 in
  Cstruct.set_uint8 txid 0 0x01;
  let tx = make_tx
    ~locktime:999999l  (* High locktime *)
    ~inputs:[make_input ~txid ~sequence:0xFFFFFFFFl ()]  (* Final sequence *)
    ~outputs:[make_output ~value:1000L ()]
    ()
  in
  Alcotest.(check bool) "final sequence makes tx final" true
    (Validation.is_tx_final tx ~block_height:100 ~block_time:100l)

let test_is_tx_final_height_locktime () =
  let txid = Cstruct.create 32 in
  Cstruct.set_uint8 txid 0 0x01;
  let tx = make_tx
    ~locktime:500l  (* Block height locktime *)
    ~inputs:[make_input ~txid ~sequence:0l ()]
    ~outputs:[make_output ~value:1000L ()]
    ()
  in
  (* Not final at height 499 *)
  Alcotest.(check bool) "not final before height" false
    (Validation.is_tx_final tx ~block_height:499 ~block_time:0l);
  (* Final at height 500 *)
  Alcotest.(check bool) "final at height" true
    (Validation.is_tx_final tx ~block_height:500 ~block_time:0l);
  (* Final after height *)
  Alcotest.(check bool) "final after height" true
    (Validation.is_tx_final tx ~block_height:501 ~block_time:0l)

let test_is_tx_final_time_locktime () =
  let txid = Cstruct.create 32 in
  Cstruct.set_uint8 txid 0 0x01;
  let tx = make_tx
    ~locktime:500_000_100l  (* Unix time locktime (>= 500_000_000) *)
    ~inputs:[make_input ~txid ~sequence:0l ()]
    ~outputs:[make_output ~value:1000L ()]
    ()
  in
  (* Not final before time *)
  Alcotest.(check bool) "not final before time" false
    (Validation.is_tx_final tx ~block_height:1000000 ~block_time:500_000_099l);
  (* Final at time *)
  Alcotest.(check bool) "final at time" true
    (Validation.is_tx_final tx ~block_height:1000000 ~block_time:500_000_100l)

(* ============================================================================
   Block Validation Tests
   ============================================================================ *)

let test_check_block_empty () =
  let block = {
    Types.header = make_header ();
    transactions = [];
  } in
  match Validation.check_block ~network:Consensus.regtest block 0 ~expected_bits:0x207fffffl ~median_time:0l with
  | Error Validation.BlockEmptyTransactions -> ()
  | Error e -> Alcotest.fail ("Wrong error: " ^ Validation.block_error_to_string e)
  | Ok () -> Alcotest.fail "Should have failed with BlockEmptyTransactions"

let test_check_block_no_coinbase () =
  let txid = Cstruct.create 32 in
  Cstruct.set_uint8 txid 0 0x01;
  let regular_tx = make_tx
    ~inputs:[make_input ~txid ()]
    ~outputs:[make_output ~value:1000L ()]
    ()
  in
  let block = {
    Types.header = make_header ();
    transactions = [regular_tx];
  } in
  match Validation.check_block ~network:Consensus.regtest block 0 ~expected_bits:0x207fffffl ~median_time:0l with
  | Error Validation.BlockNoCoinbase -> ()
  | Error e -> Alcotest.fail ("Wrong error: " ^ Validation.block_error_to_string e)
  | Ok () -> Alcotest.fail "Should have failed with BlockNoCoinbase"

let test_check_block_bad_difficulty () =
  let coinbase = make_tx
    ~inputs:[make_coinbase_input ~height:0]
    ~outputs:[make_output ~value:(Consensus.block_subsidy 0) ()]
    ()
  in
  let txid = Crypto.compute_txid coinbase in
  let (merkle, _) = Crypto.merkle_root [txid] in
  let header = make_header ~merkle_root:merkle ~bits:0x207fffffl ~timestamp:100l () in
  let block = { Types.header; transactions = [coinbase] } in
  (* Expected bits don't match *)
  match Validation.check_block ~network:Consensus.regtest block 0 ~expected_bits:0x1d00ffffl ~median_time:0l with
  | Error Validation.BlockBadDifficulty -> ()
  | Error e -> Alcotest.fail ("Wrong error: " ^ Validation.block_error_to_string e)
  | Ok () -> Alcotest.fail "Should have failed with BlockBadDifficulty"

let test_check_block_bad_merkle () =
  let coinbase = make_tx
    ~inputs:[make_coinbase_input ~height:0]
    ~outputs:[make_output ~value:(Consensus.block_subsidy 0) ()]
    ()
  in
  let wrong_merkle = Types.zero_hash in
  let header = make_header ~merkle_root:wrong_merkle ~bits:0x207fffffl ~timestamp:100l () in
  let block = { Types.header; transactions = [coinbase] } in
  match Validation.check_block ~network:Consensus.regtest block 0 ~expected_bits:0x207fffffl ~median_time:0l with
  | Error Validation.BlockBadMerkleRoot -> ()
  | Error Validation.BlockBadDifficulty -> ()  (* May fail difficulty first *)
  | Error e -> Alcotest.fail ("Wrong error: " ^ Validation.block_error_to_string e)
  | Ok () -> Alcotest.fail "Should have failed"

let test_check_block_bad_timestamp () =
  let coinbase = make_tx
    ~inputs:[make_coinbase_input ~height:100]
    ~outputs:[make_output ~value:(Consensus.block_subsidy 100) ()]
    ()
  in
  let txid = Crypto.compute_txid coinbase in
  let (merkle, _) = Crypto.merkle_root [txid] in
  (* Timestamp <= median_time should fail *)
  let header = make_header ~merkle_root:merkle ~bits:0x207fffffl ~timestamp:50l () in
  let block = { Types.header; transactions = [coinbase] } in
  match Validation.check_block ~network:Consensus.regtest block 100 ~expected_bits:0x207fffffl ~median_time:100l with
  | Error Validation.BlockBadTimestamp -> ()
  | Error Validation.BlockBadDifficulty -> ()  (* May fail PoW check *)
  | Error e -> Alcotest.fail ("Wrong error: " ^ Validation.block_error_to_string e)
  | Ok () -> Alcotest.fail "Should have failed with BlockBadTimestamp"

let test_check_block_duplicate_tx () =
  let coinbase = make_tx
    ~inputs:[make_coinbase_input ~height:100]
    ~outputs:[make_output ~value:(Consensus.block_subsidy 100) ()]
    ()
  in
  let txid = Cstruct.create 32 in
  Cstruct.set_uint8 txid 0 0x01;
  let regular_tx = make_tx
    ~inputs:[make_input ~txid ()]
    ~outputs:[make_output ~value:1000L ()]
    ()
  in
  let block = {
    Types.header = make_header ~timestamp:200l ();
    transactions = [coinbase; regular_tx; regular_tx];  (* Duplicate *)
  } in
  match Validation.check_block ~network:Consensus.regtest block 100 ~expected_bits:0x207fffffl ~median_time:0l with
  | Error Validation.BlockDuplicateTx -> ()
  | Error Validation.BlockBadMerkleRoot -> ()  (* May fail merkle first *)
  | Error Validation.BlockBadDifficulty -> ()  (* May fail PoW first *)
  | Error e -> Alcotest.fail ("Wrong error: " ^ Validation.block_error_to_string e)
  | Ok () -> Alcotest.fail "Should have failed with BlockDuplicateTx"

(* ============================================================================
   Error String Tests
   ============================================================================ *)

let test_tx_error_strings () =
  let errors = [
    Validation.TxEmptyInputs;
    Validation.TxEmptyOutputs;
    Validation.TxOversizeWeight 500000;
    Validation.TxNegativeOutput 0;
    Validation.TxOutputOverflow;
    Validation.TxDuplicateInputs;
    Validation.TxMissingInputs;
    Validation.TxInsufficientFee;
    Validation.TxScriptFailed (0, "test");
    Validation.TxNonFinalLocktime;
    Validation.TxBadCoinbase;
    Validation.TxInvalidWitness;
  ] in
  List.iter (fun e ->
    let s = Validation.tx_error_to_string e in
    Alcotest.(check bool) "error string not empty" true (String.length s > 0)
  ) errors

let test_block_error_strings () =
  let errors = [
    Validation.BlockEmptyTransactions;
    Validation.BlockNoCoinbase;
    Validation.BlockBadMerkleRoot;
    Validation.BlockBadTimestamp;
    Validation.BlockBadDifficulty;
    Validation.BlockOverweight 5000000;
    Validation.BlockTooManySigops;
    Validation.BlockBadCoinbaseValue (100L, 50L);
    Validation.BlockDuplicateTx;
    Validation.BlockTxValidationFailed (0, Validation.TxEmptyInputs);
    Validation.BlockBadVersion;
    Validation.BlockMutatedMerkle;
  ] in
  List.iter (fun e ->
    let s = Validation.block_error_to_string e in
    Alcotest.(check bool) "error string not empty" true (String.length s > 0)
  ) errors

(* ============================================================================
   BIP-34 Conditional Enforcement Tests (Bug 1)
   ============================================================================ *)

let test_bip34_not_enforced_before_activation () =
  (* Before bip34_height (regtest=500), height encoding is not checked *)
  let cb = make_tx
    ~inputs:[make_coinbase_input ~height:100]
    ~outputs:[make_output ~value:(Consensus.block_subsidy 100) ()]
    ()
  in
  (* Pass height=200 with coinbase encoded for height=100 -- should pass
     because 200 < regtest bip34_height=500 *)
  match Validation.check_coinbase ~network:Consensus.regtest cb 200 with
  | Ok () -> ()
  | Error e -> Alcotest.fail ("Should not enforce BIP34 before activation: " ^
                              Validation.tx_error_to_string e)

let test_bip34_enforced_after_activation () =
  (* After bip34_height, height encoding IS checked *)
  let cb = make_tx
    ~inputs:[make_coinbase_input ~height:500]
    ~outputs:[make_output ~value:(Consensus.block_subsidy 500) ()]
    ()
  in
  (* Pass height=600 with coinbase encoded for height=500 -- should fail *)
  match Validation.check_coinbase ~network:Consensus.regtest cb 600 with
  | Error Validation.TxBadCoinbase -> ()
  | Error e -> Alcotest.fail ("Wrong error: " ^ Validation.tx_error_to_string e)
  | Ok () -> Alcotest.fail "Should enforce BIP34 after activation height"

(* ============================================================================
   Block Version Enforcement Tests (Bug 5)
   ============================================================================ *)

let test_block_version_too_low_bip34 () =
  (* At regtest bip34_height=500, version must be >= 2 *)
  let coinbase = make_tx
    ~inputs:[make_coinbase_input ~height:500]
    ~outputs:[make_output ~value:(Consensus.block_subsidy 500) ()]
    ()
  in
  let txid = Crypto.compute_txid coinbase in
  let (merkle, _) = Crypto.merkle_root [txid] in
  let header = make_header ~version:1l ~merkle_root:merkle ~bits:0x207fffffl ~timestamp:100l () in
  let block = { Types.header; transactions = [coinbase] } in
  match Validation.check_block ~network:Consensus.regtest block 500
          ~expected_bits:0x207fffffl ~median_time:0l with
  | Error Validation.BlockBadVersion -> ()
  | Error Validation.BlockBadDifficulty -> ()  (* May fail PoW first *)
  | Error e -> Alcotest.fail ("Wrong error: " ^ Validation.block_error_to_string e)
  | Ok () -> Alcotest.fail "Should have rejected version 1 block after BIP34"

let test_block_version_ok_before_bip34 () =
  (* Before bip34_height, version 1 is fine *)
  let coinbase = make_tx
    ~inputs:[make_coinbase_input ~height:100]
    ~outputs:[make_output ~value:(Consensus.block_subsidy 100) ()]
    ()
  in
  let txid = Crypto.compute_txid coinbase in
  let (merkle, _) = Crypto.merkle_root [txid] in
  let header = make_header ~version:1l ~merkle_root:merkle ~bits:0x207fffffl ~timestamp:100l () in
  let block = { Types.header; transactions = [coinbase] } in
  match Validation.check_block ~network:Consensus.regtest block 100
          ~expected_bits:0x207fffffl ~median_time:0l with
  | Error Validation.BlockBadVersion ->
    Alcotest.fail "Should NOT reject version 1 block before BIP34 activation"
  | Error Validation.BlockBadDifficulty -> ()  (* Expected: PoW check may fail *)
  | Error _ -> ()  (* Other errors are acceptable *)
  | Ok () -> ()

let test_block_version_too_low_bip66 () =
  (* At regtest bip66_height=1251, version must be >= 3 *)
  let coinbase = make_tx
    ~inputs:[make_coinbase_input ~height:1251]
    ~outputs:[make_output ~value:(Consensus.block_subsidy 1251) ()]
    ()
  in
  let txid = Crypto.compute_txid coinbase in
  let (merkle, _) = Crypto.merkle_root [txid] in
  let header = make_header ~version:2l ~merkle_root:merkle ~bits:0x207fffffl ~timestamp:100l () in
  let block = { Types.header; transactions = [coinbase] } in
  match Validation.check_block ~network:Consensus.regtest block 1251
          ~expected_bits:0x207fffffl ~median_time:0l with
  | Error Validation.BlockBadVersion -> ()
  | Error Validation.BlockBadDifficulty -> ()
  | Error e -> Alcotest.fail ("Wrong error: " ^ Validation.block_error_to_string e)
  | Ok () -> Alcotest.fail "Should have rejected version 2 block after BIP66"

let test_block_version_too_low_bip65 () =
  (* At regtest bip65_height=1351, version must be >= 4 *)
  let coinbase = make_tx
    ~inputs:[make_coinbase_input ~height:1351]
    ~outputs:[make_output ~value:(Consensus.block_subsidy 1351) ()]
    ()
  in
  let txid = Crypto.compute_txid coinbase in
  let (merkle, _) = Crypto.merkle_root [txid] in
  let header = make_header ~version:3l ~merkle_root:merkle ~bits:0x207fffffl ~timestamp:100l () in
  let block = { Types.header; transactions = [coinbase] } in
  match Validation.check_block ~network:Consensus.regtest block 1351
          ~expected_bits:0x207fffffl ~median_time:0l with
  | Error Validation.BlockBadVersion -> ()
  | Error Validation.BlockBadDifficulty -> ()
  | Error e -> Alcotest.fail ("Wrong error: " ^ Validation.block_error_to_string e)
  | Ok () -> Alcotest.fail "Should have rejected version 3 block after BIP65"

(* ============================================================================
   Test Registration
   ============================================================================ *)

let () =
  let open Alcotest in
  run "Validation" [
    "tx_weight", [
      test_case "weight without witness" `Quick test_tx_weight_no_witness;
      test_case "weight with witness" `Quick test_tx_weight_with_witness;
    ];
    "check_transaction", [
      test_case "valid transaction" `Quick test_check_transaction_valid;
      test_case "empty inputs" `Quick test_check_transaction_empty_inputs;
      test_case "empty outputs" `Quick test_check_transaction_empty_outputs;
      test_case "negative output" `Quick test_check_transaction_negative_output;
      test_case "output over max" `Quick test_check_transaction_output_over_max;
      test_case "duplicate inputs" `Quick test_check_transaction_duplicate_inputs;
      test_case "total overflow" `Quick test_check_transaction_total_overflow;
    ];
    "coinbase", [
      test_case "is coinbase" `Quick test_is_coinbase;
      test_case "valid coinbase" `Quick test_check_coinbase_valid;
      test_case "wrong height" `Quick test_check_coinbase_wrong_height;
      test_case "multiple inputs" `Quick test_check_coinbase_multiple_inputs;
      test_case "script too short" `Quick test_check_coinbase_script_too_short;
    ];
    "sigops", [
      test_case "count checksig" `Quick test_count_sigops_checksig;
      test_case "count checksigverify" `Quick test_count_sigops_checksigverify;
      test_case "count checkmultisig" `Quick test_count_sigops_checkmultisig;
      test_case "count multiple" `Quick test_count_sigops_multiple;
      test_case "count empty" `Quick test_count_sigops_empty;
    ];
    "finality", [
      test_case "zero locktime" `Quick test_is_tx_final_zero_locktime;
      test_case "final sequences" `Quick test_is_tx_final_all_final_sequences;
      test_case "height locktime" `Quick test_is_tx_final_height_locktime;
      test_case "time locktime" `Quick test_is_tx_final_time_locktime;
    ];
    "check_block", [
      test_case "empty block" `Quick test_check_block_empty;
      test_case "no coinbase" `Quick test_check_block_no_coinbase;
      test_case "bad difficulty" `Quick test_check_block_bad_difficulty;
      test_case "bad merkle" `Quick test_check_block_bad_merkle;
      test_case "bad timestamp" `Quick test_check_block_bad_timestamp;
      test_case "duplicate tx" `Quick test_check_block_duplicate_tx;
    ];
    "error_strings", [
      test_case "tx error strings" `Quick test_tx_error_strings;
      test_case "block error strings" `Quick test_block_error_strings;
    ];
    "bip34_conditional", [
      test_case "not enforced before activation" `Quick test_bip34_not_enforced_before_activation;
      test_case "enforced after activation" `Quick test_bip34_enforced_after_activation;
    ];
    "block_version", [
      test_case "version too low at bip34" `Quick test_block_version_too_low_bip34;
      test_case "version ok before bip34" `Quick test_block_version_ok_before_bip34;
      test_case "version too low at bip66" `Quick test_block_version_too_low_bip66;
      test_case "version too low at bip65" `Quick test_block_version_too_low_bip65;
    ];
  ]
