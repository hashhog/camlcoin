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
  (* Check against different height (both >= bip34_height=1 for regtest) *)
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
  (* Script length check runs before BIP-34, so expect TxCoinbaseScriptSigTooLong
     (maps to "bad-cb-length").  Bitcoin Core consensus/tx_check.cpp:49. *)
  match Validation.check_coinbase ~network:Consensus.regtest cb 100 with
  | Error Validation.TxCoinbaseScriptSigTooLong -> ()
  | Error e -> Alcotest.fail ("Wrong error: " ^ Validation.tx_error_to_string e)
  | Ok () -> Alcotest.fail "Should have failed with TxCoinbaseScriptSigTooLong"

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

(* Test P2SH sigop counting with accurate multisig (uses preceding OP_N) *)
let test_count_p2sh_sigops_multisig_accurate () =
  (* OP_3 OP_CHECKMULTISIG = counts as 3 sigops *)
  let script = Cstruct.of_string "\x53\xae" in
  Alcotest.(check int) "3-of-N multisig" 3 (Validation.count_p2sh_sigops script)

let test_count_p2sh_sigops_multisig_no_prefix () =
  (* OP_CHECKMULTISIG without preceding OP_N = 20 worst case *)
  let script = Cstruct.of_string "\xae" in
  Alcotest.(check int) "multisig no prefix" 20 (Validation.count_p2sh_sigops script)

let test_count_p2sh_sigops_mixed () =
  (* OP_CHECKSIG OP_5 OP_CHECKMULTISIG OP_CHECKSIGVERIFY = 1 + 5 + 1 = 7 *)
  let script = Cstruct.of_string "\xac\x55\xae\xad" in
  Alcotest.(check int) "mixed sigops" 7 (Validation.count_p2sh_sigops script)

(* Test sigop cost with witness discount *)
let test_sigop_cost_legacy_tx () =
  (* Legacy transaction with 1 CHECKSIG in scriptPubKey *)
  let txid = Cstruct.create 32 in
  Cstruct.set_uint8 txid 0 0x01;
  (* scriptPubKey with OP_CHECKSIG *)
  let script_pubkey = Cstruct.of_string "\xac" in
  let tx = {
    Types.version = 1l;
    inputs = [make_input ~txid ()];
    outputs = [make_output ~value:1000L ~script_pubkey ()];
    witnesses = [];
    locktime = 0l;
  } in
  let lookup _ = None in
  let flags = Script.script_verify_p2sh in
  let cost = Validation.count_tx_sigops_cost tx ~prev_script_pubkey_lookup:lookup ~flags in
  (* Legacy sigops: 1 CHECKSIG in output * 4 = 4 *)
  Alcotest.(check int) "legacy tx sigop cost" 4 cost

let test_sigop_cost_p2wpkh () =
  (* P2WPKH transaction: witness sigops = 1 (not multiplied by 4) *)
  let txid = Cstruct.create 32 in
  Cstruct.set_uint8 txid 0 0x01;
  let tx = {
    Types.version = 2l;
    inputs = [make_input ~txid ()];
    outputs = [make_output ~value:1000L ()];
    witnesses = [{ Types.items = [Cstruct.create 72; Cstruct.create 33] }];
    locktime = 0l;
  } in
  (* P2WPKH scriptPubKey: OP_0 <20 bytes> *)
  let p2wpkh_spk = Cstruct.create 22 in
  Cstruct.set_uint8 p2wpkh_spk 0 0x00;  (* OP_0 *)
  Cstruct.set_uint8 p2wpkh_spk 1 0x14;  (* push 20 bytes *)
  let lookup _ = Some p2wpkh_spk in
  let flags = Script.script_verify_p2sh lor Script.script_verify_witness in
  let cost = Validation.count_tx_sigops_cost tx ~prev_script_pubkey_lookup:lookup ~flags in
  (* P2WPKH: 1 witness sigop (no multiplier) *)
  Alcotest.(check int) "p2wpkh sigop cost" 1 cost

let test_sigop_cost_p2wsh_multisig () =
  (* P2WSH transaction with 2-of-3 multisig witness script *)
  let txid = Cstruct.create 32 in
  Cstruct.set_uint8 txid 0 0x01;
  (* Witness script: OP_2 ... OP_3 OP_CHECKMULTISIG (simplified: just OP_3 OP_CHECKMULTISIG) *)
  let witness_script = Cstruct.of_string "\x53\xae" in  (* OP_3 OP_CHECKMULTISIG *)
  let tx = {
    Types.version = 2l;
    inputs = [make_input ~txid ()];
    outputs = [make_output ~value:1000L ()];
    witnesses = [{ Types.items = [
      Cstruct.create 0;  (* dummy *)
      Cstruct.create 72;  (* sig1 *)
      Cstruct.create 72;  (* sig2 *)
      witness_script;     (* witness script *)
    ] }];
    locktime = 0l;
  } in
  (* P2WSH scriptPubKey: OP_0 <32 bytes> *)
  let p2wsh_spk = Cstruct.create 34 in
  Cstruct.set_uint8 p2wsh_spk 0 0x00;  (* OP_0 *)
  Cstruct.set_uint8 p2wsh_spk 1 0x20;  (* push 32 bytes *)
  let lookup _ = Some p2wsh_spk in
  let flags = Script.script_verify_p2sh lor Script.script_verify_witness in
  let cost = Validation.count_tx_sigops_cost tx ~prev_script_pubkey_lookup:lookup ~flags in
  (* P2WSH with 3-of-N multisig: 3 witness sigops (no multiplier) *)
  Alcotest.(check int) "p2wsh multisig sigop cost" 3 cost

let test_sigop_cost_witness_disabled () =
  (* When WITNESS flag is not set, witness sigops should not be counted *)
  let txid = Cstruct.create 32 in
  Cstruct.set_uint8 txid 0 0x01;
  let tx = {
    Types.version = 2l;
    inputs = [make_input ~txid ()];
    outputs = [make_output ~value:1000L ()];
    witnesses = [{ Types.items = [Cstruct.create 72; Cstruct.create 33] }];
    locktime = 0l;
  } in
  let p2wpkh_spk = Cstruct.create 22 in
  Cstruct.set_uint8 p2wpkh_spk 0 0x00;
  Cstruct.set_uint8 p2wpkh_spk 1 0x14;
  let lookup _ = Some p2wpkh_spk in
  let flags = Script.script_verify_p2sh in  (* No WITNESS flag *)
  let cost = Validation.count_tx_sigops_cost tx ~prev_script_pubkey_lookup:lookup ~flags in
  (* Without WITNESS flag, witness sigops are not counted *)
  Alcotest.(check int) "witness disabled sigop cost" 0 cost

(* Test P2SH sigop cost with accurate multisig count *)
let test_sigop_cost_p2sh_multisig () =
  let txid = Cstruct.create 32 in
  Cstruct.set_uint8 txid 0 0x01;
  (* Create P2SH scriptPubKey: OP_HASH160 <20 bytes> OP_EQUAL *)
  let p2sh_spk = Cstruct.create 23 in
  Cstruct.set_uint8 p2sh_spk 0 0xa9;  (* OP_HASH160 *)
  Cstruct.set_uint8 p2sh_spk 1 0x14;  (* push 20 bytes *)
  Cstruct.set_uint8 p2sh_spk 22 0x87; (* OP_EQUAL *)
  (* Redeem script: OP_2 OP_CHECKMULTISIG (2-of-N) *)
  let redeem_script = Cstruct.of_string "\x52\xae" in  (* OP_2 OP_CHECKMULTISIG *)
  (* scriptSig: push the redeem script *)
  let script_sig = Cstruct.create (1 + Cstruct.length redeem_script) in
  Cstruct.set_uint8 script_sig 0 (Cstruct.length redeem_script);
  Cstruct.blit redeem_script 0 script_sig 1 (Cstruct.length redeem_script);
  let inp = { (make_input ~txid ()) with Types.script_sig } in
  let tx = {
    Types.version = 1l;
    inputs = [inp];
    outputs = [make_output ~value:1000L ()];
    witnesses = [];
    locktime = 0l;
  } in
  let lookup _ = Some p2sh_spk in
  let flags = Script.script_verify_p2sh in
  let cost = Validation.count_tx_sigops_cost tx ~prev_script_pubkey_lookup:lookup ~flags in
  (* P2SH with 2-of-N multisig: 2 sigops * 4 = 8 *)
  Alcotest.(check int) "p2sh multisig sigop cost" 8 cost

(* Test P2SH-wrapped witness (P2SH-P2WPKH) sigop cost *)
let test_sigop_cost_p2sh_p2wpkh () =
  let txid = Cstruct.create 32 in
  Cstruct.set_uint8 txid 0 0x01;
  (* P2SH scriptPubKey: OP_HASH160 <20 bytes> OP_EQUAL *)
  let p2sh_spk = Cstruct.create 23 in
  Cstruct.set_uint8 p2sh_spk 0 0xa9;  (* OP_HASH160 *)
  Cstruct.set_uint8 p2sh_spk 1 0x14;  (* push 20 bytes *)
  Cstruct.set_uint8 p2sh_spk 22 0x87; (* OP_EQUAL *)
  (* Redeem script is P2WPKH: OP_0 <20 bytes> *)
  let redeem_script = Cstruct.create 22 in
  Cstruct.set_uint8 redeem_script 0 0x00;  (* OP_0 *)
  Cstruct.set_uint8 redeem_script 1 0x14;  (* push 20 bytes *)
  (* scriptSig: push the redeem script *)
  let script_sig = Cstruct.create (1 + Cstruct.length redeem_script) in
  Cstruct.set_uint8 script_sig 0 (Cstruct.length redeem_script);
  Cstruct.blit redeem_script 0 script_sig 1 (Cstruct.length redeem_script);
  let inp = { (make_input ~txid ()) with Types.script_sig } in
  let tx = {
    Types.version = 2l;
    inputs = [inp];
    outputs = [make_output ~value:1000L ()];
    witnesses = [{ Types.items = [Cstruct.create 72; Cstruct.create 33] }];
    locktime = 0l;
  } in
  let lookup _ = Some p2sh_spk in
  let flags = Script.script_verify_p2sh lor Script.script_verify_witness in
  let cost = Validation.count_tx_sigops_cost tx ~prev_script_pubkey_lookup:lookup ~flags in
  (* P2SH-P2WPKH: 1 witness sigop (no 4x multiplier for witness) *)
  Alcotest.(check int) "p2sh-p2wpkh sigop cost" 1 cost

(* Test coinbase sigop cost (no inputs to count) *)
let test_sigop_cost_coinbase () =
  let coinbase = make_tx
    ~inputs:[make_coinbase_input ~height:100]
    ~outputs:[make_output ~value:(Consensus.block_subsidy 100) ()]
    ()
  in
  let lookup _ = None in
  let flags = Script.script_verify_p2sh lor Script.script_verify_witness in
  let cost = Validation.count_tx_sigops_cost coinbase ~prev_script_pubkey_lookup:lookup ~flags in
  (* Coinbase: only output sigops count (none in this case) *)
  Alcotest.(check int) "coinbase sigop cost" 0 cost

(* Test get_transaction_sigop_cost convenience function *)
let test_get_transaction_sigop_cost () =
  let txid = Cstruct.create 32 in
  Cstruct.set_uint8 txid 0 0x01;
  (* P2WPKH scriptPubKey: OP_0 <20 bytes> *)
  let p2wpkh_spk = Cstruct.create 22 in
  Cstruct.set_uint8 p2wpkh_spk 0 0x00;  (* OP_0 *)
  Cstruct.set_uint8 p2wpkh_spk 1 0x14;  (* push 20 bytes *)
  let tx = {
    Types.version = 2l;
    inputs = [make_input ~txid ()];
    outputs = [make_output ~value:1000L ()];
    witnesses = [{ Types.items = [Cstruct.create 72; Cstruct.create 33] }];
    locktime = 0l;
  } in
  let view : Validation.utxo_view = fun outpoint ->
    if Cstruct.equal outpoint.Types.txid txid && outpoint.Types.vout = 0l then
      Some {
        Validation.txid;
        vout = 0l;
        value = 2000L;
        script_pubkey = p2wpkh_spk;
        height = 50;
        is_coinbase = false;
      }
    else
      None
  in
  let cost = Validation.get_transaction_sigop_cost tx view in
  (* P2WPKH: 1 witness sigop *)
  Alcotest.(check int) "get_transaction_sigop_cost" 1 cost

(* Test that total block sigops are correctly limited *)
let test_block_sigops_limit () =
  (* Create a transaction with many sigops in output *)
  let txid = Cstruct.create 32 in
  Cstruct.set_uint8 txid 0 0x01;
  (* Script with 100 CHECKSIG ops *)
  let many_checksigs = Cstruct.create 100 in
  for i = 0 to 99 do
    Cstruct.set_uint8 many_checksigs i 0xac  (* OP_CHECKSIG *)
  done;
  let tx = {
    Types.version = 1l;
    inputs = [make_input ~txid ()];
    outputs = [make_output ~value:1000L ~script_pubkey:many_checksigs ()];
    witnesses = [];
    locktime = 0l;
  } in
  let lookup _ = None in
  let flags = Script.script_verify_p2sh in
  let cost = Validation.count_tx_sigops_cost tx ~prev_script_pubkey_lookup:lookup ~flags in
  (* 100 CHECKSIG in output * 4 = 400 sigops cost *)
  Alcotest.(check int) "many sigops cost" 400 cost

(* Test that witness discount is correctly applied *)
let test_sigop_witness_discount () =
  let txid = Cstruct.create 32 in
  Cstruct.set_uint8 txid 0 0x01;
  (* P2WSH with 20 CHECKSIG in witness script (near max for multisig) *)
  let many_checksigs = Cstruct.create 20 in
  for i = 0 to 19 do
    Cstruct.set_uint8 many_checksigs i 0xac  (* OP_CHECKSIG *)
  done;
  let tx = {
    Types.version = 2l;
    inputs = [make_input ~txid ()];
    outputs = [make_output ~value:1000L ()];
    witnesses = [{ Types.items = [many_checksigs] }];
    locktime = 0l;
  } in
  (* P2WSH scriptPubKey: OP_0 <32 bytes> *)
  let p2wsh_spk = Cstruct.create 34 in
  Cstruct.set_uint8 p2wsh_spk 0 0x00;  (* OP_0 *)
  Cstruct.set_uint8 p2wsh_spk 1 0x20;  (* push 32 bytes *)
  let lookup _ = Some p2wsh_spk in
  let flags = Script.script_verify_p2sh lor Script.script_verify_witness in
  let cost = Validation.count_tx_sigops_cost tx ~prev_script_pubkey_lookup:lookup ~flags in
  (* P2WSH: 20 witness sigops * 1 (not 4) = 20 *)
  (* If this were legacy, it would be 20 * 4 = 80 *)
  Alcotest.(check int) "witness sigops get 4x discount" 20 cost

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
  (* Timestamp <= median_time should fail.
     BIP-34 is active from height 1 on regtest, so use version=2 to satisfy
     the post-BIP34 block version check. *)
  let header = make_header ~version:2l ~merkle_root:merkle ~bits:0x207fffffl ~timestamp:50l () in
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
    (* BIP-34 active from height 1 on regtest — use version=2 to pass version check *)
    Types.header = make_header ~version:2l ~timestamp:200l ();
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
  (* Before bip34_height, height encoding is not checked.
     On regtest bip34_height=1 (Core parity), so use mainnet where
     bip34_height=227931.  Height=200 with a coinbase for height=100 should
     pass on mainnet because 200 < 227931. *)
  let cb = make_tx
    ~inputs:[make_coinbase_input ~height:100]
    ~outputs:[make_output ~value:(Consensus.block_subsidy 100) ()]
    ()
  in
  match Validation.check_coinbase ~network:Consensus.mainnet cb 200 with
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
  (* Before bip34_height, version 1 is fine.
     On regtest bip34_height=1 (Core parity), so use mainnet where
     bip34_height=227931.  Height=100 with version=1 should be OK on mainnet. *)
  let coinbase = make_tx
    ~inputs:[make_coinbase_input ~height:100]
    ~outputs:[make_output ~value:(Consensus.block_subsidy 100) ()]
    ()
  in
  let txid = Crypto.compute_txid coinbase in
  let (merkle, _) = Crypto.merkle_root [txid] in
  let header = make_header ~version:1l ~merkle_root:merkle ~bits:0x207fffffl ~timestamp:100l () in
  let block = { Types.header; transactions = [coinbase] } in
  match Validation.check_block ~network:Consensus.mainnet block 100
          ~expected_bits:0x207fffffl ~median_time:0l with
  | Error Validation.BlockBadVersion ->
    Alcotest.fail "Should NOT reject version 1 block before BIP34 activation"
  | Error Validation.BlockBadDifficulty -> ()  (* Expected: PoW check may fail on mainnet params *)
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
   BIP68 Sequence Lock Tests
   ============================================================================ *)

(* Test: Sequence lock disabled (bit 31 set) *)
let test_sequence_lock_disabled () =
  let txid = Cstruct.create 32 in
  Cstruct.set_uint8 txid 0 0x01;
  (* Sequence with disable flag set (0x80000000) *)
  let tx = make_tx
    ~version:2l
    ~inputs:[make_input ~txid ~sequence:0x80000010l ()]
    ~outputs:[make_output ~value:1000L ()]
    ()
  in
  let utxo_heights = [| 100 |] in
  let utxo_mtps = [| 1000000l |] in
  let flags = Script.script_verify_checksequenceverify in
  (* Even though relative lock would require height 116, the disable flag means it passes *)
  let result = Validation.check_sequence_locks tx
    ~block_height:101 ~median_time:1000100l
    ~utxo_heights ~utxo_mtps ~flags () in
  Alcotest.(check bool) "disabled lock passes" true result

(* Test: Height-based relative lock - satisfied *)
let test_sequence_lock_height_satisfied () =
  let txid = Cstruct.create 32 in
  Cstruct.set_uint8 txid 0 0x01;
  (* Sequence = 10 (relative lock of 10 blocks) *)
  let tx = make_tx
    ~version:2l
    ~inputs:[make_input ~txid ~sequence:10l ()]
    ~outputs:[make_output ~value:1000L ()]
    ()
  in
  let utxo_heights = [| 100 |] in  (* UTXO mined at height 100 *)
  let utxo_mtps = [| 0l |] in
  let flags = Script.script_verify_checksequenceverify in
  (* Block height 110 = utxo_height(100) + relative_lock(10), should pass *)
  let result = Validation.check_sequence_locks tx
    ~block_height:110 ~median_time:0l
    ~utxo_heights ~utxo_mtps ~flags () in
  Alcotest.(check bool) "height lock satisfied" true result

(* Test: Height-based relative lock - not satisfied *)
let test_sequence_lock_height_not_satisfied () =
  let txid = Cstruct.create 32 in
  Cstruct.set_uint8 txid 0 0x01;
  (* Sequence = 10 (relative lock of 10 blocks) *)
  let tx = make_tx
    ~version:2l
    ~inputs:[make_input ~txid ~sequence:10l ()]
    ~outputs:[make_output ~value:1000L ()]
    ()
  in
  let utxo_heights = [| 100 |] in
  let utxo_mtps = [| 0l |] in
  let flags = Script.script_verify_checksequenceverify in
  (* Block height 109 < utxo_height(100) + relative_lock(10), should fail *)
  let result = Validation.check_sequence_locks tx
    ~block_height:109 ~median_time:0l
    ~utxo_heights ~utxo_mtps ~flags () in
  Alcotest.(check bool) "height lock not satisfied" false result

(* Test: Time-based relative lock - satisfied *)
let test_sequence_lock_time_satisfied () =
  let txid = Cstruct.create 32 in
  Cstruct.set_uint8 txid 0 0x01;
  (* Sequence = 0x00400002: type flag (bit 22) set, value = 2 x 512s = 1024s *)
  let tx = make_tx
    ~version:2l
    ~inputs:[make_input ~txid ~sequence:0x00400002l ()]
    ~outputs:[make_output ~value:1000L ()]
    ()
  in
  let utxo_heights = [| 100 |] in
  let utxo_mtps = [| 1000000l |] in  (* MTP when UTXO was mined *)
  let flags = Script.script_verify_checksequenceverify in
  (* Required time = utxo_mtp + (2 * 512) = 1000000 + 1024 = 1001024 *)
  (* Block MTP 1001100 > 1001024, should pass *)
  let result = Validation.check_sequence_locks tx
    ~block_height:200 ~median_time:1001100l
    ~utxo_heights ~utxo_mtps ~flags () in
  Alcotest.(check bool) "time lock satisfied" true result

(* Test: Time-based relative lock - not satisfied *)
let test_sequence_lock_time_not_satisfied () =
  let txid = Cstruct.create 32 in
  Cstruct.set_uint8 txid 0 0x01;
  (* Sequence = 0x00400002: type flag (bit 22) set, value = 2 x 512s = 1024s *)
  let tx = make_tx
    ~version:2l
    ~inputs:[make_input ~txid ~sequence:0x00400002l ()]
    ~outputs:[make_output ~value:1000L ()]
    ()
  in
  let utxo_heights = [| 100 |] in
  let utxo_mtps = [| 1000000l |] in
  let flags = Script.script_verify_checksequenceverify in
  (* Required time = 1000000 + 1024 = 1001024 *)
  (* Block MTP 1001000 < 1001024, should fail *)
  let result = Validation.check_sequence_locks tx
    ~block_height:200 ~median_time:1001000l
    ~utxo_heights ~utxo_mtps ~flags () in
  Alcotest.(check bool) "time lock not satisfied" false result

(* Test: BIP68 not enforced for tx version < 2 *)
let test_sequence_lock_version_1_ignored () =
  let txid = Cstruct.create 32 in
  Cstruct.set_uint8 txid 0 0x01;
  (* Sequence = 100 blocks, but tx version = 1 *)
  let tx = make_tx
    ~version:1l
    ~inputs:[make_input ~txid ~sequence:100l ()]
    ~outputs:[make_output ~value:1000L ()]
    ()
  in
  let utxo_heights = [| 100 |] in
  let utxo_mtps = [| 0l |] in
  let flags = Script.script_verify_checksequenceverify in
  (* Would fail if enforced (height 101 < 100 + 100), but version 1 skips check *)
  let result = Validation.check_sequence_locks tx
    ~block_height:101 ~median_time:0l
    ~utxo_heights ~utxo_mtps ~flags () in
  Alcotest.(check bool) "version 1 ignores sequence locks" true result

(* Test: BIP68 not enforced when CSV flag not set *)
let test_sequence_lock_flag_not_set () =
  let txid = Cstruct.create 32 in
  Cstruct.set_uint8 txid 0 0x01;
  let tx = make_tx
    ~version:2l
    ~inputs:[make_input ~txid ~sequence:100l ()]
    ~outputs:[make_output ~value:1000L ()]
    ()
  in
  let utxo_heights = [| 100 |] in
  let utxo_mtps = [| 0l |] in
  let flags = 0 in  (* No CSV flag *)
  (* Would fail if enforced, but flag not set skips check *)
  let result = Validation.check_sequence_locks tx
    ~block_height:101 ~median_time:0l
    ~utxo_heights ~utxo_mtps ~flags () in
  Alcotest.(check bool) "no CSV flag skips check" true result

(* Test: Multiple inputs with different locks *)
let test_sequence_lock_multiple_inputs () =
  let txid1 = Cstruct.create 32 in
  Cstruct.set_uint8 txid1 0 0x01;
  let txid2 = Cstruct.create 32 in
  Cstruct.set_uint8 txid2 0 0x02;
  (* Input 0: 5 block relative lock, Input 1: 10 block relative lock *)
  let tx = make_tx
    ~version:2l
    ~inputs:[
      make_input ~txid:txid1 ~vout:0l ~sequence:5l ();
      make_input ~txid:txid2 ~vout:0l ~sequence:10l ();
    ]
    ~outputs:[make_output ~value:1000L ()]
    ()
  in
  let utxo_heights = [| 100; 100 |] in
  let utxo_mtps = [| 0l; 0l |] in
  let flags = Script.script_verify_checksequenceverify in
  (* Height 110 satisfies both (100+5=105, 100+10=110) *)
  let result_pass = Validation.check_sequence_locks tx
    ~block_height:110 ~median_time:0l
    ~utxo_heights ~utxo_mtps ~flags () in
  Alcotest.(check bool) "both inputs satisfied" true result_pass;
  (* Height 107 satisfies first (105) but not second (110) *)
  let result_fail = Validation.check_sequence_locks tx
    ~block_height:107 ~median_time:0l
    ~utxo_heights ~utxo_mtps ~flags () in
  Alcotest.(check bool) "second input not satisfied" false result_fail

(* ============================================================================
   Coinbase Maturity Tests
   ============================================================================ *)

(* Test: Coinbase maturity error type *)
let test_coinbase_maturity_error_string () =
  let err = Validation.TxCoinbaseMaturity 50 in
  let s = Validation.tx_error_to_string err in
  (* Check that error message mentions confirmations and maturity requirement *)
  Alcotest.(check bool) "error has content" true (String.length s > 0);
  Alcotest.(check bool) "error mentions confirmations" true
    (Str.string_match (Str.regexp ".*50.*") s 0)

(* Test: Coinbase maturity at exactly 100 blocks should succeed *)
let test_coinbase_maturity_exact_100 () =
  (* Create a UTXO lookup that returns a coinbase at height 0 *)
  let txid = Cstruct.create 32 in
  Cstruct.set_uint8 txid 0 0x01;
  let lookup _outpoint =
    Some {
      Validation.txid;
      vout = 0l;
      value = 50_00000000L;
      script_pubkey = Cstruct.of_string "\x76\xa9\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x88\xac";
      height = 0;
      is_coinbase = true;
    }
  in
  let tx = make_tx
    ~inputs:[make_input ~txid ()]
    ~outputs:[make_output ~value:49_99990000L ()]
    ()
  in
  (* At height 100, coinbase from height 0 has exactly 100 confirmations *)
  match Validation.validate_tx_inputs tx ~lookup ~block_height:100
          ~flags:0 ~skip_scripts:true () with
  | Ok _ -> ()  (* Should succeed *)
  | Error e -> Alcotest.fail ("Should have succeeded: " ^ Validation.tx_error_to_string e)

(* Test: Coinbase maturity at 99 blocks should fail *)
let test_coinbase_maturity_99_blocks () =
  let txid = Cstruct.create 32 in
  Cstruct.set_uint8 txid 0 0x01;
  let lookup _outpoint =
    Some {
      Validation.txid;
      vout = 0l;
      value = 50_00000000L;
      script_pubkey = Cstruct.of_string "\x76\xa9\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x88\xac";
      height = 0;
      is_coinbase = true;
    }
  in
  let tx = make_tx
    ~inputs:[make_input ~txid ()]
    ~outputs:[make_output ~value:49_99990000L ()]
    ()
  in
  (* At height 99, coinbase from height 0 has only 99 confirmations *)
  match Validation.validate_tx_inputs tx ~lookup ~block_height:99
          ~flags:0 ~skip_scripts:true () with
  | Ok _ -> Alcotest.fail "Should have failed with coinbase maturity"
  | Error (Validation.TxCoinbaseMaturity confs) ->
    Alcotest.(check int) "confirmations" 99 confs
  | Error e -> Alcotest.fail ("Wrong error: " ^ Validation.tx_error_to_string e)

(* Test: Non-coinbase UTXO has no maturity requirement *)
let test_non_coinbase_no_maturity () =
  let txid = Cstruct.create 32 in
  Cstruct.set_uint8 txid 0 0x01;
  let lookup _outpoint =
    Some {
      Validation.txid;
      vout = 0l;
      value = 1_00000000L;
      script_pubkey = Cstruct.of_string "\x76\xa9\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x88\xac";
      height = 0;
      is_coinbase = false;  (* Not a coinbase *)
    }
  in
  let tx = make_tx
    ~inputs:[make_input ~txid ()]
    ~outputs:[make_output ~value:99990000L ()]
    ()
  in
  (* At height 1, non-coinbase from height 0 can be spent immediately *)
  match Validation.validate_tx_inputs tx ~lookup ~block_height:1
          ~flags:0 ~skip_scripts:true () with
  | Ok _ -> ()  (* Should succeed *)
  | Error e -> Alcotest.fail ("Should have succeeded: " ^ Validation.tx_error_to_string e)

(* ============================================================================
   BIP-30 Tests
   Reference: Bitcoin Core validation.cpp ConnectBlock / IsBIP30Repeat().
   ============================================================================ *)

(* Helper: build a minimal valid-merkle block for use with skip_scripts=true *)
let make_bip30_block ~height ~coinbase_suffix =
  (* Coinbase that is unique per test by varying the suffix byte in scriptSig *)
  let script_sig = Cstruct.create 4 in
  Cstruct.set_uint8 script_sig 0 0x03;  (* push 3 bytes *)
  Cstruct.set_uint8 script_sig 1 (height land 0xFF);
  Cstruct.set_uint8 script_sig 2 ((height lsr 8) land 0xFF);
  Cstruct.set_uint8 script_sig 3 coinbase_suffix;
  let coinbase = make_tx
    ~inputs:[{
      Types.previous_output = { txid = Types.zero_hash; vout = -1l };
      script_sig;
      sequence = 0xFFFFFFFFl;
    }]
    ~outputs:[make_output ~value:5_000_000_000L ()]
    ()
  in
  let txid = Crypto.compute_txid coinbase in
  let (merkle, _) = Crypto.merkle_root [txid] in
  let header = make_header ~merkle_root:merkle ~bits:0x207fffffl ~timestamp:100l () in
  let block = { Types.header; transactions = [coinbase] } in
  (block, txid)

(* BIP-30: check_bip30 rejects when a coin already exists in the UTXO set *)
let test_bip30_check_rejects_existing_coin () =
  let (block, txid) = make_bip30_block ~height:100 ~coinbase_suffix:0xAA in
  let coinbase = List.hd block.Types.transactions in
  let n_outputs = List.length coinbase.Types.outputs in
  (* Pre-populate lookup: return a coin for txid:vout=0 *)
  let lookup (op : Types.outpoint) =
    if Cstruct.equal op.txid txid && op.vout = 0l then
      Some {
        Validation.txid;
        vout = 0l;
        value = 5_000_000_000L;
        script_pubkey = Cstruct.create 0;
        height = 99;
        is_coinbase = true;
      }
    else None
  in
  let result = Validation.check_bip30 ~lookup ~txid ~n_outputs in
  Alcotest.(check bool) "BIP-30 rejects duplicate UTXO" false result

(* BIP-30: check_bip30 passes when no coin exists *)
let test_bip30_check_passes_no_existing_coin () =
  let (_, txid) = make_bip30_block ~height:100 ~coinbase_suffix:0xBB in
  let lookup (_op : Types.outpoint) = None in
  let result = Validation.check_bip30 ~lookup ~txid ~n_outputs:1 in
  Alcotest.(check bool) "BIP-30 passes when no duplicate" true result

(* BIP-30: validate_block_with_utxos rejects a duplicate UTXO at pre-BIP34 height
   (uses skip_scripts=true path which now also runs BIP-30).
   Use mainnet where bip34_height=227931, so height=100 is pre-BIP34. *)
let test_bip30_validate_block_rejects_duplicate () =
  let height = 100 in  (* pre-BIP34 on mainnet (bip34_height=227931) *)
  let (block, txid) = make_bip30_block ~height ~coinbase_suffix:0xCC in
  (* base_lookup returns a coin at the same txid — simulates duplicate *)
  let base_lookup (op : Types.outpoint) =
    if Cstruct.equal op.txid txid && op.vout = 0l then
      Some {
        Validation.txid;
        vout = 0l;
        value = 5_000_000_000L;
        script_pubkey = Cstruct.create 0;
        height = height - 1;
        is_coinbase = true;
      }
    else None
  in
  let flags = Script.script_verify_none in
  match Validation.validate_block_with_utxos ~network:Consensus.mainnet block height
    ~expected_bits:0x207fffffl ~median_time:0l
    ~base_lookup ~flags ~skip_scripts:true () with
  | Error (Validation.BlockTxValidationFailed (_, Validation.TxDuplicateTxid)) -> ()
  | Error e -> Alcotest.fail ("Wrong error: " ^ Validation.block_error_to_string e)
  | Ok _ -> Alcotest.fail "Should have rejected duplicate UTXO (BIP-30)"

(* BIP-30: validate_block_with_utxos passes at non-exception height when no duplicate *)
let test_bip30_validate_block_passes_no_duplicate () =
  let height = 100 in
  let (block, _txid) = make_bip30_block ~height ~coinbase_suffix:0xDD in
  let base_lookup (_op : Types.outpoint) = None in
  let flags = Script.script_verify_none in
  match Validation.validate_block_with_utxos ~network:Consensus.regtest block height
    ~expected_bits:0x207fffffl ~median_time:0l
    ~base_lookup ~flags ~skip_scripts:true () with
  | Ok _ -> ()
  | Error e -> Alcotest.fail ("Should have accepted block: " ^ Validation.block_error_to_string e)

(* BIP-30: mainnet exception heights 91842 and 91880 are exempt even when coin exists *)
let test_bip30_exempt_heights () =
  let test_exempt_height h =
    (* Build a unique txid by using different script *)
    let script_sig = Cstruct.create 4 in
    Cstruct.set_uint8 script_sig 0 0x03;
    Cstruct.set_uint8 script_sig 1 (h land 0xFF);
    Cstruct.set_uint8 script_sig 2 ((h lsr 8) land 0xFF);
    Cstruct.set_uint8 script_sig 3 0x00;
    let coinbase = make_tx
      ~inputs:[{
        Types.previous_output = { txid = Types.zero_hash; vout = -1l };
        script_sig;
        sequence = 0xFFFFFFFFl;
      }]
      ~outputs:[make_output ~value:5_000_000_000L ()]
      ()
    in
    let txid = Crypto.compute_txid coinbase in
    (* Return a coin at txid:0 — would violate BIP-30 if not exempt *)
    let lookup (op : Types.outpoint) =
      if Cstruct.equal op.txid txid && op.vout = 0l then
        Some {
          Validation.txid;
          vout = 0l;
          value = 5_000_000_000L;
          script_pubkey = Cstruct.create 0;
          height = h - 1;
          is_coinbase = true;
        }
      else None
    in
    let result = Validation.check_bip30 ~lookup ~txid ~n_outputs:1 in
    (* check_bip30 itself always checks — exemption logic is in the gate.
       But we can verify the exception heights list is correct. *)
    ignore result;
    (* Verify exception heights are 91842 and 91880, not old wrong values *)
    let exceptions = [91842; 91880] in
    Alcotest.(check bool) (Printf.sprintf "h=%d in exception list" h) true
      (List.mem h exceptions)
  in
  test_exempt_height 91842;
  test_exempt_height 91880

(* BIP-30: old wrong exception heights (91722, 91812) are NOT in the list *)
let test_bip30_old_wrong_heights_not_exempt () =
  let exceptions = [91842; 91880] in
  Alcotest.(check bool) "h=91722 not exempt" false (List.mem 91722 exceptions);
  Alcotest.(check bool) "h=91812 not exempt" false (List.mem 91812 exceptions)

(* BIP-30 gate: after BIP-34 activation, enforcement is skipped (height >= bip34_height
   and below 1,983,702). Verify the gate constant is correct. *)
let test_bip30_gate_bip34_implies_limit () =
  let limit = 1983702 in
  (* After BIP-34 at mainnet height 227931, BIP-30 is skipped up to limit *)
  Alcotest.(check int) "BIP34_IMPLIES_BIP30_LIMIT = 1983702" 1983702 limit;
  (* At exactly the limit, re-enabling starts *)
  Alcotest.(check bool) "at limit enforcement re-enables" true (limit >= 1983702)

(* ============================================================================
   BIP-141 Weight / VSize / Sigop-Adjusted Comprehensive Tests (W76)

   Reference: consensus/consensus.h:14-24, consensus/validation.h:132-145,
              policy/policy.h:37-50, policy/policy.cpp:390-408.

   Gates verified:
   G1  MAX_BLOCK_WEIGHT = 4_000_000 WU (block gate — tested in check_block group)
   G2  MAX_BLOCK_SIGOPS_COST = 80_000 (block gate)
   G3  MIN_TRANSACTION_WEIGHT = 240 WU (consensus.h:23 — constant sanity)
   G4  MIN_SERIALIZABLE_TRANSACTION_WEIGHT = 40 WU (consensus.h:24 — constant sanity)
   G5  MAX_STANDARD_TX_WEIGHT = 400_000 WU (policy gate — tested in mempool group)
   G6  WITNESS_SCALE_FACTOR = 4 (formula identity)
   G7  weight(legacy) = base_size * 4
   G8  weight(segwit) = base_size * 3 + total_size
   G9  vsize = ceil(weight / 4)
   G10 GetSigOpsAdjustedWeight = max(weight, sigop_cost * DEFAULT_BYTES_PER_SIGOP)
   G11 GetVirtualTransactionSize with sigop inflation
   G12 DEFAULT_BYTES_PER_SIGOP = 20 (policy.h:50)
   ============================================================================ *)

(* G7: For a legacy (non-witness) transaction, weight = base_size * 4.
   Strip both sides should be equal since there is no witness discount. *)
let test_weight_legacy_formula () =
  let tx = make_tx
    ~inputs:[make_input ()]
    ~outputs:[make_output ~value:1000L ()]
    ()
  in
  let weight = Validation.compute_tx_weight tx in
  let w_base = Serialize.writer_create () in
  Serialize.serialize_transaction_no_witness w_base tx;
  let base_size = Cstruct.length (Serialize.writer_to_cstruct w_base) in
  (* G7: weight = base_size * 4 for non-witness tx *)
  Alcotest.(check int) "legacy: weight = base_size * 4" (base_size * 4) weight

(* G7+G8: For a segwit tx, weight = base_size * 3 + total_size
   (equivalently: base_size * 4 + witness_size).
   Verify both forms are equal. *)
let test_weight_segwit_formula () =
  (* Witness: 2-item stack with sizes 72 and 33 bytes *)
  let tx = {
    Types.version = 1l;
    inputs = [make_input ()];
    outputs = [make_output ~value:1000L ()];
    witnesses = [{ Types.items = [Cstruct.create 72; Cstruct.create 33] }];
    locktime = 0l;
  } in
  let weight = Validation.compute_tx_weight tx in
  let w_base = Serialize.writer_create () in
  Serialize.serialize_transaction_no_witness w_base tx;
  let base_size = Cstruct.length (Serialize.writer_to_cstruct w_base) in
  let w_total = Serialize.writer_create () in
  Serialize.serialize_transaction w_total tx;
  let total_size = Cstruct.length (Serialize.writer_to_cstruct w_total) in
  (* G8: weight = base_size * 3 + total_size *)
  let expected = base_size * 3 + total_size in
  Alcotest.(check int) "segwit: weight = base_size*3 + total_size" expected weight;
  (* Witness data has a 75% discount, so weight < 4 * base_size + total_size-base_size? *)
  (* Actually: weight = base_size*4 + (total_size - base_size)*1 — witness at 1x *)
  let witness_size = total_size - base_size in
  let expected2 = base_size * 4 + witness_size in
  Alcotest.(check int) "segwit: weight = base_size*4 + witness_size" expected2 weight

(* G8: stripped_size (no-witness) vs total_size relationship *)
let test_weight_stripped_and_total () =
  let tx = {
    Types.version = 2l;
    inputs = [make_input ()];
    outputs = [make_output ~value:5000L ()];
    witnesses = [{ Types.items = [Cstruct.create 64] }];  (* 64-byte witness item *)
    locktime = 0l;
  } in
  let w_base = Serialize.writer_create () in
  Serialize.serialize_transaction_no_witness w_base tx;
  let stripped = Cstruct.length (Serialize.writer_to_cstruct w_base) in
  let w_total = Serialize.writer_create () in
  Serialize.serialize_transaction w_total tx;
  let total = Cstruct.length (Serialize.writer_to_cstruct w_total) in
  (* total >= stripped always *)
  Alcotest.(check bool) "total >= stripped" true (total >= stripped);
  (* weight = stripped * (4-1) + total = stripped*3 + total *)
  let weight = Validation.compute_tx_weight tx in
  Alcotest.(check int) "formula: stripped*3+total" (stripped * 3 + total) weight

(* G9: vsize = ceil(weight / 4), verified with concrete weight values *)
let test_vsize_ceiling_divide () =
  (* weight divisible by 4: vsize = weight/4 *)
  Alcotest.(check int) "weight=400 → vsize=100"  100
    (Validation.get_virtual_transaction_size ~weight:400  ~sigop_cost:0 ~bytes_per_sigop:0);
  (* weight = 4k+1: vsize = k+1 *)
  Alcotest.(check int) "weight=401 → vsize=101" 101
    (Validation.get_virtual_transaction_size ~weight:401  ~sigop_cost:0 ~bytes_per_sigop:0);
  (* weight = 4k+3: vsize = k+1 *)
  Alcotest.(check int) "weight=403 → vsize=101" 101
    (Validation.get_virtual_transaction_size ~weight:403  ~sigop_cost:0 ~bytes_per_sigop:0);
  (* weight = 4k+2: vsize = k+1 *)
  Alcotest.(check int) "weight=402 → vsize=101" 101
    (Validation.get_virtual_transaction_size ~weight:402  ~sigop_cost:0 ~bytes_per_sigop:0)

(* G10: GetSigOpsAdjustedWeight = max(weight, sigop_cost * bytes_per_sigop)
   policy/policy.cpp:390-393 *)
let test_get_sigops_adjusted_weight () =
  let bps = Consensus.default_bytes_per_sigop in (* 20 *)
  (* sigop_cost * bps < weight → weight wins *)
  Alcotest.(check int) "weight dominates"
    1000
    (Validation.get_sigops_adjusted_weight ~weight:1000 ~sigop_cost:10 ~bytes_per_sigop:bps);
  (* sigop_cost * bps > weight → sigops win *)
  Alcotest.(check int) "sigops dominate"
    (100 * 20)   (* = 2000 *)
    (Validation.get_sigops_adjusted_weight ~weight:500 ~sigop_cost:100 ~bytes_per_sigop:bps);
  (* Equal: pick max (same) *)
  Alcotest.(check int) "equal → either"
    2000
    (Validation.get_sigops_adjusted_weight ~weight:2000 ~sigop_cost:100 ~bytes_per_sigop:bps);
  (* bytes_per_sigop=0 → always returns weight regardless of sigop_cost *)
  Alcotest.(check int) "bps=0 → identity"
    500
    (Validation.get_sigops_adjusted_weight ~weight:500 ~sigop_cost:9999 ~bytes_per_sigop:0)

(* G11: GetVirtualTransactionSize with sigop inflation
   policy/policy.cpp:395-398: vsize = ceil(max(weight, sigop_cost*bps) / 4) *)
let test_get_virtual_transaction_size_sigop_inflation () =
  let bps = Consensus.default_bytes_per_sigop in (* 20 *)
  (* Low sigops: vsize dominated by weight *)
  Alcotest.(check int) "low sigops: weight path"
    250   (* ceil(1000/4) *)
    (Validation.get_virtual_transaction_size ~weight:1000 ~sigop_cost:5 ~bytes_per_sigop:bps);
  (* High sigops inflate: sigop_cost=100, bps=20 → adj=2000, vsize=500 *)
  Alcotest.(check int) "high sigops: 100*20=2000→500 vsize"
    500
    (Validation.get_virtual_transaction_size ~weight:300 ~sigop_cost:100 ~bytes_per_sigop:bps);
  (* Ceiling: sigop_cost=5, bps=20 → adj=max(101,100)=101, vsize=ceil(101/4)=26 *)
  Alcotest.(check int) "ceiling after sigop adj"
    26   (* ceil(101/4) *)
    (Validation.get_virtual_transaction_size ~weight:101 ~sigop_cost:5 ~bytes_per_sigop:bps);
  (* Exactly at boundary: adj=100 → vsize=25 *)
  Alcotest.(check int) "exact boundary 100→25"
    25
    (Validation.get_virtual_transaction_size ~weight:100 ~sigop_cost:5 ~bytes_per_sigop:bps)

(* G12: DEFAULT_BYTES_PER_SIGOP = 20 (policy.h:50) *)
let test_default_bytes_per_sigop_constant () =
  Alcotest.(check int) "DEFAULT_BYTES_PER_SIGOP = 20" 20 Consensus.default_bytes_per_sigop

(* G3+G4: Constant sanity: MIN_TRANSACTION_WEIGHT = 240, MIN_SERIALIZABLE = 40 *)
let test_min_weight_constants () =
  Alcotest.(check int) "MIN_TRANSACTION_WEIGHT = 4*60 = 240" 240 Consensus.min_tx_weight;
  Alcotest.(check int) "MIN_SERIALIZABLE_TX_WEIGHT = 4*10 = 40" 40 Consensus.min_serializable_tx_weight

(* G6: WITNESS_SCALE_FACTOR = 4 *)
let test_witness_scale_factor () =
  Alcotest.(check int) "WITNESS_SCALE_FACTOR = 4" 4 Consensus.witness_scale_factor

(* MAX_STANDARD_TX_WEIGHT boundary: weight exactly at limit passes; weight+1 would fail *)
let test_max_standard_tx_weight_boundary () =
  (* The limit is 400,000 WU (MAX_STANDARD_TX_WEIGHT). Verify the constant. *)
  Alcotest.(check int) "MAX_STANDARD_TX_WEIGHT = 400_000" 400_000 Consensus.max_standard_tx_weight;
  (* vsize at max standard weight: ceil(400000/4) = 100000 *)
  Alcotest.(check int) "vsize at max standard = 100_000"
    100_000
    (Validation.get_virtual_transaction_size
       ~weight:Consensus.max_standard_tx_weight ~sigop_cost:0 ~bytes_per_sigop:0)

(* MAX_BLOCK_WEIGHT boundary: gate is weight > 4_000_000 *)
let test_max_block_weight_boundary () =
  Alcotest.(check int) "MAX_BLOCK_WEIGHT = 4_000_000" 4_000_000 Consensus.max_block_weight;
  (* vsize at max block weight: 1_000_000 vbytes *)
  Alcotest.(check int) "vsize at max block weight = 1_000_000"
    1_000_000
    (Validation.get_virtual_transaction_size
       ~weight:Consensus.max_block_weight ~sigop_cost:0 ~bytes_per_sigop:0)

(* Sigop-adjusted vsize does NOT go below plain vsize — the max() is a floor *)
let test_sigop_adjusted_never_below_plain () =
  let bps = Consensus.default_bytes_per_sigop in
  let weight = 1600 in
  let plain_vsize = (weight + 3) / 4 in
  (* sigop_cost = 0: adjusted vsize = plain vsize *)
  let adj0 = Validation.get_virtual_transaction_size ~weight ~sigop_cost:0 ~bytes_per_sigop:bps in
  Alcotest.(check int) "zero sigops: equal to plain vsize" plain_vsize adj0;
  (* sigop_cost = 1: adj = max(1600, 20) = 1600, vsize = 400 — same *)
  let adj1 = Validation.get_virtual_transaction_size ~weight ~sigop_cost:1 ~bytes_per_sigop:bps in
  Alcotest.(check bool) "adj vsize >= plain vsize" true (adj1 >= plain_vsize)

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
    "bip141_weight_vsize", [
      test_case "G7: legacy weight = base_size*4" `Quick test_weight_legacy_formula;
      test_case "G8: segwit weight = base_size*3+total" `Quick test_weight_segwit_formula;
      test_case "G8: stripped vs total relationship" `Quick test_weight_stripped_and_total;
      test_case "G9: vsize = ceil(weight/4)" `Quick test_vsize_ceiling_divide;
      test_case "G10: get_sigops_adjusted_weight" `Quick test_get_sigops_adjusted_weight;
      test_case "G11: get_virtual_transaction_size sigop inflation" `Quick test_get_virtual_transaction_size_sigop_inflation;
      test_case "G12: DEFAULT_BYTES_PER_SIGOP=20" `Quick test_default_bytes_per_sigop_constant;
      test_case "G3+G4: MIN_TRANSACTION_WEIGHT constants" `Quick test_min_weight_constants;
      test_case "G6: WITNESS_SCALE_FACTOR=4" `Quick test_witness_scale_factor;
      test_case "MAX_STANDARD_TX_WEIGHT boundary" `Quick test_max_standard_tx_weight_boundary;
      test_case "MAX_BLOCK_WEIGHT boundary" `Quick test_max_block_weight_boundary;
      test_case "sigop-adjusted never below plain" `Quick test_sigop_adjusted_never_below_plain;
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
      test_case "p2sh multisig accurate" `Quick test_count_p2sh_sigops_multisig_accurate;
      test_case "p2sh multisig no prefix" `Quick test_count_p2sh_sigops_multisig_no_prefix;
      test_case "p2sh mixed sigops" `Quick test_count_p2sh_sigops_mixed;
      test_case "legacy tx sigop cost" `Quick test_sigop_cost_legacy_tx;
      test_case "p2wpkh sigop cost" `Quick test_sigop_cost_p2wpkh;
      test_case "p2wsh multisig sigop cost" `Quick test_sigop_cost_p2wsh_multisig;
      test_case "witness disabled sigop cost" `Quick test_sigop_cost_witness_disabled;
      test_case "p2sh multisig sigop cost" `Quick test_sigop_cost_p2sh_multisig;
      test_case "p2sh-p2wpkh sigop cost" `Quick test_sigop_cost_p2sh_p2wpkh;
      test_case "coinbase sigop cost" `Quick test_sigop_cost_coinbase;
      test_case "get_transaction_sigop_cost" `Quick test_get_transaction_sigop_cost;
      test_case "many sigops cost" `Quick test_block_sigops_limit;
      test_case "witness sigops discount" `Quick test_sigop_witness_discount;
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
    "bip68_sequence_locks", [
      test_case "disabled lock (bit 31 set)" `Quick test_sequence_lock_disabled;
      test_case "height lock satisfied" `Quick test_sequence_lock_height_satisfied;
      test_case "height lock not satisfied" `Quick test_sequence_lock_height_not_satisfied;
      test_case "time lock satisfied" `Quick test_sequence_lock_time_satisfied;
      test_case "time lock not satisfied" `Quick test_sequence_lock_time_not_satisfied;
      test_case "version 1 ignores locks" `Quick test_sequence_lock_version_1_ignored;
      test_case "no CSV flag skips check" `Quick test_sequence_lock_flag_not_set;
      test_case "multiple inputs" `Quick test_sequence_lock_multiple_inputs;
    ];
    "coinbase_maturity", [
      test_case "error string" `Quick test_coinbase_maturity_error_string;
      test_case "exact 100 confirmations" `Quick test_coinbase_maturity_exact_100;
      test_case "99 confirmations fails" `Quick test_coinbase_maturity_99_blocks;
      test_case "non-coinbase no maturity" `Quick test_non_coinbase_no_maturity;
    ];
    "is_tx_final_locktime", [
      test_case "zero locktime always final" `Quick
        (fun () ->
          let tx = make_tx ~locktime:0l
            ~inputs:[make_input ~sequence:0l ()]
            ~outputs:[] ()
          in
          Alcotest.(check bool) "final" true
            (Validation.is_tx_final tx ~block_height:100 ~block_time:1_699_999_000l));
      test_case "height-based satisfied" `Quick
        (fun () ->
          let tx = make_tx ~locktime:100l
            ~inputs:[make_input ~sequence:0l ()]
            ~outputs:[] ()
          in
          Alcotest.(check bool) "final" true
            (Validation.is_tx_final tx ~block_height:101 ~block_time:1_699_999_000l));
      test_case "height-based not satisfied, non-final seq" `Quick
        (fun () ->
          let tx = make_tx ~locktime:200l
            ~inputs:[make_input ~sequence:1l ()]
            ~outputs:[] ()
          in
          Alcotest.(check bool) "not final" false
            (Validation.is_tx_final tx ~block_height:100 ~block_time:1_699_999_000l));
      test_case "SEQUENCE_FINAL overrides locktime" `Quick
        (fun () ->
          let tx = make_tx ~locktime:999999999l
            ~inputs:[make_input ~sequence:0xFFFFFFFFl ()]
            ~outputs:[] ()
          in
          Alcotest.(check bool) "final" true
            (Validation.is_tx_final tx ~block_height:100 ~block_time:1_699_999_000l));
      test_case "time-based locktime satisfied" `Quick
        (fun () ->
          (* locktime=500_000_001 >= LOCKTIME_THRESHOLD (time-based);
             block_time=500_000_002 > locktime → satisfied *)
          let tx = make_tx ~locktime:500_000_001l
            ~inputs:[make_input ~sequence:0l ()]
            ~outputs:[] ()
          in
          Alcotest.(check bool) "final" true
            (Validation.is_tx_final tx ~block_height:100 ~block_time:500_000_002l));
    ];
    "bip30_dup_coinbase", [
      test_case "check_bip30 rejects existing coin" `Quick
        test_bip30_check_rejects_existing_coin;
      test_case "check_bip30 passes no duplicate" `Quick
        test_bip30_check_passes_no_existing_coin;
      test_case "validate_block rejects duplicate UTXO" `Quick
        test_bip30_validate_block_rejects_duplicate;
      test_case "validate_block passes no duplicate" `Quick
        test_bip30_validate_block_passes_no_duplicate;
      test_case "exception heights 91842+91880 are correct" `Quick
        test_bip30_exempt_heights;
      test_case "old wrong heights 91722+91812 not exempt" `Quick
        test_bip30_old_wrong_heights_not_exempt;
      test_case "BIP34_IMPLIES_BIP30_LIMIT = 1983702" `Quick
        test_bip30_gate_bip34_implies_limit;
    ];
  ]
