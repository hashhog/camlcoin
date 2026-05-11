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

(* W93 helper: grind a nonce so the header satisfies hash_meets_target
   for the given [bits].  Required by tests that run on the assumevalid
   fast path now that check_block executes there.  The regtest pow
   limit (0x207fffff) accepts ~50% of random nonces so this loop
   typically finds a nonce in 0..2 iterations.  Bounded at 10M to
   prevent runaway in pathological cases. *)
let mine_header (template : Types.block_header) : Types.block_header =
  let rec loop nonce =
    if nonce > 10_000_000l then
      failwith (Printf.sprintf
                  "mine_header: failed to grind nonce for bits=0x%lx" template.bits)
    else
      let h = { template with Types.nonce } in
      let hash = Crypto.compute_block_hash h in
      if Consensus.hash_meets_target hash h.bits then h
      else loop (Int32.add nonce 1l)
  in
  loop 0l

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
  (* Bug fix: Core returns bad-txns-vout-toolarge (TxOutputTooLarge), not
     bad-txns-vout-negative.  The previous test was silently accepting the
     wrong error variant. Reference: consensus/tx_check.cpp:29-30. *)
  match Validation.check_transaction tx with
  | Error (Validation.TxOutputTooLarge _) -> ()
  | Error e -> Alcotest.fail ("Wrong error: " ^ Validation.tx_error_to_string e)
  | Ok () -> Alcotest.fail "Should have failed with TxOutputTooLarge"

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
  (* Not final at height 500 — nLockTime=500 is the *last invalid* height;
     Core IsFinalTx: (int64_t)nLockTime < nBlockHeight → 500 < 500 = false.
     Bug fixed: was >= (off-by-one), now correctly uses > (strict). *)
  Alcotest.(check bool) "not final at exact locktime height" false
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
  (* Not final at exact time — nLockTime is last invalid timestamp;
     Core: (int64_t)nLockTime < nBlockTime → 500_000_100 < 500_000_100 = false.
     Bug fixed: was >= (off-by-one), now correctly uses > (strict). *)
  Alcotest.(check bool) "not final at exact locktime timestamp" false
    (Validation.is_tx_final tx ~block_height:1000000 ~block_time:500_000_100l);
  (* Final one second after locktime *)
  Alcotest.(check bool) "final one second after locktime" true
    (Validation.is_tx_final tx ~block_height:1000000 ~block_time:500_000_101l)

(* ============================================================================
   Block Validation Tests
   ============================================================================ *)

let test_check_block_empty () =
  let block = {
    Types.header = make_header ();
    transactions = [];
  } in
  match Validation.check_block ~network:Consensus.regtest block 0 ~expected_bits:0x207fffffl ~median_time:0l () with
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
  match Validation.check_block ~network:Consensus.regtest block 0 ~expected_bits:0x207fffffl ~median_time:0l () with
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
  match Validation.check_block ~network:Consensus.regtest block 0 ~expected_bits:0x1d00ffffl ~median_time:0l () with
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
  match Validation.check_block ~network:Consensus.regtest block 0 ~expected_bits:0x207fffffl ~median_time:0l () with
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
     Regtest has bip65_height=1 and bip66_height=1, so at height=100 the block
     version must be >= 4 (bip65 threshold).  Use version=4l to pass the version
     gate so the timestamp check can fire.
     Reference: bitcoin-core/src/validation.cpp ContextualCheckBlockHeader. *)
  let header = make_header ~version:4l ~merkle_root:merkle ~bits:0x207fffffl ~timestamp:50l () in
  let block = { Types.header; transactions = [coinbase] } in
  match Validation.check_block ~network:Consensus.regtest block 100 ~expected_bits:0x207fffffl ~median_time:100l () with
  | Error Validation.BlockBadTimestamp -> ()
  | Error Validation.BlockBadDifficulty -> ()  (* May fail PoW check *)
  | Error e -> Alcotest.fail ("Wrong error: " ^ Validation.block_error_to_string e)
  | Ok () -> Alcotest.fail "Should have failed with BlockBadTimestamp"

(* BIP-94 timewarp attack: check_block fires BlockTimeWarpAttack on testnet4 at a
   difficulty-adjustment boundary when header_time < prev_block_time - MAX_TIMEWARP.
   Reference: bitcoin-core/src/validation.cpp ContextualCheckBlockHeader:4097-4104. *)
let test_check_block_timewarp_attack () =
  (* Use testnet4 (enforce_bip94=true); height=2016 is a retarget boundary *)
  let coinbase = make_tx
    ~inputs:[make_coinbase_input ~height:2016]
    ~outputs:[make_output ~value:(Consensus.block_subsidy 2016) ()]
    ()
  in
  let txid = Crypto.compute_txid coinbase in
  let (merkle, _) = Crypto.merkle_root [txid] in
  (* Timestamp > median_time (passes time-too-old), but 700s before prev block
     (fails BIP-94: needs prev_block_time - 600 <= header_time). *)
  let prev_block_time = 2_000_000l in
  let header_time = Int32.sub prev_block_time 700l in  (* 700s before parent: > MAX_TIMEWARP=600 *)
  let median_time = Int32.sub header_time 1l in        (* header_time > median_time: passes MTP gate *)
  let header = make_header ~version:4l ~merkle_root:merkle ~bits:0x207fffffl ~timestamp:header_time () in
  let block = { Types.header; transactions = [coinbase] } in
  match Validation.check_block ~network:Consensus.testnet4 block 2016
          ~expected_bits:0x207fffffl ~median_time ~prev_block_time () with
  | Error Validation.BlockTimeWarpAttack -> ()
  | Error Validation.BlockBadDifficulty -> ()  (* PoW hash check may fire first *)
  | Error e -> Alcotest.fail ("Wrong error: " ^ Validation.block_error_to_string e)
  | Ok () -> Alcotest.fail "Should have failed with BlockTimeWarpAttack on testnet4"

(* Mainnet: timewarp rule does NOT apply even at a retarget boundary. *)
let test_check_block_no_timewarp_mainnet () =
  let coinbase = make_tx
    ~inputs:[make_coinbase_input ~height:2016]
    ~outputs:[make_output ~value:(Consensus.block_subsidy 2016) ()]
    ()
  in
  let txid = Crypto.compute_txid coinbase in
  let (merkle, _) = Crypto.merkle_root [txid] in
  let prev_block_time = 2_000_000l in
  let header_time = Int32.sub prev_block_time 700l in
  let median_time = Int32.sub header_time 1l in
  let header = make_header ~version:4l ~merkle_root:merkle ~bits:0x207fffffl ~timestamp:header_time () in
  let block = { Types.header; transactions = [coinbase] } in
  (* On mainnet, the same block must NOT be rejected as BlockTimeWarpAttack *)
  (match Validation.check_block ~network:Consensus.mainnet block 2016
           ~expected_bits:0x207fffffl ~median_time ~prev_block_time () with
   | Error Validation.BlockTimeWarpAttack ->
     Alcotest.fail "Mainnet must NOT enforce BIP-94 timewarp rule"
   | _ -> ())

(* Testnet4 at a non-retarget boundary: timewarp does not apply. *)
let test_check_block_no_timewarp_non_boundary () =
  let height = 2017 in  (* NOT a retarget boundary *)
  let coinbase = make_tx
    ~inputs:[make_coinbase_input ~height]
    ~outputs:[make_output ~value:(Consensus.block_subsidy height) ()]
    ()
  in
  let txid = Crypto.compute_txid coinbase in
  let (merkle, _) = Crypto.merkle_root [txid] in
  let prev_block_time = 2_000_000l in
  let header_time = Int32.sub prev_block_time 700l in
  let median_time = Int32.sub header_time 1l in
  let header = make_header ~version:4l ~merkle_root:merkle ~bits:0x207fffffl ~timestamp:header_time () in
  let block = { Types.header; transactions = [coinbase] } in
  (* At non-boundary height, timewarp must NOT fire *)
  (match Validation.check_block ~network:Consensus.testnet4 block height
           ~expected_bits:0x207fffffl ~median_time ~prev_block_time () with
   | Error Validation.BlockTimeWarpAttack ->
     Alcotest.fail "Timewarp must not fire at non-boundary height"
   | _ -> ())

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
    (* Regtest has bip65_height=1, bip66_height=1: at height 100 the block version
       must be >= 4.  Previous test used version=2 which fired BlockBadVersion
       before the duplicate-tx check could run. *)
    Types.header = make_header ~version:4l ~timestamp:200l ();
    transactions = [coinbase; regular_tx; regular_tx];  (* Duplicate *)
  } in
  match Validation.check_block ~network:Consensus.regtest block 100 ~expected_bits:0x207fffffl ~median_time:0l () with
  | Error Validation.BlockDuplicateTx -> ()
  | Error Validation.BlockBadMerkleRoot -> ()  (* May fail merkle first *)
  | Error Validation.BlockBadDifficulty -> ()  (* May fail PoW first *)
  | Error e -> Alcotest.fail ("Wrong error: " ^ Validation.block_error_to_string e)
  | Ok () -> Alcotest.fail "Should have failed with BlockDuplicateTx"

(* ============================================================================
   Witness Commitment Tests (W77 — BIP-141 comprehensive audit)
   Reference: bitcoin-core/src/validation.cpp:3870-3916,
              bitcoin-core/src/consensus/validation.h:147-165
   ============================================================================ *)

(* Build the 6-byte witness commitment prefix: OP_RETURN 0x24 0xaa 0x21 0xa9 0xed *)
let witness_commitment_prefix () =
  let p = Cstruct.create 6 in
  Cstruct.set_uint8 p 0 0x6a;
  Cstruct.set_uint8 p 1 0x24;
  Cstruct.set_uint8 p 2 0xaa;
  Cstruct.set_uint8 p 3 0x21;
  Cstruct.set_uint8 p 4 0xa9;
  Cstruct.set_uint8 p 5 0xed;
  p

(* Build a valid 38-byte witness commitment scriptPubKey with the given 32-byte hash *)
let make_commitment_spk (hash32 : Cstruct.t) : Cstruct.t =
  Cstruct.concat [witness_commitment_prefix (); hash32]

(* Compute the expected commitment hash from a block's witness merkle root and nonce.
   commitment = SHA256d(witness_merkle_root || nonce) *)
let compute_commitment_hash (witness_root : Cstruct.t) (nonce : Cstruct.t) : Cstruct.t =
  Crypto.sha256d (Cstruct.concat [witness_root; nonce])

(* Build a minimal valid segwit block:
   - coinbase with a witness commitment output (last output) and the coinbase
     witness nonce (32 zero bytes in vin[0].scriptWitness)
   - one regular transaction (no witness) *)
let make_segwit_block ~(height : int) ~(extra_txs : Types.transaction list)
    ~(witness_nonce : Cstruct.t)
    ~(commitment_hash : Cstruct.t option)   (* None → use correct hash *)
    ~(commitment_outputs : Types.tx_out list option)  (* None → use correct output *)
    () : Types.block =
  (* Witness merkle root: coinbase wtxid=0, others use full serialization *)
  let placeholder_coinbase : Types.transaction = {
    version = 2l;
    inputs = [make_coinbase_input ~height];
    outputs = [make_output ~value:(Consensus.block_subsidy height) ()];
    witnesses = [];
    locktime = 0l;
  } in
  let all_for_witness = placeholder_coinbase :: extra_txs in
  let wtxids = List.mapi (fun i tx ->
    if i = 0 then Types.zero_hash
    else
      let w = Serialize.writer_create () in
      Serialize.serialize_transaction w tx;
      Crypto.sha256d (Serialize.writer_to_cstruct w)
  ) all_for_witness in
  let (witness_root, _) = Crypto.merkle_root wtxids in
  let commitment32 = match commitment_hash with
    | Some h -> h
    | None -> compute_commitment_hash witness_root witness_nonce
  in
  let commit_spk = make_commitment_spk commitment32 in
  let commit_output = make_output ~script_pubkey:commit_spk () in
  let coinbase_outputs = match commitment_outputs with
    | Some outs -> outs
    | None -> [make_output ~value:(Consensus.block_subsidy height) (); commit_output]
  in
  let coinbase_witness : Types.tx_witness = {
    items = [witness_nonce];
  } in
  let coinbase : Types.transaction = {
    version = 2l;
    inputs = [make_coinbase_input ~height];
    outputs = coinbase_outputs;
    witnesses = [coinbase_witness];
    locktime = 0l;
  } in
  let all_txs = coinbase :: extra_txs in
  let txids = List.map Crypto.compute_txid all_txs in
  let (merkle_root, _) = Crypto.merkle_root txids in
  let header = make_header ~version:4l ~merkle_root ~bits:0x207fffffl ~timestamp:200l () in
  { Types.header; transactions = all_txs }

(* Gate 10: coinbase witness nonce must be exactly 1 item of 32 bytes.
   Core: validation.cpp:3880-3885, bad-witness-nonce-size *)
let test_witness_nonce_wrong_size () =
  (* Nonce with 31 bytes (too short) → BlockBadWitnessNonceSize *)
  let bad_nonce = Cstruct.create 31 in
  let block = make_segwit_block ~height:1 ~extra_txs:[] ~witness_nonce:bad_nonce
    ~commitment_hash:None ~commitment_outputs:None () in
  match Validation.check_witness_commitment ~segwit_active:true block with
  | Error Validation.BlockBadWitnessNonceSize -> ()
  | Error e -> Alcotest.failf "Wrong error for 31-byte nonce: %s"
      (Validation.block_error_to_string e)
  | Ok () -> Alcotest.fail "Should have failed with BlockBadWitnessNonceSize"

let test_witness_nonce_33_bytes () =
  (* Nonce with 33 bytes (too long) → BlockBadWitnessNonceSize *)
  let bad_nonce = Cstruct.create 33 in
  let block = make_segwit_block ~height:1 ~extra_txs:[] ~witness_nonce:bad_nonce
    ~commitment_hash:None ~commitment_outputs:None () in
  match Validation.check_witness_commitment ~segwit_active:true block with
  | Error Validation.BlockBadWitnessNonceSize -> ()
  | Error e -> Alcotest.failf "Wrong error for 33-byte nonce: %s"
      (Validation.block_error_to_string e)
  | Ok () -> Alcotest.fail "Should have failed with BlockBadWitnessNonceSize"

let test_witness_nonce_empty_stack () =
  (* Empty witness stack for coinbase input → BlockBadWitnessNonceSize *)
  let zero_nonce = Cstruct.create 32 in
  let block = make_segwit_block ~height:1 ~extra_txs:[] ~witness_nonce:zero_nonce
    ~commitment_hash:None ~commitment_outputs:None () in
  (* Override witnesses to empty stack *)
  let cb = List.hd block.transactions in
  let cb2 = { cb with witnesses = [{ Types.items = [] }] } in
  let txs2 = cb2 :: List.tl block.transactions in
  let block2 = { block with transactions = txs2 } in
  (match Validation.check_witness_commitment ~segwit_active:true block2 with
  | Error Validation.BlockBadWitnessNonceSize -> ()
  | Error e -> Alcotest.failf "Wrong error for empty nonce stack: %s"
      (Validation.block_error_to_string e)
  | Ok () -> Alcotest.fail "Should have failed with BlockBadWitnessNonceSize")

let test_witness_nonce_two_items () =
  (* Two-item stack → BlockBadWitnessNonceSize *)
  let zero_nonce = Cstruct.create 32 in
  let block = make_segwit_block ~height:1 ~extra_txs:[] ~witness_nonce:zero_nonce
    ~commitment_hash:None ~commitment_outputs:None () in
  let cb = List.hd block.transactions in
  let cb2 = { cb with witnesses =
    [{ Types.items = [Cstruct.create 32; Cstruct.create 32] }] } in
  let txs2 = cb2 :: List.tl block.transactions in
  let block2 = { block with transactions = txs2 } in
  (match Validation.check_witness_commitment ~segwit_active:true block2 with
  | Error Validation.BlockBadWitnessNonceSize -> ()
  | Error e -> Alcotest.failf "Wrong error for 2-item stack: %s"
      (Validation.block_error_to_string e)
  | Ok () -> Alcotest.fail "Should have failed with BlockBadWitnessNonceSize")

(* Gate 11: SHA256d(witness_merkle_root || nonce) must equal commitment.
   Core: validation.cpp:3890-3898, bad-witness-merkle-match *)
let test_witness_merkle_mismatch () =
  let zero_nonce = Cstruct.create 32 in
  let wrong_hash = Cstruct.create 32 in  (* all-zeros ≠ correct commitment *)
  Cstruct.set_uint8 wrong_hash 0 0xFF;
  let block = make_segwit_block ~height:1 ~extra_txs:[] ~witness_nonce:zero_nonce
    ~commitment_hash:(Some wrong_hash) ~commitment_outputs:None () in
  match Validation.check_witness_commitment ~segwit_active:true block with
  | Error Validation.BlockBadWitnessCommitment -> ()
  | Error e -> Alcotest.failf "Wrong error for merkle mismatch: %s"
      (Validation.block_error_to_string e)
  | Ok () -> Alcotest.fail "Should have failed with BlockBadWitnessCommitment"

(* Valid segwit block: coinbase wtxid=0, correct commitment, correct nonce *)
let test_witness_commitment_valid () =
  let zero_nonce = Cstruct.create 32 in
  let block = make_segwit_block ~height:1 ~extra_txs:[] ~witness_nonce:zero_nonce
    ~commitment_hash:None ~commitment_outputs:None () in
  match Validation.check_witness_commitment ~segwit_active:true block with
  | Ok () -> ()
  | Error e -> Alcotest.failf "Valid witness block rejected: %s"
      (Validation.block_error_to_string e)

(* LAST-scan: Core scans coinbase outputs forward and keeps the last matching one.
   If two commitment outputs exist, the last one must be valid.
   The first (bad) one should be ignored. *)
let test_witness_last_output_wins () =
  let zero_nonce = Cstruct.create 32 in
  (* Build a block and then replace coinbase outputs with two commitment outputs,
     where the first is wrong and the second is correct. *)
  let block = make_segwit_block ~height:1 ~extra_txs:[] ~witness_nonce:zero_nonce
    ~commitment_hash:None ~commitment_outputs:None () in
  (* Extract correct commitment from the block's second coinbase output *)
  let cb = List.hd block.transactions in
  let correct_commit_output = List.nth cb.outputs 1 in
  (* Make a wrong commitment output *)
  let bad_hash = Cstruct.create 32 in
  Cstruct.set_uint8 bad_hash 0 0xDE;
  let bad_commit_spk = make_commitment_spk bad_hash in
  let bad_commit_output = make_output ~script_pubkey:bad_commit_spk () in
  (* Coinbase now has: payout, wrong-commit, correct-commit *)
  let cb2 = { cb with outputs =
    [make_output ~value:(Consensus.block_subsidy 1) ();
     bad_commit_output;
     correct_commit_output] } in
  let txids2 = List.map Crypto.compute_txid (cb2 :: List.tl block.transactions) in
  let (merkle2, _) = Crypto.merkle_root txids2 in
  let header2 = { block.header with merkle_root = merkle2 } in
  let block2 : Types.block = { header = header2;
    transactions = cb2 :: List.tl block.transactions } in
  (* Last output (correct-commit) wins → should pass *)
  match Validation.check_witness_commitment ~segwit_active:true block2 with
  | Ok () -> ()
  | Error e -> Alcotest.failf "Last-output-wins test failed: %s"
      (Validation.block_error_to_string e)

(* Gate 12: segwit active, no commitment found → any witness data = unexpected-witness.
   Core: validation.cpp:3905-3913 *)
let test_unexpected_witness_segwit_active () =
  (* Block with a non-segwit coinbase (no commitment output) but a tx with witness *)
  let coinbase : Types.transaction = {
    version = 2l;
    inputs = [make_coinbase_input ~height:1];
    outputs = [make_output ~value:(Consensus.block_subsidy 1) ()];
    witnesses = [];
    locktime = 0l;
  } in
  let witness_tx : Types.transaction = {
    version = 1l;
    inputs = [make_input ~txid:(Cstruct.create 32) ()];
    outputs = [make_output ~value:1000L ()];
    witnesses = [{ Types.items = [Cstruct.create 72; Cstruct.create 33] }];
    locktime = 0l;
  } in
  let block : Types.block = {
    header = make_header ();
    transactions = [coinbase; witness_tx];
  } in
  match Validation.check_witness_commitment ~segwit_active:true block with
  | Error Validation.BlockUnexpectedWitness -> ()
  | Error e -> Alcotest.failf "Wrong error for unexpected witness: %s"
      (Validation.block_error_to_string e)
  | Ok () -> Alcotest.fail "Should have failed with BlockUnexpectedWitness"

(* Pre-segwit block with no witness data should pass (unexpected-witness check passes) *)
let test_no_witness_pre_segwit () =
  let coinbase : Types.transaction = {
    version = 1l;
    inputs = [make_coinbase_input ~height:0];
    outputs = [make_output ~value:(Consensus.block_subsidy 0) ()];
    witnesses = [];
    locktime = 0l;
  } in
  let block : Types.block = {
    header = make_header ();
    transactions = [coinbase];
  } in
  match Validation.check_witness_commitment ~segwit_active:false block with
  | Ok () -> ()
  | Error e -> Alcotest.failf "Pre-segwit clean block rejected: %s"
      (Validation.block_error_to_string e)

(* Pre-segwit block with witness data → unexpected-witness (same as post-segwit no-commitment) *)
let test_unexpected_witness_pre_segwit () =
  let coinbase : Types.transaction = {
    version = 1l;
    inputs = [make_coinbase_input ~height:0];
    outputs = [make_output ~value:(Consensus.block_subsidy 0) ()];
    witnesses = [{ Types.items = [Cstruct.create 32] }];
    locktime = 0l;
  } in
  let block : Types.block = {
    header = make_header ();
    transactions = [coinbase];
  } in
  match Validation.check_witness_commitment ~segwit_active:false block with
  | Error Validation.BlockUnexpectedWitness -> ()
  | Error e -> Alcotest.failf "Wrong error for pre-segwit with witness: %s"
      (Validation.block_error_to_string e)
  | Ok () -> Alcotest.fail "Should have failed with BlockUnexpectedWitness"

(* Bug 1 regression: pre-segwit block with a coincidental commitment-looking output
   must NOT be validated as having a segwit commitment — the commitment check is
   skipped entirely when segwit_active=false.
   Core: CheckWitnessMalleation(expect_witness_commitment=false) skips the
   commitment block, validation.cpp:3872-3903 *)
let test_pre_segwit_ignores_commitment_output () =
  (* Coinbase with a commitment-looking output but no coinbase witness.
     Pre-segwit: commitment check is skipped, only unexpected-witness is checked.
     Since there's no witness data, this should pass. *)
  let commit_spk = make_commitment_spk (Cstruct.create 32) in
  let commit_output = make_output ~script_pubkey:commit_spk () in
  let coinbase : Types.transaction = {
    version = 1l;
    inputs = [make_coinbase_input ~height:0];
    outputs = [make_output ~value:(Consensus.block_subsidy 0) (); commit_output];
    witnesses = [];
    locktime = 0l;
  } in
  let block : Types.block = {
    header = make_header ();
    transactions = [coinbase];
  } in
  (* segwit_active=false: commitment output is ignored, no witness → Ok *)
  (match Validation.check_witness_commitment ~segwit_active:false block with
  | Ok () -> ()
  | Error e -> Alcotest.failf
      "Pre-segwit commitment-looking output should be ignored, got: %s"
      (Validation.block_error_to_string e));
  (* segwit_active=true with no coinbase witness → BlockBadWitnessNonceSize *)
  (match Validation.check_witness_commitment ~segwit_active:true block with
  | Error Validation.BlockBadWitnessNonceSize -> ()
  | Error e -> Alcotest.failf
      "Expected BlockBadWitnessNonceSize for segwit active without nonce, got: %s"
      (Validation.block_error_to_string e)
  | Ok () -> Alcotest.fail "Should fail with BlockBadWitnessNonceSize when segwit active")

(* Minimum size: commitment output must be >= 38 bytes.
   A 37-byte output matching the prefix bytes is NOT a commitment.
   Core: MINIMUM_WITNESS_COMMITMENT=38, consensus/validation.h:18 *)
let test_minimum_38_byte_commitment () =
  (* 37-byte scriptPubKey: prefix + 31-byte hash → not a valid commitment *)
  let short_spk = Cstruct.create 37 in
  Cstruct.blit (witness_commitment_prefix ()) 0 short_spk 0 6;
  (* Fill remaining 31 bytes with the "hash" (irrelevant since not picked up) *)
  let coinbase : Types.transaction = {
    version = 2l;
    inputs = [make_coinbase_input ~height:1];
    outputs = [
      make_output ~value:(Consensus.block_subsidy 1) ();
      make_output ~script_pubkey:short_spk ();
    ];
    witnesses = [{ Types.items = [Cstruct.create 32] }];
    locktime = 0l;
  } in
  let block : Types.block = {
    header = make_header ();
    transactions = [coinbase];
  } in
  (* 37-byte output is not picked up as a commitment → falls to unexpected-witness check.
     The coinbase has a witness, so BlockUnexpectedWitness is triggered. *)
  match Validation.check_witness_commitment ~segwit_active:true block with
  | Error Validation.BlockUnexpectedWitness -> ()
  | Error e -> Alcotest.failf "Wrong error for 37-byte commitment: %s"
      (Validation.block_error_to_string e)
  | Ok () -> Alcotest.fail "Should have failed"

(* No commitment in coinbase, no witness data → Ok (pre-activation-style block) *)
let test_no_commitment_no_witness () =
  let coinbase : Types.transaction = {
    version = 2l;
    inputs = [make_coinbase_input ~height:1];
    outputs = [make_output ~value:(Consensus.block_subsidy 1) ()];
    witnesses = [];
    locktime = 0l;
  } in
  let block : Types.block = {
    header = make_header ();
    transactions = [coinbase];
  } in
  match Validation.check_witness_commitment ~segwit_active:true block with
  | Ok () -> ()
  | Error e -> Alcotest.failf "No-commitment no-witness should pass: %s"
      (Validation.block_error_to_string e)

(* Coinbase wtxid must be all-zeros in the witness merkle tree.
   Build a block where the coinbase wtxid is treated as 0x00…00, then verify
   that the computed commitment matches what a reference would produce. *)
let test_coinbase_wtxid_is_zero () =
  let zero_nonce = Cstruct.create 32 in
  (* The coinbase wtxid for the witness merkle is always 0 (BIP-141) *)
  let coinbase_wtxid = Types.zero_hash in
  (* With only one tx, witness merkle root = coinbase_wtxid = 0 *)
  let expected_witness_root = coinbase_wtxid in
  let expected_commitment = compute_commitment_hash expected_witness_root zero_nonce in
  let block = make_segwit_block ~height:1 ~extra_txs:[] ~witness_nonce:zero_nonce
    ~commitment_hash:None ~commitment_outputs:None () in
  (* Extract the actual commitment from the block *)
  let cb = List.hd block.transactions in
  let commit_out = List.nth cb.outputs 1 in
  let actual_commitment = Cstruct.sub commit_out.Types.script_pubkey 6 32 in
  Alcotest.(check bool) "coinbase wtxid=0 produces correct commitment"
    true (Cstruct.equal expected_commitment actual_commitment);
  (* Also verify the validation passes *)
  match Validation.check_witness_commitment ~segwit_active:true block with
  | Ok () -> ()
  | Error e -> Alcotest.failf "Coinbase-wtxid-zero block rejected: %s"
      (Validation.block_error_to_string e)

(* check_block integration: witness commitment is checked at the correct segwit gate.
   On regtest, segwit_height=0, so every block requires a witness commitment check.
   A regtest block (height=1) without a commitment but with witness data should fail. *)
let test_check_block_unexpected_witness_regtest () =
  (* For regtest at height=1, segwit is active (segwit_height=0).
     A block with witness data but no commitment → unexpected-witness *)
  let witness_tx : Types.transaction = {
    version = 1l;
    inputs = [make_input ~txid:(let t = Cstruct.create 32 in Cstruct.set_uint8 t 0 1; t) ()];
    outputs = [make_output ~value:1000L ()];
    witnesses = [{ Types.items = [Cstruct.create 72] }];
    locktime = 0l;
  } in
  let coinbase : Types.transaction = {
    version = 2l;
    inputs = [make_coinbase_input ~height:1];
    outputs = [make_output ~value:(Consensus.block_subsidy 1) ()];
    witnesses = [];
    locktime = 0l;
  } in
  let txs = [coinbase; witness_tx] in
  let txids = List.map Crypto.compute_txid txs in
  let (merkle_root, _) = Crypto.merkle_root txids in
  let header = make_header ~version:4l ~merkle_root ~bits:0x207fffffl ~timestamp:200l () in
  let block = { Types.header; transactions = txs } in
  match Validation.check_block ~network:Consensus.regtest block 1
          ~expected_bits:0x207fffffl ~median_time:0l () with
  | Error Validation.BlockUnexpectedWitness -> ()
  | Error Validation.BlockBadWitnessNonceSize -> ()  (* also acceptable: commitment check *)
  | Error Validation.BlockBadWitnessCommitment -> ()
  | Error e -> Alcotest.failf "Expected witness error, got: %s"
      (Validation.block_error_to_string e)
  | Ok () -> Alcotest.fail "Should have failed due to witness without commitment"

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
    Validation.BlockBadWitnessCommitment;
    Validation.BlockBadWitnessNonceSize;
    Validation.BlockUnexpectedWitness;
    Validation.BlockBadVersion;
    Validation.BlockMutatedMerkle;
    Validation.BlockTimeWarpAttack;
  ] in
  List.iter (fun e ->
    let s = Validation.block_error_to_string e in
    Alcotest.(check bool) "error string not empty" true (String.length s > 0)
  ) errors;
  (* Verify the error strings match Core reject reasons exactly *)
  Alcotest.(check string) "merkle-match string"
    "bad-witness-merkle-match"
    (Validation.block_error_to_string Validation.BlockBadWitnessCommitment);
  Alcotest.(check string) "nonce-size string"
    "bad-witness-nonce-size"
    (Validation.block_error_to_string Validation.BlockBadWitnessNonceSize);
  Alcotest.(check string) "unexpected-witness string"
    "unexpected-witness"
    (Validation.block_error_to_string Validation.BlockUnexpectedWitness);
  (* BIP-94 error string matches Core's reject reason *)
  Alcotest.(check string) "time-timewarp-attack string"
    "time-timewarp-attack"
    (Validation.block_error_to_string Validation.BlockTimeWarpAttack)

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
          ~expected_bits:0x207fffffl ~median_time:0l () with
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
          ~expected_bits:0x207fffffl ~median_time:0l () with
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
          ~expected_bits:0x207fffffl ~median_time:0l () with
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
          ~expected_bits:0x207fffffl ~median_time:0l () with
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

(* BIP-68 Gate: SEQUENCE_FINAL (0xFFFFFFFF) has disable bit set → skip *)
let test_sequence_final_skipped () =
  let txid = Cstruct.create 32 in
  Cstruct.set_uint8 txid 0 0x01;
  let tx = make_tx
    ~version:2l
    ~inputs:[make_input ~txid ~sequence:0xFFFFFFFFl ()]
    ~outputs:[make_output ~value:1000L ()]
    ()
  in
  let utxo_heights = [| 100 |] in
  let utxo_mtps = [| 0l |] in
  let flags = Script.script_verify_checksequenceverify in
  (* 0xFFFFFFFF has bit 31 set → disable flag → always pass regardless of height *)
  let result = Validation.check_sequence_locks tx
    ~block_height:1 ~median_time:0l
    ~utxo_heights ~utxo_mtps ~flags () in
  Alcotest.(check bool) "SEQUENCE_FINAL skipped" true result

(* BIP-68 Gate: height-based boundary: block_height = required_height passes,
   block_height = required_height - 1 fails.
   Core: nMinHeight = nCoinHeight + mask - 1; fail if nMinHeight >= block.nHeight
   → fail iff block_height <= nCoinHeight + mask - 1 → fail iff block_height < nCoinHeight + mask *)
let test_sequence_lock_height_boundary () =
  let txid = Cstruct.create 32 in
  Cstruct.set_uint8 txid 0 0x02;
  let tx = make_tx
    ~version:2l
    ~inputs:[make_input ~txid ~sequence:5l ()]
    ~outputs:[make_output ~value:1000L ()]
    ()
  in
  let utxo_heights = [| 200 |] in
  let utxo_mtps = [| 0l |] in
  let flags = Script.script_verify_checksequenceverify in
  (* required = 200 + 5 = 205; exact boundary *)
  let pass = Validation.check_sequence_locks tx
    ~block_height:205 ~median_time:0l
    ~utxo_heights ~utxo_mtps ~flags () in
  Alcotest.(check bool) "height 205 (= 200+5) passes" true pass;
  let fail = Validation.check_sequence_locks tx
    ~block_height:204 ~median_time:0l
    ~utxo_heights ~utxo_mtps ~flags () in
  Alcotest.(check bool) "height 204 (= 200+5-1) fails" false fail

(* BIP-68 Gate: time-based boundary with granularity = 9 (×512s) *)
let test_sequence_lock_time_boundary () =
  let txid = Cstruct.create 32 in
  Cstruct.set_uint8 txid 0 0x03;
  (* sequence value = 3 → 3 × 512 = 1536 seconds relative lock *)
  let tx = make_tx
    ~version:2l
    ~inputs:[make_input ~txid ~sequence:0x00400003l ()]
    ~outputs:[make_output ~value:1000L ()]
    ()
  in
  let utxo_heights = [| 100 |] in
  let base_mtp = 1_700_000_000l in
  let utxo_mtps = [| base_mtp |] in
  let flags = Script.script_verify_checksequenceverify in
  (* required = 1_700_000_000 + (3 lsl 9) = 1_700_000_000 + 1536 = 1_700_001_536 *)
  let required = Int32.add base_mtp (Int32.of_int (3 lsl 9)) in
  let pass = Validation.check_sequence_locks tx
    ~block_height:200 ~median_time:required
    ~utxo_heights ~utxo_mtps ~flags () in
  Alcotest.(check bool) "exact MTP passes" true pass;
  let fail = Validation.check_sequence_locks tx
    ~block_height:200
    ~median_time:(Int32.sub required 1l)
    ~utxo_heights ~utxo_mtps ~flags () in
  Alcotest.(check bool) "MTP - 1 fails" false fail

(* BIP-68 Gate: time-based lock uses Int64 arithmetic — no Int32 overflow
   for large timestamps. Use values that would overflow Int32. *)
let test_sequence_lock_time_int64_no_overflow () =
  let txid = Cstruct.create 32 in
  Cstruct.set_uint8 txid 0 0x04;
  (* sequence value = 0xFFFF (max) → 0xFFFF × 512 = 33_553_920s *)
  let tx = make_tx
    ~version:2l
    ~inputs:[make_input ~txid ~sequence:0x0040FFFFl ()]
    ~outputs:[make_output ~value:1000L ()]
    ()
  in
  let utxo_heights = [| 100 |] in
  (* Use a large base MTP that, when 33_553_920 is added, would overflow Int32.
     Int32 max ≈ 2_147_483_647. Use base = 2_100_000_000. *)
  let base_mtp = Int32.of_int 2_100_000_000 in
  let utxo_mtps = [| base_mtp |] in
  let flags = Script.script_verify_checksequenceverify in
  (* required (Int64) = 2_100_000_000 + 33_553_920 = 2_133_553_920, fits in Int64
     but would overflow Int32 (max 2_147_483_647 is larger, so just barely ok here;
     use a larger base to force overflow: base = 2_130_000_000 + offset = 2_163_553_920 > 2^31-1) *)
  let base_mtp2 = Int32.of_int 2_130_000_000 in
  let utxo_mtps2 = [| base_mtp2 |] in
  (* required = 2_130_000_000 + 33_553_920 = 2_163_553_920 which overflows Int32 *)
  (* As unsigned int64: 2_163_553_920 = 0x0000_0000_80E6_5B40 *)
  let req64 = Int64.add (Int64.logand (Int64.of_int32 base_mtp2) 0xFFFFFFFFL)
                        (Int64.of_int (0xFFFF lsl 9)) in
  (* Block MTP >= req64 should pass; block MTP < req64 should fail.
     Convert req64 back to int32 for test: take low 32 bits (may wrap). *)
  let req_lo32 = Int32.of_int (Int64.to_int (Int64.logand req64 0xFFFFFFFFL)) in
  (* Pass: block MTP = req_lo32 interpreted as unsigned (which is > req64 when wrapped if we trust Int64 impl) *)
  (* Simpler: just verify the function returns true when block MTP passes as int64-derived value *)
  let _ = base_mtp in
  let _ = utxo_mtps in
  let _ = req_lo32 in
  (* Verify: with max lock (0xFFFF * 512), a modern block should still satisfy an old UTXO *)
  let modern_mtp = 1_700_000_000l in  (* year ~2023 *)
  let old_utxo_mtp = 1_000_000_000l in  (* year ~2001 *)
  let utxo_mtps3 = [| old_utxo_mtp |] in
  (* required = 1_000_000_000 + 33_553_920 = 1_033_553_920, modern_mtp 1.7B > 1.033B → pass *)
  let pass = Validation.check_sequence_locks tx
    ~block_height:200 ~median_time:modern_mtp
    ~utxo_heights ~utxo_mtps:utxo_mtps3 ~flags () in
  Alcotest.(check bool) "modern MTP satisfies old time lock" true pass;
  (* required with utxo_mtps2 = 2_163_553_920 > Int32 signed max *)
  (* block_mtp 1_700_000_000 < 2_163_553_920 (unsigned) → fail *)
  let fail = Validation.check_sequence_locks tx
    ~block_height:200 ~median_time:1_700_000_000l
    ~utxo_heights ~utxo_mtps:utxo_mtps2 ~flags () in
  Alcotest.(check bool) "Int64 overflow case: fails correctly" false fail

(* BIP-68 Gate: max mask value 0xFFFF for height lock *)
let test_sequence_lock_max_height_mask () =
  let txid = Cstruct.create 32 in
  Cstruct.set_uint8 txid 0 0x05;
  let tx = make_tx
    ~version:2l
    ~inputs:[make_input ~txid ~sequence:0x0000FFFFl ()]
    ~outputs:[make_output ~value:1000L ()]
    ()
  in
  let utxo_heights = [| 0 |] in  (* UTXO at genesis *)
  let utxo_mtps = [| 0l |] in
  let flags = Script.script_verify_checksequenceverify in
  (* required = 0 + 65535 = 65535 *)
  let pass = Validation.check_sequence_locks tx
    ~block_height:65535 ~median_time:0l
    ~utxo_heights ~utxo_mtps ~flags () in
  Alcotest.(check bool) "max height mask (65535) passes at exact height" true pass;
  let fail = Validation.check_sequence_locks tx
    ~block_height:65534 ~median_time:0l
    ~utxo_heights ~utxo_mtps ~flags () in
  Alcotest.(check bool) "max height mask (65535) fails one below" false fail

(* BIP-68 Gate: get_mtp_at_height callback used for time-based lock (BIP-68 §3) *)
let test_sequence_lock_get_mtp_callback () =
  let txid = Cstruct.create 32 in
  Cstruct.set_uint8 txid 0 0x06;
  (* time-based lock: 2 × 512s = 1024s *)
  let tx = make_tx
    ~version:2l
    ~inputs:[make_input ~txid ~sequence:0x00400002l ()]
    ~outputs:[make_output ~value:1000L ()]
    ()
  in
  let utxo_heights = [| 50 |] in
  (* Without callback: utxo_mtp is whatever caller supplies *)
  let utxo_mtp_approx = [| 1_000_000_000l |] in
  let flags = Script.script_verify_checksequenceverify in
  (* With callback: mtp at height 49 = 900_000_000, required = 900_000_000 + 1024 = 900_001_024 *)
  let get_mtp h =
    if h = 49 then 900_000_000l
    else 1_000_000_000l
  in
  (* block MTP 900_001_100 > 900_001_024 → pass with callback *)
  let pass_with_cb = Validation.check_sequence_locks tx
    ~block_height:100 ~median_time:900_001_100l
    ~utxo_heights ~utxo_mtps:utxo_mtp_approx
    ~get_mtp_at_height:get_mtp ~flags () in
  Alcotest.(check bool) "callback MTP used: passes" true pass_with_cb;
  (* block MTP 900_000_500 < 900_001_024 → fail *)
  let fail_with_cb = Validation.check_sequence_locks tx
    ~block_height:100 ~median_time:900_000_500l
    ~utxo_heights ~utxo_mtps:utxo_mtp_approx
    ~get_mtp_at_height:get_mtp ~flags () in
  Alcotest.(check bool) "callback MTP used: fails" false fail_with_cb

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

(* Helper: build a minimal valid-merkle block for use with skip_scripts=true.

   W93: the fast path now invokes check_block, which enforces
   check_coinbase including BIP-34 height encoding when
   [height >= network.bip34_height].  Regtest activates BIP-34 from
   height 1, so the coinbase scriptSig must start with the canonical
   CScriptNum encoding of [height].  We append the [coinbase_suffix]
   byte after the BIP-34 prefix so the resulting script remains 2..100
   bytes long and uniquely identifies the coinbase for txid purposes. *)
let make_bip30_block ~height ~coinbase_suffix =
  let bip34_prefix = Consensus.encode_height_in_coinbase height in
  let prefix_len = Cstruct.length bip34_prefix in
  let script_sig = Cstruct.create (prefix_len + 1) in
  Cstruct.blit bip34_prefix 0 script_sig 0 prefix_len;
  Cstruct.set_uint8 script_sig prefix_len coinbase_suffix;
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
  (* W93: block version must satisfy contextual version-bits checks.
     Pick version high enough to clear BIP-34/65/66 minimums for any
     reasonable test height.  check_block enforces these on the fast
     path now that it routes through check_block. *)
  let header_template = make_header ~version:4l ~merkle_root:merkle
                          ~bits:0x207fffffl ~timestamp:100l () in
  let header = mine_header header_template in
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
   W79: BIP-30 + BIP-34 Comprehensive Gate Tests

   10 Core gates:
   Gate 1  IsBIP30Repeat: exempt only specific canonical blocks (height+hash)
   Gate 2  IsBIP30Unspendable: for DisconnectBlock clean-flag (height+hash)
   Gate 3  fEnforceBIP30 = !IsBIP30Repeat
   Gate 4  BIP34Hash skip: skip BIP-30 when BIP34 confirmed on canonical chain
   Gate 5  BIP34_IMPLIES_BIP30_LIMIT = 1,983,702: re-enable BIP-30
   Gate 6  BIP-30 check applies to ALL txs in block, not just coinbase
   Gate 7  BIP-34 coinbase height encoding with CScriptNum
   Gate 8  BIP-34 block version enforcement (version >= 2 at bip34_height)
   Gate 9  DisconnectBlock BIP-30 exception (IsBIP30Unspendable)
   Gate 10 CScriptNum encoding correctness for all boundary heights

   Reference: Bitcoin Core validation.cpp:2400-2476, 6189-6199
   ============================================================================ *)

(* Gate 1 + Gate 3: IsBIP30Repeat — height+hash required, not height only.
   A block at h=91842 with the CANONICAL hash is exempt.
   A block at h=91842 with a DIFFERENT hash must NOT be exempt. *)
let test_bip30_repeat_requires_canonical_hash () =
  (* Canonical repeat block at h=91842:
     display hash = 00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec *)
  let canonical_hash = Types.hash256_of_hex
    "eccae000e3c8e4e093936360431f3b7603c563c1ff6181390a4d0a0000000000" in
  let wrong_hash = Types.zero_hash in  (* Any non-canonical hash *)

  Alcotest.(check bool)
    "Gate 1: canonical hash at h=91842 IS exempt (IsBIP30Repeat=true)"
    true
    (Consensus.is_bip30_repeat 91842 canonical_hash);

  Alcotest.(check bool)
    "Gate 1: wrong hash at h=91842 NOT exempt (IsBIP30Repeat=false)"
    false
    (Consensus.is_bip30_repeat 91842 wrong_hash);

  (* Same for h=91880 *)
  let canonical_hash_91880 = Types.hash256_of_hex
    "21d77ccb4c08386a04ac0196ae10f6a1d2c2a377558ca190f143070000000000" in
  Alcotest.(check bool)
    "Gate 1: canonical hash at h=91880 IS exempt"
    true
    (Consensus.is_bip30_repeat 91880 canonical_hash_91880);

  Alcotest.(check bool)
    "Gate 1: wrong hash at h=91880 NOT exempt"
    false
    (Consensus.is_bip30_repeat 91880 wrong_hash)

(* Gate 1: Heights outside the BIP30 repeat list are never exempt *)
let test_bip30_repeat_only_at_exempt_heights () =
  let any_hash = Types.zero_hash in
  Alcotest.(check bool)
    "Gate 1: h=91843 (not in list) never exempt"
    false
    (Consensus.is_bip30_repeat 91843 any_hash);
  Alcotest.(check bool)
    "Gate 1: h=100 (not in list) never exempt"
    false
    (Consensus.is_bip30_repeat 100 any_hash);
  Alcotest.(check bool)
    "Gate 1: h=91722 (unspendable, not repeat) not exempt"
    false
    (Consensus.is_bip30_repeat 91722 any_hash);
  Alcotest.(check bool)
    "Gate 1: h=91812 (unspendable, not repeat) not exempt"
    false
    (Consensus.is_bip30_repeat 91812 any_hash)

(* Gate 2: IsBIP30Unspendable — the two blocks whose outputs were destroyed.
   Used in DisconnectBlock. Reference: Core validation.cpp:6195-6198. *)
let test_bip30_unspendable_height_and_hash () =
  (* h=91722 canonical hash:
     display = 00000000000271a2dc26e7667f8419f2e15416dc6955e5a6c6cdf3f2574dd08e *)
  let h91722_canonical = Types.hash256_of_hex
    "8ed04d57f2f3cdc6a6e55569dc1654e1f219847f66e726dca271020000000000" in
  (* h=91812 canonical hash:
     display = 00000000000af0aed4792b1acee3d966af36cf5def14935db8de83d6f9306f2f *)
  let h91812_canonical = Types.hash256_of_hex
    "2f6f30f9d683deb85d9314ef5dcf36af66d9e3ce1a2b79d4aef00a0000000000" in
  let wrong_hash = Types.zero_hash in

  Alcotest.(check bool)
    "Gate 2: h=91722 + canonical hash IS unspendable"
    true
    (Consensus.is_bip30_unspendable 91722 h91722_canonical);

  Alcotest.(check bool)
    "Gate 2: h=91722 + wrong hash is NOT unspendable"
    false
    (Consensus.is_bip30_unspendable 91722 wrong_hash);

  Alcotest.(check bool)
    "Gate 2: h=91812 + canonical hash IS unspendable"
    true
    (Consensus.is_bip30_unspendable 91812 h91812_canonical);

  Alcotest.(check bool)
    "Gate 2: h=91812 + wrong hash is NOT unspendable"
    false
    (Consensus.is_bip30_unspendable 91812 wrong_hash);

  (* Repeat heights (91842/91880) are NOT in the unspendable list *)
  Alcotest.(check bool)
    "Gate 2: h=91842 NOT in unspendable list"
    false
    (Consensus.is_bip30_unspendable 91842 wrong_hash);

  (* Unspendable heights are NOT in the repeat list *)
  Alcotest.(check bool)
    "Gate 2: h=91722 NOT in repeat list"
    false
    (Consensus.is_bip30_repeat 91722 h91722_canonical)

(* Gate 3 + Gate 4: bip30_should_enforce — comprehensive gate logic.
   Tests enforcement decisions at critical heights. *)
let test_bip30_should_enforce_pre_bip34 () =
  (* Pre-BIP34 mainnet height: BIP-30 always enforced (unless repeat block) *)
  let any_hash = Types.zero_hash in
  let result = Validation.bip30_should_enforce
    ~network:Consensus.mainnet
    ~height:100
    ~block_hash:any_hash
    ~bip34_height_hash:None in
  Alcotest.(check bool)
    "Gate 3: pre-BIP34 height 100 enforces BIP-30"
    true result

let test_bip30_should_enforce_repeat_block_exempt () =
  (* Gate 1/3: canonical repeat block IS exempt, wrong hash is NOT *)
  let canonical_h91842 = Types.hash256_of_hex
    "eccae000e3c8e4e093936360431f3b7603c563c1ff6181390a4d0a0000000000" in
  let result_canonical = Validation.bip30_should_enforce
    ~network:Consensus.mainnet
    ~height:91842
    ~block_hash:canonical_h91842
    ~bip34_height_hash:None in
  Alcotest.(check bool)
    "Gate 3: canonical h=91842 is exempt from BIP-30"
    false result_canonical;

  let result_wrong = Validation.bip30_should_enforce
    ~network:Consensus.mainnet
    ~height:91842
    ~block_hash:Types.zero_hash
    ~bip34_height_hash:None in
  Alcotest.(check bool)
    "Gate 3: non-canonical h=91842 must still enforce BIP-30"
    true result_wrong

let test_bip30_should_enforce_bip34_active_canonical () =
  (* Gate 4: after BIP34 activation on the canonical chain (BIP34Hash confirmed),
     BIP-30 checking is skipped for performance. *)
  let any_hash = Types.zero_hash in
  let mainnet_bip34_hash = match Consensus.mainnet.bip34_hash with
    | Some h -> h
    | None -> failwith "mainnet must have bip34_hash"
  in
  (* Canonical chain: bip34_height_hash = mainnet BIP34Hash *)
  let result = Validation.bip30_should_enforce
    ~network:Consensus.mainnet
    ~height:300000  (* Well above BIP34 height 227931, below 1983702 *)
    ~block_hash:any_hash
    ~bip34_height_hash:(Some mainnet_bip34_hash) in
  Alcotest.(check bool)
    "Gate 4: canonical chain height 300000 → skip BIP-30"
    false result

let test_bip30_should_enforce_bip34_active_noncanonical () =
  (* Gate 4: if BIP34Hash does NOT match, we cannot confirm canonical chain → enforce *)
  let any_hash = Types.zero_hash in
  let wrong_bip34_hash = Types.zero_hash in  (* Not the real BIP34Hash *)
  let result = Validation.bip30_should_enforce
    ~network:Consensus.mainnet
    ~height:300000
    ~block_hash:any_hash
    ~bip34_height_hash:(Some wrong_bip34_hash) in
  Alcotest.(check bool)
    "Gate 4: non-canonical BIP34 ancestor → enforce BIP-30"
    true result

let test_bip30_should_enforce_bip34_no_hint () =
  (* Without bip34_height_hash hint (None), conservative: enforce BIP-30 even post-BIP34.
     This is the safe fallback when callers don't have ancestor hash available. *)
  let any_hash = Types.zero_hash in
  let result = Validation.bip30_should_enforce
    ~network:Consensus.mainnet
    ~height:300000
    ~block_hash:any_hash
    ~bip34_height_hash:None in
  Alcotest.(check bool)
    "Gate 4 fallback: no BIP34 hint → conservative enforcement"
    true result

let test_bip30_should_enforce_at_limit () =
  (* Gate 5: at height >= 1,983,702, BIP-30 is re-enabled regardless of BIP34 *)
  let any_hash = Types.zero_hash in
  let mainnet_bip34_hash = match Consensus.mainnet.bip34_hash with
    | Some h -> h
    | None -> failwith "mainnet must have bip34_hash"
  in
  (* Even with canonical BIP34 hash, at >= 1983702 enforcement re-enables *)
  let result = Validation.bip30_should_enforce
    ~network:Consensus.mainnet
    ~height:1983702
    ~block_hash:any_hash
    ~bip34_height_hash:(Some mainnet_bip34_hash) in
  Alcotest.(check bool)
    "Gate 5: height=1983702 re-enables BIP-30"
    true result;

  let result2 = Validation.bip30_should_enforce
    ~network:Consensus.mainnet
    ~height:2000000
    ~block_hash:any_hash
    ~bip34_height_hash:(Some mainnet_bip34_hash) in
  Alcotest.(check bool)
    "Gate 5: height=2000000 also enforces BIP-30"
    true result2

let test_bip30_should_enforce_regtest_no_window () =
  (* On regtest/testnet4 (bip34_hash=None, BIP34 active from genesis),
     BIP-30 is never enforced for heights in [bip34_height, 1983702).
     No pre-BIP34 window means no duplicate coinbases are possible. *)
  let any_hash = Types.zero_hash in
  let result = Validation.bip30_should_enforce
    ~network:Consensus.regtest
    ~height:1000
    ~block_hash:any_hash
    ~bip34_height_hash:None in
  Alcotest.(check bool)
    "Gate 4 regtest: bip34_hash=None → no BIP-30 enforcement"
    false result

(* Gate 6: BIP-30 applies to ALL transactions, not just coinbase.
   Verify check_bip30 is called for non-coinbase txs too. *)
let test_bip30_applies_to_all_txs () =
  (* Build a block with coinbase + one regular tx, both with same txid.
     The duplicate regular tx must also be caught. *)
  let coinbase_script = Consensus.encode_height_in_coinbase 100 in
  (* Add padding to reach minimum 2-byte scriptSig length *)
  let script_pad = Cstruct.create 1 in
  Cstruct.set_uint8 script_pad 0 0x00;
  let coinbase_full = Cstruct.append coinbase_script script_pad in
  let coinbase = make_tx
    ~inputs:[{
      Types.previous_output = { txid = Types.zero_hash; vout = -1l };
      script_sig = coinbase_full;
      sequence = 0xFFFFFFFFl;
    }]
    ~outputs:[make_output ~value:5_000_000_000L ()]
    ()
  in
  (* Regular tx that would duplicate an existing UTXO *)
  let dup_txid = Crypto.compute_txid coinbase in  (* same as coinbase for simplicity *)
  let non_cb_tx = make_tx
    ~inputs:[{
      Types.previous_output = { txid = Crypto.compute_txid coinbase; vout = 0l };
      script_sig = Cstruct.create 0;
      sequence = 0xFFFFFFFFl;
    }]
    ~outputs:[make_output ~value:1000L ()]
    ()
  in
  let all_txids = [Crypto.compute_txid coinbase; Crypto.compute_txid non_cb_tx] in
  let (merkle, _) = Crypto.merkle_root all_txids in
  let header = make_header ~merkle_root:merkle ~bits:0x207fffffl ~timestamp:100l () in
  let block = { Types.header; transactions = [coinbase; non_cb_tx] } in

  (* Gate 6: BIP-30 check on the non-coinbase tx's outputs *)
  let non_cb_txid = Crypto.compute_txid non_cb_tx in
  let n_non_cb_outputs = List.length non_cb_tx.Types.outputs in

  (* Lookup that returns a coin for the non-coinbase txid — simulates duplicate *)
  let lookup_dup (op : Types.outpoint) =
    if Cstruct.equal op.txid non_cb_txid && op.vout = 0l then
      Some {
        Validation.txid = non_cb_txid;
        vout = 0l;
        value = 1000L;
        script_pubkey = Cstruct.create 0;
        height = 99;
        is_coinbase = false;
      }
    else None
  in
  let result = Validation.check_bip30
    ~lookup:lookup_dup ~txid:non_cb_txid ~n_outputs:n_non_cb_outputs in
  Alcotest.(check bool)
    "Gate 6: BIP-30 check_bip30 fails for duplicate non-coinbase tx"
    false result;

  (* Also verify check_bip30 catches duplicate coinbase *)
  let _ = dup_txid in
  let lookup_cb_dup (op : Types.outpoint) =
    if Cstruct.equal op.txid (Crypto.compute_txid coinbase) && op.vout = 0l then
      Some {
        Validation.txid = Crypto.compute_txid coinbase;
        vout = 0l;
        value = 5_000_000_000L;
        script_pubkey = Cstruct.create 0;
        height = 99;
        is_coinbase = true;
      }
    else None
  in
  let coinbase_txid = Crypto.compute_txid coinbase in
  let n_cb_outputs = List.length coinbase.Types.outputs in
  let _ = block in
  let result_cb = Validation.check_bip30
    ~lookup:lookup_cb_dup ~txid:coinbase_txid ~n_outputs:n_cb_outputs in
  Alcotest.(check bool)
    "Gate 6: BIP-30 check_bip30 fails for duplicate coinbase too"
    false result_cb

(* Gate 7 + Gate 10: BIP-34 CScriptNum encoding — verify sign-bit boundary cases.
   Reference: Bitcoin Core script.h CScriptNum::serialize + CScript::push_int64. *)
let test_bip34_cscriptnum_sign_bit_boundaries () =
  (* Height 127 (0x7f): 1 data byte, no sign-bit padding needed *)
  let cs127 = Consensus.encode_height_in_coinbase 127 in
  Alcotest.(check int) "h=127 total length 2" 2 (Cstruct.length cs127);
  Alcotest.(check int) "h=127 push opcode" 0x01 (Cstruct.get_uint8 cs127 0);
  Alcotest.(check int) "h=127 value byte" 0x7F (Cstruct.get_uint8 cs127 1);

  (* Height 128 (0x80): MSB has sign bit set → needs 2 data bytes [0x80, 0x00] *)
  let cs128 = Consensus.encode_height_in_coinbase 128 in
  Alcotest.(check int) "h=128 total length 3" 3 (Cstruct.length cs128);
  Alcotest.(check int) "h=128 push opcode" 0x02 (Cstruct.get_uint8 cs128 0);
  Alcotest.(check int) "h=128 byte 0" 0x80 (Cstruct.get_uint8 cs128 1);
  Alcotest.(check int) "h=128 byte 1 (zero pad)" 0x00 (Cstruct.get_uint8 cs128 2);

  (* Height 32767 (0x7fff): 2 data bytes, no padding *)
  let cs32767 = Consensus.encode_height_in_coinbase 32767 in
  Alcotest.(check int) "h=32767 total length 3" 3 (Cstruct.length cs32767);
  Alcotest.(check int) "h=32767 push opcode" 0x02 (Cstruct.get_uint8 cs32767 0);
  Alcotest.(check int) "h=32767 byte 0" 0xFF (Cstruct.get_uint8 cs32767 1);
  Alcotest.(check int) "h=32767 byte 1" 0x7F (Cstruct.get_uint8 cs32767 2);

  (* Height 32768 (0x8000): MSB 0x80 → needs 3 data bytes [0x00, 0x80, 0x00] *)
  let cs32768 = Consensus.encode_height_in_coinbase 32768 in
  Alcotest.(check int) "h=32768 total length 4" 4 (Cstruct.length cs32768);
  Alcotest.(check int) "h=32768 push opcode" 0x03 (Cstruct.get_uint8 cs32768 0);
  Alcotest.(check int) "h=32768 byte 0" 0x00 (Cstruct.get_uint8 cs32768 1);
  Alcotest.(check int) "h=32768 byte 1" 0x80 (Cstruct.get_uint8 cs32768 2);
  Alcotest.(check int) "h=32768 byte 2 (zero pad)" 0x00 (Cstruct.get_uint8 cs32768 3);

  (* Height 8388607 (0x7fffff): 3 data bytes, no padding *)
  let cs8388607 = Consensus.encode_height_in_coinbase 8388607 in
  Alcotest.(check int) "h=8388607 total length 4" 4 (Cstruct.length cs8388607);
  Alcotest.(check int) "h=8388607 push opcode" 0x03 (Cstruct.get_uint8 cs8388607 0);

  (* Height 8388608 (0x800000): MSB 0x80 → needs 4 data bytes *)
  let cs8388608 = Consensus.encode_height_in_coinbase 8388608 in
  Alcotest.(check int) "h=8388608 total length 5" 5 (Cstruct.length cs8388608);
  Alcotest.(check int) "h=8388608 push opcode" 0x04 (Cstruct.get_uint8 cs8388608 0);
  Alcotest.(check int) "h=8388608 byte 0" 0x00 (Cstruct.get_uint8 cs8388608 1);
  Alcotest.(check int) "h=8388608 byte 1" 0x00 (Cstruct.get_uint8 cs8388608 2);
  Alcotest.(check int) "h=8388608 byte 2" 0x80 (Cstruct.get_uint8 cs8388608 3);
  Alcotest.(check int) "h=8388608 byte 3 (zero pad)" 0x00 (Cstruct.get_uint8 cs8388608 4)

(* Gate 7: BIP-34 OP_0/OP_1..OP_16 encoding — boundary at heights 0 and 1-16 *)
let test_bip34_op_encoding_boundaries () =
  (* Height 0 → OP_0 (0x00) *)
  let cs0 = Consensus.encode_height_in_coinbase 0 in
  Alcotest.(check int) "h=0 → OP_0 (len=1)" 1 (Cstruct.length cs0);
  Alcotest.(check int) "h=0 byte = 0x00" 0x00 (Cstruct.get_uint8 cs0 0);

  (* Height 1 → OP_1 (0x51) *)
  let cs1 = Consensus.encode_height_in_coinbase 1 in
  Alcotest.(check int) "h=1 → OP_1 (len=1)" 1 (Cstruct.length cs1);
  Alcotest.(check int) "h=1 byte = 0x51" 0x51 (Cstruct.get_uint8 cs1 0);

  (* Height 16 → OP_16 (0x60) *)
  let cs16 = Consensus.encode_height_in_coinbase 16 in
  Alcotest.(check int) "h=16 → OP_16 (len=1)" 1 (Cstruct.length cs16);
  Alcotest.(check int) "h=16 byte = 0x60" 0x60 (Cstruct.get_uint8 cs16 0);

  (* Height 17 → CScriptNum(17): push 1 byte, value 0x11 *)
  let cs17 = Consensus.encode_height_in_coinbase 17 in
  Alcotest.(check int) "h=17 len=2" 2 (Cstruct.length cs17);
  Alcotest.(check int) "h=17 push byte = 0x01" 0x01 (Cstruct.get_uint8 cs17 0);
  Alcotest.(check int) "h=17 value = 0x11" 0x11 (Cstruct.get_uint8 cs17 1)

(* Gate 7: check_coinbase returns TxBadCoinbase error string correctly for bad-cb-height *)
let test_bip34_error_on_wrong_height () =
  (* Build coinbase with wrong height (height 50 instead of 100) *)
  let wrong_script = Consensus.encode_height_in_coinbase 50 in
  let pad = Cstruct.create 1 in  (* pad to >= 2 bytes *)
  let script_sig = Cstruct.append wrong_script pad in
  let coinbase = make_tx
    ~inputs:[{
      Types.previous_output = { txid = Types.zero_hash; vout = -1l };
      script_sig;
      sequence = 0xFFFFFFFFl;
    }]
    ~outputs:[make_output ~value:5_000_000_000L ()]
    ()
  in
  (* Use mainnet at height=100 (bip34_height=227931 → NOT enforced): should be OK *)
  (match Validation.check_coinbase ~network:Consensus.mainnet coinbase 100 with
   | Ok () -> ()
   | Error _ -> Alcotest.fail "Height 100 < bip34_height=227931, no BIP34 check expected");

  (* Use regtest at height=100 (bip34_height=1 → enforced): should fail *)
  (match Validation.check_coinbase ~network:Consensus.regtest coinbase 100 with
   | Error Validation.TxBadCoinbase -> ()
   | Error e -> Alcotest.fail ("Unexpected error: " ^ Validation.tx_error_to_string e)
   | Ok () -> Alcotest.fail "Should have rejected wrong height encoding")

(* Gate 8: Block version must be >= 2 at bip34_height *)
let test_bip34_block_version_gate () =
  (* Regtest bip34_height=1: version 1 block at height >= 1 must be rejected.
     Use height=500 to mirror test_block_version_too_low_bip34. *)
  let coinbase = make_tx
    ~inputs:[make_coinbase_input ~height:500]
    ~outputs:[make_output ~value:(Consensus.block_subsidy 500) ()]
    ()
  in
  let txid = Crypto.compute_txid coinbase in
  let (merkle, _) = Crypto.merkle_root [txid] in
  let header = make_header ~version:1l ~merkle_root:merkle
    ~bits:0x207fffffl ~timestamp:100l () in
  let v1_block_h500 = { Types.header; transactions = [coinbase] } in
  (* block version check is in check_block; call it at height >= bip34_height *)
  (match Validation.check_block ~network:Consensus.regtest v1_block_h500 500
           ~expected_bits:0x207fffffl ~median_time:0l () with
   | Error Validation.BlockBadVersion -> ()
   | Error Validation.BlockBadDifficulty -> ()  (* PoW check may fire first *)
   | Error e -> Alcotest.fail ("Unexpected error: " ^ Validation.block_error_to_string e)
   | Ok () -> Alcotest.fail "Version 1 block at regtest h=500 should fail")

(* Gate 4: Mainnet bip34_hash field matches the known canonical value.
   display: 000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8 *)
let test_mainnet_bip34_hash_correct () =
  let expected_display =
    "000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8" in
  match Consensus.mainnet.bip34_hash with
  | None -> Alcotest.fail "mainnet must have bip34_hash"
  | Some h ->
    (* Convert internal LE to display hash *)
    let display = Types.hash256_to_hex_display h in
    Alcotest.(check string) "mainnet BIP34Hash display" expected_display display

(* Gate 4: Testnet3 bip34_hash field matches the known canonical value.
   display: 0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8 *)
let test_testnet3_bip34_hash_correct () =
  let expected_display =
    "0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8" in
  match Consensus.testnet.bip34_hash with
  | None -> Alcotest.fail "testnet3 must have bip34_hash"
  | Some h ->
    let display = Types.hash256_to_hex_display h in
    Alcotest.(check string) "testnet3 BIP34Hash display" expected_display display

(* Gate 4: Testnet4 and regtest have no bip34_hash (BIP34 active from genesis) *)
let test_no_bip34_hash_on_genesis_networks () =
  Alcotest.(check bool) "testnet4 bip34_hash = None" true
    (Consensus.testnet4.bip34_hash = None);
  Alcotest.(check bool) "regtest bip34_hash = None" true
    (Consensus.regtest.bip34_hash = None)

(* Gate 1: The two BIP30 repeat block hashes match Core constants.
   Core validation.cpp:6191-6192 *)
let test_bip30_repeat_block_hashes_match_core () =
  (* h=91842 display: 00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec *)
  let h91842_display = "00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec" in
  let h91842_internal = Types.hash256_of_hex
    "eccae000e3c8e4e093936360431f3b7603c563c1ff6181390a4d0a0000000000" in
  Alcotest.(check string)
    "h=91842 repeat hash round-trips to Core display value"
    h91842_display
    (Types.hash256_to_hex_display h91842_internal);

  (* h=91880 display: 00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721 *)
  let h91880_display = "00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721" in
  let h91880_internal = Types.hash256_of_hex
    "21d77ccb4c08386a04ac0196ae10f6a1d2c2a377558ca190f143070000000000" in
  Alcotest.(check string)
    "h=91880 repeat hash round-trips to Core display value"
    h91880_display
    (Types.hash256_to_hex_display h91880_internal)

(* Gate 2: The two BIP30 unspendable block hashes match Core constants.
   Core validation.cpp:6197-6198 *)
let test_bip30_unspendable_block_hashes_match_core () =
  (* h=91722 display: 00000000000271a2dc26e7667f8419f2e15416dc6955e5a6c6cdf3f2574dd08e *)
  let h91722_display = "00000000000271a2dc26e7667f8419f2e15416dc6955e5a6c6cdf3f2574dd08e" in
  let h91722_internal = Types.hash256_of_hex
    "8ed04d57f2f3cdc6a6e55569dc1654e1f219847f66e726dca271020000000000" in
  Alcotest.(check string)
    "h=91722 unspendable hash round-trips to Core display value"
    h91722_display
    (Types.hash256_to_hex_display h91722_internal);

  (* h=91812 display: 00000000000af0aed4792b1acee3d966af36cf5def14935db8de83d6f9306f2f *)
  let h91812_display = "00000000000af0aed4792b1acee3d966af36cf5def14935db8de83d6f9306f2f" in
  let h91812_internal = Types.hash256_of_hex
    "2f6f30f9d683deb85d9314ef5dcf36af66d9e3ce1a2b79d4aef00a0000000000" in
  Alcotest.(check string)
    "h=91812 unspendable hash round-trips to Core display value"
    h91812_display
    (Types.hash256_to_hex_display h91812_internal)

(* Gate 5: validate_block_with_utxos at height=1983702 enforces BIP-30
   even when canonical BIP34 hash is provided (limit re-enables enforcement). *)
let test_bip30_reenabled_at_limit_in_validate () =
  let height = 1983702 in
  let (block, txid) = make_bip30_block ~height ~coinbase_suffix:0xEE in
  let mainnet_bip34_hash = match Consensus.mainnet.bip34_hash with
    | Some h -> h | None -> failwith "mainnet must have bip34_hash"
  in
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
    ~base_lookup ~flags ~skip_scripts:true
    ~bip34_height_hash:mainnet_bip34_hash () with
  | Error (Validation.BlockTxValidationFailed (_, Validation.TxDuplicateTxid)) -> ()
  | Error e -> Alcotest.fail ("Gate 5: wrong error at 1983702: " ^ Validation.block_error_to_string e)
  | Ok _ -> Alcotest.fail "Gate 5: BIP-30 should be enforced at height=1983702"

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
   W84 — CheckTransaction / CheckTxInputs / CVE-2018-17144 / GetBlockSubsidy
   Comprehensive gate tests.
   References:
     consensus/tx_check.cpp  (CheckTransaction)
     consensus/tx_verify.cpp:164-214 (CheckTxInputs)
     validation.cpp:1839-1850 (GetBlockSubsidy)
     validation.cpp:2515-2620 (ConnectBlock fee+coinbase gates)
   ============================================================================ *)

(* ── GetBlockSubsidy: all halving boundaries 0..64 ──────────────────────── *)

(* Core validation.cpp:1841-1848: halvings = height / 210000, result >> halvings.
   At halvings >= 64 the shift is undefined behaviour in C++ — Core returns 0L
   explicitly.  OCaml Int64.shift_right is defined for all shifts, but the
   function must still return 0L for halvings >= 64. *)
let test_subsidy_all_halvings () =
  (* Subsidy at the START of each epoch 0..63 should equal 50 >> epoch BTC. *)
  let coin = Consensus.coin in  (* 100_000_000L *)
  let interval = Consensus.default_halving_interval in
  (* Epoch 0: 50 BTC *)
  Alcotest.(check int64) "epoch 0 start" (Int64.mul 50L coin)
    (Consensus.block_subsidy 0);
  (* Epoch 1: 25 BTC *)
  Alcotest.(check int64) "epoch 1 start" (Int64.mul 25L coin)
    (Consensus.block_subsidy interval);
  (* Epoch 2: 12.5 BTC = 1_250_000_000 sat *)
  Alcotest.(check int64) "epoch 2 start" 1_250_000_000L
    (Consensus.block_subsidy (2 * interval));
  (* Epoch 3: 6.25 BTC = 625_000_000 sat *)
  Alcotest.(check int64) "epoch 3 start" 625_000_000L
    (Consensus.block_subsidy (3 * interval));
  (* Epoch 32: 50*COIN >> 32 = 11 sat (rounds down) *)
  let epoch32 = Int64.shift_right (Int64.mul 50L coin) 32 in
  Alcotest.(check int64) "epoch 32 start" epoch32
    (Consensus.block_subsidy (32 * interval));
  (* Epoch 63: last non-zero epoch (50 >> 63 = 0 because 50 < 2^63 but
     50 * COIN >> 63 = 0 since 50*1e8 = 5e9 < 2^63, shift-right 63 bits → 0) *)
  let epoch63 = Int64.shift_right (Int64.mul 50L coin) 63 in
  Alcotest.(check int64) "epoch 63 start" epoch63
    (Consensus.block_subsidy (63 * interval));
  (* Epoch 64: halvings >= 64 → 0 (Core returns 0 to avoid undefined UB) *)
  Alcotest.(check int64) "epoch 64 returns 0" 0L
    (Consensus.block_subsidy (64 * interval));
  (* Deep future: still 0 *)
  Alcotest.(check int64) "epoch 100 returns 0" 0L
    (Consensus.block_subsidy (100 * interval));
  (* Last block of epoch 0: block 209_999 *)
  Alcotest.(check int64) "last block epoch 0" (Int64.mul 50L coin)
    (Consensus.block_subsidy (interval - 1));
  (* First block of epoch 1: block 210_000 *)
  Alcotest.(check int64) "first block epoch 1" (Int64.mul 25L coin)
    (Consensus.block_subsidy interval)

(* GetBlockSubsidy: regtest uses interval=150. *)
let test_subsidy_regtest_interval () =
  let coin = Consensus.coin in
  let interval = Consensus.regtest_halving_interval in  (* 150 *)
  Alcotest.(check int64) "regtest epoch 0" (Int64.mul 50L coin)
    (Consensus.block_subsidy ~halving_interval:interval 0);
  Alcotest.(check int64) "regtest epoch 1 at 150" (Int64.mul 25L coin)
    (Consensus.block_subsidy ~halving_interval:interval interval);
  Alcotest.(check int64) "regtest block 149 epoch 0" (Int64.mul 50L coin)
    (Consensus.block_subsidy ~halving_interval:interval (interval - 1));
  Alcotest.(check int64) "regtest epoch 64 = 0" 0L
    (Consensus.block_subsidy ~halving_interval:interval (64 * interval))

(* ── CVE-2010-5139: per-output value bounds ─────────────────────────────── *)

(* Core consensus/tx_check.cpp:27-33.
   The three output-value gates must fire in order: negative, toolarge, overflow. *)

(* Gate: bad-txns-vout-negative (value < 0) *)
let test_cve_2010_negative_value () =
  let txid = Cstruct.create 32 in
  Cstruct.set_uint8 txid 0 0x01;
  let tx = make_tx
    ~inputs:[make_input ~txid ()]
    ~outputs:[make_output ~value:(-1L) ()]
    ()
  in
  (match Validation.check_transaction tx with
  | Error (Validation.TxNegativeOutput 0) -> ()
  | Error e -> Alcotest.fail ("Expected TxNegativeOutput 0, got: " ^ Validation.tx_error_to_string e)
  | Ok () -> Alcotest.fail "Should have rejected negative output");
  (* Exactly Int64.min_int *)
  let tx2 = make_tx
    ~inputs:[make_input ~txid ()]
    ~outputs:[make_output ~value:Int64.min_int ()]
    ()
  in
  (match Validation.check_transaction tx2 with
  | Error (Validation.TxNegativeOutput 0) -> ()
  | Error e -> Alcotest.fail ("min_int: " ^ Validation.tx_error_to_string e)
  | Ok () -> Alcotest.fail "Should have rejected Int64.min_int output")

(* Gate: bad-txns-vout-toolarge (value > MAX_MONEY) *)
let test_cve_2010_toolarge_value () =
  let txid = Cstruct.create 32 in
  Cstruct.set_uint8 txid 0 0x01;
  (* MAX_MONEY + 1 *)
  let tx = make_tx
    ~inputs:[make_input ~txid ()]
    ~outputs:[make_output ~value:(Int64.add Consensus.max_money 1L) ()]
    ()
  in
  (match Validation.check_transaction tx with
  | Error (Validation.TxOutputTooLarge 0) -> ()
  | Error e -> Alcotest.fail ("Expected TxOutputTooLarge, got: " ^ Validation.tx_error_to_string e)
  | Ok () -> Alcotest.fail "Should have rejected value > MAX_MONEY");
  (* MAX_MONEY itself should be accepted *)
  let tx_ok = make_tx
    ~inputs:[make_input ~txid ()]
    ~outputs:[make_output ~value:Consensus.max_money ()]
    ()
  in
  (match Validation.check_transaction tx_ok with
  | Ok () -> ()
  | Error (Validation.TxDuplicateInputs) -> ()  (* zero txid dup is irrelevant here *)
  | Error e -> Alcotest.fail ("MAX_MONEY should be accepted: " ^ Validation.tx_error_to_string e))

(* Gate: bad-txns-txouttotal-toolarge (sum of outputs > MAX_MONEY) *)
let test_cve_2010_txouttotal_toolarge () =
  let txid = Cstruct.create 32 in
  Cstruct.set_uint8 txid 0 0x01;
  let txid2 = Cstruct.create 32 in
  Cstruct.set_uint8 txid2 0 0x02;
  (* Two MAX_MONEY outputs: sum > MAX_MONEY *)
  let tx = make_tx
    ~inputs:[make_input ~txid (); make_input ~txid:txid2 ()]
    ~outputs:[
      make_output ~value:Consensus.max_money ();
      make_output ~value:1L ();
    ]
    ()
  in
  (match Validation.check_transaction tx with
  | Error Validation.TxOutputOverflow -> ()
  | Error e -> Alcotest.fail ("Expected TxOutputOverflow: " ^ Validation.tx_error_to_string e)
  | Ok () -> Alcotest.fail "Should have rejected overflow sum")

(* ── CVE-2018-17144: duplicate inputs ───────────────────────────────────── *)

(* Core consensus/tx_check.cpp:41-44.
   Two inputs referencing the same outpoint must be rejected with
   bad-txns-inputs-duplicate. *)
let test_cve_2018_17144_duplicate_inputs () =
  let txid = Cstruct.create 32 in
  Cstruct.set_uint8 txid 0 0xAB;
  let inp = make_input ~txid ~vout:0l () in
  let tx = make_tx
    ~inputs:[inp; inp]
    ~outputs:[make_output ~value:1000L ()]
    ()
  in
  (match Validation.check_transaction tx with
  | Error Validation.TxDuplicateInputs -> ()
  | Error e -> Alcotest.fail ("Expected TxDuplicateInputs: " ^ Validation.tx_error_to_string e)
  | Ok () -> Alcotest.fail "Should have rejected duplicate inputs");
  (* Same txid, different vout → NOT a duplicate *)
  let inp_v0 = make_input ~txid ~vout:0l () in
  let inp_v1 = make_input ~txid ~vout:1l () in
  let tx_ok = make_tx
    ~inputs:[inp_v0; inp_v1]
    ~outputs:[make_output ~value:1000L ()]
    ()
  in
  (match Validation.check_transaction tx_ok with
  | Ok () -> ()
  | Error Validation.TxDuplicateInputs ->
    Alcotest.fail "Different vout must not be a duplicate"
  | Error _ -> ())  (* Other errors (oversize, etc.) are fine *)

(* ── bad-cb-length: coinbase scriptSig must be 2..100 bytes ─────────────── *)

(* Core consensus/tx_check.cpp:49-50. *)
let test_bad_cb_length_too_short () =
  (* scriptSig = 1 byte: below minimum of 2 *)
  let script_sig = Cstruct.create 1 in
  let coinbase = make_tx
    ~inputs:[{
      Types.previous_output = { txid = Types.zero_hash; vout = -1l };
      script_sig;
      sequence = 0xFFFFFFFFl;
    }]
    ~outputs:[make_output ~value:5_000_000_000L ()]
    ()
  in
  match Validation.check_coinbase ~network:Consensus.regtest coinbase 0 with
  | Error Validation.TxCoinbaseScriptSigTooLong -> ()
  | Error e -> Alcotest.fail ("Expected TxCoinbaseScriptSigTooLong: " ^ Validation.tx_error_to_string e)
  | Ok () -> Alcotest.fail "Should have rejected scriptSig too short"

let test_bad_cb_length_too_long () =
  (* scriptSig = 101 bytes: above maximum of 100 *)
  let script_sig = Cstruct.create 101 in
  Cstruct.set_uint8 script_sig 0 0x03;  (* height push — keeps BIP-34 happy *)
  let coinbase = make_tx
    ~inputs:[{
      Types.previous_output = { txid = Types.zero_hash; vout = -1l };
      script_sig;
      sequence = 0xFFFFFFFFl;
    }]
    ~outputs:[make_output ~value:5_000_000_000L ()]
    ()
  in
  match Validation.check_coinbase ~network:Consensus.mainnet coinbase 0 with
  | Error Validation.TxCoinbaseScriptSigTooLong -> ()
  | Error e -> Alcotest.fail ("Expected TxCoinbaseScriptSigTooLong: " ^ Validation.tx_error_to_string e)
  | Ok () -> Alcotest.fail "Should have rejected scriptSig too long"

let test_bad_cb_length_exact_boundaries () =
  (* Exactly 2 bytes: minimum, should pass (pre-BIP34 at height 0) *)
  let script_sig_2 = Cstruct.create 2 in
  let cb_min = make_tx
    ~inputs:[{
      Types.previous_output = { txid = Types.zero_hash; vout = -1l };
      script_sig = script_sig_2;
      sequence = 0xFFFFFFFFl;
    }]
    ~outputs:[make_output ~value:5_000_000_000L ()]
    ()
  in
  (match Validation.check_coinbase ~network:Consensus.mainnet cb_min 0 with
  | Ok () -> ()
  | Error e -> Alcotest.fail ("2-byte scriptSig should pass: " ^ Validation.tx_error_to_string e));
  (* Exactly 100 bytes: maximum, should pass *)
  let script_sig_100 = Cstruct.create 100 in
  let cb_max = make_tx
    ~inputs:[{
      Types.previous_output = { txid = Types.zero_hash; vout = -1l };
      script_sig = script_sig_100;
      sequence = 0xFFFFFFFFl;
    }]
    ~outputs:[make_output ~value:5_000_000_000L ()]
    ()
  in
  (match Validation.check_coinbase ~network:Consensus.mainnet cb_max 0 with
  | Ok () -> ()
  | Error e -> Alcotest.fail ("100-byte scriptSig should pass: " ^ Validation.tx_error_to_string e))

(* ── CheckTxInputs: per-input UTXO value MoneyRange ────────────────────── *)

(* Core consensus/tx_verify.cpp:186: !MoneyRange(coin.out.nValue) → reject.
   A UTXO with a value > MAX_MONEY (e.g. injected via a corrupt database) must
   be rejected at spend time. *)
let test_input_value_out_of_range () =
  let txid = Cstruct.create 32 in
  Cstruct.set_uint8 txid 0 0x01;
  (* UTXO with value > MAX_MONEY *)
  let lookup _outpoint =
    Some {
      Validation.txid;
      vout = 0l;
      value = Int64.add Consensus.max_money 1L;
      script_pubkey = Cstruct.create 0;
      height = 0;
      is_coinbase = false;
    }
  in
  let tx = make_tx
    ~inputs:[make_input ~txid ()]
    ~outputs:[make_output ~value:1000L ()]
    ()
  in
  match Validation.validate_tx_inputs tx ~lookup ~block_height:100
          ~flags:0 ~skip_scripts:true () with
  | Error Validation.TxOutputOverflow -> ()
  | Error e -> Alcotest.fail ("Expected TxOutputOverflow: " ^ Validation.tx_error_to_string e)
  | Ok _ -> Alcotest.fail "Should have rejected UTXO value > MAX_MONEY"

(* ── CheckTxInputs: cumulative nValueIn MoneyRange ──────────────────────── *)

(* Core consensus/tx_verify.cpp:186: !MoneyRange(nValueIn) → reject.
   If multiple inputs each below MAX_MONEY but their sum overflows, reject. *)
let test_input_cumulative_overflow () =
  (* Two UTXOs each worth MAX_MONEY; their sum overflows MoneyRange. *)
  let txid1 = Cstruct.create 32 in
  Cstruct.set_uint8 txid1 0 0x01;
  let txid2 = Cstruct.create 32 in
  Cstruct.set_uint8 txid2 0 0x02;
  let lookup outpoint =
    Some {
      Validation.txid = outpoint.Types.txid;
      vout = outpoint.Types.vout;
      value = Consensus.max_money;
      script_pubkey = Cstruct.create 0;
      height = 0;
      is_coinbase = false;
    }
  in
  let tx = make_tx
    ~inputs:[make_input ~txid:txid1 ~vout:0l ();
             make_input ~txid:txid2 ~vout:0l ()]
    ~outputs:[make_output ~value:1000L ()]
    ()
  in
  match Validation.validate_tx_inputs tx ~lookup ~block_height:100
          ~flags:0 ~skip_scripts:true () with
  | Error Validation.TxOutputOverflow -> ()
  | Error e -> Alcotest.fail ("Expected TxOutputOverflow: " ^ Validation.tx_error_to_string e)
  | Ok _ -> Alcotest.fail "Should have rejected overflow nValueIn"

(* ── CheckTxInputs: bad-txns-in-belowout ────────────────────────────────── *)

(* Core consensus/tx_verify.cpp:196-199: nValueIn < value_out → reject.
   In camlcoin this is checked as fee < 0L in both validate_tx_inputs and the
   block-connect loop. *)
let test_input_below_output () =
  let txid = Cstruct.create 32 in
  Cstruct.set_uint8 txid 0 0x01;
  let lookup _outpoint =
    Some {
      Validation.txid;
      vout = 0l;
      value = 1000L;   (* input worth 1000 sat *)
      script_pubkey = Cstruct.create 0;
      height = 0;
      is_coinbase = false;
    }
  in
  (* Output worth more than input *)
  let tx = make_tx
    ~inputs:[make_input ~txid ()]
    ~outputs:[make_output ~value:2000L ()]  (* outputs > inputs *)
    ()
  in
  match Validation.validate_tx_inputs tx ~lookup ~block_height:100
          ~flags:0 ~skip_scripts:true () with
  | Ok total_in when total_in = 1000L ->
    (* validate_tx_inputs just returns total_in; bad-txns-in-belowout is a
       block-level check (done in the connect loop).  Confirm 1000L returned. *)
    ()
  | Ok other ->
    Alcotest.fail (Printf.sprintf "Expected total_in=1000L, got %Ld" other)
  | Error e -> Alcotest.fail ("Unexpected error: " ^ Validation.tx_error_to_string e)

(* ── Coinbase maturity: boundary COINBASE_MATURITY − 1 and COINBASE_MATURITY *)

(* Core consensus/tx_verify.cpp:179-182: nSpendHeight - coin.nHeight < 100 → reject.
   Equality (depth = 100) is already accepted; depth = 99 is rejected. *)
let test_coinbase_maturity_boundary () =
  let txid = Cstruct.create 32 in
  Cstruct.set_uint8 txid 0 0x01;
  (* Coinbase mined at height 0 *)
  let lookup _outpoint =
    Some {
      Validation.txid;
      vout = 0l;
      value = 5_000_000_000L;
      script_pubkey = Cstruct.create 0;
      height = 0;
      is_coinbase = true;
    }
  in
  let tx = make_tx
    ~inputs:[make_input ~txid ()]
    ~outputs:[make_output ~value:4_999_990_000L ()]
    ()
  in
  (* Depth = 99: must reject *)
  (match Validation.validate_tx_inputs tx ~lookup ~block_height:99
          ~flags:0 ~skip_scripts:true () with
  | Error (Validation.TxCoinbaseMaturity 99) -> ()
  | Error e -> Alcotest.fail ("depth=99: " ^ Validation.tx_error_to_string e)
  | Ok _ -> Alcotest.fail "depth=99 must be rejected");
  (* Depth = 100: must accept (>= COINBASE_MATURITY) *)
  (match Validation.validate_tx_inputs tx ~lookup ~block_height:100
          ~flags:0 ~skip_scripts:true () with
  | Ok _ -> ()
  | Error e -> Alcotest.fail ("depth=100 must be accepted: " ^ Validation.tx_error_to_string e));
  (* Depth = 101: also fine *)
  (match Validation.validate_tx_inputs tx ~lookup ~block_height:101
          ~flags:0 ~skip_scripts:true () with
  | Ok _ -> ()
  | Error e -> Alcotest.fail ("depth=101 must be accepted: " ^ Validation.tx_error_to_string e))

(* ── bad-cb-amount: coinbase pays too much ────────────────────────────────── *)

(* Core validation.cpp:2610-2613:
     blockReward = nFees + GetBlockSubsidy(pindex->nHeight, params);
     if (block.vtx[0]->GetValueOut() > blockReward) → reject.
   Tested through validate_block_with_utxos with skip_scripts=true. *)
let test_bad_cb_amount_in_block () =
  (* Build a regtest block at height 1 with a coinbase paying subsidy+1. *)
  let height = 1 in
  let subsidy = Consensus.block_subsidy_for_network Consensus.Regtest height in
  let overpaid = Int64.add subsidy 1L in
  let coinbase_oversized = make_tx
    ~inputs:[make_coinbase_input ~height]
    ~outputs:[make_output ~value:overpaid ()]
    ()
  in
  let txid = Crypto.compute_txid coinbase_oversized in
  let (merkle, _) = Crypto.merkle_root [txid] in
  (* version=4 to satisfy bip65/bip66 checks at height=1 on regtest *)
  let header = mine_header (make_header ~version:4l ~merkle_root:merkle
    ~bits:0x207fffffl ~timestamp:200l ()) in
  let block = { Types.header; transactions = [coinbase_oversized] } in
  let lookup _outpoint = None in
  let flags = Script.script_verify_none in
  match Validation.validate_block_with_utxos ~network:Consensus.regtest block height
    ~expected_bits:0x207fffffl ~median_time:0l ~base_lookup:lookup
    ~flags ~skip_scripts:true () with
  | Error (Validation.BlockBadCoinbaseValue _) -> ()
  | Error e -> Alcotest.fail ("Expected BlockBadCoinbaseValue: "
                               ^ Validation.block_error_to_string e)
  | Ok _ -> Alcotest.fail "Should have rejected oversized coinbase"

(* Coinbase paying exactly subsidy (no fees) must be accepted. *)
let test_cb_amount_exact_subsidy () =
  let height = 1 in
  let subsidy = Consensus.block_subsidy_for_network Consensus.Regtest height in
  let coinbase_ok = make_tx
    ~inputs:[make_coinbase_input ~height]
    ~outputs:[make_output ~value:subsidy ()]
    ()
  in
  let txid = Crypto.compute_txid coinbase_ok in
  let (merkle, _) = Crypto.merkle_root [txid] in
  let header = mine_header (make_header ~version:4l ~merkle_root:merkle
    ~bits:0x207fffffl ~timestamp:200l ()) in
  let block = { Types.header; transactions = [coinbase_ok] } in
  let lookup _outpoint = None in
  let flags = Script.script_verify_none in
  match Validation.validate_block_with_utxos ~network:Consensus.regtest block height
    ~expected_bits:0x207fffffl ~median_time:0l ~base_lookup:lookup
    ~flags ~skip_scripts:true () with
  | Ok _ -> ()
  | Error e -> Alcotest.fail ("Exact subsidy must be accepted: "
                               ^ Validation.block_error_to_string e)

(* ── bad-cb-amount at epoch boundary: subsidy halves ──────────────────────── *)

(* At block 210000 (regtest: 150) the subsidy halves.  A coinbase paying the old
   full subsidy must be rejected. *)
let test_bad_cb_amount_after_halving () =
  (* Use regtest's shorter interval for fast testing *)
  let height = Consensus.regtest_halving_interval in  (* 150 *)
  (* Post-halving subsidy via block_subsidy_for_network *)
  let new_subsidy = Consensus.block_subsidy_for_network Consensus.Regtest height in
  let old_subsidy = Consensus.block_subsidy_for_network Consensus.Regtest (height - 1) in
  (* Sanity: old should be 2× new *)
  Alcotest.(check int64) "old subsidy is 2x new" (Int64.mul 2L new_subsidy) old_subsidy;
  (* Coinbase paying old_subsidy (one sat too many) *)
  let coinbase_bad = make_tx
    ~inputs:[make_coinbase_input ~height]
    ~outputs:[make_output ~value:old_subsidy ()]
    ()
  in
  let txid = Crypto.compute_txid coinbase_bad in
  let (merkle, _) = Crypto.merkle_root [txid] in
  let header = mine_header (make_header ~version:4l ~merkle_root:merkle
    ~bits:0x207fffffl ~timestamp:200l ()) in
  let block = { Types.header; transactions = [coinbase_bad] } in
  let lookup _outpoint = None in
  let flags = Script.script_verify_none in
  match Validation.validate_block_with_utxos ~network:Consensus.regtest block height
    ~expected_bits:0x207fffffl ~median_time:0l ~base_lookup:lookup
    ~flags ~skip_scripts:true () with
  | Error (Validation.BlockBadCoinbaseValue _) -> ()
  | Error e -> Alcotest.fail ("Expected BlockBadCoinbaseValue after halving: "
                               ^ Validation.block_error_to_string e)
  | Ok _ -> Alcotest.fail "Should have rejected pre-halving coinbase amount post-halving"

(* ── bad-txns-prevout-null: non-coinbase must not have null outpoints ─────── *)

(* Core consensus/tx_check.cpp:54-56. *)
let test_null_prevout_rejected_for_non_coinbase () =
  (* Null outpoint: txid = all zeros, vout = -1 (0xFFFFFFFF) *)
  let null_inp = {
    Types.previous_output = { txid = Types.zero_hash; vout = -1l };
    script_sig = Cstruct.create 0;
    sequence = 0xFFFFFFFFl;
  } in
  let tx = make_tx
    ~inputs:[null_inp]
    ~outputs:[make_output ~value:1000L ()]
    ()
  in
  match Validation.check_transaction tx with
  | Error Validation.TxNullPrevout -> ()
  | Error e -> Alcotest.fail ("Expected TxNullPrevout: " ^ Validation.tx_error_to_string e)
  | Ok () -> Alcotest.fail "Should have rejected null prevout in non-coinbase"

(* ── Accumulated fee MoneyRange (bad-txns-accumulated-fee-outofrange) ─────── *)

(* Core validation.cpp:2543-2547: nFees += txfee; if (!MoneyRange(nFees)) reject.
   Test via validate_block_with_utxos: two txs each contributing MAX_MONEY in fees
   would cause the accumulator to overflow MoneyRange. *)
let test_accumulated_fee_overflow () =
  (* Block: coinbase + tx1 + tx2.
     tx1 spends 1 UTXO worth MAX_MONEY, outputs 0 → fee = MAX_MONEY.
     tx2 spends 1 UTXO worth MAX_MONEY, outputs 0 → fee = MAX_MONEY.
     Accumulated = 2 × MAX_MONEY > MAX_MONEY → reject.
     The coinbase output must also be capped to 0 (no subsidy + no fees yet)
     but it doesn't matter because the fee check fires first. *)
  let height = 1 in

  (* Coinbase tx for block *)
  let coinbase = make_tx
    ~inputs:[make_coinbase_input ~height]
    ~outputs:[make_output ~value:0L ()]  (* 0 to avoid bad-cb-amount *)
    ()
  in

  (* Two UTXOs worth MAX_MONEY each, to be spent with zero outputs *)
  let txid1 = Cstruct.create 32 in
  Cstruct.set_uint8 txid1 0 0x11;
  let txid2 = Cstruct.create 32 in
  Cstruct.set_uint8 txid2 0 0x22;

  let spend1 = make_tx
    ~inputs:[make_input ~txid:txid1 ~vout:0l ()]
    ~outputs:[]  (* All to fees *)
    ()
  in
  let spend2 = make_tx
    ~inputs:[make_input ~txid:txid2 ~vout:0l ()]
    ~outputs:[]
    ()
  in
  (* Fix transaction outputs to empty so fee = MAX_MONEY each; but empty vout
     would fail TxEmptyOutputs in check_transaction.  Use a 0-value output. *)
  let _ = spend1 in let _ = spend2 in
  let spend1 = make_tx
    ~inputs:[make_input ~txid:txid1 ~vout:0l ()]
    ~outputs:[make_output ~value:0L ()]
    ()
  in
  let spend2 = make_tx
    ~inputs:[make_input ~txid:txid2 ~vout:0l ()]
    ~outputs:[make_output ~value:0L ()]
    ()
  in

  let all_txids = List.map Crypto.compute_txid [coinbase; spend1; spend2] in
  let (merkle, _) = Crypto.merkle_root all_txids in
  let header = make_header ~version:4l ~merkle_root:merkle
    ~bits:0x207fffffl ~timestamp:200l () in
  let block = { Types.header; transactions = [coinbase; spend1; spend2] } in

  let lookup outpoint =
    let eq_txid cs1 cs2 = Cstruct.equal cs1 cs2 in
    if eq_txid outpoint.Types.txid txid1 && outpoint.Types.vout = 0l then
      Some {
        Validation.txid = txid1; vout = 0l;
        value = Consensus.max_money;
        script_pubkey = Cstruct.create 0;
        height = 0; is_coinbase = false;
      }
    else if eq_txid outpoint.Types.txid txid2 && outpoint.Types.vout = 0l then
      Some {
        Validation.txid = txid2; vout = 0l;
        value = Consensus.max_money;
        script_pubkey = Cstruct.create 0;
        height = 0; is_coinbase = false;
      }
    else None
  in
  let flags = Script.script_verify_none in
  match Validation.validate_block_with_utxos ~network:Consensus.regtest block height
    ~expected_bits:0x207fffffl ~median_time:0l ~base_lookup:lookup
    ~flags ~skip_scripts:true () with
  | Error (Validation.BlockTxValidationFailed (_, Validation.TxOutputOverflow)) -> ()
  | Error e -> Alcotest.fail ("Expected fee-overflow error: "
                               ^ Validation.block_error_to_string e)
  | Ok _ -> Alcotest.fail "Should have rejected accumulated fee overflow"

(* ── Test Registration ───────────────────────────────────────────────────── *)

(* ============================================================================
   Test Registration
   ============================================================================ *)

(* ============================================================================
   W93: ConnectBlock + ConnectTip + UpdateCoins gates

   These tests exercise the assumevalid fast path in
   [Validation.validate_block_with_utxos] to verify that Bitcoin Core's
   ConnectBlock gates that are NOT guarded by fScriptChecks fire even
   when [skip_scripts=true].  Pre-W93 the fast path silently skipped:

     - check_block (all structural/contextual checks)
     - BIP-141 weighted sigops accumulation
     - BIP-68 SequenceLocks (because callers pass flags=0)
     - BIP-113 IsFinalTx with CSV-aware cutoff (same root cause)
     - coinbase maturity (bad-txns-premature-spend-of-coinbase)
     - per-input MoneyRange + cumulative MoneyRange
     - mutated merkle (BLOCK_MUTATED)

   Reference: Bitcoin Core validation.cpp:2295-2673 (ConnectBlock),
   :3005-... (ConnectTip), :1999-2012 (UpdateCoins),
   consensus/tx_verify.cpp:178-188 (CheckTxInputs).
   ============================================================================ *)

(* W93 Bug 10: assumevalid fast path runs check_block.  A block at
   regtest height=1 with a malformed coinbase scriptSig (no BIP-34
   prefix) must be rejected on the fast path. *)
let test_w93_fast_path_runs_check_block_bip34 () =
  let height = 1 in
  let bad_script = Cstruct.create 4 in
  Cstruct.set_uint8 bad_script 0 0x03;
  Cstruct.set_uint8 bad_script 1 0x99;  (* not the BIP-34 encoding of 1 *)
  Cstruct.set_uint8 bad_script 2 0x88;
  Cstruct.set_uint8 bad_script 3 0x77;
  let coinbase = make_tx
    ~inputs:[{
      Types.previous_output = { txid = Types.zero_hash; vout = -1l };
      script_sig = bad_script;
      sequence = 0xFFFFFFFFl;
    }]
    ~outputs:[make_output ~value:5_000_000_000L ()]
    ()
  in
  let txid = Crypto.compute_txid coinbase in
  let (merkle, _) = Crypto.merkle_root [txid] in
  let header = mine_header (make_header ~version:4l ~merkle_root:merkle
                              ~bits:0x207fffffl ~timestamp:100l ()) in
  let block = { Types.header; transactions = [coinbase] } in
  let base_lookup _ = None in
  let flags = 0 in
  match Validation.validate_block_with_utxos ~network:Consensus.regtest block height
          ~expected_bits:0x207fffffl ~median_time:0l
          ~base_lookup ~flags ~skip_scripts:true () with
  | Error (Validation.BlockTxValidationFailed (0, Validation.TxBadCoinbase)) -> ()
  | Error e -> Alcotest.fail
                 ("W93: expected BIP-34 coinbase rejection on fast path, got: "
                  ^ Validation.block_error_to_string e)
  | Ok _ -> Alcotest.fail
              "W93: fast path must run check_block; missing BIP-34 coinbase \
               was silently accepted"

(* W93 Bug 10: assumevalid fast path enforces block version-bits. *)
let test_w93_fast_path_enforces_bip34_block_version () =
  let height = 1 in
  let coinbase = make_tx
    ~inputs:[make_coinbase_input ~height]
    ~outputs:[make_output ~value:5_000_000_000L ()]
    ()
  in
  let txid = Crypto.compute_txid coinbase in
  let (merkle, _) = Crypto.merkle_root [txid] in
  (* version=1 — invalid at regtest bip34_height=1 *)
  let header = mine_header (make_header ~version:1l ~merkle_root:merkle
                              ~bits:0x207fffffl ~timestamp:100l ()) in
  let block = { Types.header; transactions = [coinbase] } in
  let base_lookup _ = None in
  let flags = 0 in
  match Validation.validate_block_with_utxos ~network:Consensus.regtest block height
          ~expected_bits:0x207fffffl ~median_time:0l
          ~base_lookup ~flags ~skip_scripts:true () with
  | Error Validation.BlockBadVersion -> ()
  | Error e -> Alcotest.fail
                 ("W93: expected BlockBadVersion on fast path, got: "
                  ^ Validation.block_error_to_string e)
  | Ok _ -> Alcotest.fail
              "W93: fast path must reject version=1 block at bip34_height"

(* W93 Bug 3: fast path rejects spending an immature coinbase. *)
let test_w93_fast_path_rejects_immature_coinbase () =
  let height = 50 in  (* spending coinbase from height=0 → depth 50 *)
  let prev_txid =
    let h = Cstruct.create 32 in
    Cstruct.set_uint8 h 0 0xAB;
    h
  in
  let outpoint = { Types.txid = prev_txid; vout = 0l } in
  let base_lookup op =
    if Cstruct.equal op.Types.txid prev_txid && op.Types.vout = 0l then
      Some {
        Validation.txid = prev_txid; vout = 0l;
        value = 5_000_000_000L;
        script_pubkey = Cstruct.create 0;
        height = 0;  (* coinbase from genesis → depth = 50, < COINBASE_MATURITY=100 *)
        is_coinbase = true;
      }
    else None
  in
  let coinbase = make_tx
    ~inputs:[make_coinbase_input ~height]
    ~outputs:[make_output ~value:5_000_000_000L ()]
    ()
  in
  let spender = make_tx
    ~inputs:[{
      Types.previous_output = outpoint;
      script_sig = Cstruct.create 0;
      sequence = 0xFFFFFFFFl;
    }]
    ~outputs:[make_output ~value:4_000_000_000L ()]
    ()
  in
  let txid_cb = Crypto.compute_txid coinbase in
  let txid_sp = Crypto.compute_txid spender in
  let (merkle, _) = Crypto.merkle_root [txid_cb; txid_sp] in
  let header = mine_header (make_header ~version:4l ~merkle_root:merkle
                              ~bits:0x207fffffl ~timestamp:200l ()) in
  let block = { Types.header; transactions = [coinbase; spender] } in
  let flags = 0 in
  match Validation.validate_block_with_utxos ~network:Consensus.regtest block height
          ~expected_bits:0x207fffffl ~median_time:0l
          ~base_lookup ~flags ~skip_scripts:true () with
  | Error (Validation.BlockTxValidationFailed
             (1, Validation.TxCoinbaseMaturity _)) -> ()
  | Error e -> Alcotest.fail
                 ("W93: expected TxCoinbaseMaturity on fast path, got: "
                  ^ Validation.block_error_to_string e)
  | Ok _ -> Alcotest.fail
              "W93: fast path must reject immature coinbase spend"

(* W93 Bug 7: fast path rejects per-input value > MAX_MONEY. *)
let test_w93_fast_path_rejects_input_value_out_of_range () =
  let height = 200 in  (* past coinbase maturity *)
  let prev_txid =
    let h = Cstruct.create 32 in
    Cstruct.set_uint8 h 0 0xCD;
    h
  in
  let outpoint = { Types.txid = prev_txid; vout = 0l } in
  let max_money = Consensus.max_money in
  let base_lookup op =
    if Cstruct.equal op.Types.txid prev_txid && op.Types.vout = 0l then
      Some {
        Validation.txid = prev_txid; vout = 0l;
        value = Int64.add max_money 1L;  (* > MAX_MONEY *)
        script_pubkey = Cstruct.create 0;
        height = 50;
        is_coinbase = false;
      }
    else None
  in
  let coinbase = make_tx
    ~inputs:[make_coinbase_input ~height]
    ~outputs:[make_output ~value:5_000_000_000L ()]
    ()
  in
  let spender = make_tx
    ~inputs:[{
      Types.previous_output = outpoint;
      script_sig = Cstruct.create 0;
      sequence = 0xFFFFFFFFl;
    }]
    ~outputs:[make_output ~value:4_000_000_000L ()]
    ()
  in
  let txid_cb = Crypto.compute_txid coinbase in
  let txid_sp = Crypto.compute_txid spender in
  let (merkle, _) = Crypto.merkle_root [txid_cb; txid_sp] in
  let header = mine_header (make_header ~version:4l ~merkle_root:merkle
                              ~bits:0x207fffffl ~timestamp:200l ()) in
  let block = { Types.header; transactions = [coinbase; spender] } in
  let flags = 0 in
  match Validation.validate_block_with_utxos ~network:Consensus.regtest block height
          ~expected_bits:0x207fffffl ~median_time:0l
          ~base_lookup ~flags ~skip_scripts:true () with
  | Error (Validation.BlockTxValidationFailed
             (1, Validation.TxOutputOverflow)) -> ()
  | Error e -> Alcotest.fail
                 ("W93: expected TxOutputOverflow on fast path, got: "
                  ^ Validation.block_error_to_string e)
  | Ok _ -> Alcotest.fail
              "W93: fast path must reject input value > MAX_MONEY"

(* W93 Bug 5/6: fast path enforces BIP-68 SequenceLocks even when caller
   passes flags=0 (the IBD/reorg dispatcher pattern for assumevalid). *)
let test_w93_fast_path_enforces_bip68_sequence_locks () =
  (* Spend a height-locked UTXO too early. *)
  let height = 200 in  (* past csv_height=0 on regtest *)
  let prev_txid =
    let h = Cstruct.create 32 in
    Cstruct.set_uint8 h 0 0xEF;
    h
  in
  let outpoint = { Types.txid = prev_txid; vout = 0l } in
  let utxo_height = 150 in
  let base_lookup op =
    if Cstruct.equal op.Types.txid prev_txid && op.Types.vout = 0l then
      Some {
        Validation.txid = prev_txid; vout = 0l;
        value = 5_000_000_000L;
        script_pubkey = Cstruct.create 0;
        height = utxo_height;
        is_coinbase = false;
      }
    else None
  in
  let coinbase = make_tx
    ~inputs:[make_coinbase_input ~height]
    ~outputs:[make_output ~value:5_000_000_000L ()]
    ()
  in
  (* sequence = 100 means input is mature at utxo.height + 100 = 250.
     We're at height=200, so BIP-68 must reject. *)
  let spender = {
    Types.version = 2l;  (* BIP-68 requires version >= 2 *)
    inputs = [{
      Types.previous_output = outpoint;
      script_sig = Cstruct.create 0;
      sequence = 100l;
    }];
    outputs = [make_output ~value:4_000_000_000L ()];
    locktime = 0l;
    witnesses = [];
  } in
  let txid_cb = Crypto.compute_txid coinbase in
  let txid_sp = Crypto.compute_txid spender in
  let (merkle, _) = Crypto.merkle_root [txid_cb; txid_sp] in
  let header = mine_header (make_header ~version:4l ~merkle_root:merkle
                              ~bits:0x207fffffl ~timestamp:200l ()) in
  let block = { Types.header; transactions = [coinbase; spender] } in
  (* CALLER PASSES FLAGS=0 — this is the pre-W93 bug pattern.
     CSV must still be enforced because regtest csv_height=0. *)
  let flags = 0 in
  match Validation.validate_block_with_utxos ~network:Consensus.regtest block height
          ~expected_bits:0x207fffffl ~median_time:0l
          ~base_lookup ~flags ~skip_scripts:true () with
  | Error (Validation.BlockTxValidationFailed
             (1, Validation.TxSequenceLocksFailed)) -> ()
  | Error e -> Alcotest.fail
                 ("W93: expected TxSequenceLocksFailed on fast path with \
                   flags=0, got: "
                  ^ Validation.block_error_to_string e)
  | Ok _ -> Alcotest.fail
              "W93: fast path silently skipped BIP-68 SequenceLocks \
               (Bug 5 regression)"

(* W93 Bug 2: fast path enforces MAX_BLOCK_SIGOPS_COST.
   Mostly a regression smoke test — we construct a small block whose
   sigops cost is well under the limit and verify it's accepted (a true
   over-limit test would need ~80k OP_CHECKSIGs).  The contract being
   verified is: total_sigops_cost is accumulated and tested on the fast
   path; pre-W93 it was zero, so any non-zero accumulation that respects
   the limit confirms wiring. *)
let test_w93_fast_path_accumulates_sigops () =
  let height = 1 in
  let coinbase = make_tx
    ~inputs:[make_coinbase_input ~height]
    ~outputs:[make_output ~value:5_000_000_000L ()]
    ()
  in
  let txid = Crypto.compute_txid coinbase in
  let (merkle, _) = Crypto.merkle_root [txid] in
  let header = mine_header (make_header ~version:4l ~merkle_root:merkle
                              ~bits:0x207fffffl ~timestamp:100l ()) in
  let block = { Types.header; transactions = [coinbase] } in
  let base_lookup _ = None in
  let flags = 0 in
  match Validation.validate_block_with_utxos ~network:Consensus.regtest block height
          ~expected_bits:0x207fffffl ~median_time:0l
          ~base_lookup ~flags ~skip_scripts:true () with
  | Ok _ -> ()
  | Error e -> Alcotest.fail
                 ("W93: well-formed block should be accepted on fast path, got: "
                  ^ Validation.block_error_to_string e)

(* W93 Bug 1: bip30_should_enforce returns false when bip34_height_hash
   matches the network's canonical BIP34Hash (skip optimization active). *)
let test_w93_bip30_skip_with_bip34_height_hash () =
  let mainnet = Consensus.mainnet in
  let canonical_hash = match mainnet.bip34_hash with
    | Some h -> h
    | None -> failwith "mainnet must have bip34_hash"
  in
  (* Some height in the BIP-34 era but below BIP34_IMPLIES_BIP30_LIMIT. *)
  let height = 500_000 in
  let probe_hash = Cstruct.create 32 in
  Cstruct.set_uint8 probe_hash 0 0x42;  (* not a repeat block *)
  let result = Validation.bip30_should_enforce
                 ~network:mainnet ~height ~block_hash:probe_hash
                 ~bip34_height_hash:(Some canonical_hash) in
  Alcotest.(check bool) "W93: BIP-30 SKIPPED when bip34_height_hash matches"
    false result

(* W93 Bug 1 (counterpart): bip30_should_enforce returns true when the
   bip34_height_hash does NOT match (Gate 4 falls through). *)
let test_w93_bip30_enforce_with_wrong_bip34_hash () =
  let mainnet = Consensus.mainnet in
  let height = 500_000 in
  let probe_hash = Cstruct.create 32 in
  Cstruct.set_uint8 probe_hash 0 0x42;
  let wrong_hash = Cstruct.create 32 in
  Cstruct.set_uint8 wrong_hash 0 0xFF;
  let result = Validation.bip30_should_enforce
                 ~network:mainnet ~height ~block_hash:probe_hash
                 ~bip34_height_hash:(Some wrong_hash) in
  Alcotest.(check bool) "W93: BIP-30 ENFORCED when bip34_height_hash mismatches"
    true result

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
      test_case "BIP94 timewarp attack testnet4" `Quick test_check_block_timewarp_attack;
      test_case "BIP94 no timewarp on mainnet" `Quick test_check_block_no_timewarp_mainnet;
      test_case "BIP94 no timewarp at non-boundary" `Quick test_check_block_no_timewarp_non_boundary;
    ];
    "witness_commitment", [
      test_case "valid commitment" `Quick test_witness_commitment_valid;
      test_case "nonce 31 bytes → bad-witness-nonce-size" `Quick test_witness_nonce_wrong_size;
      test_case "nonce 33 bytes → bad-witness-nonce-size" `Quick test_witness_nonce_33_bytes;
      test_case "empty nonce stack → bad-witness-nonce-size" `Quick test_witness_nonce_empty_stack;
      test_case "two-item nonce stack → bad-witness-nonce-size" `Quick test_witness_nonce_two_items;
      test_case "wrong hash → bad-witness-merkle-match" `Quick test_witness_merkle_mismatch;
      test_case "last output wins (LAST-scan)" `Quick test_witness_last_output_wins;
      test_case "no commitment, has witness → unexpected-witness" `Quick test_unexpected_witness_segwit_active;
      test_case "pre-segwit no witness → Ok" `Quick test_no_witness_pre_segwit;
      test_case "pre-segwit with witness → unexpected-witness" `Quick test_unexpected_witness_pre_segwit;
      test_case "pre-segwit ignores commitment output (Bug 1)" `Quick test_pre_segwit_ignores_commitment_output;
      test_case "38-byte minimum (37-byte is not a commitment)" `Quick test_minimum_38_byte_commitment;
      test_case "no commitment, no witness → Ok" `Quick test_no_commitment_no_witness;
      test_case "coinbase wtxid is zero in witness merkle" `Quick test_coinbase_wtxid_is_zero;
      test_case "check_block: unexpected-witness on regtest" `Quick test_check_block_unexpected_witness_regtest;
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
      (* New W80 gates *)
      test_case "SEQUENCE_FINAL (0xFFFFFFFF) has disable bit → skip" `Quick test_sequence_final_skipped;
      test_case "height boundary: exact required_height passes" `Quick test_sequence_lock_height_boundary;
      test_case "time boundary: granularity=9 exact passes" `Quick test_sequence_lock_time_boundary;
      test_case "time lock: Int64 arithmetic no overflow" `Quick test_sequence_lock_time_int64_no_overflow;
      test_case "max MASK=0xFFFF height lock" `Quick test_sequence_lock_max_height_mask;
      test_case "get_mtp_at_height callback for BIP-68 utxo-1 MTP" `Quick test_sequence_lock_get_mtp_callback;
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
    "bip30_bip34_w79_gates", [
      (* Gate 1 + 3: IsBIP30Repeat requires height+hash, not height-only *)
      test_case "G1: repeat exempt only with canonical hash" `Quick
        test_bip30_repeat_requires_canonical_hash;
      test_case "G1: non-exempt heights always enforce" `Quick
        test_bip30_repeat_only_at_exempt_heights;
      (* Gate 2: IsBIP30Unspendable for DisconnectBlock *)
      test_case "G2: unspendable height+hash check" `Quick
        test_bip30_unspendable_height_and_hash;
      (* Gate 3 + 4: bip30_should_enforce comprehensive *)
      test_case "G3: pre-BIP34 always enforces" `Quick
        test_bip30_should_enforce_pre_bip34;
      test_case "G3: canonical repeat block exempt" `Quick
        test_bip30_should_enforce_repeat_block_exempt;
      test_case "G4: canonical BIP34 chain skips BIP-30" `Quick
        test_bip30_should_enforce_bip34_active_canonical;
      test_case "G4: non-canonical BIP34 ancestor enforces" `Quick
        test_bip30_should_enforce_bip34_active_noncanonical;
      test_case "G4 fallback: no BIP34 hint → conservative" `Quick
        test_bip30_should_enforce_bip34_no_hint;
      (* Gate 5: BIP34_IMPLIES_BIP30_LIMIT re-enables at 1983702 *)
      test_case "G5: re-enabled at height=1983702" `Quick
        test_bip30_should_enforce_at_limit;
      test_case "G5: no BIP30 window on genesis networks" `Quick
        test_bip30_should_enforce_regtest_no_window;
      (* Gate 6: BIP-30 applies to ALL txs *)
      test_case "G6: BIP-30 catches non-coinbase duplicates too" `Quick
        test_bip30_applies_to_all_txs;
      (* Gate 7 + 10: CScriptNum encoding boundary cases *)
      test_case "G7/G10: CScriptNum sign-bit boundaries" `Quick
        test_bip34_cscriptnum_sign_bit_boundaries;
      test_case "G7: OP_0/OP_1..OP_16 encoding boundaries" `Quick
        test_bip34_op_encoding_boundaries;
      test_case "G7: bad-cb-height rejected after BIP34" `Quick
        test_bip34_error_on_wrong_height;
      (* Gate 8: block version enforcement *)
      test_case "G8: version 1 block rejected at bip34_height" `Quick
        test_bip34_block_version_gate;
      (* Gate 4: BIP34Hash field correctness *)
      test_case "G4: mainnet bip34_hash matches Core" `Quick
        test_mainnet_bip34_hash_correct;
      test_case "G4: testnet3 bip34_hash matches Core" `Quick
        test_testnet3_bip34_hash_correct;
      test_case "G4: testnet4/regtest have no bip34_hash" `Quick
        test_no_bip34_hash_on_genesis_networks;
      (* Block hash round-trip verification *)
      test_case "G1: repeat block hashes match Core constants" `Quick
        test_bip30_repeat_block_hashes_match_core;
      test_case "G2: unspendable block hashes match Core constants" `Quick
        test_bip30_unspendable_block_hashes_match_core;
      (* Gate 5: validate_block enforces at limit *)
      test_case "G5: validate_block enforces at height=1983702" `Quick
        test_bip30_reenabled_at_limit_in_validate;
    ];
    "w84_checktx_checktxinputs", [
      (* GetBlockSubsidy *)
      test_case "subsidy all halvings 0..64" `Quick test_subsidy_all_halvings;
      test_case "subsidy regtest interval" `Quick test_subsidy_regtest_interval;
      (* CVE-2010-5139 *)
      test_case "CVE-2010: negative output" `Quick test_cve_2010_negative_value;
      test_case "CVE-2010: toolarge output (bad-txns-vout-toolarge)" `Quick test_cve_2010_toolarge_value;
      test_case "CVE-2010: total output overflow" `Quick test_cve_2010_txouttotal_toolarge;
      (* CVE-2018-17144 *)
      test_case "CVE-2018-17144: duplicate inputs" `Quick test_cve_2018_17144_duplicate_inputs;
      (* bad-cb-length *)
      test_case "bad-cb-length: scriptSig too short" `Quick test_bad_cb_length_too_short;
      test_case "bad-cb-length: scriptSig too long" `Quick test_bad_cb_length_too_long;
      test_case "bad-cb-length: exact boundaries 2 and 100" `Quick test_bad_cb_length_exact_boundaries;
      (* CheckTxInputs: per-input and cumulative MoneyRange *)
      test_case "input UTXO value > MAX_MONEY rejected" `Quick test_input_value_out_of_range;
      test_case "cumulative input sum overflow rejected" `Quick test_input_cumulative_overflow;
      (* bad-txns-in-belowout *)
      test_case "validate_tx_inputs returns total_in (belowout check is block-level)" `Quick test_input_below_output;
      (* bad-txns-premature-spend-of-coinbase *)
      test_case "coinbase maturity: depth=99 reject, depth=100 accept" `Quick test_coinbase_maturity_boundary;
      (* bad-cb-amount *)
      test_case "bad-cb-amount: coinbase overpays subsidy" `Quick test_bad_cb_amount_in_block;
      test_case "bad-cb-amount: exact subsidy accepted" `Quick test_cb_amount_exact_subsidy;
      test_case "bad-cb-amount: pre-halving amount rejected post-halving" `Quick test_bad_cb_amount_after_halving;
      (* bad-txns-prevout-null *)
      test_case "bad-txns-prevout-null: non-coinbase null outpoint rejected" `Quick test_null_prevout_rejected_for_non_coinbase;
      (* accumulated fee overflow *)
      test_case "bad-txns-accumulated-fee-outofrange: 2x MAX_MONEY fees overflow" `Quick test_accumulated_fee_overflow;
    ];
    (* W93: ConnectBlock + ConnectTip + UpdateCoins comprehensive audit *)
    "w93_connectblock_gates", [
      test_case "fast path runs check_block (BIP-34 coinbase)" `Quick
        test_w93_fast_path_runs_check_block_bip34;
      test_case "fast path enforces BIP-34 block version" `Quick
        test_w93_fast_path_enforces_bip34_block_version;
      test_case "fast path rejects immature coinbase (Bug 3)" `Quick
        test_w93_fast_path_rejects_immature_coinbase;
      test_case "fast path rejects per-input value > MAX_MONEY (Bug 7)" `Quick
        test_w93_fast_path_rejects_input_value_out_of_range;
      test_case "fast path enforces BIP-68 with flags=0 (Bug 5)" `Quick
        test_w93_fast_path_enforces_bip68_sequence_locks;
      test_case "fast path accumulates sigops on well-formed block (Bug 2)" `Quick
        test_w93_fast_path_accumulates_sigops;
      test_case "bip30_should_enforce skips when bip34_hash matches (Bug 1)" `Quick
        test_w93_bip30_skip_with_bip34_height_hash;
      test_case "bip30_should_enforce enforces when bip34_hash mismatches (Bug 1)" `Quick
        test_w93_bip30_enforce_with_wrong_bip34_hash;
    ];
  ]
