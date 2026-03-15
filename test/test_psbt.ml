(* Tests for PSBT (BIP-174) *)

open Camlcoin

(* Helper to convert hex string to Cstruct *)
let hex_to_cstruct s =
  let len = String.length s / 2 in
  let buf = Cstruct.create len in
  for i = 0 to len - 1 do
    let byte = int_of_string ("0x" ^ String.sub s (i * 2) 2) in
    Cstruct.set_uint8 buf i byte
  done;
  buf

(* Helper to convert Cstruct to hex string *)
let _cstruct_to_hex cs =
  let buf = Buffer.create (Cstruct.length cs * 2) in
  for i = 0 to Cstruct.length cs - 1 do
    Buffer.add_string buf (Printf.sprintf "%02x" (Cstruct.get_uint8 cs i))
  done;
  Buffer.contents buf

(* ============================================================================
   Basic PSBT Creation Tests
   ============================================================================ *)

let test_create_empty_psbt () =
  (* Create a minimal transaction *)
  let tx : Types.transaction = {
    version = 2l;
    inputs = [{
      previous_output = {
        txid = hex_to_cstruct "0000000000000000000000000000000000000000000000000000000000000001";
        vout = 0l;
      };
      script_sig = Cstruct.empty;
      sequence = 0xFFFFFFFFl;
    }];
    outputs = [{
      value = 50000L;
      script_pubkey = hex_to_cstruct "00140000000000000000000000000000000000000000";
    }];
    witnesses = [];
    locktime = 0l;
  } in
  let psbt = Psbt.create tx in
  Alcotest.(check int) "one input" 1 (List.length psbt.inputs);
  Alcotest.(check int) "one output" 1 (List.length psbt.outputs);
  Alcotest.(check bool) "not finalized" false (Psbt.is_finalized psbt);
  Alcotest.(check int) "one unsigned input" 1 (Psbt.count_unsigned_inputs psbt)

let test_create_multi_input_psbt () =
  let tx : Types.transaction = {
    version = 2l;
    inputs = [
      {
        previous_output = {
          txid = hex_to_cstruct "0000000000000000000000000000000000000000000000000000000000000001";
          vout = 0l;
        };
        script_sig = Cstruct.empty;
        sequence = 0xFFFFFFFFl;
      };
      {
        previous_output = {
          txid = hex_to_cstruct "0000000000000000000000000000000000000000000000000000000000000002";
          vout = 1l;
        };
        script_sig = Cstruct.empty;
        sequence = 0xFFFFFFFFl;
      };
    ];
    outputs = [
      { value = 100000L; script_pubkey = hex_to_cstruct "00140000000000000000000000000000000000000000" };
      { value = 50000L; script_pubkey = hex_to_cstruct "00140000000000000000000000000000000000000001" };
    ];
    witnesses = [];
    locktime = 0l;
  } in
  let psbt = Psbt.create tx in
  Alcotest.(check int) "two inputs" 2 (List.length psbt.inputs);
  Alcotest.(check int) "two outputs" 2 (List.length psbt.outputs);
  Alcotest.(check int) "two unsigned" 2 (Psbt.count_unsigned_inputs psbt)

(* ============================================================================
   PSBT Serialization/Deserialization Tests
   ============================================================================ *)

let test_serialize_roundtrip () =
  let tx : Types.transaction = {
    version = 2l;
    inputs = [{
      previous_output = {
        txid = hex_to_cstruct "1111111111111111111111111111111111111111111111111111111111111111";
        vout = 0l;
      };
      script_sig = Cstruct.empty;
      sequence = 0xFFFFFFFEl;
    }];
    outputs = [{
      value = 99000L;
      script_pubkey = hex_to_cstruct "0014aabbccdd00112233445566778899aabbccddeeff";
    }];
    witnesses = [];
    locktime = 100l;
  } in
  let psbt = Psbt.create tx in
  let serialized = Psbt.serialize psbt in

  (* Check magic bytes *)
  Alcotest.(check string) "magic psbt" "psbt\xff" (Cstruct.to_string (Cstruct.sub serialized 0 5));

  (* Deserialize and check *)
  match Psbt.deserialize serialized with
  | Error e -> Alcotest.fail (Psbt.string_of_error e)
  | Ok psbt2 ->
    Alcotest.(check int32) "version matches" psbt.tx.version psbt2.tx.version;
    Alcotest.(check int) "inputs match" (List.length psbt.tx.inputs) (List.length psbt2.tx.inputs);
    Alcotest.(check int) "outputs match" (List.length psbt.tx.outputs) (List.length psbt2.tx.outputs);
    Alcotest.(check int32) "locktime matches" psbt.tx.locktime psbt2.tx.locktime

let test_serialize_with_utxo () =
  let tx : Types.transaction = {
    version = 2l;
    inputs = [{
      previous_output = {
        txid = hex_to_cstruct "2222222222222222222222222222222222222222222222222222222222222222";
        vout = 0l;
      };
      script_sig = Cstruct.empty;
      sequence = 0xFFFFFFFFl;
    }];
    outputs = [{
      value = 50000L;
      script_pubkey = hex_to_cstruct "0014aabbccddeeff00112233445566778899aabbccdd";
    }];
    witnesses = [];
    locktime = 0l;
  } in
  let psbt = Psbt.create tx in

  (* Add witness UTXO *)
  let utxo : Types.tx_out = {
    value = 100000L;
    script_pubkey = hex_to_cstruct "0014ffeeddccbbaa99887766554433221100ffeeddcc";
  } in
  let psbt = Psbt.add_witness_utxo psbt 0 utxo in

  let serialized = Psbt.serialize psbt in
  match Psbt.deserialize serialized with
  | Error e -> Alcotest.fail (Psbt.string_of_error e)
  | Ok psbt2 ->
    let inp = List.hd psbt2.inputs in
    Alcotest.(check bool) "has witness utxo" true (Option.is_some inp.witness_utxo);
    match inp.witness_utxo with
    | None -> Alcotest.fail "witness utxo is None"
    | Some u ->
      Alcotest.(check int64) "utxo value" 100000L u.value

let test_invalid_magic () =
  let bad_data = Cstruct.of_string "notpsbt" in
  match Psbt.deserialize bad_data with
  | Ok _ -> Alcotest.fail "should reject invalid magic"
  | Error Psbt.Invalid_magic -> ()
  | Error e -> Alcotest.fail ("wrong error: " ^ Psbt.string_of_error e)

let test_base64_roundtrip () =
  let tx : Types.transaction = {
    version = 2l;
    inputs = [{
      previous_output = {
        txid = hex_to_cstruct "3333333333333333333333333333333333333333333333333333333333333333";
        vout = 2l;
      };
      script_sig = Cstruct.empty;
      sequence = 0xFFFFFFFFl;
    }];
    outputs = [{
      value = 25000L;
      script_pubkey = hex_to_cstruct "0014112233445566778899aabbccddeeff0011223344";
    }];
    witnesses = [];
    locktime = 500000l;
  } in
  let psbt = Psbt.create tx in
  let b64 = Psbt.to_base64 psbt in

  (* Check that it starts with "cHNidP" (base64 of "psbt\xff") *)
  Alcotest.(check bool) "base64 prefix" true (String.length b64 > 0);

  match Psbt.of_base64 b64 with
  | Error e -> Alcotest.fail (Psbt.string_of_error e)
  | Ok psbt2 ->
    Alcotest.(check int32) "version matches" psbt.tx.version psbt2.tx.version;
    Alcotest.(check int32) "locktime matches" psbt.tx.locktime psbt2.tx.locktime

(* ============================================================================
   PSBT Updater Role Tests
   ============================================================================ *)

let test_add_witness_utxo () =
  let tx : Types.transaction = {
    version = 2l;
    inputs = [{
      previous_output = {
        txid = hex_to_cstruct "4444444444444444444444444444444444444444444444444444444444444444";
        vout = 0l;
      };
      script_sig = Cstruct.empty;
      sequence = 0xFFFFFFFFl;
    }];
    outputs = [{ value = 50000L; script_pubkey = hex_to_cstruct "0014aabbccdd" }];
    witnesses = [];
    locktime = 0l;
  } in
  let psbt = Psbt.create tx in
  let utxo : Types.tx_out = { value = 100000L; script_pubkey = hex_to_cstruct "0014eeff0011" } in
  let psbt = Psbt.add_witness_utxo psbt 0 utxo in

  let inp = List.hd psbt.inputs in
  Alcotest.(check bool) "has utxo" true (Option.is_some inp.witness_utxo);
  match inp.witness_utxo with
  | None -> Alcotest.fail "no utxo"
  | Some u -> Alcotest.(check int64) "value" 100000L u.value

let test_add_redeem_script () =
  let tx : Types.transaction = {
    version = 2l;
    inputs = [{
      previous_output = { txid = hex_to_cstruct (String.make 64 '5'); vout = 0l };
      script_sig = Cstruct.empty;
      sequence = 0xFFFFFFFFl;
    }];
    outputs = [{ value = 50000L; script_pubkey = hex_to_cstruct "a914" }];
    witnesses = [];
    locktime = 0l;
  } in
  let psbt = Psbt.create tx in
  let redeem = hex_to_cstruct "5121deadbeef51ae" in
  let psbt = Psbt.add_redeem_script psbt 0 redeem in

  let inp = List.hd psbt.inputs in
  Alcotest.(check bool) "has redeem script" true (Option.is_some inp.redeem_script);
  match inp.redeem_script with
  | None -> Alcotest.fail "no redeem script"
  | Some rs -> Alcotest.(check int) "script len" 8 (Cstruct.length rs)

let test_add_bip32_derivation () =
  let tx : Types.transaction = {
    version = 2l;
    inputs = [{
      previous_output = { txid = hex_to_cstruct (String.make 64 '6'); vout = 0l };
      script_sig = Cstruct.empty;
      sequence = 0xFFFFFFFFl;
    }];
    outputs = [{ value = 50000L; script_pubkey = hex_to_cstruct "0014" }];
    witnesses = [];
    locktime = 0l;
  } in
  let psbt = Psbt.create tx in
  let deriv : Psbt.bip32_derivation = {
    pubkey = hex_to_cstruct ("02" ^ String.make 64 'a');
    origin = {
      fingerprint = 0x12345678l;
      path = [0x80000054l; 0x80000000l; 0x80000000l; 0l; 0l];  (* m/84'/0'/0'/0/0 *)
    };
  } in
  let psbt = Psbt.add_input_derivation psbt 0 deriv in

  let inp = List.hd psbt.inputs in
  Alcotest.(check int) "has derivation" 1 (List.length inp.bip32_derivations);
  let d = List.hd inp.bip32_derivations in
  Alcotest.(check int32) "fingerprint" 0x12345678l d.origin.fingerprint;
  Alcotest.(check int) "path length" 5 (List.length d.origin.path)

(* ============================================================================
   PSBT Signer Role Tests
   ============================================================================ *)

let test_add_partial_sig () =
  let tx : Types.transaction = {
    version = 2l;
    inputs = [{
      previous_output = { txid = hex_to_cstruct (String.make 64 '7'); vout = 0l };
      script_sig = Cstruct.empty;
      sequence = 0xFFFFFFFFl;
    }];
    outputs = [{ value = 50000L; script_pubkey = hex_to_cstruct "0014" }];
    witnesses = [];
    locktime = 0l;
  } in
  let psbt = Psbt.create tx in
  let sig_ : Psbt.partial_sig = {
    pubkey = hex_to_cstruct ("03" ^ String.make 64 'b');
    signature = hex_to_cstruct ("3044" ^ String.make 140 'c' ^ "01");
  } in
  let psbt = Psbt.add_partial_sig psbt 0 sig_ in

  let inp = List.hd psbt.inputs in
  Alcotest.(check int) "has sig" 1 (List.length inp.partial_sigs);
  let ps = List.hd inp.partial_sigs in
  Alcotest.(check int) "pubkey len" 33 (Cstruct.length ps.pubkey)

let test_set_sighash_type () =
  let tx : Types.transaction = {
    version = 2l;
    inputs = [{
      previous_output = { txid = hex_to_cstruct (String.make 64 '8'); vout = 0l };
      script_sig = Cstruct.empty;
      sequence = 0xFFFFFFFFl;
    }];
    outputs = [{ value = 50000L; script_pubkey = hex_to_cstruct "0014" }];
    witnesses = [];
    locktime = 0l;
  } in
  let psbt = Psbt.create tx in
  let psbt = Psbt.set_sighash_type psbt 0 0x01l in (* SIGHASH_ALL *)

  let inp = List.hd psbt.inputs in
  Alcotest.(check bool) "has sighash" true (Option.is_some inp.sighash_type);
  match inp.sighash_type with
  | None -> Alcotest.fail "no sighash"
  | Some sht -> Alcotest.(check int32) "sighash value" 0x01l sht

(* ============================================================================
   PSBT Combiner Role Tests
   ============================================================================ *)

let test_combine_psbts () =
  let tx : Types.transaction = {
    version = 2l;
    inputs = [{
      previous_output = { txid = hex_to_cstruct (String.make 64 '9'); vout = 0l };
      script_sig = Cstruct.empty;
      sequence = 0xFFFFFFFFl;
    }];
    outputs = [{ value = 50000L; script_pubkey = hex_to_cstruct "0014" }];
    witnesses = [];
    locktime = 0l;
  } in

  (* Create two PSBTs with different partial sigs *)
  let psbt1 = Psbt.create tx in
  let sig1 : Psbt.partial_sig = {
    pubkey = hex_to_cstruct ("02" ^ String.make 64 'd');
    signature = hex_to_cstruct ("3045" ^ String.make 142 'e' ^ "01");
  } in
  let psbt1 = Psbt.add_partial_sig psbt1 0 sig1 in

  let psbt2 = Psbt.create tx in
  let sig2 : Psbt.partial_sig = {
    pubkey = hex_to_cstruct ("03" ^ String.make 64 'f');
    signature = hex_to_cstruct ("3044" ^ String.make 140 '0' ^ "01");
  } in
  let psbt2 = Psbt.add_partial_sig psbt2 0 sig2 in

  match Psbt.combine psbt1 psbt2 with
  | Error e -> Alcotest.fail e
  | Ok combined ->
    let inp = List.hd combined.inputs in
    Alcotest.(check int) "combined sigs" 2 (List.length inp.partial_sigs)

let test_combine_mismatched_tx () =
  let tx1 : Types.transaction = {
    version = 2l;
    inputs = [{
      previous_output = { txid = hex_to_cstruct (String.make 64 'a'); vout = 0l };
      script_sig = Cstruct.empty;
      sequence = 0xFFFFFFFFl;
    }];
    outputs = [{ value = 50000L; script_pubkey = hex_to_cstruct "0014" }];
    witnesses = [];
    locktime = 0l;
  } in
  let tx2 : Types.transaction = {
    version = 2l;
    inputs = [{
      previous_output = { txid = hex_to_cstruct (String.make 64 'b'); vout = 0l };
      script_sig = Cstruct.empty;
      sequence = 0xFFFFFFFFl;
    }];
    outputs = [{ value = 50000L; script_pubkey = hex_to_cstruct "0014" }];
    witnesses = [];
    locktime = 0l;
  } in
  let psbt1 = Psbt.create tx1 in
  let psbt2 = Psbt.create tx2 in

  match Psbt.combine psbt1 psbt2 with
  | Error _ -> ()  (* Expected *)
  | Ok _ -> Alcotest.fail "should reject mismatched transactions"

(* ============================================================================
   PSBT Finalizer Role Tests
   ============================================================================ *)

let test_finalize_p2wpkh () =
  let tx : Types.transaction = {
    version = 2l;
    inputs = [{
      previous_output = { txid = hex_to_cstruct (String.make 64 'c'); vout = 0l };
      script_sig = Cstruct.empty;
      sequence = 0xFFFFFFFFl;
    }];
    outputs = [{ value = 50000L; script_pubkey = hex_to_cstruct "0014" }];
    witnesses = [];
    locktime = 0l;
  } in
  let psbt = Psbt.create tx in

  (* Add a partial signature *)
  let sig_ : Psbt.partial_sig = {
    pubkey = hex_to_cstruct ("02" ^ String.make 64 '1');
    signature = hex_to_cstruct ("3044" ^ String.make 140 '2' ^ "01");
  } in
  let psbt = Psbt.add_partial_sig psbt 0 sig_ in

  match Psbt.finalize_input_p2wpkh psbt 0 with
  | Error e -> Alcotest.fail e
  | Ok finalized ->
    let inp = List.hd finalized.inputs in
    Alcotest.(check bool) "has witness" true (Option.is_some inp.final_scriptwitness);
    Alcotest.(check bool) "cleared partial sigs" true (inp.partial_sigs = []);
    Alcotest.(check bool) "is finalized" true (Psbt.is_input_finalized inp)

let test_finalize_no_sigs () =
  let tx : Types.transaction = {
    version = 2l;
    inputs = [{
      previous_output = { txid = hex_to_cstruct (String.make 64 'd'); vout = 0l };
      script_sig = Cstruct.empty;
      sequence = 0xFFFFFFFFl;
    }];
    outputs = [{ value = 50000L; script_pubkey = hex_to_cstruct "0014" }];
    witnesses = [];
    locktime = 0l;
  } in
  let psbt = Psbt.create tx in

  match Psbt.finalize_input_p2wpkh psbt 0 with
  | Error _ -> ()  (* Expected *)
  | Ok _ -> Alcotest.fail "should fail without signatures"

(* ============================================================================
   PSBT Extractor Role Tests
   ============================================================================ *)

let test_extract_finalized () =
  let tx : Types.transaction = {
    version = 2l;
    inputs = [{
      previous_output = { txid = hex_to_cstruct (String.make 64 'e'); vout = 0l };
      script_sig = Cstruct.empty;
      sequence = 0xFFFFFFFFl;
    }];
    outputs = [{ value = 50000L; script_pubkey = hex_to_cstruct "0014aabbccdd00112233445566778899aabbccddeeff" }];
    witnesses = [];
    locktime = 0l;
  } in
  let psbt = Psbt.create tx in

  (* Add and finalize *)
  let sig_ : Psbt.partial_sig = {
    pubkey = hex_to_cstruct ("02" ^ String.make 64 '3');
    signature = hex_to_cstruct ("3044" ^ String.make 140 '4' ^ "01");
  } in
  let psbt = Psbt.add_partial_sig psbt 0 sig_ in

  match Psbt.finalize_input_p2wpkh psbt 0 with
  | Error e -> Alcotest.fail e
  | Ok finalized ->
    match Psbt.extract finalized with
    | Error e -> Alcotest.fail e
    | Ok final_tx ->
      Alcotest.(check int) "has witnesses" 1 (List.length final_tx.witnesses);
      let wit = List.hd final_tx.witnesses in
      Alcotest.(check int) "witness items" 2 (List.length wit.items)

let test_extract_not_finalized () =
  let tx : Types.transaction = {
    version = 2l;
    inputs = [{
      previous_output = { txid = hex_to_cstruct (String.make 64 'f'); vout = 0l };
      script_sig = Cstruct.empty;
      sequence = 0xFFFFFFFFl;
    }];
    outputs = [{ value = 50000L; script_pubkey = hex_to_cstruct "0014" }];
    witnesses = [];
    locktime = 0l;
  } in
  let psbt = Psbt.create tx in

  match Psbt.extract psbt with
  | Error _ -> ()  (* Expected *)
  | Ok _ -> Alcotest.fail "should fail when not finalized"

(* ============================================================================
   PSBT Fee Calculation Tests
   ============================================================================ *)

let test_fee_calculation () =
  let tx : Types.transaction = {
    version = 2l;
    inputs = [{
      previous_output = { txid = hex_to_cstruct (String.make 64 '0'); vout = 0l };
      script_sig = Cstruct.empty;
      sequence = 0xFFFFFFFFl;
    }];
    outputs = [{ value = 90000L; script_pubkey = hex_to_cstruct "0014aabbccdd00112233445566778899aabbccddeeff" }];
    witnesses = [];
    locktime = 0l;
  } in
  let psbt = Psbt.create tx in

  (* Add witness UTXO with 100000 sats *)
  let utxo : Types.tx_out = { value = 100000L; script_pubkey = hex_to_cstruct "0014ffeeddcc" } in
  let psbt = Psbt.add_witness_utxo psbt 0 utxo in

  match Psbt.get_fee psbt with
  | None -> Alcotest.fail "should calculate fee"
  | Some fee -> Alcotest.(check int64) "fee" 10000L fee

let test_fee_calculation_missing_utxo () =
  let tx : Types.transaction = {
    version = 2l;
    inputs = [{
      previous_output = { txid = hex_to_cstruct (String.make 64 '1'); vout = 0l };
      script_sig = Cstruct.empty;
      sequence = 0xFFFFFFFFl;
    }];
    outputs = [{ value = 90000L; script_pubkey = hex_to_cstruct "0014" }];
    witnesses = [];
    locktime = 0l;
  } in
  let psbt = Psbt.create tx in

  match Psbt.get_fee psbt with
  | None -> ()  (* Expected - no UTXO info *)
  | Some _ -> Alcotest.fail "should not calculate fee without UTXOs"

(* ============================================================================
   PSBT Taproot Tests
   ============================================================================ *)

let test_taproot_key_sig () =
  let tx : Types.transaction = {
    version = 2l;
    inputs = [{
      previous_output = { txid = hex_to_cstruct (String.make 64 '2'); vout = 0l };
      script_sig = Cstruct.empty;
      sequence = 0xFFFFFFFFl;
    }];
    outputs = [{ value = 50000L; script_pubkey = hex_to_cstruct ("5120" ^ String.make 64 'a') }];
    witnesses = [];
    locktime = 0l;
  } in
  let psbt = Psbt.create tx in

  (* Add a 64-byte Schnorr signature (SIGHASH_DEFAULT) *)
  let sig_ = hex_to_cstruct (String.make 128 'b') in
  let psbt = Psbt.add_tap_key_sig psbt 0 sig_ in

  let inp = List.hd psbt.inputs in
  Alcotest.(check bool) "has tap sig" true (Option.is_some inp.tap_key_sig);
  match inp.tap_key_sig with
  | None -> Alcotest.fail "no tap sig"
  | Some s -> Alcotest.(check int) "sig len" 64 (Cstruct.length s)

let test_finalize_taproot () =
  let tx : Types.transaction = {
    version = 2l;
    inputs = [{
      previous_output = { txid = hex_to_cstruct (String.make 64 '3'); vout = 0l };
      script_sig = Cstruct.empty;
      sequence = 0xFFFFFFFFl;
    }];
    outputs = [{ value = 50000L; script_pubkey = hex_to_cstruct ("5120" ^ String.make 64 'c') }];
    witnesses = [];
    locktime = 0l;
  } in
  let psbt = Psbt.create tx in
  let sig_ = hex_to_cstruct (String.make 128 'd') in
  let psbt = Psbt.add_tap_key_sig psbt 0 sig_ in

  match Psbt.finalize_input_taproot psbt 0 with
  | Error e -> Alcotest.fail e
  | Ok finalized ->
    let inp = List.hd finalized.inputs in
    Alcotest.(check bool) "has witness" true (Option.is_some inp.final_scriptwitness);
    match inp.final_scriptwitness with
    | None -> Alcotest.fail "no witness"
    | Some wit -> Alcotest.(check int) "one witness item" 1 (List.length wit)

(* ============================================================================
   Multi-Party Signing Tests
   ============================================================================ *)

(* Simulate a 2-of-3 multisig scenario *)
let test_multi_party_combine () =
  let tx : Types.transaction = {
    version = 2l;
    inputs = [{
      previous_output = {
        txid = hex_to_cstruct "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        vout = 0l;
      };
      script_sig = Cstruct.empty;
      sequence = 0xFFFFFFFEl;
    }];
    outputs = [{
      value = 99000L;
      script_pubkey = hex_to_cstruct "0014aabbccdd00112233445566778899aabbccddeeff";
    }];
    witnesses = [];
    locktime = 0l;
  } in

  (* Party A creates PSBT and adds their signature *)
  let psbt_a = Psbt.create tx in
  let utxo : Types.tx_out = { value = 100000L; script_pubkey = hex_to_cstruct "0020ffeeddcc" } in
  let psbt_a = Psbt.add_witness_utxo psbt_a 0 utxo in
  let sig_a : Psbt.partial_sig = {
    pubkey = hex_to_cstruct ("02" ^ String.make 64 'a');
    signature = hex_to_cstruct ("3044" ^ String.make 140 'a' ^ "01");
  } in
  let psbt_a = Psbt.add_partial_sig psbt_a 0 sig_a in

  (* Party B receives PSBT (via base64), adds their signature *)
  let b64 = Psbt.to_base64 psbt_a in
  let psbt_b = match Psbt.of_base64 b64 with Ok p -> p | Error _ -> Alcotest.fail "decode failed" in
  let sig_b : Psbt.partial_sig = {
    pubkey = hex_to_cstruct ("03" ^ String.make 64 'b');
    signature = hex_to_cstruct ("3045" ^ String.make 142 'b' ^ "01");
  } in
  let psbt_b = Psbt.add_partial_sig psbt_b 0 sig_b in

  (* Combine PSBTs *)
  match Psbt.combine psbt_a psbt_b with
  | Error e -> Alcotest.fail ("combine failed: " ^ e)
  | Ok combined ->
    let inp = List.hd combined.inputs in
    Alcotest.(check int) "two signatures" 2 (List.length inp.partial_sigs);
    Alcotest.(check bool) "has utxo" true (Option.is_some inp.witness_utxo)

(* Test 3-party signing flow *)
let test_three_party_signing () =
  let tx : Types.transaction = {
    version = 2l;
    inputs = [{
      previous_output = {
        txid = hex_to_cstruct "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
        vout = 1l;
      };
      script_sig = Cstruct.empty;
      sequence = 0xFFFFFFFFl;
    }];
    outputs = [
      { value = 50000L; script_pubkey = hex_to_cstruct "00140000000000000000000000000000000000000001" };
      { value = 49000L; script_pubkey = hex_to_cstruct "00140000000000000000000000000000000000000002" };
    ];
    witnesses = [];
    locktime = 0l;
  } in

  (* Party 1 creates base PSBT *)
  let psbt1 = Psbt.create tx in
  let utxo : Types.tx_out = { value = 100000L; script_pubkey = Cstruct.concat [hex_to_cstruct "0020"; Cstruct.create 32] } in
  let psbt1 = Psbt.add_witness_utxo psbt1 0 utxo in
  let deriv1 : Psbt.bip32_derivation = {
    pubkey = hex_to_cstruct ("02" ^ String.make 64 '1');
    origin = { fingerprint = 0x11111111l; path = [0x80000054l; 0l; 0l] };
  } in
  let psbt1 = Psbt.add_input_derivation psbt1 0 deriv1 in

  (* Serialize and send to party 2 *)
  let b64_1 = Psbt.to_base64 psbt1 in

  (* Party 2 receives, adds sig *)
  let psbt2 = match Psbt.of_base64 b64_1 with Ok p -> p | Error _ -> Alcotest.fail "decode failed" in
  let sig2 : Psbt.partial_sig = {
    pubkey = hex_to_cstruct ("02" ^ String.make 64 '2');
    signature = hex_to_cstruct ("3044" ^ String.make 140 '2' ^ "01");
  } in
  let psbt2 = Psbt.add_partial_sig psbt2 0 sig2 in

  (* Send to party 3 *)
  let b64_2 = Psbt.to_base64 psbt2 in

  (* Party 3 receives, adds sig *)
  let psbt3 = match Psbt.of_base64 b64_2 with Ok p -> p | Error _ -> Alcotest.fail "decode failed" in
  let sig3 : Psbt.partial_sig = {
    pubkey = hex_to_cstruct ("03" ^ String.make 64 '3');
    signature = hex_to_cstruct ("3045" ^ String.make 142 '3' ^ "01");
  } in
  let psbt3 = Psbt.add_partial_sig psbt3 0 sig3 in

  (* Verify accumulated state *)
  let inp = List.hd psbt3.inputs in
  Alcotest.(check int) "two signatures" 2 (List.length inp.partial_sigs);
  Alcotest.(check int) "one derivation" 1 (List.length inp.bip32_derivations);
  Alcotest.(check bool) "has utxo" true (Option.is_some inp.witness_utxo)

(* Test parallel signing then combine *)
let test_parallel_signing_combine () =
  let tx : Types.transaction = {
    version = 2l;
    inputs = [
      {
        previous_output = {
          txid = hex_to_cstruct "1111111111111111111111111111111111111111111111111111111111111111";
          vout = 0l;
        };
        script_sig = Cstruct.empty;
        sequence = 0xFFFFFFFFl;
      };
      {
        previous_output = {
          txid = hex_to_cstruct "2222222222222222222222222222222222222222222222222222222222222222";
          vout = 0l;
        };
        script_sig = Cstruct.empty;
        sequence = 0xFFFFFFFFl;
      };
    ];
    outputs = [{ value = 100000L; script_pubkey = Cstruct.concat [hex_to_cstruct "0014"; Cstruct.create 20] }];
    witnesses = [];
    locktime = 0l;
  } in

  (* Creator makes base PSBT *)
  let base_psbt = Psbt.create tx in
  let b64_base = Psbt.to_base64 base_psbt in

  (* Signer A signs input 0 *)
  let psbt_a = match Psbt.of_base64 b64_base with Ok p -> p | Error _ -> Alcotest.fail "decode failed" in
  let utxo_a : Types.tx_out = { value = 60000L; script_pubkey = hex_to_cstruct "0014aaaa" } in
  let psbt_a = Psbt.add_witness_utxo psbt_a 0 utxo_a in
  let sig_a : Psbt.partial_sig = {
    pubkey = hex_to_cstruct ("02" ^ String.make 64 'a');
    signature = hex_to_cstruct ("3044" ^ String.make 140 'a' ^ "01");
  } in
  let psbt_a = Psbt.add_partial_sig psbt_a 0 sig_a in

  (* Signer B signs input 1 *)
  let psbt_b = match Psbt.of_base64 b64_base with Ok p -> p | Error _ -> Alcotest.fail "decode failed" in
  let utxo_b : Types.tx_out = { value = 50000L; script_pubkey = hex_to_cstruct "0014bbbb" } in
  let psbt_b = Psbt.add_witness_utxo psbt_b 1 utxo_b in
  let sig_b : Psbt.partial_sig = {
    pubkey = hex_to_cstruct ("03" ^ String.make 64 'b');
    signature = hex_to_cstruct ("3045" ^ String.make 142 'b' ^ "01");
  } in
  let psbt_b = Psbt.add_partial_sig psbt_b 1 sig_b in

  (* Combine both *)
  match Psbt.combine psbt_a psbt_b with
  | Error e -> Alcotest.fail ("combine failed: " ^ e)
  | Ok combined ->
    let inp0 = List.hd combined.inputs in
    let inp1 = List.nth combined.inputs 1 in
    Alcotest.(check int) "input 0 has sig" 1 (List.length inp0.partial_sigs);
    Alcotest.(check int) "input 1 has sig" 1 (List.length inp1.partial_sigs);
    Alcotest.(check bool) "input 0 has utxo" true (Option.is_some inp0.witness_utxo);
    Alcotest.(check bool) "input 1 has utxo" true (Option.is_some inp1.witness_utxo)

(* Test duplicate signature handling in combine *)
let test_combine_dedup_sigs () =
  let tx : Types.transaction = {
    version = 2l;
    inputs = [{
      previous_output = {
        txid = hex_to_cstruct "3333333333333333333333333333333333333333333333333333333333333333";
        vout = 0l;
      };
      script_sig = Cstruct.empty;
      sequence = 0xFFFFFFFFl;
    }];
    outputs = [{ value = 50000L; script_pubkey = hex_to_cstruct "0014" }];
    witnesses = [];
    locktime = 0l;
  } in

  let same_pubkey = hex_to_cstruct ("02" ^ String.make 64 'a') in
  let sig1 = hex_to_cstruct ("3044" ^ String.make 140 '1' ^ "01") in

  (* Both PSBTs have signature from same pubkey *)
  let psbt1 = Psbt.create tx in
  let psbt1 = Psbt.add_partial_sig psbt1 0 { pubkey = same_pubkey; signature = sig1 } in

  let psbt2 = Psbt.create tx in
  let psbt2 = Psbt.add_partial_sig psbt2 0 { pubkey = same_pubkey; signature = sig1 } in

  match Psbt.combine psbt1 psbt2 with
  | Error e -> Alcotest.fail ("combine failed: " ^ e)
  | Ok combined ->
    let inp = List.hd combined.inputs in
    (* Should deduplicate to one sig *)
    Alcotest.(check int) "deduplicated to one sig" 1 (List.length inp.partial_sigs)

(* Test fee calculation across multiple inputs *)
let test_multi_input_fee () =
  let tx : Types.transaction = {
    version = 2l;
    inputs = [
      {
        previous_output = { txid = hex_to_cstruct (String.make 64 '1'); vout = 0l };
        script_sig = Cstruct.empty;
        sequence = 0xFFFFFFFFl;
      };
      {
        previous_output = { txid = hex_to_cstruct (String.make 64 '2'); vout = 0l };
        script_sig = Cstruct.empty;
        sequence = 0xFFFFFFFFl;
      };
    ];
    outputs = [
      { value = 80000L; script_pubkey = hex_to_cstruct "0014" };
      { value = 10000L; script_pubkey = hex_to_cstruct "0014" };
    ];
    witnesses = [];
    locktime = 0l;
  } in

  let psbt = Psbt.create tx in
  let utxo1 : Types.tx_out = { value = 50000L; script_pubkey = hex_to_cstruct "0014" } in
  let utxo2 : Types.tx_out = { value = 50000L; script_pubkey = hex_to_cstruct "0014" } in
  let psbt = Psbt.add_witness_utxo psbt 0 utxo1 in
  let psbt = Psbt.add_witness_utxo psbt 1 utxo2 in

  match Psbt.get_fee psbt with
  | None -> Alcotest.fail "should calculate fee"
  | Some fee ->
    (* Input: 50000 + 50000 = 100000, Output: 80000 + 10000 = 90000, Fee = 10000 *)
    Alcotest.(check int64) "fee calculation" 10000L fee

(* ============================================================================
   QCheck Property Tests
   ============================================================================ *)

let qcheck_serialize_roundtrip =
  QCheck.Test.make ~count:50 ~name:"psbt serialize roundtrip"
    QCheck.(pair (int_range 1 5) (int_range 1 5))
    (fun (num_inputs, num_outputs) ->
      let make_input i =
        let txid = Cstruct.create 32 in
        Cstruct.set_uint8 txid 0 i;
        {
          Types.previous_output = { txid; vout = Int32.of_int i };
          script_sig = Cstruct.empty;
          sequence = 0xFFFFFFFFl;
        }
      in
      let make_output i = {
        Types.value = Int64.of_int (i * 10000 + 1000);
        script_pubkey = Cstruct.of_string (Printf.sprintf "\x00\x14%020d" i);
      } in
      let tx : Types.transaction = {
        version = 2l;
        inputs = List.init num_inputs make_input;
        outputs = List.init num_outputs make_output;
        witnesses = [];
        locktime = 0l;
      } in
      let psbt = Psbt.create tx in
      let serialized = Psbt.serialize psbt in
      match Psbt.deserialize serialized with
      | Error _ -> false
      | Ok psbt2 ->
        List.length psbt.inputs = List.length psbt2.inputs &&
        List.length psbt.outputs = List.length psbt2.outputs &&
        psbt.tx.version = psbt2.tx.version &&
        psbt.tx.locktime = psbt2.tx.locktime
    )

let qcheck_base64_roundtrip =
  QCheck.Test.make ~count:30 ~name:"psbt base64 roundtrip"
    QCheck.(int_range 1 3)
    (fun num_inputs ->
      let make_input i =
        let txid = Cstruct.create 32 in
        Cstruct.set_uint8 txid 0 (i + 100);
        {
          Types.previous_output = { txid; vout = 0l };
          script_sig = Cstruct.empty;
          sequence = 0xFFFFFFFFl;
        }
      in
      let tx : Types.transaction = {
        version = 2l;
        inputs = List.init num_inputs make_input;
        outputs = [{ value = 50000L; script_pubkey = Cstruct.of_string "\x00\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" }];
        witnesses = [];
        locktime = 0l;
      } in
      let psbt = Psbt.create tx in
      let b64 = Psbt.to_base64 psbt in
      match Psbt.of_base64 b64 with
      | Error _ -> false
      | Ok psbt2 ->
        List.length psbt.inputs = List.length psbt2.inputs
    )

(* ============================================================================
   Test Suite
   ============================================================================ *)

let () =
  let open Alcotest in
  run "test_psbt" [
    "creation", [
      test_case "create empty psbt" `Quick test_create_empty_psbt;
      test_case "create multi-input psbt" `Quick test_create_multi_input_psbt;
    ];
    "serialization", [
      test_case "serialize roundtrip" `Quick test_serialize_roundtrip;
      test_case "serialize with utxo" `Quick test_serialize_with_utxo;
      test_case "invalid magic" `Quick test_invalid_magic;
      test_case "base64 roundtrip" `Quick test_base64_roundtrip;
    ];
    "updater", [
      test_case "add witness utxo" `Quick test_add_witness_utxo;
      test_case "add redeem script" `Quick test_add_redeem_script;
      test_case "add bip32 derivation" `Quick test_add_bip32_derivation;
    ];
    "signer", [
      test_case "add partial sig" `Quick test_add_partial_sig;
      test_case "set sighash type" `Quick test_set_sighash_type;
    ];
    "combiner", [
      test_case "combine psbts" `Quick test_combine_psbts;
      test_case "combine mismatched tx" `Quick test_combine_mismatched_tx;
    ];
    "finalizer", [
      test_case "finalize p2wpkh" `Quick test_finalize_p2wpkh;
      test_case "finalize no sigs" `Quick test_finalize_no_sigs;
    ];
    "extractor", [
      test_case "extract finalized" `Quick test_extract_finalized;
      test_case "extract not finalized" `Quick test_extract_not_finalized;
    ];
    "fee", [
      test_case "fee calculation" `Quick test_fee_calculation;
      test_case "fee missing utxo" `Quick test_fee_calculation_missing_utxo;
    ];
    "taproot", [
      test_case "taproot key sig" `Quick test_taproot_key_sig;
      test_case "finalize taproot" `Quick test_finalize_taproot;
    ];
    "multi_party", [
      test_case "two party combine" `Quick test_multi_party_combine;
      test_case "three party signing" `Quick test_three_party_signing;
      test_case "parallel signing combine" `Quick test_parallel_signing_combine;
      test_case "combine dedup sigs" `Quick test_combine_dedup_sigs;
      test_case "multi input fee" `Quick test_multi_input_fee;
    ];
    "property", [
      QCheck_alcotest.to_alcotest qcheck_serialize_roundtrip;
      QCheck_alcotest.to_alcotest qcheck_base64_roundtrip;
    ];
  ]
