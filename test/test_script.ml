(* Tests for Bitcoin Script interpreter *)

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
let cstruct_to_hex cs =
  let buf = Buffer.create (Cstruct.length cs * 2) in
  for i = 0 to Cstruct.length cs - 1 do
    Buffer.add_string buf (Printf.sprintf "%02x" (Cstruct.get_uint8 cs i))
  done;
  Buffer.contents buf

(* Create a minimal transaction for testing *)
let make_test_tx () : Types.transaction =
  {
    Types.version = 1l;
    inputs = [{
      previous_output = {
        txid = Types.zero_hash;
        vout = 0l;
      };
      script_sig = Cstruct.create 0;
      sequence = 0xFFFFFFFFl;
    }];
    outputs = [{
      value = 0L;
      script_pubkey = Cstruct.create 0;
    }];
    witnesses = [];
    locktime = 0l;
  }

(* ============================================================================
   Script Number Tests
   ============================================================================ *)

let test_script_num_zero () =
  let result = Script.bytes_of_script_num 0L in
  Alcotest.(check int) "zero encodes to empty" 0 (Cstruct.length result)

let test_script_num_positive () =
  let result = Script.bytes_of_script_num 1L in
  Alcotest.(check string) "1 encodes to 01" "01" (cstruct_to_hex result)

let test_script_num_negative () =
  let result = Script.bytes_of_script_num (-1L) in
  Alcotest.(check string) "-1 encodes to 81" "81" (cstruct_to_hex result)

let test_script_num_large_positive () =
  let result = Script.bytes_of_script_num 255L in
  (* 255 = 0xFF but that has sign bit set, so we need extra byte *)
  Alcotest.(check string) "255 encodes to ff00" "ff00" (cstruct_to_hex result)

let test_script_num_decode_empty () =
  let result = Script.script_num_of_bytes (Cstruct.create 0) in
  Alcotest.(check int64) "empty decodes to 0" 0L result

let test_script_num_decode_positive () =
  let result = Script.script_num_of_bytes (hex_to_cstruct "01") in
  Alcotest.(check int64) "01 decodes to 1" 1L result

let test_script_num_decode_negative () =
  let result = Script.script_num_of_bytes (hex_to_cstruct "81") in
  Alcotest.(check int64) "81 decodes to -1" (-1L) result

let test_script_num_roundtrip () =
  let values = [0L; 1L; -1L; 127L; 128L; -128L; 255L; 256L; 32767L; -32768L] in
  List.iter (fun n ->
    let encoded = Script.bytes_of_script_num n in
    let decoded = Script.script_num_of_bytes encoded in
    Alcotest.(check int64) (Printf.sprintf "roundtrip %Ld" n) n decoded
  ) values

(* ============================================================================
   Script Parsing Tests
   ============================================================================ *)

let test_parse_empty_script () =
  let ops = Script.parse_script (Cstruct.create 0) in
  Alcotest.(check int) "empty script" 0 (List.length ops)

let test_parse_op_0 () =
  let script = hex_to_cstruct "00" in
  let ops = Script.parse_script script in
  Alcotest.(check int) "OP_0 parses" 1 (List.length ops);
  match List.hd ops with
  | Script.OP_0 -> ()
  | _ -> Alcotest.fail "Expected OP_0"

let test_parse_op_1_through_16 () =
  (* OP_1 = 0x51, OP_16 = 0x60 *)
  for i = 1 to 16 do
    let script = hex_to_cstruct (Printf.sprintf "%02x" (0x50 + i)) in
    let ops = Script.parse_script script in
    Alcotest.(check int) (Printf.sprintf "OP_%d parses" i) 1 (List.length ops)
  done

let test_parse_pushdata () =
  (* Push 3 bytes: 0xaabbcc *)
  let script = hex_to_cstruct "03aabbcc" in
  let ops = Script.parse_script script in
  Alcotest.(check int) "pushdata parses" 1 (List.length ops);
  match List.hd ops with
  | Script.OP_PUSHDATA data ->
    Alcotest.(check string) "pushed data" "aabbcc" (cstruct_to_hex data)
  | _ -> Alcotest.fail "Expected OP_PUSHDATA"

let test_parse_pushdata1 () =
  (* OP_PUSHDATA1 (0x4c) followed by 1-byte length *)
  let script = hex_to_cstruct "4c03aabbcc" in
  let ops = Script.parse_script script in
  Alcotest.(check int) "pushdata1 parses" 1 (List.length ops);
  match List.hd ops with
  | Script.OP_PUSHDATA data ->
    Alcotest.(check string) "pushed data" "aabbcc" (cstruct_to_hex data)
  | _ -> Alcotest.fail "Expected OP_PUSHDATA"

let test_parse_p2pkh_pubkey_script () =
  (* Standard P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG *)
  let script = hex_to_cstruct "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac" in
  let ops = Script.parse_script script in
  Alcotest.(check int) "P2PKH has 5 ops" 5 (List.length ops);
  match ops with
  | [Script.OP_DUP; Script.OP_HASH160; Script.OP_PUSHDATA _; Script.OP_EQUALVERIFY; Script.OP_CHECKSIG] -> ()
  | _ -> Alcotest.fail "Expected P2PKH pattern"

(* ============================================================================
   Script Classification Tests
   ============================================================================ *)

let test_classify_p2pkh () =
  let script = hex_to_cstruct "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac" in
  match Script.classify_script script with
  | Script.P2PKH_script _ -> ()
  | _ -> Alcotest.fail "Expected P2PKH_script"

let test_classify_p2sh () =
  let script = hex_to_cstruct "a914e8c300c87986efa84c37c0519929019ef86eb5b487" in
  match Script.classify_script script with
  | Script.P2SH_script _ -> ()
  | _ -> Alcotest.fail "Expected P2SH_script"

let test_classify_p2wpkh () =
  let script = hex_to_cstruct "0014751e76e8199196d454941c45d1b3a323f1433bd6" in
  match Script.classify_script script with
  | Script.P2WPKH_script _ -> ()
  | _ -> Alcotest.fail "Expected P2WPKH_script"

let test_classify_p2wsh () =
  let script = hex_to_cstruct ("0020" ^ String.make 64 '0') in
  match Script.classify_script script with
  | Script.P2WSH_script _ -> ()
  | _ -> Alcotest.fail "Expected P2WSH_script"

let test_classify_p2tr () =
  let script = hex_to_cstruct ("5120" ^ String.make 64 '0') in
  match Script.classify_script script with
  | Script.P2TR_script _ -> ()
  | _ -> Alcotest.fail "Expected P2TR_script"

let test_classify_op_return () =
  let script = hex_to_cstruct "6a0568656c6c6f" in (* OP_RETURN "hello" *)
  match Script.classify_script script with
  | Script.OP_RETURN_data _ -> ()
  | _ -> Alcotest.fail "Expected OP_RETURN_data"

(* ============================================================================
   Simple Script Execution Tests
   ============================================================================ *)

let eval_simple_script script =
  let tx = make_test_tx () in
  let st = Script.create_eval_state ~tx ~input_index:0 ~amount:0L ~flags:0
             ~sig_version:Script.SigVersionBase in
  Script.eval_script st (hex_to_cstruct script)

let test_eval_op_1 () =
  match eval_simple_script "51" with (* OP_1 *)
  | Ok true -> ()
  | Ok false -> Alcotest.fail "Expected true"
  | Error e -> Alcotest.fail e

let test_eval_op_0 () =
  match eval_simple_script "00" with (* OP_0 *)
  | Ok false -> ()  (* OP_0 pushes empty = false *)
  | Ok true -> Alcotest.fail "Expected false"
  | Error e -> Alcotest.fail e

let test_eval_op_add () =
  (* OP_2 OP_3 OP_ADD -> 5 *)
  match eval_simple_script "525393" with
  | Ok true -> ()  (* 5 is truthy *)
  | Ok false -> Alcotest.fail "Expected true"
  | Error e -> Alcotest.fail e

let test_eval_op_sub () =
  (* OP_5 OP_3 OP_SUB -> 2 *)
  match eval_simple_script "555394" with
  | Ok true -> ()
  | Ok false -> Alcotest.fail "Expected true"
  | Error e -> Alcotest.fail e

let test_eval_op_equal_true () =
  (* OP_2 OP_2 OP_EQUAL -> true *)
  match eval_simple_script "525287" with
  | Ok true -> ()
  | Ok false -> Alcotest.fail "Expected true"
  | Error e -> Alcotest.fail e

let test_eval_op_equal_false () =
  (* OP_2 OP_3 OP_EQUAL -> false *)
  match eval_simple_script "525387" with
  | Ok false -> ()
  | Ok true -> Alcotest.fail "Expected false"
  | Error e -> Alcotest.fail e

let test_eval_op_dup () =
  (* OP_5 OP_DUP OP_ADD -> 10 *)
  match eval_simple_script "557693" with
  | Ok true -> ()
  | Ok false -> Alcotest.fail "Expected true"
  | Error e -> Alcotest.fail e

let test_eval_op_drop () =
  (* OP_1 OP_2 OP_DROP -> 1 *)
  match eval_simple_script "515275" with
  | Ok true -> ()
  | Ok false -> Alcotest.fail "Expected true"
  | Error e -> Alcotest.fail e

let test_eval_op_swap () =
  (* OP_1 OP_2 OP_SWAP -> stack is [1, 2], swap -> [2, 1], top is 1 *)
  match eval_simple_script "51527c" with
  | Ok true -> ()
  | Ok false -> Alcotest.fail "Expected true"
  | Error e -> Alcotest.fail e

let test_eval_op_verify_success () =
  (* OP_1 OP_VERIFY OP_1 -> succeeds *)
  match eval_simple_script "516951" with
  | Ok true -> ()
  | Ok false -> Alcotest.fail "Expected true"
  | Error e -> Alcotest.fail e

let test_eval_op_verify_fail () =
  (* OP_0 OP_VERIFY -> fails *)
  match eval_simple_script "0069" with
  | Ok _ -> Alcotest.fail "Should have failed"
  | Error _ -> ()

let test_eval_op_return () =
  (* OP_RETURN immediately fails *)
  match eval_simple_script "6a" with
  | Ok _ -> Alcotest.fail "Should have failed"
  | Error _ -> ()

(* ============================================================================
   Control Flow Tests
   ============================================================================ *)

let test_eval_if_true () =
  (* OP_1 OP_IF OP_2 OP_ENDIF -> 2 *)
  (* 51=OP_1, 63=OP_IF, 52=OP_2, 68=OP_ENDIF *)
  match eval_simple_script "51635268" with
  | Ok true -> ()
  | Ok false -> Alcotest.fail "Expected true"
  | Error e -> Alcotest.fail ("If true failed: " ^ e)

let test_eval_if_false () =
  (* OP_0 OP_IF OP_2 OP_ENDIF OP_3 -> 3 (skips the 2) *)
  (* 00=OP_0, 63=OP_IF, 52=OP_2, 68=OP_ENDIF, 53=OP_3 *)
  match eval_simple_script "0063526853" with
  | Ok true -> ()
  | Ok false -> Alcotest.fail "Expected true"
  | Error e -> Alcotest.fail ("If false failed: " ^ e)

let test_eval_if_else () =
  (* OP_0 OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF -> 3 *)
  (* 00=OP_0, 63=OP_IF, 52=OP_2, 67=OP_ELSE, 53=OP_3, 68=OP_ENDIF *)
  match eval_simple_script "006352675368" with
  | Ok true -> ()
  | Ok false -> Alcotest.fail "Expected true"
  | Error e -> Alcotest.fail ("If else failed: " ^ e)

let test_eval_notif () =
  (* OP_0 OP_NOTIF OP_2 OP_ENDIF -> 2 (executes because condition is false) *)
  (* 00=OP_0, 64=OP_NOTIF, 52=OP_2, 68=OP_ENDIF *)
  match eval_simple_script "00645268" with
  | Ok true -> ()
  | Ok false -> Alcotest.fail "Expected true"
  | Error e -> Alcotest.fail ("Notif failed: " ^ e)

let test_eval_nested_if () =
  (* OP_1 OP_IF OP_1 OP_IF OP_5 OP_ENDIF OP_ENDIF -> 5 *)
  (* 51=OP_1, 63=OP_IF, 51=OP_1, 63=OP_IF, 55=OP_5, 68=OP_ENDIF, 68=OP_ENDIF *)
  match eval_simple_script "51635163556868" with
  | Ok true -> ()
  | Ok false -> Alcotest.fail "Expected true"
  | Error e -> Alcotest.fail ("Nested if failed: " ^ e)

let test_eval_op_return_in_false_branch () =
  (* OP_0 OP_IF OP_RETURN OP_ENDIF OP_1 -> should NOT fail, returns 1 *)
  match eval_simple_script "00636a6851" with
  | Ok true -> ()
  | Ok false -> Alcotest.fail "Expected true"
  | Error e -> Alcotest.fail ("OP_RETURN in false branch shouldn't fail: " ^ e)

(* ============================================================================
   Hash Operation Tests
   ============================================================================ *)

let test_eval_hash160 () =
  (* Push "hello", then OP_HASH160 *)
  let tx = make_test_tx () in
  let st = Script.create_eval_state ~tx ~input_index:0 ~amount:0L ~flags:0
             ~sig_version:Script.SigVersionBase in
  (* 0568656c6c6f = push 5 bytes "hello" *)
  let script = hex_to_cstruct "0568656c6c6fa9" in
  match Script.eval_script st script with
  | Ok true ->
    (* Check the hash on the stack *)
    begin match st.stack with
    | [hash] ->
      (* HASH160("hello") = b6a9c8c230722b7c748331a8b450f05566dc7d0f *)
      let expected = "b6a9c8c230722b7c748331a8b450f05566dc7d0f" in
      Alcotest.(check string) "hash160 result" expected (cstruct_to_hex hash)
    | _ -> Alcotest.fail "Expected single element on stack"
    end
  | Ok false -> Alcotest.fail "Expected truthy result"
  | Error e -> Alcotest.fail e

let test_eval_sha256 () =
  (* Push "hello", then OP_SHA256 *)
  let tx = make_test_tx () in
  let st = Script.create_eval_state ~tx ~input_index:0 ~amount:0L ~flags:0
             ~sig_version:Script.SigVersionBase in
  let script = hex_to_cstruct "0568656c6c6fa8" in
  match Script.eval_script st script with
  | Ok true ->
    begin match st.stack with
    | [hash] ->
      let expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" in
      Alcotest.(check string) "sha256 result" expected (cstruct_to_hex hash)
    | _ -> Alcotest.fail "Expected single element on stack"
    end
  | Ok false -> Alcotest.fail "Expected truthy result"
  | Error e -> Alcotest.fail e

(* ============================================================================
   Comparison Tests
   ============================================================================ *)

let test_eval_lessthan () =
  (* OP_2 OP_3 OP_LESSTHAN -> 1 (2 < 3) *)
  match eval_simple_script "52539f" with
  | Ok true -> ()
  | Ok false -> Alcotest.fail "Expected true"
  | Error e -> Alcotest.fail e

let test_eval_greaterthan () =
  (* OP_3 OP_2 OP_GREATERTHAN -> 1 (3 > 2) *)
  match eval_simple_script "5352a0" with
  | Ok true -> ()
  | Ok false -> Alcotest.fail "Expected true"
  | Error e -> Alcotest.fail e

let test_eval_min () =
  (* OP_5 OP_3 OP_MIN -> 3 *)
  match eval_simple_script "5553a3" with
  | Ok true -> ()
  | Ok false -> Alcotest.fail "Expected true"
  | Error e -> Alcotest.fail e

let test_eval_max () =
  (* OP_5 OP_3 OP_MAX -> 5 *)
  match eval_simple_script "5553a4" with
  | Ok true -> ()
  | Ok false -> Alcotest.fail "Expected true"
  | Error e -> Alcotest.fail e

let test_eval_within () =
  (* OP_3 OP_1 OP_5 OP_WITHIN -> 1 (3 is within [1,5)) *)
  match eval_simple_script "535155a5" with
  | Ok true -> ()
  | Ok false -> Alcotest.fail "Expected true"
  | Error e -> Alcotest.fail e

(* ============================================================================
   Stack Manipulation Tests
   ============================================================================ *)

let test_eval_2dup () =
  (* OP_1 OP_2 OP_2DUP -> stack has 4 elements [1,2,1,2] *)
  (* Just verify we get a truthy result (top element is 2) *)
  let tx = make_test_tx () in
  let st = Script.create_eval_state ~tx ~input_index:0 ~amount:0L ~flags:0
             ~sig_version:Script.SigVersionBase in
  let script = hex_to_cstruct "51526e" in (* OP_1 OP_2 OP_2DUP *)
  match Script.eval_script st script with
  | Ok true ->
    Alcotest.(check int) "stack size after 2dup" 4 (List.length st.stack)
  | Ok false -> Alcotest.fail "Expected true"
  | Error e -> Alcotest.fail e

let test_eval_3dup () =
  (* OP_1 OP_2 OP_3 OP_3DUP -> stack has 6 elements *)
  let tx = make_test_tx () in
  let st = Script.create_eval_state ~tx ~input_index:0 ~amount:0L ~flags:0
             ~sig_version:Script.SigVersionBase in
  let script = hex_to_cstruct "5152536f" in
  match Script.eval_script st script with
  | Ok true ->
    Alcotest.(check int) "stack size" 6 (List.length st.stack)
  | Ok false -> Alcotest.fail "Expected true"
  | Error e -> Alcotest.fail e

let test_eval_rot () =
  (* OP_1 OP_2 OP_3 OP_ROT -> stack is [1,3,2] with 2 on top *)
  let tx = make_test_tx () in
  let st = Script.create_eval_state ~tx ~input_index:0 ~amount:0L ~flags:0
             ~sig_version:Script.SigVersionBase in
  let script = hex_to_cstruct "5152537b" in
  match Script.eval_script st script with
  | Ok true ->
    (* Top should be 1 (rot moves third to top) *)
    begin match st.stack with
    | top :: _ ->
      Alcotest.(check int64) "rot result" 1L (Script.script_num_of_bytes top)
    | _ -> Alcotest.fail "Stack empty"
    end
  | Ok false -> Alcotest.fail "Expected true"
  | Error e -> Alcotest.fail e

let test_eval_pick () =
  (* OP_1 OP_2 OP_3 OP_2 OP_PICK -> picks element at index 2 (which is 1) *)
  (* Stack: [1,2,3], push 2, pick at index 2 -> copies 1 to top *)
  let tx = make_test_tx () in
  let st = Script.create_eval_state ~tx ~input_index:0 ~amount:0L ~flags:0
             ~sig_version:Script.SigVersionBase in
  let script = hex_to_cstruct "5152535279" in (* OP_1 OP_2 OP_3 OP_2 OP_PICK *)
  match Script.eval_script st script with
  | Ok true ->
    begin match st.stack with
    | top :: _ ->
      Alcotest.(check int64) "pick result" 1L (Script.script_num_of_bytes top)
    | _ -> Alcotest.fail "Stack empty"
    end
  | Ok false -> Alcotest.fail "Expected true"
  | Error e -> Alcotest.fail e

let test_eval_size () =
  (* Push 5 bytes, OP_SIZE -> should be 5 *)
  let tx = make_test_tx () in
  let st = Script.create_eval_state ~tx ~input_index:0 ~amount:0L ~flags:0
             ~sig_version:Script.SigVersionBase in
  let script = hex_to_cstruct "0568656c6c6f82" in
  match Script.eval_script st script with
  | Ok true ->
    begin match st.stack with
    | size_elem :: _ ->
      Alcotest.(check int64) "size" 5L (Script.script_num_of_bytes size_elem)
    | _ -> Alcotest.fail "Stack empty"
    end
  | Ok false -> Alcotest.fail "Expected true"
  | Error e -> Alcotest.fail e

let test_eval_depth () =
  (* OP_1 OP_2 OP_3 OP_DEPTH -> 3 *)
  let tx = make_test_tx () in
  let st = Script.create_eval_state ~tx ~input_index:0 ~amount:0L ~flags:0
             ~sig_version:Script.SigVersionBase in
  let script = hex_to_cstruct "51525374" in
  match Script.eval_script st script with
  | Ok true ->
    begin match st.stack with
    | depth :: _ ->
      Alcotest.(check int64) "depth" 3L (Script.script_num_of_bytes depth)
    | _ -> Alcotest.fail "Stack empty"
    end
  | Ok false -> Alcotest.fail "Expected true"
  | Error e -> Alcotest.fail e

(* ============================================================================
   Altstack Tests
   ============================================================================ *)

let test_eval_altstack () =
  (* OP_1 OP_TOALTSTACK OP_2 OP_FROMALTSTACK OP_ADD -> 3 *)
  match eval_simple_script "516b526c93" with
  | Ok true -> ()
  | Ok false -> Alcotest.fail "Expected true"
  | Error e -> Alcotest.fail e

(* ============================================================================
   Boolean Logic Tests
   ============================================================================ *)

let test_eval_booland () =
  (* OP_1 OP_1 OP_BOOLAND -> 1 *)
  match eval_simple_script "51519a" with
  | Ok true -> ()
  | Ok false -> Alcotest.fail "Expected true"
  | Error e -> Alcotest.fail e

let test_eval_booland_false () =
  (* OP_1 OP_0 OP_BOOLAND -> 0 *)
  match eval_simple_script "51009a" with
  | Ok false -> ()
  | Ok true -> Alcotest.fail "Expected false"
  | Error e -> Alcotest.fail e

let test_eval_boolor () =
  (* OP_1 OP_0 OP_BOOLOR -> 1 *)
  match eval_simple_script "51009b" with
  | Ok true -> ()
  | Ok false -> Alcotest.fail "Expected true"
  | Error e -> Alcotest.fail e

let test_eval_not () =
  (* OP_0 OP_NOT -> 1 *)
  match eval_simple_script "0091" with
  | Ok true -> ()
  | Ok false -> Alcotest.fail "Expected true"
  | Error e -> Alcotest.fail e

let test_eval_0notequal () =
  (* OP_5 OP_0NOTEQUAL -> 1 *)
  match eval_simple_script "5592" with
  | Ok true -> ()
  | Ok false -> Alcotest.fail "Expected true"
  | Error e -> Alcotest.fail e

(* ============================================================================
   Error Condition Tests
   ============================================================================ *)

let test_eval_stack_underflow () =
  (* OP_DROP on empty stack *)
  match eval_simple_script "75" with
  | Ok _ -> Alcotest.fail "Should have failed"
  | Error _ -> ()

let test_eval_unbalanced_if () =
  (* OP_1 OP_IF without ENDIF *)
  match eval_simple_script "5163" with
  | Ok _ -> Alcotest.fail "Should have failed"
  | Error _ -> ()

let test_eval_disabled_opcode () =
  (* OP_VERIF (0x65) is disabled *)
  match eval_simple_script "5165" with
  | Ok _ -> Alcotest.fail "Should have failed"
  | Error _ -> ()

(* ============================================================================
   Test Suites
   ============================================================================ *)

let script_num_tests = [
  Alcotest.test_case "script_num zero" `Quick test_script_num_zero;
  Alcotest.test_case "script_num positive" `Quick test_script_num_positive;
  Alcotest.test_case "script_num negative" `Quick test_script_num_negative;
  Alcotest.test_case "script_num large positive" `Quick test_script_num_large_positive;
  Alcotest.test_case "script_num decode empty" `Quick test_script_num_decode_empty;
  Alcotest.test_case "script_num decode positive" `Quick test_script_num_decode_positive;
  Alcotest.test_case "script_num decode negative" `Quick test_script_num_decode_negative;
  Alcotest.test_case "script_num roundtrip" `Quick test_script_num_roundtrip;
]

let parsing_tests = [
  Alcotest.test_case "parse empty script" `Quick test_parse_empty_script;
  Alcotest.test_case "parse OP_0" `Quick test_parse_op_0;
  Alcotest.test_case "parse OP_1-16" `Quick test_parse_op_1_through_16;
  Alcotest.test_case "parse pushdata" `Quick test_parse_pushdata;
  Alcotest.test_case "parse pushdata1" `Quick test_parse_pushdata1;
  Alcotest.test_case "parse P2PKH script" `Quick test_parse_p2pkh_pubkey_script;
]

let classification_tests = [
  Alcotest.test_case "classify P2PKH" `Quick test_classify_p2pkh;
  Alcotest.test_case "classify P2SH" `Quick test_classify_p2sh;
  Alcotest.test_case "classify P2WPKH" `Quick test_classify_p2wpkh;
  Alcotest.test_case "classify P2WSH" `Quick test_classify_p2wsh;
  Alcotest.test_case "classify P2TR" `Quick test_classify_p2tr;
  Alcotest.test_case "classify OP_RETURN" `Quick test_classify_op_return;
]

let simple_execution_tests = [
  Alcotest.test_case "eval OP_1" `Quick test_eval_op_1;
  Alcotest.test_case "eval OP_0" `Quick test_eval_op_0;
  Alcotest.test_case "eval OP_ADD" `Quick test_eval_op_add;
  Alcotest.test_case "eval OP_SUB" `Quick test_eval_op_sub;
  Alcotest.test_case "eval OP_EQUAL true" `Quick test_eval_op_equal_true;
  Alcotest.test_case "eval OP_EQUAL false" `Quick test_eval_op_equal_false;
  Alcotest.test_case "eval OP_DUP" `Quick test_eval_op_dup;
  Alcotest.test_case "eval OP_DROP" `Quick test_eval_op_drop;
  Alcotest.test_case "eval OP_SWAP" `Quick test_eval_op_swap;
  Alcotest.test_case "eval OP_VERIFY success" `Quick test_eval_op_verify_success;
  Alcotest.test_case "eval OP_VERIFY fail" `Quick test_eval_op_verify_fail;
  Alcotest.test_case "eval OP_RETURN" `Quick test_eval_op_return;
]

let control_flow_tests = [
  Alcotest.test_case "eval IF true" `Quick test_eval_if_true;
  Alcotest.test_case "eval IF false" `Quick test_eval_if_false;
  Alcotest.test_case "eval IF ELSE" `Quick test_eval_if_else;
  Alcotest.test_case "eval NOTIF" `Quick test_eval_notif;
  Alcotest.test_case "eval nested IF" `Quick test_eval_nested_if;
  Alcotest.test_case "OP_RETURN in false branch" `Quick test_eval_op_return_in_false_branch;
]

let hash_tests = [
  Alcotest.test_case "eval HASH160" `Quick test_eval_hash160;
  Alcotest.test_case "eval SHA256" `Quick test_eval_sha256;
]

let comparison_tests = [
  Alcotest.test_case "eval LESSTHAN" `Quick test_eval_lessthan;
  Alcotest.test_case "eval GREATERTHAN" `Quick test_eval_greaterthan;
  Alcotest.test_case "eval MIN" `Quick test_eval_min;
  Alcotest.test_case "eval MAX" `Quick test_eval_max;
  Alcotest.test_case "eval WITHIN" `Quick test_eval_within;
]

let stack_tests = [
  Alcotest.test_case "eval 2DUP" `Quick test_eval_2dup;
  Alcotest.test_case "eval 3DUP" `Quick test_eval_3dup;
  Alcotest.test_case "eval ROT" `Quick test_eval_rot;
  Alcotest.test_case "eval PICK" `Quick test_eval_pick;
  Alcotest.test_case "eval SIZE" `Quick test_eval_size;
  Alcotest.test_case "eval DEPTH" `Quick test_eval_depth;
  Alcotest.test_case "eval altstack" `Quick test_eval_altstack;
]

let boolean_tests = [
  Alcotest.test_case "eval BOOLAND" `Quick test_eval_booland;
  Alcotest.test_case "eval BOOLAND false" `Quick test_eval_booland_false;
  Alcotest.test_case "eval BOOLOR" `Quick test_eval_boolor;
  Alcotest.test_case "eval NOT" `Quick test_eval_not;
  Alcotest.test_case "eval 0NOTEQUAL" `Quick test_eval_0notequal;
]

let error_tests = [
  Alcotest.test_case "stack underflow" `Quick test_eval_stack_underflow;
  Alcotest.test_case "unbalanced IF" `Quick test_eval_unbalanced_if;
  Alcotest.test_case "disabled opcode" `Quick test_eval_disabled_opcode;
]

let () = Alcotest.run "test_script" [
  ("script_num", script_num_tests);
  ("parsing", parsing_tests);
  ("classification", classification_tests);
  ("simple_execution", simple_execution_tests);
  ("control_flow", control_flow_tests);
  ("hash", hash_tests);
  ("comparison", comparison_tests);
  ("stack", stack_tests);
  ("boolean", boolean_tests);
  ("error", error_tests);
]
