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
  | Script.OP_PUSHDATA (_, data) ->
    Alcotest.(check string) "pushed data" "aabbcc" (cstruct_to_hex data)
  | _ -> Alcotest.fail "Expected OP_PUSHDATA"

let test_parse_pushdata1 () =
  (* OP_PUSHDATA1 (0x4c) followed by 1-byte length *)
  let script = hex_to_cstruct "4c03aabbcc" in
  let ops = Script.parse_script script in
  Alcotest.(check int) "pushdata1 parses" 1 (List.length ops);
  match List.hd ops with
  | Script.OP_PUSHDATA (_, data) ->
    Alcotest.(check string) "pushed data" "aabbcc" (cstruct_to_hex data)
  | _ -> Alcotest.fail "Expected OP_PUSHDATA"

let test_parse_p2pkh_pubkey_script () =
  (* Standard P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG *)
  let script = hex_to_cstruct "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac" in
  let ops = Script.parse_script script in
  Alcotest.(check int) "P2PKH has 5 ops" 5 (List.length ops);
  match ops with
  | [Script.OP_DUP; Script.OP_HASH160; Script.OP_PUSHDATA (_, _); Script.OP_EQUALVERIFY; Script.OP_CHECKSIG] -> ()
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
             ~sig_version:Script.SigVersionBase () in
  match Script.eval_script st (hex_to_cstruct script) with
  | Error e -> Error e
  | Ok () ->
    match st.stack with
    | [] -> Ok false
    | top :: _ -> Ok (Script.is_true top)

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
             ~sig_version:Script.SigVersionBase () in
  (* 0568656c6c6f = push 5 bytes "hello" *)
  let script = hex_to_cstruct "0568656c6c6fa9" in
  match Script.eval_script st script with
  | Ok () ->
    (* Check the hash on the stack *)
    begin match st.stack with
    | [hash] ->
      (* HASH160("hello") = b6a9c8c230722b7c748331a8b450f05566dc7d0f *)
      let expected = "b6a9c8c230722b7c748331a8b450f05566dc7d0f" in
      Alcotest.(check string) "hash160 result" expected (cstruct_to_hex hash)
    | _ -> Alcotest.fail "Expected single element on stack"
    end
  | Error e -> Alcotest.fail e

let test_eval_sha256 () =
  (* Push "hello", then OP_SHA256 *)
  let tx = make_test_tx () in
  let st = Script.create_eval_state ~tx ~input_index:0 ~amount:0L ~flags:0
             ~sig_version:Script.SigVersionBase () in
  let script = hex_to_cstruct "0568656c6c6fa8" in
  match Script.eval_script st script with
  | Ok () ->
    begin match st.stack with
    | [hash] ->
      let expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" in
      Alcotest.(check string) "sha256 result" expected (cstruct_to_hex hash)
    | _ -> Alcotest.fail "Expected single element on stack"
    end
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
             ~sig_version:Script.SigVersionBase () in
  let script = hex_to_cstruct "51526e" in (* OP_1 OP_2 OP_2DUP *)
  match Script.eval_script st script with
  | Ok () ->
    Alcotest.(check int) "stack size after 2dup" 4 (List.length st.stack)
  | Error e -> Alcotest.fail e

let test_eval_3dup () =
  (* OP_1 OP_2 OP_3 OP_3DUP -> stack has 6 elements *)
  let tx = make_test_tx () in
  let st = Script.create_eval_state ~tx ~input_index:0 ~amount:0L ~flags:0
             ~sig_version:Script.SigVersionBase () in
  let script = hex_to_cstruct "5152536f" in
  match Script.eval_script st script with
  | Ok () ->
    Alcotest.(check int) "stack size" 6 (List.length st.stack)
  | Error e -> Alcotest.fail e

let test_eval_rot () =
  (* OP_1 OP_2 OP_3 OP_ROT -> stack is [1,3,2] with 2 on top *)
  let tx = make_test_tx () in
  let st = Script.create_eval_state ~tx ~input_index:0 ~amount:0L ~flags:0
             ~sig_version:Script.SigVersionBase () in
  let script = hex_to_cstruct "5152537b" in
  match Script.eval_script st script with
  | Ok () ->
    (* Top should be 1 (rot moves third to top) *)
    begin match st.stack with
    | top :: _ ->
      Alcotest.(check int64) "rot result" 1L (Script.script_num_of_bytes top)
    | _ -> Alcotest.fail "Stack empty"
    end
  | Error e -> Alcotest.fail e

let test_eval_pick () =
  (* OP_1 OP_2 OP_3 OP_2 OP_PICK -> picks element at index 2 (which is 1) *)
  (* Stack: [1,2,3], push 2, pick at index 2 -> copies 1 to top *)
  let tx = make_test_tx () in
  let st = Script.create_eval_state ~tx ~input_index:0 ~amount:0L ~flags:0
             ~sig_version:Script.SigVersionBase () in
  let script = hex_to_cstruct "5152535279" in (* OP_1 OP_2 OP_3 OP_2 OP_PICK *)
  match Script.eval_script st script with
  | Ok () ->
    begin match st.stack with
    | top :: _ ->
      Alcotest.(check int64) "pick result" 1L (Script.script_num_of_bytes top)
    | _ -> Alcotest.fail "Stack empty"
    end
  | Error e -> Alcotest.fail e

let test_eval_size () =
  (* Push 5 bytes, OP_SIZE -> should be 5 *)
  let tx = make_test_tx () in
  let st = Script.create_eval_state ~tx ~input_index:0 ~amount:0L ~flags:0
             ~sig_version:Script.SigVersionBase () in
  let script = hex_to_cstruct "0568656c6c6f82" in
  match Script.eval_script st script with
  | Ok () ->
    begin match st.stack with
    | size_elem :: _ ->
      Alcotest.(check int64) "size" 5L (Script.script_num_of_bytes size_elem)
    | _ -> Alcotest.fail "Stack empty"
    end
  | Error e -> Alcotest.fail e

let test_eval_depth () =
  (* OP_1 OP_2 OP_3 OP_DEPTH -> 3 *)
  let tx = make_test_tx () in
  let st = Script.create_eval_state ~tx ~input_index:0 ~amount:0L ~flags:0
             ~sig_version:Script.SigVersionBase () in
  let script = hex_to_cstruct "51525374" in
  match Script.eval_script st script with
  | Ok () ->
    begin match st.stack with
    | depth :: _ ->
      Alcotest.(check int64) "depth" 3L (Script.script_num_of_bytes depth)
    | _ -> Alcotest.fail "Stack empty"
    end
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

(* ============================================================================
   Round 5 Phase 1 - Consensus-Critical Script Fix Tests
   ============================================================================ *)

(* Helper: eval with specific flags *)
let eval_script_with_flags script_hex flags =
  let tx = make_test_tx () in
  let st = Script.create_eval_state ~tx ~input_index:0 ~amount:0L ~flags
             ~sig_version:Script.SigVersionBase () in
  match Script.eval_script st (hex_to_cstruct script_hex) with
  | Error e -> Error e
  | Ok () ->
    match st.stack with
    | [] -> Ok false
    | top :: _ -> Ok (Script.is_true top)

(* -- CONST_SCRIPTCODE: OP_CODESEPARATOR rejection -- *)

let test_codesep_rejected_with_const_scriptcode () =
  (* OP_1 OP_CODESEPARATOR should fail with CONST_SCRIPTCODE flag *)
  (* 0x51 = OP_1, 0xAB = OP_CODESEPARATOR *)
  let flags = Script.script_verify_const_scriptcode in
  match eval_script_with_flags "51ab" flags with
  | Error _ -> ()  (* Expected: error *)
  | Ok _ -> Alcotest.fail "OP_CODESEPARATOR should be rejected with CONST_SCRIPTCODE"

let test_codesep_allowed_without_const_scriptcode () =
  (* OP_1 OP_CODESEPARATOR should succeed without CONST_SCRIPTCODE flag *)
  match eval_script_with_flags "51ab" 0 with
  | Ok true -> ()
  | Ok false -> Alcotest.fail "Expected true on stack"
  | Error e -> Alcotest.fail ("Should succeed without flag: " ^ e)

let test_codesep_rejected_in_dead_branch () =
  (* OP_0 OP_IF OP_CODESEPARATOR OP_ENDIF OP_1 -- even in dead IF branch *)
  let flags = Script.script_verify_const_scriptcode in
  match eval_script_with_flags "0063ab6851" flags with
  | Error _ -> ()
  | Ok _ -> Alcotest.fail "OP_CODESEPARATOR in dead branch should still be rejected"

(* -- MINIMALDATA: check_minimal_push during execution -- *)

let test_minimaldata_empty_push_rejected () =
  (* OP_PUSHDATA1 with 0 bytes: 4c00 -- should use OP_0 *)
  let flags = Script.script_verify_minimaldata in
  match eval_script_with_flags "4c00" flags with
  | Error _ -> ()
  | Ok _ -> Alcotest.fail "Empty PUSHDATA should be rejected with MINIMALDATA"

let test_minimaldata_push1_should_use_opn () =
  (* Direct push of byte 0x05: 0105 -- should use OP_5 *)
  let flags = Script.script_verify_minimaldata in
  match eval_script_with_flags "0105" flags with
  | Error _ -> ()
  | Ok _ -> Alcotest.fail "Push of 0x05 should use OP_5 with MINIMALDATA"

let test_minimaldata_push_0x81_should_use_1negate () =
  (* Direct push of byte 0x81: 0181 -- should use OP_1NEGATE *)
  let flags = Script.script_verify_minimaldata in
  match eval_script_with_flags "0181" flags with
  | Error _ -> ()
  | Ok _ -> Alcotest.fail "Push of 0x81 should use OP_1NEGATE with MINIMALDATA"

let test_minimaldata_pushdata1_small () =
  (* PUSHDATA1 for 3 bytes: 4c03aabbcc -- should use direct push *)
  let flags = Script.script_verify_minimaldata in
  match eval_script_with_flags "4c03aabbcc" flags with
  | Error _ -> ()
  | Ok _ -> Alcotest.fail "PUSHDATA1 for 3-byte data should be rejected"

let test_minimaldata_valid_direct_push () =
  (* Direct push of 2 bytes 0xaa 0xbb: 02aabb -- valid minimal *)
  let flags = Script.script_verify_minimaldata in
  match eval_script_with_flags "02aabb" flags with
  | Ok true -> ()
  | Ok false -> Alcotest.fail "Expected true"
  | Error e -> Alcotest.fail ("Valid minimal push should succeed: " ^ e)

let test_minimaldata_no_flag () =
  (* PUSHDATA1 for 3 bytes without flag should succeed *)
  match eval_script_with_flags "4c03aabbcc" 0 with
  | Ok true -> ()
  | Ok false -> Alcotest.fail "Expected true"
  | Error e -> Alcotest.fail ("Should succeed without MINIMALDATA: " ^ e)

let test_minimaldata_opbyte_preserved_in_parsing () =
  (* Test that the opcode byte is correctly preserved: direct push vs PUSHDATA1 *)
  let script_direct = hex_to_cstruct "03aabbcc" in (* direct push of 3 bytes *)
  let ops_direct = Script.parse_script script_direct in
  (match List.hd ops_direct with
   | Script.OP_PUSHDATA (opbyte, _) ->
     Alcotest.(check int) "direct push opbyte" 3 opbyte
   | _ -> Alcotest.fail "Expected OP_PUSHDATA");
  let script_pd1 = hex_to_cstruct "4c03aabbcc" in (* PUSHDATA1 *)
  let ops_pd1 = Script.parse_script script_pd1 in
  (match List.hd ops_pd1 with
   | Script.OP_PUSHDATA (opbyte, _) ->
     Alcotest.(check int) "PUSHDATA1 opbyte" 0x4c opbyte
   | _ -> Alcotest.fail "Expected OP_PUSHDATA")

(* -- DISCOURAGE_UPGRADABLE_NOPS -- *)

let test_discourage_nop1 () =
  (* OP_1 OP_NOP1 -- should fail with discourage flag *)
  let flags = Script.script_verify_discourage_upgradable_nops in
  match eval_script_with_flags "51b0" flags with
  | Error _ -> ()
  | Ok _ -> Alcotest.fail "NOP1 should be rejected with DISCOURAGE_UPGRADABLE_NOPS"

let test_nop1_allowed_without_flag () =
  (* OP_1 OP_NOP1 -- should succeed without flag *)
  match eval_script_with_flags "51b0" 0 with
  | Ok true -> ()
  | Ok false -> Alcotest.fail "Expected true"
  | Error e -> Alcotest.fail ("NOP1 should succeed without flag: " ^ e)

let test_discourage_nop4 () =
  (* OP_1 OP_NOP4 (0xb3) *)
  let flags = Script.script_verify_discourage_upgradable_nops in
  match eval_script_with_flags "51b3" flags with
  | Error _ -> ()
  | Ok _ -> Alcotest.fail "NOP4 should be rejected with DISCOURAGE_UPGRADABLE_NOPS"

let test_discourage_nop10 () =
  (* OP_1 OP_NOP10 (0xb9) *)
  let flags = Script.script_verify_discourage_upgradable_nops in
  match eval_script_with_flags "51b9" flags with
  | Error _ -> ()
  | Ok _ -> Alcotest.fail "NOP10 should be rejected with DISCOURAGE_UPGRADABLE_NOPS"

(* -- DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM -- *)

let test_discourage_witness_v2 () =
  (* A witness v2 program: OP_2 <20 bytes> = 5214 + 20 zero bytes *)
  let tx = make_test_tx () in
  let script_pubkey = hex_to_cstruct ("5214" ^ String.make 40 '0') in
  let witness = { Types.items = [] } in
  let flags = Script.script_verify_witness lor Script.script_verify_discourage_upgradable_witness in
  match Script.verify_script ~tx ~input_index:0 ~script_pubkey
          ~script_sig:(Cstruct.create 0) ~witness ~amount:0L ~flags () with
  | Error _ -> ()
  | Ok _ -> Alcotest.fail "Witness v2 should be discouraged"

let test_witness_v2_allowed_without_flag () =
  let tx = make_test_tx () in
  let script_pubkey = hex_to_cstruct ("5214" ^ String.make 40 '0') in
  let witness = { Types.items = [] } in
  let flags = Script.script_verify_witness in
  match Script.verify_script ~tx ~input_index:0 ~script_pubkey
          ~script_sig:(Cstruct.create 0) ~witness ~amount:0L ~flags () with
  | Ok true -> ()
  | Ok false -> Alcotest.fail "Expected success"
  | Error e -> Alcotest.fail ("Should succeed without discourage flag: " ^ e)

(* -- DISCOURAGE_OP_SUCCESS flag constant -- *)

let test_discourage_op_success_flag_exists () =
  (* Just verify the flag constant is defined and non-zero *)
  Alcotest.(check bool) "flag is non-zero" true
    (Script.script_verify_discourage_op_success <> 0)

(* -- OP_PUSHDATA type roundtrip through serialize -- *)

let test_pushdata_serialize_roundtrip () =
  (* Test that serialization preserves the encoding format *)
  let script = hex_to_cstruct "4c03aabbcc" in (* PUSHDATA1 *)
  let ops = Script.parse_script script in
  let reserialized = Script.serialize_script ops in
  Alcotest.(check string) "roundtrip preserves PUSHDATA1"
    (cstruct_to_hex script) (cstruct_to_hex reserialized)

let test_pushdata_direct_serialize_roundtrip () =
  let script = hex_to_cstruct "03aabbcc" in (* direct push *)
  let ops = Script.parse_script script in
  let reserialized = Script.serialize_script ops in
  Alcotest.(check string) "roundtrip preserves direct push"
    (cstruct_to_hex script) (cstruct_to_hex reserialized)

(* ============================================================================
   Bug 7: Tapscript witness item size check
   ============================================================================ *)

let test_witness_item_size_checked_for_tapscript () =
  (* check_witness_item_sizes should enforce 520-byte limit for tapscript too *)
  let oversized_item = Cstruct.create 521 in
  let witness = { Types.items = [oversized_item] } in
  match Script.check_witness_item_sizes ~sig_version:Script.SigVersionTapscript witness with
  | Error _ -> ()  (* Expected: oversized item rejected *)
  | Ok () -> Alcotest.fail "Should reject oversized witness item in tapscript"

let test_witness_item_size_ok_for_tapscript () =
  (* A 520-byte item should be allowed *)
  let ok_item = Cstruct.create 520 in
  let witness = { Types.items = [ok_item] } in
  match Script.check_witness_item_sizes ~sig_version:Script.SigVersionTapscript witness with
  | Ok () -> ()
  | Error e -> Alcotest.fail ("Should allow 520-byte witness item: " ^ e)

(* ============================================================================
   Bug 8: DISCOURAGE_UPGRADABLE_TAPROOT_VERSION flag
   ============================================================================ *)

let test_discourage_upgradable_taproot_version_flag_exists () =
  Alcotest.(check bool) "flag is non-zero" true
    (Script.script_verify_discourage_upgradable_taproot_version <> 0)

let test_discourage_upgradable_taproot_version_flag_value () =
  Alcotest.(check int) "flag is 1 lsl 19" (1 lsl 19)
    Script.script_verify_discourage_upgradable_taproot_version

(* ============================================================================
   Bug 9: DISCOURAGE_UPGRADABLE_PUBKEYTYPE flag
   ============================================================================ *)

let test_discourage_upgradable_pubkeytype_flag_exists () =
  Alcotest.(check bool) "flag is non-zero" true
    (Script.script_verify_discourage_upgradable_pubkeytype <> 0)

let test_discourage_upgradable_pubkeytype_flag_value () =
  Alcotest.(check int) "flag is 1 lsl 20" (1 lsl 20)
    Script.script_verify_discourage_upgradable_pubkeytype

let bug7_8_9_tests = [
  Alcotest.test_case "Tapscript witness item size enforced" `Quick test_witness_item_size_checked_for_tapscript;
  Alcotest.test_case "Tapscript witness item size ok at 520" `Quick test_witness_item_size_ok_for_tapscript;
  Alcotest.test_case "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION flag exists" `Quick test_discourage_upgradable_taproot_version_flag_exists;
  Alcotest.test_case "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION flag value" `Quick test_discourage_upgradable_taproot_version_flag_value;
  Alcotest.test_case "DISCOURAGE_UPGRADABLE_PUBKEYTYPE flag exists" `Quick test_discourage_upgradable_pubkeytype_flag_exists;
  Alcotest.test_case "DISCOURAGE_UPGRADABLE_PUBKEYTYPE flag value" `Quick test_discourage_upgradable_pubkeytype_flag_value;
]

(* ============================================================================
   BIP-146 NULLFAIL Tests
   ============================================================================ *)

(* Test NULLFAIL flag exists and has correct value *)
let test_nullfail_flag_exists () =
  Alcotest.(check bool) "NULLFAIL flag is non-zero" true
    (Script.script_verify_nullfail <> 0)

let test_nullfail_flag_value () =
  Alcotest.(check int) "NULLFAIL flag is 1 lsl 12" (1 lsl 12)
    Script.script_verify_nullfail

(* Test that NULLFAIL is enabled at SegWit height for mainnet *)
let test_nullfail_enabled_at_segwit_height () =
  let network = Consensus.mainnet in
  let flags = Consensus.get_block_script_flags network.segwit_height network in
  let has_nullfail = flags land Script.script_verify_nullfail <> 0 in
  Alcotest.(check bool) "NULLFAIL enabled at SegWit height" true has_nullfail

(* Test that NULLFAIL is NOT enabled before SegWit height *)
let test_nullfail_disabled_before_segwit () =
  let network = Consensus.mainnet in
  let flags = Consensus.get_block_script_flags (network.segwit_height - 1) network in
  let has_nullfail = flags land Script.script_verify_nullfail <> 0 in
  Alcotest.(check bool) "NULLFAIL disabled before SegWit" false has_nullfail

(* Test NULLFAIL on OP_CHECKSIG: non-empty failing signature must be rejected.

   This test creates a simple script: <sig> <pubkey> OP_CHECKSIG
   With a deliberately invalid signature (wrong pubkey), and NULLFAIL flag set,
   the script must fail with a NULLFAIL error if the signature is non-empty. *)
let test_nullfail_checksig_nonempty_sig_rejected () =
  (* Create a script that pushes an invalid signature and pubkey, then CHECKSIG
     Script: <fake_sig> <fake_pubkey> OP_CHECKSIG
     The signature will fail because it doesn't match the pubkey.
     With NULLFAIL, non-empty failing sig must cause NULLFAIL error. *)
  (* Push a fake non-empty "signature" (9 bytes, looks like minimal DER but wrong)
     0x30 0x06 0x02 0x01 0x01 0x02 0x01 0x01 0x01 (DER-ish + hashtype)
     and a 33-byte compressed pubkey (fake) *)
  let fake_sig = hex_to_cstruct "3006020101020101" in  (* 8 bytes, no hashtype *)
  let fake_pubkey = hex_to_cstruct ("02" ^ String.make 64 'a') in (* 33 bytes *)

  (* Build script: push sig, push pubkey, OP_CHECKSIG *)
  let script_hex = Printf.sprintf "08%s21%sac"
    (cstruct_to_hex fake_sig)
    (cstruct_to_hex fake_pubkey) in

  let flags = Script.script_verify_nullfail in
  match eval_script_with_flags script_hex flags with
  | Error msg ->
    (* Should fail with NULLFAIL error *)
    let msg_lower = String.lowercase_ascii msg in
    let contains_nullfail =
      let rec check i =
        if i + 8 > String.length msg_lower then false
        else if String.sub msg_lower i 8 = "nullfail" then true
        else check (i + 1)
      in check 0
    in
    if not contains_nullfail then
      Alcotest.fail ("Expected NULLFAIL error, got: " ^ msg)
  | Ok _ -> Alcotest.fail "Expected NULLFAIL error for non-empty failing signature"

(* Test that empty signature on failing CHECKSIG does NOT trigger NULLFAIL.
   With an empty signature, CHECKSIG should just push false (not an error). *)
let test_nullfail_checksig_empty_sig_allowed () =
  (* Script: OP_0 <pubkey> OP_CHECKSIG
     Empty signature should result in false on stack, not an error *)
  let fake_pubkey = hex_to_cstruct ("02" ^ String.make 64 'a') in
  let script_hex = Printf.sprintf "0021%sac"
    (cstruct_to_hex fake_pubkey) in

  let flags = Script.script_verify_nullfail in
  match eval_script_with_flags script_hex flags with
  | Ok false -> ()  (* Expected: false on stack, no NULLFAIL error *)
  | Ok true -> Alcotest.fail "Expected false on stack for empty sig"
  | Error e -> Alcotest.fail ("Empty sig should not error: " ^ e)

(* Test NULLFAIL without flag: non-empty failing sig should NOT cause error *)
let test_nullfail_disabled_allows_nonempty_sig () =
  let fake_sig = hex_to_cstruct "3006020101020101" in
  let fake_pubkey = hex_to_cstruct ("02" ^ String.make 64 'a') in

  let script_hex = Printf.sprintf "08%s21%sac"
    (cstruct_to_hex fake_sig)
    (cstruct_to_hex fake_pubkey) in

  (* No NULLFAIL flag *)
  let flags = 0 in
  match eval_script_with_flags script_hex flags with
  | Ok false -> ()  (* Expected: false on stack, no error *)
  | Ok true -> Alcotest.fail "Expected false on stack"
  | Error e -> Alcotest.fail ("Without NULLFAIL, should push false not error: " ^ e)

(* Test NULLFAIL on OP_CHECKMULTISIG: all unused signatures must be empty.

   Script: OP_0 <sig1> OP_2 <pk1> <pk2> OP_2 OP_CHECKMULTISIG

   This is a 2-of-2 multisig, but we only provide 1 signature slot (plus dummy).
   If the provided sig is non-empty and fails, NULLFAIL must trigger. *)
let test_nullfail_checkmultisig_nonempty_sig_rejected () =
  let fake_sig = hex_to_cstruct "3006020101020101" in  (* 8 bytes *)
  let fake_pk1 = hex_to_cstruct ("02" ^ String.make 64 'a') in
  let fake_pk2 = hex_to_cstruct ("03" ^ String.make 64 'b') in

  (* Script: OP_0 (dummy) <fake_sig> OP_1 <pk1> <pk2> OP_2 OP_CHECKMULTISIG
     This is a 1-of-2 multisig with one signature that will fail *)
  let script_hex = Printf.sprintf "0008%s5121%s21%s52ae"
    (cstruct_to_hex fake_sig)
    (cstruct_to_hex fake_pk1)
    (cstruct_to_hex fake_pk2) in

  let flags = Script.script_verify_nullfail lor Script.script_verify_nulldummy in
  match eval_script_with_flags script_hex flags with
  | Error msg ->
    let msg_lower = String.lowercase_ascii msg in
    let contains_nullfail =
      let rec check i =
        if i + 8 > String.length msg_lower then false
        else if String.sub msg_lower i 8 = "nullfail" then true
        else check (i + 1)
      in check 0
    in
    if not contains_nullfail then
      Alcotest.fail ("Expected NULLFAIL error, got: " ^ msg)
  | Ok _ -> Alcotest.fail "Expected NULLFAIL error for CHECKMULTISIG with non-empty failing sig"

(* Test CHECKMULTISIG with all empty signatures passes (no NULLFAIL) *)
let test_nullfail_checkmultisig_empty_sigs_allowed () =
  let fake_pk1 = hex_to_cstruct ("02" ^ String.make 64 'a') in
  let fake_pk2 = hex_to_cstruct ("03" ^ String.make 64 'b') in

  (* Script: OP_0 (dummy) OP_0 (empty sig) OP_1 <pk1> <pk2> OP_2 OP_CHECKMULTISIG *)
  let script_hex = Printf.sprintf "00005121%s21%s52ae"
    (cstruct_to_hex fake_pk1)
    (cstruct_to_hex fake_pk2) in

  let flags = Script.script_verify_nullfail lor Script.script_verify_nulldummy in
  match eval_script_with_flags script_hex flags with
  | Ok false -> ()  (* Expected: false, but no NULLFAIL error *)
  | Ok true -> Alcotest.fail "Expected false on stack for empty sigs"
  | Error e -> Alcotest.fail ("Empty sigs should not cause error: " ^ e)

let nullfail_tests = [
  Alcotest.test_case "NULLFAIL flag exists" `Quick test_nullfail_flag_exists;
  Alcotest.test_case "NULLFAIL flag value is 1 lsl 12" `Quick test_nullfail_flag_value;
  Alcotest.test_case "NULLFAIL enabled at SegWit height" `Quick test_nullfail_enabled_at_segwit_height;
  Alcotest.test_case "NULLFAIL disabled before SegWit" `Quick test_nullfail_disabled_before_segwit;
  Alcotest.test_case "CHECKSIG non-empty failing sig rejected" `Quick test_nullfail_checksig_nonempty_sig_rejected;
  Alcotest.test_case "CHECKSIG empty sig allowed" `Quick test_nullfail_checksig_empty_sig_allowed;
  Alcotest.test_case "NULLFAIL disabled allows non-empty sig" `Quick test_nullfail_disabled_allows_nonempty_sig;
  Alcotest.test_case "CHECKMULTISIG non-empty failing sig rejected" `Quick test_nullfail_checkmultisig_nonempty_sig_rejected;
  Alcotest.test_case "CHECKMULTISIG empty sigs allowed" `Quick test_nullfail_checkmultisig_empty_sigs_allowed;
]

let round5_tests = [
  Alcotest.test_case "CONST_SCRIPTCODE rejects OP_CODESEPARATOR" `Quick test_codesep_rejected_with_const_scriptcode;
  Alcotest.test_case "OP_CODESEPARATOR allowed without flag" `Quick test_codesep_allowed_without_const_scriptcode;
  Alcotest.test_case "CONST_SCRIPTCODE rejects in dead branch" `Quick test_codesep_rejected_in_dead_branch;
  Alcotest.test_case "MINIMALDATA empty push rejected" `Quick test_minimaldata_empty_push_rejected;
  Alcotest.test_case "MINIMALDATA push 0x05 uses OP_5" `Quick test_minimaldata_push1_should_use_opn;
  Alcotest.test_case "MINIMALDATA push 0x81 uses OP_1NEGATE" `Quick test_minimaldata_push_0x81_should_use_1negate;
  Alcotest.test_case "MINIMALDATA PUSHDATA1 small rejected" `Quick test_minimaldata_pushdata1_small;
  Alcotest.test_case "MINIMALDATA valid direct push" `Quick test_minimaldata_valid_direct_push;
  Alcotest.test_case "MINIMALDATA no flag allows non-minimal" `Quick test_minimaldata_no_flag;
  Alcotest.test_case "MINIMALDATA opbyte preserved" `Quick test_minimaldata_opbyte_preserved_in_parsing;
  Alcotest.test_case "DISCOURAGE NOP1" `Quick test_discourage_nop1;
  Alcotest.test_case "NOP1 allowed without flag" `Quick test_nop1_allowed_without_flag;
  Alcotest.test_case "DISCOURAGE NOP4" `Quick test_discourage_nop4;
  Alcotest.test_case "DISCOURAGE NOP10" `Quick test_discourage_nop10;
  Alcotest.test_case "DISCOURAGE witness v2" `Quick test_discourage_witness_v2;
  Alcotest.test_case "Witness v2 allowed without flag" `Quick test_witness_v2_allowed_without_flag;
  Alcotest.test_case "DISCOURAGE_OP_SUCCESS flag exists" `Quick test_discourage_op_success_flag_exists;
  Alcotest.test_case "PUSHDATA serialize roundtrip (PUSHDATA1)" `Quick test_pushdata_serialize_roundtrip;
  Alcotest.test_case "PUSHDATA serialize roundtrip (direct)" `Quick test_pushdata_direct_serialize_roundtrip;
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
  ("round5_phase1", round5_tests);
  ("bug7_8_9", bug7_8_9_tests);
  ("nullfail", nullfail_tests);
]
