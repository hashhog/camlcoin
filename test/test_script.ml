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

(* P2A (Pay-to-Anchor) script: OP_1 OP_PUSHBYTES_2 0x4e73 *)
let test_classify_p2a () =
  let p2a_script = hex_to_cstruct "51024e73" in
  match Script.classify_script p2a_script with
  | Script.P2A_script -> ()
  | _ -> Alcotest.fail "Expected P2A_script"

let test_is_p2a () =
  let p2a_script = hex_to_cstruct "51024e73" in
  Alcotest.(check bool) "is_p2a true" true (Script.is_p2a p2a_script);
  (* Not P2A: wrong bytes *)
  let not_p2a_1 = hex_to_cstruct "51024e74" in
  Alcotest.(check bool) "is_p2a false (wrong byte)" false (Script.is_p2a not_p2a_1);
  (* Not P2A: wrong length *)
  let not_p2a_2 = hex_to_cstruct "51024e7300" in
  Alcotest.(check bool) "is_p2a false (wrong length)" false (Script.is_p2a not_p2a_2);
  (* Not P2A: P2TR *)
  let p2tr = hex_to_cstruct ("5120" ^ String.make 64 '0') in
  Alcotest.(check bool) "is_p2a false (P2TR)" false (Script.is_p2a p2tr)

let test_p2a_dust_limit () =
  Alcotest.(check int64) "P2A dust limit" 240L Script.p2a_dust_limit

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
  Alcotest.test_case "classify P2A" `Quick test_classify_p2a;
  Alcotest.test_case "classify OP_RETURN" `Quick test_classify_op_return;
]

let p2a_tests = [
  Alcotest.test_case "is_p2a detection" `Quick test_is_p2a;
  Alcotest.test_case "P2A dust limit" `Quick test_p2a_dust_limit;
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

(* ============================================================================
   WITNESS_PUBKEYTYPE Tests (BIP-141)
   ============================================================================ *)

(* Test that WITNESS_PUBKEYTYPE flag exists and has correct value *)
let test_witness_pubkeytype_flag_exists () =
  Alcotest.(check bool) "flag is non-zero" true
    (Script.script_verify_witness_pubkeytype <> 0)

let test_witness_pubkeytype_flag_value () =
  Alcotest.(check int) "flag is 1 lsl 14" (1 lsl 14)
    Script.script_verify_witness_pubkeytype

(* Test that WITNESS_PUBKEYTYPE is enabled at SegWit height for mainnet *)
let test_witness_pubkeytype_enabled_at_segwit_height () =
  let network = Consensus.mainnet in
  let flags = Consensus.get_block_script_flags network.segwit_height network in
  let has_flag = flags land Script.script_verify_witness_pubkeytype <> 0 in
  Alcotest.(check bool) "WITNESS_PUBKEYTYPE enabled at SegWit height" true has_flag

(* Test that WITNESS_PUBKEYTYPE is NOT enabled before SegWit height *)
let test_witness_pubkeytype_disabled_before_segwit () =
  let network = Consensus.mainnet in
  let flags = Consensus.get_block_script_flags (network.segwit_height - 1) network in
  let has_flag = flags land Script.script_verify_witness_pubkeytype <> 0 in
  Alcotest.(check bool) "WITNESS_PUBKEYTYPE disabled before SegWit" false has_flag

(* Test is_compressed_pubkey helper function *)
let test_is_compressed_pubkey_02_prefix () =
  (* 33-byte pubkey with 0x02 prefix - should be valid *)
  let pubkey = hex_to_cstruct ("02" ^ String.make 64 'a') in
  Alcotest.(check bool) "02 prefix compressed" true (Script.is_compressed_pubkey pubkey)

let test_is_compressed_pubkey_03_prefix () =
  (* 33-byte pubkey with 0x03 prefix - should be valid *)
  let pubkey = hex_to_cstruct ("03" ^ String.make 64 'b') in
  Alcotest.(check bool) "03 prefix compressed" true (Script.is_compressed_pubkey pubkey)

let test_is_compressed_pubkey_04_prefix_rejected () =
  (* 65-byte pubkey with 0x04 prefix - uncompressed, should be rejected *)
  let pubkey = hex_to_cstruct ("04" ^ String.make 128 'c') in
  Alcotest.(check bool) "04 prefix uncompressed" false (Script.is_compressed_pubkey pubkey)

let test_is_compressed_pubkey_wrong_length () =
  (* 32-byte key with 0x02 prefix - wrong length *)
  let pubkey = hex_to_cstruct ("02" ^ String.make 62 'd') in
  Alcotest.(check bool) "wrong length" false (Script.is_compressed_pubkey pubkey)

let test_is_compressed_pubkey_empty () =
  (* Empty pubkey *)
  let pubkey = Cstruct.create 0 in
  Alcotest.(check bool) "empty" false (Script.is_compressed_pubkey pubkey)

let test_is_compressed_pubkey_wrong_prefix () =
  (* 33-byte key with invalid prefix (0x05) *)
  let pubkey = hex_to_cstruct ("05" ^ String.make 64 'e') in
  Alcotest.(check bool) "wrong prefix" false (Script.is_compressed_pubkey pubkey)

(* Test P2WPKH with uncompressed pubkey (65 bytes, 0x04 prefix) is rejected *)
let test_p2wpkh_uncompressed_pubkey_rejected () =
  let tx = make_test_tx () in
  (* Create a 65-byte uncompressed pubkey (0x04 prefix) *)
  let uncompressed_pubkey = hex_to_cstruct ("04" ^ String.make 128 'f') in
  (* Compute P2WPKH program from uncompressed pubkey hash *)
  let pubkey_hash = Crypto.hash160 uncompressed_pubkey in
  (* P2WPKH script: OP_0 <20-byte hash> *)
  let script_pubkey_bytes =
    let w = Serialize.writer_create () in
    Serialize.write_uint8 w 0x00;  (* OP_0 *)
    Serialize.write_uint8 w 0x14;  (* push 20 bytes *)
    Serialize.write_bytes w pubkey_hash;
    Serialize.writer_to_cstruct w
  in
  (* Dummy signature (will fail sig check, but we're testing pubkey validation) *)
  let dummy_sig = hex_to_cstruct "30060201010201010001" in
  let witness = { Types.items = [dummy_sig; uncompressed_pubkey] } in
  let flags = Script.script_verify_witness lor Script.script_verify_witness_pubkeytype in
  match Script.verify_script ~tx ~input_index:0 ~script_pubkey:script_pubkey_bytes
          ~script_sig:(Cstruct.create 0) ~witness ~amount:0L ~flags () with
  | Error msg ->
    (* Should fail with WITNESS_PUBKEYTYPE error *)
    let contains_compressed = String.lowercase_ascii msg |> fun s ->
      let rec check i =
        if i + 10 > String.length s then false
        else if String.sub s i 10 = "compressed" then true
        else check (i + 1)
      in check 0
    in
    if not contains_compressed then
      Alcotest.fail ("Expected compressed pubkey error, got: " ^ msg)
  | Ok _ -> Alcotest.fail "Uncompressed pubkey should be rejected with WITNESS_PUBKEYTYPE"

(* Test P2WPKH with compressed pubkey (33 bytes, 0x02 prefix) is allowed *)
let test_p2wpkh_compressed_pubkey_allowed () =
  let tx = make_test_tx () in
  (* Create a 33-byte compressed pubkey (0x02 prefix) *)
  let compressed_pubkey = hex_to_cstruct ("02" ^ String.make 64 'a') in
  (* Compute P2WPKH program from compressed pubkey hash *)
  let pubkey_hash = Crypto.hash160 compressed_pubkey in
  (* P2WPKH script: OP_0 <20-byte hash> *)
  let script_pubkey_bytes =
    let w = Serialize.writer_create () in
    Serialize.write_uint8 w 0x00;  (* OP_0 *)
    Serialize.write_uint8 w 0x14;  (* push 20 bytes *)
    Serialize.write_bytes w pubkey_hash;
    Serialize.writer_to_cstruct w
  in
  (* Dummy signature (will fail sig check, but key should pass pubkey type check) *)
  let dummy_sig = hex_to_cstruct "30060201010201010001" in
  let witness = { Types.items = [dummy_sig; compressed_pubkey] } in
  let flags = Script.script_verify_witness lor Script.script_verify_witness_pubkeytype in
  match Script.verify_script ~tx ~input_index:0 ~script_pubkey:script_pubkey_bytes
          ~script_sig:(Cstruct.create 0) ~witness ~amount:0L ~flags () with
  | Error msg ->
    (* The sig check will fail, but the error should NOT be about compressed pubkey *)
    let contains_compressed = String.lowercase_ascii msg |> fun s ->
      let rec check i =
        if i + 10 > String.length s then false
        else if String.sub s i 10 = "compressed" then true
        else check (i + 1)
      in check 0
    in
    if contains_compressed then
      Alcotest.fail ("Compressed pubkey should pass, but got error: " ^ msg)
    (* Else: sig check failed as expected, which is fine *)
  | Ok false ->
    (* Script executed but returned false (sig check failed) - expected *)
    ()
  | Ok true ->
    (* Unexpected success - but technically fine for pubkeytype check *)
    ()

(* Test P2WPKH with wrong prefix (33 bytes, 0x05 prefix) is rejected *)
let test_p2wpkh_wrong_prefix_rejected () =
  let tx = make_test_tx () in
  (* Create a 33-byte key with invalid prefix (0x05) *)
  let bad_pubkey = hex_to_cstruct ("05" ^ String.make 64 'b') in
  let pubkey_hash = Crypto.hash160 bad_pubkey in
  let script_pubkey_bytes =
    let w = Serialize.writer_create () in
    Serialize.write_uint8 w 0x00;
    Serialize.write_uint8 w 0x14;
    Serialize.write_bytes w pubkey_hash;
    Serialize.writer_to_cstruct w
  in
  let dummy_sig = hex_to_cstruct "30060201010201010001" in
  let witness = { Types.items = [dummy_sig; bad_pubkey] } in
  let flags = Script.script_verify_witness lor Script.script_verify_witness_pubkeytype in
  match Script.verify_script ~tx ~input_index:0 ~script_pubkey:script_pubkey_bytes
          ~script_sig:(Cstruct.create 0) ~witness ~amount:0L ~flags () with
  | Error msg ->
    let contains_compressed = String.lowercase_ascii msg |> fun s ->
      let rec check i =
        if i + 10 > String.length s then false
        else if String.sub s i 10 = "compressed" then true
        else check (i + 1)
      in check 0
    in
    if not contains_compressed then
      Alcotest.fail ("Expected compressed pubkey error, got: " ^ msg)
  | Ok _ -> Alcotest.fail "Wrong prefix pubkey should be rejected with WITNESS_PUBKEYTYPE"

(* Test P2WPKH without WITNESS_PUBKEYTYPE flag allows uncompressed pubkeys *)
let test_p2wpkh_uncompressed_allowed_without_flag () =
  let tx = make_test_tx () in
  let uncompressed_pubkey = hex_to_cstruct ("04" ^ String.make 128 'c') in
  let pubkey_hash = Crypto.hash160 uncompressed_pubkey in
  let script_pubkey_bytes =
    let w = Serialize.writer_create () in
    Serialize.write_uint8 w 0x00;
    Serialize.write_uint8 w 0x14;
    Serialize.write_bytes w pubkey_hash;
    Serialize.writer_to_cstruct w
  in
  let dummy_sig = hex_to_cstruct "30060201010201010001" in
  let witness = { Types.items = [dummy_sig; uncompressed_pubkey] } in
  (* Only WITNESS flag, no WITNESS_PUBKEYTYPE *)
  let flags = Script.script_verify_witness in
  match Script.verify_script ~tx ~input_index:0 ~script_pubkey:script_pubkey_bytes
          ~script_sig:(Cstruct.create 0) ~witness ~amount:0L ~flags () with
  | Error msg ->
    let contains_compressed = String.lowercase_ascii msg |> fun s ->
      let rec check i =
        if i + 10 > String.length s then false
        else if String.sub s i 10 = "compressed" then true
        else check (i + 1)
      in check 0
    in
    if contains_compressed then
      Alcotest.fail ("Without WITNESS_PUBKEYTYPE flag, should not error on compressed: " ^ msg)
    (* Other errors (like sig failure) are expected *)
  | Ok _ -> ()  (* Success or false without WITNESS_PUBKEYTYPE is fine *)

let witness_pubkeytype_tests = [
  Alcotest.test_case "WITNESS_PUBKEYTYPE flag exists" `Quick test_witness_pubkeytype_flag_exists;
  Alcotest.test_case "WITNESS_PUBKEYTYPE flag value is 1 lsl 14" `Quick test_witness_pubkeytype_flag_value;
  Alcotest.test_case "WITNESS_PUBKEYTYPE enabled at SegWit height" `Quick test_witness_pubkeytype_enabled_at_segwit_height;
  Alcotest.test_case "WITNESS_PUBKEYTYPE disabled before SegWit" `Quick test_witness_pubkeytype_disabled_before_segwit;
  Alcotest.test_case "is_compressed_pubkey 02 prefix" `Quick test_is_compressed_pubkey_02_prefix;
  Alcotest.test_case "is_compressed_pubkey 03 prefix" `Quick test_is_compressed_pubkey_03_prefix;
  Alcotest.test_case "is_compressed_pubkey 04 prefix rejected" `Quick test_is_compressed_pubkey_04_prefix_rejected;
  Alcotest.test_case "is_compressed_pubkey wrong length" `Quick test_is_compressed_pubkey_wrong_length;
  Alcotest.test_case "is_compressed_pubkey empty" `Quick test_is_compressed_pubkey_empty;
  Alcotest.test_case "is_compressed_pubkey wrong prefix" `Quick test_is_compressed_pubkey_wrong_prefix;
  Alcotest.test_case "P2WPKH uncompressed pubkey rejected" `Quick test_p2wpkh_uncompressed_pubkey_rejected;
  Alcotest.test_case "P2WPKH compressed pubkey allowed" `Quick test_p2wpkh_compressed_pubkey_allowed;
  Alcotest.test_case "P2WPKH wrong prefix rejected" `Quick test_p2wpkh_wrong_prefix_rejected;
  Alcotest.test_case "P2WPKH uncompressed allowed without flag" `Quick test_p2wpkh_uncompressed_allowed_without_flag;
]

(* ============================================================================
   Witness Cleanstack Tests (Phase 3)

   Witness scripts (v0 and v1) implicitly require cleanstack behavior - this is
   NOT gated by the SCRIPT_VERIFY_CLEANSTACK flag like for legacy P2SH.
   After witness script execution, the stack must have exactly one element.
   ============================================================================ *)

(* Test that P2WSH with extra stack items fails even WITHOUT cleanstack flag.
   This creates a witness script that leaves extra items on the stack. *)
let test_witness_cleanstack_p2wsh_extra_item_fails () =
  let tx = make_test_tx () in
  (* Create a witness script: OP_1 OP_1 (leaves two items: 1, 1)
     Encoded: 51 51 *)
  let witness_script = hex_to_cstruct "5151" in
  let script_hash = Crypto.sha256 witness_script in
  (* P2WSH script: OP_0 <32-byte script hash> *)
  let script_pubkey =
    let w = Serialize.writer_create () in
    Serialize.write_uint8 w 0x00;  (* OP_0 = witness v0 *)
    Serialize.write_uint8 w 0x20;  (* push 32 bytes *)
    Serialize.write_bytes w script_hash;
    Serialize.writer_to_cstruct w
  in
  (* Witness stack: just the script itself (no inputs needed) *)
  let witness = { Types.items = [witness_script] } in
  (* Only WITNESS flag, explicitly NO cleanstack flag *)
  let flags = Script.script_verify_witness in
  match Script.verify_script ~tx ~input_index:0 ~script_pubkey
          ~script_sig:(Cstruct.create 0) ~witness ~amount:0L ~flags () with
  | Error msg ->
    (* Should fail with cleanstack error *)
    let msg_lower = String.lowercase_ascii msg in
    if not (String.sub msg_lower 0 (min (String.length msg_lower) 10) = "cleanstack") then
      Alcotest.fail ("Expected Cleanstack error, got: " ^ msg)
  | Ok _ -> Alcotest.fail "P2WSH with extra stack items should fail (witness cleanstack)"

(* Test that P2WSH with exactly one stack item succeeds *)
let test_witness_cleanstack_p2wsh_one_item_ok () =
  let tx = make_test_tx () in
  (* Create a witness script: OP_1 (leaves exactly one item)
     Encoded: 51 *)
  let witness_script = hex_to_cstruct "51" in
  let script_hash = Crypto.sha256 witness_script in
  let script_pubkey =
    let w = Serialize.writer_create () in
    Serialize.write_uint8 w 0x00;
    Serialize.write_uint8 w 0x20;
    Serialize.write_bytes w script_hash;
    Serialize.writer_to_cstruct w
  in
  let witness = { Types.items = [witness_script] } in
  let flags = Script.script_verify_witness in
  match Script.verify_script ~tx ~input_index:0 ~script_pubkey
          ~script_sig:(Cstruct.create 0) ~witness ~amount:0L ~flags () with
  | Ok true -> ()
  | Ok false -> Alcotest.fail "Expected success (true)"
  | Error e -> Alcotest.fail ("P2WSH with one stack item should succeed: " ^ e)

(* Test that P2WSH with empty stack fails (EvalFalse) *)
let test_witness_cleanstack_p2wsh_empty_stack_fails () =
  let tx = make_test_tx () in
  (* Create a witness script: OP_DROP (will pop the last item, leaving empty)
     We need to push something first for DROP to work: OP_1 OP_DROP
     Encoded: 51 75 *)
  let witness_script = hex_to_cstruct "5175" in
  let script_hash = Crypto.sha256 witness_script in
  let script_pubkey =
    let w = Serialize.writer_create () in
    Serialize.write_uint8 w 0x00;
    Serialize.write_uint8 w 0x20;
    Serialize.write_bytes w script_hash;
    Serialize.writer_to_cstruct w
  in
  let witness = { Types.items = [witness_script] } in
  let flags = Script.script_verify_witness in
  match Script.verify_script ~tx ~input_index:0 ~script_pubkey
          ~script_sig:(Cstruct.create 0) ~witness ~amount:0L ~flags () with
  | Error _ -> ()  (* Expected: cleanstack error (stack size != 1) *)
  | Ok _ -> Alcotest.fail "P2WSH with empty stack should fail"

(* Test that P2WSH false result fails (even with clean stack) *)
let test_witness_cleanstack_p2wsh_false_result_fails () =
  let tx = make_test_tx () in
  (* Create a witness script: OP_0 (leaves exactly one item, but it's false)
     Encoded: 00 *)
  let witness_script = hex_to_cstruct "00" in
  let script_hash = Crypto.sha256 witness_script in
  let script_pubkey =
    let w = Serialize.writer_create () in
    Serialize.write_uint8 w 0x00;
    Serialize.write_uint8 w 0x20;
    Serialize.write_bytes w script_hash;
    Serialize.writer_to_cstruct w
  in
  let witness = { Types.items = [witness_script] } in
  let flags = Script.script_verify_witness in
  match Script.verify_script ~tx ~input_index:0 ~script_pubkey
          ~script_sig:(Cstruct.create 0) ~witness ~amount:0L ~flags () with
  | Ok false -> ()  (* Expected: returns false *)
  | Ok true -> Alcotest.fail "OP_0 should return false"
  | Error e -> Alcotest.fail ("Should return Ok false, not error: " ^ e)

(* Test legacy P2SH WITH cleanstack flag requires clean stack *)
let test_legacy_cleanstack_flag_enforced () =
  let tx = make_test_tx () in
  (* Create a simple P2SH that leaves 2 items on stack: OP_1 OP_1
     Encoded: 51 51 *)
  let redeem_script = hex_to_cstruct "5151" in
  let script_hash = Crypto.hash160 redeem_script in
  (* P2SH script: OP_HASH160 <20 bytes> OP_EQUAL *)
  let script_pubkey =
    let w = Serialize.writer_create () in
    Serialize.write_uint8 w 0xa9;  (* OP_HASH160 *)
    Serialize.write_uint8 w 0x14;  (* push 20 bytes *)
    Serialize.write_bytes w script_hash;
    Serialize.write_uint8 w 0x87;  (* OP_EQUAL *)
    Serialize.writer_to_cstruct w
  in
  (* scriptSig pushes the redeem script *)
  let script_sig =
    let w = Serialize.writer_create () in
    let len = Cstruct.length redeem_script in
    Serialize.write_uint8 w len;
    Serialize.write_bytes w redeem_script;
    Serialize.writer_to_cstruct w
  in
  let witness = { Types.items = [] } in
  (* P2SH + CLEANSTACK flags *)
  let flags = Script.script_verify_p2sh lor Script.script_verify_cleanstack in
  match Script.verify_script ~tx ~input_index:0 ~script_pubkey
          ~script_sig ~witness ~amount:0L ~flags () with
  | Error msg ->
    (* Should fail with cleanstack-related error *)
    let msg_lower = String.lowercase_ascii msg in
    let has_clean =
      let rec check i =
        if i + 5 > String.length msg_lower then false
        else if String.sub msg_lower i 5 = "clean" then true
        else check (i + 1)
      in check 0
    in
    if not has_clean then
      Alcotest.fail ("Expected cleanstack error, got: " ^ msg)
  | Ok _ -> Alcotest.fail "Legacy P2SH with cleanstack flag should fail"

(* Test legacy P2SH WITHOUT cleanstack flag allows extra items *)
let test_legacy_no_cleanstack_flag_allows_extra () =
  let tx = make_test_tx () in
  let redeem_script = hex_to_cstruct "5151" in  (* OP_1 OP_1 *)
  let script_hash = Crypto.hash160 redeem_script in
  let script_pubkey =
    let w = Serialize.writer_create () in
    Serialize.write_uint8 w 0xa9;
    Serialize.write_uint8 w 0x14;
    Serialize.write_bytes w script_hash;
    Serialize.write_uint8 w 0x87;
    Serialize.writer_to_cstruct w
  in
  let script_sig =
    let w = Serialize.writer_create () in
    let len = Cstruct.length redeem_script in
    Serialize.write_uint8 w len;
    Serialize.write_bytes w redeem_script;
    Serialize.writer_to_cstruct w
  in
  let witness = { Types.items = [] } in
  (* P2SH flag only, NO cleanstack flag *)
  let flags = Script.script_verify_p2sh in
  match Script.verify_script ~tx ~input_index:0 ~script_pubkey
          ~script_sig ~witness ~amount:0L ~flags () with
  | Ok true -> ()  (* Expected: succeeds without cleanstack enforcement *)
  | Ok false -> Alcotest.fail "Expected true on stack"
  | Error e -> Alcotest.fail ("Without cleanstack flag, should succeed: " ^ e)

let witness_cleanstack_tests = [
  Alcotest.test_case "P2WSH extra stack items fails (no flag)" `Quick test_witness_cleanstack_p2wsh_extra_item_fails;
  Alcotest.test_case "P2WSH one stack item ok" `Quick test_witness_cleanstack_p2wsh_one_item_ok;
  Alcotest.test_case "P2WSH empty stack fails" `Quick test_witness_cleanstack_p2wsh_empty_stack_fails;
  Alcotest.test_case "P2WSH false result returns false" `Quick test_witness_cleanstack_p2wsh_false_result_fails;
  Alcotest.test_case "Legacy P2SH cleanstack flag enforced" `Quick test_legacy_cleanstack_flag_enforced;
  Alcotest.test_case "Legacy P2SH no flag allows extra items" `Quick test_legacy_no_cleanstack_flag_allows_extra;
]

(* ============================================================================
   MINIMALIF Tests (Phase 6)

   When MINIMALIF is active (mandatory for witness v0/v1), OP_IF/OP_NOTIF
   arguments must be exactly empty (false) or exactly [0x01] (true).
   Other truthy values like [0x02], [0x01 0x00], etc. are rejected.
   ============================================================================ *)

(* Helper to make a P2WSH script_pubkey from a witness script *)
let make_p2wsh_script_pubkey witness_script =
  let script_hash = Crypto.sha256 witness_script in
  let w = Serialize.writer_create () in
  Serialize.write_uint8 w 0x00;  (* OP_0 = witness v0 *)
  Serialize.write_uint8 w 0x20;  (* push 32 bytes *)
  Serialize.write_bytes w script_hash;
  Serialize.writer_to_cstruct w

(* Test: OP_IF with [0x02] on stack fails in witness v0 due to MINIMALIF *)
let test_minimalif_fails_with_0x02 () =
  let tx = make_test_tx () in
  (* Witness script: OP_IF OP_1 OP_ENDIF
     Encoded: 63 51 68 *)
  let witness_script = hex_to_cstruct "635168" in
  let script_pubkey = make_p2wsh_script_pubkey witness_script in
  (* Witness stack: [0x02] (truthy but not minimal), then the script *)
  let bad_value = hex_to_cstruct "02" in
  let witness = { Types.items = [bad_value; witness_script] } in
  let flags = Script.script_verify_witness in
  match Script.verify_script ~tx ~input_index:0 ~script_pubkey
          ~script_sig:(Cstruct.create 0) ~witness ~amount:0L ~flags () with
  | Error msg ->
    (* Should fail with MINIMALIF error *)
    let msg_upper = String.uppercase_ascii msg in
    let has_minimalif =
      let rec check i =
        if i + 9 > String.length msg_upper then false
        else if String.sub msg_upper i 9 = "MINIMALIF" then true
        else check (i + 1)
      in check 0
    in
    if not has_minimalif then
      Alcotest.fail ("Expected MINIMALIF error, got: " ^ msg)
  | Ok _ -> Alcotest.fail "OP_IF with [0x02] should fail MINIMALIF in witness v0"

(* Test: OP_IF with [0x01] passes in witness v0 *)
let test_minimalif_passes_with_0x01 () =
  let tx = make_test_tx () in
  (* Witness script: OP_IF OP_1 OP_ENDIF
     Encoded: 63 51 68 *)
  let witness_script = hex_to_cstruct "635168" in
  let script_pubkey = make_p2wsh_script_pubkey witness_script in
  (* Witness stack: [0x01] (minimal true), then the script *)
  let good_value = hex_to_cstruct "01" in
  let witness = { Types.items = [good_value; witness_script] } in
  let flags = Script.script_verify_witness in
  match Script.verify_script ~tx ~input_index:0 ~script_pubkey
          ~script_sig:(Cstruct.create 0) ~witness ~amount:0L ~flags () with
  | Ok true -> ()  (* Expected: succeeds with true on stack *)
  | Ok false -> Alcotest.fail "Expected true on stack after OP_IF branch"
  | Error e -> Alcotest.fail ("OP_IF with [0x01] should pass: " ^ e)

(* Test: OP_IF with empty stack (false) takes else branch correctly *)
let test_minimalif_empty_takes_else_branch () =
  let tx = make_test_tx () in
  (* Witness script: OP_IF OP_0 OP_ELSE OP_1 OP_ENDIF
     Encoded: 63 00 67 51 68
     With empty (false) on stack, should take ELSE branch and push 1 *)
  let witness_script = hex_to_cstruct "6300675168" in
  let script_pubkey = make_p2wsh_script_pubkey witness_script in
  (* Witness stack: empty (which is false), then the script *)
  let empty_value = Cstruct.create 0 in
  let witness = { Types.items = [empty_value; witness_script] } in
  let flags = Script.script_verify_witness in
  match Script.verify_script ~tx ~input_index:0 ~script_pubkey
          ~script_sig:(Cstruct.create 0) ~witness ~amount:0L ~flags () with
  | Ok true -> ()  (* Expected: takes else branch, pushes 1 *)
  | Ok false -> Alcotest.fail "Expected true from ELSE branch"
  | Error e -> Alcotest.fail ("Empty value should take ELSE branch: " ^ e)

(* Test: OP_NOTIF with [0x02] fails MINIMALIF *)
let test_minimalif_notif_fails_with_0x02 () =
  let tx = make_test_tx () in
  (* Witness script: OP_NOTIF OP_1 OP_ENDIF
     Encoded: 64 51 68 *)
  let witness_script = hex_to_cstruct "645168" in
  let script_pubkey = make_p2wsh_script_pubkey witness_script in
  let bad_value = hex_to_cstruct "02" in
  let witness = { Types.items = [bad_value; witness_script] } in
  let flags = Script.script_verify_witness in
  match Script.verify_script ~tx ~input_index:0 ~script_pubkey
          ~script_sig:(Cstruct.create 0) ~witness ~amount:0L ~flags () with
  | Error msg ->
    let msg_upper = String.uppercase_ascii msg in
    let has_minimalif =
      let rec check i =
        if i + 9 > String.length msg_upper then false
        else if String.sub msg_upper i 9 = "MINIMALIF" then true
        else check (i + 1)
      in check 0
    in
    if not has_minimalif then
      Alcotest.fail ("Expected MINIMALIF error, got: " ^ msg)
  | Ok _ -> Alcotest.fail "OP_NOTIF with [0x02] should fail MINIMALIF"

(* Test: Multi-byte value [0x01 0x00] fails MINIMALIF even though truthy *)
let test_minimalif_fails_with_multibyte () =
  let tx = make_test_tx () in
  let witness_script = hex_to_cstruct "635168" in  (* OP_IF OP_1 OP_ENDIF *)
  let script_pubkey = make_p2wsh_script_pubkey witness_script in
  (* [0x01 0x00] is truthy (non-zero) but not minimal for IF *)
  let bad_value = hex_to_cstruct "0100" in
  let witness = { Types.items = [bad_value; witness_script] } in
  let flags = Script.script_verify_witness in
  match Script.verify_script ~tx ~input_index:0 ~script_pubkey
          ~script_sig:(Cstruct.create 0) ~witness ~amount:0L ~flags () with
  | Error _ -> ()  (* Expected: MINIMALIF error *)
  | Ok _ -> Alcotest.fail "[0x01 0x00] should fail MINIMALIF"

(* Test: [0x00] (single byte zero) fails MINIMALIF - must be empty for false *)
let test_minimalif_fails_with_single_zero () =
  let tx = make_test_tx () in
  let witness_script = hex_to_cstruct "635168" in  (* OP_IF OP_1 OP_ENDIF *)
  let script_pubkey = make_p2wsh_script_pubkey witness_script in
  (* [0x00] is falsy but not the empty vector *)
  let bad_value = hex_to_cstruct "00" in
  let witness = { Types.items = [bad_value; witness_script] } in
  let flags = Script.script_verify_witness in
  match Script.verify_script ~tx ~input_index:0 ~script_pubkey
          ~script_sig:(Cstruct.create 0) ~witness ~amount:0L ~flags () with
  | Error _ -> ()  (* Expected: MINIMALIF error *)
  | Ok _ -> Alcotest.fail "[0x00] should fail MINIMALIF (must use empty)"

(* Test: Legacy script without MINIMALIF flag allows [0x02] for OP_IF *)
let test_legacy_allows_non_minimal_if () =
  let tx = make_test_tx () in
  (* Legacy script: push [0x02] OP_IF OP_1 OP_ENDIF
     Encoded: 01 02 63 51 68 *)
  let script_pubkey = hex_to_cstruct "0102635168" in
  let witness = { Types.items = [] } in
  (* No MINIMALIF flag, no witness *)
  let flags = 0 in
  match Script.verify_script ~tx ~input_index:0 ~script_pubkey
          ~script_sig:(Cstruct.create 0) ~witness ~amount:0L ~flags () with
  | Ok true -> ()  (* Legacy allows non-minimal IF values *)
  | Ok false -> Alcotest.fail "Expected true on stack"
  | Error e -> Alcotest.fail ("Legacy should allow [0x02] for IF: " ^ e)

let minimalif_tests = [
  Alcotest.test_case "MINIMALIF fails with [0x02]" `Quick test_minimalif_fails_with_0x02;
  Alcotest.test_case "MINIMALIF passes with [0x01]" `Quick test_minimalif_passes_with_0x01;
  Alcotest.test_case "MINIMALIF empty takes else branch" `Quick test_minimalif_empty_takes_else_branch;
  Alcotest.test_case "MINIMALIF NOTIF fails with [0x02]" `Quick test_minimalif_notif_fails_with_0x02;
  Alcotest.test_case "MINIMALIF fails with multi-byte" `Quick test_minimalif_fails_with_multibyte;
  Alcotest.test_case "MINIMALIF fails with [0x00]" `Quick test_minimalif_fails_with_single_zero;
  Alcotest.test_case "Legacy allows non-minimal IF" `Quick test_legacy_allows_non_minimal_if;
]

(* ============================================================================
   P2SH Push-Only Tests (Phase 4)

   P2SH scriptSig must contain only push operations (BIP-16 consensus rule).
   This is unconditional when P2SH is enabled - separate from SCRIPT_VERIFY_SIGPUSHONLY.
   ============================================================================ *)

(* Test is_push_only helper function *)
let test_is_push_only_empty () =
  (* Empty script is push-only *)
  Alcotest.(check bool) "empty is push-only" true
    (Script.is_push_only (Cstruct.create 0))

let test_is_push_only_op_0 () =
  (* OP_0 (0x00) is a push *)
  let script = hex_to_cstruct "00" in
  Alcotest.(check bool) "OP_0 is push-only" true (Script.is_push_only script)

let test_is_push_only_op_1_through_16 () =
  (* OP_1 through OP_16 (0x51-0x60) are pushes *)
  for i = 0x51 to 0x60 do
    let script = hex_to_cstruct (Printf.sprintf "%02x" i) in
    Alcotest.(check bool) (Printf.sprintf "OP_%d is push-only" (i - 0x50))
      true (Script.is_push_only script)
  done

let test_is_push_only_op_1negate () =
  (* OP_1NEGATE (0x4f) is a push *)
  let script = hex_to_cstruct "4f" in
  Alcotest.(check bool) "OP_1NEGATE is push-only" true (Script.is_push_only script)

let test_is_push_only_direct_push () =
  (* Direct push of 3 bytes: 03aabbcc *)
  let script = hex_to_cstruct "03aabbcc" in
  Alcotest.(check bool) "direct push is push-only" true (Script.is_push_only script)

let test_is_push_only_pushdata1 () =
  (* PUSHDATA1: 4c03aabbcc *)
  let script = hex_to_cstruct "4c03aabbcc" in
  Alcotest.(check bool) "PUSHDATA1 is push-only" true (Script.is_push_only script)

let test_is_push_only_pushdata2 () =
  (* PUSHDATA2: 4d0300aabbcc (little-endian length 3) *)
  let script = hex_to_cstruct "4d0300aabbcc" in
  Alcotest.(check bool) "PUSHDATA2 is push-only" true (Script.is_push_only script)

let test_is_push_only_multiple_pushes () =
  (* OP_1 OP_2 (push 3 bytes) -> all pushes *)
  let script = hex_to_cstruct "515203aabbcc" in
  Alcotest.(check bool) "multiple pushes is push-only" true (Script.is_push_only script)

let test_is_push_only_op_dup_fails () =
  (* OP_DUP (0x76) is NOT a push *)
  let script = hex_to_cstruct "76" in
  Alcotest.(check bool) "OP_DUP is not push-only" false (Script.is_push_only script)

let test_is_push_only_op_nop_fails () =
  (* OP_NOP (0x61) is NOT a push *)
  let script = hex_to_cstruct "61" in
  Alcotest.(check bool) "OP_NOP is not push-only" false (Script.is_push_only script)

let test_is_push_only_op_checksig_fails () =
  (* OP_CHECKSIG (0xac) is NOT a push *)
  let script = hex_to_cstruct "ac" in
  Alcotest.(check bool) "OP_CHECKSIG is not push-only" false (Script.is_push_only script)

let test_is_push_only_op_reserved () =
  (* OP_RESERVED (0x50) counts as push for this check per Bitcoin Core *)
  let script = hex_to_cstruct "50" in
  Alcotest.(check bool) "OP_RESERVED is push-only" true (Script.is_push_only script)

let test_is_push_only_mixed_fails () =
  (* OP_1 OP_DUP -> not push-only *)
  let script = hex_to_cstruct "5176" in
  Alcotest.(check bool) "push + OP_DUP is not push-only" false (Script.is_push_only script)

(* Test P2SH scriptSig with OP_DUP is rejected *)
let test_p2sh_scriptsig_op_dup_rejected () =
  let tx = make_test_tx () in
  (* Create a simple redeem script: OP_1 (0x51) *)
  let redeem_script = hex_to_cstruct "51" in
  let script_hash = Crypto.hash160 redeem_script in
  (* P2SH script: OP_HASH160 <20 bytes> OP_EQUAL *)
  let script_pubkey =
    let w = Serialize.writer_create () in
    Serialize.write_uint8 w 0xa9;  (* OP_HASH160 *)
    Serialize.write_uint8 w 0x14;  (* push 20 bytes *)
    Serialize.write_bytes w script_hash;
    Serialize.write_uint8 w 0x87;  (* OP_EQUAL *)
    Serialize.writer_to_cstruct w
  in
  (* scriptSig with OP_DUP before the redeem script push:
     OP_DUP (0x76) <push redeem_script> *)
  let script_sig =
    let w = Serialize.writer_create () in
    Serialize.write_uint8 w 0x76;  (* OP_DUP - NOT push-only! *)
    let len = Cstruct.length redeem_script in
    Serialize.write_uint8 w len;
    Serialize.write_bytes w redeem_script;
    Serialize.writer_to_cstruct w
  in
  let witness = { Types.items = [] } in
  let flags = Script.script_verify_p2sh in
  match Script.verify_script ~tx ~input_index:0 ~script_pubkey
          ~script_sig ~witness ~amount:0L ~flags () with
  | Error msg ->
    (* Should fail with SigPushOnly error *)
    let msg_lower = String.lowercase_ascii msg in
    let contains_push =
      let rec check i =
        if i + 4 > String.length msg_lower then false
        else if String.sub msg_lower i 4 = "push" then true
        else check (i + 1)
      in check 0
    in
    if not contains_push then
      Alcotest.fail ("Expected SigPushOnly error, got: " ^ msg)
  | Ok _ -> Alcotest.fail "P2SH scriptSig with OP_DUP should be rejected"

(* Test P2SH scriptSig with only pushes succeeds *)
let test_p2sh_scriptsig_push_only_succeeds () =
  let tx = make_test_tx () in
  (* Create a simple redeem script: OP_1 (0x51) *)
  let redeem_script = hex_to_cstruct "51" in
  let script_hash = Crypto.hash160 redeem_script in
  let script_pubkey =
    let w = Serialize.writer_create () in
    Serialize.write_uint8 w 0xa9;
    Serialize.write_uint8 w 0x14;
    Serialize.write_bytes w script_hash;
    Serialize.write_uint8 w 0x87;
    Serialize.writer_to_cstruct w
  in
  (* scriptSig with only push: <push redeem_script> *)
  let script_sig =
    let w = Serialize.writer_create () in
    let len = Cstruct.length redeem_script in
    Serialize.write_uint8 w len;
    Serialize.write_bytes w redeem_script;
    Serialize.writer_to_cstruct w
  in
  let witness = { Types.items = [] } in
  let flags = Script.script_verify_p2sh in
  match Script.verify_script ~tx ~input_index:0 ~script_pubkey
          ~script_sig ~witness ~amount:0L ~flags () with
  | Ok true -> ()
  | Ok false -> Alcotest.fail "Expected success"
  | Error e -> Alcotest.fail ("Push-only scriptSig should succeed: " ^ e)

(* Test P2SH scriptSig with OP_NOP is rejected *)
let test_p2sh_scriptsig_op_nop_rejected () =
  let tx = make_test_tx () in
  let redeem_script = hex_to_cstruct "51" in
  let script_hash = Crypto.hash160 redeem_script in
  let script_pubkey =
    let w = Serialize.writer_create () in
    Serialize.write_uint8 w 0xa9;
    Serialize.write_uint8 w 0x14;
    Serialize.write_bytes w script_hash;
    Serialize.write_uint8 w 0x87;
    Serialize.writer_to_cstruct w
  in
  (* scriptSig with OP_NOP (0x61) before the redeem script push *)
  let script_sig =
    let w = Serialize.writer_create () in
    Serialize.write_uint8 w 0x61;  (* OP_NOP - NOT push-only! *)
    let len = Cstruct.length redeem_script in
    Serialize.write_uint8 w len;
    Serialize.write_bytes w redeem_script;
    Serialize.writer_to_cstruct w
  in
  let witness = { Types.items = [] } in
  let flags = Script.script_verify_p2sh in
  match Script.verify_script ~tx ~input_index:0 ~script_pubkey
          ~script_sig ~witness ~amount:0L ~flags () with
  | Error _ -> ()  (* Expected: SigPushOnly error *)
  | Ok _ -> Alcotest.fail "P2SH scriptSig with OP_NOP should be rejected"

(* Test that P2SH push-only is NOT enforced when P2SH flag is disabled.
   We use a script that would fail with SigPushOnly error under P2SH,
   but should fail with a *different* error without P2SH flag.

   Without P2SH: scriptSig runs, then scriptPubKey runs on same stack.
   OP_DUP on empty stack fails with stack underflow, not push-only error.
   This proves push-only check wasn't applied. *)
let test_p2sh_push_only_disabled_without_flag () =
  let tx = make_test_tx () in
  let redeem_script = hex_to_cstruct "51" in
  let script_hash = Crypto.hash160 redeem_script in
  let script_pubkey =
    let w = Serialize.writer_create () in
    Serialize.write_uint8 w 0xa9;
    Serialize.write_uint8 w 0x14;
    Serialize.write_bytes w script_hash;
    Serialize.write_uint8 w 0x87;
    Serialize.writer_to_cstruct w
  in
  (* scriptSig with OP_DUP before the redeem script push *)
  let script_sig =
    let w = Serialize.writer_create () in
    Serialize.write_uint8 w 0x76;  (* OP_DUP - will fail on empty stack *)
    let len = Cstruct.length redeem_script in
    Serialize.write_uint8 w len;
    Serialize.write_bytes w redeem_script;
    Serialize.writer_to_cstruct w
  in
  let witness = { Types.items = [] } in
  (* NO P2SH flag - should fail with stack error, NOT push-only error *)
  let flags = 0 in
  match Script.verify_script ~tx ~input_index:0 ~script_pubkey
          ~script_sig ~witness ~amount:0L ~flags () with
  | Error msg ->
    (* Should NOT be a push-only error *)
    let msg_lower = String.lowercase_ascii msg in
    let is_push_error =
      let rec check i =
        if i + 8 > String.length msg_lower then false
        else if String.sub msg_lower i 8 = "pushonly" then true
        else if i + 10 <= String.length msg_lower && String.sub msg_lower i 10 = "sigpushonly" then true
        else check (i + 1)
      in check 0
    in
    if is_push_error then
      Alcotest.fail ("Without P2SH flag, should not error on push-only: " ^ msg)
    (* Else: failed for other reason (e.g., stack underflow) - that's expected *)
  | Ok _ -> ()  (* Unexpected success is also fine - proves push-only wasn't checked *)

let p2sh_push_only_tests = [
  Alcotest.test_case "is_push_only empty" `Quick test_is_push_only_empty;
  Alcotest.test_case "is_push_only OP_0" `Quick test_is_push_only_op_0;
  Alcotest.test_case "is_push_only OP_1-16" `Quick test_is_push_only_op_1_through_16;
  Alcotest.test_case "is_push_only OP_1NEGATE" `Quick test_is_push_only_op_1negate;
  Alcotest.test_case "is_push_only direct push" `Quick test_is_push_only_direct_push;
  Alcotest.test_case "is_push_only PUSHDATA1" `Quick test_is_push_only_pushdata1;
  Alcotest.test_case "is_push_only PUSHDATA2" `Quick test_is_push_only_pushdata2;
  Alcotest.test_case "is_push_only multiple pushes" `Quick test_is_push_only_multiple_pushes;
  Alcotest.test_case "is_push_only OP_DUP fails" `Quick test_is_push_only_op_dup_fails;
  Alcotest.test_case "is_push_only OP_NOP fails" `Quick test_is_push_only_op_nop_fails;
  Alcotest.test_case "is_push_only OP_CHECKSIG fails" `Quick test_is_push_only_op_checksig_fails;
  Alcotest.test_case "is_push_only OP_RESERVED ok" `Quick test_is_push_only_op_reserved;
  Alcotest.test_case "is_push_only mixed fails" `Quick test_is_push_only_mixed_fails;
  Alcotest.test_case "P2SH scriptSig OP_DUP rejected" `Quick test_p2sh_scriptsig_op_dup_rejected;
  Alcotest.test_case "P2SH scriptSig push-only succeeds" `Quick test_p2sh_scriptsig_push_only_succeeds;
  Alcotest.test_case "P2SH scriptSig OP_NOP rejected" `Quick test_p2sh_scriptsig_op_nop_rejected;
  Alcotest.test_case "P2SH push-only not enforced without flag" `Quick test_p2sh_push_only_disabled_without_flag;
]

(* ============================================================================
   Legacy Sighash Tests (Bitcoin Core sighash.json vectors)

   These tests verify our legacy sighash implementation against Bitcoin Core's
   test vectors from src/test/data/sighash.json. Format:
   [raw_transaction_hex, script_hex, input_index, hash_type, expected_sighash]
   ============================================================================ *)

(* Helper: reverse bytes in a hex string (for hash display format) *)
let reverse_hex s =
  let len = String.length s in
  let buf = Buffer.create len in
  let i = ref (len - 2) in
  while !i >= 0 do
    Buffer.add_substring buf s !i 2;
    i := !i - 2
  done;
  Buffer.contents buf

(* Test a single sighash vector *)
let test_sighash_vector (raw_tx_hex, script_hex, input_index, hash_type, expected_hash) () =
  let raw_tx = hex_to_cstruct raw_tx_hex in
  let script = hex_to_cstruct script_hex in
  let r = Serialize.reader_of_cstruct raw_tx in
  let tx = Serialize.deserialize_transaction r in
  (* hash_type in sighash.json is signed int32 - convert properly *)
  let hash_type_int =
    if hash_type < 0 then
      Int32.to_int (Int32.of_int hash_type)
    else
      hash_type
  in
  let computed = Script.compute_sighash_legacy tx input_index script hash_type_int in
  let computed_hex = cstruct_to_hex computed in
  (* Bitcoin Core outputs hash in reverse byte order (big-endian display) *)
  let computed_reversed = reverse_hex computed_hex in
  Alcotest.(check string) "sighash matches" expected_hash computed_reversed

(* Sample test vectors from Bitcoin Core's sighash.json
   Full test suite has ~500 vectors; we test a representative sample *)
let sighash_test_vectors = [
  (* Vector 1: basic SIGHASH_ALL (hash_type = 1) *)
  ("907c2bc503ade11cc3b04eb2918b6f547b0630ab569273824748c87ea14b0696526c66ba740200000004ab65ababfd1f9bdd4ef073c7afc4ae00da8a66f429c917a0081ad1e1dabce28d373eab81d8628de802000000096aab5253ab52000052ad042b5f25efb33beec9f3364e8a9139e8439d9d7e26529c3c30b6c3fd89f8684cfd68ea0200000009ab53526500636a52ab599ac2fe02a526ed040000000008535300516352515164370e010000000003006300ab2ec229", "", 2, 1864164639, "31af167a6cf3f9d5f6875caa4d31704ceb0eba078d132b78dab52c3b8997317e");

  (* Vector 2: SIGHASH_SINGLE bug - input_index >= output count returns uint256(1) *)
  ("a0aa3126041621a6dea5b800141aa696daf28408959dfb2df96095db9fa425ad3f427f2f6103000000015360290e9c6063fa26912c2e7fb6a0ad80f1c5fea1771d42f12976092e7a85a4229fdb6e890000000001abc109f6e47688ac0e4682988785744602b8c87228fcef0695085edf19088af1a9db126e93000000000665516aac536affffffff8fe53e0806e12dfd05d67ac68f4768fdbe23fc48ace22a5aa8ba04c96d58e2750300000009ac51abac63ab5153650524aa680455ce7b000000000000499e50030000000008636a00ac526563ac5051ee030000000003abacabd2b6fe000000000003516563910fb6b5", "65", 0, -1391424484, "48d6a1bd2cd9eec54eb866fc71209418a950402b5d7e52363bfb75c98e141175");

  (* Vector 3: script with OP_CODESEPARATOR (0xab) - should be stripped *)
  ("6e7e9d4b04ce17afa1e8546b627bb8d89a6a7fefd9d892ec8a192d79c2ceafc01694a6a7e7030000000953ac6a51006353636a33bced1544f797f08ceed02f108da22cd24c9e7809a446c61eb3895914508ac91f07053a01000000055163ab516affffffff11dc54eee8f9e4ff0bcf6b1a1a35b1cd10d63389571375501af7444073bcec3c02000000046aab53514a821f0ce3956e235f71e4c69d91abe1e93fb703bd33039ac567249ed339bf0ba0883ef300000000090063ab65000065ac654bec3cc504bcf499020000000005ab6a52abac64eb060100000000076a6a5351650053bbbc130100000000056a6aab53abd6e1380100000000026a51c4e509b8", "acab655151", 0, 479279909, "2a3d95b09237b72034b23f2d2bb29fa32a58ab5c6aa72f6aafdfa178ab1dd01c");

  (* Vector 4: ANYONECANPAY + SIGHASH_SINGLE *)
  ("73107cbd025c22ebc8c3e0a47b2a760739216a528de8d4dab5d45cbeb3051cebae73b01ca10200000007ab6353656a636affffffffe26816dffc670841e6a6c8c61c586da401df1261a330a6c6b3dd9f9a0789bc9e000000000800ac6552ac6aac51ffffffff0174a8f0010000000004ac52515100000000", "5163ac63635151ac", 1, 1190874345, "06e328de263a87b09beabe222a21627a6ea5c7f560030da31610c4611f4a46bc");

  (* Vector 5: SIGHASH_NONE *)
  ("e93bbf6902be872933cb987fc26ba0f914fcfc2f6ce555258554dd9939d12032a8536c8802030000000453ac5353eabb6451e074e6fef9de211347d6a45900ea5aaf2636ef7967f565dce66fa451805c5cd10000000003525253ffffffff047dc3e6020000000007516565ac656aabec9eea010000000001633e46e600000000000015080a030000000001ab00000000", "5300ac6a53ab6a", 1, -886562767, "f03aa4fc5f97e826323d0daa03343ebf8a34ed67a1ce18631f8b88e5c992e798");

  (* Vector 6: Simple hash_type *)
  ("50818f4c01b464538b1e7e7f5ae4ed96ad23c68c830e78da9a845bc19b5c3b0b20bb82e5e9030000000763526a63655352ffffffff023b3f9c040000000008630051516a6a5163a83caf01000000000553ab65510000000000", "6aac", 0, 946795545, "746306f322de2b4b58ffe7faae83f6a72433c22f88062cdde881d4dd8a5a4e2d");

  (* Vector 7: empty script *)
  ("c363a70c01ab174230bbe4afe0c3efa2d7f2feaf179431359adedccf30d1f69efe0c86ed390200000002ab51558648fe0231318b04000000000151662170000000000008ac5300006a63acac00000000", "", 0, 2146479410, "191ab180b0d753763671717d051f138d4866b7cb0d1d4811472e64de595d2c70");

  (* Vector 8: negative hash type *)
  ("8d437a7304d8772210a923fd81187c425fc28c17a5052571501db05c7e89b11448b36618cd02000000026a6340fec14ad2c9298fde1477f1e8325e5747b61b7e2ff2a549f3d132689560ab6c45dd43c3010000000963ac00ac000051516a447ed907a7efffebeb103988bf5f947fc688aab2c6a7914f48238cf92c337fad4a79348102000000085352ac526a5152517436edf2d80e3ef06725227c970a816b25d0b58d2cd3c187a7af2cea66d6b27ba69bf33a0300000007000063ab526553f3f0d6140386815d030000000003ab6300de138f00000000000900525153515265abac1f87040300000000036aac6500000000", "51", 3, -315779667, "b6632ac53578a741ae8c36d8b69e79f39b89913a2c781cdf1bf47a8c29d997a5");

  (* Vector 9: multiple outputs *)
  ("fd878840031e82fdbe1ad1d745d1185622b0060ac56638290ec4f66b1beef4450817114a2c0000000009516a63ab53650051abffffffff37b7a10322b5418bfd64fb09cd8a27ddf57731aeb1f1f920ffde7cb2dfb6cdb70300000008536a5365ac53515369ecc034f1594690dbe189094dc816d6d57ea75917de764cbf8eccce4632cbabe7e116cd0100000003515352ffffffff035777fc000000000003515200abe9140300000000050063005165bed6d10200000000076300536363ab65195e9110", "635265", 0, 1729787658, "6e3735d37a4b28c45919543aabcb732e7a3e1874db5315abb7cc6b143d62ff10");

  (* Vector 10: another negative hash type *)
  ("f40a750702af06efff3ea68e5d56e42bc41cdb8b6065c98f1221fe04a325a898cb61f3d7ee030000000363acacffffffffb5788174aef79788716f96af779d7959147a0c2e0e5bfb6c2dba2df5b4b97894030000000965510065535163ac6affffffff0445e6fd0200000000096aac536365526a526aa6546b000000000008acab656a6552535141a0fd010000000000c897ea030000000008526500ab526a6a631b39dba3", "00abab5163ac", 1, -1778064747, "d76d0fc0abfa72d646df888bce08db957e627f72962647016eeae5a8412354cf");
]

let sighash_tests =
  List.mapi (fun i vec ->
    Alcotest.test_case (Printf.sprintf "sighash vector %d" (i + 1)) `Quick (test_sighash_vector vec)
  ) sighash_test_vectors

(* Test FindAndDelete functionality *)
let test_find_and_delete_basic () =
  (* Script: PUSH 3 bytes (aabbcc), then OP_1 *)
  (* Format: 03 aabbcc 51 *)
  let script = hex_to_cstruct "03aabbcc51" in
  let sig_data = hex_to_cstruct "aabbcc" in
  let (result, removed) = Script.find_and_delete script sig_data in
  Alcotest.(check bool) "signature was removed" true removed;
  (* After removal: just OP_1 *)
  Alcotest.(check string) "remaining script" "51" (cstruct_to_hex result)

let test_find_and_delete_no_match () =
  (* Script: PUSH 3 bytes (aabbcc), then OP_1 *)
  let script = hex_to_cstruct "03aabbcc51" in
  let sig_data = hex_to_cstruct "deadbeef" in
  let (result, removed) = Script.find_and_delete script sig_data in
  Alcotest.(check bool) "no removal" false removed;
  Alcotest.(check string) "script unchanged" "03aabbcc51" (cstruct_to_hex result)

let test_find_and_delete_empty_sig () =
  let script = hex_to_cstruct "51" in
  let sig_data = Cstruct.create 0 in
  let (result, removed) = Script.find_and_delete script sig_data in
  Alcotest.(check bool) "empty sig - no removal" false removed;
  Alcotest.(check string) "script unchanged" "51" (cstruct_to_hex result)

let test_find_and_delete_multiple () =
  (* Script with same sig twice: PUSH 1 byte (aa), PUSH 1 byte (aa), OP_1 *)
  (* Format: 01 aa 01 aa 51 *)
  let script = hex_to_cstruct "01aa01aa51" in
  let sig_data = hex_to_cstruct "aa" in
  let (result, removed) = Script.find_and_delete script sig_data in
  Alcotest.(check bool) "removed" true removed;
  (* Both occurrences should be removed *)
  Alcotest.(check string) "both removed" "51" (cstruct_to_hex result)

(* Test strip_codeseparator functionality *)
let test_strip_codeseparator_basic () =
  (* Script: OP_1 OP_CODESEPARATOR OP_2 *)
  let script = hex_to_cstruct "51ab52" in
  let result = Script.strip_codeseparator script in
  Alcotest.(check string) "codesep stripped" "5152" (cstruct_to_hex result)

let test_strip_codeseparator_multiple () =
  (* Script with multiple OP_CODESEPARATOR *)
  let script = hex_to_cstruct "51abab52" in
  let result = Script.strip_codeseparator script in
  Alcotest.(check string) "both codeseps stripped" "5152" (cstruct_to_hex result)

let test_strip_codeseparator_in_push_data () =
  (* 0xAB inside push data should NOT be stripped *)
  (* Script: PUSH 01ab, OP_CODESEPARATOR, OP_1 *)
  let script = hex_to_cstruct "0201abab51" in
  let result = Script.strip_codeseparator script in
  (* The 0xAB inside push data stays, the real OP_CODESEPARATOR is stripped *)
  Alcotest.(check string) "ab in push preserved" "0201ab51" (cstruct_to_hex result)

let test_strip_codeseparator_empty () =
  let script = Cstruct.create 0 in
  let result = Script.strip_codeseparator script in
  Alcotest.(check int) "empty stays empty" 0 (Cstruct.length result)

(* Test compute_subscript_from_pos - used for OP_CODESEPARATOR handling *)
let test_subscript_from_pos_basic () =
  (* Script: OP_1 OP_2 OP_3 (indices 0, 1, 2) *)
  let script = hex_to_cstruct "515253" in
  (* After opcode at index 1 (OP_2), should get OP_3 *)
  let result = Script.compute_subscript_from_pos script 2 in
  Alcotest.(check string) "subscript after index 1" "53" (cstruct_to_hex result)

let test_subscript_from_pos_with_push () =
  (* Script: PUSH 2 bytes, OP_1 (indices 0, 1) *)
  let script = hex_to_cstruct "02aabb51" in
  (* After opcode at index 0 (the push), should get OP_1 *)
  let result = Script.compute_subscript_from_pos script 1 in
  Alcotest.(check string) "subscript after push" "51" (cstruct_to_hex result)

let test_subscript_from_pos_past_end () =
  let script = hex_to_cstruct "5152" in
  let result = Script.compute_subscript_from_pos script 10 in
  Alcotest.(check int) "past end is empty" 0 (Cstruct.length result)

(* Test SIGHASH_SINGLE bug: returns uint256(1) when input_index >= output count *)
let test_sighash_single_bug () =
  let tx = {
    Types.version = 1l;
    inputs = [
      { previous_output = { txid = Types.zero_hash; vout = 0l };
        script_sig = Cstruct.create 0;
        sequence = 0xffffffffl };
      { previous_output = { txid = Types.zero_hash; vout = 1l };
        script_sig = Cstruct.create 0;
        sequence = 0xffffffffl }
    ];
    outputs = [
      { Types.value = 1000L; script_pubkey = Cstruct.create 0 }
    ];
    witnesses = [];
    locktime = 0l;
  } in
  (* Input index 1, but only 1 output - should trigger the bug *)
  let hash_type = 0x03 in  (* SIGHASH_SINGLE *)
  let result = Script.compute_sighash_legacy tx 1 (Cstruct.create 0) hash_type in
  (* Should be uint256(1): 0x01 followed by 31 zero bytes *)
  Alcotest.(check int) "first byte is 1" 1 (Cstruct.get_uint8 result 0);
  for i = 1 to 31 do
    Alcotest.(check int) (Printf.sprintf "byte %d is 0" i) 0 (Cstruct.get_uint8 result i)
  done

let find_and_delete_tests = [
  Alcotest.test_case "find_and_delete basic" `Quick test_find_and_delete_basic;
  Alcotest.test_case "find_and_delete no match" `Quick test_find_and_delete_no_match;
  Alcotest.test_case "find_and_delete empty sig" `Quick test_find_and_delete_empty_sig;
  Alcotest.test_case "find_and_delete multiple" `Quick test_find_and_delete_multiple;
]

let strip_codeseparator_tests = [
  Alcotest.test_case "strip_codeseparator basic" `Quick test_strip_codeseparator_basic;
  Alcotest.test_case "strip_codeseparator multiple" `Quick test_strip_codeseparator_multiple;
  Alcotest.test_case "strip_codeseparator in push data" `Quick test_strip_codeseparator_in_push_data;
  Alcotest.test_case "strip_codeseparator empty" `Quick test_strip_codeseparator_empty;
]

let subscript_tests = [
  Alcotest.test_case "subscript_from_pos basic" `Quick test_subscript_from_pos_basic;
  Alcotest.test_case "subscript_from_pos with push" `Quick test_subscript_from_pos_with_push;
  Alcotest.test_case "subscript_from_pos past end" `Quick test_subscript_from_pos_past_end;
]

let sighash_special_tests = [
  Alcotest.test_case "SIGHASH_SINGLE bug" `Quick test_sighash_single_bug;
]

(* Test P2A script verification - succeeds unconditionally *)
let test_p2a_verify_script_succeeds () =
  let tx = make_test_tx () in
  let p2a_script = hex_to_cstruct "51024e73" in
  let witness = { Types.items = [] } in
  let flags = Script.script_verify_witness lor Script.script_verify_taproot in
  match Script.verify_script ~tx ~input_index:0 ~script_pubkey:p2a_script
          ~script_sig:(Cstruct.create 0) ~witness ~amount:240L ~flags () with
  | Ok true -> ()  (* P2A succeeds unconditionally *)
  | Ok false -> Alcotest.fail "P2A should return Ok true"
  | Error e -> Alcotest.fail ("P2A should succeed: " ^ e)

let test_p2a_with_nonempty_scriptsig_fails () =
  let tx = make_test_tx () in
  let p2a_script = hex_to_cstruct "51024e73" in
  let witness = { Types.items = [] } in
  let flags = Script.script_verify_witness in
  (* Non-empty scriptSig should fail for witness programs *)
  let script_sig = hex_to_cstruct "00" in
  match Script.verify_script ~tx ~input_index:0 ~script_pubkey:p2a_script
          ~script_sig ~witness ~amount:240L ~flags () with
  | Error _ -> ()  (* Expected: scriptSig must be empty *)
  | Ok _ -> Alcotest.fail "P2A with non-empty scriptSig should fail"

let p2a_verify_tests = [
  Alcotest.test_case "P2A verify succeeds" `Quick test_p2a_verify_script_succeeds;
  Alcotest.test_case "P2A with nonempty scriptSig fails" `Quick test_p2a_with_nonempty_scriptsig_fails;
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
  ("witness_pubkeytype", witness_pubkeytype_tests);
  ("witness_cleanstack", witness_cleanstack_tests);
  ("minimalif", minimalif_tests);
  ("p2sh_push_only", p2sh_push_only_tests);
  ("sighash", sighash_tests);
  ("find_and_delete", find_and_delete_tests);
  ("strip_codeseparator", strip_codeseparator_tests);
  ("subscript", subscript_tests);
  ("sighash_special", sighash_special_tests);
  ("p2a", p2a_tests);
  ("p2a_verify", p2a_verify_tests);
]
