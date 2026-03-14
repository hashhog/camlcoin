(* Tests for Miniscript module *)

open Camlcoin.Miniscript

(* Helper to create test keys *)
let test_pubkey =
  let hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" in
  let len = String.length hex / 2 in
  let buf = Cstruct.create len in
  for i = 0 to len - 1 do
    let byte = int_of_string ("0x" ^ String.sub hex (i * 2) 2) in
    Cstruct.set_uint8 buf i byte
  done;
  KeyBytes buf

let test_pubkey2 =
  let hex = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5" in
  let len = String.length hex / 2 in
  let buf = Cstruct.create len in
  for i = 0 to len - 1 do
    let byte = int_of_string ("0x" ^ String.sub hex (i * 2) 2) in
    Cstruct.set_uint8 buf i byte
  done;
  KeyBytes buf

let test_hash32 =
  let hash = Cstruct.create 32 in
  for i = 0 to 31 do Cstruct.set_uint8 hash i (i + 1) done;
  hash

let _test_hash20 =
  let hash = Cstruct.create 20 in
  for i = 0 to 19 do Cstruct.set_uint8 hash i (i + 1) done;
  hash

(* ============================================================================
   Type System Tests
   ============================================================================ *)

let test_type_0 () =
  let node = Ms_0 in
  match type_check P2WSH node with
  | Ok t ->
    Alcotest.(check bool) "has B type" true (TypeProp.has t.props TypeProp.type_b);
    Alcotest.(check bool) "has z property" true (TypeProp.has t.props TypeProp.prop_z);
    Alcotest.(check bool) "has d property" true (TypeProp.has t.props TypeProp.prop_d);
    Alcotest.(check bool) "max_sat_size is -1 (cannot satisfy)" true (t.max_sat_size < 0);
    Alcotest.(check int) "max_dissat_size is 0" 0 t.max_dissat_size
  | Error _ -> Alcotest.fail "type_check failed for Ms_0"

let test_type_1 () =
  let node = Ms_1 in
  match type_check P2WSH node with
  | Ok t ->
    Alcotest.(check bool) "has B type" true (TypeProp.has t.props TypeProp.type_b);
    Alcotest.(check bool) "has z property" true (TypeProp.has t.props TypeProp.prop_z);
    Alcotest.(check bool) "has f property" true (TypeProp.has t.props TypeProp.prop_f);
    Alcotest.(check int) "max_sat_size is 0" 0 t.max_sat_size;
    Alcotest.(check bool) "max_dissat_size is -1 (cannot dissatisfy)" true (t.max_dissat_size < 0)
  | Error _ -> Alcotest.fail "type_check failed for Ms_1"

let test_type_pk_k () =
  let node = Ms_pk_k test_pubkey in
  match type_check P2WSH node with
  | Ok t ->
    Alcotest.(check bool) "has K type" true (TypeProp.has t.props TypeProp.type_k);
    Alcotest.(check bool) "has o property" true (TypeProp.has t.props TypeProp.prop_o);
    Alcotest.(check bool) "has s property" true (TypeProp.has t.props TypeProp.prop_s);
    Alcotest.(check bool) "has d property" true (TypeProp.has t.props TypeProp.prop_d);
    Alcotest.(check bool) "script_size > 0" true (t.script_size > 0)
  | Error _ -> Alcotest.fail "type_check failed for Ms_pk_k"

let test_type_pk_h () =
  let node = Ms_pk_h test_pubkey in
  match type_check P2WSH node with
  | Ok t ->
    Alcotest.(check bool) "has K type" true (TypeProp.has t.props TypeProp.type_k);
    Alcotest.(check bool) "has n property" true (TypeProp.has t.props TypeProp.prop_n);
    Alcotest.(check bool) "has s property" true (TypeProp.has t.props TypeProp.prop_s)
  | Error _ -> Alcotest.fail "type_check failed for Ms_pk_h"

let test_type_older () =
  let node = Ms_older 144 in
  match type_check P2WSH node with
  | Ok t ->
    Alcotest.(check bool) "has B type" true (TypeProp.has t.props TypeProp.type_b);
    Alcotest.(check bool) "has z property" true (TypeProp.has t.props TypeProp.prop_z);
    Alcotest.(check bool) "has f property" true (TypeProp.has t.props TypeProp.prop_f);
    Alcotest.(check bool) "cannot dissatisfy" true (t.max_dissat_size < 0)
  | Error _ -> Alcotest.fail "type_check failed for Ms_older"

let test_type_after () =
  let node = Ms_after 500000 in
  match type_check P2WSH node with
  | Ok t ->
    Alcotest.(check bool) "has B type" true (TypeProp.has t.props TypeProp.type_b);
    Alcotest.(check bool) "has z property" true (TypeProp.has t.props TypeProp.prop_z);
    Alcotest.(check bool) "has f property" true (TypeProp.has t.props TypeProp.prop_f)
  | Error _ -> Alcotest.fail "type_check failed for Ms_after"

let test_type_sha256 () =
  let node = Ms_sha256 test_hash32 in
  match type_check P2WSH node with
  | Ok t ->
    Alcotest.(check bool) "has B type" true (TypeProp.has t.props TypeProp.type_b);
    Alcotest.(check bool) "has o property" true (TypeProp.has t.props TypeProp.prop_o);
    Alcotest.(check bool) "has d property" true (TypeProp.has t.props TypeProp.prop_d)
  | Error _ -> Alcotest.fail "type_check failed for Ms_sha256"

let test_type_and_v () =
  (* and_v(v:pk(key), 1) *)
  let node = Ms_and_v (Ms_wrap (WrapV, Ms_wrap (WrapC, Ms_pk_k test_pubkey)), Ms_1) in
  match type_check P2WSH node with
  | Ok t ->
    Alcotest.(check bool) "has B type" true (TypeProp.has t.props TypeProp.type_b);
    Alcotest.(check bool) "has s property" true (TypeProp.has t.props TypeProp.prop_s)
  | Error e ->
    let msg = match e with
      | MissingProperty s -> "MissingProperty: " ^ s
      | IncompatibleBase s -> "IncompatibleBase: " ^ s
      | ConflictingTimelocks -> "ConflictingTimelocks"
      | InvalidThreshold (k, n) -> Printf.sprintf "InvalidThreshold(%d, %d)" k n
      | InvalidMultisig s -> "InvalidMultisig: " ^ s
      | ContextMismatch s -> "ContextMismatch: " ^ s
    in
    Alcotest.fail ("type_check failed for Ms_and_v: " ^ msg)

let test_type_and_b () =
  (* and_b(pk(key1), s:pk(key2)) *)
  let node = Ms_and_b (
    Ms_wrap (WrapC, Ms_pk_k test_pubkey),
    Ms_wrap (WrapS, Ms_wrap (WrapC, Ms_pk_k test_pubkey2))
  ) in
  match type_check P2WSH node with
  | Ok t ->
    Alcotest.(check bool) "has B type" true (TypeProp.has t.props TypeProp.type_b);
    Alcotest.(check bool) "has d property" true (TypeProp.has t.props TypeProp.prop_d);
    Alcotest.(check bool) "has s property" true (TypeProp.has t.props TypeProp.prop_s)
  | Error _ -> Alcotest.fail "type_check failed for Ms_and_b"

let test_type_or_b () =
  (* or_b(pk(key1), s:pk(key2)) *)
  let node = Ms_or_b (
    Ms_wrap (WrapC, Ms_pk_k test_pubkey),
    Ms_wrap (WrapS, Ms_wrap (WrapC, Ms_pk_k test_pubkey2))
  ) in
  match type_check P2WSH node with
  | Ok t ->
    Alcotest.(check bool) "has B type" true (TypeProp.has t.props TypeProp.type_b);
    Alcotest.(check bool) "has d property" true (TypeProp.has t.props TypeProp.prop_d);
    Alcotest.(check bool) "has s property" true (TypeProp.has t.props TypeProp.prop_s)
  | Error _ -> Alcotest.fail "type_check failed for Ms_or_b"

let test_type_multi () =
  (* multi(2, key1, key2) *)
  let node = Ms_multi (2, [test_pubkey; test_pubkey2]) in
  match type_check P2WSH node with
  | Ok t ->
    Alcotest.(check bool) "has B type" true (TypeProp.has t.props TypeProp.type_b);
    Alcotest.(check bool) "has n property" true (TypeProp.has t.props TypeProp.prop_n);
    Alcotest.(check bool) "has s property" true (TypeProp.has t.props TypeProp.prop_s);
    Alcotest.(check bool) "has d property" true (TypeProp.has t.props TypeProp.prop_d);
    Alcotest.(check bool) "has m property" true (TypeProp.has t.props TypeProp.prop_m)
  | Error _ -> Alcotest.fail "type_check failed for Ms_multi"

let test_type_multi_tapscript_error () =
  (* multi should fail in tapscript context *)
  let node = Ms_multi (2, [test_pubkey; test_pubkey2]) in
  match type_check Tapscript node with
  | Ok _ -> Alcotest.fail "multi should fail in tapscript"
  | Error (ContextMismatch _) -> ()
  | Error _ -> Alcotest.fail "wrong error type for multi in tapscript"

let test_type_multi_a () =
  (* multi_a(2, key1, key2) *)
  let node = Ms_multi_a (2, [test_pubkey; test_pubkey2]) in
  match type_check Tapscript node with
  | Ok t ->
    Alcotest.(check bool) "has B type" true (TypeProp.has t.props TypeProp.type_b);
    Alcotest.(check bool) "has s property" true (TypeProp.has t.props TypeProp.prop_s)
  | Error _ -> Alcotest.fail "type_check failed for Ms_multi_a"

let test_type_thresh () =
  (* thresh(2, pk(key1), s:pk(key2), s:pk(key1)) *)
  let node = Ms_thresh (2, [
    Ms_wrap (WrapC, Ms_pk_k test_pubkey);
    Ms_wrap (WrapS, Ms_wrap (WrapC, Ms_pk_k test_pubkey2));
    Ms_wrap (WrapS, Ms_wrap (WrapC, Ms_pk_k test_pubkey));
  ]) in
  match type_check P2WSH node with
  | Ok t ->
    Alcotest.(check bool) "has B type" true (TypeProp.has t.props TypeProp.type_b);
    Alcotest.(check bool) "has d property" true (TypeProp.has t.props TypeProp.prop_d);
    Alcotest.(check bool) "has s property" true (TypeProp.has t.props TypeProp.prop_s)
  | Error _ -> Alcotest.fail "type_check failed for Ms_thresh"

let test_type_wrapper_a () =
  (* a:pk(key) *)
  let node = Ms_wrap (WrapA, Ms_wrap (WrapC, Ms_pk_k test_pubkey)) in
  match type_check P2WSH node with
  | Ok t ->
    Alcotest.(check bool) "has W type" true (TypeProp.has t.props TypeProp.type_w);
    Alcotest.(check bool) "has s property" true (TypeProp.has t.props TypeProp.prop_s)
  | Error _ -> Alcotest.fail "type_check failed for a:pk(key)"

let test_type_wrapper_c () =
  (* c:pk_k(key) = pk(key) *)
  let node = Ms_wrap (WrapC, Ms_pk_k test_pubkey) in
  match type_check P2WSH node with
  | Ok t ->
    Alcotest.(check bool) "has B type" true (TypeProp.has t.props TypeProp.type_b);
    Alcotest.(check bool) "has s property" true (TypeProp.has t.props TypeProp.prop_s)
  | Error _ -> Alcotest.fail "type_check failed for c:pk_k(key)"

let test_type_wrapper_v () =
  (* v:pk(key) *)
  let node = Ms_wrap (WrapV, Ms_wrap (WrapC, Ms_pk_k test_pubkey)) in
  match type_check P2WSH node with
  | Ok t ->
    Alcotest.(check bool) "has V type" true (TypeProp.has t.props TypeProp.type_v);
    Alcotest.(check bool) "has f property" true (TypeProp.has t.props TypeProp.prop_f);
    Alcotest.(check bool) "cannot dissatisfy" true (t.max_dissat_size < 0)
  | Error _ -> Alcotest.fail "type_check failed for v:pk(key)"

(* ============================================================================
   Script Generation Tests
   ============================================================================ *)

let test_script_0 () =
  let node = Ms_0 in
  let script = to_script P2WSH node in
  Alcotest.(check int) "script is OP_0" 1 (Cstruct.length script);
  Alcotest.(check int) "first byte is 0x00" 0x00 (Cstruct.get_uint8 script 0)

let test_script_1 () =
  let node = Ms_1 in
  let script = to_script P2WSH node in
  Alcotest.(check int) "script is OP_1" 1 (Cstruct.length script);
  Alcotest.(check int) "first byte is 0x51" 0x51 (Cstruct.get_uint8 script 0)

let test_script_pk_k () =
  let node = Ms_pk_k test_pubkey in
  let script = to_script P2WSH node in
  (* Should be: <push33> <pubkey> *)
  Alcotest.(check int) "script length is 34" 34 (Cstruct.length script);
  Alcotest.(check int) "first byte is push 33" 33 (Cstruct.get_uint8 script 0)

let test_script_pk () =
  (* pk(key) = c:pk_k(key) => <pubkey> OP_CHECKSIG *)
  let node = Ms_wrap (WrapC, Ms_pk_k test_pubkey) in
  let script = to_script P2WSH node in
  (* Should be: <push33> <pubkey> OP_CHECKSIG *)
  Alcotest.(check int) "script length is 35" 35 (Cstruct.length script);
  Alcotest.(check int) "last byte is OP_CHECKSIG" 0xac (Cstruct.get_uint8 script 34)

let test_script_older () =
  let node = Ms_older 144 in
  let script = to_script P2WSH node in
  (* Should be: <144> OP_CSV *)
  let last = Cstruct.get_uint8 script (Cstruct.length script - 1) in
  Alcotest.(check int) "last byte is OP_CSV" 0xb2 last

let test_script_after () =
  let node = Ms_after 500000 in
  let script = to_script P2WSH node in
  (* Should be: <n> OP_CLTV OP_DROP *)
  let last = Cstruct.get_uint8 script (Cstruct.length script - 1) in
  Alcotest.(check int) "last byte is OP_DROP" 0x75 last

let test_script_sha256 () =
  let node = Ms_sha256 test_hash32 in
  let script = to_script P2WSH node in
  (* Should contain OP_SHA256 *)
  let has_sha256 = ref false in
  for i = 0 to Cstruct.length script - 1 do
    if Cstruct.get_uint8 script i = 0xa8 then has_sha256 := true
  done;
  Alcotest.(check bool) "contains OP_SHA256" true !has_sha256

let test_script_multi () =
  let node = Ms_multi (2, [test_pubkey; test_pubkey2]) in
  let script = to_script P2WSH node in
  (* Should be: OP_2 <key1> <key2> OP_2 OP_CHECKMULTISIG *)
  Alcotest.(check int) "first byte is OP_2" 0x52 (Cstruct.get_uint8 script 0);
  let last = Cstruct.get_uint8 script (Cstruct.length script - 1) in
  Alcotest.(check int) "last byte is OP_CHECKMULTISIG" 0xae last

let test_script_and_v () =
  (* and_v(v:pk(key), 1) *)
  let node = Ms_and_v (Ms_wrap (WrapV, Ms_wrap (WrapC, Ms_pk_k test_pubkey)), Ms_1) in
  let script = to_script P2WSH node in
  (* Should end with OP_1 *)
  let last = Cstruct.get_uint8 script (Cstruct.length script - 1) in
  Alcotest.(check int) "last byte is OP_1" 0x51 last

let test_script_or_i () =
  (* or_i(pk(key1), pk(key2)) *)
  let node = Ms_or_i (
    Ms_wrap (WrapC, Ms_pk_k test_pubkey),
    Ms_wrap (WrapC, Ms_pk_k test_pubkey2)
  ) in
  let script = to_script P2WSH node in
  (* Should start with OP_IF *)
  Alcotest.(check int) "first byte is OP_IF" 0x63 (Cstruct.get_uint8 script 0);
  (* Should end with OP_ENDIF *)
  let last = Cstruct.get_uint8 script (Cstruct.length script - 1) in
  Alcotest.(check int) "last byte is OP_ENDIF" 0x68 last

let test_script_thresh () =
  (* thresh(2, pk(key1), s:pk(key2), s:pk(key1)) *)
  let node = Ms_thresh (2, [
    Ms_wrap (WrapC, Ms_pk_k test_pubkey);
    Ms_wrap (WrapS, Ms_wrap (WrapC, Ms_pk_k test_pubkey2));
    Ms_wrap (WrapS, Ms_wrap (WrapC, Ms_pk_k test_pubkey));
  ]) in
  let script = to_script P2WSH node in
  (* Should end with OP_NUMEQUAL - thresh compares sum against k *)
  let last = Cstruct.get_uint8 script (Cstruct.length script - 1) in
  Alcotest.(check int) "last byte is OP_NUMEQUAL" 0x9c last

(* ============================================================================
   Parsing Tests
   ============================================================================ *)

let test_parse_0 () =
  match parse_miniscript "0" with
  | Ok Ms_0 -> ()
  | Ok _ -> Alcotest.fail "parsed wrong node type"
  | Error e -> Alcotest.fail ("parse error: " ^ e)

let test_parse_1 () =
  match parse_miniscript "1" with
  | Ok Ms_1 -> ()
  | Ok _ -> Alcotest.fail "parsed wrong node type"
  | Error e -> Alcotest.fail ("parse error: " ^ e)

let test_parse_pk_k () =
  match parse_miniscript "pk_k(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)" with
  | Ok (Ms_pk_k (KeyBytes _)) -> ()
  | Ok _ -> Alcotest.fail "parsed wrong node type"
  | Error e -> Alcotest.fail ("parse error: " ^ e)

let test_parse_pk () =
  (* pk(key) = c:pk_k(key) *)
  match parse_miniscript "pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)" with
  | Ok (Ms_wrap (WrapC, Ms_pk_k _)) -> ()
  | Ok _ -> Alcotest.fail "parsed wrong node type"
  | Error e -> Alcotest.fail ("parse error: " ^ e)

let test_parse_older () =
  match parse_miniscript "older(144)" with
  | Ok (Ms_older 144) -> ()
  | Ok _ -> Alcotest.fail "parsed wrong node type"
  | Error e -> Alcotest.fail ("parse error: " ^ e)

let test_parse_after () =
  match parse_miniscript "after(500000)" with
  | Ok (Ms_after 500000) -> ()
  | Ok _ -> Alcotest.fail "parsed wrong node type"
  | Error e -> Alcotest.fail ("parse error: " ^ e)

let test_parse_sha256 () =
  match parse_miniscript "sha256(0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20)" with
  | Ok (Ms_sha256 _) -> ()
  | Ok _ -> Alcotest.fail "parsed wrong node type"
  | Error e -> Alcotest.fail ("parse error: " ^ e)

let test_parse_and_v () =
  match parse_miniscript "and_v(v:pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798),1)" with
  | Ok (Ms_and_v (Ms_wrap (WrapV, _), Ms_1)) -> ()
  | Ok _ -> Alcotest.fail "parsed wrong node type"
  | Error e -> Alcotest.fail ("parse error: " ^ e)

let test_parse_or_i () =
  match parse_miniscript "or_i(pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798),pk(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5))" with
  | Ok (Ms_or_i (Ms_wrap (WrapC, _), Ms_wrap (WrapC, _))) -> ()
  | Ok _ -> Alcotest.fail "parsed wrong node type"
  | Error e -> Alcotest.fail ("parse error: " ^ e)

let test_parse_multi () =
  match parse_miniscript "multi(2,0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)" with
  | Ok (Ms_multi (2, [_; _])) -> ()
  | Ok _ -> Alcotest.fail "parsed wrong node type"
  | Error e -> Alcotest.fail ("parse error: " ^ e)

let test_parse_thresh () =
  match parse_miniscript "thresh(2,pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798),s:pk(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5))" with
  | Ok (Ms_thresh (2, [_; _])) -> ()
  | Ok _ -> Alcotest.fail "parsed wrong node type"
  | Error e -> Alcotest.fail ("parse error: " ^ e)

let test_parse_wrapper_chain () =
  (* a:s:pk_k(key) *)
  match parse_miniscript "a:s:c:pk_k(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)" with
  | Ok (Ms_wrap (WrapA, Ms_wrap (WrapS, Ms_wrap (WrapC, Ms_pk_k _)))) -> ()
  | Ok _ -> Alcotest.fail "parsed wrong node type"
  | Error e -> Alcotest.fail ("parse error: " ^ e)

(* ============================================================================
   Roundtrip Tests
   ============================================================================ *)

let test_roundtrip node =
  let str1 = to_string node in
  match parse_miniscript str1 with
  | Ok parsed ->
    let str2 = to_string parsed in
    Alcotest.(check string) "roundtrip produces same string" str1 str2
  | Error e -> Alcotest.fail ("roundtrip parse error: " ^ e)

let test_roundtrip_pk () =
  test_roundtrip (Ms_wrap (WrapC, Ms_pk_k test_pubkey))

let test_roundtrip_and_v () =
  let node = Ms_and_v (Ms_wrap (WrapV, Ms_wrap (WrapC, Ms_pk_k test_pubkey)), Ms_1) in
  test_roundtrip node

let test_roundtrip_or_i () =
  let node = Ms_or_i (
    Ms_wrap (WrapC, Ms_pk_k test_pubkey),
    Ms_wrap (WrapC, Ms_pk_k test_pubkey2)
  ) in
  test_roundtrip node

let test_roundtrip_multi () =
  let node = Ms_multi (2, [test_pubkey; test_pubkey2]) in
  test_roundtrip node

let test_roundtrip_thresh () =
  let node = Ms_thresh (2, [
    Ms_wrap (WrapC, Ms_pk_k test_pubkey);
    Ms_wrap (WrapS, Ms_wrap (WrapC, Ms_pk_k test_pubkey2));
  ]) in
  test_roundtrip node

(* ============================================================================
   Satisfaction Tests
   ============================================================================ *)

let test_satisfy_0 () =
  let node = Ms_0 in
  let result = satisfy P2WSH empty_sign_ctx node in
  Alcotest.(check bool) "cannot satisfy 0" true (result.sat.available = AvailNo);
  Alcotest.(check bool) "can dissatisfy 0" true (result.dissat.available = AvailYes)

let test_satisfy_1 () =
  let node = Ms_1 in
  let result = satisfy P2WSH empty_sign_ctx node in
  Alcotest.(check bool) "can satisfy 1" true (result.sat.available = AvailYes);
  Alcotest.(check bool) "cannot dissatisfy 1" true (result.dissat.available = AvailNo)

let test_satisfy_pk_no_key () =
  let node = Ms_wrap (WrapC, Ms_pk_k test_pubkey) in
  let result = satisfy P2WSH empty_sign_ctx node in
  (* Without signing capability, satisfaction is "maybe" *)
  Alcotest.(check bool) "satisfaction is maybe without key" true (result.sat.available = AvailMaybe);
  Alcotest.(check bool) "can dissatisfy" true (result.dissat.available = AvailYes)

let test_satisfy_pk_with_key () =
  let sig_bytes = Cstruct.create 72 in  (* dummy signature *)
  let sign_ctx = {
    empty_sign_ctx with
    sign = (fun k -> match k with
      | KeyBytes _ -> Some sig_bytes
      | _ -> None);
  } in
  let node = Ms_wrap (WrapC, Ms_pk_k test_pubkey) in
  let result = satisfy P2WSH sign_ctx node in
  Alcotest.(check bool) "can satisfy with key" true (result.sat.available = AvailYes);
  Alcotest.(check bool) "sat has_sig" true result.sat.has_sig;
  Alcotest.(check int) "sat has 1 item" 1 (List.length result.sat.items)

let test_satisfy_older_met () =
  let sign_ctx = { empty_sign_ctx with check_older = (fun n -> n = 144) } in
  let node = Ms_older 144 in
  let result = satisfy P2WSH sign_ctx node in
  Alcotest.(check bool) "can satisfy older when met" true (result.sat.available = AvailYes);
  Alcotest.(check int) "sat has 0 items" 0 (List.length result.sat.items)

let test_satisfy_older_not_met () =
  let sign_ctx = { empty_sign_ctx with check_older = (fun _ -> false) } in
  let node = Ms_older 144 in
  let result = satisfy P2WSH sign_ctx node in
  Alcotest.(check bool) "satisfaction is maybe when not met" true (result.sat.available = AvailMaybe)

let test_satisfy_hash_with_preimage () =
  let preimage = Cstruct.create 32 in
  let sign_ctx = {
    empty_sign_ctx with
    lookup_preimage = (fun h ht ->
      if ht = HashSha256 && Cstruct.equal h test_hash32 then Some preimage
      else None);
  } in
  let node = Ms_sha256 test_hash32 in
  let result = satisfy P2WSH sign_ctx node in
  Alcotest.(check bool) "can satisfy with preimage" true (result.sat.available = AvailYes);
  Alcotest.(check int) "sat has 1 item" 1 (List.length result.sat.items)

let test_satisfy_and_v () =
  let sig_bytes = Cstruct.create 72 in
  let sign_ctx = {
    empty_sign_ctx with
    sign = (fun _ -> Some sig_bytes);
  } in
  let node = Ms_and_v (Ms_wrap (WrapV, Ms_wrap (WrapC, Ms_pk_k test_pubkey)), Ms_1) in
  let result = satisfy P2WSH sign_ctx node in
  Alcotest.(check bool) "can satisfy and_v" true (result.sat.available = AvailYes)

let test_satisfy_or_i () =
  let sig_bytes = Cstruct.create 72 in
  let sign_ctx = {
    empty_sign_ctx with
    sign = (fun k -> match k with
      | KeyBytes cs when Cstruct.equal cs (match test_pubkey with KeyBytes c -> c | _ -> Cstruct.empty) ->
        Some sig_bytes
      | _ -> None);
  } in
  let node = Ms_or_i (
    Ms_wrap (WrapC, Ms_pk_k test_pubkey),
    Ms_wrap (WrapC, Ms_pk_k test_pubkey2)
  ) in
  let result = satisfy P2WSH sign_ctx node in
  Alcotest.(check bool) "can satisfy or_i" true (result.sat.available = AvailYes);
  (* Should have witness items including the branch selector *)
  Alcotest.(check bool) "sat has items" true (List.length result.sat.items > 0)

(* ============================================================================
   Analysis Tests
   ============================================================================ *)

let test_analysis_script_size () =
  let node = Ms_wrap (WrapC, Ms_pk_k test_pubkey) in
  let size = script_size P2WSH node in
  Alcotest.(check bool) "script_size > 0" true (size > 0)

let test_analysis_max_sat () =
  let node = Ms_wrap (WrapC, Ms_pk_k test_pubkey) in
  let size = max_satisfaction_size P2WSH node in
  Alcotest.(check bool) "max_sat > 0" true (size > 0)

let test_analysis_requires_sig () =
  let node = Ms_wrap (WrapC, Ms_pk_k test_pubkey) in
  let requires = requires_signature P2WSH node in
  Alcotest.(check bool) "pk requires signature" true requires

let test_analysis_nonmalleable () =
  let node = Ms_wrap (WrapC, Ms_pk_k test_pubkey) in
  let nm = is_nonmalleable P2WSH node in
  Alcotest.(check bool) "pk is non-malleable" true nm

(* ============================================================================
   Test Suite
   ============================================================================ *)

let type_tests = [
  "type 0", `Quick, test_type_0;
  "type 1", `Quick, test_type_1;
  "type pk_k", `Quick, test_type_pk_k;
  "type pk_h", `Quick, test_type_pk_h;
  "type older", `Quick, test_type_older;
  "type after", `Quick, test_type_after;
  "type sha256", `Quick, test_type_sha256;
  "type and_v", `Quick, test_type_and_v;
  "type and_b", `Quick, test_type_and_b;
  "type or_b", `Quick, test_type_or_b;
  "type multi", `Quick, test_type_multi;
  "type multi tapscript error", `Quick, test_type_multi_tapscript_error;
  "type multi_a", `Quick, test_type_multi_a;
  "type thresh", `Quick, test_type_thresh;
  "type wrapper a", `Quick, test_type_wrapper_a;
  "type wrapper c", `Quick, test_type_wrapper_c;
  "type wrapper v", `Quick, test_type_wrapper_v;
]

let script_tests = [
  "script 0", `Quick, test_script_0;
  "script 1", `Quick, test_script_1;
  "script pk_k", `Quick, test_script_pk_k;
  "script pk", `Quick, test_script_pk;
  "script older", `Quick, test_script_older;
  "script after", `Quick, test_script_after;
  "script sha256", `Quick, test_script_sha256;
  "script multi", `Quick, test_script_multi;
  "script and_v", `Quick, test_script_and_v;
  "script or_i", `Quick, test_script_or_i;
  "script thresh", `Quick, test_script_thresh;
]

let parse_tests = [
  "parse 0", `Quick, test_parse_0;
  "parse 1", `Quick, test_parse_1;
  "parse pk_k", `Quick, test_parse_pk_k;
  "parse pk", `Quick, test_parse_pk;
  "parse older", `Quick, test_parse_older;
  "parse after", `Quick, test_parse_after;
  "parse sha256", `Quick, test_parse_sha256;
  "parse and_v", `Quick, test_parse_and_v;
  "parse or_i", `Quick, test_parse_or_i;
  "parse multi", `Quick, test_parse_multi;
  "parse thresh", `Quick, test_parse_thresh;
  "parse wrapper chain", `Quick, test_parse_wrapper_chain;
]

let roundtrip_tests = [
  "roundtrip pk", `Quick, test_roundtrip_pk;
  "roundtrip and_v", `Quick, test_roundtrip_and_v;
  "roundtrip or_i", `Quick, test_roundtrip_or_i;
  "roundtrip multi", `Quick, test_roundtrip_multi;
  "roundtrip thresh", `Quick, test_roundtrip_thresh;
]

let satisfy_tests = [
  "satisfy 0", `Quick, test_satisfy_0;
  "satisfy 1", `Quick, test_satisfy_1;
  "satisfy pk no key", `Quick, test_satisfy_pk_no_key;
  "satisfy pk with key", `Quick, test_satisfy_pk_with_key;
  "satisfy older met", `Quick, test_satisfy_older_met;
  "satisfy older not met", `Quick, test_satisfy_older_not_met;
  "satisfy hash with preimage", `Quick, test_satisfy_hash_with_preimage;
  "satisfy and_v", `Quick, test_satisfy_and_v;
  "satisfy or_i", `Quick, test_satisfy_or_i;
]

let analysis_tests = [
  "analysis script_size", `Quick, test_analysis_script_size;
  "analysis max_sat", `Quick, test_analysis_max_sat;
  "analysis requires_sig", `Quick, test_analysis_requires_sig;
  "analysis nonmalleable", `Quick, test_analysis_nonmalleable;
]

let () =
  Alcotest.run "Miniscript" [
    "type system", type_tests;
    "script generation", script_tests;
    "parsing", parse_tests;
    "roundtrip", roundtrip_tests;
    "satisfaction", satisfy_tests;
    "analysis", analysis_tests;
  ]
