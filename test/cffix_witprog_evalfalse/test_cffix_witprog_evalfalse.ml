(* cffix-camlcoin-witprog-evalfalse (from secscan2-camlcoin F2, 2026-11-25,
   camlcoin 482c676).

   Core v31.1 VerifyScript (src/script/interpreter.cpp) always evaluates the
   scriptPubKey -- and, for P2SH, the redeemScript -- and requires
   CastToBool(stack.back()) BEFORE it looks at IsWitnessProgram:

     if (!EvalScript(stack, scriptSig, ...)) return false;
     ...
     if (!EvalScript(stack, scriptPubKey, ...)) return false;
     if (stack.empty()) return EVAL_FALSE;                       (:2027)
     if (CastToBool(stack.back()) == false) return EVAL_FALSE;   (:2030)
     // Bare witness programs                                     (:2036)
     if (scriptPubKey.IsWitnessProgram(...)) {
         if (scriptSig.size() != 0) return WITNESS_MALLEATED; ... }
     ... P2SH: EvalScript(stack, pubKey2); empty/false -> EVAL_FALSE (:2073-2077)
         then pubKey2.IsWitnessProgram -> WITNESS_MALLEATED_P2SH ... (:2080)

   Evaluating "<OP_n> <program>" leaves <program> on top, so a program of
   all-zero bytes (or negative zero, 00..80) is FALSE and Core rejects the
   spend by consensus.  camlcoin's verify_script returned [Ok true] for an
   unknown-version program without evaluating it, so it accepted a block Core
   rejects.

   camlcoin reports EVAL_FALSE as [Ok false] (check_stack_top).  The
   [false_program] groups assert the node does not accept; the [error_order]
   group asserts Core's order exactly: a malleated scriptSig with a FALSE
   program is EVAL_FALSE ([Ok false]), while with a TRUE program it is still
   WITNESS_MALLEATED ([Error _]).  The controls pin that valid P2WSH,
   P2SH-P2WSH, P2SH-P2WPKH and key-path P2TR spends, and TRUE upgradable
   programs, still accept, and that bad signatures / wrong hashes still
   reject (nothing invalid became valid). *)

open Camlcoin

let block_flags = Consensus.get_block_script_flags 900_000 Consensus.mainnet

let hex s =
  let n = String.length s / 2 in
  let c = Cstruct.create n in
  for i = 0 to n - 1 do
    Cstruct.set_uint8 c i (int_of_string ("0x" ^ String.sub s (2 * i) 2))
  done;
  c

let push (d : Cstruct.t) =
  let n = Cstruct.length d in
  assert (n < 0x4c);
  Cstruct.append (Cstruct.of_string (String.make 1 (Char.chr n))) d

let p2sh_spk (redeem : Cstruct.t) =
  Cstruct.concat [ hex "a914"; Crypto.hash160 redeem; hex "87" ]

let crediting_tx spk : Types.transaction =
  { version = 1l;
    inputs = [ { previous_output = { txid = Cstruct.create 32; vout = 0xFFFFFFFFl };
                 script_sig = hex "0000"; sequence = 0xFFFFFFFFl } ];
    outputs = [ { value = 1000L; script_pubkey = spk } ];
    witnesses = []; locktime = 0l }

let spending_tx ~spk ~script_sig ~wit : Types.transaction =
  let credit = crediting_tx spk in
  { version = 1l;
    inputs = [ { previous_output = { txid = Crypto.compute_txid credit; vout = 0l };
                 script_sig; sequence = 0xFFFFFFFFl } ];
    outputs = [ { value = 1000L; script_pubkey = Cstruct.empty } ];
    witnesses = (if wit = [] then [] else [ Types.{ items = wit } ]); locktime = 0l }

let verify_tx ?(flags = block_flags) ~spk (tx : Types.transaction) =
  let inp = List.hd tx.inputs in
  let witness =
    match tx.witnesses with w :: _ -> w | [] -> Types.{ items = [] } in
  Script.verify_script ~tx ~input_index:0 ~script_pubkey:spk
    ~script_sig:inp.script_sig ~witness ~amount:1000L ~flags
    ~prevouts:[ (1000L, spk) ] ()

let verify ?flags ~spk ~script_sig ~wit () =
  verify_tx ?flags ~spk (spending_tx ~spk ~script_sig ~wit)

let show = function
  | Ok b -> Printf.sprintf "Ok %b" b
  | Error e -> "Error " ^ e

(* program script "<OP_v> <push program>" *)
let prog v program =
  let op = if v = 0 then 0x00 else 0x50 + v in
  Cstruct.append (Cstruct.of_string (String.make 1 (Char.chr op))) (push program)

let zeros n = Cstruct.create n
let negzero n = let c = Cstruct.create n in Cstruct.set_uint8 c (n - 1) 0x80; c

let false_programs = [
  "v1_len2_zero",    prog 1 (zeros 2);
  "v2_len2_zero",    prog 2 (zeros 2);
  "v3_len32_zero",   prog 3 (zeros 32);
  "v16_len40_zero",  prog 16 (zeros 40);
  "v1_len2_negzero", prog 1 (negzero 2);
  "v2_len20_negzero",prog 2 (negzero 20);
]

let must_reject name f () =
  let r = f () in
  Printf.printf "%s -> %s\n%!" name (show r);
  Alcotest.(check bool) (name ^ ": Core rejects, node must not accept")
    false (r = Ok true)

let must_accept name f () =
  let r = f () in
  Printf.printf "%s -> %s\n%!" name (show r);
  Alcotest.(check bool) (name ^ ": Core OK, node must accept") true (r = Ok true)

(* Core EVAL_FALSE == camlcoin [Ok false] *)
let must_eval_false name f () =
  let r = f () in
  Printf.printf "%s -> %s\n%!" name (show r);
  Alcotest.(check string) (name ^ ": Core EVAL_FALSE") "Ok false" (show r)

(* Core WITNESS_MALLEATED(_P2SH) == camlcoin [Error "WITNESS_MALLEATED..."]
   or "scriptSig must be empty ..." *)
let must_malleated name f () =
  let r = f () in
  Printf.printf "%s -> %s\n%!" name (show r);
  let ok = match r with
    | Error e ->
      let has sub =
        let ls = String.length sub and le = String.length e in
        let rec go i = i + ls <= le && (String.sub e i ls = sub || go (i + 1)) in
        go 0
      in
      has "WITNESS_MALLEATED" || has "scriptSig must be empty"
    | Ok _ -> false
  in
  Alcotest.(check bool) (name ^ ": Core WITNESS_MALLEATED") true ok

let native_false =
  List.map (fun (n, spk) ->
      Alcotest.test_case ("native " ^ n) `Quick
        (must_reject ("native " ^ n)
           (fun () -> verify ~spk ~script_sig:Cstruct.empty ~wit:[] ())))
    false_programs

let p2sh_false =
  List.map (fun (n, redeem) ->
      Alcotest.test_case ("p2sh " ^ n) `Quick
        (must_reject ("p2sh " ^ n)
           (fun () -> verify ~spk:(p2sh_spk redeem) ~script_sig:(push redeem) ~wit:[] ())))
    false_programs

(* The known-version arms and the pre-activation arms also dispatched before
   evaluating.  Flags here are script-level (as script_tests.json uses them):
   a v0 / v1-32 program is FALSE when all zero, whatever the flags. *)
let other_flags_false = [
  Alcotest.test_case "v1_len32_zero, witness without taproot" `Quick
    (must_reject "v1_len32_zero p2sh|witness"
       (fun () -> verify ~flags:(Script.script_verify_p2sh lor Script.script_verify_witness)
           ~spk:(prog 1 (zeros 32)) ~script_sig:Cstruct.empty ~wit:[] ()));
  Alcotest.test_case "v0_len20_zero, p2sh flag only (pre-segwit)" `Quick
    (must_reject "v0_len20_zero p2sh-only"
       (fun () -> verify ~flags:Script.script_verify_p2sh
           ~spk:(prog 0 (zeros 20)) ~script_sig:Cstruct.empty ~wit:[] ()));
  Alcotest.test_case "v0_len32_zero, p2sh flag only (pre-segwit)" `Quick
    (must_reject "v0_len32_zero p2sh-only"
       (fun () -> verify ~flags:Script.script_verify_p2sh
           ~spk:(prog 0 (zeros 32)) ~script_sig:Cstruct.empty ~wit:[] ()));
]

let op_true = hex "51"
let p2wsh_true = prog 0 (Crypto.sha256 op_true)

(* Core's error order: EVAL_FALSE is checked before WITNESS_MALLEATED. *)
let error_order = [
  Alcotest.test_case "native malleated scriptSig + false program = EVAL_FALSE" `Quick
    (must_eval_false "native malleated v2_len2_zero"
       (fun () -> verify ~spk:(prog 2 (zeros 2)) ~script_sig:op_true ~wit:[] ()));
  Alcotest.test_case "p2sh malleated scriptSig + false program = EVAL_FALSE" `Quick
    (must_eval_false "p2sh malleated v1_len2_zero"
       (fun () -> let r = prog 1 (zeros 2) in
         verify ~spk:(p2sh_spk r) ~script_sig:(Cstruct.append (hex "00") (push r))
           ~wit:[] ()));
  Alcotest.test_case "control native malleated scriptSig + true program = MALLEATED" `Quick
    (must_malleated "native malleated v2_len2_true"
       (fun () -> verify ~spk:(prog 2 (hex "0001")) ~script_sig:op_true ~wit:[] ()));
  Alcotest.test_case "control p2sh malleated scriptSig + true program = MALLEATED" `Quick
    (must_malleated "p2sh malleated v1_len2_true"
       (fun () -> let r = prog 1 (hex "0100") in
         verify ~spk:(p2sh_spk r) ~script_sig:(Cstruct.append (hex "00") (push r))
           ~wit:[] ()));
]

(* Fixed test keys (no randomness). *)
let privkey = hex "0101010101010101010101010101010101010101010101010101010101010101"

(* Valid P2SH-P2WPKH: redeem = 0014<hash160(pub)>, scriptSig = push(redeem),
   witness = [sig||ALL; pub]. *)
let p2sh_p2wpkh ~corrupt () =
  let pub = Crypto.derive_public_key ~compressed:true privkey in
  let h = Crypto.hash160 pub in
  let redeem = prog 0 h in
  let spk = p2sh_spk redeem in
  let script_sig = push redeem in
  let unsigned = spending_tx ~spk ~script_sig ~wit:[] in
  let script_code = Cstruct.concat [ hex "76a914"; h; hex "88ac" ] in
  let sighash = Script.compute_sighash_segwit unsigned 0 script_code 1000L 1 in
  let sighash =
    if corrupt then (let c = Cstruct.create 32 in Cstruct.blit sighash 0 c 0 32;
                     Cstruct.set_uint8 c 0 (Cstruct.get_uint8 c 0 lxor 1); c)
    else sighash in
  let sg = Cstruct.append (Crypto.sign privkey sighash) (hex "01") in
  verify ~spk ~script_sig ~wit:[ sg; pub ] ()

(* Valid key-path P2TR: spk = 5120<Q>, witness = [schnorr sig (SIGHASH_DEFAULT)]. *)
let p2tr_keypath ~corrupt () =
  let internal = Crypto.derive_xonly_pubkey privkey in
  let q = Crypto.compute_taproot_output_key internal None in
  let spk = prog 1 q in
  let unsigned = spending_tx ~spk ~script_sig:Cstruct.empty ~wit:[] in
  let msg = Script.compute_sighash_taproot unsigned 0 [ (1000L, spk) ] 0 () in
  let tweak = Crypto.compute_taptweak_keypath internal in
  let sg = Crypto.schnorr_sign_tweaked ~privkey ~tweak ~msg in
  if corrupt then Cstruct.set_uint8 sg 63 (Cstruct.get_uint8 sg 63 lxor 1);
  verify ~spk ~script_sig:Cstruct.empty ~wit:[ sg ] ()

let controls = [
  Alcotest.test_case "control native v2_len2 true (0001)" `Quick
    (must_accept "control native v2_len2_true"
       (fun () -> verify ~spk:(prog 2 (hex "0001")) ~script_sig:Cstruct.empty ~wit:[] ()));
  Alcotest.test_case "control p2sh v1_len2 true (0100)" `Quick
    (must_accept "control p2sh v1_len2_true"
       (fun () -> let r = prog 1 (hex "0100") in
         verify ~spk:(p2sh_spk r) ~script_sig:(push r) ~wit:[] ()));
  Alcotest.test_case "control native v16_len40 true" `Quick
    (must_accept "control native v16_len40_true"
       (fun () -> let p = zeros 40 in Cstruct.set_uint8 p 0 1;
         verify ~spk:(prog 16 p) ~script_sig:Cstruct.empty ~wit:[] ()));
  Alcotest.test_case "control native p2wsh(OP_1)" `Quick
    (must_accept "control native p2wsh_op_true"
       (fun () -> verify ~spk:p2wsh_true ~script_sig:Cstruct.empty ~wit:[ op_true ] ()));
  Alcotest.test_case "control p2sh-p2wsh(OP_1)" `Quick
    (must_accept "control p2sh_p2wsh_op_true"
       (fun () -> verify ~spk:(p2sh_spk p2wsh_true) ~script_sig:(push p2wsh_true)
           ~wit:[ op_true ] ()));
  Alcotest.test_case "control p2sh-p2wpkh valid signature" `Quick
    (must_accept "control p2sh_p2wpkh_valid" (p2sh_p2wpkh ~corrupt:false));
  Alcotest.test_case "control p2tr key-path valid signature" `Quick
    (must_accept "control p2tr_keypath_valid" (p2tr_keypath ~corrupt:false));
  Alcotest.test_case "control p2a anchor" `Quick
    (must_accept "control p2a"
       (fun () -> verify ~spk:(hex "51024e73") ~script_sig:Cstruct.empty ~wit:[] ()));
  Alcotest.test_case "negative control p2sh wrong hash" `Quick
    (must_reject "negctrl p2sh_wrong_hash"
       (fun () -> let r = prog 1 (hex "0100") in
         verify ~spk:(p2sh_spk (prog 1 (hex "0200"))) ~script_sig:(push r) ~wit:[] ()));
  Alcotest.test_case "negative control p2sh-p2wpkh bad signature" `Quick
    (must_reject "negctrl p2sh_p2wpkh_badsig" (p2sh_p2wpkh ~corrupt:true));
  Alcotest.test_case "negative control p2tr key-path bad signature" `Quick
    (must_reject "negctrl p2tr_keypath_badsig" (p2tr_keypath ~corrupt:true));
]

let () =
  Alcotest.run "cffix_witprog_evalfalse"
    [ "native_false_program", native_false;
      "p2sh_false_program", p2sh_false;
      "other_flags_false_program", other_flags_false;
      "error_order", error_order;
      "controls", controls ]
