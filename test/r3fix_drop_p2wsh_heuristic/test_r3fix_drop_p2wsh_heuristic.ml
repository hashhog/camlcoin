(* r3fix-camlcoin-drop-p2wsh-heuristic.

   Core v31.1 applies the P2WSH witness limits (script <= 3600 B, <= 100
   stack items, each item <= 80 B) only to an input whose prevout program is
   v0 32-byte, inside IsWitnessStandard (policy/policy.cpp:300-311).  A
   tapscript spend caps only the items below script + control block at
   MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE = 80 and has no item-count limit
   (policy.cpp:324-333).  IsStandardTx (policy.cpp:95-155) has no witness
   check at all.

   camlcoin's IsStandardTx used to run a prevout-blind heuristic that called
   every witness with >= 2 items and a last item > 1 B "P2WSH", so for a
   tapscript spend the CONTROL BLOCK was the "witness script" and the LEAF
   was an 80-byte-capped "stack item".  The R3 generating fuzzer (seed
   739943, night 1) found Core accepting tapscript spends camlcoin refused
   (rows R82 / R87) and the heuristic masking Core's reason in ~35 reason
   rows. *)

open Camlcoin

let of_hex (s : string) : Cstruct.t =
  let n = String.length s / 2 in
  let b = Bytes.create n in
  for i = 0 to n - 1 do
    Bytes.set b i (Char.chr (int_of_string ("0x" ^ String.sub s (2 * i) 2)))
  done;
  Cstruct.of_bytes b

let decode_tx (h : string) : Types.transaction =
  Serialize.deserialize_transaction (Serialize.reader_of_cstruct (of_hex h))

(* R82 mempool/verdict/accept|other:p2wsh, seed 739943: a tapscript 3-of-3
   CHECKSIGADD leaf (105 B) + 3 Schnorr sigs + 33-B control block.  Core
   v31.1: allowed.  camlcoin master: "P2WSH witness stack item too large at
   input 0, item 3 (105 > 80)" (item 3 = the leaf script). *)
let r82_hex =
  "0200000000010170f98c9acb74341bc1101afde62e3c21f6bb427aed2bf68f451c77ab125b74710800000000feffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc3326005402098b0a982554eb27527b0348dd077a0a6195ee741a3e584bf2e17804518cf089f80f150dfec3f4b75dea966b440740590d2c499380c0e41fa67440d757253df402098b0a982554eb27527b0348dd077a0a6195ee741a3e584bf2e17804518cf089f80f150dfec3f4b75dea966b440740590d2c499380c0e41fa67440d757253df402098b0a982554eb27527b0348dd077a0a6195ee741a3e584bf2e17804518cf089f80f150dfec3f4b75dea966b440740590d2c499380c0e41fa67440d757253df692079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac2079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ba2079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ba539d5121c079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179800000000"

(* The R82 funding output: 100000 sat to this P2TR key.  It is output 8 of
   the batch-24 funding block that tools/diff-fuzz/gen_fuzz.py builds for
   seed 739943 (3000 cases, generator v1) on Core v31.1. *)
let r82_prev_value = 100_000L
let r82_prev_spk =
  of_hex "5120d5304c9d007e072ece112bd66ed3a92fe6db55458cd1d8e527464608abce17bf"

let p2tr_spk = Cstruct.append (of_hex "5120") (Cstruct.create 32)

let p2wsh_spk_of (script : Cstruct.t) =
  Cstruct.append (of_hex "0020") (Crypto.sha256 script)

let fill n byte = Cstruct.of_string (String.make n (Char.chr byte))

(* A tapscript control block: leaf version 0xc0, a 32-byte internal key and
   [depth] 32-byte path nodes (33 + 32*depth bytes, BIP-341). *)
let control_block ~depth = Cstruct.append (of_hex "c0") (fill (32 + 32 * depth) 0x02)

let prev_txid = Cstruct.of_string (String.make 32 '\x5a')

let spend_with_witness (items : Cstruct.t list) : Types.transaction =
  { Types.version = 2l;
    inputs = [ { Types.previous_output = { Types.txid = prev_txid; vout = 0l };
                 script_sig = Cstruct.empty; sequence = 0xFFFFFFFFl } ];
    outputs = [ { Types.value = 90_000L;
                  script_pubkey = p2wsh_spk_of (of_hex "51") } ];
    witnesses = [ { Types.items } ];
    locktime = 0l }

let iws prev_spk tx = Mempool.is_witness_standard ~lookup:(fun _ -> Some prev_spk) tx

let show = function Ok () -> "Ok" | Error e -> "Error: " ^ e

let check_ok name r = Alcotest.(check string) name "Ok" (show r)

let check_refused name r =
  match r with
  | Error e ->
    Alcotest.(check bool) (name ^ " (" ^ e ^ ")") true
      (String.length e >= 23 && String.sub e 0 23 = "bad-witness-nonstandard")
  | Ok () -> Alcotest.fail (name ^ ": accepted, Core refuses bad-witness-nonstandard")

(* --- Fail on master ------------------------------------------------------ *)

let test_r82_is_standard_tx () =
  check_ok "R82: IsStandardTx accepts a tapscript spend with a 105-B leaf"
    (Mempool.is_standard_tx 1000L (decode_tx r82_hex))

let with_mempool ?(verify_scripts = true) coins f =
  Test_tmp.with_chaindb (fun db ->
      let utxo = Utxo.UtxoSet.create db in
      List.iter (fun ((op : Types.outpoint), value, spk) ->
          Utxo.UtxoSet.add utxo op.txid (Int32.to_int op.vout)
            Utxo.{ value; script_pubkey = spk; height = 1; is_coinbase = false })
        coins;
      let mp = Mempool.create ~network:Consensus.regtest ~require_standard:true
          ~verify_scripts ~utxo ~current_height:200 () in
      f mp)

let test_r82_mempool_accept () =
  (* The whole accept path, scripts verified, as testmempoolaccept runs it. *)
  let tx = decode_tx r82_hex in
  let op = (List.hd tx.Types.inputs).Types.previous_output in
  with_mempool [ (op, r82_prev_value, r82_prev_spk) ] (fun mp ->
      match Mempool.add_transaction ~dry_run:true mp tx with
      | Ok _ -> ()
      | Error e -> Alcotest.fail ("R82: Core allowed, camlcoin refused: " ^ e))

let test_tapscript_101_stack_items () =
  (* Tapscript has no stack-item COUNT limit (policy.cpp:324-333). *)
  let items = List.init 101 (fun _ -> fill 1 0x01) in
  let tx = spend_with_witness (items @ [ of_hex "6d6d51"; control_block ~depth:0 ]) in
  check_ok "IsStandardTx: 101 tapscript stack items" (Mempool.is_standard_tx 1000L tx);
  check_ok "IsWitnessStandard(P2TR): 101 tapscript stack items" (iws p2tr_spk tx)

let test_tapscript_deep_control_block () =
  (* A 128-deep path: 33 + 32*128 = 4129-B control block (> 3600). *)
  let cb = control_block ~depth:128 in
  Alcotest.(check int) "control block size" 4129 (Cstruct.length cb);
  let tx = spend_with_witness [ fill 64 0x01; of_hex "51"; cb ] in
  check_ok "IsStandardTx: 4129-B control block" (Mempool.is_standard_tx 1000L tx);
  check_ok "IsWitnessStandard(P2TR): 4129-B control block" (iws p2tr_spk tx)

let test_p2wsh_reason_is_witness_nonstandard () =
  (* A real P2WSH spend over the item limit is still refused on the full
     path, with Core's reason (IsWitnessStandard -> bad-witness-nonstandard),
     not the old IsStandardTx message. *)
  let script = of_hex "7551" in
  let tx = spend_with_witness [ fill 81 0x01; script ] in
  let op = (List.hd tx.Types.inputs).Types.previous_output in
  with_mempool ~verify_scripts:false [ (op, 100_000L, p2wsh_spk_of script) ] (fun mp ->
      match Mempool.add_transaction ~dry_run:true mp tx with
      | Ok _ -> Alcotest.fail "P2WSH 81-B stack item accepted; Core refuses"
      | Error e -> check_refused "P2WSH 81-B stack item, full path" (Error e))

(* --- Controls: the prevout-aware limits must still bite ------------------- *)

let test_controls_p2wsh_limits () =
  let script = of_hex "7551" in
  let spk = p2wsh_spk_of script in
  check_ok "P2WSH 80-B item" (iws spk (spend_with_witness [ fill 80 0x01; script ]));
  check_refused "P2WSH 81-B item" (iws spk (spend_with_witness [ fill 81 0x01; script ]));
  let n k = List.init k (fun _ -> fill 1 0x01) in
  check_ok "P2WSH 100 items" (iws spk (spend_with_witness (n 100 @ [ script ])));
  check_refused "P2WSH 101 items" (iws spk (spend_with_witness (n 101 @ [ script ])));
  check_ok "P2WSH 3600-B script"
    (iws (p2wsh_spk_of (fill 3600 0x51)) (spend_with_witness [ fill 3600 0x51 ]));
  check_refused "P2WSH 3601-B script"
    (iws (p2wsh_spk_of (fill 3601 0x51)) (spend_with_witness [ fill 3601 0x51 ]))

let test_controls_tapscript_item_limit () =
  let leaf = of_hex "75" in
  check_ok "tapscript 80-B stack item"
    (iws p2tr_spk (spend_with_witness [ fill 80 0x01; leaf; control_block ~depth:0 ]));
  check_refused "tapscript 81-B stack item"
    (iws p2tr_spk (spend_with_witness [ fill 81 0x01; leaf; control_block ~depth:0 ]));
  (* The leaf and control block themselves are not capped. *)
  check_ok "tapscript 105-B leaf, R82 shape"
    (iws p2tr_spk (decode_tx r82_hex))

let () =
  Alcotest.run "r3fix_drop_p2wsh_heuristic"
    [ ( "core-parity",
        [ Alcotest.test_case "R82 IsStandardTx accepts tapscript 105-B leaf" `Quick
            test_r82_is_standard_tx;
          Alcotest.test_case "R82 full mempool accept with scripts" `Quick
            test_r82_mempool_accept;
          Alcotest.test_case "tapscript 101 stack items standard" `Quick
            test_tapscript_101_stack_items;
          Alcotest.test_case "tapscript 4129-B control block standard" `Quick
            test_tapscript_deep_control_block;
          Alcotest.test_case "P2WSH over-limit refused as bad-witness-nonstandard" `Quick
            test_p2wsh_reason_is_witness_nonstandard ] );
      ( "controls",
        [ Alcotest.test_case "P2WSH 80/100/3600 limits still enforced" `Quick
            test_controls_p2wsh_limits;
          Alcotest.test_case "tapscript 80-B item limit still enforced" `Quick
            test_controls_tapscript_item_limit ] ) ]
