(* Legacy FindAndDelete parity with Bitcoin Core v31.1.

   Core src/script/interpreter.cpp, EvalScript OP_CHECKMULTISIG(VERIFY),
   SigVersion::BASE:

       for (int k = 0; k < nSigsCount; k++) {
           valtype& vchSig = stacktop(-isig-k);
           if (sigversion == SigVersion::BASE) {
               int found = FindAndDelete(scriptCode, CScript() << vchSig);
               if (found > 0 && (flags & SCRIPT_VERIFY_CONST_SCRIPTCODE))
                   return set_error(serror, SCRIPT_ERR_SIG_FINDANDDELETE);
           }
       }

   EvalChecksigPreTapscript does the same for OP_CHECKSIG(VERIFY), before
   any signature or pubkey encoding check.  Every signature is deleted,
   the empty one included: CScript() << valtype{} is the single byte 0x00,
   so every opcode-aligned OP_0 leaves the scriptCode.  The pattern is the
   minimal push CScript::operator<< builds: a direct push for 1-75 bytes,
   4c <len> for 76-255, 4d <len16> for 256-65535.

   camlcoin skipped empty signatures, and built the pattern for 77- and
   78-byte signatures with the length in the opbyte slot of OP_PUSHDATA,
   so it searched for 4d 4d 00 <77> / 4e 4e 00 00 00 <78> instead of
   4c 4d <77> / 4c 4e <78>.  Both change the legacy sighash, so a block
   Core rejects was accepted and a block Core accepts was rejected.

     CAMLCOIN_TEST_TMPDIR=... dune exec \
       test/multisig_findanddelete_empty_sig/test_multisig_findanddelete_empty_sig.exe

   With FAD_DUMP_DIR set, the block cases also write the regtest chain they
   submit (one block hex per line) so it can be replayed into bitcoind. *)

open Camlcoin

(* ---------- bytes ---------- *)

let hex_to_cstruct s =
  let n = String.length s / 2 in
  let cs = Cstruct.create n in
  for i = 0 to n - 1 do
    Cstruct.set_uint8 cs i (int_of_string ("0x" ^ String.sub s (2 * i) 2))
  done;
  cs

let to_hex cs =
  let b = Buffer.create (Cstruct.length cs * 2) in
  for i = 0 to Cstruct.length cs - 1 do
    Buffer.add_string b (Printf.sprintf "%02x" (Cstruct.get_uint8 cs i))
  done;
  Buffer.contents b

let byte n = let c = Cstruct.create 1 in Cstruct.set_uint8 c 0 n; c
let bytes_of l = Cstruct.concat (List.map byte l)
let filled n v = let c = Cstruct.create n in Cstruct.memset c v; c

(* Core's CScript::operator<<(valtype): the push FindAndDelete looks for. *)
let push (d : Cstruct.t) =
  let n = Cstruct.length d in
  if n < 0x4c then Cstruct.concat [byte n; d]
  else if n <= 0xff then Cstruct.concat [byte 0x4c; byte n; d]
  else begin
    let l = Cstruct.create 2 in
    Cstruct.LE.set_uint16 l 0 n;
    Cstruct.concat [byte 0x4d; l; d]
  end

let op_0 = 0x00 and op_drop = 0x75 and op_not = 0x91
and op_checksig = 0xac and op_checksigverify = 0xad
and op_checkmultisig = 0xae and op_1 = 0x51 and op_2 = 0x52
and op_3 = 0x53 and op_4 = 0x54

(* ---------- keys and signatures (RFC 6979, deterministic) ---------- *)

let seckey i = let k = Cstruct.create 32 in Cstruct.set_uint8 k 31 i; k
let pubkey i = Crypto.derive_public_key ~compressed:true (seckey i)
let pk1 = pubkey 1 and pk2 = pubkey 2 and pk3 = pubkey 3 and pk4 = pubkey 4

let sign_legacy i tx code =
  let h = Script.compute_sighash_legacy tx 0 code 1 in
  Cstruct.concat [Crypto.sign (seckey i) h; byte 1]

let sign_segwit i tx code amount =
  let h = Script.compute_sighash_segwit tx 0 code amount 1 in
  Cstruct.concat [Crypto.sign (seckey i) h; byte 1]

let op_true = byte op_1

(* P2WSH(OP_TRUE): a standard output, so Core's testmempoolaccept reaches
   the script checks of the CONST_SCRIPTCODE replays. *)
let p2wsh_true = Cstruct.concat [bytes_of [0x00; 0x20]; Crypto.sha256 op_true]

let spend_tx ?(prev = filled 32 0x11) ?(value = 1000L) ?(out = op_true) ()
    : Types.transaction =
  { Types.version = 1l;
    inputs = [{ Types.previous_output = { Types.txid = prev; vout = 0l };
                script_sig = Cstruct.empty; sequence = 0xFFFFFFFFl }];
    outputs = [{ Types.value; script_pubkey = out }];
    witnesses = []; locktime = 0l }

let with_sig (tx : Types.transaction) script_sig : Types.transaction =
  match tx.Types.inputs with
  | [i] -> { tx with Types.inputs = [{ i with Types.script_sig }] }
  | _ -> assert false

(* Core's block flags at a post-taproot height. *)
let block_flags =
  Script.(script_verify_p2sh lor script_verify_dersig
          lor script_verify_checklocktimeverify
          lor script_verify_checksequenceverify lor script_verify_witness
          lor script_verify_nulldummy lor script_verify_taproot)

let const_flags = block_flags lor Script.script_verify_const_scriptcode

let verdict ?(witness = []) ?(amount = 0L) ~flags ~spk tx =
  match Script.verify_script ~tx ~input_index:0 ~script_pubkey:spk
          ~script_sig:(List.hd tx.Types.inputs).Types.script_sig
          ~witness:{ Types.items = witness } ~amount ~flags () with
  | Ok true -> "valid"
  | Ok false -> "invalid:false"
  | Error e -> "invalid:" ^ e

let check_valid msg v = Alcotest.(check string) msg "valid" v

(* ---------- the scripts of the item ---------- *)

(* Input 1: 00 75 53 <pk1..pk4> 54 ae 91 -- the leading OP_0 is what Core's
   empty-signature FindAndDelete removes. *)
let ms_body = Cstruct.concat [byte op_3; push pk1; push pk2; push pk3;
                              push pk4; byte op_4; byte op_checkmultisig;
                              byte op_not]
let spk1 = Cstruct.concat [bytes_of [op_0; op_drop]; ms_body]
let core_code1 = Cstruct.concat [byte op_drop; ms_body]  (* 00 deleted *)

(* scriptSig 00 00 01 01 <S>: dummy, empty sig, 1-byte non-DER sig, S on top. *)
let sig1_script s = Cstruct.concat [bytes_of [op_0; op_0; 0x01; 0x01]; push s]

(* Input 2: 4c <n> <G> 75 52 <pk1> <pk2> 52 ae 91, G an n-byte non-DER blob
   that is also pushed as a signature. *)
let p2sh redeem =
  Cstruct.concat [bytes_of [0xa9; 0x14]; Crypto.hash160 redeem; byte 0x87]

let spk2 g = Cstruct.concat [push g; byte op_drop; byte op_2; push pk1;
                             push pk2; byte op_2; byte op_checkmultisig;
                             byte op_not]
let sig2_script g s = Cstruct.concat [byte op_0; push g; push s]

(* ---------- FindAndDelete, Core's pattern for every sig length ---------- *)

let test_fad_size n () =
  let d = filled n 0xcd in
  let pat = push d in
  let script = Cstruct.concat [pat; byte op_1; pat] in
  let (out, removed) = Script.find_and_delete script d in
  Alcotest.(check bool) "removed" true removed;
  Alcotest.(check string) "only OP_1 left" "51" (to_hex out)

(* An empty sig deletes opcode-aligned OP_0 only: 0x00 bytes inside a push
   (or a direct push that runs past the end of the script) stay. *)
let test_fad_empty_alignment () =
  let cases = [
    "000051",   "51",       true;
    "0200005100", "02000051", true;
    "4c0000",   "4c00",     true;     (* PUSHDATA1 of zero bytes, then OP_0 *)
    "510400",   "510400",   false;    (* direct push past the end *)
    "51",       "51",       false;
  ] in
  List.iter (fun (inp, want, want_removed) ->
    let (out, removed) = Script.find_and_delete (hex_to_cstruct inp) Cstruct.empty in
    Alcotest.(check string) ("result for " ^ inp) want (to_hex out);
    Alcotest.(check bool) ("removed for " ^ inp) want_removed removed)
    cases

(* ---------- script level, block flags ---------- *)

(* Input 1, bare: Core removes the OP_0, S verifies against pk4, the 1-byte
   garbage sig then fails strict DER: the spend is invalid.  The DER reason
   (Core: "Non-canonical DER signature") shows S verified. *)
let der_err = "invalid:Non-strict DER signature"
let test_input1_bare_invalid () =
  let tx = spend_tx () in
  let s = sign_legacy 4 tx core_code1 in
  let tx = with_sig tx (sig1_script s) in
  Alcotest.(check string) "block flags" der_err
    (verdict ~flags:block_flags ~spk:spk1 tx)

(* Same, P2SH-wrapped: the redeem script is the scriptCode. *)
let test_input1_p2sh_invalid () =
  let redeem = spk1 in
  let spk = p2sh redeem in
  let tx = spend_tx () in
  let s = sign_legacy 4 tx core_code1 in
  let tx = with_sig tx (Cstruct.concat [sig1_script s; push redeem]) in
  Alcotest.(check string) "block flags" der_err (verdict ~flags:block_flags ~spk tx)

(* The mirror of input 1: S signed over the scriptCode WITH the OP_0.  Core
   removes the OP_0, S fails against pk4 and pk3, too few keys remain, the
   garbage sig is never checked: CHECKMULTISIG false, NOT true, valid. *)
let test_input1_mirror_valid () =
  let tx = spend_tx () in
  let s = sign_legacy 4 tx spk1 in
  let tx = with_sig tx (sig1_script s) in
  check_valid "block flags" (verdict ~flags:block_flags ~spk:spk1 tx)

(* Input 2 for a 77- and a 78-byte G (wrong pattern on master) and a 76-byte
   G (already right on master: control).  Core deletes G from the scriptCode,
   S (signed over a scriptCode that still holds G) fails, valid. *)
let test_input2 n () =
  let g = filled n 0xab in
  let spk = spk2 g in
  let tx = spend_tx () in
  let s = sign_legacy 2 tx spk in
  let tx = with_sig tx (sig2_script g s) in
  check_valid "block flags" (verdict ~flags:block_flags ~spk tx)

(* Guard: a 0x00 inside a push is not an OP_0.  Input 1 with 02 00 00 in
   place of the leading OP_0: Core deletes nothing, S signed over the whole
   script verifies, the garbage sig fails DER: invalid. *)
let test_inner_zero_not_deleted () =
  let spk = Cstruct.concat [bytes_of [0x02; 0x00; 0x00; op_drop]; ms_body] in
  let tx = spend_tx () in
  let s = sign_legacy 4 tx spk in
  let tx = with_sig tx (sig1_script s) in
  Alcotest.(check string) "block flags" der_err (verdict ~flags:block_flags ~spk tx)

(* Guard: witness v0 has no FindAndDelete.  Input 1's script as a P2WSH
   witness script: S signed over the unmodified witness script verifies
   against pk4, the garbage sig fails DER: invalid. *)
let test_witness_v0_untouched () =
  let ws = spk1 in
  let spk = Cstruct.concat [bytes_of [0x00; 0x20]; Crypto.sha256 ws] in
  let amount = 100_000L in
  let tx = spend_tx () in
  let s = sign_segwit 4 tx ws amount in
  let witness = [Cstruct.empty; Cstruct.empty; byte 0x01; s; ws] in
  Alcotest.(check string) "block flags" der_err
    (verdict ~witness ~amount ~flags:block_flags ~spk tx)

(* ---------- CONST_SCRIPTCODE (policy) ---------- *)

let const_err = "invalid:CONST_SCRIPTCODE: find_and_delete modified scriptCode"

(* 00 75 51 <pk1> 51 ae 91 with scriptSig 00 00: the empty sig's OP_0 is in
   the scriptCode, so Core fails SIG_FINDANDDELETE under CONST_SCRIPTCODE. *)
let const_cms_script = Cstruct.concat [bytes_of [op_0; op_drop; op_1]; push pk1;
                                       bytes_of [op_1; op_checkmultisig; op_not]]
let const_cs_script = Cstruct.concat [bytes_of [op_0; op_drop]; push pk1;
                                      bytes_of [op_checksig; op_not]]

let test_const_checkmultisig_empty () =
  let spk = const_cms_script in
  let tx = with_sig (spend_tx ()) (bytes_of [op_0; op_0]) in
  Alcotest.(check string) "const_scriptcode" const_err
    (verdict ~flags:const_flags ~spk tx);
  check_valid "block flags" (verdict ~flags:block_flags ~spk tx)

let test_const_checksig_empty () =
  let spk = const_cs_script in
  let tx = with_sig (spend_tx ()) (byte op_0) in
  Alcotest.(check string) "const_scriptcode" const_err
    (verdict ~flags:const_flags ~spk tx);
  check_valid "block flags" (verdict ~flags:block_flags ~spk tx)

(* CHECKSIGVERIFY with an empty sig fails either way; Core's reason under
   CONST_SCRIPTCODE is SIG_FINDANDDELETE, raised before the signature check. *)
let test_const_checksigverify_empty () =
  let spk = Cstruct.concat [bytes_of [op_0; op_drop]; push pk1;
                            bytes_of [op_checksigverify; op_1]] in
  let tx = with_sig (spend_tx ()) (byte op_0) in
  Alcotest.(check string) "const_scriptcode" const_err
    (verdict ~flags:const_flags ~spk tx)

(* Control: no OP_0 in the scriptCode, so an empty sig deletes nothing and
   CONST_SCRIPTCODE does not fire. *)
let test_const_no_op0_control () =
  let spk = Cstruct.concat [bytes_of [op_1; op_drop]; push pk1;
                            bytes_of [op_checksig; op_not]] in
  let tx = with_sig (spend_tx ()) (byte op_0) in
  check_valid "const_scriptcode" (verdict ~flags:const_flags ~spk tx);
  let spk = Cstruct.concat [bytes_of [op_1]; push pk1;
                            bytes_of [op_1; op_checkmultisig; op_not]] in
  let tx = with_sig (spend_tx ()) (bytes_of [op_0; op_0]) in
  check_valid "const_scriptcode cms" (verdict ~flags:const_flags ~spk tx)

(* ---------- regtest blocks behind the real submitblock handler ---------- *)

let remine (block : Types.block) : Types.block =
  let h = ref block.Types.header in
  let n = ref 0l in
  let found = ref false in
  while (not !found) && Int32.compare !n 5_000_000l < 0 do
    h := { !h with Types.nonce = !n };
    if Consensus.hash_meets_target (Crypto.compute_block_hash !h) !h.Types.bits
    then found := true
    else n := Int32.add !n 1l
  done;
  if not !found then failwith "remine: no nonce found";
  { block with Types.header = !h }

let make_block ~(prev : Types.block option) ~height ~tag ~payout
    ?(txs = []) () : Types.block =
  let prev_hash, prev_time = match prev with
    | None -> Consensus.regtest.Consensus.genesis_hash,
              Consensus.regtest.Consensus.genesis_header.Types.timestamp
    | Some p -> Crypto.compute_block_hash p.Types.header,
                p.Types.header.Types.timestamp in
  let extra_nonce = Cstruct.create 8 in
  Cstruct.LE.set_uint64 extra_nonce 0 (Int64.of_int (height + (tag lsl 32)));
  let mk wr =
    Mining.create_coinbase ~height ~total_fee:0L ~payout_script:payout
      ~extra_nonce ~witness_root:wr ~network_type:Consensus.Regtest ()
  in
  let wr = Mining.compute_witness_merkle_root (mk None :: txs) in
  let coinbase = mk (Some wr) in
  let all = coinbase :: txs in
  let merkle_root, _ = Crypto.merkle_root (List.map Crypto.compute_txid all) in
  remine { Types.header = { version = 4l; prev_block = prev_hash; merkle_root;
                            timestamp = Int32.add prev_time 600l;
                            bits = Consensus.regtest.pow_limit; nonce = 0l };
           transactions = all }

let block_hex (b : Types.block) =
  let w = Serialize.writer_create () in
  Serialize.serialize_block w b;
  to_hex (Serialize.writer_to_cstruct w)

let with_node label f =
  Test_tmp.with_dir ~label ~mkdir:true (fun path ->
    let db = Storage.ChainDB.create path in
    Fun.protect ~finally:(fun () -> try Storage.ChainDB.close db with _ -> ())
      (fun () ->
        let chain = Sync.create_chain_state db Consensus.regtest in
        chain.Sync.sync_state <- Sync.FullySynced;
        let utxo = Utxo.OptimizedUtxoSet.create ~cache_size:10_000 db in
        Sync.shared_utxo_set := Some utxo;
        let mempool = Mempool.create ~network:Consensus.regtest
            ~require_standard:false ~verify_scripts:false
            ~utxo:(Utxo.UtxoSet.create db) ~current_height:0 () in
        let ctx : Rpc.rpc_context = {
          chain; mempool;
          peer_manager = Peer_manager.create Consensus.regtest;
          wallet = None; wallet_manager = None;
          fee_estimator = Fee_estimation.create ();
          network = Consensus.regtest;
          filter_index = None; utxo = Some utxo; data_dir = None;
          snapshot_activation = None;
        } in
        Fun.protect ~finally:(fun () -> Sync.shared_utxo_set := None)
          (fun () -> f ctx)))

let submit ctx b =
  match Rpc.handle_submitblock ctx [`String (block_hex b)] with
  | Ok `Null -> "null"
  | Ok (`String s) -> s
  | Ok j -> "unexpected:" ^ Yojson.Safe.to_string j
  | Error e -> "rpc-error:" ^ e

let tip_height (ctx : Rpc.rpc_context) =
  match Sync.block_tip ctx.chain with
  | Some (e : Sync.header_entry) -> e.height
  | None -> -1

let tx_hex (tx : Types.transaction) =
  let w = Serialize.writer_create () in
  Serialize.serialize_transaction w tx;
  to_hex (Serialize.writer_to_cstruct w)

(* <name>.hex: the chain, one block per line, the spending block last.
   <name>.tx (with [~mempool]): the spending tx alone, for Core's
   testmempoolaccept at height 101 (standard flags, CONST_SCRIPTCODE on). *)
let dump ?tx name blocks =
  match Sys.getenv_opt "FAD_DUMP_DIR" with
  | None -> ()
  | Some dir ->
    let oc = open_out (Filename.concat dir (name ^ ".hex")) in
    List.iter (fun b -> output_string oc (block_hex b ^ "\n")) blocks;
    close_out oc;
    Option.iter (fun t ->
      let oc = open_out (Filename.concat dir (name ^ ".tx")) in
      output_string oc (tx_hex t ^ "\n");
      close_out oc) tx

(* Mine a block at height 1 whose coinbase pays [spk], 100 more to mature
   it, then a block at 102 spending it with [script_sig s] where s is made
   by [sign tx].  Returns the submitblock answer for block 102 and the tip. *)
let run_block_case ?(mempool = false) ?(out = op_true) label ~spk ~sign
    ~script_sig =
  with_node label (fun ctx ->
    let b1 = make_block ~prev:None ~height:1 ~tag:1 ~payout:spk () in
    let chain = ref [b1] and prev = ref b1 in
    for h = 2 to 101 do
      let b = make_block ~prev:(Some !prev) ~height:h ~tag:1 ~payout:op_true () in
      chain := b :: !chain; prev := b
    done;
    let blocks = List.rev !chain in
    List.iteri (fun i b ->
      let r = submit ctx b in
      if r <> "null" then Alcotest.failf "setup block %d: %s" (i + 1) r) blocks;
    let cb = List.hd b1.Types.transactions in
    let value = Int64.sub (List.hd cb.Types.outputs).Types.value 10_000L in
    let tx = spend_tx ~prev:(Crypto.compute_txid cb) ~value ~out () in
    let tx = with_sig tx (script_sig (sign tx)) in
    let b102 = make_block ~prev:(Some !prev) ~height:102 ~tag:1
        ~payout:op_true ~txs:[tx] () in
    dump ?tx:(if mempool then Some tx else None) label (blocks @ [b102]);
    let r = submit ctx b102 in
    (r, tip_height ctx))

(* camlcoin's submitblock token for a script failure; Core's answer for
   these blocks is "block-script-verify-flag-failed (Non-canonical DER
   signature)" (replayed into bitcoind v31.1, see the PR). *)
let reject_token r =
  match String.index_opt r ' ' with Some i -> String.sub r 0 i | None -> r

let expect_rejected (r, tip) =
  Alcotest.(check string) "rejected like Core" "block-script-verify-flag-failed"
    (reject_token r);
  Alcotest.(check int) "tip stays at 101" 101 tip

let expect_accepted (r, tip) =
  Alcotest.(check string) "accepted like Core" "null" r;
  Alcotest.(check int) "tip moves to 102" 102 tip

let test_block_input1_rejected () =
  expect_rejected (run_block_case "fad_block_input1" ~spk:spk1
    ~sign:(fun tx -> sign_legacy 4 tx core_code1) ~script_sig:sig1_script)

let test_block_input1_p2sh_rejected () =
  expect_rejected (run_block_case "fad_block_input1_p2sh" ~spk:(p2sh spk1)
    ~sign:(fun tx -> sign_legacy 4 tx core_code1)
    ~script_sig:(fun s -> Cstruct.concat [sig1_script s; push spk1]))

let test_block_mirror_accepted () =
  expect_accepted (run_block_case "fad_block_mirror" ~spk:spk1
    ~sign:(fun tx -> sign_legacy 4 tx spk1) ~script_sig:sig1_script)

let test_block_input2 n label () =
  let g = filled n 0xab in
  let spk = spk2 g in
  expect_accepted (run_block_case label ~spk
    ~sign:(fun tx -> sign_legacy 2 tx spk) ~script_sig:(sig2_script g))

(* CONST_SCRIPTCODE is policy: the block is valid under block flags (Core
   accepts it); the dumped tx is what Core's testmempoolaccept rejects with
   "Signature is found in scriptCode". *)
let test_block_const redeem script_sig label () =
  expect_accepted (run_block_case ~mempool:true ~out:p2wsh_true label
    ~spk:(p2sh redeem) ~sign:(fun _ -> Cstruct.empty)
    ~script_sig:(fun _ -> Cstruct.concat [script_sig; push redeem]))

(* Negative control: the garbage sig on top is checked first against pk4 and
   fails strict DER, on master and on the fix.  Proves the block path runs
   the scripts at all. *)
let test_block_control_garbage_top_rejected () =
  expect_rejected (run_block_case "fad_block_control" ~spk:spk1
    ~sign:(fun tx -> sign_legacy 4 tx core_code1)
    ~script_sig:(fun s -> Cstruct.concat [bytes_of [op_0; op_0]; push s;
                                          bytes_of [0x01; 0x01]]))

let () =
  Alcotest.run "multisig_findanddelete_empty_sig" [
    "find_and_delete", List.map (fun n ->
        Alcotest.test_case (Printf.sprintf "core pattern for a %d-byte sig" n)
          `Quick (test_fad_size n))
        [0; 1; 75; 76; 77; 78; 255; 256; 520]
      @ [Alcotest.test_case "empty sig deletes only opcode-aligned OP_0"
           `Quick test_fad_empty_alignment];
    "block_flags", [
      Alcotest.test_case "input 1 bare: empty sig deletes OP_0, invalid" `Quick
        test_input1_bare_invalid;
      Alcotest.test_case "input 1 p2sh: empty sig deletes OP_0, invalid" `Quick
        test_input1_p2sh_invalid;
      Alcotest.test_case "input 1 mirror: S over undeleted code, valid" `Quick
        test_input1_mirror_valid;
      Alcotest.test_case "input 2 with a 77-byte sig: valid" `Quick (test_input2 77);
      Alcotest.test_case "input 2 with a 78-byte sig: valid" `Quick (test_input2 78);
      Alcotest.test_case "input 2 with a 76-byte sig: valid (control)" `Quick
        (test_input2 76);
      Alcotest.test_case "0x00 inside a push is not deleted" `Quick
        test_inner_zero_not_deleted;
      Alcotest.test_case "witness v0 scriptCode untouched" `Quick
        test_witness_v0_untouched;
    ];
    "const_scriptcode", [
      Alcotest.test_case "checkmultisig empty sig with OP_0 in scriptCode" `Quick
        test_const_checkmultisig_empty;
      Alcotest.test_case "checksig empty sig with OP_0 in scriptCode" `Quick
        test_const_checksig_empty;
      Alcotest.test_case "checksigverify empty sig with OP_0 in scriptCode" `Quick
        test_const_checksigverify_empty;
      Alcotest.test_case "no OP_0 in scriptCode: no error (control)" `Quick
        test_const_no_op0_control;
    ];
    "regtest_block", [
      Alcotest.test_case "input 1 block is rejected" `Quick
        test_block_input1_rejected;
      Alcotest.test_case "input 1 p2sh block is rejected" `Quick
        test_block_input1_p2sh_rejected;
      Alcotest.test_case "input 1 mirror block is accepted" `Quick
        test_block_mirror_accepted;
      Alcotest.test_case "input 2 block (77-byte sig) is accepted" `Quick
        (test_block_input2 77 "fad_block_input2");
      Alcotest.test_case "input 2 block (78-byte sig) is accepted" `Quick
        (test_block_input2 78 "fad_block_input2_78");
      Alcotest.test_case "const_scriptcode checkmultisig block is accepted" `Quick
        (test_block_const const_cms_script (bytes_of [op_0; op_0])
           "fad_block_const_cms");
      Alcotest.test_case "const_scriptcode checksig block is accepted" `Quick
        (test_block_const const_cs_script (byte op_0) "fad_block_const_cs");
      Alcotest.test_case "const_scriptcode control (no OP_0) block is accepted"
        `Quick
        (test_block_const
           (Cstruct.concat [bytes_of [op_1; op_drop]; push pk1;
                            bytes_of [op_checksig; op_not]])
           (byte op_0) "fad_block_const_ctrl");
      Alcotest.test_case "garbage sig on top is rejected (control)" `Quick
        test_block_control_garbage_top_rejected;
    ];
  ]
