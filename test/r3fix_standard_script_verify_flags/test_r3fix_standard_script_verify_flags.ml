(* r3fix-camlcoin-standard-script-verify-flags.

   Core v31.1 checks mempool scripts with STANDARD_SCRIPT_VERIFY_FLAGS
   (policy/policy.h:119-132): the mandatory set plus STRICTENC, MINIMALDATA,
   DISCOURAGE_UPGRADABLE_NOPS, CLEANSTACK, MINIMALIF, NULLFAIL, LOW_S,
   DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, WITNESS_PUBKEYTYPE,
   CONST_SCRIPTCODE, DISCOURAGE_UPGRADABLE_TAPROOT_VERSION,
   DISCOURAGE_OP_SUCCESS and DISCOURAGE_UPGRADABLE_PUBKEYTYPE.

   camlcoin's Consensus.get_standard_policy_flags added only CLEANSTACK,
   SIGPUSHONLY, NULLFAIL, LOW_S, MINIMALDATA and WITNESS_PUBKEYTYPE, so the
   mempool accepted upgrade-hook spends Core refuses and, for refused txs,
   ran on to a later error than Core's.  The R3 generating fuzzer (seed
   739943, night 1, Core v31.1) found 6 verdict rows and ~20 reason rows.
   The cases below are those rows' minimised txs; each is run through
   Mempool.test_accept_package (testmempoolaccept's path) and the refusal is
   mapped with Rpc.core_script_reject, the function testmempoolaccept uses,
   so the expected string is Core's reject-reason verbatim. *)

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

(* Every case spends one 100000-sat output (the generator's fund_value). *)
let prev_value = 100_000L

type case = { name : string; tx_hex : string; prev_spk : string; core : string }

(* The 6 night-1 verdict rows: Core refuses, camlcoin master allowed.  All
   are consensus-valid (see the "consensus" group). *)
let verdict_cases = [
    (* verdict/script-policy/DISCOURAGE_OP_SUCCESS|accept: tapscript script=[RESERVED] *)
    { name = "script-policy/DISCOURAGE_OP_SUCCESS|accept";
      tx_hex = "0200000000010129a3f0191147efbce0e1794e1f6e55423acedd94f8cef5807586faf6072908d91c00000000feffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc3326002015021c079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179800000000";
      prev_spk = "5120b24dd91099ea57f2f942a0177f1ab650eb5bec51083311ed9e1d115092ba81af"; (* night-1 funding output *)
      core = "mempool-script-verify-flag-failed (OP_SUCCESSx reserved for soft-fork upgrades)" };
    (* verdict/script-policy/DISCOURAGE_UPGRADABLE_NOPS|accept: p2sh script=[NOP10] sig=[1] *)
    { name = "script-policy/DISCOURAGE_UPGRADABLE_NOPS|accept";
      tx_hex = "0200000001bff9da767c68971b49257ff6ba4732e8d60fd8e00ccb1058eb02e3a721e7b77e01000000035101b9feffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc3326000000000";
      prev_spk = "a91415727299b05b45fdaf9ac9ecf7565cfe27c3e56787"; (* night-1 funding output *)
      core = "mempool-script-verify-flag-failed (NOPx reserved for soft-fork upgrades)" };
    (* verdict/script-policy/DISCOURAGE_UPGRADABLE_PUBKEYTYPE|accept: tapscript script=[3026020100022100fffdffffffffffffffffffffffffffffffff *)
    { name = "script-policy/DISCOURAGE_UPGRADABLE_PUBKEYTYPE|accept";
      tx_hex = "020000000001018d560687a8d21ea3deef11c27b07333df57d3256db62e40a61d7e69ab8284dba1300000000feffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260022c293026020100022100fffdffffffffffffffffffffffffffffffffffff24ffffff9cde2b3570df2000005dac21c079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179800000000";
      prev_spk = "5120dfbfac562d0f2f7189e38ff0ecf5b20733ec202efd15d6fd867c27f6388441e0"; (* night-1 funding output *)
      core = "mempool-script-verify-flag-failed (Public key version reserved for soft-fork upgrades)" };
    (* verdict/script-policy/DISCOURAGE_UPGRADABLE_TAPROOT_VERSION|accept: tapscript script=[<pk> CHECKSIG] wit=['<sig>'] leaf=0xfe ctl+=0 flip=F *)
    { name = "script-policy/DISCOURAGE_UPGRADABLE_TAPROOT_VERSION|accept";
      tx_hex = "020000000001018ab44612abec63ad6ea697c2c9dbead634824082524408e2f5421c6f6a00b7da1900000000feffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc332600340756a14a46a04c8287b17ca11d9343a34c01794c6bf811f4b0d1492c23d7830074e579ac621c0b988649e3899a6032c10389ee72c212709e938eba783e23e4600222079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac21fe79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179800000000";
      prev_spk = "5120abd0940eece3c5f55d31eb5a3292d24b88bdab7edeccd741c0a4f3519dfb9487"; (* night-1 funding output *)
      core = "mempool-script-verify-flag-failed (Taproot version reserved for soft-fork upgrades)" };
    (* verdict/script-policy/MINIMALIF|accept: p2sh-p2wsh script=[IF 1 ENDIF] wit=['02'] *)
    { name = "script-policy/MINIMALIF|accept";
      tx_hex = "020000000001018665dd6bf7ac656d707357110963b90f2aa8e13e430e4735a1dc35e3a11656e20e00000023220020c7eaf06d5ae01a58e376e126eb1e6fab2036076922b96b2711ffbec1e590665dfeffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc332600201020363516800000000";
      prev_spk = "a9149b27ee6d9010c21bf837b334d043be5d150e7ba787"; (* night-1 funding output *)
      core = "mempool-script-verify-flag-failed (OP_IF/NOTIF argument must be minimal)" };
    (* verdict/script-policy/SIG_HASHTYPE|accept: p2sh script=[<pk> CHECKSIG] sig=[<sig>] hashtype=0x04 *)
    { name = "script-policy/SIG_HASHTYPE|accept";
      tx_hex = "0200000001dfca1baf56cfe295e9c52eaa15a5b6ee7615a4dabf346c1eb2ca2d9916562a17200000006d483045022100a47c18f3f29744e13046fd1623511f73f86b17d4ca0a65288279459ea5b72a3f0220764ded0a7fc78b415cdab327e620f5a8df2a42e5cea028bc28936b9412f0bbba0423210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798acfeffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc3326000000000";
      prev_spk = "a91423b0ad3477f2178bc0b3eed26e4e6316f4e83aa187"; (* night-1 funding output *)
      core = "mempool-script-verify-flag-failed (Signature hash type missing or not understood)" };
]

(* Night-1 reason rows: both refuse, but without the flag camlcoin ran on to
   a later error.  The prevout is the P2SH / P2WSH output of the redeem or
   witness script the tx carries (rebuilt from the tx; on the three P2SH
   verdict rows above the same derivation equals the night-1 funding output). *)
let reason_cases = [
    (* reason/script-policy/OP_CODESEPARATOR|script-policy/CLEANSTACK: p2sh script=[CODESEPARATOR 31 00] *)
    { name = "script-policy/OP_CODESEPARATOR|script-policy/CLEANSTACK";
      tx_hex = "020000000176cdcba7e979431c98159e3b8fb49b109599b85a96e7ef4576c08859e2b8d7d6000000000605ab01310100feffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc3326000000000";
      prev_spk = "a91496fbab16c87db35e68548a25a366d3d0c0a0cca187"; (* derived from the redeem/witness script *)
      core = "mempool-script-verify-flag-failed (Using OP_CODESEPARATOR in non-witness script)" };
    (* reason/script-policy/SIG_FINDANDDELETE|script-policy/SIG_NULLFAIL: p2sh script=[302602210108ffffff030000fde8ff0000006f6f6f6f6f6f6f6fa75ba *)
    { name = "script-policy/SIG_FINDANDDELETE|script-policy/SIG_NULLFAIL";
      tx_hex = "02000000018941ff6870af9a24bb810fe9d780d23f73c623a1d46c8da216e1a6f60f54606a000000002d2c29302602210108ffffff030000fde8ff0000006f6f6f6f6f6f6f6fa75bafafafafa78c0007090201010076acfeffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc3326000000000";
      prev_spk = "a91494c1e2eff6f5ca91e04d07f6c18b4f47b0a21b7387"; (* derived from the redeem/witness script *)
      core = "mempool-script-verify-flag-failed (Signature is found in scriptCode)" };
    (* reason/script-policy/PUBKEYTYPE|script-policy/WITNESS_PUBKEYTYPE: p2wsh script=[0 0 CHECKSIG] *)
    { name = "script-policy/PUBKEYTYPE|script-policy/WITNESS_PUBKEYTYPE";
      tx_hex = "020000000001017ea40548e33f33ccb2255699d549762f317a06220f9ef32235c9cfba9d82bce30000000000feffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc3326001030000ac00000000";
      prev_spk = "002030408e8996679770f6b5ef8410f52c691ce22e9a1121d2d54dda6cc7577257a5"; (* derived from the redeem/witness script *)
      core = "mempool-script-verify-flag-failed (Public key is neither compressed or uncompressed)" };
    (* reason/script-policy/DISCOURAGE_UPGRADABLE_NOPS|script-policy/SIG_DER: p2sh script=[0 NOP9 HASH256 IFDUP CHECKSIG] *)
    { name = "script-policy/DISCOURAGE_UPGRADABLE_NOPS|script-policy/SIG_DER";
      tx_hex = "0200000001b018b7e2cd4755bf10ddf36149c35fbafec8a5e7d1bf06ef322314abf1df745000000000060500b8aa73acfeffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc3326000000000";
      prev_spk = "a9146e0f7048aa6c211061f6f26651cda308aa2a52de87"; (* derived from the redeem/witness script *)
      core = "mempool-script-verify-flag-failed (NOPx reserved for soft-fork upgrades)" };
    (* reason/script-policy/MINIMALIF|script-policy/CLEANSTACK: p2wsh script=[IF ENDIF] wit=['00'] *)
    { name = "script-policy/MINIMALIF|script-policy/CLEANSTACK";
      tx_hex = "02000000000101d52c3c96b042bcde10e71e06772d6b1a1bb62353b89383622c4db1920983de4e0000000000feffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc3326002010002636800000000";
      prev_spk = "0020343677762813eaeb65704cc8d9e96f7a444ba0cca92ff861af7f68648b3e6ef1"; (* derived from the redeem/witness script *)
      core = "mempool-script-verify-flag-failed (OP_IF/NOTIF argument must be minimal)" };
    (* reason/script-policy/SIG_HASHTYPE|script-policy/WITNESS_PUBKEYTYPE: p2wsh script=[3029020106022459a49377409d23bb84a6240e0c0e0eacacacac7676 *)
    { name = "script-policy/SIG_HASHTYPE|script-policy/WITNESS_PUBKEYTYPE";
      tx_hex = "0200000000010112757b05114eca6408cd89a7507432e938aaf3f69a21e2342bc331666857da310000000000feffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260012f2c3029020106022459a49377409d23bb84a6240e0c0e0eacacacac7676766facacac86a678acacacacacac767676ac00000000";
      prev_spk = "00203cbf1fb87cbe4f229296eb4b27bc282aba47e9324380f289f2c47a8280dd8800"; (* derived from the redeem/witness script *)
      core = "mempool-script-verify-flag-failed (Signature hash type missing or not understood)" };
]

(* DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM has no night-1 row (AreInputsStandard
   refuses native v2+ prevouts first), but a P2SH-wrapped witness v1 program
   reaches it: inside P2SH a v1 32-byte program is not taproot
   (interpreter.cpp VerifyWitnessProgram, `!is_p2sh`), so Core refuses it
   with the upgradable-witness error.  redeemScript = OP_1 <32 x 0x01>. *)
let p2sh_v1_redeem = "5120" ^ String.concat "" (List.init 32 (fun _ -> "01"))

let hash160_hex (s : Cstruct.t) =
  let h = Crypto.hash160 s in
  String.concat "" (List.init (Cstruct.length h)
                      (fun i -> Printf.sprintf "%02x" (Cstruct.get_uint8 h i)))

let p2sh_spk_of_hex redeem = "a914" ^ hash160_hex (of_hex redeem) ^ "87"

let p2wsh_out = of_hex "00204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260"

let spend ~(script_sig : Cstruct.t) ~(witness : Cstruct.t list) : Types.transaction =
  { Types.version = 2l;
    inputs = [ { Types.previous_output =
                   { Types.txid = Cstruct.of_string (String.make 32 '\x5a'); vout = 0l };
                 script_sig; sequence = 0xFFFFFFFEl } ];
    outputs = [ { Types.value = 98_000L; script_pubkey = p2wsh_out } ];
    witnesses = [ { Types.items = witness } ];
    locktime = 0l }

let push_hex h =
  let n = String.length h / 2 in
  assert (n <= 75);
  Printf.sprintf "%02x" n ^ h

let p2sh_v1_tx () =
  spend ~script_sig:(of_hex (push_hex p2sh_v1_redeem)) ~witness:[]

let with_mempool (op : Types.outpoint) (spk : Cstruct.t) f =
  Test_tmp.with_chaindb (fun db ->
      let utxo = Utxo.UtxoSet.create db in
      Utxo.UtxoSet.add utxo op.txid (Int32.to_int op.vout)
        Utxo.{ value = prev_value; script_pubkey = spk; height = 1;
               is_coinbase = false };
      let mp = Mempool.create ~network:Consensus.regtest ~require_standard:true
          ~verify_scripts:true ~utxo ~current_height:200 () in
      f mp)

(* testmempoolaccept's answer for [tx]: None if allowed, else Core's
   reject-reason as camlcoin's RPC reports it. *)
let test_accept (tx : Types.transaction) (spk : Cstruct.t) : string option =
  let op = (List.hd tx.Types.inputs).Types.previous_output in
  with_mempool op spk (fun mp ->
      match Mempool.test_accept_package mp [ tx ] with
      | Error e -> Some ("package error: " ^ e)
      | Ok [ Mempool.TestAccepted _ ] -> None
      | Ok [ Mempool.TestRejected msg ] ->
        (match Rpc.core_script_reject tx msg with
         | Some (reason, _) -> Some reason
         | None -> Some msg)
      | Ok _ -> Some "unexpected outcome shape")

let check_core_reason (name : string) (tx : Types.transaction) (spk : Cstruct.t)
    (core : string) =
  match test_accept tx spk with
  | None -> Alcotest.fail (name ^ ": allowed; Core v31.1 refuses: " ^ core)
  | Some got -> Alcotest.(check string) (name ^ ": Core's reject-reason") core got

let case_test (c : case) () =
  check_core_reason c.name (decode_tx c.tx_hex) (of_hex c.prev_spk) c.core

(* --- The flag set ---------------------------------------------------------- *)

(* Next block on a regtest mempool at height 200. *)
let policy_flags () = Consensus.get_standard_policy_flags 201 Consensus.regtest
let block_flags () = Consensus.get_block_script_flags 201 Consensus.regtest

(* The interpreter's bits (Script), so a Consensus/Script bit mismatch fails. *)
let missing_on_master = [
  "STRICTENC", Script.script_verify_strictenc;
  "DISCOURAGE_UPGRADABLE_NOPS", Script.script_verify_discourage_upgradable_nops;
  "MINIMALIF", Script.script_verify_minimalif;
  "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM", Script.script_verify_discourage_upgradable_witness;
  "CONST_SCRIPTCODE", Script.script_verify_const_scriptcode;
  "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION",
  Script.script_verify_discourage_upgradable_taproot_version;
  "DISCOURAGE_OP_SUCCESS", Script.script_verify_discourage_op_success;
  "DISCOURAGE_UPGRADABLE_PUBKEYTYPE", Script.script_verify_discourage_upgradable_pubkeytype;
]

let already_set = [
  "MINIMALDATA", Script.script_verify_minimaldata;
  "CLEANSTACK", Script.script_verify_cleanstack;
  "NULLFAIL", Script.script_verify_nullfail;
  "LOW_S", Script.script_verify_low_s;
  "WITNESS_PUBKEYTYPE", Script.script_verify_witness_pubkeytype;
]

let flag_test (name, bit) () =
  Alcotest.(check bool) ("standard flags include " ^ name) true
    (policy_flags () land bit <> 0)

let test_already_set () =
  List.iter (fun f -> flag_test f ()) already_set

let test_block_flags_have_no_standard_only_flag () =
  (* Core's 13 STANDARD_NOT_MANDATORY flags must never reach block validation. *)
  List.iter (fun (name, bit) ->
      Alcotest.(check bool) ("block flags exclude " ^ name) true
        (block_flags () land bit = 0))
    (missing_on_master @ already_set)

(* --- Consensus: the verdict-row txs stay valid in blocks ------------------- *)

let verify_with_flags (tx : Types.transaction) (spk : Cstruct.t) (flags : int) =
  let inp = List.hd tx.Types.inputs in
  let witness =
    match tx.Types.witnesses with w :: _ -> w | [] -> { Types.items = [] } in
  let prevouts = [ (prev_value, spk) ] in
  Script.verify_script ~tx ~input_index:0 ~script_pubkey:spk
    ~script_sig:inp.Types.script_sig ~witness ~amount:prev_value ~flags
    ~prevouts ~txdata:(Script.make_txdata ~prevouts tx) ()

let test_verdict_txs_consensus_valid () =
  let all =
    List.map (fun c -> (c.name, decode_tx c.tx_hex, of_hex c.prev_spk)) verdict_cases
    @ [ ("P2SH-wrapped witness v1", p2sh_v1_tx (), of_hex (p2sh_spk_of_hex p2sh_v1_redeem)) ] in
  List.iter (fun (name, tx, spk) ->
      let show = function Ok true -> "valid" | Ok false -> "false"
                        | Error e -> "error: " ^ e in
      Alcotest.(check string) (name ^ ": valid under block flags") "valid"
        (show (verify_with_flags tx spk (block_flags ()))))
    all

(* --- CHECKSIG: signature encoding is checked before the key ----------------- *)

(* Core EvalChecksigPreTapscript runs CheckSignatureEncoding and then
   CheckPubKeyEncoding.  camlcoin checked the key first; with STRICTENC now
   in the mempool flags that showed up as a pubkey error where Core reports
   the signature's (the SIG_HASHTYPE|WITNESS_PUBKEYTYPE reason row above).
   P2WSH witnessScript <65-byte uncompressed key> CHECKSIG[VERIFY] 1: the key
   fails WITNESS_PUBKEYTYPE, the signature is checked first. *)
let uncompressed_pk =
  "04" ^ "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
  ^ "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"

let p2wsh_checksig_result ~(verify : bool) ~(sig_hex : string) ~(flags : int) =
  let ws = of_hex (push_hex uncompressed_pk ^ (if verify then "ad51" else "ac")) in
  let spk = Cstruct.append (of_hex "0020") (Crypto.sha256 ws) in
  let tx = spend ~script_sig:Cstruct.empty ~witness:[ of_hex sig_hex; ws ] in
  match verify_with_flags tx spk flags with
  | Ok b -> "Ok " ^ string_of_bool b
  | Error e -> "Error " ^ e

(* Not DER at all; hash type 0x01. *)
let non_der_sig = "0102030401"
(* Valid low-S DER (r = s = 1), undefined hash type 0x04. *)
let hashtype4_sig = "300602010102010104"
(* Valid low-S DER (r = s = 1), SIGHASH_ALL; it does not verify. *)
let wrong_sig = "300602010102010101"

let order_case ~verify ~sig_hex ~want () =
  Alcotest.(check string)
    ((if verify then "CHECKSIGVERIFY" else "CHECKSIG") ^ ", bad sig + uncompressed key")
    want (p2wsh_checksig_result ~verify ~sig_hex ~flags:(policy_flags ()))

let test_order_consensus_unchanged () =
  (* Block flags have no STRICTENC / WITNESS_PUBKEYTYPE, so the key passes
     and a well-formed wrong signature is plain false, as before. *)
  Alcotest.(check string) "CHECKSIG under block flags" "Ok false"
    (p2wsh_checksig_result ~verify:false ~sig_hex:wrong_sig ~flags:(block_flags ()));
  Alcotest.(check string) "CHECKSIG non-DER under block flags (DERSIG)"
    "Error Non-strict DER signature"
    (p2wsh_checksig_result ~verify:false ~sig_hex:non_der_sig ~flags:(block_flags ()));
  (* Under policy flags a GOOD-encoding signature still reaches the key. *)
  Alcotest.(check string) "CHECKSIG well-formed sig + uncompressed key (policy)"
    "Error Witness requires compressed pubkey"
    (p2wsh_checksig_result ~verify:false ~sig_hex:wrong_sig ~flags:(policy_flags ()))

(* --- Controls: standard spends are still allowed --------------------------- *)

let test_control_p2sh_true () =
  let tx = spend ~script_sig:(of_hex (push_hex "51")) ~witness:[] in
  Alcotest.(check (option string)) "P2SH(OP_TRUE) spend allowed" None
    (test_accept tx (of_hex (p2sh_spk_of_hex "51")))

let test_control_p2wsh_true () =
  let tx = spend ~script_sig:Cstruct.empty ~witness:[ of_hex "51" ] in
  Alcotest.(check (option string)) "P2WSH(OP_TRUE) spend allowed" None
    (test_accept tx (Cstruct.append (of_hex "0020") (Crypto.sha256 (of_hex "51"))))

let test_control_p2wsh_minimal_if () =
  (* IF 1 ENDIF with a minimal 0x01 argument: MINIMALIF passes. *)
  let ws = of_hex "635168" in
  let tx = spend ~script_sig:Cstruct.empty ~witness:[ of_hex "01"; ws ] in
  Alcotest.(check (option string)) "P2WSH IF with minimal true argument allowed" None
    (test_accept tx (Cstruct.append (of_hex "0020") (Crypto.sha256 ws)))

let test_control_p2a_native () =
  (* Pay-to-Anchor (OP_1 <4e73>) is the one witness v1 program Core does not
     discourage: VerifyWitnessProgram returns true for it when !is_p2sh. *)
  let tx = spend ~script_sig:Cstruct.empty ~witness:[] in
  Alcotest.(check (option string)) "native P2A spend allowed" None
    (test_accept tx (of_hex "51024e73"))

let test_p2a_in_p2sh_refused () =
  (* Inside P2SH the same program is not an anchor (is_p2sh), so the
     upgradable-witness-program error applies. *)
  let redeem = "51024e73" in
  let tx = spend ~script_sig:(of_hex (push_hex redeem)) ~witness:[] in
  check_core_reason "P2SH-wrapped P2A" tx (of_hex (p2sh_spk_of_hex redeem))
    "mempool-script-verify-flag-failed (Witness version reserved for soft-fork upgrades)"

let () =
  let tc name f = Alcotest.test_case name `Quick f in
  Alcotest.run "r3fix_standard_script_verify_flags"
    [ ( "flags",
        List.map (fun ((n, _) as f) -> tc ("standard flags include " ^ n) (flag_test f))
          missing_on_master );
      ( "verdict-rows",
        List.map (fun c -> tc c.name (case_test c)) verdict_cases
        @ [ tc "P2SH-wrapped witness v1 -> DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM"
              (fun () ->
                 check_core_reason "P2SH-wrapped witness v1" (p2sh_v1_tx ())
                   (of_hex (p2sh_spk_of_hex p2sh_v1_redeem))
                   "mempool-script-verify-flag-failed (Witness version reserved for soft-fork upgrades)") ] );
      ( "reason-rows", List.map (fun c -> tc c.name (case_test c)) reason_cases );
      ( "consensus",
        [ tc "block flags carry no standard-only flag" test_block_flags_have_no_standard_only_flag;
          tc "verdict-row txs valid under block flags" test_verdict_txs_consensus_valid ] );
      ( "checksig-order",
        [ tc "CHECKSIG non-DER sig before key" (order_case ~verify:false ~sig_hex:non_der_sig
                                                 ~want:"Error Non-strict DER signature");
          tc "CHECKSIG hashtype 0x04 before key" (order_case ~verify:false ~sig_hex:hashtype4_sig
                                                    ~want:"Error Invalid hash type");
          tc "CHECKSIGVERIFY non-DER sig before key" (order_case ~verify:true ~sig_hex:non_der_sig
                                                       ~want:"Error Non-strict DER signature");
          tc "CHECKSIGVERIFY hashtype 0x04 before key" (order_case ~verify:true ~sig_hex:hashtype4_sig
                                                          ~want:"Error Invalid hash type");
          tc "consensus result unchanged" test_order_consensus_unchanged ] );
      ( "controls",
        [ tc "already-set standard flags still set" test_already_set;
          tc "P2SH(OP_TRUE) allowed" test_control_p2sh_true;
          tc "P2WSH(OP_TRUE) allowed" test_control_p2wsh_true;
          tc "P2WSH minimal IF allowed" test_control_p2wsh_minimal_if;
          tc "native P2A allowed" test_control_p2a_native;
          tc "P2SH-wrapped P2A refused" test_p2a_in_p2sh_refused ] ) ]
