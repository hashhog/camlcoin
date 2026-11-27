(* r3fix-camlcoin-p2pk-multisig-input-standard (R3 gen-fuzz night 1, seed
   739943, rows R18/R25/R30/R42/R67/R86).

   Core v31.1 AreInputsStandard (src/policy/policy.cpp:213-249) refuses an
   input only when Solver says NONSTANDARD or WITNESS_UNKNOWN (:228).  Solver
   (src/script/solver.cpp:189-207) returns PUBKEY for a bare P2PK
   (MatchPayToPubkey, :36-47: 0x21 <33> 0xac / 0x41 <65> 0xac whose key passes
   CPubKey::ValidSize, header 02/03 for 33 bytes, 04/06/07 for 65) and
   MULTISIG for a bare multisig (MatchMultisig, :85-105: 1..20 keys, the n <= 3
   limit is IsStandard's OUTPUT rule only).  Both are standard inputs, so the
   spend goes on to the script checks.

   camlcoin's validate_inputs_standardness had neither template and refused
   every such spend "bad-txns-nonstandard-inputs: input 0 script unknown",
   which is R86 (Core accepts a correctly signed P2PK spend) and, for the
   other rows, masked Core's script-policy error.

   The minimised R86 case and a Core-accepted 2-of-2 bare-multisig spend from
   the same night-1 stream are replayed through add_transaction with
   require_standard and script verification on.  Controls pin that a P2PK /
   multisig shape Core calls NONSTANDARD still fails the gate ("script
   unknown"), that WITNESS_UNKNOWN keeps its own reason, and that a bad
   signature on a now-standard P2PK spend is still refused (by the script
   check, not the standardness gate).

   Output side (same rule, the item's side note): is_standard_output used a
   length-only P2PK check, so 0x21 05<32B> 0xac was over-accepted; Core says
   NONSTANDARD -> "scriptpubkey". *)

open Camlcoin

let hex s =
  let n = String.length s / 2 in
  let c = Cstruct.create n in
  for i = 0 to n - 1 do
    Cstruct.set_uint8 c i (int_of_string ("0x" ^ String.sub s (2 * i) 2))
  done;
  c

let parse_tx h =
  Serialize.deserialize_transaction (Serialize.reader_of_cstruct (hex h))

(* The generator's fixed key (privkey 1), tools/diff-fuzz difffuzz/gen/secp.py. *)
let pk = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
let p2pk_spk = hex ("21" ^ pk ^ "ac")
let ms22_spk = hex ("52" ^ "21" ^ pk ^ "21" ^ pk ^ "52" ^ "ae")

(* R86 minimised case: bare P2PK spend, valid low-S DER sig; Core allowed. *)
let r86_tx_hex =
  "0200000001ab4e3eb8d567edd177f8de9d31f58603905941f677786fed05ebf19fb85489e3\
   100000004948304502210083aac615948edd574f3f3941722383caa840fbdf80ee9624eef4\
   6201cd6cfe38022061c1e77da52e737d500126d22fe18e1284e5e964fc270b91acaa0a0501\
   bdb5b501feffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a00094543\
   2e83e1551e6f721ee9c00b8cc3326000000000"

(* Same stream, origin tmpl:bare:multisig: 2-of-2 bare multisig; Core allowed. *)
let ms22_tx_hex =
  "0200000001ab4e3eb8d567edd177f8de9d31f58603905941f677786fed05ebf19fb85489e3\
   1100000091004730440220663183b03479d1ef1d29e4f9015f9590890d5bf2bb7f42c5b221\
   c0907e9ca60d022070cd9c37c701cada15a5b8303eb22d718cb16d20905efb5d94700bd1d9\
   92e147014730440220663183b03479d1ef1d29e4f9015f9590890d5bf2bb7f42c5b221c090\
   7e9ca60d022070cd9c37c701cada15a5b8303eb22d718cb16d20905efb5d94700bd1d992e1\
   4701feffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83\
   e1551e6f721ee9c00b8cc3326000000000"

let fund_value = 100_000L

let contains ~sub s =
  let n = String.length sub and m = String.length s in
  let rec go i = i + n <= m && (String.sub s i n = sub || go (i + 1)) in
  go 0

let show = function Ok () -> "Ok" | Error e -> "Error: " ^ e

(* validate_inputs_standardness on a one-input spend of [spk]. *)
let gate spk =
  let tx = parse_tx r86_tx_hex in
  Mempool.validate_inputs_standardness ~lookup:(fun _ -> Some spk) tx

let check_standard name spk =
  Alcotest.(check string) name "Ok" (show (gate spk))

let check_unknown name spk =
  let r = show (gate spk) in
  Alcotest.(check bool) (name ^ " -> script unknown (" ^ r ^ ")") true
    (contains ~sub:"bad-txns-nonstandard-inputs: input 0 script unknown" r)

(* --- helpers to build scripts --------------------------------------------- *)

let key33 h = hex (h ^ String.make 64 '1')          (* header + 32 bytes *)
let key65 h = hex (h ^ String.make 128 '2')         (* header + 64 bytes *)
let push (d : Cstruct.t) =
  let n = Cstruct.length d in
  assert (n < 0x4c);
  Cstruct.append (hex (Printf.sprintf "%02x" n)) d
let cat = Cstruct.concat
let ms ?(m_op = "51") ?(n_op = "51") keys =
  cat ([ hex m_op ] @ List.map push keys @ [ hex n_op; hex "ae" ])
let k1 = key33 "02" and k2 = key33 "03" and k3 = key65 "04"

(* --- R86 / multisig end to end through add_transaction -------------------- *)

let add_prevout utxo (tx : Types.transaction) spk =
  let op = (List.hd tx.inputs).previous_output in
  Utxo.UtxoSet.add utxo op.txid (Int32.to_int op.vout)
    Utxo.{ value = fund_value; script_pubkey = spk; height = 100;
           is_coinbase = false }

let accept_case name tx_hex spk () =
  let tx = parse_tx tx_hex in
  Test_tmp.with_dir ~label:"r3fix_p2pk_ms" (fun db_path ->
    let db = Storage.ChainDB.create db_path in
    Fun.protect ~finally:(fun () -> try Storage.ChainDB.close db with _ -> ())
    @@ fun () ->
    let utxo = Utxo.UtxoSet.create db in
    add_prevout utxo tx spk;
    let mp = Mempool.create ~network:Consensus.regtest ~require_standard:true
        ~verify_scripts:true ~utxo ~current_height:200 () in
    let r = match Mempool.add_transaction ~dry_run:true mp tx with
      | Ok _ -> "accept" | Error e -> "reject: " ^ e in
    Alcotest.(check string) (name ^ ": Core v31.1 allowed") "accept" r)

(* Control: the R86 spend with its signature's last S byte flipped is still
   refused (script check), and NOT by the standardness gate.  Nothing invalid
   became valid. *)
let test_bad_sig_still_rejected () =
  let good = hex r86_tx_hex in
  let bad = Cstruct.of_string (Cstruct.to_string good) in
  (* scriptSig = 49 48 <72-byte DER sig incl. hashtype>; byte 42+72-2 is the
     last S byte (offset: 4 ver + 1 cnt + 32 txid + 4 vout + 1 len + 1 push). *)
  let off = 4 + 1 + 32 + 4 + 1 + 1 + 72 - 2 in
  Cstruct.set_uint8 bad off (Cstruct.get_uint8 bad off lxor 0x01);
  let tx = Serialize.deserialize_transaction (Serialize.reader_of_cstruct bad) in
  Test_tmp.with_dir ~label:"r3fix_p2pk_ms" (fun db_path ->
    let db = Storage.ChainDB.create db_path in
    Fun.protect ~finally:(fun () -> try Storage.ChainDB.close db with _ -> ())
    @@ fun () ->
    let utxo = Utxo.UtxoSet.create db in
    add_prevout utxo tx p2pk_spk;
    let mp = Mempool.create ~network:Consensus.regtest ~require_standard:true
        ~verify_scripts:true ~utxo ~current_height:200 () in
    match Mempool.add_transaction ~dry_run:true mp tx with
    | Ok _ -> Alcotest.fail "bad-signature P2PK spend accepted"
    | Error e ->
      Alcotest.(check bool) ("refused by the script check, not 'script unknown' ("
                             ^ e ^ ")") false (contains ~sub:"script unknown" e))

(* --- the standardness gate itself ----------------------------------------- *)

let test_p2pk_inputs_standard () =
  check_standard "P2PK 33-byte 0x02 key (R86 prevout)" p2pk_spk;
  check_standard "P2PK 33-byte 0x03 key" (cat [ push (key33 "03"); hex "ac" ]);
  check_standard "P2PK 65-byte 0x04 key" (cat [ push (key65 "04"); hex "ac" ]);
  (* R42: 0x06-prefixed 65-byte key — ValidSize true, so PUBKEY; Core then
     fails it in the script check with PUBKEYTYPE. *)
  check_standard "P2PK 65-byte 0x06 key (R42)" (cat [ push (key65 "06"); hex "ac" ]);
  check_standard "P2PK 65-byte 0x07 key" (cat [ push (key65 "07"); hex "ac" ])

let test_multisig_inputs_standard () =
  check_standard "1-of-1" (ms [ k1 ]);
  check_standard "2-of-2 (stream case prevout)" ms22_spk;
  check_standard "2-of-3 mixed 33/65" (ms ~m_op:"52" ~n_op:"53" [ k1; k2; k3 ]);
  (* n > 3 is nonstandard as an OUTPUT only; as an input Solver says MULTISIG. *)
  check_standard "1-of-4 (input side has no n <= 3 limit)"
    (ms ~n_op:"54" [ k1; k2; k1; k2 ]);
  (* 20 keys, n pushed as a minimal 1-byte CScriptNum 0x14 (GetScriptNumber). *)
  check_standard "1-of-20, n = push 0x14"
    (ms ~n_op:"0114" (List.init 20 (fun i -> if i mod 2 = 0 then k1 else k2)));
  (* Key pushed with OP_PUSHDATA1: MatchMultisig reads keys with GetOp. *)
  check_standard "1-of-1, key via OP_PUSHDATA1"
    (cat [ hex "51"; hex "4c21"; k1; hex "51"; hex "ae" ])

let test_nonstandard_shapes_still_refused () =
  check_unknown "OP_NOP OP_NOP" (hex "6161");
  check_unknown "P2PK 33-byte 0x05 header" (cat [ push (key33 "05"); hex "ac" ]);
  check_unknown "P2PK 33-byte 0x04 header (65-byte header in 33)"
    (cat [ push (key33 "04"); hex "ac" ]);
  check_unknown "P2PK 65-byte 0x02 header" (cat [ push (key65 "02"); hex "ac" ]);
  check_unknown "P2PK 65-byte 0x05 header" (cat [ push (key65 "05"); hex "ac" ]);
  check_unknown "P2PK, OP_CHECKSIGVERIFY" (cat [ push k1; hex "ad" ]);
  check_unknown "multisig n != #keys" (ms ~n_op:"51" [ k1; k2 ]);
  check_unknown "multisig m > n" (ms ~m_op:"52" ~n_op:"51" [ k1 ]);
  check_unknown "multisig m = OP_0" (ms ~m_op:"00" [ k1 ]);
  check_unknown "multisig m non-minimal push 0x01 0x01" (ms ~m_op:"0101" [ k1 ]);
  check_unknown "multisig 21 keys" (ms ~n_op:"0115" (List.init 21 (fun _ -> k1)));
  check_unknown "multisig key with bad header 0x05" (ms [ key33 "05" ]);
  check_unknown "multisig trailing byte after CHECKMULTISIG"
    (cat [ ms [ k1 ]; hex "ae" ]);
  check_unknown "multisig CHECKMULTISIGVERIFY" (cat [ hex "51"; push k1; hex "51af" ]);
  check_unknown "multisig with no keys (OP_1 OP_1 OP_CHECKMULTISIG)"
    (hex "5151ae");
  check_unknown "multisig truncated push" (hex "514c21ae")

let test_witness_unknown_keeps_reason () =
  let r = show (gate (hex ("5220" ^ String.make 64 'a'))) in
  Alcotest.(check bool) ("v2 witness program -> undefined (" ^ r ^ ")") true
    (contains ~sub:"witness program is undefined" r)

(* --- Core v31.1 Solver vectors -------------------------------------------- *)

(* core_solver_vectors.ml: 1158 hostile bare P2PK / multisig shapes (header
   bytes, key lengths, PUSHDATA1/2/4 keys, m/n as OP_n, minimal and
   non-minimal pushes, 0..21 keys, m > n, trailing bytes, CHECKSIGVERIFY /
   CHECKMULTISIGVERIFY) with the type Core v31.1's decodescript (Solver)
   gives each, recorded by gen_core_solver_vectors.py.  "pubkey" and
   "multisig" must pass the input gate, "nonstandard" must be "script
   unknown"; is_p2pk_script must say true exactly for "pubkey". *)
let rebuild (prefix, idx, suffix, _, _) =
  Cstruct.concat
    ([ hex prefix ]
     @ List.map (fun i -> push (hex Core_solver_vectors.keys.(i))) idx
     @ [ hex suffix ])

let to_hex c =
  String.concat "" (List.init (Cstruct.length c)
                      (fun i -> Printf.sprintf "%02x" (Cstruct.get_uint8 c i)))

let test_core_solver_vectors () =
  let bad = ref [] in
  List.iter (fun ((_, _, _, sha, ty) as v) ->
      let spk = rebuild v in
      if to_hex (Crypto.sha256 spk) <> sha then
        Alcotest.failf "rebuilt script %s does not hash to the recorded %s"
          (to_hex spk) sha;
      let gate_ok = gate spk = Ok () in
      let unknown =
        match gate spk with
        | Error e -> contains ~sub:"script unknown" e
        | Ok () -> false in
      let want_ok = ty = "pubkey" || ty = "multisig" in
      if want_ok <> gate_ok || (not want_ok && not unknown)
         || Mempool.is_p2pk_script spk <> (ty = "pubkey") then
        bad := Printf.sprintf "%s core=%s gate=%s p2pk=%b" (to_hex spk) ty
            (show (gate spk)) (Mempool.is_p2pk_script spk) :: !bad)
    Core_solver_vectors.vectors;
  Alcotest.(check int) "vectors" 1158 (List.length Core_solver_vectors.vectors);
  Alcotest.(check (list string)) "scripts where camlcoin differs from Core's Solver"
    [] (List.rev !bad)

(* --- output side: MatchPayToPubkey's ValidSize also governs IsStandard ---- *)

let test_output_p2pk_validsize () =
  let out spk = Mempool.is_standard_output spk in
  Alcotest.(check bool) "output 21 02<32B> ac standard" true
    (out (cat [ push (key33 "02"); hex "ac" ]));
  Alcotest.(check bool) "output 41 06<64B> ac standard" true
    (out (cat [ push (key65 "06"); hex "ac" ]));
  Alcotest.(check bool) "output 21 05<32B> ac NONSTANDARD (Core: scriptpubkey)"
    false (out (cat [ push (key33 "05"); hex "ac" ]));
  Alcotest.(check bool) "output 41 02<64B> ac NONSTANDARD" false
    (out (cat [ push (key65 "02"); hex "ac" ]))

let () =
  Alcotest.run "r3fix_p2pk_multisig_input_standard" [
    "end_to_end", [
      Alcotest.test_case "R86 minimised P2PK spend accepted" `Quick
        (accept_case "R86 P2PK" r86_tx_hex p2pk_spk);
      Alcotest.test_case "bare 2-of-2 multisig spend accepted" `Quick
        (accept_case "2-of-2 multisig" ms22_tx_hex ms22_spk);
      Alcotest.test_case "bad-sig P2PK spend still refused" `Quick
        test_bad_sig_still_rejected;
    ];
    "inputs_standardness", [
      Alcotest.test_case "P2PK prevouts are standard inputs" `Quick
        test_p2pk_inputs_standard;
      Alcotest.test_case "bare multisig prevouts are standard inputs" `Quick
        test_multisig_inputs_standard;
      Alcotest.test_case "NONSTANDARD shapes still script unknown" `Quick
        test_nonstandard_shapes_still_refused;
      Alcotest.test_case "WITNESS_UNKNOWN keeps its reason" `Quick
        test_witness_unknown_keeps_reason;
      Alcotest.test_case "1158 Core v31.1 Solver vectors" `Quick
        test_core_solver_vectors;
    ];
    "outputs", [
      Alcotest.test_case "P2PK output needs a ValidSize key" `Quick
        test_output_p2pk_validsize;
    ];
  ]
