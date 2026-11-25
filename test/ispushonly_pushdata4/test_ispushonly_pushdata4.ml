(* OP_PUSHDATA4 lengths are UNSIGNED (psweep-camlcoin-ispushonly-pushdata4-
   signed-loop).

   Core v31.1 GetScriptOp (src/script/script.cpp) reads the PUSHDATA4 length
   with ReadLE32 into an `unsigned int` and fails the op when fewer than that
   many bytes remain, so IsPushOnly / Solver / SerializeScriptCode never move
   backwards and never loop.  camlcoin read it with
   `Int32.to_int (Cstruct.LE.get_uint32 ...)`, which sign-extends: the bytes
   `4e fb ff ff ff` gave a length of -5, so `pos + 5 + len` put the walker
   back on the same opcode and is_push_only_raw recursed forever.

   Reach on the pre-fix tree:
   - P2P/mempool: classify_script calls is_push_only_raw for every OP_RETURN
     output, from IsStandardTx, before any input lookup, so a relayed tx with
     output `6a 4e fb ff ff ff` hung ATMP.
   - block: a P2SH spend with scriptSig `4e fb ff ff ff` hung in the block
     sigop count (count_input_witness_sigops) and in verify_script.
   - RPC: decodescript of such a script.

   Every case runs in a forked child bounded at [bound_s] seconds; a child
   that does not finish is killed and the case fails as "hung".  Each case
   names the pre-fix outcome it catches. *)

open Camlcoin

let bound_s = 2.0

let hex s =
  let n = String.length s / 2 in
  Cstruct.of_string
    (String.init n (fun i -> Char.chr (int_of_string ("0x" ^ String.sub s (2 * i) 2))))

let to_hex (c : Cstruct.t) =
  String.concat ""
    (List.init (Cstruct.length c) (fun i -> Printf.sprintf "%02x" (Cstruct.get_uint8 c i)))

(* Remove any test_tmp chaindb a killed child left behind. *)
let reap_child_tmp pid =
  let prefix = Printf.sprintf "camlcoin_chaindb_%d_" pid in
  let pl = String.length prefix in
  try
    Array.iter
      (fun n ->
        if String.length n >= pl && String.sub n 0 pl = prefix then
          Test_tmp.rm_rf (Filename.concat "/tmp" n))
      (Sys.readdir "/tmp")
  with _ -> ()

(* Run [f] in a child.  The child writes [f ()] (or "RAISED <exn>") to a pipe
   and _exits, so no at_exit handler of the parent runs twice. *)
let bounded (f : unit -> string) : string =
  let rd, wr = Unix.pipe () in
  match Unix.fork () with
  | 0 ->
    Unix.close rd;
    let out = try f () with e -> "RAISED " ^ Printexc.to_string e in
    let b = Bytes.of_string out in
    ignore (Unix.write wr b 0 (Bytes.length b));
    Unix.close wr;
    Unix._exit 0
  | pid ->
    Unix.close wr;
    let deadline = Unix.gettimeofday () +. bound_s in
    let rec wait () =
      match Unix.waitpid [ Unix.WNOHANG ] pid with
      | 0, _ ->
        if Unix.gettimeofday () > deadline then begin
          (try Unix.kill pid Sys.sigkill with _ -> ());
          ignore (Unix.waitpid [] pid);
          false
        end else begin
          Unix.sleepf 0.02;
          wait ()
        end
      | _ -> true
    in
    let finished = wait () in
    let buf = Buffer.create 64 in
    let chunk = Bytes.create 4096 in
    let rec drain () =
      let k = try Unix.read rd chunk 0 4096 with _ -> 0 in
      if k > 0 then begin
        Buffer.add_subbytes buf chunk 0 k;
        drain ()
      end
    in
    if finished then drain ();
    Unix.close rd;
    if finished then Buffer.contents buf
    else begin
      reap_child_tmp pid;
      Printf.sprintf "HUNG (no answer within %.0fs)" bound_s
    end

let check_bounded name expected f =
  Alcotest.(check string) name expected (bounded f)

let b2s b = if b then "true" else "false"

(* ---- is_push_only_raw (Core CScript::IsPushOnly) ---------------------- *)

(* pre-fix: len = -5 -> next_pos = 0 -> check 0 forever *)
let test_ipo_minus5 () =
  check_bounded "is_push_only_raw 4efbffffff" "false" (fun () ->
      b2s (Script.is_push_only_raw (hex "4efbffffff")))

(* pre-fix: len = -16 -> next_pos = -11 -> Invalid_argument on the next read *)
let test_ipo_minus16 () =
  check_bounded "is_push_only_raw 4ef0ffffff" "false" (fun () ->
      b2s (Script.is_push_only_raw (hex "4ef0ffffff")))

(* pre-fix: len = -7 jumps back into the first push's data, re-parses it as
   `06 51 4e f9 ff ff ff` (a 6-byte push), lands on the trailing OP_1 and
   answers TRUE.  Core: GetOp fails at the PUSHDATA4 -> false. *)
let test_ipo_backjump_true () =
  check_bounded "is_push_only_raw 020651 4ef9ffffff 51" "false" (fun () ->
      b2s (Script.is_push_only_raw (hex "0206514ef9ffffff51")))

(* top-bit length, no backwards move even when read signed: still false *)
let test_ipo_top_bit_truncated () =
  check_bounded "is_push_only_raw 4e00000080" "false" (fun () ->
      b2s (Script.is_push_only_raw (hex "4e00000080")))

(* controls: a well-formed PUSHDATA4 is push-only; an overlong positive
   length is not *)
let test_ipo_controls () =
  check_bounded "is_push_only_raw 4e02000000aabb" "true" (fun () ->
      b2s (Script.is_push_only_raw (hex "4e02000000aabb")));
  check_bounded "is_push_only_raw 4e10000000aabb" "false" (fun () ->
      b2s (Script.is_push_only_raw (hex "4e10000000aabb")));
  check_bounded "is_push_only_raw 4e02000000aabb ac" "false" (fun () ->
      b2s (Script.is_push_only_raw (hex "4e02000000aabbac")))

(* ---- classify_script (Core Solver: OP_RETURN + IsPushOnly(begin+1)) --- *)

let template_name = function
  | Script.OP_RETURN_data _ -> "nulldata"
  | Script.Nonstandard -> "nonstandard"
  | _ -> "other"

let test_classify_opreturn () =
  check_bounded "classify_script 6a4efbffffff" "nonstandard" (fun () ->
      template_name (Script.classify_script (hex "6a4efbffffff")));
  check_bounded "classify_script 6a4ef0ffffff" "nonstandard" (fun () ->
      template_name (Script.classify_script (hex "6a4ef0ffffff")));
  (* pre-fix: nulldata (relay-standard); Core: NONSTANDARD *)
  check_bounded "classify_script 6a 020651 4ef9ffffff 51" "nonstandard" (fun () ->
      template_name (Script.classify_script (hex "6a0206514ef9ffffff51")));
  (* control: a well-formed PUSHDATA4 OP_RETURN stays nulldata *)
  check_bounded "classify_script 6a4e02000000aabb" "nulldata" (fun () ->
      template_name (Script.classify_script (hex "6a4e02000000aabb")))

(* ---- mempool / P2P: testmempoolaccept with require_standard ---------- *)

let coin_txid = Cstruct.of_string (String.make 32 '\x07')

let with_ctx f =
  Test_tmp.with_chaindb (fun db ->
      let utxo = Utxo.UtxoSet.create db in
      let mp =
        Mempool.create ~network:Consensus.regtest ~require_standard:true
          ~verify_scripts:true ~utxo ~current_height:0 ()
      in
      let chain = Sync.create_chain_state db Consensus.regtest in
      let ctx : Rpc.rpc_context =
        { chain; mempool = mp;
          peer_manager = Peer_manager.create Consensus.regtest;
          wallet = None; wallet_manager = None;
          fee_estimator = Fee_estimation.create ();
          network = Consensus.regtest; filter_index = None; utxo = None;
          data_dir = None; snapshot_activation = None }
      in
      f ctx)

let tx_hex (tx : Types.transaction) =
  let w = Serialize.writer_create () in
  Serialize.serialize_transaction w tx;
  to_hex (Serialize.writer_to_cstruct w)

(* One standard P2WPKH output, then the OP_RETURN under test.  97 bytes
   non-witness, so tx-size-small does not fire first.  No coin is needed:
   Core's IsStandardTx (scriptpubkey) runs before any input lookup. *)
let tx_with_opreturn spk_hex : Types.transaction =
  { Types.version = 2l;
    inputs = [ { Types.previous_output = { Types.txid = coin_txid; vout = 0l };
                 script_sig = Cstruct.create 0; sequence = 0xFFFFFFFFl } ];
    outputs = [ { Types.value = 4_999_990_000L;
                  script_pubkey = hex ("0014" ^ String.make 40 '1') };
                { Types.value = 0L; script_pubkey = hex spk_hex } ];
    witnesses = []; locktime = 0l }

let tma_reason spk_hex () =
  with_ctx (fun ctx ->
      match Rpc.dispatch_rpc ctx "testmempoolaccept"
              [ `List [ `String (tx_hex (tx_with_opreturn spk_hex)) ] ] with
      | Ok (`List [ `Assoc fields ]) ->
        (match List.assoc_opt "allowed" fields, List.assoc_opt "reject-reason" fields with
         | Some (`Bool a), Some (`String r) ->
           (* the reason TOKEN, as Core prints it; camlcoin appends a
              ": <detail>" suffix to some tokens (a separate formatting gap) *)
           Printf.sprintf "allowed=%b %s" a (List.hd (String.split_on_char ':' r))
         | Some (`Bool a), None -> Printf.sprintf "allowed=%b" a
         | _ -> "unexpected " ^ Yojson.Safe.to_string (`Assoc fields))
      | Ok j -> "unexpected " ^ Yojson.Safe.to_string j
      | Error (c, m) -> Printf.sprintf "error %d %s" c m)

(* Core v31.1 regtest (bitcoind sha256 986e63b3...88a08) answers
   allowed=false reject-reason "scriptpubkey" for this tx; pre-fix camlcoin
   never answered. *)
let test_tma_minus5 () =
  check_bounded "testmempoolaccept OP_RETURN 4efbffffff" "allowed=false scriptpubkey"
    (tma_reason "6a4efbffffff")

(* pre-fix: the OP_RETURN passed as standard and the tx got as far as the
   input lookup (missing-inputs); Core stops at scriptpubkey. *)
let test_tma_backjump () =
  check_bounded "testmempoolaccept OP_RETURN 020651 4ef9ffffff 51"
    "allowed=false scriptpubkey" (tma_reason "6a0206514ef9ffffff51")

(* control: a well-formed OP_RETURN gets past IsStandardTx to the input
   lookup, so the scriptpubkey answer above is specific to the bad push. *)
let test_tma_control () =
  check_bounded "testmempoolaccept OP_RETURN 4e02000000aabb (control)"
    "allowed=false missing-inputs" (tma_reason "6a4e02000000aabb")

(* ---- block path: P2SH spend with scriptSig 4efbffffff ---------------- *)

let p2sh_spk = hex ("a914" ^ String.make 40 '2' ^ "87")
let no_witness : Types.tx_witness = { Types.items = [] }
let flags = Script.script_verify_p2sh lor Script.script_verify_witness

(* Core GetTransactionSigOpCost -> CountWitnessSigOps: IsPushOnly is false,
   so 0.  pre-fix: hung inside the block sigop count, before scripts run. *)
let test_sigops_p2sh () =
  check_bounded "count_input_witness_sigops P2SH scriptSig 4efbffffff" "0" (fun () ->
      string_of_int
        (Validation.count_input_witness_sigops ~script_sig:(hex "4efbffffff")
           ~script_pubkey:p2sh_spk ~witness:no_witness ~flags))

let spend_tx script_sig : Types.transaction =
  { Types.version = 2l;
    inputs = [ { Types.previous_output = { Types.txid = coin_txid; vout = 0l };
                 script_sig; sequence = 0xFFFFFFFFl } ];
    outputs = [ { Types.value = 1L; script_pubkey = hex "51" } ];
    witnesses = []; locktime = 0l }

let verdict = function
  | Ok true -> "valid"
  | Ok false -> "invalid"
  | Error _ -> "invalid"

(* Core VerifyScript: EvalScript(scriptSig) fails with BAD_OPCODE -> the
   input (and its block) is invalid.  pre-fix: hung. *)
let test_verify_p2sh_bad_push () =
  check_bounded "verify_script P2SH scriptSig 4efbffffff" "invalid" (fun () ->
      let script_sig = hex "4efbffffff" in
      verdict
        (Script.verify_script ~tx:(spend_tx script_sig) ~input_index:0
           ~script_pubkey:p2sh_spk ~script_sig ~witness:no_witness ~amount:2L
           ~flags ()))

(* The opposite direction: a VALID P2SH spend whose redeemScript is pushed
   with a well-formed PUSHDATA4 must stay valid.  redeemScript = OP_1,
   P2SH spk = HASH160(51). *)
let test_verify_p2sh_pushdata4_valid () =
  check_bounded "verify_script P2SH scriptSig 4e0100000051 (valid)" "valid" (fun () ->
      let redeem = hex "51" in
      let spk =
        Cstruct.concat [ hex "a914"; Crypto.hash160 redeem; hex "87" ] in
      let script_sig = hex "4e0100000051" in
      verdict
        (Script.verify_script ~tx:(spend_tx script_sig) ~input_index:0
           ~script_pubkey:spk ~script_sig ~witness:no_witness ~amount:2L
           ~flags ()))

(* ---- decodescript (rpc.ml) ------------------------------------------ *)

(* Core v31.1 decodescript 6a4efbffffff: type "nonstandard".  pre-fix: hung. *)
let test_decodescript () =
  check_bounded "decodescript 6a4efbffffff type" "nonstandard" (fun () ->
      with_ctx (fun ctx ->
          match Rpc.dispatch_rpc ctx "decodescript" [ `String "6a4efbffffff" ] with
          | Ok (`Assoc f) ->
            (match List.assoc_opt "type" f with
             | Some (`String t) -> t
             | _ -> "no type")
          | Ok j -> "unexpected " ^ Yojson.Safe.to_string j
          | Error (c, m) -> Printf.sprintf "error %d %s" c m))

(* ---- sighash scriptCode walkers ------------------------------------- *)
(* Only reached with scripts parse_script already accepted, so not reachable
   with a negative length today; they had the same signed read.  A
   top-bit length must behave as the overlong unsigned length it is: the
   same answer as for `4e 10 00 00 00` (16, also overlong). *)

(* pre-fix: chunk_len = 0 -> i never advances -> hung *)
let test_strip_codesep () =
  check_bounded "strip_codeseparator ab4efbffffff" "4efbffffff" (fun () ->
      to_hex (Script.strip_codeseparator (hex "ab4efbffffff")));
  check_bounded "strip_codeseparator ab4e10000000 (control)" "4e10000000" (fun () ->
      to_hex (Script.strip_codeseparator (hex "ab4e10000000")))

(* pre-fix: opcode_len = 0 -> i never advances -> hung *)
let test_find_and_delete () =
  check_bounded "find_and_delete 4efbffffff" "4efbffffff false" (fun () ->
      let r, removed = Script.find_and_delete (hex "4efbffffff") (hex "aa") in
      to_hex r ^ " " ^ b2s removed)

(* pre-fix: the walker moved back to offset 0 and returned the whole script
   as the subscript after op 2 *)
let test_subscript () =
  check_bounded "compute_subscript_from_pos 4efbffffff5151 2" "" (fun () ->
      to_hex (Script.compute_subscript_from_pos (hex "4efbffffff5151") 2));
  check_bounded "compute_subscript_from_pos 4e100000005151 2 (control)" "" (fun () ->
      to_hex (Script.compute_subscript_from_pos (hex "4e100000005151") 2))

let () =
  Alcotest.run "ispushonly_pushdata4"
    [ ("is_push_only_raw",
       [ Alcotest.test_case "4efbffffff is not push-only and returns" `Quick test_ipo_minus5;
         Alcotest.test_case "4ef0ffffff is not push-only, no raise" `Quick test_ipo_minus16;
         Alcotest.test_case "negative length cannot jump back to a true verdict" `Quick
           test_ipo_backjump_true;
         Alcotest.test_case "top-bit length truncated" `Quick test_ipo_top_bit_truncated;
         Alcotest.test_case "well-formed and overlong controls" `Quick test_ipo_controls ]);
      ("classify_script",
       [ Alcotest.test_case "OP_RETURN with negative PUSHDATA4 is nonstandard" `Quick
           test_classify_opreturn ]);
      ("mempool",
       [ Alcotest.test_case "testmempoolaccept 6a4efbffffff answers scriptpubkey" `Quick
           test_tma_minus5;
         Alcotest.test_case "testmempoolaccept back-jump OP_RETURN answers scriptpubkey" `Quick
           test_tma_backjump;
         Alcotest.test_case "testmempoolaccept well-formed OP_RETURN control" `Quick
           test_tma_control ]);
      ("block",
       [ Alcotest.test_case "P2SH witness sigop count returns 0" `Quick test_sigops_p2sh;
         Alcotest.test_case "verify_script P2SH bad push is invalid" `Quick
           test_verify_p2sh_bad_push;
         Alcotest.test_case "verify_script P2SH PUSHDATA4 redeemScript stays valid" `Quick
           test_verify_p2sh_pushdata4_valid ]);
      ("rpc",
       [ Alcotest.test_case "decodescript 6a4efbffffff is nonstandard" `Quick test_decodescript ]);
      ("sighash-walkers",
       [ Alcotest.test_case "strip_codeseparator terminates" `Quick test_strip_codesep;
         Alcotest.test_case "find_and_delete terminates" `Quick test_find_and_delete;
         Alcotest.test_case "compute_subscript_from_pos does not move back" `Quick
           test_subscript ]) ]
