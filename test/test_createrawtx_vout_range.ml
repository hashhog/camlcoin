(* createrawtransaction -- [vout] must be range-checked against int32
   ============================================================================

   THE DEFECT (regression pinned by this suite)
   --------------------------------------------
   createrawtransaction's input parser only asked "is vout negative?".  It
   never asked "is vout too big?".  The value was then narrowed to the 32-bit
   [vout] field of the outpoint, so anything at or above 2^32 silently WRAPPED:

       vout 4294967296 (2^32)  -->  outpoint index 0
       vout 8589934592 (2^33)  -->  outpoint index 0

   Both were observed on the live mainnet node.  The RPC returned SUCCESS and a
   perfectly well-formed transaction hex -- one that spends a COMPLETELY
   DIFFERENT outpoint from the one the caller asked for, and index 0 of a real
   txid is very likely a real, fundable output.  A caller that signs and
   broadcasts what it was handed spends the wrong coin, with no error and no
   log line anywhere.  Silent redirection of a spend is the worst shape a bug
   can take in this RPC.

   WHAT BITCOIN CORE DOES
   ----------------------
   Core reads the field with [find_value(o, "vout").getInt<int>()] -- [int],
   i.e. THIRTY-TWO bits (bitcoin-core/src/rpc/rawtransaction_util.cpp,
   AddInputs:38-45).  univalue's [getInt<Int>]
   (src/univalue/include/univalue.h) range-checks the parsed integer against
   the destination type and throws [std::runtime_error("JSON integer out of
   range")] when it does not fit; the RPC layer surfaces that as
   RPC_MISC_ERROR (-1).

   The ORDERING IS DELIBERATE AND IS UNIVALUE'S, NOT OURS: the range check
   lives inside the *conversion*, so it fires BEFORE the handler's own
   [if (nOutput < 0) throw ... "vout cannot be negative"] sign test ever runs.
   That is why -1 gets the vout-specific -8 message while 2147483648 -- also
   "not a valid vout" in any human sense -- gets the generic -1 "JSON integer
   out of range" instead.  Matching Core here means matching that ORDER, not
   just the two checks.

   The fix therefore adds, BEFORE the existing sign test:
       if n < -2147483648 || n > 2147483647 then
         fail rpc_misc_error "JSON integer out of range";

   TEETH
   -----
   Cases 1-6 are all rejections, and a handler that rejected EVERY input would
   satisfy every one of them.  The two CONTROL cases exist to make that
   impossible: they drive the real handler to success and then DECODE the
   returned hex with the node's own deserializer, asserting the outpoint index
   that actually landed in the bytes.  In particular the int32-MAX control
   (2147483647) fails loudly if the new bound is off by one in the tight
   direction.

   References:
     bitcoin-core/src/rpc/rawtransaction_util.cpp:38-45   AddInputs
     bitcoin-core/src/univalue/include/univalue.h         getInt<Int>
     bitcoin-core/src/rpc/protocol.h                      RPC_MISC_ERROR = -1
                                                          RPC_INVALID_PARAMETER = -8
   ========================================================================== *)

open Camlcoin

let test_db_path = "/tmp/camlcoin_test_createrawtx_vout_range_db"

let cleanup_test_db () =
  let rec rm_rf path =
    if Sys.file_exists path then begin
      if Sys.is_directory path then begin
        Array.iter (fun f -> rm_rf (Filename.concat path f)) (Sys.readdir path);
        Unix.rmdir path
      end else Unix.unlink path
    end
  in
  rm_rf test_db_path

(* Well-formed 64-hex txid; the content is irrelevant -- createrawtransaction
   builds an UNSIGNED transaction and never looks the outpoint up. *)
let test_txid =
  "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"

(* createrawtransaction reads nothing but ctx.network, yet the record is total,
   so build the same minimal context test_rpc.ml uses. *)
let create_test_context () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let utxo = Utxo.UtxoSet.create db in
  let mp =
    Mempool.create ~network:Consensus.regtest ~require_standard:false
      ~verify_scripts:false ~utxo ~current_height:0 ()
  in
  let chain = Sync.create_chain_state db Consensus.mainnet in
  let pm = Peer_manager.create Consensus.mainnet in
  let fe = Fee_estimation.create () in
  let ctx : Rpc.rpc_context =
    { chain; mempool = mp; peer_manager = pm; wallet = None;
      wallet_manager = None; fee_estimator = fe; network = Consensus.mainnet;
      filter_index = None; utxo = None; data_dir = None;
      snapshot_activation = None }
  in
  (ctx, db)

(* A single OP_RETURN output. Deliberately data-only: it keeps the suite
   independent of address encoding/network, so a failure here can only mean
   the INPUT parser, never the output parser. *)
let outputs_param : Yojson.Safe.t = `Assoc [ ("data", `String "deadbeef") ]

let call_create_raw (inputs : Yojson.Safe.t list) =
  let ctx, _db = create_test_context () in
  Rpc.handle_createrawtransaction ctx [ `List inputs; outputs_param ]

let call_create_raw_locktime (inputs : Yojson.Safe.t list)
    (locktime : Yojson.Safe.t) =
  let ctx, _db = create_test_context () in
  Rpc.handle_createrawtransaction ctx
    [ `List inputs; outputs_param; locktime ]

let input_with_vout (v : int) : Yojson.Safe.t =
  `Assoc [ ("txid", `String test_txid); ("vout", `Int v) ]

(* Assert a rejection. A SUCCESS is reported as a distinct, loud failure
   rather than being silently tolerated. *)
let check_error ~what ~code ~msg result =
  match result with
  | Ok _ ->
    Alcotest.failf "%s: expected error %d %S but the call SUCCEEDED" what code msg
  | Error (c, m) ->
    Alcotest.(check int) (what ^ ": code") code c;
    Alcotest.(check string) (what ^ ": message") msg m

let hex_to_cstruct (hex : string) : Cstruct.t =
  let n = String.length hex / 2 in
  let cs = Cstruct.create n in
  for i = 0 to n - 1 do
    Cstruct.set_uint8 cs i (int_of_string ("0x" ^ String.sub hex (i * 2) 2))
  done;
  cs

(* Decode with the node's own transaction deserializer and report the outpoint
   index that actually reached the wire bytes. *)
let first_input_vout (hex : string) : int32 =
  let r = Serialize.reader_of_cstruct (hex_to_cstruct hex) in
  let tx = Serialize.deserialize_transaction r in
  match tx.Types.inputs with
  | [ i ] -> i.Types.previous_output.Types.vout
  | l -> Alcotest.failf "expected exactly one input, got %d" (List.length l)

let check_accepted ~what ~expected_vout result =
  match result with
  | Error (c, m) ->
    Alcotest.failf "%s: expected success but got error %d %S" what c m
  | Ok (`String hex) ->
    Alcotest.(check bool) (what ^ ": non-empty hex") true (String.length hex > 0);
    Alcotest.(check int32) (what ^ ": outpoint index in the tx bytes")
      expected_vout (first_input_vout hex)
  | Ok other ->
    Alcotest.failf "%s: expected a hex string result, got %s" what
      (Yojson.Safe.to_string other)

(* ---- REGRESSION: out-of-int32 vout must be -1 "JSON integer out of range" -- *)

(* PRE-FIX: returned a tx whose outpoint index was 0 (silent wrap). *)
let test_vout_2pow32 () =
  check_error ~what:"vout 2^32" ~code:(-1) ~msg:"JSON integer out of range"
    (call_create_raw [ input_with_vout 4294967296 ])

(* PRE-FIX: also wrapped to 0 -- two different requests, one wrong spend. *)
let test_vout_2pow33 () =
  check_error ~what:"vout 2^33" ~code:(-1) ~msg:"JSON integer out of range"
    (call_create_raw [ input_with_vout 8589934592 ])

(* The exact boundary: one past what Core's getInt<int> can hold. *)
let test_vout_int32_max_plus_one () =
  check_error ~what:"vout 2147483648" ~code:(-1)
    ~msg:"JSON integer out of range"
    (call_create_raw [ input_with_vout 2147483648 ])

(* Negative AND out of int32 range: Core's range check lives inside the
   conversion, so it wins over the "cannot be negative" message. This is the
   ordering assertion. *)
let test_vout_int32_min_minus_one () =
  check_error ~what:"vout -2147483649" ~code:(-1)
    ~msg:"JSON integer out of range"
    (call_create_raw [ input_with_vout (-2147483649) ])

(* ---- neighbouring guards still report Core's own codes ------------------- *)

(* In int32 range, so the range check passes and the sign test speaks. *)
let test_vout_negative_one () =
  check_error ~what:"vout -1" ~code:(-8)
    ~msg:"Invalid parameter, vout cannot be negative"
    (call_create_raw [ input_with_vout (-1) ])

let test_sequence_out_of_range () =
  check_error ~what:"sequence 2^32" ~code:(-8)
    ~msg:"Invalid parameter, sequence number is out of range"
    (call_create_raw
       [ `Assoc [ ("txid", `String test_txid); ("vout", `Int 0);
                  ("sequence", `Int 4294967296) ] ])

let test_locktime_negative () =
  check_error ~what:"locktime -1" ~code:(-8)
    ~msg:"Invalid parameter, locktime out of range"
    (call_create_raw_locktime [ input_with_vout 0 ] (`Int (-1)))

(* ---- CONTROLS: an over-tight bound must FAIL these ----------------------- *)

(* Mandatory teeth: proves the new upper bound is [> 2147483647], not
   [>= 2147483647] or some smaller cap. *)
let test_control_int32_max_accepted () =
  check_accepted ~what:"vout 2147483647 (int32 MAX)"
    ~expected_vout:2147483647l
    (call_create_raw [ input_with_vout 2147483647 ])

(* Mandatory teeth: proves the handler still does its normal job, so the
   rejection tests above cannot be satisfied by a reject-everything stub. *)
let test_control_ordinary_vout_accepted () =
  check_accepted ~what:"vout 7 (ordinary)" ~expected_vout:7l
    (call_create_raw [ input_with_vout 7 ])

let () =
  Alcotest.run "createrawtransaction vout range"
    [
      ( "vout_int32_range_REGRESSION",
        [
          Alcotest.test_case "vout 4294967296 (2^32) -> -1 out of range" `Quick
            test_vout_2pow32;
          Alcotest.test_case "vout 8589934592 (2^33) -> -1 out of range" `Quick
            test_vout_2pow33;
          Alcotest.test_case "vout 2147483648 (int32 MAX+1) -> -1" `Quick
            test_vout_int32_max_plus_one;
          Alcotest.test_case "vout -2147483649 -> -1 (range beats sign)" `Quick
            test_vout_int32_min_minus_one;
        ] );
      ( "neighbouring_guards",
        [
          Alcotest.test_case "vout -1 -> -8 cannot be negative" `Quick
            test_vout_negative_one;
          Alcotest.test_case "sequence 4294967296 -> -8 out of range" `Quick
            test_sequence_out_of_range;
          Alcotest.test_case "locktime -1 -> -8 out of range" `Quick
            test_locktime_negative;
        ] );
      ( "CONTROLS_must_still_be_accepted",
        [
          Alcotest.test_case "vout 2147483647 accepted, lands in tx bytes"
            `Quick test_control_int32_max_accepted;
          Alcotest.test_case "vout 7 accepted, lands in tx bytes" `Quick
            test_control_ordinary_vout_accepted;
        ] );
    ]
