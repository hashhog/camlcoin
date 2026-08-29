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


(* ==========================================================================
   SECOND DEFECT (same RPC, same file): replaceable=true silently contradicted
   ==========================================================================

   THE DEFECT
   ----------
   createrawtransaction lets the caller say two incompatible things at once:

       createrawtransaction '[{"txid":"..","vout":0,"sequence":4294967295}]' \
                            '{"data":"deadbeef"}' 0 true
                                                    ^^^^ "make it replaceable"
                             ^^^^^^^^^^^^^^^^^^^^ "...and make it final"

   An explicit [sequence] wins over the replaceable-derived default, so the
   node quietly picked FINAL and returned a perfectly well-formed transaction
   -- as a SUCCESS -- that CANNOT EVER BE FEE-BUMPED.  The caller's explicit
   RBF request was dropped on the floor with no error, no warning and no log
   line.  The failure only surfaces much later, when the transaction is stuck
   at a low feerate and the fee bump is refused by the network.  Nine of the
   ten node implementations in this repo accept this contradiction today.

   WHAT BITCOIN CORE DOES
   ----------------------
   It refuses to guess.  At the very END of ConstructTransaction
   (bitcoin-core/src/rpc/rawtransaction_util.cpp), after BOTH AddInputs and
   AddOutputs have run:

       if (rbf.has_value() && rbf.value() && rawTx.vin.size() > 0 &&
           !SignalsOptInRBF(CTransaction(rawTx)))
           throw JSONRPCError(RPC_INVALID_PARAMETER,
             "Invalid parameter combination: Sequence number(s) contradict "
             "replaceable option");

   with (bitcoin-core/src/util/rbf.cpp, MAX_BIP125_RBF_SEQUENCE = 0xfffffffd):

       bool SignalsOptInRBF(const CTransaction &tx) {
           for (const CTxIn &txin : tx.vin)
               if (txin.nSequence <= MAX_BIP125_RBF_SEQUENCE) return true;
           return false;
       }

   THREE conditions must ALL hold, and each one is a separate way to get this
   wrong.  The four ACCEPT rows below are therefore not garnish: they are the
   teeth that stop an over-eager check from breaking ordinary RBF usage.

   THE ABSENT-VS-EXPLICIT ASYMMETRY (row 1 -- easy to get wrong)
   ------------------------------------------------------------
   [rbf] is a [std::optional<bool>] that stays [nullopt] when the parameter
   [isNull()], and Core's two consumers ask DIFFERENT questions of it:
   AddInputs uses [rbf.value_or(true)], so an ABSENT argument still defaults
   to true when CHOOSING the sequence; but the check above uses
   [rbf.has_value() && rbf.value()], so an ABSENT argument can contradict
   nothing.  Omitting the argument and pinning a final sequence is therefore
   ACCEPTED, while passing an explicit [true] and the same sequence is
   REJECTED.  That asymmetry is deliberate, and collapsing the two -- the
   obvious simplification -- breaks every caller who never passes the 4th arg.

   ONE SIGNALLING INPUT IS ENOUGH (row 6 -- the other easy one)
   -----------------------------------------------------------
   SignalsOptInRBF is [return true] on the FIRST signalling input, not "all
   inputs signal".  BIP 125 spells out why: in a multi-party protocol a single
   counterparty must not be able to disable replacement by opting out in their
   own input.  A check written with List.for_all instead of List.exists passes
   rows 1-5 and 7-8 and fails only here.

   THE SIGNED/UNSIGNED TRAP
   ------------------------
   Core compares uint32_t.  Our [sequence] field is an int32, so the exact
   values that must NOT signal are stored NEGATIVE: 0xFFFFFFFF is -1l and
   0xFFFFFFFE is -2l.  A signed [<= 0xFFFFFFFDl] comparison rates every one of
   them as signalling, which makes the check unreachable -- it still compiles,
   still passes rows 1, 2, 5, 6, 7 and 8, and disables the feature silently.
   Rows 3 and 4 are the ones that catch it.

   EVERY ROW BELOW WAS VERIFIED AGAINST A LIVE BITCOIN CORE NODE.

     # | rbf arg | inputs                          | expected
     --+---------+---------------------------------+---------------------
     1 | ABSENT  | one, sequence 0xFFFFFFFF        | ACCEPT (no explicit rbf)
     2 | true    | one, sequence 0xFFFFFFFD        | ACCEPT (signals)
     3 | true    | one, sequence 0xFFFFFFFE        | REJECT -8
     4 | true    | one, sequence 0xFFFFFFFF        | REJECT -8
     5 | true    | none at all ([])                | ACCEPT (no inputs)
     6 | true    | two: 0xFFFFFFFF and 0           | ACCEPT (one signals)
     7 | false   | one, sequence 0xFFFFFFFF        | ACCEPT (rbf not true)
     8 | true    | one, NO explicit sequence       | ACCEPT (default signals)

   References:
     bitcoin-core/src/rpc/rawtransaction_util.cpp  ConstructTransaction (end)
     bitcoin-core/src/util/rbf.cpp                 SignalsOptInRBF
     bitcoin-core/src/util/rbf.h                   MAX_BIP125_RBF_SEQUENCE
     bitcoin-core/src/rpc/protocol.h               RPC_INVALID_PARAMETER = -8
   ========================================================================== *)

let rbf_error_msg =
  "Invalid parameter combination: Sequence number(s) contradict replaceable \
   option"

(* Core's 4-arg form: inputs, outputs, locktime, replaceable. locktime is 0
   throughout so that the !replaceable default sequence is SEQUENCE_FINAL and
   the rows differ only in the axis under test. *)
let call_create_raw_rbf (inputs : Yojson.Safe.t list) (rbf : Yojson.Safe.t) =
  let ctx, _db = create_test_context () in
  Rpc.handle_createrawtransaction ctx
    [ `List inputs; outputs_param; `Int 0; rbf ]

let input_with_sequence (v : int) (seq : int) : Yojson.Safe.t =
  `Assoc [ ("txid", `String test_txid); ("vout", `Int v);
           ("sequence", `Int seq) ]

(* Every sequence that actually reached the wire bytes, decoded with the
   node's own deserializer -- the same "assert on the serialized form, not on
   the absence of an error" discipline the vout controls above use. *)
let input_sequences (hex : string) : int32 list =
  let r = Serialize.reader_of_cstruct (hex_to_cstruct hex) in
  let tx = Serialize.deserialize_transaction r in
  List.map (fun (i : Types.tx_in) -> i.Types.sequence) tx.Types.inputs

let check_accepted_sequences ~what ~expected result =
  match result with
  | Error (c, m) ->
    Alcotest.failf "%s: expected success but got error %d %S" what c m
  | Ok (`String hex) ->
    Alcotest.(check bool) (what ^ ": non-empty hex") true (String.length hex > 0);
    Alcotest.(check (list int32)) (what ^ ": sequences in the tx bytes")
      expected (input_sequences hex)
  | Ok other ->
    Alcotest.failf "%s: expected a hex string result, got %s" what
      (Yojson.Safe.to_string other)

(* ---- ROW 1: ABSENT rbf + final sequence -> ACCEPT ------------------------ *)

(* The asymmetry test. Uses the 2-ARG form, so replaceable_param is genuinely
   absent rather than explicitly null-or-false. A check that keys off the
   effective value of replaceable (which still defaults to TRUE here) instead
   of off has_value() rejects this and breaks every ordinary caller. *)
let test_rbf_absent_final_sequence_accepted () =
  let ctx, _db = create_test_context () in
  check_accepted_sequences ~what:"row 1: rbf ABSENT, sequence 0xFFFFFFFF"
    ~expected:[ -1l ]
    (Rpc.handle_createrawtransaction ctx
       [ `List [ input_with_sequence 0 0xFFFFFFFF ]; outputs_param ])

(* ---- ROW 2: rbf=true + a signalling sequence -> ACCEPT ------------------- *)

(* MAX_BIP125_RBF_SEQUENCE itself: the boundary is <=, not <. Stored as -3l. *)
let test_rbf_true_max_bip125_sequence_accepted () =
  check_accepted_sequences ~what:"row 2: rbf=true, sequence 0xFFFFFFFD"
    ~expected:[ -3l ]
    (call_create_raw_rbf [ input_with_sequence 0 0xFFFFFFFD ] (`Bool true))

(* ---- ROWS 3 & 4: rbf=true + non-signalling sequences -> REJECT -8 -------- *)

(* One past the boundary. Stored as -2l, so a SIGNED comparison lets this
   through: this row and row 4 are what catch the int32 sign trap. *)
let test_rbf_true_sequence_nonfinal_rejected () =
  check_error ~what:"row 3: rbf=true, sequence 0xFFFFFFFE" ~code:(-8)
    ~msg:rbf_error_msg
    (call_create_raw_rbf [ input_with_sequence 0 0xFFFFFFFE ] (`Bool true))

(* SEQUENCE_FINAL, stored as -1l. The headline case: "make it replaceable and
   also make it final". *)
let test_rbf_true_sequence_final_rejected () =
  check_error ~what:"row 4: rbf=true, sequence 0xFFFFFFFF" ~code:(-8)
    ~msg:rbf_error_msg
    (call_create_raw_rbf [ input_with_sequence 0 0xFFFFFFFF ] (`Bool true))

(* ---- ROW 5: rbf=true + NO inputs -> ACCEPT ------------------------------- *)

(* Core's [rawTx.vin.size() > 0] guard. An empty input list cannot signal
   opt-in, so a check that forgot this guard rejects a legitimate
   outputs-only skeleton (the normal first step of a funded-by-the-wallet
   build) and would be caught here.

   Asserted on the RAW BYTES rather than through deserialize_transaction: a
   0-input transaction serializes its input count as 0x00, which BIP-144
   parsers -- including this node's -- read as the witness MARKER. Decoding it
   would misparse, so the honest assertion is the prefix itself:
   "02000000" (version 2, LE) followed by "00" (input count 0). *)
let test_rbf_true_no_inputs_accepted () =
  match call_create_raw_rbf [] (`Bool true) with
  | Error (c, m) ->
    Alcotest.failf "row 5: rbf=true with no inputs: expected success, got %d %S"
      c m
  | Ok (`String hex) ->
    let hex = String.lowercase_ascii hex in
    Alcotest.(check bool) "row 5: hex long enough" true (String.length hex >= 10);
    Alcotest.(check string) "row 5: version 2 + input count 0 in the tx bytes"
      "0200000000" (String.sub hex 0 10)
  | Ok other ->
    Alcotest.failf "row 5: expected a hex string result, got %s"
      (Yojson.Safe.to_string other)

(* ---- ROW 6: rbf=true + ONE signalling input among two -> ACCEPT ---------- *)

(* BIP 125's multi-party rule: ANY signalling input is enough. Input 0 is
   final (-1l), input 1 is sequence 0 (0l, deeply signalling). List.for_all
   instead of List.exists fails here and ONLY here. *)
let test_rbf_true_one_of_two_signals_accepted () =
  check_accepted_sequences
    ~what:"row 6: rbf=true, inputs 0xFFFFFFFF and 0"
    ~expected:[ -1l; 0l ]
    (call_create_raw_rbf
       [ input_with_sequence 0 0xFFFFFFFF; input_with_sequence 1 0 ]
       (`Bool true))

(* ---- ROW 7: rbf=false + final sequence -> ACCEPT ------------------------- *)

(* rbf.has_value() is true but rbf.value() is false: the caller asked for
   non-replaceable and got it. Nothing to contradict. *)
let test_rbf_false_final_sequence_accepted () =
  check_accepted_sequences ~what:"row 7: rbf=false, sequence 0xFFFFFFFF"
    ~expected:[ -1l ]
    (call_create_raw_rbf [ input_with_sequence 0 0xFFFFFFFF ] (`Bool false))

(* ---- ROW 8: rbf=true + no explicit sequence -> ACCEPT -------------------- *)

(* The ordinary, overwhelmingly common RBF call. The default sequence derived
   from replaceable=true IS MAX_BIP125_RBF_SEQUENCE (-3l), so it signals and
   the transaction is built. If this row ever fails, the check is firing on
   the normal path and the RPC is broken for its main use. It also pins that
   the new check did not perturb default_sequence. *)
let test_rbf_true_default_sequence_accepted () =
  check_accepted_sequences ~what:"row 8: rbf=true, no explicit sequence"
    ~expected:[ -3l ]
    (call_create_raw_rbf [ input_with_vout 0 ] (`Bool true))

(* ==========================================================================
   THIRD DEFECT (same RPC, same handler): a PRESENT but NON-NUMERIC
   [sequence] must be IGNORED, not rejected.
   ==========================================================================

   Core guards the WHOLE read with a type test and offers no [else]
   (bitcoin-core/src/rpc/rawtransaction_util.cpp:57-65):

       const UniValue& sequenceObj = o.find_value("sequence");
       if (sequenceObj.isNum()) {
           int64_t seqNr64 = sequenceObj.getInt<int64_t>();
           if (seqNr64 < 0 || seqNr64 > CTxIn::SEQUENCE_FINAL) {
               throw JSONRPCError(RPC_INVALID_PARAMETER,
                   "Invalid parameter, sequence number is out of range");
           } else { nSequence = (uint32_t)seqNr64; }
       }

   A string, bool, object, array or null never enters the branch, so the
   default computed a few lines above simply survives and Core ACCEPTS the
   call.  camlcoin answered -8 "Invalid parameter, sequence number is out of
   range" -- wrong twice over: nothing was out of range, and the value had no
   range to be out of.

   THE ASSERTION IS ON THE EMITTED SEQUENCE, NOT ON MERE ACCEPTANCE.  This is
   a TWO-SIDED trap.  With [replaceable] absent, rbf.value_or(true) is TRUE,
   so the surviving default is MAX_BIP125_RBF_SEQUENCE (0xFFFFFFFD = -3l as a
   signed int32) and the transaction is REPLACEABLE.  An implementation that
   fell through to SEQUENCE_FINAL (-1l) would also "accept" -- while quietly
   handing back a NON-replaceable transaction.  rustoshi originally did
   exactly that, so "the call succeeded" is not evidence of anything.

   THE FLOAT ROWS are the case a dynamically-typed implementation cannot
   express and OCaml can.  univalue keeps the RAW TOKEN and converts it with
   std::from_chars, which stops at the '.' or the 'e' and leaves trailing
   characters, so the conversion FAILS.  Verified against the live Core node
   (2026-08-28): [sequence: 1.5] AND [sequence: 100.0] are both
   -1 "JSON integer out of range" -- neither ignored nor accepted.  Yojson
   produces [`Float] only for a token carrying a fraction or an exponent,
   which is exactly that set.

   Oracle rows captured from the live Core node on 2026-08-28:
     sequence "nope" / true / false / null / {} / []  ACCEPT, emits 0xFFFFFFFD
     the same with replaceable=false                  ACCEPT, emits 0xFFFFFFFF
     sequence 1.5 / 100.0                             REJECT -1
     sequence 4294967296 (NUMERIC)                    REJECT -8  (unchanged) *)

let input_with_raw_sequence (v : int) (seq : Yojson.Safe.t) : Yojson.Safe.t =
  `Assoc [ ("txid", `String test_txid); ("vout", `Int v); ("sequence", seq) ]

(* Each non-numeric JSON type must be ignored, leaving the RBF default. *)
let test_non_numeric_sequence_ignored (label : string) (seq : Yojson.Safe.t) () =
  check_accepted_sequences
    ~what:(label ^ " sequence is ignored; RBF default reaches the bytes")
    ~expected:[ -3l ]
    (call_create_raw [ input_with_raw_sequence 0 seq ])

(* The fall-through must reach the real default COMPUTATION, not a hard-coded
   0xFFFFFFFD: with replaceable explicitly false and locktime 0, AddInputs
   picks SEQUENCE_FINAL. *)
let test_non_numeric_sequence_honours_rbf_false () =
  check_accepted_sequences
    ~what:"non-numeric sequence + rbf=false -> SEQUENCE_FINAL"
    ~expected:[ -1l ]
    (call_create_raw_rbf
       [ input_with_raw_sequence 0 (`String "nope") ] (`Bool false))

let test_float_sequence_is_misc_error (label : string) (f : float) () =
  check_error ~what:(label ^ ": isNum() but no integral token")
    ~code:(-1) ~msg:"JSON integer out of range"
    (call_create_raw [ input_with_raw_sequence 0 (`Float f) ])

(* CONTROLS: the NUMERIC branch must be untouched.  Without these the fix is
   satisfiable by deleting the range check outright, or by ignoring every
   sequence including the valid ones. *)
let test_control_numeric_sequence_negative_still_rejected () =
  check_error ~what:"CONTROL: numeric sequence -1"
    ~code:(-8) ~msg:"Invalid parameter, sequence number is out of range"
    (call_create_raw [ input_with_sequence 0 (-1) ])

let test_control_ordinary_numeric_sequence_still_assigned () =
  check_accepted_sequences
    ~what:"CONTROL: ordinary numeric sequence 12345 reaches the bytes"
    ~expected:[ 12345l ]
    (call_create_raw [ input_with_sequence 0 12345 ])


(* ------------------------------------------------------------------ *)
(* createrawtransaction must HONOUR the [version] argument (#84).      *)
(*                                                                     *)
(* Core's createrawtransaction takes a 5th argument, [version]         *)
(* (rpc/rawtransaction.cpp:122), reads it as Arg<uint32_t>, bounds it  *)
(* to [1,3] (policy/policy.h:152-153) and EMITS it                     *)
(* (rawtransaction_util.cpp:158-161).                                  *)
(*                                                                     *)
(* camlcoin did not accept the argument AT ALL: the arity match        *)
(* rejected a five-parameter call with -32602 and Core's help text, so *)
(* a caller asking for version 3 could not reach the builder. Version  *)
(* 3 is TRUC (BIP 431) and carries different policy rules.             *)
(*                                                                     *)
(* THE UNSIGNED WIDTH decides which error you get: 2147483648 fits a   *)
(* uint32, survives the conversion and reaches the DOMAIN error (-8),  *)
(* while -1 and 4294967296 fail the CONVERSION first (-1). Both are    *)
(* asserted; collapsing them would look close enough and be wrong      *)
(* twice.                                                              *)
(*                                                                     *)
(* OCAML HAZARD: [Int32.of_int] WRAPS, so the uint32 bound must be     *)
(* checked on the 63-bit int BEFORE conversion. The 2^32 case pins it. *)
(*                                                                     *)
(* THE ASSERTIONS DECODE THE VERSION BYTES off the returned            *)
(* transaction. Checking that the call was accepted is exactly the     *)
(* pre-fix behaviour... except here it is worse, because pre-fix the   *)
(* call was REJECTED, so an "accepted" assertion would pass the moment *)
(* the argument was tolerated and ignored.                             *)
(* ------------------------------------------------------------------ *)

let call_create_raw_version (version : Yojson.Safe.t option) =
  let ctx, _db = create_test_context () in
  let base =
    [ `List [ input_with_vout 0 ]; outputs_param; `Int 0; `Bool false ]
  in
  Rpc.handle_createrawtransaction ctx
    (match version with None -> base | Some v -> base @ [ v ])

let tx_version_of (hex : string) : int32 =
  let r = Serialize.reader_of_cstruct (hex_to_cstruct hex) in
  (Serialize.deserialize_transaction r).Types.version

let check_version ~what ~expected result =
  match result with
  | Error (c, m) ->
    Alcotest.failf "%s: expected success but got error %d %S" what c m
  | Ok (`String hex) ->
    Alcotest.(check int32) (what ^ ": tx version") expected (tx_version_of hex)
  | Ok other ->
    Alcotest.failf "%s: expected a hex string, got %s" what
      (Yojson.Safe.to_string other)

let test_version_emitted (v : int) () =
  check_version ~what:(Printf.sprintf "version %d" v)
    ~expected:(Int32.of_int v)
    (call_create_raw_version (Some (`Int v)))

let test_version_out_of_domain (v : int) () =
  check_error ~what:(Printf.sprintf "version %d" v) ~code:(-8)
    ~msg:"Invalid parameter, version out of range(1~3)"
    (call_create_raw_version (Some (`Int v)))

let test_version_out_of_uint32 (v : int) () =
  check_error ~what:(Printf.sprintf "version %d" v) ~code:(-1)
    ~msg:"JSON integer out of range"
    (call_create_raw_version (Some (`Int v)))

(* CONTROLS. Without these, a handler that rejected every version would
   satisfy every rejection assertion above. *)
let test_control_version_absent_defaults_to_2 () =
  check_version ~what:"absent version" ~expected:2l
    (call_create_raw_version None)

let test_control_version_null_defaults_to_2 () =
  check_version ~what:"null version" ~expected:2l
    (call_create_raw_version (Some `Null))

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
      ( "rbf_sequence_contradiction_REGRESSION",
        [
          Alcotest.test_case "row 3: rbf=true + sequence 0xFFFFFFFE -> -8"
            `Quick test_rbf_true_sequence_nonfinal_rejected;
          Alcotest.test_case "row 4: rbf=true + sequence 0xFFFFFFFF -> -8"
            `Quick test_rbf_true_sequence_final_rejected;
        ] );
      ( "rbf_CONTROLS_must_still_be_accepted",
        [
          Alcotest.test_case "row 1: rbf ABSENT + 0xFFFFFFFF accepted" `Quick
            test_rbf_absent_final_sequence_accepted;
          Alcotest.test_case "row 2: rbf=true + 0xFFFFFFFD accepted" `Quick
            test_rbf_true_max_bip125_sequence_accepted;
          Alcotest.test_case "row 5: rbf=true + no inputs accepted" `Quick
            test_rbf_true_no_inputs_accepted;
          Alcotest.test_case "row 6: rbf=true + one of two signals accepted"
            `Quick test_rbf_true_one_of_two_signals_accepted;
          Alcotest.test_case "row 7: rbf=false + 0xFFFFFFFF accepted" `Quick
            test_rbf_false_final_sequence_accepted;
          Alcotest.test_case "row 8: rbf=true + default sequence accepted"
            `Quick test_rbf_true_default_sequence_accepted;
        ] );
      ( "non_numeric_sequence_ignored_REGRESSION",
        [
          Alcotest.test_case "string sequence ignored -> 0xFFFFFFFD" `Quick
            (test_non_numeric_sequence_ignored "string" (`String "nope"));
          Alcotest.test_case "bool true sequence ignored -> 0xFFFFFFFD" `Quick
            (test_non_numeric_sequence_ignored "bool true" (`Bool true));
          Alcotest.test_case "bool false sequence ignored -> 0xFFFFFFFD" `Quick
            (test_non_numeric_sequence_ignored "bool false" (`Bool false));
          Alcotest.test_case "null sequence ignored -> 0xFFFFFFFD" `Quick
            (test_non_numeric_sequence_ignored "null" `Null);
          Alcotest.test_case "object sequence ignored -> 0xFFFFFFFD" `Quick
            (test_non_numeric_sequence_ignored "object" (`Assoc []));
          Alcotest.test_case "array sequence ignored -> 0xFFFFFFFD" `Quick
            (test_non_numeric_sequence_ignored "array" (`List []));
          Alcotest.test_case "ignored sequence still honours rbf=false" `Quick
            test_non_numeric_sequence_honours_rbf_false;
          Alcotest.test_case "float sequence 1.5 -> -1 out of range" `Quick
            (test_float_sequence_is_misc_error "sequence 1.5" 1.5);
          Alcotest.test_case "float sequence 100.0 -> -1 out of range" `Quick
            (test_float_sequence_is_misc_error "sequence 100.0" 100.0);
        ] );
      ( "version_argument_REGRESSION",
        [
          Alcotest.test_case "version 1 is emitted" `Quick (test_version_emitted 1);
          Alcotest.test_case "version 2 is emitted" `Quick (test_version_emitted 2);
          Alcotest.test_case "version 3 (TRUC) is emitted" `Quick
            (test_version_emitted 3);
          Alcotest.test_case "version 0 -> -8 out of range(1~3)" `Quick
            (test_version_out_of_domain 0);
          Alcotest.test_case "version 4 -> -8 out of range(1~3)" `Quick
            (test_version_out_of_domain 4);
          Alcotest.test_case "version 2^31 fits uint32 -> -8, not -1" `Quick
            (test_version_out_of_domain 2147483648);
          Alcotest.test_case "version 2^32 outside uint32 -> -1, not -8" `Quick
            (test_version_out_of_uint32 4294967296);
          Alcotest.test_case "version -1 outside uint32 -> -1" `Quick
            (test_version_out_of_uint32 (-1));
        ] );
      ( "version_argument_CONTROLS",
        [
          Alcotest.test_case "absent version defaults to 2" `Quick
            test_control_version_absent_defaults_to_2;
          Alcotest.test_case "null version defaults to 2" `Quick
            test_control_version_null_defaults_to_2;
        ] );
      ( "numeric_sequence_branch_CONTROLS",
        [
          Alcotest.test_case "numeric sequence -1 still -8" `Quick
            test_control_numeric_sequence_negative_still_rejected;
          Alcotest.test_case "ordinary numeric sequence still assigned" `Quick
            test_control_ordinary_numeric_sequence_still_assigned;
        ] );
    ]
