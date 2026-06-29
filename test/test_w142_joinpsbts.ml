(* W142 — joinpsbts + converttopsbt offline PSBT-secondary RPC tests.

   Parity target: Bitcoin Core v31.99 rpc/rawtransaction.cpp.
     - converttopsbt (1663): RPC_DESERIALIZATION_ERROR (-22) when an input
       carries scriptSig/scriptWitness and permitsigdata is false; with
       permitsigdata=true the sig data is stripped and a blank PSBT emitted.
     - joinpsbts (1778): RPC_INVALID_PARAMETER (-8) for fewer than 2 PSBTs and
       for a duplicate input prevout across PSBTs; otherwise the union of all
       inputs+outputs with max(version) + min(locktime).  Core SHUFFLES the
       merged input/output order for privacy, so these tests compare the
       input/output SETS, never byte order.

   Driven end-to-end through Rpc.dispatch_rpc so the per-method error-code
   routing (-8 / -22) is exercised together with the handler logic.  No node,
   no regtest, no network. *)

open Camlcoin

(* ── Minimal RPC context (handlers ignore it, but dispatch_rpc needs one) ── *)
let test_db_path = "/tmp/camlcoin_test_w142_joinpsbts_db"

let cleanup_test_db () =
  let rec rm_rf path =
    if Sys.file_exists path then begin
      if Sys.is_directory path then begin
        Array.iter (fun f -> rm_rf (Filename.concat path f)) (Sys.readdir path);
        Unix.rmdir path
      end else
        Unix.unlink path
    end
  in
  rm_rf test_db_path

(* joinpsbts/converttopsbt are pure offline handlers that ignore the context,
   so a single shared context is sufficient (and avoids re-opening the same
   rocksdb chainstate dir, which corrupts on repeated create/cleanup). *)
let shared_ctx : Rpc.rpc_context Lazy.t = lazy (
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let utxo = Utxo.UtxoSet.create db in
  let mp = Mempool.create ~network:Consensus.regtest ~require_standard:false ~verify_scripts:false
             ~utxo ~current_height:0 () in
  let chain = Sync.create_chain_state db Consensus.mainnet in
  let pm = Peer_manager.create Consensus.mainnet in
  let fe = Fee_estimation.create () in
  { Rpc.chain; mempool = mp; peer_manager = pm; wallet = None;
    wallet_manager = None; fee_estimator = fe; network = Consensus.mainnet;
    filter_index = None; utxo = None; data_dir = None;
    snapshot_activation = None })

let make_ctx () : Rpc.rpc_context = Lazy.force shared_ctx

(* ── Tx / PSBT builders ──────────────────────────────────────────────────── *)

(* A trivial P2PKH-ish scriptPubKey, content irrelevant to these tests. *)
let spk (tag : int) : Cstruct.t =
  let s = Cstruct.create 4 in
  for i = 0 to 3 do Cstruct.set_uint8 s i ((tag + i) land 0xff) done;
  s

let mk_input ?(script_sig = Cstruct.empty) txid_hex vout =
  Types.{ previous_output = { txid = hash256_of_hex txid_hex; vout };
          script_sig; sequence = 0xFFFFFFFFl }

let mk_output value tag = Types.{ value; script_pubkey = spk tag }

let mk_tx ~(version : int32) ~(locktime : int32)
    ~(inputs : Types.tx_in list) ~(outputs : Types.tx_out list)
    : Types.transaction =
  { Types.version; inputs; outputs; witnesses = []; locktime }

let tx_to_hex (tx : Types.transaction) : string =
  let w = Serialize.writer_create () in
  Serialize.serialize_transaction w tx;
  let cs = Serialize.writer_to_cstruct w in
  let b = Buffer.create (Cstruct.length cs * 2) in
  for i = 0 to Cstruct.length cs - 1 do
    Buffer.add_string b (Printf.sprintf "%02x" (Cstruct.get_uint8 cs i))
  done;
  Buffer.contents b

(* Build a base64 PSBT directly from a transaction (Creator role). *)
let psbt_b64_of_tx (tx : Types.transaction) : string =
  Psbt.to_base64 (Psbt.create tx)

let txid_a = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
let txid_b = "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098"
let txid_c = "1111111111111111111111111111111111111111111111111111111111111111"

let expect_string = function
  | `String s -> s
  | other ->
    Alcotest.failf "expected JSON string, got %s" (Yojson.Safe.to_string other)

(* Canonical key for an outpoint set-comparison: reversed txid hex + ":" + n. *)
let outpoint_key (op : Types.outpoint) : string =
  Printf.sprintf "%s:%ld" (Types.hash256_to_hex_display op.txid) op.vout

(* Canonical key for an output: value + hex(scriptPubKey). *)
let output_key (o : Types.tx_out) : string =
  let b = Buffer.create 16 in
  for i = 0 to Cstruct.length o.script_pubkey - 1 do
    Buffer.add_string b (Printf.sprintf "%02x" (Cstruct.get_uint8 o.script_pubkey i))
  done;
  Printf.sprintf "%Ld:%s" o.value (Buffer.contents b)

let sset l = List.sort_uniq compare l

(* ── converttopsbt tests ─────────────────────────────────────────────────── *)

(* scriptSig present, permitsigdata default(false) -> -22 with Core message. *)
let test_converttopsbt_sigdata_rejects () =
  let ctx = make_ctx () in
  let tx = mk_tx ~version:2l ~locktime:0l
      ~inputs:[ mk_input ~script_sig:(Cstruct.of_string "\x47sig") txid_a 0l ]
      ~outputs:[ mk_output 9_000_000L 1 ] in
  let hex = tx_to_hex tx in
  (match Rpc.dispatch_rpc ctx "converttopsbt" [`String hex] with
   | Error (code, msg) ->
     Alcotest.(check int) "converttopsbt sigdata code = -22" (-22) code;
     Alcotest.(check string) "converttopsbt sigdata message"
       "Inputs must not have scriptSigs and scriptWitnesses" msg
   | Ok _ -> Alcotest.fail "expected converttopsbt to reject sig data without permit")

(* permitsigdata=true strips sigs; result PSBT round-trips a cleared tx with
   blank input/output maps. *)
let test_converttopsbt_permitsigdata_blank_maps () =
  let ctx = make_ctx () in
  let tx = mk_tx ~version:2l ~locktime:7l
      ~inputs:[ mk_input ~script_sig:(Cstruct.of_string "\x47sig") txid_a 0l ]
      ~outputs:[ mk_output 9_000_000L 1; mk_output 1_000_000L 2 ] in
  let hex = tx_to_hex tx in
  let r = Rpc.dispatch_rpc ctx "converttopsbt" [`String hex; `Bool true] in
  Alcotest.(check bool) "converttopsbt permit ok" true (Result.is_ok r);
  let b64 = expect_string (Result.get_ok r) in
  match Psbt.of_base64 b64 with
  | Error e -> Alcotest.failf "round-trip decode failed: %s" (Psbt.string_of_error e)
  | Ok p ->
    (* scriptSig cleared in the unsigned tx. *)
    List.iter (fun (i : Types.tx_in) ->
      Alcotest.(check int) "scriptSig cleared" 0 (Cstruct.length i.script_sig))
      p.tx.inputs;
    (* version/locktime preserved. *)
    Alcotest.(check int32) "version preserved" 2l p.tx.version;
    Alcotest.(check int32) "locktime preserved" 7l p.tx.locktime;
    (* one blank input map, two blank output maps. *)
    Alcotest.(check int) "1 psbt input" 1 (List.length p.inputs);
    Alcotest.(check int) "2 psbt outputs" 2 (List.length p.outputs);
    let blank_in (i : Psbt.psbt_input) =
      i.non_witness_utxo = None && i.witness_utxo = None && i.partial_sigs = []
      && i.redeem_script = None && i.bip32_derivations = []
      && i.final_scriptsig = None && i.unknown = [] in
    let blank_out (o : Psbt.psbt_output) =
      o.redeem_script = None && o.witness_script = None
      && o.bip32_derivations = [] && o.unknown = [] in
    Alcotest.(check bool) "blank input map" true (List.for_all blank_in p.inputs);
    Alcotest.(check bool) "blank output maps" true (List.for_all blank_out p.outputs)

(* ── joinpsbts tests ─────────────────────────────────────────────────────── *)

(* Fewer than 2 PSBTs -> -8 with Core message. *)
let test_joinpsbts_fewer_than_two () =
  let ctx = make_ctx () in
  let tx = mk_tx ~version:1l ~locktime:0l
      ~inputs:[ mk_input txid_a 0l ] ~outputs:[ mk_output 5_000_000L 1 ] in
  let one = psbt_b64_of_tx tx in
  let check_reject params label =
    match Rpc.dispatch_rpc ctx "joinpsbts" params with
    | Error (code, msg) ->
      Alcotest.(check int) (label ^ " code = -8") (-8) code;
      Alcotest.(check string) (label ^ " message")
        "At least two PSBTs are required to join PSBTs." msg
    | Ok _ -> Alcotest.failf "%s: expected joinpsbts to reject" label
  in
  check_reject [`List []] "zero psbts";
  check_reject [`List [`String one]] "one psbt"

(* Duplicate input prevout across two PSBTs -> -8 with Core message. *)
let test_joinpsbts_duplicate_input () =
  let ctx = make_ctx () in
  let dup_in = mk_input txid_a 3l in
  let p1 = psbt_b64_of_tx
      (mk_tx ~version:1l ~locktime:0l ~inputs:[ dup_in ]
         ~outputs:[ mk_output 5_000_000L 1 ]) in
  let p2 = psbt_b64_of_tx
      (mk_tx ~version:1l ~locktime:0l ~inputs:[ mk_input txid_a 3l ]
         ~outputs:[ mk_output 4_000_000L 2 ]) in
  match Rpc.dispatch_rpc ctx "joinpsbts" [`List [`String p1; `String p2]] with
  | Error (code, msg) ->
    Alcotest.(check int) "dup-input code = -8" (-8) code;
    let expected =
      Printf.sprintf "Input %s:3 exists in multiple PSBTs"
        (Types.hash256_to_hex_display (Types.hash256_of_hex txid_a)) in
    Alcotest.(check string) "dup-input message" expected msg
  | Ok _ -> Alcotest.fail "expected joinpsbts to reject duplicate input"

(* Joining 2 distinct PSBTs yields the UNION of inputs+outputs (compared as
   sets, since Core shuffles) with max(version) + min(locktime). *)
let test_joinpsbts_union_sets () =
  let ctx = make_ctx () in
  (* PSBT 1: version 2, locktime 500, inputs {A:0, B:1}, outputs {o-tag10, o-tag11} *)
  let tx1 = mk_tx ~version:2l ~locktime:500l
      ~inputs:[ mk_input txid_a 0l; mk_input txid_b 1l ]
      ~outputs:[ mk_output 1_000_000L 10; mk_output 2_000_000L 11 ] in
  (* PSBT 2: version 3, locktime 100, inputs {C:2}, outputs {o-tag20} *)
  let tx2 = mk_tx ~version:3l ~locktime:100l
      ~inputs:[ mk_input txid_c 2l ]
      ~outputs:[ mk_output 3_000_000L 20 ] in
  let p1 = psbt_b64_of_tx tx1 in
  let p2 = psbt_b64_of_tx tx2 in
  let r = Rpc.dispatch_rpc ctx "joinpsbts" [`List [`String p1; `String p2]] in
  Alcotest.(check bool) "join ok" true (Result.is_ok r);
  let joined = expect_string (Result.get_ok r) in
  match Psbt.of_base64 joined with
  | Error e -> Alcotest.failf "joined decode failed: %s" (Psbt.string_of_error e)
  | Ok p ->
    (* max version (3) + min locktime (100). *)
    Alcotest.(check int32) "best version = max" 3l p.tx.version;
    Alcotest.(check int32) "best locktime = min" 100l p.tx.locktime;
    (* input SET == union of all three prevouts. *)
    let got_inputs =
      sset (List.map (fun (i : Types.tx_in) -> outpoint_key i.previous_output)
              p.tx.inputs) in
    let want_inputs =
      sset (List.concat_map (fun (tx : Types.transaction) ->
              List.map (fun (i : Types.tx_in) -> outpoint_key i.previous_output)
                tx.inputs) [tx1; tx2]) in
    Alcotest.(check int) "input count = 3" 3 (List.length p.tx.inputs);
    Alcotest.(check (list string)) "input SET = union" want_inputs got_inputs;
    Alcotest.(check int) "psbt input maps parallel" 3 (List.length p.inputs);
    (* output SET == union of all three outputs. *)
    let got_outputs = sset (List.map output_key p.tx.outputs) in
    let want_outputs =
      sset (List.concat_map (fun (tx : Types.transaction) ->
              List.map output_key tx.outputs) [tx1; tx2]) in
    Alcotest.(check int) "output count = 3" 3 (List.length p.tx.outputs);
    Alcotest.(check (list string)) "output SET = union" want_outputs got_outputs;
    Alcotest.(check int) "psbt output maps parallel" 3 (List.length p.outputs)

(* A decode failure is routed as RPC_DESERIALIZATION_ERROR (-22). *)
let test_joinpsbts_decode_failure () =
  let ctx = make_ctx () in
  let tx = mk_tx ~version:1l ~locktime:0l
      ~inputs:[ mk_input txid_a 0l ] ~outputs:[ mk_output 5_000_000L 1 ] in
  let good = psbt_b64_of_tx tx in
  match Rpc.dispatch_rpc ctx "joinpsbts"
          [`List [`String good; `String "not-a-valid-psbt!!"]] with
  | Error (code, msg) ->
    Alcotest.(check int) "decode-failure code = -22" (-22) code;
    Alcotest.(check bool) "decode-failure message prefix" true
      (String.length msg >= 16 && String.sub msg 0 16 = "TX decode failed")
  | Ok _ -> Alcotest.fail "expected joinpsbts to reject undecodable PSBT"

let () =
  Random.self_init ();
  Alcotest.run "w142_joinpsbts" [
    "converttopsbt", [
      Alcotest.test_case "sigdata-without-permit -> -22" `Quick
        test_converttopsbt_sigdata_rejects;
      Alcotest.test_case "permitsigdata -> blank maps" `Quick
        test_converttopsbt_permitsigdata_blank_maps;
    ];
    "joinpsbts", [
      Alcotest.test_case "fewer-than-2 -> -8" `Quick
        test_joinpsbts_fewer_than_two;
      Alcotest.test_case "duplicate-input -> -8" `Quick
        test_joinpsbts_duplicate_input;
      Alcotest.test_case "union of inputs+outputs (sets)" `Quick
        test_joinpsbts_union_sets;
      Alcotest.test_case "decode-failure -> -22" `Quick
        test_joinpsbts_decode_failure;
    ];
  ]
