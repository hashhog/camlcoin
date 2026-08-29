(* RPC integer arguments must be read at CORE'S WIDTH -- and honoured
   ============================================================================

   THE DEFECT (pinned by this suite)
   ---------------------------------
   Core reads every numeric RPC argument through [UniValue::getInt<T>()]
   (univalue.h), which runs std::from_chars INTO THE DESTINATION WIDTH.  The
   width check therefore lives INSIDE the conversion and fires BEFORE the
   handler's own domain test:

     out of width / fractional  ->  RPC_MISC_ERROR (-1) "JSON integer out of
                                    range"   (rpc/server.cpp:514-515)
     converts, violates range   ->  RPC_INVALID_PARAMETER (-8)

   OCaml's native int is 63-bit, so a hostile JSON integer arrives INTACT --
   but [Int32.of_int] WRAPS SILENTLY, and that is what the chainstate height
   key is written with (cf_chainstate.ml encode_height).  Measured against a
   regtest Bitcoin Core oracle (tools/rpc-arg-differential.py), camlcoin
   ACCEPTED 15 arguments Core refuses, including:

     getblockhash 4294967296  ->  encode_height wrapped it to 0 and the node
                                  answered with the GENESIS HASH, as success.
     createpsbt locktime 2^32 ->  [Int32.of_int lt] wrapped to 0l and the node
                                  returned a PSBT with locktime 0.
     estimatesmartfee 2^31    ->  answered for a target it had not been asked
                                  about.
     gettxout vout -1 / 2^32  ->  answered `null` (a legitimate-looking "no
                                  such output") for an argument Core rejects
                                  outright -- it reads n as getInt<uint32_t>,
                                  which accepts no sign at all.

   TEETH
   -----
   Every case here is a rejection, and a handler that rejected EVERYTHING would
   satisfy all of them.  The CONTROLS make that impossible: they drive the real
   handlers to SUCCESS at the boundary values (int32 max, uint32 max, locktime
   LOCKTIME_MAX, conf_target 1 and 1008, the three fee modes) and assert the
   answer, so a bound that is off by one in the tight direction fails loudly.

   References:
     bitcoin-core/src/univalue/include/univalue.h        getInt<Int>
     bitcoin-core/src/rpc/util.cpp                       ParseConfirmTarget
     bitcoin-core/src/rpc/net.cpp                        getnodeaddresses count
     bitcoin-core/src/rpc/blockchain.cpp                 gettxout n (uint32)
     bitcoin-core/src/common/messages.cpp                FeeModeFromString
     bitcoin-core/src/rpc/rawtransaction_util.cpp        ConstructTransaction *)

open Camlcoin

let test_db_path = "/tmp/camlcoin_int_arg_bounds_test_db"

let rec rm_rf path =
  if Sys.file_exists path then begin
    if Sys.is_directory path then begin
      Array.iter (fun f -> rm_rf (Filename.concat path f)) (Sys.readdir path);
      Unix.rmdir path
    end else Unix.unlink path
  end

let create_test_context () =
  rm_rf test_db_path;
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

let out_of_int32 = [ 2147483648; -2147483649; 4294967296; -4294967297 ]

let txid_hex = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"

(* Drive the REAL dispatcher, so the assertions cover the code that reaches the
   wire -- including the dispatch-level mapping from a handler's string error
   to Core's numeric code. *)
let dispatch (method_name : string) (params : Yojson.Safe.t list) =
  let ctx, _db = create_test_context () in
  Rpc.dispatch_rpc ctx method_name params

(* The wait family lives on the Lwt dispatcher (dispatch_wait_rpc), not the
   synchronous one -- routing them through dispatch_rpc would score -32601
   "method not found" and prove nothing. *)
let dispatch_wait (method_name : string) (params : Yojson.Safe.t list) =
  let ctx, _db = create_test_context () in
  match Rpc.dispatch_wait_rpc ctx method_name params with
  | None -> Error (-32601, "Method not found: " ^ method_name)
  | Some t -> Lwt_main.run t

let expect_wait_error ~code ~msg method_name params () =
  match dispatch_wait method_name params with
  | Ok _ ->
    Alcotest.failf "%s %s was ACCEPTED; expected (%d, %S)"
      method_name (Yojson.Safe.to_string (`List params)) code msg
  | Error (c, m) ->
    Alcotest.(check int) (method_name ^ " code") code c;
    Alcotest.(check string) (method_name ^ " message") msg m

let expect_wait_range_error method_name params () =
  expect_wait_error ~code:(-1) ~msg:"JSON integer out of range" method_name
    params ()

let expect_error ~code ~msg method_name params () =
  match dispatch method_name params with
  | Ok _ ->
    Alcotest.failf "%s %s was ACCEPTED; expected (%d, %S)"
      method_name (Yojson.Safe.to_string (`List params)) code msg
  | Error (c, m) ->
    Alcotest.(check int) (method_name ^ " code") code c;
    Alcotest.(check string) (method_name ^ " message") msg m

let expect_range_error method_name params () =
  expect_error ~code:(-1) ~msg:"JSON integer out of range" method_name params ()

let expect_ok method_name params () =
  match dispatch method_name params with
  | Ok _ -> ()
  | Error (c, m) ->
    Alcotest.failf "%s %s was REJECTED (%d, %S); expected success"
      method_name (Yojson.Safe.to_string (`List params)) c m

(* --------------------------------------------------------------- wait family *)

let wait_cases =
  List.concat_map
    (fun v ->
       [ Alcotest.test_case
           (Printf.sprintf "waitforblockheight height %d -> -1" v) `Quick
           (expect_wait_range_error "waitforblockheight" [ `Int v ]);
         Alcotest.test_case
           (Printf.sprintf "waitforblockheight timeout %d -> -1" v) `Quick
           (expect_wait_range_error "waitforblockheight" [ `Int 1; `Int v ]) ])
    out_of_int32

(* CONTROL for the ORDER: an in-range negative timeout converts fine and
   reaches the handler's own domain message. *)
let control_negative_timeout =
  expect_wait_error ~code:(-1) ~msg:"Negative timeout"
    "waitforblockheight" [ `Int 1; `Int (-1) ]

(* ---------------------------------------------------------- getnodeaddresses *)

let getnodeaddresses_cases =
  List.map
    (fun v ->
       Alcotest.test_case (Printf.sprintf "getnodeaddresses count %d -> -1" v)
         `Quick (expect_range_error "getnodeaddresses" [ `Int v ]))
    out_of_int32

let control_negative_count =
  expect_error ~code:(-8) ~msg:"Address count out of range"
    "getnodeaddresses" [ `Int (-1) ]

(* ------------------------------------------------------------------ gettxout *)

let gettxout_cases =
  List.map
    (fun v ->
       Alcotest.test_case (Printf.sprintf "gettxout n %d -> -1" v) `Quick
         (expect_range_error "gettxout" [ `String txid_hex; `Int v ]))
    [ 4294967296; -1; -2147483649 ]

(* CONTROL: uint32 MAX is inside the width, so it must still reach the lookup
   and answer `null` (no such output) rather than being rejected. *)
let control_gettxout_uint32_max =
  expect_ok "gettxout" [ `String txid_hex; `Int 4294967295 ]

(* -------------------------------------------------------------- getblockhash *)

let getblockhash_cases =
  List.map
    (fun v ->
       Alcotest.test_case (Printf.sprintf "getblockhash height %d -> -1" v)
         `Quick (expect_range_error "getblockhash" [ `Int v ]))
    out_of_int32

(* CONTROL for the WRAP: int32 MAX is inside the width, so it reaches the
   lookup and answers Core's -8, NOT a hash. *)
let control_getblockhash_int32_max =
  expect_error ~code:(-8) ~msg:"Block height out of range"
    "getblockhash" [ `Int 2147483647 ]

(* --------------------------------------------------------- estimatesmartfee *)

let estimatesmartfee_cases =
  List.map
    (fun v ->
       Alcotest.test_case (Printf.sprintf "estimatesmartfee %d -> -1" v) `Quick
         (expect_range_error "estimatesmartfee" [ `Int v ]))
    out_of_int32

let conf_target_domain_cases =
  List.map
    (fun v ->
       Alcotest.test_case
         (Printf.sprintf "estimatesmartfee conf_target %d -> -8" v) `Quick
         (expect_error ~code:(-8)
            ~msg:"Invalid conf_target, must be between 1 and 1008"
            "estimatesmartfee" [ `Int v ]))
    [ 0; -1; 1009; 99999 ]

let estimate_mode_cases =
  List.map
    (fun m ->
       Alcotest.test_case
         (Printf.sprintf "estimatesmartfee estimate_mode %S -> -8" m) `Quick
         (expect_error ~code:(-8)
            (* literal, NOT Rpc.core_estimate_mode_msg: referencing the new
               constant would make this suite fail at the parent commit by
               NOT COMPILING, which proves nothing about behaviour *)
            ~msg:"Invalid estimate_mode parameter, must be one of: \"unset\", \"economical\", \"conservative\"" 
            "estimatesmartfee" [ `Int 6; `String m ]))
    [ ""; "garbage"; "ECONOMICALLY" ]

let estimate_mode_controls =
  List.map
    (fun m ->
       Alcotest.test_case (Printf.sprintf "estimatesmartfee mode %S accepted" m)
         `Quick (expect_ok "estimatesmartfee" [ `Int 6; `String m ]))
    [ "unset"; "economical"; "CONSERVATIVE"; "Economical" ]

let conf_target_boundary_controls =
  List.map
    (fun v ->
       Alcotest.test_case
         (Printf.sprintf "estimatesmartfee conf_target %d accepted" v) `Quick
         (expect_ok "estimatesmartfee" [ `Int v ]))
    [ 1; 6; 1008 ]

(* ----------------------------------------------------------------- createpsbt *)

let createpsbt_locktime_cases =
  List.map
    (fun v ->
       Alcotest.test_case (Printf.sprintf "createpsbt locktime %d -> -8" v)
         `Quick
         (expect_error ~code:(-8) ~msg:"Invalid parameter, locktime out of range"
            "createpsbt" [ `List []; `List []; `Int v ]))
    [ 4294967296; -1; -2147483649 ]

(* CONTROL: LOCKTIME_MAX itself is inside the bound and must still build. *)
let control_createpsbt_locktime_max =
  expect_ok "createpsbt" [ `List []; `List []; `Int 4294967295 ]

let () =
  Alcotest.run "rpc_int_arg_bounds"
    [ ("wait_family", wait_cases);
      ( "wait_family_CONTROLS",
        [ Alcotest.test_case "in-range negative timeout keeps -1 Negative timeout"
            `Quick control_negative_timeout ] );
      ("getnodeaddresses", getnodeaddresses_cases);
      ( "getnodeaddresses_CONTROLS",
        [ Alcotest.test_case "in-range negative count keeps -8" `Quick
            control_negative_count ] );
      ("gettxout", gettxout_cases);
      ( "gettxout_CONTROLS",
        [ Alcotest.test_case "uint32 max still reaches the lookup" `Quick
            control_gettxout_uint32_max ] );
      ("getblockhash", getblockhash_cases);
      ( "getblockhash_CONTROLS",
        [ Alcotest.test_case "int32 max reaches the lookup, answers -8" `Quick
            control_getblockhash_int32_max ] );
      ("estimatesmartfee_width", estimatesmartfee_cases);
      ("estimatesmartfee_domain", conf_target_domain_cases);
      ("estimatesmartfee_mode", estimate_mode_cases);
      ("estimatesmartfee_CONTROLS", estimate_mode_controls
                                    @ conf_target_boundary_controls);
      ("createpsbt_locktime", createpsbt_locktime_cases);
      ( "createpsbt_locktime_CONTROLS",
        [ Alcotest.test_case "LOCKTIME_MAX still builds" `Quick
            control_createpsbt_locktime_max ] ) ]
