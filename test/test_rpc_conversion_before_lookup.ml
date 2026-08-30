(* The integer CONVERSION runs before the lookup, and disconnectnode accepts
   Core's by-nodeid spelling.

   #81 fixed the arguments camlcoin ACCEPTED out of range.  This is the other
   half: arguments camlcoin REJECTED, but with the wrong error, because the
   width check ran after -- or instead of -- the conversion.  Measured against
   a regtest Core oracle (tools/rpc-arg-differential.py): 16 findings, all four
   hostile widths on each of

     getblock <hash> <verbosity>   -> -5 "Block not found"              (Core -1)
     getrawtransaction <t> <verb>  -> -5 "No such mempool or ..."       (Core -1)
     getchaintxstats <nblocks>     -> -8 "Invalid block count..."       (Core -1)
     disconnectnode ["", <id>]     -> -32602 "expected [address] or ..."(Core -29)

   Core's UniValue::getInt<T> runs std::from_chars INTO THE DESTINATION WIDTH,
   so the width check fires inside the conversion and only surviving values
   reach the lookup or the domain test.  OCaml's native int is 63-bit, so the
   hostile value arrived INTACT and the handler carried it into a lookup Core
   never performs.

   getrawtransaction was the worst of the three.  Its parse_verbosity returns
   None for anything outside [0,2] and the caller did
   `Option.value ~default:0` -- so an out-of-int32 verbosity was silently READ
   AS 0 and the lookup ran anyway.  An argument read and then discarded.

   disconnectnode already had a by-id arm, but only for the BARE [id] form.
   Core documents two spellings -- "either set `address` to the empty string,
   or call using the named `nodeid` argument only" -- and refused both
   two-argument ones with -32602.  Any Core client sends a two-argument call.

   TEETH: a handler that rejected everything would satisfy every rejection
   assertion here, so each group carries a CONTROL that must reach the REAL
   answer (-5 for an absent block, -8 for an in-range illegal nblocks, -29 for
   an unconnected address). *)

open Camlcoin

let test_db_path = "/tmp/camlcoin_conv_before_lookup_test_db"

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
let absent_hash = "00000000000000000000000000000000000000000000000000000000000000ff"

(* Drive the REAL dispatcher: the handler returns a bare string for getblock /
   getrawtransaction and the dispatch arm maps it to a numeric code, so a test
   that called the handler directly would not see the code that reaches the
   wire -- which is exactly where the -5-vs--1 mapping lives. *)
let dispatch (method_name : string) (params : Yojson.Safe.t list) =
  let ctx, _db = create_test_context () in
  Rpc.dispatch_rpc ctx method_name params

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

let expect_code ~code method_name params () =
  match dispatch method_name params with
  | Ok _ ->
    Alcotest.failf "%s %s was ACCEPTED; expected code %d"
      method_name (Yojson.Safe.to_string (`List params)) code
  | Error (c, m) ->
    Alcotest.(check int) (method_name ^ " code (msg was: " ^ m ^ ")") code c

let case name f = Alcotest.test_case name `Quick f

let getblock_cases =
  List.map
    (fun v ->
      case (Printf.sprintf "getblock verbosity %d -> -1, not -5" v)
        (expect_range_error "getblock" [ `String absent_hash; `Int v ]))
    out_of_int32

let getrawtransaction_cases =
  List.map
    (fun v ->
      case (Printf.sprintf "getrawtransaction verbosity %d -> -1, not -5" v)
        (expect_range_error "getrawtransaction" [ `String txid_hex; `Int v ]))
    out_of_int32

let getchaintxstats_cases =
  List.map
    (fun v ->
      case (Printf.sprintf "getchaintxstats nblocks %d -> -1, not -8" v)
        (expect_range_error "getchaintxstats" [ `Int v ]))
    out_of_int32

let disconnectnode_cases =
  List.map
    (fun v ->
      case (Printf.sprintf "disconnectnode [\"\", %d] -> -29, not -32602" v)
        (expect_error ~code:(-29) ~msg:"Node not found in connected nodes"
           "disconnectnode" [ `String ""; `Int v ]))
    (0 :: 99 :: (-1) :: out_of_int32)

let disconnectnode_null_form =
  case "disconnectnode [null, id] is the same by-id call"
    (expect_error ~code:(-29) ~msg:"Node not found in connected nodes"
       "disconnectnode" [ `Null; `Int 7 ])

let disconnectnode_both =
  case "disconnectnode with BOTH address and nodeid -> Core's -32602"
    (expect_error ~code:(-32602)
       ~msg:"Only one of address and nodeid should be provided."
       "disconnectnode" [ `String "1.2.3.4:8333"; `Int 0 ])

(* CONTROLS: the real answers must still be reachable. *)
let control_getblock_absent =
  case "CONTROL an absent-but-well-formed hash still reaches -5 Block not found"
    (expect_error ~code:(-5) ~msg:"Block not found" "getblock"
       [ `String absent_hash; `Int 1 ])

let control_getchaintxstats_domain =
  case "CONTROL an in-range illegal nblocks still reaches the -8 domain error"
    (expect_error ~code:(-8)
       ~msg:"Invalid block count: should be between 0 and the block's height - 1"
       "getchaintxstats" [ `Int (-1) ])

let control_getrawtransaction_lookup =
  case "CONTROL an in-range verbosity still reaches the -5 lookup miss"
    (expect_code ~code:(-5) "getrawtransaction" [ `String txid_hex; `Int 1 ])

let control_disconnectnode_by_address =
  case "CONTROL by-address still reaches -29, not a param-shape error"
    (expect_error ~code:(-29) ~msg:"Node not found in connected nodes"
       "disconnectnode" [ `String "192.0.2.99:8333" ])

let () =
  Alcotest.run "rpc_conversion_before_lookup"
    [ ("getblock_verbosity", getblock_cases);
      ("getrawtransaction_verbosity", getrawtransaction_cases);
      ("getchaintxstats_nblocks", getchaintxstats_cases);
      ("disconnectnode_nodeid",
       disconnectnode_cases @ [ disconnectnode_null_form; disconnectnode_both ]);
      ("CONTROLS",
       [ control_getblock_absent; control_getchaintxstats_domain;
         control_getrawtransaction_lookup; control_disconnectnode_by_address ]) ]
