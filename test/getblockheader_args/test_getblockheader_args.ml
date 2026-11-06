open Camlcoin

let with_ctx f =
  Test_tmp.with_chaindb (fun db ->
      let utxo = Utxo.UtxoSet.create db in
      let mp =
        Mempool.create ~network:Consensus.regtest ~require_standard:false
          ~verify_scripts:false ~utxo ~current_height:0 ()
      in
      let chain = Sync.create_chain_state db Consensus.regtest in
      let ctx : Rpc.rpc_context =
        {
          chain;
          mempool = mp;
          peer_manager = Peer_manager.create Consensus.regtest;
          wallet = None;
          wallet_manager = None;
          fee_estimator = Fee_estimation.create ();
          network = Consensus.regtest;
          filter_index = None;
          utxo = None;
          data_dir = None;
          snapshot_activation = None;
        }
      in
      f ctx)

let call ctx params = Rpc.dispatch_rpc ctx "getblockheader" params

let check_err what (c, m) = function
  | Error (c', m') ->
    Alcotest.(check int) (what ^ " code") c c';
    Alcotest.(check string) (what ^ " message") m m'
  | Ok j ->
    Alcotest.failf "%s: expected error, got %s" what (Yojson.Safe.to_string j)

let zeros = String.make 64 '0'

(* Core getblockheader names its first argument "hash", so ParseHashV says
   "hash must be of length 64 ..." (operator/getblockheader/short-hash). *)
let test_short_hash () =
  with_ctx (fun ctx ->
      check_err "short-hash"
        (-8, "hash must be of length 64 (not 2, for '00')")
        (call ctx [ `String "00" ]))

let test_bad_hex () =
  with_ctx (fun ctx ->
      let z = String.make 64 'z' in
      check_err "bad-hex"
        (-8, Printf.sprintf "hash must be hexadecimal string (not '%s')" z)
        (call ctx [ `String z ]))

(* Core RPCTypeCheck: -3 "Wrong type passed" for a non-bool verbose
   (operator/getblockheader/bad-verbose). *)
let test_bad_verbose () =
  with_ctx (fun ctx ->
      check_err "bad-verbose"
        (-3,
         "Wrong type passed:\n{\n    \"Position 2 (verbose)\": \"JSON value of type string is not of expected type bool\"\n}")
        (call ctx [ `String zeros; `String "x" ]))

(* A type error wins over the hash lookup, as Core checks types first. *)
let test_type_before_lookup () =
  with_ctx (fun ctx ->
      check_err "type-before-lookup"
        (-3,
         "Wrong type passed:\n{\n    \"Position 2 (verbose)\": \"JSON value of type number is not of expected type bool\"\n}")
        (call ctx [ `String zeros; `Int 1 ]))

(* Control: a well-formed absent hash with a good verbose still answers -5. *)
let test_absent_hash () =
  with_ctx (fun ctx ->
      check_err "absent" (-5, "Block not found")
        (call ctx [ `String zeros; `Bool true ]);
      check_err "absent null verbose" (-5, "Block not found")
        (call ctx [ `String zeros; `Null ]))

let () =
  Alcotest.run "getblockheader_args"
    [ ("getblockheader", [
          Alcotest.test_case "short hash" `Quick test_short_hash;
          Alcotest.test_case "bad hex" `Quick test_bad_hex;
          Alcotest.test_case "bad verbose" `Quick test_bad_verbose;
          Alcotest.test_case "type before lookup" `Quick test_type_before_lookup;
          Alcotest.test_case "absent hash" `Quick test_absent_hash ]) ]
