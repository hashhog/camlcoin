(* R5 other/help-rot class — Core-validated probe vectors.

   CONTROL: `dune exec --no-buffer test/test_r5_other.exe`

   Encodes the two leftover T1/T2 methods whose live-lane probe failed
   against Bitcoin Core (tools/r5-probes.d, probe 2026-09-17T05:40Z):

     logging success-shape
       params [[], []]  (pure read)
       fields net/rpc/mempool/validation as bool
       (camlcoin used to emit Logs.Src names NET/RPC/MEMPOOL/VALIDATION)
     logging unknown-category
       [["notacategory"], []] -> -8 "unknown logging category notacategory"
     joinpsbts join-exact
       PSBT_A (1 in / 1 out) + PSBT_B (0 in / same out)
       -> Core's joined base64 (shuffle is byte-invisible: 1 input,
          two identical outputs)
     joinpsbts min-two
       [PSBT_A] -> -8 "At least two PSBTs are required to join PSBTs."

   Help-parity is part of the method score (r5_probe.py samples `help`
   before each spec). joinpsbts was dispatched but unlisted.

   Oracle: live Core v31.99 :8332, 2026-09-17. Dispatch through
   [Rpc.dispatch_rpc]. *)

open Camlcoin

let with_ctx f =
  Test_tmp.with_chaindb (fun db ->
      let utxo = Utxo.UtxoSet.create db in
      let mp =
        Mempool.create ~network:Consensus.mainnet ~require_standard:false
          ~verify_scripts:false ~utxo ~current_height:0 ()
      in
      let chain = Sync.create_chain_state db Consensus.mainnet in
      let ctx : Rpc.rpc_context =
        {
          chain;
          mempool = mp;
          peer_manager = Peer_manager.create Consensus.mainnet;
          wallet = None;
          wallet_manager = None;
          fee_estimator = Fee_estimation.create ();
          network = Consensus.mainnet;
          filter_index = None;
          utxo = None;
          data_dir = None;
          snapshot_activation = None;
        }
      in
      f ctx)

let check_err ~label ~code ?msg result =
  match result with
  | Error (c, m) ->
    Alcotest.(check int) (label ^ ": code") code c;
    (match msg with
    | Some expected -> Alcotest.(check string) (label ^ ": message") expected m
    | None -> ())
  | Ok j ->
    Alcotest.failf "%s: expected error (%d) but got Ok %s" label code
      (Yojson.Safe.to_string j)

let require_help_lists ctx method_name =
  match Rpc.dispatch_rpc ctx "help" [] with
  | Error (c, m) -> Alcotest.failf "help: error (%d) %s" c m
  | Ok (`String s) ->
    (try ignore (Str.search_forward (Str.regexp_string method_name) s 0)
     with Not_found -> Alcotest.fail (method_name ^ " not listed in help"))
  | Ok j ->
    Alcotest.failf "help: expected string, got %s" (Yojson.Safe.to_string j)

let field_bool fields name =
  match List.assoc_opt name fields with
  | Some (`Bool b) -> b
  | Some j ->
    Alcotest.failf "%s: expected bool, got %s" name (Yojson.Safe.to_string j)
  | None -> Alcotest.failf "missing field %s" name

(* ============================================================================
   logging — tools/r5-probes.d/control-network.jsonl
   Core src/rpc/node.cpp logging + src/logging.cpp LOG_CATEGORIES_BY_STR
   ============================================================================ *)

(* Core v31.99 logging [[],[]] keys, minus `lock` (DEBUG_LOCKCONTENTION). *)
let core_logging_keys =
  [
    "addrman";
    "bench";
    "blockstorage";
    "cmpctblock";
    "coindb";
    "estimatefee";
    "http";
    "i2p";
    "ipc";
    "kernel";
    "leveldb";
    "libevent";
    "mempool";
    "mempoolrej";
    "net";
    "privatebroadcast";
    "proxy";
    "prune";
    "qt";
    "rand";
    "reindex";
    "rpc";
    "scan";
    "selectcoins";
    "tor";
    "txpackages";
    "txreconciliation";
    "validation";
    "walletdb";
    "zmq";
  ]

let test_logging_success_shape () =
  with_ctx (fun ctx ->
      match Rpc.dispatch_rpc ctx "logging" [ `List []; `List [] ] with
      | Error (c, m) -> Alcotest.failf "success-shape: error (%d) %s" c m
      | Ok (`Assoc fields) ->
        List.iter
          (fun name -> ignore (field_bool fields name))
          [ "net"; "rpc"; "mempool"; "validation" ];
        List.iter
          (fun name -> ignore (field_bool fields name))
          core_logging_keys
      | Ok j ->
        Alcotest.failf "expected object, got %s" (Yojson.Safe.to_string j))

let test_logging_unknown_category () =
  with_ctx (fun ctx ->
      check_err ~label:"logging unknown-category" ~code:(-8)
        ~msg:"unknown logging category notacategory"
        (Rpc.dispatch_rpc ctx "logging"
           [ `List [ `String "notacategory" ]; `List [] ]))

let test_logging_listed_in_help () =
  with_ctx (fun ctx -> require_help_lists ctx "logging")

(* ============================================================================
   joinpsbts — tools/r5-probes.d/rawtx-psbt.jsonl
   Core src/rpc/rawtransaction.cpp joinpsbts
   ============================================================================ *)

let psbt_a =
  "cHNidP8BAFICAAAAAaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqAAAAAAD9////\
   AaCGAQAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9YAAAAAAAAA"

let psbt_b =
  "cHNidP8BACkCAAAAAAGghgEAAAAAABYAFHUedugZkZbUVJQcRdGzoyPxQzvWAAAAAAAA"

(* Core v31.99 joinpsbts [PSBT_A, PSBT_B], 2026-09-17. Shuffle is
   byte-invisible: one input, two identical outputs. *)
let joined_exact =
  "cHNidP8BAHECAAAAAaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqAAAAAAD9////\
   AqCGAQAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9aghgEAAAAAABYAFHUedugZkZbUVJQc\
   RdGzoyPxQzvWAAAAAAAAAAA="

let test_joinpsbts_join_exact () =
  with_ctx (fun ctx ->
      try
        match
          Rpc.dispatch_rpc ctx "joinpsbts"
            [ `List [ `String psbt_a; `String psbt_b ] ]
        with
        | Error (c, m) -> Alcotest.failf "join-exact: error (%d) %s" c m
        | Ok (`String s) ->
          Alcotest.(check string) "joinpsbts join-exact" joined_exact s
        | Ok j ->
          Alcotest.failf "expected string, got %s" (Yojson.Safe.to_string j)
      with exn ->
        Alcotest.failf "join-exact: exception %s" (Printexc.to_string exn))

let test_joinpsbts_min_two () =
  with_ctx (fun ctx ->
      check_err ~label:"joinpsbts min-two" ~code:(-8)
        ~msg:"At least two PSBTs are required to join PSBTs."
        (Rpc.dispatch_rpc ctx "joinpsbts" [ `List [ `String psbt_a ] ]))

let test_joinpsbts_listed_in_help () =
  with_ctx (fun ctx -> require_help_lists ctx "joinpsbts")

let () =
  let open Alcotest in
  run "R5 other/help-rot (Core probe vectors)"
    [
      ( "logging",
        [
          test_case "success-shape" `Quick test_logging_success_shape;
          test_case "unknown-category -> -8" `Quick
            test_logging_unknown_category;
          test_case "listed in help" `Quick test_logging_listed_in_help;
        ] );
      ( "joinpsbts",
        [
          test_case "join-exact" `Quick test_joinpsbts_join_exact;
          test_case "min-two -> -8" `Quick test_joinpsbts_min_two;
          test_case "listed in help" `Quick test_joinpsbts_listed_in_help;
        ] );
    ]
