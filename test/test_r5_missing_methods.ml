(* R5 missing-method class — Core-validated probe vectors.

   CONTROL: `dune exec --no-buffer test/test_r5_missing_methods.exe`

   Encodes the two T2 methods that live-lane returned -32601 against
   Bitcoin Core (tools/r5-probes.d/chain-analytics.jsonl,
   probe 2026-09-17T05:40Z):

     importmempool bad-path
       ["/nonexistent/r5-probe-no-such-file.dat"]
       -> -1 "Unable to import mempool file, see debug log for details."
       (rpc/mempool.cpp LoadMempool fopen-null -> RPC_MISC_ERROR)
     pruneblockchain height-type-error
       ["zz"]
       -> -3 "JSON value of type string is not of expected type number"
       (UniValue type check fires BEFORE the prune-mode gate)

   Plus help-parity (r5_probe.py samples `help` before each spec) and
   the same-method rejection probes Core would return on a well-typed
   call: IBD -10, unpruned prune -1, negative height -8.

   Dispatch goes through [Rpc.dispatch_rpc]. *)

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

let synced ctx = ctx.Rpc.chain.Sync.sync_state <- Sync.FullySynced

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

(* ============================================================================
   importmempool — tools/r5-probes.d/chain-analytics.jsonl
   ============================================================================ *)

let test_importmempool_bad_path () =
  with_ctx (fun ctx ->
      synced ctx;
      check_err ~label:"importmempool bad-path" ~code:(-1)
        ~msg:"Unable to import mempool file, see debug log for details."
        (Rpc.dispatch_rpc ctx "importmempool"
           [ `String "/nonexistent/r5-probe-no-such-file.dat" ]))

let test_importmempool_type_error () =
  with_ctx (fun ctx ->
      check_err ~label:"importmempool type-error" ~code:(-3)
        ~msg:"JSON value of type number is not of expected type string"
        (Rpc.dispatch_rpc ctx "importmempool" [ `Int 1 ]))

let test_importmempool_ibd () =
  with_ctx (fun ctx ->
      (* Default test chain is mainnet + Idle = IBD. Core checks IBD
         before opening the file (rpc/mempool.cpp:1140). *)
      check_err ~label:"importmempool IBD" ~code:(-10)
        ~msg:
          "Can only import the mempool after the block download and sync is \
           done."
        (Rpc.dispatch_rpc ctx "importmempool"
           [ `String "/nonexistent/r5-probe-no-such-file.dat" ]))

let test_importmempool_success_empty_object () =
  with_ctx (fun ctx ->
      synced ctx;
      Test_tmp.with_dir ~label:"mp" ~mkdir:true (fun dir ->
          let path = Filename.concat dir "mempool.dat" in
          Mempool.save_mempool ctx.mempool path;
          match Rpc.dispatch_rpc ctx "importmempool" [ `String path ] with
          | Error (c, m) -> Alcotest.failf "importmempool: error (%d) %s" c m
          | Ok (`Assoc []) -> ()
          | Ok j ->
            Alcotest.failf "expected empty object, got %s"
              (Yojson.Safe.to_string j)))

let test_importmempool_listed_in_help () =
  with_ctx (fun ctx -> require_help_lists ctx "importmempool")

(* ============================================================================
   pruneblockchain — tools/r5-probes.d/chain-analytics.jsonl
   ============================================================================ *)

let test_pruneblockchain_height_type_error () =
  with_ctx (fun ctx ->
      check_err ~label:"pruneblockchain height-type-error" ~code:(-3)
        ~msg:"JSON value of type string is not of expected type number"
        (Rpc.dispatch_rpc ctx "pruneblockchain" [ `String "zz" ]))

let test_pruneblockchain_unpruned () =
  with_ctx (fun ctx ->
      check_err ~label:"pruneblockchain unpruned" ~code:(-1)
        ~msg:"Cannot prune blocks because node is not in prune mode."
        (Rpc.dispatch_rpc ctx "pruneblockchain" [ `Int 100 ]))

let test_pruneblockchain_negative () =
  with_ctx (fun ctx ->
      ctx.chain.prune_target <- 1;
      check_err ~label:"pruneblockchain negative" ~code:(-8)
        ~msg:"Negative block height."
        (Rpc.dispatch_rpc ctx "pruneblockchain" [ `Int (-1) ]))

let test_pruneblockchain_listed_in_help () =
  with_ctx (fun ctx -> require_help_lists ctx "pruneblockchain")

let () =
  let open Alcotest in
  run "R5 missing methods (Core probe vectors)"
    [
      ( "importmempool",
        [
          test_case "bad-path -> -1" `Quick test_importmempool_bad_path;
          test_case "type-error -> -3" `Quick test_importmempool_type_error;
          test_case "IBD -> -10" `Quick test_importmempool_ibd;
          test_case "success empty object" `Quick
            test_importmempool_success_empty_object;
          test_case "listed in help" `Quick test_importmempool_listed_in_help;
        ] );
      ( "pruneblockchain",
        [
          test_case "height-type-error -> -3" `Quick
            test_pruneblockchain_height_type_error;
          test_case "unpruned -> -1" `Quick test_pruneblockchain_unpruned;
          test_case "negative -> -8" `Quick test_pruneblockchain_negative;
          test_case "listed in help" `Quick test_pruneblockchain_listed_in_help;
        ] );
    ]
