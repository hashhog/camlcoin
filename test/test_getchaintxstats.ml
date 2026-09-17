(* getchaintxstats: stored m_chain_tx_count + concurrent RPC.

   CONTROL: `dune exec --no-buffer test/test_getchaintxstats.exe`

   Live 2026-09-17 on deployed dd22e29 (same tip as Core):
     txcount 105,278,774 vs Core 1,441,172,939, 80 s vs 0.01 s.
     window_* matched; only the all-time total was wrong because
     chain_tx_count_at_height walked 0..height summing a sparse ntx
     index (historical block bodies are not in the CF).
   Core keeps m_chain_tx_count on CBlockIndex (chain.h), assigned at
   connect (validation.cpp). This control:
     1. stores the cumulative, deletes ntx/bodies, asserts txcount
        equals the true sum at the tip and three earlier heights
     2. asserts the call returns in under a second on a tall chain
     3. issues a deliberately slow RPC and asserts concurrent
        getblockcount returns in under a second *)

open Camlcoin

let with_ctx network f =
  Test_tmp.with_chaindb (fun db ->
      let utxo = Utxo.UtxoSet.create db in
      let mp =
        Mempool.create ~network ~require_standard:false ~verify_scripts:false
          ~utxo ~current_height:0 ()
      in
      let chain = Sync.create_chain_state db network in
      let ctx : Rpc.rpc_context =
        {
          chain;
          mempool = mp;
          peer_manager = Peer_manager.create network;
          wallet = None;
          wallet_manager = None;
          fee_estimator = Fee_estimation.create ();
          network;
          filter_index = None;
          utxo = None;
          data_dir = None;
          snapshot_activation = None;
        }
      in
      f ctx)

let assoc = function
  | `Assoc fields -> fields
  | j -> Alcotest.failf "expected object, got %s" (Yojson.Safe.to_string j)

let field_int fields name =
  match List.assoc_opt name fields with
  | Some (`Int n) -> n
  | Some (`Intlit s) -> int_of_string s
  | Some j ->
    Alcotest.failf "%s: expected int, got %s" name (Yojson.Safe.to_string j)
  | None -> Alcotest.failf "missing field %s" name

let rpc_ok ctx method_name params =
  match Rpc.dispatch_rpc ctx method_name params with
  | Ok j -> j
  | Error (c, m) -> Alcotest.failf "%s: error (%d) %s" method_name c m

let json_req method_name params : Yojson.Safe.t =
  `Assoc
    [
      ("jsonrpc", `String "1.0");
      ("id", `String "t");
      ("method", `String method_name);
      ("params", `List params);
    ]

let hash_of_height (h : int) : Types.hash256 =
  let cs = Cstruct.create 32 in
  Cstruct.LE.set_uint32 cs 0 (Int32.of_int h);
  Cstruct.set_uint8 cs 4 0xC1;
  cs

(* nTx at height h is (h+1); cumulative is the triangle (h+1)(h+2)/2. *)
let ntx_at h = h + 1
let cum_at h = (h + 1) * (h + 2) / 2

let plant_chain (ctx : Rpc.rpc_context) ~(tip_height : int) : Types.hash256 array
    =
  let genesis =
    match Sync.get_header_at_height ctx.chain 0 with
    | Some e -> e
    | None -> (
      match ctx.chain.Sync.tip with
      | Some e -> e
      | None -> Alcotest.fail "no genesis")
  in
  let hashes = Array.make (tip_height + 1) genesis.Sync.hash in
  Storage.ChainDB.store_chain_tx_count ctx.chain.db genesis.hash
    (Int64.of_int (cum_at 0));
  let prev_hash = ref genesis.hash in
  let prev_hdr = ref genesis.header in
  for h = 1 to tip_height do
    let hash = hash_of_height h in
    hashes.(h) <- hash;
    let header =
      {
        !prev_hdr with
        Types.prev_block = !prev_hash;
        timestamp = Int32.add !prev_hdr.Types.timestamp 600l;
      }
    in
    let entry : Sync.header_entry =
      {
        header;
        hash;
        height = h;
        total_work = genesis.total_work;
      }
    in
    Hashtbl.replace ctx.chain.Sync.headers (Cstruct.to_string hash) entry;
    Storage.ChainDB.set_height_hash ctx.chain.db h hash;
    Storage.ChainDB.store_chain_tx_count ctx.chain.db hash
      (Int64.of_int (cum_at h));
    prev_hash := hash;
    prev_hdr := header
  done;
  let tip_hash = hashes.(tip_height) in
  ctx.chain.Sync.blocks_synced <- tip_height;
  ctx.chain.Sync.headers_synced <- tip_height;
  ctx.chain.Sync.tip <-
    Hashtbl.find_opt ctx.chain.Sync.headers (Cstruct.to_string tip_hash);
  Storage.ChainDB.set_chain_tip ctx.chain.db tip_hash tip_height;
  Storage.ChainDB.set_header_tip ctx.chain.db tip_hash tip_height;
  hashes

let display hash = Types.hash256_to_hex_display hash

(* ---- 1. txcount equals the true cumulative even with no ntx/bodies ---- *)

let test_txcount_from_stored_cumulative () =
  with_ctx Consensus.regtest (fun ctx ->
      let hashes = plant_chain ctx ~tip_height:7 in
      (* Historical heights spanning the chain, plus the tip — the live
         control asked for tip + three historicals against Core. Here the
         oracle is the triangle formula Core uses at connect
         (nTx + parent.m_chain_tx_count). *)
      let check ~label height nblocks =
        let params =
          match nblocks with
          | None -> []
          | Some n ->
            [ `Int n; `String (display hashes.(height)) ]
        in
        let fields = assoc (rpc_ok ctx "getchaintxstats" params) in
        Alcotest.(check int)
          (label ^ " txcount") (cum_at height) (field_int fields "txcount")
      in
      (* nblocks must be in [0, height-1] (Core blockchain.cpp:1868). *)
      check ~label:"height 1" 1 (Some 0);
      check ~label:"height 4" 4 (Some 1);
      check ~label:"height 6" 6 (Some 1);
      check ~label:"tip" 7 None;
      let fields =
        assoc
          (rpc_ok ctx "getchaintxstats"
             [ `Int 3; `String (display hashes.(7)) ])
      in
      Alcotest.(check int) "window_tx_count" 21
        (field_int fields "window_tx_count");
      Alcotest.(check int) "window nTx 6+7+8" 21
        (ntx_at 5 + ntx_at 6 + ntx_at 7))

(* ---- 2. O(1) read, not a 0..height walk ---- *)

let latency_heights = 25_000

let test_call_under_one_second () =
  with_ctx Consensus.regtest (fun ctx ->
      let hashes = plant_chain ctx ~tip_height:latency_heights in
      let t0 = Unix.gettimeofday () in
      let fields =
        assoc
          (rpc_ok ctx "getchaintxstats"
             [ `Int 1; `String (display hashes.(latency_heights)) ])
      in
      let dt = Unix.gettimeofday () -. t0 in
      Alcotest.(check int) "tall-chain txcount"
        (cum_at latency_heights)
        (field_int fields "txcount");
      Alcotest.(check bool)
        (Printf.sprintf "getchaintxstats at height %d in < 1s (took %.3fs)"
           latency_heights dt)
        true (dt < 1.0))

(* ---- 3. one slow RPC must not block getblockcount ---- *)

let check_fast_getblockcount fast_r dt =
  (match fast_r with
  | `Assoc fields -> (
    match List.assoc_opt "result" fields with
    | Some (`Int n) -> Alcotest.(check int) "getblockcount result" 3 n
    | Some j ->
      Alcotest.failf "getblockcount result %s" (Yojson.Safe.to_string j)
    | None -> Alcotest.fail "getblockcount missing result")
  | j ->
    Alcotest.failf "getblockcount envelope %s" (Yojson.Safe.to_string j));
  Alcotest.(check bool)
    (Printf.sprintf "getblockcount during slow RPC in < 1s (took %.3fs)" dt)
    true (dt < 1.0)

let test_concurrent_getblockcount () =
  with_ctx Consensus.regtest (fun ctx ->
      ignore (plant_chain ctx ~tip_height:3);
      Rpc.test_sync_sleep_s := 2.0;
      Fun.protect
        ~finally:(fun () -> Rpc.test_sync_sleep_s := 0.0)
        (fun () ->
          let t0 = Unix.gettimeofday () in
          let slow = Rpc.handle_single_request_lwt ctx (json_req "help" []) in
          let fast =
            Rpc.handle_single_request_lwt ctx (json_req "getblockcount" [])
          in
          Lwt_main.run
            (Lwt.bind fast (fun fast_r ->
                 check_fast_getblockcount fast_r (Unix.gettimeofday () -. t0);
                 Lwt.bind slow (fun _ -> Lwt.return_unit)))))

let () =
  Alcotest.run "getchaintxstats stored cumulative + concurrent RPC"
    [
      ( "txcount",
        [
          Alcotest.test_case "stored cumulative at tip and historicals" `Quick
            test_txcount_from_stored_cumulative;
        ] );
      ( "latency",
        [
          Alcotest.test_case "call returns in under a second" `Slow
            test_call_under_one_second;
        ] );
      ( "concurrent",
        [
          Alcotest.test_case "slow RPC does not block getblockcount" `Slow
            test_concurrent_getblockcount;
        ] );
    ]
