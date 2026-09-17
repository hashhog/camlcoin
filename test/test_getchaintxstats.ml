(* getchaintxstats: stored m_chain_tx_count + concurrent RPC.

   CONTROL: `dune exec --no-buffer test/test_getchaintxstats.exe`

   Live 2026-09-17 on deployed dd22e29 (same tip as Core):
     txcount 105,278,774 vs Core 1,441,172,939, 80 s vs 0.01 s.
     window_* matched; only the all-time total was wrong because
     chain_tx_count_at_height walked 0..height summing a sparse ntx
     index (historical block bodies are not in the CF).
   Core keeps m_chain_tx_count on CBlockIndex (chain.h), assigned at
   connect (validation.cpp). 34cd72c stored the cumulative at connect
   and seeded AssumeUTXO bases, but reconstruct still started at the
   nearest lower AU and added 0 for every height without nTx — so a
   BETWEEN-anchor query silently returned the neighbour's value.
   The 944183 hashhog AU carried the 1_334_000_000 placeholder
   (CORE-PARITY-AUDIT/_dual-track-roadmap-2026-05-28.md), 1_914_531
   short of Core's getchaintxstats at that hash (1_335_914_531).
   This control:
     1. stores the cumulative, deletes ntx/bodies, asserts txcount
        equals the true sum at the tip and three earlier heights
     2. asserts the call returns in under a second on a tall chain
     3. issues a deliberately slow RPC and asserts concurrent
        getblockcount returns in under a second
     4. BETWEEN assumeUTXO anchors, missing nTx: must NOT return the
        lower anchor's cumulative (Core omits txcount when unknown)
     5. BETWEEN anchors with nTx: reconstruct parent + nTx, not the
        neighbour
     6. Core's live getchaintxstats at 905k/920k/930k/940k/945k must
        not be served as the lower AU value
     7. 944183 seed is Core 1_335_914_531, not the placeholder *)

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

let txcount_of fields =
  match List.assoc_opt "txcount" fields with
  | Some (`Int n) -> Some n
  | Some (`Intlit s) -> Some (int_of_string s)
  | None -> None
  | Some j -> Alcotest.failf "txcount %s" (Yojson.Safe.to_string j)

let with_extra_regtest_au (p : Assume_utxo.assumeutxo_params) f =
  let prev = !Assume_utxo.regtest_au_data in
  Fun.protect
    ~finally:(fun () -> Assume_utxo.regtest_au_data := prev)
    (fun () ->
      Assume_utxo.register_regtest_assumeutxo p;
      f ())

(* Headers + height index only. No m_chain_tx_count, no nTx — the live
   pre-snapshot shape, where reconstruct used to borrow the AU neighbour. *)
let plant_headers (ctx : Rpc.rpc_context) ~(tip_height : int) : Types.hash256 array
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

let plant_at (ctx : Rpc.rpc_context) ~height hash : unit =
  let genesis =
    match Sync.get_header_at_height ctx.chain 0 with
    | Some e -> e
    | None -> Alcotest.fail "no genesis"
  in
  let header =
    {
      genesis.header with
      Types.prev_block = genesis.hash;
      timestamp = Int32.add genesis.header.timestamp (Int32.of_int height);
    }
  in
  let entry : Sync.header_entry =
    { header; hash; height; total_work = genesis.total_work }
  in
  Hashtbl.replace ctx.chain.Sync.headers (Cstruct.to_string hash) entry;
  Storage.ChainDB.set_height_hash ctx.chain.db height hash

let au_params ~height ~hash ~chain_tx_count : Assume_utxo.assumeutxo_params =
  {
    Assume_utxo.height;
    blockhash = hash;
    coins_count = 0L;
    coins_hash = hash;
    chain_tx_count;
    base_header = None;
    base_tail_headers = [];
    chainwork = None;
    base_mtp = None;
  }

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

(* ---- 4. BETWEEN anchors without nTx must not borrow the neighbour ---- *)

let test_between_anchors_does_not_borrow_neighbour () =
  with_ctx Consensus.regtest (fun ctx ->
      let hashes = plant_headers ctx ~tip_height:20 in
      let anchor_h = 10 in
      let anchor_n = 1000L in
      let p = au_params ~height:anchor_h ~hash:hashes.(anchor_h) ~chain_tx_count:anchor_n in
      Storage.ChainDB.store_chain_tx_count ctx.chain.db hashes.(anchor_h) anchor_n;
      with_extra_regtest_au p (fun () ->
          let fields =
            assoc
              (rpc_ok ctx "getchaintxstats"
                 [ `Int 0; `String (display hashes.(15)) ])
          in
          let got = txcount_of fields in
          Alcotest.(check bool)
            "txcount must not be the height-10 anchor's 1000" true
            (got <> Some 1000);
          Alcotest.(check bool)
            "txcount omitted when nTx is missing between anchors" true
            (got = None);
          Alcotest.(check bool)
            "must not persist the neighbour cumulative at the queried height"
            true
            (Storage.ChainDB.get_chain_tx_count ctx.chain.db hashes.(15) = None)))

(* ---- 5. BETWEEN anchors with nTx reconstructs parent + nTx ---- *)

let test_between_anchors_reconstructs_from_ntx () =
  with_ctx Consensus.regtest (fun ctx ->
      let hashes = plant_headers ctx ~tip_height:20 in
      let anchor_h = 10 in
      let anchor_n = 1000L in
      let p = au_params ~height:anchor_h ~hash:hashes.(anchor_h) ~chain_tx_count:anchor_n in
      Storage.ChainDB.store_chain_tx_count ctx.chain.db hashes.(anchor_h) anchor_n;
      for h = 11 to 15 do
        Storage.ChainDB.store_block_ntx ctx.chain.db hashes.(h) 3
      done;
      with_extra_regtest_au p (fun () ->
          let fields =
            assoc
              (rpc_ok ctx "getchaintxstats"
                 [ `Int 0; `String (display hashes.(15)) ])
          in
          Alcotest.(check int) "txcount = 1000 + 5*3" 1015
            (field_int fields "txcount");
          Alcotest.(check bool) "not the neighbour" true
            (field_int fields "txcount" <> 1000)))

(* ---- 6. Core live getchaintxstats BETWEEN mainnet AU heights ---- *)

(* Core RPC 2026-09-17, same block hash as camlcoin. The third column is
   the lower AssumeUTXO seed — the value deployed b9c893d actually
   returned at 920k/930k/940k (and the 944183 placeholder at 945k). *)
let core_between_rows =
  [
    (905_000, 1_211_952_957, 1_145_604_538);
    (920_000, 1_259_327_471, 1_226_586_151);
    (930_000, 1_290_780_971, 1_226_586_151);
    (940_000, 1_320_830_439, 1_305_397_408);
    (945_000, 1_339_266_425, 1_334_000_000);
  ]

let test_mainnet_between_anchors_vs_core () =
  with_ctx Consensus.mainnet (fun ctx ->
      List.iter
        (fun (p : Assume_utxo.assumeutxo_params) ->
          if p.height >= 840_000 then plant_at ctx ~height:p.height p.blockhash)
        (Assume_utxo.assumeutxo_params_list Consensus.mainnet);
      let max_h = ref 0 in
      List.iter
        (fun (h, _, _) ->
          plant_at ctx ~height:h (hash_of_height h);
          if h > !max_h then max_h := h)
        core_between_rows;
      ctx.chain.Sync.blocks_synced <- !max_h;
      ctx.chain.Sync.headers_synced <- !max_h;
      let tip_hash = hash_of_height !max_h in
      ctx.chain.Sync.tip <-
        Hashtbl.find_opt ctx.chain.Sync.headers (Cstruct.to_string tip_hash);
      Storage.ChainDB.set_chain_tip ctx.chain.db tip_hash !max_h;
      List.iter
        (fun (h, core_n, borrowed) ->
          let fields =
            assoc
              (rpc_ok ctx "getchaintxstats"
                 [ `Int 0; `String (display (hash_of_height h)) ])
          in
          let got = txcount_of fields in
          Alcotest.(check bool)
            (Printf.sprintf "h=%d must not be the lower AU %d" h borrowed)
            true (got <> Some borrowed);
          Alcotest.(check bool)
            (Printf.sprintf "h=%d omitted or Core-exact %d (got %s)" h core_n
               (match got with None -> "omitted" | Some n -> string_of_int n))
            true
            (match got with None -> true | Some n -> n = core_n))
        core_between_rows)

(* ---- 7. 944183 seed is Core's getchaintxstats, not the placeholder ---- *)

let test_944183_seed_is_core_not_placeholder () =
  match Assume_utxo.get_assumeutxo_params_mainnet 944_183 with
  | None -> Alcotest.fail "missing 944183 assumeUTXO entry"
  | Some p ->
    Alcotest.(check int64)
      "944183 m_chain_tx_count is Core getchaintxstats (not 1334000000)"
      1_335_914_531L p.chain_tx_count

let test_au_height_matches_core () =
  with_ctx Consensus.mainnet (fun ctx ->
      List.iter
        (fun (p : Assume_utxo.assumeutxo_params) ->
          if p.height >= 840_000 then plant_at ctx ~height:p.height p.blockhash)
        (Assume_utxo.assumeutxo_params_list Consensus.mainnet);
      ctx.chain.Sync.blocks_synced <- 944_183;
      ctx.chain.Sync.headers_synced <- 944_183;
      let p910 =
        match Assume_utxo.get_assumeutxo_params_mainnet 910_000 with
        | Some p -> p
        | None -> Alcotest.fail "missing 910000"
      in
      let fields =
        assoc
          (rpc_ok ctx "getchaintxstats"
             [ `Int 0; `String (display p910.blockhash) ])
      in
      Alcotest.(check int) "910000 Core AU seed" 1_226_586_151
        (field_int fields "txcount");
      let p944 =
        match Assume_utxo.get_assumeutxo_params_mainnet 944_183 with
        | Some p -> p
        | None -> Alcotest.fail "missing 944183"
      in
      ctx.chain.Sync.tip <-
        Hashtbl.find_opt ctx.chain.Sync.headers
          (Cstruct.to_string p944.blockhash);
      Storage.ChainDB.set_chain_tip ctx.chain.db p944.blockhash 944_183;
      let fields =
        assoc
          (rpc_ok ctx "getchaintxstats"
             [ `Int 0; `String (display p944.blockhash) ])
      in
      Alcotest.(check int) "944183 Core getchaintxstats" 1_335_914_531
        (field_int fields "txcount"))

let () =
  Alcotest.run "getchaintxstats stored cumulative + concurrent RPC"
    [
      ( "txcount",
        [
          Alcotest.test_case "stored cumulative at tip and historicals" `Quick
            test_txcount_from_stored_cumulative;
          Alcotest.test_case "between anchors does not borrow neighbour" `Quick
            test_between_anchors_does_not_borrow_neighbour;
          Alcotest.test_case "between anchors reconstructs from nTx" `Quick
            test_between_anchors_reconstructs_from_ntx;
          Alcotest.test_case "mainnet between-anchor heights vs Core" `Quick
            test_mainnet_between_anchors_vs_core;
          Alcotest.test_case "944183 seed is Core not placeholder" `Quick
            test_944183_seed_is_core_not_placeholder;
          Alcotest.test_case "AU heights match Core" `Quick
            test_au_height_matches_core;
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
