(* getblockchaininfo.initialblockdownload on regtest follows Core's
   IsInitialBlockDownload.

   Core (validation.cpp ChainstateManager::UpdateIBDStatus, chain.h
   CChain::IsTipRecent) leaves IBD, and latches false for good, once the
   active tip has at least nMinimumChainWork and a time no older than
   max_tip_age (24 h, kernel/chainstatemanager_opts.h DEFAULT_MAX_TIP_AGE)
   before GetTime(), which is the mock time when setmocktime set one.
   There is no regtest exemption: a regtest chain whose tip carries an old
   timestamp is still in IBD.

   camlcoin hard-coded false on regtest, so every Core regtest ratchet
   getblockchaininfo row on the fixed 2011/2023-timestamp chains differed
   (21 rows: chain, seed_invalidated_submit, warden_invalidated_submit
   */info:initialblockdownload, Core true, camlcoin false).

     dune exec --no-buffer test/ibd_tip_age/test_ibd_tip_age.exe
*)

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
      Fun.protect
        ~finally:(fun () -> Node_clock.set_mock_time 0L)
        (fun () -> f ctx))

let genesis_entry ctx =
  match Sync.get_header_at_height ctx.Rpc.chain 0 with
  | Some e -> e
  | None -> (
    match ctx.chain.Sync.tip with
    | Some e -> e
    | None -> Alcotest.fail "no genesis")

(* Extend the active chain by [n] blocks whose times start at [time0] and
   step 600 s, the way a connect leaves it: in-memory header entry, header,
   height index, body, blocks_synced, chain-tip marker.  Returns the tip's time. *)
let extend ctx ~n ~time0 =
  let tip = genesis_entry ctx in
  let prev = ref tip.Sync.hash in
  let t = ref time0 in
  for h = 1 to n do
    let header =
      { Types.version = 1l; prev_block = !prev;
        merkle_root = Types.zero_hash; timestamp = Int32.of_float !t;
        bits = 0x207fffffl; nonce = Int32.of_int h }
    in
    let hash = Crypto.compute_block_hash header in
    Hashtbl.replace ctx.chain.Sync.headers (Cstruct.to_string hash)
      { Sync.header; hash; height = h; total_work = tip.Sync.total_work };
    Storage.ChainDB.store_block_header ctx.chain.db hash header;
    Storage.ChainDB.set_height_hash ctx.chain.db h hash;
    Storage.ChainDB.store_block ctx.chain.db hash
      { Types.header; transactions = [] };
    Storage.ChainDB.set_chain_tip ctx.chain.db hash h;
    prev := hash;
    if h < n then t := !t +. 600.0
  done;
  ctx.chain.Sync.blocks_synced <- n;
  ctx.chain.Sync.headers_synced <- n;
  ctx.chain.Sync.sync_state <- Sync.FullySynced;
  !t

let ibd ctx =
  match Rpc.dispatch_rpc ctx "getblockchaininfo" [] with
  | Ok (`Assoc fields) -> (
    match List.assoc_opt "initialblockdownload" fields with
    | Some (`Bool b) -> b
    | Some j -> Alcotest.failf "initialblockdownload: %s" (Yojson.Safe.to_string j)
    | None -> Alcotest.fail "initialblockdownload missing")
  | Ok j -> Alcotest.failf "getblockchaininfo: %s" (Yojson.Safe.to_string j)
  | Error (c, m) -> Alcotest.failf "getblockchaininfo error (%d) %s" c m

(* Core regtest chain/info/clean: a fresh node on the genesis block (2011
   timestamp) is in IBD. *)
let test_genesis_only_is_ibd () =
  with_ctx (fun ctx ->
      Alcotest.(check bool) "genesis tip is older than 24 h: Core true" true
        (ibd ctx))

(* Core regtest */info:initialblockdownload: a chain of old-timestamped
   blocks, fully connected, is still in IBD on regtest. *)
let test_old_tip_is_ibd () =
  with_ctx (fun ctx ->
      let _ = extend ctx ~n:5 ~time0:1296688602.0 in
      Alcotest.(check bool) "old regtest tip: Core true" true (ibd ctx))

(* Control: a tip stamped now is recent, so IBD is over (camlcoin answered
   false before and must keep doing so). *)
let test_recent_tip_leaves_ibd () =
  with_ctx (fun ctx ->
      let _ = extend ctx ~n:3 ~time0:(Unix.gettimeofday () -. 1200.0) in
      Alcotest.(check bool) "recent tip: Core false" false (ibd ctx))

(* GetTime() is the mock time: an old tip under a mocktime within 24 h of
   it is recent; once out of IBD the flag stays false even after the clock
   moves past max_tip_age again (UpdateIBDStatus latches). *)
let test_mocktime_and_latch () =
  with_ctx (fun ctx ->
      let tip_time = extend ctx ~n:4 ~time0:1296688602.0 in
      Alcotest.(check bool) "old tip, no mocktime: true" true (ibd ctx);
      Node_clock.set_mock_time (Int64.of_float (tip_time +. 86400.0 +. 1.0));
      Alcotest.(check bool) "mocktime 24h+1s after tip: still true" true
        (ibd ctx);
      Node_clock.set_mock_time (Int64.of_float (tip_time +. 3600.0));
      Alcotest.(check bool) "mocktime 1h after tip: false" false (ibd ctx);
      Node_clock.set_mock_time 0L;
      Alcotest.(check bool) "back on the system clock: latched false" false
        (ibd ctx))

let () =
  Alcotest.run "ibd_tip_age"
    [ ( "getblockchaininfo",
        [ Alcotest.test_case "genesis-only regtest node is in IBD" `Quick
            test_genesis_only_is_ibd;
          Alcotest.test_case "old regtest tip is in IBD" `Quick
            test_old_tip_is_ibd;
          Alcotest.test_case "recent tip is out of IBD" `Quick
            test_recent_tip_leaves_ibd;
          Alcotest.test_case "mocktime-recent tip leaves IBD and latches" `Quick
            test_mocktime_and_latch ] ) ]
