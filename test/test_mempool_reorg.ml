(* Mempool consistent with the chain on invalidateblock / reconsiderblock /
   P2P reorg, and the mempool's tip height after a catch-up connect.

   Core (validation.cpp):
     ConnectTip -> m_mempool->removeForBlock(block.vtx) for EVERY connected
       block (confirmed txs + conflicts, with descendants);
     DisconnectTip -> disconnectpool->AddTransactionsFromBlock;
     InvalidateBlock / ActivateBestChainStep -> MaybeUpdateMempoolForReorg:
       re-accept earliest first (bypass_limits), removeRecursive a failure,
       UpdateTransactionsFromBlock, removeForReorg (non-final / BIP68 /
       immature coinbase at tip+1), LimitMempoolSize;
     ATMP reads the spend height from m_chain.Height() + 1.

   Fixture: 110 coinbase-only blocks through the catch-up path, then the
   vectors of [build_vec] (111 [A], 112 [B, LT, IMM], mempool M1-M3) built
   per case below.  Mempool txs are admitted through the RPC
   (sendrawtransaction) and the mempool is read back with getrawmempool, so
   the RPC routing (main thread = chain lock) is on the path.

     dune exec --no-buffer test/test_mempool_reorg.exe
*)

open Camlcoin

let op_true = Cstruct.of_string "\x51"

let remine (block : Types.block) : Types.block =
  let h = ref block.Types.header in
  let n = ref 0l in
  let found = ref false in
  while (not !found) && Int32.compare !n 5_000_000l < 0 do
    h := { !h with Types.nonce = !n };
    if Consensus.hash_meets_target (Crypto.compute_block_hash !h) !h.Types.bits
    then found := true
    else n := Int32.add !n 1l
  done;
  if not !found then failwith "remine: no nonce found";
  { block with Types.header = !h }

let make_block ~prev_hash ~prev_time ~height ?(fee = 0L) ?(tag = 0)
    (txs : Types.transaction list) : Types.block =
  let extra_nonce = Cstruct.create 8 in
  Cstruct.LE.set_uint64 extra_nonce 0 (Int64.of_int (height + (tag lsl 32)));
  let mk wr =
    Mining.create_coinbase ~height ~total_fee:fee ~payout_script:op_true
      ~extra_nonce ~witness_root:wr ~network_type:Consensus.Regtest ()
  in
  let placeholder = mk None in
  let wr = Mining.compute_witness_merkle_root (placeholder :: txs) in
  let coinbase = mk (Some wr) in
  let all = coinbase :: txs in
  let merkle_root, _ = Crypto.merkle_root (List.map Crypto.compute_txid all) in
  remine { Types.header = { version = 4l; prev_block = prev_hash; merkle_root;
                            timestamp = Int32.add prev_time 600l;
                            bits = Consensus.regtest.pow_limit; nonce = 0l };
           transactions = all }

let fee = 10_000L

(* Spend output 0 of [prev] (value [value]) to OP_TRUE. *)
let spend ?(tag = 0) ?(locktime = 0l) ?(sequence = 0xFFFFFFFFl)
    (prev : Types.hash256) (value : int64) : Types.transaction =
  let pad = Cstruct.create 22 in
  Cstruct.set_uint8 pad 0 0x6a; Cstruct.set_uint8 pad 1 0x14;
  Cstruct.set_uint8 pad 2 tag;
  { Types.version = 2l;
    inputs = [ { Types.previous_output = { Types.txid = prev; vout = 0l };
                 script_sig = Cstruct.create 0; sequence } ];
    outputs = [ { Types.value = Int64.sub value fee; script_pubkey = op_true };
                { Types.value = 0L; script_pubkey = pad } ];
    witnesses = []; locktime }

let hex_of_string s =
  String.concat "" (List.init (String.length s)
                      (fun i -> Printf.sprintf "%02x" (Char.code s.[i])))

let tx_hex (tx : Types.transaction) =
  let w = Serialize.writer_create () in
  Serialize.serialize_transaction w tx;
  hex_of_string (Serialize.writer_to_string w)

let hash_of (b : Types.block) = Crypto.compute_block_hash b.Types.header
let cb_txid (b : Types.block) = Crypto.compute_txid (List.hd b.Types.transactions)
let txid = Crypto.compute_txid

let queue ibd (b : Types.block) h =
  Sync.queue_add ibd
    { Sync.hash = hash_of b; height = h;
      download_state = Sync.Downloaded { block = b; peer_id = None };
      tried_peers = [] }

let json_req method_name params : Yojson.Safe.t =
  `Assoc [ ("jsonrpc", `String "1.0"); ("id", `String "t");
           ("method", `String method_name); ("params", `List params) ]

(* --------------------------------------------------------------- fixture *)

type fx = {
  db : Storage.ChainDB.t;
  state : Sync.chain_state;
  utxo : Utxo.OptimizedUtxoSet.t;
  mp : Mempool.mempool;
  ctx : Rpc.rpc_context;
  cb : Types.hash256 array;            (* coinbase txid by height *)
  mutable prev_hash : Types.hash256;
  mutable prev_time : int32;
}

let subsidy = Consensus.block_subsidy_for_network Consensus.Regtest 1

let build fx ?fee ?tag h txs =
  let b = make_block ~prev_hash:fx.prev_hash ~prev_time:fx.prev_time
      ~height:h ?fee ?tag txs in
  fx.prev_hash <- hash_of b;
  fx.prev_time <- b.Types.header.Types.timestamp;
  fx.cb.(h) <- cb_txid b;
  b

let accept_hdr fx (b : Types.block) =
  match Sync.validate_header fx.state b.Types.header with
  | Ok e -> Sync.accept_header fx.state e
  | Error e -> Alcotest.failf "validate_header: %s" e

(* The node's mempool wiring, as cli.ml does it.  The connect hook existed
   before this change; the chain-attached mempool (reorg / invalidate path)
   and the chain tip-height source are the fix's. *)
let wire (state : Sync.chain_state) (mp : Mempool.mempool) =
  Sync.set_mempool_remove_hook state
    (Some (fun b h -> Mempool.remove_for_block mp b h));
  Sync.set_chain_mempool state (Some mp);
  Mempool.set_tip_height_provider mp
    (Some (fun () -> state.Sync.blocks_synced))

(* 110 blocks through the catch-up path (a node that synced over P2P),
   with the mempool created at the boot height (0) like a fresh datadir. *)
let with_fx ~label f =
  Test_tmp.with_dir ~label ~mkdir:true (fun path ->
    let db = Storage.ChainDB.create (Filename.concat path "chain") in
    Fun.protect ~finally:(fun () ->
        Sync.shared_utxo_set := None;
        try Storage.ChainDB.close db with _ -> ())
      (fun () ->
        let state = Sync.create_chain_state db Consensus.regtest in
        let genesis = Option.get state.Sync.tip in
        let utxo = Utxo.OptimizedUtxoSet.create ~cache_size:10_000 db in
        Sync.shared_utxo_set := Some utxo;
        let network = Consensus.regtest in
        let mp = Mempool.create ~network ~require_standard:false
            ~verify_scripts:false ~utxo:(Utxo.UtxoSet.create db)
            ~current_height:0 () in
        wire state mp;
        let ctx : Rpc.rpc_context =
          { chain = state; mempool = mp;
            peer_manager = Peer_manager.create network;
            wallet = None; wallet_manager = None;
            fee_estimator = Fee_estimation.create ();
            network; filter_index = None; utxo = Some utxo; data_dir = None;
            snapshot_activation = None } in
        let fx = { db; state; utxo; mp; ctx;
                   cb = Array.make 200 Types.zero_hash;
                   prev_hash = genesis.Sync.hash;
                   prev_time = genesis.Sync.header.Types.timestamp } in
        let prefix = List.init 110 (fun i ->
            let b = build fx (i + 1) [] in accept_hdr fx b; b) in
        state.Sync.blocks_synced <- 0;
        state.Sync.sync_state <- Sync.SyncingBlocks;
        let ibd = Sync.create_ibd_state ~utxo_set:utxo state in
        List.iteri (fun i b -> queue ibd b (i + 1)) prefix;
        (match Lwt_main.run (Sync.process_downloaded_blocks ~max_blocks:110 ibd)
         with Ok _ -> () | Error e -> Alcotest.failf "prefix: %s" e);
        Sync.flush_utxos ibd;
        Storage.ChainDB.set_chain_tip db fx.prev_hash 110;
        Alcotest.(check int) "fixture: 110 connected" 110 state.Sync.blocks_synced;
        state.Sync.sync_state <- Sync.FullySynced;
        f fx))

let rpc fx m params =
  Lwt_main.run (Rpc.handle_single_request_lwt fx.ctx (json_req m params))

let rpc_ok fx m params =
  let r = rpc fx m params in
  (match r with
   | `Assoc kv when (match List.assoc_opt "error" kv with
       | None | Some `Null -> false | Some _ -> true) ->
     Alcotest.failf "%s: %s" m (Yojson.Safe.to_string r)
   | _ -> ());
  r

let sendraw fx tx = ignore (rpc_ok fx "sendrawtransaction" [ `String (tx_hex tx) ])

let hx b = `String (Types.hash256_to_hex_display (hash_of b))

let connect fx b =
  accept_hdr fx b;
  match Lwt_main.run (Sync.process_new_block ~f_requested:true fx.state b) with
  | Ok () -> ()
  | Error e -> Alcotest.failf "connect at %d: %s" fx.state.Sync.blocks_synced e

(* The mempool as getrawmempool reports it, named. *)
let pool fx (names : (string * Types.transaction) list) : string list =
  let r = rpc_ok fx "getrawmempool" [] in
  let ids = match r with
    | `Assoc kv -> (match List.assoc_opt "result" kv with
        | Some (`List l) -> List.filter_map (function `String s -> Some s | _ -> None) l
        | _ -> [])
    | _ -> [] in
  let name_of id =
    match List.find_opt (fun (_, tx) ->
        Types.hash256_to_hex_display (txid tx) = id) names with
    | Some (n, _) -> n
    | None -> "?" ^ String.sub id 0 8 in
  List.sort compare (List.map name_of ids)

let check_pool what expected got =
  Printf.printf "  %s: %s (Core: %s)\n%!" what (String.concat "," got)
    (String.concat "," expected);
  Alcotest.(check (list string)) what (List.sort compare expected) got

(* Shared vectors (the sweep's shape): 111 [A <- cb1], 112 [B <- cb3,
   LT <- cb4 (nLockTime 111), IMM <- cb12]; mempool at 112: M1 <- B:0,
   M2 <- A:0, M3 <- cb6.  IMM spends the coinbase of block 12: mature for a
   block at 112 (100 confirmations), immature at 111 (99).  LT is final at
   112, not at 111. *)
type vec = {
  b111 : Types.block; b112 : Types.block;
  a : Types.transaction; b : Types.transaction; lt : Types.transaction;
  imm : Types.transaction;
  m1 : Types.transaction; m2 : Types.transaction; m3 : Types.transaction;
  names : (string * Types.transaction) list;
}

let build_vec fx =
  let a = spend ~tag:1 fx.cb.(1) subsidy in
  let b = spend ~tag:2 fx.cb.(3) subsidy in
  let lt = spend ~tag:3 ~locktime:111l ~sequence:0xFFFFFFFEl fx.cb.(4) subsidy in
  let imm = spend ~tag:4 fx.cb.(12) subsidy in
  let b111 = build fx ~fee ~tag:0 111 [ a ] in
  let b112 = build fx ~fee:(Int64.mul 3L fee) ~tag:0 112 [ b; lt; imm ] in
  let m1 = spend ~tag:5 (txid b) (Int64.sub subsidy fee) in
  let m2 = spend ~tag:6 (txid a) (Int64.sub subsidy fee) in
  let m3 = spend ~tag:7 fx.cb.(6) subsidy in
  { b111; b112; a; b; lt; imm; m1; m2; m3;
    names = [ "A", a; "B", b; "LT", lt; "IMM", imm;
              "M1", m1; "M2", m2; "M3", m3 ] }

(* ------------------------------------------------------------- cases *)

(* The catch-up connect path must run removeForBlock and the mempool must
   see the chain's tip height.  M3 spends the coinbase of block 6 at tip 110
   (spend height 111: 105 confirmations, mature).  Deployed: the catch-up
   path never told the mempool, its height stayed at the boot value 0, and
   M3 was rejected as a premature coinbase spend; a tx the catch-up path
   confirmed also stayed in the pool. *)
let test_catchup_height_and_remove () =
  with_fx ~label:"mr_catchup" (fun fx ->
    let m3 = spend ~tag:7 fx.cb.(6) subsidy in
    let r = rpc fx "sendrawtransaction" [ `String (tx_hex m3) ] in
    Printf.printf "  sendraw M3 (cb6 at tip 110): %s\n%!" (Yojson.Safe.to_string r);
    Alcotest.(check bool) "M3 (mature coinbase spend) accepted" true
      (Mempool.contains fx.mp (txid m3));
    (* T in the pool, then a block confirming T through catch-up. *)
    let t = spend ~tag:8 fx.cb.(7) subsidy in
    sendraw fx t;
    let b = build fx ~fee ~tag:0 111 [ t ] in
    accept_hdr fx b;
    fx.state.Sync.sync_state <- Sync.SyncingBlocks;
    let ibd = Sync.create_ibd_state ~utxo_set:fx.utxo fx.state in
    queue ibd b 111;
    (match Lwt_main.run (Sync.process_downloaded_blocks ~max_blocks:1 ibd)
     with Ok _ -> () | Error e -> Alcotest.failf "catch-up 111: %s" e);
    Sync.flush_utxos ibd;
    fx.state.Sync.sync_state <- Sync.FullySynced;
    Alcotest.(check int) "111 connected via catch-up" 111
      fx.state.Sync.blocks_synced;
    Alcotest.(check bool) "catch-up removeForBlock: confirmed T left the pool"
      false (Mempool.contains fx.mp (txid t)))

(* (a) invalidateblock 111 -> tip 110.  Core: the pool gets A and B back
   (earliest first) and keeps M1, M2, M3; IMM (immature at 111) and LT
   (non-final at 111) are dropped by removeForReorg.  M2 (admitted while A
   was confirmed) becomes A's child (UpdateTransactionsFromBlock).
   (b) reconsiderblock 111 -> tip 112 again; the pool is {M1, M2, M3}. *)
let test_invalidate_reconsider () =
  with_fx ~label:"mr_invalidate" (fun fx ->
    let v = build_vec fx in
    connect fx v.b111; connect fx v.b112;
    Alcotest.(check int) "tip 112" 112 fx.state.Sync.blocks_synced;
    sendraw fx v.m1; sendraw fx v.m2; sendraw fx v.m3;
    check_pool "pool at 112" [ "M1"; "M2"; "M3" ] (pool fx v.names);
    ignore (rpc_ok fx "invalidateblock" [ hx v.b111 ]);
    Alcotest.(check int) "(a) tip 110" 110 fx.state.Sync.blocks_synced;
    check_pool "(a) pool after invalidateblock 111"
      [ "A"; "B"; "M1"; "M2"; "M3" ] (pool fx v.names);
    (match Mempool.get fx.mp (txid v.m2) with
     | None -> Alcotest.fail "M2 missing"
     | Some e ->
       Alcotest.(check bool) "(a) M2 now depends on the re-added A" true
         (List.exists (Cstruct.equal (txid v.a)) e.Mempool.depends_on);
       Alcotest.(check int) "(a) M2 ancestor_count = 2" 2 e.ancestor_count);
    (match Mempool.get fx.mp (txid v.a) with
     | None -> Alcotest.fail "A missing"
     | Some e -> Alcotest.(check int) "(a) A descendant_count = 2" 2
                   e.descendant_count);
    ignore (rpc_ok fx "reconsiderblock" [ hx v.b111 ]);
    Alcotest.(check int) "(b) reconsiderblock re-activates 112" 112
      fx.state.Sync.blocks_synced;
    check_pool "(b) pool after reconsiderblock 111" [ "M1"; "M2"; "M3" ]
      (pool fx v.names))

(* (c) P2P reorg 112 -> 113b off 110: 111b [X <- cb1 (conflicts A)], 112b,
   113b [Z <- cb6 (conflicts M3)].  Core: A fails re-acceptance (its input
   is spent by X) and is removeRecursive'd, taking M2; B, LT, IMM come back
   (all valid at 113); M3 goes with Z's conflict; M1 stays. *)
let test_p2p_reorg () =
  with_fx ~label:"mr_p2p" (fun fx ->
    let fork_hash = fx.prev_hash and fork_time = fx.prev_time in
    let v = build_vec fx in
    connect fx v.b111; connect fx v.b112;
    sendraw fx v.m1; sendraw fx v.m2; sendraw fx v.m3;
    check_pool "pool at 112" [ "M1"; "M2"; "M3" ] (pool fx v.names);
    fx.prev_hash <- fork_hash; fx.prev_time <- fork_time;
    let x = spend ~tag:9 fx.cb.(1) subsidy in
    let z = spend ~tag:10 fx.cb.(6) subsidy in
    let b111b = build fx ~fee ~tag:1 111 [ x ] in
    let b112b = build fx ~tag:1 112 [] in
    let b113b = build fx ~fee ~tag:1 113 [ z ] in
    List.iter (fun b ->
        accept_hdr fx b;
        match Lwt_main.run (Sync.process_new_block ~f_requested:true fx.state b) with
        | Ok () -> ()
        | Error e -> Alcotest.failf "branch block: %s" e)
      [ b111b; b112b; b113b ];
    Alcotest.(check int) "(c) reorged to 113b" 113 fx.state.Sync.blocks_synced;
    Alcotest.(check bool) "(c) active 113 is 113b" true
      (match Storage.ChainDB.get_hash_at_height fx.db 113 with
       | Some h -> Cstruct.equal h (hash_of b113b) | None -> false);
    check_pool "(c) pool after the P2P reorg"
      [ "B"; "IMM"; "LT"; "M1" ] (pool fx (("X", x) :: ("Z", z) :: v.names)))

let () =
  Alcotest.run "mempool_reorg" [
    "mempool vs chain", [
      Alcotest.test_case "catch-up connect: tip height + removeForBlock" `Quick
        test_catchup_height_and_remove;
      Alcotest.test_case "invalidateblock refill + reconsiderblock" `Quick
        test_invalidate_reconsider;
      Alcotest.test_case "P2P reorg: refill, conflicts, descendants" `Quick
        test_p2p_reorg;
    ];
  ]
