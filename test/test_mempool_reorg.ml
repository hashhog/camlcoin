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

(* A mempool fault after the reorg's commit must not escape [reorganize]:
   its callers (process_new_block's P2P reorg, submitblock's side branch,
   reconsiderblock, invalidateblock's activate loop) match on the result and
   do not catch, and the tip is already on disk.  Same reorg as (c), with
   removeForBlock raising for every connected block: the reorg still returns
   Ok at 113b, and the refill still runs (B, IMM, LT come back). *)
let test_p2p_reorg_remove_raises () =
  with_fx ~label:"mr_p2p_raise" (fun fx ->
    let fork_hash = fx.prev_hash and fork_time = fx.prev_time in
    let v = build_vec fx in
    connect fx v.b111; connect fx v.b112;
    sendraw fx v.m1;
    check_pool "pool at 112" [ "M1" ] (pool fx v.names);
    fx.prev_hash <- fork_hash; fx.prev_time <- fork_time;
    let b111b = build fx ~tag:1 111 [] in
    let b112b = build fx ~tag:1 112 [] in
    let b113b = build fx ~tag:1 113 [] in
    let raised = ref 0 in
    let saved = !Sync.reorg_remove_for_block in
    Sync.reorg_remove_for_block := (fun _ _ _ -> incr raised; failwith "injected");
    Fun.protect ~finally:(fun () -> Sync.reorg_remove_for_block := saved)
      (fun () ->
        List.iter (fun b ->
            accept_hdr fx b;
            match Lwt_main.run
                    (Sync.process_new_block ~f_requested:true fx.state b) with
            | Ok () -> ()
            | Error e -> Alcotest.failf "branch block: %s" e
            | exception exn ->
              Alcotest.failf "reorg raised: %s" (Printexc.to_string exn))
          [ b111b; b112b; b113b ]);
    Alcotest.(check bool) "removeForBlock was called and raised" true
      (!raised > 0);
    Alcotest.(check int) "reorged to 113b" 113 fx.state.Sync.blocks_synced;
    Alcotest.(check bool) "active 113 is 113b" true
      (match Storage.ChainDB.get_hash_at_height fx.db 113 with
       | Some h -> Cstruct.equal h (hash_of b113b) | None -> false);
    check_pool "pool after the reorg (refill ran)"
      [ "A"; "B"; "IMM"; "LT"; "M1" ] (pool fx v.names))

(* Core UpdateTransactionsFromBlock ends with m_txgraph->Trim(): linking a
   re-added tx to its in-pool children can grow a cluster past the limits
   (64 txs / 404000 weight), and Trim removes txs (with descendants) until
   every cluster fits, keeping the highest-chunk-feerate ones (a merge of the
   old linearizations).  warden_e: P <- cb1 with 64 outputs, confirmed at
   111; children C_i <- P:i with fee (i+1)*1000, admitted at 111;
   invalidateblock 111 -> Core v31.1 keeps P and C_1..C_63, drops C_0 (the
   cheapest).  The re-add runs with bypass_limits and the cluster gate runs
   before the children are linked, so only the trim can enforce the bound. *)
(* P <- cb1 with [n] outputs, confirmed at 111; C_i <- P:i with fee
   (i+1)*[fee_unit] and a [pad]-byte OP_RETURN, admitted at 111 (each a singleton
   cluster while P is confirmed); then invalidateblock 111. *)
let parent_children_invalidate fx ~n ~pad ~fee_unit =
  let pfee = 10_000L in
  let each = Int64.div (Int64.sub subsidy pfee) (Int64.of_int n) in
  let parent =
    { Types.version = 2l;
      inputs = [ { Types.previous_output = { Types.txid = fx.cb.(1); vout = 0l };
                   script_sig = Cstruct.create 0; sequence = 0xFFFFFFFFl } ];
      outputs = List.init n (fun _ ->
          { Types.value = each; Types.script_pubkey = op_true });
      witnesses = []; locktime = 0l } in
  let child i =
    let data = Cstruct.create (pad + 1) in
    Cstruct.set_uint8 data 0 0x6a;
    Cstruct.set_uint8 data 1 i;
    { Types.version = 2l;
      inputs = [ { Types.previous_output =
                     { Types.txid = txid parent; vout = Int32.of_int i };
                   script_sig = Cstruct.create 0; sequence = 0xFFFFFFFFl } ];
      outputs = [ { Types.value = Int64.sub each (Int64.of_int ((i + 1) * fee_unit));
                    script_pubkey = op_true };
                  { Types.value = 0L; script_pubkey = data } ];
      witnesses = []; locktime = 0l } in
  let children = List.init n child in
  let b111 = build fx ~fee:pfee ~tag:0 111 [ parent ] in
  connect fx b111;
  List.iter (sendraw fx) children;
  Alcotest.(check int) "all children in the pool at 111" n (Mempool.count fx.mp);
  ignore (rpc_ok fx "invalidateblock" [ hx b111 ]);
  Alcotest.(check int) "tip 110" 110 fx.state.Sync.blocks_synced;
  let names = ("P", parent)
              :: List.mapi (fun i c -> (Printf.sprintf "C%02d" i, c)) children in
  parent, names

let test_invalidate_trims_oversized_cluster () =
  with_fx ~label:"mr_trim" (fun fx ->
    let parent, names = parent_children_invalidate fx ~n:64 ~pad:20 ~fee_unit:1000 in
    let expected = "P" :: List.init 63 (fun i -> Printf.sprintf "C%02d" (i + 1)) in
    check_pool "pool after invalidateblock 111 (Core: P + C01..C63)"
      expected (pool fx names);
    Alcotest.(check int) "P's cluster is at the 64-tx limit" 64
      (Mempool.get_cluster_size fx.mp (txid parent));
    (match Mempool.get fx.mp (txid parent) with
     | None -> Alcotest.fail "P missing"
     | Some e ->
       Alcotest.(check int) "P descendant_count = 64 (self + 63)" 64
         e.Mempool.descendant_count))

(* The same Trim on the WEIGHT bound: 5 children of ~96_400 weight (a
   24_000-byte OP_RETURN, fee (i+1)*30_000) each fit alone, but P + 5 children is ~483_000 >
   404_000; P + 4 is ~387_000.  Trim keeps P and the 4 highest-feerate
   children and drops C_0. *)
let test_invalidate_trims_overweight_cluster () =
  with_fx ~label:"mr_trimw" (fun fx ->
    let parent, names = parent_children_invalidate fx ~n:5 ~pad:24_000 ~fee_unit:30_000 in
    check_pool "pool after invalidateblock 111 (Core: P + C01..C04)"
      [ "P"; "C01"; "C02"; "C03"; "C04" ] (pool fx names);
    let weight =
      List.fold_left (fun acc (_, tx) ->
        match Mempool.get fx.mp (txid tx) with
        | Some e -> acc + e.Mempool.weight | None -> acc) 0 names in
    Printf.printf "  cluster weight after trim: %d (limit %d)\n%!" weight
      Mempool.max_cluster_size_weight;
    Alcotest.(check bool) "P's cluster weight within 404000" true
      (weight <= Mempool.max_cluster_size_weight);
    Alcotest.(check int) "P's cluster is 5 txs" 5
      (Mempool.get_cluster_size fx.mp (txid parent)))

(* Core InvalidateBlock: MaybeUpdateMempoolForReorg(disconnectpool,
   fAddToMempool = ++disconnected <= 10), once per DisconnectTip, tip
   first.  Only the 10 blocks nearest the old tip are resurrected; the txs of
   deeper blocks are removeRecursive'd, which takes their in-pool spenders.
   Blocks 111..121 each confirm T_k <- cb(k-110); M <- T_1:0 is admitted at
   121.  invalidateblock 111 disconnects 11 blocks: T_2..T_11 come back, T_1
   (11th disconnected) does not, and M goes with it. *)
let test_deep_invalidate_caps_readd () =
  with_fx ~label:"mr_depth" (fun fx ->
    let ts = List.init 11 (fun k -> spend ~tag:(20 + k) fx.cb.(k + 1) subsidy) in
    let blocks = List.mapi (fun k t -> build fx ~fee ~tag:0 (111 + k) [ t ]) ts in
    List.iter (connect fx) blocks;
    Alcotest.(check int) "tip 121" 121 fx.state.Sync.blocks_synced;
    let t1 = List.hd ts in
    let m = spend ~tag:40 (txid t1) (Int64.sub subsidy fee) in
    sendraw fx m;
    ignore (rpc_ok fx "invalidateblock" [ hx (List.hd blocks) ]);
    Alcotest.(check int) "tip 110" 110 fx.state.Sync.blocks_synced;
    let names = ("M", m) :: List.mapi (fun k t -> (Printf.sprintf "T%02d" (k + 1), t)) ts in
    check_pool "pool after an 11-block invalidate (Core: T02..T11)"
      (List.init 10 (fun k -> Printf.sprintf "T%02d" (k + 2))) (pool fx names))

(* ------------------------------------------- entry fields (entryToJSON) *)

(* getmempoolentry's result object for [tx]. *)
let entry_json fx (tx : Types.transaction) : (string * Yojson.Safe.t) list =
  match rpc_ok fx "getmempoolentry"
          [ `String (Types.hash256_to_hex_display (txid tx)) ] with
  | `Assoc kv -> (match List.assoc_opt "result" kv with
      | Some (`Assoc e) -> e
      | _ -> Alcotest.fail "getmempoolentry: no result object")
  | _ -> Alcotest.fail "getmempoolentry: not an object"

let field_int e k = match List.assoc_opt k e with
  | Some (`Int n) -> n
  | _ -> Alcotest.failf "entry field %s not an int" k

let chunk_fee_sats e = match List.assoc_opt "fees" e with
  | Some (`Assoc f) -> (match List.assoc_opt "chunk" f with
      | Some (`Float x) -> Int64.of_float (Float.round (x *. 1e8))
      | Some (`Int n) -> Int64.mul (Int64.of_int n) 100_000_000L
      | _ -> Alcotest.fail "fees.chunk missing")
  | _ -> Alcotest.fail "fees missing"

let spentby e = match List.assoc_opt "spentby" e with
  | Some (`List l) -> List.map (function `String s -> s | _ -> "?") l
  | _ -> Alcotest.fail "spentby missing"

let pool_entry fx tx = match Mempool.get fx.mp (txid tx) with
  | Some e -> e | None -> Alcotest.fail "tx not in pool"

(* Core entryToJSON spentby = GetChildren, sorted by CompareIteratorByHash
   (uint256 operator<: the internal byte order, which is the displayed hex
   reversed).  warden_e: P with 63 in-pool children after the invalidate
   refill.  Deployed: the children came out in hash-table order. *)
let test_spentby_txid_order () =
  with_fx ~label:"mr_spentby" (fun fx ->
    let parent, names = parent_children_invalidate fx ~n:64 ~pad:20 ~fee_unit:1000 in
    let kids = List.filter_map (fun (n, tx) ->
        if n <> "P" && Mempool.contains fx.mp (txid tx) then Some (txid tx)
        else None) names in
    Alcotest.(check int) "63 children in the pool" 63 (List.length kids);
    let core_order =
      List.map Types.hash256_to_hex_display (List.sort Cstruct.compare kids) in
    Alcotest.(check (list string)) "P spentby in Core's GetChildren order"
      core_order (spentby (entry_json fx parent)))

(* Core GetMainChunkFeerate: chunkweight / fees.chunk are the chunk's, not
   the tx's.  P (fee 10k) <- C0 (fee 100k), C1 (fee 200k), re-added by the
   invalidate refill.  The linearization chunks P with C1 (P+C1 has a higher
   feerate than P, and C0 alone is below P+C1), so P and C1 report the
   P+C1 weight and fees, and C0 its own.  Deployed: every entry reported its
   own weight and modified fee (Core regtest reorg/seed_mempool_reorg rows:
   node 340 vs Core 680). *)
let test_chunk_feerate_cpfp () =
  with_fx ~label:"mr_chunk" (fun fx ->
    let parent, names = parent_children_invalidate fx ~n:2 ~pad:20 ~fee_unit:100_000 in
    let c0 = List.assoc "C00" names and c1 = List.assoc "C01" names in
    let p = pool_entry fx parent and e0 = pool_entry fx c0
    and e1 = pool_entry fx c1 in
    let rate (f : int64) w = Int64.to_float f /. float_of_int w in
    let pc1_fee = Int64.add p.Mempool.fee e1.Mempool.fee
    and pc1_w = p.Mempool.weight + e1.Mempool.weight in
    (* The fixture's premise: C1 lifts P, C0 does not join P+C1. *)
    Alcotest.(check bool) "fixture: P+C1 above P" true
      (rate pc1_fee pc1_w > rate p.Mempool.fee p.Mempool.weight);
    Alcotest.(check bool) "fixture: C0 below P+C1" true
      (rate e0.Mempool.fee e0.Mempool.weight < rate pc1_fee pc1_w);
    let jp = entry_json fx parent and j0 = entry_json fx c0
    and j1 = entry_json fx c1 in
    Alcotest.(check int) "P chunkweight = P+C1" pc1_w (field_int jp "chunkweight");
    Alcotest.(check int64) "P fees.chunk = P+C1" pc1_fee (chunk_fee_sats jp);
    Alcotest.(check int) "C1 chunkweight = P+C1" pc1_w (field_int j1 "chunkweight");
    Alcotest.(check int64) "C1 fees.chunk = P+C1" pc1_fee (chunk_fee_sats j1);
    Alcotest.(check int) "C0 chunkweight = C0" e0.Mempool.weight
      (field_int j0 "chunkweight");
    Alcotest.(check int64) "C0 fees.chunk = C0" e0.Mempool.fee (chunk_fee_sats j0);
    (* getrawmempool verbose (shared per-cluster memo) agrees. *)
    let verbose = match rpc_ok fx "getrawmempool" [ `Bool true ] with
      | `Assoc kv -> (match List.assoc_opt "result" kv with
          | Some (`Assoc m) -> m | _ -> Alcotest.fail "no verbose result")
      | _ -> Alcotest.fail "getrawmempool" in
    List.iter (fun (tx, w) ->
        match List.assoc_opt (Types.hash256_to_hex_display (txid tx)) verbose with
        | Some (`Assoc e) ->
          Alcotest.(check int) "getrawmempool chunkweight" w (field_int e "chunkweight")
        | _ -> Alcotest.fail "entry missing from getrawmempool")
      [ parent, pc1_w; c1, pc1_w; c0, e0.Mempool.weight ])

(* The warden_e shape: P with 63 children of rising fee.  The optimal chunk
   for P takes children by feerate, highest first, while each one is
   strictly above the running chunk feerate (Core v31.1: 23107 weight,
   0.01625 BTC on warden_e; deployed: P's own 8249 / 0.0001). *)
let test_chunk_feerate_star () =
  with_fx ~label:"mr_chunk_star" (fun fx ->
    let parent, names = parent_children_invalidate fx ~n:64 ~pad:20 ~fee_unit:1000 in
    let p = pool_entry fx parent in
    let kids = List.filter_map (fun (n, tx) ->
        if n <> "P" then Mempool.get fx.mp (txid tx) else None) names in
    let by_rate = List.sort (fun (a : Mempool.mempool_entry) b ->
        compare (Int64.to_float b.fee /. float_of_int b.weight)
          (Int64.to_float a.fee /. float_of_int a.weight)) kids in
    let rec grow f w = function
      | (k : Mempool.mempool_entry) :: rest
        when Int64.to_float k.fee /. float_of_int k.weight
             > Int64.to_float f /. float_of_int w ->
        grow (Int64.add f k.fee) (w + k.weight) rest
      | _ -> (f, w) in
    let f, w = grow p.Mempool.fee p.Mempool.weight by_rate in
    Printf.printf "  P own %d wu, expected chunk %d wu / %Ld sat\n%!"
      p.Mempool.weight w f;
    Alcotest.(check bool) "fixture: P's chunk includes children" true
      (w > p.Mempool.weight);
    let jp = entry_json fx parent in
    Alcotest.(check int) "P chunkweight" w (field_int jp "chunkweight");
    Alcotest.(check int64) "P fees.chunk" f (chunk_fee_sats jp))

(* The chunk comparison is exact: fee * weight overflows int64 for a
   whole-supply fee, and equal feerates never merge (strictly higher only,
   as in ChunkLinearization). *)
let test_feerate_gt_exact () =
  let big = 2_100_000_000_000_000L in
  Alcotest.(check bool) "big fee, lower rate" false
    (Mempool.feerate_gt (big, 4_000_000) (Int64.sub big 1L, 3_999_999));
  Alcotest.(check bool) "big fee, higher rate" true
    (Mempool.feerate_gt (Int64.sub big 1L, 3_999_999) (big, 4_000_000));
  Alcotest.(check bool) "equal rate is not higher" false
    (Mempool.feerate_gt (2L, 4) (1L, 2));
  Alcotest.(check bool) "negative modified fee below zero" true
    (Mempool.feerate_gt (0L, 400) (-5L, 400));
  Alcotest.(check bool) "two negatives" true
    (Mempool.feerate_gt (-1L, 400) (-5L, 400))

(* warden_d: a chain T0 <- cb1, T1 <- T0, T2 <- T1 confirmed at 111, 112,
   113; invalidateblock 111.  Core re-accepts after each DisconnectTip, so
   T2 enters at tip 112, T1 at 111, T0 at 110.  Deployed: all three at the
   final tip 110 (Core regtest warden_d rows: node 101 vs Core 102 / 103). *)
let test_invalidate_entry_height () =
  with_fx ~label:"mr_height" (fun fx ->
    let t0 = spend ~tag:50 fx.cb.(1) subsidy in
    let t1 = spend ~tag:51 (txid t0) (Int64.sub subsidy fee) in
    let t2 = spend ~tag:52 (txid t1) (Int64.sub subsidy (Int64.mul 2L fee)) in
    let blocks = List.mapi (fun k t -> build fx ~fee ~tag:0 (111 + k) [ t ])
        [ t0; t1; t2 ] in
    List.iter (connect fx) blocks;
    Alcotest.(check int) "tip 113" 113 fx.state.Sync.blocks_synced;
    ignore (rpc_ok fx "invalidateblock" [ hx (List.hd blocks) ]);
    Alcotest.(check int) "tip 110" 110 fx.state.Sync.blocks_synced;
    check_pool "pool after invalidateblock 111" [ "T0"; "T1"; "T2" ]
      (pool fx [ "T0", t0; "T1", t1; "T2", t2 ]);
    List.iter (fun (name, tx, h) ->
        Alcotest.(check int) (name ^ " entry height") h
          (field_int (entry_json fx tx) "height"))
      [ "T0", t0, 110; "T1", t1, 111; "T2", t2, 112 ])

let () =
  Alcotest.run "mempool_reorg" [
    "mempool vs chain", [
      Alcotest.test_case "catch-up connect: tip height + removeForBlock" `Quick
        test_catchup_height_and_remove;
      Alcotest.test_case "invalidateblock refill + reconsiderblock" `Quick
        test_invalidate_reconsider;
      Alcotest.test_case "P2P reorg: refill, conflicts, descendants" `Quick
        test_p2p_reorg;
      Alcotest.test_case "P2P reorg: removeForBlock raises after commit" `Quick
        test_p2p_reorg_remove_raises;
      Alcotest.test_case "invalidateblock: Trim an oversized cluster" `Quick
        test_invalidate_trims_oversized_cluster;
      Alcotest.test_case "invalidateblock: Trim an overweight cluster" `Quick
        test_invalidate_trims_overweight_cluster;
      Alcotest.test_case "invalidateblock: re-add only the top 10 blocks" `Quick
        test_deep_invalidate_caps_readd;
    ];
    "entry fields", [
      Alcotest.test_case "spentby in Core's GetChildren (txid) order" `Quick
        test_spentby_txid_order;
      Alcotest.test_case "chunkweight / fees.chunk: CPFP chunk" `Quick
        test_chunk_feerate_cpfp;
      Alcotest.test_case "chunkweight / fees.chunk: parent with 63 children" `Quick
        test_chunk_feerate_star;
      Alcotest.test_case "chunk feerate comparison is exact" `Quick
        test_feerate_gt_exact;
      Alcotest.test_case "invalidateblock re-add: entry height per block" `Quick
        test_invalidate_entry_height;
    ];
  ]
