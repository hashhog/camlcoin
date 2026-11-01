(* Compact_relay: what a cmpctblock may store, and how long it lives
   (security audit 2026-10-31 C3; Core net_processing.cpp CMPCTBLOCK).
   test/cmpctblock_pending drives the same code through bin/main.exe; this
   file covers what that cannot see: table size, expiry, disconnect, the
   per-block and high-bandwidth rules, and the header gate's verdicts. *)

open Camlcoin

let op_true = Cstruct.of_string "\x51"

let remine (h : Types.block_header) =
  let h = ref h and n = ref 0l in
  while not (Consensus.hash_meets_target (Crypto.compute_block_hash !h)
               !h.Types.bits) do
    n := Int32.add !n 1l; h := { !h with Types.nonce = !n }
  done;
  !h

let build_block ?(tag = 0) ~prev_hash ~height ~prev_time () : Types.block =
  let extra_nonce = Cstruct.create 8 in
  Cstruct.LE.set_uint64 extra_nonce 0 (Int64.of_int ((tag * 1_000_000) + height));
  let mk wr =
    Mining.create_coinbase ~height ~total_fee:0L ~payout_script:op_true
      ~extra_nonce ~witness_root:wr ~network_type:Consensus.Regtest ()
  in
  let coinbase = mk (Some (Mining.compute_witness_merkle_root [ mk None ])) in
  let merkle_root, _ = Crypto.merkle_root [ Crypto.compute_txid coinbase ] in
  { Types.header =
      remine { version = 4l; prev_block = prev_hash; merkle_root;
               timestamp = Int32.add prev_time 600l;
               bits = Consensus.regtest.pow_limit; nonce = 0l };
    transactions = [ coinbase ] }

let hash_of (b : Types.block) = Crypto.compute_block_hash b.Types.header

(* genesis..h2 connected, FullySynced. *)
let with_chain f =
  Test_tmp.with_dir ~label:"compact_relay" ~mkdir:true (fun path ->
    let db = Storage.ChainDB.create path in
    Fun.protect ~finally:(fun () -> try Storage.ChainDB.close db with _ -> ())
      (fun () ->
        let chain = Sync.create_chain_state db Consensus.regtest in
        chain.Sync.sync_state <- Sync.FullySynced;
        let g = Option.get chain.Sync.tip in
        let prev = ref (g.Sync.hash, g.Sync.header.Types.timestamp) in
        for h = 1 to 2 do
          let b = build_block ~prev_hash:(fst !prev) ~height:h
              ~prev_time:(snd !prev) () in
          (match Sync.validate_header chain b.Types.header with
           | Ok e -> Sync.accept_header chain e
           | Error e -> Alcotest.failf "header %d: %s" h e);
          (match Lwt_main.run
                   (Sync.process_new_block ~f_requested:true chain b) with
           | Ok () -> ()
           | Error e -> Alcotest.failf "block %d: %s" h e);
          prev := (hash_of b, b.Types.header.Types.timestamp)
        done;
        f chain (fst !prev) (snd !prev)))

let no_mempool cb = P2p.reconstruct_block cb { P2p.by_short_id = Hashtbl.create 0 }

let cmpct ?(short_ids = [ 1L; 2L ]) header =
  { P2p.header; nonce = 7L; short_ids; prefilled_txs = [] }

let child ~tag tip t = (build_block ~tag ~prev_hash:tip ~height:3 ~prev_time:t ()).Types.header

let on t chain ?(peer_hb = false) ?(now = 1000.0) peer_id cb =
  Compact_relay.on_cmpctblock t chain ~peer_id ~peer_hb ~now
    ~reconstruct:no_mempool cb

let is_request = function Compact_relay.Request_txns _ -> true | _ -> false

let test_random_header_keeps_nothing () =
  with_chain (fun chain _ _ ->
    let t = Compact_relay.create () in
    for i = 1 to 50 do
      let hdr = { Types.version = 0x20000000l;
                  prev_block = Crypto.sha256d (Cstruct.of_string (string_of_int i));
                  merkle_root = Types.zero_hash; timestamp = 1l;
                  bits = 0x207fffffl; nonce = Int32.of_int i } in
      (match on t chain 1 (cmpct hdr) with
       | Compact_relay.Send_getheaders -> ()
       | _ -> Alcotest.fail "unknown parent must get getheaders")
    done;
    Alcotest.(check int) "random headers: table empty" 0 (Compact_relay.size t))

let test_bad_pow_known_parent () =
  with_chain (fun chain tip t2 ->
    let t = Compact_relay.create () in
    let good = child ~tag:1 tip t2 in
    (* Find a nonce whose hash misses the regtest target. *)
    let rec bad n =
      let h = { good with Types.nonce = n } in
      if Consensus.hash_meets_target (Crypto.compute_block_hash h) h.Types.bits
      then bad (Int32.add n 1l) else h in
    (match on t chain 1 (cmpct (bad 0l)) with
     | Compact_relay.Invalid_header _ -> ()
     | _ -> Alcotest.fail "bad-PoW header must be Invalid_header");
    Alcotest.(check int) "bad PoW: table empty" 0 (Compact_relay.size t))

let test_per_peer_cap () =
  with_chain (fun chain tip t2 ->
    let t = Compact_relay.create () in
    let stored = ref 0 in
    for tag = 1 to 20 do
      if is_request (on t chain 1 (cmpct (child ~tag tip t2))) then incr stored
    done;
    Alcotest.(check int) "20 valid headers from one peer: 3 stored"
      Compact_relay.max_pending_per_peer !stored;
    Alcotest.(check int) "table holds the cap"
      Compact_relay.max_pending_per_peer (Compact_relay.size t))

let test_per_block_and_hb () =
  with_chain (fun chain tip t2 ->
    let t = Compact_relay.create () in
    let cb = cmpct (child ~tag:1 tip t2) in
    Alcotest.(check bool) "first peer in flight: getblocktxn" true
      (is_request (on t chain 1 cb));
    Alcotest.(check bool) "same peer again: ignored" false
      (is_request (on t chain 1 cb));
    Alcotest.(check bool) "second, non-HB peer: ignored" false
      (is_request (on t chain 2 cb));
    Alcotest.(check bool) "second, HB peer: getblocktxn" true
      (is_request (on t chain ~peer_hb:true 3 cb));
    Alcotest.(check bool) "third, HB peer: last slot kept back" false
      (is_request (on t chain ~peer_hb:true 4 cb));
    Alcotest.(check int) "block held by 2 peers" 2
      (Compact_relay.peers_for_block t (Crypto.compute_block_hash cb.P2p.header)))

let test_expiry_and_disconnect () =
  with_chain (fun chain tip t2 ->
    let t = Compact_relay.create ~timeout:60.0 () in
    ignore (on t chain ~now:1000.0 1 (cmpct (child ~tag:1 tip t2)));
    ignore (on t chain ~now:1000.0 2 (cmpct (child ~tag:2 tip t2)));
    ignore (on t chain ~now:1030.0 2 (cmpct (child ~tag:3 tip t2)));
    Alcotest.(check int) "three entries" 3 (Compact_relay.size t);
    Alcotest.(check int) "peer 2 disconnects: its 2 entries go" 2
      (Compact_relay.remove_peer t 2);
    Alcotest.(check int) "peer 1 left" 1 (Compact_relay.size t);
    Alcotest.(check int) "expired after the timeout" 1
      (Compact_relay.expire t ~now:1061.0);
    Alcotest.(check int) "table empty" 0 (Compact_relay.size t))

let test_tip_rules () =
  with_chain (fun chain tip t2 ->
    let t = Compact_relay.create () in
    (* Sibling of the tip: equal work, not more. *)
    let tip_entry = Option.get (Sync.get_header chain tip) in
    let parent = tip_entry.Sync.header.Types.prev_block in
    let pt = (Option.get (Sync.get_header chain parent)).Sync.header.Types.timestamp in
    let sib = (build_block ~tag:9 ~prev_hash:parent ~height:2 ~prev_time:pt ()).Types.header in
    (match on t chain 1 (cmpct sib) with
     | Compact_relay.Ignore _ -> ()
     | _ -> Alcotest.fail "sibling of the tip must be ignored");
    (* tip+3: headers accepted, nothing kept. *)
    let h3 = build_block ~tag:1 ~prev_hash:tip ~height:3 ~prev_time:t2 () in
    let h4 = build_block ~tag:1 ~prev_hash:(hash_of h3) ~height:4
        ~prev_time:h3.Types.header.Types.timestamp () in
    let h5 = build_block ~tag:1 ~prev_hash:(hash_of h4) ~height:5
        ~prev_time:h4.Types.header.Types.timestamp () in
    List.iter (fun (b : Types.block) ->
      match Sync.validate_header chain b.Types.header with
      | Ok e -> Sync.accept_header chain e
      | Error e -> Alcotest.failf "hdr: %s" e) [ h3; h4 ];
    (match on t chain 1 (cmpct h5.Types.header) with
     | Compact_relay.Ignore _ -> ()
     | _ -> Alcotest.fail "tip+3 must not be stored");
    Alcotest.(check int) "nothing stored" 0 (Compact_relay.size t))

let test_blocktxn_bound_to_peer () =
  with_chain (fun chain tip t2 ->
    let t = Compact_relay.create () in
    let b = build_block ~tag:1 ~prev_hash:tip ~height:3 ~prev_time:t2 () in
    (* The coinbase announced by short id, so the block needs a round trip. *)
    let cb = { (P2p.create_compact_block b) with P2p.prefilled_txs = [] } in
    let cb = { cb with P2p.short_ids = [ 5L ] } in
    Alcotest.(check bool) "stored for peer 1" true (is_request (on t chain 1 cb));
    let resp = { P2p.block_hash = hash_of b; txs = b.Types.transactions } in
    (match Compact_relay.on_blocktxn t ~peer_id:2 ~now:1000.0 resp with
     | Compact_relay.Unexpected -> ()
     | _ -> Alcotest.fail "blocktxn from peer 2 must not complete peer 1's entry");
    Alcotest.(check int) "peer 1's entry survives" 1 (Compact_relay.size t);
    (match Compact_relay.on_blocktxn t ~peer_id:1 ~now:1000.0 resp with
     | Compact_relay.Txn_connect blk ->
       Alcotest.(check bool) "reconstructed block = original" true
         (Cstruct.equal (hash_of blk) (hash_of b)
          && List.length blk.Types.transactions = 1)
     | _ -> Alcotest.fail "blocktxn from the asking peer must complete");
    Alcotest.(check int) "entry consumed" 0 (Compact_relay.size t))

let test_valid_complete_connects () =
  with_chain (fun chain tip t2 ->
    let t = Compact_relay.create () in
    let b = build_block ~tag:1 ~prev_hash:tip ~height:3 ~prev_time:t2 () in
    match on t chain 1 (P2p.create_compact_block b) with
    | Compact_relay.Connect blk ->
      (match Lwt_main.run (Sync.process_new_block ~f_requested:true chain blk) with
       | Ok () -> Alcotest.(check int) "connected" 3 chain.Sync.blocks_synced
       | Error e -> Alcotest.failf "connect: %s" e)
    | _ -> Alcotest.fail "coinbase-only compact block must reconstruct")

let test_duplicate_short_ids () =
  let b = build_block ~prev_hash:Types.zero_hash ~height:1 ~prev_time:0l () in
  let cb = { (P2p.create_compact_block b) with P2p.short_ids = [ 9L; 9L ] } in
  match P2p.reconstruct_block cb { P2p.by_short_id = Hashtbl.create 0 } with
  | P2p.ReconstructFailed _ -> ()
  | _ -> Alcotest.fail "duplicate short ids must fail reconstruction"

let test_fill_missing_order () =
  let b = build_block ~prev_hash:Types.zero_hash ~height:1 ~prev_time:0l () in
  let tx = List.hd b.Types.transactions in
  let tx2 = { tx with Types.locktime = 1l } and tx3 = { tx with Types.locktime = 2l } in
  let partial = [| Some tx; None; None |] in
  match P2p.fill_missing_txs (P2p.create_compact_block b) partial [ 1; 2 ] [ tx2; tx3 ] with
  | Ok blk ->
    Alcotest.(check (list int32)) "slots filled in order" [ 0l; 1l; 2l ]
      (List.map (fun t -> t.Types.locktime) blk.Types.transactions)
  | Error e -> Alcotest.fail e

let () =
  Alcotest.run "compact_relay"
    [ "gate",
      [ Alcotest.test_case "random header keeps nothing" `Quick
          test_random_header_keeps_nothing;
        Alcotest.test_case "bad PoW on a known parent" `Quick test_bad_pow_known_parent;
        Alcotest.test_case "tip rules" `Quick test_tip_rules;
        Alcotest.test_case "valid compact block connects" `Quick
          test_valid_complete_connects ];
      "table",
      [ Alcotest.test_case "per-peer cap" `Quick test_per_peer_cap;
        Alcotest.test_case "per-block cap and HB" `Quick test_per_block_and_hb;
        Alcotest.test_case "expiry and disconnect" `Quick test_expiry_and_disconnect;
        Alcotest.test_case "blocktxn bound to peer" `Quick test_blocktxn_bound_to_peer ];
      "p2p",
      [ Alcotest.test_case "duplicate short ids" `Quick test_duplicate_short_ids;
        Alcotest.test_case "fill_missing_txs order" `Quick test_fill_missing_order ] ]
