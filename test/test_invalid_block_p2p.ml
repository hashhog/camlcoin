(* Invalid block over P2P: mark failed, never re-request, punish the sender.

   Instrument (meta tools/p2p-invalid-block-feed.py, 2026-10-03) on
   canonical 485e2a5, regtest, badcb and bip68:
     before: B1 requested 5x (2 after the decision), sender X never
             dropped; tip still reached B2'.
     after:  X never dropped; B1 / B2x never marked failed (reorg to B2x
             aborted, nothing recorded, retried on every block).

   Bitcoin Core: Chainstate::InvalidBlockFound (validation.cpp ~1988)
   marks BLOCK_FAILED_VALID (+ descendants BLOCK_FAILED_CHILD) and
   recalculates the best header; BlockChecked -> MaybePunishNodeForBlock
   (net_processing.cpp ~1906) punishes the delivering peer for
   BLOCK_CONSENSUS.  BLOCK_MUTATED and "cannot decide" errors are NOT
   marked.

     dune exec --no-buffer test/test_invalid_block_p2p.exe *)

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

(* [fee] > 0 overpays the coinbase: bad-cb-amount, a consensus verdict.
   [tag] makes siblings at the same height distinct. *)
let build_block ?(fee = 0L) ?(tag = 0) ?(txs = []) ~(prev_hash : Types.hash256)
    ~(height : int) ~(prev_time : int32) () : Types.block =
  let extra_nonce = Cstruct.create 8 in
  Cstruct.LE.set_uint64 extra_nonce 0 (Int64.of_int ((tag * 1_000_000) + height));
  let mk wr =
    Mining.create_coinbase ~height ~total_fee:fee ~payout_script:op_true
      ~extra_nonce ~witness_root:wr ~network_type:Consensus.Regtest ()
  in
  let witness_root = Mining.compute_witness_merkle_root (mk None :: txs) in
  let coinbase = mk (Some witness_root) in
  let all = coinbase :: txs in
  let merkle_root, _ = Crypto.merkle_root (List.map Crypto.compute_txid all) in
  remine
    { Types.header =
        { version = 4l; prev_block = prev_hash; merkle_root;
          timestamp = Int32.add prev_time 600l;
          bits = Consensus.regtest.pow_limit; nonce = 0l };
      transactions = all }

let hash_of (b : Types.block) = Crypto.compute_block_hash b.Types.header

let accept_hdr state (b : Types.block) =
  match Sync.validate_header state b.Types.header with
  | Ok e -> Sync.accept_header state e
  | Error "Header already known" -> ()
  | Error e -> Alcotest.failf "validate_header: %s" e

let deliver ?peer_id ?misbehavior_handler state b =
  Lwt_main.run
    (Sync.process_new_block ~f_requested:true ?peer_id ?misbehavior_handler
       state b)

(* A connected chain genesis..h3, FullySynced (the post-IBD shape the
   instrument's badcb prefix reaches). *)
let with_chain f =
  Test_tmp.with_dir ~label:"invalid_block_p2p" ~mkdir:true (fun path ->
    let db = Storage.ChainDB.create path in
    Fun.protect
      ~finally:(fun () -> try Storage.ChainDB.close db with _ -> ())
      (fun () ->
        let state = Sync.create_chain_state db Consensus.regtest in
        state.Sync.sync_state <- Sync.FullySynced;
        let genesis = Option.get state.Sync.tip in
        let prev = ref (genesis.Sync.hash, genesis.Sync.header.Types.timestamp) in
        for h = 1 to 3 do
          let b = build_block ~prev_hash:(fst !prev) ~height:h
              ~prev_time:(snd !prev) () in
          accept_hdr state b;
          (match deliver state b with
           | Ok () -> ()
           | Error e -> Alcotest.failf "prefix block %d: %s" h e);
          prev := (hash_of b, b.Types.header.Types.timestamp)
        done;
        Alcotest.(check int) "prefix connected" 3 state.Sync.blocks_synced;
        let punished = ref [] in
        let handler pid reason = punished := (pid, reason) :: !punished in
        f state (fst !prev) (snd !prev) punished handler))

let is_invalid state (b : Types.block) = Sync.is_block_invalid state (hash_of b)

let tip_hash state =
  match state.Sync.tip with Some t -> t.Sync.hash | None -> Types.zero_hash

let x = 2  (* attacker peer id *)
let h_peer = 0  (* honest peer id *)

(* before: B1 (invalid) is announced first and becomes the best header;
   B1' (valid, equal work) and then B2' arrive from H. *)
let test_before () =
  with_chain (fun state tip3 t3 punished handler ->
    let b1 = build_block ~fee:1L ~tag:1 ~prev_hash:tip3 ~height:4 ~prev_time:t3 () in
    let b1v = build_block ~tag:2 ~prev_hash:tip3 ~height:4 ~prev_time:t3 () in
    let b2v = build_block ~tag:2 ~prev_hash:(hash_of b1v) ~height:5
        ~prev_time:b1v.Types.header.Types.timestamp () in
    accept_hdr state b1;
    accept_hdr state b1v;
    Alcotest.(check bool) "B1 (first seen) is the best header" true
      (Cstruct.equal (tip_hash state) (hash_of b1));
    (match deliver ~peer_id:x ~misbehavior_handler:handler state b1 with
     | Ok () -> Alcotest.fail "invalid B1 was accepted"
     | Error _ -> ());
    Alcotest.(check bool) "B1 marked BLOCK_FAILED_VALID" true (is_invalid state b1);
    Alcotest.(check (list (pair int string)))
      "sender X punished (invalid_block) exactly once"
      [ (x, "invalid_block") ] !punished;
    Alcotest.(check bool) "best header moved off B1 to the valid sibling B1'"
      true (Cstruct.equal (tip_hash state) (hash_of b1v));
    let want = Sync.gapfill_blocks_to_download state in
    Alcotest.(check bool) "gap-fill never asks for B1 again" false
      (List.exists (Cstruct.equal (hash_of b1)) want);
    Alcotest.(check bool) "gap-fill asks for B1'" true
      (List.exists (Cstruct.equal (hash_of b1v)) want);
    (* A later relay of the cached-invalid block (inbound, Core
       BLOCK_CACHED_INVALID): not re-validated, not punished. *)
    punished := [];
    (match deliver ~peer_id:(x + 1) ~misbehavior_handler:handler state b1 with
     | Error "duplicate-invalid" -> ()
     | Error e -> Alcotest.failf "re-delivered B1 re-validated: %s" e
     | Ok () -> Alcotest.fail "re-delivered B1 accepted");
    Alcotest.(check (list (pair int string)))
      "re-relay of a cached-invalid block is not punished" [] !punished;
    (* A child header of B1 is bad-prevblk and never becomes a target. *)
    let b2x = build_block ~tag:1 ~prev_hash:(hash_of b1) ~height:5
        ~prev_time:b1.Types.header.Types.timestamp () in
    (match Sync.validate_header state b2x.Types.header with
     | Error "bad-prevblk" -> ()
     | Error e -> Alcotest.failf "child of B1: unexpected %s" e
     | Ok _ -> Alcotest.fail "child of failed B1 accepted as a header");
    (* H serves the valid chain: it connects. *)
    accept_hdr state b2v;
    (match deliver ~peer_id:h_peer ~misbehavior_handler:handler state b1v with
     | Ok () -> () | Error e -> Alcotest.failf "B1': %s" e);
    (match deliver ~peer_id:h_peer ~misbehavior_handler:handler state b2v with
     | Ok () -> () | Error e -> Alcotest.failf "B2': %s" e);
    Alcotest.(check int) "tip reached B2'" 5 state.Sync.blocks_synced;
    Alcotest.(check (list (pair int string))) "H never punished" [] !punished)

(* after: B1' is already the tip; X delivers B1 (equal work, stored as a
   side branch) then B2x on top of it (heavier).  The reorg to B2x fails
   at B1: both are marked, X is punished, the tip stays on B1'. *)
let test_after () =
  with_chain (fun state tip3 t3 punished handler ->
    let b1v = build_block ~tag:2 ~prev_hash:tip3 ~height:4 ~prev_time:t3 () in
    accept_hdr state b1v;
    (match deliver ~peer_id:h_peer ~misbehavior_handler:handler state b1v with
     | Ok () -> () | Error e -> Alcotest.failf "B1': %s" e);
    let b1 = build_block ~fee:1L ~tag:1 ~prev_hash:tip3 ~height:4 ~prev_time:t3 () in
    let b2x = build_block ~tag:1 ~prev_hash:(hash_of b1) ~height:5
        ~prev_time:b1.Types.header.Types.timestamp () in
    accept_hdr state b1;
    accept_hdr state b2x;
    ignore (deliver ~peer_id:x ~misbehavior_handler:handler state b1);
    ignore (deliver ~peer_id:x ~misbehavior_handler:handler state b2x);
    Alcotest.(check int) "validated tip stays at B1' height" 4
      state.Sync.blocks_synced;
    Alcotest.(check bool) "B1 marked failed after the failed reorg" true
      (is_invalid state b1);
    Alcotest.(check bool) "B2x marked failed (descendant)" true
      (is_invalid state b2x);
    Alcotest.(check bool) "best header back on B1'" true
      (Cstruct.equal (tip_hash state) (hash_of b1v));
    Alcotest.(check bool) "X (the source of B1) punished" true
      (List.mem (x, "invalid_block") !punished);
    Alcotest.(check bool) "H never punished" false
      (List.exists (fun (p, _) -> p = h_peer) !punished);
    Alcotest.(check bool) "gap-fill does not ask for B1 / B2x" true
      (not (List.exists
              (fun h -> Cstruct.equal h (hash_of b1) || Cstruct.equal h (hash_of b2x))
              (Sync.gapfill_blocks_to_download state))))

(* NON-verdict 1: a mutated body (same header, different transactions ->
   bad merkle root, Core BLOCK_MUTATED).  The header still names a valid
   block, so it must not be marked; the real body then connects.  Scoring
   is unchanged (Core MaybePunishNodeForBlock punishes BLOCK_MUTATED on a
   full-block delivery; camlcoin always scored a bad merkle root). *)
let test_mutated_not_marked () =
  with_chain (fun state tip3 t3 punished handler ->
    let b1v = build_block ~tag:2 ~prev_hash:tip3 ~height:4 ~prev_time:t3 () in
    let other = build_block ~tag:9 ~prev_hash:tip3 ~height:4 ~prev_time:t3 () in
    let mutated = { b1v with Types.transactions = other.Types.transactions } in
    accept_hdr state b1v;
    (match deliver ~peer_id:x ~misbehavior_handler:handler state mutated with
     | Ok () -> Alcotest.fail "mutated body accepted"
     | Error _ -> ());
    Alcotest.(check bool) "mutated body did NOT mark the header failed" false
      (is_invalid state b1v);
    Alcotest.(check (list (pair int string)))
      "bad-merkle delivery scored as before (Core: BLOCK_MUTATED, full block)"
      [ (x, "invalid_block") ] !punished;
    (match deliver ~peer_id:h_peer ~misbehavior_handler:handler state b1v with
     | Ok () -> () | Error e -> Alcotest.failf "real body after mutation: %s" e);
    Alcotest.(check int) "real body connects" 4 state.Sync.blocks_synced)

(* NON-verdict 2: ancestry-incomplete (297ab99 fail-closed deferral, the
   camlcoin analogue of the BIP68 missing-ancestor-header error): a local
   header-table defect is not a verdict on the block. *)
let test_ancestry_incomplete_not_marked () =
  with_chain (fun state tip3 t3 punished handler ->
    let b1 = build_block ~fee:1L ~tag:1 ~prev_hash:tip3 ~height:4 ~prev_time:t3 () in
    accept_hdr state b1;
    (* Drop the grandparent (height 2) from the in-memory header table:
       the MTP / nBits walk can no longer resolve the ancestry. *)
    let h2 = Option.get (Sync.get_ancestor state
                           (Option.get (Sync.get_header state tip3)) 2) in
    Hashtbl.remove state.Sync.headers (Cstruct.to_string h2.Sync.hash);
    (match deliver ~peer_id:x ~misbehavior_handler:handler state b1 with
     | Error e when Sync.is_ancestry_incomplete e -> ()
     | Error e -> Alcotest.failf "expected ancestry-incomplete, got %s" e
     | Ok () -> Alcotest.fail "block connected with incomplete ancestry");
    Alcotest.(check bool) "ancestry-incomplete did NOT mark the block" false
      (is_invalid state b1);
    Alcotest.(check (list (pair int string))) "peer not scored" [] !punished)

(* NON-verdict 3: fdcee86's fail-closed BIP68 coin time.  The block spends
   a coin with a TIME-based relative lock (BIP68); the coin's MTP window
   (heights 0..coin_height-1) is resolved through the spending block's
   ancestry by [Sync.checked_coin_mtp_lookup].  With a header of that
   window missing from the table the lookup returns 0xFFFFFFFF (lock reads
   unsatisfied -> accept_block says TxSequenceLocksFailed) AND sets the
   probe.  The probe must win: the block is NOT marked failed, the peer is
   NOT scored, and once the header is back the same block connects.  If a
   connect path misclassified the probe miss as a verdict, this block would
   be marked bad-txns-nonfinal for good — a valid block rejected forever. *)
let test_bip68_coin_time_missing_header_not_marked () =
  Test_tmp.with_dir ~label:"invalid_block_p2p_bip68" ~mkdir:true (fun path ->
    let db = Storage.ChainDB.create path in
    Fun.protect
      ~finally:(fun () -> try Storage.ChainDB.close db with _ -> ())
      (fun () ->
        let state = Sync.create_chain_state db Consensus.regtest in
        state.Sync.sync_state <- Sync.FullySynced;
        let genesis = Option.get state.Sync.tip in
        let coin_height = 5 in
        let tip_h = coin_height + 100 in   (* coinbase maturity *)
        let prev = ref (genesis.Sync.hash, genesis.Sync.header.Types.timestamp) in
        let coin_cb = ref None in
        for h = 1 to tip_h do
          let b = build_block ~prev_hash:(fst !prev) ~height:h
              ~prev_time:(snd !prev) () in
          if h = coin_height then coin_cb := Some (List.hd b.Types.transactions);
          accept_hdr state b;
          (match deliver state b with
           | Ok () -> ()
           | Error e -> Alcotest.failf "prefix block %d: %s" h e);
          prev := (hash_of b, b.Types.header.Types.timestamp)
        done;
        let cb = Option.get !coin_cb in
        let spend : Types.transaction = {
          Types.version = 2l;
          inputs = [ { Types.previous_output =
                         { Types.txid = Crypto.compute_txid cb; vout = 0l };
                       script_sig = Cstruct.empty;
                       (* type flag (1 lsl 22) | 1 unit = 512 s *)
                       sequence = 0x00400001l } ];
          outputs = [ { Types.value = 49_00000000L; script_pubkey = op_true } ];
          witnesses = []; locktime = 0l } in
        let b = build_block ~txs:[ spend ] ~prev_hash:(fst !prev)
            ~height:(tip_h + 1) ~prev_time:(snd !prev) () in
        accept_hdr state b;
        (* Drop the header at height 2 (inside the coin's MTP window 0..4,
           far below the block's own 11-header MTP window). *)
        let tip_e = Option.get (Sync.get_header state (fst !prev)) in
        let h2 = Option.get (Sync.get_ancestor state tip_e 2) in
        let h2_key = Cstruct.to_string h2.Sync.hash in
        Hashtbl.remove state.Sync.headers h2_key;
        let punished = ref [] in
        let handler pid reason = punished := (pid, reason) :: !punished in
        (match deliver ~peer_id:x ~misbehavior_handler:handler state b with
         | Error e when Sync.is_ancestry_incomplete e -> ()
         | Error e -> Alcotest.failf "expected ancestry-incomplete, got %s" e
         | Ok () -> Alcotest.fail "connected without the coin's MTP window");
        Alcotest.(check bool) "BIP68 coin-time miss did NOT mark the block" false
          (is_invalid state b);
        Alcotest.(check (list (pair int string))) "peer not scored" [] !punished;
        Alcotest.(check bool) "best header still the block (retry target)" true
          (Cstruct.equal (tip_hash state) (hash_of b));
        (* Retry: header back, the same block connects (lock satisfied). *)
        Hashtbl.replace state.Sync.headers h2_key h2;
        (match deliver ~peer_id:x ~misbehavior_handler:handler state b with
         | Ok () -> ()
         | Error e -> Alcotest.failf "retry after header restored: %s" e);
        Alcotest.(check int) "retry connected the block" (tip_h + 1)
          state.Sync.blocks_synced))

let () =
  Alcotest.run "invalid_block_p2p"
    [ ( "verdict",
        [ Alcotest.test_case "before: B1 failed, sender punished, sibling fetched"
            `Quick test_before;
          Alcotest.test_case "after: failed reorg marks B1+B2x, punishes source"
            `Quick test_after ] );
      ( "non-verdict",
        [ Alcotest.test_case "mutated body is not marked" `Quick
            test_mutated_not_marked;
          Alcotest.test_case "ancestry-incomplete is not marked" `Quick
            test_ancestry_incomplete_not_marked;
          Alcotest.test_case "BIP68 coin-time missing header is not marked"
            `Quick test_bip68_coin_time_missing_header_not_marked ] ) ]
