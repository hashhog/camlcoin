(* Reorg-connect undo-data proof for INTRA-BLOCK transaction chains (camlcoin).

   Regression for: "the reorg connect path rebuilt undo data from an
   overlay-then-disk reader, which cannot see THIS block's own outputs".

   [Sync.connect_block_into_batch] (the reorg half of the pipeline) used to
   build its undo record like this:

     let tx_undos = List.filter_map (fun (tx_idx, tx) ->
       if tx_idx > 0 then begin
         let spent = List.filter_map (fun inp ->
           lookup_utxo_entry inp.Types.previous_output
         ) tx.Types.inputs in
         Some Utxo.{ spent_outputs = spent }
       end else None) ...

   [lookup_utxo_entry] consults the reorg overlay and then disk.  NEITHER
   holds the outputs created by the block being connected.  Bitcoin permits a
   transaction to spend an output created by an EARLIER transaction in the
   SAME block (an "intra-block chain"; the only rule is creator-before-
   spender, and real blocks are full of them).  For such an input the lookup
   returned [None] and [List.filter_map] SILENTLY DROPPED it — so that
   transaction's [spent_outputs] came out SHORTER than its input list.

   That is fatal on the way back out.  camlcoin's disconnect path
   ([Sync.disconnect_block_into_batch], the "tx and undo inconsistent" check)
   REQUIRES exactly one undo entry per input:

     let n_inputs = List.length inputs in
     let n_undos  = List.length tx_undo.Utxo.spent_outputs in
     if n_undos <> n_inputs then fatal := Some "DisconnectBlock: tx and undo
       inconsistent ..."

   So a short undo list makes any LATER disconnect of that block abort the
   whole reorg.  It also under-feeds [spent_entries], which drives the BIP-157
   filter index and the coin-stats index.

   The fix takes validation's [spent_utxo_list] from the [AB_ok] arm (which IS
   intra-block correct — validation resolves through its per-block
   [local_utxos] overlay) and regroups it per transaction with the same cursor
   walk the IBD connect path already uses.

   ---------------------------------------------------------------------------
   WHAT THIS HARNESS DOES

   Both scenarios drive the REAL daemon pipeline
   (Mining.submit_block -> Sync.try_attach_side_branch_and_reorg ->
    Sync.reorganize -> connect_block_into_batch / disconnect_block_into_batch):

     1. mine chain A to height 110 (coinbase-only, OP_TRUE payouts),
     2. build side branch B forking at height 105, whose FIRST block
        (height 106) is [coinbase; txA; txB] — NOT coinbase-only, which is
        exactly the gap that let this bug survive the existing reorg tests,
     3. make branch B strictly heavier (height 111) so a single
        [Sync.reorganize] connects it,
     4. read the undo record written for that block and assert
        [List.length tx_undo.spent_outputs = List.length tx.inputs] per tx,
     5. build branch C forking at the SAME height 105 and make it heavier
        still (height 112) so the reorg-back DISCONNECTS the block from (2)
        through the live path, and assert it does not hit the
        "tx and undo inconsistent" fatal,
     6. assert the UTXO set is restored byte-for-byte (the pre-existing coins
        come back, the block's own outputs are gone).

   The two scenarios differ ONLY in txB's single input:

     MAIN    (chained)     txB spends txA:0  -> an INTRA-BLOCK chain.
                           Pre-fix: undo is short by one -> disconnect fatal.
     CONTROL (not chained) txB spends cb2:0, a different, already-on-disk
                           mature coinbase.  Same block shape, same tx count,
                           same code path — but every prevout IS resolvable
                           from disk, so it must PASS BOTH pre-fix and
                           post-fix.  That is what attributes the MAIN
                           failure to the intra-block chain rather than to
                           the harness setup.

   Coinbase maturity is 100 blocks, so txA spends the height-1 coinbase in a
   block at height 106 (105 confirmations) and the control's txB spends the
   height-2 coinbase (104 confirmations).  Both fork parents are at height
   105, below the fork point, so those coins survive every reorg here.

   Scratch DBs go under [CAMLCOIN_TEST_TMPDIR] (or TMPDIR via
   [Filename.get_temp_dir_name]) and are removed on exit. *)

open Camlcoin

(* ------------------------------------------------------------------ setup *)

let scratch_base =
  match Sys.getenv_opt "CAMLCOIN_TEST_TMPDIR" with
  | Some d when d <> "" -> d
  | _ -> Filename.get_temp_dir_name ()

let rm_rf path =
  let rec go p =
    if Sys.file_exists p then
      if Sys.is_directory p then begin
        Array.iter (fun f -> go (Filename.concat p f)) (Sys.readdir p);
        (try Unix.rmdir p with _ -> ())
      end else (try Unix.unlink p with _ -> ())
  in
  go path

(* OP_TRUE — anyone-can-spend scriptPubKey; an empty scriptSig satisfies it. *)
let op_true = Cstruct.of_string "\x51"

(* Re-mine the nonce of a hand-assembled header against the easy regtest
   target. *)
let remine (block : Types.block) : Types.block =
  let h = ref block.Types.header in
  let n = ref 0l in
  let found = ref false in
  while not !found && Int32.compare !n 5_000_000l < 0 do
    h := { !h with Types.nonce = !n };
    if Consensus.hash_meets_target (Crypto.compute_block_hash !h) !h.Types.bits
    then found := true
    else n := Int32.add !n 1l
  done;
  if not !found then failwith "remine: no nonce found";
  { block with Types.header = !h }

let chain_a_height = 110
let fork_height = 105
let branch_b_tip = 111   (* strictly heavier than chain A *)
let branch_c_tip = 112   (* strictly heavier than branch B *)
let spend_height = fork_height + 1  (* 106 — the block with txA/txB *)

let hexs (h : Types.hash256) = Types.hash256_to_hex_display h

(* --------------------------------------------------------------- scenario *)

type outcome = {
  label : string;
  failures : string list;   (* empty = PASS *)
}

let run_scenario ~(label : string) ~(chained : bool) : outcome =
  let tag = if chained then "chained" else "control" in
  let db_path =
    Filename.concat scratch_base
      (Printf.sprintf "camlcoin-intrablock-undo-%s-%d-db" tag (Unix.getpid ())) in
  let rocksdb_path = db_path ^ "_rocksdb_utxo" in
  let cleanup () = rm_rf db_path; rm_rf rocksdb_path in
  cleanup ();

  let failures = ref [] in
  let fail fmt = Printf.ksprintf (fun s ->
    failures := !failures @ [ s ];
    Printf.printf "  FAIL  %s\n%!" s) fmt in
  let ok fmt = Printf.ksprintf (fun s -> Printf.printf "  ok    %s\n%!" s) fmt in
  let info fmt = Printf.ksprintf (fun s -> Printf.printf "        %s\n%!" s) fmt in

  Printf.printf "\n=== SCENARIO: %s ===\n%!" label;

  let db = Storage.ChainDB.create db_path in
  let chain = Sync.create_chain_state db Consensus.regtest in
  let rocksdb = Rocksdb_store.open_db rocksdb_path in
  Storage.ChainDB.attach_rocksdb_utxo db rocksdb;
  let optimized =
    Utxo.OptimizedUtxoSet.create ~cache_size:65536 ~rocksdb db in
  let utxo = Utxo.UtxoSet.create db in
  let mp = Mempool.create ~network:Consensus.regtest
    ~require_standard:false ~verify_scripts:false ~utxo ~current_height:0 () in

  let submit (b : Types.block) : (unit, string) result =
    Mining.submit_block ~utxo:optimized
      ~network_type:Consensus.Regtest b chain mp
  in
  let submit_ok what (b : Types.block) : unit =
    match submit b with
    | Ok () -> ()
    | Error e -> failwith (Printf.sprintf "submit_block(%s) failed: %s" what e)
  in

  (* --- chain A: mine [chain_a_height] coinbase-only blocks. --- *)
  let mine_on_tip () : Types.block =
    let tmpl = Mining.create_block_template ~chain ~mp ~payout_script:op_true in
    match Mining.mine_block tmpl 5_000_000l with
    | Some b -> b
    | None -> failwith "mine_block (tip) failed"
  in
  let cb1 = ref None and cb2 = ref None in
  for h = 1 to chain_a_height do
    let b = mine_on_tip () in
    if h = 1 then cb1 := Some (List.hd b.Types.transactions);
    if h = 2 then cb2 := Some (List.hd b.Types.transactions);
    submit_ok (Printf.sprintf "chainA h=%d" h) b
  done;
  let cb1 = match !cb1 with Some t -> t | None -> failwith "no cb1" in
  let cb2 = match !cb2 with Some t -> t | None -> failwith "no cb2" in
  let cb1_txid = Crypto.compute_txid cb1 in
  let cb2_txid = Crypto.compute_txid cb2 in
  let cb1_value = (List.hd cb1.Types.outputs).Types.value in
  let cb2_value = (List.hd cb2.Types.outputs).Types.value in
  (match chain.Sync.tip with
   | Some t when t.Sync.height = chain_a_height -> ()
   | _ -> failwith "chain A did not reach the expected height");
  ok "chain A mined to height %d (coinbase-1 and coinbase-2 mature)" chain_a_height;

  (* Byte-exact snapshots of the two coins the side branch will spend. *)
  let pre_cb1 = Storage.ChainDB.get_utxo db cb1_txid 0 in
  let pre_cb2 = Storage.ChainDB.get_utxo db cb2_txid 0 in
  if pre_cb1 = None then failwith "coinbase-1:0 unexpectedly absent from the UTXO set";
  if pre_cb2 = None then failwith "coinbase-2:0 unexpectedly absent from the UTXO set";

  (* --- the two spends that go INSIDE the side-branch block ---
     txA always spends coinbase-1:0 (on disk, matured).
     txB spends txA:0 in the MAIN scenario (intra-block chain) and
     coinbase-2:0 in the CONTROL (also on disk, matured). *)
  let mk_tx ~(prevout : Types.outpoint) ~(value : int64) : Types.transaction =
    { Types.version = 2l;
      inputs = [ { previous_output = prevout;
                   script_sig = Cstruct.create 0;     (* OP_TRUE needs none *)
                   sequence = 0xffffffffl } ];
      outputs = [ { value; script_pubkey = op_true } ];
      witnesses = []; locktime = 0l }
  in
  let tx_a = mk_tx ~prevout:{ Types.txid = cb1_txid; vout = 0l }
      ~value:(Int64.sub cb1_value 1000L) in
  let tx_a_txid = Crypto.compute_txid tx_a in
  let tx_b =
    if chained then
      mk_tx ~prevout:{ Types.txid = tx_a_txid; vout = 0l }
        ~value:(Int64.sub cb1_value 2000L)
    else
      mk_tx ~prevout:{ Types.txid = cb2_txid; vout = 0l }
        ~value:(Int64.sub cb2_value 1000L)
  in
  let tx_b_txid = Crypto.compute_txid tx_b in
  info "txA = %s (spends coinbase-1:0)" (hexs tx_a_txid);
  info "txB = %s (spends %s)" (hexs tx_b_txid)
    (if chained then "txA:0  <-- INTRA-BLOCK CHAIN"
     else "coinbase-2:0  <-- pre-existing on-disk coin");

  (* --- deterministic block builder off an arbitrary parent. --- *)
  let fork_parent =
    match Sync.get_header_at_height chain fork_height with
    | Some e -> e | None -> failwith "fork parent missing" in
  let fork_ts = fork_parent.Sync.header.Types.timestamp in
  let build_block ~(prev_hash : Types.hash256) ~(height : int)
      ~(branch_tag : int) (txs : Types.transaction list) : Types.block =
    let extra_nonce = Cstruct.create 8 in
    Cstruct.LE.set_uint64 extra_nonce 0
      (Int64.of_int (height * 1000 + branch_tag));
    let placeholder_cb =
      Mining.create_coinbase ~height ~total_fee:0L ~payout_script:op_true
        ~extra_nonce ~witness_root:None ~network_type:Consensus.Regtest () in
    let witness_root =
      Mining.compute_witness_merkle_root (placeholder_cb :: txs) in
    let coinbase =
      Mining.create_coinbase ~height ~total_fee:0L ~payout_script:op_true
        ~extra_nonce ~witness_root:(Some witness_root)
        ~network_type:Consensus.Regtest () in
    let all = coinbase :: txs in
    let (merkle_root, _) =
      Crypto.merkle_root (List.map Crypto.compute_txid all) in
    let header : Types.block_header =
      { version = 4l; prev_block = prev_hash; merkle_root;
        (* strictly increasing per branch, and above the fork parent's MTP *)
        timestamp = Int32.add fork_ts
            (Int32.of_int (2 * (height - fork_height) + branch_tag));
        bits = Consensus.regtest.pow_limit; nonce = 0l } in
    remine { Types.header; transactions = all }
  in

  (* --- branch B: 106..111 off the height-105 fork parent.
         Block 106 carries [coinbase; txA; txB]. --- *)
  let b_blocks = ref [] in
  let prev = ref fork_parent.Sync.hash in
  for h = spend_height to branch_b_tip do
    let txs = if h = spend_height then [ tx_a; tx_b ] else [] in
    let blk = build_block ~prev_hash:!prev ~height:h ~branch_tag:1 txs in
    b_blocks := blk :: !b_blocks;
    prev := Crypto.compute_block_hash blk.Types.header
  done;
  let b_blocks = List.rev !b_blocks in
  let spend_blk = List.hd b_blocks in
  let spend_blk_hash = Crypto.compute_block_hash spend_blk.Types.header in
  if List.length spend_blk.Types.transactions <> 3 then
    failwith "the side-branch block should be [coinbase; txA; txB]";

  (* 106..110 are equal-or-lighter than chain A's tip -> stored, no reorg.
     111 is strictly heavier -> a single Sync.reorganize. *)
  let n_b = List.length b_blocks in
  List.iteri (fun i b ->
    if i < n_b - 1 then submit_ok (Printf.sprintf "branchB h=%d" (spend_height + i)) b)
    b_blocks;
  if chain.Sync.blocks_synced <> chain_a_height then
    failwith (Printf.sprintf
      "branch B prefix unexpectedly reorged (blocks_synced=%d, want %d)"
      chain.Sync.blocks_synced chain_a_height);
  ok "branch B prefix %d..%d stored as inactive side branch (no reorg yet)"
    spend_height (branch_b_tip - 1);

  let connect_err = ref None in
  (match submit (List.nth b_blocks (n_b - 1)) with
   | Ok () -> ()
   | Error e -> connect_err := Some e);
  (match !connect_err with
   | Some e ->
     fail "REORG ONTO BRANCH B FAILED (connect side): %s" e
   | None ->
     (match chain.Sync.tip with
      | Some t when t.Sync.height = branch_b_tip ->
        ok "reorg fired: tip flipped to branch B height %d" branch_b_tip
      | Some t -> fail "reorg did not reach branch B tip (height=%d)" t.Sync.height
      | None -> fail "no tip after reorg onto branch B"));

  (* ---------------- ASSERTION 1: the undo record is well formed. ---------- *)
  let undo_opt =
    match Storage.ChainDB.get_undo_data db spend_blk_hash with
    | None -> None
    | Some raw ->
      (try
         let r = Serialize.reader_of_cstruct (Cstruct.of_string raw) in
         Some (Utxo.deserialize_undo_data r)
       with e ->
         fail "undo data for the spend block failed to deserialize: %s"
           (Printexc.to_string e);
         None)
  in
  (match undo_opt with
   | None ->
     if !connect_err = None then
       fail "no undo data stored for the reorg-connected spend block %s"
         (hexs spend_blk_hash)
   | Some undo ->
     let txs = Array.of_list spend_blk.Types.transactions in
     let tus = Array.of_list undo.Utxo.tx_undos in
     if Array.length tus <> Array.length txs - 1 then
       fail "undo group count = %d, expected %d (one per non-coinbase tx)"
         (Array.length tus) (Array.length txs - 1)
     else
       Array.iteri (fun i tu ->
         let tx_idx = i + 1 in
         let n_inputs = List.length txs.(tx_idx).Types.inputs in
         let n_undos = List.length tu.Utxo.spent_outputs in
         let name = if tx_idx = 1 then "txA" else "txB" in
         if n_undos <> n_inputs then
           fail "undo for %s (tx %d) is MALFORMED: inputs=%d undos=%d \
                 (spent_outputs is short by %d — the intra-block prevout was \
                 silently dropped by List.filter_map)"
             name tx_idx n_inputs n_undos (n_inputs - n_undos)
         else
           ok "undo for %s (tx %d): inputs=%d undos=%d" name tx_idx n_inputs n_undos
       ) tus;
     (* The undo entry for txB must name txB's actual prevout. *)
     if Array.length tus = 2 then begin
       match (tus.(1)).Utxo.spent_outputs with
       | [ (op, entry) ] ->
         let want = (List.hd txs.(2).Types.inputs).Types.previous_output in
         if not (Cstruct.equal op.Types.txid want.Types.txid
                 && op.Types.vout = want.Types.vout) then
           fail "undo for txB names the wrong outpoint (%s:%ld, want %s:%ld)"
             (hexs op.Types.txid) op.Types.vout
             (hexs want.Types.txid) want.Types.vout
         else begin
           let want_value =
             if chained then Int64.sub cb1_value 1000L else cb2_value in
           if entry.Utxo.value <> want_value then
             fail "undo for txB restores value %Ld, want %Ld"
               entry.Utxo.value want_value
           else
             ok "undo for txB names %s:%ld with value %Ld"
               (hexs op.Types.txid) op.Types.vout entry.Utxo.value
         end
       | l -> info "(txB undo has %d entries — outpoint check skipped)"
                (List.length l)
     end);

  (* ---------------- ASSERTION 2: the block DISCONNECTS cleanly. ----------
     Branch C forks at the SAME height 105 and reaches 112, so submitting its
     last block runs Sync.reorganize the other way: disconnect 111..106 of
     branch B (including the spend block) and connect 106..112 of branch C. *)
  let c_blocks = ref [] in
  let prev = ref fork_parent.Sync.hash in
  for h = spend_height to branch_c_tip do
    let blk = build_block ~prev_hash:!prev ~height:h ~branch_tag:5 [] in
    c_blocks := blk :: !c_blocks;
    prev := Crypto.compute_block_hash blk.Types.header
  done;
  let c_blocks = List.rev !c_blocks in
  let n_c = List.length c_blocks in
  List.iteri (fun i b ->
    if i < n_c - 1 then
      submit_ok (Printf.sprintf "branchC h=%d" (spend_height + i)) b) c_blocks;
  ok "branch C prefix %d..%d stored as inactive side branch"
    spend_height (branch_c_tip - 1);

  let disconnect_err = ref None in
  (match submit (List.nth c_blocks (n_c - 1)) with
   | Ok () -> ()
   | Error e -> disconnect_err := Some e);
  (match !disconnect_err with
   | Some e ->
     let inconsistent =
       let needle = "tx and undo inconsistent" in
       let nl = String.length needle and el = String.length e in
       let rec scan i = i + nl <= el && (String.sub e i nl = needle || scan (i + 1)) in
       el >= nl && scan 0
     in
     if inconsistent then
       fail "DISCONNECT HIT THE FATAL: %s" e
     else
       fail "reorg back onto branch C failed: %s" e
   | None ->
     (match chain.Sync.tip with
      | Some t when t.Sync.height = branch_c_tip ->
        ok "reorg back fired: spend block disconnected, tip = branch C height %d"
          branch_c_tip
      | Some t -> fail "reorg back did not reach branch C tip (height=%d)" t.Sync.height
      | None -> fail "no tip after reorg back onto branch C"));

  (* ---------------- ASSERTION 3: the UTXO set is restored exactly. -------- *)
  if !disconnect_err <> None then
    info "(UTXO-restoration checks NOT REACHED — the disconnect aborted)"
  else begin
    let post_cb1 = Storage.ChainDB.get_utxo db cb1_txid 0 in
    let post_cb2 = Storage.ChainDB.get_utxo db cb2_txid 0 in
    let post_txa = Storage.ChainDB.get_utxo db tx_a_txid 0 in
    let post_txb = Storage.ChainDB.get_utxo db tx_b_txid 0 in
    if post_cb1 <> pre_cb1 then
      fail "coinbase-1:0 was NOT restored byte-for-byte by the disconnect"
    else ok "coinbase-1:0 restored byte-for-byte";
    if post_cb2 <> pre_cb2 then
      fail "coinbase-2:0 was NOT restored byte-for-byte by the disconnect"
    else ok "coinbase-2:0 restored byte-for-byte";
    if post_txa <> None then
      fail "txA:0 still in the UTXO set after its block was disconnected"
    else ok "txA:0 removed";
    if post_txb <> None then
      fail "txB:0 still in the UTXO set after its block was disconnected"
    else ok "txB:0 removed"
  end;

  Rocksdb_store.close rocksdb;
  Storage.ChainDB.close db;
  cleanup ();
  { label; failures = !failures }

(* ------------------------------------------------------------------- main *)

let () =
  Printf.printf
    "camlcoin reorg-connect undo data: INTRA-BLOCK transaction chain\n\
     (side-branch block = [coinbase; txA; txB]; reorg in, then reorg out)\n%!";

  (* CONTROL FIRST: it must pass both pre-fix and post-fix, which is what
     attributes any MAIN failure to the intra-block chain specifically. *)
  let control =
    run_scenario
      ~label:"CONTROL — txB spends a DIFFERENT pre-existing on-disk coin"
      ~chained:false in
  let main =
    run_scenario
      ~label:"MAIN — txB spends txA:0 (INTRA-BLOCK CHAIN)"
      ~chained:true in

  let render o =
    Printf.printf "%-8s %s\n%!"
      (if o.failures = [] then "PASS" else "FAIL") o.label;
    List.iter (fun f -> Printf.printf "         - %s\n%!" f) o.failures
  in
  Printf.printf "\n=== SUMMARY ===\n%!";
  render control;
  render main;

  if control.failures <> [] then begin
    Printf.printf
      "\nCONTROL FAILED — the harness setup itself is broken, so the MAIN \
       result is not attributable.\n%!";
    exit 1
  end;
  if main.failures <> [] then begin
    Printf.printf
      "\nBUG REPRODUCED: the reorg connect path dropped the intra-block \
       prevout from the undo record.\nCONTROL PASSED with the same block \
       shape, so the failure is attributable to the intra-block chain.\n%!";
    exit 1
  end;
  Printf.printf
    "\nALL INTRA-BLOCK REORG UNDO CHECKS PASSED (main + control)\n%!"
