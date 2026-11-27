(* An unrequested body for a block that does not extend the tip must pass
   CheckBlock before process_new_block writes it (cffix-camlcoin-nontip-
   body-checkblock, H5 residual).

   process_new_block wrote the body WITHOUT any check on two branches: when
   the block's height is not blocks_synced + 1 (the "does not extend tip,
   storing" branch) and while block_submission_paused is set.  A peer that
   had the header of H+2 could send header || junk.  The junk was stored
   under the real hash, and from then on:
     - every honest copy of H+2 hit the has_block early return and was
       dropped;
     - the cmpctblock path skips blocks it already has;
     - gap-fill excludes hashes that are on disk;
   so H+2 only came back after the drain reached it, found the body
   mutated, deleted it, and a later fill round fetched it again.

   Core ProcessNewBlock runs CheckBlock before AcceptBlock writes anything
   (validation.cpp ProcessNewBlock: CheckBlock, then AcceptBlock, which runs
   ContextualCheckBlock before WriteBlock).  A body that fails is never
   written, and BlockChecked -> MaybePunishNodeForBlock scores the sender.

     dune exec --no-buffer test/nontip_body_checkblock/test_nontip_body_checkblock.exe *)

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

let merkle_of txs = fst (Crypto.merkle_root (List.map Crypto.compute_txid txs))

let build_block ?(txs = []) ~(prev_hash : Types.hash256) ~(height : int)
    ~(prev_time : int32) () : Types.block =
  let extra_nonce = Cstruct.create 8 in
  Cstruct.LE.set_uint64 extra_nonce 0 (Int64.of_int height);
  let mk wr =
    Mining.create_coinbase ~height ~total_fee:0L ~payout_script:op_true
      ~extra_nonce ~witness_root:wr ~network_type:Consensus.Regtest ()
  in
  let witness_root = Mining.compute_witness_merkle_root (mk None :: txs) in
  let coinbase = mk (Some witness_root) in
  let all = coinbase :: txs in
  remine
    { Types.header =
        { version = 4l; prev_block = prev_hash; merkle_root = merkle_of all;
          timestamp = Int32.add prev_time 600l;
          bits = Consensus.regtest.pow_limit; nonce = 0l };
      transactions = all }

let hash_of (b : Types.block) = Crypto.compute_block_hash b.Types.header
let time_of (b : Types.block) = b.Types.header.Types.timestamp

let accept_hdr state (b : Types.block) =
  match Sync.validate_header state b.Types.header with
  | Ok e -> Sync.accept_header state e
  | Error "Header already known" -> ()
  | Error e -> Alcotest.failf "validate_header: %s" e

(* Peers scored through the misbehaviour handler, most recent first. *)
let scored : int list ref = ref []

let deliver ?(f_requested = false) ~peer state b =
  Lwt_main.run
    (Sync.process_new_block ~f_requested ~peer_id:peer
       ~misbehavior_handler:(fun pid _ -> scored := pid :: !scored)
       state b)

let has state b = Storage.ChainDB.has_block state.Sync.db (hash_of b)
let is_invalid state b = Sync.is_block_invalid state (hash_of b)

let attacker = 7
let honest = 3

(* Connected chain genesis..h3, FullySynced, then the headers of honest
   h4 and h5 accepted (headers-first): the shape the audit names. *)
let with_chain f =
  scored := [];
  Test_tmp.with_dir ~label:"nontip_body_checkblock" ~mkdir:true (fun path ->
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
          (match deliver ~f_requested:true ~peer:honest state b with
           | Ok () -> ()
           | Error e -> Alcotest.failf "prefix block %d: %s" h e);
          prev := (hash_of b, time_of b)
        done;
        Alcotest.(check int) "prefix connected" 3 state.Sync.blocks_synced;
        let h4 = build_block ~prev_hash:(fst !prev) ~height:4
            ~prev_time:(snd !prev) () in
        let h5 = build_block ~prev_hash:(hash_of h4) ~height:5
            ~prev_time:(time_of h4) () in
        accept_hdr state h4;
        accept_hdr state h5;
        scored := [];
        f state h4 h5))

(* A non-coinbase tx spending a prevout nobody has. *)
let junk_tx : Types.transaction = {
  Types.version = 2l;
  inputs = [ { Types.previous_output =
                 { Types.txid = Cstruct.of_string (String.make 32 '\x11');
                   vout = 0l };
               script_sig = Cstruct.of_string "\x51";
               sequence = 0xFFFFFFFFl } ];
  outputs = [ { Types.value = 1_000L; script_pubkey = op_true } ];
  witnesses = []; locktime = 0l }

(* h5's real header over a body it does not commit to (bad merkle root). *)
let bad_merkle (real : Types.block) =
  { real with Types.transactions = [ junk_tx ] }

(* h5's real transactions with the coinbase witness reserved value changed:
   txids and the merkle root are unchanged, the witness commitment no
   longer matches (BLOCK_MUTATED, witness class). *)
let bad_witness (real : Types.block) =
  match real.Types.transactions with
  | cb :: rest ->
    let w = [ { Types.items = [ Cstruct.of_string (String.make 32 '\x42') ] } ] in
    { real with Types.transactions = { cb with Types.witnesses = w } :: rest }
  | [] -> assert false

let connect_all_after_junk ~junk () =
  with_chain (fun state h4 h5 ->
    let bad = junk h5 in
    Alcotest.(check bool) "junk keeps h5's header" true
      (Cstruct.equal (hash_of bad) (hash_of h5));
    let r = deliver ~peer:attacker state bad in
    Alcotest.(check bool) "junk non-tip body is NOT stored" false (has state h5);
    (match r with
     | Ok () -> Alcotest.fail "junk non-tip body accepted"
     | Error _ -> ());
    Alcotest.(check bool) "junk does not mark h5 failed" false (is_invalid state h5);
    (* The honest copy now arrives first (h4 is still in flight). *)
    (match deliver ~peer:honest state h5 with
     | Ok () -> ()
     | Error e -> Alcotest.failf "honest h5: %s" e);
    Alcotest.(check bool) "honest non-tip h5 IS stored" true (has state h5);
    (match deliver ~peer:honest state h4 with
     | Ok () -> ()
     | Error e -> Alcotest.failf "honest h4: %s" e);
    Alcotest.(check int) "h4 and h5 connect without another fill round" 5
      state.Sync.blocks_synced;
    Alcotest.(check bool) "honest peer never scored" false
      (List.mem honest !scored))

(* Item repro: bad-merkle h5 delivered unrequested while only h3 is
   connected; honest h4/h5 then connect with no extra fill round, and the
   sender of the mutated body is scored (non-witness mutation). *)
let test_bad_merkle_nontip () =
  connect_all_after_junk ~junk:bad_merkle ();
  ()

let test_bad_merkle_scores_sender () =
  with_chain (fun state _h4 h5 ->
    (match deliver ~peer:attacker state (bad_merkle h5) with
     | Ok () -> Alcotest.fail "junk non-tip body accepted"
     | Error _ -> ());
    Alcotest.(check (list int)) "sender of a bad-merkle body is scored"
      [ attacker ] !scored)

(* Witness mutation: not stored either, but not scored (the at-tip path's
   existing policy: the peer may have relayed a stripped block). *)
let test_bad_witness_nontip () =
  connect_all_after_junk ~junk:bad_witness ()

let test_bad_witness_not_scored () =
  with_chain (fun state _h4 h5 ->
    (match deliver ~peer:attacker state (bad_witness h5) with
     | Ok () -> Alcotest.fail "witness-mutated non-tip body accepted"
     | Error _ -> ());
    Alcotest.(check bool) "witness-mutated body is NOT stored" false (has state h5);
    Alcotest.(check (list int)) "witness mutation is not scored" [] !scored)

(* NetworkDisable pause (dumptxoutset rollback): the body is kept for the
   post-pause drain, but only one that passes CheckBlock. *)
let test_paused_branch () =
  with_chain (fun state h4 _h5 ->
    state.Sync.block_submission_paused <- true;
    (match deliver ~peer:attacker state (bad_merkle h4) with
     | Ok () -> Alcotest.fail "junk body accepted while paused"
     | Error _ -> ());
    Alcotest.(check bool) "junk body is NOT stored while paused" false (has state h4);
    (match deliver ~peer:honest state h4 with
     | Error "block-submission-paused" -> ()
     | Ok () -> Alcotest.fail "connected while paused"
     | Error e -> Alcotest.failf "honest h4 while paused: %s" e);
    Alcotest.(check bool) "honest body IS kept while paused" true (has state h4);
    state.Sync.block_submission_paused <- false;
    ignore (Sync.connect_stored_blocks state);
    Alcotest.(check int) "kept body connects after the pause" 4
      state.Sync.blocks_synced)

(* A pause that begins while the validation worker runs (the post-await
   re-check in process_new_block).  submit_lwt stays pending until the
   worker Domain notifies, so setting the flag right after the call lands
   inside the await.  A body accept_block found mutated is not kept; a
   valid one is kept and connects after the pause. *)
let deliver_pause_during ~worker ~peer state b =
  let p =
    Sync.process_new_block ~f_requested:true ~peer_id:peer
      ~misbehavior_handler:(fun pid _ -> scored := pid :: !scored)
      ~worker state b in
  state.Sync.block_submission_paused <- true;
  Lwt_main.run p

let test_pause_during_validation () =
  with_chain (fun state h4 _h5 ->
    let worker = Sync.Validation_worker.create () in
    Fun.protect ~finally:(fun () -> Sync.Validation_worker.shutdown worker)
      (fun () ->
        (match deliver_pause_during ~worker ~peer:attacker state (bad_merkle h4) with
         | Ok () -> Alcotest.fail "junk body connected"
         | Error _ -> ());
        Alcotest.(check bool)
          "mutated body is NOT kept when a pause begins during validation"
          false (has state h4);
        Alcotest.(check bool) "mutated body does not mark h4 failed" false
          (is_invalid state h4);
        state.Sync.block_submission_paused <- false;
        (match deliver_pause_during ~worker ~peer:honest state h4 with
         | Error "block-submission-paused" -> ()
         | Ok () -> Alcotest.fail "connected although a pause began"
         | Error e -> Alcotest.failf "honest h4, pause during validation: %s" e);
        Alcotest.(check bool) "valid body IS kept for the post-pause drain"
          true (has state h4);
        state.Sync.block_submission_paused <- false;
        ignore (Sync.connect_stored_blocks state);
        Alcotest.(check int) "kept body connects after the pause" 4
          state.Sync.blocks_synced))

(* Fail closed on incomplete header ancestry: with a non-parent ancestor
   (h2) missing from the header table, the MTP window of h5 cannot be
   resolved.  The body is not stored, not marked and its sender not scored
   (a local defect, not a verdict: a short median could otherwise make a
   valid block look non-final).  Once the header is back the same valid
   body is stored and h4/h5 connect. *)
let test_incomplete_ancestry_unjudged () =
  with_chain (fun state h4 h5 ->
    let h3_hash = h4.Types.header.Types.prev_block in
    let h3e = Option.get (Sync.get_header state h3_hash) in
    let k2 = Cstruct.to_string h3e.Sync.header.Types.prev_block in
    let h2e = Hashtbl.find state.Sync.headers k2 in
    Hashtbl.remove state.Sync.headers k2;
    let r = deliver ~peer:honest state h5 in
    Hashtbl.replace state.Sync.headers k2 h2e;
    Alcotest.(check bool) "body is NOT stored on incomplete ancestry" false
      (has state h5);
    (match r with
     | Ok () -> Alcotest.fail "judged with an incomplete MTP window"
     | Error e ->
       Alcotest.(check bool) ("ancestry-incomplete error: " ^ e) true
         (Sync.is_ancestry_incomplete e));
    Alcotest.(check bool) "not marked failed" false (is_invalid state h5);
    Alcotest.(check (list int)) "sender not scored" [] !scored;
    (match deliver ~peer:honest state h5 with
     | Ok () -> ()
     | Error e -> Alcotest.failf "h5 with the ancestry back: %s" e);
    Alcotest.(check bool) "stored once the ancestry is back" true (has state h5);
    (match deliver ~peer:honest state h4 with
     | Ok () -> ()
     | Error e -> Alcotest.failf "honest h4: %s" e);
    Alcotest.(check int) "h4 and h5 connect" 5 state.Sync.blocks_synced)

(* Controls (consensus): the new check must not let an invalid block in and
   must not stop a verdict.  A non-tip block whose merkle root matches but
   which carries a non-final tx is invalid (ContextualCheckBlock
   bad-txns-nonfinal): not stored, marked failed like Core's AcceptBlock
   InvalidBlockFound, and h4 still connects. *)
let nonfinal_tx : Types.transaction =
  { junk_tx with Types.locktime = 0x7fffffffl;
                 inputs = List.map (fun i -> { i with Types.sequence = 0l })
                     junk_tx.Types.inputs }

let test_invalid_nontip_marked () =
  with_chain (fun state h4 _h5 ->
    let bad5 = build_block ~txs:[ nonfinal_tx ] ~prev_hash:(hash_of h4)
        ~height:5 ~prev_time:(time_of h4) () in
    accept_hdr state bad5;
    (match deliver ~peer:attacker state bad5 with
     | Ok () -> Alcotest.fail "non-final non-tip block accepted"
     | Error e ->
       Alcotest.(check string) "rejected as non-final"
         (Validation.block_error_to_string
            (Validation.BlockTxValidationFailed (1, Validation.TxNonFinalLocktime)))
         e);
    Alcotest.(check bool) "invalid non-tip body is NOT stored" false (has state bad5);
    Alcotest.(check bool) "invalid non-tip block IS marked failed" true
      (is_invalid state bad5);
    Alcotest.(check (list int)) "its sender is scored" [ attacker ] !scored;
    (match deliver ~peer:honest state h4 with
     | Ok () -> ()
     | Error e -> Alcotest.failf "honest h4: %s" e);
    Alcotest.(check int) "h4 connects; bad5 does not" 4 state.Sync.blocks_synced)

(* A valid-merkle non-tip block whose coinbase carries the wrong BIP34
   height (Core: bad-cb-height, ContextualCheckBlock): not stored, sender
   scored.  camlcoin's existing [Sync.is_retained_block_failure] keeps
   coinbase errors on the not-marked side, so it is not marked here
   either; this change does not alter that classification. *)
let test_valid_merkle_bad_bip34_not_stored () =
  with_chain (fun state h4 _h5 ->
    let cb = Mining.create_coinbase ~height:9 ~total_fee:0L
        ~payout_script:op_true ~extra_nonce:(Cstruct.create 8)
        ~witness_root:None ~network_type:Consensus.Regtest () in
    let b = remine
        { Types.header =
            { version = 4l; prev_block = hash_of h4; merkle_root = merkle_of [ cb ];
              timestamp = Int32.add (time_of h4) 600l;
              bits = Consensus.regtest.pow_limit; nonce = 0l };
          transactions = [ cb ] } in
    accept_hdr state b;
    (match deliver ~peer:attacker state b with
     | Ok () -> Alcotest.fail "wrong-BIP34 non-tip block accepted"
     | Error _ -> ());
    Alcotest.(check bool) "wrong-BIP34 non-tip body is NOT stored" false (has state b);
    Alcotest.(check (list int)) "its sender is scored" [ attacker ] !scored)

let () =
  Alcotest.run "nontip_body_checkblock"
    [ ( "unrequested non-tip body is checked before it is stored",
        [ Alcotest.test_case "bad merkle h5: not stored, honest h4/h5 connect"
            `Quick test_bad_merkle_nontip;
          Alcotest.test_case "bad merkle h5: sender scored" `Quick
            test_bad_merkle_scores_sender;
          Alcotest.test_case "bad witness h5: not stored, honest h4/h5 connect"
            `Quick test_bad_witness_nontip;
          Alcotest.test_case "bad witness h5: sender not scored" `Quick
            test_bad_witness_not_scored;
          Alcotest.test_case "paused: junk not kept, honest kept and drained"
            `Quick test_paused_branch;
          Alcotest.test_case
            "pause begins during validation: mutated not kept, valid kept"
            `Quick test_pause_during_validation;
          Alcotest.test_case
            "incomplete ancestry: not stored, not marked, not scored" `Quick
            test_incomplete_ancestry_unjudged ] );
      ( "consensus controls",
        [ Alcotest.test_case "non-final non-tip block: not stored, marked"
            `Quick test_invalid_nontip_marked;
          Alcotest.test_case "wrong-BIP34 non-tip block: not stored" `Quick
            test_valid_merkle_bad_bip34_not_stored ] ) ]
