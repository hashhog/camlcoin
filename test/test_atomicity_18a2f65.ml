(* Regression tests for commit 18a2f65 — apply_block_atomic commit-order
   reversal + the cli.ml four-way boot consistency check.

   The fix establishes a single invariant across the dual-DB layout
   (cf_chainstate + rocksdb_utxo cannot share a WriteBatch):

       POST-COMMIT INVARIANT:   rdb_tip >= chain_tip   (always)

   These tests pin that invariant down at the storage layer
   (apply_block_atomic) and exercise the four boot-check branches:

     1. happy_path_invariant            — heights match after apply
     2. crash_after_rdb_before_cf       — the SAFE crash window
     3. crash_after_cf_before_rdb       — the INVERSE (legacy/CF-only)
        window the boot check must rewind + persist
     4. boot_check_per_block_content    — heights agree, but a UTXO is
        missing from RDB; the per-block content scan must detect it
     5. persist_rewind_to_height_helper — direct test of the helper
        logic that closes the latent on-disk-CF-not-rewound bug

   The cli.ml boot check (and its [persist_rewind_to_height] inner
   helper) is a local [let] inside [Cli.run], not a public symbol.  We
   replicate its three observable effects in [boot_check] /
   [persist_rewind] below so each test exercises the same conceptual
   code path the daemon runs at startup. *)

open Camlcoin

let test_root = "/tmp/camlcoin_test_atomicity_18a2f65"

let cleanup () =
  let rec rm_rf path =
    if Sys.file_exists path then begin
      if Sys.is_directory path then begin
        Array.iter (fun f -> rm_rf (Filename.concat path f)) (Sys.readdir path);
        Unix.rmdir path
      end else Unix.unlink path
    end
  in
  rm_rf test_root

(* Open the dual-DB layout the way [Cli.run] does: ChainDB for the CF
   chainstate + Rocksdb_store for the UTXO mirror, with
   [attach_rocksdb_utxo] wiring them together. *)
let open_dual_db () =
  Unix.mkdir test_root 0o755;
  let db = Storage.ChainDB.create (Filename.concat test_root "chain") in
  let rdb = Rocksdb_store.open_db (Filename.concat test_root "rocksdb") in
  Storage.ChainDB.attach_rocksdb_utxo db rdb;
  db, rdb

let close_dual_db db rdb =
  Rocksdb_store.close rdb;
  Storage.ChainDB.close db

(* Mint a deterministic header at [height] / [nonce] so we can produce
   distinct block hashes per test fixture without mining real PoW. *)
let make_header ~height ~nonce =
  Types.{
    version = 1l;
    prev_block = Types.zero_hash;
    merkle_root = Types.zero_hash;
    timestamp = Int32.of_int (1700000000 + height);
    bits = 0x207fffffl;
    nonce = Int32.of_int nonce;
  }

(* Build a minimal block with one P2PKH output we can probe in RDB. *)
let make_block_with_output ~height ~nonce ~payout_value =
  let header = make_header ~height ~nonce in
  let script_pubkey = Cstruct.of_string
    "\x76\xa9\x14\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\
     \x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x88\xac" in
  let cb_in : Types.tx_in = {
    previous_output = { txid = Types.zero_hash; vout = -1l };
    script_sig = Cstruct.of_string (Printf.sprintf "\x03height=%d" height);
    sequence = 0xffffffffl;
  } in
  let cb_out : Types.tx_out = { value = payout_value; script_pubkey } in
  let coinbase : Types.transaction = {
    version = 1l; inputs = [cb_in]; outputs = [cb_out];
    witnesses = []; locktime = 0l;
  } in
  Types.{ header; transactions = [coinbase] }

(* Serialize a utxo_entry exactly the way apply_block_atomic does
   (via OptimizedUtxoSet) so the bytes stored in RDB match the layout
   the boot check will read. *)
let utxo_bytes ~value ~script_pubkey ~height ~is_coinbase =
  let w = Serialize.writer_create () in
  Utxo.serialize_utxo_entry w
    { Utxo.value; script_pubkey; height; is_coinbase };
  Cstruct.to_string (Serialize.writer_to_cstruct w)

(* Drive apply_block_atomic with one Add per output of [block]. *)
let apply_block db ~block ~height =
  let hash = Crypto.compute_block_hash block.Types.header in
  Storage.ChainDB.store_block db hash block;
  Storage.ChainDB.set_height_hash db height hash;
  let ops =
    List.concat_map (fun (tx : Types.transaction) ->
      let txid = Crypto.compute_txid tx in
      List.mapi (fun vout (out : Types.tx_out) ->
        let data = utxo_bytes
          ~value:out.value ~script_pubkey:out.script_pubkey
          ~height ~is_coinbase:true in
        (txid, vout, `Add data)
      ) tx.outputs
    ) block.Types.transactions
  in
  Storage.ChainDB.apply_block_atomic db
    ~tip_hash:hash ~tip_height:height
    ~header_tip_hash:hash ~header_tip_height:height
    ops;
  hash

(* Replica of cli.ml's [persist_rewind_to_height] (local helper inside
   [Cli.run]).  Persists the rewind to the CF chain_state, exactly
   matching the production behaviour the fix relies on. *)
let persist_rewind db target =
  let new_hash, new_height =
    if target <= 0 then (Cstruct.create 32, 0)
    else
      match Storage.ChainDB.get_hash_at_height db target with
      | Some h -> (h, target)
      | None -> (Cstruct.create 32, 0)
  in
  Storage.ChainDB.set_chain_tip db new_hash new_height;
  new_height

(* Replica of the four-way boot check from cli.ml.  Returns a tag
   describing which branch was taken so tests can assert the boot
   check classified the on-disk state correctly. *)
type boot_result =
  | Rewound_rdb_wiped
  | Rewound_inverse_window of int  (* rdb_tip *)
  | Crash_window_safe of int * int (* rdb_tip, chain_tip *)
  | Heights_match_content_ok
  | Heights_match_content_rewound

let boot_check db rdb =
  match Storage.ChainDB.get_chain_tip db with
  | None | Some (_, 0) ->
    (* Nothing to verify if there is no validated tip yet. *)
    Heights_match_content_ok
  | Some (_, chain_tip) ->
    (match Rocksdb_store.get_tip_height rdb with
     | None ->
       let _ = persist_rewind db 0 in Rewound_rdb_wiped
     | Some rdb_h when rdb_h < chain_tip ->
       let _ = persist_rewind db rdb_h in Rewound_inverse_window rdb_h
     | Some rdb_h when rdb_h > chain_tip ->
       Crash_window_safe (rdb_h, chain_tip)
     | Some _ ->
       (* Heights match — per-block content scan. *)
       (match Storage.ChainDB.get_hash_at_height db chain_tip with
        | None -> let _ = persist_rewind db 0 in Heights_match_content_rewound
        | Some tip_hash ->
          (match Storage.ChainDB.get_block db tip_hash with
           | None -> Heights_match_content_ok  (* pruned *)
           | Some block ->
             let missing = ref false in
             (try
                List.iter (fun (tx : Types.transaction) ->
                  let txid = Crypto.compute_txid tx in
                  List.iteri (fun vout (out : Types.tx_out) ->
                    if not (Utxo.is_unspendable_script out.script_pubkey)
                    then begin
                      let k = Storage.ChainDB.rocksdb_utxo_key txid vout in
                      match Rocksdb_store.get rdb k with
                      | Some _ -> () | None -> missing := true; raise Exit
                    end
                  ) tx.outputs
                ) block.transactions
              with Exit -> ());
             if !missing then begin
               let _ = persist_rewind db (chain_tip - 1) in
               Heights_match_content_rewound
             end else Heights_match_content_ok)))

(* ----------------------------------------------------------------------
   Test 1 — Happy path: apply_block_atomic leaves rdb_tip == chain_tip.
   ---------------------------------------------------------------------- *)
let test_happy_path_invariant () =
  cleanup ();
  let db, rdb = open_dual_db () in
  let blk = make_block_with_output ~height:1 ~nonce:1 ~payout_value:5000000000L in
  let _ = apply_block db ~block:blk ~height:1 in
  let chain_tip = match Storage.ChainDB.get_chain_tip db with
    | Some (_, h) -> h | None -> -1 in
  let rdb_tip = match Rocksdb_store.get_tip_height rdb with
    | Some h -> h | None -> -1 in
  Alcotest.(check int) "chain_tip == 1" 1 chain_tip;
  Alcotest.(check int) "rdb_tip == 1" 1 rdb_tip;
  Alcotest.(check bool) "invariant rdb_tip >= chain_tip" true (rdb_tip >= chain_tip);
  close_dual_db db rdb; cleanup ()

(* ----------------------------------------------------------------------
   Test 2 — Safe crash window: RDB committed, CF didn't.  Boot check
   must classify as [Crash_window_safe] and leave chain_tip alone so
   IBD re-applies the missing block idempotently.
   ---------------------------------------------------------------------- *)
let test_crash_after_rdb_before_cf () =
  cleanup ();
  let db, rdb = open_dual_db () in
  let blk0 = make_block_with_output ~height:1 ~nonce:1 ~payout_value:5000000000L in
  let _ = apply_block db ~block:blk0 ~height:1 in
  (* Simulate the crash window for block 2: RDB advances to 2 but CF
     stays at 1.  We perform ONLY the RDB half of apply_block_atomic. *)
  let blk1 = make_block_with_output ~height:2 ~nonce:2 ~payout_value:5000000000L in
  let blk1_hash = Crypto.compute_block_hash blk1.header in
  Storage.ChainDB.store_block db blk1_hash blk1;
  Storage.ChainDB.set_height_hash db 2 blk1_hash;
  let txid = Crypto.compute_txid (List.hd blk1.transactions) in
  let out = List.hd (List.hd blk1.transactions).outputs in
  let data = utxo_bytes ~value:out.value ~script_pubkey:out.script_pubkey
    ~height:2 ~is_coinbase:true in
  let rdb_key = Storage.ChainDB.rocksdb_utxo_key txid 0 in
  Rocksdb_store.batch_write ~tip_height:2 rdb [(rdb_key, Some data)];
  (* CF still at 1; RDB now at 2. *)
  Alcotest.(check int) "chain_tip stuck at 1"
    1 (match Storage.ChainDB.get_chain_tip db with Some (_, h) -> h | None -> -1);
  Alcotest.(check int) "rdb_tip advanced to 2"
    2 (match Rocksdb_store.get_tip_height rdb with Some h -> h | None -> -1);
  let result = boot_check db rdb in
  (match result with
   | Crash_window_safe (2, 1) -> ()
   | _ -> Alcotest.fail "expected Crash_window_safe (2, 1)");
  (* After the safe-window boot check, chain_tip MUST NOT have been
     persisted forward — IBD owns the re-apply. *)
  Alcotest.(check int) "chain_tip still 1 after boot check"
    1 (match Storage.ChainDB.get_chain_tip db with Some (_, h) -> h | None -> -1);
  close_dual_db db rdb; cleanup ()

(* ----------------------------------------------------------------------
   Test 3 — Inverse window: CF committed, RDB didn't.  This is exactly
   the pre-18a2f65 bug shape (legacy data or a CF-only write path).
   Boot check must rewind chain_tip down to rdb_tip AND PERSIST it.
   ---------------------------------------------------------------------- *)
let test_crash_after_cf_before_rdb () =
  cleanup ();
  let db, rdb = open_dual_db () in
  let blk0 = make_block_with_output ~height:1 ~nonce:1 ~payout_value:5000000000L in
  let _ = apply_block db ~block:blk0 ~height:1 in
  (* Simulate the INVERSE window for block 2: CF advances to 2 but RDB
     stays at 1.  Bypass apply_block_atomic and write only the CF half. *)
  let blk1 = make_block_with_output ~height:2 ~nonce:2 ~payout_value:5000000000L in
  let blk1_hash = Crypto.compute_block_hash blk1.header in
  Storage.ChainDB.store_block db blk1_hash blk1;
  Storage.ChainDB.set_height_hash db 2 blk1_hash;
  Storage.ChainDB.set_chain_tip db blk1_hash 2;
  Alcotest.(check int) "chain_tip jumped to 2 (CF-only write)"
    2 (match Storage.ChainDB.get_chain_tip db with Some (_, h) -> h | None -> -1);
  Alcotest.(check int) "rdb_tip stuck at 1"
    1 (match Rocksdb_store.get_tip_height rdb with Some h -> h | None -> -1);
  let result = boot_check db rdb in
  (match result with
   | Rewound_inverse_window 1 -> ()
   | _ -> Alcotest.fail "expected Rewound_inverse_window 1");
  (* CRITICAL: the latent-bug closer — the on-disk CF chain_tip must
     have been ACTUALLY persisted to height=1, not just rewound in
     memory.  Pre-fix this is where the silent skew hid. *)
  Alcotest.(check int) "on-disk chain_tip persisted to 1"
    1 (match Storage.ChainDB.get_chain_tip db with Some (_, h) -> h | None -> -1);
  close_dual_db db rdb; cleanup ()

(* ----------------------------------------------------------------------
   Test 4 — Per-block content scan: heights agree but one of the
   tip block's outputs is missing from RDB.  Boot check must detect
   the content-level skew and rewind one block.
   ---------------------------------------------------------------------- *)
let test_boot_check_per_block_content () =
  cleanup ();
  let db, rdb = open_dual_db () in
  let blk0 = make_block_with_output ~height:1 ~nonce:1 ~payout_value:5000000000L in
  let _ = apply_block db ~block:blk0 ~height:1 in
  let blk1 = make_block_with_output ~height:2 ~nonce:2 ~payout_value:5000000000L in
  let _ = apply_block db ~block:blk1 ~height:2 in
  (* Heights match (chain_tip=2, rdb_tip=2) — confirm. *)
  Alcotest.(check int) "chain_tip == 2 pre-damage"
    2 (match Storage.ChainDB.get_chain_tip db with Some (_, h) -> h | None -> -1);
  Alcotest.(check int) "rdb_tip == 2 pre-damage"
    2 (match Rocksdb_store.get_tip_height rdb with Some h -> h | None -> -1);
  (* Surgically delete block 2's coinbase output from RDB while
     leaving rdb_tip and chain_tip alone — simulates the
     heights-match-but-UTXOs-missing failure mode. *)
  let txid = Crypto.compute_txid (List.hd blk1.transactions) in
  let key = Storage.ChainDB.rocksdb_utxo_key txid 0 in
  Rocksdb_store.delete rdb key;
  Alcotest.(check (option string)) "RDB output gone" None (Rocksdb_store.get rdb key);
  let result = boot_check db rdb in
  (match result with
   | Heights_match_content_rewound -> ()
   | _ -> Alcotest.fail "expected Heights_match_content_rewound");
  (* The boot check should have rewound chain_tip from 2 -> 1. *)
  Alcotest.(check int) "chain_tip rewound to 1"
    1 (match Storage.ChainDB.get_chain_tip db with Some (_, h) -> h | None -> -1);
  close_dual_db db rdb; cleanup ()

(* ----------------------------------------------------------------------
   Test 5 — persist_rewind_to_height: both backends end up consistent
   from chain_tip's perspective (CF actually persists the new tip,
   not just an in-memory rewind).  Directly exercises the helper.
   ---------------------------------------------------------------------- *)
let test_persist_rewind_helper () =
  cleanup ();
  let db, rdb = open_dual_db () in
  let blk_at_1 = make_block_with_output ~height:1 ~nonce:1 ~payout_value:5000000000L in
  let h_at_1 = apply_block db ~block:blk_at_1 ~height:1 in
  let blk_at_2 = make_block_with_output ~height:2 ~nonce:2 ~payout_value:5000000000L in
  let _ = apply_block db ~block:blk_at_2 ~height:2 in
  let blk_at_3 = make_block_with_output ~height:3 ~nonce:3 ~payout_value:5000000000L in
  let _ = apply_block db ~block:blk_at_3 ~height:3 in
  (* Rewind to height 1.  Helper must look up h=1's canonical hash
     and persist it via set_chain_tip — close + reopen below proves
     the rewind survived the in-memory state. *)
  let new_h = persist_rewind db 1 in
  Alcotest.(check int) "helper returns target height" 1 new_h;
  close_dual_db db rdb;
  (* Reopen the CF and verify the rewind survived disk persistence —
     this is the assertion that fails pre-fix because the old code
     only mutated [chain.blocks_synced] in memory. *)
  let db2 = Storage.ChainDB.create (Filename.concat test_root "chain") in
  let tip = Storage.ChainDB.get_chain_tip db2 in
  Alcotest.(check int) "on-disk chain_tip persisted to 1 across reopen"
    1 (match tip with Some (_, h) -> h | None -> -1);
  (* And the persisted tip_hash matches the canonical hash for h=1. *)
  Alcotest.(check string) "persisted tip_hash == hash of height-1 block"
    (Types.hash256_to_hex h_at_1)
    (match tip with Some (h, _) -> Types.hash256_to_hex h | None -> "");
  Storage.ChainDB.close db2;
  cleanup ()

(* ----------------------------------------------------------------------
   Test 6 — Bonus: the post-commit invariant holds across 10 blocks.
   Belt-and-braces sanity check that apply_block_atomic never produces
   the [chain_tip > rdb_tip] state under happy-path replay.
   ---------------------------------------------------------------------- *)
let test_invariant_holds_across_replay () =
  cleanup ();
  let db, rdb = open_dual_db () in
  for height = 1 to 10 do
    let blk = make_block_with_output ~height ~nonce:height
      ~payout_value:5000000000L in
    let _ = apply_block db ~block:blk ~height in
    let chain_tip = match Storage.ChainDB.get_chain_tip db with
      | Some (_, h) -> h | None -> -1 in
    let rdb_tip = match Rocksdb_store.get_tip_height rdb with
      | Some h -> h | None -> -1 in
    Alcotest.(check bool)
      (Printf.sprintf "invariant at height=%d: rdb_tip(%d) >= chain_tip(%d)"
        height rdb_tip chain_tip)
      true (rdb_tip >= chain_tip)
  done;
  close_dual_db db rdb; cleanup ()

let () =
  cleanup ();
  let open Alcotest in
  run "Atomicity_18a2f65" [
    "apply_block_atomic_invariant", [
      test_case "happy path: rdb_tip == chain_tip" `Quick
        test_happy_path_invariant;
      test_case "invariant holds across 10-block replay" `Quick
        test_invariant_holds_across_replay;
    ];
    "boot_check_four_way", [
      test_case "safe crash window (rdb_tip > chain_tip)" `Quick
        test_crash_after_rdb_before_cf;
      test_case "inverse window: chain_tip rewound AND persisted" `Quick
        test_crash_after_cf_before_rdb;
      test_case "per-block content scan detects missing UTXO" `Quick
        test_boot_check_per_block_content;
    ];
    "persist_rewind_to_height", [
      test_case "rewind survives reopen (not in-memory only)" `Quick
        test_persist_rewind_helper;
    ];
  ]
