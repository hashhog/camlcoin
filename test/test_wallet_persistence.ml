(* Regression tests for the wallet restart-persistence fix (sweep wa0fq5wtk).

   The pre-fix bug had three teeth:

     1. CRASH-ON-LOAD: [save] / [save_encrypted] wrote the wallet file in place
        (open_out -> output_string -> close_out).  A SIGKILL / OOM / power loss
        mid-write left a truncated, unparseable file, and [load] called
        Yojson.Safe.from_string directly -> the exception crashed node startup.

     2. STATE LOSS: the wallet was persisted ONLY at clean shutdown.  An unclean
        exit lost every credit/debit since the last clean shutdown.

     3. NO RECONCILE: nothing brought a stale wallet up to the chain tip on
        startup, so even a recovered file could silently lag the chain.

   These tests pin all three down at the wallet-module level:

     - atomic save round-trips (incl. last_synced_height)
     - a partially-written / truncated file does NOT crash [load]
     - a corrupt file is recovered from the .bak sidecar
     - a from-nothing corrupt file falls back to a fresh wallet (no crash)
     - a mutation persisted via save-on-mutation survives a simulated unclean
       restart (the on-disk temp/rename is durable + parseable)
     - reconcile_to_tip rebuilds the ledger over a gap of unscanned blocks
     - reconcile_to_tip is idempotent (re-running over the same range does not
       double-count)

   No real PoW / chainstate is needed: the wallet ledger is driven purely by
   [scan_block] over hand-built blocks paying a wallet-owned script. *)

open Camlcoin

let test_root = "/tmp/camlcoin_test_wallet_persistence"

let rm_rf path =
  let rec go p =
    if Sys.file_exists p then begin
      if Sys.is_directory p then begin
        Array.iter (fun f -> go (Filename.concat p f)) (Sys.readdir p);
        (try Unix.rmdir p with _ -> ())
      end else (try Unix.unlink p with _ -> ())
    end
  in
  go path

let setup () =
  rm_rf test_root;
  Unix.mkdir test_root 0o755

let db_path () = Filename.concat test_root "wallet.json"

(* Build a coinbase-style block whose single output pays [script] [value] sats.
   A coinbase input (prevout txid = zero_hash) so scan_block treats it as a
   `Generate credit. [nonce] keeps block hashes distinct per height. *)
let make_block_paying ~height ~nonce ~value ~script =
  let header = Types.{
    version = 1l;
    prev_block = Types.zero_hash;
    merkle_root = Types.zero_hash;
    timestamp = Int32.of_int (1700000000 + height);
    bits = 0x207fffffl;
    nonce = Int32.of_int nonce;
  } in
  let cb_in : Types.tx_in = {
    previous_output = { txid = Types.zero_hash; vout = -1l };
    script_sig = Cstruct.of_string (Printf.sprintf "h%d" height);
    sequence = 0xffffffffl;
  } in
  let cb_out : Types.tx_out = { value; script_pubkey = script } in
  let coinbase : Types.transaction = {
    version = 1l; inputs = [cb_in]; outputs = [cb_out];
    witnesses = []; locktime = 0l;
  } in
  Types.{ header; transactions = [coinbase] }

(* ----------------------------------------------------------------------
   Test 1 — atomic save round-trips, last_synced_height persists, and
   no torn temp file is left behind.
   ---------------------------------------------------------------------- *)
let test_save_roundtrip () =
  setup ();
  let path = db_path () in
  let w = Wallet.create ~network:`Regtest ~db_path:path in
  let kp = Wallet.generate_key w in
  let script = Wallet.build_output_script kp.address in
  let blk = make_block_paying ~height:5 ~nonce:1 ~value:5000000000L ~script in
  Wallet.scan_block_and_persist w blk 5;
  Alcotest.(check int) "last_synced_height advanced to 5" 5 w.Wallet.last_synced_height;
  Alcotest.(check int) "one utxo credited" 1 (List.length (Wallet.get_utxos w));
  (* The atomic writer must not leave a .tmp behind after a successful save. *)
  Alcotest.(check bool) "no leftover .tmp" false (Sys.file_exists (path ^ ".tmp"));
  (* Reload from disk and confirm the ledger + synced height round-trip. *)
  let w2 = Wallet.load ~network:`Regtest ~db_path:path in
  Alcotest.(check int) "reloaded last_synced_height" 5 w2.Wallet.last_synced_height;
  Alcotest.(check int) "reloaded utxo count" 1 (List.length (Wallet.get_utxos w2));
  Alcotest.(check int64) "reloaded confirmed balance"
    5000000000L w2.Wallet.balance_confirmed;
  rm_rf test_root

(* ----------------------------------------------------------------------
   Test 2 — a truncated / partially-written wallet file does NOT crash
   [load].  This is the core CRASH-ON-RESTART regression: pre-fix, load
   raised Yojson's parse exception straight up the startup path.
   ---------------------------------------------------------------------- *)
let test_partial_file_does_not_crash () =
  setup ();
  let path = db_path () in
  (* Write a half-written JSON document (a torn-write artifact). *)
  let oc = open_out path in
  output_string oc "{\"network\":\"regtest\",\"keys\":[{\"private_key\":\"ab";
  close_out oc;
  (* Must not raise. *)
  let w =
    try Wallet.load ~network:`Regtest ~db_path:path
    with exn ->
      Alcotest.failf "load raised on a partial file: %s" (Printexc.to_string exn)
  in
  (* With no .bak / .tmp to recover from, we get a usable fresh wallet whose
     reconcile frontier is -1 (rescan-from-genesis on startup). *)
  Alcotest.(check int) "fresh wallet after corrupt load" 0 (Wallet.key_count w);
  Alcotest.(check int) "fresh wallet synced height = -1"
    (-1) w.Wallet.last_synced_height;
  (* The corrupt bytes were preserved, not silently discarded. *)
  Alcotest.(check bool) "corrupt bytes preserved to .corrupt"
    true (Sys.file_exists (path ^ ".corrupt"));
  rm_rf test_root

(* ----------------------------------------------------------------------
   Test 3 — a corrupt primary file is recovered from the .bak sidecar
   that a prior clean load wrote.
   ---------------------------------------------------------------------- *)
let test_recover_from_bak () =
  setup ();
  let path = db_path () in
  (* Produce a good wallet with a credited coin, saved atomically. *)
  let w = Wallet.create ~network:`Regtest ~db_path:path in
  let kp = Wallet.generate_key w in
  let script = Wallet.build_output_script kp.address in
  let blk = make_block_paying ~height:3 ~nonce:7 ~value:2500000000L ~script in
  Wallet.scan_block_and_persist w blk 3;
  (* A clean load mints the .bak sidecar. *)
  let _ = Wallet.load ~network:`Regtest ~db_path:path in
  Alcotest.(check bool) ".bak written by clean load" true
    (Sys.file_exists (path ^ ".bak"));
  (* Now corrupt the primary file (simulate a torn rewrite). *)
  let oc = open_out path in
  output_string oc "}{ this is not json"; close_out oc;
  (* Load must recover from .bak, not crash, and see the credited coin. *)
  let w2 =
    try Wallet.load ~network:`Regtest ~db_path:path
    with exn ->
      Alcotest.failf "load raised despite a good .bak: %s"
        (Printexc.to_string exn)
  in
  Alcotest.(check int) "recovered utxo count from .bak" 1
    (List.length (Wallet.get_utxos w2));
  Alcotest.(check int64) "recovered balance from .bak" 2500000000L
    w2.Wallet.balance_confirmed;
  rm_rf test_root

(* ----------------------------------------------------------------------
   Test 4 — recovery from a leftover .tmp (the crash-between-write-and-
   rename window the atomic writer is designed around).
   ---------------------------------------------------------------------- *)
let test_recover_from_tmp () =
  setup ();
  let path = db_path () in
  (* Build a complete, valid wallet document and place it ONLY at .tmp,
     as if the process were SIGKILLed after the temp write but before the
     atomic rename — the primary file does not exist at all. *)
  let w = Wallet.create ~network:`Regtest ~db_path:path in
  let _ = Wallet.generate_key w in
  Wallet.save w;                       (* materialises path *)
  Sys.rename path (path ^ ".tmp");     (* simulate pre-rename crash *)
  Alcotest.(check bool) "primary absent" false (Sys.file_exists path);
  Alcotest.(check bool) ".tmp present" true (Sys.file_exists (path ^ ".tmp"));
  let w2 =
    try Wallet.load ~network:`Regtest ~db_path:path
    with exn ->
      Alcotest.failf "load raised on .tmp recovery: %s" (Printexc.to_string exn)
  in
  Alcotest.(check int) "recovered key count from .tmp" 1 (Wallet.key_count w2);
  (* Recovery re-materialised the primary file. *)
  Alcotest.(check bool) "primary re-materialised" true (Sys.file_exists path);
  rm_rf test_root

(* ----------------------------------------------------------------------
   Test 5 — a mutation persisted via save-on-mutation survives a SIMULATED
   UNCLEAN RESTART.  We never call any clean-shutdown save: the only durable
   write is the per-mutation one.  A fresh [load] must still see the coin.
   ---------------------------------------------------------------------- *)
let test_mutation_survives_unclean_restart () =
  setup ();
  let path = db_path () in
  (* Process #1: credit a coin via the connect hook (save-on-mutation), then
     "die" without any graceful shutdown — we just drop the wallet value. *)
  let credited_balance =
    let w = Wallet.create ~network:`Regtest ~db_path:path in
    let kp = Wallet.generate_key w in
    Wallet.save_safe w;  (* persist the keypool advance, as getnewaddress does *)
    let script = Wallet.build_output_script kp.address in
    let blk = make_block_paying ~height:9 ~nonce:3 ~value:1234500000L ~script in
    Wallet.scan_block_and_persist w blk 9;  (* durable per-block persist *)
    w.Wallet.balance_confirmed
    (* no graceful_shutdown / no final save: the process is "killed" here *)
  in
  Alcotest.(check int64) "process #1 credited the coin" 1234500000L credited_balance;
  (* Process #2: a brand-new load off disk. The coin + synced height must be
     present because save-on-mutation wrote them, not a clean-shutdown save. *)
  let w2 = Wallet.load ~network:`Regtest ~db_path:path in
  Alcotest.(check int64) "coin survived unclean restart"
    1234500000L w2.Wallet.balance_confirmed;
  Alcotest.(check int) "synced height survived unclean restart"
    9 w2.Wallet.last_synced_height;
  Alcotest.(check int) "key survived unclean restart" 1 (Wallet.key_count w2);
  rm_rf test_root

(* ----------------------------------------------------------------------
   Test 6 — startup reconcile rebuilds the ledger over a gap of blocks the
   wallet had not yet scanned (last_synced_height behind the tip).
   ---------------------------------------------------------------------- *)
let test_reconcile_fills_gap () =
  setup ();
  let path = db_path () in
  let w = Wallet.create ~network:`Regtest ~db_path:path in
  let kp = Wallet.generate_key w in
  let script = Wallet.build_output_script kp.address in
  (* Chain of 4 blocks (heights 1..4), each paying the wallet 1 BTC.  The
     wallet has scanned NONE of them yet (last_synced_height = -1). *)
  let blocks =
    Array.init 5 (fun h ->
      if h = 0 then None
      else Some (make_block_paying ~height:h ~nonce:h ~value:100000000L ~script))
  in
  let get_block_at h = if h >= 0 && h < Array.length blocks then blocks.(h) else None in
  Wallet.reconcile_to_tip w ~tip_height:4 ~get_block_at;
  Alcotest.(check int) "reconcile credited all 4 blocks" 4
    (List.length (Wallet.get_utxos w));
  Alcotest.(check int64) "reconcile total balance" 400000000L
    w.Wallet.balance_confirmed;
  Alcotest.(check int) "reconcile advanced synced height to tip" 4
    w.Wallet.last_synced_height;
  (* Idempotency: re-running reconcile over the same tip is a no-op (the gap
     is now empty), so no double-count. *)
  Wallet.reconcile_to_tip w ~tip_height:4 ~get_block_at;
  Alcotest.(check int) "second reconcile does not double-count utxos" 4
    (List.length (Wallet.get_utxos w));
  Alcotest.(check int64) "second reconcile does not double-count balance"
    400000000L w.Wallet.balance_confirmed;
  rm_rf test_root

(* ----------------------------------------------------------------------
   Test 7 — partial reconcile (gap starts > 0): scanning only the new
   blocks after last_synced_height does not re-credit already-scanned ones.
   ---------------------------------------------------------------------- *)
let test_reconcile_partial_gap () =
  setup ();
  let path = db_path () in
  let w = Wallet.create ~network:`Regtest ~db_path:path in
  let kp = Wallet.generate_key w in
  let script = Wallet.build_output_script kp.address in
  let blocks =
    Array.init 5 (fun h ->
      if h = 0 then None
      else Some (make_block_paying ~height:h ~nonce:h ~value:100000000L ~script))
  in
  let get_block_at h = if h >= 0 && h < Array.length blocks then blocks.(h) else None in
  (* Pretend blocks 1..2 were already scanned + persisted. *)
  (match get_block_at 1 with Some b -> Wallet.scan_block_and_persist w b 1 | None -> ());
  (match get_block_at 2 with Some b -> Wallet.scan_block_and_persist w b 2 | None -> ());
  Alcotest.(check int) "pre-gap synced height" 2 w.Wallet.last_synced_height;
  Alcotest.(check int) "pre-gap utxos" 2 (List.length (Wallet.get_utxos w));
  (* Reconcile to tip 4: should only add blocks 3..4. *)
  Wallet.reconcile_to_tip w ~tip_height:4 ~get_block_at;
  Alcotest.(check int) "partial reconcile total utxos" 4
    (List.length (Wallet.get_utxos w));
  Alcotest.(check int64) "partial reconcile total balance" 400000000L
    w.Wallet.balance_confirmed;
  Alcotest.(check int) "partial reconcile synced height" 4
    w.Wallet.last_synced_height;
  rm_rf test_root

(* ----------------------------------------------------------------------
   Test 8 — missing file is not an error: load of a non-existent path
   yields a fresh empty wallet (the normal first-run path).
   ---------------------------------------------------------------------- *)
let test_missing_file_fresh () =
  setup ();
  let path = Filename.concat test_root "does_not_exist.json" in
  let w =
    try Wallet.load ~network:`Regtest ~db_path:path
    with exn ->
      Alcotest.failf "load raised on a missing file: %s" (Printexc.to_string exn)
  in
  Alcotest.(check int) "fresh wallet on missing file" 0 (Wallet.key_count w);
  Alcotest.(check int) "fresh synced height -1" (-1) w.Wallet.last_synced_height;
  rm_rf test_root

let () =
  let open Alcotest in
  run "Wallet_persistence" [
    "atomic_save", [
      test_case "save round-trips incl. last_synced_height" `Quick
        test_save_roundtrip;
    ];
    "fault_tolerant_load", [
      test_case "partial/truncated file does not crash load" `Quick
        test_partial_file_does_not_crash;
      test_case "recover from .bak sidecar" `Quick test_recover_from_bak;
      test_case "recover from leftover .tmp (pre-rename crash)" `Quick
        test_recover_from_tmp;
      test_case "missing file -> fresh wallet" `Quick test_missing_file_fresh;
    ];
    "save_on_mutation", [
      test_case "mutation survives a simulated unclean restart" `Quick
        test_mutation_survives_unclean_restart;
    ];
    "startup_reconcile", [
      test_case "reconcile fills a full gap idempotently" `Quick
        test_reconcile_fills_gap;
      test_case "reconcile fills only a partial gap" `Quick
        test_reconcile_partial_gap;
    ];
  ]
