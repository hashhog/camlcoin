(* Snapshot boot must not decide BIP68 from a partial pre-base header band.

   R4 slice 930000-940000 (camlcoin a059496, 2026-10-03): the campaign
   snapshot at 930000 carries a 2,027-header band, root 927974.  Valid
   mainnet block 932256 tx 1600 input 0 spends a coin created at 927979 with
   nSequence 0x004013c7 (time lock 5063 * 512 s).  Core
   (consensus/tx_verify.cpp CalculateSequenceLocks):
     nCoinTime = block.GetAncestor(927978)->GetMedianTimePast() = 1765804000
   camlcoin's height-index callback found only 927974..927978 and returned
   their median, 1765808303 (log: `input_mtp=1765808303 median_time=1768398550
   required=1768400559 short_by=2009s`), so the block was rejected.  For
   coins below the band root the same callback returned median([]) = 0:
   every time lock satisfied (fail-open).

   All timestamps below are mainnet headers read from Core RPC
   (getblockheader, 2026-10-03).  Core's mediantime(927978) = 1765804000,
   mediantime(932255) = 1768398550.

   Control:  cd _build/default/test && ./test_snapshot_prebase_headers.exe *)

open Camlcoin

let test_db_base =
  Test_tmp.register "/tmp/camlcoin_test_snapshot_prebase_headers"
let test_db_path = ref test_db_base

let rec rm_rf path =
  if Sys.file_exists path then begin
    if Sys.is_directory path then begin
      Array.iter (fun f -> rm_rf (Filename.concat path f)) (Sys.readdir path);
      Unix.rmdir path
    end else Unix.unlink path
  end

let use_db name =
  test_db_path := test_db_base ^ "_" ^ name;
  Test_tmp.register !test_db_path |> ignore;
  rm_rf !test_db_path

(* ---- the real 932256 numbers ---- *)

let real_ts = [
  927968, 1765801866l; 927969, 1765802240l; 927970, 1765802404l;
  927971, 1765802919l; 927972, 1765803403l; 927973, 1765804000l;
  927974, 1765807568l; 927975, 1765807695l; 927976, 1765808303l;
  927977, 1765808711l; 927978, 1765809159l;
]
let core_coin_mtp = 1765804000l          (* Core mediantime(927978) *)
let partial_band_mtp = 1765808303l       (* camlcoin's logged input_mtp *)
let block_mtp_932256 = 1768398550l       (* Core mediantime(932255) *)
let coin_height = 927979
let block_height = 932256
let band_root = 927974
let seq = 0x004013c7l                    (* type flag | 5063 *)

let ts_of h =
  match List.assoc_opt h real_ts with
  | Some t -> t
  | None -> Int32.of_int (1765809159 + ((h - 927978) * 600))

let spending_tx =
  Types.{
    version = 2l;
    inputs = [ { previous_output = { txid = Types.zero_hash; vout = 0l };
                 script_sig = Cstruct.empty; sequence = seq } ];
    outputs = [];
    witnesses = [];
    locktime = 0l;
  }

let csv_flags = Script.script_verify_checksequenceverify

let check_locks get_mtp_at_height =
  Validation.check_sequence_locks spending_tx ~block_height
    ~median_time:block_mtp_932256 ~utxo_heights:[| coin_height |]
    ~utxo_mtps:[| 0l |] ?get_mtp_at_height ~flags:csv_flags ()

(* An in-memory header chain [lo, 932255] at real heights, linked by
   prev_block, with height->hash rows exactly as the campaign import writes
   them for the band (and as IBD writes them above the base).  [lo] =
   [band_root] is the snapshot-boot shape; a lower [lo] is the chain after
   the pre-base headers were obtained. *)
let build_chain ~name ~lo =
  use_db name;
  let db = Storage.ChainDB.create !test_db_path in
  let state = Sync.create_chain_state db Consensus.mainnet in
  let prev = ref (Cstruct.create 32) in
  Cstruct.memset !prev 0x11;
  let parent = ref None in
  for h = lo to block_height - 1 do
    let header = Types.{ version = 0x20000000l; prev_block = !prev;
                         merkle_root = Types.zero_hash; timestamp = ts_of h;
                         bits = 0x1701e63al; nonce = Int32.of_int h } in
    let hash = Crypto.compute_block_hash header in
    let e = Sync.{ header; hash; height = h; total_work = Consensus.zero_work } in
    Hashtbl.replace state.Sync.headers (Cstruct.to_string hash) e;
    Storage.ChainDB.set_height_hash db h hash;
    prev := hash;
    parent := Some e
  done;
  let parent = match !parent with Some p -> p | None -> assert false in
  state.Sync.tip <- Some parent;
  state.Sync.blocks_synced <- parent.Sync.height;
  (db, state, parent)

(* 1. The consensus anchor, independent of any chain state. *)
let test_core_anchor () =
  let full = List.map snd real_ts in
  Alcotest.(check int32) "median of the 11 real headers == Core mediantime(927978)"
    core_coin_mtp (Consensus.median_time_past full);
  let band = List.filter_map (fun (h, t) -> if h >= band_root then Some t else None) real_ts in
  Alcotest.(check int32) "median of the 5 band headers == camlcoin's logged input_mtp"
    partial_band_mtp (Consensus.median_time_past band);
  Alcotest.(check bool) "Core's coin time satisfies the lock (932256 valid)" true
    (check_locks (Some (fun _ -> core_coin_mtp)));
  Alcotest.(check bool) "the partial-band coin time rejects it (the bug)" false
    (check_locks (Some (fun _ -> partial_band_mtp)))

(* 2. Snapshot-boot shape (band from 927974): the OLD height-index callback
   reproduces both failure modes; the checked lookup refuses to judge. *)
let test_band_only_fails_closed () =
  let db, state, parent = build_chain ~name:"band" ~lo:band_root in
  (* NEGATIVE CONTROL — the pre-fix callback. *)
  Alcotest.(check int32) "OLD get_mtp_for_height: partial median (wrong reject)"
    partial_band_mtp (Sync.get_mtp_for_height state coin_height);
  Alcotest.(check bool) "OLD callback rejects valid 932256" false
    (check_locks (Some (Sync.get_mtp_for_height state)));
  Alcotest.(check int32) "OLD get_mtp_for_height below the band: 0 (fail-open)"
    0l (Sync.get_mtp_for_height state 900000);
  (* The fix. *)
  (match Sync.resolve_coin_mtp state ~parent coin_height with
   | Ok v -> Alcotest.failf "resolve_coin_mtp judged from a partial window: %ld" v
   | Error e -> Alcotest.(check bool) "partial window: ancestry-incomplete" true
                  (Sync.is_ancestry_incomplete e));
  (match Sync.resolve_coin_mtp state ~parent 900000 with
   | Ok v -> Alcotest.failf "resolve_coin_mtp judged a coin below the band: %ld" v
   | Error e -> Alcotest.(check bool) "below the band: ancestry-incomplete" true
                  (Sync.is_ancestry_incomplete e));
  let f, failed = Sync.checked_coin_mtp_lookup state ~prev_block:parent.Sync.hash in
  Alcotest.(check bool) "checked lookup: lock reads as unsatisfied, never satisfied"
    false (check_locks (Some f));
  Alcotest.(check bool) "checked lookup: the caller is told it was not judged" true
    (match failed () with Some e -> Sync.is_ancestry_incomplete e | None -> false);
  (* Old coins must not slip through either (the fail-open half). *)
  let f2, failed2 = Sync.checked_coin_mtp_lookup state ~prev_block:parent.Sync.hash in
  ignore (f2 900000);
  Alcotest.(check bool) "coin below the band: probe set" true (failed2 () <> None);
  (* Unknown parent. *)
  let f3, failed3 = Sync.checked_coin_mtp_lookup state ~prev_block:Types.zero_hash in
  ignore (f3 coin_height);
  Alcotest.(check bool) "unknown parent: probe set" true (failed3 () <> None);
  Storage.ChainDB.close db

(* 3. With the pre-base headers present (what the from-genesis header sync
   provides), the checked lookup returns Core's value and 932256 is valid —
   through the index fast path AND through the prev_block walk. *)
let test_full_window_matches_core () =
  let db, state, parent = build_chain ~name:"full" ~lo:927960 in
  (match Sync.resolve_coin_mtp state ~parent coin_height with
   | Ok v -> Alcotest.(check int32) "coin time == Core mediantime(927978)" core_coin_mtp v
   | Error e -> Alcotest.failf "full window unresolved: %s" e);
  let f, failed = Sync.checked_coin_mtp_lookup state ~prev_block:parent.Sync.hash in
  Alcotest.(check bool) "932256 sequence locks satisfied" true (check_locks (Some f));
  Alcotest.(check bool) "probe clear" true (failed () = None);
  (* Off the active chain (no index row for the parent): prev_block walk. *)
  let side = { parent with Sync.hash = Cstruct.of_string (String.make 32 '\x42') } in
  Hashtbl.replace state.Sync.headers (Cstruct.to_string side.Sync.hash) side;
  (match Sync.resolve_coin_mtp state ~parent:side coin_height with
   | Ok v -> Alcotest.(check int32) "walk path == Core" core_coin_mtp v
   | Error e -> Alcotest.failf "walk path unresolved: %s" e);
  Storage.ChainDB.close db

(* 4. Restore: a campaign band that does not reach genesis is an island.
   The node must re-sync headers from genesis (Core has the full header
   chain before it uses a snapshot) instead of validating past the base
   from the band.  Regtest, real PoW, a 12-block chain; band = 8..10, base
   10.  After the re-anchor, feeding headers 1..12 from genesis rebuilds
   the chain with real heights and real chainwork and the base is the
   snapshot's base hash. *)
let mine prev h =
  let rec go n =
    let hdr = Types.{ version = 4l; prev_block = prev;
                      merkle_root = Types.zero_hash;
                      timestamp = Int32.of_int (1_296_688_602 + (h * 600));
                      bits = 0x207fffffl; nonce = n } in
    let hash = Crypto.compute_block_hash hdr in
    if Consensus.check_proof_of_work hash hdr.bits Consensus.regtest then (hdr, hash)
    else go (Int32.add n 1l)
  in
  go 0l

let test_restore_island_resyncs_from_genesis () =
  use_db "restore";
  let net = Consensus.regtest in
  let genesis_hash = Crypto.compute_block_hash net.genesis_header in
  let chain = Array.make 13 (net.genesis_header, genesis_hash) in
  for h = 1 to 12 do chain.(h) <- mine (snd chain.(h - 1)) h done;
  let base = 10 in
  let base_hash = snd chain.(base) in
  let db = Storage.ChainDB.create !test_db_path in
  let _ = Sync.create_chain_state db net in
  (* What load_snapshot_into_primary + persist_assumeutxo_base_headers write
     for a band 8..10: header bytes + height rows for the band, tips at base. *)
  for h = 8 to base do
    let hdr, hash = chain.(h) in
    Storage.ChainDB.store_block_header db hash hdr;
    Storage.ChainDB.set_height_hash db h hash
  done;
  Storage.ChainDB.set_header_tip db base_hash base;
  Storage.ChainDB.set_chain_tip db base_hash base;
  Storage.ChainDB.close db;
  let db = Storage.ChainDB.create !test_db_path in
  let state = Sync.restore_chain_state db net in
  (match state.Sync.tip with
   | Some t -> Alcotest.(check int) "island re-anchored at genesis" 0 t.Sync.height
   | None -> Alcotest.fail "no tip after restore");
  Alcotest.(check int) "headers_synced 0 -> blocking from-genesis sync runs"
    0 state.Sync.headers_synced;
  Alcotest.(check bool) "blocking header sync will run" true
    (Sync.should_run_blocking_header_sync state);
  Alcotest.(check int) "blocks_synced kept at the snapshot base" base
    state.Sync.blocks_synced;
  Alcotest.(check bool) "band not judged from: base absent until re-synced" true
    (Sync.get_header state base_hash = None);
  (* A block on top of the base cannot be judged yet: fail closed. *)
  let next_hdr = fst chain.(base + 1) in
  (match Sync.resolve_expected_bits state (base + 1) next_hdr with
   | Ok _ -> Alcotest.fail "judged base+1 before the header chain exists"
   | Error e -> Alcotest.(check bool) "base+1 ancestry-incomplete" true
                  (Sync.is_ancestry_incomplete e));
  (* The from-genesis header sync. *)
  let hdrs = List.init 12 (fun i -> fst chain.(i + 1)) in
  (match Sync.process_headers state hdrs with
   | Ok n -> Alcotest.(check int) "12 headers accepted from genesis" 12 n
   | Error e -> Alcotest.failf "process_headers: %s" e);
  (match Sync.get_header state base_hash with
   | None -> Alcotest.fail "snapshot base not in the re-synced chain"
   | Some e ->
     Alcotest.(check int) "base at its real height" base e.Sync.height;
     let w = ref Consensus.zero_work in
     for h = 0 to base do
       w := Consensus.work_add !w (Consensus.work_from_compact (fst chain.(h)).Types.bits)
     done;
     Alcotest.(check bool) "base chainwork is the real from-genesis work" true
       (Consensus.work_compare e.Sync.total_work !w = 0));
  Alcotest.(check bool) "base+1 now judged" true
    (match Sync.resolve_expected_bits state (base + 1) next_hdr with
     | Ok _ -> true | Error _ -> false);
  Storage.ChainDB.close db;
  (* Restart after the re-sync: the 297ab99 heal restores the rows from the
     stored header bytes; no island, no second re-sync. *)
  let db = Storage.ChainDB.create !test_db_path in
  let state = Sync.restore_chain_state db net in
  (match state.Sync.tip with
   | Some t -> Alcotest.(check int) "restart keeps the full chain (no re-anchor)" 12 t.Sync.height
   | None -> Alcotest.fail "no tip after second restore");
  Alcotest.(check bool) "height 1 in the table after restart" true
    (Sync.get_header state (snd chain.(1)) <> None);
  Storage.ChainDB.close db

let () =
  Alcotest.run "snapshot_prebase_headers" [
    "932256 BIP68 coin time across a snapshot band", [
      Alcotest.test_case "Core anchor (real mainnet numbers)" `Quick test_core_anchor;
      Alcotest.test_case "band only: old callback wrong, checked lookup fails closed"
        `Quick test_band_only_fails_closed;
      Alcotest.test_case "full window: checked lookup == Core, 932256 valid"
        `Quick test_full_window_matches_core;
      Alcotest.test_case "restore: band island re-syncs headers from genesis"
        `Quick test_restore_island_resyncs_from_genesis;
    ];
  ]
