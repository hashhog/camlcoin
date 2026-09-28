(* Control: --import-utxo must not retain a million-coin LRU during the
   load, or RPC never binds inside the campaign wait.

   Campaign 315000→340000 on 3dabf430 ERROR'd "no RPC within 3600s"
   (receipts/camlcoin-rpc-startup-timeout-315000-2026-09-12.md). The
   process was burning CPU, not hung: load_snapshot_into_primary created
   OptimizedUtxoSet ~cache_size:1_000_000 and add() LRU.put every coin.
   Perf.LRU.put with capacity 0 still inserted (length >= 0 is true and
   tail is None, so the evict branch no-ops and the node is still
   pushed). After 1M coins every subsequent add also evicted, so a
   12.7M-coin import allocated ~12.7M dll nodes on the major heap
   before Cli.run wrote the cookie.

   Bar: soak-315000 coins_count (12_707_697) inside the campaign default
   1800 s RPC deadline = 7060 coins/s. A 200k synthetic dump is large
   enough that per-coin LRU/alloc overhead dominates.

   2026-09-27: the loader writes WAL-less RocksDB batches directly (no
   OptimizedUtxoSet). Case (5) pins byte-equivalence with the old flush
   path on both stores; case (6) pins the import-incomplete crash marker.

   Command (first three cases fail if LRU capacity 0 still retains, or
   if the loader still builds a 1M import cache):
     dune exec --no-buffer test/test_snapshot_import_throughput.exe
*)

open Camlcoin

(* soak-315000 coins_count / default CAMPAIGN_RPC_DEADLINE_OVERRIDE. *)
let bar_coins_per_sec = 12_707_697. /. 1800.
let n_import = 200_000

let rec rm_rf path =
  if Sys.file_exists path then begin
    if Sys.is_directory path then begin
      Array.iter (fun f -> rm_rf (Filename.concat path f)) (Sys.readdir path);
      Unix.rmdir path
    end
    else Unix.unlink path
  end

let mk_hash n =
  let cs = Cstruct.create 32 in
  Cstruct.LE.set_uint32 cs 0 (Int32.of_int n);
  cs

let read_file path =
  let ic = open_in path in
  let s = really_input_string ic (in_channel_length ic) in
  close_in ic;
  s

let has_needle src needle =
  let rec go i =
    if i + String.length needle > String.length src then false
    else if String.sub src i (String.length needle) = needle then true
    else go (i + 1)
  in
  go 0

let find_src candidates =
  let rec read = function
    | [] -> None
    | p :: rest ->
      if Sys.file_exists p then Some (read_file p) else read rest
  in
  read candidates

(* ── (1) LRU capacity 0 must not retain a node ──────────────────────── *)

let test_lru_capacity_zero_stores_nothing () =
  let lru : (string, string) Perf.LRU.t = Perf.LRU.create 0 in
  Perf.LRU.put lru "k" "v";
  Alcotest.(check int)
    "capacity 0 must not retain an LRU node" 0 (Perf.LRU.size lru)

(* ── (2) OptimizedUtxoSet ~cache_size:0 is write-only ───────────────── *)

let test_import_cache_is_write_only () =
  let root =
    Printf.sprintf "/tmp/camlcoin_import_cache_%d" (Unix.getpid ())
  in
  rm_rf root;
  Unix.mkdir root 0o755;
  let db = Storage.ChainDB.create (Filename.concat root "chain") in
  Fun.protect
    ~finally:(fun () ->
      Storage.ChainDB.close db;
      rm_rf root)
    (fun () ->
      let utxo = Utxo.OptimizedUtxoSet.create ~cache_size:0 db in
      let script = Cstruct.of_string "\x51" in
      for i = 1 to 10_000 do
        Utxo.OptimizedUtxoSet.add utxo (mk_hash i) 0
          {
            Utxo.value = 1L;
            script_pubkey = script;
            height = 1;
            is_coinbase = false;
          }
      done;
      Alcotest.(check int)
        "write-only import cache stays empty" 0
        (Utxo.OptimizedUtxoSet.cache_size utxo);
      Alcotest.(check int)
        "dirty holds the unflushed coins" 10_000
        (Utxo.OptimizedUtxoSet.dirty_count utxo))

(* ── (3) production loader must not build a 1M import LRU ───────────── *)

let test_loader_is_write_only () =
  let src =
    match
      find_src
        [ "assume_utxo.ml"; "lib/assume_utxo.ml"; "../lib/assume_utxo.ml" ]
    with
    | Some s -> s
    | None -> Alcotest.fail "assume_utxo.ml not found for source scan"
  in
  Alcotest.(check bool)
    "load_snapshot_into_primary no longer builds a 1M import LRU"
    false
    (has_needle src "OptimizedUtxoSet.create ~cache_size:1_000_000");
  (* 2026-09-27: the loader no longer goes through OptimizedUtxoSet at
     all; it streams straight into WAL-less RocksDB batches (the
     byte-equivalence with the old flush format is test (5)). *)
  Alcotest.(check bool)
    "load_snapshot_into_primary streams into WAL-less batches"
    true
    (has_needle src "Rocksdb.write_batch_write_nowal")

(* ── (4) 200k synthetic dump beats 12.7M-in-1800s ───────────────────── *)

let write_synthetic_snapshot path n base_hash =
  let metadata : Assume_utxo.snapshot_metadata =
    {
      network_magic = Consensus.regtest.magic;
      base_blockhash = base_hash;
      coins_count = Int64.of_int n;
    }
  in
  let script = Cstruct.of_string "\x51" in
  match
    Assume_utxo.write_snapshot path metadata ~iter_coins:(fun emit ->
        for i = 0 to n - 1 do
          emit
            {
              Assume_utxo.outpoint = { Types.txid = mk_hash i; vout = 0l };
              value = 1L;
              script_pubkey = script;
              height = 1;
              is_coinbase = false;
            }
        done)
  with
  | Ok () -> ()
  | Error msg -> Alcotest.fail ("write_snapshot: " ^ msg)

let test_import_beats_315000_rpc_deadline () =
  let root =
    Printf.sprintf "/tmp/camlcoin_import_thrput_%d" (Unix.getpid ())
  in
  rm_rf root;
  Unix.mkdir root 0o755;
  let snap = Filename.concat root "snap.dat" in
  let base_hash = mk_hash 0x11 in
  write_synthetic_snapshot snap n_import base_hash;
  Assume_utxo.clear_regtest_assumeutxo ();
  Assume_utxo.register_regtest_assumeutxo
    {
      Assume_utxo.height = 100;
      blockhash = base_hash;
      coins_count = Int64.of_int n_import;
      coins_hash = Cstruct.create 32;
      chain_tx_count = 0L;
      base_header = None;
      base_tail_headers = [];
      chainwork = None;
      base_mtp = None;
    };
  let db = Storage.ChainDB.create (Filename.concat root "chain") in
  let rocksdb =
    Rocksdb_store.open_db (Filename.concat root "rocksdb_utxo")
  in
  Fun.protect
    ~finally:(fun () ->
      Rocksdb_store.close rocksdb;
      Storage.ChainDB.close db;
      Assume_utxo.clear_regtest_assumeutxo ();
      rm_rf root)
    (fun () ->
      let t0 = Unix.gettimeofday () in
      match
        Assume_utxo.load_snapshot_into_primary ~network:Consensus.regtest
          ~snapshot_path:snap ~db ~rocksdb ()
      with
      | Error msg -> Alcotest.fail ("load_snapshot_into_primary: " ^ msg)
      | Ok r ->
        let elapsed = Unix.gettimeofday () -. t0 in
        let rate =
          Int64.to_float r.Assume_utxo.coins_loaded /. max elapsed 1e-6
        in
        Printf.printf
          "imported %Ld coins in %.3fs (%.0f coins/s; bar %.0f)\n%!"
          r.coins_loaded elapsed rate bar_coins_per_sec;
        Alcotest.(check int64)
          "loaded the synthetic dump" (Int64.of_int n_import) r.coins_loaded;
        Alcotest.(check bool)
          "import faster than 12.7M coins in 1800s" true
          (rate >= bar_coins_per_sec))


(* ── (5) bulk loader writes exactly what OptimizedUtxoSet.flush wrote ──
   2026-09-27 the loader stopped going through OptimizedUtxoSet (dirty
   Hashtbl + flush) and writes WAL-less batches directly. Reference: the
   previous path, run on the same coins in a second datadir. Every
   chainstate-CF utxo row, every rocksdb_utxo row and the rocksdb_utxo
   tip_height must match byte for byte. Mixed shapes: multi-vout groups
   with vout >= 256 (LE key order != numeric order), P2PKH / P2SH /
   raw scripts, coinbase flag, a range of heights and values. *)

let bulk_coins () =
  let coins = ref [] in
  for t = 1 to 300 do
    let txid = mk_hash (0x1000 + t) in
    let vouts = if t mod 7 = 0 then [ 0; 1; 2; 255; 256; 300 ] else [ t mod 5 ] in
    List.iter (fun v ->
      let script =
        match (t + v) mod 3 with
        | 0 ->
          let s = Cstruct.create 25 in
          Cstruct.set_uint8 s 0 0x76; Cstruct.set_uint8 s 1 0xa9;
          Cstruct.set_uint8 s 2 0x14; Cstruct.set_uint8 s 3 (t land 0xff);
          Cstruct.set_uint8 s 23 0x88; Cstruct.set_uint8 s 24 0xac; s
        | 1 ->
          let s = Cstruct.create 23 in
          Cstruct.set_uint8 s 0 0xa9; Cstruct.set_uint8 s 1 0x14;
          Cstruct.set_uint8 s 2 (v land 0xff); Cstruct.set_uint8 s 22 0x87; s
        | _ -> Cstruct.of_string (String.make (1 + (t mod 40)) '\x51')
      in
      coins := {
        Assume_utxo.outpoint = { Types.txid; vout = Int32.of_int v };
        value = Int64.of_int (t * 1000 + v);
        script_pubkey = script;
        height = 1 + (t mod 90);
        is_coinbase = (t mod 11 = 0);
      } :: !coins) vouts
  done;
  (* Core dumps in coins-DB key order: txid bytes ascending (then vout).
     The load-time HASH_SERIALIZED fold relies on that order, exactly as
     Core's snapshot writer guarantees it. *)
  List.stable_sort
    (fun (a : Assume_utxo.snapshot_coin) (b : Assume_utxo.snapshot_coin) ->
      Cstruct.compare a.outpoint.Types.txid b.outpoint.Types.txid)
    (List.rev !coins)

let register_base base_hash n =
  Assume_utxo.clear_regtest_assumeutxo ();
  Assume_utxo.register_regtest_assumeutxo
    {
      Assume_utxo.height = 100;
      blockhash = base_hash;
      coins_count = Int64.of_int n;
      coins_hash = Cstruct.create 32;
      chain_tx_count = 0L;
      base_header = None;
      base_tail_headers = [];
      chainwork = None;
      base_mtp = None;
    }

let write_coins path base_hash coins =
  let metadata : Assume_utxo.snapshot_metadata = {
    network_magic = Consensus.regtest.magic;
    base_blockhash = base_hash;
    coins_count = Int64.of_int (List.length coins);
  } in
  match Assume_utxo.write_snapshot path metadata
          ~iter_coins:(fun emit -> List.iter emit coins) with
  | Ok () -> ()
  | Error msg -> Alcotest.fail ("write_snapshot: " ^ msg)

let cf_rows (db : Storage.ChainDB.t) =
  let cf = db.Storage.ChainDB.cf in
  let rows = ref [] in
  Rocksdb.cf_iter cf.Cf_chainstate.db cf.Cf_chainstate.cfh_utxo
    (fun k v -> rows := (k, v) :: !rows);
  List.rev !rows

let check_bulk_load_matches_flush ~tag ~(coins : Assume_utxo.snapshot_coin list)
    ~check_hash =
  let root = Printf.sprintf "/tmp/camlcoin_bulk_eq_%s_%d" tag (Unix.getpid ()) in
  rm_rf root;
  Unix.mkdir root 0o755;
  let n = List.length coins in
  (* Distinct outpoints: what the stores must hold (last write wins). *)
  let n_distinct =
    let h = Hashtbl.create n in
    List.iter (fun (c : Assume_utxo.snapshot_coin) ->
      Hashtbl.replace h (Cstruct.to_string c.outpoint.Types.txid,
                         c.outpoint.Types.vout) ()) coins;
    Hashtbl.length h in
  let base_hash = mk_hash 0x22 in
  let snap = Filename.concat root "snap.dat" in
  write_coins snap base_hash coins;
  register_base base_hash n;
  let db_a = Storage.ChainDB.create (Filename.concat root "a_chain") in
  let rdb_a = Rocksdb_store.open_db (Filename.concat root "a_rdb") in
  let db_b = Storage.ChainDB.create (Filename.concat root "b_chain") in
  let rdb_b = Rocksdb_store.open_db (Filename.concat root "b_rdb") in
  Fun.protect
    ~finally:(fun () ->
      Rocksdb_store.close rdb_a; Storage.ChainDB.close db_a;
      Rocksdb_store.close rdb_b; Storage.ChainDB.close db_b;
      Assume_utxo.clear_regtest_assumeutxo ();
      rm_rf root)
    (fun () ->
      (match Assume_utxo.load_snapshot_into_primary
               ~network:Consensus.regtest ~snapshot_path:snap
               ~db:db_a ~rocksdb:rdb_a () with
       | Error msg -> Alcotest.fail ("load_snapshot_into_primary: " ^ msg)
       | Ok r ->
         Alcotest.(check int64) "coins loaded" (Int64.of_int n)
           r.Assume_utxo.coins_loaded);
      (* Reference: the pre-2026-09-27 write path over the same FILE
         (file order decides which copy of a duplicate wins). *)
      let utxo = Utxo.OptimizedUtxoSet.create ~cache_size:0 ~rocksdb:rdb_b db_b in
      let ic = open_in_bin snap in
      let sr = Assume_utxo.Stream_reader.create ic
          ~start_offset:Assume_utxo.snapshot_body_offset in
      (match Assume_utxo.iter_snapshot_coins sr
               ~coins_count:(Int64.of_int n) ~f:(fun c ->
                 Utxo.OptimizedUtxoSet.add utxo c.outpoint.Types.txid
                   (Int32.to_int c.outpoint.Types.vout)
                   { Utxo.value = c.value; script_pubkey = c.script_pubkey;
                     height = c.height; is_coinbase = c.is_coinbase }) with
       | Ok _ -> close_in ic
       | Error e -> close_in ic; Alcotest.fail ("reference parse: " ^ e));
      Utxo.OptimizedUtxoSet.flush ~tip_height:100 utxo;
      let ra = cf_rows db_a and rb = cf_rows db_b in
      Alcotest.(check int) "cf utxo row count" n_distinct (List.length ra);
      Alcotest.(check bool) "cf utxo rows byte-identical" true (ra = rb);
      List.iter (fun (k, v) ->
        Alcotest.(check (option string)) "rocksdb_utxo row"
          (Some v) (Rocksdb_store.get rdb_a k);
        Alcotest.(check (option string)) "reference rocksdb_utxo row"
          (Some v) (Rocksdb_store.get rdb_b k)) rb;
      Alcotest.(check (option int)) "rocksdb_utxo tip_height"
        (Rocksdb_store.get_tip_height rdb_b) (Rocksdb_store.get_tip_height rdb_a);
      Alcotest.(check bool) "marker cleared after a completed import" false
        (Storage.ChainDB.snapshot_import_incomplete db_a);
      (* HASH_SERIALIZED from the DB walk == the value folded at load
         (meaningful only for a canonically ordered snapshot). *)
      if check_hash then begin
        let walked = Assume_utxo.compute_utxo_hash_from_db db_a in
        match Assume_utxo.cached_txoutset_for_tip base_hash 100 with
        | None -> Alcotest.fail "load did not seed the txoutset cache"
        | Some c ->
          Alcotest.(check string) "hash_serialized: load fold == DB walk"
            (Types.hash256_to_hex_display walked)
            (Types.hash256_to_hex_display c.Assume_utxo.hash_serialized)
      end)

let test_bulk_load_matches_flush_format () =
  check_bulk_load_matches_flush ~tag:"sorted" ~coins:(bulk_coins ())
    ~check_hash:true

(* Not in coins-DB order, plus a duplicated outpoint whose later copy
   differs: the later copy must win exactly as it did through the dirty
   Hashtbl. *)
let test_bulk_load_unsorted_matches_flush () =
  let coins = bulk_coins () in
  let rev = List.rev coins in
  let dup =
    match coins with
    | c :: _ -> { c with Assume_utxo.value = Int64.add c.Assume_utxo.value 7L }
    | [] -> assert false
  in
  check_bulk_load_matches_flush ~tag:"unsorted" ~coins:(rev @ [ dup ])
    ~check_hash:false

(* ── (6) a failed import leaves the marker set ───────────────────────── *)

let test_failed_import_leaves_marker () =
  let root = Printf.sprintf "/tmp/camlcoin_bulk_fail_%d" (Unix.getpid ()) in
  rm_rf root;
  Unix.mkdir root 0o755;
  let coins = bulk_coins () in
  let n = List.length coins in
  let base_hash = mk_hash 0x33 in
  let snap = Filename.concat root "snap.dat" in
  write_coins snap base_hash coins;
  (* Truncate: the metadata still promises [n] coins. *)
  let full = read_file snap in
  let oc = open_out_bin snap in
  output_string oc (String.sub full 0 (String.length full - 40));
  close_out oc;
  register_base base_hash n;
  let db = Storage.ChainDB.create (Filename.concat root "chain") in
  let rdb = Rocksdb_store.open_db (Filename.concat root "rdb") in
  Fun.protect
    ~finally:(fun () ->
      Rocksdb_store.close rdb; Storage.ChainDB.close db;
      Assume_utxo.clear_regtest_assumeutxo ();
      rm_rf root)
    (fun () ->
      Alcotest.(check bool) "fresh chainstate has no marker" false
        (Storage.ChainDB.snapshot_import_incomplete db);
      (match Assume_utxo.load_snapshot_into_primary
               ~network:Consensus.regtest ~snapshot_path:snap
               ~db ~rocksdb:rdb () with
       | Ok _ -> Alcotest.fail "truncated snapshot must not load"
       | Error _ -> ());
      Alcotest.(check bool) "marker left set by the failed import" true
        (Storage.ChainDB.snapshot_import_incomplete db);
      Alcotest.(check bool) "no chain tip recorded" true
        (match Storage.ChainDB.get_chain_tip db with
         | Some (_, h) -> h = 0 | None -> true))

let () =
  Alcotest.run "snapshot-import-throughput"
    [
      ( "lru",
        [
          Alcotest.test_case "capacity 0 stores nothing" `Quick
            test_lru_capacity_zero_stores_nothing;
          Alcotest.test_case "import cache_size 0 is write-only" `Quick
            test_import_cache_is_write_only;
          Alcotest.test_case "loader uses write-only import cache" `Quick
            test_loader_is_write_only;
        ] );
      ( "load",
        [
          Alcotest.test_case
            "200k coins beat the 315000 RPC-deadline bar" `Slow
            test_import_beats_315000_rpc_deadline;
          Alcotest.test_case
            "bulk loader == OptimizedUtxoSet.flush, byte for byte" `Quick
            test_bulk_load_matches_flush_format;
          Alcotest.test_case
            "unsorted / duplicated snapshot == flush (last write wins)"
            `Quick test_bulk_load_unsorted_matches_flush;
          Alcotest.test_case
            "failed import leaves the incomplete marker set" `Quick
            test_failed_import_leaves_marker;
        ] );
    ]
