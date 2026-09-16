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
  Alcotest.(check bool)
    "load_snapshot_into_primary uses a write-only (capacity 0) cache"
    true
    (has_needle src "OptimizedUtxoSet.create ~cache_size:0")

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
        ] );
    ]
