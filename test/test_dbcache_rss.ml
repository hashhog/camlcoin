(* Control: --dbcache must bound the RocksDB block cache, not just the LRU.

   Campaign slice 419311→450000 on 2da7d6b with --dbcache 4194304
   (~1 GB at 256 B/entry, range-runner.sh) held 11.2 GB RSS. The LRU is
   bounded; Rocksdb_store.open_db ignored the flag and opened an 8192 MiB
   SST cache, and Cf_chainstate.open_db a 2048 MiB one. Bulk validation
   from a snapshot fills those caches. Mainnet at tip only touches a
   small working set, which is why the live deploy stayed ~4 GB.

   Revert of block_cache_mb_of_dbcache (or of cli.ml / bin/main.ml not
   passing it) makes:
     - 1M/4M/16M curve flat at 8192
     - campaign 4_194_304 → 8192 (not 256)
     - production open still uses the hardcoded 8192 default

   Command (red on HEAD: Program not found; green after):
     dune exec --no-buffer test/test_dbcache_rss.exe
*)

open Camlcoin

let n1 = 1_048_576
let n4 = 4_194_304
let n16 = 16_777_216

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

let require_src name candidates =
  match find_src candidates with
  | Some s -> s
  | None -> Alcotest.fail (name ^ " not found for source scan")

let rss_kb () =
  let ic = open_in "/proc/self/status" in
  let rec go () =
    let line = input_line ic in
    if String.length line >= 6 && String.sub line 0 6 = "VmRSS:" then begin
      close_in ic;
      Scanf.sscanf (String.trim (String.sub line 6 (String.length line - 6)))
        "%d kB" (fun n -> n)
    end
    else go ()
  in
  try go () with exn -> close_in_noerr ic; raise exn

(* ── (1) 1M / 4M / 16M curve tracks the budget, campaign is not 8 GiB ── *)

let test_curve_tracks_budget () =
  let mb = Rocksdb_store.block_cache_mb_of_dbcache in
  let a = mb n1 in
  let b = mb n4 in
  let c = mb n16 in
  Printf.printf
    "dbcache 1M/4M/16M entries → rocksdb block cache %d/%d/%d MiB \
     (campaign 4194304 → %d MiB; was 8192)\n%!"
    a b c b;
  Alcotest.(check bool) "1M < 4M (curve tracks)" true (a < b);
  Alcotest.(check bool) "4M < 16M or 16M at 512 cap" true (b < c || c = 512);
  Alcotest.(check int) "campaign 4_194_304 → 256 MiB, not 8192" 256 b;
  Alcotest.(check bool) "campaign << 8192" true (b <= 256);
  Alcotest.(check bool) "1M still has a floor" true (a >= 32);
  Alcotest.(check int) "16M capped at 512" 512 c;
  let wa = Rocksdb_store.write_buffer_mb_of_dbcache n1 in
  let wb = Rocksdb_store.write_buffer_mb_of_dbcache n4 in
  let wc = Rocksdb_store.write_buffer_mb_of_dbcache n16 in
  Printf.printf
    "dbcache 1M/4M/16M entries → write buffer %d/%d/%d MiB\n%!" wa wb wc;
  Alcotest.(check bool) "write buffer tracks or caps" true (wa <= wb && wb <= wc);
  Alcotest.(check bool) "write buffer << 256 at campaign" true (wb <= 64)

(* ── (2) production open records the derived size ───────────────────── *)

let test_open_records_passed_cache () =
  Test_tmp.with_dir ~label:"rdb" ~mkdir:true (fun dir ->
      let path = Filename.concat dir "rocks" in
      let t =
        Rocksdb_store.open_db ~block_cache_mb:64 ~write_buffer_mb:16 path
      in
      Fun.protect
        ~finally:(fun () -> Rocksdb_store.close t)
        (fun () ->
          Alcotest.(check int)
            "recorded block cache" 64 (Rocksdb_store.block_cache_mb t);
          Alcotest.(check int)
            "recorded write buffer" 16 (Rocksdb_store.write_buffer_mb t);
          Alcotest.(check int)
            "bytes = MiB << 20" (64 * 1024 * 1024)
            (Rocksdb_store.block_cache_bytes t)))

let test_tmp_path_stays_small () =
  Test_tmp.with_dir ~label:"rdb" ~mkdir:true (fun dir ->
      let path = Filename.concat dir "rocks" in
      let t = Rocksdb_store.open_db path in
      Fun.protect
        ~finally:(fun () -> Rocksdb_store.close t)
        (fun () ->
          Alcotest.(check int)
            "tmp path does not inherit the 8 GiB default" 8
            (Rocksdb_store.block_cache_mb t)))

(* ── (3) LRU entry budget is honoured ───────────────────────────────── *)

let test_lru_honours_capacity () =
  Test_tmp.with_chaindb (fun db ->
      let cap = 10_000 in
      let utxo = Utxo.OptimizedUtxoSet.create ~cache_size:cap db in
      let script = Cstruct.of_string "\x51" in
      for i = 1 to (cap * 3) do
        let cs = Cstruct.create 32 in
        Cstruct.LE.set_uint32 cs 0 (Int32.of_int i);
        Utxo.OptimizedUtxoSet.add utxo cs 0
          {
            Utxo.value = 1L;
            script_pubkey = script;
            height = 1;
            is_coinbase = false;
          }
      done;
      Alcotest.(check int)
        "LRU stays at --dbcache capacity" cap
        (Utxo.OptimizedUtxoSet.cache_size utxo);
      Alcotest.(check int)
        "capacity accessor matches" cap
        (Utxo.OptimizedUtxoSet.cache_capacity utxo))

(* ── (4) small-scale RSS: filling 4x entries costs more RSS ─────────── *)

let fill_lru n =
  let lru : (string, string) Perf.LRU.t = Perf.LRU.create n in
  for i = 1 to n do
    let k = Printf.sprintf "%032d" i in
    Perf.LRU.put lru k k
  done;
  lru

let test_lru_rss_tracks_entries () =
  Gc.compact ();
  let r0 = rss_kb () in
  let a = fill_lru 8_000 in
  Gc.major ();
  let r1 = rss_kb () in
  let b = fill_lru 32_000 in
  Gc.major ();
  let r2 = rss_kb () in
  let c = fill_lru 128_000 in
  Gc.major ();
  let r3 = rss_kb () in
  (* Keep the LRUs reachable so the collector cannot drop them before
     we read RSS. *)
  let live = Perf.LRU.size a + Perf.LRU.size b + Perf.LRU.size c in
  Printf.printf
    "LRU RSS kb: empty=%d 8k=%d (d=%d) 32k=%d (d=%d) 128k=%d (d=%d) live=%d\n%!"
    r0 r1 (r1 - r0) r2 (r2 - r1) r3 (r3 - r2) live;
  Alcotest.(check int) "8k filled" 8_000 (Perf.LRU.size a);
  Alcotest.(check int) "32k filled" 32_000 (Perf.LRU.size b);
  Alcotest.(check int) "128k filled" 128_000 (Perf.LRU.size c);
  Alcotest.(check bool)
    "more entries → more RSS (8k < 128k)" true (r3 > r1)

(* ── (5) production path actually uses the mapping ──────────────────── *)

let test_production_open_uses_mapping () =
  let cli =
    require_src "cli.ml" [ "lib/cli.ml"; "cli.ml"; "../lib/cli.ml" ]
  in
  let main =
    require_src "main.ml" [ "bin/main.ml"; "main.ml"; "../bin/main.ml" ]
  in
  let store =
    require_src "rocksdb_store.ml"
      [ "lib/rocksdb_store.ml"; "rocksdb_store.ml"; "../lib/rocksdb_store.ml" ]
  in
  let cf =
    require_src "cf_chainstate.ml"
      [ "lib/cf_chainstate.ml"; "cf_chainstate.ml"; "../lib/cf_chainstate.ml" ]
  in
  Alcotest.(check bool)
    "cli.ml sizes RocksDB from --dbcache" true
    (has_needle cli "block_cache_mb_of_dbcache");
  Alcotest.(check bool)
    "bin/main.ml sizes import RocksDB from --dbcache" true
    (has_needle main "block_cache_mb_of_dbcache");
  Alcotest.(check bool)
    "rocksdb_store.ml no longer hardcodes 8192 MiB" false
    (has_needle store "block_cache_mb=8192");
  Alcotest.(check bool)
    "cf_chainstate.ml no longer hardcodes 2048 MiB fallback" false
    (has_needle cf "else 2048")

let () =
  Alcotest.run "dbcache_rss"
    [
      ( "mapping",
        [
          Alcotest.test_case
            "1M/4M/16M rocksdb cache tracks --dbcache; campaign is 256 MiB not \
             8192" `Quick test_curve_tracks_budget;
        ] );
      ( "open",
        [
          Alcotest.test_case "open_db records passed cache size" `Quick
            test_open_records_passed_cache;
          Alcotest.test_case "tmp path stays at 8 MiB" `Quick
            test_tmp_path_stays_small;
        ] );
      ( "lru",
        [
          Alcotest.test_case "LRU honours entry capacity" `Quick
            test_lru_honours_capacity;
          Alcotest.test_case "LRU RSS grows with entry count" `Quick
            test_lru_rss_tracks_entries;
        ] );
      ( "source",
        [
          Alcotest.test_case "production open uses block_cache_mb_of_dbcache"
            `Quick test_production_open_uses_mapping;
        ] );
    ]
