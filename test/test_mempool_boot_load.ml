(* Control: boot must answer RPC while mempool.dat reloads, and the
   reload itself must not quadratic-copy the remaining payload.

   QUEUES.md item 1 (2026-09-17). Live boots spent 16–20 min CPU-bound in
   the OCaml major GC after `Per-block content check PASSED` and before
   `Loaded N transactions from mempool.dat`. gdb: caml_blit_string_to_bigstring
   ← Cstruct.blit_from_string, then do_some_marking. load_mempool did
     Cstruct.of_string ~off:r.r_pos ~len:remaining r.r_data
   for every tx, copying the unread tail (70 MB down to 0) into a new
   Bigarray — O(n²) memcpy + GC of 17k large custom blocks. RPC/P2P were
   still unstarted because Cli.run loaded the dump on the main thread
   before Lwt.async of start_rpc_server.

   Core: init.cpp background_init_thread LoadMempool; RPC is callable
   (SetRPCWarmupFinished) while that thread runs.

   Command (first three cases fail on the pre-fix bodies):
     dune exec --no-buffer test/test_mempool_boot_load.exe
*)

open Camlcoin

(* 17000 × ~4 KiB ≈ 70 MB, matching the live 74 MB / 17164-tx dump.
   Pre-fix remaining-tail copies are ~17k * 35 MB ≈ 600 GB plus GC of
   that many large Bigarrays and miss the 60 s bar (live was 16–20 min).
   Post-fix is one wrap of the file plus per-tx field copies. *)
let n_txs = 17_000
let pad_bytes = 4_096
let bar_seconds = 60.0

let read_file path =
  let ic = open_in_bin path in
  Fun.protect
    ~finally:(fun () -> close_in_noerr ic)
    (fun () -> really_input_string ic (in_channel_length ic))

let has_needle src needle =
  let n = String.length needle in
  let h = String.length src in
  let rec go i =
    if i + n > h then false
    else if String.sub src i n = needle then true
    else go (i + 1)
  in
  n = 0 || go 0

let find_src name =
  let candidates =
    [
      name;
      Filename.concat "lib" name;
      Filename.concat ".." name;
      Filename.concat "../lib" name;
      Filename.concat "../../lib" name;
      Filename.concat "/home/work/hashhog/camlcoin/lib" name;
    ]
  in
  match List.find_opt Sys.file_exists candidates with
  | Some p -> read_file p
  | None -> Alcotest.fail (name ^ " not found for source scan")

let find_cli () =
  let candidates =
    [
      "cli.ml";
      "lib/cli.ml";
      "../lib/cli.ml";
      "../../lib/cli.ml";
      "/home/work/hashhog/camlcoin/lib/cli.ml";
    ]
  in
  match List.find_opt Sys.file_exists candidates with
  | Some p -> read_file p
  | None -> Alcotest.fail "cli.ml not found for source scan"

let index_of hay needle =
  let n = String.length needle in
  let h = String.length hay in
  let rec go i =
    if i + n > h then None
    else if String.sub hay i n = needle then Some i
    else go (i + 1)
  in
  go 0

(* ── (1) no per-tx remaining-payload Cstruct copy ──────────────────── *)

let test_no_remaining_tail_copy () =
  let src = find_src "mempool.ml" in
  Alcotest.(check bool)
    "load_mempool must not Cstruct.of_string the unread tail per tx"
    false
    (has_needle src "Cstruct.of_string ~off:r.r_pos");
  Alcotest.(check bool)
    "load_mempool must not pass ~len:remaining into a fresh Cstruct"
    false
    (has_needle src "~len:remaining")

(* ── (2) Cli.run starts RPC before mempool.dat reload ──────────────── *)

let test_rpc_binds_before_mempool_load () =
  let src = find_cli () in
  (match
     (index_of src "Rpc.start_rpc_server", index_of src "Mempool.load_mempool")
   with
  | None, _ -> Alcotest.fail "Rpc.start_rpc_server missing from cli.ml"
  | _, None -> Alcotest.fail "Mempool.load_mempool missing from cli.ml"
  | Some rpc_at, Some load_at ->
    Alcotest.(check bool)
      "Cli.run must call Mempool.load_mempool after Rpc.start_rpc_server"
      true (rpc_at < load_at));
  Alcotest.(check bool)
    "background reload is load_mempool_lwt (yields so RPC can answer)"
    true
    (has_needle src "load_mempool_lwt")

(* ── (3) progress line exists ──────────────────────────────────────── *)

let test_load_logs_progress () =
  let src = find_src "mempool.ml" in
  Alcotest.(check bool)
    "load_mempool logs progress every N txs"
    true
    (has_needle src "Loading mempool.dat:");
  Alcotest.(check bool)
    "load_mempool_lwt exists and pauses the Lwt loop"
    true
    (has_needle src "let load_mempool_lwt" && has_needle src "Lwt.pause")

(* ── (4) time + allocation on a ~24 MB dump ────────────────────────── *)

let put_int64_le buf v =
  let cs = Cstruct.create 8 in
  Cstruct.LE.set_uint64 cs 0 v;
  Buffer.add_string buf (Cstruct.to_string cs)

let dummy_tx i pad =
  let prev = Cstruct.create 32 in
  Cstruct.LE.set_uint32 prev 0 (Int32.of_int i);
  let script = Cstruct.create pad in
  Types.
    {
      version = 1l;
      inputs =
        [
          {
            previous_output = { txid = prev; vout = 0l };
            script_sig = Cstruct.empty;
            sequence = 0xFFFFFFFFl;
          };
        ];
      outputs = [ { value = 1L; script_pubkey = script } ];
      witnesses = [];
      locktime = 0l;
    }

let write_v1_mempool path ~n ~pad =
  let payload = Buffer.create (n * (pad + 80)) in
  put_int64_le payload (Int64.of_int n);
  for i = 1 to n do
    let w = Serialize.writer_create () in
    Serialize.serialize_transaction w (dummy_tx i pad);
    let cs = Serialize.writer_to_cstruct w in
    Buffer.add_string payload (Cstruct.to_string cs);
    put_int64_le payload 0L;
    (* nTime *)
    put_int64_le payload 0L
    (* nFeeDelta *)
  done;
  Buffer.add_char payload '\x00';
  (* 0 mapDeltas *)
  Buffer.add_char payload '\x00';
  (* 0 unbroadcast *)
  let oc = open_out_bin path in
  Fun.protect
    ~finally:(fun () -> close_out_noerr oc)
    (fun () ->
      let ver = Cstruct.create 8 in
      Cstruct.LE.set_uint64 ver 0 1L;
      output_string oc (Cstruct.to_string ver);
      output_string oc (Buffer.contents payload))

let with_empty_mempool f =
  Test_tmp.with_chaindb (fun db ->
      let utxo = Utxo.UtxoSet.create db in
      let mp =
        Mempool.create ~network:Consensus.regtest ~require_standard:false
          ~verify_scripts:false ~utxo ~current_height:100 ()
      in
      f mp)

let test_load_beats_60s_and_allocation () =
  let path = Test_tmp.fresh ~label:"boot_mempool_dat" () in
  write_v1_mempool path ~n:n_txs ~pad:pad_bytes;
  let file_bytes = (Unix.stat path).st_size in
  Printf.printf "fixture %s: %d txs, %d bytes\n%!" path n_txs file_bytes;
  with_empty_mempool (fun mp ->
      Gc.compact ();
      let st0 = Gc.quick_stat () in
      let t0 = Unix.gettimeofday () in
      let loaded = Mempool.load_mempool mp path in
      let elapsed = Unix.gettimeofday () -. t0 in
      let st1 = Gc.quick_stat () in
      let minor = st1.Gc.minor_words -. st0.Gc.minor_words in
      let major = st1.Gc.major_words -. st0.Gc.major_words in
      (* Empty UTXO set: every tx is rejected after parse. loaded may be 0.
         The bar is parse cost, not admission. *)
      Printf.printf
        "load_mempool parsed %d-tx dump in %.3fs (accepted %d); \
         minor_words=%.0f major_words=%.0f file=%d\n%!"
        n_txs elapsed loaded minor major file_bytes;
      (* Tail copies live off-heap (Bigarray custom blocks), so
         minor_words / major_words do not drop by an order of magnitude;
         wall time does (452 s → ~1.5 s on this fixture). *)
      Alcotest.(check bool)
        "load_mempool on ~70 MB dump finishes under 60s" true
        (elapsed < bar_seconds))

(* ── (5) load_mempool_lwt yields so another promise can run ────────── *)

let test_load_lwt_yields () =
  let path = Test_tmp.fresh ~label:"boot_mempool_lwt" () in
  write_v1_mempool path ~n:512 ~pad:64;
  with_empty_mempool (fun mp ->
      let ticks = ref 0 in
      let stop = ref false in
      let rec ticker () =
        if !stop then Lwt.return_unit
        else begin
          incr ticks;
          Lwt.bind (Lwt.pause ()) (fun () -> ticker ())
        end
      in
      Lwt_main.run
        (Lwt.async ticker;
         Lwt.bind (Mempool.load_mempool_lwt mp path) (fun n ->
           stop := true;
           Printf.printf
             "load_mempool_lwt accepted %d, event-loop ticks=%d\n%!" n !ticks;
           Alcotest.(check bool)
             "Lwt event loop ticked during load_mempool_lwt" true (!ticks > 0);
           Lwt.return_unit)))

let () =
  Alcotest.run "mempool-boot-load"
    [
      ( "source",
        [
          Alcotest.test_case "no per-tx remaining-tail Cstruct copy" `Quick
            test_no_remaining_tail_copy;
          Alcotest.test_case "RPC start precedes mempool reload in Cli.run"
            `Quick test_rpc_binds_before_mempool_load;
          Alcotest.test_case "progress log + load_mempool_lwt + Lwt.pause"
            `Quick test_load_logs_progress;
        ] );
      ( "load",
        [
          Alcotest.test_case "70 MB dump under 60s" `Slow
            test_load_beats_60s_and_allocation;
          Alcotest.test_case "load_mempool_lwt yields to the event loop" `Quick
            test_load_lwt_yields;
        ] );
    ]
