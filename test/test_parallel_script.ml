(* Parallel script verification — QUEUES.md 2026-09-19 control.

   Bitcoin Core: -par (init.cpp:513), CCheckQueue (src/checkqueue.h),
   CScriptCheck batched per-input in ConnectBlock (validation.cpp). Extra
   worker Domains drain a bounded job array; the connecting thread joins as
   the master; the block is accepted only if every check returns true; the
   reported failure is the lowest-index one so worker count cannot change
   the decision.

   REQUIRED:
     (1) decision identity — accept/reject AND reject reason identical at
         1 worker and at N
     (2) failure propagation — one failing check rejects the whole batch
         with the same reason as the serial path
     (3) measured scaling — blk/h at 1, 2, 4, 8 workers, printed
     (4) bounded RSS — more workers must not mean unbounded buffers

   CONTROL: dune exec --no-buffer test/test_parallel_script.exe
*)

open Camlcoin

let op byte =
  let c = Cstruct.create 1 in
  Cstruct.set_uint8 c 0 byte;
  c

let op_true () = op 0x51
let op_false () = op 0x00
let op_return () = op 0x6a
let op_cat () = op 0x7e
let op_if_unbalanced () = op 0x63

let hash256_n n =
  let t = Cstruct.create 32 in
  Cstruct.set_uint8 t 0 (n land 0xff);
  Cstruct.set_uint8 t 1 ((n lsr 8) land 0xff);
  Cstruct.set_uint8 t 2 ((n lsr 16) land 0xff);
  t

let hash_heavy_script rounds =
  (* <32-byte push> OP_HASH256{rounds} OP_DROP OP_TRUE. Opcode count is
     rounds+3, so rounds<=180 stays under MAX_OPS_PER_SCRIPT (201). *)
  let n = 33 + rounds + 2 in
  let c = Cstruct.create n in
  Cstruct.set_uint8 c 0 0x20;
  for i = 1 to 32 do Cstruct.set_uint8 c i 0x11 done;
  for i = 0 to rounds - 1 do
    Cstruct.set_uint8 c (33 + i) 0xaa
  done;
  Cstruct.set_uint8 c (33 + rounds) 0x75;
  Cstruct.set_uint8 c (33 + rounds + 1) 0x51;
  c

(* Sig-cache keys are (wtxid, input_index, flags) — not the scriptPubKey.
   Two txs with the same inputs/outputs share a wtxid, so a prior OP_TRUE
   success would mask a later OP_RETURN at the same index. Unique locktime
   (covered by wtxid) keeps cases isolated, matching test_w143. *)
let uid = ref 0

let make_tx n_inputs =
  incr uid;
  let inputs =
    List.init n_inputs (fun i ->
      { Types.previous_output =
          { Types.txid = hash256_n (i + 1); vout = 0l };
        script_sig = Cstruct.create 0;
        sequence = 0xffffffffl })
  in
  { Types.version = 2l;
    inputs;
    outputs = [ { Types.value = 900L; script_pubkey = op_true () } ];
    witnesses = [];
    locktime = Int32.of_int !uid }

let make_utxo i spk : Validation.utxo =
  { Validation.txid = hash256_n (1000 + i);
    vout = 0l;
    value = Int64.of_int (100_000 + i);
    script_pubkey = spk;
    height = 1;
    is_coinbase = false }

let jobs_of_spks (spks : Cstruct.t list) : Validation.script_check_job array =
  let n = List.length spks in
  let tx = make_tx n in
  let wtxid = Crypto.compute_wtxid tx in
  let utxos = List.mapi make_utxo spks in
  let prevouts =
    List.map (fun (u : Validation.utxo) -> (u.value, u.script_pubkey)) utxos
  in
  let rec zip i inps utxos acc =
    match (inps, utxos) with
    | [], [] -> List.rev acc
    | inp :: inps, utxo :: utxos ->
      zip (i + 1) inps utxos
        ({ Validation.tx; tx_idx = 0; input_idx = i; inp; utxo; prevouts;
           flags = 0; wtxid; txdata = None; err = None } :: acc)
    | _ -> assert false
  in
  Array.of_list (zip 0 tx.inputs utxos [])

let run_n n jobs =
  let extra = max 0 (n - 1) in
  let q = Validation.create_script_check_queue extra in
  let r = Validation.run_script_check_queue q jobs in
  Validation.shutdown_script_check_queue q;
  r

let pp_res (r : Validation.script_check_result) =
  if r.ok then "OK"
  else
    Printf.sprintf "FAIL idx=%d tx=%d reason=%S"
      r.first_fail_index r.first_fail_tx_idx r.first_fail_reason

let rss_kb () =
  try
    let ic = open_in "/proc/self/status" in
    Fun.protect ~finally:(fun () -> close_in_noerr ic) (fun () ->
      let rec loop () =
        let line = input_line ic in
        if String.length line >= 6 && String.sub line 0 6 = "VmRSS:" then
          let rest = String.trim (String.sub line 6 (String.length line - 6)) in
          Scanf.sscanf rest "%d" (fun n -> n)
        else loop ()
      in
      try loop () with End_of_file -> 0)
  with _ -> 0

(* ---------------------------------------------------------------------------
   -par mapping (Core chainstatemanager_args.cpp:53-60)
   --------------------------------------------------------------------------- *)

let test_par_1_is_serial () =
  Alcotest.(check int) "--par=1 is 0 extra workers" 0
    (Validation.resolve_script_check_workers 1)

let test_par_2_is_one_extra () =
  Alcotest.(check int) "--par=2 is 1 extra worker" 1
    (Validation.resolve_script_check_workers 2)

let test_par_auto_is_every_core () =
  let cores = max 1 (Domain.recommended_domain_count ()) in
  let extra = Validation.resolve_script_check_workers 0 in
  Alcotest.(check int) "--par=0 extra = CPU-1" (cores - 1) extra;
  Alcotest.(check bool) "default par is 0 (auto)" true
    (Validation.default_scriptcheck_threads = 0);
  Alcotest.(check int) "batch size is Core's 128" 128
    Validation.script_check_batch_size

let test_par_leave_one_free () =
  let auto = Validation.resolve_script_check_workers 0 in
  let leave = Validation.resolve_script_check_workers (-1) in
  Alcotest.(check bool) "--par=-1 <= auto" true (leave <= auto);
  Alcotest.(check int) "--par=-1 is auto-1 (floored at 0)"
    (max 0 (auto - 1)) leave

let test_init_0_spawns_none () =
  let q = Validation.create_script_check_queue 0 in
  Fun.protect ~finally:(fun () -> Validation.shutdown_script_check_queue q)
    (fun () ->
      Alcotest.(check int) "extra=0" 0 (Validation.extra_workers q);
      Alcotest.(check bool) "HasThreads false" false (Validation.has_threads q))

let test_init_n_spawns_n () =
  let q = Validation.create_script_check_queue 4 in
  Fun.protect ~finally:(fun () -> Validation.shutdown_script_check_queue q)
    (fun () ->
      Alcotest.(check int) "extra=4" 4 (Validation.extra_workers q);
      Alcotest.(check bool) "HasThreads true" true (Validation.has_threads q))

(* ---------------------------------------------------------------------------
   (1) Decision identity — 1 worker vs N
   --------------------------------------------------------------------------- *)

let test_identity_accept () =
  Sig_cache.init_global ~max_entries:100_000 ();
  Sig_cache.clear_global ();
  let jobs = jobs_of_spks (List.init 64 (fun _ -> op_true ())) in
  let one = run_n 1 jobs in
  let eight = run_n 8 jobs in
  Alcotest.(check bool) "serial accepts OP_TRUE" true one.ok;
  Alcotest.(check string) "1 vs 8 accept identity" (pp_res one) (pp_res eight)

let test_identity_mixed_corpus () =
  Sig_cache.init_global ~max_entries:100_000 ();
  Sig_cache.clear_global ();
  let corpus =
    [ op_true (); op_true (); op_false (); op_true ();
      op_return (); op_true (); op_cat (); op_true ();
      op_if_unbalanced (); op_true (); op_false (); op_return ();
      op_true (); op_cat (); op_true (); op_if_unbalanced ();
      op_true (); op_false (); op_true (); op_return ();
      op_true (); op_cat (); op_true (); op_true () ]
  in
  let jobs_s = jobs_of_spks corpus in
  let jobs_p = jobs_of_spks corpus in
  let serial = run_n 1 jobs_s in
  let parallel = run_n 8 jobs_p in
  Alcotest.(check bool) "mixed corpus rejects" false serial.ok;
  Alcotest.(check string) "1 vs 8 mixed identity" (pp_res serial) (pp_res parallel)

(* ---------------------------------------------------------------------------
   (2) Failure propagation
   --------------------------------------------------------------------------- *)

let test_failure_propagation_one_bad () =
  Sig_cache.init_global ~max_entries:100_000 ();
  Sig_cache.clear_global ();
  let fail_at = 17 in
  let spks =
    List.init 64 (fun i -> if i = fail_at then op_cat () else op_true ())
  in
  let serial = run_n 1 (jobs_of_spks spks) in
  let parallel = run_n 8 (jobs_of_spks spks) in
  Alcotest.(check bool) "serial rejects" false serial.ok;
  Alcotest.(check bool) "parallel rejects" false parallel.ok;
  Alcotest.(check int) "serial first-fail index" fail_at serial.first_fail_index;
  Alcotest.(check int) "parallel first-fail index" fail_at parallel.first_fail_index;
  Alcotest.(check string) "reason identity" serial.first_fail_reason
    parallel.first_fail_reason;
  Alcotest.(check bool) "reason is non-empty" true
    (String.length serial.first_fail_reason > 0)

let test_failure_propagation_all_pass () =
  Sig_cache.init_global ~max_entries:100_000 ();
  Sig_cache.clear_global ();
  let jobs = jobs_of_spks (List.init 32 (fun _ -> op_true ())) in
  let serial = run_n 1 jobs in
  let parallel = run_n 8 jobs in
  Alcotest.(check bool) "serial OK" true serial.ok;
  Alcotest.(check bool) "parallel OK" true parallel.ok;
  Alcotest.(check int) "first_fail_index identity" serial.first_fail_index
    parallel.first_fail_index

let test_lowest_index_failure () =
  (* Three distinct failures. The reported reason MUST be the lowest index
     (job 5), never the race-winner. *)
  Sig_cache.init_global ~max_entries:100_000 ();
  Sig_cache.clear_global ();
  let spk i =
    if i = 5 then op_cat ()
    else if i = 20 then op_if_unbalanced ()
    else if i = 40 then op_false ()
    else op_true ()
  in
  let spks = List.init 48 spk in
  let serial = run_n 1 (jobs_of_spks spks) in
  let parallel = run_n 8 (jobs_of_spks spks) in
  Alcotest.(check int) "serial lowest index" 5 serial.first_fail_index;
  Alcotest.(check int) "parallel lowest index" 5 parallel.first_fail_index;
  Alcotest.(check string) "reason identity" serial.first_fail_reason
    parallel.first_fail_reason;
  Alcotest.(check bool) "lowest reason is the CAT (disabled) fail, not a later one"
    true (String.length serial.first_fail_reason > 0
          && serial.first_fail_reason <> "Script returned false")

let test_one_job_fail_not_skipped () =
  Sig_cache.init_global ~max_entries:100_000 ();
  Sig_cache.clear_global ();
  let r = run_n 5 (jobs_of_spks [ op_cat () ]) in
  Alcotest.(check bool) "1-job OP_CAT rejects" false r.ok;
  Alcotest.(check int) "FirstFailIndex=0" 0 r.first_fail_index;
  Alcotest.(check bool) "reason is non-empty" true
    (String.length r.first_fail_reason > 0)

(* ---------------------------------------------------------------------------
   (3) Measured scaling — 1, 2, 4, 8 total workers
   --------------------------------------------------------------------------- *)

let test_measured_scaling () =
  Sig_cache.init_global ~max_entries:100_000 ();
  let inputs = 2048 in
  let rounds = ref 64 in
  let rec warmup () =
    Sig_cache.clear_global ();
    let spks = List.init inputs (fun _ -> hash_heavy_script !rounds) in
    let jobs = jobs_of_spks spks in
    let t0 = Unix.gettimeofday () in
    let r = run_n 1 jobs in
    let ms = (Unix.gettimeofday () -. t0) *. 1000.0 in
    if not r.ok then
      Alcotest.fail ("hash-heavy OP_TRUE rejected: " ^ r.first_fail_reason);
    Printf.eprintf
      "scaling warmup: 1 worker %.0f ms at %d HASH256 rounds, %d inputs\n%!"
      ms !rounds inputs;
    if ms >= 150.0 || !rounds >= 180 then (ms, jobs, !rounds)
    else begin
      rounds := min 180 (!rounds * 2);
      warmup ()
    end
  in
  let (_warm_ms, _warm_jobs, rounds) = warmup () in
  let widths = [ 1; 2; 4; 8 ] in
  let times = ref [] in
  Printf.eprintf
    "measured scaling (%d inputs, %d HASH256 rounds/input):\n%!" inputs rounds;
  List.iter (fun n ->
    Sig_cache.clear_global ();
    let jobs = jobs_of_spks (List.init inputs (fun _ -> hash_heavy_script rounds)) in
    let q = Validation.create_script_check_queue (max 0 (n - 1)) in
    let t0 = Unix.gettimeofday () in
    let r = Validation.run_script_check_queue q jobs in
    let elapsed = Unix.gettimeofday () -. t0 in
    Validation.shutdown_script_check_queue q;
    if not r.ok then
      Alcotest.fail (Printf.sprintf "workers=%d rejected: %s" n r.first_fail_reason);
    let wall = if elapsed < 1e-9 then 1e-9 else elapsed in
    let blk_h = 3600.0 /. wall in
    Printf.eprintf
      "scaling workers=%d wall_s=%.4f blk_h=%.1f (n_jobs=%d HASH256_rounds=%d)\n%!"
      n wall blk_h inputs rounds;
    times := (n, wall, blk_h) :: !times
  ) widths;
  let times = List.rev !times in
  let wall1 = List.assoc 1 (List.map (fun (n, w, _) -> (n, w)) times) in
  let wall8 = List.assoc 8 (List.map (fun (n, w, _) -> (n, w)) times) in
  let speedup = wall1 /. wall8 in
  Printf.eprintf "scaling speedup 1→8 workers: %.2fx\n%!" speedup;
  Alcotest.(check bool) "8 workers beat 1 worker" true (wall8 < wall1);
  Alcotest.(check bool) "speedup 1→8 >= 1.3x (parallelism is load-bearing)"
    true (speedup >= 1.3)

(* ---------------------------------------------------------------------------
   (4) Bounded RSS — more workers must not mean unbounded buffers
   --------------------------------------------------------------------------- *)

let test_bounded_rss () =
  Sig_cache.init_global ~max_entries:100_000 ();
  Sig_cache.clear_global ();
  let jobs = jobs_of_spks (List.init 256 (fun _ -> op_true ())) in
  let q1 = Validation.create_script_check_queue 1 in
  let q8 = Validation.create_script_check_queue 8 in
  Fun.protect
    ~finally:(fun () ->
      Validation.shutdown_script_check_queue q1;
      Validation.shutdown_script_check_queue q8)
    (fun () ->
      let rss_before = rss_kb () in
      let r1 = Validation.run_script_check_queue q1 jobs in
      let r8 = Validation.run_script_check_queue q8 jobs in
      let rss_after = rss_kb () in
      Alcotest.(check bool) "q1 OK" true r1.ok;
      Alcotest.(check bool) "q8 OK" true r8.ok;
      Alcotest.(check bool) "q1 borrowed the job array" true
        (Validation.job_array_is q1 jobs);
      Alcotest.(check bool) "q8 borrowed the job array" true
        (Validation.job_array_is q8 jobs);
      let cap1 = Validation.script_check_batch_size * (Validation.extra_workers q1 + 1) in
      let cap8 = Validation.script_check_batch_size * (Validation.extra_workers q8 + 1) in
      Alcotest.(check bool)
        (Printf.sprintf "q1 maxInFlight=%d <= bound %d"
           (Validation.max_in_flight q1) cap1)
        true (Validation.max_in_flight q1 <= cap1);
      Alcotest.(check bool)
        (Printf.sprintf "q8 maxInFlight=%d <= bound %d"
           (Validation.max_in_flight q8) cap8)
        true (Validation.max_in_flight q8 <= cap8);
      Alcotest.(check bool) "8-worker cap exceeds 1-worker cap" true (cap8 > cap1);
      let extra_kb = rss_after - rss_before in
      Printf.eprintf
        "bounded RSS: VmRSS before=%d kB after=%d kB extra=%d kB; \
         maxInFlight 1w=%d 8w=%d (caps %d/%d)\n%!"
        rss_before rss_after extra_kb
        (Validation.max_in_flight q1) (Validation.max_in_flight q8) cap1 cap8;
      (* Domain arenas are O(workers), not O(workers × jobs). 512 MiB is
         well above 8 × 32 MiB minor heaps and well below an unbounded
         copy of the job list per worker. *)
      Alcotest.(check bool) "extra RSS is O(workers) not unbounded"
        true (extra_kb < 512 * 1024))

let test_persistent_pool_two_batches () =
  Sig_cache.init_global ~max_entries:100_000 ();
  Sig_cache.clear_global ();
  let q = Validation.create_script_check_queue 4 in
  Fun.protect ~finally:(fun () -> Validation.shutdown_script_check_queue q)
    (fun () ->
      let extra = Validation.extra_workers q in
      let pass = Validation.run_script_check_queue q
          (jobs_of_spks (List.init 16 (fun _ -> op_true ()))) in
      Alcotest.(check bool) "first batch OK" true pass.ok;
      let fail_jobs =
        jobs_of_spks
          (List.init 16 (fun i -> if i = 1 then op_false () else op_true ()))
      in
      let failed = Validation.run_script_check_queue q fail_jobs in
      Alcotest.(check bool) "second batch rejects" false failed.ok;
      Alcotest.(check int) "FirstFailIndex=1" 1 failed.first_fail_index;
      Alcotest.(check int) "pool did not respawn" extra
        (Validation.extra_workers q))

let () =
  Sig_cache.init_global ~max_entries:100_000 ();
  let open Alcotest in
  run "parallel script verification" [
    "par", [
      test_case "par=1 is serial" `Quick test_par_1_is_serial;
      test_case "par=2 is one extra" `Quick test_par_2_is_one_extra;
      test_case "par=0 is every core" `Quick test_par_auto_is_every_core;
      test_case "par=-1 leaves one core free" `Quick test_par_leave_one_free;
      test_case "init 0 spawns none" `Quick test_init_0_spawns_none;
      test_case "init N spawns N" `Quick test_init_n_spawns_n;
    ];
    "identity", [
      test_case "1 vs 8 accept identity" `Quick test_identity_accept;
      test_case "1 vs 8 mixed corpus identity" `Quick test_identity_mixed_corpus;
    ];
    "failure", [
      test_case "one bad input same reason at 1 and N" `Quick
        test_failure_propagation_one_bad;
      test_case "all-pass identity" `Quick test_failure_propagation_all_pass;
      test_case "lowest-index fail is deterministic" `Quick
        test_lowest_index_failure;
      test_case "1-job fail is not skipped" `Quick test_one_job_fail_not_skipped;
    ];
    "scaling", [
      test_case "measured scaling 1/2/4/8" `Quick test_measured_scaling;
    ];
    "rss", [
      test_case "bounded RSS / in-flight" `Quick test_bounded_rss;
      test_case "persistent pool two batches" `Quick
        test_persistent_pool_two_batches;
    ];
  ]
