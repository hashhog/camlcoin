(* connect_prof.ml — opt-in per-phase profile of the IBD block-connect path.

   Enabled only when CAMLCOIN_CONNECT_PROFILE=<N> (N > 0): every N connected
   blocks one "[prof]" INFO line reports, averaged per block over the window,
   the wall time of each connect phase, process CPU (utime+stime, all
   domains), script-check parallelism actually achieved (summed per-batch
   busy time over the drain's wall time), GC counts, heap and RSS.  Off (the default) every entry point is a single
   branch on [enabled]; nothing here changes what is validated or how.

   Phases are only written by one thread at a time (the IBD connect path is
   one block at a time: the Lwt main thread parks while the validation worker
   runs), so plain float refs suffice; the script-check busy counter is hit
   from every ScriptCheckQueue domain and is an Atomic. *)

let every =
  match Sys.getenv_opt "CAMLCOIN_CONNECT_PROFILE" with
  | Some s -> (match int_of_string_opt (String.trim s) with
      | Some n when n > 0 -> n | _ -> 0)
  | None -> 0

let enabled = every > 0

(* Phase ids *)
let p_pre = 0          (* sync: expected bits / MTP / readers before submit *)
let p_validate = 1     (* sync: whole accept_block round trip on the worker *)
let p_check_block = 2  (* validation: check_block (merkle, weight, witness...) *)
let p_txid = 3         (* validation: txid computation *)
let p_prefetch = 4     (* validation: batched UTXO prefetch *)
let p_txloop = 5       (* validation: serial tx loop (inputs, sigops, BIP68, jobs) *)
let p_scripts = 6      (* validation: ScriptCheckQueue drain (wall) *)
let p_store = 7        (* sync: store_block *)
let p_undo = 8         (* sync: undo build + store *)
let p_utxo = 9         (* sync: UTXO cache apply *)
let p_flush = 10       (* sync: periodic UTXO flush (+ its Gc.major) *)
let p_misc = 11        (* sync: index/tx-count/log/prune/zmq/orphans *)
let p_compact = 12     (* run_ibd: ibd-cadence compaction *)
let n_phases = 13
let names = [| "pre"; "validate"; "check_block"; "txid"; "prefetch"; "txloop";
               "scripts"; "store"; "undo"; "utxo"; "flush"; "misc"; "compact" |]

let acc = Array.make n_phases 0.0

let add id dt = if enabled then acc.(id) <- acc.(id) +. dt

let now = Unix.gettimeofday

let span id f =
  if not enabled then f ()
  else begin
    let t0 = now () in
    match f () with
    | v -> acc.(id) <- acc.(id) +. (now () -. t0); v
    | exception e -> acc.(id) <- acc.(id) +. (now () -. t0); raise e
  end

(* Script-check busy time (ns) summed over every domain that claimed work. *)
let script_busy_ns = Atomic.make 0
let script_jobs = ref 0

let add_script_busy_ns n = ignore (Atomic.fetch_and_add script_busy_ns n)

let mono_ns () = Int64.to_int (Int64.of_float (Unix.gettimeofday () *. 1e9))

(* Set while a ScriptCheckQueue generation runs script checks (not the
   block-input prefetch, which shares the queue's domains). *)
let counting_scripts = Atomic.make false

(* ---- window bookkeeping ---------------------------------------------------- *)

let win_blocks = ref 0
let win_txs = ref 0
let win_start = ref (now ())
let cpu () = let t = Unix.times () in t.Unix.tms_utime +. t.Unix.tms_stime
let win_cpu = ref (if enabled then cpu () else 0.0)
let win_gc = ref (if enabled then Gc.quick_stat () else Gc.quick_stat ())

let rss_mb () =
  try
    let ic = open_in "/proc/self/statm" in
    let line = input_line ic in
    close_in ic;
    (match String.split_on_char ' ' line with
     | _ :: res :: _ -> float_of_string res *. 4096.0 /. 1_048_576.0
     | _ -> 0.0)
  with _ -> 0.0

let block_done ?(extra = fun () -> "") ~height ~n_tx () =
  if enabled then begin
    incr win_blocks;
    win_txs := !win_txs + n_tx;
    if !win_blocks >= every then begin
      let t = now () in
      let c = cpu () in
      let st = Gc.quick_stat () in
      let nb = float_of_int !win_blocks in
      let wall = t -. !win_start in
      let per x = x /. nb in
      let sum_sync =
        acc.(p_pre) +. acc.(p_validate) +. acc.(p_store) +. acc.(p_undo)
        +. acc.(p_utxo) +. acc.(p_flush) +. acc.(p_misc) +. acc.(p_compact) in
      let phases =
        String.concat " "
          (List.map (fun i -> Printf.sprintf "%s=%.3f" names.(i) (per acc.(i)))
             [p_pre; p_validate; p_check_block; p_txid; p_prefetch; p_txloop;
              p_scripts; p_store; p_undo; p_utxo; p_flush; p_misc; p_compact])
      in
      let busy = float_of_int (Atomic.get script_busy_ns) /. 1e9 in
      let par = if acc.(p_scripts) > 0.0 then busy /. acc.(p_scripts) else 0.0 in
      let mw = st.Gc.minor_words -. !win_gc.Gc.minor_words in
      let pw = st.Gc.promoted_words -. !win_gc.Gc.promoted_words in
      Logs.info (fun m ->
        m "[prof] h=%d blocks=%d tx/blk=%.0f inputs/blk=%.0f wall/blk=%.3f \
           cpu/blk=%.3f other/blk=%.3f | %s | script_busy/blk=%.3f par=%.1f | \
           minors=%d majors=%d compactions=%d | alloc/blk minor=%.0fMB \
           promoted=%.0fMB | heap=%.0fMB top=%.0fMB rss=%.0fMB | %s"
          height !win_blocks (per (float_of_int !win_txs))
          (per (float_of_int !script_jobs)) (per wall) (per (c -. !win_cpu))
          (per (wall -. sum_sync)) phases (per busy) par
          (st.Gc.minor_collections - !win_gc.Gc.minor_collections)
          (st.Gc.major_collections - !win_gc.Gc.major_collections)
          (st.Gc.compactions - !win_gc.Gc.compactions)
          (per (mw *. 8.0 /. 1_048_576.0)) (per (pw *. 8.0 /. 1_048_576.0))
          (float_of_int st.Gc.heap_words *. 8.0 /. 1_048_576.0)
          (float_of_int st.Gc.top_heap_words *. 8.0 /. 1_048_576.0)
          (rss_mb ()) (extra ()));
      Array.fill acc 0 n_phases 0.0;
      Atomic.set script_busy_ns 0;
      script_jobs := 0;
      win_blocks := 0; win_txs := 0;
      win_start := t; win_cpu := c; win_gc := st
    end
  end
