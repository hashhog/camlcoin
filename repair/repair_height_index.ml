(* Offline height->hash index repair for a poisoned camlcoin chainstate.
   Design + rationale: receipts/camlcoin-repair-design-2026-08-11.md.

   The CF chainstate's height->hash index carries scattered difficulty-1 poison
   rows (interleaved with real rows).  The block_header CF, the UTXO set, the
   rocksdb_utxo mirror, and the persisted tips are all CLEAN.  restore_chain_state
   recomputes cumulative work by summing work_from_bits along the index every
   boot, so poison rows break the work chain and park the node below
   minimum_chain_work.

   This tool walks the REAL active chain from the persisted header tip DOWN via
   prev_block links (block_header CF), builds real_map[h], and rewrites only the
   height->hash rows that disagree.  No UTXO change, no reorg, no dual-store
   touch: correct work re-derives itself on the next boot and the node un-parks.

   Read-only by default.  --apply performs set_height_hash + sync.  --dump-diffs
   writes "height real_hash_hex" per differing row for an INDEPENDENT Core
   cross-check that must pass before --apply is authorized.

   --to-chain-tip anchors the walk on the VALIDATED chain tip instead of the
   header tip, so no row is written above the block tip (the index projects the
   ACTIVE VALIDATED chain only, fecf534).  This is the mode for the 2026-10-03
   snapshot-swap incident: a datadir bootstrapped from a Core dumptxoutset has
   real header bytes for (0, base) in the block_header CF (synced from genesis
   on the first run) but NO height->hash rows for them, so every restart loads
   only genesis + [base, tip] into the in-memory header table and the first
   retarget after the base cannot resolve its period-first ancestor.

   The node MUST be stopped (exclusive RocksDB lock) before running this. *)

module S = Camlcoin.Storage.ChainDB
module T = Camlcoin.Types

(* DISPLAY order (reversed), matching Core's getblockhash output, so the
   --dump-diffs file cross-checks directly against Core.  The internal diff
   detection below compares raw bytes via Cstruct.equal and is unaffected. *)
let hex (h : T.hash256) : string = T.hash256_to_hex_display h

let () =
  let datadir = ref "" and apply = ref false and dump_diffs = ref ""
  and to_chain_tip = ref false in
  Arg.parse
    [ ("--datadir", Arg.Set_string datadir,
       "camlcoin datadir (the dir that contains chainstate/)");
      ("--apply", Arg.Set apply,
       "rewrite differing rows + sync (default: read-only dry-run)");
      ("--dump-diffs", Arg.Set_string dump_diffs,
       "write 'height real_hash' per differing row to this file");
      ("--to-chain-tip", Arg.Set to_chain_tip,
       "anchor the walk on the validated chain tip (no rows above it)") ]
    (fun _ -> ())
    "repair_height_index --datadir <dir> [--to-chain-tip] [--apply] [--dump-diffs <file>]";
  if !datadir = "" then (prerr_endline "ERROR: --datadir required"; exit 2);
  let db_path = Filename.concat !datadir "chainstate" in
  Printf.printf "opening chainstate at %s\n%!" db_path;
  let db = S.create db_path in
  let fail code msg = Printf.eprintf "ABORT: %s\n%!" msg; S.close db; exit code in
  (match S.get_header_tip db with
   | Some (h, n) -> Printf.printf "header tip (stored): height=%d hash=%s\n%!" n (hex h)
   | None -> Printf.printf "header tip (stored): none\n%!");
  (match S.get_chain_tip db with
   | Some (h, n) -> Printf.printf "chain tip (validated): height=%d hash=%s\n%!" n (hex h)
   | None -> Printf.printf "chain tip (validated): none\n%!");
  (match S.get_assumeutxo_chainwork db with
   | Some w -> Printf.printf "assumeutxo chainwork key: SET (%s)\n%!" (hex w)
   | None -> Printf.printf "assumeutxo chainwork key: not set\n%!");
  let anchor = if !to_chain_tip then S.get_chain_tip db else S.get_header_tip db in
  match anchor with
  | None -> fail 3 (if !to_chain_tip then "no chain_tip on disk" else "no header_tip on disk")
  | Some (tip_hash, tip_height) ->
    Printf.printf "walk anchor (%s): height=%d hash=%s\n%!"
      (if !to_chain_tip then "chain tip" else "header tip") tip_height (hex tip_hash);
    (* Walk prev_block down (iterative — a recursive tip-deep walk overflows). *)
    let real_map = Hashtbl.create (tip_height + 1) in
    let cur = ref tip_hash and h = ref tip_height and broke = ref false in
    while !h >= 0 && not !broke do
      match S.get_block_header db !cur with
      | None ->
        Printf.eprintf "WALK BROKE at height %d (missing real header %s)\n%!"
          !h (hex !cur);
        broke := true
      | Some hdr ->
        Hashtbl.replace real_map !h !cur;
        if !h > 0 then cur := hdr.T.prev_block;
        decr h
    done;
    if not (Hashtbl.mem real_map 0) then
      fail 4 "walk did not reach genesis (a real header is missing) — use Option B (-reindex)";
    Printf.printf "walk OK: reached genesis, mapped %d heights\n%!"
      (Hashtbl.length real_map);
    (* Diff the on-disk index against real_map. *)
    let diffs = ref [] in
    for hh = 0 to tip_height do
      match Hashtbl.find_opt real_map hh with
      | None -> ()
      | Some r ->
        let needs =
          match S.get_hash_at_height db hh with
          | Some c -> not (Cstruct.equal c r)
          | None -> true
        in
        if needs then diffs := (hh, r) :: !diffs
    done;
    let diffs = List.rev !diffs in
    Printf.printf "DIFF rows (index != real chain): %d\n%!" (List.length diffs);
    let missing = List.length (List.filter (fun (hh, _) -> S.get_hash_at_height db hh = None) diffs) in
    Printf.printf "  of which MISSING rows: %d, WRONG-HASH rows: %d\n%!"
      missing (List.length diffs - missing);
    (match diffs with
     | [] -> ()
     | (lo, _) :: _ ->
       let (hi, hhash) = List.nth diffs (List.length diffs - 1) in
       Printf.printf "  lowest diff height=%d, highest diff height=%d (%s)\n%!" lo hi (hex hhash));
    List.iter (fun hh ->
        match Hashtbl.find_opt real_map hh with
        | Some r -> Printf.printf "  sample real h=%d %s\n" hh (hex r)
        | None -> ())
      [1; 100000; 500000; 967679; 967680; 969000; tip_height - 513; tip_height - 1];
    List.iteri
      (fun i (hh, r) -> if i < 25 then Printf.printf "  h=%d -> real=%s\n" hh (hex r))
      diffs;
    (if !dump_diffs <> "" then begin
       let oc = open_out !dump_diffs in
       List.iter (fun (hh, r) -> Printf.fprintf oc "%d %s\n" hh (hex r)) diffs;
       close_out oc;
       Printf.printf "dumped %d diffs to %s — cross-check vs Core before --apply\n%!"
         (List.length diffs) !dump_diffs
     end);
    if !apply then begin
      List.iter (fun (hh, r) -> S.set_height_hash db hh r) diffs;
      S.sync db;
      Printf.printf "APPLIED %d height->hash rewrites + sync\n%!" (List.length diffs)
    end else
      Printf.printf "DRY-RUN — no writes performed.\n%!";
    S.close db
