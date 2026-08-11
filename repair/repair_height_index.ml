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

   The node MUST be stopped (exclusive RocksDB lock) before running this. *)

module S = Camlcoin.Storage.ChainDB
module T = Camlcoin.Types

(* DISPLAY order (reversed), matching Core's getblockhash output, so the
   --dump-diffs file cross-checks directly against Core.  The internal diff
   detection below compares raw bytes via Cstruct.equal and is unaffected. *)
let hex (h : T.hash256) : string = T.hash256_to_hex_display h

let () =
  let datadir = ref "" and apply = ref false and dump_diffs = ref "" in
  Arg.parse
    [ ("--datadir", Arg.Set_string datadir,
       "camlcoin datadir (the dir that contains chainstate/)");
      ("--apply", Arg.Set apply,
       "rewrite differing rows + sync (default: read-only dry-run)");
      ("--dump-diffs", Arg.Set_string dump_diffs,
       "write 'height real_hash' per differing row to this file") ]
    (fun _ -> ())
    "repair_height_index --datadir <dir> [--apply] [--dump-diffs <file>]";
  if !datadir = "" then (prerr_endline "ERROR: --datadir required"; exit 2);
  let db_path = Filename.concat !datadir "chainstate" in
  Printf.printf "opening chainstate at %s\n%!" db_path;
  let db = S.create db_path in
  let fail code msg = Printf.eprintf "ABORT: %s\n%!" msg; S.close db; exit code in
  match S.get_header_tip db with
  | None -> fail 3 "no header_tip on disk"
  | Some (tip_hash, tip_height) ->
    Printf.printf "header tip: height=%d hash=%s\n%!" tip_height (hex tip_hash);
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
