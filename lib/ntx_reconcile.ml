(* One-time nTx provenance reconcile.

   Until the R3 no-proxy change, getblockheader answered nTx for a block
   whose body this node did not hold by asking the co-located Bitcoin Core
   over RPC (127.0.0.1:8332, Core's .cookie) and PERSISTED the answer into
   the per-block nTx index ("n:" keys in the chain_state CF).  getchaintxstats
   then summed those borrowed values into cumulative m_chain_tx_count ("c:"
   keys).  Removing the proxy stops new borrowing; this pass removes what was
   already borrowed so the node answers only from its own state.

   Core's semantics (chain.h CBlockIndex::nTx; validation.cpp
   ReceivedBlockTransactions): nTx is set only when this node received the
   block's transactions, and is 0 otherwise (header-only blocks, blocks
   below an assumeUTXO snapshot base that were never downloaded).

   Per stored "n:" entry:
     - genesis                                     -> keep (Core: nTx = 1)
     - active chain, within [floor, tip]           -> keep (connected here:
       the connect path wrote nTx from the block it validated)
     - undo data held                              -> keep (connected here)
     - block body held                             -> recount from the body
     - otherwise                                   -> reset (key deleted;
       getblockheader answers 0 and getchaintxstats sees an unknown count,
       exactly as for a block this node never processed)
   [floor] is the lowest height of the contiguous block-body range
   (Storage.ChainDB.history_floor), 1 for a node that holds history from
   genesis. The in-range rule avoids reading ~1M bodies/undo records on a
   genesis-synced node; anything outside it falls through to the direct
   evidence checks (undo, then body), so a mis-estimated floor can only keep
   a value the node has evidence for or fall back to the body/undo checks.

   Known limitation: a PRUNED node that no longer holds body or undo for a
   block below its prune floor cannot prove it connected that block (the
   prune horizon is not persisted), so such entries are reset.

   Cumulative "c:" values derived from a reset entry are unvouchable too: we
   delete every "c:" on the active chain in [lowest reset height, floor) and
   the "c:" of every reset hash. getchaintxstats re-derives what it can from
   the assumeUTXO anchors (seed_chain_tx_anchors) and omits the rest.

   Runs once per datadir: a done-marker key in the chain_state CF is written
   after a successful pass and checked first on every later boot (one point
   read). Never fatal: any exception is logged and startup continues (the
   marker is then not written, so the pass is retried next boot). *)

let marker_key = "ntx_provenance_reconciled_v1"

type stats = {
  examined : int;
  kept_in_range : int;
  kept_undo : int;
  kept_genesis : int;
  recounted_same : int;
  recounted_changed : int;
  reset : int;
  cum_deleted : int;
}

type outcome =
  | Skipped_already_done
  | Ran of stats
  | Failed of string

let summary_line (s : stats) : string =
  Printf.sprintf
    "nTx provenance reconcile: examined=%d kept(in-range=%d undo=%d \
     genesis=%d) recounted(same=%d changed=%d) reset-to-unknown=%d \
     chain_tx_count-deleted=%d"
    s.examined s.kept_in_range s.kept_undo s.kept_genesis s.recounted_same
    s.recounted_changed s.reset s.cum_deleted

(* [height_of raw] : height of the header with 32-byte internal-order hash
   [raw], if known. [tip] : validated tip height. *)
let run ~(db : Storage.ChainDB.t) ~(genesis_hash : Types.hash256)
    ~(tip : int) ~(height_of : string -> int option) : outcome =
  match Storage.ChainDB.get_meta db marker_key with
  | Some _ -> Skipped_already_done
  | None ->
    (try
       let floor =
         match Storage.ChainDB.history_floor db ~tip with
         | None -> 1
         | Some f -> f
       in
       let genesis_raw = Cstruct.to_string genesis_hash in
       let active_at h raw =
         match Storage.ChainDB.get_hash_at_height db h with
         | Some x -> Cstruct.to_string x = raw
         | None -> false
       in
       (* Collect first; never mutate the CF under the live iterator. *)
       let ntx = ref [] and cum = ref [] in
       Storage.ChainDB.iter_tx_count_keys db (fun kind raw value ->
         match kind with
         | 'n' when String.length value >= 4 ->
           let b i = Char.code value.[i] in
           ntx := (raw, b 0 lor (b 1 lsl 8) lor (b 2 lsl 16) lor (b 3 lsl 24))
                  :: !ntx
         | 'c' -> cum := raw :: !cum
         | _ -> ());
       let examined = ref 0 and kept_in_range = ref 0 and kept_undo = ref 0
       and kept_genesis = ref 0 and recounted_same = ref 0
       and recounted_changed = ref 0 and reset = ref 0 in
       let reset_hashes : (string, unit) Hashtbl.t = Hashtbl.create 64 in
       let min_reset_height = ref max_int in
       List.iter (fun (raw, stored) ->
         incr examined;
         if raw = genesis_raw then incr kept_genesis
         else begin
           let h = height_of raw in
           let in_range =
             match h with
             | Some h -> h >= floor && h <= tip && active_at h raw
             | None -> false
           in
           if in_range then incr kept_in_range
           else begin
             let hash = Cstruct.of_string raw in
             if Storage.ChainDB.has_undo_data db hash then incr kept_undo
             else
               match Storage.ChainDB.get_block_ntx_from_body db hash with
               | Some n when n = stored -> incr recounted_same
               | Some n ->
                 Storage.ChainDB.store_block_ntx db hash n;
                 incr recounted_changed
               | None ->
                 Storage.ChainDB.delete_block_ntx db hash;
                 Hashtbl.replace reset_hashes raw ();
                 incr reset;
                 (match h with
                  | Some h when active_at h raw ->
                    if h < !min_reset_height then min_reset_height := h
                  | _ -> ())
           end
         end) !ntx;
       ntx := [];
       let cum_deleted = ref 0 in
       if !reset > 0 then
         List.iter (fun raw ->
           let derived_from_reset =
             Hashtbl.mem reset_hashes raw
             || (match height_of raw with
                 | Some h ->
                   h >= !min_reset_height && h < floor && active_at h raw
                 | None -> false)
           in
           if derived_from_reset && raw <> genesis_raw then begin
             Storage.ChainDB.delete_chain_tx_count_raw db raw;
             incr cum_deleted
           end) !cum;
       let stats = {
         examined = !examined; kept_in_range = !kept_in_range;
         kept_undo = !kept_undo; kept_genesis = !kept_genesis;
         recounted_same = !recounted_same;
         recounted_changed = !recounted_changed; reset = !reset;
         cum_deleted = !cum_deleted;
       } in
       Storage.ChainDB.put_meta db marker_key (summary_line stats);
       Ran stats
     with exn -> Failed (Printexc.to_string exn))

(* Startup entry point: log exactly one summary line, never raise. *)
let run_at_startup ~db ~genesis_hash ~tip ~height_of : unit =
  let t0 = Unix.gettimeofday () in
  match (try run ~db ~genesis_hash ~tip ~height_of
         with exn -> Failed (Printexc.to_string exn)) with
  | Skipped_already_done -> ()
  | Ran s ->
    Logs.info (fun m ->
      m "%s (%.1fs, one-time; marker %s written)" (summary_line s)
        (Unix.gettimeofday () -. t0) marker_key)
  | Failed e ->
    Logs.warn (fun m ->
      m "nTx provenance reconcile FAILED (%s) — continuing startup; will \
         retry next boot" e)
