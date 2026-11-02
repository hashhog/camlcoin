(* BIP 152 receive side: which cmpctblock may create a partially downloaded
   block, and the bounded table that holds those blocks until blocktxn.

   Bitcoin Core (net_processing.cpp, CMPCTBLOCK branch and
   ProcessCompactBlockTxns):
     - unknown hashPrevBlock: send getheaders, keep nothing;
     - prev work + header proof < GetAntiDoSWorkThreshold: ignore;
     - the header goes through ProcessNewBlockHeaders (PoW, nBits, MTP,
       checkpoints) before any PartiallyDownloadedBlock exists, and an
       invalid header punishes the sender;
     - nothing is kept for a block we already have, for one with no more
       work than the active tip, or for one more than 2 above the tip;
     - a partial block is an in-flight request from ONE peer, at most
       MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK (3) peers per block, and the
       getblocktxn round trip goes to the first peer in flight, or to a
       high-bandwidth peer while a slot is left;
     - blocktxn is matched against the partial block of the peer that sent
       it, never another peer's.

   camlcoin used to run [reconstruct_from_mempool] on every cmpctblock and
   keep each incomplete one in one global table keyed by block hash, with no
   header check, no cap, no expiry and no removal on disconnect (security
   audit 2026-10-31 C3: 393 MB of random-header cmpctblocks took RSS from
   0.54 to 7.0 GB, and 5.5 GB stayed after the attacker left).  Here every
   entry is keyed by (peer id, block hash), each peer holds at most
   [max_pending_per_peer], each block at most [max_peers_per_block], entries
   expire after [pending_timeout] seconds, and [remove_peer] drops a peer's
   entries when it disconnects. *)

(* Partial blocks one peer may hold.  Core bounds a peer by its in-flight
   blocks; a compact block is only accepted for tip+1 / tip+2, so a few are
   enough for honest relay. *)
let max_pending_per_peer = 3

(* Core MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK. *)
let max_peers_per_block = 3

(* Seconds before an unanswered getblocktxn is dropped (Core's block
   download timeout base is one block interval). *)
let pending_timeout = 600.0

type entry = {
  cb : P2p.compact_block;
  partial : Types.transaction option array;
  missing : int list;
  added_at : float;
}

type t = {
  pending : (int * string, entry) Hashtbl.t;  (* (peer id, block hash) *)
  timeout : float;
}

let create ?(timeout = pending_timeout) () =
  { pending = Hashtbl.create 16; timeout }

let size t = Hashtbl.length t.pending

let count_peer t peer_id =
  Hashtbl.fold (fun (p, _) _ n -> if p = peer_id then n + 1 else n)
    t.pending 0

let peers_for_block t (hash : Types.hash256) =
  let k = Cstruct.to_string hash in
  Hashtbl.fold (fun (_, h) _ n -> if String.equal h k then n + 1 else n)
    t.pending 0

let mem t ~peer_id ~(hash : Types.hash256) =
  Hashtbl.mem t.pending (peer_id, Cstruct.to_string hash)

let remove_where t pred =
  let doomed =
    Hashtbl.fold (fun k e acc -> if pred k e then k :: acc else acc)
      t.pending []
  in
  List.iter (Hashtbl.remove t.pending) doomed;
  List.length doomed

(* Drop entries older than the timeout; returns how many. *)
let expire t ~now =
  remove_where t (fun _ e -> now -. e.added_at > t.timeout)

(* A peer disconnected: its partial blocks can never complete. *)
let remove_peer t peer_id = remove_where t (fun (p, _) _ -> p = peer_id)

(* The block connected (or arrived in full): nobody's partial copy is
   needed any more. *)
let remove_block t (hash : Types.hash256) =
  let k = Cstruct.to_string hash in
  ignore (remove_where t (fun (_, h) _ -> String.equal h k))

(* What the caller must do with a cmpctblock. *)
type cmpct_action =
  | Ignore of string                       (* nothing kept, nothing sent *)
  | Send_getheaders                        (* parent unknown *)
  | Invalid_header of string               (* punish the sender *)
  | Connect of Types.block                 (* reconstructed in full *)
  | Request_txns of P2p.block_txns_request (* entry stored; send getblocktxn *)
  | Request_block of Types.hash256         (* fall back to getdata *)

(* Core GetAntiDoSWorkThreshold, shared with the header and block paths. *)
let anti_dos_work_threshold = Sync.anti_dos_work_threshold

(* Decide what to do with [cb] from [peer_id].  [peer_hb] is true when the
   peer asked us for high-bandwidth relay (Core m_bip152_highbandwidth_to).
   [reconstruct] runs the mempool match; it is called only once the header
   has passed every check, so an unvalidated header costs no mempool scan. *)
let on_cmpctblock t (chain : Sync.chain_state) ~peer_id ~peer_hb ~now
    ~(reconstruct : P2p.compact_block -> P2p.reconstruct_status)
    (cb : P2p.compact_block) : cmpct_action =
  ignore (expire t ~now);
  let header = cb.P2p.header in
  let hash = Crypto.compute_block_hash header in
  match Sync.get_header chain header.Types.prev_block with
  | None -> Send_getheaders
  | Some prev ->
    let work =
      Consensus.work_add prev.Sync.total_work
        (Sync.work_from_bits header.Types.bits)
    in
    if Consensus.work_compare work (anti_dos_work_threshold chain) < 0 then
      Ignore "low-work compact block"
    else begin
      let entry =
        match Sync.get_header chain hash with
        | Some e -> Ok e
        | None ->
          (match Sync.validate_header chain header with
           | Ok e -> Sync.accept_header chain e; Ok e
           | Error e -> Error e)
      in
      match entry with
      | Error e -> Invalid_header e
      | Ok entry ->
        let tip_work, tip_height =
          match Sync.block_tip chain with
          | Some tip -> tip.Sync.total_work, tip.Sync.height
          | None -> Consensus.zero_work, chain.Sync.blocks_synced
        in
        if Sync.is_block_invalid chain hash then Ignore "block marked invalid"
        else if Storage.ChainDB.has_block chain.Sync.db hash then
          Ignore "already have block"
        else if Consensus.work_compare entry.Sync.total_work tip_work <= 0 then
          Ignore "no more work than the active tip"
        else if entry.Sync.height > tip_height + 2 then
          Ignore "more than 2 blocks above the tip (header kept)"
        else if mem t ~peer_id ~hash then
          Ignore "already in flight from this peer"
        else begin
          let in_flight = peers_for_block t hash in
          let first = in_flight = 0 in
          let slot =
            in_flight < max_peers_per_block
            && count_peer t peer_id < max_pending_per_peer
          in
          match reconstruct cb with
          | P2p.ReconstructComplete block -> Connect block
          | P2p.ReconstructFailed reason ->
            if slot && first then Request_block hash else Ignore reason
          | P2p.ReconstructNeedTxs (partial, missing) ->
            if not slot then Ignore "compact block slots full"
            else if first
                 || (peer_hb && in_flight < max_peers_per_block - 1) then begin
              Hashtbl.replace t.pending (peer_id, Cstruct.to_string hash)
                { cb; partial; missing; added_at = now };
              Request_txns (P2p.make_getblocktxn_request hash missing)
            end else Ignore "not first in flight"
        end
    end

type blocktxn_action =
  | Unexpected                          (* this peer was not asked *)
  | Txn_connect of Types.block
  | Txn_request_block of string         (* fill failed: getdata the block *)

(* A blocktxn completes only the partial block of the peer that sent it. *)
let on_blocktxn t ~peer_id ~now (resp : P2p.block_txns) : blocktxn_action =
  ignore (expire t ~now);
  let key = (peer_id, Cstruct.to_string resp.P2p.block_hash) in
  match Hashtbl.find_opt t.pending key with
  | None -> Unexpected
  | Some e ->
    Hashtbl.remove t.pending key;
    (match P2p.fill_missing_txs e.cb e.partial e.missing resp.P2p.txs with
     | Ok block -> Txn_connect block
     | Error reason -> Txn_request_block reason)
