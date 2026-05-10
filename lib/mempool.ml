(* Memory Pool for Unconfirmed Transactions

   The mempool holds transactions that have been validated against the
   current UTXO set but not yet included in a block. Features:

   - Validation against chain UTXO set plus other mempool transactions
   - Fee-rate based prioritization (satoshis per weight unit)
   - Size limits with eviction of lowest fee-rate transactions
   - Transaction dependency tracking (child-pays-for-parent)
   - Conflict detection when blocks are mined
   - Script verification at acceptance
   - IsStandard policy checks
   - Dust output filtering
   - Ancestor/descendant limits
   - RBF rules 1-5
   - Locktime and BIP68 sequence lock enforcement
   - Orphan transaction pool

   KNOWN PITFALL — When a transaction is removed, all dependent
   transactions must also be removed (descendants spending its outputs). *)

let log_src = Logs.Src.create "MEMPOOL" ~doc:"Memory pool"
module Log = (val Logs.src_log log_src : Logs.LOG)
let _ = Log.info  (* suppress unused module warning *)

(* ============================================================================
   Mempool Entry Type
   ============================================================================ *)

type mempool_entry = {
  tx : Types.transaction;
  txid : Types.hash256;
  wtxid : Types.hash256;
  fee : int64;
  weight : int;
  fee_rate : float;           (* satoshis per weight unit *)
  time_added : float;
  height_added : int;
  depends_on : Types.hash256 list;  (* parent txids in mempool *)
  (* Cached ancestor/descendant stats for O(1) limit checks after initial computation *)
  mutable ancestor_count : int;     (* number of ancestors including self *)
  mutable ancestor_size : int;      (* total vsize of ancestors including self *)
  mutable descendant_count : int;   (* number of descendants including self *)
  mutable descendant_size : int;    (* total vsize of descendants including self *)
}

(* ============================================================================
   Orphan Pool Types
   ============================================================================ *)

type orphan_entry = {
  orphan_tx : Types.transaction;
  orphan_txid : Types.hash256;
  orphan_time : float;
}

(* ============================================================================
   Mempool State
   ============================================================================ *)

type mempool = {
  mutable entries : (string, mempool_entry) Hashtbl.t;
  mutable total_weight : int;
  mutable total_fee : int64;
  max_size_bytes : int;       (* default 300 MB *)
  min_relay_fee : int64;      (* minimum fee rate in sat/kvB *)
  mutable dynamic_min_fee : int64;  (* raised when mempool is full and evictions occur *)
  utxo : Utxo.UtxoSet.t;
  mutable current_height : int;
  mutable network : Consensus.network_config;
  mutable current_median_time : int32;
  (* Policy flags — can be relaxed for testing or regtest *)
  require_standard : bool;    (* enforce IsStandard checks *)
  verify_scripts : bool;      (* enforce script verification *)
  (* Orphan pool *)
  orphans : (string, orphan_entry) Hashtbl.t;
  max_orphans : int;
  (* Spending index: outpoint (txid_str * vout) -> spending txid_str for O(1) conflict detection *)
  map_next_tx : (string * int32, string) Hashtbl.t;
  (* ZMQ notifications *)
  mutable zmq_sequence : int64;                 (* monotonically increasing sequence for ZMQ *)
  mutable zmq_notifier : Zmq_notify.t option;   (* optional ZMQ notifier *)
}

(* ============================================================================
   Constants
   ============================================================================ *)

let max_ancestor_count = 25
let max_descendant_count = 25
let max_ancestor_size = 101_000
let max_descendant_size = 101_000
let max_rbf_evictions = 100
let max_standard_tx_weight = 400_000
let incremental_relay_fee = 1000L  (* 1000 sat/kvB, same as default relay fee *)

(* Cluster mempool constants (replaces ancestor/descendant limits) *)
let max_cluster_count = 101    (* max transactions per cluster *)

(* ============================================================================
   Union-Find Data Structure for Clustering

   Reference: Bitcoin Core /src/cluster_linearize.h
   Clusters are connected components in the transaction dependency graph.
   ============================================================================ *)

(* Union-Find with path compression and union by rank *)
type uf = {
  parent : (string, string) Hashtbl.t;  (* txid_key -> parent txid_key *)
  rank : (string, int) Hashtbl.t;       (* txid_key -> rank *)
}

let uf_create () : uf =
  { parent = Hashtbl.create 256; rank = Hashtbl.create 256 }

(* Find root with path compression *)
let rec uf_find (uf : uf) (x : string) : string =
  match Hashtbl.find_opt uf.parent x with
  | None ->
    (* Not yet in structure, add as its own root *)
    Hashtbl.replace uf.parent x x;
    Hashtbl.replace uf.rank x 0;
    x
  | Some p ->
    if p = x then x
    else begin
      let root = uf_find uf p in
      (* Path compression *)
      Hashtbl.replace uf.parent x root;
      root
    end

(* Union two sets by rank *)
let uf_union (uf : uf) (x : string) (y : string) : unit =
  let rx = uf_find uf x in
  let ry = uf_find uf y in
  if rx <> ry then begin
    let rank_x = Hashtbl.find uf.rank rx in
    let rank_y = Hashtbl.find uf.rank ry in
    if rank_x < rank_y then
      Hashtbl.replace uf.parent rx ry
    else if rank_x > rank_y then
      Hashtbl.replace uf.parent ry rx
    else begin
      Hashtbl.replace uf.parent ry rx;
      Hashtbl.replace uf.rank rx (rank_x + 1)
    end
  end

(* ============================================================================
   Cluster Types

   A cluster is a connected component in the tx dependency graph.
   Reference: Bitcoin Core /src/txmempool.cpp, /src/cluster_linearize.h
   ============================================================================ *)

type cluster = {
  txs : mempool_entry list;
  total_fee : int64;
  total_vsize : int;
  fee_rate : float;  (* total_fee / total_vsize *)
}

(* Chunk: a subset of a cluster used for linearization.
   Each chunk is topologically valid (all parents included before children). *)
type chunk = {
  chunk_txs : mempool_entry list;
  chunk_fee : int64;
  chunk_vsize : int;
  chunk_fee_rate : float;
}

(* TRUC/v3 transaction policy (BIP-431)
   Reference: Bitcoin Core /src/policy/truc_policy.cpp *)
let truc_version = 3l
let truc_max_vsize = 10_000       (* max virtual size for any v3 transaction *)
let truc_child_max_vsize = 1_000  (* max virtual size for v3 child (has unconfirmed v3 parent) *)
let truc_ancestor_limit = 2       (* max unconfirmed ancestors including self *)
let truc_descendant_limit = 2     (* max unconfirmed descendants including self *)

(* ============================================================================
   Mempool Creation
   ============================================================================ *)

let create ?(require_standard=true) ?(verify_scripts=true)
    ?(zmq_notifier : Zmq_notify.t option)
    ~(utxo : Utxo.UtxoSet.t) ~(current_height : int) () : mempool =
  let network = Consensus.regtest in
  { entries = Hashtbl.create 10_000;
    total_weight = 0;
    total_fee = 0L;
    max_size_bytes = 300 * 1024 * 1024;
    min_relay_fee = 1000L;  (* 1 sat/vB = 1000 sat/kvB *)
    dynamic_min_fee = 0L;
    utxo;
    current_height;
    network;
    current_median_time = 0l;
    require_standard;
    verify_scripts;
    orphans = Hashtbl.create 100;
    max_orphans = 100;
    map_next_tx = Hashtbl.create 10_000;
    zmq_sequence = 0L;
    zmq_notifier }

(* ============================================================================
   Basic Queries
   ============================================================================ *)

(* Check if a transaction is already in the mempool *)
let contains (mp : mempool) (txid : Types.hash256) : bool =
  Hashtbl.mem mp.entries (Cstruct.to_string txid)

(* Get a transaction from the mempool *)
let get (mp : mempool) (txid : Types.hash256) : mempool_entry option =
  Hashtbl.find_opt mp.entries (Cstruct.to_string txid)

(* ============================================================================
   UTXO Lookup (Chain + Mempool)
   ============================================================================ *)

(* Look up a UTXO considering both chain state and mempool *)
let lookup_utxo (mp : mempool) (outpoint : Types.outpoint)
    : Utxo.utxo_entry option =
  (* First check chain UTXO set *)
  match Utxo.UtxoSet.get mp.utxo outpoint.txid
          (Int32.to_int outpoint.vout) with
  | Some entry -> Some entry
  | None ->
    (* Check mempool for unconfirmed parent *)
    let txid_key = Cstruct.to_string outpoint.txid in
    match Hashtbl.find_opt mp.entries txid_key with
    | None -> None
    | Some parent_entry ->
      let vout = Int32.to_int outpoint.vout in
      if vout < List.length parent_entry.tx.outputs then begin
        let out = List.nth parent_entry.tx.outputs vout in
        Some {
          Utxo.value = out.Types.value;
          script_pubkey = out.script_pubkey;
          height = mp.current_height;
          is_coinbase = false;
        }
      end else None

(* Check if a UTXO is confirmed (in chain UTXO set, not just mempool) *)
let is_confirmed_utxo (mp : mempool) (outpoint : Types.outpoint) : bool =
  match Utxo.UtxoSet.get mp.utxo outpoint.txid
          (Int32.to_int outpoint.vout) with
  | Some _ -> true
  | None -> false

(* ============================================================================
   Transaction Removal
   ============================================================================ *)

(* Set the ZMQ notifier for the mempool *)
let set_zmq_notifier (mp : mempool) (notifier : Zmq_notify.t) : unit =
  mp.zmq_notifier <- Some notifier

(* Get the current mempool ZMQ sequence number *)
let get_zmq_sequence (mp : mempool) : int64 = mp.zmq_sequence

(* Notify ZMQ subscribers about a transaction event *)
let zmq_notify_tx (mp : mempool) (txid : Types.hash256) (tx : Types.transaction)
    (acceptance : bool) : unit =
  match mp.zmq_notifier with
  | None -> ()
  | Some notifier ->
    let seq = mp.zmq_sequence in
    mp.zmq_sequence <- Int64.add seq 1L;
    (* Publish hashtx and rawtx *)
    ignore (Zmq_notify.notify_hashtx notifier txid);
    ignore (Zmq_notify.notify_rawtx notifier tx);
    (* Publish sequence event *)
    if acceptance then
      ignore (Zmq_notify.notify_tx_acceptance notifier txid seq)
    else
      ignore (Zmq_notify.notify_tx_removal notifier txid seq)

(* Remove a transaction and its dependents recursively.
   Collects dependent txids before removal to avoid mutating Hashtbl during iteration.
   Updates cached descendant counts of ancestors using BFS. *)
let rec remove_transaction (mp : mempool) (txid : Types.hash256) : unit =
  let txid_key = Cstruct.to_string txid in
  match Hashtbl.find_opt mp.entries txid_key with
  | None -> ()
  | Some entry ->
    (* Notify ZMQ subscribers about removal *)
    zmq_notify_tx mp entry.txid entry.tx false;
    let vsize = (entry.weight + 3) / 4 in
    (* Update ancestor descendant counts before removal *)
    let visited = Hashtbl.create 16 in
    let queue = Queue.create () in
    List.iter (fun parent_txid ->
      let parent_key = Cstruct.to_string parent_txid in
      if not (Hashtbl.mem visited parent_key) then begin
        Hashtbl.replace visited parent_key ();
        Queue.push parent_key queue
      end
    ) entry.depends_on;
    while not (Queue.is_empty queue) do
      let key = Queue.pop queue in
      match Hashtbl.find_opt mp.entries key with
      | None -> ()
      | Some ancestor_entry ->
        ancestor_entry.descendant_count <- max 1 (ancestor_entry.descendant_count - 1);
        ancestor_entry.descendant_size <- max ancestor_entry.descendant_size (ancestor_entry.descendant_size - vsize);
        List.iter (fun gp_txid ->
          let gp_key = Cstruct.to_string gp_txid in
          if not (Hashtbl.mem visited gp_key) then begin
            Hashtbl.replace visited gp_key ();
            Queue.push gp_key queue
          end
        ) ancestor_entry.depends_on
    done;
    Hashtbl.remove mp.entries txid_key;
    mp.total_weight <- mp.total_weight - entry.weight;
    mp.total_fee <- Int64.sub mp.total_fee entry.fee;
    List.iter (fun inp ->
      let out_key = (Cstruct.to_string inp.Types.previous_output.txid,
                     inp.Types.previous_output.vout) in
      Hashtbl.remove mp.map_next_tx out_key
    ) entry.tx.inputs;
    let dependent_txids = Hashtbl.fold (fun _k dep acc ->
      if List.exists (fun d -> Cstruct.equal d txid) dep.depends_on then
        dep.txid :: acc
      else acc
    ) mp.entries [] in
    List.iter (fun dep_txid -> remove_transaction mp dep_txid) dependent_txids

(* ============================================================================
   Ancestor/Descendant Tracking
   ============================================================================ *)

(* Get all ancestors of a transaction (transactions it depends on) *)
let get_ancestors (mp : mempool) (txid : Types.hash256)
    : mempool_entry list =
  let rec collect visited txid =
    let txid_key = Cstruct.to_string txid in
    if Hashtbl.mem visited txid_key then []
    else begin
      Hashtbl.add visited txid_key ();
      match Hashtbl.find_opt mp.entries txid_key with
      | None -> []
      | Some entry ->
        let parent_ancestors = List.concat_map
          (collect visited) entry.depends_on in
        entry :: parent_ancestors
    end
  in
  let visited = Hashtbl.create 16 in
  match Hashtbl.find_opt mp.entries (Cstruct.to_string txid) with
  | None -> []
  | Some entry ->
    List.concat_map (collect visited) entry.depends_on

(* Get all descendants of a transaction (transactions that depend on it) *)
let get_descendants (mp : mempool) (txid : Types.hash256)
    : mempool_entry list =
  let rec collect visited txid =
    let txid_key = Cstruct.to_string txid in
    if Hashtbl.mem visited txid_key then []
    else begin
      Hashtbl.add visited txid_key ();
      (* Find all entries that depend on this txid *)
      let children = Hashtbl.fold (fun _ entry acc ->
        if List.exists (fun d -> Cstruct.equal d txid) entry.depends_on
        then entry :: acc
        else acc
      ) mp.entries [] in

      (* Recursively get descendants of children *)
      let grandchildren = List.concat_map
        (fun e -> collect visited e.txid) children in
      children @ grandchildren
    end
  in
  collect (Hashtbl.create 16) txid

(* ============================================================================
   Cluster Mempool

   Group transactions into connected clusters based on parent/child relationships.
   Reference: Bitcoin Core /src/cluster_linearize.cpp, /src/txmempool.cpp
   ============================================================================ *)

(* Build Union-Find structure from all mempool transactions *)
let build_clusters_uf (mp : mempool) : uf =
  let uf = uf_create () in
  (* Add all transactions to UF structure *)
  Hashtbl.iter (fun txid_key _entry ->
    ignore (uf_find uf txid_key)
  ) mp.entries;
  (* Union transactions with their in-mempool parents *)
  Hashtbl.iter (fun txid_key entry ->
    List.iter (fun parent_txid ->
      let parent_key = Cstruct.to_string parent_txid in
      if Hashtbl.mem mp.entries parent_key then
        uf_union uf txid_key parent_key
    ) entry.depends_on
  ) mp.entries;
  uf

(* Get all clusters in the mempool *)
let get_clusters (mp : mempool) : cluster list =
  let uf = build_clusters_uf mp in
  (* Group transactions by cluster root *)
  let cluster_map : (string, mempool_entry list) Hashtbl.t = Hashtbl.create 64 in
  Hashtbl.iter (fun txid_key entry ->
    let root = uf_find uf txid_key in
    let current = try Hashtbl.find cluster_map root with Not_found -> [] in
    Hashtbl.replace cluster_map root (entry :: current)
  ) mp.entries;
  (* Convert to cluster list *)
  Hashtbl.fold (fun _root txs acc ->
    let total_fee = List.fold_left (fun acc e -> Int64.add acc e.fee) 0L txs in
    let total_vsize = List.fold_left (fun acc e -> acc + (e.weight + 3) / 4) 0 txs in
    let fee_rate = if total_vsize > 0 then
      Int64.to_float total_fee /. float_of_int total_vsize
    else 0.0 in
    { txs; total_fee; total_vsize; fee_rate } :: acc
  ) cluster_map []

(* Get the cluster containing a specific transaction *)
let get_cluster (mp : mempool) (txid : Types.hash256) : cluster option =
  let txid_key = Cstruct.to_string txid in
  if not (Hashtbl.mem mp.entries txid_key) then None
  else begin
    let uf = build_clusters_uf mp in
    let target_root = uf_find uf txid_key in
    (* Collect all transactions in the same cluster *)
    let txs = Hashtbl.fold (fun key entry acc ->
      if uf_find uf key = target_root then entry :: acc
      else acc
    ) mp.entries [] in
    let total_fee = List.fold_left (fun acc e -> Int64.add acc e.fee) 0L txs in
    let total_vsize = List.fold_left (fun acc e -> acc + (e.weight + 3) / 4) 0 txs in
    let fee_rate = if total_vsize > 0 then
      Int64.to_float total_fee /. float_of_int total_vsize
    else 0.0 in
    Some { txs; total_fee; total_vsize; fee_rate }
  end

(* Get cluster size (number of transactions) for a given txid *)
let get_cluster_size (mp : mempool) (txid : Types.hash256) : int =
  match get_cluster mp txid with
  | None -> 0
  | Some cluster -> List.length cluster.txs

(* ============================================================================
   Cluster Linearization

   Compute an optimal or near-optimal topological ordering that maximizes
   fee rate at each prefix. Uses the chunking algorithm:
   greedily pick the highest-fee-rate topologically valid subset.

   Reference: Bitcoin Core /src/cluster_linearize.h ChunkLinearization
   ============================================================================ *)

(* Check if a set of txids forms a topologically valid subset
   (all parents of included txs are also included) *)
let is_topologically_valid (subset : (string, unit) Hashtbl.t)
    (mp : mempool) : bool =
  let valid = ref true in
  Hashtbl.iter (fun txid_key () ->
    if !valid then begin
      match Hashtbl.find_opt mp.entries txid_key with
      | None -> valid := false
      | Some entry ->
        List.iter (fun parent_txid ->
          let parent_key = Cstruct.to_string parent_txid in
          if Hashtbl.mem mp.entries parent_key then begin
            if not (Hashtbl.mem subset parent_key) then
              valid := false
          end
        ) entry.depends_on
    end
  ) subset;
  !valid

(* Find the highest-fee-rate topologically valid subset (chunk) from remaining txs.
   This implements a greedy approximation of the optimal chunking algorithm. *)
let find_best_chunk (remaining : mempool_entry list) (_mp : mempool) : chunk =
  (* Build dependency info for remaining transactions *)
  let remaining_set = Hashtbl.create (List.length remaining) in
  List.iter (fun e ->
    Hashtbl.replace remaining_set (Cstruct.to_string e.txid) e
  ) remaining;

  (* Find transactions with no remaining parents (can be chunk roots) *)
  let has_remaining_parent e =
    List.exists (fun parent_txid ->
      Hashtbl.mem remaining_set (Cstruct.to_string parent_txid)
    ) e.depends_on
  in

  (* Try each transaction as a potential chunk seed and find its closure *)
  let best_chunk = ref { chunk_txs = []; chunk_fee = 0L;
                         chunk_vsize = 0; chunk_fee_rate = 0.0 } in

  (* For each transaction, compute its ancestor closure within remaining *)
  List.iter (fun seed ->
    (* Compute the minimal topologically valid subset containing seed *)
    let subset = Hashtbl.create 16 in
    let rec add_with_ancestors txid_key =
      if not (Hashtbl.mem subset txid_key) then begin
        Hashtbl.replace subset txid_key ();
        match Hashtbl.find_opt remaining_set txid_key with
        | None -> ()
        | Some entry ->
          List.iter (fun parent_txid ->
            let parent_key = Cstruct.to_string parent_txid in
            if Hashtbl.mem remaining_set parent_key then
              add_with_ancestors parent_key
          ) entry.depends_on
      end
    in
    add_with_ancestors (Cstruct.to_string seed.txid);

    (* Calculate fee rate of this subset *)
    let chunk_txs = Hashtbl.fold (fun txid_key () acc ->
      match Hashtbl.find_opt remaining_set txid_key with
      | Some e -> e :: acc
      | None -> acc
    ) subset [] in
    let chunk_fee = List.fold_left (fun acc e -> Int64.add acc e.fee) 0L chunk_txs in
    let chunk_vsize = List.fold_left (fun acc e -> acc + (e.weight + 3) / 4) 0 chunk_txs in
    let chunk_fee_rate = if chunk_vsize > 0 then
      Int64.to_float chunk_fee /. float_of_int chunk_vsize
    else 0.0 in

    if chunk_fee_rate > !best_chunk.chunk_fee_rate ||
       (!best_chunk.chunk_txs = [] && chunk_txs <> []) then
      best_chunk := { chunk_txs; chunk_fee; chunk_vsize; chunk_fee_rate }
  ) remaining;

  (* If no good chunk found, try transactions with no remaining parents *)
  if !best_chunk.chunk_txs = [] then begin
    let roots = List.filter (fun e -> not (has_remaining_parent e)) remaining in
    if roots <> [] then begin
      (* Pick the highest fee-rate root as a single-tx chunk *)
      let sorted_roots = List.sort (fun (a : mempool_entry) (b : mempool_entry) ->
        compare b.fee_rate a.fee_rate
      ) roots in
      let best_root = List.hd sorted_roots in
      best_chunk := {
        chunk_txs = [best_root];
        chunk_fee = best_root.fee;
        chunk_vsize = (best_root.weight + 3) / 4;
        chunk_fee_rate = best_root.fee_rate;
      }
    end else if remaining <> [] then begin
      (* Fallback: take any remaining tx (shouldn't happen if deps are correct) *)
      let e = List.hd remaining in
      best_chunk := {
        chunk_txs = [e];
        chunk_fee = e.fee;
        chunk_vsize = (e.weight + 3) / 4;
        chunk_fee_rate = e.fee_rate;
      }
    end
  end;
  !best_chunk

(* Remove a chunk's transactions from the remaining list *)
let remove_chunk (remaining : mempool_entry list) (chunk : chunk)
    : mempool_entry list =
  let chunk_txids = Hashtbl.create (List.length chunk.chunk_txs) in
  List.iter (fun e ->
    Hashtbl.replace chunk_txids (Cstruct.to_string e.txid) ()
  ) chunk.chunk_txs;
  List.filter (fun e ->
    not (Hashtbl.mem chunk_txids (Cstruct.to_string e.txid))
  ) remaining

(* Linearize a cluster into chunks ordered by fee rate.
   Reference: Bitcoin Core ChunkLinearization in cluster_linearize.h *)
let linearize_cluster (cluster : cluster) (mp : mempool) : chunk list =
  let rec chunk_loop remaining acc =
    if remaining = [] then List.rev acc
    else begin
      let best = find_best_chunk remaining mp in
      if best.chunk_txs = [] then List.rev acc  (* shouldn't happen *)
      else begin
        let new_remaining = remove_chunk remaining best in
        chunk_loop new_remaining (best :: acc)
      end
    end
  in
  chunk_loop cluster.txs []

(* Get all chunks from all clusters, sorted by fee rate (highest first) *)
let get_all_chunks (mp : mempool) : chunk list =
  let clusters = get_clusters mp in
  let all_chunks = List.concat_map (fun c -> linearize_cluster c mp) clusters in
  (* Sort by fee rate descending *)
  List.sort (fun a b -> compare b.chunk_fee_rate a.chunk_fee_rate) all_chunks

(* Get the worst (lowest fee-rate) chunk for eviction *)
let get_worst_chunk (mp : mempool) : chunk option =
  let chunks = get_all_chunks mp in
  if chunks = [] then None
  else begin
    (* Chunks are sorted highest first, so worst is last *)
    Some (List.nth chunks (List.length chunks - 1))
  end

(* ============================================================================
   Cluster-Based Mining Selection

   Select transactions by iterating chunks in fee-rate order.
   Reference: Bitcoin Core BlockAssembler with cluster mempool
   ============================================================================ *)

(* Select transactions for mining using chunk-based ordering *)
let select_for_block_chunked (mp : mempool) ~(max_weight : int)
    : mempool_entry list =
  let chunks = get_all_chunks mp in
  let selected = ref [] in
  let selected_txids = Hashtbl.create 100 in
  let current_weight = ref 0 in

  (* Iterate through chunks in fee-rate order *)
  List.iter (fun chunk ->
    (* Check if all transactions in chunk fit *)
    let chunk_weight = List.fold_left (fun acc e -> acc + e.weight) 0 chunk.chunk_txs in
    if !current_weight + chunk_weight <= max_weight then begin
      (* Verify all dependencies are satisfied *)
      let deps_ok = List.for_all (fun e ->
        List.for_all (fun dep_txid ->
          let dep_key = Cstruct.to_string dep_txid in
          (* Either dep is already selected, or not in mempool *)
          Hashtbl.mem selected_txids dep_key ||
          not (Hashtbl.mem mp.entries dep_key)
        ) e.depends_on
      ) chunk.chunk_txs in

      if deps_ok then begin
        (* Add all transactions from this chunk *)
        List.iter (fun e ->
          selected := e :: !selected;
          Hashtbl.add selected_txids (Cstruct.to_string e.txid) ();
          current_weight := !current_weight + e.weight
        ) chunk.chunk_txs
      end
    end
  ) chunks;

  List.rev !selected

(* ============================================================================
   Cluster-Based Eviction

   Evict the lowest-fee-rate chunk when mempool is full.
   Reference: Bitcoin Core TrimToSize with GetWorstMainChunk
   ============================================================================ *)

(* Evict lowest fee-rate chunks until mempool is under target size.
   Updates dynamic_min_fee based on the last evicted chunk's fee rate. *)
let evict_by_chunks (mp : mempool) : unit =
  let target = mp.max_size_bytes * 3 / 4 in
  let rec evict_loop () =
    if mp.total_weight <= target then ()
    else begin
      match get_worst_chunk mp with
      | None -> ()
      | Some worst_chunk ->
        let evicted_fee_rate_kvb =
          worst_chunk.chunk_fee_rate *. 4.0 *. 1000.0 in
        mp.dynamic_min_fee <-
          Int64.add (Int64.of_float evicted_fee_rate_kvb) incremental_relay_fee;
        List.iter (fun e ->
          remove_transaction mp e.txid
        ) worst_chunk.chunk_txs;
        evict_loop ()
    end
  in
  evict_loop ()

(* Effective minimum fee rate: max of static min_relay_fee and dynamic_min_fee.
   dynamic_min_fee is raised when the mempool is full and evictions occur. *)
let effective_min_fee (mp : mempool) : int64 =
  if mp.total_weight > mp.max_size_bytes / 4 then
    Int64.max mp.min_relay_fee mp.dynamic_min_fee
  else begin
    mp.dynamic_min_fee <- 0L;
    mp.min_relay_fee
  end

(* ============================================================================
   Cluster Size Limit Check

   Replace ancestor/descendant limit checks with cluster size limit.
   Max 101 transactions per cluster (Bitcoin Core default).
   ============================================================================ *)

(* Check if adding a transaction would exceed cluster size limit *)
let check_cluster_size_limit (mp : mempool) (depends : Types.hash256 list)
    (new_txid : Types.hash256) : (unit, string) result =
  if depends = [] then
    (* No dependencies, would form a singleton cluster *)
    Ok ()
  else begin
    (* Find the cluster(s) that would be affected *)
    let uf = build_clusters_uf mp in

    (* Simulate adding the new tx to UF *)
    let new_txid_key = Cstruct.to_string new_txid in
    ignore (uf_find uf new_txid_key);

    (* Union with all parent clusters *)
    List.iter (fun parent_txid ->
      let parent_key = Cstruct.to_string parent_txid in
      if Hashtbl.mem mp.entries parent_key then
        uf_union uf new_txid_key parent_key
    ) depends;

    (* Count the resulting cluster size *)
    let merged_root = uf_find uf new_txid_key in
    let cluster_size = Hashtbl.fold (fun txid_key _entry count ->
      if uf_find uf txid_key = merged_root then count + 1
      else count
    ) mp.entries 1 in  (* +1 for the new tx *)

    if cluster_size > max_cluster_count then
      Error (Printf.sprintf "Cluster size limit exceeded (%d > %d)"
        cluster_size max_cluster_count)
    else
      Ok ()
  end

(* ============================================================================
   Eviction Policy (Gap 8: TrimToSize by descendant score)
   ============================================================================ *)

(* Compute descendant score for an entry: (fee + desc_fees) / (weight + desc_weights) *)
let descendant_score (mp : mempool) (entry : mempool_entry) : float =
  let descs = get_descendants mp entry.txid in
  let desc_fees = List.fold_left (fun acc d -> Int64.add acc d.fee) 0L descs in
  let desc_weights = List.fold_left (fun acc d -> acc + d.weight) 0 descs in
  let total_fee = Int64.add entry.fee desc_fees in
  let total_weight = entry.weight + desc_weights in
  if total_weight = 0 then 0.0
  else Int64.to_float total_fee /. float_of_int total_weight

(* Evict lowest descendant-score transactions when mempool is full *)
let evict_lowest_feerate (mp : mempool) : unit =
  let entries = Hashtbl.fold (fun _ v acc -> v :: acc) mp.entries [] in
  let sorted = List.sort
    (fun a b ->
      compare (descendant_score mp a) (descendant_score mp b)) entries in
  (* Target 75% of max size -- fixed integer division ordering bug *)
  let target = mp.max_size_bytes * 3 / 4 in
  let rec evict = function
    | [] -> ()
    | entry :: rest ->
      if mp.total_weight <= target then ()
      else begin
        remove_transaction mp entry.txid;
        evict rest
      end
  in
  evict sorted

(* ============================================================================
   Dust Threshold (Task 6)
   ============================================================================ *)

(* Estimate the spending input size for a given script type *)
let spending_input_size (script_pubkey : Cstruct.t) : int =
  match Script.classify_script script_pubkey with
  | Script.P2PKH_script _ -> 148
  | Script.P2SH_script _ -> 91
  | Script.P2WPKH_script _ -> 67
  | Script.P2WSH_script _ -> 109
  | Script.P2TR_script _ -> 58
  | Script.P2A_script -> 41  (* P2A: minimal input, empty witness *)
  | Script.OP_RETURN_data _ -> 0  (* OP_RETURN outputs are unspendable *)
  | Script.Nonstandard -> 148  (* Conservative: use P2PKH size *)

let output_serialized_size (output : Types.tx_out) : int =
  let script_len = Cstruct.length output.script_pubkey in
  let varint_len = if script_len < 0xFD then 1 else if script_len <= 0xFFFF then 3 else 5 in
  8 + varint_len + script_len

(* Check if an output is dust. Dust = value < 3 * min_relay_fee * spending_size / 1000
   P2A outputs have a fixed dust limit of 240 satoshis *)
let is_dust (min_relay_fee : int64) (output : Types.tx_out) : bool =
  match Script.classify_script output.script_pubkey with
  | Script.OP_RETURN_data _ -> false  (* OP_RETURN is not dust *)
  | Script.P2A_script ->
    (* P2A outputs must have exactly 240 satoshis -- the P2A dust limit *)
    output.Types.value <> Script.p2a_dust_limit
  | _ ->
    let spend_size = spending_input_size output.script_pubkey in
    if spend_size = 0 then false
    else begin
      let threshold = Int64.of_float (
        3.0 *. Int64.to_float min_relay_fee *.
        float_of_int (output_serialized_size output + spend_size) /. 1000.0) in
      output.Types.value < threshold
    end

(* ============================================================================
   IsStandard Checks (Task 7)
   ============================================================================ *)

(* Check if a scriptSig is push-only (contains only push data opcodes) *)
let is_push_only_script_sig (script_sig : Cstruct.t) : bool =
  if Cstruct.length script_sig = 0 then true
  else begin
    try
      let ops = Script.parse_script script_sig in
      List.for_all (fun op ->
        match op with
        | Script.OP_0 -> true
        | Script.OP_1NEGATE -> true
        | Script.OP_1 | Script.OP_2 | Script.OP_3 | Script.OP_4
        | Script.OP_5 | Script.OP_6 | Script.OP_7 | Script.OP_8
        | Script.OP_9 | Script.OP_10 | Script.OP_11 | Script.OP_12
        | Script.OP_13 | Script.OP_14 | Script.OP_15 | Script.OP_16 -> true
        | Script.OP_PUSHDATA (_, _) -> true
        | _ -> false
      ) ops
    with _ -> false
  end

(* Check if a script is a P2PK (bare pubkey) output.
   Format: <33 or 65 byte pubkey> OP_CHECKSIG (0xac).
   Core: MatchPayToPubkey in solver.cpp — pubkey must be 33 (compressed)
   or 65 (uncompressed) bytes. *)
let is_p2pk_script (script : Cstruct.t) : bool =
  let len = Cstruct.length script in
  (* Compressed: 35 bytes total — 0x21 <33 bytes> 0xac *)
  ((len = 35 &&
    Cstruct.get_uint8 script 0 = 0x21 &&
    Cstruct.get_uint8 script 34 = 0xac) ||
   (* Uncompressed: 67 bytes total — 0x41 <65 bytes> 0xac *)
   (len = 67 &&
    Cstruct.get_uint8 script 0 = 0x41 &&
    Cstruct.get_uint8 script 66 = 0xac))

(* Decode bare multisig (m-of-n OP_CHECKMULTISIG) output.
   Returns Some (m, n) where m is the minimum required signatures and n is the
   total number of pubkeys, or None if the script is not bare multisig.
   Core: MatchMultisig in solver.cpp — OP_m <pubkeys> OP_n OP_CHECKMULTISIG.
   n and m must be OP_1..OP_16 small integers. *)
let decode_bare_multisig (script : Cstruct.t) : (int * int) option =
  let len = Cstruct.length script in
  (* Minimum: OP_1 <33-byte-pub> OP_1 OP_CHECKMULTISIG = 37 bytes *)
  if len < 37 then None
  else
    let last_byte = Cstruct.get_uint8 script (len - 1) in
    if last_byte <> 0xae (* OP_CHECKMULTISIG *) then None
    else begin
      (* First byte must be OP_1..OP_16 (0x51..0x60): the m value *)
      let m_byte = Cstruct.get_uint8 script 0 in
      if m_byte < 0x51 || m_byte > 0x60 then None
      else begin
        let m = m_byte - 0x50 in
        (* Walk pubkeys — each must be a 0x21 (33) or 0x41 (65) byte push *)
        let i = ref 1 in
        let n = ref 0 in
        let bad = ref false in
        while not !bad && !i < len - 2 do
          let push_byte = Cstruct.get_uint8 script !i in
          let pk_len =
            if push_byte = 0x21 then 33
            else if push_byte = 0x41 then 65
            else 0
          in
          if pk_len = 0 then bad := true
          else if !i + 1 + pk_len > len - 2 then bad := true
          else begin
            incr n;
            i := !i + 1 + pk_len
          end
        done;
        if !bad then None
        else begin
          (* Next byte (at position i) must be OP_n (0x51..0x60) *)
          if !i <> len - 2 then None
          else begin
            let n_byte = Cstruct.get_uint8 script !i in
            if n_byte < 0x51 || n_byte > 0x60 then None
            else begin
              let n_val = n_byte - 0x50 in
              (* Pubkey count must match n and constraints must hold *)
              if !n <> n_val then None
              else Some (m, n_val)
            end
          end
        end
      end
    end

(* Check if a script is a recognized standard output type.
   Reference: Bitcoin Core IsStandard() in policy/policy.cpp + Solver() in
   script/solver.cpp.  Standard types: P2PKH, P2SH, P2WPKH, P2WSH, P2TR, P2A,
   P2PK (bare pubkey), bare multisig m-of-n with n <= 3, and OP_RETURN.
   OP_RETURN size is NOT checked here — it is checked cumulatively in
   is_standard_tx (see datacarrier_bytes_left logic below). *)
let is_standard_output (script_pubkey : Cstruct.t) : bool =
  match Script.classify_script script_pubkey with
  | Script.P2PKH_script _ -> true
  | Script.P2SH_script _ -> true
  | Script.P2WPKH_script _ -> true
  | Script.P2WSH_script _ -> true
  | Script.P2TR_script _ -> true
  | Script.P2A_script -> true  (* P2A is standard -- BIP-PR-3535 *)
  | Script.OP_RETURN_data _ -> true  (* size checked cumulatively in is_standard_tx *)
  | Script.Nonstandard ->
    (* Check P2PK (bare pubkey) — not in classify_script but standard in Core *)
    if is_p2pk_script script_pubkey then true
    (* Check bare multisig m-of-n with n <= 3 (Core policy limit) *)
    else match decode_bare_multisig script_pubkey with
    | Some (m, n) -> n >= 1 && n <= 3 && m >= 1 && m <= n
    | None -> false

(* Count legacy sigops in a script with accurate multisig counting.
   OP_CHECKSIG/VERIFY = 1 sigop.
   OP_CHECKMULTISIG/VERIFY = N sigops where N is the preceding OP_N (1-16),
   or 20 if the preceding opcode is not an OP_N push. *)
let count_script_sigops (script : Cstruct.t) : int =
  let op_n_value = function
    | Script.OP_1  -> Some 1  | Script.OP_2  -> Some 2
    | Script.OP_3  -> Some 3  | Script.OP_4  -> Some 4
    | Script.OP_5  -> Some 5  | Script.OP_6  -> Some 6
    | Script.OP_7  -> Some 7  | Script.OP_8  -> Some 8
    | Script.OP_9  -> Some 9  | Script.OP_10 -> Some 10
    | Script.OP_11 -> Some 11 | Script.OP_12 -> Some 12
    | Script.OP_13 -> Some 13 | Script.OP_14 -> Some 14
    | Script.OP_15 -> Some 15 | Script.OP_16 -> Some 16
    | _ -> None
  in
  try
    let ops = Script.parse_script script in
    let (count, _) = List.fold_left (fun (acc, prev_op) op ->
      match op with
      | Script.OP_CHECKSIG | Script.OP_CHECKSIGVERIFY -> (acc + 1, Some op)
      | Script.OP_CHECKMULTISIG | Script.OP_CHECKMULTISIGVERIFY ->
        let n = match prev_op with
          | Some prev -> (match op_n_value prev with Some n -> n | None -> 20)
          | None -> 20
        in
        (acc + n, Some op)
      | _ -> (acc, Some op)
    ) (0, None) ops in
    count
  with _ -> 0

let last_push_data (ops : Script.opcode list) : Cstruct.t option =
  List.fold_left (fun acc op -> match op with Script.OP_PUSHDATA (_, data) -> Some data | _ -> acc) None ops

let count_p2sh_sigops (script_sig : Cstruct.t) : int =
  try
    let ops = Script.parse_script script_sig in
    match last_push_data ops with
    | Some redeem_script -> count_script_sigops redeem_script
    | None -> 0
  with _ -> 0

(* Count total legacy sigops cost for a transaction (legacy sigops * 4 for witness scale) *)
let count_tx_sigops_cost (tx : Types.transaction) : int =
  let input_sigops = List.fold_left (fun acc inp ->
    acc + count_script_sigops inp.Types.script_sig
  ) 0 tx.inputs in
  let output_sigops = List.fold_left (fun acc out ->
    acc + count_script_sigops out.Types.script_pubkey
  ) 0 tx.outputs in
  let legacy_cost = (input_sigops + output_sigops) * 4 in
  (* P2SH redeem script sigops, also at witness scale *)
  let p2sh_cost = List.fold_left (fun acc (inp : Types.tx_in) ->
    acc + count_p2sh_sigops inp.script_sig * 4
  ) 0 tx.inputs in
  (* P2SH-wrapped witness sigops at 1x weight *)
  let witness_cost =
    if tx.witnesses = [] then 0
    else
      List.fold_left (fun acc wit ->
        let n = List.length wit.Types.items in
        if n >= 2 then begin
          let last_item = List.nth wit.items (n - 1) in
          let last_len = Cstruct.length last_item in
          if last_len = 20 then acc + 1  (* P2SH-P2WPKH: 1 sigop *)
          else if last_len > 1 then acc + count_script_sigops last_item  (* P2SH-P2WSH witness script *)
          else acc
        end else acc
      ) 0 tx.witnesses
  in
  legacy_cost + p2sh_cost + witness_cost

(* Gap 2: Check P2WSH witness policy limits *)
let check_p2wsh_witness_limits (tx : Types.transaction) : (unit, string) result =
  let error = ref None in
  List.iteri (fun i witness ->
    if !error = None then begin
      let items = witness.Types.items in
      let n = List.length items in
      if n >= 2 then begin
        (* Last item is potentially the witness script *)
        let last_item = List.nth items (n - 1) in
        let last_len = Cstruct.length last_item in
        if last_len > 1 then begin
          (* Heuristic: this looks like a P2WSH input *)
          (* Check witness script size *)
          if last_len > Consensus.max_standard_p2wsh_script_size then
            error := Some (Printf.sprintf
              "P2WSH witness script too large at input %d (%d > %d)"
              i last_len Consensus.max_standard_p2wsh_script_size)
          else begin
            (* Check number of stack items excluding the script *)
            let stack_item_count = n - 1 in
            if stack_item_count > Consensus.max_standard_p2wsh_stack_items then
              error := Some (Printf.sprintf
                "Too many P2WSH witness stack items at input %d (%d > %d)"
                i stack_item_count Consensus.max_standard_p2wsh_stack_items)
            else begin
              (* Check each non-script witness item size *)
              let bad_item = ref None in
              List.iteri (fun j item ->
                if !bad_item = None && j < n - 1 then begin
                  let item_len = Cstruct.length item in
                  if item_len > Consensus.max_standard_p2wsh_stack_item_size then
                    bad_item := Some (Printf.sprintf
                      "P2WSH witness stack item too large at input %d, item %d (%d > %d)"
                      i j item_len Consensus.max_standard_p2wsh_stack_item_size)
                end
              ) items;
              match !bad_item with
              | Some e -> error := Some e
              | None -> ()
            end
          end
        end
      end
    end
  ) tx.witnesses;
  match !error with
  | Some e -> Error e
  | None -> Ok ()

(* IsWitnessStandard — per-input witness policy check.
   Reference: Bitcoin Core policy/policy.cpp:265-352.

   Called after IsStandardTx when the transaction has any witness data.
   Iterates over every input.  Skips inputs whose witness is null (empty items).

   The six gates (in Core order):
     Gate 1 — P2A prevout + non-empty witness → "bad-witness-nonstandard"
     Gate 2 — P2SH prevout: extract redeemScript from scriptSig (casually, no
               hash check).  Fail/empty scriptSig → reject.
     Gate 3 — non-witness prevScript + non-empty witness → reject
     Gate 4 — P2WSH v0 32B:  script ≤ 3600;  stack items (excl. script) ≤ 100;
               each item ≤ 80 bytes
     Gate 5 — P2TR v1 32B (not P2SH-wrapped):
               annex (stack.back[0] == 0x50 when ≥2 items) → reject;
               tapscript path (control_block[0] & 0xfe == 0xc0): each item ≤ 80;
               0-item stack → reject (already invalid by consensus)
     Gate 6 — coinbase: exempt (return Ok immediately)

   The function takes a UTXO lookup callback so it can be called from
   add_transaction (which has the full mempool UTXO set) and from tests
   (which pass a simple closure). *)
let is_witness_standard
    ~(lookup : Types.outpoint -> Cstruct.t option)
    (tx : Types.transaction)
    : (unit, string) result =
  (* Gate 6: coinbases are exempt — same as Core's first check. *)
  let first_input = List.hd tx.inputs in
  if Cstruct.equal first_input.Types.previous_output.txid Types.zero_hash then
    Ok ()
  else begin
    let error = ref None in
    List.iteri (fun i inp ->
      if !error = None then begin
        let witness =
          if i < List.length tx.witnesses then List.nth tx.witnesses i
          else { Types.items = [] }
        in
        (* Skip inputs with null (empty) witness — Core does the same. *)
        if witness.Types.items <> [] then begin
          match lookup inp.Types.previous_output with
          | None ->
            (* No prevout info — cannot check; skip this input conservatively.
               The script-verification pass will catch missing UTXOs. *)
            ()
          | Some prev_script ->
            (* Gate 1: P2A + non-empty witness → reject. *)
            if Script.is_p2a prev_script then
              error := Some "bad-witness-nonstandard: P2A input with non-empty witness"
            else begin
              (* Gate 2: if prevout is P2SH, extract redeemScript from scriptSig.
                 Core: EvalScript(stack, scriptSig, SCRIPT_VERIFY_NONE, ...) then
                 prevScript = stack.back().  We simulate by walking push opcodes. *)
              let p2sh = match Script.classify_script prev_script with
                | Script.P2SH_script _ -> true
                | _ -> false
              in
              let effective_script =
                if p2sh then begin
                  (* Walk scriptSig push ops to get last pushed item.
                     Any failure (parse error, empty result) → reject. *)
                  match (try
                    let ops = Script.parse_script inp.Types.script_sig in
                    (* Core's EvalScript in SCRIPT_VERIFY_NONE mode:
                       push each item onto the stack without checking anything. *)
                    let stack = List.filter_map (fun op ->
                      match op with
                      | Script.OP_0 -> Some Cstruct.empty
                      | Script.OP_PUSHDATA (_, data) -> Some data
                      | Script.OP_1NEGATE ->
                        let cs = Cstruct.create 1 in
                        Cstruct.set_uint8 cs 0 0x81; Some cs
                      | Script.OP_1  -> let cs = Cstruct.create 1 in Cstruct.set_uint8 cs 0 1; Some cs
                      | Script.OP_2  -> let cs = Cstruct.create 1 in Cstruct.set_uint8 cs 0 2; Some cs
                      | Script.OP_3  -> let cs = Cstruct.create 1 in Cstruct.set_uint8 cs 0 3; Some cs
                      | Script.OP_4  -> let cs = Cstruct.create 1 in Cstruct.set_uint8 cs 0 4; Some cs
                      | Script.OP_5  -> let cs = Cstruct.create 1 in Cstruct.set_uint8 cs 0 5; Some cs
                      | Script.OP_6  -> let cs = Cstruct.create 1 in Cstruct.set_uint8 cs 0 6; Some cs
                      | Script.OP_7  -> let cs = Cstruct.create 1 in Cstruct.set_uint8 cs 0 7; Some cs
                      | Script.OP_8  -> let cs = Cstruct.create 1 in Cstruct.set_uint8 cs 0 8; Some cs
                      | Script.OP_9  -> let cs = Cstruct.create 1 in Cstruct.set_uint8 cs 0 9; Some cs
                      | Script.OP_10 -> let cs = Cstruct.create 1 in Cstruct.set_uint8 cs 0 10; Some cs
                      | Script.OP_11 -> let cs = Cstruct.create 1 in Cstruct.set_uint8 cs 0 11; Some cs
                      | Script.OP_12 -> let cs = Cstruct.create 1 in Cstruct.set_uint8 cs 0 12; Some cs
                      | Script.OP_13 -> let cs = Cstruct.create 1 in Cstruct.set_uint8 cs 0 13; Some cs
                      | Script.OP_14 -> let cs = Cstruct.create 1 in Cstruct.set_uint8 cs 0 14; Some cs
                      | Script.OP_15 -> let cs = Cstruct.create 1 in Cstruct.set_uint8 cs 0 15; Some cs
                      | Script.OP_16 -> let cs = Cstruct.create 1 in Cstruct.set_uint8 cs 0 16; Some cs
                      | _ -> None  (* non-push opcode: EvalScript returns false → reject *)
                    ) ops in
                    (* If any non-push opcode was encountered, filter_map skips it
                       but doesn't signal failure.  Core would return false from
                       EvalScript.  We detect this by checking parse succeeded and
                       all ops produced Some. *)
                    let all_push = List.for_all (fun op ->
                      match op with
                      | Script.OP_0 | Script.OP_PUSHDATA _ | Script.OP_1NEGATE
                      | Script.OP_1  | Script.OP_2  | Script.OP_3  | Script.OP_4
                      | Script.OP_5  | Script.OP_6  | Script.OP_7  | Script.OP_8
                      | Script.OP_9  | Script.OP_10 | Script.OP_11 | Script.OP_12
                      | Script.OP_13 | Script.OP_14 | Script.OP_15 | Script.OP_16 -> true
                      | _ -> false
                    ) ops in
                    if not all_push then Error "non-push in scriptSig"
                    else if stack = [] then Error "empty P2SH scriptSig stack"
                    else Ok (List.nth stack (List.length stack - 1))
                  with exn -> Error (Printexc.to_string exn)) with
                  | Error msg ->
                    error := Some (Printf.sprintf
                      "bad-witness-nonstandard: P2SH scriptSig eval failed at input %d: %s" i msg);
                    None
                  | Ok redeem_script -> Some redeem_script
                end else
                  Some prev_script
              in
              match effective_script with
              | None -> ()  (* error already set *)
              | Some script ->
                (* Gate 3: non-witness program + non-empty witness → reject. *)
                (match Script.get_witness_program script with
                | None ->
                  error := Some (Printf.sprintf
                    "bad-witness-nonstandard: non-witness script with witness at input %d" i)
                | Some (version, program) ->
                  (* Gate 4: P2WSH v0 (32-byte program) *)
                  if version = 0 && Cstruct.length program = 32 then begin
                    let items = witness.Types.items in
                    let n = List.length items in
                    if n = 0 then
                      (* Empty witness for P2WSH is an error but caught by script
                         execution.  Not a policy reject per Core — skip. *)
                      ()
                    else begin
                      let witness_script = List.nth items (n - 1) in
                      let script_size = Cstruct.length witness_script in
                      if script_size > Consensus.max_standard_p2wsh_script_size then
                        error := Some (Printf.sprintf
                          "bad-witness-nonstandard: P2WSH witness script too large at input %d \
                           (%d > %d)" i script_size Consensus.max_standard_p2wsh_script_size)
                      else begin
                        let stack_items = n - 1 in  (* exclude the witness script *)
                        if stack_items > Consensus.max_standard_p2wsh_stack_items then
                          error := Some (Printf.sprintf
                            "bad-witness-nonstandard: too many P2WSH stack items at input %d \
                             (%d > %d)" i stack_items Consensus.max_standard_p2wsh_stack_items)
                        else begin
                          let bad = ref None in
                          List.iteri (fun j item ->
                            if !bad = None && j < n - 1 then begin
                              let item_len = Cstruct.length item in
                              if item_len > Consensus.max_standard_p2wsh_stack_item_size then
                                bad := Some (Printf.sprintf
                                  "bad-witness-nonstandard: P2WSH stack item too large at \
                                   input %d item %d (%d > %d)"
                                  i j item_len Consensus.max_standard_p2wsh_stack_item_size)
                            end
                          ) items;
                          match !bad with
                          | Some e -> error := Some e
                          | None -> ()
                        end
                      end
                    end
                  end
                  (* Gate 5: P2TR v1 (32-byte program, not P2SH-wrapped) *)
                  else if version = 1 && Cstruct.length program = 32 && not p2sh then begin
                    let items = witness.Types.items in
                    let n = List.length items in
                    (* Strip optional annex from the back. *)
                    let (has_annex, n_eff) =
                      if n >= 2 then begin
                        let last = List.nth items (n - 1) in
                        if Cstruct.length last > 0 &&
                           Cstruct.get_uint8 last 0 = Consensus.annex_tag then
                          (* Annex is non-standard as long as no semantics defined. *)
                          (true, n - 1)
                        else
                          (false, n)
                      end else
                        (false, n)
                    in
                    if has_annex then
                      error := Some (Printf.sprintf
                        "bad-witness-nonstandard: taproot annex present at input %d" i)
                    else if n_eff >= 2 then begin
                      (* Script-path spend: stack | script | control_block *)
                      let control_block = List.nth items (n_eff - 1) in
                      if Cstruct.length control_block = 0 then
                        error := Some (Printf.sprintf
                          "bad-witness-nonstandard: empty control block at input %d" i)
                      else begin
                        let leaf_version =
                          Cstruct.get_uint8 control_block 0 land Consensus.taproot_leaf_mask in
                        if leaf_version = Consensus.taproot_leaf_tapscript then begin
                          (* BIP-342 tapscript: check stack items (excl. script + ctrl block) *)
                          let stack_top = n_eff - 2 in  (* items[0..stack_top-1] *)
                          let bad = ref None in
                          List.iteri (fun j item ->
                            if !bad = None && j < stack_top then begin
                              let item_len = Cstruct.length item in
                              if item_len > Consensus.max_standard_tapscript_stack_item_size then
                                bad := Some (Printf.sprintf
                                  "bad-witness-nonstandard: tapscript stack item too large at \
                                   input %d item %d (%d > %d)"
                                  i j item_len Consensus.max_standard_tapscript_stack_item_size)
                            end
                          ) items;
                          match !bad with
                          | Some e -> error := Some e
                          | None -> ()
                        end
                        (* Other leaf versions: no additional policy rules. *)
                      end
                    end else if n_eff = 1 then
                      (* Key-path spend: one stack element.  No extra policy. *)
                      ()
                    else
                      (* Zero elements: invalid by consensus but reject as non-standard. *)
                      error := Some (Printf.sprintf
                        "bad-witness-nonstandard: empty taproot witness stack at input %d" i)
                  end)
            end
        end
      end
    ) tx.inputs;
    match !error with
    | Some e -> Error e
    | None -> Ok ()
  end

(* Policy constants matching Bitcoin Core policy/policy.h *)
let max_standard_scriptsig_size = 1650  (* MAX_STANDARD_SCRIPTSIG_SIZE *)
let min_standard_tx_nonwitness_size = 65 (* MIN_STANDARD_TX_NONWITNESS_SIZE — CVE-2017-12842 *)
(* MAX_OP_RETURN_RELAY = MAX_STANDARD_TX_WEIGHT / WITNESS_SCALE_FACTOR = 400000/4 = 100000 *)
let max_datacarrier_bytes = 100_000
(* MAX_DUST_OUTPUTS_PER_TX = 1 (ephemeral dust: exactly 1 dust output allowed) *)
let max_dust_outputs_per_tx = 1

(* Compute the non-witness serialized size of a transaction (base size).
   Used for MIN_STANDARD_TX_NONWITNESS_SIZE check (CVE-2017-12842). *)
let compute_tx_nonwitness_size (tx : Types.transaction) : int =
  let w = Serialize.writer_create () in
  Serialize.serialize_transaction_no_witness w tx;
  Cstruct.length (Serialize.writer_to_cstruct w)

(* Check if a transaction passes IsStandard policy.
   Reference: Bitcoin Core IsStandardTx() in policy/policy.cpp.

   Gate order follows Core exactly:
   1. version ∈ [1, TX_MAX_STANDARD_VERSION=3]
   2. weight ≤ MAX_STANDARD_TX_WEIGHT (400,000 WU)
   3. non-witness size ≥ MIN_STANDARD_TX_NONWITNESS_SIZE (65 bytes) — CVE-2017-12842
   4. per-input: scriptSig ≤ MAX_STANDARD_SCRIPTSIG_SIZE (1650) + IsPushOnly
   5. per-output: standard scriptPubKey; cumulative OP_RETURN ≤ 100,000 bytes
   6. dust: at most MAX_DUST_OUTPUTS_PER_TX (1) dust outputs
   7. P2WSH witness policy limits (check_p2wsh_witness_limits) *)
let is_standard_tx (min_relay_fee : int64) (tx : Types.transaction) : (unit, string) result =
  (* Gate 1: Version must be in [1, TX_MAX_STANDARD_VERSION=3].
     v3/TRUC transactions (BIP-431) are standard. *)
  let version = Int32.to_int tx.version in
  if version < 1 || version > 3 then
    Error "Non-standard transaction version"
  else begin
    (* Gate 2: Weight must not exceed MAX_STANDARD_TX_WEIGHT (400,000 WU) *)
    let weight = Validation.compute_tx_weight tx in
    if weight > max_standard_tx_weight then
      Error "Transaction weight exceeds standard limit"
    else begin
      (* Gate 3: Non-witness size must be >= MIN_STANDARD_TX_NONWITNESS_SIZE (65 bytes).
         Prevents the CVE-2017-12842 merkle-tree attack via 64-byte transactions. *)
      let nonwitness_size = compute_tx_nonwitness_size tx in
      if nonwitness_size < min_standard_tx_nonwitness_size then
        Error "Transaction non-witness size too small (CVE-2017-12842)"
      else begin
        (* Gate 4: Per-input scriptSig checks.
           - scriptSig must not exceed 1650 bytes (MAX_STANDARD_SCRIPTSIG_SIZE)
           - scriptSig must be push-only *)
        let bad_input = ref None in
        List.iteri (fun i inp ->
          if !bad_input = None then begin
            let sig_len = Cstruct.length inp.Types.script_sig in
            if sig_len > max_standard_scriptsig_size then
              bad_input := Some (Printf.sprintf
                "scriptsig-size: scriptSig at input %d too large (%d > %d)"
                i sig_len max_standard_scriptsig_size)
            else if not (is_push_only_script_sig inp.Types.script_sig) then
              bad_input := Some (Printf.sprintf
                "scriptsig-not-pushonly: non-push-only scriptSig at input %d" i)
          end
        ) tx.inputs;

        match !bad_input with
        | Some e -> Error e
        | None ->
          (* Gate 5: Per-output scriptPubKey standardness + cumulative datacarrier budget.
             OP_RETURN outputs consume from a shared 100,000-byte budget (datacarrier_bytes_left).
             Each OP_RETURN scriptPubKey's total byte length (including the 0x6a prefix) is
             charged, matching Core's `size = txout.scriptPubKey.size()` in IsStandardTx. *)
          let datacarrier_bytes_left = ref max_datacarrier_bytes in
          let bad_output = ref None in
          List.iteri (fun i out ->
            if !bad_output = None then begin
              if not (is_standard_output out.Types.script_pubkey) then
                bad_output := Some (Printf.sprintf
                  "scriptpubkey: non-standard output script at index %d" i)
              else begin
                match Script.classify_script out.Types.script_pubkey with
                | Script.OP_RETURN_data _ ->
                  let op_return_size = Cstruct.length out.Types.script_pubkey in
                  if op_return_size > !datacarrier_bytes_left then
                    bad_output := Some (Printf.sprintf
                      "datacarrier: OP_RETURN output at index %d exceeds datacarrier budget \
                       (%d bytes, %d remaining)"
                      i op_return_size !datacarrier_bytes_left)
                  else
                    datacarrier_bytes_left := !datacarrier_bytes_left - op_return_size
                | _ -> ()
              end
            end
          ) tx.outputs;

          match !bad_output with
          | Some e -> Error e
          | None ->
            (* Gate 6: Dust check.
               Core allows at most MAX_DUST_OUTPUTS_PER_TX (1) dust outputs (ephemeral dust).
               Count dust outputs and reject if more than 1. *)
            let dust_count = List.fold_left (fun acc out ->
              if is_dust min_relay_fee out then acc + 1 else acc
            ) 0 tx.outputs in
            if dust_count > max_dust_outputs_per_tx then
              Error (Printf.sprintf
                "dust: transaction has %d dust outputs (max %d)"
                dust_count max_dust_outputs_per_tx)
            else begin
              (* Gate 7: P2WSH witness policy limits (stack item count/size).
                 This is a heuristic pre-check that does not require prevout lookup.
                 The full per-prevout check (including P2TR, annex, P2SH unwrapping)
                 is performed by is_witness_standard, called from add_transaction. *)
              check_p2wsh_witness_limits tx
            end
      end
    end
  end

(* ============================================================================
   Ancestor/Descendant Limit Checks (Task 3 + Gap 6: size limits)

   Uses BFS to compute ancestor set. Cached descendant counts in mempool_entry
   allow O(1) limit checks after initial ancestor walk.
   ============================================================================ *)

(* Check if adding a transaction would violate ancestor/descendant limits.
   Uses BFS to walk parent links and compute ancestor set. *)
let check_ancestor_descendant_limits (mp : mempool) (depends : Types.hash256 list)
    (_txid : Types.hash256) (new_tx_weight : int) : (unit, string) result =
  let new_tx_vsize = (new_tx_weight + 3) / 4 in

  (* BFS to compute ancestor set *)
  let all_ancestors = Hashtbl.create 16 in
  let queue = Queue.create () in
  List.iter (fun parent_txid ->
    let parent_key = Cstruct.to_string parent_txid in
    if not (Hashtbl.mem all_ancestors parent_key) then begin
      Hashtbl.replace all_ancestors parent_key ();
      Queue.push parent_key queue
    end
  ) depends;
  let ancestor_size_sum = ref 0 in
  while not (Queue.is_empty queue) do
    let key = Queue.pop queue in
    match Hashtbl.find_opt mp.entries key with
    | None -> ()
    | Some entry ->
      ancestor_size_sum := !ancestor_size_sum + (entry.weight + 3) / 4;
      List.iter (fun gp_txid ->
        let gp_key = Cstruct.to_string gp_txid in
        if not (Hashtbl.mem all_ancestors gp_key) then begin
          Hashtbl.replace all_ancestors gp_key ();
          Queue.push gp_key queue
        end
      ) entry.depends_on
  done;

  let ancestor_count = Hashtbl.length all_ancestors + 1 in  (* +1 for self *)
  if ancestor_count > max_ancestor_count then
    Error (Printf.sprintf "Too many ancestors (%d > %d)"
      ancestor_count max_ancestor_count)
  else begin
    (* Check ancestor cumulative size (in vbytes) *)
    let total_ancestor_size = !ancestor_size_sum + new_tx_vsize in
    if total_ancestor_size > max_ancestor_size then
      Error (Printf.sprintf "Ancestor size limit exceeded (%d > %d)"
        total_ancestor_size max_ancestor_size)
    else begin
      (* Check descendant limits for each ancestor using cached counts.
         Adding this tx increases the descendant count of all ancestors by 1. *)
      let too_many_desc = ref false in
      let desc_size_exceeded = ref false in
      Hashtbl.iter (fun ancestor_key () ->
        if not !too_many_desc && not !desc_size_exceeded then begin
          match Hashtbl.find_opt mp.entries ancestor_key with
          | None -> ()
          | Some ancestor_entry ->
            (* Use cached descendant_count: current + 1 for new tx *)
            if ancestor_entry.descendant_count + 1 > max_descendant_count then
              too_many_desc := true;
            (* Use cached descendant_size: current + new tx vsize *)
            if ancestor_entry.descendant_size + new_tx_vsize > max_descendant_size then
              desc_size_exceeded := true
        end
      ) all_ancestors;
      if !too_many_desc then
        Error (Printf.sprintf "Adding transaction would exceed descendant limit (%d)"
          max_descendant_count)
      else if !desc_size_exceeded then
        Error (Printf.sprintf "Descendant size limit exceeded (%d)"
          max_descendant_size)
      else
        Ok ()
    end
  end

(* ============================================================================
   TRUC/v3 Transaction Policy (BIP-431)

   Reference: Bitcoin Core /src/policy/truc_policy.cpp

   TRUC (Topologically Restricted Until Confirmation) enforces a strict
   1-parent-1-child topology for v3 transactions:
   - A v3 tx can have at most 1 unconfirmed parent
   - A v3 tx can have at most 1 unconfirmed child
   - v3 tx max size: 10,000 vbytes
   - v3 child (with unconfirmed parent) max size: 1,000 vbytes
   - v3 transactions signal replaceability unconditionally
   - Non-v3 cannot spend unconfirmed v3 outputs (and vice versa)
   ============================================================================ *)

(* Check if a transaction is a v3/TRUC transaction *)
let is_truc_tx (tx : Types.transaction) : bool =
  tx.Types.version = truc_version

(* Check TRUC/v3 policy constraints for a transaction *)
let check_truc_policy (mp : mempool) (tx : Types.transaction)
    (depends : Types.hash256 list) (weight : int) : (unit, string) result =
  let is_v3 = is_truc_tx tx in
  let vsize = (weight + 3) / 4 in

  if is_v3 then begin
    (* Rule 1: v3 transaction size limit (10,000 vbytes) *)
    if vsize > truc_max_vsize then
      Error (Printf.sprintf
        "TRUC/v3 transaction too large: %d vbytes > %d limit"
        vsize truc_max_vsize)
    else begin
      let has_unconfirmed_parents = depends <> [] in

      (* Check if any parent is v3 *)
      let v3_parents = List.filter (fun parent_txid ->
        match Hashtbl.find_opt mp.entries (Cstruct.to_string parent_txid) with
        | None -> false
        | Some parent_entry -> is_truc_tx parent_entry.tx
      ) depends in

      (* Check if any parent is non-v3 *)
      let non_v3_parents = List.filter (fun parent_txid ->
        match Hashtbl.find_opt mp.entries (Cstruct.to_string parent_txid) with
        | None -> false  (* confirmed UTXOs are fine *)
        | Some parent_entry -> not (is_truc_tx parent_entry.tx)
      ) depends in

      (* Rule: v3 cannot spend from unconfirmed non-v3 *)
      if non_v3_parents <> [] then
        Error "TRUC/v3 transaction cannot spend from unconfirmed non-v3 transaction"

      (* Rules for v3 child transactions (with unconfirmed v3 parents) *)
      else if has_unconfirmed_parents && v3_parents <> [] then begin
        (* Rule 2: v3 child size limit (1,000 vbytes) *)
        if vsize > truc_child_max_vsize then
          Error (Printf.sprintf
            "TRUC/v3 child transaction too large: %d vbytes > %d limit"
            vsize truc_child_max_vsize)
        else begin
          (* Rule 3: v3 child can only have 1 unconfirmed parent *)
          let ancestor_count = List.length depends + 1 in  (* parents + self *)
          if ancestor_count > truc_ancestor_limit then
            Error (Printf.sprintf
              "TRUC/v3 transaction exceeds ancestor limit (%d > %d)"
              ancestor_count truc_ancestor_limit)
          else begin
            (* Check for grandparents: if parent has parents, we exceed limit *)
            let has_grandparents = List.exists (fun parent_txid ->
              match Hashtbl.find_opt mp.entries (Cstruct.to_string parent_txid) with
              | None -> false
              | Some parent_entry -> parent_entry.depends_on <> []
            ) depends in
            if has_grandparents then
              Error "TRUC/v3 transaction would exceed ancestor limit (grandparents exist)"
            else begin
              (* Rule 4: v3 parent can only have 1 child *)
              let parent_has_child = List.exists (fun parent_txid ->
                match Hashtbl.find_opt mp.entries (Cstruct.to_string parent_txid) with
                | None -> false
                | Some _parent_entry ->
                  (* Check if parent already has a child in mempool *)
                  Hashtbl.fold (fun _ entry found ->
                    found || (List.exists (fun d ->
                      Cstruct.equal d parent_txid) entry.depends_on)
                  ) mp.entries false
              ) depends in
              if parent_has_child then
                Error "TRUC/v3 parent already has an unconfirmed child (descendant limit)"
              else
                Ok ()
            end
          end
        end
      end else
        Ok ()
    end
  end else begin
    (* Non-v3 transaction: reject if it spends unconfirmed v3 outputs *)
    let spends_v3 = List.exists (fun parent_txid ->
      match Hashtbl.find_opt mp.entries (Cstruct.to_string parent_txid) with
      | None -> false
      | Some parent_entry -> is_truc_tx parent_entry.tx
    ) depends in
    if spends_v3 then
      Error "Non-v3 transaction cannot spend unconfirmed v3 outputs"
    else
      Ok ()
  end

(* Check if a v3 transaction signals replaceability (always true for v3) *)
let truc_signals_rbf (tx : Types.transaction) : bool =
  is_truc_tx tx

(* ============================================================================
   Conflict Detection
   ============================================================================ *)

(* Find all conflicting transactions using the spending index for O(1) lookups *)
let find_all_conflicts (mp : mempool) (tx : Types.transaction)
    : mempool_entry list =
  let conflicts = Hashtbl.create 4 in
  List.iter (fun inp ->
    let key = (Cstruct.to_string inp.Types.previous_output.txid,
               inp.Types.previous_output.vout) in
    match Hashtbl.find_opt mp.map_next_tx key with
    | Some spending_txid_key ->
      (match Hashtbl.find_opt mp.entries spending_txid_key with
       | Some entry -> Hashtbl.replace conflicts spending_txid_key entry
       | None -> ())
    | None -> ()
  ) tx.inputs;
  Hashtbl.fold (fun _ v acc -> v :: acc) conflicts []

(* Check if a transaction conflicts with one in the mempool *)
let check_conflict (mp : mempool) (tx : Types.transaction)
    : Types.hash256 option =
  let conflict = ref None in
  List.iter (fun inp ->
    if !conflict = None then begin
      let key = (Cstruct.to_string inp.Types.previous_output.txid,
                 inp.Types.previous_output.vout) in
      match Hashtbl.find_opt mp.map_next_tx key with
      | Some spending_txid_key ->
        (match Hashtbl.find_opt mp.entries spending_txid_key with
         | Some entry -> conflict := Some entry.txid
         | None -> ())
      | None -> ()
    end
  ) tx.inputs;
  !conflict

(* ============================================================================
   Script Verification Helper
   ============================================================================ *)

(* Verify all input scripts for a transaction *)
let verify_tx_scripts (mp : mempool) (tx : Types.transaction)
    : (unit, string) result =
  (* Mempool uses standard (policy) flags — stricter than consensus block flags.
     This rejects non-standard txs at acceptance time while still accepting all
     consensus-valid txs during block validation. *)
  let flags = Consensus.get_standard_policy_flags (mp.current_height + 1) mp.network in
  let error = ref None in

  (* Build prevouts list for Taproot sighash *)
  let prevouts = List.map (fun inp ->
    let prev = inp.Types.previous_output in
    match lookup_utxo mp prev with
    | Some entry -> (entry.Utxo.value, entry.Utxo.script_pubkey)
    | None -> (0L, Cstruct.empty)
  ) tx.inputs in

  List.iteri (fun i inp ->
    if !error = None then begin
      let prev = inp.Types.previous_output in
      match lookup_utxo mp prev with
      | None ->
        error := Some (Printf.sprintf "Missing input for script verification: %d" i)
      | Some utxo_entry ->
        let witness =
          if i < List.length tx.witnesses then
            List.nth tx.witnesses i
          else
            { Types.items = [] }
        in
        (* P2A witness stuffing prevention (policy): P2A spends must have empty witness *)
        if Script.is_p2a utxo_entry.Utxo.script_pubkey &&
           witness.Types.items <> [] then
          error := Some (Printf.sprintf
            "P2A input %d has non-empty witness (witness stuffing)" i)
        else
          match Script.verify_script
                  ~tx ~input_index:i
                  ~script_pubkey:utxo_entry.Utxo.script_pubkey
                  ~script_sig:inp.Types.script_sig
                  ~witness
                  ~amount:utxo_entry.Utxo.value
                  ~flags ~prevouts () with
          | Error msg ->
            error := Some (Printf.sprintf "Script verification failed for input %d: %s" i msg)
          | Ok false ->
            error := Some (Printf.sprintf "Script returned false for input %d" i)
          | Ok true -> ()
    end
  ) tx.inputs;

  match !error with
  | Some e -> Error e
  | None -> Ok ()

(* ============================================================================
   Transaction Addition
   ============================================================================ *)

(* Validate and add a transaction to the mempool.
   When ~dry_run:true, all validation is performed but the transaction
   is not actually inserted into the mempool. *)
let add_transaction ?(dry_run=false) ?(bypass_fee_check=false) (mp : mempool) (tx : Types.transaction)
    : (mempool_entry, string) result =
  let txid = Crypto.compute_txid tx in
  let txid_key = Cstruct.to_string txid in

  (* Check for duplicate *)
  if Hashtbl.mem mp.entries txid_key then
    Error "Transaction already in mempool"

  (* Check for mempool input conflicts (double-spends) *)
  else
    let conflict = if not dry_run then check_conflict mp tx else None in
    if conflict <> None then
      let conflict_txid = Option.get conflict in
      Error (Printf.sprintf "txn-mempool-conflict: spends same input as %s"
        (Types.hash256_to_hex_display conflict_txid))

  (* Basic structure validation *)
  else match Validation.check_transaction tx with
  | Error e -> Error (Validation.tx_error_to_string e)
  | Ok () ->
    (* Must not be a coinbase *)
    let first_input = List.hd tx.inputs in
    if Cstruct.equal first_input.previous_output.txid Types.zero_hash then
      Error "Coinbase in mempool"

    (* Task 7: IsStandard checks (skipped when require_standard=false) *)
    else match (if mp.require_standard then is_standard_tx mp.min_relay_fee tx else Ok ()) with
    | Error e -> Error e
    | Ok () ->

    (* IsWitnessStandard checks (skipped when require_standard=false).
       Core: validation.cpp:904 — guarded by tx.HasWitness() + require_standard.
       We check witnesses <> [] as camlcoin's HasWitness equivalent.
       The UTXO lookup is threaded in via a closure over mp. *)
    let has_witness = List.exists (fun w -> w.Types.items <> []) tx.witnesses in
    (match (if has_witness && mp.require_standard then
      is_witness_standard
        ~lookup:(fun op ->
          match lookup_utxo mp op with
          | Some e -> Some e.Utxo.script_pubkey
          | None -> None)
        tx
    else Ok ()) with
    | Error e -> Error e
    | Ok () ->

    (* Phase 1C: Per-tx sigops cost check *)
    let sigops_cost = count_tx_sigops_cost tx in
    if sigops_cost > 80_000 then
      Error "Transaction exceeds max standard sigops cost"

    (* Task 5: Locktime enforcement *)
    else
    if not (Validation.is_tx_final tx
              ~block_height:(mp.current_height + 1)
              ~block_time:mp.current_median_time) then
      Error "Transaction is not final (locktime not reached)"

    else begin
      (* Validate inputs *)
      let input_sum = ref 0L in
      let depends = ref [] in
      let error = ref None in
      let utxo_heights = Array.make (List.length tx.inputs) 0 in
      let utxo_mtps = Array.make (List.length tx.inputs) 0l in

      List.iteri (fun i inp ->
        if !error = None then begin
          let prev = inp.Types.previous_output in
          match lookup_utxo mp prev with
          | None ->
            error := Some (Printf.sprintf
              "Missing input: %s:%ld"
              (Types.hash256_to_hex_display prev.txid)
              prev.vout)
          | Some entry ->
            if entry.is_coinbase &&
               mp.current_height - entry.height < Consensus.coinbase_maturity then
              error := Some "Spending immature coinbase"
            else begin
              input_sum := Int64.add !input_sum entry.value;
              utxo_heights.(i) <- entry.height;
              utxo_mtps.(i) <- mp.current_median_time;
              (* Track mempool dependencies *)
              if Hashtbl.mem mp.entries (Cstruct.to_string prev.txid) then
                depends := prev.txid :: !depends
            end
        end
      ) tx.inputs;

      match !error with
      | Some e -> Error e
      | None ->
        (* Task 5: BIP68 sequence lock enforcement *)
        let flags = Consensus.get_block_script_flags (mp.current_height + 1) mp.network in
        if not (Validation.check_sequence_locks tx
                  ~block_height:(mp.current_height + 1)
                  ~median_time:mp.current_median_time
                  ~utxo_heights ~utxo_mtps ~flags ()) then
          Error "Transaction sequence locks not satisfied (BIP68)"
        else begin
          let output_sum = List.fold_left
            (fun acc out -> Int64.add acc out.Types.value)
            0L tx.outputs in

          if output_sum > !input_sum then
            Error "Output exceeds input"
          else begin
            let fee = Int64.sub !input_sum output_sum in
            let weight = Validation.compute_tx_weight tx in
            let fee_rate =
              Int64.to_float fee /. float_of_int weight in

            (* Check minimum relay fee (uses dynamic minimum when mempool is full) *)
            let eff_min = effective_min_fee mp in
            let min_fee = Int64.of_float (
              Int64.to_float eff_min *.
              float_of_int weight /. 4000.0) in

            if fee < min_fee && not bypass_fee_check then
              Error "Fee below minimum relay fee"

            (* Cluster size limit check (replaces ancestor/descendant limits for cluster mempool) *)
            else match check_cluster_size_limit mp !depends txid with
            | Error e -> Error e
            | Ok () ->

            (* Task 3 + Gap 6: Ancestor/descendant limits (count + size) - kept for backward compat *)
            match check_ancestor_descendant_limits mp !depends txid weight with
            | Error e -> Error e
            | Ok () ->

            (* TRUC/v3 policy (BIP-431) *)
            match check_truc_policy mp tx !depends weight with
            | Error e -> Error e
            | Ok () ->

            (* Task 1: Script verification at acceptance (skipped when verify_scripts=false) *)
            match (if mp.verify_scripts then verify_tx_scripts mp tx else Ok ()) with
            | Error e -> Error e
            | Ok () ->

            let wtxid = Crypto.compute_wtxid tx in
            let vsize = (weight + 3) / 4 in

            (* Compute initial ancestor stats using BFS *)
            let (anc_count, anc_size) =
              if !depends = [] then (1, vsize)
              else begin
                (* BFS to find all ancestors *)
                let visited = Hashtbl.create 16 in
                let queue = Queue.create () in
                List.iter (fun parent_txid ->
                  let parent_key = Cstruct.to_string parent_txid in
                  if not (Hashtbl.mem visited parent_key) then begin
                    Hashtbl.replace visited parent_key ();
                    Queue.push parent_key queue
                  end
                ) !depends;
                let total_size = ref vsize in
                while not (Queue.is_empty queue) do
                  let key = Queue.pop queue in
                  match Hashtbl.find_opt mp.entries key with
                  | None -> ()
                  | Some parent_entry ->
                    total_size := !total_size + (parent_entry.weight + 3) / 4;
                    List.iter (fun gp_txid ->
                      let gp_key = Cstruct.to_string gp_txid in
                      if not (Hashtbl.mem visited gp_key) then begin
                        Hashtbl.replace visited gp_key ();
                        Queue.push gp_key queue
                      end
                    ) parent_entry.depends_on
                done;
                (Hashtbl.length visited + 1, !total_size)
              end
            in

            let entry = {
              tx;
              txid;
              wtxid;
              fee;
              weight;
              fee_rate;
              time_added = Unix.gettimeofday ();
              height_added = mp.current_height;
              depends_on = !depends;
              ancestor_count = anc_count;
              ancestor_size = anc_size;
              descendant_count = 1;  (* initially just self *)
              descendant_size = vsize;
            } in

            if not dry_run then begin
              Hashtbl.replace mp.entries txid_key entry;
              mp.total_weight <- mp.total_weight + weight;
              mp.total_fee <- Int64.add mp.total_fee fee;
              List.iter (fun inp ->
                let out_key = (Cstruct.to_string inp.Types.previous_output.txid,
                               inp.Types.previous_output.vout) in
                Hashtbl.replace mp.map_next_tx out_key txid_key
              ) tx.inputs;

              (* Update ancestor descendant counts - new tx is a descendant of all ancestors *)
              let visited = Hashtbl.create 16 in
              let queue = Queue.create () in
              List.iter (fun parent_txid ->
                let parent_key = Cstruct.to_string parent_txid in
                if not (Hashtbl.mem visited parent_key) then begin
                  Hashtbl.replace visited parent_key ();
                  Queue.push parent_key queue
                end
              ) !depends;
              while not (Queue.is_empty queue) do
                let key = Queue.pop queue in
                match Hashtbl.find_opt mp.entries key with
                | None -> ()
                | Some ancestor_entry ->
                  ancestor_entry.descendant_count <- ancestor_entry.descendant_count + 1;
                  ancestor_entry.descendant_size <- ancestor_entry.descendant_size + vsize;
                  List.iter (fun gp_txid ->
                    let gp_key = Cstruct.to_string gp_txid in
                    if not (Hashtbl.mem visited gp_key) then begin
                      Hashtbl.replace visited gp_key ();
                      Queue.push gp_key queue
                    end
                  ) ancestor_entry.depends_on
              done;

              (* Evict if over size limit - use cluster-based eviction *)
              if mp.total_weight > mp.max_size_bytes / 4 then
                evict_by_chunks mp;

              (* Notify ZMQ subscribers about new transaction *)
              zmq_notify_tx mp txid tx true
            end;

            Ok entry
          end
        end
    end)

(* ============================================================================
   Block Processing
   ============================================================================ *)

(* Remove confirmed transactions after a block is mined.
   Collects txids to remove before mutating the Hashtbl. *)
let remove_for_block (mp : mempool) (block : Types.block) (height : int)
    : unit =
  mp.current_height <- height;

  List.iter (fun tx ->
    let txid = Crypto.compute_txid tx in
    remove_transaction mp txid;

    (* Collect conflicting txids first, then remove *)
    List.iter (fun inp ->
      let to_remove = Hashtbl.fold (fun _k entry acc ->
        let dominated = List.exists (fun entry_inp ->
          Cstruct.equal
            entry_inp.Types.previous_output.txid
            inp.Types.previous_output.txid &&
          entry_inp.previous_output.vout = inp.previous_output.vout
        ) entry.tx.inputs in
        if dominated then entry.txid :: acc else acc
      ) mp.entries [] in
      List.iter (fun conflict_txid ->
        remove_transaction mp conflict_txid
      ) to_remove
    ) tx.inputs
  ) block.transactions

(* ============================================================================
   Block Template Construction
   ============================================================================ *)

(* Get transactions sorted by fee rate for block template *)
let get_sorted_transactions (mp : mempool) : mempool_entry list =
  let entries = Hashtbl.fold (fun _ v acc -> v :: acc) mp.entries [] in
  List.sort (fun (a : mempool_entry) (b : mempool_entry) ->
    compare b.fee_rate a.fee_rate) entries

(* Select transactions for a block template respecting dependencies *)
let select_for_block (mp : mempool) ~(max_weight : int)
    : mempool_entry list =
  let sorted = get_sorted_transactions mp in
  let selected = ref [] in
  let selected_txids = Hashtbl.create 100 in
  let current_weight = ref 0 in

  List.iter (fun entry ->
    (* Check if we have room *)
    if !current_weight + entry.weight <= max_weight then begin
      (* Check if all dependencies are satisfied *)
      let deps_ok = List.for_all (fun dep_txid ->
        Hashtbl.mem selected_txids (Cstruct.to_string dep_txid)
      ) entry.depends_on in

      if deps_ok then begin
        selected := entry :: !selected;
        Hashtbl.add selected_txids (Cstruct.to_string entry.txid) ();
        current_weight := !current_weight + entry.weight
      end
    end
  ) sorted;

  List.rev !selected

(* ============================================================================
   Mempool Info
   ============================================================================ *)

(* Get mempool statistics *)
let get_info (mp : mempool) : (int * int * int64) =
  let count = Hashtbl.length mp.entries in
  (count, mp.total_weight, mp.total_fee)

(* Get detailed mempool stats *)
type mempool_stats = {
  tx_count : int;
  total_weight : int;
  total_fee : int64;
  min_fee_rate : float;
  max_fee_rate : float;
  avg_fee_rate : float;
}

let get_stats (mp : mempool) : mempool_stats =
  let entries = Hashtbl.fold (fun _ v acc -> v :: acc) mp.entries [] in
  let count = List.length entries in

  if count = 0 then
    { tx_count = 0;
      total_weight = 0;
      total_fee = 0L;
      min_fee_rate = 0.0;
      max_fee_rate = 0.0;
      avg_fee_rate = 0.0 }
  else begin
    let fee_rates = List.map (fun (e : mempool_entry) -> e.fee_rate) entries in
    let min_fr = List.fold_left min max_float fee_rates in
    let max_fr = List.fold_left max 0.0 fee_rates in
    let sum_fr = List.fold_left (+.) 0.0 fee_rates in

    { tx_count = count;
      total_weight = mp.total_weight;
      total_fee = mp.total_fee;
      min_fee_rate = min_fr;
      max_fee_rate = max_fr;
      avg_fee_rate = sum_fr /. float_of_int count }
  end

(* ============================================================================
   Replace-by-Fee (RBF) Support
   ============================================================================ *)

(* Check if a transaction signals RBF (BIP-125 or TRUC/v3)
   v3/TRUC transactions signal replaceability unconditionally. *)
let signals_rbf (tx : Types.transaction) : bool =
  (* v3/TRUC transactions are always replaceable *)
  is_truc_tx tx ||
  (* BIP-125: sequence number < 0xFFFFFFFE signals RBF.
     Sequences are unsigned uint32; use Int64 mask to avoid signed-comparison
     gotcha: 0xFFFFFFFEl as OCaml int32 is -2l, so Int32.compare 0l (-2l) > 0
     which would incorrectly report sequence=0 as non-RBF. *)
  List.exists (fun inp ->
    let seq_u = Int64.logand (Int64.of_int32 inp.Types.sequence) 0xFFFFFFFFL in
    Int64.compare seq_u 0xFFFFFFFEL < 0
  ) tx.inputs

(* Get total fees for a transaction and all its descendants *)
let get_fees_with_descendants (mp : mempool) (entry : mempool_entry) : int64 =
  let desc = get_descendants mp entry.txid in
  let desc_fees = List.fold_left (fun acc d -> Int64.add acc d.fee) 0L desc in
  Int64.add entry.fee desc_fees

(* Attempt to replace an existing transaction with higher fee.
   Full RBF: no BIP125 signaling required (-mempoolfullrbf=1 default).

   Rules enforced:
   1. New fee > sum of all conflicting fees (including descendants)
   2. New fee_rate > conflicting fee_rate + incremental_relay_fee
   3. Max 100 transactions evicted
   4. No new unconfirmed inputs (except from conflicting txs) *)
let replace_by_fee (mp : mempool) (tx : Types.transaction)
    : (mempool_entry, string) result =
  let conflicts = find_all_conflicts mp tx in
  match conflicts with
  | [] ->
    (* No conflict, just add normally *)
    add_transaction mp tx
  | _ ->
    (* Full RBF: no BIP125 signaling check required *)
    (* Calculate new transaction fee *)
    let input_sum = ref 0L in
    let error = ref None in

    List.iter (fun inp ->
      if !error = None then begin
        let prev = inp.Types.previous_output in
        match lookup_utxo mp prev with
        | None -> error := Some "Missing input"
        | Some entry ->
          input_sum := Int64.add !input_sum entry.value
      end
    ) tx.inputs;

    match !error with
    | Some e -> Error e
    | None ->
      let output_sum = List.fold_left
        (fun acc out -> Int64.add acc out.Types.value)
        0L tx.outputs in

      if output_sum > !input_sum then
        Error "Output exceeds input"
      else begin
        let new_fee = Int64.sub !input_sum output_sum in
        let new_weight = Validation.compute_tx_weight tx in
        let new_vsize = max 1 ((new_weight + 3) / 4) in
        let new_feerate = Int64.to_float new_fee /. float_of_int new_vsize in

        (* Rule 3: Calculate total evictions first (conflicts + all descendants) *)
        let all_evicted = ref [] in
        List.iter (fun conflict_entry ->
          all_evicted := conflict_entry :: !all_evicted;
          let desc = get_descendants mp conflict_entry.txid in
          all_evicted := desc @ !all_evicted
        ) conflicts;
        let eviction_count = List.length !all_evicted in

        if eviction_count > max_rbf_evictions then
          Error (Printf.sprintf
            "RBF would evict %d transactions (max %d)"
            eviction_count max_rbf_evictions)

        else begin
          (* Rule 1: Total fee of all conflicting transactions INCLUDING descendants *)
          let total_conflict_fee = List.fold_left
            (fun acc e -> Int64.add acc (get_fees_with_descendants mp e))
            0L conflicts in

          if new_fee <= total_conflict_fee then
            Error (Printf.sprintf
              "Replacement fee %Ld not higher than total conflicting fee %Ld (including descendants)"
              new_fee total_conflict_fee)

          else begin
            (* Rule 2: Replacement must pay at least incremental_relay_fee more per kvB.
               This ensures the additional fees cover the bandwidth for relaying. *)
            let incremental_fee = Int64.of_float (
              Int64.to_float mp.min_relay_fee *.
              float_of_int new_vsize /. 1000.0) in
            let required_fee = Int64.add total_conflict_fee incremental_fee in

            if new_fee < required_fee then
              Error (Printf.sprintf
                "Replacement fee %Ld too low (need >= %Ld = conflict fee %Ld + relay fee %Ld)"
                new_fee required_fee total_conflict_fee incremental_fee)

            else begin
              (* Additional check: new feerate must be higher than each direct conflict's feerate *)
              let low_feerate_conflict = List.find_opt (fun e ->
                let conflict_vsize = max 1 ((e.weight + 3) / 4) in
                let conflict_feerate = Int64.to_float e.fee /. float_of_int conflict_vsize in
                new_feerate <= conflict_feerate
              ) conflicts in

              match low_feerate_conflict with
              | Some conflict ->
                let conflict_vsize = max 1 ((conflict.weight + 3) / 4) in
                let conflict_feerate = Int64.to_float conflict.fee /. float_of_int conflict_vsize in
                Error (Printf.sprintf
                  "Replacement feerate %.2f sat/vB not higher than conflicting tx feerate %.2f sat/vB"
                  new_feerate conflict_feerate)
              | None ->

              (* Rule 4: Replacement must not introduce new unconfirmed inputs *)
              let has_new_unconfirmed = List.exists (fun inp ->
                let prev = inp.Types.previous_output in
                (* If input is unconfirmed (from mempool) *)
                if not (is_confirmed_utxo mp prev) then begin
                  (* Check if this unconfirmed input was also used by a conflicting tx *)
                  let was_in_conflicts = List.exists (fun conflict_entry ->
                    List.exists (fun conflict_inp ->
                      Cstruct.equal conflict_inp.Types.previous_output.txid prev.txid &&
                      conflict_inp.Types.previous_output.vout = prev.vout
                    ) conflict_entry.tx.inputs
                  ) conflicts in
                  not was_in_conflicts
                end else
                  false
              ) tx.inputs in

              if has_new_unconfirmed then
                Error "Replacement introduces new unconfirmed inputs"

              else begin
                (* Remove all conflicting transactions and their descendants, then add new *)
                List.iter (fun conflict_entry ->
                  remove_transaction mp conflict_entry.txid
                ) conflicts;
                add_transaction mp tx
              end
            end
          end
        end
      end

(* Accept a transaction with full RBF support.
   If the transaction conflicts with existing mempool entries, automatically
   attempts replacement if the new transaction pays higher fees.
   This is the main entry point for accepting transactions with full RBF. *)
let accept_transaction ?(dry_run=false) (mp : mempool) (tx : Types.transaction)
    : (mempool_entry, string) result =
  (* First check if there are conflicts *)
  let conflicts = find_all_conflicts mp tx in
  match conflicts with
  | [] ->
    (* No conflicts, use normal add_transaction *)
    add_transaction ~dry_run mp tx
  | _ ->
    if dry_run then
      (* For dry_run, just check if RBF would succeed by doing validation *)
      (* We can't actually call replace_by_fee since it modifies state *)
      Error "txn-mempool-conflict (dry run with conflicts)"
    else
      (* Attempt full RBF replacement *)
      replace_by_fee mp tx

(* AcceptToMemoryPool — main entry point matching Bitcoin Core's AcceptToMemoryPool.
   Validates and adds a transaction to the mempool, handling RBF conflicts.
   Returns (Ok entry) on success or (Error reason) on failure. *)

type accept_result = {
  atmp_accepted : bool;
  atmp_txid : Types.hash256;
  atmp_fee : int64;
  atmp_vsize : int;
  atmp_reject_reason : string option;
}

let accept_to_memory_pool ?(test_accept=false) (mp : mempool) (tx : Types.transaction)
    : accept_result =
  let txid = Crypto.compute_txid tx in
  if test_accept then begin
    (* Dry-run: validate without modifying state *)
    match accept_transaction ~dry_run:true mp tx with
    | Ok entry ->
      { atmp_accepted = true; atmp_txid = txid; atmp_fee = entry.fee;
        atmp_vsize = entry.weight / 4;
        atmp_reject_reason = None }
    | Error reason ->
      { atmp_accepted = false; atmp_txid = txid; atmp_fee = 0L; atmp_vsize = 0;
        atmp_reject_reason = Some reason }
  end else begin
    match accept_transaction mp tx with
    | Ok entry ->
      { atmp_accepted = true; atmp_txid = txid; atmp_fee = entry.fee;
        atmp_vsize = entry.weight / 4;
        atmp_reject_reason = None }
    | Error reason ->
      { atmp_accepted = false; atmp_txid = txid; atmp_fee = 0L; atmp_vsize = 0;
        atmp_reject_reason = Some reason }
  end

(* ============================================================================
   Orphan Transaction Pool (Task 8)
   ============================================================================ *)

(* Add a transaction to the orphan pool *)
let add_orphan (mp : mempool) (tx : Types.transaction) : unit =
  let txid = Crypto.compute_txid tx in
  let txid_key = Cstruct.to_string txid in
  if not (Hashtbl.mem mp.orphans txid_key) then begin
    (* Enforce max orphan count by evicting oldest if full *)
    if Hashtbl.length mp.orphans >= mp.max_orphans then begin
      (* Evict the oldest orphan *)
      let oldest_key = ref "" in
      let oldest_time = ref max_float in
      Hashtbl.iter (fun k entry ->
        if entry.orphan_time < !oldest_time then begin
          oldest_key := k;
          oldest_time := entry.orphan_time
        end
      ) mp.orphans;
      if !oldest_key <> "" then
        Hashtbl.remove mp.orphans !oldest_key
    end;
    let entry = {
      orphan_tx = tx;
      orphan_txid = txid;
      orphan_time = Unix.gettimeofday ();
    } in
    Hashtbl.replace mp.orphans txid_key entry
  end

(* Try to process orphans when a new transaction is accepted.
   Returns list of successfully added entries. *)
let process_orphans (mp : mempool) (new_txid : Types.hash256)
    : mempool_entry list =
  let accepted = ref [] in
  let changed = ref true in
  (* Keep trying until no more orphans can be resolved *)
  while !changed do
    changed := false;
    let to_try = Hashtbl.fold (fun k v acc -> (k, v) :: acc) mp.orphans [] in
    List.iter (fun (orphan_key, orphan) ->
      (* Check if any input references the new txid or any previously accepted tx *)
      let relevant = List.exists (fun inp ->
        let prev_txid = inp.Types.previous_output.txid in
        Cstruct.equal prev_txid new_txid ||
        List.exists (fun e -> Cstruct.equal prev_txid e.txid) !accepted
      ) orphan.orphan_tx.inputs in
      if relevant then begin
        Hashtbl.remove mp.orphans orphan_key;
        match add_transaction mp orphan.orphan_tx with
        | Ok entry ->
          accepted := entry :: !accepted;
          changed := true
        | Error _ ->
          (* Orphan still can't be added; discard it *)
          ()
      end
    ) to_try
  done;
  List.rev !accepted

(* ============================================================================
   Ephemeral Anchor Policy

   Ephemeral anchors are zero-value (dust) outputs that are exempt from dust
   limits if they are spent by a child transaction in the same package.

   This policy ensures dust outputs don't enter the UTXO set by requiring:
   1. PreCheckEphemeralTx: tx with dust outputs must have 0 fee (disincentivize
      mining alone)
   2. CheckEphemeralSpends: all dust outputs from parents must be spent by
      children in the package

   Reference: Bitcoin Core /src/policy/ephemeral_policy.cpp
   ============================================================================ *)

(* Maximum number of dust outputs allowed per transaction *)
let max_dust_outputs_per_tx = 1

(* Check if an output is dust (would fail is_dust check).
   Zero-value outputs are always dust. Returns list of dust output indices. *)
let get_dust_outputs (min_relay_fee : int64) (tx : Types.transaction)
    : int list =
  List.mapi (fun i out ->
    if is_dust min_relay_fee out then Some i else None
  ) tx.outputs |> List.filter_map Fun.id

(* PreCheckEphemeralTx: A transaction with dust outputs must have 0 fee.
   This prevents miners from having incentive to mine the tx alone, which
   would leave dust in the UTXO set.
   Reference: Bitcoin Core PreCheckEphemeralTx *)
let pre_check_ephemeral_tx (min_relay_fee : int64) (tx : Types.transaction)
    (fee : int64) : (unit, string) result =
  let dust_outs = get_dust_outputs min_relay_fee tx in
  if dust_outs <> [] && fee <> 0L then
    Error "tx with dust output must be 0-fee"
  else
    Ok ()

(* Check if a transaction's parents have any dust outputs.
   Returns a list of (parent_txid, outpoint_index) for all dust outputs. *)
let find_parent_dust_outputs (mp : mempool) (tx : Types.transaction)
    ~(package_txs : (string, Types.transaction) Hashtbl.t)
    ~(processed : (string, unit) Hashtbl.t)
    : (Types.hash256 * int) list =
  let dust_list = ref [] in
  List.iter (fun inp ->
    let parent_txid = inp.Types.previous_output.txid in
    let parent_key = Cstruct.to_string parent_txid in
    (* Skip already processed parents *)
    if not (Hashtbl.mem processed parent_key) then begin
      Hashtbl.replace processed parent_key ();
      (* Find parent in package or mempool *)
      let parent_tx_opt =
        match Hashtbl.find_opt package_txs parent_key with
        | Some tx -> Some tx
        | None ->
          match Hashtbl.find_opt mp.entries parent_key with
          | Some entry -> Some entry.tx
          | None -> None
      in
      match parent_tx_opt with
      | Some parent_tx ->
        (* Check each output of the parent for dust *)
        let dust_indices = get_dust_outputs mp.min_relay_fee parent_tx in
        List.iter (fun idx ->
          dust_list := (parent_txid, idx) :: !dust_list
        ) dust_indices
      | None -> ()
    end
  ) tx.Types.inputs;
  !dust_list

(* CheckEphemeralSpends: Ensure all dust outputs from parents are spent.
   Each transaction in the package must spend ALL dust outputs from its
   parents (either in-package or in-mempool).
   Reference: Bitcoin Core CheckEphemeralSpends *)
let check_ephemeral_spends (mp : mempool) (package : Types.transaction list)
    : (unit, string * Types.hash256) result =
  (* Build a map of package txid -> transaction *)
  let package_txs = Hashtbl.create (List.length package) in
  List.iter (fun tx ->
    let txid = Crypto.compute_txid tx in
    Hashtbl.replace package_txs (Cstruct.to_string txid) tx
  ) package;

  let error = ref None in

  List.iter (fun tx ->
    if !error = None then begin
      let txid = Crypto.compute_txid tx in
      let processed = Hashtbl.create 8 in

      (* Find all dust outputs from parents *)
      let parent_dust = find_parent_dust_outputs mp tx
        ~package_txs ~processed in

      if parent_dust <> [] then begin
        (* Build set of inputs that this tx spends *)
        let spent_outpoints = Hashtbl.create 8 in
        List.iter (fun inp ->
          let key = Printf.sprintf "%s:%ld"
            (Cstruct.to_string inp.Types.previous_output.txid)
            inp.Types.previous_output.vout in
          Hashtbl.replace spent_outpoints key ()
        ) tx.Types.inputs;

        (* Check that all dust outputs are spent *)
        let unspent_dust = List.filter (fun (parent_txid, idx) ->
          let key = Printf.sprintf "%s:%d"
            (Cstruct.to_string parent_txid) idx in
          not (Hashtbl.mem spent_outpoints key)
        ) parent_dust in

        if unspent_dust <> [] then begin
          let (unspent_parent, unspent_idx) = List.hd unspent_dust in
          error := Some (
            Printf.sprintf "tx %s did not spend parent's ephemeral dust at output %d of %s"
              (Types.hash256_to_hex_display txid)
              unspent_idx
              (Types.hash256_to_hex_display unspent_parent),
            txid
          )
        end
      end
    end
  ) package;

  match !error with
  | Some (msg, txid) -> Error (msg, txid)
  | None -> Ok ()

(* Check ephemeral anchor policy for a single transaction.
   For standalone txs, this just checks that there are no dust outputs
   (since dust is only allowed with package validation). *)
let check_ephemeral_single (mp : mempool) (tx : Types.transaction)
    (fee : int64) : (unit, string) result =
  match pre_check_ephemeral_tx mp.min_relay_fee tx fee with
  | Error msg -> Error msg
  | Ok () ->
    (* Standalone tx with dust is rejected unless it has 0 fee
       and will be validated as part of a package *)
    let dust_outs = get_dust_outputs mp.min_relay_fee tx in
    if List.length dust_outs > max_dust_outputs_per_tx then
      Error (Printf.sprintf "Too many dust outputs (%d > %d)"
        (List.length dust_outs) max_dust_outputs_per_tx)
    else
      Ok ()

(* Get orphan pool size *)
let orphan_count (mp : mempool) : int =
  Hashtbl.length mp.orphans

(* ============================================================================
   Expiration Functions
   ============================================================================ *)

(* Gap 7: Expire mempool transactions older than 14 days *)
let expire_old_transactions (mp : mempool) : int =
  let now = Unix.gettimeofday () in
  let max_age = 1_209_600.0 in (* 14 days in seconds *)
  let to_remove = Hashtbl.fold (fun _k entry acc ->
    if now -. entry.time_added > max_age then entry.txid :: acc else acc
  ) mp.entries [] in
  List.iter (fun txid -> remove_transaction mp txid) to_remove;
  List.length to_remove

(* Gap 9: Expire orphan transactions older than 20 minutes *)
let expire_orphans (mp : mempool) : int =
  let now = Unix.gettimeofday () in
  let max_age = 1200.0 in (* 20 minutes *)
  let to_remove = Hashtbl.fold (fun k entry acc ->
    if now -. entry.orphan_time > max_age then k :: acc else acc
  ) mp.orphans [] in
  List.iter (Hashtbl.remove mp.orphans) to_remove;
  List.length to_remove

(* ============================================================================
   Update Current Height
   ============================================================================ *)

let update_height (mp : mempool) (height : int) : unit =
  mp.current_height <- height

let update_median_time (mp : mempool) (mtp : int32) : unit =
  mp.current_median_time <- mtp

let set_network (mp : mempool) (network : Consensus.network_config) : unit =
  mp.network <- network

(* ============================================================================
   Clear Mempool
   ============================================================================ *)

let clear (mp : mempool) : unit =
  Hashtbl.clear mp.entries;
  mp.total_weight <- 0;
  mp.total_fee <- 0L

(* ============================================================================
   Compact Block Support (BIP 152)
   ============================================================================ *)

(* Find transaction by short ID for compact block reconstruction *)
let find_by_short_id (mp : mempool) ~(k0 : int64) ~(k1 : int64) (short_id : int64)
    : Types.transaction option =
  let result = ref None in
  Hashtbl.iter (fun _ entry ->
    if !result = None then begin
      let computed_sid = Crypto.compute_short_txid k0 k1 entry.wtxid in
      if computed_sid = short_id then
        result := Some entry.tx
    end
  ) mp.entries;
  !result

(* Get all transactions from mempool (for compact block reconstruction) *)
let get_all_transactions (mp : mempool) : Types.transaction list =
  Hashtbl.fold (fun _ entry acc -> entry.tx :: acc) mp.entries []

(* Create a transaction lookup table for compact block reconstruction.
   This is more efficient than find_by_short_id for multiple lookups. *)
let create_short_id_lookup (mp : mempool) ~(k0 : int64) ~(k1 : int64)
    : (int64, Types.transaction) Hashtbl.t =
  let tbl = Hashtbl.create (Hashtbl.length mp.entries) in
  Hashtbl.iter (fun _ entry ->
    let short_id = Crypto.compute_short_txid k0 k1 entry.wtxid in
    Hashtbl.replace tbl short_id entry.tx
  ) mp.entries;
  tbl

(* ============================================================================
   Mempool Persistence — Bitcoin Core byte-compatible format

   File layout (mirrors bitcoin-core/src/node/mempool_persist.cpp):
     [0,  8)  : uint64 LE version  (= 2 for the obfuscated format)
     [8, 17)  : compact-size 0x08 + 8 raw key bytes  (the XOR obfuscation key)
     [17, …)  : XOR-obfuscated payload, where byte at file offset p is XOR'd
                with key[p mod 8]  (matches Core's [Obfuscation::operator()])

   Payload (post-XOR, in declaration order):
     uint64 LE                          total_txns_to_load
     <total_txns_to_load times>         CTransaction-with-witness
                                        int64 LE  nTime
                                        int64 LE  nFeeDelta
     compact-size + entries             mapDeltas       (Txid + int64 LE)
     compact-size + entries             unbroadcast set (Txid only)

   Camlcoin currently stores neither [nFeeDelta] nor an unbroadcast set; we
   therefore emit empty maps in those positions and ignore them on read.  When
   either is wired in, the writer/reader can extend without changing the on-
   wire format.

   The previous custom format (4-byte BE count, BE 64-bit fee, BE float time,
   4-byte BE tx-data length, raw tx) is NOT detected — it carried no stable
   magic and lived only inside our datadir.  On read of a non-Core file the
   loader returns 0 (best-effort) and the node continues with an empty
   mempool, exactly as Core does on a malformed file.
   ============================================================================ *)

let mempool_dump_version = 2L

(* Generate 8 random bytes for the XOR key.  We avoid pulling in the full
   mirage_crypto dependency stack (already used elsewhere) and just read from
   /dev/urandom; the key is non-secret and only obscures the on-disk bytes
   from incidental file scans.  Falls back to gettimeofday-seeded hash if
   /dev/urandom is unavailable. *)
let random_xor_key () : bytes =
  try
    let ic = open_in_bin "/dev/urandom" in
    let buf = Bytes.create 8 in
    Fun.protect ~finally:(fun () -> close_in_noerr ic)
      (fun () -> really_input ic buf 0 8);
    buf
  with _ ->
    let k = Bytes.create 8 in
    let t = Unix.gettimeofday () in
    let bits = Int64.bits_of_float t in
    for i = 0 to 7 do
      Bytes.set_uint8 k i
        (Int64.to_int (Int64.logand
          (Int64.shift_right_logical bits (i * 8)) 0xFFL))
    done;
    k

(* In-place XOR a buffer at the given starting [file_offset].  [key] is the
   8-byte obfuscation key. *)
let xor_in_place ~(key : bytes) ~(file_offset : int) (b : bytes) : unit =
  let k0 = Bytes.unsafe_get key 0 |> Char.code in
  let k1 = Bytes.unsafe_get key 1 |> Char.code in
  let k2 = Bytes.unsafe_get key 2 |> Char.code in
  let k3 = Bytes.unsafe_get key 3 |> Char.code in
  let k4 = Bytes.unsafe_get key 4 |> Char.code in
  let k5 = Bytes.unsafe_get key 5 |> Char.code in
  let k6 = Bytes.unsafe_get key 6 |> Char.code in
  let k7 = Bytes.unsafe_get key 7 |> Char.code in
  let n = Bytes.length b in
  for i = 0 to n - 1 do
    let p = file_offset + i in
    let kb = match p land 7 with
      | 0 -> k0 | 1 -> k1 | 2 -> k2 | 3 -> k3
      | 4 -> k4 | 5 -> k5 | 6 -> k6 | _ -> k7
    in
    let c = Char.code (Bytes.unsafe_get b i) in
    Bytes.unsafe_set b i (Char.chr (c lxor kb))
  done

(* Helpers: encode/decode primitives at known buffer offsets, working in raw
   bytes so we can XOR-obfuscate a contiguous payload before writing it to
   disk in one shot. *)
let put_uint64_le (buf : Buffer.t) (v : int64) : unit =
  let cs = Cstruct.create 8 in
  Cstruct.LE.set_uint64 cs 0 v;
  Buffer.add_string buf (Cstruct.to_string cs)

let put_int64_le (buf : Buffer.t) (v : int64) : unit = put_uint64_le buf v

let put_compact_size (buf : Buffer.t) (n : int) : unit =
  if n < 0xFD then Buffer.add_char buf (Char.chr n)
  else if n <= 0xFFFF then begin
    Buffer.add_char buf '\xFD';
    let cs = Cstruct.create 2 in
    Cstruct.LE.set_uint16 cs 0 n;
    Buffer.add_string buf (Cstruct.to_string cs)
  end else if n <= 0xFFFFFFFF then begin
    Buffer.add_char buf '\xFE';
    let cs = Cstruct.create 4 in
    Cstruct.LE.set_uint32 cs 0 (Int32.of_int n);
    Buffer.add_string buf (Cstruct.to_string cs)
  end else begin
    Buffer.add_char buf '\xFF';
    put_uint64_le buf (Int64.of_int n)
  end

(* Save mempool in Bitcoin Core byte-compatible format (atomic via temp file
   + rename, mirroring Core's "<path>.new" → rename pattern). *)
let save_mempool (mp : mempool) (path : string) : unit =
  let tmp = path ^ ".new" in
  let oc = open_out_bin tmp in
  Fun.protect ~finally:(fun () -> close_out_noerr oc) (fun () ->
    (* 1. Header: version (no XOR yet) *)
    let hdr = Buffer.create 17 in
    put_uint64_le hdr mempool_dump_version;
    (* 2. Header: serialized 8-byte XOR key as compact-size + raw bytes (no
       XOR yet — Core writes this before SetObfuscation). *)
    let xor_key = random_xor_key () in
    Buffer.add_char hdr (Char.chr 0x08);
    Buffer.add_bytes hdr xor_key;
    output_string oc (Buffer.contents hdr);
    (* 3. Build the obfuscated payload in memory, then XOR + write. *)
    let payload = Buffer.create 4096 in
    (* Snapshot entries first to make iteration deterministic relative to
       any concurrent mutation (the caller is expected to hold or know the
       single-writer invariant; Core takes [pool.cs] for the same reason). *)
    let entries =
      Hashtbl.fold (fun _k e acc -> e :: acc) mp.entries [] in
    let n = List.length entries in
    put_uint64_le payload (Int64.of_int n);
    List.iter (fun (entry : mempool_entry) ->
      (* CTransaction with witness *)
      let w = Serialize.writer_create () in
      Serialize.serialize_transaction w entry.tx;
      let tx_cs = Serialize.writer_to_cstruct w in
      Buffer.add_string payload (Cstruct.to_string tx_cs);
      (* int64 LE nTime (seconds since epoch) *)
      put_int64_le payload (Int64.of_float entry.time_added);
      (* int64 LE nFeeDelta — camlcoin does not (yet) track prioritisetransaction
         deltas, so we emit 0.  Core treats absent deltas the same way. *)
      put_int64_le payload 0L
    ) entries;
    (* mapDeltas: empty (camlcoin lacks prioritisetransaction tracking) *)
    put_compact_size payload 0;
    (* unbroadcast_txids: empty (camlcoin lacks an unbroadcast set) *)
    put_compact_size payload 0;
    (* XOR the entire payload, then write. Payload starts at file offset 17. *)
    let payload_bytes = Buffer.to_bytes payload in
    xor_in_place ~key:xor_key ~file_offset:17 payload_bytes;
    output_bytes oc payload_bytes
  );
  Sys.rename tmp path

(* Streaming reader over a Buffer.contents-style raw payload string with an
   internal cursor.  The caller pre-XOR-decodes the payload before passing it
   in, so this just needs to walk a string. *)
type reader_state = {
  mutable r_pos : int;
  r_data : string;
}

let r_remaining (r : reader_state) : int =
  String.length r.r_data - r.r_pos

let r_read_u8 (r : reader_state) : int =
  if r_remaining r < 1 then failwith "mempool.dat truncated";
  let c = Char.code r.r_data.[r.r_pos] in
  r.r_pos <- r.r_pos + 1;
  c

let r_read_bytes (r : reader_state) (n : int) : string =
  if r_remaining r < n then failwith "mempool.dat truncated";
  let s = String.sub r.r_data r.r_pos n in
  r.r_pos <- r.r_pos + n;
  s

let r_read_uint16_le (r : reader_state) : int =
  let s = r_read_bytes r 2 in
  Cstruct.LE.get_uint16 (Cstruct.of_string s) 0

let r_read_uint32_le (r : reader_state) : int32 =
  let s = r_read_bytes r 4 in
  Cstruct.LE.get_uint32 (Cstruct.of_string s) 0

let r_read_int64_le (r : reader_state) : int64 =
  let s = r_read_bytes r 8 in
  Cstruct.LE.get_uint64 (Cstruct.of_string s) 0

let r_read_compact_size (r : reader_state) : int =
  let first = r_read_u8 r in
  if first < 0xFD then first
  else if first = 0xFD then r_read_uint16_le r
  else if first = 0xFE then Int32.to_int (r_read_uint32_le r)
  else Int64.to_int (r_read_int64_le r)

(* Load mempool from a Bitcoin Core byte-compatible mempool.dat.  Returns the
   number of transactions successfully accepted into the mempool.  Silently
   returns 0 on malformed / unsupported / missing files (matches Core's
   "Continuing anyway" loss-tolerant policy). *)
let load_mempool (mp : mempool) (path : string) : int =
  if not (Sys.file_exists path) then 0
  else begin
    let loaded = ref 0 in
    (try
      let ic = open_in_bin path in
      Fun.protect ~finally:(fun () -> close_in_noerr ic) (fun () ->
        let file_len = in_channel_length ic in
        if file_len < 8 then raise Exit;
        let hdr_v = Bytes.create 8 in
        really_input ic hdr_v 0 8;
        let version = Cstruct.LE.get_uint64
          (Cstruct.of_bytes hdr_v) 0 in
        let key, payload_offset =
          if Int64.equal version 1L then
            (* Legacy unobfuscated v1: zero key (no XOR) *)
            (Bytes.make 8 '\x00', 8)
          else if Int64.equal version mempool_dump_version then begin
            if file_len < 17 then raise Exit;
            let csize_buf = Bytes.create 1 in
            really_input ic csize_buf 0 1;
            (* Core serializes the key as vector<byte>: compact-size length
               followed by raw bytes.  For an 8-byte key this MUST be 0x08;
               we also tolerate 0xFD-prefixed encodings just in case. *)
            let csize = Char.code (Bytes.get csize_buf 0) in
            let n =
              if csize < 0xFD then csize
              else if csize = 0xFD then begin
                let b2 = Bytes.create 2 in
                really_input ic b2 0 2;
                Cstruct.LE.get_uint16 (Cstruct.of_bytes b2) 0
              end else raise Exit
            in
            if n <> 8 then raise Exit;
            let k = Bytes.create 8 in
            really_input ic k 0 8;
            (* file offset now: 8 (version) + (1 csize byte) + 8 (key) = 17 *)
            (k, 17)
          end else
            (* Unknown version (incl. legacy big-endian custom format) *)
            raise Exit
        in
        (* Read the rest of the file as one chunk and XOR-decode. *)
        let payload_len = file_len - payload_offset in
        if payload_len <= 0 then raise Exit;
        let payload = Bytes.create payload_len in
        really_input ic payload 0 payload_len;
        xor_in_place ~key ~file_offset:payload_offset payload;
        let r = { r_pos = 0; r_data = Bytes.unsafe_to_string payload } in
        let total = r_read_int64_le r in
        if Int64.compare total 0L < 0 then raise Exit;
        let total_int = Int64.to_int total in
        for _i = 1 to total_int do
          (* Build a sub-reader on the remaining payload so [Serialize] can
             walk the variable-length transaction.  We use [Serialize]'s own
             reader by handing it the remaining slice via Cstruct. *)
          let remaining = r_remaining r in
          if remaining <= 0 then raise Exit;
          let cs = Cstruct.of_string ~off:r.r_pos ~len:remaining
            r.r_data in
          let sr = Serialize.reader_of_cstruct cs in
          let tx = Serialize.deserialize_transaction sr in
          (* Advance our cursor by however many bytes Serialize consumed. *)
          r.r_pos <- r.r_pos + sr.pos;
          let _n_time = r_read_int64_le r in   (* discarded — mempool re-times *)
          let _n_fee_delta = r_read_int64_le r in (* no prioritisetx tracking *)
          (match add_transaction mp tx with
           | Ok _ -> incr loaded
           | Error _ -> ())
        done;
        (* mapDeltas: read + discard *)
        let n_deltas = r_read_compact_size r in
        for _i = 1 to n_deltas do
          let _txid = r_read_bytes r 32 in
          let _amount = r_read_int64_le r in
          ()
        done;
        (* unbroadcast_txids: read + discard *)
        let n_unbcast =
          try r_read_compact_size r
          with _ -> 0 in
        for _i = 1 to n_unbcast do
          let _txid = r_read_bytes r 32 in ()
        done
      )
    with _ -> ());
    !loaded
  end

(* ============================================================================
   Package Relay (BIP 331)

   Package relay allows transactions to be validated and relayed as packages,
   enabling CPFP (Child Pays For Parent) fee-bumping of transactions that
   would otherwise be below the mempool minimum fee.

   Key concepts:
   - 1p1c (1 parent, 1 child): The initial supported package topology
   - Package fee rate: sum(fees) / sum(vsizes) across all transactions
   - Individual tx may be below min fee if package fee rate is sufficient
   - Orphan resolution triggers 1p1c package validation
   ============================================================================ *)

(* Package validation result *)
type package_result =
  | PackageAccepted of mempool_entry list
  | PackageRejected of string
  | PackagePartial of {
      accepted : mempool_entry list;
      rejected : (Types.transaction * string) list;
    }

(* Maximum package size constraints (from Bitcoin Core) *)
let max_package_count = 25
let max_package_weight = 404_000

(* Topologically sort transactions so parents come before children.
   Returns Error if there's a cycle or invalid topology. *)
let topo_sort (txs : Types.transaction list) : (Types.transaction list, string) result =
  if txs = [] then Ok []
  else begin
    (* Build a map of txid -> transaction *)
    let tx_by_id = Hashtbl.create (List.length txs) in
    List.iter (fun tx ->
      let txid = Crypto.compute_txid tx in
      Hashtbl.replace tx_by_id (Cstruct.to_string txid) tx
    ) txs;

    (* Build dependency graph: txid -> list of parent txids within package *)
    let deps = Hashtbl.create (List.length txs) in
    List.iter (fun tx ->
      let txid = Cstruct.to_string (Crypto.compute_txid tx) in
      let parent_ids = List.filter_map (fun inp ->
        let parent_id = Cstruct.to_string inp.Types.previous_output.txid in
        if Hashtbl.mem tx_by_id parent_id then Some parent_id else None
      ) tx.Types.inputs in
      Hashtbl.replace deps txid parent_ids
    ) txs;

    (* Kahn's algorithm for topological sort *)
    let in_degree = Hashtbl.create (List.length txs) in
    Hashtbl.iter (fun txid parents ->
      if not (Hashtbl.mem in_degree txid) then
        Hashtbl.replace in_degree txid 0;
      List.iter (fun parent_id ->
        let current = try Hashtbl.find in_degree txid with Not_found -> 0 in
        Hashtbl.replace in_degree txid (current + 1);
        (* Ensure parent is in in_degree *)
        if not (Hashtbl.mem in_degree parent_id) then
          Hashtbl.replace in_degree parent_id 0
      ) parents
    ) deps;

    (* Find all nodes with in_degree 0 *)
    let queue = Queue.create () in
    Hashtbl.iter (fun txid degree ->
      if degree = 0 then Queue.push txid queue
    ) in_degree;

    let sorted = ref [] in
    let visited = ref 0 in
    while not (Queue.is_empty queue) do
      let txid = Queue.pop queue in
      incr visited;
      (match Hashtbl.find_opt tx_by_id txid with
       | Some tx -> sorted := tx :: !sorted
       | None -> ());
      (* Decrease in_degree for all children *)
      Hashtbl.iter (fun child_id parents ->
        if List.mem txid parents then begin
          let deg = Hashtbl.find in_degree child_id in
          Hashtbl.replace in_degree child_id (deg - 1);
          if deg - 1 = 0 then Queue.push child_id queue
        end
      ) deps
    done;

    if !visited <> List.length txs then
      Error "Package contains a cycle"
    else
      Ok (List.rev !sorted)
  end

(* Check if a package is well-formed:
   - At most max_package_count transactions
   - Total weight at most max_package_weight
   - Topologically sorted (parents before children)
   - No conflicting transactions (same input spent twice) *)
let is_well_formed_package (txs : Types.transaction list) : (unit, string) result =
  if List.length txs > max_package_count then
    Error (Printf.sprintf "Package exceeds max transaction count (%d > %d)"
      (List.length txs) max_package_count)
  else begin
    (* Check total weight *)
    let total_weight = List.fold_left (fun acc tx ->
      acc + Validation.compute_tx_weight tx
    ) 0 txs in
    if total_weight > max_package_weight then
      Error (Printf.sprintf "Package exceeds max weight (%d > %d)"
        total_weight max_package_weight)
    else begin
      (* Check for conflicting transactions (same outpoint spent twice) *)
      let spent_outpoints = Hashtbl.create 64 in
      let conflict = ref None in
      List.iter (fun tx ->
        if !conflict = None then
          List.iter (fun inp ->
            let key = Printf.sprintf "%s:%ld"
              (Types.hash256_to_hex inp.Types.previous_output.txid)
              inp.Types.previous_output.vout in
            if Hashtbl.mem spent_outpoints key then
              conflict := Some (Printf.sprintf "Conflicting spend of %s" key)
            else
              Hashtbl.replace spent_outpoints key ()
          ) tx.Types.inputs
      ) txs;
      match !conflict with
      | Some msg -> Error msg
      | None -> Ok ()
    end
  end

(* Check if package is child-with-parents (1p1c) topology:
   - Last transaction is the child
   - All preceding transactions are parents of the child
   - Parents have no dependencies on each other *)
let is_1p1c_package (txs : Types.transaction list) : bool =
  match txs with
  | [] | [_] -> true  (* Empty or single tx is trivially valid *)
  | _ ->
    let n = List.length txs in
    if n <> 2 then false  (* 1p1c is exactly 2 txs *)
    else begin
      let parent = List.hd txs in
      let child = List.nth txs 1 in
      let parent_txid = Crypto.compute_txid parent in
      (* Child must spend from parent *)
      List.exists (fun inp ->
        Cstruct.equal inp.Types.previous_output.txid parent_txid
      ) child.Types.inputs
    end

(* Calculate fee and vsize for a single transaction given available UTXOs.
   Returns (fee, vsize) or Error if inputs are missing. *)
let calc_tx_fee_vsize (mp : mempool) (tx : Types.transaction)
    ~(package_utxos : (string, Utxo.utxo_entry) Hashtbl.t)
    : (int64 * int, string) result =
  let input_sum = ref 0L in
  let error = ref None in
  List.iter (fun inp ->
    if !error = None then begin
      let prev = inp.Types.previous_output in
      let key = Printf.sprintf "%s:%ld"
        (Types.hash256_to_hex prev.txid) prev.vout in
      (* Check package UTXOs first (outputs from earlier package txs) *)
      match Hashtbl.find_opt package_utxos key with
      | Some entry -> input_sum := Int64.add !input_sum entry.Utxo.value
      | None ->
        (* Fall back to mempool/chain UTXOs *)
        match lookup_utxo mp prev with
        | Some entry -> input_sum := Int64.add !input_sum entry.value
        | None ->
          error := Some (Printf.sprintf "Missing input: %s:%ld"
            (Types.hash256_to_hex_display prev.txid) prev.vout)
    end
  ) tx.Types.inputs;
  match !error with
  | Some msg -> Error msg
  | None ->
    let output_sum = List.fold_left
      (fun acc out -> Int64.add acc out.Types.value) 0L tx.Types.outputs in
    if output_sum > !input_sum then
      Error "Output exceeds input"
    else begin
      let fee = Int64.sub !input_sum output_sum in
      let weight = Validation.compute_tx_weight tx in
      let vsize = (weight + 3) / 4 in
      Ok (fee, vsize)
    end

(* Accept a package of transactions.
   Validates topologically (parents before children).
   Computes package fee rate as total_fees / total_vsize.
   Accepts if package fee rate meets minimum, even if individual txs don't. *)
let accept_package (mp : mempool) (txs : Types.transaction list)
    : package_result =
  (* Validate well-formedness *)
  match is_well_formed_package txs with
  | Error msg -> PackageRejected msg
  | Ok () ->
    (* Topologically sort *)
    match topo_sort txs with
    | Error msg -> PackageRejected msg
    | Ok sorted ->
      (* Track UTXOs created by earlier transactions in the package *)
      let package_utxos = Hashtbl.create 16 in
      let total_fee = ref 0L in
      let total_vsize = ref 0 in
      let accepted = ref [] in
      let rejected = ref [] in
      let package_txids = Hashtbl.create 16 in

      (* First pass: calculate fees and check for already-in-mempool txs *)
      let fees_vsizes = List.map (fun tx ->
        let txid = Crypto.compute_txid tx in
        let txid_key = Cstruct.to_string txid in
        Hashtbl.replace package_txids txid_key ();
        (* Check if already in mempool *)
        if Hashtbl.mem mp.entries txid_key then
          `AlreadyInMempool (tx, Hashtbl.find mp.entries txid_key)
        else
          (* Calculate fee and vsize *)
          match calc_tx_fee_vsize mp tx ~package_utxos with
          | Error msg -> `Error (tx, msg)
          | Ok (fee, vsize) ->
            (* Add outputs to package UTXOs for later txs *)
            List.iteri (fun i out ->
              let key = Printf.sprintf "%s:%d"
                (Types.hash256_to_hex txid) i in
              Hashtbl.replace package_utxos key Utxo.{
                value = out.Types.value;
                script_pubkey = out.Types.script_pubkey;
                height = mp.current_height;
                is_coinbase = false;
              }
            ) tx.Types.outputs;
            `NeedValidation (tx, fee, vsize)
      ) sorted in

      (* Calculate package totals for txs that need validation *)
      List.iter (function
        | `AlreadyInMempool (_, entry) ->
          (* Already accepted, add to accepted list *)
          accepted := entry :: !accepted
        | `Error (tx, _) ->
          (* Will be handled below *)
          ignore tx
        | `NeedValidation (_, fee, vsize) ->
          total_fee := Int64.add !total_fee fee;
          total_vsize := !total_vsize + vsize
      ) fees_vsizes;

      (* Check package fee rate *)
      let package_feerate =
        if !total_vsize > 0 then
          (* Fee rate in sat/kvB: (fee * 1000) / vsize *)
          Int64.to_float !total_fee *. 1000.0 /. float_of_int !total_vsize
        else 0.0
      in
      let min_feerate = Int64.to_float mp.min_relay_fee in

      (* If package fee rate is sufficient, accept txs even if individual is below min *)
      let use_package_feerate = package_feerate >= min_feerate in

      (* Second pass: actually add transactions *)
      List.iter (function
        | `AlreadyInMempool _ -> ()  (* Already handled *)
        | `Error (tx, msg) ->
          rejected := (tx, msg) :: !rejected
        | `NeedValidation (tx, fee, vsize) ->
          let _txid = Crypto.compute_txid tx in
          (* Check individual fee rate *)
          let individual_feerate = Int64.to_float fee *. 1000.0 /. float_of_int vsize in
          let passes_feerate = individual_feerate >= min_feerate || use_package_feerate in

          if not passes_feerate then
            rejected := (tx, "Fee below minimum relay fee (not enough CPFP)") :: !rejected
          else begin
            (* Always use add_transaction to ensure full validation including
               script verification. Pass ~bypass_fee_check for CPFP packages. *)
            let add_result =
              add_transaction ~bypass_fee_check:use_package_feerate mp tx
            in
            match add_result with
            | Ok entry -> accepted := entry :: !accepted
            | Error msg -> rejected := (tx, msg) :: !rejected
          end
      ) fees_vsizes;

      let accepted_list = List.rev !accepted in
      let rejected_list = List.rev !rejected in

      (* Check ephemeral anchor policy: all dust outputs must be spent *)
      if rejected_list = [] && accepted_list <> [] then begin
        match check_ephemeral_spends mp sorted with
        | Error (msg, _txid) ->
          PackageRejected (Printf.sprintf "missing-ephemeral-spends: %s" msg)
        | Ok () ->
          PackageAccepted accepted_list
      end else if accepted_list = [] then
        PackageRejected (snd (List.hd rejected_list))
      else
        (* Partial acceptance - still check ephemeral spends for accepted txs *)
        let accepted_txs = List.map (fun e -> e.tx) accepted_list in
        match check_ephemeral_spends mp accepted_txs with
        | Error (msg, _txid) ->
          PackageRejected (Printf.sprintf "missing-ephemeral-spends: %s" msg)
        | Ok () ->
          PackagePartial { accepted = accepted_list; rejected = rejected_list }

(* Find a 1p1c package for an orphan transaction.
   When an orphan's parent arrives but is rejected for low fee,
   try to validate the orphan+parent as a 1p1c package. *)
let find_1p1c_for_orphan (mp : mempool) (parent_txid : Types.hash256)
    : (Types.transaction * Types.transaction) option =
  (* Look for orphans that spend this parent *)
  let candidates = Hashtbl.fold (fun _k entry acc ->
    let spends_parent = List.exists (fun inp ->
      Cstruct.equal inp.Types.previous_output.txid parent_txid
    ) entry.orphan_tx.Types.inputs in
    if spends_parent then entry.orphan_tx :: acc else acc
  ) mp.orphans [] in
  match candidates with
  | [] -> None
  | child :: _ ->
    (* We need the parent transaction - check if it's in the reject cache
       or was just validated. For now, return None if parent not available. *)
    (* In practice, the caller should provide the parent tx *)
    ignore child;
    None

(* Try 1p1c validation for a rejected parent transaction.
   Called when a transaction is rejected for fee-related reasons
   and we want to check if any orphan can pay for it. *)
let try_1p1c_with_orphans (mp : mempool) (parent : Types.transaction)
    : package_result =
  let parent_txid = Crypto.compute_txid parent in
  (* Find orphans that spend this parent *)
  let candidates = Hashtbl.fold (fun orphan_key entry acc ->
    let spends_parent = List.exists (fun inp ->
      Cstruct.equal inp.Types.previous_output.txid parent_txid
    ) entry.orphan_tx.Types.inputs in
    if spends_parent then (orphan_key, entry.orphan_tx) :: acc else acc
  ) mp.orphans [] in

  match candidates with
  | [] -> PackageRejected "No orphans available for CPFP"
  | (orphan_key, child) :: _ ->
    (* Try to validate as 1p1c package *)
    let result = accept_package mp [parent; child] in
    (match result with
     | PackageAccepted _ | PackagePartial { accepted = _ :: _; _ } ->
       (* Remove the orphan since it was accepted *)
       Hashtbl.remove mp.orphans orphan_key
     | _ -> ());
    result

(* Enhanced orphan processing: when a transaction is accepted,
   try 1p1c package validation with waiting orphans. *)
let process_orphans_with_cpfp (mp : mempool) (new_txid : Types.hash256)
    : mempool_entry list =
  let accepted = ref [] in
  let changed = ref true in

  while !changed do
    changed := false;
    let to_try = Hashtbl.fold (fun k v acc -> (k, v) :: acc) mp.orphans [] in
    List.iter (fun (orphan_key, orphan) ->
      (* Check if any input references the new txid or previously accepted tx *)
      let relevant = List.exists (fun inp ->
        let prev_txid = inp.Types.previous_output.txid in
        Cstruct.equal prev_txid new_txid ||
        List.exists (fun e -> Cstruct.equal prev_txid e.txid) !accepted
      ) orphan.orphan_tx.Types.inputs in

      if relevant then begin
        Hashtbl.remove mp.orphans orphan_key;
        (* Try normal add first *)
        match add_transaction mp orphan.orphan_tx with
        | Ok entry ->
          accepted := entry :: !accepted;
          changed := true
        | Error _ ->
          (* If normal add fails, the orphan may need CPFP from its own children.
             For now, just discard it since we don't have a child yet. *)
          ()
      end
    ) to_try
  done;
  List.rev !accepted
