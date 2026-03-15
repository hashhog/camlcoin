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
    map_next_tx = Hashtbl.create 10_000 }

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

(* Remove a transaction and its dependents recursively.
   Collects dependent txids before removal to avoid mutating Hashtbl during iteration.
   Updates cached descendant counts of ancestors using BFS. *)
let rec remove_transaction (mp : mempool) (txid : Types.hash256) : unit =
  let txid_key = Cstruct.to_string txid in
  match Hashtbl.find_opt mp.entries txid_key with
  | None -> ()
  | Some entry ->
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

(* Check if a script is a recognized standard output type *)
let is_standard_output (script_pubkey : Cstruct.t) : bool =
  match Script.classify_script script_pubkey with
  | Script.P2PKH_script _ -> true
  | Script.P2SH_script _ -> true
  | Script.P2WPKH_script _ -> true
  | Script.P2WSH_script _ -> true
  | Script.P2TR_script _ -> true
  | Script.P2A_script -> true  (* P2A is standard -- BIP-PR-3535 *)
  | Script.OP_RETURN_data _ -> Cstruct.length script_pubkey <= 83
  | Script.Nonstandard -> false

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

(* Check if a transaction passes IsStandard policy *)
let is_standard_tx (min_relay_fee : int64) (tx : Types.transaction) : (unit, string) result =
  (* Version must be 1 or 2 *)
  let version = Int32.to_int tx.version in
  if version < 1 || version > 2 then
    Error "Non-standard transaction version"
  else begin
    (* Weight must not exceed 400,000 *)
    let weight = Validation.compute_tx_weight tx in
    if weight > max_standard_tx_weight then
      Error "Transaction weight exceeds standard limit"
    else begin
      (* All outputs must be recognized script types *)
      let bad_output = ref None in
      List.iteri (fun i out ->
        if !bad_output = None then begin
          if not (is_standard_output out.Types.script_pubkey) then
            bad_output := Some (Printf.sprintf
              "Non-standard output script at index %d" i)
          else if is_dust min_relay_fee out &&
                  not (tx.version = 3l && out.Types.value = 0L) then
            bad_output := Some (Printf.sprintf
              "Dust output at index %d (value: %Ld)" i out.Types.value)
        end
      ) tx.outputs;

      match !bad_output with
      | Some e -> Error e
      | None ->
        (* All scriptSigs must be push-only *)
        let bad_input = ref None in
        List.iteri (fun i inp ->
          if !bad_input = None then begin
            if not (is_push_only_script_sig inp.Types.script_sig) then
              bad_input := Some (Printf.sprintf
                "Non-push-only scriptSig at input %d" i)
          end
        ) tx.inputs;

        match !bad_input with
        | Some e -> Error e
        | None ->
          (* Gap 2: P2WSH witness policy limits *)
          check_p2wsh_witness_limits tx
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
  let flags = Consensus.get_block_script_flags (mp.current_height + 1) mp.network in
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
                evict_by_chunks mp
            end;

            Ok entry
          end
        end
    end

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
  (* BIP-125: sequence number < 0xFFFFFFFE signals RBF *)
  List.exists (fun inp ->
    Int32.compare inp.Types.sequence 0xFFFFFFFEl < 0
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
   Mempool Persistence (Gap 5)
   ============================================================================ *)

(* Save mempool to a binary file (atomic via temp file + rename) *)
let save_mempool (mp : mempool) (path : string) : unit =
  let tmp = path ^ ".tmp" in
  let oc = open_out_bin tmp in
  Fun.protect ~finally:(fun () -> close_out_noerr oc) (fun () ->
    (* Write 4-byte BE count *)
    let count = Hashtbl.length mp.entries in
    let buf4 = Cstruct.create 4 in
    Cstruct.BE.set_uint32 buf4 0 (Int32.of_int count);
    output_string oc (Cstruct.to_string buf4);
    (* Write each entry *)
    Hashtbl.iter (fun _k entry ->
      (* txid: 32 bytes *)
      output_string oc (Cstruct.to_string entry.txid);
      (* fee: 8 bytes BE *)
      let buf8 = Cstruct.create 8 in
      Cstruct.BE.set_uint64 buf8 0 entry.fee;
      output_string oc (Cstruct.to_string buf8);
      (* time_added: 8 bytes BE (Int64.bits_of_float) *)
      let buf8t = Cstruct.create 8 in
      Cstruct.BE.set_uint64 buf8t 0 (Int64.bits_of_float entry.time_added);
      output_string oc (Cstruct.to_string buf8t);
      (* tx_data: serialize transaction *)
      let w = Serialize.writer_create () in
      Serialize.serialize_transaction w entry.tx;
      let tx_cs = Serialize.writer_to_cstruct w in
      let tx_data = Cstruct.to_string tx_cs in
      (* tx_data_len: 4 bytes BE *)
      let buf4l = Cstruct.create 4 in
      Cstruct.BE.set_uint32 buf4l 0 (Int32.of_int (String.length tx_data));
      output_string oc (Cstruct.to_string buf4l);
      (* tx_data: raw bytes *)
      output_string oc tx_data
    ) mp.entries
  );
  Sys.rename tmp path

(* Load mempool from a binary file, returns count of loaded transactions *)
let load_mempool (mp : mempool) (path : string) : int =
  if not (Sys.file_exists path) then 0
  else
    let loaded = ref 0 in
    (try
      let ic = open_in_bin path in
      Fun.protect ~finally:(fun () -> close_in_noerr ic) (fun () ->
        (* Read 4-byte BE count *)
        let hdr = Bytes.create 4 in
        really_input ic hdr 0 4;
        let hdr_cs = Cstruct.of_bytes hdr in
        let count = Int32.to_int (Cstruct.BE.get_uint32 hdr_cs 0) in
        for _i = 1 to count do
          (* txid: 32 bytes *)
          let txid_buf = Bytes.create 32 in
          really_input ic txid_buf 0 32;
          ignore (Cstruct.of_bytes txid_buf);  (* txid — used only for verification *)
          (* fee: 8 bytes BE *)
          let fee_buf = Bytes.create 8 in
          really_input ic fee_buf 0 8;
          ignore (Cstruct.BE.get_uint64 (Cstruct.of_bytes fee_buf) 0);  (* fee — recomputed by add_transaction *)
          (* time_added: 8 bytes BE *)
          let time_buf = Bytes.create 8 in
          really_input ic time_buf 0 8;
          ignore (Int64.float_of_bits (Cstruct.BE.get_uint64 (Cstruct.of_bytes time_buf) 0));  (* time_added — recomputed *)
          (* tx_data_len: 4 bytes BE *)
          let len_buf = Bytes.create 4 in
          really_input ic len_buf 0 4;
          let tx_data_len = Int32.to_int (Cstruct.BE.get_uint32 (Cstruct.of_bytes len_buf) 0) in
          (* tx_data: raw bytes *)
          let tx_buf = Bytes.create tx_data_len in
          really_input ic tx_buf 0 tx_data_len;
          let tx_cs = Cstruct.of_bytes tx_buf in
          let r = Serialize.reader_of_cstruct tx_cs in
          let tx = Serialize.deserialize_transaction r in
          match add_transaction mp tx with
          | Ok _ -> incr loaded
          | Error _ -> ()  (* skip silently *)
        done
      )
    with _ -> ());  (* handle corrupt files gracefully *)
    !loaded

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
