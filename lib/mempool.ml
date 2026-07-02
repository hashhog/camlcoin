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
  orphan_txid : Types.hash256;   (* txid — used for parent-resolution lookups *)
  orphan_wtxid : Types.hash256;  (* wtxid — primary pool key per BIP-339 *)
  orphan_time : float;
}

(* ============================================================================
   Mempool State
   ============================================================================ *)

type mempool = {
  mutable entries : (string, mempool_entry) Hashtbl.t;
  mutable total_weight : int;
  mutable total_fee : int64;
  max_size_bytes : int;       (* default 300 MB = 300_000_000 bytes (SI, matching Core) *)
  min_relay_fee : int64;      (* minimum fee rate in sat/kvB *)
  mutable dynamic_min_fee : int64;  (* raised when mempool is full and evictions occur *)
  (* Rolling minimum fee — tracks eviction floor with exponential decay.
     Reference: Bitcoin Core txmempool.h:195-197, txmempool.cpp:829-859
     rollingMinimumFeeRate decays to zero over ROLLING_FEE_HALFLIFE (12h) after a block.
     blockSinceLastRollingFeeBump gates whether decay is active. *)
  mutable rolling_min_fee_rate : float;         (* sat/kvB, updated by track_package_removed *)
  mutable last_rolling_fee_update : float;      (* Unix timestamp of last decay computation *)
  mutable block_since_last_rolling_fee_bump : bool;  (* true after block connected; enables decay *)
  utxo : Utxo.UtxoSet.t;
  mutable current_height : int;
  mutable network : Consensus.network_config;
  mutable current_median_time : int32;
  (* Policy flags — can be relaxed for testing or regtest *)
  require_standard : bool;    (* enforce IsStandard checks *)
  verify_scripts : bool;      (* enforce script verification *)
  (* Orphan pool — primary key is wtxid_str per BIP-339; secondary index maps
     txid_str → wtxid_str for fast parent-arrival resolution. *)
  orphans : (string, orphan_entry) Hashtbl.t;       (* wtxid_str → orphan_entry *)
  orphan_by_txid : (string, string) Hashtbl.t;      (* txid_str → wtxid_str *)
  max_orphans : int;
  (* Spending index: outpoint (txid_str * vout) -> spending txid_str for O(1) conflict detection *)
  map_next_tx : (string * int32, string) Hashtbl.t;
  (* Reverse parent->children index (#135 step 1): for each parent txid_key,
     a set (Hashtbl-as-set with unit values) of child txid_keys that depend
     on it. Maintained in add_transaction (insert) and remove_transaction
     (delete) so get_descendants is O(D) instead of O(N·D). The prior
     implementation did Hashtbl.fold over all mp.entries per recursion step
     — at a 50k-entry mempool with a 100-tx RBF cluster, that was ~5M
     comparisons per call. *)
  children : (string, (string, unit) Hashtbl.t) Hashtbl.t;
  (* ZMQ notifications *)
  mutable zmq_sequence : int64;                 (* monotonically increasing sequence for ZMQ *)
  mutable zmq_notifier : Zmq_notify.t option;   (* optional ZMQ notifier *)
  (* Fee-estimation eviction hook.
     Called by remove_transaction for every tx removed without confirmation
     (eviction, expiry, RBF conflict).  Wired to Fee_estimation.record_eviction
     from cli.ml so the estimator can update leftmempool stats.
     Core: TransactionRemovedFromMempool → CBlockPolicyEstimator::processTransaction
     Reference: validation.cpp / node/txmempool_impl.cpp *)
  mutable on_eviction : (Types.hash256 -> unit) option;
  (* FIX-72 W120 BUG-10: prioritisetransaction fee deltas.
     Maps txid (binary string key, internal byte order) to a signed satoshi
     delta added by `prioritisetransaction` RPC.  Used by `get_modified_fee`
     and `apply_delta` to bias selection/RBF math.  Persisted across
     restart by save_mempool (per-entry inline nFeeDelta + standalone tail
     map) and restored by load_mempool via prioritise_transaction (FIX-77).
     Matches Core's auto-restart LoadMempool default
     apply_fee_delta_priority=true (mempool_persist.h:23).
     Reference: bitcoin-core/src/txmempool.h:299 (`mapDeltas`),
     txmempool.cpp:630 (`PrioritiseTransaction`),
     txmempool.cpp:657 (`ApplyDelta`),
     node/mempool_persist.cpp:99-102 + 125-132 (LoadMempool ApplyDelta). *)
  map_deltas : (string, int64) Hashtbl.t;
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

(* 2026-07-02 at-tip RPC-stall fix: how many inputs the Lwt mempool-accept path
   processes between cooperative [Lwt.pause] yields while it does the SYNCHRONOUS
   per-input UTXO reads (lookup_utxo → direct RocksDB point read, which blocks the
   single Lwt/RPC domain).  Bounds the worst-case uninterrupted read storm — and
   thus the RPC stall — from one large-input tx to ~this many reads.  Scheduling
   only: does not affect the accept/reject decision.  Overridable via
   CAMLCOIN_ATMP_YIELD_EVERY for soak tuning; <=0 disables interior yielding
   (restores the old single-stretch behaviour); invalid values fall back. *)
let atmp_yield_every =
  match Sys.getenv_opt "CAMLCOIN_ATMP_YIELD_EVERY" with
  | Some s ->
    (match int_of_string_opt (String.trim s) with
     | Some v -> v
     | None -> 16)
  | None -> 16
(* DEFAULT_INCREMENTAL_RELAY_FEE = 100 sat/kvB.
   Reference: bitcoin-core/src/policy/policy.h:48
   Previous value was 1000 sat/kvB (10× too high). *)
let incremental_relay_fee = 100L  (* sat/kvB — policy/policy.h DEFAULT_INCREMENTAL_RELAY_FEE *)
let incremental_relay_fee_float = 100.0  (* float copy for rolling-fee math *)

(* DUST_RELAY_TX_FEE = 3000 sat/kvB — the feerate used to compute the dust
   threshold. This is SEPARATE from min_relay_fee (the relay/admission floor):
   Core's IsDust/GetDustThreshold and IsStandardTx take a distinct dustRelayFee
   CFeeRate (default DUST_RELAY_TX_FEE). Keeping dust on its own constant means
   lowering min_relay_fee to the Core default (100) does NOT collapse the dust
   limit (it would 10x undercount if coupled). The dust threshold stays
   3 * 3000 * size / 1000 == Core.
   Reference: bitcoin-core/src/policy/policy.h:68 (DUST_RELAY_TX_FEE),
   policy.h:140/142/159 (dustRelayFee separate from the min-relay floor). *)
let dust_relay_fee = 3000L  (* sat/kvB — policy/policy.h DUST_RELAY_TX_FEE *)

(* ROLLING_FEE_HALFLIFE = 12 hours in seconds.
   Reference: bitcoin-core/src/txmempool.h:212 *)
let rolling_fee_halflife = float_of_int (60 * 60 * 12)  (* 43200.0 s *)

(* Cluster mempool constants.
   Reference: Bitcoin Core policy/policy.h DEFAULT_CLUSTER_LIMIT / DEFAULT_CLUSTER_SIZE_LIMIT_KVB.
   DEFAULT_CLUSTER_LIMIT = 64 (max tx count per cluster).
   DEFAULT_CLUSTER_SIZE_LIMIT_KVB = 101 (max cluster vsize in kvB = 101_000 vbytes).
   Note: 101 is the *size* limit in kvB, NOT the count limit. Count limit is 64. *)
let max_cluster_count = 64     (* DEFAULT_CLUSTER_LIMIT — max transactions per cluster *)
let max_cluster_size_vbytes = 101_000  (* DEFAULT_CLUSTER_SIZE_LIMIT_KVB * 1000 — max cluster vsize *)
(* MAX_P2SH_SIGOPS = 15 — maximum legacy sigops in a P2SH redeemScript.
   Reference: Bitcoin Core policy/policy.h:42.
   ValidateInputsStandardness gate 3: reject P2SH inputs whose redeemScript
   sigops exceed this limit to mitigate expensive-script DoS. *)
let max_p2sh_sigops = 15

(* ORPHAN_EXPIRE_TIME — orphan transactions are dropped this many seconds after
   they are added to the pool.
   Reference: Bitcoin Core src/node/txorphanage.cpp ORPHAN_TX_EXPIRE_TIME = 20 min.
   Used by expire_orphans (the sweeper). Note: Core's getorphantxs RPC does NOT
   expose an expiration field, so this is sweeper-only. *)
let orphan_expire_seconds = 1200.0  (* 20 minutes *)

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
    ?(on_eviction : (Types.hash256 -> unit) option = None)
    ~(network : Consensus.network_config)
    ~(utxo : Utxo.UtxoSet.t) ~(current_height : int) () : mempool =
  { entries = Hashtbl.create 10_000;
    total_weight = 0;
    total_fee = 0L;
    (* DEFAULT_MAX_MEMPOOL_SIZE_MB * 1_000_000 — SI megabytes, not MiB.
       Reference: bitcoin-core/src/kernel/mempool_options.h:40
       Previous value was 300 * 1024 * 1024 = 314,572,800 (too large by ~4.9%). *)
    max_size_bytes = 300 * 1_000_000;
    (* DEFAULT_MIN_RELAY_TX_FEE = 100 sat/kvB.
       Reference: bitcoin-core/src/policy/policy.h:70.
       Previous value was 1000 sat/kvB (10x Core's default). The dust
       threshold is intentionally NOT coupled to this floor — dust uses the
       separate dust_relay_fee = 3000 (DUST_RELAY_TX_FEE), so lowering this
       admission/relay floor does NOT drop the dust limit (Core parity). *)
    min_relay_fee = 100L;
    dynamic_min_fee = 0L;
    rolling_min_fee_rate = 0.0;
    last_rolling_fee_update = Unix.gettimeofday ();
    block_since_last_rolling_fee_bump = false;
    utxo;
    current_height;
    network;
    current_median_time = 0l;
    require_standard;
    verify_scripts;
    orphans = Hashtbl.create 100;
    orphan_by_txid = Hashtbl.create 100;
    max_orphans = 100;
    map_next_tx = Hashtbl.create 10_000;
    zmq_sequence = 0L;
    zmq_notifier;
    on_eviction;
    (* FIX-72: prioritisetransaction deltas, in-memory only. *)
    map_deltas = Hashtbl.create 64;
    (* #135 step 1: reverse parent→children index, sized for typical mempool. *)
    children = Hashtbl.create 10_000; }

(* ============================================================================
   Basic Queries
   ============================================================================ *)

(* Expose internal entries table for testing (allows direct injection of fake entries
   to stress-test cluster limits without needing to bypass ancestor/descendant checks). *)
let get_entries (mp : mempool) : (string, mempool_entry) Hashtbl.t = mp.entries

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
    (* Notify fee estimator — mirrors Core's TransactionRemovedFromMempool hook.
       Called for every removal: eviction, expiry, RBF conflict, block inclusion.
       Fee_estimation.record_eviction is a no-op for txids not in tracked_txs,
       so block-confirmed txs (already removed via process_block→record_confirmation)
       are silently skipped. *)
    (match mp.on_eviction with
     | Some cb -> cb entry.txid
     | None -> ());
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
        ancestor_entry.descendant_count <- max 0 (ancestor_entry.descendant_count - 1);
        ancestor_entry.descendant_size <- max 0 (ancestor_entry.descendant_size - vsize);
        List.iter (fun gp_txid ->
          let gp_key = Cstruct.to_string gp_txid in
          if not (Hashtbl.mem visited gp_key) then begin
            Hashtbl.replace visited gp_key ();
            Queue.push gp_key queue
          end
        ) ancestor_entry.depends_on
    done;
    Hashtbl.remove mp.entries txid_key;
    (* #135 step 1: remove this tx from the children-set of each parent in
       the reverse children index. *)
    List.iter (fun parent_txid ->
      let parent_key = Cstruct.to_string parent_txid in
      match Hashtbl.find_opt mp.children parent_key with
      | None -> ()
      | Some s ->
        Hashtbl.remove s txid_key;
        if Hashtbl.length s = 0 then Hashtbl.remove mp.children parent_key
    ) entry.depends_on;
    mp.total_weight <- mp.total_weight - entry.weight;
    mp.total_fee <- Int64.sub mp.total_fee entry.fee;
    List.iter (fun inp ->
      let out_key = (Cstruct.to_string inp.Types.previous_output.txid,
                     inp.Types.previous_output.vout) in
      Hashtbl.remove mp.map_next_tx out_key
    ) entry.tx.inputs;
    (* #135 step 1: O(D) via reverse children index instead of O(N·D) over
       all mp.entries. The children-set was already cleaned of THIS txid
       above, so we read its remaining children (txs that still depend on
       us, which we recursively remove). *)
    let dependent_txids =
      match Hashtbl.find_opt mp.children txid_key with
      | None -> []
      | Some s ->
        let children_keys = Hashtbl.fold (fun k () acc -> k :: acc) s [] in
        List.filter_map (fun child_key ->
          match Hashtbl.find_opt mp.entries child_key with
          | Some child_entry -> Some child_entry.txid
          | None -> None
        ) children_keys
    in
    (* Clear the now-orphaned children entry for this parent. *)
    Hashtbl.remove mp.children txid_key;
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

(* Get all descendants of a transaction (transactions that depend on it).
   #135 step 1: O(D) via the reverse children index in mp.children. The
   prior implementation did Hashtbl.fold over all mp.entries per recursion
   step — O(N·D) total, which at 50k-entry mempools and 100-tx clusters
   was ~5M comparisons per call (the dominant cost in replace_by_fee). *)
let get_descendants (mp : mempool) (txid : Types.hash256)
    : mempool_entry list =
  let rec collect visited txid =
    let txid_key = Cstruct.to_string txid in
    if Hashtbl.mem visited txid_key then []
    else begin
      Hashtbl.add visited txid_key ();
      (* O(D): look up direct children from the reverse index. *)
      let children =
        match Hashtbl.find_opt mp.children txid_key with
        | None -> []
        | Some s ->
          Hashtbl.fold (fun child_key () acc ->
            match Hashtbl.find_opt mp.entries child_key with
            | Some entry -> entry :: acc
            | None -> acc
          ) s []
      in
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
   Rolling Minimum Fee — exponential decay after blocks
   Reference: Bitcoin Core txmempool.cpp:829-859
   ============================================================================ *)

(* track_package_removed — update rolling_min_fee_rate when a chunk is evicted.
   Only raises the floor (never lowers it here).  Clears blockSinceLastRollingFeeBump
   so the decay timer is reset.
   Reference: Bitcoin Core txmempool.cpp:853-859
     if (rate.GetFeePerK() > rollingMinimumFeeRate) {
         rollingMinimumFeeRate = rate.GetFeePerK();
         blockSinceLastRollingFeeBump = false; } *)
let track_package_removed (mp : mempool) (evicted_fee_rate_kvb : float) : unit =
  if evicted_fee_rate_kvb > mp.rolling_min_fee_rate then begin
    mp.rolling_min_fee_rate <- evicted_fee_rate_kvb;
    mp.block_since_last_rolling_fee_bump <- false
  end

(* get_min_fee — return the current minimum fee rate, applying exponential decay.
   Reference: Bitcoin Core txmempool.cpp:829-851
   Half-life is 12h (43200s); halved to 6h when pool < 1/2 full, halved again to
   3h when pool < 1/4 full.  Decay is only applied when blockSinceLastRollingFeeBump
   is true (a block was connected since the last eviction bump).
   Returns max(decayed_rolling_rate, incremental_relay_fee) in sat/kvB. *)
let get_min_fee (mp : mempool) : int64 =
  if (not mp.block_since_last_rolling_fee_bump) || mp.rolling_min_fee_rate = 0.0 then
    (* No decay active: return the current rolling rate directly (rounded). *)
    Int64.of_float (Float.round mp.rolling_min_fee_rate)
  else begin
    let now = Unix.gettimeofday () in
    if now > mp.last_rolling_fee_update +. 10.0 then begin
      (* Apply exponential decay with conditional halflife adjustment.
         Reference: txmempool.cpp:836-843 *)
      let halflife =
        let usage = mp.total_weight in
        let limit = mp.max_size_bytes in
        if usage < limit / 4 then rolling_fee_halflife /. 4.0
        else if usage < limit / 2 then rolling_fee_halflife /. 2.0
        else rolling_fee_halflife
      in
      let elapsed = now -. mp.last_rolling_fee_update in
      mp.rolling_min_fee_rate <-
        mp.rolling_min_fee_rate /. (2.0 ** (elapsed /. halflife));
      mp.last_rolling_fee_update <- now;
      (* Clear to zero once it falls below incremental_relay_fee / 2.
         Reference: txmempool.cpp:845-848 *)
      if mp.rolling_min_fee_rate < incremental_relay_fee_float /. 2.0 then begin
        mp.rolling_min_fee_rate <- 0.0;
        0L
      end else
        Int64.of_float (max mp.rolling_min_fee_rate incremental_relay_fee_float)
    end else
      Int64.of_float (max mp.rolling_min_fee_rate incremental_relay_fee_float)
  end

(* ============================================================================
   Cluster-Based Eviction

   Evict the lowest-fee-rate chunk when mempool exceeds the size limit.
   Reference: Bitcoin Core txmempool.cpp:861-911 (TrimToSize)
   ============================================================================ *)

(* evict_by_chunks — evict lowest-fee-rate chunks until total_weight <= max_size_bytes.
   Uses track_package_removed to maintain the rolling floor.
   Reference: Core TrimToSize evicts until DynamicMemoryUsage() <= sizelimit (full limit,
   not 75%).  The per-chunk feerate floor is raised by incremental_relay_fee each round.
   Reference: txmempool.cpp:877-878 — removed += incremental_relay_feerate before track.

   2026-07-01 GC-churn fix (un-pin attempt #3 post-mortem): the old loop called
   [get_worst_chunk] PER EVICTED CHUNK, and get_worst_chunk = get_all_chunks =
   whole-pool union-find + cluster grouping + per-cluster linearization + a full
   sort — all rebuilt from scratch, allocating multiple MB, to pick ONE chunk.
   Once the pool sits at its 300 MB cap (exactly the public-mempool-flood
   regime), eviction runs on ~every accept, so the per-accept garbage was
   O(pool) and the OCaml major heap inflated at ~300 MB/s — faster than the
   incremental collector's pacing — driving the 2500 MB backstop ceiling and a
   1.2-1.4 s STW Gc.compact every ~8 s (the residual RPC stall of the
   2026-07-01 soak).  Fixed by (a) building the chunk list ONCE per trim and
   evicting worst-first from it, and (b) a small overshoot slack at the
   add_transaction trigger (see there) so trims are batched.

   Evicting ascending from one snapshot is equivalent to the old
   re-linearize-per-round loop: within a cluster, [linearize_cluster] emits
   chunks in non-increasing feerate order, so the globally-worst remaining
   chunk is always a not-yet-evicted suffix chunk of its cluster, and removing
   it never changes the linearization of the chunks before it.  A chunk whose
   txs were already removed as descendants of an earlier evicted chunk is
   skipped (remove_transaction on a missing txid is a no-op; the floor is only
   bumped for chunks that still evict something). *)
let evict_by_chunks (mp : mempool) : unit =
  if mp.total_weight > mp.max_size_bytes then begin
    (* Single structure rebuild per trim; get_all_chunks sorts descending, so
       walk the reversed list (worst chunk first). *)
    let worst_first = List.rev (get_all_chunks mp) in
    let rec evict_loop chunks =
      if mp.total_weight <= mp.max_size_bytes then ()
      else match chunks with
        | [] -> ()
        | chunk :: rest ->
          (* Skip members already removed (descendant cascade of an earlier
             evicted chunk); only bump the rolling floor when this chunk
             actually evicts something, matching the old per-round behavior. *)
          let live =
            List.filter
              (fun e -> Hashtbl.mem mp.entries (Cstruct.to_string e.txid))
              chunk.chunk_txs
          in
          if live <> [] then begin
            (* chunk_fee_rate is in sat/weight-unit; convert to sat/kvB for the
               rolling fee.  1 sat/wu * 4 wu/vB * 1000 vB/kvB. *)
            let evicted_fee_rate_kvb = chunk.chunk_fee_rate *. 4.0 *. 1000.0 in
            (* Add incremental_relay_fee before updating the floor, so the floor
               is strictly above the just-evicted rate (Core txmempool.cpp:877-878). *)
            let floor_rate = evicted_fee_rate_kvb +. incremental_relay_fee_float in
            track_package_removed mp floor_rate;
            List.iter (fun e -> remove_transaction mp e.txid) live
          end;
          evict_loop rest
    in
    evict_loop worst_first
  end

(* Overshoot slack before a trim is triggered from the accept hot path.
   Core's TrimToSize is O(log n) per eviction (multi-indexed mempool), so it
   trims on every accept; camlcoin's chunk-based trim rebuilds the cluster
   linearization (O(pool)), so triggering it per-accept at the cap is the GC
   churn documented above.  Allowing the pool to overshoot the cap by ~1.6 %
   (300 MB → ≤ ~304.7 MB) batches ~thousands of accepts per rebuild; each trim
   still evicts back down to max_size_bytes exactly.  Memory stays bounded by
   cap + slack.  Policy-only (mempool contents; non-consensus). *)
let eviction_trigger_slack (mp : mempool) : int =
  mp.max_size_bytes / 64

(* effective_min_fee — the minimum fee rate (sat/kvB) a new transaction must meet.
   Uses the rolling exponential-decay model from get_min_fee, then takes the max
   with the static min_relay_fee.
   Reference: Core callers of GetMinFee pass the full sizelimit; min is raised by
   rolling eviction history and decays back down after blocks. *)
let effective_min_fee (mp : mempool) : int64 =
  let rolling = get_min_fee mp in
  Int64.max mp.min_relay_fee rolling

(* ============================================================================
   Cluster Size Limit Check

   Enforces both cluster count and cluster vsize limits.
   Reference: Bitcoin Core txmempool.cpp CTxMemPool::CTxMemPool() lines 179-181;
   kernel/mempool_limits.h MemPoolLimits::cluster_count + cluster_size_vbytes;
   policy/policy.h DEFAULT_CLUSTER_LIMIT=64, DEFAULT_CLUSTER_SIZE_LIMIT_KVB=101.

   Core enforces:
     max_cluster_count=64   — no more than 64 txs in one connected cluster
     max_cluster_size=101_000 vbytes — cluster total vsize ≤ 101 kvB
   ============================================================================ *)

(* Check if adding a transaction would exceed either cluster limit.
   [new_tx_weight] is the weight of the new transaction being added; used to
   compute its vsize contribution to the merged cluster total.

   2026-07-01 GC-churn fix (un-pin attempt #3 post-mortem): the old
   implementation built a union-find over the ENTIRE mempool
   (build_clusters_uf) plus a full Hashtbl.fold — O(pool) time AND O(pool)
   allocation — on EVERY accept that has an in-mempool parent.  Under the
   public-mempool flood this was a major contributor (with the per-accept
   eviction rebuild, see evict_by_chunks) to the ~300 MB/s major-heap churn
   behind the residual RPC stall.  A cluster is just the connected component
   of the parent/child graph, and it is BOUNDED by these very limits (64 txs /
   101 kvB), so a local BFS from the new tx's in-pool parents over
   depends_on + the [mp.children] reverse index, with early exit as soon as a
   limit is exceeded, computes the identical accept/reject decision in
   O(cluster) ≤ O(65) instead of O(pool).

   Note on the error text: with early exit the reported count/vsize is the
   value at the first violation (e.g. "65 > 64"), not the full merged-cluster
   total the old code printed.  The accept/reject DECISION is unchanged; the
   reason tag ("too-large-cluster") is unchanged. *)
let check_cluster_size_limit ?(new_tx_weight=0) (mp : mempool)
    (depends : Types.hash256 list) (new_txid : Types.hash256)
    : (unit, string) result =
  ignore new_txid;
  if depends = [] then
    (* No dependencies — would form a singleton cluster of size 1.
       Singleton always passes both count (1 ≤ 64) and size limits. *)
    Ok ()
  else begin
    let new_tx_vsize = (new_tx_weight + 3) / 4 in
    (* BFS over the union of the parents' connected components (= the merged
       cluster after adding the new tx).  The new tx itself contributes
       1 tx / new_tx_vsize; it has no children yet, and its only in-pool
       edges are [depends]. *)
    let visited : (string, unit) Hashtbl.t =
      Hashtbl.create (max_cluster_count * 2) in
    let queue = Queue.create () in
    let push key =
      if Hashtbl.mem mp.entries key && not (Hashtbl.mem visited key) then begin
        Hashtbl.replace visited key ();
        Queue.push key queue
      end
    in
    List.iter (fun parent_txid -> push (Cstruct.to_string parent_txid)) depends;
    let cluster_count = ref 1 in           (* the new tx itself *)
    let cluster_vsize = ref new_tx_vsize in
    let violation = ref None in
    while !violation = None && not (Queue.is_empty queue) do
      let key = Queue.pop queue in
      (match Hashtbl.find_opt mp.entries key with
       | None -> ()
       | Some entry ->
         incr cluster_count;
         cluster_vsize := !cluster_vsize + (entry.weight + 3) / 4;
         (* Gate 1: cluster transaction count limit (DEFAULT_CLUSTER_LIMIT = 64) *)
         if !cluster_count > max_cluster_count then
           violation := Some (Printf.sprintf
             "cluster tx count limit exceeded (%d > %d); too-large-cluster"
             !cluster_count max_cluster_count)
         (* Gate 2: cluster vsize limit (DEFAULT_CLUSTER_SIZE_LIMIT_KVB * 1000) *)
         else if !cluster_vsize > max_cluster_size_vbytes then
           violation := Some (Printf.sprintf
             "cluster vsize limit exceeded (%d > %d vbytes); too-large-cluster"
             !cluster_vsize max_cluster_size_vbytes)
         else begin
           (* Expand the component: in-pool parents ... *)
           List.iter
             (fun p -> push (Cstruct.to_string p))
             entry.depends_on;
           (* ... and in-pool children (reverse index, #135 step 1). *)
           (match Hashtbl.find_opt mp.children key with
            | None -> ()
            | Some children_set ->
              Hashtbl.iter (fun child_key () -> push child_key) children_set)
         end)
    done;
    match !violation with
    | Some e -> Error e
    | None -> Ok ()
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

(* Spending cost (in vbytes) of the CTxIn needed to redeem an output, faithful
   to Core GetDustThreshold (policy/policy.cpp:46-61). This is a binary choice,
   NOT a per-script-type table: every witness program (P2WPKH/P2WSH/P2TR and any
   unknown-version witness program — Core's IsWitnessProgram test) takes the
   75%-segwit-discounted 67 vbytes; everything else takes 148.
     witness:     32 + 4 + 1 + (107 / WITNESS_SCALE_FACTOR=4) + 4 = 67
     non-witness: 32 + 4 + 1 + 107 + 4                           = 148 *)
let dust_spending_cost (script_pubkey : Cstruct.t) : int =
  match Script.get_witness_program script_pubkey with
  | Some _ -> 32 + 4 + 1 + (107 / 4) + 4   (* = 67, segwit-discounted *)
  | None   -> 32 + 4 + 1 + 107 + 4          (* = 148 *)

(* Dust threshold (satoshis) for an output at the given dust relay fee rate
   (sat/kvB), faithful to Core GetDustThreshold (policy/policy.cpp:27-63):
     nSize     = GetSerializeSize(txout) + spending_cost
     threshold = dustRelayFee.GetFee(nSize) = CeilDiv(nSize * fee, 1000)
   Unspendable outputs (OP_RETURN, or scriptPubKey > MAX_SCRIPT_SIZE) can never
   be dust (Core: txout.scriptPubKey.IsUnspendable() => return 0). There is NO
   3x multiplier and NO P2A special-case: P2A is a witness program, so Core
   gives it spending_cost=67 and a real threshold of 240 sat (a P2A output
   below 240 is dust, 240+ is not). Integer ceil-div matches Core's CeilDiv;
   no float arithmetic. *)
let dust_threshold (dust_relay_fee : int64) (output : Types.tx_out) : int64 =
  let spk = output.Types.script_pubkey in
  let len = Cstruct.length spk in
  let is_unspendable =
    (len > 0 && Cstruct.get_uint8 spk 0 = 0x6a)  (* OP_RETURN *)
    || len > Script.max_script_size in
  if is_unspendable then 0L
  else begin
    let n_size =
      Int64.of_int (output_serialized_size output + dust_spending_cost spk) in
    (* CeilDiv(n_size * fee, 1000) *)
    let num = Int64.mul n_size dust_relay_fee in
    Int64.div (Int64.add num 999L) 1000L
  end

(* Check if an output is dust: value < dust_threshold. The fee argument is the
   DUST feerate (dust_relay_fee = 3000 sat/kvB, DUST_RELAY_TX_FEE), NOT the
   min-relay floor — Core's IsDust takes its own dustRelayFee CFeeRate. *)
let is_dust (dust_relay_fee : int64) (output : Types.tx_out) : bool =
  Int64.compare output.Types.value (dust_threshold dust_relay_fee output) < 0

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
        (* Walk pubkeys — each must be a push whose pushed-data length is a
           valid pubkey size (33 or 65).  Core's MatchMultisig (solver.cpp:
           97) reads each operand with CScript::GetOp (PUSHDATA-aware) and
           keeps it while CPubKey::ValidSize(data) holds.  So a pubkey may be
           pushed with a direct opcode (0x21 / 0x41) OR via OP_PUSHDATA1/2/4 —
           e.g. OP_PUSHDATA1 0x21 <33 bytes>.  We decode the push opcode in a
           PUSHDATA-aware way and validate the *pushed-data length*, mirroring
           the length component of CPubKey::ValidSize.  RELAY policy only. *)
        let i = ref 1 in
        let n = ref 0 in
        let bad = ref false in
        while not !bad && !i < len - 2 do
          let op = Cstruct.get_uint8 script !i in
          (* (data_offset_from_op, pk_len): data_offset includes the opcode
             byte and any length prefix.  pk_len = -1 ⇒ not a usable push. *)
          let data_off, pk_len =
            if op >= 0x01 && op <= 0x4b then
              (* direct push of [op] bytes *)
              (1, op)
            else if op = 0x4c (* OP_PUSHDATA1 *) then
              (if !i + 1 < len then (2, Cstruct.get_uint8 script (!i + 1))
               else (0, -1))
            else if op = 0x4d (* OP_PUSHDATA2 *) then
              (if !i + 2 < len then (3, Cstruct.LE.get_uint16 script (!i + 1))
               else (0, -1))
            else if op = 0x4e (* OP_PUSHDATA4 *) then
              (if !i + 4 < len then
                 (5, Int32.to_int (Cstruct.LE.get_uint32 script (!i + 1)))
               else (0, -1))
            else (0, -1)
          in
          (* Pushed-data length must be a valid pubkey size (33 or 65),
             matching CPubKey::ValidSize's length test. *)
          if pk_len <> 33 && pk_len <> 65 then bad := true
          else if !i + data_off + pk_len > len - 2 then bad := true
          else begin
            incr n;
            i := !i + data_off + pk_len
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
    (* WITNESS_UNKNOWN — a witness program of version >= 1 (future segwit
       versions) is a recognisable witness shape of unknown type.  Core's
       Solver (script/solver.cpp:172-176) returns TxoutType::WITNESS_UNKNOWN
       for witnessversion != 0, and IsStandard (policy/policy.cpp:80-98)
       returns true for every type except NONSTANDARD / out-of-range MULTISIG.
       So a v2..v16 witness program (and a v1 program of non-taproot,
       non-anchor shape) is relay-standard, NOT nonstandard.  Known v0/v1
       shapes (P2WPKH/P2WSH/P2TR/P2A) are already matched above; a v0 witness
       program of wrong size stays NONSTANDARD (Core: witnessversion == 0 with
       unrecognised size → NONSTANDARD), which is why this only triggers for
       version >= 1.  RELAY policy only — never consensus. *)
    else (match Script.get_witness_program script_pubkey with
      | Some (v, _) when v >= 1 -> true
      | _ ->
        (* Check bare multisig m-of-n with n <= 3 (Core policy limit) *)
        match decode_bare_multisig script_pubkey with
        | Some (m, n) -> n >= 1 && n <= 3 && m >= 1 && m <= n
        | None -> false)

(* Count UTXO-aware sigops cost for a mempool transaction.
   Delegates to Validation.count_tx_sigops_cost which correctly implements
   Bitcoin Core's GetTransactionSigOpCost (tx_verify.cpp:143-162):
     legacy sigops × WITNESS_SCALE_FACTOR
   + P2SH sigops × WITNESS_SCALE_FACTOR  (guarded by P2SH flag, checks prevout)
   + witness sigops × 1                  (guarded by WITNESS flag, checks prevout)

   Requires a UTXO lookup closure so that P2SH and witness sigops can be
   attributed to the correct input type.  Inputs whose prevout is not found
   (e.g. unconfirmed parents not yet in the UTXO set) contribute 0 P2SH /
   witness sigops; their legacy sigops are still counted. *)
let count_tx_sigops_cost_for_mempool (tx : Types.transaction)
    (mp : mempool) : int =
  let prev_script_pubkey_lookup op =
    match lookup_utxo mp op with
    | Some e -> Some e.Utxo.script_pubkey
    | None -> None
  in
  let flags = Script.script_verify_p2sh lor Script.script_verify_witness in
  Validation.count_tx_sigops_cost tx ~prev_script_pubkey_lookup ~flags

(* Public alias used by mining.ml.
   Counts sigops for a transaction that is already in the mempool pool
   (its prevouts are accessible via the UTXO set). *)
let count_tx_sigops_cost (tx : Types.transaction) (mp : mempool) : int =
  count_tx_sigops_cost_for_mempool tx mp

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

(* ValidateInputsStandardness — per-input prevout-type and P2SH-sigops check.
   Reference: Bitcoin Core policy/policy.cpp:214-263.

   Called after IsStandardTx and BEFORE IsWitnessStandard, guarded by
   require_standard.  Three gates per Core:

     Gate 1 — NONSTANDARD prevout type → "bad-txns-nonstandard-inputs"
               Spends of genuinely nonstandard scriptPubKeys are rejected.
               In camlcoin, classify_script returns Nonstandard for these AND
               for WITNESS_UNKNOWN scripts, so gate 1 and gate 2 are
               distinguished by whether get_witness_program also matches.

     Gate 2 — WITNESS_UNKNOWN prevout → "bad-txns-nonstandard-inputs"
               Witness programs with unrecognised version/size (e.g. v2..v16,
               or v1 with ≠32-byte data, or v0 with ≠20/32-byte data) are
               reserved as upgrade hooks and rejected at relay.  In camlcoin
               these scripts are Nonstandard but get_witness_program returns
               Some, distinguishing them from gate-1 rejections.

     Gate 3 — P2SH prevout with redeemScript sigops > MAX_P2SH_SIGOPS (15)
               → "bad-txns-nonstandard-inputs"
               The last push item in the scriptSig is the redeemScript.
               Its legacy sigop count (accurate, with OP_n context) must not
               exceed 15.  Empty-scriptSig P2SH inputs are also rejected here
               because there is no redeemScript to inspect.

   Coinbase transactions are exempt (Core returns valid state immediately).
   Takes a ~lookup callback so it can be used from both add_transaction and
   unit tests. *)
let validate_inputs_standardness
    ~(lookup : Types.outpoint -> Cstruct.t option)
    (tx : Types.transaction)
    : (unit, string) result =
  (* Coinbases are exempt — same first check as Core. *)
  let first_input = List.hd tx.inputs in
  if Cstruct.equal first_input.Types.previous_output.txid Types.zero_hash then
    Ok ()
  else begin
    let error = ref None in
    List.iteri (fun i inp ->
      if !error = None then begin
        match lookup inp.Types.previous_output with
        | None ->
          (* Prevout not found — skip; script verification will catch it. *)
          ()
        | Some prev_script ->
          begin match Script.classify_script prev_script with
          | Script.Nonstandard ->
            (* Distinguish WITNESS_UNKNOWN (a recognisable witness program in an
               unspecified version/size slot) from a truly nonstandard script. *)
            begin match Script.get_witness_program prev_script with
            | Some _ ->
              (* Gate 2: WITNESS_UNKNOWN — a witness program of unknown version
                 or unsupported size.  Reserved for future upgrades; reject now
                 so we don't relay unvalidatable scripts. *)
              error := Some (Printf.sprintf
                "bad-txns-nonstandard-inputs: input %d witness program is undefined" i)
            | None ->
              (* Gate 1: genuinely nonstandard scriptPubKey. *)
              error := Some (Printf.sprintf
                "bad-txns-nonstandard-inputs: input %d script unknown" i)
            end
          | Script.P2SH_script _ ->
            (* Gate 3: P2SH — extract redeemScript (last push of scriptSig)
               and check its legacy sigop count against MAX_P2SH_SIGOPS.
               Reference: policy.cpp:241-258, CScript::GetSigOpCount(true). *)
            begin match Validation.extract_last_push_data inp.Types.script_sig with
            | None ->
              (* Missing or empty redeemScript — reject. *)
              error := Some (Printf.sprintf
                "bad-txns-nonstandard-inputs: input %d P2SH redeemscript missing" i)
            | Some redeem_script ->
              let sigops = Validation.count_p2sh_sigops redeem_script in
              if sigops > max_p2sh_sigops then
                error := Some (Printf.sprintf
                  "bad-txns-nonstandard-inputs: p2sh redeemscript sigops exceed limit \
                   (input %d: %d > %d)" i sigops max_p2sh_sigops)
            end
          | _ ->
            (* All other standard types (P2PKH, P2WPKH, P2WSH, P2TR, P2A,
               OP_RETURN) pass without further checks here. *)
            ()
          end
      end
    ) tx.inputs;
    match !error with
    | Some e -> Error e
    | None -> Ok ()
  end

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
(* The first parameter is kept for call-site stability (tests pass a feerate
   positionally) but is no longer consulted: the dust gate below uses the
   dedicated module constant dust_relay_fee (3000), decoupled from the relay
   floor, per Core IsStandardTx(..., dust_relay_fee, ...). *)
let is_standard_tx (_min_relay_fee : int64) (tx : Types.transaction) : (unit, string) result =
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
               Count dust outputs and reject if more than 1.
               Uses the dedicated dust_relay_fee (3000), NOT the relay floor
               (min_relay_fee), matching Core IsStandardTx(..., dust_relay_fee, ...). *)
            let dust_count = List.fold_left (fun acc out ->
              if is_dust dust_relay_fee out then acc + 1 else acc
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

(* Check TRUC/v3 policy constraints for a transaction.
   [vsize] must be the sigop-adjusted virtual size (use
   Validation.get_virtual_transaction_size), matching Core's SingleTRUCChecks
   which also receives the sigop-adjusted vsize.

   Gate order mirrors Bitcoin Core truc_policy.cpp:SingleTRUCChecks:
     1. Inheritance: non-v3 cannot spend v3, v3 cannot spend non-v3.
     2. (v3 only) TRUC_MAX_VSIZE: vsize ≤ 10,000 vbytes.
     3. (v3 only) TRUC_ANCESTOR_LIMIT: direct unconfirmed parents ≤ 1.
     4. (v3 with unconfirmed parents) grandparent check via parent's ancestor count.
     5. (v3 with unconfirmed parents) TRUC_CHILD_MAX_VSIZE: vsize ≤ 1,000 vbytes.
     6. (v3 with unconfirmed parents) TRUC_DESCENDANT_LIMIT: parent's descendant
        count + 1 ≤ 2.

   Reference: bitcoin-core/src/policy/truc_policy.cpp:171-261. *)
let check_truc_policy (mp : mempool) (tx : Types.transaction)
    (depends : Types.hash256 list) (vsize : int) : (unit, string) result =
  let is_v3 = is_truc_tx tx in

  (* Gate 1 (ALL transactions): version-inheritance check.
     Core truc_policy.cpp:178-191. *)
  let inheritance_error = ref None in
  List.iter (fun parent_txid ->
    if !inheritance_error = None then begin
      match Hashtbl.find_opt mp.entries (Cstruct.to_string parent_txid) with
      | None -> ()  (* confirmed parent — no version constraint *)
      | Some parent_entry ->
        let parent_is_v3 = is_truc_tx parent_entry.tx in
        if (not is_v3) && parent_is_v3 then
          inheritance_error := Some
            "Non-v3 transaction cannot spend unconfirmed v3 outputs"
        else if is_v3 && (not parent_is_v3) then
          inheritance_error := Some
            "TRUC/v3 transaction cannot spend from unconfirmed non-v3 transaction"
    end
  ) depends;

  match !inheritance_error with
  | Some e -> Error e
  | None ->

  (* Remaining gates only apply to v3 transactions. *)
  if not is_v3 then Ok ()
  else begin
    (* Gate 2 (v3): TRUC_MAX_VSIZE — 10,000 sigop-adjusted vbytes.
       Core truc_policy.cpp:200-204. *)
    if vsize > truc_max_vsize then
      Error (Printf.sprintf
        "TRUC/v3 transaction too large: %d vbytes > %d limit"
        vsize truc_max_vsize)

    else begin
      (* Gate 3 (v3): TRUC_ANCESTOR_LIMIT — at most 1 direct unconfirmed parent.
         Core truc_policy.cpp:207-211:
           if mempool_parents.size() + 1 > TRUC_ANCESTOR_LIMIT  *)
      let direct_parent_count = List.length depends in
      if direct_parent_count + 1 > truc_ancestor_limit then
        Error (Printf.sprintf
          "TRUC/v3 transaction has too many unconfirmed ancestors (%d > %d)"
          (direct_parent_count + 1) truc_ancestor_limit)

      else if depends = [] then
        (* v3 root (no unconfirmed parents): all gates passed. *)
        Ok ()

      else begin
        (* has_unconfirmed_parents = true from here on.
           Exactly 1 direct unconfirmed parent (gate 3 enforces this). *)
        let parent_txid = List.hd depends in
        match Hashtbl.find_opt mp.entries (Cstruct.to_string parent_txid) with
        | None ->
          (* Parent not in mempool anymore — should not happen since depends
             is built from mempool lookups; treat as no constraint. *)
          Ok ()
        | Some parent_entry ->
          (* Gate 4 (v3 child): parent's ancestor count + 1 must not exceed limit.
             This rejects grandparent chains.
             Core truc_policy.cpp:215-220:
               if pool.GetAncestorCount(mempool_parents[0]) + 1 > TRUC_ANCESTOR_LIMIT
             GetAncestorCount includes the parent itself, so parent has 0
             unconfirmed ancestors ⟹ count=1, 1+1=2≤2 ✓.
             Parent has 1 unconfirmed grandparent ⟹ count=2, 2+1=3>2 ✗. *)
          let parent_ancestor_count = List.length parent_entry.depends_on + 1 in
          if parent_ancestor_count + 1 > truc_ancestor_limit then
            Error (Printf.sprintf
              "TRUC/v3 transaction would have too many ancestors \
               (parent already has %d ancestors)" parent_ancestor_count)

          else begin
            (* Gate 5 (v3 child): TRUC_CHILD_MAX_VSIZE — 1,000 sigop-adjusted vbytes.
               Core truc_policy.cpp:222-227. *)
            if vsize > truc_child_max_vsize then
              Error (Printf.sprintf
                "TRUC/v3 child transaction too large: %d vbytes > %d limit"
                vsize truc_child_max_vsize)

            else begin
              (* Gate 6 (v3 child): TRUC_DESCENDANT_LIMIT — parent can have at most
                 1 child (descendant_count including itself must stay ≤ 2).
                 Core truc_policy.cpp:229-258.
                 We use the cached descendant_count on the parent entry:
                   parent.descendant_count + 1 > TRUC_DESCENDANT_LIMIT
                 descendant_count includes the parent itself, so:
                   0 children ⟹ count=1, 1+1=2≤2 ✓
                   1 child    ⟹ count=2, 2+1=3>2 ✗ *)
              if parent_entry.descendant_count + 1 > truc_descendant_limit then
                Error (Printf.sprintf
                  "TRUC/v3 parent %s already has an unconfirmed child \
                   (descendant count %d would exceed limit %d)"
                  (Types.hash256_to_hex_display parent_txid)
                  (parent_entry.descendant_count + 1)
                  truc_descendant_limit)
              else
                Ok ()
            end
          end
      end
    end
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
(* W96 Bug 12 helper: TX_WITNESS_STRIPPED detection — when a tx that should
   have a witness (its input scripts are witness programs) was relayed without
   one, peer should re-fetch with witness.  Detect via prev script pubkey +
   empty witness on that input.  Anchor (P2A) spends are exempt — they are
   valid without a witness. *)
let spends_non_anchor_witness_prog (mp : mempool) (tx : Types.transaction) : bool =
  let result = ref false in
  List.iteri (fun i inp ->
    if not !result then
      match lookup_utxo mp inp.Types.previous_output with
      | None -> ()
      | Some entry ->
        if Script.is_p2a entry.Utxo.script_pubkey then ()
        else match Script.get_witness_program entry.Utxo.script_pubkey with
        | None -> ()
        | Some _ ->
          if i >= List.length tx.witnesses ||
             (List.nth tx.witnesses i).Types.items = []
          then result := true
  ) tx.inputs;
  !result

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
  | Some e ->
    (* W96 Bug 12: TX_WITNESS_STRIPPED detection.  Core PolicyScriptChecks
       (validation.cpp:1147-1151) checks `!tx.HasWitness() &&
       SpendsNonAnchorWitnessProg(tx, m_view)` and re-tags the error as
       TX_WITNESS_STRIPPED so the p2p layer can request the tx WITH witness
       from a peer.  Without this signal, peers cache the bad tx without
       knowing to retry, hurting block-relay resilience. *)
    let has_witness = List.exists (fun w -> w.Types.items <> []) tx.witnesses in
    if not has_witness && spends_non_anchor_witness_prog mp tx then
      Error (Printf.sprintf "witness-stripped: %s" e)
    else
      Error e
  | None -> Ok ()

(* Bug #135 step 2: Lwt-flavoured script verification that delegates the
   per-input ECDSA/Schnorr/witness evaluation to
   [Validation.verify_scripts_parallel], which fans the work out across
   OCaml 5 Domains and returns a `(unit, _) result Lwt.t`.

   This is the script-verify entry point used by the Lwt ATMP wrapper
   ([accept_transaction_lwt] / [accept_to_memory_pool]).  Behaviour MUST
   match the sync [verify_tx_scripts] above bit-for-bit on the
   accept/reject decision — the only difference is *how* the work is
   scheduled (Domain workers + an Lwt.pause yield instead of a sequential
   List.iteri on the Lwt main thread).  Specifically:

   1. Pre-pass: per-input P2A witness-stuffing policy gate.  P2A spends
      must have an empty witness; otherwise reject with the exact same
      error string the sync path produces.  This is a policy check that
      lives *outside* the consensus script evaluator, so we keep it here
      and short-circuit before fanning out to Domains.
   2. Build [utxos : utxo option array] from [lookup_utxo].  Missing
      inputs propagate as [None] and are mapped to the same
      "Missing input for script verification" error string the sync
      path emits, in input-index order.
   3. Build the [prevouts] list (Taproot sighash dependency) — same
      shape as the sync path.
   4. Hand off to [Validation.verify_scripts_parallel] which runs the
      Domain workers and returns the first failure.
   5. Post-pass: on error, re-check the TX_WITNESS_STRIPPED condition
      via [spends_non_anchor_witness_prog] and wrap the error so the
      P2P layer can re-request the witness — identical to sync. *)
let verify_tx_scripts_lwt (mp : mempool) (tx : Types.transaction)
    : (unit, string) result Lwt.t =
  let flags =
    Consensus.get_standard_policy_flags (mp.current_height + 1) mp.network in

  (* 2026-07-02 at-tip RPC-stall fix (un-pin soak #4 — see
     CORE-PARITY-AUDIT/_camlcoin-gc-rpc-stall-rootcause-2026-06-24.md follow-up):
     the multi-second RPC stalls that failed the soak are NOT GC (stw_cum=0,
     RSS flat) — they are the single Lwt/RPC domain being blocked by the
     SYNCHRONOUS UTXO reads on the mempool-accept path.  [lookup_utxo] →
     Utxo.UtxoSet.get is a DIRECT RocksDB point read (utxo.ml: "no in-process
     caching … prevents unbounded GC heap growth" — which is exactly why RSS
     stays flat), and caml_rocksdb_get holds the OCaml runtime lock for the read.
     The old body did THREE separate O(inputs) lookup passes (prevouts, P2A,
     utxos) with NO cooperative yield, so a large-input tx — or a public-flood
     backlog of many accepts — storms the RocksDB reads and freezes the Cohttp
     RPC callback (another promise on this same domain) for the whole run.

     Fix (pure scheduling + read-dedup; the derived prevouts/p2a_error/utxos are
     bit-identical to the previous three-pass version, so the accept/reject
     decision is unchanged):
       (1) ONE lookup_utxo per input instead of three  → 3× fewer synchronous
           RocksDB reads on the loop; and
       (2) [Lwt.pause] every [atmp_yield_every] inputs so no single accept
           monopolises the event loop while it reads — bounding the worst-case
           synchronous stretch (and thus the RPC stall) to that many reads.
     The bounded-in-flight gate on the P2P relay path (cli.ml) bounds the
     AGGREGATE flood; this bounds a single large-input tx. *)
  let inputs = Array.of_list tx.inputs in
  let witnesses = Array.of_list tx.witnesses in
  let n = Array.length inputs in
  let utxos = Array.make n None in
  let prevouts_arr = Array.make n (0L, Cstruct.empty) in
  let p2a_error = ref None in
  let rec pass i =
    if i >= n then Lwt.return_unit
    else begin
      let inp = inputs.(i) in
      let prev = inp.Types.previous_output in
      (match lookup_utxo mp prev with
       | None -> ()  (* utxos.(i) stays None (missing-input rejection is produced
                        by the utxos[] None branch inside the verifier); prevout
                        stays (0L, empty) to match the sync path. *)
       | Some e ->
         prevouts_arr.(i) <- (e.Utxo.value, e.Utxo.script_pubkey);
         utxos.(i) <- Some {
           Validation.txid = prev.txid;
           vout = prev.vout;
           value = e.Utxo.value;
           script_pubkey = e.Utxo.script_pubkey;
           height = e.Utxo.height;
           is_coinbase = e.Utxo.is_coinbase;
         };
         (* P2A witness-stuffing pre-pass: first violation in input order wins
            (identical to the old separate pass). *)
         if !p2a_error = None then begin
           let witness =
             if i < Array.length witnesses then witnesses.(i)
             else { Types.items = [] }
           in
           if Script.is_p2a e.Utxo.script_pubkey &&
              witness.Types.items <> [] then
             p2a_error := Some (Printf.sprintf
               "P2A input %d has non-empty witness (witness stuffing)" i)
         end);
      if atmp_yield_every > 0 && (i + 1) mod atmp_yield_every = 0 then
        let%lwt () = Lwt.pause () in pass (i + 1)
      else pass (i + 1)
    end
  in
  let%lwt () = pass 0 in
  let prevouts = Array.to_list prevouts_arr in

  (* Wrap helper that adds the TX_WITNESS_STRIPPED tag when applicable. *)
  let tag_witness_stripped (e : string) : string =
    let has_witness =
      List.exists (fun w -> w.Types.items <> []) tx.witnesses in
    if not has_witness && spends_non_anchor_witness_prog mp tx then
      Printf.sprintf "witness-stripped: %s" e
    else e
  in

  match !p2a_error with
  | Some e -> Lwt.return (Error (tag_witness_stripped e))
  | None ->
    let%lwt result =
      Validation.verify_scripts_parallel ~tx ~flags ~prevouts ~utxos in
    match result with
    | Ok () -> Lwt.return (Ok ())
    | Error (Validation.TxScriptFailed (i, msg)) ->
      (* Re-shape the error to match the sync path's wording so callers
         (and tests asserting on substring matches) remain stable.
         Mirror the three branches of sync [verify_tx_scripts]:
           "missing input"           → "Missing input for script verification: %d"
           "Script returned false"   → "Script returned false for input %d"
           anything else (script err)→ "Script verification failed for input %d: %s" *)
      let mapped =
        if msg = "missing input" then
          Printf.sprintf "Missing input for script verification: %d" i
        else if msg = "Script returned false" then
          Printf.sprintf "Script returned false for input %d" i
        else
          Printf.sprintf "Script verification failed for input %d: %s" i msg
      in
      Lwt.return (Error (tag_witness_stripped mapped))
    | Error other ->
      Lwt.return (Error (tag_witness_stripped
        (Validation.tx_error_to_string other)))

(* ============================================================================
   Transaction Addition
   ============================================================================ *)

(* Validate and add a transaction to the mempool.
   When ~dry_run:true, all validation is performed but the transaction
   is not actually inserted into the mempool.

   Bug #135 step 2: [~skip_verify_scripts:true] suppresses the internal
   [verify_tx_scripts] call.  Used by [accept_transaction_lwt] which has
   already performed Lwt-flavoured script verification via the
   Validation Domain worker BEFORE entering the sync ATMP body.  Callers
   on the sync path leave the flag at its default [false] and the
   existing sync verify_tx_scripts runs as before. *)
let add_transaction ?(dry_run=false) ?(bypass_fee_check=false) ?(bypass_limits=false)
    ?(skip_verify_scripts=false)
    (mp : mempool) (tx : Types.transaction)
    : (mempool_entry, string) result =
  let txid = Crypto.compute_txid tx in
  let txid_key = Cstruct.to_string txid in

  (* Basic structure validation (matches Core PreChecks step 1: CheckTransaction).
     Must run BEFORE List.hd / coinbase check so empty-inputs txs don't crash. *)
  (match Validation.check_transaction tx with
  | Error e -> Error (Validation.tx_error_to_string e)
  | Ok () ->

  (* W96 Bug 1: coinbase rejection.  Core: validation.cpp:803 — tx.IsCoinBase()
     requires vin.size() == 1 AND prevout.IsNull() (both txid==0 AND vout==-1).
     Previously camlcoin only checked first_input.txid == zero, which
     mis-rejected non-coinbase txs whose first input happens to spend a
     null-txid prevout AND under-rejected multi-input txs with a null first
     input. *)
  if Validation.is_coinbase_tx tx then
    Error "coinbase"
  else

  (* Check for duplicate by txid + wtxid.
     W96 Bug 3: distinguish wtxid-exact-duplicate ("txn-already-in-mempool")
     from same-txid-different-witness ("txn-same-nonwitness-data-in-mempool").
     Matches Core validation.cpp:823-830. *)
  (match Hashtbl.find_opt mp.entries txid_key with
  | Some existing ->
    let new_wtxid = Crypto.compute_wtxid tx in
    if Cstruct.equal existing.wtxid new_wtxid then
      Error "txn-already-in-mempool"
    else
      Error "txn-same-nonwitness-data-in-mempool"
  | None ->

  (* W96 Bug 4: txn-already-known — tx outputs already in the chain coins
     cache means the tx is already CONFIRMED.  Core: validation.cpp:858-863.
     If ANY output of (txid, n) is already a UTXO, the tx is known. *)
  let already_known =
    let found = ref false in
    List.iteri (fun i _out ->
      if not !found then begin
        let op = { Types.txid; vout = Int32.of_int i } in
        if is_confirmed_utxo mp op then found := true
      end
    ) tx.outputs;
    !found
  in
  if already_known then
    Error "txn-already-known"
  else

  (* Check for mempool input conflicts (double-spends) *)
  let conflict = if not dry_run then check_conflict mp tx else None in
  if conflict <> None then
    let conflict_txid = Option.get conflict in
    Error (Printf.sprintf "txn-mempool-conflict: spends same input as %s"
      (Types.hash256_to_hex_display conflict_txid))

  else begin
    (* W96 Bug 2: MIN_STANDARD_TX_NONWITNESS_SIZE (CVE-2017-12842) must run
       independently of require_standard.  Core validation.cpp:812-814 places
       this check OUTSIDE the require_standard guard so that even non-standard
       relay (regtest/signet/-acceptnonstdtxn) rejects 64-byte malleable txs. *)
    let nonwitness_size = compute_tx_nonwitness_size tx in
    if nonwitness_size < min_standard_tx_nonwitness_size then
      Error "tx-size-small"
    else

    (* Task 7: IsStandard checks (skipped when require_standard=false) *)
    (match (if mp.require_standard then is_standard_tx mp.min_relay_fee tx else Ok ()) with
    | Error e -> Error e
    | Ok () ->

    (* ValidateInputsStandardness — per-input prevout-type and P2SH-sigops check.
       Core: validation.cpp:896-901 — guarded by require_standard, runs AFTER
       IsStandardTx and BEFORE IsWitnessStandard.
       Three gates: nonstandard prevout, WITNESS_UNKNOWN prevout, P2SH sigops > 15.
       Reference: policy/policy.cpp:214-263. *)
    (match (if mp.require_standard then
      validate_inputs_standardness
        ~lookup:(fun op ->
          match lookup_utxo mp op with
          | Some e -> Some e.Utxo.script_pubkey
          | None -> None)
        tx
    else Ok ()) with
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

    (* Phase 1C: Per-tx sigops cost check.
       Core: validation.cpp:905 + policy/policy.h:44
       MAX_STANDARD_TX_SIGOPS_COST = MAX_BLOCK_SIGOPS_COST / 5 = 16,000.
       We use the UTXO-aware counter so P2SH/witness inputs are attributed
       correctly (matching GetTransactionSigOpCost in tx_verify.cpp:143). *)
    let sigops_cost = count_tx_sigops_cost_for_mempool tx mp in
    if sigops_cost > Consensus.max_standard_tx_sigops_cost then
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
            (* W96 Bug 5: coinbase maturity off-by-one.  Core CheckTxInputs uses
               nSpendHeight = active_chainstate.m_chain.Height() + 1 (the next
               block) as the spend height.  Previously camlcoin used the
               current tip height, which is one block too strict — a coinbase
               at tip-100 was rejected when Core would accept it on the next
               block.  Reference: validation.cpp:892 (Height()+1 passed to
               CheckTxInputs), consensus/tx_verify.cpp:88. *)
            let spend_height = mp.current_height + 1 in
            if entry.is_coinbase &&
               spend_height - entry.height < Consensus.coinbase_maturity then
              error := Some "Spending immature coinbase"
            (* W96 Bug 7: per-input MoneyRange check.  Core's CheckTxInputs:
               consensus/tx_verify.cpp:103-105 — every coin.out.nValue must be
               in [0, MAX_MONEY].  Previously camlcoin accumulated input value
               without this gate, so a negative or out-of-range UTXO (from a
               corrupted UTXO set or malicious peer chainstate) could silently
               poison fee math. *)
            else if entry.value < 0L || entry.value > Consensus.max_money then
              error := Some "bad-txns-inputvalues-outofrange"
            else begin
              input_sum := Int64.add !input_sum entry.value;
              (* W96 Bug 8: accumulated input MoneyRange.  Core CheckTxInputs:
                 consensus/tx_verify.cpp:108-110 — after each addition,
                 nValueIn must remain in [0, MAX_MONEY]. *)
              if !input_sum < 0L || !input_sum > Consensus.max_money then
                error := Some "bad-txns-inputvalues-outofrange"
              else begin
                utxo_heights.(i) <- entry.height;
                utxo_mtps.(i) <- mp.current_median_time;
                (* Track mempool dependencies *)
                if Hashtbl.mem mp.entries (Cstruct.to_string prev.txid) then
                  depends := prev.txid :: !depends
              end
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
            (* W96 Bug 9: tx fee MoneyRange.  Core CheckTxInputs:
               consensus/tx_verify.cpp:113-115 — txfee = value_in - value_out
               must be in [0, MAX_MONEY].  Previously camlcoin only checked
               output_sum <= input_sum, missing the upper bound.  An
               attacker-controlled UTXO set could produce a fee field that
               wraps the int64 fee counter in the mempool aggregate. *)
            if fee < 0L || fee > Consensus.max_money then
              Error "bad-txns-fee-outofrange"
            else
            let weight = Validation.compute_tx_weight tx in

            (* Sigop-adjusted vsize — policy/policy.cpp:395-398, kernel/mempool_entry.h:110-112.
               Core's GetTxSize() = GetVirtualTransactionSize(nTxWeight, sigOpCost, nBytesPerSigOp).
               When the sigop cost inflates vsize beyond the raw weight/4 value, the larger
               vsize is used for feerate comparisons and ancestor/descendant size accounting.
               sigops_cost is already computed above for the MAX_STANDARD_TX_SIGOPS_COST gate.
               Hoisted ABOVE the fee gate (was below) so the floor is computed
               against the sigop-adjusted vsize, matching Core validation.cpp:948
               (CheckFeeRate uses ws.m_vsize, the sigop-adjusted value). *)
            let vsize = Validation.get_virtual_transaction_size
              ~weight ~sigop_cost:sigops_cost
              ~bytes_per_sigop:Consensus.default_bytes_per_sigop in

            let fee_rate =
              Int64.to_float fee /. float_of_int (max 1 vsize) in

            (* W96 Bug 6: PreCheckEphemeralTx — dust outputs require 0 fee
               (ephemeral anchor policy).  Core validation.cpp:935-938 runs
               this only when require_standard, BEFORE the fee floor check.
               Previously camlcoin only ran it from package paths, never from
               single-tx ATMP.  Skip on bypass_limits (reorg refill). *)
            (* Inline equivalent of pre_check_ephemeral_tx (defined later) so
               the gate runs at the right point in PreChecks without forward
               reference.  Logic mirrors mempool.ml:pre_check_ephemeral_tx. *)
            let ephemeral_err =
              if mp.require_standard && not bypass_limits then
                let has_dust = List.exists (is_dust dust_relay_fee) tx.outputs in
                if has_dust && fee <> 0L then
                  Some "tx with dust output must be 0-fee"
                else None
              else None
            in
            (match ephemeral_err with
             | Some e -> Error e
             | None ->

            (* W96 Bug 10: fee floor uses sigop-adjusted vsize, not raw weight.
               Core validation.cpp:948 calls CheckFeeRate(ws.m_vsize, ...).
               Previously camlcoin computed min_fee = eff_min * weight / 4000
               which under-charges sigop-heavy txs (a tx with high sigops has
               vsize > weight/4 and should owe more relay fee).  Use
               integer-truncation math matching Core's GetFee (CFeeRate
               feerate.cpp:23: amount * size / 1000). *)
            let eff_min = effective_min_fee mp in
            let min_fee =
              Int64.div (Int64.mul eff_min (Int64.of_int vsize)) 1000L in

            if fee < min_fee && not bypass_fee_check then
              Error "Fee below minimum relay fee"

            (* Cluster size limit check: enforce both count (≤64) and vsize (≤101 kvB) limits.
               Reference: Bitcoin Core txmempool.cpp:1341-1344 (CheckMemPoolPolicyLimits).
               Pass the new tx weight so the vsize gate can account for this tx's contribution. *)
            else match check_cluster_size_limit ~new_tx_weight:weight mp !depends txid with
            | Error e -> Error e
            | Ok () ->

            (* Task 3 + Gap 6: Ancestor/descendant limits (count + size) - kept for backward compat *)
            match check_ancestor_descendant_limits mp !depends txid weight with
            | Error e -> Error e
            | Ok () ->

            (* TRUC/v3 policy (BIP-431).
               Pass sigop-adjusted vsize — Core truc_policy.cpp:SingleTRUCChecks
               receives the same adjusted vsize.
               W96 Bug 11: skip TRUC checks when bypass_limits is set.  Core
               validation.cpp:954 wraps SingleTRUCChecks in
               `if (!args.m_bypass_limits)` so that reorg refill (txs from a
               disconnected block) bypasses the TRUC v3 inheritance rules.
               Without this skip, valid v3 chains that survived a reorg would
               be re-rejected when the parent has not yet re-entered the
               mempool. *)
            match (if bypass_limits then Ok () else check_truc_policy mp tx !depends vsize) with
            | Error e -> Error e
            | Ok () ->

            (* Task 1: Script verification at acceptance (skipped when
               verify_scripts=false, or when the Lwt entry has already
               performed parallel script verification — bug #135 step 2). *)
            match (if mp.verify_scripts && not skip_verify_scripts
                   then verify_tx_scripts mp tx else Ok ()) with
            | Error e -> Error e
            | Ok () ->

            let wtxid = Crypto.compute_wtxid tx in

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
              (* #135 step 1: register this tx as a child of each parent in
                 the reverse children index, so get_descendants is O(D). *)
              List.iter (fun parent_txid ->
                let parent_key = Cstruct.to_string parent_txid in
                let children_set =
                  match Hashtbl.find_opt mp.children parent_key with
                  | Some s -> s
                  | None ->
                    let s = Hashtbl.create 4 in
                    Hashtbl.replace mp.children parent_key s;
                    s
                in
                Hashtbl.replace children_set txid_key ()
              ) !depends;
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

              (* Evict if over size limit - use cluster-based eviction.
                 Reference: Core validation.cpp:275 calls TrimToSize(max_size_bytes)
                 after every accept — triggers when total weight exceeds the full
                 limit (not 25% of it as the old code did).
                 2026-07-01 GC-churn fix: trigger only past a small overshoot
                 slack (~1.6 % of the cap) so the O(pool) chunk rebuild inside
                 evict_by_chunks is amortized over many accepts instead of
                 running on EVERY accept once the pool sits at the cap (the
                 public-flood churn that stalled RPC — see evict_by_chunks).
                 Each trim still evicts back down to max_size_bytes exactly;
                 memory is bounded by cap + slack. *)
              if mp.total_weight > mp.max_size_bytes + eviction_trigger_slack mp then
                evict_by_chunks mp;

              (* Notify ZMQ subscribers about new transaction *)
              zmq_notify_tx mp txid tx true
            end;

            Ok entry)
          end
        end
    end)))
  end))

(* ============================================================================
   Block Processing
   ============================================================================ *)

(* Remove confirmed transactions after a block is mined.
   Collects txids to remove before mutating the Hashtbl.
   Also resets the rolling fee decay timer so the floor can begin decaying.
   Reference: Bitcoin Core txmempool.cpp:405-431 (removeForBlock)
     lastRollingFeeUpdate = GetTime();
     blockSinceLastRollingFeeBump = true; *)
let remove_for_block (mp : mempool) (block : Types.block) (height : int)
    : unit =
  mp.current_height <- height;

  List.iter (fun tx ->
    let txid = Crypto.compute_txid tx in
    remove_transaction mp txid;

    (* Evict any mempool tx that double-spends an input now spent by this block
       tx.  W165 un-pin fix (#9): each outpoint is spent by AT MOST ONE mempool
       tx (double-spends are rejected at accept / resolved by RBF), so the
       [map_next_tx] spent-outpoint index gives the sole conflicting spender in
       O(1) — mirroring Core's mapNextTx-driven removeForBlock
       (txmempool.cpp).  The previous code did a full [Hashtbl.fold] over the
       ENTIRE mempool for EVERY input of EVERY block tx (O(block_txs * pool)),
       which — with a saturated ~20k-tx pool and a full block — monopolised the
       single Lwt/RPC domain for tens of seconds on block connection (a 60-90s
       RPC stall under sustained-saturation soak; the second serialization layer
       after the RBF-diagram O(N^2)).  [remove_transaction] keeps map_next_tx
       consistent (it erases the tx's own outpoints on removal) and cascades to
       descendants, so a direct lookup is behaviourally identical. *)
    List.iter (fun inp ->
      let out_key = (Cstruct.to_string inp.Types.previous_output.txid,
                     inp.Types.previous_output.vout) in
      match Hashtbl.find_opt mp.map_next_tx out_key with
      | None -> ()
      | Some conflict_key ->
        (match Hashtbl.find_opt mp.entries conflict_key with
         | Some ce -> remove_transaction mp ce.txid
         | None -> ())
    ) tx.inputs
  ) block.transactions;
  (* Reset rolling fee update timestamp and mark block-since-last-bump so the
     exponential decay starts running from this point forward.
     Reference: Core txmempool.cpp:426-427 *)
  mp.last_rolling_fee_update <- Unix.gettimeofday ();
  mp.block_since_last_rolling_fee_bump <- true

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
   v3/TRUC transactions signal replaceability unconditionally.
   This function checks only the transaction itself, not mempool ancestors.
   Use [signals_rbf_with_ancestors] when mempool context is available. *)
let signals_rbf (tx : Types.transaction) : bool =
  (* v3/TRUC transactions are always replaceable *)
  is_truc_tx tx ||
  (* BIP-125: any input with nSequence <= MAX_BIP125_RBF_SEQUENCE (0xFFFFFFFD) signals RBF.
     Sequences are unsigned uint32; use Int64 mask to avoid signed-comparison
     gotcha: 0xFFFFFFFEl as OCaml int32 is -2l, so Int32.compare 0l (-2l) > 0
     which would incorrectly report sequence=0 as non-RBF.  Fixed by W70. *)
  List.exists (fun inp ->
    let seq_u = Int64.logand (Int64.of_int32 inp.Types.sequence) 0xFFFFFFFFL in
    Int64.compare seq_u 0xFFFFFFFEL < 0
  ) tx.inputs

(* Gate 2: BIP-125 inheritable opt-in — also REPLACEABLE_BIP125 if any in-mempool
   ancestor signals RBF, even if this tx's own sequence numbers don't.
   Core: rbf.cpp IsRBFOptIn, walks pool.CalculateMemPoolAncestors. *)
let signals_rbf_with_ancestors (mp : mempool) (tx : Types.transaction) : bool =
  if signals_rbf tx then true
  else begin
    (* Walk all mempool ancestors via BFS — same logic as ancestor-limit walk *)
    let txid_key = Cstruct.to_string (Crypto.compute_txid tx) in
    (* Seed with direct parents of this tx *)
    let direct_parents = List.filter_map (fun inp ->
      let parent_key = Cstruct.to_string inp.Types.previous_output.txid in
      if Hashtbl.mem mp.entries parent_key then Some parent_key else None
    ) tx.inputs in
    if direct_parents = [] then false
    else begin
      let visited = Hashtbl.create 8 in
      let queue = Queue.create () in
      List.iter (fun pk ->
        if pk <> txid_key && not (Hashtbl.mem visited pk) then begin
          Hashtbl.replace visited pk ();
          Queue.push pk queue
        end
      ) direct_parents;
      let found = ref false in
      while not (Queue.is_empty queue) && not !found do
        let key = Queue.pop queue in
        match Hashtbl.find_opt mp.entries key with
        | None -> ()
        | Some ancestor_entry ->
          if signals_rbf ancestor_entry.tx then
            found := true
          else
            List.iter (fun gp_txid ->
              let gp_key = Cstruct.to_string gp_txid in
              if not (Hashtbl.mem visited gp_key) then begin
                Hashtbl.replace visited gp_key ();
                Queue.push gp_key queue
              end
            ) ancestor_entry.depends_on
      done;
      !found
    end
  end

(* Get total fees for a transaction and all its descendants *)
let get_fees_with_descendants (mp : mempool) (entry : mempool_entry) : int64 =
  let desc = get_descendants mp entry.txid in
  let desc_fees = List.fold_left (fun acc d -> Int64.add acc d.fee) 0L desc in
  Int64.add entry.fee desc_fees

(* ============================================================================
   ImprovesFeerateDiagram
   Reference: bitcoin-core/src/policy/rbf.cpp ImprovesFeerateDiagram
              bitcoin-core/src/util/feefrac.cpp CompareChunks

   Checks that the feerate diagram of the post-replacement mempool strictly
   dominates the pre-replacement diagram at every cumulative-vsize boundary.

   Algorithm:
     1. Compute "before" chunks from the current mempool (get_all_chunks).
     2. Build a virtual "after" entry list = (all entries) - (evicted set)
        + a synthetic mempool_entry for the replacement transaction.
     3. Linearize the "after" entry list via the same greedy chunk algorithm
        (find_best_chunk / remove_chunk, which do not read mp.entries so they
        work on an arbitrary list).
     4. Convert both chunk lists into cumulative (vsize, fee) diagrams.
     5. Compare: "after" must be strictly greater than "before" at every
        breakpoint — i.e. no point where "before" is strictly above "after",
        and at least one point where "after" is strictly above "before".
        Returns true iff the "after" diagram strictly dominates.

   Note: This is a simplified (non-cached) implementation equivalent in
   correctness to Core's CalculateChunksForRBF + CompareChunks.
   ============================================================================ *)

(* Linearize an arbitrary list of mempool entries into chunks (highest-feerate
   first), ignoring the mempool hashtable (uses the entry list itself). *)
let linearize_entries (mp : mempool) (entries : mempool_entry list) : chunk list =
  let rec chunk_loop remaining acc =
    match remaining with
    | [] -> List.rev acc
    | _ ->
      let best = find_best_chunk remaining mp in
      if best.chunk_txs = [] then List.rev acc
      else
        let new_remaining = remove_chunk remaining best in
        chunk_loop new_remaining (best :: acc)
  in
  chunk_loop entries []

(* Convert a list of chunks (highest-feerate first) into a cumulative diagram:
   a list of (cumulative_vsize, cumulative_fee) pairs, one per chunk boundary,
   sorted by increasing cumulative_vsize. *)
let chunks_to_diagram (chunks : chunk list)
    : (int * int64) list =
  let rec build chunks cum_size cum_fee acc =
    match chunks with
    | [] -> List.rev acc
    | c :: rest ->
      let new_size = cum_size + c.chunk_vsize in
      let new_fee  = Int64.add cum_fee c.chunk_fee in
      build rest new_size new_fee ((new_size, new_fee) :: acc)
  in
  build chunks 0 0L []

(* CompareChunks: compare two feerate diagrams at their combined breakpoints.
   Returns `Strictly_better if "after" strictly dominates "before" everywhere
   (i.e. after ≥ before at every vsize, and strictly > at ≥ one point).
   Returns `Not_better otherwise (equal or incomparable diagrams are also
   rejected — Core requires strict improvement). *)
type diagram_cmp = Strictly_better | Not_better

let compare_feerate_diagrams
    ~(before : (int * int64) list)
    ~(after  : (int * int64) list)
    : diagram_cmp =
  (* Walk both sorted-by-vsize lists simultaneously, interpolating linearly
     between breakpoints (a segment of constant fee_rate has a linear cumulative
     fee curve).  At each combined breakpoint we check whether "after" is ≥
     "before".  We also track whether "after" is strictly > "before" at ≥ 1 pt.
     Interpolation formula for diagram D at vsize v between points (v0,f0) and
     (v1,f1):  fee(v) = f0 + (f1 - f0) * (v - v0) / (v1 - v1)
     To stay in integer arithmetic we compare cross-products. *)
  let fee_at (pts : (int * int64) list) (v : int) : int64 =
    (* Find the two bracketing points.  Diagrams start at (0, 0) implicitly. *)
    let rec go pts prev_v prev_f =
      match pts with
      | [] ->
        (* Beyond the last point: extrapolate as flat (fee stays at last value). *)
        prev_f
      | (pv, pf) :: rest ->
        if v <= pv then begin
          if v = pv then pf
          else begin
            (* v is in (prev_v, pv).  Interpolate:
               fee = prev_f + (pf - prev_f) * (v - prev_v) / (pv - prev_v)
               Use integer division rounding down (conservative, matches Core
               which uses FeeFrac cross-product comparisons). *)
            let span = Int64.of_int (pv - prev_v) in
            let delta_v = Int64.of_int (v - prev_v) in
            let delta_f = Int64.sub pf prev_f in
            Int64.add prev_f (Int64.div (Int64.mul delta_f delta_v) span)
          end
        end else
          go rest pv pf
    in
    go pts 0 0L
  in
  (* Collect all vsize breakpoints from both diagrams. *)
  let all_vsizes =
    let s : (int, unit) Hashtbl.t = Hashtbl.create 32 in
    List.iter (fun (v, _) -> Hashtbl.replace s v ()) before;
    List.iter (fun (v, _) -> Hashtbl.replace s v ()) after;
    let lst = Hashtbl.fold (fun v () acc -> v :: acc) s [] in
    List.sort compare lst
  in
  if all_vsizes = [] then Not_better  (* both diagrams empty → not strictly better *)
  else begin
    let after_better_somewhere = ref false in
    let before_better_somewhere = ref false in
    List.iter (fun v ->
      if not !before_better_somewhere || not !after_better_somewhere then begin
        let f_before = fee_at before v in
        let f_after  = fee_at after  v in
        if f_after > f_before then after_better_somewhere := true;
        if f_before > f_after then before_better_somewhere := true
      end
    ) all_vsizes;
    (* "after" strictly dominates iff after is better somewhere AND before is
       never better (same semantics as Core's CompareChunks returning > 0). *)
    if !after_better_somewhere && not !before_better_somewhere then
      Strictly_better
    else
      Not_better
  end

(* Collect the full connected components (clusters) TOUCHED by an RBF
   replacement: every mempool tx reachable through parent/child edges from any
   evicted tx (= the direct conflicts plus their descendants) or from any
   in-pool parent of the replacement.  Those clusters are the ONLY part of the
   mempool whose feerate-diagram chunks differ before vs after the replacement;
   every other cluster is byte-identical in both diagrams and cancels in
   CompareChunks, so it cannot affect the strictly-improves decision.

   This mirrors Bitcoin Core exactly: ImprovesFeerateDiagram compares the
   diagrams returned by ChangeSet::CalculateChunksForRBF ->
   TxGraph::GetMainStagingDiagrams (src/policy/rbf.cpp:130,
   src/txmempool.cpp:994), which are computed over the staged (affected)
   clusters only — never the whole mempool.

   Bounded / un-pin fix (W165 #9): each mempool cluster is capped at
   max_cluster_count (64) txs by check_cluster_size_limit at accept time, and
   the number of seed clusters is bounded by MAX_REPLACEMENT_CANDIDATES (100).
   So this is O(affected) — INDEPENDENT of total mempool size.  The previous
   code linearized the ENTIRE mempool via [get_all_chunks] / whole-pool
   [linearize_entries]; because [find_best_chunk] rescans its whole [remaining]
   list per extracted chunk, that made [check_improves_feerate_diagram] O(N^2)
   in mempool size, run twice (before+after) per RBF replacement, synchronously
   on the single Lwt/RPC domain with no yield.  At a saturated pool (~16k txs)
   one replacement monopolized the domain for tens of seconds and wedged RPC
   (getblockcount 60s timeout, no self-recovery — the un-pin blocker). *)
let collect_affected_cluster_entries
    (mp : mempool)
    ~(evicted_set : (string, mempool_entry) Hashtbl.t)
    ~(replacement_tx : Types.transaction)
    : mempool_entry list =
  let result : (string, mempool_entry) Hashtbl.t = Hashtbl.create 128 in
  let visited : (string, unit) Hashtbl.t = Hashtbl.create 128 in
  let queue = Queue.create () in
  let enqueue key =
    if Hashtbl.mem mp.entries key && not (Hashtbl.mem visited key) then begin
      Hashtbl.replace visited key ();
      Queue.push key queue
    end
  in
  (* Seeds: every evicted tx (conflicts + their descendants) and every in-pool
     parent of the replacement (post-eviction the replacement lands in the
     cluster formed by those parents). *)
  Hashtbl.iter (fun k _ -> enqueue k) evicted_set;
  List.iter (fun inp ->
    enqueue (Cstruct.to_string inp.Types.previous_output.txid)
  ) replacement_tx.inputs;
  (* BFS the parent/child graph so the collected subset is CLOSED under the
     cluster relation (every collected tx has all its in-pool parents AND
     children collected too); [linearize_entries] then behaves identically to
     how it would within the full pool for these clusters. *)
  while not (Queue.is_empty queue) do
    let key = Queue.pop queue in
    (match Hashtbl.find_opt mp.entries key with
     | None -> ()
     | Some e ->
       Hashtbl.replace result key e;
       List.iter (fun p -> enqueue (Cstruct.to_string p)) e.depends_on;
       (match Hashtbl.find_opt mp.children key with
        | None -> ()
        | Some s -> Hashtbl.iter (fun ck () -> enqueue ck) s))
  done;
  Hashtbl.fold (fun _ e acc -> e :: acc) result []

(* Top-level gate: returns Ok () if the replacement improves the feerate
   diagram, or Error msg if it does not.
   evicted_set: the Hashtbl of entries to be removed.
   new_fee / new_weight: pre-computed from the replacement tx. *)
let check_improves_feerate_diagram
    (mp : mempool)
    ~(evicted_set : (string, mempool_entry) Hashtbl.t)
    ~(replacement_tx : Types.transaction)
    ~(new_fee : int64)
    ~(new_weight : int)
    : (unit, string) result =
  (* Only the clusters touched by the replacement can differ between the before
     and after diagrams; compute over exactly those (Core-faithful, bounded). *)
  let affected_entries =
    collect_affected_cluster_entries mp ~evicted_set ~replacement_tx in

  (* Before diagram: chunks of the affected clusters as they currently stand. *)
  let before_chunks = linearize_entries mp affected_entries in
  let before_diag   = chunks_to_diagram before_chunks in

  (* After entry list: affected entries minus evicted, plus synthetic replacement. *)
  let evicted_keys = evicted_set in  (* Hashtbl string → entry *)
  let remaining_entries =
    List.filter
      (fun entry -> not (Hashtbl.mem evicted_keys (Cstruct.to_string entry.txid)))
      affected_entries
  in
  let new_vsize = max 1 ((new_weight + 3) / 4) in
  let new_fee_rate = Int64.to_float new_fee /. float_of_int new_vsize in
  let rep_txid = Crypto.compute_txid replacement_tx in
  let rep_wtxid = Crypto.compute_wtxid replacement_tx in
  (* Determine which (if any) of the replacement's inputs are still unconfirmed
     after eviction — those become depends_on entries in the synthetic entry. *)
  let depends_after_eviction =
    List.filter_map (fun inp ->
      let parent_key = Cstruct.to_string inp.Types.previous_output.txid in
      if Hashtbl.mem mp.entries parent_key &&
         not (Hashtbl.mem evicted_keys parent_key)
      then Some inp.Types.previous_output.txid
      else None
    ) replacement_tx.inputs
  in
  let synthetic_entry = {
    tx             = replacement_tx;
    txid           = rep_txid;
    wtxid          = rep_wtxid;
    fee            = new_fee;
    weight         = new_weight;
    fee_rate       = new_fee_rate;
    time_added     = 0.0;
    height_added   = mp.current_height;
    depends_on     = depends_after_eviction;
    ancestor_count = 1;
    ancestor_size  = new_vsize;
    descendant_count = 1;
    descendant_size  = new_vsize;
  } in
  let after_entries = synthetic_entry :: remaining_entries in
  let after_chunks  = linearize_entries mp after_entries in
  let after_diag    = chunks_to_diagram after_chunks in

  match compare_feerate_diagrams ~before:before_diag ~after:after_diag with
  | Strictly_better -> Ok ()
  | Not_better ->
    Error "insufficient feerate: does not improve feerate diagram"

(* ============================================================================
   FIX-72 / W120 BUG-10 — prioritisetransaction (mapDeltas) machinery

   Mirrors Bitcoin Core's mempool fee-delta mechanism.  An out-of-band signed
   satoshi delta can be attached to a txid (whether the tx is in the mempool
   yet or not).  All fee comparisons that affect ordering / admission /
   replacement use the *modified* fee = base_fee + delta.

   Core references:
     - src/txmempool.cpp:630   PrioritiseTransaction(hash, nFeeDelta)
     - src/txmempool.cpp:657   ApplyDelta(hash, nFeeDelta)   const
     - src/txmempool.cpp:667   ClearPrioritisation(hash)
     - src/rpc/mining.cpp:502  prioritisetransaction RPC
     - src/policy/rbf.cpp:100  PaysForRBF (uses GetModifiedFee on both sides
                                 — validation.cpp:1006, 1090)

   Persistence: Core writes mapDeltas to mempool.dat; we mirror that on
   dump_mempool but the in-memory map is the source of truth and is NOT
   re-loaded across a fresh start unless mempool.dat exists.  The
   docstring on `prioritise_transaction` makes the "not persisted across
   restart" property explicit so tests can pin it (Core parity).
   ============================================================================ *)

(* int64-saturating add — matches Core's SaturatingAdd<CAmount> used in
   PrioritiseTransaction so a malicious operator can't wrap the delta to a
   negative value with int64-overflow tricks. *)
let saturating_add_i64 (a : int64) (b : int64) : int64 =
  let r = Int64.add a b in
  let a_pos = Int64.compare a 0L >= 0 in
  let b_pos = Int64.compare b 0L >= 0 in
  let r_pos = Int64.compare r 0L >= 0 in
  if a_pos = b_pos && r_pos <> a_pos then
    (if a_pos then Int64.max_int else Int64.min_int)
  else r

(* Look up the prioritise delta for a txid.  Returns 0L if no delta has been
   set (Core: ApplyDelta is a no-op when mapDeltas does not contain the key). *)
let get_delta (mp : mempool) (txid : Types.hash256) : int64 =
  match Hashtbl.find_opt mp.map_deltas (Cstruct.to_string txid) with
  | Some d -> d
  | None -> 0L

(* Apply the prioritise delta to a base fee.
   Mirrors Core's CTxMemPool::ApplyDelta(hash, nFeeDelta) which mutates a
   reference parameter.  We return a fresh int64 instead. *)
let apply_delta (mp : mempool) (txid : Types.hash256) (base_fee : int64)
    : int64 =
  let delta = get_delta mp txid in
  if Int64.equal delta 0L then base_fee
  else saturating_add_i64 base_fee delta

(* Modified fee = base fee + prioritise delta for this entry.
   Wired into RBF Rule 3, getmempoolentry "fees.modified", and any other
   selection / admission math that must respect operator-applied priority.
   Core: CTxMemPoolEntry::GetModifiedFee() = m_fee + m_fee_delta (the
   per-entry copy maintained by UpdateModifiedFee). *)
let get_modified_fee (mp : mempool) (entry : mempool_entry) : int64 =
  apply_delta mp entry.txid entry.fee

(* prioritise_transaction txid delta_sats
   Apply a signed fee delta to a txid's mapDeltas slot.  If the delta
   accumulates to exactly 0, the entry is removed from the map entirely
   (Core txmempool.cpp:644 — "if (delta == 0) { mapDeltas.erase(hash); }").
   The txid does NOT need to be in the mempool — Core also allows
   prioritising a not-yet-seen tx, and the delta will be picked up if/when
   the tx arrives.

   Persisted across restart via mempool.dat: save_mempool emits each delta
   as the per-entry inline nFeeDelta (for in-pool txids) plus the standalone
   tail map (for absent txids); load_mempool replays via this function on
   restart (FIX-77).  Matches Core's auto-restart default
   apply_fee_delta_priority=true (mempool_persist.h:23); only the
   `importmempool` RPC opts the flag back to false. *)
let prioritise_transaction (mp : mempool) (txid : Types.hash256)
    (delta_sats : int64) : unit =
  let key = Cstruct.to_string txid in
  let cur = match Hashtbl.find_opt mp.map_deltas key with
    | Some d -> d
    | None -> 0L
  in
  let new_delta = saturating_add_i64 cur delta_sats in
  if Int64.equal new_delta 0L then
    Hashtbl.remove mp.map_deltas key
  else
    Hashtbl.replace mp.map_deltas key new_delta

(* Clear a prioritisation for a txid (Core: ClearPrioritisation). *)
let clear_prioritisation (mp : mempool) (txid : Types.hash256) : unit =
  Hashtbl.remove mp.map_deltas (Cstruct.to_string txid)

(* Snapshot of all current prioritisations as a list of (txid, delta, in_pool)
   tuples.  Backs the getprioritisedtransactions RPC. *)
let get_prioritised_transactions (mp : mempool)
    : (Types.hash256 * int64 * bool * int64 option) list =
  Hashtbl.fold (fun k delta acc ->
    let in_pool = Hashtbl.mem mp.entries k in
    let modified_fee = if in_pool then
      match Hashtbl.find_opt mp.entries k with
      | Some e -> Some (Int64.add e.fee delta)
      | None -> None
    else None in
    (* Reconstruct a Cstruct.t txid from the binary string key. *)
    let txid_cs = Cstruct.of_string k in
    (txid_cs, delta, in_pool, modified_fee) :: acc
  ) mp.map_deltas []

(* Attempt to replace an existing transaction with higher fee.
   Full RBF: no BIP125 signaling required (-mempoolfullrbf=1 default).

   Rules enforced:
   1. New fee > sum of all conflicting fees (including descendants)
   2. New fee_rate > conflicting fee_rate + incremental_relay_fee
   3. Max 100 transactions evicted
   4. No new unconfirmed inputs (except from conflicting txs)

   FIX-73 W120 BUG-4: [replace_by_fee_with_replaced] returns the deduplicated
   list of evicted txids alongside the new entry so the submitpackage RPC can
   populate `replaced-transactions` matching Core's
   PackageMempoolAcceptResult::m_replaced_transactions (validation.cpp:1236).
   The list comes straight from [evicted_set] (direct conflicts + descendants,
   dedup'd by txid) so it is the exact set of mempool entries that were
   physically removed by the replacement.  Empty list ⇒ no RBF happened (the
   add was on a free outpoint).  Existing [replace_by_fee] is preserved as
   a thin discard-wrapper so the ~20 call sites in test_mempool.ml continue
   to compile. *)
let replace_by_fee_with_replaced ?(dry_run=false) ?(skip_verify_scripts=false)
    (mp : mempool) (tx : Types.transaction)
    : (mempool_entry * Types.hash256 list, string) result =
  let conflicts = find_all_conflicts mp tx in
  match conflicts with
  | [] ->
    (* No conflict, just add normally — empty replaced list *)
    (match add_transaction ~dry_run ~skip_verify_scripts mp tx with
     | Ok e -> Ok (e, [])
     | Error s -> Error s)
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

        (* Rule #5 (Gate 3): Collect the full set of transactions that would be
           evicted (conflicts + all their descendants). Deduplicate by txid so
           that a tx that appears as both a direct conflict and a descendant of
           another conflict is only counted once (same as Core's unique-cluster
           bound — rbf.cpp GetEntriesForConflicts uses a set<txiter>).
           Core constant: MAX_REPLACEMENT_CANDIDATES = 100. *)
        let evicted_set : (string, mempool_entry) Hashtbl.t = Hashtbl.create 16 in
        List.iter (fun conflict_entry ->
          let key = Cstruct.to_string conflict_entry.txid in
          if not (Hashtbl.mem evicted_set key) then
            Hashtbl.replace evicted_set key conflict_entry;
          let desc = get_descendants mp conflict_entry.txid in
          List.iter (fun d ->
            let dk = Cstruct.to_string d.txid in
            if not (Hashtbl.mem evicted_set dk) then
              Hashtbl.replace evicted_set dk d
          ) desc
        ) conflicts;
        let eviction_count = Hashtbl.length evicted_set in

        if eviction_count > max_rbf_evictions then
          Error (Printf.sprintf
            "rejecting replacement; too many conflicting transactions (%d > %d)"
            eviction_count max_rbf_evictions)

        else begin
          (* Build set of conflict txids for the disjoint check below *)
          let conflict_txid_set : (string, unit) Hashtbl.t = Hashtbl.create 8 in
          List.iter (fun ce ->
            Hashtbl.replace conflict_txid_set (Cstruct.to_string ce.txid) ()
          ) conflicts;

          (* Gate 5 (EntriesAndTxidsDisjoint — Core rbf.cpp line 85):
             The replacement tx's mempool ancestors must not overlap with the
             direct conflict set.  If they did, the replacement would depend on
             a tx being evicted, making the whole operation incoherent.
             Core: ancestors-of-replacement ∩ direct_conflicts = ∅. *)
          let ancestor_in_conflict =
            let found = ref false in
            let visited = Hashtbl.create 8 in
            let queue = Queue.create () in
            List.iter (fun inp ->
              let pk = Cstruct.to_string inp.Types.previous_output.txid in
              if Hashtbl.mem mp.entries pk && not (Hashtbl.mem visited pk) then begin
                Hashtbl.replace visited pk ();
                Queue.push pk queue
              end
            ) tx.inputs;
            while not (Queue.is_empty queue) && not !found do
              let key = Queue.pop queue in
              if Hashtbl.mem conflict_txid_set key then
                found := true
              else
                (match Hashtbl.find_opt mp.entries key with
                 | None -> ()
                 | Some ae ->
                   List.iter (fun gp ->
                     let gk = Cstruct.to_string gp in
                     if not (Hashtbl.mem visited gk) then begin
                       Hashtbl.replace visited gk ();
                       Queue.push gk queue
                     end
                   ) ae.depends_on)
            done;
            !found
          in

          if ancestor_in_conflict then
            Error "replacement tx spends a conflicting transaction"

          else begin
            (* Rule #3 (Gate 6): replacement_modified_fees >= original_modified_fees.
               Core: PaysForRBF rejects when replacement_fees < original_fees.
               Note: equal is ALLOWED (>= not >).  Previous code used <= which
               was wrong — it rejected replacements with exactly the same fee.

               FIX-72 W120 BUG-10: both sides MUST use GetModifiedFee — Core's
               validation.cpp:930+1006+1090 calls ws.m_tx_handle->GetModifiedFee()
               for the candidate and it->GetModifiedFee() for every conflict.
               Without this, operator-applied prioritisetransaction deltas are
               ignored by Rule 3 and the modified-fee field becomes ornamental.

               Forward-regression: raw-fee comparison in Rule 3 path is
               explicitly forbidden — `apply_delta` MUST be called on both
               sides before the `<` check.  test_w120 G3-FIX72-guard asserts
               this by source inspection. *)
            let rep_txid_for_delta = Crypto.compute_txid tx in
            let new_modified_fee = apply_delta mp rep_txid_for_delta new_fee in
            let total_conflict_fee = Hashtbl.fold
              (fun _ e acc -> Int64.add acc (get_modified_fee mp e)) evicted_set 0L in

            if new_modified_fee < total_conflict_fee then
              Error (Printf.sprintf
                "rejecting replacement, less fees than conflicting txs; %Ld < %Ld"
                new_modified_fee total_conflict_fee)

            else begin
              (* Rule #4 (Gate 7): additional_fees >= relay_fee.GetFee(replacement_vsize).
                 Core: PaysForRBF, additional_fees = replacement_fees − original_fees.
                 relay_fee is in sat/kvB; GetFee(vsize) = ceil(rate * vsize / 1000).
                 We use integer arithmetic to match Core's truncating GetFee.

                 W120 BUG-RBF4-FEERATE fix: Core's PaysForRBF is called with
                 m_pool.m_opts.incremental_relay_feerate (validation.cpp:1011),
                 NOT the minimum relay feerate.  camlcoin previously used
                 [mp.min_relay_fee] (the relay/admission floor, not the
                 incremental feerate) instead of Core's
                 DEFAULT_INCREMENTAL_RELAY_FEE (100 sat/kvB, policy/policy.h:48),
                 making Rule 4 over-strict and diverging from a default-flag Core
                 oracle.  Switch to [incremental_relay_fee] to match Core exactly. *)
              let additional_fees = Int64.sub new_modified_fee total_conflict_fee in
              let relay_fee_for_replacement =
                Int64.div (Int64.mul incremental_relay_fee (Int64.of_int new_vsize)) 1000L in
              if additional_fees < relay_fee_for_replacement then
                Error (Printf.sprintf
                  "rejecting replacement, not enough additional fees to relay; %Ld < %Ld"
                  additional_fees relay_fee_for_replacement)

              else begin
                (* Rule #2 (Gate 4, HasNoNewUnconfirmed / BIP125 Rule 2):
                   The replacement may only include an unconfirmed input if that
                   exact outpoint (txid:vout) was already spent by one of the
                   directly conflicting transactions.
                   Rationale: prevents the replacement from pulling in new
                   unconfirmed parents that were never part of the original
                   conflict cluster.
                   BIP125: "The replacement transaction may only include an
                   unconfirmed input if that input was included in one of the
                   original transactions." *)
                let conflict_outpoints : (string * int32, unit) Hashtbl.t =
                  Hashtbl.create 16 in
                List.iter (fun ce ->
                  List.iter (fun inp ->
                    let key = (Cstruct.to_string inp.Types.previous_output.txid,
                               inp.Types.previous_output.vout) in
                    Hashtbl.replace conflict_outpoints key ()
                  ) ce.tx.inputs
                ) conflicts;

                let new_unconfirmed = List.exists (fun inp ->
                  let parent_key = Cstruct.to_string inp.Types.previous_output.txid in
                  let outpoint_key = (parent_key, inp.Types.previous_output.vout) in
                  (* Only flag as "new unconfirmed" if:
                     1. The parent is in the mempool (so it's an unconfirmed input), AND
                     2. This exact outpoint was NOT already spent by a conflicting tx *)
                  Hashtbl.mem mp.entries parent_key &&
                  not (Hashtbl.mem conflict_outpoints outpoint_key)
                ) tx.inputs in

                if new_unconfirmed then
                  Error "replacement tx introduces new unconfirmed inputs not in original transactions"

                else begin
                  ignore new_feerate; (* suppress unused warning after removing non-Core feerate check *)
                  (* ImprovesFeerateDiagram (W106 BUG-10 fix):
                     Core rbf.cpp ImprovesFeerateDiagram requires that the post-
                     replacement mempool feerate diagram strictly dominates the
                     pre-replacement diagram.  Check this BEFORE the dry_run/commit
                     so a diagram-failing replacement is rejected without touching
                     mempool state (mirrors FIX-24 atomicity pattern). *)
                  match check_improves_feerate_diagram mp
                          ~evicted_set
                          ~replacement_tx:tx
                          ~new_fee
                          ~new_weight with
                  | Error e -> Error e
                  | Ok () ->
                  begin
                  (* BUG-9/BUG-12 fix: pre-check then commit (mirrors Core's staged-removal pattern).
                     Run add_transaction in dry_run mode BEFORE removing conflicts.  dry_run=true
                     executes every validation gate (cluster limits, TRUC inheritance, ancestor/
                     descendant limits, script verification, fee floor) without mutating mempool state.
                     Only if the pre-check passes do we proceed with the atomic remove+add.
                     If the pre-check fails, conflicts remain in the mempool unchanged.
                     Reference: Bitcoin Core MemPoolAccept::ConsiderReplacement runs ALL gates before
                     RemoveStaged; Finalize does the atomic RemoveStaged+addUnchecked together. *)
                  match add_transaction ~dry_run:true ~skip_verify_scripts mp tx with
                  | Error e -> Error e
                  | Ok dry_entry ->
                    (* All gates passed; collect the deduplicated evicted txid list. *)
                    let evicted_txids =
                      Hashtbl.fold (fun _k e acc -> e.txid :: acc) evicted_set [] in
                    if dry_run then
                      (* W120 BUG-RBF-DRYRUN fix: testmempoolaccept must evaluate the
                         FULL RBF rule set (1-4 + diagram) WITHOUT mutating the mempool.
                         Every gate above has run against the live state; we now return
                         the dry-run synthetic entry + the would-be-evicted set without
                         performing the remove+add.  This makes testmempoolaccept's
                         allowed/reject-reason agree with what sendrawtransaction would
                         actually do for the same conflicting submit (Core's
                         testmempoolaccept runs MemPoolAccept with test_accept=true,
                         which executes ConsiderReplacement before bailing out at the
                         Finalize step). *)
                      Ok (dry_entry, evicted_txids)
                    else begin
                      (* Now atomically remove conflicts and add replacement.
                         FIX-73 W120 BUG-4: the evicted txid list (direct conflicts +
                         descendants) was collected BEFORE [remove_transaction] so even
                         though removal triggers cascading dependents-cleanup we still
                         return the canonical Core PackageMempoolAcceptResult set: every
                         entry that was in [evicted_set] is one Core would include in
                         m_replaced_transactions.  Order is unspecified (Core uses a
                         std::set<uint256> on the RPC side too — rpc/mempool.cpp:1500). *)
                      List.iter (fun conflict_entry ->
                        remove_transaction mp conflict_entry.txid
                      ) conflicts;
                      (* Residual risk: add_transaction can fail here if mempool state changed
                         between dry_run and commit (e.g. concurrent eviction or OOM).  In that
                         case the conflicts are already removed.  This window is negligible in
                         single-threaded OCaml execution but documented for completeness. *)
                      (match add_transaction ~skip_verify_scripts mp tx with
                       | Ok e -> Ok (e, evicted_txids)
                       | Error s -> Error s)
                    end
                  end
                end
              end
            end
          end
        end
      end

(* Thin discard-wrapper: legacy [replace_by_fee] callers (tests + internal
   accept_transaction) that don't care about the evicted-txid list.  Mirrors
   the original API exactly so the FIX-73 refactor does not ripple. *)
let replace_by_fee (mp : mempool) (tx : Types.transaction)
    : (mempool_entry, string) result =
  match replace_by_fee_with_replaced mp tx with
  | Ok (e, _) -> Ok e
  | Error s -> Error s

(* Accept a transaction with full RBF support.
   If the transaction conflicts with existing mempool entries, automatically
   attempts replacement if the new transaction pays higher fees.
   This is the main entry point for accepting transactions with full RBF.

   FIX-73 W120 BUG-4: [accept_transaction_with_replaced] forwards the
   evicted-txid list from [replace_by_fee_with_replaced] so package and
   single-tx paths can plumb it into Core-compatible RPC responses.  The
   legacy [accept_transaction] wrapper preserves the old return type for
   the test suite. *)
let accept_transaction_with_replaced ?(dry_run=false)
    ?(skip_verify_scripts=false)
    (mp : mempool) (tx : Types.transaction)
    : (mempool_entry * Types.hash256 list, string) result =
  let result =
    (* First check if there are conflicts *)
    let conflicts = find_all_conflicts mp tx in
    match conflicts with
    | [] ->
      (* No conflicts, use normal add_transaction — empty replaced list *)
      (match add_transaction ~dry_run ~skip_verify_scripts mp tx with
       | Ok e -> Ok (e, [])
       | Error s -> Error s)
    | _ ->
      (* Conflict(s) present: evaluate the full RBF rule set.  In dry_run mode
         (testmempoolaccept) [replace_by_fee_with_replaced ~dry_run:true] runs
         every gate (rules 1-4 + ImprovesFeerateDiagram + the standardness/limit
         pre-check) against the live mempool but does NOT mutate state, so the
         reject-reason it surfaces is exactly what a real submit would produce.
         In non-dry-run mode it performs the eviction + insert.  This replaces the
         old behaviour where dry_run returned a generic
         "txn-mempool-conflict (dry run with conflicts)" that disagreed with the
         real sendrawtransaction outcome for the same conflicting tx. *)
      replace_by_fee_with_replaced ~dry_run ~skip_verify_scripts mp tx
  in
  (* Hot-path GC keep-up (2026-06-09, made non-STW 2026-06-24): this
     synchronous function is the single choke point for RPC
     sendrawtransaction (rpc.ml handle_sendrawtransaction runs it with ZERO
     Lwt yields — the detached gc_thread timer can never preempt it) as well
     as the _lwt wrapper and the RBF path.  Mirrors Bitcoin Core's
     AcceptToMemoryPool ending with FlushStateToDisk(PERIODIC)
     (validation.cpp:1803) — the budget check rides the work itself.  Drives
     the major collector forward with a NON-STW [Gc.major_slice]
     ([maybe_keep_up]) so the per-accept churn is reclaimed incrementally
     WITHOUT a stop-the-world pause on the RPC-serving domain (the 2026-06-24
     RPC-stall fix — the old [Gc.compact] here was the stall).  The rare STW
     backstop is owned by the gc_thread/status-loop on a dedicated domain, not
     this hot path.  Once per tx accept, never per-input; O(1)
     (Gc.major_slice 0 + one gettimeofday). *)
  Gc_guard.maybe_keep_up ~reason:"hot-path:sendraw";
  result

let accept_transaction ?(dry_run=false) ?(skip_verify_scripts=false)
    (mp : mempool) (tx : Types.transaction)
    : (mempool_entry, string) result =
  match accept_transaction_with_replaced ~dry_run ~skip_verify_scripts mp tx with
  | Ok (e, _) -> Ok e
  | Error s -> Error s

(* Bug #135 step 2: Lwt-flavoured ATMP entry that runs script verification
   on the Domain worker (via [verify_tx_scripts_lwt]) BEFORE entering the
   synchronous body of [accept_transaction_with_replaced].  All other
   pre-script gates (size, standardness, locktime, BIP-68, fee floor,
   cluster + ancestor/descendant limits, TRUC) keep running on the Lwt
   main thread inside the sync body — they are cheap relative to the
   script-verify step that this refactor moves off the main thread.

   Correctness note (TOCTOU): mempool / UTXO state is single-threaded
   under Lwt; cooperative yields can only land at our explicit Lwt.pause
   points (and inside the Domain wait in verify_scripts_parallel).  An
   interleaved handler can spend a UTXO out from under us between the
   pre-verify and the sync body, but the sync body re-reads
   [lookup_utxo] for every input and will produce a Missing-input error
   in that case — i.e. the worst case is a redundant verify + a clean
   reject, never a false-accept (UTXOs are immutable once present;
   they can only disappear, not change value/script). *)
let accept_transaction_with_replaced_lwt ?(dry_run=false)
    (mp : mempool) (tx : Types.transaction)
    : (mempool_entry * Types.hash256 list, string) result Lwt.t =
  let verify_first =
    if mp.verify_scripts then verify_tx_scripts_lwt mp tx
    else Lwt.return (Ok ())
  in
  let%lwt verified = verify_first in
  match verified with
  | Error e -> Lwt.return (Error e)
  | Ok () ->
    Lwt.return
      (accept_transaction_with_replaced ~dry_run
         ~skip_verify_scripts:true mp tx)

let accept_transaction_lwt ?(dry_run=false)
    (mp : mempool) (tx : Types.transaction)
    : (mempool_entry, string) result Lwt.t =
  let%lwt res =
    accept_transaction_with_replaced_lwt ~dry_run mp tx in
  match res with
  | Ok (e, _) -> Lwt.return (Ok e)
  | Error s -> Lwt.return (Error s)

(* AcceptToMemoryPool — main entry point matching Bitcoin Core's AcceptToMemoryPool.
   Validates and adds a transaction to the mempool, handling RBF conflicts.
   Returns (Ok entry) on success or (Error reason) on failure. *)

type accept_result = {
  atmp_accepted : bool;
  atmp_txid : Types.hash256;
  atmp_fee : int64;
  atmp_vsize : int;
  atmp_reject_reason : string option;
  (* FIX-73 W120 BUG-4: list of txids physically evicted by RBF when this tx
     was accepted as a replacement.  Empty when no conflicts were resolved
     (the common case: fresh outpoint admission).  Matches the per-tx
     contribution to Core's PackageMempoolAcceptResult::m_replaced_transactions. *)
  atmp_replaced_txids : Types.hash256 list;
}

let accept_to_memory_pool ?(test_accept=false) (mp : mempool) (tx : Types.transaction)
    : accept_result Lwt.t =
  (* Bug #134 + bug #135 step 2: cooperative-yield + Domain-parallel
     script verification.  The entry/exit [Lwt.pause] yields preserve
     bug #134's behaviour (RPC tasks get a slot between every tx
     accept).  Bug #135 step 2 additionally moves the per-tx script
     verification off the Lwt main thread by routing through
     [accept_transaction_with_replaced_lwt] / [accept_transaction_lwt],
     which delegate verify to [Validation.verify_scripts_parallel]
     (OCaml 5 Domain workers).

     W96 Bug 13: ATMP entry point must catch ALL exceptions.  Matches the
     W95-class hardening — peer-controlled inputs (txid/wtxid computation,
     script eval via libsecp, deeply nested helpers) MUST NOT be allowed to
     propagate failwith/Not_found/Invalid_argument out of ATMP, since RPC,
     P2P and miner paths call ATMP without their own try/with.  Core's
     equivalent is the ATMPArgs::m_state mechanism — every failure is
     reflected through TxValidationState, never via C++ exceptions. *)
  let%lwt () = Lwt.pause () in
  let txid =
    try Crypto.compute_txid tx
    with _ -> Types.zero_hash
  in
  let safe_run () : (mempool_entry * Types.hash256 list, string) result Lwt.t =
    Lwt.catch (fun () ->
      if test_accept then
        (* dry_run path never mutates — no real evictions possible. *)
        let%lwt r = accept_transaction_lwt ~dry_run:true mp tx in
        (match r with
         | Ok e -> Lwt.return (Ok (e, []))
         | Error s -> Lwt.return (Error s))
      else
        accept_transaction_with_replaced_lwt mp tx)
    (function
      | Failure msg ->
        Lwt.return (Error (Printf.sprintf "atmp-exception: %s" msg))
      | Invalid_argument msg ->
        Lwt.return (Error (Printf.sprintf "atmp-exception: %s" msg))
      | Not_found ->
        Lwt.return (Error "atmp-exception: Not_found")
      | exn ->
        Lwt.return (Error
          (Printf.sprintf "atmp-exception: %s" (Printexc.to_string exn))))
  in
  let%lwt outcome = safe_run () in
  let result = match outcome with
  | Ok (entry, replaced_txids) ->
    { atmp_accepted = true; atmp_txid = txid; atmp_fee = entry.fee;
      (* ceil(weight / 4) — must round up, not truncate; policy/policy.cpp:395-398 *)
      atmp_vsize = (entry.weight + 3) / 4;
      atmp_reject_reason = None;
      atmp_replaced_txids = replaced_txids; }
  | Error reason ->
    { atmp_accepted = false; atmp_txid = txid; atmp_fee = 0L; atmp_vsize = 0;
      atmp_reject_reason = Some reason;
      atmp_replaced_txids = []; }
  in
  (* Hot-path GC check (2026-06-09; non-STW slice + dedicated-domain backstop
     2026-06-24): covers the P2P TxMsg arm (cli.ml's listener routes every
     relayed tx through here — THE public-flood path that drove the un-pin
     thrash).  Core analog: AcceptToMemoryPool ends with
     FlushStateToDisk(PERIODIC) (validation.cpp:1803).  Non-STW
     [Gc.major_slice] keep-up reclaims the per-accept churn incrementally
     without stopping the RPC-serving domain; the ceiling backstop is
     fire-and-forget to the dedicated [Backstop] worker domain.  Once per tx,
     never per-input. *)
  Gc_guard.maybe_keep_up ~reason:"hot-path:atmp";
  Gc_guard.maybe_backstop ~reason:"hot-path:atmp";
  let%lwt () = Lwt.pause () in
  Lwt.return result

(* ============================================================================
   Orphan Transaction Pool (Task 8)
   ============================================================================ *)

(* Add a transaction to the orphan pool.
   BIP-339: primary key is wtxid so that witness-malleated copies of the same
   txid are deduplicated while different witnesses map to different entries.
   A secondary txid→wtxid index allows fast parent-arrival resolution. *)
let add_orphan (mp : mempool) (tx : Types.transaction) : unit =
  let txid = Crypto.compute_txid tx in
  let wtxid = Crypto.compute_wtxid tx in
  let wtxid_key = Cstruct.to_string wtxid in
  (* Dedup by wtxid — reject if this exact witness form is already present *)
  if not (Hashtbl.mem mp.orphans wtxid_key) then begin
    (* Enforce max orphan count by evicting oldest if full *)
    if Hashtbl.length mp.orphans >= mp.max_orphans then begin
      let oldest_key = ref "" in
      let oldest_time = ref max_float in
      Hashtbl.iter (fun k entry ->
        if entry.orphan_time < !oldest_time then begin
          oldest_key := k;
          oldest_time := entry.orphan_time
        end
      ) mp.orphans;
      if !oldest_key <> "" then begin
        (* Also remove the evicted entry from the secondary txid index *)
        (match Hashtbl.find_opt mp.orphans !oldest_key with
         | Some evicted ->
           let evicted_txid_key = Cstruct.to_string evicted.orphan_txid in
           Hashtbl.remove mp.orphan_by_txid evicted_txid_key
         | None -> ());
        Hashtbl.remove mp.orphans !oldest_key
      end
    end;
    let entry = {
      orphan_tx = tx;
      orphan_txid = txid;
      orphan_wtxid = wtxid;
      orphan_time = Unix.gettimeofday ();
    } in
    Hashtbl.replace mp.orphans wtxid_key entry;
    (* Secondary index: txid_str → wtxid_str for parent-arrival lookups *)
    let txid_key = Cstruct.to_string txid in
    Hashtbl.replace mp.orphan_by_txid txid_key wtxid_key
  end

(* Helper: remove an orphan from both the primary (wtxid-keyed) pool and the
   secondary txid→wtxid index. *)
let remove_orphan (mp : mempool) (orphan_key : string) (entry : orphan_entry) : unit =
  Hashtbl.remove mp.orphans orphan_key;
  let txid_key = Cstruct.to_string entry.orphan_txid in
  Hashtbl.remove mp.orphan_by_txid txid_key

(* Try to process orphans when a new transaction is accepted.
   Returns list of successfully added entries.
   Note: inputs reference parent txids (not wtxids), so new_txid is a txid. *)
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
        remove_orphan mp orphan_key orphan;
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
   Zero-value outputs are always dust. Returns list of dust output indices.
   The fee argument is the DUST feerate (dust_relay_fee = 3000), not the
   relay floor — see is_dust. *)
let get_dust_outputs (dust_relay_fee : int64) (tx : Types.transaction)
    : int list =
  List.mapi (fun i out ->
    if is_dust dust_relay_fee out then Some i else None
  ) tx.outputs |> List.filter_map Fun.id

(* PreCheckEphemeralTx: A transaction with dust outputs must have 0 fee.
   This prevents miners from having incentive to mine the tx alone, which
   would leave dust in the UTXO set.
   Reference: Bitcoin Core PreCheckEphemeralTx *)
let pre_check_ephemeral_tx (dust_relay_fee : int64) (tx : Types.transaction)
    (fee : int64) : (unit, string) result =
  let dust_outs = get_dust_outputs dust_relay_fee tx in
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
        let dust_indices = get_dust_outputs dust_relay_fee parent_tx in
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
let check_ephemeral_single (_mp : mempool) (tx : Types.transaction)
    (fee : int64) : (unit, string) result =
  match pre_check_ephemeral_tx dust_relay_fee tx fee with
  | Error msg -> Error msg
  | Ok () ->
    (* Standalone tx with dust is rejected unless it has 0 fee
       and will be validated as part of a package *)
    let dust_outs = get_dust_outputs dust_relay_fee tx in
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
  let max_age = orphan_expire_seconds in (* 20 minutes — shared with getorphantxs *)
  let to_remove = Hashtbl.fold (fun k entry acc ->
    if now -. entry.orphan_time > max_age then (k, entry) :: acc else acc
  ) mp.orphans [] in
  List.iter (fun (wtxid_key, entry) ->
    Hashtbl.remove mp.orphans wtxid_key;
    let txid_key = Cstruct.to_string entry.orphan_txid in
    Hashtbl.remove mp.orphan_by_txid txid_key
  ) to_remove;
  List.length to_remove

(* ============================================================================
   Update Current Height
   ============================================================================ *)

let update_height (mp : mempool) (height : int) : unit =
  mp.current_height <- height

let update_median_time (mp : mempool) (mtp : int32) : unit =
  mp.current_median_time <- mtp

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
      (* int64 LE nFeeDelta — FIX-72: emit any prioritisetransaction delta
         attached to this txid (Core txmempool.cpp:411 writes the same field
         under "all entries with a delta tracked"). *)
      put_int64_le payload (get_delta mp entry.txid)
    ) entries;
    (* mapDeltas: FIX-72 — write the full prioritisation map so Core / a
       restart with -persistmempool=1 can reconstruct.  FIX-77: load_mempool
       now applies these deltas via prioritise_transaction, matching Core's
       node/mempool_persist.cpp:128-132 LoadMempool ApplyDelta loop (default
       apply_fee_delta_priority=true since Core v25; only the RPC
       `importmempool` defaults the flag to false).
       FIX-77: exclude in-mempool entries from the standalone tail map —
       matches Core mempool_persist.cpp:200 [mapDeltas.erase(i.tx->GetHash())]
       which removes per-entry txids from the standalone map before
       serializing.  Without this exclusion, deltas for in-mempool entries
       would be written twice (once inline, once in the tail) and the
       LoadMempool ApplyDelta loop on the tail would double-count them. *)
    let in_pool = Hashtbl.create (Hashtbl.length mp.entries) in
    Hashtbl.iter (fun k _e -> Hashtbl.replace in_pool k ()) mp.entries;
    let deltas = Hashtbl.fold (fun k d acc ->
      if Hashtbl.mem in_pool k then acc
      else (k, d) :: acc
    ) mp.map_deltas [] in
    put_compact_size payload (List.length deltas);
    List.iter (fun (txid_str, delta) ->
      Buffer.add_string payload txid_str;
      put_int64_le payload delta
    ) deltas;
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
          let n_fee_delta = r_read_int64_le r in
          (match add_transaction mp tx with
           | Ok entry ->
             incr loaded;
             (* FIX-77: apply the per-entry inline nFeeDelta to map_deltas so
                modified-fee, RBF Rule 3, and getmempoolentry "fees.modified"
                pick it up.  Matches Core node/mempool_persist.cpp:99-102
                (LoadMempool ApplyDelta on per-entry nFeeDelta).  We record
                via prioritise_transaction so the delta survives eviction +
                re-admission via the standard apply_delta lookup path. *)
             if not (Int64.equal n_fee_delta 0L) then
               prioritise_transaction mp entry.txid n_fee_delta
           | Error _ ->
             (* FIX-77: entry could not be admitted (e.g. UTXO missing on
                fresh chain) — Core still records the standalone-delta path
                so any future arrival picks up priority.  Per-entry deltas
                for failed-admission txs are intentionally dropped (Core
                applies only when the loop body sees a valid tx). *)
             ())
        done;
        (* mapDeltas: FIX-77 — apply standalone deltas via
           prioritise_transaction so txids that are NOT (yet) in the mempool
           still get their delta recorded.  Matches Core
           node/mempool_persist.cpp:125-132 — read the full
           std::map<Txid, CAmount> mapDeltas and call PrioritiseTransaction
           for each entry.  Core gates this on apply_fee_delta_priority
           (default true on LoadMempool restart, false only on the
           `importmempool` RPC). *)
        let n_deltas = r_read_compact_size r in
        for _i = 1 to n_deltas do
          let txid_str = r_read_bytes r 32 in
          let amount = r_read_int64_le r in
          if not (Int64.equal amount 0L) then begin
            let txid_cs = Cstruct.of_string txid_str in
            prioritise_transaction mp txid_cs amount
          end
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

(* is_child_with_parents_tree — topology check required by submitpackage.
   Mirrors Bitcoin Core IsChildWithParentsTree (policy/packages.cpp):
     1. Package must have ≥ 2 transactions.
     2. Every non-last transaction must be a direct parent of the last (child)
        transaction, i.e. the child spends at least one output of each parent.
     3. No parent may spend an output of another parent (no parent-to-parent deps).
   Returns Ok () on valid child-with-parents-tree topology, Error msg otherwise.
   Reference: bitcoin-core/src/policy/packages.cpp IsChildWithParentsTree *)
let is_child_with_parents_tree (txs : Types.transaction list)
    : (unit, string) result =
  let n = List.length txs in
  if n < 2 then
    Error "package topology disallowed. not child-with-parents"
  else begin
    let parents = List.filteri (fun i _ -> i < n - 1) txs in
    let child   = List.nth txs (n - 1) in
    (* Collect all txids the child directly spends *)
    let child_input_txids =
      List.fold_left (fun acc inp ->
        let k = Cstruct.to_string inp.Types.previous_output.txid in
        Hashtbl.replace acc k (); acc
      ) (Hashtbl.create 8) child.Types.inputs
    in
    (* Every parent must be directly spent by the child *)
    let bad_parent = List.find_opt (fun p ->
      let ptxid = Crypto.compute_txid p in
      not (Hashtbl.mem child_input_txids (Cstruct.to_string ptxid))
    ) parents in
    (match bad_parent with
     | Some _ ->
       Error "package topology disallowed. not child-with-parents or parents depend on each other."
     | None ->
       (* Collect all parent txids *)
       let parent_txid_set =
         List.fold_left (fun acc p ->
           let k = Cstruct.to_string (Crypto.compute_txid p) in
           Hashtbl.replace acc k (); acc
         ) (Hashtbl.create 8) parents
       in
       (* No parent may spend an output of another parent *)
       let parent_spends_parent = List.exists (fun p ->
         List.exists (fun inp ->
           Hashtbl.mem parent_txid_set
             (Cstruct.to_string inp.Types.previous_output.txid)
         ) p.Types.inputs
       ) parents in
       if parent_spends_parent then
         Error "package topology disallowed. not child-with-parents or parents depend on each other."
       else
         Ok ())
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
   Accepts if package fee rate meets minimum, even if individual txs don't.

   FIX-73 W120 BUG-4: the [_with_replaced] variant returns the deduplicated
   union of all txids evicted by the package's admissions (across every
   per-tx RBF triggered inside the package).  Matches Core's
   PackageMempoolAcceptResult::m_replaced_transactions which accumulates the
   per-MempoolAcceptResult::m_replaced_transactions across the package
   (validation.cpp:760, rpc/mempool.cpp:1500).  The legacy [accept_package]
   wrapper returns only the package_result so the existing test suite +
   net-processing call sites stay source-compatible. *)
let accept_package_with_replaced (mp : mempool) (txs : Types.transaction list)
    : package_result * Types.hash256 list =
  (* Validate well-formedness *)
  match is_well_formed_package txs with
  | Error msg -> (PackageRejected msg, [])
  | Ok () ->
    (* Topologically sort *)
    match topo_sort txs with
    | Error msg -> (PackageRejected msg, [])
    | Ok sorted ->
      (* BUG-6 fix: enforce IsChildWithParentsTree topology for multi-tx packages.
         Core rejects any package that is not child-with-parents-tree before
         calling the validation engine (policy/packages.cpp, net_processing.cpp).
         Single-tx packages are exempted (equivalent to plain ATMP). *)
      let n_sorted = List.length sorted in
      (match (if n_sorted >= 2 then is_child_with_parents_tree sorted else Ok ()) with
       | Error msg -> (PackageRejected msg, [])
       | Ok () ->
      (* Track UTXOs created by earlier transactions in the package *)
      let package_utxos = Hashtbl.create 16 in
      let total_fee = ref 0L in
      let total_vsize = ref 0 in
      let accepted = ref [] in
      let rejected = ref [] in
      let package_txids = Hashtbl.create 16 in
      (* FIX-73 W120 BUG-4: accumulator for evicted-txid union across the
         package.  Hashtbl provides O(1) dedup keyed by binary txid string. *)
      let evicted_union : (string, Types.hash256) Hashtbl.t = Hashtbl.create 16 in

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
      (* BUG-5 fix: use effective_min_fee (max of static min_relay_fee and rolling
         decay floor) so that mempool-pressure packages cannot bypass the eviction
         floor.  Reference: CTxMemPool::GetMinFee + ATMP's mempoolReplacementInfo. *)
      let min_feerate = Int64.to_float (effective_min_fee mp) in

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
            (* FIX-73 W120 BUG-4: per-tx admission inside the package.  Pre-
               check for conflicts; if any are present route through the FIX-72
               wired [replace_by_fee_with_replaced] so RBF Rule 3 (with modified
               fees on both sides) gates the replacement and the evicted-txid
               list propagates up into the package's m_replaced_transactions
               union.  No conflicts → plain [add_transaction] path is preserved
               so CPFP-style packages keep their ~bypass_fee_check behaviour
               (replace_by_fee_with_replaced has no need for it — it operates
               on the candidate's own fees vs the conflict set).
               Note: this NARROWS BUG-7 (package-RBF) — per-tx RBF inside a
               package now works, but true package-feerate-based replacement
               (treating the whole package as one replacement unit per BIP-431
               §"RBF for packages") is still missing and tracked separately. *)
            let conflicts_for_tx = find_all_conflicts mp tx in
            let add_result =
              if conflicts_for_tx = [] then
                (match add_transaction ~bypass_fee_check:use_package_feerate mp tx with
                 | Ok e -> Ok (e, [])
                 | Error s -> Error s)
              else
                replace_by_fee_with_replaced mp tx
            in
            match add_result with
            | Ok (entry, evicted) ->
              accepted := entry :: !accepted;
              List.iter (fun (txid : Types.hash256) ->
                let k = Cstruct.to_string txid in
                if not (Hashtbl.mem evicted_union k) then
                  Hashtbl.replace evicted_union k txid
              ) evicted
            | Error msg -> rejected := (tx, msg) :: !rejected
          end
      ) fees_vsizes;

      let accepted_list = List.rev !accepted in
      let rejected_list = List.rev !rejected in
      let evicted_list =
        Hashtbl.fold (fun _k txid acc -> txid :: acc) evicted_union [] in

      (* Check ephemeral anchor policy: all dust outputs must be spent *)
      let pkg_result =
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
      in
      (* Hot-path GC check (2026-06-09; non-STW slice + dedicated-domain
         backstop 2026-06-24): once per <=25-tx package batch (covers P2P
         pkgtxns via package_relay.ml and RPC submitpackage), never
         per-tx/per-input.  Core analog: ProcessNewPackage ends with
         FlushStateToDisk(PERIODIC) (validation.cpp:1835).  Non-STW slice +
         dedicated-domain ceiling backstop (same rationale as the atmp/block
         sites). *)
      Gc_guard.maybe_keep_up ~reason:"hot-path:package";
      Gc_guard.maybe_backstop ~reason:"hot-path:package";
      (pkg_result, evicted_list)
      )  (* end is_child_with_parents_tree match *)

(* Thin discard-wrapper: legacy [accept_package] callers (test suite +
   net-processing) that don't surface the evicted-txid list. *)
let accept_package (mp : mempool) (txs : Types.transaction list)
    : package_result =
  fst (accept_package_with_replaced mp txs)

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
  (* Find orphans that spend this parent — carry the full entry for index cleanup *)
  let candidates = Hashtbl.fold (fun orphan_key entry acc ->
    let spends_parent = List.exists (fun inp ->
      Cstruct.equal inp.Types.previous_output.txid parent_txid
    ) entry.orphan_tx.Types.inputs in
    if spends_parent then (orphan_key, entry, entry.orphan_tx) :: acc else acc
  ) mp.orphans [] in

  match candidates with
  | [] -> PackageRejected "No orphans available for CPFP"
  | (orphan_key, oe, child) :: _ ->
    (* Try to validate as 1p1c package *)
    let result = accept_package mp [parent; child] in
    (match result with
     | PackageAccepted _ | PackagePartial { accepted = _ :: _; _ } ->
       (* Remove the orphan (primary + secondary index) since it was accepted *)
       remove_orphan mp orphan_key oe
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
        remove_orphan mp orphan_key orphan;
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

(* ============================================================================
   W86 Test Accessors — expose rolling-fee internals for unit tests
   Only used by test/test_mempool.ml; not part of the public API.
   ============================================================================ *)

let get_rolling_min_fee_rate (mp : mempool) : float =
  mp.rolling_min_fee_rate

let set_rolling_min_fee_rate (mp : mempool) (r : float) : unit =
  mp.rolling_min_fee_rate <- r

let get_block_since_last_rolling_fee_bump (mp : mempool) : bool =
  mp.block_since_last_rolling_fee_bump

let set_block_since_last_rolling_fee_bump (mp : mempool) (v : bool) : unit =
  mp.block_since_last_rolling_fee_bump <- v

let get_last_rolling_fee_update (mp : mempool) : float =
  mp.last_rolling_fee_update

let set_last_rolling_fee_update (mp : mempool) (t : float) : unit =
  mp.last_rolling_fee_update <- t

(* count — number of entries in the pool (alias for get_info fst) *)
let count (mp : mempool) : int =
  Hashtbl.length mp.entries

(* set_total_weight_for_testing — inject an arbitrary total_weight for eviction
   threshold tests without needing to add real transactions. *)
let set_total_weight_for_testing (mp : mempool) (w : int) : unit =
  mp.total_weight <- w

(* evict_by_chunks_for_testing — public wrapper so tests can call the eviction
   loop directly. *)
let evict_by_chunks_for_testing (mp : mempool) : unit =
  evict_by_chunks mp

(* set_entry_time_for_testing — backdate a transaction's time_added so expiry
   tests can trigger the 336h gate without sleeping. *)
let set_entry_time_for_testing (mp : mempool) (txid : Types.hash256) (t : float) : unit =
  let key = Cstruct.to_string txid in
  match Hashtbl.find_opt mp.entries key with
  | None -> ()
  | Some entry ->
    Hashtbl.replace mp.entries key { entry with time_added = t }
