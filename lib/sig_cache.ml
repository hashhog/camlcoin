(* Signature/script verification cache.

   Stores results of successful script verifications to avoid re-verifying
   the same inputs during block connection and mempool acceptance.

   Matches Bitcoin Core's sigcache.cpp behavior:
   - Cache key: (wtxid, input_index, flags)
   - Bounded size with random eviction when full
   - Clear on reorg to prevent stale entries

   W159 BUG-17 / W160 BUG-1 fix: key on wtxid (witness-covering) not txid
   (no-witness). For SegWit inputs, two transactions can share the same
   non-witness txid but differ in witness data; keying on txid lets a
   malleated witness cache-hit a previously-verified valid witness and
   bypass script verification — a chain-split candidate vs Bitcoin Core
   which keys its sigcache on the full (sighash, pubkey, sig) tuple
   (sigcache.cpp:39-49). wtxid is SHA256d of the full serialised tx
   INCLUDING witness, so any witness mutation produces a different wtxid
   and therefore a different cache key — closing the malleability
   oracle. *)

(* ============================================================================
   Types
   ============================================================================ *)

(** Cache key uniquely identifies a script verification.
    The key must include script verification flags because verification
    under stricter flags (e.g., SCRIPT_VERIFY_WITNESS) should not satisfy
    a check under looser flags.

    [wtxid] is the WITNESS transaction id (SHA256d of full serialised
    transaction including witness data), NOT the no-witness txid.  See
    module-level comment for the SegWit-malleability chain-split this
    closes. *)
type cache_key = {
  wtxid : Types.hash256;
  input_index : int;
  flags : int;
}

(** Hash function for cache keys.
    Combines wtxid bytes with input_index and flags into a single int. *)
let hash_key (key : cache_key) : int =
  (* Use first 8 bytes of wtxid as base, XOR with index and flags *)
  let h = ref 0 in
  for i = 0 to min 7 (Cstruct.length key.wtxid - 1) do
    h := (!h lsl 8) lxor (Cstruct.get_uint8 key.wtxid i)
  done;
  !h lxor (key.input_index * 31) lxor (key.flags * 17)

(** Equality for cache keys. *)
let key_equal (a : cache_key) (b : cache_key) : bool =
  Cstruct.equal a.wtxid b.wtxid &&
  a.input_index = b.input_index &&
  a.flags = b.flags

(** Cache entry: stores the verification result (always true for successful
    verifications; failed verifications are not cached). *)
type cache_entry = {
  key : cache_key;
  mutable result : bool;
}

(** The signature cache type.
    Uses a hashtable for O(1) lookup and random eviction when full.
    This is simpler than Bitcoin Core's CuckooCache but effective. *)
type t = {
  table : (int, cache_entry list) Hashtbl.t;  (* hash -> entries with that hash *)
  mutable count : int;
  max_entries : int;
}

(* ============================================================================
   Cache Operations
   ============================================================================ *)

(** Default maximum entries (~50,000 to match Bitcoin Core's
    DEFAULT_SIGNATURE_CACHE_BYTES / entry_size approximation). *)
let default_max_entries = 50_000

(** Create a new signature cache with bounded size. *)
let create ?(max_entries = default_max_entries) () : t =
  {
    table = Hashtbl.create (min max_entries 1024);
    count = 0;
    max_entries;
  }

(** Lookup a verification result in the cache.
    Returns Some true if the verification is cached as successful,
    None if not in cache. *)
let lookup (cache : t) (key : cache_key) : bool option =
  let h = hash_key key in
  match Hashtbl.find_opt cache.table h with
  | None -> None
  | Some entries ->
    match List.find_opt (fun e -> key_equal e.key key) entries with
    | None -> None
    | Some entry -> Some entry.result

(** Evict random entries to make room for new ones.
    Removes approximately 10% of entries when cache is full.
    This is simpler than true LRU but effective for our use case. *)
let evict_random (cache : t) : unit =
  let to_evict = max 1 (cache.max_entries / 10) in
  let evicted = ref 0 in
  (* Iterate through buckets and remove some entries *)
  Hashtbl.filter_map_inplace (fun _h entries ->
    if !evicted >= to_evict then
      Some entries
    else begin
      match entries with
      | [] -> None
      | [_] ->
        incr evicted;
        cache.count <- cache.count - 1;
        None
      | _ :: rest ->
        incr evicted;
        cache.count <- cache.count - 1;
        Some rest
    end
  ) cache.table

(** Insert a verification result into the cache.
    If the cache is full, evicts some entries first.
    Only successful verifications should be cached. *)
let insert (cache : t) (key : cache_key) (result : bool) : unit =
  (* Only cache successful verifications *)
  if not result then ()
  else begin
    (* Check if already present *)
    let h = hash_key key in
    let already_present =
      match Hashtbl.find_opt cache.table h with
      | None -> false
      | Some entries -> List.exists (fun e -> key_equal e.key key) entries
    in

    if not already_present then begin
      (* Evict if full *)
      if cache.count >= cache.max_entries then
        evict_random cache;

      (* Insert new entry *)
      let entry = { key; result } in
      let entries =
        match Hashtbl.find_opt cache.table h with
        | None -> [entry]
        | Some existing -> entry :: existing
      in
      Hashtbl.replace cache.table h entries;
      cache.count <- cache.count + 1
    end
  end

(** Clear all entries from the cache.
    Should be called on reorg to prevent stale entries from a
    now-invalid chain. *)
let clear (cache : t) : unit =
  Hashtbl.clear cache.table;
  cache.count <- 0

(** Get the current number of entries in the cache. *)
let size (cache : t) : int =
  cache.count

(* ============================================================================
   Global Cache Instance
   ============================================================================ *)

(** Global signature cache instance.
    This is used by the validation module to cache verification results. *)
let global_cache : t ref = ref (create ())

(** Initialize or reinitialize the global cache with a specific size. *)
let init_global ?(max_entries = default_max_entries) () : unit =
  global_cache := create ~max_entries ()

(** Get the global cache instance. *)
let get_global () : t =
  !global_cache

(** Clear the global cache (e.g., on reorg). *)
let clear_global () : unit =
  clear !global_cache
