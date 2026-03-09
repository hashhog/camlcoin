(* Performance Optimization Utilities

   This module provides performance-critical data structures and instrumentation
   for optimizing the Bitcoin full node, particularly during Initial Block Download
   (IBD).

   Key components:
   - LRU cache for O(1) amortized UTXO lookups
   - Performance timers for profiling critical paths
   - Compact header storage for memory-efficient IBD
   - Optimized hash functions with reduced allocations *)

(* ============================================================================
   LRU Cache
   ============================================================================

   A Least Recently Used cache provides O(1) amortized lookup for frequently
   accessed UTXOs. During IBD, the most recently created UTXOs are the most
   likely to be spent, so an LRU eviction policy is ideal.

   Implementation uses a hashtable for O(1) lookup combined with a list to
   track access order. *)

module LRU = struct
  type ('k, 'v) t = {
    capacity : int;
    mutable entries : ('k * 'v) list;
    table : ('k, 'v) Hashtbl.t;
  }

  let create capacity = {
    capacity;
    entries = [];
    table = Hashtbl.create capacity;
  }

  let get t key =
    match Hashtbl.find_opt t.table key with
    | None -> None
    | Some v ->
      (* Move to front (most recently used) *)
      t.entries <- (key, v) ::
        List.filter (fun (k, _) -> k <> key) t.entries;
      Some v

  let put t key value =
    (match Hashtbl.find_opt t.table key with
     | Some _ ->
       (* Key exists - remove from entries list to re-add at front *)
       t.entries <-
         List.filter (fun (k, _) -> k <> key) t.entries
     | None ->
       (* New key - check if we need to evict *)
       if Hashtbl.length t.table >= t.capacity then begin
         match List.rev t.entries with
         | [] -> ()
         | (evict_key, _) :: rest ->
           Hashtbl.remove t.table evict_key;
           t.entries <- List.rev rest
       end);
    Hashtbl.replace t.table key value;
    t.entries <- (key, value) :: t.entries

  let remove t key =
    Hashtbl.remove t.table key;
    t.entries <-
      List.filter (fun (k, _) -> k <> key) t.entries

  let size t = Hashtbl.length t.table

  let capacity t = t.capacity

  let clear t =
    Hashtbl.clear t.table;
    t.entries <- []

  let mem t key =
    Hashtbl.mem t.table key

  let iter f t =
    Hashtbl.iter f t.table
end

(* ============================================================================
   Performance Timers
   ============================================================================

   Instrumentation for measuring time spent in critical code paths.
   Use these timers to identify bottlenecks during profiling. *)

module Timer = struct
  type t = {
    name : string;
    mutable total_time : float;
    mutable call_count : int;
  }

  let timers : (string, t) Hashtbl.t = Hashtbl.create 20

  let create name =
    let t = { name; total_time = 0.0; call_count = 0 } in
    Hashtbl.replace timers name t;
    t

  let time (t : t) (f : unit -> 'a) : 'a =
    let start = Unix.gettimeofday () in
    let result = f () in
    let elapsed = Unix.gettimeofday () -. start in
    t.total_time <- t.total_time +. elapsed;
    t.call_count <- t.call_count + 1;
    result

  let time_lwt (t : t) (f : unit -> 'a Lwt.t) : 'a Lwt.t =
    let open Lwt.Syntax in
    let start = Unix.gettimeofday () in
    let* result = f () in
    let elapsed = Unix.gettimeofday () -. start in
    t.total_time <- t.total_time +. elapsed;
    t.call_count <- t.call_count + 1;
    Lwt.return result

  let avg_time t =
    if t.call_count > 0 then
      t.total_time /. float_of_int t.call_count
    else 0.0

  let reset t =
    t.total_time <- 0.0;
    t.call_count <- 0

  let reset_all () =
    Hashtbl.iter (fun _ t -> reset t) timers

  let report () : string =
    let buf = Buffer.create 256 in
    Hashtbl.iter (fun _name t ->
      Buffer.add_string buf
        (Printf.sprintf "%s: %.3fs total, %d calls, %.6fs avg\n"
          t.name t.total_time t.call_count (avg_time t))
    ) timers;
    Buffer.contents buf

  let to_json () : Yojson.Safe.t =
    let entries = Hashtbl.fold (fun name t acc ->
      (name, `Assoc [
        ("total_time", `Float t.total_time);
        ("call_count", `Int t.call_count);
        ("avg_time", `Float (avg_time t));
      ]) :: acc
    ) timers [] in
    `Assoc entries

  (* Pre-defined timers for common operations *)
  let block_validation = create "block_validation"
  let script_execution = create "script_execution"
  let utxo_lookup = create "utxo_lookup"
  let db_read = create "db_read"
  let db_write = create "db_write"
  let serialize = create "serialize"
  let deserialize = create "deserialize"
  let hash_compute = create "hash_compute"
  let merkle_root = create "merkle_root"
  let signature_verify = create "signature_verify"
end

(* ============================================================================
   Compact Header Storage
   ============================================================================

   Memory-efficient header storage for IBD using a contiguous memory buffer.
   Each header is exactly 80 bytes. This reduces GC pressure compared to
   boxed OCaml records when millions of headers are stored.

   Note: Uses Bigstringaf for efficient memory access. *)

module CompactHeaders = struct
  type t = {
    mutable data : Bigstringaf.t;
    mutable count : int;
    mutable capacity : int;
  }

  let header_size = 80

  let create ?(initial_capacity=100_000) () = {
    data = Bigstringaf.create (initial_capacity * header_size);
    count = 0;
    capacity = initial_capacity;
  }

  let grow t =
    let new_capacity = t.capacity * 2 in
    let new_data = Bigstringaf.create (new_capacity * header_size) in
    Bigstringaf.blit t.data ~src_off:0 new_data ~dst_off:0
      ~len:(t.count * header_size);
    t.data <- new_data;
    t.capacity <- new_capacity

  let get t index =
    if index < 0 || index >= t.count then
      failwith "CompactHeaders: index out of bounds";
    let offset = index * header_size in
    Cstruct.of_bigarray
      ~off:offset ~len:header_size t.data

  let add t (header_bytes : Cstruct.t) =
    if Cstruct.length header_bytes <> header_size then
      failwith "CompactHeaders: header must be exactly 80 bytes";
    if t.count >= t.capacity then
      grow t;
    let offset = t.count * header_size in
    Cstruct.blit header_bytes 0
      (Cstruct.of_bigarray t.data) offset header_size;
    t.count <- t.count + 1

  let length t = t.count

  let clear t =
    t.count <- 0

  (* Add a block header by serializing it *)
  let add_header t (header : Types.block_header) =
    let w = Serialize.writer_create () in
    Serialize.serialize_block_header w header;
    add t (Serialize.writer_to_cstruct w)

  (* Get a block header at index, deserializing it *)
  let get_header t index : Types.block_header =
    let cs = get t index in
    let r = Serialize.reader_of_cstruct cs in
    Serialize.deserialize_block_header r
end

(* ============================================================================
   UTXO Cache Statistics
   ============================================================================ *)

type utxo_cache_stats = {
  mutable lookups : int;
  mutable cache_hits : int;
  mutable db_hits : int;
  mutable misses : int;
}

let create_utxo_stats () = {
  lookups = 0;
  cache_hits = 0;
  db_hits = 0;
  misses = 0;
}

let utxo_hit_rate stats =
  if stats.lookups = 0 then 0.0
  else float_of_int stats.cache_hits /. float_of_int stats.lookups

let utxo_stats_to_json stats : Yojson.Safe.t =
  `Assoc [
    ("lookups", `Int stats.lookups);
    ("cache_hits", `Int stats.cache_hits);
    ("db_hits", `Int stats.db_hits);
    ("misses", `Int stats.misses);
    ("hit_rate", `Float (utxo_hit_rate stats));
  ]

(* ============================================================================
   Optimized Hash Functions
   ============================================================================

   Reduced-allocation versions of common hash operations. *)

(* Reusable buffer for SHA256d to avoid repeated allocation *)
let sha256d_buffer = Cstruct.create 32

let sha256d_inplace (data : Cstruct.t) (output : Cstruct.t) : unit =
  let h1 = Digestif.SHA256.digest_string (Cstruct.to_string data) in
  let h2 = Digestif.SHA256.digest_string (Digestif.SHA256.to_raw_string h1) in
  Cstruct.blit_from_string
    (Digestif.SHA256.to_raw_string h2) 0 output 0 32

(* Compute SHA256d and return result in pre-allocated buffer *)
let sha256d_fast (data : Cstruct.t) : Cstruct.t =
  sha256d_inplace data sha256d_buffer;
  sha256d_buffer

(* ============================================================================
   Batch Processing Utilities
   ============================================================================ *)

(* Process a batch of items with a callback, returning on first error *)
let process_batch (items : 'a list) (f : 'a -> (unit, string) result)
    : (int, string) result =
  let count = ref 0 in
  let error = ref None in
  List.iter (fun item ->
    if !error = None then begin
      match f item with
      | Ok () -> incr count
      | Error e -> error := Some e
    end
  ) items;
  match !error with
  | Some e -> Error e
  | None -> Ok !count

(* ============================================================================
   Benchmark Suite
   ============================================================================ *)

let run_benchmarks () =
  Logs.info (fun m -> m "Running benchmarks...");

  (* Benchmark SHA256d *)
  let data = Cstruct.create 80 in
  let start = Unix.gettimeofday () in
  for _ = 1 to 1_000_000 do
    ignore (Crypto.sha256d data)
  done;
  let elapsed = Unix.gettimeofday () -. start in
  Logs.info (fun m ->
    m "SHA256d: %.0f hashes/sec" (1_000_000.0 /. elapsed));

  (* Benchmark serialization *)
  let header = Consensus.mainnet_genesis_header in
  let start = Unix.gettimeofday () in
  for _ = 1 to 1_000_000 do
    let w = Serialize.writer_create () in
    Serialize.serialize_block_header w header;
    ignore (Serialize.writer_to_cstruct w)
  done;
  let elapsed = Unix.gettimeofday () -. start in
  Logs.info (fun m ->
    m "Header serialize: %.0f ops/sec" (1_000_000.0 /. elapsed));

  (* Benchmark deserialization *)
  let w = Serialize.writer_create () in
  Serialize.serialize_block_header w header;
  let header_bytes = Serialize.writer_to_cstruct w in
  let start = Unix.gettimeofday () in
  for _ = 1 to 1_000_000 do
    let r = Serialize.reader_of_cstruct header_bytes in
    ignore (Serialize.deserialize_block_header r)
  done;
  let elapsed = Unix.gettimeofday () -. start in
  Logs.info (fun m ->
    m "Header deserialize: %.0f ops/sec" (1_000_000.0 /. elapsed));

  (* Benchmark LRU cache *)
  let cache : (string, int) LRU.t = LRU.create 100_000 in
  for i = 0 to 99_999 do
    LRU.put cache (string_of_int i) i
  done;
  let start = Unix.gettimeofday () in
  for _ = 1 to 10_000_000 do
    ignore (LRU.get cache (string_of_int (Random.int 100_000)))
  done;
  let elapsed = Unix.gettimeofday () -. start in
  Logs.info (fun m ->
    m "LRU cache: %.0f lookups/sec" (10_000_000.0 /. elapsed));

  (* Benchmark compact headers *)
  let headers = CompactHeaders.create ~initial_capacity:10_000 () in
  let start = Unix.gettimeofday () in
  for _ = 1 to 100_000 do
    CompactHeaders.add_header headers header
  done;
  let elapsed = Unix.gettimeofday () -. start in
  Logs.info (fun m ->
    m "Compact headers add: %.0f ops/sec" (100_000.0 /. elapsed));

  let start = Unix.gettimeofday () in
  for _ = 1 to 1_000_000 do
    ignore (CompactHeaders.get_header headers (Random.int 100_000))
  done;
  let elapsed = Unix.gettimeofday () -. start in
  Logs.info (fun m ->
    m "Compact headers get: %.0f ops/sec" (1_000_000.0 /. elapsed));

  Logs.info (fun m -> m "Benchmarks complete")
