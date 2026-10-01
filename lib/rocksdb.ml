(* Minimal RocksDB bindings via C stubs.
   See rocksdb_stubs.c for the C implementation. *)

type t  (* opaque: rocksdb_t* wrapped in a custom block *)
type batch  (* opaque: rocksdb_writebatch_t* wrapped in a custom block *)

external open_db : string -> int -> int -> int -> t
  = "caml_rocksdb_open"

(* Actively return glibc free-arena memory to the OS (malloc_trim(0)).
   Called after Gc.compact() during forward-sync so the freed transient-Bigarray
   memory is released rather than retained in glibc's arenas. *)
external malloc_trim : unit -> unit
  = "caml_rocksdb_malloc_trim"

external close : t -> unit
  = "caml_rocksdb_close"

external get : t -> string -> string option
  = "caml_rocksdb_get"

external put : t -> string -> string -> unit
  = "caml_rocksdb_put"

external delete : t -> string -> unit
  = "caml_rocksdb_delete"

external write_batch_create : unit -> batch
  = "caml_rocksdb_writebatch_create"

external write_batch_put : batch -> string -> string -> unit
  = "caml_rocksdb_writebatch_put"

external write_batch_delete : batch -> string -> unit
  = "caml_rocksdb_writebatch_delete"

external write_batch_write : t -> batch -> unit
  = "caml_rocksdb_writebatch_write"

external write_batch_destroy : batch -> unit
  = "caml_rocksdb_writebatch_destroy"

(* --- Column family support (Option D) ----------------------------------
   See rocksdb_stubs.c "Column family support" section for ownership rules.
   In particular: the caller MUST destroy every cf_handle BEFORE closing
   the parent DB. *)

type cf_handle  (* opaque: rocksdb_column_family_handle_t* *)

external open_cfs :
  string -> string array -> int -> int -> int -> t * cf_handle array
  = "caml_rocksdb_open_cfs"
(* [open_cfs path cf_names write_buf_mb block_cache_mb bloom_bits].
   Returns the DB handle plus a CF handle array in the same order as
   cf_names. The "default" CF is implicitly created by RocksDB; include
   it in cf_names if you want a handle to it. *)

external cf_destroy : t -> cf_handle -> unit
  = "caml_rocksdb_cf_destroy"
(* Destroy a single CF handle. Must be called for each handle BEFORE
   closing the parent DB. *)

external cf_get : t -> cf_handle -> string -> string option
  = "caml_rocksdb_cf_get"

external cf_put : t -> cf_handle -> string -> string -> unit
  = "caml_rocksdb_cf_put"

external cf_delete : t -> cf_handle -> string -> unit
  = "caml_rocksdb_cf_delete"

external write_batch_put_cf : batch -> cf_handle -> string -> string -> unit
  = "caml_rocksdb_writebatch_put_cf"

external write_batch_delete_cf : batch -> cf_handle -> string -> unit
  = "caml_rocksdb_writebatch_delete_cf"

external list_column_families : string -> string array
  = "caml_rocksdb_list_column_families"
(* [list_column_families path] returns the on-disk CF names. Returns
   an empty array if the DB does not exist. *)

external cf_iter : t -> cf_handle -> (string -> string -> unit) -> unit
  = "caml_rocksdb_cf_iter"
(* Iterate every key/value in a CF, calling [f key value] for each.
   Holds RocksDB resources (iterator) for the duration; caller's [f]
   must not call back into the same DB. *)

external iter : t -> (string -> string -> unit) -> unit
  = "caml_rocksdb_iter"
(* Iterate every key/value in the DEFAULT column family, in bytewise key
   order, over an implicit point-in-time snapshot.  [f] must not call back
   into the same DB. *)

type snapshot

external snapshot_create : t -> snapshot = "caml_rocksdb_snapshot_create"
(* Pin a point-in-time view of the DEFAULT column family.  Must be released
   with [snapshot_release] before the DB is closed. *)

external snapshot_release : snapshot -> unit = "caml_rocksdb_snapshot_release"
(* Idempotent. *)

external iter_snapshot : snapshot -> (string -> string -> unit) -> unit
  = "caml_rocksdb_iter_snapshot"
(* [iter] over an explicit snapshot, releasing the OCaml runtime around each
   cursor move.  Safe to call from a non-main domain.  [f] must not call
   back into the same DB. *)

(* --- Snapshot-import helpers --------------------------------------- *)

external write_batch_write_sync : t -> batch -> unit
  = "caml_rocksdb_writebatch_write_sync"
(* Commit [batch] with the WAL fsynced before returning. *)

external set_bulk_load_open : int -> int -> unit
  = "caml_rocksdb_set_bulk_load_open"
(* [set_bulk_load_open flush_threads write_buffers]: while non-zero, stores
   opened by this process use that max_background_flushes and
   max_write_buffer_number (see rocksdb_stubs.c). Snapshot import only;
   reset with [0 0]. *)

external write_batch_write_nowal : t -> batch -> unit
  = "caml_rocksdb_writebatch_write_nowal"
(* Commit [batch] with the WAL disabled (snapshot import only). *)

external flush_memtables : t -> cf_handle array -> unit
  = "caml_rocksdb_flush_memtables"
(* Flush every CF in the array (default CF if empty) and wait. *)
