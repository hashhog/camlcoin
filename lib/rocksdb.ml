(* Minimal RocksDB bindings via C stubs.
   See rocksdb_stubs.c for the C implementation. *)

type t  (* opaque: rocksdb_t* wrapped in a custom block *)
type batch  (* opaque: rocksdb_writebatch_t* wrapped in a custom block *)

external open_db : string -> int -> int -> int -> t
  = "caml_rocksdb_open"

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
