/* RocksDB C API stubs for OCaml
 *
 * Bridges OCaml values to the RocksDB C API for UTXO set storage.
 * Uses custom blocks to prevent GC from collecting live DB handles. */

#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/fail.h>
#include <caml/custom.h>
#include <rocksdb/c.h>
#include <string.h>
#include <stdlib.h>

/* ---------- Cached read/write options ------------------------------------- */
/* Creating and destroying rocksdb_{read,write}options on every get/put call
   is surprisingly expensive: each call does a malloc + memset + free.
   Caching a single instance per type eliminates this overhead entirely.
   Thread-safety: rocksdb_readoptions/writeoptions are immutable after
   creation so sharing across threads is safe. */

static rocksdb_readoptions_t  *g_read_options  = NULL;
static rocksdb_writeoptions_t *g_write_options = NULL;

static rocksdb_readoptions_t *get_read_options(void) {
  if (!g_read_options) g_read_options = rocksdb_readoptions_create();
  return g_read_options;
}

static rocksdb_writeoptions_t *get_write_options(void) {
  if (!g_write_options) g_write_options = rocksdb_writeoptions_create();
  return g_write_options;
}

/* ---------- Custom block for rocksdb_t* --------------------------------- */

#define Rocksdb_val(v) (*((rocksdb_t **)Data_custom_val(v)))

static void rocksdb_finalize(value v) {
  rocksdb_t *db = Rocksdb_val(v);
  if (db) {
    rocksdb_close(db);
    Rocksdb_val(v) = NULL;
  }
}

static struct custom_operations rocksdb_ops = {
  "camlcoin.rocksdb",
  rocksdb_finalize,
  custom_compare_default,
  custom_hash_default,
  custom_serialize_default,
  custom_deserialize_default,
  custom_compare_ext_default,
  custom_fixed_length_default,
};

/* ---------- Custom block for write_batch -------------------------------- */

#define Writebatch_val(v) (*((rocksdb_writebatch_t **)Data_custom_val(v)))

static void writebatch_finalize(value v) {
  rocksdb_writebatch_t *wb = Writebatch_val(v);
  if (wb) {
    rocksdb_writebatch_destroy(wb);
    Writebatch_val(v) = NULL;
  }
}

static struct custom_operations writebatch_ops = {
  "camlcoin.rocksdb.writebatch",
  writebatch_finalize,
  custom_compare_default,
  custom_hash_default,
  custom_serialize_default,
  custom_deserialize_default,
  custom_compare_ext_default,
  custom_fixed_length_default,
};

/* ---------- open -------------------------------------------------------- */

CAMLprim value caml_rocksdb_open(value v_path,
                                  value v_write_buffer_mb,
                                  value v_block_cache_mb,
                                  value v_bloom_bits) {
  CAMLparam4(v_path, v_write_buffer_mb, v_block_cache_mb, v_bloom_bits);
  CAMLlocal1(v_db);

  const char *path = String_val(v_path);
  int write_buffer_mb = Int_val(v_write_buffer_mb);
  int block_cache_mb  = Int_val(v_block_cache_mb);
  int bloom_bits      = Int_val(v_bloom_bits);

  char *err = NULL;

  rocksdb_options_t *opts = rocksdb_options_create();
  rocksdb_options_set_create_if_missing(opts, 1);
  rocksdb_options_set_write_buffer_size(opts,
      (size_t)write_buffer_mb * 1024 * 1024);
  rocksdb_options_set_max_write_buffer_number(opts, 3);
  rocksdb_options_set_target_file_size_base(opts, 64 * 1024 * 1024);
  rocksdb_options_set_max_background_jobs(opts, 4);
  rocksdb_options_set_level_compaction_dynamic_level_bytes(opts, 1);
  rocksdb_options_set_compression(opts, rocksdb_no_compression);

  /* Block-based table with bloom filter and LRU block cache */
  rocksdb_block_based_table_options_t *table_opts =
      rocksdb_block_based_options_create();
  if (bloom_bits > 0) {
    rocksdb_filterpolicy_t *bloom =
        rocksdb_filterpolicy_create_bloom(bloom_bits);
    rocksdb_block_based_options_set_filter_policy(table_opts, bloom);
  }
  if (block_cache_mb > 0) {
    rocksdb_cache_t *cache =
        rocksdb_cache_create_lru((size_t)block_cache_mb * 1024 * 1024);
    rocksdb_block_based_options_set_block_cache(table_opts, cache);
    /* cache is now owned by table_opts */
  }
  rocksdb_options_set_block_based_table_factory(opts, table_opts);

  rocksdb_t *db = rocksdb_open(opts, path, &err);
  rocksdb_options_destroy(opts);
  rocksdb_block_based_options_destroy(table_opts);

  if (err) {
    char msg[512];
    snprintf(msg, sizeof(msg), "rocksdb_open: %s", err);
    rocksdb_free(err);
    caml_failwith(msg);
  }

  v_db = caml_alloc_custom(&rocksdb_ops, sizeof(rocksdb_t *), 0, 1);
  Rocksdb_val(v_db) = db;
  CAMLreturn(v_db);
}

/* ---------- close ------------------------------------------------------- */

CAMLprim value caml_rocksdb_close(value v_db) {
  CAMLparam1(v_db);
  rocksdb_t *db = Rocksdb_val(v_db);
  if (db) {
    rocksdb_close(db);
    Rocksdb_val(v_db) = NULL;
  }
  CAMLreturn(Val_unit);
}

/* ---------- get --------------------------------------------------------- */

CAMLprim value caml_rocksdb_get(value v_db, value v_key) {
  CAMLparam2(v_db, v_key);
  CAMLlocal2(v_some, v_data);

  rocksdb_t *db = Rocksdb_val(v_db);
  if (!db) caml_failwith("rocksdb_get: database is closed");

  char *err = NULL;
  size_t vallen = 0;

  char *val = rocksdb_get(db, get_read_options(),
      String_val(v_key), caml_string_length(v_key),
      &vallen, &err);

  if (err) {
    char msg[512];
    snprintf(msg, sizeof(msg), "rocksdb_get: %s", err);
    rocksdb_free(err);
    caml_failwith(msg);
  }

  if (!val) {
    CAMLreturn(Val_none);
  }

  v_data = caml_alloc_string(vallen);
  memcpy(Bytes_val(v_data), val, vallen);
  rocksdb_free(val);

  v_some = caml_alloc(1, 0);  /* Some */
  Store_field(v_some, 0, v_data);
  CAMLreturn(v_some);
}

/* ---------- put --------------------------------------------------------- */

CAMLprim value caml_rocksdb_put(value v_db, value v_key, value v_val) {
  CAMLparam3(v_db, v_key, v_val);

  rocksdb_t *db = Rocksdb_val(v_db);
  if (!db) caml_failwith("rocksdb_put: database is closed");

  char *err = NULL;

  rocksdb_put(db, get_write_options(),
      String_val(v_key), caml_string_length(v_key),
      String_val(v_val), caml_string_length(v_val),
      &err);

  if (err) {
    char msg[512];
    snprintf(msg, sizeof(msg), "rocksdb_put: %s", err);
    rocksdb_free(err);
    caml_failwith(msg);
  }

  CAMLreturn(Val_unit);
}

/* ---------- delete ------------------------------------------------------ */

CAMLprim value caml_rocksdb_delete(value v_db, value v_key) {
  CAMLparam2(v_db, v_key);

  rocksdb_t *db = Rocksdb_val(v_db);
  if (!db) caml_failwith("rocksdb_delete: database is closed");

  char *err = NULL;

  rocksdb_delete(db, get_write_options(),
      String_val(v_key), caml_string_length(v_key),
      &err);

  if (err) {
    char msg[512];
    snprintf(msg, sizeof(msg), "rocksdb_delete: %s", err);
    rocksdb_free(err);
    caml_failwith(msg);
  }

  CAMLreturn(Val_unit);
}

/* ---------- write batch ------------------------------------------------- */

CAMLprim value caml_rocksdb_writebatch_create(value v_unit) {
  CAMLparam1(v_unit);
  CAMLlocal1(v_wb);

  rocksdb_writebatch_t *wb = rocksdb_writebatch_create();
  v_wb = caml_alloc_custom(&writebatch_ops,
      sizeof(rocksdb_writebatch_t *), 0, 1);
  Writebatch_val(v_wb) = wb;
  CAMLreturn(v_wb);
}

CAMLprim value caml_rocksdb_writebatch_put(value v_wb,
                                            value v_key,
                                            value v_val) {
  CAMLparam3(v_wb, v_key, v_val);

  rocksdb_writebatch_t *wb = Writebatch_val(v_wb);
  if (!wb) caml_failwith("rocksdb_writebatch_put: batch is destroyed");

  rocksdb_writebatch_put(wb,
      String_val(v_key), caml_string_length(v_key),
      String_val(v_val), caml_string_length(v_val));

  CAMLreturn(Val_unit);
}

CAMLprim value caml_rocksdb_writebatch_delete(value v_wb, value v_key) {
  CAMLparam2(v_wb, v_key);

  rocksdb_writebatch_t *wb = Writebatch_val(v_wb);
  if (!wb) caml_failwith("rocksdb_writebatch_delete: batch is destroyed");

  rocksdb_writebatch_delete(wb,
      String_val(v_key), caml_string_length(v_key));

  CAMLreturn(Val_unit);
}

CAMLprim value caml_rocksdb_writebatch_write(value v_db, value v_wb) {
  CAMLparam2(v_db, v_wb);

  rocksdb_t *db = Rocksdb_val(v_db);
  if (!db) caml_failwith("rocksdb_writebatch_write: database is closed");

  rocksdb_writebatch_t *wb = Writebatch_val(v_wb);
  if (!wb) caml_failwith("rocksdb_writebatch_write: batch is destroyed");

  rocksdb_writeoptions_t *wopts = rocksdb_writeoptions_create();
  /* Disable WAL sync for batch writes during IBD — much faster,
     acceptable because we flush periodically and can re-sync on crash. */
  rocksdb_writeoptions_disable_WAL(wopts, 1);
  char *err = NULL;

  rocksdb_write(db, wopts, wb, &err);
  rocksdb_writeoptions_destroy(wopts);

  if (err) {
    char msg[512];
    snprintf(msg, sizeof(msg), "rocksdb_writebatch_write: %s", err);
    rocksdb_free(err);
    caml_failwith(msg);
  }

  CAMLreturn(Val_unit);
}

CAMLprim value caml_rocksdb_writebatch_destroy(value v_wb) {
  CAMLparam1(v_wb);

  rocksdb_writebatch_t *wb = Writebatch_val(v_wb);
  if (wb) {
    rocksdb_writebatch_destroy(wb);
    Writebatch_val(v_wb) = NULL;
  }

  CAMLreturn(Val_unit);
}
