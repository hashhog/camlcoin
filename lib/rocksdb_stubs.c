/* RocksDB C API stubs for OCaml
 *
 * Bridges OCaml values to the RocksDB C API for UTXO set storage.
 * Uses custom blocks to prevent GC from collecting live DB handles. */

#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/fail.h>
#include <caml/custom.h>
#include <caml/callback.h>
#include <caml/threads.h>
#include <rocksdb/c.h>
#include <string.h>
#include <stdlib.h>
#include <malloc.h>
#include <pthread.h>

/* Force glibc to return free heap at the top of its arenas to the OS.
   camlcoin's Cstruct-based validation churns millions of tiny transient
   Bigarrays per block; glibc retains the freed blocks in its per-thread
   arenas (worsened by the multicore validation Domain) instead of returning
   them, so forward-sync RSS crept ~6MB/block off-heap even with
   MALLOC_ARENA_MAX/MALLOC_TRIM_THRESHOLD_ set passively. Called from sync.ml
   right after each Gc.compact() (which frees the OCaml-side Bigarray proxies)
   so the now-unused arena memory is actively released. malloc_trim is cheap
   relative to the surrounding compaction + validation. */
CAMLprim value caml_rocksdb_malloc_trim(value v_unit) {
  CAMLparam1(v_unit);
  /* malloc_trim can walk every glibc arena and be slow; release the OCaml
     runtime lock around it (mirrors the pattern in zmq_stubs.c around the
     blocking zmq_send) so SIGTERM handling and the RPC thread stay responsive
     even if the trim takes a while. malloc_trim touches no OCaml values, so
     releasing the runtime system around it is safe. */
  caml_release_runtime_system();
  malloc_trim(0);
  caml_acquire_runtime_system();
  CAMLreturn(Val_unit);
}

/* Per-store cap on open SST file descriptors. The daemon opens two
   RocksDB stores in one process and its Lwt loop runs on the select(2)
   backend, which cannot poll any fd >= FD_SETSIZE (1024). Two stores at
   256 each (= 512) plus stdio, sockets, WAL/MANIFEST and RocksDB
   internals stays well under that ceiling with headroom for the
   chainstate to keep growing. Applied via rocksdb_options_set_max_open_
   files() in every DB-open path below; see the open-path comment for
   the full rationale. */
#define ROCKSDB_MAX_OPEN_FILES 256

/* ---------- Cached read/write options ------------------------------------- */
/* Creating and destroying rocksdb_{read,write}options on every get/put call
   is surprisingly expensive: each call does a malloc + memset + free.
   Caching a single instance per type eliminates this overhead entirely.
   Thread-safety: rocksdb_readoptions/writeoptions are immutable after
   creation so sharing across threads is safe. */

static rocksdb_readoptions_t  *g_read_options  = NULL;
static rocksdb_writeoptions_t *g_write_options = NULL;

/* Created exactly once: point reads now run concurrently on several OCaml 5
   domains (block-input prefetch), so the lazy init must not race. */
static pthread_once_t g_read_options_once = PTHREAD_ONCE_INIT;
static void init_read_options(void) { g_read_options = rocksdb_readoptions_create(); }
static rocksdb_readoptions_t *get_read_options(void) {
  pthread_once(&g_read_options_once, init_read_options);
  return g_read_options;
}

/* Point read with the OCaml runtime released for the RocksDB call.
   A Get can block in pread() for milliseconds on a cache miss. Holding the
   domain lock across it means every stop-the-world minor GC requested by ANY
   other domain waits for the read (OCaml 5 STW needs every domain, or its
   backup thread, to answer). The key is copied out of the OCaml heap first
   because the GC may move/free it once the runtime is released. */
static char *get_released(rocksdb_t *db, rocksdb_column_family_handle_t *cfh,
                          value v_key, size_t *vallen, char **err) {
  size_t klen = caml_string_length(v_key);
  char stackbuf[128];
  char *kbuf = klen <= sizeof(stackbuf) ? stackbuf : malloc(klen);
  if (!kbuf) caml_raise_out_of_memory();
  memcpy(kbuf, String_val(v_key), klen);
  rocksdb_readoptions_t *ro = get_read_options();
  char *val;
  caml_release_runtime_system();
  if (cfh)
    val = rocksdb_get_cf(db, ro, cfh, kbuf, klen, vallen, err);
  else
    val = rocksdb_get(db, ro, kbuf, klen, vallen, err);
  caml_acquire_runtime_system();
  if (kbuf != stackbuf) free(kbuf);
  return val;
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

/* ---------- Bulk-load open tunables (snapshot import only) ------------- */
/* While non-zero, every open in this process raises max_background_flushes
   and max_write_buffer_number. bin/main.ml sets them around the two opens
   --import-utxo does and resets them before the node-run reopen.

   Why: the import is bound by how fast memtables reach disk. On the shared
   NVMe each flush stream is throttled (writeback throttling, ext4 journal
   waits), and a single flush thread per store left the loader parked in
   "Stopping writes because we have 3 immutable memtables". Several flush
   streams per store move the same bytes several times faster (A/B, 4M
   coins, same moment, same disk: 1 thread x 3 buffers 148 s, 4 x 6 72 s,
   8 x 10 55 s for load + final flush). Memtable memory is bounded by
   write_buffer_size x max_write_buffer_number per store. */
static int g_bulk_flush_threads = 0;  /* max_background_flushes */
static int g_bulk_write_buffers = 0;  /* max_write_buffer_number */

CAMLprim value caml_rocksdb_set_bulk_load_open(value v_flush_threads,
                                               value v_write_buffers) {
  g_bulk_flush_threads = Int_val(v_flush_threads);
  g_bulk_write_buffers = Int_val(v_write_buffers);
  return Val_unit;
}

static void apply_bulk_load_opts(rocksdb_options_t *opts) {
  if (g_bulk_flush_threads > 0) {
    rocksdb_options_set_max_background_flushes(opts, g_bulk_flush_threads);
    rocksdb_options_set_max_background_jobs(opts, g_bulk_flush_threads + 3);
  }
  if (g_bulk_write_buffers > 0)
    rocksdb_options_set_max_write_buffer_number(opts, g_bulk_write_buffers);
}

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
  apply_bulk_load_opts(opts);

  /* Cap the number of SST file descriptors RocksDB keeps open.
     RocksDB's default (max_open_files = -1) holds an FD open for every
     SST file in the LSM tree. A mature mainnet chainstate has 500+ SST
     files PER store, and this process opens two RocksDB stores
     (rocksdb_utxo + chainstate-rocks). Left unbounded, the combined FD
     count climbs past 1024 — and the daemon's Lwt event loop uses the
     select(2) backend (the libev backend is not installed), whose
     fd_set bitmap cannot represent any descriptor >= FD_SETSIZE (1024).
     The first such descriptor makes select() fail hard with EINVAL and
     the whole node aborts right after the RPC/P2P listeners come up.
     ROCKSDB_MAX_OPEN_FILES bounds each store so the process-wide FD
     total stays comfortably under the select() ceiling; RocksDB falls
     back to its internal table cache for any SST beyond the cap, which
     costs a re-open on a cold read but is otherwise transparent. */
  rocksdb_options_set_max_open_files(opts, ROCKSDB_MAX_OPEN_FILES);

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

  char *val = get_released(db, NULL, v_key, &vallen, &err);

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
  /* WAL stays ENABLED (rocksdb default). The previous code disabled the WAL
     here ("much faster ... can re-sync on crash"), but that premise was false:
     there is NO periodic WAL/memtable flush, so the chain tip + UTXO deltas —
     written ONLY through this batch path (storage.ml apply_block_atomic /
     set_chain_tip) — were durable only on a clean rocksdb_close (graceful
     SIGTERM). An unclean exit (SIGKILL/OOM/power loss) rewound the tip to the
     last natural SST flush, so the node booted to genesis ("Chain state
     initialized, headers at height 0") and re-IBD'd. With the WAL on, rocksdb
     appends each batch to the WAL and replays it on Open, recovering the tip to
     the crash height with no boot-path change — matching Core/leveldb, which
     always WAL the coins + DB_BEST_BLOCK batch (dbwrapper.cpp:285, txdb.cpp:159).
     WriteOptions.sync stays false (default): the WAL append is buffered, so this
     survives process death (page cache) though not a hard power loss without an
     fsync — matching Core's default (it syncs only on its periodic Flush). This
     preserves the RDB-then-CF "RDB >= CF durable" ordering invariant
     (apply_block_atomic) because BOTH stores commit through this same stub, so
     they gain WAL durability in lockstep (a crash can only leave RDB ahead of
     CF — the safe direction). NOTE: this adds a WAL append per batch; on a full
     re-IBD the bulk 500-block UTXO flush (sync.ml ~2609) doubles its write
     volume. A surgical `disable_wal` opt-out for ONLY the bulk-IBD flush (keeping
     the connect path WAL-on) is the throughput follow-up if re-IBD regresses. */
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

/* =========================================================================
 * Column family support — Option D (retire LogStorage, migrate 9 namespaces
 * to RocksDB column families). The helper API keeps the existing
 * single-CF [caml_rocksdb_*] entry points working unchanged; CF-aware
 * call sites use [caml_rocksdb_cf_*] explicitly.
 *
 * The handle layout uses a parent rocksdb_t* (owned by [Rocksdb_val]) and
 * a separately-allocated rocksdb_column_family_handle_t* per CF (owned by
 * [Cfh_val]). The CF handle's lifetime is bounded by the parent DB; the
 * caller MUST close all CF handles before closing the parent DB.
 * ========================================================================= */

#define Cfh_val(v) (*((rocksdb_column_family_handle_t **)Data_custom_val(v)))

/* CF handles do not need a finalizer that calls
   rocksdb_column_family_handle_destroy — that destroy is illegal once the
   parent DB has been closed, and OCaml's GC ordering between CF handle and
   parent DB is unspecified. We rely on explicit [caml_rocksdb_cf_destroy]
   from a [close_db] entry point. The OCaml binding guarantees this. */
static struct custom_operations cfh_ops = {
  "camlcoin.rocksdb.cfhandle",
  custom_finalize_default,
  custom_compare_default,
  custom_hash_default,
  custom_serialize_default,
  custom_deserialize_default,
  custom_compare_ext_default,
  custom_fixed_length_default,
};

/* Open (or create) a RocksDB DB with a fixed list of named column families.
   [v_cf_names] is an OCaml string array. Returns a tuple (db, cfh array)
   where cfh array is in the same order as v_cf_names. The "default" CF
   is implicitly created by RocksDB; callers MUST include "default" in
   v_cf_names if they want a handle to it. */
CAMLprim value caml_rocksdb_open_cfs(value v_path,
                                      value v_cf_names,
                                      value v_write_buffer_mb,
                                      value v_block_cache_mb,
                                      value v_bloom_bits) {
  CAMLparam5(v_path, v_cf_names, v_write_buffer_mb,
             v_block_cache_mb, v_bloom_bits);
  CAMLlocal4(v_db, v_cfh_array, v_cfh, v_pair);

  const char *path = String_val(v_path);
  int n = Wosize_val(v_cf_names);
  int write_buffer_mb = Int_val(v_write_buffer_mb);
  int block_cache_mb  = Int_val(v_block_cache_mb);
  int bloom_bits      = Int_val(v_bloom_bits);

  if (n <= 0) caml_failwith("rocksdb_open_cfs: empty CF list");

  /* Build name array + per-CF options array. We share one set of options
     across all CFs for simplicity; per-CF tuning can be added later. */
  const char **cf_names = (const char **)malloc(sizeof(const char *) * n);
  const rocksdb_options_t **cf_opts =
      (const rocksdb_options_t **)malloc(sizeof(rocksdb_options_t *) * n);
  rocksdb_column_family_handle_t **cf_handles =
      (rocksdb_column_family_handle_t **)
        malloc(sizeof(rocksdb_column_family_handle_t *) * n);

  if (!cf_names || !cf_opts || !cf_handles) {
    free(cf_names); free(cf_opts); free(cf_handles);
    caml_failwith("rocksdb_open_cfs: out of memory");
  }

  /* Shared base options for all CFs. */
  rocksdb_options_t *opts = rocksdb_options_create();
  rocksdb_options_set_create_if_missing(opts, 1);
  rocksdb_options_set_create_missing_column_families(opts, 1);
  rocksdb_options_set_write_buffer_size(opts,
      (size_t)write_buffer_mb * 1024 * 1024);
  rocksdb_options_set_max_write_buffer_number(opts, 3);
  rocksdb_options_set_target_file_size_base(opts, 64 * 1024 * 1024);
  rocksdb_options_set_max_background_jobs(opts, 4);
  rocksdb_options_set_level_compaction_dynamic_level_bytes(opts, 1);
  rocksdb_options_set_compression(opts, rocksdb_no_compression);
  apply_bulk_load_opts(opts);
  /* Bound the open-SST-fd count — see the ROCKSDB_MAX_OPEN_FILES define
     and caml_rocksdb_open for the full rationale. max_open_files is a
     DB-wide option, so setting it on the shared db_options here caps the
     whole chainstate store regardless of CF count. Without this the
     chainstate + UTXO stores together exhaust the select(2) FD_SETSIZE
     ceiling and the daemon aborts on EINVAL just after startup. */
  rocksdb_options_set_max_open_files(opts, ROCKSDB_MAX_OPEN_FILES);

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
  }
  rocksdb_options_set_block_based_table_factory(opts, table_opts);

  for (int i = 0; i < n; i++) {
    cf_names[i] = String_val(Field(v_cf_names, i));
    cf_opts[i] = opts;
  }

  char *err = NULL;
  rocksdb_t *db = rocksdb_open_column_families(
      opts, path, n, cf_names, cf_opts, cf_handles, &err);

  rocksdb_options_destroy(opts);
  rocksdb_block_based_options_destroy(table_opts);

  if (err) {
    char msg[512];
    snprintf(msg, sizeof(msg), "rocksdb_open_cfs: %s", err);
    rocksdb_free(err);
    free(cf_names); free(cf_opts); free(cf_handles);
    caml_failwith(msg);
  }

  v_db = caml_alloc_custom(&rocksdb_ops, sizeof(rocksdb_t *), 0, 1);
  Rocksdb_val(v_db) = db;

  v_cfh_array = caml_alloc(n, 0);
  for (int i = 0; i < n; i++) {
    v_cfh = caml_alloc_custom(&cfh_ops,
        sizeof(rocksdb_column_family_handle_t *), 0, 1);
    Cfh_val(v_cfh) = cf_handles[i];
    Store_field(v_cfh_array, i, v_cfh);
  }

  free(cf_names); free(cf_opts); free(cf_handles);

  v_pair = caml_alloc(2, 0);
  Store_field(v_pair, 0, v_db);
  Store_field(v_pair, 1, v_cfh_array);
  CAMLreturn(v_pair);
}

/* Destroy a single CF handle. Must be called for each handle BEFORE
   closing the parent DB. After this call the handle is unusable. */
CAMLprim value caml_rocksdb_cf_destroy(value v_db, value v_cfh) {
  CAMLparam2(v_db, v_cfh);
  rocksdb_t *db = Rocksdb_val(v_db);
  rocksdb_column_family_handle_t *cfh = Cfh_val(v_cfh);
  if (db && cfh) {
    rocksdb_column_family_handle_destroy(cfh);
    Cfh_val(v_cfh) = NULL;
  }
  CAMLreturn(Val_unit);
}

/* CF-aware get/put/delete. */
CAMLprim value caml_rocksdb_cf_get(value v_db, value v_cfh, value v_key) {
  CAMLparam3(v_db, v_cfh, v_key);
  CAMLlocal2(v_some, v_data);

  rocksdb_t *db = Rocksdb_val(v_db);
  rocksdb_column_family_handle_t *cfh = Cfh_val(v_cfh);
  if (!db || !cfh) caml_failwith("rocksdb_cf_get: handle is closed");

  char *err = NULL;
  size_t vallen = 0;

  char *val = get_released(db, cfh, v_key, &vallen, &err);

  if (err) {
    char msg[512];
    snprintf(msg, sizeof(msg), "rocksdb_cf_get: %s", err);
    rocksdb_free(err);
    caml_failwith(msg);
  }

  if (!val) {
    CAMLreturn(Val_none);
  }

  v_data = caml_alloc_string(vallen);
  memcpy(Bytes_val(v_data), val, vallen);
  rocksdb_free(val);

  v_some = caml_alloc(1, 0);
  Store_field(v_some, 0, v_data);
  CAMLreturn(v_some);
}

CAMLprim value caml_rocksdb_cf_put(value v_db, value v_cfh,
                                    value v_key, value v_val) {
  CAMLparam4(v_db, v_cfh, v_key, v_val);

  rocksdb_t *db = Rocksdb_val(v_db);
  rocksdb_column_family_handle_t *cfh = Cfh_val(v_cfh);
  if (!db || !cfh) caml_failwith("rocksdb_cf_put: handle is closed");

  char *err = NULL;

  rocksdb_put_cf(db, get_write_options(), cfh,
      String_val(v_key), caml_string_length(v_key),
      String_val(v_val), caml_string_length(v_val),
      &err);

  if (err) {
    char msg[512];
    snprintf(msg, sizeof(msg), "rocksdb_cf_put: %s", err);
    rocksdb_free(err);
    caml_failwith(msg);
  }

  CAMLreturn(Val_unit);
}

CAMLprim value caml_rocksdb_cf_delete(value v_db, value v_cfh, value v_key) {
  CAMLparam3(v_db, v_cfh, v_key);

  rocksdb_t *db = Rocksdb_val(v_db);
  rocksdb_column_family_handle_t *cfh = Cfh_val(v_cfh);
  if (!db || !cfh) caml_failwith("rocksdb_cf_delete: handle is closed");

  char *err = NULL;

  rocksdb_delete_cf(db, get_write_options(), cfh,
      String_val(v_key), caml_string_length(v_key),
      &err);

  if (err) {
    char msg[512];
    snprintf(msg, sizeof(msg), "rocksdb_cf_delete: %s", err);
    rocksdb_free(err);
    caml_failwith(msg);
  }

  CAMLreturn(Val_unit);
}

/* CF-aware writebatch put/delete. The batch can mix CFs. */
CAMLprim value caml_rocksdb_writebatch_put_cf(value v_wb, value v_cfh,
                                               value v_key, value v_val) {
  CAMLparam4(v_wb, v_cfh, v_key, v_val);

  rocksdb_writebatch_t *wb = Writebatch_val(v_wb);
  rocksdb_column_family_handle_t *cfh = Cfh_val(v_cfh);
  if (!wb || !cfh)
    caml_failwith("rocksdb_writebatch_put_cf: handle is closed");

  rocksdb_writebatch_put_cf(wb, cfh,
      String_val(v_key), caml_string_length(v_key),
      String_val(v_val), caml_string_length(v_val));

  CAMLreturn(Val_unit);
}

CAMLprim value caml_rocksdb_writebatch_delete_cf(value v_wb, value v_cfh,
                                                  value v_key) {
  CAMLparam3(v_wb, v_cfh, v_key);

  rocksdb_writebatch_t *wb = Writebatch_val(v_wb);
  rocksdb_column_family_handle_t *cfh = Cfh_val(v_cfh);
  if (!wb || !cfh)
    caml_failwith("rocksdb_writebatch_delete_cf: handle is closed");

  rocksdb_writebatch_delete_cf(wb, cfh,
      String_val(v_key), caml_string_length(v_key));

  CAMLreturn(Val_unit);
}

/* List the column families on disk for a given DB path. Returns a
   string array. Used by the migration command to decide whether a
   prior partial-migration needs resuming. */
CAMLprim value caml_rocksdb_list_column_families(value v_path) {
  CAMLparam1(v_path);
  CAMLlocal2(v_arr, v_s);

  const char *path = String_val(v_path);
  rocksdb_options_t *opts = rocksdb_options_create();
  char *err = NULL;
  size_t lencf = 0;

  char **cfs = rocksdb_list_column_families(opts, path, &lencf, &err);
  rocksdb_options_destroy(opts);

  if (err) {
    /* When the DB doesn't exist yet, RocksDB returns an error.
       Treat as empty list rather than failing. */
    rocksdb_free(err);
    CAMLreturn(caml_alloc(0, 0));
  }

  v_arr = caml_alloc((mlsize_t)lencf, 0);
  for (size_t i = 0; i < lencf; i++) {
    v_s = caml_copy_string(cfs[i]);
    Store_field(v_arr, i, v_s);
  }
  rocksdb_list_column_families_destroy(cfs, lencf);
  CAMLreturn(v_arr);
}

/* Iterate every key/value in a CF, calling [f key value] for each.
   For migration verification — should not be used on hot paths. */
CAMLprim value caml_rocksdb_cf_iter(value v_db, value v_cfh, value v_f) {
  CAMLparam3(v_db, v_cfh, v_f);
  CAMLlocal2(v_key, v_val);

  rocksdb_t *db = Rocksdb_val(v_db);
  rocksdb_column_family_handle_t *cfh = Cfh_val(v_cfh);
  if (!db || !cfh) caml_failwith("rocksdb_cf_iter: handle is closed");

  rocksdb_iterator_t *it =
      rocksdb_create_iterator_cf(db, get_read_options(), cfh);
  rocksdb_iter_seek_to_first(it);
  while (rocksdb_iter_valid(it)) {
    size_t klen = 0, vlen = 0;
    const char *kp = rocksdb_iter_key(it, &klen);
    const char *vp = rocksdb_iter_value(it, &vlen);

    v_key = caml_alloc_initialized_string(klen, kp);
    v_val = caml_alloc_initialized_string(vlen, vp);
    caml_callback2(v_f, v_key, v_val);

    rocksdb_iter_next(it);
  }
  char *err = NULL;
  rocksdb_iter_get_error(it, &err);
  rocksdb_iter_destroy(it);
  if (err) {
    char msg[512];
    snprintf(msg, sizeof(msg), "rocksdb_cf_iter: %s", err);
    rocksdb_free(err);
    caml_failwith(msg);
  }
  CAMLreturn(Val_unit);
}

/* Iterate every key/value in the DEFAULT column family of a plain
   (non-CF) store opened with caml_rocksdb_open -- i.e. Rocksdb_store's
   rocksdb_utxo, the coin store validation reads.  Keys arrive in bytewise
   order.  The iterator is created without an explicit snapshot, so RocksDB
   pins an implicit one: the walk sees one consistent point-in-time view
   even if writes land while it runs.  An exception raised by [f] destroys
   the iterator before it propagates (cf_iter above leaks it). */
CAMLprim value caml_rocksdb_iter(value v_db, value v_f) {
  CAMLparam2(v_db, v_f);
  CAMLlocal3(v_key, v_val, v_res);

  rocksdb_t *db = Rocksdb_val(v_db);
  if (!db) caml_failwith("rocksdb_iter: database is closed");

  rocksdb_iterator_t *it = rocksdb_create_iterator(db, get_read_options());
  rocksdb_iter_seek_to_first(it);
  while (rocksdb_iter_valid(it)) {
    size_t klen = 0, vlen = 0;
    const char *kp = rocksdb_iter_key(it, &klen);
    const char *vp = rocksdb_iter_value(it, &vlen);

    v_key = caml_alloc_initialized_string(klen, kp);
    v_val = caml_alloc_initialized_string(vlen, vp);
    v_res = caml_callback2_exn(v_f, v_key, v_val);
    if (Is_exception_result(v_res)) {
      rocksdb_iter_destroy(it);
      caml_raise(Extract_exception(v_res));
    }

    rocksdb_iter_next(it);
  }
  char *err = NULL;
  rocksdb_iter_get_error(it, &err);
  rocksdb_iter_destroy(it);
  if (err) {
    char msg[512];
    snprintf(msg, sizeof(msg), "rocksdb_iter: %s", err);
    rocksdb_free(err);
    caml_failwith(msg);
  }
  CAMLreturn(Val_unit);
}

/* ---------- Explicit point-in-time snapshots ---------------------------- */
/* gettxoutsetinfo must hash ONE state and label it with that state's tip.
   [caml_rocksdb_iter] pins an implicit snapshot when the iterator is
   CREATED, which is too late once the walk runs on another domain: the
   dirty overlay and the tip are captured on the Lwt main thread, and a
   flush landing between that capture and the iterator's creation would
   hash coins the overlay already holds (or miss ones it dropped).  So the
   snapshot is taken explicitly, in the same main-thread instant as the
   overlay copy, and the walk later iterates THAT snapshot.

   The custom block owns {db, snapshot, readoptions}.  Release is explicit
   ([snapshot_release]) because the finalizer could run after the DB was
   closed at shutdown; an unreleased snapshot only pins old SST files. */
typedef struct {
  rocksdb_t *db;
  const rocksdb_snapshot_t *snap;
  rocksdb_readoptions_t *ro;
} caml_rdb_snapshot;

#define Rdbsnap_val(v) ((caml_rdb_snapshot *)Data_custom_val(v))

static struct custom_operations rdbsnap_ops = {
  "camlcoin.rocksdb.snapshot",
  custom_finalize_default,
  custom_compare_default,
  custom_hash_default,
  custom_serialize_default,
  custom_deserialize_default,
  custom_compare_ext_default,
  custom_fixed_length_default,
};

CAMLprim value caml_rocksdb_snapshot_create(value v_db) {
  CAMLparam1(v_db);
  CAMLlocal1(v_snap);
  rocksdb_t *db = Rocksdb_val(v_db);
  if (!db) caml_failwith("rocksdb_snapshot_create: database is closed");
  v_snap = caml_alloc_custom(&rdbsnap_ops, sizeof(caml_rdb_snapshot), 0, 1);
  caml_rdb_snapshot *s = Rdbsnap_val(v_snap);
  s->db = db;
  s->snap = rocksdb_create_snapshot(db);
  s->ro = rocksdb_readoptions_create();
  rocksdb_readoptions_set_snapshot(s->ro, s->snap);
  /* A full walk must not evict the hot working set validation relies on. */
  rocksdb_readoptions_set_fill_cache(s->ro, 0);
  CAMLreturn(v_snap);
}

CAMLprim value caml_rocksdb_snapshot_release(value v_snap) {
  CAMLparam1(v_snap);
  caml_rdb_snapshot *s = Rdbsnap_val(v_snap);
  if (s->snap) {
    rocksdb_readoptions_destroy(s->ro);
    rocksdb_release_snapshot(s->db, s->snap);
    s->snap = NULL;
    s->ro = NULL;
  }
  CAMLreturn(Val_unit);
}

/* Like [caml_rocksdb_iter] but over an explicit snapshot, and with the
   runtime RELEASED around every RocksDB cursor move: a seek/next can block
   in pread() on a cache miss, and while this domain holds its runtime lock
   every stop-the-world minor GC of every other domain (the Lwt main domain
   included) waits for it.  The key/value bytes are copied into the OCaml
   heap only after the runtime is re-acquired; RocksDB owns them until the
   next cursor move. */
CAMLprim value caml_rocksdb_iter_snapshot(value v_snap, value v_f) {
  CAMLparam2(v_snap, v_f);
  CAMLlocal3(v_key, v_val, v_res);

  caml_rdb_snapshot *s = Rdbsnap_val(v_snap);
  if (!s->snap) caml_failwith("rocksdb_iter_snapshot: snapshot released");
  rocksdb_iterator_t *it = rocksdb_create_iterator(s->db, s->ro);
  caml_release_runtime_system();
  rocksdb_iter_seek_to_first(it);
  caml_acquire_runtime_system();
  while (rocksdb_iter_valid(it)) {
    size_t klen = 0, vlen = 0;
    const char *kp = rocksdb_iter_key(it, &klen);
    const char *vp = rocksdb_iter_value(it, &vlen);

    v_key = caml_alloc_initialized_string(klen, kp);
    v_val = caml_alloc_initialized_string(vlen, vp);
    v_res = caml_callback2_exn(v_f, v_key, v_val);
    if (Is_exception_result(v_res)) {
      rocksdb_iter_destroy(it);
      caml_raise(Extract_exception(v_res));
    }

    caml_release_runtime_system();
    rocksdb_iter_next(it);
    caml_acquire_runtime_system();
  }
  char *err = NULL;
  rocksdb_iter_get_error(it, &err);
  rocksdb_iter_destroy(it);
  if (err) {
    char msg[512];
    snprintf(msg, sizeof(msg), "rocksdb_iter_snapshot: %s", err);
    rocksdb_free(err);
    caml_failwith(msg);
  }
  CAMLreturn(Val_unit);
}

/* ---------- Snapshot-import durability helpers ------------------------- */
/* Write a batch with WAL on AND WriteOptions.sync = true (fsync the WAL
   before returning). Used for the snapshot-import-incomplete marker and
   the import's final tip_height, which must be on disk before the import
   is declared complete. */
CAMLprim value caml_rocksdb_writebatch_write_sync(value v_db, value v_wb) {
  CAMLparam2(v_db, v_wb);
  rocksdb_t *db = Rocksdb_val(v_db);
  if (!db) caml_failwith("rocksdb_writebatch_write_sync: database is closed");
  rocksdb_writebatch_t *wb = Writebatch_val(v_wb);
  if (!wb) caml_failwith("rocksdb_writebatch_write_sync: batch is destroyed");
  rocksdb_writeoptions_t *wopts = rocksdb_writeoptions_create();
  rocksdb_writeoptions_set_sync(wopts, 1);
  char *err = NULL;
  caml_release_runtime_system();
  rocksdb_write(db, wopts, wb, &err);
  caml_acquire_runtime_system();
  rocksdb_writeoptions_destroy(wopts);
  if (err) {
    char msg[512];
    snprintf(msg, sizeof(msg), "rocksdb_writebatch_write_sync: %s", err);
    rocksdb_free(err);
    caml_failwith(msg);
  }
  CAMLreturn(Val_unit);
}

/* Write a batch with the WAL DISABLED (snapshot import only). The rows are
   made durable by [caml_rocksdb_flush_memtables] before the import clears
   its incomplete marker. The runtime lock is released for the write: the
   batch lives outside the OCaml heap. */
CAMLprim value caml_rocksdb_writebatch_write_nowal(value v_db, value v_wb) {
  CAMLparam2(v_db, v_wb);
  rocksdb_t *db = Rocksdb_val(v_db);
  if (!db) caml_failwith("rocksdb_writebatch_write_nowal: database is closed");
  rocksdb_writebatch_t *wb = Writebatch_val(v_wb);
  if (!wb) caml_failwith("rocksdb_writebatch_write_nowal: batch is destroyed");
  rocksdb_writeoptions_t *wopts = rocksdb_writeoptions_create();
  rocksdb_writeoptions_disable_WAL(wopts, 1);
  char *err = NULL;
  caml_release_runtime_system();
  rocksdb_write(db, wopts, wb, &err);
  caml_acquire_runtime_system();
  rocksdb_writeoptions_destroy(wopts);
  if (err) {
    char msg[512];
    snprintf(msg, sizeof(msg), "rocksdb_writebatch_write_nowal: %s", err);
    rocksdb_free(err);
    caml_failwith(msg);
  }
  CAMLreturn(Val_unit);
}

/* Flush the memtable of every CF in [v_cfhs] (or the default CF when the
   array is empty) and wait. RocksDB fsyncs the SSTs and the MANIFEST
   before a waited flush returns. */
CAMLprim value caml_rocksdb_flush_memtables(value v_db, value v_cfhs) {
  CAMLparam2(v_db, v_cfhs);
  rocksdb_t *db = Rocksdb_val(v_db);
  if (!db) caml_failwith("rocksdb_flush_memtables: database is closed");
  size_t n = Wosize_val(v_cfhs);
  rocksdb_column_family_handle_t **hs = NULL;
  if (n > 0) {
    hs = malloc(sizeof(*hs) * n);
    if (!hs) caml_raise_out_of_memory();
    for (size_t i = 0; i < n; i++) {
      hs[i] = Cfh_val(Field(v_cfhs, i));
      if (!hs[i]) { free(hs); caml_failwith("rocksdb_flush_memtables: CF handle closed"); }
    }
  }
  rocksdb_flushoptions_t *fo = rocksdb_flushoptions_create();
  rocksdb_flushoptions_set_wait(fo, 1);
  char *err = NULL;
  caml_release_runtime_system();
  if (n == 0)
    rocksdb_flush(db, fo, &err);
  else
    for (size_t i = 0; i < n && !err; i++)
      rocksdb_flush_cf(db, fo, hs[i], &err);
  caml_acquire_runtime_system();
  rocksdb_flushoptions_destroy(fo);
  free(hs);
  if (err) {
    char msg[512];
    snprintf(msg, sizeof(msg), "rocksdb_flush_memtables: %s", err);
    rocksdb_free(err);
    caml_failwith(msg);
  }
  CAMLreturn(Val_unit);
}
