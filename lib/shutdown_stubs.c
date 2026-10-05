/* Shutdown deadline thread.
 *
 * graceful_shutdown closes RocksDB on the Lwt domain without releasing the
 * runtime lock (caml_rocksdb_close).  An OCaml systhread parked on
 * Thread.delay cannot start, or cannot resume, while that lock is held, so
 * it never reaches Unix._exit and the supervisor's SIGKILL wins
 * (journald result 'signal', status=9/KILL).  This thread is a raw pthread:
 * it never enters the OCaml runtime, so a stuck rocksdb_close cannot block
 * the sleep or the _exit(0).
 */

#include <caml/mlvalues.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

/* Gate 6: set to 1 when the shutdown was started by AbortNode. */
static volatile int shutdown_exit_code = 0;

CAMLprim value camlcoin_set_shutdown_exit_code(value v_code) {
  shutdown_exit_code = Int_val(v_code);
  return Val_unit;
}

static void *deadline_thread(void *arg) {
  int secs = (int)(intptr_t)arg;
  if (secs < 1) secs = 150;
  sleep((unsigned)secs);
  fprintf(stderr,
          "[camlcoin] shutdown deadline %ds exceeded — exiting %d so the "
          "supervisor does not SIGKILL\n",
          secs, shutdown_exit_code);
  fflush(stderr);
  _exit(shutdown_exit_code);
  return NULL;
}

CAMLprim value camlcoin_arm_shutdown_deadline(value v_secs) {
  int secs = Int_val(v_secs);
  pthread_t thread;
  int rc = pthread_create(&thread, NULL, deadline_thread,
                           (void *)(intptr_t)secs);
  if (rc != 0) return Val_false;
  pthread_detach(thread);
  return Val_true;
}
