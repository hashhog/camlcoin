/* ZeroMQ C API stubs for OCaml.
 *
 * Wraps the publisher half of libzmq's PUB/SUB pattern so [Zmq_notify] can
 * push 3-frame Bitcoin-Core-compatible messages to a real network socket.
 *
 * We deliberately do NOT include <zmq.h>: the Debian package providing the
 * shared library (libzmq5) does not always carry the dev headers (libzmq3-dev)
 * on the target machine, and the public ABI is stable enough to declare here.
 * The forward declarations below mirror the prototypes from
 * https://api.zeromq.org and the ZMQ 4.x ABI contract.
 *
 * Linkage: lib/dune adds [-lzmq] to [c_library_flags]. */

#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/fail.h>
#include <caml/custom.h>
#include <caml/threads.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>

/* ---------- libzmq ABI forward declarations ----------------------------- */
/* These match the ZMQ 4.x C API. Symbols are looked up at link time
 * against libzmq.so.5 via -lzmq in lib/dune. */

extern void *zmq_ctx_new(void);
extern int   zmq_ctx_term(void *context);
extern void *zmq_socket(void *context, int type);
extern int   zmq_close(void *socket);
extern int   zmq_bind(void *socket, const char *endpoint);
extern int   zmq_setsockopt(void *socket, int option_name,
                            const void *option_value, size_t option_len);
extern int   zmq_send(void *socket, const void *buf, size_t len, int flags);
extern int   zmq_errno(void);
extern const char *zmq_strerror(int errnum);

/* Constants from zmq.h (stable ABI). */
#define ZMQ_PUB     1
#define ZMQ_SNDMORE 2
#define ZMQ_DONTWAIT 1
#define ZMQ_SNDHWM   23
#define ZMQ_LINGER    17

/* ---------- Custom block for ZMQ context -------------------------------- */

#define Zmq_ctx_val(v) (*((void **)Data_custom_val(v)))

static void zmq_ctx_finalize(value v) {
  void *ctx = Zmq_ctx_val(v);
  if (ctx) {
    /* zmq_ctx_term blocks until all sockets are closed. The OCaml side is
       responsible for closing sockets first; this is best-effort to avoid
       leaking the I/O thread on GC. */
    zmq_ctx_term(ctx);
    Zmq_ctx_val(v) = NULL;
  }
}

static struct custom_operations zmq_ctx_ops = {
  "camlcoin.zmq.ctx",
  zmq_ctx_finalize,
  custom_compare_default,
  custom_hash_default,
  custom_serialize_default,
  custom_deserialize_default,
  custom_compare_ext_default,
  custom_fixed_length_default,
};

/* ---------- Custom block for ZMQ socket --------------------------------- */
/* Store the context pointer alongside so the finalizer can validate, but
 * we only call zmq_close on the socket (the context owns its lifetime). */

#define Zmq_sock_val(v) (*((void **)Data_custom_val(v)))

static void zmq_sock_finalize(value v) {
  void *sock = Zmq_sock_val(v);
  if (sock) {
    zmq_close(sock);
    Zmq_sock_val(v) = NULL;
  }
}

static struct custom_operations zmq_sock_ops = {
  "camlcoin.zmq.socket",
  zmq_sock_finalize,
  custom_compare_default,
  custom_hash_default,
  custom_serialize_default,
  custom_deserialize_default,
  custom_compare_ext_default,
  custom_fixed_length_default,
};

/* ---------- Helpers ----------------------------------------------------- */

static value alloc_zmq_ctx(void *ctx) {
  value v = caml_alloc_custom(&zmq_ctx_ops, sizeof(void *), 0, 1);
  Zmq_ctx_val(v) = ctx;
  return v;
}

static value alloc_zmq_sock(void *sock) {
  value v = caml_alloc_custom(&zmq_sock_ops, sizeof(void *), 0, 1);
  Zmq_sock_val(v) = sock;
  return v;
}

/* ---------- Public OCaml entry points ---------------------------------- */

CAMLprim value caml_zmq_ctx_new(value unit) {
  CAMLparam1(unit);
  void *ctx = zmq_ctx_new();
  if (!ctx) caml_failwith("zmq_ctx_new failed");
  CAMLreturn(alloc_zmq_ctx(ctx));
}

CAMLprim value caml_zmq_ctx_term(value v_ctx) {
  CAMLparam1(v_ctx);
  void *ctx = Zmq_ctx_val(v_ctx);
  if (ctx) {
    zmq_ctx_term(ctx);
    Zmq_ctx_val(v_ctx) = NULL;
  }
  CAMLreturn(Val_unit);
}

/* Create a PUB socket on the given context. */
CAMLprim value caml_zmq_pub_socket(value v_ctx) {
  CAMLparam1(v_ctx);
  void *ctx = Zmq_ctx_val(v_ctx);
  if (!ctx) caml_failwith("zmq_pub_socket: context already terminated");
  void *sock = zmq_socket(ctx, ZMQ_PUB);
  if (!sock) {
    int e = zmq_errno();
    caml_failwith(zmq_strerror(e));
  }
  /* Set LINGER=0 so close() returns immediately on shutdown rather than
     blocking on undelivered messages — matches Bitcoin Core's CZMQNotifier
     teardown where shutdown latency matters more than at-most-once retry. */
  int linger = 0;
  (void)zmq_setsockopt(sock, ZMQ_LINGER, &linger, sizeof(linger));
  CAMLreturn(alloc_zmq_sock(sock));
}

/* Set the SNDHWM (high-water-mark) on a PUB socket. */
CAMLprim value caml_zmq_set_sndhwm(value v_sock, value v_hwm) {
  CAMLparam2(v_sock, v_hwm);
  void *sock = Zmq_sock_val(v_sock);
  if (!sock) caml_failwith("zmq_set_sndhwm: socket closed");
  int hwm = Int_val(v_hwm);
  int rc = zmq_setsockopt(sock, ZMQ_SNDHWM, &hwm, sizeof(hwm));
  if (rc != 0) {
    int e = zmq_errno();
    caml_failwith(zmq_strerror(e));
  }
  CAMLreturn(Val_unit);
}

/* Bind a socket to the given endpoint (e.g. "tcp://127.0.0.1:28332"). */
CAMLprim value caml_zmq_bind(value v_sock, value v_endpoint) {
  CAMLparam2(v_sock, v_endpoint);
  void *sock = Zmq_sock_val(v_sock);
  if (!sock) caml_failwith("zmq_bind: socket closed");
  const char *endpoint = String_val(v_endpoint);
  int rc = zmq_bind(sock, endpoint);
  if (rc != 0) {
    int e = zmq_errno();
    caml_failwith(zmq_strerror(e));
  }
  CAMLreturn(Val_unit);
}

CAMLprim value caml_zmq_close(value v_sock) {
  CAMLparam1(v_sock);
  void *sock = Zmq_sock_val(v_sock);
  if (sock) {
    zmq_close(sock);
    Zmq_sock_val(v_sock) = NULL;
  }
  CAMLreturn(Val_unit);
}

/* Send a single 3-frame ZMQ message on a PUB socket.
 *
 * Frames:
 *   1. topic     (string, sent with ZMQ_SNDMORE)
 *   2. body      (string, sent with ZMQ_SNDMORE)
 *   3. seq_le    (4-byte little-endian uint32, no SNDMORE)
 *
 * Returns true on success, false if all three frames could be written.
 * Uses ZMQ_DONTWAIT so a slow / disconnected subscriber can't stall
 * the publisher; ZMQ buffers up to SNDHWM messages and silently drops
 * the rest (Bitcoin Core has the same semantics). */
CAMLprim value caml_zmq_pub_send3(value v_sock,
                                  value v_topic,
                                  value v_body,
                                  value v_seq) {
  CAMLparam4(v_sock, v_topic, v_body, v_seq);
  void *sock = Zmq_sock_val(v_sock);
  if (!sock) CAMLreturn(Val_false);

  /* Materialise OCaml strings into C buffers we control: the SNDMORE
     send sequence is brief but might still block briefly, and we want
     to release the OCaml runtime lock so concurrent block validation
     keeps running. */
  size_t topic_len = caml_string_length(v_topic);
  size_t body_len  = caml_string_length(v_body);
  size_t seq_len   = caml_string_length(v_seq);

  /* Defensive copies so caml_release_runtime_system can let the GC move
     the original strings without breaking the in-flight send. Stack
     allocation for topic/seq (small, fixed sizes), heap for body
     (block bodies can exceed 4 MiB). */
  char topic_buf[64];
  if (topic_len >= sizeof(topic_buf))
    caml_failwith("zmq_pub_send3: topic too long");
  memcpy(topic_buf, String_val(v_topic), topic_len);

  unsigned char seq_buf[16];
  if (seq_len > sizeof(seq_buf))
    caml_failwith("zmq_pub_send3: seq too long");
  memcpy(seq_buf, String_val(v_seq), seq_len);

  void *body_buf = NULL;
  if (body_len > 0) {
    body_buf = malloc(body_len);
    if (!body_buf) caml_failwith("zmq_pub_send3: body allocation failed");
    memcpy(body_buf, String_val(v_body), body_len);
  }

  int ok;
  caml_release_runtime_system();
  do {
    int rc1 = zmq_send(sock, topic_buf, topic_len, ZMQ_SNDMORE | ZMQ_DONTWAIT);
    if (rc1 < 0) { ok = 0; break; }
    int rc2 = zmq_send(sock, body_buf, body_len, ZMQ_SNDMORE | ZMQ_DONTWAIT);
    if (rc2 < 0) { ok = 0; break; }
    int rc3 = zmq_send(sock, seq_buf, seq_len, ZMQ_DONTWAIT);
    if (rc3 < 0) { ok = 0; break; }
    ok = 1;
  } while (0);
  caml_acquire_runtime_system();

  if (body_buf) free(body_buf);
  CAMLreturn(ok ? Val_true : Val_false);
}

/* Send a single-frame ZMQ message (rarely used by the notifier — kept for
   completeness so that future topics with no payload can avoid the 3-frame
   helper above). */
CAMLprim value caml_zmq_send_single(value v_sock, value v_data) {
  CAMLparam2(v_sock, v_data);
  void *sock = Zmq_sock_val(v_sock);
  if (!sock) CAMLreturn(Val_false);
  size_t len = caml_string_length(v_data);
  char *buf = NULL;
  if (len > 0) {
    buf = malloc(len);
    if (!buf) caml_failwith("zmq_send_single: allocation failed");
    memcpy(buf, String_val(v_data), len);
  }
  caml_release_runtime_system();
  int rc = zmq_send(sock, buf, len, ZMQ_DONTWAIT);
  caml_acquire_runtime_system();
  if (buf) free(buf);
  CAMLreturn(rc >= 0 ? Val_true : Val_false);
}
