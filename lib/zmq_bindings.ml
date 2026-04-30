(* Low-level OCaml bindings to libzmq, exposed via lib/zmq_stubs.c.
 *
 * Only the publisher half is wired here — camlcoin's ZMQ surface is purely
 * a Bitcoin-Core-compatible PUB notifier (rawblock / hashblock / rawtx /
 * hashtx / sequence). Subscribing or REQ/REP would be future work.
 *
 * Linkage: lib/dune adds [-lzmq] to [c_library_flags]; the symbols are
 * resolved against [libzmq.so.5] at process startup. *)

(* opaque ctx — wraps a libzmq context pointer (zmq_ctx_t).        *)
type ctx
(* opaque pub_sock — wraps a libzmq PUB socket (zmq_socket_t).      *)
type pub_sock

(* Create a new ZMQ context. Each context spawns one I/O thread by default;
   one context per process is the canonical pattern (matching Bitcoin Core's
   single g_zmq_notification_interface). *)
external ctx_new : unit -> ctx = "caml_zmq_ctx_new"

(* Terminate the context. Blocks until all sockets owned by the context are
   closed. Idempotent. *)
external ctx_term : ctx -> unit = "caml_zmq_ctx_term"

(* Create a PUB socket on this context. Bound endpoints are configured via
   [bind] below. *)
external pub_socket : ctx -> pub_sock = "caml_zmq_pub_socket"

(* Set send-side high-water-mark. ZMQ buffers up to [hwm] outbound messages
   per peer; further sends are dropped (PUB) when [DONTWAIT] is in use. *)
external set_sndhwm : pub_sock -> int -> unit = "caml_zmq_set_sndhwm"

(* Bind a PUB socket to an endpoint. Format follows the ZMQ URL grammar:
   - tcp://<host>:<port>
   - ipc:///<path>
   - inproc://<name>
   The Bitcoin Core notifier convention is tcp://127.0.0.1:28332. *)
external bind : pub_sock -> string -> unit = "caml_zmq_bind"

(* Close a socket. The owning context's [ctx_term] must be called separately
   to release the I/O thread; closing all sockets first is required for
   [ctx_term] to return. *)
external close : pub_sock -> unit = "caml_zmq_close"

(* Send a 3-frame ZMQ message: [topic; body; seq_le32]. Uses ZMQ_DONTWAIT
   so a slow/disconnected subscriber cannot stall block validation. Returns
   [true] iff all three frames were queued for delivery; [false] indicates
   a transient send failure (HWM hit, EAGAIN) which the caller may log
   and ignore — Bitcoin Core's notifier silently drops in this case. *)
external pub_send3 :
  pub_sock -> string -> string -> string -> bool
  = "caml_zmq_pub_send3"
