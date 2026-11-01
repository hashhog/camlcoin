/* poll(2) for the Lwt event loop (Poll_engine).
 *
 * Lwt's default engine here is select(2) (lwt was built without libev).
 * select cannot watch an fd >= FD_SETSIZE (1024): Unix.select raises
 * EINVAL, Lwt_engine.select#iter lets it escape, and Lwt_main.run ends the
 * process.  poll has no such ceiling.
 *
 * camlcoin_poll(fds, events, revents, timeout): fds and events are parallel
 * arrays (events: bit 0 = read, bit 1 = write); revents is filled the same
 * way.  timeout is in seconds, negative = wait forever.  Returns the number
 * of ready entries.  Raises Unix.Unix_error on failure (EINTR included,
 * which Lwt_engine handles).
 */

#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/fail.h>
#include <caml/signals.h>
#include <caml/unixsupport.h>
#include <errno.h>
#include <math.h>
#include <poll.h>
#include <stdlib.h>

CAMLprim value camlcoin_poll(value v_fds, value v_events, value v_revents,
                             value v_timeout) {
  CAMLparam4(v_fds, v_events, v_revents, v_timeout);
  mlsize_t n = Wosize_val(v_fds);
  double timeout = Double_val(v_timeout);
  int ms;
  if (timeout < 0.0)
    ms = -1;
  else if (timeout > 2147483.0)
    ms = 2147483647;
  else
    ms = (int)ceil(timeout * 1000.0);

  struct pollfd *pfds = NULL;
  if (n > 0) {
    pfds = malloc(n * sizeof(struct pollfd));
    if (pfds == NULL) caml_raise_out_of_memory();
  }
  for (mlsize_t i = 0; i < n; i++) {
    int ev = Int_val(Field(v_events, i));
    pfds[i].fd = Int_val(Field(v_fds, i));
    pfds[i].events = (short)(((ev & 1) ? POLLIN : 0) | ((ev & 2) ? POLLOUT : 0));
    pfds[i].revents = 0;
  }

  caml_enter_blocking_section();
  int r = poll(pfds, (nfds_t)n, ms);
  int err = errno;
  caml_leave_blocking_section();

  if (r < 0) {
    free(pfds);
    errno = err;
    caml_uerror("poll", Nothing);
  }

  int ready = 0;
  for (mlsize_t i = 0; i < n; i++) {
    short re = pfds[i].revents;
    int ev = Int_val(Field(v_events, i));
    int out = 0;
    /* select reports hangup and error as readable/writable, so the waiting
       read or write runs and sees EOF or the error itself.  POLLNVAL (a
       closed fd) is reported the same way: the action gets EBADF, as with
       select's EBADF path. */
    if ((ev & 1) && (re & (POLLIN | POLLPRI | POLLHUP | POLLERR | POLLNVAL)))
      out |= 1;
    if ((ev & 2) && (re & (POLLOUT | POLLHUP | POLLERR | POLLNVAL)))
      out |= 2;
    if (out) ready++;
    Store_field(v_revents, i, Val_int(out));
  }
  free(pfds);
  CAMLreturn(Val_int(ready));
}
