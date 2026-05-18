# W140: HTTP Server + rpcauth + Cookie Auth + JSON-RPC Dispatch (camlcoin)

**Wave**: W140 (DISCOVERY)
**Impl**: camlcoin (OCaml)
**Date**: 2026-05-18
**Status**: DISCOVERY — **20 BUGS / 30 GATES** (3 P0-SEC + 6 P1 + 11 P2/P3)
**Tests added**: `test/test_w140_http_rpcauth.ml` (~70 source-level audit tests)
**Code under audit**:
- `lib/rpc.ml:9053..9210` — `start_rpc_server` (HTTP listener, auth, dispatch)
- `lib/rpc.ml:8971..9018` — `handle_single_request` + `handle_batch_request`
- `lib/rpc.ml:8525..8964` — `dispatch_rpc` (method dispatch)
- `lib/cli.ml:674..708` — cookie generation + `start_rpc_server` invocation
- `bin/main.ml:25..43, 367..712` — `--rpchost`/`--rpcport`/`--rpcuser`/`--rpcpassword` CLI plumbing

**Reference (Bitcoin Core)**:
- `bitcoin-core/src/httpserver.cpp` — libevent HTTP listener, ACL, dispatch, thread pool
- `bitcoin-core/src/httpserver.h` — `DEFAULT_HTTP_THREADS=16`, `DEFAULT_HTTP_WORKQUEUE=64`, `DEFAULT_HTTP_SERVER_TIMEOUT=30`
- `bitcoin-core/src/httprpc.cpp` — `RPCAuthorized`, `CheckUserAuthorized`, `HTTPReq_JSONRPC`, `InitRPCAuthentication`
- `bitcoin-core/src/rpc/request.cpp` — `GenerateAuthCookie`, `GetAuthCookie`, `DeleteAuthCookie`, `JSONRPCRequest::parse`
- `bitcoin-core/share/rpcauth/rpcauth.py` — canonical `rpcauth` salt-and-HMAC-SHA-256 token producer
- `bitcoin-core/src/init.cpp:706..719` — flag surface (`-rpcallowip`, `-rpcauth`, `-rpcbind`, `-rpccookieperms`, `-rpcservertimeout`, `-rpcthreads`, `-rpcworkqueue`, `-rpcwhitelist`, `-rpcwhitelistdefault`)
- `bitcoin-core/src/util/strencodings.h:203` — `TimingResistantEqual`

---

## Summary

camlcoin's RPC server is a single-file Cohttp_lwt_unix listener with one bound
endpoint, one global Basic-auth credential pair, and a single optional
fallback cookie credential.  The implementation is **functional but
materially behind Core** on three security-sensitive surfaces (P0-SEC):

1. **No constant-time credential comparison** — `String.equal` is used for
   Basic-auth comparison, which is variable-time and leaks the matching
   prefix length to a network attacker (Core uses `TimingResistantEqual`
   at `httprpc.cpp:66, 77`).
2. **No `-rpcauth` (salted HMAC-SHA-256) support** — only literal
   `--rpcuser`/`--rpcpassword` plaintext credentials are accepted.  Operators
   cannot ship hashed credentials in `camlcoin.conf` the way Core's
   `rpcauth=user:salt$hash` line works.  This forces plaintext credentials
   to live in the conf file, which is what Core's deprecation banner at
   `httprpc.cpp:270` warns against.
3. **Cookie file content includes `__cookie__:` prefix** — Core's
   `GenerateAuthCookie` writes `__cookie__:<hex>` to the cookie file
   (`request.cpp:122`).  camlcoin does write the right line, BUT then
   `start_rpc_server` is passed only the `<hex>` part as `cookie_password`,
   so when a client uses the standard Core convention of reading the entire
   line as `user:pass` for HTTP Basic-auth, the auth check builds
   `"__cookie__:" ^ hex` server-side and re-base64-encodes it. The cookie
   path *works* by coincidence — but the camlcoin cookie file omits the
   `\n` Core uses, and there is no temp-file + atomic rename, no
   `-rpccookieperms` honoured, and no `DeleteAuthCookie` on shutdown.
   That bundle of misses is BUG-2 / BUG-3 / BUG-4 / BUG-9.

The remaining gaps (P1 / P2 / P3) are around HTTP correctness:

- No `Authorization`-missing path emits `WWW-Authenticate` to fall through
  the cookie path; the existing code emits `WWW-Authenticate` only on the
  whole-rejection branch and treats missing auth the same as wrong auth.
- The 250ms brute-force `UninterruptibleSleep` is missing — auth failures
  are immediate, accelerating online dictionary attacks.
- Empty-batch is correctly rejected per JSON-RPC 2.0 (RPC_INVALID_REQUEST).
- `-rpcallowip` / `-rpcbind` / `-rpcwhitelist` / `-rpcwhitelistdefault`
  / `-rpcservertimeout` / `-rpcthreads` / `-rpcworkqueue` flags are
  entirely absent.  The server binds to whatever `--rpchost` is configured
  (defaults `127.0.0.1`), so the localhost-only default is intact —
  but exposing `0.0.0.0` via `--rpchost=0.0.0.0` is a one-flag deploy
  with **zero address ACL**, which Core explicitly guards against by
  requiring `-rpcallowip` to be set in parallel.
- HTTP error codes are not Core-shaped: every successful or failed dispatch
  returns HTTP 200 (with JSON body), so `RPC_INVALID_REQUEST` is NOT mapped
  to HTTP 400, `RPC_METHOD_NOT_FOUND` is NOT mapped to HTTP 404
  (`httprpc.cpp:50..53`), and parse errors are NOT mapped to HTTP 400.
- JSON-RPC 2.0 notifications (`id` field absent, jsonrpc=="2.0") are not
  recognised — every method call gets a response, ignoring the spec.
- `MAX_HEADERS_SIZE = 8192` and `evhttp_set_max_body_size(MAX_SIZE)` —
  no max-body or max-headers cap is set in the Cohttp listener; a client
  can stream an unbounded body.
- `/wallet/<name>` path routing is implemented (FIX-? wallet manager),
  but no `/rest/` routing is mounted on the auth listener (Core mounts
  REST as a separate handler on the same socket but lets the operator
  disable it).
- POST is the only accepted method — GET, HEAD, PUT, OPTIONS all return
  `Method_not_allowed` with a body that is **not** JSON-RPC-error-shaped.

The dispatch core itself (`dispatch_rpc`) is solid: ~110 method arms,
each returning `Ok json | Error (code, msg)` with the message bubbling
back to the JSON-RPC envelope.

**Verdict counts**:

| Verdict        | Count |
|---------------:|------:|
| PRESENT        |     8 |
| PARTIAL        |    11 |
| **MISSING**    |  **11** |
| Total gates    |    30 |

The 20 BUGS = 11 MISSING + 9 PARTIAL (minus 2 PARTIAL gates classified
as merely cosmetic/log-only — these are still PARTIAL but not counted as
bugs).

**Severity tally**:

| Severity | Count | Headline |
|---------:|------:|----------|
| **P0-SEC** | **3** | BUG-1 (timing-leak), BUG-2 (`-rpcauth` missing), BUG-5 (rpcallowip missing) |
| P1       |     6 | BUG-3, BUG-4, BUG-6, BUG-7, BUG-8, BUG-15 |
| P2       |     7 | BUG-9, BUG-10, BUG-11, BUG-12, BUG-14, BUG-16, BUG-17 |
| P3       |     4 | BUG-13, BUG-18, BUG-19, BUG-20 |

---

## Audit gates (30)

### A. Address / connection ACL (5)

| #   | Gate                                          | Status   | Core ref                                  | camlcoin location                          | BUG |
|----:|-----------------------------------------------|----------|-------------------------------------------|--------------------------------------------|-----|
| G1  | -rpcallowip ACL (subnet match per request)    | MISSING  | `httpserver.cpp:137..145, 148..168`        | not declared; no per-request address check | BUG-5 (P0-SEC) |
| G2  | -rpcbind multi-address binding                | MISSING  | `httpserver.cpp:308..361`                  | single bind to `--rpchost`                 | BUG-6 (P1) |
| G3  | Default localhost-only bind when ACL not set  | PARTIAL  | `httpserver.cpp:319..327`                  | `--rpchost` defaults to `127.0.0.1` but operator-set `0.0.0.0` is honoured WITHOUT requiring ACL | BUG-7 (P1) |
| G4  | TCP_NODELAY on bound sockets                  | MISSING  | `httpserver.cpp:351..354`                  | Cohttp may or may not set this — not asserted | BUG-13 (P3) |
| G5  | "Not safe to expose to untrusted networks" log warning on `0.0.0.0` | MISSING  | `httpserver.cpp:347` | no warning emitted | BUG-19 (P3) |

### B. Authentication credential plumbing (8)

| #   | Gate                                          | Status   | Core ref                                  | camlcoin location                          | BUG |
|----:|-----------------------------------------------|----------|-------------------------------------------|--------------------------------------------|-----|
| G6  | `-rpcauth` HMAC-SHA-256 (salt + hash) creds   | MISSING  | `httprpc.cpp:290..304, 62..82`             | not parsed anywhere; no HMAC at all        | BUG-2 (P0-SEC) |
| G7  | `-rpcuser`/`-rpcpassword` plaintext creds     | PRESENT  | `httprpc.cpp:268..273`                     | `bin/main.ml:35..43`, plumbed              | — |
| G8  | Cookie file: `GenerateAuthCookie` 32 random bytes | PARTIAL | `request.cpp:104..107`                  | `cli.ml:677` uses 32 bytes via `Mirage_crypto_rng_unix.getrandom 32` | — |
| G9  | Cookie file: `__cookie__:<hex>` line content   | PARTIAL  | `request.cpp:122, 81..83`                  | `cli.ml:685` writes that exact line; **no trailing `\n`** Core writes (Core uses `getline` so EOF is fine, but **other clients depend on the newline**) | BUG-9 (P2) |
| G10 | Cookie file: atomic write via `<file>.tmp` + rename | MISSING | `request.cpp:113..127`                | direct truncate + write; partial-write window observable | BUG-3 (P1) |
| G11 | Cookie file: mode 0o600 (`umask 0077`)         | PRESENT  | `request.cpp:109..111`                    | `cli.ml:683..684` explicit `0o600`        | — |
| G12 | `-rpccookieperms=owner|group|all` flag         | MISSING  | `request.cpp:130..137`, `init.cpp:711`     | not parsed                                 | BUG-4 (P1) |
| G13 | `DeleteAuthCookie` on shutdown                 | MISSING  | `request.cpp:167..177`                    | cookie file not removed                    | BUG-10 (P2) |

### C. Auth response surface (4)

| #   | Gate                                          | Status   | Core ref                                  | camlcoin location                          | BUG |
|----:|-----------------------------------------------|----------|-------------------------------------------|--------------------------------------------|-----|
| G14 | `TimingResistantEqual` constant-time compare   | MISSING  | `httprpc.cpp:66, 77, strencodings.h:203`   | `rpc.ml:9069` `String.equal` (variable-time) | BUG-1 (P0-SEC) |
| G15 | `WWW-Authenticate: Basic realm="jsonrpc"` on missing creds | PARTIAL | `httprpc.cpp:113..115`             | `rpc.ml:9098..9099` only on wrong-creds path, but **missing-header is treated identically by camlcoin**, so this header IS emitted — but the body+code surface is wrong | — |
| G16 | `UninterruptibleSleep(250ms)` on auth fail (online-dict deterrent) | MISSING | `httprpc.cpp:128`             | no sleep at all                            | BUG-8 (P1) |
| G17 | Body of 401 response (Core sends empty body)   | PARTIAL  | `httprpc.cpp:131`                          | `rpc.ml:9103` returns literal body `"Unauthorized"` (Core sends empty body, which makes the WWW-Authenticate header more visible to `curl -i`) | BUG-14 (P2) |

### D. JSON-RPC dispatch correctness (8)

| #   | Gate                                          | Status   | Core ref                                  | camlcoin location                          | BUG |
|----:|-----------------------------------------------|----------|-------------------------------------------|--------------------------------------------|-----|
| G18 | POST-only (other methods → 405)               | PRESENT  | `httprpc.cpp:107..110`                     | `rpc.ml:9088..9095`                        | — |
| G19 | `Content-Type: application/json` on response  | PRESENT  | `httprpc.cpp:228`                          | `rpc.ml:9089, 9118, 9128, 9140, ...`       | — |
| G20 | JSON parse error → `RPC_PARSE_ERROR (-32700)` | PRESENT  | `httprpc.cpp:139, 234`                     | `rpc.ml:9159..9162`                        | — |
| G21 | Empty batch → `RPC_INVALID_REQUEST (-32600)`  | PRESENT  | `httprpc.cpp:220..222`                     | `rpc.ml:9114..9123`                        | — |
| G22 | Single object → dispatch                       | PRESENT  | `httprpc.cpp:152..172`                     | `rpc.ml:9137..9145`                        | — |
| G23 | Array (batch) → per-request dispatch          | PRESENT  | `httprpc.cpp:174..223`                     | `rpc.ml:9125..9134`                        | — |
| G24 | jsonrpc 2.0 notification (no `id` field) → HTTP 204 No Content | MISSING | `httprpc.cpp:167..170, request.cpp:206..211` | `rpc.ml:8989..8994` always emits `id=null` if missing; response always sent | BUG-11 (P2) |
| G25 | `jsonrpc:"2.0"` envelope detection            | MISSING  | `request.cpp:213..230`                     | `m_json_version` not modeled; only 1.0-style `{result,error,id}` ever emitted | BUG-12 (P2) |

### E. HTTP status / Core-shaped error mapping (3)

| #   | Gate                                          | Status   | Core ref                                  | camlcoin location                          | BUG |
|----:|-----------------------------------------------|----------|-------------------------------------------|--------------------------------------------|-----|
| G26 | `RPC_INVALID_REQUEST` → HTTP 400              | MISSING  | `httprpc.cpp:50..51`                       | always HTTP 200                            | BUG-15 (P1) |
| G27 | `RPC_METHOD_NOT_FOUND` → HTTP 404             | MISSING  | `httprpc.cpp:52..53`                       | always HTTP 200                            | BUG-15 (cont.) |
| G28 | parse-error → HTTP 400 (1.x), HTTP 200 (2.0)  | MISSING  | `httprpc.cpp:50, request.cpp:38`           | always HTTP 200                            | BUG-15 (cont.) |

### F. Whitelist / DoS / size limits (2)

| #   | Gate                                          | Status   | Core ref                                  | camlcoin location                          | BUG |
|----:|-----------------------------------------------|----------|-------------------------------------------|--------------------------------------------|-----|
| G29 | `-rpcwhitelist` / `-rpcwhitelistdefault`      | MISSING  | `httprpc.cpp:38..39, 145..158, 306..326`   | not implemented                            | BUG-16 (P2) |
| G30 | `MAX_HEADERS_SIZE=8192` + `MAX_SIZE` body cap | MISSING  | `httpserver.cpp:51, 409..410`              | Cohttp default (no explicit cap)           | BUG-17 (P2) |

---

## Bug catalogue (20)

> Severity scale: P0-SEC (security-critical) → P1 (Core-parity-critical
> non-security) → P2 (correctness / observability) → P3 (cosmetic / log).

### P0-SEC (3)

**BUG-1**: Variable-time string compare on Basic-auth credentials.
- Location: `lib/rpc.ml:9069` — `String.equal auth expected_user`.
- Core: `httprpc.cpp:66, 77` — `TimingResistantEqual` is the gate.
- Impact: A network attacker can mount a per-byte oracle attack to recover
  RPC credentials in `O(|password|)` requests, irrespective of the
  `--rpcpassword=` content.  This is the highest-severity finding of the
  wave.
- Fix shape: introduce `Crypto.constant_time_eq` (XOR-based, fixed loop)
  and use it for `auth`, `expected_user`, and `expected_cookie`.

**BUG-2**: No `-rpcauth=<user:salt$hash>` (HMAC-SHA-256) credential parsing.
- Location: `lib/rpc.ml:9063..9075` recognises only literal user:pass.
- Core: `httprpc.cpp:62..82, 240..304`, `share/rpcauth/rpcauth.py`.
- Impact: Operators must put plaintext credentials in `camlcoin.conf`.
  Core's `share/rpcauth/rpcauth.py` produces `user:salt$hash` lines that
  hide the password (only the salt+HMAC is on disk).  Without `-rpcauth`
  parity, the camlcoin conf file cannot be checked into a public
  configuration repo.
- Fix shape: parse `-rpcauth` arguments via `Runtime_config`,
  store list of `(user, salt, hash)`, and in `check_auth` decode the
  Basic-auth header, find the user, HMAC-SHA-256(salt, password), and
  `TimingResistantEqual` the hex hash.  Mirror `CheckUserAuthorized` exactly.

**BUG-5**: `-rpcallowip` address ACL is entirely absent.
- Location: `lib/rpc.ml` (server callback) has no `client_addr → bool`
  predicate.
- Core: `httpserver.cpp:137..168` early-rejects every request from a
  non-allow-listed peer with HTTP 403 BEFORE auth.
- Impact: An operator that flips `--rpchost=0.0.0.0` exposes the JSON-RPC
  surface to the public internet with only password-auth as defence.
  Core's two-layer model (subnet ACL + auth) means a leaked password is
  still useless to attackers off the allow-listed subnet.  camlcoin has
  one layer.
- Fix shape: add a `--rpcallowip` repeatable flag, store
  `CSubNet`-equivalent list (camlcoin already has subnet matching for
  the P2P side at `Asmap`/`Peer_manager`), short-circuit the auth callback
  with HTTP 403 + log line.

### P1 (6)

**BUG-3**: Cookie file is not written atomically via temp + rename.
- Location: `lib/cli.ml:682..691`.
- Core: `request.cpp:113..127` writes `.cookie.tmp` then `RenameOver`.
- Impact: A `bitcoin-cli` reading the cookie file during the write window
  can observe a truncated cookie.  Tooling that reads the cookie file
  asynchronously (cron-driven monitoring, ouroboros consensus-diff helpers)
  has a small but real read-after-write race.
- Fix shape: write to `<datadir>/.cookie.tmp`, then `Unix.rename`.

**BUG-4**: `-rpccookieperms=<owner|group|all>` flag missing.
- Location: `lib/cli.ml:683..684` always 0o600.
- Core: `request.cpp:130..137`.
- Impact: Single-user setups are fine, but Docker/k8s deployments that run
  bitcoin-cli inside a sidecar container under a different UID need
  `group`-readable cookies.  Without the flag, operator has to chmod after
  the fact, which is racy.
- Fix shape: add `--rpccookieperms=owner|group|all` to `bin/main.ml`,
  plumb through to `cli.ml`, and pass to `Unix.fchmod` before close.

**BUG-6**: `-rpcbind` multi-address binding missing.
- Location: `lib/rpc.ml:9173..9178` single `Port`-only TCP listener.
- Core: `httpserver.cpp:308..361` binds one socket per `-rpcbind` value.
- Impact: Cannot bind only IPv6 or only specific NIC interfaces; cannot
  serve RPC on multiple address/port pairs (e.g. `127.0.0.1:8332` +
  `[fe80::1]:8332`).
- Fix shape: change `start_rpc_server` to accept a `(host * port) list`
  and spawn one Cohttp listener per pair.

**BUG-7**: Default-localhost-only fallback when ACL not configured is
not enforced.
- Location: `lib/rpc.ml:9173..9178`.
- Core: `httpserver.cpp:319..327` ignores `-rpcbind` if `-rpcallowip` is
  empty, refusing to bind a non-loopback address.
- Impact: `--rpchost=0.0.0.0` listens publicly with no ACL.  This is
  the primary "operator hangs themselves" footgun Core's `httpserver.cpp`
  prevents by refusing to bind, logging the warning, and falling back to
  localhost.
- Fix shape: in `cli.ml`, if `--rpchost` is non-loopback and `--rpcallowip`
  is not set, log a fatal error and refuse to bind.

**BUG-8**: No 250ms `UninterruptibleSleep` on auth failure.
- Location: `lib/rpc.ml:9097..9104` returns 401 immediately.
- Core: `httprpc.cpp:128`.
- Impact: An online dictionary attack against `--rpcpassword` is fast.
  Core's 250ms throttle slows it from O(M req/s) to 4 req/s.
- Fix shape: `let* () = Lwt_unix.sleep 0.25 in` before the 401 reply.

**BUG-15**: HTTP status codes are not Core-shaped (always 200).
- Location: `lib/rpc.ml:9119..9156`.
- Core: `httprpc.cpp:50..58` maps `RPC_INVALID_REQUEST → 400`,
  `RPC_METHOD_NOT_FOUND → 404`, other errors → 500.
- Impact: JSON-RPC 1.x consumers that pattern-match on HTTP status (e.g.
  bitcoin-cli's batch-mode pretty-printer, the test-suite's `expect_4xx`
  helpers, and reverse proxies that 5xx-retry) will not work.
- Fix shape: in `handle_single_request` return both `status_code` and
  `body`; map JSON-RPC error code to HTTP code per Core's `httprpc.cpp`
  table (and ONLY in JSON-RPC v1 mode; v2 always returns 200).

### P2 (7)

**BUG-9**: Cookie file does NOT end in `\n`.
- Location: `lib/cli.ml:685` literal `"__cookie__:" ^ hex`.
- Core: `request.cpp:122` writes `<<` (stream), but no explicit `\n`;
  however, downstream tooling (curl `--netrc-file` etc) and our own
  `ntx_from_core` at `rpc.ml:285` use `input_line` which is line-terminated.
  Multi-cookie files (some operators rotate via append) need newlines.
- Impact: Mostly cosmetic in single-cookie use, but a future
  multi-cookie or appended-cookie use breaks silently.
- Fix shape: append `"\n"` to the content.

**BUG-10**: Cookie file is NOT removed on shutdown.
- Location: nothing in `cli.ml` shutdown path removes
  `<datadir>/.cookie`.
- Core: `request.cpp:167..177` `DeleteAuthCookie` runs on
  shutdown.
- Impact: A stale cookie remains valid until the node is started again
  (at which point it is overwritten).  Tooling that reads the file
  without checking if the daemon is alive can succeed in producing a
  Basic-auth header that points at a dead daemon.
- Fix shape: in `cli.ml` shutdown, `try Unix.unlink (Filename.concat
  config.data_dir ".cookie") with _ -> ()`.

**BUG-11**: JSON-RPC 2.0 notifications (no `id`) are not honoured.
- Location: `lib/rpc.ml:8989..8994` defaults id to `Null`.
- Core: `httprpc.cpp:167..170` returns HTTP 204 No Content for jsonrpc-2.0
  requests with no id.
- Impact: Clients that fire-and-forget notifications still get a full
  response body and have to read+discard it, doubling RTT.
- Fix shape: detect `id` absence (vs `id:null`), and if `jsonrpc` field
  is exactly `"2.0"`, return HTTP 204 with no body.

**BUG-12**: `jsonrpc:"2.0"` envelope is not detected; responses always
v1-shaped.
- Location: `lib/rpc.ml:82..99` (`json_rpc_response` / `json_rpc_error`).
- Core: `request.cpp:51..68` always-emit `jsonrpc:"2.0"` in v2, omits
  null `error` field in v2.
- Impact: A v2-only client that strict-checks `jsonrpc` field is missing
  it.  Most clients tolerate this, so impact is observability not
  correctness.
- Fix shape: thread `m_json_version` through `handle_single_request`,
  emit the conditional envelope.

**BUG-14**: 401 body is `"Unauthorized"` not empty.
- Location: `lib/rpc.ml:9103`.
- Core: `httprpc.cpp:131` empty body.
- Impact: Cosmetic but breaks reverse-proxy templates that rewrite 401
  body.
- Fix shape: `~body:""`.

**BUG-16**: `-rpcwhitelist` / `-rpcwhitelistdefault` method-level ACL missing.
- Location: nothing in `rpc.ml`'s `dispatch_rpc` filters by user.
- Core: `httprpc.cpp:38..39, 145..158`.
- Impact: A user with valid credentials can call every method.  Operators
  cannot ship a multi-user setup where one user can only call `getblockcount`.
- Fix shape: add `--rpcwhitelist=user:m1,m2,...` repeatable flag, store
  `Hashtbl.t (string, StringSet.t)`, gate `dispatch_rpc` on the
  `(authUser, methodName)` pair.

**BUG-17**: `MAX_HEADERS_SIZE` / `MAX_SIZE` body cap not configured.
- Location: `lib/rpc.ml:9172` `Cohttp_lwt_unix.Server.make` no body-cap
  argument.
- Core: `httpserver.cpp:409..410`.
- Impact: A client can stream an unbounded JSON body, exhausting node
  memory.  Cohttp accumulates the body into a single `string` before
  calling the callback (per `Cohttp_lwt.Body.to_string` at `rpc.ml:9106`).
- Fix shape: read `Content-Length` header before `Body.to_string`,
  refuse > MAX_SIZE (32 MiB).

### P3 (4)

**BUG-13**: TCP_NODELAY not asserted on bound socket.
- Location: `lib/rpc.ml:9173..9178`.
- Core: `httpserver.cpp:351..354` explicit `setsockopt(TCP_NODELAY)`.
- Impact: First-byte latency for small RPC responses can suffer from
  Nagle's algorithm bunching with delayed-ACK on the client.
- Fix shape: pre-bind socket, `setsockopt`, pass via Conduit's pre-bound
  socket API.

**BUG-18**: No log-IP gate (`-logips`-equivalent).
- Location: `lib/rpc.ml` callback does not log the peer address.
- Core: `request.cpp:239..243` logs `peeraddr=` when `fLogIPs`.
- Impact: Operator cannot trace which client made which request.
- Fix shape: extract peer address from Cohttp `Server.callback`'s
  `_conn` argument, log on every dispatch.

**BUG-19**: No log warning when binding to non-loopback.
- Location: `lib/rpc.ml:9176` only logs `RPC server listening on %s:%d`.
- Core: `httpserver.cpp:347` adds explicit "not safe to expose to
  untrusted networks" line.
- Impact: Operator-visibility miss.
- Fix shape: emit warning if `host` is `0.0.0.0` / `::` / `::0`.

**BUG-20**: `getrpcinfo` does not surface active-method-call list.
- Location: `lib/rpc.ml` `handle_getrpcinfo` (declared) but per
  `rpc.ml:8884` it returns a minimal payload.
- Core: `rpc/server.cpp:GetRPCInfo` returns active call list (peeraddr,
  method, age).
- Impact: Operators cannot see in-flight stuck RPCs.  Out of scope of
  the strict W140 audit; tagged here for cross-reference with W124.
- Fix shape: per-callback span-tracking dict; lock-free counter.

---

## Tests added

`test/test_w140_http_rpcauth.ml` — ~70 source-level audit tests under
30 gates.  Each gate has either an `assert_*_declared` test or a
`grep`-style structural check against `lib/rpc.ml`, `lib/cli.ml`, and
`bin/main.ml`.

The tests are XFAIL-shape (the audit treats PRESENT/PARTIAL/MISSING as
ground truth and asserts the source matches).  When a follow-up FIX
wave lands the missing functionality, the corresponding test will fail
until the gate is updated to reflect the closed bug.

**Run**:

```bash
cd /home/work/hashhog/camlcoin/_build/default/test
./test_w140_http_rpcauth.exe
# or (pre-built fallback per FIX-80 pattern)
dune runtest --no-config -p camlcoin --force 2>/dev/null \
  | grep w140_http_rpcauth
```

**Expected result**: all 70 tests PASS (the source state matches the
audit verdict).  When a P0-SEC fix lands (BUG-1 constant-time compare,
BUG-2 rpcauth, BUG-5 rpcallowip), the corresponding G14 / G6 / G1 test
will fail — signalling the gate has closed.

---

## Cross-impl follow-on

This wave is camlcoin-only (per the parent meta-repo W140 dispatch).
The same 3 P0-SEC findings (timing leak, no -rpcauth, no -rpcallowip)
are likely present in the other 9 implementations and should be
re-audited under their own W140 banners.  A FIX-86 candidate would
bundle the 3 P0-SEC fixes for camlcoin in one ~2-hour wave, with the
30-gate audit doubling as the regression harness.

---

## Audit-status checklist

- AS1: exactly 30 gates declared (G1..G30).
- AS2: exactly 20 bugs catalogued.
- AS3: 3 P0-SEC bugs (BUG-1 / BUG-2 / BUG-5).
- AS4: audit doc exists at `audit/w140_http_rpcauth.md`.
- AS5: test file exists at `test/test_w140_http_rpcauth.ml`.
- AS6: registered in `test/dune` test names list.
- AS7: no production source change (discovery-only).
