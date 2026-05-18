(* W140 audit — HTTP server + rpcauth + cookie auth + JSON-RPC dispatch
   (camlcoin)

   Reference:
     bitcoin-core/src/httpserver.cpp + httpserver.h
     bitcoin-core/src/httprpc.cpp
     bitcoin-core/src/rpc/request.cpp
     bitcoin-core/share/rpcauth/rpcauth.py

   30 audit gates covering Core's HTTP RPC surface — address ACL, auth
   credential plumbing (rpcuser/rpcpassword/rpcauth/cookie), 401 response
   shape, JSON-RPC envelope detection, HTTP status mapping, whitelist /
   size limits.

   Each gate asserts source-level the PRESENT / PARTIAL / MISSING status
   captured in audit/w140_http_rpcauth.md.  Tests pass when the audit
   verdict is faithful — i.e. PRESENT features are declared AND wired,
   PARTIAL features are declared but not fully wired, MISSING features
   are not declared.  When a follow-up FIX wave lands a missing feature,
   the corresponding test will fail until updated, signalling the audit
   gate was closed.

   This file does NOT exercise the RPC server with live HTTP calls — it
   reads lib/rpc.ml, lib/cli.ml, bin/main.ml at runtime and asserts the
   static structure of declarations and code paths.  The same shape used
   by W125 (error parity) audit tests.

   Audit checklist:
     [A] Address / connection ACL (5)
       G1  -rpcallowip ACL                    MISSING (BUG-5, P0-SEC)
       G2  -rpcbind multi-address binding     MISSING (BUG-6, P1)
       G3  default loopback-only fallback     PARTIAL (BUG-7, P1)
       G4  TCP_NODELAY on socket              MISSING (BUG-13, P3)
       G5  unsafe-bind warning log            MISSING (BUG-19, P3)
     [B] Authentication credential plumbing (8)
       G6  -rpcauth HMAC-SHA-256 creds        MISSING (BUG-2, P0-SEC)
       G7  -rpcuser/-rpcpassword              PRESENT
       G8  cookie file: 32 random bytes       PARTIAL
       G9  cookie file: __cookie__:<hex>      PARTIAL (BUG-9, P2 — missing \n)
       G10 cookie file: atomic write          MISSING (BUG-3, P1)
       G11 cookie file: 0o600 perms           PRESENT
       G12 -rpccookieperms flag               MISSING (BUG-4, P1)
       G13 DeleteAuthCookie on shutdown       MISSING (BUG-10, P2)
     [C] Auth response surface (4)
       G14 TimingResistantEqual               MISSING (BUG-1, P0-SEC)
       G15 WWW-Authenticate Basic realm       PARTIAL
       G16 250ms brute-force sleep            MISSING (BUG-8, P1)
       G17 401 empty body                     PARTIAL (BUG-14, P2)
     [D] JSON-RPC dispatch correctness (8)
       G18 POST-only                          PRESENT
       G19 Content-Type response              PRESENT
       G20 JSON parse → -32700                PRESENT
       G21 empty batch → -32600               PRESENT
       G22 single object dispatch             PRESENT
       G23 array (batch) dispatch             PRESENT
       G24 v2 notification → HTTP 204         MISSING (BUG-11, P2)
       G25 jsonrpc:"2.0" envelope             MISSING (BUG-12, P2)
     [E] HTTP status / Core-shape error map (3)
       G26 RPC_INVALID_REQUEST → 400          MISSING (BUG-15, P1)
       G27 RPC_METHOD_NOT_FOUND → 404         MISSING (BUG-15, P1)
       G28 parse-error → 400 (v1)             MISSING (BUG-15, P1)
     [F] Whitelist / DoS / size limits (2)
       G29 -rpcwhitelist                      MISSING (BUG-16, P2)
       G30 MAX_HEADERS_SIZE / MAX body cap    MISSING (BUG-17, P2)
   ============================================================================ *)

(* -- helpers ------------------------------------------------------------- *)

let read_file path =
  let ic = open_in path in
  let n = in_channel_length ic in
  let buf = Bytes.create n in
  really_input ic buf 0 n;
  close_in ic;
  Bytes.to_string buf

(* Walk up from the current working directory until we find the
   camlcoin repo root (recognised by the lib/rpc.ml marker file).
   Alcotest invokes test executables from a CWD deep inside _build, so
   we cannot use a fixed relative path.  Borrowed from W125. *)
let resolve_repo_root () =
  let rec up dir depth =
    if depth > 10 then
      Alcotest.fail "could not locate repo root from CWD"
    else if Sys.file_exists (Filename.concat dir "lib/rpc.ml") then dir
    else up (Filename.dirname dir) (depth + 1)
  in
  up (Sys.getcwd ()) 0

let rpc_ml () : string =
  read_file (Filename.concat (resolve_repo_root ()) "lib/rpc.ml")

let cli_ml () : string =
  read_file (Filename.concat (resolve_repo_root ()) "lib/cli.ml")

let main_ml () : string =
  read_file (Filename.concat (resolve_repo_root ()) "bin/main.ml")

let audit_doc_path () : string =
  Filename.concat (resolve_repo_root ()) "audit/w140_http_rpcauth.md"

let contains_substring (haystack : string) (needle : string) : bool =
  let h = String.length haystack in
  let n = String.length needle in
  if n = 0 || n > h then false
  else
    let rec scan i =
      if i + n > h then false
      else if String.sub haystack i n = needle then true
      else scan (i + 1)
    in
    scan 0

let count_substring (haystack : string) (needle : string) : int =
  let h = String.length haystack in
  let n = String.length needle in
  if n = 0 then 0
  else
    let rec scan i acc =
      if i + n > h then acc
      else if String.sub haystack i n = needle then scan (i + 1) (acc + 1)
      else scan (i + 1) acc
    in
    scan 0 0

(* ============================================================================
   [A] Address / connection ACL (5 gates)
   ============================================================================ *)

(* -- G1 -rpcallowip ACL — MISSING (BUG-5, P0-SEC) ----------------------- *)

let g1_rpcallowip_flag_NOT_declared () =
  (* No --rpcallowip CLI flag should exist. *)
  let main = main_ml () in
  Alcotest.(check bool)
    "G1 (P0-SEC BUG-5) --rpcallowip flag NOT declared in bin/main.ml"
    false (contains_substring main "\"rpcallowip\"")

let g1_rpcallowip_no_subnet_check () =
  (* No per-request CSubNet equivalent / ClientAllowed predicate in the
     RPC callback.  Conservative: search for any reference to allowip
     or ClientAllowed-style subnet check. *)
  let rpc = rpc_ml () in
  Alcotest.(check bool)
    "G1 (BUG-5) no ClientAllowed-style subnet matcher in rpc.ml"
    false
    (contains_substring rpc "ClientAllowed"
     || contains_substring rpc "rpc_allow_subnets"
     || contains_substring rpc "rpcallowip")

(* -- G2 -rpcbind multi-address binding — MISSING (BUG-6, P1) ------------ *)

let g2_rpcbind_flag_NOT_declared () =
  let main = main_ml () in
  Alcotest.(check bool)
    "G2 (BUG-6) --rpcbind flag NOT declared"
    false (contains_substring main "\"rpcbind\"")

let g2_rpcbind_single_listener_only () =
  (* The start_rpc_server signature takes a SINGLE [~host:string ~port:int]
     pair, not a list, so multi-bind is structurally impossible. *)
  let rpc = rpc_ml () in
  Alcotest.(check bool)
    "G2 (BUG-6) start_rpc_server takes single host:port (no list-of-binds)"
    true
    (contains_substring rpc "~host:string ~port:int"
     || contains_substring rpc "~(host : string)"
     || contains_substring rpc "~host ~port")

(* -- G3 default loopback-only fallback — PARTIAL (BUG-7, P1) ------------ *)

let g3_default_rpchost_loopback () =
  (* CLI defaults --rpchost to "127.0.0.1" — good. *)
  let main = main_ml () in
  Alcotest.(check bool)
    "G3 --rpchost default 127.0.0.1 (loopback-only by default)"
    true (contains_substring main "opt string \"127.0.0.1\"")

let g3_no_refusal_to_bind_nonloopback_without_acl () =
  (* PARTIAL bug: if operator sets --rpchost=0.0.0.0 there is NO refusal
     to bind without --rpcallowip — Core's httpserver.cpp:319 enforces
     this. Verify camlcoin does NOT have such a refusal. *)
  let cli = cli_ml () in
  Alcotest.(check bool)
    "G3 (BUG-7) no fatal refusal-to-bind on non-loopback w/o rpcallowip"
    false
    (contains_substring cli "non-loopback"
     || contains_substring cli "untrusted networks"
     || contains_substring cli "refusing to allow everyone")

(* -- G4 TCP_NODELAY on bound socket — MISSING (BUG-13, P3) -------------- *)

let g4_tcp_nodelay_NOT_set () =
  let rpc = rpc_ml () in
  Alcotest.(check bool)
    "G4 (BUG-13) TCP_NODELAY not explicitly set on RPC listener socket"
    false
    (contains_substring rpc "TCP_NODELAY"
     || contains_substring rpc "tcp_nodelay")

(* -- G5 unsafe-bind warning log — MISSING (BUG-19, P3) ------------------ *)

let g5_no_unsafe_bind_warning () =
  let rpc = rpc_ml () in
  Alcotest.(check bool)
    "G5 (BUG-19) no \"not safe to expose to untrusted networks\" warning"
    false
    (contains_substring rpc "untrusted"
     || contains_substring rpc "unsafe to expose")

(* ============================================================================
   [B] Authentication credential plumbing (8 gates)
   ============================================================================ *)

(* -- G6 -rpcauth HMAC-SHA-256 creds — MISSING (BUG-2, P0-SEC) ----------- *)

let g6_rpcauth_flag_NOT_declared () =
  let main = main_ml () in
  Alcotest.(check bool)
    "G6 (P0-SEC BUG-2) --rpcauth flag NOT declared"
    false (contains_substring main "\"rpcauth\"")

let g6_no_hmac_sha256_in_rpc () =
  let rpc = rpc_ml () in
  (* No HMAC-SHA-256 over (salt,password) anywhere in rpc.ml's auth path.
     (HMAC is fine elsewhere in the file for other purposes but not for
     password verification.)  Conservative check: look for the canonical
     password-hashing pattern. *)
  Alcotest.(check bool)
    "G6 (BUG-2) no HMAC-based password verification in rpc.ml auth path"
    false
    (contains_substring rpc "Hmac.sha256"
     && contains_substring rpc "check_auth")

let g6_no_salt_dollar_hash_parse () =
  let rpc = rpc_ml () in
  (* Core's rpcauth field format is user:salt$hash.  No such parser. *)
  Alcotest.(check bool)
    "G6 (BUG-2) no parse of Core's user:salt$hash rpcauth format"
    false
    (contains_substring rpc "salt$"
     || contains_substring rpc "$hash"
     || contains_substring rpc "salt_hmac")

(* -- G7 -rpcuser/-rpcpassword plaintext creds — PRESENT ----------------- *)

let g7_rpcuser_flag_declared () =
  let main = main_ml () in
  Alcotest.(check bool)
    "G7 --rpcuser flag declared in bin/main.ml"
    true (contains_substring main "\"rpcuser\"")

let g7_rpcpassword_flag_declared () =
  let main = main_ml () in
  Alcotest.(check bool)
    "G7 --rpcpassword flag declared"
    true (contains_substring main "\"rpcpassword\"")

let g7_rpcuser_plumbed_to_server () =
  let cli = cli_ml () in
  Alcotest.(check bool)
    "G7 --rpcuser threaded into start_rpc_server"
    true (contains_substring cli "~rpc_user:config.rpc_user")

(* -- G8 Cookie file 32 random bytes — PARTIAL ------------------------- *)

let g8_cookie_32_random_bytes () =
  let cli = cli_ml () in
  (* Core uses 32 bytes; camlcoin matches. *)
  Alcotest.(check bool)
    "G8 cookie generated from 32 random bytes (Core parity)"
    true
    (contains_substring cli "getrandom 32"
     || contains_substring cli "Mirage_crypto_rng_unix.getrandom 32")

(* -- G9 Cookie content __cookie__:<hex> — PARTIAL (BUG-9, P2: missing \n) - *)

let g9_cookie_user_prefix () =
  let cli = cli_ml () in
  Alcotest.(check bool)
    "G9 cookie file content prefixed with __cookie__:"
    true (contains_substring cli "\"__cookie__:\" ^ hex")

let g9_cookie_missing_trailing_newline () =
  (* BUG-9: Core ends the cookie line implicitly via stream close;
     line-oriented readers should still see a complete line.  camlcoin's
     `content` literal has no \n, so `input_line` on the file returns
     the cookie + EOF rather than a line-terminated string. *)
  let cli = cli_ml () in
  Alcotest.(check bool)
    "G9 (BUG-9) cookie content literal has no trailing '\\n'"
    false
    (contains_substring cli "\"__cookie__:\" ^ hex ^ \"\\n\"")

(* -- G10 Cookie atomic write (tmp + rename) — MISSING (BUG-3, P1) ------- *)

let g10_no_tmp_rename_for_cookie () =
  let cli = cli_ml () in
  (* Core writes .cookie.tmp then RenameOver. *)
  Alcotest.(check bool)
    "G10 (BUG-3) no .cookie.tmp + Unix.rename pattern in cookie writer"
    false
    (contains_substring cli ".cookie.tmp"
     || (contains_substring cli "Unix.rename"
         && contains_substring cli ".cookie"))

(* -- G11 Cookie 0o600 perms — PRESENT ----------------------------------- *)

let g11_cookie_perms_0o600 () =
  let cli = cli_ml () in
  Alcotest.(check bool)
    "G11 cookie file created with 0o600 perms (Core parity, umask 0077)"
    true (contains_substring cli "0o600")

(* -- G12 -rpccookieperms flag — MISSING (BUG-4, P1) --------------------- *)

let g12_rpccookieperms_NOT_declared () =
  let main = main_ml () in
  Alcotest.(check bool)
    "G12 (BUG-4) --rpccookieperms flag NOT declared"
    false (contains_substring main "\"rpccookieperms\"")

(* -- G13 DeleteAuthCookie on shutdown — MISSING (BUG-10, P2) ------------ *)

let g13_no_delete_auth_cookie_on_shutdown () =
  let cli = cli_ml () in
  Alcotest.(check bool)
    "G13 (BUG-10) no cookie removal on shutdown"
    false
    (contains_substring cli "Unix.unlink"
     && contains_substring cli ".cookie")

(* ============================================================================
   [C] Auth response surface (4 gates)
   ============================================================================ *)

(* -- G14 TimingResistantEqual constant-time compare — MISSING (BUG-1, P0-SEC) *)

let g14_String_equal_is_variable_time () =
  (* SEC issue: rpc.ml line ~9069 uses String.equal for auth comparison.
     Variable-time, leaks prefix length to network attacker.  Verify
     String.equal IS the comparator in the check_auth body. *)
  let rpc = rpc_ml () in
  Alcotest.(check bool)
    "G14 (P0-SEC BUG-1) check_auth uses String.equal (variable-time)"
    true (contains_substring rpc "String.equal auth expected_user")

let g14_no_constant_time_compare_for_auth () =
  let rpc = rpc_ml () in
  Alcotest.(check bool)
    "G14 (BUG-1) no constant_time_eq / TimingResistantEqual for auth"
    false
    (contains_substring rpc "constant_time_eq"
     || contains_substring rpc "TimingResistantEqual"
     || contains_substring rpc "ct_eq"
     || contains_substring rpc "Eqaf.equal")

(* -- G15 WWW-Authenticate Basic realm="jsonrpc" — PARTIAL --------------- *)

let g15_www_authenticate_header_emitted () =
  let rpc = rpc_ml () in
  Alcotest.(check bool)
    "G15 WWW-Authenticate header emitted with Basic realm=\"jsonrpc\""
    true (contains_substring rpc "WWW-Authenticate")

let g15_basic_realm_jsonrpc () =
  let rpc = rpc_ml () in
  Alcotest.(check bool)
    "G15 Basic realm=\"jsonrpc\" realm name matches Core"
    true (contains_substring rpc "Basic realm=\\\"jsonrpc\\\"")

(* -- G16 250ms brute-force deterrent sleep — MISSING (BUG-8, P1) -------- *)

let g16_no_sleep_on_auth_failure () =
  let rpc = rpc_ml () in
  Alcotest.(check bool)
    "G16 (BUG-8) no Lwt_unix.sleep 0.25 on auth failure path"
    false
    ((contains_substring rpc "Lwt_unix.sleep 0.25"
      || contains_substring rpc "UninterruptibleSleep")
     && contains_substring rpc "check_auth")

(* -- G17 401 body — PARTIAL (BUG-14, P2: literal "Unauthorized" body) --- *)

let g17_401_body_is_unauthorized_literal () =
  let rpc = rpc_ml () in
  Alcotest.(check bool)
    "G17 (BUG-14) 401 body is literal \"Unauthorized\" (Core sends empty)"
    true (contains_substring rpc "~body:\"Unauthorized\"")

(* ============================================================================
   [D] JSON-RPC dispatch correctness (8 gates)
   ============================================================================ *)

(* -- G18 POST-only — PRESENT -------------------------------------------- *)

let g18_post_only_enforced () =
  let rpc = rpc_ml () in
  Alcotest.(check bool)
    "G18 POST-only enforced (non-POST → Method_not_allowed)"
    true (contains_substring rpc "if meth <> `POST then")

let g18_method_not_allowed_status () =
  let rpc = rpc_ml () in
  Alcotest.(check bool)
    "G18 non-POST returns `Method_not_allowed status"
    true (contains_substring rpc "~status:`Method_not_allowed")

(* -- G19 Content-Type: application/json — PRESENT ----------------------- *)

let g19_content_type_application_json () =
  let rpc = rpc_ml () in
  let n = count_substring rpc "\"Content-Type\" \"application/json\"" in
  Alcotest.(check bool)
    "G19 Content-Type: application/json emitted on >= 4 response paths"
    true (n >= 4)

(* -- G20 JSON parse error → RPC_PARSE_ERROR -32700 — PRESENT ------------ *)

let g20_parse_error_routed_on_invalid_body () =
  let rpc = rpc_ml () in
  Alcotest.(check bool)
    "G20 with exn → rpc_parse_error response"
    true
    (contains_substring rpc "with exn"
     && contains_substring rpc "~code:rpc_parse_error")

(* -- G21 Empty batch → RPC_INVALID_REQUEST -32600 — PRESENT ------------- *)

let g21_empty_batch_invalid_request () =
  let rpc = rpc_ml () in
  Alcotest.(check bool)
    "G21 empty batch returns rpc_invalid_request with 'empty batch' msg"
    true
    (contains_substring rpc "Invalid Request: empty batch"
     && contains_substring rpc "rpc_invalid_request")

(* -- G22 Single object dispatch — PRESENT ------------------------------- *)

let g22_single_object_dispatch () =
  let rpc = rpc_ml () in
  Alcotest.(check bool)
    "G22 single `Assoc request → handle_single_request"
    true
    (contains_substring rpc "| `Assoc _ as single_request"
     && contains_substring rpc "handle_single_request request_ctx single_request")

(* -- G23 Array (batch) dispatch — PRESENT ------------------------------- *)

let g23_array_batch_dispatch () =
  let rpc = rpc_ml () in
  Alcotest.(check bool)
    "G23 `List requests → handle_batch_request"
    true
    (contains_substring rpc "| `List requests"
     && contains_substring rpc "handle_batch_request request_ctx requests")

let g23_batch_parallel () =
  let rpc = rpc_ml () in
  Alcotest.(check bool)
    "G23 batch processed in parallel via Lwt_list.map_p"
    true (contains_substring rpc "Lwt_list.map_p")

(* -- G24 v2 notification → HTTP 204 — MISSING (BUG-11, P2) -------------- *)

let g24_no_http_204_for_notifications () =
  let rpc = rpc_ml () in
  Alcotest.(check bool)
    "G24 (BUG-11) no HTTP 204 No Content for jsonrpc-2.0 notifications"
    false
    (contains_substring rpc "`No_content"
     || contains_substring rpc "HTTP_NO_CONTENT"
     || contains_substring rpc "(`Code 204)"
     || contains_substring rpc "status:`No_content"
     || contains_substring rpc "IsNotification")

let g24_id_always_defaults_to_null () =
  let rpc = rpc_ml () in
  (* Sanity: confirm camlcoin defaults missing id to `Null instead of
     branching on "id absent". *)
  Alcotest.(check bool)
    "G24 (BUG-11) handle_single_request defaults missing id to `Null"
    true (contains_substring rpc "| None -> `Null")

(* -- G25 jsonrpc:"2.0" envelope detection — MISSING (BUG-12, P2) -------- *)

let g25_no_m_json_version_field () =
  let rpc = rpc_ml () in
  Alcotest.(check bool)
    "G25 (BUG-12) no m_json_version / V1_LEGACY / V2 detection"
    false
    (contains_substring rpc "m_json_version"
     || contains_substring rpc "V1_LEGACY"
     || contains_substring rpc "JSONRPCVersion")

let g25_response_always_v1_shape () =
  let rpc = rpc_ml () in
  (* json_rpc_response always pushes ("result"; "error"; "id") — v1
     legacy shape, never the v2 conditional shape. *)
  Alcotest.(check bool)
    "G25 (BUG-12) json_rpc_response always emits v1-legacy envelope"
    true
    (contains_substring rpc "(\"result\", result);\n    (\"error\", `Null);")

(* ============================================================================
   [E] HTTP status / Core-shape error mapping (3 gates)
   ============================================================================ *)

(* -- G26 RPC_INVALID_REQUEST → HTTP 400 — MISSING (BUG-15) -------------- *)

let g26_no_http_400_mapping () =
  let rpc = rpc_ml () in
  (* Core maps RPC_INVALID_REQUEST → HTTP 400, RPC_METHOD_NOT_FOUND → 404.
     camlcoin always returns ~status:`OK. *)
  Alcotest.(check bool)
    "G26 (BUG-15) no `Bad_request / 400 status for invalid-request"
    false
    (contains_substring rpc "`Bad_request"
     || contains_substring rpc "HTTP 400"
     || contains_substring rpc "(`Code 400)")

(* -- G27 RPC_METHOD_NOT_FOUND → HTTP 404 — MISSING (BUG-15) ------------- *)

let g27_no_http_404_mapping () =
  let rpc = rpc_ml () in
  Alcotest.(check bool)
    "G27 (BUG-15) no `Not_found / 404 status for method-not-found"
    false
    (contains_substring rpc "`Not_found"
     || contains_substring rpc "(`Code 404)")

(* -- G28 parse-error → 400 (v1) — MISSING (BUG-15) ---------------------- *)

let g28_all_responses_always_status_OK () =
  let rpc = rpc_ml () in
  (* Every response path uses ~status:`OK (even for errors).  This is
     the symptom of BUG-15 — we count the call sites to make it visible. *)
  let n = count_substring rpc "~status:`OK" in
  Alcotest.(check bool)
    (Printf.sprintf
       "G28 (BUG-15) all dispatch paths use ~status:`OK (count=%d, >= 5)" n)
    true (n >= 5)

(* ============================================================================
   [F] Whitelist / DoS / size limits (2 gates)
   ============================================================================ *)

(* -- G29 -rpcwhitelist / -rpcwhitelistdefault — MISSING (BUG-16, P2) ---- *)

let g29_rpcwhitelist_flag_NOT_declared () =
  let main = main_ml () in
  Alcotest.(check bool)
    "G29 (BUG-16) --rpcwhitelist flag NOT declared"
    false
    (contains_substring main "\"rpcwhitelist\"")

let g29_no_per_user_method_acl () =
  let rpc = rpc_ml () in
  Alcotest.(check bool)
    "G29 (BUG-16) no per-(user,method) ACL in dispatcher"
    false
    (contains_substring rpc "g_rpc_whitelist"
     || contains_substring rpc "user_whitelist"
     || contains_substring rpc "whitelist_default")

(* -- G30 MAX_HEADERS_SIZE / MAX body cap — MISSING (BUG-17, P2) --------- *)

let g30_no_max_body_size () =
  let rpc = rpc_ml () in
  Alcotest.(check bool)
    "G30 (BUG-17) no max-body-size cap on Cohttp listener"
    false
    (contains_substring rpc "max_body_size"
     || contains_substring rpc "MAX_BODY_SIZE"
     || contains_substring rpc "MAX_SIZE")

let g30_no_max_headers_size () =
  let rpc = rpc_ml () in
  Alcotest.(check bool)
    "G30 (BUG-17) no MAX_HEADERS_SIZE (8192) limit"
    false
    (contains_substring rpc "MAX_HEADERS_SIZE"
     || contains_substring rpc "max_headers_size"
     || contains_substring rpc "8192")

(* ============================================================================
   Audit-status checks
   ============================================================================ *)

let as1_audit_doc_exists () =
  Alcotest.(check bool) "AS1 audit doc exists" true
    (Sys.file_exists (audit_doc_path ()))

let as2_30_gates_documented () =
  (* The audit md tabulates 30 gates; verify all G1..G30 markers are
     present (one per gate). *)
  let doc = read_file (audit_doc_path ()) in
  let missing =
    List.filter
      (fun i ->
        not (contains_substring doc (Printf.sprintf "| G%d " i)))
      (List.init 30 (fun i -> i + 1))
  in
  Alcotest.(check (list int))
    "AS2 all 30 gates G1..G30 documented in audit md" [] missing

let as3_three_p0_sec_bugs () =
  let doc = read_file (audit_doc_path ()) in
  let n = count_substring doc "P0-SEC" in
  Alcotest.(check bool)
    (Printf.sprintf "AS3 audit md mentions P0-SEC >= 4 times (count=%d) — \
                     3 bugs + 1 severity header" n)
    true (n >= 4)

let as4_twenty_bugs () =
  let doc = read_file (audit_doc_path ()) in
  let n = count_substring doc "BUG-" in
  Alcotest.(check bool)
    (Printf.sprintf "AS4 audit md catalogues >= 20 BUG-N references \
                     (count=%d)" n)
    true (n >= 20)

let as5_w140_banner () =
  let doc = read_file (audit_doc_path ()) in
  Alcotest.(check bool)
    "AS5 audit md starts with W140 banner"
    true
    (contains_substring doc "# W140:"
     && contains_substring doc "HTTP Server + rpcauth")

let as6_canonical_references () =
  let doc = read_file (audit_doc_path ()) in
  let refs = [
    "httpserver.cpp";
    "httprpc.cpp";
    "rpc/request.cpp";
    "share/rpcauth";
    "init.cpp";
  ] in
  let missing =
    List.filter (fun r -> not (contains_substring doc r)) refs in
  Alcotest.(check (list string))
    "AS6 audit md references all 5 canonical Core source files" [] missing

(* ============================================================================
   Alcotest suite
   ============================================================================ *)

open Alcotest

let () =
  run "w140-http-rpcauth" [
    "[A] Address / connection ACL", [
      test_case "G1 -rpcallowip flag NOT declared (P0-SEC BUG-5)" `Quick
        g1_rpcallowip_flag_NOT_declared;
      test_case "G1 no ClientAllowed subnet check (BUG-5)" `Quick
        g1_rpcallowip_no_subnet_check;
      test_case "G2 -rpcbind flag NOT declared (BUG-6)" `Quick
        g2_rpcbind_flag_NOT_declared;
      test_case "G2 start_rpc_server single-host signature (BUG-6)" `Quick
        g2_rpcbind_single_listener_only;
      test_case "G3 --rpchost default loopback" `Quick
        g3_default_rpchost_loopback;
      test_case "G3 no refusal-to-bind on non-loopback (BUG-7)" `Quick
        g3_no_refusal_to_bind_nonloopback_without_acl;
      test_case "G4 TCP_NODELAY NOT set (BUG-13)" `Quick
        g4_tcp_nodelay_NOT_set;
      test_case "G5 no unsafe-bind warning log (BUG-19)" `Quick
        g5_no_unsafe_bind_warning;
    ];
    "[B] Auth credential plumbing", [
      test_case "G6 --rpcauth flag NOT declared (P0-SEC BUG-2)" `Quick
        g6_rpcauth_flag_NOT_declared;
      test_case "G6 no HMAC-SHA-256 in auth path (BUG-2)" `Quick
        g6_no_hmac_sha256_in_rpc;
      test_case "G6 no salt$hash parser (BUG-2)" `Quick
        g6_no_salt_dollar_hash_parse;
      test_case "G7 --rpcuser flag declared" `Quick
        g7_rpcuser_flag_declared;
      test_case "G7 --rpcpassword flag declared" `Quick
        g7_rpcpassword_flag_declared;
      test_case "G7 plumbed into start_rpc_server" `Quick
        g7_rpcuser_plumbed_to_server;
      test_case "G8 cookie from 32 random bytes" `Quick
        g8_cookie_32_random_bytes;
      test_case "G9 cookie content __cookie__: prefix" `Quick
        g9_cookie_user_prefix;
      test_case "G9 cookie missing trailing newline (BUG-9)" `Quick
        g9_cookie_missing_trailing_newline;
      test_case "G10 no atomic .cookie.tmp + rename (BUG-3)" `Quick
        g10_no_tmp_rename_for_cookie;
      test_case "G11 cookie 0o600 perms (PRESENT)" `Quick
        g11_cookie_perms_0o600;
      test_case "G12 --rpccookieperms flag NOT declared (BUG-4)" `Quick
        g12_rpccookieperms_NOT_declared;
      test_case "G13 no DeleteAuthCookie on shutdown (BUG-10)" `Quick
        g13_no_delete_auth_cookie_on_shutdown;
    ];
    "[C] Auth response surface", [
      test_case "G14 String.equal used (P0-SEC BUG-1)" `Quick
        g14_String_equal_is_variable_time;
      test_case "G14 no constant-time compare (BUG-1)" `Quick
        g14_no_constant_time_compare_for_auth;
      test_case "G15 WWW-Authenticate header emitted" `Quick
        g15_www_authenticate_header_emitted;
      test_case "G15 Basic realm=\"jsonrpc\"" `Quick
        g15_basic_realm_jsonrpc;
      test_case "G16 no 250ms sleep on auth failure (BUG-8)" `Quick
        g16_no_sleep_on_auth_failure;
      test_case "G17 401 body 'Unauthorized' literal (BUG-14)" `Quick
        g17_401_body_is_unauthorized_literal;
    ];
    "[D] JSON-RPC dispatch correctness", [
      test_case "G18 POST-only enforced" `Quick
        g18_post_only_enforced;
      test_case "G18 non-POST status Method_not_allowed" `Quick
        g18_method_not_allowed_status;
      test_case "G19 Content-Type: application/json" `Quick
        g19_content_type_application_json;
      test_case "G20 parse error routed -32700" `Quick
        g20_parse_error_routed_on_invalid_body;
      test_case "G21 empty batch -32600 invalid-request" `Quick
        g21_empty_batch_invalid_request;
      test_case "G22 single object dispatch" `Quick
        g22_single_object_dispatch;
      test_case "G23 array (batch) dispatch" `Quick
        g23_array_batch_dispatch;
      test_case "G23 batch parallel via map_p" `Quick
        g23_batch_parallel;
      test_case "G24 no HTTP 204 for notifications (BUG-11)" `Quick
        g24_no_http_204_for_notifications;
      test_case "G24 id defaults to `Null on missing (BUG-11)" `Quick
        g24_id_always_defaults_to_null;
      test_case "G25 no m_json_version detection (BUG-12)" `Quick
        g25_no_m_json_version_field;
      test_case "G25 response always v1-legacy shape (BUG-12)" `Quick
        g25_response_always_v1_shape;
    ];
    "[E] HTTP status mapping", [
      test_case "G26 no HTTP 400 for invalid-request (BUG-15)" `Quick
        g26_no_http_400_mapping;
      test_case "G27 no HTTP 404 for method-not-found (BUG-15)" `Quick
        g27_no_http_404_mapping;
      test_case "G28 all responses ~status:`OK (BUG-15)" `Quick
        g28_all_responses_always_status_OK;
    ];
    "[F] Whitelist / DoS / size limits", [
      test_case "G29 --rpcwhitelist flag NOT declared (BUG-16)" `Quick
        g29_rpcwhitelist_flag_NOT_declared;
      test_case "G29 no (user,method) ACL in dispatcher (BUG-16)" `Quick
        g29_no_per_user_method_acl;
      test_case "G30 no max-body-size cap (BUG-17)" `Quick
        g30_no_max_body_size;
      test_case "G30 no MAX_HEADERS_SIZE (BUG-17)" `Quick
        g30_no_max_headers_size;
    ];
    "Audit-status", [
      test_case "AS1 audit doc exists" `Quick as1_audit_doc_exists;
      test_case "AS2 all 30 gates G1..G30 documented" `Quick
        as2_30_gates_documented;
      test_case "AS3 3 P0-SEC bugs documented" `Quick as3_three_p0_sec_bugs;
      test_case "AS4 >= 20 BUG-N references" `Quick as4_twenty_bugs;
      test_case "AS5 W140 audit banner" `Quick as5_w140_banner;
      test_case "AS6 5 Core canonical refs" `Quick as6_canonical_references;
    ];
  ]
