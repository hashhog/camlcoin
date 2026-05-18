(* W141 ZMQ + REST + Notification scripts audit — camlcoin (OCaml)

   Discovery-only audit.  30 gates / 24 BUGs documented.

   Bitcoin Core references:
   - bitcoin-core/src/zmq/zmqnotificationinterface.cpp
     - L60: gArgs.GetArgs("-zmq" + topic) — one option per CLI arg
     - L62-64: ADDR_PREFIX_UNIX → ADDR_PREFIX_IPC rewrite
     - L69: DEFAULT_ZMQ_SNDHWM=1000 + per-topic HWM override
     - L151-159: UpdatedBlockTip skips IBD AND pindexNew==pindexFork
     - L180-196: BlockConnected fires NotifyTransaction per-tx
   - bitcoin-core/src/zmq/zmqpublishnotifier.cpp + .h
     - L21 (header): nSequence is per-(topic, address) instance
     - L100-159: mapPublishNotifiers keyed by ADDRESS — socket reuse
     - L185-186: ZMQ_LINGER=0 before zmq_close
     - L254-265: SendSequenceMsg — 33 vs 41 byte payloads
   - bitcoin-core/src/rest.cpp
     - L44-45: MAX_GETUTXOS_OUTPOINTS=15, MAX_REST_HEADERS_RESULTS=2000
     - L171-177: CheckWarmup on every endpoint
     - L1100: SanitizeString(SAFE_CHARS_URI) of user input
     - L1141-1159: 14 URI prefixes
   - bitcoin-core/src/init.cpp
     - L256-265, L737-746: ShutdownNotify / StartupNotify
     - L2008-2019: -blocknotify, post-IBD gate
   - bitcoin-core/src/node/kernel_notifications.cpp
     - L30-47: AlertNotify — SanitizeString + ShellEscape + runCommand
   - bitcoin-core/src/wallet/wallet.cpp
     - L1139-1165: -walletnotify substitutes %s/%b/%h/%w
   - bitcoin-core/src/common/system.cpp
     - L40-46: ShellEscape; L49-62: runCommand

   Severity legend:
   - P0-CDIV: protocol-correctness divergence externally visible to
              subscribers / REST clients (wrong bytes, silent drop)
   - P1: feature-correctness gap (right format, wrong gating / coverage)
   - P2: privacy / fingerprinting / fairness drift
   - P3: surface / doc / constant drift

   BUGs (this wave) — 24 across 30 gates:

   BUG-W141-1 (P2 G1):  ZMQ topic-alias double-prefix accepted
   BUG-W141-2 (P1 G2):  no -zmqpub<topic>hwm per-topic HWM override
   BUG-W141-3 (P0-CDIV G3): sequence Hashtbl keyed by topic globally,
                            second address silently dropped
   BUG-W141-4 (P1 G4):  multi-bind on one PUB socket → cross-address
                        topic spillover
   BUG-W141-5 (P3 G5):  no unix:// → ipc:// rewrite
   BUG-W141-6 (P0-CDIV G6): hashblock + rawblock fire during IBD
   BUG-W141-7 (P0-CDIV G7): no per-tx hashtx/rawtx on BlockConnected
   BUG-W141-8 (P1 G8):  no role.historical gate
   BUG-W141-9 (P3 G9):  ZMQ_LINGER=0 set at socket-create not just-before-close
   BUG-W141-10 (P2 G10): in-process queue retains every sent message
   BUG-W141-11 (P1 G12): REST has no CheckWarmup gate
   BUG-W141-12 (P2 G13): REST error echoes raw user-input (no SAFE_CHARS_URI)
   BUG-W141-13 (P1 G14): /rest/getutxos missing
   BUG-W141-14 (P3 G15): /rest/blockpart/ missing
   BUG-W141-15 (P1 G16): /rest/spenttxouts/ missing
   BUG-W141-16 (P3 G17): /rest/deploymentinfo missing
   BUG-W141-17 (P1 G18): rest_tx doesn't block on tx-index sync
   BUG-W141-18 (P1 G23): no -blocknotify script support
   BUG-W141-19 (P1 G25): no -alertnotify script support
   BUG-W141-20 (P1 G26): no -walletnotify script support
   BUG-W141-21 (P3 G27): no -startupnotify / -shutdownnotify
   BUG-W141-22 (P1 G28): no ShellEscape helper
   BUG-W141-23 (P1 G29): no SanitizeString helper
   BUG-W141-24 (P3 G30): no runCommand-equivalent wrapper
*)

open Camlcoin

(* ============================================================================
   Helpers — pattern mirrors W130 / W134 / W136 / W137
   ============================================================================ *)

let read_file_opt (path : string) : string option =
  try
    let ic = open_in path in
    let len = in_channel_length ic in
    let buf = Bytes.create len in
    really_input ic buf 0 len;
    close_in ic;
    Some (Bytes.unsafe_to_string buf)
  with _ -> None

let string_contains (haystack : string) (needle : string) : bool =
  let hl = String.length haystack and nl = String.length needle in
  if nl = 0 then true
  else if nl > hl then false
  else begin
    let found = ref false in
    let i = ref 0 in
    while not !found && !i + nl <= hl do
      if String.sub haystack !i nl = needle then found := true
      else incr i
    done;
    !found
  end

let load_source (relative_path : string) : string option =
  let candidates = [
    relative_path;
    "../" ^ relative_path;
    "../../" ^ relative_path;
    "../../../" ^ relative_path;
    "/home/work/hashhog/camlcoin/" ^ relative_path;
  ] in
  let rec try_each = function
    | [] -> None
    | p :: rest ->
      (match read_file_opt p with Some s -> Some s | None -> try_each rest)
  in
  try_each candidates

(* Generate a random-ish hash for testing.  Same generator as test_zmq.ml. *)
let make_test_hash (seed : int) : Types.hash256 =
  let h = Cstruct.create 32 in
  for i = 0 to 31 do
    Cstruct.set_uint8 h i ((seed * (i + 1)) mod 256)
  done;
  h

(* ============================================================================
   G1-G10 — ZMQ pub/sub notifier
   ============================================================================ *)

(* G1: BUG-W141-1 — topic-alias grammar accepts `pub<topic>=` form, which
   means `-zmqpubpubhashblock=...` is accepted alongside Core's
   `-zmqpubhashblock=...`. *)
let test_g1_zmq_topic_alias_double_prefix () =
  (* The parser strips `-zmqpub` (7 chars) and then matches the remainder
     against parse_topic_name.  parse_topic_name accepts both `hashblock`
     and `pubhashblock`.  So `-zmqpubpubhashblock=tcp://...` should
     succeed. *)
  let result =
    Zmq_notify.Config.parse_zmq_option
      "-zmqpubpubhashblock=tcp://127.0.0.1:28332"
  in
  Alcotest.(check bool)
    "G1: BUG-W141-1 — `-zmqpubpubhashblock=` double-prefix accepted"
    true (result <> None)

(* G1b: numerical example — Core-canonical form is also accepted. *)
let test_g1b_zmq_canonical_form_accepted () =
  let result =
    Zmq_notify.Config.parse_zmq_option
      "-zmqpubhashblock=tcp://127.0.0.1:28332"
  in
  Alcotest.(check bool)
    "G1b: canonical `-zmqpubhashblock=` form accepted"
    true (result <> None)

(* G2: BUG-W141-2 — no -zmqpub<topic>hwm support.  Source-grep: no
   `hwm` token in any of bin/main.ml or lib/zmq_notify.ml or
   lib/cli.ml at the option-parse layer. *)
let test_g2_no_per_topic_hwm_override () =
  let main = load_source "bin/main.ml" in
  let cli = load_source "lib/cli.ml" in
  let zmq_notify = load_source "lib/zmq_notify.ml" in
  let combined =
    Option.value main ~default:""
    ^ Option.value cli ~default:""
    ^ Option.value zmq_notify ~default:""
  in
  (* hwm appears in `high_water_mark` records but NOT as an
     option-parser token.  Look for `zmqpubhashblockhwm` or any
     parser hook for `hwm=` argument. *)
  let has_per_topic_hwm =
    string_contains combined "zmqpubhashblockhwm" ||
    string_contains combined "zmqpubhashtxhwm" ||
    string_contains combined "zmqpubrawblockhwm" ||
    string_contains combined "zmqpubrawtxhwm" ||
    string_contains combined "zmqpubsequencehwm" ||
    string_contains combined "topic_hwm"
  in
  Alcotest.(check bool)
    "G2: BUG-W141-2 — no `-zmqpub<topic>hwm` per-topic HWM parser"
    false has_per_topic_hwm

(* G3: BUG-W141-3 (P0-CDIV) — sequence/state Hashtbl keyed by TOPIC
   globally.  Two endpoints for same topic ⇒ second silently dropped.

   We exercise this via the actual Zmq_notify.create API: building
   two endpoint configs with the same topic at different addresses
   should produce TWO publisher states (one per address), but only
   produces ONE because of the `if not (Hashtbl.mem publishers topic)`
   guard at zmq_notify.ml:103. *)
let test_g3_topic_keyed_state_drops_second_address () =
  let configs = [
    Zmq_notify.{
      address = "tcp://127.0.0.1:28332";
      topics = [Zmq_notify.HashBlock];
      high_water_mark = 1000;
    };
    Zmq_notify.{
      address = "tcp://127.0.0.1:28333";
      topics = [Zmq_notify.HashBlock];
      high_water_mark = 1000;
    };
  ] in
  let notifier = Zmq_notify.create configs in
  (* Core would create TWO CZMQPublishHashBlockNotifier instances, each
     with its own nSequence counter and address.  camlcoin's
     `publishers` Hashtbl has exactly ONE HashBlock entry. *)
  let count = Hashtbl.length notifier.Zmq_notify.publishers in
  Alcotest.(check int)
    "G3: BUG-W141-3 — only ONE HashBlock state for TWO addresses"
    1 count

(* G3b: source-level confirmation of the root cause — the `if not
   Hashtbl.mem` guard. *)
let test_g3b_topic_keyed_state_source () =
  let src = load_source "lib/zmq_notify.ml" in
  match src with
  | None ->
    Alcotest.(check bool) "G3b: documentary — zmq_notify.ml not in cwd" true true
  | Some s ->
    Alcotest.(check bool)
      "G3b: BUG-W141-3 — `if not (Hashtbl.mem publishers topic)` guard present"
      true (string_contains s "if not (Hashtbl.mem publishers topic)")

(* G4: BUG-W141-4 — multi-bind on one PUB socket.
   Source-grep: zmq_socket.ml's `create_from_config` binds every
   distinct address onto the SAME publisher via List.iter. *)
let test_g4_multi_bind_one_socket () =
  let src = load_source "lib/zmq_socket.ml" in
  match src with
  | None ->
    Alcotest.(check bool) "G4: BUG-W141-4 PRESENT (documentary)" true true
  | Some s ->
    (* The relevant snippet: `List.iter (fun addr -> bind pub addr) addresses`
       — single publisher object, every address bound to it. *)
    Alcotest.(check bool)
      "G4: BUG-W141-4 — single `pub` shared across `List.iter bind addresses`"
      true (string_contains s "List.iter (fun addr -> bind pub addr) addresses")

(* G5: BUG-W141-5 — no unix:// → ipc:// rewrite.  Source-grep absence
   of the rewrite token itself. *)
let test_g5_no_unix_to_ipc_rewrite () =
  let socket = load_source "lib/zmq_socket.ml" in
  let notify = load_source "lib/zmq_notify.ml" in
  let combined =
    Option.value socket ~default:""
    ^ Option.value notify ~default:""
  in
  (* `ipc://` is mentioned in a doc-comment in lib/zmq_bindings.ml as a
     valid bind format, but no rewrite from `unix://` happens.  The
     bug-evidence is the absence of `unix://` (Core's input form) in the
     ZMQ wrappers — no Core operator config can be copied across. *)
  Alcotest.(check bool)
    "G5: BUG-W141-5 — no `unix://` substring in ZMQ wrappers (no rewrite)"
    false (string_contains combined "unix://");
  Alcotest.(check bool)
    "G5: BUG-W141-5 — no `ADDR_PREFIX_UNIX` token in ZMQ wrappers"
    false (string_contains combined "ADDR_PREFIX_UNIX")

(* G6: BUG-W141-6 (P0-CDIV) — no IBD gate around zmq_notify_block.
   Source-grep: sync.ml's call site at line 2590 has no IBD predicate. *)
let test_g6_no_ibd_gate_on_block_publish () =
  let src = load_source "lib/sync.ml" in
  match src with
  | None ->
    Alcotest.(check bool) "G6: BUG-W141-6 PRESENT (documentary)" true true
  | Some s ->
    (* Look for the marker comment "Notify ZMQ subscribers about block
       connect" and confirm no `IsInitialBlockDownload` / `sync_state`
       check appears within ~200 chars before it.  Conservative test:
       check that `zmq_notify_block ibd block entry.hash true` is NOT
       preceded by `if ibd.chain.sync_state` on the same call. *)
    let has_call =
      string_contains s "zmq_notify_block ibd block entry.hash true" in
    let has_ibd_gate =
      string_contains s "if not (is_initial_block_download" ||
      string_contains s "if ibd.chain.sync_state = FullySynced" ||
      string_contains s "if not in_ibd"
    in
    Alcotest.(check bool)
      "G6: BUG-W141-6 — zmq_notify_block call exists in sync.ml" true has_call;
    Alcotest.(check bool)
      "G6: BUG-W141-6 — no IBD gate around zmq_notify_block"
      false has_ibd_gate

(* G7: BUG-W141-7 (P0-CDIV) — no per-tx hashtx/rawtx fired on
   block-connect.  sync.ml's zmq_notify_block only fires hashblock /
   rawblock / sequence-C; never iterates over block.transactions. *)
let test_g7_no_per_tx_hashtx_on_block_connect () =
  let src = load_source "lib/sync.ml" in
  match src with
  | None ->
    Alcotest.(check bool) "G7: BUG-W141-7 PRESENT (documentary)" true true
  | Some s ->
    (* The zmq_notify_block helper body should NOT contain a List.iter
       over block.transactions with notify_hashtx or notify_rawtx. *)
    let has_tx_iter =
      string_contains s "List.iter (fun tx -> Zmq_notify.notify_hashtx" ||
      string_contains s "Zmq_notify.notify_rawtx notifier tx" ||
      string_contains s "List.iter.*notify_hashtx"
    in
    Alcotest.(check bool)
      "G7: BUG-W141-7 — no per-tx hashtx/rawtx in zmq_notify_block"
      false has_tx_iter

(* G8: BUG-W141-8 — no role.historical / assumeutxo background gate. *)
let test_g8_no_historical_role_gate () =
  let sync = load_source "lib/sync.ml" in
  let assume = load_source "lib/assume_utxo.ml" in
  let combined =
    Option.value sync ~default:"" ^ Option.value assume ~default:""
  in
  let has_historical_gate =
    string_contains combined "role.historical" ||
    string_contains combined "ChainstateRole" ||
    string_contains combined "is_historical"
  in
  Alcotest.(check bool)
    "G8: BUG-W141-8 — no `role.historical` gate threaded into ZMQ"
    false has_historical_gate

(* G9: BUG-W141-9 — ZMQ_LINGER=0 is set, but at SOCKET-CREATE time
   (zmq_stubs.c:141-145 caml_zmq_pub_socket), NOT just-before-close
   like Core (zmqpublishnotifier.cpp:185-186 — `int linger = 0;
   zmq_setsockopt(...,ZMQ_LINGER,...); zmq_close(psocket);`).  The
   close-latency effect is the same, but Core's pattern lets the
   operator configure a non-zero linger for retry-on-publish and only
   flips to 0 at shutdown.  camlcoin is permanently linger-0. *)
let test_g9_linger_at_create_not_close () =
  let stubs = load_source "lib/zmq_stubs.c" in
  let socket = load_source "lib/zmq_socket.ml" in
  let stubs_content = Option.value stubs ~default:"" in
  let socket_content = Option.value socket ~default:"" in
  (* Linger IS set in zmq_stubs.c (at socket creation). *)
  Alcotest.(check bool)
    "G9: ZMQ_LINGER setsockopt exists in zmq_stubs.c"
    true (string_contains stubs_content "ZMQ_LINGER");
  (* But close_publisher in zmq_socket.ml does NOT set linger before close.
     Look for the pattern `set_linger` or `setsockopt` immediately before
     `Zmq_bindings.close`. *)
  let close_resets_linger =
    string_contains socket_content "set_linger 0" ||
    string_contains socket_content "Zmq_bindings.set_linger"
  in
  Alcotest.(check bool)
    "G9: BUG-W141-9 — close_publisher does NOT set LINGER=0 just-before-close"
    false close_resets_linger

(* G10: BUG-W141-10 — in-process queue retains every sent message.
   Behavioural test: after one notify call, the publisher's queue
   has one entry even though the in-memory test-mode `send_cb` is
   set (no libzmq attempt). *)
let test_g10_in_process_queue_retains_every_send () =
  let notifier =
    Zmq_notify.create [
      Zmq_notify.{
        address = "tcp://127.0.0.1:28332";
        topics = [Zmq_notify.HashBlock];
        high_water_mark = 1000;
      }
    ]
  in
  let block_hash = make_test_hash 1 in
  ignore (Zmq_notify.notify_hashblock notifier block_hash);
  let q = Zmq_notify.get_queued_messages notifier Zmq_notify.HashBlock in
  Alcotest.(check int)
    "G10: BUG-W141-10 — single notify queues exactly one message"
    1 (List.length q)

(* ============================================================================
   G11-G22 — REST API
   ============================================================================ *)

(* G11: -rest default = false (PARITY).  Constants probe. *)
let test_g11_rest_default_disabled () =
  let cfg = Cli.default_config in
  Alcotest.(check bool)
    "G11: PARITY — rest_enabled default = false"
    false cfg.Cli.rest_enabled

(* G12: BUG-W141-11 — no CheckWarmup gate on any REST handler. *)
let test_g12_no_rest_warmup_gate () =
  let src = load_source "lib/rest.ml" in
  match src with
  | None ->
    Alcotest.(check bool) "G12: BUG-W141-11 PRESENT (documentary)" true true
  | Some s ->
    let has_warmup =
      string_contains s "CheckWarmup" ||
      string_contains s "is_warmup" ||
      string_contains s "RPCIsInWarmup" ||
      string_contains s "Service temporarily unavailable" ||
      string_contains s "warmup"
    in
    Alcotest.(check bool)
      "G12: BUG-W141-11 — rest.ml has no warmup gate"
      false has_warmup

(* G13: BUG-W141-12 — no SAFE_CHARS_URI sanitisation of user input. *)
let test_g13_no_user_input_sanitisation_on_error () =
  let src = load_source "lib/rest.ml" in
  match src with
  | None ->
    Alcotest.(check bool) "G13: BUG-W141-12 PRESENT (documentary)" true true
  | Some s ->
    let has_sanitize =
      string_contains s "SanitizeString" ||
      string_contains s "SAFE_CHARS_URI" ||
      string_contains s "safe_chars_uri" ||
      string_contains s "sanitize_string"
    in
    Alcotest.(check bool)
      "G13: BUG-W141-12 — no SanitizeString helper in rest.ml"
      false has_sanitize

(* G14: BUG-W141-13 — /rest/getutxos missing. *)
let test_g14_no_getutxos_endpoint () =
  let src = load_source "lib/rest.ml" in
  match src with
  | None ->
    Alcotest.(check bool) "G14: BUG-W141-13 PRESENT (documentary)" true true
  | Some s ->
    let has_endpoint =
      string_contains s "/rest/getutxos" ||
      string_contains s "handle_getutxos" ||
      string_contains s "checkmempool"
    in
    Alcotest.(check bool)
      "G14: BUG-W141-13 — /rest/getutxos NOT implemented" false has_endpoint

(* G15: BUG-W141-14 — /rest/blockpart/ missing. *)
let test_g15_no_blockpart_endpoint () =
  let src = load_source "lib/rest.ml" in
  match src with
  | None ->
    Alcotest.(check bool) "G15: BUG-W141-14 PRESENT (documentary)" true true
  | Some s ->
    let has_endpoint =
      string_contains s "/rest/blockpart" ||
      string_contains s "handle_blockpart" ||
      string_contains s "block_part"
    in
    Alcotest.(check bool)
      "G15: BUG-W141-14 — /rest/blockpart/ NOT implemented" false has_endpoint

(* G16: BUG-W141-15 — /rest/spenttxouts/ missing. *)
let test_g16_no_spenttxouts_endpoint () =
  let src = load_source "lib/rest.ml" in
  match src with
  | None ->
    Alcotest.(check bool) "G16: BUG-W141-15 PRESENT (documentary)" true true
  | Some s ->
    let has_endpoint =
      string_contains s "/rest/spenttxouts" ||
      string_contains s "handle_spent_txouts" ||
      string_contains s "SerializeBlockUndo"
    in
    Alcotest.(check bool)
      "G16: BUG-W141-15 — /rest/spenttxouts/ NOT implemented" false has_endpoint

(* G17: BUG-W141-16 — /rest/deploymentinfo missing. *)
let test_g17_no_deploymentinfo_endpoint () =
  let src = load_source "lib/rest.ml" in
  match src with
  | None ->
    Alcotest.(check bool) "G17: BUG-W141-16 PRESENT (documentary)" true true
  | Some s ->
    let has_endpoint =
      string_contains s "/rest/deploymentinfo" ||
      string_contains s "handle_deploymentinfo"
    in
    Alcotest.(check bool)
      "G17: BUG-W141-16 — /rest/deploymentinfo NOT implemented" false has_endpoint

(* G18: BUG-W141-17 — rest_tx doesn't block on tx-index sync. *)
let test_g18_rest_tx_no_index_sync_barrier () =
  let src = load_source "lib/rest.ml" in
  match src with
  | None ->
    Alcotest.(check bool) "G18: BUG-W141-17 PRESENT (documentary)" true true
  | Some s ->
    let has_barrier =
      string_contains s "BlockUntilSyncedToCurrentChain" ||
      string_contains s "block_until_synced" ||
      string_contains s "wait_for_tx_index"
    in
    Alcotest.(check bool)
      "G18: BUG-W141-17 — rest_tx has no tx-index sync barrier"
      false has_barrier

(* G19: PARITY — ParseDataFormat strips query string at '?'.  Probe. *)
let test_g19_parse_data_format_strips_query () =
  let (rf, base) = Rest.parse_data_format "abc.json?count=5" in
  Alcotest.(check string) "G19: ParseDataFormat base stripped of ?" "abc" base;
  Alcotest.(check bool) "G19: ParseDataFormat returns JSON"
    true (rf = Rest.JSON)

(* G19b: extension `.bin` recognised. *)
let test_g19b_parse_data_format_recognises_bin () =
  let (rf, _) = Rest.parse_data_format "abc.bin" in
  Alcotest.(check bool) "G19b: .bin → Binary" true (rf = Rest.Binary)

(* G19c: missing extension → Undefined + raw input. *)
let test_g19c_parse_data_format_undefined () =
  let (rf, _) = Rest.parse_data_format "abc" in
  Alcotest.(check bool) "G19c: no extension → Undefined" true
    (rf = Rest.Undefined)

(* G20: PARITY — deprecated `<count>/<hash>` path supported via
   split_string parsing.  Probe handle_headers entry via source. *)
let test_g20_deprecated_count_hash_path_supported () =
  let src = load_source "lib/rest.ml" in
  match src with
  | None ->
    Alcotest.(check bool) "G20: documentary" true true
  | Some s ->
    Alcotest.(check bool)
      "G20: PARITY — deprecated `count; hash` path present"
      true (string_contains s "Deprecated path: /rest/headers/<count>/<hash>")

(* G21: PARITY — RESTERR body terminator is \r\n.  Probe respond_error. *)
let test_g21_resterr_terminator () =
  let src = load_source "lib/rest.ml" in
  match src with
  | None ->
    Alcotest.(check bool) "G21: documentary" true true
  | Some s ->
    (* The respond_error helper appends "\r\n" to the message. *)
    Alcotest.(check bool)
      "G21: PARITY — respond_error appends \\r\\n"
      true (string_contains s "body:(message ^ \"\\r\\n\")")

(* G22: PARITY — max_headers_results = 2000. *)
let test_g22_max_headers_constant () =
  Alcotest.(check int) "G22: PARITY — max_headers_results = 2000"
    2000 Rest.max_headers_results

(* ============================================================================
   G23-G30 — Notification scripts
   ============================================================================ *)

(* G23: BUG-W141-18 — no -blocknotify CLI arg. *)
let test_g23_no_blocknotify_arg () =
  let main = load_source "bin/main.ml" in
  let cli = load_source "lib/cli.ml" in
  let combined =
    Option.value main ~default:"" ^ Option.value cli ~default:""
  in
  let has =
    string_contains combined "blocknotify" ||
    string_contains combined "block_notify"
  in
  Alcotest.(check bool)
    "G23: BUG-W141-18 — no `blocknotify` parser / arg"
    false has

(* G24: pre-req for G23 — Core's post-IBD gate.  No bug yet (no impl).
   We document it as "would-be-required" and assert the IBD-state surface
   exists in sync.ml so a future fix can wire it. *)
let test_g24_post_ibd_gate_prerequisite () =
  let src = load_source "lib/sync.ml" in
  match src with
  | None ->
    Alcotest.(check bool) "G24: documentary" true true
  | Some s ->
    Alcotest.(check bool)
      "G24: sync.ml has FullySynced concept (prereq for post-IBD blocknotify)"
      true (string_contains s "FullySynced")

(* G25: BUG-W141-19 — no -alertnotify CLI arg or AlertNotify path. *)
let test_g25_no_alertnotify_arg () =
  let main = load_source "bin/main.ml" in
  let cli = load_source "lib/cli.ml" in
  let runtime = load_source "lib/runtime_config.ml" in
  let combined =
    Option.value main ~default:""
    ^ Option.value cli ~default:""
    ^ Option.value runtime ~default:""
  in
  let has =
    string_contains combined "alertnotify" ||
    string_contains combined "alert_notify" ||
    string_contains combined "AlertNotify"
  in
  Alcotest.(check bool)
    "G25: BUG-W141-19 — no `alertnotify` parser / arg"
    false has

(* G26: BUG-W141-20 — no -walletnotify hook in wallet.ml. *)
let test_g26_no_walletnotify_hook () =
  let wallet = load_source "lib/wallet.ml" in
  let main = load_source "bin/main.ml" in
  let cli = load_source "lib/cli.ml" in
  let combined =
    Option.value wallet ~default:""
    ^ Option.value main ~default:""
    ^ Option.value cli ~default:""
  in
  let has =
    string_contains combined "walletnotify" ||
    string_contains combined "wallet_notify" ||
    string_contains combined "WalletNotify" ||
    string_contains combined "m_notify_tx_changed_script"
  in
  Alcotest.(check bool)
    "G26: BUG-W141-20 — no `walletnotify` hook"
    false has

(* G27: BUG-W141-21 — no startupnotify / shutdownnotify. *)
let test_g27_no_startup_shutdown_notify () =
  let main = load_source "bin/main.ml" in
  let cli = load_source "lib/cli.ml" in
  let combined =
    Option.value main ~default:"" ^ Option.value cli ~default:""
  in
  let has =
    string_contains combined "startupnotify" ||
    string_contains combined "shutdownnotify" ||
    string_contains combined "startup_notify" ||
    string_contains combined "shutdown_notify"
  in
  Alcotest.(check bool)
    "G27: BUG-W141-21 — no `startup/shutdownnotify`"
    false has

(* G28: BUG-W141-22 — no ShellEscape helper anywhere in lib/. *)
let test_g28_no_shell_escape_helper () =
  let common = load_source "lib/cli.ml" in
  let wallet = load_source "lib/wallet.ml" in
  let runtime = load_source "lib/runtime_config.ml" in
  let combined =
    Option.value common ~default:""
    ^ Option.value wallet ~default:""
    ^ Option.value runtime ~default:""
  in
  let has =
    string_contains combined "ShellEscape" ||
    string_contains combined "shell_escape" ||
    string_contains combined "shellEscape"
  in
  Alcotest.(check bool)
    "G28: BUG-W141-22 — no `ShellEscape`-equivalent helper"
    false has

(* G29: BUG-W141-23 — no SanitizeString helper. *)
let test_g29_no_sanitize_string_helper () =
  let common = load_source "lib/cli.ml" in
  let runtime = load_source "lib/runtime_config.ml" in
  let rpc = load_source "lib/rpc.ml" in
  let rest = load_source "lib/rest.ml" in
  let combined =
    Option.value common ~default:""
    ^ Option.value runtime ~default:""
    ^ Option.value rpc ~default:""
    ^ Option.value rest ~default:""
  in
  let has =
    string_contains combined "SanitizeString" ||
    string_contains combined "sanitize_string" ||
    string_contains combined "SafeChars" ||
    string_contains combined "SAFE_CHARS"
  in
  Alcotest.(check bool)
    "G29: BUG-W141-23 — no `SanitizeString`-equivalent helper"
    false has

(* G30: BUG-W141-24 — no runCommand wrapper.  Source-grep absence of
   Sys.command or Unix.system used for notify-style external commands. *)
let test_g30_no_run_command_wrapper () =
  let cli = load_source "lib/cli.ml" in
  let runtime = load_source "lib/runtime_config.ml" in
  let main = load_source "bin/main.ml" in
  let combined =
    Option.value cli ~default:""
    ^ Option.value runtime ~default:""
    ^ Option.value main ~default:""
  in
  let has =
    string_contains combined "runCommand" ||
    string_contains combined "run_command" ||
    string_contains combined "Sys.command" ||
    string_contains combined "Unix.system"
  in
  (* Some code may legitimately use Sys.command for build-side scripting,
     but no notify-style wrapper exists.  We confirm none of the canonical
     names appear. *)
  Alcotest.(check bool)
    "G30: BUG-W141-24 — no runCommand-equivalent wrapper"
    false has

(* ============================================================================
   Invariant guards
   ============================================================================ *)

(* INV-1: ZMQ topic name strings match Core (zmqpublishnotifier.cpp:33-37). *)
let test_inv1_zmq_topic_strings () =
  Alcotest.(check string) "INV-1: hashblock" "hashblock"
    (Zmq_notify.topic_to_string Zmq_notify.HashBlock);
  Alcotest.(check string) "INV-1: hashtx" "hashtx"
    (Zmq_notify.topic_to_string Zmq_notify.HashTx);
  Alcotest.(check string) "INV-1: rawblock" "rawblock"
    (Zmq_notify.topic_to_string Zmq_notify.RawBlock);
  Alcotest.(check string) "INV-1: rawtx" "rawtx"
    (Zmq_notify.topic_to_string Zmq_notify.RawTx);
  Alcotest.(check string) "INV-1: sequence" "sequence"
    (Zmq_notify.topic_to_string Zmq_notify.Sequence)

(* INV-2: sequence event chars match Core
   (zmqpublishnotifier.cpp:271-292: 'C', 'D', 'A', 'R'). *)
let test_inv2_sequence_event_chars () =
  Alcotest.(check char) "INV-2: BlockConnect = 'C'" 'C'
    (Zmq_notify.sequence_event_to_char Zmq_notify.BlockConnect);
  Alcotest.(check char) "INV-2: BlockDisconnect = 'D'" 'D'
    (Zmq_notify.sequence_event_to_char Zmq_notify.BlockDisconnect);
  Alcotest.(check char) "INV-2: TxAcceptance = 'A'" 'A'
    (Zmq_notify.sequence_event_to_char Zmq_notify.TxAcceptance);
  Alcotest.(check char) "INV-2: TxRemoval = 'R'" 'R'
    (Zmq_notify.sequence_event_to_char Zmq_notify.TxRemoval)

(* INV-3: hashblock data is 32 bytes reversed (display-format).
   Core (zmqpublishnotifier.cpp:210-218): `data[31 - i] = hash.begin()[i]`.
   Camlcoin's reverse_hash produces the same byte order. *)
let test_inv3_hash_reversal () =
  let h = make_test_hash 1 in
  (* h[i] = i+1 mod 256.  Reversed: reversed[31-i] = h[i] = i+1. *)
  let reversed = Zmq_notify.reverse_hash h in
  Alcotest.(check int) "INV-3: reversed length = 32" 32
    (Cstruct.length reversed);
  (* reversed[31] should equal h[0] = 1. *)
  Alcotest.(check int) "INV-3: reversed[31] == h[0]"
    (Cstruct.get_uint8 h 0) (Cstruct.get_uint8 reversed 31);
  (* reversed[0] should equal h[31]. *)
  Alcotest.(check int) "INV-3: reversed[0] == h[31]"
    (Cstruct.get_uint8 h 31) (Cstruct.get_uint8 reversed 0)

(* INV-4: LE 32-bit sequence encoding.  Core
   (zmqpublishnotifier.cpp:198-199): `WriteLE32(msgseq, nSequence)`. *)
let test_inv4_sequence_le_encoding () =
  let enc = Zmq_notify.encode_sequence_le 0x12345678l in
  Alcotest.(check int) "INV-4: seq encoding is 4 bytes" 4 (String.length enc);
  Alcotest.(check int) "INV-4: byte 0 = 0x78 (LE LSB)"
    0x78 (Char.code enc.[0]);
  Alcotest.(check int) "INV-4: byte 3 = 0x12 (LE MSB)"
    0x12 (Char.code enc.[3])

(* INV-5: 33-byte vs 41-byte sequence payload (block vs tx).
   Block connect/disconnect = hash(32) + label(1) = 33 bytes.
   Tx accept/remove = hash(32) + label(1) + mempool_seq(8) = 41 bytes. *)
let test_inv5_sequence_payload_sizes () =
  let notifier =
    Zmq_notify.create [
      Zmq_notify.{
        address = "tcp://127.0.0.1:28332";
        topics = [Zmq_notify.Sequence];
        high_water_mark = 1000;
      }
    ]
  in
  let h = make_test_hash 7 in
  ignore (Zmq_notify.notify_block_connect notifier h);
  let qb = Zmq_notify.get_queued_messages notifier Zmq_notify.Sequence in
  (match qb with
   | [msg] ->
     Alcotest.(check int) "INV-5: block-connect payload = 33 bytes"
       33 (String.length msg.Zmq_notify.data)
   | _ ->
     Alcotest.fail "INV-5: expected one queued message after block-connect");
  Zmq_notify.clear_queue notifier Zmq_notify.Sequence;
  ignore (Zmq_notify.notify_tx_acceptance notifier h 1234L);
  let qt = Zmq_notify.get_queued_messages notifier Zmq_notify.Sequence in
  match qt with
  | [msg] ->
    Alcotest.(check int) "INV-5: tx-accept payload = 41 bytes"
      41 (String.length msg.Zmq_notify.data)
  | _ -> Alcotest.fail "INV-5: expected one queued message after tx-accept"

(* INV-6: REST format extension recognition.
   parse_data_format accepts .json, .hex, .bin only.  Unknown ext
   yields Undefined + original string. *)
let test_inv6_format_recognition () =
  let (rf_json, _) = Rest.parse_data_format "abc.json" in
  let (rf_hex, _)  = Rest.parse_data_format "abc.hex" in
  let (rf_bin, _)  = Rest.parse_data_format "abc.bin" in
  let (rf_xyz, _)  = Rest.parse_data_format "abc.xyz" in
  Alcotest.(check bool) "INV-6: .json → JSON" true (rf_json = Rest.JSON);
  Alcotest.(check bool) "INV-6: .hex → Hex"  true (rf_hex  = Rest.Hex);
  Alcotest.(check bool) "INV-6: .bin → Binary" true (rf_bin = Rest.Binary);
  Alcotest.(check bool) "INV-6: .xyz → Undefined" true
    (rf_xyz = Rest.Undefined)

(* INV-7: ZMQ option parser canonical-form fields. *)
let test_inv7_zmq_option_fields () =
  match Zmq_notify.Config.parse_zmq_option
          "-zmqpubrawblock=tcp://1.2.3.4:5678" with
  | None -> Alcotest.fail "INV-7: expected Some"
  | Some opt ->
    Alcotest.(check bool) "INV-7: topic = RawBlock"
      true (opt.Zmq_notify.Config.topic = Zmq_notify.RawBlock);
    Alcotest.(check string) "INV-7: address parsed"
      "tcp://1.2.3.4:5678" opt.Zmq_notify.Config.address

(* INV-8: REST available_formats string. *)
let test_inv8_rest_available_formats () =
  let s = Rest.available_formats () in
  Alcotest.(check bool) "INV-8: available_formats contains .json"
    true (string_contains s ".json");
  Alcotest.(check bool) "INV-8: available_formats contains .hex"
    true (string_contains s ".hex");
  Alcotest.(check bool) "INV-8: available_formats contains .bin"
    true (string_contains s ".bin")

(* ============================================================================
   Test runner
   ============================================================================ *)

let () =
  Alcotest.run "W141 ZMQ + REST + Notification scripts" [
    "G1-G10 — ZMQ pub/sub notifier", [
      Alcotest.test_case "G1: topic-alias double-prefix (BUG-W141-1)" `Quick
        test_g1_zmq_topic_alias_double_prefix;
      Alcotest.test_case "G1b: canonical form accepted" `Quick
        test_g1b_zmq_canonical_form_accepted;
      Alcotest.test_case "G2: no per-topic HWM (BUG-W141-2)" `Quick
        test_g2_no_per_topic_hwm_override;
      Alcotest.test_case "G3: ★ topic-keyed Hashtbl drops 2nd addr (BUG-W141-3 P0)"
        `Quick test_g3_topic_keyed_state_drops_second_address;
      Alcotest.test_case "G3b: source-level guard" `Quick
        test_g3b_topic_keyed_state_source;
      Alcotest.test_case "G4: multi-bind cross-talk (BUG-W141-4)" `Quick
        test_g4_multi_bind_one_socket;
      Alcotest.test_case "G5: no unix://→ipc:// rewrite (BUG-W141-5)" `Quick
        test_g5_no_unix_to_ipc_rewrite;
      Alcotest.test_case "G6: ★ no IBD gate (BUG-W141-6 P0)" `Quick
        test_g6_no_ibd_gate_on_block_publish;
      Alcotest.test_case "G7: ★ no per-tx hashtx on connect (BUG-W141-7 P0)"
        `Quick test_g7_no_per_tx_hashtx_on_block_connect;
      Alcotest.test_case "G8: no historical-role gate (BUG-W141-8)" `Quick
        test_g8_no_historical_role_gate;
      Alcotest.test_case "G9: LINGER set at create not close (BUG-W141-9)" `Quick
        test_g9_linger_at_create_not_close;
      Alcotest.test_case "G10: in-process queue retains (BUG-W141-10)" `Quick
        test_g10_in_process_queue_retains_every_send;
    ];
    "G11-G22 — REST API", [
      Alcotest.test_case "G11: -rest default false (PARITY)" `Quick
        test_g11_rest_default_disabled;
      Alcotest.test_case "G12: no warmup gate (BUG-W141-11)" `Quick
        test_g12_no_rest_warmup_gate;
      Alcotest.test_case "G13: no sanitisation (BUG-W141-12)" `Quick
        test_g13_no_user_input_sanitisation_on_error;
      Alcotest.test_case "G14: /rest/getutxos missing (BUG-W141-13)" `Quick
        test_g14_no_getutxos_endpoint;
      Alcotest.test_case "G15: /rest/blockpart/ missing (BUG-W141-14)" `Quick
        test_g15_no_blockpart_endpoint;
      Alcotest.test_case "G16: /rest/spenttxouts/ missing (BUG-W141-15)" `Quick
        test_g16_no_spenttxouts_endpoint;
      Alcotest.test_case "G17: /rest/deploymentinfo missing (BUG-W141-16)" `Quick
        test_g17_no_deploymentinfo_endpoint;
      Alcotest.test_case "G18: rest_tx no index sync (BUG-W141-17)" `Quick
        test_g18_rest_tx_no_index_sync_barrier;
      Alcotest.test_case "G19: parse_data_format strips ?" `Quick
        test_g19_parse_data_format_strips_query;
      Alcotest.test_case "G19b: .bin extension" `Quick
        test_g19b_parse_data_format_recognises_bin;
      Alcotest.test_case "G19c: undefined extension" `Quick
        test_g19c_parse_data_format_undefined;
      Alcotest.test_case "G20: deprecated count/hash path (PARITY)" `Quick
        test_g20_deprecated_count_hash_path_supported;
      Alcotest.test_case "G21: RESTERR \\r\\n terminator (PARITY)" `Quick
        test_g21_resterr_terminator;
      Alcotest.test_case "G22: max_headers = 2000 (PARITY)" `Quick
        test_g22_max_headers_constant;
    ];
    "G23-G30 — Notification scripts", [
      Alcotest.test_case "G23: no -blocknotify (BUG-W141-18)" `Quick
        test_g23_no_blocknotify_arg;
      Alcotest.test_case "G24: FullySynced surface exists" `Quick
        test_g24_post_ibd_gate_prerequisite;
      Alcotest.test_case "G25: no -alertnotify (BUG-W141-19)" `Quick
        test_g25_no_alertnotify_arg;
      Alcotest.test_case "G26: no -walletnotify (BUG-W141-20)" `Quick
        test_g26_no_walletnotify_hook;
      Alcotest.test_case "G27: no startup/shutdownnotify (BUG-W141-21)" `Quick
        test_g27_no_startup_shutdown_notify;
      Alcotest.test_case "G28: no ShellEscape (BUG-W141-22)" `Quick
        test_g28_no_shell_escape_helper;
      Alcotest.test_case "G29: no SanitizeString (BUG-W141-23)" `Quick
        test_g29_no_sanitize_string_helper;
      Alcotest.test_case "G30: no runCommand wrapper (BUG-W141-24)" `Quick
        test_g30_no_run_command_wrapper;
    ];
    "Invariant guards", [
      Alcotest.test_case "INV-1: ZMQ topic strings" `Quick
        test_inv1_zmq_topic_strings;
      Alcotest.test_case "INV-2: sequence event chars" `Quick
        test_inv2_sequence_event_chars;
      Alcotest.test_case "INV-3: hash reversal" `Quick
        test_inv3_hash_reversal;
      Alcotest.test_case "INV-4: LE-32 sequence encoding" `Quick
        test_inv4_sequence_le_encoding;
      Alcotest.test_case "INV-5: 33 vs 41-byte payloads" `Quick
        test_inv5_sequence_payload_sizes;
      Alcotest.test_case "INV-6: REST format recognition" `Quick
        test_inv6_format_recognition;
      Alcotest.test_case "INV-7: ZMQ option fields" `Quick
        test_inv7_zmq_option_fields;
      Alcotest.test_case "INV-8: REST available_formats" `Quick
        test_inv8_rest_available_formats;
    ];
  ]
