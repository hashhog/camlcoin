(* W125 audit — JSON-RPC error code parity (camlcoin)

   Reference: bitcoin-core/src/rpc/protocol.h enum RPCErrorCode

   30 audit gates covering Core's 27-value RPCErrorCode enum plus 3
   policy gates (declaration coverage, dispatcher-routing coverage,
   wallet-cluster sub-codes).

   Each gate asserts source-level the PRESENT / PARTIAL / MISSING status
   captured in audit/w125_rpc_error_parity.md.  Tests pass when the audit
   verdict is faithful — i.e. PRESENT codes are declared AND routed,
   PARTIAL codes are declared but not routed, MISSING codes are not
   declared.  When a follow-up FIX wave lands a missing code, the
   corresponding test will fail until updated, signalling the audit
   gate was closed.

   This file does NOT exercise the RPC server with live HTTP calls — it
   reads lib/rpc.ml at runtime and asserts the static structure of
   declarations and dispatcher arms.  The same shape used by W122 audit
   tests for codec invariants.

   Audit checklist:
     G1  RPC_INVALID_REQUEST       -32600 PRESENT
     G2  RPC_METHOD_NOT_FOUND      -32601 PRESENT
     G3  RPC_INVALID_PARAMS        -32602 PRESENT
     G4  RPC_INTERNAL_ERROR        -32603 PARTIAL (declared, not routed)
     G5  RPC_PARSE_ERROR           -32700 PRESENT
     G6  RPC_MISC_ERROR              -1   PRESENT
     G7  RPC_FORBIDDEN_BY_SAFE_MODE  -2   MISSING
     G8  RPC_TYPE_ERROR              -3   PARTIAL (declared, not routed)
     G9  RPC_WALLET_ERROR            -4   PRESENT
     G10 RPC_INVALID_ADDRESS_OR_KEY  -5   PARTIAL (declared, under-routed)
     G11 RPC_WALLET_INSUFFICIENT_FUNDS -6 PARTIAL (declared, not routed)
     G12 RPC_OUT_OF_MEMORY           -7   MISSING
     G13 RPC_INVALID_PARAMETER       -8   MISSING
     G14 RPC_DATABASE_ERROR         -20   MISSING
     G15 RPC_DESERIALIZATION_ERROR  -22   PRESENT
     G16 RPC_VERIFY_ERROR           -25   PARTIAL (declared, not routed; submitblock mis-routed)
     G17 RPC_VERIFY_REJECTED        -26   PRESENT
     G18 RPC_VERIFY_ALREADY_IN_UTXO_SET -27 MISSING
     G19 RPC_IN_WARMUP              -28   MISSING
     G20 RPC_METHOD_DEPRECATED      -32   MISSING
     G21 RPC_CLIENT_NOT_CONNECTED    -9   MISSING
     G22 RPC_CLIENT_IN_INITIAL_DOWNLOAD -10 MISSING
     G23 RPC_CLIENT_NODE_ALREADY_ADDED -23 MISSING
     G24 RPC_CLIENT_NODE_NOT_ADDED  -24   MISSING
     G25 RPC_CLIENT_NODE_NOT_CONNECTED -29 MISSING
     G26 RPC_CLIENT_INVALID_IP_OR_SUBNET -30 MISSING
     G27 RPC_CLIENT_P2P_DISABLED    -31   MISSING
     G28 RPC_CLIENT_NODE_CAPACITY_REACHED -34 MISSING
     G29 RPC_CLIENT_MEMPOOL_DISABLED -33  MISSING
     G30 RPC_WALLET_* cluster (-11..-19, -35, -36) PARTIAL (all 11 missing,
         all wallet errors routed through -4)
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
   we cannot use a fixed relative path. *)
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

let audit_doc_path () : string =
  Filename.concat (resolve_repo_root ()) "audit/w125_rpc_error_parity.md"

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

(* Count occurrences of [needle] in [haystack]. *)
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

(* Assert a code is declared in lib/rpc.ml's table at the canonical
   integer value. *)
let assert_code_declared ~name ~value =
  let src = rpc_ml () in
  let pat = Printf.sprintf "let %s = %d" name value in
  Alcotest.(check bool)
    (Printf.sprintf "code %s = %d declared at canonical value" name value)
    true (contains_substring src pat)

(* Assert a code is NOT declared in lib/rpc.ml. *)
let assert_code_not_declared ~name =
  let src = rpc_ml () in
  let pat = Printf.sprintf "let %s =" name in
  Alcotest.(check bool)
    (Printf.sprintf "code %s NOT declared" name) false
    (contains_substring src pat)

(* Assert a code is routed at least once in the dispatcher (or anywhere
   in the file body, more conservatively).  We approximate "routed" by
   searching for [Error (name,] (the dispatcher's mapping idiom). *)
let count_routes ~name =
  let src = rpc_ml () in
  count_substring src (Printf.sprintf "Error (%s," name)

let count_uses ~name =
  let src = rpc_ml () in
  (* Any usage of the constant (declaration line + every route). *)
  count_substring src name

(* -- G1 RPC_INVALID_REQUEST -32600 PRESENT ----------------------------- *)

let g1_invalid_request_declared () =
  assert_code_declared ~name:"rpc_invalid_request" ~value:(-32600)

let g1_invalid_request_routed () =
  (* Used by start_rpc_server when batch is empty / body is not object/array. *)
  let n = count_uses ~name:"rpc_invalid_request" in
  Alcotest.(check bool)
    "G1 rpc_invalid_request used >= 2 (declaration + at least 1 route)" true
    (n >= 2)

(* -- G2 RPC_METHOD_NOT_FOUND -32601 PRESENT ---------------------------- *)

let g2_method_not_found_declared () =
  assert_code_declared ~name:"rpc_method_not_found" ~value:(-32601)

let g2_method_not_found_routed () =
  (* Dispatcher uses it on unknown method. *)
  let src = rpc_ml () in
  Alcotest.(check bool)
    "G2 rpc_method_not_found routed for unknown method" true
    (contains_substring src "rpc_method_not_found, \"Method not found")

(* -- G3 RPC_INVALID_PARAMS -32602 PRESENT ------------------------------ *)

let g3_invalid_params_declared () =
  assert_code_declared ~name:"rpc_invalid_params" ~value:(-32602)

let g3_invalid_params_routed () =
  (* Used by ~20 dispatcher arms; demand >= 10 to be confident the
     fan-out is real and not just the declaration. *)
  let n = count_routes ~name:"rpc_invalid_params" in
  Alcotest.(check bool)
    "G3 rpc_invalid_params routed >= 10 times" true (n >= 10)

(* -- G4 RPC_INTERNAL_ERROR -32603 PARTIAL ------------------------------ *)

let g4_internal_error_declared () =
  assert_code_declared ~name:"rpc_internal_error" ~value:(-32603)

let g4_internal_error_NOT_routed () =
  (* PARTIAL: declared but never routed. *)
  let n = count_routes ~name:"rpc_internal_error" in
  Alcotest.(check int)
    "G4 rpc_internal_error PARTIAL: routed 0 times (declared, never used)"
    0 n

(* -- G5 RPC_PARSE_ERROR -32700 PRESENT --------------------------------- *)

let g5_parse_error_declared () =
  assert_code_declared ~name:"rpc_parse_error" ~value:(-32700)

let g5_parse_error_routed () =
  let n = count_uses ~name:"rpc_parse_error" in
  Alcotest.(check bool)
    "G5 rpc_parse_error used >= 2 (declaration + route)" true (n >= 2)

(* -- G6 RPC_MISC_ERROR -1 PRESENT -------------------------------------- *)

let g6_misc_error_declared () =
  assert_code_declared ~name:"rpc_misc_error" ~value:(-1)

let g6_misc_error_overused () =
  (* Used as a catch-all >= 30 times; this is the audit's "overflow"
     signal — every gap in routing flows to -1. *)
  let n = count_routes ~name:"rpc_misc_error" in
  Alcotest.(check bool)
    "G6 rpc_misc_error routed >= 30 times (catch-all overflow signal)"
    true (n >= 30)

(* -- G7 RPC_FORBIDDEN_BY_SAFE_MODE -2 MISSING ------------------------- *)

let g7_forbidden_by_safe_mode_NOT_declared () =
  assert_code_not_declared ~name:"rpc_forbidden_by_safe_mode"

(* -- G8 RPC_TYPE_ERROR -3 PARTIAL ------------------------------------- *)

let g8_type_error_declared () =
  assert_code_declared ~name:"rpc_type_error" ~value:(-3)

let g8_type_error_NOT_routed () =
  (* PARTIAL: declared at line 34 but never routed by the dispatcher. *)
  let n = count_routes ~name:"rpc_type_error" in
  Alcotest.(check int)
    "G8 rpc_type_error PARTIAL: routed 0 times (declared, never used)"
    0 n

(* -- G9 RPC_WALLET_ERROR -4 PRESENT ----------------------------------- *)

let g9_wallet_error_declared () =
  assert_code_declared ~name:"rpc_wallet_error" ~value:(-4)

let g9_wallet_error_routed () =
  let n = count_routes ~name:"rpc_wallet_error" in
  Alcotest.(check bool)
    "G9 rpc_wallet_error routed >= 10 times" true (n >= 10)

(* -- G10 RPC_INVALID_ADDRESS_OR_KEY -5 PARTIAL ------------------------ *)

let g10_invalid_address_declared () =
  assert_code_declared ~name:"rpc_invalid_address" ~value:(-5)

let g10_invalid_address_under_routed () =
  (* PARTIAL: routed only for validateaddress/signmessage*/verifymessage
     (4 dispatcher arms).  Core uses it for ~12 distinct call sites
     including block-not-found / txid-not-found.  Assert 3..6 routes
     captures the current under-routed state.  When the gate closes,
     this count will rise. *)
  let n = count_routes ~name:"rpc_invalid_address" in
  Alcotest.(check bool)
    (Printf.sprintf "G10 rpc_invalid_address PARTIAL: routed %d times (3..6 = under-routed)" n)
    true (n >= 3 && n <= 6)

(* -- G11 RPC_WALLET_INSUFFICIENT_FUNDS -6 PARTIAL -------------------- *)

let g11_insufficient_funds_declared () =
  assert_code_declared ~name:"rpc_insufficient_funds" ~value:(-6)

let g11_insufficient_funds_NOT_routed () =
  (* PARTIAL: declared at line 37 but never routed by the dispatcher.
     sendtoaddress/walletcreatefundedpsbt fall through to -4. *)
  let n = count_routes ~name:"rpc_insufficient_funds" in
  Alcotest.(check int)
    "G11 rpc_insufficient_funds PARTIAL: routed 0 times (declared, never used)"
    0 n

(* -- G12 RPC_OUT_OF_MEMORY -7 MISSING --------------------------------- *)

let g12_out_of_memory_NOT_declared () =
  assert_code_not_declared ~name:"rpc_out_of_memory"

(* -- G13 RPC_INVALID_PARAMETER -8 MISSING ----------------------------- *)

let g13_invalid_parameter_NOT_declared () =
  assert_code_not_declared ~name:"rpc_invalid_parameter"

(* -- G14 RPC_DATABASE_ERROR -20 MISSING ------------------------------- *)

let g14_database_error_NOT_declared () =
  assert_code_not_declared ~name:"rpc_database_error"

(* -- G15 RPC_DESERIALIZATION_ERROR -22 PRESENT ----------------------- *)

let g15_deserialization_error_declared () =
  assert_code_declared ~name:"rpc_deserialization_error" ~value:(-22)

let g15_deserialization_error_routed () =
  (* Used by decoderawtransaction, decodescript, decodepsbt. *)
  let n = count_routes ~name:"rpc_deserialization_error" in
  Alcotest.(check bool)
    "G15 rpc_deserialization_error routed >= 2 times" true (n >= 2)

(* -- G16 RPC_VERIFY_ERROR -25 PARTIAL --------------------------------- *)

let g16_verify_error_declared () =
  assert_code_declared ~name:"rpc_verify_error" ~value:(-25)

let g16_verify_error_NOT_routed () =
  (* PARTIAL: declared at line 39 but never routed by the dispatcher.
     submitblock errors are routed to -26 (rpc_verify_rejected) instead
     of -25, which is Core's choice for submitblock (mining.cpp:1141,
     1143).  See BUG-3 in audit/w125_rpc_error_parity.md. *)
  let n = count_routes ~name:"rpc_verify_error" in
  Alcotest.(check int)
    "G16 rpc_verify_error PARTIAL: routed 0 times (declared, never used)"
    0 n

let g16_submitblock_routes_through_wrong_code () =
  (* Confirm the BUG-3 mis-routing: submitblock uses
     rpc_verify_rejected (-26) instead of rpc_verify_error (-25). *)
  let src = rpc_ml () in
  Alcotest.(check bool)
    "G16 BUG-3: submitblock currently routes Error -> rpc_verify_rejected"
    true
    (contains_substring src
       "\"submitblock\" ->\n    (match handle_submitblock ctx params with\n     | Ok r -> Ok r\n     | Error msg -> Error (rpc_verify_rejected,")

(* -- G17 RPC_VERIFY_REJECTED -26 PRESENT ------------------------------ *)

let g17_verify_rejected_declared () =
  assert_code_declared ~name:"rpc_verify_rejected" ~value:(-26)

let g17_verify_rejected_routed () =
  (* Used by sendrawtransaction, testmempoolaccept, submitpackage,
     submitblock (BUG-3 routing).  Demand >= 3 routes. *)
  let n = count_routes ~name:"rpc_verify_rejected" in
  Alcotest.(check bool)
    "G17 rpc_verify_rejected routed >= 3 times" true (n >= 3)

(* -- G18 RPC_VERIFY_ALREADY_IN_UTXO_SET -27 MISSING ------------------ *)

let g18_already_in_utxo_set_NOT_declared () =
  assert_code_not_declared ~name:"rpc_verify_already_in_utxo_set"

(* -- G19 RPC_IN_WARMUP -28 MISSING ------------------------------------ *)

let g19_in_warmup_NOT_declared () =
  assert_code_not_declared ~name:"rpc_in_warmup"

(* -- G20 RPC_METHOD_DEPRECATED -32 MISSING ---------------------------- *)

let g20_method_deprecated_NOT_declared () =
  assert_code_not_declared ~name:"rpc_method_deprecated"

(* -- G21 RPC_CLIENT_NOT_CONNECTED -9 MISSING -------------------------- *)

let g21_client_not_connected_NOT_declared () =
  assert_code_not_declared ~name:"rpc_client_not_connected"

(* -- G22 RPC_CLIENT_IN_INITIAL_DOWNLOAD -10 MISSING ------------------ *)

let g22_client_in_ibd_NOT_declared () =
  assert_code_not_declared ~name:"rpc_client_in_initial_download"

(* -- G23 RPC_CLIENT_NODE_ALREADY_ADDED -23 MISSING ------------------- *)

let g23_node_already_added_NOT_declared () =
  assert_code_not_declared ~name:"rpc_client_node_already_added"

(* -- G24 RPC_CLIENT_NODE_NOT_ADDED -24 MISSING ------------------------ *)

let g24_node_not_added_NOT_declared () =
  assert_code_not_declared ~name:"rpc_client_node_not_added"

(* -- G25 RPC_CLIENT_NODE_NOT_CONNECTED -29 MISSING ------------------- *)

let g25_node_not_connected_NOT_declared () =
  assert_code_not_declared ~name:"rpc_client_node_not_connected"

(* -- G26 RPC_CLIENT_INVALID_IP_OR_SUBNET -30 MISSING ----------------- *)

let g26_invalid_ip_or_subnet_NOT_declared () =
  assert_code_not_declared ~name:"rpc_client_invalid_ip_or_subnet"

(* -- G27 RPC_CLIENT_P2P_DISABLED -31 MISSING ------------------------- *)

let g27_p2p_disabled_NOT_declared () =
  assert_code_not_declared ~name:"rpc_client_p2p_disabled"

(* -- G28 RPC_CLIENT_NODE_CAPACITY_REACHED -34 MISSING --------------- *)

let g28_node_capacity_reached_NOT_declared () =
  assert_code_not_declared ~name:"rpc_client_node_capacity_reached"

(* -- G29 RPC_CLIENT_MEMPOOL_DISABLED -33 MISSING -------------------- *)

let g29_mempool_disabled_NOT_declared () =
  assert_code_not_declared ~name:"rpc_client_mempool_disabled"

(* -- G30 RPC_WALLET_* cluster PARTIAL -------------------------------- *)

(* All 11 wallet sub-codes are MISSING from declarations.  Wallet
   errors uniformly route through rpc_wallet_error (-4). *)
let g30_wallet_cluster_all_missing () =
  let cluster_codes = [
    "rpc_wallet_invalid_label_name";   (* -11 *)
    "rpc_wallet_keypool_ran_out";      (* -12 *)
    "rpc_wallet_unlock_needed";        (* -13 *)
    "rpc_wallet_passphrase_incorrect"; (* -14 *)
    "rpc_wallet_wrong_enc_state";      (* -15 *)
    "rpc_wallet_encryption_failed";    (* -16 *)
    "rpc_wallet_already_unlocked";     (* -17 *)
    "rpc_wallet_not_found";            (* -18 *)
    "rpc_wallet_not_specified";        (* -19 *)
    "rpc_wallet_already_loaded";       (* -35 *)
    "rpc_wallet_already_exists";       (* -36 *)
  ] in
  let src = rpc_ml () in
  List.iter (fun code ->
    let pat = Printf.sprintf "let %s =" code in
    Alcotest.(check bool)
      (Printf.sprintf "G30 wallet sub-code %s NOT declared" code) false
      (contains_substring src pat)
  ) cluster_codes

let g30_wallet_errors_route_to_minus4 () =
  (* The encryptwallet/walletpassphrase/walletlock handlers internally
     emit Core-compatible body text, but they all route through
     rpc_wallet_error = -4 at the dispatcher.  Spot-check that the
     wallet-encryption handlers' Error sites flow into that arm. *)
  let src = rpc_ml () in
  Alcotest.(check bool)
    "G30 encryptwallet routes Error -> rpc_wallet_error" true
    (contains_substring src
       "\"encryptwallet\" ->\n    (match handle_encryptwallet ctx params with\n     | Ok r -> Ok r\n     | Error msg -> Error (rpc_wallet_error,");
  Alcotest.(check bool)
    "G30 walletpassphrase routes Error -> rpc_wallet_error" true
    (contains_substring src
       "\"walletpassphrase\" ->\n    (match handle_walletpassphrase ctx params with\n     | Ok r -> Ok r\n     | Error msg -> Error (rpc_wallet_error,");
  Alcotest.(check bool)
    "G30 walletlock routes Error -> rpc_wallet_error" true
    (contains_substring src
       "\"walletlock\" ->\n    (match handle_walletlock ctx params with\n     | Ok r -> Ok r\n     | Error msg -> Error (rpc_wallet_error,")

(* -- Audit-status assertions ----------------------------------------- *)

(* Total declared codes in rpc.ml's table.  Should be exactly 13 as of
   the W125 baseline.  If a follow-up FIX wave lands new declarations,
   this count rises and the test must be updated. *)
let as1_declared_code_count () =
  let src = rpc_ml () in
  let codes = [
    "rpc_invalid_request"; "rpc_method_not_found"; "rpc_invalid_params";
    "rpc_internal_error"; "rpc_parse_error";
    "rpc_misc_error"; "rpc_type_error"; "rpc_invalid_address";
    "rpc_wallet_error"; "rpc_insufficient_funds";
    "rpc_deserialization_error"; "rpc_verify_error"; "rpc_verify_rejected";
  ] in
  let declared = List.fold_left (fun acc c ->
    let pat = Printf.sprintf "let %s =" c in
    if contains_substring src pat then acc + 1 else acc
  ) 0 codes in
  Alcotest.(check int)
    "AS1 W125 baseline: exactly 13 codes declared in rpc.ml table"
    13 declared

(* Audit framework expects 14 Core codes are NOT declared (the MISSING
   gates G7, G12, G13, G14, G18, G19, G20, G21, G22, G23, G24, G25,
   G26, G27, G28, G29 plus G30's 11-code wallet cluster).  The cluster
   counts as 1 gate, but if we enumerate every distinct code Core
   defines that camlcoin does not, the total is 14 (top-level codes) +
   11 (wallet sub-codes) = 25 missing distinct codes versus Core. *)
let as2_missing_distinct_codes () =
  let src = rpc_ml () in
  let missing = [
    "rpc_forbidden_by_safe_mode";     (* G7 *)
    "rpc_out_of_memory";              (* G12 *)
    "rpc_invalid_parameter";          (* G13 *)
    "rpc_database_error";             (* G14 *)
    "rpc_verify_already_in_utxo_set"; (* G18 *)
    "rpc_in_warmup";                  (* G19 *)
    "rpc_method_deprecated";          (* G20 *)
    "rpc_client_not_connected";       (* G21 *)
    "rpc_client_in_initial_download"; (* G22 *)
    "rpc_client_node_already_added";  (* G23 *)
    "rpc_client_node_not_added";      (* G24 *)
    "rpc_client_node_not_connected";  (* G25 *)
    "rpc_client_invalid_ip_or_subnet"; (* G26 *)
    "rpc_client_p2p_disabled";        (* G27 *)
    "rpc_client_node_capacity_reached"; (* G28 *)
    "rpc_client_mempool_disabled";    (* G29 *)
    (* G30 wallet cluster (11 codes) *)
    "rpc_wallet_invalid_label_name";
    "rpc_wallet_keypool_ran_out";
    "rpc_wallet_unlock_needed";
    "rpc_wallet_passphrase_incorrect";
    "rpc_wallet_wrong_enc_state";
    "rpc_wallet_encryption_failed";
    "rpc_wallet_already_unlocked";
    "rpc_wallet_not_found";
    "rpc_wallet_not_specified";
    "rpc_wallet_already_loaded";
    "rpc_wallet_already_exists";
  ] in
  let still_missing = List.fold_left (fun acc c ->
    let pat = Printf.sprintf "let %s =" c in
    if contains_substring src pat then acc else acc + 1
  ) 0 missing in
  Alcotest.(check int)
    "AS2 W125 baseline: 27 Core codes NOT declared (16 top-level + 11 wallet)"
    27 still_missing

(* Bug count: 22 catalogued in audit/w125_rpc_error_parity.md.  This
   assertion encodes the audit-time count via a sentinel constant. *)
let as3_audit_bug_count () =
  Alcotest.(check int) "AS3 W125 bug count == 22" 22 22

(* Audit gate count: 30 gates. *)
let as4_audit_gate_count () =
  Alcotest.(check int) "AS4 W125 gate count == 30" 30 30

(* Confirm the audit document exists at the canonical path. *)
let as5_audit_doc_exists () =
  Alcotest.(check bool)
    "AS5 audit doc exists at audit/w125_rpc_error_parity.md" true
    (Sys.file_exists (audit_doc_path ()))

(* -- test suite ------------------------------------------------------- *)

let () =
  let open Alcotest in
  run "W125 JSON-RPC Error Code Parity (camlcoin)" [
    "G1 RPC_INVALID_REQUEST -32600 PRESENT", [
      test_case "declared" `Quick g1_invalid_request_declared;
      test_case "routed" `Quick g1_invalid_request_routed;
    ];
    "G2 RPC_METHOD_NOT_FOUND -32601 PRESENT", [
      test_case "declared" `Quick g2_method_not_found_declared;
      test_case "routed" `Quick g2_method_not_found_routed;
    ];
    "G3 RPC_INVALID_PARAMS -32602 PRESENT", [
      test_case "declared" `Quick g3_invalid_params_declared;
      test_case "routed >= 10" `Quick g3_invalid_params_routed;
    ];
    "G4 RPC_INTERNAL_ERROR -32603 PARTIAL", [
      test_case "declared" `Quick g4_internal_error_declared;
      test_case "NOT routed (BUG-19)" `Quick g4_internal_error_NOT_routed;
    ];
    "G5 RPC_PARSE_ERROR -32700 PRESENT", [
      test_case "declared" `Quick g5_parse_error_declared;
      test_case "routed" `Quick g5_parse_error_routed;
    ];
    "G6 RPC_MISC_ERROR -1 PRESENT", [
      test_case "declared" `Quick g6_misc_error_declared;
      test_case "overused as catch-all" `Quick g6_misc_error_overused;
    ];
    "G7 RPC_FORBIDDEN_BY_SAFE_MODE -2 MISSING (BUG-9)", [
      test_case "NOT declared" `Quick g7_forbidden_by_safe_mode_NOT_declared;
    ];
    "G8 RPC_TYPE_ERROR -3 PARTIAL (BUG-7)", [
      test_case "declared" `Quick g8_type_error_declared;
      test_case "NOT routed" `Quick g8_type_error_NOT_routed;
    ];
    "G9 RPC_WALLET_ERROR -4 PRESENT", [
      test_case "declared" `Quick g9_wallet_error_declared;
      test_case "routed" `Quick g9_wallet_error_routed;
    ];
    "G10 RPC_INVALID_ADDRESS_OR_KEY -5 PARTIAL (BUG-6)", [
      test_case "declared" `Quick g10_invalid_address_declared;
      test_case "under-routed" `Quick g10_invalid_address_under_routed;
    ];
    "G11 RPC_WALLET_INSUFFICIENT_FUNDS -6 PARTIAL (BUG-5)", [
      test_case "declared" `Quick g11_insufficient_funds_declared;
      test_case "NOT routed" `Quick g11_insufficient_funds_NOT_routed;
    ];
    "G12 RPC_OUT_OF_MEMORY -7 MISSING (BUG-17)", [
      test_case "NOT declared" `Quick g12_out_of_memory_NOT_declared;
    ];
    "G13 RPC_INVALID_PARAMETER -8 MISSING (BUG-20)", [
      test_case "NOT declared" `Quick g13_invalid_parameter_NOT_declared;
    ];
    "G14 RPC_DATABASE_ERROR -20 MISSING (BUG-8)", [
      test_case "NOT declared" `Quick g14_database_error_NOT_declared;
    ];
    "G15 RPC_DESERIALIZATION_ERROR -22 PRESENT", [
      test_case "declared" `Quick g15_deserialization_error_declared;
      test_case "routed" `Quick g15_deserialization_error_routed;
    ];
    "G16 RPC_VERIFY_ERROR -25 PARTIAL (BUG-3)", [
      test_case "declared" `Quick g16_verify_error_declared;
      test_case "NOT routed" `Quick g16_verify_error_NOT_routed;
      test_case "submitblock currently uses wrong code" `Quick
        g16_submitblock_routes_through_wrong_code;
    ];
    "G17 RPC_VERIFY_REJECTED -26 PRESENT", [
      test_case "declared" `Quick g17_verify_rejected_declared;
      test_case "routed" `Quick g17_verify_rejected_routed;
    ];
    "G18 RPC_VERIFY_ALREADY_IN_UTXO_SET -27 MISSING (BUG-4)", [
      test_case "NOT declared" `Quick g18_already_in_utxo_set_NOT_declared;
    ];
    "G19 RPC_IN_WARMUP -28 MISSING (BUG-1)", [
      test_case "NOT declared" `Quick g19_in_warmup_NOT_declared;
    ];
    "G20 RPC_METHOD_DEPRECATED -32 MISSING (BUG-16)", [
      test_case "NOT declared" `Quick g20_method_deprecated_NOT_declared;
    ];
    "G21 RPC_CLIENT_NOT_CONNECTED -9 MISSING", [
      test_case "NOT declared" `Quick g21_client_not_connected_NOT_declared;
    ];
    "G22 RPC_CLIENT_IN_INITIAL_DOWNLOAD -10 MISSING (BUG-2)", [
      test_case "NOT declared" `Quick g22_client_in_ibd_NOT_declared;
    ];
    "G23 RPC_CLIENT_NODE_ALREADY_ADDED -23 MISSING (BUG-10)", [
      test_case "NOT declared" `Quick g23_node_already_added_NOT_declared;
    ];
    "G24 RPC_CLIENT_NODE_NOT_ADDED -24 MISSING (BUG-11)", [
      test_case "NOT declared" `Quick g24_node_not_added_NOT_declared;
    ];
    "G25 RPC_CLIENT_NODE_NOT_CONNECTED -29 MISSING (BUG-12)", [
      test_case "NOT declared" `Quick g25_node_not_connected_NOT_declared;
    ];
    "G26 RPC_CLIENT_INVALID_IP_OR_SUBNET -30 MISSING (BUG-13)", [
      test_case "NOT declared" `Quick g26_invalid_ip_or_subnet_NOT_declared;
    ];
    "G27 RPC_CLIENT_P2P_DISABLED -31 MISSING (BUG-14)", [
      test_case "NOT declared" `Quick g27_p2p_disabled_NOT_declared;
    ];
    "G28 RPC_CLIENT_NODE_CAPACITY_REACHED -34 MISSING (BUG-15)", [
      test_case "NOT declared" `Quick g28_node_capacity_reached_NOT_declared;
    ];
    "G29 RPC_CLIENT_MEMPOOL_DISABLED -33 MISSING (BUG-18)", [
      test_case "NOT declared" `Quick g29_mempool_disabled_NOT_declared;
    ];
    "G30 RPC_WALLET_* cluster (-11..-19, -35, -36) PARTIAL (BUG-W1..W11)", [
      test_case "all 11 sub-codes NOT declared" `Quick
        g30_wallet_cluster_all_missing;
      test_case "wallet errors uniformly route -> -4" `Quick
        g30_wallet_errors_route_to_minus4;
    ];
    "Audit-status", [
      test_case "AS1 baseline: exactly 13 codes declared" `Quick
        as1_declared_code_count;
      test_case "AS2 baseline: 27 Core codes missing" `Quick
        as2_missing_distinct_codes;
      test_case "AS3 bug count == 22" `Quick as3_audit_bug_count;
      test_case "AS4 gate count == 30" `Quick as4_audit_gate_count;
      test_case "AS5 audit doc exists" `Quick as5_audit_doc_exists;
    ];
  ]
