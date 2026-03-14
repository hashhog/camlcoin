(* Tests for REST API module *)

open Camlcoin

(* Test directory that gets cleaned up *)
let test_db_path = "/tmp/camlcoin_test_rest_db"

let cleanup_test_db () =
  let rec rm_rf path =
    if Sys.file_exists path then begin
      if Sys.is_directory path then begin
        Array.iter (fun f -> rm_rf (Filename.concat path f)) (Sys.readdir path);
        Unix.rmdir path
      end else
        Unix.unlink path
    end
  in
  rm_rf test_db_path

(* ============================================================================
   Format Parsing Tests
   ============================================================================ *)

let test_parse_json_format () =
  let rf, param = Rest.parse_data_format "abc123def.json" in
  Alcotest.(check bool) "JSON format" true (rf = Rest.JSON);
  Alcotest.(check string) "param without ext" "abc123def" param

let test_parse_hex_format () =
  let rf, param = Rest.parse_data_format "abc123def.hex" in
  Alcotest.(check bool) "Hex format" true (rf = Rest.Hex);
  Alcotest.(check string) "param without ext" "abc123def" param

let test_parse_binary_format () =
  let rf, param = Rest.parse_data_format "abc123def.bin" in
  Alcotest.(check bool) "Binary format" true (rf = Rest.Binary);
  Alcotest.(check string) "param without ext" "abc123def" param

let test_parse_undefined_format () =
  let rf, param = Rest.parse_data_format "abc123def" in
  Alcotest.(check bool) "Undefined format" true (rf = Rest.Undefined);
  Alcotest.(check string) "param unchanged" "abc123def" param

let test_parse_unknown_format () =
  let rf, param = Rest.parse_data_format "abc123def.xml" in
  Alcotest.(check bool) "Unknown format -> Undefined" true (rf = Rest.Undefined);
  Alcotest.(check string) "param unchanged" "abc123def.xml" param

let test_parse_format_with_query_string () =
  let rf, param = Rest.parse_data_format "abc123def.json?count=5" in
  Alcotest.(check bool) "JSON format with query" true (rf = Rest.JSON);
  Alcotest.(check string) "param without query" "abc123def" param

let test_parse_hash_format () =
  let hash_hex = "0000000000000000000000000000000000000000000000000000000000000001" in
  let rf, param = Rest.parse_data_format (hash_hex ^ ".json") in
  Alcotest.(check bool) "JSON format for hash" true (rf = Rest.JSON);
  Alcotest.(check string) "hash param" hash_hex param

let test_parse_headers_path_deprecated () =
  (* Test deprecated path format: /rest/headers/<count>/<hash> *)
  let rf, param = Rest.parse_data_format "5/abc123.json" in
  Alcotest.(check bool) "JSON format" true (rf = Rest.JSON);
  Alcotest.(check string) "param has count/hash" "5/abc123" param

(* ============================================================================
   Helper Tests
   ============================================================================ *)

let test_cstruct_to_hex () =
  let cs = Cstruct.of_string "\x00\x01\x02\xff" in
  let hex = Rest.cstruct_to_hex cs in
  Alcotest.(check string) "hex encoding" "000102ff" hex

let test_parse_display_hash_valid () =
  let hash_hex = "0000000000000000000000000000000000000000000000000000000000000001" in
  match Rest.parse_display_hash hash_hex with
  | Some h ->
    Alcotest.(check int) "hash length" 32 (Cstruct.length h);
    (* Display format is reversed, so last byte of display is first byte internal *)
    Alcotest.(check int) "first byte" 1 (Cstruct.get_uint8 h 0)
  | None ->
    Alcotest.fail "Expected valid hash"

let test_parse_display_hash_invalid_length () =
  let hash_hex = "0001020304" in
  match Rest.parse_display_hash hash_hex with
  | Some _ -> Alcotest.fail "Expected None for invalid hash"
  | None -> ()

let test_parse_display_hash_invalid_chars () =
  let hash_hex = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz" in
  match Rest.parse_display_hash hash_hex with
  | Some _ -> Alcotest.fail "Expected None for invalid hex chars"
  | None -> ()

let test_split_string () =
  let parts = Rest.split_string "a/b/c" '/' in
  Alcotest.(check (list string)) "split parts" ["a"; "b"; "c"] parts

let test_split_string_empty () =
  let parts = Rest.split_string "" '/' in
  Alcotest.(check (list string)) "empty string" [] parts

let test_split_string_trailing () =
  let parts = Rest.split_string "a/b/" '/' in
  Alcotest.(check (list string)) "trailing slash" ["a"; "b"] parts

(* ============================================================================
   Context Setup
   ============================================================================ *)

(* Create a test context for REST endpoints *)
let create_test_context () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let utxo = Utxo.UtxoSet.create db in
  let mempool = Mempool.create ~require_standard:false ~verify_scripts:false
                  ~utxo ~current_height:0 () in
  let network = Consensus.testnet4 in

  (* Create minimal chain state *)
  let chain_state = Sync.create_chain_state db network in

  (* Initialize peer manager *)
  let peer_manager = Peer_manager.create network in

  (* Create fee estimator *)
  let fee_estimator = Fee_estimation.create () in

  Rpc.create_context
    ~chain:chain_state
    ~mempool
    ~peer_manager
    ~wallet:None
    ~fee_estimator
    ~network ()

(* ============================================================================
   Integration Tests
   ============================================================================ *)

let test_dispatch_block_not_found () =
  let ctx = create_test_context () in
  let hash = "0000000000000000000000000000000000000000000000000000000000000001" in
  let path = "/rest/block/" ^ hash ^ ".json" in
  let req = Cohttp.Request.make (Uri.of_string path) in
  let response = Lwt_main.run (Rest.dispatch_rest ctx req path) in
  let status = Cohttp.Response.status (fst response) in
  Alcotest.(check bool) "404 for missing block" true (status = `Not_found);
  cleanup_test_db ()

let test_dispatch_tx_not_found () =
  let ctx = create_test_context () in
  let txid = "0000000000000000000000000000000000000000000000000000000000000001" in
  let path = "/rest/tx/" ^ txid ^ ".json" in
  let req = Cohttp.Request.make (Uri.of_string path) in
  let response = Lwt_main.run (Rest.dispatch_rest ctx req path) in
  let status = Cohttp.Response.status (fst response) in
  Alcotest.(check bool) "404 for missing tx" true (status = `Not_found);
  cleanup_test_db ()

let test_dispatch_chaininfo () =
  let ctx = create_test_context () in
  let path = "/rest/chaininfo.json" in
  let req = Cohttp.Request.make (Uri.of_string path) in
  let response = Lwt_main.run (Rest.dispatch_rest ctx req path) in
  let status = Cohttp.Response.status (fst response) in
  Alcotest.(check bool) "200 for chaininfo" true (status = `OK);

  (* Check response body *)
  let body = Lwt_main.run (Cohttp_lwt.Body.to_string (snd response)) in
  let json = Yojson.Safe.from_string body in
  (match json with
   | `Assoc fields ->
     Alcotest.(check bool) "has chain field" true
       (List.mem_assoc "chain" fields);
     Alcotest.(check bool) "has blocks field" true
       (List.mem_assoc "blocks" fields);
     Alcotest.(check bool) "has bestblockhash field" true
       (List.mem_assoc "bestblockhash" fields)
   | _ -> Alcotest.fail "Expected JSON object");
  cleanup_test_db ()

let test_dispatch_mempool_info () =
  let ctx = create_test_context () in
  let path = "/rest/mempool/info.json" in
  let req = Cohttp.Request.make (Uri.of_string path) in
  let response = Lwt_main.run (Rest.dispatch_rest ctx req path) in
  let status = Cohttp.Response.status (fst response) in
  Alcotest.(check bool) "200 for mempool info" true (status = `OK);

  let body = Lwt_main.run (Cohttp_lwt.Body.to_string (snd response)) in
  let json = Yojson.Safe.from_string body in
  (match json with
   | `Assoc fields ->
     Alcotest.(check bool) "has size field" true
       (List.mem_assoc "size" fields);
     Alcotest.(check bool) "has loaded field" true
       (List.mem_assoc "loaded" fields)
   | _ -> Alcotest.fail "Expected JSON object");
  cleanup_test_db ()

let test_dispatch_mempool_contents () =
  let ctx = create_test_context () in
  let path = "/rest/mempool/contents.json" in
  let req = Cohttp.Request.make (Uri.of_string path) in
  let response = Lwt_main.run (Rest.dispatch_rest ctx req path) in
  let status = Cohttp.Response.status (fst response) in
  Alcotest.(check bool) "200 for mempool contents" true (status = `OK);

  let body = Lwt_main.run (Cohttp_lwt.Body.to_string (snd response)) in
  let json = Yojson.Safe.from_string body in
  (match json with
   | `Assoc _ -> ()  (* verbose format: object with txid keys *)
   | `List _ -> ()   (* non-verbose: list of txids *)
   | _ -> Alcotest.fail "Expected JSON object or list");
  cleanup_test_db ()

let test_dispatch_blockhashbyheight_not_found () =
  let ctx = create_test_context () in
  let path = "/rest/blockhashbyheight/999999.json" in
  let req = Cohttp.Request.make (Uri.of_string path) in
  let response = Lwt_main.run (Rest.dispatch_rest ctx req path) in
  let status = Cohttp.Response.status (fst response) in
  Alcotest.(check bool) "404 for invalid height" true (status = `Not_found);
  cleanup_test_db ()

let test_dispatch_blockhashbyheight_invalid () =
  let ctx = create_test_context () in
  let path = "/rest/blockhashbyheight/abc.json" in
  let req = Cohttp.Request.make (Uri.of_string path) in
  let response = Lwt_main.run (Rest.dispatch_rest ctx req path) in
  let status = Cohttp.Response.status (fst response) in
  Alcotest.(check bool) "400 for invalid height" true (status = `Bad_request);
  cleanup_test_db ()

let test_dispatch_unknown_path () =
  let ctx = create_test_context () in
  let path = "/rest/unknown/something.json" in
  let req = Cohttp.Request.make (Uri.of_string path) in
  let response = Lwt_main.run (Rest.dispatch_rest ctx req path) in
  let status = Cohttp.Response.status (fst response) in
  Alcotest.(check bool) "404 for unknown path" true (status = `Not_found);
  cleanup_test_db ()

let test_dispatch_headers_invalid_hash () =
  let ctx = create_test_context () in
  let path = "/rest/headers/invalidhash.json" in
  let req = Cohttp.Request.make (Uri.of_string path) in
  let response = Lwt_main.run (Rest.dispatch_rest ctx req path) in
  let status = Cohttp.Response.status (fst response) in
  Alcotest.(check bool) "400 for invalid hash" true (status = `Bad_request);
  cleanup_test_db ()

let test_chaininfo_json_only () =
  let ctx = create_test_context () in
  let path = "/rest/chaininfo.hex" in
  let req = Cohttp.Request.make (Uri.of_string path) in
  let response = Lwt_main.run (Rest.dispatch_rest ctx req path) in
  let status = Cohttp.Response.status (fst response) in
  Alcotest.(check bool) "404 for non-json chaininfo" true (status = `Not_found);
  cleanup_test_db ()

let test_mempool_info_json_only () =
  let ctx = create_test_context () in
  let path = "/rest/mempool/info.hex" in
  let req = Cohttp.Request.make (Uri.of_string path) in
  let response = Lwt_main.run (Rest.dispatch_rest ctx req path) in
  let status = Cohttp.Response.status (fst response) in
  Alcotest.(check bool) "404 for non-json mempool info" true (status = `Not_found);
  cleanup_test_db ()

(* ============================================================================
   Test Suite
   ============================================================================ *)

let format_parsing_tests = [
  "parse JSON format", `Quick, test_parse_json_format;
  "parse Hex format", `Quick, test_parse_hex_format;
  "parse Binary format", `Quick, test_parse_binary_format;
  "parse Undefined format", `Quick, test_parse_undefined_format;
  "parse unknown format", `Quick, test_parse_unknown_format;
  "parse format with query string", `Quick, test_parse_format_with_query_string;
  "parse hash format", `Quick, test_parse_hash_format;
  "parse headers deprecated path", `Quick, test_parse_headers_path_deprecated;
]

let helper_tests = [
  "cstruct to hex", `Quick, test_cstruct_to_hex;
  "parse display hash valid", `Quick, test_parse_display_hash_valid;
  "parse display hash invalid length", `Quick, test_parse_display_hash_invalid_length;
  "parse display hash invalid chars", `Quick, test_parse_display_hash_invalid_chars;
  "split string", `Quick, test_split_string;
  "split empty string", `Quick, test_split_string_empty;
  "split string trailing slash", `Quick, test_split_string_trailing;
]

let dispatch_tests = [
  "dispatch block not found", `Quick, test_dispatch_block_not_found;
  "dispatch tx not found", `Quick, test_dispatch_tx_not_found;
  "dispatch chaininfo", `Quick, test_dispatch_chaininfo;
  "dispatch mempool info", `Quick, test_dispatch_mempool_info;
  "dispatch mempool contents", `Quick, test_dispatch_mempool_contents;
  "dispatch blockhashbyheight not found", `Quick, test_dispatch_blockhashbyheight_not_found;
  "dispatch blockhashbyheight invalid", `Quick, test_dispatch_blockhashbyheight_invalid;
  "dispatch unknown path", `Quick, test_dispatch_unknown_path;
  "dispatch headers invalid hash", `Quick, test_dispatch_headers_invalid_hash;
  "chaininfo json only", `Quick, test_chaininfo_json_only;
  "mempool info json only", `Quick, test_mempool_info_json_only;
]

let () =
  Alcotest.run "REST" [
    "format_parsing", format_parsing_tests;
    "helpers", helper_tests;
    "dispatch", dispatch_tests;
  ]
