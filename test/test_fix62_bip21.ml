(* FIX-62: BIP-21 URI parser tests
   See BIP-0021: https://github.com/bitcoin/bips/blob/master/bip-0021.mediawiki
   Camlcoin is the only fleet impl with a partial-present starting state —
   Address.address_of_string already rejected `bitcoin:` URIs; this suite
   verifies the new Bip21.parse handles them properly, and that the
   original rejection regression is preserved. *)

open Camlcoin

let net_pp ppf = function
  | `Mainnet -> Format.fprintf ppf "mainnet"
  | `Testnet -> Format.fprintf ppf "testnet"
  | `Regtest -> Format.fprintf ppf "regtest"

(* Sample valid mainnet bech32 P2WPKH address from BIP-173 §"Test vectors" *)
let mainnet_bech32 = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"

(* Sample valid mainnet P2PKH (genesis coinbase recipient) *)
let mainnet_p2pkh = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"

(* Sample valid testnet bech32 P2WPKH (used elsewhere in the test suite) *)
let testnet_bech32 = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"

let ok_or_fail tag = function
  | Ok v -> v
  | Error e -> Alcotest.failf "%s: parse failed with %s" tag (Bip21.string_of_error e)

let parse_or_fail uri net = ok_or_fail uri (Bip21.parse uri net)

(* ============================================================================
   Basic parses
   ============================================================================ *)

let test_parse_bare_address () =
  let uri = "bitcoin:" ^ mainnet_bech32 in
  let r = parse_or_fail uri `Mainnet in
  Alcotest.(check (option int64)) "no amount" None r.amount;
  Alcotest.(check (option string)) "no label" None r.label;
  Alcotest.(check (option string)) "no message" None r.message;
  Alcotest.(check (option string)) "no lightning" None r.lightning;
  Alcotest.(check (option string)) "no pj" None r.pj;
  Alcotest.(check (option bool)) "no pjos" None r.pjos;
  Alcotest.(check (list (pair string string))) "no extras" [] r.extras

let test_parse_p2pkh () =
  let uri = "bitcoin:" ^ mainnet_p2pkh in
  let r = parse_or_fail uri `Mainnet in
  Alcotest.(check string) "address class"
    "P2PKH"
    (match r.address.Address.addr_type with
     | Address.P2PKH -> "P2PKH" | _ -> "other")

let test_parse_testnet_address () =
  let uri = "bitcoin:" ^ testnet_bech32 in
  let r = parse_or_fail uri `Testnet in
  Alcotest.(check (testable net_pp (=))) "testnet" `Testnet r.address.Address.network

let test_scheme_case_insensitive () =
  (* Per RFC 3986 §3.1 scheme names are case-insensitive *)
  let r = parse_or_fail ("Bitcoin:" ^ mainnet_bech32) `Mainnet in
  Alcotest.(check string) "decoded ok"
    "Mainnet"
    (match r.address.Address.network with `Mainnet -> "Mainnet" | _ -> "x")

(* ============================================================================
   Amount parsing
   ============================================================================ *)

let test_amount_whole_btc () =
  let r = parse_or_fail ("bitcoin:" ^ mainnet_bech32 ^ "?amount=1") `Mainnet in
  Alcotest.(check (option int64)) "1 BTC = 1e8 sats" (Some 100_000_000L) r.amount

let test_amount_fractional () =
  let r = parse_or_fail ("bitcoin:" ^ mainnet_bech32 ^ "?amount=0.001") `Mainnet in
  Alcotest.(check (option int64)) "0.001 BTC" (Some 100_000L) r.amount

let test_amount_full_precision () =
  (* 8 decimal places → 1 sat *)
  let r = parse_or_fail ("bitcoin:" ^ mainnet_bech32 ^ "?amount=0.00000001") `Mainnet in
  Alcotest.(check (option int64)) "1 sat" (Some 1L) r.amount

let test_amount_trailing_dot () =
  let r = parse_or_fail ("bitcoin:" ^ mainnet_bech32 ^ "?amount=5.") `Mainnet in
  Alcotest.(check (option int64)) "5. BTC" (Some 500_000_000L) r.amount

let test_amount_leading_dot () =
  let r = parse_or_fail ("bitcoin:" ^ mainnet_bech32 ^ "?amount=.5") `Mainnet in
  Alcotest.(check (option int64)) ".5 BTC" (Some 50_000_000L) r.amount

let test_amount_too_many_decimals () =
  match Bip21.parse ("bitcoin:" ^ mainnet_bech32 ^ "?amount=0.123456789") `Mainnet with
  | Error (Bip21.Invalid_amount _) -> ()
  | _ -> Alcotest.fail "expected Invalid_amount for >8 decimal places"

let test_amount_signed_rejected () =
  match Bip21.parse ("bitcoin:" ^ mainnet_bech32 ^ "?amount=-1") `Mainnet with
  | Error (Bip21.Invalid_amount _) -> ()
  | _ -> Alcotest.fail "expected Invalid_amount for negative"

let test_amount_scientific_rejected () =
  match Bip21.parse ("bitcoin:" ^ mainnet_bech32 ^ "?amount=1e8") `Mainnet with
  | Error (Bip21.Invalid_amount _) -> ()
  | _ -> Alcotest.fail "expected Invalid_amount for scientific"

let test_amount_garbage_rejected () =
  match Bip21.parse ("bitcoin:" ^ mainnet_bech32 ^ "?amount=foo") `Mainnet with
  | Error (Bip21.Invalid_amount _) -> ()
  | _ -> Alcotest.fail "expected Invalid_amount for non-numeric"

(* ============================================================================
   Label / message / percent-decoding
   ============================================================================ *)

let test_label_simple () =
  let uri = "bitcoin:" ^ mainnet_bech32 ^ "?label=Donation" in
  let r = parse_or_fail uri `Mainnet in
  Alcotest.(check (option string)) "label" (Some "Donation") r.label

let test_label_percent_decoded () =
  (* "Foo%20Bar" → "Foo Bar" *)
  let uri = "bitcoin:" ^ mainnet_bech32 ^ "?label=Foo%20Bar" in
  let r = parse_or_fail uri `Mainnet in
  Alcotest.(check (option string)) "decoded space" (Some "Foo Bar") r.label

let test_label_plus_decoded_to_space () =
  let uri = "bitcoin:" ^ mainnet_bech32 ^ "?label=Foo+Bar" in
  let r = parse_or_fail uri `Mainnet in
  Alcotest.(check (option string)) "+ → space" (Some "Foo Bar") r.label

let test_message_utf8 () =
  (* "Caf%C3%A9" → "Café" (UTF-8) *)
  let uri = "bitcoin:" ^ mainnet_bech32 ^ "?message=Caf%C3%A9" in
  let r = parse_or_fail uri `Mainnet in
  Alcotest.(check (option string)) "utf8" (Some "Café") r.message

let test_key_case_insensitive () =
  (* spec: keys are case-insensitive *)
  let uri = "bitcoin:" ^ mainnet_bech32 ^ "?AMOUNT=1&LaBeL=x" in
  let r = parse_or_fail uri `Mainnet in
  Alcotest.(check (option int64)) "AMOUNT" (Some 100_000_000L) r.amount;
  Alcotest.(check (option string)) "LaBeL" (Some "x") r.label

(* ============================================================================
   Lightning / pj / pjos (BIP-78)
   ============================================================================ *)

let test_lightning () =
  let invoice = "lnbc1pvjluezpp5..." in
  let uri = "bitcoin:" ^ mainnet_bech32 ^ "?lightning=" ^ invoice in
  let r = parse_or_fail uri `Mainnet in
  Alcotest.(check (option string)) "lightning" (Some invoice) r.lightning

let test_pj_endpoint () =
  let uri = "bitcoin:" ^ mainnet_bech32
            ^ "?pj=https%3A%2F%2Fexample.com%2Fpj" in
  let r = parse_or_fail uri `Mainnet in
  Alcotest.(check (option string)) "pj endpoint"
    (Some "https://example.com/pj") r.pj

let test_pjos_zero () =
  let uri = "bitcoin:" ^ mainnet_bech32 ^ "?pj=https%3A%2F%2Fx%2Fpj&pjos=0" in
  let r = parse_or_fail uri `Mainnet in
  Alcotest.(check (option bool)) "pjos=0 → false" (Some false) r.pjos

let test_pjos_one () =
  let uri = "bitcoin:" ^ mainnet_bech32 ^ "?pj=https%3A%2F%2Fx%2Fpj&pjos=1" in
  let r = parse_or_fail uri `Mainnet in
  Alcotest.(check (option bool)) "pjos=1 → true" (Some true) r.pjos

let test_pjos_invalid_value () =
  let uri = "bitcoin:" ^ mainnet_bech32 ^ "?pjos=true" in
  match Bip21.parse uri `Mainnet with
  | Error (Bip21.Invalid_pjos "true") -> ()
  | _ -> Alcotest.fail "expected Invalid_pjos for non-0/1"

(* ============================================================================
   req- prefix rejection (forward compatibility)
   ============================================================================ *)

let test_req_unknown_rejected () =
  let uri = "bitcoin:" ^ mainnet_bech32 ^ "?req-future=1" in
  match Bip21.parse uri `Mainnet with
  | Error (Bip21.Unknown_required_param "future") -> ()
  | _ -> Alcotest.fail "expected Unknown_required_param"

let test_req_case_insensitive_prefix () =
  (* "REQ-foo" should also be caught — case-insensitive key matching *)
  let uri = "bitcoin:" ^ mainnet_bech32 ^ "?REQ-bar=1" in
  match Bip21.parse uri `Mainnet with
  | Error (Bip21.Unknown_required_param "bar") -> ()
  | _ -> Alcotest.fail "expected Unknown_required_param for REQ-bar"

(* ============================================================================
   Unknown non-req- params → ignored / surfaced in extras
   ============================================================================ *)

let test_unknown_non_req_in_extras () =
  let uri = "bitcoin:" ^ mainnet_bech32 ^ "?somefuture=42" in
  let r = parse_or_fail uri `Mainnet in
  Alcotest.(check (list (pair string string))) "extras"
    [("somefuture", "42")] r.extras

(* ============================================================================
   Error cases
   ============================================================================ *)

let test_missing_scheme () =
  match Bip21.parse mainnet_bech32 `Mainnet with
  | Error Bip21.Missing_scheme -> ()
  | _ -> Alcotest.fail "expected Missing_scheme for raw address"

let test_wrong_scheme () =
  match Bip21.parse ("bitcoincash:" ^ mainnet_bech32) `Mainnet with
  | Error Bip21.Missing_scheme -> ()
  | _ -> Alcotest.fail "expected Missing_scheme for bitcoincash:"

let test_empty_address () =
  match Bip21.parse "bitcoin:?amount=1" `Mainnet with
  | Error Bip21.Empty_address -> ()
  | _ -> Alcotest.fail "expected Empty_address"

let test_invalid_address () =
  match Bip21.parse "bitcoin:NOT_AN_ADDRESS" `Mainnet with
  | Error (Bip21.Invalid_address _) -> ()
  | _ -> Alcotest.fail "expected Invalid_address"

let test_network_mismatch () =
  (* mainnet address, parser called with testnet expectation *)
  match Bip21.parse ("bitcoin:" ^ mainnet_bech32) `Testnet with
  | Error (Bip21.Network_mismatch _) -> ()
  | _ -> Alcotest.fail "expected Network_mismatch"

let test_malformed_query_no_equals () =
  (* "amount&label=x" — first chunk has no '=' *)
  let uri = "bitcoin:" ^ mainnet_bech32 ^ "?amount&label=x" in
  match Bip21.parse uri `Mainnet with
  | Error (Bip21.Malformed_query _) -> ()
  | _ -> Alcotest.fail "expected Malformed_query for bare key"

let test_malformed_percent () =
  let uri = "bitcoin:" ^ mainnet_bech32 ^ "?label=%ZZ" in
  match Bip21.parse uri `Mainnet with
  | Error (Bip21.Malformed_query _) -> ()
  | _ -> Alcotest.fail "expected Malformed_query for bad %"

let test_duplicate_question_mark () =
  let uri = "bitcoin:" ^ mainnet_bech32 ^ "?amount=1?label=foo" in
  match Bip21.parse uri `Mainnet with
  | Error Bip21.Duplicate_address_separator -> ()
  | _ -> Alcotest.fail "expected Duplicate_address_separator"

(* ============================================================================
   Spec vectors (BIP-21 §"Examples")
   ============================================================================ *)

let test_spec_example_just_address () =
  let r = parse_or_fail
    "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" `Mainnet in
  Alcotest.(check (option int64)) "no amount" None r.amount

let test_spec_example_with_amount () =
  let r = parse_or_fail
    "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?amount=50" `Mainnet in
  Alcotest.(check (option int64)) "50 BTC" (Some 5_000_000_000L) r.amount

let test_spec_example_amount_label () =
  let r = parse_or_fail
    "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?amount=50&label=Luke-Jr" `Mainnet in
  Alcotest.(check (option int64)) "50 BTC" (Some 5_000_000_000L) r.amount;
  Alcotest.(check (option string)) "label" (Some "Luke-Jr") r.label

let test_spec_example_amount_label_message () =
  let r = parse_or_fail
    ("bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?amount=20.3"
     ^ "&label=Luke-Jr&message=Donation%20for%20project%20xyz") `Mainnet in
  Alcotest.(check (option int64)) "20.3 BTC" (Some 2_030_000_000L) r.amount;
  Alcotest.(check (option string)) "label" (Some "Luke-Jr") r.label;
  Alcotest.(check (option string)) "message decoded"
    (Some "Donation for project xyz") r.message

let test_spec_example_required_unknown () =
  (* From spec: "characters must be URI encoded properly. … req-X
     unknown to the implementation … reject the URI" *)
  match Bip21.parse
    "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?req-somethingyoudontunderstand=50&req-somethingelseyoudontget=999" `Mainnet with
  | Error (Bip21.Unknown_required_param _) -> ()
  | _ -> Alcotest.fail "expected req-* rejection per spec example"

let test_spec_example_known_required () =
  (* "?somethingyoudontunderstand=50" — NOT req-, should be tolerated *)
  let r = parse_or_fail
    "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?somethingyoudontunderstand=50&somethingelseyoudontget=999" `Mainnet in
  Alcotest.(check int) "two extras" 2 (List.length r.extras)

(* ============================================================================
   Regression: Address.address_of_string still strict
   (preserve W119 BUG-28 audit semantic — raw URI must still be Error)
   ============================================================================ *)

let test_regression_address_of_string_still_rejects_uri () =
  match Address.address_of_string ("bitcoin:" ^ mainnet_bech32) with
  | Ok _ -> Alcotest.fail
      "Address.address_of_string accepted a bitcoin: URI — \
       FIX-62 must NOT relax this; URI handling lives in Bip21.parse"
  | Error _ -> ()

let test_regression_address_of_string_still_accepts_raw () =
  (* And the non-URI path keeps working *)
  match Address.address_of_string mainnet_bech32 with
  | Ok _ -> ()
  | Error e -> Alcotest.failf
      "Address.address_of_string rejected raw bech32 (regression): %s" e

let test_regression_address_of_string_still_accepts_p2pkh () =
  match Address.address_of_string mainnet_p2pkh with
  | Ok _ -> ()
  | Error e -> Alcotest.failf
      "Address.address_of_string rejected raw P2PKH (regression): %s" e

(* ============================================================================
   W119 G28/G29 audit assertions still hold
   (after FIX-62, those tests must still pass since they probe
   Address.address_of_string, not Bip21.parse)
   ============================================================================ *)

let test_w119_g28_assertion_preserved () =
  let uri = "bitcoin:bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4?amount=0.1" in
  match Address.address_of_string uri with
  | Ok _ -> Alcotest.fail "W119 G28 audit assertion broken"
  | Error _ -> ()

let test_w119_g29_assertion_preserved () =
  let uri = "bitcoin:bc1qaddr?pj=https://x/pj&pjos=1" in
  match Address.address_of_string uri with
  | Ok _ -> Alcotest.fail "W119 G29 audit assertion broken"
  | Error _ -> ()

(* ============================================================================
   Suite
   ============================================================================ *)

let suite =
  [ "basic parses",
    [ Alcotest.test_case "bare address" `Quick test_parse_bare_address;
      Alcotest.test_case "P2PKH" `Quick test_parse_p2pkh;
      Alcotest.test_case "testnet address" `Quick test_parse_testnet_address;
      Alcotest.test_case "scheme case-insensitive" `Quick test_scheme_case_insensitive;
    ];
    "amount parsing",
    [ Alcotest.test_case "whole BTC" `Quick test_amount_whole_btc;
      Alcotest.test_case "fractional" `Quick test_amount_fractional;
      Alcotest.test_case "full precision (8 decimals)" `Quick test_amount_full_precision;
      Alcotest.test_case "trailing dot" `Quick test_amount_trailing_dot;
      Alcotest.test_case "leading dot" `Quick test_amount_leading_dot;
      Alcotest.test_case "too many decimals rejected" `Quick test_amount_too_many_decimals;
      Alcotest.test_case "signed rejected" `Quick test_amount_signed_rejected;
      Alcotest.test_case "scientific rejected" `Quick test_amount_scientific_rejected;
      Alcotest.test_case "garbage rejected" `Quick test_amount_garbage_rejected;
    ];
    "label / message / percent-decoding",
    [ Alcotest.test_case "label simple" `Quick test_label_simple;
      Alcotest.test_case "label %20 → space" `Quick test_label_percent_decoded;
      Alcotest.test_case "label + → space" `Quick test_label_plus_decoded_to_space;
      Alcotest.test_case "message UTF-8" `Quick test_message_utf8;
      Alcotest.test_case "key case-insensitive" `Quick test_key_case_insensitive;
    ];
    "lightning / pj / pjos (BIP-78)",
    [ Alcotest.test_case "lightning passthrough" `Quick test_lightning;
      Alcotest.test_case "pj endpoint decoded" `Quick test_pj_endpoint;
      Alcotest.test_case "pjos=0" `Quick test_pjos_zero;
      Alcotest.test_case "pjos=1" `Quick test_pjos_one;
      Alcotest.test_case "pjos invalid rejected" `Quick test_pjos_invalid_value;
    ];
    "req- forward compat",
    [ Alcotest.test_case "req-X rejected" `Quick test_req_unknown_rejected;
      Alcotest.test_case "REQ-X case-insensitive" `Quick test_req_case_insensitive_prefix;
    ];
    "unknown non-req- → extras",
    [ Alcotest.test_case "unknown surfaced in extras" `Quick test_unknown_non_req_in_extras;
    ];
    "error cases",
    [ Alcotest.test_case "missing scheme" `Quick test_missing_scheme;
      Alcotest.test_case "wrong scheme" `Quick test_wrong_scheme;
      Alcotest.test_case "empty address" `Quick test_empty_address;
      Alcotest.test_case "invalid address" `Quick test_invalid_address;
      Alcotest.test_case "network mismatch" `Quick test_network_mismatch;
      Alcotest.test_case "malformed query (no =)" `Quick test_malformed_query_no_equals;
      Alcotest.test_case "malformed percent" `Quick test_malformed_percent;
      Alcotest.test_case "duplicate ?" `Quick test_duplicate_question_mark;
    ];
    "BIP-21 spec vectors",
    [ Alcotest.test_case "just address" `Quick test_spec_example_just_address;
      Alcotest.test_case "with amount" `Quick test_spec_example_with_amount;
      Alcotest.test_case "amount + label" `Quick test_spec_example_amount_label;
      Alcotest.test_case "amount + label + message"
        `Quick test_spec_example_amount_label_message;
      Alcotest.test_case "req-* rejection" `Quick test_spec_example_required_unknown;
      Alcotest.test_case "non-req-* tolerated" `Quick test_spec_example_known_required;
    ];
    "regression: Address.address_of_string strict",
    [ Alcotest.test_case "still rejects URI" `Quick
        test_regression_address_of_string_still_rejects_uri;
      Alcotest.test_case "still accepts raw bech32" `Quick
        test_regression_address_of_string_still_accepts_raw;
      Alcotest.test_case "still accepts raw P2PKH" `Quick
        test_regression_address_of_string_still_accepts_p2pkh;
    ];
    "W119 audit assertions preserved",
    [ Alcotest.test_case "G28 still fails URI" `Quick
        test_w119_g28_assertion_preserved;
      Alcotest.test_case "G29 still fails pjos URI" `Quick
        test_w119_g29_assertion_preserved;
    ];
  ]

let () = Alcotest.run "FIX-62 BIP-21" suite
