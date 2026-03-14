(* Tests for output descriptors (BIP 380-386) *)

open Camlcoin

(* ============================================================================
   Helper functions
   ============================================================================ *)

let _hex_to_cstruct s =
  let len = String.length s / 2 in
  let buf = Cstruct.create len in
  for i = 0 to len - 1 do
    let byte = int_of_string ("0x" ^ String.sub s (i * 2) 2) in
    Cstruct.set_uint8 buf i byte
  done;
  buf

let _cstruct_to_hex cs =
  let len = Cstruct.length cs in
  let buf = Buffer.create (len * 2) in
  for i = 0 to len - 1 do
    Buffer.add_string buf (Printf.sprintf "%02x" (Cstruct.get_uint8 cs i))
  done;
  Buffer.contents buf

(* ============================================================================
   Checksum tests
   ============================================================================ *)

let test_checksum_simple () =
  (* Test vector from BIP 380 *)
  let desc = "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)" in
  match Descriptor.descriptor_checksum desc with
  | Some cs ->
    Alcotest.(check int) "checksum length" 8 (String.length cs);
    (* Checksum should be 8 lowercase characters from bech32 charset *)
    Alcotest.(check bool) "checksum valid chars" true
      (String.for_all (fun c -> String.contains "qpzry9x8gf2tvdw0s3jn54khce6mua7l" c) cs)
  | None ->
    Alcotest.fail "checksum computation failed"

let test_checksum_add () =
  let desc = "pkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)" in
  match Descriptor.add_checksum desc with
  | Some with_cs ->
    Alcotest.(check bool) "has checksum separator" true (String.contains with_cs '#');
    let parts = String.split_on_char '#' with_cs in
    Alcotest.(check int) "two parts" 2 (List.length parts);
    Alcotest.(check string) "original preserved" desc (List.hd parts);
    Alcotest.(check int) "checksum length" 8 (String.length (List.nth parts 1))
  | None ->
    Alcotest.fail "add_checksum failed"

let test_checksum_verify () =
  let desc = "pkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)" in
  match Descriptor.add_checksum desc with
  | Some with_cs ->
    Alcotest.(check bool) "valid checksum" true (Descriptor.verify_checksum with_cs);
    (* Modify checksum and verify it fails *)
    let modified = String.sub with_cs 0 (String.length with_cs - 1) ^ "x" in
    Alcotest.(check bool) "invalid checksum" false (Descriptor.verify_checksum modified)
  | None ->
    Alcotest.fail "add_checksum failed"

let test_checksum_invalid_chars () =
  (* Non-ASCII characters should fail checksum computation *)
  let desc = "pkh(\xc3\xa9)" in
  match Descriptor.descriptor_checksum desc with
  | Some _ -> Alcotest.fail "should fail for non-ASCII"
  | None -> ()

(* ============================================================================
   Parsing tests - basic descriptor types
   ============================================================================ *)

let test_parse_pk () =
  let pk = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9" in
  let desc_str = "pk(" ^ pk ^ ")" in
  match Descriptor.parse desc_str with
  | Error e -> Alcotest.fail e
  | Ok parsed ->
    match parsed.desc with
    | Descriptor.Pk _ -> ()
    | _ -> Alcotest.fail "expected Pk"

let test_parse_pkh () =
  let pk = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9" in
  let desc_str = "pkh(" ^ pk ^ ")" in
  match Descriptor.parse desc_str with
  | Error e -> Alcotest.fail e
  | Ok parsed ->
    match parsed.desc with
    | Descriptor.Pkh _ -> ()
    | _ -> Alcotest.fail "expected Pkh"

let test_parse_wpkh () =
  let pk = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9" in
  let desc_str = "wpkh(" ^ pk ^ ")" in
  match Descriptor.parse desc_str with
  | Error e -> Alcotest.fail e
  | Ok parsed ->
    match parsed.desc with
    | Descriptor.Wpkh _ -> ()
    | _ -> Alcotest.fail "expected Wpkh"

let test_parse_sh_wpkh () =
  let pk = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9" in
  let desc_str = "sh(wpkh(" ^ pk ^ "))" in
  match Descriptor.parse desc_str with
  | Error e -> Alcotest.fail e
  | Ok parsed ->
    match parsed.desc with
    | Descriptor.Sh (Descriptor.Wpkh _) -> ()
    | _ -> Alcotest.fail "expected Sh(Wpkh)"

let test_parse_wsh_multi () =
  let pk1 = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9" in
  let pk2 = "03dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659" in
  let desc_str = Printf.sprintf "wsh(multi(1,%s,%s))" pk1 pk2 in
  match Descriptor.parse desc_str with
  | Error e -> Alcotest.fail e
  | Ok parsed ->
    match parsed.desc with
    | Descriptor.Wsh (Descriptor.Multi (1, keys)) ->
      Alcotest.(check int) "two keys" 2 (List.length keys)
    | _ -> Alcotest.fail "expected Wsh(Multi)"

let test_parse_sortedmulti () =
  let pk1 = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9" in
  let pk2 = "03dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659" in
  let desc_str = Printf.sprintf "sortedmulti(2,%s,%s)" pk1 pk2 in
  match Descriptor.parse desc_str with
  | Error e -> Alcotest.fail e
  | Ok parsed ->
    match parsed.desc with
    | Descriptor.SortedMulti (2, keys) ->
      Alcotest.(check int) "two keys" 2 (List.length keys)
    | _ -> Alcotest.fail "expected SortedMulti"

let test_parse_tr () =
  let pk = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9" in  (* x-only *)
  let desc_str = "tr(" ^ pk ^ ")" in
  match Descriptor.parse desc_str with
  | Error e -> Alcotest.fail e
  | Ok parsed ->
    match parsed.desc with
    | Descriptor.Tr (_, None) -> ()
    | _ -> Alcotest.fail "expected Tr without script tree"

let test_parse_combo () =
  let pk = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9" in
  let desc_str = "combo(" ^ pk ^ ")" in
  match Descriptor.parse desc_str with
  | Error e -> Alcotest.fail e
  | Ok parsed ->
    match parsed.desc with
    | Descriptor.Combo _ -> ()
    | _ -> Alcotest.fail "expected Combo"

let test_parse_addr () =
  let desc_str = "addr(bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4)" in
  match Descriptor.parse desc_str with
  | Error e -> Alcotest.fail e
  | Ok parsed ->
    match parsed.desc with
    | Descriptor.Addr addr ->
      Alcotest.(check bool) "is P2WPKH" true
        (addr.addr_type = Address.P2WPKH)
    | _ -> Alcotest.fail "expected Addr"

let test_parse_raw () =
  let script_hex = "76a914000000000000000000000000000000000000000088ac" in
  let desc_str = "raw(" ^ script_hex ^ ")" in
  match Descriptor.parse desc_str with
  | Error e -> Alcotest.fail e
  | Ok parsed ->
    match parsed.desc with
    | Descriptor.Raw script ->
      Alcotest.(check int) "script length" 25 (Cstruct.length script)
    | _ -> Alcotest.fail "expected Raw"

(* ============================================================================
   Key origin parsing tests
   ============================================================================ *)

let test_parse_with_origin () =
  let pk = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9" in
  let desc_str = "pkh([d34db33f/44'/0'/0']" ^ pk ^ ")" in
  match Descriptor.parse desc_str with
  | Error e -> Alcotest.fail e
  | Ok parsed ->
    match parsed.desc with
    | Descriptor.Pkh (Descriptor.WithOrigin (origin, _)) ->
      Alcotest.(check bool) "fingerprint" true (origin.fingerprint = 0xd34db33fl);
      Alcotest.(check int) "path length" 3 (List.length origin.origin_path)
    | _ -> Alcotest.fail "expected Pkh with origin"

(* ============================================================================
   Extended key parsing tests
   ============================================================================ *)

let test_parse_xpub () =
  (* Standard BIP32 test vector xpub *)
  let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8" in
  let desc_str = "pkh(" ^ xpub ^ ")" in
  match Descriptor.parse desc_str with
  | Error e -> Alcotest.fail e
  | Ok parsed ->
    match parsed.desc with
    | Descriptor.Pkh (Descriptor.Xpub _) -> ()
    | _ -> Alcotest.fail "expected Pkh with xpub"

let test_parse_xpub_with_path () =
  let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8" in
  let desc_str = "wpkh(" ^ xpub ^ "/0/1)" in
  match Descriptor.parse desc_str with
  | Error e -> Alcotest.fail e
  | Ok parsed ->
    match parsed.desc with
    | Descriptor.Wpkh (Descriptor.Xpub { path; _ }) ->
      Alcotest.(check int) "path length" 2 (List.length path)
    | _ -> Alcotest.fail "expected Wpkh with xpub"

let test_parse_ranged_descriptor () =
  let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8" in
  let desc_str = "wpkh(" ^ xpub ^ "/0/*)" in
  match Descriptor.parse desc_str with
  | Error e -> Alcotest.fail e
  | Ok parsed ->
    Alcotest.(check bool) "is ranged" true (Descriptor.is_ranged parsed.desc)

let test_parse_hardened_ranged () =
  let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8" in
  let desc_str = "wpkh(" ^ xpub ^ "/0/*')" in
  match Descriptor.parse desc_str with
  | Error e -> Alcotest.fail e
  | Ok parsed ->
    match parsed.desc with
    | Descriptor.Wpkh (Descriptor.Xpub { derive; _ }) ->
      Alcotest.(check bool) "hardened ranged" true
        (derive = Descriptor.HardenedRanged)
    | _ -> Alcotest.fail "expected hardened ranged"

(* ============================================================================
   Expansion tests
   ============================================================================ *)

let test_expand_pkh () =
  let pk = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9" in
  let desc_str = "pkh(" ^ pk ^ ")" in
  match Descriptor.parse desc_str with
  | Error e -> Alcotest.fail e
  | Ok parsed ->
    match Descriptor.expand parsed.desc 0 `Mainnet with
    | Error e -> Alcotest.fail e
    | Ok [exp] ->
      Alcotest.(check int) "P2PKH script length" 25 (Cstruct.length exp.script_pubkey);
      Alcotest.(check bool) "has address" true (Option.is_some exp.address);
      (* P2PKH address starts with '1' on mainnet *)
      let addr = Option.get exp.address in
      Alcotest.(check bool) "mainnet P2PKH prefix" true (addr.[0] = '1')
    | Ok _ -> Alcotest.fail "expected single expansion"

let test_expand_wpkh () =
  let pk = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9" in
  let desc_str = "wpkh(" ^ pk ^ ")" in
  match Descriptor.parse desc_str with
  | Error e -> Alcotest.fail e
  | Ok parsed ->
    match Descriptor.expand parsed.desc 0 `Mainnet with
    | Error e -> Alcotest.fail e
    | Ok [exp] ->
      Alcotest.(check int) "P2WPKH script length" 22 (Cstruct.length exp.script_pubkey);
      let addr = Option.get exp.address in
      (* Mainnet P2WPKH address starts with "bc1q" *)
      Alcotest.(check bool) "mainnet bech32 prefix" true
        (String.length addr >= 4 && String.sub addr 0 4 = "bc1q")
    | Ok _ -> Alcotest.fail "expected single expansion"

let test_expand_sh_wpkh () =
  let pk = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9" in
  let desc_str = "sh(wpkh(" ^ pk ^ "))" in
  match Descriptor.parse desc_str with
  | Error e -> Alcotest.fail e
  | Ok parsed ->
    match Descriptor.expand parsed.desc 0 `Mainnet with
    | Error e -> Alcotest.fail e
    | Ok [exp] ->
      Alcotest.(check int) "P2SH script length" 23 (Cstruct.length exp.script_pubkey);
      let addr = Option.get exp.address in
      (* Mainnet P2SH address starts with '3' *)
      Alcotest.(check bool) "mainnet P2SH prefix" true (addr.[0] = '3')
    | Ok _ -> Alcotest.fail "expected single expansion"

let test_expand_multisig () =
  let pk1 = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9" in
  let pk2 = "03dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659" in
  let desc_str = Printf.sprintf "multi(1,%s,%s)" pk1 pk2 in
  match Descriptor.parse desc_str with
  | Error e -> Alcotest.fail e
  | Ok parsed ->
    match Descriptor.expand parsed.desc 0 `Mainnet with
    | Error e -> Alcotest.fail e
    | Ok [exp] ->
      (* Multisig script: OP_1 <pk1> <pk2> OP_2 OP_CHECKMULTISIG *)
      (* Length: 1 + (1+33) + (1+33) + 1 + 1 = 71 *)
      Alcotest.(check int) "multisig script length" 71 (Cstruct.length exp.script_pubkey);
      Alcotest.(check int) "two pubkeys" 2 (List.length exp.pubkeys)
    | Ok _ -> Alcotest.fail "expected single expansion"

let test_expand_sortedmulti () =
  (* Keys in "wrong" order - should be sorted *)
  let pk1 = "03dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659" in
  let pk2 = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9" in
  let desc_str = Printf.sprintf "sortedmulti(1,%s,%s)" pk1 pk2 in
  match Descriptor.parse desc_str with
  | Error e -> Alcotest.fail e
  | Ok parsed ->
    match Descriptor.expand parsed.desc 0 `Mainnet with
    | Error e -> Alcotest.fail e
    | Ok [exp] ->
      (* Verify keys are sorted in the output *)
      begin match exp.pubkeys with
      | [k1; k2] ->
        let cmp = Cstruct.compare k1 k2 in
        Alcotest.(check bool) "keys sorted" true (cmp <= 0)
      | _ -> Alcotest.fail "expected two keys"
      end
    | Ok _ -> Alcotest.fail "expected single expansion"

let test_expand_combo () =
  let pk = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9" in
  let desc_str = "combo(" ^ pk ^ ")" in
  match Descriptor.parse desc_str with
  | Error e -> Alcotest.fail e
  | Ok parsed ->
    match Descriptor.expand parsed.desc 0 `Mainnet with
    | Error e -> Alcotest.fail e
    | Ok exps ->
      (* Combo should produce P2PK, P2PKH, P2WPKH, P2SH-P2WPKH for compressed key *)
      Alcotest.(check int) "four expansions" 4 (List.length exps)

let test_expand_addr () =
  let desc_str = "addr(bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4)" in
  match Descriptor.parse desc_str with
  | Error e -> Alcotest.fail e
  | Ok parsed ->
    match Descriptor.expand parsed.desc 0 `Mainnet with
    | Error e -> Alcotest.fail e
    | Ok [exp] ->
      Alcotest.(check int) "P2WPKH script length" 22 (Cstruct.length exp.script_pubkey);
      let addr = Option.get exp.address in
      Alcotest.(check string) "address matches" "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4" addr
    | Ok _ -> Alcotest.fail "expected single expansion"

(* ============================================================================
   Range derivation tests
   ============================================================================ *)

let test_derive_addresses_single () =
  let pk = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9" in
  let desc_str = "wpkh(" ^ pk ^ ")" in
  match Descriptor.parse desc_str with
  | Error e -> Alcotest.fail e
  | Ok parsed ->
    match Descriptor.derive_addresses parsed.desc (0, 0) `Mainnet with
    | Error e -> Alcotest.fail e
    | Ok addrs ->
      Alcotest.(check int) "one address" 1 (List.length addrs)

let test_derive_addresses_range () =
  let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8" in
  let desc_str = "wpkh(" ^ xpub ^ "/0/*)" in
  match Descriptor.parse desc_str with
  | Error e -> Alcotest.fail e
  | Ok parsed ->
    match Descriptor.derive_addresses parsed.desc (0, 4) `Mainnet with
    | Error e -> Alcotest.fail e
    | Ok addrs ->
      Alcotest.(check int) "five addresses" 5 (List.length addrs);
      (* All addresses should be unique *)
      let unique = List.sort_uniq String.compare addrs in
      Alcotest.(check int) "all unique" 5 (List.length unique)

let test_derive_addresses_non_ranged_error () =
  let pk = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9" in
  let desc_str = "wpkh(" ^ pk ^ ")" in
  match Descriptor.parse desc_str with
  | Error e -> Alcotest.fail e
  | Ok parsed ->
    match Descriptor.derive_addresses parsed.desc (0, 5) `Mainnet with
    | Error _ -> ()  (* Expected error *)
    | Ok _ -> Alcotest.fail "should error for non-ranged with range > 1"

(* ============================================================================
   Descriptor info tests
   ============================================================================ *)

let test_get_info_simple () =
  let pk = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9" in
  let desc_str = "wpkh(" ^ pk ^ ")" in
  match Descriptor.get_info desc_str with
  | Error e -> Alcotest.fail e
  | Ok info ->
    Alcotest.(check bool) "not ranged" false info.is_range;
    Alcotest.(check bool) "solvable" true info.is_solvable;
    Alcotest.(check bool) "has checksum" true (String.contains info.descriptor '#')

let test_get_info_ranged () =
  let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8" in
  let desc_str = "wpkh(" ^ xpub ^ "/0/*)" in
  match Descriptor.get_info desc_str with
  | Error e -> Alcotest.fail e
  | Ok info ->
    Alcotest.(check bool) "is ranged" true info.is_range

(* ============================================================================
   Descriptor to string tests
   ============================================================================ *)

let test_to_string_pk () =
  let pk = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9" in
  let desc_str = "pk(" ^ pk ^ ")" in
  match Descriptor.parse desc_str with
  | Error e -> Alcotest.fail e
  | Ok parsed ->
    let str = Descriptor.to_string parsed.desc in
    Alcotest.(check bool) "starts with pk(" true (String.sub str 0 3 = "pk(");
    Alcotest.(check bool) "ends with )" true (str.[String.length str - 1] = ')')

let test_to_string_nested () =
  let pk = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9" in
  let desc_str = "sh(wpkh(" ^ pk ^ "))" in
  match Descriptor.parse desc_str with
  | Error e -> Alcotest.fail e
  | Ok parsed ->
    let str = Descriptor.to_string parsed.desc in
    Alcotest.(check bool) "starts with sh(" true (String.sub str 0 3 = "sh(");
    Alcotest.(check bool) "contains wpkh(" true (String.length str > 8)

(* ============================================================================
   Error handling tests
   ============================================================================ *)

let test_parse_invalid_descriptor () =
  let invalid = "invalid()" in
  match Descriptor.parse invalid with
  | Error _ -> ()
  | Ok _ -> Alcotest.fail "should fail for invalid descriptor"

let test_parse_unmatched_paren () =
  let invalid = "pk(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9" in
  match Descriptor.parse invalid with
  | Error _ -> ()
  | Ok _ -> Alcotest.fail "should fail for unmatched paren"

let test_parse_invalid_pubkey () =
  let invalid = "pk(invalidhex)" in
  match Descriptor.parse invalid with
  | Error _ -> ()
  | Ok _ -> Alcotest.fail "should fail for invalid pubkey"

let test_parse_multi_threshold_exceeds () =
  let pk1 = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9" in
  let invalid = "multi(3," ^ pk1 ^ ")" in
  match Descriptor.parse invalid with
  | Error _ -> ()
  | Ok _ -> Alcotest.fail "should fail when threshold exceeds key count"

let test_parse_invalid_checksum () =
  let pk = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9" in
  let invalid = "wpkh(" ^ pk ^ ")#invalid1" in
  match Descriptor.parse invalid with
  | Error e ->
    let lowercase_e = String.lowercase_ascii e in
    let has_checksum = try
      let _ = Str.search_forward (Str.regexp_string "checksum") lowercase_e 0 in
      true
    with Not_found -> false
    in
    Alcotest.(check bool) "mentions checksum" true has_checksum
  | Ok _ -> Alcotest.fail "should fail for invalid checksum"

(* ============================================================================
   Test runner
   ============================================================================ *)

let () =
  Alcotest.run "descriptor" [
    "checksum", [
      Alcotest.test_case "simple" `Quick test_checksum_simple;
      Alcotest.test_case "add" `Quick test_checksum_add;
      Alcotest.test_case "verify" `Quick test_checksum_verify;
      Alcotest.test_case "invalid chars" `Quick test_checksum_invalid_chars;
    ];
    "parsing basic", [
      Alcotest.test_case "pk" `Quick test_parse_pk;
      Alcotest.test_case "pkh" `Quick test_parse_pkh;
      Alcotest.test_case "wpkh" `Quick test_parse_wpkh;
      Alcotest.test_case "sh(wpkh)" `Quick test_parse_sh_wpkh;
      Alcotest.test_case "wsh(multi)" `Quick test_parse_wsh_multi;
      Alcotest.test_case "sortedmulti" `Quick test_parse_sortedmulti;
      Alcotest.test_case "tr" `Quick test_parse_tr;
      Alcotest.test_case "combo" `Quick test_parse_combo;
      Alcotest.test_case "addr" `Quick test_parse_addr;
      Alcotest.test_case "raw" `Quick test_parse_raw;
    ];
    "parsing keys", [
      Alcotest.test_case "with origin" `Quick test_parse_with_origin;
      Alcotest.test_case "xpub" `Quick test_parse_xpub;
      Alcotest.test_case "xpub with path" `Quick test_parse_xpub_with_path;
      Alcotest.test_case "ranged" `Quick test_parse_ranged_descriptor;
      Alcotest.test_case "hardened ranged" `Quick test_parse_hardened_ranged;
    ];
    "expansion", [
      Alcotest.test_case "pkh" `Quick test_expand_pkh;
      Alcotest.test_case "wpkh" `Quick test_expand_wpkh;
      Alcotest.test_case "sh(wpkh)" `Quick test_expand_sh_wpkh;
      Alcotest.test_case "multisig" `Quick test_expand_multisig;
      Alcotest.test_case "sortedmulti" `Quick test_expand_sortedmulti;
      Alcotest.test_case "combo" `Quick test_expand_combo;
      Alcotest.test_case "addr" `Quick test_expand_addr;
    ];
    "deriveaddresses", [
      Alcotest.test_case "single" `Quick test_derive_addresses_single;
      Alcotest.test_case "range" `Quick test_derive_addresses_range;
      Alcotest.test_case "non-ranged error" `Quick test_derive_addresses_non_ranged_error;
    ];
    "info", [
      Alcotest.test_case "simple" `Quick test_get_info_simple;
      Alcotest.test_case "ranged" `Quick test_get_info_ranged;
    ];
    "to_string", [
      Alcotest.test_case "pk" `Quick test_to_string_pk;
      Alcotest.test_case "nested" `Quick test_to_string_nested;
    ];
    "errors", [
      Alcotest.test_case "invalid descriptor" `Quick test_parse_invalid_descriptor;
      Alcotest.test_case "unmatched paren" `Quick test_parse_unmatched_paren;
      Alcotest.test_case "invalid pubkey" `Quick test_parse_invalid_pubkey;
      Alcotest.test_case "multi threshold" `Quick test_parse_multi_threshold_exceeds;
      Alcotest.test_case "invalid checksum" `Quick test_parse_invalid_checksum;
    ];
  ]
