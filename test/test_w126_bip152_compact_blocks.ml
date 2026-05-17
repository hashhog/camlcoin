(* W126 audit — BIP-152 Compact Block Relay (camlcoin)

   Reference: bitcoin-core/src/blockencodings.{h,cpp} +
              bitcoin-core/src/net_processing.cpp
              (SENDCMPCT / CMPCTBLOCK / GETBLOCKTXN / BLOCKTXN handlers +
               MAX_CMPCTBLOCK_DEPTH=5 / MAX_BLOCKTXN_DEPTH=10 /
               CMPCTBLOCKS_VERSION=2 / SHORT_IDS_BLOCKS_VERSION=70014 /
               MaybeSetPeerAsAnnouncingHeaderAndIDs / NewPoWValidBlock).

   30 audit gates classifying each gate PRESENT / PARTIAL / MISSING with
   camlcoin code references.  Tests are source-marker style — they read
   lib/p2p.ml / lib/peer.ml / lib/peer_manager.ml / lib/sync.ml /
   lib/cli.ml / lib/crypto.ml at runtime and assert the static shape that
   the audit verdict captures.  PRESENT tests assert the present-shape;
   PARTIAL / MISSING tests assert the bug-pre-fix shape that BUG-N would
   flip — i.e. they fail when the corresponding fix lands, signalling
   the audit gate was closed.

   See audit/w126_bip152_compact_blocks.md for the full write-up.

   Build:
     dune build && _build/default/test/test_w126_bip152_compact_blocks.exe

   Avoid `dune runtest` (FIX-64 / FIX-80 dune-lock-contention lessons).
   ============================================================================ *)

open Camlcoin

(* ============================================================================
   Source-marker helpers
   ============================================================================ *)

let read_file path =
  let ic = open_in path in
  let n = in_channel_length ic in
  let buf = Bytes.create n in
  really_input ic buf 0 n;
  close_in ic;
  Bytes.to_string buf

let resolve_repo_root () =
  let rec up dir depth =
    if depth > 10 then
      Alcotest.fail "could not locate camlcoin repo root from CWD"
    else if Sys.file_exists (Filename.concat dir "lib/p2p.ml") then dir
    else up (Filename.dirname dir) (depth + 1)
  in
  up (Sys.getcwd ()) 0

let slurp_lib (rel : string) : string =
  read_file (Filename.concat (resolve_repo_root ()) ("lib/" ^ rel))

let contains_substring haystack needle =
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

(* Extract the body of a top-level function for ~scope-local asserts. *)
let extract_function_body ~src ~prefix ~max_chars =
  try
    let i = Str.search_forward (Str.regexp_string prefix) src 0 in
    String.sub src i (min max_chars (String.length src - i))
  with Not_found -> ""

(* ============================================================================
   G1: Inv-type MSG_CMPCT_BLOCK = 4 — PRESENT
   ============================================================================ *)

let g1_inv_compact_block_value () =
  let src = slurp_lib "p2p.ml" in
  Alcotest.(check bool)
    "G1: InvCompactBlock encodes to 4l on the wire"
    true (contains_substring src "| InvCompactBlock -> 4l");
  Alcotest.(check bool)
    "G1: 4l decodes back to InvCompactBlock"
    true (contains_substring src "| 4l -> InvCompactBlock")

(* ============================================================================
   G2: Message-type wire names — PRESENT
   ============================================================================ *)

let g2_message_type_wire_names () =
  let src = slurp_lib "p2p.ml" in
  Alcotest.(check bool)
    "G2: \"sendcmpct\" wire name"
    true (contains_substring src "| Sendcmpct -> \"sendcmpct\"");
  Alcotest.(check bool)
    "G2: \"cmpctblock\" wire name"
    true (contains_substring src "| Cmpctblock -> \"cmpctblock\"");
  Alcotest.(check bool)
    "G2: \"getblocktxn\" wire name"
    true (contains_substring src "| Getblocktxn -> \"getblocktxn\"");
  Alcotest.(check bool)
    "G2: \"blocktxn\" wire name"
    true (contains_substring src "| Blocktxn -> \"blocktxn\"")

(* ============================================================================
   G3: Cmpctblock/Getblocktxn/Blocktxn variants exist + serialize — PRESENT
   ============================================================================ *)

let g3_compact_block_variants_present () =
  let src = slurp_lib "p2p.ml" in
  Alcotest.(check bool)
    "G3: CmpctblockMsg variant in message_payload"
    true (contains_substring src "| CmpctblockMsg of compact_block");
  Alcotest.(check bool)
    "G3: GetblocktxnMsg variant"
    true (contains_substring src "| GetblocktxnMsg of block_txns_request");
  Alcotest.(check bool)
    "G3: BlocktxnMsg variant"
    true (contains_substring src "| BlocktxnMsg of block_txns");
  Alcotest.(check bool)
    "G3: serialize_compact_block defined"
    true (contains_substring src "let serialize_compact_block w (cb :")

(* ============================================================================
   G4: Prefilled-tx differential encoding — PARTIAL (uint16 range unenforced
   on serialize-side; soft P3)
   ============================================================================ *)

let g4_prefilled_tx_differential_encoding () =
  let src = slurp_lib "p2p.ml" in
  (* The differential encoding helper itself is present. *)
  Alcotest.(check bool)
    "G4: serialize_prefilled_tx writes compact_size index then tx"
    true (contains_substring src "Serialize.write_compact_size w ptx.index");
  (* PARTIAL: there is no explicit uint16 range check on the serialize
     side; the field is an OCaml [int].  Soft P3 — Core stores as
     [uint16_t] (blockencodings.h:77) and would reject on overflow at
     parse time.  Verify the field type is unqualified [int]. *)
  Alcotest.(check bool)
    "G4 PARTIAL: prefilled_tx.index is plain OCaml int (no uint16 bound)"
    true (contains_substring src "index : int;        (* differential index from last prefilled tx *)")

(* ============================================================================
   G5: Short-id is 6-byte (48-bit) lower bits — PRESENT
   ============================================================================ *)

let g5_short_id_48_bit_mask () =
  let src = slurp_lib "crypto.ml" in
  Alcotest.(check bool)
    "G5: compute_short_txid masks to lower 48 bits (0xFFFFFFFFFFFFL)"
    true (contains_substring src "Int64.logand hash 0xFFFFFFFFFFFFL")

(* ============================================================================
   G6: SENDCMPCT sent on handshake completion + SHORT_IDS_BLOCKS_VERSION gate
   — PARTIAL  (no protocol-version gate; BUG-5 P2)
   ============================================================================ *)

let g6_sendcmpct_sent_unconditionally_bug () =
  let src = slurp_lib "peer.ml" in
  (* Outbound + inbound handshake unconditionally send make_sendcmpct_msg. *)
  Alcotest.(check bool)
    "G6 baseline: outbound handshake sends sendcmpct"
    true (contains_substring src
            "let* () = send_message peer (P2p.make_sendcmpct_msg ~high_bandwidth:false) in");
  (* BUG-5 pre-fix marker: no protocol-version gate around the send. *)
  Alcotest.(check bool)
    "BUG-5 (pre-fix): handshake does NOT gate sendcmpct on SHORT_IDS_BLOCKS_VERSION"
    false (contains_substring src "SHORT_IDS_BLOCKS_VERSION");
  Alcotest.(check bool)
    "BUG-5 (pre-fix): handshake does NOT gate sendcmpct on 70014"
    false (contains_substring src ">= 70014" || contains_substring src "70014")

(* ============================================================================
   G7: SENDCMPCT with v != 2 silently dropped — PRESENT (FIX-43)
   ============================================================================ *)

let g7_sendcmpct_v_ne_2_dropped () =
  let src = slurp_lib "peer.ml" in
  (* All 3 SendcmpctMsg arms (read_until_verack, pre-handshake, post-
     handshake) check `version = 2L` before mutating peer state. *)
  let count_v2_guards =
    let h = src in
    let n = "if version = 2L then" in
    let hs = String.length h in
    let ns = String.length n in
    let rec scan i acc =
      if i + ns > hs then acc
      else if String.sub h i ns = n then scan (i + ns) (acc + 1)
      else scan (i + 1) acc
    in
    scan 0 0
  in
  Alcotest.(check bool)
    "G7 FIX-43: every SendcmpctMsg arm gated on `version = 2L`"
    true (count_v2_guards >= 2)

(* ============================================================================
   G8: nonce uses CSPRNG (/dev/urandom) — PRESENT (FIX-49)
   ============================================================================ *)

let g8_nonce_csprng () =
  let src = slurp_lib "p2p.ml" in
  Alcotest.(check bool)
    "G8 FIX-49: generate_compact_nonce opens /dev/urandom"
    true (contains_substring src "open_in_bin \"/dev/urandom\"");
  Alcotest.(check bool)
    "G8: generate_compact_nonce NOT using Random.int64"
    false
    (* Search inside the generate_compact_nonce body specifically. *)
    (let body = extract_function_body ~src
                  ~prefix:"let generate_compact_nonce" ~max_chars:600 in
     contains_substring body "Random.int64")

(* ============================================================================
   G9: SipHash keys = single-SHA256(serialize(header) || nonce_le); k0 = first
   8 bytes, k1 = second 8 bytes — PRESENT
   ============================================================================ *)

let g9_siphash_key_derivation_correct () =
  let src = slurp_lib "crypto.ml" in
  let body = extract_function_body ~src
               ~prefix:"let derive_keys (header :" ~max_chars:800 in
  Alcotest.(check bool)
    "G9: derive_keys serializes block_header (80 bytes)"
    true (contains_substring body "Serialize.serialize_block_header w header");
  Alcotest.(check bool)
    "G9: nonce written as little-endian uint64"
    true (contains_substring body "Cstruct.LE.set_uint64 nonce_cs 0 nonce");
  Alcotest.(check bool)
    "G9: hash = single sha256 over preimage"
    true (contains_substring body "let hash = sha256 preimage");
  Alcotest.(check bool)
    "G9: k0 = first 8 bytes"
    true (contains_substring body "let k0 = get_uint64_le hash 0");
  Alcotest.(check bool)
    "G9: k1 = second 8 bytes"
    true (contains_substring body "let k1 = get_uint64_le hash 8")

(* Functional spot-check: derive_keys is deterministic + produces non-zero
   keys for a representative header/nonce pair.  Functional rather than
   source-marker because the math is well-defined. *)
let g9_siphash_key_derivation_functional () =
  let header : Types.block_header =
    { Types.version = 0x20000000l;
      prev_block = Types.zero_hash;
      merkle_root = Types.zero_hash;
      timestamp = 1600000000l;
      bits = 0x1d00ffffl;
      nonce = 0l;
    }
  in
  let (k0a, k1a) = Crypto.SipHash.derive_keys header 0xdeadbeefL in
  let (k0b, k1b) = Crypto.SipHash.derive_keys header 0xdeadbeefL in
  Alcotest.(check bool) "G9 deterministic k0" true (Int64.equal k0a k0b);
  Alcotest.(check bool) "G9 deterministic k1" true (Int64.equal k1a k1b);
  Alcotest.(check bool) "G9 non-zero k0" true (not (Int64.equal k0a 0L));
  Alcotest.(check bool) "G9 non-zero k1" true (not (Int64.equal k1a 0L));
  (* Different nonce → different keys (proves nonce mixes in). *)
  let (k0c, _) = Crypto.SipHash.derive_keys header 0xcafebabeL in
  Alcotest.(check bool) "G9 nonce mixes into k0" true
    (not (Int64.equal k0a k0c))

(* ============================================================================
   G10: short-id computed over wtxid (not txid) — PRESENT
   ============================================================================ *)

let g10_short_id_uses_wtxid () =
  let src = slurp_lib "p2p.ml" in
  let body = extract_function_body ~src
               ~prefix:"let create_compact_block" ~max_chars:1500 in
  Alcotest.(check bool)
    "G10: create_compact_block calls Crypto.compute_wtxid"
    true (contains_substring body "Crypto.compute_wtxid tx");
  Alcotest.(check bool)
    "G10: short_id derived from wtxid via compute_short_txid"
    true (contains_substring body "Crypto.compute_short_txid k0 k1 wtxid")

(* ============================================================================
   G11: coinbase always prefilled at index 0 — PRESENT
   ============================================================================ *)

let g11_coinbase_always_prefilled () =
  let src = slurp_lib "p2p.ml" in
  let body = extract_function_body ~src
               ~prefix:"let create_compact_block" ~max_chars:1500 in
  Alcotest.(check bool)
    "G11: coinbase = List.hd block.transactions"
    true (contains_substring body "let coinbase = List.hd block.transactions");
  Alcotest.(check bool)
    "G11: prefilled_txs = [{ index = 0; tx = coinbase }]"
    true (contains_substring body "{ index = 0; tx = coinbase }")

(* ============================================================================
   G12: short_ids covers non-coinbase txs only — PRESENT
   ============================================================================ *)

let g12_short_ids_skip_coinbase () =
  let src = slurp_lib "p2p.ml" in
  let body = extract_function_body ~src
               ~prefix:"let create_compact_block" ~max_chars:1500 in
  Alcotest.(check bool)
    "G12: i = 0 short-id is None (coinbase skipped)"
    true (contains_substring body "if i = 0 then None")

(* ============================================================================
   G13: BlockTxCount = short_ids + prefilled — PRESENT
   ============================================================================ *)

let g13_block_tx_count_helper () =
  let src = slurp_lib "p2p.ml" in
  let body = extract_function_body ~src
               ~prefix:"let compact_block_tx_count" ~max_chars:400 in
  Alcotest.(check bool)
    "G13: compact_block_tx_count returns List.length cb.short_ids + List.length cb.prefilled_txs"
    true (contains_substring body
            "List.length cb.short_ids + List.length cb.prefilled_txs")

(* ============================================================================
   G14: reconstruct InitData prefilled-index < tx_count — PRESENT
   (W112 Bug #4 fix)
   ============================================================================ *)

let g14_prefilled_index_bounded () =
  let src = slurp_lib "p2p.ml" in
  let body = extract_function_body ~src
               ~prefix:"let reconstruct_block" ~max_chars:4000 in
  Alcotest.(check bool)
    "G14: reconstruct propagates abs_idx >= tx_count as a failure"
    true (contains_substring body "if abs_idx >= tx_count then");
  Alcotest.(check bool)
    "G14: ReconstructFailed \"compact block prefilled index out of range\""
    true (contains_substring body "ReconstructFailed \"compact block prefilled index out of range\"")

(* ============================================================================
   G15: short-ID collision → both treated as missing — PRESENT
   (W112 Bug #2 fix)
   ============================================================================ *)

let g15_short_id_collision_marked_missing () =
  let src = slurp_lib "p2p.ml" in
  let body = extract_function_body ~src
               ~prefix:"let reconstruct_block" ~max_chars:5000 in
  Alcotest.(check bool)
    "G15: have_txn[] tracks first match"
    true (contains_substring body "let have_txn = Array.make tx_count false");
  Alcotest.(check bool)
    "G15: on second match, clear slot and add to missing[]"
    true (contains_substring body "missing := i :: !missing")

(* ============================================================================
   G16: getblocktxn indexes use differential encoding — PRESENT
   ============================================================================ *)

let g16_getblocktxn_differential_encoding () =
  let src = slurp_lib "p2p.ml" in
  Alcotest.(check bool)
    "G16: make_getblocktxn_request defined"
    true (contains_substring src "let make_getblocktxn_request");
  Alcotest.(check bool)
    "G16: decode_differential_indices defined"
    true (contains_substring src "let decode_differential_indices");
  let mk_body = extract_function_body ~src
                  ~prefix:"let make_getblocktxn_request" ~max_chars:800 in
  Alcotest.(check bool)
    "G16: make_getblocktxn_request sorts before differential encoding"
    true (contains_substring mk_body "let sorted = List.sort compare missing")

(* ============================================================================
   G17: getblocktxn responds within MAX_BLOCKTXN_DEPTH=10 of tip — PRESENT
   (FIX-42)
   ============================================================================ *)

let g17_getblocktxn_depth_guard () =
  let src_p2p = slurp_lib "p2p.ml" in
  Alcotest.(check bool)
    "G17 FIX-42: max_blocktxn_depth = 10 declared"
    true (contains_substring src_p2p "let max_blocktxn_depth = 10");
  let src_cli = slurp_lib "cli.ml" in
  Alcotest.(check bool)
    "G17 FIX-42: cli.ml GetblocktxnMsg arm consults max_blocktxn_depth"
    true (contains_substring src_cli "P2p.max_blocktxn_depth")

(* ============================================================================
   G18: blocktxn fill_missing fills slots, errors on remaining None — PRESENT
   ============================================================================ *)

let g18_blocktxn_fill_missing_completeness () =
  let src = slurp_lib "p2p.ml" in
  let body = extract_function_body ~src
               ~prefix:"let fill_missing_txs" ~max_chars:1200 in
  Alcotest.(check bool)
    "G18: fill_missing_txs checks all_filled = Array.for_all"
    true (contains_substring body "let all_filled = Array.for_all (fun x -> x <> None) partial_txs");
  Alcotest.(check bool)
    "G18: returns Error \"not all transactions filled\" on incomplete fill"
    true (contains_substring body "Error \"not all transactions filled\"")

(* ============================================================================
   G19: BlocktxnMsg arm gated on LoadingBlocks/IBD — MISSING (BUG-7 P2)
   ============================================================================ *)

let g19_blocktxn_no_loading_blocks_gate () =
  let src = slurp_lib "cli.ml" in
  (* Find the BlocktxnMsg listener arm and verify it has no IBD/
     FullySynced/LoadingBlocks guard. *)
  let body = extract_function_body ~src
               ~prefix:"| P2p.BlocktxnMsg resp ->" ~max_chars:1500 in
  Alcotest.(check bool)
    "G19 baseline: BlocktxnMsg arm body present"
    true (String.length body > 0);
  (* BUG-7 pre-fix marker: the arm head is the bare pattern with no
     when-guard.  Core would gate on LoadingBlocks. *)
  Alcotest.(check bool)
    "BUG-7 (pre-fix): BlocktxnMsg arm has no `when` guard for IBD/LoadingBlocks"
    false (contains_substring src
             "| P2p.BlocktxnMsg resp when chain.sync_state = Sync.FullySynced");
  Alcotest.(check bool)
    "BUG-7 (pre-fix): no LoadingBlocks-equivalent check in cli.ml BlocktxnMsg arm"
    false (contains_substring body "LoadingBlocks")

(* ============================================================================
   G20: GetblocktxnMsg arm gated on LoadingBlocks/IBD — MISSING (BUG-7 P2)
   ============================================================================ *)

let g20_getblocktxn_no_loading_blocks_gate () =
  let src = slurp_lib "cli.ml" in
  let body = extract_function_body ~src
               ~prefix:"| P2p.GetblocktxnMsg req ->" ~max_chars:2500 in
  Alcotest.(check bool)
    "G20 baseline: GetblocktxnMsg arm body present"
    true (String.length body > 0);
  Alcotest.(check bool)
    "BUG-7 (pre-fix): GetblocktxnMsg arm has no `when` guard for IBD/LoadingBlocks"
    false (contains_substring src
             "| P2p.GetblocktxnMsg req when chain.sync_state = Sync.FullySynced")

(* ============================================================================
   G21: CmpctblockMsg arm gates on FullySynced — PRESENT
   ============================================================================ *)

let g21_cmpctblock_fullysynced_gate () =
  let src = slurp_lib "cli.ml" in
  Alcotest.(check bool)
    "G21: CmpctblockMsg arm has `when chain.sync_state = Sync.FullySynced`"
    true (contains_substring src
            "| P2p.CmpctblockMsg cb when chain.sync_state = Sync.FullySynced")

(* ============================================================================
   G22: reconstruct consults extra_txn pool — MISSING (BUG-6 P2)
   ============================================================================ *)

let g22_no_extra_txn_pool_bug () =
  let src_pm = slurp_lib "peer_manager.ml" in
  let src_cli = slurp_lib "cli.ml" in
  (* BUG-6 pre-fix markers: no vExtraTxnForCompact-equivalent storage,
     no extra_txn pool consulted during reconstruction. *)
  Alcotest.(check bool)
    "BUG-6 (pre-fix): peer_manager.ml has no extra_txn pool field"
    false (contains_substring src_pm "extra_txn_for_compact"
        || contains_substring src_pm "vExtraTxnForCompact"
        || contains_substring src_pm "extra_compact_tx");
  Alcotest.(check bool)
    "BUG-6 (pre-fix): cli.ml reconstruct call only consults mempool"
    true (contains_substring src_cli
            "Peer_manager.reconstruct_from_mempool peer_manager cb");
  (* Functional check: reconstruct_from_mempool API takes only the
     compact block, not an extra_txn list parameter. *)
  let src = slurp_lib "peer_manager.ml" in
  let body = extract_function_body ~src
               ~prefix:"let reconstruct_from_mempool" ~max_chars:600 in
  Alcotest.(check bool)
    "BUG-6 (pre-fix): reconstruct_from_mempool signature has no extra_txn parameter"
    false (contains_substring body "extra_txn" || contains_substring body "~extra")

(* ============================================================================
   G23: reconstruct → GETBLOCKTXN round-trip on missing indices — PRESENT
   ============================================================================ *)

let g23_reconstruct_round_trip () =
  let src = slurp_lib "cli.ml" in
  Alcotest.(check bool)
    "G23: ReconstructNeedTxs branch makes getblocktxn request"
    true (contains_substring src
            "let req = P2p.make_getblocktxn_request header_hash missing");
  Alcotest.(check bool)
    "G23: getblocktxn message sent to source peer"
    true (contains_substring src "let getblocktxn_msg = P2p.make_getblocktxn_msg req")

(* ============================================================================
   G24: InvCompactBlock served via getdata within MAX_CMPCTBLOCK_DEPTH=5 —
   PRESENT (FIX-42)
   ============================================================================ *)

let g24_inv_compact_block_served_with_depth_guard () =
  let src_p2p = slurp_lib "p2p.ml" in
  Alcotest.(check bool)
    "G24 FIX-42: max_cmpctblock_depth = 5 declared"
    true (contains_substring src_p2p "let max_cmpctblock_depth = 5");
  let src_peer = slurp_lib "peer.ml" in
  let body = extract_function_body ~src:src_peer
               ~prefix:"| P2p.InvCompactBlock ->" ~max_chars:1500 in
  Alcotest.(check bool)
    "G24: InvCompactBlock branch in handle_getdata"
    true (String.length body > 0);
  Alcotest.(check bool)
    "G24: branch consults max_cmpctblock_depth"
    true (contains_substring body "P2p.max_cmpctblock_depth")

(* ============================================================================
   G25: Recent-block cache for serving subsequent getblocktxn — PARTIAL
   (BUG-9 P3 — re-runs create_compact_block per request)
   ============================================================================ *)

let g25_no_recent_compact_block_cache_bug () =
  let src_peer = slurp_lib "peer.ml" in
  let src_pm   = slurp_lib "peer_manager.ml" in
  (* BUG-9 pre-fix marker: no cache field for m_most_recent_compact_block-
     equivalent on peer_manager. *)
  Alcotest.(check bool)
    "BUG-9 (pre-fix): peer_manager.ml has no most_recent_compact_block field"
    false (contains_substring src_pm "most_recent_compact_block"
        || contains_substring src_pm "m_most_recent_compact_block"
        || contains_substring src_pm "cached_cmpctblock");
  (* InvCompactBlock service calls P2p.create_compact_block inline, every
     time. *)
  let body = extract_function_body ~src:src_peer
               ~prefix:"| P2p.InvCompactBlock ->" ~max_chars:1500 in
  Alcotest.(check bool)
    "BUG-9 (pre-fix): InvCompactBlock service re-runs P2p.create_compact_block per request"
    true (contains_substring body "P2p.create_compact_block block")

(* ============================================================================
   G26: maybe_set_hb_compact_peer (3-slot list, outbound-pref, evict-front)
   — PARTIAL (BUG-2 P1: helper defined but never called)
   ============================================================================ *)

let g26_maybe_set_hb_compact_peer_dead_helper () =
  let src = slurp_lib "peer_manager.ml" in
  (* Helper is well-engineered: 3-slot cap, outbound preference, evict
     front-of-list.  We assert it is present in source. *)
  Alcotest.(check bool)
    "G26 baseline: maybe_set_hb_compact_peer defined"
    true (contains_substring src "let maybe_set_hb_compact_peer (pm : t)");
  Alcotest.(check bool)
    "G26 baseline: max_hb_compact_peers = 3"
    true (contains_substring src "let max_hb_compact_peers = 3");
  (* BUG-2 marker: count call sites in lib/ + bin/.  Definition itself
     should be the only occurrence in peer_manager.ml. *)
  let count_calls_in_file path =
    let s = read_file path in
    let n = "maybe_set_hb_compact_peer" in
    let hs = String.length s in
    let ns = String.length n in
    let rec scan i acc =
      if i + ns > hs then acc
      else if String.sub s i ns = n then scan (i + ns) (acc + 1)
      else scan (i + 1) acc
    in
    scan 0 0
  in
  let n_pm = count_calls_in_file
               (Filename.concat (resolve_repo_root ()) "lib/peer_manager.ml") in
  let main_path =
    Filename.concat (resolve_repo_root ()) "bin/main.ml" in
  let n_main = if Sys.file_exists main_path then count_calls_in_file main_path else 0 in
  let cli_path =
    Filename.concat (resolve_repo_root ()) "lib/cli.ml" in
  let n_cli = count_calls_in_file cli_path in
  let sync_path =
    Filename.concat (resolve_repo_root ()) "lib/sync.ml" in
  let n_sync = count_calls_in_file sync_path in
  let peer_path =
    Filename.concat (resolve_repo_root ()) "lib/peer.ml" in
  let n_peer = count_calls_in_file peer_path in
  (* peer_manager.ml has 3 occurrences: definition + 2 comment lines.
     Anywhere else should be 0. *)
  Alcotest.(check int)
    "BUG-2 (pre-fix): maybe_set_hb_compact_peer NOT called from bin/main.ml"
    0 n_main;
  Alcotest.(check int)
    "BUG-2 (pre-fix): maybe_set_hb_compact_peer NOT called from lib/cli.ml"
    0 n_cli;
  Alcotest.(check int)
    "BUG-2 (pre-fix): maybe_set_hb_compact_peer NOT called from lib/sync.ml"
    0 n_sync;
  Alcotest.(check int)
    "BUG-2 (pre-fix): maybe_set_hb_compact_peer NOT called from lib/peer.ml"
    0 n_peer;
  (* Sanity: definition is present. *)
  Alcotest.(check bool)
    "BUG-2 (pre-fix): peer_manager.ml has the definition + comment references"
    true (n_pm >= 1)

(* ============================================================================
   G27: maybe_set_hb_compact_peer call-site at block-validated hook — MISSING
   (BUG-2 P1; same finding as G26, cataloguing the call-graph gap)
   ============================================================================ *)

let g27_no_block_validated_callout () =
  let src_sync = slurp_lib "sync.ml" in
  let src_cli  = slurp_lib "cli.ml" in
  let src_pm   = slurp_lib "peer_manager.ml" in
  (* No NewPoWValidBlock-style hook anywhere. *)
  Alcotest.(check bool)
    "BUG-2 (pre-fix): no NewPoWValidBlock-equivalent helper in sync.ml"
    false (contains_substring src_sync "NewPoWValidBlock"
        || contains_substring src_sync "new_pow_valid_block"
        || contains_substring src_sync "fast_announce_compact_block");
  Alcotest.(check bool)
    "BUG-2 (pre-fix): no map_block_source equivalent"
    false (contains_substring src_pm "map_block_source"
        || contains_substring src_pm "mapBlockSource"
        || contains_substring src_pm "block_source_map");
  (* cli.ml process_new_block does not call maybe_set_hb_compact_peer. *)
  Alcotest.(check bool)
    "BUG-2 (pre-fix): cli.ml does not wire process_new_block to HB-peer setup"
    false (contains_substring src_cli "maybe_set_hb_compact_peer")

(* ============================================================================
   G28: HB-announce CmpctblockMsg sent on local block discovery — MISSING
   (BUG-1 P0-CDIV)
   ============================================================================ *)

let g28_announce_block_no_cmpctblock_path () =
  let src = slurp_lib "peer_manager.ml" in
  let body = extract_function_body ~src
               ~prefix:"let announce_block (pm : t)" ~max_chars:2000 in
  (* announce_block exists and is the production block-announce path. *)
  Alcotest.(check bool)
    "G28 baseline: announce_block body has HeadersMsg branch"
    true (contains_substring body "P2p.HeadersMsg [header]");
  Alcotest.(check bool)
    "G28 baseline: announce_block body has InvMsg fallback"
    true (contains_substring body "P2p.InvMsg");
  (* BUG-1 P0-CDIV: announce_block must NOT push CmpctblockMsg. *)
  Alcotest.(check bool)
    "BUG-1 P0-CDIV (pre-fix): announce_block does NOT push CmpctblockMsg \
                              (HB fast-announce broken)"
    false (contains_substring body "CmpctblockMsg"
        || contains_substring body "make_cmpctblock_msg"
        || contains_substring body "relay_compact_block");
  (* And cli.ml never calls relay_compact_block either. *)
  let src_cli = slurp_lib "cli.ml" in
  Alcotest.(check bool)
    "BUG-1 P0-CDIV (pre-fix): cli.ml never calls relay_compact_block"
    false (contains_substring src_cli "relay_compact_block")

(* ============================================================================
   G29: relay_compact_block called from new-block hook — MISSING (BUG-3 P1)
   ============================================================================ *)

let g29_relay_compact_block_dead_helper () =
  let count_calls_in_file path =
    if not (Sys.file_exists path) then 0
    else
      let s = read_file path in
      let n = "relay_compact_block" in
      let hs = String.length s in
      let ns = String.length n in
      let rec scan i acc =
        if i + ns > hs then acc
        else if String.sub s i ns = n then scan (i + ns) (acc + 1)
        else scan (i + 1) acc
      in
      scan 0 0
  in
  let root = resolve_repo_root () in
  let n_pm   = count_calls_in_file (Filename.concat root "lib/peer_manager.ml") in
  let n_cli  = count_calls_in_file (Filename.concat root "lib/cli.ml") in
  let n_sync = count_calls_in_file (Filename.concat root "lib/sync.ml") in
  let n_peer = count_calls_in_file (Filename.concat root "lib/peer.ml") in
  let n_main = count_calls_in_file (Filename.concat root "bin/main.ml") in
  (* peer_manager.ml has 2 occurrences: definition + comment. *)
  Alcotest.(check bool)
    "G29 baseline: relay_compact_block definition is present in peer_manager.ml"
    true (n_pm >= 1);
  Alcotest.(check int)
    "BUG-3 (pre-fix): relay_compact_block NOT called from lib/cli.ml"
    0 n_cli;
  Alcotest.(check int)
    "BUG-3 (pre-fix): relay_compact_block NOT called from lib/sync.ml"
    0 n_sync;
  Alcotest.(check int)
    "BUG-3 (pre-fix): relay_compact_block NOT called from lib/peer.ml"
    0 n_peer;
  Alcotest.(check int)
    "BUG-3 (pre-fix): relay_compact_block NOT called from bin/main.ml"
    0 n_main

(* ============================================================================
   G30: peer_has_header consulted before HB-relay (skip peers missing parent
   header) — PARTIAL (BUG-4 P1; stub returns true)
   ============================================================================ *)

let g30_peer_has_header_stub () =
  let src = slurp_lib "sync.ml" in
  let body = extract_function_body ~src
               ~prefix:"let peer_has_header" ~max_chars:400 in
  (* Baseline: helper exists. *)
  Alcotest.(check bool)
    "G30 baseline: peer_has_header defined in sync.ml"
    true (String.length body > 0);
  (* BUG-4 pre-fix marker: stub returns true unconditionally — no
     pindexBestKnownBlock-equivalent tracking. *)
  Alcotest.(check bool)
    "BUG-4 (pre-fix): peer_has_header body is the stub returning true"
    true (contains_substring body "true");
  Alcotest.(check bool)
    "BUG-4 (pre-fix): no per-peer best-known-block tracking referenced"
    false (contains_substring body "best_known_block"
        || contains_substring body "pindexBestKnown"
        || contains_substring body "Hashtbl.find");
  (* Functional spot-check via the public API. *)
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let peer = Peer.make_peer ~network:Consensus.mainnet ~addr:"127.0.0.1"
    ~port:8333 ~id:777 ~direction:Peer.Outbound ~fd () in
  let result = Sync.peer_has_header peer Types.zero_hash in
  Alcotest.(check bool)
    "BUG-4 (pre-fix): peer_has_header returns true for arbitrary peer/hash"
    true result;
  (* Cleanup the FD so we don't leak it. *)
  (try Lwt_main.run (Lwt_unix.close fd) with _ -> ())

(* ============================================================================
   Test registration
   ============================================================================ *)

let wire_tests = [
  Alcotest.test_case "G1 InvCompactBlock value = 4"      `Quick g1_inv_compact_block_value;
  Alcotest.test_case "G2 message-type wire names"        `Quick g2_message_type_wire_names;
  Alcotest.test_case "G3 cmpctblock/getblocktxn/blocktxn variants"
                                                         `Quick g3_compact_block_variants_present;
  Alcotest.test_case "G4 prefilled-tx differential encoding (uint16)"
                                                         `Quick g4_prefilled_tx_differential_encoding;
  Alcotest.test_case "G5 short-id 48-bit mask"           `Quick g5_short_id_48_bit_mask;
]

let siphash_tests = [
  Alcotest.test_case "G6/BUG-5 SENDCMPCT not version-gated"
                                                         `Quick g6_sendcmpct_sent_unconditionally_bug;
  Alcotest.test_case "G7 FIX-43 SENDCMPCT v != 2 dropped" `Quick g7_sendcmpct_v_ne_2_dropped;
  Alcotest.test_case "G8 FIX-49 nonce CSPRNG"             `Quick g8_nonce_csprng;
  Alcotest.test_case "G9 SipHash key derivation source"   `Quick g9_siphash_key_derivation_correct;
  Alcotest.test_case "G9 SipHash key derivation functional"
                                                         `Quick g9_siphash_key_derivation_functional;
  Alcotest.test_case "G10 short-id uses wtxid"            `Quick g10_short_id_uses_wtxid;
]

let cmpctblock_tests = [
  Alcotest.test_case "G11 coinbase prefilled at index 0"  `Quick g11_coinbase_always_prefilled;
  Alcotest.test_case "G12 short_ids skip coinbase"        `Quick g12_short_ids_skip_coinbase;
  Alcotest.test_case "G13 BlockTxCount helper"            `Quick g13_block_tx_count_helper;
  Alcotest.test_case "G14 prefilled abs_idx bounded"      `Quick g14_prefilled_index_bounded;
  Alcotest.test_case "G15 collision-marked missing"       `Quick g15_short_id_collision_marked_missing;
]

let getblocktxn_tests = [
  Alcotest.test_case "G16 getblocktxn differential encoding"
                                                         `Quick g16_getblocktxn_differential_encoding;
  Alcotest.test_case "G17 FIX-42 getblocktxn MAX_BLOCKTXN_DEPTH=10"
                                                         `Quick g17_getblocktxn_depth_guard;
  Alcotest.test_case "G18 blocktxn fill_missing"          `Quick g18_blocktxn_fill_missing_completeness;
  Alcotest.test_case "G19/BUG-7 blocktxn arm no LoadingBlocks gate"
                                                         `Quick g19_blocktxn_no_loading_blocks_gate;
  Alcotest.test_case "G20/BUG-7 getblocktxn arm no LoadingBlocks gate"
                                                         `Quick g20_getblocktxn_no_loading_blocks_gate;
]

let reconstruction_tests = [
  Alcotest.test_case "G21 cmpctblock FullySynced gate"   `Quick g21_cmpctblock_fullysynced_gate;
  Alcotest.test_case "G22/BUG-6 no extra_txn pool"        `Quick g22_no_extra_txn_pool_bug;
  Alcotest.test_case "G23 reconstruct getblocktxn round-trip"
                                                         `Quick g23_reconstruct_round_trip;
]

let outbound_tests = [
  Alcotest.test_case "G24 FIX-42 InvCompactBlock served with depth"
                                                         `Quick g24_inv_compact_block_served_with_depth_guard;
  Alcotest.test_case "G25/BUG-9 no recent-cb cache"       `Quick g25_no_recent_compact_block_cache_bug;
  Alcotest.test_case "G26/BUG-2 maybe_set_hb_compact_peer dead helper"
                                                         `Quick g26_maybe_set_hb_compact_peer_dead_helper;
  Alcotest.test_case "G27/BUG-2 no block-validated callout to HB-setup"
                                                         `Quick g27_no_block_validated_callout;
]

let hb_announce_tests = [
  Alcotest.test_case "G28/BUG-1 P0-CDIV announce_block has NO cmpctblock"
                                                         `Quick g28_announce_block_no_cmpctblock_path;
  Alcotest.test_case "G29/BUG-3 relay_compact_block dead helper"
                                                         `Quick g29_relay_compact_block_dead_helper;
  Alcotest.test_case "G30/BUG-4 peer_has_header stub"     `Quick g30_peer_has_header_stub;
]

let () =
  Alcotest.run "W126_bip152_compact_blocks" [
    ("Wire shape (G1-G5)",                 wire_tests);
    ("SipHash + sendcmpct (G6-G10)",       siphash_tests);
    ("CmpctblockMsg (G11-G15)",            cmpctblock_tests);
    ("Getblocktxn/Blocktxn (G16-G20)",     getblocktxn_tests);
    ("Reconstruction (G21-G23)",           reconstruction_tests);
    ("Outbound serve (G24-G27)",           outbound_tests);
    ("HB-announce side (G28-G30)",         hb_announce_tests);
  ]
