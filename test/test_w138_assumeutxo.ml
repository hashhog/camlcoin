(* W138 assumeUTXO snapshots — camlcoin (OCaml)

   Discovery-only audit. 30 gates / 21 NEW bugs.

   This is the SECOND assumeUTXO discovery wave (after W102, commit
   cb6130a + ab6025c). W102 closed B1-B7 load-time preconditions;
   W138 expands the surface to 30 gates covering the Core
   ActivateSnapshot/MaybeValidateSnapshot lifecycle, restart-recovery,
   RPC handler service-bits, and orphan-code dual-chainstate cluster.

   References:
   - bitcoin-core/src/node/utxo_snapshot.{h,cpp} — SnapshotMetadata,
     WriteSnapshotBaseBlockhash, ReadSnapshotBaseBlockhash,
     FindAssumeutxoChainstateDir.
   - bitcoin-core/src/validation.cpp:5588-6232 — ActivateSnapshot,
     PopulateAndValidateSnapshot, MaybeValidateSnapshot,
     LoadAssumeutxoChainstate, AddChainstate,
     InvalidateCoinsDBOnDisk.
   - bitcoin-core/src/rpc/blockchain.cpp:3072-3519 — dumptxoutset,
     loadtxoutset, getchainstates.

   Severity legend:
   - P0-CDIV: client-observable correctness divergence
   - P1: feature/field absent that the spec mandates and clients use
   - P2: performance / DoS / belt-and-suspenders
   - P3: surface drift, error-message shape, comments

   NEW BUGs (full catalogue in audit/w138_assumeutxo.md):

   BUG-W138-1  (P3 G7):   loadtxoutset "Assumeutxo height not recognized"
                          error does not enumerate available heights.
   BUG-W138-2  (P2 G9):   No BLOCK_FAILED_VALID gate on snapshot start.
   BUG-W138-3  (P1 G10):  No "best_header has snapshot_start as ancestor"
                          check; fork-divergence on activate.
   BUG-W138-4  (P0-CDIV G12): outpoint.n >= UINT32_MAX not enforced;
                              comment at assume_utxo.ml:516 documents but
                              Int32.of_int truncates silently.
   BUG-W138-5  (P0-CDIV G17): au_data.m_chain_tx_count stored but never
                              written into block index — getblockheader.nTx
                              and getchaintxstats wrong for snapshot tip.
   BUG-W138-6  (P2 G18):  BLOCK_OPT_WITNESS faking on snapshot chain index
                          absent; precondition for NeedsRedownload parity.
   BUG-W138-7  (P1 G19):  WriteSnapshotBaseBlockhash sidecar absent.
   BUG-W138-8  (P0-CDIV G20): LoadAssumeutxoChainstate on startup absent.
                              Snapshot-on-disk invisible across restart.
   BUG-W138-9  (P0-CDIV G21): m_target_blockhash field absent; unvalidated→
                              validated transition never happens.
   BUG-W138-10 (P0-CDIV G22): MaybeValidateSnapshot background handshake
                              absent (skeleton dormant).
   BUG-W138-11 (P1 G23):  InvalidateCoinsDBOnDisk rename-to-_INVALID absent.
   BUG-W138-12 (P1 G24):  cleanup_bad_snapshot (remove partial dir on
                          load failure) absent.
   BUG-W138-13 (P1 G25):  m_target_utxohash post-validation record absent
                          (folded into BUG-10).
   BUG-W138-14 (P1 G26):  getchainstates RPC absent.
   BUG-W138-15 (P1 G27):  loadtxoutset success path does not swap
                          NODE_NETWORK → NODE_NETWORK_LIMITED.
   BUG-W138-16 (P1 G28):  dumptxoutset.txoutset_hash reflects post-restore
                          live tip, not historical dumped state
                          (W102 B10 re-pinned, TODO at rpc.ml:7179).
   BUG-W138-17 (P1 G29):  dumptxoutset response omits nchaintx
                          (W102 B9 re-pinned).
   BUG-W138-18 (P3 G3):   network_magic stored as int32 LE rather than
                          4 raw bytes.
   BUG-W138-19 (P3 G4):   Throw-on-bad-magic shape divergence
                          (Core: ios_base::failure; camlcoin: Error).
   BUG-W138-20 (P3 G5):   Network-mismatch error generic, no
                          ChainTypeToString human-readable name.
   BUG-W138-21 (P1 G7):   ~210 LOC orphan dual-chainstate cluster
                          (node_state + create_chainstate +
                          run_background_validation + connect_block_to_cache)
                          has zero callers outside the file.

   Tests below are pass-as-evidence: each documents the current
   behaviour and serves as a regression-pin. When a future fix wave
   closes a gap, the matching test should flip from "documents
   absence" to "verifies presence". *)

open Camlcoin

(* ============================================================================
   Helpers
   ============================================================================ *)

let mk_dummy_txid (b : int) : Types.hash256 =
  let h = Cstruct.create 32 in
  Cstruct.set_uint8 h 0 b;
  h

(* Read source file and check whether a substring is present. *)
let source_contains ~path ~needle =
  if not (Sys.file_exists path) then false
  else begin
    let ic = open_in path in
    let n = in_channel_length ic in
    let s = really_input_string ic n in
    close_in ic;
    try ignore (Str.search_forward (Str.regexp_string needle) s 0); true
    with Not_found -> false
  end

(* Path lookup that works from either dune runtest cwd or _build cwd. *)
let find_source filename =
  let candidates = [
    Filename.concat "lib" filename;
    Filename.concat "../lib" filename;
    Filename.concat "../../lib" filename;
    Filename.concat "../../../lib" filename;
    Filename.concat "../../camlcoin/lib" filename;
    Filename.concat "../../../camlcoin/lib" filename;
  ] in
  try List.find Sys.file_exists candidates
  with Not_found ->
    Filename.concat "/home/work/hashhog/camlcoin/lib" filename

let assume_utxo_ml () = find_source "assume_utxo.ml"
let rpc_ml () = find_source "rpc.ml"

(* Temp dir for tests that need filesystem state. *)
let temp_dir () =
  let name = Printf.sprintf "/tmp/camlcoin_w138_%d_%d"
               (Unix.getpid ()) (Random.int 1_000_000) in
  Unix.mkdir name 0o755;
  name

let cleanup_dir path =
  if Sys.file_exists path && Sys.is_directory path then begin
    let entries = Sys.readdir path in
    Array.iter (fun name ->
      let full = Filename.concat path name in
      if Sys.is_directory full then
        ignore (Sys.command (Printf.sprintf "rm -rf %s" full))
      else
        (try Sys.remove full with _ -> ())
    ) entries;
    (try Unix.rmdir path with _ -> ())
  end

(* ============================================================================
   G1-G5: Wire format / metadata
   ============================================================================ *)

(* G1: snapshot magic is the canonical 5-byte 'utxo\xff'. *)
let test_g1_magic_bytes_are_core_canonical () =
  Alcotest.(check int) "G1: magic length is 5 (Core canonical)"
    5 (Cstruct.length Assume_utxo.snapshot_magic);
  let core_magic = Cstruct.of_string "utxo\xff" in
  Alcotest.(check bool) "G1: magic bytes match Core SNAPSHOT_MAGIC_BYTES"
    true (Cstruct.equal Assume_utxo.snapshot_magic core_magic)

(* G2: snapshot version constant is 2 (Core's current). *)
let test_g2_version_constant_matches_core () =
  Alcotest.(check int) "G2: snapshot_version = 2 (Core VERSION)" 2
    Assume_utxo.snapshot_version

(* G2-bis: camlcoin uses a single-version check rather than a
   std::set<uint16_t> like Core. Not a bug today (Core only supports
   version 2), but pin so future Core multi-version growth is noticed. *)
let test_g2_version_check_is_strict_equality () =
  let src_has_set =
    source_contains ~path:(assume_utxo_ml ())
      ~needle:"m_supported_versions"
  in
  Alcotest.(check bool)
    "G2: camlcoin does not maintain a supported-version set \
     (single-version equality; cosmetic vs Core's std::set)"
    false src_has_set

(* G3: network_magic storage form (BUG-W138-18). *)
let test_g3_network_magic_stored_as_int32 () =
  let src_has_int32 =
    source_contains ~path:(assume_utxo_ml ())
      ~needle:"network_magic : int32"
  in
  Alcotest.(check bool)
    "G3: network_magic is stored as int32 (host-byte-order), not raw \
     bytes(4) like Core MessageStartChars (BUG-W138-18 surface drift)"
    true src_has_int32

(* G3-bis: but the wire layout is byte-identical for current mainnet
   magic — verify with a roundtrip. *)
let test_g3_wire_layout_byte_identical_for_mainnet () =
  let metadata : Assume_utxo.snapshot_metadata = {
    network_magic = Consensus.mainnet.magic;
    base_blockhash = Types.hash256_of_hex
      "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5";
    coins_count = 177_240_679L;
  } in
  let w = Serialize.writer_create () in
  Assume_utxo.serialize_metadata w metadata;
  let bytes = Cstruct.to_string (Serialize.writer_to_cstruct w) in
  let expected_prefix = "utxo\xff\x02\x00\xf9\xbe\xb4\xd9" in
  Alcotest.(check string)
    "G3: wire prefix matches Core canonical for mainnet"
    expected_prefix (String.sub bytes 0 11);
  Alcotest.(check int) "G3: total metadata is 51 bytes"
    51 (String.length bytes)

(* G4: throw-on-bad-magic shape divergence (BUG-W138-19). *)
let test_g4_bad_magic_returns_error_not_exception () =
  let data = Cstruct.of_string "XSBT\xff\x02\x00\xf9\xbe\xb4\xd9" in
  let bad = Cstruct.concat [data; Cstruct.create (51 - Cstruct.length data)] in
  let r = Serialize.reader_of_cstruct bad in
  match Assume_utxo.deserialize_metadata r
          ~expected_network_magic:Consensus.mainnet.magic with
  | Error _ ->
    Alcotest.(check bool)
      "G4: bad magic returns Error (Core throws ios_base::failure; \
       BUG-W138-19 surface-form drift)"
      true true
  | Ok _ ->
    Alcotest.fail "G4: bad magic must not return Ok"

(* G5: network-mismatch error string is generic (BUG-W138-20). *)
let test_g5_network_mismatch_error_lacks_human_name () =
  let metadata : Assume_utxo.snapshot_metadata = {
    network_magic = Consensus.mainnet.magic;
    base_blockhash = mk_dummy_txid 0xaa;
    coins_count = 100L;
  } in
  let w = Serialize.writer_create () in
  Assume_utxo.serialize_metadata w metadata;
  let data = Serialize.writer_to_cstruct w in
  let r = Serialize.reader_of_cstruct data in
  match Assume_utxo.deserialize_metadata r
          ~expected_network_magic:Consensus.testnet4.magic with
  | Error msg ->
    let has_generic = try ignore (Str.search_forward
      (Str.regexp_string "Network mismatch") msg 0); true
      with Not_found -> false in
    let has_chain_type_name = try ignore (Str.search_forward
      (Str.regexp_string "(mainnet)") msg 0); true
      with Not_found -> false in
    Alcotest.(check bool)
      "G5: generic 'Network mismatch' message (BUG-W138-20)"
      true has_generic;
    Alcotest.(check bool)
      "G5: human-readable network name ('(mainnet)') absent vs Core's \
       ChainTypeToString-shaped message"
      false has_chain_type_name
  | Ok _ ->
    Alcotest.fail "G5: network mismatch must return Error"

(* ============================================================================
   G6-G10: ActivateSnapshot lifecycle gates
   ============================================================================ *)

(* G6: double-activation guard — Core validation.cpp:5600-5602. W102 B5
   closure verifies behaviour; here we pin the surface. *)
let test_g6_double_activation_guard_surface () =
  let src_has = source_contains ~path:(rpc_ml ())
                  ~needle:"Can't activate a snapshot-based chainstate more than once" in
  Alcotest.(check bool)
    "G6: rpc.ml has Core-verbatim double-activation refusal (W102 B5 closure)"
    true src_has

(* G7: AssumeutxoForBlockhash whitelist — Core validation.cpp:5603-5609 also
   emits available heights via GetAvailableSnapshotHeights. camlcoin omits
   that hint (BUG-W138-1). *)
let test_g7_whitelist_error_omits_available_heights () =
  let src_has_hint = source_contains ~path:(rpc_ml ())
                       ~needle:"available snapshot heights are" in
  let src_has_get_avail = source_contains ~path:(rpc_ml ())
                           ~needle:"available_snapshot_heights" in
  Alcotest.(check bool)
    "G7: error does NOT enumerate available heights (BUG-W138-1)"
    false src_has_hint;
  (* The helper exists (used elsewhere); just isn't called in this error path. *)
  Alcotest.(check bool)
    "G7: available_snapshot_heights helper IS defined in assume_utxo.ml"
    true (source_contains ~path:(assume_utxo_ml ())
            ~needle:"available_snapshot_heights")
  |> fun () -> ignore src_has_get_avail

(* G7-bis: the whitelist helper itself works on a non-mainnet blockhash. *)
let test_g7_whitelist_helper_rejects_unknown_hash () =
  let unknown = mk_dummy_txid 0xff in
  match Assume_utxo.get_assumeutxo_for_hash
          ~network:Consensus.mainnet unknown with
  | None ->
    Alcotest.(check bool) "G7: whitelist refuses unknown hash" true true
  | Some _ ->
    Alcotest.fail "G7: whitelist must refuse dummy 0xff hash"

(* G8: base block in header chain — Core 5611-5615 (W102 B4 closure). *)
let test_g8_header_chain_membership_pinned () =
  let src_has = source_contains ~path:(rpc_ml ())
                  ~needle:"must appear in the headers" in
  Alcotest.(check bool)
    "G8: header-chain-membership check present (W102 B4 closure)" true src_has

(* G9: BLOCK_FAILED_VALID gate — Core 5617-5620 absent in camlcoin
   (BUG-W138-2). *)
let test_g9_block_failed_valid_gate_absent () =
  let src_has = source_contains ~path:(rpc_ml ())
                  ~needle:"BLOCK_FAILED_VALID" in
  let src_has_invalid_chain = source_contains ~path:(rpc_ml ())
                                ~needle:"part of an invalid chain" in
  Alcotest.(check bool)
    "G9: rpc.ml has no BLOCK_FAILED_VALID gate on snapshot start \
     (BUG-W138-2)"
    false src_has;
  Alcotest.(check bool)
    "G9: rpc.ml has no 'part of an invalid chain' refusal"
    false src_has_invalid_chain

(* G10: best_header GetAncestor check — Core 5622-5624 absent (BUG-W138-3). *)
let test_g10_best_header_ancestor_check_absent () =
  let src_has = source_contains ~path:(rpc_ml ())
                  ~needle:"GetAncestor" in
  let src_has_forked = source_contains ~path:(rpc_ml ())
                         ~needle:"forked headers-chain" in
  Alcotest.(check bool)
    "G10: rpc.ml has no GetAncestor-style check (BUG-W138-3)"
    false src_has;
  Alcotest.(check bool)
    "G10: rpc.ml has no 'forked headers-chain with more work' refusal"
    false src_has_forked

(* ============================================================================
   G11-G15: Per-coin content validation
   ============================================================================ *)

(* G11: coin.height > base_height rejection (W102 B1 closure). *)
let test_g11_coin_height_check_pinned () =
  let src_has = source_contains ~path:(assume_utxo_ml ())
                  ~needle:"coin.height > base_height" in
  Alcotest.(check bool)
    "G11: assume_utxo.ml documents B1 coin.height check"
    true src_has

(* G12: outpoint.n >= UINT32_MAX check — Core 5814-5816 — documented in
   comment but NOT ENFORCED (BUG-W138-4). *)
let test_g12_outpoint_n_uint32_max_check_absent () =
  let src_path = assume_utxo_ml () in
  let src_has_comment = source_contains ~path:src_path
                          ~needle:"outpoint.n >= UINT32_MAX" in
  let src_has_check = source_contains ~path:src_path
                        ~needle:"vout_int >= 0xffffffff" in
  let src_has_int_check = source_contains ~path:src_path
                            ~needle:"vout_int >= " in
  Alcotest.(check bool)
    "G12: assume_utxo.ml documents the UINT32_MAX requirement in a comment"
    true src_has_comment;
  Alcotest.(check bool)
    "G12: assume_utxo.ml has NO actual 'vout_int >= 0xffffffff' check \
     (BUG-W138-4 P0-CDIV)"
    false src_has_check;
  Alcotest.(check bool)
    "G12: assume_utxo.ml has NO 'vout_int >= ...' boundary check at all"
    false src_has_int_check

(* G13: MoneyRange check (W102 B2 closure). *)
let test_g13_money_range_check_pinned () =
  let src_has = source_contains ~path:(assume_utxo_ml ())
                  ~needle:"bad tx out value" in
  Alcotest.(check bool)
    "G13: assume_utxo.ml enforces MoneyRange (W102 B2 closure)"
    true src_has

(* G14: trailing-bytes rejection (W102 B3 closure). *)
let test_g14_trailing_bytes_check_pinned () =
  let src_has = source_contains ~path:(assume_utxo_ml ())
                  ~needle:"coins left over after deserializing" in
  Alcotest.(check bool)
    "G14: assume_utxo.ml rejects trailing bytes (W102 B3 closure)"
    true src_has

(* G15: coins_per_txid > coins_left rejection — Core 5804-5806. *)
let test_g15_coins_per_txid_overflow_check () =
  let src_has = source_contains ~path:(assume_utxo_ml ())
                  ~needle:"Mismatch in coins count" in
  Alcotest.(check bool)
    "G15: assume_utxo.ml enforces coins_per_txid <= coins_left"
    true src_has

(* ============================================================================
   G16-G20: Post-load chainstate finalization
   ============================================================================ *)

(* G16: SetBestBlock equivalent (set_chain_tip after coin load). *)
let test_g16_set_chain_tip_after_load () =
  let src_has = source_contains ~path:(assume_utxo_ml ())
                  ~needle:"set_chain_tip db" in
  Alcotest.(check bool)
    "G16: load_snapshot sets chain_tip after bulk coin load"
    true src_has

(* G17: m_chain_tx_count write-back — Core 5949 — absent (BUG-W138-5). *)
let test_g17_chain_tx_count_writeback_absent () =
  let src_has_field = source_contains ~path:(assume_utxo_ml ())
                        ~needle:"chain_tx_count" in
  let src_has_writeback = source_contains ~path:(assume_utxo_ml ())
                            ~needle:"params.chain_tx_count" in
  let rpc_has_writeback = source_contains ~path:(rpc_ml ())
                            ~needle:"chain_tx_count" in
  Alcotest.(check bool)
    "G17: assumeutxo_params.chain_tx_count field exists (W47 work)"
    true src_has_field;
  (* The field exists but is never propagated into the block index. *)
  Alcotest.(check bool)
    "G17: load_snapshot does NOT write params.chain_tx_count into chain \
     index (BUG-W138-5 P0-CDIV: getblockheader.nTx wrong for snapshot tip)"
    false src_has_writeback;
  Alcotest.(check bool)
    "G17: rpc.ml does not consult chain_tx_count for getblockheader.nTx \
     on snapshot-tip blocks"
    false rpc_has_writeback

(* G18: BLOCK_OPT_WITNESS faking on snapshot chain index — absent
   (BUG-W138-6). camlcoin has no nStatus bitfield, so the immediate impact
   is moot, but the gate is open if NeedsRedownload parity is ever added. *)
let test_g18_block_opt_witness_faking_absent () =
  let src_has = source_contains ~path:(assume_utxo_ml ())
                  ~needle:"BLOCK_OPT_WITNESS" in
  let src_has_needs_redownload = source_contains ~path:(assume_utxo_ml ())
                                   ~needle:"NeedsRedownload" in
  Alcotest.(check bool)
    "G18: assume_utxo.ml has no BLOCK_OPT_WITNESS faking (BUG-W138-6)"
    false src_has;
  Alcotest.(check bool)
    "G18: assume_utxo.ml has no NeedsRedownload reference"
    false src_has_needs_redownload

(* G19: WriteSnapshotBaseBlockhash sidecar — absent (BUG-W138-7). *)
let test_g19_base_blockhash_sidecar_absent () =
  let src_has_write = source_contains ~path:(assume_utxo_ml ())
                        ~needle:"base_blockhash" in
  let src_has_sidecar_filename = source_contains ~path:(assume_utxo_ml ())
                                   ~needle:"SNAPSHOT_BLOCKHASH_FILENAME" in
  let src_has_sidecar_path = source_contains ~path:(assume_utxo_ml ())
                               ~needle:"chainstate_snapshot/base_blockhash" in
  Alcotest.(check bool)
    "G19: assume_utxo.ml uses base_blockhash internally (in metadata)"
    true src_has_write;
  Alcotest.(check bool)
    "G19: but has no SNAPSHOT_BLOCKHASH_FILENAME constant (BUG-W138-7)"
    false src_has_sidecar_filename;
  Alcotest.(check bool)
    "G19: and does not write a sidecar file alongside chainstate_snapshot/"
    false src_has_sidecar_path

(* G20: LoadAssumeutxoChainstate on startup — absent (BUG-W138-8). *)
let test_g20_load_assumeutxo_on_startup_absent () =
  let bin_main = find_source "../bin/main.ml" in
  let src_has_load_on_startup = source_contains ~path:bin_main
                                  ~needle:"FindAssumeutxoChainstateDir" in
  let src_has_reconstruct = source_contains ~path:bin_main
                              ~needle:"LoadAssumeutxoChainstate" in
  Alcotest.(check bool)
    "G20: bin/main.ml has no FindAssumeutxoChainstateDir on startup \
     (BUG-W138-8 P0-CDIV)"
    false src_has_load_on_startup;
  Alcotest.(check bool)
    "G20: bin/main.ml has no LoadAssumeutxoChainstate equivalent"
    false src_has_reconstruct

(* ============================================================================
   G21-G25: Background validation / completion handshake
   ============================================================================ *)

(* G21: m_target_blockhash field absent — Core 6176 (BUG-W138-9). *)
let test_g21_target_blockhash_field_absent () =
  let src_has = source_contains ~path:(assume_utxo_ml ())
                  ~needle:"target_blockhash" in
  let src_has_m_target = source_contains ~path:(assume_utxo_ml ())
                           ~needle:"m_target_blockhash" in
  Alcotest.(check bool)
    "G21: assume_utxo.ml has NO target_blockhash field on chainstate \
     (BUG-W138-9 P0-CDIV: unvalidated→validated transition never happens)"
    false src_has;
  Alcotest.(check bool)
    "G21: no m_target_blockhash reference at all"
    false src_has_m_target

(* G22: MaybeValidateSnapshot — dormant (BUG-W138-10).
   The skeleton run_background_validation exists but has zero callers. *)
let test_g22_background_validation_skeleton_dormant () =
  let src_has_skeleton = source_contains ~path:(assume_utxo_ml ())
                           ~needle:"run_background_validation" in
  Alcotest.(check bool)
    "G22: run_background_validation skeleton exists in assume_utxo.ml"
    true src_has_skeleton;
  (* Verify NO production caller exists. Search all lib + bin + test files
     for an invocation pattern (not just the definition). *)
  let all_callers_grep =
    Sys.command "grep -rln 'run_background_validation' \
                 /home/work/hashhog/camlcoin/lib/ \
                 /home/work/hashhog/camlcoin/bin/ 2>/dev/null \
                 | grep -v assume_utxo.ml | wc -l > /tmp/w138_callers.txt"
  in
  let _ = all_callers_grep in
  let caller_count =
    try
      let ic = open_in "/tmp/w138_callers.txt" in
      let s = String.trim (input_line ic) in
      close_in ic;
      int_of_string s
    with _ -> -1
  in
  Alcotest.(check int)
    "G22: run_background_validation has ZERO production callers \
     outside assume_utxo.ml (BUG-W138-10 / BUG-W138-21 dormant cluster)"
    0 caller_count

(* G23: InvalidateCoinsDBOnDisk rename-to-_INVALID — absent (BUG-W138-11). *)
let test_g23_invalidate_rename_absent () =
  let src_has = source_contains ~path:(assume_utxo_ml ())
                  ~needle:"InvalidateCoinsDBOnDisk" in
  let src_has_rename = source_contains ~path:(assume_utxo_ml ())
                         ~needle:"_INVALID" in
  Alcotest.(check bool)
    "G23: assume_utxo.ml has no InvalidateCoinsDBOnDisk equivalent \
     (BUG-W138-11)"
    false src_has;
  Alcotest.(check bool)
    "G23: no '_INVALID' rename suffix used anywhere"
    false src_has_rename

(* G24: cleanup_bad_snapshot — partial dir removal on PopulateAndValidateSnapshot
   failure — absent (BUG-W138-12). *)
let test_g24_cleanup_bad_snapshot_absent () =
  let src_has = source_contains ~path:(assume_utxo_ml ())
                  ~needle:"cleanup_bad_snapshot" in
  let src_has_delete_db = source_contains ~path:(assume_utxo_ml ())
                            ~needle:"DeleteCoinsDBFromDisk" in
  let src_has_remove_partial = source_contains ~path:(assume_utxo_ml ())
                                 ~needle:"rm -rf snapshot_db_path" in
  Alcotest.(check bool)
    "G24: assume_utxo.ml has no cleanup_bad_snapshot helper (BUG-W138-12)"
    false src_has;
  Alcotest.(check bool)
    "G24: no DeleteCoinsDBFromDisk equivalent"
    false src_has_delete_db;
  Alcotest.(check bool)
    "G24: no partial-dir removal on load failure"
    false src_has_remove_partial

(* G25: m_target_utxohash record — folded into G22. *)
let test_g25_target_utxohash_record_absent () =
  let src_has = source_contains ~path:(assume_utxo_ml ())
                  ~needle:"target_utxohash" in
  Alcotest.(check bool)
    "G25: no m_target_utxohash record post-validation (BUG-W138-13, folded)"
    false src_has

(* ============================================================================
   G26-G30: RPC surface + ops
   ============================================================================ *)

(* G26: getchainstates RPC — absent (BUG-W138-14). *)
let test_g26_getchainstates_rpc_absent () =
  let src_has_handler = source_contains ~path:(rpc_ml ())
                          ~needle:"handle_getchainstates" in
  let src_has_dispatch = source_contains ~path:(rpc_ml ())
                           ~needle:"\"getchainstates\" ->" in
  Alcotest.(check bool)
    "G26: rpc.ml has no handle_getchainstates handler (BUG-W138-14)"
    false src_has_handler;
  Alcotest.(check bool)
    "G26: rpc.ml has no 'getchainstates' command dispatch arm"
    false src_has_dispatch

(* G27: NODE_NETWORK → NODE_NETWORK_LIMITED swap on loadtxoutset
   success — absent (BUG-W138-15). *)
let test_g27_node_network_limited_swap_absent () =
  let src_has_remove = source_contains ~path:(rpc_ml ())
                         ~needle:"RemoveLocalServices" in
  let src_has_add = source_contains ~path:(rpc_ml ())
                      ~needle:"AddLocalServices" in
  let src_has_swap_in_load = source_contains ~path:(rpc_ml ())
                               ~needle:"NODE_NETWORK_LIMITED" in
  Alcotest.(check bool)
    "G27: rpc.ml has no RemoveLocalServices call (BUG-W138-15)"
    false src_has_remove;
  Alcotest.(check bool)
    "G27: rpc.ml has no AddLocalServices call"
    false src_has_add;
  (* NODE_NETWORK_LIMITED bit ITSELF is referenced elsewhere (peer.ml,
     cli.ml) — pin that this is for cli/peer plumbing, not the post-
     loadtxoutset swap. *)
  let _ = src_has_swap_in_load in
  ()

(* G28: dumptxoutset.txoutset_hash reflects post-restore state — W102 B10
   re-pinned (BUG-W138-16). The TODO at rpc.ml:7179 documents the gap. *)
let test_g28_txoutset_hash_post_restore_drift () =
  let src_has_todo = source_contains ~path:(rpc_ml ())
                       ~needle:"TODO(W47-followup)" in
  Alcotest.(check bool)
    "G28: rpc.ml has TODO acknowledging post-restore hash drift \
     (BUG-W138-16 / W102 B10 re-pinned)"
    true src_has_todo

(* G29: dumptxoutset response omits nchaintx — W102 B9 re-pinned
   (BUG-W138-17). *)
let test_g29_dumptxoutset_nchaintx_field_absent () =
  let src_has = source_contains ~path:(rpc_ml ())
                  ~needle:"\"nchaintx\"" in
  Alcotest.(check bool)
    "G29: rpc.ml dumptxoutset response omits 'nchaintx' field \
     (BUG-W138-17 / W102 B9 re-pinned)"
    false src_has

(* G30: pruned-mode dumptxoutset precondition (Core 3164-3170 parity). *)
let test_g30_dumptxoutset_pruned_mode_check () =
  let src_has = source_contains ~path:(rpc_ml ())
                  ~needle:"not available (pruned data)" in
  Alcotest.(check bool)
    "G30: rpc.ml dumptxoutset enforces pruned-mode precondition (match)"
    true src_has

(* ============================================================================
   INV: dormant-orphan cluster (BUG-W138-21)
   ============================================================================
   Verify the dual-chainstate scaffolding genuinely has zero production
   callers. This is a single test that asserts the W47 cleanup epitaph
   at assume_utxo.ml:1240-1273 still holds — if a future commit wires
   one of these into Sync / Block_import / Peer_manager, this test
   will flip and the BUG should be re-classified.
*)

let count_external_refs symbol =
  let cmd = Printf.sprintf
    "grep -rln '%s' \
     /home/work/hashhog/camlcoin/lib/ \
     /home/work/hashhog/camlcoin/bin/ 2>/dev/null \
     | grep -v assume_utxo.ml | wc -l > /tmp/w138_count.txt"
    symbol in
  let _ = Sys.command cmd in
  try
    let ic = open_in "/tmp/w138_count.txt" in
    let s = String.trim (input_line ic) in
    close_in ic;
    int_of_string s
  with _ -> -1

let test_inv_orphan_cluster_remains_dormant () =
  let symbols = [
    "create_chainstate";
    "has_snapshot_chainstate";
    "background_chainstate";
    "run_background_validation";
    "connect_block_to_cache";
  ] in
  List.iter (fun sym ->
    let n = count_external_refs sym in
    Alcotest.(check int)
      (Printf.sprintf
         "INV: %s has zero production callers outside assume_utxo.ml \
          (BUG-W138-21 dormant cluster)" sym)
      0 n
  ) symbols;
  (* node_state appears in mempool.ml comments — pin that no actual
     uses (constructor invocation / field access) exist there. *)
  let n_node_state = count_external_refs "Assume_utxo.node_state" in
  Alcotest.(check int)
    "INV: Assume_utxo.node_state type has zero external uses \
     (BUG-W138-21)" 0 n_node_state

(* ============================================================================
   INV: positive regression pins
   ============================================================================ *)

(* INV-2: snapshot magic + version constants pin (regression guard). *)
let test_inv_magic_version_pin () =
  let metadata : Assume_utxo.snapshot_metadata = {
    network_magic = Consensus.mainnet.magic;
    base_blockhash = Types.hash256_of_hex
      "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5";
    coins_count = 177_240_679L;
  } in
  let w = Serialize.writer_create () in
  Assume_utxo.serialize_metadata w metadata;
  let bytes = Cstruct.to_string (Serialize.writer_to_cstruct w) in
  (* Bytes 0..6 must be "utxo\xff" + version 2 LE — exactly Core
     SnapshotMetadata::Serialize output. *)
  Alcotest.(check string) "INV-2: bytes 0..4 = 'utxo\\xff' (magic)"
    "utxo\xff" (String.sub bytes 0 5);
  Alcotest.(check string) "INV-2: bytes 5..6 = 0x02 0x00 (version 2 LE)"
    "\x02\x00" (String.sub bytes 5 2)

(* INV-3: HASH_SERIALIZED is the strict gate (NOT MuHash). *)
let test_inv_hash_serialized_is_strict_gate () =
  let src_path = assume_utxo_ml () in
  let src_has_hash_serialized =
    source_contains ~path:src_path
      ~needle:"HASH_SERIALIZED" in
  let src_has_not_the =
    source_contains ~path:src_path ~needle:"NOT the" in
  Alcotest.(check bool)
    "INV-3: assume_utxo.ml docstring asserts HASH_SERIALIZED is the strict gate"
    true src_has_hash_serialized;
  Alcotest.(check bool)
    "INV-3: docstring explicitly contrasts HASH_SERIALIZED vs MuHash3072"
    true src_has_not_the

(* INV-4: mainnet AssumeUTXO entries are all 4 Core 31.99 heights. *)
let test_inv_mainnet_au_entries_complete () =
  let heights = Assume_utxo.available_snapshot_heights
                  Consensus.mainnet in
  Alcotest.(check (list int)) "INV-4: 4 mainnet heights present"
    [840_000; 880_000; 910_000; 935_000] heights

(* INV-5: testnet4 has no published AssumeUTXO heights (Core 31.99). *)
let test_inv_testnet4_au_entries_empty () =
  let heights = Assume_utxo.available_snapshot_heights
                  Consensus.testnet4 in
  Alcotest.(check (list int)) "INV-5: testnet4 has zero published heights"
    [] heights

(* ============================================================================
   Test runner
   ============================================================================ *)

let () =
  Random.self_init ();
  let _ = temp_dir in
  let _ = cleanup_dir in
  Alcotest.run "w138_assumeutxo" [
    "g1_g5_wire_format", [
      Alcotest.test_case "G1: magic bytes = 'utxo\\xff'" `Quick
        test_g1_magic_bytes_are_core_canonical;
      Alcotest.test_case "G2: version constant = 2" `Quick
        test_g2_version_constant_matches_core;
      Alcotest.test_case "G2: single-version strict equality" `Quick
        test_g2_version_check_is_strict_equality;
      Alcotest.test_case "G3: network_magic stored as int32 (BUG-18)" `Quick
        test_g3_network_magic_stored_as_int32;
      Alcotest.test_case "G3: wire layout byte-identical for mainnet" `Quick
        test_g3_wire_layout_byte_identical_for_mainnet;
      Alcotest.test_case "G4: bad magic returns Error not throw (BUG-19)" `Quick
        test_g4_bad_magic_returns_error_not_exception;
      Alcotest.test_case "G5: network-mismatch generic message (BUG-20)" `Quick
        test_g5_network_mismatch_error_lacks_human_name;
    ];
    "g6_g10_activate_lifecycle", [
      Alcotest.test_case "G6: double-activation guard (W102 B5 pin)" `Quick
        test_g6_double_activation_guard_surface;
      Alcotest.test_case "G7: whitelist error omits available heights (BUG-1)" `Quick
        test_g7_whitelist_error_omits_available_heights;
      Alcotest.test_case "G7: whitelist helper rejects unknown hash" `Quick
        test_g7_whitelist_helper_rejects_unknown_hash;
      Alcotest.test_case "G8: header-chain membership (W102 B4 pin)" `Quick
        test_g8_header_chain_membership_pinned;
      Alcotest.test_case "G9: BLOCK_FAILED_VALID gate absent (BUG-2)" `Quick
        test_g9_block_failed_valid_gate_absent;
      Alcotest.test_case "G10: best_header ancestor check absent (BUG-3)" `Quick
        test_g10_best_header_ancestor_check_absent;
    ];
    "g11_g15_content_validation", [
      Alcotest.test_case "G11: coin.height check pinned (W102 B1)" `Quick
        test_g11_coin_height_check_pinned;
      Alcotest.test_case "G12: outpoint.n >= UINT32_MAX absent (BUG-4 P0)" `Quick
        test_g12_outpoint_n_uint32_max_check_absent;
      Alcotest.test_case "G13: MoneyRange check pinned (W102 B2)" `Quick
        test_g13_money_range_check_pinned;
      Alcotest.test_case "G14: trailing-bytes check pinned (W102 B3)" `Quick
        test_g14_trailing_bytes_check_pinned;
      Alcotest.test_case "G15: coins_per_txid overflow check" `Quick
        test_g15_coins_per_txid_overflow_check;
    ];
    "g16_g20_post_load_finalization", [
      Alcotest.test_case "G16: set_chain_tip after bulk load" `Quick
        test_g16_set_chain_tip_after_load;
      Alcotest.test_case "G17: chain_tx_count writeback absent (BUG-5 P0)" `Quick
        test_g17_chain_tx_count_writeback_absent;
      Alcotest.test_case "G18: BLOCK_OPT_WITNESS faking absent (BUG-6)" `Quick
        test_g18_block_opt_witness_faking_absent;
      Alcotest.test_case "G19: base_blockhash sidecar absent (BUG-7)" `Quick
        test_g19_base_blockhash_sidecar_absent;
      Alcotest.test_case "G20: LoadAssumeutxoChainstate startup absent (BUG-8 P0)" `Quick
        test_g20_load_assumeutxo_on_startup_absent;
    ];
    "g21_g25_background_validation", [
      Alcotest.test_case "G21: m_target_blockhash field absent (BUG-9 P0)" `Quick
        test_g21_target_blockhash_field_absent;
      Alcotest.test_case "G22: background validation dormant (BUG-10 P0)" `Quick
        test_g22_background_validation_skeleton_dormant;
      Alcotest.test_case "G23: InvalidateCoinsDBOnDisk rename absent (BUG-11)" `Quick
        test_g23_invalidate_rename_absent;
      Alcotest.test_case "G24: cleanup_bad_snapshot absent (BUG-12)" `Quick
        test_g24_cleanup_bad_snapshot_absent;
      Alcotest.test_case "G25: m_target_utxohash record absent (BUG-13)" `Quick
        test_g25_target_utxohash_record_absent;
    ];
    "g26_g30_rpc_surface", [
      Alcotest.test_case "G26: getchainstates RPC absent (BUG-14)" `Quick
        test_g26_getchainstates_rpc_absent;
      Alcotest.test_case "G27: NODE_NETWORK→LIMITED swap absent (BUG-15)" `Quick
        test_g27_node_network_limited_swap_absent;
      Alcotest.test_case "G28: txoutset_hash post-restore drift (BUG-16)" `Quick
        test_g28_txoutset_hash_post_restore_drift;
      Alcotest.test_case "G29: dumptxoutset.nchaintx field absent (BUG-17)" `Quick
        test_g29_dumptxoutset_nchaintx_field_absent;
      Alcotest.test_case "G30: pruned-mode dumptxoutset check (match)" `Quick
        test_g30_dumptxoutset_pruned_mode_check;
    ];
    "inv_regression_pins", [
      Alcotest.test_case "INV: dormant orphan cluster (BUG-21)" `Quick
        test_inv_orphan_cluster_remains_dormant;
      Alcotest.test_case "INV-2: magic + version wire bytes" `Quick
        test_inv_magic_version_pin;
      Alcotest.test_case "INV-3: HASH_SERIALIZED is strict gate" `Quick
        test_inv_hash_serialized_is_strict_gate;
      Alcotest.test_case "INV-4: 4 mainnet AssumeUTXO entries" `Quick
        test_inv_mainnet_au_entries_complete;
      Alcotest.test_case "INV-5: testnet4 has zero AssumeUTXO entries" `Quick
        test_inv_testnet4_au_entries_empty;
    ];
  ]
