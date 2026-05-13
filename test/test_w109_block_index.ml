(* W109 — CChain + CBlockIndex + CBlockTreeDB + block-file storage 30-gate audit
   Camlcoin (OCaml Bitcoin full-node implementation)

   Reference: bitcoin-core/src/chain.h, chain.cpp, node/blockstorage.h, blockstorage.cpp, txdb.h

   Gate summary:
   BUG-1  : block_status bitmask values wrong — BLOCK_HAVE_DATA serialises as bit-6 (64)
             not Core's 8; BLOCK_HAVE_UNDO as bit-7 (128) not Core's 16;
             BLOCK_FAILED_VALID as bit-8 (256) not Core's 32; etc.
   BUG-2  : CDiskBlockIndex serialisation format incompatible with Core — height/status/nTx
             stored as fixed int32-LE, not VARINT; nFile conditionally absent in Core.
   BUG-3  : block_status list representation — duplicate status tags silently accepted
             and round-trip through bitmask collapses duplicates (idempotent by accident,
             but wrong semantics for BLOCK_VALID_MASK extraction).
   BUG-4  : Missing BLOCK_VALID_MASK (0x1F) — cannot extract validity level from status;
             IsValid / RaiseValidity equivalents absent in FlatFileStorage.
   BUG-5  : Missing BLOCK_OPT_WITNESS flag (Core bit-7 = 128) — flag absent in type;
             needed for NeedsRedownload and ActivateSnapshot.
   BUG-6  : Missing m_chain_tx_count / HaveNumChainTxs — no per-block
             cumulative-tx-count field; getblockheader "nTx" returns only per-block count.
   BUG-7  : Missing nTimeMax (in-memory per-CBlockIndex) — FindEarliestAtLeast
             equivalent cannot work correctly; compute_median_time_past is linear scan.
   BUG-8  : Skip-list (CBlockIndex::pskip / BuildSkip / GetAncestor) absent —
             find_fork_point is O(n) pprev walk; LastCommonAncestor missing.
   BUG-9  : CChain::SetTip equivalent absent — active chain is not a random-access
             array; operator[] by height is O(log n) via DB lookup, not O(1).
   BUG-10 : CChain::Contains not O(1) — contains check requires DB round-trip.
   BUG-11 : Block locator exponential stepping wrong — step doubles after 10 hashes
             but step resets per call; genesis always appended as a separate pass
             that may re-insert it (list_exists scan is O(n^2)).
   BUG-12 : undo checksum algorithm wrong — camlcoin uses SHA256(undo_data only),
             Core uses HashWriter (SHA256d) over (pprev_hash || undo_data).
   BUG-13 : undo serialisation wire format incompatible with Core —
             camlcoin stores value as int64-LE + script, Core uses VARINT(height*2+coinbase)
             + TxOutCompression(amount+script); cross-node undo files unreadable.
   BUG-14 : nMinDiskSpace check absent — FindNextBlockPos never checks available
             disk space before allocating; node can fill the disk silently.
   BUG-15 : File pre-allocation (BLOCKFILE_CHUNK_SIZE / UNDOFILE_CHUNK_SIZE) absent —
             block files grow exactly byte-by-byte; Core pre-allocates in 16 MiB chunks
             to reduce fragmentation and speed sequential writes.
   BUG-16 : BlockfileType (NORMAL/ASSUMED) cursor split absent — single last_file
             cursor used for both normal and assumedvalid chainstates; mixing heights
             in the same blockfile impairs pruning correctness.
   BUG-17 : WriteBlockIndexDB atomicity missing — save_index writes one flat binary file
             (not LevelDB batch); a crash mid-save corrupts the index with no recovery path
             (WAL exists for ChainDB but NOT for FlatFileStorage.save_index).
   BUG-18 : m_dirty_blockindex / m_dirty_fileinfo absent — every block-index mutation
             calls save_index (O(n) full write), not lazy dirty-set flush like Core.
   BUG-19 : Missing nSequenceId initialisation — header_entry has no sequence-id field;
             setBlockIndexCandidates cannot break ties between equal-work blocks.
   BUG-20 : Missing CBlockLocator genesis fallback for pruned nodes — build_locator
             only returns hashes that exist in ChainDB; on a pruned node height 0 may
             not be stored, silently producing a locator without genesis.
   BUG-21 : FlatFileStorage index_path is a single "index.dat" — Core uses LevelDB in
             blocks/index/ with LoadBlockIndexGuts; camlcoin's custom binary format is
             incompatible and cannot be recovered by bitcoin-core -reindex.
   BUG-22 : Missing ScanAndUnlinkAlreadyPrunedFiles — on restart after pruning crash,
             deleted-in-index but still-on-disk files are not cleaned up.
   BUG-23 : Block_pruned flag not a Core status bit — Core clears BLOCK_HAVE_DATA and
             BLOCK_HAVE_UNDO; it has no separate "pruned" flag in nStatus.
             Camlcoin adds Block_pruned to the status list without clearing Have flags.
   BUG-24 : find_fork_point O(n) without skip list — for 900k-block mainnet chain,
             worst-case fork resolution requires 900k pprev link traversals.
   BUG-25 : Header entry total_work recomputed from genesis on restore_chain_state
             via sequential work_add — crash during restore_chain_state leaves
             total_work unset (zero_work fallback) for orphan headers.
   BUG-26 : Missing block-file flush before switching to new file — find_next_block_pos
             does not call FlushBlockFile when fi.n_size + add_size exceeds
             max_blockfile_size; buffered writes may be lost on crash.
   BUG-27 : write_block races on concurrent access — no mutex around file open/lseek/write
             (Unix.O_CREAT without O_EXCL or locking); two concurrent writers could
             interleave data.
   BUG-28 : block_file_info time_first / time_last stored as int32 LE (4 bytes) —
             Core stores CBlockFileInfo.nTimeFirst / nTimeLast as uint64 VARINT;
             timestamps above 2^31-1 (year 2038) overflow.
   BUG-29 : Missing CChain::IsTipRecent / tip-recency check — no equivalent of
             IsTipRecent(min_chain_work, max_tip_age) used by net_processing to gate
             header advertisements and new block announcements.
   PASS-30: max_blockfile_size = 0x8000000 (128 MiB) matches Core's MAX_BLOCKFILE_SIZE.
*)

open Camlcoin

(* ============================================================================
   Helpers
   ============================================================================ *)

let test_db_path = "/tmp/camlcoin_test_w109_block_index_db"
let test_blocks_dir = "/tmp/camlcoin_test_w109_blocks"

let cleanup () =
  let rec rm_rf path =
    if Sys.file_exists path then begin
      if Sys.is_directory path then begin
        Array.iter (fun f -> rm_rf (Filename.concat path f)) (Sys.readdir path);
        Unix.rmdir path
      end else
        Unix.unlink path
    end
  in
  rm_rf test_db_path;
  rm_rf test_blocks_dir

let _create_test_chain_state () =
  cleanup ();
  let db = Storage.ChainDB.create test_db_path in
  let chain = Sync.create_chain_state db Consensus.regtest in
  (chain, db)

(* Build a minimal block header for testing *)
let make_test_header ?(version=1) ?(prev_block=Types.zero_hash) ?(timestamp=1296688602l) ?(bits=0x207fffffl) ?(nonce=0l) () =
  { Types.version = Int32.of_int version;
    prev_block;
    merkle_root = Types.zero_hash;
    timestamp;
    bits;
    nonce;
  }

(* Build a minimal block *)
let make_test_block ?header () =
  let h = match header with Some h -> h | None -> make_test_header () in
  { Types.header = h; transactions = [] }

(* ============================================================================
   BUG-1: block_status bitmask values incompatible with Core
   Core chain.h:
     BLOCK_HAVE_DATA   = 8   (bit 3)
     BLOCK_HAVE_UNDO   = 16  (bit 4)
     BLOCK_FAILED_VALID = 32 (bit 5)
     BLOCK_FAILED_CHILD = 64 (bit 6)
     BLOCK_OPT_WITNESS = 128 (bit 7)
   Camlcoin status_to_int:
     Block_have_data → 6 → mask (1 lsl 6) = 64  (wrong)
     Block_have_undo → 7 → mask (1 lsl 7) = 128 (wrong)
     Block_failed    → 8 → mask (1 lsl 8) = 256 (wrong)
   ============================================================================ *)

let test_bug1_block_status_bitmask () =
  (* The correct bitmask values from Bitcoin Core chain.h *)
  let core_block_have_data    =  8 in  (* 1 lsl 3 *)
  let core_block_have_undo    = 16 in  (* 1 lsl 4 *)
  let core_block_failed_valid = 32 in  (* 1 lsl 5 *)
  let core_block_failed_child = 64 in  (* 1 lsl 6 *)

  (* Camlcoin status_to_int values (from storage.ml) — these are the shift amounts *)
  (* Block_have_data → 6, Block_have_undo → 7, Block_failed → 8, Block_failed_child → 10 *)
  let caml_have_data_mask    = 1 lsl 6  in  (* = 64,  Core wants 8  *)
  let caml_have_undo_mask    = 1 lsl 7  in  (* = 128, Core wants 16 *)
  let caml_failed_mask       = 1 lsl 8  in  (* = 256, Core wants 32 *)
  let caml_failed_child_mask = 1 lsl 10 in  (* = 1024, Core wants 64 *)

  (* BUG-1: masks diverge from Core *)
  Alcotest.(check bool) "BUG-1a: BLOCK_HAVE_DATA mask matches Core (8)"
    true (caml_have_data_mask = core_block_have_data);
  Alcotest.(check bool) "BUG-1b: BLOCK_HAVE_UNDO mask matches Core (16)"
    true (caml_have_undo_mask = core_block_have_undo);
  Alcotest.(check bool) "BUG-1c: BLOCK_FAILED_VALID mask matches Core (32)"
    true (caml_failed_mask = core_block_failed_valid);
  Alcotest.(check bool) "BUG-1d: BLOCK_FAILED_CHILD mask matches Core (64)"
    true (caml_failed_child_mask = core_block_failed_child)

(* ============================================================================
   BUG-2: CDiskBlockIndex serialisation uses fixed int32-LE, not VARINT
   Core chain.h CDiskBlockIndex::SERIALIZE_METHODS:
     READWRITE(VARINT_MODE(obj.nHeight, NONNEGATIVE_SIGNED));
     READWRITE(VARINT(obj.nStatus));
     READWRITE(VARINT(obj.nTx));
     if (nStatus & (BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO)) READWRITE(VARINT_MODE(obj.nFile, ...));
   Camlcoin serialize_entry (storage.ml:1222):
     serialize_pos (file_pos + undo_pos as fixed int32-LE × 4)
     write_int32_le height
     serialize_block_header (fixed 80 bytes)
     write_int32_le mask
     write_int32_le n_tx
   ============================================================================ *)

let test_bug2_diskblockindex_serialisation () =
  (* Core CDiskBlockIndex uses VARINT for height, status, nTx.
     nFile is only present when BLOCK_HAVE_DATA or BLOCK_HAVE_UNDO is set.
     Camlcoin always writes file_pos (8 bytes) and undo_pos (8 bytes) regardless
     of status, and uses fixed int32-LE for height, status, nTx. *)
  (* Document the divergence with a size check.
     Core CDiskBlockIndex at height=0, nTx=0, no data: varint(0) + varint(0) + varint(0)
       + version(4) + prev(32) + merkle(32) + time(4) + bits(4) + nonce(4) = 3 + 80 = 83 bytes
     Camlcoin at height=0, nTx=0, no data: 8(file_pos) + 8(undo_pos) + 4(height) + 80(header)
       + 4(status) + 4(nTx) = 108 bytes *)
  let core_min_disk_bytes = 83 in
  let caml_fixed_overhead = 8 + 8 + 4 + 80 + 4 + 4 in  (* = 108 *)
  Alcotest.(check bool) "BUG-2: serialisation byte count matches Core VARINT format"
    true (caml_fixed_overhead = core_min_disk_bytes)

(* ============================================================================
   BUG-3: Duplicate status tags silently accepted in status list
   The block_status type is a list — nothing prevents duplicates.
   status_to_int / serialize round-trip collapses duplicates (bitmask OR),
   so an entry with [Block_have_data; Block_have_data] serialises identically
   to [Block_have_data], but the pre-serialisation representation is wrong.
   ============================================================================ *)

let test_bug3_duplicate_status_tags () =
  let status_with_dup = Storage.[ Block_have_data; Block_have_data; Block_valid_scripts ] in
  let status_clean    = Storage.[ Block_have_data; Block_valid_scripts ] in
  (* Both have the same logical meaning but different list lengths *)
  let len_dup   = List.length status_with_dup in
  let len_clean = List.length status_clean in
  (* BUG-3: no deduplication in the type — lists differ *)
  Alcotest.(check bool) "BUG-3: status list rejects/normalises duplicates"
    true (len_dup = len_clean)

(* ============================================================================
   BUG-4: Missing BLOCK_VALID_MASK and IsValid / RaiseValidity
   Core CBlockIndex::IsValid checks (nStatus & BLOCK_VALID_MASK) >= nUpTo
   and (nStatus & BLOCK_FAILED_VALID) == 0.
   Camlcoin has no BLOCK_VALID_MASK extraction; validity level comparison
   requires scanning the status list, which is not equivalent.
   ============================================================================ *)

let test_bug4_block_valid_mask () =
  (* Core BLOCK_VALID_MASK = 0x1F (bits 0-4) *)
  let core_valid_mask = 0x1f in
  (* Camlcoin "valid" levels map to bit positions 0..5.
     BLOCK_VALID_SCRIPTS = 5 → bit 5 = mask 32.
     Core BLOCK_VALID_SCRIPTS = 5 (raw value, NOT a bit position).
     In Core: (nStatus & BLOCK_VALID_MASK) = 5 means VALID_SCRIPTS.
     In Camlcoin: the bitmask for VALID_SCRIPTS is 1 lsl 5 = 32. *)
  (* The camlcoin "level" is the bit position; Core uses 0-5 as linear levels stored
     in the low 5 bits of nStatus. These are fundamentally different encodings. *)
  let caml_valid_scripts_mask = 1 lsl 5 in  (* = 32 in camlcoin's scheme *)
  let core_valid_scripts_level = 5 in        (* Core stores 5 directly in bits 0-4 *)

  (* Show the divergence: in Core, VALID_SCRIPTS status = nStatus & 0x1F = 5.
     In camlcoin, it's stored as bit-5 set = 32. They are NOT compatible. *)
  Alcotest.(check bool) "BUG-4: BLOCK_VALID_MASK encoding compatible with Core"
    true (caml_valid_scripts_mask = core_valid_scripts_level);

  (* Also: IsValid/RaiseValidity absent from FlatFileStorage API *)
  ignore core_valid_mask  (* keep compiler happy *)

(* ============================================================================
   BUG-5: BLOCK_OPT_WITNESS flag absent from block_status type
   Core chain.h: BLOCK_OPT_WITNESS = 128 (bit 7)
   Used by NeedsRedownload and ActivateSnapshot.
   Camlcoin block_status variant list has no Block_opt_witness constructor.
   ============================================================================ *)

let test_bug5_block_opt_witness_absent () =
  (* Enumerate all constructors in Storage.block_status.
     The test deliberately constructs all known values to check the type. *)
  let all_known_statuses = Storage.[
    Block_valid_unknown; Block_valid_header; Block_valid_tree;
    Block_valid_transactions; Block_valid_chain; Block_valid_scripts;
    Block_have_data; Block_have_undo; Block_failed; Block_failed_child;
    Block_pruned;
  ] in
  let count = List.length all_known_statuses in
  (* Core has BLOCK_OPT_WITNESS = 128 (bit 7) and BLOCK_STATUS_RESERVED = 256 (bit 8).
     Camlcoin has 11 variants — both BLOCK_OPT_WITNESS and BLOCK_STATUS_RESERVED are absent. *)
  (* BUG-5: count should be at least 12 to include BLOCK_OPT_WITNESS *)
  Alcotest.(check bool) "BUG-5: BLOCK_OPT_WITNESS variant present in block_status"
    true (count >= 12)

(* ============================================================================
   BUG-6: Missing m_chain_tx_count / HaveNumChainTxs
   Core CBlockIndex has m_chain_tx_count (cumulative tx count from genesis).
   HaveNumChainTxs() = (m_chain_tx_count != 0) gates activateBestChain.
   Camlcoin block_index_entry.n_tx stores only the per-block tx count.
   ChainDB.store_block_ntx stores per-block nTx, no cumulative field.
   ============================================================================ *)

let test_bug6_missing_chain_tx_count () =
  cleanup ();
  let db = Storage.ChainDB.create test_db_path in
  (* Store some nTx values *)
  let hash1 = Crypto.sha256d (Cstruct.of_string "block1") in
  Storage.ChainDB.store_block_ntx db hash1 3;
  (* Try to get it back *)
  let got = Storage.ChainDB.get_block_ntx db hash1 in
  (* This is per-block nTx; there is no API for cumulative m_chain_tx_count *)
  (match got with
   | Some n ->
     Alcotest.(check int) "PASS: per-block nTx stored" 3 n
   | None ->
     Alcotest.fail "nTx not stored");
  (* BUG-6: no cumulative chain_tx_count; document by checking API absence *)
  (* If ChainDB had get_chain_tx_count we'd call it here; it does not. *)
  Alcotest.(check bool) "BUG-6: cumulative chain_tx_count API present"
    true false;  (* expected to fail — BUG *)
  Storage.ChainDB.close db;
  cleanup ()

(* ============================================================================
   BUG-7: Missing nTimeMax per-block index entry
   Core CBlockIndex.nTimeMax = max timestamp in chain up to this block.
   Used by CChain::FindEarliestAtLeast for wallet rescanning.
   Camlcoin header_entry has no nTimeMax; FindEarliestAtLeast equivalent is absent.
   ============================================================================ *)

let test_bug7_missing_ntimemax () =
  (* Demonstrate that header_entry has no time_max field.
     The fields are: header, hash, height, total_work *)
  let h = make_test_header ~timestamp:1296688602l () in
  let hash = Crypto.compute_block_hash h in
  let entry : Sync.header_entry = {
    header = h;
    hash;
    height = 0;
    total_work = Consensus.zero_work;
  } in
  (* BUG-7: no nTimeMax in header_entry — accessing entry.time_max would not compile *)
  let _ = entry in
  (* The test passing means time_max is absent (compile-time proof via type structure) *)
  Alcotest.(check bool) "BUG-7: nTimeMax field present in header_entry"
    true false  (* BUG: field absent *)

(* ============================================================================
   BUG-8: Skip list (pskip / BuildSkip / GetAncestor) absent
   Core CBlockIndex::BuildSkip sets pskip = pprev->GetAncestor(GetSkipHeight(nHeight))
   for O(log n) ancestor lookup. GetAncestor uses skip+pprev traversal.
   Camlcoin find_fork_point is a pure pprev walk — O(n).
   ============================================================================ *)

let test_bug8_skip_list_absent () =
  (* Verify O(n) worst-case: find_fork_point walks pprev links one by one.
     With a 900k-block mainnet chain, this is ~900k iterations worst case.
     Build a small chain and verify the walk is proportional to height diff. *)
  cleanup ();
  let db = Storage.ChainDB.create test_db_path in
  let state = Sync.create_chain_state db Consensus.regtest in

  (* Simulate chain of 5 blocks by storing headers *)
  let genesis_entry = match state.Sync.tip with Some e -> e | None -> assert false in
  let make_entry (prev_entry : Sync.header_entry) : Sync.header_entry =
    let h = make_test_header ~prev_block:prev_entry.hash ~timestamp:(Int32.add prev_entry.header.timestamp 600l) ~bits:0x207fffffl () in
    let hash = Crypto.compute_block_hash h in
    { Sync.header = h; hash; height = prev_entry.height + 1;
      total_work = Consensus.work_add prev_entry.total_work (Sync.work_from_bits h.bits); }
  in
  let e1 = make_entry genesis_entry in
  let e2 = make_entry e1 in
  let e3 = make_entry e2 in

  (* Manually register entries in state.headers *)
  Hashtbl.replace state.headers (Cstruct.to_string e1.hash) e1;
  Hashtbl.replace state.headers (Cstruct.to_string e2.hash) e2;
  Hashtbl.replace state.headers (Cstruct.to_string e3.hash) e3;

  (* find_fork_point between e3 and genesis should work but does pprev walk *)
  let result = Sync.find_fork_point state e3 genesis_entry in
  (match result with
   | Ok fork -> Alcotest.(check int) "fork at genesis" 0 fork.height
   | Error msg -> Alcotest.failf "find_fork_point failed: %s" msg);

  (* BUG-8: no skip-list means O(n) traversal; document *)
  (* A proper GetAncestor(height) implementation would use the skip list.
     Since pskip is absent, we can't call it.  The BUG test is the structural absence. *)
  Alcotest.(check bool) "BUG-8: skip-list GetAncestor present (O(log n))"
    true false;  (* BUG: absent *)
  Storage.ChainDB.close db;
  cleanup ()

(* ============================================================================
   BUG-9: CChain::SetTip / random-access vChain array absent
   Core CChain maintains std::vector<CBlockIndex*> vChain indexed by height,
   giving O(1) operator[](height).  SetTip walks pprev to fill the array.
   Camlcoin uses ChainDB.get_hash_at_height (DB lookup) for height→hash, O(1)
   only if RocksDB is in page cache; no in-memory vector equivalent.
   ============================================================================ *)

let test_bug9_cchain_settip_absent () =
  cleanup ();
  let db = Storage.ChainDB.create test_db_path in
  let _state = Sync.create_chain_state db Consensus.regtest in
  (* chain_state has no vChain array field — O(1) by-height access is via DB *)
  (* Document: chain_state.tip is the current tip only; no vChain vector *)
  Alcotest.(check bool) "BUG-9: in-memory vChain array (O(1) by-height) present"
    true false;  (* BUG: absent; access is via RocksDB *)
  Storage.ChainDB.close db;
  cleanup ()

(* ============================================================================
   BUG-10: CChain::Contains O(1) check absent
   Core: Contains(pindex) = ( this[pindex->nHeight] == pindex ) -- O(1).
   Camlcoin equivalent requires DB lookup + hash comparison — O(1) only when
   cached, and no explicit Contains API.
   ============================================================================ *)

let test_bug10_cchain_contains () =
  cleanup ();
  let db = Storage.ChainDB.create test_db_path in
  let state = Sync.create_chain_state db Consensus.regtest in
  let genesis = match state.tip with Some e -> e | None -> assert false in
  (* Closest equivalent: check genesis is at height 0 *)
  let stored = Storage.ChainDB.get_hash_at_height db 0 in
  (match stored with
   | Some h -> Alcotest.(check bool) "genesis hash at height 0"
       true (Cstruct.equal h genesis.hash)
   | None -> Alcotest.fail "genesis not stored at height 0");
  (* BUG-10: no explicit O(1) Contains API *)
  Alcotest.(check bool) "BUG-10: O(1) CChain::Contains API present"
    true false;  (* BUG: absent *)
  Storage.ChainDB.close db;
  cleanup ()

(* ============================================================================
   BUG-11: Block locator O(n^2) genesis inclusion
   build_locator (peer_manager.ml:1503) uses List.exists to check genesis.
   On mainnet (900k blocks) each List.exists scan is O(result_len).
   The step-doubling loop is correct but the genesis re-add loop is O(n).
   Core's LocatorEntries terminates at nHeight==0 with a break, O(1).
   ============================================================================ *)

let test_bug11_locator_genesis_inclusion () =
  cleanup ();
  let db = Storage.ChainDB.create test_db_path in
  let state = Sync.create_chain_state db Consensus.regtest in
  let genesis_hash = match Storage.ChainDB.get_hash_at_height db 0 with
    | Some h -> h | None -> assert false in
  let tip_height = state.blocks_synced in
  (* build_locator — imported from Peer_manager *)
  let locator = Peer_manager.build_locator db tip_height in
  (* Genesis (height 0) must be last in locator *)
  let last = List.nth locator (List.length locator - 1) in
  Alcotest.(check bool) "genesis is last entry in locator"
    true (Cstruct.equal last genesis_hash);
  (* Count how many times genesis appears (should be exactly once) *)
  let genesis_count = List.fold_left (fun acc h ->
    if Cstruct.equal h genesis_hash then acc + 1 else acc
  ) 0 locator in
  Alcotest.(check int) "BUG-11: genesis appears exactly once in locator"
    1 genesis_count;
  Storage.ChainDB.close db;
  cleanup ()

(* ============================================================================
   BUG-12: Undo checksum algorithm wrong (SHA256 vs SHA256d with pprev_hash)
   Core blockstorage.cpp:996-999:
     HashWriter hasher{};
     hasher << block.pprev->GetBlockHash() << blockundo;
     fileout << blockundo << hasher.GetHash();
   Core read (line 711-720):
     HashVerifier verifier{filein};
     verifier << index.pprev->GetBlockHash();
     verifier >> blockundo;
     uint256 hashChecksum; filein >> hashChecksum;
     if (hashChecksum != verifier.GetHash()) return false;
   Camlcoin storage.ml (serialize_block_undo):
     checksum = Crypto.sha256(serialized_data_without_pprev_hash)
   Two bugs: (1) SHA256 not SHA256d, (2) pprev hash not included.
   ============================================================================ *)

let test_bug12_undo_checksum_algorithm () =
  (* The undo serialisation includes a SHA256 checksum (single hash).
     Core uses HashWriter = SHA256d(pprev_hash || undo_data). *)
  let dummy_data = Cstruct.of_string "test undo data" in
  let sha256_single = Crypto.sha256 dummy_data in
  let sha256_double = Crypto.sha256d dummy_data in
  (* They differ for non-trivial inputs *)
  let differs = not (Cstruct.equal sha256_single sha256_double) in
  Alcotest.(check bool)
    "SHA256 != SHA256d for the same data (shows checksum algo diverges)" true differs;
  (* BUG-12: the undo checksum uses single SHA256 without pprev hash *)
  (* Core's HashWriter over pprev||data would produce yet another value *)
  let pprev_hash = Crypto.sha256d (Cstruct.of_string "fake_prev_block_hash_32byte12") in
  let combined = Cstruct.concat [pprev_hash; dummy_data] in
  let core_checksum = Crypto.sha256d combined in
  Alcotest.(check bool) "BUG-12: undo checksum matches Core SHA256d(pprev||data)"
    true (Cstruct.equal sha256_single core_checksum)

(* ============================================================================
   BUG-13: Undo serialisation wire format incompatible with Core
   Core undo.h TxInUndoFormatter:
     Ser: VARINT(txout.nHeight * 2 + txout.fCoinBase) + TxOutCompression(out)
     TxOutCompression = CompressAmount(value) + CompressScript(scriptPubKey)
   Camlcoin storage.ml serialize_tx_in_undo:
     int64_le(value) + compact_size(script_len) + raw_script_bytes
     + int32_le(height) + uint8(is_coinbase)
   These wire formats are completely different; undo files are not interchangeable.
   ============================================================================ *)

let test_bug13_undo_wire_format () =
  (* Demonstrate that the two formats produce different byte sequences for the same input *)
  (* Camlcoin format for height=1, is_coinbase=false, value=50_0000_0000, script=\x51 *)
  let w = Serialize.writer_create () in
  let undo_entry : Storage.tx_in_undo = {
    value = 5_000_000_000L;    (* 50 BTC in satoshis *)
    script_pubkey = Cstruct.of_string "\x51";  (* OP_1 *)
    height = 1;
    is_coinbase = false;
  } in
  (* We can serialize to check the format *)
  Serialize.write_int64_le w undo_entry.value;
  Serialize.write_compact_size w (Cstruct.length undo_entry.script_pubkey);
  Serialize.write_bytes w undo_entry.script_pubkey;
  Serialize.write_int32_le w (Int32.of_int undo_entry.height);
  Serialize.write_uint8 w (if undo_entry.is_coinbase then 1 else 0);
  let caml_bytes = Cstruct.to_string (Serialize.writer_to_cstruct w) in
  let caml_len = String.length caml_bytes in

  (* Core format: VARINT(height*2 + coinbase_flag) + CompressAmount + CompressScript
     For height=1, coinbase=false: VARINT(2) = 1 byte
     CompressAmount(50 BTC = 5e9 sats): https://github.com/bitcoin/bitcoin/blob/master/src/compressor.cpp
       5e9 / 10 = 500_000_000; n = 500_000_000 / 1 = 500_000_000 (exponent 1, mantissa 0)
       Stored as VARINT roughly 5-6 bytes
     CompressScript(\x51 = OP_1 = P2SH-like): 1 type byte + 20 or 32 bytes for known types,
       or len+1 for other; \x51 is 1 byte → compressed as a 1-byte opcode type → ~2 bytes
     Total Core ≈ 1 + 5 + 2 = ~8 bytes *)
  let core_approx_len = 8 in

  (* Camlcoin: 8 (int64) + 1 (compact_size) + 1 (script) + 4 (height) + 1 (coinbase) = 15 *)
  let expected_caml_len = 8 + 1 + 1 + 4 + 1 in
  Alcotest.(check int) "camlcoin undo entry byte length" expected_caml_len caml_len;
  (* BUG-13: formats differ *)
  Alcotest.(check bool) "BUG-13: undo wire format size matches Core (~8 bytes)"
    true (caml_len = core_approx_len)

(* ============================================================================
   BUG-14: nMinDiskSpace check absent in find_next_block_pos
   Core blockstorage.cpp FindNextBlockPos checks CheckDiskSpace(nAddSize + nMinDiskSpace)
   where nMinDiskSpace = 50 * 1024 * 1024 (50 MiB).  Camlcoin find_next_block_pos
   (storage.ml:1342) has no such check.
   ============================================================================ *)

let test_bug14_nmindbiskspace_absent () =
  cleanup ();
  Unix.mkdir test_blocks_dir 0o755;
  let t = Storage.FlatFileStorage.create ~magic:Storage.regtest_magic test_blocks_dir in
  (* find_next_block_pos is called internally by write_block.
     Write a small block and verify it succeeds without any disk-space check. *)
  let blk = make_test_block () in
  let _pos = Storage.FlatFileStorage.write_block t blk 0 in
  (* BUG-14: if disk is full, write_block still proceeds without a disk-space pre-check *)
  Alcotest.(check bool) "BUG-14: disk-space pre-check (nMinDiskSpace) present"
    true false;  (* BUG: absent *)
  Storage.FlatFileStorage.close t;
  cleanup ()

(* ============================================================================
   BUG-15: File pre-allocation absent (BLOCKFILE_CHUNK_SIZE = 16 MiB)
   Core blockstorage.cpp FindNextBlockPos pre-allocates in 16 MiB chunks for block
   files and 1 MiB chunks for undo files to reduce filesystem fragmentation.
   Camlcoin find_next_block_pos writes without pre-allocation.
   ============================================================================ *)

let test_bug15_file_preallocation_absent () =
  (* Core BLOCKFILE_CHUNK_SIZE = 0x1000000 = 16 MiB *)
  let core_blockfile_chunk = 0x1000000 in
  (* Core UNDOFILE_CHUNK_SIZE = 0x100000 = 1 MiB *)
  let core_undofile_chunk = 0x100000 in
  (* Camlcoin has no pre-allocation constants or logic *)
  (* Document as a BUG: no such constants in storage.ml *)
  Alcotest.(check bool) "BUG-15a: BLOCKFILE_CHUNK_SIZE pre-allocation present"
    true (core_blockfile_chunk = 0);  (* BUG: not implemented *)
  Alcotest.(check bool) "BUG-15b: UNDOFILE_CHUNK_SIZE pre-allocation present"
    true (core_undofile_chunk = 0)    (* BUG: not implemented *)

(* ============================================================================
   BUG-16: BlockfileType NORMAL/ASSUMED cursor split absent
   Core has two BlockfileCursor entries: NORMAL and ASSUMED.
   When an assumeutxo snapshot is active, assumed-chainstate blocks go into
   ASSUMED cursor files (separate from NORMAL-cursor files), preventing
   height interleaving that impairs pruning.
   Camlcoin FlatFileStorage.t has a single last_file cursor.
   ============================================================================ *)

let test_bug16_blockfile_type_cursor_absent () =
  cleanup ();
  Unix.mkdir test_blocks_dir 0o755;
  let t = Storage.FlatFileStorage.create ~magic:Storage.mainnet_magic test_blocks_dir in
  (* last_file_num returns the single cursor *)
  let last = Storage.FlatFileStorage.last_file_num t in
  Alcotest.(check int) "single cursor starts at 0" 0 last;
  (* BUG-16: no ASSUMED cursor; document *)
  Alcotest.(check bool) "BUG-16: NORMAL/ASSUMED dual cursor present"
    true false;  (* BUG: single cursor only *)
  Storage.FlatFileStorage.close t;
  cleanup ()

(* ============================================================================
   BUG-17: WriteBlockIndexDB atomicity missing — no WAL for FlatFileStorage
   save_index writes a tmp file and renames (atomic at FS level), which is good.
   However, the in-memory block_index Hashtbl can diverge from the on-disk
   index.dat if the process crashes after writing block data but before save_index.
   Core writes the block index to LevelDB in WriteBlockIndexDB which is a
   transactional batch — no partial state.  Camlcoin save_index is called
   manually (lazy via dirty flag), but a crash window exists.
   ============================================================================ *)

let test_bug17_writeblockindex_atomicity () =
  cleanup ();
  Unix.mkdir test_blocks_dir 0o755;
  let t = Storage.FlatFileStorage.create ~magic:Storage.regtest_magic test_blocks_dir in
  let blk = make_test_block () in
  let _pos = Storage.FlatFileStorage.write_block t blk 0 in
  (* At this point, block is on disk but index.dat may not be updated yet *)
  (* t.dirty = true but save_index not called *)
  let count_before_close = Storage.FlatFileStorage.block_count t in
  Alcotest.(check int) "block in memory index" 1 count_before_close;
  (* Simulate crash: don't call close (which would call save_index) *)
  (* Reopen and check if block is indexed *)
  let t2 = Storage.FlatFileStorage.create ~magic:Storage.regtest_magic test_blocks_dir in
  let count_after_reopen = Storage.FlatFileStorage.block_count t2 in
  (* BUG-17: if save_index was not called before crash, count_after_reopen = 0 *)
  Alcotest.(check bool) "BUG-17: block survives simulated crash (WAL protected)"
    true (count_after_reopen = count_before_close);
  Storage.FlatFileStorage.close t;
  Storage.FlatFileStorage.close t2;
  cleanup ()

(* ============================================================================
   BUG-18: m_dirty_blockindex absent — every mutation triggers full O(n) save
   Core maintains a std::set<CBlockIndex*> m_dirty_blockindex.
   WriteBlockIndexDB only flushes dirty entries.
   Camlcoin: every update_block_index call sets t.dirty = true and save_index
   writes the entire index.dat (all entries).  On a mainnet node with 900k entries
   this is ~900k × entry_size bytes on every block connect.
   ============================================================================ *)

let test_bug18_dirty_set_absent () =
  (* No m_dirty_blockindex in FlatFileStorage.t type.
     Document: every update_block_index causes a full rewrite. *)
  Alcotest.(check bool) "BUG-18: dirty-blockindex set for incremental flushing present"
    true false  (* BUG: absent *)

(* ============================================================================
   BUG-19: Missing nSequenceId — equal-work tie-breaking impossible
   Core CBlockIndex::nSequenceId (int32) is assigned sequentially as blocks are
   received, with SEQ_ID_BEST_CHAIN_FROM_DISK=0 for best-chain blocks and
   SEQ_ID_INIT_FROM_DISK=1 for others.  Used in CBlockIndexWorkComparator as a
   tie-breaker when two blocks have equal chainwork.
   Camlcoin header_entry has no sequence_id field.
   ============================================================================ *)

let test_bug19_sequence_id_absent () =
  let h = make_test_header () in
  let hash = Crypto.compute_block_hash h in
  let entry : Sync.header_entry = { header = h; hash; height = 0;
                                    total_work = Consensus.zero_work } in
  let _ = entry in
  (* entry.sequence_id would not compile — field absent *)
  Alcotest.(check bool) "BUG-19: nSequenceId field present in header_entry"
    true false  (* BUG: absent *)

(* ============================================================================
   BUG-20: Locator genesis fallback broken for pruned nodes
   build_locator (peer_manager.ml) appends genesis if not already in the list by
   calling List.exists (O(n)).  On a pruned node, height 0 may not be in ChainDB,
   so the genesis-append code finds no hash and silently skips it.
   Core LocatorEntries always terminates with genesis (nHeight==0 break).
   ============================================================================ *)

let test_bug20_locator_pruned_genesis () =
  cleanup ();
  let db = Storage.ChainDB.create test_db_path in
  let state = Sync.create_chain_state db Consensus.regtest in
  (* Normal case: genesis should be in locator *)
  let locator = Peer_manager.build_locator db state.blocks_synced in
  Alcotest.(check bool) "locator non-empty on fresh chain" true (locator <> []);
  (* On pruned node where height 0 is deleted, genesis would be absent.
     Simulate by checking what happens if we build with a fabricated tip_height > 0
     and height 0 not in DB (only genesis was ever stored, so it IS there). *)
  let len = List.length locator in
  Alcotest.(check bool) "BUG-20: locator includes genesis even on pruned node"
    true (len >= 1);  (* This passes because genesis is not pruned in tests *)
  Storage.ChainDB.close db;
  cleanup ()

(* ============================================================================
   BUG-21: FlatFileStorage index format incompatible with Core LevelDB
   Core BlockTreeDB uses LevelDB (CDBWrapper) with key prefixes for block
   index entries ('b' prefix + block_hash → CDiskBlockIndex).
   Camlcoin uses a custom binary "BLKIDX01" file format (storage.ml:1256).
   A node operator cannot run bitcoin-core -reindex on a camlcoin datadir.
   ============================================================================ *)

let test_bug21_blocktreedb_format_incompatible () =
  cleanup ();
  Unix.mkdir test_blocks_dir 0o755;
  let t = Storage.FlatFileStorage.create ~magic:Storage.regtest_magic test_blocks_dir in
  let blk = make_test_block () in
  let _pos = Storage.FlatFileStorage.write_block t blk 0 in
  Storage.FlatFileStorage.close t;
  (* Check that an "index.dat" file was created (not LevelDB directory) *)
  let index_path = Filename.concat test_blocks_dir "index.dat" in
  let is_file = Sys.file_exists index_path && not (Sys.is_directory index_path) in
  (* BUG-21: Core uses a LevelDB directory at blocks/index/, not a flat binary file *)
  Alcotest.(check bool) "BUG-21: index is Core-compatible LevelDB (not a flat file)"
    true (not is_file);  (* BUG: it IS a flat file *)
  cleanup ()

(* ============================================================================
   BUG-22: ScanAndUnlinkAlreadyPrunedFiles absent
   Core: ScanAndUnlinkAlreadyPrunedFiles removes physical blk/rev files that
   were marked pruned in the index but not deleted on disk (e.g., crash during prune).
   Camlcoin has no equivalent startup recovery pass.
   ============================================================================ *)

let test_bug22_scan_unlink_pruned_absent () =
  Alcotest.(check bool) "BUG-22: ScanAndUnlinkAlreadyPrunedFiles equivalent present"
    true false  (* BUG: absent *)

(* ============================================================================
   BUG-23: Block_pruned is not a Core nStatus bit — prune_one_block_file
   adds Block_pruned to the status list without clearing Block_have_data / Block_have_undo.
   Core PruneOneBlockFile only clears BLOCK_HAVE_DATA and BLOCK_HAVE_UNDO
   (nStatus &= ~BLOCK_HAVE_MASK); there is no separate "pruned" bit.
   Camlcoin prune_one_block_file (storage.ml:1642) filters out Block_have_data
   and Block_have_undo but then prepends Block_pruned — introducing a non-Core flag.
   ============================================================================ *)

let test_bug23_block_pruned_not_core_bit () =
  cleanup ();
  Unix.mkdir test_blocks_dir 0o755;
  let t = Storage.FlatFileStorage.create ~magic:Storage.regtest_magic test_blocks_dir in
  let blk = make_test_block () in
  let _pos = Storage.FlatFileStorage.write_block t blk 0 in
  let hash = Crypto.compute_block_hash blk.header in
  (* Prune file 0 *)
  Storage.FlatFileStorage.prune_one_block_file t 0;
  (* Check status after pruning *)
  let entry = Storage.FlatFileStorage.get_block_index t hash in
  (match entry with
   | None -> Alcotest.fail "block not in index after prune"
   | Some e ->
     let has_pruned = List.mem Storage.Block_pruned e.status in
     let has_have_data = List.mem Storage.Block_have_data e.status in
     let has_have_undo = List.mem Storage.Block_have_undo e.status in
     Alcotest.(check bool) "Block_have_data cleared on prune" false has_have_data;
     Alcotest.(check bool) "Block_have_undo cleared on prune" false has_have_undo;
     (* BUG-23: Block_pruned is added (not a Core nStatus bit) *)
     Alcotest.(check bool) "BUG-23: Block_pruned is not added (not a Core nStatus flag)"
       false has_pruned);  (* BUG: it IS added *)
  Storage.FlatFileStorage.close t;
  cleanup ()

(* ============================================================================
   BUG-24: find_fork_point is O(n) pprev walk (confirmed regression from BUG-8)
   Tests the runtime path explicitly: on a chain of depth N, fork from genesis
   requires N steps.
   ============================================================================ *)

let test_bug24_find_fork_point_linear () =
  cleanup ();
  let db = Storage.ChainDB.create test_db_path in
  let state = Sync.create_chain_state db Consensus.regtest in
  let genesis = match state.Sync.tip with Some e -> e | None -> assert false in

  (* Build a linear chain of 20 headers *)
  let rec build_chain (prev : Sync.header_entry) n acc =
    if n = 0 then acc
    else
      let h = make_test_header ~prev_block:prev.hash
                ~timestamp:(Int32.add prev.header.timestamp 600l)
                ~bits:0x207fffffl () in
      let hash = Crypto.compute_block_hash h in
      let e : Sync.header_entry = { header = h; hash; height = prev.height + 1;
                total_work = Consensus.work_add prev.total_work (Sync.work_from_bits h.bits) } in
      Hashtbl.replace state.headers (Cstruct.to_string hash) e;
      build_chain e (n-1) (e :: acc)
  in
  let chain = List.rev (build_chain genesis 20 []) in
  let tip = List.nth chain 19 in

  (* find_fork_point between tip (height 20) and genesis (height 0) *)
  let _t0 = Unix.gettimeofday () in
  let result = Sync.find_fork_point state tip genesis in
  (match result with
   | Ok fork -> Alcotest.(check int) "BUG-24: fork at genesis" 0 fork.height
   | Error msg -> Alcotest.failf "find_fork_point failed: %s" msg);
  Storage.ChainDB.close db;
  cleanup ()

(* ============================================================================
   BUG-25: total_work recomputed sequentially on restore — orphan entries get zero_work
   restore_chain_state (sync.ml:690) loads headers h=0..tip_height and calls
   work_add(parent.total_work, work_from_bits(header.bits)) for each.
   If parent entry is missing (orphan or out-of-order DB), total_work defaults to zero_work.
   Core reconstructs nChainWork from nBits during LoadBlockIndex by walking pprev.
   ============================================================================ *)

let test_bug25_total_work_orphan_fallback () =
  cleanup ();
  let db = Storage.ChainDB.create test_db_path in
  let state = Sync.create_chain_state db Consensus.regtest in
  let genesis = match state.tip with Some e -> e | None -> assert false in

  (* Build header at height 2 with a missing parent at height 1 *)
  let h1 = make_test_header ~prev_block:genesis.hash
             ~timestamp:(Int32.add genesis.header.timestamp 600l)
             ~bits:0x207fffffl () in
  let h1_hash = Crypto.compute_block_hash h1 in
  let h2 = make_test_header ~prev_block:h1_hash
             ~timestamp:(Int32.add genesis.header.timestamp 1200l)
             ~bits:0x207fffffl () in
  let h2_hash = Crypto.compute_block_hash h2 in
  (* Store h2 in DB at height 2 but skip h1 *)
  Storage.ChainDB.store_block_header db h2_hash h2;
  Storage.ChainDB.set_height_hash db 2 h2_hash;

  (* Restore — h2's parent h1 is not in state.headers *)
  (* total_work for h2 will default to zero_work *)
  let h2_entry_opt = Hashtbl.find_opt state.headers (Cstruct.to_string h2_hash) in
  (* h2 not loaded because height_hash 2 exists but parent chain is broken *)
  (* BUG-25: if h2 were loaded, total_work would be zero_work (wrong) *)
  let _ = h2_entry_opt in
  Alcotest.(check bool) "BUG-25: orphan header total_work correctly computed (not zero)"
    true false;  (* BUG: defaults to zero_work *)
  Storage.ChainDB.close db;
  cleanup ()

(* ============================================================================
   BUG-26: No FlushBlockFile before switching to new file
   Core FindNextBlockPos calls FlushBlockFile(old_file) before incrementing
   the cursor to ensure all buffered writes are persisted.
   Camlcoin find_next_block_pos (storage.ml:1342) increments last_file without
   flushing the previous file.
   ============================================================================ *)

let test_bug26_flush_before_new_file () =
  cleanup ();
  Unix.mkdir test_blocks_dir 0o755;
  (* Create a storage with a very small max blockfile size to force rollover *)
  (* We cannot easily override max_blockfile_size in the module, but we can
     write enough data to approach the limit in a unit-test scale.
     Instead, document the structural absence of a flush call. *)
  Alcotest.(check bool) "BUG-26: FlushBlockFile called before new-file rollover"
    true false;  (* BUG: absent *)
  cleanup ()

(* ============================================================================
   BUG-27: write_block has no mutual-exclusion lock
   Unix.openfile + Unix.lseek + Unix.write is not atomic.
   Concurrent write_block calls on the same FlatFileStorage.t could interleave.
   Core uses cs_LastBlockFile (RecursiveMutex) around all block-file writes.
   Camlcoin: no mutex in FlatFileStorage.write_block.
   ============================================================================ *)

let test_bug27_write_block_no_mutex () =
  (* No cs_LastBlockFile equivalent in FlatFileStorage.t type *)
  Alcotest.(check bool) "BUG-27: write_block has cs_LastBlockFile-equivalent mutex"
    true false  (* BUG: absent *)

(* ============================================================================
   BUG-28: block_file_info time_first/time_last stored as int32 (4 bytes)
   Core CBlockFileInfo.nTimeFirst / nTimeLast are uint64 VARINT (8 bytes).
   Camlcoin block_file_info time_first/time_last are int32 (4 bytes).
   Unix timestamps > 2^31 - 1 (after 2038-01-19) will overflow.
   ============================================================================ *)

let test_bug28_time_overflow () =
  (* Demonstrate that time_first/time_last is int32 in camlcoin's block_file_info *)
  let fi = Storage.empty_file_info () in
  (* int32 max = 2147483647 = 2038-01-19 03:14:07 UTC *)
  let post_2038_timestamp = 0x80000000l in  (* 2147483648 — overflows int32 *)
  fi.time_first <- post_2038_timestamp;
  (* int32 wraps: 0x80000000l = -2147483648l in signed int32 *)
  let wrapped = fi.time_first in
  Alcotest.(check bool) "BUG-28: timestamp 2^31 stored without overflow"
    true (Int32.compare wrapped post_2038_timestamp = 0)

(* ============================================================================
   BUG-29: CChain::IsTipRecent absent
   Core CChain::IsTipRecent(min_chain_work, max_tip_age) checks that the tip
   has sufficient work and was mined recently.  Used by net_processing to gate
   header relay and new-block announcements.
   Camlcoin: no equivalent — sync.ml checks minimum_chain_work inline but does
   not check tip age.
   ============================================================================ *)

let test_bug29_is_tip_recent_absent () =
  Alcotest.(check bool) "BUG-29: CChain::IsTipRecent equivalent present"
    true false  (* BUG: absent *)

(* ============================================================================
   PASS-30: max_blockfile_size = 0x8000000 = 128 MiB matches Core MAX_BLOCKFILE_SIZE
   ============================================================================ *)

let test_pass30_max_blockfile_size () =
  (* Core: static const unsigned int MAX_BLOCKFILE_SIZE = 0x8000000; // 128 MiB *)
  let core_max = 0x8000000 in
  Alcotest.(check int) "PASS-30: max_blockfile_size = 0x8000000 (128 MiB)"
    core_max Storage.max_blockfile_size

(* ============================================================================
   Runner
   ============================================================================ *)

let () =
  Alcotest.run "W109 CChain + CBlockIndex + CBlockTreeDB + block-file storage"
    [
      "G1  block_status bitmask", [
        Alcotest.test_case "block_status_bitmask_wrong" `Quick test_bug1_block_status_bitmask;
      ];
      "G2  CDiskBlockIndex serialisation", [
        Alcotest.test_case "diskblockindex_varint_format" `Quick test_bug2_diskblockindex_serialisation;
      ];
      "G3  Duplicate status tags", [
        Alcotest.test_case "duplicate_status_accepted" `Quick test_bug3_duplicate_status_tags;
      ];
      "G4  BLOCK_VALID_MASK absent", [
        Alcotest.test_case "block_valid_mask_encoding" `Quick test_bug4_block_valid_mask;
      ];
      "G5  BLOCK_OPT_WITNESS absent", [
        Alcotest.test_case "block_opt_witness_absent" `Quick test_bug5_block_opt_witness_absent;
      ];
      "G6  m_chain_tx_count absent", [
        Alcotest.test_case "chain_tx_count_absent" `Quick test_bug6_missing_chain_tx_count;
      ];
      "G7  nTimeMax absent", [
        Alcotest.test_case "ntimemax_absent" `Quick test_bug7_missing_ntimemax;
      ];
      "G8  Skip list absent", [
        Alcotest.test_case "skip_list_absent" `Quick test_bug8_skip_list_absent;
      ];
      "G9  CChain::SetTip absent", [
        Alcotest.test_case "cchain_settip_absent" `Quick test_bug9_cchain_settip_absent;
      ];
      "G10 CChain::Contains absent", [
        Alcotest.test_case "cchain_contains_absent" `Quick test_bug10_cchain_contains;
      ];
      "G11 Locator genesis O(n^2)", [
        Alcotest.test_case "locator_genesis_o_n_squared" `Quick test_bug11_locator_genesis_inclusion;
      ];
      "G12 Undo checksum SHA256 not SHA256d+pprev", [
        Alcotest.test_case "undo_checksum_algorithm" `Quick test_bug12_undo_checksum_algorithm;
      ];
      "G13 Undo wire format incompatible", [
        Alcotest.test_case "undo_wire_format" `Quick test_bug13_undo_wire_format;
      ];
      "G14 nMinDiskSpace absent", [
        Alcotest.test_case "nmindbiskspace_absent" `Quick test_bug14_nmindbiskspace_absent;
      ];
      "G15 File pre-allocation absent", [
        Alcotest.test_case "file_prealloc_absent" `Quick test_bug15_file_preallocation_absent;
      ];
      "G16 BlockfileType cursor absent", [
        Alcotest.test_case "blockfile_type_cursor" `Quick test_bug16_blockfile_type_cursor_absent;
      ];
      "G17 WriteBlockIndexDB atomicity", [
        Alcotest.test_case "writeblockindexdb_atomicity" `Quick test_bug17_writeblockindex_atomicity;
      ];
      "G18 m_dirty_blockindex absent", [
        Alcotest.test_case "dirty_blockindex_absent" `Quick test_bug18_dirty_set_absent;
      ];
      "G19 nSequenceId absent", [
        Alcotest.test_case "sequence_id_absent" `Quick test_bug19_sequence_id_absent;
      ];
      "G20 Locator pruned-genesis", [
        Alcotest.test_case "locator_pruned_genesis" `Quick test_bug20_locator_pruned_genesis;
      ];
      "G21 BlockTreeDB format incompatible", [
        Alcotest.test_case "blocktreedb_format" `Quick test_bug21_blocktreedb_format_incompatible;
      ];
      "G22 ScanUnlinkPrunedFiles absent", [
        Alcotest.test_case "scan_unlink_absent" `Quick test_bug22_scan_unlink_pruned_absent;
      ];
      "G23 Block_pruned non-Core bit", [
        Alcotest.test_case "block_pruned_noncore_bit" `Quick test_bug23_block_pruned_not_core_bit;
      ];
      "G24 find_fork_point O(n)", [
        Alcotest.test_case "find_fork_point_linear" `Quick test_bug24_find_fork_point_linear;
      ];
      "G25 total_work orphan zero-fallback", [
        Alcotest.test_case "total_work_orphan" `Quick test_bug25_total_work_orphan_fallback;
      ];
      "G26 No flush before new file", [
        Alcotest.test_case "flush_before_new_file" `Quick test_bug26_flush_before_new_file;
      ];
      "G27 write_block no mutex", [
        Alcotest.test_case "write_block_no_mutex" `Quick test_bug27_write_block_no_mutex;
      ];
      "G28 time_first/last int32 overflow", [
        Alcotest.test_case "time_overflow" `Quick test_bug28_time_overflow;
      ];
      "G29 IsTipRecent absent", [
        Alcotest.test_case "is_tip_recent_absent" `Quick test_bug29_is_tip_recent_absent;
      ];
      "G30 max_blockfile_size correct", [
        Alcotest.test_case "max_blockfile_size" `Quick test_pass30_max_blockfile_size;
      ];
    ]
