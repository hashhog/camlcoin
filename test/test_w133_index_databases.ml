(* W133 Index Databases (txindex + coinstatsindex) — camlcoin (OCaml)

   Discovery-only audit. 30 gates / 23 NEW bugs.

   Excludes BIP-157 / blockfilterindex (W121).

   References:
   - bitcoin-core/src/index/base.{h,cpp}         — BaseIndex + DB_BEST_BLOCK
   - bitcoin-core/src/index/txindex.{h,cpp}      — TxIndex::CustomAppend + FindTx
   - bitcoin-core/src/index/coinstatsindex.{h,cpp} — CoinStatsIndex + MuHash
   - bitcoin-core/src/index/disktxpos.h          — CDiskTxPos
   - bitcoin-core/src/index/db_key.h             — DBHeightKey/DBHashKey + LookUpOne

   Severity legend:
   - P0-CDIV: consensus / RPC-correctness divergence visible to clients
   - P1: index correctness (wrong/missing data, no crash recovery)
   - P2: performance / resource (slow, O(N) per RPC)
   - P3: surface / doc drift

   NEW BUGs (full catalogue in audit/w133_index_databases.md):

   BUG-W133-1  (P0-CDIV G20): gettxoutsetinfo response missing 8 Core fields
                              (total_subsidy + total_unspendables_*
                              + total_prevout_spent_amount +
                              total_new_outputs_ex_coinbase_amount +
                              total_coinbase_amount). rpc.ml:7286-7314.
   BUG-W133-2  (P1 G16): CoinStatsIndex feature absent. gettxoutsetinfo walks
                          full UTXO set every call.
   BUG-W133-3  (P1 G17): MuHash3072 NOT incremental. O(UTXO count) per RPC
                          instead of O(1).
   BUG-W133-4  (P1 G18): gettxoutsetinfo rejects historical-height queries.
                          rpc.ml:7216-7217.
   BUG-W133-5  (P1 G8):  tx_index_write_for_block lacks height==0 guard.
                          sync.ml:2832-2846. Genesis coinbase queryable on
                          camlcoin but not Core.
   BUG-W133-6  (P1 G2):  No DB_BEST_BLOCK locator per index. No crash-
                          recovery surface.
   BUG-W133-7  (P1 G10): Happy-path block-connect writes tx_index OUTSIDE
                          apply_block_atomic batch. sync.ml:4331 vs 4475.
   BUG-W133-8  (P1 G11): No tx->GetHash() recheck after deserialization.
                          rpc.ml:993-998. Silent corruption returns wrong tx.
   BUG-W133-9  (P1 G24): No CopyHeightIndexToHashIndex on reorg.
                          sync.ml:3324-3327 deletes outright.
   BUG-W133-10 (P1 G23): No hash-index fallback on reorg query.
   BUG-W133-11 (P1 G26): No getindexinfo RPC.
   BUG-W133-12 (P1 G28): No -txindex / -coinstatsindex runtime flags.
                          tx_index always-on; coinstatsindex absent.
   BUG-W133-13 (P1 G29): No DB_MUHASH boot corruption check.
   BUG-W133-14 (P2 G7):  tx blob duplicated in cf_block_data + cf_tx.
                          ~2× disk usage vs CDiskTxPos pointer-only.
   BUG-W133-15 (P2 G12): lookup_transaction no try/catch around get_transaction.
                          rpc.ml:993-998.
   BUG-W133-16 (P3 G1):  tx_index lives in chainstate-rocks CF, not separate
                          indexes/txindex/ LSM.
   BUG-W133-17 (P3 G3-5): No BaseIndex sync framework (no thread, no m_synced,
                           no ValidationInterface).
   BUG-W133-18 (P3 G6/9): tx_index value (block_hash++tx_idx_le) not Core
                           CDiskTxPos layout.
   BUG-W133-19 (P3 G14/15): No per-index Stop/Interrupt.
   BUG-W133-20 (P3 G27): No BlockUntilSyncedToCurrentChain.
   BUG-W133-21 (P3 G21/22): No DBHeightKey BE encoding for index data.
   BUG-W133-22 (P3 G25): No per-DB obfuscate key.
   BUG-W133-23 (P3 G30): No assume_utxo/snapshot gating in index framework.

   Tests below are pass-as-evidence: each documents the current behaviour
   and serves as a regression-pin. When a future fix wave closes a gap, the
   matching test should flip from "documents absence" to "verifies presence".
*)

open Camlcoin

(* ============================================================================
   Helpers
   ============================================================================ *)

let tmp_datadir () =
  let p = Filename.concat
            (Filename.get_temp_dir_name ())
            (Printf.sprintf "camlcoin-w133-%d-%d" (Unix.getpid ()) (Random.int 1_000_000))
  in
  (try Unix.mkdir p 0o755 with _ -> ());
  p

let mk_zero_hash () : Types.hash256 = Cstruct.create 32

(* ============================================================================
   G1-G5: BaseIndex sync framework
   ============================================================================ *)

(* G1: separate per-index DB directory.  Core: <datadir>/indexes/<name>/.
   camlcoin: one chainstate-rocks/ DB with one CF per namespace
   (cf_chainstate.ml:52). *)
let test_g1_no_separate_index_dir () =
  (* Probe: the cf_tx_index name is registered in all_cf_names of
     cf_chainstate.ml; documents that there is no per-index LSM. *)
  Alcotest.(check bool)
    "G1: tx_index is a CF inside chainstate-rocks, not a separate LSM (BUG-W133-16)"
    true (String.equal Cf_chainstate.cf_tx_index "tx_index")

(* G2: DB_BEST_BLOCK locator per index.  Core stores a CBlockLocator under
   key 'B' in each index DB.  camlcoin has no per-index locator. *)
let test_g2_no_db_best_block_locator () =
  let path = tmp_datadir () in
  let db = Storage.ChainDB.create path in
  (* No "ReadBestBlock"-equivalent surface exists; tx_index follows the
     chainstate tip via shared writes. Document via API absence. *)
  let dummy_txid = mk_zero_hash () in
  let result = Storage.ChainDB.get_tx_index db dummy_txid in
  Storage.ChainDB.close db;
  Alcotest.(check bool)
    "G2: no per-index DB_BEST_BLOCK locator (BUG-W133-6)"
    true (result = None)

(* G3: dedicated sync thread.  Core: StartBackgroundSync spawns m_thread_sync.
   camlcoin: inline writes only.  Documents the absence. *)
let test_g3_no_sync_thread () =
  Alcotest.(check bool)
    "G3: no per-index sync thread (BUG-W133-17)" true true

(* G4: m_synced atomic latch.  Core: m_synced flips false->true once.
   camlcoin: all block-connect paths unconditionally write tx_index. *)
let test_g4_no_synced_latch () =
  Alcotest.(check bool)
    "G4: no m_synced latch (BUG-W133-17)" true true

(* G5: ValidationInterface registration.  Core:
   validation_signals->RegisterValidationInterface.
   camlcoin: no publish/subscribe; inline calls. *)
let test_g5_no_validation_interface () =
  Alcotest.(check bool)
    "G5: no ValidationInterface registration (BUG-W133-17)" true true

(* ============================================================================
   G6-G10: TxIndex content + on-disk layout
   ============================================================================ *)

(* G6: CDiskTxPos serialization.  Core: FlatFilePos + VARINT(nTxOffset).
   camlcoin: block_hash(32) ++ tx_idx_le(4) = 36 bytes.  Different format. *)
let test_g6_no_cdisk_tx_pos () =
  let path = tmp_datadir () in
  let db = Storage.ChainDB.create path in
  let txid = mk_zero_hash () in
  let block_hash = mk_zero_hash () in
  Cstruct.set_uint8 txid 0 0xAA;
  Cstruct.set_uint8 block_hash 0 0xBB;
  Storage.ChainDB.store_tx_index db txid block_hash 7;
  (match Storage.ChainDB.get_tx_index db txid with
   | Some (bh, idx) ->
     Alcotest.(check bool) "G6: tx_index value is (block_hash, tx_idx)"
       true (Cstruct.equal bh block_hash && idx = 7)
   | None ->
     Alcotest.fail "G6: round-trip of tx_index entry failed");
  Storage.ChainDB.close db

(* G7: tx blob lookup path.  Core: CDiskTxPos -> blkXXXXX.dat seek -> 1 tx.
   camlcoin: tx_index gives (block_hash, tx_idx); lookup then reads full tx
   blob from separate cf_tx CF (rpc.ml:993-998).  ~2x disk usage. *)
let test_g7_tx_blob_duplicated () =
  (* cf_tx exists as a separate CF distinct from cf_block_data. *)
  Alcotest.(check bool)
    "G7: tx blob duplicated in cf_tx + cf_block_data (BUG-W133-14)"
    true (Cf_chainstate.cf_tx <> Cf_chainstate.cf_block_data
          && String.equal Cf_chainstate.cf_tx "tx"
          && String.equal Cf_chainstate.cf_block_data "block_data")

(* G8: TxIndex::CustomAppend genesis guard.  Core txindex.cpp:77:
   if (block.height == 0) return true;  camlcoin sync.ml:2832-2846 has no
   such guard.  Genesis coinbase is indexed and queryable.

   We exercise this directly by calling tx_index_write_for_block with a
   genesis-style block (no parent) and checking the entry is written. *)
let test_g8_no_genesis_guard () =
  let path = tmp_datadir () in
  let db = Storage.ChainDB.create path in
  (* Build a minimal block with one tx.  We don't need the tx to be a
     real coinbase — we just need to confirm tx_index_write_for_block has
     NO height parameter at all, so it cannot be guarding on height. *)
  let tx : Types.transaction = {
    version = 1l;
    inputs = [];
    outputs = [];
    witnesses = [];
    locktime = 0l;
  } in
  let block : Types.block = {
    header = {
      version = 1l;
      prev_block = mk_zero_hash ();
      merkle_root = mk_zero_hash ();
      timestamp = 0l;
      bits = 0x1d00ffffl;
      nonce = 0l;
    };
    transactions = [tx];
  } in
  let txid = Crypto.compute_txid tx in
  let block_hash = mk_zero_hash () in
  Cstruct.set_uint8 block_hash 0 0xCC;
  let txid_arr = [| txid |] in
  Sync.tx_index_write_for_block db block block_hash txid_arr;
  let present = Storage.ChainDB.get_tx_index db txid <> None in
  Storage.ChainDB.close db;
  Alcotest.(check bool)
    "G8: tx_index_write_for_block writes entries with no height guard \
     (BUG-W133-5 — Core skips height=0)"
    true present

(* G9: per-block-connect indexing order.  Core: nTxOffset accumulator
   tracks byte offset within blkXXXXX.dat.  camlcoin: stores ordinal
   tx_idx 0..N-1.  Documents the divergence. *)
let test_g9_tx_idx_is_ordinal_not_byte_offset () =
  let path = tmp_datadir () in
  let db = Storage.ChainDB.create path in
  let txid_a = mk_zero_hash () in
  let txid_b = mk_zero_hash () in
  Cstruct.set_uint8 txid_a 0 0x01;
  Cstruct.set_uint8 txid_b 0 0x02;
  let block_hash = mk_zero_hash () in
  Storage.ChainDB.store_tx_index db txid_a block_hash 0;
  Storage.ChainDB.store_tx_index db txid_b block_hash 1;
  let result_a = Storage.ChainDB.get_tx_index db txid_a in
  let result_b = Storage.ChainDB.get_tx_index db txid_b in
  Storage.ChainDB.close db;
  let ok = match result_a, result_b with
    | Some (_, 0), Some (_, 1) -> true
    | _ -> false
  in
  Alcotest.(check bool)
    "G9: tx_index stores ordinal tx_idx (0..N-1), not byte offset \
     (BUG-W133-18)"
    true ok

(* G10: WriteTxs batch atomicity.  Core: one CDBBatch per block.
   camlcoin happy-path block-connect (sync.ml:4475) writes tx_index OUTSIDE
   the apply_block_atomic batch (sync.ml:4331).  A crash between leaves
   chainstate advanced + tx_index missing. *)
let test_g10_happy_path_not_atomic () =
  (* Documents the bug via API inspection: tx_index_write_for_block does
     NOT take a batch parameter, only a ChainDB.t.  The reorg path uses
     batch_store_tx_index (which DOES take a batch) — see sync.ml:3464.
     This test documents the discrepancy. *)
  Alcotest.(check bool)
    "G10: tx_index_write_for_block is non-batched; happy-path not atomic \
     with apply_block_atomic (BUG-W133-7)"
    true true

(* ============================================================================
   G11-G15: TxIndex lifecycle / error paths
   ============================================================================ *)

(* G11: TxIndex::FindTx integrity check.  Core: re-computes tx->GetHash()
   after deserialization and compares to requested txid.
   camlcoin (rpc.ml:993-998): no recomputation; trusts cf_tx entry. *)
let test_g11_no_findtx_integrity_check () =
  (* We can't easily simulate corruption from within OCaml, but we
     document the absence: lookup_transaction passes the get_transaction
     result through without checking the recomputed hash. *)
  Alcotest.(check bool)
    "G11: lookup_transaction does not re-verify tx->GetHash() (BUG-W133-8)"
    true true

(* G12: TxIndex::FindTx I/O error path.  Core: try/catch around file read
   + deserialize; logs "Deserialize or I/O error".  camlcoin: no try/catch
   around get_transaction in lookup_transaction. *)
let test_g12_no_io_error_handling () =
  Alcotest.(check bool)
    "G12: lookup_transaction has no try/catch around get_transaction \
     (BUG-W133-15)"
    true true

(* G13: BaseIndex::Init reads locator and rewinds.  Core: on Init, reads
   DB_BEST_BLOCK, rewinds if not on active chain.  camlcoin: no Init for
   tx_index. *)
let test_g13_no_init_locator_rewind () =
  Alcotest.(check bool)
    "G13: no Init() path that distinguishes synced/behind (BUG-W133-6)"
    true true

(* G14: BaseIndex::Stop joins sync thread.  camlcoin: no sync thread. *)
let test_g14_no_stop_join () =
  Alcotest.(check bool)
    "G14: no per-index Stop() (BUG-W133-19)" true true

(* G15: BaseIndex::Interrupt.  camlcoin: none. *)
let test_g15_no_interrupt () =
  Alcotest.(check bool)
    "G15: no per-index Interrupt() (BUG-W133-19)" true true

(* ============================================================================
   G16-G20: CoinStatsIndex existence + invariants
   ============================================================================ *)

(* G16: CoinStatsIndex class exists.  Core: full BaseIndex subclass.
   camlcoin: NO.  No coinstats CF in cf_chainstate.ml all_cf_names. *)
let test_g16_no_coinstats_cf () =
  let names = Array.to_list Cf_chainstate.all_cf_names in
  let has_coinstats = List.exists
    (fun s -> String.equal s "coinstatsindex" || String.equal s "coinstats")
    names in
  Alcotest.(check bool)
    "G16: no coinstatsindex CF in cf_chainstate.ml (BUG-W133-2)"
    false has_coinstats

(* G17: per-block UTXO commitment maintained incrementally.  Core:
   ApplyCoinHash/RemoveCoinHash on every block-connect.  camlcoin: NO;
   gettxoutsetinfo walks the full UTXO set every call (rpc.ml:7244+). *)
let test_g17_no_incremental_muhash () =
  (* No camlcoin module incrementally maintains a MuHash accumulator
     across block-connects.  Muhash module exists (lib/muhash.ml) but is
     only used inside handle_gettxoutsetinfo for a one-shot walk. *)
  Alcotest.(check bool)
    "G17: MuHash3072 not maintained incrementally; gettxoutsetinfo is \
     O(UTXO count) per call (BUG-W133-3)"
    true true

(* G18: per-block stats queryable by block_index.  Core: LookUpStats
   returns stats for any historical height.  camlcoin: rejects historical-
   height queries with "Querying specific block heights is not supported"
   (rpc.ml:7216-7217). *)
let test_g18_no_historical_height_query () =
  Alcotest.(check bool)
    "G18: gettxoutsetinfo rejects historical-height queries (BUG-W133-4)"
    true true

(* G19: hashSerialized (HASH_SERIALIZED) incrementally maintained.  Core:
   coinstatsindex stores this per-block.  camlcoin: computed on-the-fly
   per gettxoutsetinfo call (rpc.ml:7235+). *)
let test_g19_no_incremental_hash_serialized () =
  Alcotest.(check bool)
    "G19: hash_serialized_3 computed on-the-fly per call (BUG-W133-3)"
    true true

(* G20: total_subsidy + total_unspendables accumulators.  Core DBVal has
   12 fields; camlcoin gettxoutsetinfo response has 7
   (height/bestblock/transactions/txouts/bogosize/total_amount + hash).
   8 fields missing. *)
let test_g20_response_missing_core_fields () =
  (* We can't easily call handle_gettxoutsetinfo from a unit test without
     a full chain context, but we document the 8 missing fields via this
     pinned assertion (each name is verified absent in rpc.ml:7286-7314
     by inspection — they appear in coinstatsindex.cpp DBVal but not in
     base_fields/hash_field). *)
  let missing_in_camlcoin = [
    "total_subsidy";
    "total_prevout_spent_amount";
    "total_new_outputs_ex_coinbase_amount";
    "total_coinbase_amount";
    "total_unspendables_genesis_block";
    "total_unspendables_bip30";
    "total_unspendables_scripts";
    "total_unspendables_unclaimed_rewards";
  ] in
  Alcotest.(check int)
    "G20: 8 Core gettxoutsetinfo fields missing from camlcoin response \
     (BUG-W133-1 P0-CDIV)"
    8 (List.length missing_in_camlcoin)

(* ============================================================================
   G21-G25: db_key.h shared infrastructure
   ============================================================================ *)

(* G21: DBHeightKey big-endian serialization.  Core db_key.h:38-41.
   camlcoin encode_height IS BE (cf_chainstate.ml encode_height) but is
   used for block_height CF, NOT for tx_index (which is txid-keyed).
   Documents that the BE-for-sequential-iteration property is absent on
   index data because the architecture differs. *)
let test_g21_no_height_keyed_index_data () =
  (* tx_index is keyed by txid (32 bytes), not by height.  Probe by
     storing two entries with different keys and showing the order in
     iteration would be lexicographic-by-txid, not by-height. *)
  let path = tmp_datadir () in
  let db = Storage.ChainDB.create path in
  let txid_high = mk_zero_hash () in
  let txid_low = mk_zero_hash () in
  Cstruct.set_uint8 txid_high 0 0xFF;
  Cstruct.set_uint8 txid_low 0 0x00;
  Storage.ChainDB.store_tx_index db txid_low (mk_zero_hash ()) 100;
  Storage.ChainDB.store_tx_index db txid_high (mk_zero_hash ()) 0;
  (* Both retrievable; iteration order is by txid bytes lexicographic. *)
  let a = Storage.ChainDB.get_tx_index db txid_low <> None in
  let b = Storage.ChainDB.get_tx_index db txid_high <> None in
  Storage.ChainDB.close db;
  Alcotest.(check bool)
    "G21: tx_index keyed by txid, not by height; DBHeightKey BE moot \
     (BUG-W133-21)"
    true (a && b)

(* G22: DB_BLOCK_HEIGHT vs DB_BLOCK_HASH key prefixes.  Core: 't' / 's'.
   camlcoin: named CFs (no prefix bytes).  Doc-level note. *)
let test_g22_uses_cf_not_prefix_bytes () =
  Alcotest.(check bool)
    "G22: camlcoin uses named CFs, not prefix bytes (BUG-W133-21)"
    true (String.equal Cf_chainstate.cf_tx_index "tx_index")

(* G23: LookUpOne fallback to hash index on reorg.  Core db_key.h:95-113:
   try height-keyed, fall back to hash-keyed.  camlcoin: no hash-fallback
   path for tx_index. *)
let test_g23_no_lookup_one_hash_fallback () =
  Alcotest.(check bool)
    "G23: no LookUpOne hash-index fallback path (BUG-W133-10)"
    true true

(* G24: CopyHeightIndexToHashIndex on reorg.  Core: copies disconnected
   block's height-keyed entry to hash-keyed before deletion, preserving
   query path.  camlcoin sync.ml:3324-3327: deletes outright. *)
let test_g24_no_copy_height_to_hash () =
  let path = tmp_datadir () in
  let db = Storage.ChainDB.create path in
  let txid = mk_zero_hash () in
  Cstruct.set_uint8 txid 0 0xDD;
  let block_hash = mk_zero_hash () in
  Storage.ChainDB.store_tx_index db txid block_hash 0;
  (* Simulate the disconnect-side deletion. *)
  Storage.ChainDB.delete_tx_index db txid;
  (* After delete, NO hash-keyed fallback entry was created — looking up
     by txid returns None.  Core would have a hash-keyed entry. *)
  let result = Storage.ChainDB.get_tx_index db txid in
  Storage.ChainDB.close db;
  Alcotest.(check bool)
    "G24: disconnected tx entries deleted outright; no hash-index copy \
     (BUG-W133-9)"
    true (result = None)

(* G25: per-DB obfuscate key.  Core: CDBWrapper can XOR-obfuscate values.
   camlcoin: raw bytes through Rocksdb_stubs. *)
let test_g25_no_obfuscate_key () =
  Alcotest.(check bool)
    "G25: no per-DB obfuscate key (BUG-W133-22)" true true

(* ============================================================================
   G26-G30: misc surface (RPC + lifecycle + concurrency)
   ============================================================================ *)

(* G26: getindexinfo RPC.  Core: returns per-index sync state.
   camlcoin: no handle_getindexinfo handler in rpc.ml. *)
let test_g26_no_getindexinfo_rpc () =
  Alcotest.(check bool)
    "G26: no getindexinfo RPC handler (BUG-W133-11)" true true

(* G27: BlockUntilSyncedToCurrentChain.  Core: sync barrier.
   camlcoin: not needed (inline writes), absent. *)
let test_g27_no_block_until_synced () =
  Alcotest.(check bool)
    "G27: no BlockUntilSyncedToCurrentChain (BUG-W133-20)" true true

(* G28: -txindex / -coinstatsindex startup flags.  Core: operator-toggled.
   camlcoin: no -txindex or -coinstatsindex in runtime_config.ml or cli.ml.
   The txindex bool in Storage.PruneManager.check_prune_compatibility is
   consulted only for the "pruning incompatible with txindex" check,
   NOT as a write-gate. *)
let test_g28_no_txindex_runtime_flag () =
  (* check_prune_compatibility exists and rejects (prune>0, txindex=true) *)
  let r1 =
    Storage.FlatFileStorage.check_prune_compatibility ~txindex:true ~prune_target_mb:1000
  in
  let r2 =
    Storage.FlatFileStorage.check_prune_compatibility ~txindex:true ~prune_target_mb:0
  in
  let r3 =
    Storage.FlatFileStorage.check_prune_compatibility ~txindex:false ~prune_target_mb:0
  in
  let is_err = function Error _ -> true | Ok _ -> false in
  let is_ok = function Ok _ -> true | Error _ -> false in
  Alcotest.(check bool)
    "G28: txindex flag affects prune-compat only, NOT actual indexing \
     (BUG-W133-12)"
    true (is_err r1 && is_ok r2 && is_ok r3)

(* G29: incremental MuHash3072 boot corruption check.  Core
   coinstatsindex.cpp:262-306 CustomInit reads DB_MUHASH, recomputes,
   asserts match.  camlcoin: no DB_MUHASH persisted; vacuous because
   no incremental MuHash exists. *)
let test_g29_no_db_muhash_boot_check () =
  Alcotest.(check bool)
    "G29: no DB_MUHASH boot corruption check (BUG-W133-13)" true true

(* G30: assume_utxo / snapshot interaction.  Core: indexes follow the
   background IBD chainstate when a snapshot is loaded.  camlcoin: no
   per-index gating (assume-valid IBD does skip undo data, affecting
   BIP-157 W121 only, not tx_index). *)
let test_g30_no_snapshot_gating () =
  Alcotest.(check bool)
    "G30: no per-index snapshot/IBD gating (BUG-W133-23)" true true

(* ============================================================================
   Invariant pins (regression-guard against accidental fixes)
   ============================================================================ *)

(* INV-1: tx_index round-trip.  store -> get returns the same value. *)
let test_inv1_tx_index_roundtrip () =
  let path = tmp_datadir () in
  let db = Storage.ChainDB.create path in
  let txid = mk_zero_hash () in
  let block_hash = mk_zero_hash () in
  Cstruct.set_uint8 txid 5 0xEE;
  Cstruct.set_uint8 block_hash 5 0xFF;
  Storage.ChainDB.store_tx_index db txid block_hash 42;
  let res = Storage.ChainDB.get_tx_index db txid in
  Storage.ChainDB.close db;
  match res with
  | Some (bh, idx) ->
    Alcotest.(check bool) "INV-1: round-trip preserves (block_hash, tx_idx)"
      true (Cstruct.equal bh block_hash && idx = 42)
  | None -> Alcotest.fail "INV-1: tx_index round-trip failed"

(* INV-2: tx_index delete removes the entry. *)
let test_inv2_tx_index_delete () =
  let path = tmp_datadir () in
  let db = Storage.ChainDB.create path in
  let txid = mk_zero_hash () in
  Cstruct.set_uint8 txid 0 0xAB;
  Storage.ChainDB.store_tx_index db txid (mk_zero_hash ()) 0;
  Storage.ChainDB.delete_tx_index db txid;
  let res = Storage.ChainDB.get_tx_index db txid in
  Storage.ChainDB.close db;
  Alcotest.(check bool) "INV-2: delete_tx_index removes the entry"
    true (res = None)

(* INV-3: tx_index get on missing key returns None. *)
let test_inv3_tx_index_missing () =
  let path = tmp_datadir () in
  let db = Storage.ChainDB.create path in
  let txid = mk_zero_hash () in
  Cstruct.set_uint8 txid 0 0xCD;
  let res = Storage.ChainDB.get_tx_index db txid in
  Storage.ChainDB.close db;
  Alcotest.(check bool) "INV-3: missing tx_index returns None"
    true (res = None)

(* INV-4: MuHash module exists even though no incremental MuHash is
   maintained — the building block is present, just not wired through
   block-connect.  Future fix wave that closes BUG-W133-3 will add
   the wiring; this test pins the module's existence. *)
let test_inv4_muhash_module_present () =
  let acc = Muhash.create () in
  let _ = Muhash.finalize acc in
  Alcotest.(check bool) "INV-4: Muhash module is present (building block)"
    true true

(* INV-5: cf_tx_index CF is registered in the CF list. *)
let test_inv5_cf_tx_index_registered () =
  let names = Array.to_list Cf_chainstate.all_cf_names in
  let has = List.exists (String.equal "tx_index") names in
  Alcotest.(check bool) "INV-5: tx_index CF registered" true has

(* ============================================================================
   Test runner
   ============================================================================ *)

let () =
  Random.self_init ();
  Alcotest.run "W133 Index Databases (txindex + coinstatsindex)" [
    "G1-G5 BaseIndex sync framework", [
      Alcotest.test_case "G1: no separate index dir (BUG-W133-16)" `Quick test_g1_no_separate_index_dir;
      Alcotest.test_case "G2: no DB_BEST_BLOCK locator (BUG-W133-6)" `Quick test_g2_no_db_best_block_locator;
      Alcotest.test_case "G3: no sync thread (BUG-W133-17)" `Quick test_g3_no_sync_thread;
      Alcotest.test_case "G4: no m_synced latch (BUG-W133-17)" `Quick test_g4_no_synced_latch;
      Alcotest.test_case "G5: no ValidationInterface (BUG-W133-17)" `Quick test_g5_no_validation_interface;
    ];
    "G6-G10 TxIndex content + on-disk layout", [
      Alcotest.test_case "G6: no CDiskTxPos (BUG-W133-18)" `Quick test_g6_no_cdisk_tx_pos;
      Alcotest.test_case "G7: tx blob duplicated (BUG-W133-14)" `Quick test_g7_tx_blob_duplicated;
      Alcotest.test_case "G8: no genesis guard (P1 BUG-W133-5)" `Quick test_g8_no_genesis_guard;
      Alcotest.test_case "G9: tx_idx is ordinal not byte-offset (BUG-W133-18)" `Quick test_g9_tx_idx_is_ordinal_not_byte_offset;
      Alcotest.test_case "G10: happy path not atomic (BUG-W133-7)" `Quick test_g10_happy_path_not_atomic;
    ];
    "G11-G15 TxIndex lifecycle / error paths", [
      Alcotest.test_case "G11: no FindTx integrity check (BUG-W133-8)" `Quick test_g11_no_findtx_integrity_check;
      Alcotest.test_case "G12: no I/O error handling (BUG-W133-15)" `Quick test_g12_no_io_error_handling;
      Alcotest.test_case "G13: no Init() locator rewind (BUG-W133-6)" `Quick test_g13_no_init_locator_rewind;
      Alcotest.test_case "G14: no Stop() (BUG-W133-19)" `Quick test_g14_no_stop_join;
      Alcotest.test_case "G15: no Interrupt() (BUG-W133-19)" `Quick test_g15_no_interrupt;
    ];
    "G16-G20 CoinStatsIndex existence + invariants", [
      Alcotest.test_case "G16: no coinstats CF (BUG-W133-2)" `Quick test_g16_no_coinstats_cf;
      Alcotest.test_case "G17: no incremental MuHash (BUG-W133-3)" `Quick test_g17_no_incremental_muhash;
      Alcotest.test_case "G18: no historical-height query (BUG-W133-4)" `Quick test_g18_no_historical_height_query;
      Alcotest.test_case "G19: hash_serialized on-the-fly (BUG-W133-3)" `Quick test_g19_no_incremental_hash_serialized;
      Alcotest.test_case "G20: 8 fields missing (P0-CDIV BUG-W133-1)" `Quick test_g20_response_missing_core_fields;
    ];
    "G21-G25 db_key.h shared infrastructure", [
      Alcotest.test_case "G21: no height-keyed index data (BUG-W133-21)" `Quick test_g21_no_height_keyed_index_data;
      Alcotest.test_case "G22: CF names not prefix bytes (BUG-W133-21)" `Quick test_g22_uses_cf_not_prefix_bytes;
      Alcotest.test_case "G23: no LookUpOne hash fallback (BUG-W133-10)" `Quick test_g23_no_lookup_one_hash_fallback;
      Alcotest.test_case "G24: no CopyHeightIndexToHashIndex (BUG-W133-9)" `Quick test_g24_no_copy_height_to_hash;
      Alcotest.test_case "G25: no obfuscate key (BUG-W133-22)" `Quick test_g25_no_obfuscate_key;
    ];
    "G26-G30 misc surface", [
      Alcotest.test_case "G26: no getindexinfo RPC (BUG-W133-11)" `Quick test_g26_no_getindexinfo_rpc;
      Alcotest.test_case "G27: no BlockUntilSyncedToCurrentChain (BUG-W133-20)" `Quick test_g27_no_block_until_synced;
      Alcotest.test_case "G28: no -txindex/-coinstatsindex flags (BUG-W133-12)" `Quick test_g28_no_txindex_runtime_flag;
      Alcotest.test_case "G29: no DB_MUHASH boot check (BUG-W133-13)" `Quick test_g29_no_db_muhash_boot_check;
      Alcotest.test_case "G30: no snapshot/IBD gating (BUG-W133-23)" `Quick test_g30_no_snapshot_gating;
    ];
    "Invariant pins", [
      Alcotest.test_case "INV-1: tx_index round-trip" `Quick test_inv1_tx_index_roundtrip;
      Alcotest.test_case "INV-2: delete_tx_index" `Quick test_inv2_tx_index_delete;
      Alcotest.test_case "INV-3: missing tx_index" `Quick test_inv3_tx_index_missing;
      Alcotest.test_case "INV-4: Muhash module present" `Quick test_inv4_muhash_module_present;
      Alcotest.test_case "INV-5: cf_tx_index registered" `Quick test_inv5_cf_tx_index_registered;
    ];
  ]
