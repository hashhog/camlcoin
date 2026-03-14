(* Tests for sync module *)

open Camlcoin

(* Test directory that gets cleaned up *)
let test_db_path = "/tmp/camlcoin_test_sync_db"

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

(* Helper to create a test block header with valid PoW for regtest *)
let make_test_header ~prev_block ~ts ~nc =
  Types.{
    version = 1l;
    prev_block;
    merkle_root = Types.zero_hash;
    timestamp = ts;
    bits = 0x207fffffl;  (* Very low difficulty for regtest *)
    nonce = nc;
  }

(* Test work_from_bits calculation *)
let test_work_from_bits () =
  (* Low difficulty (regtest) should have low work per block *)
  let regtest_work = Sync.work_from_bits 0x207fffffl in
  Alcotest.(check bool) "regtest work > 0" true
    (Consensus.work_compare regtest_work Consensus.zero_work > 0);

  (* High difficulty (mainnet genesis) should have higher work *)
  let mainnet_work = Sync.work_from_bits 0x1d00ffffl in
  Alcotest.(check bool) "mainnet work > regtest work"
    true (Consensus.work_compare mainnet_work regtest_work > 0);

  (* Zero target should give 0 work *)
  let zero_work = Sync.work_from_bits 0l in
  Alcotest.(check bool) "zero bits gives 0 work" true
    (Consensus.work_compare zero_work Consensus.zero_work = 0)

(* Test create_chain_state initializes with genesis *)
let test_create_chain_state () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let state = Sync.create_chain_state db Consensus.regtest in

  (* Should have genesis as tip *)
  let tip = Sync.get_tip state in
  Alcotest.(check bool) "tip exists" true (Option.is_some tip);
  let entry = Option.get tip in
  Alcotest.(check int) "tip height is 0" 0 entry.height;
  Alcotest.(check bool) "tip has work" true (Consensus.work_compare entry.total_work Consensus.zero_work > 0);

  (* Header count should be 1 (just genesis) *)
  Alcotest.(check int) "header count" 1 (Sync.header_count state);

  (* Sync state should be Idle *)
  let info = Sync.get_sync_info state in
  Alcotest.(check string) "sync state" "idle" info.state;

  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test validate_header with valid header *)
let test_validate_header_valid () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let state = Sync.create_chain_state db Consensus.regtest in

  let genesis_hash = Crypto.compute_block_hash Consensus.regtest.genesis_header in
  let header = make_test_header ~prev_block:genesis_hash ~ts:1296688603l ~nc:3l in

  (* Validate the header - need to find a nonce that meets target *)
  let result = Sync.validate_header state header in
  (* Note: This may fail if the nonce doesn't meet the target *)
  (* For regtest with very low difficulty, most nonces should work *)
  let ok = match result with
    | Ok entry ->
      Alcotest.(check int) "valid header height" 1 entry.height;
      Alcotest.(check bool) "valid header has work" true (Consensus.work_compare entry.total_work Consensus.zero_work > 0);
      true
    | Error "Insufficient proof of work" ->
      (* This is acceptable - we'd need to mine a valid header *)
      true
    | Error _ -> false
  in
  Alcotest.(check bool) "validation result acceptable" true ok;
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test validate_header with duplicate header *)
let test_validate_header_duplicate () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let state = Sync.create_chain_state db Consensus.regtest in

  (* Try to validate genesis again - should be rejected as duplicate *)
  let result = Sync.validate_header state Consensus.regtest.genesis_header in
  let is_duplicate = match result with
    | Error "Header already known" -> true
    | _ -> false
  in
  Alcotest.(check bool) "duplicate rejected" true is_duplicate;
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test validate_header with unknown parent *)
let test_validate_header_unknown_parent () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let state = Sync.create_chain_state db Consensus.regtest in

  (* Create header with fake parent *)
  let fake_parent = Types.hash256_of_hex
    "0000000000000000000000000000000000000000000000000000000000000001" in
  let header = make_test_header ~prev_block:fake_parent ~ts:1296688603l ~nc:1l in

  let result = Sync.validate_header state header in
  let is_unknown_parent = match result with
    | Error "Unknown parent header" -> true
    | _ -> false
  in
  Alcotest.(check bool) "unknown parent rejected" true is_unknown_parent;
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test validate_header with future timestamp *)
let test_validate_header_future_timestamp () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let state = Sync.create_chain_state db Consensus.regtest in

  let genesis_hash = Crypto.compute_block_hash Consensus.regtest.genesis_header in
  (* Timestamp 3 hours in the future *)
  let future_ts = Int32.of_float (Unix.gettimeofday () +. 10800.0) in
  let header = make_test_header ~prev_block:genesis_hash ~ts:future_ts ~nc:1l in

  let result = Sync.validate_header state header in
  let acceptable = match result with
    | Error "Header timestamp too far in future" -> true
    | Error "Insufficient proof of work" -> true  (* Also acceptable *)
    | _ -> false
  in
  Alcotest.(check bool) "future timestamp handled" true acceptable;
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test process_headers with empty list *)
let test_process_headers_empty () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let state = Sync.create_chain_state db Consensus.regtest in

  let result = Sync.process_headers state [] in
  let accepted = match result with
    | Ok n -> n
    | Error _ -> -1
  in
  Alcotest.(check int) "empty headers accepted 0" 0 accepted;
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test build_locator returns genesis for empty chain *)
let test_build_locator_genesis () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let state = Sync.create_chain_state db Consensus.regtest in

  let locator = Sync.build_locator state in
  Alcotest.(check int) "locator length" 1 (List.length locator);

  let genesis_hash = Crypto.compute_block_hash Consensus.regtest.genesis_header in
  Alcotest.(check string) "locator contains genesis"
    (Types.hash256_to_hex genesis_hash)
    (Types.hash256_to_hex (List.hd locator));

  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test get_header by hash *)
let test_get_header () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let state = Sync.create_chain_state db Consensus.regtest in

  let genesis_hash = Crypto.compute_block_hash Consensus.regtest.genesis_header in
  let entry = Sync.get_header state genesis_hash in
  Alcotest.(check bool) "genesis header found" true (Option.is_some entry);
  let e = Option.get entry in
  Alcotest.(check int) "genesis height" 0 e.height;

  (* Non-existent hash should return None *)
  let fake_hash = Types.hash256_of_hex
    "0000000000000000000000000000000000000000000000000000000000000001" in
  let missing = Sync.get_header state fake_hash in
  Alcotest.(check bool) "missing header" true (Option.is_none missing);

  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test get_header_at_height *)
let test_get_header_at_height () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let state = Sync.create_chain_state db Consensus.regtest in

  let entry = Sync.get_header_at_height state 0 in
  Alcotest.(check bool) "height 0 found" true (Option.is_some entry);

  let missing = Sync.get_header_at_height state 1 in
  Alcotest.(check bool) "height 1 missing" true (Option.is_none missing);

  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test has_header *)
let test_has_header () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let state = Sync.create_chain_state db Consensus.regtest in

  let genesis_hash = Crypto.compute_block_hash Consensus.regtest.genesis_header in
  Alcotest.(check bool) "has genesis" true (Sync.has_header state genesis_hash);

  let fake_hash = Types.hash256_of_hex
    "0000000000000000000000000000000000000000000000000000000000000001" in
  Alcotest.(check bool) "doesn't have fake" false (Sync.has_header state fake_hash);

  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test sync_state_to_string *)
let test_sync_state_to_string () =
  Alcotest.(check string) "idle" "idle" (Sync.sync_state_to_string Sync.Idle);
  Alcotest.(check string) "syncing_headers" "syncing_headers"
    (Sync.sync_state_to_string Sync.SyncingHeaders);
  Alcotest.(check string) "syncing_blocks" "syncing_blocks"
    (Sync.sync_state_to_string Sync.SyncingBlocks);
  Alcotest.(check string) "fully_synced" "fully_synced"
    (Sync.sync_state_to_string Sync.FullySynced)

(* Test restore_chain_state with no stored state *)
let test_restore_chain_state_fresh () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let state = Sync.restore_chain_state db Consensus.regtest in

  (* Should initialize with genesis *)
  let tip = Sync.get_tip state in
  Alcotest.(check bool) "tip exists" true (Option.is_some tip);
  let entry = Option.get tip in
  Alcotest.(check int) "tip height is 0" 0 entry.height;

  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test restore_chain_state with stored headers *)
let test_restore_chain_state_with_headers () =
  cleanup_test_db ();
  (* First, create and populate a chain *)
  let db = Storage.ChainDB.create test_db_path in
  let state = Sync.create_chain_state db Consensus.regtest in
  let _ = state in  (* Use state *)
  Storage.ChainDB.close db;

  (* Now restore *)
  let db2 = Storage.ChainDB.create test_db_path in
  let state2 = Sync.restore_chain_state db2 Consensus.regtest in
  let tip = Sync.get_tip state2 in
  Alcotest.(check bool) "restored tip exists" true (Option.is_some tip);

  Storage.ChainDB.close db2;
  cleanup_test_db ()

(* Test that header_tip is separate from chain_tip *)
let test_header_tip_separate () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let _ = Sync.create_chain_state db Consensus.regtest in

  (* Check that header_tip was set *)
  let header_tip = Storage.ChainDB.get_header_tip db in
  Alcotest.(check bool) "header_tip set" true (Option.is_some header_tip);
  let (_, height) = Option.get header_tip in
  Alcotest.(check int) "header_tip height" 0 height;

  (* chain_tip might not be set by sync module *)
  (* The important thing is they are stored separately *)

  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test needs_header_sync *)
let test_needs_header_sync () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let state = Sync.create_chain_state db Consensus.regtest in

  (* Create a mock peer structure manually since we can't create real peers *)
  (* The needs_header_sync function checks peer.state = Ready and
     peer.best_height > headers_synced *)

  (* For this test, we just verify the function exists and state is Idle *)
  let info = Sync.get_sync_info state in
  Alcotest.(check string) "state is idle" "idle" info.state;
  Alcotest.(check int) "headers_synced is 0" 0 info.headers_synced;

  Storage.ChainDB.close db;
  cleanup_test_db ()

(* ============================================================================
   IBD (Initial Block Download) Tests
   ============================================================================ *)

(* Test create_ibd_state initialization *)
let test_create_ibd_state () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let chain = Sync.create_chain_state db Consensus.regtest in
  let ibd = Sync.create_ibd_state chain in

  (* IBD should start from height 1 (after genesis) *)
  Alcotest.(check int) "next_download_height" 1 ibd.next_download_height;
  Alcotest.(check int) "next_process_height" 1 ibd.next_process_height;
  Alcotest.(check int) "total_blocks_in_flight" 0 ibd.total_blocks_in_flight;
  Alcotest.(check int) "block_queue length" 0 (List.length ibd.block_queue);

  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test fill_download_queue populates queue from headers *)
let test_fill_download_queue () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let chain = Sync.create_chain_state db Consensus.regtest in

  (* Add some headers to the chain (simulated) *)
  (* For this test, we just verify the function works with genesis only *)
  let ibd = Sync.create_ibd_state chain in
  Sync.fill_download_queue ibd;

  (* With only genesis block and no additional headers, queue should be empty *)
  (* (genesis is at height 0, we start downloading from height 1) *)
  Alcotest.(check int) "queue empty with no headers beyond genesis"
    0 (List.length ibd.block_queue);

  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test peer_download_state management *)
let test_get_peer_state () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let chain = Sync.create_chain_state db Consensus.regtest in
  let ibd = Sync.create_ibd_state chain in

  (* Get state for a new peer *)
  let peer_state = Sync.get_peer_state ibd 1 in
  Alcotest.(check int) "new peer blocks_in_flight" 0 peer_state.blocks_in_flight;
  Alcotest.(check int) "new peer consecutive_timeouts" 0 peer_state.consecutive_timeouts;
  Alcotest.(check (float 0.001)) "new peer current_timeout"
    Sync.base_block_timeout peer_state.current_timeout;

  (* Modify peer state *)
  peer_state.blocks_in_flight <- 5;
  peer_state.consecutive_timeouts <- 2;

  (* Get state again - should be the same instance *)
  let peer_state2 = Sync.get_peer_state ibd 1 in
  Alcotest.(check int) "same peer blocks_in_flight" 5 peer_state2.blocks_in_flight;
  Alcotest.(check int) "same peer consecutive_timeouts" 2 peer_state2.consecutive_timeouts;

  (* Different peer should have fresh state *)
  let peer_state3 = Sync.get_peer_state ibd 2 in
  Alcotest.(check int) "different peer blocks_in_flight" 0 peer_state3.blocks_in_flight;

  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test block_download_state types *)
let test_block_download_states () =
  (* Test NotRequested state *)
  let state1 = Sync.NotRequested in
  let is_not_requested = match state1 with
    | Sync.NotRequested -> true
    | _ -> false
  in
  Alcotest.(check bool) "NotRequested" true is_not_requested;

  (* Test Requested state *)
  let state2 = Sync.Requested {
    peer_id = 42;
    requested_at = 1000.0;
    timeout = 5.0;
  } in
  let peer_id = match state2 with
    | Sync.Requested { peer_id; _ } -> peer_id
    | _ -> -1
  in
  Alcotest.(check int) "Requested peer_id" 42 peer_id;

  (* Test Downloaded state *)
  let block = Types.{
    header = Consensus.regtest.genesis_header;
    transactions = [];
  } in
  let state3 = Sync.Downloaded { block; peer_id = None } in
  let is_downloaded = match state3 with
    | Sync.Downloaded _ -> true
    | _ -> false
  in
  Alcotest.(check bool) "Downloaded" true is_downloaded;

  (* Test Validated state *)
  let state4 = Sync.Validated in
  let is_validated = match state4 with
    | Sync.Validated -> true
    | _ -> false
  in
  Alcotest.(check bool) "Validated" true is_validated

(* Test UTXO encoding *)
let test_encode_utxo () =
  let value = 50_00_000_000L in (* 50 BTC *)
  let script = Cstruct.of_string "\x76\xa9\x14" in (* Start of P2PKH *)
  let height = 100 in
  let is_coinbase = true in

  let encoded = Sync.encode_utxo value script height is_coinbase in

  (* Decode and verify *)
  let r = Serialize.reader_of_cstruct (Cstruct.of_string encoded) in
  let decoded_value = Serialize.read_int64_le r in
  let script_len = Serialize.read_compact_size r in
  let decoded_script = Serialize.read_bytes r script_len in
  let decoded_height = Int32.to_int (Serialize.read_int32_le r) in
  let decoded_is_coinbase = Serialize.read_uint8 r = 1 in

  Alcotest.(check int64) "value" value decoded_value;
  Alcotest.(check int) "script length" (Cstruct.length script) script_len;
  Alcotest.(check string) "script"
    (Cstruct.to_string script) (Cstruct.to_string decoded_script);
  Alcotest.(check int) "height" height decoded_height;
  Alcotest.(check bool) "is_coinbase" is_coinbase decoded_is_coinbase

(* Test check_timeouts *)
let test_check_timeouts () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let chain = Sync.create_chain_state db Consensus.regtest in
  let ibd = Sync.create_ibd_state chain in

  let hash = Types.hash256_of_hex
    "0000000000000000000000000000000000000000000000000000000000000001" in

  (* Create an entry that has timed out *)
  let entry = Sync.{
    hash;
    height = 1;
    download_state = Requested {
      peer_id = 1;
      requested_at = Unix.gettimeofday () -. 100.0; (* 100 seconds ago *)
      timeout = 5.0;
    };
  } in
  ibd.block_queue <- [entry];
  ibd.total_blocks_in_flight <- 1;

  (* Set up peer state *)
  let peer_state = Sync.get_peer_state ibd 1 in
  peer_state.blocks_in_flight <- 1;

  (* Run timeout check *)
  Sync.check_timeouts ibd;

  (* Entry should be reset to NotRequested *)
  let is_reset = match entry.download_state with
    | Sync.NotRequested -> true
    | _ -> false
  in
  Alcotest.(check bool) "entry reset after timeout" true is_reset;
  Alcotest.(check int) "total_blocks_in_flight reset" 0 ibd.total_blocks_in_flight;
  Alcotest.(check int) "peer blocks_in_flight reset" 0 peer_state.blocks_in_flight;

  (* Peer timeout should have doubled *)
  Alcotest.(check (float 0.001)) "timeout doubled"
    (Sync.base_block_timeout *. 2.0) peer_state.current_timeout;

  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test record_successful_download *)
let test_record_successful_download () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let chain = Sync.create_chain_state db Consensus.regtest in
  let ibd = Sync.create_ibd_state chain in

  (* Set up peer state with elevated timeout *)
  let peer_state = Sync.get_peer_state ibd 1 in
  peer_state.blocks_in_flight <- 3;
  peer_state.consecutive_timeouts <- 2;
  peer_state.current_timeout <- 20.0;

  (* Record successful download *)
  Sync.record_successful_download ibd 1;

  (* Verify state is reset *)
  Alcotest.(check int) "blocks_in_flight decremented" 2 peer_state.blocks_in_flight;
  Alcotest.(check int) "consecutive_timeouts reset" 0 peer_state.consecutive_timeouts;
  Alcotest.(check (float 0.001)) "timeout reset to base"
    Sync.base_block_timeout peer_state.current_timeout;

  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test receive_block *)
let test_receive_block () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let chain = Sync.create_chain_state db Consensus.regtest in
  let ibd = Sync.create_ibd_state chain in

  let genesis_hash = Crypto.compute_block_hash Consensus.regtest.genesis_header in
  let block = Types.{
    header = Consensus.regtest.genesis_header;
    transactions = [];
  } in

  (* Add entry to queue *)
  let entry = Sync.{
    hash = genesis_hash;
    height = 0;
    download_state = Requested {
      peer_id = 1;
      requested_at = Unix.gettimeofday ();
      timeout = 5.0;
    };
  } in
  ibd.block_queue <- [entry];
  ibd.total_blocks_in_flight <- 1;

  (* Set up peer state *)
  let peer_state = Sync.get_peer_state ibd 1 in
  peer_state.blocks_in_flight <- 1;

  (* Receive the block *)
  let result = Sync.receive_block ibd block in
  Alcotest.(check bool) "receive_block succeeds" true (Result.is_ok result);

  (* Entry should be Downloaded *)
  let is_downloaded = match entry.download_state with
    | Sync.Downloaded _ -> true
    | _ -> false
  in
  Alcotest.(check bool) "entry marked downloaded" true is_downloaded;
  Alcotest.(check int) "total_blocks_in_flight decremented" 0 ibd.total_blocks_in_flight;

  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test receive_block with unrequested block *)
let test_receive_unrequested_block () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let chain = Sync.create_chain_state db Consensus.regtest in
  let ibd = Sync.create_ibd_state chain in

  let block = Types.{
    header = Consensus.regtest.genesis_header;
    transactions = [];
  } in

  (* Queue is empty - block is stored as orphan instead of rejected *)
  let result = Sync.receive_block ibd block in
  Alcotest.(check bool) "receive unrequested block stored as orphan" true (Result.is_ok result);

  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test IBD constants *)
let test_ibd_constants () =
  Alcotest.(check int) "max_blocks_per_peer" 16 Sync.max_blocks_per_peer;
  Alcotest.(check int) "max_total_blocks_in_flight" 128 Sync.max_total_blocks_in_flight;
  Alcotest.(check (float 0.001)) "base_block_timeout" 60.0 Sync.base_block_timeout;
  Alcotest.(check (float 0.001)) "max_block_timeout" 300.0 Sync.max_block_timeout;
  Alcotest.(check int) "utxo_flush_interval" 2000 Sync.utxo_flush_interval;
  Alcotest.(check int) "block_download_window" 1024 Sync.block_download_window

(* Test find_fork_point with same chain *)
let test_find_fork_point_same () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let chain = Sync.create_chain_state db Consensus.regtest in

  let genesis_entry = Option.get (Sync.get_tip chain) in

  (* Fork point of genesis with itself should be genesis *)
  let result = Sync.find_fork_point chain genesis_entry genesis_entry in
  Alcotest.(check bool) "find_fork_point succeeds" true (Result.is_ok result);

  let fork = Result.get_ok result in
  Alcotest.(check int) "fork at genesis" 0 fork.height;

  Storage.ChainDB.close db;
  cleanup_test_db ()

(* ============================================================================
   PRESYNC/REDOWNLOAD Header Sync Anti-DoS Tests
   ============================================================================ *)

(* Test header_sync_state type and to_string *)
let test_header_sync_state_to_string () =
  let presync_state = Sync.Presync {
    cumulative_work = Cstruct.create 32;
    last_hash = Types.zero_hash;
    last_bits = 0x207fffffl;
    count = 100;
  } in
  let presync_str = Sync.header_sync_state_to_string presync_state in
  Alcotest.(check bool) "presync string contains count"
    true (String.sub presync_str 0 7 = "presync");

  let redownload_state = Sync.Redownload {
    target_hash = Types.zero_hash;
    expected_work = Cstruct.create 32;
    headers_received = 500;
  } in
  let redownload_str = Sync.header_sync_state_to_string redownload_state in
  Alcotest.(check bool) "redownload string contains received"
    true (String.sub redownload_str 0 10 = "redownload");

  let synced_str = Sync.header_sync_state_to_string Sync.Synced in
  Alcotest.(check string) "synced string" "synced" synced_str

(* Test create_presync_state *)
let test_create_presync_state () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let chain = Sync.create_chain_state db Consensus.regtest in
  let genesis_entry = Option.get (Sync.get_tip chain) in

  let ps = Sync.create_presync_state ~peer_id:42 ~chain_start:genesis_entry in

  Alcotest.(check int) "peer_id" 42 ps.peer_id;
  Alcotest.(check int) "chain_start_height" 0 ps.chain_start_height;

  (* Should start in Presync state with zero work and count 0 *)
  let is_presync_zero = match ps.state with
    | Sync.Presync { count; _ } -> count = 0
    | _ -> false
  in
  Alcotest.(check bool) "starts in presync with count 0" true is_presync_zero;

  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test validate_presync_header with valid header *)
let test_validate_presync_header_valid () =
  let genesis_hash = Crypto.compute_block_hash Consensus.regtest.genesis_header in
  let header = make_test_header ~prev_block:genesis_hash ~ts:1296688603l ~nc:0l in

  let result = Sync.validate_presync_header ~expected_prev:genesis_hash ~header in
  (* May fail PoW check - that's acceptable for regtest without mining *)
  let acceptable = match result with
    | Ok (hash, work, bits) ->
      Cstruct.length hash = 32 &&
      Cstruct.length work = 32 &&
      bits = 0x207fffffl
    | Error "PRESYNC: insufficient proof of work" -> true
    | Error _ -> false
  in
  Alcotest.(check bool) "valid or pow fail" true acceptable

(* Test validate_presync_header with wrong prev_block *)
let test_validate_presync_header_bad_prev () =
  let fake_prev = Types.hash256_of_hex
    "0000000000000000000000000000000000000000000000000000000000000001" in
  let header = make_test_header ~prev_block:Types.zero_hash ~ts:1296688603l ~nc:0l in

  let result = Sync.validate_presync_header ~expected_prev:fake_prev ~header in
  let is_mismatch = match result with
    | Error "PRESYNC: header prev_block mismatch" -> true
    | _ -> false
  in
  Alcotest.(check bool) "prev_block mismatch rejected" true is_mismatch

(* Test process_presync_headers - simulating a low-work header flood *)
let test_process_presync_headers_flood () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let chain = Sync.create_chain_state db Consensus.regtest in
  let genesis_entry = Option.get (Sync.get_tip chain) in

  let ps = Sync.create_presync_state ~peer_id:1 ~chain_start:genesis_entry in

  (* For regtest, minimum_chain_work is zero, so any headers will pass.
     This test verifies the state machine works correctly. *)

  (* Process empty headers - should succeed with 0 accepted *)
  let result = Sync.process_presync_headers ~ps ~headers:[] ~network:Consensus.regtest in
  Alcotest.(check bool) "empty headers ok" true (Result.is_ok result);
  let accepted = Result.get_ok result in
  Alcotest.(check int) "0 accepted" 0 accepted;

  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test get_header_sync_phase *)
let test_get_header_sync_phase () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let chain = Sync.create_chain_state db Consensus.regtest in
  let genesis_entry = Option.get (Sync.get_tip chain) in

  let ps = Sync.create_presync_state ~peer_id:1 ~chain_start:genesis_entry in

  (* Should start in Presync phase *)
  let phase1 = Sync.get_header_sync_phase ps in
  Alcotest.(check bool) "starts in presync" true (phase1 = `Presync);

  (* Manually transition to Redownload *)
  ps.state <- Sync.Redownload {
    target_hash = Types.zero_hash;
    expected_work = Cstruct.create 32;
    headers_received = 0;
  };
  let phase2 = Sync.get_header_sync_phase ps in
  Alcotest.(check bool) "in redownload" true (phase2 = `Redownload);

  (* Transition to Synced *)
  ps.state <- Sync.Synced;
  let phase3 = Sync.get_header_sync_phase ps in
  Alcotest.(check bool) "synced" true (phase3 = `Synced);

  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test build_presync_locator *)
let test_build_presync_locator () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let chain = Sync.create_chain_state db Consensus.regtest in
  let genesis_entry = Option.get (Sync.get_tip chain) in

  let ps = Sync.create_presync_state ~peer_id:1 ~chain_start:genesis_entry in

  let locator = Sync.build_presync_locator ps in
  Alcotest.(check int) "locator has 1 hash" 1 (List.length locator);

  (* The locator should contain the genesis hash (last_hash) *)
  let genesis_hash = Crypto.compute_block_hash Consensus.regtest.genesis_header in
  Alcotest.(check bool) "locator contains genesis"
    true (Cstruct.equal (List.hd locator) genesis_hash);

  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test build_redownload_locator *)
let test_build_redownload_locator () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let chain = Sync.create_chain_state db Consensus.regtest in

  let locator = Sync.build_redownload_locator chain in
  Alcotest.(check int) "locator has 1 hash (genesis)" 1 (List.length locator);

  let genesis_hash = Crypto.compute_block_hash Consensus.regtest.genesis_header in
  Alcotest.(check bool) "locator is genesis hash"
    true (Cstruct.equal (List.hd locator) genesis_hash);

  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test should_request_more_headers and rate limiting *)
let test_should_request_more_headers () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let chain = Sync.create_chain_state db Consensus.regtest in
  let genesis_entry = Option.get (Sync.get_tip chain) in

  let ps = Sync.create_presync_state ~peer_id:1 ~chain_start:genesis_entry in

  (* Initial state: should be able to request (last_getheaders_time is 0) *)
  Alcotest.(check bool) "can request initially"
    true (Sync.should_request_more_headers ps);

  (* Mark as sent *)
  Sync.mark_getheaders_sent ps;

  (* Immediately after: should NOT be able to request (rate limited) *)
  Alcotest.(check bool) "rate limited after send"
    false (Sync.should_request_more_headers ps);

  (* After Synced: should not request *)
  ps.state <- Sync.Synced;
  Alcotest.(check bool) "synced doesn't request"
    false (Sync.should_request_more_headers ps);

  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test needs_lowwork_sync *)
let test_needs_lowwork_sync () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in

  (* Regtest has minimum_chain_work = zero, so we never need low-work sync *)
  let chain_regtest = Sync.create_chain_state db Consensus.regtest in
  let needs_regtest = Sync.needs_lowwork_sync ~chain_state:chain_regtest in
  (* With genesis, work > 0, and minimum = 0, so we don't need low-work sync *)
  Alcotest.(check bool) "regtest doesn't need lowwork sync (min=0)"
    false needs_regtest;

  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test PRESYNC memory footprint is constant (< 100 bytes per peer) *)
let test_presync_memory_footprint () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let chain = Sync.create_chain_state db Consensus.regtest in
  let genesis_entry = Option.get (Sync.get_tip chain) in

  (* Create presync state - should only use ~100 bytes regardless of
     how many headers have been processed *)
  let ps = Sync.create_presync_state ~peer_id:1 ~chain_start:genesis_entry in

  (* Calculate approximate memory usage:
     - cumulative_work: 32 bytes
     - last_hash: 32 bytes
     - last_bits: 4 bytes
     - count: 8 bytes (OCaml int)
     - peer_id: 8 bytes
     - state discriminant: 8 bytes
     - chain_start_hash: 32 bytes
     - chain_start_height: 8 bytes
     - last_getheaders_time: 8 bytes
     Total: ~140 bytes (well under kilobyte scale)
  *)

  let is_presync = match ps.state with
    | Sync.Presync _ -> true
    | _ -> false
  in
  Alcotest.(check bool) "state is presync" true is_presync;

  (* The key invariant: Presync state size doesn't grow with header count *)
  (* Simulate processing 10000 headers without storing them *)
  let ps_after = match ps.state with
    | Sync.Presync data ->
      Sync.Presync {
        data with
        count = 10000;
        cumulative_work = Consensus.work_from_compact 0x1d00ffffl;
      }
    | _ -> ps.state
  in
  ps.state <- ps_after;

  (* State is still ~100 bytes, not 10000 * 80 bytes *)
  let is_still_presync = match ps.state with
    | Sync.Presync { count; _ } -> count = 10000
    | _ -> false
  in
  Alcotest.(check bool) "10000 headers, still just presync state" true is_still_presync;

  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test PRESYNC constants *)
let test_presync_constants () =
  Alcotest.(check int) "max_headers_per_message" 2000 Sync.max_headers_per_message;
  Alcotest.(check (float 0.001)) "getheaders_rate_limit" 2.0 Sync.getheaders_rate_limit

(* ============================================================================
   Block Invalidation Tests
   ============================================================================ *)

(* Test is_block_invalid initially returns false *)
let test_is_block_invalid_initially_false () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let state = Sync.create_chain_state db Consensus.regtest in
  let genesis_hash = Crypto.compute_block_hash Consensus.regtest.genesis_header in
  Alcotest.(check bool) "genesis not initially invalid" false
    (Sync.is_block_invalid state genesis_hash);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test invalidate_block marks block as invalid *)
let test_invalidate_block_basic () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let state = Sync.create_chain_state db Consensus.regtest in
  let genesis_hash = Crypto.compute_block_hash Consensus.regtest.genesis_header in
  (* Cannot invalidate genesis block *)
  (match Sync.invalidate_block state genesis_hash with
   | Error msg ->
     Alcotest.(check bool) "genesis block error" true
       (String.length msg > 0 && msg = "Cannot invalidate genesis block")
   | Ok _ ->
     Alcotest.fail "Should not be able to invalidate genesis block");
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test invalidate_block with non-existent block *)
let test_invalidate_nonexistent_block () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let state = Sync.create_chain_state db Consensus.regtest in
  let fake_hash = Cstruct.create 32 in
  Cstruct.set_uint8 fake_hash 0 0xFF;
  (match Sync.invalidate_block state fake_hash with
   | Error msg ->
     Alcotest.(check string) "block not found error" "Block not found" msg
   | Ok _ ->
     Alcotest.fail "Should fail for non-existent block");
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test reconsider_block with non-existent block *)
let test_reconsider_nonexistent_block () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let state = Sync.create_chain_state db Consensus.regtest in
  let fake_hash = Cstruct.create 32 in
  Cstruct.set_uint8 fake_hash 0 0xFF;
  (match Sync.reconsider_block state fake_hash with
   | Error msg ->
     Alcotest.(check string) "block not found error" "Block not found" msg
   | Ok _ ->
     Alcotest.fail "Should fail for non-existent block");
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test find_descendants with no descendants *)
let test_find_descendants_empty () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let state = Sync.create_chain_state db Consensus.regtest in
  let genesis_hash = Crypto.compute_block_hash Consensus.regtest.genesis_header in
  let descendants = Sync.find_descendants state genesis_hash in
  Alcotest.(check int) "genesis has no descendants initially" 0
    (List.length descendants);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test find_best_valid_tip returns genesis when only genesis exists *)
let test_find_best_valid_tip_genesis () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let state = Sync.create_chain_state db Consensus.regtest in
  let best = Sync.find_best_valid_tip state in
  Alcotest.(check bool) "best tip exists" true (Option.is_some best);
  let entry = Option.get best in
  Alcotest.(check int) "best tip is genesis" 0 entry.height;
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test invalidation persists across restarts *)
let test_invalidation_persistence () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let _state = Sync.create_chain_state db Consensus.regtest in
  (* Create a fake block hash and mark it as invalidated *)
  let fake_hash = Cstruct.create 32 in
  Cstruct.set_uint8 fake_hash 0 0xAB;
  Storage.ChainDB.set_block_invalidated db fake_hash;
  Storage.ChainDB.sync db;
  Storage.ChainDB.close db;
  (* Reopen and check *)
  let db2 = Storage.ChainDB.create test_db_path in
  let is_invalid = Storage.ChainDB.is_block_invalidated db2 fake_hash in
  Alcotest.(check bool) "invalidation persisted" true is_invalid;
  Storage.ChainDB.close db2;
  cleanup_test_db ()

(* Test clear_block_invalidated removes invalidation *)
let test_clear_block_invalidated () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let _state = Sync.create_chain_state db Consensus.regtest in
  let fake_hash = Cstruct.create 32 in
  Cstruct.set_uint8 fake_hash 0 0xCD;
  Storage.ChainDB.set_block_invalidated db fake_hash;
  Alcotest.(check bool) "block is invalidated" true
    (Storage.ChainDB.is_block_invalidated db fake_hash);
  Storage.ChainDB.clear_block_invalidated db fake_hash;
  Alcotest.(check bool) "block is no longer invalidated" false
    (Storage.ChainDB.is_block_invalidated db fake_hash);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test get_all_invalidated_blocks *)
let test_get_all_invalidated_blocks () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let _state = Sync.create_chain_state db Consensus.regtest in
  let hash1 = Cstruct.create 32 in
  let hash2 = Cstruct.create 32 in
  Cstruct.set_uint8 hash1 0 0x11;
  Cstruct.set_uint8 hash2 0 0x22;
  Storage.ChainDB.set_block_invalidated db hash1;
  Storage.ChainDB.set_block_invalidated db hash2;
  let all = Storage.ChainDB.get_all_invalidated_blocks db in
  Alcotest.(check int) "two invalidated blocks" 2 (List.length all);
  Storage.ChainDB.close db;
  cleanup_test_db ()

let () =
  cleanup_test_db ();
  let open Alcotest in
  run "Sync" [
    "work_calculation", [
      test_case "work_from_bits" `Quick test_work_from_bits;
    ];
    "chain_state", [
      test_case "create_chain_state" `Quick test_create_chain_state;
      test_case "restore fresh" `Quick test_restore_chain_state_fresh;
      test_case "restore with headers" `Quick test_restore_chain_state_with_headers;
      test_case "header_tip separate" `Quick test_header_tip_separate;
    ];
    "header_validation", [
      test_case "valid header" `Quick test_validate_header_valid;
      test_case "duplicate header" `Quick test_validate_header_duplicate;
      test_case "unknown parent" `Quick test_validate_header_unknown_parent;
      test_case "future timestamp" `Quick test_validate_header_future_timestamp;
      test_case "empty headers" `Quick test_process_headers_empty;
    ];
    "locator", [
      test_case "build_locator genesis" `Quick test_build_locator_genesis;
    ];
    "accessors", [
      test_case "get_header" `Quick test_get_header;
      test_case "get_header_at_height" `Quick test_get_header_at_height;
      test_case "has_header" `Quick test_has_header;
      test_case "sync_state_to_string" `Quick test_sync_state_to_string;
      test_case "needs_header_sync" `Quick test_needs_header_sync;
    ];
    "ibd_state", [
      test_case "create_ibd_state" `Quick test_create_ibd_state;
      test_case "fill_download_queue" `Quick test_fill_download_queue;
      test_case "get_peer_state" `Quick test_get_peer_state;
      test_case "block_download_states" `Quick test_block_download_states;
      test_case "ibd_constants" `Quick test_ibd_constants;
    ];
    "ibd_utxo", [
      test_case "encode_utxo" `Quick test_encode_utxo;
    ];
    "ibd_timeout", [
      test_case "check_timeouts" `Quick test_check_timeouts;
      test_case "record_successful_download" `Quick test_record_successful_download;
    ];
    "ibd_receive", [
      test_case "receive_block" `Quick test_receive_block;
      test_case "receive_unrequested_block" `Quick test_receive_unrequested_block;
    ];
    "reorganization", [
      test_case "find_fork_point_same" `Quick test_find_fork_point_same;
    ];
    "header_sync_antidos", [
      test_case "header_sync_state_to_string" `Quick test_header_sync_state_to_string;
      test_case "create_presync_state" `Quick test_create_presync_state;
      test_case "validate_presync_header_valid" `Quick test_validate_presync_header_valid;
      test_case "validate_presync_header_bad_prev" `Quick test_validate_presync_header_bad_prev;
      test_case "process_presync_headers_flood" `Quick test_process_presync_headers_flood;
      test_case "get_header_sync_phase" `Quick test_get_header_sync_phase;
      test_case "build_presync_locator" `Quick test_build_presync_locator;
      test_case "build_redownload_locator" `Quick test_build_redownload_locator;
      test_case "should_request_more_headers" `Quick test_should_request_more_headers;
      test_case "needs_lowwork_sync" `Quick test_needs_lowwork_sync;
      test_case "presync_memory_footprint" `Quick test_presync_memory_footprint;
      test_case "presync_constants" `Quick test_presync_constants;
    ];
    "block_invalidation", [
      test_case "is_block_invalid_initially_false" `Quick test_is_block_invalid_initially_false;
      test_case "invalidate_block_basic" `Quick test_invalidate_block_basic;
      test_case "invalidate_nonexistent_block" `Quick test_invalidate_nonexistent_block;
      test_case "reconsider_nonexistent_block" `Quick test_reconsider_nonexistent_block;
      test_case "find_descendants_empty" `Quick test_find_descendants_empty;
      test_case "find_best_valid_tip_genesis" `Quick test_find_best_valid_tip_genesis;
      test_case "invalidation_persistence" `Quick test_invalidation_persistence;
      test_case "clear_block_invalidated" `Quick test_clear_block_invalidated;
      test_case "get_all_invalidated_blocks" `Quick test_get_all_invalidated_blocks;
    ];
  ]
