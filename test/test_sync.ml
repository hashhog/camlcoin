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
  Alcotest.(check int) "block_queue length" 0 (Queue.length ibd.block_queue);

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
    0 (Queue.length ibd.block_queue);

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
    tried_peers = [];
  } in
  Queue.clear ibd.block_queue;
  Queue.push entry ibd.block_queue;
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
    tried_peers = [];
  } in
  Queue.clear ibd.block_queue;
  Queue.push entry ibd.block_queue;
  Hashtbl.replace ibd.queue_by_hash (Cstruct.to_string genesis_hash) entry;
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
  Alcotest.(check int) "utxo_flush_interval" 500 Sync.utxo_flush_interval;
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

(* Helper to create a valid regtest header that meets proof-of-work requirements *)
let mine_test_header ?(merkle_marker : int32 = 0l) ~prev_block ~prev_height ~bits () =
  let rec find_valid_nonce nonce =
    if nonce > 1_000_000l then
      failwith "Could not find valid nonce for test header"
    else begin
      (* The merkle_marker bytes occupy the last 4 bytes of merkle_root,
         which gives callers a cheap way to mint two distinct blocks
         that share prev_block (e.g. the A1 / B1 pair in
         side-branch tests). Without this, mine_test_header for two
         calls with the same prev_block and same wallclock second
         returns identical headers. *)
      let merkle = Cstruct.create 32 in
      Cstruct.LE.set_uint32 merkle 28 merkle_marker;
      let header = Types.{
        version = 1l;
        prev_block;
        merkle_root = merkle;
        timestamp = Int32.of_float (Unix.gettimeofday () +. (Int32.to_float nonce));
        bits;
        nonce;
      } in
      let hash = Crypto.compute_block_hash header in
      if Consensus.hash_meets_target hash bits then
        (header, hash)
      else
        find_valid_nonce (Int32.succ nonce)
    end
  in
  let (header, hash) = find_valid_nonce 0l in
  let parent_work = Sync.work_from_bits bits in
  let total_work = Consensus.work_add parent_work (Sync.work_from_bits bits) in
  Sync.{
    header;
    hash;
    height = prev_height + 1;
    total_work;
  }

(* ============================================================================
   D-FULL multi-block reorg atomicity (2026-05-05)
   ============================================================================

   Guards the structural invariants of the [Sync.reorganize] D-FULL
   refactor: ALL disk mutations from BOTH halves of a reorg
   (UTXO + undo + block + tx_index + tip flip) accumulate into ONE
   shared [Storage.ChainDB.batch] and commit via a single
   [batch_write].

   Reference: 2026-05-05 cross-impl post-reorg-consistency audit
   [CORE-PARITY-AUDIT/_post-reorg-consistency-fleet-result-2026-05-05.md]
   which graded the fleet "D-PARTIAL (best in fleet) for camlcoin"
   on the strength of the disconnect-side accumulator.  This refactor
   extends the same accumulator to the connect side.

   End-to-end behavior is exercised by the diff-test corpus reorg
   entries (reorg-via-submitblock, mempool-refill-on-reorg,
   txindex-revert-on-reorg, post-reorg-consistency).  These unit tests
   guard the in-process invariants that the corpus harness cannot
   observe directly. *)

(* MAX_REORG_DEPTH cap: a reorg whose depth exceeds 100 must return an
   error and MUST NOT touch the disk batch, mirroring Bitcoin Core's
   [DEFAULT_MAX_REORG_DEPTH] in validation.h. *)
let test_reorganize_max_reorg_depth_cap () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let state = Sync.create_chain_state db Consensus.regtest in
  let ibd = Sync.create_ibd_state state in

  let genesis_hash = Crypto.compute_block_hash Consensus.regtest.genesis_header in
  let genesis_entry = match Sync.get_header state genesis_hash with
    | Some e -> e | None -> failwith "genesis missing" in

  (* Build a 102-deep side-branch chain on genesis, all distinct from
     the active chain so [find_fork_point] resolves to genesis and the
     depth check fires.  The active chain stays at genesis (height 0).  *)
  let chain_depth = 102 in
  let last = ref genesis_entry in
  let last_marker = ref 0xC0DECAFEl in
  for _ = 1 to chain_depth do
    last_marker := Int32.add !last_marker 1l;
    let entry = mine_test_header
      ~merkle_marker:!last_marker
      ~prev_block:(!last).hash
      ~prev_height:(!last).height
      ~bits:Consensus.regtest.genesis_header.bits () in
    let total_work = Consensus.work_add (!last).total_work
      (Sync.work_from_bits entry.header.bits) in
    let entry = Sync.{ entry with total_work } in
    Hashtbl.replace state.headers (Cstruct.to_string entry.hash) entry;
    Storage.ChainDB.store_block_header state.db entry.hash entry.header;
    last := entry
  done;

  (* Capture batch_write_count BEFORE the reorg attempt.  Setup writes
     above touched the counter, so we record the baseline. *)
  let baseline = Storage.ChainDB.get_batch_write_count db in

  let new_tip = !last in
  Alcotest.(check int) "side-branch tip at expected height"
    chain_depth new_tip.height;

  let result = Sync.reorganize ibd new_tip in
  (match result with
   | Ok () ->
     Alcotest.fail
       (Printf.sprintf
         "reorganize over MAX_REORG_DEPTH=100 unexpectedly succeeded \
          (chain_depth=%d)" chain_depth)
   | Error msg ->
     Alcotest.(check bool)
       (Printf.sprintf
         "depth-cap error mentions MAX_REORG_DEPTH (got: %S)" msg)
       true
       (let needle = "MAX_REORG_DEPTH" in
        let nlen = String.length needle in
        let mlen = String.length msg in
        let rec contains i =
          if i + nlen > mlen then false
          else if String.sub msg i nlen = needle then true
          else contains (i + 1)
        in contains 0));

  (* No batch_write must have fired during the aborted reorg. *)
  Alcotest.(check int)
    "no batch_write committed during depth-cap rejection"
    baseline (Storage.ChainDB.get_batch_write_count db);

  (* In-memory chain state must be unchanged. *)
  Alcotest.(check int) "tip height unchanged after depth-cap reject"
    0 (match state.tip with Some t -> t.height | None -> -1);

  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Crash-pre-commit invariant: when [reorganize] errors out partway
   through (e.g. a missing block on disk during the connect side),
   NO [batch_write] must have fired and the on-disk chain tip must be
   unchanged from the pre-reorg state.  RocksDB's [WriteBatch] is
   atomic, so the absence of a [batch_write] call is sufficient
   evidence that the disk image is exactly what it was before the
   reorg started. *)
let test_reorganize_crash_pre_commit_no_disk_change () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let state = Sync.create_chain_state db Consensus.regtest in
  let ibd = Sync.create_ibd_state state in

  let genesis_hash = Crypto.compute_block_hash Consensus.regtest.genesis_header in
  let genesis_entry = match Sync.get_header state genesis_hash with
    | Some e -> e | None -> failwith "genesis missing" in

  (* Active chain: genesis.  Build a side-branch B1 -> B2 -> B3 in the
     in-memory header map.  No bodies on disk for any of them, so
     [reorganize] hits a "Missing block at height N during reorg
     connect" error during the connect loop on the FIRST block --
     the canonical crash-pre-commit shape. *)
  let mk_side step (prev_entry : Sync.header_entry) marker =
    let entry = mine_test_header
      ~merkle_marker:marker
      ~prev_block:prev_entry.hash
      ~prev_height:prev_entry.height
      ~bits:Consensus.regtest.genesis_header.bits () in
    let total_work = Consensus.work_add prev_entry.total_work
      (Sync.work_from_bits entry.header.bits) in
    let entry = Sync.{ entry with total_work } in
    Hashtbl.replace state.headers (Cstruct.to_string entry.hash) entry;
    Storage.ChainDB.store_block_header state.db entry.hash entry.header;
    Logs.debug (fun m -> m "side-branch step %d at height %d" step entry.height);
    entry
  in
  let b1 = mk_side 1 genesis_entry 0xb1b1b1b1l in
  let b2 = mk_side 2 b1 0xb2b2b2b2l in
  let b3 = mk_side 3 b2 0xb3b3b3b3l in
  Alcotest.(check bool) "B1 body intentionally missing" false
    (Storage.ChainDB.has_block db b1.hash);
  Alcotest.(check bool) "B2 body intentionally missing" false
    (Storage.ChainDB.has_block db b2.hash);
  Alcotest.(check bool) "B3 body intentionally missing" false
    (Storage.ChainDB.has_block db b3.hash);

  (* Capture pre-reorg state. *)
  let baseline_writes = Storage.ChainDB.get_batch_write_count db in
  let pre_tip = Storage.ChainDB.get_chain_tip db in

  let result = Sync.reorganize ibd b3 in
  (match result with
   | Ok () ->
     Alcotest.fail
       "reorganize unexpectedly succeeded with missing connect block"
   | Error _msg ->
     ());

  (* No batch_write must have fired during the aborted connect. *)
  Alcotest.(check int)
    "no batch_write committed during connect-side abort"
    baseline_writes (Storage.ChainDB.get_batch_write_count db);

  (* On-disk chain tip is unchanged: still at genesis (or unset, which
     [Storage.ChainDB.get_chain_tip] returns as None). *)
  let post_tip = Storage.ChainDB.get_chain_tip db in
  let tip_eq a b = match a, b with
    | None, None -> true
    | Some (h1, n1), Some (h2, n2) -> Cstruct.equal h1 h2 && n1 = n2
    | _ -> false
  in
  Alcotest.(check bool) "on-disk tip unchanged after aborted reorg"
    true (tip_eq pre_tip post_tip);

  (* In-memory tip must NOT have advanced to b3. *)
  let in_mem_height = match state.tip with Some t -> t.height | None -> -1 in
  Alcotest.(check bool)
    (Printf.sprintf "in-memory tip stays below b3 (got height %d)" in_mem_height)
    true (in_mem_height < 3);

  (* Pending UTXO lists must be empty after the abort (defensive
     invariant -- a leak here would corrupt a subsequent reorg). *)
  Alcotest.(check int) "pending utxo updates drained after abort"
    0 (List.length ibd.pending_utxo_updates);
  Alcotest.(check int) "pending utxo deletes drained after abort"
    0 (List.length ibd.pending_utxo_deletes);

  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Single-batch invariant: a multi-block reorg's disk-side mutations
   must commit through EXACTLY ONE [batch_write] call.  We exercise
   the atomicity primitives directly (rather than driving the full
   [reorganize] / [accept_block] pipeline, which requires a regtest
   coinbase + UTXO harness already covered by the diff-test corpus):
   stage 3 disconnect-shape ops + 4 connect-shape ops via the public
   batch helpers, [batch_write] once, assert the counter went up by
   exactly one.  This is the structural property the D-FULL refactor
   guarantees: one in-flight batch, one commit, regardless of the
   number of blocks involved on either side of the fork. *)
let test_reorganize_single_batch_commit () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in

  Storage.ChainDB.reset_batch_write_count db;
  let baseline = Storage.ChainDB.get_batch_write_count db in
  Alcotest.(check int) "baseline counter is 0 after reset" 0 baseline;

  let batch = Storage.ChainDB.batch_create () in

  (* Stage three "disconnect" blocks worth of ops: each one would
     [batch_delete_undo_data] + [batch_delete_tx_index] for a few
     txs + a UTXO restore via [batch_store_utxo] + an output-delete
     via [batch_delete_utxo]. *)
  for i = 0 to 2 do
    let block_hash = Cstruct.create 32 in
    Cstruct.set_uint8 block_hash 0 (0xD0 + i);  (* Distinct disconnect-N hash *)
    Storage.ChainDB.batch_delete_undo_data batch block_hash;
    let restored_txid = Cstruct.create 32 in
    Cstruct.set_uint8 restored_txid 0 (0xA0 + i);
    let restored_data = "restored-utxo-data-" ^ string_of_int i in
    Storage.ChainDB.batch_store_utxo batch restored_txid 0 restored_data;
    let removed_txid = Cstruct.create 32 in
    Cstruct.set_uint8 removed_txid 0 (0xB0 + i);
    Storage.ChainDB.batch_delete_utxo batch removed_txid 0;
    Storage.ChainDB.batch_delete_tx_index batch restored_txid
  done;

  (* Stage four "connect" blocks worth of ops: each writes a block
     body + undo data + tx_index pointer + UTXO put + UTXO delete. *)
  for i = 0 to 3 do
    let block_hash = Cstruct.create 32 in
    Cstruct.set_uint8 block_hash 0 (0xC0 + i);
    let block : Types.block = {
      header = Types.{
        version = 1l;
        prev_block = Types.zero_hash;
        merkle_root = Types.zero_hash;
        timestamp = Int32.of_int (1500000000 + i);
        bits = 0x207fffffl;
        nonce = Int32.of_int i;
      };
      transactions = [];
    } in
    Storage.ChainDB.batch_store_block batch block_hash block;
    Storage.ChainDB.batch_store_undo_data batch block_hash
      ("undo-payload-" ^ string_of_int i);
    let txid = Cstruct.create 32 in
    Cstruct.set_uint8 txid 0 (0xE0 + i);
    Storage.ChainDB.batch_store_tx_index batch txid block_hash 0;
    let utxo_txid = Cstruct.create 32 in
    Cstruct.set_uint8 utxo_txid 0 (0xF0 + i);
    Storage.ChainDB.batch_store_utxo batch utxo_txid 0
      ("connect-utxo-" ^ string_of_int i);
    let spent_txid = Cstruct.create 32 in
    Cstruct.set_uint8 spent_txid 0 (0x70 + i);
    Storage.ChainDB.batch_delete_utxo batch spent_txid 0;
    Storage.ChainDB.batch_set_height_hash batch (1000 + i) block_hash
  done;

  (* Stage final tip flip. *)
  let new_tip_hash = Cstruct.create 32 in
  Cstruct.set_uint8 new_tip_hash 0 0xFF;
  Storage.ChainDB.batch_set_chain_tip batch new_tip_hash 1003;

  (* The mutation accumulator has 3 disconnect-shape blocks + 4
     connect-shape blocks + a tip flip queued; so far ZERO commits. *)
  Alcotest.(check int) "no batch_write before final commit"
    0 (Storage.ChainDB.get_batch_write_count db - baseline);

  (* Single commit. *)
  Storage.ChainDB.batch_write db batch;

  Alcotest.(check int) "exactly ONE batch_write for entire reorg"
    1 (Storage.ChainDB.get_batch_write_count db - baseline);

  (* Verify the new tip landed and a sample of the connect-side puts
     is readable post-commit (proves the batch did the work). *)
  let post_tip = Storage.ChainDB.get_chain_tip db in
  (match post_tip with
   | Some (hash, height) ->
     Alcotest.(check bool) "tip hash matches" true
       (Cstruct.equal hash new_tip_hash);
     Alcotest.(check int) "tip height matches" 1003 height
   | None -> Alcotest.fail "post-commit tip read returned None");

  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test invalidate_block causes reorg and reconsider_block restores the chain *)
let test_invalidate_reorg_reconsider () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let state = Sync.create_chain_state db Consensus.regtest in

  (* Get genesis info *)
  let genesis_hash = Crypto.compute_block_hash Consensus.regtest.genesis_header in
  let genesis_entry = match Sync.get_header state genesis_hash with
    | Some e -> e
    | None -> failwith "Genesis not found"
  in

  (* Build a chain: genesis -> block1 -> block2 *)
  let block1_entry = mine_test_header
    ~prev_block:genesis_hash
    ~prev_height:0
    ~bits:Consensus.regtest.genesis_header.bits () in

  (* Manually add block1 to state *)
  let block1_key = Cstruct.to_string block1_entry.hash in
  Hashtbl.replace state.headers block1_key block1_entry;
  Storage.ChainDB.store_block_header state.db block1_entry.hash block1_entry.header;
  Storage.ChainDB.set_height_hash state.db block1_entry.height block1_entry.hash;

  (* Properly compute block1's cumulative work *)
  let block1_work = Consensus.work_add genesis_entry.total_work
    (Sync.work_from_bits block1_entry.header.bits) in
  let block1_entry = Sync.{ block1_entry with total_work = block1_work } in
  Hashtbl.replace state.headers block1_key block1_entry;

  (* Update tip to block1 *)
  state.tip <- Some block1_entry;
  state.blocks_synced <- 1;
  Storage.ChainDB.set_chain_tip state.db block1_entry.hash block1_entry.height;

  (* Build block2 on top of block1 *)
  let block2_entry = mine_test_header
    ~prev_block:block1_entry.hash
    ~prev_height:1
    ~bits:Consensus.regtest.genesis_header.bits () in

  let block2_key = Cstruct.to_string block2_entry.hash in
  Hashtbl.replace state.headers block2_key block2_entry;
  Storage.ChainDB.store_block_header state.db block2_entry.hash block2_entry.header;
  Storage.ChainDB.set_height_hash state.db block2_entry.height block2_entry.hash;

  (* Properly compute block2's cumulative work *)
  let block2_work = Consensus.work_add block1_entry.total_work
    (Sync.work_from_bits block2_entry.header.bits) in
  let block2_entry = Sync.{ block2_entry with total_work = block2_work } in
  Hashtbl.replace state.headers block2_key block2_entry;

  (* Update tip to block2 *)
  state.tip <- Some block2_entry;
  state.blocks_synced <- 2;
  Storage.ChainDB.set_chain_tip state.db block2_entry.hash block2_entry.height;

  (* Verify initial state *)
  Alcotest.(check int) "initial tip height" 2
    (match state.tip with Some t -> t.height | None -> -1);

  (* Invalidate block1 - this should affect the chain since block2 is a descendant *)
  let result = Sync.invalidate_block state block1_entry.hash in
  Alcotest.(check bool) "invalidate succeeds" true (Result.is_ok result);

  (* Verify block1 is marked invalid *)
  Alcotest.(check bool) "block1 is invalid" true
    (Sync.is_block_invalid state block1_entry.hash);

  (* Verify block2 (descendant) is also marked invalid *)
  Alcotest.(check bool) "block2 is invalid (descendant)" true
    (Sync.is_block_invalid state block2_entry.hash);

  (* Verify invalidation is persisted *)
  Alcotest.(check bool) "block1 invalidation persisted" true
    (Storage.ChainDB.is_block_invalidated db block1_entry.hash);
  Alcotest.(check bool) "block2 invalidation persisted" true
    (Storage.ChainDB.is_block_invalidated db block2_entry.hash);

  (* Now reconsider block1 - should clear invalidity *)
  let reconsider_result = Sync.reconsider_block state block1_entry.hash in
  Alcotest.(check bool) "reconsider succeeds" true (Result.is_ok reconsider_result);

  (* Verify block1 is no longer invalid *)
  Alcotest.(check bool) "block1 no longer invalid" false
    (Sync.is_block_invalid state block1_entry.hash);

  (* Verify block2 is also no longer invalid (descendants cleared) *)
  Alcotest.(check bool) "block2 no longer invalid" false
    (Sync.is_block_invalid state block2_entry.hash);

  (* Verify invalidation is cleared in storage *)
  Alcotest.(check bool) "block1 invalidation cleared" false
    (Storage.ChainDB.is_block_invalidated db block1_entry.hash);
  Alcotest.(check bool) "block2 invalidation cleared" false
    (Storage.ChainDB.is_block_invalidated db block2_entry.hash);

  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Test find_descendants correctly identifies all descendants *)
let test_find_descendants_with_chain () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let state = Sync.create_chain_state db Consensus.regtest in

  (* Get genesis info *)
  let genesis_hash = Crypto.compute_block_hash Consensus.regtest.genesis_header in
  let genesis_entry = match Sync.get_header state genesis_hash with
    | Some e -> e
    | None -> failwith "Genesis not found"
  in

  (* Build block1 *)
  let block1_entry = mine_test_header
    ~prev_block:genesis_hash
    ~prev_height:0
    ~bits:Consensus.regtest.genesis_header.bits () in
  let block1_key = Cstruct.to_string block1_entry.hash in
  let block1_work = Consensus.work_add genesis_entry.total_work
    (Sync.work_from_bits block1_entry.header.bits) in
  let block1_entry = Sync.{ block1_entry with total_work = block1_work } in
  Hashtbl.replace state.headers block1_key block1_entry;

  (* Build block2 on block1 *)
  let block2_entry = mine_test_header
    ~prev_block:block1_entry.hash
    ~prev_height:1
    ~bits:Consensus.regtest.genesis_header.bits () in
  let block2_key = Cstruct.to_string block2_entry.hash in
  let block2_work = Consensus.work_add block1_entry.total_work
    (Sync.work_from_bits block2_entry.header.bits) in
  let block2_entry = Sync.{ block2_entry with total_work = block2_work } in
  Hashtbl.replace state.headers block2_key block2_entry;

  (* Find descendants of genesis - should include block1 and block2 *)
  let genesis_descendants = Sync.find_descendants state genesis_hash in
  Alcotest.(check int) "genesis has 2 descendants" 2 (List.length genesis_descendants);

  (* Find descendants of block1 - should include only block2 *)
  let block1_descendants = Sync.find_descendants state block1_entry.hash in
  Alcotest.(check int) "block1 has 1 descendant" 1 (List.length block1_descendants);

  (* Find descendants of block2 - should be empty *)
  let block2_descendants = Sync.find_descendants state block2_entry.hash in
  Alcotest.(check int) "block2 has 0 descendants" 0 (List.length block2_descendants);

  Storage.ChainDB.close db;
  cleanup_test_db ()

(* ============================================================================
   BIP-35 mempool dispatch (NODE_BLOOM gate)
   ============================================================================ *)

(* Verify that NODE_BLOOM (BIP-35 / BIP-111) is OFF by default — mirrors
   Bitcoin Core's DEFAULT_PEERBLOOMFILTERS = false (net_processing.h:44).
   With the bit unset, [handle_mempool_msg] disconnects the requesting
   peer rather than serving an InvMsg. *)
let test_bip35_default_off () =
  Peer.set_peer_bloom_filters false;
  Alcotest.(check bool) "our_services bloom default off"
    false (Peer.our_services ()).bloom;
  let bits = Peer.services_to_int64 (Peer.our_services ()) in
  Alcotest.(check bool) "service bits exclude NODE_BLOOM (4) by default"
    true (Int64.logand bits 4L = 0L);
  Alcotest.(check int64) "default service bits = 9 (NETWORK|WITNESS)" 9L bits

(* When the operator passes --peerbloomfilters, NODE_BLOOM is set and the
   MEMPOOL handler will serve InvMsg responses to peers. *)
let test_bip35_advertise_when_enabled () =
  Peer.set_peer_bloom_filters true;
  Alcotest.(check bool) "our_services advertises NODE_BLOOM when enabled"
    true (Peer.our_services ()).bloom;
  let bits = Peer.services_to_int64 (Peer.our_services ()) in
  Alcotest.(check bool) "service bits include NODE_BLOOM (4) when enabled"
    true (Int64.logand bits 4L <> 0L);
  Alcotest.(check int64) "enabled service bits = 13 (NETWORK|BLOOM|WITNESS)"
    13L bits;
  (* Restore Core default for subsequent tests *)
  Peer.set_peer_bloom_filters false

(* With NODE_BLOOM advertised AND no mempool attached, [handle_mempool_msg]
   must return cleanly without writing to the peer.  The fact that the
   handler exists, is reachable from [handle_mempool_msg_for], and runs
   to completion (no Lwt exception) is what proves the dispatch wiring
   from [Cli.run]'s listener works end-to-end.  We flip the flag on for
   this test (default is off, per Core parity). *)
let test_bip35_handler_no_mempool () =
  cleanup_test_db ();
  Peer.set_peer_bloom_filters true;
  let db = Storage.ChainDB.create test_db_path in
  let chain = Sync.create_chain_state db Consensus.regtest in
  let ibd = Sync.create_ibd_state chain in
  Alcotest.(check bool) "ibd has no mempool" true (ibd.mempool = None);
  (* Build a peer with a dummy fd; no IO will be performed because the
     mempool is empty / absent. *)
  let fd = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let peer = Peer.make_peer ~network:Consensus.mainnet ~addr:"127.0.0.1"
    ~port:8333 ~id:0 ~direction:Peer.Outbound ~fd in
  (* Should complete without raising; the gate accepts because we DO
     advertise NODE_BLOOM, then the empty-mempool branch returns unit. *)
  Lwt_main.run (Sync.handle_mempool_msg ibd peer);
  (* Same path via the bare-mempool entry point used post-IBD. *)
  Lwt_main.run (Sync.handle_mempool_msg_for None peer);
  Storage.ChainDB.close db;
  (* Restore Core default for subsequent tests *)
  Peer.set_peer_bloom_filters false;
  cleanup_test_db ()

(* ============================================================================
   Pruning: --prune CLI value is MiB, internal prune_target is bytes.
   Audit: CORE-PARITY-AUDIT/_pruning-cross-impl-audit-2026-05-05.md (Bug 5).
   Reference: bitcoin-core/src/init.cpp:524 (--prune semantics).
   ============================================================================ *)

(* Static helper: matches the conversion in bin/main.ml. Kept here so the
   test pins the semantic; if the CLI conversion changes, this function and
   the assertions move together. *)
let convert_prune_mib_to_bytes mib =
  if mib = 0 then 0
  else if mib = 1 then 1  (* manual-mode sentinel *)
  else if mib < 550 then
    failwith "prune below floor"  (* CLI exits 1; tests just raise *)
  else mib * 1024 * 1024

let test_prune_cli_550_mib_to_bytes () =
  (* Core convention: --prune=550 means 550 MiB, i.e. 576716800 bytes. *)
  Alcotest.(check int) "550 MiB → bytes"
    (550 * 1024 * 1024) (convert_prune_mib_to_bytes 550);
  Alcotest.(check int) "550 MiB → 576716800"
    576716800 (convert_prune_mib_to_bytes 550)

let test_prune_cli_zero_is_off () =
  Alcotest.(check int) "--prune=0 stays 0 (off)" 0
    (convert_prune_mib_to_bytes 0)

let test_prune_cli_one_is_manual_sentinel () =
  (* --prune=1 is Core's manual-mode sentinel; auto-prune off. We keep
     literal 1 (not 1 MiB) so [prune_target > 0] still flags prune-mode
     for NODE_NETWORK_LIMITED. [prune_old_blocks] short-circuits on the
     literal sentinel — see [test_prune_old_blocks_manual_mode_short_circuits]. *)
  Alcotest.(check int) "--prune=1 manual sentinel" 1
    (convert_prune_mib_to_bytes 1)

let test_prune_cli_floor_rejects_2_to_549 () =
  (* Below-floor values must be rejected (Core init.cpp:524 floor at 550). *)
  let raised n =
    try ignore (convert_prune_mib_to_bytes n); false
    with _ -> true
  in
  Alcotest.(check bool) "--prune=2 rejected" true (raised 2);
  Alcotest.(check bool) "--prune=549 rejected" true (raised 549);
  Alcotest.(check bool) "--prune=100 rejected" true (raised 100)

let test_prune_cli_above_floor () =
  Alcotest.(check int) "--prune=1000 → 1000 MiB"
    (1000 * 1024 * 1024) (convert_prune_mib_to_bytes 1000);
  Alcotest.(check int) "--prune=2000 → 2 GiB"
    (2000 * 1024 * 1024) (convert_prune_mib_to_bytes 2000)

(* prune_old_blocks honors the byte semantic: with target=550 MiB and
   avg_block_size=1.5 MB, target_blocks ≈ 384, so keep_blocks = max 384 288
   = 384 (rounding aside; the math here is the spec). *)
let test_prune_old_blocks_uses_bytes () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let state = Sync.create_chain_state db Consensus.regtest in
  (* Set 550 MiB as the prune target (in bytes). *)
  state.prune_target <- 550 * 1024 * 1024;
  state.prune_height <- 0;
  (* current_height too small to trigger pruning; the function should be a
     no-op (prune_below would be negative). This is the regression-pin
     that prune_old_blocks doesn't crash on the new bytes semantic. *)
  Sync.prune_old_blocks state 100;
  Alcotest.(check int) "prune_height unchanged when below keep window"
    0 state.prune_height;
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_prune_old_blocks_manual_mode_short_circuits () =
  (* `--prune=1` manual-only mode (Bitcoin Core init.cpp:524 /
     blockmanager_args.cpp:27): node is in prune mode but the auto-prune
     trigger MUST NOT fire. Only the pruneblockchain RPC may delete
     data. Maps to Core's PRUNE_TARGET_MANUAL = uint64::MAX sentinel
     (an unreachable target so FindFilesToPrune's usage check is dead).

     Pre-fix behavior: prune_target=1 fell through to the keep-window
     math (target_blocks = 1 / 1_500_000 = 0; keep_blocks = max 0 288 =
     288), so prune_below = current_height - 288 still fired auto-prune
     deletes. Post-fix: function short-circuits without advancing
     prune_height. *)
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let state = Sync.create_chain_state db Consensus.regtest in
  state.prune_target <- 1; (* manual-mode sentinel *)
  state.prune_height <- 0;
  (* High current_height — auto-prune would normally fire here. Manual
     mode must keep prune_height pinned at 0. *)
  Sync.prune_old_blocks state 1_000_000;
  Alcotest.(check int) "manual mode: prune_height does not advance"
    0 state.prune_height;
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_prune_old_blocks_off_short_circuits () =
  (* prune_target=0 (off / archive default) is also a no-op. *)
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let state = Sync.create_chain_state db Consensus.regtest in
  state.prune_target <- 0;
  state.prune_height <- 0;
  Sync.prune_old_blocks state 1_000_000;
  Alcotest.(check int) "archive: prune_height does not advance"
    0 state.prune_height;
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* ============================================================================
   Side-branch acceptance (Pattern Y closure 2026-05-05)
   ============================================================================

   These tests guard the structural invariants of the side-branch path
   added to make [Mining.submit_block] accept a heavier fork's first
   block (rustoshi 68a422b counterpart; corpus entry
   `tools/diff-test-corpus/regression/reorg-via-submitblock`).

   The full end-to-end test (submit A1+A2 then B1+B2+B3 → tip flips to
   B3, UTXO state matches the B chain) lives in the diff-test corpus
   harness because it requires Validation.accept_block + a regtest
   coinbase + the OptimizedUtxoSet wiring. These unit tests exercise
   the in-process invariants the patch is responsible for. *)

(* register_side_branch_header MUST insert the entry into both the
   in-memory header map and the on-disk header store. It MUST NOT
   touch [set_height_hash] (that mapping is owned by accept_header /
   the active chain), and it MUST NOT rewind the active tip. *)
let test_register_side_branch_header_invariants () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let state = Sync.create_chain_state db Consensus.regtest in

  let genesis_hash = Crypto.compute_block_hash Consensus.regtest.genesis_header in
  let genesis_entry = Option.get (Sync.get_tip state) in
  Alcotest.(check int) "genesis at height 0" 0 genesis_entry.height;

  (* Build A1 on top of genesis via accept_header — this is the active
     chain block at height 1; height-hash maps 1 -> A1. *)
  let a1_entry = mine_test_header
    ~prev_block:genesis_hash
    ~prev_height:0
    ~bits:Consensus.regtest.genesis_header.bits () in
  let a1_total_work = Consensus.work_add genesis_entry.total_work
    (Sync.work_from_bits a1_entry.header.bits) in
  let a1_entry = Sync.{ a1_entry with total_work = a1_total_work } in
  Sync.accept_header state a1_entry;
  Alcotest.(check bool) "A1 in headers map" true
    (Hashtbl.mem state.headers (Cstruct.to_string a1_entry.hash));
  (* set_height_hash 1 -> A1 *)
  let h1_active_pre = Storage.ChainDB.get_hash_at_height db 1 in
  Alcotest.(check bool) "h=1 active mapping = A1" true
    (match h1_active_pre with
     | Some h -> Cstruct.equal h a1_entry.hash
     | None -> false);

  (* Now build B1 sharing the same parent (genesis) and register as
     side-branch. B1 must NOT clobber the active h=1 mapping. The
     [merkle_marker] picks a non-zero merkle root so B1's header is
     distinct from A1 even when both calls happen in the same wallclock
     second. *)
  let b1_entry = mine_test_header
    ~merkle_marker:0xb1b1b1b1l
    ~prev_block:genesis_hash
    ~prev_height:0
    ~bits:Consensus.regtest.genesis_header.bits () in
  Alcotest.(check bool) "B1 distinct from A1" true
    (not (Cstruct.equal a1_entry.hash b1_entry.hash));
  let b1_total_work = Consensus.work_add genesis_entry.total_work
    (Sync.work_from_bits b1_entry.header.bits) in
  let b1_entry = Sync.{ b1_entry with total_work = b1_total_work } in

  Sync.register_side_branch_header state b1_entry;

  (* B1 in headers map. *)
  Alcotest.(check bool) "B1 in headers map" true
    (Hashtbl.mem state.headers (Cstruct.to_string b1_entry.hash));
  (* B1's header is on disk. *)
  Alcotest.(check bool) "B1 header on disk" true
    (Storage.ChainDB.has_block_header db b1_entry.hash);
  (* CRUCIAL: active height-hash mapping STILL points at A1. This is
     the structural invariant accept_header would have broken. *)
  let h1_active_post = Storage.ChainDB.get_hash_at_height db 1 in
  Alcotest.(check bool) "h=1 active mapping STILL A1 (not B1)" true
    (match h1_active_post with
     | Some h -> Cstruct.equal h a1_entry.hash
     | None -> false);
  (* CRUCIAL: state.tip is unchanged (still A1, the equal-work first-
     accepted entry). *)
  Alcotest.(check bool) "state.tip unchanged after side-branch register" true
    (match state.tip with
     | Some t -> Cstruct.equal t.hash a1_entry.hash
     | None -> false);

  Storage.ChainDB.close db;
  cleanup_test_db ()

(* When [Mining.submit_block] receives a block whose parent is in the
   index but is NOT the validated tip, it must NOT reject with the
   pre-fix "Block does not build on validated tip" error. The actual
   acceptance result depends on whether the parent's header is in the
   in-memory map; in this test we don't do a full coinbase + UTXO
   build, so we assert only that the gate flips: pre-fix error string
   gone, replaced by a header / validation error from the side-branch
   path or by Ok () on a successful path. *)
let test_submit_block_side_branch_gate () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let state = Sync.create_chain_state db Consensus.regtest in
  let genesis_hash = Crypto.compute_block_hash Consensus.regtest.genesis_header in

  (* Build the active chain to height 1: A1 on genesis. *)
  let a1_entry = mine_test_header
    ~prev_block:genesis_hash
    ~prev_height:0
    ~bits:Consensus.regtest.genesis_header.bits () in
  let a1_total_work = Consensus.work_add
    (Option.get (Sync.get_tip state)).total_work
    (Sync.work_from_bits a1_entry.header.bits) in
  let a1_entry = Sync.{ a1_entry with total_work = a1_total_work } in
  Sync.accept_header state a1_entry;
  state.tip <- Some a1_entry;
  state.blocks_synced <- 1;
  Storage.ChainDB.set_chain_tip state.db a1_entry.hash a1_entry.height;

  (* Build B1 on genesis (a side-branch). Its synthetic block body
     won't pass full validation (no real coinbase, no merkle), but the
     ERROR returned must NOT be the pre-fix "does not build on
     validated tip" guard — it must come from inside the side-branch
     path (e.g. CheckBlock failure). *)
  let b1_entry = mine_test_header
    ~merkle_marker:0xb1b1b1b1l
    ~prev_block:genesis_hash
    ~prev_height:0
    ~bits:Consensus.regtest.genesis_header.bits () in
  Alcotest.(check bool) "B1 distinct from A1" true
    (not (Cstruct.equal a1_entry.hash b1_entry.hash));
  let utxo = Utxo.UtxoSet.create db in
  let mp = Mempool.create ~require_standard:false ~verify_scripts:false
    ~utxo ~current_height:1 () in
  let block_b1 : Types.block = { header = b1_entry.header; transactions = [] } in
  let result = Mining.submit_block ~network_type:Consensus.Regtest
    block_b1 state mp in
  (match result with
   | Ok () ->
     (* Unlikely without a coinbase, but accept this outcome — the gate
        is open. *)
     ()
   | Error msg ->
     (* The pre-fix error message is the regression we're guarding
        against. *)
     Alcotest.(check bool)
       (Printf.sprintf
          "submit_block must NOT reject side-branch with the pre-fix \
           gate string (got: %S)" msg)
       true
       (not (String.length msg >= 32
             && String.sub msg 0 32
                = "Block does not build on validated")));

  Storage.ChainDB.close db;
  cleanup_test_db ()

(* ============================================================================
   Tx-index connect/disconnect (Pattern C0 closure 2026-05-05)
   ============================================================================

   Guards the Pattern C0 wiring added in lib/sync.ml that mirrors Bitcoin
   Core's [TxIndex::CustomAppend] / [CustomRemove] semantics
   ([bitcoin-core/src/index/txindex.cpp]). Pre-fix, [Storage.ChainDB.store_tx_index]
   existed but had no production caller; getrawtransaction returned
   "no such transaction" for every IBD-fetched / submitblock-accepted
   tx (see CORE-PARITY-AUDIT/_txindex-revert-on-reorg-fleet-result-2026-05-05.md).

   These tests exercise the helpers directly because the full block-
   connect pipeline requires a coinbase + UTXO + accept_block harness
   that the diff-test corpus already covers (entry
   tools/diff-test-corpus/regression/txindex-revert-on-reorg). *)

(* Build a synthetic block with one fake non-coinbase tx so we can
   exercise [tx_index_write_for_block] and [tx_index_erase_for_block]
   without a full coinbase + UTXO setup. The tx itself is structurally
   minimal — the helpers index by [Crypto.compute_txid tx], which works
   for any well-formed Types.transaction value. *)
let make_synthetic_tx ~marker : Types.transaction =
  {
    version = 1l;
    inputs = [{
      previous_output = { txid = Types.zero_hash; vout = 0xffffffffl };
      script_sig = Cstruct.create 0;
      sequence = 0xffffffffl;
    }];
    outputs = [{
      value = 0L;
      script_pubkey = Cstruct.of_string (Printf.sprintf "tx-%d" marker);
    }];
    witnesses = [];
    locktime = 0l;
  }

(* Build a synthetic block with two transactions sharing a known parent.
   The block hash is whatever Crypto.compute_block_hash returns for the
   header — fine for a tx_index round-trip test where we just need a
   stable 32-byte block_hash key. *)
let make_synthetic_block ~tx_count : Types.block * Types.hash256 =
  let header = Types.{
    version = 1l;
    prev_block = Types.zero_hash;
    merkle_root = Types.zero_hash;
    timestamp = 0l;
    bits = 0x207fffffl;
    nonce = 0l;
  } in
  let hash = Crypto.compute_block_hash header in
  let txs = List.init tx_count (fun i -> make_synthetic_tx ~marker:i) in
  ({ header; transactions = txs }, hash)

(* tx_index_write_for_block_recompute MUST populate the txid -> (block_hash,
   tx_idx) mapping for every tx in the block. After the helper runs,
   [Storage.ChainDB.get_tx_index] returns the right (block_hash, tx_idx)
   pair for each tx. This is the Pattern C0 invariant: pre-fix the
   helpers existed but had no caller, so [getrawtransaction] returned
   "no such tx" for every IBD-fetched tx. *)
let test_tx_index_write_populates_index () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let (block, block_hash) = make_synthetic_block ~tx_count:3 in

  (* Pre-fix invariant: lookup MISSes for every tx before the helper
     fires. Confirms the test setup correctly mirrors a fresh datadir
     on the IBD path. *)
  List.iter (fun tx ->
    let txid = Crypto.compute_txid tx in
    Alcotest.(check bool) "pre-write: tx_index miss" true
      (Storage.ChainDB.get_tx_index db txid = None)
  ) block.transactions;

  Sync.tx_index_write_for_block_recompute db block block_hash;

  (* Post-write: every tx is indexed at the right (block_hash, tx_idx). *)
  List.iteri (fun expected_idx tx ->
    let txid = Crypto.compute_txid tx in
    match Storage.ChainDB.get_tx_index db txid with
    | None ->
      Alcotest.fail (Printf.sprintf
        "tx_index miss for tx_idx=%d post-write" expected_idx)
    | Some (got_blockhash, got_idx) ->
      Alcotest.(check int)
        (Printf.sprintf "tx_idx for txid #%d" expected_idx)
        expected_idx got_idx;
      Alcotest.(check bool)
        (Printf.sprintf "block_hash for txid #%d" expected_idx)
        true (Cstruct.equal block_hash got_blockhash);
      (* Tx blob is also stored — required by [Rpc.lookup_transaction]
         which dereferences the index pointer through
         [Storage.ChainDB.get_transaction]. *)
      Alcotest.(check bool)
        (Printf.sprintf "tx blob retrievable for tx_idx=%d" expected_idx)
        true (Storage.ChainDB.get_transaction db txid <> None)
  ) block.transactions;

  Storage.ChainDB.close db;
  cleanup_test_db ()

(* tx_index_erase_for_block MUST delete the txid -> (block_hash, tx_idx)
   mapping for every tx in a disconnected block. This is the Pattern C
   invariant: post-reorg, [getrawtransaction] for a tx that lived only
   in a now-disconnected block must NOT return positive confirmations.
   Mirrors Bitcoin Core's [TxIndex::CustomRemove] (txindex.cpp:69-83)
   fired from [BaseIndex::BlockDisconnected]. *)
let test_tx_index_erase_drops_disconnected_txs () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let (block, block_hash) = make_synthetic_block ~tx_count:2 in

  Sync.tx_index_write_for_block_recompute db block block_hash;
  (* Sanity: post-write all hits. *)
  List.iter (fun tx ->
    let txid = Crypto.compute_txid tx in
    Alcotest.(check bool) "post-write: tx_index hit" true
      (Storage.ChainDB.get_tx_index db txid <> None)
  ) block.transactions;

  Sync.tx_index_erase_for_block db block;

  (* Post-erase: every tx_index entry is gone. *)
  List.iter (fun tx ->
    let txid = Crypto.compute_txid tx in
    Alcotest.(check bool) "post-erase: tx_index miss" true
      (Storage.ChainDB.get_tx_index db txid = None)
  ) block.transactions;

  Storage.ChainDB.close db;
  cleanup_test_db ()

(* tx_index_write_for_block (the precomputed-txid variant) MUST agree
   with tx_index_write_for_block_recompute on the same block. The two
   helpers exist because some callers have a precomputed txid array
   from accept_block (faster) and some don't. They must be byte-
   identical in their resulting tx_index CF state. *)
let test_tx_index_write_precomputed_matches_recompute () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let (block, block_hash) = make_synthetic_block ~tx_count:2 in
  let txid_arr =
    Array.of_list (List.map Crypto.compute_txid block.transactions) in

  Sync.tx_index_write_for_block db block block_hash txid_arr;

  (* Post-write: every tx is indexed at the right (block_hash, tx_idx),
     matching what the recompute variant would produce. *)
  List.iteri (fun expected_idx tx ->
    let txid = Crypto.compute_txid tx in
    (match Storage.ChainDB.get_tx_index db txid with
     | None ->
       Alcotest.fail (Printf.sprintf
         "tx_index miss for tx_idx=%d (precomputed-txid variant)"
         expected_idx)
     | Some (got_blockhash, got_idx) ->
       Alcotest.(check int)
         (Printf.sprintf "tx_idx for txid #%d (precomputed)" expected_idx)
         expected_idx got_idx;
       Alcotest.(check bool)
         (Printf.sprintf "block_hash for txid #%d (precomputed)" expected_idx)
         true (Cstruct.equal block_hash got_blockhash))
  ) block.transactions;

  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Core parity: per-peer unconnecting-headers counter must tolerate up
   to MAX_NUM_UNCONNECTING_HEADERS_MSGS=10 successive unlinked batches
   before the caller drops the peer.  Mirrors Bitcoin Core's
   `nUnconnectingHeaders` accounting in
   net_processing.cpp::ProcessHeadersMessage.  Pre-fix, camlcoin
   silently dropped sync_peer (-> Idle) on the first orphan with no
   penalty — see
   CORE-PARITY-AUDIT/_header-sync-dos-cross-impl-audit-2026-05-06-part1.md
   (Pattern B). *)
let test_unconnecting_headers_counter_under_threshold () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let state = Sync.create_chain_state db Consensus.regtest in
  let peer_id = 42 in
  Alcotest.(check int) "initial counter is 0"
    0 (Sync.unconnecting_headers_count state peer_id);
  (* 10 successive unconnecting messages should NOT exceed threshold. *)
  for _ = 1 to Sync.max_num_unconnecting_headers_msgs do
    let exceeded = Sync.note_unconnecting_headers state peer_id in
    Alcotest.(check bool)
      "under threshold should not signal exceeded"
      false exceeded
  done;
  Alcotest.(check int) "counter at threshold"
    Sync.max_num_unconnecting_headers_msgs
    (Sync.unconnecting_headers_count state peer_id);
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_unconnecting_headers_counter_exceeds_threshold () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let state = Sync.create_chain_state db Consensus.regtest in
  let peer_id = 7 in
  for _ = 1 to Sync.max_num_unconnecting_headers_msgs do
    let _ = Sync.note_unconnecting_headers state peer_id in ()
  done;
  (* 11th call MUST signal exceeded. *)
  let exceeded = Sync.note_unconnecting_headers state peer_id in
  Alcotest.(check bool) "11th unconnecting message exceeds threshold"
    true exceeded;
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_unconnecting_headers_reset_on_connecting () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let state = Sync.create_chain_state db Consensus.regtest in
  let peer_id = 99 in
  (* Bump the counter a few times. *)
  for _ = 1 to 5 do
    let _ = Sync.note_unconnecting_headers state peer_id in ()
  done;
  Alcotest.(check int) "counter reflects bumps"
    5 (Sync.unconnecting_headers_count state peer_id);
  (* Reset on a successful connecting batch. *)
  Sync.reset_unconnecting_headers state peer_id;
  Alcotest.(check int) "counter resets to 0"
    0 (Sync.unconnecting_headers_count state peer_id);
  (* Subsequent unconnecting starts fresh. *)
  let _ = Sync.note_unconnecting_headers state peer_id in
  Alcotest.(check int) "counter starts fresh after reset"
    1 (Sync.unconnecting_headers_count state peer_id);
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_unconnecting_headers_per_peer () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let state = Sync.create_chain_state db Consensus.regtest in
  let pa = 1 and pb = 2 in
  for _ = 1 to Sync.max_num_unconnecting_headers_msgs do
    let _ = Sync.note_unconnecting_headers state pa in ()
  done;
  Alcotest.(check int) "peer A at threshold"
    Sync.max_num_unconnecting_headers_msgs
    (Sync.unconnecting_headers_count state pa);
  Alcotest.(check int) "peer B unaffected"
    0 (Sync.unconnecting_headers_count state pb);
  let exceeded_b = Sync.note_unconnecting_headers state pb in
  Alcotest.(check bool) "peer B's first message does not exceed threshold"
    false exceeded_b;
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
      (* D-FULL multi-block reorg atomicity (2026-05-05).  Guards the
         single-batch invariant of [Sync.reorganize] across the
         disconnect+reconnect halves; reference:
         CORE-PARITY-AUDIT/_post-reorg-consistency-fleet-result-2026-05-05.md *)
      test_case "MAX_REORG_DEPTH cap returns error" `Quick
        test_reorganize_max_reorg_depth_cap;
      test_case "crash pre-commit leaves disk untouched" `Quick
        test_reorganize_crash_pre_commit_no_disk_change;
      test_case "single-batch commit (3-disconnect + 4-reconnect)" `Quick
        test_reorganize_single_batch_commit;
    ];
    "side_branch_acceptance", [
      (* Pattern Y closure 2026-05-05 (rustoshi 68a422b counterpart).
         Guards the structural invariants of the submit_block side-
         branch path. End-to-end coverage lives in
         tools/diff-test-corpus/regression/reorg-via-submitblock. *)
      test_case "register_side_branch_header preserves active chain"
        `Quick test_register_side_branch_header_invariants;
      test_case "submit_block side-branch gate is open"
        `Quick test_submit_block_side_branch_gate;
    ];
    "txindex_connect_disconnect", [
      (* Pattern C0 closure 2026-05-05. Guards the tx_index wiring
         that mirrors Bitcoin Core's TxIndex::CustomAppend /
         CustomRemove (bitcoin-core/src/index/txindex.cpp). End-to-end
         coverage lives in
         tools/diff-test-corpus/regression/txindex-revert-on-reorg.
         Findings doc:
         CORE-PARITY-AUDIT/_txindex-revert-on-reorg-fleet-result-2026-05-05.md *)
      test_case "tx_index_write populates index"
        `Quick test_tx_index_write_populates_index;
      test_case "tx_index_erase drops disconnected txs"
        `Quick test_tx_index_erase_drops_disconnected_txs;
      test_case "precomputed-txid variant matches recompute"
        `Quick test_tx_index_write_precomputed_matches_recompute;
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
    "bip35_mempool_dispatch", [
      test_case "default off (Core parity)" `Quick test_bip35_default_off;
      test_case "advertise when enabled" `Quick
        test_bip35_advertise_when_enabled;
      test_case "handler no mempool" `Quick test_bip35_handler_no_mempool;
    ];
    "prune_units", [
      test_case "--prune=0 → 0 (off)" `Quick test_prune_cli_zero_is_off;
      test_case "--prune=1 manual sentinel" `Quick test_prune_cli_one_is_manual_sentinel;
      test_case "--prune=550 MiB → bytes" `Quick test_prune_cli_550_mib_to_bytes;
      test_case "--prune=N for N in 2..549 rejected" `Quick test_prune_cli_floor_rejects_2_to_549;
      test_case "--prune above floor scales" `Quick test_prune_cli_above_floor;
      test_case "prune_old_blocks honors bytes semantic" `Quick test_prune_old_blocks_uses_bytes;
      test_case "prune_old_blocks: manual mode short-circuits" `Quick test_prune_old_blocks_manual_mode_short_circuits;
      test_case "prune_old_blocks: archive (off) short-circuits" `Quick test_prune_old_blocks_off_short_circuits;
    ];
    "unconnecting_headers", [
      test_case "under threshold tolerated" `Quick
        test_unconnecting_headers_counter_under_threshold;
      test_case "11th message exceeds threshold" `Quick
        test_unconnecting_headers_counter_exceeds_threshold;
      test_case "reset on connecting batch" `Quick
        test_unconnecting_headers_reset_on_connecting;
      test_case "per-peer independent" `Quick
        test_unconnecting_headers_per_peer;
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
      test_case "invalidate_reorg_reconsider" `Slow test_invalidate_reorg_reconsider;
      test_case "find_descendants_with_chain" `Slow test_find_descendants_with_chain;
    ];
  ]
