(* Tests for regtest mode functionality *)

open Camlcoin

(* Test directory that gets cleaned up *)
let test_db_path = "/tmp/camlcoin_test_regtest_db"

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
   Regtest Chain Parameters Tests
   ============================================================================ *)

let test_regtest_network_config () =
  (* Verify regtest network configuration matches Bitcoin Core *)
  let regtest = Consensus.regtest in

  (* Magic bytes (reversed for little-endian) *)
  Alcotest.(check int32) "regtest magic" 0xDAB5BFFAl regtest.magic;

  (* Default port *)
  Alcotest.(check int) "regtest port" 18444 regtest.default_port;

  (* No retargeting on regtest *)
  Alcotest.(check bool) "pow_no_retargeting" true regtest.pow_no_retargeting;

  (* Allow min difficulty *)
  Alcotest.(check bool) "pow_allow_min_difficulty" true regtest.pow_allow_min_difficulty;

  (* Very easy difficulty (0x207fffff) *)
  Alcotest.(check int32) "pow_limit" 0x207fffffl regtest.pow_limit;

  (* SegWit active from genesis *)
  Alcotest.(check int) "segwit_height" 0 regtest.segwit_height;

  (* Taproot active from genesis *)
  Alcotest.(check int) "taproot_height" 0 regtest.taproot_height;

  (* Bech32 HRP is bcrt *)
  Alcotest.(check string) "bech32_hrp" "bcrt" regtest.bech32_hrp;

  (* No DNS seeds *)
  Alcotest.(check int) "no dns seeds" 0 (List.length regtest.dns_seeds);

  (* Halving interval is 150 (not 210000) *)
  Alcotest.(check int) "halving_interval" 150 regtest.halving_interval

let test_regtest_genesis_block () =
  let regtest = Consensus.regtest in

  (* Genesis hash *)
  let expected_genesis = Types.hash256_of_hex
    "06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f" in
  Alcotest.(check bool) "genesis hash" true
    (Cstruct.equal expected_genesis regtest.genesis_hash);

  (* Genesis header values *)
  Alcotest.(check int32) "genesis version" 1l regtest.genesis_header.version;
  Alcotest.(check int32) "genesis timestamp" 1296688602l regtest.genesis_header.timestamp;
  Alcotest.(check int32) "genesis bits" 0x207fffffl regtest.genesis_header.bits;
  Alcotest.(check int32) "genesis nonce" 2l regtest.genesis_header.nonce

(* ============================================================================
   Regtest Subsidy Tests
   ============================================================================ *)

let test_regtest_halving_interval () =
  (* Regtest halves every 150 blocks, not 210000 *)
  let regtest = Consensus.regtest in

  (* Block 0-149: 50 BTC *)
  Alcotest.(check int64) "block 0 subsidy" 5_000_000_000L
    (Consensus.block_subsidy ~halving_interval:regtest.halving_interval 0);
  Alcotest.(check int64) "block 149 subsidy" 5_000_000_000L
    (Consensus.block_subsidy ~halving_interval:regtest.halving_interval 149);

  (* Block 150-299: 25 BTC (first halving) *)
  Alcotest.(check int64) "block 150 subsidy" 2_500_000_000L
    (Consensus.block_subsidy ~halving_interval:regtest.halving_interval 150);
  Alcotest.(check int64) "block 299 subsidy" 2_500_000_000L
    (Consensus.block_subsidy ~halving_interval:regtest.halving_interval 299);

  (* Block 300-449: 12.5 BTC (second halving) *)
  Alcotest.(check int64) "block 300 subsidy" 1_250_000_000L
    (Consensus.block_subsidy ~halving_interval:regtest.halving_interval 300);

  (* Block 450-599: 6.25 BTC (third halving) *)
  Alcotest.(check int64) "block 450 subsidy" 625_000_000L
    (Consensus.block_subsidy ~halving_interval:regtest.halving_interval 450)

let test_block_subsidy_for_network () =
  (* Test the block_subsidy_for_network convenience function *)

  (* Mainnet uses 210000 interval *)
  Alcotest.(check int64) "mainnet block 0" 5_000_000_000L
    (Consensus.block_subsidy_for_network Consensus.Mainnet 0);
  Alcotest.(check int64) "mainnet block 209999" 5_000_000_000L
    (Consensus.block_subsidy_for_network Consensus.Mainnet 209_999);
  Alcotest.(check int64) "mainnet block 210000" 2_500_000_000L
    (Consensus.block_subsidy_for_network Consensus.Mainnet 210_000);

  (* Regtest uses 150 interval *)
  Alcotest.(check int64) "regtest block 0" 5_000_000_000L
    (Consensus.block_subsidy_for_network Consensus.Regtest 0);
  Alcotest.(check int64) "regtest block 149" 5_000_000_000L
    (Consensus.block_subsidy_for_network Consensus.Regtest 149);
  Alcotest.(check int64) "regtest block 150" 2_500_000_000L
    (Consensus.block_subsidy_for_network Consensus.Regtest 150)

(* ============================================================================
   Regtest Mining Tests
   ============================================================================ *)

let create_test_chain_state () =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let chain = Sync.create_chain_state db Consensus.regtest in
  (chain, db)

let test_regtest_instant_mining () =
  (* On regtest, mining should find a valid nonce almost instantly *)
  let (chain, db) = create_test_chain_state () in
  let utxo = Utxo.UtxoSet.create db in
  let mp = Mempool.create ~require_standard:false ~verify_scripts:false ~utxo ~current_height:0 () in
  let payout_script = Cstruct.of_string "\x76\xa9\x14test\x88\xac" in

  let template = Mining.create_block_template ~chain ~mp ~payout_script in

  (* Regtest difficulty: 0x207fffff means almost any hash is valid
     Should find a block within the first few nonces *)
  let result = Mining.mine_block template 1000l in

  Alcotest.(check bool) "found a block" true (Option.is_some result);

  let block = Option.get result in
  let block_hash = Crypto.compute_block_hash block.header in

  (* Verify hash meets the easy target *)
  Alcotest.(check bool) "hash meets regtest target" true
    (Consensus.hash_meets_target block_hash block.header.bits);

  (* Verify nonce is small (should be found quickly) *)
  Alcotest.(check bool) "nonce < 1000" true
    (Int32.compare block.header.nonce 1000l < 0);

  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_regtest_no_difficulty_adjustment () =
  (* Verify that pow_no_retargeting prevents difficulty changes *)
  let regtest = Consensus.regtest in

  (* Even at a difficulty adjustment boundary, bits should stay the same *)
  let bits = Consensus.get_next_work_required
    ~height:2016
    ~block_time:1296688602l
    ~prev_block_time:1296688000l  (* Some time difference *)
    ~prev_bits:regtest.pow_limit
    ~get_block_info:(fun _ -> (1296688000l, regtest.pow_limit))
    ~network:regtest in

  (* Should be unchanged from pow_limit *)
  Alcotest.(check int32) "no difficulty change" regtest.pow_limit bits

let test_mine_multiple_blocks_regtest () =
  (* Test mining multiple blocks in sequence *)
  let (chain, db) = create_test_chain_state () in
  let utxo = Utxo.UtxoSet.create db in
  let mp = Mempool.create ~require_standard:false ~verify_scripts:false ~utxo ~current_height:0 () in
  let payout_script = Cstruct.of_string "\x76\xa9\x14test\x88\xac" in

  let hashes = ref [] in

  (* Mine 5 blocks *)
  for _ = 1 to 5 do
    let template = Mining.create_block_template ~chain ~mp ~payout_script in
    match Mining.mine_block template 10000l with
    | None -> Alcotest.fail "Failed to mine block on regtest"
    | Some block ->
      match Mining.submit_block block chain mp with
      | Error msg -> Alcotest.fail ("Block submission failed: " ^ msg)
      | Ok () ->
        let hash = Crypto.compute_block_hash block.header in
        hashes := hash :: !hashes
  done;

  Alcotest.(check int) "mined 5 blocks" 5 (List.length !hashes);

  (* Each hash should be unique *)
  let unique_hashes = List.sort_uniq (fun a b ->
    if Cstruct.equal a b then 0 else Cstruct.compare a b
  ) !hashes in
  Alcotest.(check int) "all hashes unique" 5 (List.length unique_hashes);

  Storage.ChainDB.close db;
  cleanup_test_db ()

(* ============================================================================
   Regtest Coinbase Tests
   ============================================================================ *)

let test_coinbase_uses_regtest_subsidy () =
  let height = 160 in  (* After first halving on regtest *)
  let total_fee = 10_000L in
  let payout_script = Cstruct.of_string "\x76\xa9\x14test\x88\xac" in
  let extra_nonce = Cstruct.create 8 in

  let coinbase = Mining.create_coinbase
    ~height ~total_fee ~payout_script ~extra_nonce
    ~witness_root:None ~network_type:Consensus.Regtest () in

  (* Expected: 25 BTC (post-halving at 150) + 10k fee *)
  let expected_reward = Int64.add 2_500_000_000L total_fee in
  let actual_reward = (List.hd coinbase.outputs).value in

  Alcotest.(check int64) "post-halving coinbase value" expected_reward actual_reward

let test_block_template_regtest_subsidy () =
  let (chain, db) = create_test_chain_state () in
  let utxo = Utxo.UtxoSet.create db in
  let mp = Mempool.create ~require_standard:false ~verify_scripts:false ~utxo ~current_height:0 () in
  let payout_script = Cstruct.of_string "\x76\xa9\x14test\x88\xac" in

  let template = Mining.create_block_template ~chain ~mp ~payout_script in

  (* Template should use regtest network type *)
  Alcotest.(check bool) "network_type is Regtest"
    (template.network_type = Consensus.Regtest)
    true;

  (* Coinbase should have 50 BTC (block 1 is before first halving at 150) *)
  let coinbase_value = (List.hd template.coinbase_tx.outputs).value in
  Alcotest.(check int64) "coinbase is 50 BTC" 5_000_000_000L coinbase_value;

  Storage.ChainDB.close db;
  cleanup_test_db ()

(* ============================================================================
   Regtest CLI Configuration Tests
   ============================================================================ *)

let test_regtest_cli_config () =
  let config = Cli.config_for_network `Regtest in

  Alcotest.(check string) "network is regtest"
    (match config.network with `Regtest -> "regtest" | _ -> "other")
    "regtest";

  (* Data directory should be under regtest subdirectory *)
  Alcotest.(check bool) "data_dir contains regtest" true
    (Astring.String.is_suffix ~affix:"regtest" config.data_dir);

  (* RPC port should be 18443 *)
  Alcotest.(check int) "rpc_port" 18443 config.rpc_port;

  (* P2P port should be 18444 *)
  Alcotest.(check int) "p2p_port" 18444 config.p2p_port

(* ============================================================================
   All Soft Forks Active from Genesis Tests
   ============================================================================ *)

let test_regtest_soft_forks_active () =
  let regtest = Consensus.regtest in

  (* All soft forks should have low activation heights *)
  Alcotest.(check int) "SegWit active from genesis" 0 regtest.segwit_height;
  Alcotest.(check int) "Taproot active from genesis" 0 regtest.taproot_height;

  (* Script flags at height 0 should include SegWit and Taproot *)
  let flags = Consensus.get_block_script_flags 0 regtest in

  Alcotest.(check bool) "SegWit flag set" true
    (flags land Consensus.script_verify_witness <> 0);
  Alcotest.(check bool) "Taproot flag set" true
    (flags land Consensus.script_verify_taproot <> 0)

(* ============================================================================
   Test Runner
   ============================================================================ *)

let () =
  cleanup_test_db ();
  let open Alcotest in
  run "Regtest" [
    "network_config", [
      test_case "regtest network configuration" `Quick test_regtest_network_config;
      test_case "regtest genesis block" `Quick test_regtest_genesis_block;
    ];
    "subsidy", [
      test_case "regtest halving interval (150 blocks)" `Quick test_regtest_halving_interval;
      test_case "block_subsidy_for_network" `Quick test_block_subsidy_for_network;
    ];
    "mining", [
      test_case "instant mining on regtest" `Slow test_regtest_instant_mining;
      test_case "no difficulty adjustment" `Quick test_regtest_no_difficulty_adjustment;
      test_case "mine multiple blocks" `Slow test_mine_multiple_blocks_regtest;
    ];
    "coinbase", [
      test_case "coinbase uses regtest subsidy" `Quick test_coinbase_uses_regtest_subsidy;
      test_case "block template regtest subsidy" `Quick test_block_template_regtest_subsidy;
    ];
    "cli", [
      test_case "regtest CLI config" `Quick test_regtest_cli_config;
    ];
    "soft_forks", [
      test_case "all soft forks active from genesis" `Quick test_regtest_soft_forks_active;
    ];
  ]
