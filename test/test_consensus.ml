(* Tests for consensus parameters and functions *)

open Camlcoin

(* Test block subsidy calculation *)
let test_block_subsidy () =
  (* Initial subsidy: 50 BTC = 5,000,000,000 satoshis *)
  Alcotest.(check int64) "genesis block subsidy" 5_000_000_000L
    (Consensus.block_subsidy 0);
  Alcotest.(check int64) "block 1 subsidy" 5_000_000_000L
    (Consensus.block_subsidy 1);
  Alcotest.(check int64) "block 209999 subsidy" 5_000_000_000L
    (Consensus.block_subsidy 209_999);
  (* First halving at block 210000: 25 BTC *)
  Alcotest.(check int64) "first halving" 2_500_000_000L
    (Consensus.block_subsidy 210_000);
  (* Second halving at block 420000: 12.5 BTC *)
  Alcotest.(check int64) "second halving" 1_250_000_000L
    (Consensus.block_subsidy 420_000);
  (* Third halving: 6.25 BTC *)
  Alcotest.(check int64) "third halving" 625_000_000L
    (Consensus.block_subsidy 630_000);
  (* After 64 halvings, subsidy is 0 *)
  Alcotest.(check int64) "64th halving" 0L
    (Consensus.block_subsidy (64 * 210_000));
  Alcotest.(check int64) "way in the future" 0L
    (Consensus.block_subsidy (100 * 210_000))

(* Test consensus constants *)
let test_consensus_constants () =
  Alcotest.(check int) "max block weight" 4_000_000 Consensus.max_block_weight;
  Alcotest.(check int64) "coin value" 100_000_000L Consensus.coin;
  Alcotest.(check int64) "max money" 2_100_000_000_000_000L Consensus.max_money;
  Alcotest.(check int) "coinbase maturity" 100 Consensus.coinbase_maturity;
  Alcotest.(check int) "difficulty interval" 2016 Consensus.difficulty_adjustment_interval;
  Alcotest.(check int) "target timespan" 1_209_600 Consensus.target_timespan;
  Alcotest.(check int) "halving interval" 210_000 Consensus.halving_interval

(* Test is_valid_money *)
let test_valid_money () =
  Alcotest.(check bool) "zero is valid" true (Consensus.is_valid_money 0L);
  Alcotest.(check bool) "1 satoshi is valid" true (Consensus.is_valid_money 1L);
  Alcotest.(check bool) "1 BTC is valid" true (Consensus.is_valid_money 100_000_000L);
  Alcotest.(check bool) "max money is valid" true
    (Consensus.is_valid_money Consensus.max_money);
  Alcotest.(check bool) "over max is invalid" false
    (Consensus.is_valid_money (Int64.add Consensus.max_money 1L));
  Alcotest.(check bool) "negative is invalid" false
    (Consensus.is_valid_money (-1L))

(* Test median time past *)
let test_median_time_past () =
  (* Empty list *)
  Alcotest.(check int32) "empty list" 0l (Consensus.median_time_past []);
  (* Single element *)
  Alcotest.(check int32) "single element" 100l
    (Consensus.median_time_past [100l]);
  (* Three elements *)
  Alcotest.(check int32) "three elements" 200l
    (Consensus.median_time_past [100l; 200l; 300l]);
  (* Unsorted input *)
  Alcotest.(check int32) "unsorted input" 200l
    (Consensus.median_time_past [300l; 100l; 200l]);
  (* 11 elements (typical Bitcoin MTP) *)
  let timestamps = [1l; 2l; 3l; 4l; 5l; 6l; 7l; 8l; 9l; 10l; 11l] in
  Alcotest.(check int32) "eleven elements" 6l
    (Consensus.median_time_past timestamps);
  (* Even number of elements *)
  Alcotest.(check int32) "four elements" 30l
    (Consensus.median_time_past [10l; 20l; 30l; 40l])

(* Test difficulty adjustment height detection *)
let test_difficulty_adjustment_height () =
  Alcotest.(check bool) "height 0 is not adjustment" false
    (Consensus.is_difficulty_adjustment_height 0);
  Alcotest.(check bool) "height 1 is not adjustment" false
    (Consensus.is_difficulty_adjustment_height 1);
  Alcotest.(check bool) "height 2015 is not adjustment" false
    (Consensus.is_difficulty_adjustment_height 2015);
  Alcotest.(check bool) "height 2016 is adjustment" true
    (Consensus.is_difficulty_adjustment_height 2016);
  Alcotest.(check bool) "height 4032 is adjustment" true
    (Consensus.is_difficulty_adjustment_height 4032);
  Alcotest.(check bool) "height 4033 is not adjustment" false
    (Consensus.is_difficulty_adjustment_height 4033)

(* Test coinbase height encoding *)
let test_encode_height_in_coinbase () =
  (* Height 0: OP_0 *)
  let cs0 = Consensus.encode_height_in_coinbase 0 in
  Alcotest.(check int) "height 0 length" 1 (Cstruct.length cs0);
  Alcotest.(check int) "height 0 byte" 0x00 (Cstruct.get_uint8 cs0 0);
  (* Height 1-16: OP_1 through OP_16 *)
  let cs1 = Consensus.encode_height_in_coinbase 1 in
  Alcotest.(check int) "height 1 length" 1 (Cstruct.length cs1);
  Alcotest.(check int) "height 1 byte" 0x51 (Cstruct.get_uint8 cs1 0);
  let cs16 = Consensus.encode_height_in_coinbase 16 in
  Alcotest.(check int) "height 16 length" 1 (Cstruct.length cs16);
  Alcotest.(check int) "height 16 byte" 0x60 (Cstruct.get_uint8 cs16 0);
  (* Height 17: needs 1 byte push *)
  let cs17 = Consensus.encode_height_in_coinbase 17 in
  Alcotest.(check int) "height 17 length" 2 (Cstruct.length cs17);
  Alcotest.(check int) "height 17 push byte" 1 (Cstruct.get_uint8 cs17 0);
  Alcotest.(check int) "height 17 value" 17 (Cstruct.get_uint8 cs17 1);
  (* Height 127 (0x7f): still 1 byte (max before sign bit issue) *)
  let cs127 = Consensus.encode_height_in_coinbase 127 in
  Alcotest.(check int) "height 127 length" 2 (Cstruct.length cs127);
  Alcotest.(check int) "height 127 push byte" 1 (Cstruct.get_uint8 cs127 0);
  (* Height 128 (0x80): needs 2 bytes due to sign bit *)
  let cs128 = Consensus.encode_height_in_coinbase 128 in
  Alcotest.(check int) "height 128 length" 3 (Cstruct.length cs128);
  Alcotest.(check int) "height 128 push byte" 2 (Cstruct.get_uint8 cs128 0);
  (* Height 0x7fff: still 2 bytes *)
  let cs32767 = Consensus.encode_height_in_coinbase 32767 in
  Alcotest.(check int) "height 32767 length" 3 (Cstruct.length cs32767);
  (* Height 0x8000: needs 3 bytes due to sign bit *)
  let cs32768 = Consensus.encode_height_in_coinbase 32768 in
  Alcotest.(check int) "height 32768 length" 4 (Cstruct.length cs32768);
  Alcotest.(check int) "height 32768 push byte" 3 (Cstruct.get_uint8 cs32768 0)

(* Test network configurations *)
let test_mainnet_config () =
  Alcotest.(check string) "mainnet name" "mainnet" Consensus.mainnet.name;
  Alcotest.(check int32) "mainnet magic" 0xD9B4BEF9l Consensus.mainnet.magic;
  Alcotest.(check int) "mainnet port" 8333 Consensus.mainnet.default_port;
  Alcotest.(check string) "mainnet bech32" "bc" Consensus.mainnet.bech32_hrp;
  Alcotest.(check int) "mainnet pubkey prefix" 0x00
    Consensus.mainnet.pubkey_address_prefix;
  Alcotest.(check bool) "mainnet no min difficulty" false
    Consensus.mainnet.pow_allow_min_difficulty;
  Alcotest.(check bool) "mainnet retargets" false
    Consensus.mainnet.pow_no_retargeting

let test_testnet_config () =
  Alcotest.(check string) "testnet name" "testnet3" Consensus.testnet.name;
  Alcotest.(check int32) "testnet magic" 0x0709110Bl Consensus.testnet.magic;
  Alcotest.(check int) "testnet port" 18333 Consensus.testnet.default_port;
  Alcotest.(check string) "testnet bech32" "tb" Consensus.testnet.bech32_hrp;
  Alcotest.(check bool) "testnet allows min difficulty" true
    Consensus.testnet.pow_allow_min_difficulty;
  Alcotest.(check bool) "testnet retargets" false
    Consensus.testnet.pow_no_retargeting

let test_regtest_config () =
  Alcotest.(check string) "regtest name" "regtest" Consensus.regtest.name;
  Alcotest.(check int32) "regtest magic" 0xDAB5BFFAl Consensus.regtest.magic;
  Alcotest.(check int) "regtest port" 18444 Consensus.regtest.default_port;
  Alcotest.(check string) "regtest bech32" "bcrt" Consensus.regtest.bech32_hrp;
  Alcotest.(check int) "regtest segwit height" 0 Consensus.regtest.segwit_height;
  Alcotest.(check bool) "regtest allows min difficulty" true
    Consensus.regtest.pow_allow_min_difficulty;
  Alcotest.(check bool) "regtest no retargeting" true
    Consensus.regtest.pow_no_retargeting

(* Test genesis block coinbase check *)
let test_genesis_coinbase () =
  let dummy_hash = Types.zero_hash in
  Alcotest.(check bool) "height 0 is genesis" true
    (Consensus.is_genesis_coinbase 0 dummy_hash);
  Alcotest.(check bool) "height 1 is not genesis" false
    (Consensus.is_genesis_coinbase 1 dummy_hash);
  Alcotest.(check bool) "height 100 is not genesis" false
    (Consensus.is_genesis_coinbase 100 dummy_hash)

(* Test compact target conversion *)
let test_compact_to_target () =
  (* Test mainnet initial difficulty: 0x1d00ffff *)
  let target = Consensus.compact_to_target 0x1d00ffffl in
  Alcotest.(check int) "target length" 32 (Cstruct.length target);
  (* The target should be 00000000FFFF0000...0000 (in big-endian display) *)
  (* In little-endian internal format, high bytes are at end *)
  (* Exponent 0x1d = 29, mantissa 0x00ffff *)
  (* Target = mantissa * 256^(exponent-3) = 0x00ffff * 256^26 *)
  ()

(* Test protocol version constants *)
let test_protocol_versions () =
  Alcotest.(check int32) "min peer version" 31800l Consensus.min_peer_proto_version;
  Alcotest.(check int32) "sendheaders version" 70012l Consensus.sendheaders_version;
  Alcotest.(check int32) "feefilter version" 70013l Consensus.feefilter_version;
  Alcotest.(check int32) "wtxid relay version" 70016l Consensus.wtxid_relay_version

let () =
  let open Alcotest in
  run "Consensus" [
    "block_subsidy", [
      test_case "block subsidy calculation" `Quick test_block_subsidy;
    ];
    "constants", [
      test_case "consensus constants" `Quick test_consensus_constants;
      test_case "protocol versions" `Quick test_protocol_versions;
    ];
    "validation", [
      test_case "valid money" `Quick test_valid_money;
      test_case "difficulty adjustment height" `Quick test_difficulty_adjustment_height;
      test_case "genesis coinbase" `Quick test_genesis_coinbase;
    ];
    "time", [
      test_case "median time past" `Quick test_median_time_past;
    ];
    "encoding", [
      test_case "encode height in coinbase" `Quick test_encode_height_in_coinbase;
      test_case "compact to target" `Quick test_compact_to_target;
    ];
    "network_config", [
      test_case "mainnet config" `Quick test_mainnet_config;
      test_case "testnet config" `Quick test_testnet_config;
      test_case "regtest config" `Quick test_regtest_config;
    ];
  ]
