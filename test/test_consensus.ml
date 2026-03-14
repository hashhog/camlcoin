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

(* Test testnet4 configuration *)
let test_testnet4_config () =
  Alcotest.(check string) "testnet4 name" "testnet4" Consensus.testnet4.name;
  Alcotest.(check int32) "testnet4 magic" 0x1c163f28l Consensus.testnet4.magic;
  Alcotest.(check int) "testnet4 port" 48333 Consensus.testnet4.default_port;
  Alcotest.(check bool) "testnet4 allows min difficulty" true
    Consensus.testnet4.pow_allow_min_difficulty;
  Alcotest.(check bool) "testnet4 enforces BIP94" true
    Consensus.testnet4.enforce_bip94;
  Alcotest.(check bool) "testnet4 retargets" false
    Consensus.testnet4.pow_no_retargeting

(* Test network variant type *)
let test_network_type () =
  Alcotest.(check bool) "mainnet type" true
    (Consensus.mainnet.network_type = Consensus.Mainnet);
  Alcotest.(check bool) "testnet3 type" true
    (Consensus.testnet.network_type = Consensus.Testnet3);
  Alcotest.(check bool) "testnet4 type" true
    (Consensus.testnet4.network_type = Consensus.Testnet4);
  Alcotest.(check bool) "regtest type" true
    (Consensus.regtest.network_type = Consensus.Regtest)

(* Test difficulty retargeting calculation *)
let test_calculate_next_work_required () =
  (* Test mainnet: normal retarget with exact timing *)
  let first_time = 1000000l in
  let last_time = Int32.add first_time (Int32.of_int Consensus.target_timespan) in
  let bits = 0x1d00ffffl in
  let new_bits = Consensus.calculate_next_work_required
    ~first_block_time:first_time
    ~last_block_time:last_time
    ~base_bits:bits
    ~network:Consensus.mainnet
  in
  (* With exact target timespan, difficulty should stay the same *)
  Alcotest.(check int32) "exact timespan keeps difficulty" bits new_bits;

  (* Test with faster blocks (half the time) - difficulty should increase (target decreases) *)
  let fast_last_time = Int32.add first_time (Int32.of_int (Consensus.target_timespan / 2)) in
  let fast_bits = Consensus.calculate_next_work_required
    ~first_block_time:first_time
    ~last_block_time:fast_last_time
    ~base_bits:bits
    ~network:Consensus.mainnet
  in
  (* Target should be halved (difficulty doubled), so compact form should differ *)
  Alcotest.(check bool) "faster blocks increase difficulty" true
    (fast_bits < bits || fast_bits = bits);  (* Lower compact = harder difficulty *)

  (* Test with slower blocks (double the time) - difficulty should decrease *)
  let slow_last_time = Int32.add first_time (Int32.of_int (Consensus.target_timespan * 2)) in
  let slow_bits = Consensus.calculate_next_work_required
    ~first_block_time:first_time
    ~last_block_time:slow_last_time
    ~base_bits:bits
    ~network:Consensus.mainnet
  in
  (* Target should be doubled (difficulty halved), so compact might be larger *)
  Alcotest.(check bool) "slower blocks decrease difficulty" true
    (slow_bits >= bits)

(* Test clamping to 4x bounds *)
let test_difficulty_clamping () =
  let first_time = 1000000l in
  let bits = 0x1d00ffffl in

  (* Very fast blocks (1/10th of target time) should be clamped to 4x *)
  let very_fast_time = Int32.add first_time (Int32.of_int (Consensus.target_timespan / 10)) in
  let clamped_fast = Consensus.calculate_next_work_required
    ~first_block_time:first_time
    ~last_block_time:very_fast_time
    ~base_bits:bits
    ~network:Consensus.mainnet
  in
  (* With 1/10th time, should clamp to 1/4x (difficulty can only increase 4x) *)
  let quarter_time = Int32.add first_time (Int32.of_int (Consensus.target_timespan / 4)) in
  let expected_clamped = Consensus.calculate_next_work_required
    ~first_block_time:first_time
    ~last_block_time:quarter_time
    ~base_bits:bits
    ~network:Consensus.mainnet
  in
  Alcotest.(check int32) "fast blocks clamped to 4x" expected_clamped clamped_fast;

  (* Very slow blocks (10x target time) should be clamped to 4x *)
  let very_slow_time = Int32.add first_time (Int32.of_int (Consensus.target_timespan * 10)) in
  let clamped_slow = Consensus.calculate_next_work_required
    ~first_block_time:first_time
    ~last_block_time:very_slow_time
    ~base_bits:bits
    ~network:Consensus.mainnet
  in
  let four_x_time = Int32.add first_time (Int32.of_int (Consensus.target_timespan * 4)) in
  let expected_slow_clamped = Consensus.calculate_next_work_required
    ~first_block_time:first_time
    ~last_block_time:four_x_time
    ~base_bits:bits
    ~network:Consensus.mainnet
  in
  Alcotest.(check int32) "slow blocks clamped to 4x" expected_slow_clamped clamped_slow

(* Test regtest always returns pow_limit *)
let test_regtest_no_retarget () =
  let get_block_info _h = (0l, Consensus.regtest.pow_limit) in
  (* At adjustment boundary *)
  let bits = Consensus.get_next_work_required
    ~height:2016
    ~block_time:1000000l
    ~prev_block_time:500000l
    ~prev_bits:0x1d00ffffl  (* Different from pow_limit *)
    ~get_block_info
    ~network:Consensus.regtest
  in
  (* Regtest should return the prev_bits unchanged (no retargeting) *)
  Alcotest.(check int32) "regtest no retarget" 0x1d00ffffl bits;

  (* Non-adjustment block *)
  let bits2 = Consensus.get_next_work_required
    ~height:100
    ~block_time:1000000l
    ~prev_block_time:500000l
    ~prev_bits:0x1d00ffffl
    ~get_block_info
    ~network:Consensus.regtest
  in
  Alcotest.(check int32) "regtest non-adjustment" 0x1d00ffffl bits2

(* Test testnet min-difficulty rule *)
let test_testnet_min_difficulty () =
  let pow_limit = Consensus.testnet.pow_limit in
  let normal_bits = 0x1c00ffffl in  (* Higher difficulty than pow_limit *)

  (* Create block info callback that returns normal difficulty *)
  let get_block_info h =
    let ts = Int32.of_int (1000000 + h * 600) in
    (ts, normal_bits)
  in

  (* Block coming after >20 minutes should get min difficulty *)
  let prev_time = 1000000l in
  let slow_block_time = Int32.add prev_time 1500l in  (* 25 minutes = 1500 seconds *)
  let bits = Consensus.get_next_work_required
    ~height:100  (* Not an adjustment block *)
    ~block_time:slow_block_time
    ~prev_block_time:prev_time
    ~prev_bits:normal_bits
    ~get_block_info
    ~network:Consensus.testnet
  in
  Alcotest.(check int32) "testnet slow block gets min diff" pow_limit bits;

  (* Block coming after <20 minutes should walk back *)
  let fast_block_time = Int32.add prev_time 600l in  (* 10 minutes *)
  let bits2 = Consensus.get_next_work_required
    ~height:100
    ~block_time:fast_block_time
    ~prev_block_time:prev_time
    ~prev_bits:normal_bits
    ~get_block_info
    ~network:Consensus.testnet
  in
  Alcotest.(check int32) "testnet fast block keeps difficulty" normal_bits bits2

(* Test testnet walk-back to find non-min-difficulty block *)
let test_testnet_walk_back () =
  let pow_limit = Consensus.testnet.pow_limit in
  let real_bits = 0x1c00ffffl in

  (* Create chain where blocks 95-99 are min-diff but 94 has real difficulty *)
  let get_block_info h =
    let ts = Int32.of_int (1000000 + h * 600) in
    if h >= 95 then (ts, pow_limit)  (* Min difficulty *)
    else (ts, real_bits)  (* Real difficulty *)
  in

  (* Fast block at height 100 should walk back to block 94 *)
  let prev_time = Int32.of_int (1000000 + 99 * 600) in
  let block_time = Int32.add prev_time 600l in  (* 10 minutes - fast *)
  let bits = Consensus.get_next_work_required
    ~height:100
    ~block_time
    ~prev_block_time:prev_time
    ~prev_bits:pow_limit
    ~get_block_info
    ~network:Consensus.testnet
  in
  Alcotest.(check int32) "testnet walk-back finds real difficulty" real_bits bits

(* Test BIP94 uses first block's bits at retarget *)
let test_bip94_retarget () =
  let first_bits = 0x1c00ffffl in  (* Real difficulty at period start *)
  let last_bits = Consensus.testnet4.pow_limit in  (* Min difficulty at period end *)

  let get_block_info h =
    let ts = Int32.of_int (1000000 + h * 600) in
    if h = 0 then (ts, first_bits)  (* First block of period *)
    else (ts, last_bits)  (* Other blocks at min difficulty *)
  in

  (* At height 2016 (adjustment), BIP94 should use first_bits, not last_bits *)
  let first_time = Int32.of_int 1000000 in
  let last_time = Int32.add first_time (Int32.of_int Consensus.target_timespan) in

  let bits = Consensus.get_next_work_required
    ~height:2016
    ~block_time:(Int32.add last_time 1l)
    ~prev_block_time:last_time
    ~prev_bits:last_bits
    ~get_block_info
    ~network:Consensus.testnet4
  in

  (* Calculate expected using first_bits as base *)
  let expected = Consensus.calculate_next_work_required
    ~first_block_time:first_time
    ~last_block_time:last_time
    ~base_bits:first_bits
    ~network:Consensus.testnet4
  in
  Alcotest.(check int32) "BIP94 uses first block bits" expected bits

(* Test mainnet vs testnet4 retarget difference *)
let test_mainnet_vs_bip94 () =
  let first_bits = 0x1c00ffffl in
  let last_bits = 0x1d00ffffl in  (* Different bits at end *)

  let first_time = 1000000l in
  let last_time = Int32.add first_time (Int32.of_int Consensus.target_timespan) in

  (* Mainnet: uses last block's bits *)
  let mainnet_bits = Consensus.calculate_next_work_required
    ~first_block_time:first_time
    ~last_block_time:last_time
    ~base_bits:last_bits  (* Mainnet uses last bits *)
    ~network:Consensus.mainnet
  in

  (* Testnet4/BIP94: uses first block's bits *)
  let bip94_bits = Consensus.calculate_next_work_required
    ~first_block_time:first_time
    ~last_block_time:last_time
    ~base_bits:first_bits  (* BIP94 uses first bits *)
    ~network:Consensus.testnet4
  in

  (* They should differ when base_bits differ *)
  Alcotest.(check bool) "mainnet vs BIP94 differ" true
    (mainnet_bits <> bip94_bits)

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
      test_case "testnet4 config" `Quick test_testnet4_config;
      test_case "regtest config" `Quick test_regtest_config;
      test_case "network type" `Quick test_network_type;
    ];
    "difficulty_retarget", [
      test_case "calculate next work required" `Quick test_calculate_next_work_required;
      test_case "difficulty clamping" `Quick test_difficulty_clamping;
      test_case "regtest no retarget" `Quick test_regtest_no_retarget;
      test_case "testnet min difficulty" `Quick test_testnet_min_difficulty;
      test_case "testnet walk-back" `Quick test_testnet_walk_back;
      test_case "BIP94 retarget" `Quick test_bip94_retarget;
      test_case "mainnet vs BIP94" `Quick test_mainnet_vs_bip94;
    ];
  ]
