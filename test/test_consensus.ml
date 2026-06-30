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
  Alcotest.(check int) "default halving interval" 210_000 Consensus.default_halving_interval

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

(* W2 Finding 2 EFFECTIVE test: median_time_past must sort timestamps as UNSIGNED
   uint32.  A timestamp of 0x80000000l (= 2^31 = year 2038 boundary) is negative
   in OCaml's signed int32, so a signed sort would place it before all positive
   values.  In unsigned order it is the largest of any current timestamp.

   Pre-fix (signed Int32.compare): sorted [1l; 0x80000000l] → [0x80000000l; 1l]
     → median at index 1 = 1l (wrong: treats year-2038 block as "before" year 1970).
   Post-fix (unsigned compare via Int64): sorted [1l; 0x80000000l] → [1l; 0x80000000l]
     → median at index 1 = 0x80000000l (correct).

   Reference: bitcoin-core/src/chain.h:233-244 (GetMedianTimePast sorts int64_t,
   because nTime is uint32_t widened to int64_t via GetBlockTime). *)
let test_median_time_past_unsigned_sort () =
  (* 2-element list: 1 (year 1970) and 0x80000000 (year 2038, negative as int32).
     Unsigned median = the larger of the two = 0x80000000. *)
  Alcotest.(check int32)
    "post-2038 timestamp sorts AFTER past timestamps (unsigned)"
    0x80000000l
    (Consensus.median_time_past [1l; 0x80000000l]);
  (* Prove direction: if signed sort were used the result would be 1l, not 0x80000000l.
     The assertion above would FAIL on the unfixed code (signed Int32.compare). *)
  (* 3-element: two past and one post-2038. Unsigned median = the middle (past value). *)
  Alcotest.(check int32)
    "mixed list median with post-2038 element"
    500_000_000l
    (Consensus.median_time_past [100_000_000l; 500_000_000l; 0x80000000l]);
  (* All timestamps > 0x7FFFFFFF (all post-2038, all negative in signed int32).
     Unsigned sort: 0x80000000 < 0xC0000000 < 0xFFFFFFFF. Median of 3 = 0xC0000000. *)
  Alcotest.(check int32)
    "all post-2038 timestamps: unsigned sort gives correct median"
    0xC0000000l
    (Consensus.median_time_past [0xFFFFFFFFl; 0x80000000l; 0xC0000000l])

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

(* ============================================================================
   BIP-94 Timewarp Rule Tests
   Reference: bitcoin-core/src/validation.cpp ContextualCheckBlockHeader:4097-4104
              consensus/consensus.h:35 (MAX_TIMEWARP=600)
   ============================================================================ *)

(* The timewarp rule fires ONLY on testnet4 (enforce_bip94=true) and ONLY at
   difficulty-adjustment boundaries (height % 2016 = 0). *)

let test_timewarp_not_enforced_mainnet () =
  (* Mainnet: enforce_bip94=false — rule never fires even at boundary *)
  let prev_time = 1_000_000l in
  let header_time = Int32.sub prev_time 1000l in  (* 1000s before parent — would fail on testnet4 *)
  Alcotest.(check bool) "mainnet no timewarp enforcement" true
    (Consensus.check_timewarp_rule
       ~height:2016
       ~header_time
       ~prev_block_time:prev_time
       ~network:Consensus.mainnet)

let test_timewarp_not_enforced_regtest () =
  (* Regtest: enforce_bip94=false — rule never fires *)
  let prev_time = 1_000_000l in
  let header_time = Int32.sub prev_time 1000l in
  Alcotest.(check bool) "regtest no timewarp enforcement" true
    (Consensus.check_timewarp_rule
       ~height:2016
       ~header_time
       ~prev_block_time:prev_time
       ~network:Consensus.regtest)

let test_timewarp_non_boundary_testnet4 () =
  (* Testnet4 but NOT a retarget boundary — rule does not apply *)
  let prev_time = 1_000_000l in
  let header_time = Int32.sub prev_time 1000l in
  Alcotest.(check bool) "testnet4 non-boundary skipped" true
    (Consensus.check_timewarp_rule
       ~height:2017  (* not a multiple of 2016 *)
       ~header_time
       ~prev_block_time:prev_time
       ~network:Consensus.testnet4)

let test_timewarp_passes_at_boundary () =
  (* Testnet4 at boundary: header_time >= prev_block_time - 600 should pass *)
  let prev_time = 1_000_000l in
  (* Exactly at the limit: header_time = prev_time - 600 *)
  let header_time = Int32.sub prev_time 600l in
  Alcotest.(check bool) "testnet4 boundary exactly at limit passes" true
    (Consensus.check_timewarp_rule
       ~height:2016
       ~header_time
       ~prev_block_time:prev_time
       ~network:Consensus.testnet4)

let test_timewarp_passes_normal () =
  (* Testnet4 at boundary: normal forward-progressing timestamp passes *)
  let prev_time = 1_000_000l in
  let header_time = Int32.add prev_time 600l in  (* 10 min after parent *)
  Alcotest.(check bool) "testnet4 normal timestamp passes" true
    (Consensus.check_timewarp_rule
       ~height:2016
       ~header_time
       ~prev_block_time:prev_time
       ~network:Consensus.testnet4)

let test_timewarp_fails_over_limit () =
  (* Testnet4 at boundary: header_time < prev_block_time - 600 should fail *)
  let prev_time = 1_000_000l in
  let header_time = Int32.sub prev_time 601l in  (* 601s before parent — over MAX_TIMEWARP *)
  Alcotest.(check bool) "testnet4 boundary over limit fails" false
    (Consensus.check_timewarp_rule
       ~height:2016
       ~header_time
       ~prev_block_time:prev_time
       ~network:Consensus.testnet4)

let test_timewarp_boundary_detection () =
  (* Only height % 2016 = 0 is a boundary; verify adjacent heights *)
  let prev_time = 1_000_000l in
  let header_time = Int32.sub prev_time 700l in  (* Would fail if boundary checked *)
  (* height=2015: not a boundary → should pass *)
  Alcotest.(check bool) "h=2015 not boundary" true
    (Consensus.check_timewarp_rule ~height:2015
       ~header_time ~prev_block_time:prev_time ~network:Consensus.testnet4);
  (* height=2016: boundary → should fail *)
  Alcotest.(check bool) "h=2016 is boundary" false
    (Consensus.check_timewarp_rule ~height:2016
       ~header_time ~prev_block_time:prev_time ~network:Consensus.testnet4);
  (* height=2017: not a boundary → should pass *)
  Alcotest.(check bool) "h=2017 not boundary" true
    (Consensus.check_timewarp_rule ~height:2017
       ~header_time ~prev_block_time:prev_time ~network:Consensus.testnet4);
  (* height=4032: next boundary → should fail *)
  Alcotest.(check bool) "h=4032 is boundary" false
    (Consensus.check_timewarp_rule ~height:4032
       ~header_time ~prev_block_time:prev_time ~network:Consensus.testnet4)

(* ============================================================================
   BIP9 Version Bits Tests
   ============================================================================ *)

(* Test deployment state type *)
let test_deployment_state_strings () =
  Alcotest.(check string) "defined" "defined"
    (Consensus.string_of_deployment_state Consensus.Defined);
  Alcotest.(check string) "started" "started"
    (Consensus.string_of_deployment_state Consensus.Started);
  Alcotest.(check string) "locked_in" "locked_in"
    (Consensus.string_of_deployment_state Consensus.LockedIn);
  Alcotest.(check string) "active" "active"
    (Consensus.string_of_deployment_state Consensus.Active);
  Alcotest.(check string) "failed" "failed"
    (Consensus.string_of_deployment_state Consensus.Failed)

(* Test version bit signaling check *)
let test_version_signals_bit () =
  (* Valid versionbits signaling: top bits = 0x20000000 *)
  let base_version = 0x20000000l in

  (* Bit 0 signaling *)
  let v_bit0 = Int32.logor base_version 0x00000001l in
  Alcotest.(check bool) "bit 0 signals" true
    (Consensus.version_signals_bit v_bit0 0);
  Alcotest.(check bool) "bit 0 no signal for bit 1" false
    (Consensus.version_signals_bit v_bit0 1);

  (* Bit 2 signaling (Taproot uses bit 2) *)
  let v_bit2 = Int32.logor base_version 0x00000004l in
  Alcotest.(check bool) "bit 2 signals" true
    (Consensus.version_signals_bit v_bit2 2);
  Alcotest.(check bool) "bit 2 no signal for bit 0" false
    (Consensus.version_signals_bit v_bit2 0);

  (* Bit 28 signaling (testdummy uses bit 28) *)
  let v_bit28 = Int32.logor base_version 0x10000000l in
  Alcotest.(check bool) "bit 28 signals" true
    (Consensus.version_signals_bit v_bit28 28);

  (* Wrong top bits: must be 001xxxxx (0x20000000) *)
  let wrong_top = 0x10000001l in  (* 000... top bits *)
  Alcotest.(check bool) "wrong top bits no signal" false
    (Consensus.version_signals_bit wrong_top 0);

  (* Old-style version (< 0x20000000) should not signal *)
  Alcotest.(check bool) "old version no signal" false
    (Consensus.version_signals_bit 4l 0)

(* Test deployment mask computation *)
let test_deployment_mask () =
  let dep_bit0 : Consensus.deployment = {
    name = "test0"; bit = 0;
    start_time = 0L; timeout = 0L;
    min_activation_height = 0; period = 2016; threshold = 1815;
  } in
  Alcotest.(check int32) "bit 0 mask" 0x00000001l
    (Consensus.deployment_mask dep_bit0);

  let dep_bit2 : Consensus.deployment = {
    name = "test2"; bit = 2;
    start_time = 0L; timeout = 0L;
    min_activation_height = 0; period = 2016; threshold = 1815;
  } in
  Alcotest.(check int32) "bit 2 mask" 0x00000004l
    (Consensus.deployment_mask dep_bit2);

  let dep_bit28 : Consensus.deployment = {
    name = "test28"; bit = 28;
    start_time = 0L; timeout = 0L;
    min_activation_height = 0; period = 2016; threshold = 1815;
  } in
  Alcotest.(check int32) "bit 28 mask" 0x10000000l
    (Consensus.deployment_mask dep_bit28)

(* Test period start height calculation *)
let test_period_start_height () =
  let period = 2016 in
  Alcotest.(check int) "height 0" 0
    (Consensus.period_start_height 0 period);
  Alcotest.(check int) "height 100" 0
    (Consensus.period_start_height 100 period);
  Alcotest.(check int) "height 2015" 0
    (Consensus.period_start_height 2015 period);
  Alcotest.(check int) "height 2016" 2016
    (Consensus.period_start_height 2016 period);
  Alcotest.(check int) "height 2017" 2016
    (Consensus.period_start_height 2017 period);
  Alcotest.(check int) "height 4032" 4032
    (Consensus.period_start_height 4032 period)

(* Test always_active deployment *)
let test_always_active_deployment () =
  let dep : Consensus.deployment = {
    name = "always_active";
    bit = 0;
    start_time = Consensus.always_active;
    timeout = 0L;
    min_activation_height = 0;
    period = 2016;
    threshold = 1815;
  } in
  let cache = ref Consensus.DeploymentCache.empty in
  let get_block _ = None in
  let count_signals ~start_height:_ = 0 in

  let state = Consensus.get_deployment_state
    ~dep ~height:0 ~get_block ~count_signals ~cache in
  Alcotest.(check bool) "always active at height 0" true
    (state = Consensus.Active);

  let state2 = Consensus.get_deployment_state
    ~dep ~height:100000 ~get_block ~count_signals ~cache in
  Alcotest.(check bool) "always active at height 100000" true
    (state2 = Consensus.Active)

(* Test never_active deployment *)
let test_never_active_deployment () =
  let dep : Consensus.deployment = {
    name = "never_active";
    bit = 0;
    start_time = Consensus.never_active;
    timeout = 0L;
    min_activation_height = 0;
    period = 2016;
    threshold = 1815;
  } in
  let cache = ref Consensus.DeploymentCache.empty in
  let get_block _ = None in
  let count_signals ~start_height:_ = 0 in

  let state = Consensus.get_deployment_state
    ~dep ~height:0 ~get_block ~count_signals ~cache in
  Alcotest.(check bool) "never active at height 0" true
    (state = Consensus.Failed);

  let state2 = Consensus.get_deployment_state
    ~dep ~height:100000 ~get_block ~count_signals ~cache in
  Alcotest.(check bool) "never active at height 100000" true
    (state2 = Consensus.Failed)

(* Test state transitions: Defined -> Started -> LockedIn -> Active

   Bitcoin Core versionbits.cpp:GetStateFor uses the MTP of the last block of
   the *previous* period (= the anchor, period_start - 1) to drive state
   transitions.  Chain layout for this test:

   Period 0 (blocks 0-2015): anchor = block -1 (before genesis) → Defined
     Blocks 0-2015 have MTP < start_time (irrelevant — anchor is genesis parent)
   Period 1 (blocks 2016-4031): anchor = block 2015, MTP >= start_time → Started
     No signals in period 1.
   Period 2 (blocks 4032-6047): anchor = block 4031, MTP >= start_time, signals → LockedIn
     Signals in period 2 (start_height=4032): 2016 >= threshold.
   Period 3 (blocks 6048-8063): anchor = block 6047.  LockedIn.
     period_start=6048 >= min_activation_height=0 → Active.
*)
let test_full_activation_cycle () =
  let period = 2016 in
  let threshold = 1815 in  (* 90% of 2016 *)
  let start_time = 1000000L in
  let timeout = 2000000L in

  let dep : Consensus.deployment = {
    name = "test_activation";
    bit = 0;
    start_time;
    timeout;
    min_activation_height = 0;
    period;
    threshold;
  } in

  (* Key: the anchor for a period is period_start - 1.
     - Anchor for period 0 = -1 (genesis parent, get_block returns None → Defined)
     - Anchor for period 1 = 2015 → must have MTP >= start_time
     - Anchor for period 2 = 4031 → must have MTP >= start_time
     - Anchor for period 3 = 6047 → must have MTP >= start_time
     Block 2015 is the boundary: heights < 2015 have MTP < start_time,
     heights >= 2015 have MTP >= start_time. *)
  let make_block height =
    let mtp =
      if height < 2015 then 500000L    (* Before start_time *)
      else 1500000L                     (* After start_time — covers all anchors *)
    in
    Some { Consensus.height; version = 0x20000000l; median_time_past = mtp }
  in

  (* count_signals is called with the start_height of the period being evaluated
     when the state machine is in Started.  We signal in period 2 (start_height=4032)
     to trigger LockedIn. *)
  let count_signals ~start_height =
    if start_height = 4032 then 2016  (* All blocks in period 2 signal *)
    else 0
  in

  let cache = ref Consensus.DeploymentCache.empty in

  (* Test state at various heights *)
  let get_state height =
    Consensus.get_deployment_state
      ~dep ~height ~get_block:make_block ~count_signals ~cache
  in

  (* Period 0: Defined — anchor is genesis parent (height -1), no block → Defined *)
  Alcotest.(check bool) "period 0 is defined" true
    (get_state 1000 = Consensus.Defined);

  (* Period 1 (2016-4031): anchor = block 2015, MTP=1500000L >= start_time → Started *)
  Alcotest.(check bool) "period 1 is started" true
    (get_state 3000 = Consensus.Started);

  (* Period 2 (4032-6047): Started + signals(4032)=2016 >= 1815 → LockedIn *)
  Alcotest.(check bool) "period 2 is locked_in" true
    (get_state 5000 = Consensus.LockedIn);

  (* Period 3 (6048-8063): LockedIn + period_start=6048 >= min_activation_height=0 → Active *)
  Alcotest.(check bool) "period 3 is active" true
    (get_state 7000 = Consensus.Active)

(* Test timeout -> Failed transition

   Anchor layout (period_start - 1):
   - Anchor for period 1 = block 2015 → MTP >= start_time, MTP < timeout → Started
   - Anchor for period 2 = block 4031 → MTP >= start_time, MTP < timeout → Started (no threshold)
   - Anchor for period 3 = block 6047 → MTP >= timeout, no signals → Failed
*)
let test_timeout_to_failed () =
  let period = 2016 in
  let start_time = 1000000L in
  let timeout = 1500000L in

  let dep : Consensus.deployment = {
    name = "test_timeout";
    bit = 0;
    start_time;
    timeout;
    min_activation_height = 0;
    period;
    threshold = 1815;
  } in

  (* Anchor for period 1 (= block 2015): MTP=1200000L >= start_time, < timeout → Started.
     Anchor for period 2 (= block 4031): MTP=1200000L >= start_time, < timeout → still Started
       (count=0 < threshold, MTP < timeout).
     Anchor for period 3 (= block 6047): MTP=1600000L >= timeout, count=0 → Failed. *)
  let make_block height =
    let mtp =
      if height < 2015 then 500000L       (* Before start *)
      else if height < 6047 then 1200000L (* After start, before timeout *)
      else 1600000L                        (* At/after timeout *)
    in
    Some { Consensus.height; version = 0x20000000l; median_time_past = mtp }
  in

  let count_signals ~start_height:_ = 0 in
  let cache = ref Consensus.DeploymentCache.empty in

  let get_state height =
    Consensus.get_deployment_state
      ~dep ~height ~get_block:make_block ~count_signals ~cache
  in

  (* Period 1 (2016-4031): anchor=2015, MTP=1200000L >= start_time → Started *)
  Alcotest.(check bool) "period 1 is started" true
    (get_state 3000 = Consensus.Started);

  (* Period 3 (6048-8063): anchor=6047, MTP=1600000L >= timeout, count=0 → Failed *)
  Alcotest.(check bool) "after timeout is failed" true
    (get_state 7000 = Consensus.Failed)

(* Test min_activation_height delays Active state

   Core versionbits.cpp:102: LOCKED_IN → ACTIVE when
   `pindexPrev->nHeight + 1 >= min_activation_height`, i.e. period_start >= mah.

   Anchor layout (period_start - 1):
   - Anchor for period 0 = -1 (genesis parent) → Defined
   - Anchor for period 1 = 2015 → MTP >= start_time → Started
   - Anchor for period 2 = 4031 → state=Started, signals(4032)=2016 → LockedIn
   - Period 3 (6048): period_start=6048 < 10000 → LockedIn
   - Period 4 (8064): period_start=8064 < 10000 → LockedIn
   - Period 5 (10080): period_start=10080 >= 10000 → Active   ← Core correct behaviour
*)
let test_min_activation_height () =
  let period = 2016 in
  let start_time = 1000000L in

  let dep : Consensus.deployment = {
    name = "test_min_height";
    bit = 0;
    start_time;
    timeout = 9999999999L;  (* Far future *)
    min_activation_height = 10000;  (* Must wait until period_start >= 10000 *)
    period;
    threshold = 1815;
  } in

  (* Anchor for period 1 = block 2015; must have MTP >= start_time.
     Block 2015 needs MTP=1500000L; heights < 2015 are MTP < start_time
     (the anchor for period 0 is genesis parent = None → Defined). *)
  let make_block height =
    let mtp = if height < 2015 then 500000L else 1500000L in
    Some { Consensus.height; version = 0x20000000l; median_time_past = mtp }
  in

  (* With the corrected anchor-based MTP check:
     - period_start=2016 is Started (anchor 2015 MTP >= start_time)
     - period_start=4032 is in Started state; count_signals(4032)=2016 → LockedIn
     - period_start=6048..8064: LockedIn (period_start < 10000)
     - period_start=10080: Active (10080 >= 10000)
     Signals only need to fire in period 4032 (the Started period) to lock in. *)
  let count_signals ~start_height =
    if start_height = 4032 then 2016  (* All blocks in period 2 signal → LockedIn *)
    else 0
  in

  let cache = ref Consensus.DeploymentCache.empty in

  let get_state height =
    Consensus.get_deployment_state
      ~dep ~height ~get_block:make_block ~count_signals ~cache
  in

  (* Period 3 (6048-8063): LockedIn — period_start=6048 < min_activation_height=10000 *)
  Alcotest.(check bool) "before min_height is locked_in" true
    (get_state 7000 = Consensus.LockedIn);

  (* Period 4 (8064-10079): still LockedIn — period_start=8064 < 10000 *)
  Alcotest.(check bool) "period 4 still locked_in" true
    (get_state 9000 = Consensus.LockedIn);

  (* Period 5 (10080-12095): Active — period_start=10080 >= 10000.
     Core: `pindexPrev->nHeight + 1 = period_start >= min_activation_height`. *)
  Alcotest.(check bool) "after min_height is active" true
    (get_state 11000 = Consensus.Active)

(* Test BIP9 statistics *)
let test_bip9_stats () =
  let dep : Consensus.deployment = {
    name = "test_stats";
    bit = 0;
    start_time = 0L;
    timeout = 999999999L;
    min_activation_height = 0;
    period = 2016;
    threshold = 1815;
  } in

  (* Create blocks where some signal and some don't *)
  let make_block height =
    let version =
      if height mod 2 = 0 then 0x20000001l  (* Even blocks signal *)
      else 0x20000000l                       (* Odd blocks don't *)
    in
    Some { Consensus.height; version; median_time_past = 1000000L }
  in

  (* At height 100 in period 0 *)
  let stats = Consensus.get_bip9_stats
    ~dep ~height:100 ~get_block:make_block in

  Alcotest.(check int) "period is 2016" 2016 stats.period_length;
  Alcotest.(check int) "threshold is 1815" 1815 stats.threshold_count;
  Alcotest.(check int) "elapsed is 101" 101 stats.elapsed;
  (* Even heights 0-100 = 51 signaling blocks *)
  Alcotest.(check int) "signaling count" 51 stats.signaling_count;
  (* With 1915 remaining blocks and 51 signals, 51 + 1915 = 1966 >= 1815 *)
  Alcotest.(check bool) "still possible" true stats.possible

(* Test cache clearing *)
let test_versionbits_cache () =
  let cache = Consensus.create_versionbits_cache () in

  (* Add some data *)
  cache.taproot := Consensus.DeploymentCache.add 0 Consensus.Started !(cache.taproot);
  cache.testdummy := Consensus.DeploymentCache.add 0 Consensus.Defined !(cache.testdummy);

  Alcotest.(check bool) "cache not empty" true
    (not (Consensus.DeploymentCache.is_empty !(cache.taproot)));

  (* Clear cache *)
  Consensus.clear_versionbits_cache cache;

  Alcotest.(check bool) "cache empty after clear" true
    (Consensus.DeploymentCache.is_empty !(cache.taproot));
  Alcotest.(check bool) "testdummy cache empty" true
    (Consensus.DeploymentCache.is_empty !(cache.testdummy))

(* Test that LockedIn→Active fires at the correct period when
   min_activation_height is an exact period multiple.

   Taproot on mainnet: min_activation_height=709632, period=2016.
   709632 / 2016 = 352 exactly → period starting at 709632.

   Core: activates when period_start >= 709632.
   - period_start=707616 (period 351): 707616 >= 709632? No → LockedIn.
   - period_start=709632 (period 352): 709632 >= 709632? Yes → Active.

   Old buggy code checked (period_start + period) >= mah:
   - period_start=707616: (707616+2016)=709632 >= 709632? Yes → Active (WRONG — one period early).
*)
let test_locked_in_exact_period_boundary () =
  let period = 2016 in
  let min_activation_height = 709632 in  (* Taproot activation height: exact period boundary *)

  let dep : Consensus.deployment = {
    name = "taproot_boundary";
    bit = 2;
    start_time = 1000000L;
    timeout = 9999999999L;
    min_activation_height;
    period;
    threshold = 1815;
  } in

  (* Chain: blocks >= 2015 have MTP >= start_time.
     We pre-seed the cache with LockedIn at a period well before the boundary
     to skip the full DEFINED→STARTED→LOCKED_IN walk. *)
  let make_block height =
    let mtp = if height < 2015 then 500000L else 1500000L in
    Some { Consensus.height; version = 0x20000000l; median_time_past = mtp }
  in
  let count_signals ~start_height:_ = 0 in

  (* Pre-seed: inject LockedIn at period 705600 (= 350 * 2016) to avoid
     walking the full mainnet chain.  The state machine just reads forward
     from there. *)
  let cache = ref (Consensus.DeploymentCache.add 705600 Consensus.LockedIn
                     Consensus.DeploymentCache.empty) in

  let get_state height =
    Consensus.get_deployment_state
      ~dep ~height ~get_block:make_block ~count_signals ~cache
  in

  (* Period 351 (707616..709631): period_start=707616 < 709632 → LockedIn *)
  Alcotest.(check bool) "period before boundary is still locked_in" true
    (get_state 708000 = Consensus.LockedIn);

  (* Period 352 (709632..711647): period_start=709632 >= 709632 → Active.
     Core ref: versionbits.cpp:102 `pindexPrev->nHeight + 1 >= min_activation_height`. *)
  Alcotest.(check bool) "period at exact boundary activates" true
    (get_state 710000 = Consensus.Active)

(* Test that period 0 (anchor = genesis parent) is always Defined.
   Verifies the genesis-boundary edge case: get_block(-1) must return None
   and the None branch must inherit Defined, not crash. *)
let test_genesis_period_is_defined () =
  let dep : Consensus.deployment = {
    name = "genesis_test";
    bit = 0;
    start_time = 0L;  (* start_time=0 so MTP=0 would satisfy it *)
    timeout = 9999999999L;
    min_activation_height = 0;
    period = 2016;
    threshold = 1815;
  } in
  (* Even though start_time=0, the anchor for period 0 is height -1 (before
     genesis), which get_block returns None for.  State must be Defined. *)
  let make_block h =
    if h < 0 then None
    else Some { Consensus.height = h; version = 0x20000000l; median_time_past = 0L }
  in
  let count_signals ~start_height:_ = 0 in
  let cache = ref Consensus.DeploymentCache.empty in
  let state = Consensus.get_deployment_state
    ~dep ~height:0 ~get_block:make_block ~count_signals ~cache in
  Alcotest.(check bool) "genesis period is Defined despite start_time=0" true
    (state = Consensus.Defined)

(* Test mainnet taproot deployment parameters *)
let test_mainnet_taproot () =
  let dep = Consensus.mainnet_taproot in
  Alcotest.(check string) "name" "taproot" dep.name;
  Alcotest.(check int) "bit" 2 dep.bit;
  Alcotest.(check int) "min_activation_height" 709632 dep.min_activation_height;
  Alcotest.(check int) "period" 2016 dep.period;
  Alcotest.(check int) "threshold" 1815 dep.threshold

(* Test testnet4 taproot is always active *)
let test_testnet4_taproot () =
  let dep = Consensus.testnet4_taproot in
  Alcotest.(check int64) "start_time is always_active" Consensus.always_active dep.start_time;

  let cache = ref Consensus.DeploymentCache.empty in
  let state = Consensus.get_deployment_state
    ~dep ~height:0
    ~get_block:(fun _ -> None)
    ~count_signals:(fun ~start_height:_ -> 0)
    ~cache
  in
  Alcotest.(check bool) "testnet4 taproot active at genesis" true
    (state = Consensus.Active)

(* ============================================================================
   Checkpoint Verification Tests
   ============================================================================ *)

(* Test checkpoint verification at checkpoint height with correct hash *)
let test_checkpoint_ok () =
  (* Mainnet checkpoint at height 11111 *)
  let height = 11111 in
  let expected_hash = Types.hash256_of_hex
    "1d7c6eb2fd42f55925e92efad68b61edd22fba29fde8783df744e26900000000" in
  let result = Consensus.verify_checkpoint height expected_hash Consensus.mainnet in
  Alcotest.(check bool) "checkpoint matches" true
    (result = Consensus.CheckpointOk)

(* Test checkpoint verification at checkpoint height with wrong hash *)
let test_checkpoint_mismatch () =
  (* Mainnet checkpoint at height 11111, but with wrong hash *)
  let height = 11111 in
  let wrong_hash = Types.hash256_of_hex
    "0000000000000000000000000000000000000000000000000000000000000001" in
  let result = Consensus.verify_checkpoint height wrong_hash Consensus.mainnet in
  match result with
  | Consensus.CheckpointMismatch { height = h; _ } ->
    Alcotest.(check int) "mismatch at correct height" 11111 h
  | Consensus.CheckpointOk ->
    Alcotest.fail "expected checkpoint mismatch"

(* Test checkpoint verification at non-checkpoint height *)
let test_checkpoint_non_checkpoint_height () =
  let height = 12345 in  (* Not a checkpoint height *)
  let any_hash = Types.hash256_of_hex
    "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef" in
  let result = Consensus.verify_checkpoint height any_hash Consensus.mainnet in
  Alcotest.(check bool) "non-checkpoint height is ok" true
    (result = Consensus.CheckpointOk)

(* Test checkpoint result to string *)
let test_checkpoint_result_to_string () =
  let ok_str = Consensus.checkpoint_result_to_string Consensus.CheckpointOk in
  Alcotest.(check string) "ok string" "ok" ok_str;

  let expected = Types.hash256_of_hex
    "1d7c6eb2fd42f55925e92efad68b61edd22fba29fde8783df744e26900000000" in
  let actual = Types.hash256_of_hex
    "0000000000000000000000000000000000000000000000000000000000000001" in
  let mismatch = Consensus.CheckpointMismatch { height = 11111; expected; actual } in
  let mismatch_str = Consensus.checkpoint_result_to_string mismatch in
  Alcotest.(check bool) "mismatch string contains height" true
    (String.length mismatch_str > 0 &&
     String.sub mismatch_str 0 10 = "checkpoint")

(* Test get_checkpoint_hash for mainnet checkpoints *)
let test_get_checkpoint_hash () =
  (* Test that all mainnet checkpoints are retrievable *)
  let test_heights = [11111; 33333; 74000; 105000; 134444; 168000; 193000;
                      210000; 216116; 225430; 250000; 279000; 295000] in
  List.iter (fun h ->
    match Consensus.get_checkpoint_hash h Consensus.mainnet with
    | Some _ -> ()
    | None -> Alcotest.fail (Printf.sprintf "missing checkpoint at height %d" h)
  ) test_heights;

  (* Test non-checkpoint height returns None *)
  Alcotest.(check bool) "no checkpoint at 12345" true
    (Consensus.get_checkpoint_hash 12345 Consensus.mainnet = None)

(* Test minimum chain work verification *)
let test_meets_minimum_chain_work () =
  (* Zero work should not meet mainnet minimum *)
  let zero = Consensus.zero_work in
  Alcotest.(check bool) "zero work < minimum" false
    (Consensus.meets_minimum_chain_work zero Consensus.mainnet);

  (* Regtest has zero minimum, so zero work should meet it *)
  Alcotest.(check bool) "zero work meets regtest minimum" true
    (Consensus.meets_minimum_chain_work zero Consensus.regtest);

  (* Large work should meet mainnet minimum *)
  let large_work = Consensus.work_of_hex
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" in
  Alcotest.(check bool) "large work >= minimum" true
    (Consensus.meets_minimum_chain_work large_work Consensus.mainnet)

(* Test should_skip_scripts for assume_valid *)
let test_should_skip_scripts () =
  (* Without assume_valid height, should not skip *)
  Alcotest.(check bool) "no assume_valid height" false
    (Consensus.should_skip_scripts ~block_height:100
       ~assume_valid_height:None ~network:Consensus.mainnet);

  (* Block below assume_valid height should skip *)
  Alcotest.(check bool) "below assume_valid height" true
    (Consensus.should_skip_scripts ~block_height:100
       ~assume_valid_height:(Some 200) ~network:Consensus.mainnet);

  (* Block at assume_valid height should skip *)
  Alcotest.(check bool) "at assume_valid height" true
    (Consensus.should_skip_scripts ~block_height:200
       ~assume_valid_height:(Some 200) ~network:Consensus.mainnet);

  (* Block above assume_valid height should not skip *)
  Alcotest.(check bool) "above assume_valid height" false
    (Consensus.should_skip_scripts ~block_height:300
       ~assume_valid_height:(Some 200) ~network:Consensus.mainnet);

  (* Network without assume_valid_hash should not skip *)
  Alcotest.(check bool) "no assume_valid_hash" false
    (Consensus.should_skip_scripts ~block_height:100
       ~assume_valid_height:(Some 200) ~network:Consensus.regtest)

(* Test mainnet has assume_valid configured *)
let test_mainnet_assume_valid () =
  Alcotest.(check bool) "mainnet has assume_valid" true
    (Consensus.mainnet.assume_valid_hash <> None);
  Alcotest.(check bool) "regtest has no assume_valid" true
    (Consensus.regtest.assume_valid_hash = None)

(* Test mainnet has checkpoints *)
let test_mainnet_checkpoints () =
  Alcotest.(check bool) "mainnet has checkpoints" true
    (List.length Consensus.mainnet.checkpoints > 0);
  Alcotest.(check int) "mainnet has 13 checkpoints" 13
    (List.length Consensus.mainnet.checkpoints);
  Alcotest.(check bool) "testnet has no checkpoints" true
    (List.length Consensus.testnet.checkpoints = 0);
  Alcotest.(check bool) "regtest has no checkpoints" true
    (List.length Consensus.regtest.checkpoints = 0)

(* ============================================================================
   W83 — GetNextWorkRequired + PoW audit tests
   ============================================================================ *)

(* Test Core's CalculateNextWorkRequired with the exact vectors from
   bitcoin-core/src/test/pow_tests.cpp. *)

(* pow_tests.cpp: get_next_work — no constraint, normal retarget
   nLastRetargetTime=1261130161 (block #30240)
   pindexLast: nHeight=32255, nTime=1262152739, nBits=0x1d00ffff
   expected: 0x1d00d86a *)
let test_core_vector_get_next_work () =
  let first_time = 1261130161l in
  let last_time  = 1262152739l in
  let bits       = 0x1d00ffffl in
  let expected   = 0x1d00d86al in
  let got = Consensus.calculate_next_work_required
    ~first_block_time:first_time
    ~last_block_time:last_time
    ~base_bits:bits
    ~network:Consensus.mainnet
  in
  Alcotest.(check int32) "Core vector: get_next_work" expected got

(* pow_tests.cpp: get_next_work_pow_limit — early chain, result clamped to pow_limit
   nLastRetargetTime=1231006505 (genesis)
   pindexLast: nHeight=2015, nTime=1233061996, nBits=0x1d00ffff
   expected: 0x1d00ffff (clamped to pow_limit) *)
let test_core_vector_pow_limit () =
  let first_time = 1231006505l in
  let last_time  = 1233061996l in
  let bits       = 0x1d00ffffl in
  let expected   = 0x1d00ffffl in
  let got = Consensus.calculate_next_work_required
    ~first_block_time:first_time
    ~last_block_time:last_time
    ~base_bits:bits
    ~network:Consensus.mainnet
  in
  Alcotest.(check int32) "Core vector: pow_limit" expected got

(* pow_tests.cpp: get_next_work_lower_limit_actual — fast blocks, clamped at min timespan
   nLastRetargetTime=1279008237 (block #66528)
   pindexLast: nHeight=68543, nTime=1279297671, nBits=0x1c05a3f4
   expected: 0x1c0168fd *)
let test_core_vector_lower_limit () =
  let first_time = 1279008237l in
  let last_time  = 1279297671l in
  let bits       = 0x1c05a3f4l in
  let expected   = 0x1c0168fdl in
  let got = Consensus.calculate_next_work_required
    ~first_block_time:first_time
    ~last_block_time:last_time
    ~base_bits:bits
    ~network:Consensus.mainnet
  in
  Alcotest.(check int32) "Core vector: lower_limit_actual" expected got

(* pow_tests.cpp: get_next_work_upper_limit_actual — slow blocks, clamped at max timespan
   nLastRetargetTime=1263163443
   pindexLast: nHeight=46367, nTime=1269211443, nBits=0x1c387f6f
   expected: 0x1d00e1fd *)
let test_core_vector_upper_limit () =
  let first_time = 1263163443l in
  let last_time  = 1269211443l in
  let bits       = 0x1c387f6fl in
  let expected   = 0x1d00e1fdl in
  let got = Consensus.calculate_next_work_required
    ~first_block_time:first_time
    ~last_block_time:last_time
    ~base_bits:bits
    ~network:Consensus.mainnet
  in
  Alcotest.(check int32) "Core vector: upper_limit_actual" expected got

(* Test compact_is_negative and compact_is_overflow *)
let test_compact_flags () =
  (* Normal bits: not negative, not overflow *)
  Alcotest.(check bool) "0x1d00ffff not negative" false
    (Consensus.compact_is_negative 0x1d00ffffl);
  Alcotest.(check bool) "0x1d00ffff not overflow" false
    (Consensus.compact_is_overflow 0x1d00ffffl);

  (* Negative bit set with non-zero mantissa *)
  (* 0x1d800001: sign bit set, mantissa=0x000001 -> fNegative=true *)
  Alcotest.(check bool) "0x1d800001 is negative" true
    (Consensus.compact_is_negative 0x1d800001l);
  Alcotest.(check bool) "0x1d800001 not overflow" false
    (Consensus.compact_is_overflow 0x1d800001l);

  (* Zero mantissa with sign bit: Core fNegative = false (nWord=0) *)
  (* 0x1d800000: sign bit set but mantissa=0 -> fNegative=false *)
  Alcotest.(check bool) "0x1d800000 not negative (zero mantissa)" false
    (Consensus.compact_is_negative 0x1d800000l);

  (* Overflow: nSize=35 (0x23), nWord=0x000001 -> fOverflow (nSize>34) *)
  Alcotest.(check bool) "nSize=35 is overflow" true
    (Consensus.compact_is_overflow (Int32.logor 0x23000000l 0x000001l));

  (* Core overflow rules (arith_uint256.cpp SetCompact):
       nSize > 34: always overflow
       nWord > 0xff && nSize > 33: overflow
       nWord > 0xffff && nSize > 32: overflow  *)

  (* Not overflow: nSize=33 (0x21), nWord=0x0000ff (<=0xff, 0x21 not >33) *)
  Alcotest.(check bool) "nSize=33 nWord=0xff not overflow" false
    (Consensus.compact_is_overflow (Int32.logor 0x21000000l 0x0000ffl));

  (* Not overflow: nSize=33 (0x21), nWord=0x000100 (>0xff BUT nSize=33 not >33) *)
  Alcotest.(check bool) "nSize=33 nWord=0x100 not overflow (nSize not >33)" false
    (Consensus.compact_is_overflow (Int32.logor 0x21000000l 0x000100l));

  (* Not overflow: nSize=33 (0x21), nWord=0x010000 (>0xffff BUT nSize=33 not >33, check >32 applies: 0x010000>0xffff && 33>32 = true) *)
  (* Wait: nWord=0x010000 > 0xffff = true, nSize=33 > 32 = true -> overflow *)
  Alcotest.(check bool) "nSize=33 nWord=0x10000 is overflow (>0xffff && nSize>32)" true
    (Consensus.compact_is_overflow (Int32.logor 0x21000000l 0x010000l));

  (* Overflow: nSize=34 (0x22), nWord=0x00ffff (nWord>0xff && nSize=34>33 -> overflow) *)
  Alcotest.(check bool) "nSize=34 nWord=0xffff is overflow (>0xff && nSize>33)" true
    (Consensus.compact_is_overflow (Int32.logor 0x22000000l 0x00ffffl));

  (* Not overflow: nSize=34 (0x22), nWord=0x0000ff (nWord not >0xff; nWord>0xffff is false) *)
  Alcotest.(check bool) "nSize=34 nWord=0xff not overflow (not >0xff)" false
    (Consensus.compact_is_overflow (Int32.logor 0x22000000l 0x0000ffl));

  (* Overflow: nSize=34 (0x22), nWord=0x010000 (>0xffff && nSize>32) *)
  Alcotest.(check bool) "nSize=34 nWord=0x10000 is overflow" true
    (Consensus.compact_is_overflow (Int32.logor 0x22000000l 0x010000l));

  (* Overflow: nSize=35 (0x23) -> always overflow (nSize>34) *)
  Alcotest.(check bool) "nSize=35 always overflow" true
    (Consensus.compact_is_overflow (Int32.logor 0x23000000l 0x000001l))

(* Test check_proof_of_work — mirrors Core's pow_tests.cpp *)
let test_check_proof_of_work () =
  let consensus = Consensus.mainnet in

  (* Negative target: pow_limit.GetCompact(true) → should fail.
     nBits = mainnet pow_limit bits with sign bit set.
     pow_limit = 0x1d00ffff → mantissa 0x00ffff, sign bit → 0x1d80ffff
     ... actually Core test uses: nBits = UintToArith256(consensus.powLimit).GetCompact(true)
     which forces fNegative=true. Simplest: use bits with sign bit set + non-zero mantissa. *)
  let negative_bits = 0x1d800001l in
  let hash_one = Cstruct.create 32 in
  Cstruct.set_uint8 hash_one 0 1;
  Alcotest.(check bool) "negative target rejected" false
    (Consensus.check_proof_of_work hash_one negative_bits consensus);

  (* Overflow target: nBits = ~0x00800000 (exponent=0xff, huge overflow).
     Core test: unsigned int nBits{~0x00800000U} which is 0xff7fffff.
     nSize=0xff=255 > 34 → overflow *)
  let overflow_bits = 0xff7fffffl in
  Alcotest.(check bool) "overflow target rejected" false
    (Consensus.check_proof_of_work hash_one overflow_bits consensus);

  (* Too-easy target: pow_limit * 2, should be rejected as above pow_limit *)
  let pow_limit_target = Consensus.compact_to_target consensus.pow_limit in
  let doubled = Consensus.target_multiply pow_limit_target 2 in
  let too_easy_bits = Consensus.target_to_compact (Cstruct.sub doubled 0 32) in
  Alcotest.(check bool) "too-easy target rejected" false
    (Consensus.check_proof_of_work hash_one too_easy_bits consensus);

  (* Zero target: nBits from zero value → rejected *)
  let zero_bits = 0x00000000l in
  Alcotest.(check bool) "zero target rejected" false
    (Consensus.check_proof_of_work hash_one zero_bits consensus);

  (* Valid: hash=0x01 with easy pow_limit bits — hash < target *)
  Alcotest.(check bool) "valid hash meets pow_limit" true
    (Consensus.check_proof_of_work hash_one consensus.pow_limit consensus);

  (* Invalid: hash > target (hash=pow_limit*2, target=pow_limit) *)
  let big_hash = Cstruct.create 32 in
  for i = 0 to 31 do
    Cstruct.set_uint8 big_hash i (Cstruct.get_uint8 pow_limit_target i)
  done;
  (* Set big_hash to pow_limit * 2 by shifting left *)
  let carry = ref 0 in
  for i = 0 to 31 do
    let v = Cstruct.get_uint8 big_hash i * 2 + !carry in
    Cstruct.set_uint8 big_hash i (v land 0xFF);
    carry := v lsr 8
  done;
  Alcotest.(check bool) "hash bigger than target rejected" false
    (Consensus.check_proof_of_work big_hash consensus.pow_limit consensus)

(* Test permitted_difficulty_transition — mirrors Core's pow_tests.cpp vectors *)
let test_permitted_difficulty_transition () =
  let consensus = Consensus.mainnet in

  (* Vector: get_next_work — height 32256, old=0x1d00ffff, expected=0x1d00d86a *)
  Alcotest.(check bool) "32256: 0x1d00ffff->0x1d00d86a permitted" true
    (Consensus.permitted_difficulty_transition ~network:consensus
       ~height:32256 ~old_nbits:0x1d00ffffl ~new_nbits:0x1d00d86al);

  (* Vector: get_next_work_pow_limit — height 2016, old=0x1d00ffff, expected=0x1d00ffff *)
  Alcotest.(check bool) "2016: 0x1d00ffff->0x1d00ffff permitted" true
    (Consensus.permitted_difficulty_transition ~network:consensus
       ~height:2016 ~old_nbits:0x1d00ffffl ~new_nbits:0x1d00ffffl);

  (* Vector: lower_limit_actual — height 68544, old=0x1c05a3f4, expected=0x1c0168fd *)
  Alcotest.(check bool) "68544: 0x1c05a3f4->0x1c0168fd permitted" true
    (Consensus.permitted_difficulty_transition ~network:consensus
       ~height:68544 ~old_nbits:0x1c05a3f4l ~new_nbits:0x1c0168fdl);

  (* Core test: reducing further from 0x1c0168fd should NOT be permitted *)
  Alcotest.(check bool) "68544: too-hard transition rejected" false
    (Consensus.permitted_difficulty_transition ~network:consensus
       ~height:68544 ~old_nbits:0x1c05a3f4l
       ~new_nbits:(Int32.sub 0x1c0168fdl 1l));

  (* Vector: upper_limit_actual — height 46368, old=0x1c387f6f, expected=0x1d00e1fd *)
  Alcotest.(check bool) "46368: 0x1c387f6f->0x1d00e1fd permitted" true
    (Consensus.permitted_difficulty_transition ~network:consensus
       ~height:46368 ~old_nbits:0x1c387f6fl ~new_nbits:0x1d00e1fdl);

  (* Core test: increasing further from 0x1d00e1fd should NOT be permitted *)
  Alcotest.(check bool) "46368: too-easy transition rejected" false
    (Consensus.permitted_difficulty_transition ~network:consensus
       ~height:46368 ~old_nbits:0x1c387f6fl
       ~new_nbits:(Int32.add 0x1d00e1fdl 1l));

  (* Non-adjustment block: bits must match exactly *)
  Alcotest.(check bool) "non-boundary: same bits permitted" true
    (Consensus.permitted_difficulty_transition ~network:consensus
       ~height:100 ~old_nbits:0x1c05a3f4l ~new_nbits:0x1c05a3f4l);
  Alcotest.(check bool) "non-boundary: different bits rejected" false
    (Consensus.permitted_difficulty_transition ~network:consensus
       ~height:100 ~old_nbits:0x1c05a3f4l ~new_nbits:0x1c05a3f5l);

  (* Testnet: always returns true regardless of transition *)
  Alcotest.(check bool) "testnet: any transition permitted" true
    (Consensus.permitted_difficulty_transition ~network:Consensus.testnet
       ~height:2016 ~old_nbits:0x1d00ffffl ~new_nbits:0x1c0000ffl);

  (* Regtest: always returns true *)
  Alcotest.(check bool) "regtest: any transition permitted" true
    (Consensus.permitted_difficulty_transition ~network:Consensus.regtest
       ~height:2016 ~old_nbits:0x207fffffl ~new_nbits:0x1d00ffffl)

(* ============================================================================
   Script-flag exception table tests (GetBlockScriptFlags)
   Bitcoin Core: src/validation.cpp GetBlockScriptFlags script_flag_exceptions
   ============================================================================ *)

(* Test that the mainnet BIP-16 exception block (height 170060) returns
   SCRIPT_VERIFY_NONE when the correct hash is passed, and normal P2SH-only
   flags for a non-exception hash at the same height.
   Canonical override: 0 (no flags at all, not even P2SH).
   display hash: 00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22 *)
let test_script_flag_exception_mainnet_bip16 () =
  let exception_hash = Types.hash256_of_hex
    "229c4fac88bab194eb08f1a528cc308ded2397f4f4eb6e75dc02000000000000" in
  (* With the exception hash: override fires → 0 (no flags) *)
  Alcotest.(check int) "mainnet BIP16 exception: override fires" 0
    (Consensus.get_block_script_flags ~block_hash:exception_hash 170060 Consensus.mainnet);
  (* With zero_hash (non-exception) at the same height: height-derived flags.
     Height 170060 is pre-DERSIG/CLTV/CSV/SegWit/Taproot, so only P2SH. *)
  let p2sh = Consensus.script_verify_p2sh in
  Alcotest.(check int) "mainnet height 170060 normal hash: P2SH only" p2sh
    (Consensus.get_block_script_flags ~block_hash:Types.zero_hash 170060 Consensus.mainnet)

(* Test that the mainnet Taproot exception block (height 692261) returns
   P2SH | WITNESS only when the correct hash is passed, and the full
   height-derived flags (which additionally include DERSIG/CLTV/CSV/NULLDUMMY)
   for a non-exception hash at the same height.
   Canonical override: script_verify_p2sh | script_verify_witness.
   display hash: 0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad *)
let test_script_flag_exception_mainnet_taproot () =
  let exception_hash = Types.hash256_of_hex
    "ad95e3a15ee5ffd585c5e81d44b56a981e842d5bc3140f000000000000000000" in
  let expected_override =
    Consensus.script_verify_p2sh lor Consensus.script_verify_witness in
  (* With the exception hash: override fires → P2SH | WITNESS (no taproot, no DERSIG etc.) *)
  Alcotest.(check int) "mainnet taproot exception: override fires" expected_override
    (Consensus.get_block_script_flags ~block_hash:exception_hash 692261 Consensus.mainnet);
  (* With zero_hash at the same height: normal flags include DERSIG, CLTV, CSV,
     WITNESS, NULLDUMMY (height 692261 is below taproot_height=709632). *)
  let normal_flags =
    Consensus.script_verify_p2sh
    lor Consensus.script_verify_dersig
    lor Consensus.script_verify_checklocktimeverify
    lor Consensus.script_verify_checksequenceverify
    lor Consensus.script_verify_witness
    lor Consensus.script_verify_nulldummy in
  Alcotest.(check int) "mainnet height 692261 normal hash: full pre-taproot flags" normal_flags
    (Consensus.get_block_script_flags ~block_hash:Types.zero_hash 692261 Consensus.mainnet)

(* Test that the testnet3 BIP-16 exception block (height 514) returns
   SCRIPT_VERIFY_NONE when the correct hash is passed, and normal flags for a
   non-exception hash at the same height.
   Canonical override: 0.
   display hash: 00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105 *)
let test_script_flag_exception_testnet3_bip16 () =
  let exception_hash = Types.hash256_of_hex
    "05b132a4f74a8799a57a4202d0eeb09612cc08d295401f007c4530dd00000000" in
  (* With exception hash: override fires → 0 (no flags) *)
  Alcotest.(check int) "testnet3 BIP16 exception: override fires" 0
    (Consensus.get_block_script_flags ~block_hash:exception_hash 514 Consensus.testnet);
  (* With zero_hash at same height on testnet3: height-derived flags.
     testnet3 bip66_height=330776, bip65_height=581885 — both > 514, so P2SH only. *)
  let p2sh = Consensus.script_verify_p2sh in
  Alcotest.(check int) "testnet3 height 514 normal hash: P2SH only" p2sh
    (Consensus.get_block_script_flags ~block_hash:Types.zero_hash 514 Consensus.testnet)

(* Test that testnet4/regtest have NO exception entries
   (exception table is empty for those networks).  We verify this by checking
   that passing the mainnet BIP16 exception hash gives the same result as
   zero_hash (i.e., the exception table is not consulted and the height-derived
   flags are returned in both cases). *)
let test_script_flag_exception_empty_on_other_nets () =
  let mainnet_hash = Types.hash256_of_hex
    "229c4fac88bab194eb08f1a528cc308ded2397f4f4eb6e75dc02000000000000" in
  (* testnet4 activates all softforks from height 1, so at height 170060 ALL
     flags are set.  The key assertion is that the exception does NOT fire
     (result == height-derived flags, not 0). *)
  let testnet4_normal =
    Consensus.get_block_script_flags ~block_hash:Types.zero_hash 170060 Consensus.testnet4 in
  Alcotest.(check int) "testnet4: mainnet hash does not trigger exception" testnet4_normal
    (Consensus.get_block_script_flags ~block_hash:mainnet_hash 170060 Consensus.testnet4);
  (* Also verify it's non-zero (i.e., we're not accidentally returning 0) *)
  Alcotest.(check bool) "testnet4: normal flags at height 170060 are non-zero" true
    (testnet4_normal <> 0);
  (* regtest: all softforks from genesis, so normal flags are also all flags *)
  let regtest_normal =
    Consensus.get_block_script_flags ~block_hash:Types.zero_hash 170060 Consensus.regtest in
  Alcotest.(check int) "regtest: mainnet hash does not trigger exception" regtest_normal
    (Consensus.get_block_script_flags ~block_hash:mainnet_hash 170060 Consensus.regtest)

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
      test_case "median time past unsigned sort (W2 Finding 2)" `Quick test_median_time_past_unsigned_sort;
    ];
    "timewarp_rule", [
      test_case "mainnet no enforcement" `Quick test_timewarp_not_enforced_mainnet;
      test_case "regtest no enforcement" `Quick test_timewarp_not_enforced_regtest;
      test_case "testnet4 non-boundary skipped" `Quick test_timewarp_non_boundary_testnet4;
      test_case "testnet4 passes at limit" `Quick test_timewarp_passes_at_boundary;
      test_case "testnet4 normal timestamp" `Quick test_timewarp_passes_normal;
      test_case "testnet4 over limit fails" `Quick test_timewarp_fails_over_limit;
      test_case "testnet4 boundary detection" `Quick test_timewarp_boundary_detection;
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
    "core_pow_vectors", [
      test_case "Core vector: get_next_work" `Quick test_core_vector_get_next_work;
      test_case "Core vector: pow_limit" `Quick test_core_vector_pow_limit;
      test_case "Core vector: lower_limit_actual" `Quick test_core_vector_lower_limit;
      test_case "Core vector: upper_limit_actual" `Quick test_core_vector_upper_limit;
    ];
    "compact_flags", [
      test_case "compact_is_negative / compact_is_overflow" `Quick test_compact_flags;
    ];
    "check_proof_of_work", [
      test_case "check_proof_of_work all cases" `Quick test_check_proof_of_work;
    ];
    "permitted_difficulty_transition", [
      test_case "permitted_difficulty_transition vectors" `Quick test_permitted_difficulty_transition;
    ];
    "bip9_versionbits", [
      test_case "deployment state strings" `Quick test_deployment_state_strings;
      test_case "version signals bit" `Quick test_version_signals_bit;
      test_case "deployment mask" `Quick test_deployment_mask;
      test_case "period start height" `Quick test_period_start_height;
      test_case "always active deployment" `Quick test_always_active_deployment;
      test_case "never active deployment" `Quick test_never_active_deployment;
      test_case "full activation cycle" `Quick test_full_activation_cycle;
      test_case "timeout to failed" `Quick test_timeout_to_failed;
      test_case "min activation height" `Quick test_min_activation_height;
      test_case "locked_in exact period boundary" `Quick test_locked_in_exact_period_boundary;
      test_case "genesis period is defined" `Quick test_genesis_period_is_defined;
      test_case "bip9 stats" `Quick test_bip9_stats;
      test_case "versionbits cache" `Quick test_versionbits_cache;
      test_case "mainnet taproot" `Quick test_mainnet_taproot;
      test_case "testnet4 taproot" `Quick test_testnet4_taproot;
    ];
    "checkpoint_verification", [
      test_case "checkpoint ok" `Quick test_checkpoint_ok;
      test_case "checkpoint mismatch" `Quick test_checkpoint_mismatch;
      test_case "non-checkpoint height" `Quick test_checkpoint_non_checkpoint_height;
      test_case "checkpoint result to string" `Quick test_checkpoint_result_to_string;
      test_case "get checkpoint hash" `Quick test_get_checkpoint_hash;
      test_case "meets minimum chain work" `Quick test_meets_minimum_chain_work;
      test_case "should skip scripts" `Quick test_should_skip_scripts;
      test_case "mainnet assume valid" `Quick test_mainnet_assume_valid;
      test_case "mainnet checkpoints" `Quick test_mainnet_checkpoints;
    ];
    "script_flag_exceptions", [
      test_case "mainnet BIP16 exception block" `Quick test_script_flag_exception_mainnet_bip16;
      test_case "mainnet taproot exception block" `Quick test_script_flag_exception_mainnet_taproot;
      test_case "testnet3 BIP16 exception block" `Quick test_script_flag_exception_testnet3_bip16;
      test_case "no exceptions on testnet4/regtest" `Quick test_script_flag_exception_empty_on_other_nets;
    ];
  ]
