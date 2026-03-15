(* Consensus-critical constants for Bitcoin protocol *)

(* Network variant type for selecting difficulty behavior *)
type network =
  | Mainnet
  | Testnet3
  | Testnet4
  | Regtest

(* Block weight limits (post-SegWit) *)
let max_block_weight = 4_000_000
let max_block_serialized_size = 4_000_000
let max_block_sigops_cost = 80_000

(* Monetary constants *)
let coin = 100_000_000L  (* 1 BTC = 100,000,000 satoshis *)
let max_money = 2_100_000_000_000_000L  (* 21 million BTC in satoshis *)
let coinbase_maturity = 100

(* Block timing *)
let target_block_time = 600  (* 10 minutes in seconds *)
let difficulty_adjustment_interval = 2016  (* blocks between adjustments *)
let target_timespan = 14 * 24 * 60 * 60  (* 2 weeks in seconds = 1,209,600 *)
let max_target_timespan = target_timespan * 4  (* 4x upper bound *)
let min_target_timespan = target_timespan / 4  (* 4x lower bound *)
let max_timewarp = 600  (* BIP-94: max seconds a retarget-boundary block can predate its parent *)

(* Witness limits *)
let witness_scale_factor = 4

(* Transaction limits *)
let max_tx_weight = max_block_weight  (* Consensus limit: base_size*4 <= MAX_BLOCK_WEIGHT *)
let max_standard_tx_weight = 400_000  (* Policy limit for relay/mempool *)
let max_tx_base_size_for_block = max_block_weight / witness_scale_factor
let min_tx_weight = 4 * 60  (* 240 weight units *)
let max_standard_tx_sigops_cost = 16_000
let max_script_size = 10_000
let max_script_element_size = 520
let max_ops_per_script = 201
let max_stack_size = 1000
let max_pubkeys_per_multisig = 20
let locktime_threshold = 500_000_000l  (* locktime < this = block height, >= = Unix time *)
let max_standard_p2wsh_script_size = 3600
let max_standard_p2wsh_stack_items = 100
let max_standard_p2wsh_stack_item_size = 80

(* Version bits for soft fork deployment (BIP-9) *)
let versionbits_top_mask = 0xE0000000l
let versionbits_top_bits = 0x20000000l
let versionbits_num_bits = 29

(* Minimum protocol versions for features *)
let min_peer_proto_version = 31800l
let bip0031_version = 60000l
let sendheaders_version = 70012l
let feefilter_version = 70013l
let short_ids_blocks_version = 70014l
let wtxid_relay_version = 70016l

(* Block subsidy halving *)
let halving_interval = 210_000

(* Calculate block subsidy (mining reward) for a given height *)
let block_subsidy (height : int) : int64 =
  let halvings = height / halving_interval in
  if halvings >= 64 then 0L
  else Int64.shift_right 5_000_000_000L halvings  (* 50 BTC initial *)

(* Compact target format (nBits) conversion to 256-bit target.

   The compact format is: bits[31:24] = exponent, bits[22:0] = mantissa
   Target = mantissa * 256^(exponent - 3)

   The result is stored in little-endian format (byte 0 = LSB, byte 31 = MSB).
   For regtest 0x207fffff: mantissa=0x7fffff, exp=32, target=0x7fffff * 256^29
   This puts bytes at indices 29, 30, 31 in little-endian storage. *)
let compact_to_target (bits : int32) : Cstruct.t =
  let bits_i = Int32.to_int bits in
  let exponent = (bits_i lsr 24) land 0xFF in
  let mantissa = bits_i land 0x7FFFFF in
  let target = Cstruct.create 32 in

  (* Negative bit set: return zero target *)
  if bits_i land 0x00800000 <> 0 then
    target
  (* Exponent overflow: return zero target *)
  else if exponent > 32 then
    target
  else if exponent = 0 || mantissa = 0 then
    target  (* Zero target *)
  else if exponent <= 3 then begin
    (* Small exponent: mantissa is shifted right *)
    let shift = 8 * (3 - exponent) in
    let m = mantissa lsr shift in
    (* Place at low bytes (little-endian, so at start of array) *)
    Cstruct.set_uint8 target 0 (m land 0xFF);
    if exponent >= 2 then
      Cstruct.set_uint8 target 1 ((m lsr 8) land 0xFF);
    if exponent >= 3 then
      Cstruct.set_uint8 target 2 ((m lsr 16) land 0xFF);
    target
  end else begin
    (* Normal case: mantissa shifted left by (exponent - 3) bytes *)
    (* In little-endian, byte position starts at (exponent - 3) *)
    let base_pos = exponent - 3 in
    (* Mantissa low byte at base_pos, high byte at base_pos + 2 *)
    if base_pos < 32 then
      Cstruct.set_uint8 target base_pos (mantissa land 0xFF);
    if base_pos + 1 < 32 then
      Cstruct.set_uint8 target (base_pos + 1) ((mantissa lsr 8) land 0xFF);
    if base_pos + 2 < 32 then
      Cstruct.set_uint8 target (base_pos + 2) ((mantissa lsr 16) land 0xFF);
    target
  end

(* Convert 256-bit target back to compact nBits format.
   Target is in little-endian: byte 0 = LSB, byte 31 = MSB. *)
let target_to_compact (target : Cstruct.t) : int32 =
  (* Find the highest non-zero byte (MSB position in little-endian) *)
  let rec find_msb_position i =
    if i < 0 then (-1)  (* All zeros *)
    else if Cstruct.get_uint8 target i <> 0 then i
    else find_msb_position (i - 1)
  in
  let msb_pos = find_msb_position 31 in
  if msb_pos < 0 then 0l  (* Zero target *)
  else begin
    (* Exponent is (position + 1), as that's the number of significant bytes *)
    let size = msb_pos + 1 in
    (* Extract 3-byte mantissa from highest bytes, reading high to low *)
    let mantissa =
      if size >= 3 then
        (Cstruct.get_uint8 target msb_pos lsl 16) lor
        (Cstruct.get_uint8 target (msb_pos - 1) lsl 8) lor
        Cstruct.get_uint8 target (msb_pos - 2)
      else if size = 2 then
        (Cstruct.get_uint8 target msb_pos lsl 16) lor
        (Cstruct.get_uint8 target (msb_pos - 1) lsl 8)
      else
        Cstruct.get_uint8 target msb_pos lsl 16
    in
    (* If MSB of mantissa is set, we need to shift to avoid sign confusion *)
    let mantissa, size =
      if mantissa land 0x800000 <> 0 then
        (mantissa lsr 8, size + 1)
      else
        (mantissa, size)
    in
    Int32.logor (Int32.shift_left (Int32.of_int size) 24)
                (Int32.of_int (mantissa land 0x7FFFFF))
  end

(* Check if a hash meets the target difficulty *)
let hash_meets_target (hash : Types.hash256) (bits : int32) : bool =
  let target = compact_to_target bits in
  (* Compare hash to target (both in internal little-endian format) *)
  (* Hash must be <= target. Compare from MSB (byte 31) to LSB (byte 0) *)
  let rec compare_bytes i =
    if i < 0 then true  (* Equal, meets target *)
    else begin
      let h = Cstruct.get_uint8 hash i in
      let t = Cstruct.get_uint8 target i in
      if h < t then true
      else if h > t then false
      else compare_bytes (i - 1)
    end
  in
  compare_bytes 31

(* Network configuration type *)
type network_config = {
  name : string;
  magic : int32;  (* Network magic bytes for P2P messages *)
  default_port : int;
  dns_seeds : string list;
  genesis_hash : Types.hash256;
  genesis_header : Types.block_header;
  pubkey_address_prefix : int;  (* Version byte for P2PKH addresses *)
  script_address_prefix : int;  (* Version byte for P2SH addresses *)
  wif_prefix : int;  (* Wallet Import Format prefix *)
  bech32_hrp : string;  (* Bech32 human-readable part *)
  bip34_height : int;  (* Height at which BIP34 activated *)
  bip65_height : int;  (* Height at which BIP65 (CLTV) activated *)
  bip66_height : int;  (* Height at which BIP66 (strict DER) activated *)
  csv_height : int;  (* Height at which BIP68/112/113 (CSV) activated *)
  segwit_height : int;  (* Height at which SegWit activated *)
  taproot_height : int;  (* Height at which Taproot activated *)
  pow_allow_min_difficulty : bool;  (* Allow min difficulty blocks (testnet) *)
  pow_no_retargeting : bool;  (* Skip difficulty retargeting (regtest) *)
  pow_limit : int32;  (* Compact nBits form of the maximum allowed target *)
  enforce_bip94 : bool;  (* BIP-94 time warp fix for testnet4 difficulty *)
  network_type : network;  (* Network variant for difficulty selection *)
  minimum_chain_work : Cstruct.t;  (* 32-byte LE; tip must reach this before block sync *)
  assume_valid_hash : Types.hash256 option;  (* Skip script verification at/below this block *)
  checkpoints : (int * Types.hash256) list;  (* Known-good block hashes at specific heights *)
}

(* Multiply a LE byte-array target by a positive int, producing a result
   that is (Cstruct.length target + 4) bytes long to hold overflow. *)
let target_multiply (target : Cstruct.t) (factor : int) : Cstruct.t =
  let len = Cstruct.length target in
  let result = Cstruct.create (len + 4) in
  let carry = ref 0 in
  for i = 0 to len - 1 do
    let v = (Cstruct.get_uint8 target i) * factor + !carry in
    Cstruct.set_uint8 result i (v land 0xFF);
    carry := v lsr 8
  done;
  (* Write remaining carry into the extra bytes *)
  let c = ref !carry in
  for i = len to len + 3 do
    Cstruct.set_uint8 result i (!c land 0xFF);
    c := !c lsr 8
  done;
  result

(* Divide a LE byte-array by a positive int, producing a result truncated
   to out_len bytes. Division proceeds from MSB to LSB (schoolbook). *)
let target_divide (target : Cstruct.t) (divisor : int) (out_len : int) : Cstruct.t =
  let len = Cstruct.length target in
  let result = Cstruct.create out_len in
  let remainder = ref 0 in
  for i = len - 1 downto 0 do
    let v = !remainder * 256 + Cstruct.get_uint8 target i in
    let q = v / divisor in
    remainder := v mod divisor;
    if i < out_len then
      Cstruct.set_uint8 result i q
  done;
  result

(* Compare two 32-byte LE numbers. Returns negative if a < b, 0 if equal,
   positive if a > b. Compares from MSB (byte 31) downward. *)
let target_compare (a : Cstruct.t) (b : Cstruct.t) : int =
  let rec cmp i =
    if i < 0 then 0
    else
      let av = Cstruct.get_uint8 a i in
      let bv = Cstruct.get_uint8 b i in
      if av <> bv then av - bv
      else cmp (i - 1)
  in
  cmp 31

(* Calculate next work required at difficulty adjustment boundary.
   This is CalculateNextWorkRequired from Bitcoin Core pow.cpp.

   Parameters:
   - first_block_time: timestamp of the first block in the difficulty period
   - last_block_time: timestamp of the last block before adjustment (pindexLast)
   - base_bits: bits to use as base for calculation:
     - For BIP94 (testnet4): bits from first block of period
     - Otherwise: bits from last block of period
   - network: network configuration

   Returns: new compact target (nBits) *)
let calculate_next_work_required ~(first_block_time : int32)
    ~(last_block_time : int32)
    ~(base_bits : int32)
    ~(network : network_config) : int32 =
  (* Regtest: no retargeting, return current bits *)
  if network.pow_no_retargeting then base_bits
  else begin
    (* Calculate actual time taken for the difficulty period *)
    let actual_timespan =
      Int32.to_int (Int32.sub last_block_time first_block_time) in
    (* Clamp to [target_timespan/4, target_timespan*4] *)
    let adjusted_timespan =
      min max_target_timespan (max min_target_timespan actual_timespan) in
    (* new_target = old_target * adjusted_timespan / target_timespan *)
    let old_target = compact_to_target base_bits in
    let product = target_multiply old_target adjusted_timespan in
    let new_target = target_divide product target_timespan 32 in
    (* Clamp to pow_limit *)
    let pow_limit_target = compact_to_target network.pow_limit in
    let clamped =
      if target_compare new_target pow_limit_target > 0 then pow_limit_target
      else new_target
    in
    target_to_compact clamped
  end

(* Get next work required for a block at given height.
   This is GetNextWorkRequired from Bitcoin Core pow.cpp.

   Parameters:
   - height: height of the block being mined (pindexLast->nHeight + 1)
   - block_time: timestamp of the block being mined
   - prev_block_time: timestamp of the previous block (pindexLast)
   - prev_bits: bits of the previous block (pindexLast->nBits)
   - get_block_info: callback to get (timestamp, bits) at a given height
   - network: network configuration

   Returns: required compact target (nBits) *)
let get_next_work_required ~(height : int)
    ~(block_time : int32)
    ~(prev_block_time : int32)
    ~(prev_bits : int32)
    ~(get_block_info : int -> (int32 * int32))  (* height -> (timestamp, bits) *)
    ~(network : network_config) : int32 =
  let pow_limit_compact = network.pow_limit in

  (* Regtest: no difficulty adjustment, always use previous bits *)
  if network.pow_no_retargeting then
    prev_bits
  else begin
    (* Check if this is a difficulty adjustment block *)
    let is_adjustment_block = (height mod difficulty_adjustment_interval) = 0 in

    if not is_adjustment_block then begin
      (* Not an adjustment block *)
      if network.pow_allow_min_difficulty then begin
        (* Testnet special rule: if block timestamp > 20 minutes after previous,
           allow minimum difficulty *)
        let elapsed = Int32.to_int (Int32.sub block_time prev_block_time) in
        if elapsed > 2 * target_block_time then
          pow_limit_compact
        else begin
          (* Walk back to find the last non-min-difficulty block or a retarget
             boundary. Return that block's bits. *)
          let rec walk h =
            if h <= 0 then pow_limit_compact
            else begin
              let (_ts, bits) = get_block_info h in
              if bits <> pow_limit_compact || h mod difficulty_adjustment_interval = 0 then
                bits
              else
                walk (h - 1)
            end
          in
          walk (height - 1)
        end
      end else
        (* Mainnet: just use previous block's bits *)
        prev_bits
    end else begin
    (* Difficulty adjustment block: recalculate target *)
    (* Go back 2015 blocks (not 2016) to find the first block of the period.
       nHeightFirst = pindexLast->nHeight - (DifficultyAdjustmentInterval() - 1)
       Since height = pindexLast->nHeight + 1, we have:
       nHeightFirst = height - 1 - 2015 = height - 2016 *)
    let first_block_height = height - difficulty_adjustment_interval in
    let (first_block_time, first_block_bits) = get_block_info first_block_height in
    let (last_block_time, last_block_bits) = (prev_block_time, prev_bits) in

    (* BIP94 (testnet4): use first block's bits as base for calculation.
       This preserves the real difficulty in the first block, since it cannot
       use the min-difficulty exception. *)
    let base_bits =
      if network.enforce_bip94 then first_block_bits
      else last_block_bits
    in

    calculate_next_work_required
      ~first_block_time
      ~last_block_time
      ~base_bits
      ~network
  end
  end  (* Close the outer "else begin" for pow_no_retargeting check *)

(* Legacy wrapper for backward compatibility *)
let next_work_required ~(last_retarget_time : int32)
    ~(current_header : Types.block_header)
    ~(current_bits : int32)
    ~(network : network_config) : int32 =
  calculate_next_work_required
    ~first_block_time:last_retarget_time
    ~last_block_time:current_header.timestamp
    ~base_bits:current_bits
    ~network

(* Parse a big-endian hex string into a 32-byte little-endian Cstruct.
   The hex string is in normal reading order (MSB first), but the Cstruct
   stores bytes in LE (byte 0 = LSB). If the hex is shorter than 64 chars
   it is zero-padded on the left (high bytes). *)
let work_of_hex (hex : string) : Cstruct.t =
  (* Pad to 64 hex chars *)
  let padded =
    let len = String.length hex in
    if len >= 64 then hex
    else String.make (64 - len) '0' ^ hex
  in
  let cs = Cstruct.create 32 in
  for i = 0 to 31 do
    (* BE hex byte i maps to LE byte (31 - i) *)
    let byte = int_of_string ("0x" ^ String.sub padded (i * 2) 2) in
    Cstruct.set_uint8 cs (31 - i) byte
  done;
  cs

let zero_work : Cstruct.t = Cstruct.create 32

(* Mainnet genesis block header *)
let mainnet_genesis_header : Types.block_header = {
  version = 1l;
  prev_block = Types.zero_hash;
  merkle_root = Types.hash256_of_hex
    "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a";
  timestamp = 1231006505l;  (* 2009-01-03 18:15:05 UTC *)
  bits = 0x1d00ffffl;  (* Initial difficulty *)
  nonce = 2083236893l;
}

(* Mainnet configuration *)
let mainnet : network_config = {
  name = "mainnet";
  magic = 0xD9B4BEF9l;
  default_port = 8333;
  dns_seeds = [
    "seed.bitcoin.sipa.be";
    "dnsseed.bluematt.me";
    "dnsseed.bitcoin.dashjr-list-of-p2p-nodes.us";
    "seed.bitcoinstats.com";
    "seed.bitcoin.jonasschnelli.ch";
    "seed.btc.petertodd.net";
    "seed.bitcoin.sprovoost.nl";
    "dnsseed.emzy.de";
    "seed.bitcoin.wiz.biz";
  ];
  genesis_hash = Types.hash256_of_hex
    "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000";
  genesis_header = mainnet_genesis_header;
  pubkey_address_prefix = 0x00;
  script_address_prefix = 0x05;
  wif_prefix = 0x80;
  bech32_hrp = "bc";
  bip34_height = 227931;
  bip65_height = 388381;
  bip66_height = 363725;
  csv_height = 419328;
  segwit_height = 481824;
  taproot_height = 709632;
  pow_allow_min_difficulty = false;
  pow_no_retargeting = false;
  pow_limit = 0x1d00ffffl;
  enforce_bip94 = false;
  network_type = Mainnet;
  (* From Bitcoin Core chainparams.cpp (approximately block 804000) *)
  minimum_chain_work = work_of_hex
    "000000000000000000000000000000000000000052b2559353df4117b7348b64";
  (* Mainnet assumevalid — block 804000 in internal LE byte order.
     Display hash: 00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72f8571c4 *)
  assume_valid_hash = Some (Types.hash256_of_hex
    "c471852fd7a8b75601275a160279a3c5768de4c1c4a702000000000000000000");
  checkpoints = [
    (11111, Types.hash256_of_hex "1d7c6eb2fd42f55925e92efad68b61edd22fba29fde8783df744e26900000000");
    (33333, Types.hash256_of_hex "a6d0b5df7d0df069ceb1e736a216ad187a50b07aaa4e78748a58d52d00000000");
    (74000, Types.hash256_of_hex "201a66b853f9e7814a820e2af5f5dc79c07144e31ce4c9a39339570000000000");
    (105000, Types.hash256_of_hex "97dc6b1d15fbeef373a744fee0b254b0d2c820a3ae7f0228ce91020000000000");
    (134444, Types.hash256_of_hex "feb0d2420d4a18914c81ac30f494a5d4ff34cd15d34cfd2fb105000000000000");
    (168000, Types.hash256_of_hex "63b703835cb735cb9a89d733cbe66f212f63795e0172ea619e09000000000000");
    (193000, Types.hash256_of_hex "17138bca83bdc3e6f60f01177c3877a98266de40735f2a459f05000000000000");
    (210000, Types.hash256_of_hex "2e3471a19b8e22b7f939c63663076603cf692f19837e34958b04000000000000");
    (216116, Types.hash256_of_hex "4edf231bf170234e6a811460f95c94af9464e41ee833b4f4b401000000000000");
    (225430, Types.hash256_of_hex "32595730b165f097e7b806a679cf7f3e439040f750433808c101000000000000");
    (250000, Types.hash256_of_hex "14d2f24d29bed75354f3f88a5fb50022fc064b02291fdf873800000000000000");
    (279000, Types.hash256_of_hex "407ebde958e44190fa9e810ea1fc3a7ef601c3b0a0728cae0100000000000000");
    (295000, Types.hash256_of_hex "83a93246c67003105af33ae0b29dd66f689d0f0ff54e9b4d0000000000000000");
  ];
}

(* Testnet3 configuration *)
let testnet : network_config = {
  name = "testnet3";
  magic = 0x0709110Bl;
  default_port = 18333;
  dns_seeds = [
    "testnet-seed.bitcoin.jonasschnelli.ch";
    "seed.tbtc.petertodd.net";
    "seed.testnet.bitcoin.sprovoost.nl";
    "testnet-seed.bluematt.me";
  ];
  genesis_hash = Types.hash256_of_hex
    "43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000";
  genesis_header = {
    version = 1l;
    prev_block = Types.zero_hash;
    merkle_root = Types.hash256_of_hex
      "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a";
    timestamp = 1296688602l;  (* 2011-02-02 23:16:42 UTC *)
    bits = 0x1d00ffffl;
    nonce = 414098458l;
  };
  pubkey_address_prefix = 0x6F;
  script_address_prefix = 0xC4;
  wif_prefix = 0xEF;
  bech32_hrp = "tb";
  bip34_height = 21111;
  bip65_height = 581885;
  bip66_height = 330776;
  csv_height = 770112;
  segwit_height = 834624;
  taproot_height = 2_032_291;
  pow_allow_min_difficulty = true;
  pow_no_retargeting = false;
  pow_limit = 0x1d00ffffl;
  enforce_bip94 = false;
  network_type = Testnet3;
  minimum_chain_work = zero_work;
  assume_valid_hash = None;
  checkpoints = [];
}

(* Testnet4 configuration (BIP-94) *)
let testnet4 : network_config = {
  name = "testnet4";
  magic = 0x1c163f28l;  (* BIP-94 testnet4 magic *)
  default_port = 48333;
  dns_seeds = [
    "seed.testnet4.bitcoin.sprovoost.nl";
    "seed.testnet4.wiz.biz";
  ];
  genesis_hash = Types.hash256_of_hex
    "da5e13c38306e8b0b7fd65cfc9db5fd888cf5b0a4fa1479d04c7dfc8e2f1a000";
  genesis_header = {
    version = 1l;
    prev_block = Types.zero_hash;
    merkle_root = Types.hash256_of_hex
      "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a";
    timestamp = 1714777860l;  (* 2024-05-03 *)
    bits = 0x1d00ffffl;
    nonce = 393743547l;
  };
  pubkey_address_prefix = 0x6F;
  script_address_prefix = 0xC4;
  wif_prefix = 0xEF;
  bech32_hrp = "tb";
  bip34_height = 1;  (* Active from genesis on testnet4 *)
  bip65_height = 1;
  bip66_height = 1;
  csv_height = 1;
  segwit_height = 1;
  taproot_height = 1;
  pow_allow_min_difficulty = true;
  pow_no_retargeting = false;
  pow_limit = 0x1d00ffffl;
  enforce_bip94 = true;  (* BIP-94 time warp fix enabled *)
  network_type = Testnet4;
  minimum_chain_work = zero_work;
  assume_valid_hash = None;
  checkpoints = [];
}

(* Regtest configuration (local testing) *)
let regtest : network_config = {
  name = "regtest";
  magic = 0xDAB5BFFAl;
  default_port = 18444;
  dns_seeds = [];  (* No seeds for local testing *)
  genesis_hash = Types.hash256_of_hex
    "06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f";
  genesis_header = {
    version = 1l;
    prev_block = Types.zero_hash;
    merkle_root = Types.hash256_of_hex
      "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a";
    timestamp = 1296688602l;
    bits = 0x207fffffl;  (* Very low difficulty for instant mining *)
    nonce = 2l;
  };
  pubkey_address_prefix = 0x6F;
  script_address_prefix = 0xC4;
  wif_prefix = 0xEF;
  bech32_hrp = "bcrt";
  bip34_height = 500;
  bip65_height = 1351;
  bip66_height = 1251;
  csv_height = 432;  (* CSV active early in regtest for testing *)
  segwit_height = 0;  (* SegWit active from genesis *)
  taproot_height = 0;  (* Taproot active from genesis *)
  pow_allow_min_difficulty = true;
  pow_no_retargeting = true;
  pow_limit = 0x207fffffl;
  enforce_bip94 = false;  (* No BIP-94 on regtest *)
  network_type = Regtest;
  minimum_chain_work = zero_work;
  assume_valid_hash = None;
  checkpoints = [];
}

(* Encode block height in coinbase transaction (BIP-34)
   Bitcoin Core's CScript::push_int64 uses:
   - OP_0 (0x00) for height 0
   - OP_1..OP_16 (0x51..0x60) for heights 1-16
   - CScriptNum serialization for larger values (length-prefixed, sign-magnitude)
   IMPORTANT: Sign bit thresholds are 0x7f/0x7fff/0x7fffff, not 0xff/0xffff *)
let encode_height_in_coinbase (height : int) : Cstruct.t =
  if height < 0 then
    failwith "encode_height_in_coinbase: height cannot be negative"
  else if height = 0 then begin
    (* OP_0 *)
    let cs = Cstruct.create 1 in
    Cstruct.set_uint8 cs 0 0x00;
    cs
  end
  else if height >= 1 && height <= 16 then begin
    (* OP_1 through OP_16 (0x51 + height - 1) *)
    let cs = Cstruct.create 1 in
    Cstruct.set_uint8 cs 0 (0x50 + height);
    cs
  end
  else begin
    (* CScriptNum: length-prefixed sign-magnitude little-endian *)
    let bytes_needed =
      if height <= 0x7f then 1           (* 1 byte: 0x01-0x7f *)
      else if height <= 0x7fff then 2    (* 2 bytes: 0x80-0x7fff *)
      else if height <= 0x7fffff then 3  (* 3 bytes: 0x8000-0x7fffff *)
      else 4                             (* 4 bytes: larger values *)
    in
    let cs = Cstruct.create (1 + bytes_needed) in
    Cstruct.set_uint8 cs 0 bytes_needed;
    for i = 0 to bytes_needed - 1 do
      Cstruct.set_uint8 cs (1 + i) ((height lsr (8 * i)) land 0xFF)
    done;
    cs
  end

(* Calculate median time past (MTP) from last 11 block timestamps *)
let median_time_past (timestamps : int32 list) : int32 =
  let sorted = List.sort Int32.compare timestamps in
  let len = List.length sorted in
  if len = 0 then 0l
  else List.nth sorted (len / 2)

(* Validate that a value is within valid money range *)
let is_valid_money (value : int64) : bool =
  value >= 0L && value <= max_money

(* Check if a height is at a difficulty adjustment boundary *)
let is_difficulty_adjustment_height (height : int) : bool =
  height > 0 && height mod difficulty_adjustment_interval = 0

(* BIP-94 timewarp protection: at difficulty adjustment boundaries, the new
   block's timestamp must not be more than max_timewarp seconds before the
   previous block's timestamp. Returns true if the block passes the check. *)
let check_timewarp_rule ~(height : int) ~(header_time : int32)
    ~(prev_block_time : int32) ~(network : network_config) : bool =
  if network.pow_no_retargeting then true  (* Regtest skips this *)
  else if height mod difficulty_adjustment_interval <> 0 then true  (* Not a boundary *)
  else
    (* header_time >= prev_block_time - max_timewarp *)
    Int32.compare header_time
      (Int32.sub prev_block_time (Int32.of_int max_timewarp)) >= 0

(* Genesis block coinbase is NOT spendable (not in UTXO set) *)
let is_genesis_coinbase (height : int) (_txid : Types.hash256) : bool =
  height = 0

(* ============================================================================
   Script verification flags (duplicated from Script to avoid dependency)
   ============================================================================ *)

let script_verify_p2sh                  = 1 lsl 0   (* BIP-16 *)
let script_verify_dersig                = 1 lsl 2   (* BIP-66 *)
let script_verify_low_s                 = 1 lsl 3   (* BIP-62 rule 5 *)
let script_verify_nulldummy             = 1 lsl 4   (* BIP-147 *)
let script_verify_minimaldata           = 1 lsl 5   (* BIP-62 minimal push *)
let script_verify_sigpushonly           = 1 lsl 6   (* scriptSig push-only *)
let script_verify_cleanstack            = 1 lsl 7   (* exactly one stack element *)
let script_verify_checklocktimeverify   = 1 lsl 9   (* BIP-65 *)
let script_verify_checksequenceverify   = 1 lsl 10  (* BIP-68/112 *)
let script_verify_witness               = 1 lsl 11  (* BIP-141 *)
let script_verify_nullfail              = 1 lsl 12  (* BIP-146 *)
let script_verify_witness_pubkeytype    = 1 lsl 14  (* BIP-141 compressed keys *)
let script_verify_taproot               = 1 lsl 17  (* BIP-341/342 *)

(* Compute the correct script verification flags for a given block height *)
let get_block_script_flags (height : int) (network : network_config) : int =
  (* P2SH is always on (BIP-16 activated at height 173805 on mainnet,
     but we treat it as always-on for simplicity) *)
  let flags = script_verify_p2sh in
  (* BIP-66: strict DER signatures *)
  let flags =
    if height >= network.bip66_height then flags lor script_verify_dersig
    else flags
  in
  (* BIP-65: OP_CHECKLOCKTIMEVERIFY *)
  let flags =
    if height >= network.bip65_height then flags lor script_verify_checklocktimeverify
    else flags
  in
  (* BIP-68/112/113: OP_CHECKSEQUENCEVERIFY and sequence locks *)
  let flags =
    if height >= network.csv_height then flags lor script_verify_checksequenceverify
    else flags
  in
  (* SegWit (BIP-141) and associated rules *)
  let flags =
    if height >= network.segwit_height then
      flags
      lor script_verify_witness
      lor script_verify_nulldummy
      lor script_verify_cleanstack
      lor script_verify_sigpushonly
      lor script_verify_nullfail
      lor script_verify_low_s
      lor script_verify_minimaldata
      lor script_verify_witness_pubkeytype
    else flags
  in
  (* Taproot (BIP-341/342) *)
  let flags =
    if height >= network.taproot_height then flags lor script_verify_taproot
    else flags
  in
  flags

(* ============================================================================
   Testnet min-difficulty rule
   ============================================================================ *)

(* Target spacing in seconds (10 minutes) *)
let target_spacing = 600

(* On testnet, if a block's timestamp is more than 2 * target_spacing (20 min)
   after the previous block, allow mining at the minimum difficulty (pow_limit).
   When the block is NOT slow (elapsed <= 2*target_spacing), Bitcoin Core walks
   backward to find the last block whose bits != pow_limit (or a retarget
   boundary), and returns those bits instead.
   Returns None if the rule does not apply, Some nbits if it does. *)
let testnet_min_difficulty_bits ~(prev_block_time : int32)
    ~(current_time : int32) ~(network : network_config)
    ?(get_bits_at_height : (int -> int32) option) ~(height : int) ()
    : int32 option =
  if network.pow_allow_min_difficulty then begin
    let elapsed = Int32.to_int (Int32.sub current_time prev_block_time) in
    if elapsed > 2 * target_spacing then
      Some network.pow_limit
    else begin
      (* Walk backward to find the last non-min-difficulty block or a retarget
         boundary. If no callback is provided, return None (caller uses
         current_bits as before). *)
      match get_bits_at_height with
      | None -> None
      | Some get_bits ->
        let rec walk h =
          if h < 0 then None
          else
            let bits = get_bits h in
            if bits <> network.pow_limit || h mod difficulty_adjustment_interval = 0 then
              Some bits
            else
              walk (h - 1)
        in
        walk (height - 1)
    end
  end else
    None

(* ============================================================================
   256-bit work addition
   ============================================================================ *)

(* Add two 32-byte little-endian integers with carry, returning a new 32-byte
   result (overflow beyond 256 bits is silently truncated). *)
(* Compare two 32-byte LE work values. Delegates to target_compare. *)
let work_compare (a : Cstruct.t) (b : Cstruct.t) : int =
  target_compare a b

(* Compute proof-of-work for a compact target (nBits) as a 32-byte LE integer.
   Uses Bitcoin Core's formula: work = (~target / (target + 1)) + 1
   which avoids overflow since ~target + target + 1 = 2^256.
   Returns zero-work if the target is zero. *)
(* Compute proof-of-work value for a given compact target.
   work = (~target / (target + 1)) + 1 = (2^256 - target - 1) / (target + 1) + 1
   Uses schoolbook byte-level long division (32 iterations) instead of
   bit-by-bit (256 iterations). *)
let work_from_compact (bits : int32) : Cstruct.t =
  let target = compact_to_target bits in
  let is_zero = ref true in
  for i = 0 to 31 do
    if Cstruct.get_uint8 target i <> 0 then is_zero := false
  done;
  if !is_zero then Cstruct.create 32
  else begin
    let target_plus_1 = Cstruct.create 32 in
    Cstruct.blit target 0 target_plus_1 0 32;
    let carry = ref 1 in
    for i = 0 to 31 do
      let v = Cstruct.get_uint8 target_plus_1 i + !carry in
      Cstruct.set_uint8 target_plus_1 i (v land 0xFF);
      carry := v lsr 8
    done;
    let not_target = Cstruct.create 32 in
    for i = 0 to 31 do
      Cstruct.set_uint8 not_target i (0xFF lxor Cstruct.get_uint8 target i)
    done;
    (* Schoolbook long division: not_target / target_plus_1.
       Process from MSB (byte 31) to LSB (byte 0) in LE representation. *)
    let _quotient = target_divide
      (let extended = Cstruct.create 36 in
       Cstruct.blit not_target 0 extended 0 32;
       extended)
      1 32 in
    (* Since target_divide divides by int, and we need to divide by a
       multi-byte value, use the existing bit-by-bit approach but optimized
       with early termination based on MSB of divisor. *)
    let result = Cstruct.create 32 in
    let remainder = Cstruct.create 33 in
    (* Find MSB position of target_plus_1 for early comparison *)
    let divisor_msb = ref 31 in
    while !divisor_msb > 0 && Cstruct.get_uint8 target_plus_1 !divisor_msb = 0 do
      decr divisor_msb
    done;
    let dmsb = !divisor_msb in
    for bit = 255 downto 0 do
      let c = ref 0 in
      for i = 0 to 32 do
        let v = (Cstruct.get_uint8 remainder i lsl 1) lor !c in
        Cstruct.set_uint8 remainder i (v land 0xFF);
        c := v lsr 8
      done;
      let byte_idx = bit / 8 in
      let bit_idx = bit mod 8 in
      let b = (Cstruct.get_uint8 not_target byte_idx lsr bit_idx) land 1 in
      Cstruct.set_uint8 remainder 0
        (Cstruct.get_uint8 remainder 0 lor b);
      (* Quick check: if remainder byte above divisor MSB is nonzero, remainder >= divisor *)
      let ge =
        if Cstruct.get_uint8 remainder 32 > 0 then true
        else if Cstruct.get_uint8 remainder (dmsb + 1) > 0 then true
        else begin
          let result = ref true in
          let decided = ref false in
          let i = ref dmsb in
          while !i >= 0 && not !decided do
            let rv = Cstruct.get_uint8 remainder !i in
            let tv = Cstruct.get_uint8 target_plus_1 !i in
            if rv > tv then (result := true; decided := true)
            else if rv < tv then (result := false; decided := true);
            decr i
          done;
          !result
        end
      in
      if ge then begin
        let qbyte = bit / 8 in
        let qbit = bit mod 8 in
        Cstruct.set_uint8 result qbyte
          (Cstruct.get_uint8 result qbyte lor (1 lsl qbit));
        let borrow = ref 0 in
        for i = 0 to 31 do
          let v = Cstruct.get_uint8 remainder i
                  - Cstruct.get_uint8 target_plus_1 i - !borrow in
          if v < 0 then begin
            Cstruct.set_uint8 remainder i (v + 256);
            borrow := 1
          end else begin
            Cstruct.set_uint8 remainder i v;
            borrow := 0
          end
        done;
        let v32 = Cstruct.get_uint8 remainder 32 - !borrow in
        Cstruct.set_uint8 remainder 32 (max 0 v32)
      end
    done;
    let carry = ref 1 in
    for i = 0 to 31 do
      let v = Cstruct.get_uint8 result i + !carry in
      Cstruct.set_uint8 result i (v land 0xFF);
      carry := v lsr 8
    done;
    result
  end

let work_add (a : Cstruct.t) (b : Cstruct.t) : Cstruct.t =
  let result = Cstruct.create 32 in
  let carry = ref 0 in
  for i = 0 to 31 do
    let sum = Cstruct.get_uint8 a i + Cstruct.get_uint8 b i + !carry in
    Cstruct.set_uint8 result i (sum land 0xFF);
    carry := sum lsr 8
  done;
  result

(* ============================================================================
   BIP-30 exception heights
   ============================================================================ *)

(* The two blocks where duplicate coinbase TXIDs were allowed (before BIP-34
   enforced unique coinbase scripts via block height encoding). These blocks
   contained coinbase transactions whose TXIDs matched earlier coinbases,
   effectively destroying the earlier outputs. *)
let bip30_exception_heights = [91842; 91880]

(* Compute difficulty from compact bits format.
   difficulty = max_target / current_target
   max_target for mainnet genesis: 0x1d00ffff *)
let difficulty_from_bits (bits : int32) : float =
  let max_bits = 0x1d00ffffl in
  let target_from_compact b =
    let exp = Int32.to_int (Int32.shift_right_logical b 24) in
    let mant = Int32.to_float (Int32.logand b 0x007fffffl) in
    mant *. (2.0 ** (8.0 *. (float_of_int (exp - 3))))
  in
  let max_target = target_from_compact max_bits in
  let current_target = target_from_compact bits in
  if current_target = 0.0 then 0.0
  else max_target /. current_target

(* Look up the expected block hash for a checkpoint height *)
let get_checkpoint_hash (height : int) (network : network_config) : Types.hash256 option =
  List.assoc_opt height network.checkpoints

(* ============================================================================
   Checkpoint Verification
   ============================================================================ *)

(* Checkpoint verification result *)
type checkpoint_result =
  | CheckpointOk             (* Not at checkpoint height, or hash matches *)
  | CheckpointMismatch of {  (* Block at checkpoint height doesn't match expected hash *)
      height : int;
      expected : Types.hash256;
      actual : Types.hash256;
    }

(* Verify that a block hash matches the expected checkpoint at a given height.
   Returns CheckpointOk if:
   - The height is not a checkpoint height, OR
   - The block hash matches the expected checkpoint hash
   Returns CheckpointMismatch if the block is at a checkpoint height but has wrong hash.

   This function should be called during accept_block_header and connect_block. *)
let verify_checkpoint (height : int) (block_hash : Types.hash256)
    (network : network_config) : checkpoint_result =
  match get_checkpoint_hash height network with
  | None -> CheckpointOk  (* Not a checkpoint height *)
  | Some expected ->
    if Cstruct.equal block_hash expected then
      CheckpointOk
    else
      CheckpointMismatch { height; expected; actual = block_hash }

(* Convert checkpoint result to string for error messages *)
let checkpoint_result_to_string = function
  | CheckpointOk -> "ok"
  | CheckpointMismatch { height; expected; actual } ->
    Printf.sprintf "checkpoint mismatch at height %d: expected %s, got %s"
      height
      (Types.hash256_to_hex_display expected)
      (Types.hash256_to_hex_display actual)

(* Check if chain work meets minimum_chain_work threshold.
   This should be used to reject headers that would lead to a chain with less
   total work than the hardcoded minimum. Returns true if work >= minimum. *)
let meets_minimum_chain_work (work : Cstruct.t) (network : network_config) : bool =
  work_compare work network.minimum_chain_work >= 0

(* Check if a block hash is an ancestor of the assume_valid hash.
   If assume_valid_hash is set and this block is at or below the assume_valid
   block's height (which must be verified through the header chain), script
   verification can be skipped.

   Parameters:
   - block_hash: the hash of the block being validated
   - block_height: the height of the block being validated
   - assume_valid_height: the height of the assume_valid block (if known)
   - network: network configuration

   Returns true if script verification should be skipped. *)
let should_skip_scripts ~(block_height : int)
    ~(assume_valid_height : int option) ~(network : network_config) : bool =
  match network.assume_valid_hash, assume_valid_height with
  | Some _, Some av_height -> block_height <= av_height
  | _ -> false

(* ============================================================================
   BIP9 Version Bits State Machine (versionbits)
   ============================================================================ *)

(* BIP9 deployment state machine states *)
type deployment_state =
  | Defined    (* Initial state for each deployment. Genesis block is by definition here. *)
  | Started    (* For blocks past the start time. *)
  | LockedIn   (* Threshold met, activation pending. *)
  | Active     (* Final state after LockedIn period. *)
  | Failed     (* Timeout reached before LockedIn (terminal). *)

(* String representation of deployment state (for debugging/RPC) *)
let string_of_deployment_state = function
  | Defined  -> "defined"
  | Started  -> "started"
  | LockedIn -> "locked_in"
  | Active   -> "active"
  | Failed   -> "failed"

(* BIP9 deployment parameters *)
type deployment = {
  name : string;                   (* Human-readable name (e.g., "segwit", "taproot") *)
  bit : int;                       (* Bit position in nVersion (0-28) *)
  start_time : int64;              (* Start MedianTime for signaling *)
  timeout : int64;                 (* Timeout MedianTime for deployment *)
  min_activation_height : int;     (* Minimum height for activation after LockedIn *)
  period : int;                    (* Period for checking signals (usually 2016) *)
  threshold : int;                 (* Minimum signals needed in period *)
}

(* Special start_time values *)
let always_active = -1L     (* Deployment is always active (for testing) *)
let never_active = -2L      (* Deployment is never active (disabled) *)

(* Default threshold values *)
let mainnet_threshold = 1916   (* 95% of 2016, Bitcoin Core default *)
let testnet_threshold = 1512   (* 75% of 2016 for test networks *)

(* Known deployments *)
type deployment_pos =
  | Deployment_testdummy    (* For testing versionbits logic *)
  | Deployment_taproot      (* BIP 341/342 *)

(* Check if a block version signals for a deployment bit.
   Version must have top 3 bits = 001 (0x20000000 mask) and the specific bit set. *)
let version_signals_bit (version : int32) (bit : int) : bool =
  let top_mask = 0xE0000000l in
  let top_bits = 0x20000000l in
  let bit_mask = Int32.shift_left 1l bit in
  Int32.logand version top_mask = top_bits &&
  Int32.logand version bit_mask <> 0l

(* Compute the bit mask for a deployment *)
let deployment_mask (dep : deployment) : int32 =
  Int32.shift_left 1l dep.bit

(* Abstract block index for BIP9 state computation.
   Callers must provide functions to traverse the chain. *)
type block_index = {
  height : int;
  version : int32;
  median_time_past : int64;  (* MTP of this block *)
}

(* Cache for deployment states per block height.
   Key is the height of the first block of the retarget period.
   In Bitcoin Core, the cache is keyed by the block *before* the period start,
   but we key by the period start height for simplicity. *)
module DeploymentCache = Map.Make(Int)

type deployment_cache = deployment_state DeploymentCache.t

(* Get the height of the first block of the retarget period containing `height`.
   For height H, period start is: H - (H mod period)
   But Bitcoin Core computes state based on pindexPrev, so the first block
   of the period *being computed for* is at height that's a multiple of period.

   For a block at height H, its state is determined by:
   - Looking at the period ending at the last retarget boundary before H
   - pindexPrev = H - 1, so pindexPrev adjusted = pindexPrev - ((pindexPrev + 1) % period)

   This gives us the last block of the previous period (or the block before period start). *)
let period_start_height (height : int) (period : int) : int =
  height - (height mod period)

(* Get the state for a deployment at a given block height.

   This implements the BIP9 state machine:
   - DEFINED: Initial state, before start_time MTP is reached
   - STARTED: After start_time MTP, counting signals
   - LOCKED_IN: Threshold met, waiting for activation
   - ACTIVE: Deployment is active (terminal state)
   - FAILED: Timeout reached before threshold (terminal state)

   Parameters:
   - dep: The deployment parameters
   - height: Height of the block we're computing state for
   - get_block: Function to get block info at a given height
   - count_signals: Function to count signaling blocks in a period
   - cache: Mutable cache reference for optimization

   Returns the deployment state for the given height. *)
let get_deployment_state
    ~(dep : deployment)
    ~(height : int)
    ~(get_block : int -> block_index option)
    ~(count_signals : start_height:int -> int)
    ~(cache : deployment_cache ref)
    : deployment_state =

  (* Handle special start_time values *)
  if dep.start_time = always_active then Active
  else if dep.start_time = never_active then Failed
  else begin
    let period = dep.period in

    (* State is computed for retarget periods. Find the period containing this height. *)
    let period_start = period_start_height height period in

    (* Check cache first *)
    match DeploymentCache.find_opt period_start !cache with
    | Some state -> state
    | None ->
      (* Need to compute state by walking back through periods *)

      (* Collect periods we need to compute, working backwards *)
      let rec collect_periods ps start =
        if start < 0 then ps
        else
          match DeploymentCache.find_opt start !cache with
          | Some _ -> ps  (* Found cached state, stop here *)
          | None ->
            let prev_start = start - period in
            collect_periods (start :: ps) prev_start
      in
      let periods_to_compute = collect_periods [] period_start in

      (* Get the state before the first period we need to compute *)
      let initial_state =
        if periods_to_compute = [] then
          DeploymentCache.find period_start !cache
        else
          let first = List.hd periods_to_compute in
          let prev_start = first - period in
          if prev_start < 0 then Defined
          else
            match DeploymentCache.find_opt prev_start !cache with
            | Some s -> s
            | None ->
              (* Genesis period is always Defined *)
              Defined
      in

      (* Walk forward computing states for each period *)
      let rec compute_states state = function
        | [] -> state
        | period_start :: rest ->
          let new_state =
            (* Get the block at the end of this period (pindexPrev in Bitcoin Core) *)
            let period_end = period_start + period - 1 in
            match get_block period_end with
            | None ->
              (* No block at this height yet, state is inherited *)
              state
            | Some block ->
              match state with
              | Defined ->
                (* Transition to Started if MTP >= start_time *)
                if block.median_time_past >= dep.start_time then
                  Started
                else
                  Defined
              | Started ->
                (* Count signals in this period *)
                let count = count_signals ~start_height:period_start in
                if count >= dep.threshold then
                  LockedIn
                else if block.median_time_past >= dep.timeout then
                  Failed
                else
                  Started
              | LockedIn ->
                (* Transition to Active if min_activation_height reached *)
                (* The next period starts at period_start + period *)
                let next_period_start = period_start + period in
                if next_period_start >= dep.min_activation_height then
                  Active
                else
                  LockedIn
              | Active -> Active    (* Terminal state *)
              | Failed -> Failed    (* Terminal state *)
          in
          (* Cache this period's state *)
          cache := DeploymentCache.add period_start new_state !cache;
          compute_states new_state rest
      in
      compute_states initial_state periods_to_compute
  end

(* Count signaling blocks in a period.
   Helper function that counts blocks with the deployment bit set. *)
let count_signals_in_period
    ~(dep : deployment)
    ~(start_height : int)
    ~(get_block : int -> block_index option)
    : int =
  let period = dep.period in
  let rec count acc h =
    if h >= start_height + period then acc
    else
      match get_block h with
      | None -> acc
      | Some block ->
        let signaling = version_signals_bit block.version dep.bit in
        count (if signaling then acc + 1 else acc) (h + 1)
  in
  count 0 start_height

(* BIP9 statistics for a deployment during Started state *)
type bip9_stats = {
  period_length : int;       (* Period length in blocks *)
  threshold_count : int;     (* Threshold needed for lock-in *)
  elapsed : int;             (* Blocks elapsed in current period *)
  signaling_count : int;     (* Blocks signaling so far *)
  possible : bool;           (* Can still reach threshold? *)
}

(* Get BIP9 statistics for current period *)
let get_bip9_stats
    ~(dep : deployment)
    ~(height : int)
    ~(get_block : int -> block_index option)
    : bip9_stats =
  let period = dep.period in
  let period_start = period_start_height height period in
  let elapsed = (height mod period) + 1 in

  (* Count signals so far in this period *)
  let rec count_signals acc h =
    if h > height then acc
    else
      match get_block h with
      | None -> acc
      | Some block ->
        let signaling = version_signals_bit block.version dep.bit in
        count_signals (if signaling then acc + 1 else acc) (h + 1)
  in
  let signaling_count = count_signals 0 period_start in

  (* Check if threshold is still possible *)
  let remaining = period - elapsed in
  let possible = signaling_count + remaining >= dep.threshold in

  {
    period_length = period;
    threshold_count = dep.threshold;
    elapsed;
    signaling_count;
    possible;
  }

(* Compute block version for mining.
   Sets the deployment bits for any deployment in Started or LockedIn state.

   Returns a version with:
   - Top bits = 0x20000000 (versionbits signaling)
   - Deployment bits set for active signaling *)
let compute_block_version
    ~(deployments : deployment list)
    ~(height : int)
    ~(get_block : int -> block_index option)
    ~(caches : (deployment_pos * deployment_cache ref) list)
    : int32 =
  let base_version = versionbits_top_bits in

  List.fold_left (fun version (pos, dep) ->
    (* Find the cache for this deployment *)
    let cache =
      match List.assoc_opt pos caches with
      | Some c -> c
      | None -> ref DeploymentCache.empty
    in
    let state = get_deployment_state
      ~dep
      ~height
      ~get_block
      ~count_signals:(fun ~start_height ->
        count_signals_in_period ~dep ~start_height ~get_block)
      ~cache
    in
    match state with
    | Started | LockedIn ->
      (* Set the bit for this deployment *)
      Int32.logor version (deployment_mask dep)
    | _ -> version
  ) base_version (List.combine (List.map fst caches) deployments)

(* ============================================================================
   Deployment configurations for each network
   ============================================================================ *)

(* Mainnet Taproot deployment (BIP 341/342) *)
let mainnet_taproot : deployment = {
  name = "taproot";
  bit = 2;
  start_time = 1619222400L;       (* April 24, 2021 00:00:00 UTC *)
  timeout = 1628640000L;          (* August 11, 2021 00:00:00 UTC *)
  min_activation_height = 709632; (* Actual activation height *)
  period = 2016;
  threshold = 1815;               (* 90% of 2016 *)
}

(* Testnet4 Taproot deployment (always active from genesis) *)
let testnet4_taproot : deployment = {
  name = "taproot";
  bit = 2;
  start_time = always_active;
  timeout = 0L;
  min_activation_height = 0;
  period = 2016;
  threshold = 1512;
}

(* Regtest Taproot deployment (always active from genesis) *)
let regtest_taproot : deployment = {
  name = "taproot";
  bit = 2;
  start_time = always_active;
  timeout = 0L;
  min_activation_height = 0;
  period = 144;  (* Regtest uses 144 block periods *)
  threshold = 108;
}

(* Test dummy deployment (for testing versionbits logic) *)
let testdummy_deployment : deployment = {
  name = "testdummy";
  bit = 28;
  start_time = never_active;
  timeout = 0L;
  min_activation_height = 0;
  period = 2016;
  threshold = 1815;
}

(* Check if a deployment is active at a given height *)
let is_deployment_active
    ~(dep : deployment)
    ~(height : int)
    ~(get_block : int -> block_index option)
    ~(cache : deployment_cache ref)
    : bool =
  let state = get_deployment_state
    ~dep
    ~height
    ~get_block
    ~count_signals:(fun ~start_height ->
      count_signals_in_period ~dep ~start_height ~get_block)
    ~cache
  in
  state = Active

(* ============================================================================
   VersionBits cache management
   ============================================================================ *)

(* Full cache for all deployments *)
type versionbits_cache = {
  taproot : deployment_cache ref;
  testdummy : deployment_cache ref;
}

(* Create a new empty cache *)
let create_versionbits_cache () : versionbits_cache = {
  taproot = ref DeploymentCache.empty;
  testdummy = ref DeploymentCache.empty;
}

(* Clear all cached states (needed on reorg) *)
let clear_versionbits_cache (cache : versionbits_cache) : unit =
  cache.taproot := DeploymentCache.empty;
  cache.testdummy := DeploymentCache.empty
