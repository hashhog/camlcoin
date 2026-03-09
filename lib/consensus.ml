(* Consensus-critical constants for Bitcoin protocol *)

(* Block weight limits (post-SegWit) *)
let max_block_weight = 4_000_000
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

(* Transaction limits *)
let max_tx_weight = 400_000
let max_standard_tx_weight = 400_000
let min_tx_weight = 4 * 60  (* 240 weight units *)
let max_script_size = 10_000
let max_script_element_size = 520
let max_ops_per_script = 201
let max_stack_size = 1000
let max_pubkeys_per_multisig = 20
let locktime_threshold = 500_000_000l  (* locktime < this = block height, >= = Unix time *)

(* Witness limits *)
let witness_scale_factor = 4
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

(* Compact target format (nBits) conversion to 256-bit target *)
let compact_to_target (bits : int32) : Cstruct.t =
  let bits_i = Int32.to_int bits in
  let exponent = (bits_i lsr 24) land 0xFF in
  let mantissa = bits_i land 0x7FFFFF in
  (* Note: negative targets are invalid in Bitcoin, but we handle the format *)
  let _negative = bits_i land 0x800000 <> 0 in
  let target = Cstruct.create 32 in
  (* Target is stored in little-endian format *)
  if exponent <= 3 then begin
    (* mantissa fits in low bytes, shift right *)
    let m = mantissa lsr (8 * (3 - exponent)) in
    Cstruct.set_uint8 target 31 (m land 0xFF);
    if exponent >= 2 then
      Cstruct.set_uint8 target 30 ((m lsr 8) land 0xFF);
    if exponent >= 3 then
      Cstruct.set_uint8 target 29 ((m lsr 16) land 0xFF)
  end else begin
    (* mantissa at higher byte positions *)
    let offset = exponent - 3 in
    let pos = 32 - offset - 3 in
    if pos >= 0 && pos < 32 then
      Cstruct.set_uint8 target pos ((mantissa lsr 16) land 0xFF);
    if pos + 1 >= 0 && pos + 1 < 32 then
      Cstruct.set_uint8 target (pos + 1) ((mantissa lsr 8) land 0xFF);
    if pos + 2 >= 0 && pos + 2 < 32 then
      Cstruct.set_uint8 target (pos + 2) (mantissa land 0xFF)
  end;
  target

(* Convert 256-bit target back to compact nBits format *)
let target_to_compact (target : Cstruct.t) : int32 =
  (* Find the first non-zero byte (big-endian perspective) *)
  let rec find_first_nonzero i =
    if i >= 32 then 32
    else if Cstruct.get_uint8 target i <> 0 then i
    else find_first_nonzero (i + 1)
  in
  let first_nonzero = find_first_nonzero 0 in
  if first_nonzero >= 32 then 0l  (* Zero target *)
  else begin
    let size = 32 - first_nonzero in
    let mantissa =
      if size >= 3 then
        (Cstruct.get_uint8 target first_nonzero lsl 16) lor
        (Cstruct.get_uint8 target (first_nonzero + 1) lsl 8) lor
        Cstruct.get_uint8 target (first_nonzero + 2)
      else if size = 2 then
        (Cstruct.get_uint8 target first_nonzero lsl 16) lor
        (Cstruct.get_uint8 target (first_nonzero + 1) lsl 8)
      else
        Cstruct.get_uint8 target first_nonzero lsl 16
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
      let h = Cstruct.get_uint8 hash (31 - i) in
      let t = Cstruct.get_uint8 target i in
      if h < t then true
      else if h > t then false
      else compare_bytes (i - 1)
    end
  in
  compare_bytes 31

(* Calculate next work required (difficulty adjustment) *)
let next_work_required ~(last_retarget_time : int32)
    ~(current_header : Types.block_header)
    ~(current_bits : int32) : int32 =
  (* Calculate actual time taken for last 2016 blocks *)
  let actual_timespan =
    Int32.to_int (Int32.sub current_header.timestamp last_retarget_time) in
  (* Clamp to [min_target_timespan, max_target_timespan] *)
  let adjusted_timespan =
    min max_target_timespan (max min_target_timespan actual_timespan) in
  (* Get current target and adjust *)
  let target = compact_to_target current_bits in
  (* Multiply target by (adjusted_timespan / target_timespan) *)
  (* We need big integer arithmetic for this - using a simplified approach *)
  (* For a full implementation, use Zarith or similar *)
  let _ = target in
  let _ = adjusted_timespan in
  (* TODO: Implement proper 256-bit arithmetic for target adjustment *)
  (* For now, return current bits unchanged *)
  current_bits

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
  segwit_height : int;  (* Height at which SegWit activated *)
  pow_allow_min_difficulty : bool;  (* Allow min difficulty blocks (testnet) *)
  pow_no_retargeting : bool;  (* Skip difficulty retargeting (regtest) *)
}

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
  segwit_height = 481824;
  pow_allow_min_difficulty = false;
  pow_no_retargeting = false;
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
  segwit_height = 834624;
  pow_allow_min_difficulty = true;
  pow_no_retargeting = false;
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
  segwit_height = 0;  (* SegWit active from genesis *)
  pow_allow_min_difficulty = true;
  pow_no_retargeting = true;
}

(* Encode block height in coinbase transaction (BIP-34) *)
(* IMPORTANT: Uses CScriptNum sign-magnitude encoding, where MSB is sign bit *)
(* Thresholds are 0x7f/0x7fff/0x7fffff (not 0xff/0xffff) because of sign bit *)
let encode_height_in_coinbase (height : int) : Cstruct.t =
  if height < 0 then
    failwith "encode_height_in_coinbase: height cannot be negative"
  else if height = 0 then begin
    (* OP_0 *)
    let cs = Cstruct.create 1 in
    Cstruct.set_uint8 cs 0 0x00;
    cs
  end else if height >= 1 && height <= 16 then begin
    (* OP_1 through OP_16 (0x51 - 0x60) *)
    let cs = Cstruct.create 1 in
    Cstruct.set_uint8 cs 0 (0x50 + height);
    cs
  end else begin
    (* Use minimal CScriptNum encoding *)
    (* Must account for sign-magnitude: if MSB would be set, add extra byte *)
    let bytes_needed =
      if height <= 0x7f then 1                (* 1 byte: 0x01-0x7f *)
      else if height <= 0x7fff then 2         (* 2 bytes: 0x80-0x7fff *)
      else if height <= 0x7fffff then 3       (* 3 bytes: 0x8000-0x7fffff *)
      else 4                                  (* 4 bytes: larger values *)
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

(* Genesis block coinbase is NOT spendable (not in UTXO set) *)
let is_genesis_coinbase (height : int) (_txid : Types.hash256) : bool =
  height = 0
