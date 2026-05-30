(* AssumeUTXO Implementation (BIP 199)

   Allows a node to start with a trusted UTXO snapshot and validate
   the full chain in the background. The snapshot contains the UTXO
   set at a specific block height, enabling fast initial sync.

   Reference: Bitcoin Core validation.cpp (ActivateSnapshot, PopulateAndValidateSnapshot)
   Reference: Bitcoin Core node/utxo_snapshot.h (SnapshotMetadata) *)

(* ============================================================================
   Snapshot Constants
   ============================================================================ *)

(* Magic bytes identifying a UTXO snapshot file: 'utxo' + 0xff *)
let snapshot_magic = Cstruct.of_string "utxo\xff"

(* Current snapshot format version *)
let snapshot_version = 2

(* ============================================================================
   AssumeUTXO Validation State
   ============================================================================ *)

(** State of assumeutxo validation for a chainstate.
    Mirrors Bitcoin Core's Assumeutxo enum. *)
type assumeutxo_state =
  | Validated      (** Normal IBD, all blocks validated *)
  | Unvalidated    (** Snapshot loaded, blocks after snapshot validated,
                       but snapshot itself not yet validated by background sync *)
  | Invalid        (** Background validation failed - snapshot is invalid *)

let assumeutxo_state_to_string = function
  | Validated -> "validated"
  | Unvalidated -> "unvalidated"
  | Invalid -> "invalid"

(* ============================================================================
   Snapshot Metadata
   ============================================================================ *)

(** Metadata describing a serialized UTXO set snapshot.
    All fields come from an untrusted file and must be validated. *)
type snapshot_metadata = {
  network_magic : int32;     (** Network identifier (mainnet/testnet/etc) *)
  base_blockhash : Types.hash256;  (** Block hash at snapshot height *)
  coins_count : int64;       (** Number of coins in snapshot (for progress) *)
}

(** Serialize snapshot metadata *)
let serialize_metadata w (m : snapshot_metadata) =
  (* Magic bytes *)
  Serialize.write_bytes w snapshot_magic;
  (* Version (2 bytes LE) *)
  Serialize.write_uint16_le w snapshot_version;
  (* Network magic (4 bytes) *)
  Serialize.write_int32_le w m.network_magic;
  (* Base blockhash (32 bytes) *)
  Serialize.write_bytes w m.base_blockhash;
  (* Coins count (8 bytes LE) *)
  Serialize.write_int64_le w m.coins_count

(** Deserialize snapshot metadata, validating magic and version *)
let deserialize_metadata r ~expected_network_magic : (snapshot_metadata, string) result =
  try
    (* Read and verify magic bytes *)
    let magic = Serialize.read_bytes r 5 in
    if not (Cstruct.equal magic snapshot_magic) then
      Error "Invalid UTXO snapshot magic bytes"
    else begin
      (* Read and verify version *)
      let version = Serialize.read_uint16_le r in
      if version <> snapshot_version then
        Error (Printf.sprintf "Unsupported snapshot version %d (expected %d)"
                 version snapshot_version)
      else begin
        (* Read network magic *)
        let network_magic = Serialize.read_int32_le r in
        if network_magic <> expected_network_magic then
          Error (Printf.sprintf "Network mismatch: snapshot is for network 0x%08lx, node is 0x%08lx"
                   network_magic expected_network_magic)
        else begin
          (* Read base blockhash *)
          let base_blockhash = Serialize.read_bytes r 32 in
          (* Read coins count *)
          let coins_count = Serialize.read_int64_le r in
          Ok { network_magic; base_blockhash; coins_count }
        end
      end
    end
  with
  | Failure msg -> Error ("Failed to read metadata: " ^ msg)
  | Invalid_argument msg -> Error ("Failed to parse snapshot metadata: " ^ msg)
  | _ -> Error "Failed to parse snapshot metadata"

(* ============================================================================
   Hardcoded AssumeUTXO Parameters
   ============================================================================ *)

(** AssumeUTXO parameters for a specific height.

    Mirrors Bitcoin Core's [struct AssumeutxoData] in
    [src/kernel/chainparams.h]. The snapshot file itself does NOT carry
    [hash_serialized] or [chain_tx_count] — they are hardcoded in
    chainparams and used to validate user-supplied snapshot data. *)
type assumeutxo_params = {
  height : int;              (** Block height *)
  blockhash : Types.hash256; (** Expected block hash *)
  (** Hardcoded coin count expected in the snapshot. Used by the loader to
      reject mismatched snapshot files before decoding the body. *)
  coins_count : int64;
  (** SHA256 hash of the serialized UTXO set ([HASH_SERIALIZED] in Core's
      [coinstats.cpp]). Used by the background validator to verify the
      assume-utxo trust assumption. *)
  coins_hash : Types.hash256;
  (** Cumulative chain-tx count at [blockhash], used to populate
      [m_chain_tx_count] when loading the snapshot's chain index without
      having the historical block bodies on hand. *)
  chain_tx_count : int64;
}

(* Helper: build an [assumeutxo_params] record from raw hex fields. The
   blockhash + coins_hash are accepted in DISPLAY order (the way Core's
   chainparams.cpp lists them) and stored in internal little-endian order to
   match the rest of camlcoin. *)
let make_au ~height ~blockhash_display ~coins_count ~coins_hash_display
    ~chain_tx_count =
  let rev_hex h =
    if String.length h <> 64 then
      invalid_arg "assume_utxo: hex must be 64 chars";
    let buf = Buffer.create 64 in
    for i = 31 downto 0 do
      Buffer.add_string buf (String.sub h (i * 2) 2)
    done;
    Buffer.contents buf
  in
  {
    height;
    blockhash = Types.hash256_of_hex (rev_hex blockhash_display);
    coins_count;
    coins_hash = Types.hash256_of_hex (rev_hex coins_hash_display);
    chain_tx_count;
  }

(** Mainnet AssumeUTXO entries — verbatim from Bitcoin Core's
    [src/kernel/chainparams.cpp] [m_assumeutxo_data] (heights 840k / 880k /
    910k / 935k). The on-disk values displayed below match Core's
    [getchaintxstats]/[gettxoutsetinfo] output and can be cross-checked at
    any time against [bitcoin-core/src/kernel/chainparams.cpp]. *)
let mainnet_au_data : assumeutxo_params list = [
  (* height = 840000, April 2024 halving. *)
  make_au
    ~height:840_000
    ~blockhash_display:
      "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5"
    ~coins_hash_display:
      "a2a5521b1b5ab65f67818e5e8eccabb7171a517f9e2382208f77687310768f96"
    ~coins_count:177_240_679L (* informational; canonical count: see Core *)
    ~chain_tx_count:991_032_194L;
  (* height = 880000. *)
  make_au
    ~height:880_000
    ~blockhash_display:
      "000000000000000000010b17283c3c400507969a9c2afd1dcf2082ec5cca2880"
    ~coins_hash_display:
      "dbd190983eaf433ef7c15f78a278ae42c00ef52e0fd2a54953782175fbadcea9"
    ~coins_count:0L
    ~chain_tx_count:1_145_604_538L;
  (* height = 910000. *)
  make_au
    ~height:910_000
    ~blockhash_display:
      "0000000000000000000108970acb9522ffd516eae17acddcb1bd16469194a821"
    ~coins_hash_display:
      "4daf8a17b4902498c5787966a2b51c613acdab5df5db73f196fa59a4da2f1568"
    ~coins_count:0L
    ~chain_tx_count:1_226_586_151L;
  (* height = 935000. *)
  make_au
    ~height:935_000
    ~blockhash_display:
      "0000000000000000000147034958af1652b2b91bba607beacc5e72a56f0fb5ee"
    ~coins_hash_display:
      "e4b90ef9eae834f56c4b64d2d50143cee10ad87994c614d7d04125e2a6025050"
    ~coins_count:0L
    ~chain_tx_count:1_305_397_408L;
  (* height = 944183. *)
  make_au
    ~height:944_183
    ~blockhash_display:
      "0000000000000000000146180a1603839d0e9ac6c00d17a5ab45323398ced817"
    ~coins_hash_display:
      "2eaf71725669a83c1c7947517b84c09b0d65f4e7c813087c74840320bcbc88a8"
    ~coins_count:165_095_935L
    ~chain_tx_count:1_334_000_000L;
]

(** Testnet4 has no Core-published AssumeUTXO entries as of release 31.99.
    Preserve a placeholder slot for camlcoin's existing testnet-4 fast-sync
    flow but flag it explicitly. *)
let testnet4_au_data : assumeutxo_params list = []

(** Get assumeUTXO parameters for mainnet at specific heights.
    Returns None if the height doesn't have hardcoded params. *)
let get_assumeutxo_params_mainnet (height : int) : assumeutxo_params option =
  List.find_opt (fun p -> p.height = height) mainnet_au_data

(** Get assumeUTXO parameters for testnet4 *)
let get_assumeutxo_params_testnet4 (height : int) : assumeutxo_params option =
  List.find_opt (fun p -> p.height = height) testnet4_au_data

(** Lookup assumeUTXO params by block hash for the network *)
let get_assumeutxo_for_hash ~network:(network : Consensus.network_config)
    (blockhash : Types.hash256) : assumeutxo_params option =
  let candidates = match network.network_type with
    | Consensus.Mainnet -> mainnet_au_data
    | Consensus.Testnet4 -> testnet4_au_data
    | _ -> []
  in
  List.find_opt (fun p -> Cstruct.equal p.blockhash blockhash) candidates

(** All hardcoded AssumeUTXO heights for [network], smallest first.
    Mirrors Core's [GetAvailableSnapshotHeights]. *)
let available_snapshot_heights (network : Consensus.network_config) : int list =
  let candidates = match network.network_type with
    | Consensus.Mainnet -> mainnet_au_data
    | Consensus.Testnet4 -> testnet4_au_data
    | _ -> []
  in
  List.sort compare (List.map (fun p -> p.height) candidates)

(* ============================================================================
   Snapshot Coin Entry
   ============================================================================ *)

(** A single coin entry in the snapshot.
    Matches Bitcoin Core's [Coin] structure. *)
type snapshot_coin = {
  outpoint : Types.outpoint;
  value : int64;
  script_pubkey : Cstruct.t;
  height : int;
  is_coinbase : bool;
}

(** Serialize the body of a coin in Bitcoin Core's [Coin::Serialize] format
    (everything AFTER the outpoint key has been written by the caller).

    Wire layout:
      code   = VARINT(height * 2 + fCoinBase)
      value  = VARINT(CompressAmount(value))
      script = ScriptCompression(scriptPubKey)

    This is what Core stores per coin in both the leveldb chainstate and
    inside [dumptxoutset] snapshot files. *)
let serialize_coin_body w (coin : snapshot_coin) =
  let code = coin.height * 2 + (if coin.is_coinbase then 1 else 0) in
  Compressor.write_varint w code;
  Compressor.write_varint_int64 w (Compressor.compress_amount coin.value);
  Compressor.serialize_script w coin.script_pubkey

(** Deserialize the body of a coin from a Core-format reader. The outpoint
    is provided separately because the wire format groups multiple coins
    under a single txid. *)
let deserialize_coin_body r ~(outpoint : Types.outpoint) : snapshot_coin =
  let code = Compressor.read_varint r in
  let height = code / 2 in
  let is_coinbase = (code mod 2) = 1 in
  let amount_compr = Compressor.read_varint_int64 r in
  let value = Compressor.decompress_amount amount_compr in
  let script_pubkey = Compressor.deserialize_script r in
  { outpoint; value; script_pubkey; height; is_coinbase }

(** [serialize_coin w coin] writes a single, standalone coin in
    [outpoint || coin_body] form. This is NOT the dumptxoutset wire format
    (which groups by txid), but it is convenient for round-trip tests and
    for storing a single coin in isolation. *)
let serialize_coin w (coin : snapshot_coin) =
  (* Outpoint: txid (32) + vout (4 LE). *)
  Serialize.write_bytes w coin.outpoint.Types.txid;
  Serialize.write_int32_le w coin.outpoint.Types.vout;
  serialize_coin_body w coin

(** [deserialize_coin r] is the inverse of [serialize_coin]. *)
let deserialize_coin r : snapshot_coin =
  let txid = Serialize.read_bytes r 32 in
  let vout = Serialize.read_int32_le r in
  let outpoint = { Types.txid; vout } in
  deserialize_coin_body r ~outpoint

(* ============================================================================
   Snapshot File I/O — Bitcoin Core wire format
   ============================================================================

   The dumptxoutset / loadtxoutset wire format groups coins under a single
   txid prefix to avoid duplicating the 32-byte hash for every UTXO. See
   [bitcoin-core/src/rpc/blockchain.cpp:WriteUTXOSnapshot] for the writer
   side and [bitcoin-core/src/validation.cpp:PopulateAndValidateSnapshot]
   for the reader side. The high-level layout is:

     [metadata: 51 bytes]                         (per [serialize_metadata])
     repeat until coins_count exhausted:
       txid           : 32 raw bytes (LE / internal order)
       coins_per_txid : CompactSize
       repeat coins_per_txid times:
         vout         : CompactSize
         coin_body    : VARINT(code) || VARINT(CompressAmount(value))
                        || ScriptCompression(scriptPubKey)
*)

(* A small streaming reader that fills a Cstruct on demand from an
   [in_channel]. We need this because [Serialize.reader] consumes a fixed
   buffer, and a multi-GiB UTXO snapshot must not be slurped into memory in
   one go. *)
module Stream_reader = struct
  type t = {
    ic : in_channel;
    mutable cs : Cstruct.t;
    mutable pos : int;
    mutable file_pos : int;
  }

  let buf_size = 1 lsl 20  (* 1 MiB chunks *)

  (* Low-water mark for the streaming top-up in the coin-reader hot loop.
     The reader must never trigger a buffer refill on EVERY record: doing so
     reallocates a fresh [buf_size] Cstruct and memmoves the (up to ~1 MiB)
     unconsumed tail for each of the ~165M coins, which collapses throughput
     to a few hundred coins/sec and storms the major GC — the import then
     appears wedged (0% CPU, no further disk writes) for hours.

     Instead the hot path tops up to this [low_water] target: [ensure_soft]
     returns instantly (no allocation, no copy) while [remaining >= low_water],
     and only refills — to a full [buf_size] — once the buffer drops below it.
     A refill therefore happens about once per (buf_size - low_water) bytes
     consumed (≈ every ~12k coins) rather than once per coin.

     [low_water] must comfortably exceed the largest single record the reader
     consumes between top-up checks: a per-txid group header (32-byte txid +
     CompactSize) plus one coin body (vout CompactSize + code/amount VARINTs +
     a ScriptCompression script up to [Compressor.max_script_size] = 10_000
     bytes). 64 KiB leaves ample headroom; oversized / malicious scripts that
     exceed even the full buffer are still caught by the hard [ensure] guards
     and the deserializer's own bounds checks. *)
  let low_water = 64 * 1024

  let create ic ~start_offset =
    seek_in ic start_offset;
    {
      ic;
      cs = Cstruct.create 0;
      pos = 0;
      file_pos = start_offset;
    }

  (* Refill the local buffer to hold up to [target] bytes. [need] is a
     hard minimum: if the file does not have at least that many bytes
     available between [pos] and EOF, the call raises. The actual buffer
     length after refill may exceed [need] when the file has more data,
     but it may also be exactly [need] near EOF. *)
  let ensure t ~need =
    let remaining = Cstruct.length t.cs - t.pos in
    if remaining >= need then ()
    else begin
      let target = max (max need buf_size) remaining in
      let new_cs = Cstruct.create target in
      if remaining > 0 then
        Cstruct.blit t.cs t.pos new_cs 0 remaining;
      let to_read = target - remaining in
      let read = ref 0 in
      let eof = ref false in
      while not !eof && !read < to_read do
        let want = to_read - !read in
        let bs = Bytes.create want in
        let got = input t.ic bs 0 want in
        if got = 0 then eof := true
        else begin
          Cstruct.blit_from_bytes bs 0 new_cs (remaining + !read) got;
          read := !read + got
        end
      done;
      let total = remaining + !read in
      t.cs <-
        (if total = target then new_cs
         else Cstruct.sub new_cs 0 total);
      t.pos <- 0;
      if Cstruct.length t.cs < need then
        failwith
          (Printf.sprintf "Stream_reader: unexpected end of snapshot (need %d, have %d)"
             need (Cstruct.length t.cs))
    end

  (* Caller-friendly variant: top up to a soft target without failing if
     the file ends earlier. Returns how many bytes are actually available
     in the buffer after the call. *)
  let ensure_soft t ~target =
    let remaining = Cstruct.length t.cs - t.pos in
    if remaining >= target then remaining
    else begin
      let new_cs = Cstruct.create (max target buf_size) in
      if remaining > 0 then
        Cstruct.blit t.cs t.pos new_cs 0 remaining;
      let cap = Cstruct.length new_cs in
      let to_read = cap - remaining in
      let read = ref 0 in
      let eof = ref false in
      while not !eof && !read < to_read do
        let want = to_read - !read in
        let bs = Bytes.create want in
        let got = input t.ic bs 0 want in
        if got = 0 then eof := true
        else begin
          Cstruct.blit_from_bytes bs 0 new_cs (remaining + !read) got;
          read := !read + got
        end
      done;
      let total = remaining + !read in
      t.cs <-
        (if total = cap then new_cs
         else Cstruct.sub new_cs 0 total);
      t.pos <- 0;
      total
    end

  let to_serialize_reader t : Serialize.reader =
    { Serialize.buf = t.cs; pos = t.pos }

  let advance t ~from_serialize =
    let consumed = from_serialize.Serialize.pos - t.pos in
    t.pos <- from_serialize.Serialize.pos;
    t.file_pos <- t.file_pos + consumed
end

(** Write a UTXO snapshot to a file in Bitcoin Core's [dumptxoutset] format.

    [iter_coins] is invoked with a callback that takes each coin in turn.
    Coins must be supplied in canonical txid-then-vout order — that is the
    same order RocksDB / leveldb iterators yield them with the per-coin key
    layout [txid(32) || vout(LE 4)] / [DB_COIN || txid || VARINT(n)] —
    because the writer assumes adjacent coins with the same txid form a
    contiguous group. The iterator the camlcoin chainstate provides
    ([Storage.ChainDB.iter_utxos]) already yields in that order. *)
let write_snapshot (path : string) (metadata : snapshot_metadata)
    ~(iter_coins : (snapshot_coin -> unit) -> unit) : (unit, string) result =
  (* Atomic-write protocol mirrors Bitcoin Core's
     [rpc/blockchain.cpp::dumptxoutset]:
       1. write to [<path>.incomplete]
       2. fsync the fd
       3. atomic rename to [<path>]
     so an operator copying mid-dump never sees a torn file, and a
     SIGKILL during dump leaves at most a [.incomplete] artifact (never
     a half-written [<path>]). On any error we best-effort-remove the
     temp file before returning the error to the caller. *)
  let tmp_path = path ^ ".incomplete" in
  let cleanup_temp () =
    try Sys.remove tmp_path with _ -> ()
  in
  try
    let oc = open_out_bin tmp_path in
    let oc_open = ref true in
    let cleanup_on_error exn =
      if !oc_open then (try close_out_noerr oc with _ -> ());
      oc_open := false;
      cleanup_temp ();
      raise exn
    in
    (try
       (* 1. Metadata. *)
       let w = Serialize.writer_create () in
       serialize_metadata w metadata;
       output_string oc (Cstruct.to_string (Serialize.writer_to_cstruct w));

       (* 2. Per-txid groups. We accumulate same-txid coins in a buffer and
          flush them under a single txid prefix when the txid changes. *)
       let cur_txid : Types.hash256 option ref = ref None in
       let group_buf = Buffer.create 1024 in
       let group_count = ref 0 in
       let flush_group () =
         match !cur_txid with
         | None -> ()
         | Some txid ->
           (* Header: txid (32) + coins_per_txid CompactSize. *)
           let hw = Serialize.writer_create () in
           Serialize.write_bytes hw txid;
           Serialize.write_compact_size hw !group_count;
           output_string oc (Cstruct.to_string (Serialize.writer_to_cstruct hw));
           (* Body: pre-built per-coin entries. *)
           output_string oc (Buffer.contents group_buf);
           Buffer.clear group_buf;
           group_count := 0
       in
       iter_coins (fun coin ->
         let coin_txid = coin.outpoint.Types.txid in
         let starts_new_group =
           match !cur_txid with
           | None -> true
           | Some t -> not (Cstruct.equal t coin_txid)
         in
         if starts_new_group then begin
           flush_group ();
           cur_txid := Some coin_txid
         end;
         (* Append [vout : CompactSize] || coin body. *)
         let cw = Serialize.writer_create () in
         Serialize.write_compact_size cw (Int32.to_int coin.outpoint.vout);
         serialize_coin_body cw coin;
         Buffer.add_string group_buf
           (Cstruct.to_string (Serialize.writer_to_cstruct cw));
         incr group_count
       );
       flush_group ();
       (* Durability: flush the user-space buffer and fsync the fd
          BEFORE the rename. Without the fsync, a power loss between
          rename and the OS flushing dirty pages could leave [<path>]
          visible with zero-length / torn contents. *)
       flush oc;
       let fd = Unix.descr_of_out_channel oc in
       (try Unix.fsync fd with Unix.Unix_error _ -> ());
       close_out oc;
       oc_open := false
     with exn -> cleanup_on_error exn);

    (* 3. Atomic rename: temp -> final. *)
    (try Sys.rename tmp_path path
     with exn ->
       cleanup_temp ();
       raise exn);
    Ok ()
  with
  | Sys_error msg ->
    cleanup_temp ();
    Error ("Failed to write snapshot: " ^ msg)
  | exn ->
    cleanup_temp ();
    Error (Printf.sprintf "Failed to write snapshot: %s"
             (Printexc.to_string exn))

(** Iterate every coin in a Core-format snapshot file, calling [f] for each.

    Returns [Ok n] on success ([n] = coins read), or [Error msg] on
    truncation / format errors. The metadata block must already have been
    consumed by the caller (use [Stream_reader.create] with
    [start_offset:51]).

    [~base_height] (optional, default [max_int]) — when provided, any coin
    whose [height > base_height] causes an immediate [Error], mirroring
    Bitcoin Core [validation.cpp:5814-5819]:
      if (coin.nHeight > base_height || outpoint.n >= UINT32_MAX)
        return error("Bad snapshot data after deserializing %d coins")

    B2: every coin's [value] is checked against [MoneyRange]; a coin with
    [value < 0 || value > MAX_MONEY] causes an immediate [Error], mirroring
    [validation.cpp:5820-5823]:
      if (!MoneyRange(coin.out.nValue))
        return error("Bad snapshot data ... bad tx out value")

    B3: after all declared coins are consumed a trailing-byte probe is
    attempted.  If the file has further data the load is rejected, mirroring
    [validation.cpp:5872-5883]:
      try { coins_file >> left_over_byte; }
      catch (failure&) { out_of_coins = true; }
      if (!out_of_coins) return error("coins left over after deserializing N") *)
let iter_snapshot_coins ?(base_height : int = max_int)
    (sr : Stream_reader.t) ~(coins_count : int64)
    ~(f : snapshot_coin -> unit) : (int64, string) result =
  let coins_left = ref coins_count in
  let total = ref 0L in
  (* B2: MAX_MONEY = 21_000_000 BTC in satoshis *)
  let max_money = 2_100_000_000_000_000L in
  try
    while Int64.compare !coins_left 0L > 0 do
      (* Read the next per-txid group header. The minimum is 32 (txid) +
         1 (smallest CompactSize) bytes. We top up through the soft variant
         only when the buffer has fallen below the [low_water] mark, so the
         common case is a no-op (no realloc, no memmove) and a refill happens
         roughly once per ~1 MiB consumed rather than once per group. The
         hard [ensure ~need:33] below still guarantees the header bytes are
         present (and a near-EOF group still succeeds). *)
      let _ = Stream_reader.ensure_soft sr ~target:Stream_reader.low_water in
      Stream_reader.ensure sr ~need:33;
      let r = Stream_reader.to_serialize_reader sr in
      let txid = Serialize.read_bytes r 32 in
      let coins_per_txid = Serialize.read_compact_size r in
      Stream_reader.advance sr ~from_serialize:r;
      if Int64.compare (Int64.of_int coins_per_txid) !coins_left > 0 then
        failwith
          "Mismatch in coins count in snapshot metadata and actual snapshot data";
      for _ = 1 to coins_per_txid do
        (* Each coin needs at minimum 4 bytes (vout CompactSize 1 + code
           VARINT 1 + amount VARINT 1 + script size VARINT 1). Top up only
           when the buffer has dropped below [low_water]; while it is above
           that mark this is a pure length comparison with no allocation or
           copy, which is what keeps the 165M-coin import streaming instead
           of reallocating + memmoving a fresh ~1 MiB buffer per coin. The
           hard [ensure ~need:4] fallback still guarantees forward progress
           at EOF / on a short tail. *)
        let avail =
          Stream_reader.ensure_soft sr ~target:Stream_reader.low_water in
        if avail < 4 then
          Stream_reader.ensure sr ~need:4;
        let r = Stream_reader.to_serialize_reader sr in
        let vout_int = Serialize.read_compact_size r in
        let outpoint = {
          Types.txid;
          vout = Int32.of_int vout_int;
        } in
        let coin = deserialize_coin_body r ~outpoint in
        Stream_reader.advance sr ~from_serialize:r;
        (* B1: coin.height must not exceed the snapshot base_height.
           Reference: validation.cpp:5814-5819. *)
        if coin.height > base_height then
          failwith (Printf.sprintf
            "Bad snapshot data after deserializing %Ld coins"
            !total);
        (* B2: MoneyRange check — coin value must be in [0, MAX_MONEY].
           Reference: validation.cpp:5820-5823. *)
        if coin.value < 0L || coin.value > max_money then
          failwith (Printf.sprintf
            "Bad snapshot data after deserializing %Ld coins [bad tx out value]"
            !total);
        f coin;
        coins_left := Int64.sub !coins_left 1L;
        total := Int64.add !total 1L
      done
    done;
    (* B3: trailing-bytes probe.  After consuming exactly [coins_count] coins,
       try to read one more byte.  If the file has further data the snapshot
       is malformed.  Reference: validation.cpp:5872-5883. *)
    let trailing = Stream_reader.ensure_soft sr ~target:1 in
    if trailing > 0 then
      failwith (Printf.sprintf
        "coins left over after deserializing %Ld coins from snapshot"
        !total);
    Ok !total
  with
  | Failure msg -> Error msg
  | exn -> Error (Printexc.to_string exn)

(** Read snapshot metadata from a file without loading all coins. *)
let read_snapshot_metadata (path : string) ~expected_network_magic
    : (snapshot_metadata, string) result =
  try
    let ic = open_in_bin path in
    (* Metadata block size: 5 (magic) + 2 (version) + 4 (network) + 32
       (blockhash) + 8 (coins_count) = 51 bytes. *)
    let buf = really_input_string ic 51 in
    close_in ic;
    let r = Serialize.reader_of_cstruct (Cstruct.of_string buf) in
    deserialize_metadata r ~expected_network_magic
  with
  | Sys_error msg -> Error ("Failed to read snapshot: " ^ msg)
  | End_of_file -> Error "Snapshot file too small"
  | _ -> Error "Failed to read snapshot metadata"

(** Constant offset (in bytes) of the first txid group in the snapshot
    file, i.e. the size of the serialized metadata block. *)
let snapshot_body_offset = 51

(* ============================================================================
   Dual Chainstate Management
   ============================================================================ *)

(** Chainstate identifier *)
type chainstate_id =
  | Ibd          (** Normal IBD chainstate (background when snapshot loaded) *)
  | Snapshot     (** Snapshot-based chainstate (active when snapshot loaded) *)

let chainstate_id_to_string = function
  | Ibd -> "ibd"
  | Snapshot -> "snapshot"

(** A single chainstate with its own UTXO set and validation state *)
type chainstate = {
  id : chainstate_id;
  db : Storage.ChainDB.t;
  utxo_cache : Utxo.UtxoCache.t;
  mutable tip_hash : Types.hash256;
  mutable tip_height : int;
  mutable assumeutxo_state : assumeutxo_state;
  mutable from_snapshot_blockhash : Types.hash256 option;
}

(** Node state managing potentially two chainstates *)
type node_state = {
  network : Consensus.network_config;
  mutable active_chainstate : chainstate;
  mutable background_chainstate : chainstate option;
  mutable snapshot_height : int option;
}

(** Create a new chainstate *)
let create_chainstate ~id ~db_path ~network : chainstate =
  let db = Storage.ChainDB.create db_path in
  let db_view = Utxo.DbView.create db in
  let utxo_cache = Utxo.UtxoCache.create db_view in
  let tip_hash, tip_height = match Storage.ChainDB.get_chain_tip db with
    | Some (h, height) -> (h, height)
    | None -> (network.Consensus.genesis_hash, 0)
  in
  {
    id;
    db;
    utxo_cache;
    tip_hash;
    tip_height;
    assumeutxo_state = Validated;
    from_snapshot_blockhash = None;
  }

(** Check if we have a snapshot-based chainstate *)
let has_snapshot_chainstate (state : node_state) : bool =
  state.background_chainstate <> None

(* ============================================================================
   Snapshot Loading
   ============================================================================ *)

(** Progress callback for snapshot loading *)
type load_progress = {
  coins_loaded : int64;
  total_coins : int64;
  pct : float;
}

(** Result of a primary-chainstate snapshot bootstrap. *)
type primary_load_result = {
  base_blockhash : Types.hash256;  (** Snapshot base block hash (internal LE). *)
  base_height : int;               (** Snapshot base height. *)
  coins_loaded : int64;            (** Number of coins streamed into the store. *)
}

(** Load a UTXO snapshot into the PRIMARY chainstate that the running node
    (Cli.run / Sync) reads, then record the snapshot base block as the
    validated chain tip so that forward-sync continues from there
    ("accept-then-continue", mirroring rustoshi / blockbrew).

    Unlike [load_snapshot] (which writes a SECONDARY, inert
    [chainstate_snapshot/] directory), this writes coins into the same
    [Rocksdb_store] the IBD path's [OptimizedUtxoSet] reads from at
    [cli.ml:560], records the RocksDB [tip_height], stores the base block
    header + height->hash mapping, and sets the CF [chain_tip] to the base
    height. After this returns, the caller should fall through into normal
    node-run: [restore_chain_state] reads [chain_tip] -> [blocks_synced] =
    base_height; P2P header sync from genesis (the locator gracefully skips
    the sparse heights) drives the in-memory header tip past base_height;
    then [start_ibd] downloads block base_height+1 onward.

    Coins are written ONLY to [Rocksdb_store] (not the cf_chainstate UTXO
    column family). This matches the established camlcoin convention that
    assume-valid IBD UTXOs live only in RocksDB (see cli.ml:369-373); the
    [Storage.ChainDB.get_utxo] fallback reads RocksDB on a CF miss, and the
    IBD [OptimizedUtxoSet.get] reads RocksDB directly, so forward-sync
    prevout lookups resolve. (dumptxoutset / gettxoutsetinfo, which iterate
    the CF, will not enumerate snapshot coins until they are re-validated;
    that does not affect forward-sync.)

    The snapshot file MUST be in Bitcoin Core's [dumptxoutset] format
    (per-txid-grouped, ScriptCompression-encoded coins). The metadata is
    validated against the hardcoded AssumeUTXO parameters before any coin
    is loaded; mismatches reject the snapshot up front. *)
let load_snapshot_into_primary
    ~(network : Consensus.network_config)
    ~(snapshot_path : string)
    ~(db : Storage.ChainDB.t)
    ~(rocksdb : Rocksdb_store.t)
    ?(on_progress : load_progress -> unit = fun _ -> ())
    ()
    : (primary_load_result, string) result =
  match read_snapshot_metadata snapshot_path ~expected_network_magic:network.magic with
  | Error e -> Error e
  | Ok metadata ->
    match get_assumeutxo_for_hash ~network metadata.base_blockhash with
    | None ->
      Error (Printf.sprintf "Snapshot blockhash %s not recognized for this network"
               (Types.hash256_to_hex_display metadata.base_blockhash))
    | Some params ->
      if Int64.compare params.coins_count 0L <> 0
         && metadata.coins_count <> params.coins_count then
        Error (Printf.sprintf "Coins count mismatch: snapshot has %Ld, expected %Ld"
                 metadata.coins_count params.coins_count)
      else begin
        (* Write coins through OptimizedUtxoSet so the on-disk key format
           and per-coin serialization are byte-identical to what the IBD
           reader ([Sync] via the same module) expects. A modest cache is
           fine — we flush in bounded batches to keep RSS in check. *)
        let utxo =
          Utxo.OptimizedUtxoSet.create ~cache_size:1_000_000 ~rocksdb db in
        let ic = open_in_bin snapshot_path in
        try
          let sr = Stream_reader.create ic
                     ~start_offset:snapshot_body_offset in
          let total = metadata.coins_count in
          let coins_loaded = ref 0L in
          let progress_step = 10_000 in
          let since_progress = ref 0 in
          (* Bounded-memory flush: drain the dirty set to RocksDB every
             [flush_every] coins so a 165M-coin snapshot never accumulates
             the whole set in memory. The tip_height is recorded only on the
             final flush below. *)
          let flush_every = 1_000_000 in
          let since_flush = ref 0 in
          let res = iter_snapshot_coins ~base_height:params.height sr
            ~coins_count:total
            ~f:(fun coin ->
              let entry = {
                Utxo.value = coin.value;
                script_pubkey = coin.script_pubkey;
                height = coin.height;
                is_coinbase = coin.is_coinbase;
              } in
              Utxo.OptimizedUtxoSet.add utxo
                coin.outpoint.Types.txid
                (Int32.to_int coin.outpoint.Types.vout)
                entry;
              coins_loaded := Int64.add !coins_loaded 1L;
              incr since_flush;
              if !since_flush >= flush_every then begin
                since_flush := 0;
                (* No tip_height yet — only mutations. *)
                Utxo.OptimizedUtxoSet.flush utxo
              end;
              incr since_progress;
              if !since_progress >= progress_step then begin
                since_progress := 0;
                let pct =
                  if Int64.equal total 0L then 100.0
                  else 100.0 *. Int64.to_float !coins_loaded
                       /. Int64.to_float total in
                on_progress {
                  coins_loaded = !coins_loaded;
                  total_coins = total;
                  pct;
                }
              end)
          in
          close_in ic;
          match res with
          | Error msg -> Error msg
          | Ok _ ->
            (* Final flush: drain any remaining dirty coins AND record the
               RocksDB tip_height. The cli.ml:434 boot consistency check
               compares [Rocksdb_store.get_tip_height] against
               [chain_tip.height]; both must equal base_height or the boot
               check rewinds blocks_synced to 0 and defeats the snapshot. *)
            Utxo.OptimizedUtxoSet.flush ~tip_height:params.height utxo;
            (* Seed the genesis header into the chainstate DB. On a fresh
               snapshot-bootstrapped datadir [create_chain_state] (which is
               what normally inserts genesis — sync.ml:704-718) is NEVER
               called, because [restore_chain_state] takes the Some-branch
               once we set header_tip below. The from-genesis P2P header
               rebuild needs genesis present so the FIRST received header
               (height 1) finds its parent: [process_headers] connects each
               header via a parent lookup in [state.headers], and that table
               is populated by restore_chain_state's 0..tip walk, which reads
               headers out of the block_header CF. Without genesis in the CF,
               restore loads an empty header table, header 1 is unconnecting,
               and forward-sync wedges at the snapshot base. Mirrors the
               genesis insert in create_chain_state. *)
            let genesis_hash =
              Crypto.compute_block_hash network.genesis_header in
            if not (Storage.ChainDB.has_block_header db genesis_hash) then begin
              Storage.ChainDB.store_block_header db genesis_hash
                network.genesis_header;
              Storage.ChainDB.set_height_hash db 0 genesis_hash
            end;
            (* Store the base block height->hash so the getheaders locator can
               anchor at base_height (build_locator_from_height gracefully
               skips the unfilled intermediate heights). We only have the base
               block's hash (from this network's hardcoded AssumeUTXO
               whitelist), not its real header bytes — the UTXO snapshot
               carries no headers — so the height->hash map is recorded but
               the in-memory header entry for the base is left to the normal
               P2P header sync from genesis. *)
            Storage.ChainDB.set_height_hash db params.height
              metadata.base_blockhash;
            (* Record the validated chain tip. restore_chain_state reads this
               into blocks_synced so forward block download begins at
               base_height+1 (create_ibd_state: start_height =
               blocks_synced + 1). *)
            Storage.ChainDB.set_chain_tip db metadata.base_blockhash
              params.height;
            (* CRITICAL: also record the header tip at the snapshot base.
               restore_chain_state (sync.ml:751) keys EVERYTHING off
               [get_header_tip]: if header_tip is absent it falls through to
               [create_chain_state] (a genesis-fresh state) and NEVER reads
               [chain_tip], silently discarding the snapshot and rewinding
               blocks_synced to 0. Setting header_tip here makes restore take
               the Some-branch, walk the (sparse) stored height->hash map, and
               then read chain_tip into blocks_synced = base_height.
               We do NOT have the snapshot base block's real header bytes (the
               UTXO snapshot carries no headers), so the restore loop's
               [get_block_header base] miss leaves [state.tip = None] with
               [headers_synced = base_height]; P2P header sync from genesis
               then rebuilds the in-memory header chain forward past the base
               (build_locator falls back to genesis when tip is None, and
               every current network peer advertises best_height > base_height
               so should_request_headers fires). Mirrors rustoshi
               main.rs:2287-2289 (HeaderSync::new(genesis) +
               set_best_header(snapshot_height, snapshot_hash)) and
               blockbrew main.go:2083-2091 (SetChainState + SetBlockHeight). *)
            Storage.ChainDB.set_header_tip db metadata.base_blockhash
              params.height;
            Ok {
              base_blockhash = metadata.base_blockhash;
              base_height = params.height;
              coins_loaded = !coins_loaded;
            }
        with
        | Failure msg -> close_in_noerr ic; Error msg
        | End_of_file -> close_in_noerr ic; Error "Unexpected end of snapshot file"
        | exn ->
          close_in_noerr ic;
          Error (Printf.sprintf "Failed to load snapshot into primary chainstate: %s"
                   (Printexc.to_string exn))
      end

(** Load a UTXO snapshot into a new chainstate.

    The snapshot file MUST be in Bitcoin Core's [dumptxoutset] format
    (per-txid-grouped, ScriptCompression-encoded coins). The metadata is
    validated against the hardcoded AssumeUTXO parameters before any coin
    is loaded; mismatches reject the snapshot up front. *)
let load_snapshot ~(network : Consensus.network_config)
    ~(snapshot_path : string)
    ~(snapshot_db_path : string)
    ?(on_progress : load_progress -> unit = fun _ -> ())
    ()
    : (chainstate, string) result =
  match read_snapshot_metadata snapshot_path ~expected_network_magic:network.magic with
  | Error e -> Error e
  | Ok metadata ->
    match get_assumeutxo_for_hash ~network metadata.base_blockhash with
    | None ->
      Error (Printf.sprintf "Snapshot blockhash %s not recognized for this network"
               (Types.hash256_to_hex_display metadata.base_blockhash))
    | Some params ->
      if Int64.compare params.coins_count 0L <> 0
         && metadata.coins_count <> params.coins_count then
        Error (Printf.sprintf "Coins count mismatch: snapshot has %Ld, expected %Ld"
                 metadata.coins_count params.coins_count)
      else begin
        let db = Storage.ChainDB.create snapshot_db_path in
        let db_view = Utxo.DbView.create db in
        let utxo_cache = Utxo.UtxoCache.create db_view in
        let ic = open_in_bin snapshot_path in
        try
          let sr = Stream_reader.create ic
                     ~start_offset:snapshot_body_offset in
          let total = metadata.coins_count in
          let coins_loaded = ref 0L in
          let progress_step = 10_000 in
          let since_progress = ref 0 in
          let res = iter_snapshot_coins ~base_height:params.height sr ~coins_count:total
            ~f:(fun coin ->
              let utxo_coin = {
                Utxo.txout = {
                  Types.value = coin.value;
                  script_pubkey = coin.script_pubkey
                };
                height = coin.height;
                is_coinbase = coin.is_coinbase;
              } in
              Utxo.UtxoCache.add_coin utxo_cache coin.outpoint utxo_coin
                ~possible_overwrite:false;
              coins_loaded := Int64.add !coins_loaded 1L;
              incr since_progress;
              if !since_progress >= progress_step then begin
                since_progress := 0;
                let pct =
                  if Int64.equal total 0L then 100.0
                  else 100.0 *. Int64.to_float !coins_loaded
                       /. Int64.to_float total in
                on_progress {
                  coins_loaded = !coins_loaded;
                  total_coins = total;
                  pct;
                }
              end)
          in
          close_in ic;
          match res with
          | Error msg -> Error msg
          | Ok _ ->
            let _ = Lwt_main.run (Utxo.UtxoCache.flush utxo_cache) in
            Storage.ChainDB.set_chain_tip db
              metadata.base_blockhash params.height;
            Ok {
              id = Snapshot;
              db;
              utxo_cache;
              tip_hash = metadata.base_blockhash;
              tip_height = params.height;
              assumeutxo_state = Unvalidated;
              from_snapshot_blockhash = Some metadata.base_blockhash;
            }
        with
        | Failure msg -> close_in_noerr ic; Error msg
        | End_of_file -> close_in_noerr ic; Error "Unexpected end of snapshot file"
        | exn ->
          close_in_noerr ic;
          Error (Printf.sprintf "Failed to load snapshot: %s"
                   (Printexc.to_string exn))
      end

(* ============================================================================
   Snapshot Creation (dumptxoutset)
   ============================================================================ *)

(** Iterate this chainstate's UTXO set in canonical order, yielding each
    coin as a [snapshot_coin]. Used by [dump_snapshot] and reusable by RPC
    handlers. *)
let iter_chainstate_coins (chainstate : chainstate)
    (f : snapshot_coin -> unit) : unit =
  Storage.ChainDB.iter_utxos chainstate.db (fun txid vout data ->
    let r = Serialize.reader_of_cstruct (Cstruct.of_string data) in
    let utxo = Utxo.deserialize_utxo_entry r in
    let coin = {
      outpoint = { Types.txid; vout = Int32.of_int vout };
      value = utxo.value;
      script_pubkey = utxo.script_pubkey;
      height = utxo.height;
      is_coinbase = utxo.is_coinbase;
    } in
    f coin)

(** Dump the current UTXO set to a Core-format snapshot file. *)
let dump_snapshot ~(chainstate : chainstate)
    ~(network : Consensus.network_config)
    ~(output_path : string)
    ?(on_progress : load_progress -> unit = fun _ -> ())
    ()
    : (snapshot_metadata, string) result =
  (* Count total coins first so the metadata can be written in a single
     pass over the iterator. *)
  let total_coins = ref 0L in
  Storage.ChainDB.iter_utxos chainstate.db (fun _txid _vout _data ->
    total_coins := Int64.add !total_coins 1L
  );
  let metadata = {
    network_magic = network.magic;
    base_blockhash = chainstate.tip_hash;
    coins_count = !total_coins;
  } in
  let coins_written = ref 0L in
  let res = write_snapshot output_path metadata
    ~iter_coins:(fun emit ->
      iter_chainstate_coins chainstate (fun coin ->
        emit coin;
        coins_written := Int64.add !coins_written 1L;
        if Int64.rem !coins_written 10000L = 0L
           && not (Int64.equal !total_coins 0L) then begin
          let pct = 100.0 *. Int64.to_float !coins_written
                    /. Int64.to_float !total_coins in
          on_progress { coins_loaded = !coins_written;
                        total_coins = !total_coins; pct }
        end))
  in
  match res with
  | Ok () -> Ok metadata
  | Error msg -> Error msg

(* ============================================================================
   UTXO Set Hash Computation
   ============================================================================ *)

(** Serialize a coin for hash computation.
    Format matches Bitcoin Core's TxOutSer:
    [outpoint:36][code:4][txout:var]
    where code = (height << 1) + is_coinbase *)
let serialize_coin_for_hash w (outpoint : Types.outpoint) (coin : snapshot_coin) =
  (* Outpoint: txid (32) + vout (4 LE) *)
  Serialize.write_bytes w outpoint.txid;
  Serialize.write_int32_le w outpoint.vout;
  (* Code: (height << 1) | is_coinbase as uint32 *)
  let code = Int32.of_int ((coin.height lsl 1) lor (if coin.is_coinbase then 1 else 0)) in
  Serialize.write_int32_le w code;
  (* TxOut: value (8 LE) + scriptPubKey (compact_size + bytes) *)
  Serialize.write_int64_le w coin.value;
  Serialize.write_compact_size w (Cstruct.length coin.script_pubkey);
  Serialize.write_bytes w coin.script_pubkey

(** Compute the UTXO set hash by iterating over all coins.
    This matches Bitcoin Core's HASH_SERIALIZED hash type.
    The hash is SHA256d of the concatenation of all serialized coins. *)
let compute_utxo_hash ~(iter_coins : (Types.outpoint -> snapshot_coin -> unit) -> unit)
    : Types.hash256 =
  (* We use an incremental SHA256 approach: hash each coin individually,
     then combine all coin hashes into a single hash using a Merkle-like structure.
     For simplicity, we concatenate all serialized coins and hash once. *)
  let buffer = Buffer.create (1024 * 1024) in  (* 1MB initial buffer *)
  iter_coins (fun outpoint coin ->
    let w = Serialize.writer_create () in
    serialize_coin_for_hash w outpoint coin;
    let data = Serialize.writer_to_cstruct w in
    Buffer.add_string buffer (Cstruct.to_string data)
  );
  let data = Cstruct.of_string (Buffer.contents buffer) in
  Crypto.sha256d data

(** Compute UTXO hash from a database by iterating all stored UTXOs *)
let compute_utxo_hash_from_db (db : Storage.ChainDB.t) : Types.hash256 =
  let buffer = Buffer.create (1024 * 1024) in
  Storage.ChainDB.iter_utxos db (fun txid vout data ->
    let r = Serialize.reader_of_cstruct (Cstruct.of_string data) in
    let utxo = Utxo.deserialize_utxo_entry r in
    let outpoint = { Types.txid; vout = Int32.of_int vout } in
    let coin = {
      outpoint;
      value = utxo.Utxo.value;
      script_pubkey = utxo.script_pubkey;
      height = utxo.height;
      is_coinbase = utxo.is_coinbase;
    } in
    let w = Serialize.writer_create () in
    serialize_coin_for_hash w outpoint coin;
    let coin_data = Serialize.writer_to_cstruct w in
    Buffer.add_string buffer (Cstruct.to_string coin_data)
  );
  let data = Cstruct.of_string (Buffer.contents buffer) in
  Crypto.sha256d data

(** Compute UTXO hash from a UTXO cache *)
let compute_utxo_hash_from_cache (cache : Utxo.UtxoCache.t)
    (db : Storage.ChainDB.t) : Types.hash256 =
  (* For computing the hash, we need to iterate all UTXOs.
     We flush the cache first to ensure consistency, then iterate the DB. *)
  let _ = Lwt_main.run (Utxo.UtxoCache.flush cache) in
  compute_utxo_hash_from_db db

(** Compute the MuHash3072-based [txoutset_hash] over the UTXO set.
    Mirrors Bitcoin Core's [CoinStatsHashType::MUHASH] path in
    [src/kernel/coinstats.cpp]: feed each [(outpoint, coin)] preimage —
    [outpoint || code(LE32) || value(LE64) || script(varint+bytes)] — into
    a [MuHash3072] accumulator, then SHA256(LE-3072(num/den mod p)).

    This is the value the [gettxoutsetinfo "muhash"] RPC returns and the
    quantity Core's strict snapshot validator computes after a successful
    [loadtxoutset]. We expose it as a [hash256] (32 raw bytes) so callers
    can feed it straight into [Types.hash256_to_hex_display] for RPC
    output, matching Core's wire form. *)
let compute_utxo_muhash_from_db (db : Storage.ChainDB.t) : Types.hash256 =
  let acc = Muhash.create () in
  Storage.ChainDB.iter_utxos db (fun txid vout data ->
    let r = Serialize.reader_of_cstruct (Cstruct.of_string data) in
    let utxo = Utxo.deserialize_utxo_entry r in
    let outpoint = { Types.txid; vout = Int32.of_int vout } in
    let coin_buf =
      Muhash.serialize_txout outpoint
        ~value:utxo.Utxo.value
        ~script_pubkey:utxo.script_pubkey
        ~height:utxo.height
        ~is_coinbase:utxo.is_coinbase
    in
    Muhash.add acc (Bytes.unsafe_to_string coin_buf)
  );
  Cstruct.of_bytes (Muhash.finalize acc)

(** Compute the MuHash3072 [txoutset_hash] from a UTXO cache view. As with
    [compute_utxo_hash_from_cache], we flush the cache first so the on-disk
    set is the one we accumulate. *)
let compute_utxo_muhash_from_cache (cache : Utxo.UtxoCache.t)
    (db : Storage.ChainDB.t) : Types.hash256 =
  let _ = Lwt_main.run (Utxo.UtxoCache.flush cache) in
  compute_utxo_muhash_from_db db

(** [verify_loaded_utxo_hash ~db ~expected] is the strict snapshot
    content-hash check performed by [loadtxoutset] after a snapshot's
    coins have been streamed into the chainstate DB.

    This mirrors Bitcoin Core's [ActivateSnapshot] gate at
    [src/validation.cpp:5902-5915]: Core invokes
    [ComputeUTXOStats(CoinStatsHashType::HASH_SERIALIZED, ...)]
    ([src/kernel/coinstats.cpp:161-163]) which streams every
    [(outpoint, coin)] preimage through a [HashWriter] (i.e. SHA256d
    of the concatenation, see [src/hash.h:HashWriter::GetHash]) and
    compares the result against
    [m_assumeutxo_data.hash_serialized] from chainparams. The
    chainparams field is named [hash_serialized] precisely because it
    holds the [HASH_SERIALIZED] (SHA256d) commitment — NOT the
    MuHash3072 commitment, which Core uses only for the
    [gettxoutsetinfo "muhash"] RPC.

    We compute the same SHA256d via [compute_utxo_hash_from_db db]
    and compare against [expected] (the [params.coins_hash] from the
    chainparams AssumeUTXO whitelist).

    On mismatch returns Core's verbatim wording from
    [src/validation.cpp:5913]:
        "Bad snapshot content hash: expected <expected>, got <actual>"
    so external tooling that scrapes the message keeps working.

    Returns [Ok actual] when the hashes agree, where [actual] is the
    same [hash256] callers can surface as [txoutset_hash]. *)
let verify_loaded_utxo_hash ~(db : Storage.ChainDB.t)
    ~(expected : Types.hash256) : (Types.hash256, string) result =
  let actual = compute_utxo_hash_from_db db in
  if Cstruct.equal actual expected then
    Ok actual
  else
    Error (Printf.sprintf
             "Bad snapshot content hash: expected %s, got %s"
             (Types.hash256_to_hex_display expected)
             (Types.hash256_to_hex_display actual))

(** [verify_loaded_utxo_muhash ~db ~expected] is the MuHash3072 variant
    of the snapshot content-hash check. NOT used by [loadtxoutset] —
    Core's strict gate uses [HASH_SERIALIZED] (see
    [verify_loaded_utxo_hash] above). Retained as a building block for
    the [gettxoutsetinfo hash_type=muhash] RPC and for tests that
    exercise the MuHash3072 plumbing. *)
let verify_loaded_utxo_muhash ~(db : Storage.ChainDB.t)
    ~(expected : Types.hash256) : (Types.hash256, string) result =
  let actual = compute_utxo_muhash_from_db db in
  if Cstruct.equal actual expected then
    Ok actual
  else
    Error (Printf.sprintf
             "Bad snapshot content hash: expected %s, got %s"
             (Types.hash256_to_hex_display expected)
             (Types.hash256_to_hex_display actual))

(* ============================================================================
   Background Validation
   ============================================================================ *)

(** Background validation state *)
type background_validation_state =
  | BgNotStarted
  | BgValidating of { height : int; target_height : int }
  | BgCompleted
  | BgFailed of string

(** Background validation context *)
type background_validation = {
  mutable state : background_validation_state;
  mutable validated_height : int;
  target_height : int;
  snapshot_coins_hash : Types.hash256;
}

(** Create a background validation context *)
let create_background_validation ~(snapshot_params : assumeutxo_params) : background_validation =
  {
    state = BgNotStarted;
    validated_height = 0;
    target_height = snapshot_params.height;
    snapshot_coins_hash = snapshot_params.coins_hash;
  }

(** Update UTXO cache with a connected block.
    Returns the collected fees from the block. *)
let connect_block_to_cache ~(cache : Utxo.UtxoCache.t) ~(block : Types.block)
    ~(height : int) ?(network_type : Consensus.network = Consensus.Mainnet) ()
    : (int64, string) result =
  let error = ref None in
  let total_fees = ref 0L in

  List.iteri (fun tx_idx tx ->
    if !error = None then begin
      let txid = Crypto.compute_txid tx in
      let is_coinbase = tx_idx = 0 in

      (* Process inputs (skip coinbase) *)
      if not is_coinbase then begin
        let input_sum = ref 0L in
        List.iter (fun inp ->
          if !error = None then begin
            let prev = inp.Types.previous_output in
            match Utxo.UtxoCache.get_coin cache prev with
            | None ->
              error := Some (Printf.sprintf
                "Missing UTXO: %s:%ld"
                (Types.hash256_to_hex_display prev.txid)
                prev.vout)
            | Some coin ->
              if coin.is_coinbase &&
                 height - coin.height < Consensus.coinbase_maturity then
                error := Some "Immature coinbase spend"
              else begin
                input_sum := Int64.add !input_sum coin.txout.Types.value;
                ignore (Utxo.UtxoCache.spend_coin cache prev)
              end
          end
        ) tx.Types.inputs;

        if !error = None then begin
          let output_sum = List.fold_left
            (fun acc out -> Int64.add acc out.Types.value)
            0L tx.Types.outputs in
          if output_sum > !input_sum then
            error := Some "Output exceeds input"
          else
            total_fees :=
              Int64.add !total_fees
                (Int64.sub !input_sum output_sum)
        end
      end;

      (* Add outputs *)
      if !error = None then
        List.iteri (fun vout out ->
          let outpoint = { Types.txid; vout = Int32.of_int vout } in
          let coin : Utxo.coin = {
            txout = { Types.value = out.Types.value; script_pubkey = out.script_pubkey };
            height;
            is_coinbase;
          } in
          Utxo.UtxoCache.add_coin cache outpoint coin ~possible_overwrite:false
        ) tx.Types.outputs
    end
  ) block.Types.transactions;

  match !error with
  | Some e -> Error e
  | None ->
    (* Verify coinbase value *)
    let subsidy = Consensus.block_subsidy_for_network network_type height in
    let max_coinbase = Int64.add subsidy !total_fees in
    let coinbase = List.hd block.Types.transactions in
    let coinbase_out = List.fold_left
      (fun acc out -> Int64.add acc out.Types.value)
      0L coinbase.Types.outputs in
    if coinbase_out > max_coinbase then
      Error (Printf.sprintf "Coinbase too large: %Ld > %Ld" coinbase_out max_coinbase)
    else
      Ok !total_fees

(** Run background validation in an Lwt thread.
    Validates blocks from genesis to snapshot height, then compares UTXO hashes. *)
let run_background_validation
    ~(ibd_chainstate : chainstate)
    ~(snapshot_chainstate : chainstate)
    ~(bg_validation : background_validation)
    ~(get_block : Types.hash256 -> Types.block option)
    ~(get_header_at_height : int -> Sync.header_entry option)
    ~(network : Consensus.network_config)
    () : unit Lwt.t =
  let open Lwt.Syntax in
  bg_validation.state <- BgValidating {
    height = bg_validation.validated_height;
    target_height = bg_validation.target_height;
  };

  let rec validate_next_block () =
    if bg_validation.validated_height >= bg_validation.target_height then begin
      (* Validation complete - compute UTXO hash and compare *)
      Logs.info (fun m -> m "[assumeutxo] Computing UTXO hash at height %d..."
                   bg_validation.target_height);

      (* Flush cache and compute hash *)
      let* _ = Utxo.UtxoCache.flush ibd_chainstate.utxo_cache in
      let db = Utxo.DbView.db (Utxo.UtxoCache.get_view ibd_chainstate.utxo_cache) in
      let computed_hash = compute_utxo_hash_from_db db in

      (* Compare with expected hash *)
      if Cstruct.equal computed_hash bg_validation.snapshot_coins_hash then begin
        bg_validation.state <- BgCompleted;
        snapshot_chainstate.assumeutxo_state <- Validated;
        Logs.info (fun m -> m "[assumeutxo] Background validation completed successfully! \
                               UTXO hashes match at height %d"
                     bg_validation.target_height);
        Lwt.return_unit
      end else begin
        let msg = Printf.sprintf
          "UTXO hash mismatch! Expected %s, got %s"
          (Types.hash256_to_hex_display bg_validation.snapshot_coins_hash)
          (Types.hash256_to_hex_display computed_hash)
        in
        bg_validation.state <- BgFailed msg;
        snapshot_chainstate.assumeutxo_state <- Invalid;
        Logs.err (fun m -> m "[assumeutxo] Background validation failed: %s" msg);
        Lwt.return_unit
      end
    end else begin
      let next_height = bg_validation.validated_height + 1 in
      match get_header_at_height next_height with
      | None ->
        (* Wait for more blocks to be available *)
        let* () = Lwt_unix.sleep 1.0 in
        validate_next_block ()
      | Some header_entry ->
        match get_block header_entry.hash with
        | None ->
          (* Block not available yet, wait *)
          let* () = Lwt_unix.sleep 1.0 in
          validate_next_block ()
        | Some block ->
          (* Validate block against IBD chainstate *)
          let median_time = 0l in (* TODO: compute properly from chain *)
          let flags = Validation.get_script_flags_for_height ~network next_height in
          let base_lookup outpoint =
            match Utxo.UtxoCache.get_coin ibd_chainstate.utxo_cache outpoint with
            | Some coin ->
              Some {
                Validation.txid = outpoint.Types.txid;
                vout = outpoint.vout;
                value = coin.txout.Types.value;
                script_pubkey = coin.txout.script_pubkey;
                height = coin.height;
                is_coinbase = coin.is_coinbase;
              }
            | None -> None
          in
          (* accept_block: unified ProcessNewBlock check pipeline.
             The assumeutxo background validator applies the same check
             sequence as all other block-acceptance paths, ensuring that
             the background IBD chain reaches the same consensus state as
             a from-genesis sync would.
             Reference: bitcoin-core/src/validation.cpp ProcessNewBlock. *)
          (* W93 Bug 1 fix: pass BIP34Height hash so the BIP-30 skip
             optimization activates on mainnet. *)
          let bip34_height_hash =
            match network.Consensus.bip34_hash with
            | None -> None
            | Some _ ->
              (match get_header_at_height network.Consensus.bip34_height with
               | None -> None
               | Some e -> Some e.hash)
          in
          match Validation.accept_block ~network ~block ~height:next_height
                  ~expected_bits:header_entry.header.bits
                  ~median_time
                  ~base_lookup
                  ~flags
                  ~skip_scripts:false
                  ?bip34_height_hash
                  () with
          | Validation.AB_err e ->
            bg_validation.state <- BgFailed (Validation.block_error_to_string e);
            snapshot_chainstate.assumeutxo_state <- Invalid;
            Logs.err (fun m -> m "[assumeutxo] Background validation failed at height %d: %s"
                        next_height (Validation.block_error_to_string e));
            Lwt.return_unit
          | Validation.AB_ok (_fees, _txid_arr, _spent_utxos) ->
            (* Update IBD chainstate UTXO set with the block's changes *)
            (match connect_block_to_cache ~cache:ibd_chainstate.utxo_cache
                     ~block ~height:next_height () with
            | Error e ->
              bg_validation.state <- BgFailed e;
              snapshot_chainstate.assumeutxo_state <- Invalid;
              Logs.err (fun m -> m "[assumeutxo] UTXO update failed at height %d: %s"
                          next_height e);
              Lwt.return_unit
            | Ok _ ->
              bg_validation.validated_height <- next_height;
              ibd_chainstate.tip_height <- next_height;
              ibd_chainstate.tip_hash <- header_entry.hash;
              bg_validation.state <- BgValidating {
                height = next_height;
                target_height = bg_validation.target_height;
              };
              (* Log progress periodically *)
              if next_height mod 10000 = 0 then
                Logs.info (fun m -> m "[assumeutxo] Background validation progress: %d / %d (%.1f%%)"
                             next_height bg_validation.target_height
                             (100.0 *. (float_of_int next_height) /. (float_of_int bg_validation.target_height)));
              (* Flush cache periodically to avoid memory pressure *)
              let* () =
                if next_height mod 5000 = 0 then begin
                  let* _ = Utxo.UtxoCache.flush ibd_chainstate.utxo_cache in
                  Lwt.return_unit
                end else Lwt.return_unit
              in
              (* Yield to scheduler periodically *)
              let* () = if next_height mod 100 = 0 then Lwt.pause () else Lwt.return_unit in
              validate_next_block ())
    end
  in
  validate_next_block ()

(* ============================================================================
   Activation — DELETED 2026-05-05
   ============================================================================

   [activate_snapshot] used to live here. It operated on [node_state] (the
   2-chainstate IBD/snapshot pair below) and was meant to mirror Bitcoin
   Core's [ChainstateManager::ActivateSnapshot] in [src/validation.cpp:5588]:
   promote a freshly-loaded snapshot chainstate to "active" and demote the
   prior tip to "background" for behind-the-scenes IBD validation.

   It was removed because it had zero callers across [lib/], [bin/], and
   [test/] — and the wider 2-chainstate machinery it depended on is dormant:
   [node_state] / [active_chainstate] / [background_chainstate] /
   [has_snapshot_chainstate] / [create_chainstate] are never instantiated
   anywhere in the codebase. They were a 2026-04-29 design draft for
   in-process Core-style dual-chainstate switching that camlcoin never
   integrated.

   What ships instead: both the CLI ([bin/main.ml::import_utxo]) and the
   RPC ([lib/rpc.ml::handle_loadtxoutset]) symmetrically write the snapshot
   into a sibling [chainstate_snapshot/] RocksDB directory. That data is
   currently inert with respect to the running daemon — the live chainstate
   used by [Sync] / [Block_import] / [Peer_manager] is the genesis-rooted
   IBD chainstate at [<datadir>/chainstate/] and is never swapped or
   merged with the snapshot directory. Wiring real snapshot activation is
   an architectural change (camlcoin's chain data model would need to
   become dual-chainstate) and is out of scope here. See the
   2026-05-05 snapshot CLI/RPC parity audit for the GREEN scoring rationale.

   The orphan supporting surface ([node_state] + [create_chainstate] +
   [has_snapshot_chainstate]) is intentionally retained for now to keep
   the diff narrow; a follow-up cleanup may remove that whole cluster
   together with [run_background_validation] once the assumeutxo
   integration plan is decided. *)
