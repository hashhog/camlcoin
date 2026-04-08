(* UTXO Snapshot Import (HDOG format)

   Imports a UTXO snapshot in HDOG binary format directly into the RocksDB
   UTXO store.  This is used for AssumeUTXO-style fast sync: instead of
   validating every block from genesis, load a trusted UTXO set at a known
   height and start syncing from there.

   HDOG Binary Format:
     Header (52 bytes):
       Magic:        4 bytes    "HDOG"
       Version:      uint32 LE  (1)
       Block Hash:   32 bytes   (little-endian, internal byte order)
       Block Height: uint32 LE
       UTXO Count:   uint64 LE
     Per UTXO (repeated UTXO_COUNT times):
       TxID:         32 bytes   (little-endian)
       Vout:         uint32 LE
       Amount:       int64 LE   (satoshis)
       Height+CB:    uint32 LE  (height in bits [31:1], coinbase flag in bit [0])
       Script Len:   uint16 LE
       Script:       N bytes    (raw scriptPubKey)

   The UTXO key/value encoding matches OptimizedUtxoSet / Rocksdb_store:
     Key:   36 bytes = txid (32 LE) ++ vout (4 LE)
     Value: serialize_utxo_entry = int64 LE (value) ++ compact_size (script_len)
            ++ script_pubkey ++ int32 LE (height) ++ uint8 (is_coinbase) *)

(* ============================================================================
   HDOG Header
   ============================================================================ *)

type hdog_header = {
  version : int;
  block_hash : Types.hash256;   (* 32 bytes, little-endian / internal order *)
  block_height : int;
  utxo_count : int64;
}

let hdog_magic = "HDOG"
let hdog_header_size = 52

(** Read and validate the HDOG header from an input channel. *)
let read_header (ic : in_channel) : (hdog_header, string) result =
  try
    let buf = really_input_string ic hdog_header_size in
    (* Check magic *)
    let magic = String.sub buf 0 4 in
    if magic <> hdog_magic then
      Error (Printf.sprintf "Bad magic: expected HDOG, got %S" magic)
    else begin
      (* Version: uint32 LE at offset 4 *)
      let version =
        Char.code buf.[4]
        lor (Char.code buf.[5] lsl 8)
        lor (Char.code buf.[6] lsl 16)
        lor (Char.code buf.[7] lsl 24) in
      if version <> 1 then
        Error (Printf.sprintf "Unsupported HDOG version %d (expected 1)" version)
      else begin
        (* Block hash: 32 bytes at offset 8, already LE *)
        let block_hash = Cstruct.create 32 in
        for i = 0 to 31 do
          Cstruct.set_uint8 block_hash i (Char.code buf.[8 + i])
        done;
        (* Block height: uint32 LE at offset 40 *)
        let block_height =
          Char.code buf.[40]
          lor (Char.code buf.[41] lsl 8)
          lor (Char.code buf.[42] lsl 16)
          lor (Char.code buf.[43] lsl 24) in
        (* UTXO count: uint64 LE at offset 44 *)
        let utxo_count =
          let b i = Int64.of_int (Char.code buf.[44 + i]) in
          Int64.logor (b 0)
            (Int64.logor (Int64.shift_left (b 1) 8)
              (Int64.logor (Int64.shift_left (b 2) 16)
                (Int64.logor (Int64.shift_left (b 3) 24)
                  (Int64.logor (Int64.shift_left (b 4) 32)
                    (Int64.logor (Int64.shift_left (b 5) 40)
                      (Int64.logor (Int64.shift_left (b 6) 48)
                        (Int64.shift_left (b 7) 56))))))) in
        Ok { version; block_hash; block_height; utxo_count }
      end
    end
  with
  | End_of_file -> Error "HDOG file too small to contain header"
  | exn -> Error (Printf.sprintf "Failed to read HDOG header: %s" (Printexc.to_string exn))

(* ============================================================================
   Streaming UTXO Reader
   ============================================================================ *)

(** Read a single UTXO entry from the input channel.
    Returns (key, value) pair ready for RocksDB insertion.
    Key:   36-byte outpoint (txid ++ vout LE)
    Value: serialized utxo_entry *)
let read_one_utxo (ic : in_channel) : string * string =
  (* Read fixed-size prefix: txid(32) + vout(4) + amount(8) + height_cb(4) + script_len(2) = 50 bytes *)
  let prefix = really_input_string ic 50 in

  (* Build 36-byte key: txid(32) ++ vout(4), already in correct LE format *)
  let key = String.sub prefix 0 36 in

  (* Parse amount: int64 LE at offset 36 *)
  let amount =
    let b i = Int64.of_int (Char.code prefix.[36 + i]) in
    Int64.logor (b 0)
      (Int64.logor (Int64.shift_left (b 1) 8)
        (Int64.logor (Int64.shift_left (b 2) 16)
          (Int64.logor (Int64.shift_left (b 3) 24)
            (Int64.logor (Int64.shift_left (b 4) 32)
              (Int64.logor (Int64.shift_left (b 5) 40)
                (Int64.logor (Int64.shift_left (b 6) 48)
                  (Int64.shift_left (b 7) 56))))))) in

  (* Parse height+coinbase: uint32 LE at offset 44 *)
  let height_cb =
    Char.code prefix.[44]
    lor (Char.code prefix.[45] lsl 8)
    lor (Char.code prefix.[46] lsl 16)
    lor (Char.code prefix.[47] lsl 24) in
  let height = height_cb lsr 1 in
  let is_coinbase = (height_cb land 1) = 1 in

  (* Script length: uint16 LE at offset 48 *)
  let script_len =
    Char.code prefix.[48]
    lor (Char.code prefix.[49] lsl 8) in

  (* Read script bytes *)
  let script = really_input_string ic script_len in

  (* Serialize value in the same format as Utxo.serialize_utxo_entry:
     int64 LE (amount) ++ compact_size (script_len) ++ script ++ int32 LE (height) ++ uint8 (is_coinbase)

     For efficiency, build the value directly as bytes rather than going
     through the Serialize.writer abstraction. *)
  let compact_size_len =
    if script_len < 0xFD then 1
    else if script_len <= 0xFFFF then 3
    else 5 (* script_len fits in uint16, so max 3 *) in
  let value_len = 8 + compact_size_len + script_len + 4 + 1 in
  let vbuf = Bytes.create value_len in
  let pos = ref 0 in

  (* Amount: int64 LE *)
  for i = 0 to 7 do
    Bytes.set vbuf (!pos + i)
      (Char.chr (Int64.to_int (Int64.logand (Int64.shift_right_logical amount (i * 8)) 0xFFL)))
  done;
  pos := !pos + 8;

  (* Compact size for script length *)
  if script_len < 0xFD then begin
    Bytes.set vbuf !pos (Char.chr script_len);
    pos := !pos + 1
  end else begin
    Bytes.set vbuf !pos (Char.chr 0xFD);
    Bytes.set vbuf (!pos + 1) (Char.chr (script_len land 0xFF));
    Bytes.set vbuf (!pos + 2) (Char.chr ((script_len lsr 8) land 0xFF));
    pos := !pos + 3
  end;

  (* Script bytes *)
  Bytes.blit_string script 0 vbuf !pos script_len;
  pos := !pos + script_len;

  (* Height: int32 LE *)
  Bytes.set vbuf !pos (Char.chr (height land 0xFF));
  Bytes.set vbuf (!pos + 1) (Char.chr ((height lsr 8) land 0xFF));
  Bytes.set vbuf (!pos + 2) (Char.chr ((height lsr 16) land 0xFF));
  Bytes.set vbuf (!pos + 3) (Char.chr ((height lsr 24) land 0xFF));
  pos := !pos + 4;

  (* Is coinbase: uint8 *)
  Bytes.set vbuf !pos (Char.chr (if is_coinbase then 1 else 0));

  (key, Bytes.unsafe_to_string vbuf)

(* ============================================================================
   Import Entry Point
   ============================================================================ *)

(** Import a HDOG UTXO snapshot into the RocksDB UTXO store.

    The import:
    1. Parses and validates the HDOG header
    2. Deletes the existing RocksDB UTXO database directory and re-opens fresh
    3. Streams UTXOs in batches of 100K, writing each batch atomically
    4. Sets the chain tip to the snapshot block hash/height
    5. Sets the RocksDB tip height for consistency checking

    @param snapshot_path  Path to the .hdog snapshot file
    @param data_dir       Camlcoin data directory (contains chainstate/, rocksdb_utxo/)
    @param network        Network config (for logging)
    @return number of UTXOs imported, or an error message *)
let run ~(snapshot_path : string) ~(data_dir : string)
    ~(network : Consensus.network_config) : (int, string) result =
  Printf.eprintf "[utxo-import] Network: %s\n%!" network.Consensus.name;
  Printf.eprintf "[utxo-import] Opening snapshot: %s\n%!" snapshot_path;

  let ic = open_in_bin snapshot_path in
  match read_header ic with
  | Error e ->
    close_in ic;
    Error e
  | Ok header ->
    Printf.eprintf "[utxo-import] HDOG v%d | block %s | height %d | %Ld UTXOs\n%!"
      header.version
      (Types.hash256_to_hex_display header.block_hash)
      header.block_height
      header.utxo_count;

    (* Wipe and re-open RocksDB UTXO store for a clean import *)
    let rocksdb_path = Filename.concat data_dir "rocksdb_utxo" in
    Printf.eprintf "[utxo-import] Removing existing RocksDB at %s\n%!" rocksdb_path;
    (* Remove directory recursively if it exists *)
    (try
      let cmd = Printf.sprintf "rm -rf %s" (Filename.quote rocksdb_path) in
      let ret = Sys.command cmd in
      if ret <> 0 then
        Printf.eprintf "[utxo-import] WARNING: rm -rf returned %d\n%!" ret
    with _ -> ());

    let rocksdb = Rocksdb_store.open_db
      ~write_buffer_mb:256 ~block_cache_mb:1024 ~bloom_bits:10
      rocksdb_path in

    Printf.eprintf "[utxo-import] Starting import...\n%!";
    let batch_size = 100_000 in
    let total = header.utxo_count in
    let imported = ref 0L in
    let batch_ops = ref [] in
    let batch_count = ref 0 in
    let t_start = Unix.gettimeofday () in
    let t_last_report = ref t_start in

    (try
      while !imported < total do
        let (key, value) = read_one_utxo ic in
        batch_ops := (key, Some value) :: !batch_ops;
        incr batch_count;
        imported := Int64.add !imported 1L;

        (* Flush batch every batch_size entries *)
        if !batch_count >= batch_size then begin
          Rocksdb_store.batch_write rocksdb !batch_ops;
          batch_ops := [];
          batch_count := 0
        end;

        (* Progress report every 1M UTXOs *)
        if Int64.rem !imported 1_000_000L = 0L then begin
          let now = Unix.gettimeofday () in
          let elapsed = now -. t_start in
          let rate = Int64.to_float !imported /. elapsed in
          let remaining = Int64.to_float (Int64.sub total !imported) /. rate in
          Printf.eprintf "[utxo-import] %Ld / %Ld (%.1f%%) | %.0f utxo/s | ETA %.0fs\n%!"
            !imported total
            (100.0 *. Int64.to_float !imported /. Int64.to_float total)
            rate remaining;
          t_last_report := now
        end
      done;

      (* Flush remaining entries with tip_height *)
      if !batch_count > 0 then
        Rocksdb_store.batch_write ~tip_height:header.block_height rocksdb !batch_ops
      else
        Rocksdb_store.set_tip_height rocksdb header.block_height;

      let elapsed = Unix.gettimeofday () -. t_start in
      Printf.eprintf "[utxo-import] Imported %Ld UTXOs in %.1fs (%.0f utxo/s)\n%!"
        !imported elapsed (Int64.to_float !imported /. elapsed);

      (* Update chainstate chain_tip to match the snapshot *)
      let db_path = Filename.concat data_dir "chainstate" in
      let db = Storage.ChainDB.create db_path in
      Storage.ChainDB.set_chain_tip db header.block_hash header.block_height;
      Printf.eprintf "[utxo-import] Set chain tip to height %d (%s)\n%!"
        header.block_height
        (Types.hash256_to_hex_display header.block_hash);
      Storage.ChainDB.sync db;
      Storage.ChainDB.close db;

      close_in ic;
      Rocksdb_store.close rocksdb;
      Printf.eprintf "[utxo-import] Done.\n%!";
      Ok (Int64.to_int !imported)
    with exn ->
      close_in_noerr ic;
      Rocksdb_store.close rocksdb;
      Error (Printf.sprintf "Import failed at UTXO %Ld: %s"
               !imported (Printexc.to_string exn)))
