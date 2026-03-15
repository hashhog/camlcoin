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
    These are hardcoded in the node and must match the snapshot exactly. *)
type assumeutxo_params = {
  height : int;              (** Block height *)
  blockhash : Types.hash256; (** Expected block hash *)
  coins_count : int64;       (** Expected number of coins *)
  coins_hash : Types.hash256; (** SHA256 hash of serialized UTXO set *)
}

(** Get assumeUTXO parameters for mainnet at specific heights.
    Returns None if the height doesn't have hardcoded params. *)
let get_assumeutxo_params_mainnet (height : int) : assumeutxo_params option =
  (* Mainnet assumeUTXO parameters - from Bitcoin Core chainparams.cpp *)
  match height with
  | 840000 ->
    (* Block 840000 - April 2024 halving *)
    Some {
      height = 840000;
      blockhash = Types.hash256_of_hex
        "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5";
      coins_count = 177_240_679L;
      coins_hash = Types.hash256_of_hex
        "51c8d11d8b5c1de51543c579736c786f0cf5426e3cc25db2aea5c99c05bc4c0f";
    }
  | _ -> None

(** Get assumeUTXO parameters for testnet4 *)
let get_assumeutxo_params_testnet4 (height : int) : assumeutxo_params option =
  match height with
  | 160000 ->
    Some {
      height = 160000;
      blockhash = Types.hash256_of_hex
        "0000000000003a88c5c6bb026ca8e91c21dc3e17a04cfc55ec1a60ce31a9b0e6";
      coins_count = 2_097_657L;
      coins_hash = Types.hash256_of_hex
        "5e34ae8ace75e37d2f0c96a1ad7768b9e3c7f0a9ed08e55a4a66d43adbd0de07";
    }
  | _ -> None

(** Lookup assumeUTXO params by block hash *)
let get_assumeutxo_for_hash ~network:(network : Consensus.network_config)
    (blockhash : Types.hash256) : assumeutxo_params option =
  (* Check all known heights for this network *)
  let check_height h =
    let params = match network.network_type with
      | Consensus.Mainnet -> get_assumeutxo_params_mainnet h
      | Consensus.Testnet4 -> get_assumeutxo_params_testnet4 h
      | _ -> None
    in
    match params with
    | Some p when Cstruct.equal p.blockhash blockhash -> Some p
    | _ -> None
  in
  (* Check known heights *)
  match network.network_type with
  | Consensus.Mainnet ->
    check_height 840000
  | Consensus.Testnet4 ->
    check_height 160000
  | _ -> None

(* ============================================================================
   Snapshot Coin Entry
   ============================================================================ *)

(** A single coin entry in the snapshot.
    Matches Bitcoin Core's Coin structure. *)
type snapshot_coin = {
  outpoint : Types.outpoint;
  value : int64;
  script_pubkey : Cstruct.t;
  height : int;
  is_coinbase : bool;
}

(** Serialize a coin for snapshot storage.
    Format: [outpoint:36][code:varint][amount:8][script:var]
    where code encodes (height * 2 + is_coinbase) *)
let serialize_coin w (coin : snapshot_coin) =
  (* Outpoint: txid (32) + vout (4 LE) *)
  Serialize.write_bytes w coin.outpoint.Types.txid;
  Serialize.write_int32_le w coin.outpoint.Types.vout;
  (* Code: height * 2 + is_coinbase *)
  let code = coin.height * 2 + (if coin.is_coinbase then 1 else 0) in
  Serialize.write_compact_size w code;
  (* Amount (8 bytes LE) *)
  Serialize.write_int64_le w coin.value;
  (* Script *)
  Serialize.write_compact_size w (Cstruct.length coin.script_pubkey);
  Serialize.write_bytes w coin.script_pubkey

(** Deserialize a coin from snapshot data *)
let deserialize_coin r : snapshot_coin =
  let txid = Serialize.read_bytes r 32 in
  let vout = Serialize.read_int32_le r in
  let outpoint = { Types.txid; vout } in
  let code = Serialize.read_compact_size r in
  let height = code / 2 in
  let is_coinbase = (code mod 2) = 1 in
  let value = Serialize.read_int64_le r in
  let script_len = Serialize.read_compact_size r in
  let script_pubkey = Serialize.read_bytes r script_len in
  { outpoint; value; script_pubkey; height; is_coinbase }

(* ============================================================================
   Snapshot File I/O
   ============================================================================ *)

(** Write a UTXO snapshot to a file.
    Format: [metadata][coin_entries...] *)
let write_snapshot (path : string) (metadata : snapshot_metadata)
    ~(iter_coins : (snapshot_coin -> unit) -> unit) : (unit, string) result =
  try
    let oc = open_out_bin path in
    let w = Serialize.writer_create () in
    (* Write metadata *)
    serialize_metadata w metadata;
    let meta_bytes = Serialize.writer_to_cstruct w in
    output_string oc (Cstruct.to_string meta_bytes);
    (* Write coins *)
    iter_coins (fun coin ->
      let cw = Serialize.writer_create () in
      serialize_coin cw coin;
      output_string oc (Cstruct.to_string (Serialize.writer_to_cstruct cw))
    );
    close_out oc;
    Ok ()
  with
  | Sys_error msg -> Error ("Failed to write snapshot: " ^ msg)
  | _ -> Error "Failed to write snapshot"

(** Read snapshot metadata from a file without loading all coins *)
let read_snapshot_metadata (path : string) ~expected_network_magic
    : (snapshot_metadata, string) result =
  try
    let ic = open_in_bin path in
    (* Read enough bytes for metadata: 5 (magic) + 2 (version) + 4 (network) + 32 (hash) + 8 (count) = 51 *)
    let buf = really_input_string ic 51 in
    close_in ic;
    let r = Serialize.reader_of_cstruct (Cstruct.of_string buf) in
    deserialize_metadata r ~expected_network_magic
  with
  | Sys_error msg -> Error ("Failed to read snapshot: " ^ msg)
  | End_of_file -> Error "Snapshot file too small"
  | _ -> Error "Failed to read snapshot metadata"

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

(** Load a UTXO snapshot into a new chainstate.
    Validates metadata against hardcoded assumeUTXO parameters. *)
let load_snapshot ~(network : Consensus.network_config)
    ~(snapshot_path : string)
    ~(snapshot_db_path : string)
    ?(on_progress : load_progress -> unit = fun _ -> ())
    ()
    : (chainstate, string) result =
  (* Read and validate metadata *)
  match read_snapshot_metadata snapshot_path ~expected_network_magic:network.magic with
  | Error e -> Error e
  | Ok metadata ->
    (* Verify against hardcoded assumeUTXO params *)
    match get_assumeutxo_for_hash ~network metadata.base_blockhash with
    | None ->
      Error (Printf.sprintf "Snapshot blockhash %s not recognized for this network"
               (Types.hash256_to_hex_display metadata.base_blockhash))
    | Some params ->
      if metadata.coins_count <> params.coins_count then
        Error (Printf.sprintf "Coins count mismatch: snapshot has %Ld, expected %Ld"
                 metadata.coins_count params.coins_count)
      else begin
        (* Create new chainstate for snapshot *)
        let db = Storage.ChainDB.create snapshot_db_path in
        let db_view = Utxo.DbView.create db in
        let utxo_cache = Utxo.UtxoCache.create db_view in

        (* Open snapshot file and load coins *)
        try
          let ic = open_in_bin snapshot_path in
          (* Skip metadata (51 bytes) *)
          seek_in ic 51;

          let coins_loaded = ref 0L in
          let total = metadata.coins_count in

          (* Load coins in batches for efficiency *)
          let batch_size = 10000 in
          let coins_in_batch = ref 0 in

          while !coins_loaded < total do
            let remaining = in_channel_length ic - pos_in ic in
            if remaining <= 0 then
              raise (Failure "Unexpected end of snapshot file");

            (* Read next coin *)
            let coin = begin
              (* Read coin data - this is simplified; real impl needs streaming reader *)
              let buf_size = min 1024 remaining in
              let buf = really_input_string ic buf_size in
              let r = Serialize.reader_of_cstruct (Cstruct.of_string buf) in
              let coin = deserialize_coin r in
              (* Seek back to actual position *)
              seek_in ic (pos_in ic - buf_size + r.Serialize.pos);
              coin
            end in

            (* Add to UTXO cache *)
            let utxo_coin = {
              Utxo.txout = { Types.value = coin.value; script_pubkey = coin.script_pubkey };
              height = coin.height;
              is_coinbase = coin.is_coinbase;
            } in
            Utxo.UtxoCache.add_coin utxo_cache coin.outpoint utxo_coin ~possible_overwrite:false;

            coins_loaded := Int64.add !coins_loaded 1L;
            incr coins_in_batch;

            (* Flush batch periodically *)
            if !coins_in_batch >= batch_size then begin
              coins_in_batch := 0;
              let pct = 100.0 *. (Int64.to_float !coins_loaded) /. (Int64.to_float total) in
              on_progress { coins_loaded = !coins_loaded; total_coins = total; pct }
            end
          done;

          close_in ic;

          (* Flush UTXO cache to disk *)
          let _ = Lwt_main.run (Utxo.UtxoCache.flush utxo_cache) in

          (* Set chain tip *)
          Storage.ChainDB.set_chain_tip db metadata.base_blockhash params.height;

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
        | Failure msg -> Error msg
        | End_of_file -> Error "Unexpected end of snapshot file"
        | _ -> Error "Failed to load snapshot"
      end

(* ============================================================================
   Snapshot Creation (dumptxoutset)
   ============================================================================ *)

(** Dump the current UTXO set to a snapshot file *)
let dump_snapshot ~(chainstate : chainstate)
    ~(network : Consensus.network_config)
    ~(output_path : string)
    ?(on_progress : load_progress -> unit = fun _ -> ())
    ()
    : (snapshot_metadata, string) result =
  (* Count total coins first *)
  let total_coins = ref 0L in
  Storage.ChainDB.iter_utxos chainstate.db (fun _txid _vout _data ->
    total_coins := Int64.add !total_coins 1L
  );

  let metadata = {
    network_magic = network.magic;
    base_blockhash = chainstate.tip_hash;
    coins_count = !total_coins;
  } in

  try
    let oc = open_out_bin output_path in
    (* Write metadata *)
    let w = Serialize.writer_create () in
    serialize_metadata w metadata;
    output_string oc (Cstruct.to_string (Serialize.writer_to_cstruct w));

    (* Write coins *)
    let coins_written = ref 0L in
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
      let cw = Serialize.writer_create () in
      serialize_coin cw coin;
      output_string oc (Cstruct.to_string (Serialize.writer_to_cstruct cw));

      coins_written := Int64.add !coins_written 1L;
      if Int64.rem !coins_written 10000L = 0L then begin
        let pct = 100.0 *. (Int64.to_float !coins_written) /. (Int64.to_float !total_coins) in
        on_progress { coins_loaded = !coins_written; total_coins = !total_coins; pct }
      end
    );

    close_out oc;
    Ok metadata
  with
  | Sys_error msg -> Error ("Failed to write snapshot: " ^ msg)
  | _ -> Error "Failed to dump snapshot"

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
    ~(height : int) : (int64, string) result =
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
    let subsidy = Consensus.block_subsidy height in
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
          match Validation.validate_block_with_utxos ~network block next_height
                  ~expected_bits:header_entry.header.bits
                  ~median_time
                  ~base_lookup
                  ~flags
                  ~skip_scripts:false
                  () with
          | Error e ->
            bg_validation.state <- BgFailed (Validation.block_error_to_string e);
            snapshot_chainstate.assumeutxo_state <- Invalid;
            Logs.err (fun m -> m "[assumeutxo] Background validation failed at height %d: %s"
                        next_height (Validation.block_error_to_string e));
            Lwt.return_unit
          | Ok _fees ->
            (* Update IBD chainstate UTXO set with the block's changes *)
            (match connect_block_to_cache ~cache:ibd_chainstate.utxo_cache
                     ~block ~height:next_height with
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
   Activation
   ============================================================================ *)

(** Activate a snapshot chainstate, making it the active chainstate.
    The current IBD chainstate becomes the background chainstate. *)
let activate_snapshot ~(node_state : node_state)
    ~(snapshot_chainstate : chainstate)
    : (unit, string) result =
  (* Verify snapshot has more work than current tip *)
  if snapshot_chainstate.tip_height <= node_state.active_chainstate.tip_height then
    Error "Snapshot does not have more work than current chain"
  else begin
    (* Store old chainstate as background *)
    node_state.background_chainstate <- Some node_state.active_chainstate;
    (* Make snapshot the active chainstate *)
    node_state.active_chainstate <- snapshot_chainstate;
    node_state.snapshot_height <- Some snapshot_chainstate.tip_height;
    Logs.info (fun m -> m "[assumeutxo] Activated snapshot at height %d"
                 snapshot_chainstate.tip_height);
    Ok ()
  end
