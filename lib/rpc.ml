(* JSON-RPC 1.0/2.0 Server over HTTP

   Implements the standard Bitcoin RPC interface for querying blockchain state,
   submitting transactions, managing the wallet, and controlling the node.

   The server uses HTTP Basic authentication and responds to POST requests.
   Response format: {"result": ..., "error": null, "id": ...} on success
                    {"result": null, "error": {"code": N, "message": "..."}, "id": ...} on failure

   KNOWN PITFALL: All RPC requests must be POST. GET requests are rejected. *)

let log_src = Logs.Src.create "RPC" ~doc:"RPC server"
module Log = (val Logs.src_log log_src : Logs.LOG)
let _ = Log.info  (* suppress unused module warning *)

(* ============================================================================
   Standard Bitcoin RPC Error Codes
   ============================================================================ *)

type rpc_error = {
  code : int;
  message : string;
}

(* JSON-RPC 2.0 standard errors *)
let rpc_invalid_request = -32600
let rpc_method_not_found = -32601
let rpc_invalid_params = -32602
let rpc_internal_error = -32603
let rpc_parse_error = -32700

(* Bitcoin-specific error codes *)
let rpc_misc_error = -1
let rpc_type_error = -3
let rpc_invalid_address = -5
let rpc_wallet_error = -4
let rpc_insufficient_funds = -6
let rpc_deserialization_error = -22
let rpc_verify_error = -25
let rpc_verify_rejected = -26

(* ============================================================================
   RPC Context
   ============================================================================ *)

type rpc_context = {
  chain : Sync.chain_state;
  mempool : Mempool.mempool;
  peer_manager : Peer_manager.t;
  wallet : Wallet.t option;  (* Legacy: single wallet for backward compat *)
  wallet_manager : Wallet.wallet_manager option;  (* Multi-wallet support *)
  fee_estimator : Fee_estimation.t;
  network : Consensus.network_config;
  filter_index : Block_index.filter_index option;  (* BIP-157/158 block filter index *)
  utxo : Utxo.OptimizedUtxoSet.t option;  (* UTXO set for submitblock atomic writes *)
  data_dir : string option;  (* Datadir for dumpmempool / loadmempool — None disables *)
}

(* ============================================================================
   JSON-RPC Response Helpers
   ============================================================================ *)

let json_rpc_response ~(id : Yojson.Safe.t)
    ~(result : Yojson.Safe.t) : Yojson.Safe.t =
  `Assoc [
    ("result", result);
    ("error", `Null);
    ("id", id);
  ]

let json_rpc_error ~(id : Yojson.Safe.t)
    ~(code : int) ~(message : string) : Yojson.Safe.t =
  `Assoc [
    ("result", `Null);
    ("error", `Assoc [
      ("code", `Int code);
      ("message", `String message);
    ]);
    ("id", id);
  ]

(* ============================================================================
   Shared Deployment Helpers
   These helpers are shared by getblockchaininfo (.softforks) and
   getdeploymentinfo (.deployments) so both RPCs always read from the same
   source of truth: chainparams (network_config) + active chain state.
   ============================================================================ *)

(* Build a buried-deployment JSON object for a soft fork that activated at
   a specific height.  Returns a BIP9-style object (type = "buried") with:
     type, active, height, min_activation_height
   active = true when the block height we are querying is >= activation height. *)
let deployment_buried_json ~(name : string) ~(activation_height : int)
    ~(query_height : int) : string * Yojson.Safe.t =
  let active = query_height >= activation_height in
  (name, `Assoc [
    ("type",                  `String "buried");
    ("active",                `Bool active);
    ("height",                `Int activation_height);
    ("min_activation_height", `Int activation_height);
  ])

(* Build a BIP9-deployment JSON object for a deployment that uses the
   version-bits state machine.  Returns the full bip9 sub-object and outer
   wrapper matching Bitcoin Core's getdeploymentinfo output shape. *)
let deployment_bip9_json
    ~(dep : Consensus.deployment)
    ~(query_height : int)
    ~(get_block : int -> Consensus.block_index option)
    ~(cache : Consensus.deployment_cache ref)
    : string * Yojson.Safe.t =
  let state = Consensus.get_deployment_state
    ~dep ~height:query_height ~get_block
    ~count_signals:(fun ~start_height ->
      Consensus.count_signals_in_period ~dep ~start_height ~get_block)
    ~cache
  in
  let status_str = Consensus.string_of_deployment_state state in

  (* Compute the "since" block — the start of the retarget period in which
     the current state first became active.  We walk back through periods
     to find the one that last changed the state. *)
  let since =
    let period = dep.period in
    let rec find_since h =
      if h <= 0 then 0
      else
        let prev_period = h - period in
        let prev_state = Consensus.get_deployment_state
          ~dep ~height:(max 0 (prev_period - 1))
          ~get_block
          ~count_signals:(fun ~start_height ->
            Consensus.count_signals_in_period ~dep ~start_height ~get_block)
          ~cache
        in
        if prev_state <> state then h
        else find_since prev_period
    in
    let period_start = query_height - (query_height mod period) in
    find_since period_start
  in

  let bip9_fields = ref [
    ("start_time",           `Int (Int64.to_int dep.start_time));
    ("timeout",              `Int (Int64.to_int dep.timeout));
    ("min_activation_height",`Int dep.min_activation_height);
    ("status",               `String status_str);
    ("since",                `Int since);
  ] in

  (match state with
   | Consensus.Started | Consensus.LockedIn ->
     bip9_fields := ("bit", `Int dep.bit) :: !bip9_fields
   | _ -> ());

  (match state with
   | Consensus.Started | Consensus.LockedIn ->
     let stats = Consensus.get_bip9_stats ~dep ~height:query_height ~get_block in
     let stats_obj = `Assoc [
       ("period",    `Int stats.period_length);
       ("threshold", `Int stats.threshold_count);
       ("elapsed",   `Int stats.elapsed);
       ("count",     `Int stats.signaling_count);
       ("possible",  `Bool stats.possible);
     ] in
     bip9_fields := ("statistics", stats_obj) :: !bip9_fields
   | _ -> ());

  let active = state = Consensus.Active in

  let outer_fields = ref [
    ("type",   `String "bip9");
    ("active", `Bool active);
    ("bip9",   `Assoc (List.rev !bip9_fields));
  ] in

  (if active then
     outer_fields := ("height", `Int dep.min_activation_height) :: !outer_fields);

  (dep.name, `Assoc (List.rev !outer_fields))

(* build_deployments_assoc: canonical deployment list for a given chain state.
   Both getblockchaininfo (.softforks) and getdeploymentinfo (.deployments)
   call this function so they always read from the same source of truth.
   Returns an association list of (name, json_object) pairs. *)
let build_deployments_assoc
    ~(net : Consensus.network_config)
    ~(query_height : int)
    ~(get_block : int -> Consensus.block_index option)
    : (string * Yojson.Safe.t) list =
  let taproot_cache   = ref Consensus.DeploymentCache.empty in
  let testdummy_cache = ref Consensus.DeploymentCache.empty in

  let buried = [
    deployment_buried_json ~name:"bip34" ~activation_height:net.bip34_height ~query_height;
    deployment_buried_json ~name:"bip65" ~activation_height:net.bip65_height ~query_height;
    deployment_buried_json ~name:"bip66" ~activation_height:net.bip66_height ~query_height;
    deployment_buried_json ~name:"csv"   ~activation_height:net.csv_height   ~query_height;
    deployment_buried_json ~name:"segwit"~activation_height:net.segwit_height~query_height;
  ] in

  let taproot_dep = match net.network_type with
    | Consensus.Mainnet  -> Consensus.mainnet_taproot
    | Consensus.Testnet4 -> Consensus.testnet4_taproot
    | Consensus.Regtest  -> Consensus.regtest_taproot
    | Consensus.Testnet3 -> Consensus.mainnet_taproot
  in
  let bip9_deps = [
    (taproot_dep,                    taproot_cache);
    (Consensus.testdummy_deployment, testdummy_cache);
  ] in
  let bip9 = List.map (fun (dep, cache) ->
    deployment_bip9_json ~dep ~query_height ~get_block ~cache
  ) bip9_deps in

  buried @ bip9

(* make_get_block: build the block-index lookup function used by the BIP9
   state machine from a chain_state. *)
let make_get_block (chain : Sync.chain_state) (h : int)
    : Consensus.block_index option =
  match Sync.get_header_at_height chain h with
  | None -> None
  | Some e ->
    let mtp = Sync.compute_median_time_past chain h in
    Some Consensus.{
      height           = e.height;
      version          = e.header.version;
      median_time_past = Int64.of_int32 mtp;
    }

(* ============================================================================
   Formatting Helpers (used by multiple handlers below)
   ============================================================================ *)

(* Render a Cstruct as a lowercase hex string. *)
let cstruct_to_hex_early (cs : Cstruct.t) : string =
  let len = Cstruct.length cs in
  let buf = Buffer.create (len * 2) in
  for i = 0 to len - 1 do
    Buffer.add_string buf (Printf.sprintf "%02x" (Cstruct.get_uint8 cs i))
  done;
  Buffer.contents buf

(* Convert compact bits to 64-char big-endian hex target string (Core format).
   compact_to_target returns little-endian (byte 0 = LSB); iterate 31..0 for
   MSB-first display order matching Bitcoin Core. *)
let bits_to_target_hex (bits : int32) : string =
  let target = Consensus.compact_to_target bits in
  let buf = Buffer.create 64 in
  for i = 31 downto 0 do
    Buffer.add_string buf (Printf.sprintf "%02x" (Cstruct.get_uint8 target i))
  done;
  Buffer.contents buf

(* ============================================================================
   Blockchain Info Handlers
   ============================================================================ *)

let handle_getblockchaininfo (ctx : rpc_context)
    : Yojson.Safe.t =
  let tip_entry = ctx.chain.tip in
  let _tip_height, tip_hash = match tip_entry with
    | Some t -> (t.height,
        Types.hash256_to_hex_display t.hash)
    | None -> (0, "0000000000000000000000000000000000000000000000000000000000000000")
  in
  let difficulty = match tip_entry with
    | Some t -> Consensus.difficulty_from_bits t.header.bits
    | None -> 1.0
  in
  let chainwork = match tip_entry with
    | Some t -> Types.hash256_to_hex_display t.total_work
    | None -> "0000000000000000000000000000000000000000000000000000000000000000"
  in
  let tip_bits_hex = match tip_entry with
    | Some t -> Printf.sprintf "%08lx" t.header.bits
    | None -> "1d00ffff"
  in
  let tip_target_hex = match tip_entry with
    | Some t -> bits_to_target_hex t.header.bits
    | None -> String.make 64 '0'
  in
  let tip_time = match tip_entry with
    | Some t -> Int32.to_int t.header.timestamp
    | None -> 0
  in
  let validated_height = ctx.chain.blocks_synced in
  (* Build softforks using the shared helper so the data matches
     getdeploymentinfo exactly — same source, same state machine. *)
  let query_height = match tip_entry with Some t -> t.height | None -> 0 in
  let get_block = make_get_block ctx.chain in
  let softforks = `Assoc (build_deployments_assoc
    ~net:ctx.network ~query_height ~get_block) in
  let base_fields = [
    ("chain", `String ctx.network.name);
    ("blocks", `Int validated_height);
    ("headers", `Int ctx.chain.headers_synced);
    ("bestblockhash", `String tip_hash);
    ("difficulty", `Float difficulty);
    ("time", `Int tip_time);
    ("mediantime", `Int 0);
    ("verificationprogress", `Float
      (if ctx.chain.headers_synced = 0 then 0.0
       else float_of_int validated_height /.
            float_of_int ctx.chain.headers_synced));
    ("initialblockdownload",
      `Bool (ctx.chain.sync_state <> Sync.FullySynced));
    ("chainwork", `String chainwork);
    ("bits", `String tip_bits_hex);
    ("target", `String tip_target_hex);
    ("size_on_disk", `Int 0);
    ("pruned", `Bool (ctx.chain.prune_target > 0));
  ] @
  (if ctx.chain.prune_target > 0 then
    [("pruneheight", `Int ctx.chain.prune_height);
     ("prune_target_size", `Int ctx.chain.prune_target)]
   else []) @
  [
    ("softforks", softforks);
    ("warnings", `String "");
  ] in
  `Assoc base_fields

let handle_getblockhash (ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  match params with
  | [`Int height] ->
    (match Storage.ChainDB.get_hash_at_height ctx.chain.db height with
     | Some hash ->
       Ok (`String (Types.hash256_to_hex_display hash))
     | None ->
       Error "Block height out of range")
  | _ ->
    Error "Invalid parameters: expected [height]"

let handle_getblock (ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  match params with
  | [`String hash_hex] | [`String hash_hex; `Int _] ->
    (* Parse hash in display format (reversed) *)
    let hash_bytes = Types.hash256_of_hex hash_hex in
    (* Reverse for internal format *)
    let hash = Cstruct.create 32 in
    for i = 0 to 31 do
      Cstruct.set_uint8 hash i (Cstruct.get_uint8 hash_bytes (31 - i))
    done;
    (match Storage.ChainDB.get_block ctx.chain.db hash with
     | None -> Error "Block not found"
     | Some block ->
       (* Get height and total_work from header entry *)
       let entry = Sync.get_header ctx.chain hash in
       let height = match entry with
         | Some e -> e.height
         | None -> 0
       in
       let chainwork = match entry with
         | Some e -> Types.hash256_to_hex_display e.total_work
         | None -> "0000000000000000000000000000000000000000000000000000000000000000"
       in
       (* Compute block sizes *)
       let w_total = Serialize.writer_create () in
       Serialize.serialize_block w_total block;
       let total_size = Cstruct.length (Serialize.writer_to_cstruct w_total) in
       let total_weight =
         (* Header weight = 80 * 4, plus sum of tx weights *)
         80 * Consensus.witness_scale_factor +
         List.fold_left (fun acc tx -> acc + Validation.compute_tx_weight tx) 0 block.transactions
       in
       (* Stripped size = (total_weight - total_size) / 3 *)
       let stripped_size = (total_weight - total_size) / 3 in
       let tip_height = match ctx.chain.tip with Some t -> t.height | None -> 0 in
       let confirmations = tip_height - height + 1 in
       let median_time = Sync.compute_median_time_past ctx.chain height in
       Ok (`Assoc [
         ("hash", `String hash_hex);
         ("confirmations", `Int confirmations);
         ("size", `Int total_size);
         ("strippedsize", `Int stripped_size);
         ("weight", `Int total_weight);
         ("height", `Int height);
         ("version", `Int (Int32.to_int block.header.version));
         ("versionHex", `String (Printf.sprintf "%08lx" block.header.version));
         ("merkleroot", `String
           (Types.hash256_to_hex_display block.header.merkle_root));
         ("tx", `List (List.map (fun tx ->
           `String (Types.hash256_to_hex_display (Crypto.compute_txid tx))
         ) block.transactions));
         ("time", `Int (Int32.to_int block.header.timestamp));
         ("mediantime", `Int (Int32.to_int median_time));
         ("nonce", `Int (Int32.to_int block.header.nonce));
         ("bits", `String (Printf.sprintf "%08lx" block.header.bits));
         ("target", `String (bits_to_target_hex block.header.bits));
         ("difficulty", `Float (Consensus.difficulty_from_bits block.header.bits));
         ("chainwork", `String chainwork);
         ("nTx", `Int (List.length block.transactions));
         ("previousblockhash", `String
           (Types.hash256_to_hex_display block.header.prev_block));
         ("coinbase_tx",
           (match block.transactions with
            | [] -> `Null
            | cb :: _ ->
              let seq_val = match cb.Types.inputs with
                | inp :: _ -> Int32.to_int inp.Types.sequence
                | [] -> 0
              in
              let script_hex = match cb.Types.inputs with
                | inp :: _ -> cstruct_to_hex_early inp.Types.script_sig
                | [] -> ""
              in
              let witness_hex = match cb.Types.witnesses with
                | w :: _ when w.Types.items <> [] ->
                  Some (cstruct_to_hex_early (List.hd w.Types.items))
                | _ -> None
              in
              let base = [
                ("version", `Int (Int32.to_int cb.Types.version));
                ("locktime", `Int (Int32.to_int cb.Types.locktime));
                ("sequence", `Int seq_val);
                ("coinbase", `String script_hex);
              ] in
              `Assoc (match witness_hex with
                | Some h -> base @ [("witness", `String h)]
                | None -> base)));
       ]))
  | _ ->
    Error "Invalid parameters: expected [blockhash] or [blockhash, verbosity]"

let handle_getblockheader (ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  match params with
  | [`String hash_hex] | [`String hash_hex; `Bool true] ->
    let hash_bytes = Types.hash256_of_hex hash_hex in
    let hash = Cstruct.create 32 in
    for i = 0 to 31 do
      Cstruct.set_uint8 hash i (Cstruct.get_uint8 hash_bytes (31 - i))
    done;
    (match Storage.ChainDB.get_block_header ctx.chain.db hash with
     | None -> Error "Block header not found"
     | Some header ->
       let entry = Sync.get_header ctx.chain hash in
       let height = match entry with
         | Some e -> e.height
         | None -> 0
       in
       let chainwork = match entry with
         | Some e -> Types.hash256_to_hex_display e.total_work
         | None -> "0000000000000000000000000000000000000000000000000000000000000000"
       in
       let tip_height = match ctx.chain.tip with Some t -> t.height | None -> 0 in
       let confirmations = tip_height - height + 1 in
       let median_time = Sync.compute_median_time_past ctx.chain height in
       let n_tx = match Storage.ChainDB.get_block ctx.chain.db hash with
         | Some block -> List.length block.transactions
         | None -> 0
       in
       Ok (`Assoc [
         ("hash", `String hash_hex);
         ("confirmations", `Int confirmations);
         ("height", `Int height);
         ("version", `Int (Int32.to_int header.version));
         ("versionHex", `String (Printf.sprintf "%08lx" header.version));
         ("merkleroot", `String
           (Types.hash256_to_hex_display header.merkle_root));
         ("time", `Int (Int32.to_int header.timestamp));
         ("mediantime", `Int (Int32.to_int median_time));
         ("nonce", `Int (Int32.to_int header.nonce));
         ("bits", `String (Printf.sprintf "%08lx" header.bits));
         ("difficulty", `Float (Consensus.difficulty_from_bits header.bits));
         ("chainwork", `String chainwork);
         ("nTx", `Int n_tx);
         ("previousblockhash", `String
           (Types.hash256_to_hex_display header.prev_block));
       ]))
  | [`String hash_hex; `Bool false] ->
    (* Return raw hex *)
    let hash_bytes = Types.hash256_of_hex hash_hex in
    let hash = Cstruct.create 32 in
    for i = 0 to 31 do
      Cstruct.set_uint8 hash i (Cstruct.get_uint8 hash_bytes (31 - i))
    done;
    (match Storage.ChainDB.get_block_header ctx.chain.db hash with
     | None -> Error "Block header not found"
     | Some header ->
       let w = Serialize.writer_create () in
       Serialize.serialize_block_header w header;
       let cs = Serialize.writer_to_cstruct w in
       (* W27-A: serialized header is 80 bytes; hash256_to_hex is 32-only
          and would silently truncate. *)
       let hex = cstruct_to_hex_early cs in
       Ok (`String hex))
  | _ ->
    Error "Invalid parameters: expected [blockhash] or [blockhash, verbose]"

let handle_getblockcount (ctx : rpc_context) : Yojson.Safe.t =
  `Int ctx.chain.blocks_synced

let handle_getbestblockhash (ctx : rpc_context) : Yojson.Safe.t =
  match ctx.chain.tip with
  | Some t -> `String (Types.hash256_to_hex_display t.hash)
  | None -> `String "0000000000000000000000000000000000000000000000000000000000000000"

(* hashhog W70: uniform fleet-wide sync-state report.
   Spec: meta-repo `spec/getsyncstate.md`.

   SHOULD fields return JSON `Null (not omitted) so consumer parsers
   can index by key without presence checks. blocks_in_flight,
   blocks_pending_connect, and last_block_received_time are null in
   v1 because rpc_context does not currently carry the ibd_state. *)
let handle_getsyncstate (ctx : rpc_context) : Yojson.Safe.t =
  let zero_hash =
    "0000000000000000000000000000000000000000000000000000000000000000" in
  let tip_hash = match ctx.chain.tip with
    | Some t -> Types.hash256_to_hex_display t.hash
    | None -> zero_hash
  in
  let tip_height = ctx.chain.blocks_synced in
  let header_height = max ctx.chain.headers_synced tip_height in
  (* No distinct header-tip hash tracked in chain_state; tip_hash is
     the best we can offer in v1 without a larger refactor. *)
  let best_header_hash = tip_hash in
  let is_ibd = ctx.chain.sync_state <> Sync.FullySynced in
  let num_peers = Peer_manager.peer_count ctx.peer_manager in
  let chain_name = match ctx.network.name with
    | "mainnet" -> "main"
    | "testnet3" -> "test"
    | other -> other
  in
  let progress =
    if header_height = 0 then 0.0
    else
      let p = float_of_int tip_height /. float_of_int header_height in
      if p > 1.0 then 1.0 else p
  in
  `Assoc [
    ("tip_height", `Int tip_height);
    ("tip_hash", `String tip_hash);
    ("best_header_height", `Int header_height);
    ("best_header_hash", `String best_header_hash);
    ("initial_block_download", `Bool is_ibd);
    ("num_peers", `Int num_peers);
    ("verification_progress", `Float progress);
    ("blocks_in_flight", `Null);
    ("blocks_pending_connect", `Null);
    ("last_block_received_time", `Null);
    ("chain", `String chain_name);
    ("protocol_version", `Int (Int32.to_int Types.protocol_version));
  ]

let handle_getdifficulty (ctx : rpc_context) : Yojson.Safe.t =
  match ctx.chain.tip with
  | Some t -> `Float (Consensus.difficulty_from_bits t.header.bits)
  | None -> `Float 1.0

(* getchaintips — return the set of chain tips known to this node.
   Camlcoin only tracks the active chain, so we always return exactly
   one entry with status "active" and branchlen 0 (same as beamchain).
   Bitcoin Core: src/rpc/blockchain.cpp::getchaintips *)
let handle_getchaintips (ctx : rpc_context) : Yojson.Safe.t =
  match ctx.chain.tip with
  | Some t ->
    `List [`Assoc [
      ("height",    `Int t.height);
      ("hash",      `String (Types.hash256_to_hex_display t.hash));
      ("branchlen", `Int 0);
      ("status",    `String "active");
    ]]
  | None ->
    `List []

(* ============================================================================
   Block Filter Handler (BIP-157/158)
   ============================================================================ *)

let handle_getblockfilter (ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  match ctx.filter_index with
  | None -> Error "Block filter index is not enabled"
  | Some idx ->
    (match params with
     | [`String hash_hex] | [`String hash_hex; `String "basic"] ->
       (* Parse hash in display format (reversed) *)
       let hash_bytes = Types.hash256_of_hex hash_hex in
       let hash = Cstruct.create 32 in
       for i = 0 to 31 do
         Cstruct.set_uint8 hash i (Cstruct.get_uint8 hash_bytes (31 - i))
       done;
       (match Block_index.read_filter idx hash with
        | None -> Error "Block filter not found"
        | Some bf ->
          (* Get filter header *)
          let header_opt = Block_index.get_filter_header idx hash in
          let header_hex = match header_opt with
            | Some h -> Types.hash256_to_hex_display h
            | None -> ""
          in
          Ok (`Assoc [
            (* W27-A: BIP-158 filter is variable-length (potentially KB);
               hash256_to_hex would silently truncate to 32 bytes. *)
            ("filter", `String (cstruct_to_hex_early
              (Cstruct.of_string bf.filter.Block_index.encoded)));
            ("header", `String header_hex);
          ]))
     | _ ->
       Error "Invalid parameters: expected [blockhash] or [blockhash, \"basic\"]")

(* ============================================================================
   Block Invalidation Handlers
   ============================================================================ *)

(* Parse block hash from hex display format (reversed) to internal format *)
let parse_blockhash_hex (hex : string) : (Types.hash256, string) result =
  let hex = String.lowercase_ascii hex in
  if String.length hex <> 64 then
    Error "Invalid block hash: must be 64 hex characters"
  else begin
    let hash_bytes = Types.hash256_of_hex hex in
    (* Reverse for internal format *)
    let hash = Cstruct.create 32 in
    for i = 0 to 31 do
      Cstruct.set_uint8 hash i (Cstruct.get_uint8 hash_bytes (31 - i))
    done;
    Ok hash
  end

(* invalidateblock - permanently marks a block as invalid *)
let handle_invalidateblock (ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  match params with
  | [`String blockhash_hex] ->
    (match parse_blockhash_hex blockhash_hex with
     | Error msg -> Error msg
     | Ok hash ->
       match Sync.invalidate_block ctx.chain hash with
       | Ok _new_height -> Ok `Null
       | Error msg -> Error msg)
  | _ ->
    Error "Invalid parameters: expected [blockhash]"

(* reconsiderblock - removes invalidity status of a block *)
let handle_reconsiderblock (ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  match params with
  | [`String blockhash_hex] ->
    (match parse_blockhash_hex blockhash_hex with
     | Error msg -> Error msg
     | Ok hash ->
       match Sync.reconsider_block ctx.chain hash with
       | Ok _new_height -> Ok `Null
       | Error msg -> Error msg)
  | _ ->
    Error "Invalid parameters: expected [blockhash]"

(* ============================================================================
   Transaction Handlers
   ============================================================================ *)

(* Convert network config to Address.network based on bech32_hrp *)
let network_to_address_network (config : Consensus.network_config) : Address.network =
  match config.bech32_hrp with
  | "bc" -> `Mainnet
  | "tb" -> `Testnet
  | "bcrt" -> `Regtest
  | _ -> `Mainnet  (* Default to mainnet if unknown *)

(* Convert Cstruct to hex string (for arbitrary length data) *)
let cstruct_to_hex (cs : Cstruct.t) : string =
  let len = Cstruct.length cs in
  let buf = Buffer.create (len * 2) in
  for i = 0 to len - 1 do
    Buffer.add_string buf (Printf.sprintf "%02x" (Cstruct.get_uint8 cs i))
  done;
  Buffer.contents buf

(* Convert hex string to Cstruct *)
let hex_to_cstruct (s : string) : Cstruct.t =
  let len = String.length s / 2 in
  let buf = Cstruct.create len in
  for i = 0 to len - 1 do
    let byte = int_of_string ("0x" ^ String.sub s (i * 2) 2) in
    Cstruct.set_uint8 buf i byte
  done;
  buf

(* Get script type name for JSON output *)
let script_type_name (template : Script.script_template) : string =
  match template with
  | Script.P2PKH_script _ -> "pubkeyhash"
  | Script.P2SH_script _ -> "scripthash"
  | Script.P2WPKH_script _ -> "witness_v0_keyhash"
  | Script.P2WSH_script _ -> "witness_v0_scripthash"
  | Script.P2TR_script _ -> "witness_v1_taproot"
  | Script.P2A_script -> "anchor"
  | Script.OP_RETURN_data _ -> "nulldata"
  | Script.Nonstandard -> "nonstandard"

(* Get address from scriptPubKey if applicable *)
let script_to_address (script : Cstruct.t) (network : Address.network) : string option =
  match Script.classify_script script with
  | Script.P2PKH_script hash ->
    Some (Address.address_to_string { addr_type = P2PKH; hash; network })
  | Script.P2SH_script hash ->
    Some (Address.address_to_string { addr_type = P2SH; hash; network })
  | Script.P2WPKH_script hash ->
    Some (Address.address_to_string { addr_type = P2WPKH; hash; network })
  | Script.P2WSH_script hash ->
    Some (Address.address_to_string { addr_type = P2WSH; hash; network })
  | Script.P2TR_script hash ->
    Some (Address.address_to_string { addr_type = P2TR; hash; network })
  | Script.P2A_script | Script.OP_RETURN_data _ | Script.Nonstandard -> None

(* Build scriptPubKey JSON object with type and optional address *)
let build_script_pubkey_json (script : Cstruct.t) (network : Address.network) : Yojson.Safe.t =
  let template = Script.classify_script script in
  let type_name = script_type_name template in
  let hex = cstruct_to_hex script in
  let base_fields = [
    ("hex", `String hex);
    ("type", `String type_name);
  ] in
  let with_address = match script_to_address script network with
    | Some addr -> base_fields @ [("address", `String addr)]
    | None -> base_fields
  in
  `Assoc with_address

(* Check if input is coinbase (all zeros txid, vout = 0xFFFFFFFF) *)
let is_coinbase_input (inp : Types.tx_in) : bool =
  let all_zeros = Cstruct.for_all (fun b -> b = '\x00') inp.previous_output.txid in
  all_zeros && inp.previous_output.vout = 0xFFFFFFFFl

(* Build vin JSON for a transaction *)
let build_vin_json (tx : Types.transaction) : Yojson.Safe.t list =
  List.mapi (fun i inp ->
    let witness_items =
      if i < List.length tx.witnesses then
        `List (List.map (fun item ->
          `String (cstruct_to_hex item)
        ) (List.nth tx.witnesses i).items)
      else
        `List []
    in
    if is_coinbase_input inp then
      (* Coinbase input *)
      `Assoc [
        ("coinbase", `String (cstruct_to_hex inp.script_sig));
        ("txinwitness", witness_items);
        ("sequence", `Int (Int32.to_int inp.sequence));
      ]
    else
      (* Regular input *)
      `Assoc [
        ("txid", `String (Types.hash256_to_hex_display inp.previous_output.txid));
        ("vout", `Int (Int32.to_int inp.previous_output.vout));
        ("scriptSig", `Assoc [
          ("hex", `String (cstruct_to_hex inp.script_sig));
        ]);
        ("txinwitness", witness_items);
        ("sequence", `Int (Int32.to_int inp.sequence));
      ]
  ) tx.inputs

(* Build vout JSON for a transaction *)
let build_vout_json (tx : Types.transaction) (network : Address.network) : Yojson.Safe.t list =
  List.mapi (fun i out ->
    `Assoc [
      ("value", `Float (Int64.to_float out.Types.value /. 100_000_000.0));
      ("n", `Int i);
      ("scriptPubKey", build_script_pubkey_json out.script_pubkey network);
    ]
  ) tx.outputs

(* Serialize transaction to hex *)
let tx_to_hex (tx : Types.transaction) : string =
  let w = Serialize.writer_create () in
  Serialize.serialize_transaction w tx;
  let cs = Serialize.writer_to_cstruct w in
  cstruct_to_hex cs

(* Lookup transaction in mempool, specific block, or txindex *)
type tx_location =
  | InMempool
  | InBlock of Types.hash256 * int (* block_hash, tx_index *)

let lookup_transaction (ctx : rpc_context) (txid : Cstruct.t)
    (blockhash_opt : Cstruct.t option) : (Types.transaction * tx_location option, string) result =
  let txid_key = Cstruct.to_string txid in

  (* If blockhash is specified, search only in that block *)
  match blockhash_opt with
  | Some block_hash ->
    (match Storage.ChainDB.get_block ctx.chain.db block_hash with
     | None -> Error "Block not found"
     | Some block ->
       (* Search for transaction in block *)
       let rec find_tx idx = function
         | [] -> None
         | tx :: rest ->
           let tx_txid = Crypto.compute_txid tx in
           if Cstruct.equal tx_txid txid then
             Some (tx, idx)
           else
             find_tx (idx + 1) rest
       in
       match find_tx 0 block.transactions with
       | Some (tx, idx) -> Ok (tx, Some (InBlock (block_hash, idx)))
       | None -> Error "No such transaction found in the provided block")
  | None ->
    (* Check mempool first *)
    match Hashtbl.find_opt ctx.mempool.entries txid_key with
    | Some entry -> Ok (entry.tx, Some InMempool)
    | None ->
      (* Check txindex for confirmed tx *)
      match Storage.ChainDB.get_tx_index ctx.chain.db txid with
      | Some (block_hash, tx_idx) ->
        (match Storage.ChainDB.get_transaction ctx.chain.db txid with
         | Some tx -> Ok (tx, Some (InBlock (block_hash, tx_idx)))
         | None -> Error "Transaction indexed but not found")
      | None ->
        (* Try getting transaction directly (may be in storage without index) *)
        match Storage.ChainDB.get_transaction ctx.chain.db txid with
        | Some tx -> Ok (tx, None) (* No block info available *)
        | None -> Error "No such mempool or blockchain transaction. Use -txindex or provide a block hash"

(* Get block height from block hash *)
let get_block_height (ctx : rpc_context) (block_hash : Cstruct.t) : int option =
  match Sync.get_header ctx.chain block_hash with
  | Some entry -> Some entry.height
  | None -> None

(* Get block timestamp from block hash *)
let get_block_time (ctx : rpc_context) (block_hash : Cstruct.t) : int32 option =
  match Storage.ChainDB.get_block_header ctx.chain.db block_hash with
  | Some header -> Some header.timestamp
  | None -> None

(* Handle getrawtransaction RPC
   Params: txid (hex), verbosity (int/bool, default 0), blockhash (hex, optional)
   - verbosity=0: return raw hex
   - verbosity=1: return decoded JSON with block info
   - verbosity=2: return decoded JSON with fee and prevout info (TODO: prevout) *)
let handle_getrawtransaction (ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =

  (* Parse parameters *)
  let parse_verbosity = function
    | `Bool false | `Int 0 -> Some 0
    | `Bool true | `Int 1 -> Some 1
    | `Int 2 -> Some 2
    | `Int n when n >= 0 && n <= 2 -> Some n
    | _ -> None
  in

  let parse_blockhash hex =
    try
      let hash_bytes = Types.hash256_of_hex hex in
      let hash = Cstruct.create 32 in
      for i = 0 to 31 do
        Cstruct.set_uint8 hash i (Cstruct.get_uint8 hash_bytes (31 - i))
      done;
      Some hash
    with _ -> None
  in

  let parse_txid hex =
    try
      let txid_bytes = Types.hash256_of_hex hex in
      let txid = Cstruct.create 32 in
      for i = 0 to 31 do
        Cstruct.set_uint8 txid i (Cstruct.get_uint8 txid_bytes (31 - i))
      done;
      Some txid
    with _ -> None
  in

  (* Extract params *)
  let (txid_hex, verbosity, blockhash_opt) = match params with
    | [`String txid_hex] ->
      (Some txid_hex, 0, None)
    | [`String txid_hex; v] ->
      (Some txid_hex, Option.value ~default:0 (parse_verbosity v), None)
    | [`String txid_hex; v; `String bh] ->
      (Some txid_hex, Option.value ~default:0 (parse_verbosity v), parse_blockhash bh)
    | [`String txid_hex; v; `Null] ->
      (Some txid_hex, Option.value ~default:0 (parse_verbosity v), None)
    | _ -> (None, 0, None)
  in

  match txid_hex with
  | None -> Error "Invalid parameters: expected [txid] or [txid, verbose] or [txid, verbose, blockhash]"
  | Some txid_hex ->
    match parse_txid txid_hex with
    | None -> Error "Invalid txid"
    | Some txid ->
      match lookup_transaction ctx txid blockhash_opt with
      | Error e -> Error e
      | Ok (tx, location) ->
        (* Verbosity 0: return raw hex *)
        if verbosity = 0 then
          Ok (`String (tx_to_hex tx))
        else begin
          (* Verbose mode: build full JSON response *)
          let network = network_to_address_network ctx.network in
          let wtxid = Crypto.compute_wtxid tx in
          let vin = build_vin_json tx in
          let vout = build_vout_json tx network in
          let hex = tx_to_hex tx in

          (* Base transaction fields *)
          let base_fields = [
            ("txid", `String txid_hex);
            ("hash", `String (Types.hash256_to_hex_display wtxid));
            ("version", `Int (Int32.to_int tx.version));
            ("size", `Int (Validation.compute_tx_size tx));
            ("vsize", `Int (Validation.compute_tx_vsize tx));
            ("weight", `Int (Validation.compute_tx_weight tx));
            ("locktime", `Int (Int32.to_int tx.locktime));
            ("vin", `List vin);
            ("vout", `List vout);
            ("hex", `String hex);
          ] in

          (* Add block info if confirmed *)
          let with_block_info = match location with
            | Some InMempool ->
              (* Mempool transaction has no confirmations *)
              base_fields
            | Some (InBlock (block_hash, _tx_idx)) ->
              let blockhash_hex = Types.hash256_to_hex_display block_hash in
              let tip_height = match ctx.chain.tip with Some t -> t.height | None -> 0 in
              let block_height = Option.value ~default:0 (get_block_height ctx block_hash) in
              let confirmations = tip_height - block_height + 1 in
              let blocktime = match get_block_time ctx block_hash with
                | Some t -> Int32.to_int t
                | None -> 0
              in
              base_fields @ [
                ("blockhash", `String blockhash_hex);
                ("confirmations", `Int confirmations);
                ("time", `Int blocktime);
                ("blocktime", `Int blocktime);
              ]
            | None ->
              (* Transaction found but no block info available *)
              base_fields
          in

          Ok (`Assoc with_block_info)
        end

(* Default constants for sendrawtransaction *)
let default_max_raw_tx_fee_rate = 0.10  (* 0.10 BTC/kvB *)
let default_max_burn_amount = 0L        (* 0 BTC by default *)

(* Check if a scriptPubKey is provably unspendable (OP_RETURN or invalid ops) *)
let is_unspendable_script (script : Cstruct.t) : bool =
  if Cstruct.length script = 0 then false
  else
    (* OP_RETURN (0x6a) at the start makes it unspendable *)
    Cstruct.get_uint8 script 0 = 0x6a

(* Sum up the value of all unspendable (OP_RETURN) outputs in satoshis *)
let sum_burn_amount (tx : Types.transaction) : int64 =
  List.fold_left (fun acc out ->
    if is_unspendable_script out.Types.script_pubkey then
      Int64.add acc out.Types.value
    else acc
  ) 0L tx.outputs

let handle_sendrawtransaction (ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  (* Parse parameters: hexstring [, maxfeerate [, maxburnamount]] *)
  let parse_params params =
    match params with
    | [`String hex] ->
      Ok (hex, default_max_raw_tx_fee_rate, default_max_burn_amount)
    | [`String hex; `Float maxfeerate] ->
      Ok (hex, maxfeerate, default_max_burn_amount)
    | [`String hex; `Int maxfeerate] ->
      Ok (hex, float_of_int maxfeerate, default_max_burn_amount)
    | [`String hex; `Float maxfeerate; `Float maxburn] ->
      (* Convert BTC to satoshis *)
      let maxburn_sats = Int64.of_float (maxburn *. 100_000_000.0) in
      Ok (hex, maxfeerate, maxburn_sats)
    | [`String hex; `Float maxfeerate; `Int maxburn] ->
      (* Integer BTC to satoshis *)
      let maxburn_sats = Int64.mul (Int64.of_int maxburn) 100_000_000L in
      Ok (hex, maxfeerate, maxburn_sats)
    | [`String hex; `Int maxfeerate; `Float maxburn] ->
      let maxburn_sats = Int64.of_float (maxburn *. 100_000_000.0) in
      Ok (hex, float_of_int maxfeerate, maxburn_sats)
    | [`String hex; `Int maxfeerate; `Int maxburn] ->
      let maxburn_sats = Int64.mul (Int64.of_int maxburn) 100_000_000L in
      Ok (hex, float_of_int maxfeerate, maxburn_sats)
    | _ ->
      Error "Invalid parameters: expected [hexstring] or [hexstring, maxfeerate] or [hexstring, maxfeerate, maxburnamount]"
  in
  match parse_params params with
  | Error e -> Error e
  | Ok (hex, max_fee_rate, max_burn_amount) ->
    (try
      let data = Cstruct.of_hex hex in
      let r = Serialize.reader_of_cstruct data in
      let tx = Serialize.deserialize_transaction r in

      (* Check burn amount before mempool validation *)
      let burn_amount = sum_burn_amount tx in
      if burn_amount > max_burn_amount then
        Error (Printf.sprintf
          "Unspendable output exceeds maximum: %Ld > %Ld satoshis"
          burn_amount max_burn_amount)
      else
        match Mempool.add_transaction ctx.mempool tx with
        | Ok entry ->
          (* Check fee rate limit (maxfeerate in BTC/kvB)
             Convert to satoshis per vbyte: BTC/kvB * 100_000_000 / 1000 = sat/vB
             Then multiply by vsize to get max acceptable fee *)
          let vsize = (entry.weight + 3) / 4 in
          let max_fee_sats =
            if max_fee_rate <= 0.0 then Int64.max_int
            else Int64.of_float (max_fee_rate *. 100_000_000.0 /. 1000.0 *. float_of_int vsize)
          in
          if entry.fee > max_fee_sats && max_fee_rate > 0.0 then begin
            (* Transaction fee too high - remove from mempool and reject *)
            Mempool.remove_transaction ctx.mempool entry.txid;
            Error (Printf.sprintf
              "Fee exceeds maximum: %Ld > %Ld satoshis (maxfeerate %.8f BTC/kvB)"
              entry.fee max_fee_sats max_fee_rate)
          end
          else begin
            (* Relay to peers *)
            let wtxid = Crypto.compute_wtxid tx in
            let fee_rate = Int64.div entry.fee (Int64.of_int (max 1 (entry.weight / 4))) in
            Lwt.async (fun () ->
              Peer_manager.announce_tx ctx.peer_manager
                ~txid:entry.txid ~wtxid ~fee_rate
            );
            Ok (`String (Types.hash256_to_hex_display entry.txid))
          end
        | Error msg ->
          Error msg
    with exn ->
      Error (Printf.sprintf "TX decode failed: %s" (Printexc.to_string exn)))

let handle_decoderawtransaction (_ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  match params with
  | [`String hex] ->
    (try
      let data = Cstruct.of_hex hex in
      let r = Serialize.reader_of_cstruct data in
      let tx = Serialize.deserialize_transaction r in
      let txid = Crypto.compute_txid tx in
      let vin = List.mapi (fun i inp ->
        `Assoc [
          ("txid", `String (Types.hash256_to_hex_display inp.Types.previous_output.txid));
          ("vout", `Int (Int32.to_int inp.Types.previous_output.vout));
          ("scriptSig", `Assoc [
            (* W27-A: scriptSig is variable-length; hash256_to_hex truncates. *)
            ("hex", `String (cstruct_to_hex_early inp.Types.script_sig));
          ]);
          ("sequence", `Int (Int32.to_int inp.Types.sequence));
          ("txinwitness",
            if i < List.length tx.witnesses then
              `List (List.map (fun item ->
                (* W27-A: witness items are variable-length. *)
                `String (cstruct_to_hex_early item)
              ) (List.nth tx.witnesses i).items)
            else
              `List []);
        ]
      ) tx.inputs in
      let vout = List.mapi (fun i out ->
        `Assoc [
          ("value", `Float (Int64.to_float out.Types.value /. 100_000_000.0));
          ("n", `Int i);
          ("scriptPubKey", `Assoc [
            (* W27-A: scriptPubKey is variable-length; hash256_to_hex truncates. *)
            ("hex", `String (cstruct_to_hex_early out.Types.script_pubkey));
          ]);
        ]
      ) tx.outputs in
      Ok (`Assoc [
        ("txid", `String (Types.hash256_to_hex_display txid));
        ("version", `Int (Int32.to_int tx.version));
        ("size", `Int (Validation.compute_tx_size tx));
        ("vsize", `Int (Validation.compute_tx_vsize tx));
        ("weight", `Int (Validation.compute_tx_weight tx));
        ("locktime", `Int (Int32.to_int tx.locktime));
        ("vin", `List vin);
        ("vout", `List vout);
      ])
    with exn ->
      Error (Printf.sprintf "TX decode failed: %s" (Printexc.to_string exn)))
  | _ ->
    Error "Invalid parameters: expected [hexstring]"

(* ============================================================================
   Peer Info Handlers
   ============================================================================ *)

let handle_getpeerinfo (ctx : rpc_context) : Yojson.Safe.t =
  let peers = Peer_manager.get_peer_stats ctx.peer_manager in
  `List (List.map (fun stats ->
    let svc = stats.Peer.stat_services in
    let svc_names =
      (if Int64.logand svc 1L <> 0L then ["NETWORK"] else []) @
      (if Int64.logand svc 8L <> 0L then ["WITNESS"] else []) @
      (if Int64.logand svc 1024L <> 0L then ["NETWORK_LIMITED"] else []) in
    let is_inbound = stats.stat_direction = Peer.Inbound in
    `Assoc [
      ("id", `Int stats.Peer.stat_id);
      ("addr", `String (Printf.sprintf "%s:%d"
        stats.stat_addr stats.stat_port));
      ("network", `String "ipv4");
      ("services", `String (Printf.sprintf "%016Lx" svc));
      ("servicesnames", `List (List.map (fun s -> `String s) svc_names));
      ("relaytxes", `Bool stats.stat_relay);
      ("lastsend", `Int (int_of_float stats.stat_last_seen));
      ("lastrecv", `Int (int_of_float stats.stat_last_seen));
      ("last_transaction", `Int 0);
      ("last_block", `Int 0);
      ("bytessent", `Int stats.stat_bytes_sent);
      ("bytesrecv", `Int stats.stat_bytes_received);
      ("conntime", `Int (int_of_float stats.stat_last_seen));
      ("timeoffset", `Int (Int64.to_int stats.stat_time_offset));
      ("pingtime", `Float (stats.stat_latency_ms /. 1000.0));
      ("minping", `Float (stats.stat_latency_ms /. 1000.0));
      ("version", `Int (Int32.to_int stats.stat_protocol_version));
      ("subver", `String stats.stat_user_agent);
      ("inbound", `Bool is_inbound);
      ("bip152_hb_to", `Bool false);
      ("bip152_hb_from", `Bool false);
      ("startingheight", `Int (Int32.to_int stats.stat_best_height));
      ("presynced_headers", `Int (-1));
      ("synced_headers", `Int (-1));
      ("synced_blocks", `Int (-1));
      ("inflight", `List []);
      ("addr_relay_enabled", `Bool true);
      ("addr_processed", `Int 0);
      ("addr_rate_limited", `Int 0);
      ("permissions", `List []);
      ("minfeefilter", `Float 0.0);
      ("bytessent_per_msg", `Assoc []);
      ("bytesrecv_per_msg", `Assoc []);
      ("connection_type", `String (if is_inbound then "inbound" else "outbound-full-relay"));
      ("transport_protocol_type", `String "v1");
      ("session_id", `String "");
    ]
  ) peers)

let handle_getconnectioncount (ctx : rpc_context) : Yojson.Safe.t =
  `Int (Peer_manager.peer_count ctx.peer_manager)

let handle_getnetworkinfo (ctx : rpc_context) : Yojson.Safe.t =
  (* Render localservices straight from [Peer.our_services] so the RPC
     output matches the bits we actually advertise on the wire.  When
     -peerbloomfilters=0 (Core default) the NODE_BLOOM bit is off and the
     hex string drops to "...0009" with BLOOM removed from the names list. *)
  let svc = Peer.our_services () in
  let svc_bits = Peer.services_to_int64 svc in
  let localservices_hex = Printf.sprintf "%016Lx" svc_bits in
  let localservicesnames =
    let names = ref [] in
    if svc.network_limited then names := `String "NETWORK_LIMITED" :: !names;
    if svc.compact_filters then names := `String "COMPACT_FILTERS" :: !names;
    if svc.witness then names := `String "WITNESS" :: !names;
    if svc.bloom then names := `String "BLOOM" :: !names;
    if svc.getutxo then names := `String "GETUTXO" :: !names;
    if svc.network then names := `String "NETWORK" :: !names;
    `List !names
  in
  `Assoc [
    ("version", `Int 210000);
    ("subversion", `String ("/CamlCoin:" ^ Types.version ^ "/"));
    ("protocolversion", `Int (Int32.to_int Types.protocol_version));
    ("localservices", `String localservices_hex);
    ("localservicesnames", localservicesnames);
    ("localrelay", `Bool true);
    ("timeoffset", `Int 0);
    ("networkactive", `Bool true);
    ("connections", `Int (Peer_manager.peer_count ctx.peer_manager));
    ("connections_in", `Int 0);
    ("connections_out", `Int (Peer_manager.peer_count ctx.peer_manager));
    ("networks", `List [
      `Assoc [
        ("name", `String "ipv4");
        ("limited", `Bool false);
        ("reachable", `Bool true);
        ("proxy", `String "");
        ("proxy_randomize_credentials", `Bool false);
      ];
      `Assoc [
        ("name", `String "ipv6");
        ("limited", `Bool false);
        ("reachable", `Bool true);
        ("proxy", `String "");
        ("proxy_randomize_credentials", `Bool false);
      ];
    ]);
    ("relayfee", `Float 0.00001);
    ("incrementalfee", `Float 0.00001);
    ("localaddresses", `List []);
    ("warnings", `String "");
  ]

(* ============================================================================
   Mempool Handlers
   ============================================================================ *)

let handle_getmempoolinfo (ctx : rpc_context) : Yojson.Safe.t =
  let (count, weight, fees) = Mempool.get_info ctx.mempool in
  `Assoc [
    ("loaded", `Bool true);
    ("size", `Int count);
    ("bytes", `Int (weight / 4));
    ("usage", `Int weight);
    ("maxmempool", `Int ctx.mempool.max_size_bytes);
    ("mempoolminfee", `Float
      (Int64.to_float ctx.mempool.min_relay_fee /. 100_000_000.0));
    ("minrelaytxfee", `Float
      (Int64.to_float ctx.mempool.min_relay_fee /. 100_000_000.0));
    ("unbroadcastcount", `Int 0);
    ("fullrbf", `Bool true);
    ("total_fee", `Float (Int64.to_float fees /. 100_000_000.0));
    ("incrementalrelayfee", `Float 0.00001);
  ]

let handle_getrawmempool (ctx : rpc_context)
    (params : Yojson.Safe.t list) : Yojson.Safe.t =
  let verbose = match params with
    | [`Bool true] -> true
    | _ -> false
  in
  if verbose then begin
    let entries = Hashtbl.fold (fun _ entry acc ->
      let txid = Types.hash256_to_hex_display entry.Mempool.txid in
      let descendants = Mempool.get_descendants ctx.mempool entry.txid in
      let descendantcount = 1 + List.length descendants in
      let descendantsize = (entry.weight +
        List.fold_left (fun s (e : Mempool.mempool_entry) -> s + e.weight) 0 descendants) / 4 in
      let descendantfees = Int64.to_float (List.fold_left
        (fun s (e : Mempool.mempool_entry) -> Int64.add s e.fee)
        entry.fee descendants) /. 100_000_000.0 in
      let ancestors = Mempool.get_ancestors ctx.mempool entry.txid in
      let ancestorcount = 1 + List.length ancestors in
      let ancestorsize = (entry.weight +
        List.fold_left (fun s (e : Mempool.mempool_entry) -> s + e.weight) 0 ancestors) / 4 in
      let ancestorfees = Int64.to_float (List.fold_left
        (fun s (e : Mempool.mempool_entry) -> Int64.add s e.fee)
        entry.fee ancestors) /. 100_000_000.0 in
      let fee_btc = Int64.to_float entry.fee /. 100_000_000.0 in
      let info = `Assoc [
        ("vsize", `Int (entry.weight / 4));
        ("weight", `Int entry.weight);
        ("fee", `Float fee_btc);
        ("modifiedfee", `Float fee_btc);
        ("time", `Int (int_of_float entry.time_added));
        ("height", `Int entry.height_added);
        ("descendantcount", `Int descendantcount);
        ("descendantsize", `Int descendantsize);
        ("descendantfees", `Float descendantfees);
        ("ancestorcount", `Int ancestorcount);
        ("ancestorsize", `Int ancestorsize);
        ("ancestorfees", `Float ancestorfees);
        ("wtxid", `String txid);
        ("fees", `Assoc [
          ("base", `Float fee_btc);
          ("modified", `Float fee_btc);
          ("ancestor", `Float ancestorfees);
          ("descendant", `Float descendantfees);
        ]);
        ("depends", `List (List.map (fun dep ->
          `String (Types.hash256_to_hex_display dep)
        ) entry.depends_on));
        ("spentby", `List []);
        ("bip125-replaceable", `Bool true);
        ("unbroadcast", `Bool false);
      ] in
      (txid, info) :: acc
    ) ctx.mempool.entries [] in
    `Assoc entries
  end else begin
    let txids = Hashtbl.fold (fun _ entry acc ->
      `String (Types.hash256_to_hex_display entry.Mempool.txid) :: acc
    ) ctx.mempool.entries [] in
    `List txids
  end

(* ============================================================================
   Mempool Ancestor/Descendant/Entry Handlers
   ============================================================================ *)

(* Helper: parse txid hex and convert to internal format (reversed) *)
let parse_txid_param (txid_hex : string) : Cstruct.t =
  let txid_bytes = Types.hash256_of_hex txid_hex in
  let txid = Cstruct.create 32 in
  for i = 0 to 31 do
    Cstruct.set_uint8 txid i (Cstruct.get_uint8 txid_bytes (31 - i))
  done;
  txid

let handle_getmempoolancestors (ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  match params with
  | [`String txid_hex] ->
    let txid = parse_txid_param txid_hex in
    let ancestors = Mempool.get_ancestors ctx.mempool txid in
    Ok (`List (List.map (fun entry ->
      `String (Types.hash256_to_hex_display entry.Mempool.txid)
    ) ancestors))
  | _ ->
    Error "Invalid parameters: expected [txid]"

let handle_getmempooldescendants (ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  match params with
  | [`String txid_hex] ->
    let txid = parse_txid_param txid_hex in
    let descendants = Mempool.get_descendants ctx.mempool txid in
    Ok (`List (List.map (fun entry ->
      `String (Types.hash256_to_hex_display entry.Mempool.txid)
    ) descendants))
  | _ ->
    Error "Invalid parameters: expected [txid]"

let handle_getmempoolentry (ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  match params with
  | [`String txid_hex] ->
    let txid = parse_txid_param txid_hex in
    let txid_key = Cstruct.to_string txid in
    (match Hashtbl.find_opt ctx.mempool.entries txid_key with
     | Some entry ->
       Ok (`Assoc [
         ("fee", `Float (Int64.to_float entry.Mempool.fee /. 100_000_000.0));
         ("weight", `Int entry.weight);
         ("time", `Float entry.time_added);
         ("depends", `List (List.map (fun dep ->
           `String (Types.hash256_to_hex_display dep)
         ) entry.depends_on));
       ])
     | None ->
       Error "Transaction not in mempool")
  | _ ->
    Error "Invalid parameters: expected [txid]"

(* ============================================================================
   Fee Estimation Handlers
   ============================================================================ *)

let handle_estimatesmartfee (ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  match params with
  | [`Int conf_target] | [`Int conf_target; _] ->
    let fee_rate = Fee_estimation.estimate_fee ctx.fee_estimator conf_target in
    (match fee_rate with
     | Some rate ->
       Ok (`Assoc [
         ("feerate", `Float (rate /. 100_000.0));
         ("blocks", `Int conf_target);
       ])
     | None ->
       Ok (`Assoc [
         ("errors", `List [`String "Insufficient data or no feerate found"]);
         ("blocks", `Int conf_target);
       ]))
  | _ ->
    Error "Invalid parameters: expected [conf_target]"

(* estimaterawfee — advanced/unstable equivalent of Bitcoin Core's
   src/rpc/fees.cpp::estimaterawfee.  Core returns one bucket-detail object
   per horizon (short / medium / long) that tracks the requested
   conf_target, with feerate (in BTC/kvB), decay, scale, and pass/fail
   bucket statistics.  We mirror the shape using camlcoin's existing
   horizon/bucket structures so callers that consume the JSON for analytics
   keep working. *)
let estimate_raw_horizon (h : Fee_estimation.horizon)
    (conf_target : int) (threshold : float) : Yojson.Safe.t option =
  if conf_target > h.max_target then None
  else begin
    let n = Array.length h.buckets in
    let target_f = float_of_int conf_target in
    (* Walk buckets low → high.  The first bucket whose [conf_target]-percentile
       confirmation count satisfies (within_target / total_confirmed) >=
       threshold is the "pass" bucket; the bucket immediately below it (if
       any) is the highest-fee "fail" bucket, matching Core's traversal. *)
    let pass_idx = ref (-1) in
    let fail_idx = ref (-1) in
    let i = ref 0 in
    while !i < n && !pass_idx < 0 do
      let b = h.buckets.(!i) in
      let total = b.total_confirmed in
      if total >= float_of_int Fee_estimation.min_samples then begin
        let within =
          List.fold_left (fun acc x ->
            if x <= target_f then acc +. 1.0 else acc)
            0.0 b.blocks_to_confirm
        in
        let ratio = if total > 0.0 then within /. total else 0.0 in
        if ratio >= threshold then pass_idx := !i
        else fail_idx := !i
      end;
      incr i
    done;
    let bucket_json (idx : int) : Yojson.Safe.t =
      if idx < 0 then
        `Assoc [
          ("startrange", `Float (-1.0));
          ("endrange", `Float (-1.0));
          ("withintarget", `Float 0.0);
          ("totalconfirmed", `Float 0.0);
          ("inmempool", `Float 0.0);
          ("leftmempool", `Float 0.0);
        ]
      else
        let b = h.buckets.(idx) in
        let within =
          List.fold_left (fun acc x ->
            if x <= target_f then acc +. 1.0 else acc)
            0.0 b.blocks_to_confirm
        in
        `Assoc [
          ("startrange", `Float b.min_fee_rate);
          ("endrange",
            `Float (if Float.is_finite b.max_fee_rate
                    then b.max_fee_rate
                    else b.min_fee_rate *. 1.05));
          ("withintarget", `Float within);
          ("totalconfirmed", `Float b.total_confirmed);
          ("inmempool", `Float b.total_unconfirmed);
          ("leftmempool", `Float 0.0);
        ]
    in
    let scale = 1.05 in
    let common = [
      ("decay", `Float h.decay);
      ("scale", `Float scale);
    ] in
    if !pass_idx < 0 then
      Some (`Assoc (common @ [
        ("fail", bucket_json !fail_idx);
        ("errors", `List [
          `String "Insufficient data or no feerate found which meets threshold";
        ]);
      ]))
    else begin
      let b = h.buckets.(!pass_idx) in
      (* feerate in BTC/kvB.  Bucket fee rate is sat/vB.  Convert:
         sat/vB = 1000 * sat/kvB; 1 BTC = 100_000_000 sat.  So
         BTC/kvB = sat_per_vB * 1000 / 1e8 = sat_per_vB / 100_000. *)
      let feerate_btc_per_kvb = b.min_fee_rate /. 100_000.0 in
      let pass_obj = bucket_json !pass_idx in
      let fail_obj = bucket_json !fail_idx in
      Some (`Assoc (
        ("feerate", `Float feerate_btc_per_kvb)
        :: common
        @ [ ("pass", pass_obj); ("fail", fail_obj) ]
      ))
    end
  end

let handle_estimaterawfee (ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  let parse_target (j : Yojson.Safe.t) : (int, string) result =
    match j with
    | `Int n -> Ok n
    | _ -> Error "Invalid parameter: expected integer conf_target"
  in
  let parse_threshold (j : Yojson.Safe.t) : (float, string) result =
    match j with
    | `Int n -> Ok (float_of_int n)
    | `Float f -> Ok f
    | `Null -> Ok 0.95
    | _ -> Error "Invalid parameter: expected number threshold"
  in
  let target_r, threshold_r = match params with
    | [t] -> (parse_target t, Ok 0.95)
    | [t; th] -> (parse_target t, parse_threshold th)
    | _ ->
      (Error "Invalid parameters: expected [conf_target] or [conf_target, threshold]",
       Ok 0.95)
  in
  match target_r, threshold_r with
  | Error e, _ | _, Error e -> Error e
  | Ok target, Ok threshold ->
    if target < Fee_estimation.min_confirm_target
       || target > Fee_estimation.max_confirm_target then
      Error (Printf.sprintf
        "Invalid conf_target, must be between %d and %d"
        Fee_estimation.min_confirm_target Fee_estimation.max_confirm_target)
    else if threshold < 0.0 || threshold > 1.0 then
      Error "Invalid threshold, must be between 0.0 and 1.0"
    else begin
      let est = ctx.fee_estimator in
      let fields = ref [] in
      let add name h_opt = match h_opt with
        | Some j -> fields := (name, j) :: !fields
        | None -> ()
      in
      add "short"  (estimate_raw_horizon est.short  target threshold);
      add "medium" (estimate_raw_horizon est.medium target threshold);
      add "long"   (estimate_raw_horizon est.long   target threshold);
      Ok (`Assoc (List.rev !fields))
    end

(* ============================================================================
   Mining Handlers
   ============================================================================ *)

let handle_getmininginfo (ctx : rpc_context) : Yojson.Safe.t =
  let height, difficulty, bits = match ctx.chain.tip with
    | Some t ->
      (t.height, Consensus.difficulty_from_bits t.header.bits, t.header.bits)
    | None -> (0, 1.0, 0x1d00ffffl)
  in
  let bits_hex = Printf.sprintf "%08lx" bits in
  let target_hex = bits_to_target_hex bits in
  let next_height = height + 1 in
  `Assoc [
    ("blocks", `Int height);
    ("currentblocksize", `Int 0);
    ("currentblockweight", `Int 0);
    ("currentblocktx", `Int 0);
    ("bits", `String bits_hex);
    ("difficulty", `Float difficulty);
    ("target", `String target_hex);
    ("blockmintxfee", `Float 0.00001000);
    ("networkhashps", `Float 0.0);
    ("pooledtx", `Int (Hashtbl.length ctx.mempool.entries));
    ("chain", `String ctx.network.name);
    ("next", `Assoc [
      ("height", `Int next_height);
      ("bits", `String bits_hex);
      ("difficulty", `Float difficulty);
      ("target", `String target_hex);
    ]);
    ("warnings", `String "");
  ]

let handle_getblocktemplate (ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  (* Try to get coinbase_address from the first param object *)
  let coinbase_address_opt = match params with
    | (`Assoc fields) :: _ ->
      (match List.assoc_opt "coinbase_address" fields with
       | Some (`String addr) -> Some addr
       | _ -> None)
    | _ -> None
  in
  (* Resolve payout script: from provided address, wallet, or error *)
  let payout_script_result = match coinbase_address_opt with
    | Some addr_str ->
      (match Address.address_of_string addr_str with
       | Ok addr -> Ok (Wallet.build_output_script addr)
       | Error e -> Error (Printf.sprintf "Invalid coinbase_address: %s" e))
    | None ->
      (match ctx.wallet with
       | Some wallet ->
         let kp = Wallet.generate_key wallet in
         Ok (Wallet.build_output_script kp.address)
       | None ->
         Error "No coinbase_address provided and no wallet available")
  in
  match payout_script_result with
  | Error msg -> Error msg
  | Ok payout_script ->
    let template = Mining.create_block_template
      ~chain:ctx.chain ~mp:ctx.mempool ~payout_script in
    Ok (Mining.template_to_json template)

(* Map a submitblock error string to the canonical BIP-22 result token.
   Per BIP-22 and Bitcoin Core BIP22ValidationResult() in
   src/rpc/mining.cpp, rejection reasons must be short ASCII strings in
   the result field, not verbose error messages.
   Strings are matched against known substrings from validation.ml. *)
let bip22_of_submitblock_error (msg : string) : string =
  let c s = let open String in
    let n = length s and m = length msg in
    if n > m then false
    else
      let rec go i = if i > m - n then false
                     else if sub msg i n = s then true
                     else go (i + 1)
      in go 0
  in
  if c "difficulty target" || c "does not meet" then "high-hash"
  else if c "merkle root" || c "mutated" then "bad-txnmrklroot"
  else if c "witness commitment" then "bad-witness-merkle-match"
  else if c "coinbase value" || c "coinbase value too high" then "bad-cb-amount"
  else if c "sigop" then "bad-blk-sigops"
  (* BIP-30 cross-block duplicate UTXO: "transaction has duplicate txid in UTXO set (BIP30)"
     — Core returns "bad-txns-BIP30" for this; the "BIP30" substring distinguishes it from
     the in-block dup-txid case below. *)
  else if c "BIP30" then "bad-txns-BIP30"
  (* In-block dup-txid (CVE-2012-2459): "block contains duplicate transactions"
     — Core reaches ConnectBlock prevout-already-spent and returns
     "bad-txns-inputs-missingorspent" for the same block (dup-txid-merkle-malleation corpus). *)
  else if c "duplicate transaction" then "bad-txns-inputs-missingorspent"
  else if c "non-final" || c "not final" || c "sequence locks" then "bad-txns-nonfinal"
  (* bad-cb-length: coinbase scriptSig 2..100 byte cap (consensus/tx_check.cpp:49) *)
  else if c "bad-cb-length" then "bad-cb-length"
  (* bad-cb-height: BIP-34 height prefix wrong *)
  else if c "invalid coinbase" || c "bad coinbase" then "bad-cb-height"
  else if c "timestamp too far" then "time-too-new"
  else if c "timestamp" then "time-too-old"
  (* Connect-block stage: Core validation.cpp:2122 "block-script-verify-flag-failed (%s)".
     Covers disabled opcodes (OP_CAT and 14 peers), signature failures, etc. *)
  else if c "script verification failed" || c "disabled opcode" || c "Disabled opcode"
       || c "script failed" || c "checksig" || c "witness program" then
       "block-script-verify-flag-failed"
  else if c "missing inputs" || c "missing or spent" then "bad-txns-inputs-missingorspent"
  (* Coinbase maturity violation: consensus/tx_verify.cpp::CheckTxInputs.
     Core: state.Invalid(TX_PREMATURE_SPEND, "bad-txns-premature-spend-of-coinbase").
     validation.ml emits "spending immature coinbase (N < 100 confirmations required)". *)
  else if c "immature coinbase" then "bad-txns-premature-spend-of-coinbase"
  (* Negative output value: consensus/tx_check.cpp::CheckTransaction — Core parity *)
  else if c "has negative value" then "bad-txns-vout-negative"
  (* Output value > MAX_MONEY: consensus/tx_check.cpp::CheckTransaction — Core parity *)
  else if c "exceeds MAX_MONEY" then "bad-txns-vout-toolarge"
  (* Non-coinbase tx where sum(inputs) < sum(outputs).
     Core consensus/tx_verify.cpp::CheckTxInputs:
       state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-in-belowout", ...)
     validation.ml emits "transaction fee is insufficient" for TxInsufficientFee. *)
  else if c "fee is insufficient" then "bad-txns-in-belowout"
  else "rejected"

let handle_submitblock (ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  (* NetworkDisable gate. Refuse submissions while a [dumptxoutset
     rollback] dance is in progress. Mirrors Bitcoin Core's NetworkDisable
     RAII around TemporaryRollback in [rpc/blockchain.cpp::dumptxoutset]. *)
  if ctx.chain.block_submission_paused then
    Ok (`String
      "rejected: block submission paused (dumptxoutset rollback in progress)")
  else
  match params with
  | [`String hex] ->
    (try
      let data = Cstruct.of_hex hex in
      let r = Serialize.reader_of_cstruct data in
      let block = Serialize.deserialize_block r in
      match Mining.submit_block ?utxo:ctx.utxo
              ~network_type:ctx.network.network_type
              block ctx.chain ctx.mempool with
      | Ok () -> Ok `Null
      (* Return canonical BIP-22 string in result field (not as an error).
         Bitcoin Core BIP22ValidationResult() returns the string as a
         successful JSON-RPC result, not a JSON-RPC error object. *)
      | Error msg -> Ok (`String (bip22_of_submitblock_error msg))
    with exn ->
      (* Deserialization / structural failure: still a BIP-22 "rejected". *)
      let _ = Printf.sprintf "Block decode failed: %s" (Printexc.to_string exn) in
      Ok (`String "rejected"))
  | _ ->
    Error "Invalid parameters: expected [hexdata]"

(* ============================================================================
   Regtest Mining RPCs (generate, generatetoaddress, generateblock)
   ============================================================================ *)

(* Mine a single block with the given payout script.
   Returns the block hash on success. *)
let mine_single_block (ctx : rpc_context) (payout_script : Cstruct.t)
    : (Types.hash256, string) result =
  let template = Mining.create_block_template
    ~chain:ctx.chain ~mp:ctx.mempool ~payout_script in
  (* Regtest difficulty (0x207fffff) means almost any nonce works.
     Use a generous limit to handle edge cases. *)
  match Mining.mine_block template 100_000_000l with
  | None -> Error "Failed to find valid nonce (unexpected on regtest)"
  | Some block ->
    match Mining.submit_block ?utxo:ctx.utxo
            ~network_type:ctx.network.network_type
            block ctx.chain ctx.mempool with
    | Error msg -> Error msg
    | Ok () ->
      let hash = Crypto.compute_block_hash block.header in
      (* Announce the new block to all connected peers *)
      Lwt.async (fun () ->
        Peer_manager.announce_block ctx.peer_manager block.header hash);
      Ok hash

(* generate nblocks [maxtries]
   Mine blocks immediately (regtest only).
   Returns array of block hashes. *)
let handle_generate (ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  (* Only available on regtest *)
  if ctx.network.network_type <> Consensus.Regtest then
    Error "generate is only available on regtest"
  else
    let nblocks = match params with
      | `Int n :: _ -> n
      | _ -> 1
    in
    if nblocks < 0 || nblocks > 1000 then
      Error "nblocks must be between 0 and 1000"
    else begin
      (* Get payout script from wallet *)
      let payout_script = match ctx.wallet with
        | Some wallet ->
          let kp = Wallet.generate_key wallet in
          Wallet.build_output_script kp.address
        | None ->
          (* Fallback: P2SH output to dummy script hash *)
          let script = Cstruct.create 23 in
          Cstruct.set_uint8 script 0 0xa9;  (* OP_HASH160 *)
          Cstruct.set_uint8 script 1 0x14;  (* 20 bytes *)
          (* Fill with zeros - valid but unspendable *)
          Cstruct.set_uint8 script 22 0x87;  (* OP_EQUAL *)
          script
      in
      let rec mine_blocks acc remaining =
        if remaining <= 0 then Ok (List.rev acc)
        else
          match mine_single_block ctx payout_script with
          | Error msg -> Error msg
          | Ok hash ->
            mine_blocks (hash :: acc) (remaining - 1)
      in
      match mine_blocks [] nblocks with
      | Error msg -> Error msg
      | Ok hashes ->
        Ok (`List (List.map (fun h ->
          `String (Types.hash256_to_hex_display h)
        ) hashes))
    end

(* generatetoaddress nblocks address [maxtries]
   Mine blocks to a specified address (regtest only).
   Returns array of block hashes. *)
let handle_generatetoaddress (ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  (* Only available on regtest *)
  if ctx.network.network_type <> Consensus.Regtest then
    Error "generatetoaddress is only available on regtest"
  else
    match params with
    | `Int nblocks :: `String address :: _ ->
      if nblocks < 0 || nblocks > 1000 then
        Error "nblocks must be between 0 and 1000"
      else begin
        (* Parse address and build output script *)
        match Address.address_of_string address with
        | Error e -> Error (Printf.sprintf "Invalid address: %s" e)
        | Ok addr ->
          let payout_script = Wallet.build_output_script addr in
          let rec mine_blocks acc remaining =
            if remaining <= 0 then Ok (List.rev acc)
            else
              match mine_single_block ctx payout_script with
              | Error msg -> Error msg
              | Ok hash ->
                mine_blocks (hash :: acc) (remaining - 1)
          in
          match mine_blocks [] nblocks with
          | Error msg -> Error msg
          | Ok hashes ->
            Ok (`List (List.map (fun h ->
              `String (Types.hash256_to_hex_display h)
            ) hashes))
      end
    | _ ->
      Error "Invalid parameters: expected [nblocks, address]"

(* generateblock output [transactions]
   Mine a block with specific transactions (regtest only).
   output: address or descriptor for coinbase
   transactions: array of hex-encoded raw transactions or txids
   Returns {"hash": blockhash}. *)
let handle_generateblock (ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  (* Only available on regtest *)
  if ctx.network.network_type <> Consensus.Regtest then
    Error "generateblock is only available on regtest"
  else
    match params with
    | `String output :: rest ->
      (* Parse output address *)
      let payout_script_result = match Address.address_of_string output with
        | Ok addr -> Ok (Wallet.build_output_script addr)
        | Error e -> Error (Printf.sprintf "Invalid output address: %s" e)
      in
      (match payout_script_result with
       | Error msg -> Error msg
       | Ok payout_script ->
         (* Parse optional transactions array *)
         let txs_result = match rest with
           | `List txs :: _ ->
             (* Each element can be a raw tx hex or a txid to pull from mempool *)
             let rec parse_txs acc = function
               | [] -> Ok (List.rev acc)
               | `String hex :: rest ->
                 if String.length hex = 64 then begin
                   (* Looks like a txid - try to get from mempool *)
                   let txid = parse_txid_param hex in
                   let key = Cstruct.to_string txid in
                   match Hashtbl.find_opt ctx.mempool.entries key with
                   | Some entry -> parse_txs (entry.tx :: acc) rest
                   | None -> Error (Printf.sprintf "Transaction not in mempool: %s" hex)
                 end else begin
                   (* Raw transaction hex *)
                   try
                     let data = Cstruct.of_hex hex in
                     let r = Serialize.reader_of_cstruct data in
                     let tx = Serialize.deserialize_transaction r in
                     parse_txs (tx :: acc) rest
                   with exn ->
                     Error (Printf.sprintf "Invalid transaction: %s"
                              (Printexc.to_string exn))
                 end
               | _ -> Error "Invalid transaction format (expected hex string)"
             in
             parse_txs [] txs
           | _ -> Ok []  (* No transactions specified *)
         in
         match txs_result with
         | Error msg -> Error msg
         | Ok transactions ->
           (* Build block template manually with specified transactions *)
           let tip = match ctx.chain.tip with
             | Some t -> t
             | None -> failwith "No chain tip"
           in
           let height = tip.height + 1 in
           (* Calculate fees for specified transactions *)
           let total_fee = List.fold_left (fun acc tx ->
             let key = Cstruct.to_string (Crypto.compute_txid tx) in
             match Hashtbl.find_opt ctx.mempool.entries key with
             | Some entry -> Int64.add acc entry.Mempool.fee
             | None -> acc  (* Unknown fee, assume 0 *)
           ) 0L transactions in
           (* Create coinbase *)
           let extra_nonce = Cstruct.create 8 in
           let ts = Int64.of_float (Unix.gettimeofday () *. 1000000.0) in
           Cstruct.LE.set_uint64 extra_nonce 0 ts;
           (* Compute witness commitment if any segwit transactions *)
           let network_type = ctx.network.network_type in
           let placeholder_coinbase = Mining.create_coinbase
             ~height ~total_fee ~payout_script ~extra_nonce ~witness_root:None
             ~network_type () in
           let all_txs_for_witness = placeholder_coinbase :: transactions in
           let witness_root = Mining.compute_witness_merkle_root all_txs_for_witness in
           let coinbase_tx = Mining.create_coinbase
             ~height ~total_fee ~payout_script ~extra_nonce
             ~witness_root:(Some witness_root) ~network_type () in
           (* Build block *)
           let all_txs = coinbase_tx :: transactions in
           let txids = List.map Crypto.compute_txid all_txs in
           let (merkle_root, _mutated) = Crypto.merkle_root txids in
           (* Calculate MTP to ensure timestamp is valid *)
           let rec collect_ts acc count entry =
             if count >= 11 then acc
             else
               let acc = entry.Sync.header.timestamp :: acc in
               if entry.height = 0 then acc
               else
                 let parent_key = Cstruct.to_string entry.header.prev_block in
                 match Hashtbl.find_opt ctx.chain.headers parent_key with
                 | Some parent -> collect_ts acc (count + 1) parent
                 | None -> acc
           in
           let ancestor_ts = collect_ts [] 0 tip in
           let mtp = Consensus.median_time_past ancestor_ts in
           let now = Int32.of_float (Unix.gettimeofday ()) in
           let timestamp = max (Int32.add mtp 1l) now in
           let header : Types.block_header = {
             version = 0x20000000l;
             prev_block = tip.hash;
             merkle_root;
             timestamp;
             bits = ctx.network.pow_limit;  (* Use regtest min difficulty *)
             nonce = 0l;
           } in
           let template : Mining.block_template = {
             header;
             coinbase_tx;
             transactions;
             tx_fees = [];
             total_fee;
             total_weight = 0;
             height;
             target = Consensus.compact_to_target ctx.network.pow_limit;
             network_type = ctx.network.network_type;
           } in
           (* Mine the block *)
           match Mining.mine_block template 100_000_000l with
           | None -> Error "Failed to find valid nonce"
           | Some block ->
             match Mining.submit_block ?utxo:ctx.utxo
                     ~network_type:ctx.network.network_type
                     block ctx.chain ctx.mempool with
             | Error msg -> Error msg
             | Ok () ->
               let hash = Crypto.compute_block_hash block.header in
               Ok (`Assoc [("hash", `String (Types.hash256_to_hex_display hash))]))
    | _ ->
      Error "Invalid parameters: expected [output, transactions?]"

(* ============================================================================
   Wallet Handlers (Stub implementations)
   ============================================================================ *)

let handle_getbalance (ctx : rpc_context)
    (_params : Yojson.Safe.t list) : Yojson.Safe.t =
  match ctx.wallet with
  | None -> `Float 0.0
  | Some wallet ->
    let utxos = Wallet.get_utxos wallet in
    let total = List.fold_left (fun acc (wutxo : Wallet.wallet_utxo) ->
      Int64.add acc wutxo.utxo.Utxo.value
    ) 0L utxos in
    `Float (Int64.to_float total /. 100_000_000.0)

let handle_getnewaddress (ctx : rpc_context)
    (_params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  match ctx.wallet with
  | None -> Error "Wallet not loaded"
  | Some wallet ->
    let kp = Wallet.generate_key wallet in
    let addr = Address.address_to_string kp.address in
    Ok (`String addr)

let handle_listunspent (ctx : rpc_context)
    (_params : Yojson.Safe.t list) : Yojson.Safe.t =
  match ctx.wallet with
  | None -> `List []
  | Some wallet ->
    let utxos = Wallet.get_utxos wallet in
    let tip_height = match ctx.chain.tip with
      | Some t -> t.height
      | None -> 0
    in
    `List (List.map (fun (wutxo : Wallet.wallet_utxo) ->
      let confirmations =
        if wutxo.confirmed then tip_height - wutxo.utxo.Utxo.height + 1
        else 0
      in
      `Assoc [
        ("txid", `String (Types.hash256_to_hex_display wutxo.outpoint.txid));
        ("vout", `Int (Int32.to_int wutxo.outpoint.vout));
        ("amount", `Float (Int64.to_float wutxo.utxo.Utxo.value /. 100_000_000.0));
        ("confirmations", `Int confirmations);
      ]
    ) utxos)

let handle_sendtoaddress (ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  (* Extract conf_target from params (index 6 in Bitcoin Core RPC) *)
  let conf_target = match List.nth_opt params 6 with
    | Some (`Int n) -> Some n
    | _ -> None
  in
  (* Determine fee rate: use estimator with conf_target, fall back to 1.0 sat/vB *)
  let fee_rate = match conf_target with
    | Some target ->
      (match Fee_estimation.estimate_fee ctx.fee_estimator target with
       | Some rate -> rate
       | None -> 1.0)
    | None ->
      (match Fee_estimation.estimate_fee ctx.fee_estimator 6 with
       | Some rate -> rate
       | None -> 1.0)
  in
  match params with
  | `String address :: `Float amount_btc :: _ ->
    (match ctx.wallet with
     | None -> Error "Wallet not loaded"
     | Some wallet ->
       let current_height = match ctx.chain.tip with
         | Some t -> Some t.height
         | None -> None
       in
       let amount_sats = Int64.of_float (amount_btc *. 100_000_000.0) in
       match Wallet.create_transaction wallet ~dest_address:address
               ~amount:amount_sats ~fee_rate ?tip_height:current_height () with
       | Error e -> Error e
       | Ok tx ->
         match Mempool.add_transaction ctx.mempool tx with
         | Ok entry ->
           Ok (`String (Types.hash256_to_hex_display entry.txid))
         | Error msg ->
           Error msg)
  | [`String address; `Int amount_sats_int] ->
    (match ctx.wallet with
     | None -> Error "Wallet not loaded"
     | Some wallet ->
       let current_height = match ctx.chain.tip with
         | Some t -> Some t.height
         | None -> None
       in
       let amount_btc = float_of_int amount_sats_int in
       let amount_sats = Int64.of_float (amount_btc *. 100_000_000.0) in
       match Wallet.create_transaction wallet ~dest_address:address
               ~amount:amount_sats ~fee_rate ?tip_height:current_height () with
       | Error e -> Error e
       | Ok tx ->
         match Mempool.add_transaction ctx.mempool tx with
         | Ok entry ->
           Ok (`String (Types.hash256_to_hex_display entry.txid))
         | Error msg ->
           Error msg)
  | _ ->
    Error "Invalid parameters: expected [address, amount]"

let handle_signrawtransactionwithwallet (ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  match params with
  | [`String hex] ->
    (match ctx.wallet with
     | None -> Error "Wallet not loaded"
     | Some wallet ->
       (try
         let data = Cstruct.of_hex hex in
         let r = Serialize.reader_of_cstruct data in
         let tx = Serialize.deserialize_transaction r in
         (* Build wallet_utxo list for inputs we can sign *)
         let wallet_utxos = Wallet.get_utxos wallet in
         let input_utxos = List.map (fun inp ->
           let prev = inp.Types.previous_output in
           List.find_opt (fun (wutxo : Wallet.wallet_utxo) ->
             Cstruct.equal wutxo.outpoint.txid prev.txid &&
             wutxo.outpoint.vout = prev.vout
           ) wallet_utxos
         ) tx.inputs in
         (* Check if all inputs can be signed *)
         let all_found = List.for_all (fun opt -> opt <> None) input_utxos in
         let found_utxos = List.filter_map Fun.id input_utxos in
         let signed_tx =
           if List.length found_utxos > 0 then
             Wallet.sign_transaction_inputs wallet tx found_utxos
           else
             tx
         in
         let w = Serialize.writer_create () in
         Serialize.serialize_transaction w signed_tx;
         let cs = Serialize.writer_to_cstruct w in
         (* W27-A: signed tx is variable-length (100-1000+ bytes);
            hash256_to_hex would truncate to 64 hex chars. *)
         let signed_hex = cstruct_to_hex_early cs in
         Ok (`Assoc [
           ("hex", `String signed_hex);
           ("complete", `Bool all_found);
         ])
       with exn ->
         Error (Printf.sprintf "TX decode failed: %s" (Printexc.to_string exn))))
  | _ ->
    Error "Invalid parameters: expected [hexstring]"

(* ============================================================================
   lockunspent / listlockunspent Handlers
   (Bitcoin Core: src/wallet/rpc/coins.cpp::lockunspent + ::listlockunspent)
   ============================================================================ *)

(* Parse a {"txid": "...", "vout": N} object into a Types.outpoint.  We reverse
   the txid hex before storing so the on-disk byte layout matches Core's
   internal big-endian representation (createpsbt does the same — see line
   ~2980).  Returns Error if the object is malformed. *)
let parse_lock_outpoint (obj : Yojson.Safe.t) : (Types.outpoint, string) result =
  match obj with
  | `Assoc fields ->
    let txid_r = match List.assoc_opt "txid" fields with
      | Some (`String s) when String.length s = 64 ->
        (try
          let display = Types.hash256_of_hex s in
          (* Reverse bytes to match the canonical internal layout *)
          let txid = Cstruct.create 32 in
          for i = 0 to 31 do
            Cstruct.set_uint8 txid i (Cstruct.get_uint8 display (31 - i))
          done;
          Ok txid
        with _ -> Error "Invalid txid")
      | _ -> Error "Missing or invalid txid"
    in
    let vout_r = match List.assoc_opt "vout" fields with
      | Some (`Int n) ->
        if n < 0 then Error "Invalid parameter, vout cannot be negative"
        else Ok (Int32.of_int n)
      | _ -> Error "Missing or invalid vout"
    in
    (match txid_r, vout_r with
     | Ok txid, Ok vout -> Ok { Types.txid; vout }
     | Error e, _ | _, Error e -> Error e)
  | _ -> Error "Expected outpoint object {txid, vout}"

(* lockunspent unlock ([{txid,vout},...]) (persistent)
   - When unlock=true and transactions array is omitted, ALL locks are cleared.
   - When transactions are provided, validate each (must reference a wallet
     UTXO; lock-direction must match current state) and then apply the lock
     change atomically (Core: see two-pass loop in coins.cpp:283-340). *)
let handle_lockunspent (ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  match ctx.wallet with
  | None -> Error "Wallet not loaded"
  | Some wallet ->
    let unlock_r = match params with
      | (`Bool b) :: _ -> Ok b
      | _ -> Error "Invalid parameter, expected bool unlock"
    in
    (match unlock_r with
     | Error e -> Error e
     | Ok unlock ->
       (* persistent flag is the optional 3rd parameter *)
       let persistent = match params with
         | _ :: _ :: (`Bool b) :: _ -> b
         | _ -> false
       in
       (* Determine if the transactions array was omitted or null. *)
       let txs_param = match params with
         | _ :: t :: _ -> Some t
         | _ -> None
       in
       (match txs_param with
        | None | Some `Null ->
          if unlock then
            let _ = Wallet.unlock_all_coins wallet in
            Ok (`Bool true)
          else
            Ok (`Bool true)
        | Some (`List arr) ->
          (* Pass 1: validate every outpoint (Core does the same: parse +
             validate first, mutate second, so a partial failure leaves the
             lockset untouched). *)
          let parsed = List.map parse_lock_outpoint arr in
          let first_err = List.find_opt Result.is_error parsed in
          (match first_err with
           | Some (Error e) -> Error e
           | _ ->
             let outpoints = List.map (function
               | Ok op -> op
               | Error _ -> assert false  (* unreachable: filtered above *)
             ) parsed in
             let wallet_utxos = Wallet.get_utxos wallet in
             let validation_err = List.find_map (fun op ->
               (* Core checks: wallet knows the parent tx, vout is in range,
                  output unspent, and (un)lock direction matches current
                  state. *)
               let known = List.exists (fun (wu : Wallet.wallet_utxo) ->
                 Cstruct.equal wu.outpoint.txid op.Types.txid &&
                 wu.outpoint.vout = op.Types.vout
               ) wallet_utxos in
               if not known then
                 Some "Invalid parameter, unknown transaction"
               else
                 let is_locked = Wallet.is_locked_coin wallet op in
                 if unlock && not is_locked then
                   Some "Invalid parameter, expected locked output"
                 else if (not unlock) && is_locked && not persistent then
                   Some "Invalid parameter, output already locked"
                 else
                   None
             ) outpoints in
             (match validation_err with
              | Some msg -> Error msg
              | None ->
                List.iter (fun op ->
                  if unlock then
                    let _ = Wallet.unlock_coin wallet op in ()
                  else
                    let _ = Wallet.lock_coin wallet op ~persistent in ()
                ) outpoints;
                Ok (`Bool true)))
        | Some _ -> Error "transactions parameter must be an array"))

let handle_listlockunspent (ctx : rpc_context)
    (_params : Yojson.Safe.t list) : Yojson.Safe.t =
  match ctx.wallet with
  | None -> `List []
  | Some wallet ->
    let outpoints = Wallet.list_locked_coins wallet in
    `List (List.map (fun op ->
      `Assoc [
        ("txid", `String (Types.hash256_to_hex_display op.Types.txid));
        ("vout", `Int (Int32.to_int op.Types.vout));
      ]
    ) outpoints)

(* ============================================================================
   Transaction History Handler
   ============================================================================ *)

let handle_listtransactions (ctx : rpc_context)
    (params : Yojson.Safe.t list) : Yojson.Safe.t =
  match ctx.wallet with
  | None -> `List []
  | Some wallet ->
    let count = match params with
      | `Int c :: _ -> c
      | _ -> 10
    in
    let skip = match params with
      | _ :: `Int s :: _ -> s
      | _ -> 0
    in
    (* Sort by timestamp descending *)
    let sorted = List.sort (fun a b ->
      compare b.Wallet.hist_timestamp a.Wallet.hist_timestamp
    ) wallet.Wallet.tx_history in
    (* Apply skip *)
    let rec drop n lst = match n, lst with
      | 0, l -> l
      | _, [] -> []
      | n, _ :: rest -> drop (n - 1) rest
    in
    let skipped = drop skip sorted in
    (* Apply count *)
    let rec take n lst = match n, lst with
      | 0, _ -> []
      | _, [] -> []
      | n, x :: rest -> x :: take (n - 1) rest
    in
    let entries = take count skipped in
    `List (List.map (fun h ->
      `Assoc [
        ("txid", `String h.Wallet.hist_txid);
        ("category", `String (match h.Wallet.hist_category with
          | `Send -> "send" | `Receive -> "receive"));
        ("amount", `Float (Int64.to_float h.Wallet.hist_amount /. 100_000_000.0));
        ("fee", `Float (Int64.to_float h.Wallet.hist_fee /. 100_000_000.0));
        ("address", `String h.Wallet.hist_address);
        ("confirmations", `Int h.Wallet.hist_confirmations);
        ("blockhash", `String h.Wallet.hist_block_hash);
        ("blockheight", `Int h.Wallet.hist_block_height);
        ("time", `Int (int_of_float h.Wallet.hist_timestamp));
      ]
    ) entries)

(* ============================================================================
   Multi-Wallet Management Handlers
   ============================================================================ *)

(* Helper: get wallet by name from wallet manager, or fall back to legacy wallet *)
let get_wallet_for_request (ctx : rpc_context) (wallet_name : string option)
    : (Wallet.t, string) result =
  match ctx.wallet_manager with
  | Some wm ->
    let name = Option.value wallet_name ~default:"" in
    (match Wallet.get_wallet wm name with
     | Some w -> Ok w
     | None ->
       if name = "" then
         (* Fall back to legacy wallet if no default in manager *)
         (match ctx.wallet with
          | Some w -> Ok w
          | None -> Error "No wallet loaded")
       else
         Error (Printf.sprintf "Wallet \"%s\" not found" name))
  | None ->
    (* Legacy single-wallet mode *)
    (match ctx.wallet with
     | Some w -> Ok w
     | None -> Error "Wallet not loaded")

(* createwallet "name" ( disable_private_keys blank "passphrase" avoid_reuse descriptors load_on_startup ) *)
let handle_createwallet (ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  match ctx.wallet_manager with
  | None -> Error "Wallet manager not initialized"
  | Some wm ->
    let name = match params with
      | `String n :: _ -> n
      | [] -> ""
      | _ -> ""
    in
    let disable_private_keys = match List.nth_opt params 1 with
      | Some (`Bool b) -> b
      | _ -> false
    in
    let blank = match List.nth_opt params 2 with
      | Some (`Bool b) -> b
      | _ -> false
    in
    let passphrase = match List.nth_opt params 3 with
      | Some (`String s) when s <> "" -> Some s
      | _ -> None
    in
    let avoid_reuse = match List.nth_opt params 4 with
      | Some (`Bool b) -> b
      | _ -> false
    in
    let options = {
      Wallet.disable_private_keys;
      blank;
      passphrase;
      avoid_reuse;
      descriptors = true;
      load_on_startup = None;
    } in
    match Wallet.create_wallet wm name ~options () with
    | Ok _wallet ->
      Ok (`Assoc [
        ("name", `String name);
        ("warning", `String (if blank then "Empty wallet created" else ""));
      ])
    | Error e -> Error e

(* loadwallet "name" ( load_on_startup ) *)
let handle_loadwallet (ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  match ctx.wallet_manager with
  | None -> Error "Wallet manager not initialized"
  | Some wm ->
    match params with
    | `String name :: _ ->
      (match Wallet.load_wallet wm name with
       | Ok _wallet ->
         Ok (`Assoc [
           ("name", `String name);
           ("warning", `String "");
         ])
       | Error e -> Error e)
    | _ -> Error "Invalid parameters: expected [wallet_name]"

(* unloadwallet ( "wallet_name" load_on_startup ) *)
let handle_unloadwallet (ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  match ctx.wallet_manager with
  | None -> Error "Wallet manager not initialized"
  | Some wm ->
    let name = match params with
      | `String n :: _ -> n
      | [] -> ""
      | _ -> ""
    in
    match Wallet.unload_wallet wm name with
    | Ok () ->
      Ok (`Assoc [("warning", `String "")])
    | Error e -> Error e

(* listwallets *)
let handle_listwallets (ctx : rpc_context)
    (_params : Yojson.Safe.t list) : Yojson.Safe.t =
  match ctx.wallet_manager with
  | None ->
    (* Legacy mode: return single wallet name if present *)
    (match ctx.wallet with
     | Some _ -> `List [`String ""]
     | None -> `List [])
  | Some wm ->
    let names = Wallet.list_wallets wm in
    `List (List.map (fun n -> `String n) names)

(* getwalletinfo - returns info about the currently selected wallet *)
let handle_getwalletinfo (ctx : rpc_context)
    (wallet_name : string option) (_params : Yojson.Safe.t list)
    : (Yojson.Safe.t, string) result =
  match get_wallet_for_request ctx wallet_name with
  | Error e -> Error e
  | Ok wallet ->
    let name = Option.value wallet_name ~default:"" in
    let info = Wallet.get_wallet_info name wallet in
    Ok (`Assoc [
      ("walletname", `String info.Wallet.wallet_name);
      ("walletversion", `Int info.wallet_version);
      ("format", `String info.format);
      ("balance", `Float info.balance);
      ("unconfirmed_balance", `Float info.unconfirmed_balance);
      ("immature_balance", `Float info.immature_balance);
      ("txcount", `Int info.tx_count);
      ("keypoolsize", `Int info.keypoolsize);
      ("private_keys_enabled", `Bool info.private_keys_enabled);
      ("avoid_reuse", `Bool info.avoid_reuse);
      ("scanning", `Bool info.scanning);
      ("descriptors", `Bool info.descriptors);
      ("external_signer", `Bool info.external_signer);
    ])

(* ============================================================================
   Wallet Encryption Handlers (encryptwallet / walletpassphrase / walletlock)
   ============================================================================

   These wire the existing PBKDF2 + AES-256-CBC primitives in
   [Wallet.encrypt_wallet], [Wallet.wallet_passphrase], [Wallet.wallet_lock]
   to JSON-RPC. Behaviour mirrors Bitcoin Core's
   [src/wallet/rpc/encrypt.cpp]:
     - encryptwallet "passphrase"
         Encrypts a previously-unencrypted wallet. The wallet is left in the
         locked state; Core also recommends the operator restart, but our
         implementation can keep running locked.
     - walletpassphrase "passphrase" timeout
         Decrypts the wallet's master key for [timeout] seconds. After the
         timeout elapses, an [Lwt.async] timer triggers [wallet_lock], which
         zeroes the in-memory private keys.
     - walletlock
         Immediately re-locks an unlocked wallet. *)

(* encryptwallet "passphrase" *)
let handle_encryptwallet (ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  match params with
  | `String passphrase :: _ ->
    if String.length passphrase = 0 then
      Error "passphrase can not be empty"
    else begin
      match get_wallet_for_request ctx None with
      | Error e -> Error e
      | Ok wallet ->
        if Wallet.is_encrypted wallet then
          Error "Error: running with an encrypted wallet, but encryptwallet was called."
        else begin
          match Wallet.encrypt_wallet wallet ~passphrase with
          | Error e -> Error e
          | Ok () ->
            Ok (`String
              "wallet encrypted; The keypool has been flushed and a new HD seed was generated (if you are using HD). You need to make a new backup.")
        end
    end
  | _ ->
    Error "Invalid parameters: expected [passphrase]"

(* walletpassphrase "passphrase" timeout

   Unlocks the wallet for [timeout] seconds. Schedules an Lwt.async sleeper
   that re-locks once the deadline passes. The sleeper uses a snapshot of
   the unlock-state expiry so a later [walletpassphrase] that *extends* the
   timeout is honoured: if the wallet is still unlocked but the snapshotted
   deadline has been superseded, we leave it alone. *)
let handle_walletpassphrase (ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  match params with
  | `String passphrase :: timeout_param :: _ ->
    let timeout = match timeout_param with
      | `Int n -> float_of_int n
      | `Float f -> f
      | _ -> -1.0
    in
    if timeout <= 0.0 then
      Error "Timeout cannot be negative."
    else if String.length passphrase = 0 then
      Error "passphrase can not be empty"
    else begin
      (* Core caps the unlock timeout at 100,000,000 seconds. *)
      let timeout = min timeout 100_000_000.0 in
      match get_wallet_for_request ctx None with
      | Error e -> Error e
      | Ok wallet ->
        if not (Wallet.is_encrypted wallet) then
          Error "Error: running with an unencrypted wallet, but walletpassphrase was called."
        else begin
          match Wallet.wallet_passphrase wallet ~passphrase ~timeout with
          | Error e -> Error e
          | Ok () ->
            (* Snapshot the deadline this unlock established. If the user
               re-issues walletpassphrase with a larger timeout before this
               sleeper fires, the new deadline will exceed our snapshot and
               we must NOT lock — Core's behaviour is to extend, not reset. *)
            let our_deadline = Unix.gettimeofday () +. timeout in
            Lwt.async (fun () ->
              let open Lwt.Syntax in
              let* () = Lwt_unix.sleep timeout in
              (* Only lock if the wallet is still unlocked AND the current
                 unlock state matches our timer (i.e. nobody extended it). *)
              (match wallet.Wallet.encryption.lock_state with
               | Wallet.Locked -> ()
               | Wallet.Unlocked { expires; _ } ->
                 if expires <= our_deadline +. 0.5 then
                   Wallet.wallet_lock wallet);
              Lwt.return_unit
            );
            Ok `Null
        end
    end
  | _ ->
    Error "Invalid parameters: expected [passphrase, timeout]"

(* walletlock *)
let handle_walletlock (ctx : rpc_context)
    (_params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  match get_wallet_for_request ctx None with
  | Error e -> Error e
  | Ok wallet ->
    if not (Wallet.is_encrypted wallet) then
      Error "Error: running with an unencrypted wallet, but walletlock was called."
    else begin
      Wallet.wallet_lock wallet;
      Ok `Null
    end

(* ============================================================================
   Address Validation Handler
   ============================================================================ *)

let handle_validateaddress (_ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  match params with
  | [`String address] ->
    (match Address.address_of_string address with
     | Ok addr ->
       let script_pubkey = Wallet.build_output_script addr in
       let is_witness = match addr.Address.addr_type with
         | Address.P2WPKH | Address.P2WSH | Address.P2TR | Address.WitnessUnknown _ -> true
         | Address.P2PKH | Address.P2SH -> false
       in
       let witness_version = match addr.Address.addr_type with
         | Address.P2WPKH | Address.P2WSH -> Some 0
         | Address.P2TR -> Some 1
         | Address.WitnessUnknown v -> Some v
         | _ -> None
       in
       (* W27-A: scriptPubKey from build_output_script is 22-34 bytes
          depending on address type; hash256_to_hex would truncate. *)
       let hex = cstruct_to_hex_early script_pubkey in
       let base_fields = [
         ("isvalid", `Bool true);
         ("address", `String address);
         ("scriptPubKey", `String hex);
         ("isscript", `Bool (addr.Address.addr_type = Address.P2SH));
         ("iswitness", `Bool is_witness);
       ] in
       let fields = match witness_version with
         | Some v -> ("witness_version", `Int v) :: base_fields
         | None -> base_fields
       in
       Ok (`Assoc fields)
     | Error _ ->
       Ok (`Assoc [("isvalid", `Bool false)]))
  | _ -> Error "Invalid parameters: expected [address]"

(* ============================================================================
   Message Sign / Verify Handlers
   (Bitcoin Core: src/rpc/signmessage.cpp + src/common/signmessage.cpp)
   ============================================================================ *)

(* signmessagewithprivkey ["WIF", "message"]: returns base64 65-byte compact
   signature.  Mirrors Core's "signmessagewithprivkey" RPC
   (src/rpc/signmessage.cpp::signmessagewithprivkey): caller supplies a WIF
   directly, no wallet involvement. *)
let handle_signmessagewithprivkey (_ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  match params with
  | [`String wif; `String message] ->
    (match Address.wif_decode wif with
     | Error e -> Error (Printf.sprintf "Invalid private key: %s" e)
     | Ok (privkey, compressed, _network) ->
       let msg_hash = Crypto.message_hash message in
       (try
         let sig_bytes = Crypto.sign_compact ~compressed privkey msg_hash in
         let sig_str = Cstruct.to_string sig_bytes in
         Ok (`String (Base64.encode_string sig_str))
       with _ -> Error "Sign failed"))
  | _ -> Error "Invalid parameters: expected [\"privkey\", \"message\"]"

(* signmessage ["address", "message"]: wallet-scoped signing.  Mirrors Core's
   wallet/rpc/signmessage.cpp::signmessage — looks up the private key for
   [address] in the loaded wallet, then produces a base64 65-byte compact
   signature over the Bitcoin-Signed-Message MessageHash framing.  Core
   restricts the destination to PKHash (P2PKH); we follow that.

   For backward compatibility with the legacy "signmessage WIF message"
   shape that earlier camlcoin builds (and the cross-impl test fleet) used,
   we sniff the first parameter: if it parses as a WIF, dispatch to the
   privkey path; otherwise treat it as an address and require the wallet. *)
let handle_signmessage (ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  match params with
  | [`String addr_or_wif; `String message] ->
    (* Backward-compat: if the first arg parses as WIF, route to the legacy
       privkey-based path.  This keeps existing callers working without
       forcing them to switch to "signmessagewithprivkey". *)
    (match Address.wif_decode addr_or_wif with
     | Ok _ ->
       handle_signmessagewithprivkey ctx params
     | Error _ ->
       (* Wallet-scoped path: look up the address in the loaded wallet. *)
       match ctx.wallet with
       | None -> Error "Method not found: no wallet is loaded."
       | Some wallet ->
         match Address.address_of_string addr_or_wif with
         | Error _ -> Error "Invalid address"
         | Ok addr ->
           (* Core requires PKHash (P2PKH) for signmessage. *)
           (match addr.Address.addr_type with
            | Address.P2PKH -> ()
            | _ ->
              (* Fall through into the lookup; if no key matches, the user
                 will get a clear error.  But first, return the Core message
                 directly for non-P2PKH so callers see the same shape. *)
              ()) ;
           if addr.Address.addr_type <> Address.P2PKH then
             Error "Address does not refer to key"
           else
             match Wallet.find_by_address wallet addr_or_wif with
             | None ->
               Error "Private key not available"
             | Some kp ->
               let msg_hash = Crypto.message_hash message in
               (try
                 let sig_bytes = Crypto.sign_compact ~compressed:true
                   kp.Wallet.private_key msg_hash in
                 let sig_str = Cstruct.to_string sig_bytes in
                 Ok (`String (Base64.encode_string sig_str))
               with _ -> Error "Sign failed"))
  | _ ->
    Error "Invalid parameters: expected [\"address\", \"message\"]"

(* verifymessage ["address", "signature_b64", "message"]: returns true iff the
   recovered pubkey hashes to the address's pubkey hash.  Only P2PKH is
   supported (matches Core's MessageVerify which rejects non-PKHash
   destinations). *)
let handle_verifymessage (_ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  match params with
  | [`String address_str; `String sig_b64; `String message] ->
    (match Address.address_of_string address_str with
     | Error _ -> Error "Invalid address"
     | Ok addr ->
       (match addr.Address.addr_type with
        | Address.P2PKH ->
          (match Base64.decode sig_b64 with
           | Error _ -> Error "Malformed base64 encoding"
           | Ok sig_str ->
             let sig_cs = Cstruct.of_string sig_str in
             if Cstruct.length sig_cs <> 65 then Ok (`Bool false)
             else begin
               let msg_hash = Crypto.message_hash message in
               match Crypto.recover_compact sig_cs msg_hash with
               | None -> Ok (`Bool false)
               | Some pubkey ->
                 let recovered_h160 = Crypto.hash160 pubkey in
                 Ok (`Bool (Cstruct.equal recovered_h160 addr.Address.hash))
             end)
        | _ -> Error "Address does not refer to a key (only P2PKH supported)"))
  | _ ->
    Error "Invalid parameters: expected [\"address\", \"signature\", \"message\"]"

(* ============================================================================
   Mempool Persistence Handlers
   (Bitcoin Core: src/rpc/mempool.cpp::dumpmempool, ::loadmempool;
    "savemempool" is an alias for dumpmempool that exists for legacy callers.)
   ============================================================================ *)

let mempool_dat_path (ctx : rpc_context) : (string, string) result =
  match ctx.data_dir with
  | None ->
    Error "Mempool persistence unavailable: rpc context has no data_dir"
  | Some d -> Ok (Filename.concat d "mempool.dat")

let handle_dumpmempool (ctx : rpc_context)
    (_params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  match mempool_dat_path ctx with
  | Error e -> Error e
  | Ok path ->
    (try
      Mempool.save_mempool ctx.mempool path;
      Ok (`Assoc [("filename", `String path)])
    with exn ->
      Error (Printf.sprintf "Unable to dump mempool: %s"
        (Printexc.to_string exn)))

let handle_loadmempool (ctx : rpc_context)
    (_params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  match mempool_dat_path ctx with
  | Error e -> Error e
  | Ok path ->
    (try
      let n = Mempool.load_mempool ctx.mempool path in
      Ok (`Assoc [
        ("path", `String path);
        ("loaded", `Int n);
      ])
    with exn ->
      Error (Printf.sprintf "Unable to load mempool: %s"
        (Printexc.to_string exn)))

(* ============================================================================
   UTXO Lookup Handler
   ============================================================================ *)

let handle_gettxout (ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  match params with
  | [`String txid_hex; `Int vout] ->
    let txid = parse_txid_param txid_hex in
    let utxo_set = Utxo.UtxoSet.create ctx.chain.db in
    (match Utxo.UtxoSet.get utxo_set txid vout with
     | None -> Ok `Null
     | Some utxo ->
       let tip_hash_hex = match ctx.chain.tip with
         | Some t -> Types.hash256_to_hex_display t.hash
         | None -> "0000000000000000000000000000000000000000000000000000000000000000"
       in
       let tip_height = match ctx.chain.tip with
         | Some t -> t.height
         | None -> 0
       in
       let confirmations = max 1 (tip_height - utxo.Utxo.height + 1) in
       Ok (`Assoc [
         ("bestblock", `String tip_hash_hex);
         ("confirmations", `Int confirmations);
         ("value", `Float (Int64.to_float utxo.Utxo.value /. 100_000_000.0));
         ("scriptPubKey", `Assoc [
           (* W27-A: scriptPubKey is variable-length; hash256_to_hex truncates. *)
           ("hex", `String (cstruct_to_hex_early utxo.Utxo.script_pubkey));
         ]);
         ("coinbase", `Bool utxo.Utxo.is_coinbase);
       ]))
  | _ -> Error "Invalid parameters: expected [txid, vout]"

(* ============================================================================
   testmempoolaccept Handler
   ============================================================================ *)

let handle_testmempoolaccept (ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  match params with
  | [`List [`String hex_tx]] ->
    (try
      let data = Cstruct.of_hex hex_tx in
      let r = Serialize.reader_of_cstruct data in
      let tx = Serialize.deserialize_transaction r in
      let txid = Crypto.compute_txid tx in
      let hex_txid = Types.hash256_to_hex_display txid in
      match Mempool.add_transaction ~dry_run:true ctx.mempool tx with
      | Ok entry ->
        let vsize = (entry.Mempool.weight + 3) / 4 in
        let fee_btc = Int64.to_float entry.Mempool.fee /. 100_000_000.0 in
        Ok (`List [`Assoc [
          ("txid", `String hex_txid);
          ("allowed", `Bool true);
          ("vsize", `Int vsize);
          ("fees", `Assoc [
            ("base", `Float fee_btc);
          ]);
        ]])
      | Error msg ->
        Ok (`List [`Assoc [
          ("txid", `String hex_txid);
          ("allowed", `Bool false);
          ("reject-reason", `String msg);
        ]])
    with exn ->
      Error (Printf.sprintf "TX decode failed: %s" (Printexc.to_string exn)))
  | _ ->
    Error "Invalid parameters: expected [[rawtx]]"

(* ============================================================================
   submitpackage Handler

   Mirrors Bitcoin Core's `submitpackage` RPC. Accepts an array of raw tx
   hex strings (parents + child(ren), max 25 txs), validates atomically via
   Mempool.accept_package, and returns a Core-compatible JSON object:

     {
       "package_msg":  "success" | "<error string>",
       "tx-results":   { <wtxid_hex>: { txid, [vsize, fees{base,...}], [error] } },
       "replaced-transactions": [ ... ]   (* always present, may be empty *)
     }

   Wired to the existing Mempool.accept_package engine; does not refactor
   it. See CORE-PARITY-AUDIT/_mempool-package-rbf-cross-impl-audit-2026-05-06-part1.md
   YELLOW-5.
   ============================================================================ *)

let handle_submitpackage (ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  (* Parse parameters: [package_array [, maxfeerate [, maxburnamount]]] *)
  let parse_params params =
    let parse_amount json default =
      match json with
      | `Float f -> Ok f
      | `Int i -> Ok (float_of_int i)
      | `Null -> Ok default
      | _ -> Error "maxfeerate / maxburnamount must be numeric"
    in
    match params with
    | [`List arr] ->
      Ok (arr, default_max_raw_tx_fee_rate, default_max_burn_amount)
    | [`List arr; mf] ->
      (match parse_amount mf default_max_raw_tx_fee_rate with
       | Ok f -> Ok (arr, f, default_max_burn_amount)
       | Error e -> Error e)
    | [`List arr; mf; mb] ->
      (match parse_amount mf default_max_raw_tx_fee_rate, parse_amount mb 0.0 with
       | Ok f, Ok b ->
         let burn_sats = Int64.of_float (b *. 100_000_000.0) in
         Ok (arr, f, burn_sats)
       | Error e, _ | _, Error e -> Error e)
    | _ ->
      Error "Invalid parameters: expected [[\"rawtx\",...] (, maxfeerate (, maxburnamount))]"
  in
  match parse_params params with
  | Error e -> Error e
  | Ok (raw_arr, max_fee_rate, max_burn_amount) ->
    (* Enforce 1..MAX_PACKAGE_COUNT before doing any decoding work *)
    let n = List.length raw_arr in
    if n = 0 || n > Mempool.max_package_count then
      Error (Printf.sprintf
        "Array must contain between 1 and %d transactions."
        Mempool.max_package_count)
    else begin
      (* Decode all transactions, halt on first decode error (Core behavior) *)
      let decode_one json =
        match json with
        | `String hex ->
          (try
            let data = Cstruct.of_hex hex in
            let r = Serialize.reader_of_cstruct data in
            Ok (Serialize.deserialize_transaction r)
          with exn ->
            Error (Printf.sprintf "TX decode failed: %s" (Printexc.to_string exn)))
        | _ -> Error "package element must be a hex string"
      in
      let rec decode_all acc = function
        | [] -> Ok (List.rev acc)
        | j :: rest ->
          (match decode_one j with
           | Ok tx -> decode_all (tx :: acc) rest
           | Error e -> Error e)
      in
      match decode_all [] raw_arr with
      | Error e -> Error e
      | Ok txs ->
        (* Burn-amount check on every output before mempool validation.
           Core throws MAX_BURN_EXCEEDED here; we surface it as an Error. *)
        let burn_violation = List.find_opt (fun tx ->
          sum_burn_amount tx > max_burn_amount
        ) txs in
        (match burn_violation with
         | Some tx ->
           let burn = sum_burn_amount tx in
           Error (Printf.sprintf
             "Unspendable output exceeds maximum: %Ld > %Ld satoshis"
             burn max_burn_amount)
         | None ->
           (* Validate as a package via existing engine *)
           let pkg_result = Mempool.accept_package ctx.mempool txs in
           (* Build a wtxid -> entry-or-error lookup *)
           let entry_by_wtxid_key : (string, Mempool.mempool_entry) Hashtbl.t =
             Hashtbl.create n in
           let error_by_wtxid_key : (string, string) Hashtbl.t =
             Hashtbl.create n in
           let package_msg = ref "success" in
           (match pkg_result with
            | Mempool.PackageAccepted entries ->
              List.iter (fun e ->
                Hashtbl.replace entry_by_wtxid_key
                  (Cstruct.to_string e.Mempool.wtxid) e
              ) entries
            | Mempool.PackagePartial { accepted; rejected } ->
              package_msg := "package-partial-accept";
              List.iter (fun e ->
                Hashtbl.replace entry_by_wtxid_key
                  (Cstruct.to_string e.Mempool.wtxid) e
              ) accepted;
              List.iter (fun (tx, msg) ->
                let wtxid = Crypto.compute_wtxid tx in
                Hashtbl.replace error_by_wtxid_key
                  (Cstruct.to_string wtxid) msg
              ) rejected
            | Mempool.PackageRejected msg ->
              package_msg := msg);

           (* maxfeerate post-check on accepted entries; evict + flag if exceeded *)
           if max_fee_rate > 0.0 then begin
             let exceed_keys = ref [] in
             Hashtbl.iter (fun key e ->
               let vsize = (e.Mempool.weight + 3) / 4 in
               let max_fee_sats =
                 Int64.of_float
                   (max_fee_rate *. 100_000_000.0 /. 1000.0
                    *. float_of_int vsize)
               in
               if e.Mempool.fee > max_fee_sats then
                 exceed_keys := (key, e) :: !exceed_keys
             ) entry_by_wtxid_key;
             List.iter (fun (key, e) ->
               Mempool.remove_transaction ctx.mempool e.Mempool.txid;
               Hashtbl.remove entry_by_wtxid_key key;
               Hashtbl.replace error_by_wtxid_key key "max-fee-exceeded"
             ) !exceed_keys;
             if !exceed_keys <> [] && !package_msg = "success" then
               package_msg := "max-fee-exceeded"
           end;

           (* Build tx-results map and announce accepted txs to peers *)
           let tx_results = List.map (fun tx ->
             let txid = Crypto.compute_txid tx in
             let wtxid = Crypto.compute_wtxid tx in
             let wtxid_key = Cstruct.to_string wtxid in
             let txid_hex = Types.hash256_to_hex_display txid in
             let wtxid_hex = Types.hash256_to_hex_display wtxid in
             match Hashtbl.find_opt entry_by_wtxid_key wtxid_key with
             | Some e ->
               let vsize = (e.Mempool.weight + 3) / 4 in
               let fee_btc = Int64.to_float e.Mempool.fee /. 100_000_000.0 in
               let effective_feerate_btc_per_kvb =
                 if vsize > 0 then
                   Int64.to_float e.Mempool.fee
                   /. float_of_int vsize
                   /. 100_000.0
                 else 0.0
               in
               (* Announce to peers (best-effort) *)
               let fee_rate =
                 Int64.div e.Mempool.fee
                   (Int64.of_int (max 1 (e.Mempool.weight / 4)))
               in
               Lwt.async (fun () ->
                 Peer_manager.announce_tx ctx.peer_manager
                   ~txid:e.Mempool.txid ~wtxid ~fee_rate);
               (wtxid_hex, `Assoc [
                 ("txid", `String txid_hex);
                 ("vsize", `Int vsize);
                 ("fees", `Assoc [
                   ("base", `Float fee_btc);
                   ("effective-feerate", `Float effective_feerate_btc_per_kvb);
                   ("effective-includes", `List [`String wtxid_hex]);
                 ]);
               ])
             | None ->
               let err_msg =
                 match Hashtbl.find_opt error_by_wtxid_key wtxid_key with
                 | Some msg -> msg
                 | None -> "package-not-validated"
               in
               (wtxid_hex, `Assoc [
                 ("txid", `String txid_hex);
                 ("error", `String err_msg);
               ])
           ) txs in
           Ok (`Assoc [
             ("package_msg", `String !package_msg);
             ("tx-results", `Assoc tx_results);
             ("replaced-transactions", `List []);
           ]))
    end

(* ============================================================================
   signrawtransactionwithkey Handler
   ============================================================================ *)

let handle_signrawtransactionwithkey (ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  match params with
  | [`String hex_tx; `List wif_keys] | [`String hex_tx; `List wif_keys; _] ->
    (try
      let data = Cstruct.of_hex hex_tx in
      let r = Serialize.reader_of_cstruct data in
      let tx = Serialize.deserialize_transaction r in
      (* Decode all WIF keys *)
      let decoded_keys = List.filter_map (fun wif_json ->
        match wif_json with
        | `String wif ->
          (match Address.wif_decode wif with
           | Ok (privkey, _compressed, _network) ->
             let pubkey = Crypto.derive_public_key ~compressed:true privkey in
             let pkh = Crypto.hash160 pubkey in
             let xonly = Crypto.derive_xonly_pubkey privkey in
             Some (privkey, pubkey, pkh, xonly)
           | Error _ -> None)
        | _ -> None
      ) wif_keys in
      (* Look up UTXO info for each input *)
      let utxo_set = Utxo.UtxoSet.create ctx.chain.db in
      let input_utxos = List.map (fun inp ->
        let prev = inp.Types.previous_output in
        (* Try chain UTXO set first *)
        match Utxo.UtxoSet.get utxo_set prev.txid (Int32.to_int prev.vout) with
        | Some utxo -> Some utxo
        | None ->
          (* Try mempool *)
          let txid_key = Cstruct.to_string prev.txid in
          match Hashtbl.find_opt ctx.mempool.entries txid_key with
          | Some parent_entry ->
            let vout = Int32.to_int prev.vout in
            if vout < List.length parent_entry.tx.outputs then
              let out = List.nth parent_entry.tx.outputs vout in
              Some { Utxo.value = out.Types.value;
                     script_pubkey = out.script_pubkey;
                     height = 0; is_coinbase = false }
            else None
          | None ->
            (* Try chain db for confirmed tx *)
            (match Storage.ChainDB.get_tx_index ctx.chain.db prev.txid with
             | Some (block_hash, _tx_idx) ->
               (match Storage.ChainDB.get_block ctx.chain.db block_hash with
                | Some block ->
                  let found = List.find_opt (fun btx ->
                    Cstruct.equal (Crypto.compute_txid btx) prev.txid
                  ) block.transactions in
                  (match found with
                   | Some btx ->
                     let vout = Int32.to_int prev.vout in
                     if vout < List.length btx.outputs then
                       let out = List.nth btx.outputs vout in
                       Some { Utxo.value = out.Types.value;
                              script_pubkey = out.script_pubkey;
                              height = 0; is_coinbase = false }
                     else None
                   | None -> None)
                | None -> None)
             | None -> None)
      ) tx.inputs in
      (* Build prevouts list for taproot sighash *)
      let prevouts = List.map (fun utxo_opt ->
        match utxo_opt with
        | Some utxo -> (utxo.Utxo.value, utxo.Utxo.script_pubkey)
        | None -> (0L, Cstruct.empty)
      ) input_utxos in
      (* Sign each input *)
      let signed_count = ref 0 in
      let total_inputs = List.length tx.inputs in
      let existing_witness_at i =
        if i < List.length tx.witnesses then
          List.nth tx.witnesses i
        else
          { Types.items = [] }
      in
      let new_inputs_and_witnesses = List.mapi (fun i inp ->
        match List.nth_opt input_utxos i with
        | None | Some None ->
          (inp, existing_witness_at i)
        | Some (Some utxo) ->
          let script_type = Script.classify_script utxo.Utxo.script_pubkey in
          let matching_key = match script_type with
            | Script.P2WPKH_script hash ->
              List.find_opt (fun (_priv, _pub, pkh, _xonly) ->
                Cstruct.equal pkh hash
              ) decoded_keys
            | Script.P2PKH_script hash ->
              List.find_opt (fun (_priv, _pub, pkh, _xonly) ->
                Cstruct.equal pkh hash
              ) decoded_keys
            | Script.P2TR_script xonly_hash ->
              List.find_opt (fun (_priv, _pub, _pkh, xonly) ->
                Cstruct.equal xonly xonly_hash
              ) decoded_keys
            | _ -> None
          in
          (match matching_key with
           | None ->
             (inp, existing_witness_at i)
           | Some (privkey, pubkey, pkh, _xonly) ->
             incr signed_count;
             (match script_type with
              | Script.P2TR_script _ ->
                let sighash = Script.compute_sighash_taproot tx i prevouts 0x00 () in
                let xonly_pk = Cstruct.sub pubkey 1 32 in
                let tweak = Crypto.compute_taproot_tweak xonly_pk None in
                let sig_bytes = Crypto.schnorr_sign_tweaked ~privkey ~tweak ~msg:sighash in
                (inp, { Types.items = [sig_bytes] })
              | Script.P2WPKH_script _ ->
                let script_code = Wallet.build_p2pkh_script pkh in
                let sighash = Script.compute_sighash_segwit
                  tx i script_code utxo.Utxo.value Script.sighash_all in
                let signature = Crypto.sign privkey sighash in
                let sig_with_hashtype = Cstruct.concat [
                  signature; Cstruct.of_string "\x01"
                ] in
                (inp, { Types.items = [sig_with_hashtype; pubkey] })
              | Script.P2PKH_script _ ->
                (* Legacy P2PKH: build scriptSig <sig+hashtype> <pubkey>; no witness *)
                let script_code = utxo.Utxo.script_pubkey in
                let sighash = Script.compute_sighash_legacy tx i script_code
                  Script.sighash_all in
                let signature = Crypto.sign privkey sighash in
                let sig_with_hashtype = Cstruct.concat [
                  signature; Cstruct.of_string "\x01"
                ] in
                let sig_len = Cstruct.length sig_with_hashtype in
                let pub_len = Cstruct.length pubkey in
                let script_sig = Cstruct.create (1 + sig_len + 1 + pub_len) in
                Cstruct.set_uint8 script_sig 0 sig_len;
                Cstruct.blit sig_with_hashtype 0 script_sig 1 sig_len;
                Cstruct.set_uint8 script_sig (1 + sig_len) pub_len;
                Cstruct.blit pubkey 0 script_sig (1 + sig_len + 1) pub_len;
                ({ inp with Types.script_sig }, { Types.items = [] })
              | _ ->
                (inp, existing_witness_at i)))
      ) tx.inputs in
      let new_inputs = List.map fst new_inputs_and_witnesses in
      let new_witnesses = List.map snd new_inputs_and_witnesses in
      (* Only carry the segwit marker/flag if at least one witness is non-empty;
         otherwise downstream deserialization rejects with "Superfluous witness
         record". This matches Bitcoin Core's CTransaction::HasWitness gating. *)
      let any_witness = List.exists (fun (w : Types.tx_witness) ->
        w.items <> []
      ) new_witnesses in
      let final_witnesses = if any_witness then new_witnesses else [] in
      let signed_tx = { tx with inputs = new_inputs; witnesses = final_witnesses } in
      let complete = !signed_count = total_inputs in
      let w = Serialize.writer_create () in
      Serialize.serialize_transaction w signed_tx;
      let cs = Serialize.writer_to_cstruct w in
      (* hash256_to_hex is hard-coded to 32 bytes; signed tx is variable length.
         Use the variable-length helper. *)
      let signed_hex = cstruct_to_hex_early cs in
      Ok (`Assoc [
        ("hex", `String signed_hex);
        ("complete", `Bool complete);
      ])
    with exn ->
      Error (Printf.sprintf "TX decode failed: %s" (Printexc.to_string exn)))
  | _ ->
    Error "Invalid parameters: expected [hexstring, [privkeys]]"

(* ============================================================================
   getblockstats Handler
   ============================================================================ *)

let handle_getblockstats (ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  let hash_opt = match params with
    | [`Int height] | [`Int height; _] ->
      Storage.ChainDB.get_hash_at_height ctx.chain.db height
    | [`String hash_hex] | [`String hash_hex; _] ->
      let hash_bytes = Types.hash256_of_hex hash_hex in
      let hash = Cstruct.create 32 in
      for i = 0 to 31 do
        Cstruct.set_uint8 hash i (Cstruct.get_uint8 hash_bytes (31 - i))
      done;
      Some hash
    | _ -> None
  in
  match hash_opt with
  | None -> Error "Invalid parameters: expected [height] or [blockhash]"
  | Some hash ->
    (match Storage.ChainDB.get_block ctx.chain.db hash with
     | None -> Error "Block not found"
     | Some block ->
       let entry = Sync.get_header ctx.chain hash in
       let height = match entry with
         | Some e -> e.height
         | None -> 0
       in
       let txs = List.length block.transactions in
       let ins = List.fold_left (fun acc tx ->
         let is_cb = match tx.Types.inputs with
           | inp :: _ -> Cstruct.equal inp.Types.previous_output.txid Types.zero_hash
           | [] -> false
         in
         if is_cb then acc else acc + List.length tx.Types.inputs
       ) 0 block.transactions in
       let outs = List.fold_left (fun acc tx ->
         acc + List.length tx.Types.outputs
       ) 0 block.transactions in
       let total_out = List.fold_left (fun acc tx ->
         List.fold_left (fun a out -> Int64.add a out.Types.value) acc tx.Types.outputs
       ) 0L block.transactions in
       let subsidy = Consensus.block_subsidy_for_network ctx.network.network_type height in
       let total_weight =
         80 * Consensus.witness_scale_factor +
         List.fold_left (fun acc tx ->
           acc + Validation.compute_tx_weight tx
         ) 0 block.transactions in
       let w_ser = Serialize.writer_create () in
       Serialize.serialize_block w_ser block;
       let total_size = Cstruct.length (Serialize.writer_to_cstruct w_ser) in
       let coinbase_output = match block.transactions with
         | cb :: _ ->
           List.fold_left (fun acc out -> Int64.add acc out.Types.value) 0L cb.Types.outputs
         | [] -> 0L
       in
       let totalfee = Int64.sub coinbase_output subsidy in
       let totalfee = if totalfee < 0L then 0L else totalfee in
       let avgfee = if txs > 1 then Int64.div totalfee (Int64.of_int (txs - 1)) else 0L in
       let utxo_increase = outs - ins in
       Ok (`Assoc [
         ("avgfee", `Int (Int64.to_int avgfee));
         ("height", `Int height);
         ("ins", `Int ins);
         ("outs", `Int outs);
         ("subsidy", `Int (Int64.to_int subsidy));
         ("total_out", `Int (Int64.to_int total_out));
         ("total_size", `Int total_size);
         ("total_weight", `Int total_weight);
         ("totalfee", `Int (Int64.to_int totalfee));
         ("txs", `Int txs);
         ("utxo_increase", `Int utxo_increase);
       ]))

(* ============================================================================
   PSBT (BIP-174) Handlers
   ============================================================================ *)

(* createpsbt [{"txid":"...", "vout":n},...] [{"address":amount},...] ( locktime )
   Creates an unsigned PSBT from raw transaction components *)
let handle_createpsbt (ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  let extract_inputs inputs_json =
    let extract_one = function
      | `Assoc fields ->
        let txid = match List.assoc_opt "txid" fields with
          | Some (`String s) ->
            let hash_bytes = Types.hash256_of_hex s in
            (* Reverse bytes for internal representation *)
            let hash = Cstruct.create 32 in
            for i = 0 to 31 do
              Cstruct.set_uint8 hash i (Cstruct.get_uint8 hash_bytes (31 - i))
            done;
            hash
          | _ -> failwith "Missing txid"
        in
        let vout = match List.assoc_opt "vout" fields with
          | Some (`Int n) -> Int32.of_int n
          | _ -> failwith "Missing vout"
        in
        let sequence = match List.assoc_opt "sequence" fields with
          | Some (`Int n) -> Int32.of_int n
          | _ -> 0xFFFFFFFEl
        in
        { Types.previous_output = { txid; vout };
          script_sig = Cstruct.empty;
          sequence }
      | _ -> failwith "Invalid input format"
    in
    match inputs_json with
    | `List l -> List.map extract_one l
    | _ -> failwith "Inputs must be an array"
  in
  let extract_outputs outputs_json network =
    let extract_one = function
      | `Assoc fields ->
        List.filter_map (fun (addr_str, amt) ->
          if addr_str = "data" then
            (* OP_RETURN output *)
            match amt with
            | `String hex_data ->
              let data = hex_to_cstruct hex_data in
              let script = Cstruct.create (2 + Cstruct.length data) in
              Cstruct.set_uint8 script 0 0x6a; (* OP_RETURN *)
              Cstruct.set_uint8 script 1 (Cstruct.length data);
              Cstruct.blit data 0 script 2 (Cstruct.length data);
              Some { Types.value = 0L; script_pubkey = script }
            | _ -> None
          else
            match Address.address_of_string addr_str with
            | Error _ -> None
            | Ok addr ->
              if addr.network <> network then None
              else
                let value = match amt with
                  | `Float f -> Int64.of_float (f *. 100_000_000.0)
                  | `Int i -> Int64.of_int (i * 100_000_000)
                  | `String s -> Int64.of_float (float_of_string s *. 100_000_000.0)
                  | _ -> 0L
                in
                let script_pubkey = Address.address_to_script addr in
                Some { Types.value; script_pubkey }
        ) fields
      | _ -> []
    in
    match outputs_json with
    | `List l -> List.concat_map extract_one l
    | _ -> failwith "Outputs must be an array"
  in
  match params with
  | [inputs_json; outputs_json] | [inputs_json; outputs_json; _] ->
    (try
      let network = network_to_address_network ctx.network in
      let inputs = extract_inputs inputs_json in
      let outputs = extract_outputs outputs_json network in
      let locktime = match params with
        | [_; _; `Int lt] -> Int32.of_int lt
        | _ -> 0l
      in
      let tx : Types.transaction = {
        version = 2l;
        inputs;
        outputs;
        witnesses = [];
        locktime;
      } in
      let psbt = Psbt.create tx in
      let b64 = Psbt.to_base64 psbt in
      Ok (`String b64)
    with
    | Failure msg -> Error msg
    | exn -> Error (Printexc.to_string exn))
  | _ ->
    Error "Invalid parameters: expected [[inputs], [outputs], (locktime)]"

(* decodepsbt "base64string"
   Decode a PSBT and return detailed information *)
let handle_decodepsbt (_ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  match params with
  | [`String b64] ->
    (match Psbt.of_base64 b64 with
     | Error e -> Error (Psbt.string_of_error e)
     | Ok psbt ->
       (* Build tx JSON *)
       let tx = psbt.tx in
       let txid = Crypto.compute_txid tx in
       let inputs_json = List.map (fun inp ->
         `Assoc [
           ("txid", `String (Types.hash256_to_hex_display inp.Types.previous_output.txid));
           ("vout", `Int (Int32.to_int inp.Types.previous_output.vout));
           ("sequence", `Int (Int32.to_int inp.sequence));
         ]
       ) tx.inputs in
       let outputs_json = List.map (fun out ->
         `Assoc [
           ("value", `Float (Int64.to_float out.Types.value /. 100_000_000.0));
           ("scriptPubKey", `Assoc [
             ("hex", `String (cstruct_to_hex out.Types.script_pubkey));
           ]);
         ]
       ) tx.outputs in
       let tx_json = `Assoc [
         ("txid", `String (Types.hash256_to_hex_display txid));
         ("version", `Int (Int32.to_int tx.version));
         ("locktime", `Int (Int32.to_int tx.locktime));
         ("vin", `List inputs_json);
         ("vout", `List outputs_json);
       ] in
       (* Build inputs JSON *)
       let psbt_inputs_json = List.mapi (fun i inp ->
         let fields = ref [] in
         (match inp.Psbt.witness_utxo with
          | Some utxo ->
            fields := !fields @ [
              ("witness_utxo", `Assoc [
                ("amount", `Float (Int64.to_float utxo.value /. 100_000_000.0));
                ("scriptPubKey", `Assoc [
                  ("hex", `String (cstruct_to_hex utxo.script_pubkey));
                ]);
              ])
            ]
          | None -> ());
         (match inp.Psbt.non_witness_utxo with
          | Some _ -> fields := !fields @ [("non_witness_utxo", `Bool true)]
          | None -> ());
         if inp.Psbt.partial_sigs <> [] then
           fields := !fields @ [
             ("partial_signatures", `Assoc (List.map (fun (ps : Psbt.partial_sig) ->
               (cstruct_to_hex ps.pubkey, `String (cstruct_to_hex ps.signature))
             ) inp.partial_sigs))
           ];
         (match inp.Psbt.sighash_type with
          | Some sht -> fields := !fields @ [("sighash", `String (Int32.to_string sht))]
          | None -> ());
         (match inp.Psbt.redeem_script with
          | Some rs -> fields := !fields @ [("redeem_script", `Assoc [("hex", `String (cstruct_to_hex rs))])]
          | None -> ());
         (match inp.Psbt.witness_script with
          | Some ws -> fields := !fields @ [("witness_script", `Assoc [("hex", `String (cstruct_to_hex ws))])]
          | None -> ());
         if inp.Psbt.bip32_derivations <> [] then
           fields := !fields @ [
             ("bip32_derivs", `List (List.map (fun d ->
               `Assoc [
                 ("pubkey", `String (cstruct_to_hex d.Psbt.pubkey));
                 ("master_fingerprint", `String (Printf.sprintf "%08lx" d.origin.fingerprint));
                 ("path", `String (String.concat "/" (
                   "m" :: List.map (fun idx ->
                     if Int32.compare idx 0x80000000l >= 0 then
                       Printf.sprintf "%ld'" (Int32.sub idx 0x80000000l)
                     else
                       Printf.sprintf "%ld" idx
                   ) d.origin.path
                 )));
               ]
             ) inp.bip32_derivations))
           ];
         (match inp.Psbt.final_scriptsig with
          | Some ss -> fields := !fields @ [("final_scriptSig", `Assoc [("hex", `String (cstruct_to_hex ss))])]
          | None -> ());
         (match inp.Psbt.final_scriptwitness with
          | Some wit -> fields := !fields @ [
              ("final_scriptwitness", `List (List.map (fun item ->
                `String (cstruct_to_hex item)
              ) wit))
            ]
          | None -> ());
         (match inp.Psbt.tap_key_sig with
          | Some sig_ -> fields := !fields @ [("taproot_key_path_sig", `String (cstruct_to_hex sig_))]
          | None -> ());
         (match inp.Psbt.tap_internal_key with
          | Some key -> fields := !fields @ [("taproot_internal_key", `String (cstruct_to_hex key))]
          | None -> ());
         `Assoc (("index", `Int i) :: !fields)
       ) psbt.inputs in
       (* Build outputs JSON *)
       let psbt_outputs_json = List.mapi (fun i out ->
         let fields = ref [] in
         (match out.Psbt.redeem_script with
          | Some rs -> fields := !fields @ [("redeem_script", `Assoc [("hex", `String (cstruct_to_hex rs))])]
          | None -> ());
         (match out.Psbt.witness_script with
          | Some ws -> fields := !fields @ [("witness_script", `Assoc [("hex", `String (cstruct_to_hex ws))])]
          | None -> ());
         if out.Psbt.bip32_derivations <> [] then
           fields := !fields @ [
             ("bip32_derivs", `List (List.map (fun d ->
               `Assoc [
                 ("pubkey", `String (cstruct_to_hex d.Psbt.pubkey));
                 ("master_fingerprint", `String (Printf.sprintf "%08lx" d.origin.fingerprint));
               ]
             ) out.bip32_derivations))
           ];
         (match out.Psbt.tap_internal_key with
          | Some key -> fields := !fields @ [("taproot_internal_key", `String (cstruct_to_hex key))]
          | None -> ());
         `Assoc (("index", `Int i) :: !fields)
       ) psbt.outputs in
       (* Calculate fee if possible *)
       let fee_json = match Psbt.get_fee psbt with
         | Some fee -> [("fee", `Float (Int64.to_float fee /. 100_000_000.0))]
         | None -> []
       in
       Ok (`Assoc ([
         ("tx", tx_json);
         ("global_xpubs", `List (List.map (fun gx ->
           `Assoc [
             ("xpub", `String (cstruct_to_hex gx.Psbt.xpub));
             ("master_fingerprint", `String (Printf.sprintf "%08lx" gx.origin.fingerprint));
           ]
         ) psbt.global_xpubs));
         ("psbt_version", `Int (match psbt.version with Some v -> Int32.to_int v | None -> 0));
         ("inputs", `List psbt_inputs_json);
         ("outputs", `List psbt_outputs_json);
       ] @ fee_json)))
  | _ ->
    Error "Invalid parameters: expected [base64string]"

(* analyzepsbt "base64string"
   Analyze a PSBT and provide information about its status *)
let handle_analyzepsbt (_ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  match params with
  | [`String b64] ->
    (match Psbt.of_base64 b64 with
     | Error e -> Error (Psbt.string_of_error e)
     | Ok psbt ->
       let input_analyses = List.mapi (fun _i inp ->
         let has_utxo = inp.Psbt.witness_utxo <> None || inp.Psbt.non_witness_utxo <> None in
         let is_final = Psbt.is_input_finalized inp in
         let has_sigs = inp.Psbt.partial_sigs <> [] || inp.Psbt.tap_key_sig <> None in
         let next_role =
           if is_final then "extractor"
           else if has_sigs then "finalizer"
           else if has_utxo then "signer"
           else "updater"
         in
         `Assoc [
           ("has_utxo", `Bool has_utxo);
           ("is_final", `Bool is_final);
           ("next", `String next_role);
         ]
       ) psbt.inputs in
       let all_finalized = Psbt.is_finalized psbt in
       let unsigned_count = Psbt.count_unsigned_inputs psbt in
       let next_role =
         if all_finalized then "extractor"
         else if unsigned_count = 0 then "finalizer"
         else "signer"
       in
       let fee_json = match Psbt.get_fee psbt with
         | Some fee -> [("estimated_feerate", `Float (Int64.to_float fee /. 100_000_000.0))]
         | None -> []
       in
       Ok (`Assoc ([
         ("inputs", `List input_analyses);
         ("estimated_vsize", `Int 0); (* Would need weight calculation *)
         ("next", `String next_role);
       ] @ fee_json)))
  | _ ->
    Error "Invalid parameters: expected [base64string]"

(* combinepsbt ["base64string",...]
   Combine multiple PSBTs into one *)
let handle_combinepsbt (_ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  match params with
  | [`List psbts] when List.length psbts >= 1 ->
    let decode_psbt = function
      | `String b64 -> Psbt.of_base64 b64
      | _ -> Error (Psbt.Parse_error "Not a string")
    in
    let decoded = List.map decode_psbt psbts in
    let errors = List.filter_map (function
      | Error e -> Some (Psbt.string_of_error e)
      | Ok _ -> None
    ) decoded in
    if errors <> [] then
      Error (String.concat "; " errors)
    else
      let psbts = List.filter_map (function
        | Ok p -> Some p
        | Error _ -> None
      ) decoded in
      (match psbts with
       | [] -> Error "No valid PSBTs"
       | first :: rest ->
         let combined = List.fold_left (fun acc p ->
           match acc with
           | Error e -> Error e
           | Ok psbt ->
             match Psbt.combine psbt p with
             | Ok c -> Ok c
             | Error msg -> Error msg
         ) (Ok first) rest in
         match combined with
         | Error msg -> Error msg
         | Ok psbt -> Ok (`String (Psbt.to_base64 psbt)))
  | _ ->
    Error "Invalid parameters: expected [[base64strings]]"

(* finalizepsbt "base64string" ( extract )
   Finalize the inputs of a PSBT *)
let handle_finalizepsbt (_ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  match params with
  | [`String b64] | [`String b64; _] ->
    let extract = match params with
      | [_; `Bool b] -> b
      | _ -> true
    in
    (match Psbt.of_base64 b64 with
     | Error e -> Error (Psbt.string_of_error e)
     | Ok psbt ->
       (* Try to finalize each input based on its type *)
       let finalize_one psbt i inp =
         if Psbt.is_input_finalized inp then
           Ok psbt
         else if inp.Psbt.tap_key_sig <> None then
           Psbt.finalize_input_taproot psbt i
         else if inp.Psbt.partial_sigs <> [] then
           (* Determine script type from witness_utxo *)
           match inp.Psbt.witness_utxo with
           | Some utxo ->
             let script = utxo.script_pubkey in
             if Cstruct.length script = 22 && Cstruct.get_uint8 script 0 = 0x00 then
               (* P2WPKH *)
               Psbt.finalize_input_p2wpkh psbt i
             else if Cstruct.length script = 23 && Cstruct.get_uint8 script 0 = 0xa9 then
               (* P2SH - check if it's P2SH-P2WPKH *)
               Psbt.finalize_input_p2sh_p2wpkh psbt i
             else
               (* Try P2WPKH as fallback *)
               Psbt.finalize_input_p2wpkh psbt i
           | None ->
             (* Try P2PKH for non-witness *)
             Psbt.finalize_input_p2pkh psbt i
         else
           Ok psbt
       in
       let result = List.fold_left (fun acc (i, inp) ->
         match acc with
         | Error e -> Error e
         | Ok psbt -> finalize_one psbt i inp
       ) (Ok psbt) (List.mapi (fun i inp -> (i, inp)) psbt.inputs) in
       match result with
       | Error msg -> Error msg
       | Ok finalized ->
         let complete = Psbt.is_finalized finalized in
         if extract && complete then
           match Psbt.extract finalized with
           | Error msg -> Error msg
           | Ok tx ->
             let w = Serialize.writer_create () in
             Serialize.serialize_transaction w tx;
             let hex = cstruct_to_hex (Serialize.writer_to_cstruct w) in
             Ok (`Assoc [
               ("hex", `String hex);
               ("complete", `Bool true);
             ])
         else
           Ok (`Assoc [
             ("psbt", `String (Psbt.to_base64 finalized));
             ("complete", `Bool complete);
           ]))
  | _ ->
    Error "Invalid parameters: expected [base64string, (extract)]"

(* utxoupdatepsbt "base64string"
   Update PSBT inputs with UTXO information from the UTXO set *)
let handle_utxoupdatepsbt (ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  match params with
  | [`String b64] ->
    (match Psbt.of_base64 b64 with
     | Error e -> Error (Psbt.string_of_error e)
     | Ok psbt ->
       (* Create UTXO set accessor *)
       let utxo_set = Utxo.UtxoSet.create ctx.chain.db in
       (* Update each input with UTXO from chain if available *)
       let updated = List.fold_left (fun psbt (i, inp) ->
         if inp.Psbt.witness_utxo <> None || inp.Psbt.non_witness_utxo <> None then
           psbt (* Already has UTXO info *)
         else
           let tx_in = List.nth psbt.Psbt.tx.inputs i in
           let txid = tx_in.previous_output.txid in
           let vout = Int32.to_int tx_in.previous_output.vout in
           match Utxo.UtxoSet.get utxo_set txid vout with
           | None -> psbt
           | Some entry ->
             let utxo : Types.tx_out = {
               value = entry.Utxo.value;
               script_pubkey = entry.Utxo.script_pubkey;
             } in
             Psbt.add_witness_utxo psbt i utxo
       ) psbt (List.mapi (fun i inp -> (i, inp)) psbt.inputs) in
       Ok (`String (Psbt.to_base64 updated)))
  | _ ->
    Error "Invalid parameters: expected [base64string]"

(* converttopsbt "hexstring" ( permitsigdata )
   Convert a raw transaction to a PSBT *)
let handle_converttopsbt (_ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  match params with
  | [`String hex] | [`String hex; _] ->
    let permitsigdata = match params with
      | [_; `Bool b] -> b
      | _ -> false
    in
    (try
      let data = Cstruct.of_hex hex in
      let r = Serialize.reader_of_cstruct data in
      let tx = Serialize.deserialize_transaction r in
      (* Check if there are signatures *)
      let has_sigs = List.exists (fun inp ->
        Cstruct.length inp.Types.script_sig > 0
      ) tx.inputs || tx.witnesses <> [] in
      if has_sigs && not permitsigdata then
        Error "Transaction has signature data. Set permitsigdata=true to strip them."
      else
        let psbt = Psbt.create tx in
        Ok (`String (Psbt.to_base64 psbt))
    with exn ->
      Error (Printf.sprintf "TX decode failed: %s" (Printexc.to_string exn)))
  | _ ->
    Error "Invalid parameters: expected [hexstring, (permitsigdata)]"

(* ============================================================================
   walletcreatefundedpsbt Handler
   (Bitcoin Core: src/wallet/rpc/spend.cpp::walletcreatefundedpsbt)
   Creates and funds a PSBT.  Implements the Creator + Updater roles:
   - parse user inputs/outputs into a base transaction skeleton
   - if no manual inputs, run wallet coin selection to fund the target
   - emit a PSBT with witness_utxo populated for each wallet input
   - return {psbt, fee, changepos}
   ============================================================================ *)

let handle_walletcreatefundedpsbt (ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  match ctx.wallet with
  | None -> Error "Wallet not loaded"
  | Some wallet ->
    let inputs_param, outputs_param, locktime_param, options_param =
      match params with
      | [a; b] -> (a, b, `Int 0, `Assoc [])
      | [a; b; c] -> (a, b, c, `Assoc [])
      | [a; b; c; d] -> (a, b, c, d)
      | a :: b :: c :: d :: _ -> (a, b, c, d)
      | _ ->
        (`List [], `List [], `Int 0, `Assoc [])
    in
    if List.length params < 2 then
      Error "Invalid parameters: expected [inputs, outputs, (locktime, options, bip32derivs, version)]"
    else
    (try
      let network = network_to_address_network ctx.network in
      (* --- Manual inputs (may be empty) --- *)
      let manual_inputs = match inputs_param with
        | `List arr ->
          List.map (fun obj ->
            match obj with
            | `Assoc fields ->
              let txid = match List.assoc_opt "txid" fields with
                | Some (`String s) ->
                  let display = Types.hash256_of_hex s in
                  let h = Cstruct.create 32 in
                  for i = 0 to 31 do
                    Cstruct.set_uint8 h i (Cstruct.get_uint8 display (31 - i))
                  done;
                  h
                | _ -> failwith "Missing input txid"
              in
              let vout = match List.assoc_opt "vout" fields with
                | Some (`Int n) -> Int32.of_int n
                | _ -> failwith "Missing input vout"
              in
              let sequence = match List.assoc_opt "sequence" fields with
                | Some (`Int n) -> Int32.of_int n
                | _ -> 0xFFFFFFFEl
              in
              { Types.previous_output = { txid; vout };
                script_sig = Cstruct.empty;
                sequence }
            | _ -> failwith "Each input must be an object"
          ) arr
        | `Null -> []
        | _ -> failwith "inputs must be an array"
      in
      (* --- Outputs (Core accepts both [{addr:amt},...] and {addr:amt}) --- *)
      let parse_amount = function
        | `Float f -> Int64.of_float (f *. 100_000_000.0)
        | `Int i -> Int64.of_int (i * 100_000_000)
        | `String s -> Int64.of_float (float_of_string s *. 100_000_000.0)
        | _ -> 0L
      in
      let parse_one_output_field (addr_str, amt) =
        if addr_str = "data" then
          match amt with
          | `String hex_data ->
            let data = hex_to_cstruct hex_data in
            let script = Cstruct.create (2 + Cstruct.length data) in
            Cstruct.set_uint8 script 0 0x6a;
            Cstruct.set_uint8 script 1 (Cstruct.length data);
            Cstruct.blit data 0 script 2 (Cstruct.length data);
            Some { Types.value = 0L; script_pubkey = script }
          | _ -> None
        else
          match Address.address_of_string addr_str with
          | Error _ -> failwith (Printf.sprintf "Invalid address: %s" addr_str)
          | Ok addr ->
            if addr.network <> network then
              failwith (Printf.sprintf "Address not on this network: %s" addr_str)
            else
              let script_pubkey = Address.address_to_script addr in
              Some { Types.value = parse_amount amt; script_pubkey }
      in
      let outputs = match outputs_param with
        | `List arr ->
          List.concat_map (function
            | `Assoc fields -> List.filter_map parse_one_output_field fields
            | _ -> failwith "Each output entry must be an object"
          ) arr
        | `Assoc fields ->
          List.filter_map parse_one_output_field fields
        | _ -> failwith "outputs must be an array or object"
      in
      if outputs = [] then
        Error "Cannot create PSBT with no outputs"
      else
      let locktime = match locktime_param with
        | `Int n -> Int32.of_int n
        | `Null -> 0l
        | _ -> 0l
      in
      (* --- Options --- *)
      let opt_field name = match options_param with
        | `Assoc fields -> List.assoc_opt name fields
        | _ -> None
      in
      let add_inputs_default = (manual_inputs = []) in
      let add_inputs = match opt_field "add_inputs" with
        | Some (`Bool b) -> b
        | _ -> add_inputs_default
      in
      (* Fee-rate selection mirrors Core's options parser
         (src/wallet/rpc/spend.cpp::SetFeeEstimateMode):
           - fee_rate: sat/vB (most callers)
           - feeRate:  BTC/kvB legacy alias.  BTC/kvB → sat/vB == f * 1e5
         If both are set, fee_rate wins (Core errors out, we follow the
         simpler "explicit > legacy" rule). *)
      let fee_rate = match opt_field "fee_rate" with
        | Some (`Float f) -> f
        | Some (`Int n) -> float_of_int n
        | _ ->
          (match opt_field "feeRate" with
           | Some (`Float f) -> f *. 100_000.0
           | Some (`Int n) -> float_of_int n *. 100_000.0
           | _ -> 1.0)
      in
      let lock_unspents = match opt_field "lockUnspents" with
        | Some (`Bool b) -> b
        | _ -> false
      in
      let change_address_opt = match opt_field "changeAddress" with
        | Some (`String s) -> Some s
        | _ -> None
      in
      let change_position = match opt_field "changePosition" with
        | Some (`Int n) -> Some n
        | _ -> None
      in
      (* --- Build inputs + change --- *)
      let target_amount = List.fold_left (fun acc o ->
        Int64.add acc o.Types.value
      ) 0L outputs in
      let (final_inputs, selected_wutxos, change_amount) =
        if manual_inputs <> [] && not add_inputs then
          (* All inputs supplied manually; no auto-funding.  We still need to
             know the wallet UTXO behind each input (if any) to populate
             witness_utxo and to determine change.  Compute totals. *)
          let wallet_utxos = Wallet.get_utxos wallet in
          let resolved = List.filter_map (fun (inp : Types.tx_in) ->
            List.find_opt (fun (wu : Wallet.wallet_utxo) ->
              Cstruct.equal wu.outpoint.txid inp.previous_output.txid &&
              wu.outpoint.vout = inp.previous_output.vout
            ) wallet_utxos
          ) manual_inputs in
          let total_input = List.fold_left (fun acc (wu : Wallet.wallet_utxo) ->
            Int64.add acc wu.utxo.Utxo.value
          ) 0L resolved in
          let n_inputs = List.length manual_inputs in
          let n_outputs = List.length outputs + 1 in
          let wt = Wallet.estimate_tx_weight n_inputs n_outputs in
          let est_fee = Int64.of_float
            (fee_rate *. float_of_int wt /. 4.0) in
          let change = Int64.sub total_input
            (Int64.add target_amount est_fee) in
          (manual_inputs, resolved, change)
        else
          match Wallet.select_coins wallet target_amount fee_rate with
          | Error e -> failwith e
          | Ok sel ->
            let auto_inputs = List.map (fun (wu : Wallet.wallet_utxo) ->
              { Types.previous_output = wu.outpoint;
                script_sig = Cstruct.empty;
                sequence = 0xFFFFFFFEl }
            ) sel.selected in
            (manual_inputs @ auto_inputs,
             sel.selected,
             sel.change)
      in
      (* Assemble outputs with optional change.  Change position is
         determined by the user's request, else random (Core: random by
         default).  changepos = -1 means no change output. *)
      let dust = 546L in
      let (final_outputs, changepos) =
        if Int64.compare change_amount dust > 0 then
          let change_script = match change_address_opt with
            | Some addr_str ->
              (match Address.address_of_string addr_str with
               | Ok a when a.Address.network = network ->
                 Address.address_to_script a
               | _ -> failwith (Printf.sprintf "Invalid changeAddress: %s" addr_str))
            | None ->
              let kp = Wallet.generate_change_key wallet in
              let dest_script = match outputs with
                | first :: _ -> first.Types.script_pubkey
                | [] -> Cstruct.empty
              in
              Wallet.build_change_script dest_script kp.Wallet.public_key
          in
          let change_out = { Types.value = change_amount;
                             script_pubkey = change_script } in
          let pos = match change_position with
            | Some p when p >= 0 && p <= List.length outputs -> p
            | Some _ -> List.length outputs  (* clamp to end *)
            | None ->
              (* Random insert position so observers cannot trivially tell
                 the change output apart.  Matches Core's randomization. *)
              Random.int (List.length outputs + 1)
          in
          let rec insert_at i acc = function
            | rest when i = 0 -> List.rev_append acc (change_out :: rest)
            | x :: rest -> insert_at (i - 1) (x :: acc) rest
            | [] -> List.rev (change_out :: acc)
          in
          (insert_at pos [] outputs, pos)
        else
          (outputs, -1)
      in
      let tx : Types.transaction = {
        version = 2l;
        inputs = final_inputs;
        outputs = final_outputs;
        witnesses = [];
        locktime;
      } in
      (* Build PSBT, attach witness_utxo for every wallet-known input. *)
      let psbt = Psbt.create tx in
      let psbt =
        List.fold_left (fun (acc : Psbt.psbt) (i, inp) ->
          let prev = inp.Types.previous_output in
          match List.find_opt (fun (wu : Wallet.wallet_utxo) ->
            Cstruct.equal wu.outpoint.txid prev.txid &&
            wu.outpoint.vout = prev.vout
          ) selected_wutxos with
          | Some wu ->
            let utxo_out = { Types.value = wu.utxo.Utxo.value;
                             script_pubkey = wu.utxo.Utxo.script_pubkey } in
            Psbt.add_witness_utxo acc i utxo_out
          | None -> acc
        ) psbt
        (List.mapi (fun i inp -> (i, inp)) final_inputs)
      in
      (* lockUnspents=true: lock every selected wallet utxo (Core does this
         atomically after the PSBT is built — see spend.cpp ::FundTransaction). *)
      if lock_unspents then
        List.iter (fun (wu : Wallet.wallet_utxo) ->
          let _ = Wallet.lock_coin wallet wu.outpoint ~persistent:false in ()
        ) selected_wutxos;
      let total_input = List.fold_left (fun acc (wu : Wallet.wallet_utxo) ->
        Int64.add acc wu.utxo.Utxo.value
      ) 0L selected_wutxos in
      let total_output = List.fold_left (fun acc o ->
        Int64.add acc o.Types.value
      ) 0L final_outputs in
      let fee = Int64.sub total_input total_output in
      let fee = if Int64.compare fee 0L < 0 then 0L else fee in
      Ok (`Assoc [
        ("psbt", `String (Psbt.to_base64 psbt));
        ("fee", `Float (Int64.to_float fee /. 100_000_000.0));
        ("changepos", `Int changepos);
      ])
    with
    | Failure msg -> Error msg
    | exn -> Error (Printexc.to_string exn))

(* ============================================================================
   Output Descriptor Handlers (BIP 380-386)
   ============================================================================ *)

(* getdescriptorinfo "descriptor"
   Analyzes a descriptor string and returns information about it *)
let handle_getdescriptorinfo (_ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  match params with
  | [`String desc_str] ->
    (match Descriptor.get_info desc_str with
     | Ok info ->
       Ok (`Assoc [
         ("descriptor", `String info.Descriptor.descriptor);
         ("checksum", `String (
           (* Extract just the checksum from "desc#checksum" *)
           match String.rindex_opt info.Descriptor.descriptor '#' with
           | Some pos ->
             String.sub info.descriptor (pos + 1)
               (String.length info.descriptor - pos - 1)
           | None -> ""
         ));
         ("isrange", `Bool info.is_range);
         ("issolvable", `Bool info.is_solvable);
         ("hasprivatekeys", `Bool info.has_private_keys);
       ])
     | Error e -> Error e)
  | _ ->
    Error "Invalid parameters: expected [descriptor]"

(* deriveaddresses "descriptor" ( range )
   Derives addresses from a descriptor for a given range *)
let handle_deriveaddresses (ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  let network = match ctx.network.name with
    | "mainnet" -> `Mainnet
    | "testnet" -> `Testnet
    | _ -> `Regtest
  in
  match params with
  | [`String desc_str] ->
    (* No range specified - derive single address at index 0 *)
    (match Descriptor.parse desc_str with
     | Error e -> Error e
     | Ok parsed ->
       if Descriptor.is_ranged parsed.desc then
         Error "Descriptor is ranged; please specify a range"
       else
         match Descriptor.derive_addresses parsed.desc (0, 0) network with
         | Error e -> Error e
         | Ok addrs -> Ok (`List (List.map (fun a -> `String a) addrs)))
  | [`String desc_str; `List [`Int start_idx; `Int end_idx]] ->
    (* Range specified as [start, end] *)
    (match Descriptor.parse desc_str with
     | Error e -> Error e
     | Ok parsed ->
       match Descriptor.derive_addresses parsed.desc (start_idx, end_idx) network with
       | Error e -> Error e
       | Ok addrs -> Ok (`List (List.map (fun a -> `String a) addrs)))
  | [`String desc_str; `Int single_idx] ->
    (* Single index *)
    (match Descriptor.parse desc_str with
     | Error e -> Error e
     | Ok parsed ->
       match Descriptor.derive_addresses parsed.desc (single_idx, single_idx) network with
       | Error e -> Error e
       | Ok addrs -> Ok (`List (List.map (fun a -> `String a) addrs)))
  | _ ->
    Error "Invalid parameters: expected [descriptor, (range)]"

(* listdescriptors ( private )
   Lists all descriptors imported into the wallet.
   Currently, this returns implicit descriptors based on the wallet's HD keys. *)
let handle_listdescriptors (ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  let include_private = match params with
    | [`Bool true] -> true
    | _ -> false
  in
  match ctx.wallet with
  | None -> Error "Wallet not loaded"
  | Some wallet ->
    (* Generate implicit descriptors from wallet's master key *)
    let descriptors = match wallet.Wallet.master_key with
      | None -> []
      | Some master_key ->
        (* Serialize the master key as xpub/xprv *)
        let key_str = if include_private then
          Wallet.serialize_xprv master_key
        else
          Wallet.serialize_xpub master_key
        in
        (* Generate standard BIP-84/86 descriptors *)
        let wpkh_recv = Printf.sprintf "wpkh(%s/84'/0'/0'/0/*)" key_str in
        let wpkh_change = Printf.sprintf "wpkh(%s/84'/0'/0'/1/*)" key_str in
        let tr_recv = Printf.sprintf "tr(%s/86'/0'/0'/0/*)" key_str in
        let tr_change = Printf.sprintf "tr(%s/86'/0'/0'/1/*)" key_str in
        let make_desc d internal =
          let desc_with_checksum = match Descriptor.add_checksum d with
            | Some s -> s
            | None -> d
          in
          `Assoc [
            ("desc", `String desc_with_checksum);
            ("timestamp", `Int 0);
            ("active", `Bool true);
            ("internal", `Bool internal);
            ("range", `List [`Int 0; `Int 999]);
            ("next", `Int 0);
          ]
        in
        [
          make_desc wpkh_recv false;
          make_desc wpkh_change true;
          make_desc tr_recv false;
          make_desc tr_change true;
        ]
    in
    Ok (`Assoc [
      ("wallet_name", `String (match ctx.wallet_manager with
        | Some wm -> (match Wallet.list_wallets wm with
          | name :: _ -> name
          | [] -> "")
        | None -> ""));
      ("descriptors", `List descriptors);
    ])

(* ============================================================================
   Performance Stats Handlers
   ============================================================================ *)

let handle_getperfstats (_ctx : rpc_context) : Yojson.Safe.t =
  let report = Perf.Timer.report () in
  `Assoc [
    ("timers", Perf.Timer.to_json ());
    ("timer_report", `String report);
  ]

(* ============================================================================
   Ban Management Handlers
   ============================================================================ *)

(* listbanned - Return list of currently banned addresses *)
let handle_listbanned (ctx : rpc_context) : Yojson.Safe.t =
  let now = Unix.gettimeofday () in
  let bans = Peer_manager.get_banned_list ctx.peer_manager in
  `List (List.filter_map (fun (addr, ban_until) ->
    if ban_until > now then
      Some (`Assoc [
        ("address", `String addr);
        ("banned_until", `Int (int_of_float ban_until));
        ("ban_created", `Int (int_of_float (ban_until -. 86400.0)));
        ("ban_reason", `String "misbehavior");
      ])
    else
      None
  ) bans)

(* setban - Add or remove an address from the ban list *)
let handle_setban (ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  match params with
  | [`String addr; `String "add"] ->
    Peer_manager.ban_addr ctx.peer_manager addr ~duration:86400.0 ();
    Ok `Null
  | [`String addr; `String "add"; `Int duration] ->
    Peer_manager.ban_addr ctx.peer_manager addr ~duration:(float_of_int duration) ();
    Ok `Null
  | [`String addr; `String "remove"] ->
    Peer_manager.unban_addr ctx.peer_manager addr;
    Ok `Null
  | _ ->
    Error "Invalid parameters: expected [address, \"add\"|\"remove\", (bantime)]"

(* clearbanned - Clear all banned addresses *)
let handle_clearbanned (ctx : rpc_context) : Yojson.Safe.t =
  Peer_manager.clear_bans ctx.peer_manager;
  `Null

(* disconnectnode - Disconnect from a peer *)
let handle_disconnectnode (ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  match params with
  | [`String addr] ->
    (match Peer_manager.find_peer_by_addr ctx.peer_manager addr with
     | Some peer ->
       Lwt.async (fun () -> Peer_manager.remove_peer ctx.peer_manager peer.Peer.id);
       Ok `Null
     | None -> Error ("Peer not found: " ^ addr))
  | [`Int id] ->
    (match Peer_manager.find_peer_by_id ctx.peer_manager id with
     | Some _ ->
       Lwt.async (fun () -> Peer_manager.remove_peer ctx.peer_manager id);
       Ok `Null
     | None -> Error ("Peer not found with id: " ^ string_of_int id))
  | _ ->
    Error "Invalid parameters: expected [address] or [node_id]"

(* addnode - Manually connect to or disconnect from a peer *)
let handle_addnode (ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  match params with
  | [`String node; `String command] ->
    (* Parse host:port *)
    let (host, port) =
      match String.rindex_opt node ':' with
      | Some idx ->
        let h = String.sub node 0 idx in
        let p_str = String.sub node (idx + 1) (String.length node - idx - 1) in
        (match int_of_string_opt p_str with
         | Some p -> (h, p)
         | None -> (node, ctx.network.Consensus.default_port))
      | None -> (node, ctx.network.Consensus.default_port)
    in
    (match command with
     | "onetry" | "add" ->
       Lwt.async (fun () -> Peer_manager.force_add_peer ctx.peer_manager host port);
       Ok `Null
     | "remove" ->
       (match Peer_manager.find_peer_by_addr ctx.peer_manager host with
        | Some peer ->
          Lwt.async (fun () -> Peer_manager.remove_peer ctx.peer_manager peer.Peer.id);
          Ok `Null
        | None -> Ok `Null)
     | _ -> Error ("Invalid command: " ^ command ^
                   ". Expected \"onetry\", \"add\", or \"remove\""))
  | _ ->
    Error "Invalid parameters: expected [\"node\", \"command\"]"

(* ============================================================================
   AssumeUTXO Handlers (loadtxoutset / dumptxoutset)
   ============================================================================ *)

(* loadtxoutset and dumptxoutset both speak Bitcoin Core's [dumptxoutset]
   wire format (magic 'utxo\xff', version 2, per-txid grouped coins with
   ScriptCompression-encoded scriptPubKeys). The bespoke "HDOG" format is
   retired (2026-04-29) — see lib/compressor.ml + lib/assume_utxo.ml. *)

let handle_loadtxoutset (_ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  match params with
  | [`String path] ->
    (match Assume_utxo.read_snapshot_metadata path
             ~expected_network_magic:_ctx.network.magic with
    | Error e -> Error e
    | Ok metadata ->
      (* Core-strict whitelist check: refuse any snapshot whose
         base_blockhash height isn't in [m_assumeutxo_data].
         Mirrors [bitcoin-core/src/validation.cpp:5775-5780]:

           if (!maybe_au_data) {
               return util::Error{Untranslated(strprintf(
                   "Assumeutxo height in snapshot metadata not recognized "
                   "(%d) - refusing to load snapshot", base_height))};
           }

         Camlcoin already short-circuits via [get_assumeutxo_for_hash]
         (hash-keyed lookup against [mainnet_au_data]); reuse that, and
         when the lookup fails attempt to resolve the height from the
         header index for the error message. Falls back to -1 (matching
         Core's behaviour for an unknown blockhash). *)
      (match Assume_utxo.get_assumeutxo_for_hash ~network:_ctx.network
               metadata.base_blockhash with
      | None ->
        let base_height =
          match Sync.get_header _ctx.chain metadata.base_blockhash with
          | Some hdr -> hdr.height
          | None -> -1
        in
        Error (Printf.sprintf
                 "Assumeutxo height in snapshot metadata not recognized \
                  (%d) - refusing to load snapshot"
                 base_height)
      | Some params ->
        if Int64.compare params.coins_count 0L <> 0
           && metadata.coins_count <> params.coins_count then
          Error (Printf.sprintf
                   "Coins count mismatch: snapshot has %Ld, expected %Ld"
                   metadata.coins_count params.coins_count)
        else begin
          (* Stream the coins into a fresh snapshot chainstate sibling
             directory of the active datadir. The active chainstate is
             unaffected — this matches Core's "second chainstate" model. *)
          let snapshot_db_path =
            match _ctx.data_dir with
            | Some d -> Filename.concat d "chainstate_snapshot"
            | None ->
              (* No datadir provided in test contexts: pick a sibling of
                 the snapshot file so we still have a unique location. *)
              (Filename.dirname path) ^ "/chainstate_snapshot"
          in
          (match Assume_utxo.load_snapshot
                   ~network:_ctx.network
                   ~snapshot_path:path
                   ~snapshot_db_path
                   () with
          | Error msg -> Error msg
          | Ok cs ->
            (* Strict snapshot content-hash check.

               Mirrors Bitcoin Core's [ActivateSnapshot] step in
               [src/validation.cpp:5902-5915]: after the coins have
               been loaded into the new chainstate, recompute the
               canonical UTXO commitment over the loaded set and
               reject the snapshot if it disagrees with the
               chainparams-pinned value.

               Core uses [CoinStatsHashType::HASH_SERIALIZED] here
               (see [src/kernel/coinstats.cpp:161-163]) — i.e. SHA256d
               of the streamed [(outpoint, coin)] preimages via
               [HashWriter] ([src/hash.h:HashWriter::GetHash] is the
               canonical SHA256d). The chainparams field is named
               [hash_serialized] for exactly this reason: it pins a
               SHA256d commitment, NOT the MuHash3072 value. (MuHash
               is used only on the [gettxoutsetinfo "muhash"] surface,
               see [handle_gettxoutsetinfo] below.)

               We compute the same SHA256d via
               [verify_loaded_utxo_hash], which calls
               [compute_utxo_hash_from_db] (HASH_SERIALIZED-equivalent
               streaming SHA256d). The error string is Core's verbatim
               wording from [validation.cpp:5913] so external tooling
               that scrapes the message keeps working.

               Both [params.coins_hash] (stored LE per [make_au]) and
               our [Crypto.sha256d] output are 32 raw bytes in the
               same byte order — Core's [uint256] hex constructor
               reverses on parse and the digest is raw — so a direct
               [Cstruct.equal] is the right check. For the error
               message we render both via [hash256_to_hex_display] so
               the operator sees the same hex Core would print. *)
            (match Assume_utxo.verify_loaded_utxo_hash
                     ~db:cs.db ~expected:params.coins_hash with
            | Error msg -> Error msg
            | Ok actual_hash ->
              Ok (`Assoc [
                ("coins_loaded", `Int (Int64.to_int metadata.coins_count));
                ("base_hash",
                   `String (Types.hash256_to_hex_display
                              metadata.base_blockhash));
                ("base_height", `Int params.height);
                ("path", `String path);
                ("tip_hash",
                   `String (Types.hash256_to_hex_display cs.tip_hash));
                ("tip_height", `Int cs.tip_height);
                ("txoutset_hash",
                   `String (Types.hash256_to_hex_display actual_hash));
              ]))
          )
        end))
  | _ ->
    Error "Invalid parameters: expected [path]"

(* Resolve the rollback target for a [dumptxoutset] call.

   Mirrors Bitcoin Core's [src/rpc/blockchain.cpp:3074-3130] selector
   logic. Three modes:
     - ["latest"]         → current chain tip
     - ["rollback"]       → highest [m_assumeutxo_data] entry ≤ current tip
     - [{"rollback": v}]  → resolve [v] as a height (int) or block hash (str)

   Returns the resolved target [header_entry], or [Ok None] for the
   trivial "dump current tip" case (caller skips the rollback dance).
   We deliberately reject targets that aren't on the active chain — the
   rollback path needs a clean ancestor of [tip] so [Sync.disconnect_to_target]
   can rewind through stored undo data. *)
let parse_dumptxoutset_target (ctx : rpc_context)
    (snapshot_type : string) (options : Yojson.Safe.t)
  : (Sync.header_entry option, string) result =
  let lookup_at_height (h : int) : (Sync.header_entry, string) result =
    let tip_height = match ctx.chain.tip with
      | Some t -> t.height
      | None -> -1
    in
    if h < 0 then
      Error (Printf.sprintf "Target block height %d is negative" h)
    else if h > tip_height then
      Error (Printf.sprintf
               "Target block height %d after current tip %d" h tip_height)
    else
      match Sync.get_header_at_height ctx.chain h with
      | Some e -> Ok e
      | None -> Error (Printf.sprintf
                         "Target block at height %d not found" h)
  in
  let lookup_at_hash (hex : string) : (Sync.header_entry, string) result =
    match parse_blockhash_hex hex with
    | Error msg -> Error msg
    | Ok hash ->
      (match Sync.get_header ctx.chain hash with
       | None -> Error "Block not found"
       | Some entry -> Ok entry)
  in
  (* Pull rollback option (named param) if provided. *)
  let rollback_opt =
    match options with
    | `Assoc fields -> List.assoc_opt "rollback" fields
    | `Null -> None
    | _ -> None
  in
  let snapshot_type_norm = String.lowercase_ascii snapshot_type in
  match rollback_opt with
  | Some v ->
    if snapshot_type_norm <> "" && snapshot_type_norm <> "rollback" then
      Error (Printf.sprintf
               "Invalid snapshot type \"%s\" specified with rollback option"
               snapshot_type)
    else begin
      match v with
      | `Int h -> Result.map (fun e -> Some e) (lookup_at_height h)
      | `Intlit s ->
        (try
           let h = int_of_string s in
           Result.map (fun e -> Some e) (lookup_at_height h)
         with _ -> Error "rollback: not a valid integer")
      | `String s ->
        (* Could be a block hash OR a stringified height (Core accepts
           both via its [skip_type_check] flag). Try int parse first,
           fall through to hash. *)
        (match int_of_string_opt s with
         | Some h -> Result.map (fun e -> Some e) (lookup_at_height h)
         | None -> Result.map (fun e -> Some e) (lookup_at_hash s))
      | `Null -> Error "rollback: missing value"
      | _ -> Error "rollback: expected integer or block hash"
    end
  | None ->
    (match snapshot_type_norm with
     | "" | "latest" -> Ok None
     | "rollback" ->
       (* No explicit target: pick the highest hardcoded assumeutxo
          entry that is ≤ current tip. Mirrors Core's
          [GetAvailableSnapshotHeights] loop in blockchain.cpp:3122-3125. *)
       let tip_height = match ctx.chain.tip with
         | Some t -> t.height
         | None -> -1
       in
       let heights = Assume_utxo.available_snapshot_heights ctx.network in
       let candidates = List.filter (fun h -> h <= tip_height) heights in
       (match candidates with
        | [] ->
          Error "No assumeutxo snapshot heights available at or below \
                 current tip"
        | _ ->
          let max_h = List.fold_left max min_int candidates in
          Result.map (fun e -> Some e) (lookup_at_height max_h))
     | other ->
       Error (Printf.sprintf
                "Invalid snapshot type \"%s\" specified. Please specify \
                 \"rollback\" or \"latest\"" other))

let handle_dumptxoutset (_ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  (* Parse [path, type?, options?]. The [type] field accepts Core's
     three modes ("latest", "rollback", or "" + named-rollback option),
     and we keep the legacy single-arg ["path"] form working as
     "latest". *)
  let path_and_modes : (string * string * Yojson.Safe.t, string) result =
    match params with
    | [`String path] -> Ok (path, "", `Null)
    | [`String path; `String t] -> Ok (path, t, `Null)
    | [`String path; `Null] -> Ok (path, "", `Null)
    | [`String path; `String t; opts] -> Ok (path, t, opts)
    | [`String path; `Null; opts] -> Ok (path, "", opts)
    | _ ->
      Error "Invalid parameters: expected [path, type?, options?]"
  in
  match path_and_modes with
  | Error e -> Error e
  | Ok (path, snapshot_type, options) ->
    (* Refuse to overwrite an existing destination — matches Core's
       "<path> already exists. If you are sure this is what you want,
       move it out of the way first." guard in
       [rpc/blockchain.cpp::dumptxoutset]. We probe with [Sys.file_exists]
       BEFORE any chain-state mutation so a name collision does not
       leave the chain in a half-rolled-back state. *)
    if Sys.file_exists path then
      Error (Printf.sprintf
               "%s already exists. If you are sure this is what you want, \
                move it out of the way first." path)
    else
    match parse_dumptxoutset_target _ctx snapshot_type options with
    | Error e -> Error e
    | Ok target_opt ->
      let original_tip = _ctx.chain.tip in
      (* Pruned-mode pre-check (Bitcoin Core
         [rpc/blockchain.cpp:dumptxoutset]):
             if (IsPruneMode() &&
                 target_index->nHeight <
                 m_blockman.GetFirstBlock()->nHeight)
                 throw "Block height N not available (pruned data).
                        Use a height after M.";
         Camlcoin tracks the prune horizon via [chain.prune_height]
         (see [handle_getblockchaininfo]), populated by the storage prune
         sweep. We fail fast so a pruned datadir does not begin a
         disconnect that is guaranteed to fail when undo data is missing. *)
      let prune_check : (unit, string) result =
        match target_opt with
        | Some target
          when _ctx.chain.prune_target > 0
            && target.height < _ctx.chain.prune_height ->
          Error (Printf.sprintf
                   "Block height %d not available (pruned data). \
                    Use a height after %d."
                   target.height (_ctx.chain.prune_height - 1))
        | _ -> Ok ()
      in
      match prune_check with
      | Error msg -> Error msg
      | Ok () ->
      (* NetworkDisable RAII (Bitcoin Core
         [src/rpc/blockchain.cpp::NetworkDisable] around
         [TemporaryRollback]). Pause inbound block acceptance for the
         duration of the rewind→dump→replay dance and restore on every
         exit path. We only activate when there's actual rewind work
         (a "latest" dump doesn't need the gate). Restoration is wrapped
         in [finally_restore_pause] so a partway-through error does not
         strand the flag set. *)
      let pause_active =
        match target_opt, original_tip with
        | Some target, Some tip when not (Cstruct.equal target.hash tip.hash) ->
          true
        | _ -> false
      in
      if pause_active then
        _ctx.chain.block_submission_paused <- true;
      let finally_restore_pause () =
        if pause_active then
          _ctx.chain.block_submission_paused <- false
      in
      (* Optionally rewind to the rollback target before dumping. We
         restore the chain afterwards in [finally_restore]. *)
      let saved_tip_for_restore : Sync.header_entry option ref = ref None in
      let rollback_step : (unit, string) result =
        match target_opt, original_tip with
        | Some target, Some tip when not (Cstruct.equal target.hash tip.hash) ->
          (match Sync.disconnect_to_target _ctx.chain target with
           | Ok () ->
             saved_tip_for_restore := Some tip;
             Ok ()
           | Error e ->
             finally_restore_pause ();
             Error e)
        | _ -> Ok ()
      in
      match rollback_step with
      | Error msg ->
        finally_restore_pause ();
        Error (Printf.sprintf "rollback failed: %s" msg)
      | Ok () ->
        (* Resolve the base block (post-rollback tip) used in metadata. *)
        let base_height, base_hash =
          match _ctx.chain.tip with
          | Some t -> (t.height, t.hash)
          | None -> (0, Types.zero_hash)
        in
        let finally_restore () =
          (* Re-apply the original tip if we rewound. We use [reorganize]
             with a freshly-constructed [ibd_state] — that's the same
             primitive [Sync.run_ibd] uses to advance tip and it's the
             cleanest way to drive UTXO reapplication + undo-data
             rebuild via the existing connect path. *)
          match !saved_tip_for_restore with
          | None -> Ok ()
          | Some saved_tip ->
            let ibd = Sync.create_ibd_state _ctx.chain in
            Sync.reorganize ibd saved_tip
        in
        (* Count total coins post-rollback. Single iterator pass. *)
        let total_coins = ref 0L in
        Storage.ChainDB.iter_utxos _ctx.chain.db (fun _txid _vout _data ->
          total_coins := Int64.add !total_coins 1L
        );
        let metadata : Assume_utxo.snapshot_metadata = {
          network_magic = _ctx.network.magic;
          base_blockhash = base_hash;
          coins_count = !total_coins;
        } in
        let coins_written = ref 0L in
        let res = Assume_utxo.write_snapshot path metadata
          ~iter_coins:(fun emit ->
            Storage.ChainDB.iter_utxos _ctx.chain.db (fun txid vout data ->
              let r = Serialize.reader_of_cstruct (Cstruct.of_string data) in
              let utxo = Utxo.deserialize_utxo_entry r in
              let coin : Assume_utxo.snapshot_coin = {
                outpoint = { Types.txid; vout = Int32.of_int vout };
                value = utxo.value;
                script_pubkey = utxo.script_pubkey;
                height = utxo.height;
                is_coinbase = utxo.is_coinbase;
              } in
              emit coin;
              coins_written := Int64.add !coins_written 1L))
        in
        (* Always attempt to restore the chain, even if the dump failed,
           so we never leave the node sitting on a rolled-back tip. *)
        let restore_res = finally_restore () in
        (* Restore the NetworkDisable flag now that the rewind+dump+replay
           dance is complete (success or failure). Done BEFORE returning so
           subsequent submitblock requests in the same process don't see a
           stale pause. *)
        finally_restore_pause ();
        (match res, restore_res with
        | Error msg, _ -> Error msg
        | Ok (), Error rmsg ->
          (* Dump succeeded but restore failed — this is a state-inconsistent
             outcome the operator must know about. *)
          Error (Printf.sprintf
                   "dumptxoutset: dump completed but post-dump rollback \
                    restore failed: %s. The chain is currently at the \
                    rollback height; restart the node to recover." rmsg)
        | Ok (), Ok () ->
          (* Compute the MuHash3072 commitment over the dumped UTXO set so the
             operator can record it alongside the snapshot. Matches Bitcoin
             Core's [dumptxoutset] response field [txoutset_hash], which is the
             MuHash3072 path of [CoinStatsHashType] in [kernel/coinstats.cpp].
             We iterate the chain DB rather than the dump file so we never have
             to re-deserialize the on-disk snapshot format here.

             NOTE: after a successful rollback+dump+restore round-trip the
             DB is at [original_tip], so this hash now reflects the live UTXO
             set, not the dumped (historical) one. The dump file itself was
             written from the historical state during the rolled-back window,
             so [base_hash]/[base_height] in the response are still correct.
             For a Core-faithful [txoutset_hash] of the dumped set we'd need
             to compute the MuHash inside the iter_coins callback above —
             TODO(W47-followup): wire that through Assume_utxo.write_snapshot. *)
          let txoutset_hash =
            Assume_utxo.compute_utxo_muhash_from_db _ctx.chain.db
          in
          Ok (`Assoc [
            ("coins_written", `Int (Int64.to_int !coins_written));
            ("base_hash", `String (Types.hash256_to_hex_display base_hash));
            ("base_height", `Int base_height);
            ("path", `String path);
            ("txoutset_hash",
               `String (Types.hash256_to_hex_display txoutset_hash));
          ]))

(* ============================================================================
   gettxoutsetinfo Handler
   ============================================================================

   Mirrors Bitcoin Core's RPC of the same name (see
   [src/rpc/blockchain.cpp:gettxoutsetinfo]). We expose the same shape:
   [height], [bestblock], [transactions], [txouts], [bogosize], [total_amount],
   [hash_serialized_3] and/or [muhash] (depending on the [hash_type]
   argument), and [disk_size]. Only the [hash_type] parameter is consulted —
   we accept "none", "hash_serialized_3", and "muhash". An optional second
   argument ([blockhash]) is rejected with the same error Core returns
   ("Querying specific block heights is not supported") because we do not
   maintain a coinstats index. *)

let handle_gettxoutsetinfo (ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  let hash_type, extra_args =
    match params with
    | [] -> ("hash_serialized_3", [])
    | [`Null] -> ("hash_serialized_3", [])
    | (`String s) :: rest -> (s, rest)
    | (`Null) :: rest -> ("hash_serialized_3", rest)
    | _ -> ("hash_serialized_3", List.tl params)
  in
  if extra_args <> [] && extra_args <> [`Null] then
    Error "Querying specific block heights is not supported"
  else
    let normalized = String.lowercase_ascii hash_type in
    if normalized <> "none"
       && normalized <> "hash_serialized_3"
       && normalized <> "muhash" then
      Error (Printf.sprintf
               "%s is not a valid hash_type" hash_type)
    else begin
      (* Walk the UTXO set once, computing aggregate stats and (optionally)
         the requested commitment in a single pass. The MuHash accumulator
         is allocated lazily so callers asking for hash_type=none don't pay
         for it. The hash_serialized_3 path uses the same buffer-then-SHA256d
         encoding [compute_utxo_hash_from_db] does — we replicate the loop
         locally to avoid a second pass over the iterator. *)
      let muhash_acc =
        if normalized = "muhash" then Some (Muhash.create ()) else None
      in
      let hash_buffer =
        if normalized = "hash_serialized_3" then
          Some (Buffer.create (1024 * 1024))
        else None
      in
      let txouts = ref 0 in
      let bogosize = ref 0L in
      let total_amount = ref 0L in
      let txid_set = Hashtbl.create 1024 in
      Storage.ChainDB.iter_utxos ctx.chain.db (fun txid vout data ->
        let r = Serialize.reader_of_cstruct (Cstruct.of_string data) in
        let utxo = Utxo.deserialize_utxo_entry r in
        let outpoint = { Types.txid; vout = Int32.of_int vout } in
        (* Track unique txids for the [transactions] field. *)
        let key = Types.hash256_to_hex txid in
        if not (Hashtbl.mem txid_set key) then
          Hashtbl.add txid_set key ();
        incr txouts;
        total_amount := Int64.add !total_amount utxo.Utxo.value;
        (* Core's GetBogoSize: 32 + 4 + 4 + 8 + 2 + scriptPubKey.size *)
        let spk_len = Cstruct.length utxo.script_pubkey in
        bogosize := Int64.add !bogosize (Int64.of_int (50 + spk_len));
        (match muhash_acc with
         | None -> ()
         | Some acc ->
           let buf =
             Muhash.serialize_txout outpoint
               ~value:utxo.Utxo.value
               ~script_pubkey:utxo.script_pubkey
               ~height:utxo.height
               ~is_coinbase:utxo.is_coinbase
           in
           Muhash.add acc (Bytes.unsafe_to_string buf));
        (match hash_buffer with
         | None -> ()
         | Some buf ->
           let coin : Assume_utxo.snapshot_coin = {
             outpoint;
             value = utxo.Utxo.value;
             script_pubkey = utxo.script_pubkey;
             height = utxo.height;
             is_coinbase = utxo.is_coinbase;
           } in
           let w = Serialize.writer_create () in
           Assume_utxo.serialize_coin_for_hash w outpoint coin;
           let cs = Serialize.writer_to_cstruct w in
           Buffer.add_string buf (Cstruct.to_string cs)));
      let tip_height, tip_hash = match ctx.chain.tip with
        | Some t -> (t.height, t.hash)
        | None -> (0, Types.zero_hash)
      in
      let base_fields = [
        ("height", `Int tip_height);
        ("bestblock",
           `String (Types.hash256_to_hex_display tip_hash));
        ("transactions", `Int (Hashtbl.length txid_set));
        ("txouts", `Int !txouts);
        ("bogosize", `Int (Int64.to_int !bogosize));
        ("total_amount",
           (* Core formats total_amount as a fixed-precision BTC float;
              we emit satoshis as int to keep the value loss-free for
              downstream tooling, matching what camlcoin does in
              getblockstats. *)
           `Int (Int64.to_int !total_amount));
      ] in
      let hash_field =
        match muhash_acc, hash_buffer with
        | Some acc, _ ->
          let raw = Muhash.finalize acc in
          [("muhash",
              `String (Types.hash256_to_hex_display
                         (Cstruct.of_bytes raw)))]
        | None, Some buf ->
          let cs = Cstruct.of_string (Buffer.contents buf) in
          let h = Crypto.sha256d cs in
          [("hash_serialized_3",
              `String (Types.hash256_to_hex_display h))]
        | None, None -> []
      in
      Ok (`Assoc (base_fields @ hash_field))
    end

(* ============================================================================
   scrubunspendable Handler
   ============================================================================

   Operator-invoked one-shot scrub. Walks the [Cf_chainstate.cfh_utxo]
   column family via [Storage.ChainDB.iter_utxos] and removes any entry
   whose [script_pubkey] is provably unspendable per
   [Utxo.is_unspendable_script] (mirrors Bitcoin Core's
   [CScript::IsUnspendable]: leading [OP_RETURN] or oversize script).

   Background: prior to commit 0c02b15, [connect_block_optimized] /
   [Sync.process_new_block] / [Sync.connect_stored_blocks] inserted
   every coinbase output into the UTXO set, including the SegWit
   witness-commitment [OP_RETURN] and any other [OP_RETURN] data
   carriers.  Bitcoin Core's [validation.cpp:AddCoins] skips
   [IsUnspendable()] outputs, so legacy datadirs carry an over-count of
   coins versus Core. The write-time filter in 0c02b15 stops new
   orphans, but pre-existing on-disk entries linger.  This RPC closes
   that gap.

   Idempotent: a second invocation finds no unspendable entries and
   returns [{"removed": 0, "bytes_freed": 0}].

   Implementation note: we collect the (txid, vout, value-bytes) tuples
   in a first iterator pass and delete in a second pass, so we never
   mutate the CF while a RocksDB iterator is still walking it.
   [Storage.ChainDB.delete_utxo] mirrors the delete into the optional
   [rocksdb_utxo] backend so a scrubbed coin cannot reappear via the
   AssumeUTXO fallback path. *)

let handle_scrubunspendable (ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  match params with
  | [] | [`Null] ->
    let to_delete : (Types.hash256 * int * int) list ref = ref [] in
    let scanned = ref 0 in
    (* Phase 1: collect orphan keys.  Iteration runs over a RocksDB
       snapshot, so deletes are deferred to phase 2 to keep iterator
       semantics well-defined. *)
    Storage.ChainDB.iter_utxos ctx.chain.db (fun txid vout data ->
      incr scanned;
      try
        let r = Serialize.reader_of_cstruct (Cstruct.of_string data) in
        let utxo = Utxo.deserialize_utxo_entry r in
        if Utxo.is_unspendable_script utxo.script_pubkey then
          to_delete :=
            (txid, vout, String.length data) :: !to_delete
      with _ ->
        (* A torn or otherwise undeserializable record is not what this
           RPC is meant to scrub — leave it alone for the operator to
           triage. *)
        ());
    (* Phase 2: delete + tally bytes freed (key 36 + value bytes). *)
    let removed = ref 0 in
    let bytes_freed = ref 0 in
    List.iter (fun (txid, vout, vlen) ->
      Storage.ChainDB.delete_utxo ctx.chain.db txid vout;
      incr removed;
      bytes_freed := !bytes_freed + 36 + vlen
    ) !to_delete;
    Ok (`Assoc [
      ("removed",     `Int !removed);
      ("bytes_freed", `Int !bytes_freed);
      ("scanned",     `Int !scanned);
    ])
  | _ ->
    Error "Invalid parameters: scrubunspendable takes no arguments"

(* ============================================================================
   getdeploymentinfo Handler
   ============================================================================ *)

(* getdeploymentinfo — returns state info for all known soft-fork deployments.
   Optional param: blockhash (default: chain tip). *)
let handle_getdeploymentinfo (ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  (* Resolve the block to query *)
  let entry_opt = match params with
    | [] | [`Null] ->
      ctx.chain.tip
    | [`String hash_hex] ->
      (match parse_blockhash_hex hash_hex with
       | Error msg -> failwith msg
       | Ok hash -> Sync.get_header ctx.chain hash)
    | _ ->
      failwith "Invalid parameters: expected [] or [blockhash]"
  in
  match entry_opt with
  | None ->
    (* No tip yet (empty chain) — return empty deployments *)
    Ok (`Assoc [
      ("hash",        `String "0000000000000000000000000000000000000000000000000000000000000000");
      ("height",      `Int 0);
      ("deployments", `Assoc []);
    ])
  | Some entry ->
    let query_height = entry.height in
    let hash_str = Types.hash256_to_hex_display entry.hash in
    let net = ctx.network in
    let get_block = make_get_block ctx.chain in
    let deployments = `Assoc (build_deployments_assoc ~net ~query_height ~get_block) in

    Ok (`Assoc [
      ("hash",        `String hash_str);
      ("height",      `Int query_height);
      ("deployments", deployments);
    ])

(* ============================================================================
   Control Handlers
   ============================================================================ *)

let handle_stop (_ctx : rpc_context) : Yojson.Safe.t =
  `String "CamlCoin server stopping"

let handle_uptime (_ctx : rpc_context) : Yojson.Safe.t =
  (* Return seconds since start - simplified *)
  `Int 0

let handle_help (_ctx : rpc_context)
    (params : Yojson.Safe.t list) : Yojson.Safe.t =
  match params with
  | [] ->
    `String (String.concat "\n" [
      "== Blockchain ==";
      "getbestblockhash";
      "getblock \"blockhash\" ( verbosity )";
      "getblockchaininfo";
      "getblockcount";
      "getsyncstate";
      "getblockhash height";
      "getblockheader \"blockhash\" ( verbose )";
      "getblockstats hash_or_height";
      "getblockfilter \"blockhash\" ( filtertype )";
      "getdeploymentinfo ( \"blockhash\" )";
      "getdifficulty";
      "getchaintips";
      "";
      "== Mining ==";
      "getblocktemplate";
      "getmininginfo";
      "submitblock \"hexdata\"";
      "";
      "== Regtest Mining ==";
      "generate nblocks (regtest only)";
      "generatetoaddress nblocks \"address\" (regtest only)";
      "generateblock \"output\" [\"rawtx\",...] (regtest only)";
      "";
      "== Mempool ==";
      "dumpmempool";
      "getmempoolancestors \"txid\"";
      "getmempooldescendants \"txid\"";
      "getmempoolentry \"txid\"";
      "getmempoolinfo";
      "getrawmempool ( verbose )";
      "loadmempool";
      "savemempool";
      "testmempoolaccept [\"rawtx\"]";
      "";
      "== Network ==";
      "addnode \"node\" \"add\"|\"remove\"|\"onetry\"";
      "clearbanned";
      "disconnectnode \"address\"";
      "getconnectioncount";
      "getnetworkinfo";
      "getpeerinfo";
      "listbanned";
      "setban \"address\" \"add\"|\"remove\" ( bantime )";
      "";
      "== Rawtransactions ==";
      "decoderawtransaction \"hexstring\"";
      "getrawtransaction \"txid\" ( verbose )";
      "sendrawtransaction \"hexstring\"";
      "signrawtransactionwithkey \"hexstring\" [\"privkey\",...]";
      "submitpackage [\"rawtx\",...] ( maxfeerate maxburnamount )";
      "";
      "== PSBT ==";
      "analyzepsbt \"psbt\"";
      "combinepsbt [\"psbt\",...]";
      "converttopsbt \"hexstring\" ( permitsigdata )";
      "createpsbt [{\"txid\":\"...\", \"vout\":n},...] [{\"address\":amount},...] ( locktime )";
      "decodepsbt \"psbt\"";
      "finalizepsbt \"psbt\" ( extract )";
      "utxoupdatepsbt \"psbt\"";
      "walletcreatefundedpsbt [{\"txid\":\"...\", \"vout\":n},...] [{\"address\":amount},...] ( locktime options bip32derivs )";
      "";
      "== Descriptors ==";
      "deriveaddresses \"descriptor\" ( range )";
      "getdescriptorinfo \"descriptor\"";
      "listdescriptors ( private )";
      "";
      "== Blockchain ==";
      "gettxout \"txid\" vout";
      "invalidateblock \"blockhash\"";
      "reconsiderblock \"blockhash\"";
      "";
      "== Util ==";
      "estimatesmartfee conf_target";
      "estimaterawfee conf_target ( threshold )";
      "signmessage \"address\" \"message\"";
      "signmessagewithprivkey \"privkey\" \"message\"";
      "verifymessage \"address\" \"signature\" \"message\"";
      "validateaddress \"address\"";
      "";
      "== Wallet ==";
      "getbalance";
      "getnewaddress";
      "listtransactions ( count skip )";
      "listunspent";
      "lockunspent unlock ( [{\"txid\":\"...\", \"vout\":n},...] persistent )";
      "listlockunspent";
      "sendtoaddress \"address\" amount";
      "signrawtransactionwithwallet \"hexstring\"";
      "encryptwallet \"passphrase\"";
      "walletpassphrase \"passphrase\" timeout";
      "walletlock";
      "";
      "== Control ==";
      "help ( \"command\" )";
      "stop";
      "uptime";
      "";
      "== Performance ==";
      "getperfstats";
      "";
      "== AssumeUTXO ==";
      "loadtxoutset \"path\"";
      "dumptxoutset \"path\"";
      "gettxoutsetinfo ( \"hash_type\" )";
      "scrubunspendable";
    ])
  | [`String _cmd] ->
    (* Could provide help for specific command *)
    `String "Help for specific commands not implemented"
  | _ ->
    `String "Invalid parameters"

(* ============================================================================
   Wave-47b Handlers: getnetworkhashps, gettxoutproof, verifytxoutproof,
   getrpcinfo
   ============================================================================ *)

(* w47b_dsha256_pair: double-SHA256(a || b), both are 32-byte Cstructs.
   Matches Bitcoin Core Hash(a, b) = DSHA256(a || b). *)
let w47b_dsha256_pair (a : Cstruct.t) (b : Cstruct.t) : Cstruct.t =
  let combined = Cstruct.create 64 in
  Cstruct.blit a 0 combined 0 32;
  Cstruct.blit b 0 combined 32 32;
  Crypto.sha256d combined

(* w47b_tree_width: CalcTreeWidth from Bitcoin Core merkleblock.cpp.
   height 0 = leaf level (width = n_tx); height nHeight = root (width = 1).
   Formula: (n_tx + (1<<height) - 1) >> height *)
let w47b_tree_width (n_tx : int) (height : int) : int =
  (n_tx + (1 lsl height) - 1) lsr height

(* w47b_encode_varint: encode a Bitcoin varint into a Buffer *)
let w47b_encode_varint (buf : Buffer.t) (v : int) : unit =
  if v < 0xFD then
    Buffer.add_char buf (Char.chr v)
  else if v <= 0xFFFF then begin
    Buffer.add_char buf '\xFD';
    Buffer.add_char buf (Char.chr (v land 0xFF));
    Buffer.add_char buf (Char.chr ((v lsr 8) land 0xFF))
  end else begin
    Buffer.add_char buf '\xFE';
    Buffer.add_char buf (Char.chr (v land 0xFF));
    Buffer.add_char buf (Char.chr ((v lsr 8) land 0xFF));
    Buffer.add_char buf (Char.chr ((v lsr 16) land 0xFF));
    Buffer.add_char buf (Char.chr ((v lsr 24) land 0xFF))
  end

(* w47b_write_le32: write 4-byte LE int32 into a Buffer *)
let w47b_write_le32 (buf : Buffer.t) (v : int32) : unit =
  Buffer.add_char buf (Char.chr (Int32.to_int (Int32.logand v 0xFFl)));
  Buffer.add_char buf (Char.chr (Int32.to_int (Int32.logand (Int32.shift_right_logical v 8) 0xFFl)));
  Buffer.add_char buf (Char.chr (Int32.to_int (Int32.logand (Int32.shift_right_logical v 16) 0xFFl)));
  Buffer.add_char buf (Char.chr (Int32.to_int (Int32.logand (Int32.shift_right_logical v 24) 0xFFl)))

(* w47b_calc_hash: CalcHash from Bitcoin Core.
   height 0 = leaves (txids); height > 0 = internal node.
   At height 0, returns txid_arr[pos].
   At height > 0, combines left and right children, duplicating right if out of range. *)
let rec w47b_calc_hash (txid_arr : Cstruct.t array) (n_tx : int)
    (height : int) (pos : int) : Cstruct.t =
  if height = 0 then
    (* leaf: return the txid *)
    txid_arr.(pos)
  else begin
    let left = w47b_calc_hash txid_arr n_tx (height - 1) (pos * 2) in
    let right =
      if pos * 2 + 1 < w47b_tree_width n_tx (height - 1)
      then w47b_calc_hash txid_arr n_tx (height - 1) (pos * 2 + 1)
      else left
    in
    w47b_dsha256_pair left right
  end

(* w47b_build_partial_merkle_tree: TraverseAndBuild from Bitcoin Core.
   Starts at the root (height = nHeight, pos = 0) and recurses toward leaves.
   Returns (hashes_list, bits_list) in the order emitted (pre-order DFS). *)
let w47b_build_partial_merkle_tree (txid_arr : Cstruct.t array)
    (match_arr : bool array) : Cstruct.t list * bool list =
  let n_tx = Array.length txid_arr in
  if n_tx = 0 then ([], [])
  else begin
    (* nHeight: smallest h such that CalcTreeWidth(h) == 1 *)
    let n_height = ref 0 in
    while w47b_tree_width n_tx !n_height > 1 do incr n_height done;
    let hashes = ref [] in
    let bits   = ref [] in
    (* TraverseAndBuild(height, pos): height=0 is leaves, height=nHeight is root *)
    let rec traverse height pos =
      (* fParentOfMatch: any match in range [pos<<height, (pos+1)<<height) *)
      let lo = pos lsl height in
      let hi = min ((pos + 1) lsl height) n_tx in
      let parent_match = ref false in
      for p = lo to hi - 1 do
        if match_arr.(p) then parent_match := true
      done;
      bits := !parent_match :: !bits;
      if height = 0 || not !parent_match then begin
        (* emit hash for this node *)
        hashes := (w47b_calc_hash txid_arr n_tx height pos) :: !hashes
      end else begin
        (* recurse into children *)
        traverse (height - 1) (pos * 2);
        if pos * 2 + 1 < w47b_tree_width n_tx (height - 1) then
          traverse (height - 1) (pos * 2 + 1)
      end
    in
    traverse !n_height 0;
    (List.rev !hashes, List.rev !bits)
  end

(* w47b_read_varint: read a Bitcoin varint from a Cstruct, returns (value, new_pos) *)
let w47b_read_varint (data : Cstruct.t) (pos : int) : int * int =
  let b0 = Cstruct.get_uint8 data pos in
  if b0 < 0xFD then (b0, pos + 1)
  else if b0 = 0xFD then
    let v = Cstruct.LE.get_uint16 data (pos + 1) in (v, pos + 3)
  else if b0 = 0xFE then
    let v = Int32.to_int (Cstruct.LE.get_uint32 data (pos + 1)) in (v, pos + 5)
  else
    let v = Int32.to_int (Cstruct.LE.get_uint32 data (pos + 1)) in (v, pos + 9)

(* w47b_parse_partial_merkle_tree: TraverseAndExtract from Bitcoin Core.
   Returns list of matched txids in display-hex order, or Error. *)
let w47b_parse_partial_merkle_tree (n_tx : int) (hash_list : Cstruct.t list)
    (flag_cs : Cstruct.t) : (string list, string) result =
  if n_tx = 0 then Ok []
  else begin
    let n_height = ref 0 in
    while w47b_tree_width n_tx !n_height > 1 do incr n_height done;
    let total_bits = Cstruct.length flag_cs * 8 in
    let bits = Array.init total_bits (fun i ->
      let byte_i = i / 8 in
      let bit_i  = i mod 8 in
      (Cstruct.get_uint8 flag_cs byte_i) land (1 lsl bit_i) <> 0
    ) in
    let hash_arr = Array.of_list hash_list in
    let bit_pos  = ref 0 in
    let hash_pos = ref 0 in
    let matched  = ref [] in
    let bad      = ref false in
    (* TraverseAndExtract(height, pos): mirrors Bitcoin Core *)
    let rec extract height pos =
      if !bad then Cstruct.create 32
      else if !bit_pos >= total_bits then begin bad := true; Cstruct.create 32 end
      else begin
        let flag = bits.(!bit_pos) in
        incr bit_pos;
        if height = 0 || not flag then begin
          (* use stored hash *)
          if !hash_pos >= Array.length hash_arr
          then begin bad := true; Cstruct.create 32 end
          else begin
            let h = hash_arr.(!hash_pos) in
            incr hash_pos;
            if height = 0 && flag then
              matched := (Types.hash256_to_hex_display h) :: !matched;
            h
          end
        end else begin
          let left  = extract (height - 1) (pos * 2) in
          let right =
            if pos * 2 + 1 < w47b_tree_width n_tx (height - 1)
            then extract (height - 1) (pos * 2 + 1)
            else left
          in
          w47b_dsha256_pair left right
        end
      end
    in
    let _root = extract !n_height 0 in
    if !bad then Error "Invalid proof (bad bit/hash count)"
    else Ok (List.rev !matched)
  end

let handle_getnetworkhashps (ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  let nblocks = match params with
    | `Int n :: _ -> n
    | _ -> 120
  in
  let tip_height = ctx.chain.blocks_synced in
  if tip_height < 2 then Ok (`Int 0)
  else begin
    let window = if nblocks <= 0 then 120 else min nblocks tip_height in
    let hi = tip_height in
    let lo = hi - window in
    match Sync.get_header_at_height ctx.chain hi,
          Sync.get_header_at_height ctx.chain lo with
    | Some hi_e, Some lo_e ->
      (* total_work is a 32-byte LE Cstruct.  Read bytes LE → float. *)
      let cstruct_to_float (cs : Cstruct.t) : float =
        let acc  = ref 0.0 in
        let base = ref 1.0 in
        for i = 0 to 31 do
          acc  := !acc +. float_of_int (Cstruct.get_uint8 cs i) *. !base;
          base := !base *. 256.0
        done;
        !acc
      in
      let work_diff = cstruct_to_float hi_e.Sync.total_work
                   -. cstruct_to_float lo_e.Sync.total_work in
      let time_diff = Int32.to_int hi_e.Sync.header.timestamp
                    - Int32.to_int lo_e.Sync.header.timestamp in
      if time_diff <= 0 then Ok (`Int 0)
      else begin
        let hashps = work_diff /. float_of_int time_diff in
        if hashps < 9.007199254740992e15
        then Ok (`Int (int_of_float hashps))
        else Ok (`Float hashps)
      end
    | _ -> Ok (`Int 0)
  end

let handle_gettxoutproof (ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  match params with
  | (`List txids_json) :: rest ->
    let blockhash_opt = match rest with
      | [`String bh] -> Some bh
      | _ -> None
    in
    (* Parse requested txids: display hex → internal LE Cstruct *)
    let req_txids =
      List.filter_map (function
        | `String hex ->
          let hash_bytes = Types.hash256_of_hex hex in
          let txid = Cstruct.create 32 in
          for i = 0 to 31 do
            Cstruct.set_uint8 txid i (Cstruct.get_uint8 hash_bytes (31 - i))
          done;
          Some txid
        | _ -> None
      ) txids_json
    in
    if req_txids = [] then Error "No txids provided"
    else begin
      let block_hash_result = match blockhash_opt with
        | Some hex ->
          let bh = Types.hash256_of_hex hex in
          let h = Cstruct.create 32 in
          for i = 0 to 31 do
            Cstruct.set_uint8 h i (Cstruct.get_uint8 bh (31 - i))
          done;
          Ok h
        | None ->
          let first_txid = List.hd req_txids in
          (match Storage.ChainDB.get_tx_index ctx.chain.db first_txid with
           | Some (bh, _idx) -> Ok bh
           | None -> Error "Transaction not found in block index")
      in
      match block_hash_result with
      | Error e -> Error e
      | Ok bh ->
        match Storage.ChainDB.get_block ctx.chain.db bh with
        | None -> Error "Block not found"
        | Some block ->
          let all_txids = List.map Crypto.compute_txid block.transactions in
          let n_tx = List.length all_txids in
          let txid_arr = Array.of_list all_txids in
          let match_arr = Array.map (fun tx_cs ->
            List.exists (fun req -> Cstruct.equal tx_cs req) req_txids
          ) txid_arr in
          let (hashes, bits) = w47b_build_partial_merkle_tree txid_arr match_arr in
          (* Encode CMerkleBlock wire format *)
          let buf = Buffer.create 512 in
          (* 80-byte block header *)
          let w = Serialize.writer_create () in
          Serialize.serialize_block_header w block.header;
          Buffer.add_string buf (Cstruct.to_string (Serialize.writer_to_cstruct w));
          (* nTx uint32 LE *)
          w47b_write_le32 buf (Int32.of_int n_tx);
          (* hashes *)
          w47b_encode_varint buf (List.length hashes);
          List.iter (fun h -> Buffer.add_string buf (Cstruct.to_string h)) hashes;
          (* flag bytes *)
          let n_bits  = List.length bits in
          let n_bytes = (n_bits + 7) / 8 in
          let flag_arr = Bytes.make n_bytes '\x00' in
          List.iteri (fun i b ->
            if b then
              Bytes.set_uint8 flag_arr (i / 8)
                (Bytes.get_uint8 flag_arr (i / 8) lor (1 lsl (i mod 8)))
          ) bits;
          w47b_encode_varint buf n_bytes;
          Buffer.add_string buf (Bytes.to_string flag_arr);
          Ok (`String (cstruct_to_hex (Cstruct.of_string (Buffer.contents buf))))
    end
  | _ -> Error "Invalid parameters: expected [txids] or [txids, blockhash]"

let handle_verifytxoutproof (ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  match params with
  | [`String proof_hex] ->
    (try
      let proof_cs = hex_to_cstruct proof_hex in
      let proof_len = Cstruct.length proof_cs in
      if proof_len < 84 then Error "Proof too short"
      else begin
        (* Verify block exists in our chain by hashing the 80-byte header *)
        let block_hash = Crypto.sha256d (Cstruct.sub proof_cs 0 80) in
        match Sync.get_header ctx.chain block_hash with
        | None -> Error "Block not found in chain"
        | Some _entry ->
          let pos = ref 80 in
          let n_tx = Int32.to_int (Cstruct.LE.get_uint32 proof_cs !pos) in
          pos := !pos + 4;
          if n_tx = 0 then Ok (`List [])
          else begin
            let (hash_count, new_pos) = w47b_read_varint proof_cs !pos in
            pos := new_pos;
            if proof_len < !pos + hash_count * 32
            then Error "Proof truncated (hashes)"
            else begin
              let hashes = List.init hash_count (fun i ->
                Cstruct.sub proof_cs (!pos + i * 32) 32
              ) in
              pos := !pos + hash_count * 32;
              let (flag_count, new_pos2) = w47b_read_varint proof_cs !pos in
              pos := new_pos2;
              if proof_len < !pos + flag_count
              then Error "Proof truncated (flags)"
              else begin
                let flag_cs = Cstruct.sub proof_cs !pos flag_count in
                match w47b_parse_partial_merkle_tree n_tx hashes flag_cs with
                | Error e -> Error e
                | Ok matched ->
                  Ok (`List (List.map (fun txid_hex -> `String txid_hex) matched))
              end
            end
          end
      end
    with _ -> Error "Failed to decode proof")
  | _ -> Error "Invalid parameters: expected [proof_hex]"

let handle_getrpcinfo (_ctx : rpc_context) : Yojson.Safe.t =
  `Assoc [
    ("active_commands", `List []);
    ("logpath", `String "");
  ]

(* ============================================================================
   RPC Method Dispatcher
   ============================================================================ *)

let dispatch_rpc (ctx : rpc_context)
    (method_name : string)
    (params : Yojson.Safe.t list)
    : (Yojson.Safe.t, int * string) result =
  match method_name with
  (* Blockchain *)
  | "getblockchaininfo" ->
    Ok (handle_getblockchaininfo ctx)
  | "getblockhash" ->
    (match handle_getblockhash ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_invalid_params, msg))
  | "getblock" ->
    (match handle_getblock ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_misc_error, msg))
  | "getblockheader" ->
    (match handle_getblockheader ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_misc_error, msg))
  | "getblockcount" ->
    Ok (handle_getblockcount ctx)
  | "getbestblockhash" ->
    Ok (handle_getbestblockhash ctx)
  | "getsyncstate" ->
    Ok (handle_getsyncstate ctx)
  | "getdifficulty" ->
    Ok (handle_getdifficulty ctx)
  | "getchaintips" ->
    Ok (handle_getchaintips ctx)
  | "gettxout" ->
    (match handle_gettxout ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_misc_error, msg))
  | "getblockstats" ->
    (match handle_getblockstats ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_misc_error, msg))
  | "invalidateblock" ->
    (match handle_invalidateblock ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_misc_error, msg))
  | "reconsiderblock" ->
    (match handle_reconsiderblock ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_misc_error, msg))
  | "getblockfilter" ->
    (match handle_getblockfilter ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_misc_error, msg))
  | "getdeploymentinfo" ->
    (try
      (match handle_getdeploymentinfo ctx params with
       | Ok r -> Ok r
       | Error msg -> Error (rpc_misc_error, msg))
    with Failure msg -> Error (rpc_misc_error, msg))

  (* Transactions *)
  | "getrawtransaction" ->
    (match handle_getrawtransaction ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_misc_error, msg))
  | "sendrawtransaction" ->
    (match handle_sendrawtransaction ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_verify_rejected, msg))
  | "decoderawtransaction" ->
    (match handle_decoderawtransaction ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_deserialization_error, msg))
  | "signrawtransactionwithkey" ->
    (match handle_signrawtransactionwithkey ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_misc_error, msg))

  (* Network *)
  | "getpeerinfo" ->
    Ok (handle_getpeerinfo ctx)
  | "getconnectioncount" ->
    Ok (handle_getconnectioncount ctx)
  | "getnetworkinfo" ->
    Ok (handle_getnetworkinfo ctx)
  | "listbanned" ->
    Ok (handle_listbanned ctx)
  | "setban" ->
    (match handle_setban ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_invalid_params, msg))
  | "clearbanned" ->
    Ok (handle_clearbanned ctx)
  | "disconnectnode" ->
    (match handle_disconnectnode ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_misc_error, msg))
  | "addnode" ->
    (match handle_addnode ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_invalid_params, msg))

  (* Mempool *)
  | "getmempoolinfo" ->
    Ok (handle_getmempoolinfo ctx)
  | "getrawmempool" ->
    Ok (handle_getrawmempool ctx params)
  | "getmempoolancestors" ->
    (match handle_getmempoolancestors ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_invalid_params, msg))
  | "getmempooldescendants" ->
    (match handle_getmempooldescendants ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_invalid_params, msg))
  | "getmempoolentry" ->
    (match handle_getmempoolentry ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_misc_error, msg))
  | "testmempoolaccept" ->
    (match handle_testmempoolaccept ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_verify_rejected, msg))
  | "submitpackage" ->
    (match handle_submitpackage ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_verify_rejected, msg))
  | "dumpmempool" | "savemempool" ->
    (match handle_dumpmempool ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_misc_error, msg))
  | "loadmempool" ->
    (match handle_loadmempool ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_misc_error, msg))

  (* Fee estimation / Util *)
  | "estimatesmartfee" ->
    (match handle_estimatesmartfee ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_misc_error, msg))
  | "estimaterawfee" ->
    (match handle_estimaterawfee ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_invalid_params, msg))
  | "validateaddress" ->
    (match handle_validateaddress ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_invalid_address, msg))
  | "signmessage" ->
    (match handle_signmessage ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_invalid_address, msg))
  | "signmessagewithprivkey" ->
    (match handle_signmessagewithprivkey ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_invalid_address, msg))
  | "verifymessage" ->
    (match handle_verifymessage ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_invalid_address, msg))

  (* Mining *)
  | "getmininginfo" ->
    Ok (handle_getmininginfo ctx)
  | "getblocktemplate" ->
    (match handle_getblocktemplate ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_misc_error, msg))
  | "submitblock" ->
    (match handle_submitblock ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_verify_rejected, msg))
  | "generate" ->
    (match handle_generate ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_misc_error, msg))
  | "generatetoaddress" ->
    (match handle_generatetoaddress ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_misc_error, msg))
  | "generateblock" ->
    (match handle_generateblock ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_misc_error, msg))

  (* Wallet *)
  | "getbalance" ->
    Ok (handle_getbalance ctx params)
  | "getnewaddress" ->
    (match handle_getnewaddress ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_wallet_error, msg))
  | "listtransactions" ->
    Ok (handle_listtransactions ctx params)
  | "listunspent" ->
    Ok (handle_listunspent ctx params)
  | "sendtoaddress" ->
    (match handle_sendtoaddress ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_wallet_error, msg))
  | "signrawtransactionwithwallet" ->
    (match handle_signrawtransactionwithwallet ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_wallet_error, msg))
  | "lockunspent" ->
    (match handle_lockunspent ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_invalid_params, msg))
  | "listlockunspent" ->
    Ok (handle_listlockunspent ctx params)

  (* Wallet Management *)
  | "createwallet" ->
    (match handle_createwallet ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_wallet_error, msg))
  | "loadwallet" ->
    (match handle_loadwallet ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_wallet_error, msg))
  | "unloadwallet" ->
    (match handle_unloadwallet ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_wallet_error, msg))
  | "listwallets" ->
    Ok (handle_listwallets ctx params)
  | "getwalletinfo" ->
    (match handle_getwalletinfo ctx None params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_wallet_error, msg))

  (* Wallet Encryption *)
  | "encryptwallet" ->
    (match handle_encryptwallet ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_wallet_error, msg))
  | "walletpassphrase" ->
    (match handle_walletpassphrase ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_wallet_error, msg))
  | "walletlock" ->
    (match handle_walletlock ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_wallet_error, msg))

  (* PSBT *)
  | "createpsbt" ->
    (match handle_createpsbt ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_misc_error, msg))
  | "decodepsbt" ->
    (match handle_decodepsbt ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_deserialization_error, msg))
  | "analyzepsbt" ->
    (match handle_analyzepsbt ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_misc_error, msg))
  | "combinepsbt" ->
    (match handle_combinepsbt ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_misc_error, msg))
  | "finalizepsbt" ->
    (match handle_finalizepsbt ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_misc_error, msg))
  | "utxoupdatepsbt" ->
    (match handle_utxoupdatepsbt ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_misc_error, msg))
  | "converttopsbt" ->
    (match handle_converttopsbt ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_misc_error, msg))
  | "walletcreatefundedpsbt" ->
    (match handle_walletcreatefundedpsbt ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_wallet_error, msg))

  (* Output Descriptors *)
  | "getdescriptorinfo" ->
    (match handle_getdescriptorinfo ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_misc_error, msg))
  | "deriveaddresses" ->
    (match handle_deriveaddresses ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_misc_error, msg))
  | "listdescriptors" ->
    (match handle_listdescriptors ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_wallet_error, msg))

  (* Control *)
  | "stop" ->
    Ok (handle_stop ctx)
  | "uptime" ->
    Ok (handle_uptime ctx)
  | "help" ->
    Ok (handle_help ctx params)

  (* Performance *)
  | "getperfstats" ->
    Ok (handle_getperfstats ctx)

  (* AssumeUTXO *)
  | "loadtxoutset" ->
    (match handle_loadtxoutset ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_misc_error, msg))
  | "dumptxoutset" ->
    (match handle_dumptxoutset ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_misc_error, msg))
  | "gettxoutsetinfo" ->
    (match handle_gettxoutsetinfo ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_invalid_params, msg))
  | "scrubunspendable" ->
    (match handle_scrubunspendable ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_invalid_params, msg))

  (* Wave-47b *)
  | "getnetworkhashps" ->
    (match handle_getnetworkhashps ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_misc_error, msg))
  | "gettxoutproof" ->
    (match handle_gettxoutproof ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_misc_error, msg))
  | "verifytxoutproof" ->
    (match handle_verifytxoutproof ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_misc_error, msg))
  | "getrpcinfo" ->
    Ok (handle_getrpcinfo ctx)

  | _ ->
    Error (rpc_method_not_found, "Method not found: " ^ method_name)

(* ============================================================================
   HTTP Server
   ============================================================================ *)

(* Handle a single JSON-RPC request object, returning the response *)
let handle_single_request (ctx : rpc_context) (json : Yojson.Safe.t)
    : Yojson.Safe.t =
  let method_name = match json with
    | `Assoc fields ->
      (match List.assoc_opt "method" fields with
       | Some (`String m) -> m
       | _ -> "")
    | _ -> ""
  in
  let params = match json with
    | `Assoc fields ->
      (match List.assoc_opt "params" fields with
       | Some (`List l) -> l
       | Some (`Null) -> []
       | None -> []
       | _ -> [])
    | _ -> []
  in
  let id = match json with
    | `Assoc fields ->
      (match List.assoc_opt "id" fields with
       | Some v -> v
       | None -> `Null)
    | _ -> `Null
  in
  match dispatch_rpc ctx method_name params with
  | Ok r -> json_rpc_response ~id ~result:r
  | Error (code, message) -> json_rpc_error ~id ~code ~message

(* Handle a batch of JSON-RPC requests in parallel *)
let handle_batch_request (ctx : rpc_context) (requests : Yojson.Safe.t list)
    : Yojson.Safe.t list Lwt.t =
  Lwt_list.map_p (fun req ->
    (* Each request is processed independently - errors in one don't affect others *)
    try
      Lwt.return (handle_single_request ctx req)
    with exn ->
      (* Extract id from malformed request if possible *)
      let id = match req with
        | `Assoc fields ->
          (match List.assoc_opt "id" fields with
           | Some v -> v
           | None -> `Null)
        | _ -> `Null
      in
      Lwt.return (json_rpc_error ~id ~code:rpc_parse_error
                    ~message:(Printexc.to_string exn))
  ) requests

(* Extract wallet name from URI path: /wallet/<name> or / *)
let extract_wallet_from_uri (uri : Uri.t) : string option =
  let path = Uri.path uri in
  if String.length path > 8 && String.sub path 0 8 = "/wallet/" then
    Some (String.sub path 8 (String.length path - 8))
  else if path = "/" || path = "" then
    None  (* Use default wallet *)
  else
    None

(* Create a context with wallet override for specific wallet routing *)
let context_with_wallet (ctx : rpc_context) (wallet_name : string option) : rpc_context =
  match wallet_name, ctx.wallet_manager with
  | None, _ -> ctx  (* Use existing context *)
  | Some name, Some wm ->
    (* Override wallet in context with specific wallet from manager *)
    (match Wallet.get_wallet wm name with
     | Some w -> { ctx with wallet = Some w }
     | None -> ctx)
  | Some _, None -> ctx  (* No manager, use existing *)

let start_rpc_server ~(ctx : rpc_context)
    ~(host : string) ~(port : int)
    ~(rpc_user : string) ~(rpc_password : string)
    ~(cookie_password : string option)
    : unit Lwt.t =
  let open Lwt.Syntax in

  let check_auth headers =
    match Cohttp.Header.get headers "authorization" with
    | None -> false
    | Some auth ->
      let expected_user = "Basic " ^
        Base64.encode_string (rpc_user ^ ":" ^ rpc_password) in
      if String.equal auth expected_user then true
      else match cookie_password with
        | None -> false
        | Some cp ->
          let expected_cookie = "Basic " ^
            Base64.encode_string ("__cookie__:" ^ cp) in
          String.equal auth expected_cookie
  in

  let callback _conn req body =
    let headers = Cohttp.Request.headers req in
    let meth = Cohttp.Request.meth req in
    let uri = Cohttp.Request.uri req in

    (* Extract wallet name from URI for multi-wallet routing *)
    let wallet_name = extract_wallet_from_uri uri in
    let request_ctx = context_with_wallet ctx wallet_name in

    (* Only accept POST requests *)
    if meth <> `POST then begin
      let response_headers = Cohttp.Header.init_with
        "Content-Type" "application/json" in
      Cohttp_lwt_unix.Server.respond_string
        ~status:`Method_not_allowed
        ~headers:response_headers
        ~body:"{\"error\": \"Method not allowed\"}" ()
    end
    (* Check authentication *)
    else if not (check_auth headers) then begin
      let response_headers = Cohttp.Header.init_with
        "WWW-Authenticate" "Basic realm=\"jsonrpc\"" in
      Cohttp_lwt_unix.Server.respond_string
        ~status:`Unauthorized
        ~headers:response_headers
        ~body:"Unauthorized" ()
    end
    else begin
      let* body_str = Cohttp_lwt.Body.to_string body in
      try
        let json = Yojson.Safe.from_string body_str in

        match json with
        (* Batch request: JSON array of request objects *)
        | `List requests ->
          (* Empty batch is an error per JSON-RPC 2.0 spec *)
          if requests = [] then begin
            let error = json_rpc_error ~id:`Null ~code:rpc_invalid_request
                          ~message:"Invalid Request: empty batch" in
            let response_headers = Cohttp.Header.init_with
              "Content-Type" "application/json" in
            Cohttp_lwt_unix.Server.respond_string
              ~status:`OK
              ~headers:response_headers
              ~body:(Yojson.Safe.to_string error) ()
          end
          else begin
            (* Process batch requests in parallel *)
            let* responses = handle_batch_request request_ctx requests in
            let response_body = Yojson.Safe.to_string (`List responses) in
            let response_headers = Cohttp.Header.init_with
              "Content-Type" "application/json" in
            Cohttp_lwt_unix.Server.respond_string
              ~status:`OK
              ~headers:response_headers
              ~body:response_body ()
          end

        (* Single request: JSON object *)
        | `Assoc _ as single_request ->
          let result = handle_single_request request_ctx single_request in
          let response_body = Yojson.Safe.to_string result in
          let response_headers = Cohttp.Header.init_with
            "Content-Type" "application/json" in
          Cohttp_lwt_unix.Server.respond_string
            ~status:`OK
            ~headers:response_headers
            ~body:response_body ()

        (* Invalid request: neither object nor array *)
        | _ ->
          let error = json_rpc_error ~id:`Null ~code:rpc_invalid_request
                        ~message:"Invalid Request" in
          let response_headers = Cohttp.Header.init_with
            "Content-Type" "application/json" in
          Cohttp_lwt_unix.Server.respond_string
            ~status:`OK
            ~headers:response_headers
            ~body:(Yojson.Safe.to_string error) ()

      with exn ->
        let error = json_rpc_error
          ~id:`Null
          ~code:rpc_parse_error
          ~message:(Printexc.to_string exn) in
        let response_headers = Cohttp.Header.init_with
          "Content-Type" "application/json" in
        Cohttp_lwt_unix.Server.respond_string
          ~status:`OK
          ~headers:response_headers
          ~body:(Yojson.Safe.to_string error) ()
    end
  in

  let server = Cohttp_lwt_unix.Server.make ~callback () in
  let mode = `TCP (`Port port) in
  Logs.info (fun m -> m "RPC server listening on %s:%d" host port);
  Cohttp_lwt_unix.Server.create ~mode server

(* ============================================================================
   Server Creation Helpers
   ============================================================================ *)

(* Create an RPC context from node components *)
let create_context
    ~(chain : Sync.chain_state)
    ~(mempool : Mempool.mempool)
    ~(peer_manager : Peer_manager.t)
    ~(wallet : Wallet.t option)
    ~(fee_estimator : Fee_estimation.t)
    ~(network : Consensus.network_config)
    ?(wallet_manager : Wallet.wallet_manager option = None)
    ?(filter_index : Block_index.filter_index option = None)
    ?(utxo : Utxo.OptimizedUtxoSet.t option = None)
    ?(data_dir : string option = None) () : rpc_context =
  { chain; mempool; peer_manager; wallet; wallet_manager; fee_estimator; network;
    filter_index; utxo; data_dir }

(* Create an RPC context with multi-wallet support *)
let create_context_with_wallet_manager
    ~(chain : Sync.chain_state)
    ~(mempool : Mempool.mempool)
    ~(peer_manager : Peer_manager.t)
    ~(wallet_manager : Wallet.wallet_manager)
    ~(fee_estimator : Fee_estimation.t)
    ~(network : Consensus.network_config)
    ?(filter_index : Block_index.filter_index option = None)
    ?(utxo : Utxo.OptimizedUtxoSet.t option = None)
    ?(data_dir : string option = None) () : rpc_context =
  (* Get default wallet from manager for backward compatibility *)
  let wallet = Wallet.get_default_wallet wallet_manager in
  { chain; mempool; peer_manager; wallet; wallet_manager = Some wallet_manager;
    fee_estimator; network; filter_index; utxo; data_dir }

(* Default RPC ports by network *)
let default_port (network : Consensus.network_config) : int =
  match network.name with
  | "mainnet" -> 8332
  | "testnet3" | "testnet4" -> 18332
  | "regtest" -> 18443
  | _ -> 8332
