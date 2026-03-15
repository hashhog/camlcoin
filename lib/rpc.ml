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
   Blockchain Info Handlers
   ============================================================================ *)

let handle_getblockchaininfo (ctx : rpc_context)
    : Yojson.Safe.t =
  let tip_entry = ctx.chain.tip in
  let tip_height, tip_hash = match tip_entry with
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
  let base_fields = [
    ("chain", `String ctx.network.name);
    ("blocks", `Int tip_height);
    ("headers", `Int ctx.chain.headers_synced);
    ("bestblockhash", `String tip_hash);
    ("difficulty", `Float difficulty);
    ("mediantime", `Int 0);
    ("verificationprogress", `Float
      (if ctx.chain.headers_synced = 0 then 0.0
       else float_of_int tip_height /.
            float_of_int ctx.chain.headers_synced));
    ("initialblockdownload",
      `Bool (ctx.chain.sync_state <> Sync.FullySynced));
    ("chainwork", `String chainwork);
    ("size_on_disk", `Int 0);
    ("pruned", `Bool (ctx.chain.prune_target > 0));
  ] @
  (if ctx.chain.prune_target > 0 then
    [("pruneheight", `Int ctx.chain.prune_height);
     ("prune_target_size", `Int ctx.chain.prune_target)]
   else []) @
  [
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
         ("difficulty", `Float (Consensus.difficulty_from_bits block.header.bits));
         ("chainwork", `String chainwork);
         ("nTx", `Int (List.length block.transactions));
         ("previousblockhash", `String
           (Types.hash256_to_hex_display block.header.prev_block));
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
       let hex = Types.hash256_to_hex cs in
       Ok (`String hex))
  | _ ->
    Error "Invalid parameters: expected [blockhash] or [blockhash, verbose]"

let handle_getblockcount (ctx : rpc_context) : Yojson.Safe.t =
  match ctx.chain.tip with
  | Some t -> `Int t.height
  | None -> `Int 0

let handle_getbestblockhash (ctx : rpc_context) : Yojson.Safe.t =
  match ctx.chain.tip with
  | Some t -> `String (Types.hash256_to_hex_display t.hash)
  | None -> `String "0000000000000000000000000000000000000000000000000000000000000000"

let handle_getdifficulty (ctx : rpc_context) : Yojson.Safe.t =
  match ctx.chain.tip with
  | Some t -> `Float (Consensus.difficulty_from_bits t.header.bits)
  | None -> `Float 1.0

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
            ("filter", `String (Types.hash256_to_hex
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
            ("hex", `String (Types.hash256_to_hex inp.Types.script_sig));
          ]);
          ("sequence", `Int (Int32.to_int inp.Types.sequence));
          ("txinwitness",
            if i < List.length tx.witnesses then
              `List (List.map (fun item ->
                `String (Types.hash256_to_hex item)
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
            ("hex", `String (Types.hash256_to_hex out.Types.script_pubkey));
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
    `Assoc [
      ("id", `Int stats.Peer.stat_id);
      ("addr", `String (Printf.sprintf "%s:%d"
        stats.stat_addr stats.stat_port));
      ("services", `String (Printf.sprintf "%016Lx" stats.stat_services));
      ("relaytxes", `Bool true);
      ("lastsend", `Int (int_of_float stats.stat_last_seen));
      ("lastrecv", `Int (int_of_float stats.stat_last_seen));
      ("bytessent", `Int stats.stat_bytes_sent);
      ("bytesrecv", `Int stats.stat_bytes_received);
      ("conntime", `Int (int_of_float stats.stat_last_seen));
      ("timeoffset", `Int 0);
      ("pingtime", `Float (stats.stat_latency_ms /. 1000.0));
      ("version", `Int 70016);
      ("subver", `String stats.stat_user_agent);
      ("inbound", `Bool (stats.stat_direction = Peer.Inbound));
      ("startingheight", `Int (Int32.to_int stats.stat_best_height));
      ("synced_headers", `Int (-1));
      ("synced_blocks", `Int (-1));
      ("inflight", `List []);
      ("misbehavior_score", `Int stats.stat_misbehavior);
    ]
  ) peers)

let handle_getconnectioncount (ctx : rpc_context) : Yojson.Safe.t =
  `Int (Peer_manager.peer_count ctx.peer_manager)

let handle_getnetworkinfo (ctx : rpc_context) : Yojson.Safe.t =
  `Assoc [
    ("version", `Int 210000);
    ("subversion", `String ("/CamlCoin:" ^ Types.version ^ "/"));
    ("protocolversion", `Int (Int32.to_int Types.protocol_version));
    ("localservices", `String "0000000000000009");
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
    ("totalfee", `Float (Int64.to_float fees /. 100_000_000.0));
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
      let info = `Assoc [
        ("vsize", `Int (entry.weight / 4));
        ("weight", `Int entry.weight);
        ("fee", `Float (Int64.to_float entry.fee /. 100_000_000.0));
        ("modifiedfee", `Float (Int64.to_float entry.fee /. 100_000_000.0));
        ("time", `Int (int_of_float entry.time_added));
        ("height", `Int entry.height_added);
        ("descendantcount", `Int descendantcount);
        ("descendantsize", `Int descendantsize);
        ("descendantfees", `Float descendantfees);
        ("ancestorcount", `Int ancestorcount);
        ("ancestorsize", `Int ancestorsize);
        ("ancestorfees", `Float ancestorfees);
        ("depends", `List (List.map (fun dep ->
          `String (Types.hash256_to_hex_display dep)
        ) entry.depends_on));
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

(* ============================================================================
   Mining Handlers
   ============================================================================ *)

let handle_getmininginfo (ctx : rpc_context) : Yojson.Safe.t =
  let height, difficulty = match ctx.chain.tip with
    | Some t -> (t.height, Consensus.difficulty_from_bits t.header.bits)
    | None -> (0, 1.0)
  in
  `Assoc [
    ("blocks", `Int height);
    ("difficulty", `Float difficulty);
    ("networkhashps", `Float 0.0);
    ("pooledtx", `Int (Hashtbl.length ctx.mempool.entries));
    ("chain", `String ctx.network.name);
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

let handle_submitblock (ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  match params with
  | [`String hex] ->
    (try
      let data = Cstruct.of_hex hex in
      let r = Serialize.reader_of_cstruct data in
      let block = Serialize.deserialize_block r in
      match Mining.submit_block block ctx.chain ctx.mempool with
      | Ok () -> Ok `Null
      | Error msg -> Error msg
    with exn ->
      Error (Printf.sprintf "Block decode failed: %s" (Printexc.to_string exn)))
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
    match Mining.submit_block block ctx.chain ctx.mempool with
    | Error msg -> Error msg
    | Ok () ->
      let hash = Crypto.compute_block_hash block.header in
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
           let placeholder_coinbase = Mining.create_coinbase
             ~height ~total_fee ~payout_script ~extra_nonce ~witness_root:None in
           let all_txs_for_witness = placeholder_coinbase :: transactions in
           let witness_root = Mining.compute_witness_merkle_root all_txs_for_witness in
           let coinbase_tx = Mining.create_coinbase
             ~height ~total_fee ~payout_script ~extra_nonce
             ~witness_root:(Some witness_root) in
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
           } in
           (* Mine the block *)
           match Mining.mine_block template 100_000_000l with
           | None -> Error "Failed to find valid nonce"
           | Some block ->
             match Mining.submit_block block ctx.chain ctx.mempool with
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
         let signed_hex = Types.hash256_to_hex cs in
         Ok (`Assoc [
           ("hex", `String signed_hex);
           ("complete", `Bool all_found);
         ])
       with exn ->
         Error (Printf.sprintf "TX decode failed: %s" (Printexc.to_string exn))))
  | _ ->
    Error "Invalid parameters: expected [hexstring]"

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
       let hex = Types.hash256_to_hex script_pubkey in
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
           ("hex", `String (Types.hash256_to_hex utxo.Utxo.script_pubkey));
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
      let new_witnesses = List.mapi (fun i _inp ->
        match List.nth_opt input_utxos i with
        | None | Some None ->
          if i < List.length tx.witnesses then
            List.nth tx.witnesses i
          else
            { Types.items = [] }
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
             if i < List.length tx.witnesses then
               List.nth tx.witnesses i
             else
               { Types.items = [] }
           | Some (privkey, pubkey, pkh, _xonly) ->
             incr signed_count;
             (match script_type with
              | Script.P2TR_script _ ->
                let sighash = Script.compute_sighash_taproot tx i prevouts 0x00 () in
                let xonly_pk = Cstruct.sub pubkey 1 32 in
                let tweak = Crypto.compute_taproot_tweak xonly_pk None in
                let sig_bytes = Crypto.schnorr_sign_tweaked ~privkey ~tweak ~msg:sighash in
                { Types.items = [sig_bytes] }
              | Script.P2WPKH_script _ ->
                let script_code = Wallet.build_p2pkh_script pkh in
                let sighash = Script.compute_sighash_segwit
                  tx i script_code utxo.Utxo.value Script.sighash_all in
                let signature = Crypto.sign privkey sighash in
                let sig_with_hashtype = Cstruct.concat [
                  signature; Cstruct.of_string "\x01"
                ] in
                { Types.items = [sig_with_hashtype; pubkey] }
              | Script.P2PKH_script _ ->
                (* Legacy P2PKH needs scriptSig, not witness *)
                if i < List.length tx.witnesses then
                  List.nth tx.witnesses i
                else
                  { Types.items = [] }
              | _ ->
                if i < List.length tx.witnesses then
                  List.nth tx.witnesses i
                else
                  { Types.items = [] }))
      ) tx.inputs in
      let signed_tx = { tx with witnesses = new_witnesses } in
      let complete = !signed_count = total_inputs in
      let w = Serialize.writer_create () in
      Serialize.serialize_transaction w signed_tx;
      let cs = Serialize.writer_to_cstruct w in
      let signed_hex = Types.hash256_to_hex cs in
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
       let subsidy = Consensus.block_subsidy height in
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

(* ============================================================================
   AssumeUTXO Handlers (loadtxoutset / dumptxoutset)
   ============================================================================ *)

let handle_loadtxoutset (_ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  match params with
  | [`String path] ->
    (* Read and validate snapshot metadata *)
    (match Assume_utxo.read_snapshot_metadata path
             ~expected_network_magic:_ctx.network.magic with
    | Error e -> Error e
    | Ok metadata ->
      (* Check if snapshot blockhash is in our hardcoded params *)
      (match Assume_utxo.get_assumeutxo_for_hash ~network:_ctx.network
               metadata.base_blockhash with
      | None ->
        Error (Printf.sprintf
                 "Snapshot blockhash %s not recognized. AssumeUTXO is only \
                  supported for specific block heights."
                 (Types.hash256_to_hex_display metadata.base_blockhash))
      | Some params ->
        (* Verify coins count matches *)
        if metadata.coins_count <> params.coins_count then
          Error (Printf.sprintf
                   "Coins count mismatch: snapshot has %Ld, expected %Ld"
                   metadata.coins_count params.coins_count)
        else
          (* Return info about the snapshot *)
          Ok (`Assoc [
            ("coins_loaded", `Int (Int64.to_int metadata.coins_count));
            ("block_hash", `String
               (Types.hash256_to_hex_display metadata.base_blockhash));
            ("height", `Int params.height);
            ("path", `String path);
          ])))
  | _ ->
    Error "Invalid parameters: expected [path]"

let handle_dumptxoutset (_ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  match params with
  | [`String path] ->
    (* Get current tip info *)
    let tip_entry = _ctx.chain.tip in
    let tip_height, tip_hash = match tip_entry with
      | Some t -> (t.height, t.hash)
      | None -> (0, Types.zero_hash)
    in
    (* Count total coins in UTXO set *)
    let total_coins = ref 0L in
    Storage.ChainDB.iter_utxos _ctx.chain.db (fun _txid _vout _data ->
      total_coins := Int64.add !total_coins 1L
    );
    (* Create metadata *)
    let metadata : Assume_utxo.snapshot_metadata = {
      network_magic = _ctx.network.magic;
      base_blockhash = tip_hash;
      coins_count = !total_coins;
    } in
    (* Write snapshot file *)
    (try
      let oc = open_out_bin path in
      (* Write metadata *)
      let w = Serialize.writer_create () in
      Assume_utxo.serialize_metadata w metadata;
      output_string oc (Cstruct.to_string (Serialize.writer_to_cstruct w));
      (* Write coins *)
      let coins_written = ref 0L in
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
        let cw = Serialize.writer_create () in
        Assume_utxo.serialize_coin cw coin;
        output_string oc (Cstruct.to_string (Serialize.writer_to_cstruct cw));
        coins_written := Int64.add !coins_written 1L
      );
      close_out oc;
      Ok (`Assoc [
        ("coins_dumped", `Int (Int64.to_int !coins_written));
        ("base_hash", `String (Types.hash256_to_hex_display tip_hash));
        ("base_height", `Int tip_height);
        ("path", `String path);
      ])
    with
    | Sys_error msg -> Error ("Failed to write snapshot: " ^ msg)
    | _ -> Error "Failed to dump UTXO snapshot")
  | _ ->
    Error "Invalid parameters: expected [path]"

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
      "getblockhash height";
      "getblockheader \"blockhash\" ( verbose )";
      "getblockstats hash_or_height";
      "getblockfilter \"blockhash\" ( filtertype )";
      "getdifficulty";
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
      "getmempoolancestors \"txid\"";
      "getmempooldescendants \"txid\"";
      "getmempoolentry \"txid\"";
      "getmempoolinfo";
      "getrawmempool ( verbose )";
      "testmempoolaccept [\"rawtx\"]";
      "";
      "== Network ==";
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
      "";
      "== PSBT ==";
      "analyzepsbt \"psbt\"";
      "combinepsbt [\"psbt\",...]";
      "converttopsbt \"hexstring\" ( permitsigdata )";
      "createpsbt [{\"txid\":\"...\", \"vout\":n},...] [{\"address\":amount},...] ( locktime )";
      "decodepsbt \"psbt\"";
      "finalizepsbt \"psbt\" ( extract )";
      "utxoupdatepsbt \"psbt\"";
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
      "validateaddress \"address\"";
      "";
      "== Wallet ==";
      "getbalance";
      "getnewaddress";
      "listtransactions ( count skip )";
      "listunspent";
      "sendtoaddress \"address\" amount";
      "signrawtransactionwithwallet \"hexstring\"";
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
    ])
  | [`String _cmd] ->
    (* Could provide help for specific command *)
    `String "Help for specific commands not implemented"
  | _ ->
    `String "Invalid parameters"

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
  | "getdifficulty" ->
    Ok (handle_getdifficulty ctx)
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

  (* Fee estimation / Util *)
  | "estimatesmartfee" ->
    (match handle_estimatesmartfee ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_misc_error, msg))
  | "validateaddress" ->
    (match handle_validateaddress ctx params with
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
    : unit Lwt.t =
  let open Lwt.Syntax in

  let check_auth headers =
    match Cohttp.Header.get headers "authorization" with
    | None -> false
    | Some auth ->
      let expected = "Basic " ^
        Base64.encode_string (rpc_user ^ ":" ^ rpc_password) in
      String.equal auth expected
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
    ?(filter_index : Block_index.filter_index option = None) () : rpc_context =
  { chain; mempool; peer_manager; wallet; wallet_manager; fee_estimator; network;
    filter_index }

(* Create an RPC context with multi-wallet support *)
let create_context_with_wallet_manager
    ~(chain : Sync.chain_state)
    ~(mempool : Mempool.mempool)
    ~(peer_manager : Peer_manager.t)
    ~(wallet_manager : Wallet.wallet_manager)
    ~(fee_estimator : Fee_estimation.t)
    ~(network : Consensus.network_config)
    ?(filter_index : Block_index.filter_index option = None) () : rpc_context =
  (* Get default wallet from manager for backward compatibility *)
  let wallet = Wallet.get_default_wallet wallet_manager in
  { chain; mempool; peer_manager; wallet; wallet_manager = Some wallet_manager;
    fee_estimator; network; filter_index }

(* Default RPC ports by network *)
let default_port (network : Consensus.network_config) : int =
  match network.name with
  | "mainnet" -> 8332
  | "testnet3" | "testnet4" -> 18332
  | "regtest" -> 18443
  | _ -> 8332
