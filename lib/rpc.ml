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
  wallet : Wallet.t option;
  fee_estimator : Fee_estimation.t;
  network : Consensus.network_config;
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

(* Get script type name for JSON output *)
let script_type_name (template : Script.script_template) : string =
  match template with
  | Script.P2PKH_script _ -> "pubkeyhash"
  | Script.P2SH_script _ -> "scripthash"
  | Script.P2WPKH_script _ -> "witness_v0_keyhash"
  | Script.P2WSH_script _ -> "witness_v0_scripthash"
  | Script.P2TR_script _ -> "witness_v1_taproot"
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
  | Script.OP_RETURN_data _ | Script.Nonstandard -> None

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
                let sig_bytes = Crypto.schnorr_sign ~privkey ~msg:sighash in
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
      "getdifficulty";
      "";
      "== Mining ==";
      "getblocktemplate";
      "getmininginfo";
      "submitblock \"hexdata\"";
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
      "== Blockchain ==";
      "gettxout \"txid\" vout";
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
            let* responses = handle_batch_request ctx requests in
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
          let result = handle_single_request ctx single_request in
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
    ~(network : Consensus.network_config) : rpc_context =
  { chain; mempool; peer_manager; wallet; fee_estimator; network }

(* Default RPC ports by network *)
let default_port (network : Consensus.network_config) : int =
  match network.name with
  | "mainnet" -> 8332
  | "testnet3" | "testnet4" -> 18332
  | "regtest" -> 18443
  | _ -> 8332
