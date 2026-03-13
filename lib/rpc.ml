(* JSON-RPC 1.0/2.0 Server over HTTP

   Implements the standard Bitcoin RPC interface for querying blockchain state,
   submitting transactions, managing the wallet, and controlling the node.

   The server uses HTTP Basic authentication and responds to POST requests.
   Response format: {"result": ..., "error": null, "id": ...} on success
                    {"result": null, "error": {"code": N, "message": "..."}, "id": ...} on failure

   KNOWN PITFALL: All RPC requests must be POST. GET requests are rejected. *)

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
  `Assoc [
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
    ("pruned", `Bool false);
    ("warnings", `String "");
  ]

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
       Ok (`Assoc [
         ("hash", `String hash_hex);
         ("confirmations", `Int 1);
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
         ("mediantime", `Int (Int32.to_int block.header.timestamp));
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
       Ok (`Assoc [
         ("hash", `String hash_hex);
         ("confirmations", `Int 1);
         ("height", `Int height);
         ("version", `Int (Int32.to_int header.version));
         ("versionHex", `String (Printf.sprintf "%08lx" header.version));
         ("merkleroot", `String
           (Types.hash256_to_hex_display header.merkle_root));
         ("time", `Int (Int32.to_int header.timestamp));
         ("mediantime", `Int (Int32.to_int header.timestamp));
         ("nonce", `Int (Int32.to_int header.nonce));
         ("bits", `String (Printf.sprintf "%08lx" header.bits));
         ("difficulty", `Float (Consensus.difficulty_from_bits header.bits));
         ("chainwork", `String chainwork);
         ("nTx", `Int 0);
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

let handle_getrawtransaction (ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  match params with
  | [`String txid_hex] | [`String txid_hex; `Bool false] ->
    let txid_bytes = Types.hash256_of_hex txid_hex in
    let txid = Cstruct.create 32 in
    for i = 0 to 31 do
      Cstruct.set_uint8 txid i (Cstruct.get_uint8 txid_bytes (31 - i))
    done;
    let txid_key = Cstruct.to_string txid in
    (* Check mempool first *)
    (match Hashtbl.find_opt ctx.mempool.entries txid_key with
     | Some entry ->
       let w = Serialize.writer_create () in
       Serialize.serialize_transaction w entry.tx;
       let cs = Serialize.writer_to_cstruct w in
       let hex = Types.hash256_to_hex cs in
       Ok (`String hex)
     | None ->
       (* Check on-chain *)
       match Storage.ChainDB.get_transaction ctx.chain.db txid with
       | Some tx ->
         let w = Serialize.writer_create () in
         Serialize.serialize_transaction w tx;
         let cs = Serialize.writer_to_cstruct w in
         let hex = Types.hash256_to_hex cs in
         Ok (`String hex)
       | None -> Error "Transaction not found")
  | [`String txid_hex; `Bool true] ->
    (* Verbose mode - return decoded JSON *)
    let txid_bytes = Types.hash256_of_hex txid_hex in
    let txid = Cstruct.create 32 in
    for i = 0 to 31 do
      Cstruct.set_uint8 txid i (Cstruct.get_uint8 txid_bytes (31 - i))
    done;
    let txid_key = Cstruct.to_string txid in
    let tx_opt =
      match Hashtbl.find_opt ctx.mempool.entries txid_key with
      | Some entry -> Some (entry.tx, None)
      | None ->
        match Storage.ChainDB.get_transaction ctx.chain.db txid with
        | Some tx -> Some (tx, Storage.ChainDB.get_tx_index ctx.chain.db txid)
        | None -> None
    in
    (match tx_opt with
     | None -> Error "Transaction not found"
     | Some (tx, _block_info) ->
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
         ("txid", `String txid_hex);
         ("version", `Int (Int32.to_int tx.version));
         ("size", `Int (Validation.compute_tx_vsize tx));
         ("vsize", `Int (Validation.compute_tx_vsize tx));
         ("weight", `Int (Validation.compute_tx_weight tx));
         ("locktime", `Int (Int32.to_int tx.locktime));
         ("vin", `List vin);
         ("vout", `List vout);
       ]))
  | _ ->
    Error "Invalid parameters: expected [txid] or [txid, verbose]"

let handle_sendrawtransaction (ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  match params with
  | [`String hex] | [`String hex; _] ->
    (try
      let data = Cstruct.of_hex hex in
      let r = Serialize.reader_of_cstruct data in
      let tx = Serialize.deserialize_transaction r in
      match Mempool.add_transaction ctx.mempool tx with
      | Ok entry ->
        Ok (`String (Types.hash256_to_hex_display entry.txid))
      | Error msg ->
        Error msg
    with exn ->
      Error (Printf.sprintf "TX decode failed: %s" (Printexc.to_string exn)))
  | _ ->
    Error "Invalid parameters: expected [hexstring]"

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
        ("size", `Int (Validation.compute_tx_vsize tx));
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
      ("inbound", `Bool false);
      ("startingheight", `Int (Int32.to_int stats.stat_best_height));
      ("synced_headers", `Int (-1));
      ("synced_blocks", `Int (-1));
      ("inflight", `List []);
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
    (_params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  (* Create a simple P2PKH payout script *)
  let payout_script = Cstruct.create 25 in
  Cstruct.set_uint8 payout_script 0 0x76;  (* OP_DUP *)
  Cstruct.set_uint8 payout_script 1 0xa9;  (* OP_HASH160 *)
  Cstruct.set_uint8 payout_script 2 0x14;  (* Push 20 bytes *)
  (* Use zeros for the pubkey hash - miner should provide their own *)
  Cstruct.set_uint8 payout_script 23 0x88;  (* OP_EQUALVERIFY *)
  Cstruct.set_uint8 payout_script 24 0xac;  (* OP_CHECKSIG *)

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
  | Some _wallet ->
    (* Generate a new address - stub implementation *)
    let privkey = Crypto.generate_private_key () in
    let pubkey = Crypto.derive_public_key privkey in
    let pkh = Crypto.hash160 pubkey in
    let addr = Address.encode_p2pkh ctx.network.pubkey_address_prefix pkh in
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
  match params with
  | [`String address; `Float amount_btc] | [`String address; `Float amount_btc; _] ->
    (match ctx.wallet with
     | None -> Error "Wallet not loaded"
     | Some wallet ->
       let amount_sats = Int64.of_float (amount_btc *. 100_000_000.0) in
       (* Use a default fee rate of 1.0 sat/vB *)
       match Wallet.create_transaction wallet ~dest_address:address
               ~amount:amount_sats ~fee_rate:1.0 with
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
       let amount_btc = float_of_int amount_sats_int in
       let amount_sats = Int64.of_float (amount_btc *. 100_000_000.0) in
       match Wallet.create_transaction wallet ~dest_address:address
               ~amount:amount_sats ~fee_rate:1.0 with
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
         | Address.P2WPKH | Address.P2WSH | Address.P2TR -> true
         | Address.P2PKH | Address.P2SH -> false
       in
       let witness_version = match addr.Address.addr_type with
         | Address.P2WPKH | Address.P2WSH -> Some 0
         | Address.P2TR -> Some 1
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
   Performance Stats Handlers
   ============================================================================ *)

let handle_getperfstats (_ctx : rpc_context) : Yojson.Safe.t =
  let report = Perf.Timer.report () in
  `Assoc [
    ("timers", Perf.Timer.to_json ());
    ("timer_report", `String report);
  ]

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
      "";
      "== Network ==";
      "getconnectioncount";
      "getnetworkinfo";
      "getpeerinfo";
      "";
      "== Rawtransactions ==";
      "decoderawtransaction \"hexstring\"";
      "getrawtransaction \"txid\" ( verbose )";
      "sendrawtransaction \"hexstring\"";
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

  (* Network *)
  | "getpeerinfo" ->
    Ok (handle_getpeerinfo ctx)
  | "getconnectioncount" ->
    Ok (handle_getconnectioncount ctx)
  | "getnetworkinfo" ->
    Ok (handle_getnetworkinfo ctx)

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

        let result = match dispatch_rpc ctx method_name params with
          | Ok r -> json_rpc_response ~id ~result:r
          | Error (code, message) -> json_rpc_error ~id ~code ~message
        in

        let response_body = Yojson.Safe.to_string result in
        let response_headers = Cohttp.Header.init_with
          "Content-Type" "application/json" in
        Cohttp_lwt_unix.Server.respond_string
          ~status:`OK
          ~headers:response_headers
          ~body:response_body ()

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
