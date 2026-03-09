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
  let tip_height, tip_hash = match ctx.chain.tip with
    | Some t -> (t.height,
        Types.hash256_to_hex_display t.hash)
    | None -> (0, "0000000000000000000000000000000000000000000000000000000000000000")
  in
  `Assoc [
    ("chain", `String ctx.network.name);
    ("blocks", `Int tip_height);
    ("headers", `Int ctx.chain.headers_synced);
    ("bestblockhash", `String tip_hash);
    ("difficulty", `Float 1.0);
    ("mediantime", `Int 0);
    ("verificationprogress", `Float
      (if ctx.chain.headers_synced = 0 then 0.0
       else float_of_int tip_height /.
            float_of_int ctx.chain.headers_synced));
    ("initialblockdownload",
      `Bool (ctx.chain.sync_state <> Sync.FullySynced));
    ("chainwork", `String "0");
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
       (* Get height from header entry *)
       let height = match Sync.get_header ctx.chain hash with
         | Some entry -> entry.height
         | None -> 0
       in
       Ok (`Assoc [
         ("hash", `String hash_hex);
         ("confirmations", `Int 1);
         ("size", `Int 0);
         ("strippedsize", `Int 0);
         ("weight", `Int 0);
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
         ("difficulty", `Float 1.0);
         ("chainwork", `String "0");
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
       let height = match Sync.get_header ctx.chain hash with
         | Some entry -> entry.height
         | None -> 0
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
         ("difficulty", `Float 1.0);
         ("chainwork", `String "0");
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

let handle_getdifficulty (_ctx : rpc_context) : Yojson.Safe.t =
  (* Simplified: return 1.0 for now *)
  `Float 1.0

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
    ("fullrbf", `Bool false);
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
      let info = `Assoc [
        ("vsize", `Int (entry.weight / 4));
        ("weight", `Int entry.weight);
        ("fee", `Float (Int64.to_float entry.fee /. 100_000_000.0));
        ("modifiedfee", `Float (Int64.to_float entry.fee /. 100_000_000.0));
        ("time", `Int (int_of_float entry.time_added));
        ("height", `Int entry.height_added);
        ("descendantcount", `Int 1);
        ("descendantsize", `Int (entry.weight / 4));
        ("descendantfees", `Int (Int64.to_int entry.fee));
        ("ancestorcount", `Int (1 + List.length entry.depends_on));
        ("ancestorsize", `Int (entry.weight / 4));
        ("ancestorfees", `Int (Int64.to_int entry.fee));
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
  let height = match ctx.chain.tip with
    | Some t -> t.height
    | None -> 0
  in
  `Assoc [
    ("blocks", `Int height);
    ("difficulty", `Float 1.0);
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

let handle_getbalance (_ctx : rpc_context)
    (_params : Yojson.Safe.t list) : Yojson.Safe.t =
  (* Stub - would need full wallet implementation *)
  `Float 0.0

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

let handle_listunspent (_ctx : rpc_context)
    (_params : Yojson.Safe.t list) : Yojson.Safe.t =
  (* Stub - would need full wallet implementation *)
  `List []

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
      "== Util ==";
      "estimatesmartfee conf_target";
      "";
      "== Wallet ==";
      "getbalance";
      "getnewaddress";
      "listunspent";
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

  (* Fee estimation *)
  | "estimatesmartfee" ->
    (match handle_estimatesmartfee ctx params with
     | Ok r -> Ok r
     | Error msg -> Error (rpc_misc_error, msg))

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
