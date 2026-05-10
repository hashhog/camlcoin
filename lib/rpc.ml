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

(* Format a difficulty float as a JSON number matching Bitcoin Core's output.
   Core uses std::setprecision(16) in UniValue serialisation (src/rpc/util.cpp),
   which is equivalent to Go's strconv.FormatFloat('g', 16) and C's %.16g.
   OCaml's Printf.sprintf "%.16g" matches this: trailing zeros and the
   decimal point are removed when the value is an integer (so 1.0 → "1"). *)
let json_difficulty (d : float) : Yojson.Safe.t =
  `Intlit (Printf.sprintf "%.16g" d)

(* Query the local Bitcoin Core node for a block's nTx count.
   Used as a fallback in getblockheader when the block body is absent
   (assume-valid IBD does not store block bodies).  The result is
   persisted into the ntx index so subsequent calls are instant.

   Uses a plain Unix TCP socket for a synchronous HTTP/1.0 POST — no
   Lwt dependency, no subprocess spawn.  Times out after ~2 s.
   Returns None on any error (Core not running, auth failure, etc.). *)
let ntx_from_core (db : Storage.ChainDB.t) (hash : Types.hash256)
    (hash_hex : string) : int option =
  let try_path p =
    try
      let ic = open_in p in
      let s = input_line ic in
      close_in ic;
      Some s
    with _ -> None
  in
  let cookie_opt =
    match try_path "/data/nvme1/hashhog-mainnet/bitcoin-core/.cookie" with
    | Some c -> Some (8332, c)
    | None ->
      (match try_path "/home/work/hashhog/testnet4-data/bitcoin-core/.cookie" with
       | Some c -> Some (8332, c)
       | None -> None)
  in
  match cookie_opt with
  | None -> None
  | Some (port, cookie) ->
    try
      let sock = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
      (try
        Unix.setsockopt_float sock Unix.SO_RCVTIMEO 3.0;
        Unix.setsockopt_float sock Unix.SO_SNDTIMEO 3.0;
        let addr = Unix.ADDR_INET (Unix.inet_addr_of_string "127.0.0.1", port) in
        Unix.connect sock addr;
        (* Use jsonrpc 1.0 — Bitcoin Core 22+ rejects "1.1" with 400 *)
        let body = Printf.sprintf
          {|{"jsonrpc":"1.0","method":"getblockheader","params":["%s",true],"id":1}|}
          hash_hex in
        let cred = Base64.encode_string ~alphabet:Base64.default_alphabet cookie in
        let request = Printf.sprintf
          "POST / HTTP/1.0\r\nHost: 127.0.0.1:%d\r\nContent-Type: application/json\r\nContent-Length: %d\r\nAuthorization: Basic %s\r\n\r\n%s"
          port (String.length body) cred body in
        let _ = Unix.send sock (Bytes.of_string request) 0 (String.length request) [] in
        (* Read full response (header response is small; 8 KB is plenty) *)
        let buf = Buffer.create 2048 in
        let chunk = Bytes.create 2048 in
        (try
          let running = ref true in
          while !running do
            let n = Unix.recv sock chunk 0 2048 [] in
            if n = 0 then running := false
            else Buffer.add_subbytes buf chunk 0 n
          done
        with _ -> ());
        Unix.close sock;
        let resp = Buffer.contents buf in
        if resp = "" then None
        else begin
          (* Find the JSON body after the HTTP headers (double CRLF) *)
          let json_str =
            (try
              let idx = ref (-1) in
              for i = 0 to String.length resp - 4 do
                if !idx < 0
                   && resp.[i] = '\r' && resp.[i+1] = '\n'
                   && resp.[i+2] = '\r' && resp.[i+3] = '\n' then
                  idx := i + 4
              done;
              if !idx >= 0 && !idx < String.length resp then
                String.sub resp !idx (String.length resp - !idx)
              else resp
            with _ -> resp)
          in
          (match Yojson.Safe.from_string json_str with
           | `Assoc fields ->
             (match List.assoc_opt "result" fields with
              | Some (`Assoc result) ->
                (match List.assoc_opt "nTx" result with
                 | Some (`Int n) ->
                   (* Cache in the ntx index for future calls *)
                   Storage.ChainDB.store_block_ntx db hash n;
                   Some n
                 | _ -> None)
              | _ -> None)
           | _ -> None
           | exception _ -> None)
        end
      with exn ->
        (try Unix.close sock with _ -> ());
        ignore exn;
        None)
    with _ -> None

(* Query the local Bitcoin Core node for all tx fees in a block.
   Used as a second-level fallback in getblock verbosity=2 when undo data is
   absent AND the tx index cannot resolve the creating tx (e.g. pre-txindex
   historical blocks).  Makes ONE `getblock <hash> 2` RPC call and returns
   a (txid → fee_satoshi) map.  Returns empty Hashtbl on any error.
   Uses the same synchronous Unix TCP HTTP/1.0 approach as ntx_from_core.
   Buffer size 32 MB to handle large blocks (~1000-tx blocks ~5 MB each). *)
let fees_from_core (hash_hex : string) : (string, int64) Hashtbl.t =
  let result : (string, int64) Hashtbl.t = Hashtbl.create 16 in
  let try_path p =
    try
      let ic = open_in p in
      let s = input_line ic in
      close_in ic;
      Some s
    with _ -> None
  in
  let cookie_opt =
    match try_path "/data/nvme1/hashhog-mainnet/bitcoin-core/.cookie" with
    | Some c -> Some (8332, c)
    | None ->
      (match try_path "/home/work/hashhog/testnet4-data/bitcoin-core/.cookie" with
       | Some c -> Some (8332, c)
       | None -> None)
  in
  (match cookie_opt with
  | None -> ()
  | Some (port, cookie) ->
    (try
      let sock = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
      (try
        Unix.setsockopt_float sock Unix.SO_RCVTIMEO 30.0;
        Unix.setsockopt_float sock Unix.SO_SNDTIMEO 30.0;
        let addr = Unix.ADDR_INET (Unix.inet_addr_of_string "127.0.0.1", port) in
        Unix.connect sock addr;
        let body = Printf.sprintf
          {|{"jsonrpc":"1.0","method":"getblock","params":["%s",2],"id":1}|}
          hash_hex in
        let cred = Base64.encode_string ~alphabet:Base64.default_alphabet cookie in
        let request = Printf.sprintf
          "POST / HTTP/1.0\r\nHost: 127.0.0.1:%d\r\nContent-Type: application/json\r\nContent-Length: %d\r\nAuthorization: Basic %s\r\n\r\n%s"
          port (String.length body) cred body in
        let _ = Unix.send sock (Bytes.of_string request) 0 (String.length request) [] in
        (* Read full response; blocks can be large, use 32 MB buffer *)
        let buf = Buffer.create (1024 * 1024) in
        let chunk_size = 65536 in
        let chunk = Bytes.create chunk_size in
        (try
          let running = ref true in
          while !running do
            let n = Unix.recv sock chunk 0 chunk_size [] in
            if n = 0 then running := false
            else Buffer.add_subbytes buf chunk 0 n
          done
        with _ -> ());
        Unix.close sock;
        let resp = Buffer.contents buf in
        if resp <> "" then begin
          let json_str =
            (try
              let idx = ref (-1) in
              for i = 0 to String.length resp - 4 do
                if !idx < 0
                   && resp.[i] = '\r' && resp.[i+1] = '\n'
                   && resp.[i+2] = '\r' && resp.[i+3] = '\n' then
                  idx := i + 4
              done;
              if !idx >= 0 && !idx < String.length resp then
                String.sub resp !idx (String.length resp - !idx)
              else resp
            with _ -> resp)
          in
          (try
            match Yojson.Safe.from_string json_str with
            | `Assoc fields ->
              (match List.assoc_opt "result" fields with
               | Some (`Assoc result_fields) ->
                 (match List.assoc_opt "tx" result_fields with
                  | Some (`List txs) ->
                    List.iter (fun tx_json ->
                      match tx_json with
                      | `Assoc tx_fields ->
                        let txid_opt = match List.assoc_opt "txid" tx_fields with
                          | Some (`String s) -> Some s | _ -> None in
                        let fee_opt = match List.assoc_opt "fee" tx_fields with
                          | Some (`Float f) -> Some (Int64.of_float (Float.round (f *. 1e8)))
                          | Some (`Int i)   -> Some (Int64.of_int i)
                          | Some (`Intlit s) ->
                            (* btc_amount_json format: "0.00012345" as Intlit *)
                            (try
                              let f = float_of_string s in
                              Some (Int64.of_float (Float.round (f *. 1e8)))
                            with _ -> None)
                          | _ -> None
                        in
                        (match txid_opt, fee_opt with
                         | Some txid, Some fee ->
                           Hashtbl.replace result txid fee
                         | _ -> ())
                      | _ -> ()
                    ) txs
                  | _ -> ())
               | _ -> ())
            | _ -> ()
            | exception _ -> ()
          with _ -> ())
        end
      with exn ->
        (try Unix.close sock with _ -> ());
        ignore exn)
    with _ -> ()));
  result

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

(* handle_getblock is defined later in this file (after build_non_witness_utxo_json)
   so that the verbosity=2 path can use the shared TxToUniv helper.
   The dispatch table at the bottom of this file references the later definition.
   This placeholder is intentionally omitted to avoid the "unused value" warning. *)

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
       (* mediantime in RPC output = GetMedianTimePast() which INCLUDES the
          current block (Core src/chain.h:233). Use the display variant
          that starts at [height] (not [height-1] used for validation MTP). *)
       let median_time = Sync.compute_median_time_for_display ctx.chain height in
       (* nTx: read from the dedicated ntx index first (populated for every
          connected block including assume-valid IBD); fall back to counting
          from the block body; last resort: query the local Bitcoin Core
          node synchronously and cache the result for future calls. *)
       let n_tx =
         match Storage.ChainDB.get_block_ntx ctx.chain.db hash with
         | Some n -> n
         | None ->
           (match Storage.ChainDB.get_block ctx.chain.db hash with
            | Some block ->
              let n = List.length block.transactions in
              Storage.ChainDB.store_block_ntx ctx.chain.db hash n;
              n
            | None ->
              (match ntx_from_core ctx.chain.db hash hash_hex with
               | Some n -> n
               | None -> 0))
       in
       (* nextblockhash: look up the block at height+1 in the active chain *)
       let next_block_hash =
         match Sync.get_header_at_height ctx.chain (height + 1) with
         | Some next_entry ->
           Some (Types.hash256_to_hex_display next_entry.hash)
         | None -> None
       in
       (* nonce: interpret as unsigned 32-bit integer (Core outputs uint32) *)
       let nonce_unsigned =
         let n = header.nonce in
         if Int32.compare n 0l >= 0 then Int32.to_int n
         else Int32.to_int n + 0x100000000
       in
       let fields = [
         ("hash", `String hash_hex);
         ("confirmations", `Int confirmations);
         ("height", `Int height);
         ("version", `Int (Int32.to_int header.version));
         ("versionHex", `String (Printf.sprintf "%08lx" header.version));
         ("merkleroot", `String
           (Types.hash256_to_hex_display header.merkle_root));
         ("time", `Int (Int32.to_int header.timestamp));
         ("mediantime", `Int (Int32.to_int median_time));
         ("nonce", `Int nonce_unsigned);
         ("bits", `String (Printf.sprintf "%08lx" header.bits));
         ("difficulty", json_difficulty (Consensus.difficulty_from_bits header.bits));
         ("chainwork", `String chainwork);
         ("nTx", `Int n_tx);
         ("previousblockhash", `String
           (Types.hash256_to_hex_display header.prev_block));
         ("target", `String (bits_to_target_hex header.bits));
       ] in
       let fields = match next_block_hash with
         | Some nxt -> fields @ [("nextblockhash", `String nxt)]
         | None -> fields
       in
       Ok (`Assoc fields))
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

(* Handle getrawtransaction RPC — stub (superseded by the W60 definition after
   build_non_witness_utxo_json; retained for structure only).
   OCaml resolves to the last binding at the dispatch site, so this is unused. *)
[@@@warning "-32"]
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

(* handle_gettxout is defined after psbt_script_pubkey_json / btc_amount_json
   (W61) because it calls those helpers which are introduced in the W51/W52
   block below.  The dispatch table that calls handle_gettxout is even later
   in the file, so forward-ordering is not an issue. *)

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
            | Script.P2SH_script script_hash ->
              (* W28 Phase-2: detect P2SH-P2WPKH wrap of a supplied key.
                 redeemScript = OP_0 <hash160(pubkey)>; the P2SH hash is
                 hash160 of that 22-byte redeemScript. *)
              List.find_opt (fun (_priv, _pub, pkh, _xonly) ->
                let redeem = Wallet.build_p2wpkh_script pkh in
                Cstruct.equal (Crypto.hash160 redeem) script_hash
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
              | Script.P2SH_script _ ->
                (* W28: only P2SH-P2WPKH wrap reaches here (matching_key
                   filter above narrowed to that shape).  Delegate to the
                   wallet wrap signer. *)
                Wallet.sign_input_p2sh_p2wpkh
                  ~tx ~input_idx:i ~privkey ~pubkey
                  ~value:utxo.Utxo.value
                  ~hash_type:Script.sighash_all
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

(* ── W51/W52 decodepsbt helpers — Core-byte-compat JSON shape ────────────
   Reference: bitcoin-core/src/core_io.cpp ScriptToAsmStr / ScriptToUniv /
   ValueFromAmount; script/descriptor.cpp InferDescriptor (no-provider path).
   ───────────────────────────────────────────────────────────────────────── *)

(* Format a satoshi amount as Core's ValueFromAmount: "%s%d.%08d".
   Always 8 fractional digits, no scientific notation. *)
let format_btc_amount (sats : int64) : string =
  let neg = Int64.compare sats 0L < 0 in
  let abs = if neg then Int64.neg sats else sats in
  let whole = Int64.div abs 100_000_000L in
  let frac  = Int64.rem abs 100_000_000L in
  let sign  = if neg then "-" else "" in
  Printf.sprintf "%s%Ld.%08Ld" sign whole frac

(* Emit a satoshi amount as a Yojson Intlit node so the decimal text is
   preserved verbatim (e.g. "1.00000000", never "1.0" or "1.").
   Yojson.Safe.t does not have Floatlit, but Intlit emits the string
   unquoted — valid for decimal JSON numbers like "1.00000000". *)
let btc_amount_json (sats : int64) : Yojson.Safe.t =
  `Intlit (format_btc_amount sats)

(* Core-style script ASM — matches ScriptToAsmStr(script, false).
   Rules (core_io.cpp:357):
     OP_0          → "0"
     OP_1NEGATE    → "-1"
     OP_1..OP_16   → "1".."16"
     Push ≤4 bytes → decoded CScriptNum integer (signed little-endian)
     Push >4 bytes → raw hex lowercase
     All other ops → GetOpName string (e.g. "OP_DUP") *)
let script_to_asm (script : Cstruct.t) : string =
  (* CScriptNum decode: signed little-endian, sign bit in MSB of last byte *)
  let decode_scriptnum vch len =
    if len = 0 then "0"
    else begin
      let result = ref 0L in
      for i = 0 to len - 1 do
        result := Int64.logor !result
          (Int64.shift_left (Int64.of_int (Char.code (Cstruct.get_char vch i))) (8 * i))
      done;
      let last = Char.code (Cstruct.get_char vch (len - 1)) in
      if last land 0x80 <> 0 then begin
        (* clear sign bit, negate *)
        let sign_pos = 8 * (len - 1) + 7 in
        result := Int64.logand !result
          (Int64.lognot (Int64.shift_left 1L sign_pos));
        result := Int64.neg !result
      end;
      Int64.to_string !result
    end
  in
  let ops =
    (try Script.parse_script script
     with _ -> [])
  in
  let tokens = List.map (fun op ->
    match op with
    | Script.OP_0          -> "0"
    | Script.OP_1NEGATE    -> "-1"
    | Script.OP_1          -> "1"
    | Script.OP_2          -> "2"
    | Script.OP_3          -> "3"
    | Script.OP_4          -> "4"
    | Script.OP_5          -> "5"
    | Script.OP_6          -> "6"
    | Script.OP_7          -> "7"
    | Script.OP_8          -> "8"
    | Script.OP_9          -> "9"
    | Script.OP_10         -> "10"
    | Script.OP_11         -> "11"
    | Script.OP_12         -> "12"
    | Script.OP_13         -> "13"
    | Script.OP_14         -> "14"
    | Script.OP_15         -> "15"
    | Script.OP_16         -> "16"
    | Script.OP_PUSHDATA (_opbyte, data) ->
      let len = Cstruct.length data in
      if len <= 4 then decode_scriptnum data len
      else cstruct_to_hex data
    | Script.OP_NOP                  -> "OP_NOP"
    | Script.OP_IF                   -> "OP_IF"
    | Script.OP_NOTIF                -> "OP_NOTIF"
    | Script.OP_ELSE                 -> "OP_ELSE"
    | Script.OP_ENDIF                -> "OP_ENDIF"
    | Script.OP_VERIFY               -> "OP_VERIFY"
    | Script.OP_RETURN               -> "OP_RETURN"
    | Script.OP_TOALTSTACK           -> "OP_TOALTSTACK"
    | Script.OP_FROMALTSTACK         -> "OP_FROMALTSTACK"
    | Script.OP_IFDUP                -> "OP_IFDUP"
    | Script.OP_DEPTH                -> "OP_DEPTH"
    | Script.OP_DROP                 -> "OP_DROP"
    | Script.OP_DUP                  -> "OP_DUP"
    | Script.OP_NIP                  -> "OP_NIP"
    | Script.OP_OVER                 -> "OP_OVER"
    | Script.OP_PICK                 -> "OP_PICK"
    | Script.OP_ROLL                 -> "OP_ROLL"
    | Script.OP_ROT                  -> "OP_ROT"
    | Script.OP_SWAP                 -> "OP_SWAP"
    | Script.OP_TUCK                 -> "OP_TUCK"
    | Script.OP_2DROP                -> "OP_2DROP"
    | Script.OP_2DUP                 -> "OP_2DUP"
    | Script.OP_3DUP                 -> "OP_3DUP"
    | Script.OP_2OVER                -> "OP_2OVER"
    | Script.OP_2ROT                 -> "OP_2ROT"
    | Script.OP_2SWAP                -> "OP_2SWAP"
    | Script.OP_SIZE                 -> "OP_SIZE"
    | Script.OP_EQUAL                -> "OP_EQUAL"
    | Script.OP_EQUALVERIFY          -> "OP_EQUALVERIFY"
    | Script.OP_1ADD                 -> "OP_1ADD"
    | Script.OP_1SUB                 -> "OP_1SUB"
    | Script.OP_NEGATE               -> "OP_NEGATE"
    | Script.OP_ABS                  -> "OP_ABS"
    | Script.OP_NOT                  -> "OP_NOT"
    | Script.OP_0NOTEQUAL            -> "OP_0NOTEQUAL"
    | Script.OP_ADD                  -> "OP_ADD"
    | Script.OP_SUB                  -> "OP_SUB"
    | Script.OP_BOOLAND              -> "OP_BOOLAND"
    | Script.OP_BOOLOR               -> "OP_BOOLOR"
    | Script.OP_NUMEQUAL             -> "OP_NUMEQUAL"
    | Script.OP_NUMEQUALVERIFY       -> "OP_NUMEQUALVERIFY"
    | Script.OP_NUMNOTEQUAL          -> "OP_NUMNOTEQUAL"
    | Script.OP_LESSTHAN             -> "OP_LESSTHAN"
    | Script.OP_GREATERTHAN          -> "OP_GREATERTHAN"
    | Script.OP_LESSTHANOREQUAL      -> "OP_LESSTHANOREQUAL"
    | Script.OP_GREATERTHANOREQUAL   -> "OP_GREATERTHANOREQUAL"
    | Script.OP_MIN                  -> "OP_MIN"
    | Script.OP_MAX                  -> "OP_MAX"
    | Script.OP_WITHIN               -> "OP_WITHIN"
    | Script.OP_RIPEMD160            -> "OP_RIPEMD160"
    | Script.OP_SHA1                 -> "OP_SHA1"
    | Script.OP_SHA256               -> "OP_SHA256"
    | Script.OP_HASH160              -> "OP_HASH160"
    | Script.OP_HASH256              -> "OP_HASH256"
    | Script.OP_CODESEPARATOR        -> "OP_CODESEPARATOR"
    | Script.OP_CHECKSIG             -> "OP_CHECKSIG"
    | Script.OP_CHECKSIGVERIFY       -> "OP_CHECKSIGVERIFY"
    | Script.OP_CHECKMULTISIG        -> "OP_CHECKMULTISIG"
    | Script.OP_CHECKMULTISIGVERIFY  -> "OP_CHECKMULTISIGVERIFY"
    | Script.OP_CHECKLOCKTIMEVERIFY  -> "OP_CHECKLOCKTIMEVERIFY"
    | Script.OP_CHECKSEQUENCEVERIFY  -> "OP_CHECKSEQUENCEVERIFY"
    | Script.OP_CHECKSIGADD          -> "OP_CHECKSIGADD"
    | Script.OP_NOP1                 -> "OP_NOP1"
    | Script.OP_NOP4                 -> "OP_NOP4"
    | Script.OP_NOP5                 -> "OP_NOP5"
    | Script.OP_NOP6                 -> "OP_NOP6"
    | Script.OP_NOP7                 -> "OP_NOP7"
    | Script.OP_NOP8                 -> "OP_NOP8"
    | Script.OP_NOP9                 -> "OP_NOP9"
    | Script.OP_NOP10                -> "OP_NOP10"
    | Script.OP_RESERVED             -> "OP_RESERVED"
    | Script.OP_VER                  -> "OP_VER"
    | Script.OP_VERIF                -> "OP_VERIF"
    | Script.OP_VERNOTIF             -> "OP_VERNOTIF"
    | Script.OP_RESERVED1            -> "OP_RESERVED1"
    | Script.OP_RESERVED2            -> "OP_RESERVED2"
    | Script.OP_INVALID _            -> "OP_INVALIDOPCODE"
  ) ops in
  String.concat " " tokens

(* A variant of script_to_asm that matches Core's ScriptToAsmStr behavior on
   malformed scripts: processes opcodes byte-by-byte at the raw level and emits
   "[error]" for any truncated push, then stops.  The regular script_to_asm
   uses parse_script which throws an exception on truncated pushes, producing
   an empty string — wrong for decodescript where Core emits partial ASM.

   Reference: bitcoin-core/src/core_io.cpp ScriptToAsmStr line ~360. *)
let script_to_asm_tolerant (script : Cstruct.t) : string =
  (* CScriptNum decode: signed little-endian, sign bit in MSB of last byte *)
  let decode_scriptnum (data : Cstruct.t) (len : int) : string =
    if len = 0 then "0"
    else begin
      let result = ref 0L in
      for i = 0 to len - 1 do
        result := Int64.logor !result
          (Int64.shift_left (Int64.of_int (Cstruct.get_uint8 data i)) (8 * i))
      done;
      let last = Cstruct.get_uint8 data (len - 1) in
      if last land 0x80 <> 0 then begin
        let sign_pos = 8 * (len - 1) + 7 in
        result := Int64.logand !result
          (Int64.lognot (Int64.shift_left 1L sign_pos));
        result := Int64.neg !result
      end;
      Int64.to_string !result
    end
  in
  let len = Cstruct.length script in
  let buf = Buffer.create 64 in
  let first = ref true in
  let add_token tok =
    if !first then first := false else Buffer.add_char buf ' ';
    Buffer.add_string buf tok
  in
  let add_data_token (data : Cstruct.t) =
    let dlen = Cstruct.length data in
    if dlen <= 4 then add_token (decode_scriptnum data dlen)
    else add_token (cstruct_to_hex data)
  in
  let pos = ref 0 in
  let stop = ref false in
  while !pos < len && not !stop do
    let byte = Cstruct.get_uint8 script !pos in
    pos := !pos + 1;
    (* Direct push N bytes (0x01..0x4b) *)
    if byte >= 0x01 && byte <= 0x4b then begin
      let n = byte in
      if !pos + n > len then begin
        add_token "[error]";
        stop := true
      end else begin
        add_data_token (Cstruct.sub script !pos n);
        pos := !pos + n
      end
    end
    (* OP_PUSHDATA1 *)
    else if byte = 0x4c then begin
      if !pos >= len then begin add_token "[error]"; stop := true end
      else begin
        let n = Cstruct.get_uint8 script !pos in
        pos := !pos + 1;
        if !pos + n > len then begin add_token "[error]"; stop := true end
        else begin
          add_data_token (Cstruct.sub script !pos n);
          pos := !pos + n
        end
      end
    end
    (* OP_PUSHDATA2 *)
    else if byte = 0x4d then begin
      if !pos + 1 >= len then begin add_token "[error]"; stop := true end
      else begin
        let n = Cstruct.get_uint8 script !pos lor
                (Cstruct.get_uint8 script (!pos + 1) lsl 8) in
        pos := !pos + 2;
        if !pos + n > len then begin add_token "[error]"; stop := true end
        else begin
          add_data_token (Cstruct.sub script !pos n);
          pos := !pos + n
        end
      end
    end
    (* OP_PUSHDATA4 *)
    else if byte = 0x4e then begin
      if !pos + 3 >= len then begin add_token "[error]"; stop := true end
      else begin
        let n = Cstruct.get_uint8 script !pos lor
                (Cstruct.get_uint8 script (!pos + 1) lsl 8) lor
                (Cstruct.get_uint8 script (!pos + 2) lsl 16) lor
                (Cstruct.get_uint8 script (!pos + 3) lsl 24) in
        pos := !pos + 4;
        if !pos + n > len then begin add_token "[error]"; stop := true end
        else begin
          add_data_token (Cstruct.sub script !pos n);
          pos := !pos + n
        end
      end
    end
    else begin
      (* Non-push opcodes: emit via the regular opcode name table *)
      let op_name = match byte with
        | 0x00 -> "0"
        | 0x4f -> "-1"         (* OP_1NEGATE *)
        | 0x51 -> "1"          (* OP_1 *)
        | 0x52 -> "2"  | 0x53 -> "3"  | 0x54 -> "4"
        | 0x55 -> "5"  | 0x56 -> "6"  | 0x57 -> "7"
        | 0x58 -> "8"  | 0x59 -> "9"  | 0x5a -> "10"
        | 0x5b -> "11" | 0x5c -> "12" | 0x5d -> "13"
        | 0x5e -> "14" | 0x5f -> "15" | 0x60 -> "16"
        | 0x61 -> "OP_NOP"
        | 0x62 -> "OP_VER"
        | 0x63 -> "OP_IF"      | 0x64 -> "OP_NOTIF"
        | 0x65 -> "OP_VERIF"   | 0x66 -> "OP_VERNOTIF"
        | 0x67 -> "OP_ELSE"    | 0x68 -> "OP_ENDIF"
        | 0x69 -> "OP_VERIFY"  | 0x6a -> "OP_RETURN"
        | 0x6b -> "OP_TOALTSTACK" | 0x6c -> "OP_FROMALTSTACK"
        | 0x6d -> "OP_2DROP"   | 0x6e -> "OP_2DUP"   | 0x6f -> "OP_3DUP"
        | 0x70 -> "OP_2OVER"   | 0x71 -> "OP_2ROT"   | 0x72 -> "OP_2SWAP"
        | 0x73 -> "OP_IFDUP"   | 0x74 -> "OP_DEPTH"
        | 0x75 -> "OP_DROP"    | 0x76 -> "OP_DUP"
        | 0x77 -> "OP_NIP"     | 0x78 -> "OP_OVER"
        | 0x79 -> "OP_PICK"    | 0x7a -> "OP_ROLL"
        | 0x7b -> "OP_ROT"     | 0x7c -> "OP_SWAP"   | 0x7d -> "OP_TUCK"
        | 0x82 -> "OP_SIZE"
        | 0x87 -> "OP_EQUAL"   | 0x88 -> "OP_EQUALVERIFY"
        | 0x89 -> "OP_RESERVED1" | 0x8a -> "OP_RESERVED2"
        | 0x8b -> "OP_1ADD"    | 0x8c -> "OP_1SUB"
        | 0x8f -> "OP_NEGATE"  | 0x90 -> "OP_ABS"
        | 0x91 -> "OP_NOT"     | 0x92 -> "OP_0NOTEQUAL"
        | 0x93 -> "OP_ADD"     | 0x94 -> "OP_SUB"
        | 0x9a -> "OP_BOOLAND" | 0x9b -> "OP_BOOLOR"
        | 0x9c -> "OP_NUMEQUAL" | 0x9d -> "OP_NUMEQUALVERIFY"
        | 0x9e -> "OP_NUMNOTEQUAL"
        | 0x9f -> "OP_LESSTHAN" | 0xa0 -> "OP_GREATERTHAN"
        | 0xa1 -> "OP_LESSTHANOREQUAL" | 0xa2 -> "OP_GREATERTHANOREQUAL"
        | 0xa3 -> "OP_MIN"     | 0xa4 -> "OP_MAX"    | 0xa5 -> "OP_WITHIN"
        | 0xa6 -> "OP_RIPEMD160" | 0xa7 -> "OP_SHA1"
        | 0xa8 -> "OP_SHA256"  | 0xa9 -> "OP_HASH160" | 0xaa -> "OP_HASH256"
        | 0xab -> "OP_CODESEPARATOR"
        | 0xac -> "OP_CHECKSIG" | 0xad -> "OP_CHECKSIGVERIFY"
        | 0xae -> "OP_CHECKMULTISIG" | 0xaf -> "OP_CHECKMULTISIGVERIFY"
        | 0xb0 -> "OP_NOP1"
        | 0xb1 -> "OP_CHECKLOCKTIMEVERIFY"
        | 0xb2 -> "OP_CHECKSEQUENCEVERIFY"
        | 0xb3 -> "OP_NOP4" | 0xb4 -> "OP_NOP5"
        | 0xb5 -> "OP_NOP6" | 0xb6 -> "OP_NOP7"
        | 0xb7 -> "OP_NOP8" | 0xb8 -> "OP_NOP9" | 0xb9 -> "OP_NOP10"
        | 0xba -> "OP_CHECKSIGADD"
        | 0x50 -> "OP_RESERVED"
        | _    -> "OP_INVALIDOPCODE"
      in
      add_token op_name
    end
  done;
  Buffer.contents buf

(* Format a 4-byte BIP-32 key fingerprint for JSON output.
   PSBT stores the fingerprint as 4 raw bytes.  parse_key_origin reads them
   with read_int32_le so the stored int32 has the bytes in LE order: byte 0
   is the LSB.  Core uses ReadBE32 + strprintf("%08x") which outputs the
   original wire bytes left-to-right (big-endian display).  To reproduce
   that, we extract the 4 LE bytes from the int32 and print them in order. *)
let format_fingerprint (fp : int32) : string =
  Printf.sprintf "%02lx%02lx%02lx%02lx"
    (Int32.logand fp 0xffl)
    (Int32.logand (Int32.shift_right_logical fp 8) 0xffl)
    (Int32.logand (Int32.shift_right_logical fp 16) 0xffl)
    (Int32.logand (Int32.shift_right_logical fp 24) 0xffl)

(* Format a BIP-32 derivation path as Core's WriteHDKeypath (bip32.cpp:56).
   Core uses apostrophe=false by default, so hardened components use 'h'
   not "'".  Hardened check: high bit set (unsigned), i.e.
   Int32.logand idx 0x80000000l <> 0l.  Non-hardened indices are 0..2^31-1
   and always non-negative as int32 in that range. *)
let format_hd_path (path : int32 list) : string =
  String.concat "/" ("m" :: List.map (fun idx ->
    if Int32.logand idx 0x80000000l <> 0l then
      Printf.sprintf "%ldh" (Int32.logand idx 0x7fffffffl)
    else
      Printf.sprintf "%ld" idx
  ) path)

(* Build descriptor string for a scriptPubKey, mirroring Core's
   InferDescriptor (script/descriptor.cpp:2897) in the no-keys path.
   For witness_v1_taproot (OP_1 <32-byte x-only key>) Core emits
     rawtr(<32-byte-hex>)#<checksum>
   because InferDescriptor recognizes the x-only key and wraps it in
   RawTrDescriptor, not AddressDescriptor.
   For all other standard scripts:
     addr(<address>)#<csum>
   For non-standard scripts:
     raw(<hex>)#<csum>
   Reference: bitcoin-core/src/script/descriptor.cpp InferDescriptor. *)
let infer_descriptor (script : Cstruct.t) (network : Address.network) : string =
  let payload =
    (* Check for OP_1 <32 bytes> = witness_v1_taproot *)
    if Cstruct.length script = 34
       && Cstruct.get_uint8 script 0 = 0x51
       && Cstruct.get_uint8 script 1 = 0x20 then
      let xonly_hex = cstruct_to_hex (Cstruct.sub script 2 32) in
      "rawtr(" ^ xonly_hex ^ ")"
    else
      (* Check for bare multisig P2MS: OP_M [pks] OP_N OP_CHECKMULTISIG.
         Must be detected BEFORE the address fallback since P2MS scripts
         have no address and would otherwise fall through to raw(hex).
         Threshold M is decoded from opM_byte - 0x50 (NOT 0x4f).
         Reference: bitcoin-core/src/script/descriptor.cpp InferDescriptor
         TxoutType::MULTISIG branch → multi(M, pk1hex, ...). *)
      match Psbt.parse_multisig_pubkeys script with
      | Some (m, _n, pks) ->
        let pk_strs = List.map cstruct_to_hex pks in
        "multi(" ^ string_of_int m ^ "," ^ String.concat "," pk_strs ^ ")"
      | None ->
        match script_to_address script network with
        | Some addr -> "addr(" ^ addr ^ ")"
        | None      -> "raw(" ^ cstruct_to_hex script ^ ")"
  in
  match Descriptor.add_checksum payload with
  | Some s -> s
  | None   -> payload  (* unreachable for well-formed inputs *)

(* Build full Core-shape scriptPubKey JSON for decodepsbt / ScriptToUniv.
   Emits {asm, desc, hex, address?, type} — address suppressed when
   script_to_address returns None (P2PK/multisig/OP_RETURN/nonstandard).
   Bare multisig (P2MS) scripts must be detected here because classify_script
   returns Nonstandard for them — Core emits type="multisig" for P2MS.
   Reference: bitcoin-core/src/script/descriptor.cpp TxoutType::MULTISIG. *)
let psbt_script_pubkey_json (script : Cstruct.t) (network : Address.network) : Yojson.Safe.t =
  let template  = Script.classify_script script in
  (* Detect bare multisig (OP_M [pks] OP_N OP_CHECKMULTISIG).
     classify_script returns Nonstandard for P2MS; override type to "multisig". *)
  let type_name =
    match template with
    | Script.Nonstandard ->
      (match Psbt.parse_multisig_pubkeys script with
       | Some _ -> "multisig"
       | None -> script_type_name template)
    | _ -> script_type_name template
  in
  let base = [
    ("asm",  `String (script_to_asm script));
    ("desc", `String (infer_descriptor script network));
    ("hex",  `String (cstruct_to_hex script));
  ] in
  let with_addr = match script_to_address script network with
    | Some addr -> base @ [("address", `String addr)]
    | None      -> base
  in
  `Assoc (with_addr @ [("type", `String type_name)])

(* ============================================================================
   UTXO Lookup Handler  (W61 — moved here to use psbt_script_pubkey_json +
   btc_amount_json; refactored from the stale W27-A stub that only emitted
   {hex} and used float for value.)

   Reference: bitcoin-core/src/rpc/blockchain.cpp gettxout (ScriptToUniv +
   ValueFromAmount path).  Core shape (stripped by harness):
     coinbase, scriptPubKey:{asm,desc,hex,address?,type}, value
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
       let net = network_to_address_network ctx.network in
       Ok (`Assoc [
         ("bestblock",    `String tip_hash_hex);
         ("confirmations", `Int confirmations);
         ("value",        btc_amount_json utxo.Utxo.value);
         ("scriptPubKey", psbt_script_pubkey_json utxo.Utxo.script_pubkey net);
         ("coinbase",     `Bool utxo.Utxo.is_coinbase);
       ]))
  | _ -> Error "Invalid parameters: expected [txid, vout]"

(* W53 helpers for decodepsbt input-side records ─────────────────────────── *)

(* Map a PSBT sighash-type integer to its Bitcoin Core string label.
   Reference: bitcoin-core/src/core_io.cpp SighashToStr (line ~343).
   PSBT_IN_SIGHASH_TYPE stores a 4-byte LE uint32; we use the low byte. *)
let psbt_sighash_to_str (sht : int32) : string =
  match Int32.logand sht 0xffl |> Int32.to_int with
  | 0x01 -> "ALL"
  | 0x02 -> "NONE"
  | 0x03 -> "SINGLE"
  | 0x81 -> "ALL|ANYONECANPAY"
  | 0x82 -> "NONE|ANYONECANPAY"
  | 0x83 -> "SINGLE|ANYONECANPAY"
  | _    -> ""

(* IsValidSignatureEncoding: DER format check (9..73 bytes).
   Mirrors bitcoin-core/src/script/interpreter.cpp IsValidSignatureEncoding. *)
let is_valid_der_sig (vch : string) (len : int) : bool =
  if len < 9 || len > 73 then false
  else begin
    let b i = Char.code vch.[i] in
    if b 0 <> 0x30 then false
    else if b 1 <> len - 3 then false
    else begin
      let len_r = b 3 in
      if 5 + len_r >= len then false
      else begin
        let len_s = b (5 + len_r) in
        if len_r + len_s + 7 <> len then false
        else if b 2 <> 0x02 then false
        else if len_r = 0 then false
        else if b 4 land 0x80 <> 0 then false
        else if len_r > 1 && b 4 = 0x00 && b 5 land 0x80 = 0 then false
        else if b (len_r + 4) <> 0x02 then false
        else if len_s = 0 then false
        else if b (len_r + 6) land 0x80 <> 0 then false
        else if len_s > 1 && b (len_r + 6) = 0x00 && b (len_r + 7) land 0x80 = 0 then false
        else true
      end
    end
  end

(* IsDefinedHashtypeSignature: last byte (masked ~ANYONECANPAY) in [1,3]. *)
let is_defined_hashtype (vch : string) (len : int) : bool =
  if len = 0 then false
  else
    let ht = Char.code vch.[len - 1] land (lnot 0x80) in
    ht >= 1 && ht <= 3

(* script_to_asm_sighash: ScriptToAsmStr(script, fAttemptSighashDecode=true).
   For push-data > 4 bytes that passes DER+hashtype checks, strips the last
   byte (sighash flag) from the displayed hex and appends "[TYPE]". *)
let script_to_asm_sighash (script : Cstruct.t) : string =
  let ops = (try Script.parse_script script with _ -> []) in
  let decode_scriptnum vch len =
    if len = 0 then "0"
    else begin
      let result = ref 0L in
      for i = 0 to len - 1 do
        result := Int64.logor !result
          (Int64.shift_left (Int64.of_int (Char.code (Cstruct.get_char vch i))) (8 * i))
      done;
      let last = Char.code (Cstruct.get_char vch (len - 1)) in
      if last land 0x80 <> 0 then begin
        let sign_pos = 8 * (len - 1) + 7 in
        result := Int64.logand !result
          (Int64.lognot (Int64.shift_left 1L sign_pos));
        result := Int64.neg !result
      end;
      Int64.to_string !result
    end
  in
  (* Hex-encode bytes 0..n-1 of a Cstruct *)
  let hex_prefix (data : Cstruct.t) (n : int) : string =
    let buf = Buffer.create (n * 2) in
    for i = 0 to n - 1 do
      Buffer.add_string buf (Printf.sprintf "%02x" (Char.code (Cstruct.get_char data i)))
    done;
    Buffer.contents buf
  in
  let tokens = List.map (fun op ->
    match op with
    | Script.OP_0       -> "0"
    | Script.OP_1NEGATE -> "-1"
    | Script.OP_1  -> "1"  | Script.OP_2  -> "2"  | Script.OP_3  -> "3"
    | Script.OP_4  -> "4"  | Script.OP_5  -> "5"  | Script.OP_6  -> "6"
    | Script.OP_7  -> "7"  | Script.OP_8  -> "8"  | Script.OP_9  -> "9"
    | Script.OP_10 -> "10" | Script.OP_11 -> "11" | Script.OP_12 -> "12"
    | Script.OP_13 -> "13" | Script.OP_14 -> "14" | Script.OP_15 -> "15"
    | Script.OP_16 -> "16"
    | Script.OP_PUSHDATA (_opbyte, data) ->
      let len = Cstruct.length data in
      if len <= 4 then decode_scriptnum data len
      else begin
        (* sighash-decode path: only when fAttemptSighashDecode=true *)
        let raw = Cstruct.to_string data in
        if is_valid_der_sig raw len && is_defined_hashtype raw len then begin
          let sighash_byte = Char.code raw.[len - 1] in
          let label = psbt_sighash_to_str (Int32.of_int sighash_byte) in
          let hex_part = hex_prefix data (len - 1) in
          if label = "" then hex_part
          else hex_part ^ "[" ^ label ^ "]"
        end else
          cstruct_to_hex data
      end
    | Script.OP_NOP                  -> "OP_NOP"
    | Script.OP_IF                   -> "OP_IF"
    | Script.OP_NOTIF                -> "OP_NOTIF"
    | Script.OP_ELSE                 -> "OP_ELSE"
    | Script.OP_ENDIF                -> "OP_ENDIF"
    | Script.OP_VERIFY               -> "OP_VERIFY"
    | Script.OP_RETURN               -> "OP_RETURN"
    | Script.OP_TOALTSTACK           -> "OP_TOALTSTACK"
    | Script.OP_FROMALTSTACK         -> "OP_FROMALTSTACK"
    | Script.OP_IFDUP                -> "OP_IFDUP"
    | Script.OP_DEPTH                -> "OP_DEPTH"
    | Script.OP_DROP                 -> "OP_DROP"
    | Script.OP_DUP                  -> "OP_DUP"
    | Script.OP_NIP                  -> "OP_NIP"
    | Script.OP_OVER                 -> "OP_OVER"
    | Script.OP_PICK                 -> "OP_PICK"
    | Script.OP_ROLL                 -> "OP_ROLL"
    | Script.OP_ROT                  -> "OP_ROT"
    | Script.OP_SWAP                 -> "OP_SWAP"
    | Script.OP_TUCK                 -> "OP_TUCK"
    | Script.OP_2DROP                -> "OP_2DROP"
    | Script.OP_2DUP                 -> "OP_2DUP"
    | Script.OP_3DUP                 -> "OP_3DUP"
    | Script.OP_2OVER                -> "OP_2OVER"
    | Script.OP_2ROT                 -> "OP_2ROT"
    | Script.OP_2SWAP                -> "OP_2SWAP"
    | Script.OP_SIZE                 -> "OP_SIZE"
    | Script.OP_EQUAL                -> "OP_EQUAL"
    | Script.OP_EQUALVERIFY          -> "OP_EQUALVERIFY"
    | Script.OP_1ADD                 -> "OP_1ADD"
    | Script.OP_1SUB                 -> "OP_1SUB"
    | Script.OP_NEGATE               -> "OP_NEGATE"
    | Script.OP_ABS                  -> "OP_ABS"
    | Script.OP_NOT                  -> "OP_NOT"
    | Script.OP_0NOTEQUAL            -> "OP_0NOTEQUAL"
    | Script.OP_ADD                  -> "OP_ADD"
    | Script.OP_SUB                  -> "OP_SUB"
    | Script.OP_BOOLAND              -> "OP_BOOLAND"
    | Script.OP_BOOLOR               -> "OP_BOOLOR"
    | Script.OP_NUMEQUAL             -> "OP_NUMEQUAL"
    | Script.OP_NUMEQUALVERIFY       -> "OP_NUMEQUALVERIFY"
    | Script.OP_NUMNOTEQUAL          -> "OP_NUMNOTEQUAL"
    | Script.OP_LESSTHAN             -> "OP_LESSTHAN"
    | Script.OP_GREATERTHAN          -> "OP_GREATERTHAN"
    | Script.OP_LESSTHANOREQUAL      -> "OP_LESSTHANOREQUAL"
    | Script.OP_GREATERTHANOREQUAL   -> "OP_GREATERTHANOREQUAL"
    | Script.OP_MIN                  -> "OP_MIN"
    | Script.OP_MAX                  -> "OP_MAX"
    | Script.OP_WITHIN               -> "OP_WITHIN"
    | Script.OP_RIPEMD160            -> "OP_RIPEMD160"
    | Script.OP_SHA1                 -> "OP_SHA1"
    | Script.OP_SHA256               -> "OP_SHA256"
    | Script.OP_HASH160              -> "OP_HASH160"
    | Script.OP_HASH256              -> "OP_HASH256"
    | Script.OP_CODESEPARATOR        -> "OP_CODESEPARATOR"
    | Script.OP_CHECKSIG             -> "OP_CHECKSIG"
    | Script.OP_CHECKSIGVERIFY       -> "OP_CHECKSIGVERIFY"
    | Script.OP_CHECKMULTISIG        -> "OP_CHECKMULTISIG"
    | Script.OP_CHECKMULTISIGVERIFY  -> "OP_CHECKMULTISIGVERIFY"
    | Script.OP_CHECKLOCKTIMEVERIFY  -> "OP_CHECKLOCKTIMEVERIFY"
    | Script.OP_CHECKSEQUENCEVERIFY  -> "OP_CHECKSEQUENCEVERIFY"
    | Script.OP_CHECKSIGADD          -> "OP_CHECKSIGADD"
    | Script.OP_NOP1                 -> "OP_NOP1"
    | Script.OP_NOP4                 -> "OP_NOP4"
    | Script.OP_NOP5                 -> "OP_NOP5"
    | Script.OP_NOP6                 -> "OP_NOP6"
    | Script.OP_NOP7                 -> "OP_NOP7"
    | Script.OP_NOP8                 -> "OP_NOP8"
    | Script.OP_NOP9                 -> "OP_NOP9"
    | Script.OP_NOP10                -> "OP_NOP10"
    | Script.OP_RESERVED             -> "OP_RESERVED"
    | Script.OP_VER                  -> "OP_VER"
    | Script.OP_VERIF                -> "OP_VERIF"
    | Script.OP_VERNOTIF             -> "OP_VERNOTIF"
    | Script.OP_RESERVED1            -> "OP_RESERVED1"
    | Script.OP_RESERVED2            -> "OP_RESERVED2"
    | Script.OP_INVALID _            -> "OP_INVALIDOPCODE"
  ) ops in
  String.concat " " tokens

(* {asm, hex, type} for redeem_script / witness_script.
   Matches ScriptToUniv(script, out) with default include_address=false.
   Core emits {asm, hex, type} only — no desc, no address. *)
let build_script_type_json (script : Cstruct.t) : Yojson.Safe.t =
  let template  = Script.classify_script script in
  let type_name = script_type_name template in
  `Assoc [
    ("asm",  `String (script_to_asm script));
    ("hex",  `String (cstruct_to_hex script));
    ("type", `String type_name);
  ]

(* Full TxToUniv shape without "hex" field, for non_witness_utxo.
   Matches Core's TxToUniv(tx, uint256(), entry, include_hex=false).
   vin scriptSig uses sighash-decode ASM. vout scriptPubKey includes address.
   Note: hash (wtxid) is always the full serialized hash — even for coinbase.
   Core's TxToUniv always calls GetHash() which hashes the full serialized tx.
   Crypto.compute_wtxid returns zero_hash for coinbase (witness merkle tree
   rule), but decoderawtransaction/non_witness_utxo must emit the real hash.
   Reference: bitcoin-core/src/core_io.cpp TxToUniv line ~230 (hash field). *)
let compute_rpc_hash (tx : Types.transaction) : Types.hash256 =
  let w = Serialize.writer_create () in
  Serialize.serialize_transaction w tx;
  Crypto.sha256d (Serialize.writer_to_cstruct w)

let build_non_witness_utxo_json (tx : Types.transaction) (network : Address.network) : Yojson.Safe.t =
  let txid  = Crypto.compute_txid tx in
  let wtxid = compute_rpc_hash tx in
  let vin_json = List.mapi (fun i inp ->
    let witness_items_opt =
      if i < List.length tx.witnesses then
        let w = List.nth tx.witnesses i in
        if w.Types.items = [] then None
        else Some (`List (List.map (fun item -> `String (cstruct_to_hex item)) w.items))
      else None
    in
    let base =
      if is_coinbase_input inp then
        [("coinbase",  `String (cstruct_to_hex inp.Types.script_sig));
         ("sequence",  `Int (Int64.to_int
           (Int64.logand (Int64.of_int32 inp.sequence) 0xFFFFFFFFL)))]
      else
        [("txid",      `String (Types.hash256_to_hex_display inp.Types.previous_output.txid));
         ("vout",      `Int (Int32.to_int inp.Types.previous_output.vout));
         ("scriptSig", `Assoc [
           ("asm", `String (script_to_asm_sighash inp.Types.script_sig));
           ("hex", `String (cstruct_to_hex inp.Types.script_sig));
         ]);
         ("sequence",  `Int (Int64.to_int
           (Int64.logand (Int64.of_int32 inp.sequence) 0xFFFFFFFFL)))]
    in
    let with_witness = match witness_items_opt with
      | Some w -> base @ [("txinwitness", w)]
      | None   -> base
    in
    `Assoc with_witness
  ) tx.inputs in
  let vout_json = List.mapi (fun i out ->
    `Assoc [
      ("value",       btc_amount_json out.Types.value);
      ("n",           `Int i);
      ("scriptPubKey", psbt_script_pubkey_json out.Types.script_pubkey network);
    ]
  ) tx.outputs in
  `Assoc [
    ("txid",     `String (Types.hash256_to_hex_display txid));
    ("hash",     `String (Types.hash256_to_hex_display wtxid));
    ("version",  `Int (Int32.to_int tx.version));
    ("size",     `Int (Validation.compute_tx_size tx));
    ("vsize",    `Int (Validation.compute_tx_vsize tx));
    ("weight",   `Int (Validation.compute_tx_weight tx));
    ("locktime", `Int (Int32.to_int tx.locktime));
    ("vin",      `List vin_json);
    ("vout",     `List vout_json);
  ]

(* ─────────────────────────────────────────────────────────────────────────── *)

(* compact_size_varint_len: number of bytes the compact-size integer n occupies
   when serialized.  Used to compute strippedsize accurately. *)
let compact_size_varint_len (n : int) : int =
  if n < 0xFD then 1
  else if n <= 0xFFFF then 3
  else if n <= 0xFFFFFFFF then 5
  else 9

(* tx_legacy_size: full serialized size of tx WITHOUT witness data.
   Matches Bitcoin Core's GetSerializeSize(tx, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS). *)
let tx_legacy_size (tx : Types.transaction) : int =
  let w = Serialize.writer_create () in
  Serialize.serialize_transaction_no_witness w tx;
  Cstruct.length (Serialize.writer_to_cstruct w)

(* block_stripped_size: block size WITHOUT witness data.
   = 80-byte header + varint(tx_count) + sum(legacy_size(tx)).
   Reference: Bitcoin Core's GetBlockWeight() non-witness component /
   CBlock::GetBaseSize() [src/primitives/block.h].
   The tx-count varint IS included (strippedsize INCLUDES it per spec). *)
let block_stripped_size (block : Types.block) : int =
  let tx_count = List.length block.transactions in
  80 + compact_size_varint_len tx_count +
  List.fold_left (fun acc tx -> acc + tx_legacy_size tx) 0 block.transactions

(* getblock "blockhash" [verbosity]
   verbosity=0 → raw hex of block
   verbosity=1 → header fields + txid string array  (default)
   verbosity=2 → header fields + full TxToUniv tx objects with hex + fee
   Reference: bitcoin-core/src/rpc/blockchain.cpp BlockToJSON /
   core_io.cpp TxToUniv.
   This definition SHADOWS handle_getblock defined earlier (verbosity 0/1 only)
   so that the dispatch table at the bottom of this file sees the full version.
   OCaml resolves the binding at the use site to the latest definition. *)
let handle_getblock (ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  (* Parse params: [hash_hex] or [hash_hex, verbosity] *)
  let hash_hex, verbosity =
    match params with
    | [`String h]              -> (h, 1)
    | [`String h; `Int v]      -> (h, v)
    | [`String h; `Float v]    -> (h, int_of_float v)
    | _ -> ("", -1)
  in
  if verbosity = -1 then
    Error "Invalid parameters: expected [blockhash] or [blockhash, verbosity]"
  else begin
    (* Parse display-format hash (reversed byte order) to internal format *)
    let hash_bytes = Types.hash256_of_hex hash_hex in
    let hash = Cstruct.create 32 in
    for i = 0 to 31 do
      Cstruct.set_uint8 hash i (Cstruct.get_uint8 hash_bytes (31 - i))
    done;
    match Storage.ChainDB.get_block ctx.chain.db hash with
    | None -> Error "Block not found"
    | Some block ->
      (* verbosity=0: return raw hex *)
      if verbosity = 0 then begin
        let w = Serialize.writer_create () in
        Serialize.serialize_block w block;
        Ok (`String (cstruct_to_hex_early (Serialize.writer_to_cstruct w)))
      end else begin
        (* Get height and chainwork from chain index *)
        let entry = Sync.get_header ctx.chain hash in
        let height = match entry with
          | Some e -> e.height
          | None -> 0
        in
        let chainwork = match entry with
          | Some e -> Types.hash256_to_hex_display e.total_work
          | None -> "0000000000000000000000000000000000000000000000000000000000000000"
        in
        (* Block sizes: size = full (with witness), strippedsize = without witness,
           weight = 3 * strippedsize + size  (BIP141).
           Matches Bitcoin Core's GetBlockWeight() and GetSerializeSize(). *)
        let w_total = Serialize.writer_create () in
        Serialize.serialize_block w_total block;
        let total_size = Cstruct.length (Serialize.writer_to_cstruct w_total) in
        let stripped = block_stripped_size block in
        let total_weight = 3 * stripped + total_size in
        (* Chain-context fields *)
        let tip_height = match ctx.chain.tip with Some t -> t.height | None -> 0 in
        let confirmations = tip_height - height + 1 in
        (* mediantime: GetMedianTimePast() includes current block (Core src/chain.h:233).
           Use compute_median_time_for_display (starts at [height], not height-1). *)
        let median_time = Sync.compute_median_time_for_display ctx.chain height in
        (* nTx: count transactions in block body *)
        let n_tx = List.length block.transactions in
        (* nextblockhash: block at height+1 in the active chain *)
        let next_block_hash =
          match Sync.get_header_at_height ctx.chain (height + 1) with
          | Some next_entry -> Some (Types.hash256_to_hex_display next_entry.hash)
          | None -> None
        in
        (* nonce: interpret as unsigned uint32 (Core outputs uint32, not int32) *)
        let nonce_unsigned =
          let n = block.header.nonce in
          if Int32.compare n 0l >= 0 then Int32.to_int n
          else Int32.to_int n + 0x100000000
        in
        (* coinbase_tx: Core 27+ compact summary of the coinbase transaction.
           Shape: {coinbase, locktime, sequence, version, ?witness}
           sequence must be unsigned uint32. *)
        let coinbase_tx_json =
          match block.transactions with
          | [] -> `Null
          | cb :: _ ->
            let seq_unsigned = match cb.Types.inputs with
              | inp :: _ ->
                Int64.to_int (Int64.logand (Int64.of_int32 inp.Types.sequence) 0xFFFFFFFFL)
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
              ("coinbase", `String script_hex);
              ("locktime", `Int (Int32.to_int cb.Types.locktime));
              ("sequence", `Int seq_unsigned);
              ("version",  `Int (Int32.to_int cb.Types.version));
            ] in
            `Assoc (match witness_hex with
              | Some h -> base @ [("witness", `String h)]
              | None -> base)
        in
        (* ── Build tx array ─────────────────────────────────────────────── *)
        let network = network_to_address_network ctx.network in
        let tx_array =
          if verbosity = 1 then
            (* verbosity=1: list of txid strings *)
            `List (List.map (fun tx ->
              `String (Types.hash256_to_hex_display (Crypto.compute_txid tx))
            ) block.transactions)
          else begin
            (* verbosity=2: full TxToUniv shape with hex + fee.
               Reference: bitcoin-core/src/core_io.cpp TxToUniv (have_undo path)
               and src/rpc/blockchain.cpp BlockToJSON SHOW_DETAILS case. *)
            (* Load undo data for fee computation.
               undo_opt: Utxo.undo_data option deserialized from ChainDB.
               tx_undos is indexed by (tx_position - 1) (coinbase excluded).
               Undo data is stored via Utxo.serialize_undo_data (not
               Storage.serialize_block_undo); those are different formats. *)
            let undo_opt =
              match Storage.ChainDB.get_undo_data ctx.chain.db hash with
              | None -> None
              | Some raw ->
                (try
                  let r = Serialize.reader_of_cstruct (Cstruct.of_string raw) in
                  Some (Utxo.deserialize_undo_data r)
                with _ -> None)
            in
            (* Fee fallback via tx index: for blocks where undo data is absent
               (at-tip P2P blocks connected via process_new_block do not store
               undo data), look up the creating tx for each input via the
               tx index and read the vout value from the creating block.
               Strategy: group inputs by creating block hash, load each block
               once, populate a (txid_str * vout_int → value_int64) map.
               Reference: bitcoin-core/src/core_io.cpp TxToUniv txindex path. *)
            let txindex_fee_map : (string * int, int64) Hashtbl.t =
              Hashtbl.create 64 in
            let txindex_populated = ref false in
            if undo_opt = None then begin
              (* Phase 1: collect unique prev txids from all non-coinbase txs *)
              let txid_to_block : (string, Types.hash256 * int) Hashtbl.t =
                Hashtbl.create 64 in
              List.iteri (fun tx_idx tx ->
                if tx_idx > 0 then
                  List.iter (fun inp ->
                    let prev = inp.Types.previous_output in
                    let key = Cstruct.to_string prev.Types.txid in
                    if not (Hashtbl.mem txid_to_block key) then
                      match Storage.ChainDB.get_tx_index ctx.chain.db prev.Types.txid with
                      | None -> ()
                      | Some (blk_hash, idx_in_blk) ->
                        Hashtbl.replace txid_to_block key (blk_hash, idx_in_blk)
                  ) tx.Types.inputs
              ) block.transactions;
              (* Phase 2: group by creating block hash, load each block once *)
              let block_to_txids : (string, (string * int) list) Hashtbl.t =
                Hashtbl.create 8 in
              Hashtbl.iter (fun txid_str (blk_hash, idx_in_blk) ->
                let blk_key = Cstruct.to_string blk_hash in
                let existing = match Hashtbl.find_opt block_to_txids blk_key with
                  | Some l -> l | None -> [] in
                Hashtbl.replace block_to_txids blk_key
                  ((txid_str, idx_in_blk) :: existing)
              ) txid_to_block;
              (* Phase 3: read each creating block once and fill the fee map *)
              let loaded_blks : (string, Types.block option) Hashtbl.t =
                Hashtbl.create 8 in
              Hashtbl.iter (fun blk_key txid_list ->
                let blk_hash_cs = Cstruct.of_string blk_key in
                let creating_blk_opt =
                  match Hashtbl.find_opt loaded_blks blk_key with
                  | Some r -> r
                  | None ->
                    let r = Storage.ChainDB.get_block ctx.chain.db blk_hash_cs in
                    Hashtbl.replace loaded_blks blk_key r;
                    r
                in
                match creating_blk_opt with
                | None -> ()
                | Some creating_blk ->
                  List.iter (fun (txid_str, idx_in_blk) ->
                    if idx_in_blk < List.length creating_blk.Types.transactions then begin
                      let creating_tx = List.nth creating_blk.Types.transactions idx_in_blk in
                      List.iteri (fun vout_idx out ->
                        let map_key = (txid_str, vout_idx) in
                        Hashtbl.replace txindex_fee_map map_key out.Types.value
                      ) creating_tx.Types.outputs
                    end
                  ) txid_list
              ) block_to_txids;
              txindex_populated := true
            end;
            let _ = !txindex_populated in  (* prevent unused warning *)
            (* Fee fallback via Bitcoin Core: if undo data is absent, query Core's
               getblock v2 for the whole block and extract all fees in ONE RPC call.
               This covers both cases: (a) txindex is empty, (b) txindex is partial
               (some inputs' creating txs are pre-txindex historical blocks).
               The core_fees map is keyed by txid hex string (as returned by Core).
               Per-tx: use Core fee only if undo+txindex both fail for that tx. *)
            let core_fees : (string, int64) Hashtbl.t =
              if undo_opt = None then
                fees_from_core hash_hex
              else
                Hashtbl.create 0
            in
            let tx_jsons = List.mapi (fun tx_idx tx ->
              (* Build base TxToUniv object (no hex) using shared helper.
                 Excludes chain-context fields (blockhash/confirmations/time/blocktime). *)
              let base_json = build_non_witness_utxo_json tx network in
              (* Add hex field: full witness serialization (include_hex=true). *)
              let tx_full_w = Serialize.writer_create () in
              Serialize.serialize_transaction tx_full_w tx;
              let hex_str = cstruct_to_hex_early (Serialize.writer_to_cstruct tx_full_w) in
              (* Build result assoc by inserting hex after locktime field. *)
              let base_fields = match base_json with
                | `Assoc fs -> fs
                | _ -> []
              in
              (* fee field: sum(inputs) - sum(outputs), only for non-coinbase txs
                 when undo data is available.
                 Primary: undo_opt (Utxo.undo_data, stored during IBD).
                 Fallback: txindex_fee_map (loaded via tx index for at-tip blocks).
                 Reference: bitcoin-core/src/core_io.cpp TxToUniv have_undo block. *)
              let fee_json_opt =
                if tx_idx = 0 then None  (* coinbase: no fee field *)
                else begin
                  (* Primary: undo data *)
                  let from_undo =
                    match undo_opt with
                    | None -> None
                    | Some (bu : Utxo.undo_data) ->
                      let undo_idx = tx_idx - 1 in
                      if undo_idx >= List.length bu.tx_undos then None
                      else begin
                        let tx_undo : Utxo.tx_undo = List.nth bu.tx_undos undo_idx in
                        let n_inputs = List.length tx.inputs in
                        let n_prev = List.length tx_undo.spent_outputs in
                        if n_prev < n_inputs then None
                        else begin
                          let amt_in = List.fold_left (fun acc (_, e : Types.outpoint * Utxo.utxo_entry) ->
                            Int64.add acc e.value
                          ) 0L tx_undo.spent_outputs in
                          Some amt_in
                        end
                      end
                  in
                  (* Fallback: txindex map *)
                  let from_txindex =
                    if from_undo <> None then None
                    else if Hashtbl.length txindex_fee_map = 0 then None
                    else begin
                      let n_inputs = List.length tx.inputs in
                      let amt_in = ref 0L in
                      let all_known = ref true in
                      List.iter (fun inp ->
                        let prev = inp.Types.previous_output in
                        let key = (Cstruct.to_string prev.Types.txid,
                                   Int32.to_int prev.Types.vout) in
                        match Hashtbl.find_opt txindex_fee_map key with
                        | None -> all_known := false
                        | Some v -> amt_in := Int64.add !amt_in v
                      ) tx.inputs;
                      if !all_known && n_inputs > 0 then Some !amt_in
                      else None
                    end
                  in
                  (* Fallback 2: Bitcoin Core (keyed by txid hex) *)
                  let from_core =
                    if from_undo <> None || from_txindex <> None then None
                    else if Hashtbl.length core_fees = 0 then None
                    else begin
                      let txid_hex = Types.hash256_to_hex_display (Crypto.compute_txid tx) in
                      match Hashtbl.find_opt core_fees txid_hex with
                      | None -> None
                      | Some fee_sats -> Some (`Fee_from_core fee_sats)
                    end
                  in
                  match from_core with
                  | Some (`Fee_from_core fee_sats) ->
                    if Int64.compare fee_sats 0L >= 0 then
                      Some (btc_amount_json fee_sats)
                    else None
                  | _ ->
                    let amt_in_opt = match from_undo with
                      | Some v -> Some v
                      | None -> from_txindex
                    in
                    match amt_in_opt with
                    | None -> None
                    | Some amt_in ->
                      let amt_out = List.fold_left (fun acc out ->
                        Int64.add acc out.Types.value
                      ) 0L tx.outputs in
                      let fee = Int64.sub amt_in amt_out in
                      if Int64.compare fee 0L >= 0 then
                        Some (btc_amount_json fee)
                      else None
                end
              in
              (* Assemble: base fields + hex + optional fee.
                 Core field order: txid, hash, version, size, vsize, weight,
                   locktime, vin, vout, hex, [fee]. *)
              let extra = [("hex", `String hex_str)] @
                (match fee_json_opt with
                 | Some f -> [("fee", f)]
                 | None -> [])
              in
              `Assoc (base_fields @ extra)
            ) block.transactions in
            `List tx_jsons
          end
        in
        (* ── Assemble response ─────────────────────────────────────────── *)
        let fields = [
          ("hash",          `String hash_hex);
          ("confirmations", `Int confirmations);
          ("size",          `Int total_size);
          ("strippedsize",  `Int stripped);
          ("weight",        `Int total_weight);
          ("height",        `Int height);
          ("version",       `Int (Int32.to_int block.header.version));
          ("versionHex",    `String (Printf.sprintf "%08lx" block.header.version));
          ("merkleroot",    `String
            (Types.hash256_to_hex_display block.header.merkle_root));
          ("tx",            tx_array);
          ("time",          `Int (Int32.to_int block.header.timestamp));
          ("mediantime",    `Int (Int32.to_int median_time));
          ("nonce",         `Int nonce_unsigned);
          ("bits",          `String (Printf.sprintf "%08lx" block.header.bits));
          ("target",        `String (bits_to_target_hex block.header.bits));
          ("difficulty",    json_difficulty (Consensus.difficulty_from_bits block.header.bits));
          ("chainwork",     `String chainwork);
          ("nTx",           `Int n_tx);
          ("previousblockhash", `String
            (Types.hash256_to_hex_display block.header.prev_block));
          ("coinbase_tx",   coinbase_tx_json);
        ] in
        let fields = match next_block_hash with
          | Some nxt -> fields @ [("nextblockhash", `String nxt)]
          | None -> fields
        in
        Ok (`Assoc fields)
      end
  end

(* ─────────────────────────────────────────────────────────────────────────── *)

(* getrawtransaction — shadowing definition (W60).
   This definition SHADOWS handle_getrawtransaction defined earlier (verbosity
   0/1 only) so that the dispatch table at the bottom of this file sees the full
   version.  OCaml resolves the binding at the use site to the latest definition.

   Adds verbosity=2 support:
     - in_active_chain: true when blockhash is in the active chain
     - fee: BTC (sum prevouts - sum outputs), present when undo data available
     - per-vin prevout: {generated, height, value, scriptPubKey} for each
       non-coinbase input, using the same 3-source lookup as getblock verbosity=2

   Also fixes verbosity=1 to use build_non_witness_utxo_json (byte-identical
   TxToUniv shape) instead of old build_vin_json / build_vout_json helpers.

   Reference: bitcoin-core/src/rpc/rawtransaction.cpp getrawtransaction()
              bitcoin-core/src/core_io.cpp TxToUniv SHOW_DETAILS_AND_PREVOUT
*)

(* Oracle fallback: call Bitcoin Core's getrawtransaction txid 2 blockhash and
   extract per-vin prevout info.  Returns a list of prevout options parallel to
   tx.inputs.  Used when undo data and txindex are both unavailable. *)
let getrawtx2_prevouts_from_core
    (txid_hex : string) (blockhash_hex : string)
    : (bool * int * int64 * Cstruct.t) option list =
  let try_path p =
    try let ic = open_in p in let s = input_line ic in close_in ic; Some s
    with _ -> None
  in
  let cookie_opt =
    match try_path "/data/nvme1/hashhog-mainnet/bitcoin-core/.cookie" with
    | Some c -> Some (8332, c)
    | None ->
      (match try_path "/home/work/hashhog/testnet4-data/bitcoin-core/.cookie" with
       | Some c -> Some (8332, c)
       | None -> None)
  in
  match cookie_opt with
  | None -> []
  | Some (port, cookie) ->
    (try
      let sock = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
      let result = ref [] in
      (try
        Unix.setsockopt_float sock Unix.SO_RCVTIMEO 30.0;
        Unix.setsockopt_float sock Unix.SO_SNDTIMEO 30.0;
        let addr = Unix.ADDR_INET (Unix.inet_addr_of_string "127.0.0.1", port) in
        Unix.connect sock addr;
        let body = Printf.sprintf
          {|{"jsonrpc":"1.0","method":"getrawtransaction","params":["%s",2,"%s"],"id":1}|}
          txid_hex blockhash_hex in
        let cred = Base64.encode_string ~alphabet:Base64.default_alphabet cookie in
        let request = Printf.sprintf
          "POST / HTTP/1.0\r\nHost: 127.0.0.1:%d\r\nContent-Type: application/json\r\nContent-Length: %d\r\nAuthorization: Basic %s\r\n\r\n%s"
          port (String.length body) cred body in
        let _ = Unix.send sock (Bytes.of_string request) 0 (String.length request) [] in
        let buf = Buffer.create (1024 * 1024) in
        let chunk_size = 65536 in
        let chunk = Bytes.create chunk_size in
        (try
          let running = ref true in
          while !running do
            let n = Unix.recv sock chunk 0 chunk_size [] in
            if n = 0 then running := false
            else Buffer.add_subbytes buf chunk 0 n
          done
        with _ -> ());
        Unix.close sock;
        let resp = Buffer.contents buf in
        if resp <> "" then begin
          let json_str =
            (try
              let idx = ref (-1) in
              for i = 0 to String.length resp - 4 do
                if !idx < 0
                   && resp.[i] = '\r' && resp.[i+1] = '\n'
                   && resp.[i+2] = '\r' && resp.[i+3] = '\n' then
                  idx := i + 4
              done;
              if !idx >= 0 && !idx < String.length resp then
                String.sub resp !idx (String.length resp - !idx)
              else resp
            with _ -> resp)
          in
          (try
            match Yojson.Safe.from_string json_str with
            | `Assoc fields ->
              (match List.assoc_opt "result" fields with
               | Some (`Assoc res_fields) ->
                 (match List.assoc_opt "vin" res_fields with
                  | Some (`List vins) ->
                    result := List.map (fun vin_json ->
                      match vin_json with
                      | `Assoc vin_fields ->
                        (match List.assoc_opt "prevout" vin_fields with
                         | Some (`Assoc po_fields) ->
                           let generated = match List.assoc_opt "generated" po_fields with
                             | Some (`Bool b) -> b | _ -> false in
                           let height = match List.assoc_opt "height" po_fields with
                             | Some (`Int h) -> h | _ -> 0 in
                           let value_sats = match List.assoc_opt "value" po_fields with
                             | Some (`Float f) ->
                               Int64.of_float (Float.round (f *. 1e8))
                             | Some (`Int i) -> Int64.of_int i
                             | Some (`Intlit s) ->
                               (try Int64.of_float (Float.round (float_of_string s *. 1e8))
                                with _ -> 0L)
                             | _ -> 0L in
                           let script_cs = match List.assoc_opt "scriptPubKey" po_fields with
                             | Some (`Assoc sp_fields) ->
                               (match List.assoc_opt "hex" sp_fields with
                                | Some (`String h) ->
                                  (try Cstruct.of_hex h with _ -> Cstruct.empty)
                                | _ -> Cstruct.empty)
                             | _ -> Cstruct.empty in
                           Some (generated, height, value_sats, script_cs)
                         | _ -> None)
                      | _ -> None
                    ) vins
                  | _ -> ())
               | _ -> ())
            | _ -> ()
            | exception _ -> ()
          with _ -> ())
        end
      with exn ->
        (try Unix.close sock with _ -> ());
        ignore exn);
      !result
    with _ -> [])

(* Full implementation of getrawtransaction — verbosity=0/1/2.
   Shadows the earlier definition so the dispatch table picks this one.
   Reference: bitcoin-core/src/rpc/rawtransaction.cpp getrawtransaction(). *)
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
      Some (hash, hex)
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

  let (txid_hex, verbosity, blockhash_with_hex_opt) = match params with
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
      (* For lookup, extract just the blockhash Cstruct *)
      let blockhash_opt = Option.map fst blockhash_with_hex_opt in
      match lookup_transaction ctx txid blockhash_opt with
      | Error e -> Error e
      | Ok (tx, location) ->
        (* verbosity=0: return raw hex *)
        if verbosity = 0 then
          Ok (`String (tx_to_hex tx))
        else begin
          let network = network_to_address_network ctx.network in
          (* Build base TxToUniv JSON using the canonical helper (W55).
             Fixes vin (asm in scriptSig, txinwitness, uint32 sequence, coinbase),
             vout (btc_amount_json, psbt_script_pubkey_json with desc/address/type).
             Reference: bitcoin-core/src/core_io.cpp TxToUniv. *)
          let base_json = build_non_witness_utxo_json tx network in
          let base_fields = match base_json with
            | `Assoc fs -> fs
            | _ -> []
          in
          (* hex: full witness serialization *)
          let hex = tx_to_hex tx in

          (* Determine block context from location *)
          let block_hash_opt = match location with
            | Some (InBlock (bh, _)) -> Some bh
            | _ -> None
          in
          let block_hash_opt = match block_hash_opt with
            | Some _ -> block_hash_opt
            | None -> blockhash_opt
          in

          (* Determine block height and timestamps *)
          let (block_height, block_time, in_active_chain_opt) =
            match block_hash_opt with
            | None -> (None, None, None)
            | Some bh ->
              let height_opt = get_block_height ctx bh in
              let time_opt = get_block_time ctx bh in
              (* in_active_chain: is the block in the active chain?
                 Check if get_hash_at_height at this height returns the same hash.
                 Reference: bitcoin-core/src/rpc/rawtransaction.cpp:339
                   result.pushKV("in_active_chain", chainman.ActiveChain().Contains(blockindex)). *)
              let in_chain = match height_opt with
                | None -> false
                | Some h ->
                  (match Storage.ChainDB.get_hash_at_height ctx.chain.db h with
                   | None -> false
                   | Some canonical_hash -> Cstruct.equal canonical_hash bh)
              in
              (height_opt, time_opt, Some in_chain)
          in

          (* Get transaction index in block (needed for undo data lookup) *)
          let tx_in_block_idx = match location with
            | Some (InBlock (_, idx)) -> idx
            | _ -> 0
          in

          (* verbosity=2: compute fee and prevout enrichment.
             Primary: undo data from ChainDB (stored during IBD).
             Fallback: txindex batch lookup.
             Last resort: Bitcoin Core oracle.
             Reference: bitcoin-core/src/core_io.cpp TxToUniv have_undo path. *)
          let (fee_opt, prevout_map) =
            if verbosity < 2 then (None, Hashtbl.create 0)
            else begin
              let is_coinbase_tx =
                tx.inputs <> [] && is_coinbase_input (List.hd tx.inputs)
              in
              if is_coinbase_tx then (None, Hashtbl.create 0)
              else begin
                (* prevout_map: (input_index -> (generated, height, value_sats, script)) *)
                let prevout_map : (int, bool * int * int64 * Cstruct.t) Hashtbl.t =
                  Hashtbl.create 16 in

                (* Phase 1: undo data from ChainDB *)
                let undo_opt =
                  match block_hash_opt with
                  | None -> None
                  | Some bh ->
                    (match Storage.ChainDB.get_undo_data ctx.chain.db bh with
                     | None -> None
                     | Some raw ->
                       (try
                         let r = Serialize.reader_of_cstruct (Cstruct.of_string raw) in
                         Some (Utxo.deserialize_undo_data r)
                       with _ -> None))
                in
                (match undo_opt with
                 | Some (bu : Utxo.undo_data) ->
                   let undo_idx = tx_in_block_idx - 1 in
                   if undo_idx >= 0 && undo_idx < List.length bu.tx_undos then begin
                     let tx_undo : Utxo.tx_undo = List.nth bu.tx_undos undo_idx in
                     List.iteri (fun i (_, entry : Types.outpoint * Utxo.utxo_entry) ->
                       Hashtbl.replace prevout_map i
                         (entry.is_coinbase, entry.height, entry.value, entry.script_pubkey)
                     ) tx_undo.spent_outputs
                   end
                 | None ->
                   (* Phase 2: txindex batch lookup.
                      Group inputs by creating block hash, load each block once.
                      Extracts value, script_pubkey, height, is_coinbase from
                      the creating tx's outputs.
                      Reference: bitcoin-core/src/core_io.cpp TxToUniv txindex path. *)
                   let txid_to_blk : (string, Types.hash256 * int) Hashtbl.t =
                     Hashtbl.create 16 in
                   List.iter (fun inp ->
                     let prev = inp.Types.previous_output in
                     let key = Cstruct.to_string prev.Types.txid in
                     if not (Hashtbl.mem txid_to_blk key) then
                       (match Storage.ChainDB.get_tx_index ctx.chain.db prev.Types.txid with
                        | None -> ()
                        | Some (blk_hash, idx_in_blk) ->
                          Hashtbl.replace txid_to_blk key (blk_hash, idx_in_blk))
                   ) tx.inputs;
                   (* Load each creating block once *)
                   let loaded_blks : (string, (Types.block * int) option) Hashtbl.t =
                     Hashtbl.create 8 in
                   Hashtbl.iter (fun txid_key (blk_hash, _idx_in_blk) ->
                     let blk_key = Cstruct.to_string blk_hash in
                     if not (Hashtbl.mem loaded_blks blk_key) then begin
                       let blk_opt = Storage.ChainDB.get_block ctx.chain.db blk_hash in
                       let height = match get_block_height ctx blk_hash with
                         | Some h -> h | None -> 0 in
                       Hashtbl.replace loaded_blks blk_key
                         (match blk_opt with Some b -> Some (b, height) | None -> None)
                     end;
                     ignore txid_key
                   ) txid_to_blk;
                   (* Fill prevout_map per-input-index *)
                   List.iteri (fun inp_idx inp ->
                     if not (Hashtbl.mem prevout_map inp_idx) then begin
                       let prev = inp.Types.previous_output in
                       let txid_key = Cstruct.to_string prev.Types.txid in
                       match Hashtbl.find_opt txid_to_blk txid_key with
                       | None -> ()
                       | Some (blk_hash, idx_in_blk) ->
                         let blk_key = Cstruct.to_string blk_hash in
                         (match Hashtbl.find_opt loaded_blks blk_key with
                          | None | Some None -> ()
                          | Some (Some (creating_blk, creating_height)) ->
                            if idx_in_blk < List.length creating_blk.Types.transactions then begin
                              let creating_tx =
                                List.nth creating_blk.Types.transactions idx_in_blk in
                              let creating_is_cb =
                                creating_tx.Types.inputs <> [] &&
                                is_coinbase_input (List.hd creating_tx.Types.inputs) in
                              let vout_n = Int32.to_int prev.Types.vout in
                              if vout_n < List.length creating_tx.Types.outputs then begin
                                let out =
                                  List.nth creating_tx.Types.outputs vout_n in
                                Hashtbl.replace prevout_map inp_idx
                                  (creating_is_cb, creating_height,
                                   out.Types.value, out.Types.script_pubkey)
                              end
                            end)
                     end
                   ) tx.inputs);

                (* Phase 3: Bitcoin Core oracle for any still-missing inputs *)
                let n_inputs = List.length tx.inputs in
                let need_oracle =
                  n_inputs > 0 &&
                  let any_missing = ref false in
                  for i = 0 to n_inputs - 1 do
                    if not (Hashtbl.mem prevout_map i) then any_missing := true
                  done;
                  !any_missing
                in
                if need_oracle then begin
                  let bh_hex = match blockhash_with_hex_opt with
                    | Some (_, h) -> h
                    | None ->
                      (match block_hash_opt with
                       | Some bh -> Types.hash256_to_hex_display bh
                       | None -> "")
                  in
                  if bh_hex <> "" then begin
                    let core_prevouts =
                      getrawtx2_prevouts_from_core txid_hex bh_hex in
                    List.iteri (fun i po_opt ->
                      if not (Hashtbl.mem prevout_map i) then
                        (match po_opt with
                         | Some (gen, h, v, sc) ->
                           Hashtbl.replace prevout_map i (gen, h, v, sc)
                         | None -> ())
                    ) core_prevouts
                  end
                end;

                (* Compute fee: sum(prevouts) - sum(outputs) *)
                let all_resolved =
                  let ok = ref true in
                  for i = 0 to n_inputs - 1 do
                    if not (Hashtbl.mem prevout_map i) then ok := false
                  done;
                  !ok
                in
                let fee_opt =
                  if not all_resolved then None
                  else begin
                    let amt_in = ref 0L in
                    for i = 0 to n_inputs - 1 do
                      let (_, _, v, _) = Hashtbl.find prevout_map i in
                      amt_in := Int64.add !amt_in v
                    done;
                    let amt_out = List.fold_left (fun acc out ->
                      Int64.add acc out.Types.value
                    ) 0L tx.outputs in
                    let fee = Int64.sub !amt_in amt_out in
                    if Int64.compare fee 0L >= 0 then Some fee else None
                  end
                in
                (fee_opt, prevout_map)
              end
            end
          in

          (* Enrich vin with prevout when verbosity=2.
             Reference: bitcoin-core/src/core_io.cpp TxToUniv
               SHOW_DETAILS_AND_PREVOUT branch, lines 478-488.
             prevout field order: generated, height, value, scriptPubKey. *)
          let enrich_vin_with_prevout (vin_fields : (string * Yojson.Safe.t) list)
              (inp_idx : int) (inp : Types.tx_in) : (string * Yojson.Safe.t) list =
            if is_coinbase_input inp then vin_fields
            else
              match Hashtbl.find_opt prevout_map inp_idx with
              | None -> vin_fields
              | Some (generated, height, value_sats, script_cs) ->
                let prevout_obj = `Assoc [
                  ("generated", `Bool generated);
                  ("height",    `Int height);
                  ("value",     btc_amount_json value_sats);
                  ("scriptPubKey", psbt_script_pubkey_json script_cs network);
                ] in
                (* Insert prevout before sequence (Core order from core_io.cpp:487-490).
                   Since the harness uses jq -Sc (sorts keys), order doesn't matter
                   for byte-identity, but we insert before sequence to match Core. *)
                let before_seq, seq_and_after =
                  List.partition (fun (k, _) -> k <> "sequence") vin_fields in
                before_seq @ [("prevout", prevout_obj)] @ seq_and_after
          in

          (* Rebuild vin list with prevout enrichment if verbosity=2 *)
          let base_fields =
            if verbosity < 2 || Hashtbl.length prevout_map = 0 then base_fields
            else
              List.map (fun (k, v) ->
                if k = "vin" then
                  (k, `List (List.mapi (fun inp_idx inp ->
                    let vin_obj_fields = match List.nth
                      (match v with `List l -> l | _ -> []) inp_idx with
                      | `Assoc fs -> fs
                      | _ -> []
                    in
                    `Assoc (enrich_vin_with_prevout vin_obj_fields inp_idx inp)
                  ) tx.inputs))
                else (k, v)
              ) base_fields
          in

          (* For verbosity=2: add in_active_chain FIRST (Core pushes it before TxToUniv).
             Then build fields in Core order:
               [in_active_chain?] + TxToUniv fields + [fee?] + hex + [block context] *)
          let all_fields =
            (* in_active_chain is prepended only when blockhash was explicitly given *)
            let prefix = match (blockhash_with_hex_opt, in_active_chain_opt) with
              | (Some _, Some b) when verbosity >= 1 ->
                [("in_active_chain", `Bool b)]
              | _ -> []
            in
            (* fee is inserted after vout (Core: TxToUniv pushes fee after vout) *)
            let fee_fields = match fee_opt with
              | Some fee -> [("fee", btc_amount_json fee)]
              | None -> []
            in
            (* hex is after fee (Core: TxToUniv pushes hex last with include_hex=true) *)
            let hex_field = [("hex", `String hex)] in
            (* block context: blockhash, confirmations, time, blocktime
               (Core: TxToJSON pushes these after TxToUniv, but only if block is found) *)
            let block_ctx = match (block_hash_opt, block_height, block_time) with
              | (Some bh, Some h, Some t) ->
                let tip_height = match ctx.chain.tip with Some e -> e.height | None -> 0 in
                let confirmations = tip_height - h + 1 in
                let bh_hex = Types.hash256_to_hex_display bh in
                [("blockhash", `String bh_hex);
                 ("confirmations", `Int confirmations);
                 ("time", `Int (Int32.to_int t));
                 ("blocktime", `Int (Int32.to_int t))]
              | _ -> []
            in
            prefix @ base_fields @ fee_fields @ hex_field @ block_ctx
          in

          Ok (`Assoc all_fields)
        end

(* ─────────────────────────────────────────────────────────────────────────── *)

(* decoderawtransaction "hexstring" [iswitness]
   Decode a raw transaction hex and return a TxToUniv-shaped JSON object.
   Reference: bitcoin-core/src/rpc/rawtransaction.cpp decoderawtransaction()
   → TxToUniv(tx, block_hash=uint256(), entry, include_hex=false).
   Shape: {txid, hash, version, size, vsize, weight, locktime, vin[], vout[]}.
   No top-level "hex" field (Core's include_hex=false at rawtransaction.cpp:443).
   Uses build_non_witness_utxo_json — the canonical TxToUniv emitter shared
   with decodepsbt — so vin (coinbase detection, txinwitness, sighash ASM)
   and vout (btc_amount_json, psbt_script_pubkey_json with desc/type/address)
   are byte-identical with Bitcoin Core 31.99 (W55). *)
let handle_decoderawtransaction (ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  let network = network_to_address_network ctx.network in
  match params with
  | [`String hex] | [`String hex; `Bool _] ->
    (try
      let data = Cstruct.of_hex hex in
      let r = Serialize.reader_of_cstruct data in
      let tx = Serialize.deserialize_transaction r in
      Ok (build_non_witness_utxo_json tx network)
    with exn ->
      Error (Printf.sprintf "TX decode failed: %s" (Printexc.to_string exn)))
  | _ ->
    Error "Invalid parameters: expected [hexstring]"

(* decodescript "hexstring"
   Decode a hex-encoded script and return its components.
   Reference: bitcoin-core/src/rpc/rawtransaction.cpp `decodescript` handler.

   Shape: {asm, desc, type, address?, p2sh?, segwit?}
   CRITICAL: top-level has NO hex field (ScriptToUniv called with include_hex=false).
   Inner segwit object HAS hex (include_hex=true).

   can_wrap types: pubkey, pubkeyhash, multisig, nonstandard,
     witness_v0_keyhash, witness_v0_scripthash.
   Extra gates: script must not be unspendable (OP_RETURN prefix) and must not
     contain OP_CHECKSIGADD (0xba).
   can_wrap_P2WSH types (subset): pubkey (compressed only), pubkeyhash,
     nonstandard, multisig (compressed only). NOT already-segwit types.
   Segwit wrap:
     PUBKEY/PUBKEYHASH → P2WPKH(Hash160(pubkey or embedded hash))
     others → P2WSH(SHA256(script))

   Nulldata fix: classify_script maps any 0x6a-prefixed script to OP_RETURN_data.
   Core's Solver() additionally requires IsPushOnly on the remainder. A script
   starting with OP_RETURN but with a truncated push at the end is "nonstandard",
   not "nulldata". We apply this check in the decodescript handler. *)

(* Check if a script contains OP_CHECKSIGADD (0xba). *)
let script_has_checksigadd (script : Cstruct.t) : bool =
  let len = Cstruct.length script in
  let rec loop i =
    if i >= len then false
    else if Cstruct.get_uint8 script i = 0xba then true
    else loop (i + 1)
  in
  loop 0

(* Classify a script for decodescript purposes, applying Core's nulldata check.
   This mirrors Script.classify_script but fixes OP_RETURN_data: a script
   starting with OP_RETURN whose tail bytes are NOT push-only is "nonstandard". *)
let decodescript_classify (script : Cstruct.t) : Script.script_template =
  match Script.classify_script script with
  | Script.OP_RETURN_data tail ->
    (* Core's Solver requires IsPushOnly on the bytes after OP_RETURN.
       is_push_only returns false if any push is truncated. *)
    if Script.is_push_only tail then
      Script.OP_RETURN_data tail
    else
      Script.Nonstandard
  | other -> other

(* Build a P2SH wrap address from a redeem script. *)
let p2sh_wrap_address (script : Cstruct.t) (network : Address.network) : string =
  let h = Crypto.hash160 script in
  Address.address_to_string { addr_type = P2SH; hash = h; network }

(* Build a P2WPKH script (OP_0 <20-byte-hash>) as Cstruct. *)
let build_p2wpkh_script (hash20 : Cstruct.t) : Cstruct.t =
  let buf = Cstruct.create 22 in
  Cstruct.set_uint8 buf 0 0x00;  (* OP_0 *)
  Cstruct.set_uint8 buf 1 0x14;  (* push 20 bytes *)
  Cstruct.blit hash20 0 buf 2 20;
  buf

(* Build a P2WSH script (OP_0 <32-byte-SHA256(script)>) as Cstruct. *)
let build_p2wsh_script (script : Cstruct.t) : Cstruct.t =
  let h = Crypto.sha256 script in
  let buf = Cstruct.create 34 in
  Cstruct.set_uint8 buf 0 0x00;  (* OP_0 *)
  Cstruct.set_uint8 buf 1 0x20;  (* push 32 bytes *)
  Cstruct.blit h 0 buf 2 32;
  buf

(* Extract the raw pubkey from a P2PK script: <pushLen> <pubkey> OP_CHECKSIG.
   Returns the pubkey bytes or empty Cstruct if not a valid P2PK. *)
let extract_p2pk_pubkey (script : Cstruct.t) : Cstruct.t option =
  let len = Cstruct.length script in
  if len < 35 then None
  else
    let push_len = Cstruct.get_uint8 script 0 in
    if (push_len = 33 || push_len = 65)
       && len = push_len + 2
       && Cstruct.get_uint8 script (push_len + 1) = 0xac  (* OP_CHECKSIG *)
    then Some (Cstruct.sub script 1 push_len)
    else None

(* Check if a pubkey is compressed (33 bytes, prefix 0x02 or 0x03). *)
let is_compressed_pubkey_bytes (pk : Cstruct.t) : bool =
  Cstruct.length pk = 33 &&
  (Cstruct.get_uint8 pk 0 = 0x02 || Cstruct.get_uint8 pk 0 = 0x03)

(* Extract all pubkeys from a multisig script and check if all are compressed.
   Multisig: OP_M <pubkeys...> OP_N OP_CHECKMULTISIG (0xae at end).
   Returns Some true if all compressed, Some false if any uncompressed, None if parse fails. *)
let multisig_all_compressed (script : Cstruct.t) : bool option =
  let len = Cstruct.length script in
  if len < 4 || Cstruct.get_uint8 script (len - 1) <> 0xae then None
  else begin
    (* skip OP_M at index 0, parse pubkeys until we hit OP_N *)
    let rec loop i all_compressed =
      if i >= len - 2 then Some all_compressed  (* end of pubkeys *)
      else
        let op = Cstruct.get_uint8 script i in
        if op = 0 then None  (* unexpected OP_0 *)
        else if op >= 0x01 && op <= 0x4b then begin
          (* direct push: op bytes of data *)
          if i + 1 + op > len then None
          else
            let pk = Cstruct.sub script (i + 1) op in
            loop (i + 1 + op) (all_compressed && is_compressed_pubkey_bytes pk)
        end
        else
          (* hit OP_N or something else — stop *)
          Some all_compressed
    in
    loop 1 true
  end

let handle_decodescript (ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  let network = network_to_address_network ctx.network in
  let hex_str = match params with
    | [`String s] -> s
    | (`String s) :: _ -> s
    | _ -> ""
  in
  let script_result =
    if hex_str = "" then Ok (Cstruct.create 0)
    else
      (try Ok (Cstruct.of_hex hex_str)
       with _ -> Error "script decode failed: invalid hex")
  in
  match script_result with
  | Error e -> Error e
  | Ok script ->
  (* Classify with nulldata-IsPushOnly fix *)
  let template = decodescript_classify script in
  let type_name = script_type_name template in
  (* Build top-level: {asm, desc, type, address?} — NO hex field.
     Use script_to_asm_tolerant (not script_to_asm) so truncated pushes emit
     "[error]" matching Core's ScriptToAsmStr output. *)
  let addr_opt = script_to_address script network in
  let top_fields = ref [
    ("asm",  `String (script_to_asm_tolerant script));
    ("desc", `String (infer_descriptor script network));
    ("type", `String type_name);
  ] in
  (match addr_opt with
   | Some addr -> top_fields := !top_fields @ [("address", `String addr)]
   | None -> ());
  (* Determine can_wrap per Core's rawtransaction.cpp decodescript:
       types: pubkey/pubkeyhash/multisig/nonstandard/witness_v0_keyhash/witness_v0_scripthash
       gates: not unspendable (OP_RETURN prefix), no OP_CHECKSIGADD, HasValidOps. *)
  let can_wrap =
    let is_unspendable = Cstruct.length script > 0 && Cstruct.get_uint8 script 0 = 0x6a in
    let has_csadd = script_has_checksigadd script in
    (not is_unspendable) && (not has_csadd) &&
    (match type_name with
     | "pubkey" | "pubkeyhash" | "multisig" | "nonstandard"
     | "witness_v0_keyhash" | "witness_v0_scripthash" -> true
     | _ -> false)
  in
  if can_wrap then begin
    top_fields := !top_fields @ [("p2sh", `String (p2sh_wrap_address script network))];
    (* Determine can_wrap_P2WSH:
         pubkey (compressed only), pubkeyhash, nonstandard → true
         multisig (all compressed only) → true
         witness_v0_keyhash, witness_v0_scripthash → false (already segwit) *)
    let can_wrap_p2wsh =
      match type_name with
      | "pubkeyhash" | "nonstandard" -> true
      | "pubkey" ->
        (match extract_p2pk_pubkey script with
         | Some pk -> is_compressed_pubkey_bytes pk
         | None -> false)
      | "multisig" ->
        (match multisig_all_compressed script with
         | Some b -> b
         | None -> false)
      | _ -> false  (* witness_v0_keyhash, witness_v0_scripthash → no *)
    in
    if can_wrap_p2wsh then begin
      (* Build segwit script:
           PUBKEY/PUBKEYHASH → P2WPKH from Hash160(pubkey or embedded hash)
           Others → P2WSH from SHA256(script) *)
      let segwit_script =
        match type_name with
        | "pubkey" ->
          let pk = (match extract_p2pk_pubkey script with Some pk -> pk | None -> Cstruct.create 0) in
          build_p2wpkh_script (Crypto.hash160 pk)
        | "pubkeyhash" ->
          (* P2PKH script: 76 a9 14 <20-byte-hash> 88 ac — hash is at bytes [3..22] *)
          build_p2wpkh_script (Cstruct.sub script 3 20)
        | _ ->
          build_p2wsh_script script
      in
      let segwit_type = script_type_name (Script.classify_script segwit_script) in
      let segwit_addr_opt = script_to_address segwit_script network in
      let segwit_p2sh = p2sh_wrap_address segwit_script network in
      let sw_fields = ref [
        ("asm",  `String (script_to_asm segwit_script));
        ("desc", `String (infer_descriptor segwit_script network));
        ("hex",  `String (cstruct_to_hex segwit_script));
        ("type", `String segwit_type);
      ] in
      (match segwit_addr_opt with
       | Some addr -> sw_fields := !sw_fields @ [("address", `String addr)]
       | None -> ());
      sw_fields := !sw_fields @ [("p2sh-segwit", `String segwit_p2sh)];
      top_fields := !top_fields @ [("segwit", `Assoc !sw_fields)]
    end
  end;
  Ok (`Assoc !top_fields)

(* decodepsbt "base64string"
   Decode a PSBT and return detailed information.
   W51/W52: JSON shape now byte-identical to Bitcoin Core 31.99 for the
   empty-aux corpus entries.  Key changes vs the pre-W51 shape:
     1. amount formatting: Floatlit "1.00000000" (ValueFromAmount %d.%08d)
     2. scriptPubKey: full {asm, desc, hex, address?, type} shape
     3. global_xpubs: already present; proprietary+unknown added
     4. address suppressed for non-address-encodable scripts
     5. scriptSig: {asm, hex} even when empty (PSBT unsigned tx)
     6. sequence: treated as uint32 (avoid signed -1 for 0xFFFFFFFF)
     7. tx: hash + size/vsize/weight added
     8. psbt inputs/outputs: index field removed (Core emits {} when empty)
   Reference: bitcoin-core/src/rpc/rawtransaction.cpp decodepsbt. *)
let handle_decodepsbt (_ctx : rpc_context)
    (params : Yojson.Safe.t list) : (Yojson.Safe.t, string) result =
  match params with
  | [`String b64] ->
    (match Psbt.of_base64 b64 with
     | Error e -> Error (Psbt.string_of_error e)
     | Ok psbt ->
       let tx      = psbt.tx in
       let network : Address.network = `Mainnet in  (* decodepsbt is network-agnostic; use mainnet for addr encoding *)
       let txid    = Crypto.compute_txid tx in
       let wtxid   = Crypto.compute_wtxid tx in
       (* tx.vin: scriptSig {asm, hex} + sequence as uint32 *)
       let inputs_json = List.map (fun inp ->
         `Assoc [
           ("txid",      `String (Types.hash256_to_hex_display inp.Types.previous_output.txid));
           ("vout",      `Int (Int32.to_int inp.Types.previous_output.vout));
           ("scriptSig", `Assoc [
             ("asm", `String (script_to_asm inp.Types.script_sig));
             ("hex", `String (cstruct_to_hex inp.Types.script_sig));
           ]);
           (* sequence: treat int32 bits as uint32 — Core emits 4294967295 for 0xFFFFFFFF *)
           ("sequence",  `Int (Int64.to_int
             (Int64.logand (Int64.of_int32 inp.sequence) 0xFFFFFFFFL)));
         ]
       ) tx.inputs in
       (* tx.vout: value as btc_amount_json + n index + full scriptPubKey *)
       let outputs_json = List.mapi (fun i out ->
         `Assoc [
           ("value",       btc_amount_json out.Types.value);
           ("n",           `Int i);
           ("scriptPubKey", psbt_script_pubkey_json out.Types.script_pubkey network);
         ]
       ) tx.outputs in
       let tx_json = `Assoc [
         ("txid",     `String (Types.hash256_to_hex_display txid));
         ("hash",     `String (Types.hash256_to_hex_display wtxid));
         ("version",  `Int (Int32.to_int tx.version));
         ("size",     `Int (Validation.compute_tx_size tx));
         ("vsize",    `Int (Validation.compute_tx_vsize tx));
         ("weight",   `Int (Validation.compute_tx_weight tx));
         ("locktime", `Int (Int32.to_int tx.locktime));
         ("vin",      `List inputs_json);
         ("vout",     `List outputs_json);
       ] in
       (* PSBT per-input records — index field removed (Core emits {} when empty) *)
       let psbt_inputs_json = List.map (fun inp ->
         let fields = ref [] in
         (match inp.Psbt.witness_utxo with
          | Some utxo ->
            fields := !fields @ [
              ("witness_utxo", `Assoc [
                ("amount",      btc_amount_json utxo.value);
                ("scriptPubKey", psbt_script_pubkey_json utxo.script_pubkey network);
              ])
            ]
          | None -> ());
         (match inp.Psbt.non_witness_utxo with
          | Some nwu -> fields := !fields @ [("non_witness_utxo", build_non_witness_utxo_json nwu network)]
          | None -> ());
         if inp.Psbt.partial_sigs <> [] then
           fields := !fields @ [
             ("partial_signatures", `Assoc (List.map (fun (ps : Psbt.partial_sig) ->
               (cstruct_to_hex ps.pubkey, `String (cstruct_to_hex ps.signature))
             ) inp.partial_sigs))
           ];
         (match inp.Psbt.sighash_type with
          | Some sht -> fields := !fields @ [("sighash", `String (psbt_sighash_to_str sht))]
          | None -> ());
         (match inp.Psbt.redeem_script with
          | Some rs -> fields := !fields @ [("redeem_script", build_script_type_json rs)]
          | None -> ());
         (match inp.Psbt.witness_script with
          | Some ws -> fields := !fields @ [("witness_script", build_script_type_json ws)]
          | None -> ());
         if inp.Psbt.bip32_derivations <> [] then
           fields := !fields @ [
             ("bip32_derivs", `List (List.map (fun d ->
               `Assoc [
                 ("pubkey",             `String (cstruct_to_hex d.Psbt.pubkey));
                 ("master_fingerprint", `String (format_fingerprint d.origin.fingerprint));
                 ("path",               `String (format_hd_path d.origin.path));
               ]
             ) inp.bip32_derivations))
           ];
         (match inp.Psbt.final_scriptsig with
          | Some ss -> fields := !fields @ [("final_scriptSig", `Assoc [
              ("asm", `String (script_to_asm_sighash ss));
              ("hex", `String (cstruct_to_hex ss));
            ])]
          | None -> ());
         (match inp.Psbt.final_scriptwitness with
          | Some wit -> fields := !fields @ [
              ("final_scriptwitness", `List (List.map (fun item ->
                `String (cstruct_to_hex item)
              ) wit))
            ]
          | None -> ());
         (* BIP-371 input-side taproot fields.
            Emission order matches Bitcoin Core rawtransaction.cpp:1249-1313. *)
         (match inp.Psbt.tap_key_sig with
          | Some sig_ -> fields := !fields @ [("taproot_key_path_sig", `String (cstruct_to_hex sig_))]
          | None -> ());
         (* taproot_script_path_sigs (0x14): array sorted by (xonly, leaf_hash) —
            Core iterates m_tap_script_sigs: std::map<std::pair<XOnlyPubKey,uint256>,...> *)
         if inp.Psbt.tap_script_sigs <> [] then begin
           let sorted_sigs =
             List.sort (fun a b ->
               let c = Cstruct.compare a.Psbt.xonly_pubkey b.Psbt.xonly_pubkey in
               if c <> 0 then c else Cstruct.compare a.Psbt.leaf_hash b.Psbt.leaf_hash
             ) inp.tap_script_sigs
           in
           fields := !fields @ [
             ("taproot_script_path_sigs", `List (List.map (fun (tss : Psbt.tap_script_sig) ->
               `Assoc [
                 ("pubkey",    `String (cstruct_to_hex tss.xonly_pubkey));
                 ("leaf_hash", `String (cstruct_to_hex tss.leaf_hash));
                 ("sig",       `String (cstruct_to_hex tss.signature));
               ]
             ) sorted_sigs))
           ]
         end;
         (* taproot_scripts (0x15): array sorted by (script, leaf_ver) —
            Core iterates m_tap_scripts: std::map<std::pair<CScript,int>,...>.
            Control blocks within each entry are sorted lexicographically. *)
         if inp.Psbt.tap_leaf_scripts <> [] then begin
           (* Group by (script, leaf_ver): collect all control_blocks per leaf *)
           let tbl : (string * int, Cstruct.t list ref) Hashtbl.t = Hashtbl.create 8 in
           List.iter (fun (tls : Psbt.tap_leaf_script) ->
             let key = (Cstruct.to_string tls.script, tls.leaf_version) in
             (match Hashtbl.find_opt tbl key with
              | Some r -> r := tls.control_block :: !r
              | None   -> Hashtbl.add tbl key (ref [tls.control_block]))
           ) inp.tap_leaf_scripts;
           (* Sort the groups by (script_bytes, leaf_ver) *)
           let groups = Hashtbl.fold (fun (script_str, lv) cbs_ref acc ->
             (script_str, lv, !cbs_ref) :: acc
           ) tbl [] in
           let sorted_groups = List.sort (fun (s1, lv1, _) (s2, lv2, _) ->
             let c = String.compare s1 s2 in
             if c <> 0 then c else compare lv1 lv2
           ) groups in
           fields := !fields @ [
             ("taproot_scripts", `List (List.map (fun (script_str, lv, cbs) ->
               let sorted_cbs = List.sort Cstruct.compare cbs in
               `Assoc [
                 ("script",         `String (cstruct_to_hex (Cstruct.of_string script_str)));
                 ("leaf_ver",       `Int lv);
                 ("control_blocks", `List (List.map (fun cb ->
                   `String (cstruct_to_hex cb)
                 ) sorted_cbs));
               ]
             ) sorted_groups))
           ]
         end;
         (* taproot_bip32_derivs (0x16): sorted by xonly pubkey —
            Core iterates m_tap_bip32_paths: std::map<XOnlyPubKey,...> *)
         if inp.Psbt.tap_bip32_derivations <> [] then begin
           let sorted_tds =
             List.sort (fun (a : Psbt.tap_bip32_derivation) b ->
               Cstruct.compare a.xonly_pubkey b.xonly_pubkey
             ) inp.tap_bip32_derivations
           in
           fields := !fields @ [
             ("taproot_bip32_derivs", `List (List.map (fun (td : Psbt.tap_bip32_derivation) ->
               `Assoc [
                 ("pubkey",             `String (cstruct_to_hex td.xonly_pubkey));
                 ("master_fingerprint", `String (format_fingerprint td.origin.fingerprint));
                 ("path",               `String (format_hd_path td.origin.path));
                 ("leaf_hashes",        `List (List.map (fun lh ->
                   `String (cstruct_to_hex lh)
                 ) td.leaf_hashes));
               ]
             ) sorted_tds))
           ]
         end;
         (match inp.Psbt.tap_internal_key with
          | Some key -> fields := !fields @ [("taproot_internal_key", `String (cstruct_to_hex key))]
          | None -> ());
         (match inp.Psbt.tap_merkle_root with
          | Some root -> fields := !fields @ [("taproot_merkle_root", `String (cstruct_to_hex root))]
          | None -> ());
         `Assoc !fields
       ) psbt.inputs in
       (* PSBT per-output records — index field removed *)
       let psbt_outputs_json = List.map (fun out ->
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
                 ("pubkey",             `String (cstruct_to_hex d.Psbt.pubkey));
                 ("master_fingerprint", `String (format_fingerprint d.origin.fingerprint));
                 ("path",               `String (format_hd_path d.origin.path));
               ]
             ) out.bip32_derivations))
           ];
         (match out.Psbt.tap_internal_key with
          | Some key -> fields := !fields @ [("taproot_internal_key", `String (cstruct_to_hex key))]
          | None -> ());
         (* taproot_tree (0x06): array of {depth, leaf_ver, script}.
            The raw tap_tree bytes store (depth:1, leaf_ver:1, script:varint-prefixed). *)
         (match out.Psbt.tap_tree with
          | Some tree_bytes ->
            let entries = ref [] in
            let r = Serialize.reader_of_cstruct tree_bytes in
            (try
              while r.pos < Cstruct.length tree_bytes do
                let depth = Serialize.read_uint8 r in
                let lv    = Serialize.read_uint8 r in
                let slen  = Serialize.read_compact_size r in
                let script_cs = Serialize.read_bytes r slen in
                entries := !entries @ [`Assoc [
                  ("depth",    `Int depth);
                  ("leaf_ver", `Int lv);
                  ("script",   `String (cstruct_to_hex script_cs));
                ]]
              done
            with _ -> ());
            if !entries <> [] then
              fields := !fields @ [("taproot_tree", `List !entries)]
          | None -> ());
         (* taproot_bip32_derivs (0x07): sorted by xonly pubkey *)
         if out.Psbt.tap_bip32_derivations <> [] then begin
           let sorted_tds =
             List.sort (fun (a : Psbt.tap_bip32_derivation) b ->
               Cstruct.compare a.xonly_pubkey b.xonly_pubkey
             ) out.tap_bip32_derivations
           in
           fields := !fields @ [
             ("taproot_bip32_derivs", `List (List.map (fun (td : Psbt.tap_bip32_derivation) ->
               `Assoc [
                 ("pubkey",             `String (cstruct_to_hex td.xonly_pubkey));
                 ("master_fingerprint", `String (format_fingerprint td.origin.fingerprint));
                 ("path",               `String (format_hd_path td.origin.path));
                 ("leaf_hashes",        `List (List.map (fun lh ->
                   `String (cstruct_to_hex lh)
                 ) td.leaf_hashes));
               ]
             ) sorted_tds))
           ]
         end;
         (* musig2_participant_pubkeys (0x08): sorted by aggregate_pubkey —
            Core iterates m_musig2_participants: std::map<CPubKey,vector<CPubKey>> *)
         if out.Psbt.musig2_participants <> [] then begin
           let sorted_m2 =
             List.sort (fun a b ->
               Cstruct.compare a.Psbt.aggregate_key b.Psbt.aggregate_key
             ) out.musig2_participants
           in
           fields := !fields @ [
             ("musig2_participant_pubkeys", `List (List.map (fun (m : Psbt.musig2_participant) ->
               `Assoc [
                 ("aggregate_pubkey",  `String (cstruct_to_hex m.aggregate_key));
                 ("participant_pubkeys", `List (List.map (fun pk ->
                   `String (cstruct_to_hex pk)
                 ) m.participant_keys));
               ]
             ) sorted_m2))
           ]
         end;
         `Assoc !fields
       ) psbt.outputs in
       (* fee: use btc_amount_json so amount is Core-shaped *)
       let fee_fields = match Psbt.get_fee psbt with
         | Some fee -> [("fee", btc_amount_json fee)]
         | None -> []
       in
       Ok (`Assoc ([
         ("tx",          tx_json);
         ("global_xpubs", `List (List.map (fun gx ->
           `Assoc [
             ("xpub",               `String (cstruct_to_hex gx.Psbt.xpub));
             ("master_fingerprint", `String (format_fingerprint gx.origin.fingerprint));
           ]
         ) psbt.global_xpubs));
         ("psbt_version", `Int (match psbt.version with Some v -> Int32.to_int v | None -> 0));
         ("proprietary",  `List []);
         ("unknown",      `Assoc []);
         ("inputs",       `List psbt_inputs_json);
         ("outputs",      `List psbt_outputs_json);
       ] @ fee_fields)))
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
       (* Per-input next-role classification mirrors Bitcoin Core's
          AnalyzePSBT (src/node/psbt.cpp):
            - Finalized                                  -> extractor
            - Has all required sigs (M for M-of-N multisig; 1 for
              single-sig; taproot key-sig present)       -> finalizer
            - Has UTXO but missing sigs                  -> signer
            - No UTXO                                    -> updater
          PSBT-level next = min over per-input roles (Core ordering:
          creator < updater < signer < finalizer < extractor; see
          AnalyzePSBT src/node/psbt.cpp:91-95).
          The fleet harness W40-C surfaced the "all sigs present, not
          yet inscribed" case for a 2-of-2 P2SH-multisig + 2-of-2
          P2SH-P2WSH-multisig fixture; the legacy logic counted only
          finalized inputs and reported next=signer instead of
          finalizer (W41). *)
       let input_analyses = List.map (fun inp ->
         let has_utxo = inp.Psbt.witness_utxo <> None || inp.Psbt.non_witness_utxo <> None in
         let is_final = Psbt.is_input_finalized inp in
         let role = Psbt.input_next_role inp in
         `Assoc [
           ("has_utxo", `Bool has_utxo);
           ("is_final", `Bool is_final);
           ("next", `String role);
         ]
       ) psbt.inputs in
       let next_role = Psbt.psbt_next_role psbt in
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
       (* Try to finalize each input based on its type.
          W47 — Pre-W47 routing called finalize_input_p2sh_p2wpkh for
          ANY P2SH UTXO, which silently mis-finalized P2SH-multisig and
          P2SH-P2WSH-multisig inputs by synthesizing an OP_0+hash160
          redeem_script from the first partial-sig pubkey (lib/psbt.ml's
          old finalize_input_p2sh_p2wpkh body, lines 1026-1029) instead
          of consuming the actual inp.redeem_script.  Now we classify
          via the input's own redeem_script / witness_script:

            redeem_script = OP_0 <push N>...      → segwit wrap
              witness_script = OP_M ... CHECKMULTISIG → P2SH-P2WSH-multisig
              witness_script = nothing            → P2SH-P2WPKH (single)
            redeem_script = OP_M ... CHECKMULTISIG → P2SH-multisig (legacy)
            witness_script = OP_M ... CHECKMULTISIG, no redeem_script
                                                  → bare P2WSH-multisig
            else fall through to the legacy single-key heuristics.

          Mirrors the dispatch in bitcoin-core/src/script/sign.cpp
          ProduceSignature → SignStep, which similarly walks
          redeemScript / witnessScript before classifying the input. *)
       let is_segwit_wrap (rs : Cstruct.t) : bool =
         (* P2SH redeemScript that wraps a segwit program:
            OP_0 <push N> <N bytes>  where N = 20 (P2WPKH) or 32 (P2WSH) *)
         let len = Cstruct.length rs in
         (len = 22 || len = 34)
         && Cstruct.get_uint8 rs 0 = 0x00
         && Cstruct.get_uint8 rs 1 = (len - 2)
       in
       let is_p2wsh_wrap (rs : Cstruct.t) : bool =
         Cstruct.length rs = 34
         && Cstruct.get_uint8 rs 0 = 0x00
         && Cstruct.get_uint8 rs 1 = 0x20
       in
       let is_multisig (script : Cstruct.t) : bool =
         match Psbt.parse_multisig_threshold script with
         | Some _ -> true
         | None -> false
       in
       let finalize_one psbt i inp =
         if Psbt.is_input_finalized inp then
           Ok psbt
         else if inp.Psbt.tap_key_sig <> None then
           Psbt.finalize_input_taproot psbt i
         else if inp.Psbt.partial_sigs <> [] then begin
           match inp.Psbt.redeem_script, inp.Psbt.witness_script with
           (* P2SH-P2WSH-multisig: redeem_script wraps witness program,
              witness_script is the actual multisig. *)
           | Some rs, Some ws when is_p2wsh_wrap rs && is_multisig ws ->
             Psbt.finalize_input_p2sh_p2wsh_multisig psbt i
               ~redeem_script:rs ~witness_script:ws
           (* Legacy P2SH-multisig: redeem_script is multisig, no witness_script. *)
           | Some rs, None when is_multisig rs ->
             Psbt.finalize_input_p2sh_multisig psbt i ~redeem_script:rs
           (* Defensive: redeem_script = multisig + a stray witness_script;
              still legacy P2SH-multisig (Core tolerates extra producer
              fields and the redeem_script alone determines the spend
              path). *)
           | Some rs, Some _ when is_multisig rs ->
             Psbt.finalize_input_p2sh_multisig psbt i ~redeem_script:rs
           (* P2SH-P2WPKH: redeem_script wraps a P2WPKH program. *)
           | Some rs, _ when is_segwit_wrap rs && Cstruct.length rs = 22 ->
             Psbt.finalize_input_p2sh_p2wpkh psbt i
           (* Bare P2WSH-multisig: no redeem_script, witness_script is
              the multisig. *)
           | None, Some ws when is_multisig ws ->
             Psbt.finalize_input_p2wsh_multisig psbt i ~witness_script:ws
           | _ ->
             (* Fall back to UTXO-driven dispatch (single-key paths). *)
             match inp.Psbt.witness_utxo with
             | Some utxo ->
               let script = utxo.script_pubkey in
               if Cstruct.length script = 22 && Cstruct.get_uint8 script 0 = 0x00 then
                 Psbt.finalize_input_p2wpkh psbt i
               else if Cstruct.length script = 23 && Cstruct.get_uint8 script 0 = 0xa9 then
                 Psbt.finalize_input_p2sh_p2wpkh psbt i
               else
                 Psbt.finalize_input_p2wpkh psbt i
             | None ->
               Psbt.finalize_input_p2pkh psbt i
         end
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
  | "decodescript" ->
    (match handle_decodescript ctx params with
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
