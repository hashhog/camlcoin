(* REST API for lightweight clients to query blockchain data

   Provides read-only HTTP endpoints for blocks, transactions, headers,
   and chain state without JSON-RPC overhead. Supports multiple output
   formats (.json, .hex, .bin) via URI extension.

   Reference: Bitcoin Core rest.cpp *)

let log_src = Logs.Src.create "REST" ~doc:"REST server"
module Log = (val Logs.src_log log_src : Logs.LOG)
let _ = Log.info  (* suppress unused module warning *)

(* ============================================================================
   Response Format Types
   ============================================================================ *)

type response_format =
  | JSON
  | Hex
  | Binary
  | Undefined

(* Maximum number of headers to return in one request *)
let max_headers_results = 2000

(* ============================================================================
   Format Parsing
   ============================================================================ *)

(* Parse format from URI extension, returning (format, param_without_extension) *)
let parse_data_format (uri_part : string) : response_format * string =
  (* Strip query string if present *)
  let param = match String.index_opt uri_part '?' with
    | Some pos -> String.sub uri_part 0 pos
    | None -> uri_part
  in
  (* Find last dot *)
  match String.rindex_opt param '.' with
  | None -> (Undefined, param)
  | Some pos ->
    let suffix = String.sub param (pos + 1) (String.length param - pos - 1) in
    let base = String.sub param 0 pos in
    match suffix with
    | "json" -> (JSON, base)
    | "hex" -> (Hex, base)
    | "bin" -> (Binary, base)
    | _ -> (Undefined, param)

(* Available format string for error messages *)
let available_formats () = ".json, .hex, .bin"

(* ============================================================================
   HTTP Response Helpers
   ============================================================================ *)

let respond_error status message =
  let headers = Cohttp.Header.init_with "Content-Type" "text/plain" in
  Cohttp_lwt_unix.Server.respond_string
    ~status ~headers ~body:(message ^ "\r\n") ()

let respond_json body =
  let headers = Cohttp.Header.init_with "Content-Type" "application/json" in
  Cohttp_lwt_unix.Server.respond_string
    ~status:`OK ~headers ~body:(body ^ "\n") ()

let respond_hex body =
  let headers = Cohttp.Header.init_with "Content-Type" "text/plain" in
  Cohttp_lwt_unix.Server.respond_string
    ~status:`OK ~headers ~body:(body ^ "\n") ()

let respond_binary body =
  let headers = Cohttp.Header.init_with "Content-Type" "application/octet-stream" in
  Cohttp_lwt_unix.Server.respond_string
    ~status:`OK ~headers ~body ()

(* ============================================================================
   Utility Functions
   ============================================================================ *)

(* Convert Cstruct to hex string *)
let cstruct_to_hex (cs : Cstruct.t) : string =
  let len = Cstruct.length cs in
  let buf = Buffer.create (len * 2) in
  for i = 0 to len - 1 do
    Buffer.add_string buf (Printf.sprintf "%02x" (Cstruct.get_uint8 cs i))
  done;
  Buffer.contents buf

(* Parse display-format hash (reversed) to internal format *)
let parse_display_hash (hash_hex : string) : Types.hash256 option =
  if String.length hash_hex <> 64 then None
  else try
    let hash_bytes = Types.hash256_of_hex hash_hex in
    let hash = Cstruct.create 32 in
    for i = 0 to 31 do
      Cstruct.set_uint8 hash i (Cstruct.get_uint8 hash_bytes (31 - i))
    done;
    Some hash
  with _ -> None

(* Split string on delimiter *)
let split_string (s : string) (c : char) : string list =
  String.split_on_char c s |> List.filter (fun x -> x <> "")

(* Parse query parameter from request *)
let get_query_param (req : Cohttp.Request.t) (name : string) : string option =
  let uri = Cohttp.Request.uri req in
  Uri.get_query_param uri name

(* ============================================================================
   Block Endpoint: GET /rest/block/<hash>.<format>
                   GET /rest/block/notxdetails/<hash>.<format>

   [notx_details] toggles the JSON-mode tx verbosity:
     false (default) — Core's "DETAILS_AND_PREVOUT": each tx is a JSON
                       object with vin/vout/locktime; matches /rest/block/.
     true            — Core's "SHOW_TXID": tx field is a flat list of
                       txid hex strings; matches /rest/block/notxdetails/.
   .bin and .hex are byte-for-byte identical between the two paths
   (Core rest.cpp:471-479).
   ============================================================================ *)

let handle_block ?(notx_details : bool = false)
    (ctx : Rpc.rpc_context) (_req : Cohttp.Request.t)
    (uri_part : string) =
  let open Lwt.Syntax in
  let rf, hash_str = parse_data_format uri_part in
  match parse_display_hash hash_str with
  | None ->
    respond_error `Bad_request ("Invalid hash: " ^ hash_str)
  | Some hash ->
    match Storage.ChainDB.get_block ctx.chain.db hash with
    | None ->
      respond_error `Not_found (hash_str ^ " not found")
    | Some block ->
      match rf with
      | Binary ->
        let w = Serialize.writer_create () in
        Serialize.serialize_block w block;
        let cs = Serialize.writer_to_cstruct w in
        let* () = Lwt.return_unit in
        respond_binary (Cstruct.to_string cs)
      | Hex ->
        let w = Serialize.writer_create () in
        Serialize.serialize_block w block;
        let cs = Serialize.writer_to_cstruct w in
        respond_hex (cstruct_to_hex cs)
      | JSON ->
        (* Get block entry for height and chainwork *)
        let entry = Sync.get_header ctx.chain hash in
        let height = match entry with Some e -> e.height | None -> 0 in
        let chainwork = match entry with
          | Some e -> Types.hash256_to_hex_display e.total_work
          | None -> String.make 64 '0'
        in
        (* Compute sizes *)
        let w_total = Serialize.writer_create () in
        Serialize.serialize_block w_total block;
        let total_size = Cstruct.length (Serialize.writer_to_cstruct w_total) in
        let total_weight =
          80 * Consensus.witness_scale_factor +
          List.fold_left (fun acc tx -> acc + Validation.compute_tx_weight tx) 0 block.transactions
        in
        let stripped_size = (total_weight - total_size) / 3 in
        let tip_height = match ctx.chain.tip with Some t -> t.height | None -> 0 in
        let confirmations = tip_height - height + 1 in
        let median_time = Sync.compute_median_time_past ctx.chain height in
        let tx_field =
          if notx_details then
            (* /rest/block/notxdetails — Core's SHOW_TXID verbosity: flat
               txid strings only. *)
            `List (List.map (fun tx ->
              `String (Types.hash256_to_hex_display (Crypto.compute_txid tx))
            ) block.transactions)
          else
            (* /rest/block — Core's DETAILS_AND_PREVOUT verbosity: tx
               objects with vin/vout/locktime/etc. We do not yet plumb
               undo data here so prevout decoration is omitted; the
               shape still matches DETAILS for SPV/lightweight clients. *)
            `List (List.map (fun (tx : Types.transaction) ->
              let w = Serialize.writer_create () in
              Serialize.serialize_transaction w tx;
              let raw_size = Cstruct.length (Serialize.writer_to_cstruct w) in
              `Assoc [
                ("txid", `String (Types.hash256_to_hex_display (Crypto.compute_txid tx)));
                ("hash", `String (Types.hash256_to_hex_display (Crypto.compute_wtxid tx)));
                ("version", `Int (Int32.to_int tx.version));
                ("size", `Int raw_size);
                ("weight", `Int (Validation.compute_tx_weight tx));
                ("locktime", `Int (Int32.to_int tx.locktime));
                ("vin", `List (List.map (fun (inp : Types.tx_in) ->
                  `Assoc [
                    ("txid", `String (Types.hash256_to_hex_display inp.previous_output.txid));
                    ("vout", `Int (Int32.to_int inp.previous_output.vout));
                    ("scriptSig", `Assoc [
                      ("hex", `String (cstruct_to_hex inp.script_sig))
                    ]);
                    ("sequence", `Int (Int32.to_int inp.sequence));
                  ]
                ) tx.inputs));
                ("vout", `List (List.mapi (fun n (out : Types.tx_out) ->
                  `Assoc [
                    ("value", `Float (Int64.to_float out.value /. 100_000_000.0));
                    ("n", `Int n);
                    ("scriptPubKey", `Assoc [
                      ("hex", `String (cstruct_to_hex out.script_pubkey))
                    ]);
                  ]
                ) tx.outputs));
              ]
            ) block.transactions)
        in
        let json = `Assoc [
          ("hash", `String hash_str);
          ("confirmations", `Int confirmations);
          ("size", `Int total_size);
          ("strippedsize", `Int stripped_size);
          ("weight", `Int total_weight);
          ("height", `Int height);
          ("version", `Int (Int32.to_int block.header.version));
          ("versionHex", `String (Printf.sprintf "%08lx" block.header.version));
          ("merkleroot", `String (Types.hash256_to_hex_display block.header.merkle_root));
          ("tx", tx_field);
          ("time", `Int (Int32.to_int block.header.timestamp));
          ("mediantime", `Int (Int32.to_int median_time));
          ("nonce", `Int (Int32.to_int block.header.nonce));
          ("bits", `String (Printf.sprintf "%08lx" block.header.bits));
          ("difficulty", `Float (Consensus.difficulty_from_bits block.header.bits));
          ("chainwork", `String chainwork);
          ("nTx", `Int (List.length block.transactions));
          ("previousblockhash", `String (Types.hash256_to_hex_display block.header.prev_block));
        ] in
        respond_json (Yojson.Safe.to_string json)
      | Undefined ->
        respond_error `Not_found ("output format not found (available: " ^ available_formats () ^ ")")

(* /rest/block/notxdetails/<hash>.<format>: Core rest.cpp:476-479. Wraps
   handle_block with [notx_details=true] so the JSON tx field is a flat
   list of txid hex strings. .bin and .hex paths are byte-identical to
   /rest/block/. *)
let handle_block_notxdetails (ctx : Rpc.rpc_context) (req : Cohttp.Request.t)
    (uri_part : string) =
  handle_block ~notx_details:true ctx req uri_part

(* ============================================================================
   Transaction Endpoint: GET /rest/tx/<txid>.<format>
   ============================================================================ *)

let handle_tx (ctx : Rpc.rpc_context) (_req : Cohttp.Request.t)
    (uri_part : string) =
  let rf, txid_str = parse_data_format uri_part in
  match parse_display_hash txid_str with
  | None ->
    respond_error `Bad_request ("Invalid hash: " ^ txid_str)
  | Some txid ->
    (* Check mempool first *)
    let tx_opt = match Mempool.get ctx.mempool txid with
      | Some entry -> Some (entry.tx, None)  (* No block hash for mempool tx *)
      | None ->
        (* Search in chain storage via tx index *)
        match Storage.ChainDB.get_tx_index ctx.chain.db txid with
        | Some (block_hash, _tx_idx) ->
          (match Storage.ChainDB.get_transaction ctx.chain.db txid with
           | Some tx -> Some (tx, Some block_hash)
           | None -> None)
        | None ->
          (* Try getting transaction directly (may be in storage without index) *)
          match Storage.ChainDB.get_transaction ctx.chain.db txid with
          | Some tx -> Some (tx, None)
          | None -> None
    in
    match tx_opt with
    | None ->
      respond_error `Not_found (txid_str ^ " not found")
    | Some (tx, block_hash_opt) ->
      match rf with
      | Binary ->
        let w = Serialize.writer_create () in
        Serialize.serialize_transaction w tx;
        let cs = Serialize.writer_to_cstruct w in
        respond_binary (Cstruct.to_string cs)
      | Hex ->
        let w = Serialize.writer_create () in
        Serialize.serialize_transaction w tx;
        let cs = Serialize.writer_to_cstruct w in
        respond_hex (cstruct_to_hex cs)
      | JSON ->
        let block_hash_str = match block_hash_opt with
          | Some h -> Types.hash256_to_hex_display h
          | None -> ""
        in
        let json = `Assoc [
          ("txid", `String txid_str);
          ("hash", `String (Types.hash256_to_hex_display (Crypto.compute_wtxid tx)));
          ("version", `Int (Int32.to_int tx.version));
          ("size", `Int (let w = Serialize.writer_create () in
            Serialize.serialize_transaction w tx;
            Cstruct.length (Serialize.writer_to_cstruct w)));
          ("weight", `Int (Validation.compute_tx_weight tx));
          ("locktime", `Int (Int32.to_int tx.locktime));
          ("vin", `List (List.map (fun (inp : Types.tx_in) ->
            `Assoc [
              ("txid", `String (Types.hash256_to_hex_display inp.previous_output.txid));
              ("vout", `Int (Int32.to_int inp.previous_output.vout));
              ("scriptSig", `Assoc [
                ("hex", `String (cstruct_to_hex inp.script_sig))
              ]);
              ("sequence", `Int (Int32.to_int inp.sequence));
            ]
          ) tx.inputs));
          ("vout", `List (List.mapi (fun n (out : Types.tx_out) ->
            `Assoc [
              ("value", `Float (Int64.to_float out.value /. 100_000_000.0));
              ("n", `Int n);
              ("scriptPubKey", `Assoc [
                ("hex", `String (cstruct_to_hex out.script_pubkey))
              ]);
            ]
          ) tx.outputs));
          ("blockhash", `String block_hash_str);
        ] in
        respond_json (Yojson.Safe.to_string json)
      | Undefined ->
        respond_error `Not_found ("output format not found (available: " ^ available_formats () ^ ")")

(* ============================================================================
   Headers Endpoint: GET /rest/headers/<hash>.<format>?count=<count>
                  or GET /rest/headers/<count>/<hash>.<format> (deprecated)
   ============================================================================ *)

let handle_headers (ctx : Rpc.rpc_context) (req : Cohttp.Request.t)
    (uri_part : string) =
  let rf, param = parse_data_format uri_part in
  let path_parts = split_string param '/' in
  let hash_str, count_str =
    match path_parts with
    | [hash] ->
      (* New path: use query parameter *)
      let count = match get_query_param req "count" with
        | Some c -> c
        | None -> "5"  (* Default count *)
      in
      (hash, count)
    | [count; hash] ->
      (* Deprecated path: /rest/headers/<count>/<hash> *)
      (hash, count)
    | _ ->
      ("", "")
  in
  if hash_str = "" then
    respond_error `Bad_request "Invalid URI format. Expected /rest/headers/<hash>.<ext>?count=<count>"
  else
    let count = try int_of_string count_str with _ -> 0 in
    if count < 1 || count > max_headers_results then
      respond_error `Bad_request
        (Printf.sprintf "Header count is invalid or out of acceptable range (1-%d): %s"
          max_headers_results count_str)
    else
      match parse_display_hash hash_str with
      | None ->
        respond_error `Bad_request ("Invalid hash: " ^ hash_str)
      | Some hash ->
        (* Collect headers starting from hash *)
        let rec collect_headers h remaining acc =
          if remaining = 0 then List.rev acc
          else
            match Sync.get_header ctx.chain h with
            | None -> List.rev acc
            | Some entry ->
              (* Check if this is in active chain *)
              let in_chain = match ctx.chain.tip with
                | None -> false
                | Some tip -> entry.height <= tip.height
              in
              if not in_chain then List.rev acc
              else
                (* Get next block *)
                match Storage.ChainDB.get_hash_at_height ctx.chain.db (entry.height + 1) with
                | None -> List.rev (entry :: acc)
                | Some next_hash -> collect_headers next_hash (remaining - 1) (entry :: acc)
        in
        let headers = collect_headers hash count [] in
        if headers = [] then
          respond_error `Not_found (hash_str ^ " not found or not in active chain")
        else
          match rf with
          | Binary ->
            let w = Serialize.writer_create () in
            List.iter (fun (entry : Sync.header_entry) ->
              Serialize.serialize_block_header w entry.header
            ) headers;
            let cs = Serialize.writer_to_cstruct w in
            respond_binary (Cstruct.to_string cs)
          | Hex ->
            let w = Serialize.writer_create () in
            List.iter (fun (entry : Sync.header_entry) ->
              Serialize.serialize_block_header w entry.header
            ) headers;
            let cs = Serialize.writer_to_cstruct w in
            respond_hex (cstruct_to_hex cs)
          | JSON ->
            let tip_height = match ctx.chain.tip with Some t -> t.height | None -> 0 in
            let json = `List (List.map (fun (entry : Sync.header_entry) ->
              let confirmations = tip_height - entry.height + 1 in
              let median_time = Sync.compute_median_time_past ctx.chain entry.height in
              `Assoc [
                ("hash", `String (Types.hash256_to_hex_display entry.hash));
                ("confirmations", `Int confirmations);
                ("height", `Int entry.height);
                ("version", `Int (Int32.to_int entry.header.version));
                ("versionHex", `String (Printf.sprintf "%08lx" entry.header.version));
                ("merkleroot", `String (Types.hash256_to_hex_display entry.header.merkle_root));
                ("time", `Int (Int32.to_int entry.header.timestamp));
                ("mediantime", `Int (Int32.to_int median_time));
                ("nonce", `Int (Int32.to_int entry.header.nonce));
                ("bits", `String (Printf.sprintf "%08lx" entry.header.bits));
                ("difficulty", `Float (Consensus.difficulty_from_bits entry.header.bits));
                ("chainwork", `String (Types.hash256_to_hex_display entry.total_work));
                ("nTx", `Int 0);  (* Would need to look up block *)
                ("previousblockhash", `String (Types.hash256_to_hex_display entry.header.prev_block));
              ]
            ) headers) in
            respond_json (Yojson.Safe.to_string json)
          | Undefined ->
            respond_error `Not_found ("output format not found (available: " ^ available_formats () ^ ")")

(* ============================================================================
   Block Filter Endpoint (BIP-157/158)
     GET /rest/blockfilter/<filtertype>/<hash>.<format>
     GET /rest/blockfilterheaders/<filtertype>/<hash>.<format>?count=<count>
     GET /rest/blockfilterheaders/<filtertype>/<count>/<hash>.<format>
                                                  (deprecated path form)

   Reference: bitcoin-core/src/rest.cpp:500-711.

   When the filter index is not enabled (the default), Core returns
   HTTP 400 with "Index is not enabled for filtertype <name>"; we mirror
   that exactly so SPV clients can probe and back off cleanly.
   ============================================================================ *)

(* Currently only "basic" (BIP-158 basic filter) is supported, matching
   Core's BlockFilterTypeByName. Returns the parsed type when the name
   matches (case-insensitive), [None] otherwise. *)
let parse_filter_type (name : string) : Block_index.block_filter_type option =
  match String.lowercase_ascii name with
  | "basic" -> Some Block_index.Basic
  | _ -> None

let handle_blockfilter (ctx : Rpc.rpc_context) (_req : Cohttp.Request.t)
    (uri_part : string) =
  let rf, param = parse_data_format uri_part in
  let parts = split_string param '/' in
  match parts with
  | [filtertype_str; hash_str] ->
    (match parse_filter_type filtertype_str with
     | None ->
       respond_error `Bad_request ("Unknown filtertype " ^ filtertype_str)
     | Some _ftype ->
       (match ctx.filter_index with
        | None ->
          respond_error `Bad_request
            ("Index is not enabled for filtertype " ^ filtertype_str)
        | Some idx ->
          (match parse_display_hash hash_str with
           | None ->
             respond_error `Bad_request ("Invalid hash: " ^ hash_str)
           | Some hash ->
             (match Block_index.read_filter idx hash with
              | None ->
                respond_error `Not_found
                  "Filter not found. Block was not connected to active chain."
              | Some bf ->
                (* Encoded filter is the raw GCS bytes per BIP-158. Core's
                   wire format on the REST endpoint is the same compact
                   bytes that get serialized into a `cfilter` P2P message
                   payload. *)
                let encoded = bf.filter.Block_index.encoded in
                (match rf with
                 | Binary ->
                   respond_binary encoded
                 | Hex ->
                   respond_hex (cstruct_to_hex (Cstruct.of_string encoded))
                 | JSON ->
                   let json = `Assoc [
                     ("filter",
                      `String (cstruct_to_hex (Cstruct.of_string encoded)))
                   ] in
                   respond_json (Yojson.Safe.to_string json)
                 | Undefined ->
                   respond_error `Not_found
                     ("output format not found (available: "
                      ^ available_formats () ^ ")"))))))
  | _ ->
    respond_error `Bad_request
      "Invalid URI format. Expected /rest/blockfilter/<filtertype>/<blockhash>"

let handle_blockfilterheaders (ctx : Rpc.rpc_context) (req : Cohttp.Request.t)
    (uri_part : string) =
  let rf, param = parse_data_format uri_part in
  let parts = split_string param '/' in
  let filtertype_str, count_str, hash_str =
    match parts with
    | [ft; hash] ->
      (* New path: /rest/blockfilterheaders/<ft>/<hash>?count=<n> *)
      let count = match get_query_param req "count" with
        | Some c -> c | None -> "5" in
      (ft, count, hash)
    | [ft; count; hash] ->
      (* Deprecated path: /rest/blockfilterheaders/<ft>/<count>/<hash> *)
      (ft, count, hash)
    | _ ->
      ("", "", "")
  in
  if filtertype_str = "" then
    respond_error `Bad_request
      "Invalid URI format. Expected \
       /rest/blockfilterheaders/<filtertype>/<blockhash>.<ext>?count=<count>"
  else match parse_filter_type filtertype_str with
  | None ->
    respond_error `Bad_request ("Unknown filtertype " ^ filtertype_str)
  | Some _ ->
    let count = try int_of_string count_str with _ -> 0 in
    if count < 1 || count > max_headers_results then
      respond_error `Bad_request
        (Printf.sprintf
           "Header count is invalid or out of acceptable range (1-%d): %s"
           max_headers_results count_str)
    else match ctx.filter_index with
    | None ->
      respond_error `Bad_request
        ("Index is not enabled for filtertype " ^ filtertype_str)
    | Some idx ->
      match parse_display_hash hash_str with
      | None ->
        respond_error `Bad_request ("Invalid hash: " ^ hash_str)
      | Some hash ->
        (* FIX-74: Walk forward from [hash] along the active chain.
           Core rest.cpp:rest_filter_header uses LookupBlockIndex(hash)
           and then iterates via active_chain.Next(pindex), guarded by
           active_chain.Contains(pindex).  We mirror that: at each step
           we verify the current entry is on the active chain by
           comparing the header table entry's hash to
           Storage.ChainDB.get_hash_at_height at that entry's height.

           Previously this loop walked active chain via
           get_hash_at_height keyed by [entry.height + 1] without first
           verifying [entry] itself is on the active chain.  When the
           initial [hash] was on an orphan branch, the first emitted
           filter header was the orphan's (BUG-18), then the walk
           silently jumped to the active chain at the next height. *)
        let is_on_active_chain (entry : Sync.header_entry) =
          match Storage.ChainDB.get_hash_at_height ctx.chain.db entry.height with
          | None -> false
          | Some h -> Cstruct.equal h entry.hash
        in
        let rec collect h remaining acc =
          if remaining = 0 then List.rev acc
          else
            match Sync.get_header ctx.chain h with
            | None -> List.rev acc
            | Some entry ->
              if not (is_on_active_chain entry) then List.rev acc
              else
                match Block_index.get_filter_header idx h with
                | None -> List.rev acc  (* index gap → return what we have *)
                | Some fh ->
                  match Storage.ChainDB.get_hash_at_height
                          ctx.chain.db (entry.height + 1) with
                  | None -> List.rev (fh :: acc)
                  | Some next -> collect next (remaining - 1) (fh :: acc)
        in
        let filter_headers = collect hash count [] in
        if filter_headers = [] then
          respond_error `Not_found
            "Filter not found. Block filters are still in the process of being indexed."
        else match rf with
        | Binary ->
          let buf = Buffer.create (32 * List.length filter_headers) in
          List.iter (fun fh -> Buffer.add_string buf (Cstruct.to_string fh))
            filter_headers;
          respond_binary (Buffer.contents buf)
        | Hex ->
          let buf = Buffer.create (64 * List.length filter_headers) in
          List.iter (fun fh ->
            Buffer.add_string buf (cstruct_to_hex fh)) filter_headers;
          respond_hex (Buffer.contents buf)
        | JSON ->
          let json = `List (List.map (fun fh ->
            `String (Types.hash256_to_hex_display fh)) filter_headers) in
          respond_json (Yojson.Safe.to_string json)
        | Undefined ->
          respond_error `Not_found
            ("output format not found (available: "
             ^ available_formats () ^ ")")

(* ============================================================================
   Chain Info Endpoint: GET /rest/chaininfo.json
   ============================================================================ *)

let handle_chaininfo (ctx : Rpc.rpc_context) (_req : Cohttp.Request.t)
    (uri_part : string) =
  let rf, _ = parse_data_format uri_part in
  match rf with
  | JSON ->
    let tip_entry = ctx.chain.tip in
    let tip_height, tip_hash = match tip_entry with
      | Some t -> (t.height, Types.hash256_to_hex_display t.hash)
      | None -> (0, String.make 64 '0')
    in
    let difficulty = match tip_entry with
      | Some t -> Consensus.difficulty_from_bits t.header.bits
      | None -> 1.0
    in
    let chainwork = match tip_entry with
      | Some t -> Types.hash256_to_hex_display t.total_work
      | None -> String.make 64 '0'
    in
    let json = `Assoc [
      ("chain", `String (Rpc.core_chain_name ctx.network.name));
      ("blocks", `Int tip_height);
      ("headers", `Int ctx.chain.headers_synced);
      ("bestblockhash", `String tip_hash);
      ("difficulty", `Float difficulty);
      ("mediantime", `Int 0);
      ("verificationprogress", `Float
        (if ctx.chain.headers_synced = 0 then 0.0
         else float_of_int tip_height /. float_of_int ctx.chain.headers_synced));
      ("initialblockdownload", `Bool (ctx.chain.sync_state <> Sync.FullySynced));
      ("chainwork", `String chainwork);
      ("size_on_disk", `Int 0);
      ("pruned", `Bool (ctx.chain.prune_target > 0));
      ("warnings", `String "");
    ] in
    respond_json (Yojson.Safe.to_string json)
  | _ ->
    respond_error `Not_found "output format not found (available: json)"

(* ============================================================================
   Mempool Info Endpoint: GET /rest/mempool/info.json
   ============================================================================ *)

let handle_mempool_info (ctx : Rpc.rpc_context) (_req : Cohttp.Request.t)
    (uri_part : string) =
  let rf, _ = parse_data_format uri_part in
  match rf with
  | JSON ->
    let (count, total_weight, total_fee) = Mempool.get_info ctx.mempool in
    (* Weight is approximate bytes for mempool size estimation *)
    let bytes_approx = total_weight / 4 in  (* weight to vbytes *)
    let json = `Assoc [
      ("loaded", `Bool true);
      ("size", `Int count);
      ("bytes", `Int bytes_approx);
      ("usage", `Int bytes_approx);
      ("maxmempool", `Int 300_000_000);  (* default 300 MB *)
      (* sat/kvB -> BTC/kvB is /. 1e8 (was /. 100_000.0, a real unit bug:
         it rendered 100 sat/kvB as 0.001 instead of 0.00000100). Read the
         live floor + module incremental constant, matching the RPC. *)
      ("mempoolminfee", `Float (Int64.to_float (Mempool.effective_min_fee ctx.mempool) /. 1e8));
      ("minrelaytxfee", `Float (Int64.to_float ctx.mempool.min_relay_fee /. 1e8));
      ("incrementalrelayfee", `Float (Int64.to_float Mempool.incremental_relay_fee /. 1e8));
      ("unbroadcastcount", `Int 0);
      ("fullrbf", `Bool true);
      ("totalfee", `Float (Int64.to_float total_fee /. 100_000_000.0));
    ] in
    respond_json (Yojson.Safe.to_string json)
  | _ ->
    respond_error `Not_found "output format not found (available: json)"

(* ============================================================================
   Mempool Contents Endpoint: GET /rest/mempool/contents.json
   ============================================================================ *)

let handle_mempool_contents (ctx : Rpc.rpc_context) (req : Cohttp.Request.t)
    (uri_part : string) =
  let rf, _ = parse_data_format uri_part in
  match rf with
  | JSON ->
    let verbose = match get_query_param req "verbose" with
      | Some "false" -> false
      | _ -> true
    in
    (* Get all transactions from mempool *)
    let txs = Mempool.get_all_transactions ctx.mempool in
    let json =
      if verbose then
        `Assoc (List.map (fun tx ->
          let txid = Crypto.compute_txid tx in
          let txid_str = Types.hash256_to_hex_display txid in
          match Mempool.get ctx.mempool txid with
          | None -> (txid_str, `Null)
          | Some entry ->
            let weight = Validation.compute_tx_weight entry.tx in
            let vsize = (weight + 3) / 4 in
            let fees = entry.fee in
            let ancestors = Mempool.get_ancestors ctx.mempool txid in
            let descendants = Mempool.get_descendants ctx.mempool txid in
            (txid_str, `Assoc [
              ("vsize", `Int vsize);
              ("weight", `Int (Validation.compute_tx_weight entry.tx));
              ("fee", `Float (Int64.to_float fees /. 100_000_000.0));
              ("time", `Float entry.time_added);
              ("height", `Int entry.height_added);
              ("descendantcount", `Int (List.length descendants + 1));
              ("descendantsize", `Int vsize);
              ("ancestorcount", `Int (List.length ancestors + 1));
              ("ancestorsize", `Int vsize);
              ("depends", `List (List.map (fun (e : Mempool.mempool_entry) ->
                `String (Types.hash256_to_hex_display e.txid)) ancestors));
              ("spentby", `List (List.map (fun (e : Mempool.mempool_entry) ->
                `String (Types.hash256_to_hex_display e.txid)) descendants));
            ])
        ) txs)
      else
        `List (List.map (fun tx ->
          let txid = Crypto.compute_txid tx in
          `String (Types.hash256_to_hex_display txid)
        ) txs)
    in
    respond_json (Yojson.Safe.to_string json)
  | _ ->
    respond_error `Not_found "output format not found (available: json)"

(* ============================================================================
   Block Hash by Height Endpoint: GET /rest/blockhashbyheight/<height>.<format>
   ============================================================================ *)

let handle_blockhashbyheight (ctx : Rpc.rpc_context) (_req : Cohttp.Request.t)
    (uri_part : string) =
  let rf, height_str = parse_data_format uri_part in
  let height = try int_of_string height_str with _ -> -1 in
  if height < 0 then
    respond_error `Bad_request ("Invalid height: " ^ height_str)
  else
    match Storage.ChainDB.get_hash_at_height ctx.chain.db height with
    | None ->
      respond_error `Not_found "Block height out of range"
    | Some hash ->
      match rf with
      | Binary ->
        respond_binary (Cstruct.to_string hash)
      | Hex ->
        respond_hex (Types.hash256_to_hex_display hash)
      | JSON ->
        let json = `Assoc [("blockhash", `String (Types.hash256_to_hex_display hash))] in
        respond_json (Yojson.Safe.to_string json)
      | Undefined ->
        respond_error `Not_found ("output format not found (available: " ^ available_formats () ^ ")")

(* ============================================================================
   REST Dispatcher
   ============================================================================ *)

(* Helper: prefix test that's safe regardless of path length. *)
let starts_with (s : string) (prefix : string) : bool =
  let n = String.length prefix in
  String.length s >= n && String.sub s 0 n = prefix

(* ============================================================================
   POST /payjoin  (BIP-78 receiver — FIX-65)
   ============================================================================

   Activates the FIX-60 cross-wave dep: [Wallet.process_psbt] is called
   here to sign the receiver's appended input.  Returns the PayjoinPSBT
   base64 on success or one of BIP-78's 4 wire-error envelopes on
   failure.

   Path:  POST /payjoin
   Query: v=1 [&pjos=0|1] [&additionalfeeoutputindex=N]
          [&maxadditionalfeecontribution=SAT] [&minfeerate=F]
   Body:  Content-Type: text/plain, base64-encoded PSBT

   Reference: BIP-78 §"Receiver responses". *)
let handle_payjoin (ctx : Rpc.rpc_context) (req : Cohttp.Request.t)
    (body_str : string) =
  let h = Cohttp.Request.headers req in
  let uri = Cohttp.Request.uri req in
  let query = Uri.query uri in
  let ct_ok = Payjoin.validate_content_type h in
  let respond_payjoin_error err msg =
    let status = Payjoin.error_http_status err in
    let body = Payjoin.error_to_json_string ~message:msg err in
    let headers = Cohttp.Header.init_with "Content-Type" "application/json" in
    Cohttp_lwt_unix.Server.respond_string ~status ~headers ~body ()
  in
  match Payjoin.parse_sender_params query with
  | Error err ->
    (* v=N with N != 1 — version-unsupported per BIP-78. *)
    respond_payjoin_error err "Unsupported PayJoin version (only v=1 supported)"
  | Ok params ->
    (* The receiver wallet is required to be loaded.  Without a wallet
       we have nothing to sign with — emit "unavailable" per spec. *)
    match ctx.Rpc.wallet with
    | None ->
      respond_payjoin_error Payjoin.Unavailable
        "PayJoin receiver wallet not loaded"
    | Some wallet ->
      let result =
        Payjoin.process_request wallet
          ~content_type_ok:ct_ok ~params ~body_b64:body_str
          ~receiver_utxo:None  (* no-op PayJoin: validates + signs the
                                  unmodified OrigPSBT.  Higher-level
                                  RPC may pre-stage a UTXO. *)
          ()
      in
      match result with
      | Error (err, msg) ->
        respond_payjoin_error err msg
      | Ok signed_b64 ->
        let headers = Cohttp.Header.init_with "Content-Type" "text/plain" in
        Cohttp_lwt_unix.Server.respond_string
          ~status:`OK ~headers ~body:signed_b64 ()

let dispatch_rest (ctx : Rpc.rpc_context) (req : Cohttp.Request.t)
    (path : string) =
  (* Route based on path prefix - most specific matches first.
     Ordering rules (longer/more-specific first to avoid ambiguity):
       /rest/blockhashbyheight/    before /rest/block/
       /rest/blockfilterheaders/   before /rest/blockfilter/
       /rest/blockfilter/          before /rest/block/  (block is shortest)
       /rest/block/notxdetails/    before /rest/block/  (notxdetails-then-block)
  *)
  if starts_with path "/rest/blockhashbyheight/" then
    let pfx = String.length "/rest/blockhashbyheight/" in
    let uri_part = String.sub path pfx (String.length path - pfx) in
    handle_blockhashbyheight ctx req uri_part
  else if starts_with path "/rest/blockfilterheaders/" then
    let pfx = String.length "/rest/blockfilterheaders/" in
    let uri_part = String.sub path pfx (String.length path - pfx) in
    handle_blockfilterheaders ctx req uri_part
  else if starts_with path "/rest/blockfilter/" then
    let pfx = String.length "/rest/blockfilter/" in
    let uri_part = String.sub path pfx (String.length path - pfx) in
    handle_blockfilter ctx req uri_part
  else if starts_with path "/rest/block/notxdetails/" then
    let pfx = String.length "/rest/block/notxdetails/" in
    let uri_part = String.sub path pfx (String.length path - pfx) in
    handle_block_notxdetails ctx req uri_part
  else if starts_with path "/rest/block/" then
    let pfx = String.length "/rest/block/" in
    let uri_part = String.sub path pfx (String.length path - pfx) in
    handle_block ctx req uri_part
  else if String.length path > 9 && String.sub path 0 9 = "/rest/tx/" then
    let uri_part = String.sub path 9 (String.length path - 9) in
    handle_tx ctx req uri_part
  else if String.length path > 14 && String.sub path 0 14 = "/rest/headers/" then
    let uri_part = String.sub path 14 (String.length path - 14) in
    handle_headers ctx req uri_part
  else if String.length path >= 15 && String.sub path 0 15 = "/rest/chaininfo" then
    let uri_part = String.sub path 15 (String.length path - 15) in
    handle_chaininfo ctx req uri_part
  else if String.length path > 21 && String.sub path 0 18 = "/rest/mempool/info" then
    let uri_part = String.sub path 18 (String.length path - 18) in
    handle_mempool_info ctx req uri_part
  else if String.length path > 25 && String.sub path 0 22 = "/rest/mempool/contents" then
    let uri_part = String.sub path 22 (String.length path - 22) in
    handle_mempool_contents ctx req uri_part
  else if String.length path > 13 && String.sub path 0 13 = "/rest/mempool" then
    let uri_part = String.sub path 13 (String.length path - 13) in
    (* Route to info or contents based on path *)
    if String.length uri_part > 5 && String.sub uri_part 0 5 = "/info" then
      handle_mempool_info ctx req (String.sub uri_part 5 (String.length uri_part - 5))
    else if String.length uri_part > 9 && String.sub uri_part 0 9 = "/contents" then
      handle_mempool_contents ctx req (String.sub uri_part 9 (String.length uri_part - 9))
    else
      respond_error `Bad_request "Invalid URI format. Expected /rest/mempool/<info|contents>.json"
  else
    respond_error `Not_found "Not found"

(* ============================================================================
   REST Server
   ============================================================================ *)

(* W119 / FIX-64: optional HTTPS/TLS termination on the REST listener.
   Semantics match Rpc.start_rpc_server. *)
let start_rest_server ~(ctx : Rpc.rpc_context)
    ~(host : string) ~(port : int)
    ?(tls_cert_path : string option = None)
    ?(tls_key_path : string option = None)
    () : unit Lwt.t =
  let callback _conn req body =
    let meth = Cohttp.Request.meth req in
    let uri = Cohttp.Request.uri req in
    let path = Uri.path uri in

    (* FIX-65: BIP-78 PayJoin receiver — POST /payjoin only.  Routed
       before the REST GET-only guard so the POST path is reachable. *)
    if meth = `POST && (path = "/payjoin" || path = "/payjoin/") then
      Lwt.bind (Cohttp_lwt.Body.to_string body) (fun body_str ->
        handle_payjoin ctx req body_str)
    (* REST only accepts GET requests *)
    else if meth <> `GET then
      respond_error `Method_not_allowed "Method not allowed"
    (* Only handle /rest/* paths *)
    else if String.length path < 6 || String.sub path 0 6 <> "/rest/" then
      respond_error `Not_found "Not found"
    else
      dispatch_rest ctx req path
  in

  let server = Cohttp_lwt_unix.Server.make ~callback () in
  let mode : Conduit_lwt_unix.server =
    match tls_cert_path, tls_key_path with
    | None, None ->
      Logs.info (fun m -> m "REST server listening on %s:%d (HTTP, plaintext)" host port);
      `TCP (`Port port)
    | Some cert, Some key ->
      if not (Sys.file_exists cert) then begin
        Logs.err (fun m -> m "REST TLS cert file does not exist: %s" cert);
        failwith ("REST TLS cert file not found: " ^ cert)
      end;
      if not (Sys.file_exists key) then begin
        Logs.err (fun m -> m "REST TLS key file does not exist: %s" key);
        failwith ("REST TLS key file not found: " ^ key)
      end;
      Logs.info (fun m ->
        m "REST server listening on %s:%d (HTTPS, cert=%s key=%s)"
          host port cert key);
      `TLS (`Crt_file_path cert,
            `Key_file_path key,
            `No_password,
            `Port port)
    | Some _, None ->
      Logs.err (fun m ->
        m "--rest-tls-cert was set but --rest-tls-key was not.");
      failwith "REST TLS: cert provided without key"
    | None, Some _ ->
      Logs.err (fun m ->
        m "--rest-tls-key was set but --rest-tls-cert was not.");
      failwith "REST TLS: key provided without cert"
  in
  Cohttp_lwt_unix.Server.create ~mode server

(* Default REST port *)
let default_port () = 8080
