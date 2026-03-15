(* Block Template Construction and Mining

   This module provides block template construction for mining:
   - Transaction selection from mempool by fee rate
   - Coinbase transaction generation with correct subsidy/fees
   - Merkle tree computation with SegWit witness commitment
   - BIP-22/BIP-23 compatible getblocktemplate response

   The coinbase transaction includes:
   - BIP-34 block height encoding in scriptSig
   - Extra nonce space for mining variance
   - SegWit witness commitment output (OP_RETURN)

   KNOWN PITFALL: The witness commitment must be computed from the
   witness merkle root (with coinbase witness = 32 zero bytes) and
   a witness nonce (also 32 zero bytes by convention). *)

let log_src = Logs.Src.create "MINING" ~doc:"Mining"
module Log = (val Logs.src_log log_src : Logs.LOG)
let _ = Log.info  (* suppress unused module warning *)

(* ============================================================================
   Block Template Type
   ============================================================================ *)

type block_template = {
  header : Types.block_header;
  coinbase_tx : Types.transaction;
  transactions : Types.transaction list;
  tx_fees : int64 list;  (* per-transaction fees, same order as transactions *)
  total_fee : int64;
  total_weight : int;
  height : int;
  target : Cstruct.t;
}

(* ============================================================================
   Transaction Selection
   ============================================================================ *)

(* Reserve weight units for coinbase transaction *)
let coinbase_reserve_weight = 4000

(* Compute ancestor fee rate for a transaction, skipping already-selected ancestors.
   ancestor_fee_rate = (tx_fee + sum of unselected ancestor fees) /
                       (tx_weight + sum of unselected ancestor weights) *)
let compute_ancestor_fee_rate (entry : Mempool.mempool_entry)
    (mp : Mempool.mempool) (selected : (string, unit) Hashtbl.t) : float =
  let ancestors = Mempool.get_ancestors mp entry.txid in
  let unselected_ancestors = List.filter (fun (a : Mempool.mempool_entry) ->
    not (Hashtbl.mem selected (Cstruct.to_string a.txid))
  ) ancestors in
  let total_fee = List.fold_left
    (fun acc (a : Mempool.mempool_entry) -> Int64.add acc a.fee)
    entry.fee unselected_ancestors in
  let total_weight = List.fold_left
    (fun acc (a : Mempool.mempool_entry) -> acc + a.weight)
    entry.weight unselected_ancestors in
  if total_weight = 0 then 0.0
  else Int64.to_float total_fee /. float_of_int total_weight

(* Select transactions from mempool using ancestor fee rate (CPFP).
   Pre-sorts by ancestor fee rate and iterates in descending order,
   re-evaluating rates only when ancestors are consumed. *)
let select_transactions (mp : Mempool.mempool) (max_weight : int)
    : (Types.transaction * int64) list =
  let all_entries = Mempool.get_sorted_transactions mp in
  let selected = ref [] in
  let current_weight = ref 0 in
  let total_sigops_cost = ref 0 in
  let included_txids = Hashtbl.create 100 in
  let available_weight = max_weight - coinbase_reserve_weight in

  (* Pre-compute ancestor fee rates and sort descending *)
  let rated_entries = List.map (fun (entry : Mempool.mempool_entry) ->
    let rate = compute_ancestor_fee_rate entry mp included_txids in
    (rate, entry)
  ) all_entries in
  let sorted = List.sort (fun (r1, _) (r2, _) -> compare r2 r1) rated_entries in

  List.iter (fun (_, (best_entry : Mempool.mempool_entry)) ->
    let key = Cstruct.to_string best_entry.txid in
    if Hashtbl.mem included_txids key then ()
    else begin
      let ancestors = Mempool.get_ancestors mp best_entry.txid in
      let unselected_ancestors = List.filter (fun (a : Mempool.mempool_entry) ->
        not (Hashtbl.mem included_txids (Cstruct.to_string a.txid))
      ) ancestors in
      let package = unselected_ancestors @ [best_entry] in

      let pkg_weight = List.fold_left
        (fun acc (e : Mempool.mempool_entry) -> acc + e.weight)
        0 package in

      let pkg_sigops = List.fold_left (fun acc (e : Mempool.mempool_entry) ->
        acc + Mempool.count_tx_sigops_cost e.tx
      ) 0 package in

      if !total_sigops_cost + pkg_sigops > Consensus.max_block_sigops_cost then
        ()
      else if !current_weight + pkg_weight <= available_weight then begin
        List.iter (fun (e : Mempool.mempool_entry) ->
          let ekey = Cstruct.to_string e.txid in
          if not (Hashtbl.mem included_txids ekey) then begin
            selected := (e.tx, e.fee) :: !selected;
            current_weight := !current_weight + e.weight;
            Hashtbl.replace included_txids ekey ()
          end
        ) package;
        total_sigops_cost := !total_sigops_cost + pkg_sigops
      end
    end
  ) sorted;

  List.rev !selected

(* ============================================================================
   Witness Commitment Computation
   ============================================================================ *)

(* Compute witness transaction ID (wtxid).
   For coinbase, wtxid is always zero.
   For other transactions, wtxid includes witness data. *)
let compute_wtxid (tx : Types.transaction) (is_coinbase : bool) : Types.hash256 =
  if is_coinbase then
    Types.zero_hash
  else begin
    let w = Serialize.writer_create () in
    Serialize.serialize_transaction w tx;
    Crypto.sha256d (Serialize.writer_to_cstruct w)
  end

(* Compute the witness merkle root from a list of transactions.
   The first transaction (coinbase) has wtxid = 0. *)
let compute_witness_merkle_root (transactions : Types.transaction list)
    : Types.hash256 =
  let wtxids = List.mapi (fun i tx ->
    compute_wtxid tx (i = 0)
  ) transactions in
  let (root, _mutated) = Crypto.merkle_root wtxids in
  root

(* Compute the witness commitment for the coinbase output.
   commitment = SHA256d(witness_merkle_root || witness_nonce)
   where witness_nonce is 32 zero bytes by convention. *)
let compute_witness_commitment (witness_root : Types.hash256) : Types.hash256 =
  let witness_nonce = Cstruct.create 32 in  (* 32 zero bytes *)
  let combined = Cstruct.concat [witness_root; witness_nonce] in
  Crypto.sha256d combined

(* Build the OP_RETURN script for witness commitment.
   Format: OP_RETURN OP_PUSHBYTES_36 <marker><commitment>
   Marker is: 0xaa21a9ed *)
let build_witness_commitment_script (commitment : Types.hash256) : Cstruct.t =
  let prefix = Cstruct.create 6 in
  Cstruct.set_uint8 prefix 0 0x6a;  (* OP_RETURN *)
  Cstruct.set_uint8 prefix 1 0x24;  (* OP_PUSHBYTES_36 *)
  Cstruct.set_uint8 prefix 2 0xaa;  (* witness marker bytes *)
  Cstruct.set_uint8 prefix 3 0x21;
  Cstruct.set_uint8 prefix 4 0xa9;
  Cstruct.set_uint8 prefix 5 0xed;
  Cstruct.concat [prefix; commitment]

(* ============================================================================
   Coinbase Transaction Creation
   ============================================================================ *)

(* Create a coinbase transaction for the given height.

   Parameters:
   - height: Block height (for BIP-34 encoding and subsidy calculation)
   - total_fee: Total fees from included transactions
   - payout_script: scriptPubKey for the mining reward output
   - extra_nonce: Extra nonce bytes for mining variance (usually 8 bytes)
   - witness_root: Optional witness merkle root for SegWit commitment *)
let create_coinbase ~(height : int) ~(total_fee : int64)
    ~(payout_script : Cstruct.t) ~(extra_nonce : Cstruct.t)
    ~(witness_root : Types.hash256 option) : Types.transaction =

  let subsidy = Consensus.block_subsidy height in
  let reward = Int64.add subsidy total_fee in

  (* Build coinbase scriptSig: height encoding + extra nonce *)
  let height_bytes = Consensus.encode_height_in_coinbase height in
  let coinbase_script = Cstruct.concat [height_bytes; extra_nonce] in

  (* Coinbase input: null outpoint *)
  let coinbase_input : Types.tx_in = {
    previous_output = {
      txid = Types.zero_hash;
      vout = 0xFFFFFFFFl;
    };
    script_sig = coinbase_script;
    sequence = 0xFFFFFFFFl;
  } in

  (* Primary payout output *)
  let payout_output : Types.tx_out = {
    value = reward;
    script_pubkey = payout_script;
  } in

  (* Build outputs list *)
  let outputs, witnesses = match witness_root with
    | Some root ->
      (* Add SegWit witness commitment output *)
      let commitment = compute_witness_commitment root in
      let commitment_script = build_witness_commitment_script commitment in
      let commitment_output : Types.tx_out = {
        value = 0L;
        script_pubkey = commitment_script;
      } in
      (* Coinbase witness is a single 32-byte zero value *)
      let coinbase_witness : Types.tx_witness = {
        items = [Cstruct.create 32];
      } in
      ([payout_output; commitment_output], [coinbase_witness])
    | None ->
      (* No witness commitment needed *)
      ([payout_output], [])
  in

  {
    version = 2l;
    inputs = [coinbase_input];
    outputs;
    witnesses;
    locktime = 0l;
  }

(* ============================================================================
   Block Template Construction
   ============================================================================ *)

(* Build a complete block template from current chain state and mempool.

   Parameters:
   - chain: Current chain state with tip
   - mp: Mempool with unconfirmed transactions
   - payout_script: scriptPubKey for mining reward

   Returns a block template ready for mining (just need to find valid nonce). *)
let create_block_template ~(chain : Sync.chain_state)
    ~(mp : Mempool.mempool) ~(payout_script : Cstruct.t) : block_template =

  let tip = match chain.tip with
    | Some t -> t
    | None -> failwith "No chain tip"
  in

  let height = tip.height + 1 in

  (* Select transactions from mempool *)
  let selected = select_transactions mp Consensus.max_block_weight in

  (* Calculate total fees *)
  let total_fee = List.fold_left
    (fun acc (_, fee) -> Int64.add acc fee) 0L selected in

  (* Extract transactions and per-transaction fees *)
  let selected_txs = List.map fst selected in
  let tx_fees = List.map snd selected in

  (* Create extra nonce (8 bytes of random data) *)
  let extra_nonce = Cstruct.create 8 in
  (* In production, this would be randomized. For now, use timestamp-based *)
  let ts = Int64.of_float (Unix.gettimeofday () *. 1000000.0) in
  Cstruct.LE.set_uint64 extra_nonce 0 ts;

  (* Compute witness merkle root for SegWit commitment.
     We need to include the coinbase (with wtxid=0) and all selected txs. *)
  let placeholder_coinbase =
    create_coinbase ~height ~total_fee ~payout_script ~extra_nonce
      ~witness_root:None in
  let all_txs_for_witness = placeholder_coinbase :: selected_txs in
  let witness_root = compute_witness_merkle_root all_txs_for_witness in

  (* Create final coinbase with witness commitment *)
  let coinbase_tx =
    create_coinbase ~height ~total_fee ~payout_script ~extra_nonce
      ~witness_root:(Some witness_root) in

  (* Build final transaction list for merkle root *)
  let all_txs = coinbase_tx :: selected_txs in
  let txids = List.map Crypto.compute_txid all_txs in
  let (merkle_root, _mutated) = Crypto.merkle_root txids in

  (* Calculate median-time-past to ensure our timestamp is valid.
     Collect timestamps from tip and its ancestors (up to 11 total). *)
  let rec collect_ts acc count entry =
    if count >= 11 then acc
    else
      let acc = entry.Sync.header.timestamp :: acc in
      if entry.height = 0 then acc
      else
        let parent_key = Cstruct.to_string entry.header.prev_block in
        match Hashtbl.find_opt chain.headers parent_key with
        | Some parent -> collect_ts acc (count + 1) parent
        | None -> acc
  in
  let ancestor_ts = collect_ts [] 0 tip in
  let mtp = Consensus.median_time_past ancestor_ts in

  (* Current timestamp - ensure it's greater than MTP *)
  let now = Int32.of_float (Unix.gettimeofday ()) in
  let timestamp = max (Int32.add mtp 1l) now in

  (* Compute correct difficulty target using consensus rules *)
  let bits =
    let get_block_info h =
      let rec find_entry (entry : Sync.header_entry) =
        if entry.Sync.height = h then
          (entry.Sync.header.timestamp, entry.Sync.header.bits)
        else if entry.height = 0 then
          (entry.Sync.header.timestamp, entry.Sync.header.bits)
        else
          let parent_key = Cstruct.to_string entry.header.prev_block in
          match Hashtbl.find_opt chain.headers parent_key with
          | Some parent -> find_entry parent
          | None -> (entry.Sync.header.timestamp, entry.Sync.header.bits)
      in
      find_entry tip
    in
    Consensus.get_next_work_required
      ~height
      ~block_time:timestamp
      ~prev_block_time:tip.header.timestamp
      ~prev_bits:tip.header.bits
      ~get_block_info
      ~network:chain.network
  in

  (* Compute block version with BIP-9 deployment signaling *)
  let version =
    let get_block h =
      match Sync.get_header_at_height chain h with
      | None -> None
      | Some entry ->
        let mtp = Int64.of_int32 (Sync.compute_median_time_past chain entry.height) in
        Some Consensus.{ height = entry.height; version = entry.header.version; median_time_past = mtp }
    in
    let taproot_dep = match chain.network.name with
      | "mainnet" -> Consensus.mainnet_taproot
      | "testnet4" -> Consensus.testnet4_taproot
      | _ -> Consensus.regtest_taproot
    in
    let deployments = [taproot_dep; Consensus.testdummy_deployment] in
    let vb_cache = Consensus.create_versionbits_cache () in
    let caches = [
      (Consensus.Deployment_taproot, vb_cache.taproot);
      (Consensus.Deployment_testdummy, vb_cache.testdummy);
    ] in
    Consensus.compute_block_version ~deployments ~height ~get_block ~caches
  in

  let header : Types.block_header = {
    version;
    prev_block = tip.hash;
    merkle_root;
    timestamp;
    bits;
    nonce = 0l;
  } in

  (* Calculate total weight *)
  let total_weight = List.fold_left (fun acc tx ->
    acc + Validation.compute_tx_weight tx
  ) 0 all_txs in

  {
    header;
    coinbase_tx;
    transactions = selected_txs;
    tx_fees;
    total_fee;
    total_weight;
    height;
    target = Consensus.compact_to_target bits;
  }

(* ============================================================================
   Simple CPU Miner (for regtest)
   ============================================================================ *)

(* Mine a block by incrementing the nonce until the hash meets the target.
   Returns Some block if successful within max_nonce attempts, None otherwise.

   NOTE: This is a simple CPU miner intended for regtest testing only.
   Real mining uses ASICs and pool protocols like Stratum. *)
let mine_block (template : block_template) (max_nonce : int32)
    : Types.block option =

  let header = ref template.header in
  let found = ref false in
  let nonce = ref 0l in

  while not !found && Int32.compare !nonce max_nonce < 0 do
    header := { !header with nonce = !nonce };
    let hash = Crypto.compute_block_hash !header in

    if Consensus.hash_meets_target hash !header.bits then begin
      found := true
    end else
      nonce := Int32.add !nonce 1l
  done;

  if !found then
    Some {
      header = !header;
      transactions = template.coinbase_tx :: template.transactions;
    }
  else
    None

(* Mine a block with extended nonce space using timestamp rolling.
   This allows mining beyond the 2^32 nonce space by updating the
   timestamp periodically. *)
let mine_block_extended (template : block_template)
    ~(max_iterations : int) ~(nonces_per_iteration : int32)
    : Types.block option =

  let result = ref None in
  let iteration = ref 0 in
  let base_timestamp = template.header.timestamp in

  while !result = None && !iteration < max_iterations do
    (* Update timestamp for this iteration *)
    let timestamp = Int32.add base_timestamp (Int32.of_int !iteration) in
    let current_template = {
      template with
      header = { template.header with timestamp }
    } in

    result := mine_block current_template nonces_per_iteration;
    incr iteration
  done;

  !result

(* ============================================================================
   Getblocktemplate RPC Response (BIP-22/BIP-23)
   ============================================================================ *)

(* Serialize a transaction to hex string *)
let tx_to_hex (tx : Types.transaction) : string =
  let w = Serialize.writer_create () in
  Serialize.serialize_transaction w tx;
  let cs = Serialize.writer_to_cstruct w in
  let buf = Buffer.create (Cstruct.length cs * 2) in
  for i = 0 to Cstruct.length cs - 1 do
    Buffer.add_string buf (Printf.sprintf "%02x" (Cstruct.get_uint8 cs i))
  done;
  Buffer.contents buf

(* Convert a block template to BIP-22/BIP-23 JSON format.
   This is the format expected by mining software. *)
let template_to_json (template : block_template) : Yojson.Safe.t =
  (* Build txid -> index map for depends *)
  let txid_to_idx = Hashtbl.create 16 in
  List.iteri (fun i tx ->
    let txid = Crypto.compute_txid tx in
    Hashtbl.replace txid_to_idx (Cstruct.to_string txid) (i + 1)
  ) template.transactions;

  let txs_json = List.mapi (fun _i tx ->
    let txid = Crypto.compute_txid tx in
    let fee = List.nth template.tx_fees _i in
    (* Find depends: which inputs reference other template txs *)
    let depends = List.filter_map (fun (inp : Types.tx_in) ->
      Hashtbl.find_opt txid_to_idx (Cstruct.to_string inp.previous_output.txid)
    ) tx.inputs in
    `Assoc [
      ("data", `String (tx_to_hex tx));
      ("txid", `String (Types.hash256_to_hex_display txid));
      ("fee", `Int (Int64.to_int fee));
      ("depends", `List (List.map (fun i -> `Int i) depends));
      ("sigops", `Int (Mempool.count_tx_sigops_cost tx));
      ("weight", `Int (Validation.compute_tx_weight tx));
    ]
  ) template.transactions in

  (* Compute the default witness commitment script for miners *)
  let all_txs = template.coinbase_tx :: template.transactions in
  let witness_root = compute_witness_merkle_root all_txs in
  let commitment = compute_witness_commitment witness_root in
  let commitment_script = build_witness_commitment_script commitment in
  let commitment_hex =
    let buf = Buffer.create (Cstruct.length commitment_script * 2) in
    for i = 0 to Cstruct.length commitment_script - 1 do
      Buffer.add_string buf (Printf.sprintf "%02x" (Cstruct.get_uint8 commitment_script i))
    done;
    Buffer.contents buf
  in

  `Assoc [
    ("version", `Int (Int32.to_int template.header.version));
    ("previousblockhash",
      `String (Types.hash256_to_hex_display template.header.prev_block));
    ("transactions", `List txs_json);
    ("coinbasevalue",
      `String (Int64.to_string
        (Int64.add
          (Consensus.block_subsidy template.height)
          template.total_fee)));
    ("target",
      `String (Types.hash256_to_hex template.target));
    ("mintime",
      `Int (Int32.to_int template.header.timestamp));
    ("mutable",
      `List [`String "time"; `String "transactions"; `String "prevblock"]);
    ("noncerange", `String "00000000ffffffff");
    ("sigoplimit", `Int Consensus.max_block_sigops_cost);
    ("sizelimit", `Int 1000000);
    ("weightlimit", `Int Consensus.max_block_weight);
    ("curtime",
      `Int (Int32.to_int template.header.timestamp));
    ("bits",
      `String (Printf.sprintf "%08lx" template.header.bits));
    ("height", `Int template.height);
    ("default_witness_commitment", `String commitment_hex);
  ]

(* Simplified getblocktemplate response for basic mining *)
let template_to_json_simple (template : block_template) : Yojson.Safe.t =
  `Assoc [
    ("version", `Int (Int32.to_int template.header.version));
    ("previousblockhash",
      `String (Types.hash256_to_hex_display template.header.prev_block));
    ("merkleroot",
      `String (Types.hash256_to_hex_display template.header.merkle_root));
    ("curtime", `Int (Int32.to_int template.header.timestamp));
    ("bits", `String (Printf.sprintf "%08lx" template.header.bits));
    ("height", `Int template.height);
    ("coinbasevalue",
      `String (Int64.to_string
        (Int64.add
          (Consensus.block_subsidy template.height)
          template.total_fee)));
    ("transactions", `Int (List.length template.transactions));
    ("total_fee", `String (Int64.to_string template.total_fee));
    ("total_weight", `Int template.total_weight);
  ]

(* ============================================================================
   Block Submission
   ============================================================================ *)

(* Submit a mined block to the network.
   Returns Ok() if the block is valid and was accepted. *)
let submit_block (block : Types.block) (chain : Sync.chain_state)
    (mp : Mempool.mempool) : (unit, string) result =

  let hash = Crypto.compute_block_hash block.header in

  (* Validate the block header *)
  match Validation.check_block_header block.header with
  | Error e -> Error e
  | Ok () ->
    (* Get expected values from chain *)
    match chain.tip with
    | None -> Error "No chain tip"
    | Some tip ->
      if not (Cstruct.equal block.header.prev_block tip.hash) then
        Error "Block does not build on current tip"
      else begin
        let height = tip.height + 1 in

        (* Validate the full block *)
        match Sync.validate_header chain block.header with
        | Error e -> Error e
        | Ok entry ->
          (* Accept the header *)
          Sync.accept_header chain entry;

          (* Store the block *)
          Storage.ChainDB.store_block chain.db hash block;
          Storage.ChainDB.set_chain_tip chain.db hash height;

          (* Remove confirmed transactions from mempool *)
          Mempool.remove_for_block mp block height;

          Logs.info (fun m -> m "Accepted mined block at height %d: %s"
            height (Types.hash256_to_hex_display hash));

          Ok ()
      end
