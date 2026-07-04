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
  network_type : Consensus.network;  (* For correct halving interval in JSON *)
  transactions_updated : int;  (* mempool entry count at template creation time; used for longpollid *)
}

(* ============================================================================
   Transaction Selection
   ============================================================================ *)

(* Reserve weight units for coinbase + block header overhead.
   Mirrors Bitcoin Core policy.h:
     DEFAULT_BLOCK_RESERVED_WEIGHT = 8000   (resetBlock starts nBlockWeight here)
     MINIMUM_BLOCK_RESERVED_WEIGHT = 2000   (lower clamp in ClampOptions)
   The available weight for transactions is:
     nBlockMaxWeight (4_000_000) - block_reserved_weight (8_000) = 3_992_000
   Reference: bitcoin-core/src/node/miner.cpp resetBlock(), policy.h:27-34 *)
let default_block_reserved_weight = 8000
let minimum_block_reserved_weight = 2000
let max_consecutive_failures = 1000
let block_full_enough_weight_delta = 4000

(* Clamp a user-supplied reserved weight into [minimum, max_block_weight].
   Mirrors ClampOptions() in bitcoin-core/src/node/miner.cpp:79-88. *)
let clamp_reserved_weight w =
  max minimum_block_reserved_weight (min w Consensus.max_block_weight)

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
   re-evaluating rates only when ancestors are consumed.

   Parameters:
   - max_weight: nBlockMaxWeight (usually Consensus.max_block_weight = 4_000_000)
   - reserved_weight: block_reserved_weight (default DEFAULT_BLOCK_RESERVED_WEIGHT = 8_000)
   - min_fee_rate_sat_per_kvb: minimum acceptable fee rate in sat/kvB (0 = no minimum)
   - block_height: height of the block being assembled (for IsFinalTx)
   - lock_time_cutoff: MTP of prev block (for IsFinalTx, BIP-113)

   Mirrors the addChunks() / TestChunkBlockLimits() / TestChunkTransactions() logic
   in bitcoin-core/src/node/miner.cpp:239-333. *)
let select_transactions ?(reserved_weight = default_block_reserved_weight)
    ?(min_fee_rate_sat_per_kvb = 0)
    ?(block_height = 1)
    ?(lock_time_cutoff = 0l)
    (mp : Mempool.mempool) (max_weight : int)
    : (Types.transaction * int64) list =
  (* Clamp reserved weight: [MINIMUM_BLOCK_RESERVED_WEIGHT, MAX_BLOCK_WEIGHT].
     Mirrors ClampOptions in miner.cpp:79-88. *)
  let reserved = clamp_reserved_weight reserved_weight in
  (* nBlockWeight starts at reserved_weight; available for txs = max - reserved.
     Core: nBlockWeight += entry.GetTxWeight() and gate is
       nBlockWeight + chunk >= nBlockMaxWeight  ⟹  refuse if true.
     Equivalently: allow only if current_weight + pkg_weight < (max - reserved). *)
  let available_weight = max_weight - reserved in

  let all_entries = Mempool.get_sorted_transactions mp in
  let selected = ref [] in
  let current_weight = ref 0 in
  let total_sigops_cost = ref 0 in
  let n_consecutive_failed = ref 0 in
  let included_txids = Hashtbl.create 100 in

  (* Pre-compute ancestor fee rates and sort descending *)
  let rated_entries = List.map (fun (entry : Mempool.mempool_entry) ->
    let rate = compute_ancestor_fee_rate entry mp included_txids in
    (rate, entry)
  ) all_entries in
  let sorted = List.sort (fun (r1, _) (r2, _) -> compare r2 r1) rated_entries in

  let done_ = ref false in
  List.iter (fun (rate, (best_entry : Mempool.mempool_entry)) ->
    if !done_ then ()
    else begin
      (* BUG 3 fixed: blockMinFeeRate gate — mirrors miner.cpp:297-301.
         min_fee_rate_sat_per_kvb is sat per 1000 virtual bytes = sat per 1000 wu/4.
         rate is sat per weight unit (sat/wu).  Convert: min_rate_sat_per_wu =
         min_fee_rate_sat_per_kvb / 4000.0 (1 kvB = 4000 wu).
         Skip this chunk (and all cheaper ones — feerate-sorted) if rate is too low. *)
      if min_fee_rate_sat_per_kvb > 0 then begin
        let min_rate_sat_per_wu = float_of_int min_fee_rate_sat_per_kvb /. 4000.0 in
        if rate < min_rate_sat_per_wu then begin
          done_ := true  (* everything remaining is cheaper — stop *)
        end
      end;
      if not !done_ then begin
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
            acc + Mempool.count_tx_sigops_cost e.tx mp
          ) 0 package in

          (* BUG 1 fixed: TestChunkTransactions — IsFinalTx check.
             Core miner.cpp:252-259: for each tx in chunk, check IsFinalTx with
             (nHeight, m_lock_time_cutoff=pindexPrev->GetMedianTimePast()).
             Without this, non-final transactions (future locktime) can be
             included in block templates, which validators will reject.
             Reference: bitcoin-core/src/node/miner.cpp TestChunkTransactions. *)
          let chunk_is_final = List.for_all (fun (e : Mempool.mempool_entry) ->
            Validation.is_tx_final e.tx ~block_height ~block_time:lock_time_cutoff
          ) package in

          (* BUG 2 fixed: sigops gate uses >= (not >) matching Core miner.cpp:244.
             Core: if (nBlockSigOpsCost + chunk_sigops_cost >= MAX_BLOCK_SIGOPS_COST) return false
             Previous code used >, allowing one extra sigop up to = 80000. *)
          let sigops_ok = !total_sigops_cost + pkg_sigops < Consensus.max_block_sigops_cost in

          (* Weight gate: allow if current + pkg < available (strict less-than).
             Core: nBlockWeight + chunk_size >= nBlockMaxWeight → refuse.
             Equivalent: allow when current_weight + pkg_weight < available_weight.
             This correctly reserves space for the coinbase / block overhead. *)
          let weight_ok = !current_weight + pkg_weight < available_weight in

          if not (sigops_ok && weight_ok && chunk_is_final) then begin
            (* Chunk doesn't fit or is non-final — skip it.
               BUG 4 fixed: MAX_CONSECUTIVE_FAILURES early exit.
               Core miner.cpp:313-317: after 1000 consecutive failures, quit if block
               is "full enough" (within BLOCK_FULL_ENOUGH_WEIGHT_DELTA=4000 of limit).
               This prevents O(N) iteration over a full mempool when the block is close
               to weight-limit. *)
            incr n_consecutive_failed;
            if !n_consecutive_failed > max_consecutive_failures &&
               !current_weight + block_full_enough_weight_delta > available_weight then
              done_ := true
          end else begin
            n_consecutive_failed := 0;
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
   - witness_root: Optional witness merkle root for SegWit commitment
   - network_type: Network variant (regtest uses shorter halving interval) *)
let create_coinbase ~(height : int) ~(total_fee : int64)
    ~(payout_script : Cstruct.t) ~(extra_nonce : Cstruct.t)
    ~(witness_root : Types.hash256 option)
    ?(network_type : Consensus.network = Consensus.Mainnet) () : Types.transaction =

  let subsidy = Consensus.block_subsidy_for_network network_type height in
  let reward = Int64.add subsidy total_fee in

  (* Build coinbase scriptSig: height encoding + extra nonce *)
  let height_bytes = Consensus.encode_height_in_coinbase height in
  let coinbase_script = Cstruct.concat [height_bytes; extra_nonce] in

  (* Coinbase input: null outpoint.
     BUG 5 fixed: sequence must be MAX_SEQUENCE_NONFINAL (0xFFFFFFFE), not 0xFFFFFFFF.
     Core miner.cpp:171: coinbaseTx.vin[0].nSequence = CTxIn::MAX_SEQUENCE_NONFINAL
     Comment: "Make sure timelock is enforced."
     0xFFFFFFFF (SEQUENCE_FINAL) disables nLockTime enforcement; 0xFFFFFFFE keeps it
     active so the nLockTime = height-1 rule is honoured by validators.
     Reference: bitcoin-core/src/node/miner.cpp:171,
                bitcoin-core/src/primitives/transaction.h:76,82 *)
  let coinbase_input : Types.tx_in = {
    previous_output = {
      txid = Types.zero_hash;
      vout = 0xFFFFFFFFl;
    };
    script_sig = coinbase_script;
    sequence = 0xFFFFFFFEl;  (* CTxIn::MAX_SEQUENCE_NONFINAL — NOT 0xFFFFFFFF *)
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

  (* BUG 6 fixed: coinbase locktime must be nHeight - 1, not 0.
     Core miner.cpp:196: coinbaseTx.nLockTime = static_cast<uint32_t>(nHeight - 1)
     This works together with sequence = 0xFFFFFFFE: the locktime is the *last invalid*
     height, so nLockTime = height-1 means the coinbase is valid at height (strictly
     greater). Without this, the locktime is 0 (always valid), which is technically fine
     for consensus, but deviates from Core's canonical coinbase format and would cause
     getblocktemplate clients (and test vectors) expecting height-1 to diverge.
     Reference: bitcoin-core/src/node/miner.cpp:196 *)
  {
    version = 2l;
    inputs = [coinbase_input];
    outputs;
    witnesses;
    locktime = Int32.of_int (max 0 (height - 1));
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

  (* Select transactions from mempool.
     Pass block_height and lock_time_cutoff (MTP of prev block) for IsFinalTx checks.
     Core miner.cpp:148: m_lock_time_cutoff = pindexPrev->GetMedianTimePast().
     Default reserved_weight = DEFAULT_BLOCK_RESERVED_WEIGHT (8000). *)
  let tip_ts_list =
    let rec collect acc count entry =
      if count >= 11 then acc
      else
        let acc = entry.Sync.header.timestamp :: acc in
        if entry.height = 0 then acc
        else
          let parent_key = Cstruct.to_string entry.header.prev_block in
          match Hashtbl.find_opt chain.headers parent_key with
          | Some parent -> collect acc (count + 1) parent
          | None -> acc
    in
    collect [] 0 tip
  in
  let lock_time_cutoff = Consensus.median_time_past tip_ts_list in
  let selected = select_transactions mp Consensus.max_block_weight
    ~reserved_weight:default_block_reserved_weight
    ~block_height:height
    ~lock_time_cutoff in

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
  let network_type = chain.network.network_type in
  let placeholder_coinbase =
    create_coinbase ~height ~total_fee ~payout_script ~extra_nonce
      ~witness_root:None ~network_type () in
  let all_txs_for_witness = placeholder_coinbase :: selected_txs in
  let witness_root = compute_witness_merkle_root all_txs_for_witness in

  (* Create final coinbase with witness commitment *)
  let coinbase_tx =
    create_coinbase ~height ~total_fee ~payout_script ~extra_nonce
      ~witness_root:(Some witness_root) ~network_type () in

  (* Build final transaction list for merkle root *)
  let all_txs = coinbase_tx :: selected_txs in
  let txids = List.map Crypto.compute_txid all_txs in
  let (merkle_root, _mutated) = Crypto.merkle_root txids in

  (* tip_ts_list was computed above for lock_time_cutoff; reuse for MTP.
     Current timestamp — must exceed MTP of previous block (GetMinimumTime).
     Core miner.cpp:52: nNewTime = max(GetMinimumTime(pindexPrev, ...), now) *)
  let mtp = lock_time_cutoff in  (* MTP = median_time_past tip_ts_list, already computed *)
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
    network_type;
    transactions_updated = Hashtbl.length mp.entries;
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
      ("sigops", `Int (Validation.count_tx_sigops_cost_simple tx
                         ~prev_script_pubkey_lookup:(fun _ -> None)));
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

  (* BIP-9/BIP-23 rules list.
     Core rpc/mining.cpp:950-963: "csv", "!segwit", "taproot" for all non-signet networks.
     "!" prefix marks rules that affect coinbase/block structure (require explicit client support).
     CSV and taproot do not use "!" because they are purely optional for the miner.
     SegWit uses "!" because the commitment output in the coinbase is required. *)
  let rules_json =
    `List [`String "csv"; `String "!segwit"; `String "taproot"]
  in

  (* BIP-22/BIP-23 capabilities — always includes "proposal" (BIP-23).
     Core rpc/mining.cpp:895. *)
  let capabilities_json =
    `List [`String "proposal"]
  in

  (* BIP-9 vbavailable: map of deployment_name → bit for signaling deployments
     (Started or LockedIn). On all current networks (mainnet/testnet4/regtest)
     taproot is buried (Active), so vbavailable is empty.
     Core rpc/mining.cpp:965-983. *)
  let vbavailable_json = `Assoc [] in

  (* vbrequired: bitmask of version bits the miner MUST set. Always 0 for current
     deployments (no deployment is in LockedIn-but-not-yet-mandatory state).
     Core rpc/mining.cpp:996. *)
  let vbrequired_json = `Int 0 in

  (* coinbaseaux: auxiliary data required in coinbase scriptSig. Core returns {}
     (empty object) since BIP-22's COINBASEAUX flags are not used in current policy.
     Core rpc/mining.cpp:938,1000. *)
  let coinbaseaux_json = `Assoc [] in

  (* longpollid: tip hash hex + transactions-updated counter.
     Miners use this opaque string to detect when the template should be refreshed.
     Core rpc/mining.cpp:1002: tip.GetHex() + ToString(nTransactionsUpdatedLast).
     We use the prev_block hash (= current tip) and the mempool entry count
     captured at template creation time as a proxy for nTransactionsUpdatedLast. *)
  let longpollid_json =
    `String (Types.hash256_to_hex_display template.header.prev_block
             ^ string_of_int template.transactions_updated)
  in

  `Assoc [
    ("capabilities", capabilities_json);
    ("rules", rules_json);
    ("vbavailable", vbavailable_json);
    ("vbrequired", vbrequired_json);
    ("version", `Int (Int32.to_int template.header.version));
    ("previousblockhash",
      `String (Types.hash256_to_hex_display template.header.prev_block));
    ("transactions", `List txs_json);
    ("coinbaseaux", coinbaseaux_json);
    ("coinbasevalue",
      `String (Int64.to_string
        (Int64.add
          (Consensus.block_subsidy_for_network template.network_type template.height)
          template.total_fee)));
    ("longpollid", longpollid_json);
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
          (Consensus.block_subsidy_for_network template.network_type template.height)
          template.total_fee)));
    ("transactions", `Int (List.length template.transactions));
    ("total_fee", `String (Int64.to_string template.total_fee));
    ("total_weight", `Int template.total_weight);
  ]

(* ============================================================================
   Block Submission
   ============================================================================ *)

(* Submit a mined block to the network.
   Returns Ok() if the block is valid and was accepted.
   When [utxo] is provided, the block is connected through the atomic
   [connect_block_optimized] path so that UTXO mutations and the tip
   height are written in a single RocksDB WriteBatch. *)
let submit_block ?(utxo : Utxo.OptimizedUtxoSet.t option)
    ?(network_type : Consensus.network = Consensus.Mainnet)
    (block : Types.block) (chain : Sync.chain_state)
    (mp : Mempool.mempool) : (unit, string) result =

  let hash = Crypto.compute_block_hash block.header in

  (* Validate the block header (DeriveTarget bounds: negative/overflow/above-pow_limit) *)
  match Validation.check_block_header ?network:(Some chain.network) block.header with
  | Error e -> Error e
  | Ok () ->
    (* For submitblock we must compare against the validated-block tip, not
       the header tip (which may lead `blocks_synced` post-IBD).  Use the
       `Sync.block_tip` helper instead of reading `chain.tip` directly. *)
    let validated_height = chain.blocks_synced in
    let validated_tip = Sync.block_tip chain in
    match validated_tip with
    | None -> Error "No validated tip found (blocks_synced=0 or missing header)"
    | Some vtip ->
      if not (Cstruct.equal block.header.prev_block vtip.hash) then begin
        (* Side-branch / heavier-fork submission (Pattern Y closure
           2026-05-05). The block does not extend the validated tip but
           its parent is already known. This is exactly the code path
           Bitcoin Core's [BlockManager::AcceptBlock] handles for non-
           best-chain blocks: store header + body, defer ConnectBlock
           to a later [ActivateBestChain]. If the new chain has more
           work than the active tip, [reorganize] flips the tip;
           otherwise the side-branch is stored-but-inactive and the
           BIP-22 result is "inconclusive" (rendered as Ok () here;
           [bip22_of_submitblock_error] is not consulted on the
           accept path).
           Counterpart to rustoshi 68a422b — see
           lib/sync.ml::try_attach_side_branch_and_reorg.
           Pre-fix this returned "Block does not build on validated tip",
           which the diff-test corpus surfaced as ctx-rej-h113. *)
        let parent_key = Cstruct.to_string block.header.prev_block in
        match Hashtbl.find_opt chain.headers parent_key with
        | None ->
          (* Truly orphan — neither the validated tip nor any known
             header. Mirror Core's BIP-22 "rejected" result; the
             previous error string ("Block does not build on validated
             tip") is no longer accurate when the parent is also
             unknown. *)
          Error (Printf.sprintf
                   "Block %s parent %s not in block index"
                   (Types.hash256_to_hex_display hash)
                   (Types.hash256_to_hex_display block.header.prev_block))
        | Some parent ->
          (* Delegate to the side-branch / reorg path. *)
          Sync.try_attach_side_branch_and_reorg
            ?utxo_set:utxo
            ~mempool:mp
            chain block parent
      end
      else begin
        let height = validated_height + 1 in

        (* Unified block validation via accept_block — mirrors Bitcoin Core's
           ProcessNewBlock pipeline (AcceptBlock → CheckBlock →
           ContextualCheckBlock → ConnectBlock checks).
           Both the context-free checks (merkle, sigops, weight, coinbase
           script length, witness commitment) and the UTXO-aware checks
           (BIP-30 dup-UTXO, per-input scripts, BIP-141 weighted sigops,
           coinbase value ≤ subsidy+fees, BIP-68 sequence locks) are
           performed inside accept_block via validate_block_with_utxos.
           This eliminates the former double-call pattern (check_block then
           validate_block_with_utxos) and keeps the check sequence in sync
           with the IBD path (Sync.process_new_block uses accept_block too).
           Reference: bitcoin-core/src/validation.cpp ProcessNewBlock. *)
        let median_time = Sync.compute_median_time_past chain height in
        let prev_block_time = Sync.get_prev_block_time chain height in
        (* Consensus difficulty check (bad-diffbits).  Compute the REQUIRED
           nBits from the parent (the validated tip [vtip]) using the same
           retarget/no-retarget logic the P2P/IBD path uses
           (Sync.compute_expected_bits, cf. sync.ml:5471-5476), then pass THAT
           as ~expected_bits so validation.ml's ContextualCheckBlockHeader
           equality test (block.header.bits <> expected_bits) actually
           compares the declared bits against consensus — instead of the block
           against itself.  Passing block.header.bits here made the check a
           tautology (x <> x) that could never fire, so submitblock/mining
           accepted wrong-nBits blocks Core rejects.
           Uses ~parent_entry so the required bits are derived from vtip's own
           hash-linked ancestry (immune to height-index clobbering by heavier
           competing header chains — see block_tip's doc comment).
           Reference: bitcoin-core/src/validation.cpp ContextualCheckBlockHeader:4088-4089,
                      pow.cpp GetNextWorkRequired. *)
        let expected_bits =
          Sync.compute_expected_bits ~parent_entry:vtip chain height block.header
        in
        let base_lookup (outpoint : Types.outpoint) : Validation.utxo option =
          let txid = outpoint.Types.txid in
          let vout = Int32.to_int outpoint.Types.vout in
          (* Check the OptimizedUtxoSet in-memory cache first (mirrors
             sync.ml:1794-1809: IBD uses the same layered lookup). *)
          let entry_opt = match utxo with
            | Some utxo_set ->
              (match Utxo.OptimizedUtxoSet.get utxo_set txid vout with
               | Some e ->
                 Some Validation.{
                   txid; vout = outpoint.Types.vout;
                   value = e.Utxo.value;
                   script_pubkey = e.Utxo.script_pubkey;
                   height = e.Utxo.height;
                   is_coinbase = e.Utxo.is_coinbase;
                 }
               | None -> None)
            | None -> None
          in
          match entry_opt with
          | Some _ as found -> found
          | None ->
            (* Fall back to raw DB (cf_chainstate / rocksdb_utxo) *)
            (match Storage.ChainDB.get_utxo chain.db txid vout with
             | None -> None
             | Some data ->
               let r = Serialize.reader_of_cstruct (Cstruct.of_string data) in
               let value = Serialize.read_int64_le r in
               let script_len = Serialize.read_compact_size r in
               let script = Serialize.read_bytes r script_len in
               let stored_height = Int32.to_int (Serialize.read_int32_le r) in
               let utxo_is_coinbase = Serialize.read_uint8 r = 1 in
               Some Validation.{
                 txid; vout = outpoint.Types.vout;
                 value; script_pubkey = script;
                 height = stored_height; is_coinbase = utxo_is_coinbase;
               })
        in
        let validation_flags =
          Consensus.get_block_script_flags ~block_hash:hash height chain.network
        in
        (match Validation.accept_block
                 ~network:chain.network ~block ~height
                 ~expected_bits ~median_time ~prev_block_time
                 ~base_lookup ~flags:validation_flags
                 ~skip_scripts:false
                 ~get_mtp_at_height:(Sync.get_mtp_for_height chain)
                 ?bip34_height_hash:(Sync.bip34_height_hash_for chain) () with
        | Validation.AB_err e -> Error (Validation.block_error_to_string e)
        | Validation.AB_ok (_fees, txid_arr, _spent_utxos) ->
        (* Write tx_index entries for every tx in this submitblock-
           accepted block (Pattern C0 closure 2026-05-05). Mirrors
           [Sync.process_new_block]'s tx_index_write_for_block call.
           Without this, [getrawtransaction] returns "No such mempool
           or blockchain transaction" for every tx in a submitblock-
           accepted block (findings:
           [_txindex-revert-on-reorg-fleet-result-2026-05-05.md]
           Pattern C0; the pre-fix harness flagged camlcoin's A1.coinbase
           probe as `tx-err` even pre-reorg). Companion to the undo-data
           persistence on the same path that 22667c2 added. *)
        Sync.tx_index_write_for_block chain.db block hash txid_arr;

        (* During IBD with headers-first sync, the header is already in the chain.
           Look up existing entry or validate as new. *)
        let entry_result = match Sync.validate_header chain block.header with
          | Ok entry -> Ok entry
          | Error "Header already known" ->
            (* Header already exists — look it up. This is the normal IBD case. *)
            (match Sync.get_header_at_height chain height with
             | Some entry -> Ok entry
             | None -> Error "Header already known but not found at expected height")
          | Error e -> Error e
        in
        match entry_result with
        | Error e -> Error e
        | Ok entry ->
          (* Register header in in-memory chain state and persist height→hash
             mapping so subsequent get_header_at_height lookups succeed. *)
          Sync.accept_header chain entry;
          (* Collected during connect for the BIP-157 filter-index append
             below.  The spent prevout scriptPubKeys live in the [undo]
             produced by [connect_block_optimized]; we capture them here so
             the post-connect filter append (which mirrors Core's
             [BlockFilterIndex::CustomAppend] firing on every connected block)
             includes the spent-prevout element set.  Empty list = no UTXO
             path / no spends, which still produces the correct coinbase-only
             filter. *)
          let spent_entries_for_filter = ref [] in
          (* Connect through the atomic UTXO path when available *)
          let utxo_result = match utxo with
            | Some utxo_set ->
              (match Utxo.connect_block_optimized ~network_type utxo_set block height with
               | Ok undo ->
                 (* Persist undo data so [Sync.reorganize] (and any
                    submitblock-driven side-branch promotion below)
                    can roll back this block on the disconnect path.
                    Pre-fix the happy path discarded [undo], which left
                    the IBD-path-only [reorganize] unable to disconnect
                    submitblock-mined blocks: every reorg crossing a
                    submitblock-mined block tripped "Missing undo data
                    at height N during reorg disconnect".

                    Counterpart to [Sync.process_new_block:1957-1961]
                    which calls the same [store_undo_data] for IBD
                    blocks. Pattern Y closure 2026-05-05 (rustoshi
                    68a422b counterpart). *)
                 let uw = Serialize.writer_create () in
                 Utxo.serialize_undo_data uw undo;
                 Storage.ChainDB.store_undo_data chain.db hash
                   (Cstruct.to_string (Serialize.writer_to_cstruct uw));
                 (* Flatten the per-tx spent outputs into the (outpoint,
                    utxo_entry) list shape expected by the BIP-157 filter
                    append helper. *)
                 spent_entries_for_filter :=
                   List.concat_map (fun (tu : Utxo.tx_undo) -> tu.spent_outputs)
                     undo.Utxo.tx_undos;
                 (* Drain the per-block dirty set into BOTH stores
                    (cf_chainstate UTXO column family + rocksdb_utxo) via
                    the same [apply_block_atomic] path used by
                    [Sync.process_new_block].  Without this, the deferred
                    [OptimizedUtxoSet.flush] writes only to rocksdb_utxo,
                    leaving cf_chainstate empty — and dumptxoutset (which
                    iterates cf_chainstate via [Storage.ChainDB.iter_utxos])
                    emits a 51-byte header-only snapshot.

                    The atomic write also advances tip_hash / tip_height /
                    header_tip in the same RocksDB batch, replacing the
                    separate [set_chain_tip] call below. *)
                 Utxo.OptimizedUtxoSet.persist_dirty_atomic utxo_set
                   ~tip_hash:hash ~tip_height:height
                   ~header_tip_hash:hash ~header_tip_height:height;
                 Ok ()
               | Error e -> Error e)
            | None ->
              (* Legacy path: no UTXO validation (unsafe).  Without an
                 OptimizedUtxoSet we still need to persist the tip pointer
                 so subsequent reads/dumps see the new height. *)
              Storage.ChainDB.set_chain_tip chain.db hash height;
              Ok ()
          in
          (match utxo_result with
           | Error e -> Error e
           | Ok () ->
             (* Store the block body *)
             Storage.ChainDB.store_block chain.db hash block;

             (* Record this block's tx count in the dedicated ntx index so
                getblockheader / getchaintxstats can read it without parsing
                the body.  Mirrors the IBD / process_new_block connect path's
                store_block_ntx call. *)
             Storage.ChainDB.store_block_ntx chain.db hash
               (List.length block.transactions);

             (* Update blocks_synced to match *)
             chain.blocks_synced <- height;

             (* BIP-157/158 filter index append (no-op when --blockfilterindex
                is off).  Mirrors Bitcoin Core's [BlockFilterIndex::CustomAppend]
                firing on every connected block — without this, blocks that
                arrive via submitblock (rather than IBD / process_new_block)
                never get a filter computed, so getblockfilter would 404 for
                them.  Uses the spent prevout scriptPubKeys captured from the
                connect undo above so the spend-block filter includes both the
                output spk and the spent-prevout spk. *)
             Sync.append_filter_if_enabled_from_entries chain
               ~block ~height ~spent_entries:!spent_entries_for_filter;

             (* Coin-stats index append for the submitblock / mining /
                generate* accept path (no-op when --coinstatsindex is off).
                Uses the spent prevout entries captured from the connect
                undo above so the per-height MuHash removes exactly the
                coins this block spent (with their ORIGINAL height +
                coinbase flag). Mirrors Bitcoin Core's
                [CoinStatsIndex::CustomAppend] firing on every connected
                block — this is the block-connect choke-point for the
                submitblock path the harness drives. *)
             Sync.coinstats_connect_if_enabled_from_entries chain
               ~block ~height ~spent_entries:!spent_entries_for_filter;

             (* Tx-output spender index append for the submitblock / mining /
                generate* accept path (no-op when --txospenderindex is off).
                Writes [spent_outpoint -> spending tx] for every non-coinbase
                input. This is the block-connect choke-point for the
                submitblock path the harness drives; without it a node fed
                only via submitblock would never index a confirmed spend.
                Mirrors Core's [TxoSpenderIndex::CustomAppend]. *)
             Sync.txospender_connect_if_enabled chain ~block ~height;

             (* Remove confirmed transactions from mempool *)
             Mempool.remove_for_block mp block height;

             (* Notify the wallet so its UTXO ledger tracks coins this block
                pays to / spends from wallet addresses (credits wallet-script
                outputs, debits spent wallet UTXOs).  Mirrors Bitcoin Core's
                CWallet::blockConnected firing on every connected block.
                Best-effort via [run_wallet_scan_hook]: a wallet-side failure
                never rolls back this already-connected block.  This is the
                single block-connect choke-point for the mining / generate /
                generatetoaddress / generateblock / submitblock paths. *)
             Sync.run_wallet_scan_hook chain block height;

             Logs.info (fun m -> m "Accepted mined block at height %d: %s"
               height (Types.hash256_to_hex_display hash));

             (* Hot-path GC keep-up (2026-06-09, made non-STW 2026-06-24):
                once per block connected via the mining / generate* /
                submitblock path (the third primary-connect choke point
                alongside Sync.process_new_block and
                Sync.connect_stored_blocks).  Mirrors Core's ConnectTip ->
                FlushStateToDisk(IF_NEEDED) (validation.cpp:3063).  Uses the
                NON-STW [Gc.major_slice] keep-up so connecting a block at tip
                does not stop-the-world the RPC-serving domain (2026-06-24
                fix); the rare STW backstop is owned by the gc_thread on a
                dedicated domain. *)
             Gc_guard.maybe_keep_up ~reason:"hot-path:block";

             (* Wake the wait-family RPCs on this submitblock / generate /
                generatetoaddress / generateblock accept-path tip advance
                (Core KernelNotifications blockTip / WaitTipChanged fires on
                the ProcessNewBlock accept path too).  The side-branch /
                heavier-fork submission path delegates to
                [Sync.try_attach_side_branch_and_reorg] -> [Sync.reorganize],
                which carries its own notify, so this covers the direct-extend
                case here.  Best-effort: a notifier fault must never fail an
                already-accepted block. *)
             (try Tip_notifier.notify () with _ -> ());

             Ok ()))
      end
