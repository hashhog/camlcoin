(* Fee Rate Estimation Based on Confirmation Times

   Estimates fee rates by observing how quickly transactions at various
   fee rates get confirmed. The system tracks transactions entering the
   mempool with their fee rate and block height, then records how many
   blocks they wait before confirmation.

   Fee rate buckets group transactions by fee level. To estimate a fee
   for a target confirmation time, we find the lowest fee-rate bucket
   where the median confirmation time meets the target.

   KNOWN PITFALL — Estimates require sufficient data points (at least 10
   per bucket) to be reliable. Default fallback rates are used when
   insufficient data exists. *)

(* ============================================================================
   Fee Bucket Type
   ============================================================================ *)

type fee_bucket = {
  min_fee_rate : float;        (* sat/vB *)
  max_fee_rate : float;
  mutable total_confirmed : float;
  mutable total_unconfirmed : float;
  mutable blocks_to_confirm : float list;
}

(* ============================================================================
   Fee Estimator Type
   ============================================================================ *)

type t = {
  buckets : fee_bucket array;
  mutable block_height : int;
  tracked_txs : (string, float * int * float) Hashtbl.t;
  (* txid -> (fee_rate, height_added, timestamp) *)
}

(* ============================================================================
   Constants
   ============================================================================ *)

(* Fee rate bucket boundaries in sat/vB *)
let bucket_boundaries = [|
  1.0; 2.0; 3.0; 5.0; 7.0; 10.0; 15.0; 20.0;
  30.0; 50.0; 75.0; 100.0; 150.0; 200.0; 300.0;
  500.0; 750.0; 1000.0; 1500.0; 2000.0;
|]

(* Minimum data points required for reliable estimates *)
let min_samples = 10

(* Maximum confirmation samples to keep per bucket *)
let max_samples_per_bucket = 1000

(* Default fallback rates when insufficient data *)
let default_high_priority = 20.0    (* 1 block target *)
let default_medium_priority = 10.0  (* 6 block target *)
let default_low_priority = 1.0      (* 25 block target *)

(* Exponential decay factor applied per block.
   0.998 per block ~ half-life of 346 blocks ~ 2.4 days at 10 min/block *)
let decay_factor = 0.998

(* Default maximum age for tracked mempool transactions: 14 days in seconds *)
let default_max_tx_age = 14.0 *. 24.0 *. 3600.0

(* ============================================================================
   Creation
   ============================================================================ *)

let create () : t =
  let n = Array.length bucket_boundaries in
  let buckets = Array.init n (fun i ->
    let min_fr = bucket_boundaries.(i) in
    let max_fr =
      if i < n - 1 then bucket_boundaries.(i + 1)
      else Float.infinity
    in
    { min_fee_rate = min_fr;
      max_fee_rate = max_fr;
      total_confirmed = 0.0;
      total_unconfirmed = 0.0;
      blocks_to_confirm = [] }
  ) in
  { buckets;
    block_height = 0;
    tracked_txs = Hashtbl.create 10_000 }

(* ============================================================================
   Bucket Lookup
   ============================================================================ *)

let find_bucket (est : t) (fee_rate : float) : int =
  let n = Array.length est.buckets in
  let rec search i =
    if i >= n - 1 then n - 1
    else if fee_rate < est.buckets.(i).max_fee_rate then i
    else search (i + 1)
  in
  search 0

(* ============================================================================
   Transaction Tracking
   ============================================================================ *)

let track_transaction (est : t) (txid : Types.hash256)
    (fee_rate : float) (height : int) : unit =
  let txid_key = Cstruct.to_string txid in
  let now = Unix.gettimeofday () in
  Hashtbl.replace est.tracked_txs txid_key (fee_rate, height, now);
  let bucket_idx = find_bucket est fee_rate in
  est.buckets.(bucket_idx).total_unconfirmed <-
    est.buckets.(bucket_idx).total_unconfirmed +. 1.0

(* Record that a tracked transaction was confirmed *)
let record_confirmation (est : t) (txid : Types.hash256)
    (confirm_height : int) : unit =
  let txid_key = Cstruct.to_string txid in
  match Hashtbl.find_opt est.tracked_txs txid_key with
  | None -> ()
  | Some (fee_rate, added_height, _timestamp) ->
    Hashtbl.remove est.tracked_txs txid_key;
    let blocks = confirm_height - added_height in
    let bucket_idx = find_bucket est fee_rate in
    let bucket = est.buckets.(bucket_idx) in
    bucket.total_confirmed <- bucket.total_confirmed +. 1.0;
    bucket.total_unconfirmed <- Float.max 0.0 (bucket.total_unconfirmed -. 1.0);
    bucket.blocks_to_confirm <-
      float_of_int blocks :: bucket.blocks_to_confirm;
    (* Keep only last max_samples_per_bucket samples *)
    if List.length bucket.blocks_to_confirm > max_samples_per_bucket then
      bucket.blocks_to_confirm <-
        List.filteri (fun i _ -> i < max_samples_per_bucket)
          bucket.blocks_to_confirm

(* ============================================================================
   Exponential Decay
   ============================================================================ *)

(* Apply exponential decay to all bucket counts. Called once per block to
   gradually discount old data, preventing stale fee information from
   dominating estimates after fee regime changes. Samples in
   blocks_to_confirm are trimmed from the tail (oldest) to stay in line
   with the decayed confirmed count. *)
let apply_decay (est : t) : unit =
  Array.iter (fun bucket ->
    bucket.total_confirmed <- bucket.total_confirmed *. decay_factor;
    bucket.total_unconfirmed <- bucket.total_unconfirmed *. decay_factor;
    (* Trim oldest samples so sample count does not exceed the
       decayed confirmed count (rounded up) *)
    let max_keep = int_of_float (Float.round (bucket.total_confirmed +. 0.5)) in
    let current_len = List.length bucket.blocks_to_confirm in
    if current_len > max_keep then
      bucket.blocks_to_confirm <-
        List.filteri (fun i _ -> i < max_keep) bucket.blocks_to_confirm
  ) est.buckets

(* ============================================================================
   Block Processing
   ============================================================================ *)

let process_block (est : t) (block : Types.block) (height : int) : unit =
  est.block_height <- height;
  (* Apply decay before processing confirmations so that new data is
     recorded at full weight while old data is discounted *)
  apply_decay est;
  List.iter (fun tx ->
    let txid = Crypto.compute_txid tx in
    record_confirmation est txid height
  ) block.transactions

(* ============================================================================
   Fee Estimation
   ============================================================================ *)

(* Helper to compute median of a list *)
let compute_median (samples : float list) : float option =
  match samples with
  | [] -> None
  | _ ->
    let sorted = List.sort compare samples in
    let len = List.length sorted in
    Some (List.nth sorted (len / 2))

(* Estimate fee rate for target confirmation blocks.
   Searches from lowest fee rate up, finding the lowest fee-rate bucket
   where the median confirmation time meets the target. Higher fee rate
   buckets are expected to confirm faster, so we want the minimum fee
   that achieves the target confirmation time. *)
let estimate_fee (est : t) (target_blocks : int) : float option =
  let n = Array.length est.buckets in
  let target_f = float_of_int target_blocks in

  (* Search from lowest to highest fee rate, return first bucket that
     has enough data AND median confirmation time <= target *)
  let rec search_up i =
    if i >= n then
      (* No bucket meets the target *)
      None
    else begin
      let bucket = est.buckets.(i) in
      if bucket.total_confirmed < float_of_int min_samples then
        search_up (i + 1)  (* not enough data, try higher fee rate *)
      else begin
        match compute_median bucket.blocks_to_confirm with
        | None -> search_up (i + 1)
        | Some median ->
          if median <= target_f then
            Some bucket.min_fee_rate
          else
            search_up (i + 1)  (* doesn't meet target, try higher fee rate *)
      end
    end
  in
  search_up 0

(* ============================================================================
   Priority-Based Estimates
   ============================================================================ *)

let estimate_high_priority (est : t) : float =
  match estimate_fee est 1 with
  | Some r -> r
  | None -> default_high_priority

let estimate_medium_priority (est : t) : float =
  match estimate_fee est 6 with
  | Some r -> r
  | None -> default_medium_priority

let estimate_low_priority (est : t) : float =
  match estimate_fee est 25 with
  | Some r -> r
  | None -> default_low_priority

(* ============================================================================
   Query Functions
   ============================================================================ *)

(* Get the current block height *)
let current_height (est : t) : int =
  est.block_height

(* Get number of tracked (unconfirmed) transactions *)
let tracked_count (est : t) : int =
  Hashtbl.length est.tracked_txs

(* Get stats for a specific bucket *)
type bucket_stats = {
  min_rate : float;
  max_rate : float;
  confirmed : int;
  unconfirmed : int;
  sample_count : int;
  median_blocks : float option;
}

let get_bucket_stats (est : t) (bucket_idx : int) : bucket_stats option =
  if bucket_idx < 0 || bucket_idx >= Array.length est.buckets then
    None
  else begin
    let bucket = est.buckets.(bucket_idx) in
    Some {
      min_rate = bucket.min_fee_rate;
      max_rate = bucket.max_fee_rate;
      confirmed = int_of_float bucket.total_confirmed;
      unconfirmed = int_of_float bucket.total_unconfirmed;
      sample_count = List.length bucket.blocks_to_confirm;
      median_blocks = compute_median bucket.blocks_to_confirm;
    }
  end

(* Get number of buckets *)
let bucket_count (est : t) : int =
  Array.length est.buckets

(* ============================================================================
   Remove Transaction
   ============================================================================ *)

(* Stop tracking a transaction (e.g., if it was rejected or expired) *)
let remove_transaction (est : t) (txid : Types.hash256) : unit =
  let txid_key = Cstruct.to_string txid in
  match Hashtbl.find_opt est.tracked_txs txid_key with
  | None -> ()
  | Some (fee_rate, _, _) ->
    Hashtbl.remove est.tracked_txs txid_key;
    let bucket_idx = find_bucket est fee_rate in
    let bucket = est.buckets.(bucket_idx) in
    bucket.total_unconfirmed <- Float.max 0.0 (bucket.total_unconfirmed -. 1.0)

(* ============================================================================
   Time-based Expiration
   ============================================================================ *)

(* Remove tracked transactions older than [max_age] seconds (default 14 days).
   This prevents the mempool tracker from accumulating entries for transactions
   that were dropped or replaced without the node noticing. *)
let expire_old_transactions ?(max_age = default_max_tx_age) (est : t) : int =
  let now = Unix.gettimeofday () in
  let cutoff = now -. max_age in
  let to_remove = ref [] in
  Hashtbl.iter (fun txid_key (_fee_rate, _height, timestamp) ->
    if timestamp < cutoff then
      to_remove := txid_key :: !to_remove
  ) est.tracked_txs;
  List.iter (fun txid_key ->
    match Hashtbl.find_opt est.tracked_txs txid_key with
    | None -> ()
    | Some (fee_rate, _, _) ->
      Hashtbl.remove est.tracked_txs txid_key;
      let bucket_idx = find_bucket est fee_rate in
      let bucket = est.buckets.(bucket_idx) in
      bucket.total_unconfirmed <- Float.max 0.0 (bucket.total_unconfirmed -. 1.0)
  ) !to_remove;
  List.length !to_remove

(* ============================================================================
   Clear All Data
   ============================================================================ *)

let clear (est : t) : unit =
  Hashtbl.clear est.tracked_txs;
  Array.iter (fun bucket ->
    bucket.total_confirmed <- 0.0;
    bucket.total_unconfirmed <- 0.0;
    bucket.blocks_to_confirm <- []
  ) est.buckets
