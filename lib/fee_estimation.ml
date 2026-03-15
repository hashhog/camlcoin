(* Fee Rate Estimation Based on Confirmation Times

   Estimates fee rates by observing how quickly transactions at various
   fee rates get confirmed. The system tracks transactions entering the
   mempool with their fee rate and block height, then records how many
   blocks they wait before confirmation.

   Fee rate buckets group transactions by fee level using exponentially
   spaced boundaries (spacing factor 1.05, starting at 1 sat/vB),
   matching Bitcoin Core's bucketing scheme.

   Three estimation horizons are maintained:
   - Short:  decay 0.998,  max target 12 blocks
   - Medium: decay 0.9995, max target 48 blocks
   - Long:   decay 0.99931, max target 1008 blocks

   KNOWN PITFALL — Estimates require sufficient data points (at least 10
   per bucket) to be reliable. Default fallback rates are used when
   insufficient data exists. *)

(* ============================================================================
   Estimate Mode
   ============================================================================ *)

type estimate_mode = Conservative | Economical

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
   Estimation Horizon
   ============================================================================ *)

type horizon = {
  name : string;
  decay : float;
  max_target : int;
  buckets : fee_bucket array;
}

(* ============================================================================
   Fee Estimator Type
   ============================================================================ *)

type t = {
  bucket_boundaries : float array;
  short : horizon;
  medium : horizon;
  long : horizon;
  mutable block_height : int;
  tracked_txs : (string, float * int * float) Hashtbl.t;
  (* txid -> (fee_rate, height_added, timestamp) *)
}

(* ============================================================================
   Constants
   ============================================================================ *)

(* Minimum data points required for reliable estimates *)
let min_samples = 10

(* Maximum confirmation samples to keep per bucket *)
let max_samples_per_bucket = 1000

(* Default fallback rates when insufficient data *)
let default_high_priority = 20.0    (* 1 block target *)
let default_medium_priority = 10.0  (* 6 block target *)
let default_low_priority = 1.0      (* 25 block target *)

(* Default maximum age for tracked mempool transactions: 14 days in seconds *)
let default_max_tx_age = 14.0 *. 24.0 *. 3600.0

(* Confirmation target limits *)
let min_confirm_target = 1
let max_confirm_target = 1008

(* ============================================================================
   Exponentially Spaced Bucket Boundaries
   ============================================================================ *)

(* Build bucket boundaries matching Bitcoin Core: spacing factor 1.05,
   starting at 1.0 sat/vB, up to ~10000 sat/vB *)
let make_bucket_boundaries () : float array =
  let factor = 1.05 in
  let max_rate = 10_000.0 in
  let boundaries = ref [1.0] in
  let v = ref (1.0 *. factor) in
  while !v <= max_rate do
    boundaries := !v :: !boundaries;
    v := !v *. factor
  done;
  Array.of_list (List.rev !boundaries)

(* ============================================================================
   Creation
   ============================================================================ *)

let make_buckets (boundaries : float array) : fee_bucket array =
  let n = Array.length boundaries in
  Array.init n (fun i ->
    let min_fr = boundaries.(i) in
    let max_fr =
      if i < n - 1 then boundaries.(i + 1)
      else Float.infinity
    in
    { min_fee_rate = min_fr;
      max_fee_rate = max_fr;
      total_confirmed = 0.0;
      total_unconfirmed = 0.0;
      blocks_to_confirm = [] }
  )

let make_horizon (name : string) (decay : float) (max_target : int)
    (boundaries : float array) : horizon =
  { name; decay; max_target; buckets = make_buckets boundaries }

let create () : t =
  let boundaries = make_bucket_boundaries () in
  { bucket_boundaries = boundaries;
    short  = make_horizon "short"  0.998   12   boundaries;
    medium = make_horizon "medium" 0.9995  48   boundaries;
    long   = make_horizon "long"   0.99931 1008 boundaries;
    block_height = 0;
    tracked_txs = Hashtbl.create 10_000 }

(* ============================================================================
   Bucket Lookup
   ============================================================================ *)

let find_bucket_in (boundaries : float array) (buckets : fee_bucket array)
    (fee_rate : float) : int =
  let n = Array.length buckets in
  let rec search i =
    if i >= n - 1 then n - 1
    else if fee_rate < buckets.(i).max_fee_rate then i
    else search (i + 1)
  in
  ignore boundaries;
  search 0

let find_bucket (est : t) (fee_rate : float) : int =
  find_bucket_in est.bucket_boundaries est.short.buckets fee_rate

(* ============================================================================
   Transaction Tracking
   ============================================================================ *)

let track_transaction (est : t) (txid : Types.hash256)
    (fee_rate : float) (height : int) : unit =
  let txid_key = Cstruct.to_string txid in
  let now = Unix.gettimeofday () in
  Hashtbl.replace est.tracked_txs txid_key (fee_rate, height, now);
  let idx = find_bucket est fee_rate in
  est.short.buckets.(idx).total_unconfirmed <-
    est.short.buckets.(idx).total_unconfirmed +. 1.0;
  est.medium.buckets.(idx).total_unconfirmed <-
    est.medium.buckets.(idx).total_unconfirmed +. 1.0;
  est.long.buckets.(idx).total_unconfirmed <-
    est.long.buckets.(idx).total_unconfirmed +. 1.0

let record_confirmation_horizon (h : horizon) (bucket_idx : int) (blocks : int) : unit =
  let bucket = h.buckets.(bucket_idx) in
  bucket.total_confirmed <- bucket.total_confirmed +. 1.0;
  bucket.total_unconfirmed <- Float.max 0.0 (bucket.total_unconfirmed -. 1.0);
  bucket.blocks_to_confirm <-
    float_of_int blocks :: bucket.blocks_to_confirm;
  if List.length bucket.blocks_to_confirm > max_samples_per_bucket then
    bucket.blocks_to_confirm <-
      List.filteri (fun i _ -> i < max_samples_per_bucket)
        bucket.blocks_to_confirm

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
    record_confirmation_horizon est.short bucket_idx blocks;
    record_confirmation_horizon est.medium bucket_idx blocks;
    record_confirmation_horizon est.long bucket_idx blocks

(* Remove a transaction that was evicted from the mempool without counting
   it as a confirmation. *)
let record_eviction (est : t) (txid : Types.hash256) : unit =
  let txid_key = Cstruct.to_string txid in
  match Hashtbl.find_opt est.tracked_txs txid_key with
  | None -> ()
  | Some (fee_rate, _added_height, _timestamp) ->
    Hashtbl.remove est.tracked_txs txid_key;
    let idx = find_bucket est fee_rate in
    est.short.buckets.(idx).total_unconfirmed <-
      Float.max 0.0 (est.short.buckets.(idx).total_unconfirmed -. 1.0);
    est.medium.buckets.(idx).total_unconfirmed <-
      Float.max 0.0 (est.medium.buckets.(idx).total_unconfirmed -. 1.0);
    est.long.buckets.(idx).total_unconfirmed <-
      Float.max 0.0 (est.long.buckets.(idx).total_unconfirmed -. 1.0)

(* ============================================================================
   Exponential Decay
   ============================================================================ *)

let apply_decay_horizon (h : horizon) : unit =
  Array.iter (fun bucket ->
    bucket.total_confirmed <- bucket.total_confirmed *. h.decay;
    bucket.total_unconfirmed <- bucket.total_unconfirmed *. h.decay;
    let max_keep = int_of_float (Float.round (bucket.total_confirmed +. 0.5)) in
    let current_len = List.length bucket.blocks_to_confirm in
    if current_len > max_keep then
      bucket.blocks_to_confirm <-
        List.filteri (fun i _ -> i < max_keep) bucket.blocks_to_confirm
  ) h.buckets

let apply_decay (est : t) : unit =
  apply_decay_horizon est.short;
  apply_decay_horizon est.medium;
  apply_decay_horizon est.long

(* ============================================================================
   Block Processing
   ============================================================================ *)

let process_block (est : t) (block : Types.block) (height : int) : unit =
  est.block_height <- height;
  apply_decay est;
  List.iter (fun tx ->
    let txid = Crypto.compute_txid tx in
    record_confirmation est txid height
  ) block.transactions

(* ============================================================================
   Fee Estimation
   ============================================================================ *)

let compute_percentile (samples : float list) (p : float) : float option =
  match samples with
  | [] -> None
  | _ ->
    let sorted = List.sort compare samples in
    let len = List.length sorted in
    let idx = int_of_float (p *. float_of_int (len - 1)) in
    let idx = max 0 (min idx (len - 1)) in
    Some (List.nth sorted idx)

let compute_median (samples : float list) : float option =
  compute_percentile samples 0.5

let conservative_multiplier (target_blocks : int) : float =
  if target_blocks <= 2 then 1.5
  else if target_blocks <= 6 then 1.25
  else 1.10

(* Select the appropriate horizon for the given confirmation target *)
let select_horizon (est : t) (target_blocks : int) : horizon =
  if target_blocks <= est.short.max_target then est.short
  else if target_blocks <= est.medium.max_target then est.medium
  else est.long

(* Estimate fee rate for target confirmation blocks with horizon selection.
   Enforces target range [1, 1008]. *)
let estimate_fee ?(mode = Economical) (est : t) (target_blocks : int) : float option =
  let target_blocks = max min_confirm_target (min max_confirm_target target_blocks) in
  let horizon = select_horizon est target_blocks in
  let n = Array.length horizon.buckets in
  let target_f = float_of_int target_blocks in
  let percentile = match mode with
    | Conservative -> 0.85
    | Economical -> 0.5
  in

  let rec search_up i =
    if i >= n then None
    else begin
      let bucket = horizon.buckets.(i) in
      if bucket.total_confirmed < float_of_int min_samples then
        search_up (i + 1)
      else begin
        match compute_percentile bucket.blocks_to_confirm percentile with
        | None -> search_up (i + 1)
        | Some pct_val ->
          if pct_val <= target_f then begin
            let base_rate = bucket.min_fee_rate in
            let rate = match mode with
              | Conservative -> base_rate *. conservative_multiplier target_blocks
              | Economical -> base_rate
            in
            Some rate
          end else
            search_up (i + 1)
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

let current_height (est : t) : int =
  est.block_height

let tracked_count (est : t) : int =
  Hashtbl.length est.tracked_txs

type bucket_stats = {
  min_rate : float;
  max_rate : float;
  confirmed : int;
  unconfirmed : int;
  sample_count : int;
  median_blocks : float option;
}

let get_bucket_stats (est : t) (bucket_idx : int) : bucket_stats option =
  if bucket_idx < 0 || bucket_idx >= Array.length est.short.buckets then
    None
  else begin
    let bucket = est.short.buckets.(bucket_idx) in
    Some {
      min_rate = bucket.min_fee_rate;
      max_rate = bucket.max_fee_rate;
      confirmed = int_of_float bucket.total_confirmed;
      unconfirmed = int_of_float bucket.total_unconfirmed;
      sample_count = List.length bucket.blocks_to_confirm;
      median_blocks = compute_median bucket.blocks_to_confirm;
    }
  end

let bucket_count (est : t) : int =
  Array.length est.short.buckets

(* ============================================================================
   Remove Transaction
   ============================================================================ *)

let remove_transaction (est : t) (txid : Types.hash256) : unit =
  let txid_key = Cstruct.to_string txid in
  match Hashtbl.find_opt est.tracked_txs txid_key with
  | None -> ()
  | Some (fee_rate, _, _) ->
    Hashtbl.remove est.tracked_txs txid_key;
    let idx = find_bucket est fee_rate in
    est.short.buckets.(idx).total_unconfirmed <-
      Float.max 0.0 (est.short.buckets.(idx).total_unconfirmed -. 1.0);
    est.medium.buckets.(idx).total_unconfirmed <-
      Float.max 0.0 (est.medium.buckets.(idx).total_unconfirmed -. 1.0);
    est.long.buckets.(idx).total_unconfirmed <-
      Float.max 0.0 (est.long.buckets.(idx).total_unconfirmed -. 1.0)

(* ============================================================================
   Time-based Expiration
   ============================================================================ *)

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
      let idx = find_bucket est fee_rate in
      est.short.buckets.(idx).total_unconfirmed <-
        Float.max 0.0 (est.short.buckets.(idx).total_unconfirmed -. 1.0);
      est.medium.buckets.(idx).total_unconfirmed <-
        Float.max 0.0 (est.medium.buckets.(idx).total_unconfirmed -. 1.0);
      est.long.buckets.(idx).total_unconfirmed <-
        Float.max 0.0 (est.long.buckets.(idx).total_unconfirmed -. 1.0)
  ) !to_remove;
  List.length !to_remove

(* ============================================================================
   Clear All Data
   ============================================================================ *)

let clear (est : t) : unit =
  Hashtbl.clear est.tracked_txs;
  let clear_horizon h =
    Array.iter (fun bucket ->
      bucket.total_confirmed <- 0.0;
      bucket.total_unconfirmed <- 0.0;
      bucket.blocks_to_confirm <- []
    ) h.buckets
  in
  clear_horizon est.short;
  clear_horizon est.medium;
  clear_horizon est.long
