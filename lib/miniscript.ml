(* Miniscript - A structured subset of Bitcoin Script for analysis and composition

   Miniscript enables:
   - Static analysis of spending conditions
   - Composition of complex scripts from building blocks
   - Generic signing for any spending condition
   - Calculation of worst-case witness sizes

   Reference: Bitcoin Core src/script/miniscript.cpp/h
*)

(* ============================================================================
   Types
   ============================================================================ *)

(* Script context - affects which fragments and limits are valid *)
type script_ctx =
  | P2WSH      (* SegWit v0 witness script - CHECKMULTISIG, no OP_SUCCESS *)
  | Tapscript  (* SegWit v1 tapscript - CHECKSIGADD, OP_SUCCESS *)

(* Key representation - abstract over concrete key types *)
type key =
  | KeyBytes of Cstruct.t      (* raw pubkey: 33 bytes compressed or 32 bytes xonly *)
  | KeyPlaceholder of string   (* named placeholder for descriptors *)

(* Hash types for preimage conditions *)
type hash_type =
  | HashSha256
  | HashHash256     (* double SHA256 *)
  | HashRipemd160
  | HashHash160     (* RIPEMD160(SHA256()) *)

(* Wrapper types that transform type properties *)
type wrapper =
  | WrapA   (* a: - OP_TOALTSTACK [X] OP_FROMALTSTACK -> B -> W *)
  | WrapS   (* s: - OP_SWAP [X] -> Bo -> Ws *)
  | WrapC   (* c: - [X] OP_CHECKSIG -> K -> B *)
  | WrapD   (* d: - OP_DUP OP_IF [X] OP_ENDIF -> Vz -> Bdu *)
  | WrapV   (* v: - [X] OP_VERIFY (or modify last op) -> B -> V *)
  | WrapJ   (* j: - OP_SIZE OP_0NOTEQUAL OP_IF [X] OP_ENDIF -> Bn -> Bdu *)
  | WrapN   (* n: - [X] OP_0NOTEQUAL -> B -> B *)
  (* Synthetic wrappers (expanded to other forms) *)
  | WrapL   (* l: - OR_I(0, X) *)
  | WrapU   (* u: - OR_I(X, 0) *)
  | WrapT   (* t: - AND_V(X, 1) *)

(* Miniscript AST - the core expression type *)
type miniscript =
  (* Basic fragments *)
  | Ms_0                                  (* 0 - push 0 (false) *)
  | Ms_1                                  (* 1 - push 1 (true) *)
  | Ms_pk_k of key                        (* pk_k(key) - push key *)
  | Ms_pk_h of key                        (* pk_h(key) - check pubkey hash *)
  | Ms_older of int                       (* older(n) - relative timelock (CSV) *)
  | Ms_after of int                       (* after(n) - absolute timelock (CLTV) *)
  (* Hash preimage conditions *)
  | Ms_sha256 of Cstruct.t                (* sha256(h) - 32-byte hash *)
  | Ms_hash256 of Cstruct.t               (* hash256(h) - 32-byte hash *)
  | Ms_ripemd160 of Cstruct.t             (* ripemd160(h) - 20-byte hash *)
  | Ms_hash160 of Cstruct.t               (* hash160(h) - 20-byte hash *)
  (* Conjunctions *)
  | Ms_and_v of miniscript * miniscript   (* and_v(X, Y) - Y must be V-type *)
  | Ms_and_b of miniscript * miniscript   (* and_b(X, Y) - OP_BOOLAND *)
  (* Disjunctions *)
  | Ms_or_b of miniscript * miniscript    (* or_b(X, Y) - OP_BOOLOR *)
  | Ms_or_c of miniscript * miniscript    (* or_c(X, Y) - [X] NOTIF [Y] ENDIF *)
  | Ms_or_d of miniscript * miniscript    (* or_d(X, Y) - [X] IFDUP NOTIF [Y] ENDIF *)
  | Ms_or_i of miniscript * miniscript    (* or_i(X, Y) - IF [X] ELSE [Y] ENDIF *)
  | Ms_andor of miniscript * miniscript * miniscript  (* andor(X, Y, Z) *)
  (* Threshold *)
  | Ms_thresh of int * miniscript list    (* thresh(k, X1, ..., Xn) *)
  (* Multisig *)
  | Ms_multi of int * key list            (* multi(k, key1, ..., keyn) - P2WSH only *)
  | Ms_multi_a of int * key list          (* multi_a(k, key1, ..., keyn) - Tapscript only *)
  (* Wrapper application *)
  | Ms_wrap of wrapper * miniscript       (* wrapper:X *)

(* ============================================================================
   Type System
   ============================================================================ *)

type base_type =
  | TypeB | TypeV | TypeK | TypeW

module TypeProp = struct
  let type_b = 1 lsl 0
  let type_v = 1 lsl 1
  let type_k = 1 lsl 2
  let type_w = 1 lsl 3
  let prop_z = 1 lsl 4
  let prop_o = 1 lsl 5
  let prop_n = 1 lsl 6
  let prop_d = 1 lsl 7
  let prop_u = 1 lsl 8
  let prop_e = 1 lsl 9
  let prop_f = 1 lsl 10
  let prop_s = 1 lsl 11
  let prop_m = 1 lsl 12
  let prop_x = 1 lsl 13
  let prop_g = 1 lsl 14
  let prop_h = 1 lsl 15
  let prop_i = 1 lsl 16
  let prop_j = 1 lsl 17
  let prop_k = 1 lsl 18
  let has t prop = t land prop <> 0
  let lacks t prop = t land prop = 0
end

type type_error =
  | IncompatibleBase of string
  | MissingProperty of string
  | ConflictingTimelocks
  | InvalidThreshold of int * int
  | InvalidMultisig of string
  | ContextMismatch of string

type node_type = {
  props : int;
  script_size : int;
  max_sat_size : int;
  max_dissat_size : int;
}

let locktime_threshold = 500_000_000
let sequence_locktime_type_flag = 1 lsl 22
let is_time_based_locktime n = n >= locktime_threshold
let is_time_based_sequence n = n land sequence_locktime_type_flag <> 0

let get_base_type props =
  if TypeProp.has props TypeProp.type_b then Some TypeB
  else if TypeProp.has props TypeProp.type_v then Some TypeV
  else if TypeProp.has props TypeProp.type_k then Some TypeK
  else if TypeProp.has props TypeProp.type_w then Some TypeW
  else None

let validate_type props =
  let open TypeProp in
  if has props type_k && lacks props prop_u then Some (MissingProperty "K requires u")
  else if has props type_k && lacks props prop_s then Some (MissingProperty "K requires s")
  else if has props prop_z && has props prop_o then Some (IncompatibleBase "z and o are mutually exclusive")
  else if has props prop_z && has props prop_n then Some (IncompatibleBase "z and n are mutually exclusive")
  else if has props prop_n && has props type_w then Some (IncompatibleBase "n conflicts with W")
  else if has props type_v && has props prop_d then Some (IncompatibleBase "V conflicts with d")
  else if has props type_v && has props prop_u then Some (IncompatibleBase "V conflicts with u")
  else if has props type_v && has props prop_e then Some (IncompatibleBase "V conflicts with e")
  (* Note: V-type CAN have f property - it means "forced to succeed" *)
  else if has props prop_d && has props prop_f then Some (IncompatibleBase "d and f are mutually exclusive")
  else if has props prop_e && lacks props prop_d then Some (MissingProperty "e requires d")
  else if has props prop_e && lacks props prop_m then Some (MissingProperty "e requires m")
  else None

let combine_timelocks a b =
  let open TypeProp in
  let a_time = a land (prop_g lor prop_h lor prop_i lor prop_j lor prop_k) in
  let b_time = b land (prop_g lor prop_h lor prop_i lor prop_j lor prop_k) in
  let has_conflict =
    (has a_time prop_g && has b_time prop_h) || (has a_time prop_h && has b_time prop_g) ||
    (has a_time prop_i && has b_time prop_j) || (has a_time prop_j && has b_time prop_i)
  in
  if has_conflict then a_time lor b_time else a_time lor b_time lor prop_k

let rec compute_type ctx node : (node_type, type_error) result =
  let open TypeProp in
  match node with
  | Ms_0 -> Ok { props = type_b lor prop_z lor prop_u lor prop_d lor prop_e lor prop_m lor prop_k;
                 script_size = 1; max_sat_size = -1; max_dissat_size = 0 }
  | Ms_1 -> Ok { props = type_b lor prop_z lor prop_u lor prop_f lor prop_m lor prop_k;
                 script_size = 1; max_sat_size = 0; max_dissat_size = -1 }
  | Ms_pk_k key ->
    let key_size = match key with KeyBytes cs -> Cstruct.length cs | KeyPlaceholder _ -> 33 in
    let push_size = if key_size <= 75 then 1 else 2 in
    Ok { props = type_k lor prop_o lor prop_n lor prop_u lor prop_d lor prop_e lor prop_m lor prop_s lor prop_x lor prop_k;
         script_size = push_size + key_size; max_sat_size = 73; max_dissat_size = 1 }
  | Ms_pk_h _key ->
    Ok { props = type_k lor prop_n lor prop_u lor prop_d lor prop_e lor prop_m lor prop_s lor prop_x lor prop_k;
         script_size = 3 + 20 + 1; max_sat_size = 73 + 34; max_dissat_size = 34 }
  | Ms_older n ->
    if n <= 0 || n >= (1 lsl 31) then Error (InvalidThreshold (n, 1))
    else
      let time_props = if is_time_based_sequence n then prop_g else prop_h in
      let num_size = if n <= 16 then 1 else if n < 0x80 then 2 else if n < 0x8000 then 3 else if n < 0x800000 then 4 else 5 in
      Ok { props = type_b lor prop_z lor prop_f lor prop_m lor time_props lor prop_k;
           script_size = num_size + 1; max_sat_size = 0; max_dissat_size = -1 }
  | Ms_after n ->
    if n <= 0 || n >= (1 lsl 31) then Error (InvalidThreshold (n, 1))
    else
      let time_props = if is_time_based_locktime n then prop_i else prop_j in
      let num_size = if n <= 16 then 1 else if n < 0x80 then 2 else if n < 0x8000 then 3 else if n < 0x800000 then 4 else 5 in
      Ok { props = type_b lor prop_z lor prop_f lor prop_m lor time_props lor prop_k;
           script_size = num_size + 2; max_sat_size = 0; max_dissat_size = -1 }
  | Ms_sha256 h ->
    if Cstruct.length h <> 32 then Error (InvalidMultisig "sha256 requires 32-byte hash")
    else Ok { props = type_b lor prop_o lor prop_n lor prop_u lor prop_d lor prop_m lor prop_k;
              script_size = 4 + 32 + 1; max_sat_size = 33; max_dissat_size = 33 }
  | Ms_hash256 h ->
    if Cstruct.length h <> 32 then Error (InvalidMultisig "hash256 requires 32-byte hash")
    else Ok { props = type_b lor prop_o lor prop_n lor prop_u lor prop_d lor prop_m lor prop_k;
              script_size = 4 + 32 + 1; max_sat_size = 33; max_dissat_size = 33 }
  | Ms_ripemd160 h ->
    if Cstruct.length h <> 20 then Error (InvalidMultisig "ripemd160 requires 20-byte hash")
    else Ok { props = type_b lor prop_o lor prop_n lor prop_u lor prop_d lor prop_m lor prop_k;
              script_size = 4 + 20 + 1; max_sat_size = 33; max_dissat_size = 33 }
  | Ms_hash160 h ->
    if Cstruct.length h <> 20 then Error (InvalidMultisig "hash160 requires 20-byte hash")
    else Ok { props = type_b lor prop_o lor prop_n lor prop_u lor prop_d lor prop_m lor prop_k;
              script_size = 4 + 20 + 1; max_sat_size = 33; max_dissat_size = 33 }
  | Ms_and_v (x, y) -> compute_and_v ctx x y
  | Ms_and_b (x, y) -> compute_and_b ctx x y
  | Ms_or_b (x, y) -> compute_or_b ctx x y
  | Ms_or_c (x, y) -> compute_or_c ctx x y
  | Ms_or_d (x, y) -> compute_or_d ctx x y
  | Ms_or_i (x, y) -> compute_or_i ctx x y
  | Ms_andor (x, y, z) -> compute_andor ctx x y z
  | Ms_thresh (k, subs) -> compute_thresh ctx k subs
  | Ms_multi (k, keys) -> compute_multi ctx k keys
  | Ms_multi_a (k, keys) -> compute_multi_a ctx k keys
  | Ms_wrap (w, x) ->
    (match compute_type ctx x with
     | Error e -> Error e
     | Ok tx -> compute_wrapper ctx w x tx)

and compute_and_v ctx x y =
  let open TypeProp in
  match compute_type ctx x with Error e -> Error e | Ok tx ->
  match compute_type ctx y with Error e -> Error e | Ok ty ->
  (* and_v(X, Y): X must be V-type, Y can be B/V/K, result is same type as Y *)
  if lacks tx.props type_v then Error (MissingProperty "and_v requires V-type first argument")
  else let combined_time = combine_timelocks tx.props ty.props in
       if combined_time land prop_k = 0 then Error ConflictingTimelocks
       else
         (* Calculate z/o/n properties correctly:
            z: both X and Y are z (zero additional stack elements)
            o: exactly one of them is o, and the other is z
            n: either X or Y is n (could be nonzero on top) *)
         let new_z = has tx.props prop_z && has ty.props prop_z in
         let new_o = (has tx.props prop_o && has ty.props prop_z) ||
                     (has tx.props prop_z && has ty.props prop_o) in
         let new_n = has tx.props prop_n || has ty.props prop_n in
         (* Get base type from Y - remove base type bits and zon from Y, then add correct ones *)
         let base_type = ty.props land (type_b lor type_v lor type_k lor type_w) in
         let props = base_type
                     lor (if new_z then prop_z else 0)
                     lor (if new_o then prop_o else 0)
                     lor (if new_n then prop_n else 0)
                     lor (if has tx.props prop_u && has ty.props prop_u then prop_u else 0)
                     lor (if has tx.props prop_s || has ty.props prop_s then prop_s else 0)
                     lor (if has tx.props prop_f || has ty.props prop_f then prop_f else 0)
                     lor (if has tx.props prop_m && has ty.props prop_m then prop_m else 0)
                     lor combined_time in
            Ok { props; script_size = tx.script_size + ty.script_size;
                 max_sat_size = if tx.max_sat_size < 0 || ty.max_sat_size < 0 then -1 else tx.max_sat_size + ty.max_sat_size;
                 max_dissat_size = -1 }

and compute_and_b ctx x y =
  let open TypeProp in
  match compute_type ctx x with Error e -> Error e | Ok tx ->
  match compute_type ctx y with Error e -> Error e | Ok ty ->
  if lacks tx.props type_b then Error (MissingProperty "and_b requires B-type first argument")
  else if lacks ty.props type_w then Error (MissingProperty "and_b requires W-type second argument")
  else let combined_time = combine_timelocks tx.props ty.props in
       if combined_time land prop_k = 0 then Error ConflictingTimelocks
       else let props = type_b lor (if has tx.props prop_z && has ty.props prop_z then prop_z else 0)
                       lor (if has tx.props prop_o && has ty.props prop_z then prop_o else 0)
                       lor (if has tx.props prop_z && has ty.props prop_o then prop_o else 0)
                       lor (if has tx.props prop_n || has ty.props prop_n then prop_n else 0)
                       lor (if has tx.props prop_d && has ty.props prop_d then prop_d else 0) lor prop_u
                       lor (if has tx.props prop_e && has ty.props prop_e && (has tx.props prop_s || has ty.props prop_f) && (has ty.props prop_s || has tx.props prop_f) then prop_e else 0)
                       lor (if has tx.props prop_s || has ty.props prop_s then prop_s else 0)
                       lor (if has tx.props prop_f && has ty.props prop_f then prop_f else 0)
                       lor (if has tx.props prop_m && has ty.props prop_m then prop_m else 0)
                       lor combined_time in
            Ok { props; script_size = tx.script_size + ty.script_size + 1;
                 max_sat_size = if tx.max_sat_size < 0 || ty.max_sat_size < 0 then -1 else tx.max_sat_size + ty.max_sat_size;
                 max_dissat_size = if tx.max_dissat_size < 0 || ty.max_dissat_size < 0 then -1 else tx.max_dissat_size + ty.max_dissat_size }

and compute_or_b ctx x y =
  let open TypeProp in
  match compute_type ctx x with Error e -> Error e | Ok tx ->
  match compute_type ctx y with Error e -> Error e | Ok ty ->
  if lacks tx.props type_b || lacks tx.props prop_d then Error (MissingProperty "or_b requires Bd-type first argument")
  else if lacks ty.props type_w || lacks ty.props prop_d then Error (MissingProperty "or_b requires Wd-type second argument")
  else let combined_time = combine_timelocks tx.props ty.props in
       let props = type_b lor (if has tx.props prop_z && has ty.props prop_z then prop_z else 0)
                   lor (if has tx.props prop_o && has ty.props prop_z then prop_o else 0)
                   lor (if has tx.props prop_z && has ty.props prop_o then prop_o else 0)
                   lor prop_d lor prop_u
                   lor (if has tx.props prop_e && has ty.props prop_e && has tx.props prop_s && has ty.props prop_s then prop_e else 0)
                   lor (if has tx.props prop_s && has ty.props prop_s then prop_s else 0)
                   lor (if has tx.props prop_m && has ty.props prop_m && has tx.props prop_e && has ty.props prop_e then prop_m else 0)
                   lor combined_time in
       let sat_xy = if tx.max_sat_size < 0 || ty.max_dissat_size < 0 then max_int else tx.max_sat_size + ty.max_dissat_size in
       let sat_yx = if ty.max_sat_size < 0 || tx.max_dissat_size < 0 then max_int else ty.max_sat_size + tx.max_dissat_size in
       let max_sat = min sat_xy sat_yx in
       Ok { props; script_size = tx.script_size + ty.script_size + 1;
            max_sat_size = if max_sat = max_int then -1 else max_sat;
            max_dissat_size = if tx.max_dissat_size < 0 || ty.max_dissat_size < 0 then -1 else tx.max_dissat_size + ty.max_dissat_size }

and compute_or_c ctx x y =
  let open TypeProp in
  match compute_type ctx x with Error e -> Error e | Ok tx ->
  match compute_type ctx y with Error e -> Error e | Ok ty ->
  if lacks tx.props type_b || lacks tx.props prop_d || lacks tx.props prop_u then Error (MissingProperty "or_c requires Bdu-type first argument")
  else if lacks ty.props type_v then Error (MissingProperty "or_c requires V-type second argument")
  else let combined_time = combine_timelocks tx.props ty.props in
       let props = type_v lor (if has tx.props prop_z && has ty.props prop_z then prop_z else 0)
                   lor (if has tx.props prop_o && has ty.props prop_z then prop_o else 0)
                   lor (if has tx.props prop_z && has ty.props prop_o then prop_o else 0)
                   lor (if has tx.props prop_s || has ty.props prop_s then prop_s else 0)
                   lor (if has tx.props prop_m && has ty.props prop_m then prop_m else 0)
                   lor combined_time in
       let sat_x = tx.max_sat_size in
       let sat_y = if ty.max_sat_size < 0 || tx.max_dissat_size < 0 then max_int else ty.max_sat_size + tx.max_dissat_size in
       let max_sat = min (if sat_x < 0 then max_int else sat_x) sat_y in
       Ok { props; script_size = tx.script_size + ty.script_size + 2;
            max_sat_size = if max_sat = max_int then -1 else max_sat; max_dissat_size = -1 }

and compute_or_d ctx x y =
  let open TypeProp in
  match compute_type ctx x with Error e -> Error e | Ok tx ->
  match compute_type ctx y with Error e -> Error e | Ok ty ->
  if lacks tx.props type_b || lacks tx.props prop_d || lacks tx.props prop_u then Error (MissingProperty "or_d requires Bdu-type first argument")
  else if lacks ty.props type_b then Error (MissingProperty "or_d requires B-type second argument")
  else let combined_time = combine_timelocks tx.props ty.props in
       let props = type_b lor (if has tx.props prop_z && has ty.props prop_z then prop_z else 0)
                   lor (if has tx.props prop_o && has ty.props prop_z then prop_o else 0)
                   lor (if has tx.props prop_z && has ty.props prop_o then prop_o else 0)
                   lor (if has ty.props prop_d then prop_d else 0)
                   lor (if has tx.props prop_u && has ty.props prop_u then prop_u else 0)
                   lor (if has ty.props prop_e && has tx.props prop_s then prop_e else 0)
                   lor (if has tx.props prop_s || has ty.props prop_s then prop_s else 0)
                   lor (if has ty.props prop_f && has tx.props prop_s then prop_f else 0)
                   lor (if has tx.props prop_m && has ty.props prop_m && has tx.props prop_e then prop_m else 0)
                   lor combined_time in
       let sat_x = tx.max_sat_size in
       let sat_y = if ty.max_sat_size < 0 || tx.max_dissat_size < 0 then max_int else ty.max_sat_size + tx.max_dissat_size in
       let max_sat = min (if sat_x < 0 then max_int else sat_x) sat_y in
       Ok { props; script_size = tx.script_size + ty.script_size + 3;
            max_sat_size = if max_sat = max_int then -1 else max_sat;
            max_dissat_size = if ty.max_dissat_size < 0 || tx.max_dissat_size < 0 then -1 else ty.max_dissat_size + tx.max_dissat_size }

and compute_or_i ctx x y =
  let open TypeProp in
  match compute_type ctx x with Error e -> Error e | Ok tx ->
  match compute_type ctx y with Error e -> Error e | Ok ty ->
  let base_x = get_base_type tx.props in
  let base_y = get_base_type ty.props in
  if base_x <> base_y then Error (IncompatibleBase "or_i requires same base type for both branches")
  else let combined_time = combine_timelocks tx.props ty.props in
       let base = match base_x with Some TypeB -> type_b | Some TypeV -> type_v | Some TypeK -> type_k | Some TypeW -> type_w | None -> 0 in
       let props = base lor (if has tx.props prop_o && has ty.props prop_o then prop_o else 0)
                   lor (if has tx.props prop_u && has ty.props prop_u then prop_u else 0)
                   lor (if has tx.props prop_d || has ty.props prop_d then prop_d else 0)
                   lor (if has tx.props prop_s && has ty.props prop_s then prop_s else 0)
                   lor (if has tx.props prop_f || has ty.props prop_f then prop_f else 0)
                   lor (if has tx.props prop_e && has ty.props prop_f || has ty.props prop_e && has tx.props prop_f then prop_e else 0)
                   lor (if has tx.props prop_m && has ty.props prop_m && (has tx.props prop_s || has ty.props prop_f) && (has ty.props prop_s || has tx.props prop_f) then prop_m else 0)
                   lor combined_time in
       let max_sat = let sx = if tx.max_sat_size < 0 then max_int else tx.max_sat_size + 1 in
                     let sy = if ty.max_sat_size < 0 then max_int else ty.max_sat_size + 1 in min sx sy in
       let max_dis = let dx = if tx.max_dissat_size < 0 then max_int else tx.max_dissat_size + 1 in
                     let dy = if ty.max_dissat_size < 0 then max_int else ty.max_dissat_size + 1 in min dx dy in
       Ok { props; script_size = tx.script_size + ty.script_size + 3;
            max_sat_size = if max_sat = max_int then -1 else max_sat;
            max_dissat_size = if max_dis = max_int then -1 else max_dis }

and compute_andor ctx x y z =
  let open TypeProp in
  match compute_type ctx x with Error e -> Error e | Ok tx ->
  match compute_type ctx y with Error e -> Error e | Ok ty ->
  match compute_type ctx z with Error e -> Error e | Ok tz ->
  if lacks tx.props type_b || lacks tx.props prop_d || lacks tx.props prop_u then Error (MissingProperty "andor requires Bdu-type first argument")
  else let base_y = get_base_type ty.props in let base_z = get_base_type tz.props in
       if base_y <> base_z then Error (IncompatibleBase "andor requires same base type for Y and Z")
       else let combined_time = combine_timelocks tx.props (combine_timelocks ty.props tz.props) in
            let base = match base_y with Some TypeB -> type_b | Some TypeV -> type_v | Some TypeK -> type_k | Some TypeW -> type_w | None -> 0 in
            let props = base lor (if has tx.props prop_z && has ty.props prop_z && has tz.props prop_z then prop_z else 0)
                        lor (if (has tx.props prop_z && has ty.props prop_o && has tz.props prop_o) || (has tx.props prop_o && has ty.props prop_z && has tz.props prop_z) then prop_o else 0)
                        lor (if has ty.props prop_u && has tz.props prop_u then prop_u else 0)
                        lor (if has tz.props prop_d then prop_d else 0)
                        lor (if has ty.props prop_s || has tz.props prop_s then prop_s else 0)
                        lor (if has ty.props prop_f || (has tz.props prop_f && has tx.props prop_s) then prop_f else 0)
                        lor (if has tz.props prop_e && has tx.props prop_s then prop_e else 0)
                        lor (if has tx.props prop_m && has ty.props prop_m && has tz.props prop_m && has tx.props prop_e && (has tx.props prop_s || has ty.props prop_f || has tz.props prop_f) then prop_m else 0)
                        lor combined_time in
            let sat_xy = if tx.max_sat_size < 0 || ty.max_sat_size < 0 then max_int else tx.max_sat_size + ty.max_sat_size in
            let sat_z = if tx.max_dissat_size < 0 || tz.max_sat_size < 0 then max_int else tx.max_dissat_size + tz.max_sat_size in
            let max_sat = min sat_xy sat_z in
            Ok { props; script_size = tx.script_size + ty.script_size + tz.script_size + 3;
                 max_sat_size = if max_sat = max_int then -1 else max_sat;
                 max_dissat_size = if tx.max_dissat_size < 0 || tz.max_dissat_size < 0 then -1 else tx.max_dissat_size + tz.max_dissat_size }

and compute_thresh ctx k subs =
  let open TypeProp in
  let n = List.length subs in
  if k < 1 || k > n then Error (InvalidThreshold (k, n)) else if n = 0 then Error (InvalidThreshold (k, 0))
  else let rec type_all acc = function [] -> Ok (List.rev acc) | x :: xs -> match compute_type ctx x with Error e -> Error e | Ok t -> type_all (t :: acc) xs in
       match type_all [] subs with Error e -> Error e | Ok types ->
       match types with [] -> Error (InvalidThreshold (k, 0)) | t0 :: rest ->
       if lacks t0.props type_b || lacks t0.props prop_d || lacks t0.props prop_u then Error (MissingProperty "thresh requires Bdu-type first argument")
       else let all_wdu = List.for_all (fun t -> has t.props type_w && has t.props prop_d && has t.props prop_u) rest in
            if not all_wdu then Error (MissingProperty "thresh requires Wdu-type remaining arguments")
            else let all_z = List.for_all (fun t -> has t.props prop_z) types in
                 let count_o = List.length (List.filter (fun t -> has t.props prop_o) types) in
                 let all_e = List.for_all (fun t -> has t.props prop_e) types in
                 let all_m = List.for_all (fun t -> has t.props prop_m) types in
                 let any_s = List.exists (fun t -> has t.props prop_s) types in
                 let count_s = List.length (List.filter (fun t -> has t.props prop_s) types) in
                 let combined_time = List.fold_left (fun acc t -> combine_timelocks acc t.props) (prop_g lor prop_h lor prop_i lor prop_j lor prop_k) types in
                 let props = type_b lor prop_d lor prop_u lor (if all_z then prop_z else 0)
                             lor (if count_o = 1 && (List.length types - count_o) = (List.length (List.filter (fun t -> has t.props prop_z) types)) then prop_o else 0)
                             lor (if all_e && count_s >= n - k then prop_e else 0) lor (if any_s then prop_s else 0)
                             lor (if all_m && all_e && count_s >= n - k then prop_m else 0) lor combined_time in
                 let script_size = List.fold_left (fun acc t -> acc + t.script_size) 0 types + (n - 1) + (if k <= 16 then 1 else if k < 0x80 then 2 else 3) + 1 in
                 let max_sat = let sats = List.filter_map (fun t -> if t.max_sat_size >= 0 then Some t.max_sat_size else None) types in
                               let dissats = List.filter_map (fun t -> if t.max_dissat_size >= 0 then Some t.max_dissat_size else None) types in
                               if List.length sats < k || List.length dissats < (n - k) then -1
                               else let sorted_sats = List.sort compare sats in let k_sats = List.filteri (fun i _ -> i < k) sorted_sats in
                                    let sorted_dissats = List.sort compare dissats in let nk_dissats = List.filteri (fun i _ -> i < n - k) sorted_dissats in
                                    List.fold_left (+) 0 k_sats + List.fold_left (+) 0 nk_dissats in
                 let max_dissat = let dissats = List.filter_map (fun t -> if t.max_dissat_size >= 0 then Some t.max_dissat_size else None) types in
                                  if List.length dissats < n then -1 else List.fold_left (+) 0 dissats in
                 Ok { props; script_size; max_sat_size = max_sat; max_dissat_size = max_dissat }

and compute_multi ctx k keys =
  let open TypeProp in let n = List.length keys in
  if k < 1 || k > n then Error (InvalidThreshold (k, n)) else if n > 20 then Error (InvalidMultisig "multi limited to 20 keys")
  else if ctx = Tapscript then Error (ContextMismatch "multi not allowed in tapscript, use multi_a")
  else let key_sizes = List.map (fun k -> match k with KeyBytes cs -> Cstruct.length cs | KeyPlaceholder _ -> 33) keys in
       let script_size = 1 + List.fold_left (fun acc ks -> acc + 1 + ks) 0 key_sizes + 1 + 1 in
       Ok { props = type_b lor prop_n lor prop_u lor prop_d lor prop_e lor prop_m lor prop_s lor prop_k;
            script_size; max_sat_size = 1 + k * 73; max_dissat_size = 1 + n }

and compute_multi_a ctx k keys =
  let open TypeProp in let n = List.length keys in
  if k < 1 || k > n then Error (InvalidThreshold (k, n)) else if n > 999 then Error (InvalidMultisig "multi_a limited to 999 keys")
  else if ctx = P2WSH then Error (ContextMismatch "multi_a only allowed in tapscript")
  else let key_sizes = List.map (fun k -> match k with KeyBytes cs -> Cstruct.length cs | KeyPlaceholder _ -> 32) keys in
       let script_size = List.fold_left (fun acc ks -> acc + 1 + ks) 0 key_sizes + 1 + (n - 1) + (if k <= 16 then 1 else 2) + 1 in
       Ok { props = type_b lor prop_n lor prop_u lor prop_d lor prop_e lor prop_m lor prop_s lor prop_k;
            script_size; max_sat_size = n * 65; max_dissat_size = n }

and compute_wrapper ctx w x tx =
  let open TypeProp in
  match w with
  | WrapA -> if lacks tx.props type_b then Error (MissingProperty "a: wrapper requires B-type argument")
             else Ok { props = type_w lor (tx.props land (prop_d lor prop_u lor prop_s lor prop_m lor prop_e lor prop_f lor prop_g lor prop_h lor prop_i lor prop_j lor prop_k));
                       script_size = tx.script_size + 2; max_sat_size = tx.max_sat_size; max_dissat_size = tx.max_dissat_size }
  | WrapS -> if lacks tx.props type_b || lacks tx.props prop_o then Error (MissingProperty "s: wrapper requires Bo-type argument")
             else Ok { props = type_w lor (tx.props land (prop_d lor prop_u lor prop_s lor prop_m lor prop_e lor prop_f lor prop_g lor prop_h lor prop_i lor prop_j lor prop_k));
                       script_size = tx.script_size + 1; max_sat_size = tx.max_sat_size; max_dissat_size = tx.max_dissat_size }
  | WrapC -> if lacks tx.props type_k then Error (MissingProperty "c: wrapper requires K-type argument")
             else Ok { props = type_b lor (tx.props land (prop_o lor prop_n lor prop_d lor prop_u lor prop_s lor prop_m lor prop_e lor prop_f lor prop_g lor prop_h lor prop_i lor prop_j lor prop_k));
                       script_size = tx.script_size + 1; max_sat_size = tx.max_sat_size; max_dissat_size = tx.max_dissat_size }
  | WrapD -> if lacks tx.props type_v || lacks tx.props prop_z then Error (MissingProperty "d: wrapper requires Vz-type argument")
             else Ok { props = type_b lor prop_o lor prop_n lor prop_d lor prop_u lor (tx.props land (prop_s lor prop_m lor prop_g lor prop_h lor prop_i lor prop_j lor prop_k)) lor (if has tx.props prop_s then prop_e else 0);
                       script_size = tx.script_size + 3; max_sat_size = if tx.max_sat_size < 0 then -1 else tx.max_sat_size + 1; max_dissat_size = 1 }
  | WrapV -> if lacks tx.props type_b then Error (MissingProperty "v: wrapper requires B-type argument")
             else let extra_size = if has tx.props prop_x then 1 else 0 in
                  Ok { props = type_v lor (tx.props land (prop_z lor prop_o lor prop_n lor prop_s lor prop_m lor prop_g lor prop_h lor prop_i lor prop_j lor prop_k)) lor prop_f;
                       script_size = tx.script_size + extra_size; max_sat_size = tx.max_sat_size; max_dissat_size = -1 }
  | WrapJ -> if lacks tx.props type_b || lacks tx.props prop_n then Error (MissingProperty "j: wrapper requires Bn-type argument")
             else Ok { props = type_b lor prop_o lor prop_n lor prop_d lor prop_u lor (tx.props land (prop_s lor prop_m lor prop_e lor prop_f lor prop_g lor prop_h lor prop_i lor prop_j lor prop_k));
                       script_size = tx.script_size + 4; max_sat_size = tx.max_sat_size; max_dissat_size = 1 }
  | WrapN -> if lacks tx.props type_b then Error (MissingProperty "n: wrapper requires B-type argument")
             else Ok { props = type_b lor (tx.props land (prop_z lor prop_o lor prop_d lor prop_s lor prop_m lor prop_e lor prop_f lor prop_g lor prop_h lor prop_i lor prop_j lor prop_k)) lor prop_u;
                       script_size = tx.script_size + 1; max_sat_size = tx.max_sat_size; max_dissat_size = tx.max_dissat_size }
  | WrapL -> (match compute_type ctx (Ms_or_i (Ms_0, Ms_wrap (WrapN, x))) with Error e -> Error e | Ok t -> Ok { t with script_size = t.script_size })
  | WrapU -> (match compute_type ctx (Ms_or_i (Ms_wrap (WrapN, x), Ms_0)) with Error e -> Error e | Ok t -> Ok { t with script_size = t.script_size })
  | WrapT -> compute_type ctx (Ms_and_v (Ms_wrap (WrapV, x), Ms_1))

let type_check ctx node = match compute_type ctx node with Error e -> Error e | Ok t -> match validate_type t.props with Some err -> Error err | None -> Ok t

(* ============================================================================
   Script Generation
   ============================================================================ *)

let serialize_number n =
  if n = 0 then [0x00]  (* OP_0 *)
  else if n >= 1 && n <= 16 then [0x50 + n]  (* OP_1 through OP_16 *)
  else if n = -1 then [0x4f]  (* OP_1NEGATE *)
  else
    (* CScriptNum encoding *)
    let abs_n = abs n in
    let rec num_bytes acc v =
      if v = 0 then List.rev acc
      else num_bytes ((v land 0xff) :: acc) (v lsr 8)
    in
    let bytes = if abs_n = 0 then [0] else num_bytes [] abs_n in
    let bytes =
      if List.nth bytes (List.length bytes - 1) land 0x80 <> 0 then
        bytes @ [if n < 0 then 0x80 else 0x00]
      else if n < 0 then
        let last_idx = List.length bytes - 1 in
        List.mapi (fun i b -> if i = last_idx then b lor 0x80 else b) bytes
      else bytes
    in
    let len = List.length bytes in
    if len <= 75 then len :: bytes
    else if len <= 0xff then 0x4c :: len :: bytes
    else [0x4d; len land 0xff; len lsr 8] @ bytes

let serialize_push data =
  let len = Cstruct.length data in
  let bytes = List.init len (fun i -> Cstruct.get_uint8 data i) in
  if len <= 75 then len :: bytes
  else if len <= 0xff then 0x4c :: len :: bytes
  else if len <= 0xffff then [0x4d; len land 0xff; len lsr 8] @ bytes
  else [0x4e; len land 0xff; (len lsr 8) land 0xff; (len lsr 16) land 0xff; len lsr 24] @ bytes

let serialize_key key =
  match key with
  | KeyBytes cs -> serialize_push cs
  | KeyPlaceholder _ -> serialize_push (Cstruct.create 33)  (* placeholder: 33 zero bytes *)

(* Opcodes *)
let op_0 = 0x00
let op_if = 0x63
let op_notif = 0x64
let op_else = 0x67
let op_endif = 0x68
let op_verify = 0x69
let op_return = 0x6a
let op_toaltstack = 0x6b
let op_fromaltstack = 0x6c
let op_ifdup = 0x73
let op_size = 0x82
let op_equal = 0x87
let op_equalverify = 0x88
let op_0notequal = 0x92
let op_booland = 0x9a
let op_boolor = 0x9b
let op_add = 0x93
let op_numequal = 0x9c
let op_dup = 0x76
let op_swap = 0x7c
let op_sha256 = 0xa8
let op_hash160 = 0xa9
let op_hash256 = 0xaa
let op_ripemd160 = 0xa6
let op_checksig = 0xac
let op_checkmultisig = 0xae
let op_checksigverify = 0xad
let op_checksigadd = 0xba
let op_checklocktimeverify = 0xb1
let op_checksequenceverify = 0xb2
let op_drop = 0x75

let rec to_script_inner ctx node =
  match node with
  | Ms_0 -> [op_0]
  | Ms_1 -> [0x51]  (* OP_1 *)
  | Ms_pk_k key -> serialize_key key
  | Ms_pk_h key ->
    let keyhash = match key with
      | KeyBytes cs ->
        let sha = Digestif.SHA256.digest_string (Cstruct.to_string cs) in
        let ripemd = Digestif.RMD160.digest_string (Digestif.SHA256.to_raw_string sha) in
        Cstruct.of_string (Digestif.RMD160.to_raw_string ripemd)
      | KeyPlaceholder _ -> Cstruct.create 20
    in
    [op_dup; op_hash160] @ serialize_push keyhash @ [op_equalverify]
  | Ms_older n -> serialize_number n @ [op_checksequenceverify]
  | Ms_after n -> serialize_number n @ [op_checklocktimeverify; op_drop]
  | Ms_sha256 h -> [op_size] @ serialize_number 32 @ [op_equalverify; op_sha256] @ serialize_push h @ [op_equal]
  | Ms_hash256 h -> [op_size] @ serialize_number 32 @ [op_equalverify; op_hash256] @ serialize_push h @ [op_equal]
  | Ms_ripemd160 h -> [op_size] @ serialize_number 32 @ [op_equalverify; op_ripemd160] @ serialize_push h @ [op_equal]
  | Ms_hash160 h -> [op_size] @ serialize_number 32 @ [op_equalverify; op_hash160] @ serialize_push h @ [op_equal]
  | Ms_and_v (x, y) -> to_script_inner ctx x @ to_script_inner ctx y
  | Ms_and_b (x, y) -> to_script_inner ctx x @ to_script_inner ctx y @ [op_booland]
  | Ms_or_b (x, y) -> to_script_inner ctx x @ to_script_inner ctx y @ [op_boolor]
  | Ms_or_c (x, y) -> to_script_inner ctx x @ [op_notif] @ to_script_inner ctx y @ [op_endif]
  | Ms_or_d (x, y) -> to_script_inner ctx x @ [op_ifdup; op_notif] @ to_script_inner ctx y @ [op_endif]
  | Ms_or_i (x, y) -> [op_if] @ to_script_inner ctx x @ [op_else] @ to_script_inner ctx y @ [op_endif]
  | Ms_andor (x, y, z) -> to_script_inner ctx x @ [op_notif] @ to_script_inner ctx z @ [op_else] @ to_script_inner ctx y @ [op_endif]
  | Ms_thresh (k, subs) ->
    (match subs with
     | [] -> []
     | [s] -> to_script_inner ctx s
     | s0 :: rest ->
       let first_script = to_script_inner ctx s0 in
       let rest_script = List.fold_left (fun acc s -> acc @ to_script_inner ctx s @ [op_add]) [] rest in
       first_script @ rest_script @ serialize_number k @ [op_numequal])
  | Ms_multi (k, keys) ->
    serialize_number k @
    List.concat_map serialize_key keys @
    serialize_number (List.length keys) @
    [op_checkmultisig]
  | Ms_multi_a (k, keys) ->
    let rec build_keys = function
      | [] -> []
      | [key] -> serialize_key key @ [op_checksig]
      | key :: rest -> serialize_key key @ [op_checksigadd] @ build_keys rest
    in
    build_keys keys @ serialize_number k @ [op_numequal]
  | Ms_wrap (w, x) ->
    let inner = to_script_inner ctx x in
    (match w with
     | WrapA -> [op_toaltstack] @ inner @ [op_fromaltstack]
     | WrapS -> [op_swap] @ inner
     | WrapC -> inner @ [op_checksig]
     | WrapD -> [op_dup; op_if] @ inner @ [op_endif]
     | WrapV ->
       (* Check if last opcode can be converted to VERIFY form *)
       (match List.rev inner with
        | last :: rest when last = op_equal -> List.rev (op_equalverify :: rest)
        | last :: rest when last = op_checksig -> List.rev (op_checksigverify :: rest)
        | last :: rest when last = op_numequal -> List.rev (0x9d :: rest)  (* OP_NUMEQUALVERIFY *)
        | _ -> inner @ [op_verify])
     | WrapJ -> [op_size; op_0notequal; op_if] @ inner @ [op_endif]
     | WrapN -> inner @ [op_0notequal]
     | WrapL -> to_script_inner ctx (Ms_or_i (Ms_0, x))
     | WrapU -> to_script_inner ctx (Ms_or_i (x, Ms_0))
     | WrapT -> to_script_inner ctx (Ms_and_v (Ms_wrap (WrapV, x), Ms_1)))

let to_script ctx node =
  let bytes = to_script_inner ctx node in
  Cstruct.of_string (String.init (List.length bytes) (fun i -> Char.chr (List.nth bytes i)))

(* ============================================================================
   Satisfaction / Witness Generation
   ============================================================================ *)

type availability =
  | AvailNo     (* Cannot satisfy this condition *)
  | AvailYes    (* Can satisfy this condition *)
  | AvailMaybe  (* May be able to satisfy (e.g., timelock may be valid) *)

type witness_item = Cstruct.t

type sat_info = {
  available : availability;
  has_sig : bool;
  items : witness_item list;
}

type satisfaction_result = {
  sat : sat_info;
  dissat : sat_info;
}

(* Signing context type *)
type sign_ctx = {
  sign : key -> Cstruct.t option;
  check_older : int -> bool;
  check_after : int -> bool;
  lookup_preimage : Cstruct.t -> hash_type -> Cstruct.t option;
}

(* Default empty signing context *)
let empty_sign_ctx = {
  sign = (fun _ -> None);
  check_older = (fun _ -> false);
  check_after = (fun _ -> false);
  lookup_preimage = (fun _ _ -> None);
}

let sat_yes items has_sig = { available = AvailYes; has_sig; items }
let sat_no = { available = AvailNo; has_sig = false; items = [] }
let sat_maybe = { available = AvailMaybe; has_sig = false; items = [] }

let combine_sat_and a b =
  match a.available, b.available with
  | AvailYes, AvailYes -> { available = AvailYes; has_sig = a.has_sig || b.has_sig; items = a.items @ b.items }
  | AvailNo, _ | _, AvailNo -> sat_no
  | AvailMaybe, _ | _, AvailMaybe -> sat_maybe

let combine_sat_or a b =
  match a.available, b.available with
  | AvailYes, AvailYes ->
    (* Prefer shorter or one with signature for malleability *)
    if List.length a.items <= List.length b.items then a else b
  | AvailYes, _ -> a
  | _, AvailYes -> b
  | AvailMaybe, _ -> sat_maybe
  | _, AvailMaybe -> sat_maybe
  | AvailNo, AvailNo -> sat_no

let rec satisfy_inner _ctx sctx node =
  match node with
  | Ms_0 -> { sat = sat_no; dissat = sat_yes [] false }
  | Ms_1 -> { sat = sat_yes [] false; dissat = sat_no }
  | Ms_pk_k key ->
    (match sctx.sign key with
     | Some sig_bytes -> { sat = sat_yes [sig_bytes] true; dissat = sat_yes [Cstruct.create 0] false }
     | None -> { sat = sat_maybe; dissat = sat_yes [Cstruct.create 0] false })
  | Ms_pk_h key ->
    let pubkey = match key with KeyBytes cs -> cs | KeyPlaceholder _ -> Cstruct.create 33 in
    (match sctx.sign key with
     | Some sig_bytes -> { sat = sat_yes [sig_bytes; pubkey] true; dissat = sat_yes [Cstruct.create 0; pubkey] false }
     | None -> { sat = sat_maybe; dissat = sat_yes [Cstruct.create 0; pubkey] false })
  | Ms_older n ->
    if sctx.check_older n then
      { sat = sat_yes [] false; dissat = sat_no }
    else
      { sat = sat_maybe; dissat = sat_no }
  | Ms_after n ->
    if sctx.check_after n then
      { sat = sat_yes [] false; dissat = sat_no }
    else
      { sat = sat_maybe; dissat = sat_no }
  | Ms_sha256 h -> satisfy_hash_inner sctx h HashSha256
  | Ms_hash256 h -> satisfy_hash_inner sctx h HashHash256
  | Ms_ripemd160 h -> satisfy_hash_inner sctx h HashRipemd160
  | Ms_hash160 h -> satisfy_hash_inner sctx h HashHash160
  | Ms_and_v (x, y) ->
    let rx = satisfy_inner _ctx sctx x in
    let ry = satisfy_inner _ctx sctx y in
    { sat = combine_sat_and rx.sat ry.sat; dissat = sat_no }
  | Ms_and_b (x, y) ->
    let rx = satisfy_inner _ctx sctx x in
    let ry = satisfy_inner _ctx sctx y in
    { sat = combine_sat_and rx.sat ry.sat; dissat = combine_sat_and rx.dissat ry.dissat }
  | Ms_or_b (x, y) ->
    let rx = satisfy_inner _ctx sctx x in
    let ry = satisfy_inner _ctx sctx y in
    let sat1 = combine_sat_and rx.sat ry.dissat in
    let sat2 = combine_sat_and rx.dissat ry.sat in
    { sat = combine_sat_or sat1 sat2; dissat = combine_sat_and rx.dissat ry.dissat }
  | Ms_or_c (x, y) ->
    let rx = satisfy_inner _ctx sctx x in
    let ry = satisfy_inner _ctx sctx y in
    let sat2 = combine_sat_and rx.dissat ry.sat in
    { sat = combine_sat_or rx.sat sat2; dissat = sat_no }
  | Ms_or_d (x, y) ->
    let rx = satisfy_inner _ctx sctx x in
    let ry = satisfy_inner _ctx sctx y in
    let sat2 = combine_sat_and rx.dissat ry.sat in
    { sat = combine_sat_or rx.sat sat2; dissat = combine_sat_and rx.dissat ry.dissat }
  | Ms_or_i (x, y) ->
    let rx = satisfy_inner _ctx sctx x in
    let ry = satisfy_inner _ctx sctx y in
    let sat1 = { rx.sat with items = rx.sat.items @ [Cstruct.of_string "\x01"] } in
    let sat2 = { ry.sat with items = ry.sat.items @ [Cstruct.create 0] } in
    let dissat1 = { rx.dissat with items = rx.dissat.items @ [Cstruct.of_string "\x01"] } in
    let dissat2 = { ry.dissat with items = ry.dissat.items @ [Cstruct.create 0] } in
    { sat = combine_sat_or sat1 sat2; dissat = combine_sat_or dissat1 dissat2 }
  | Ms_andor (x, y, z) ->
    let rx = satisfy_inner _ctx sctx x in
    let ry = satisfy_inner _ctx sctx y in
    let rz = satisfy_inner _ctx sctx z in
    let sat1 = combine_sat_and rx.sat ry.sat in
    let sat2 = combine_sat_and rx.dissat rz.sat in
    { sat = combine_sat_or sat1 sat2; dissat = combine_sat_and rx.dissat rz.dissat }
  | Ms_thresh (k, subs) -> satisfy_thresh_inner _ctx sctx k subs
  | Ms_multi (k, keys) -> satisfy_multi_inner sctx k keys
  | Ms_multi_a (k, keys) -> satisfy_multi_a_inner sctx k keys
  | Ms_wrap (w, x) -> satisfy_wrapper_inner _ctx sctx w x

and satisfy_hash_inner sctx h ht =
  match sctx.lookup_preimage h ht with
  | Some preimage -> { sat = sat_yes [preimage] false; dissat = sat_yes [Cstruct.create 32] false }
  | None -> { sat = sat_maybe; dissat = sat_yes [Cstruct.create 32] false }

and satisfy_thresh_inner ctx sctx k subs =
  let results = List.map (satisfy_inner ctx sctx) subs in
  let n = List.length subs in
  let sats_available = List.filter (fun r -> r.sat.available = AvailYes) results in
  let dissats_available = List.filter (fun r -> r.dissat.available = AvailYes) results in
  if List.length sats_available >= k && List.length dissats_available >= (n - k) then
    let all_items = List.mapi (fun i r ->
      if i < k then r.sat.items else r.dissat.items
    ) results |> List.concat in
    let has_sig = List.exists (fun r -> r.sat.has_sig) (List.filteri (fun i _ -> i < k) results) in
    let dissat_items = List.concat_map (fun r -> r.dissat.items) results in
    { sat = sat_yes all_items has_sig; dissat = sat_yes dissat_items false }
  else if List.length dissats_available >= n then
    let dissat_items = List.concat_map (fun r -> r.dissat.items) results in
    { sat = sat_maybe; dissat = sat_yes dissat_items false }
  else
    { sat = sat_maybe; dissat = sat_maybe }

and satisfy_multi_inner sctx k keys =
  let sigs = List.filter_map sctx.sign keys in
  let n = List.length keys in
  if List.length sigs >= k then
    let chosen = List.filteri (fun i _ -> i < k) sigs in
    let dissat_items = Cstruct.create 0 :: List.init n (fun _ -> Cstruct.create 0) in
    { sat = sat_yes (Cstruct.create 0 :: chosen) true; dissat = sat_yes dissat_items false }
  else
    let dissat_items = Cstruct.create 0 :: List.init n (fun _ -> Cstruct.create 0) in
    { sat = sat_maybe; dissat = sat_yes dissat_items false }

and satisfy_multi_a_inner sctx k keys =
  let n = List.length keys in
  let sigs = List.map (fun key ->
    match sctx.sign key with Some s -> s | None -> Cstruct.create 0
  ) keys in
  let valid = List.filter (fun s -> Cstruct.length s > 0) sigs in
  if List.length valid >= k then
    let dissat_items = List.init n (fun _ -> Cstruct.create 0) in
    { sat = sat_yes sigs true; dissat = sat_yes dissat_items false }
  else
    let dissat_items = List.init n (fun _ -> Cstruct.create 0) in
    { sat = sat_maybe; dissat = sat_yes dissat_items false }

and satisfy_wrapper_inner ctx sctx w x =
  let r = satisfy_inner ctx sctx x in
  match w with
  | WrapA | WrapS | WrapC | WrapN -> r
  | WrapD ->
    let sat = { r.sat with items = r.sat.items @ [Cstruct.of_string "\x01"] } in
    { sat; dissat = sat_yes [Cstruct.create 0] false }
  | WrapV -> { sat = r.sat; dissat = sat_no }
  | WrapJ -> { sat = r.sat; dissat = sat_yes [Cstruct.create 0] false }
  | WrapL -> satisfy_inner ctx sctx (Ms_or_i (Ms_0, x))
  | WrapU -> satisfy_inner ctx sctx (Ms_or_i (x, Ms_0))
  | WrapT -> satisfy_inner ctx sctx (Ms_and_v (Ms_wrap (WrapV, x), Ms_1))

let satisfy ctx sctx node = satisfy_inner ctx sctx node

(* ============================================================================
   Analysis Functions
   ============================================================================ *)

let max_satisfaction_size ctx node =
  match compute_type ctx node with
  | Error _ -> 0
  | Ok t -> if t.max_sat_size < 0 then 0 else t.max_sat_size

let max_dissatisfaction_size ctx node =
  match compute_type ctx node with
  | Error _ -> 0
  | Ok t -> if t.max_dissat_size < 0 then 0 else t.max_dissat_size

let script_size ctx node =
  match compute_type ctx node with
  | Error _ -> 0
  | Ok t -> t.script_size

let requires_signature _ctx node =
  let rec check = function
    | Ms_0 | Ms_1 -> false
    | Ms_pk_k _ | Ms_pk_h _ -> true
    | Ms_older _ | Ms_after _ -> false
    | Ms_sha256 _ | Ms_hash256 _ | Ms_ripemd160 _ | Ms_hash160 _ -> false
    | Ms_and_v (x, y) | Ms_and_b (x, y) | Ms_or_b (x, y) | Ms_or_c (x, y) | Ms_or_d (x, y) | Ms_or_i (x, y) -> check x || check y
    | Ms_andor (x, y, z) -> check x || check y || check z
    | Ms_thresh (_, subs) -> List.exists check subs
    | Ms_multi _ | Ms_multi_a _ -> true
    | Ms_wrap (_, x) -> check x
  in check node

let is_nonmalleable ctx node =
  match compute_type ctx node with
  | Error _ -> false
  | Ok t -> TypeProp.has t.props TypeProp.prop_m

(* ============================================================================
   Parsing
   ============================================================================ *)

let find_matching_paren s start =
  let rec loop depth i =
    if i >= String.length s then None
    else match s.[i] with
      | '(' -> loop (depth + 1) (i+1)
      | ')' -> if depth = 1 then Some i else loop (depth - 1) (i+1)
      | _ -> loop depth (i+1)
  in loop 1 (start+1)

let split_args s =
  let len = String.length s in
  let rec loop acc start depth i =
    if i >= len then
      let last = String.sub s start (len - start) in
      List.rev (if String.length last > 0 then last :: acc else acc)
    else match s.[i] with
      | '(' -> loop acc start (depth+1) (i+1)
      | ')' -> loop acc start (depth-1) (i+1)
      | ',' when depth = 0 ->
        let arg = String.sub s start (i - start) in
        loop (arg :: acc) (i+1) 0 (i+1)
      | _ -> loop acc start depth (i+1)
  in loop [] 0 0 0

let trim s =
  let len = String.length s in
  let rec find_start i = if i >= len then len else if s.[i] = ' ' || s.[i] = '\t' || s.[i] = '\n' then find_start (i+1) else i in
  let rec find_end i = if i <= 0 then 0 else if s.[i-1] = ' ' || s.[i-1] = '\t' || s.[i-1] = '\n' then find_end (i-1) else i in
  let start = find_start 0 in
  let stop = find_end len in
  if start >= stop then "" else String.sub s start (stop - start)

let is_hex c = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')

let hex_to_cstruct s =
  let len = String.length s in
  if len mod 2 <> 0 then None
  else
    let hex_val c =
      if c >= '0' && c <= '9' then Char.code c - Char.code '0'
      else if c >= 'a' && c <= 'f' then Char.code c - Char.code 'a' + 10
      else Char.code c - Char.code 'A' + 10
    in
    let cs = Cstruct.create (len / 2) in
    try
      for i = 0 to (len / 2) - 1 do
        let hi = hex_val s.[i*2] in
        let lo = hex_val s.[i*2+1] in
        Cstruct.set_uint8 cs i ((hi lsl 4) lor lo)
      done;
      Some cs
    with _ -> None

let parse_key s =
  let s = trim s in
  if String.length s > 0 && s.[0] = '@' then
    Ok (KeyPlaceholder (String.sub s 1 (String.length s - 1)))
  else match hex_to_cstruct s with
    | Some cs when Cstruct.length cs = 33 || Cstruct.length cs = 32 -> Ok (KeyBytes cs)
    | _ -> Error ("invalid key: " ^ s)

let rec parse_miniscript s : (miniscript, string) result =
  let s = trim s in
  if String.length s = 0 then Error "empty expression"
  else if s = "0" then Ok Ms_0
  else if s = "1" then Ok Ms_1
  else
    (* Check for wrappers (single char followed by colon) *)
    let wrapper_prefix =
      if String.length s >= 2 && s.[1] = ':' then Some (s.[0], String.sub s 2 (String.length s - 2))
      else None
    in
    match wrapper_prefix with
    | Some (w_char, rest) ->
      let wrapper = match w_char with
        | 'a' -> Some WrapA | 's' -> Some WrapS | 'c' -> Some WrapC | 'd' -> Some WrapD
        | 'v' -> Some WrapV | 'j' -> Some WrapJ | 'n' -> Some WrapN | 'l' -> Some WrapL
        | 'u' -> Some WrapU | 't' -> Some WrapT | _ -> None
      in
      (match wrapper with
       | Some w -> (match parse_miniscript rest with Ok inner -> Ok (Ms_wrap (w, inner)) | Error e -> Error e)
       | None -> parse_miniscript_fragment s)
    | None -> parse_miniscript_fragment s

and parse_miniscript_fragment s =
  (* Find the function name and arguments *)
  match String.index_opt s '(' with
  | None -> Error ("invalid fragment: " ^ s)
  | Some paren_start ->
    let name = String.sub s 0 paren_start in
    (match find_matching_paren s paren_start with
     | None -> Error "unmatched parenthesis"
     | Some paren_end ->
       if paren_end <> String.length s - 1 then Error "trailing characters after )"
       else
         let args_str = String.sub s (paren_start + 1) (paren_end - paren_start - 1) in
         let args = split_args args_str in
         parse_fragment_with_args name args)

and parse_fragment_with_args name args =
  match name, args with
  | "pk_k", [k] -> (match parse_key k with Ok key -> Ok (Ms_pk_k key) | Error e -> Error e)
  | "pk_h", [k] -> (match parse_key k with Ok key -> Ok (Ms_pk_h key) | Error e -> Error e)
  | "pk", [k] -> (match parse_key k with Ok key -> Ok (Ms_wrap (WrapC, Ms_pk_k key)) | Error e -> Error e)
  | "pkh", [k] -> (match parse_key k with Ok key -> Ok (Ms_wrap (WrapC, Ms_pk_h key)) | Error e -> Error e)
  | "older", [n] -> (match int_of_string_opt (trim n) with Some v -> Ok (Ms_older v) | None -> Error "invalid older value")
  | "after", [n] -> (match int_of_string_opt (trim n) with Some v -> Ok (Ms_after v) | None -> Error "invalid after value")
  | "sha256", [h] -> (match hex_to_cstruct (trim h) with Some cs when Cstruct.length cs = 32 -> Ok (Ms_sha256 cs) | _ -> Error "sha256 requires 32-byte hex")
  | "hash256", [h] -> (match hex_to_cstruct (trim h) with Some cs when Cstruct.length cs = 32 -> Ok (Ms_hash256 cs) | _ -> Error "hash256 requires 32-byte hex")
  | "ripemd160", [h] -> (match hex_to_cstruct (trim h) with Some cs when Cstruct.length cs = 20 -> Ok (Ms_ripemd160 cs) | _ -> Error "ripemd160 requires 20-byte hex")
  | "hash160", [h] -> (match hex_to_cstruct (trim h) with Some cs when Cstruct.length cs = 20 -> Ok (Ms_hash160 cs) | _ -> Error "hash160 requires 20-byte hex")
  | "and_v", [x; y] ->
    (match parse_miniscript x with Error e -> Error e | Ok mx ->
     match parse_miniscript y with Error e -> Error e | Ok my -> Ok (Ms_and_v (mx, my)))
  | "and_b", [x; y] ->
    (match parse_miniscript x with Error e -> Error e | Ok mx ->
     match parse_miniscript y with Error e -> Error e | Ok my -> Ok (Ms_and_b (mx, my)))
  | "or_b", [x; y] ->
    (match parse_miniscript x with Error e -> Error e | Ok mx ->
     match parse_miniscript y with Error e -> Error e | Ok my -> Ok (Ms_or_b (mx, my)))
  | "or_c", [x; y] ->
    (match parse_miniscript x with Error e -> Error e | Ok mx ->
     match parse_miniscript y with Error e -> Error e | Ok my -> Ok (Ms_or_c (mx, my)))
  | "or_d", [x; y] ->
    (match parse_miniscript x with Error e -> Error e | Ok mx ->
     match parse_miniscript y with Error e -> Error e | Ok my -> Ok (Ms_or_d (mx, my)))
  | "or_i", [x; y] ->
    (match parse_miniscript x with Error e -> Error e | Ok mx ->
     match parse_miniscript y with Error e -> Error e | Ok my -> Ok (Ms_or_i (mx, my)))
  | "andor", [x; y; z] ->
    (match parse_miniscript x with Error e -> Error e | Ok mx ->
     match parse_miniscript y with Error e -> Error e | Ok my ->
     match parse_miniscript z with Error e -> Error e | Ok mz -> Ok (Ms_andor (mx, my, mz)))
  | "thresh", k_str :: subs when List.length subs >= 1 ->
    (match int_of_string_opt (trim k_str) with
     | None -> Error "invalid thresh k value"
     | Some k ->
       let rec parse_subs acc = function
         | [] -> Ok (List.rev acc)
         | s :: rest -> match parse_miniscript s with Ok m -> parse_subs (m :: acc) rest | Error e -> Error e
       in
       match parse_subs [] subs with Ok ms -> Ok (Ms_thresh (k, ms)) | Error e -> Error e)
  | "multi", k_str :: keys when List.length keys >= 1 ->
    (match int_of_string_opt (trim k_str) with
     | None -> Error "invalid multi k value"
     | Some k ->
       let rec parse_keys acc = function
         | [] -> Ok (List.rev acc)
         | s :: rest -> match parse_key s with Ok key -> parse_keys (key :: acc) rest | Error e -> Error e
       in
       match parse_keys [] keys with Ok ks -> Ok (Ms_multi (k, ks)) | Error e -> Error e)
  | "multi_a", k_str :: keys when List.length keys >= 1 ->
    (match int_of_string_opt (trim k_str) with
     | None -> Error "invalid multi_a k value"
     | Some k ->
       let rec parse_keys acc = function
         | [] -> Ok (List.rev acc)
         | s :: rest -> match parse_key s with Ok key -> parse_keys (key :: acc) rest | Error e -> Error e
       in
       match parse_keys [] keys with Ok ks -> Ok (Ms_multi_a (k, ks)) | Error e -> Error e)
  | name, _ -> Error ("unknown fragment or wrong arity: " ^ name)

(* ============================================================================
   String Conversion
   ============================================================================ *)

let cstruct_to_hex cs =
  let hex_char n = if n < 10 then Char.chr (Char.code '0' + n) else Char.chr (Char.code 'a' + n - 10) in
  let len = Cstruct.length cs in
  let buf = Bytes.create (len * 2) in
  for i = 0 to len - 1 do
    let b = Cstruct.get_uint8 cs i in
    Bytes.set buf (i * 2) (hex_char (b lsr 4));
    Bytes.set buf (i * 2 + 1) (hex_char (b land 0xf))
  done;
  Bytes.to_string buf

let key_to_string key =
  match key with
  | KeyBytes cs -> cstruct_to_hex cs
  | KeyPlaceholder name -> "@" ^ name

let wrapper_to_char = function
  | WrapA -> 'a' | WrapS -> 's' | WrapC -> 'c' | WrapD -> 'd'
  | WrapV -> 'v' | WrapJ -> 'j' | WrapN -> 'n' | WrapL -> 'l'
  | WrapU -> 'u' | WrapT -> 't'

let rec to_string node =
  match node with
  | Ms_0 -> "0"
  | Ms_1 -> "1"
  | Ms_pk_k key -> "pk_k(" ^ key_to_string key ^ ")"
  | Ms_pk_h key -> "pk_h(" ^ key_to_string key ^ ")"
  | Ms_older n -> "older(" ^ string_of_int n ^ ")"
  | Ms_after n -> "after(" ^ string_of_int n ^ ")"
  | Ms_sha256 h -> "sha256(" ^ cstruct_to_hex h ^ ")"
  | Ms_hash256 h -> "hash256(" ^ cstruct_to_hex h ^ ")"
  | Ms_ripemd160 h -> "ripemd160(" ^ cstruct_to_hex h ^ ")"
  | Ms_hash160 h -> "hash160(" ^ cstruct_to_hex h ^ ")"
  | Ms_and_v (x, y) -> "and_v(" ^ to_string x ^ "," ^ to_string y ^ ")"
  | Ms_and_b (x, y) -> "and_b(" ^ to_string x ^ "," ^ to_string y ^ ")"
  | Ms_or_b (x, y) -> "or_b(" ^ to_string x ^ "," ^ to_string y ^ ")"
  | Ms_or_c (x, y) -> "or_c(" ^ to_string x ^ "," ^ to_string y ^ ")"
  | Ms_or_d (x, y) -> "or_d(" ^ to_string x ^ "," ^ to_string y ^ ")"
  | Ms_or_i (x, y) -> "or_i(" ^ to_string x ^ "," ^ to_string y ^ ")"
  | Ms_andor (x, y, z) -> "andor(" ^ to_string x ^ "," ^ to_string y ^ "," ^ to_string z ^ ")"
  | Ms_thresh (k, subs) -> "thresh(" ^ string_of_int k ^ "," ^ String.concat "," (List.map to_string subs) ^ ")"
  | Ms_multi (k, keys) -> "multi(" ^ string_of_int k ^ "," ^ String.concat "," (List.map key_to_string keys) ^ ")"
  | Ms_multi_a (k, keys) -> "multi_a(" ^ string_of_int k ^ "," ^ String.concat "," (List.map key_to_string keys) ^ ")"
  | Ms_wrap (w, x) -> String.make 1 (wrapper_to_char w) ^ ":" ^ to_string x
