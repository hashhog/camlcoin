(* The MAX_STACK_SIZE check and the stack-depth bookkeeping behind it.

   Core bounds stack.size() + altstack.size() by MAX_STACK_SIZE (1000) once
   per opcode (script/interpreter.cpp, end of the EvalScript loop), and both
   sizes are O(1).  Tapscript has no 201-opcode cap and no 10,000-byte script
   cap, so a leaf may push and drop any number of times at depth ~1000.  If
   the check walks both stacks on every push, each push costs ~1000 list
   steps.

   The timing case runs the same opcodes twice: N x (OP_1 OP_DROP) with 998
   items already on the stack, and the same N pairs before the 998 pushes.
   With an O(1) check the two cost the same (ratio ~1).  With a check that
   walks the stacks, the deep run does ~1000 steps per push and the shallow
   run ~1, so the ratio is large (~7 on the pre-fix tree).  The bound 3.5
   sits between them.

   The other cases pin what the counters must keep: the exact overflow
   boundary of every opcode that grows the stack, the altstack counted in
   the same total, OP_DEPTH's value, and a seeded differential of random
   stack-opcode scripts against an explicit list model. *)

open Camlcoin

let make_tx () : Types.transaction =
  {
    Types.version = 2l;
    inputs = [{
      previous_output = { txid = Types.zero_hash; vout = 0l };
      script_sig = Cstruct.create 0;
      sequence = 0xFFFFFFFFl;
    }];
    outputs = [{ value = 0L; script_pubkey = Cstruct.create 0 }];
    witnesses = [];
    locktime = 0l;
  }

let state sig_version =
  Script.create_eval_state ~tx:(make_tx ()) ~input_index:0 ~amount:0L
    ~flags:0 ~sig_version ()

let script_of_bytes (l : int list) =
  let b = Cstruct.create (List.length l) in
  List.iteri (fun i v -> Cstruct.set_uint8 b i v) l;
  b

let rep n x = List.init n (fun _ -> x)

let op_0 = 0x00
let op_1 = 0x51
let op_n n = if n = 0 then op_0 else 0x50 + n
let op_ifdup = 0x73
let op_depth = 0x74
let op_drop = 0x75
let op_dup = 0x76
let op_nip = 0x77
let op_over = 0x78
let op_pick = 0x79
let op_roll = 0x7a
let op_rot = 0x7b
let op_swap = 0x7c
let op_tuck = 0x7d
let op_2drop = 0x6d
let op_2dup = 0x6e
let op_3dup = 0x6f
let op_2over = 0x70
let op_2rot = 0x71
let op_2swap = 0x72
let op_toalt = 0x6b
let op_fromalt = 0x6c
let op_size = 0x82
let op_add = 0x93

(* ---- cost ---- *)

let n_pairs = 20000

let push_drop_pairs n = List.concat (rep n [op_1; op_drop])

let deep_script = script_of_bytes (rep 998 op_1 @ push_drop_pairs n_pairs)
let shallow_script = script_of_bytes (push_drop_pairs n_pairs @ rep 998 op_1)

let eval_once script =
  Gc.full_major ();
  let st = state Script.SigVersionTapscript in
  let t0 = Unix.gettimeofday () in
  let r = Script.eval_script st script in
  let dt = Unix.gettimeofday () -. t0 in
  (match r with
   | Ok () -> ()
   | Error e -> Alcotest.failf "push/drop script failed: %s" e);
  Alcotest.(check int) "998 items left" 998 (List.length st.Script.stack);
  dt

(* The two scripts alternate, so a burst of load on a busy box hits both
   sides alike; the best of 9 runs of each is compared. *)
let test_push_at_depth_998_is_o1 () =
  ignore (eval_once shallow_script);  (* warm-up *)
  ignore (eval_once deep_script);
  let best_shallow = ref infinity and best_deep = ref infinity in
  for _ = 1 to 9 do
    best_shallow := min !best_shallow (eval_once shallow_script);
    best_deep := min !best_deep (eval_once deep_script)
  done;
  let t_shallow = !best_shallow and t_deep = !best_deep in
  let ratio = t_deep /. (max t_shallow 1e-6) in
  Printf.printf
    "tapscript %d x (OP_1 OP_DROP): at depth 0 %.6fs, at depth 998 %.6fs, ratio %.2f\n%!"
    n_pairs t_shallow t_deep ratio;
  if ratio >= 3.5 then
    Alcotest.failf
      "the stack-size check is not O(1): the same %d OP_1 OP_DROP pairs took \
       %.2fx as long at depth 998 as at depth 0 (%.6fs vs %.6fs); an O(1) \
       check gives ~1"
      n_pairs ratio t_deep t_shallow

(* ---- exact overflow boundaries ---- *)

(* name, script, expected Ok? *)
let boundary_cases = [
  "push_to_1000", rep 1000 op_1, true;
  "push_to_1001", rep 1001 op_1, false;
  "dup_to_1000", rep 999 op_1 @ [op_dup], true;
  "dup_to_1001", rep 1000 op_1 @ [op_dup], false;
  "2dup_to_1000", rep 998 op_1 @ [op_2dup], true;
  "2dup_to_1001", rep 999 op_1 @ [op_2dup], false;
  "3dup_to_1000", rep 997 op_1 @ [op_3dup], true;
  "3dup_to_1001", rep 998 op_1 @ [op_3dup], false;
  "over_to_1000", rep 999 op_1 @ [op_over], true;
  "over_to_1001", rep 1000 op_1 @ [op_over], false;
  "2over_to_1000", rep 998 op_1 @ [op_2over], true;
  "2over_to_1001", rep 999 op_1 @ [op_2over], false;
  "tuck_to_1000", rep 999 op_1 @ [op_tuck], true;
  "tuck_to_1001", rep 1000 op_1 @ [op_tuck], false;
  "depth_to_1000", rep 999 op_1 @ [op_depth], true;
  "depth_to_1001", rep 1000 op_1 @ [op_depth], false;
  "size_to_1000", rep 999 op_1 @ [op_size], true;
  "size_to_1001", rep 1000 op_1 @ [op_size], false;
  "ifdup_true_to_1001", rep 1000 op_1 @ [op_ifdup], false;
  "ifdup_false_at_1000", rep 999 op_1 @ [op_0; op_ifdup], true;
  "pick_at_1000", rep 999 op_1 @ [op_0; op_pick], true;
  "pick_then_push", rep 999 op_1 @ [op_0; op_pick; op_1], false;
  "roll_at_1000", rep 999 op_1 @ [op_1; op_roll; op_1], true;
  "roll_then_2push", rep 999 op_1 @ [op_1; op_roll; op_1; op_1], false;
  "nip_frees_one", rep 1000 op_1 @ [op_nip; op_1], true;
  "nip_frees_only_one", rep 1000 op_1 @ [op_nip; op_1; op_1], false;
  "2drop_frees_two", rep 1000 op_1 @ [op_2drop; op_1; op_1], true;
  "2drop_frees_only_two", rep 1000 op_1 @ [op_2drop; op_1; op_1; op_1], false;
  "add_frees_one", rep 1000 op_1 @ [op_add; op_1], true;
  "add_frees_only_one", rep 1000 op_1 @ [op_add; op_1; op_1], false;
  "drop_frees_one", rep 1000 op_1 @ [op_drop; op_1], true;
  (* The altstack counts toward the same 1000.  90 moves keep the base
     sig version under its 201-opcode cap. *)
  "altstack_counts", rep 1000 op_1 @ rep 90 op_toalt @ [op_1], false;
  "altstack_full_round_trip",
    rep 1000 op_1 @ rep 90 op_toalt @ rep 90 op_fromalt @ [op_drop; op_1], true;
  "altstack_round_trip_still_full",
    rep 1000 op_1 @ rep 90 op_toalt @ rep 90 op_fromalt @ [op_1], false;
  "altstack_drop_main_frees",
    rep 1000 op_1 @ rep 90 op_toalt @ [op_drop; op_1], true;
  "altstack_drop_main_frees_one",
    rep 1000 op_1 @ rep 90 op_toalt @ [op_drop; op_1; op_1], false;
  "fromalt_then_drop_frees",
    rep 1000 op_1 @ rep 3 op_toalt @ [op_fromalt; op_drop; op_1], true;
  "rearrange_keeps_depth",
    rep 1000 op_1 @ [op_swap; op_rot; op_2swap; op_2rot; op_1], false;
  "rearrange_keeps_depth_ok",
    rep 999 op_1 @ [op_swap; op_rot; op_2swap; op_2rot; op_1], true;
]

let boundary_case sv (name, ops, expect_ok) =
  Alcotest.test_case name `Quick (fun () ->
    let st = state sv in
    let r = Script.eval_script st (script_of_bytes ops) in
    let got = match r with Ok () -> "ok" | Error e -> "error: " ^ e in
    let got_ok = match r with Ok () -> true | Error _ -> false in
    if got_ok <> expect_ok then
      Alcotest.failf "%s: expected %s, got %s" name
        (if expect_ok then "ok" else "error") got;
    Alcotest.(check int) "stack_size agrees with the stack"
      (List.length st.Script.stack) (Script.stack_size st))

(* OP_DEPTH reports the main stack only, after pops and altstack moves. *)
let test_depth_value () =
  let st = state Script.SigVersionTapscript in
  let ops = rep 7 op_1 @ [op_toalt; op_toalt; op_drop; op_2dup; op_nip; op_depth] in
  (match Script.eval_script st (script_of_bytes ops) with
   | Ok () -> ()
   | Error e -> Alcotest.failf "depth script failed: %s" e);
  (* 7 - 2 (alt) - 1 (drop) + 2 (2dup) - 1 (nip) = 5, then DEPTH pushes 5 *)
  (match st.Script.stack with
   | top :: _ ->
     Alcotest.(check int64) "OP_DEPTH value" 5L
       (Script.script_num_of_bytes ~require_minimal:false top)
   | [] -> Alcotest.fail "empty stack");
  Alcotest.(check int) "stack_size" 6 (Script.stack_size st);
  Alcotest.(check int) "altstack" 2 (List.length st.Script.altstack)

(* Two scripts on one state carry the depth across, as scriptSig ->
   scriptPubKey on the shared legacy state does. *)
let test_depth_carries_across_scripts () =
  let st = state Script.SigVersionBase in
  (match Script.eval_script st (script_of_bytes (rep 600 op_1)) with
   | Ok () -> () | Error e -> Alcotest.failf "first script: %s" e);
  (match Script.eval_script st (script_of_bytes (rep 400 op_1)) with
   | Ok () -> () | Error e -> Alcotest.failf "second script: %s" e);
  Alcotest.(check int) "stack_size" 1000 (Script.stack_size st);
  match Script.eval_script st (script_of_bytes [op_1]) with
  | Ok () -> Alcotest.fail "push 1001 across two scripts must overflow"
  | Error _ -> ()

(* ---- differential against an explicit list model ---- *)

(* Model: main and alt stacks as int lists (values are script numbers).
   Returns Ok (stack, alt) or Error.  Mirrors Core's EvalScript for this
   opcode subset: underflow checks per opcode, then the combined size must
   not exceed 1000 after the opcode. *)
let model_size n = Cstruct.length (Script.bytes_of_script_num (Int64.of_int n))

let model ops =
  let exception Fail in
  let st = ref [] and alt = ref [] in
  let need k = if List.length !st < k then raise Fail in
  let check () = if List.length !st + List.length !alt > 1000 then raise Fail in
  let pop () = match !st with x :: r -> st := r; x | [] -> raise Fail in
  let push x = st := x :: !st in
  try
    List.iter (fun op ->
      (if op = op_0 then push 0
       else if op >= 0x51 && op <= 0x60 then push (op - 0x50)
       else if op = op_drop then ignore (pop ())
       else if op = op_dup then (need 1; push (List.hd !st))
       else if op = op_2dup then
         (need 2; match !st with a :: b :: _ -> st := a :: b :: !st | _ -> ())
       else if op = op_3dup then
         (need 3; match !st with a :: b :: c :: _ -> st := a :: b :: c :: !st | _ -> ())
       else if op = op_over then (need 2; push (List.nth !st 1))
       else if op = op_2over then
         (need 4; match !st with _ :: _ :: c :: d :: _ -> st := c :: d :: !st | _ -> ())
       else if op = op_tuck then
         (need 2; match !st with a :: b :: r -> st := a :: b :: a :: r | _ -> ())
       else if op = op_nip then
         (need 2; match !st with a :: _ :: r -> st := a :: r | _ -> ())
       else if op = op_2drop then (need 2; ignore (pop ()); ignore (pop ()))
       else if op = op_swap then
         (need 2; match !st with a :: b :: r -> st := b :: a :: r | _ -> ())
       else if op = op_rot then
         (need 3; match !st with a :: b :: c :: r -> st := c :: a :: b :: r | _ -> ())
       else if op = op_2swap then
         (need 4; match !st with a :: b :: c :: d :: r -> st := c :: d :: a :: b :: r | _ -> ())
       else if op = op_2rot then
         (need 6; match !st with
          | a :: b :: c :: d :: e :: f :: r -> st := e :: f :: a :: b :: c :: d :: r
          | _ -> ())
       else if op = op_toalt then (let v = pop () in alt := v :: !alt)
       else if op = op_fromalt then
         (match !alt with v :: r -> alt := r; push v | [] -> raise Fail)
       else if op = op_depth then push (List.length !st)
       else if op = op_size then (need 1; push (model_size (List.hd !st)))
       else if op = op_ifdup then (need 1; let t = List.hd !st in if t <> 0 then push t)
       else if op = op_pick then begin
         let n = pop () in
         if n >= List.length !st then raise Fail;
         push (List.nth !st n)
       end else if op = op_roll then begin
         let n = pop () in
         if n >= List.length !st then raise Fail;
         let v = List.nth !st n in
         st := v :: List.filteri (fun i _ -> i <> n) !st
       end else failwith "model: unknown op");
      check ()) ops;
    Ok (!st, !alt)
  with Fail -> Error ()

let stack_ops = [| op_drop; op_dup; op_2dup; op_3dup; op_over; op_2over;
                   op_tuck; op_nip; op_2drop; op_swap; op_rot; op_2swap;
                   op_2rot; op_toalt; op_toalt; op_fromalt; op_fromalt;
                   op_depth; op_size; op_ifdup; op_0; op_1; op_n 3 |]

let gen_script rng =
  let prefix = match Random.State.int rng 4 with
    | 0 -> Random.State.int rng 20
    | 1 -> 990 + Random.State.int rng 11
    | _ -> 960 + Random.State.int rng 41
  in
  let pre = List.init prefix (fun _ -> op_n (Random.State.int rng 4)) in
  let body = List.concat (List.init (1 + Random.State.int rng 60) (fun _ ->
    match Random.State.int rng 10 with
    | 0 -> [op_n (Random.State.int rng 4); op_pick]
    | 1 -> [op_n (Random.State.int rng 4); op_roll]
    | _ -> [stack_ops.(Random.State.int rng (Array.length stack_ops))])) in
  pre @ body

let enc n = Script.bytes_of_script_num (Int64.of_int n)

let same_stack (real : Cstruct.t list) (m : int list) =
  List.length real = List.length m
  && List.for_all2 (fun r v -> Cstruct.equal r (enc v)) real m

let test_differential () =
  let rng = Random.State.make [| 0x5eed; 1000 |] in
  let oks = ref 0 and errs = ref 0 and full = ref 0 in
  for i = 1 to 4000 do
    let ops = gen_script rng in
    let script = script_of_bytes ops in
    List.iter (fun sv ->
      let st = state sv in
      let r = Script.eval_script st script in
      match r, model ops with
      | Error _, Error () -> incr errs
      | Ok (), Ok (ms, malt) ->
        incr oks;
        if not (same_stack st.Script.stack ms) then
          Alcotest.failf "case %d: final stack differs from the model" i;
        if not (same_stack st.Script.altstack malt) then
          Alcotest.failf "case %d: final altstack differs from the model" i;
        if Script.stack_size st <> List.length ms then
          Alcotest.failf "case %d: stack_size %d, model %d" i
            (Script.stack_size st) (List.length ms);
        (* The combined counter: exactly 1000 - used more pushes fit. *)
        let room = 1000 - List.length ms - List.length malt in
        if room = 0 then incr full;
        (match Script.eval_script st (script_of_bytes (rep room op_1)) with
         | Ok () -> ()
         | Error e ->
           Alcotest.failf "case %d: %d pushes should fit, got %s" i room e);
        (match Script.eval_script st (script_of_bytes [op_1]) with
         | Ok () -> Alcotest.failf "case %d: push past 1000 accepted" i
         | Error _ -> ())
      | Ok (), Error () ->
        Alcotest.failf "case %d: interpreter accepted, model rejects" i
      | Error e, Ok _ ->
        Alcotest.failf "case %d: interpreter rejected (%s), model accepts" i e)
      [Script.SigVersionBase; Script.SigVersionTapscript]
  done;
  Printf.printf "differential: %d ok, %d error, %d ended exactly full\n%!"
    !oks !errs !full;
  if !oks < 500 || !errs < 500 || !full < 20 then
    Alcotest.failf "differential did not reach every outcome (%d ok, %d error, %d full)"
      !oks !errs !full

let () =
  Alcotest.run "stack_depth_counter" [
    "cost", [
      Alcotest.test_case "push_drop_at_depth_998_is_o1" `Quick
        test_push_at_depth_998_is_o1;
    ];
    "boundary_tapscript",
      List.map (boundary_case Script.SigVersionTapscript) boundary_cases;
    "boundary_base",
      List.map (boundary_case Script.SigVersionBase) boundary_cases;
    "depth", [
      Alcotest.test_case "depth_value" `Quick test_depth_value;
      Alcotest.test_case "depth_carries_across_scripts" `Quick
        test_depth_carries_across_scripts;
    ];
    "differential", [
      Alcotest.test_case "random_stack_scripts_vs_list_model" `Quick
        test_differential;
    ];
  ]
