(* Tapscript OP_IF nesting cost and IF/NOTIF/ELSE/ENDIF semantics.

   Core keeps the IF state in a ConditionStack (script/interpreter.cpp,
   class ConditionStack): a size plus the position of the first false
   entry, so "are we executing?" is O(1).  Tapscript has no 201-opcode
   cap and no 10,000-byte script cap, so a leaf of (OP_1 OP_IF)xN
   OP_ENDIFxN is legal at any N that fits in a standard tx.  If the
   executing check walks the whole IF stack the leaf costs O(N^2).

   The timing case compares N and 4N: linear work gives a ratio near 4,
   quadratic near 16.  The bound 8 sits between them.  The semantic cases
   pin the IF/ELSE behaviour the cheaper representation must keep. *)

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

let hex s =
  let s = String.concat "" (String.split_on_char ' ' s) in
  let n = String.length s / 2 in
  let b = Cstruct.create n in
  for i = 0 to n - 1 do
    Cstruct.set_uint8 b i (int_of_string ("0x" ^ String.sub s (2 * i) 2))
  done;
  b

(* (OP_1 OP_IF) x n, then OP_ENDIF x n *)
let nested_if_script n =
  let b = Cstruct.create (3 * n) in
  for i = 0 to n - 1 do
    Cstruct.set_uint8 b (2 * i) 0x51;
    Cstruct.set_uint8 b (2 * i + 1) 0x63
  done;
  for i = 0 to n - 1 do
    Cstruct.set_uint8 b (2 * n + i) 0x68
  done;
  b

let time_eval n =
  let script = nested_if_script n in
  let best = ref infinity in
  for _ = 1 to 5 do
    Gc.full_major ();
    let st = state Script.SigVersionTapscript in
    let t0 = Unix.gettimeofday () in
    let r = Script.eval_script st script in
    let dt = Unix.gettimeofday () -. t0 in
    (match r with
     | Ok () -> ()
     | Error e -> Alcotest.failf "nested IF n=%d failed: %s" n e);
    if dt < !best then best := dt
  done;
  !best

let test_nested_if_linear () =
  ignore (time_eval 1000);  (* warm-up *)
  let t_small = time_eval 4000 in
  let t_large = time_eval 16000 in
  let ratio = t_large /. (max t_small 1e-6) in
  Printf.printf "tapscript nested OP_IF: n=4000 %.6fs, n=16000 %.6fs, ratio %.2f\n%!"
    t_small t_large ratio;
  if ratio >= 8.0 then
    Alcotest.failf
      "tapscript nested OP_IF is superlinear: 4x the depth took %.2fx the time \
       (n=4000 %.6fs, n=16000 %.6fs); linear is ~4, quadratic ~16"
      ratio t_small t_large

(* Expected outcome per Core's EvalScript:
   `True = Ok with a true stack top; `Err = script error. *)
let cases = [
  (* 1 IF 2 ELSE RETURN ENDIF *)
  "true_branch", "51 63 52 67 6a 68", `True;
  (* 0 IF RETURN ELSE 1 ENDIF *)
  "false_branch", "00 63 6a 67 51 68", `True;
  (* 1 NOTIF RETURN ELSE 1 ENDIF *)
  "notif", "51 64 6a 67 51 68", `True;
  (* 1 IF ELSE ELSE 1 ENDIF : a second ELSE toggles back *)
  "double_else", "51 63 67 67 51 68", `True;
  (* 1 IF ELSE RETURN ELSE 1 ENDIF *)
  "double_else_skip", "51 63 67 6a 67 51 68", `True;
  (* 0 IF 1 IF RETURN ELSE RETURN ENDIF ELSE 1 ENDIF : inner ELSE under a
     false outer branch must not start executing *)
  "inner_else_under_false", "00 63 51 63 6a 67 6a 68 67 51 68", `True;
  (* 0 IF 0 IF ELSE RETURN ENDIF ELSE 1 ENDIF : two false levels, the inner
     toggles to true but the outer false still holds *)
  "two_false_levels", "00 63 00 63 67 6a 68 67 51 68", `True;
  (* 1 IF 0 IF RETURN ENDIF 1 ENDIF : executing resumes after the inner ENDIF *)
  "resume_after_inner_endif", "51 63 00 63 6a 68 51 68", `True;
  (* 1 IF 0 IF ELSE 1 ELSE RETURN ENDIF ENDIF : toggle false->true->false *)
  "toggle_twice", "51 63 00 63 67 51 67 6a 68 68", `True;
  (* 0 IF ELSE 0 IF RETURN ELSE 1 ENDIF ENDIF *)
  "false_then_nested", "00 63 67 00 63 6a 67 51 68 68", `True;
  (* 1 IF 0 IF 1 IF RETURN ENDIF ELSE 1 ENDIF ENDIF : true under a toggled
     level after a nested IF pushed and popped inside the false region *)
  "pop_inside_false_region", "51 63 00 63 51 63 6a 68 67 51 68 68", `True;
  (* 1 IF 0 ELSE 1 ENDIF : stack top false, no error *)
  "false_top", "51 63 00 67 51 68", `False;
  "endif_without_if", "68", `Err;
  "else_without_if", "67", `Err;
  "unbalanced_if", "51 63", `Err;
  "extra_endif", "51 63 68 68", `Err;
  "unbalanced_false_if", "00 63 51", `Err;
  (* 1 IF RETURN ENDIF : RETURN in an executing branch fails *)
  "return_executed", "51 63 6a 68", `Err;
]

let run sv script =
  let st = state sv in
  match Script.eval_script st (hex script) with
  | Error _ -> `Err
  | Ok () ->
    (match st.Script.stack with
     | top :: _ when Script.is_true top -> `True
     | _ -> `False)

let show = function `True -> "true" | `False -> "false" | `Err -> "error"

let semantic_case sv (name, script, expected) =
  Alcotest.test_case name `Quick (fun () ->
    Alcotest.(check string) name (show expected) (show (run sv script)))

(* A false branch 3000 deep inside a true one, then the outer ELSE: the
   deep false region must not execute and must unwind exactly. *)
let test_deep_false_region () =
  let n = 3000 in
  let b = Buffer.create (4 * n + 16) in
  Buffer.add_string b "\x51\x63";            (* 1 IF *)
  Buffer.add_string b "\x00\x63";            (* 0 IF *)
  for _ = 1 to n do Buffer.add_string b "\x51\x63" done;  (* (1 IF) x n *)
  Buffer.add_string b "\x6a";                (* RETURN, not executed *)
  for _ = 1 to n do Buffer.add_string b "\x67\x6a\x68" done; (* (ELSE RETURN ENDIF) x n *)
  Buffer.add_string b "\x67\x51\x68";        (* ELSE 1 ENDIF *)
  Buffer.add_string b "\x68";                (* ENDIF *)
  let script = Cstruct.of_string (Buffer.contents b) in
  let st = state Script.SigVersionTapscript in
  match Script.eval_script st script with
  | Error e -> Alcotest.failf "deep false region: %s" e
  | Ok () ->
    Alcotest.(check int) "one item left" 1 (List.length st.Script.stack);
    Alcotest.(check bool) "top true" true
      (Script.is_true (List.hd st.Script.stack))

(* Randomised differential against a reference model that keeps the IF
   state as an explicit bool list (the representation before the fix,
   and the one Core's ConditionStack comment describes as the "would-be
   stack").  Alphabet: OP_0 OP_1 OP_IF OP_NOTIF OP_ELSE OP_ENDIF OP_RETURN
   OP_DROP.  Any divergence would mean a script accepted by one and
   rejected by the other: a consensus split. *)
type mop = M0 | M1 | MIf | MNotIf | MElse | MEndif | MReturn | MDrop

let byte_of = function
  | M0 -> 0x00 | M1 -> 0x51 | MIf -> 0x63 | MNotIf -> 0x64
  | MElse -> 0x67 | MEndif -> 0x68 | MReturn -> 0x6a | MDrop -> 0x75

let model ops =
  let rec go data ifs = function
    | [] ->
      if ifs <> [] then `Err
      else (match data with b :: _ when b -> `True | _ -> `False)
    | op :: rest ->
      let exec = List.for_all (fun b -> b) ifs in
      match op with
      | MIf | MNotIf ->
        if not exec then go data (false :: ifs) rest
        else (match data with
            | [] -> `Err
            | b :: d -> go d ((if op = MIf then b else not b) :: ifs) rest)
      | MElse ->
        (match ifs with [] -> `Err | b :: r -> go data ((not b) :: r) rest)
      | MEndif ->
        (match ifs with [] -> `Err | _ :: r -> go data r rest)
      | _ when not exec -> go data ifs rest
      | M0 -> go (false :: data) ifs rest
      | M1 -> go (true :: data) ifs rest
      | MReturn -> `Err
      | MDrop -> (match data with [] -> `Err | _ :: d -> go d ifs rest)
  in
  go [] [] ops

let rng = Random.State.make [| 0x1f2e3d |]

let test_random_differential () =
  let alphabet = [| M0; M1; MIf; MNotIf; MElse; MEndif; MReturn; MDrop |] in
  (* Weight towards structure so most scripts are balanced enough to run. *)
  let weights = [| 3; 4; 3; 2; 2; 4; 1; 1 |] in
  let total = Array.fold_left ( + ) 0 weights in
  let pick () =
    let r = ref (Random.State.int rng total) and i = ref 0 in
    while !r >= weights.(!i) do r := !r - weights.(!i); incr i done;
    alphabet.(!i)
  in
  let counts = Hashtbl.create 3 in
  for _ = 1 to 20000 do
    let len = 1 + Random.State.int rng 40 in
    let ops = List.init len (fun _ -> pick ()) in
    let script =
      String.concat "" (List.map (fun o -> Printf.sprintf "%02x" (byte_of o)) ops)
    in
    let expected = model ops in
    Hashtbl.replace counts expected
      (1 + try Hashtbl.find counts expected with Not_found -> 0);
    List.iter (fun sv ->
        let got = run sv script in
        if got <> expected then
          Alcotest.failf "script %s: model %s, interpreter %s" script
            (show expected) (show got))
      [ Script.SigVersionTapscript; Script.SigVersionBase ]
  done;
  (* The generator must reach every outcome, or the comparison is hollow. *)
  List.iter (fun k ->
      Alcotest.(check bool) ("outcome reached: " ^ show k) true
        (Hashtbl.mem counts k))
    [ `True; `False; `Err ]

let () =
  Alcotest.run "tapscript_conditionstack" [
    "cost", [
      Alcotest.test_case "nested_if_linear_tapscript" `Quick test_nested_if_linear;
    ];
    "semantics_tapscript",
      List.map (semantic_case Script.SigVersionTapscript) cases
      @ [ Alcotest.test_case "deep_false_region" `Quick test_deep_false_region ];
    "semantics_base", List.map (semantic_case Script.SigVersionBase) cases;
    "differential", [
      Alcotest.test_case "random_if_scripts_vs_list_model" `Quick
        test_random_differential;
    ];
  ]
