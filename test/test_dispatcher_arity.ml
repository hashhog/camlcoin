(* Dispatcher arity check — Core rpc/util.cpp:644 / IsValidNumArgs (:733).

   Core validates argument COUNT centrally before any handler runs; a violation
   is error -1. camlcoin's dispatch_rpc matched straight to a handler with no
   argument-count gate, so surplus positional arguments were silently ignored.
   savemempool failed this in 10 of 10 fleet implementations, clearbanned in
   9 of 10.

   Fails at the parent commit: without check_core_arity the surplus-argument
   calls fall through to their handlers. *)

open Camlcoin

let failures = ref 0
let checks = ref 0

let ok cond name =
  incr checks;
  if not cond then begin
    incr failures;
    Printf.printf "  FAIL: %s\n" name
  end

let () =
  (* Guard: every assertion below is vacuous if the table did not load. *)
  ok (Hashtbl.length Rpc.core_arity >= 80)
    (Printf.sprintf "arity table loaded (%d entries)" (Hashtbl.length Rpc.core_arity));
  ok (Hashtbl.mem Rpc.core_arity "savemempool") "savemempool present in table";
  ok (Hashtbl.mem Rpc.core_arity "clearbanned") "clearbanned present in table";

  (* Core's own signatures: both take zero arguments. *)
  (match Hashtbl.find_opt Rpc.core_arity "savemempool" with
   | Some (r, d) -> ok (r = 0 && d = 0) "savemempool declares 0 args"
   | None -> ok false "savemempool declares 0 args");

  (* A surplus argument must be refused with Core's code. *)
  List.iter
    (fun m ->
       match Rpc.check_core_arity m [ `String "r5-probe-extra-arg" ] with
       | Some (code, _) -> ok (code = -1) (m ^ ": surplus arg -> error -1")
       | None -> ok false (m ^ ": surplus arg -> error -1"))
    [ "savemempool"; "clearbanned" ];

  (* CONTROL: correct calls must still be accepted. Without this a dispatcher
     that rejected everything would pass the assertions above. *)
  List.iter
    (fun m -> ok (Rpc.check_core_arity m [] = None)
                 (m ^ ": correct zero-arg call accepted (control)"))
    [ "savemempool"; "clearbanned" ];

  (* CONTROL: every legal count for a method that takes real arguments.
     gettxout is 2 required / 3 declared; getblockhash exactly 1. *)
  ok (Rpc.check_core_arity "getblockhash" [ `Int 100000 ] = None)
    "getblockhash with 1 arg accepted (control)";
  ok (Rpc.check_core_arity "gettxout" [ `String "ab"; `Int 0 ] = None)
    "gettxout with 2 args accepted (control)";
  ok (Rpc.check_core_arity "gettxout" [ `String "ab"; `Int 0; `Bool true ] = None)
    "gettxout with 3 args accepted (control)";
  ok (Rpc.check_core_arity "gettxout"
        [ `String "ab"; `Int 0; `Bool true; `String "x" ] <> None)
    "gettxout with 4 args rejected";
  ok (Rpc.check_core_arity "gettxout" [ `String "ab" ] <> None)
    "gettxout with 1 arg rejected (too few)";

  (* CONTROL: coverage is 87 of 103; an unknown method must fail OPEN, not be
     treated as zero-arg, or correct calls would start erroring. *)
  ok (Rpc.check_core_arity "definitely-not-an-rpc" [ `String "a"; `String "b" ] = None)
    "unknown method is not arity-checked (control)";

  (* CONTROL: named (object) params are exempt from the positional check. *)
  ok (Rpc.check_core_arity "savemempool" [ `Assoc [ ("unexpected", `Int 1) ] ] = None)
    "object params exempt (control)";

  Printf.printf "\ndispatcher arity: %d checks, %d failed\n"
    !checks !failures;
  if !failures > 0 then exit 1
