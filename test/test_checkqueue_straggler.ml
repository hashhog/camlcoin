(* ScriptCheckQueue: an EMPTY generation must not leave straggler workers.

   run_script_check_queue used to bump the generation (waking every worker)
   even for an empty job array, then return WITHOUT waiting for them.  A
   worker woken for that empty generation could increment workers_done after
   the NEXT run had reset it to 0, so the next run's master stopped waiting
   while a worker was still executing a claimed batch, and scan_first_fail
   could miss that batch's failing check: a block with an invalid script
   ACCEPTED.  Core's CCheckQueue master (checkqueue.h Loop/Complete) waits
   for nTodo == 0, so it cannot lose a check this way.

   CONTROL: dune exec --no-buffer test/test_checkqueue_straggler.exe
   (reverting the guard: 2 of 5 runs FAIL on maxbox 2026-09-24; with it 10/10
   pass).
*)

open Camlcoin

let op byte = let c = Cstruct.create 1 in Cstruct.set_uint8 c 0 byte; c
let op_true () = op 0x51
let op_false () = op 0x00

let hash_n n =
  let t = Cstruct.create 32 in
  Cstruct.set_uint8 t 0 (n land 0xff);
  Cstruct.set_uint8 t 1 ((n lsr 8) land 0xff);
  Cstruct.set_uint8 t 31 0x77;
  t

let inp txid vout : Types.tx_in =
  { Types.previous_output = { Types.txid; vout };
    script_sig = Cstruct.create 0; sequence = 0xFFFFFFFFl }

let make_tx ~inputs ~outputs () =
  { Types.version = 1l; inputs; outputs; witnesses = []; locktime = 0l }

let out value : Types.tx_out = { Types.value; script_pubkey = op_true () }

(* Empty generation then a failing batch, many times: the failure must be
   seen every time. *)
let test_empty_generation_no_straggler () =
  let q = Validation.create_script_check_queue 8 in
  Fun.protect ~finally:(fun () -> Validation.shutdown_script_check_queue q)
    (fun () ->
      let tx = make_tx ~inputs:(List.init 64 (fun i -> inp (hash_n (500 + i)) 0l))
                 ~outputs:[ out 1L ] () in
      let wtxid = Crypto.compute_wtxid tx in
      let misses = ref 0 in
      for iter = 1 to 300 do
        ignore (Validation.run_script_check_queue q [||]);
        let jobs = Array.of_list (List.mapi (fun i (tin : Types.tx_in) ->
          let spk = if i = 63 then op_false () else op_true () in
          { Validation.tx; tx_idx = 1; input_idx = i; inp = tin;
            utxo = { Validation.txid = hash_n (500 + i); vout = 0l;
                     value = 1L; script_pubkey = spk; height = 1;
                     is_coinbase = false };
            prevouts = []; flags = 0;
            wtxid = (let w = Cstruct.create 32 in
                     Cstruct.blit wtxid 0 w 0 32;
                     Cstruct.set_uint8 w 0 (iter land 0xff);
                     Cstruct.set_uint8 w 1 (iter lsr 8); w);
            err = None }) tx.inputs) in
        let r = Validation.run_script_check_queue q jobs in
        if r.ok then incr misses
      done;
      Alcotest.(check int) "failing batch after an empty one never passes" 0 !misses)

let () =
  Alcotest.run "checkqueue_straggler" [
    "queue", [
      Alcotest.test_case "empty generation straggler" `Quick
        test_empty_generation_no_straggler;
    ];
  ]
