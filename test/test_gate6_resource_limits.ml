(* Gate 6 (docs/RELEASE-CHECKLIST.md): a system fault -- OOM, an I/O
   error, a dead worker, a secp256k1 context failure -- leads to retry or
   halt, NEVER to a reject or an accept.

   Bitcoin Core: CheckECDSASignature / CheckSchnorrSignature can only say
   valid or invalid (the context is created once at init, ECC_Start, and
   bad_alloc terminates); a ConnectBlock that fails for a system reason is
   FatalError -> AbortNode (validation.cpp, node/abort.cpp): the block is
   never marked BLOCK_FAILED_VALID, no peer is punished, the coins cache
   is discarded, the node exits with EXIT_FAILURE.

   Every fault case here FAILS on the deployed code (c06963e) + the inert
   hooks and PASSES on the fix.  The controls (genuinely invalid inputs,
   fault-free runs) pass on both: a verdict is still a verdict.

     dune exec --no-buffer test/test_gate6_resource_limits.exe *)

open Camlcoin

(* ---------------------------------------------------------------- keys *)

let privkey = Cstruct.of_string (String.make 31 '\x00' ^ "\x2a")
let pubkey = Crypto.derive_public_key ~compressed:true privkey
let op_true = Cstruct.of_string "\x51"

let push (b : Cstruct.t) =
  let n = Cstruct.length b in
  assert (n < 0x4c);
  Cstruct.concat [ Cstruct.of_string (String.make 1 (Char.chr n)); b ]

(* bare <pk> CHECKSIG *)
let spk_checksig = Cstruct.concat [ push pubkey; Cstruct.of_string "\xac" ]
(* bare <pk> CHECKSIG NOT : spendable ONLY with an INVALID signature *)
let spk_checksig_not =
  Cstruct.concat [ push pubkey; Cstruct.of_string "\xac\x91" ]
(* bare <pk> CHECKSIGVERIFY 1 *)
let spk_checksigverify =
  Cstruct.concat [ push pubkey; Cstruct.of_string "\xad\x51" ]

let spend_tx ~(prev_txid : Types.hash256) ~(value : int64)
    ~(script_sig : Cstruct.t) : Types.transaction =
  { Types.version = 2l;
    inputs = [ { Types.previous_output = { Types.txid = prev_txid; vout = 0l };
                 script_sig; sequence = 0xFFFFFFFFl } ];
    outputs = [ { Types.value; script_pubkey = op_true } ];
    witnesses = []; locktime = 0l }

(* A VALID signature over input 0 for [spk] (legacy sighash, ALL). *)
let sign_input (tx : Types.transaction) (spk : Cstruct.t) : Cstruct.t =
  let sighash = Script.compute_sighash_legacy tx 0 spk 1 in
  let der = Crypto.sign privkey sighash in
  push (Cstruct.concat [ der; Cstruct.of_string "\x01" ])

(* A signed spend of (prev_txid:0, [spk]).  [bad] corrupts the signature
   (a genuinely INVALID signature, still strict DER). *)
let signed_spend ?(bad = false) ~prev_txid ~value spk =
  let unsigned = spend_tx ~prev_txid ~value ~script_sig:Cstruct.empty in
  let ss = sign_input unsigned spk in
  let ss =
    if not bad then ss
    else begin
      (* flip a bit of r (byte 6 of the push: 1 len + 30 02 len 0x..) *)
      let c = Cstruct.of_string (Cstruct.to_string ss) in
      Cstruct.set_uint8 c 8 (Cstruct.get_uint8 c 8 lxor 0x01);
      c
    end
  in
  { unsigned with Types.inputs =
      List.map (fun i -> { i with Types.script_sig = ss }) unsigned.Types.inputs }

(* -------------------------------------------------------------- faults *)

let secp_ctx_failure () = failwith "ensure_ctx: secp256k1_context_create failed"

let with_hook h f =
  Crypto.fault_hook := Some h;
  Fun.protect ~finally:(fun () -> Crypto.fault_hook := None) f

let once (fault : unit -> unit) : unit -> unit =
  let fired = ref false in
  fun () -> if not !fired then begin fired := true; fault () end

let reset () =
  Fatal.reset_for_tests ();
  Crypto.fault_hook := None;
  Validation.job_fault_hook := None;
  Fatal.write_fault_hook := None;
  Validation.cache_clear_global ()

(* A system fault must surface as an exception that is NOT a script
   verdict (never Ok true -- an accept -- and never Ok false / Error -- a
   reject). *)
type outcome = Verdict of (bool, string) result | Raised of exn

let run_verify ~flags ~(tx : Types.transaction) ~spk ~amount =
  let inp = List.hd tx.Types.inputs in
  match
    Script.verify_script ~tx ~input_index:0 ~script_pubkey:spk
      ~script_sig:inp.Types.script_sig ~witness:{ Types.items = [] }
      ~amount ~flags ~prevouts:[ (amount, spk) ] ()
  with
  | r -> Verdict r
  | exception e -> Raised e

let show = function
  | Verdict (Ok b) -> Printf.sprintf "Ok %b" b
  | Verdict (Error e) -> "Error " ^ e
  | Raised e -> "raised " ^ Printexc.to_string e

let flags_block = Script.script_verify_p2sh lor Script.script_verify_dersig
let fake_prev = Cstruct.of_string (String.make 32 '\x07')
let amount = 50_000L

(* ======================================================= script level *)

let test_checksig_not_fault_never_accepts () =
  reset ();
  let tx = signed_spend ~prev_txid:fake_prev ~value:amount spk_checksig_not in
  let r = with_hook secp_ctx_failure (fun () ->
      run_verify ~flags:flags_block ~tx ~spk:spk_checksig_not ~amount) in
  (match r with
   | Verdict (Ok true) ->
     Alcotest.failf "<validsig> <pk> CHECKSIG NOT ACCEPTED under a secp \
                     context failure (%s)" (show r)
   | Raised (Fatal.System_fault _) -> ()
   | _ -> Alcotest.failf "expected a System_fault, got %s" (show r));
  (* OOM in the FFI copy: propagates untouched *)
  let r2 = with_hook (fun () -> raise Out_of_memory) (fun () ->
      run_verify ~flags:flags_block ~tx ~spk:spk_checksig_not ~amount) in
  match r2 with
  | Raised Out_of_memory -> ()
  | _ -> Alcotest.failf "OOM: expected Out_of_memory to propagate, got %s"
           (show r2)

let test_checksigverify_fault_not_a_reject () =
  reset ();
  let tx = signed_spend ~prev_txid:fake_prev ~value:amount spk_checksigverify in
  let r = with_hook secp_ctx_failure (fun () ->
      run_verify ~flags:flags_block ~tx ~spk:spk_checksigverify ~amount) in
  match r with
  | Raised (Fatal.System_fault _) -> ()
  | _ -> Alcotest.failf "valid CHECKSIGVERIFY under a secp fault must not be \
                         a script verdict; got %s" (show r)

let test_low_s_fault_not_a_reject () =
  reset ();
  let flags = flags_block lor Script.script_verify_low_s in
  let tx = signed_spend ~prev_txid:fake_prev ~value:amount spk_checksig in
  let r = with_hook secp_ctx_failure (fun () ->
      run_verify ~flags ~tx ~spk:spk_checksig ~amount) in
  match r with
  | Raised (Fatal.System_fault _) -> ()
  | _ -> Alcotest.failf "LOW_S check under a secp fault must not be a \
                         verdict; got %s" (show r)

(* CONTROLS (both trees): no fault -> correct verdicts. *)
let test_script_controls () =
  reset ();
  let ok_tx = signed_spend ~prev_txid:fake_prev ~value:amount spk_checksig in
  (match run_verify ~flags:flags_block ~tx:ok_tx ~spk:spk_checksig ~amount with
   | Verdict (Ok true) -> ()
   | r -> Alcotest.failf "valid CHECKSIG: %s" (show r));
  let not_tx = signed_spend ~prev_txid:fake_prev ~value:amount spk_checksig_not in
  (match run_verify ~flags:flags_block ~tx:not_tx ~spk:spk_checksig_not ~amount with
   | Verdict (Ok false) | Verdict (Error _) -> ()
   | r -> Alcotest.failf "valid sig under CHECKSIG NOT must fail: %s" (show r));
  let bad_tx = signed_spend ~bad:true ~prev_txid:fake_prev ~value:amount
      spk_checksig_not in
  (match run_verify ~flags:flags_block ~tx:bad_tx ~spk:spk_checksig_not ~amount with
   | Verdict (Ok true) -> ()
   | r -> Alcotest.failf "invalid sig under CHECKSIG NOT must pass: %s" (show r));
  let bad_v = signed_spend ~bad:true ~prev_txid:fake_prev ~value:amount
      spk_checksigverify in
  (match run_verify ~flags:flags_block ~tx:bad_v ~spk:spk_checksigverify ~amount with
   | Verdict (Error _) | Verdict (Ok false) -> ()
   | r -> Alcotest.failf "invalid CHECKSIGVERIFY must fail: %s" (show r));
  (* malformed bytes are SCRIPT errors (a property of the input), never a
     system fault: truncated PUSHDATA1, CHECKSIG on an empty stack *)
  List.iter (fun hex ->
      let spk = Cstruct.of_hex hex in
      let tx = spend_tx ~prev_txid:fake_prev ~value:amount ~script_sig:Cstruct.empty in
      match run_verify ~flags:flags_block ~tx ~spk ~amount with
      | Verdict (Error _) | Verdict (Ok false) -> ()
      | r -> Alcotest.failf "malformed %s: %s" hex (show r))
    [ "4cff"; "ac"; "4d0100"; "6a4e" ]

(* ===================================================== block script queue *)

let job_of ~flags (tx : Types.transaction) spk =
  let utxo = { Validation.txid = fake_prev; vout = 0l; value = amount;
               script_pubkey = spk; height = 1; is_coinbase = false } in
  Array.of_list (List.rev
    (Validation.append_script_jobs [] ~tx ~tx_idx:1 ~flags
       ~prevouts:[ (amount, spk) ] ~utxos:[| Some utxo |]))

type qout = Q of Validation.script_check_result | QRaised of exn

let run_q jobs =
  match Validation.run_script_checks jobs with
  | r -> Q r
  | exception e -> QRaised e

let showq = function
  | Q r -> Printf.sprintf "ok=%b reason=%s" r.Validation.ok r.Validation.first_fail_reason
  | QRaised e -> "raised " ^ Printexc.to_string e

(* run with and without the persistent CCheckQueue (extra worker domains) *)
let both_queues name f =
  reset ();
  f (name ^ " [serial]");
  Validation.set_par 4;
  Validation.start_script_check_queue ();
  Fun.protect ~finally:Validation.stop_script_check_queue (fun () ->
      reset (); f (name ^ " [queue]"))

let test_queue_persistent_fault_halts () =
  both_queues "persistent fault" (fun name ->
    let tx = signed_spend ~prev_txid:fake_prev ~value:amount spk_checksig in
    let r = with_hook secp_ctx_failure (fun () ->
        run_q (job_of ~flags:flags_block tx spk_checksig)) in
    (match r with
     | QRaised (Fatal.System_fault _) -> ()
     | _ -> Alcotest.failf "%s: a valid input whose check cannot complete \
                            must not be judged; got %s" name (showq r));
    Alcotest.(check bool) (name ^ ": AbortNode latched") true
      (Fatal.is_latched ()))

let test_queue_checksig_not_fault_no_accept_no_cache () =
  both_queues "CHECKSIG NOT" (fun name ->
    let tx = signed_spend ~prev_txid:fake_prev ~value:amount spk_checksig_not in
    let jobs = job_of ~flags:flags_block tx spk_checksig_not in
    let r = with_hook secp_ctx_failure (fun () -> run_q jobs) in
    (match r with
     | Q { Validation.ok = true; _ } ->
       Alcotest.failf "%s: block script check ACCEPTED a <validsig> <pk> \
                       CHECKSIG NOT under a secp fault" name
     | QRaised (Fatal.System_fault _) -> ()
     | _ -> Alcotest.failf "%s: expected System_fault, got %s" name (showq r));
    (* the faulted result must not have been cached: fault gone -> the
       real verdict (script fails) *)
    Fatal.reset_for_tests ();
    let jobs2 = job_of ~flags:flags_block tx spk_checksig_not in
    match run_q jobs2 with
    | Q { Validation.ok = false; _ } -> ()
    | r2 -> Alcotest.failf "%s: after the fault, CHECKSIG NOT must fail (no \
                            cached accept); got %s" name (showq r2))

let test_queue_transient_fault_retried () =
  both_queues "transient fault" (fun name ->
    let tx = signed_spend ~prev_txid:fake_prev ~value:amount spk_checksig in
    let r = with_hook (once secp_ctx_failure) (fun () ->
        run_q (job_of ~flags:flags_block tx spk_checksig)) in
    (match r with
     | Q { Validation.ok = true; _ } -> ()
     | _ -> Alcotest.failf "%s: a transient fault must be retried to the real \
                            verdict (valid); got %s" name (showq r));
    Alcotest.(check bool) (name ^ ": not latched") false (Fatal.is_latched ()))

let test_queue_dead_worker_not_a_verdict () =
  both_queues "dead worker" (fun name ->
    let tx = signed_spend ~prev_txid:fake_prev ~value:amount spk_checksig in
    Validation.job_fault_hook := Some (fun _ -> raise Out_of_memory);
    let r = Fun.protect ~finally:(fun () -> Validation.job_fault_hook := None)
        (fun () -> run_q (job_of ~flags:flags_block tx spk_checksig)) in
    (match r with
     | QRaised (Fatal.System_fault _) -> ()
     | _ -> Alcotest.failf "%s: a job that died (OOM) must not be judged; got %s"
              name (showq r));
    Alcotest.(check bool) (name ^ ": latched") true (Fatal.is_latched ()))

let test_queue_controls () =
  both_queues "controls" (fun name ->
    let bad = signed_spend ~bad:true ~prev_txid:fake_prev ~value:amount spk_checksig in
    (match run_q (job_of ~flags:flags_block bad spk_checksig) with
     | Q { Validation.ok = false; _ } -> ()
     | r -> Alcotest.failf "%s: invalid sig must be a verdict; got %s" name (showq r));
    let good = signed_spend ~prev_txid:fake_prev ~value:amount spk_checksig in
    (match run_q (job_of ~flags:flags_block good spk_checksig) with
     | Q { Validation.ok = true; _ } -> ()
     | r -> Alcotest.failf "%s: valid sig: %s" name (showq r));
    Alcotest.(check bool) (name ^ ": not latched") false (Fatal.is_latched ()))

(* Mempool script entry (Mempool_verify_pool worker domains). *)
let test_mempool_verify_fault_not_a_reject () =
  reset ();
  let tx = signed_spend ~prev_txid:fake_prev ~value:amount spk_checksig in
  let utxo = { Validation.txid = fake_prev; vout = 0l; value = amount;
               script_pubkey = spk_checksig; height = 1; is_coinbase = false } in
  let r =
    with_hook secp_ctx_failure (fun () ->
      match Lwt_main.run
              (Validation.verify_scripts_parallel ~tx ~flags:flags_block
                 ~prevouts:[ (amount, spk_checksig) ] ~utxos:[| Some utxo |])
      with
      | Ok () -> "accepted"
      | Error e -> "rejected: " ^ Validation.tx_error_to_string e
      | exception (Fatal.System_fault _) -> "system-fault")
  in
  Alcotest.(check string) "mempool: fault is not a script reject"
    "system-fault" r

(* ============================================================ P2P chain *)

let remine (block : Types.block) : Types.block =
  let h = ref block.Types.header in
  let n = ref 0l in
  let found = ref false in
  while (not !found) && Int32.compare !n 5_000_000l < 0 do
    h := { !h with Types.nonce = !n };
    if Consensus.hash_meets_target (Crypto.compute_block_hash !h) !h.Types.bits
    then found := true
    else n := Int32.add !n 1l
  done;
  if not !found then failwith "remine: no nonce found";
  { block with Types.header = !h }

let build_block ?(payout = op_true) ?(tag = 0) ?(txs = [])
    ~(prev_hash : Types.hash256) ~(height : int) ~(prev_time : int32) () =
  let extra_nonce = Cstruct.create 8 in
  Cstruct.LE.set_uint64 extra_nonce 0 (Int64.of_int ((tag * 1_000_000) + height));
  let mk wr =
    Mining.create_coinbase ~height ~total_fee:0L ~payout_script:payout
      ~extra_nonce ~witness_root:wr ~network_type:Consensus.Regtest ()
  in
  let witness_root = Mining.compute_witness_merkle_root (mk None :: txs) in
  let coinbase = mk (Some witness_root) in
  let all = coinbase :: txs in
  let merkle_root, _ = Crypto.merkle_root (List.map Crypto.compute_txid all) in
  remine
    { Types.header =
        { version = 4l; prev_block = prev_hash; merkle_root;
          timestamp = Int32.add prev_time 600l;
          bits = Consensus.regtest.pow_limit; nonce = 0l };
      transactions = all }

let hash_of (b : Types.block) = Crypto.compute_block_hash b.Types.header

let accept_hdr state (b : Types.block) =
  match Sync.validate_header state b.Types.header with
  | Ok e -> Sync.accept_header state e
  | Error "Header already known" -> ()
  | Error e -> Alcotest.failf "validate_header: %s" e

type dres = DOk | DErr of string | DExn of exn

let deliver ?peer_id ?misbehavior_handler state b =
  match Lwt_main.run
          (Sync.process_new_block ~f_requested:true ?peer_id
             ?misbehavior_handler state b) with
  | Ok () -> DOk
  | Error e -> DErr e
  | exception e -> DExn e

let showd = function
  | DOk -> "Ok" | DErr e -> "Error " ^ e | DExn e -> "raised " ^ Printexc.to_string e

let disk_tip_height state =
  match Storage.ChainDB.get_chain_tip state.Sync.db with
  | Some (_, h) -> h | None -> -1

(* Chain genesis..101: block 1 pays to <pk> CHECKSIG, block 2 to
   <pk> CHECKSIG NOT; both mature at 102. *)
type fx = {
  state : Sync.chain_state;
  tip : Types.hash256;
  tip_time : int32;
  cb1 : Types.hash256;  (* txid of block-1 coinbase (<pk> CHECKSIG) *)
  cb2 : Types.hash256;  (* txid of block-2 coinbase (<pk> CHECKSIG NOT) *)
  cb_value : int64;
  punished : (int * string) list ref;
  handler : int -> string -> unit;
}

let with_chain f =
  reset ();
  Test_tmp.with_dir ~label:"gate6" ~mkdir:true (fun path ->
    let db = Storage.ChainDB.create path in
    Fun.protect
      ~finally:(fun () -> reset (); try Storage.ChainDB.close db with _ -> ())
      (fun () ->
        let state = Sync.create_chain_state db Consensus.regtest in
        state.Sync.sync_state <- Sync.FullySynced;
        let genesis = Option.get state.Sync.tip in
        let prev = ref (genesis.Sync.hash, genesis.Sync.header.Types.timestamp) in
        let cb1 = ref Types.zero_hash and cb2 = ref Types.zero_hash in
        let cbv = ref 0L in
        for h = 1 to 101 do
          let payout = if h = 1 then spk_checksig
            else if h = 2 then spk_checksig_not else op_true in
          let b = build_block ~payout ~prev_hash:(fst !prev) ~height:h
              ~prev_time:(snd !prev) () in
          let cb = List.hd b.Types.transactions in
          if h = 1 then begin
            cb1 := Crypto.compute_txid cb;
            cbv := (List.hd cb.Types.outputs).Types.value
          end;
          if h = 2 then cb2 := Crypto.compute_txid cb;
          accept_hdr state b;
          (match deliver state b with
           | DOk -> ()
           | r -> Alcotest.failf "prefix block %d: %s" h (showd r));
          prev := (hash_of b, b.Types.header.Types.timestamp)
        done;
        Alcotest.(check int) "prefix connected" 101 state.Sync.blocks_synced;
        let punished = ref [] in
        let handler pid reason = punished := (pid, reason) :: !punished in
        f { state; tip = fst !prev; tip_time = snd !prev; cb1 = !cb1;
            cb2 = !cb2; cb_value = !cbv; punished; handler }))

let peer_x = 7

let spend_block ?(bad = false) ?(tag = 0) fx ~cb ~spk =
  let tx = signed_spend ~bad ~prev_txid:cb ~value:fx.cb_value spk in
  build_block ~tag ~txs:[ tx ] ~prev_hash:fx.tip ~height:102
    ~prev_time:fx.tip_time ()

(* A VALID block whose script check cannot complete: never marked, never
   punished, tip unchanged, AbortNode; after the fault clears (restart)
   the same block connects. *)
let test_p2p_fault_no_mark_no_punish () =
  with_chain (fun fx ->
    let b = spend_block fx ~cb:fx.cb1 ~spk:spk_checksig in
    accept_hdr fx.state b;
    let r = with_hook secp_ctx_failure (fun () ->
        deliver ~peer_id:peer_x ~misbehavior_handler:fx.handler fx.state b) in
    Alcotest.(check bool) ("valid block not connected under the fault: " ^ showd r)
      true (r <> DOk);
    Alcotest.(check bool) "valid block NOT marked BLOCK_FAILED_VALID" false
      (Sync.is_block_invalid fx.state (hash_of b));
    Alcotest.(check (list (pair int string))) "delivering peer NOT punished"
      [] !(fx.punished);
    Alcotest.(check int) "tip unchanged" 101 fx.state.Sync.blocks_synced;
    Alcotest.(check bool) "AbortNode latched" true (Fatal.is_latched ());
    (* after AbortNode nothing connects *)
    (match deliver fx.state b with
     | DOk -> Alcotest.fail "connected while latched"
     | _ -> ());
    (* restart (latch cleared, fault gone): the same block connects *)
    Fatal.reset_for_tests ();
    match deliver ~peer_id:peer_x ~misbehavior_handler:fx.handler fx.state b with
    | DOk -> Alcotest.(check int) "connects after restart" 102
               fx.state.Sync.blocks_synced
    | r -> Alcotest.failf "valid block after the fault cleared: %s" (showd r))

(* <validsig> <pk> CHECKSIG NOT in a block under a secp fault: the block
   must NEVER connect (it is invalid: the signature is valid). *)
let test_p2p_checksig_not_fault_never_connects () =
  with_chain (fun fx ->
    let b = spend_block fx ~cb:fx.cb2 ~spk:spk_checksig_not in
    accept_hdr fx.state b;
    let r = with_hook secp_ctx_failure (fun () ->
        deliver ~peer_id:peer_x ~misbehavior_handler:fx.handler fx.state b) in
    Alcotest.(check bool) ("invalid block NOT connected under the fault: "
                           ^ showd r) true (r <> DOk);
    Alcotest.(check int) "tip unchanged" 101 fx.state.Sync.blocks_synced;
    (* fault gone: now the real verdict *)
    Fatal.reset_for_tests ();
    (match deliver ~peer_id:peer_x ~misbehavior_handler:fx.handler fx.state b with
     | DOk -> Alcotest.fail "invalid CHECKSIG NOT block accepted"
     | _ -> ());
    Alcotest.(check bool) "now marked failed (a real verdict)" true
      (Sync.is_block_invalid fx.state (hash_of b));
    Alcotest.(check int) "tip unchanged" 101 fx.state.Sync.blocks_synced)

(* CONTROL: a genuinely invalid signature is still marked + punished. *)
let test_p2p_control_invalid_sig () =
  with_chain (fun fx ->
    let b = spend_block ~bad:true fx ~cb:fx.cb1 ~spk:spk_checksig in
    accept_hdr fx.state b;
    (match deliver ~peer_id:peer_x ~misbehavior_handler:fx.handler fx.state b with
     | DErr _ -> ()
     | r -> Alcotest.failf "invalid sig block: %s" (showd r));
    Alcotest.(check bool) "marked failed" true
      (Sync.is_block_invalid fx.state (hash_of b));
    Alcotest.(check (list (pair int string))) "sender punished"
      [ (peer_x, "invalid_block") ] !(fx.punished);
    Alcotest.(check bool) "not latched" false (Fatal.is_latched ()))

(* ENOSPC once on the chainstate commit: retried; memory == disk. *)
let test_write_fault_once_retried () =
  with_chain (fun fx ->
    let b = spend_block fx ~cb:fx.cb1 ~spk:spk_checksig in
    accept_hdr fx.state b;
    let fired = ref false in
    Fatal.write_fault_hook := Some (fun what ->
        if what = "apply_block_atomic" && not !fired then begin
          fired := true; failwith "rocksdb_writebatch_write: IO error: No space left on device"
        end);
    let r = Fun.protect ~finally:(fun () -> Fatal.write_fault_hook := None)
        (fun () -> deliver ~peer_id:peer_x ~misbehavior_handler:fx.handler fx.state b) in
    Alcotest.(check int) ("memory tip == disk tip (" ^ showd r ^ ")")
      fx.state.Sync.blocks_synced (disk_tip_height fx.state);
    Alcotest.(check int) "block connected after the retry" 102
      (disk_tip_height fx.state);
    Alcotest.(check bool) "not latched" false (Fatal.is_latched ()))

(* ENOSPC on every commit: AbortNode; memory NOT ahead of disk; nothing
   marked/punished; after restart the block's coins exist. *)
let test_write_fault_persistent_halts () =
  with_chain (fun fx ->
    let b = spend_block fx ~cb:fx.cb1 ~spk:spk_checksig in
    accept_hdr fx.state b;
    Fatal.write_fault_hook := Some (fun what ->
        if what = "apply_block_atomic" then
          failwith "rocksdb_writebatch_write: IO error: No space left on device");
    let r = Fun.protect ~finally:(fun () -> Fatal.write_fault_hook := None)
        (fun () -> deliver ~peer_id:peer_x ~misbehavior_handler:fx.handler fx.state b) in
    Alcotest.(check bool) ("not reported as connected: " ^ showd r) true (r <> DOk);
    Alcotest.(check int) "memory tip NOT ahead of disk" (disk_tip_height fx.state)
      fx.state.Sync.blocks_synced;
    Alcotest.(check bool) "not marked" false
      (Sync.is_block_invalid fx.state (hash_of b));
    Alcotest.(check (list (pair int string))) "nobody punished" [] !(fx.punished);
    Alcotest.(check bool) "AbortNode latched" true (Fatal.is_latched ());
    (* restart: the block (and a child) connect; the block's coin exists *)
    Fatal.reset_for_tests ();
    let child = build_block ~prev_hash:(hash_of b) ~height:103
        ~prev_time:b.Types.header.Types.timestamp () in
    accept_hdr fx.state child;
    ignore (deliver fx.state b);
    ignore (deliver fx.state child);
    Alcotest.(check int) "chain extends after restart" 103
      (disk_tip_height fx.state);
    let spend_txid = Crypto.compute_txid (List.nth b.Types.transactions 1) in
    Alcotest.(check bool) "block 102's output is in the coin set" true
      (Storage.ChainDB.get_utxo fx.state.Sync.db spend_txid 0 <> None);
    Alcotest.(check bool) "block 102's spent coin is gone" true
      (Storage.ChainDB.get_utxo fx.state.Sync.db fx.cb1 0 = None))

(* ============================================================ submitblock *)

let block_hex (b : Types.block) =
  let w = Serialize.writer_create () in
  Serialize.serialize_block w b;
  let s = Serialize.writer_to_string w in
  String.concat "" (List.init (String.length s)
                      (fun i -> Printf.sprintf "%02x" (Char.code s.[i])))

let rpc_ctx (state : Sync.chain_state) : Rpc.rpc_context =
  let utxo = Utxo.UtxoSet.create state.Sync.db in
  let network = Consensus.regtest in
  { chain = state;
    mempool = Mempool.create ~network ~require_standard:false
        ~verify_scripts:true ~utxo ~current_height:101 ();
    peer_manager = Peer_manager.create network;
    wallet = None; wallet_manager = None;
    fee_estimator = Fee_estimation.create ();
    network; filter_index = None; utxo = None; data_dir = None;
    snapshot_activation = None }

let showr = function
  | Ok j -> "Ok " ^ Yojson.Safe.to_string j
  | Error (c, m) -> Printf.sprintf "Error (%d) %s" c m

let test_submitblock_fault_is_rpc_error () =
  with_chain (fun fx ->
    let ctx = rpc_ctx fx.state in
    let b = spend_block fx ~cb:fx.cb1 ~spk:spk_checksig in
    let r = with_hook secp_ctx_failure (fun () ->
        Rpc.dispatch_rpc ctx "submitblock" [ `String (block_hex b) ]) in
    (match r with
     | Error (-25, _) -> ()
     | _ -> Alcotest.failf "submitblock under a system fault must be \
                            RPC_VERIFY_ERROR (-25), never a BIP-22 token; got %s"
              (showr r));
    Alcotest.(check bool) "not marked" false
      (Sync.is_block_invalid fx.state (hash_of b));
    (* latched: a perfectly good block is refused with -25 *)
    let r2 = Rpc.dispatch_rpc ctx "submitblock" [ `String (block_hex b) ] in
    (match r2 with
     | Error (-25, _) -> ()
     | _ -> Alcotest.failf "latched node must answer -25; got %s" (showr r2));
    (* latched mempool: refuses with a non-verdict reason *)
    let tx = signed_spend ~prev_txid:fx.cb1 ~value:fx.cb_value spk_checksig in
    let res = Lwt_main.run (Mempool.accept_to_memory_pool ctx.mempool tx) in
    match res.Mempool.atmp_reject_reason with
    | Some reason when String.length reason >= 14
                       && String.sub reason 0 14 = "system-fault: " -> ()
    | other -> Alcotest.failf "latched mempool: expected a system-fault \
                               refusal, got %s"
                 (match other with Some s -> s | None -> "ACCEPTED"))

(* CONTROL: an invalid block via submitblock is still a BIP-22 result. *)
let test_submitblock_control () =
  with_chain (fun fx ->
    let ctx = rpc_ctx fx.state in
    let b = spend_block ~bad:true fx ~cb:fx.cb1 ~spk:spk_checksig in
    match Rpc.dispatch_rpc ctx "submitblock" [ `String (block_hex b) ] with
    | Ok (`String _) -> ()
    | r -> Alcotest.failf "invalid block: expected a BIP-22 string; got %s"
             (showr r))

let () =
  Alcotest.run "gate6_resource_limits"
    [ ("script",
       [ Alcotest.test_case "CHECKSIG NOT + secp fault never accepts" `Quick
           test_checksig_not_fault_never_accepts;
         Alcotest.test_case "CHECKSIGVERIFY + secp fault not a reject" `Quick
           test_checksigverify_fault_not_a_reject;
         Alcotest.test_case "LOW_S + secp fault not a reject" `Quick
           test_low_s_fault_not_a_reject;
         Alcotest.test_case "CONTROL script verdicts" `Quick test_script_controls ]);
      ("queue",
       [ Alcotest.test_case "persistent fault halts, no verdict" `Quick
           test_queue_persistent_fault_halts;
         Alcotest.test_case "CHECKSIG NOT fault: no accept, not cached" `Quick
           test_queue_checksig_not_fault_no_accept_no_cache;
         Alcotest.test_case "transient fault retried" `Quick
           test_queue_transient_fault_retried;
         Alcotest.test_case "dead worker (OOM) not a verdict" `Quick
           test_queue_dead_worker_not_a_verdict;
         Alcotest.test_case "CONTROL queue verdicts" `Quick test_queue_controls;
         Alcotest.test_case "mempool verify fault not a reject" `Quick
           test_mempool_verify_fault_not_a_reject ]);
      ("p2p",
       [ Alcotest.test_case "fault: no mark, no punish, halt" `Slow
           test_p2p_fault_no_mark_no_punish;
         Alcotest.test_case "CHECKSIG NOT fault never connects" `Slow
           test_p2p_checksig_not_fault_never_connects;
         Alcotest.test_case "CONTROL invalid sig marked + punished" `Slow
           test_p2p_control_invalid_sig;
         Alcotest.test_case "ENOSPC once: retried, memory == disk" `Slow
           test_write_fault_once_retried;
         Alcotest.test_case "ENOSPC persistent: halt, no torn state" `Slow
           test_write_fault_persistent_halts ]);
      ("submitblock",
       [ Alcotest.test_case "fault -> -25, latched -> -25, mempool refuses" `Slow
           test_submitblock_fault_is_rpc_error;
         Alcotest.test_case "CONTROL invalid block -> BIP-22" `Slow
           test_submitblock_control ]) ]
