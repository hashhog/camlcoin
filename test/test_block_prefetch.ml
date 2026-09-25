(* Block-input prefetch control (perf/block-validation, 2026-09-24).

   validate_block_with_utxos ?prefetch_base resolves every base-view read a
   block can make (non-coinbase prevouts not created in-block, plus BIP-30
   probes when BIP-30 is enforced) in one batched call, then serves them from
   a memo.  This is a PERF change only: the decision and the reject reason
   must be identical to the serial path for every block.

   REQUIRED
     (1) decision identity — accept/reject AND reason identical with no
         prefetch, a full prefetch, an EMPTY prefetch (nothing resolved), and
         a full prefetch run across the ScriptCheckQueue domains
     (2) the memo is actually consulted — with a full prefetch the serial
         loop makes ZERO live base_lookup calls (a memo that is never read is
         a decoration, not a cache)
     (3) parallel_for runs every index once and re-raises a task exception
         only after every worker has finished

   CONTROL: dune exec --no-buffer test/test_block_prefetch.exe
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

let make_tx ?(version = 1l) ?(locktime = 0l) ~inputs ~outputs () =
  { Types.version; inputs; outputs; witnesses = []; locktime }

let inp ?(sequence = 0xFFFFFFFFl) txid vout : Types.tx_in =
  { Types.previous_output = { Types.txid; vout };
    script_sig = Cstruct.create 0; sequence }

let out ?(spk = op_true ()) value : Types.tx_out =
  { Types.value; script_pubkey = spk }

let height = 200

let coinbase ?(extra = 0) fees =
  let bip34 = Consensus.encode_height_in_coinbase height in
  let s = Cstruct.create (Cstruct.length bip34 + 2) in
  Cstruct.blit bip34 0 s 0 (Cstruct.length bip34);
  Cstruct.set_uint8 s (Cstruct.length bip34) 0xC0;
  Cstruct.set_uint8 s (Cstruct.length bip34 + 1) extra;
  let subsidy = Consensus.block_subsidy_for_network Consensus.Regtest height in
  make_tx
    ~inputs:[ { Types.previous_output = { Types.txid = Types.zero_hash; vout = -1l };
                script_sig = s; sequence = 0xFFFFFFFFl } ]
    ~outputs:[ out (Int64.add subsidy fees) ] ()

let mine (h : Types.block_header) =
  let rec loop n =
    let h' = { h with Types.nonce = n } in
    if Consensus.hash_meets_target (Crypto.compute_block_hash h') h'.bits then h'
    else loop (Int32.add n 1l)
  in
  loop 0l

let make_block (txs : Types.transaction list) : Types.block =
  let (merkle, _) = Crypto.merkle_root (List.map Crypto.compute_txid txs) in
  let header = mine { Types.version = 4l; prev_block = Types.zero_hash;
                      merkle_root = merkle; timestamp = 1000l;
                      bits = 0x207fffffl; nonce = 0l } in
  { Types.header; transactions = txs }

(* Base UTXO view: A,B spendable (OP_TRUE), F fails its script (OP_FALSE),
   M is an immature coinbase. *)
let a = hash_n 1 and b = hash_n 2 and f = hash_n 3 and m = hash_n 4

let base : (string * int32, Validation.utxo) Hashtbl.t = Hashtbl.create 16
let add_base ?(cb = false) ?(h = 10) ?(spk = op_true ()) txid vout value =
  Hashtbl.replace base (Cstruct.to_string txid, vout)
    { Validation.txid; vout; value; script_pubkey = spk; height = h;
      is_coinbase = cb }
let () =
  add_base a 0l 50_000L; add_base a 1l 60_000L;
  add_base b 0l 70_000L;
  add_base ~spk:(op_false ()) f 0l 80_000L;
  add_base ~cb:true ~h:(height - 5) m 0l 90_000L

let live_calls = ref 0
let base_lookup (o : Types.outpoint) =
  incr live_calls;
  Hashtbl.find_opt base (Cstruct.to_string o.txid, o.vout)

(* Pure (no counter) resolution for the prefetch implementations. *)
let resolve (o : Types.outpoint) =
  Hashtbl.find_opt base (Cstruct.to_string o.txid, o.vout)

let full_prefetch : Validation.base_prefetch =
  fun ops -> Array.map (fun o -> Some (resolve o)) ops
let empty_prefetch : Validation.base_prefetch =
  fun ops -> Array.make (Array.length ops) None
let parallel_prefetch : Validation.base_prefetch = fun ops ->
  let res = Array.make (Array.length ops) None in
  Validation.parallel_for (Array.length ops)
    (fun i -> res.(i) <- Some (resolve ops.(i)));
  res

let run ?prefetch_base block =
  match Validation.validate_block_with_utxos ~network:Consensus.regtest block
          height ~expected_bits:0x207fffffl ~median_time:0l ~base_lookup
          ~flags:Script.script_verify_p2sh ~skip_scripts:false
          ?prefetch_base () with
  | Ok (fees, txids, spent) ->
    Printf.sprintf "OK fees=%Ld ntx=%d spent=%d" fees (Array.length txids)
      (List.length spent)
  | Error e -> "ERR " ^ Validation.block_error_to_string e

(* ---- blocks ---------------------------------------------------------- *)

let blocks () =
  let t1 = make_tx ~inputs:[ inp a 0l ] ~outputs:[ out 49_000L ] () in
  let t1id = Crypto.compute_txid t1 in
  let t2 = make_tx ~inputs:[ inp t1id 0l; inp b 0l ] ~outputs:[ out 118_000L ] () in
  let t3 = make_tx ~inputs:[ inp a 1l ] ~outputs:[ out 59_000L; out 500L ] () in
  let valid = make_block [ coinbase 2_500L; t1; t2; t3 ] in
  let missing =
    make_block [ coinbase ~extra:1 0L;
                 make_tx ~inputs:[ inp (hash_n 99) 0l ] ~outputs:[ out 1L ] () ] in
  let dbl =
    make_block [ coinbase ~extra:2 0L;
                 make_tx ~inputs:[ inp b 0l ] ~outputs:[ out 1L ] ();
                 make_tx ~locktime:1l ~inputs:[ inp b 0l ] ~outputs:[ out 2L ] () ] in
  let script_fail =
    make_block [ coinbase ~extra:3 0L;
                 make_tx ~inputs:[ inp a 0l ] ~outputs:[ out 1L ] ();
                 make_tx ~inputs:[ inp f 0l ] ~outputs:[ out 1L ] () ] in
  let immature =
    make_block [ coinbase ~extra:4 0L;
                 make_tx ~inputs:[ inp m 0l ] ~outputs:[ out 1L ] () ] in
  let fwd_later = make_tx ~inputs:[ inp b 0l ] ~outputs:[ out 69_000L ] () in
  let fwd =
    make_block [ coinbase ~extra:5 0L;
                 make_tx ~inputs:[ inp (Crypto.compute_txid fwd_later) 0l ]
                   ~outputs:[ out 1L ] ();
                 fwd_later ] in
  (* BIP-30: the coinbase txid already has an unspent output in the base. *)
  let dup_cb = coinbase ~extra:6 0L in
  add_base ~cb:true (Crypto.compute_txid dup_cb) 0l 1L;
  let bip30 = make_block [ dup_cb ] in
  [ "valid", valid; "missing-input", missing; "in-block-double-spend", dbl;
    "script-fail", script_fail; "immature-coinbase", immature;
    "forward-reference", fwd; "bip30-duplicate", bip30 ]

let test_decision_identity () =
  List.iter (fun (name, blk) ->
    let serial = run blk in
    let full = run ~prefetch_base:full_prefetch blk in
    let empty = run ~prefetch_base:empty_prefetch blk in
    Validation.start_script_check_queue ();
    let par = run ~prefetch_base:parallel_prefetch blk in
    Validation.stop_script_check_queue ();
    Printf.printf "  %-22s serial=%s\n" name serial;
    Alcotest.(check string) (name ^ " full") serial full;
    Alcotest.(check string) (name ^ " empty") serial empty;
    Alcotest.(check string) (name ^ " parallel") serial par
  ) (blocks ());
  (* Sanity that the corpus is not all-accept or all-reject. *)
  let outs = List.map (fun (_, b) -> run b) (blocks ()) in
  Alcotest.(check bool) "has an accept" true
    (List.exists (fun s -> String.length s > 2 && String.sub s 0 2 = "OK") outs);
  Alcotest.(check bool) "has >=5 distinct rejects" true
    (List.length (List.sort_uniq compare
       (List.filter (fun s -> String.sub s 0 3 = "ERR") outs)) >= 5)

let test_memo_is_consulted () =
  let blk = List.assoc "valid" (blocks ()) in
  live_calls := 0;
  ignore (run blk);
  let serial_calls = !live_calls in
  live_calls := 0;
  ignore (run ~prefetch_base:full_prefetch blk);
  let prefetched_calls = !live_calls in
  Printf.printf "  live base_lookup calls: serial=%d prefetched=%d\n"
    serial_calls prefetched_calls;
  Alcotest.(check bool) "serial path reads the base" true (serial_calls > 0);
  Alcotest.(check int) "prefetched path makes no live reads" 0 prefetched_calls

(* The IBD dispatcher's own readers (Sync.ibd_base_readers): serial
   [lookup] and batched [prefetch_base] must agree per outpoint, and a coin
   the OptimizedUtxoSet holds as SPENT is missing to both — even though the
   store still has it until the next flush.  f90bd03 kept the old
   behaviour here on purpose (Mem_removed -> raw-store read, returning the
   spent coin) to stay identical to [lookup]; both now treat the cache as
   authoritative, as Core's CCoinsViewCache::FetchCoin does (coins.cpp).
   QUEUES.md 2026-09-24 cross-block double spend. *)
let test_ibd_readers_spent_is_authoritative () =
  Test_tmp.with_dir ~label:"prefetch_readers" ~mkdir:true (fun path ->
    let db = Storage.ChainDB.create path in
    Fun.protect ~finally:(fun () -> try Storage.ChainDB.close db with _ -> ())
      (fun () ->
        let state = Sync.create_chain_state db Consensus.regtest in
        let u = Utxo.OptimizedUtxoSet.create ~cache_size:100 db in
        let ibd = Sync.create_ibd_state ~utxo_set:u state in
        let e v = { Utxo.value = v; script_pubkey = op_true (); height = 5;
                    is_coinbase = false } in
        let disk = hash_n 201 and cache_only = hash_n 202
        and spent = hash_n 203 and never = hash_n 204 in
        Utxo.OptimizedUtxoSet.add u disk 0 (e 1L);
        Utxo.OptimizedUtxoSet.add u spent 0 (e 3L);
        Utxo.OptimizedUtxoSet.flush u;
        Utxo.OptimizedUtxoSet.add u cache_only 0 (e 2L);
        Utxo.OptimizedUtxoSet.remove_fast u spent 0;
        Alcotest.(check bool) "precondition: spent coin still in the store"
          true (Storage.ChainDB.get_utxo db spent 0 <> None);
        let lookup, prefetch = Sync.ibd_base_readers ibd in
        let ops = Array.map (fun t -> { Types.txid = t; vout = 0l })
                    [| disk; cache_only; spent; never |] in
        let show = function
          | None -> "missing"
          | Some (x : Validation.utxo) -> Int64.to_string x.value in
        let serial = Array.map (fun o -> show (lookup o)) ops in
        let batched = Array.map (function
            | None -> "unresolved" | Some r -> show r) (prefetch ops) in
        Printf.printf "  serial=[%s] prefetch=[%s]\n"
          (String.concat "," (Array.to_list serial))
          (String.concat "," (Array.to_list batched));
        Alcotest.(check (array string)) "serial lookup"
          [| "1"; "2"; "missing"; "missing" |] serial;
        Alcotest.(check (array string)) "prefetch == serial" serial batched))

let test_parallel_for () =
  Validation.start_script_check_queue ();
  Fun.protect ~finally:Validation.stop_script_check_queue (fun () ->
    let n = 10_000 in
    let hits = Array.make n 0 in
    Validation.parallel_for n (fun i -> hits.(i) <- hits.(i) + 1);
    Alcotest.(check bool) "every index exactly once" true
      (Array.for_all (fun x -> x = 1) hits);
    let done_ = Array.make n false in
    let raised =
      try
        Validation.parallel_for n (fun i ->
          if i = 1234 then failwith "boom";
          done_.(i) <- true);
        false
      with Failure m -> m = "boom"
    in
    Alcotest.(check bool) "task exception re-raised" true raised;
    Alcotest.(check int) "all other indices ran" (n - 1)
      (Array.fold_left (fun acc d -> if d then acc + 1 else acc) 0 done_))

let () =
  Alcotest.run "block_prefetch" [
    "prefetch", [
      Alcotest.test_case "decision identity serial/full/empty/parallel" `Quick
        test_decision_identity;
      Alcotest.test_case "memo is consulted (0 live reads)" `Quick
        test_memo_is_consulted;
      Alcotest.test_case "IBD readers: cache-spent coin is missing" `Quick
        test_ibd_readers_spent_is_authoritative;
    ];
    "queue", [
      Alcotest.test_case "parallel_for coverage + exception" `Quick test_parallel_for;
    ];
  ]
