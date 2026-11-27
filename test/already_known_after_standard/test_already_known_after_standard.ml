(* txn-already-known: after standardness, only on a missing input, and only
   from in-memory coins.

   Core MemPoolAccept::PreChecks (validation.cpp:808-866) runs IsStandardTx
   and tx-size-small first.  It probes the tx's own outputs only once an
   input is missing, and then only with CCoinsViewCache::HaveCoinInCache,
   which never reads the coins DB.  camlcoin ran the probe for every output,
   before standardness, through Utxo.UtxoSet.get, which falls through to the
   store: a relayed 1 MB tx with ~111k outputs cost ~111k point reads, and it
   could be resent.

   The store-read counter is the chain coin view in front of the store
   (Utxo.UtxoSet.tip_view): every Utxo.UtxoSet.get asks it first and, on
   Tip_miss, reads the store.  A view that counts and answers Tip_miss
   therefore counts the store reads made through Utxo.UtxoSet.get. *)

open Camlcoin

let p2wpkh = Cstruct.of_string ("\x00\x14" ^ String.make 20 '\x11')
let op_true = Cstruct.of_string "\x51"

let entry ?(value = 5_000_000_000L) spk : Utxo.utxo_entry =
  { value; script_pubkey = spk; height = 1; is_coinbase = false }

let tx_with ~(prev : Types.hash256) ~prev_vout (outputs : Types.tx_out list)
    : Types.transaction =
  { Types.version = 2l;
    inputs = [ { Types.previous_output =
                   { Types.txid = prev; vout = Int32.of_int prev_vout };
                 script_sig = Cstruct.empty; sequence = 0xFFFFFFFFl } ];
    outputs; witnesses = []; locktime = 0l }

(* One value output plus a zero-value OP_RETURN so the non-witness size
   clears MIN_STANDARD_TX_NONWITNESS_SIZE. *)
let two_outputs : Types.tx_out list =
  [ { Types.value = 4_999_990_000L; script_pubkey = op_true };
    { Types.value = 0L;
      script_pubkey = Cstruct.of_string ("\x6a\x14" ^ String.make 20 'x') } ]

let coinbase height : Types.transaction =
  { Types.version = 2l;
    inputs = [ { Types.previous_output =
                   { Types.txid = Types.zero_hash; vout = -1l };
                 script_sig = Cstruct.of_string
                     (Printf.sprintf "\x01%c\x00" (Char.chr height));
                 sequence = 0xFFFFFFFFl } ];
    outputs = [ { Types.value = 0L; script_pubkey = op_true } ];
    witnesses = []; locktime = 0l }

let block ~(prev : Types.hash256) height txs : Types.block =
  { Types.header = { Types.version = 0x20000000l; prev_block = prev;
                     merkle_root = Types.zero_hash;
                     timestamp = Int32.of_int (1_700_000_000 + height);
                     bits = 0x207fffffl; nonce = Int32.of_int height };
    transactions = coinbase height :: txs }

let block_hash (b : Types.block) = Crypto.compute_block_hash b.Types.header

let prev_txid = Cstruct.of_string (String.make 32 '\x07')

(* Install a counting coin view for [f]; restore the previous one after. *)
let with_counting_view ?(answer = fun _ _ -> Utxo.UtxoSet.Tip_miss)
    ~(count : Types.hash256 -> bool) f =
  let old = Atomic.get Utxo.UtxoSet.tip_view in
  let n = ref 0 in
  Atomic.set Utxo.UtxoSet.tip_view
    (Some (fun txid vout ->
         if count txid then incr n;
         match answer txid vout with
         | Utxo.UtxoSet.Tip_miss ->
           (match old with Some v -> v txid vout | None -> Utxo.UtxoSet.Tip_miss)
         | a -> a));
  Fun.protect ~finally:(fun () -> Atomic.set Utxo.UtxoSet.tip_view old)
    (fun () -> f n)

let with_mempool ?(require_standard = false) f =
  Test_tmp.with_chaindb (fun db ->
      let utxo = Utxo.UtxoSet.create db in
      let mp = Mempool.create ~network:Consensus.regtest ~require_standard
                 ~verify_scripts:false ~utxo ~current_height:200 () in
      f db utxo mp)

let reason = function
  | Ok _ -> "accepted"
  | Error e -> e

let is_missing r =
  match r with
  | Error e -> String.length e >= 14 && String.sub e 0 14 = "Missing input:"
  | Ok _ -> false

(* The item's test: K = 10,000 outputs, the input present.  IsStandardTx
   rejects it (tx-size) before any output is probed; master probed all
   10,000 outputs through the store first. *)
let test_standardness_first () =
  with_mempool ~require_standard:true (fun _db utxo mp ->
      Utxo.UtxoSet.add utxo prev_txid 0 (entry p2wpkh);
      let k = 10_000 in
      let outputs =
        List.init k (fun _ -> { Types.value = 1_000L; script_pubkey = p2wpkh }) in
      let tx = tx_with ~prev:prev_txid ~prev_vout:0 outputs in
      let txid = Crypto.compute_txid tx in
      with_counting_view ~count:(Cstruct.equal txid) (fun n ->
          let r = Mempool.add_transaction mp tx in
          Printf.printf "K=%d outputs: output-probe store reads=%d, reason=%s\n"
            k !n (reason r);
          Alcotest.(check int) "output-probe store reads" 0 !n;
          Alcotest.(check string) "standardness reject token" "tx-size"
            (Rpc.canonical_mempool_reject_reason ~testmempoolaccept:false
               (reason r))))

(* Inputs present: Core never probes the outputs, so a tx whose outputs are
   in memory is not "txn-already-known" (and nothing is read for them). *)
let test_inputs_present_no_probe () =
  with_mempool (fun _db utxo mp ->
      Utxo.UtxoSet.add utxo prev_txid 0 (entry op_true);
      let tx = tx_with ~prev:prev_txid ~prev_vout:0 two_outputs in
      let txid = Crypto.compute_txid tx in
      (* The tx's outputs are already in the store (a BIP30-style duplicate). *)
      Utxo.UtxoSet.add utxo txid 0 (entry op_true);
      with_counting_view ~count:(Cstruct.equal txid) (fun n ->
          let r = Mempool.add_transaction ~dry_run:true mp tx in
          Alcotest.(check bool) "not txn-already-known" true
            (r <> Error "txn-already-known");
          Alcotest.(check int) "output probes" 0 !n))

(* Confirmed in a connected block, its input spent by that block: the coins
   are in memory, so the answer is txn-already-known with no store read for
   any output. *)
let test_confirmed_in_recent_block () =
  with_mempool (fun _db _utxo mp ->
      let tx = tx_with ~prev:prev_txid ~prev_vout:0 two_outputs in
      let txid = Crypto.compute_txid tx in
      Mempool.remove_for_block mp (block ~prev:Types.zero_hash 1 [ tx ]) 1;
      let r = Mempool.add_transaction mp tx in
      Alcotest.(check string) "reason" "txn-already-known" (reason r);
      ignore txid)

(* Cache-only: the outputs exist only in the store (not in the shared coin
   cache, not in a remembered block).  HaveCoinInCache is false, so Core
   answers bad-txns-inputs-missingorspent; master read the store and said
   txn-already-known. *)
let test_store_only_is_missing () =
  with_mempool (fun _db utxo mp ->
      let tx = tx_with ~prev:prev_txid ~prev_vout:0 two_outputs in
      let txid = Crypto.compute_txid tx in
      Utxo.UtxoSet.add utxo txid 0 (entry op_true);
      let r = Mempool.add_transaction mp tx in
      Alcotest.(check bool) ("missing input, got " ^ reason r) true (is_missing r);
      Alcotest.(check string) "sendraw token" "bad-txns-inputs-missingorspent"
        (Rpc.canonical_mempool_reject_reason ~testmempoolaccept:false (reason r)))

(* The shared chain coin cache: a held coin is known, a coin it holds
   spent is not (authoritative, even over a remembered block). *)
let test_shared_cache () =
  with_mempool (fun _db _utxo mp ->
      let tx = tx_with ~prev:prev_txid ~prev_vout:0 two_outputs in
      let txid = Crypto.compute_txid tx in
      let hit _ _ = Utxo.UtxoSet.Tip_hit (entry op_true) in
      with_counting_view ~answer:(fun t v -> if Cstruct.equal t txid && v = 0
                                    then hit t v else Utxo.UtxoSet.Tip_miss)
        ~count:(fun _ -> false) (fun _ ->
          Alcotest.(check string) "cache hit" "txn-already-known"
            (reason (Mempool.add_transaction mp tx)));
      Mempool.remove_for_block mp (block ~prev:Types.zero_hash 1 [ tx ]) 1;
      with_counting_view ~answer:(fun t _ -> if Cstruct.equal t txid
                                    then Utxo.UtxoSet.Tip_spent
                                    else Utxo.UtxoSet.Tip_miss)
        ~count:(fun _ -> false) (fun _ ->
          let r = Mempool.add_transaction mp tx in
          Alcotest.(check bool) ("cache spent, got " ^ reason r) true
            (is_missing r)))

(* A coin spent by a later remembered block is not known; one output still
   unspent keeps the tx known. *)
let test_spent_later () =
  with_mempool (fun _db _utxo mp ->
      let tx = tx_with ~prev:prev_txid ~prev_vout:0 two_outputs in
      let txid = Crypto.compute_txid tx in
      let b1 = block ~prev:Types.zero_hash 1 [ tx ] in
      Mempool.remove_for_block mp b1 1;
      let spend0 = tx_with ~prev:txid ~prev_vout:0
          [ { Types.value = 1L; script_pubkey = op_true } ] in
      let b2 = block ~prev:(block_hash b1) 2 [ spend0 ] in
      Mempool.remove_for_block mp b2 2;
      Alcotest.(check string) "output 1 still unspent" "txn-already-known"
        (reason (Mempool.add_transaction mp tx));
      let spend1 = tx_with ~prev:txid ~prev_vout:1
          [ { Types.value = 1L; script_pubkey = op_true } ] in
      Mempool.remove_for_block mp (block ~prev:(block_hash b2) 3 [ spend1 ]) 3;
      let r = Mempool.add_transaction mp tx in
      Alcotest.(check bool) ("both spent, got " ^ reason r) true (is_missing r))

(* Disconnects forget the remembered coins: a block that does not extend
   the newest one, and update_for_reorg. *)
let test_reorg_forgets () =
  with_mempool (fun _db _utxo mp ->
      let tx = tx_with ~prev:prev_txid ~prev_vout:0 two_outputs in
      let b1 = block ~prev:Types.zero_hash 1 [ tx ] in
      Mempool.remove_for_block mp b1 1;
      Alcotest.(check string) "known" "txn-already-known"
        (reason (Mempool.add_transaction mp tx));
      (* A sibling of b1 (same parent): b1 was disconnected. *)
      Mempool.remove_for_block mp (block ~prev:Types.zero_hash 99 []) 1;
      let r = Mempool.add_transaction mp tx in
      Alcotest.(check bool) ("after sibling, got " ^ reason r) true (is_missing r);
      Mempool.remove_for_block mp b1 1;
      ignore (Mempool.update_for_reorg mp ~disconnected:[] ~dropped:[]);
      let r = Mempool.add_transaction mp tx in
      Alcotest.(check bool) ("after update_for_reorg, got " ^ reason r) true
        (is_missing r))

(* The RPC codes are unchanged: sendrawtransaction -27 for a confirmed tx,
   -25 for a missing input; testmempoolaccept txn-already-known. *)
let with_ctx f =
  Test_tmp.with_chaindb (fun db ->
      let utxo = Utxo.UtxoSet.create db in
      let mp = Mempool.create ~network:Consensus.regtest ~require_standard:false
                 ~verify_scripts:false ~utxo ~current_height:0 () in
      let chain = Sync.create_chain_state db Consensus.regtest in
      let ctx : Rpc.rpc_context =
        { chain; mempool = mp;
          peer_manager = Peer_manager.create Consensus.regtest;
          wallet = None; wallet_manager = None;
          fee_estimator = Fee_estimation.create ();
          network = Consensus.regtest; filter_index = None; utxo = None;
          data_dir = None; snapshot_activation = None } in
      f ctx)

let tx_hex (tx : Types.transaction) =
  let w = Serialize.writer_create () in
  Serialize.serialize_transaction w tx;
  let s = Serialize.writer_to_string w in
  String.concat "" (List.init (String.length s)
                      (fun i -> Printf.sprintf "%02x" (Char.code s.[i])))

let test_rpc_codes () =
  with_ctx (fun ctx ->
      let tx = tx_with ~prev:prev_txid ~prev_vout:0 two_outputs in
      let other = tx_with ~prev:(Cstruct.of_string (String.make 32 '\x08'))
          ~prev_vout:0 two_outputs in
      Mempool.remove_for_block ctx.mempool (block ~prev:Types.zero_hash 1 [ tx ]) 1;
      (match Rpc.dispatch_rpc ctx "sendrawtransaction" [ `String (tx_hex tx) ] with
       | Error (code, msg) ->
         Alcotest.(check int) "confirmed code" (-27) code;
         Alcotest.(check string) "confirmed msg"
           "Transaction outputs already in utxo set" msg
       | Ok _ -> Alcotest.fail "confirmed: accepted");
      (match Rpc.dispatch_rpc ctx "sendrawtransaction" [ `String (tx_hex other) ] with
       | Error (code, msg) ->
         Alcotest.(check int) "missing code" (-25) code;
         Alcotest.(check string) "missing msg" "bad-txns-inputs-missingorspent" msg
       | Ok _ -> Alcotest.fail "missing: accepted");
      match Rpc.dispatch_rpc ctx "testmempoolaccept"
              [ `List [ `String (tx_hex tx) ] ] with
      | Ok (`List [ `Assoc kv ]) ->
        Alcotest.(check bool) "tmpa reject-reason" true
          (List.assoc_opt "reject-reason" kv = Some (`String "txn-already-known"))
      | _ -> Alcotest.fail "testmempoolaccept shape")

let () =
  Alcotest.run "already_known_after_standard"
    [ ("already-known", [
          Alcotest.test_case "10k outputs, inputs present: standardness first, 0 output store reads"
            `Quick test_standardness_first;
          Alcotest.test_case "inputs present: outputs not probed" `Quick
            test_inputs_present_no_probe;
          Alcotest.test_case "confirmed in a connected block: already-known from memory"
            `Quick test_confirmed_in_recent_block;
          Alcotest.test_case "outputs only in the store: missingorspent (cache-only)"
            `Quick test_store_only_is_missing;
          Alcotest.test_case "shared coin cache: hit known, spent not" `Quick
            test_shared_cache;
          Alcotest.test_case "spent by a later block" `Quick test_spent_later;
          Alcotest.test_case "disconnect forgets remembered coins" `Quick
            test_reorg_forgets;
          Alcotest.test_case "sendraw -27 / -25, testmempoolaccept token" `Quick
            test_rpc_codes ]) ]
