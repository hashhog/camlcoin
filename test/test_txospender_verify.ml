(* Verifier-2 in-process proof for txospender_index (camlcoin).
   Proves: connect writes spend record, find_spender resolves to spender,
   disconnect (reorg/invalidate hook) RE-DERIVES + erases, best-pointer rolls
   back, default-off falsification (find on a never-indexed outpoint = None). *)

open Camlcoin
module Txospender_index = Camlcoin__Txospender_index

let tmp_dir () =
  let d = Filename.concat (Filename.get_temp_dir_name ())
            (Printf.sprintf "txospender-verify-%d-%d" (Unix.getpid ())
               (Random.int 1_000_000)) in
  Unix.mkdir d 0o755; d

let h32 (b : int) : Types.hash256 =
  let c = Cstruct.create 32 in Cstruct.memset c b; c

let coinbase () : Types.transaction =
  { Types.version = 1l;
    inputs = [ { previous_output = { txid = Types.zero_hash; vout = 0xffffffffl };
                 script_sig = Cstruct.of_string "\x01\x01"; sequence = 0xffffffffl } ];
    outputs = [ { value = 50_0000_0000L; script_pubkey = Cstruct.of_string "\x51" } ];
    witnesses = []; locktime = 0l }

(* tx spending (spent_txid, vout). *)
let spender_tx (spent_txid : Types.hash256) (vout : int32) (out_tag : int)
    : Types.transaction =
  { Types.version = 1l;
    inputs = [ { previous_output = { txid = spent_txid; vout };
                 script_sig = Cstruct.of_string "\x00"; sequence = 0xfffffffel } ];
    outputs = [ { value = 49_0000_0000L;
                  script_pubkey = Cstruct.create out_tag } ];
    witnesses = []; locktime = 0l }

let mk_block (prev : Types.hash256) (txs : Types.transaction list) : Types.block =
  { Types.header =
      { version = 1l; prev_block = prev; merkle_root = h32 0;
        timestamp = 1_700_000_000l; bits = 0x207fffffl; nonce = 0l };
    transactions = txs }

let () =
  Random.self_init ();
  let dir = tmp_dir () in
  let idx = Txospender_index.create ~data_dir:dir in

  (* outpoint A:0 — the output tx B will spend. *)
  let a_txid = h32 0xaa in
  let op_a0 = { Types.txid = a_txid; vout = 0l } in

  (* FALSIFICATION: before any connect, the index answers None. *)
  assert (Txospender_index.find_spender idx op_a0 = None);
  assert (Txospender_index.best_height idx = -1);

  (* Block 1: coinbase + tx B (spends A:0). Connect at height 1. *)
  let b = spender_tx a_txid 0l 10 in
  let b_txid = Crypto.compute_txid b in
  let blk1 = mk_block (h32 0) [ coinbase (); b ] in
  let blk1_hash = Crypto.compute_block_hash blk1.Types.header in
  Txospender_index.connect_block idx ~block:blk1 ~height:1 ~block_hash:blk1_hash;

  (* find_spender(A:0) must resolve to B + the confirming block hash. *)
  (match Txospender_index.find_spender idx op_a0 with
   | None -> failwith "FAIL: A:0 should resolve to spender B after connect"
   | Some s ->
     assert (Cstruct.equal s.Txospender_index.spending_txid b_txid);
     assert (Cstruct.equal s.Txospender_index.block_hash blk1_hash);
     (* stored spending-tx bytes round-trip to B. *)
     let r = Serialize.reader_of_cstruct s.Txospender_index.spending_tx_bytes in
     let decoded = Serialize.deserialize_transaction r in
     assert (Cstruct.equal (Crypto.compute_txid decoded) b_txid));
  assert (Txospender_index.best_height idx = 1);
  Printf.printf "OK  connect -> find_spender(A:0) = B (+ blockhash)\n";

  (* LIVE-REORG disconnect: a heavier branch orphans block 1. The disconnect
     hook re-derives B's spend keys from the block's own inputs and erases. *)
  Txospender_index.disconnect_block idx ~block:blk1 ~height:1
    ~prev_block_hash:(Some (h32 0));
  assert (Txospender_index.find_spender idx op_a0 = None);
  assert (Txospender_index.best_height idx = 0);
  Printf.printf "OK  reorg/invalidate disconnect erases A:0 + rolls best->0\n";

  (* SAME-OUTPOINT RE-SPEND on the new branch (the reorg hazard): a different
     tx C spends the SAME A:0. disconnect-before-connect means the new write
     is correct (B erased first, C written). *)
  let c = spender_tx a_txid 0l 20 in
  let c_txid = Crypto.compute_txid c in
  let blk1b = mk_block (h32 0) [ coinbase (); c ] in
  let blk1b_hash = Crypto.compute_block_hash blk1b.Types.header in
  Txospender_index.connect_block idx ~block:blk1b ~height:1 ~block_hash:blk1b_hash;
  (match Txospender_index.find_spender idx op_a0 with
   | None -> failwith "FAIL: A:0 should now resolve to C"
   | Some s ->
     assert (Cstruct.equal s.Txospender_index.spending_txid c_txid);
     assert (not (Cstruct.equal s.Txospender_index.spending_txid b_txid)));
  Printf.printf "OK  same-outpoint re-spend by C resolves to C, not stale B\n";

  (* Persistence: a fresh handle over the same dir reloads best + record. *)
  let idx2 = Txospender_index.create ~data_dir:dir in
  assert (Txospender_index.best_height idx2 = 1);
  (match Txospender_index.find_spender idx2 op_a0 with
   | Some s -> assert (Cstruct.equal s.Txospender_index.spending_txid c_txid)
   | None -> failwith "FAIL: reopened index lost A:0 -> C");
  Printf.printf "OK  best-pointer + record persist across reopen\n";

  Printf.printf "ALL TXOSPENDER VERIFY CHECKS PASSED\n"
