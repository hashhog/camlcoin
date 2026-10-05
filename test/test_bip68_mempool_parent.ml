(* BIP68 relative height locks on coins created by a MEMPOOL parent.

   Core (validation.cpp CalculateLockPointsAtTip / CheckSequenceLocksAtTip,
   txmempool.cpp CCoinsViewMemPool): an unconfirmed coin has height
   MEMPOOL_HEIGHT, which is replaced by tip->nHeight + 1 — the earliest block
   that could include the parent — and the lock is evaluated for a block at
   height tip+1.  So a child with nSequence relative height lock 1 spending a
   mempool parent needs tip+1 >= (tip+1) + 1: it is non-BIP68-final until the
   parent confirms (or another block arrives).

   camlcoin b08ea33 gave the mempool coin the TIP height (mempool.ml
   lookup_utxo), accepting such children one block early — and they could then
   reach a block template that is invalid.

   Every case drives the real Mempool.add_transaction (scripts off, standard
   off: only the BIP68 gate is under test).  Controls: lock 0 on a mempool
   parent, lock 1 / lock 2 on a coin confirmed AT the tip, and the child
   accepted once the parent is confirmed. *)

open Camlcoin

let test_db_path = Test_tmp.register "/tmp/camlcoin_test_bip68_mempool_parent_db"

let rec rm_rf path =
  if Sys.file_exists path then begin
    if Sys.is_directory path then begin
      Array.iter (fun f -> rm_rf (Filename.concat path f)) (Sys.readdir path);
      Unix.rmdir path
    end else Unix.unlink path
  end

let tip = 100
let spk = Cstruct.of_string "\x76\xa9\x14test_script_pubkey\x88\xac"
let out v = Types.{ value = v; script_pubkey = spk }

let input ?(sequence = 0xFFFFFFFFl) txid vout =
  Types.{ previous_output = { txid; vout }; script_sig = Cstruct.of_string "\x00";
          sequence }

let tx2 inputs outputs =
  Types.{ version = 2l; inputs; outputs; witnesses = []; locktime = 0l }

let conf_a = Types.hash256_of_hex
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
let conf_tip = Types.hash256_of_hex
    "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098"

let with_mempool f =
  rm_rf test_db_path;
  let db = Storage.ChainDB.create test_db_path in
  let utxo = Utxo.UtxoSet.create db in
  (* conf_a: an old confirmed coin, funds the mempool parent. *)
  Utxo.UtxoSet.add utxo conf_a 0
    Utxo.{ value = 1_000_000L; script_pubkey = spk; height = 50; is_coinbase = false };
  (* conf_tip: a coin confirmed in the tip block itself. *)
  Utxo.UtxoSet.add utxo conf_tip 0
    Utxo.{ value = 1_000_000L; script_pubkey = spk; height = tip; is_coinbase = false };
  let mp = Mempool.create ~network:Consensus.regtest ~require_standard:false
      ~verify_scripts:false ~utxo ~current_height:tip () in
  Fun.protect ~finally:(fun () -> Storage.ChainDB.close db; rm_rf test_db_path)
    (fun () -> f mp utxo)

(* Parent P (in the mempool) spends the old confirmed coin. *)
let add_parent mp =
  let p = tx2 [input conf_a 0l] [out 990_000L] in
  (match Mempool.add_transaction mp p with
   | Ok _ -> ()
   | Error e -> Alcotest.failf "parent rejected: %s" e);
  (p, Crypto.compute_txid p)

let is_bip68_reject = function
  | Error e ->
    (* the mempool's BIP68 token (rpc.ml maps it to Core's non-BIP68-final) *)
    let needle = "sequence locks not satisfied" in
    let ls = String.lowercase_ascii e in
    let n = String.length needle and m = String.length ls in
    let rec go i = i + n <= m && (String.sub ls i n = needle || go (i + 1)) in
    go 0
  | Ok _ -> false

let show = function Ok _ -> "accepted" | Error e -> "rejected: " ^ e

(* FAILS on b08ea33: lock 1 on a mempool parent was accepted at tip. *)
let test_lock1_mempool_parent_rejected () =
  with_mempool (fun mp _ ->
    let (_, ptxid) = add_parent mp in
    let child = tx2 [input ~sequence:1l ptxid 0l] [out 980_000L] in
    let r = Mempool.add_transaction mp child in
    Alcotest.(check bool)
      ("relative lock 1 on a mempool parent is non-BIP68-final at tip ("
       ^ show r ^ ")") true (is_bip68_reject r))

(* FAILS on b08ea33: still non-final after the tip advances while the parent
   stays unconfirmed (coin height tracks tip+1). *)
let test_lock2_mempool_parent_after_new_tip () =
  with_mempool (fun mp _ ->
    let (_, ptxid) = add_parent mp in
    Mempool.update_height mp (tip + 1);
    let child = tx2 [input ~sequence:1l ptxid 0l] [out 980_000L] in
    let r = Mempool.add_transaction mp child in
    Alcotest.(check bool)
      ("lock 1 on a still-unconfirmed parent stays non-final after a new tip ("
       ^ show r ^ ")") true (is_bip68_reject r))

(* CONTROL: lock 0 on a mempool parent is final (passes before and after). *)
let test_lock0_mempool_parent_accepted () =
  with_mempool (fun mp _ ->
    let (_, ptxid) = add_parent mp in
    let child = tx2 [input ~sequence:0l ptxid 0l] [out 980_000L] in
    let r = Mempool.add_transaction mp child in
    Alcotest.(check bool) ("lock 0 accepted (" ^ show r ^ ")") true (Result.is_ok r))

(* CONTROL: a coin confirmed IN the tip block — lock 1 is satisfied by the
   next block (tip + 1 >= tip + 1), lock 2 is not. *)
let test_confirmed_at_tip_lock1_accepted () =
  with_mempool (fun mp _ ->
    let child = tx2 [input ~sequence:1l conf_tip 0l] [out 980_000L] in
    let r = Mempool.add_transaction mp child in
    Alcotest.(check bool) ("confirmed-at-tip lock 1 accepted (" ^ show r ^ ")")
      true (Result.is_ok r))

let test_confirmed_at_tip_lock2_rejected () =
  with_mempool (fun mp _ ->
    let child = tx2 [input ~sequence:2l conf_tip 0l] [out 980_000L] in
    let r = Mempool.add_transaction mp child in
    Alcotest.(check bool) ("confirmed-at-tip lock 2 rejected (" ^ show r ^ ")")
      true (is_bip68_reject r))

(* CONTROL: once the parent confirms (block tip+1 carries it), lock 1 is
   satisfied by block tip+2 and the child is accepted. *)
let test_lock1_accepted_once_parent_confirms () =
  with_mempool (fun mp utxo ->
    let (p, ptxid) = add_parent mp in
    (* Confirm P in block tip+1: P's output enters the UTXO set at tip+1,
       P leaves the mempool, the tip advances. *)
    ignore (Utxo.UtxoSet.remove utxo conf_a 0);
    Utxo.UtxoSet.add utxo ptxid 0
      Utxo.{ value = (List.hd p.Types.outputs).Types.value; script_pubkey = spk;
             height = tip + 1; is_coinbase = false };
    Mempool.remove_transaction mp ptxid;
    Mempool.update_height mp (tip + 1);
    let child = tx2 [input ~sequence:1l ptxid 0l] [out 980_000L] in
    let r = Mempool.add_transaction mp child in
    Alcotest.(check bool) ("accepted once the parent is confirmed (" ^ show r ^ ")")
      true (Result.is_ok r))

let () =
  Alcotest.run "bip68_mempool_parent" [
    "bip68-mempool-parent", [
      Alcotest.test_case "lock 1 on mempool parent rejected at tip" `Quick
        test_lock1_mempool_parent_rejected;
      Alcotest.test_case "lock 1 on mempool parent rejected after new tip" `Quick
        test_lock2_mempool_parent_after_new_tip;
      Alcotest.test_case "CONTROL lock 0 on mempool parent accepted" `Quick
        test_lock0_mempool_parent_accepted;
      Alcotest.test_case "CONTROL confirmed-at-tip lock 1 accepted" `Quick
        test_confirmed_at_tip_lock1_accepted;
      Alcotest.test_case "CONTROL confirmed-at-tip lock 2 rejected" `Quick
        test_confirmed_at_tip_lock2_rejected;
      Alcotest.test_case "CONTROL lock 1 accepted once parent confirms" `Quick
        test_lock1_accepted_once_parent_confirms;
    ];
  ]
