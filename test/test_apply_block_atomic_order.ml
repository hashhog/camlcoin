(* Storage.ChainDB.apply_block_atomic must apply [ops] in the SAME order to
   both coin stores.

   Callers (Sync.process_new_block, the gap-fill connect) build [ops] in
   block order, so a coin created and spent inside one block arrives as
   [`Add X; `Del X].  The CF batch applied that order; the Rocksdb_store
   batch got [List.rev_map]'s REVERSED list, [`Del X; `Add X], and kept X.
   Validation reads Rocksdb_store, so X stayed spendable.

   Cases:
     - add-then-del in one call: X absent from BOTH stores, and from
       OptimizedUtxoSet.get (the validation read).
     - del-then-add in one call (a re-created key): present in BOTH, with
       the new bytes -- guards against "fixing" this by dropping keys that
       appear twice.

   NEGATIVE CONTROL: with the old bare [List.rev_map] both cases fail
   (verified by hand 2026-09-30): case 1 "Rocksdb_store dropped X" gets
   [Some _], and case 2 finds the re-created coin DELETED from
   Rocksdb_store.

   Command:
     dune exec --no-buffer test/test_apply_block_atomic_order.exe *)

open Camlcoin

let root_base = "/tmp/camlcoin_test_apply_block_atomic_order"
let case_n = ref 0
let root_ref = ref root_base

let rec rm_rf path =
  if Sys.file_exists path then begin
    if Sys.is_directory path then begin
      Array.iter (fun f -> rm_rf (Filename.concat path f)) (Sys.readdir path);
      Unix.rmdir path
    end else Unix.unlink path
  end

let with_dual f =
  incr case_n;
  root_ref :=
    Test_tmp.register
      (Printf.sprintf "%s_%d_%d" root_base (Unix.getpid ()) !case_n);
  rm_rf !root_ref;
  Unix.mkdir !root_ref 0o755;
  let db = Storage.ChainDB.create (Filename.concat !root_ref "chain") in
  let rdb = Rocksdb_store.open_db (Filename.concat !root_ref "rocksdb") in
  Storage.ChainDB.attach_rocksdb_utxo db rdb;
  Fun.protect
    ~finally:(fun () ->
      Rocksdb_store.close rdb; Storage.ChainDB.close db; rm_rf !root_ref)
    (fun () -> f db rdb)

let txid_of_byte b =
  let buf = Cstruct.create 32 in
  Cstruct.set_uint8 buf 0 b; Cstruct.set_uint8 buf 31 0x77;
  buf

let ser value height : string =
  let spk = Cstruct.of_string "\x00\x14aaaaaaaaaaaaaaaaaaaa" in
  let w = Serialize.writer_create () in
  Utxo.serialize_utxo_entry w
    { Utxo.value; script_pubkey = spk; height; is_coinbase = false };
  Serialize.writer_to_string w

let tip = txid_of_byte 0xee

let apply db ~height ops =
  Storage.ChainDB.apply_block_atomic db ~tip_hash:tip ~tip_height:height
    ~header_tip_hash:tip ~header_tip_height:height ops

let in_rdb rdb txid vout =
  Rocksdb_store.get rdb (Storage.ChainDB.rocksdb_utxo_key txid vout)

let in_cf db txid vout =
  let found = ref None in
  Storage.ChainDB.iter_utxos db (fun t v d ->
    if Cstruct.equal t txid && v = vout then found := Some d);
  !found

let test_add_then_del_same_block () =
  with_dual (fun db rdb ->
    let parent = txid_of_byte 0x11 and other = txid_of_byte 0x22 in
    (* Block 10: parent creates X=(parent,0) and Y=(parent,1); a child in
       the same block spends X.  Block order: Add X, Add Y, Del X. *)
    apply db ~height:10
      [ (parent, 0, `Add (ser 5000L 10));
        (parent, 1, `Add (ser 6000L 10));
        (other, 0, `Add (ser 7000L 10));
        (parent, 0, `Del) ];
    Alcotest.(check (option string)) "CF dropped X" None (in_cf db parent 0);
    Alcotest.(check (option string)) "Rocksdb_store dropped X" None
      (in_rdb rdb parent 0);
    let cache = Utxo.OptimizedUtxoSet.create ~rocksdb:rdb db in
    Alcotest.(check bool) "validation read (OptimizedUtxoSet.get) misses X"
      true (Utxo.OptimizedUtxoSet.get cache parent 0 = None);
    Alcotest.(check bool) "Y kept in Rocksdb_store" true
      (in_rdb rdb parent 1 <> None);
    Alcotest.(check bool) "Y kept in CF" true (in_cf db parent 1 <> None);
    (* The walks gettxoutsetinfo uses agree with the CF: {Y, other:0}. *)
    let n = ref 0 in
    Utxo.iter_committed_utxos (Some cache) db (fun _ _ _ -> incr n);
    Alcotest.(check int) "committed walk = 2 coins" 2 !n)

let test_del_then_add_same_key () =
  with_dual (fun db rdb ->
    let t = txid_of_byte 0x33 in
    apply db ~height:5 [ (t, 0, `Add (ser 1L 5)) ];
    apply db ~height:6 [ (t, 0, `Del); (t, 0, `Add (ser 2L 6)) ];
    Alcotest.(check (option string)) "CF holds the re-created coin"
      (Some (ser 2L 6)) (in_cf db t 0);
    Alcotest.(check (option string)) "Rocksdb_store holds the re-created coin"
      (Some (ser 2L 6)) (in_rdb rdb t 0))

let () =
  Alcotest.run "apply-block-atomic-order" [
    "order", [
      Alcotest.test_case "add then del in one block" `Quick
        test_add_then_del_same_block;
      Alcotest.test_case "del then add same key" `Quick
        test_del_then_add_same_key;
    ];
  ]
