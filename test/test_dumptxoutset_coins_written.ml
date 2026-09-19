(* Control: dumptxoutset.coins_written must equal gettxoutsetinfo.txouts.

   2026-09-19 genesis-link attestation at height 6299: gettxoutsetinfo
   reported txouts=6028 and hash_serialized_3 equal to Core's ladder
   value, while dumptxoutset wrote 5735 coins (deterministic). The dump
   walked ChainDB.iter_utxos (last flushed CF). The connected coins sit
   in OptimizedUtxoSet.dirty until Sync.utxo_flush_interval=500, so a
   dump mid-window loses the unflushed class — 293 coins, 4.9% of the
   set. gettxoutsetinfo already overlays dirty (c48ff9b); dumptxoutset
   did not.

   Core ForceFlushStateToDisk then cursors CoinsDB
   (rpc/blockchain.cpp PrepareUTXOSnapshot). camlcoin cannot flush from
   a read-only RPC (two RocksDB instances; SECREV-CAMLCOIN-CRASH). Walk
   the same committed overlay gettxoutsetinfo hashes, and do not write.

   Revert of the overlay walk makes dirty-only coins_written=0 (txouts=1)
   and the net-plus case coins_written=2 (txouts=3).

   Command:
     dune exec --no-buffer test/test_dumptxoutset_coins_written.exe
*)

open Camlcoin

let p2pkh tag =
  let script = Cstruct.create 25 in
  Cstruct.set_uint8 script 0 0x76;
  Cstruct.set_uint8 script 1 0xa9;
  Cstruct.set_uint8 script 2 0x14;
  Cstruct.set_uint8 script 3 tag;
  Cstruct.set_uint8 script 23 0x88;
  Cstruct.set_uint8 script 24 0xac;
  script

let entry ~tag ~value ~height : Utxo.utxo_entry =
  { value; script_pubkey = p2pkh tag; height; is_coinbase = false }

let txid_of_byte b =
  let buf = Cstruct.create 32 in
  Cstruct.set_uint8 buf 0 b;
  buf

let txid_a = txid_of_byte 0x00
let txid_b = txid_of_byte 0x80
let txid_c = txid_of_byte 0xff
let txid_d = txid_of_byte 0xc0

let snapshot_disk db =
  let acc = ref [] in
  Storage.ChainDB.iter_utxos db (fun txid vout data ->
    acc := (Types.hash256_to_hex txid, vout, data) :: !acc);
  List.sort compare !acc

let make_ctx db ~utxo =
  let legacy = Utxo.UtxoSet.create db in
  let mp =
    Mempool.create ~network:Consensus.regtest ~require_standard:false
      ~verify_scripts:false ~utxo:legacy ~current_height:100 ()
  in
  let chain = Sync.create_chain_state db Consensus.mainnet in
  let pm = Peer_manager.create Consensus.mainnet in
  let fe = Fee_estimation.create () in
  Rpc.create_context ~chain ~mempool:mp ~peer_manager:pm ~wallet:None
    ~fee_estimator:fe ~network:Consensus.mainnet ~utxo ()

let rpc_setinfo ctx =
  match Rpc.handle_gettxoutsetinfo ctx [`String "hash_serialized_3"] with
  | Error msg -> Alcotest.fail ("gettxoutsetinfo: " ^ msg)
  | Ok (`Assoc fields) -> fields
  | Ok _ -> Alcotest.fail "gettxoutsetinfo: expected object"

let field_string fields name =
  match List.assoc_opt name fields with
  | Some (`String s) -> s
  | _ -> Alcotest.fail ("missing string field " ^ name)

let field_int fields name =
  match List.assoc_opt name fields with
  | Some (`Int n) -> n
  | _ -> Alcotest.fail ("missing int field " ^ name)

let dump_fields ctx path =
  (try Sys.remove path with _ -> ());
  match Rpc.handle_dumptxoutset ctx [`String path] with
  | Error msg -> Alcotest.fail ("dumptxoutset: " ^ msg)
  | Ok (`Assoc fields) -> fields
  | Ok _ -> Alcotest.fail "dumptxoutset: expected object"

let file_coins_count path =
  match
    Assume_utxo.read_snapshot_metadata path
      ~expected_network_magic:Consensus.mainnet.magic
  with
  | Error msg -> Alcotest.fail ("dump metadata: " ^ msg)
  | Ok meta -> Int64.to_int meta.Assume_utxo.coins_count

let file_body_coins path =
  match
    Assume_utxo.read_snapshot_metadata path
      ~expected_network_magic:Consensus.mainnet.magic
  with
  | Error msg -> Alcotest.fail ("dump metadata: " ^ msg)
  | Ok meta ->
    let ic = open_in_bin path in
    Fun.protect
      ~finally:(fun () -> close_in_noerr ic)
      (fun () ->
        let sr =
          Assume_utxo.Stream_reader.create ic
            ~start_offset:Assume_utxo.snapshot_body_offset
        in
        let n = ref 0 in
        match
          Assume_utxo.iter_snapshot_coins sr
            ~coins_count:meta.Assume_utxo.coins_count
            ~f:(fun _ -> incr n)
        with
        | Error msg -> Alcotest.fail ("dump body: " ^ msg)
        | Ok _ -> !n)

let with_db name f =
  Test_tmp.with_dir ~label:name ~mkdir:true (fun root ->
    let path = Filename.concat root "chain" in
    Unix.mkdir path 0o755;
    let db = Storage.ChainDB.create path in
    Fun.protect
      ~finally:(fun () -> Storage.ChainDB.close db)
      (fun () -> f db root))

(* Empty CF, one coin only in dirty. Disk-only dump writes 0; the
   committed set has 1. This is the first flush window after a snapshot
   or genesis, and the class that lost 293 coins at height 6299. *)
let test_dirty_only_coins_written_equals_txouts () =
  with_db "dirty-only" (fun db root ->
    let cache = Utxo.OptimizedUtxoSet.create db in
    Utxo.OptimizedUtxoSet.add cache txid_b 0
      (entry ~tag:9 ~value:50_000_000L ~height:1);
    let ctx = make_ctx db ~utxo:(Some cache) in
    let info = rpc_setinfo ctx in
    let txouts = field_int info "txouts" in
    let dump_path = Filename.concat root "utxo.dat" in
    let dump = dump_fields ctx dump_path in
    let written = field_int dump "coins_written" in
    let hdr = file_coins_count dump_path in
    let body = file_body_coins dump_path in
    Printf.printf
      "dirty-only: txouts=%d coins_written=%d file_hdr=%d file_body=%d\n%!"
      txouts written hdr body;
    Alcotest.(check int) "gettxoutsetinfo.txouts" 1 txouts;
    Alcotest.(check int) "dumptxoutset.coins_written == txouts" txouts written;
    Alcotest.(check int) "snapshot header coins_count == txouts" txouts hdr;
    Alcotest.(check int) "snapshot body coin count == txouts" txouts body;
    Alcotest.(check bool) "dump did not persist dirty onto the CF"
      true (snapshot_disk db = []);
    Alcotest.(check int) "dirty still unflushed"
      1 (Utxo.OptimizedUtxoSet.dirty_count cache))

(* CF holds {A,C}; dirty spends A and creates B,D. Committed set is
   {B,C,D}=3; disk-only walk is {A,C}=2. Count AND membership both
   change, so a dump that happens to write 2 coins of the wrong set
   still fails. *)
let test_overlay_net_plus_coins_written_equals_txouts () =
  with_db "overlay" (fun db root ->
    let cache = Utxo.OptimizedUtxoSet.create db in
    Utxo.OptimizedUtxoSet.add cache txid_a 0
      (entry ~tag:1 ~value:1_000_000L ~height:10);
    Utxo.OptimizedUtxoSet.add cache txid_c 0
      (entry ~tag:3 ~value:3_000_000L ~height:10);
    Utxo.OptimizedUtxoSet.flush cache;
    Utxo.OptimizedUtxoSet.add cache txid_b 0
      (entry ~tag:2 ~value:2_000_000L ~height:11);
    Utxo.OptimizedUtxoSet.add cache txid_d 0
      (entry ~tag:4 ~value:4_000_000L ~height:11);
    ignore (Utxo.OptimizedUtxoSet.remove cache txid_a 0);
    let dirty_before = Utxo.OptimizedUtxoSet.dirty_count cache in
    let disk_before = snapshot_disk db in
    let ctx = make_ctx db ~utxo:(Some cache) in
    let info = rpc_setinfo ctx in
    let txouts = field_int info "txouts" in
    let dump_path = Filename.concat root "utxo.dat" in
    let dump = dump_fields ctx dump_path in
    let written = field_int dump "coins_written" in
    let hdr = file_coins_count dump_path in
    let body = file_body_coins dump_path in
    Printf.printf
      "overlay: txouts=%d coins_written=%d file_hdr=%d file_body=%d dirty=%d\n%!"
      txouts written hdr body dirty_before;
    Alcotest.(check int) "committed txouts = {B,C,D}" 3 txouts;
    Alcotest.(check int) "dumptxoutset.coins_written == txouts" txouts written;
    Alcotest.(check int) "snapshot header coins_count == txouts" txouts hdr;
    Alcotest.(check int) "snapshot body coin count == txouts" txouts body;
    Alcotest.(check int) "dump did not drain dirty"
      dirty_before (Utxo.OptimizedUtxoSet.dirty_count cache);
    Alcotest.(check bool) "dump did not persist the overlay onto the CF"
      true (disk_before = snapshot_disk db))

(* Flushed tip: overlay is identity. Dump must still match. *)
let test_flushed_dump_matches_txouts () =
  with_db "flushed" (fun db root ->
    let cache = Utxo.OptimizedUtxoSet.create db in
    Utxo.OptimizedUtxoSet.add cache txid_a 0
      (entry ~tag:1 ~value:1L ~height:4);
    Utxo.OptimizedUtxoSet.add cache txid_c 0
      (entry ~tag:3 ~value:3L ~height:4);
    Utxo.OptimizedUtxoSet.flush cache;
    let ctx = make_ctx db ~utxo:(Some cache) in
    let info = rpc_setinfo ctx in
    let txouts = field_int info "txouts" in
    let dump_path = Filename.concat root "utxo.dat" in
    let dump = dump_fields ctx dump_path in
    let written = field_int dump "coins_written" in
    Printf.printf "flushed: txouts=%d coins_written=%d\n%!" txouts written;
    Alcotest.(check int) "txouts" 2 txouts;
    Alcotest.(check int) "dumptxoutset.coins_written == txouts" txouts written;
    Alcotest.(check int) "file header" txouts (file_coins_count dump_path))

(* Core dumptxoutset.txoutset_hash is HASH_SERIALIZED of the dumped set
   (PrepareUTXOSnapshot GetUTXOStats HASH_SERIALIZED), the same value
   gettxoutsetinfo hash_serialized_3 returns. Three impls used three
   conventions for this field; camlcoin previously emitted MuHash of the
   post-restore CF. *)
let test_txoutset_hash_is_hash_serialized_3 () =
  with_db "hash" (fun db root ->
    let cache = Utxo.OptimizedUtxoSet.create db in
    Utxo.OptimizedUtxoSet.add cache txid_a 0
      (entry ~tag:1 ~value:1_000_000L ~height:10);
    Utxo.OptimizedUtxoSet.flush cache;
    Utxo.OptimizedUtxoSet.add cache txid_b 0
      (entry ~tag:2 ~value:2_000_000L ~height:11);
    ignore (Utxo.OptimizedUtxoSet.remove cache txid_a 0);
    let ctx = make_ctx db ~utxo:(Some cache) in
    let info = rpc_setinfo ctx in
    let dump_path = Filename.concat root "utxo.dat" in
    let dump = dump_fields ctx dump_path in
    let want = field_string info "hash_serialized_3" in
    let got = field_string dump "txoutset_hash" in
    Printf.printf "txoutset_hash dump=%s setinfo=%s\n%!" got want;
    Alcotest.(check int) "coins_written == txouts"
      (field_int info "txouts") (field_int dump "coins_written");
    Alcotest.(check string)
      "dumptxoutset.txoutset_hash == gettxoutsetinfo.hash_serialized_3"
      want got)

let () =
  Alcotest.run "dumptxoutset-coins-written" [
    "dump", [
      Alcotest.test_case
        "dirty-only: coins_written == txouts, file matches, no write" `Quick
        test_dirty_only_coins_written_equals_txouts;
      Alcotest.test_case
        "overlay net-plus: coins_written == txouts (not the stale CF count)"
        `Quick test_overlay_net_plus_coins_written_equals_txouts;
      Alcotest.test_case
        "flushed tip: coins_written == txouts" `Quick
        test_flushed_dump_matches_txouts;
      Alcotest.test_case
        "txoutset_hash is HASH_SERIALIZED of the dumped set" `Quick
        test_txoutset_hash_is_hash_serialized_3;
    ];
  ]
