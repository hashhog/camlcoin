(* Control: gettxoutsetinfo immediately after --load-snapshot / --import-utxo
   must report height == the snapshot base (QUEUES.md 2026-09-19).

   Range 419311→450000 on 8f3c441: NO-ORACLE-SURFACE, "no usable height",
   utxo_hash="-1". The runner calls gettxoutsetinfo at the base before any
   window block connects. handle_gettxoutsetinfo walked the committed set
   (39.8M coins) on the Lwt thread and only then emitted height from
   Sync.block_tip. A timeout / empty JSON is parsed as height=-1.

   8f3c441 did not touch the RPC path. It started 31 extra script-check
   domains (par=0); the walk then lost the scan deadline to STW GC + IBD.
   Sibling shape (hotbuns 4534e61 / ouroboros snapshot cache): the load
   already folded HASH_SERIALIZED + totals; gettxoutsetinfo at that tip
   must answer without a second coins-DB walk.

   Command (first case fails if height is 0/missing after load; second
   fails if the answer required a live CF walk):
     dune exec --no-buffer test/test_snapshot_boot_txoutset.exe
*)

open Camlcoin

let base_height = 100
let n_coins = 8

let rec rm_rf path =
  if Sys.file_exists path then begin
    if Sys.is_directory path then begin
      Array.iter (fun f -> rm_rf (Filename.concat path f)) (Sys.readdir path);
      Unix.rmdir path
    end
    else Unix.unlink path
  end

let mk_hash n =
  let cs = Cstruct.create 32 in
  Cstruct.LE.set_uint32 cs 0 (Int32.of_int n);
  cs

let p2pkh tag =
  let script = Cstruct.create 25 in
  Cstruct.set_uint8 script 0 0x76;
  Cstruct.set_uint8 script 1 0xa9;
  Cstruct.set_uint8 script 2 0x14;
  Cstruct.set_uint8 script 3 tag;
  Cstruct.set_uint8 script 23 0x88;
  Cstruct.set_uint8 script 24 0xac;
  script

let write_synthetic_snapshot path n base_hash =
  let metadata : Assume_utxo.snapshot_metadata =
    {
      network_magic = Consensus.regtest.magic;
      base_blockhash = base_hash;
      coins_count = Int64.of_int n;
    }
  in
  let script = p2pkh 0x42 in
  match
    Assume_utxo.write_snapshot path metadata ~iter_coins:(fun emit ->
        for i = 0 to n - 1 do
          emit
            {
              Assume_utxo.outpoint = { Types.txid = mk_hash (i + 1); vout = 0l };
              value = Int64.of_int ((i + 1) * 1000);
              script_pubkey = script;
              height = 1;
              is_coinbase = false;
            }
        done)
  with
  | Ok () -> ()
  | Error msg -> Alcotest.fail ("write_snapshot: " ^ msg)

let rpc_setinfo ctx =
  match Rpc.handle_gettxoutsetinfo ctx [`String "hash_serialized_3"] with
  | Error msg -> Alcotest.fail ("gettxoutsetinfo: " ^ msg)
  | Ok (`Assoc fields) -> fields
  | Ok json ->
    Alcotest.fail
      ("gettxoutsetinfo: expected object, got "
       ^ Yojson.Safe.to_string json)

let field_int fields name =
  match List.assoc_opt name fields with
  | Some (`Int n) -> n
  | Some (`Intlit s) ->
    Alcotest.fail
      (Printf.sprintf
         "field %s is Intlit %s (runner regex ^[0-9]+$ rejects this shape)"
         name s)
  | Some (`Float f) ->
    Alcotest.fail
      (Printf.sprintf
         "field %s is Float %g (runner prints %g, regex rejects it)"
         name f f)
  | Some other ->
    Alcotest.fail
      (Printf.sprintf "field %s has unusable JSON type %s" name
         (Yojson.Safe.to_string other))
  | None -> Alcotest.fail ("missing field " ^ name)

let field_string fields name =
  match List.assoc_opt name fields with
  | Some (`String s) -> s
  | _ -> Alcotest.fail ("missing string field " ^ name)

let make_ctx db ~height =
  let legacy = Utxo.UtxoSet.create db in
  let mp =
    Mempool.create ~network:Consensus.regtest ~require_standard:false
      ~verify_scripts:false ~utxo:legacy ~current_height:height ()
  in
  let chain = Sync.restore_chain_state db Consensus.regtest in
  let pm = Peer_manager.create Consensus.regtest in
  let fe = Fee_estimation.create () in
  Rpc.create_context ~chain ~mempool:mp ~peer_manager:pm ~wallet:None
    ~fee_estimator:fe ~network:Consensus.regtest ~utxo:None ()

let wipe_cf_utxos db =
  let keys = ref [] in
  Storage.ChainDB.iter_utxos db (fun txid vout _ ->
      keys := (txid, vout) :: !keys);
  List.iter (fun (txid, vout) -> Storage.ChainDB.delete_utxo db txid vout) !keys;
  let left = ref 0 in
  Storage.ChainDB.iter_utxos db (fun _ _ _ -> incr left);
  Alcotest.(check int) "CF is empty after wipe" 0 !left

let with_loaded_snapshot f =
  let root =
    Printf.sprintf "/tmp/camlcoin_snap_txoutset_%d" (Unix.getpid ())
  in
  rm_rf root;
  Unix.mkdir root 0o755;
  let snap = Filename.concat root "snap.dat" in
  let base_hash = mk_hash 0x11 in
  write_synthetic_snapshot snap n_coins base_hash;
  Assume_utxo.clear_regtest_assumeutxo ();
  Assume_utxo.register_regtest_assumeutxo
    {
      Assume_utxo.height = base_height;
      blockhash = base_hash;
      coins_count = Int64.of_int n_coins;
      coins_hash = Cstruct.create 32;
      chain_tx_count = Int64.of_int (base_height + 1);
      base_header = None;
      base_tail_headers = [];
      chainwork = None;
      base_mtp = None;
    };
  let db = Storage.ChainDB.create (Filename.concat root "chain") in
  let rocksdb =
    Rocksdb_store.open_db (Filename.concat root "rocksdb_utxo")
  in
  Fun.protect
    ~finally:(fun () ->
      Rocksdb_store.close rocksdb;
      Storage.ChainDB.close db;
      Assume_utxo.clear_cached_txoutset ();
      Assume_utxo.clear_regtest_assumeutxo ();
      rm_rf root)
    (fun () ->
      (match
         Assume_utxo.load_snapshot_into_primary ~network:Consensus.regtest
           ~snapshot_path:snap ~db ~rocksdb ()
       with
       | Error msg -> Alcotest.fail ("load_snapshot_into_primary: " ^ msg)
       | Ok r ->
         Alcotest.(check int) "loaded base height" base_height r.base_height;
         Alcotest.(check int64)
           "loaded coin count" (Int64.of_int n_coins) r.coins_loaded);
      f db base_hash)

(* After --import-utxo the runner's first RPC is gettxoutsetinfo. Height
   must be the snapshot base, as a JSON integer the runner's
   ^[0-9]+$ regex accepts, and hash_serialized_3 must be present. *)
let test_height_equals_base_immediately_after_load () =
  with_loaded_snapshot (fun db base_hash ->
      let ctx = make_ctx db ~height:base_height in
      let fields = rpc_setinfo ctx in
      let height = field_int fields "height" in
      Printf.printf "gettxoutsetinfo height=%d (want %d)\n%!" height base_height;
      Alcotest.(check int)
        "gettxoutsetinfo.height equals the snapshot base" base_height height;
      Alcotest.(check string) "bestblock is the snapshot base hash"
        (Types.hash256_to_hex_display base_hash)
        (field_string fields "bestblock");
      let digest = field_string fields "hash_serialized_3" in
      Alcotest.(check int) "hash_serialized_3 is 64 hex chars" 64
        (String.length digest);
      Alcotest.(check int) "txouts is the loaded set" n_coins
        (field_int fields "txouts"))

(* Negative: after load, the coins CF is emptied. A live walk would
   report txouts=0 and a different hash. The snapshot-base cache must
   still return height==base and the load-time HASH_SERIALIZED. *)
let test_cache_survives_wiped_coins_db () =
  with_loaded_snapshot (fun db base_hash ->
      let ctx = make_ctx db ~height:base_height in
      let before = rpc_setinfo ctx in
      let height_before = field_int before "height" in
      let hash_before = field_string before "hash_serialized_3" in
      Alcotest.(check int) "pre-wipe height is the base" base_height
        height_before;
      wipe_cf_utxos db;
      let after = rpc_setinfo ctx in
      Alcotest.(check int)
        "wiped CF still reports snapshot-base height" base_height
        (field_int after "height");
      Alcotest.(check string)
        "wiped CF still reports load-time hash_serialized_3" hash_before
        (field_string after "hash_serialized_3");
      Alcotest.(check int) "wiped CF still reports loaded txouts" n_coins
        (field_int after "txouts");
      Alcotest.(check string) "bestblock still the snapshot base"
        (Types.hash256_to_hex_display base_hash)
        (field_string after "bestblock"))

let () =
  Alcotest.run "snapshot-boot-txoutset"
    [
      ( "gettxoutsetinfo",
        [
          Alcotest.test_case
            "height equals base immediately after load_snapshot_into_primary"
            `Quick test_height_equals_base_immediately_after_load;
          Alcotest.test_case
            "snapshot-base cache does not walk the coins CF" `Quick
            test_cache_survives_wiped_coins_db;
        ] );
    ]
