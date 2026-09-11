(* Control: HASH_SERIALIZED must walk vouts in numeric order, not the
   UTXO CF's [txid || vout_le32] cursor order.

   Bitcoin Core (kernel/coinstats.cpp:87-93) groups the coins cursor
   into std::map<uint32_t, Coin>, so vout 1 is hashed before vout 256.
   camlcoin keys are little-endian, so 256 (00 01 00 00) sorts before
   1 (01 00 00 00). That first happens on mainnet between 115,000
   (max vout 98, hash matches Core) and 140,000 (max vout 2001).

   First divergent coin on soak-140000: txid
     41e46057b8f8363c90389ed8d1a3fbb9cddcd769b6f154b2cf44c12a52a88703
   after vout 0 (shared). Core's next coin is vout 1; LE32's is vout 256.

   Command (fails on revert — 140k snapshot hashes to a361c92d…):
     dune exec --no-buffer test/test_hash_serialized_3.exe
*)

open Camlcoin

let core_140k =
  "dc9ded5c1179d6aacc50bb2d5e980ad3ba08722552290ddd8efca4fdc6b4d5df"

let le32_140k =
  "a361c92d4a2472541ae51b6d5b1f3cc93980bda5bf62cf4f212a83b7bb3a5986"

let core_vout256 =
  "1bf5fd3c3e7b4266925b7d85418718358853084202838070cbf1197f0191ce25"

let le32_vout256 =
  "310c957afea7f7f39626929ad4ef0374411083917732563ec2a586d3710de77a"

let rec rm_rf path =
  if Sys.file_exists path then begin
    if Sys.is_directory path then begin
      Array.iter (fun f -> rm_rf (Filename.concat path f)) (Sys.readdir path);
      Unix.rmdir path
    end else
      Unix.unlink path
  end

let snapshot_path () =
  match Sys.getenv_opt "CAMLCOIN_UTXO_140000" with
  | Some p when Sys.file_exists p -> p
  | _ ->
    let p =
      "/home/work/hashhog/tools/boundary-blocks/soak-140000/utxo-140000.dat"
    in
    if Sys.file_exists p then p
    else
      Alcotest.fail
        "140k snapshot not found; set CAMLCOIN_UTXO_140000 to \
         tools/boundary-blocks/soak-140000/utxo-140000.dat"

let put_utxo db ~txid ~vout ~value ~script ~height ~is_coinbase =
  let entry : Utxo.utxo_entry =
    { value; script_pubkey = script; height; is_coinbase }
  in
  let w = Serialize.writer_create () in
  Utxo.serialize_utxo_entry w entry;
  Storage.ChainDB.store_utxo db txid vout
    (Cstruct.to_string (Serialize.writer_to_cstruct w))

let test_vout_256_from_db () =
  let root =
    Printf.sprintf "/tmp/camlcoin_hs3_%d" (Unix.getpid ())
  in
  rm_rf root;
  Unix.mkdir root 0o755;
  let db = Storage.ChainDB.create (Filename.concat root "chain") in
  Fun.protect
    ~finally:(fun () -> Storage.ChainDB.close db; rm_rf root)
    (fun () ->
      let txid = Types.hash256_of_hex (String.make 64 '1') in
      let script = Cstruct.of_string "\x51" in
      put_utxo db ~txid ~vout:1 ~value:1000L ~script
        ~height:100 ~is_coinbase:false;
      put_utxo db ~txid ~vout:256 ~value:1000L ~script
        ~height:100 ~is_coinbase:false;
      let got =
        Types.hash256_to_hex_display
          (Assume_utxo.compute_utxo_hash_from_db db)
      in
      Alcotest.(check bool) "must not be the LE32-order hash" true
        (got <> le32_vout256);
      Alcotest.(check string) "numeric vout HASH_SERIALIZED" core_vout256 got)

let load_snapshot_into_db db path =
  match
    Assume_utxo.read_snapshot_metadata path
      ~expected_network_magic:Consensus.mainnet.magic
  with
  | Error msg -> Alcotest.fail ("snapshot metadata: " ^ msg)
  | Ok meta ->
    let ic = open_in_bin path in
    Fun.protect
      ~finally:(fun () -> close_in_noerr ic)
      (fun () ->
        let sr =
          Assume_utxo.Stream_reader.create ic
            ~start_offset:Assume_utxo.snapshot_body_offset
        in
        let batch = ref (Storage.ChainDB.batch_create ()) in
        let n = ref 0 in
        let flush () =
          Storage.ChainDB.batch_write db !batch;
          batch := Storage.ChainDB.batch_create ()
        in
        match
          Assume_utxo.iter_snapshot_coins sr ~coins_count:meta.coins_count
            ~f:(fun coin ->
              let entry : Utxo.utxo_entry = {
                value = coin.value;
                script_pubkey = coin.script_pubkey;
                height = coin.height;
                is_coinbase = coin.is_coinbase;
              } in
              let w = Serialize.writer_create () in
              Utxo.serialize_utxo_entry w entry;
              Storage.ChainDB.batch_store_utxo !batch
                coin.outpoint.txid
                (Int32.to_int coin.outpoint.vout)
                (Cstruct.to_string (Serialize.writer_to_cstruct w));
              incr n;
              if !n mod 10_000 = 0 then flush ())
        with
        | Error msg -> Alcotest.fail ("iter_snapshot_coins: " ^ msg)
        | Ok count ->
          flush ();
          (count, meta))

let test_140k_snapshot_vs_core () =
  let path = snapshot_path () in
  let root =
    Printf.sprintf "/tmp/camlcoin_hs3_140k_%d" (Unix.getpid ())
  in
  rm_rf root;
  Unix.mkdir root 0o755;
  let db = Storage.ChainDB.create (Filename.concat root "chain") in
  Fun.protect
    ~finally:(fun () -> Storage.ChainDB.close db; rm_rf root)
    (fun () ->
      let count, _meta = load_snapshot_into_db db path in
      Alcotest.(check bool) "loaded coins" true (Int64.compare count 0L > 0);
      let got =
        Types.hash256_to_hex_display
          (Assume_utxo.compute_utxo_hash_from_db db)
      in
      Alcotest.(check bool)
        "must not be the known-wrong LE32 hash a361c92d"
        true (got <> le32_140k);
      Alcotest.(check string)
        "140k HASH_SERIALIZED equals Core dumptxoutset"
        core_140k got)

let () =
  Alcotest.run "hash-serialized-3" [
    "HASH_SERIALIZED", [
      Alcotest.test_case
        "DB vout 1 vs 256 is numeric, not LE32" `Quick
        test_vout_256_from_db;
      Alcotest.test_case
        "140k snapshot hash_serialized_3 equals Core dc9ded5c"
        `Slow test_140k_snapshot_vs_core;
    ];
  ]
