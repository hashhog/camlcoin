(* Control: snapshot-boot header pointer must sit on the assumeUTXO base,
   not genesis.

   After `--import-utxo` / campaign load at rung 825,000, restore_chain_state
   re-anchored headers_synced to 0 because the UTXO snapshot carries no
   header bytes and campaign_entry_of_json ignored base_header /
   base_tail_headers. getblockchaininfo.headers stayed 0 against a serving
   --connect peer (tools/range-artifacts/camlcoin/825000-852000.json).
   rustoshi and ouroboros passed the same base by persisting the fixture
   band. Hotbuns 52e0ba95 is the same stitch.

   Command (fails if persist_assumeutxo_base_headers is a no-op):
     dune exec --no-buffer test/test_snapshot_header_boot.exe
*)

open Camlcoin

let test_db_base = "/tmp/camlcoin_test_snapshot_header_boot"
let test_db_path = ref test_db_base

let rec rm_rf path =
  if Sys.file_exists path then begin
    if Sys.is_directory path then begin
      Array.iter (fun f -> rm_rf (Filename.concat path f)) (Sys.readdir path);
      Unix.rmdir path
    end else
      Unix.unlink path
  end

let cleanup_test_db () = rm_rf !test_db_path

let use_db name =
  test_db_path := test_db_base ^ "_" ^ name;
  cleanup_test_db ()

let make_header ~prev_block ~ts ~nc =
  Types.{
    version = 1l;
    prev_block;
    merkle_root = Types.zero_hash;
    timestamp = ts;
    bits = 0x207fffffl;
    nonce = nc;
  }

let header_to_hex hdr =
  let w = Serialize.writer_create () in
  Serialize.serialize_block_header w hdr;
  let raw = Serialize.writer_to_cstruct w in
  let buf = Buffer.create 160 in
  for i = 0 to Cstruct.length raw - 1 do
    Buffer.add_string buf (Printf.sprintf "%02x" (Cstruct.get_uint8 raw i))
  done;
  Buffer.contents buf

let dummy_hash_display = String.make 64 'a'

(* Three linked headers at heights 8, 9, 10 — the campaign tail band,
   last element IS the snapshot base. *)
let build_tail_band () =
  let h8 = make_header ~prev_block:(Cstruct.create 32)
      ~ts:1_600_000_000l ~nc:8l in
  let hash8 = Crypto.compute_block_hash h8 in
  let h9 = make_header ~prev_block:hash8
      ~ts:1_600_000_600l ~nc:9l in
  let hash9 = Crypto.compute_block_hash h9 in
  let h10 = make_header ~prev_block:hash9
      ~ts:1_600_001_200l ~nc:10l in
  let hash10 = Crypto.compute_block_hash h10 in
  ([h8; h9; h10], hash10)

let campaign_json ~height ~blockhash_display ~base_header_hex
    ~tail_hexes ~chainwork_hex =
  let tails =
    String.concat ", "
      (List.map (fun h -> Printf.sprintf {|"%s"|} h) tail_hexes)
  in
  Printf.sprintf
    {|{"height": %d, "blockhash": "%s", "hash_serialized": "%s", "m_chain_tx_count": %d, "base_mtp": 1600000000, "base_header": "%s", "chainwork": "%s", "base_tail_headers": [%s]}|}
    height blockhash_display dummy_hash_display (height + 1)
    base_header_hex chainwork_hex tails

let chainwork_hex =
  "00000000000000000000000000000000000000000000000000000000000000ff"

(* The 825k stall: header_tip at the base, genesis only, no header bytes.
   restore re-anchors headers_synced to 0. Negative control — the instrument
   must still see this. *)
let test_bare_snapshot_still_reanchors () =
  use_db "bare";
  let db = Storage.ChainDB.create !test_db_path in
  let _state = Sync.create_chain_state db Consensus.regtest in
  let base_hash = Cstruct.create 32 in
  Cstruct.memset base_hash 0xBB;
  Storage.ChainDB.set_header_tip db base_hash 10;
  Storage.ChainDB.set_chain_tip db base_hash 10;
  Storage.ChainDB.set_height_hash db 10 base_hash;
  Storage.ChainDB.close db;
  let db = Storage.ChainDB.create !test_db_path in
  let state = Sync.restore_chain_state db Consensus.regtest in
  (match state.Sync.tip with
   | Some t ->
     Alcotest.(check int) "bare snapshot re-anchors to genesis" 0 t.Sync.height
   | None -> Alcotest.fail "bare snapshot restore left no tip");
  Alcotest.(check int) "headers_synced rewound to 0 (the 825k stall)"
    0 state.Sync.headers_synced;
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Production path: campaign JSON → persist → loader tip pointers → restore.
   headers_synced must be the base, locator must start at the base hash. *)
let test_fixture_headers_leave_pointer_at_base () =
  use_db "fixture";
  let tails, base_hash = build_tail_band () in
  let base_header = List.nth tails 2 in
  let blockhash_display = Types.hash256_to_hex_display base_hash in
  let tail_hexes = List.map header_to_hex tails in
  let json =
    campaign_json ~height:10 ~blockhash_display
      ~base_header_hex:(header_to_hex base_header)
      ~tail_hexes ~chainwork_hex
  in
  let params =
    match Assume_utxo.campaign_entry_of_json (Yojson.Safe.from_string json) with
    | Error e -> Alcotest.fail ("campaign_entry_of_json: " ^ e)
    | Ok p -> p
  in
  Alcotest.(check int) "parsed height" 10 params.Assume_utxo.height;
  Alcotest.(check bool) "parsed base_header" true
    (match params.Assume_utxo.base_header with Some _ -> true | None -> false);
  Alcotest.(check int) "parsed 3 tail headers"
    3 (List.length params.Assume_utxo.base_tail_headers);
  Alcotest.(check bool) "parsed chainwork" true
    (match params.Assume_utxo.chainwork with Some _ -> true | None -> false);

  let db = Storage.ChainDB.create !test_db_path in
  let _state = Sync.create_chain_state db Consensus.regtest in
  let n = Assume_utxo.persist_assumeutxo_base_headers db params in
  Alcotest.(check int) "persist wrote 3 headers" 3 n;
  Storage.ChainDB.set_header_tip db base_hash 10;
  Storage.ChainDB.set_chain_tip db base_hash 10;
  Storage.ChainDB.close db;

  let db = Storage.ChainDB.create !test_db_path in
  let state = Sync.restore_chain_state db Consensus.regtest in
  (match state.Sync.tip with
   | None -> Alcotest.fail "restore left state.tip = None (re-anchored)"
   | Some t ->
     Alcotest.(check int) "tip height is the snapshot base" 10 t.Sync.height;
     Alcotest.(check bool) "tip hash is the snapshot base" true
       (Cstruct.equal t.Sync.hash base_hash);
     Alcotest.(check bool) "fixture chainwork pinned on the tip" true
       (Cstruct.equal t.Sync.total_work (Consensus.work_of_hex chainwork_hex)));
  Alcotest.(check int) "headers_synced is the base, not 0"
    10 state.Sync.headers_synced;
  Alcotest.(check int) "blocks_synced preserved at the snapshot base"
    10 state.Sync.blocks_synced;
  (match Sync.build_locator state with
   | [] -> Alcotest.fail "empty locator"
   | head :: _ ->
     Alcotest.(check bool)
       "getheaders locator anchors at the snapshot base, not genesis" true
       (Cstruct.equal head base_hash));
  (match Sync.best_header_at_height state 0 with
   | None -> Alcotest.fail "genesis missing after snapshot-boot"
   | Some e -> Alcotest.(check int) "genesis stays at height 0" 0 e.Sync.height);
  (match Sync.best_header_at_height state 8,
         Sync.best_header_at_height state 10 with
   | Some lo, Some hi ->
     Alcotest.(check bool) "tail band is in the in-memory header table" true
       (lo.Sync.height = 8 && hi.Sync.height = 10)
   | _ -> Alcotest.fail "tail band missing from in-memory headers");
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* Loader must actually call persist. A persist that only the test invokes
   would leave --import-utxo stalled. *)
let test_loader_calls_persist () =
  let rec read = function
    | [] -> Alcotest.fail "assume_utxo.ml not found for source scan"
    | p :: rest ->
      if Sys.file_exists p then begin
        let ic = open_in p in
        let s = really_input_string ic (in_channel_length ic) in
        close_in ic; s
      end else read rest
  in
  let src = read [
    "assume_utxo.ml";
    "lib/assume_utxo.ml";
    "../lib/assume_utxo.ml";
  ] in
  let has needle =
    let rec go i =
      if i + String.length needle > String.length src then false
      else if String.sub src i (String.length needle) = needle then true
      else go (i + 1)
    in
    go 0
  in
  Alcotest.(check bool)
    "load_snapshot_into_primary calls persist_assumeutxo_base_headers"
    true (has "persist_assumeutxo_base_headers db params")

let () =
  Alcotest.run "snapshot_header_boot" [
    "825k stall", [
      Alcotest.test_case
        "bare snapshot (no fixture headers) still re-anchors to 0"
        `Quick test_bare_snapshot_still_reanchors;
      Alcotest.test_case
        "campaign fixture headers leave the pointer on the base, not 0"
        `Quick test_fixture_headers_leave_pointer_at_base;
      Alcotest.test_case
        "load_snapshot_into_primary calls persist_assumeutxo_base_headers"
        `Quick test_loader_calls_persist;
    ];
  ]
