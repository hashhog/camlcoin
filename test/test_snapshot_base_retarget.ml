(* Snapshot-base retarget wedge (live mainnet 2026-10-03, block 969696).

   A datadir bootstrapped from a Core dumptxoutset (base 969183) has
   height->hash rows only for genesis and [base, tip]: the from-genesis
   header sync that follows the import stores every pre-base header's BYTES
   but no index row.  After a restart, restore_chain_state reloaded only the
   indexed heights, so the (0, base) band vanished from the in-memory header
   table.  At the first retarget after the base, compute_expected_bits could
   not resolve the period-first ancestor (967680), substituted
   (timestamp 0, pow_limit), and every honest copy of 969696 was rejected
   "block does not meet difficulty target" (BlockBadDifficulty).

   This test builds the same on-disk shape with mainnet parameters (retarget
   interval 2016): genesis + fabricated headers 1..4031, index rows ONLY for
   0 and [3000, 4031] (snapshot base 3000), chain_tip = header_tip = 4031.
   Then the block at 4032 is a retarget whose period-first ancestor (2016) is
   below the base.

   Pre-fix (master): the restored table lacks height 2016, compute_expected_bits
   returns a placeholder-derived value != the consensus bits, i.e. validation
   rejects the honest block with BlockBadDifficulty.
   Post-fix: restore heals the index from the stored headers, the expected
   bits equal the independently computed consensus value, MTP below the base
   resolves, and with the pre-base header bytes genuinely ABSENT the resolver
   fails closed (ancestry-incomplete) instead of returning a placeholder. *)

open Camlcoin

let test_db_base = Test_tmp.register "/tmp/camlcoin_test_snapshot_base_retarget"
let test_db_path = ref test_db_base

let rec rm_rf path =
  if Sys.file_exists path then begin
    if Sys.is_directory path then begin
      Array.iter (fun f -> rm_rf (Filename.concat path f)) (Sys.readdir path);
      Unix.rmdir path
    end else Unix.unlink path
  end

let use_db name =
  test_db_path := test_db_base ^ "_" ^ name;
  Test_tmp.register !test_db_path |> ignore;
  rm_rf !test_db_path

let net = Consensus.mainnet
let tip_height = 4031
let base_height = 3000
let bits0 = 0x1d00ffffl
(* 300 s spacing: twice as fast as target, so the retarget at 4032 must
   HARDEN the target (a value distinct from pow_limit and from bits0). *)
let ts_of h = Int32.of_int (1_300_000_000 + (h * 300))

let make_header ~prev_block ~h =
  Types.{ version = 4l; prev_block; merkle_root = Types.zero_hash;
          timestamp = ts_of h; bits = bits0; nonce = Int32.of_int h }

(* Build the snapshot-swap datadir.  [with_prebase_bytes = false] models a
   node whose header sync never reached the base: the pre-base header bytes
   are genuinely absent. *)
let build ~name ~with_prebase_bytes =
  use_db name;
  let db = Storage.ChainDB.create !test_db_path in
  let _ = Sync.create_chain_state db net in
  let genesis_hash = Crypto.compute_block_hash net.genesis_header in
  let hashes = Array.make (tip_height + 1) genesis_hash in
  let headers = Array.make (tip_height + 1) net.genesis_header in
  let prev = ref genesis_hash in
  for h = 1 to tip_height do
    let hdr = make_header ~prev_block:!prev ~h in
    let hash = Crypto.compute_block_hash hdr in
    if with_prebase_bytes || h >= base_height then
      Storage.ChainDB.store_block_header db hash hdr;
    (* Index rows: genesis + [base, tip] only — exactly the live shape. *)
    if h >= base_height then Storage.ChainDB.set_height_hash db h hash;
    hashes.(h) <- hash; headers.(h) <- hdr;
    prev := hash
  done;
  Storage.ChainDB.set_header_tip db hashes.(tip_height) tip_height;
  Storage.ChainDB.set_chain_tip db hashes.(tip_height) tip_height;
  Storage.ChainDB.close db;
  hashes, headers

(* Independent consensus oracle: GetNextWorkRequired fed straight from the
   fabricated arrays, no chain state involved. *)
let oracle_bits (headers : Types.block_header array) (next : Types.block_header) =
  Consensus.get_next_work_required ~height:(tip_height + 1)
    ~block_time:next.timestamp
    ~prev_block_time:headers.(tip_height).timestamp
    ~prev_bits:headers.(tip_height).bits
    ~get_block_info:(fun h -> (headers.(h).timestamp, headers.(h).bits))
    ~network:net

let next_header hashes =
  make_header ~prev_block:hashes.(tip_height) ~h:(tip_height + 1)

(* Real mainnet anchor (OBSERVED via RPC 2026-10-03): 969696's required bits
   from 967680's time, 969695's time and bits. *)
let test_mainnet_969696_anchor () =
  let first_ts = 1789801745l and last_ts = 1791011720l in
  let bits =
    Consensus.get_next_work_required ~height:969696
      ~block_time:1791011796l ~prev_block_time:last_ts ~prev_bits:0x17021ec5l
      ~get_block_info:(fun h ->
          if h = 967680 then (first_ts, 0x17021ec5l) else (0l, net.pow_limit))
      ~network:net
  in
  Alcotest.(check int32) "969696 requires 0x17021ef0" 0x17021ef0l bits;
  (* The failure mode: first-block timestamp 0 (the placeholder). *)
  let bad =
    Consensus.get_next_work_required ~height:969696
      ~block_time:1791011796l ~prev_block_time:last_ts ~prev_bits:0x17021ec5l
      ~get_block_info:(fun _ -> (0l, net.pow_limit)) ~network:net
  in
  Alcotest.(check bool) "placeholder ancestry gives a different value" true
    (bad <> 0x17021ef0l)

let test_restore_then_retarget () =
  let hashes, headers = build ~name:"heal" ~with_prebase_bytes:true in
  let next = next_header hashes in
  let want = oracle_bits headers next in
  Alcotest.(check bool) "oracle retarget differs from bits0" true (want <> bits0);
  let db = Storage.ChainDB.create !test_db_path in
  let state = Sync.restore_chain_state db net in
  let parent = match Sync.get_header state hashes.(tip_height) with
    | Some p -> p | None -> Alcotest.fail "tip missing" in
  let got = Sync.compute_expected_bits ~parent_entry:parent state (tip_height + 1) next in
  Alcotest.(check int32) "expected_bits == consensus (no BlockBadDifficulty)" want got;
  (* The period-first ancestor (2016) is below the base. *)
  (match Sync.get_header state hashes.(2016) with
   | Some e -> Alcotest.(check int) "pre-base header has its real height" 2016 e.Sync.height
   | None -> Alcotest.fail "pre-base header 2016 missing from the restored table");
  (match Sync.resolve_expected_bits state (tip_height + 1) next with
   | Ok b -> Alcotest.(check int32) "resolve_expected_bits == consensus" want b
   | Error e -> Alcotest.failf "resolve_expected_bits failed: %s" e);
  (* MTP for the block right after the base walks 11 ancestors, 10 of them
     below the base. *)
  (match Sync.resolve_mtp_hash_linked state ~height:(base_height + 1)
           hashes.(base_height) with
   | Ok mtp -> Alcotest.(check int32) "MTP at base+1 = median of base-10..base"
                 (ts_of (base_height - 5)) mtp
   | Error e -> Alcotest.failf "MTP below base unresolved: %s" e);
  (* Height-index BIP-68 MTP (get_mtp_for_height) reads the index too. *)
  Alcotest.(check int32) "index MTP at base+1"
    (ts_of (base_height - 5)) (Sync.get_mtp_for_height state (base_height + 1));
  (* Real cumulative work from genesis, not from the base. *)
  let expect_work = ref Consensus.zero_work in
  for _ = 0 to tip_height do
    expect_work := Consensus.work_add !expect_work (Consensus.work_from_compact bits0)
  done;
  Alcotest.(check bool) "tip work is the full chain's work" true
    (Consensus.work_compare parent.Sync.total_work !expect_work = 0);
  Storage.ChainDB.close db;
  (* Idempotent: second restore finds no holes and the same answer. *)
  let db = Storage.ChainDB.create !test_db_path in
  for h = 0 to tip_height do
    match Storage.ChainDB.get_hash_at_height db h with
    | Some x when Cstruct.equal x hashes.(h) -> ()
    | _ -> Alcotest.failf "index row %d not healed" h
  done;
  let state = Sync.restore_chain_state db net in
  (match Sync.resolve_expected_bits state (tip_height + 1) next with
   | Ok b -> Alcotest.(check int32) "after 2nd restore" want b
   | Error e -> Alcotest.failf "2nd restore: %s" e);
  Storage.ChainDB.close db

(* Fail-closed: pre-base bytes genuinely absent -> the resolver must refuse
   (ancestry-incomplete), never hand back a placeholder-derived verdict. *)
let test_absent_ancestry_fails_closed () =
  let hashes, headers = build ~name:"absent" ~with_prebase_bytes:false in
  let next = next_header hashes in
  let want = oracle_bits headers next in
  let db = Storage.ChainDB.create !test_db_path in
  let state = Sync.restore_chain_state db net in
  Alcotest.(check bool) "nothing healed: 2016 still absent" true
    (Sync.get_header state hashes.(2016) = None);
  (* The unguarded function still produces a placeholder value — that is the
     hazard the resolver exists to contain. *)
  let parent = match Sync.get_header state hashes.(tip_height) with
    | Some p -> p | None -> Alcotest.fail "tip missing" in
  let placeholder =
    Sync.compute_expected_bits ~parent_entry:parent state (tip_height + 1) next in
  Alcotest.(check bool) "unguarded value is wrong" true (placeholder <> want);
  (match Sync.resolve_expected_bits state (tip_height + 1) next with
   | Ok b -> Alcotest.failf "resolver returned a verdict 0x%08lx on absent ancestry" b
   | Error e ->
     Alcotest.(check bool) "tagged ancestry-incomplete" true
       (Sync.is_ancestry_incomplete e));
  (match Sync.resolve_mtp_hash_linked state ~height:(base_height + 1)
           hashes.(base_height) with
   | Ok _ -> Alcotest.fail "MTP resolved with only 1 of 11 ancestors"
   | Error e -> Alcotest.(check bool) "MTP tagged" true (Sync.is_ancestry_incomplete e));
  (* Unknown parent. *)
  let orphan = { next with Types.prev_block = Types.zero_hash } in
  (match Sync.resolve_expected_bits state (tip_height + 1) orphan with
   | Ok _ -> Alcotest.fail "resolver judged a block with an unknown parent"
   | Error e -> Alcotest.(check bool) "orphan tagged" true (Sync.is_ancestry_incomplete e));
  Storage.ChainDB.close db

let () =
  Alcotest.run "snapshot_base_retarget" [
    "retarget across a snapshot base", [
      Alcotest.test_case "mainnet 969696 consensus anchor" `Quick
        test_mainnet_969696_anchor;
      Alcotest.test_case "restore heals pre-base index; retarget == consensus"
        `Quick test_restore_then_retarget;
      Alcotest.test_case "absent ancestry fails closed" `Quick
        test_absent_ancestry_fails_closed;
    ];
  ]
