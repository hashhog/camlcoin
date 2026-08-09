(* W145 — bad-diffbits at HEADER time.

   Core: ContextualCheckBlockHeader (bitcoin-core/src/validation.cpp:4086-4089)
   rejects any header whose nBits differs from GetNextWorkRequired(pindexPrev).
   camlcoin's [Sync.validate_header] used to check only [check_proof_of_work]
   (hash-vs-CLAIMED-target = Core's "high-hash"), so a peer could serve a chain
   of difficulty-1 headers whose PoW was trivially valid against their own
   declared target.  That is what happened on mainnet: 1,254 headers with
   bits=0x1d00ffff forked off block 957599 and poisoned the height->hash index.
   See receipts/camlcoin-bad-diffbits-2026-08-09.md.

   These tests deliberately do NOT use [Consensus.regtest] unmodified.  regtest
   has pow_no_retargeting=true, so on regtest the expected value is always the
   parent's bits and a naive "bits must equal parent bits" implementation would
   pass every regtest test while being wrong on every other network.  Each test
   below uses a regtest-MINEABLE network whose pow FLAGS are shaped like the
   network under test, so the min-difficulty / retarget branches are actually
   exercised. *)

open Camlcoin

let pow_limit = 0x207fffffl   (* regtest pow_limit — the "easy" target *)
let hard_bits = 0x1f00ffffl   (* ~2^16 hashes to mine; strictly harder *)

(* Mainnet-shaped: no min-difficulty exception, retargeting on. *)
let net_mainnet_shape =
  { Consensus.regtest with
    Consensus.pow_allow_min_difficulty = false;
    pow_no_retargeting = false;
    enforce_bip94 = false }

(* Testnet4-shaped: min-difficulty exception legal, BIP-94 retarget base. *)
let net_testnet4_shape =
  { Consensus.regtest with
    Consensus.pow_allow_min_difficulty = true;
    pow_no_retargeting = false;
    enforce_bip94 = true }

let db_path = "/tmp/camlcoin_test_w145_db"

let rm_rf path =
  let rec go p =
    if Sys.file_exists p then
      if Sys.is_directory p then begin
        Array.iter (fun f -> go (Filename.concat p f)) (Sys.readdir p);
        Unix.rmdir p
      end else Unix.unlink p
  in
  go path

let mine ~prev_block ~ts ~bits =
  let rec loop nonce =
    if nonce > 20_000_000l then failwith "w145: mining failed"
    else
      let h = { Types.version = 1l; prev_block; merkle_root = Types.zero_hash;
                timestamp = ts; bits; nonce } in
      if Consensus.hash_meets_target (Crypto.compute_block_hash h) bits then h
      else loop (Int32.add nonce 1l)
  in
  loop 0l

(* Insert a header DIRECTLY (bypassing validate_header) so the test controls
   the ancestry's bits freely. *)
let insert state (parent : Sync.header_entry) header : Sync.header_entry =
  let hash = Crypto.compute_block_hash header in
  let entry = { Sync.header; hash; height = parent.Sync.height + 1;
                total_work = Consensus.work_add parent.Sync.total_work
                    (Sync.work_from_bits header.Types.bits) } in
  Sync.accept_header state entry;
  entry

(* Build [n] ancestors carrying [bits], 600 s apart, starting from genesis. *)
let build network ~bits ~n =
  rm_rf db_path;
  let db = Storage.ChainDB.create db_path in
  let state = Sync.create_chain_state db network in
  let g = Crypto.compute_block_hash network.Consensus.genesis_header in
  let genesis =
    match Sync.get_header state g with
    | Some e -> e
    | None -> Alcotest.fail "genesis missing from header table"
  in
  let ts = ref (Int32.add network.Consensus.genesis_header.Types.timestamp 600l) in
  let cur = ref genesis in
  for _ = 1 to n do
    let h = mine ~prev_block:(!cur).Sync.hash ~ts:!ts ~bits in
    cur := insert state !cur h;
    ts := Int32.add !ts 600l
  done;
  (state, db, !cur)

let finish db = Storage.ChainDB.close db; rm_rf db_path

let is_bad_diffbits = function
  | Error e -> String.length e >= 13 && String.sub e 0 13 = "bad-diffbits "
  | Ok _ -> false

let is_ok = function Ok _ -> true | Error _ -> false

(* ------------------------------------------------------------------ *)
(* 1. THE MAINNET ATTACK REPRO: an easier-than-required header is
      rejected at HEADER time, even though its PoW is valid for the
      target it declares. *)
let test_mainnet_rejects_easier_bits () =
  let (state, db, tip) = build net_mainnet_shape ~bits:hard_bits ~n:3 in
  let ts = Int32.add tip.Sync.header.Types.timestamp 600l in
  let attack = mine ~prev_block:tip.Sync.hash ~ts ~bits:pow_limit in
  let honest = mine ~prev_block:tip.Sync.hash ~ts ~bits:hard_bits in
  (* Sanity: the attack header's own PoW IS valid for its own claimed bits —
     this is precisely why check_proof_of_work alone let it through. *)
  Alcotest.(check bool) "attack header passes high-hash (its own target)"
    true (Consensus.check_proof_of_work (Crypto.compute_block_hash attack)
            pow_limit net_mainnet_shape);
  let r_attack = Sync.validate_header state attack in
  let r_honest = Sync.validate_header state honest in
  finish db;
  Alcotest.(check bool) "easier-than-required header rejected as bad-diffbits"
    true (is_bad_diffbits r_attack);
  Alcotest.(check bool) "correct-difficulty header still accepted"
    true (is_ok r_honest)

(* 2. The poisoned-index claim, made explicit: WITHOUT ~parent_entry the
      expected value collapses to pow_limit (the height->hash index does not
      cover headers above the validated tip since fecf534), which would have
      INVERTED the check — rejecting honest headers and admitting the attack.
      validate_header must not depend on that path. *)
let test_check_does_not_consult_height_index () =
  let (state, db, tip) = build net_mainnet_shape ~bits:hard_bits ~n:3 in
  let height = tip.Sync.height + 1 in
  let ts = Int32.add tip.Sync.header.Types.timestamp 600l in
  let honest = mine ~prev_block:tip.Sync.hash ~ts ~bits:hard_bits in
  let via_index = Sync.compute_expected_bits state height honest in
  let via_ancestry =
    Sync.compute_expected_bits ~parent_entry:tip state height honest in
  let r_honest = Sync.validate_header state honest in
  finish db;
  Alcotest.(check int32)
    "index path collapses to pow_limit (would invert the check)"
    pow_limit via_index;
  Alcotest.(check int32) "ancestry path returns the real required bits"
    hard_bits via_ancestry;
  Alcotest.(check bool) "validate_header uses the ancestry path"
    true (is_ok r_honest)

(* 3. testnet4: a min-difficulty header >20 min after its parent is not merely
      permitted, it is MANDATORY (Core pow.cpp:27-28). *)
let test_testnet4_min_difficulty_is_mandatory_when_late () =
  let (state, db, tip) = build net_testnet4_shape ~bits:hard_bits ~n:3 in
  let ts = Int32.add tip.Sync.header.Types.timestamp 1201l in
  let min_diff = mine ~prev_block:tip.Sync.hash ~ts ~bits:pow_limit in
  let still_hard = mine ~prev_block:tip.Sync.hash ~ts ~bits:hard_bits in
  let r_min = Sync.validate_header state min_diff in
  let r_hard = Sync.validate_header state still_hard in
  finish db;
  Alcotest.(check bool) "legal min-difficulty header ACCEPTED on testnet4"
    true (is_ok r_min);
  Alcotest.(check bool) "non-min-difficulty header REJECTED when 20-min rule fires"
    true (is_bad_diffbits r_hard)

(* 4. testnet4: not late enough → the walk-back's bits are required, and a
      min-difficulty header is rejected.  This is the case a naive
      "min-difficulty network ⇒ accept pow_limit" shortcut would get wrong. *)
let test_testnet4_min_difficulty_rejected_when_not_late () =
  let (state, db, tip) = build net_testnet4_shape ~bits:hard_bits ~n:3 in
  let ts = Int32.add tip.Sync.header.Types.timestamp 600l in
  let min_diff = mine ~prev_block:tip.Sync.hash ~ts ~bits:pow_limit in
  let honest = mine ~prev_block:tip.Sync.hash ~ts ~bits:hard_bits in
  let r_min = Sync.validate_header state min_diff in
  let r_honest = Sync.validate_header state honest in
  finish db;
  Alcotest.(check bool) "min-difficulty header rejected when not 20-min late"
    true (is_bad_diffbits r_min);
  Alcotest.(check bool) "walk-back bits accepted" true (is_ok r_honest)

(* 5. The 20-minute rule is a STRICT greater-than: exactly parent+1200 does
      NOT qualify (Core pow.cpp:27 `>`), parent+1201 does. *)
let test_testnet4_twenty_minute_boundary_is_strict () =
  let (state, db, tip) = build net_testnet4_shape ~bits:hard_bits ~n:3 in
  let at_1200 =
    mine ~prev_block:tip.Sync.hash
      ~ts:(Int32.add tip.Sync.header.Types.timestamp 1200l) ~bits:pow_limit in
  let at_1201 =
    mine ~prev_block:tip.Sync.hash
      ~ts:(Int32.add tip.Sync.header.Types.timestamp 1201l) ~bits:pow_limit in
  let r1200 = Sync.validate_header state at_1200 in
  let r1201 = Sync.validate_header state at_1201 in
  finish db;
  Alcotest.(check bool) "exactly +1200 s does NOT qualify for min-difficulty"
    true (is_bad_diffbits r1200);
  Alcotest.(check bool) "+1201 s does qualify" true (is_ok r1201)

(* 6. The min-difficulty walk-back terminates on the first non-pow_limit
      ancestor, not on the parent — a run of legal min-difficulty headers must
      not ratchet the required difficulty down to pow_limit permanently. *)
let test_testnet4_walk_back_past_min_difficulty_run () =
  let (state, db, tip) = build net_testnet4_shape ~bits:hard_bits ~n:2 in
  (* Three legal min-difficulty headers, each >20 min after its parent. *)
  let cur = ref tip in
  for _ = 1 to 3 do
    let ts = Int32.add (!cur).Sync.header.Types.timestamp 1201l in
    let h = mine ~prev_block:(!cur).Sync.hash ~ts ~bits:pow_limit in
    (match Sync.validate_header state h with
     | Ok e -> Sync.accept_header state e; cur := e
     | Error e -> Alcotest.failf "legal min-difficulty header rejected: %s" e)
  done;
  (* Now a NOT-late child: the walk-back must skip the three pow_limit
     ancestors and land on the hard-bits block. *)
  let ts = Int32.add (!cur).Sync.header.Types.timestamp 600l in
  let honest = mine ~prev_block:(!cur).Sync.hash ~ts ~bits:hard_bits in
  let easy = mine ~prev_block:(!cur).Sync.hash ~ts ~bits:pow_limit in
  let r_honest = Sync.validate_header state honest in
  let r_easy = Sync.validate_header state easy in
  finish db;
  Alcotest.(check bool) "walk-back lands on the pre-run difficulty"
    true (is_ok r_honest);
  Alcotest.(check bool) "pow_limit rejected after the run ends"
    true (is_bad_diffbits r_easy)

(* 7. regtest (pow_no_retargeting) is unchanged in shape: expected = parent
      bits, and a one-bit twiddle is rejected.  This is the inverted W97-G7. *)
let test_regtest_rejects_wrong_bits () =
  let (state, db, tip) = build Consensus.regtest ~bits:pow_limit ~n:2 in
  let ts = Int32.add tip.Sync.header.Types.timestamp 600l in
  let wrong = mine ~prev_block:tip.Sync.hash ~ts ~bits:0x207ffffel in
  let right = mine ~prev_block:tip.Sync.hash ~ts ~bits:pow_limit in
  let r_wrong = Sync.validate_header state wrong in
  let r_right = Sync.validate_header state right in
  finish db;
  Alcotest.(check bool) "regtest rejects non-canonical bits"
    true (is_bad_diffbits r_wrong);
  Alcotest.(check bool) "regtest accepts canonical bits" true (is_ok r_right)

let () =
  Alcotest.run "w145_bad_diffbits" [
    "header_bad_diffbits", [
      Alcotest.test_case "mainnet rejects easier bits" `Quick
        test_mainnet_rejects_easier_bits;
      Alcotest.test_case "check does not consult height index" `Quick
        test_check_does_not_consult_height_index;
      Alcotest.test_case "testnet4 min-difficulty mandatory when late" `Quick
        test_testnet4_min_difficulty_is_mandatory_when_late;
      Alcotest.test_case "testnet4 min-difficulty rejected when not late" `Quick
        test_testnet4_min_difficulty_rejected_when_not_late;
      Alcotest.test_case "testnet4 20-min boundary is strict" `Quick
        test_testnet4_twenty_minute_boundary_is_strict;
      Alcotest.test_case "testnet4 walk-back past min-difficulty run" `Quick
        test_testnet4_walk_back_past_min_difficulty_run;
      Alcotest.test_case "regtest rejects wrong bits" `Quick
        test_regtest_rejects_wrong_bits;
    ]
  ]
