(* verify-neon-camlcoin-findings, header group (Neon audit 2026-11-24,
   findings 18 and 16; camlcoin 482c676).

   F18  Core ContextualCheckBlockHeader (src/validation.cpp) rejects a HEADER
        whose nVersion is below 2 / 3 / 4 once BIP34 / BIP66 / BIP65 are
        active at its height:
          if ((block.nVersion < 2 && DeploymentActiveAfter(pindexPrev, .., HEIGHTINCB)) ||
              (block.nVersion < 3 && DeploymentActiveAfter(pindexPrev, .., DERSIG)) ||
              (block.nVersion < 4 && DeploymentActiveAfter(pindexPrev, .., CLTV)))
            return state.Invalid(BLOCK_INVALID_HEADER, strprintf("bad-version(0x%08x)", ..));
        so submitheader answers -25 "bad-version(0x00000001)" and a P2P
        headers message carrying one is refused.  camlcoin's
        Sync.validate_header never looked at the version: it indexed the
        header and moved the best header onto it (only the BODY was checked,
        later, by Validation.check_block).  On regtest BIP34/66/65 are active
        from height 1 (chainparams.cpp), so this is reachable on Core's
        regtest.

   F16  Core GetNextWorkRequired (src/pow.cpp) applies the testnet
        min-difficulty rule at every non-retarget height:
          if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + 2*spacing)
              return nProofOfWorkLimit;
          else walk back past min-difficulty blocks to the last real nBits;
        and ContextualCheckBlockHeader compares it ("bad-diffbits") for a
        side-branch block exactly as for a tip block.  camlcoin's
        Sync.try_attach_side_branch_and_reorg (submitblock of a block whose
        parent is not the tip) used the parent's nBits at every non-retarget
        height.  Regtest cannot show this: every regtest block is at the pow
        limit.  The test uses a regtest-mineable network with the testnet
        pow flags (pow_allow_min_difficulty, retargeting on) and a genesis
        whose nBits is harder than the pow limit, so the min-difficulty and
        walk-back branches are both exercised. *)

open Camlcoin

let op_true = Cstruct.of_string "\x51"

let mine (h : Types.block_header) : Types.block_header =
  let rec loop n =
    if Int32.compare n 20_000_000l >= 0 then failwith "mine: no nonce found"
    else
      let h' = { h with Types.nonce = n } in
      if Consensus.hash_meets_target (Crypto.compute_block_hash h') h.Types.bits
      then h' else loop (Int32.add n 1l)
  in
  loop 0l

let hash_of_header = Crypto.compute_block_hash
let hash_of (b : Types.block) = hash_of_header b.Types.header
let hex = Types.hash256_to_hex_display

(* ---------- node ---------- *)
let with_node ?(network = Consensus.regtest) label f =
  Test_tmp.with_dir ~label ~mkdir:true (fun path ->
    let db = Storage.ChainDB.create path in
    Fun.protect ~finally:(fun () -> try Storage.ChainDB.close db with _ -> ())
      (fun () ->
        let chain = Sync.create_chain_state db network in
        chain.Sync.sync_state <- Sync.FullySynced;
        let utxo = Utxo.OptimizedUtxoSet.create ~cache_size:10_000 db in
        Sync.shared_utxo_set := Some utxo;
        let mempool = Mempool.create ~network
            ~require_standard:false ~verify_scripts:false
            ~utxo:(Utxo.UtxoSet.create db) ~current_height:0 () in
        let ctx : Rpc.rpc_context = {
          chain; mempool;
          peer_manager = Peer_manager.create network;
          wallet = None; wallet_manager = None;
          fee_estimator = Fee_estimation.create ();
          network;
          filter_index = None; utxo = Some utxo; data_dir = None;
          snapshot_activation = None;
        } in
        Fun.protect ~finally:(fun () -> Sync.shared_utxo_set := None)
          (fun () -> f ctx)))

(* ================= F18: header version ================= *)

let regtest_genesis = Consensus.regtest.Consensus.genesis_header

let header_v ?(prev = Consensus.regtest.Consensus.genesis_hash)
    ?(ts = Int32.add regtest_genesis.Types.timestamp 600l) version =
  mine { Types.version; prev_block = prev; merkle_root = Types.zero_hash;
         timestamp = ts; bits = Consensus.regtest.pow_limit; nonce = 0l }

let header_hex (h : Types.block_header) =
  let w = Serialize.writer_create () in
  Serialize.serialize_block_header w h;
  let cs = Serialize.writer_to_cstruct w in
  String.concat "" (List.init (Cstruct.length cs)
                      (fun i -> Printf.sprintf "%02x" (Cstruct.get_uint8 cs i)))

let submitheader ctx h =
  match Rpc.handle_submitheader ctx [ `String (header_hex h) ] with
  | Ok `Null -> "null"
  | Ok j -> "unexpected:" ^ Yojson.Safe.to_string j
  | Error (code, msg) -> Printf.sprintf "%d:%s" code msg

let known ctx h = Sync.get_header ctx.Rpc.chain (hash_of_header h) <> None

(* Core v31.1 regtest answers (rpc/mining.cpp submitheader -> -25 with the
   reject reason; recorded with the pinned bitcoind 31.1 on regtest, script
   and output in the PR description). *)
let submitheader_case version expected () =
  with_node (Printf.sprintf "vnh_sh_%08lx" version) (fun ctx ->
    let h = header_v version in
    let got = submitheader ctx h in
    Printf.printf "submitheader v=0x%08lx -> %s\n%!" version got;
    Alcotest.(check string) "submitheader answer (Core v31.1)" expected got;
    Alcotest.(check bool) "indexed only if Core accepts"
      (expected = "null") (known ctx h))

let f18_submitheader = [
  "v1_at_height1_rejected", 1l, "-25:bad-version(0x00000001)";
  "v2_at_height1_rejected", 2l, "-25:bad-version(0x00000002)";
  "v3_at_height1_rejected", 3l, "-25:bad-version(0x00000003)";
  "v_negative_0x80000000_rejected", 0x80000000l, "-25:bad-version(0x80000000)";
  "control_v4_accepted", 4l, "null";
  "control_v0x20000000_accepted", 0x20000000l, "null";
]

(* Activation heights: each floor applies from its own BIP height and not one
   block earlier.  Regtest has all three at height 1, so this network moves
   them to BIP34 = 2, BIP66 = 3, BIP65 = 4 and walks one header chain up
   through them.  At each height the header one version below the floor is
   refused and the floor version extends the chain (Core:
   DeploymentActiveAfter(pindexPrev) = pindexPrev->nHeight + 1 >= height). *)
let net_staggered =
  { Consensus.regtest with
    Consensus.bip34_height = 2; bip66_height = 3; bip65_height = 4 }

let test_activation_heights () =
  with_node ~network:net_staggered "vnh_staggered" (fun ctx ->
    let step prev ts ~reject ~accept =
      (match reject with
       | None -> ()
       | Some v ->
         let bad = header_v ~prev ~ts v in
         let got = submitheader ctx bad in
         Printf.printf "staggered v=%ld -> %s\n%!" v got;
         Alcotest.(check string) (Printf.sprintf "v%ld below its floor" v)
           (Printf.sprintf "-25:bad-version(0x%08lx)" v) got);
      let good = header_v ~prev ~ts accept in
      let got = submitheader ctx good in
      Printf.printf "staggered v=%ld -> %s\n%!" accept got;
      Alcotest.(check string) (Printf.sprintf "v%ld at its floor accepted" accept)
        "null" got;
      good
    in
    let t0 = regtest_genesis.Types.timestamp in
    (* height 1: no floor active yet, v1 is valid *)
    let h1 = step Consensus.regtest.Consensus.genesis_hash (Int32.add t0 600l)
        ~reject:None ~accept:1l in
    (* height 2: BIP34 -> v1 refused, v2 valid *)
    let h2 = step (hash_of_header h1) (Int32.add t0 1200l) ~reject:(Some 1l) ~accept:2l in
    (* height 3: BIP66 -> v2 refused, v3 valid *)
    let h3 = step (hash_of_header h2) (Int32.add t0 1800l) ~reject:(Some 2l) ~accept:3l in
    (* height 4: BIP65 -> v3 refused, v4 valid *)
    ignore (step (hash_of_header h3) (Int32.add t0 2400l) ~reject:(Some 3l) ~accept:4l))

(* P2P path: Sync.process_headers is what a headers message runs.  A batch
   whose second header is v1 must not index it (Core: the whole message is
   refused at the first invalid header; the v4 header before it stays). *)
let test_p2p_headers_v1 () =
  with_node "vnh_p2p" (fun ctx ->
    let h1 = header_v 4l in
    let h2 = header_v ~prev:(hash_of_header h1)
        ~ts:(Int32.add h1.Types.timestamp 600l) 1l in
    let r = Sync.process_headers ctx.Rpc.chain [ h1; h2 ] in
    Printf.printf "process_headers [v4; v1] -> %s\n%!"
      (match r with Ok n -> Printf.sprintf "Ok %d" n | Error e -> "Error " ^ e);
    Alcotest.(check bool) "v4 header indexed" true (known ctx h1);
    Alcotest.(check bool) "v1 header at height 2 not indexed" false (known ctx h2))


(* ================= F16: side-branch min-difficulty ================= *)

let hard_bits = 0x1f00ffffl          (* harder than the regtest pow limit *)
let pow_limit = Consensus.regtest.Consensus.pow_limit

let mindiff_genesis =
  { regtest_genesis with Types.bits = hard_bits }

(* testnet pow rules, regtest-mineable *)
let net_mindiff =
  { Consensus.regtest with
    Consensus.pow_allow_min_difficulty = true;
    pow_no_retargeting = false;
    enforce_bip94 = false;
    genesis_header = mindiff_genesis;
    genesis_hash = Crypto.compute_block_hash mindiff_genesis }

let block_hex (b : Types.block) =
  let w = Serialize.writer_create () in
  Serialize.serialize_block w b;
  let cs = Serialize.writer_to_cstruct w in
  String.concat "" (List.init (Cstruct.length cs)
                      (fun i -> Printf.sprintf "%02x" (Cstruct.get_uint8 cs i)))

let make_block ~(prev : Types.block option) ~height ~tag ~dt ~bits : Types.block =
  let prev_hash, prev_time = match prev with
    | None -> net_mindiff.Consensus.genesis_hash, mindiff_genesis.Types.timestamp
    | Some p -> hash_of p, p.Types.header.Types.timestamp in
  let extra_nonce = Cstruct.create 8 in
  Cstruct.LE.set_uint64 extra_nonce 0 (Int64.of_int (height + (tag lsl 32)));
  let mk wr =
    Mining.create_coinbase ~height ~total_fee:0L ~payout_script:op_true
      ~extra_nonce ~witness_root:wr ~network_type:Consensus.Regtest ()
  in
  let wr = Mining.compute_witness_merkle_root [ mk None ] in
  let coinbase = mk (Some wr) in
  let merkle_root, _ = Crypto.merkle_root [ Crypto.compute_txid coinbase ] in
  let header = mine { Types.version = 4l; prev_block = prev_hash; merkle_root;
                      timestamp = Int32.add prev_time dt; bits; nonce = 0l } in
  { Types.header; transactions = [ coinbase ] }

let submit ctx b =
  match Rpc.handle_submitblock ctx [ `String (block_hex b) ] with
  | Ok `Null -> "null"
  | Ok (`String s) -> s
  | Ok j -> "unexpected:" ^ Yojson.Safe.to_string j
  | Error e -> "rpc-error:" ^ e

let tip (ctx : Rpc.rpc_context) =
  match Sync.block_tip ctx.chain with
  | Some (e : Sync.header_entry) -> Printf.sprintf "%s@%d" (hex e.hash) e.height
  | None -> "none"

let at b h = Printf.sprintf "%s@%d" (hex (hash_of b)) h

(* Active chain: a1 = genesis + 600 s at the genesis nBits (walk-back value).
   Side s1 on genesis, 1800 s later than genesis (> 2 * 600), at the pow
   limit: the min-difficulty rule makes pow_limit the REQUIRED nBits, so Core
   stores it (less work than a1) and submitblock answers "inconclusive". *)
let test_side_mindiff_valid_accepted () =
  with_node ~network:net_mindiff "vnh_side_valid" (fun ctx ->
    let a1 = make_block ~prev:None ~height:1 ~tag:1 ~dt:600l ~bits:hard_bits in
    Alcotest.(check string) "a1 (tip path) accepted" "null" (submit ctx a1);
    let s1 = make_block ~prev:None ~height:1 ~tag:2 ~dt:1800l ~bits:pow_limit in
    let got = submit ctx s1 in
    Printf.printf "side min-diff s1 -> %s\n%!" got;
    Alcotest.(check string) "valid min-difficulty side block (Core: inconclusive)"
      "inconclusive" got;
    Alcotest.(check string) "tip stays a1" (at a1 1) (tip ctx))

(* Active chain: m1 = genesis + 1800 s at the pow limit (min-difficulty),
   m2 = m1 + 600 s at the walked-back genesis nBits.  Side s2 on m1, 600 s
   after it, at the pow limit: 600 <= 1200, so Core walks back past m1 (a
   min-difficulty block) to genesis and requires hard_bits -> bad-diffbits. *)
let test_side_repeat_mindiff_rejected () =
  with_node ~network:net_mindiff "vnh_side_invalid" (fun ctx ->
    let m1 = make_block ~prev:None ~height:1 ~tag:1 ~dt:1800l ~bits:pow_limit in
    let m2 = make_block ~prev:(Some m1) ~height:2 ~tag:1 ~dt:600l ~bits:hard_bits in
    Alcotest.(check string) "m1 (tip path, min-diff) accepted" "null" (submit ctx m1);
    Alcotest.(check string) "m2 (tip path, walked back) accepted" "null" (submit ctx m2);
    let s2 = make_block ~prev:(Some m1) ~height:2 ~tag:2 ~dt:600l ~bits:pow_limit in
    let got = submit ctx s2 in
    Printf.printf "side repeat-min-diff s2 -> %s\n%!" got;
    Alcotest.(check bool) "invalid side block not stored (Core: bad-diffbits)"
      false (got = "inconclusive" || got = "null");
    Alcotest.(check bool) "s2 body not stored" false
      (Storage.ChainDB.has_block ctx.chain.Sync.db (hash_of s2));
    Alcotest.(check string) "tip stays m2" (at m2 2) (tip ctx))

(* Same chain m1, m2.  Side s2 on m1, 600 s after it, at the WALKED-BACK
   nBits (genesis = hard_bits): that is exactly what Core requires, so it is
   stored -> "inconclusive".  Using the parent's nBits (pow limit) refused it. *)
let test_side_walked_back_accepted () =
  with_node ~network:net_mindiff "vnh_side_walkback" (fun ctx ->
    let m1 = make_block ~prev:None ~height:1 ~tag:1 ~dt:1800l ~bits:pow_limit in
    let m2 = make_block ~prev:(Some m1) ~height:2 ~tag:1 ~dt:600l ~bits:hard_bits in
    Alcotest.(check string) "m1 accepted" "null" (submit ctx m1);
    Alcotest.(check string) "m2 accepted" "null" (submit ctx m2);
    let s2 = make_block ~prev:(Some m1) ~height:2 ~tag:2 ~dt:600l ~bits:hard_bits in
    let got = submit ctx s2 in
    Printf.printf "side walked-back s2 -> %s\n%!" got;
    Alcotest.(check string) "walked-back side block (Core: inconclusive)"
      "inconclusive" got;
    Alcotest.(check string) "tip stays m2" (at m2 2) (tip ctx))

(* Fail-closed path the fix introduces.  Chain a1 (genesis + 600 s, hard nBits)
   -> m2 (a1 + 1800 s, min-difficulty) -> m3 (tip, m2 + 600 s, walked-back
   nBits).  Side s3 on m2 (sibling of m3), 600 s later, at the
   walked-back nBits: the walk passes m2 (min-difficulty) and stops at a1.
   With a1 missing from the in-memory header table the required nBits cannot
   be computed (Core asserts the ancestor exists, pow.cpp), so the block must
   be neither stored nor marked invalid, and the tip must not move.  Once a1
   is back, the same block is judged normally and stored ("inconclusive"). *)
let test_side_walkback_missing_ancestor () =
  with_node ~network:net_mindiff "vnh_side_missing" (fun ctx ->
    let a1 = make_block ~prev:None ~height:1 ~tag:1 ~dt:600l ~bits:hard_bits in
    let m2 = make_block ~prev:(Some a1) ~height:2 ~tag:1 ~dt:1800l ~bits:pow_limit in
    Alcotest.(check string) "a1 accepted" "null" (submit ctx a1);
    Alcotest.(check string) "m2 (min-diff) accepted" "null" (submit ctx m2);
    let m3 = make_block ~prev:(Some m2) ~height:3 ~tag:1 ~dt:600l ~bits:hard_bits in
    Alcotest.(check string) "m3 (walked back) accepted" "null" (submit ctx m3);
    let s3 = make_block ~prev:(Some m2) ~height:3 ~tag:2 ~dt:600l ~bits:hard_bits in
    let key = Cstruct.to_string (hash_of a1) in
    let saved = Hashtbl.find ctx.chain.Sync.headers key in
    Hashtbl.remove ctx.chain.Sync.headers key;
    let got = submit ctx s3 in
    Printf.printf "side s3 with ancestor a1 missing -> %s\n%!" got;
    Alcotest.(check bool) "not stored or accepted while the ancestor is missing"
      false (got = "inconclusive" || got = "null");
    Alcotest.(check bool) "s3 body not stored" false
      (Storage.ChainDB.has_block ctx.chain.Sync.db (hash_of s3));
    Alcotest.(check bool) "s3 not marked invalid" false
      (Hashtbl.mem ctx.chain.Sync.invalidated_blocks (Cstruct.to_string (hash_of s3)));
    Alcotest.(check string) "tip stays m3" (at m3 3) (tip ctx);
    Hashtbl.replace ctx.chain.Sync.headers key saved;
    let got2 = submit ctx s3 in
    Printf.printf "side s3 with ancestor a1 restored -> %s\n%!" got2;
    Alcotest.(check string) "same block, ancestry complete (Core: inconclusive)"
      "inconclusive" got2;
    Alcotest.(check string) "tip still m3" (at m3 3) (tip ctx))

(* Controls: side blocks that are valid on both sides stay "inconclusive",
   and the tip path itself refuses the same invalid block (it was already
   Core-correct there). *)
let test_side_controls () =
  with_node ~network:net_mindiff "vnh_side_ctrl" (fun ctx ->
    let m1 = make_block ~prev:None ~height:1 ~tag:1 ~dt:1800l ~bits:pow_limit in
    let m2 = make_block ~prev:(Some m1) ~height:2 ~tag:1 ~dt:600l ~bits:hard_bits in
    ignore (submit ctx m1); ignore (submit ctx m2);
    (* side on m1, 1800 s, pow limit: valid min-difficulty *)
    let s2b = make_block ~prev:(Some m1) ~height:2 ~tag:3 ~dt:1800l ~bits:pow_limit in
    Alcotest.(check string) "side min-diff after min-diff parent" "inconclusive"
      (submit ctx s2b);
    (* side on genesis, 600 s, pow limit: invalid (walk back = genesis nBits) *)
    let s1bad = make_block ~prev:None ~height:1 ~tag:4 ~dt:600l ~bits:pow_limit in
    Alcotest.(check bool) "side 600 s at pow limit on a hard parent rejected" false
      (let g = submit ctx s1bad in g = "inconclusive" || g = "null");
    (* tip path: m3 on m2, 600 s, pow limit -> rejected (already Core-correct) *)
    let m3bad = make_block ~prev:(Some m2) ~height:3 ~tag:1 ~dt:600l ~bits:pow_limit in
    Alcotest.(check bool) "tip-path 600 s at pow limit rejected" false
      (submit ctx m3bad = "null");
    Alcotest.(check string) "tip stays m2" (at m2 2) (tip ctx))

let () =
  Alcotest.run "verify_neon_header_checks" [
    "f18_submitheader_version",
      List.map (fun (name, v, exp) ->
        Alcotest.test_case name `Quick (submitheader_case v exp)) f18_submitheader;
    "f18_activation_heights", [
      Alcotest.test_case "floor_starts_at_each_bip_height" `Quick test_activation_heights ];
    "f18_p2p_headers_version", [
      Alcotest.test_case "v1_after_v4_not_indexed" `Quick test_p2p_headers_v1 ];
    "f16_side_branch_min_difficulty", [
      Alcotest.test_case "valid_mindiff_side_block_inconclusive" `Quick
        test_side_mindiff_valid_accepted;
      Alcotest.test_case "repeat_mindiff_side_block_rejected" `Quick
        test_side_repeat_mindiff_rejected;
      Alcotest.test_case "walked_back_side_block_inconclusive" `Quick
        test_side_walked_back_accepted;
      Alcotest.test_case "walkback_missing_ancestor_fails_closed" `Quick
        test_side_walkback_missing_ancestor;
      Alcotest.test_case "controls" `Quick test_side_controls ];
  ]
