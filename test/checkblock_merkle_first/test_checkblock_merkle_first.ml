(* A real header with a body that is not the block it commits to must not
   mark the header failed (security audit 2026-10-31, C4).

   check_block used to test txs = [], first-tx-is-coinbase and the BIP34
   coinbase height before it compared the merkle root.  Those errors are
   verdicts (Sync.is_block_mutation_error = false), so a peer that had a
   new block's 80-byte header could send header || one non-coinbase tx,
   and process_new_block marked the honest block BLOCK_FAILED_VALID,
   persisted the mark and covered every descendant: the node stopped at
   the parent.  The same held for a body whose witness was inflated past
   the size limit: BlockOversized ran before the witness commitment check.

   Core CheckBlock (validation.cpp): "All potential-corruption validation
   must be done before we do any transaction validation, as otherwise we
   may mark the header as invalid because we receive the wrong
   transactions for it."  CheckMerkleRoot runs first, and a
   BLOCK_MUTATED result is never marked by InvalidBlockFound.

     dune exec --no-buffer test/checkblock_merkle_first/test_checkblock_merkle_first.exe *)

open Camlcoin

let op_true = Cstruct.of_string "\x51"

let remine (block : Types.block) : Types.block =
  let h = ref block.Types.header in
  let n = ref 0l in
  let found = ref false in
  while (not !found) && Int32.compare !n 5_000_000l < 0 do
    h := { !h with Types.nonce = !n };
    if Consensus.hash_meets_target (Crypto.compute_block_hash !h) !h.Types.bits
    then found := true
    else n := Int32.add !n 1l
  done;
  if not !found then failwith "remine: no nonce found";
  { block with Types.header = !h }

let merkle_of txs = fst (Crypto.merkle_root (List.map Crypto.compute_txid txs))

let build_block ?(tag = 0) ?(txs = []) ~(prev_hash : Types.hash256)
    ~(height : int) ~(prev_time : int32) () : Types.block =
  let extra_nonce = Cstruct.create 8 in
  Cstruct.LE.set_uint64 extra_nonce 0 (Int64.of_int ((tag * 1_000_000) + height));
  let mk wr =
    Mining.create_coinbase ~height ~total_fee:0L ~payout_script:op_true
      ~extra_nonce ~witness_root:wr ~network_type:Consensus.Regtest ()
  in
  let witness_root = Mining.compute_witness_merkle_root (mk None :: txs) in
  let coinbase = mk (Some witness_root) in
  let all = coinbase :: txs in
  remine
    { Types.header =
        { version = 4l; prev_block = prev_hash; merkle_root = merkle_of all;
          timestamp = Int32.add prev_time 600l;
          bits = Consensus.regtest.pow_limit; nonce = 0l };
      transactions = all }

let hash_of (b : Types.block) = Crypto.compute_block_hash b.Types.header

let accept_hdr state (b : Types.block) =
  match Sync.validate_header state b.Types.header with
  | Ok e -> Sync.accept_header state e
  | Error "Header already known" -> ()
  | Error e -> Alcotest.failf "validate_header: %s" e

let deliver ?peer_id state b =
  Lwt_main.run (Sync.process_new_block ~f_requested:true ?peer_id state b)

(* Connected chain genesis..h3, FullySynced (the at-tip shape). *)
let with_chain f =
  Test_tmp.with_dir ~label:"checkblock_merkle_first" ~mkdir:true (fun path ->
    let db = Storage.ChainDB.create path in
    Fun.protect
      ~finally:(fun () -> try Storage.ChainDB.close db with _ -> ())
      (fun () ->
        let state = Sync.create_chain_state db Consensus.regtest in
        state.Sync.sync_state <- Sync.FullySynced;
        let genesis = Option.get state.Sync.tip in
        let prev = ref (genesis.Sync.hash, genesis.Sync.header.Types.timestamp) in
        for h = 1 to 3 do
          let b = build_block ~prev_hash:(fst !prev) ~height:h
              ~prev_time:(snd !prev) () in
          accept_hdr state b;
          (match deliver state b with
           | Ok () -> ()
           | Error e -> Alcotest.failf "prefix block %d: %s" h e);
          prev := (hash_of b, b.Types.header.Types.timestamp)
        done;
        Alcotest.(check int) "prefix connected" 3 state.Sync.blocks_synced;
        f state (fst !prev) (snd !prev)))

let is_invalid state (b : Types.block) = Sync.is_block_invalid state (hash_of b)

let attacker = 2
let honest = 0

(* A non-coinbase tx spending a prevout nobody has. *)
let junk_tx : Types.transaction = {
  Types.version = 2l;
  inputs = [ { Types.previous_output =
                 { Types.txid = Cstruct.of_string (String.make 32 '\x11');
                   vout = 0l };
               script_sig = Cstruct.of_string "\x51";
               sequence = 0xFFFFFFFFl } ];
  outputs = [ { Types.value = 1_000L; script_pubkey = op_true } ];
  witnesses = []; locktime = 0l }

(* The attack: the honest block's header arrives (headers-first), then
   [junk] under that header arrives before the honest body.  The junk must
   be rejected without marking, and the honest body must then connect. *)
let attack ~(junk : Types.block -> Types.block) () =
  with_chain (fun state tip3 t3 ->
    let real = build_block ~prev_hash:tip3 ~height:4 ~prev_time:t3 () in
    accept_hdr state real;
    let bad = junk real in
    Alcotest.(check bool) "junk keeps the real header" true
      (Cstruct.equal (hash_of bad) (hash_of real));
    (match deliver ~peer_id:attacker state bad with
     | Ok () -> Alcotest.fail "junk body accepted"
     | Error _ -> ());
    Alcotest.(check bool) "junk body did NOT mark the honest block failed"
      false (is_invalid state real);
    (match deliver ~peer_id:honest state real with
     | Ok () -> ()
     | Error e -> Alcotest.failf "honest body after the junk: %s" e);
    Alcotest.(check int) "honest body connects" 4 state.Sync.blocks_synced)

(* Audit repro shape: header || 01 || one non-coinbase tx. *)
let test_one_noncoinbase_tx =
  attack ~junk:(fun real -> { real with Types.transactions = [ junk_tx ] })

(* header || 00: no transactions at all. *)
let test_empty_body =
  attack ~junk:(fun real -> { real with Types.transactions = [] })

(* A coinbase whose BIP34 height is wrong (check_coinbase used to run
   first). *)
let test_wrong_bip34_coinbase =
  attack ~junk:(fun real ->
    let other = Mining.create_coinbase ~height:7 ~total_fee:0L
        ~payout_script:op_true ~extra_nonce:(Cstruct.create 8)
        ~witness_root:None ~network_type:Consensus.Regtest () in
    { real with Types.transactions = [ other ] })

(* The real transactions with the coinbase witness inflated past the 4 MB
   serialized-size limit.  txids (and so the merkle root) are unchanged;
   only the witness commitment can tell these bytes are not the block.
   BlockOversized used to run before the witness check. *)
let test_witness_inflated_past_size_limit =
  attack ~junk:(fun real ->
    match real.Types.transactions with
    | cb :: rest ->
      let big = Cstruct.create 4_000_100 in
      let w = match cb.Types.witnesses with
        | [] -> [ { Types.items = [ big ] } ]
        | x :: tl -> { Types.items = x.Types.items @ [ big ] } :: tl in
      { real with Types.transactions = { cb with Types.witnesses = w } :: rest }
    | [] -> assert false)

(* BIP 152 path: a cmpctblock for the real header carrying one prefilled
   non-coinbase tx at index 0 and no short ids reconstructs to header ||
   that tx and reaches the same process_new_block. *)
let test_cmpctblock_prefilled_noncoinbase () =
  attack ~junk:(fun real ->
    let cb = { P2p.header = real.Types.header; nonce = 0L; short_ids = [];
               prefilled_txs = [ { P2p.index = 0; tx = junk_tx } ] } in
    match P2p.reconstruct_block cb (P2p.create_tx_lookup ~k0:0L ~k1:0L []) with
    | P2p.ReconstructComplete b -> b
    | P2p.ReconstructNeedTxs _ -> Alcotest.fail "reconstruction wants txs"
    | P2p.ReconstructFailed e -> Alcotest.failf "reconstruction failed: %s" e)
    ()

(* Controls: the reorder must not let an invalid block through or stop it
   being marked.  A body whose merkle root IS the header's commits the
   header to those transactions, so a failure after the merkle check is a
   verdict on the block and is marked. *)
let test_valid_merkle_no_coinbase_marked () =
  with_chain (fun state tip3 t3 ->
    let b = remine
        { Types.header =
            { version = 4l; prev_block = tip3; merkle_root = merkle_of [ junk_tx ];
              timestamp = Int32.add t3 600l;
              bits = Consensus.regtest.pow_limit; nonce = 0l };
          transactions = [ junk_tx ] } in
    accept_hdr state b;
    (match deliver ~peer_id:attacker state b with
     | Ok () -> Alcotest.fail "block with no coinbase accepted"
     | Error e ->
       Alcotest.(check string) "rejected as no-coinbase"
         (Validation.block_error_to_string Validation.BlockNoCoinbase) e);
    Alcotest.(check bool) "no-coinbase block with a matching merkle root IS marked"
      true (is_invalid state b);
    Alcotest.(check int) "tip unchanged" 3 state.Sync.blocks_synced)

(* A real block (matching merkle root, valid witness commitment) whose
   coinbase carries a wrong BIP34 height: a verdict, marked. *)
let test_valid_merkle_bad_bip34_marked () =
  with_chain (fun state tip3 t3 ->
    let real = build_block ~prev_hash:tip3 ~height:7 ~prev_time:t3 () in
    accept_hdr state real;
    (match deliver ~peer_id:attacker state real with
     | Ok () -> Alcotest.fail "wrong-BIP34 block accepted"
     | Error _ -> ());
    Alcotest.(check bool) "wrong-BIP34 block with a matching merkle root IS marked"
      true (is_invalid state real);
    Alcotest.(check int) "tip unchanged" 3 state.Sync.blocks_synced)

(* Check-order unit pins on Validation.check_block directly. *)
let check net blk height =
  Validation.check_block ~network:net blk height
    ~expected_bits:Consensus.regtest.pow_limit ~median_time:0l ~skip_pow:true ()

let test_unit_order () =
  let net = Consensus.regtest in
  let real = build_block ~prev_hash:Types.zero_hash ~height:1
      ~prev_time:1_700_000_000l () in
  (match check net real 1 with
   | Ok () -> ()
   | Error e -> Alcotest.failf "real block: %s" (Validation.block_error_to_string e));
  let expect name blk want =
    match check net blk 1 with
    | Ok () -> Alcotest.failf "%s: accepted" name
    | Error e ->
      Alcotest.(check string) name want (Validation.block_error_to_string e);
      Alcotest.(check bool) (name ^ " is a mutation (not marked)") true
        (Sync.is_block_mutation_error e)
  in
  expect "one non-coinbase tx under a real header"
    { real with Types.transactions = [ junk_tx ] }
    (Validation.block_error_to_string Validation.BlockBadMerkleRoot);
  expect "empty body under a real header"
    { real with Types.transactions = [] }
    (Validation.block_error_to_string Validation.BlockBadMerkleRoot)

let () =
  Alcotest.run "checkblock_merkle_first"
    [ ( "junk body under a real header is not marked",
        [ Alcotest.test_case "one non-coinbase tx (audit C4 repro)" `Quick
            test_one_noncoinbase_tx;
          Alcotest.test_case "empty body" `Quick test_empty_body;
          Alcotest.test_case "coinbase with the wrong BIP34 height" `Quick
            test_wrong_bip34_coinbase;
          Alcotest.test_case "witness inflated past the size limit" `Quick
            test_witness_inflated_past_size_limit;
          Alcotest.test_case "cmpctblock: prefilled non-coinbase tx at index 0"
            `Quick test_cmpctblock_prefilled_noncoinbase;
          Alcotest.test_case "check_block reports the merkle mismatch first"
            `Quick test_unit_order ] );
      ( "invalid block with a matching merkle root is still marked",
        [ Alcotest.test_case "no coinbase" `Quick
            test_valid_merkle_no_coinbase_marked;
          Alcotest.test_case "wrong BIP34 height" `Quick
            test_valid_merkle_bad_bip34_marked ] ) ]
