(* test/test_dual_chainstate_spec.ml
   --------------------------------------------------------------------------
   AssumeUTXO REAL dual-chainstate background validation (camlcoin pilot).

   This is the functional gate for the dual-chainstate pilot.  It proves that
   snapshot activation spins up a SECOND (background) chainstate with its OWN
   separate UTXO store, that the background chainstate REALLY re-connects every
   block genesis -> base into that store (not a counter), that a correct-hash
   snapshot is ACCEPTED (validated flips true), and — most importantly — that a
   deliberately-WRONG assumed hash is REJECTED (the falsification).

   Core reference: bitcoin-core/src/validation.cpp.
     ActivateSnapshot (5588): snapshot loaded into the active chainstate.
     AddChainstate (6170): genesis-validated chainstate demoted to a BACKGROUND
       chainstate (m_target_blockhash = snapshot base), keeping its OWN coins DB.
     MaybeValidateSnapshot (5967): at the base, compute the bg coins'
       HASH_SERIALIZED and compare to au_data.hash_serialized.  MATCH ->
       VALIDATED + retire bg; MISMATCH -> INVALID + AbortNode.

   Cross-impl reference: lunarblock a39dd42
   (spec/assumeutxo_dual_chainstate_spec.lua).
   --------------------------------------------------------------------------

   Unique temp paths per run.  [Filename.temp_dir] uses a fresh OS-unique
   directory each call; combined with a per-process counter this guarantees no
   two builds/runs reuse leftover RocksDB state (which would false-green the
   wrong-hash falsification by letting the bg store survive across runs).  This
   is the trap that bit lunarblock (os.time-based paths) — we avoid it
   structurally. *)

open Camlcoin

(* ── pass/fail bookkeeping (mirrors test_assume_utxo.ml's style) ─────────── *)

let pass_count = ref 0
let fail_count = ref 0

let test_passed name =
  incr pass_count;
  Printf.printf "  [PASS] %s\n%!" name

let test_failed name msg =
  incr fail_count;
  Printf.printf "  [FAIL] %s: %s\n%!" name msg

let check name cond msg = if cond then () else failwith (name ^ ": " ^ msg)

(* Per-process / per-call unique temp directory.  Filename.temp_dir is
   itself collision-safe; the counter is belt-and-suspenders so that even a
   single test that needs several distinct stores never collides. *)
let dir_counter = ref 0
let unique_dir (label : string) : string =
  incr dir_counter;
  Filename.temp_dir
    (Printf.sprintf "camlcoin_dualcs_%s_%d_" label !dir_counter) ""

let rec rm_rf path =
  if Sys.file_exists path then begin
    if Sys.is_directory path then begin
      Array.iter (fun f -> rm_rf (Filename.concat path f)) (Sys.readdir path);
      (try Unix.rmdir path with _ -> ())
    end else
      (try Unix.unlink path with _ -> ())
  end

(* ── block-building helpers ──────────────────────────────────────────────── *)

(* A plain, spendable P2PKH-shaped coinbase with NO SegWit witness commitment.
   We deliberately avoid Mining.create_block_template (which inserts an
   OP_RETURN witness commitment output): the background validator's
   connect_block_to_cache adds every output unconditionally, so a witness
   commitment output would diverge the bg UTXO set from any reference set that
   filtered it.  A commitment-free, witnessless coinbase keeps the bg replay
   and the reference replay byte-for-byte identical.

   BIP34 is active on regtest from height 1, so the coinbase scriptSig must
   begin with the serialized height (Consensus.encode_height_in_coinbase). We
   append a per-height tag byte so coinbase txids are unique across heights
   (BIP30) and pad to the >= 2-byte minimum. *)
let make_coinbase_tx ~(height : int) ~(value : int64)
    ~(script_pubkey : Cstruct.t) : Types.transaction =
  let height_enc = Consensus.encode_height_in_coinbase height in
  (* tag byte makes each coinbase txid distinct; guarantees length >= 2. *)
  let tag = Cstruct.create 2 in
  Cstruct.set_uint8 tag 0 0x4b;
  Cstruct.set_uint8 tag 1 (height land 0xff);
  let script_sig = Cstruct.concat [height_enc; tag] in
  {
    Types.version = 1l;
    inputs = [ {
      Types.previous_output = { Types.txid = Types.zero_hash; vout = -1l };
      script_sig;
      sequence = 0xFFFFFFFFl;
    } ];
    outputs = [ { Types.value; script_pubkey } ];
    witnesses = [];
    locktime = 0l;
  }

(* Build a real, mined regtest block at [height] on top of [prev_hash].
   Real PoW: regtest pow_limit (0x207fffff) is trivially satisfiable, so we
   grind the nonce until the hash meets target (accept_block enforces PoW with
   skip_pow=false — these are GENUINE proof-of-work blocks, not skip-pow). *)
let make_block ~(prev_hash : Types.hash256)
    ~(txs : Types.transaction list) ~(timestamp : int32)
    ~(bits : int32) : Types.block * Types.hash256 =
  let txids = List.map Crypto.compute_txid txs in
  let (merkle_root, _mutated) = Crypto.merkle_root txids in
  let base_header : Types.block_header = {
    Types.version = 0x20000000l;   (* version >= 2: satisfies BIP34/65/66 *)
    prev_block = prev_hash;
    merkle_root;
    timestamp;
    bits;
    nonce = 0l;
  } in
  (* Grind nonce for real PoW. *)
  let rec grind nonce =
    let header = { base_header with nonce } in
    let hash = Crypto.compute_block_hash header in
    if Consensus.hash_meets_target hash header.bits then (header, hash)
    else grind (Int32.add nonce 1l)
  in
  let (header, hash) = grind 0l in
  ({ Types.header; transactions = txs }, hash)

let regtest = Consensus.regtest
let p2pkh_script = Cstruct.of_string
  "\x76\xa9\x14\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\
   \x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x88\xac"

type built = {
  block : Types.block;
  hash  : Types.hash256;
  height : int;
}

(* Build [n] real coinbase blocks (heights 1..n) on top of the regtest
   genesis.  Returns the ordered list. *)
let build_chain (n : int) : built list =
  let prev = ref regtest.Consensus.genesis_hash in
  let base_ts = regtest.Consensus.genesis_header.timestamp in
  let acc = ref [] in
  for h = 1 to n do
    (* heights 1..n are all < 150 (regtest first halving), subsidy = 50 BTC,
       which equals the MAINNET subsidy at these heights — important because
       connect_block_to_cache defaults to Mainnet for its coinbase-value
       ceiling check. *)
    let cb = make_coinbase_tx ~height:h ~value:5_000_000_000L
               ~script_pubkey:p2pkh_script in
    let ts = Int32.add base_ts (Int32.of_int h) in
    let (block, hash) =
      make_block ~prev_hash:!prev ~txs:[cb] ~timestamp:ts
        ~bits:regtest.Consensus.pow_limit in
    acc := { block; hash; height = h } :: !acc;
    prev := hash
  done;
  List.rev !acc

(* Populate a Sync.chain_state's header table + the underlying ChainDB block
   store with the built chain so that get_header_at_height / get_block resolve
   for the background validator.  This is the shared blockman that Core's
   background chainstate reads block bodies from. *)
let seed_blockstore (chain : Sync.chain_state) (db : Storage.ChainDB.t)
    (blocks : built list) : unit =
  let cum = ref (Consensus.work_from_compact regtest.Consensus.genesis_header.bits) in
  List.iter (fun b ->
    Storage.ChainDB.store_block db b.hash b.block;
    Storage.ChainDB.store_block_header db b.hash b.block.Types.header;
    cum := Consensus.work_add !cum
             (Consensus.work_from_compact b.block.Types.header.bits);
    let entry : Sync.header_entry = {
      Sync.header = b.block.Types.header;
      hash = b.hash;
      height = b.height;
      total_work = Cstruct.of_string (Cstruct.to_string !cum);
    } in
    Sync.accept_header chain entry
  ) blocks

(* Independently compute the UTXO-set hash at the base by connecting the same
   blocks into a SEPARATE reference store via connect_block_to_cache (the exact
   logic the bg validator uses).  This is the ground-truth "correct" assumed
   hash — derived independently of the bg run. *)
let reference_utxo_hash (blocks : built list) : Types.hash256 =
  let dir = unique_dir "ref" in
  let db = Storage.ChainDB.create (Filename.concat dir "chain") in
  let cache = Utxo.UtxoCache.create (Utxo.DbView.create db) in
  List.iter (fun b ->
    match Assume_utxo.connect_block_to_cache ~cache ~block:b.block
            ~height:b.height ~network_type:Consensus.Mainnet () with
    | Ok _ -> ()
    | Error e -> failwith ("reference connect_block_to_cache failed: " ^ e)
  ) blocks;
  let _ = Lwt_main.run (Utxo.UtxoCache.flush cache) in
  let h = Assume_utxo.compute_utxo_hash_from_db db in
  Storage.ChainDB.close db;
  rm_rf dir;
  h

(* Build a fresh snapshot ("active") chainstate object.  We don't need a real
   loaded snapshot file for these unit-level tests — the snapshot chainstate's
   only role in the activation/validation path is to carry the
   assumeutxo_state that the bg pass flips.  We construct it via the same
   create_chainstate helper load_snapshot uses, then mark it Unvalidated +
   record the base block as its from_snapshot_blockhash, exactly as
   load_snapshot does. *)
let make_snapshot_chainstate ~(base_hash : Types.hash256)
    ~(base_height : int) : Assume_utxo.chainstate * Storage.ChainDB.t * string =
  let dir = unique_dir "snap" in
  let db_path = Filename.concat dir "snapshot" in
  let cs = Assume_utxo.create_chainstate
             ~id:Assume_utxo.Snapshot ~db_path ~network:regtest in
  cs.Assume_utxo.assumeutxo_state <- Assume_utxo.Unvalidated;
  cs.Assume_utxo.from_snapshot_blockhash <- Some base_hash;
  cs.Assume_utxo.tip_hash <- base_hash;
  cs.Assume_utxo.tip_height <- base_height;
  (cs, cs.Assume_utxo.db, dir)

(* ── tests ───────────────────────────────────────────────────────────────── *)

(* (a) The background chainstate's coins store is a DIFFERENT object/directory
   from the active store (proven by identity + aliasing: an active-store write
   is NOT visible in the bg store). *)
let test_separate_store () =
  let name = "(a) bg chainstate uses a SEPARATE UTXO store (not aliased)" in
  try
    let blocks = build_chain 3 in
    let base = (List.nth blocks 2) in
    let (snapshot, _snap_db, snap_dir) =
      make_snapshot_chainstate ~base_hash:base.hash ~base_height:3 in

    let bg_chain_dir = unique_dir "bg" in
    let bg_db_path = Filename.concat bg_chain_dir "bg" in
    let activation = Assume_utxo.activate_snapshot_with_background
        ~snapshot ~bg_db_path
        ~assumed_hash:(Cstruct.create 32)
        ~base_height:3
        ~get_block:(fun _ -> None)
        ~get_header_at_height:(fun _ -> None)
        ~network:regtest () in
    let bg = activation.Assume_utxo.background in

    (* Distinct ChainDB objects. *)
    check name (snapshot.Assume_utxo.db != bg.Assume_utxo.db)
      "bg db must be a distinct object from the active snapshot db";
    check name (snapshot.Assume_utxo.utxo_cache != bg.Assume_utxo.utxo_cache)
      "bg utxo_cache must be a distinct object from the active cache";

    (* Aliasing falsification: write a probe coin into the ACTIVE store and
       confirm it is NOT visible in the bg store, and vice-versa. *)
    let probe_txid = Types.hash256_of_hex
      "7777777777777777777777777777777777777777777777777777777777777777" in
    let coin : Utxo.coin = {
      Utxo.txout = { Types.value = 123L; script_pubkey = Cstruct.of_string "\x51" };
      height = 1; is_coinbase = false;
    } in
    let probe_op = { Types.txid = probe_txid; vout = 0l } in
    Utxo.UtxoCache.add_coin snapshot.Assume_utxo.utxo_cache probe_op coin
      ~possible_overwrite:false;
    let _ = Lwt_main.run (Utxo.UtxoCache.flush snapshot.Assume_utxo.utxo_cache) in
    check name
      (Utxo.UtxoCache.get_coin bg.Assume_utxo.utxo_cache probe_op = None)
      "active-store write must NOT be visible in the separate bg store";

    Storage.ChainDB.close snapshot.Assume_utxo.db;
    Storage.ChainDB.close bg.Assume_utxo.db;
    rm_rf snap_dir; rm_rf bg_chain_dir;
    test_passed name
  with
  | Failure msg -> test_failed name msg
  | e -> test_failed name (Printexc.to_string e)

(* (b) The bg chainstate REALLY connects genesis -> base into its OWN store:
   after the run, the bg UTXO set hash == the independently-computed reference
   set (NOT empty, NOT a counter), and the bg reached the base height. *)
let test_real_connection () =
  let name = "(b) bg REALLY connects genesis->base into its own store" in
  try
    let blocks = build_chain 4 in
    let base = List.nth blocks 3 in
    let correct_hash = reference_utxo_hash blocks in

    let (snapshot, _snap_db, snap_dir) =
      make_snapshot_chainstate ~base_hash:base.hash ~base_height:4 in

    (* Shared blockman: a Sync.chain_state over the bg's OWN db, seeded with
       all blocks + headers so get_block / get_header_at_height resolve. *)
    let bg_chain_dir = unique_dir "bg" in
    let bg_db_path = Filename.concat bg_chain_dir "bg" in

    let activation = Assume_utxo.activate_snapshot_with_background
        ~snapshot ~bg_db_path
        ~assumed_hash:correct_hash
        ~base_height:4
        ~get_block:(fun _ -> None)   (* replaced below *)
        ~get_header_at_height:(fun _ -> None)
        ~network:regtest () in
    let bg = activation.Assume_utxo.background in

    (* Header/block index lives in a Sync.chain_state over the bg db. *)
    let hdr_chain = Sync.create_chain_state bg.Assume_utxo.db regtest in
    seed_blockstore hdr_chain bg.Assume_utxo.db blocks;
    let by_hash = Hashtbl.create 16 in
    List.iter (fun b -> Hashtbl.replace by_hash (Cstruct.to_string b.hash) b.block)
      blocks;
    let activation = {
      activation with
      Assume_utxo.get_block =
        (fun h -> Hashtbl.find_opt by_hash (Cstruct.to_string h));
      get_header_at_height = (fun h -> Sync.get_header_at_height hdr_chain h);
    } in

    let (validated, err) = Assume_utxo.run_background_to_completion activation in
    check name validated
      ("bg replay should match the reference set: " ^
       (match err with Some e -> e | None -> "(no error)"));
    check name (activation.Assume_utxo.bg_validation.Assume_utxo.validated_height = 4)
      "bg must have connected every block up to the base height";

    (* Cross-check the bg store hash equals the reference (not empty). *)
    let empty_hash = Crypto.sha256d Cstruct.empty in
    let bg_hash =
      let _ = Lwt_main.run (Utxo.UtxoCache.flush bg.Assume_utxo.utxo_cache) in
      Assume_utxo.compute_utxo_hash_from_db bg.Assume_utxo.db in
    check name (Cstruct.equal bg_hash correct_hash)
      "bg UTXO set hash must equal the independently-computed reference set";
    check name (not (Cstruct.equal bg_hash empty_hash))
      "bg UTXO set must be non-empty (proves real connection, not a counter)";

    Storage.ChainDB.close snapshot.Assume_utxo.db;
    Storage.ChainDB.close bg.Assume_utxo.db;
    rm_rf snap_dir; rm_rf bg_chain_dir;
    test_passed name
  with
  | Failure msg -> test_failed name msg
  | e -> test_failed name (Printexc.to_string e)

(* (c) ACCEPT: a correct assumed hash flips the snapshot to validated. *)
let test_accept_correct_hash () =
  let name = "(c) ACCEPT: correct assumed hash flips snapshot validated=true" in
  try
    let blocks = build_chain 4 in
    let base = List.nth blocks 3 in
    let correct_hash = reference_utxo_hash blocks in

    let (snapshot, _snap_db, snap_dir) =
      make_snapshot_chainstate ~base_hash:base.hash ~base_height:4 in

    let bg_chain_dir = unique_dir "bg" in
    let bg_db_path = Filename.concat bg_chain_dir "bg" in
    let activation = Assume_utxo.activate_snapshot_with_background
        ~snapshot ~bg_db_path ~assumed_hash:correct_hash ~base_height:4
        ~get_block:(fun _ -> None) ~get_header_at_height:(fun _ -> None)
        ~network:regtest () in
    let bg = activation.Assume_utxo.background in
    let hdr_chain = Sync.create_chain_state bg.Assume_utxo.db regtest in
    seed_blockstore hdr_chain bg.Assume_utxo.db blocks;
    let by_hash = Hashtbl.create 16 in
    List.iter (fun b -> Hashtbl.replace by_hash (Cstruct.to_string b.hash) b.block) blocks;
    let activation = { activation with
      Assume_utxo.get_block = (fun h -> Hashtbl.find_opt by_hash (Cstruct.to_string h));
      get_header_at_height = (fun h -> Sync.get_header_at_height hdr_chain h) } in

    (* BEFORE the run: snapshot must be UNVALIDATED. *)
    check name (not (Assume_utxo.snapshot_is_validated snapshot))
      "snapshot must start UNVALIDATED (validated=false)";

    let (validated, err) = Assume_utxo.run_background_to_completion activation in
    check name validated
      ("background validation should ACCEPT: " ^
       (match err with Some e -> e | None -> "(no error)"));
    check name (Assume_utxo.snapshot_is_validated snapshot)
      "snapshot must flip to VALIDATED after a correct-hash match";
    check name (not (Assume_utxo.snapshot_is_invalid snapshot))
      "validated snapshot must not also be marked invalid";

    Storage.ChainDB.close snapshot.Assume_utxo.db;
    Storage.ChainDB.close bg.Assume_utxo.db;
    rm_rf snap_dir; rm_rf bg_chain_dir;
    test_passed name
  with
  | Failure msg -> test_failed name msg
  | e -> test_failed name (Printexc.to_string e)

(* (d) ⭐ REJECT (falsification): a deliberately-WRONG assumed hash marks the
   snapshot invalid.  The bg connected every block (REAL work) and then caught
   the mismatch — it is NOT validated and surfaces a hard error.  THIS IS THE
   MOST IMPORTANT ASSERTION. *)
let test_reject_wrong_hash () =
  let name = "(d) REJECT: a deliberately-WRONG assumed hash marks snapshot INVALID" in
  try
    let blocks = build_chain 4 in
    let base = List.nth blocks 3 in
    (* DELIBERATELY WRONG assumed hash (all 0xEE): the blocks are real, but the
       assumeutxo commitment is corrupt.  The bg re-derivation must NOT pass. *)
    let wrong_hash = Cstruct.create 32 in
    Cstruct.memset wrong_hash 0xEE;

    let (snapshot, _snap_db, snap_dir) =
      make_snapshot_chainstate ~base_hash:base.hash ~base_height:4 in

    let bg_chain_dir = unique_dir "bg" in
    let bg_db_path = Filename.concat bg_chain_dir "bg" in
    let activation = Assume_utxo.activate_snapshot_with_background
        ~snapshot ~bg_db_path ~assumed_hash:wrong_hash ~base_height:4
        ~get_block:(fun _ -> None) ~get_header_at_height:(fun _ -> None)
        ~network:regtest () in
    let bg = activation.Assume_utxo.background in
    let hdr_chain = Sync.create_chain_state bg.Assume_utxo.db regtest in
    seed_blockstore hdr_chain bg.Assume_utxo.db blocks;
    let by_hash = Hashtbl.create 16 in
    List.iter (fun b -> Hashtbl.replace by_hash (Cstruct.to_string b.hash) b.block) blocks;
    let activation = { activation with
      Assume_utxo.get_block = (fun h -> Hashtbl.find_opt by_hash (Cstruct.to_string h));
      get_header_at_height = (fun h -> Sync.get_header_at_height hdr_chain h) } in

    let (validated, err) = Assume_utxo.run_background_to_completion activation in
    check name (not validated) "wrong-hash snapshot must NOT validate";
    let err_str = match err with Some e -> e | None -> "" in
    check name (err <> None) "a wrong-hash mismatch must surface an error";
    (* The error must name the failure ("mismatch"), Core's wording. *)
    let contains hay needle =
      let nl = String.length needle and hl = String.length hay in
      let rec go i = if i + nl > hl then false
        else if String.sub hay i nl = needle then true else go (i + 1) in
      go 0 in
    check name (contains err_str "mismatch")
      (Printf.sprintf "error must mention 'mismatch', got: %s" err_str);
    (* Snapshot chainstate marked INVALID (Core handle_invalid_snapshot). *)
    check name (Assume_utxo.snapshot_is_invalid snapshot)
      "snapshot must be marked INVALID on a hash mismatch";
    check name (not (Assume_utxo.snapshot_is_validated snapshot))
      "an invalid snapshot must NOT also be validated";
    (* It REALLY did the work: the bg connected every block up to base before
       catching the mismatch (not short-circuited). *)
    check name (activation.Assume_utxo.bg_validation.Assume_utxo.validated_height = 4)
      "bg must have connected every block genesis->base before the mismatch";

    Storage.ChainDB.close snapshot.Assume_utxo.db;
    Storage.ChainDB.close bg.Assume_utxo.db;
    rm_rf snap_dir; rm_rf bg_chain_dir;
    test_passed name
  with
  | Failure msg -> test_failed name msg
  | e -> test_failed name (Printexc.to_string e)

let () =
  Random.self_init ();
  Printf.printf "Running AssumeUTXO dual-chainstate background-validation spec...\n%!";
  test_separate_store ();
  test_real_connection ();
  test_accept_correct_hash ();
  test_reject_wrong_hash ();
  Printf.printf "\nDual-chainstate spec: %d passed, %d failed\n%!"
    !pass_count !fail_count;
  if !fail_count > 0 then exit 1
  else Printf.printf "All dual-chainstate spec tests passed!\n%!"
