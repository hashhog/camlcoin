(* test/test_loadtxoutset_live.ml
   --------------------------------------------------------------------------
   AssumeUTXO LIVE-RPC dual-chainstate wiring (camlcoin pilot completion).

   The function-level gate (test_dual_chainstate_spec.ml) proves the
   dual-chainstate MACHINERY works.  THIS test proves the LIVE RPC PATH is
   wired to that machinery, the way lunarblock's RPC was wired (a39dd42):

     - handle_loadtxoutset, on a regtest snapshot, loads the snapshot into the
       active chainstate AND spins up the REAL background validator
       (activate_snapshot_with_background + run_background_to_completion) that
       re-connects every block genesis -> base into its OWN separate coins
       store and compares the recomputed UTXO hash to the assumeutxo value.
     - handle_getchainstates then reports the snapshot chainstate:
         * validated  = snapshot_is_validated (false while bg runs / after a
                        mismatch, true after a match)
         * snapshot_blockhash = the snapshot base block hash.

   Two end-to-end scenarios through the LIVE RPC:
     (1) ACCEPT  — a consistent snapshot whose genesis->base replay matches the
                   committed hash: loadtxoutset succeeds, getchainstates reports
                   validated=true + snapshot_blockhash.
     (2) REJECT  — a snapshot whose committed hash matches the snapshot FILE
                   (so the load-time content-hash gate passes) but is
                   INCONSISTENT with the actual chain history: the background
                   re-derivation produces a different UTXO set, the mismatch is
                   caught in the background (Core's AbortNode equivalent), and
                   getchainstates reports validated=false (snapshot invalid).
                   loadtxoutset itself still returns success — Core runs
                   MaybeValidateSnapshot asynchronously, so the verdict is
                   surfaced via the chainstate state, not the RPC return.

   Core reference: bitcoin-core/src/validation.cpp ActivateSnapshot (5588) /
   PopulateAndValidateSnapshot (5775+) / MaybeValidateSnapshot (5967), and
   rpc/blockchain.cpp make_chain_data (3462-3519) for getchainstates fields.
   Cross-impl reference: lunarblock a39dd42 (src/rpc.lua loadtxoutset wiring).

   Unique temp dirs per run (Filename.temp_dir is OS-unique); the regtest
   AssumeUTXO whitelist is registered fresh per case and CLEARED in teardown so
   no verifier-probe state leaks across runs. *)

open Camlcoin

(* ── pass/fail bookkeeping (mirrors the other camlcoin specs) ────────────── *)

let pass_count = ref 0
let fail_count = ref 0

let test_passed name =
  incr pass_count;
  Printf.printf "  [PASS] %s\n%!" name

let test_failed name msg =
  incr fail_count;
  Printf.printf "  [FAIL] %s: %s\n%!" name msg

let check name cond msg = if cond then () else failwith (name ^ ": " ^ msg)

let dir_counter = ref 0
let unique_dir (label : string) : string =
  incr dir_counter;
  Filename.temp_dir
    (Printf.sprintf "camlcoin_ltx_%s_%d_" label !dir_counter) ""

let unique_file (label : string) : string =
  incr dir_counter;
  let d = Filename.temp_dir (Printf.sprintf "camlcoin_ltxf_%s_%d_" label !dir_counter) "" in
  Filename.concat d "snapshot.dat"

let rec rm_rf path =
  if Sys.file_exists path then begin
    if Sys.is_directory path then begin
      Array.iter (fun f -> rm_rf (Filename.concat path f)) (Sys.readdir path);
      (try Unix.rmdir path with _ -> ())
    end else
      (try Unix.unlink path with _ -> ())
  end

(* ── block-building helpers (same shape proven in test_dual_chainstate_spec) ─ *)

let regtest = Consensus.regtest

let p2pkh_script = Cstruct.of_string
  "\x76\xa9\x14\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\
   \x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x88\xac"

(* Commitment-free, witnessless coinbase (no SegWit witness commitment output)
   so the bg replay and the snapshot UTXO set stay byte-for-byte identical.
   BIP34 active on regtest from height 1 => height-encoded scriptSig + tag. *)
let make_coinbase_tx ~(height : int) ~(value : int64)
    ~(script_pubkey : Cstruct.t) : Types.transaction =
  let height_enc = Consensus.encode_height_in_coinbase height in
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

let make_block ~(prev_hash : Types.hash256)
    ~(txs : Types.transaction list) ~(timestamp : int32)
    ~(bits : int32) : Types.block * Types.hash256 =
  let txids = List.map Crypto.compute_txid txs in
  let (merkle_root, _mutated) = Crypto.merkle_root txids in
  let base_header : Types.block_header = {
    Types.version = 0x20000000l;
    prev_block = prev_hash;
    merkle_root;
    timestamp;
    bits;
    nonce = 0l;
  } in
  let rec grind nonce =
    let header = { base_header with nonce } in
    let hash = Crypto.compute_block_hash header in
    if Consensus.hash_meets_target hash header.bits then (header, hash)
    else grind (Int32.add nonce 1l)
  in
  let (header, hash) = grind 0l in
  ({ Types.header; transactions = txs }, hash)

type built = { block : Types.block; hash : Types.hash256; height : int }

let build_chain (n : int) : built list =
  let prev = ref regtest.Consensus.genesis_hash in
  let base_ts = regtest.Consensus.genesis_header.timestamp in
  let acc = ref [] in
  for h = 1 to n do
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

(* Build a snapshot chainstate (own ChainDB) by connecting the chain's coins
   into it, then dump it to a Core-format snapshot file.  Returns the file
   path, the snapshot's UTXO-set hash (its HASH_SERIALIZED commitment), the
   base block hash, and the dir to clean up. *)
let dump_snapshot_for (blocks : built list)
    ?(extra_coins : (Types.outpoint * Utxo.coin) list = [])
    () : string * Types.hash256 * Types.hash256 * int * string =
  let dir = unique_dir "dumpsrc" in
  let db_path = Filename.concat dir "src" in
  let cs =
    Assume_utxo.create_chainstate ~id:Assume_utxo.Snapshot ~db_path ~network:regtest
  in
  List.iter (fun b ->
    match Assume_utxo.connect_block_to_cache ~cache:cs.Assume_utxo.utxo_cache
            ~block:b.block ~height:b.height ~network_type:Consensus.Mainnet () with
    | Ok _ -> ()
    | Error e -> failwith ("dump connect_block_to_cache failed: " ^ e)
  ) blocks;
  (* Optionally inject extra spurious coins so the snapshot's coin SET (and
     thus its committed hash) is INTERNALLY consistent but inconsistent with
     the real genesis->base replay — the bg-mismatch falsification. *)
  List.iter (fun (op, coin) ->
    Utxo.UtxoCache.add_coin cs.Assume_utxo.utxo_cache op coin
      ~possible_overwrite:false
  ) extra_coins;
  let _ = Lwt_main.run (Utxo.UtxoCache.flush cs.Assume_utxo.utxo_cache) in
  let base = List.nth blocks (List.length blocks - 1) in
  (* dump_snapshot uses chainstate.tip_hash as the base block hash. *)
  cs.Assume_utxo.tip_hash <- base.hash;
  cs.Assume_utxo.tip_height <- base.height;
  let snap_path = unique_file "snap" in
  (match Assume_utxo.dump_snapshot ~chainstate:cs ~network:regtest
           ~output_path:snap_path () with
   | Ok _meta -> ()
   | Error e -> failwith ("dump_snapshot failed: " ^ e));
  let snap_hash = Assume_utxo.compute_utxo_hash_from_db cs.Assume_utxo.db in
  Storage.ChainDB.close cs.Assume_utxo.db;
  rm_rf dir;
  (snap_path, snap_hash, base.hash, base.height, dir)

(* Build the LIVE RPC context whose chain block store + header table are seeded
   with [blocks], so the wired handle_loadtxoutset's bg validator can read
   genesis->base via the same accessors the daemon uses.  The active tip is
   pinned to genesis with deliberately LOW work so the B7 work-vs-active-tip
   gate passes (the base header carries HIGH work) — mirroring the existing
   B5/B7 tests in test_assume_utxo.ml. *)
let make_live_ctx (blocks : built list)
    : Rpc.rpc_context * string * Storage.ChainDB.t =
  let dir = unique_dir "node" in
  let db_path = Filename.concat dir "chain" in
  let db = Storage.ChainDB.create db_path in
  let utxo = Utxo.UtxoSet.create db in
  let chain = Sync.create_chain_state db regtest in
  (* Seed block bodies + headers + the height index so get_block /
     get_header_at_height resolve for the bg replay. *)
  let work = ref 1 in
  List.iter (fun b ->
    Storage.ChainDB.store_block db b.hash b.block;
    Storage.ChainDB.store_block_header db b.hash b.block.Types.header;
    Storage.ChainDB.set_height_hash db b.height b.hash;
    incr work;
    let tw = Cstruct.create 32 in
    (* Monotone increasing work per height (little-endian byte 0 is enough for
       these short chains); the base header ends up with the most work. *)
    Cstruct.set_uint8 tw 0 (!work land 0xff);
    let entry : Sync.header_entry = {
      Sync.header = b.block.Types.header;
      hash = b.hash;
      height = b.height;
      total_work = tw;
    } in
    Hashtbl.replace chain.Sync.headers (Cstruct.to_string b.hash) entry
  ) blocks;
  (* Pin the ACTIVE tip to genesis with the LOWEST work (0) so the snapshot
     base (work >= 2) strictly exceeds it: B7 "work does not exceed active
     chainstate" must pass.  We do NOT advance chain.tip to the header tip. *)
  let genesis_entry : Sync.header_entry = {
    Sync.header = regtest.Consensus.genesis_header;
    hash = regtest.Consensus.genesis_hash;
    height = 0;
    total_work = Cstruct.create 32;  (* zero work *)
  } in
  Hashtbl.replace chain.Sync.headers
    (Cstruct.to_string regtest.Consensus.genesis_hash) genesis_entry;
  chain.Sync.tip <- Some genesis_entry;
  let mp = Mempool.create ~require_standard:false ~verify_scripts:false
             ~utxo ~current_height:0 () in
  let pm = Peer_manager.create regtest in
  let fe = Fee_estimation.create () in
  let ctx : Rpc.rpc_context = {
    chain; mempool = mp; peer_manager = pm;
    wallet = None; wallet_manager = None; fee_estimator = fe;
    network = regtest; filter_index = None; utxo = None;
    data_dir = Some dir; snapshot_activation = None;
  } in
  (ctx, dir, db)

(* Pull validated + snapshot_blockhash out of a getchainstates JSON response. *)
let read_getchainstates (j : Yojson.Safe.t) : bool * string option =
  match j with
  | `Assoc top ->
    (match List.assoc_opt "chainstates" top with
     | Some (`List (cs :: _)) ->
       (match cs with
        | `Assoc fields ->
          let validated =
            match List.assoc_opt "validated" fields with
            | Some (`Bool b) -> b
            | _ -> failwith "getchainstates: missing/invalid 'validated'"
          in
          let snap =
            match List.assoc_opt "snapshot_blockhash" fields with
            | Some (`String s) -> Some s
            | _ -> None
          in
          (validated, snap)
        | _ -> failwith "getchainstates: chainstate is not an object")
     | _ -> failwith "getchainstates: missing 'chainstates' array")
  | _ -> failwith "getchainstates: response is not an object"

(* ── (0) sanity: with NO snapshot active, getchainstates is the single
   fully-validated chainstate (validated=true, snapshot_blockhash omitted). *)
let test_no_snapshot_default () =
  let name = "(0) getchainstates with no snapshot: validated=true, no snapshot_blockhash" in
  try
    let blocks = build_chain 2 in
    let (ctx, node_dir, db) = make_live_ctx blocks in
    let resp = Rpc.handle_getchainstates ctx in
    let (validated, snap) = read_getchainstates resp in
    check name validated "no-snapshot chainstate must report validated=true";
    check name (snap = None)
      "no-snapshot chainstate must omit snapshot_blockhash";
    Storage.ChainDB.close db;
    rm_rf node_dir;
    test_passed name
  with
  | Failure msg -> test_failed name msg
  | e -> test_failed name (Printexc.to_string e)

(* ── (1) ACCEPT through the LIVE RPC: loadtxoutset -> real bg validator runs
   genesis->base -> match -> getchainstates validated=true + snapshot_blockhash. *)
let test_live_loadtxoutset_accept () =
  let name = "(1) LIVE loadtxoutset ACCEPT: bg validates genesis->base, getchainstates validated=true" in
  Assume_utxo.clear_regtest_assumeutxo ();
  try
    let n = 4 in
    let blocks = build_chain n in
    let base = List.nth blocks (n - 1) in
    (* Snapshot whose coin set == the real genesis->base replay. *)
    let (snap_path, snap_hash, base_hash, base_height, _) =
      dump_snapshot_for blocks () in
    check name (Cstruct.equal base_hash base.hash) "dump base hash sanity";

    (* Register the regtest AssumeUTXO entry committing to the snapshot's hash
       (Core regtest m_assumeutxo_data; coins_count 0 disables the count
       pre-check). *)
    Assume_utxo.register_regtest_assumeutxo {
      Assume_utxo.height = base_height;
      blockhash = base_hash;
      coins_count = 0L;
      coins_hash = snap_hash;
      chain_tx_count = Int64.of_int (n + 1);
    };

    let (ctx, node_dir, db) = make_live_ctx blocks in

    (* BEFORE: no snapshot -> getchainstates is the single validated chainstate. *)
    let (v0, s0) = read_getchainstates (Rpc.handle_getchainstates ctx) in
    check name (v0 && s0 = None) "pre-load: single validated chainstate";

    (* LIVE call. *)
    let result = Rpc.handle_loadtxoutset ctx [`String snap_path] in
    (match result with
     | Error e -> failwith ("loadtxoutset returned Error: " ^ e)
     | Ok _ -> ());

    (* The wiring must have recorded an activation on the context. *)
    check name (ctx.Rpc.snapshot_activation <> None)
      "loadtxoutset must record a snapshot activation (dual-chainstate wired)";

    (* getchainstates must now report the snapshot chainstate: validated=true
       (bg matched) + snapshot_blockhash = the base. *)
    let (validated, snap) = read_getchainstates (Rpc.handle_getchainstates ctx) in
    check name validated
      "ACCEPT: getchainstates.validated must be true after a matching bg run";
    let expect_hex = Types.hash256_to_hex_display base_hash in
    check name (snap = Some expect_hex)
      (Printf.sprintf "snapshot_blockhash must equal the base (%s), got %s"
         expect_hex (match snap with Some s -> s | None -> "(none)"));

    (* Cross-check the machinery verdict directly. *)
    (match ctx.Rpc.snapshot_activation with
     | Some act ->
       check name
         (Assume_utxo.snapshot_is_validated act.Assume_utxo.snapshot)
         "snapshot chainstate must be marked Validated";
       check name
         (not (Assume_utxo.snapshot_is_invalid act.Assume_utxo.snapshot))
         "a validated snapshot must not also be invalid";
       Storage.ChainDB.close act.Assume_utxo.background.Assume_utxo.db;
       Storage.ChainDB.close act.Assume_utxo.snapshot.Assume_utxo.db
     | None -> ());

    Storage.ChainDB.close db;
    rm_rf node_dir;
    rm_rf (Filename.dirname snap_path);
    Assume_utxo.clear_regtest_assumeutxo ();
    test_passed name
  with
  | Failure msg -> Assume_utxo.clear_regtest_assumeutxo (); test_failed name msg
  | e -> Assume_utxo.clear_regtest_assumeutxo ();
         test_failed name (Printexc.to_string e)

(* ── (2) ⭐ REJECT through the LIVE RPC (falsification): a snapshot whose
   committed hash matches the snapshot FILE (load-time gate passes) but is
   INCONSISTENT with the real chain history -> the bg re-derivation mismatches
   -> snapshot marked Invalid -> getchainstates validated=false.  THE most
   important assertion: the mismatch still rejects through the LIVE path, and
   a corrupt snapshot is NEVER silently reported validated. *)
let test_live_loadtxoutset_reject () =
  let name = "(2) LIVE loadtxoutset REJECT: bg-inconsistent snapshot -> getchainstates validated=false" in
  Assume_utxo.clear_regtest_assumeutxo ();
  try
    let n = 4 in
    let blocks = build_chain n in
    let base = List.nth blocks (n - 1) in

    (* Dump a snapshot that contains an EXTRA spurious coin not produced by the
       real genesis->base replay.  The snapshot file is internally consistent
       (it hashes to snap_hash), so the load-time content-hash gate PASSES when
       we commit to snap_hash — but the bg re-connects the real blocks and
       derives a DIFFERENT set, so the background comparison MISMATCHES.  This
       is exactly the threat the dual-chainstate exists to catch: a snapshot
       whose hash matches its own commitment but disagrees with the chain. *)
    let spurious_op =
      { Types.txid = Types.hash256_of_hex
          "abababababababababababababababababababababababababababababababab";
        vout = 0l } in
    let spurious_coin : Utxo.coin = {
      Utxo.txout = { Types.value = 999L; script_pubkey = Cstruct.of_string "\x51" };
      height = 1; is_coinbase = false;
    } in
    let (snap_path, snap_hash, base_hash, base_height, _) =
      dump_snapshot_for blocks ~extra_coins:[ (spurious_op, spurious_coin) ] () in
    check name (Cstruct.equal base_hash base.hash) "dump base hash sanity";

    (* Commit to the snapshot's OWN hash so the load-time gate passes; the bg
       (which replays the real blocks WITHOUT the spurious coin) will not
       reproduce snap_hash -> background mismatch. *)
    Assume_utxo.register_regtest_assumeutxo {
      Assume_utxo.height = base_height;
      blockhash = base_hash;
      coins_count = 0L;
      coins_hash = snap_hash;
      chain_tx_count = Int64.of_int (n + 1);
    };

    let (ctx, node_dir, db) = make_live_ctx blocks in

    (* LIVE call.  Per the Core async model, loadtxoutset itself SUCCEEDS even
       though the background pass will reject; the verdict is surfaced via the
       chainstate state, read by getchainstates. *)
    let result = Rpc.handle_loadtxoutset ctx [`String snap_path] in
    (match result with
     | Error e ->
       (* If the load-time gate had been the rejecter we'd see an Error here;
          that is NOT this scenario (we committed to the snapshot's own hash so
          the load gate passes and the BACKGROUND is the rejecter). *)
       failwith ("loadtxoutset unexpectedly returned a load-time Error "
                 ^ "(the bg, not the load gate, should reject here): " ^ e)
     | Ok _ -> ());

    check name (ctx.Rpc.snapshot_activation <> None)
      "loadtxoutset must still record the activation (so the invalid verdict is visible)";

    (* getchainstates must report the snapshot chainstate as NOT validated. *)
    let (validated, snap) = read_getchainstates (Rpc.handle_getchainstates ctx) in
    check name (not validated)
      "REJECT: getchainstates.validated must be FALSE for a bg-mismatched snapshot";
    let expect_hex = Types.hash256_to_hex_display base_hash in
    check name (snap = Some expect_hex)
      "REJECT: snapshot_blockhash must still be the base (the snapshot IS active, just invalid)";

    (* The machinery must have marked the snapshot Invalid (Core AbortNode). *)
    (match ctx.Rpc.snapshot_activation with
     | Some act ->
       check name
         (Assume_utxo.snapshot_is_invalid act.Assume_utxo.snapshot)
         "snapshot chainstate must be marked Invalid on a bg mismatch";
       check name
         (not (Assume_utxo.snapshot_is_validated act.Assume_utxo.snapshot))
         "an invalid snapshot must NOT also be validated";
       (* It REALLY did the work: bg connected every block genesis->base before
          catching the mismatch (not short-circuited). *)
       check name
         (act.Assume_utxo.bg_validation.Assume_utxo.validated_height = base_height)
         "bg must have connected every block genesis->base before the mismatch";
       Storage.ChainDB.close act.Assume_utxo.background.Assume_utxo.db;
       Storage.ChainDB.close act.Assume_utxo.snapshot.Assume_utxo.db
     | None -> ());

    Storage.ChainDB.close db;
    rm_rf node_dir;
    rm_rf (Filename.dirname snap_path);
    Assume_utxo.clear_regtest_assumeutxo ();
    test_passed name
  with
  | Failure msg -> Assume_utxo.clear_regtest_assumeutxo (); test_failed name msg
  | e -> Assume_utxo.clear_regtest_assumeutxo ();
         test_failed name (Printexc.to_string e)

let () =
  Random.self_init ();
  Printf.printf
    "Running AssumeUTXO LIVE loadtxoutset/getchainstates wiring spec...\n%!";
  test_no_snapshot_default ();
  test_live_loadtxoutset_accept ();
  test_live_loadtxoutset_reject ();
  Printf.printf "\nLive loadtxoutset spec: %d passed, %d failed\n%!"
    !pass_count !fail_count;
  if !fail_count > 0 then exit 1
  else Printf.printf "All live loadtxoutset spec tests passed!\n%!"
