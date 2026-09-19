(* Control: post-IBD gap-fill must CONNECT the batch it is served.

   2026-09-19T19:40:53→19:51:43Z, range 419311→450000 on rebuilt 4c08fb4
   (101b458 is an ancestor). Base control passed, then:
     STALLED — no net progress: max tip 419311 < 450000 for 600s
   Own log: `Post-IBD gap-fill: requesting 2289 missing blocks
   [419312..421311] from peer 0`. Replay server served all 2289 (1.7 GB)
   in five minutes, then sat idle. Zero heights advanced.

   Two bugs, one line of log:
     (1) [419312..421311] is 2000 heights; 2289 = 2000 + (max_reorg_depth
         288 + the validated tip itself). Snapshot/prune has no bodies at
         or below the UTXO tip, so the fork-below walk treats the active
         chain as a competing fork and getdatas 289 unsconnectable
         historical hashes.
     (2) connect_stored_blocks resolves the next height via the ACTIVE
         height index, which has no rows above blocks_synced. Out-of-order
         (and even in-order-then-drain) bodies sit on disk and are never
         connected. process_new_block of tip+1 can connect one block; the
         rest of the batch is "delivered and not connected".

   101b458's HOL-cap test models IBD request_blocks, not this FullySynced
   HeadersMsg path. A green unit test is not evidence the node can run.

   Command (red on HEAD, green after):
     dune exec --no-buffer test/test_gapfill_connect_none.exe
*)

open Camlcoin

let n_headers = 2010
let n_validated = 10
let gap = n_headers - n_validated (* 2000, the live [419312..421311] span *)
let min_connect = 32

let make_header ~prev_block ~ts ~nc ~merkle =
  Types.{
    version = 4l;
    prev_block;
    merkle_root = merkle;
    timestamp = ts;
    bits = Consensus.regtest.pow_limit;
    nonce = nc;
  }

(* Campaign snapshot shape: headers far ahead of the UTXO base, height
   index only at/below the validated tip, no bodies anywhere. *)
let build_snapshot_shape ~label ~n_headers ~n_validated =
  let path = Test_tmp.fresh ~label ~mkdir:true () in
  let db = Storage.ChainDB.create path in
  let state = Sync.create_chain_state db Consensus.regtest in
  let genesis = Option.get state.Sync.tip in
  let hashes = Array.make (n_headers + 1) genesis.Sync.hash in
  hashes.(0) <- genesis.Sync.hash;
  let prev = ref genesis in
  for h = 1 to n_headers do
    let hdr =
      make_header ~prev_block:!prev.Sync.hash
        ~ts:(Int32.of_int (1_600_000_000 + (h * 600)))
        ~nc:(Int32.of_int h) ~merkle:Types.zero_hash
    in
    let hash = Crypto.compute_block_hash hdr in
    let work =
      Consensus.work_add !prev.Sync.total_work
        (Consensus.work_from_compact hdr.Types.bits)
    in
    let e : Sync.header_entry =
      { header = hdr; hash; height = h; total_work = work }
    in
    Hashtbl.replace state.Sync.headers (Cstruct.to_string hash) e;
    if h <= n_validated then Storage.ChainDB.set_height_hash db h hash;
    state.Sync.tip <- Some e;
    state.Sync.headers_synced <- h;
    hashes.(h) <- hash;
    prev := e
  done;
  state.Sync.blocks_synced <- n_validated;
  state.Sync.sync_state <- Sync.FullySynced;
  (state, db, hashes)

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

let build_coinbase_block ~(prev_hash : Types.hash256) ~(height : int)
    ~(prev_time : int32) : Types.block =
  let extra_nonce = Cstruct.create 8 in
  Cstruct.LE.set_uint64 extra_nonce 0 (Int64.of_int height);
  let placeholder =
    Mining.create_coinbase ~height ~total_fee:0L ~payout_script:op_true
      ~extra_nonce ~witness_root:None ~network_type:Consensus.Regtest ()
  in
  let witness_root = Mining.compute_witness_merkle_root [ placeholder ] in
  let coinbase =
    Mining.create_coinbase ~height ~total_fee:0L ~payout_script:op_true
      ~extra_nonce ~witness_root:(Some witness_root)
      ~network_type:Consensus.Regtest ()
  in
  let merkle_root, _ = Crypto.merkle_root [ Crypto.compute_txid coinbase ] in
  let header : Types.block_header =
    {
      version = 4l;
      prev_block = prev_hash;
      merkle_root;
      timestamp = Int32.add prev_time 600l;
      bits = Consensus.regtest.pow_limit;
      nonce = 0l;
    }
  in
  remine { Types.header; transactions = [ coinbase ] }

(* ---- (1) 2289 vs 2000: do not request snapshot holes ---- *)

let test_request_set_is_tip_plus_one_capped_not_2289 () =
  let state, db, hashes =
    build_snapshot_shape ~label:"gapfill_count" ~n_headers ~n_validated
  in
  Fun.protect
    ~finally:(fun () -> try Storage.ChainDB.close db with _ -> ())
    (fun () ->
      Alcotest.(check int) "header tip" n_headers
        (match state.Sync.tip with Some t -> t.Sync.height | None -> -1);
      Alcotest.(check int) "block tip" n_validated state.Sync.blocks_synced;
      let got = Sync.gapfill_blocks_to_download state in
      let n = List.length got in
      Printf.printf
        "gapfill_blocks_to_download count=%d (want <=%d, live was %d)\n%!" n
        Sync.max_blocks_per_peer
        (gap + Sync.max_reorg_depth + 1);
      Alcotest.(check bool)
        (Printf.sprintf
           "requested %d hashes for a %d-height span; live was 2289 = 2000 + \
            289 snapshot holes. Cap is max_blocks_per_peer=%d starting at \
            tip+1"
           n gap Sync.max_blocks_per_peer)
        true
        (n > 0 && n <= Sync.max_blocks_per_peer);
      (match got with
      | h :: _ ->
        Alcotest.(check bool) "first hash is block_tip+1" true
          (Cstruct.equal h hashes.(n_validated + 1))
      | [] -> Alcotest.fail "nothing to request at the connect cursor");
      List.iter
        (fun h ->
          match Hashtbl.find_opt state.Sync.headers (Cstruct.to_string h) with
          | Some e ->
            Alcotest.(check bool)
              (Printf.sprintf
                 "requested height %d is above the validated tip %d \
                  (snapshot hole)"
                 e.Sync.height n_validated)
              true
              (e.Sync.height > n_validated)
          | None -> Alcotest.fail "requested hash is not on the header chain")
        got)

(* ---- (2)+(3) delivered bodies must connect, at a RATE ---- *)

let with_mined_gap ?(store = true) ~n f =
  Test_tmp.with_dir ~label:"gapfill_drain" ~mkdir:true (fun path ->
      let db = Storage.ChainDB.create path in
      Fun.protect
        ~finally:(fun () -> try Storage.ChainDB.close db with _ -> ())
        (fun () ->
          let state = Sync.create_chain_state db Consensus.regtest in
          let genesis = Option.get state.Sync.tip in
          let bodies = Array.make (n + 1) (None : Types.block option) in
          let prev_hash = ref genesis.Sync.hash in
          let prev_time = ref genesis.Sync.header.Types.timestamp in
          for h = 1 to n do
            let b =
              build_coinbase_block ~prev_hash:!prev_hash ~height:h
                ~prev_time:!prev_time
            in
            (match Sync.validate_header state b.Types.header with
            | Ok entry -> Sync.accept_header state entry
            | Error e -> Alcotest.failf "validate_header height %d: %s" h e);
            if store then
              Storage.ChainDB.store_block db
                (Crypto.compute_block_hash b.Types.header)
                b;
            bodies.(h) <- Some b;
            prev_hash := Crypto.compute_block_hash b.Types.header;
            prev_time := b.Types.header.Types.timestamp
          done;
          (* Snapshot/post-IBD shape: headers ahead, height index only at
             genesis, blocks_synced still 0. [store] puts bodies on disk
             for the drain path; the rate path delivers them via
             process_new_block so has_block does not short-circuit. *)
          state.Sync.blocks_synced <- 0;
          state.Sync.sync_state <- Sync.FullySynced;
          f state db bodies))

let test_connect_stored_drains_batch_without_height_index () =
  with_mined_gap ~n:min_connect (fun state _db _bodies ->
      let n = Sync.connect_stored_blocks state in
      Printf.printf "connect_stored_blocks drained %d (want %d)\n%!" n
        min_connect;
      Alcotest.(check int)
        "height-index-only drain connects nothing above the validated tip \
         (live: 2289 delivered, 0 connected)"
        min_connect n;
      Alcotest.(check int) "tip advanced through the whole batch" min_connect
        state.Sync.blocks_synced)

let test_outoforder_process_new_block_rate () =
  with_mined_gap ~store:false ~n:min_connect (fun state _db bodies ->
      let connects_at = ref [] in
      (* Deliver FAR FIRST, then the connect cursor — the live getdata
         of 2000 bodies is not guaranteed in-order, and even in-order the
         drain after tip+1 used to stop. *)
      for h = min_connect downto 1 do
        match bodies.(h) with
        | None -> Alcotest.failf "missing body %d" h
        | Some b ->
          let before = state.Sync.blocks_synced in
          (match
             Lwt_main.run (Sync.process_new_block ~f_requested:true state b)
           with
          | Ok () -> ()
          | Error e ->
            Alcotest.failf "process_new_block height %d: %s" h e);
          let after = state.Sync.blocks_synced in
          if after > before then
            connects_at := (h, after - before, after) :: !connects_at
      done;
      let events = List.rev !connects_at in
      Printf.printf "process_new_block reverse-delivery: tip=%d events=%s\n%!"
        state.Sync.blocks_synced
        (String.concat ","
           (List.map
              (fun (h, n, tip) ->
                Printf.sprintf "deliv%d:+%d->%d" h n tip)
              events));
      Alcotest.(check int)
        "delivered every body and connected NONE of them (or only tip+1)"
        min_connect state.Sync.blocks_synced;
      (match events with
      | [] ->
        Alcotest.fail
          "connect cursor never advanced after the batch landed — \
           delivered-and-not-connected"
      | (h, n, _) :: _ ->
        Alcotest.(check int)
          "first connect happens when tip+1 is delivered, not after a \
           600s stall"
          1 h;
        Alcotest.(check bool)
          (Printf.sprintf
             "delivering tip+1 drained %d stored successors (rate, not \
              eventual one-by-one re-request)"
             n)
          true (n >= min_connect)))

let () =
  Alcotest.run "gapfill_connect_none"
    [
      ( "request-set",
        [
          Alcotest.test_case
            "2000-header snapshot gap requests 16 at tip+1, not 2289"
            `Quick test_request_set_is_tip_plus_one_capped_not_2289;
        ] );
      ( "drain",
        [
          Alcotest.test_case
            "connect_stored_blocks drains a stored batch with no height-index \
             rows above the tip" `Quick
            test_connect_stored_drains_batch_without_height_index;
        ] );
      ( "rate",
        [
          Alcotest.test_case
            "out-of-order process_new_block connects the whole batch when \
             tip+1 lands" `Quick test_outoforder_process_new_block_rate;
        ] );
    ]
