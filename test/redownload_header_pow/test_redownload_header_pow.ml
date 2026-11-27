(* REDOWNLOAD must run Core's header checks before it stores a header
   (cffix-camlcoin-redownload-header-pow).

   Core: every HEADERS message goes through CheckHeadersPoW and
   CheckHeadersAreContinuous in ProcessHeadersMessage (net_processing.cpp)
   BEFORE the low-work sync state machine sees it, and the headers that
   HeadersSyncState releases from REDOWNLOAD are handed to
   ProcessNewBlockHeaders -> AcceptBlockHeader, which runs CheckBlockHeader
   (proof of work) and ContextualCheckBlockHeader (bad-diffbits,
   time-too-old against the median time past, time-too-new) and refuses a
   child of a failed block (bad-prevblk).

   camlcoin's [Sync.process_redownload_headers] checked only continuity,
   the headerssync difficulty-transition bound and (on release) the exact
   nBits.  Once the redownloaded chain crossed minimum_chain_work
   ([process_all_remaining]) the commitment check stops, so the peer could
   send headers that were never committed in PRESYNC, and every one of them
   was written to [chain_state.headers], the header DB and the header tip
   without proof of work, without the MTP / future-time checks and even on
   top of an invalidated block.

   Setup: regtest params (every header is 2 units of work, PoW trivially
   minable) with minimum_chain_work lowered to 20, so the chain crosses at
   height 9.  PRESYNC runs over 30 real headers; REDOWNLOAD then gets
   headers that diverge from that chain after the crossing.

     dune build @test/redownload_header_pow/runtest *)

open Camlcoin

let base = Consensus.regtest

(* 10 regtest headers' worth of work (regtest work per header = 2). *)
let min_work =
  let w = ref Consensus.zero_work in
  for _ = 1 to 10 do
    w := Consensus.work_add !w (Consensus.work_from_compact base.pow_limit)
  done;
  !w

let network = { base with Consensus.minimum_chain_work = min_work }

let genesis_hash = Crypto.compute_block_hash network.genesis_header
let genesis_ts = network.genesis_header.Types.timestamp
let ts_at h = Int32.add genesis_ts (Int32.of_int (600 * h))

let merkle_of ~tag ~height =
  let m = Cstruct.create 32 in
  Cstruct.LE.set_uint32 m 0 (Int32.of_int height);
  Cstruct.LE.set_uint32 m 4 (Int32.of_int tag);
  m

let pow_ok (h : Types.block_header) =
  Consensus.check_proof_of_work (Crypto.compute_block_hash h) h.bits network

(* Search nonces from 0 until [want] holds: [true] mines a valid header,
   [false] picks the first nonce whose hash misses the target (nonce 0
   about half the time on regtest). *)
let with_pow ~want (h : Types.block_header) : Types.block_header =
  let rec go n =
    let h' = { h with Types.nonce = n } in
    if pow_ok h' = want then h' else go (Int32.add n 1l)
  in
  go 0l

let header ?(want_pow = true) ?timestamp ~tag ~prev ~height () =
  let timestamp = match timestamp with Some t -> t | None -> ts_at height in
  with_pow ~want:want_pow
    { Types.version = 4l; prev_block = prev;
      merkle_root = merkle_of ~tag ~height; timestamp;
      bits = network.pow_limit; nonce = 0l }

(* Chain of [n] headers on top of [prev] (at [from - 1]). *)
let chain_from ?(want_pow = true) ~tag ~prev ~from n =
  let rec go acc prev h =
    if h >= from + n then List.rev acc
    else
      let hd = header ~want_pow ~tag ~prev ~height:h () in
      go (hd :: acc) (Crypto.compute_block_hash hd) (h + 1)
  in
  go [] prev from

let hash = Crypto.compute_block_hash
let stored chain (h : Types.block_header) =
  Hashtbl.mem chain.Sync.headers (Cstruct.to_string (hash h))

let honest = chain_from ~tag:1 ~prev:genesis_hash ~from:1 30
let honest_upto n = List.filteri (fun i _ -> i < n) honest
let honest_at h = List.nth honest (h - 1)

(* A chain_state at genesis plus a peer that has finished PRESYNC over the
   30 honest headers and is now in REDOWNLOAD. *)
let with_redownload f =
  Test_tmp.with_chaindb (fun db ->
      let chain = Sync.create_chain_state db network in
      let start = Option.get (Sync.get_tip chain) in
      let ps = Sync.create_presync_state ~peer_id:7 ~chain_start:start in
      (match Sync.process_presync_headers ~ps ~headers:honest ~network with
       | Ok _ -> ()
       | Error e -> Alcotest.failf "PRESYNC over honest headers: %s" e);
      Alcotest.(check bool) "PRESYNC crossed minimum_chain_work" true
        (Sync.get_header_sync_phase ps = `Redownload);
      f chain ps)

let redownload chain ps headers =
  Sync.process_redownload_headers ~ps ~headers ~chain_state:chain

let tip_height chain = (Option.get (Sync.get_tip chain)).Sync.height

let none_stored chain hs = List.for_all (fun h -> not (stored chain h)) hs
let slice lo hi = List.filteri (fun i _ -> i >= lo && i < hi) honest

(* Master finalizes REDOWNLOAD (state Synced) as soon as the batch that
   crosses minimum_chain_work has drained the buffer, and every later batch
   from the peer takes the direct path, which does check PoW.  The hole is
   the crossing batch itself: everything in it after the crossing (up to
   ~1999 headers in a full message), and everything still buffered from
   earlier batches, was released with only the nBits check.  So each
   invalid header below rides in the batch that crosses. *)

(* 1. One REDOWNLOAD batch: honest 1..12 (crossing at 9), then 8 headers
      whose hash misses their own target.  Core: CheckHeadersPoW fails the
      message. *)
let test_bad_pow_in_batch_not_stored () =
  with_redownload (fun chain ps ->
      let bad = chain_from ~want_pow:false ~tag:0xBAD
          ~prev:(hash (honest_at 12)) ~from:13 8 in
      Alcotest.(check bool) "fixture: bad headers really fail PoW" true
        (List.for_all (fun h -> not (pow_ok h)) bad);
      let r = redownload chain ps (honest_upto 12 @ bad) in
      Alcotest.(check bool) "no header without proof of work is stored" true
        (none_stored chain bad);
      Alcotest.(check bool) "header tip is not a header without PoW" true
        (tip_height chain <= 12);
      Alcotest.(check bool) "batch is refused" true (Result.is_error r))

(* 2. Honest 1..8 buffered (below the threshold), then a batch of headers
      without PoW from 9 on: their own claimed work makes the crossing, so
      the commitment check is already off for them. *)
let test_bad_pow_makes_the_crossing_not_stored () =
  with_redownload (fun chain ps ->
      (match redownload chain ps (honest_upto 8) with
       | Ok [] -> ()
       | Ok l -> Alcotest.failf "released %d headers below the threshold"
                   (List.length l)
       | Error e -> Alcotest.failf "honest 1..8 rejected: %s" e);
      let bad = chain_from ~want_pow:false ~tag:0xBAD
          ~prev:(hash (honest_at 8)) ~from:9 12 in
      let r = redownload chain ps bad in
      Alcotest.(check bool) "no header without proof of work is stored" true
        (none_stored chain bad);
      Alcotest.(check bool) "header tip is not a header without PoW" true
        (tip_height chain <= 8);
      Alcotest.(check bool) "batch is refused" true (Result.is_error r))

(* 3. Valid PoW but timestamp not above the median time past
      (Core time-too-old), after the crossing in the same batch. *)
let test_mtp_violation_not_stored () =
  with_redownload (fun chain ps ->
      let old = header ~timestamp:(Int32.add genesis_ts 1l) ~tag:0x0D
          ~prev:(hash (honest_at 12)) ~height:13 () in
      let r = redownload chain ps (honest_upto 12 @ [ old ]) in
      Alcotest.(check bool) "header at or below MTP is not stored" false
        (stored chain old);
      Alcotest.(check int) "honest prefix stored, header tip at 12" 12
        (tip_height chain);
      Alcotest.(check bool) "batch is refused" true (Result.is_error r))

(* 4. Valid PoW, timestamp 3 hours in the future (Core time-too-new). *)
let test_future_time_not_stored () =
  with_redownload (fun chain ps ->
      let future =
        Int32.of_float (Unix.gettimeofday () +. 3. *. 3600.) in
      let h = header ~timestamp:future ~tag:0x0F
          ~prev:(hash (honest_at 12)) ~height:13 () in
      let r = redownload chain ps (honest_upto 12 @ [ h ]) in
      Alcotest.(check bool) "header > 2h in the future is not stored" false
        (stored chain h);
      Alcotest.(check int) "honest prefix stored, header tip at 12" 12
        (tip_height chain);
      Alcotest.(check bool) "batch is refused" true (Result.is_error r))

(* 5. Honest 1..5 are already in the header table and 5 has been
      invalidated; the peer redownloads honest 1..30 from genesis.  1..5
      are skipped as known; 6.. are children of a failed block
      (Core bad-prevblk). *)
let test_child_of_invalid_not_stored () =
  Test_tmp.with_chaindb (fun db ->
      let chain = Sync.create_chain_state db network in
      let start = Option.get (Sync.get_tip chain) in
      (match Sync.process_headers chain (honest_upto 5) with
       | Ok 5 -> ()
       | Ok n -> Alcotest.failf "direct accept of 1..5 stored %d" n
       | Error e -> Alcotest.failf "direct accept of 1..5: %s" e);
      Hashtbl.replace chain.Sync.invalidated_blocks
        (Cstruct.to_string (hash (honest_at 5))) ();
      let ps = Sync.create_presync_state ~peer_id:7 ~chain_start:start in
      (match Sync.process_presync_headers ~ps ~headers:honest ~network with
       | Ok _ -> ()
       | Error e -> Alcotest.failf "PRESYNC over honest headers: %s" e);
      let rest = slice 5 30 in
      let r = redownload chain ps honest in
      Alcotest.(check bool) "children of an invalid block are not stored" true
        (none_stored chain rest);
      Alcotest.(check bool) "batch is refused" true (Result.is_error r))

(* 6. Guard for the nBits check the release loop used to do by hand (now
      in [validate_header]): valid PoW for its own claimed nBits, but not
      the nBits regtest requires (Core bad-diffbits).  master caught this
      too, so this case passes on both trees; it is here so the move into
      [validate_header] cannot lose it. *)
let test_bad_diffbits_not_stored () =
  with_redownload (fun chain ps ->
      let h = with_pow ~want:true
          { Types.version = 4l; prev_block = hash (honest_at 12);
            merkle_root = merkle_of ~tag:0xD1F ~height:13;
            timestamp = ts_at 13; bits = 0x200fffffl; nonce = 0l } in
      let _ = redownload chain ps (honest_upto 12 @ [ h ]) in
      Alcotest.(check bool) "header with the wrong nBits is not stored" false
        (stored chain h);
      Alcotest.(check int) "honest prefix stored, header tip at 12" 12
        (tip_height chain))

(* 7. Control: an honest low-work sync still completes, in one batch and
      in several (1..5 and 6..8 buffered below the threshold, 9..30 cross
      it and release everything). *)
let test_valid_lowwork_sync_completes () =
  with_redownload (fun chain ps ->
      (match redownload chain ps honest with
       | Ok _ -> ()
       | Error e -> Alcotest.failf "honest REDOWNLOAD rejected: %s" e);
      Alcotest.(check bool) "every honest header stored" true
        (List.for_all (stored chain) honest);
      Alcotest.(check int) "header tip at 30" 30 (tip_height chain);
      Alcotest.(check bool) "peer state is Synced" true
        (Sync.get_header_sync_phase ps = `Synced))

let test_valid_lowwork_sync_in_batches () =
  with_redownload (fun chain ps ->
      List.iter (fun (lo, hi) ->
          match redownload chain ps (slice lo hi) with
          | Ok _ -> ()
          | Error e ->
            Alcotest.failf "honest REDOWNLOAD batch %d..%d rejected: %s"
              (lo + 1) hi e)
        [ (0, 5); (5, 8); (8, 30) ];
      Alcotest.(check bool) "every honest header stored" true
        (List.for_all (stored chain) honest);
      Alcotest.(check int) "header tip at 30" 30 (tip_height chain);
      Alcotest.(check bool) "peer state is Synced" true
        (Sync.get_header_sync_phase ps = `Synced))

let () =
  Logs.set_level (Some Logs.Error);
  Alcotest.run "redownload_header_pow"
    [ "redownload",
      [ Alcotest.test_case "bad_pow_in_batch_not_stored" `Quick
          test_bad_pow_in_batch_not_stored;
        Alcotest.test_case "bad_pow_makes_the_crossing_not_stored" `Quick
          test_bad_pow_makes_the_crossing_not_stored;
        Alcotest.test_case "mtp_violation_not_stored" `Quick
          test_mtp_violation_not_stored;
        Alcotest.test_case "future_time_not_stored" `Quick
          test_future_time_not_stored;
        Alcotest.test_case "child_of_invalid_not_stored" `Quick
          test_child_of_invalid_not_stored;
        Alcotest.test_case "bad_diffbits_not_stored" `Quick
          test_bad_diffbits_not_stored;
        Alcotest.test_case "valid_lowwork_sync_completes" `Quick
          test_valid_lowwork_sync_completes;
        Alcotest.test_case "valid_lowwork_sync_in_batches" `Quick
          test_valid_lowwork_sync_in_batches ] ]
