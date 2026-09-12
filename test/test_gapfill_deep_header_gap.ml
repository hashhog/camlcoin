(* Control: at-tip gap-fill must request block_tip+1 when the header tip
   is far ahead of the validated tip.

   Campaign 315000→340000 on 76d7a58 stalled at the snapshot base:
     At-tip gap fill FOUND NOTHING TO REQUEST: block tip 315000,
     header tip 596696, walked 4096 header(s) (max 4096)
   The old walk started at the header tip and gave up after 4096 hops,
   never reaching block_tip+1. Core's FindNextBlocksToDownload walks
   forward from the last connected block regardless of how far headers
   are ahead.

   Command (fails if next_blocks_to_download walks 4096 back from tip):
     dune exec --no-buffer test/test_gapfill_deep_header_gap.exe
*)

open Camlcoin

let test_db_base = "/tmp/camlcoin_test_gapfill_deep_header_gap"
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

(* The 2026-09-12 stall: walk BACKWARD from the header tip, cap at 4096,
   collect [block_tip+1, block_tip+count]. Returns [] whenever
   header_tip - block_tip > 4096. Kept here as the negative control. *)
let legacy_walk_from_tip ?(count = 16) ?(max_walk = 4096)
    (state : Sync.chain_state) : Types.hash256 list =
  let block_height = state.Sync.blocks_synced in
  let want_lo = block_height + 1 in
  let want_hi = block_height + count in
  let acc = ref [] in
  let steps = ref 0 in
  let cur = ref state.Sync.tip in
  let stop = ref false in
  while not !stop do
    match !cur with
    | None -> stop := true
    | Some (e : Sync.header_entry) ->
      if !steps >= max_walk || e.Sync.height < want_lo then
        stop := true
      else begin
        if e.Sync.height <= want_hi then
          acc := e.Sync.hash :: !acc;
        incr steps;
        cur := Hashtbl.find_opt state.Sync.headers
                 (Cstruct.to_string e.Sync.header.Types.prev_block)
      end
  done;
  !acc

(* Build an in-memory header chain of [n_headers] past genesis, with the
   validated tip (blocks_synced) at [n_validated]. Mirrors the campaign
   snapshot: headers far ahead of the UTXO base, no height-index rows
   for the gap. *)
let build_header_ahead_chain ~name ~n_headers ~n_validated =
  use_db name;
  let db = Storage.ChainDB.create !test_db_path in
  let state = Sync.create_chain_state db Consensus.regtest in
  let genesis = Option.get state.Sync.tip in
  let hashes = Array.make (n_headers + 1) genesis.Sync.hash in
  hashes.(0) <- genesis.Sync.hash;
  let prev = ref genesis in
  for h = 1 to n_headers do
    let hdr = make_header ~prev_block:!prev.Sync.hash
        ~ts:(Int32.of_int (1_600_000_000 + (h * 600)))
        ~nc:(Int32.of_int h) in
    let hash = Crypto.compute_block_hash hdr in
    let work = Consensus.work_add !prev.Sync.total_work
        (Consensus.work_from_compact hdr.Types.bits) in
    let e : Sync.header_entry =
      { header = hdr; hash; height = h; total_work = work } in
    Hashtbl.replace state.Sync.headers (Cstruct.to_string hash) e;
    state.Sync.tip <- Some e;
    state.Sync.headers_synced <- h;
    hashes.(h) <- hash;
    prev := e
  done;
  state.Sync.blocks_synced <- n_validated;
  (state, db, hashes)

let test_deep_gap_requests_block_tip_plus_one () =
  let n_headers = 4200 in
  let n_validated = 10 in
  let state, db, hashes =
    build_header_ahead_chain ~name:"deep" ~n_headers ~n_validated in
  Alcotest.(check int) "header tip is 4200" n_headers
    (match state.Sync.tip with Some t -> t.Sync.height | None -> -1);
  Alcotest.(check int) "block tip is 10" n_validated
    state.Sync.blocks_synced;

  (* Negative control: the 4096-from-tip walk finds nothing. *)
  let legacy = legacy_walk_from_tip ~count:16 ~max_walk:4096 state in
  Alcotest.(check int)
    "legacy 4096-from-tip walk returns nothing on a 4190-header gap"
    0 (List.length legacy);

  (* Production: must return exactly heights 11..26. *)
  let got = Sync.next_blocks_to_download ~count:16 state in
  Alcotest.(check int) "requests 16 blocks at the FRONT of the gap"
    16 (List.length got);
  List.iteri (fun i hash ->
    let h = n_validated + 1 + i in
    Alcotest.(check bool)
      (Printf.sprintf "requested hash %d is height %d" i h)
      true (Cstruct.equal hash hashes.(h))
  ) got;
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_small_gap_still_works () =
  let n_headers = 20 in
  let n_validated = 10 in
  let state, db, hashes =
    build_header_ahead_chain ~name:"small" ~n_headers ~n_validated in
  let got = Sync.next_blocks_to_download ~count:16 state in
  (* Header tip 20, so only 10 gap blocks (11..20). *)
  Alcotest.(check int) "small gap yields 10 hashes" 10 (List.length got);
  List.iteri (fun i hash ->
    Alcotest.(check bool)
      (Printf.sprintf "small-gap hash %d is height %d" i (11 + i))
      true (Cstruct.equal hash hashes.(11 + i))
  ) got;
  (* Legacy walk also works on a small gap (the 2.9-day incident was 398). *)
  let legacy = legacy_walk_from_tip ~count:16 ~max_walk:4096 state in
  Alcotest.(check int) "legacy walk still works on a small gap"
    10 (List.length legacy);
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_no_gap_is_empty () =
  let state, db, _ =
    build_header_ahead_chain ~name:"nogap" ~n_headers:10 ~n_validated:10 in
  let got = Sync.next_blocks_to_download ~count:16 state in
  Alcotest.(check int) "no gap → nothing to request" 0 (List.length got);
  Storage.ChainDB.close db;
  cleanup_test_db ()

let () =
  Alcotest.run "gapfill_deep_header_gap" [
    "at-tip gap fill", [
      Alcotest.test_case
        "deep gap (header tip - block tip > 4096) requests block_tip+1"
        `Quick test_deep_gap_requests_block_tip_plus_one;
      Alcotest.test_case
        "small gap still requests block_tip+1"
        `Quick test_small_gap_still_works;
      Alcotest.test_case
        "no gap returns empty"
        `Quick test_no_gap_is_empty;
    ];
  ]
