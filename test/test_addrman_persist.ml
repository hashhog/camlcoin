(* Axis #2 — persistent bucketed addrman (peers.dat-equivalent) — camlcoin.
   Ports the lunarblock pilot (ac3eb03) restart-persistence proof to OCaml.

   Proves:
     1. RESTART PERSISTENCE: populate an addrman with K addrs across multiple
        source groups (distinct /16 netgroups → distinct buckets), promote a
        few to tried, save to peers.dat, load into a FRESH addrman, and assert
        the addrs + their bucket/position + tried-vs-new classification survive
        VERBATIM (counts match, placement verbatim — NOT a reshuffled flat list).
     2. The bucket_key salt round-trips.
     3. known_addrs is re-joined (full peer_info, not just the bucket key-list).
     4. CORRUPT/MISSING file → empty fallback, no crash.
     5. FALSIFICATION: a fresh addrman with NO load is empty (the pre-impl cold
        start) — so the "survives" assertions are meaningful.

   Reference: bitcoin-core/src/addrman.{h,cpp} Serialize/Unserialize, nKey,
   vvNew[1024][64]/vvTried[256][64], DumpAddresses/DUMP_PEERS_INTERVAL. *)

open Camlcoin

let make_pm () = Peer_manager.create Consensus.mainnet

let add_addr ?(services = 9L) ?(port = 8333) pm addr =
  Peer_manager.add_known_addr pm {
    Peer_manager.address = addr;
    port;
    services;
    last_connected = 0.0;
    last_attempt = 0.0;
    last_success = 0.0;
    failures = 0;
    banned_until = 0.0;
    source = Peer_manager.Addr;
    table_status = Peer_manager.NotInTable;
  }

(* Fresh unique temp datadir per test run; NEVER touches the live datadir. *)
let tmp_dir () =
  let d = Filename.concat (Filename.get_temp_dir_name ())
    (Printf.sprintf "camlcoin-addrman-test-%d-%d" (Unix.getpid ()) (Random.int 1_000_000)) in
  (try Unix.mkdir d 0o755 with Unix.Unix_error (Unix.EEXIST, _, _) -> ());
  d

let rm_rf dir =
  (try
     Sys.readdir dir |> Array.iter (fun f ->
       try Sys.remove (Filename.concat dir f) with _ -> ());
     Unix.rmdir dir
   with _ -> ())

(* Snapshot of a bucket table as a sorted, comparable structure: for each
   bucket, the ORDERED list of addr-keys (order = position). *)
let table_snapshot (tbl : (int, string list) Hashtbl.t) : (int * string list) list =
  Hashtbl.fold (fun b addrs acc -> (b, addrs) :: acc) tbl []
  |> List.sort (fun (a, _) (b, _) -> compare a b)

(* Across multiple source groups: distinct first-two octets → distinct /16
   netgroups → spread across buckets (the eclipse-resistant bucketing). *)
let group_a = ["11.1.0.1"; "11.1.0.2"; "11.1.0.3"]
let group_b = ["22.2.0.1"; "22.2.0.2"]
let group_c = ["33.3.0.1"; "33.3.0.2"; "33.3.0.3"; "33.3.0.4"]
let group_d = ["44.4.0.1"; "44.4.0.2"]
let all_new = group_a @ group_b @ group_c @ group_d
let promote_to_tried = ["22.2.0.1"; "33.3.0.1"; "44.4.0.2"]

(* Build a populated addrman: all addrs in new, then promote a few to tried. *)
let build_populated () =
  let pm = make_pm () in
  List.iter (fun a -> add_addr pm a) all_new;
  List.iter (fun a -> ignore (Peer_manager.move_to_tried_table pm a)) promote_to_tried;
  pm

(* ===== TEST 1: restart persistence via a real peers.dat file ============== *)
let test_file_round_trip () =
  let dir = tmp_dir () in
  Fun.protect ~finally:(fun () -> rm_rf dir) @@ fun () ->
    let pm = build_populated () in

    (* Pre-conditions: non-trivial population across multiple buckets. *)
    let pre_new = Peer_manager.new_table_size pm in
    let pre_tried = Peer_manager.tried_table_size pm in
    Alcotest.(check bool) "populated new table" true (pre_new > 0);
    Alcotest.(check bool) "populated tried table" true (pre_tried > 0);
    Alcotest.(check bool) "multiple new buckets occupied" true
      (List.length (table_snapshot pm.new_table) >= 2);

    let pre_new_snap = table_snapshot pm.new_table in
    let pre_tried_snap = table_snapshot pm.tried_table in
    let pre_key = pm.bucket_key in
    let pre_known =
      Hashtbl.fold (fun k _ acc -> k :: acc) pm.known_addrs []
      |> List.sort compare in

    (* Save to peers.dat, then load into a TRUE fresh addrman. *)
    Peer_manager.save_addrman pm dir;
    Alcotest.(check bool) "peers.dat written" true
      (Sys.file_exists (Filename.concat dir "peers.dat"));

    let pm2 = make_pm () in
    (* Sanity: the fresh pm has a DIFFERENT random salt before load. *)
    Alcotest.(check bool) "fresh pm has different salt pre-load" true
      (pm2.bucket_key <> pre_key);
    (* Load-bearing check: under pm2's OWN (different) salt, re-adding the same
       addrs from source lands them in a DIFFERENT bucket layout.  So the
       verbatim-placement assertions below can only pass if load restored the
       salt AND the stored bucket/position — not by re-bucketing from source. *)
    List.iter (fun a -> add_addr pm2 a) all_new;
    Alcotest.(check bool) "different-salt re-add yields different placement" true
      (table_snapshot pm2.new_table <> pre_new_snap);
    (* Reset pm2 to a clean state, then load from disk. *)
    Hashtbl.reset pm2.new_table;
    Hashtbl.reset pm2.tried_table;
    Hashtbl.reset pm2.known_addrs;
    let ok = Peer_manager.load_addrman pm2 dir in
    Alcotest.(check bool) "load_addrman succeeded" true ok;

    (* Counts match. *)
    Alcotest.(check int) "new count preserved" pre_new (Peer_manager.new_table_size pm2);
    Alcotest.(check int) "tried count preserved" pre_tried (Peer_manager.tried_table_size pm2);

    (* Placement VERBATIM: bucket index + ordered position per bucket. *)
    let cmp_tbl name a b =
      Alcotest.(check (list (pair int (list string)))) name a b in
    cmp_tbl "new-table placement verbatim" pre_new_snap (table_snapshot pm2.new_table);
    cmp_tbl "tried-table placement verbatim" pre_tried_snap (table_snapshot pm2.tried_table);

    (* tried-vs-new classification survives: every promoted addr is in tried. *)
    List.iter (fun a ->
      Alcotest.(check bool) (Printf.sprintf "%s still classified tried" a)
        true (Peer_manager.is_in_tried_table pm2 a)
    ) promote_to_tried;

    (* The salt round-trips verbatim. *)
    Alcotest.(check bool) "bucket_key salt restored verbatim" true
      (pm2.bucket_key = pre_key);

    (* known_addrs re-joined: full peer_info restored for the bucket keys. *)
    let post_known =
      Hashtbl.fold (fun k _ acc -> k :: acc) pm2.known_addrs []
      |> List.sort compare in
    Alcotest.(check (list string)) "known_addrs re-joined" pre_known post_known;
    (* Spot-check a re-joined record carries its full peer_info (port/services). *)
    (match Hashtbl.find_opt pm2.known_addrs "11.1.0.1" with
     | Some info ->
       Alcotest.(check int) "re-joined record keeps port" 8333 info.Peer_manager.port;
       Alcotest.(check bool) "re-joined record keeps services" true
         (info.Peer_manager.services = 9L)
     | None -> Alcotest.fail "expected 11.1.0.1 re-joined in known_addrs")

(* ===== TEST 2: in-process serialize→deserialize round-trip ================ *)
let test_in_process_round_trip () =
  let pm = build_populated () in
  let pre_new_snap = table_snapshot pm.new_table in
  let pre_tried_snap = table_snapshot pm.tried_table in
  let pre_key = pm.bucket_key in

  let json = Peer_manager.serialize_addrman pm in

  let pm2 = make_pm () in
  Peer_manager.deserialize_addrman pm2 json;

  Alcotest.(check (list (pair int (list string)))) "in-proc new verbatim"
    pre_new_snap (table_snapshot pm2.new_table);
  Alcotest.(check (list (pair int (list string)))) "in-proc tried verbatim"
    pre_tried_snap (table_snapshot pm2.tried_table);
  Alcotest.(check bool) "in-proc salt restored" true (pm2.bucket_key = pre_key)

(* ===== TEST 3: missing file → empty fallback, no crash ==================== *)
let test_missing_file () =
  let dir = tmp_dir () in
  Fun.protect ~finally:(fun () -> rm_rf dir) @@ fun () ->
    let pm = make_pm () in
    let ok = Peer_manager.load_addrman pm dir in
    Alcotest.(check bool) "missing file → false" false ok;
    Alcotest.(check int) "missing file → empty new" 0 (Peer_manager.new_table_size pm);
    Alcotest.(check int) "missing file → empty tried" 0 (Peer_manager.tried_table_size pm)

(* ===== TEST 4: corrupt files → empty fallback, no crash ================== *)
let write_file path content =
  let oc = open_out path in output_string oc content; close_out oc

let test_corrupt_files () =
  let dir = tmp_dir () in
  Fun.protect ~finally:(fun () -> rm_rf dir) @@ fun () ->
    let path = Filename.concat dir "peers.dat" in
    let cases = [
      "garbage non-json",            "this is not json {{{{";
      "truncated json",              "{\"version\":1,\"new\":[";
      "empty file",                  "";
      "wrong type (array)",          "[1,2,3]";
      "wrong version",               "{\"version\":999,\"new\":[],\"tried\":[],\"known\":[]}";
      "missing tables",              "{\"version\":1}";
      "null",                        "null";
      "new not a list",              "{\"version\":1,\"new\":42,\"tried\":[],\"known\":[]}";
    ] in
    List.iter (fun (name, content) ->
      write_file path content;
      (* Pre-load the pm with something so we can prove a corrupt load does not
         leave a half-applied / inconsistent state. *)
      let pm = make_pm () in
      add_addr pm "55.5.0.1";
      let ok =
        try Peer_manager.load_addrman pm dir
        with exn ->
          Alcotest.failf "load_addrman raised on %s: %s" name (Printexc.to_string exn)
      in
      Alcotest.(check bool) (Printf.sprintf "%s → false" name) false ok;
      (* Empty fallback: corrupt load resets to a clean empty addrman. *)
      Alcotest.(check int) (Printf.sprintf "%s → empty new" name) 0
        (Peer_manager.new_table_size pm);
      Alcotest.(check int) (Printf.sprintf "%s → empty tried" name) 0
        (Peer_manager.tried_table_size pm)
    ) cases

(* ===== TEST 5: oversized entry count is bounded to the bucket ceiling ===== *)
let test_bounded_load () =
  let dir = tmp_dir () in
  Fun.protect ~finally:(fun () -> rm_rf dir) @@ fun () ->
    let path = Filename.concat dir "peers.dat" in
    (* Forge a single new bucket claiming far more than bucket_size positions. *)
    let huge = List.init 500 (fun i -> Printf.sprintf "\"7.7.%d.%d\"" (i / 256) (i mod 256)) in
    let content = Printf.sprintf
      "{\"version\":1,\"nkey\":\"\",\"asmap_version\":\"\",\
       \"new\":[{\"b\":0,\"a\":[%s]}],\"tried\":[],\"known\":[]}"
      (String.concat "," huge) in
    write_file path content;
    let pm = make_pm () in
    let _ = Peer_manager.load_addrman pm dir in
    (* Per-bucket cap = bucket_size (64); never exceeds it. *)
    let b0 = match Hashtbl.find_opt pm.new_table 0 with Some l -> List.length l | None -> 0 in
    Alcotest.(check bool) "single bucket bounded to bucket_size" true
      (b0 <= Peer_manager.bucket_size);
    Alcotest.(check bool) "total bounded to capacity" true
      (Peer_manager.new_table_size pm <= Peer_manager.bucket_size)

(* ===== TEST 6: FALSIFICATION — pre-impl cold start is empty =============== *)
let test_falsification_cold_start_empty () =
  (* A fresh addrman that NEVER loaded is empty — the pre-impl behaviour the
     persistence fixes.  If this ever fails, the round-trip tests are vacuous. *)
  let pm = make_pm () in
  Alcotest.(check int) "cold-start new empty" 0 (Peer_manager.new_table_size pm);
  Alcotest.(check int) "cold-start tried empty" 0 (Peer_manager.tried_table_size pm);
  Alcotest.(check int) "cold-start known empty" 0 (Hashtbl.length pm.known_addrs);

  (* And the contrast: WITH persistence, a saved book is non-empty after load. *)
  let dir = tmp_dir () in
  Fun.protect ~finally:(fun () -> rm_rf dir) @@ fun () ->
    let src = build_populated () in
    Peer_manager.save_addrman src dir;
    let restored = make_pm () in
    let ok = Peer_manager.load_addrman restored dir in
    Alcotest.(check bool) "post-impl load succeeds" true ok;
    Alcotest.(check bool) "post-impl restored addrman is NON-empty" true
      (Peer_manager.new_table_size restored > 0)

let () =
  Random.self_init ();
  Alcotest.run "addrman-persist" [
    "restart-persistence", [
      Alcotest.test_case "file round-trip (bucket/pos/class verbatim)" `Quick test_file_round_trip;
      Alcotest.test_case "in-process round-trip" `Quick test_in_process_round_trip;
    ];
    "corrupt-safe", [
      Alcotest.test_case "missing file → empty fallback" `Quick test_missing_file;
      Alcotest.test_case "corrupt files → empty fallback, no crash" `Quick test_corrupt_files;
      Alcotest.test_case "oversized → bounded to bucket ceiling" `Quick test_bounded_load;
    ];
    "falsification", [
      Alcotest.test_case "pre-impl cold start empty" `Quick test_falsification_cold_start_empty;
    ];
  ]
