(* Control: stale getheaders locator (QUEUES.md item 0, live wedge at 967188).

   Live 2026-09-15T22:07Z.. : pin 7921e5a, FullySynced, blocks=967188
   (that hash IS Core's main-chain block) but every getheaders comes back
   `[WARNING] All 2000 headers rejected (2000 known, first_err=none)` /
   `All 2000 headers were duplicates, locator may be stale` (~19k times),
   then `Stale tip check ... peer reports height 972515 vs our 967188` and
   a peer rotation that yields the same 2000 known headers.

   Root cause: getheaders locators were built from the height->hash index
   at the validated height (Peer_manager.build_locator db our_height, and
   Sync.build_locator via hash_at when tip.height <= blocks_synced). Core
   is GetLocator(pindexBestHeader): the first hash is the tip ENTRY's
   hash, never a height lookup. A poisoned/stale index row at 967188 made
   locator[0] a hash public peers did not have, so FindForkInGlobalIndex
   fell through to genesis and they re-sent headers 1..2000.

   Command (fails on the pre-fix bodies, passes after):
     dune exec --no-buffer test/test_stale_locator.exe
*)

open Camlcoin

let test_db_base = "/tmp/camlcoin_test_stale_locator"

let rec rm_rf path =
  if Sys.file_exists path then
    if Sys.is_directory path then begin
      Array.iter (fun f -> rm_rf (Filename.concat path f)) (Sys.readdir path);
      Unix.rmdir path
    end
    else Unix.unlink path

let with_state name f =
  let db_path = test_db_base ^ "_" ^ name in
  rm_rf db_path;
  let db = Storage.ChainDB.create db_path in
  let state = Sync.create_chain_state db Consensus.regtest in
  Fun.protect
    ~finally:(fun () ->
      Storage.ChainDB.close db;
      rm_rf db_path)
    (fun () -> f db state)

let genesis_ts = Consensus.regtest.genesis_header.Types.timestamp

let make_header ~prev ~height ~nonce =
  Types.
    {
      version = 1l;
      prev_block = prev;
      merkle_root = Types.zero_hash;
      timestamp = Int32.add genesis_ts (Int32.of_int (height * 600));
      bits = 0x207fffffl;
      nonce;
    }

(* Regtest target 0x207fffff still rejects ~half of random hashes
   (high bit of the 256-bit value). Headers that go through
   process_headers must actually meet it. *)
let mine_header ~prev ~height : Types.block_header * Types.hash256 =
  let rec grind nonce =
    let hdr = make_header ~prev ~height ~nonce in
    let hash = Crypto.compute_block_hash hdr in
    if Consensus.check_proof_of_work hash hdr.Types.bits Consensus.regtest then
      (hdr, hash)
    else grind (Int32.succ nonce)
  in
  grind 0l

(* Stuff [n] headers onto [state] after genesis. Returns the by-height
   hash array (index 0 = genesis). Does NOT write the height->hash index
   (accept_header doesn't either); the caller decides what the index
   contains. *)
let extend_headers (state : Sync.chain_state) (n : int) : Types.hash256 array =
  let genesis = Option.get state.Sync.tip in
  let hashes = Array.make (n + 1) genesis.Sync.hash in
  let prev = ref genesis in
  for h = 1 to n do
    let hdr, hash = mine_header ~prev:!prev.Sync.hash ~height:h in
    let work =
      Consensus.work_add !prev.Sync.total_work
        (Consensus.work_from_compact hdr.Types.bits)
    in
    let e : Sync.header_entry =
      { header = hdr; hash; height = h; total_work = work }
    in
    Hashtbl.replace state.Sync.headers (Cstruct.to_string hash) e;
    state.Sync.tip <- Some e;
    state.Sync.headers_synced <- h;
    hashes.(h) <- hash;
    prev := e
  done;
  hashes

let poison_height_index db ~from_h ~to_h =
  let fake = Cstruct.create 32 in
  Cstruct.memset fake 0xAA;
  for h = from_h to to_h do
    Storage.ChainDB.set_height_hash db h fake
  done;
  fake

(* Core FindForkInGlobalIndex + send up to 2000 headers after the fork.
   Uses the in-memory header table (pindex), not the height index. *)
let respond_getheaders (peer : Sync.chain_state) (locator : Types.hash256 list)
    : Types.block_header list =
  let genesis = Option.get (Sync.get_header_at_height peer 0) in
  let fork =
    let rec find = function
      | [] -> genesis
      | h :: rest -> (
        match Sync.get_header peer h with
        | Some e -> e
        | None -> find rest)
    in
    find locator
  in
  let tip = Option.get peer.Sync.tip in
  let rec collect acc h n =
    if n >= P2p.max_headers_count || h > tip.Sync.height then List.rev acc
    else
      match Sync.get_ancestor peer tip h with
      | Some e -> collect (e.Sync.header :: acc) (h + 1) (n + 1)
      | None -> collect acc (h + 1) n
  in
  collect [] (fork.Sync.height + 1) 0

(* Live shape: validated tip T, height-index rows at 1..T overwritten
   with a hash no peer has. locator[0] must still be the tip ENTRY. *)
let test_locator_head_is_tip_hash_not_height_index () =
  with_state "poisoned_index" (fun db state ->
      let n = 32 in
      let hashes = extend_headers state n in
      state.Sync.blocks_synced <- n;
      let fake = poison_height_index db ~from_h:1 ~to_h:n in
      match Sync.build_locator state with
      | [] -> Alcotest.fail "empty locator"
      | head :: _ ->
        Alcotest.(check bool)
          "locator head is the active tip hash, not the poisoned index row"
          true
          (Cstruct.equal head hashes.(n));
        Alcotest.(check bool)
          "locator head is NOT the 0xAA height-index poison" false
          (Cstruct.equal head fake))

(* Node at T (>= 2000 so a genesis-fork reply is a full 2000-known batch)
   with a peer at T+k. First getheaders must accept k new headers.
   Pre-fix: poisoned index -> locator matches at genesis -> 2000 known
   -> accepted=0, tip stuck at T. *)
let test_first_getheaders_accepts_k_new_headers () =
  let n = 2000 in
  let k = 8 in
  with_state "node" (fun db_node node ->
      let hashes = extend_headers node n in
      node.Sync.blocks_synced <- n;
      ignore (poison_height_index db_node ~from_h:1 ~to_h:n);
      with_state "peer" (fun _db_peer peer ->
          ignore (extend_headers peer n);
          (* Same k headers the node does not yet have. Mined so the
             node's process_headers PoW check will accept them. *)
          let extra = ref [] in
          let prev = ref hashes.(n) in
          for h = n + 1 to n + k do
            let hdr, hash = mine_header ~prev:!prev ~height:h in
            extra := hdr :: !extra;
            let work =
              Consensus.work_add
                (Option.get peer.Sync.tip).Sync.total_work
                (Consensus.work_from_compact hdr.Types.bits)
            in
            let e : Sync.header_entry =
              { header = hdr; hash; height = h; total_work = work }
            in
            Hashtbl.replace peer.Sync.headers (Cstruct.to_string hash) e;
            peer.Sync.tip <- Some e;
            peer.Sync.headers_synced <- h;
            prev := hash
          done;
          let extra = List.rev !extra in
          Alcotest.(check int) "peer has T+k headers" (n + k)
            peer.Sync.headers_synced;
          ignore extra;
          let locator = Sync.build_locator node in
          let response = respond_getheaders peer locator in
          (match locator with
           | head :: _ ->
             Alcotest.(check bool)
               "node locator head is the node tip (height T)" true
               (Cstruct.equal head hashes.(n))
           | [] -> Alcotest.fail "empty locator");
          Alcotest.(check int)
            "peer replies with k headers after the tip, not 2000 known"
            k (List.length response);
          match Sync.process_headers node response with
          | Ok accepted ->
            Alcotest.(check int)
              "node at T accepts k new headers on the first getheaders" k
              accepted;
            Alcotest.(check int) "node header tip advanced to T+k" (n + k)
              node.Sync.headers_synced
          | Error e -> Alcotest.fail ("node process_headers: " ^ e)))

(* A 2000-known batch is not progress: it must not look like a successful
   catch-up, and it must not trigger stale-tip rotation. *)
let test_2000_known_is_not_progress () =
  with_state "known2000" (fun db state ->
      let n = 2000 in
      ignore (extend_headers state n);
      state.Sync.blocks_synced <- n;
      ignore (poison_height_index db ~from_h:1 ~to_h:n);
      (* Replay headers 1..2000 (already in the table) as a peer reply. *)
      let tip = Option.get state.Sync.tip in
      let rec collect acc h =
        if h < 1 then acc
        else
          match Sync.get_ancestor state tip h with
          | Some e -> collect (e.Sync.header :: acc) (h - 1)
          | None -> collect acc (h - 1)
      in
      let known = collect [] n in
      Alcotest.(check int) "replay is a full 2000-header batch" 2000
        (List.length known);
      let accepted =
        match Sync.process_headers state known with
        | Ok n_acc -> n_acc
        | Error _ -> 0
      in
      Alcotest.(check int) "2000 already-known headers accepted none" 0 accepted;
      Alcotest.(check bool) "2000 known is not progress" false (accepted > 0);
      Alcotest.(check int) "tip still at T after 2000 known" n
        state.Sync.headers_synced;
      (* Rotation during a known-headers stall is the live 967188 failure
         mode. Header==block here (we never accepted new ones); the
         production follow-up is re-request from the tip, not rotate. *)
      let rotate =
        Peer_manager.should_rotate_stale_peer ~header_height:n ~block_height:n
          ~time_since_update:100_000.0 ~stale_tip_check_interval:1800.0
          ~has_plausibly_ahead_peer:false
      in
      Alcotest.(check bool)
        "do not rotate peers just because a 2000-known batch came back" false
        rotate)

let test_headers_batch_is_progress () =
  Alcotest.(check bool) "k new is progress" true
    (Sync.headers_batch_is_progress ~accepted:8);
  Alcotest.(check bool) "2000 known is not progress" false
    (Sync.headers_batch_is_progress ~accepted:0)

let test_rerequest_from_tip_on_stale_batch () =
  let tip = Cstruct.create 32 in
  Cstruct.memset tip 0x11;
  let genesis = Types.zero_hash in
  let stale_first =
    Types.
      {
        version = 1l;
        prev_block = genesis;
        merkle_root = Types.zero_hash;
        timestamp = 1l;
        bits = 0x207fffffl;
        nonce = 1l;
      }
  in
  let connecting_first =
    { stale_first with Types.prev_block = tip }
  in
  Alcotest.(check bool)
    "2000 known whose first prev is not the tip -> rerequest from tip" true
    (Sync.should_rerequest_from_tip ~accepted:0 ~received:2000 ~our_tip_hash:tip
       [stale_first]);
  Alcotest.(check bool)
    "2000 known that connect to the tip are caught-up headers, not a stale locator"
    false
    (Sync.should_rerequest_from_tip ~accepted:0 ~received:2000 ~our_tip_hash:tip
       [connecting_first]);
  Alcotest.(check bool) "progressing batch does not rerequest" false
    (Sync.should_rerequest_from_tip ~accepted:8 ~received:8 ~our_tip_hash:tip
       [connecting_first]);
  Alcotest.(check bool) "short empty-ish reply is peer tip, not stale" false
    (Sync.should_rerequest_from_tip ~accepted:0 ~received:3 ~our_tip_hash:tip
       [stale_first])

let test_version_height_replaced_by_observed_headers () =
  let got =
    Peer_manager.best_height_after_headers ~version_height:972515l
      ~observed_height:2000l
  in
  Alcotest.(check int32)
    "VERSION 972515 is a hint; observed 2000-known batch replaces it" 2000l got

let test_getheaders_locator_uses_builder () =
  with_state "pm_locator" (fun db state ->
      let n = 32 in
      let hashes = extend_headers state n in
      state.Sync.blocks_synced <- n;
      ignore (poison_height_index db ~from_h:1 ~to_h:n);
      let pm = Peer_manager.create Consensus.regtest in
      Peer_manager.set_db pm db;
      Peer_manager.set_height pm (Int32.of_int n);
      Peer_manager.set_locator_builder pm (fun () -> Sync.build_locator state);
      match Peer_manager.getheaders_locator pm with
      | [] -> Alcotest.fail "empty getheaders locator"
      | head :: _ ->
        Alcotest.(check bool)
          "stale-tip getheaders locator is the header-tip hash, not the poisoned index"
          true
          (Cstruct.equal head hashes.(n)))

(* Persist in-memory headers 1..n the way accept_header + connect do, close,
   restore. Caller must close the returned db and rm_rf the path. *)
let persist_close_restore name n =
  let db_path = test_db_base ^ "_" ^ name in
  rm_rf db_path;
  let db = Storage.ChainDB.create db_path in
  let state = Sync.create_chain_state db Consensus.regtest in
  let hashes = extend_headers state n in
  state.Sync.blocks_synced <- n;
  let rec persist_walk (e : Sync.header_entry) =
    Storage.ChainDB.store_block_header db e.hash e.header;
    Storage.ChainDB.set_height_hash db e.height e.hash;
    if e.height > 0 then
      match Sync.get_header state e.header.Types.prev_block with
      | Some p -> persist_walk p
      | None -> ()
  in
  (match state.Sync.tip with
   | Some t ->
     persist_walk t;
     Storage.ChainDB.set_header_tip db t.hash t.height;
     Storage.ChainDB.set_chain_tip db t.hash t.height
   | None -> failwith "no tip to persist");
  Storage.ChainDB.close db;
  let db = Storage.ChainDB.create db_path in
  let restored = Sync.restore_chain_state db Consensus.regtest in
  (db, restored, hashes, db_path)

let test_restart_does_not_block_on_header_sync () =
  let db, state, hashes, path = persist_close_restore "restart_block" 32 in
  Fun.protect
    ~finally:(fun () ->
      Storage.ChainDB.close db;
      rm_rf path)
    (fun () ->
      Alcotest.(check int) "restored header tip" 32 state.Sync.headers_synced;
      Alcotest.(check int) "restored block tip" 32 state.Sync.blocks_synced;
      Alcotest.(check bool)
        "restart with a restored header chain must not enter the blocking \
         header-sync loop (that loop skip-deadlocks on 2000-known)"
        false
        (Sync.should_run_blocking_header_sync state);
      match Sync.build_locator state with
      | [] -> Alcotest.fail "empty locator after restore"
      | head :: _ ->
        Alcotest.(check bool) "locator[0] is restored tip" true
          (Cstruct.equal head hashes.(32)))

let test_outstanding_known_batch_is_the_reply_not_a_leftover () =
  with_state "leftover" (fun _db state ->
      ignore (extend_headers state 32);
      state.Sync.blocks_synced <- 32;
      let tip = Option.get state.Sync.tip in
      let rec collect acc h =
        if h < 1 then acc
        else
          match Sync.get_ancestor state tip h with
          | Some e -> collect (e.Sync.header :: acc) (h - 1)
          | None -> collect acc (h - 1)
      in
      let known = collect [] 32 in
      Alcotest.(check int) "32 known headers" 32 (List.length known);
      Alcotest.(check bool)
        "pre-send leftover drain may skip already-known headers" true
        (Sync.headers_sync_is_leftover ~outstanding_getheaders:false state known);
      Alcotest.(check bool)
        "after we sent getheaders, a known batch is the reply — do not wait"
        false
        (Sync.headers_sync_is_leftover ~outstanding_getheaders:true state known))

(* QUEUES.md item 0 (2026-09-17 restart wedge): node at tip T, peer at T+k,
   first getheaders AFTER A RESTART must accept k headers. Goes through the
   on-wire CBlockLocator layout (int32 version + compact-size + 32-byte
   hashes) so a byte-order or framing bug fails this, not just in-memory
   locator construction. *)
let test_restart_first_getheaders_accepts_k () =
  let n = 32 in
  let k = 8 in
  let db, node, hashes, path = persist_close_restore "restart_k" n in
  Fun.protect
    ~finally:(fun () ->
      Storage.ChainDB.close db;
      rm_rf path)
    (fun () ->
      with_state "peer_k" (fun _db_peer peer ->
          ignore (extend_headers peer n);
          let prev = ref hashes.(n) in
          for h = n + 1 to n + k do
            let hdr, hash = mine_header ~prev:!prev ~height:h in
            let work =
              Consensus.work_add
                (Option.get peer.Sync.tip).Sync.total_work
                (Consensus.work_from_compact hdr.Types.bits)
            in
            let e : Sync.header_entry =
              { header = hdr; hash; height = h; total_work = work }
            in
            Hashtbl.replace peer.Sync.headers (Cstruct.to_string hash) e;
            peer.Sync.tip <- Some e;
            peer.Sync.headers_synced <- h;
            prev := hash
          done;
          let locator = Sync.build_locator node in
          let msg =
            P2p.serialize_message P2p.regtest_magic
              (P2p.GetheadersMsg
                 {
                   version = Types.protocol_version;
                   locator_hashes = locator;
                   hash_stop = Types.zero_hash;
                 })
          in
          let payload = Cstruct.shift msg P2p.message_header_size in
          let r = Serialize.reader_of_cstruct payload in
          let _ver = Serialize.read_int32_le r in
          let count = Serialize.read_compact_size r in
          let wire_hashes =
            List.init count (fun _ -> Serialize.read_bytes r 32)
          in
          (match wire_hashes with
           | [] -> Alcotest.fail "no hashes on the wire"
           | h0 :: _ ->
             Alcotest.(check bool)
               "wire locator[0] is the restored tip (internal byte order)" true
               (Cstruct.equal h0 hashes.(n));
             let rev = Cstruct.create 32 in
             for i = 0 to 31 do
               Cstruct.set_uint8 rev i (Cstruct.get_uint8 hashes.(n) (31 - i))
             done;
             Alcotest.(check bool)
               "wire locator[0] is NOT the display-reversed tip" false
               (Cstruct.equal h0 rev));
          let response = respond_getheaders peer wire_hashes in
          Alcotest.(check int) "Core-style FindFork returns k new headers" k
            (List.length response);
          match Sync.process_headers node response with
          | Ok accepted ->
            Alcotest.(check int)
              "node at T accepts k new headers on the first getheaders after restart"
              k accepted;
            Alcotest.(check int) "header tip is T+k" (n + k)
              node.Sync.headers_synced
          | Error e -> Alcotest.fail ("process_headers: " ^ e)))

let () =
  Alcotest.run "stale_locator" [
    ( "locator from tip entry",
      [
        Alcotest.test_case
          "poisoned height index does not become locator[0]" `Quick
          test_locator_head_is_tip_hash_not_height_index;
        Alcotest.test_case
          "node at T, peer at T+k: first getheaders accepts k" `Quick
          test_first_getheaders_accepts_k_new_headers;
        Alcotest.test_case
          "peer_manager getheaders_locator uses Sync.build_locator" `Quick
          test_getheaders_locator_uses_builder;
        Alcotest.test_case
          "after restart, do not run the blocking header-sync loop" `Quick
          test_restart_does_not_block_on_header_sync;
        Alcotest.test_case
          "node at T, peer at T+k: first getheaders after restart accepts k"
          `Quick test_restart_first_getheaders_accepts_k;
      ] );
    ( "blocking header-sync leftover",
      [
        Alcotest.test_case
          "outstanding getheaders: 2000-known is the reply, not a leftover"
          `Quick test_outstanding_known_batch_is_the_reply_not_a_leftover;
      ] );
    ( "2000 known is not progress",
      [
        Alcotest.test_case "2000 known does not advance the tip or rotate"
          `Quick test_2000_known_is_not_progress;
        Alcotest.test_case "headers_batch_is_progress is accepted>0" `Quick
          test_headers_batch_is_progress;
        Alcotest.test_case "2000 known with prev!=tip rerequests from tip"
          `Quick test_rerequest_from_tip_on_stale_batch;
      ] );
    ( "VERSION height is a hint",
      [
        Alcotest.test_case "observed headers replace VERSION 972515" `Quick
          test_version_height_replaced_by_observed_headers;
      ] );
  ]
