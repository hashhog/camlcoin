(* Control: a ~4 M-weight block from a peer that goes mute mid-body must
   time out, rotate to a different peer, and the tip must advance.

   Live 2026-09-18T04:10Z: camlcoin sat at 967494 (header 967495) with
     IBD stall: queue=1 in-flight=1 next_dl=967496 next_proc=967495
     Stale tip check (no update for 533s), polling peer 190
   Block 967495 was weight=3,993,841 (99.8 % of max). Six other impls and
   Core took it. Stale-tip polling of VERSION height is not a body
   re-request. Core: BLOCK_STALLING_TIMEOUT (2s) disconnects a unique
   staller; BLOCK_DOWNLOAD_TIMEOUT_BASE (net_processing.cpp) bounds a
   mute download. Recovering after 500+ s is not having a timeout.

   Command (fails on the mute-and-hold body, passes after):
     dune exec --no-buffer test/test_block_download_timeout.exe
*)

open Camlcoin
open Lwt.Syntax

let regtest = Consensus.regtest

(* The live "always re-ask the same peer" shape: stall check never
   rotates, so a mute first peer holds the in-flight slot forever. *)
let legacy_assign ~peer_ids =
  match peer_ids with [] -> None | pid :: _ -> Some pid

let test_legacy_hammers_first_peer () =
  let got = ref [] in
  for _ = 1 to 8 do
    match legacy_assign ~peer_ids:[ 190; 8 ] with
    | Some pid -> got := pid :: !got
    | None -> ()
  done;
  let n190 = List.length (List.filter (( = ) 190) !got) in
  Alcotest.(check int) "legacy re-asks mute peer 190 every time" 8 n190

(* ---- socketpair peers ------------------------------------------------ *)

let make_pair ~id =
  let a_u, b_u = Unix.socketpair Unix.PF_UNIX Unix.SOCK_STREAM 0 in
  Unix.set_nonblock a_u;
  Unix.set_nonblock b_u;
  let node_fd = Lwt_unix.of_unix_file_descr ~blocking:false a_u in
  let rem_fd = Lwt_unix.of_unix_file_descr ~blocking:false b_u in
  let peer =
    Peer.make_peer ~network:regtest ~addr:"127.0.0.1" ~port:(8000 + id) ~id
      ~direction:Peer.Outbound ~fd:node_fd ()
  in
  peer.Peer.state <- Peer.Ready;
  peer.Peer.handshake_complete <- true;
  peer.Peer.msg_loop_started <- true;
  let rem_ic = Lwt_io.of_fd ~mode:Lwt_io.Input rem_fd in
  let rem_oc = Lwt_io.of_fd ~mode:Lwt_io.Output rem_fd in
  (peer, rem_ic, rem_oc, rem_fd)

let write_bytes oc s =
  let* () = Lwt_io.write oc s in
  Lwt_io.flush oc

(* 24-byte v1 header claiming [len] payload bytes of command "block". *)
let fake_block_header ~len =
  let w = Serialize.writer_create () in
  let payload = Cstruct.create len in
  (* checksum of the (unread) payload — we never finish the body *)
  P2p.serialize_message_header w regtest.magic P2p.Block payload;
  Cstruct.to_string (Serialize.writer_to_cstruct w)

(* Pump the same read_message_with_timeout loop the production
   peer_message_loop uses, for [seconds]. *)
let pump_reads peer seconds =
  let deadline = Unix.gettimeofday () +. seconds in
  let rec loop () =
    if Unix.gettimeofday () >= deadline || peer.Peer.state = Peer.Disconnected
    then Lwt.return_unit
    else
      let* _ = Peer.read_message_with_timeout peer 0.2 in
      loop ()
  in
  loop ()

(* A mute mid-body read must disconnect the peer well before the live
   500 s hang. Current body: read_into_exactly of the full length is
   Lwt.no_cancel and the 30 s choose timeout leaves the read in
   pending_read, so the peer stays Ready. *)
let test_mute_mid_body_disconnects_peer () =
  let peer, _ic, oc, _fd = make_pair ~id:1 in
  let claimed = 200_000 in
  let hdr = fake_block_header ~len:claimed in
  Lwt_main.run
    (let* () = write_bytes oc (hdr ^ String.make 256 'x') in
     (* Do not write the rest. Production must give up. *)
     let* () = pump_reads peer (Sync.stall_timeout +. 1.0) in
     Lwt.return_unit);
  Alcotest.(check bool)
    "mute mid-body disconnects the peer (not Ready with a stuck read)"
    true
    (peer.Peer.state = Peer.Disconnected || peer.Peer.state = Peer.Disconnecting)

(* ---- ~4 M-weight regtest block -------------------------------------- *)

let pad_script =
  let s = Cstruct.create 77 in
  Cstruct.set_uint8 s 0 0x6a;
  (* OP_RETURN *)
  Cstruct.set_uint8 s 1 75;
  (* PUSH 75 *)
  s

let make_coinbase ~height ~outputs =
  let height_enc = Consensus.encode_height_in_coinbase height in
  let tag = Cstruct.create 2 in
  Cstruct.set_uint8 tag 0 0x4b;
  Cstruct.set_uint8 tag 1 (height land 0xff);
  let script_sig = Cstruct.concat [ height_enc; tag ] in
  {
    Types.version = 1l;
    inputs =
      [
        {
          Types.previous_output = { Types.txid = Types.zero_hash; vout = -1l };
          script_sig;
          sequence = 0xFFFFFFFFl;
        };
      ];
    outputs;
    witnesses = [];
    locktime = 0l;
  }

let grind_header (base : Types.block_header) =
  let rec loop nonce =
    let header = { base with Types.nonce } in
    let hash = Crypto.compute_block_hash header in
    if Consensus.hash_meets_target hash header.Types.bits then (header, hash)
    else loop (Int32.add nonce 1l)
  in
  loop 0l

let make_near_max_block ~prev_hash ~height ~timestamp =
  (* ~11.6k OP_RETURN outputs ≈ 1 MB serialized ≈ 4 M weight. Tuned to
     land inside [3.9M, 4.0M] like live 967495 (3,993,841). *)
  let n = 11620 in
  let outputs =
    { Types.value = 5_000_000_000L; script_pubkey = pad_script }
    :: List.init (n - 1) (fun _ ->
           { Types.value = 0L; script_pubkey = pad_script })
  in
  let cb = make_coinbase ~height ~outputs in
  let txids = [ Crypto.compute_txid cb ] in
  let merkle_root, _ = Crypto.merkle_root txids in
  let base : Types.block_header =
    {
      Types.version = 0x20000000l;
      prev_block = prev_hash;
      merkle_root;
      timestamp;
      bits = regtest.Consensus.pow_limit;
      nonce = 0l;
    }
  in
  let header, hash = grind_header base in
  let block = { Types.header; transactions = [ cb ] } in
  (block, hash)

let test_near_max_weight () =
  let genesis = Crypto.compute_block_hash regtest.genesis_header in
  let block, _ =
    make_near_max_block ~prev_hash:genesis ~height:1
      ~timestamp:(Int32.add regtest.genesis_header.timestamp 600l)
  in
  let w = Validation.compute_block_weight block.Types.transactions in
  Alcotest.(check bool)
    (Printf.sprintf "near-max weight got %d (want 3.9M..4.0M)" w)
    true
    (w >= 3_900_000 && w <= Consensus.max_block_weight)

(* ---- IBD: stall rotates off the mute peer ---------------------------- *)

let with_ibd f =
  Test_tmp.with_chaindb (fun db ->
      let chain = Sync.create_chain_state db regtest in
      chain.Sync.sync_state <- Sync.SyncingBlocks;
      let ibd = Sync.create_ibd_state chain in
      f chain ibd)

let accept_block1 chain (block : Types.block) hash =
  let genesis_work =
    Consensus.work_from_compact regtest.genesis_header.Types.bits
  in
  let total_work =
    Consensus.work_add genesis_work
      (Consensus.work_from_compact block.Types.header.Types.bits)
  in
  let entry : Sync.header_entry =
    { Sync.header = block.Types.header; hash; height = 1; total_work }
  in
  Sync.accept_header chain entry

let drain_one_msg ic timeout_s =
  let buf = Bytes.create 4096 in
  Lwt.pick
    [
      (let* n = Lwt_io.read_into ic buf 0 4096 in
       Lwt.return (if n <= 0 then None else Some (Bytes.sub buf 0 n)));
      (let* () = Lwt_unix.sleep timeout_s in
       Lwt.return None);
    ]

let rec wait_getdata ic deadline =
  if Unix.gettimeofday () >= deadline then Lwt.return None
  else
    let* chunk = drain_one_msg ic 0.2 in
    match chunk with
    | None -> wait_getdata ic deadline
    | Some bytes -> (
      try
        let msg = P2p.deserialize_message (Cstruct.of_bytes bytes) in
        match msg.P2p.payload with
        | P2p.GetdataMsg _ -> Lwt.return (Some bytes)
        | _ -> wait_getdata ic deadline
      with _ -> wait_getdata ic deadline)

let test_stall_rotates_to_other_peer () =
  with_ibd (fun _chain ibd ->
      let hash =
        Types.hash256_of_hex
          "00000000000000000000000000000000000000000000000000000000000000ab"
      in
      let entry : Sync.block_queue_entry =
        {
          Sync.hash;
          height = 1;
          download_state =
            Sync.Requested
              {
                peer_id = 1;
                requested_at = Unix.gettimeofday () -. Sync.stall_timeout -. 0.2;
                timeout = Sync.base_block_timeout;
              };
          tried_peers = [];
        }
      in
      Queue.push entry ibd.block_queue;
      Hashtbl.replace ibd.queue_by_hash (Cstruct.to_string hash) entry;
      Hashtbl.replace ibd.queue_by_height 1 entry;
      ibd.total_blocks_in_flight <- 1;
      ibd.next_process_height <- 1;
      let ps = Sync.get_peer_state ibd 1 in
      ps.blocks_in_flight <- 1;
      let peer1, ic1, _oc1, _ = make_pair ~id:1 in
      let peer2, ic2, _oc2, _ = make_pair ~id:2 in
      let to_drop = Sync.check_stalled_downloads ~n_ready_peers:2 ibd in
      Alcotest.(check bool) "unique staller is named for disconnect" true
        (List.mem 1 to_drop);
      (match entry.Sync.download_state with
      | Sync.NotRequested -> ()
      | _ -> Alcotest.fail "stall did not release the in-flight request");
      Alcotest.(check bool) "mute peer recorded in tried_peers" true
        (List.mem 1 entry.Sync.tried_peers);
      Lwt_main.run
        (let* () = Sync.request_blocks ibd [ peer1; peer2 ] in
         let* g1 = drain_one_msg ic1 0.3 in
         let* g2 = drain_one_msg ic2 0.3 in
         (match entry.Sync.download_state with
         | Sync.Requested { peer_id; _ } ->
           Alcotest.(check int) "re-request goes to the other peer" 2 peer_id
         | Sync.NotRequested ->
           Alcotest.fail "did not re-request after stall"
         | _ -> Alcotest.fail "unexpected download_state after re-request");
         Alcotest.(check bool) "GetData sent to peer 2, not the mute peer" true
           (g2 <> None && g1 = None);
         Lwt.return_unit))

(* Full control: mute peer A mid-body of a near-max block; peer B serves
   the complete body; catch-up IBD must rotate and connect the block. *)
let test_mute_mid_body_tip_advances () =
  with_ibd (fun chain ibd ->
      let genesis = Crypto.compute_block_hash regtest.genesis_header in
      let block, hash =
        make_near_max_block ~prev_hash:genesis ~height:1
          ~timestamp:(Int32.add regtest.genesis_header.timestamp 600l)
      in
      accept_block1 chain block hash;
      Sync.fill_download_queue ibd;
      Alcotest.(check int) "queued the header-ahead block" 1
        (Queue.length ibd.Sync.block_queue);
      let peer_a, ic_a, oc_a, _ = make_pair ~id:1 in
      let peer_b, ic_b, oc_b, _ = make_pair ~id:2 in
      let wire = P2p.serialize_message regtest.magic (P2p.BlockMsg block) in
      let wire_s = Cstruct.to_string wire in
      Alcotest.(check bool) "serialized body is large (near-max)" true
        (String.length wire_s > 900_000);
      let rec node_loop peer =
        if peer.Peer.state = Peer.Disconnected then Lwt.return_unit
        else
          let* msg = Peer.read_message_with_timeout peer 0.2 in
          (match msg with
          | Some (P2p.BlockMsg b) -> ignore (Sync.receive_block ibd b)
          | _ -> ());
          if chain.Sync.blocks_synced >= 1 then Lwt.return_unit
          else node_loop peer
      in
      let mute_a () =
        let* _ = wait_getdata ic_a (Unix.gettimeofday () +. 2.0) in
        (* Header + 1 KiB of the ~1 MB body, then mute. *)
        let n = min 1024 (String.length wire_s) in
        write_bytes oc_a (String.sub wire_s 0 n)
      in
      let serve_b () =
        let rec wait () =
          if chain.Sync.blocks_synced >= 1 then Lwt.return_unit
          else
            let* got = wait_getdata ic_b (Unix.gettimeofday () +. 0.4) in
            match got with
            | None -> wait ()
            | Some _ -> write_bytes oc_b wire_s
        in
        wait ()
      in
      let rec ibd_loop deadline =
        if Unix.gettimeofday () >= deadline || chain.Sync.blocks_synced >= 1
        then Lwt.return_unit
        else begin
          let n_ready =
            List.length
              (List.filter
                 (fun p -> p.Peer.state = Peer.Ready)
                 [ peer_a; peer_b ])
          in
          let stalled = Sync.check_stalled_downloads ~n_ready_peers:n_ready ibd in
          List.iter
            (fun pid ->
              List.iter
                (fun p ->
                  if p.Peer.id = pid then
                    Lwt.async (fun () ->
                        Lwt.catch
                          (fun () -> Peer.disconnect p)
                          (fun _ -> Lwt.return_unit)))
                [ peer_a; peer_b ])
            stalled;
          let ready =
            List.filter
              (fun p -> p.Peer.state = Peer.Ready)
              [ peer_a; peer_b ]
          in
          let* () = Sync.request_blocks ibd ready in
          let* _ = Sync.process_downloaded_blocks ibd in
          let* () = Lwt_unix.sleep 0.05 in
          ibd_loop deadline
        end
      in
      Lwt_main.run
        (let* () =
           Lwt.pick
             [
               (let* () =
                  Lwt.join
                    [
                      node_loop peer_a;
                      node_loop peer_b;
                      mute_a ();
                      serve_b ();
                      ibd_loop (Unix.gettimeofday () +. 8.0);
                    ]
                in
                Lwt.return_unit);
               (let* () = Lwt_unix.sleep 9.0 in
                Lwt.return_unit);
             ]
         in
         Lwt.return_unit);
      Alcotest.(check int)
        "tip advanced off the mute peer (block 1 connected)" 1
        chain.Sync.blocks_synced)

let () =
  Alcotest.run "block_download_timeout"
    [
      ( "legacy",
        [
          Alcotest.test_case "legacy always re-asks the mute peer" `Quick
            test_legacy_hammers_first_peer;
        ] );
      ( "payload",
        [
          Alcotest.test_case "mute mid-body disconnects the peer" `Quick
            test_mute_mid_body_disconnects_peer;
        ] );
      ( "weight",
        [
          Alcotest.test_case "fixture is ~4 M weight" `Quick
            test_near_max_weight;
        ] );
      ( "rotate",
        [
          Alcotest.test_case "stall rotates GetData to the other peer" `Quick
            test_stall_rotates_to_other_peer;
        ] );
      ( "tip",
        [
          Alcotest.test_case "mute mid-body: rotate and tip advances" `Slow
            test_mute_mid_body_tip_advances;
        ] );
    ]
