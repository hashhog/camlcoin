(* Control: post-IBD gap-fill must rotate off a peer that withholds
   blocks, and getblockcount must stay answerable while a gap-fill is
   in flight.

   Live 2026-09-17T14:20-14:38Z on deployed dd22e29: headers 967421,
   blocks 967419 for ~18 min. Log: `Post-IBD gap-fill: requesting 2
   missing blocks [967420..967421] from peer 8` over and over (14/40
   to peer 8, 3 to peer 104). Self-healed after 651.3 s. RPC
   getblockcount unanswered for 120 s; fleet-snapshot recorded
   TIMEOUT_OR_REFUSED twice.

   Core: FindNextBlocksToDownload + BLOCK_STALLING_TIMEOUT (2s).

   Command (fails on the always-headers-sender body, passes after):
     dune exec --no-buffer test/test_gapfill_peer_rotate.exe
*)

open Camlcoin

let h n : Types.hash256 =
  let cs = Cstruct.create 32 in
  Cstruct.set_uint8 cs 0 n;
  Cstruct.set_uint8 cs 1 0xF1;
  cs

(* The live HeadersMsg body: always the peer that sent the headers
   (passed first), every hash, every duplicate-headers batch. *)
let legacy_assign ~peer_ids hashes =
  ignore hashes;
  match peer_ids with
  | [] -> None
  | pid :: _ -> Some pid

let test_legacy_hammers_headers_peer () =
  let hashes = [ h 1; h 2 ] in
  let got = ref [] in
  for _ = 1 to 14 do
    match legacy_assign ~peer_ids:[ 8; 104 ] hashes with
    | Some pid -> got := pid :: !got
    | None -> ()
  done;
  let n8 = List.length (List.filter (( = ) 8) !got) in
  Alcotest.(check int)
    "legacy re-asks peer 8 on every duplicate-headers batch" 14 n8

let assign t ~now ~peer_ids hashes =
  Sync.Gapfill.assign t ~now ~peer_ids hashes

let test_first_try_uses_headers_peer () =
  let t = Sync.Gapfill.create () in
  match assign t ~now:0.0 ~peer_ids:[ 8; 104 ] [ h 1; h 2 ] with
  | None -> Alcotest.fail "first assign produced nothing"
  | Some a ->
    Alcotest.(check int) "first try is the headers-sender" 8 a.Sync.Gapfill.peer_id;
    Alcotest.(check int) "both missing hashes requested" 2
      (List.length a.Sync.Gapfill.hashes)

let test_no_rerequest_while_inflight () =
  let t = Sync.Gapfill.create () in
  ignore (assign t ~now:0.0 ~peer_ids:[ 8; 104 ] [ h 1; h 2 ]);
  match assign t ~now:0.5 ~peer_ids:[ 8; 104 ] [ h 1; h 2 ] with
  | None -> ()
  | Some a ->
    Alcotest.failf
      "re-asked peer %d at +0.5s while in-flight (live hammering)"
      a.Sync.Gapfill.peer_id

let test_rotates_after_stall_timeout () =
  let t = Sync.Gapfill.create () in
  (match assign t ~now:0.0 ~peer_ids:[ 8; 104 ] [ h 1; h 2 ] with
  | Some a -> Alcotest.(check int) "first peer" 8 a.Sync.Gapfill.peer_id
  | None -> Alcotest.fail "first assign empty");
  (* Peer 8 withholds. After BLOCK_STALLING_TIMEOUT the same hashes
     must go to another connected peer, with a reason logged. *)
  match
    assign t ~now:(Sync.Gapfill.stall_timeout +. 0.1) ~peer_ids:[ 8; 104 ]
      [ h 1; h 2 ]
  with
  | None -> Alcotest.fail "stalled gap-fill produced nothing to send"
  | Some a ->
    Alcotest.(check int)
      "rotates off the withholding peer within stall_timeout" 104
      a.Sync.Gapfill.peer_id;
    Alcotest.(check int) "still requesting both hashes" 2
      (List.length a.Sync.Gapfill.hashes);
    let notes = String.concat "; " a.Sync.Gapfill.stall_notes in
    Alcotest.(check bool)
      ("stall notes name peer 8, got: " ^ notes)
      true
      (String.length notes > 0
      &&
      try
        ignore (Str.search_forward (Str.regexp_string "peer 8") notes 0);
        true
      with Not_found -> false)

let test_notfound_rotates_immediately () =
  let t = Sync.Gapfill.create () in
  ignore (assign t ~now:0.0 ~peer_ids:[ 8; 104 ] [ h 1; h 2 ]);
  Sync.Gapfill.note_notfound t ~peer_id:8 (h 1);
  Sync.Gapfill.note_notfound t ~peer_id:8 (h 2);
  match assign t ~now:0.2 ~peer_ids:[ 8; 104 ] [ h 1; h 2 ] with
  | None -> Alcotest.fail "notfound left the gap unassigned"
  | Some a ->
    Alcotest.(check int) "notfound rotates off peer 8 immediately" 104
      a.Sync.Gapfill.peer_id

let test_receipt_clears_inflight () =
  let t = Sync.Gapfill.create () in
  ignore (assign t ~now:0.0 ~peer_ids:[ 8; 104 ] [ h 1; h 2 ]);
  Sync.Gapfill.note_received t (h 1);
  Sync.Gapfill.note_received t (h 2);
  match assign t ~now:0.2 ~peer_ids:[ 8; 104 ] [ h 1; h 2 ] with
  | None -> Alcotest.fail "cleared inflight should allow a fresh request"
  | Some a ->
    Alcotest.(check int) "fresh request after receipt" 8 a.Sync.Gapfill.peer_id

let with_ctx network f =
  Test_tmp.with_chaindb (fun db ->
      let utxo = Utxo.UtxoSet.create db in
      let mp =
        Mempool.create ~network ~require_standard:false ~verify_scripts:false
          ~utxo ~current_height:0 ()
      in
      let chain = Sync.create_chain_state db network in
      let ctx : Rpc.rpc_context =
        {
          chain;
          mempool = mp;
          peer_manager = Peer_manager.create network;
          wallet = None;
          wallet_manager = None;
          fee_estimator = Fee_estimation.create ();
          network;
          filter_index = None;
          utxo = None;
          data_dir = None;
          snapshot_activation = None;
        }
      in
      f ctx)

let json_req method_name params : Yojson.Safe.t =
  `Assoc
    [
      ("jsonrpc", `String "1.0");
      ("id", `String "t");
      ("method", `String method_name);
      ("params", `List params);
    ]

let test_getblockcount_during_gapfill () =
  with_ctx Consensus.regtest (fun ctx ->
      let t = Sync.Gapfill.create () in
      ignore (assign t ~now:0.0 ~peer_ids:[ 8; 104 ] [ h 1; h 2 ]);
      Rpc.test_sync_sleep_s := 2.0;
      Fun.protect
        ~finally:(fun () -> Rpc.test_sync_sleep_s := 0.0)
        (fun () ->
          let t0 = Unix.gettimeofday () in
          let slow = Rpc.handle_single_request_lwt ctx (json_req "help" []) in
          let fast =
            Rpc.handle_single_request_lwt ctx (json_req "getblockcount" [])
          in
          Lwt_main.run
            (Lwt.bind fast (fun fast_r ->
                 let dt = Unix.gettimeofday () -. t0 in
                 (match fast_r with
                 | `Assoc fields -> (
                   match List.assoc_opt "result" fields with
                   | Some (`Int _) -> ()
                   | Some j ->
                     Alcotest.failf "getblockcount result %s"
                       (Yojson.Safe.to_string j)
                   | None -> Alcotest.fail "getblockcount missing result")
                 | j ->
                   Alcotest.failf "getblockcount envelope %s"
                     (Yojson.Safe.to_string j));
                 Alcotest.(check bool)
                   (Printf.sprintf
                      "getblockcount during in-flight gap-fill in < 1s \
                       (took %.3fs)"
                      dt)
                   true (dt < 1.0);
                 Lwt.bind slow (fun _ -> Lwt.return_unit)))))

let () =
  Alcotest.run "gapfill_peer_rotate"
    [
      ( "legacy",
        [
          Alcotest.test_case "legacy always re-asks the headers-sender" `Quick
            test_legacy_hammers_headers_peer;
        ] );
      ( "rotate",
        [
          Alcotest.test_case "first try is the headers-sender" `Quick
            test_first_try_uses_headers_peer;
          Alcotest.test_case "does not re-ask while in-flight" `Quick
            test_no_rerequest_while_inflight;
          Alcotest.test_case "rotates after 2s stall timeout" `Quick
            test_rotates_after_stall_timeout;
          Alcotest.test_case "notfound rotates immediately" `Quick
            test_notfound_rotates_immediately;
          Alcotest.test_case "receipt clears in-flight" `Quick
            test_receipt_clears_inflight;
        ] );
      ( "rpc",
        [
          Alcotest.test_case "getblockcount answers during in-flight gap-fill"
            `Quick test_getblockcount_during_gapfill;
        ] );
    ]
