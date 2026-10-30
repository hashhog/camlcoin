(* getpeerinfo conntime must be the time the peer connected (Core
   CNode::m_connected, rpc/net.cpp "conntime"), fixed at connect, not the
   moving last-activity time that also feeds lastsend/lastrecv.

   Drives the real RPC handler: register a peer the way
   getpeerinfo_field_order in test_rpc.ml does, advance last_seen as message
   traffic would, then read the JSON integers back out of
   Rpc.handle_getpeerinfo. *)
open Camlcoin

let int_field fields k =
  match List.assoc_opt k fields with
  | Some (`Int n) -> n
  | _ -> Alcotest.failf "getpeerinfo %s missing or not an integer" k

let peer_fields ctx =
  match Rpc.handle_getpeerinfo ctx with
  | `List [ `Assoc fields ] -> fields
  | j -> Alcotest.failf "getpeerinfo: expected one peer, got %s"
           (Yojson.Safe.to_string j)

let test_conntime_is_connect_time () =
  Test_tmp.with_dir ~label:"conntime" ~mkdir:true (fun path ->
    let network = Consensus.mainnet in
    let db = Storage.ChainDB.create path in
    Fun.protect ~finally:(fun () -> Storage.ChainDB.close db) (fun () ->
      let utxo = Utxo.UtxoSet.create db in
      let ctx : Rpc.rpc_context = {
        chain = Sync.create_chain_state db network;
        mempool = Mempool.create ~network:Consensus.regtest
            ~require_standard:false ~verify_scripts:false ~utxo
            ~current_height:0 ();
        peer_manager = Peer_manager.create network;
        wallet = None;
        wallet_manager = None;
        fee_estimator = Fee_estimation.create ();
        network;
        filter_index = None;
        utxo = None;
        data_dir = None;
        snapshot_activation = None;
      } in
      let (fd_peer_u, _fd_remote_u) =
        Unix.socketpair Unix.PF_UNIX Unix.SOCK_STREAM 0 in
      let fd = Lwt_unix.of_unix_file_descr fd_peer_u in
      let peer = Peer.make_peer ~network ~addr:"127.0.0.1" ~port:8333
          ~id:7 ~direction:Peer.Outbound ~fd () in
      ctx.Rpc.peer_manager.Peer_manager.peers <-
        peer :: ctx.Rpc.peer_manager.Peer_manager.peers;
      let before = peer_fields ctx in
      let conn0 = int_field before "conntime" in
      let send0 = int_field before "lastsend" in
      (* Traffic an hour later moves last_seen (and so lastsend); it must not
         move the connection time. *)
      peer.Peer.last_seen <- peer.Peer.last_seen +. 3600.0;
      let after = peer_fields ctx in
      Alcotest.(check bool) "lastsend moved with activity" true
        (int_field after "lastsend" >= send0 + 3600);
      Alcotest.(check int) "conntime stays at connect time"
        conn0 (int_field after "conntime");
      let now = int_of_float (Unix.gettimeofday ()) in
      Alcotest.(check bool) "conntime is not in the future" true
        (int_field after "conntime" <= now)))

let () = Alcotest.run "conntime"
  [ "conntime",
    [ Alcotest.test_case "getpeerinfo conntime is connect time" `Quick
        test_conntime_is_connect_time ] ]
