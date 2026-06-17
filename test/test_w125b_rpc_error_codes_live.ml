(* W125b — JSON-RPC error-code parity, LIVE behavioral tests (camlcoin)

   De-stales the W125 source-audit gates G23/G24/G25/G26 (and the getblockhash
   -8 case) into REAL behavioral tests that drive [Rpc.dispatch_rpc] end-to-end
   and assert the exact Bitcoin Core JSON-RPC error code + message for each
   bad-input case.  Unlike test_w125_error_parity.ml (which greps lib/rpc.ml for
   declarations), every test here exercises the live RPC dispatch path, so it
   PASSES with the error-code-parity fix and FAILS without it.

   Ported from the verified rustoshi fixes:
     getblockhash out-of-range            -> RPC_INVALID_PARAMETER        (-8)
     addnode "add" already-added node     -> RPC_CLIENT_NODE_ALREADY_ADDED (-23)
     addnode "remove" not-added node      -> RPC_CLIENT_NODE_NOT_ADDED     (-24)
     disconnectnode not-connected peer    -> RPC_CLIENT_NODE_NOT_CONNECTED (-29)
     setban invalid IP/subnet             -> RPC_CLIENT_INVALID_IP_OR_SUBNET (-30)

   Oracle: bitcoin-core/src/rpc/{blockchain,net}.cpp + src/rpc/protocol.h:60-63. *)

open Camlcoin

let test_db_path = "/tmp/camlcoin_test_w125b_db"

let cleanup_test_db () =
  let rec rm_rf path =
    if Sys.file_exists path then begin
      if Sys.is_directory path then begin
        Array.iter (fun f -> rm_rf (Filename.concat path f)) (Sys.readdir path);
        Unix.rmdir path
      end else
        Unix.unlink path
    end
  in
  rm_rf test_db_path

(* Minimal RPC context for the network/blockchain management RPCs under test.
   Only [chain] (getblockhash) and [peer_manager] (addnode / setban /
   disconnectnode) are load-bearing here. *)
let make_ctx () : Rpc.rpc_context * Storage.ChainDB.t =
  cleanup_test_db ();
  let db = Storage.ChainDB.create test_db_path in
  let utxo = Utxo.UtxoSet.create db in
  let mp = Mempool.create
    ~require_standard:false ~verify_scripts:false ~utxo ~current_height:0 () in
  let chain = Sync.create_chain_state db Consensus.regtest in
  let pm = Peer_manager.create Consensus.regtest in
  let fe = Fee_estimation.create () in
  let ctx : Rpc.rpc_context = {
    chain; mempool = mp; peer_manager = pm;
    wallet = None; wallet_manager = None; fee_estimator = fe;
    network = Consensus.regtest; filter_index = None; utxo = None;
    data_dir = None; snapshot_activation = None;
  } in
  (ctx, db)

let check_err ~label ~code ?msg result =
  match result with
  | Error (c, m) ->
    Alcotest.(check int) (label ^ ": code") code c;
    (match msg with
     | Some expected -> Alcotest.(check string) (label ^ ": message") expected m
     | None -> ())
  | Ok j ->
    Alcotest.failf "%s: expected error (%d) but got Ok %s"
      label code (Yojson.Safe.to_string j)

let check_ok ~label result =
  match result with
  | Ok _ -> ()
  | Error (c, m) -> Alcotest.failf "%s: expected Ok but got error (%d) %s" label c m

(* ============================================================================
   getblockhash height out-of-range -> RPC_INVALID_PARAMETER (-8)
   Core rpc/blockchain.cpp:591 "Block height out of range".
   ============================================================================ *)

let test_getblockhash_out_of_range () =
  let (ctx, db) = make_ctx () in
  (* Seed genesis at height 0 so getblockhash(0) is the success path and the
     out-of-range query is distinguished from an empty chain. *)
  let genesis_hash = Types.hash256_of_hex
    "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206" in
  Storage.ChainDB.set_height_hash db 0 genesis_hash;
  (* Success path unchanged: in-range height returns a 64-hex string. *)
  check_ok ~label:"getblockhash(0)"
    (Rpc.dispatch_rpc ctx "getblockhash" [`Int 0]);
  (* Bad input: a height far past the tip -> -8 with Core's exact message. *)
  check_err ~label:"getblockhash(999999)"
    ~code:(-8) ~msg:"Block height out of range"
    (Rpc.dispatch_rpc ctx "getblockhash" [`Int 999999]);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* ============================================================================
   addnode "add"/"remove" -> RPC_CLIENT_NODE_ALREADY_ADDED (-23)
                          /  RPC_CLIENT_NODE_NOT_ADDED      (-24)
   Core rpc/net.cpp:358-369 + protocol.h:60-61.
   ============================================================================ *)

let test_addnode_already_added () =
  let (ctx, db) = make_ctx () in
  let node = "192.0.2.7:18444" in
  (* First add succeeds (fresh entry). *)
  check_ok ~label:"addnode add (fresh)"
    (Rpc.dispatch_rpc ctx "addnode" [`String node; `String "add"]);
  (* Second add of the SAME node -> -23 with Core's exact message. *)
  check_err ~label:"addnode add (duplicate)"
    ~code:(-23) ~msg:"Error: Node already added"
    (Rpc.dispatch_rpc ctx "addnode" [`String node; `String "add"]);
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_addnode_remove_not_added () =
  let (ctx, db) = make_ctx () in
  (* Remove of a never-added node -> -24 with Core's exact message. *)
  check_err ~label:"addnode remove (absent)"
    ~code:(-24)
    ~msg:"Error: Node could not be removed. It has not been added previously."
    (Rpc.dispatch_rpc ctx "addnode" [`String "192.0.2.9:18444"; `String "remove"]);
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_addnode_add_then_remove_roundtrip () =
  let (ctx, db) = make_ctx () in
  let node = "192.0.2.11:18444" in
  check_ok ~label:"add"
    (Rpc.dispatch_rpc ctx "addnode" [`String node; `String "add"]);
  (* remove of a previously-added node succeeds (no error). *)
  check_ok ~label:"remove (present)"
    (Rpc.dispatch_rpc ctx "addnode" [`String node; `String "remove"]);
  (* a second remove now errors -24 (it is no longer on the list). *)
  check_err ~label:"remove (now absent)"
    ~code:(-24)
    ~msg:"Error: Node could not be removed. It has not been added previously."
    (Rpc.dispatch_rpc ctx "addnode" [`String node; `String "remove"]);
  (* onetry never touches the list: it neither errors nor records membership,
     so a subsequent "add" of the same node still succeeds. *)
  check_ok ~label:"onetry"
    (Rpc.dispatch_rpc ctx "addnode" [`String node; `String "onetry"]);
  check_ok ~label:"add after onetry (onetry did not record membership)"
    (Rpc.dispatch_rpc ctx "addnode" [`String node; `String "add"]);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* ============================================================================
   disconnectnode not-connected peer -> RPC_CLIENT_NODE_NOT_CONNECTED (-29)
   Core rpc/net.cpp:467-479 + protocol.h:62 "Node not found in connected nodes".
   ============================================================================ *)

let test_disconnectnode_unknown_address () =
  let (ctx, db) = make_ctx () in
  (* No peers connected: disconnect-by-address of an unknown peer -> -29. *)
  check_err ~label:"disconnectnode (unknown address)"
    ~code:(-29) ~msg:"Node not found in connected nodes"
    (Rpc.dispatch_rpc ctx "disconnectnode" [`String "203.0.113.5:8333"]);
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_disconnectnode_unknown_id () =
  let (ctx, db) = make_ctx () in
  (* No peers connected: disconnect-by-id of an unknown peer -> -29. *)
  check_err ~label:"disconnectnode (unknown id)"
    ~code:(-29) ~msg:"Node not found in connected nodes"
    (Rpc.dispatch_rpc ctx "disconnectnode" [`Int 4242]);
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_disconnectnode_connected_peer_succeeds () =
  let (ctx, db) = make_ctx () in
  (* Register a connected peer (socketpair-backed, like the getblockfrompeer
     success test) so the by-id path is the SUCCESS path, not -29. *)
  let (fd_a, _fd_b) = Unix.socketpair Unix.PF_UNIX Unix.SOCK_STREAM 0 in
  let fd_peer = Lwt_unix.of_unix_file_descr fd_a in
  let peer_id = 5 in
  let peer = Peer.make_peer ~network:Consensus.regtest ~addr:"127.0.0.1"
    ~port:18444 ~id:peer_id ~direction:Peer.Outbound ~fd:fd_peer () in
  ctx.Rpc.peer_manager.Peer_manager.peers <-
    peer :: ctx.Rpc.peer_manager.Peer_manager.peers;
  Alcotest.(check bool) "peer registered" true
    (Peer_manager.find_peer_by_id ctx.Rpc.peer_manager peer_id <> None);
  (* disconnect-by-id of a CONNECTED peer succeeds (no -29). *)
  check_ok ~label:"disconnectnode (connected id)"
    (Rpc.dispatch_rpc ctx "disconnectnode" [`Int peer_id]);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* ============================================================================
   setban invalid IP/subnet -> RPC_CLIENT_INVALID_IP_OR_SUBNET (-30)
   Core rpc/net.cpp:779-781 + protocol.h:63 "Error: Invalid IP/Subnet".
   ============================================================================ *)

let test_setban_invalid_ip () =
  let (ctx, db) = make_ctx () in
  check_err ~label:"setban (garbage IP)"
    ~code:(-30) ~msg:"Error: Invalid IP/Subnet"
    (Rpc.dispatch_rpc ctx "setban" [`String "not-an-ip"; `String "add"]);
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_setban_invalid_subnet_prefix () =
  let (ctx, db) = make_ctx () in
  (* Valid host but out-of-range prefix length -> -30. *)
  check_err ~label:"setban (bad subnet prefix)"
    ~code:(-30) ~msg:"Error: Invalid IP/Subnet"
    (Rpc.dispatch_rpc ctx "setban" [`String "10.0.0.0/99"; `String "add"]);
  Storage.ChainDB.close db;
  cleanup_test_db ()

let test_setban_valid_ip_succeeds () =
  let (ctx, db) = make_ctx () in
  (* Success path preserved: a well-formed IP does NOT hit the -30 path. *)
  check_ok ~label:"setban (valid IPv4)"
    (Rpc.dispatch_rpc ctx "setban" [`String "192.0.2.55"; `String "add"]);
  (* And a well-formed subnet is accepted too. *)
  check_ok ~label:"setban (valid subnet)"
    (Rpc.dispatch_rpc ctx "setban" [`String "192.0.2.0/24"; `String "add"]);
  Storage.ChainDB.close db;
  cleanup_test_db ()

(* ============================================================================ *)

let () =
  let open Alcotest in
  run "W125b RPC error-code parity (live dispatch)" [
    "getblockhash -8", [
      test_case "out-of-range height -> -8" `Quick test_getblockhash_out_of_range;
    ];
    "addnode -23/-24", [
      test_case "add duplicate -> -23" `Quick test_addnode_already_added;
      test_case "remove not-added -> -24" `Quick test_addnode_remove_not_added;
      test_case "add/remove round-trip + onetry" `Quick
        test_addnode_add_then_remove_roundtrip;
    ];
    "disconnectnode -29", [
      test_case "unknown address -> -29" `Quick test_disconnectnode_unknown_address;
      test_case "unknown id -> -29" `Quick test_disconnectnode_unknown_id;
      test_case "connected peer succeeds" `Quick
        test_disconnectnode_connected_peer_succeeds;
    ];
    "setban -30", [
      test_case "garbage IP -> -30" `Quick test_setban_invalid_ip;
      test_case "bad subnet prefix -> -30" `Quick test_setban_invalid_subnet_prefix;
      test_case "valid IP/subnet succeeds" `Quick test_setban_valid_ip_succeeds;
    ];
  ]
