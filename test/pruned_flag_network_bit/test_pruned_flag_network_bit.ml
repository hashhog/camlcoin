(* A node that is pruned WITHOUT --prune (existing pruned datadir / config
   file leaves prune_target = 0 but bodies are missing below a floor) must
   advertise NODE_NETWORK_LIMITED and not NODE_NETWORK, matching
   getblockchaininfo.pruned.  Unpruned node keeps NODE_NETWORK. *)
open Camlcoin

let hash_of h = Types.hash256_of_hex (Printf.sprintf "%064x" h)

let plant chain ~floor ~tip =
  let db = chain.Sync.db in
  for h = 1 to tip do
    let header =
      { Types.version = 1l; prev_block = hash_of (h - 1);
        merkle_root = Types.zero_hash; timestamp = Int32.of_int (1000 + h);
        bits = 0x207fffffl; nonce = Int32.of_int h } in
    let hash = Crypto.compute_block_hash header in
    Storage.ChainDB.store_block_header db hash header;
    Storage.ChainDB.set_height_hash db h hash;
    if h >= floor then
      Storage.ChainDB.store_block db hash
        { Types.header; transactions = [] }
  done;
  chain.Sync.blocks_synced <- tip

let svc () = Peer.services_to_int64 (Peer.our_services ())

let run ~floor ~prune_target =
  Test_tmp.with_chaindb (fun db ->
      let chain = Sync.create_chain_state db Consensus.regtest in
      chain.Sync.prune_target <- prune_target;
      plant chain ~floor ~tip:20;
      Fun.protect ~finally:(fun () -> Peer.set_prune_mode_advertise false)
        (fun () ->
           let pruned = Cli.apply_prune_advertisement chain in
           (pruned, svc ())))

let test_pruned_datadir_no_flag () =
  let pruned, bits = run ~floor:10 ~prune_target:0 in
  Alcotest.(check bool) "pruned" true pruned;
  Alcotest.(check int64) "NODE_NETWORK clear" 0L (Int64.logand bits 1L);
  Alcotest.(check int64) "NODE_NETWORK_LIMITED set" 0x400L
    (Int64.logand bits 0x400L)

let test_full_datadir_no_flag () =
  let pruned, bits = run ~floor:1 ~prune_target:0 in
  Alcotest.(check bool) "pruned" false pruned;
  Alcotest.(check int64) "NODE_NETWORK set" 1L (Int64.logand bits 1L)

let test_prune_flag_full_datadir () =
  let pruned, bits = run ~floor:1 ~prune_target:550_000_000 in
  Alcotest.(check bool) "pruned" true pruned;
  Alcotest.(check int64) "NODE_NETWORK clear" 0L (Int64.logand bits 1L)

let () =
  Alcotest.run "pruned_flag_network_bit"
    [ ("services",
       [ Alcotest.test_case "pruned datadir without --prune" `Quick
           test_pruned_datadir_no_flag;
         Alcotest.test_case "full datadir keeps NODE_NETWORK" `Quick
           test_full_datadir_no_flag;
         Alcotest.test_case "--prune on full datadir" `Quick
           test_prune_flag_full_datadir ]) ]
