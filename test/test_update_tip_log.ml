(* Control: one INFO UpdateTip line per connected block, including IBD.

   QUEUES.md 2026-09-19: campaign range 419311→450000 produced 67 log
   lines, 39 of them [utxo-import]. 907680c added
     UpdateTip: hash=… height=… nTx=…
   on process_new_block and connect_stored_blocks (gap-fill drain). The
   live run then logged exactly 16 of those (heights 419312..419327, the
   gap-fill request cap) while the tip moved to 419983. The remaining
   ~670 connects went through process_downloaded_blocks (run_ibd), which
   only emitted the batch line
     Processed 10 blocks, height now 419983, in-flight: 1 (avg 1 blk/s)
   Core's Chainstate::UpdateTip (validation.cpp UpdateTipLog) fires per
   active-chain connect, with rate-limiting disabled so IBD is visible.

   This drives the IBD path, not gap-fill: 32 downloaded bodies (>16)
   through process_downloaded_blocks. Revert of the IBD UpdateTip makes
   n_tip=0 while tip=32.

   Command (red on HEAD, green after):
     dune exec --no-buffer test/test_update_tip_log.exe
*)

open Camlcoin

let n_blocks = 32

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

let with_captured_info f =
  let acc = ref [] in
  let old_reporter = Logs.reporter () in
  let old_level = Logs.level () in
  let report _src level ~over k msgf =
    let k _ = over (); k () in
    msgf @@ fun ?header:_ ?tags:_ fmt ->
    Format.kasprintf
      (fun s ->
        if level = Logs.Info then acc := s :: !acc;
        k ())
      fmt
  in
  Logs.set_reporter { Logs.report };
  Logs.set_level ~all:true (Some Logs.Info);
  Fun.protect
    ~finally:(fun () ->
      Logs.set_reporter old_reporter;
      Logs.set_level old_level)
    (fun () ->
      let r = f () in
      (List.rev !acc, r))

let is_update_tip s =
  let len = String.length s in
  len >= 10 && String.sub s 0 10 = "UpdateTip:"

let field_int line key =
  let prefix = key ^ "=" in
  let plen = String.length prefix in
  let rec find = function
    | [] -> None
    | tok :: rest ->
      if String.length tok >= plen && String.sub tok 0 plen = prefix then
        try Some (int_of_string (String.sub tok plen (String.length tok - plen)))
        with _ -> None
      else find rest
  in
  find (String.split_on_char ' ' line)

let has_prefix_field line key =
  let prefix = key ^ "=" in
  let plen = String.length prefix in
  List.exists
    (fun tok ->
      String.length tok >= plen && String.sub tok 0 plen = prefix)
    (String.split_on_char ' ' line)

let with_ibd_downloaded ~n f =
  Test_tmp.with_dir ~label:"updatetip_ibd" ~mkdir:true (fun path ->
      let db = Storage.ChainDB.create path in
      Fun.protect
        ~finally:(fun () -> try Storage.ChainDB.close db with _ -> ())
        (fun () ->
          let state = Sync.create_chain_state db Consensus.regtest in
          let genesis = Option.get state.Sync.tip in
          let prev_hash = ref genesis.Sync.hash in
          let prev_time = ref genesis.Sync.header.Types.timestamp in
          let bodies = Array.make (n + 1) (None : Types.block option) in
          for h = 1 to n do
            let b =
              build_coinbase_block ~prev_hash:!prev_hash ~height:h
                ~prev_time:!prev_time
            in
            (match Sync.validate_header state b.Types.header with
            | Ok entry -> Sync.accept_header state entry
            | Error e -> Alcotest.failf "validate_header height %d: %s" h e);
            bodies.(h) <- Some b;
            prev_hash := Crypto.compute_block_hash b.Types.header;
            prev_time := b.Types.header.Types.timestamp
          done;
          state.Sync.blocks_synced <- 0;
          state.Sync.sync_state <- Sync.SyncingBlocks;
          let ibd = Sync.create_ibd_state state in
          for h = 1 to n do
            match bodies.(h) with
            | None -> Alcotest.failf "missing body %d" h
            | Some b ->
              let hash = Crypto.compute_block_hash b.Types.header in
              Sync.queue_add ibd
                {
                  Sync.hash;
                  height = h;
                  download_state =
                    Sync.Downloaded { block = b; peer_id = None };
                  tried_peers = [];
                }
          done;
          f state ibd))

let test_ibd_logs_update_tip_every_block () =
  with_ibd_downloaded ~n:n_blocks (fun state ibd ->
      let logs, processed =
        with_captured_info (fun () ->
            match
              Lwt_main.run
                (Sync.process_downloaded_blocks ~max_blocks:n_blocks ibd)
            with
            | Ok n -> n
            | Error e -> Alcotest.failf "process_downloaded_blocks: %s" e)
      in
      let tips = List.filter is_update_tip logs in
      let heights = List.filter_map (fun l -> field_int l "height") tips in
      Printf.printf
        "IBD process_downloaded_blocks: processed=%d tip=%d n_updatetip=%d \
         heights=%s (live logged 16 then stopped)\n%!"
        processed state.Sync.blocks_synced (List.length tips)
        (String.concat "," (List.map string_of_int heights));
      Alcotest.(check int) "connected the whole downloaded batch" n_blocks
        processed;
      Alcotest.(check int) "block tip advanced through all 32" n_blocks
        state.Sync.blocks_synced;
      Alcotest.(check int)
        "UpdateTip only for the first 16 (gap-fill cap); IBD path silent \
         while tip moved hundreds of heights"
        n_blocks (List.length tips);
      Alcotest.(check (list int))
        "one UpdateTip per height 1..32, not 1..16"
        (List.init n_blocks (fun i -> i + 1))
        heights;
      List.iteri
        (fun i line ->
          let h = i + 1 in
          Alcotest.(check bool)
            (Printf.sprintf "height %d line has hash=" h)
            true (has_prefix_field line "hash");
          Alcotest.(check bool)
            (Printf.sprintf "height %d line has nTx=" h)
            true (has_prefix_field line "nTx");
          Alcotest.(check bool)
            (Printf.sprintf "height %d line has elapsed=" h)
            true (has_prefix_field line "elapsed"))
        tips)

let () =
  Alcotest.run "update_tip_log"
    [
      ( "ibd",
        [
          Alcotest.test_case
            "process_downloaded_blocks emits UpdateTip for every connected \
             block, not the first 16" `Quick
            test_ibd_logs_update_tip_every_block;
        ] );
    ]
