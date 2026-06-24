(* Block Import Mode
   Reads blocks from stdin or a file in a simple framed format:
     [4 bytes height LE] [4 bytes size LE] [size bytes raw block]

   Bypasses the P2P layer entirely, feeding blocks directly to the
   validation and UTXO connection pipeline.

   Usage:
     tools/block_reader.py ... | camlcoin --import-blocks -
     camlcoin --import-blocks /path/to/blocks.bin
*)

(* Progress report interval *)
let progress_interval = 1000

(* Read exactly n bytes from an input channel *)
let really_input_bytes ic n =
  let buf = Bytes.create n in
  really_input ic buf 0 n;
  buf

(* Read a 32-bit little-endian integer from an input channel *)
let read_le32 ic =
  let buf = really_input_bytes ic 4 in
  let b0 = Char.code (Bytes.get buf 0) in
  let b1 = Char.code (Bytes.get buf 1) in
  let b2 = Char.code (Bytes.get buf 2) in
  let b3 = Char.code (Bytes.get buf 3) in
  b0 lor (b1 lsl 8) lor (b2 lsl 16) lor (b3 lsl 24)

(* Run the import loop.  Reads framed blocks from [ic] and connects
   them to the chain state using the optimized UTXO set. *)
let run ~(ic : in_channel) ~(db : Storage.ChainDB.t)
    ~(chain : Sync.chain_state) ~(network : Consensus.network_config)
    ~(utxo : Utxo.OptimizedUtxoSet.t) () =
  let count = ref 0 in
  let start_time = Unix.gettimeofday () in
  let last_height = ref 0 in
  let running = ref true in
  while !running do
    (* Read 8-byte frame header *)
    match (try let h = read_le32 ic in let s = read_le32 ic in Some (h, s)
           with End_of_file -> None) with
    | None ->
      running := false
    | Some (height, size) ->
      last_height := height;
      (* Read the raw block data *)
      let raw = really_input_bytes ic size in

      (* Skip blocks at or below current tip *)
      if height <= chain.blocks_synced then
        () (* already have this block, skip *)
      else begin
      let cs = Cstruct.of_bytes raw in
      let r = Serialize.reader_of_cstruct cs in
      let block = Serialize.deserialize_block r in

      (* Compute block hash for storage *)
      let hash = Crypto.compute_block_hash block.header in

      (* Store the block in the database *)
      Storage.ChainDB.store_block db hash block;

      (* Accept the header into the chain state if not already known *)
      let hash_key = Cstruct.to_string hash in
      if not (Hashtbl.mem chain.Sync.headers hash_key) then begin
        (* Build a minimal header entry *)
        let parent_work =
          match Hashtbl.find_opt chain.headers
              (Cstruct.to_string block.header.prev_block) with
          | Some parent -> parent.Sync.total_work
          | None -> Consensus.zero_work
        in
        let entry : Sync.header_entry = {
          header = block.header;
          hash;
          height;
          total_work = Consensus.work_add parent_work
            (Sync.work_from_bits block.header.bits);
        } in
        Hashtbl.replace chain.headers hash_key entry;
        if height > chain.headers_synced then begin
          chain.headers_synced <- height;
          chain.tip <- Some entry
        end;
        (* Store header in DB for persistence *)
        Storage.ChainDB.store_block_header db hash block.header;
        Storage.ChainDB.set_height_hash db height hash;
        Storage.ChainDB.set_header_tip db hash height
      end;

      (* Connect the block to the UTXO set *)
      let network_type = network.Consensus.network_type in
      (match Utxo.connect_block_optimized ~network_type utxo block height with
       | Ok _undo ->
         (* Write tx_index entries for every tx in the imported block
            (Pattern C0 closure 2026-05-05). Mirrors
            [Sync.process_new_block]; the import path has its own
            [Utxo.connect_block_optimized] driver that bypasses
            [Sync.process_new_block], so the txindex wire must be
            duplicated here. *)
         Sync.tx_index_write_for_block_recompute db block hash;
         (* Update chain tip in DB *)
         chain.blocks_synced <- height;
         (* Wake any wait-family RPC blocked on a tip change (Core
            KernelNotifications blockTip / WaitTipChanged).  Best-effort —
            the offline --import-blocks path normally has no RPC server up,
            but wiring it keeps every blocks_synced advance covered. *)
         (try Tip_notifier.notify () with _ -> ());
         (match Hashtbl.find_opt chain.headers hash_key with
          | Some entry -> chain.tip <- Some entry
          | None -> ());
         (* Bug 8 fix (2026-04-26): mirror chain.tip advance into
            chain.headers_synced. The earlier branch at line 83-86 only
            updates headers_synced when the header was FRESHLY added
            (`if height > chain.headers_synced`); when the header was
            already in chain.headers (the typical IBD/catch-up path:
            header accepted earlier, block now connecting), that branch
            is skipped and chain.tip advances here without
            headers_synced moving. The getheaders locator builder reads
            chain.headers_synced, so the divergence wedges peer sync. *)
         if height > chain.headers_synced then
           chain.headers_synced <- height;
         Storage.ChainDB.set_chain_tip db hash height;

         incr count;

         (* Periodic progress *)
         if !count mod progress_interval = 0 then begin
           let elapsed = Unix.gettimeofday () -. start_time in
           let rate = if elapsed > 0.0 then
               float_of_int !count /. elapsed else 0.0 in
           Printf.eprintf "\rImported %d blocks (height %d, %.1f blk/s)%!"
             !count height rate
         end;

         (* Periodic UTXO flush every 10000 blocks *)
         if !count mod 10000 = 0 then begin
           Utxo.OptimizedUtxoSet.flush ~tip_height:height utxo;
           Storage.ChainDB.sync db
         end
       | Error msg ->
         Printf.eprintf "\nFailed to connect block at height %d: %s\n%!"
           height msg;
         running := false)
      end (* if height > blocks_synced *)
  done;
  (* Final flush *)
  let elapsed = max 1.0 (Unix.gettimeofday () -. start_time) in
  let rate = float_of_int !count /. elapsed in
  Printf.eprintf "\nImport complete: %d blocks in %.0fs (%.1f blk/s)\n%!"
    !count elapsed rate;
  Utxo.OptimizedUtxoSet.flush ~tip_height:chain.blocks_synced utxo;
  (* Final chain_tip update *)
  let h = chain.blocks_synced in
  (match Sync.get_header_at_height chain h with
   | Some entry ->
     Storage.ChainDB.set_chain_tip db entry.hash h
   | None -> ());
  Storage.ChainDB.sync db;
  !count
