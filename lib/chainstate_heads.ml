(* Boot-time replay of a chainstate commit that died half-way (audit H11 +
   H12; Core [CCoinsViewDB::GetHeadBlocks] + [Chainstate::ReplayBlocks],
   validation.cpp).

   The coins live in two RocksDB instances: rocksdb_utxo (the set block
   validation and gettxoutsetinfo read) and the chainstate column families,
   which hold a mirror of the coins plus the tip, the height index, bodies
   and undo.  A WriteBatch cannot span both, so every commit writes
   rocksdb_utxo first and the chainstate second, and rocksdb_utxo records in
   its own batch the block its coins are now at and the chainstate tip they
   moved away from ([Rocksdb_store.head_blocks]).

   If the process dies between the two writes, the head marker names a
   block the chainstate tip does not.  The coins in rocksdb_utxo are the
   complete, validated set at that block (one atomic batch), so the
   recovery here finishes the commit the chainstate missed: it moves the
   chainstate tip and height index to the marker's block and brings the
   coin mirror to the same set.  That is Core's roll-forward.  Rolling
   rocksdb_utxo back instead would need undo data that an assumevalid IBD
   never wrote.

   The marker is only acted on when it is checkable: the chainstate tip
   must be exactly the marker's [old] block, and the marker's block must be
   in the header index, at the recorded height, on a header chain that
   meets the chainstate's height index at or below its tip.  Anything else
   is left to the height checks in cli.ml, which only ever move the
   chainstate tip back (and now wipe both coin stores when they go to
   genesis). *)

type outcome =
  | Consistent                       (* marker absent or names the tip *)
  | Rolled_forward of {
      height : int;
      fork : int;
      disconnected : int;
      connected : int;
      mirror : [ `Replayed | `Rebuilt of int ];
    }
  | Untrusted of string              (* left to the height checks *)

(* A block's coin changes for the chainstate mirror, in apply order: for
   each tx, its inputs go, then its outputs come (the same rule as every
   connect path: no provably-unspendable outputs, no genesis coinbase). *)
let connect_ops (block : Types.block) (height : int)
    : (Types.hash256 * int * string option) list =
  let ops = ref [] in
  List.iteri (fun tx_idx (tx : Types.transaction) ->
    let txid = Crypto.compute_txid tx in
    let is_cb = tx_idx = 0 in
    if not is_cb then
      List.iter (fun (inp : Types.tx_in) ->
        let p = inp.Types.previous_output in
        ops := (p.Types.txid, Int32.to_int p.Types.vout, None) :: !ops)
        tx.Types.inputs;
    if not (Consensus.is_genesis_coinbase height txid) then
      List.iteri (fun vout (out : Types.tx_out) ->
        if not (Utxo.is_unspendable_script out.Types.script_pubkey) then
          ops := (txid, vout,
                  Some (Sync.encode_utxo out.Types.value
                          out.Types.script_pubkey height is_cb)) :: !ops)
        tx.Types.outputs)
    block.Types.transactions;
  List.rev !ops

let disconnect_ops db (hash : Types.hash256)
    : ((Types.hash256 * int * string option) list, string) result =
  match Storage.ChainDB.get_block db hash, Storage.ChainDB.get_undo_data db hash
  with
  | None, _ -> Error "no body"
  | _, None -> Error "no undo data"
  | Some block, Some raw ->
    let undo =
      Utxo.deserialize_undo_data
        (Serialize.reader_of_cstruct (Cstruct.of_string raw)) in
    (match Sync.block_disconnect_ops block undo with
     | Error e -> Error e
     | Ok ops ->
       Ok (List.map (function
           | Sync.Disc_del (txid, vout) -> (txid, vout, None)
           | Sync.Disc_put (txid, vout, (e : Utxo.utxo_entry)) ->
             (txid, vout,
              Some (Sync.encode_utxo e.Utxo.value e.Utxo.script_pubkey
                      e.Utxo.height e.Utxo.is_coinbase))) ops))

(* Walk the header chain back from the marker's block to the first height
   whose index slot already holds it, at or below the chainstate tip.
   Returns the fork height and the blocks above it, lowest first. *)
let path_to_index db ~(head : Types.hash256) ~(height : int) ~(cf_height : int)
    : (int * (int * Types.hash256 * Types.block_header) list, string) result =
  let rec walk h hash acc =
    if h < 0 then Error "header chain does not meet the height index"
    else if h <= cf_height
         && (match Storage.ChainDB.get_hash_at_height db h with
             | Some x -> Cstruct.equal x hash | None -> false)
    then Ok (h, acc)
    else
      match Storage.ChainDB.get_block_header db hash with
      | None ->
        Error (Printf.sprintf "no header for %s at height %d"
                 (Types.hash256_to_hex_display hash) h)
      | Some hdr -> walk (h - 1) hdr.Types.prev_block ((h, hash, hdr) :: acc)
  in
  walk height head []

let roll_forward db rdb (hb : Rocksdb_store.head_blocks)
    ~(cf_hash : Types.hash256) ~(cf_height : int) : (outcome, string) result =
  if Rocksdb_store.get_tip_height rdb <> Some hb.head_height then
    Error "marker height differs from rocksdb_utxo tip_height"
  else if (match Storage.ChainDB.get_hash_at_height db cf_height with
      | Some x -> not (Cstruct.equal x cf_hash) | None -> cf_height > 0) then
    Error "chainstate tip is not in its own height index"
  else
    match path_to_index db ~head:hb.head_new ~height:hb.head_height ~cf_height
    with
    | Error e -> Error e
    | Ok (fork, to_connect) ->
      (* The blocks leaving the active chain: index slots fork+1..cf_height,
         tip first. *)
      let to_disconnect =
        List.init (max 0 (cf_height - fork)) (fun i -> cf_height - i)
        |> List.filter_map (fun h ->
            Option.map (fun x -> (h, x))
              (Storage.ChainDB.get_hash_at_height db h)) in
      if List.length to_disconnect <> max 0 (cf_height - fork) then
        Error "height index has a hole on the old branch"
      else begin
        (* Coin mirror: replay the blocks when they are all on disk (reorg,
           at-tip, full-validation IBD); otherwise copy rocksdb_utxo
           (assumevalid IBD stores neither bodies nor undo). *)
        (* Per-block op lists, newest-first, flattened once at the end:
           disconnects tip-down, then connects fork-up.  One WriteBatch,
           last write per key wins, so this is sequential application. *)
        let replay =
          let rec disc acc = function
            | [] -> Ok acc
            | (_, h) :: rest ->
              (match disconnect_ops db h with
               | Ok ops -> disc (ops :: acc) rest
               | Error e -> Error e) in
          let rec conn acc = function
            | [] -> Ok acc
            | (height, h, _) :: rest ->
              (match Storage.ChainDB.get_block db h with
               | Some b -> conn (connect_ops b height :: acc) rest
               | None -> Error "no body") in
          match disc [] to_disconnect with
          | Error e -> Error e
          | Ok d -> (match conn d to_connect with
              | Error e -> Error e
              | Ok all -> Ok (List.concat (List.rev all)))
        in
        let batch = Storage.ChainDB.batch_create () in
        let mirror =
          match replay with
          | Ok ops ->
            List.iter (fun (txid, vout, v) -> match v with
              | Some data -> Storage.ChainDB.batch_store_utxo batch txid vout data
              | None -> Storage.ChainDB.batch_delete_utxo batch txid vout) ops;
            `Replayed
          | Error _ ->
            `Rebuilt (Storage.ChainDB.rebuild_utxo_mirror_from_rocksdb db)
        in
        (* Core CChain::SetTip: index slots fork+1..head, and nothing above
           the new tip from a taller old branch. *)
        List.iter (fun (h, hash, _) ->
          Storage.ChainDB.batch_set_height_hash batch h hash) to_connect;
        for h = hb.head_height + 1 to cf_height do
          Storage.ChainDB.batch_delete_height_hash batch h
        done;
        Storage.ChainDB.batch_set_chain_tip batch hb.head_new hb.head_height;
        Storage.ChainDB.batch_write db batch;
        (* nTx / chain tx counts, as the connect paths record after their
           commit (parent before child). *)
        List.iter (fun (_, h, (hdr : Types.block_header)) ->
          match Storage.ChainDB.get_block db h with
          | Some b ->
            Storage.ChainDB.record_connected_tx_counts db ~hash:h
              ~prev:hdr.Types.prev_block
              ~n_tx:(List.length b.Types.transactions)
          | None -> ()) to_connect;
        Ok (Rolled_forward { height = hb.head_height; fork;
                             disconnected = List.length to_disconnect;
                             connected = List.length to_connect; mirror })
      end

(* Run before [Sync.restore_chain_state], so the in-memory chain is loaded
   from the repaired chainstate. *)
let recover_on_boot ~(db : Storage.ChainDB.t) ~(rdb : Rocksdb_store.t)
    : outcome =
  let cf_hash, cf_height =
    match Storage.ChainDB.get_chain_tip db with
    | Some (h, n) -> (h, n)
    | None -> (Types.zero_hash, 0) in
  let hex = Types.hash256_to_hex_display in
  let outcome =
    match Rocksdb_store.get_head_blocks rdb with
    | None -> Consistent
    | Some hb when Cstruct.equal hb.head_new cf_hash -> Consistent
    | Some hb when not (Cstruct.equal hb.head_old cf_hash) ->
      Untrusted (Printf.sprintf
                   "head marker %s@%d moved from %s, but the chainstate tip \
                    is %s@%d" (hex hb.head_new) hb.head_height
                   (hex hb.head_old) (hex cf_hash) cf_height)
    | Some hb ->
      (match roll_forward db rdb hb ~cf_hash ~cf_height with
       | Ok o -> o
       | Error e ->
         Untrusted (Printf.sprintf "head marker %s@%d: %s"
                      (hex hb.head_new) hb.head_height e))
  in
  (match outcome with
   | Consistent -> ()
   | Rolled_forward r ->
     Logs.warn (fun m ->
       m "chainstate commit was interrupted: rocksdb_utxo is at %d, the \
          chainstate tip was at %d.  Rolled the chainstate forward to %d \
          (fork %d, %d disconnected, %d connected; coin mirror %s)"
         r.height cf_height r.height r.fork r.disconnected r.connected
         (match r.mirror with
          | `Replayed -> "replayed from block data"
          | `Rebuilt n -> Printf.sprintf "rebuilt from rocksdb_utxo, %d coins" n))
   | Untrusted why ->
     Logs.warn (fun m ->
       m "chainstate head marker not used (%s); falling back to the height \
          checks" why));
  (* A chainstate at genesis over a non-empty rocksdb_utxo is a datadir
     an older build rewound without wiping (audit H11).  Re-syncing on top
     of it meets every coin twice; start from an empty set. *)
  (match Storage.ChainDB.get_chain_tip db, Rocksdb_store.get_tip_height rdb with
   | (None | Some (_, 0)), Some h when h > 0 ->
     let n_rdb, n_cf = Storage.ChainDB.wipe_utxo_stores db in
     Logs.warn (fun m ->
       m "chainstate is at genesis but rocksdb_utxo is at %d: wiped both \
          coin stores (%d + %d keys) before re-sync" h n_rdb n_cf)
   | _ -> ());
  outcome
