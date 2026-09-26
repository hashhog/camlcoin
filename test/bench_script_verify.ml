(* Script-verification CPU microbenchmark over real mainnet blocks.

   Input: a directory of block dumps produced from Core's
   `getblock <hash> 3` (one file per block):
     B <height> <ntx>
     T <nin> <tx_hex>          (non-coinbase txs only)
     P <sats> <spk_hex|->      (one per input, the spent prevout)

   Every input of every tx is verified through the REAL block-connect entry
   point Validation.verify_scripts_parallel_domain ~use_pool:false (serial,
   single domain, so CPU time is a clean measure), with the consensus flags
   Consensus.get_block_script_flags gives at that height.  The sig cache is
   cleared before every run so each run does all the work.

   Only uses APIs that exist before and after the precomputed-txdata change,
   so the same file measures both commits.

   Usage: bench_script_verify.exe <dir> [runs] *)

module V = Camlcoin.Validation
module T = Camlcoin.Types
module S = Camlcoin.Serialize
module C = Camlcoin.Consensus

let hex_decode s =
  let n = String.length s / 2 in
  let b = Bytes.create n in
  for i = 0 to n - 1 do
    Bytes.set b i (Char.chr (int_of_string ("0x" ^ String.sub s (2 * i) 2)))
  done;
  Cstruct.of_bytes b

type btx = {
  tx : T.transaction;
  prevouts : (int64 * Cstruct.t) list;
  utxos : V.utxo option array;
}

let load_block path =
  let ic = open_in path in
  let height = ref 0 in
  let txs = ref [] in
  let cur = ref None in
  let flush () =
    match !cur with
    | None -> ()
    | Some (tx, ps) ->
      let prevouts = List.rev ps in
      let utxos = Array.of_list (List.mapi (fun i (v, spk) ->
        let inp = List.nth tx.T.inputs i in
        Some { V.txid = inp.T.previous_output.T.txid;
               vout = inp.T.previous_output.T.vout;
               value = v; script_pubkey = spk; height = 1;
               is_coinbase = false }) prevouts) in
      txs := { tx; prevouts; utxos } :: !txs;
      cur := None
  in
  (try
     while true do
       let line = input_line ic in
       match String.split_on_char ' ' line with
       | ["B"; h; _] -> height := int_of_string h
       | ["T"; _; hex] ->
         flush ();
         let tx = S.deserialize_transaction (S.reader_of_cstruct (hex_decode hex)) in
         cur := Some (tx, [])
       | ["P"; sats; spk] ->
         (match !cur with
          | Some (tx, ps) ->
            let spk = if spk = "-" then Cstruct.empty else hex_decode spk in
            cur := Some (tx, (Int64.of_string sats, spk) :: ps)
          | None -> failwith "P before T")
       | _ -> failwith ("bad line in " ^ path)
     done
   with End_of_file -> ());
  flush ();
  close_in ic;
  (!height, Array.of_list (List.rev !txs))

let () =
  let dir = Sys.argv.(1) in
  let runs = if Array.length Sys.argv > 2 then int_of_string Sys.argv.(2) else 5 in
  let files = Sys.readdir dir |> Array.to_list
              |> List.filter (fun f -> Filename.check_suffix f ".txt")
              |> List.sort compare in
  let blocks = List.map (fun f -> load_block (Filename.concat dir f)) files in
  let ninputs = List.fold_left (fun acc (_, txs) ->
    Array.fold_left (fun a b -> a + List.length b.tx.T.inputs) acc txs) 0 blocks in
  Printf.printf "blocks=%d inputs=%d runs=%d\n%!" (List.length blocks) ninputs runs;
  let per_block = Hashtbl.create 16 in
  let totals = ref [] in
  for run = 1 to runs do
    V.cache_clear_global ();
    Gc.full_major ();
    let t0 = Sys.time () in
    let failures = ref 0 in
    List.iter (fun (h, txs) ->
      let flags = C.get_block_script_flags h C.mainnet in
      let b0 = Sys.time () in
      Array.iter (fun b ->
        match V.verify_scripts_parallel_domain ~use_pool:false ~tx:b.tx ~flags
                ~prevouts:b.prevouts ~utxos:b.utxos () with
        | Ok () -> ()
        | Error _ -> incr failures) txs;
      let dt = Sys.time () -. b0 in
      let prev = try Hashtbl.find per_block h with Not_found -> [] in
      Hashtbl.replace per_block h (dt :: prev)) blocks;
    let dt = Sys.time () -. t0 in
    totals := dt :: !totals;
    Printf.printf "run %d: cpu=%.3fs failures=%d\n%!" run dt !failures
  done;
  let median l =
    let a = Array.of_list l in
    Array.sort compare a;
    let n = Array.length a in
    if n mod 2 = 1 then a.(n / 2) else (a.(n / 2 - 1) +. a.(n / 2)) /. 2.
  in
  List.iter (fun (h, _) ->
    Printf.printf "block %d median_cpu=%.3fs\n" h (median (Hashtbl.find per_block h))) blocks;
  Printf.printf "TOTAL median_cpu=%.3fs min=%.3fs\n" (median !totals)
    (List.fold_left min infinity !totals)
