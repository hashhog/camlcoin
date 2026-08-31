(* Wave B liveness harness: drive the committed boundary-exception fixtures
   (tools/boundary-blocks/{170060,692261}) through camlcoin's REAL block-hash
   producer + REAL exception lookup + REAL script interpreter.
   Implements the fixture's harness_contract, including the MANDATORY negative
   control (force the no-exception mask; the block MUST then be rejected). *)

let root = "/home/work/hashhog/tools/boundary-blocks"

let hex_to_cs (s : string) : Cstruct.t =
  let n = String.length s / 2 in
  let b = Cstruct.create n in
  for i = 0 to n - 1 do
    Cstruct.set_uint8 b i (int_of_string ("0x" ^ String.sub s (i*2) 2))
  done; b

(* Core display hex (big-endian) -> camlcoin internal LE hash256 *)
let txid_of_display (s : string) : Cstruct.t =
  let n = String.length s / 2 in
  let b = Cstruct.create n in
  for i = 0 to n - 1 do
    Cstruct.set_uint8 b (n-1-i) (int_of_string ("0x" ^ String.sub s (i*2) 2))
  done; b

let read_file p =
  let ic = open_in_bin p in
  let n = in_channel_length ic in
  let s = really_input_string ic n in
  close_in ic; s

let read_lines p =
  let ic = open_in p in
  let acc = ref [] in
  (try while true do acc := input_line ic :: !acc done with End_of_file -> ());
  close_in ic; List.rev !acc

type prevout = { value : int64; spk : Cstruct.t; height : int; coinbase : bool }

let load_prevouts dir =
  let tbl = Hashtbl.create 8192 in
  List.iter (fun line ->
    if String.trim line <> "" then begin
      let j = Yojson.Safe.from_string line in
      let o = Yojson.Safe.Util.to_assoc j in
      let g k = List.assoc k o in
      let txid = Yojson.Safe.Util.to_string (g "txid") in
      let vout = Yojson.Safe.Util.to_int (g "vout") in
      let value = Int64.of_int (Yojson.Safe.Util.to_int (g "value")) in
      let spk = hex_to_cs (Yojson.Safe.Util.to_string (g "scriptPubKey")) in
      let height = Yojson.Safe.Util.to_int (g "height") in
      let coinbase = Yojson.Safe.Util.to_bool (g "coinbase") in
      Hashtbl.replace tbl (Cstruct.to_string (txid_of_display txid), vout)
        { value; spk; height; coinbase }
    end) (read_lines (Filename.concat dir "prevouts.jsonl"));
  tbl

(* Verify every input of every non-coinbase tx with [flags].
   Returns Ok () or Error (tx_index, txid_display, input_index, msg). *)
let verify_block ~(flags : int) ~(txs : Camlcoin.Types.transaction list) ~prevouts =
  let cache = Camlcoin.Sig_cache.create () in
  let res = ref (Ok ()) in
  List.iteri (fun ti (tx : Camlcoin.Types.transaction) ->
    if !res = Ok () && ti > 0 then begin
      let ins = tx.Camlcoin.Types.inputs in
      let coins = List.map (fun (inp : Camlcoin.Types.tx_in) ->
        let op = inp.Camlcoin.Types.previous_output in
        let key = (Cstruct.to_string op.Camlcoin.Types.txid,
                   Int32.to_int op.Camlcoin.Types.vout) in
        match Hashtbl.find_opt prevouts key with
        | Some p -> p
        | None -> failwith "prevout missing from fixture") ins in
      let pv = List.map (fun p -> (p.value, p.spk)) coins in
      let wtxid = Camlcoin.Crypto.compute_wtxid tx in
      List.iteri (fun i inp ->
        if !res = Ok () then begin
          let c = List.nth coins i in
          let u : Camlcoin.Validation.utxo = {
            txid = (List.nth ins i).Camlcoin.Types.previous_output.Camlcoin.Types.txid;
            vout = (List.nth ins i).Camlcoin.Types.previous_output.Camlcoin.Types.vout;
            value = c.value; script_pubkey = c.spk;
            height = c.height; is_coinbase = c.coinbase } in
          match Camlcoin.Validation.verify_one_input
                  ~tx ~flags ~prevouts:pv ~wtxid ~cache i inp u with
          | Ok () -> ()
          | Error (idx, msg) ->
            res := Error (ti, Camlcoin.Types.hash256_to_hex_display
                                (Camlcoin.Crypto.compute_txid tx), idx, msg)
        end) ins
    end) txs;
  !res

let show_res = function
  | Ok () -> "ACCEPT"
  | Error (ti, txid, i, msg) ->
    Printf.sprintf "REJECT (tx#%d %s vin%d: %s)" ti (String.sub txid 0 16) i msg

let run boundary =
  let dir = Filename.concat root (string_of_int boundary) in
  let fx = Yojson.Safe.from_file (Filename.concat dir "exception-fixture.json") in
  let u = Yojson.Safe.Util.member in
  let height = Yojson.Safe.Util.to_int (u "height" fx) in
  let disp = Yojson.Safe.Util.to_string (u "block_hash" fx) in
  let want = Yojson.Safe.Util.to_int (u "mask" (u "expected_script_flags" fx)) in
  let want_no = Yojson.Safe.Util.to_int
      (u "mask" (u "expected_script_flags_if_no_exception" fx)) in
  let raw = hex_to_cs (String.trim (read_file (Filename.concat dir "block.hex"))) in
  let blk = Camlcoin.Serialize.deserialize_block
              (Camlcoin.Serialize.reader_of_cstruct raw) in
  (* 1. camlcoin's OWN hash producer on the real block bytes *)
  let bh = Camlcoin.Crypto.compute_block_hash blk.Camlcoin.Types.header in
  let bh_disp = Camlcoin.Types.hash256_to_hex_display bh in
  Printf.printf "\n===== boundary %d (height %d, %d txs) =====\n"
    boundary height (List.length blk.Camlcoin.Types.transactions);
  Printf.printf "Crypto.compute_block_hash -> %s  [%s fixture]\n"
    bh_disp (if bh_disp = disp then "MATCHES" else "MISMATCH");
  (* 2. real production lookup, fed the real hash *)
  let got = Camlcoin.Consensus.get_block_script_flags
              ~block_hash:bh height Camlcoin.Consensus.mainnet in
  let got_z = Camlcoin.Consensus.get_block_script_flags
                ~block_hash:Camlcoin.Types.zero_hash height Camlcoin.Consensus.mainnet in
  Printf.printf "get_block_script_flags(real hash) = 0x%x  (Core: 0x%x) %s\n"
    got want (if got = want then "OK" else "*** WRONG ***");
  Printf.printf "get_block_script_flags(zero hash) = 0x%x  (Core no-exc: 0x%x) %s\n"
    got_z want_no (if got_z = want_no then "OK" else "*** WRONG ***");
  (* 3. + 4. + 5. drive the interpreter both ways *)
  let prevouts = load_prevouts dir in
  Printf.printf "prevouts loaded: %d\n" (Hashtbl.length prevouts);
  let t0 = Unix.gettimeofday () in
  let a = verify_block ~flags:got ~txs:blk.Camlcoin.Types.transactions ~prevouts in
  Printf.printf "WITH exception   (flags 0x%x): %s   [%.1fs]\n"
    got (show_res a) (Unix.gettimeofday () -. t0);
  let t1 = Unix.gettimeofday () in
  let b = verify_block ~flags:want_no ~txs:blk.Camlcoin.Types.transactions ~prevouts in
  Printf.printf "NEG CONTROL no-exc(flags 0x%x): %s   [%.1fs]\n"
    want_no (show_res b) (Unix.gettimeofday () -. t1);
  (match Sys.getenv_opt "LEGACY_MASK" with
   | Some m ->
     let m = int_of_string m in
     let t2 = Unix.gettimeofday () in
     let c = verify_block ~flags:m ~txs:blk.Camlcoin.Types.transactions ~prevouts in
     Printf.printf "PRE-FIX early-return (flags 0x%x): %s   [%.1fs]\n"
       m (show_res c) (Unix.gettimeofday () -. t2)
   | None -> ());
  let verdict = (a = Ok ()) && (b <> Ok ()) in
  Printf.printf "VERDICT: %s\n"
    (if verdict then "PASS (accept with exception, reject without -> path is LIVE)"
     else "FAIL");
  verdict

let () =
  let args = List.tl (Array.to_list Sys.argv) in
  let bs = if args = [] then [170060; 692261] else List.map int_of_string args in
  let ok = List.for_all (fun b -> run b) bs in
  Printf.printf "\n%s\n" (if ok then "ALL BOUNDARIES PASS" else "FAILURES PRESENT");
  exit (if ok then 0 else 1)
