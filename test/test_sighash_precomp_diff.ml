(* Differential proof for the per-transaction precomputed sighash data
   (Script.precomputed_txdata, Core's PrecomputedTransactionData).

   REFERENCE: [Ref.compute_sighash_segwit] / [Ref.compute_sighash_taproot]
   below are VERBATIM copies of the pre-change functions from camlcoin master
   5ad8f2a (lib/script.ml), which recomputed hashPrevouts / hashSequence /
   hashOutputs / sha_* on every call.  The new functions must produce
   byte-identical sighashes with and without a shared txdata.

   Usage:
     test_sighash_precomp_diff.exe <blocks-dir> [bip341_wallet_vectors.json]

   <blocks-dir> holds block dumps made from Core's `getblock <hash> 3`:
     B <height> <ntx>
     T <nin> <tx_hex>          (non-coinbase txs)
     P <sats> <spk_hex|->      (one per input: the spent prevout)

   Arms:
     A. sighash differential over every input of every tx: BIP-143 for every
        input x hash types {0x00,0x01,0x02,0x03,0x04,0x81,0x82,0x83} and
        BIP-341 for every input x {0x00,0x01,0x02,0x03,0x81,0x82,0x83} x
        {key path, annex, script path, annex+script path w/ codesep}.  New
        (shared txdata, evaluated in REVERSE input order so later inputs hit a
        cache filled by an earlier call) and new (no txdata) vs reference.
     B. full Script.verify_script with the shared txdata on every input:
        real mainnet signatures must verify (Ok true).
     C. the block's inputs through a ScriptCheckQueue with 8 worker Domains
        (append_script_jobs => one shared txdata per tx across Domains).
     D. controls: a cache built for a DIFFERENT tx / a structurally-equal but
        physically-different prevouts list is ignored (falls back); a
        deliberately CORRUPTED cache changes the sighash and makes a real
        segwit / taproot input FAIL verify_script (proves the cache is
        actually reached by the verify path); a mutated output value makes
        a SIGHASH_ALL input fail.
     E. BIP-341 wallet vectors (Core bip341_wallet_vectors.json keyPathSpending):
        intermediary single hashes + sigHash, computed through the cache. *)

open Camlcoin

module Ref = struct
  open Types
  let sighash_none = Script.sighash_none
  let sighash_single = Script.sighash_single
  let sighash_anyonecanpay = Script.sighash_anyonecanpay
  let is_valid_taproot_hash_type = Script.is_valid_taproot_hash_type
  let _ = (zero_hash : hash256)
(* BIP-143 segwit v0 sighash computation *)
let compute_sighash_segwit (tx : Types.transaction) (input_index : int)
    (script_code : Cstruct.t) (amount : int64) (hash_type : int) : Types.hash256 =
  let base_type = hash_type land 0x1f in
  let anyone_can_pay = hash_type land sighash_anyonecanpay <> 0 in

  (* hashPrevouts *)
  let hash_prevouts =
    if anyone_can_pay then Types.zero_hash
    else begin
      let w = Serialize.writer_create () in
      List.iter (fun inp ->
        Serialize.serialize_outpoint w inp.Types.previous_output
      ) tx.inputs;
      Crypto.sha256d (Serialize.writer_to_cstruct w)
    end
  in

  (* hashSequence *)
  let hash_sequence =
    if anyone_can_pay || base_type = sighash_none || base_type = sighash_single
    then Types.zero_hash
    else begin
      let w = Serialize.writer_create () in
      List.iter (fun inp ->
        Serialize.write_int32_le w inp.Types.sequence
      ) tx.inputs;
      Crypto.sha256d (Serialize.writer_to_cstruct w)
    end
  in

  (* hashOutputs *)
  let hash_outputs =
    if base_type <> sighash_none && base_type <> sighash_single then begin
      let w = Serialize.writer_create () in
      List.iter (Serialize.serialize_tx_out w) tx.outputs;
      Crypto.sha256d (Serialize.writer_to_cstruct w)
    end
    else if base_type = sighash_single && input_index < List.length tx.outputs then begin
      let w = Serialize.writer_create () in
      Serialize.serialize_tx_out w (List.nth tx.outputs input_index);
      Crypto.sha256d (Serialize.writer_to_cstruct w)
    end
    else Types.zero_hash
  in

  (* Build preimage *)
  let w = Serialize.writer_create () in
  Serialize.write_int32_le w tx.version;
  Serialize.write_bytes w hash_prevouts;
  Serialize.write_bytes w hash_sequence;
  let inp = List.nth tx.inputs input_index in
  Serialize.serialize_outpoint w inp.previous_output;
  Serialize.write_compact_size w (Cstruct.length script_code);
  Serialize.write_bytes w script_code;
  Serialize.write_int64_le w amount;
  Serialize.write_int32_le w inp.sequence;
  Serialize.write_bytes w hash_outputs;
  Serialize.write_int32_le w tx.locktime;
  Serialize.write_int32_le w (Int32.of_int hash_type);
  Crypto.sha256d (Serialize.writer_to_cstruct w)

(* BIP-341 Taproot sighash computation (SignatureHashSchnorr).

   Parameters:
   - tx: the transaction being signed
   - input_index: index of the input being signed
   - prevouts: list of ALL input amounts and scriptPubKeys (needed for Taproot)
   - hash_type: the sighash type byte (0x00 = SIGHASH_DEFAULT = ALL)
   - annex_hash: optional SHA256 hash of (compact_size(len) || annex_bytes)
   - tapleaf_hash: optional leaf hash for script path spends
   - codesep_pos: OP_CODESEPARATOR position (0xFFFFFFFF if none)

   prevouts is a list of (amount, scriptPubKey) for ALL inputs. *)
let compute_sighash_taproot
    (tx : Types.transaction)
    (input_index : int)
    (prevouts : (int64 * Cstruct.t) list)
    (hash_type : int)
    ?(annex_hash : Cstruct.t option)
    ?(tapleaf_hash : Cstruct.t option)
    ?(codesep_pos : int = 0xFFFFFFFF)
    () : Cstruct.t =
  (* Validate hash_type per BIP-341. See is_valid_taproot_hash_type above.
     Callers MUST pre-check; we still re-check defensively so a future caller
     can't accidentally feed a bad hash_type and produce a silently-wrong
     sighash. *)
  let base_type = hash_type land 0x03 in
  let anyone_can_pay = hash_type land 0x80 <> 0 in
  if not (is_valid_taproot_hash_type hash_type) then
    failwith (Printf.sprintf "Invalid Taproot hash_type: 0x%02x" hash_type);

  (* W94/BIP-341: prevouts MUST be exactly one entry per tx input. Core asserts
     `cache.m_spent_outputs.size() == tx_to.vin.size()` in `PrecomputedTransactionData::Init`.
     Without this guard, a short or oversized list would silently produce a
     wrong sha_amounts / sha_scriptpubkeys, leaking a different sighash to
     callers that don't notice. *)
  let n_inputs = List.length tx.Types.inputs in
  let n_prevouts = List.length prevouts in
  if n_prevouts <> n_inputs then
    failwith (Printf.sprintf
                "Taproot sighash: prevouts length %d does not match inputs length %d"
                n_prevouts n_inputs);
  if input_index < 0 || input_index >= n_inputs then
    failwith (Printf.sprintf
                "Taproot sighash: input_index %d out of range [0, %d)"
                input_index n_inputs);

  (* Compute spend_type byte *)
  let has_annex = annex_hash <> None in
  let has_tapleaf = tapleaf_hash <> None in
  let spend_type =
    (if has_annex then 1 else 0) lor
    (if has_tapleaf then 2 else 0)
  in

  (* Begin building the preimage *)
  let w = Serialize.writer_create () in

  (* epoch *)
  Serialize.write_uint8 w 0x00;

  (* hash_type *)
  Serialize.write_uint8 w hash_type;

  (* nVersion *)
  Serialize.write_int32_le w tx.version;

  (* nLockTime *)
  Serialize.write_int32_le w tx.locktime;

  (* If not ANYONECANPAY, compute and write shared input hashes *)
  if not anyone_can_pay then begin
    (* sha_prevouts: SHA256 of all outpoints *)
    let sha_prevouts =
      let pw = Serialize.writer_create () in
      List.iter (fun inp -> Serialize.serialize_outpoint pw inp.Types.previous_output) tx.inputs;
      Crypto.sha256 (Serialize.writer_to_cstruct pw)
    in
    (* sha_amounts: SHA256 of all input amounts *)
    let sha_amounts =
      let pw = Serialize.writer_create () in
      List.iter (fun (amount, _) -> Serialize.write_int64_le pw amount) prevouts;
      Crypto.sha256 (Serialize.writer_to_cstruct pw)
    in
    (* sha_scriptpubkeys: SHA256 of all input scriptPubKeys with compact_size prefix *)
    let sha_scriptpubkeys =
      let pw = Serialize.writer_create () in
      List.iter (fun (_, spk) ->
        Serialize.write_compact_size pw (Cstruct.length spk);
        Serialize.write_bytes pw spk
      ) prevouts;
      Crypto.sha256 (Serialize.writer_to_cstruct pw)
    in
    (* sha_sequences: SHA256 of all input sequences *)
    let sha_sequences =
      let pw = Serialize.writer_create () in
      List.iter (fun inp -> Serialize.write_int32_le pw inp.Types.sequence) tx.inputs;
      Crypto.sha256 (Serialize.writer_to_cstruct pw)
    in
    Serialize.write_bytes w sha_prevouts;
    Serialize.write_bytes w sha_amounts;
    Serialize.write_bytes w sha_scriptpubkeys;
    Serialize.write_bytes w sha_sequences
  end;

  (* If hash_type base is not NONE and not SINGLE, write sha_outputs *)
  if base_type <> 2 && base_type <> 3 then begin
    let sha_outputs =
      let pw = Serialize.writer_create () in
      List.iter (fun out ->
        Serialize.write_int64_le pw out.Types.value;
        Serialize.write_compact_size pw (Cstruct.length out.Types.script_pubkey);
        Serialize.write_bytes pw out.Types.script_pubkey
      ) tx.outputs;
      Crypto.sha256 (Serialize.writer_to_cstruct pw)
    in
    Serialize.write_bytes w sha_outputs
  end;

  (* spend_type *)
  Serialize.write_uint8 w spend_type;

  (* Input data *)
  if anyone_can_pay then begin
    let inp = List.nth tx.inputs input_index in
    let (amount, spk) = List.nth prevouts input_index in
    Serialize.serialize_outpoint w inp.Types.previous_output;
    Serialize.write_int64_le w amount;
    Serialize.write_compact_size w (Cstruct.length spk);
    Serialize.write_bytes w spk;
    Serialize.write_int32_le w inp.sequence
  end else begin
    Serialize.write_int32_le w (Int32.of_int input_index)
  end;

  (* If annex is present. Core writes the annex hash BEFORE the SIGHASH_SINGLE
     single-output hash (interpreter.cpp:1544-1557: annex at 1544-1546, then
     sha_single_output at 1548-1557). This order is consensus-critical: a taproot
     spend that carries BOTH a witness annex AND base hash_type SIGHASH_SINGLE
     would otherwise get a different TapSighash than Core (and the other 9 impls),
     false-rejecting an otherwise-valid block -> chain split. *)
  (match annex_hash with
   | Some ah -> Serialize.write_bytes w ah
   | None -> ());

  (* If SIGHASH_SINGLE, write sha_single_output *)
  if base_type = 3 then begin
    if input_index >= List.length tx.outputs then
      failwith "SIGHASH_SINGLE: input_index exceeds number of outputs";
    let out = List.nth tx.outputs input_index in
    let pw = Serialize.writer_create () in
    Serialize.write_int64_le pw out.Types.value;
    Serialize.write_compact_size pw (Cstruct.length out.Types.script_pubkey);
    Serialize.write_bytes pw out.Types.script_pubkey;
    let sha_single_output = Crypto.sha256 (Serialize.writer_to_cstruct pw) in
    Serialize.write_bytes w sha_single_output
  end;

  (* If tapscript (script path spend) *)
  (match tapleaf_hash with
   | Some lh ->
     Serialize.write_bytes w lh;
     (* key_version *)
     Serialize.write_uint8 w 0x00;
     (* codesep_pos *)
     Serialize.write_int32_le w (Int32.of_int codesep_pos)
   | None -> ());

  (* Final tagged hash *)
  Crypto.tagged_hash "TapSighash" (Serialize.writer_to_cstruct w)

end

let hex_decode s =
  let n = String.length s / 2 in
  let b = Bytes.create n in
  for i = 0 to n - 1 do
    Bytes.set b i (Char.chr (int_of_string ("0x" ^ String.sub s (2 * i) 2)))
  done;
  Cstruct.of_bytes b

let hex_of cs =
  let b = Buffer.create (2 * Cstruct.length cs) in
  for i = 0 to Cstruct.length cs - 1 do
    Buffer.add_string b (Printf.sprintf "%02x" (Cstruct.get_uint8 cs i))
  done;
  Buffer.contents b

type btx = { tx : Types.transaction; prevouts : (int64 * Cstruct.t) list }

let load_block path =
  let ic = open_in path in
  let height = ref 0 and txs = ref [] and cur = ref None in
  let flush () = match !cur with
    | None -> ()
    | Some (tx, ps) -> txs := { tx; prevouts = List.rev ps } :: !txs; cur := None in
  (try while true do
       match String.split_on_char ' ' (input_line ic) with
       | ["B"; h; _] -> height := int_of_string h
       | ["T"; _; hex] ->
         flush ();
         cur := Some (Serialize.deserialize_transaction
                        (Serialize.reader_of_cstruct (hex_decode hex)), [])
       | ["P"; sats; spk] ->
         (match !cur with
          | Some (tx, ps) ->
            let spk = if spk = "-" then Cstruct.empty else hex_decode spk in
            cur := Some (tx, (Int64.of_string sats, spk) :: ps)
          | None -> failwith "P before T")
       | _ -> failwith ("bad line in " ^ path)
     done with End_of_file -> ());
  flush (); close_in ic;
  (!height, Array.of_list (List.rev !txs))

let is_p2tr spk =
  Cstruct.length spk = 34 && Cstruct.get_uint8 spk 0 = 0x51
  && Cstruct.get_uint8 spk 1 = 0x20

let failures = ref 0
let fail fmt = Printf.ksprintf (fun s -> incr failures; print_endline ("FAIL: " ^ s)) fmt
let check name ok = if ok then () else fail "%s" name

let bip143_types = [0x00; 0x01; 0x02; 0x03; 0x04; 0x81; 0x82; 0x83]
let bip341_types = [0x00; 0x01; 0x02; 0x03; 0x81; 0x82; 0x83]
let fake_annex = Crypto.sha256 (Cstruct.of_string "annex")
let fake_leaf = Crypto.sha256 (Cstruct.of_string "leaf")

(* scriptCode used for the BIP-143 differential: the real one where it is
   cheap to derive (P2WPKH: the implied P2PKH; P2WSH: the witness script),
   otherwise the scriptPubKey.  The sighash functions do not interpret it. *)
let script_code_for (b : btx) i =
  let (_, spk) = List.nth b.prevouts i in
  let items = if i < List.length b.tx.witnesses
    then (List.nth b.tx.witnesses i).Types.items else [] in
  match items with
  | [_sig; pk] when Cstruct.length pk = 33 ->
    Script.build_p2pkh_script (Crypto.hash160 pk)
  | _ :: _ -> List.nth items (List.length items - 1)
  | [] -> spk

let n_seg_cmp = ref 0 and n_tap_cmp = ref 0
let n_inputs = ref 0 and n_wit_inputs = ref 0 and n_tap_inputs = ref 0
let n_verified = ref 0

let diff_tx (b : btx) =
  let tx = b.tx and prevouts = b.prevouts in
  let nin = List.length tx.inputs and nout = List.length tx.outputs in
  let txdata = Script.make_txdata ~prevouts tx in
  for i = nin - 1 downto 0 do
    incr n_inputs;
    let (amount, spk) = List.nth prevouts i in
    let has_wit = i < List.length tx.witnesses
                  && (List.nth tx.witnesses i).Types.items <> [] in
    if has_wit then incr n_wit_inputs;
    if has_wit && is_p2tr spk then incr n_tap_inputs;
    let sc = script_code_for b i in
    List.iter (fun ht ->
      let r = Ref.compute_sighash_segwit tx i sc amount ht in
      let a = Script.compute_sighash_segwit ~txdata tx i sc amount ht in
      let c = Script.compute_sighash_segwit tx i sc amount ht in
      incr n_seg_cmp;
      if not (Cstruct.equal r a && Cstruct.equal r c) then
        fail "bip143 mismatch txid=%s in=%d ht=0x%02x"
          (Types.hash256_to_hex_display (Crypto.compute_txid tx)) i ht
    ) bip143_types;
    List.iter (fun ht ->
      if Script.taproot_sighash_single_safe ht i nout then
        List.iter (fun (annex_hash, tapleaf_hash, codesep_pos) ->
          let r = Ref.compute_sighash_taproot tx i prevouts ht ?annex_hash
                    ?tapleaf_hash ~codesep_pos () in
          let a = Script.compute_sighash_taproot ~txdata tx i prevouts ht
                    ?annex_hash ?tapleaf_hash ~codesep_pos () in
          let c = Script.compute_sighash_taproot tx i prevouts ht ?annex_hash
                    ?tapleaf_hash ~codesep_pos () in
          incr n_tap_cmp;
          if not (Cstruct.equal r a && Cstruct.equal r c) then
            fail "bip341 mismatch txid=%s in=%d ht=0x%02x"
              (Types.hash256_to_hex_display (Crypto.compute_txid tx)) i ht
        ) [ (None, None, 0xFFFFFFFF); (Some fake_annex, None, 0xFFFFFFFF);
            (None, Some fake_leaf, 0xFFFFFFFF); (Some fake_annex, Some fake_leaf, 7) ]
    ) bip341_types
  done

let verify_tx ~flags ?txdata (b : btx) i =
  let tx = b.tx in
  let (amount, spk) = List.nth b.prevouts i in
  let inp = List.nth tx.inputs i in
  let witness = if i < List.length tx.witnesses then List.nth tx.witnesses i
    else { Types.items = [] } in
  Script.verify_script ~tx ~input_index:i ~script_pubkey:spk
    ~script_sig:inp.Types.script_sig ~witness ~amount ~flags
    ~prevouts:b.prevouts ?txdata ()

let verify_block ~flags txs =
  Array.iter (fun (b : btx) ->
    let txdata = Script.make_txdata ~prevouts:b.prevouts b.tx in
    List.iteri (fun i _ ->
      match verify_tx ~flags ~txdata b i with
      | Ok true -> incr n_verified
      | Ok false -> fail "verify false txid=%s in=%d"
                      (Types.hash256_to_hex_display (Crypto.compute_txid b.tx)) i
      | Error e -> fail "verify error txid=%s in=%d: %s"
                     (Types.hash256_to_hex_display (Crypto.compute_txid b.tx)) i e
    ) b.tx.inputs) txs

let queue_block q ~flags txs =
  Validation.cache_clear_global ();
  let jobs = ref [] in
  Array.iteri (fun tx_idx (b : btx) ->
    let utxos = Array.of_list (List.mapi (fun i (v, spk) ->
      let inp = List.nth b.tx.inputs i in
      Some { Validation.txid = inp.Types.previous_output.Types.txid;
             vout = inp.Types.previous_output.Types.vout; value = v;
             script_pubkey = spk; height = 1; is_coinbase = false }) b.prevouts) in
    jobs := Validation.append_script_jobs !jobs ~tx:b.tx ~tx_idx ~flags
              ~prevouts:b.prevouts ~utxos) txs;
  let jobs = Array.of_list (List.rev !jobs) in
  (* every job of a tx must carry the SAME physical txdata *)
  let shared = ref true in
  Array.iteri (fun k (j : Validation.script_check_job) ->
    if k > 0 then begin
      let p = jobs.(k - 1) in
      if p.tx == j.tx then
        match p.txdata, j.txdata with
        | Some a, Some b -> if a != b then shared := false
        | _ -> shared := false
    end) jobs;
  check "append_script_jobs shares one txdata per tx" !shared;
  let r = Validation.run_script_check_queue q jobs in
  check (Printf.sprintf "ScriptCheckQueue ok (%d jobs, fail=%s)" (Array.length jobs)
           r.first_fail_reason) r.ok;
  Array.length jobs

(* ---- D. controls --------------------------------------------------------- *)
let controls ~flags (all : btx list) =
  let seg = List.find (fun (b : btx) ->
      List.length b.tx.inputs >= 2 &&
      List.exists (fun (_, spk) -> Cstruct.length spk = 22
                                   && Cstruct.get_uint8 spk 0 = 0) b.prevouts
      && List.for_all (fun (_, spk) -> Cstruct.length spk = 22
                                       && Cstruct.get_uint8 spk 0 = 0) b.prevouts) all in
  let tap = List.find (fun (b : btx) ->
      List.length b.tx.inputs >= 2 &&
      List.for_all (fun (_, spk) -> is_p2tr spk) b.prevouts) all in
  let other = List.find (fun (b : btx) -> b.tx != seg.tx) all in
  (* D1: foreign-tx cache is ignored *)
  let foreign = Script.make_txdata ~prevouts:other.prevouts other.tx in
  let sc = script_code_for seg 0 in
  let (amt, _) = List.nth seg.prevouts 0 in
  let r = Ref.compute_sighash_segwit seg.tx 0 sc amt 1 in
  check "D1 foreign-tx txdata ignored (bip143)"
    (Cstruct.equal r (Script.compute_sighash_segwit ~txdata:foreign seg.tx 0 sc amt 1));
  check "D1 foreign-tx txdata ignored (verify)"
    (verify_tx ~flags ~txdata:foreign seg 0 = Ok true);
  (* D2: structurally-equal but physically-different prevouts => recompute *)
  let tdata = Script.make_txdata ~prevouts:tap.prevouts tap.tx in
  let copy = List.map (fun (a, s) -> (a, Cstruct.of_string (Cstruct.to_string s))) tap.prevouts in
  let bumped = List.mapi (fun i (a, s) -> if i = 0 then (Int64.add a 1L, s) else (a, s)) tap.prevouts in
  let r0 = Ref.compute_sighash_taproot tap.tx 0 tap.prevouts 0 () in
  check "D2 copied prevouts same sighash"
    (Cstruct.equal r0 (Script.compute_sighash_taproot ~txdata:tdata tap.tx 0 copy 0 ()));
  let rb = Ref.compute_sighash_taproot tap.tx 0 bumped 0 () in
  check "D2 bumped prevouts differ from original (instrument)" (not (Cstruct.equal r0 rb));
  check "D2 cache for original prevouts NOT used for bumped list"
    (Cstruct.equal rb (Script.compute_sighash_taproot ~txdata:tdata tap.tx 0 bumped 0 ()));
  (* D3: corrupted cache is REACHED: sighash changes, verify fails *)
  let bad = Cstruct.of_string (String.make 32 '\x42') in
  let corrupt_seg = Script.make_txdata ~prevouts:seg.prevouts seg.tx in
  Atomic.set corrupt_seg.Script.pt_hash_prevouts (Some bad);
  check "D3 corrupted bip143 cache changes the sighash"
    (not (Cstruct.equal r (Script.compute_sighash_segwit ~txdata:corrupt_seg seg.tx 0 sc amt 1)));
  check "D3 control: seg input verifies with a clean cache"
    (verify_tx ~flags ~txdata:(Script.make_txdata ~prevouts:seg.prevouts seg.tx) seg 0 = Ok true);
  check "D3 corrupted bip143 cache makes the real P2WPKH input FAIL verify"
    (verify_tx ~flags ~txdata:corrupt_seg seg 0 <> Ok true);
  let corrupt_tap = Script.make_txdata ~prevouts:tap.prevouts tap.tx in
  Atomic.set corrupt_tap.Script.pt_amounts_single (Some bad);
  check "D3 control: taproot input verifies with a clean cache"
    (verify_tx ~flags ~txdata:(Script.make_txdata ~prevouts:tap.prevouts tap.tx) tap 0 = Ok true);
  check "D3 corrupted bip341 cache makes the real P2TR input FAIL verify"
    (verify_tx ~flags ~txdata:corrupt_tap tap 0 <> Ok true);
  (* D4: mutated output value => SIGHASH_ALL signature fails *)
  let mutate (b : btx) =
    let outs = List.mapi (fun i (o : Types.tx_out) ->
      if i = 0 then { o with Types.value = Int64.add o.value 1L } else o) b.tx.outputs in
    { b with tx = { b.tx with Types.outputs = outs } } in
  check "D4 mutated-output seg tx fails verify" (verify_tx ~flags (mutate seg) 0 <> Ok true);
  check "D4 mutated-output taproot tx fails verify" (verify_tx ~flags (mutate tap) 0 <> Ok true);
  (* D5: the block-connect job path (append_script_jobs -> ScriptCheckQueue
     worker Domains -> verify_one_input -> verify_script) REACHES the shared
     cache: corrupting it makes the batch fail; the clean batch passes. *)
  let q = Validation.create_script_check_queue 4 in
  let run_jobs (b : btx) corrupt =
    Validation.cache_clear_global ();
    let utxos = Array.of_list (List.mapi (fun i (v, spk) ->
      let inp = List.nth b.tx.inputs i in
      Some { Validation.txid = inp.Types.previous_output.Types.txid;
             vout = inp.Types.previous_output.Types.vout; value = v;
             script_pubkey = spk; height = 1; is_coinbase = false }) b.prevouts) in
    let jobs = Array.of_list (List.rev (Validation.append_script_jobs [] ~tx:b.tx
                 ~tx_idx:0 ~flags ~prevouts:b.prevouts ~utxos)) in
    (if corrupt then match jobs.(0).txdata with
      | Some d -> Atomic.set d.Script.pt_hash_prevouts (Some bad);
                  Atomic.set d.Script.pt_amounts_single (Some bad)
      | None -> fail "D5 job has no txdata");
    (Validation.run_script_check_queue q jobs).ok in
  check "D5 clean seg jobs pass through the queue" (run_jobs seg false);
  check "D5 corrupted shared txdata makes seg queue batch FAIL" (not (run_jobs seg true));
  check "D5 clean taproot jobs pass through the queue" (run_jobs tap false);
  check "D5 corrupted shared txdata makes taproot queue batch FAIL" (not (run_jobs tap true));
  Validation.shutdown_script_check_queue q;
  Printf.printf "controls: seg tx %s (%d in), taproot tx %s (%d in)\n"
    (Types.hash256_to_hex_display (Crypto.compute_txid seg.tx)) (List.length seg.tx.inputs)
    (Types.hash256_to_hex_display (Crypto.compute_txid tap.tx)) (List.length tap.tx.inputs)

(* ---- E. BIP-341 wallet vectors -------------------------------------------- *)
let bip341_vectors vec_path =
  let open Yojson.Safe.Util in
  let j = Yojson.Safe.from_file vec_path in
  let n = ref 0 in
  List.iter (fun kp ->
    let g = kp |> member "given" in
    let tx = Serialize.deserialize_transaction
        (Serialize.reader_of_cstruct (hex_decode (g |> member "rawUnsignedTx" |> to_string))) in
    let prevouts = g |> member "utxosSpent" |> to_list |> List.map (fun u ->
      (Int64.of_int (u |> member "amountSats" |> to_int),
       hex_decode (u |> member "scriptPubKey" |> to_string))) in
    let txdata = Script.make_txdata ~prevouts tx in
    let im = kp |> member "intermediary" in
    let exp k = im |> member k |> to_string in
    check "bip341 hashPrevouts" (hex_of (Script.prevouts_single_sha txdata) = exp "hashPrevouts");
    check "bip341 hashAmounts" (hex_of (Script.amounts_single_sha txdata) = exp "hashAmounts");
    check "bip341 hashScriptPubkeys" (hex_of (Script.scripts_single_sha txdata) = exp "hashScriptPubkeys");
    check "bip341 hashSequences" (hex_of (Script.sequences_single_sha txdata) = exp "hashSequences");
    check "bip341 hashOutputs" (hex_of (Script.outputs_single_sha txdata) = exp "hashOutputs");
    List.iter (fun is ->
      let gi = is |> member "given" in
      let idx = gi |> member "txinIndex" |> to_int in
      let ht = gi |> member "hashType" |> to_int in
      let want = is |> member "intermediary" |> member "sigHash" |> to_string in
      let got = Script.compute_sighash_taproot ~txdata tx idx prevouts ht () in
      incr n;
      if hex_of got <> want then fail "bip341 vector in=%d ht=0x%02x" idx ht
    ) (kp |> member "inputSpending" |> to_list)
  ) (j |> member "keyPathSpending" |> to_list);
  !n

let () =
  let dir = Sys.argv.(1) in
  let files = Sys.readdir dir |> Array.to_list
              |> List.filter (fun f -> Filename.check_suffix f ".txt") |> List.sort compare in
  let q = Validation.create_script_check_queue 8 in
  let all = ref [] in
  let n_jobs = ref 0 in
  List.iter (fun f ->
    let (h, txs) = load_block (Filename.concat dir f) in
    let flags = Consensus.get_block_script_flags h Consensus.mainnet in
    Array.iter diff_tx txs;
    verify_block ~flags txs;
    n_jobs := !n_jobs + queue_block q ~flags txs;
    all := Array.to_list txs @ !all;
    Printf.printf "block %d: txs=%d cumulative inputs=%d failures=%d\n%!"
      h (Array.length txs) !n_inputs !failures) files;
  Validation.shutdown_script_check_queue q;
  let flags = Consensus.get_block_script_flags 800000 Consensus.mainnet in
  controls ~flags !all;
  let nv = if Array.length Sys.argv > 2 then bip341_vectors Sys.argv.(2) else 0 in
  Printf.printf "inputs=%d witness_inputs=%d p2tr_inputs=%d\n" !n_inputs !n_wit_inputs !n_tap_inputs;
  Printf.printf "bip143_comparisons=%d bip341_comparisons=%d verify_ok=%d queue_jobs=%d bip341_vectors=%d\n"
    !n_seg_cmp !n_tap_cmp !n_verified !n_jobs nv;
  Printf.printf "RESULT: %s (failures=%d)\n" (if !failures = 0 then "PASS" else "FAIL") !failures;
  exit (if !failures = 0 then 0 else 1)
