(* PSBT - Partially Signed Bitcoin Transactions (BIP-174)

   This module implements BIP-174 PSBT support for multi-party transaction signing.

   PSBT workflow roles:
   - Creator: Creates an unsigned transaction and initial PSBT
   - Updater: Adds UTXO info, scripts, derivation paths
   - Signer: Adds partial signatures
   - Combiner: Merges PSBTs from multiple signers
   - Finalizer: Produces the final signed transaction
   - Extractor: Extracts the final transaction for broadcast *)

(* ============================================================================
   PSBT Constants (BIP-174)
   ============================================================================ *)

(* Magic bytes: "psbt" + 0xff *)
let psbt_magic = Cstruct.of_string "psbt\xff"

(* Global types *)
let psbt_global_unsigned_tx = 0x00
let psbt_global_xpub = 0x01
let psbt_global_version = 0xFB
let psbt_global_proprietary = 0xFC

(* Input types *)
let psbt_in_non_witness_utxo = 0x00
let psbt_in_witness_utxo = 0x01
let psbt_in_partial_sig = 0x02
let psbt_in_sighash_type = 0x03
let psbt_in_redeem_script = 0x04
let psbt_in_witness_script = 0x05
let psbt_in_bip32_derivation = 0x06
let psbt_in_final_scriptsig = 0x07
let psbt_in_final_scriptwitness = 0x08
let psbt_in_tap_key_sig = 0x13
let psbt_in_tap_script_sig = 0x14
let psbt_in_tap_leaf_script = 0x15
let psbt_in_tap_bip32_derivation = 0x16
let psbt_in_tap_internal_key = 0x17
let psbt_in_tap_merkle_root = 0x18

(* Output types *)
let psbt_out_redeem_script = 0x00
let psbt_out_witness_script = 0x01
let psbt_out_bip32_derivation = 0x02
let psbt_out_tap_internal_key = 0x05
let psbt_out_tap_tree = 0x06
let psbt_out_tap_bip32_derivation = 0x07

(* Separator byte (0x00 length key) *)
let psbt_separator = 0x00

(* Maximum PSBT size: 100 MB *)
let max_psbt_size = 100_000_000

(* Highest supported PSBT version *)
let psbt_highest_version = 0l

(* ============================================================================
   PSBT Key-Value Map Types
   ============================================================================ *)

(* BIP-32 key origin info *)
type key_origin = {
  fingerprint : int32;        (* Master key fingerprint *)
  path : int32 list;          (* Derivation path indices *)
}

(* Partial signature entry *)
type partial_sig = {
  pubkey : Cstruct.t;         (* 33-byte compressed pubkey *)
  signature : Cstruct.t;      (* DER signature + sighash byte *)
}

(* BIP-32 derivation entry *)
type bip32_derivation = {
  pubkey : Cstruct.t;         (* 33-byte compressed pubkey *)
  origin : key_origin;        (* Key origin info *)
}

(* Taproot BIP-32 derivation *)
type tap_bip32_derivation = {
  xonly_pubkey : Cstruct.t;   (* 32-byte x-only pubkey *)
  leaf_hashes : Cstruct.t list; (* List of 32-byte leaf hashes *)
  origin : key_origin;
}

(* Taproot script signature *)
type tap_script_sig = {
  xonly_pubkey : Cstruct.t;   (* 32-byte x-only pubkey *)
  leaf_hash : Cstruct.t;      (* 32-byte leaf hash *)
  signature : Cstruct.t;      (* 64 or 65 byte Schnorr signature *)
}

(* Taproot leaf script *)
type tap_leaf_script = {
  control_block : Cstruct.t;  (* Control block *)
  script : Cstruct.t;         (* Leaf script *)
  leaf_version : int;         (* Leaf version *)
}

(* PSBT Input *)
type psbt_input = {
  non_witness_utxo : Types.transaction option;   (* Full previous tx *)
  witness_utxo : Types.tx_out option;            (* Previous output *)
  partial_sigs : partial_sig list;               (* Partial signatures *)
  sighash_type : int32 option;                   (* Sighash type *)
  redeem_script : Cstruct.t option;              (* P2SH redeem script *)
  witness_script : Cstruct.t option;             (* P2WSH witness script *)
  bip32_derivations : bip32_derivation list;     (* BIP-32 derivation paths *)
  final_scriptsig : Cstruct.t option;            (* Final scriptSig *)
  final_scriptwitness : Cstruct.t list option;   (* Final witness stack *)
  tap_key_sig : Cstruct.t option;                (* Taproot key path sig *)
  tap_script_sigs : tap_script_sig list;         (* Taproot script sigs *)
  tap_leaf_scripts : tap_leaf_script list;       (* Taproot leaf scripts *)
  tap_bip32_derivations : tap_bip32_derivation list;
  tap_internal_key : Cstruct.t option;           (* 32-byte internal key *)
  tap_merkle_root : Cstruct.t option;            (* 32-byte merkle root *)
  unknown : (Cstruct.t * Cstruct.t) list;        (* Unknown key-values *)
}

(* PSBT Output *)
type psbt_output = {
  redeem_script : Cstruct.t option;
  witness_script : Cstruct.t option;
  bip32_derivations : bip32_derivation list;
  tap_internal_key : Cstruct.t option;
  tap_tree : Cstruct.t option;                   (* Serialized tap tree *)
  tap_bip32_derivations : tap_bip32_derivation list;
  unknown : (Cstruct.t * Cstruct.t) list;
}

(* Global extended public key *)
type global_xpub = {
  xpub : Cstruct.t;           (* 78-byte extended public key *)
  origin : key_origin;
}

(* Full PSBT structure *)
type psbt = {
  tx : Types.transaction;           (* Unsigned transaction *)
  global_xpubs : global_xpub list;  (* Global xpubs *)
  version : int32 option;           (* PSBT version (0xFB) *)
  inputs : psbt_input list;
  outputs : psbt_output list;
  unknown : (Cstruct.t * Cstruct.t) list;
}

(* PSBT Error types *)
type psbt_error =
  | Invalid_magic
  | Missing_unsigned_tx
  | Invalid_tx_scriptSig_not_empty
  | Invalid_tx_witness_not_empty
  | Duplicate_key of string
  | Invalid_key_length of string
  | Input_output_count_mismatch
  | Missing_separator
  | Unsupported_version of int32
  | Parse_error of string

let string_of_error = function
  | Invalid_magic -> "Invalid PSBT magic bytes"
  | Missing_unsigned_tx -> "Missing unsigned transaction"
  | Invalid_tx_scriptSig_not_empty -> "Unsigned tx has non-empty scriptSig"
  | Invalid_tx_witness_not_empty -> "Unsigned tx has non-empty witness"
  | Duplicate_key s -> Printf.sprintf "Duplicate key: %s" s
  | Invalid_key_length s -> Printf.sprintf "Invalid key length: %s" s
  | Input_output_count_mismatch -> "Input/output count doesn't match transaction"
  | Missing_separator -> "Missing separator at end of map"
  | Unsupported_version v -> Printf.sprintf "Unsupported PSBT version: %ld" v
  | Parse_error s -> Printf.sprintf "Parse error: %s" s

(* Empty input/output constructors *)
let empty_input = {
  non_witness_utxo = None;
  witness_utxo = None;
  partial_sigs = [];
  sighash_type = None;
  redeem_script = None;
  witness_script = None;
  bip32_derivations = [];
  final_scriptsig = None;
  final_scriptwitness = None;
  tap_key_sig = None;
  tap_script_sigs = [];
  tap_leaf_scripts = [];
  tap_bip32_derivations = [];
  tap_internal_key = None;
  tap_merkle_root = None;
  unknown = [];
}

let empty_output = {
  redeem_script = None;
  witness_script = None;
  bip32_derivations = [];
  tap_internal_key = None;
  tap_tree = None;
  tap_bip32_derivations = [];
  unknown = [];
}

(* ============================================================================
   PSBT Serialization
   ============================================================================ *)

(* Write a key-value pair *)
let write_kv w key_type key_data value =
  (* Key: [key_len][key_type][key_data] *)
  let key_len = 1 + Cstruct.length key_data in
  Serialize.write_compact_size w key_len;
  Serialize.write_uint8 w key_type;
  Serialize.write_bytes w key_data;
  (* Value: [value_len][value] *)
  Serialize.write_compact_size w (Cstruct.length value);
  Serialize.write_bytes w value

(* Write a key-value pair with no key data *)
let write_kv_simple w key_type value =
  (* Key: [1][key_type] *)
  Serialize.write_compact_size w 1;
  Serialize.write_uint8 w key_type;
  (* Value: [value_len][value] *)
  Serialize.write_compact_size w (Cstruct.length value);
  Serialize.write_bytes w value

(* Write separator *)
let write_separator w =
  Serialize.write_uint8 w psbt_separator

(* Serialize key origin *)
let serialize_key_origin (origin : key_origin) : Cstruct.t =
  let w = Serialize.writer_create () in
  Serialize.write_int32_le w origin.fingerprint;
  List.iter (fun idx -> Serialize.write_int32_le w idx) origin.path;
  Serialize.writer_to_cstruct w

(* Serialize transaction without witness for PSBT global *)
let serialize_tx_no_witness (tx : Types.transaction) : Cstruct.t =
  let w = Serialize.writer_create () in
  Serialize.serialize_transaction_no_witness w tx;
  Serialize.writer_to_cstruct w

(* Serialize a PSBT input *)
let serialize_input w (inp : psbt_input) =
  (* Non-witness UTXO *)
  (match inp.non_witness_utxo with
   | Some tx ->
     let tx_bytes = serialize_tx_no_witness tx in
     write_kv_simple w psbt_in_non_witness_utxo tx_bytes
   | None -> ());

  (* Witness UTXO *)
  (match inp.witness_utxo with
   | Some utxo ->
     let w2 = Serialize.writer_create () in
     Serialize.serialize_tx_out w2 utxo;
     write_kv_simple w psbt_in_witness_utxo (Serialize.writer_to_cstruct w2)
   | None -> ());

  (* Only write partial sigs and other signing data if not finalized *)
  let is_finalized = inp.final_scriptsig <> None || inp.final_scriptwitness <> None in

  if not is_finalized then begin
    (* Partial signatures *)
    List.iter (fun (ps : partial_sig) ->
      write_kv w psbt_in_partial_sig ps.pubkey ps.signature
    ) inp.partial_sigs;

    (* Sighash type *)
    (match inp.sighash_type with
     | Some sht ->
       let w2 = Serialize.writer_create () in
       Serialize.write_int32_le w2 sht;
       write_kv_simple w psbt_in_sighash_type (Serialize.writer_to_cstruct w2)
     | None -> ());

    (* Redeem script *)
    (match inp.redeem_script with
     | Some rs -> write_kv_simple w psbt_in_redeem_script rs
     | None -> ());

    (* Witness script *)
    (match inp.witness_script with
     | Some ws -> write_kv_simple w psbt_in_witness_script ws
     | None -> ());

    (* BIP-32 derivations *)
    List.iter (fun d ->
      write_kv w psbt_in_bip32_derivation d.pubkey (serialize_key_origin d.origin)
    ) inp.bip32_derivations;

    (* Taproot key signature *)
    (match inp.tap_key_sig with
     | Some sig_ -> write_kv_simple w psbt_in_tap_key_sig sig_
     | None -> ());

    (* Taproot script signatures *)
    List.iter (fun tss ->
      let key_data = Cstruct.concat [tss.xonly_pubkey; tss.leaf_hash] in
      write_kv w psbt_in_tap_script_sig key_data tss.signature
    ) inp.tap_script_sigs;

    (* Taproot leaf scripts *)
    List.iter (fun tls ->
      let value = Cstruct.concat [tls.script; Cstruct.of_string (String.make 1 (Char.chr tls.leaf_version))] in
      write_kv w psbt_in_tap_leaf_script tls.control_block value
    ) inp.tap_leaf_scripts;

    (* Taproot BIP-32 derivations *)
    List.iter (fun td ->
      let w2 = Serialize.writer_create () in
      Serialize.write_compact_size w2 (List.length td.leaf_hashes);
      List.iter (fun lh -> Serialize.write_bytes w2 lh) td.leaf_hashes;
      let origin_bytes = serialize_key_origin td.origin in
      Serialize.write_bytes w2 origin_bytes;
      write_kv w psbt_in_tap_bip32_derivation td.xonly_pubkey (Serialize.writer_to_cstruct w2)
    ) inp.tap_bip32_derivations;

    (* Taproot internal key *)
    (match inp.tap_internal_key with
     | Some key -> write_kv_simple w psbt_in_tap_internal_key key
     | None -> ());

    (* Taproot merkle root *)
    (match inp.tap_merkle_root with
     | Some root -> write_kv_simple w psbt_in_tap_merkle_root root
     | None -> ())
  end;

  (* Final scriptSig *)
  (match inp.final_scriptsig with
   | Some ss -> write_kv_simple w psbt_in_final_scriptsig ss
   | None -> ());

  (* Final scriptWitness *)
  (match inp.final_scriptwitness with
   | Some wit ->
     let w2 = Serialize.writer_create () in
     Serialize.write_compact_size w2 (List.length wit);
     List.iter (fun item ->
       Serialize.write_compact_size w2 (Cstruct.length item);
       Serialize.write_bytes w2 item
     ) wit;
     write_kv_simple w psbt_in_final_scriptwitness (Serialize.writer_to_cstruct w2)
   | None -> ());

  (* Unknown entries *)
  List.iter (fun (k, v) ->
    Serialize.write_compact_size w (Cstruct.length k);
    Serialize.write_bytes w k;
    Serialize.write_compact_size w (Cstruct.length v);
    Serialize.write_bytes w v
  ) inp.unknown;

  (* Separator *)
  write_separator w

(* Serialize a PSBT output *)
let serialize_output w (out : psbt_output) =
  (* Redeem script *)
  (match out.redeem_script with
   | Some rs -> write_kv_simple w psbt_out_redeem_script rs
   | None -> ());

  (* Witness script *)
  (match out.witness_script with
   | Some ws -> write_kv_simple w psbt_out_witness_script ws
   | None -> ());

  (* BIP-32 derivations *)
  List.iter (fun d ->
    write_kv w psbt_out_bip32_derivation d.pubkey (serialize_key_origin d.origin)
  ) out.bip32_derivations;

  (* Taproot internal key *)
  (match out.tap_internal_key with
   | Some key -> write_kv_simple w psbt_out_tap_internal_key key
   | None -> ());

  (* Taproot tree *)
  (match out.tap_tree with
   | Some tree -> write_kv_simple w psbt_out_tap_tree tree
   | None -> ());

  (* Taproot BIP-32 derivations *)
  List.iter (fun td ->
    let w2 = Serialize.writer_create () in
    Serialize.write_compact_size w2 (List.length td.leaf_hashes);
    List.iter (fun lh -> Serialize.write_bytes w2 lh) td.leaf_hashes;
    let origin_bytes = serialize_key_origin td.origin in
    Serialize.write_bytes w2 origin_bytes;
    write_kv w psbt_out_tap_bip32_derivation td.xonly_pubkey (Serialize.writer_to_cstruct w2)
  ) out.tap_bip32_derivations;

  (* Unknown entries *)
  List.iter (fun (k, v) ->
    Serialize.write_compact_size w (Cstruct.length k);
    Serialize.write_bytes w k;
    Serialize.write_compact_size w (Cstruct.length v);
    Serialize.write_bytes w v
  ) out.unknown;

  (* Separator *)
  write_separator w

(* Serialize a complete PSBT *)
let serialize (psbt : psbt) : Cstruct.t =
  let w = Serialize.writer_create () in

  (* Magic bytes *)
  Serialize.write_bytes w psbt_magic;

  (* Global: unsigned transaction *)
  let tx_bytes = serialize_tx_no_witness psbt.tx in
  write_kv_simple w psbt_global_unsigned_tx tx_bytes;

  (* Global: xpubs *)
  List.iter (fun gx ->
    write_kv w psbt_global_xpub gx.xpub (serialize_key_origin gx.origin)
  ) psbt.global_xpubs;

  (* Global: version (only if > 0) *)
  (match psbt.version with
   | Some v when v > 0l ->
     let w2 = Serialize.writer_create () in
     Serialize.write_int32_le w2 v;
     write_kv_simple w psbt_global_version (Serialize.writer_to_cstruct w2)
   | _ -> ());

  (* Global: unknown entries *)
  List.iter (fun (k, v) ->
    Serialize.write_compact_size w (Cstruct.length k);
    Serialize.write_bytes w k;
    Serialize.write_compact_size w (Cstruct.length v);
    Serialize.write_bytes w v
  ) psbt.unknown;

  (* Global separator *)
  write_separator w;

  (* Inputs *)
  List.iter (serialize_input w) psbt.inputs;

  (* Outputs *)
  List.iter (serialize_output w) psbt.outputs;

  Serialize.writer_to_cstruct w

(* ============================================================================
   PSBT Deserialization
   ============================================================================ *)

(* Read a key from the stream, returns None if separator *)
let read_key r : Cstruct.t option =
  let len = Serialize.read_compact_size r in
  if len = 0 then None
  else Some (Serialize.read_bytes r len)

(* Read a value from the stream *)
let read_value r : Cstruct.t =
  let len = Serialize.read_compact_size r in
  Serialize.read_bytes r len

(* Parse key origin from bytes *)
let parse_key_origin (data : Cstruct.t) : key_origin =
  let r = Serialize.reader_of_cstruct data in
  let fingerprint = Serialize.read_int32_le r in
  let path_len = (Cstruct.length data - 4) / 4 in
  let path = List.init path_len (fun _ -> Serialize.read_int32_le r) in
  { fingerprint; path }

(* Deserialize a PSBT input *)
let deserialize_input r : (psbt_input, psbt_error) result =
  let inp = ref empty_input in
  let seen_keys = Hashtbl.create 16 in

  let rec read_entries () =
    match read_key r with
    | None -> Ok !inp  (* Separator found *)
    | Some key ->
      let value = read_value r in

      (* Check for duplicate keys *)
      let key_str = Cstruct.to_string key in
      if Hashtbl.mem seen_keys key_str then
        Error (Duplicate_key "input key")
      else begin
        Hashtbl.add seen_keys key_str ();

        (* Parse key type *)
        let key_type = Cstruct.get_uint8 key 0 in
        let key_data = if Cstruct.length key > 1 then Cstruct.sub key 1 (Cstruct.length key - 1) else Cstruct.empty in

        (match key_type with
         | t when t = psbt_in_non_witness_utxo ->
           let tx_r = Serialize.reader_of_cstruct value in
           let tx = Serialize.deserialize_transaction tx_r in
           inp := { !inp with non_witness_utxo = Some tx }

         | t when t = psbt_in_witness_utxo ->
           let utxo_r = Serialize.reader_of_cstruct value in
           let utxo = Serialize.deserialize_tx_out utxo_r in
           inp := { !inp with witness_utxo = Some utxo }

         | t when t = psbt_in_partial_sig ->
           if Cstruct.length key_data <> 33 && Cstruct.length key_data <> 65 then
             ()  (* Skip invalid pubkey size *)
           else begin
             let ps = { pubkey = key_data; signature = value } in
             inp := { !inp with partial_sigs = ps :: !inp.partial_sigs }
           end

         | t when t = psbt_in_sighash_type ->
           let sht_r = Serialize.reader_of_cstruct value in
           let sht = Serialize.read_int32_le sht_r in
           inp := { !inp with sighash_type = Some sht }

         | t when t = psbt_in_redeem_script ->
           inp := { !inp with redeem_script = Some value }

         | t when t = psbt_in_witness_script ->
           inp := { !inp with witness_script = Some value }

         | t when t = psbt_in_bip32_derivation ->
           if Cstruct.length key_data = 33 then begin
             let origin = parse_key_origin value in
             let d = { pubkey = key_data; origin } in
             inp := { !inp with bip32_derivations = d :: !inp.bip32_derivations }
           end

         | t when t = psbt_in_final_scriptsig ->
           inp := { !inp with final_scriptsig = Some value }

         | t when t = psbt_in_final_scriptwitness ->
           let wit_r = Serialize.reader_of_cstruct value in
           let count = Serialize.read_compact_size wit_r in
           let items = List.init count (fun _ ->
             let len = Serialize.read_compact_size wit_r in
             Serialize.read_bytes wit_r len
           ) in
           inp := { !inp with final_scriptwitness = Some items }

         | t when t = psbt_in_tap_key_sig ->
           inp := { !inp with tap_key_sig = Some value }

         | t when t = psbt_in_tap_script_sig ->
           if Cstruct.length key_data = 64 then begin
             let xonly = Cstruct.sub key_data 0 32 in
             let leaf_hash = Cstruct.sub key_data 32 32 in
             let tss = { xonly_pubkey = xonly; leaf_hash; signature = value } in
             inp := { !inp with tap_script_sigs = tss :: !inp.tap_script_sigs }
           end

         | t when t = psbt_in_tap_leaf_script ->
           if Cstruct.length value >= 1 then begin
             let script = Cstruct.sub value 0 (Cstruct.length value - 1) in
             let leaf_version = Cstruct.get_uint8 value (Cstruct.length value - 1) in
             let tls = { control_block = key_data; script; leaf_version } in
             inp := { !inp with tap_leaf_scripts = tls :: !inp.tap_leaf_scripts }
           end

         | t when t = psbt_in_tap_bip32_derivation ->
           if Cstruct.length key_data = 32 then begin
             let val_r = Serialize.reader_of_cstruct value in
             let num_hashes = Serialize.read_compact_size val_r in
             let leaf_hashes = List.init num_hashes (fun _ -> Serialize.read_bytes val_r 32) in
             let remaining = Cstruct.sub value val_r.pos (Cstruct.length value - val_r.pos) in
             let origin = parse_key_origin remaining in
             let td = { xonly_pubkey = key_data; leaf_hashes; origin } in
             inp := { !inp with tap_bip32_derivations = td :: !inp.tap_bip32_derivations }
           end

         | t when t = psbt_in_tap_internal_key ->
           inp := { !inp with tap_internal_key = Some value }

         | t when t = psbt_in_tap_merkle_root ->
           inp := { !inp with tap_merkle_root = Some value }

         | _ ->
           (* Unknown key type *)
           inp := { !inp with unknown = (key, value) :: !inp.unknown }
        );
        read_entries ()
      end
  in
  read_entries ()

(* Deserialize a PSBT output *)
let deserialize_output r : (psbt_output, psbt_error) result =
  let out = ref empty_output in
  let seen_keys = Hashtbl.create 16 in

  let rec read_entries () =
    match read_key r with
    | None -> Ok !out
    | Some key ->
      let value = read_value r in

      let key_str = Cstruct.to_string key in
      if Hashtbl.mem seen_keys key_str then
        Error (Duplicate_key "output key")
      else begin
        Hashtbl.add seen_keys key_str ();

        let key_type = Cstruct.get_uint8 key 0 in
        let key_data = if Cstruct.length key > 1 then Cstruct.sub key 1 (Cstruct.length key - 1) else Cstruct.empty in

        (match key_type with
         | t when t = psbt_out_redeem_script ->
           out := { !out with redeem_script = Some value }

         | t when t = psbt_out_witness_script ->
           out := { !out with witness_script = Some value }

         | t when t = psbt_out_bip32_derivation ->
           if Cstruct.length key_data = 33 then begin
             let origin = parse_key_origin value in
             let d = { pubkey = key_data; origin } in
             out := { !out with bip32_derivations = d :: !out.bip32_derivations }
           end

         | t when t = psbt_out_tap_internal_key ->
           out := { !out with tap_internal_key = Some value }

         | t when t = psbt_out_tap_tree ->
           out := { !out with tap_tree = Some value }

         | t when t = psbt_out_tap_bip32_derivation ->
           if Cstruct.length key_data = 32 then begin
             let val_r = Serialize.reader_of_cstruct value in
             let num_hashes = Serialize.read_compact_size val_r in
             let leaf_hashes = List.init num_hashes (fun _ -> Serialize.read_bytes val_r 32) in
             let remaining = Cstruct.sub value val_r.pos (Cstruct.length value - val_r.pos) in
             let origin = parse_key_origin remaining in
             let td = { xonly_pubkey = key_data; leaf_hashes; origin } in
             out := { !out with tap_bip32_derivations = td :: !out.tap_bip32_derivations }
           end

         | _ ->
           out := { !out with unknown = (key, value) :: !out.unknown }
        );
        read_entries ()
      end
  in
  read_entries ()

(* Deserialize a complete PSBT *)
let deserialize (data : Cstruct.t) : (psbt, psbt_error) result =
  if Cstruct.length data < 5 then
    Error Invalid_magic
  else
    let r = Serialize.reader_of_cstruct data in

    (* Check magic bytes *)
    let magic = Serialize.read_bytes r 5 in
    if not (Cstruct.equal magic psbt_magic) then
      Error Invalid_magic
    else begin
      let tx = ref None in
      let global_xpubs = ref [] in
      let version = ref None in
      let unknown = ref [] in
      let seen_keys = Hashtbl.create 16 in

      (* Read global map *)
      let rec read_global () =
        match read_key r with
        | None -> Ok ()  (* Separator found *)
        | Some key ->
          let value = read_value r in

          let key_str = Cstruct.to_string key in
          if Hashtbl.mem seen_keys key_str then
            Error (Duplicate_key "global key")
          else begin
            Hashtbl.add seen_keys key_str ();

            let key_type = Cstruct.get_uint8 key 0 in
            let key_data = if Cstruct.length key > 1 then Cstruct.sub key 1 (Cstruct.length key - 1) else Cstruct.empty in

            (match key_type with
             | t when t = psbt_global_unsigned_tx ->
               let tx_r = Serialize.reader_of_cstruct value in
               let parsed_tx = Serialize.deserialize_transaction tx_r in
               (* Verify scriptSig and witness are empty *)
               let has_script = List.exists (fun inp ->
                 Cstruct.length inp.Types.script_sig > 0
               ) parsed_tx.inputs in
               let has_witness = parsed_tx.witnesses <> [] &&
                 List.exists (fun wit -> wit.Types.items <> []) parsed_tx.witnesses in
               if has_script then
                 Error Invalid_tx_scriptSig_not_empty
               else if has_witness then
                 Error Invalid_tx_witness_not_empty
               else begin
                 tx := Some parsed_tx;
                 read_global ()
               end

             | t when t = psbt_global_xpub ->
               if Cstruct.length key_data = 78 then begin
                 let origin = parse_key_origin value in
                 let gx = { xpub = key_data; origin } in
                 global_xpubs := gx :: !global_xpubs
               end;
               read_global ()

             | t when t = psbt_global_version ->
               let v_r = Serialize.reader_of_cstruct value in
               let v = Serialize.read_int32_le v_r in
               if v > psbt_highest_version then
                 Error (Unsupported_version v)
               else begin
                 version := Some v;
                 read_global ()
               end

             | _ ->
               unknown := (key, value) :: !unknown;
               read_global ()
            )
          end
      in

      match read_global () with
      | Error e -> Error e
      | Ok () ->
        match !tx with
        | None -> Error Missing_unsigned_tx
        | Some parsed_tx ->
          (* Read inputs *)
          let num_inputs = List.length parsed_tx.inputs in
          let inputs = ref [] in
          let rec read_inputs n =
            if n = 0 then Ok ()
            else
              match deserialize_input r with
              | Error e -> Error e
              | Ok inp ->
                inputs := inp :: !inputs;
                read_inputs (n - 1)
          in

          match read_inputs num_inputs with
          | Error e -> Error e
          | Ok () ->
            (* Read outputs *)
            let num_outputs = List.length parsed_tx.outputs in
            let outputs = ref [] in
            let rec read_outputs n =
              if n = 0 then Ok ()
              else
                match deserialize_output r with
                | Error e -> Error e
                | Ok out ->
                  outputs := out :: !outputs;
                  read_outputs (n - 1)
            in

            match read_outputs num_outputs with
            | Error e -> Error e
            | Ok () ->
              Ok {
                tx = parsed_tx;
                global_xpubs = List.rev !global_xpubs;
                version = !version;
                inputs = List.rev !inputs;
                outputs = List.rev !outputs;
                unknown = List.rev !unknown;
              }
    end

(* ============================================================================
   PSBT Roles: Creator, Updater, Signer, Combiner, Finalizer, Extractor
   ============================================================================ *)

(* Creator role: Create a PSBT from an unsigned transaction *)
let create (tx : Types.transaction) : psbt =
  (* Ensure transaction has empty scriptSigs and witnesses *)
  let clean_tx = {
    tx with
    inputs = List.map (fun inp ->
      { inp with Types.script_sig = Cstruct.empty }
    ) tx.inputs;
    witnesses = [];
  } in
  {
    tx = clean_tx;
    global_xpubs = [];
    version = None;
    inputs = List.map (fun _ -> empty_input) clean_tx.inputs;
    outputs = List.map (fun _ -> empty_output) clean_tx.outputs;
    unknown = [];
  }

(* Updater role: Add UTXO info to an input *)
let add_witness_utxo (psbt : psbt) (input_index : int) (utxo : Types.tx_out) : psbt =
  let inputs = List.mapi (fun i inp ->
    if i = input_index then { inp with witness_utxo = Some utxo }
    else inp
  ) psbt.inputs in
  { psbt with inputs }

let add_non_witness_utxo (psbt : psbt) (input_index : int) (tx : Types.transaction) : psbt =
  let inputs = List.mapi (fun i inp ->
    if i = input_index then { inp with non_witness_utxo = Some tx }
    else inp
  ) psbt.inputs in
  { psbt with inputs }

(* Add redeem script for P2SH input *)
let add_redeem_script (psbt : psbt) (input_index : int) (script : Cstruct.t) : psbt =
  let inputs = List.mapi (fun i (inp : psbt_input) ->
    if i = input_index then { inp with redeem_script = Some script }
    else inp
  ) psbt.inputs in
  { psbt with inputs }

(* Add witness script for P2WSH input *)
let add_witness_script (psbt : psbt) (input_index : int) (script : Cstruct.t) : psbt =
  let inputs = List.mapi (fun i (inp : psbt_input) ->
    if i = input_index then { inp with witness_script = Some script }
    else inp
  ) psbt.inputs in
  { psbt with inputs }

(* Add BIP-32 derivation path to input *)
let add_input_derivation (psbt : psbt) (input_index : int) (deriv : bip32_derivation) : psbt =
  let inputs = List.mapi (fun i (inp : psbt_input) ->
    if i = input_index then { inp with bip32_derivations = deriv :: inp.bip32_derivations }
    else inp
  ) psbt.inputs in
  { psbt with inputs }

(* Add BIP-32 derivation path to output *)
let add_output_derivation (psbt : psbt) (output_index : int) (deriv : bip32_derivation) : psbt =
  let outputs = List.mapi (fun i (out : psbt_output) ->
    if i = output_index then { out with bip32_derivations = deriv :: out.bip32_derivations }
    else out
  ) psbt.outputs in
  { psbt with outputs }

(* Signer role: Add a partial signature *)
let add_partial_sig (psbt : psbt) (input_index : int) (sig_ : partial_sig) : psbt =
  let inputs = List.mapi (fun i (inp : psbt_input) ->
    if i = input_index then { inp with partial_sigs = sig_ :: inp.partial_sigs }
    else inp
  ) psbt.inputs in
  { psbt with inputs }

(* Add sighash type to input *)
let set_sighash_type (psbt : psbt) (input_index : int) (sighash : int32) : psbt =
  let inputs = List.mapi (fun i (inp : psbt_input) ->
    if i = input_index then { inp with sighash_type = Some sighash }
    else inp
  ) psbt.inputs in
  { psbt with inputs }

(* Add taproot key path signature *)
let add_tap_key_sig (psbt : psbt) (input_index : int) (sig_ : Cstruct.t) : psbt =
  let inputs = List.mapi (fun i (inp : psbt_input) ->
    if i = input_index then { inp with tap_key_sig = Some sig_ }
    else inp
  ) psbt.inputs in
  { psbt with inputs }

(* Add taproot script path signature *)
let add_tap_script_sig (psbt : psbt) (input_index : int) (tss : tap_script_sig) : psbt =
  let inputs = List.mapi (fun i (inp : psbt_input) ->
    if i = input_index then { inp with tap_script_sigs = tss :: inp.tap_script_sigs }
    else inp
  ) psbt.inputs in
  { psbt with inputs }

(* Deduplicate partial signatures by pubkey (keep the first occurrence) *)
let dedup_partial_sigs (sigs : partial_sig list) : partial_sig list =
  let seen = Hashtbl.create 16 in
  List.filter (fun (ps : partial_sig) ->
    let key = Cstruct.to_string ps.pubkey in
    if Hashtbl.mem seen key then false
    else begin Hashtbl.replace seen key (); true end
  ) sigs

(* Combiner role: Merge two PSBTs *)
let combine (psbt1 : psbt) (psbt2 : psbt) : (psbt, string) result =
  (* Check that underlying transactions match *)
  let tx1_bytes = serialize_tx_no_witness psbt1.tx in
  let tx2_bytes = serialize_tx_no_witness psbt2.tx in
  if not (Cstruct.equal tx1_bytes tx2_bytes) then
    Error "Cannot combine PSBTs: transactions don't match"
  else
    (* Merge inputs *)
    let merged_inputs = List.map2 (fun inp1 inp2 ->
      {
        non_witness_utxo = (match inp1.non_witness_utxo with Some _ -> inp1.non_witness_utxo | None -> inp2.non_witness_utxo);
        witness_utxo = (match inp1.witness_utxo with Some _ -> inp1.witness_utxo | None -> inp2.witness_utxo);
        partial_sigs = dedup_partial_sigs (inp1.partial_sigs @ inp2.partial_sigs);
        sighash_type = (match inp1.sighash_type with Some _ -> inp1.sighash_type | None -> inp2.sighash_type);
        redeem_script = (match inp1.redeem_script with Some _ -> inp1.redeem_script | None -> inp2.redeem_script);
        witness_script = (match inp1.witness_script with Some _ -> inp1.witness_script | None -> inp2.witness_script);
        bip32_derivations = inp1.bip32_derivations @ inp2.bip32_derivations;
        final_scriptsig = (match inp1.final_scriptsig with Some _ -> inp1.final_scriptsig | None -> inp2.final_scriptsig);
        final_scriptwitness = (match inp1.final_scriptwitness with Some _ -> inp1.final_scriptwitness | None -> inp2.final_scriptwitness);
        tap_key_sig = (match inp1.tap_key_sig with Some _ -> inp1.tap_key_sig | None -> inp2.tap_key_sig);
        tap_script_sigs = inp1.tap_script_sigs @ inp2.tap_script_sigs;
        tap_leaf_scripts = inp1.tap_leaf_scripts @ inp2.tap_leaf_scripts;
        tap_bip32_derivations = inp1.tap_bip32_derivations @ inp2.tap_bip32_derivations;
        tap_internal_key = (match inp1.tap_internal_key with Some _ -> inp1.tap_internal_key | None -> inp2.tap_internal_key);
        tap_merkle_root = (match inp1.tap_merkle_root with Some _ -> inp1.tap_merkle_root | None -> inp2.tap_merkle_root);
        unknown = inp1.unknown @ inp2.unknown;
      }
    ) psbt1.inputs psbt2.inputs in

    (* Merge outputs *)
    let merged_outputs = List.map2 (fun out1 out2 ->
      {
        redeem_script = (match out1.redeem_script with Some _ -> out1.redeem_script | None -> out2.redeem_script);
        witness_script = (match out1.witness_script with Some _ -> out1.witness_script | None -> out2.witness_script);
        bip32_derivations = out1.bip32_derivations @ out2.bip32_derivations;
        tap_internal_key = (match out1.tap_internal_key with Some _ -> out1.tap_internal_key | None -> out2.tap_internal_key);
        tap_tree = (match out1.tap_tree with Some _ -> out1.tap_tree | None -> out2.tap_tree);
        tap_bip32_derivations = out1.tap_bip32_derivations @ out2.tap_bip32_derivations;
        unknown = out1.unknown @ out2.unknown;
      }
    ) psbt1.outputs psbt2.outputs in

    Ok {
      tx = psbt1.tx;
      global_xpubs = psbt1.global_xpubs @ psbt2.global_xpubs;
      version = psbt1.version;
      inputs = merged_inputs;
      outputs = merged_outputs;
      unknown = psbt1.unknown @ psbt2.unknown;
    }

(* Finalizer role: Finalize an input with scriptSig/witness *)
let finalize_input_p2wpkh (psbt : psbt) (input_index : int) : (psbt, string) result =
  if input_index < 0 || input_index >= List.length psbt.inputs then
    Error "Invalid input index"
  else
    let inp = List.nth psbt.inputs input_index in
    match inp.partial_sigs with
    | [] -> Error "No partial signatures for P2WPKH input"
    | ps :: _ ->
      (* P2WPKH witness: [signature, pubkey] *)
      let witness = [ps.signature; ps.pubkey] in
      let inputs = List.mapi (fun i inp' ->
        if i = input_index then {
          inp' with
          final_scriptwitness = Some witness;
          (* Clear signing data *)
          partial_sigs = [];
          bip32_derivations = [];
          redeem_script = None;
          witness_script = None;
        }
        else inp'
      ) psbt.inputs in
      Ok { psbt with inputs }

let finalize_input_p2pkh (psbt : psbt) (input_index : int) : (psbt, string) result =
  if input_index < 0 || input_index >= List.length psbt.inputs then
    Error "Invalid input index"
  else
    let inp = List.nth psbt.inputs input_index in
    match inp.partial_sigs with
    | [] -> Error "No partial signatures for P2PKH input"
    | ps :: _ ->
      (* P2PKH scriptSig: [sig_len][signature][pubkey_len][pubkey] *)
      let w = Serialize.writer_create () in
      Serialize.write_compact_size w (Cstruct.length ps.signature);
      Serialize.write_bytes w ps.signature;
      Serialize.write_compact_size w (Cstruct.length ps.pubkey);
      Serialize.write_bytes w ps.pubkey;
      let scriptsig = Serialize.writer_to_cstruct w in
      let inputs = List.mapi (fun i inp' ->
        if i = input_index then {
          inp' with
          final_scriptsig = Some scriptsig;
          partial_sigs = [];
          bip32_derivations = [];
        }
        else inp'
      ) psbt.inputs in
      Ok { psbt with inputs }

(* Finalize a P2WSH input given a witness script and assembled witness stack.
   The final witness is: [witness_stack..., witness_script] *)
let finalize_input_p2wsh (psbt : psbt) (input_index : int)
    ~(witness_script : Cstruct.t) ~(witness_stack : Cstruct.t list)
    : (psbt, string) result =
  if input_index < 0 || input_index >= List.length psbt.inputs then
    Error "Invalid input index"
  else
    let witness = witness_stack @ [witness_script] in
    let inputs = List.mapi (fun i inp' ->
      if i = input_index then {
        inp' with
        final_scriptwitness = Some witness;
        partial_sigs = [];
        bip32_derivations = [];
        redeem_script = None;
        witness_script = None;
      }
      else inp'
    ) psbt.inputs in
    Ok { psbt with inputs }

(* Finalize a P2SH-P2WPKH input: wraps P2WPKH witness with the P2SH redeemScript.
   scriptSig = <push redeemScript>  where redeemScript = OP_0 <20-byte-pubkey-hash>
   witness   = [signature, pubkey] *)
let finalize_input_p2sh_p2wpkh (psbt : psbt) (input_index : int)
    : (psbt, string) result =
  if input_index < 0 || input_index >= List.length psbt.inputs then
    Error "Invalid input index"
  else
    let inp = List.nth psbt.inputs input_index in
    match inp.partial_sigs with
    | [] -> Error "No partial signatures for P2SH-P2WPKH input"
    | ps :: _ ->
      let pubkey_hash = Crypto.hash160 ps.pubkey in
      (* redeemScript = OP_0 <20 bytes> *)
      let redeem_script = Cstruct.create 22 in
      Cstruct.set_uint8 redeem_script 0 0x00;
      Cstruct.set_uint8 redeem_script 1 0x14;
      Cstruct.blit pubkey_hash 0 redeem_script 2 20;
      (* scriptSig = push(redeemScript) *)
      let w = Serialize.writer_create () in
      Serialize.write_compact_size w (Cstruct.length redeem_script);
      Serialize.write_bytes w redeem_script;
      let scriptsig = Serialize.writer_to_cstruct w in
      (* witness = [signature, pubkey] *)
      let witness = [ps.signature; ps.pubkey] in
      let inputs = List.mapi (fun i inp' ->
        if i = input_index then {
          inp' with
          final_scriptsig = Some scriptsig;
          final_scriptwitness = Some witness;
          partial_sigs = [];
          bip32_derivations = [];
          redeem_script = None;
          witness_script = None;
        }
        else inp'
      ) psbt.inputs in
      Ok { psbt with inputs }

let finalize_input_taproot (psbt : psbt) (input_index : int) : (psbt, string) result =
  if input_index < 0 || input_index >= List.length psbt.inputs then
    Error "Invalid input index"
  else
    let inp = List.nth psbt.inputs input_index in
    match inp.tap_key_sig with
    | Some sig_ ->
      (* Taproot key path spend: witness = [signature] *)
      let witness = [sig_] in
      let inputs = List.mapi (fun i inp' ->
        if i = input_index then {
          inp' with
          final_scriptwitness = Some witness;
          tap_key_sig = None;
          tap_script_sigs = [];
          tap_leaf_scripts = [];
          tap_bip32_derivations = [];
          tap_internal_key = None;
          tap_merkle_root = None;
        }
        else inp'
      ) psbt.inputs in
      Ok { psbt with inputs }
    | None -> Error "No taproot key signature"

(* Check if an input is finalized *)
let is_input_finalized (inp : psbt_input) : bool =
  inp.final_scriptsig <> None || inp.final_scriptwitness <> None

(* Check if all inputs are finalized *)
let is_finalized (psbt : psbt) : bool =
  List.for_all is_input_finalized psbt.inputs

(* Count unsigned inputs *)
let count_unsigned_inputs (psbt : psbt) : int =
  List.length (List.filter (fun inp -> not (is_input_finalized inp)) psbt.inputs)

(* Extractor role: Extract the final signed transaction *)
let extract (psbt : psbt) : (Types.transaction, string) result =
  if not (is_finalized psbt) then
    Error "PSBT is not fully finalized"
  else
    (* Build final transaction with scriptSigs and witnesses *)
    let inputs = List.map2 (fun tx_in psbt_in ->
      let script_sig = match psbt_in.final_scriptsig with
        | Some ss -> ss
        | None -> Cstruct.empty
      in
      { tx_in with Types.script_sig }
    ) psbt.tx.inputs psbt.inputs in

    let has_witness = List.exists (fun inp -> inp.final_scriptwitness <> None) psbt.inputs in

    let witnesses = if has_witness then
      List.map (fun psbt_in ->
        match psbt_in.final_scriptwitness with
        | Some items -> { Types.items }
        | None -> { Types.items = [] }
      ) psbt.inputs
    else
      []
    in

    Ok {
      psbt.tx with
      Types.inputs;
      Types.witnesses;
    }

(* ============================================================================
   PSBT Analysis and Utilities
   ============================================================================ *)

(* PSBT role names *)
type psbt_role = Creator | Updater | Signer | Finalizer | Extractor

let string_of_role = function
  | Creator -> "creator"
  | Updater -> "updater"
  | Signer -> "signer"
  | Finalizer -> "finalizer"
  | Extractor -> "extractor"

(* Get the UTXO for an input (witness or non-witness) *)
let get_input_utxo (psbt : psbt) (input_index : int) : Types.tx_out option =
  if input_index < 0 || input_index >= List.length psbt.inputs then
    None
  else
    let inp = List.nth psbt.inputs input_index in
    match inp.witness_utxo with
    | Some utxo -> Some utxo
    | None ->
      match inp.non_witness_utxo with
      | Some tx ->
        let tx_in = List.nth psbt.tx.inputs input_index in
        let vout = Int32.to_int tx_in.previous_output.vout in
        if vout >= 0 && vout < List.length tx.outputs then
          Some (List.nth tx.outputs vout)
        else
          None
      | None -> None

(* Calculate total input value *)
let get_total_input_value (psbt : psbt) : int64 option =
  let values = List.mapi (fun i _ ->
    match get_input_utxo psbt i with
    | Some utxo -> Some utxo.value
    | None -> None
  ) psbt.inputs in
  if List.exists Option.is_none values then
    None
  else
    Some (List.fold_left Int64.add 0L (List.filter_map Fun.id values))

(* Calculate total output value *)
let get_total_output_value (psbt : psbt) : int64 =
  List.fold_left (fun acc out -> Int64.add acc out.Types.value) 0L psbt.tx.outputs

(* Calculate fee (if all input values are known) *)
let get_fee (psbt : psbt) : int64 option =
  match get_total_input_value psbt with
  | Some input_val ->
    let output_val = get_total_output_value psbt in
    Some (Int64.sub input_val output_val)
  | None -> None

(* Base64 encoding/decoding *)
let to_base64 (psbt : psbt) : string =
  let data = serialize psbt in
  Base64.encode_string (Cstruct.to_string data)

let of_base64 (s : string) : (psbt, psbt_error) result =
  match Base64.decode s with
  | Error _ -> Error (Parse_error "Invalid base64")
  | Ok decoded ->
    deserialize (Cstruct.of_string decoded)
