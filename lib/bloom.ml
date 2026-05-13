(* BIP-37 Bloom Filter — camlcoin W110 audit implementation
 *
 * Reference: Bitcoin Core src/common/bloom.h + bloom.cpp
 * Hash schedule: MurmurHash3(nHashNum * 0xFBA4C795 + nTweak, data)
 *
 * Constants (G1-G2):
 *   MAX_BLOOM_FILTER_SIZE = 36000 bytes
 *   MAX_HASH_FUNCS       = 50
 *
 * Update flags (G11-G14):
 *   BLOOM_UPDATE_NONE        = 0
 *   BLOOM_UPDATE_ALL         = 1
 *   BLOOM_UPDATE_P2PUBKEY_ONLY = 2
 *   BLOOM_UPDATE_MASK        = 3
 *)

let max_bloom_filter_size = 36000   (* bytes — G1 *)
let max_hash_funcs = 50              (* — G2 *)

(* G3: LN2SQUARED — full precision from Bitcoin Core bloom.cpp *)
let ln2squared = 0.4804530139182014246671025263266649717305529515945455
let ln2 = 0.6931471805599453094172321214581765680755001343602552

(* G11-G14: Update flags — bitmask values MUST match Core exactly *)
let bloom_update_none         = 0  (* G11 *)
let bloom_update_all          = 1  (* G12 *)
let bloom_update_p2pubkey_only = 2 (* G13 *)
let bloom_update_mask         = 3  (* G14 *)

(* ============================================================================
   MurmurHash3 (x86_32) — G6
   Reference: Bitcoin Core src/hash.cpp MurmurHash3()
   Implements the MurmurHash3 (x86_32) variant as used by Bitcoin Core.
   All arithmetic is unsigned 32-bit; OCaml uses signed 63-bit ints on
   64-bit systems so we must mask to 32 bits after each multiply/shift.
   ============================================================================ *)

let rotl32 (x : int) (n : int) : int =
  let x = x land 0xFFFFFFFF in
  ((x lsl n) lor (x lsr (32 - n))) land 0xFFFFFFFF

let murmurhash3 (seed : int) (data : bytes) : int =
  let len = Bytes.length data in
  let h1 = ref (seed land 0xFFFFFFFF) in
  let c1 = 0xcc9e2d51 in
  let c2 = 0x1b873593 in
  (* body: process 4-byte blocks (little-endian) *)
  let nblocks = len / 4 in
  for i = 0 to nblocks - 1 do
    let base = i * 4 in
    let k1 =
      (Bytes.get_uint8 data base) lor
      ((Bytes.get_uint8 data (base + 1)) lsl 8) lor
      ((Bytes.get_uint8 data (base + 2)) lsl 16) lor
      ((Bytes.get_uint8 data (base + 3)) lsl 24)
    in
    let k1 = (k1 * c1) land 0xFFFFFFFF in
    let k1 = rotl32 k1 15 in
    let k1 = (k1 * c2) land 0xFFFFFFFF in
    h1 := !h1 lxor k1;
    h1 := rotl32 !h1 13;
    h1 := ((!h1 * 5) land 0xFFFFFFFF + 0xe6546b64) land 0xFFFFFFFF
  done;
  (* tail *)
  let tail_base = nblocks * 4 in
  let k1 = ref 0 in
  (match len land 3 with
   | 3 ->
     k1 := !k1 lxor ((Bytes.get_uint8 data (tail_base + 2)) lsl 16);
     k1 := !k1 lxor ((Bytes.get_uint8 data (tail_base + 1)) lsl 8);
     k1 := !k1 lxor (Bytes.get_uint8 data tail_base);
     k1 := (!k1 * c1) land 0xFFFFFFFF;
     k1 := rotl32 !k1 15;
     k1 := (!k1 * c2) land 0xFFFFFFFF;
     h1 := !h1 lxor !k1
   | 2 ->
     k1 := !k1 lxor ((Bytes.get_uint8 data (tail_base + 1)) lsl 8);
     k1 := !k1 lxor (Bytes.get_uint8 data tail_base);
     k1 := (!k1 * c1) land 0xFFFFFFFF;
     k1 := rotl32 !k1 15;
     k1 := (!k1 * c2) land 0xFFFFFFFF;
     h1 := !h1 lxor !k1
   | 1 ->
     k1 := !k1 lxor (Bytes.get_uint8 data tail_base);
     k1 := (!k1 * c1) land 0xFFFFFFFF;
     k1 := rotl32 !k1 15;
     k1 := (!k1 * c2) land 0xFFFFFFFF;
     h1 := !h1 lxor !k1
   | _ -> ());
  (* finalization: fmix32 *)
  h1 := !h1 lxor len;
  h1 := !h1 lxor (!h1 lsr 16);
  h1 := (!h1 * 0x85ebca6b) land 0xFFFFFFFF;
  h1 := !h1 lxor (!h1 lsr 13);
  h1 := (!h1 * 0xc2b2ae35) land 0xFFFFFFFF;
  h1 := !h1 lxor (!h1 lsr 16);
  !h1

(* ============================================================================
   Bloom filter type
   ============================================================================ *)

type t = {
  mutable vdata : bytes;     (* filter bit array, byte-granular *)
  mutable n_hash_funcs : int;
  mutable n_tweak : int;
  mutable n_flags : int;
}

(* G4: Constructor sizing formula — mirrors Core bloom.cpp
   vData size = min(-1/ln2^2 * nElements * log(fpRate), MAX*8) / 8
   nHashFuncs = min(vData.size*8/nElements * ln2, MAX_HASH_FUNCS) *)
let create (n_elements : int) (fp_rate : float) (n_tweak : int) (n_flags : int) : t =
  let n_elements = max 1 n_elements in  (* guard divide-by-zero *)
  let size_bits =
    let raw = int_of_float (-.1.0 /. ln2squared *. (float_of_int n_elements) *. (log fp_rate)) in
    min raw (max_bloom_filter_size * 8)
  in
  let size_bytes = size_bits / 8 in
  let n_hash_funcs =
    let raw = int_of_float (float_of_int (size_bytes * 8) /. float_of_int n_elements *. ln2) in
    min raw max_hash_funcs
  in
  { vdata = Bytes.make size_bytes '\x00';
    n_hash_funcs;
    n_tweak;
    n_flags }

(* G5: nHashFuncs computation — checked by create() above *)

(* G7: Hash schedule — nHashNum * 0xFBA4C795 + nTweak
   G8: bit index = hash % (vData.size * 8) *)
let bloom_hash (filter : t) (n_hash_num : int) (data : bytes) : int =
  let seed = (n_hash_num * 0xFBA4C795 + filter.n_tweak) land 0xFFFFFFFF in
  let h = murmurhash3 seed data in
  h mod (Bytes.length filter.vdata * 8)

(* G9: Insert — set bit at each hash index *)
let insert (filter : t) (data : bytes) : unit =
  if Bytes.length filter.vdata = 0 then ()  (* CVE-2013-5700 guard *)
  else
    for i = 0 to filter.n_hash_funcs - 1 do
      let idx = bloom_hash filter i data in
      let byte_pos = idx lsr 3 in
      let bit_mask = 1 lsl (idx land 7) in
      Bytes.set_uint8 filter.vdata byte_pos
        (Bytes.get_uint8 filter.vdata byte_pos lor bit_mask)
    done

(* G9: Contains — check all hash indices *)
let contains (filter : t) (data : bytes) : bool =
  if Bytes.length filter.vdata = 0 then true  (* CVE-2013-5700: empty = match-all *)
  else
    let result = ref true in
    let i = ref 0 in
    while !result && !i < filter.n_hash_funcs do
      let idx = bloom_hash filter !i data in
      let byte_pos = idx lsr 3 in
      let bit_mask = 1 lsl (idx land 7) in
      if (Bytes.get_uint8 filter.vdata byte_pos) land bit_mask = 0 then
        result := false;
      incr i
    done;
    !result

(* G10: isFull / isEmpty short-circuit
   isFull  = all bytes are 0xFF
   isEmpty = all bytes are 0x00 *)
let is_full (filter : t) : bool =
  let len = Bytes.length filter.vdata in
  let i = ref 0 in
  while !i < len && Bytes.get_uint8 filter.vdata !i = 0xFF do incr i done;
  !i = len

let is_empty (filter : t) : bool =
  let len = Bytes.length filter.vdata in
  let i = ref 0 in
  while !i < len && Bytes.get_uint8 filter.vdata !i = 0 do incr i done;
  !i = len

(* G29: IsWithinSizeConstraints — mirrors Core's check *)
let is_within_size_constraints (filter : t) : bool =
  Bytes.length filter.vdata <= max_bloom_filter_size &&
  filter.n_hash_funcs <= max_hash_funcs

(* ============================================================================
   Outpoint serialization for insert/contains
   COutPoint is serialized as txid (32 bytes LE) || vout (4 bytes LE)
   G24: Outpoint serialization matches Core's DataStream << outpoint
   ============================================================================ *)

let outpoint_to_bytes (txid : Cstruct.t) (vout : int32) : bytes =
  let buf = Bytes.create 36 in
  Cstruct.blit_to_bytes txid 0 buf 0 32;
  (* vout: 4 bytes LE *)
  Bytes.set_uint8 buf 32 (Int32.to_int (Int32.logand vout 0xFFl));
  Bytes.set_uint8 buf 33 (Int32.to_int (Int32.logand (Int32.shift_right_logical vout 8) 0xFFl));
  Bytes.set_uint8 buf 34 (Int32.to_int (Int32.logand (Int32.shift_right_logical vout 16) 0xFFl));
  Bytes.set_uint8 buf 35 (Int32.to_int (Int32.logand (Int32.shift_right_logical vout 24) 0xFFl));
  buf

let insert_outpoint (filter : t) (txid : Cstruct.t) (vout : int32) : unit =
  insert filter (outpoint_to_bytes txid vout)

let contains_outpoint (filter : t) (txid : Cstruct.t) (vout : int32) : bool =
  contains filter (outpoint_to_bytes txid vout)

(* ============================================================================
   Script pushdata extraction helper
   Iterates over script opcodes and yields each data push element (non-empty).
   G17-G20: per-output-script and scriptSig data matching.
   ============================================================================ *)

(** [iter_pushdata script f] calls [f data] for each push-data element in
    [script] that has length > 0.  Stops silently on malformed input. *)
let iter_pushdata (script : Cstruct.t) (f : bytes -> unit) : unit =
  let len = Cstruct.length script in
  let pos = ref 0 in
  while !pos < len do
    let op = Cstruct.get_uint8 script !pos in
    incr pos;
    let data_len =
      if op >= 0x01 && op <= 0x4b then
        (* OP_PUSHDATA_N: next op bytes are the data *)
        Some op
      else if op = 0x4c then begin
        (* OP_PUSHDATA1 *)
        if !pos < len then begin let v = Cstruct.get_uint8 script !pos in incr pos; Some v end
        else None
      end
      else if op = 0x4d then begin
        (* OP_PUSHDATA2 *)
        if !pos + 1 < len then begin
          let v = Cstruct.LE.get_uint16 script !pos in pos := !pos + 2; Some v
        end else None
      end
      else if op = 0x4e then begin
        (* OP_PUSHDATA4 *)
        if !pos + 3 < len then begin
          let v = Int32.to_int (Cstruct.LE.get_uint32 script !pos) in pos := !pos + 4; Some v
        end else None
      end
      else
        None  (* not a push opcode — skip *)
    in
    match data_len with
    | None -> ()  (* nothing to extract for this opcode *)
    | Some dl ->
      if dl > 0 && !pos + dl <= len then begin
        let data = Bytes.create dl in
        Cstruct.blit_to_bytes script !pos data 0 dl;
        f data;
        pos := !pos + dl
      end else if dl = 0 then
        ()  (* zero-length push: skip *)
      else
        pos := len  (* malformed: abort iteration *)
  done

(* ============================================================================
   Script type detection for UPDATE_P2PUBKEY_ONLY (G22)
   Core Solver identifies TxoutType::PUBKEY and TxoutType::MULTISIG.
   We need to detect these in scriptPubKey.
   ============================================================================ *)

(** Returns true if [script] is a bare P2PK output:
    <33 or 65 bytes pubkey> OP_CHECKSIG (0xAC) *)
let is_p2pk (script : Cstruct.t) : bool =
  let len = Cstruct.length script in
  (* Compressed: 0x21 <33 bytes> 0xac = 35 bytes *)
  if len = 35 &&
     Cstruct.get_uint8 script 0 = 0x21 &&
     Cstruct.get_uint8 script 34 = 0xac
  then true
  (* Uncompressed: 0x41 <65 bytes> 0xac = 67 bytes *)
  else if len = 67 &&
          Cstruct.get_uint8 script 0 = 0x41 &&
          Cstruct.get_uint8 script 66 = 0xac
  then true
  else false

(** Returns true if [script] is a bare multisig output:
    OP_m <pubkeys> OP_n OP_CHECKMULTISIG (0xAE) *)
let is_multisig (script : Cstruct.t) : bool =
  let len = Cstruct.length script in
  if len < 3 then false
  else
    let last = Cstruct.get_uint8 script (len - 1) in
    if last <> 0xae then false  (* must end with OP_CHECKMULTISIG *)
    else
      let first = Cstruct.get_uint8 script 0 in
      (* OP_1..OP_16 = 0x51..0x60 *)
      first >= 0x51 && first <= 0x60

(* ============================================================================
   IsRelevantAndUpdate — G16-G23
   Mirrors Bitcoin Core CBloomFilter::IsRelevantAndUpdate(const CTransaction& tx)
   ============================================================================ *)

(** [is_relevant_and_update filter tx] returns true if [tx] is relevant to
    [filter], and also inserts outpoints into [filter] as appropriate based
    on [filter.n_flags & BLOOM_UPDATE_MASK].

    [tx] is provided as a {Types.transaction} record.
    [txid_bytes] is the transaction's hash as 32 bytes (little-endian wire form).
*)
let is_relevant_and_update (filter : t) (tx : Types.transaction)
    (txid_bytes : bytes) : bool =
  let found = ref false in

  (* G9/G10: empty vData = "match-all" filter *)
  if Bytes.length filter.vdata = 0 then true
  else begin

    (* G16: Check if txid matches *)
    if contains filter txid_bytes then
      found := true;

    (* G17-G22: Scan outputs — txout is a Types.tx_out *)
    List.iteri (fun i txout ->
      let script = txout.Types.script_pubkey in
      (* Core scans all outputs even if already found, to insert outpoints
         for all matching outputs when UPDATE_ALL/UPDATE_P2PUBKEY_ONLY *)
      iter_pushdata script (fun data ->
        if contains filter data then begin
          found := true;
          (* G21-G22: UPDATE_ALL and UPDATE_P2PUBKEY_ONLY *)
          let flags = filter.n_flags land bloom_update_mask in
          let txid_cs = Cstruct.of_bytes txid_bytes in
          if flags = bloom_update_all then
            insert_outpoint filter txid_cs (Int32.of_int i)
          else if flags = bloom_update_p2pubkey_only then begin
            (* G22: only add outpoint for P2PK or multisig outputs *)
            if is_p2pk script || is_multisig script then
              insert_outpoint filter txid_cs (Int32.of_int i)
          end
          (* G23: UPDATE_NONE — do not insert outpoint *)
        end
      )
    ) tx.outputs;

    if !found then true
    else begin
      (* G19: Check inputs for matching outpoints *)
      let found_input =
        List.exists (fun txin ->
          (* G19: Outpoint match *)
          let outpoint = outpoint_to_bytes txin.Types.previous_output.Types.txid
                           txin.Types.previous_output.Types.vout in
          if contains filter outpoint then true
          else begin
            (* G20: scriptSig data items *)
            let matched = ref false in
            iter_pushdata txin.Types.script_sig (fun data ->
              if contains filter data then matched := true
            );
            !matched
          end
        ) tx.inputs
      in
      found_input
    end
  end

(* ============================================================================
   Wire (de)serialization for filterload
   CBloomFilter SERIALIZE_METHODS: vData (compact_size + bytes),
                                   nHashFuncs (uint32 LE),
                                   nTweak (uint32 LE),
                                   nFlags (uint8)
   G25: filterload
   ============================================================================ *)

let serialize (filter : t) : Cstruct.t =
  let vdata_len = Bytes.length filter.vdata in
  (* compact_size for vdata_len *)
  let cs_len =
    if vdata_len < 0xFD then 1
    else if vdata_len <= 0xFFFF then 3
    else 5
  in
  let total = cs_len + vdata_len + 4 + 4 + 1 in
  let buf = Cstruct.create total in
  let pos = ref 0 in
  (* Write compact_size *)
  if vdata_len < 0xFD then begin
    Cstruct.set_uint8 buf !pos vdata_len; incr pos
  end else if vdata_len <= 0xFFFF then begin
    Cstruct.set_uint8 buf !pos 0xFD; incr pos;
    Cstruct.LE.set_uint16 buf !pos vdata_len; pos := !pos + 2
  end else begin
    Cstruct.set_uint8 buf !pos 0xFE; incr pos;
    Cstruct.LE.set_uint32 buf !pos (Int32.of_int vdata_len); pos := !pos + 4
  end;
  (* Write vdata bytes *)
  Cstruct.blit_from_bytes filter.vdata 0 buf !pos vdata_len;
  pos := !pos + vdata_len;
  (* nHashFuncs uint32 LE *)
  Cstruct.LE.set_uint32 buf !pos (Int32.of_int filter.n_hash_funcs);
  pos := !pos + 4;
  (* nTweak uint32 LE *)
  Cstruct.LE.set_uint32 buf !pos (Int32.of_int filter.n_tweak);
  pos := !pos + 4;
  (* nFlags uint8 *)
  Cstruct.set_uint8 buf !pos filter.n_flags;
  Cstruct.sub buf 0 (!pos + 1)

let deserialize (cs : Cstruct.t) : (t, string) result =
  try
    let pos = ref 0 in
    let len = Cstruct.length cs in
    (* Read compact_size for vdata *)
    if !pos >= len then Error "filterload: truncated (compact_size)"
    else begin
      let b0 = Cstruct.get_uint8 cs !pos in incr pos;
      let vdata_len =
        if b0 < 0xFD then b0
        else if b0 = 0xFD then begin
          if !pos + 1 >= len then raise Exit;
          let v = Cstruct.LE.get_uint16 cs !pos in pos := !pos + 2; v
        end
        else if b0 = 0xFE then begin
          if !pos + 3 >= len then raise Exit;
          let v = Int32.to_int (Cstruct.LE.get_uint32 cs !pos) in pos := !pos + 4; v
        end
        else raise Exit  (* 0xFF: 8-byte varint, we reject *)
      in
      if !pos + vdata_len + 4 + 4 + 1 > len then
        Error "filterload: truncated (body)"
      else begin
        let vdata = Bytes.create vdata_len in
        Cstruct.blit_to_bytes cs !pos vdata 0 vdata_len;
        pos := !pos + vdata_len;
        let n_hash_funcs = Int32.to_int (Cstruct.LE.get_uint32 cs !pos) in
        pos := !pos + 4;
        let n_tweak = Int32.to_int (Cstruct.LE.get_uint32 cs !pos) in
        pos := !pos + 4;
        let n_flags = Cstruct.get_uint8 cs !pos in
        let f = { vdata; n_hash_funcs; n_tweak; n_flags } in
        Ok f
      end
    end
  with Exit -> Error "filterload: truncated"
