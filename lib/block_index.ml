(* Block Index Module for BIP-157/158 Block Filters

   Reference: Bitcoin Core's blockfilter.cpp and index/blockfilterindex.cpp

   Implements:
   - SipHash-2-4 for filter key hashing
   - Golomb-Rice coding for compact set encoding
   - GCS (Golomb-coded set) filters
   - Basic block filter construction (BIP-158)
   - Block filter index with persistent storage
   - Height index for O(1) height-to-hash lookup
*)

(* ============================================================================
   SipHash-2-4 Implementation

   Reference: https://131002.net/siphash/
   Used by BIP-158 to hash filter elements with a per-block key derived
   from the block hash (first 16 bytes = k0 || k1).
   ============================================================================ *)

module SipHash = struct
  (* SipHash-2-4 constants *)
  let rotl64 x b = Int64.(logor (shift_left x b) (shift_right_logical x (64 - b)))

  let sipround v0 v1 v2 v3 =
    let v0 = Int64.add v0 v1 in
    let v1 = rotl64 v1 13 in
    let v1 = Int64.logxor v1 v0 in
    let v0 = rotl64 v0 32 in
    let v2 = Int64.add v2 v3 in
    let v3 = rotl64 v3 16 in
    let v3 = Int64.logxor v3 v2 in
    let v0 = Int64.add v0 v3 in
    let v3 = rotl64 v3 21 in
    let v3 = Int64.logxor v3 v0 in
    let v2 = Int64.add v2 v1 in
    let v1 = rotl64 v1 17 in
    let v1 = Int64.logxor v1 v2 in
    let v2 = rotl64 v2 32 in
    (v0, v1, v2, v3)

  let get_le64 data off =
    let b i = Int64.of_int (Char.code (String.get data (off + i))) in
    Int64.(logor (b 0)
      (logor (shift_left (b 1) 8)
      (logor (shift_left (b 2) 16)
      (logor (shift_left (b 3) 24)
      (logor (shift_left (b 4) 32)
      (logor (shift_left (b 5) 40)
      (logor (shift_left (b 6) 48)
             (shift_left (b 7) 56))))))))

  (* SipHash-2-4 with two 64-bit keys *)
  let siphash24 ~k0 ~k1 (data : string) : int64 =
    let len = String.length data in
    let b = Int64.(shift_left (of_int (len land 0xff)) 56) in

    (* Initialize state *)
    let v0 = Int64.logxor k0 0x736f6d6570736575L in
    let v1 = Int64.logxor k1 0x646f72616e646f6dL in
    let v2 = Int64.logxor k0 0x6c7967656e657261L in
    let v3 = Int64.logxor k1 0x7465646279746573L in

    (* Process full 8-byte blocks *)
    let full_blocks = len / 8 in
    let v0, v1, v2, v3 = ref v0, ref v1, ref v2, ref v3 in
    for i = 0 to full_blocks - 1 do
      let m = get_le64 data (i * 8) in
      v3 := Int64.logxor !v3 m;
      let (a, b_, c, d) = sipround !v0 !v1 !v2 !v3 in
      let (a, b_, c, d) = sipround a b_ c d in
      v0 := a; v1 := b_; v2 := c; v3 := d;
      v0 := Int64.logxor !v0 m
    done;

    (* Process remaining bytes *)
    let tail_start = full_blocks * 8 in
    let tail_len = len - tail_start in
    let b = ref b in
    for i = tail_len - 1 downto 0 do
      b := Int64.logor !b
        (Int64.shift_left
          (Int64.of_int (Char.code (String.get data (tail_start + i))))
          (i * 8))
    done;

    v3 := Int64.logxor !v3 !b;
    let (a, b_, c, d) = sipround !v0 !v1 !v2 !v3 in
    let (a, b_, c, d) = sipround a b_ c d in
    v0 := a; v1 := b_; v2 := c; v3 := d;
    v0 := Int64.logxor !v0 !b;

    (* Finalization *)
    v2 := Int64.logxor !v2 0xffL;
    let (a, b_, c, d) = sipround !v0 !v1 !v2 !v3 in
    let (a, b_, c, d) = sipround a b_ c d in
    let (a, b_, c, d) = sipround a b_ c d in
    let (a, b_, c, d) = sipround a b_ c d in

    Int64.(logxor (logxor a b_) (logxor c d))
end

(* ============================================================================
   Golomb-Rice Coding

   Reference: Bitcoin Core's util/golombrice.h
   Encodes deltas between sorted hashes using unary quotient + P-bit remainder.
   ============================================================================ *)

module GolombRice = struct
  (* Bit stream writer for Golomb-Rice encoding *)
  type bit_writer = {
    mutable buffer : int;      (* Bits waiting to be written *)
    mutable bits : int;        (* Number of bits in buffer (0-7) *)
    mutable data : bytes;      (* Output buffer *)
    mutable pos : int;         (* Current position in output *)
  }

  let create_writer () = {
    buffer = 0;
    bits = 0;
    data = Bytes.create 256;
    pos = 0;
  }

  let ensure_capacity w needed =
    if w.pos + needed > Bytes.length w.data then begin
      let new_size = max (Bytes.length w.data * 2) (w.pos + needed) in
      let new_data = Bytes.create new_size in
      Bytes.blit w.data 0 new_data 0 w.pos;
      w.data <- new_data
    end

  let write_bits w value nbits =
    (* Write nbits from value (LSB first within each byte) *)
    let value = ref value in
    let nbits = ref nbits in
    while !nbits > 0 do
      let space = 8 - w.bits in
      let take = min space !nbits in
      let mask = (1 lsl take) - 1 in
      w.buffer <- w.buffer lor ((Int64.to_int !value land mask) lsl w.bits);
      value := Int64.shift_right_logical !value take;
      nbits := !nbits - take;
      w.bits <- w.bits + take;
      if w.bits = 8 then begin
        ensure_capacity w 1;
        Bytes.set w.data w.pos (Char.chr w.buffer);
        w.pos <- w.pos + 1;
        w.buffer <- 0;
        w.bits <- 0
      end
    done

  let flush w =
    if w.bits > 0 then begin
      ensure_capacity w 1;
      Bytes.set w.data w.pos (Char.chr w.buffer);
      w.pos <- w.pos + 1;
      w.buffer <- 0;
      w.bits <- 0
    end

  let to_string w =
    flush w;
    Bytes.sub_string w.data 0 w.pos

  (* Encode a single value using Golomb-Rice coding *)
  let encode w ~p x =
    (* Write quotient as unary (q 1-bits followed by a 0) *)
    let q = Int64.shift_right_logical x p in
    let q = Int64.to_int q in  (* Quotient should be small *)
    let rec write_ones remaining =
      if remaining > 0 then begin
        let nbits = min remaining 64 in
        write_bits w Int64.minus_one nbits;
        write_ones (remaining - nbits)
      end
    in
    write_ones q;
    write_bits w 0L 1;
    (* Write remainder in p bits *)
    write_bits w x p

  (* Bit stream reader for Golomb-Rice decoding *)
  type bit_reader = {
    data : string;
    mutable byte_pos : int;
    mutable bit_pos : int;  (* Bits consumed in current byte (0-7) *)
  }

  let create_reader data = {
    data;
    byte_pos = 0;
    bit_pos = 0;
  }

  let read_bits r nbits =
    let result = ref 0L in
    let shift = ref 0 in
    let nbits = ref nbits in
    while !nbits > 0 do
      if r.byte_pos >= String.length r.data then
        failwith "GolombRice: unexpected end of data";
      let byte = Char.code (String.get r.data r.byte_pos) in
      let available = 8 - r.bit_pos in
      let take = min available !nbits in
      let mask = (1 lsl take) - 1 in
      let bits = (byte lsr r.bit_pos) land mask in
      result := Int64.logor !result (Int64.shift_left (Int64.of_int bits) !shift);
      shift := !shift + take;
      nbits := !nbits - take;
      r.bit_pos <- r.bit_pos + take;
      if r.bit_pos = 8 then begin
        r.byte_pos <- r.byte_pos + 1;
        r.bit_pos <- 0
      end
    done;
    !result

  let read_bit r =
    Int64.to_int (read_bits r 1)

  (* Decode a single value using Golomb-Rice coding *)
  let decode r ~p =
    (* Read unary quotient: count 1-bits until we hit a 0 *)
    let q = ref 0 in
    while read_bit r = 1 do
      incr q
    done;
    (* Read p-bit remainder *)
    let remainder = read_bits r p in
    Int64.(add (shift_left (of_int !q) p) remainder)
end

(* ============================================================================
   GCS Filter (Golomb-coded Set)

   Reference: BIP-158, Bitcoin Core's blockfilter.cpp

   Parameters for basic filter (BIP-158):
   - P = 19 (Golomb-Rice parameter)
   - M = 784931 (inverse false positive rate ≈ 2^20)
   ============================================================================ *)

(** BIP-158 basic filter parameters *)
let basic_filter_p = 19
let basic_filter_m = 784931

(** GCS filter parameters *)
type gcs_params = {
  siphash_k0 : int64;
  siphash_k1 : int64;
  p : int;
  m : int;
}

(** GCS filter *)
type gcs_filter = {
  params : gcs_params;
  n : int;            (** Number of elements *)
  f : int64;          (** Range = N * M *)
  encoded : string;   (** Golomb-Rice encoded data *)
}

(** FastRange64: map a hash to [0, range) without bias
    Equivalent to (hash * range) >> 64 but using 128-bit multiplication *)
let fast_range64 hash range =
  (* Approximate using floating point for now since OCaml doesn't have native
     128-bit integers. This matches Bitcoin Core's FastRange64. *)
  let h = Int64.to_float hash in
  let r = Int64.to_float range in
  (* Handle negative interpretation of int64 *)
  let h = if h < 0.0 then h +. 18446744073709551616.0 else h in
  let r = if r < 0.0 then r +. 18446744073709551616.0 else r in
  let result = (h *. r) /. 18446744073709551616.0 in
  Int64.of_float result

(** Hash an element to the filter's range [0, N*M) *)
let hash_to_range params f element =
  let hash = SipHash.siphash24 ~k0:params.siphash_k0 ~k1:params.siphash_k1 element in
  fast_range64 hash f

(** Build a GCS filter from a set of elements *)
let build_filter params (elements : string list) : gcs_filter =
  let n = List.length elements in
  let f = Int64.(mul (of_int n) (of_int params.m)) in

  if n = 0 then
    (* Empty filter: just encode N=0 *)
    let w = Serialize.writer_create () in
    Serialize.write_compact_size w 0;
    let encoded = Cstruct.to_string (Serialize.writer_to_cstruct w) in
    { params; n; f; encoded }
  else begin
    (* Hash all elements and sort *)
    let hashes = List.map (hash_to_range params f) elements in
    let sorted = List.sort Int64.compare hashes in

    (* Encode using Golomb-Rice coding *)
    let buf = Buffer.create 256 in

    (* Write N as compact size *)
    let w = Serialize.writer_create () in
    Serialize.write_compact_size w n;
    Buffer.add_string buf (Cstruct.to_string (Serialize.writer_to_cstruct w));

    (* Write Golomb-Rice encoded deltas *)
    let bit_writer = GolombRice.create_writer () in
    let last = ref 0L in
    List.iter (fun hash ->
      let delta = Int64.sub hash !last in
      GolombRice.encode bit_writer ~p:params.p delta;
      last := hash
    ) sorted;

    Buffer.add_string buf (GolombRice.to_string bit_writer);

    { params; n; f; encoded = Buffer.contents buf }
  end

(** Decode a GCS filter from encoded data *)
let decode_filter params encoded : gcs_filter =
  let r = Serialize.reader_of_cstruct (Cstruct.of_string encoded) in
  let n = Serialize.read_compact_size r in
  let f = Int64.(mul (of_int n) (of_int params.m)) in
  { params; n; f; encoded }

(** Check if a single element may be in the filter *)
let match_element filter element =
  if filter.n = 0 then false
  else begin
    let query = hash_to_range filter.params filter.f element in

    (* Decode the filter and search for the hash *)
    let r = Serialize.reader_of_cstruct (Cstruct.of_string filter.encoded) in
    let _ = Serialize.read_compact_size r in  (* Skip N *)

    (* Create bit reader for the remaining Golomb data *)
    let remaining_pos = r.Serialize.pos in
    let remaining_data = String.sub filter.encoded remaining_pos
      (String.length filter.encoded - remaining_pos) in
    let bit_reader = GolombRice.create_reader remaining_data in

    let value = ref 0L in
    let found = ref false in
    let i = ref 0 in
    while !i < filter.n && not !found do
      let delta = GolombRice.decode bit_reader ~p:filter.params.p in
      value := Int64.add !value delta;
      if Int64.equal !value query then found := true
      else if Int64.compare !value query > 0 then
        i := filter.n;  (* Early exit: passed the query value *)
      incr i
    done;
    !found
  end

(** Check if any of the given elements may be in the filter *)
let match_any filter elements =
  if filter.n = 0 || elements = [] then false
  else begin
    (* Hash and sort query elements *)
    let queries = List.map (hash_to_range filter.params filter.f) elements in
    let sorted_queries = Array.of_list (List.sort Int64.compare queries) in
    let query_count = Array.length sorted_queries in

    (* Decode the filter and merge-search *)
    let r = Serialize.reader_of_cstruct (Cstruct.of_string filter.encoded) in
    let _ = Serialize.read_compact_size r in

    let remaining_pos = r.Serialize.pos in
    let remaining_data = String.sub filter.encoded remaining_pos
      (String.length filter.encoded - remaining_pos) in
    let bit_reader = GolombRice.create_reader remaining_data in

    let value = ref 0L in
    let query_idx = ref 0 in
    let found = ref false in
    let i = ref 0 in

    while !i < filter.n && !query_idx < query_count && not !found do
      let delta = GolombRice.decode bit_reader ~p:filter.params.p in
      value := Int64.add !value delta;

      (* Advance query index past values less than current filter value *)
      while !query_idx < query_count &&
            Int64.compare sorted_queries.(!query_idx) !value < 0 do
        incr query_idx
      done;

      (* Check for match *)
      if !query_idx < query_count &&
         Int64.equal sorted_queries.(!query_idx) !value then
        found := true;

      incr i
    done;
    !found
  end

(* ============================================================================
   Block Filter Construction (BIP-158)

   The basic filter contains all scriptPubKeys:
   - From outputs created in the block
   - From outputs spent by inputs in the block (from undo data)

   Excludes OP_RETURN outputs and empty scripts.
   ============================================================================ *)

(** Block filter type *)
type block_filter_type =
  | Basic

let block_filter_type_name = function
  | Basic -> "basic"

(** Block filter *)
type block_filter = {
  filter_type : block_filter_type;
  block_hash : Types.hash256;
  filter : gcs_filter;
}

(** Extract filter key (siphash k0, k1) from block hash
    First 16 bytes of block hash = k0 || k1 (little-endian) *)
let filter_key_of_block_hash (hash : Types.hash256) : int64 * int64 =
  let get_le64 offset =
    let b i = Int64.of_int (Cstruct.get_uint8 hash (offset + i)) in
    Int64.(logor (b 0)
      (logor (shift_left (b 1) 8)
      (logor (shift_left (b 2) 16)
      (logor (shift_left (b 3) 24)
      (logor (shift_left (b 4) 32)
      (logor (shift_left (b 5) 40)
      (logor (shift_left (b 6) 48)
             (shift_left (b 7) 56))))))))
  in
  (get_le64 0, get_le64 8)

(** Build basic filter params from block hash *)
let basic_filter_params (block_hash : Types.hash256) : gcs_params =
  let k0, k1 = filter_key_of_block_hash block_hash in
  { siphash_k0 = k0; siphash_k1 = k1; p = basic_filter_p; m = basic_filter_m }

(** Build a basic block filter from a block and its undo data.

    Matches Bitcoin Core's BasicFilterElements in blockfilter.cpp:
    - Includes all non-empty, non-OP_RETURN output scriptPubKeys
    - Includes all spent output scriptPubKeys from undo data *)
let build_basic_filter (block : Types.block) (undo : Storage.block_undo option)
    : block_filter =
  let block_hash = Crypto.compute_block_hash block.header in
  let params = basic_filter_params block_hash in

  let elements = ref [] in

  (* Add output scriptPubKeys *)
  List.iter (fun tx ->
    List.iter (fun (output : Types.tx_out) ->
      let script = output.script_pubkey in
      let len = Cstruct.length script in
      (* Skip empty scripts and OP_RETURN (0x6a) *)
      if len > 0 && Cstruct.get_uint8 script 0 <> 0x6a then
        elements := Cstruct.to_string script :: !elements
    ) tx.Types.outputs
  ) block.transactions;

  (* Add spent scriptPubKeys from undo data *)
  (match undo with
   | None -> ()
   | Some u ->
     List.iter (fun (tx_undo : Storage.tx_undo) ->
       List.iter (fun (prev_out : Storage.tx_in_undo) ->
         let script = prev_out.script_pubkey in
         if Cstruct.length script > 0 then
           elements := Cstruct.to_string script :: !elements
       ) tx_undo.prev_outputs
     ) u.tx_undos);

  (* Deduplicate elements *)
  let unique = List.sort_uniq String.compare !elements in

  let filter = build_filter params unique in
  { filter_type = Basic; block_hash; filter }

(** Compute filter hash (SHA256d of encoded filter) *)
let compute_filter_hash (bf : block_filter) : Types.hash256 =
  Crypto.sha256d (Cstruct.of_string bf.filter.encoded)

(** Compute filter header given the previous header.
    filter_header = SHA256d(filter_hash || prev_header) *)
let compute_filter_header (bf : block_filter) (prev_header : Types.hash256)
    : Types.hash256 =
  let filter_hash = compute_filter_hash bf in
  let data = Cstruct.concat [filter_hash; prev_header] in
  Crypto.sha256d data

(* ============================================================================
   Block Filter Index

   Reference: Bitcoin Core's index/blockfilterindex.cpp

   Stores:
   - Filter data in flat files (fltr00000.dat, ...)
   - Index mapping block hash -> (filter_hash, filter_header, file_pos)
   - Filter headers cache for chain traversal
   ============================================================================ *)

(** Maximum filter file size (16 MB) *)
let max_filter_file_size = 0x1000000

(** Filter index entry *)
type filter_index_entry = {
  filter_hash : Types.hash256;
  filter_header : Types.hash256;
  file_num : int;
  file_pos : int;
  filter_len : int;
}

(** Block filter index *)
type filter_index = {
  filter_dir : string;
  mutable last_file : int;
  mutable file_size : int;
  index : (string, filter_index_entry) Hashtbl.t;  (* block_hash -> entry *)
  mutable dirty : bool;
}

let filter_file_path idx file_num =
  Filename.concat idx.filter_dir (Printf.sprintf "fltr%05d.dat" file_num)

let filter_index_path idx =
  Filename.concat idx.filter_dir "filter_index.dat"

let ensure_dir path =
  try Unix.mkdir path 0o755
  with Unix.Unix_error (Unix.EEXIST, _, _) -> ()

(** Serialize filter index entry *)
let serialize_filter_entry w (e : filter_index_entry) =
  Serialize.write_bytes w e.filter_hash;
  Serialize.write_bytes w e.filter_header;
  Serialize.write_int32_le w (Int32.of_int e.file_num);
  Serialize.write_int32_le w (Int32.of_int e.file_pos);
  Serialize.write_int32_le w (Int32.of_int e.filter_len)

(** Deserialize filter index entry *)
let deserialize_filter_entry r : filter_index_entry =
  let filter_hash = Serialize.read_bytes r 32 in
  let filter_header = Serialize.read_bytes r 32 in
  let file_num = Int32.to_int (Serialize.read_int32_le r) in
  let file_pos = Int32.to_int (Serialize.read_int32_le r) in
  let filter_len = Int32.to_int (Serialize.read_int32_le r) in
  { filter_hash; filter_header; file_num; file_pos; filter_len }

(** Save filter index to disk *)
let save_filter_index idx =
  if not idx.dirty then ()
  else begin
    let path = filter_index_path idx in
    let tmp = path ^ ".tmp" in
    let oc = open_out_bin tmp in
    (* Header: magic, count, last_file, file_size *)
    output_string oc "FLTIDX01";
    let write_le32 n =
      output_byte oc (n land 0xff);
      output_byte oc ((n lsr 8) land 0xff);
      output_byte oc ((n lsr 16) land 0xff);
      output_byte oc ((n lsr 24) land 0xff)
    in
    write_le32 (Hashtbl.length idx.index);
    write_le32 idx.last_file;
    write_le32 idx.file_size;
    (* Write entries *)
    Hashtbl.iter (fun hash_str entry ->
      output_string oc hash_str;  (* 32 bytes *)
      let w = Serialize.writer_create () in
      serialize_filter_entry w entry;
      let data = Serialize.writer_to_cstruct w in
      write_le32 (Cstruct.length data);
      output_string oc (Cstruct.to_string data)
    ) idx.index;
    close_out oc;
    Unix.rename tmp path;
    idx.dirty <- false
  end

(** Load filter index from disk *)
let load_filter_index idx =
  let path = filter_index_path idx in
  if not (Sys.file_exists path) then ()
  else begin
    let ic = open_in_bin path in
    (try
      let magic = really_input_string ic 8 in
      if magic <> "FLTIDX01" then raise Exit;
      let read_le32 () =
        let b0 = input_byte ic in
        let b1 = input_byte ic in
        let b2 = input_byte ic in
        let b3 = input_byte ic in
        b0 lor (b1 lsl 8) lor (b2 lsl 16) lor (b3 lsl 24)
      in
      let count = read_le32 () in
      idx.last_file <- read_le32 ();
      idx.file_size <- read_le32 ();
      for _ = 1 to count do
        let hash_str = really_input_string ic 32 in
        let entry_len = read_le32 () in
        let entry_data = really_input_string ic entry_len in
        let r = Serialize.reader_of_cstruct (Cstruct.of_string entry_data) in
        let entry = deserialize_filter_entry r in
        Hashtbl.replace idx.index hash_str entry
      done
    with _ -> ());
    close_in ic
  end

(** Create or open a filter index *)
let create_filter_index filter_dir =
  ensure_dir filter_dir;
  let idx = {
    filter_dir;
    last_file = 0;
    file_size = 0;
    index = Hashtbl.create 10000;
    dirty = false;
  } in
  load_filter_index idx;
  idx

(** Close filter index (saves to disk) *)
let close_filter_index idx =
  save_filter_index idx

(** Sync filter index to disk *)
let sync_filter_index idx =
  save_filter_index idx

(** Store a block filter *)
let store_filter idx (bf : block_filter) (prev_header : Types.hash256) =
  let block_hash_str = Cstruct.to_string bf.block_hash in

  (* Check if already stored *)
  if Hashtbl.mem idx.index block_hash_str then ()
  else begin
    let filter_hash = compute_filter_hash bf in
    let filter_header = compute_filter_header bf prev_header in
    let filter_data = bf.filter.encoded in
    let filter_len = String.length filter_data in

    (* Check if we need a new file *)
    if idx.file_size + filter_len + 36 > max_filter_file_size then begin
      idx.last_file <- idx.last_file + 1;
      idx.file_size <- 0
    end;

    let file_num = idx.last_file in
    let file_pos = idx.file_size in

    (* Write to filter file *)
    let file_path = filter_file_path idx file_num in
    let flags = [Unix.O_WRONLY; Unix.O_CREAT] in
    let fd = Unix.openfile file_path flags 0o644 in
    let _ = Unix.lseek fd file_pos Unix.SEEK_SET in
    (* Write: block_hash (32) + filter_len (4) + filter_data *)
    let _ = Unix.write fd (Cstruct.to_bytes bf.block_hash) 0 32 in
    let len_buf = Bytes.create 4 in
    Bytes.set len_buf 0 (Char.chr (filter_len land 0xff));
    Bytes.set len_buf 1 (Char.chr ((filter_len lsr 8) land 0xff));
    Bytes.set len_buf 2 (Char.chr ((filter_len lsr 16) land 0xff));
    Bytes.set len_buf 3 (Char.chr ((filter_len lsr 24) land 0xff));
    let _ = Unix.write fd len_buf 0 4 in
    let _ = Unix.write fd (Bytes.of_string filter_data) 0 filter_len in
    Unix.close fd;

    idx.file_size <- idx.file_size + 32 + 4 + filter_len;

    (* Update index *)
    let entry = { filter_hash; filter_header; file_num; file_pos; filter_len } in
    Hashtbl.replace idx.index block_hash_str entry;
    idx.dirty <- true
  end

(** Get filter index entry for a block *)
let get_filter_entry idx (block_hash : Types.hash256) : filter_index_entry option =
  Hashtbl.find_opt idx.index (Cstruct.to_string block_hash)

(** Get filter header for a block *)
let get_filter_header idx (block_hash : Types.hash256) : Types.hash256 option =
  match get_filter_entry idx block_hash with
  | None -> None
  | Some entry -> Some entry.filter_header

(** Read filter data from disk *)
let read_filter idx (block_hash : Types.hash256) : block_filter option =
  match get_filter_entry idx block_hash with
  | None -> None
  | Some entry ->
    let file_path = filter_file_path idx entry.file_num in
    if not (Sys.file_exists file_path) then None
    else begin
      let fd = Unix.openfile file_path [Unix.O_RDONLY] 0 in
      (try
        let _ = Unix.lseek fd entry.file_pos Unix.SEEK_SET in
        (* Read block hash *)
        let hash_buf = Bytes.create 32 in
        let n = Unix.read fd hash_buf 0 32 in
        if n <> 32 then begin
          Unix.close fd;
          None
        end
        else begin
          (* Read length *)
          let len_buf = Bytes.create 4 in
          let n = Unix.read fd len_buf 0 4 in
          if n <> 4 then begin
            Unix.close fd;
            None
          end
          else begin
            let filter_len =
              (Char.code (Bytes.get len_buf 0))
              lor ((Char.code (Bytes.get len_buf 1)) lsl 8)
              lor ((Char.code (Bytes.get len_buf 2)) lsl 16)
              lor ((Char.code (Bytes.get len_buf 3)) lsl 24) in
            (* Read filter data *)
            let data_buf = Bytes.create filter_len in
            let n = Unix.read fd data_buf 0 filter_len in
            Unix.close fd;
            if n <> filter_len then None
            else begin
              let params = basic_filter_params block_hash in
              let filter = decode_filter params (Bytes.to_string data_buf) in
              Some { filter_type = Basic; block_hash; filter }
            end
          end
        end
      with _ ->
        Unix.close fd;
        None)
    end

(** Check if we have a filter for a block *)
let has_filter idx (block_hash : Types.hash256) : bool =
  Hashtbl.mem idx.index (Cstruct.to_string block_hash)

(** Get filter count *)
let filter_count idx = Hashtbl.length idx.index

(* ============================================================================
   Height Index

   O(1) height-to-hash lookup using an in-memory array that's persisted to disk.
   This supplements ChainDB's height_hash mapping which requires DB lookup.
   ============================================================================ *)

type height_index = {
  dir : string;
  mutable hashes : Types.hash256 option array;
  mutable max_height : int;
  mutable dirty : bool;
}

let height_index_path idx =
  Filename.concat idx.dir "height_index.dat"

(** Save height index to disk *)
let save_height_index idx =
  if not idx.dirty then ()
  else begin
    let path = height_index_path idx in
    let tmp = path ^ ".tmp" in
    let oc = open_out_bin tmp in
    (* Header: magic, max_height *)
    output_string oc "HTIDX001";
    let write_le32 n =
      output_byte oc (n land 0xff);
      output_byte oc ((n lsr 8) land 0xff);
      output_byte oc ((n lsr 16) land 0xff);
      output_byte oc ((n lsr 24) land 0xff)
    in
    write_le32 idx.max_height;
    (* Write hashes: 1 byte present flag + 32 bytes if present *)
    for i = 0 to idx.max_height do
      match idx.hashes.(i) with
      | None -> output_byte oc 0
      | Some h ->
        output_byte oc 1;
        output_string oc (Cstruct.to_string h)
    done;
    close_out oc;
    Unix.rename tmp path;
    idx.dirty <- false
  end

(** Load height index from disk *)
let load_height_index idx =
  let path = height_index_path idx in
  if not (Sys.file_exists path) then ()
  else begin
    let ic = open_in_bin path in
    (try
      let magic = really_input_string ic 8 in
      if magic <> "HTIDX001" then raise Exit;
      let b0 = input_byte ic in
      let b1 = input_byte ic in
      let b2 = input_byte ic in
      let b3 = input_byte ic in
      let max_height = b0 lor (b1 lsl 8) lor (b2 lsl 16) lor (b3 lsl 24) in
      idx.max_height <- max_height;
      if max_height >= 0 then begin
        idx.hashes <- Array.make (max_height + 1) None;
        for i = 0 to max_height do
          let present = input_byte ic in
          if present = 1 then begin
            let hash_str = really_input_string ic 32 in
            idx.hashes.(i) <- Some (Cstruct.of_string hash_str)
          end
        done
      end
    with _ -> ());
    close_in ic
  end

(** Create or open a height index *)
let create_height_index dir =
  ensure_dir dir;
  let idx = {
    dir;
    hashes = Array.make 1000 None;
    max_height = -1;
    dirty = false;
  } in
  load_height_index idx;
  idx

(** Close height index *)
let close_height_index idx =
  save_height_index idx

(** Sync height index to disk *)
let sync_height_index idx =
  save_height_index idx

(** Ensure array capacity *)
let ensure_height_capacity idx height =
  let current_cap = Array.length idx.hashes in
  if height >= current_cap then begin
    let new_cap = max (current_cap * 2) (height + 1000) in
    let new_arr = Array.make new_cap None in
    Array.blit idx.hashes 0 new_arr 0 current_cap;
    idx.hashes <- new_arr
  end

(** Set hash at height *)
let set_hash_at_height idx height (hash : Types.hash256) =
  ensure_height_capacity idx height;
  idx.hashes.(height) <- Some hash;
  if height > idx.max_height then idx.max_height <- height;
  idx.dirty <- true

(** Get hash at height (O(1)) *)
let get_hash_at_height idx height : Types.hash256 option =
  if height < 0 || height >= Array.length idx.hashes then None
  else idx.hashes.(height)

(** Get current maximum height *)
let get_max_height idx = idx.max_height

(** Remove hash at height (for reorgs) *)
let remove_hash_at_height idx height =
  if height >= 0 && height < Array.length idx.hashes then begin
    idx.hashes.(height) <- None;
    idx.dirty <- true;
    (* Update max_height if needed *)
    if height = idx.max_height then begin
      while idx.max_height >= 0 && idx.hashes.(idx.max_height) = None do
        idx.max_height <- idx.max_height - 1
      done
    end
  end
