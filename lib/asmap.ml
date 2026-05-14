(* ASMap (Autonomous System Map) interpreter.
   Reference: bitcoin-core/src/util/asmap.h + asmap.cpp
              bitcoin-core/src/netgroup.h (NetGroupManager)

   Format: bit-packed binary trie bytecode.
   - ASMap data bits: LSB-first (little-endian bit order)
   - IP address bits:  MSB-first (big-endian / network byte order)

   Four instructions: RETURN, JUMP, MATCH, DEFAULT.

   MAX_ASMAP_FILESIZE mirrors Core: MAX_ASMAP_FILESIZE = 8 * 1024 * 1024. *)

let max_asmap_file_size = 8_388_608  (* 8 * 1024 * 1024 bytes *)

(* Sentinel for decoding errors / invalid data. *)
let invalid_asn : int32 = 0xFFFFFFFFl

(* ============================================================================
   Bit readers
   ============================================================================ *)

(* Read one bit from [bytes] at bit position [bitpos], LSB-first (little-endian).
   Used for asmap bytecode.  Increments [bitpos]. *)
let consume_bit_le (bitpos : int ref) (bytes : bytes) : bool =
  let byte_idx = !bitpos / 8 in
  let bit_idx  = !bitpos mod 8 in
  incr bitpos;
  (Char.code (Bytes.get bytes byte_idx) lsr bit_idx) land 1 = 1

(* Read one bit from [bytes] at bit position [bitpos], MSB-first (big-endian).
   Used for IP address traversal.  Increments [bitpos]. *)
let consume_bit_be (bitpos : int ref) (bytes : bytes) : bool =
  let byte_idx = !bitpos / 8 in
  let bit_idx  = 7 - (!bitpos mod 8) in
  incr bitpos;
  (Char.code (Bytes.get bytes byte_idx) lsr bit_idx) land 1 = 1

(* ============================================================================
   Variable-length integer decoder (DecodeBits)
   Core: DecodeBits(bitpos, data, minval, bit_sizes)

   Encoding classes (example with minval=100, bit_sizes=[4,2,2,3]):
     class 0: prefix=[0],   data=4 bits BE → values 100..115
     class 1: prefix=[1,0], data=2 bits BE → values 116..119
     class 2: prefix=[1,1,0], data=2 bits BE → values 120..123
     class 3 (last): prefix=[1,1,1], data=3 bits BE → values 124..131
   The last class has no continuation bit (it is implicitly "0").
   Returns [invalid_asn] on EOF or format error.
   ============================================================================ *)
let decode_bits (bitpos : int ref) (data : bytes) (minval : int)
    (bit_sizes : int array) : int32 =
  let endpos = Bytes.length data * 8 in
  let n = Array.length bit_sizes in
  let val_ = ref minval in
  let found = ref false in
  let result = ref invalid_asn in
  let i = ref 0 in
  while !i < n && not !found do
    let is_last = (!i = n - 1) in
    (* Read the continuation bit (except for the last class). *)
    let cont_bit =
      if is_last then false
      else begin
        if !bitpos >= endpos then begin
          found := true;  (* EOF in exponent → INVALID *)
          ()
        end;
        if not !found then consume_bit_le bitpos data
        else false
      end
    in
    if not !found then begin
      if cont_bit then begin
        (* Not in this class: add size of this class and proceed. *)
        val_ := !val_ + (1 lsl bit_sizes.(!i));
        i := !i + 1
      end else begin
        (* In this class: read the mantissa in big-endian order. *)
        let bsz = bit_sizes.(!i) in
        let ok = ref true in
        for b = 0 to bsz - 1 do
          if !bitpos >= endpos then ok := false
          else begin
            let bit = consume_bit_le bitpos data in
            if bit then
              val_ := !val_ + (1 lsl (bsz - 1 - b))
          end
        done;
        if !ok then result := Int32.of_int !val_
        (* else INVALID — result stays invalid_asn *)
        ;
        found := true
      end
    end
  done;
  !result

(* ============================================================================
   Instruction type encoding:  [0]=RETURN  [1,0]=JUMP  [1,1,0]=MATCH  [1,1,1]=DEFAULT
   Core: TYPE_BIT_SIZES = {0, 0, 1}; DecodeType uses DecodeBits(pos, data, 0, TYPE_BIT_SIZES)
   ============================================================================ *)
let type_bit_sizes : int array = [| 0; 0; 1 |]

type instruction = Return | Jump | Match | Default | Invalid_instr

let decode_type (bitpos : int ref) (data : bytes) : instruction =
  match Int32.to_int (decode_bits bitpos data 0 type_bit_sizes) with
  | 0 -> Return
  | 1 -> Jump
  | 2 -> Match
  | 3 -> Default
  | _ -> Invalid_instr  (* 0xFFFFFFFF -> INVALID *)

(* ASN encoding: minval=1, bit_sizes=[15,16,...,24]
   Core: ASN_BIT_SIZES = {15,16,17,18,19,20,21,22,23,24}
   Encodes ASNs from 1 to ~16.7 million.  ASN 0 = no match. *)
let asn_bit_sizes : int array = [| 15; 16; 17; 18; 19; 20; 21; 22; 23; 24 |]

let decode_asn (bitpos : int ref) (data : bytes) : int32 =
  decode_bits bitpos data 1 asn_bit_sizes

(* MATCH argument: minval=2, bit_sizes=[1,2,...,8]
   Core: MATCH_BIT_SIZES = {1,2,3,4,5,6,7,8}
   Values [2..511]; highest set bit = match length, lower bits = pattern. *)
let match_bit_sizes : int array = [| 1; 2; 3; 4; 5; 6; 7; 8 |]

let decode_match (bitpos : int ref) (data : bytes) : int32 =
  decode_bits bitpos data 2 match_bit_sizes

(* JUMP offset: minval=17, bit_sizes=[5,6,...,30]
   Core: JUMP_BIT_SIZES = {5,6,...,30} (26 entries)
   Minimum jump offset = 17. *)
let jump_bit_sizes : int array =
  Array.init 26 (fun i -> 5 + i)   (* [5;6;7;...;30] *)

let decode_jump (bitpos : int ref) (data : bytes) : int32 =
  decode_bits bitpos data 17 jump_bit_sizes

(* ============================================================================
   Integer log2 floor (bit_width of an int, i.e. floor(log2(n))+1 for n>=1)
   Mirrors std::bit_width(match) in Core.
   ============================================================================ *)
let bit_width (n : int) : int =
  if n <= 0 then 0
  else
    let n = ref n in
    let w = ref 0 in
    while !n > 0 do
      n := !n lsr 1;
      incr w
    done;
    !w

(* ============================================================================
   Interpret: execute ASMap bytecode to find ASN for an IP address.
   Reference: bitcoin-core/src/util/asmap.cpp Interpret()

   [asmap] — the asmap bytecode (loaded from file, LSB-first bits)
   [ip]    — the IP address as 16 bytes (IPv6 or IPv4-mapped), MSB-first bits

   Returns ASN (> 0) on success, 0 if no match (unassigned prefix).
   ============================================================================ *)
let interpret (asmap : bytes) (ip : bytes) : int32 =
  let pos     = ref 0 in
  let endpos  = Bytes.length asmap * 8 in
  let ip_bit  = ref 0 in
  let ip_bits_end = Bytes.length ip * 8 in
  let default_asn = ref 0l in
  let stop    = ref false in
  let result  = ref 0l in
  while !pos < endpos && not !stop do
    let opcode = decode_type pos asmap in
    (match opcode with
     | Return ->
       let asn = decode_asn pos asmap in
       if asn = invalid_asn then stop := true
       else begin result := asn; stop := true end
     | Jump ->
       let jump = decode_jump pos asmap in
       if jump = invalid_asn then stop := true
       else if !ip_bit = ip_bits_end then stop := true
       else begin
         let jump_i = Int32.to_int jump in
         (* Check: jump would land past EOF. *)
         if jump_i >= (endpos - !pos) then stop := true
         else begin
           if consume_bit_be ip_bit ip then
             pos := !pos + jump_i
           (* else fall through (bit=0, left subtree) *)
         end
       end
     | Match ->
       let m = decode_match pos asmap in
       if m = invalid_asn then stop := true
       else begin
         let m_i = Int32.to_int m in
         let matchlen = (bit_width m_i) - 1 in
         if (ip_bits_end - !ip_bit) < matchlen then stop := true
         else begin
           let mismatch = ref false in
           for bit = 0 to matchlen - 1 do
             if not !mismatch then begin
               let ip_b = consume_bit_be ip_bit ip in
               let pat_b = (m_i lsr (matchlen - 1 - bit)) land 1 = 1 in
               if ip_b <> pat_b then begin
                 mismatch := true;
                 result := !default_asn;
                 stop := true
               end
             end
           done
           (* If loop completed without mismatch: continue execution. *)
         end
       end
     | Default ->
       let asn = decode_asn pos asmap in
       if asn = invalid_asn then stop := true
       else default_asn := asn
     | Invalid_instr ->
       stop := true)
  done;
  !result

(* ============================================================================
   SanityCheckAsmap: validate all execution paths terminate correctly.
   Reference: bitcoin-core/src/util/asmap.cpp SanityCheckAsmap()

   Simulates every possible execution path through the bytecode using a
   jump-target stack (pairs of (bit_offset_in_asmap, ip_bits_remaining)).
   Ensures:
   - every path ends with a RETURN
   - no unreachable code (gap between successive RETURNs and jump targets)
   - at most one <8-bit MATCH in a consecutive MATCH sequence
   - no successive DEFAULTs (could be merged)
   - no RETURN immediately after DEFAULT (ditto)
   - padding after final RETURN is at most 7 zero bits
   Returns [true] if the asmap is well-formed, [false] otherwise.
   ============================================================================ *)
let sanity_check_asmap (asmap : bytes) (bits : int) : bool =
  let pos    = ref 0 in
  let endpos = Bytes.length asmap * 8 in
  (* Stack of (jump_target_bit_offset, ip_bits_remaining_at_target) *)
  let jumps  : (int * int) Stack.t = Stack.create () in
  let bits_left = ref bits in
  let prevopcode = ref Jump in   (* start as if after a JUMP *)
  let had_incomplete_match = ref false in
  let result = ref true in
  let stop   = ref false in

  while not !stop && !result do
    if !pos = endpos then begin
      (* Reached EOF without a RETURN — invalid. *)
      result := false;
      stop   := true
    end else begin
      (* If there is a pending jump target and we've reached or passed it,
         that means a prior instruction straddled the jump boundary → invalid. *)
      if not (Stack.is_empty jumps) then begin
        let (jmp_pos, _) = Stack.top jumps in
        if !pos >= jmp_pos && !pos <> jmp_pos then begin
          result := false;
          stop   := true
        end
      end;
      if not !stop then begin
        let opcode = decode_type pos asmap in
        match opcode with
        | Return ->
          (* RETURN immediately after DEFAULT is redundant — invalid. *)
          if !prevopcode = Default then begin
            result := false;
            stop   := true
          end else begin
            let asn = decode_asn pos asmap in
            if asn = invalid_asn then begin
              result := false;
              stop   := true
            end else begin
              if Stack.is_empty jumps then begin
                (* This is the final RETURN: check padding. *)
                if endpos - !pos > 7 then begin
                  result := false;
                  stop   := true
                end else begin
                  (* All remaining bits must be zero. *)
                  while !pos < endpos && !result do
                    if consume_bit_le pos asmap then begin
                      result := false
                    end
                  done;
                  (* Sanely reached EOF. *)
                  stop := true
                end
              end else begin
                (* Pop the jump target; we must be exactly at its position. *)
                let (jmp_pos, saved_bits) = Stack.pop jumps in
                if !pos <> jmp_pos then begin
                  result := false;
                  stop   := true
                end else begin
                  bits_left  := saved_bits;
                  prevopcode := Jump   (* after a simulated jump *)
                end
              end
            end
          end
        | Jump ->
          let jump = decode_jump pos asmap in
          if jump = invalid_asn then begin
            result := false; stop := true
          end else begin
            let jump_i = Int32.to_int jump in
            if jump_i > (endpos - !pos) then begin
              result := false; stop := true
            end else if !bits_left = 0 then begin
              result := false; stop := true
            end else begin
              bits_left := !bits_left - 1;
              let jump_target = !pos + jump_i in
              (* Intersecting jumps are invalid. *)
              if not (Stack.is_empty jumps) then begin
                let (top_pos, _) = Stack.top jumps in
                if jump_target >= top_pos then begin
                  result := false; stop := true
                end
              end;
              if not !stop then begin
                Stack.push (jump_target, !bits_left) jumps;
                prevopcode := Jump
              end
            end
          end
        | Match ->
          let m = decode_match pos asmap in
          if m = invalid_asn then begin
            result := false; stop := true
          end else begin
            let m_i = Int32.to_int m in
            let matchlen = (bit_width m_i) - 1 in
            if !prevopcode <> Match then had_incomplete_match := false;
            (* At most one <8-bit MATCH in a consecutive sequence. *)
            if matchlen < 8 && !had_incomplete_match then begin
              result := false; stop := true
            end else begin
              had_incomplete_match := (matchlen < 8);
              if !bits_left < matchlen then begin
                result := false; stop := true
              end else begin
                bits_left  := !bits_left - matchlen;
                prevopcode := Match
              end
            end
          end
        | Default ->
          (* Two successive DEFAULTs are redundant — invalid. *)
          if !prevopcode = Default then begin
            result := false; stop := true
          end else begin
            let asn = decode_asn pos asmap in
            if asn = invalid_asn then begin
              result := false; stop := true
            end else
              prevopcode := Default
          end
        | Invalid_instr ->
          result := false; stop := true
      end
    end
  done;
  !result

(* Standard 128-bit wrapper used for IPv6 inputs. *)
let check_standard_asmap (data : bytes) : bool =
  sanity_check_asmap data 128

(* ============================================================================
   load_asmap: read an asmap file from disk and validate it.
   Returns [Some bytes] on success, [None] on failure (bad size / invalid data).
   MAX_ASMAP_FILESIZE = 8 MiB.
   ============================================================================ *)
let load_asmap (path : string) : bytes option =
  try
    let ic    = open_in_bin path in
    let len   = in_channel_length ic in
    if len > max_asmap_file_size then begin
      close_in_noerr ic;
      Logs.warn (fun m ->
        m "asmap file %s too large (%d bytes, max %d)" path len max_asmap_file_size);
      None
    end else begin
      let buf = Bytes.create len in
      really_input ic buf 0 len;
      close_in ic;
      if check_standard_asmap buf then begin
        Logs.info (fun m ->
          m "Opened asmap file %s (%d bytes)" path len);
        Some buf
      end else begin
        Logs.warn (fun m ->
          m "Sanity check of asmap file %s failed" path);
        None
      end
    end
  with exn ->
    Logs.warn (fun m ->
      m "Failed to open asmap file %s: %s" path (Printexc.to_string exn));
    None

(* ============================================================================
   asmap_version: SHA256 of the asmap bytes for versioning.
   Mirrors Core: AsmapVersion() — HashWriter over the data.
   ============================================================================ *)
let asmap_version (data : bytes) : string =
  Digestif.SHA256.(to_raw_string (digest_string (Bytes.to_string data)))

(* ============================================================================
   IPv4 → 16-byte IPv4-mapped IPv6
   Core maps IPv4 to ::ffff:a.b.c.d for consistent 128-bit trie lookups.
   ============================================================================ *)
let ipv4_to_ipv6_mapped (a : int) (b : int) (c : int) (d : int) : bytes =
  (* ::ffff:a.b.c.d  = 10 zero bytes + 0xff 0xff + a b c d *)
  let buf = Bytes.make 16 '\x00' in
  Bytes.set buf 10 '\xff';
  Bytes.set buf 11 '\xff';
  Bytes.set buf 12 (Char.chr (a land 0xff));
  Bytes.set buf 13 (Char.chr (b land 0xff));
  Bytes.set buf 14 (Char.chr (c land 0xff));
  Bytes.set buf 15 (Char.chr (d land 0xff));
  buf

(* Parse a dotted-quad IPv4 string and return the 16-byte IPv4-mapped form.
   Returns None if the string is not a valid IPv4 address. *)
let parse_ipv4_to_bytes (addr : string) : bytes option =
  match String.split_on_char '.' addr with
  | [a_s; b_s; c_s; d_s] ->
    (match
       (int_of_string_opt a_s, int_of_string_opt b_s,
        int_of_string_opt c_s, int_of_string_opt d_s)
     with
     | Some a, Some b, Some c, Some d
       when a >= 0 && a <= 255
         && b >= 0 && b <= 255
         && c >= 0 && c <= 255
         && d >= 0 && d <= 255 ->
       Some (ipv4_to_ipv6_mapped a b c d)
     | _ -> None)
  | _ -> None

(* ============================================================================
   NetGroupManager: wraps the asmap data and exposes get_group / get_mapped_as.

   With asmap active:
     get_group(addr) → 4-byte ASN big-endian
     get_mapped_as(addr) → ASN int32 (0 = no match)

   Without asmap (or parse failure):
     get_group(addr) → "A.B" bytes (the /16 fallback, matching legacy code)
     get_mapped_as(addr) → 0l
   ============================================================================ *)
type net_group_manager = {
  asmap : bytes option;   (* None = asmap not loaded; Some = active asmap *)
}

let create_net_group_manager (asmap : bytes option) : net_group_manager =
  { asmap }

let using_asmap (ngm : net_group_manager) : bool =
  ngm.asmap <> None

(* Look up the ASN for [addr] (dotted-quad IPv4 string).
   Returns 0l if asmap is not loaded, if the IP cannot be parsed, or if the
   address does not match any prefix in the trie. *)
let get_mapped_as (ngm : net_group_manager) (addr : string) : int32 =
  match ngm.asmap with
  | None -> 0l
  | Some asmap_data ->
    (match parse_ipv4_to_bytes addr with
     | None -> 0l
     | Some ip_bytes -> interpret asmap_data ip_bytes)

(* Return the group bytes for bucketing in AddrMan.
   - With asmap: 4-byte big-endian ASN.
   - Without asmap: legacy "/16" string "A.B".
   Returned as a string (raw bytes) for use in SHA256 hashing. *)
let get_group (ngm : net_group_manager) (addr : string) : string =
  match ngm.asmap with
  | None ->
    (* Legacy /16 fallback: "A.B" *)
    (match String.split_on_char '.' addr with
     | a :: b :: _ -> a ^ "." ^ b
     | _ -> addr)
  | Some _ ->
    let asn = get_mapped_as ngm addr in
    if asn = 0l then begin
      (* No ASN match: fall back to /16 *)
      (match String.split_on_char '.' addr with
       | a :: b :: _ -> a ^ "." ^ b
       | _ -> addr)
    end else begin
      (* 4-byte big-endian ASN. *)
      let n = Int32.to_int asn in
      let buf = Bytes.create 4 in
      Bytes.set buf 0 (Char.chr ((n lsr 24) land 0xff));
      Bytes.set buf 1 (Char.chr ((n lsr 16) land 0xff));
      Bytes.set buf 2 (Char.chr ((n lsr 8)  land 0xff));
      Bytes.set buf 3 (Char.chr  (n         land 0xff));
      Bytes.to_string buf
    end
