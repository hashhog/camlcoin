(* Output Descriptors (BIP 380-386)

   A portable, human-readable way to describe collections of output scripts.

   Supports:
   - pk(KEY) - P2PK (pay to public key)
   - pkh(KEY) - P2PKH (pay to public key hash)
   - wpkh(KEY) - P2WPKH (native SegWit v0 pubkey hash)
   - sh(SCRIPT) - P2SH wrapper
   - wsh(SCRIPT) - P2WSH (native SegWit v0 script hash)
   - tr(KEY) / tr(KEY, TREE) - P2TR (Taproot)
   - multi(k, KEY, ...) - k-of-n multisig
   - sortedmulti(k, KEY, ...) - sorted k-of-n multisig
   - combo(KEY) - all output types for a key
   - addr(ADDRESS) - raw address
   - raw(HEX) - raw script bytes

   Key expressions:
   - Hex pubkey (33 or 65 bytes compressed/uncompressed)
   - WIF private key
   - xpub/xprv extended keys with derivation paths
   - Origin info: [fingerprint/path]key
   - Wildcards: * (unhardened), *' or *h (hardened)
*)

(* ============================================================================
   Types
   ============================================================================ *)

(* Derivation path component *)
type path_element =
  | Normal of int     (* unhardened index *)
  | Hardened of int   (* hardened index (will have 0x80000000 added) *)

(* Derivation path *)
type derivation_path = path_element list

(* Whether a key uses wildcards *)
type derive_type =
  | NonRanged          (* no wildcard *)
  | UnhardenedRanged   (* ends with /* *)
  | HardenedRanged     (* ends with /*' or /*h *)

(* Key origin info: [fingerprint/path] *)
type key_origin = {
  fingerprint : int32;        (* 4-byte fingerprint *)
  origin_path : derivation_path;
}

(* Key expression - represents a key in a descriptor *)
type key_expr =
  | ConstPubkey of Cstruct.t * bool  (* raw pubkey, is_xonly *)
  | ConstPrivkey of Cstruct.t        (* WIF-decoded private key *)
  | Xpub of {
      extkey : Wallet.extended_key;
      path : derivation_path;
      derive : derive_type;
      is_private : bool;  (* was parsed from xprv *)
    }
  | WithOrigin of key_origin * key_expr  (* wrapped with origin info *)

(* Taproot script tree *)
type tap_tree =
  | TapLeaf of int * descriptor  (* leaf_version, script descriptor *)
  | TapBranch of tap_tree * tap_tree

(* Descriptor AST *)
and descriptor =
  | Pk of key_expr                            (* pk(KEY) *)
  | Pkh of key_expr                           (* pkh(KEY) *)
  | Wpkh of key_expr                          (* wpkh(KEY) *)
  | Sh of descriptor                          (* sh(SCRIPT) *)
  | Wsh of descriptor                         (* wsh(SCRIPT) *)
  | Tr of key_expr * tap_tree option          (* tr(KEY) or tr(KEY, TREE) *)
  | Multi of int * key_expr list              (* multi(k, KEY, ...) *)
  | SortedMulti of int * key_expr list        (* sortedmulti(k, KEY, ...) *)
  | Combo of key_expr                         (* combo(KEY) *)
  | Addr of Address.address                   (* addr(ADDRESS) *)
  | Raw of Cstruct.t                          (* raw(HEX) *)

(* A fully parsed descriptor with checksum *)
type parsed_descriptor = {
  desc : descriptor;
  checksum : string option;  (* 8-char checksum if present *)
}

(* Script type produced by a descriptor *)
type script_type =
  | ScriptP2PK
  | ScriptP2PKH
  | ScriptP2WPKH
  | ScriptP2SH
  | ScriptP2WSH
  | ScriptP2TR
  | ScriptMultisig
  | ScriptRaw

(* Result of expanding a descriptor at a specific index *)
type expansion = {
  script_pubkey : Cstruct.t;
  script_type : script_type;
  pubkeys : Cstruct.t list;
  address : string option;
}

(* ============================================================================
   Checksum (BIP 380)
   ============================================================================ *)

(* The input charset for descriptor checksum calculation *)
let input_charset =
  "0123456789()[],'/*abcdefgh@:$%{}" ^
  "IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~" ^
  "ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "

(* The checksum charset (same as bech32) *)
let checksum_charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

(* Polynomial modular arithmetic for checksum *)
let polymod (c : int64) (v : int) : int64 =
  let c0 = Int64.to_int (Int64.shift_right_logical c 35) in
  let c = Int64.logxor
    (Int64.shift_left (Int64.logand c 0x7ffffffffL) 5)
    (Int64.of_int v) in
  let c = if c0 land 1 <> 0 then Int64.logxor c 0xf5dee51989L else c in
  let c = if c0 land 2 <> 0 then Int64.logxor c 0xa9fdca3312L else c in
  let c = if c0 land 4 <> 0 then Int64.logxor c 0x1bab10e32dL else c in
  let c = if c0 land 8 <> 0 then Int64.logxor c 0x3706b1677aL else c in
  let c = if c0 land 16 <> 0 then Int64.logxor c 0x644d626ffdL else c in
  c

(* Compute descriptor checksum *)
let descriptor_checksum (s : string) : string option =
  let len = String.length s in
  let c = ref 1L in
  let cls = ref 0 in
  let clscount = ref 0 in
  try
    for i = 0 to len - 1 do
      let ch = s.[i] in
      match String.index_opt input_charset ch with
      | None -> raise Exit
      | Some pos ->
        c := polymod !c (pos land 31);
        cls := !cls * 3 + (pos lsr 5);
        incr clscount;
        if !clscount = 3 then begin
          c := polymod !c !cls;
          cls := 0;
          clscount := 0
        end
    done;
    if !clscount > 0 then c := polymod !c !cls;
    for _ = 0 to 7 do
      c := polymod !c 0
    done;
    c := Int64.logxor !c 1L;
    let result = Bytes.create 8 in
    for j = 0 to 7 do
      let idx = Int64.to_int (Int64.logand (Int64.shift_right_logical !c (5 * (7 - j))) 31L) in
      Bytes.set result j (String.get checksum_charset idx)
    done;
    Some (Bytes.to_string result)
  with Exit -> None

(* Add checksum to descriptor string *)
let add_checksum (s : string) : string option =
  match descriptor_checksum s with
  | Some cs -> Some (s ^ "#" ^ cs)
  | None -> None

(* Verify checksum *)
let verify_checksum (s : string) : bool =
  match String.rindex_opt s '#' with
  | None -> false
  | Some pos ->
    let desc = String.sub s 0 pos in
    let given = String.sub s (pos + 1) (String.length s - pos - 1) in
    if String.length given <> 8 then false
    else match descriptor_checksum desc with
      | Some computed -> String.equal computed given
      | None -> false

(* ============================================================================
   Hex helpers
   ============================================================================ *)

let is_hex_char c =
  (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')

let is_hex s =
  String.length s > 0 &&
  String.length s mod 2 = 0 &&
  String.for_all is_hex_char s

let hex_to_cstruct s =
  let len = String.length s / 2 in
  let buf = Cstruct.create len in
  for i = 0 to len - 1 do
    let byte = int_of_string ("0x" ^ String.sub s (i * 2) 2) in
    Cstruct.set_uint8 buf i byte
  done;
  buf

let cstruct_to_hex cs =
  let len = Cstruct.length cs in
  let buf = Buffer.create (len * 2) in
  for i = 0 to len - 1 do
    Buffer.add_string buf (Printf.sprintf "%02x" (Cstruct.get_uint8 cs i))
  done;
  Buffer.contents buf

(* ============================================================================
   Parsing helpers
   ============================================================================ *)

(* Find matching close parenthesis *)
let find_matching_paren s start =
  let len = String.length s in
  let depth = ref 1 in
  let i = ref (start + 1) in
  while !i < len && !depth > 0 do
    if s.[!i] = '(' then incr depth
    else if s.[!i] = ')' then decr depth;
    incr i
  done;
  if !depth = 0 then Some (!i - 1) else None

(* Split on comma, respecting parentheses *)
let split_args s =
  let len = String.length s in
  let parts = ref [] in
  let start = ref 0 in
  let depth = ref 0 in
  for i = 0 to len - 1 do
    let c = s.[i] in
    if c = '(' || c = '{' then incr depth
    else if c = ')' || c = '}' then decr depth
    else if c = ',' && !depth = 0 then begin
      parts := String.sub s !start (i - !start) :: !parts;
      start := i + 1
    end
  done;
  if !start < len then
    parts := String.sub s !start (len - !start) :: !parts;
  List.rev !parts

(* Trim whitespace *)
let trim s =
  let len = String.length s in
  let i = ref 0 in
  while !i < len && (s.[!i] = ' ' || s.[!i] = '\t' || s.[!i] = '\n') do incr i done;
  let j = ref (len - 1) in
  while !j >= !i && (s.[!j] = ' ' || s.[!j] = '\t' || s.[!j] = '\n') do decr j done;
  if !i > !j then "" else String.sub s !i (!j - !i + 1)

(* ============================================================================
   Key parsing
   ============================================================================ *)

(* Parse derivation path like /0/1'/2h *)
let parse_derivation_path (s : string) : (derivation_path * derive_type, string) result =
  if String.length s = 0 then Ok ([], NonRanged)
  else begin
    let parts = String.split_on_char '/' s in
    let parts = List.filter (fun p -> String.length p > 0) parts in
    let rec parse_parts acc = function
      | [] -> Ok (List.rev acc, NonRanged)
      | ["*"] -> Ok (List.rev acc, UnhardenedRanged)
      | ["*'"] | ["*h"] -> Ok (List.rev acc, HardenedRanged)
      | p :: rest ->
        let len = String.length p in
        let is_hardened = len > 0 && (p.[len-1] = '\'' || p.[len-1] = 'h') in
        let num_str = if is_hardened then String.sub p 0 (len - 1) else p in
        match int_of_string_opt num_str with
        | None -> Error ("invalid path element: " ^ p)
        | Some n when n < 0 || n > 0x7fffffff ->
          Error ("path index out of range: " ^ p)
        | Some n ->
          let elem = if is_hardened then Hardened n else Normal n in
          parse_parts (elem :: acc) rest
    in
    parse_parts [] parts
  end

(* Parse key origin [fingerprint/path] *)
let parse_key_origin (s : string) : (key_origin * string, string) result =
  if String.length s < 2 || s.[0] <> '[' then
    Error "expected '[' at start of origin"
  else
    match String.index_opt s ']' with
    | None -> Error "missing ']' in origin"
    | Some close_pos ->
      let origin_str = String.sub s 1 (close_pos - 1) in
      let rest = String.sub s (close_pos + 1) (String.length s - close_pos - 1) in
      (* Parse fingerprint and path *)
      let parts = String.split_on_char '/' origin_str in
      match parts with
      | [] -> Error "empty origin"
      | fp_hex :: path_parts ->
        if String.length fp_hex <> 8 || not (is_hex fp_hex) then
          Error "invalid fingerprint in origin"
        else begin
          let fp = Int32.of_string ("0x" ^ fp_hex) in
          let path_str = String.concat "/" path_parts in
          match parse_derivation_path path_str with
          | Error e -> Error e
          | Ok (path, _) ->
            Ok ({ fingerprint = fp; origin_path = path }, rest)
        end

(* Parse a pubkey (hex, WIF, xpub, xprv) *)
let parse_key_inner (s : string) (ctx : [`Top | `P2SH | `P2WSH | `P2TR])
    : (key_expr, string) result =
  let s = trim s in
  (* Check for derivation path *)
  let base_key, path_str =
    match String.index_opt s '/' with
    | None -> (s, "")
    | Some pos -> (String.sub s 0 pos, String.sub s pos (String.length s - pos))
  in
  (* Parse the path *)
  match parse_derivation_path path_str with
  | Error e -> Error e
  | Ok (path, derive) ->
    (* Try parsing as hex pubkey *)
    if is_hex base_key then begin
      let data = hex_to_cstruct base_key in
      let len = Cstruct.length data in
      if len = 33 || len = 65 then begin
        (* Check if compressed is required *)
        let is_compressed = len = 33 in
        if not is_compressed && ctx <> `Top && ctx <> `P2SH then
          Error "uncompressed keys not allowed here"
        else if List.length path > 0 || derive <> NonRanged then
          Error "cannot derive from raw pubkey"
        else
          Ok (ConstPubkey (data, false))
      end else if len = 32 && ctx = `P2TR then begin
        (* x-only pubkey for taproot *)
        if List.length path > 0 || derive <> NonRanged then
          Error "cannot derive from x-only pubkey"
        else
          (* Prefix with 0x02 to make a full compressed key *)
          let full = Cstruct.create 33 in
          Cstruct.set_uint8 full 0 0x02;
          Cstruct.blit data 0 full 1 32;
          Ok (ConstPubkey (full, true))
      end else
        Error ("invalid pubkey length: " ^ string_of_int len)
    end
    (* Try parsing as xpub/xprv *)
    else begin
      match Wallet.deserialize_extended_key base_key with
      | Ok (extkey, is_private) ->
        Ok (Xpub { extkey; path; derive; is_private })
      | Error _ ->
        (* Try as WIF *)
        match Address.base58check_decode base_key with
        | Error _ -> Error ("cannot parse key: " ^ base_key)
        | Ok payload ->
          let len = Cstruct.length payload in
          if len = 33 || len = 34 then begin
            let version = Cstruct.get_uint8 payload 0 in
            if version = 0x80 || version = 0xef then begin
              let privkey = Cstruct.sub payload 1 32 in
              if List.length path > 0 || derive <> NonRanged then
                Error "cannot derive from WIF key"
              else
                Ok (ConstPrivkey privkey)
            end else
              Error "invalid WIF version"
          end else
            Error "invalid WIF length"
    end

(* Parse a full key expression (with optional origin) *)
let parse_key (s : string) (ctx : [`Top | `P2SH | `P2WSH | `P2TR])
    : (key_expr, string) result =
  let s = trim s in
  if String.length s > 0 && s.[0] = '[' then
    match parse_key_origin s with
    | Error e -> Error e
    | Ok (origin, rest) ->
      match parse_key_inner rest ctx with
      | Error e -> Error e
      | Ok key -> Ok (WithOrigin (origin, key))
  else
    parse_key_inner s ctx

(* ============================================================================
   Descriptor parsing
   ============================================================================ *)

(* Forward declaration for recursive parsing *)
let rec parse_descriptor_inner (s : string) : (descriptor, string) result =
  let s = trim s in
  if String.length s = 0 then Error "empty descriptor"
  (* pk(KEY) *)
  else if String.length s > 3 && String.sub s 0 3 = "pk(" then
    match find_matching_paren s 2 with
    | None -> Error "unmatched parenthesis in pk()"
    | Some close ->
      let key_str = String.sub s 3 (close - 3) in
      match parse_key key_str `Top with
      | Error e -> Error ("pk: " ^ e)
      | Ok key -> Ok (Pk key)
  (* pkh(KEY) *)
  else if String.length s > 4 && String.sub s 0 4 = "pkh(" then
    match find_matching_paren s 3 with
    | None -> Error "unmatched parenthesis in pkh()"
    | Some close ->
      let key_str = String.sub s 4 (close - 4) in
      match parse_key key_str `Top with
      | Error e -> Error ("pkh: " ^ e)
      | Ok key -> Ok (Pkh key)
  (* wpkh(KEY) *)
  else if String.length s > 5 && String.sub s 0 5 = "wpkh(" then
    match find_matching_paren s 4 with
    | None -> Error "unmatched parenthesis in wpkh()"
    | Some close ->
      let key_str = String.sub s 5 (close - 5) in
      match parse_key key_str `P2WSH with
      | Error e -> Error ("wpkh: " ^ e)
      | Ok key -> Ok (Wpkh key)
  (* sh(SCRIPT) *)
  else if String.length s > 3 && String.sub s 0 3 = "sh(" then
    match find_matching_paren s 2 with
    | None -> Error "unmatched parenthesis in sh()"
    | Some close ->
      let inner_str = String.sub s 3 (close - 3) in
      match parse_descriptor_inner inner_str with
      | Error e -> Error ("sh: " ^ e)
      | Ok inner -> Ok (Sh inner)
  (* wsh(SCRIPT) *)
  else if String.length s > 4 && String.sub s 0 4 = "wsh(" then
    match find_matching_paren s 3 with
    | None -> Error "unmatched parenthesis in wsh()"
    | Some close ->
      let inner_str = String.sub s 4 (close - 4) in
      match parse_descriptor_inner inner_str with
      | Error e -> Error ("wsh: " ^ e)
      | Ok inner -> Ok (Wsh inner)
  (* tr(KEY) or tr(KEY, TREE) *)
  else if String.length s > 3 && String.sub s 0 3 = "tr(" then
    match find_matching_paren s 2 with
    | None -> Error "unmatched parenthesis in tr()"
    | Some close ->
      let args_str = String.sub s 3 (close - 3) in
      let args = split_args args_str in
      begin match args with
      | [] -> Error "tr: missing internal key"
      | [key_str] ->
        begin match parse_key key_str `P2TR with
        | Error e -> Error ("tr: " ^ e)
        | Ok key -> Ok (Tr (key, None))
        end
      | key_str :: tree_parts ->
        begin match parse_key key_str `P2TR with
        | Error e -> Error ("tr: " ^ e)
        | Ok key ->
          (* Parse script tree *)
          let tree_str = String.concat "," tree_parts in
          match parse_tap_tree tree_str with
          | Error e -> Error ("tr tree: " ^ e)
          | Ok tree -> Ok (Tr (key, Some tree))
        end
      end
  (* multi(k, KEY, KEY, ...) *)
  else if String.length s > 6 && String.sub s 0 6 = "multi(" then
    match find_matching_paren s 5 with
    | None -> Error "unmatched parenthesis in multi()"
    | Some close ->
      let args_str = String.sub s 6 (close - 6) in
      parse_multisig args_str false
  (* sortedmulti(k, KEY, KEY, ...) *)
  else if String.length s > 12 && String.sub s 0 12 = "sortedmulti(" then
    match find_matching_paren s 11 with
    | None -> Error "unmatched parenthesis in sortedmulti()"
    | Some close ->
      let args_str = String.sub s 12 (close - 12) in
      parse_multisig args_str true
  (* combo(KEY) *)
  else if String.length s > 6 && String.sub s 0 6 = "combo(" then
    match find_matching_paren s 5 with
    | None -> Error "unmatched parenthesis in combo()"
    | Some close ->
      let key_str = String.sub s 6 (close - 6) in
      match parse_key key_str `Top with
      | Error e -> Error ("combo: " ^ e)
      | Ok key -> Ok (Combo key)
  (* addr(ADDRESS) *)
  else if String.length s > 5 && String.sub s 0 5 = "addr(" then
    match find_matching_paren s 4 with
    | None -> Error "unmatched parenthesis in addr()"
    | Some close ->
      let addr_str = String.sub s 5 (close - 5) in
      (* Parse address - network is inferred from the address format *)
      match Address.address_of_string addr_str with
      | Ok addr -> Ok (Addr addr)
      | Error e -> Error ("addr: " ^ e)
  (* raw(HEX) *)
  else if String.length s > 4 && String.sub s 0 4 = "raw(" then
    match find_matching_paren s 3 with
    | None -> Error "unmatched parenthesis in raw()"
    | Some close ->
      let hex_str = String.sub s 4 (close - 4) in
      if not (is_hex hex_str) then
        Error "raw: invalid hex"
      else
        Ok (Raw (hex_to_cstruct hex_str))
  else
    Error ("unknown descriptor: " ^ s)

(* Parse tap tree *)
and parse_tap_tree (s : string) : (tap_tree, string) result =
  let s = trim s in
  if String.length s = 0 then Error "empty tap tree"
  else if s.[0] = '{' then begin
    (* Branch: {left, right} *)
    match String.rindex_opt s '}' with
    | None -> Error "unmatched '{' in tap tree"
    | Some close ->
      let inner = String.sub s 1 (close - 1) in
      let parts = split_args inner in
      match parts with
      | [left; right] ->
        begin match parse_tap_tree left with
        | Error e -> Error e
        | Ok left_tree ->
          match parse_tap_tree right with
          | Error e -> Error e
          | Ok right_tree -> Ok (TapBranch (left_tree, right_tree))
        end
      | _ -> Error "tap branch requires exactly 2 children"
  end else begin
    (* Leaf: script descriptor with optional leaf version *)
    (* For now, assume leaf version 0xc0 (tapscript) *)
    match parse_descriptor_inner s with
    | Error e -> Error e
    | Ok desc -> Ok (TapLeaf (0xc0, desc))
  end

(* Parse multisig arguments *)
and parse_multisig (s : string) (sorted : bool) : (descriptor, string) result =
  let args = split_args s in
  match args with
  | [] -> Error "multi: missing threshold"
  | k_str :: key_strs ->
    match int_of_string_opt (trim k_str) with
    | None -> Error "multi: invalid threshold"
    | Some k ->
      if k < 1 then Error "multi: threshold must be at least 1"
      else begin
        let keys = List.map (fun ks -> parse_key ks `P2WSH) key_strs in
        let errors = List.filter_map (function Error e -> Some e | Ok _ -> None) keys in
        if List.length errors > 0 then
          Error ("multi: " ^ List.hd errors)
        else begin
          let keys = List.filter_map (function Ok k -> Some k | Error _ -> None) keys in
          let n = List.length keys in
          if k > n then Error "multi: threshold exceeds key count"
          else if n > 20 then Error "multi: too many keys (max 20)"
          else if sorted then Ok (SortedMulti (k, keys))
          else Ok (Multi (k, keys))
        end
      end

(* Parse a descriptor with optional checksum *)
let parse (s : string) : (parsed_descriptor, string) result =
  let s = trim s in
  let desc_str, checksum =
    match String.rindex_opt s '#' with
    | None -> (s, None)
    | Some pos ->
      let cs = String.sub s (pos + 1) (String.length s - pos - 1) in
      if String.length cs = 8 then
        (String.sub s 0 pos, Some cs)
      else
        (s, None)
  in
  (* Verify checksum if present *)
  if Option.is_some checksum then begin
    if not (verify_checksum s) then
      Error "invalid checksum"
    else match parse_descriptor_inner desc_str with
      | Error e -> Error e
      | Ok desc -> Ok { desc; checksum }
  end else
    match parse_descriptor_inner desc_str with
    | Error e -> Error e
    | Ok desc -> Ok { desc; checksum = None }

(* ============================================================================
   Key derivation
   ============================================================================ *)

(* Derive a key at a specific index *)
let derive_key_at (key : key_expr) (index : int) : (Cstruct.t, string) result =
  let rec derive k =
    match k with
    | ConstPubkey (pk, _) -> Ok pk
    | ConstPrivkey priv ->
      Ok (Crypto.derive_public_key ~compressed:true priv)
    | WithOrigin (_, inner) -> derive inner
    | Xpub { extkey; path; derive = dt; is_private = _ } ->
      (* Derive along the path *)
      let rec derive_path ek = function
        | [] -> Ok ek
        | Normal n :: rest ->
          begin match Wallet.derive_normal ek n with
          | Error e -> Error e
          | Ok ek' -> derive_path ek' rest
          end
        | Hardened n :: rest ->
          begin match Wallet.derive_hardened ek n with
          | Error e -> Error e
          | Ok ek' -> derive_path ek' rest
          end
      in
      match derive_path extkey path with
      | Error e -> Error e
      | Ok derived ->
        (* Handle wildcard derivation *)
        begin match dt with
        | NonRanged ->
          Ok (Crypto.derive_public_key ~compressed:true derived.key)
        | UnhardenedRanged ->
          begin match Wallet.derive_normal derived index with
          | Error e -> Error e
          | Ok final ->
            Ok (Crypto.derive_public_key ~compressed:true final.key)
          end
        | HardenedRanged ->
          begin match Wallet.derive_hardened derived index with
          | Error e -> Error e
          | Ok final ->
            Ok (Crypto.derive_public_key ~compressed:true final.key)
          end
        end
  in
  derive key

(* Get x-only pubkey for taproot *)
let get_xonly_pubkey (pubkey : Cstruct.t) : Cstruct.t =
  if Cstruct.length pubkey = 32 then pubkey
  else if Cstruct.length pubkey = 33 then
    Cstruct.sub pubkey 1 32
  else
    (* Uncompressed - need to derive compressed first *)
    let x = Cstruct.sub pubkey 1 32 in
    x

(* ============================================================================
   Script generation
   ============================================================================ *)

(* Build P2PK script: <pubkey> OP_CHECKSIG *)
let build_p2pk_script (pubkey : Cstruct.t) : Cstruct.t =
  let len = Cstruct.length pubkey in
  let script = Cstruct.create (1 + len + 1) in
  Cstruct.set_uint8 script 0 len;
  Cstruct.blit pubkey 0 script 1 len;
  Cstruct.set_uint8 script (1 + len) 0xac; (* OP_CHECKSIG *)
  script

(* Build P2PKH script: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG *)
let build_p2pkh_script (pubkey_hash : Cstruct.t) : Cstruct.t =
  let script = Cstruct.create 25 in
  Cstruct.set_uint8 script 0 0x76;  (* OP_DUP *)
  Cstruct.set_uint8 script 1 0xa9;  (* OP_HASH160 *)
  Cstruct.set_uint8 script 2 0x14;  (* push 20 bytes *)
  Cstruct.blit pubkey_hash 0 script 3 20;
  Cstruct.set_uint8 script 23 0x88; (* OP_EQUALVERIFY *)
  Cstruct.set_uint8 script 24 0xac; (* OP_CHECKSIG *)
  script

(* Build P2WPKH script: OP_0 <20 bytes> *)
let build_p2wpkh_script (pubkey_hash : Cstruct.t) : Cstruct.t =
  let script = Cstruct.create 22 in
  Cstruct.set_uint8 script 0 0x00;  (* OP_0 *)
  Cstruct.set_uint8 script 1 0x14;  (* push 20 bytes *)
  Cstruct.blit pubkey_hash 0 script 2 20;
  script

(* Build P2SH script: OP_HASH160 <20 bytes> OP_EQUAL *)
let build_p2sh_script (script_hash : Cstruct.t) : Cstruct.t =
  let script = Cstruct.create 23 in
  Cstruct.set_uint8 script 0 0xa9;  (* OP_HASH160 *)
  Cstruct.set_uint8 script 1 0x14;  (* push 20 bytes *)
  Cstruct.blit script_hash 0 script 2 20;
  Cstruct.set_uint8 script 22 0x87; (* OP_EQUAL *)
  script

(* Build P2WSH script: OP_0 <32 bytes> *)
let build_p2wsh_script (script_hash : Cstruct.t) : Cstruct.t =
  let script = Cstruct.create 34 in
  Cstruct.set_uint8 script 0 0x00;  (* OP_0 *)
  Cstruct.set_uint8 script 1 0x20;  (* push 32 bytes *)
  Cstruct.blit script_hash 0 script 2 32;
  script

(* Build P2TR script: OP_1 <32 bytes> *)
let build_p2tr_script (xonly_pubkey : Cstruct.t) : Cstruct.t =
  let script = Cstruct.create 34 in
  Cstruct.set_uint8 script 0 0x51;  (* OP_1 *)
  Cstruct.set_uint8 script 1 0x20;  (* push 32 bytes *)
  Cstruct.blit xonly_pubkey 0 script 2 32;
  script

(* Build multisig script: k <pk1> <pk2> ... <pkn> n OP_CHECKMULTISIG *)
let build_multisig_script (k : int) (pubkeys : Cstruct.t list) : Cstruct.t =
  let n = List.length pubkeys in
  (* Calculate size: OP_k + (push + 33 bytes) per key + OP_n + OP_CHECKMULTISIG *)
  let size = 1 + (n * 34) + 1 + 1 in
  let script = Cstruct.create size in
  let pos = ref 0 in
  (* OP_k (OP_1 = 0x51, etc) *)
  Cstruct.set_uint8 script !pos (0x50 + k);
  incr pos;
  (* Push each pubkey *)
  List.iter (fun pk ->
    let len = Cstruct.length pk in
    Cstruct.set_uint8 script !pos len;
    incr pos;
    Cstruct.blit pk 0 script !pos len;
    pos := !pos + len
  ) pubkeys;
  (* OP_n *)
  Cstruct.set_uint8 script !pos (0x50 + n);
  incr pos;
  (* OP_CHECKMULTISIG *)
  Cstruct.set_uint8 script !pos 0xae;
  script

(* Expand a descriptor at a specific index *)
let rec expand (desc : descriptor) (index : int) (network : Address.network)
    : (expansion list, string) result =
  match desc with
  | Pk key ->
    begin match derive_key_at key index with
    | Error e -> Error e
    | Ok pubkey ->
      let script = build_p2pk_script pubkey in
      Ok [{ script_pubkey = script; script_type = ScriptP2PK;
            pubkeys = [pubkey]; address = None }]
    end

  | Pkh key ->
    begin match derive_key_at key index with
    | Error e -> Error e
    | Ok pubkey ->
      let pkh = Crypto.hash160 pubkey in
      let script = build_p2pkh_script pkh in
      let addr = Address.address_to_string {
        addr_type = Address.P2PKH;
        hash = pkh;
        network;
      } in
      Ok [{ script_pubkey = script; script_type = ScriptP2PKH;
            pubkeys = [pubkey]; address = Some addr }]
    end

  | Wpkh key ->
    begin match derive_key_at key index with
    | Error e -> Error e
    | Ok pubkey ->
      let pkh = Crypto.hash160 pubkey in
      let script = build_p2wpkh_script pkh in
      let addr = Address.address_to_string {
        addr_type = Address.P2WPKH;
        hash = pkh;
        network;
      } in
      Ok [{ script_pubkey = script; script_type = ScriptP2WPKH;
            pubkeys = [pubkey]; address = Some addr }]
    end

  | Sh inner ->
    begin match expand inner index network with
    | Error e -> Error e
    | Ok expansions ->
      let results = List.map (fun exp ->
        let script_hash = Crypto.hash160 exp.script_pubkey in
        let script = build_p2sh_script script_hash in
        let addr = Address.address_to_string {
          addr_type = Address.P2SH;
          hash = script_hash;
          network;
        } in
        { script_pubkey = script; script_type = ScriptP2SH;
          pubkeys = exp.pubkeys; address = Some addr }
      ) expansions in
      Ok results
    end

  | Wsh inner ->
    begin match expand inner index network with
    | Error e -> Error e
    | Ok expansions ->
      let results = List.map (fun exp ->
        let script_hash = Crypto.sha256 exp.script_pubkey in
        let script = build_p2wsh_script script_hash in
        let addr = Address.address_to_string {
          addr_type = Address.P2WSH;
          hash = script_hash;
          network;
        } in
        { script_pubkey = script; script_type = ScriptP2WSH;
          pubkeys = exp.pubkeys; address = Some addr }
      ) expansions in
      Ok results
    end

  | Tr (key, tree_opt) ->
    begin match derive_key_at key index with
    | Error e -> Error e
    | Ok pubkey ->
      let xonly = get_xonly_pubkey pubkey in
      (* Compute tweaked output key *)
      let output_key = match tree_opt with
        | None ->
          (* Key-path only: tweak with tagged hash of pubkey *)
          Crypto.compute_taproot_output_key xonly None
        | Some tree ->
          (* Script tree: compute merkle root and tweak *)
          let merkle_root = compute_tap_tree_root tree index network in
          Crypto.compute_taproot_output_key xonly (Some merkle_root)
      in
      let script = build_p2tr_script output_key in
      let addr = Address.address_to_string {
        addr_type = Address.P2TR;
        hash = output_key;
        network;
      } in
      Ok [{ script_pubkey = script; script_type = ScriptP2TR;
            pubkeys = [pubkey]; address = Some addr }]
    end

  | Multi (k, keys) ->
    let pubkeys_result = List.map (fun key -> derive_key_at key index) keys in
    let errors = List.filter_map (function Error e -> Some e | Ok _ -> None) pubkeys_result in
    if List.length errors > 0 then Error (List.hd errors)
    else begin
      let pubkeys = List.filter_map (function Ok pk -> Some pk | Error _ -> None) pubkeys_result in
      let script = build_multisig_script k pubkeys in
      Ok [{ script_pubkey = script; script_type = ScriptMultisig;
            pubkeys; address = None }]
    end

  | SortedMulti (k, keys) ->
    let pubkeys_result = List.map (fun key -> derive_key_at key index) keys in
    let errors = List.filter_map (function Error e -> Some e | Ok _ -> None) pubkeys_result in
    if List.length errors > 0 then Error (List.hd errors)
    else begin
      let pubkeys = List.filter_map (function Ok pk -> Some pk | Error _ -> None) pubkeys_result in
      (* Sort pubkeys lexicographically *)
      let sorted = List.sort (fun a b ->
        Cstruct.compare a b
      ) pubkeys in
      let script = build_multisig_script k sorted in
      Ok [{ script_pubkey = script; script_type = ScriptMultisig;
            pubkeys = sorted; address = None }]
    end

  | Combo key ->
    (* Combo produces P2PK, P2PKH, and (if compressed) P2WPKH and P2SH-P2WPKH *)
    begin match derive_key_at key index with
    | Error e -> Error e
    | Ok pubkey ->
      let is_compressed = Cstruct.length pubkey = 33 in
      let results = ref [] in
      (* P2PK *)
      let pk_script = build_p2pk_script pubkey in
      results := { script_pubkey = pk_script; script_type = ScriptP2PK;
                   pubkeys = [pubkey]; address = None } :: !results;
      (* P2PKH *)
      let pkh = Crypto.hash160 pubkey in
      let pkh_script = build_p2pkh_script pkh in
      let pkh_addr = Address.address_to_string {
        addr_type = Address.P2PKH; hash = pkh; network
      } in
      results := { script_pubkey = pkh_script; script_type = ScriptP2PKH;
                   pubkeys = [pubkey]; address = Some pkh_addr } :: !results;
      if is_compressed then begin
        (* P2WPKH *)
        let wpkh_script = build_p2wpkh_script pkh in
        let wpkh_addr = Address.address_to_string {
          addr_type = Address.P2WPKH; hash = pkh; network
        } in
        results := { script_pubkey = wpkh_script; script_type = ScriptP2WPKH;
                     pubkeys = [pubkey]; address = Some wpkh_addr } :: !results;
        (* P2SH-P2WPKH *)
        let sh_hash = Crypto.hash160 wpkh_script in
        let sh_script = build_p2sh_script sh_hash in
        let sh_addr = Address.address_to_string {
          addr_type = Address.P2SH; hash = sh_hash; network
        } in
        results := { script_pubkey = sh_script; script_type = ScriptP2SH;
                     pubkeys = [pubkey]; address = Some sh_addr } :: !results;
      end;
      Ok (List.rev !results)
    end

  | Addr addr ->
    let script = Address.address_to_script addr in
    let addr_str = Address.address_to_string addr in
    let script_type = match addr.addr_type with
      | Address.P2PKH -> ScriptP2PKH
      | Address.P2SH -> ScriptP2SH
      | Address.P2WPKH -> ScriptP2WPKH
      | Address.P2WSH -> ScriptP2WSH
      | Address.P2TR -> ScriptP2TR
      | Address.WitnessUnknown _ -> ScriptRaw
    in
    Ok [{ script_pubkey = script; script_type;
          pubkeys = []; address = Some addr_str }]

  | Raw script ->
    Ok [{ script_pubkey = script; script_type = ScriptRaw;
          pubkeys = []; address = None }]

(* Compute taproot tree merkle root *)
and compute_tap_tree_root (tree : tap_tree) (index : int) (network : Address.network) : Cstruct.t =
  match tree with
  | TapLeaf (leaf_version, desc) ->
    (* Expand the script *)
    let script = match expand desc index network with
      | Ok [exp] -> exp.script_pubkey
      | _ -> Cstruct.create 0  (* fallback *)
    in
    Crypto.compute_tapleaf_hash leaf_version script
  | TapBranch (left, right) ->
    let left_hash = compute_tap_tree_root left index network in
    let right_hash = compute_tap_tree_root right index network in
    Crypto.compute_tapbranch_hash left_hash right_hash

(* ============================================================================
   Range expansion (deriveaddresses)
   ============================================================================ *)

(* Check if descriptor is ranged (has wildcards) *)
let rec is_ranged (desc : descriptor) : bool =
  let rec key_is_ranged = function
    | ConstPubkey _ | ConstPrivkey _ -> false
    | WithOrigin (_, k) -> key_is_ranged k
    | Xpub { derive; _ } -> derive <> NonRanged
  in
  match desc with
  | Pk k | Pkh k | Wpkh k | Combo k -> key_is_ranged k
  | Tr (k, tree) ->
    key_is_ranged k || (match tree with Some t -> tap_tree_is_ranged t | None -> false)
  | Multi (_, keys) | SortedMulti (_, keys) ->
    List.exists key_is_ranged keys
  | Sh inner | Wsh inner -> is_ranged inner
  | Addr _ | Raw _ -> false

and tap_tree_is_ranged (tree : tap_tree) : bool =
  match tree with
  | TapLeaf (_, desc) -> is_ranged desc
  | TapBranch (left, right) ->
    tap_tree_is_ranged left || tap_tree_is_ranged right

(* Derive addresses for a range of indices *)
let derive_addresses (desc : descriptor) (range : int * int) (network : Address.network)
    : (string list, string) result =
  let (start_idx, end_idx) = range in
  if start_idx < 0 || end_idx < start_idx then
    Error "invalid range"
  else if not (is_ranged desc) && end_idx > start_idx then
    Error "descriptor is not ranged but range has multiple indices"
  else begin
    let addresses = ref [] in
    let error = ref None in
    for i = start_idx to end_idx do
      if Option.is_none !error then
        match expand desc i network with
        | Error e -> error := Some e
        | Ok expansions ->
          List.iter (fun exp ->
            match exp.address with
            | Some addr -> addresses := addr :: !addresses
            | None -> ()
          ) expansions
    done;
    match !error with
    | Some e -> Error e
    | None -> Ok (List.rev !addresses)
  end

(* ============================================================================
   Descriptor to string
   ============================================================================ *)

(* Convert path element to string *)
let path_elem_to_string = function
  | Normal n -> string_of_int n
  | Hardened n -> string_of_int n ^ "'"

(* Convert derivation path to string *)
let path_to_string (path : derivation_path) : string =
  if List.length path = 0 then ""
  else "/" ^ String.concat "/" (List.map path_elem_to_string path)

(* Convert key expression to string *)
let rec key_to_string (key : key_expr) : string =
  match key with
  | ConstPubkey (pk, is_xonly) ->
    if is_xonly then
      cstruct_to_hex (Cstruct.sub pk 1 32)  (* strip prefix for x-only *)
    else
      cstruct_to_hex pk
  | ConstPrivkey _ ->
    "<private>"  (* don't expose private keys *)
  | Xpub { extkey; path; derive; is_private = _ } ->
    let base = Wallet.serialize_xpub extkey in
    let path_str = path_to_string path in
    let wildcard = match derive with
      | NonRanged -> ""
      | UnhardenedRanged -> "/*"
      | HardenedRanged -> "/*'"
    in
    base ^ path_str ^ wildcard
  | WithOrigin (origin, inner) ->
    let fp = Printf.sprintf "%08lx" origin.fingerprint in
    let path = path_to_string origin.origin_path in
    "[" ^ fp ^ path ^ "]" ^ key_to_string inner

(* Convert descriptor to string *)
and to_string (desc : descriptor) : string =
  match desc with
  | Pk key -> "pk(" ^ key_to_string key ^ ")"
  | Pkh key -> "pkh(" ^ key_to_string key ^ ")"
  | Wpkh key -> "wpkh(" ^ key_to_string key ^ ")"
  | Sh inner -> "sh(" ^ to_string inner ^ ")"
  | Wsh inner -> "wsh(" ^ to_string inner ^ ")"
  | Tr (key, None) -> "tr(" ^ key_to_string key ^ ")"
  | Tr (key, Some tree) -> "tr(" ^ key_to_string key ^ "," ^ tap_tree_to_string tree ^ ")"
  | Multi (k, keys) ->
    "multi(" ^ string_of_int k ^ "," ^
    String.concat "," (List.map key_to_string keys) ^ ")"
  | SortedMulti (k, keys) ->
    "sortedmulti(" ^ string_of_int k ^ "," ^
    String.concat "," (List.map key_to_string keys) ^ ")"
  | Combo key -> "combo(" ^ key_to_string key ^ ")"
  | Addr addr -> "addr(" ^ Address.address_to_string addr ^ ")"
  | Raw script -> "raw(" ^ cstruct_to_hex script ^ ")"

and tap_tree_to_string (tree : tap_tree) : string =
  match tree with
  | TapLeaf (_, desc) -> to_string desc
  | TapBranch (left, right) ->
    "{" ^ tap_tree_to_string left ^ "," ^ tap_tree_to_string right ^ "}"

(* ============================================================================
   Descriptor info (getdescriptorinfo)
   ============================================================================ *)

type descriptor_info = {
  descriptor : string;    (* canonical descriptor with checksum *)
  is_range : bool;        (* whether it contains wildcards *)
  is_solvable : bool;     (* whether we can sign for it *)
  has_private_keys : bool;
}

(* Check if descriptor has private keys *)
let rec has_private_keys (desc : descriptor) : bool =
  let rec key_has_private = function
    | ConstPrivkey _ -> true
    | Xpub { is_private; _ } -> is_private
    | WithOrigin (_, k) -> key_has_private k
    | ConstPubkey _ -> false
  in
  match desc with
  | Pk k | Pkh k | Wpkh k | Combo k -> key_has_private k
  | Tr (k, tree) ->
    key_has_private k ||
    (match tree with Some t -> tap_tree_has_private t | None -> false)
  | Multi (_, keys) | SortedMulti (_, keys) ->
    List.exists key_has_private keys
  | Sh inner | Wsh inner -> has_private_keys inner
  | Addr _ | Raw _ -> false

and tap_tree_has_private (tree : tap_tree) : bool =
  match tree with
  | TapLeaf (_, desc) -> has_private_keys desc
  | TapBranch (left, right) ->
    tap_tree_has_private left || tap_tree_has_private right

(* Check if a descriptor is solvable: we know the script structure and have
   sufficient information (keys/scripts) to construct a valid scriptSig/witness
   if private keys were available.  addr() and raw() are not solvable because
   we don't know the underlying script structure. *)
let rec is_solvable (desc : descriptor) : bool =
  match desc with
  | Pk _ | Pkh _ | Wpkh _ | Combo _ -> true
  | Tr _ -> true
  | Multi _ | SortedMulti _ -> true
  | Sh inner | Wsh inner -> is_solvable inner
  | Addr _ | Raw _ -> false

(* Get descriptor info *)
let get_info (desc_str : string) : (descriptor_info, string) result =
  match parse desc_str with
  | Error e -> Error e
  | Ok parsed ->
    let canonical = to_string parsed.desc in
    let with_checksum = match add_checksum canonical with
      | Some s -> s
      | None -> canonical
    in
    let is_range = is_ranged parsed.desc in
    let has_private = has_private_keys parsed.desc in
    Ok {
      descriptor = with_checksum;
      is_range;
      is_solvable = is_solvable parsed.desc;
      has_private_keys = has_private;
    }
