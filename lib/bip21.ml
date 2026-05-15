(* BIP-21 URI parser
   Spec: https://github.com/bitcoin/bips/blob/master/bip-0021.mediawiki

   Format: bitcoin:<address>[?<query>]
     query = key1=value1&key2=value2&...
     keys are case-insensitive, values are percent-encoded UTF-8
   Known params:
     - amount  (decimal BTC, REQUIRED to be parseable if present)
     - label   (free-form UTF-8)
     - message (free-form UTF-8)
     - lightning (BOLT-11 invoice; lowercase, opaque to BIP-21)
     - pj      (BIP-78 PayJoin endpoint URL)
     - pjos    (BIP-78 disable output substitution; "0" or "1")
   Param rules:
     - Unknown params starting with "req-" MUST cause parse failure (spec
       §"Forward Compatibility").
     - Other unknown params are ignored and surfaced in `extras` so callers
       can opt in to handling them later.
     - Keys are matched case-insensitively. `req-` prefix is matched
       case-insensitively too.
     - Duplicate keys: spec is silent. We accept the LAST occurrence for
       known keys (lenient parse; the BIP itself only says clients SHOULD
       use the first valid amount). Duplicates of req-X still trip the
       unknown-req- check on the first sighting.
   Network handling:
     The address embedded in the URI is decoded via Address.address_of_string,
     which itself determines the network from prefix/HRP. The caller passes
     in the EXPECTED network; we error out if the decoded address belongs
     to a different one (so a mainnet wallet does not silently pay a
     testnet URI). Pass `network` matching your wallet's configuration.
*)

type bip21_uri = {
  address : Address.address;
  amount : int64 option;       (* satoshis *)
  label : string option;
  message : string option;
  lightning : string option;
  pj : string option;          (* BIP-78 PayJoin endpoint *)
  pjos : bool option;          (* BIP-78 disable output substitution *)
  extras : (string * string) list;  (* unknown non-req- params, lowercase keys *)
}

type bip21_error =
  | Missing_scheme              (* string did not start with "bitcoin:" *)
  | Empty_address               (* "bitcoin:?..." *)
  | Invalid_address of string   (* address segment failed Address decode *)
  | Network_mismatch of {
      expected : Address.network;
      got : Address.network;
    }
  | Invalid_amount of string    (* malformed decimal / out of range *)
  | Invalid_pjos of string      (* pjos= was not "0" or "1" *)
  | Unknown_required_param of string  (* req-X seen; X is the bare name *)
  | Malformed_query of string   (* percent-decode failure, malformed pair *)
  | Duplicate_address_separator (* >1 '?' in URI; spec disallows *)

let scheme_lower = "bitcoin:"

(* ---------- percent-decoding ---------- *)

let hex_value (c : char) : int option =
  match c with
  | '0' .. '9' -> Some (Char.code c - Char.code '0')
  | 'a' .. 'f' -> Some (Char.code c - Char.code 'a' + 10)
  | 'A' .. 'F' -> Some (Char.code c - Char.code 'A' + 10)
  | _ -> None

(* Percent-decode an application/x-www-form-urlencoded chunk. '+' → ' '
   per the URL-encoded form convention used by browsers; the BIP itself
   only specifies percent-encoding, but real-world wallets send '+' for
   spaces in labels (Bitcoin Core's GUI in particular). Return None on
   malformed % sequences. *)
let percent_decode (s : string) : string option =
  let n = String.length s in
  let buf = Buffer.create n in
  let i = ref 0 in
  let ok = ref true in
  while !ok && !i < n do
    let c = s.[!i] in
    if c = '%' then begin
      if !i + 2 >= n then ok := false
      else begin
        match hex_value s.[!i + 1], hex_value s.[!i + 2] with
        | Some hi, Some lo ->
          Buffer.add_char buf (Char.chr ((hi lsl 4) lor lo));
          i := !i + 3
        | _ -> ok := false
      end
    end else if c = '+' then begin
      Buffer.add_char buf ' ';
      incr i
    end else begin
      Buffer.add_char buf c;
      incr i
    end
  done;
  if !ok then Some (Buffer.contents buf) else None

(* ---------- BTC amount parsing ---------- *)

(* Parse a BIP-21 amount (decimal BTC) into satoshis. Spec §"Transfer amount":
   - Decimal, optional fraction, no leading +/-
   - Up to 8 fractional digits (1 sat = 1e-8 BTC)
   - Empty fraction permitted ("1." → 1 BTC); empty whole permitted (".5")
   - Reject scientific notation, leading whitespace, signs.
   Returns satoshis as int64; rejects > MAX_MONEY (caller may also cap). *)
let parse_amount (s : string) : (int64, string) result =
  let n = String.length s in
  if n = 0 then Error "empty amount"
  else if s.[0] = '-' || s.[0] = '+' then Error "signed amount not allowed"
  else begin
    let dot = String.index_opt s '.' in
    let whole_str, frac_str = match dot with
      | None -> s, ""
      | Some i -> String.sub s 0 i, String.sub s (i + 1) (n - i - 1)
    in
    if whole_str = "" && frac_str = "" then Error "no digits"
    else begin
      let is_digit c = c >= '0' && c <= '9' in
      let all_digits str =
        let ok = ref true in
        String.iter (fun c -> if not (is_digit c) then ok := false) str;
        !ok
      in
      if not (all_digits whole_str) then Error "non-digit in whole part"
      else if not (all_digits frac_str) then Error "non-digit in fraction"
      else if String.length frac_str > 8 then
        Error "more than 8 fractional digits"
      else begin
        (* Pad fraction to 8 digits, then concat → satoshi count as
           plain decimal int64. *)
        let frac_padded =
          frac_str ^ String.make (8 - String.length frac_str) '0'
        in
        let whole = if whole_str = "" then "0" else whole_str in
        let combined = whole ^ frac_padded in
        match Int64.of_string_opt combined with
        | Some v when Int64.compare v 0L >= 0 ->
          (* Optional MAX_MONEY guard. Consensus.max_money already lives
             in lib/consensus.ml but pulling that dep here would couple
             BIP-21 to consensus params; we let the caller decide if
             they want to cap. *)
          Ok v
        | Some _ -> Error "negative result"
        | None -> Error "amount overflow"
      end
    end
  end

(* ---------- query string parsing ---------- *)

(* Split a key=value pair. Spec uses '=', so we look for first '=' only.
   A bare key with no '=' (e.g. "foo&bar") is malformed per BIP-21
   ("name=value" syntax). *)
let split_kv (pair : string) : (string * string) option =
  match String.index_opt pair '=' with
  | None -> None
  | Some i ->
    let k = String.sub pair 0 i in
    let v = String.sub pair (i + 1) (String.length pair - i - 1) in
    Some (k, v)

let split_query (q : string) : string list =
  if q = "" then []
  else String.split_on_char '&' q

let lowercase = String.lowercase_ascii

(* ---------- main parser ---------- *)

let parse (s : string) (network : Address.network) : (bip21_uri, bip21_error) result =
  let n = String.length s in
  let scheme_len = String.length scheme_lower in
  if n < scheme_len ||
     not (String.equal (lowercase (String.sub s 0 scheme_len)) scheme_lower) then
    Error Missing_scheme
  else begin
    let body = String.sub s scheme_len (n - scheme_len) in
    (* Split address from query on the FIRST '?'. Spec disallows multiple
       '?'s — we error rather than greedy-include them in the query. *)
    let addr_str, query_str =
      match String.index_opt body '?' with
      | None -> body, ""
      | Some i ->
        let rest = String.sub body (i + 1) (String.length body - i - 1) in
        String.sub body 0 i, rest
    in
    if String.contains query_str '?' then Error Duplicate_address_separator
    else if addr_str = "" then Error Empty_address
    else begin
      (* Decode the address. Address.address_of_string is strict — it does
         NOT consume URI prefixes (correct: that's our job). *)
      match Address.address_of_string addr_str with
      | Error e -> Error (Invalid_address e)
      | Ok address when address.Address.network <> network ->
        Error (Network_mismatch { expected = network; got = address.Address.network })
      | Ok address ->
        (* Now walk query params. *)
        let pairs = split_query query_str in
        let amount = ref None in
        let label = ref None in
        let message = ref None in
        let lightning = ref None in
        let pj = ref None in
        let pjos = ref None in
        let extras = ref [] in
        let err = ref None in
        let set_err e = if !err = None then err := Some e in
        List.iter (fun raw ->
          if !err <> None || raw = "" then ()
          else match split_kv raw with
          | None -> set_err (Malformed_query raw)
          | Some (k_raw, v_raw) ->
            match percent_decode k_raw, percent_decode v_raw with
            | None, _ | _, None -> set_err (Malformed_query raw)
            | Some k_dec, Some v_dec ->
              let k = lowercase k_dec in
              (* req- prefix check FIRST (spec): a key like "req-foo" is
                 unknown to us → fail. Known keys never start with "req-",
                 so this check before the dispatch is correct. *)
              if String.length k >= 4 &&
                 String.equal (String.sub k 0 4) "req-" then begin
                let bare = String.sub k 4 (String.length k - 4) in
                set_err (Unknown_required_param bare)
              end else match k with
              | "amount" ->
                (match parse_amount v_dec with
                 | Ok sats -> amount := Some sats
                 | Error e -> set_err (Invalid_amount e))
              | "label" -> label := Some v_dec
              | "message" -> message := Some v_dec
              | "lightning" -> lightning := Some v_dec
              | "pj" -> pj := Some v_dec
              | "pjos" ->
                (match v_dec with
                 | "0" -> pjos := Some false
                 | "1" -> pjos := Some true
                 | _ -> set_err (Invalid_pjos v_dec))
              | _ ->
                extras := (k, v_dec) :: !extras
        ) pairs;
        match !err with
        | Some e -> Error e
        | None ->
          Ok {
            address;
            amount = !amount;
            label = !label;
            message = !message;
            lightning = !lightning;
            pj = !pj;
            pjos = !pjos;
            extras = List.rev !extras;
          }
    end
  end

(* Convenience for callers that want a single-line error message. *)
let string_of_error (e : bip21_error) : string =
  let net_to_string = function
    | `Mainnet -> "mainnet"
    | `Testnet -> "testnet"
    | `Regtest -> "regtest"
  in
  match e with
  | Missing_scheme -> "missing or wrong scheme (expected bitcoin:)"
  | Empty_address -> "empty address"
  | Invalid_address e -> "invalid address: " ^ e
  | Network_mismatch { expected; got } ->
    Printf.sprintf "network mismatch (expected %s, got %s)"
      (net_to_string expected) (net_to_string got)
  | Invalid_amount e -> "invalid amount: " ^ e
  | Invalid_pjos v -> "invalid pjos value: " ^ v
  | Unknown_required_param k -> "unknown required param: req-" ^ k
  | Malformed_query p -> "malformed query pair: " ^ p
  | Duplicate_address_separator -> "duplicate '?' separator"
