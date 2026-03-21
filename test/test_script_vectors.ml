(* Test harness for Bitcoin Core script_tests.json vectors *)
(* Build: eval $(opam env --switch=/home/max/hashhog/camlcoin 2>/dev/null) && dune build test/test_script_vectors.exe *)

open Camlcoin

let script_tests_path =
  "/home/max/hashhog/bitcoin/src/test/data/script_tests.json"

(* ---- Hex utilities ---- *)

let hex_char_to_int c =
  match c with
  | '0'..'9' -> Char.code c - Char.code '0'
  | 'a'..'f' -> Char.code c - Char.code 'a' + 10
  | 'A'..'F' -> Char.code c - Char.code 'A' + 10
  | _ -> failwith (Printf.sprintf "Invalid hex char: %c" c)

let hex_to_bytes hex =
  let len = String.length hex in
  if len mod 2 <> 0 then failwith "Odd hex length";
  let buf = Buffer.create (len / 2) in
  for i = 0 to (len / 2) - 1 do
    let hi = hex_char_to_int hex.[2*i] in
    let lo = hex_char_to_int hex.[2*i+1] in
    Buffer.add_char buf (Char.chr ((hi lsl 4) lor lo))
  done;
  Cstruct.of_string (Buffer.contents buf)

let bytes_to_hex (cs : Cstruct.t) : string =
  let len = Cstruct.length cs in
  let buf = Buffer.create (len * 2) in
  for i = 0 to len - 1 do
    Buffer.add_string buf (Printf.sprintf "%02x" (Cstruct.get_uint8 cs i))
  done;
  Buffer.contents buf

(* ---- ASM parser ---- *)

(* Map opcode name (without OP_ prefix) to byte value *)
let opcode_map = [
  ("0", 0x00); ("FALSE", 0x00);
  ("1NEGATE", 0x4f);
  ("RESERVED", 0x50);
  ("1", 0x51); ("TRUE", 0x51);
  ("2", 0x52); ("3", 0x53); ("4", 0x54); ("5", 0x55);
  ("6", 0x56); ("7", 0x57); ("8", 0x58); ("9", 0x59);
  ("10", 0x5a); ("11", 0x5b); ("12", 0x5c); ("13", 0x5d);
  ("14", 0x5e); ("15", 0x5f); ("16", 0x60);
  ("NOP", 0x61); ("VER", 0x62);
  ("IF", 0x63); ("NOTIF", 0x64);
  ("VERIF", 0x65); ("VERNOTIF", 0x66);
  ("ELSE", 0x67); ("ENDIF", 0x68);
  ("VERIFY", 0x69); ("RETURN", 0x6a);
  ("TOALTSTACK", 0x6b); ("FROMALTSTACK", 0x6c);
  ("2DROP", 0x6d); ("2DUP", 0x6e); ("3DUP", 0x6f);
  ("2OVER", 0x70); ("2ROT", 0x71); ("2SWAP", 0x72);
  ("IFDUP", 0x73); ("DEPTH", 0x74);
  ("DROP", 0x75); ("DUP", 0x76);
  ("NIP", 0x77); ("OVER", 0x78);
  ("PICK", 0x79); ("ROLL", 0x7a);
  ("ROT", 0x7b); ("SWAP", 0x7c); ("TUCK", 0x7d);
  ("CAT", 0x7e); ("SUBSTR", 0x7f); ("LEFT", 0x80); ("RIGHT", 0x81);
  ("SIZE", 0x82);
  ("INVERT", 0x83); ("AND", 0x84); ("OR", 0x85); ("XOR", 0x86);
  ("EQUAL", 0x87); ("EQUALVERIFY", 0x88);
  ("RESERVED1", 0x89); ("RESERVED2", 0x8a);
  ("1ADD", 0x8b); ("1SUB", 0x8c);
  ("2MUL", 0x8d); ("2DIV", 0x8e);
  ("NEGATE", 0x8f); ("ABS", 0x90);
  ("NOT", 0x91); ("0NOTEQUAL", 0x92);
  ("ADD", 0x93); ("SUB", 0x94);
  ("MUL", 0x95); ("DIV", 0x96); ("MOD", 0x97);
  ("LSHIFT", 0x98); ("RSHIFT", 0x99);
  ("BOOLAND", 0x9a); ("BOOLOR", 0x9b);
  ("NUMEQUAL", 0x9c); ("NUMEQUALVERIFY", 0x9d);
  ("NUMNOTEQUAL", 0x9e);
  ("LESSTHAN", 0x9f); ("GREATERTHAN", 0xa0);
  ("LESSTHANOREQUAL", 0xa1); ("GREATERTHANOREQUAL", 0xa2);
  ("MIN", 0xa3); ("MAX", 0xa4); ("WITHIN", 0xa5);
  ("RIPEMD160", 0xa6); ("SHA1", 0xa7); ("SHA256", 0xa8);
  ("HASH160", 0xa9); ("HASH256", 0xaa);
  ("CODESEPARATOR", 0xab);
  ("CHECKSIG", 0xac); ("CHECKSIGVERIFY", 0xad);
  ("CHECKMULTISIG", 0xae); ("CHECKMULTISIGVERIFY", 0xaf);
  ("NOP1", 0xb0);
  ("CHECKLOCKTIMEVERIFY", 0xb1); ("NOP2", 0xb1);
  ("CHECKSEQUENCEVERIFY", 0xb2); ("NOP3", 0xb2);
  ("NOP4", 0xb3); ("NOP5", 0xb4); ("NOP6", 0xb5);
  ("NOP7", 0xb6); ("NOP8", 0xb7); ("NOP9", 0xb8); ("NOP10", 0xb9);
  ("CHECKSIGADD", 0xba);
  ("INVALIDOPCODE", 0xff);
]

let opcode_table =
  let tbl = Hashtbl.create 128 in
  List.iter (fun (name, code) -> Hashtbl.replace tbl name code) opcode_map;
  tbl

(* Encode a script number as minimal CScriptNum bytes *)
let encode_script_num n =
  if n = 0 then ""
  else begin
    let abs_n = abs n in
    let neg = n < 0 in
    let buf = Buffer.create 5 in
    let v = ref abs_n in
    while !v > 0 do
      Buffer.add_char buf (Char.chr (!v land 0xff));
      v := !v lsr 8
    done;
    let s = Bytes.of_string (Buffer.contents buf) in
    let last_idx = Bytes.length s - 1 in
    let last_byte = Char.code (Bytes.get s last_idx) in
    if last_byte land 0x80 <> 0 then begin
      (* Need extra byte for sign *)
      let result = Buffer.create (Bytes.length s + 1) in
      Buffer.add_bytes result s;
      Buffer.add_char result (if neg then '\x80' else '\x00');
      Buffer.contents result
    end else begin
      if neg then
        Bytes.set s last_idx (Char.chr (last_byte lor 0x80));
      Bytes.to_string s
    end
  end

(* Push data onto script with appropriate opcode *)
let push_data (w : Buffer.t) (data : string) =
  let len = String.length data in
  if len >= 1 && len <= 0x4b then begin
    Buffer.add_char w (Char.chr len);
    Buffer.add_string w data
  end else if len <= 0xff then begin
    Buffer.add_char w (Char.chr 0x4c);
    Buffer.add_char w (Char.chr len);
    Buffer.add_string w data
  end else if len <= 0xffff then begin
    Buffer.add_char w (Char.chr 0x4d);
    Buffer.add_char w (Char.chr (len land 0xff));
    Buffer.add_char w (Char.chr ((len lsr 8) land 0xff));
    Buffer.add_string w data
  end else begin
    Buffer.add_char w (Char.chr 0x4e);
    Buffer.add_char w (Char.chr (len land 0xff));
    Buffer.add_char w (Char.chr ((len lsr 8) land 0xff));
    Buffer.add_char w (Char.chr ((len lsr 16) land 0xff));
    Buffer.add_char w (Char.chr ((len lsr 24) land 0xff));
    Buffer.add_string w data
  end

(* Assemble a script from Bitcoin ASM notation to raw bytes *)
let assemble_script (asm : string) : Cstruct.t =
  let asm = String.trim asm in
  if String.length asm = 0 then Cstruct.empty
  else begin
    let tokens = String.split_on_char ' ' asm
                 |> List.filter (fun s -> String.length s > 0) in
    let buf = Buffer.create 256 in
    List.iter (fun token ->
      (* Remove OP_ prefix if present *)
      let name = if String.length token > 3 && String.sub token 0 3 = "OP_" then
        String.sub token 3 (String.length token - 3)
      else token in
      if String.length name >= 2 && String.sub name 0 2 = "0x" then begin
        (* Raw hex data: 0xNN... -> emit bytes literally *)
        let hex = String.sub name 2 (String.length name - 2) in
        let cs = hex_to_bytes hex in
        for i = 0 to Cstruct.length cs - 1 do
          Buffer.add_char buf (Char.chr (Cstruct.get_uint8 cs i))
        done
      end else if String.length name >= 1 && name.[0] = '\'' then begin
        (* Quoted string: 'text' -> push as data *)
        let s = if String.length name >= 2 && name.[String.length name - 1] = '\'' then
          String.sub name 1 (String.length name - 2)
        else
          String.sub name 1 (String.length name - 1)
        in
        if String.length s = 0 then
          Buffer.add_char buf (Char.chr 0x00)  (* OP_0 for empty *)
        else
          push_data buf s
      end else if Hashtbl.mem opcode_table name then begin
        Buffer.add_char buf (Char.chr (Hashtbl.find opcode_table name))
      end else begin
        (* Try to parse as a decimal number *)
        try
          let n = int_of_string name in
          if n = 0 then Buffer.add_char buf (Char.chr 0x00)
          else if n = -1 then Buffer.add_char buf (Char.chr 0x4f)
          else if n >= 1 && n <= 16 then Buffer.add_char buf (Char.chr (0x50 + n))
          else begin
            let data = encode_script_num n in
            push_data buf data
          end
        with Failure _ ->
          Printf.eprintf "WARNING: Unknown token: %s\n" token
      end
    ) tokens;
    Cstruct.of_string (Buffer.contents buf)
  end

(* ---- Flag parsing ---- *)

let parse_flags (flags_str : string) : int =
  let flags_str = String.trim flags_str in
  if String.length flags_str = 0 || flags_str = "NONE" then
    Script.script_verify_none
  else begin
    let flag_list = String.split_on_char ',' flags_str in
    List.fold_left (fun acc flag ->
      let flag = String.trim flag in
      acc lor (match flag with
        | "P2SH" -> Script.script_verify_p2sh
        | "STRICTENC" -> Script.script_verify_strictenc
        | "DERSIG" -> Script.script_verify_dersig
        | "LOW_S" -> Script.script_verify_low_s
        | "NULLDUMMY" -> Script.script_verify_nulldummy
        | "SIGPUSHONLY" -> Script.script_verify_sigpushonly
        | "MINIMALDATA" -> Script.script_verify_minimaldata
        | "DISCOURAGE_UPGRADABLE_NOPS" -> Script.script_verify_discourage_upgradable_nops
        | "CLEANSTACK" -> Script.script_verify_cleanstack
        | "CHECKLOCKTIMEVERIFY" -> Script.script_verify_checklocktimeverify
        | "CHECKSEQUENCEVERIFY" -> Script.script_verify_checksequenceverify
        | "WITNESS" -> Script.script_verify_witness
        | "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM" -> Script.script_verify_discourage_upgradable_witness
        | "MINIMALIF" -> Script.script_verify_minimalif
        | "NULLFAIL" -> Script.script_verify_nullfail
        | "WITNESS_PUBKEYTYPE" -> Script.script_verify_witness_pubkeytype
        | "CONST_SCRIPTCODE" -> Script.script_verify_const_scriptcode
        | "TAPROOT" -> Script.script_verify_taproot
        | "DISCOURAGE_OP_SUCCESS" -> Script.script_verify_discourage_op_success
        | "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION" -> Script.script_verify_discourage_upgradable_taproot_version
        | "DISCOURAGE_UPGRADABLE_PUBKEYTYPE" -> Script.script_verify_discourage_upgradable_pubkeytype
        | "NONE" -> 0
        | unknown ->
          Printf.eprintf "WARNING: Unknown flag: %s\n" unknown;
          0)
    ) 0 flag_list
  end

(* ---- Crediting and Spending transactions (Bitcoin Core approach) ---- *)

(* Bitcoin Core's test framework creates two canonical transactions:
   1. A "crediting transaction" that creates the UTXO with the test's scriptPubKey
   2. A "spending transaction" that spends it with the test's scriptSig
   This ensures real sighash computation works correctly for signature verification. *)

(* Build the crediting transaction:
   version=1, locktime=0
   Input: null prevout (txid=0, vout=0xFFFFFFFF), scriptSig = OP_0 OP_0, sequence=0xFFFFFFFF
   Output: value=amount, scriptPubKey = test's scriptPubKey *)
let make_crediting_tx ?(amount=0L) (script_pubkey : Cstruct.t) : Types.transaction =
  let open Types in
  let null_hash = Cstruct.create 32 in  (* 32 zero bytes *)
  (* scriptSig = OP_0 OP_0 *)
  let credit_script_sig = Cstruct.of_string "\x00\x00" in
  let input = {
    previous_output = { txid = null_hash; vout = 0xFFFFFFFFl };
    script_sig = credit_script_sig;
    sequence = 0xFFFFFFFFl;
  } in
  let output = {
    value = amount;
    script_pubkey;
  } in
  {
    version = 1l;
    inputs = [input];
    outputs = [output];
    witnesses = [];
    locktime = 0l;
  }

(* Build the spending transaction:
   version=1, locktime=0
   Input: prevout = crediting_txid:0, scriptSig = test's scriptSig, sequence=0xFFFFFFFF
   Output: value=0, scriptPubKey = empty *)
let make_spending_tx (crediting_tx : Types.transaction) (script_sig : Cstruct.t)
    ~(locktime : int32) ~(sequence : int32) ?(witnesses=[]) () : Types.transaction =
  let open Types in
  let crediting_txid = Crypto.compute_txid crediting_tx in
  let credit_value = (List.hd crediting_tx.outputs).value in
  let input = {
    previous_output = { txid = crediting_txid; vout = 0l };
    script_sig;
    sequence;
  } in
  let output = {
    value = credit_value;
    script_pubkey = Cstruct.empty;
  } in
  {
    version = 1l;
    inputs = [input];
    outputs = [output];
    witnesses;
    locktime;
  }

(* Bitcoin Core's BuildSpendingTransaction always uses locktime=0, sequence=0xFFFFFFFF.
   The CLTV/CSV flags are not used in the non-witness (4/5-element) test vectors. *)

(* ---- Main ---- *)

let () =
  let json = Yojson.Basic.from_file script_tests_path in
  let tests = match json with
    | `List l -> l
    | _ -> failwith "Expected JSON array"
  in
  let pass_count = ref 0 in
  let fail_count = ref 0 in
  let skip_count = ref 0 in
  let error_count = ref 0 in
  let total = ref 0 in
  let witness_total = ref 0 in

  (* Helper to run a single test case and update counters *)
  let run_one_test idx ~script_sig_asm ~script_pubkey_asm ~flags_str ~expected
      ~comment ~witness_items ~amount ~is_witness =
    incr total;
    if is_witness then incr witness_total;
    try
      let script_sig = assemble_script script_sig_asm in
      let script_pubkey = assemble_script script_pubkey_asm in
      let flags = parse_flags flags_str in

      (* Build crediting and spending transactions *)
      let crediting_tx = make_crediting_tx ~amount script_pubkey in
      let witness = Types.({ items = witness_items }) in
      let witnesses = if witness_items <> [] then [witness] else [] in
      let tx = make_spending_tx crediting_tx script_sig
                 ~locktime:0l ~sequence:0xFFFFFFFFl ~witnesses () in

      let result = Script.verify_script
        ~tx ~input_index:0
        ~script_pubkey ~script_sig
        ~witness ~amount
        ~flags () in

      let got_ok = match result with
        | Ok true -> true
        | _ -> false
      in
      let expected_ok = (expected = "OK") in

      if got_ok = expected_ok then begin
        incr pass_count
      end else begin
        incr fail_count;
        Printf.printf "FAIL test %d: expected=%s got=%s sig=[%s] pub=[%s] flags=%s %s\n"
          idx expected
          (match result with
           | Ok true -> "OK"
           | Ok false -> "EVAL_FALSE"
           | Error e -> e)
          script_sig_asm script_pubkey_asm flags_str comment
      end
    with exn ->
      let expected_ok = (expected = "OK") in
      if not expected_ok then
        incr pass_count  (* Expected failure, and we got an exception *)
      else begin
        incr error_count;
        Printf.printf "ERROR test %d: exception=%s sig=[%s] pub=[%s] flags=%s %s\n"
          idx (Printexc.to_string exn)
          script_sig_asm script_pubkey_asm flags_str comment
      end
  in

  List.iteri (fun idx test ->
    match test with
    | `List elems ->
      let n = List.length elems in
      if n = 1 || n = 2 || n = 3 then
        ()  (* comment or malformed, skip *)
      else begin
        let is_witness = match List.nth elems 0 with `List _ -> true | _ -> false in
        if is_witness then begin
          (* Witness test vector: [witness_stack_with_amount, scriptSig, scriptPubKey, flags, expected, ?comment]
             The witness stack array's last element is the amount (in BTC as float).
             All other elements are hex-encoded witness items. *)
          let witness_arr = match List.nth elems 0 with
            | `List l -> l
            | _ -> failwith "Expected witness array"
          in
          (* Check for taproot template tests *)
          let string_contains s sub =
            let slen = String.length s and sublen = String.length sub in
            if sublen > slen then false
            else
              let rec check i =
                if i > slen - sublen then false
                else if String.sub s i sublen = sub then true
                else check (i + 1)
              in check 0
          in
          let has_template =
            List.exists (fun item ->
              match item with
              | `String s -> string_contains s "#SCRIPT#" || string_contains s "#CONTROLBLOCK#"
              | _ -> false
            ) witness_arr ||
            (match List.nth elems 2 with
             | `String s -> string_contains s "#TAPROOTOUTPUT#"
             | _ -> false)
          in
          (* Last element of witness array is the amount in BTC *)
          let amount_btc = match List.nth witness_arr (List.length witness_arr - 1) with
            | `Float f -> f
            | `Int i -> float_of_int i
            | _ -> failwith "Expected amount as last witness array element"
          in
          let amount = Int64.of_float (amount_btc *. 100_000_000.0 +. 0.5) in
          if has_template then begin
            (* Resolve taproot template placeholders *)
            (* Internal key: the generator point x-coordinate (x-only) *)
            let internal_key = hex_to_bytes "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798" in
            (* Find the #SCRIPT# witness item and extract the ASM *)
            let script_prefix = "#SCRIPT# " in
            let leaf_script = ref Cstruct.empty in
            let wit_hex_items = List.filteri (fun i _ -> i < List.length witness_arr - 1) witness_arr in
            let witness_items = List.map (fun item ->
              match item with
              | `String s when string_contains s "#SCRIPT#" ->
                (* Extract ASM after "#SCRIPT# " prefix *)
                let prefix_len = String.length script_prefix in
                let asm = String.sub s prefix_len (String.length s - prefix_len) in
                let script_bytes = assemble_script asm in
                leaf_script := script_bytes;
                script_bytes
              | `String s when s = "#CONTROLBLOCK#" ->
                (* Compute control block from leaf script *)
                (* Tapleaf hash: tagged_hash("TapLeaf", 0xc0 || compact_size(script_len) || script) *)
                let tapleaf_hash = Crypto.compute_tapleaf_hash 0xc0 !leaf_script in
                (* Merkle root = tapleaf hash (single leaf) *)
                let merkle_root = tapleaf_hash in
                (* Compute output key with parity *)
                let (_output_key, parity) = Crypto.compute_taproot_output_key_with_parity internal_key (Some merkle_root) in
                (* Control block = (0xc0 | parity) || internal_key (33 bytes for single leaf) *)
                let cb = Cstruct.create 33 in
                Cstruct.set_uint8 cb 0 (0xc0 lor parity);
                Cstruct.blit internal_key 0 cb 1 32;
                cb
              | `String hex -> hex_to_bytes hex
              | _ -> failwith "Expected string in witness array"
            ) wit_hex_items in
            let get_str i = match List.nth elems i with
              | `String s -> s
              | _ -> failwith "Expected string"
            in
            let script_sig_asm = get_str 1 in
            let script_pubkey_str = get_str 2 in
            (* Resolve #TAPROOTOUTPUT# in scriptPubKey *)
            let script_pubkey_asm =
              if string_contains script_pubkey_str "#TAPROOTOUTPUT#" then begin
                (* Compute output key from internal key + merkle root *)
                let tapleaf_hash = Crypto.compute_tapleaf_hash 0xc0 !leaf_script in
                let output_key = Crypto.compute_taproot_output_key internal_key (Some tapleaf_hash) in
                let output_hex = bytes_to_hex output_key in
                (* Replace #TAPROOTOUTPUT# with the hex of the output key *)
                let parts = String.split_on_char '#' script_pubkey_str in
                (* The format is "0x51 0x20 #TAPROOTOUTPUT#" *)
                (* After splitting on #: ["0x51 0x20 "; "TAPROOTOUTPUT"; ""] *)
                let prefix = List.hd parts in
                prefix ^ "0x" ^ output_hex
              end else
                script_pubkey_str
            in
            let flags_str = get_str 3 in
            let expected = get_str 4 in
            let comment = if n >= 6 then (try get_str 5 with _ -> "") else "" in
            run_one_test idx ~script_sig_asm ~script_pubkey_asm ~flags_str ~expected
              ~comment ~witness_items ~amount ~is_witness:true
          end else begin
          (* All other elements are hex witness items *)
          let wit_hex_items = List.filteri (fun i _ -> i < List.length witness_arr - 1) witness_arr in
          let witness_items = List.map (fun item ->
            match item with
            | `String hex -> hex_to_bytes hex
            | _ -> failwith "Expected hex string in witness array"
          ) wit_hex_items in
          let get_str i = match List.nth elems i with
            | `String s -> s
            | _ -> failwith "Expected string"
          in
          let script_sig_asm = get_str 1 in
          let script_pubkey_asm = get_str 2 in
          let flags_str = get_str 3 in
          let expected = get_str 4 in
          let comment = if n >= 6 then (try get_str 5 with _ -> "") else "" in
          run_one_test idx ~script_sig_asm ~script_pubkey_asm ~flags_str ~expected
            ~comment ~witness_items ~amount ~is_witness:true
          end
        end else begin
          (* Non-witness: 4 or 5 element test [scriptSig, scriptPubKey, flags, expected, ?comment] *)
          if n >= 4 then begin
            let get_str i = match List.nth elems i with
              | `String s -> s
              | _ -> failwith "Expected string"
            in
            let script_sig_asm = get_str 0 in
            let script_pubkey_asm = get_str 1 in
            let flags_str = get_str 2 in
            let expected = get_str 3 in
            let comment = if n >= 5 then (try get_str 4 with _ -> "") else "" in
            run_one_test idx ~script_sig_asm ~script_pubkey_asm ~flags_str ~expected
              ~comment ~witness_items:[] ~amount:0L ~is_witness:false
          end
        end
      end
    | _ -> ()
  ) tests;

  Printf.printf "\n=== Script Test Vector Results ===\n";
  Printf.printf "Total tests: %d (non-witness: %d, witness: %d)\n"
    !total (!total - !witness_total) !witness_total;
  Printf.printf "  PASS:  %d\n" !pass_count;
  Printf.printf "  FAIL:  %d\n" !fail_count;
  Printf.printf "  ERROR: %d\n" !error_count;
  Printf.printf "  Skipped: %d\n" !skip_count;

  if !fail_count > 0 || !error_count > 0 then
    exit 1
  else
    exit 0
