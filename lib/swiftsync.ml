(* `camlcoin swiftsync-pass` -- a fully-validating SwiftSync batch pass.

   Hashhog meta-repo design: receipts/swiftsync-design-2026-10-05.md
   (§1.2 protocol P, §2 soundness, §2.4 controls, §3 "How nodes consume it"),
   ratified as TRUST-ANCHOR "SwiftSync-verified" (2026-10-05); draft BIP 457.
   The reference driver is rustoshi's `swiftsync-pass` (receipts/
   swiftsync-step2-rustoshi-2026-10-07.md): same pack readers, same coin hash,
   same result.json contract, same controls, so tools/swiftsync-run.py,
   swiftsync-combine.py and swiftsync-close.py consume this output unchanged.

   The pass validates a height range WITHOUT a UTXO set.  Spent coins come
   from Bitcoin Core's undo data (undo.pack, untrusted); which outputs survive
   comes from a hints file (untrusted).  Both are bound to camlcoin's own parse
   of the chain by a salted 256-bit additive hash aggregate:

     Agg_in  = sum H(salt | code | amount | script | prevout)   every input
     Agg_out = sum H(salt | code | amount | script | outpoint)  every created,
               spendable, NOT-hinted output

   Hinted outputs go to a spill (TxOutSer records); the close tool requires
   Agg_in = Agg_out, scripts_run = sum(inputs) and the spill's
   hash_serialized_3 = the commitment.

   PATH IDENTITY -- camlcoin's production connect, with supplied coins.
   Every block goes through exactly the calls of the live IBD connect loop
   (Sync.process_downloaded_blocks, sync.ml), with the arguments built by the
   same Sync functions over a chain_state whose header table was filled by
   the production header acceptance (Sync.validate_header + accept_header):

     Sync.resolve_expected_bits / Sync.resolve_mtp_hash_linked   (the `pre`)
     Sync.get_prev_block_time, Sync.checked_coin_mtp_lookup,
     Consensus.get_block_script_flags ~block_hash, Sync.bip34_height_hash_for
     Validation.accept_block ~skip_scripts:false ?prefetch_base
       -> validate_block_with_utxos, FULL path (the `else` branch: check_block,
          BIP30 probe, sigops cost, IsFinalTx/BIP113, maturity, MoneyRange,
          BIP68, fees, then run_script_checks over every input, subsidy)

   The only differences from production are where the inputs come from: the
   base_lookup serves THIS block's undo coins created below h (instead of the
   UTXO cache), and the chain_state is a scratch one built from the blk files.
   skip_scripts is the literal false (assumevalid never consulted), so the
   FAST path (skip_scripts=true, validation.ml) cannot run; the `fast-path`
   control runs it on purpose so a receipt can show the two are told apart.

   scripts_run is counted by Validation.job_fault_hook, the hook run_one_job
   calls before every script check (production leaves it None), so it counts
   inputs handed to the node's script checker, signature-cache hits included.

   The three mandatory soundness extensions (TRUST-ANCHOR ruling 1):
   - P-ORD: a supplied coin's height must be < h, or = h with the prevout
     created by an EARLIER tx of this block with identical data;
   - completeness: every height of the range processed exactly once;
   - BIP30: coinbase outputs of 91722 and 91812 unspendable, coinbase txids
     below BIP34 unique (Consensus.is_bip30_repeat exemptions); the txids are
     written out so swiftsync-combine.py checks uniqueness ACROSS ranges.

   Parallelism: D validation domains per process claim heights from an atomic
   cursor (out of order); each keeps its own partial aggregates, merged mod
   2^256 at the end.  Ranges sharing one salt compose; a range given
   --start-snapshot (the set at from-1) is standalone. *)

let bip30_overwritten_mainnet = [ 91_722; 91_812 ]
let max_script_size = 10_000

exception Stop

(* ------------------------------------------------------------------------ *)
(* little-endian helpers                                                     *)
(* ------------------------------------------------------------------------ *)

let u32_at (s : string) (o : int) : int =
  Char.code s.[o]
  lor (Char.code s.[o + 1] lsl 8)
  lor (Char.code s.[o + 2] lsl 16)
  lor (Char.code s.[o + 3] lsl 24)

let u64_at (s : string) (o : int) : int = u32_at s o lor (u32_at s (o + 4) lsl 32)

let le32 (n : int) : string =
  let b = Bytes.create 4 in
  Bytes.set_int32_le b 0 (Int32.of_int (n land 0xffffffff));
  Bytes.unsafe_to_string b

let hex_of_string (s : string) : string =
  String.concat "" (List.init (String.length s) (fun i -> Printf.sprintf "%02x" (Char.code s.[i])))

let display_hex (s : string) : string =
  let n = String.length s in
  String.concat "" (List.init n (fun i -> Printf.sprintf "%02x" (Char.code s.[n - 1 - i])))

let string_of_hex (h : string) : string =
  let h = String.trim h in
  if String.length h mod 2 <> 0 then failwith "odd hex";
  String.init (String.length h / 2) (fun i -> Char.chr (int_of_string ("0x" ^ String.sub h (2 * i) 2)))

let read_file (p : string) : string = In_channel.with_open_bin p In_channel.input_all

let add_compact_size (b : Buffer.t) (n : int) : unit =
  if n < 0xfd then Buffer.add_uint8 b n
  else if n <= 0xffff then (Buffer.add_uint8 b 0xfd; Buffer.add_uint16_le b n)
  else if n <= 0xffffffff then (Buffer.add_uint8 b 0xfe; Buffer.add_int32_le b (Int32.of_int n))
  else (Buffer.add_uint8 b 0xff; Buffer.add_int64_le b (Int64.of_int n))

(* ------------------------------------------------------------------------ *)
(* controls (in-memory mutations; nothing on disk is modified)              *)
(* ------------------------------------------------------------------------ *)

type controls = {
  field : (string * int * string) option;  (* field, height, coin class *)
  hint_drop : int option;
  hint_add : int option;
  drop_block : int option;
  dup_block : int option;
  forge_order : int option;
  drop_coin : int option;
  no_pord : bool;
  bip30_spendable : bool;
  bip30_noexempt : bool;
  fast_path : bool;  (* run the assumevalid FAST path (skip_scripts=true): instrument check *)
}

let no_controls = {
  field = None; hint_drop = None; hint_add = None; drop_block = None; dup_block = None;
  forge_order = None; drop_coin = None; no_pord = false; bip30_spendable = false;
  bip30_noexempt = false; fast_path = false;
}

let parse_controls (s : string) : controls =
  List.fold_left (fun c part ->
    if part = "" then c else
    let name, arg =
      match String.index_opt part '@' with
      | Some i ->
        (String.sub part 0 i, Some (int_of_string (String.sub part (i + 1) (String.length part - i - 1))))
      | None -> (part, None)
    in
    let need () = match arg with Some a -> a | None -> failwith (name ^ " needs @HEIGHT") in
    if String.length name > 6 && String.sub name 0 6 = "field:" then begin
      let rest = String.sub name 6 (String.length name - 6) in
      let f, cls =
        match String.index_opt rest '/' with
        | Some i -> (String.sub rest 0 i, String.sub rest (i + 1) (String.length rest - i - 1))
        | None -> (rest, "p2pkh")
      in
      if not (List.mem f [ "amount"; "script"; "height"; "coinbase"; "vout" ]) then failwith ("unknown field " ^ f);
      if not (List.mem cls [ "p2pkh"; "p2wpkh"; "p2pk" ]) then failwith ("unknown coin class " ^ cls);
      { c with field = Some (f, need (), cls) }
    end else
      match name with
      | "hint-drop" -> { c with hint_drop = Some (need ()) }
      | "hint-add" -> { c with hint_add = Some (need ()) }
      | "drop-block" -> { c with drop_block = Some (need ()) }
      | "dup-block" -> { c with dup_block = Some (need ()) }
      | "forge-order" -> { c with forge_order = Some (need ()) }
      | "drop-coin" -> { c with drop_coin = Some (need ()) }
      | "no-pord" -> { c with no_pord = true }
      | "bip30-spendable" -> { c with bip30_spendable = true }
      | "bip30-noexempt" -> { c with bip30_noexempt = true }
      | "fast-path" -> { c with fast_path = true }
      | _ -> failwith ("unknown control " ^ name))
    no_controls (String.split_on_char ',' s)

(* ------------------------------------------------------------------------ *)
(* pack readers (formats: tools/swiftsync-gen.py docstring)                  *)
(* ------------------------------------------------------------------------ *)

type pack = {
  ph : int;              (* pack height H *)
  xor : string;          (* 8-byte blk XOR key *)
  base : string;         (* block hash at H, internal order *)
  bidx : string;         (* blocks.idx raw *)
  undo_from : int;
  uidx : string;         (* undo.idx raw *)
  undo_n : int;
  undo_path : string;
}

let open_pack (dir : string) : pack =
  let b = read_file (Filename.concat dir "blocks.idx") in
  if String.sub b 0 8 <> "HHSSB1\000\000" then failwith "bad blocks.idx magic";
  let ph = u32_at b 12 in
  if String.length b <> 64 + 64 * (ph + 1) then failwith "blocks.idx size";
  let u = read_file (Filename.concat dir "undo.idx") in
  if String.sub u 0 8 <> "HHSSU1\000\000" then failwith "bad undo.idx magic";
  if u32_at u 12 <> ph then failwith "undo.idx height != blocks.idx height";
  { ph; xor = String.sub b 16 8; base = String.sub b 24 32; bidx = b; undo_from = u32_at u 16;
    uidx = u; undo_n = (String.length u - 32) / 16; undo_path = Filename.concat dir "undo.pack" }

let ent_hash p h = String.sub p.bidx (64 + 64 * h) 32
let ent_file p h = u32_at p.bidx (64 + 64 * h + 32)
let ent_pos p h = u32_at p.bidx (64 + 64 * h + 36)
let ent_size p h = u32_at p.bidx (64 + 64 * h + 40)

let undo_entry (p : pack) (h : int) : (int * int * int) option =
  if h < p.undo_from || h - p.undo_from >= p.undo_n then None
  else
    let o = 32 + 16 * (h - p.undo_from) in
    Some (u64_at p.uidx o, u32_at p.uidx (o + 8), u32_at p.uidx (o + 12))

type hints = { hh : int; hidx : string; hints_path : string }

let open_hints (dir : string) : hints =
  let b = read_file (Filename.concat dir "hints.idx") in
  if String.sub b 0 8 <> "HHSSH1\000\000" then failwith "bad hints.idx magic";
  { hh = u32_at b 12; hidx = b; hints_path = Filename.concat dir "hints.pack" }

let hint_start (hs : hints) (h : int) = u64_at hs.hidx (32 + 8 * h)

let hints_count_range (hs : hints) (a : int) (b : int) : int =
  let b = min b hs.hh in
  if a > b then 0 else hint_start hs (b + 1) - hint_start hs a

(* Unbuffered positional read on a private fd (per domain: no shared offset). *)
let pread (fd : Unix.file_descr) (pos : int) (len : int) : string =
  let buf = Bytes.create len in
  ignore (Unix.LargeFile.lseek fd (Int64.of_int pos) Unix.SEEK_SET);
  let rec go off =
    if off < len then begin
      let n = Unix.read fd buf off (len - off) in
      if n = 0 then failwith (Printf.sprintf "short read at %d" (pos + off));
      go (off + n)
    end
  in
  go 0;
  Bytes.unsafe_to_string buf

(* Per-domain reader: blk-file fd cache (read-only, de-XOR), undo + hints fds. *)
type reader = {
  blocks_dir : string;
  rxor : string;
  files : (int, Unix.file_descr) Hashtbl.t;
  undo_fd : Unix.file_descr;
  hints_fd : Unix.file_descr;
}

let new_reader (blocks_dir : string) (p : pack) (hs : hints) : reader =
  { blocks_dir; rxor = p.xor; files = Hashtbl.create 64;
    undo_fd = Unix.openfile p.undo_path [ Unix.O_RDONLY ] 0;
    hints_fd = Unix.openfile hs.hints_path [ Unix.O_RDONLY ] 0 }

let close_reader (r : reader) =
  Hashtbl.iter (fun _ fd -> Unix.close fd) r.files;
  Unix.close r.undo_fd;
  Unix.close r.hints_fd

let read_blk (r : reader) (file : int) (pos : int) (len : int) : string =
  let fd =
    match Hashtbl.find_opt r.files file with
    | Some fd -> fd
    | None ->
      if Hashtbl.length r.files >= 64 then begin
        Hashtbl.iter (fun _ fd -> Unix.close fd) r.files;
        Hashtbl.reset r.files
      end;
      let fd = Unix.openfile (Filename.concat r.blocks_dir (Printf.sprintf "blk%05d.dat" file)) [ Unix.O_RDONLY ] 0 in
      Hashtbl.replace r.files file fd;
      fd
  in
  let raw = pread fd pos len in
  if r.rxor = "\000\000\000\000\000\000\000\000" then raw
  else String.mapi (fun i c -> Char.chr (Char.code c lxor Char.code r.rxor.[(pos + i) mod 8])) raw

let hints_at (r : reader) (hs : hints) (h : int) : string list =
  if h > hs.hh then []
  else
    let s = hint_start hs h and e = hint_start hs (h + 1) in
    if e = s then []
    else
      let raw = pread r.hints_fd (s * 36) ((e - s) * 36) in
      List.init (e - s) (fun i -> String.sub raw (36 * i) 36)

(* ------------------------------------------------------------------------ *)
(* undo coins: Core TxInUndoFormatter, decoded with camlcoin's snapshot coin  *)
(* primitives (Compressor: VARINT, CompressAmount, ScriptCompression)        *)
(* ------------------------------------------------------------------------ *)

type ucoin = {
  mutable height : int;
  mutable coinbase : bool;
  mutable value : int64;
  mutable script : Cstruct.t;
}

let read_txin_undo (r : Serialize.reader) : ucoin =
  let code = Compressor.read_varint r in
  let height = code lsr 1 in
  let coinbase = code land 1 = 1 in
  (* Core undo.h TxInUndoFormatter::Unser: a dummy VARINT when nHeight > 0 *)
  if height > 0 then ignore (Compressor.read_varint r);
  let value = Compressor.decompress_amount (Compressor.read_varint_int64 r) in
  let script = Compressor.deserialize_script r in
  { height; coinbase; value; script }

let parse_undo (raw : string) : ucoin array array =
  let r = Serialize.reader_of_cstruct (Cstruct.of_string raw) in
  let n = Serialize.read_compact_size r in
  let out = Array.init n (fun _ ->
    let m = Serialize.read_compact_size r in
    Array.init m (fun _ -> read_txin_undo r)) in
  if r.Serialize.pos <> String.length raw then
    failwith (Printf.sprintf "%d trailing bytes" (String.length raw - r.Serialize.pos));
  out

(* ------------------------------------------------------------------------ *)
(* aggregate: 256-bit, mod 2^256, as 8 little-endian 32-bit limbs            *)
(* (the same number as rustoshi's 4 x u64 limbs; same hex)                   *)
(* ------------------------------------------------------------------------ *)

type agg = int array

let agg_zero () : agg = Array.make 8 0

let agg_add_digest (a : agg) (d : string) : unit =
  let carry = ref 0 in
  for i = 0 to 7 do
    let s = a.(i) + u32_at d (4 * i) + !carry in
    a.(i) <- s land 0xffffffff;
    carry := s lsr 32
  done

let agg_add (a : agg) (b : agg) : unit =
  let carry = ref 0 in
  for i = 0 to 7 do
    let s = a.(i) + b.(i) + !carry in
    a.(i) <- s land 0xffffffff;
    carry := s lsr 32
  done

let agg_hex (a : agg) : string = String.concat "" (List.init 8 (fun i -> Printf.sprintf "%08x" a.(7 - i)))
let agg_is_zero (a : agg) = Array.for_all (fun x -> x = 0) a

(* H(c) = SHA256(salt | code u32 | amount i64 | CompactSize(len) | script | txid | vout u32),
   code = height*2 + coinbase: every Coin field plus the outpoint (design §1.2),
   byte-identical to tools/swiftsync-refval.py and rustoshi's coin_hash. *)
let coin_hash (b : Buffer.t) (salt : string) (code : int) (amount : int64) (script : Cstruct.t)
    (txid : string) (vout : int) : string =
  Buffer.clear b;
  Buffer.add_string b salt;
  Buffer.add_int32_le b (Int32.of_int (code land 0xffffffff));
  Buffer.add_int64_le b amount;
  add_compact_size b (Cstruct.length script);
  Buffer.add_string b (Cstruct.to_string script);
  Buffer.add_string b txid;
  Buffer.add_int32_le b (Int32.of_int (vout land 0xffffffff));
  Crypto.sha256_accel (Buffer.contents b)

(* TxOutSer record (kernel/coinstats.cpp), the spill format swiftsync-close.py reads. *)
let txoutser (out : Buffer.t) (txid : string) (vout : int) (code : int) (amount : int64) (script : Cstruct.t) =
  Buffer.add_string out txid;
  Buffer.add_int32_le out (Int32.of_int vout);
  Buffer.add_int32_le out (Int32.of_int (code land 0xffffffff));
  Buffer.add_int64_le out amount;
  add_compact_size out (Cstruct.length script);
  Buffer.add_string out (Cstruct.to_string script)

let is_unspendable (script : Cstruct.t) : bool =
  (* Core CScript::IsUnspendable (script.h): OP_RETURN start, or > MAX_SCRIPT_SIZE *)
  (Cstruct.length script > 0 && Cstruct.get_uint8 script 0 = 0x6a)
  || Cstruct.length script > max_script_size

(* ------------------------------------------------------------------------ *)
(* per-domain partial state                                                  *)
(* ------------------------------------------------------------------------ *)

type partial = {
  agg_in : agg;
  agg_out : agg;
  mutable blocks : int;
  mutable txs : int;
  mutable inputs : int;
  mutable inputs_connected : int;
  mutable outputs : int;
  mutable hinted : int;
  mutable agg_out_terms : int;
  mutable skipped : int;
  mutable same_block : int;
  mutable cbs : (string * int) list;  (* BIP30 coinbase-txid cache entries *)
}

let new_partial () = {
  agg_in = agg_zero (); agg_out = agg_zero (); blocks = 0; txs = 0; inputs = 0;
  inputs_connected = 0; outputs = 0; hinted = 0; agg_out_terms = 0; skipped = 0;
  same_block = 0; cbs = [];
}

let merge_partial (a : partial) (b : partial) : unit =
  agg_add a.agg_in b.agg_in;
  agg_add a.agg_out b.agg_out;
  a.blocks <- a.blocks + b.blocks;
  a.txs <- a.txs + b.txs;
  a.inputs <- a.inputs + b.inputs;
  a.inputs_connected <- a.inputs_connected + b.inputs_connected;
  a.outputs <- a.outputs + b.outputs;
  a.hinted <- a.hinted + b.hinted;
  a.agg_out_terms <- a.agg_out_terms + b.agg_out_terms;
  a.skipped <- a.skipped + b.skipped;
  a.same_block <- a.same_block + b.same_block;
  a.cbs <- List.rev_append b.cbs a.cbs

type ctx = {
  net : Consensus.network_config;
  pack : pack;
  hints : hints;
  chain : Sync.chain_state;     (* scratch chain_state: production-accepted headers 0..to *)
  hashes : string array;        (* label height -> header hash (internal order) *)
  salt : string;
  ctl : controls;
  relabel : (int, int) Hashtbl.t;
  overrides : (int, string) Hashtbl.t;
  err_mutex : Mutex.t;
  mutable errs : (string * int * string) list;  (* newest first, capped *)
  n_errors : int Atomic.t;
  max_errors : int;
  applied_mutex : Mutex.t;
  mutable applied : string list;
  bip30_overwritten : int list;
}

let push_error (c : ctx) (kind : string) (h : int) (msg : string) : unit =
  Atomic.incr c.n_errors;
  Mutex.protect c.err_mutex (fun () ->
    if List.length c.errs < c.max_errors then c.errs <- (kind, h, msg) :: c.errs)

let note_applied (c : ctx) (s : string) : unit =
  Mutex.protect c.applied_mutex (fun () -> c.applied <- s :: c.applied)

let phys (c : ctx) (h : int) : int = match Hashtbl.find_opt c.relabel h with Some p -> p | None -> h

let opkey (txid : string) (vout : int) : string = txid ^ le32 vout

(* ------------------------------------------------------------------------ *)
(* one height                                                                *)
(* ------------------------------------------------------------------------ *)

(* Validate one height.  [h] is the LABEL height (what the pass believes). *)
let process_height (c : ctx) (rd : reader) (part : partial) (spill : Buffer.t) (hb : Buffer.t) (h : int) : unit =
  let err kind msg = push_error c kind h msg in
  let fail kind msg = err kind msg; raise Stop in
  let ph = phys c h in
  try
    (* -- block bytes, parsed by the node's own decoder *)
    let raw =
      match Hashtbl.find_opt c.overrides h with
      | Some p -> note_applied c (Printf.sprintf "block-file h=%d from %s" h p); read_file p
      | None -> read_blk rd (ent_file c.pack ph) (ent_pos c.pack ph) (ent_size c.pack ph)
    in
    let r = Serialize.reader_of_cstruct (Cstruct.of_string raw) in
    let block =
      try Serialize.deserialize_block r with e -> fail "parse" ("block decode: " ^ Printexc.to_string e)
    in
    if r.Serialize.pos <> String.length raw then fail "parse" "trailing bytes after block";
    let bhash = Crypto.compute_block_hash block.Types.header in
    let bhs = Cstruct.to_string bhash in
    (* Header binds to the chain: hash == blocks.idx[h] == phase-0 header chain *)
    if bhs <> ent_hash c.pack h || bhs <> c.hashes.(h) then
      err "header" (Printf.sprintf "block hash %s != blocks.idx[%d]" (display_hex bhs) h);
    let txs = Array.of_list block.Types.transactions in
    let ntx = Array.length txs in
    part.blocks <- part.blocks + 1;
    part.txs <- part.txs + ntx;
    let txids = Array.map (fun tx -> Cstruct.to_string (Crypto.compute_txid tx)) txs in
    if h = 0 then begin
      (* Genesis: no inputs; its output is unspendable (never in the set). *)
      if not (Cstruct.equal bhash c.net.Consensus.genesis_hash) then err "header" "genesis hash mismatch";
      Array.iter (fun (tx : Types.transaction) ->
        let n = List.length tx.outputs in
        part.outputs <- part.outputs + n;
        part.skipped <- part.skipped + n) txs;
      raise Stop
    end;
    (* -- undo coins (untrusted) *)
    let uoff, ulen, unin =
      match undo_entry c.pack ph with Some e -> e | None -> fail "undo" (Printf.sprintf "no undo.idx entry for %d" ph)
    in
    let undo =
      try parse_undo (pread rd.undo_fd uoff ulen) with
      | Stop -> raise Stop
      | e -> fail "undo-parse" (Printexc.to_string e)
    in
    if Array.length undo + 1 <> ntx then
      fail "undo-count" (Printf.sprintf "%d CTxUndo for %d txs" (Array.length undo) (ntx - 1));
    let nin = ref 0 in
    Array.iteri (fun i tu ->
      let want = List.length txs.(i + 1).Types.inputs in
      nin := !nin + Array.length tu;
      if Array.length tu <> want then
        fail "undo-count" (Printf.sprintf "tx %d has %d inputs, %d undo coins" (i + 1) want (Array.length tu))) undo;
    let nin = !nin in
    if nin <> unin then err "undo-count" (Printf.sprintf "undo.idx n_inputs %d != coins %d" unin nin);
    (* -- controls on the supplied coins *)
    if Hashtbl.length c.relabel > 0 then
      Array.iter (Array.iter (fun (k : ucoin) ->
        match Hashtbl.find_opt c.relabel k.height with Some r -> k.height <- r | None -> ())) undo;
    let vout_flip = ref None in
    (match c.ctl.field with
     | Some (f, fh, cls) when fh = h ->
       (try
          Array.iteri (fun i tu ->
            Array.iteri (fun j (k : ucoin) ->
              let s = k.script in
              let len = Cstruct.length s in
              let class_ok =
                match cls with
                | "p2pkh" -> len = 25 && Cstruct.get_uint8 s 0 = 0x76 && Cstruct.get_uint8 s 1 = 0xa9 && Cstruct.get_uint8 s 2 = 0x14
                | "p2wpkh" -> len = 22 && Cstruct.get_uint8 s 0 = 0x00 && Cstruct.get_uint8 s 1 = 0x14
                | "p2pk" -> (len = 35 && Cstruct.get_uint8 s 0 = 33) || (len = 67 && Cstruct.get_uint8 s 0 = 65)
                | _ -> false
              in
              if not (k.coinbase || (not class_ok) || k.height >= h || h - k.height <= 100) then begin
                (match f with
                 | "amount" -> k.value <- Int64.add k.value 1L
                 | "script" ->
                   (* P2PKH: last pubkey-hash byte; P2PK: a pubkey byte *)
                   let s' = Cstruct.of_string (Cstruct.to_string s) in
                   let p = if cls = "p2pk" then 10 else len - 3 in
                   Cstruct.set_uint8 s' p (Cstruct.get_uint8 s' p lxor 1);
                   k.script <- s'
                 | "height" -> k.height <- k.height - 1
                 | "coinbase" -> k.coinbase <- not k.coinbase
                 | "vout" -> vout_flip := Some (i + 1, j)
                 | _ -> ());
                note_applied c (Printf.sprintf "field:%s/%s h=%d tx=%d in=%d coin_height=%d value=%Ld" f cls h (i + 1) j k.height k.value);
                raise Exit
              end) tu) undo
        with Exit -> ())
     | _ -> ());
    let undo =
      if c.ctl.drop_coin = Some h then begin
        match Array.find_index (fun tu -> Array.length tu > 0) undo with
        | Some i ->
          let u = Array.copy undo in
          u.(i) <- Array.sub undo.(i) 0 (Array.length undo.(i) - 1);
          note_applied c (Printf.sprintf "drop-coin h=%d" h);
          u
        | None -> undo
      end else undo
    in
    Array.iteri (fun i tu ->
      if Array.length tu <> List.length txs.(i + 1).Types.inputs then
        fail "undo-count" (Printf.sprintf "tx %d inputs != undo coins" (i + 1))) undo;
    (* -- P-ORD [extension a] + the supplied base view *)
    let base : (string, Validation.utxo) Hashtbl.t = Hashtbl.create (2 * nin + 1) in
    let same_block = ref [] in
    let utxo_of (op : Types.outpoint) (k : ucoin) : Validation.utxo =
      { Validation.txid = op.txid; vout = op.vout; value = k.value; script_pubkey = k.script;
        height = k.height; is_coinbase = k.coinbase }
    in
    Array.iteri (fun i tu ->
      let ins = Array.of_list txs.(i + 1).Types.inputs in
      Array.iteri (fun j (k : ucoin) ->
        let op = ins.(j).Types.previous_output in
        let key = opkey (Cstruct.to_string op.txid) (Int32.to_int op.vout land 0xffffffff) in
        if k.height = h then begin
          same_block := (i + 1, j) :: !same_block;
          (* Not supplied: validate_block_with_utxos must find it among this
             block's own earlier outputs (its local_utxos), or reject. *)
          if c.ctl.no_pord then Hashtbl.replace base key (utxo_of op k)
        end else begin
          if k.height > h && not c.ctl.no_pord then
            err "P-ORD" (Printf.sprintf "tx %d in %d spends a coin created at %d > %d" (i + 1) j k.height h);
          Hashtbl.replace base key (utxo_of op k)
        end) tu) undo;
    let same_block = List.rev !same_block in
    let base_lookup (op : Types.outpoint) : Validation.utxo option =
      Hashtbl.find_opt base (opkey (Cstruct.to_string op.txid) (Int32.to_int op.vout land 0xffffffff))
    in
    (* -- THE production connect, argument for argument as
          Sync.process_downloaded_blocks builds it (sync.ml, the IBD loop) *)
    let hdr = block.Types.header in
    let pre =
      match Sync.resolve_expected_bits c.chain h hdr with
      | Error _ as e -> e
      | Ok bits ->
        (match Sync.resolve_mtp_hash_linked c.chain ~height:h hdr.Types.prev_block with
         | Error _ as e -> e
         | Ok mtp -> Ok (bits, mtp))
    in
    (match pre with
     | Error msg -> err "node:ancestry" msg
     | Ok (expected_bits, median_time) ->
       let prev_block_time = Sync.get_prev_block_time c.chain h in
       let skip_scripts = c.ctl.fast_path in
       let validation_flags =
         if skip_scripts then 0
         else Consensus.get_block_script_flags ~block_hash:bhash h c.net
       in
       let coin_mtp, coin_mtp_failed = Sync.checked_coin_mtp_lookup c.chain ~prev_block:hdr.Types.prev_block in
       (* Live: bip34_height_hash_for reads the ACTIVE-chain height index,
          which covers 0..h-1 when block h connects. *)
       let bip34_height_hash =
         if c.net.Consensus.bip34_height <= h - 1 then Sync.bip34_height_hash_for c.chain else None
       in
       let prefetch_base : Validation.base_prefetch option =
         if skip_scripts then None
         else Some (fun ops -> Array.map (fun op -> Some (base_lookup op)) ops)
       in
       (match
          Validation.accept_block ~network:c.net ~block ~height:h ~expected_bits ~median_time
            ~prev_block_time ~base_lookup ~flags:validation_flags ~skip_scripts
            ~get_mtp_at_height:coin_mtp ?bip34_height_hash ?prefetch_base ()
        with
        | Validation.AB_ok _ -> part.inputs_connected <- part.inputs_connected + nin
        | Validation.AB_err e -> err "node" (Validation.block_error_to_string e));
       (match coin_mtp_failed () with Some m -> err "node:ancestry" m | None -> ()));
    (* -- P-ORD, same-block half: created by an EARLIER tx with identical data *)
    if (not c.ctl.no_pord) && same_block <> [] then begin
      let pos : (string, int) Hashtbl.t = Hashtbl.create (2 * ntx) in
      Array.iteri (fun k t -> if not (Hashtbl.mem pos t) then Hashtbl.add pos t k) txids;
      List.iter (fun (i, j) ->
        part.same_block <- part.same_block + 1;
        let op = (List.nth txs.(i).Types.inputs j).Types.previous_output in
        let k = undo.(i - 1).(j) in
        match Hashtbl.find_opt pos (Cstruct.to_string op.txid) with
        | Some t when t < i ->
          let outs = Array.of_list txs.(t).Types.outputs in
          let v = Int32.to_int op.vout land 0xffffffff in
          let ok =
            v < Array.length outs
            && outs.(v).Types.value = k.value
            && Cstruct.equal outs.(v).Types.script_pubkey k.script
            && k.coinbase = (t = 0)
          in
          if not ok then err "P-ORD" (Printf.sprintf "tx %d in %d: same-block coin data != created output" i j)
        | _ -> err "P-ORD" (Printf.sprintf "tx %d in %d: coin height == h but prevout not created earlier in block" i j))
        same_block
    end;
    (* -- Agg_in over every input (supplied coin, prevout from the BLOCK) *)
    Array.iteri (fun i tu ->
      let ins = Array.of_list txs.(i + 1).Types.inputs in
      Array.iteri (fun j (k : ucoin) ->
        let op = ins.(j).Types.previous_output in
        let vout = Int32.to_int op.vout land 0xffffffff in
        let vout = if !vout_flip = Some (i + 1, j) then vout lxor 1 else vout in
        let code = (k.height * 2) + if k.coinbase then 1 else 0 in
        agg_add_digest part.agg_in (coin_hash hb c.salt code k.value k.script (Cstruct.to_string op.txid) vout);
        part.inputs <- part.inputs + 1) tu) undo;
    (* -- outputs: unspendable skip / hinted -> spill / else Agg_out *)
    let hint_list = hints_at rd c.hints ph in
    let hint_list =
      if c.ctl.hint_drop = Some h && hint_list <> [] then begin
        note_applied c (Printf.sprintf "hint-drop %s h=%d" (hex_of_string (List.hd hint_list)) h);
        List.tl hint_list
      end else hint_list
    in
    let hset : (string, unit) Hashtbl.t = Hashtbl.create (2 * List.length hint_list + 1) in
    List.iter (fun k -> Hashtbl.replace hset k ()) hint_list;
    if Hashtbl.length hset <> List.length hint_list then err "hints" "duplicate hint";
    if c.ctl.hint_add = Some h then begin
      let order = List.init (ntx - 1) (fun k -> k + 1) @ [ 0 ] in
      (try
         List.iter (fun k ->
           List.iteri (fun v (o : Types.tx_out) ->
             let key = opkey txids.(k) v in
             if (not (Hashtbl.mem hset key)) && not (is_unspendable o.script_pubkey) then begin
               Hashtbl.replace hset key ();
               note_applied c (Printf.sprintf "hint-add %s:%d h=%d" (display_hex txids.(k)) v h);
               raise Exit
             end) txs.(k).Types.outputs) order
       with Exit -> ())
    end;
    let hits = ref 0 in
    let overwritten_h = List.mem h c.bip30_overwritten && not c.ctl.bip30_spendable in
    Array.iteri (fun k (tx : Types.transaction) ->
      List.iteri (fun v (o : Types.tx_out) ->
        part.outputs <- part.outputs + 1;
        if (k = 0 && overwritten_h) || is_unspendable o.script_pubkey then part.skipped <- part.skipped + 1
        else begin
          let code = (h * 2) + if k = 0 then 1 else 0 in
          if Hashtbl.mem hset (opkey txids.(k) v) then begin
            incr hits;
            part.hinted <- part.hinted + 1;
            txoutser spill txids.(k) v code o.value o.script_pubkey
          end else begin
            part.agg_out_terms <- part.agg_out_terms + 1;
            agg_add_digest part.agg_out (coin_hash hb c.salt code o.value o.script_pubkey txids.(k) v)
          end
        end) tx.outputs) txs;
    if !hits <> Hashtbl.length hset then
      err "hint-count" (Printf.sprintf "hint hits %d != |hints[%d]| %d" !hits h (Hashtbl.length hset));
    (* -- BIP30 coinbase-txid cache [extension c] *)
    if h < c.net.Consensus.bip34_height && (c.ctl.bip30_noexempt || not (Consensus.is_bip30_repeat h bhash)) then
      part.cbs <- (txids.(0), h) :: part.cbs
  with
  | Stop -> ()
  | Fatal.System_fault m -> err "node-fault" m
  | e -> err "exception" (Printexc.to_string e)

(* ------------------------------------------------------------------------ *)
(* start set (standalone ranges)                                             *)
(* ------------------------------------------------------------------------ *)

(* Sorted fixed-width (36-byte) key table without per-key allocation. *)
let cmp_rec (b : Bytes.t) (i : int) (key : string) : int =
  let o = 36 * i in
  let rec go k =
    if k = 36 then 0
    else
      let x = Char.code (Bytes.unsafe_get b (o + k)) and y = Char.code (String.unsafe_get key k) in
      if x <> y then compare x y else go (k + 1)
  in
  go 0

let process_start_set (c : ctx) (rd : reader) (path : string) (from : int) (spill_dir : string) =
  let n = hints_count_range c.hints 0 (from - 1) in
  let keys = Bytes.create (36 * n) in
  let fill = ref 0 in
  for h = 0 to min (from - 1) c.hints.hh do
    let s = hint_start c.hints h and e = hint_start c.hints (h + 1) in
    if e > s then begin
      let raw = pread rd.hints_fd (s * 36) ((e - s) * 36) in
      Bytes.blit_string raw 0 keys (36 * !fill) (String.length raw);
      fill := !fill + (e - s)
    end
  done;
  (* Any total order works: membership by binary search, never relying on
     the snapshot's own coin order. *)
  let idx = Array.init n (fun i -> i) in
  let cmp_ij i j =
    let oi = 36 * i and oj = 36 * j in
    let rec go k =
      if k = 36 then 0
      else
        let x = Char.code (Bytes.unsafe_get keys (oi + k)) and y = Char.code (Bytes.unsafe_get keys (oj + k)) in
        if x <> y then compare x y else go (k + 1)
    in
    go 0
  in
  Array.sort cmp_ij idx;
  let matched = Bytes.make n '\000' in
  let find key =
    let lo = ref 0 and hi = ref (n - 1) and res = ref (-1) in
    while !res < 0 && !lo <= !hi do
      let mid = (!lo + !hi) / 2 in
      let r = cmp_rec keys idx.(mid) key in
      if r = 0 then res := mid else if r < 0 then lo := mid + 1 else hi := mid - 1
    done;
    !res
  in
  let meta =
    match Assume_utxo.read_snapshot_metadata path ~expected_network_magic:c.net.Consensus.magic with
    | Ok m -> m
    | Error e -> failwith ("start snapshot: " ^ e)
  in
  let mb = Cstruct.to_string meta.Assume_utxo.base_blockhash in
  if mb <> c.hashes.(from - 1) then
    failwith (Printf.sprintf "start snapshot base %s != header chain [%d] %s" (display_hex mb) (from - 1)
                (display_hex c.hashes.(from - 1)));
  let oc = open_out_bin (Filename.concat spill_dir "startset-survivors.bin") in
  let rec_buf = Buffer.create 256 and hb = Buffer.create 256 in
  let agg = agg_zero () in
  let coins = ref 0 and survivors = ref 0 and spent = ref 0 in
  let ic = open_in_bin path in
  let res =
    Fun.protect ~finally:(fun () -> close_in_noerr ic) (fun () ->
      let sr = Assume_utxo.Stream_reader.create ic ~start_offset:Assume_utxo.snapshot_body_offset in
      Assume_utxo.iter_snapshot_coins ~base_height:(from - 1) sr ~coins_count:meta.Assume_utxo.coins_count
        ~f:(fun (coin : Assume_utxo.snapshot_coin) ->
          incr coins;
          let txid = Cstruct.to_string coin.outpoint.Types.txid in
          let vout = Int32.to_int coin.outpoint.Types.vout land 0xffffffff in
          let code = (coin.height * 2) + if coin.is_coinbase then 1 else 0 in
          let key = opkey txid vout in
          let i = find key in
          if i >= 0 then begin
            if Bytes.get matched i <> '\000' then failwith (Printf.sprintf "start set: duplicate coin %s:%d" (display_hex txid) vout);
            Bytes.set matched i '\001';
            incr survivors;
            Buffer.clear rec_buf;
            txoutser rec_buf txid vout code coin.value coin.script_pubkey;
            Buffer.output_buffer oc rec_buf
          end else begin
            incr spent;
            agg_add_digest agg (coin_hash hb c.salt code coin.value coin.script_pubkey txid vout)
          end))
  in
  close_out oc;
  (match res with
   | Ok total -> if Int64.to_int total <> !coins then failwith "start snapshot: short"
   | Error e -> failwith ("start snapshot: " ^ e));
  let unmatched = ref 0 in
  Bytes.iter (fun ch -> if ch = '\000' then incr unmatched) matched;
  if !unmatched <> 0 then failwith (Printf.sprintf "start set: %d hints below --from are not coins of S(from-1)" !unmatched);
  (agg, !coins, !survivors, !spent, n)

(* ------------------------------------------------------------------------ *)
(* driver                                                                    *)
(* ------------------------------------------------------------------------ *)

let proc_status_kb (key : string) : int =
  try
    let s = read_file "/proc/self/status" in
    let lines = String.split_on_char '\n' s in
    match List.find_opt (fun l -> String.length l > String.length key && String.sub l 0 (String.length key) = key) lines with
    | None -> 0
    | Some l ->
      let parts = List.filter (( <> ) "") (String.split_on_char ' ' (String.map (fun ch -> if ch = '\t' then ' ' else ch) l)) in
      int_of_string (List.nth parts 1)
  with _ -> 0

let exe_sha256 () = try hex_of_string (Crypto.sha256_accel (read_file "/proc/self/exe")) with _ -> ""

let rec rm_rf (p : string) =
  match (Unix.lstat p).Unix.st_kind with
  | Unix.S_DIR ->
    Array.iter (fun n -> rm_rf (Filename.concat p n)) (Sys.readdir p);
    Unix.rmdir p
  | _ -> Unix.unlink p
  | exception Unix.Unix_error _ -> ()

type args = {
  mutable network : string;
  mutable pack_dir : string;
  mutable blocks : string option;
  mutable hints_dir : string option;
  mutable from : int;
  mutable to_ : int;
  mutable out : string;
  mutable threads : int;
  mutable par : int;
  mutable salt_file : string option;
  mutable start_snapshot : string option;
  mutable control : string;
  mutable block_file : string list;
  mutable max_errors : int;
  mutable keep_hdrdb : bool;
}

let usage =
  "camlcoin swiftsync-pass --pack DIR --from A --to B --out DIR [--network mainnet|regtest] \
   [--blocks DIR] [--hints DIR] [--threads N] [--par P] [--salt-file F] [--start-snapshot F] \
   [--control C] [--block-file H=PATH] [--max-errors N] [--keep-hdrdb]"

let parse_args (argv : string list) : args =
  let a = { network = "mainnet"; pack_dir = ""; blocks = None; hints_dir = None; from = -1; to_ = -1;
            out = ""; threads = 8; par = 0; salt_file = None; start_snapshot = None; control = "";
            block_file = []; max_errors = 200; keep_hdrdb = false } in
  let rec go = function
    | [] -> ()
    | "--network" :: v :: r -> a.network <- v; go r
    | "--pack" :: v :: r -> a.pack_dir <- v; go r
    | "--blocks" :: v :: r -> a.blocks <- Some v; go r
    | "--hints" :: v :: r -> a.hints_dir <- Some v; go r
    | "--from" :: v :: r -> a.from <- int_of_string v; go r
    | "--to" :: v :: r -> a.to_ <- int_of_string v; go r
    | "--out" :: v :: r -> a.out <- v; go r
    | "--threads" :: v :: r -> a.threads <- int_of_string v; go r
    | "--par" :: v :: r -> a.par <- int_of_string v; go r
    | "--salt-file" :: v :: r -> a.salt_file <- Some v; go r
    | "--start-snapshot" :: v :: r -> a.start_snapshot <- Some v; go r
    | "--control" :: v :: r -> a.control <- v; go r
    | "--block-file" :: v :: r -> a.block_file <- a.block_file @ [ v ]; go r
    | "--max-errors" :: v :: r -> a.max_errors <- int_of_string v; go r
    | "--keep-hdrdb" :: r -> a.keep_hdrdb <- true; go r
    | x :: _ -> failwith (Printf.sprintf "unknown argument %s\nusage: %s" x usage)
  in
  go argv;
  if a.pack_dir = "" || a.out = "" || a.from < 0 || a.to_ < 0 then failwith ("usage: " ^ usage);
  a

let run_inner (a : args) : bool =
  let t0 = Unix.gettimeofday () in
  let net =
    match a.network with
    | "mainnet" -> Consensus.mainnet
    | "regtest" -> Consensus.regtest
    | n -> failwith ("--network " ^ n ^ ": only mainnet and regtest are supported")
  in
  let ctl = parse_controls a.control in
  let pack = open_pack a.pack_dir in
  let hints_dir = Option.value a.hints_dir ~default:a.pack_dir in
  let hints = open_hints hints_dir in
  if a.to_ > pack.ph || a.from > a.to_ then
    failwith (Printf.sprintf "bad range %d..%d (pack H=%d)" a.from a.to_ pack.ph);
  if a.to_ > hints.hh then failwith (Printf.sprintf "hints describe height %d < --to %d" hints.hh a.to_);
  let blocks_dir =
    match a.blocks with
    | Some b -> b
    | None ->
      let m = Yojson.Safe.from_file (Filename.concat a.pack_dir "MANIFEST.json") in
      Yojson.Safe.Util.(m |> member "sources" |> member "core_blocks" |> to_string)
  in
  let salt =
    match a.salt_file with
    | Some p ->
      let s = string_of_hex (read_file p) in
      if String.length s <> 32 then failwith "salt must be 32 bytes hex";
      s
    | None -> In_channel.with_open_bin "/dev/urandom" (fun ic -> really_input_string ic 32)
  in
  let threads = max 1 (min 32 a.threads) in
  (* Script checking: --par 0 (default) = no CCheckQueue, each validation
     domain runs run_script_checks' serial branch (same run_one_job /
     resolve_job_faults / scan_first_fail); --par P >= 1 starts the
     production ScriptCheckQueue with P-1 extra workers (Sync's
     start_script_pool), shared by the validation domains. *)
  if a.par >= 1 then begin
    Validation.set_par a.par;
    Validation.start_script_check_queue ()
  end;
  (* scripts_run: every input handed to the node's script checker *)
  let scripts = Atomic.make 0 in
  Validation.job_fault_hook := Some (fun _ -> Atomic.incr scripts);
  (try Unix.mkdir a.out 0o755 with Unix.Unix_error (Unix.EEXIST, _, _) -> ());
  let spill_dir = Filename.concat a.out "spill" in
  (try Unix.mkdir spill_dir 0o755 with Unix.Unix_error (Unix.EEXIST, _, _) -> ());
  Array.iter (fun n -> Sys.remove (Filename.concat spill_dir n)) (Sys.readdir spill_dir);
  let relabel = Hashtbl.create 4 in
  (match ctl.forge_order with
   | Some k -> Hashtbl.replace relabel k (k + 1); Hashtbl.replace relabel (k + 1) k
   | None -> ());
  let overrides = Hashtbl.create 4 in
  List.iter (fun s ->
    match String.index_opt s '=' with
    | Some i -> Hashtbl.replace overrides (int_of_string (String.sub s 0 i)) (String.sub s (i + 1) (String.length s - i - 1))
    | None -> failwith "--block-file H=PATH") a.block_file;
  Printf.eprintf "swiftsync-pass: range %d..%d hints@%d threads=%d par=%d control=%S pack=%s\n%!" a.from a.to_ hints.hh
    threads a.par a.control a.pack_dir;
  (* ---- phase 0: header chain 0..to through the production header acceptance
     (Sync.validate_header: PoW, future time, MTP, bad-diffbits, timewarp,
     checkpoints; Sync.accept_header) into a scratch chain_state, plus the
     active-chain height index the connect-side functions read. *)
  let tp = Unix.gettimeofday () in
  let n = a.to_ + 1 in
  let phys0 h = match Hashtbl.find_opt relabel h with Some p -> p | None -> h in
  let raw_hdrs = Array.make n "" in
  let hnext = Atomic.make 0 in
  let read_hdrs () =
    let rd = new_reader blocks_dir pack hints in
    let rec loop () =
      let i = Atomic.fetch_and_add hnext 1024 in
      if i < n then begin
        for h = i to min (n - 1) (i + 1023) do
          let p = phys0 h in
          raw_hdrs.(h) <- read_blk rd (ent_file pack p) (ent_pos pack p) 80
        done;
        loop ()
      end
    in
    loop ();
    close_reader rd
  in
  let hd = List.init (threads - 1) (fun _ -> Domain.spawn read_hdrs) in
  read_hdrs ();
  List.iter Domain.join hd;
  let headers = Array.map (fun s -> Serialize.deserialize_block_header (Serialize.reader_of_cstruct (Cstruct.of_string s))) raw_hdrs in
  let hashes = Array.map (fun hd -> Cstruct.to_string (Crypto.compute_block_hash hd)) headers in
  Array.fill raw_hdrs 0 n "";
  let hdr_errors = ref [] in
  let herr m = if List.length !hdr_errors < 50 then hdr_errors := m :: !hdr_errors in
  let hdrdb_dir = Filename.concat a.out "hdrdb" in
  rm_rf hdrdb_dir;
  let db = Storage.ChainDB.create ~write_buffer_mb:16 ~block_cache_mb:16 hdrdb_dir in
  let chain = Sync.create_chain_state db net in
  if hashes.(0) <> Cstruct.to_string net.Consensus.genesis_hash then herr "header 0 is not the network genesis";
  for h = 0 to n - 1 do
    if hashes.(h) <> ent_hash pack h then herr (Printf.sprintf "header %d: hash != blocks.idx" h)
  done;
  let prev_entry = ref (Hashtbl.find chain.Sync.headers (Cstruct.to_string net.Consensus.genesis_hash)) in
  for h = 1 to n - 1 do
    let hd = headers.(h) in
    let linked = Cstruct.to_string hd.Types.prev_block = hashes.(h - 1) in
    let forced () =
      { Sync.header = hd; hash = Cstruct.of_string hashes.(h); height = h;
        total_work = Consensus.work_add !prev_entry.Sync.total_work (Sync.work_from_bits hd.Types.bits) }
    in
    let entry =
      if not linked then begin
        herr (Printf.sprintf "header %d: hashPrev != hash[%d] (linkage)" h (h - 1));
        forced ()
      end else
        match Sync.validate_header chain hd with
        | Ok e when e.Sync.height = h -> e
        | Ok e -> herr (Printf.sprintf "header %d: accepted at height %d" h e.Sync.height); forced ()
        | Error m -> herr (Printf.sprintf "header %d: %s" h m); forced ()
    in
    (* a forged/broken header is still inserted (as rustoshi's pass keeps its
       header chain complete) so the per-block checks show WHICH checks see it *)
    Sync.accept_header chain entry;
    prev_entry := entry
  done;
  for h = 0 to n - 1 do
    Storage.ChainDB.set_height_hash db h (Cstruct.of_string hashes.(h))
  done;
  if a.to_ = pack.ph && hashes.(a.to_) <> pack.base then herr "tip != pack base hash";
  let hdr_errors = List.rev !hdr_errors in
  let phase0_s = Unix.gettimeofday () -. tp in
  Printf.eprintf "swiftsync-pass: phase 0: %d headers in %.1fs, %d header errors\n%!" n phase0_s (List.length hdr_errors);
  let ctx = {
    net; pack; hints; chain; hashes; salt; ctl; relabel; overrides;
    err_mutex = Mutex.create (); errs = []; n_errors = Atomic.make 0; max_errors = a.max_errors;
    applied_mutex = Mutex.create (); applied = [];
    bip30_overwritten = (if a.network = "mainnet" then bip30_overwritten_mainnet else []);
  } in
  List.iter (fun m -> push_error ctx "header-chain" 0 m) hdr_errors;
  (* ---- phase 1: every height of the range, out of order, on D domains *)
  let heights =
    let l = List.init (a.to_ - a.from + 1) (fun i -> a.from + i) in
    let l = match ctl.drop_block with
      | Some d -> note_applied ctx (Printf.sprintf "drop-block %d" d); List.filter (( <> ) d) l
      | None -> l in
    let l = match ctl.dup_block with
      | Some d -> note_applied ctx (Printf.sprintf "dup-block %d" d); l @ [ d ]
      | None -> l in
    Array.of_list l
  in
  let total = Array.length heights in
  let seen = Array.init (a.to_ - a.from + 1) (fun _ -> Atomic.make 0) in
  let done_ = Atomic.make 0 in
  let next = Atomic.make 0 in
  let tp1 = Unix.gettimeofday () in
  let script_base = Atomic.get scripts in
  let last_progress = ref (Unix.gettimeofday ()) in
  let worker (d : int) () : partial =
    let rd = new_reader blocks_dir pack hints in
    let part = new_partial () in
    let spill = Buffer.create (1 lsl 20) and hb = Buffer.create 256 in
    let oc = open_out_bin (Filename.concat spill_dir (Printf.sprintf "r%07d-%07d-t%02d.bin" a.from a.to_ d)) in
    let rec loop () =
      let i = Atomic.fetch_and_add next 1 in
      if i < total then begin
        let h = heights.(i) in
        Atomic.incr seen.(h - a.from);
        process_height ctx rd part spill hb h;
        if Buffer.length spill > 1 lsl 20 then (Buffer.output_buffer oc spill; Buffer.clear spill);
        Atomic.incr done_;
        if d = 0 && Unix.gettimeofday () -. !last_progress >= 60.0 then begin
          last_progress := Unix.gettimeofday ();
          let st = Gc.quick_stat () in
          Printf.eprintf
            "swiftsync-pass: %d/%d blocks, %.0fs, scripts %d, rss %d MiB (hwm %d MiB), heap %d MiB (top %d MiB), minor %d major %d compactions %d, errors %d\n%!"
            (Atomic.get done_) total (Unix.gettimeofday () -. tp1) (Atomic.get scripts - script_base)
            (proc_status_kb "VmRSS:" / 1024) (proc_status_kb "VmHWM:" / 1024)
            (st.Gc.heap_words * 8 / 1048576) (st.Gc.top_heap_words * 8 / 1048576)
            st.Gc.minor_collections st.Gc.major_collections st.Gc.compactions (Atomic.get ctx.n_errors)
        end;
        loop ()
      end
    in
    loop ();
    Buffer.output_buffer oc spill;
    close_out oc;
    close_reader rd;
    part
  in
  let doms = List.init (threads - 1) (fun d -> Domain.spawn (worker (d + 1))) in
  let p0 = worker 0 () in
  let part = List.fold_left (fun acc dm -> merge_partial acc (Domain.join dm); acc) p0 doms in
  let phase1_s = Unix.gettimeofday () -. tp1 in
  let scripts_run = Atomic.get scripts - script_base in
  let gc_end = Gc.quick_stat () in
  let agg_out = Array.copy part.agg_out in
  (* ---- start set (standalone range) *)
  let start_json =
    match a.start_snapshot with
    | Some p when a.from > 0 ->
      let rd = new_reader blocks_dir pack hints in
      (match process_start_set ctx rd p a.from spill_dir with
       | (sagg, coins, survivors, spent, hb) ->
         close_reader rd;
         agg_add agg_out sagg;
         `Assoc [ ("snapshot", `String p); ("coins", `Int coins); ("survivors", `Int survivors);
                  ("spent_in_range", `Int spent); ("hints_below_from", `Int hb) ]
       | exception e ->
         close_reader rd;
         push_error ctx "startset" a.from (Printexc.to_string e);
         `Null)
    | _ -> `Null
  in
  (* ---- completeness [extension b] *)
  let missing = ref [] and dups = ref [] in
  for h = a.to_ downto a.from do
    let s = Atomic.get seen.(h - a.from) in
    if s = 0 then missing := h :: !missing else if s > 1 then dups := h :: !dups
  done;
  let first5 l = List.filteri (fun i _ -> i < 5) l |> List.map string_of_int |> String.concat "," in
  if !missing <> [] then
    push_error ctx "completeness" (List.hd !missing)
      (Printf.sprintf "%d heights never processed, first [%s]" (List.length !missing) (first5 !missing));
  if !dups <> [] then
    push_error ctx "completeness" (List.hd !dups)
      (Printf.sprintf "%d heights processed twice: [%s]" (List.length !dups) (first5 !dups));
  (* ---- BIP30 coinbase-txid uniqueness [extension c] *)
  let cbs = List.sort compare part.cbs in
  let rec dupscan = function
    | (t1, h1) :: ((t2, h2) :: _ as rest) ->
      if t1 = t2 then
        push_error ctx "BIP30" h2 (Printf.sprintf "duplicate coinbase txid %s at %d and %d" (display_hex t1) h1 h2);
      dupscan rest
    | _ -> ()
  in
  dupscan cbs;
  let oc = open_out_bin (Filename.concat a.out "bip30-coinbase.bin") in
  List.iter (fun (t, h) -> output_string oc t; output_string oc (le32 h)) cbs;
  close_out oc;
  (* ---- verdict *)
  let expected_inputs = ref 0 in
  for h = max 1 a.from to a.to_ do
    match undo_entry pack h with Some (_, _, k) -> expected_inputs := !expected_inputs + k | None -> ()
  done;
  let expected_inputs = !expected_inputs in
  let standalone = a.from = 0 || a.start_snapshot <> None in
  let complete_to_hints = a.to_ = hints.hh in
  let errs = List.rev ctx.errs in
  let n_errors = Atomic.get ctx.n_errors in
  let fired = List.sort_uniq compare (List.map (fun (k, _, _) -> k) errs) in
  let agg_equal = part.agg_in = agg_out in
  let fired =
    if standalone && complete_to_hints then
      fired @ (if agg_equal then [] else [ "aggregate" ])
      @ (if agg_is_zero part.agg_in || agg_is_zero agg_out then [ "aggregate-zero" ] else [])
    else fired
  in
  (* Script-count denominator: every input consumed from U was handed to the
     node's script checker, and the inputs consumed equal sum n_inputs of
     undo.idx over the range. *)
  let fired =
    if scripts_run <> part.inputs
       || (part.inputs <> expected_inputs && ctl.drop_block = None && ctl.dup_block = None)
    then fired @ [ "script-count" ] else fired
  in
  let verdict = if fired = [] then "PASS" else "FAIL" in
  let total_s = Unix.gettimeofday () -. t0 in
  let res =
    `Assoc [
      ("tool", `String "camlcoin swiftsync-pass");
      ("node", `String "camlcoin");
      ("network", `String a.network);
      ("exe_sha256", `String (exe_sha256 ()));
      ("validation_path",
       `String "sync.ml process_downloaded_blocks argument build (Sync.resolve_expected_bits, \
                Sync.resolve_mtp_hash_linked, Sync.get_prev_block_time, Sync.checked_coin_mtp_lookup, \
                Consensus.get_block_script_flags, Sync.bip34_height_hash_for) -> \
                Validation.accept_block ~skip_scripts:false ?prefetch_base -> \
                validate_block_with_utxos FULL path (check_block, BIP30 probe, sigops cost, IsFinalTx, \
                maturity, MoneyRange, BIP68, fees, run_script_checks, subsidy); headers via \
                Sync.validate_header + Sync.accept_header");
      ("validation_branch", `String (if ctl.fast_path then "FAST (skip_scripts=true; control)" else "FULL (skip_scripts=false)"));
      ("script_check_mode", `String (if a.par >= 1 then Printf.sprintf "ScriptCheckQueue par=%d" a.par
                                    else "run_script_checks serial branch per validation domain"));
      ("range", `List [ `Int a.from; `Int a.to_ ]);
      ("hints_height", `Int hints.hh);
      ("hints_dir", `String hints_dir);
      ("standalone", `Bool standalone);
      ("composes", `Bool (not standalone));
      ("control", if a.control = "" then `Null else `String a.control);
      ("block_file", `List (List.map (fun s -> `String s) a.block_file));
      ("control_applied", `List (List.rev_map (fun s -> `String s) ctx.applied));
      ("salt", `String (hex_of_string salt));
      ("agg_in", `String (agg_hex part.agg_in));
      ("agg_out", `String (agg_hex agg_out));
      ("agg_out_blocks_only", `String (agg_hex part.agg_out));
      ("agg_equal", `Bool agg_equal);
      ("scripts_run", `Int scripts_run);
      ("scripts_counter", `String "Validation.job_fault_hook (called by run_one_job before every script check: inputs handed to the script checker, sig-cache hits included)");
      ("inputs", `Int part.inputs);
      ("inputs_connected", `Int part.inputs_connected);
      ("expected_inputs_undo_idx", `Int expected_inputs);
      ("missing_heights", `Int (List.length !missing));
      ("duplicate_heights", `Int (List.length !dups));
      ("start_set", start_json);
      ("stats", `Assoc [
          ("blocks", `Int part.blocks); ("txs", `Int part.txs); ("outputs", `Int part.outputs);
          ("hinted", `Int part.hinted); ("agg_out_terms", `Int part.agg_out_terms);
          ("skipped", `Int part.skipped); ("same_block", `Int part.same_block);
          ("bip30_coinbases", `Int (List.length cbs));
          ("hints_in_range", `Int (hints_count_range hints a.from a.to_)) ]);
      ("fired", `List (List.map (fun s -> `String s) fired));
      ("errors", `List (List.map (fun (k, h, m) -> `String (Printf.sprintf "%s @%d: %s" k h m)) errs));
      ("n_errors", `Int n_errors);
      ("threads", `Int threads);
      ("par", `Int a.par);
      ("timing_s", `Assoc [ ("phase0_headers", `Float phase0_s); ("phase1_blocks", `Float phase1_s);
                            ("total", `Float total_s) ]);
      ("throughput", `Assoc [
          ("blocks_per_s", `Float (float part.blocks /. Float.max phase1_s 1e-9));
          ("inputs_per_s", `Float (float part.inputs /. Float.max phase1_s 1e-9)) ]);
      ("rss_peak_kib", `Int (proc_status_kb "VmHWM:"));
      ("gc", `Assoc [
          ("heap_mib", `Int (gc_end.Gc.heap_words * 8 / 1048576));
          ("top_heap_mib", `Int (gc_end.Gc.top_heap_words * 8 / 1048576));
          ("minor_collections", `Int gc_end.Gc.minor_collections);
          ("major_collections", `Int gc_end.Gc.major_collections);
          ("compactions", `Int gc_end.Gc.compactions) ]);
      ("verdict", `String verdict);
    ]
  in
  Yojson.Safe.to_file (Filename.concat a.out "result.json") res;
  (try Storage.ChainDB.close db with _ -> ());
  if not a.keep_hdrdb then rm_rf hdrdb_dir;
  let first_error = match errs with (k, h, m) :: _ -> `String (Printf.sprintf "%s @%d: %s" k h m) | [] -> `Null in
  print_endline
    (Yojson.Safe.to_string
       (`Assoc [ ("range", `List [ `Int a.from; `Int a.to_ ]); ("verdict", `String verdict);
                 ("fired", `List (List.map (fun s -> `String s) fired)); ("agg_equal", `Bool agg_equal);
                 ("scripts_run", `Int scripts_run); ("inputs", `Int part.inputs);
                 ("expected_inputs_undo_idx", `Int expected_inputs); ("n_errors", `Int n_errors);
                 ("first_error", first_error); ("elapsed_s", `Float total_s) ]));
  if a.par >= 1 then Validation.stop_script_check_queue ();
  verdict = "PASS"

(* Entry point: `camlcoin swiftsync-pass ARGS`.  Exit 0 = PASS, 1 = FAIL, 2 = fatal. *)
let main (argv : string list) : int =
  Cli.setup_logging false ();
  Logs.set_level (Some Logs.Warning);
  match run_inner (parse_args argv) with
  | true -> 0
  | false -> 1
  | exception e ->
    Printf.eprintf "swiftsync-pass: FATAL: %s\n%!" (Printexc.to_string e);
    2
