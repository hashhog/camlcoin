(* Regtest tests for `camlcoin swiftsync-pass` (lib/swiftsync.ml).

   The pass validates a height range against Core-format undo data (the
   spent coins) and an unspent-hints file, both untrusted, and closes only
   when the salted input aggregate equals the output aggregate.  These tests
   build a small regtest chain in-process (real PoW at the regtest limit,
   signed P2PKH spends, intra-block spends, an OP_RETURN output), write it
   out in the pack layout the pass reads, and run [Swiftsync.main] -- the
   function bin/main.ml's `swiftsync-pass` dispatch exits with.

   Pack layout (all integers little-endian), as read by lib/swiftsync.ml:
     blocks.idx  64-byte header "HHSSB1\0\0" | ver u32 | H u32 | xor[8] |
                 base hash[32] | 8 zero bytes; then (H+1) x 64-byte rows:
                 hash[32] | blk file u32 | blk pos u32 | blk size u32 |
                 rev file/pos/size u32 x3 | nTx u32 | status u32
     undo.pack   CBlockUndo bytes for heights 1..H (Core TxInUndoFormatter)
     undo.idx    32-byte header "HHSSU1\0\0" | ver | H | from | 12 zero
                 bytes; then per height: offset u64 | len u32 | n_inputs u32
     hints.pack  36-byte outpoints (txid | vout u32) of the outputs still
                 unspent at H, grouped by creation height
     hints.idx   32-byte header "HHSSH1\0\0" | ver | H | total u64 | 8 zero
                 bytes; then (H+2) cumulative u64 record starts
     blocks/blk00000.dat  magic | size | block, xor key 0

   What is pinned:
   - the valid chain, standalone (--from 0) and complete (--to = hints
     height): exit 0, verdict PASS, closed, scripts_run = every input;
   - one bad signature, or a bad merkle root: exit 1, verdict FAIL;
   - one hint removed, or one extra hint (an output that IS spent): exit 1;
   - a composing slice (--from > 0, no start snapshot) never reports
     closed, and the dropped-hint fault is invisible to it: a slice PASS
     only feeds a combine step, it is not a validation of the chain. *)

open Camlcoin

let net = Consensus.regtest
let tip = 112
let maturity = 100

(* ---------------------------------------------------------------- keys *)

let privkey = Cstruct.of_string (String.make 32 '\x11')
let pubkey = Crypto.derive_public_key ~compressed:true privkey

let p2pkh_spk =
  let h = Crypto.hash160 pubkey in
  Cstruct.concat
    [ Cstruct.of_string "\x76\xa9\x14"; h; Cstruct.of_string "\x88\xac" ]

let push (data : Cstruct.t) : Cstruct.t =
  let n = Cstruct.length data in
  assert (n < 0x4c);
  Cstruct.concat [ Cstruct.of_string (String.make 1 (Char.chr n)); data ]

(* Sign input [i] of [tx] (spending a P2PKH coin) with SIGHASH_ALL.  When
   [corrupt] is set the low bit of r's last byte is flipped: the DER
   encoding stays valid, only the signature is wrong. *)
let sign_input ?(corrupt = false) (tx : Types.transaction) (i : int) :
    Types.transaction =
  let sighash = Script.compute_sighash_legacy tx i p2pkh_spk 1 in
  let der = Crypto.sign privkey sighash in
  let der = Cstruct.of_string (Cstruct.to_string der) in
  if corrupt then begin
    let rlen = Cstruct.get_uint8 der 3 in
    let p = 4 + rlen - 1 in
    Cstruct.set_uint8 der p (Cstruct.get_uint8 der p lxor 1)
  end;
  let sig_ = Cstruct.concat [ der; Cstruct.of_string "\x01" ] in
  let script_sig = Cstruct.concat [ push sig_; push pubkey ] in
  let inputs =
    List.mapi
      (fun j (inp : Types.tx_in) ->
        if j = i then { inp with Types.script_sig } else inp)
      tx.Types.inputs
  in
  { tx with Types.inputs }

(* --------------------------------------------------------------- chain *)

type coin = { c_height : int; c_cb : bool; c_value : int64; c_spk : Cstruct.t }

type chain = {
  blocks : Types.block array;           (* 0..tip *)
  undo : coin array array array;        (* per height: per non-cb tx: coins *)
  unspent : (int * (string * int) list) list;  (* creation height -> outpoints *)
  spent_cb1 : string * int;             (* an outpoint created at 1, spent later *)
  n_inputs : int;
}

type fault = No_fault | Bad_sig of int | Bad_merkle of int

(* The genesis coinbase (the same transaction on mainnet and regtest). *)
let genesis_tx_hex =
  "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d"
  ^ "0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66"
  ^ "207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe55"
  ^ "48271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba"
  ^ "0b8d578a4c702b6bf11d5fac00000000"

let genesis_block : Types.block =
  let raw =
    String.init (String.length genesis_tx_hex / 2) (fun i ->
        Char.chr (int_of_string ("0x" ^ String.sub genesis_tx_hex (2 * i) 2)))
  in
  let tx = Serialize.deserialize_transaction (Serialize.reader_of_cstruct (Cstruct.of_string raw)) in
  assert (Cstruct.equal (Crypto.compute_txid tx) net.Consensus.genesis_header.merkle_root);
  { Types.header = net.Consensus.genesis_header; transactions = [ tx ] }

let txid_s tx = Cstruct.to_string (Crypto.compute_txid tx)

let mine (hdr : Types.block_header) : Types.block_header =
  let rec go n =
    let h = { hdr with Types.nonce = n } in
    if Consensus.hash_meets_target (Crypto.compute_block_hash h) h.Types.bits
    then h
    else go (Int32.add n 1l)
  in
  go 0l

let build_chain (fault : fault) : chain =
  let utxo : (string, coin) Hashtbl.t = Hashtbl.create 512 in
  let created_at : (string, int) Hashtbl.t = Hashtbl.create 512 in
  let key txid vout = txid ^ Printf.sprintf "%08x" vout in
  let unkey k = (String.sub k 0 32, int_of_string ("0x" ^ String.sub k 32 8)) in
  let blocks = Array.make (tip + 1) genesis_block in
  let undo = Array.make (tip + 1) [||] in
  let prev = ref net.Consensus.genesis_hash in
  let cb_txids = Array.make (tip + 1) "" in
  (* output 1 of the h=103 parent tx, spent cross-block at h=110 *)
  let later = ref None in
  let n_inputs = ref 0 in
  for h = 1 to tip do
    let txs = ref [] and fees = ref 0L and block_undo = ref [] in
    let spend (tx : Types.transaction) ~corrupt_input0 =
      (* sign each input, record its coin, remove it from the set *)
      let tx =
        List.fold_left
          (fun tx i -> sign_input ~corrupt:(corrupt_input0 && i = 0) tx i)
          tx
          (List.init (List.length tx.Types.inputs) Fun.id)
      in
      let coins =
        List.map
          (fun (inp : Types.tx_in) ->
            let op = inp.Types.previous_output in
            let k = key (Cstruct.to_string op.txid) (Int32.to_int op.vout) in
            let c = Hashtbl.find utxo k in
            Hashtbl.remove utxo k;
            c)
          tx.Types.inputs
      in
      let vin = List.fold_left (fun a c -> Int64.add a c.c_value) 0L coins in
      let vout =
        List.fold_left (fun a (o : Types.tx_out) -> Int64.add a o.value) 0L
          tx.Types.outputs
      in
      fees := Int64.add !fees (Int64.sub vin vout);
      n_inputs := !n_inputs + List.length coins;
      block_undo := Array.of_list coins :: !block_undo;
      let t = txid_s tx in
      List.iteri
        (fun v (o : Types.tx_out) ->
          let k = key t v in
          Hashtbl.replace created_at k h;
          if not (Cstruct.length o.script_pubkey > 0
                  && Cstruct.get_uint8 o.script_pubkey 0 = 0x6a)
          then
            Hashtbl.replace utxo k
              { c_height = h; c_cb = false; c_value = o.value;
                c_spk = o.script_pubkey })
        tx.Types.outputs;
      txs := tx :: !txs;
      t
    in
    let mk_in txid vout : Types.tx_in =
      { previous_output = { txid = Cstruct.of_string txid; vout = Int32.of_int vout };
        script_sig = Cstruct.empty; sequence = 0xFFFFFFFFl }
    in
    let out value spk : Types.tx_out = { value; script_pubkey = spk } in
    if h > maturity + 1 then begin
      (* A: spends the coinbase of h-101 (a matured coinbase coin) *)
      let src = cb_txids.(h - maturity - 1) in
      let outs =
        [ out 3_000_000_000L p2pkh_spk; out 1_999_990_000L p2pkh_spk ]
        @ (if h = 105 then
             [ out 0L (Cstruct.of_string "\x6a\x04test") ]
           else [])
      in
      let a =
        { Types.version = 1l; inputs = [ mk_in src 0 ]; outputs = outs;
          witnesses = []; locktime = 0l }
      in
      let a_id = spend a ~corrupt_input0:(fault = Bad_sig h) in
      if h = 103 then later := Some a_id;
      (* B: spends A:0 in the same block (an intra-block coin, P-ORD) *)
      let b =
        { Types.version = 1l; inputs = [ mk_in a_id 0 ];
          outputs = [ out 2_999_980_000L p2pkh_spk ];
          witnesses = []; locktime = 0l }
      in
      ignore (spend b ~corrupt_input0:false);
      (* C at 110: spends A(103):1, a non-coinbase coin from an earlier block *)
      (match !later with
       | Some id when h = 110 ->
         let c =
           { Types.version = 2l; inputs = [ mk_in id 1 ];
             outputs = [ out 1_000_000_000L p2pkh_spk; out 999_980_000L p2pkh_spk ];
             witnesses = []; locktime = 0l }
         in
         ignore (spend c ~corrupt_input0:false)
       | _ -> ())
    end;
    let cb =
      let script_sig =
        Cstruct.concat
          [ Consensus.encode_height_in_coinbase h; Cstruct.of_string "\x00" ]
      in
      { Types.version = 1l;
        inputs =
          [ { previous_output = { txid = Types.zero_hash; vout = -1l };
              script_sig; sequence = 0xFFFFFFFFl } ];
        outputs =
          [ out
              (Int64.add
                 (Consensus.block_subsidy ~halving_interval:net.halving_interval h)
                 !fees)
              p2pkh_spk ];
        witnesses = []; locktime = 0l }
    in
    let cb_id = txid_s cb in
    cb_txids.(h) <- cb_id;
    Hashtbl.replace created_at (key cb_id 0) h;
    Hashtbl.replace utxo (key cb_id 0)
      { c_height = h; c_cb = true; c_value = (List.hd cb.outputs).value;
        c_spk = p2pkh_spk };
    let transactions = cb :: List.rev !txs in
    let root, _ = Crypto.merkle_root (List.map Crypto.compute_txid transactions) in
    let root =
      if fault = Bad_merkle h then begin
        let r = Cstruct.of_string (Cstruct.to_string root) in
        Cstruct.set_uint8 r 0 (Cstruct.get_uint8 r 0 lxor 1);
        r
      end else root
    in
    let header =
      mine
        { Types.version = 0x20000000l; prev_block = !prev; merkle_root = root;
          timestamp =
            Int32.add net.Consensus.genesis_header.timestamp (Int32.of_int (600 * h));
          bits = 0x207fffffl; nonce = 0l }
    in
    blocks.(h) <- { Types.header; transactions };
    undo.(h) <- Array.of_list (List.rev !block_undo);
    prev := Crypto.compute_block_hash header
  done;
  let by_h = Hashtbl.create 128 in
  Hashtbl.iter
    (fun k _ ->
      let h = Hashtbl.find created_at k in
      Hashtbl.replace by_h h (unkey k :: Option.value ~default:[] (Hashtbl.find_opt by_h h)))
    utxo;
  let unspent =
    List.init (tip + 1) (fun h ->
        (h, List.sort compare (Option.value ~default:[] (Hashtbl.find_opt by_h h))))
  in
  { blocks; undo; unspent; spent_cb1 = (cb_txids.(1), 0); n_inputs = !n_inputs }

(* ---------------------------------------------------------------- pack *)

let u32 b n = Buffer.add_int32_le b (Int32.of_int (n land 0xffffffff))
let u64 b n = Buffer.add_int64_le b (Int64.of_int n)

let write_file path s =
  Out_channel.with_open_bin path (fun oc -> Out_channel.output_string oc s)

let encode_undo (coins : coin array array) : string =
  let w = Serialize.writer_create () in
  Serialize.write_compact_size w (Array.length coins);
  Array.iter
    (fun tu ->
      Serialize.write_compact_size w (Array.length tu);
      Array.iter
        (fun c ->
          Compressor.write_varint w ((c.c_height * 2) + if c.c_cb then 1 else 0);
          if c.c_height > 0 then Compressor.write_varint w 0;
          Compressor.write_varint_int64 w (Compressor.compress_amount c.c_value);
          Compressor.serialize_script w c.c_spk)
        tu)
    coins;
  Serialize.writer_to_string w

(* Write the pack into [dir]; [hints] overrides the hint groups. *)
let write_pack ?hints (dir : string) (ch : chain) : unit =
  let blocks_dir = Filename.concat dir "blocks" in
  Unix.mkdir blocks_dir 0o755;
  let blk = Buffer.create (1 lsl 16) in
  let rows = Buffer.create (64 * (tip + 1)) in
  let base = ref "" in
  Array.iter
    (fun (b : Types.block) ->
      let w = Serialize.writer_create () in
      Serialize.serialize_block w b;
      let raw = Serialize.writer_to_string w in
      u32 blk 0xdab5bffa;
      u32 blk (String.length raw);
      let pos = Buffer.length blk in
      Buffer.add_string blk raw;
      let hash = Cstruct.to_string (Crypto.compute_block_hash b.Types.header) in
      base := hash;
      Buffer.add_string rows hash;
      u32 rows 0; u32 rows pos; u32 rows (String.length raw);
      u32 rows 0xffffffff; u32 rows 0xffffffff; u32 rows 0xffffffff;
      u32 rows (List.length b.Types.transactions); u32 rows 0)
    ch.blocks;
  write_file (Filename.concat blocks_dir "blk00000.dat") (Buffer.contents blk);
  let bidx = Buffer.create 64 in
  Buffer.add_string bidx "HHSSB1\000\000";
  u32 bidx 1; u32 bidx tip;
  Buffer.add_string bidx (String.make 8 '\000');
  Buffer.add_string bidx !base;
  Buffer.add_string bidx (String.make 8 '\000');
  Buffer.add_buffer bidx rows;
  write_file (Filename.concat dir "blocks.idx") (Buffer.contents bidx);
  let upack = Buffer.create 4096 and uidx = Buffer.create 4096 in
  Buffer.add_string uidx "HHSSU1\000\000";
  u32 uidx 1; u32 uidx tip; u32 uidx 1;
  Buffer.add_string uidx (String.make 12 '\000');
  for h = 1 to tip do
    let raw = encode_undo ch.undo.(h) in
    u64 uidx (Buffer.length upack);
    u32 uidx (String.length raw);
    u32 uidx (Array.fold_left (fun a tu -> a + Array.length tu) 0 ch.undo.(h));
    Buffer.add_string upack raw
  done;
  write_file (Filename.concat dir "undo.pack") (Buffer.contents upack);
  write_file (Filename.concat dir "undo.idx") (Buffer.contents uidx);
  let groups = Option.value hints ~default:ch.unspent in
  let hpack = Buffer.create 4096 and starts = Buffer.create 1024 in
  let total = ref 0 in
  for h = 0 to tip do
    u64 starts !total;
    List.iter
      (fun (t, v) -> Buffer.add_string hpack t; u32 hpack v; incr total)
      (Option.value ~default:[] (List.assoc_opt h groups))
  done;
  u64 starts !total;
  let hidx = Buffer.create 1024 in
  Buffer.add_string hidx "HHSSH1\000\000";
  u32 hidx 1; u32 hidx tip; u64 hidx !total;
  Buffer.add_string hidx (String.make 8 '\000');
  Buffer.add_buffer hidx starts;
  write_file (Filename.concat dir "hints.pack") (Buffer.contents hpack);
  write_file (Filename.concat dir "hints.idx") (Buffer.contents hidx)

(* ----------------------------------------------------------------- run *)

type outcome = { code : int; result : Yojson.Safe.t }

let salt_hex = String.concat "" (List.init 32 (fun i -> Printf.sprintf "%02x" (i * 7 land 0xff)))

let run_pass ?hints ?(from = 0) ?(to_ = tip) (ch : chain) : outcome =
  Test_tmp.with_dir ~label:"swiftsync" ~mkdir:true (fun dir ->
      let pack = Filename.concat dir "pack" and out = Filename.concat dir "out" in
      Unix.mkdir pack 0o755;
      write_pack ?hints pack ch;
      let salt = Filename.concat dir "salt" in
      write_file salt salt_hex;
      let code =
        Fun.protect
          ~finally:(fun () -> Validation.job_fault_hook := None)
          (fun () ->
            Swiftsync.main
              [ "--network"; "regtest"; "--pack"; pack;
                "--blocks"; Filename.concat pack "blocks";
                "--from"; string_of_int from; "--to"; string_of_int to_;
                "--out"; out; "--threads"; "1"; "--salt-file"; salt ])
      in
      { code; result = Yojson.Safe.from_file (Filename.concat out "result.json") })

let field r k = Yojson.Safe.Util.member k r.result
let verdict r = Yojson.Safe.Util.to_string (field r "verdict")
let fired r = List.map Yojson.Safe.Util.to_string (Yojson.Safe.Util.to_list (field r "fired"))
let closed r = Yojson.Safe.Util.to_bool (field r "closed")
let show r = Yojson.Safe.to_string r.result

let valid = lazy (build_chain No_fault)

let expect_fail ~what r =
  Alcotest.(check int) (what ^ ": exit 1\n" ^ show r) 1 r.code;
  Alcotest.(check string) (what ^ ": verdict") "FAIL" (verdict r);
  Alcotest.(check bool) (what ^ ": not closed") false (closed r)

let test_valid_full_chain () =
  let ch = Lazy.force valid in
  let r = run_pass ch in
  Alcotest.(check int) ("exit 0\n" ^ show r) 0 r.code;
  Alcotest.(check string) "verdict" "PASS" (verdict r);
  Alcotest.(check bool) "closed" true (closed r);
  Alcotest.(check bool) "agg_equal" true (Yojson.Safe.Util.to_bool (field r "agg_equal"));
  Alcotest.(check bool) "fixture has spends" true (ch.n_inputs > 20);
  Alcotest.(check int) "scripts_run = every input" ch.n_inputs
    (Yojson.Safe.Util.to_int (field r "scripts_run"));
  Alcotest.(check int) "inputs" ch.n_inputs (Yojson.Safe.Util.to_int (field r "inputs"))

let contains s sub =
  let n = String.length s and m = String.length sub in
  let rec go i = i + m <= n && (String.sub s i m = sub || go (i + 1)) in
  go 0

let test_bad_signature () =
  let r = run_pass (build_chain (Bad_sig 108)) in
  expect_fail ~what:"bad signature" r;
  Alcotest.(check bool) ("fired node\n" ^ show r) true (List.mem "node" (fired r));
  (* the node's script checker rejected it, not some earlier check *)
  Alcotest.(check bool) ("script check failed at 108\n" ^ show r) true
    (List.exists
       (fun e -> contains e "@108" && contains e "script verification failed")
       (List.map Yojson.Safe.Util.to_string (Yojson.Safe.Util.to_list (field r "errors"))))

let test_bad_merkle_root () =
  let r = run_pass (build_chain (Bad_merkle 108)) in
  expect_fail ~what:"bad merkle root" r;
  Alcotest.(check bool) ("fired node\n" ^ show r) true (List.mem "node" (fired r))

let drop_one_hint (ch : chain) =
  List.map (fun (h, l) -> if h = 110 then (h, List.tl l) else (h, l)) ch.unspent

let test_hint_removed () =
  let ch = Lazy.force valid in
  Alcotest.(check bool) "h110 has hints" true (List.assoc 110 ch.unspent <> []);
  let r = run_pass ~hints:(drop_one_hint ch) ch in
  expect_fail ~what:"hint removed" r;
  Alcotest.(check bool) ("fired aggregate\n" ^ show r) true (List.mem "aggregate" (fired r))

let test_extra_hint () =
  (* The coinbase output of block 1 is spent at 102; hinting it as unspent
     moves it out of Agg_out while Agg_in still holds it. *)
  let ch = Lazy.force valid in
  let hints =
    List.map (fun (h, l) -> if h = 1 then (h, ch.spent_cb1 :: l) else (h, l)) ch.unspent
  in
  let r = run_pass ~hints ch in
  expect_fail ~what:"extra hint" r;
  Alcotest.(check bool) ("fired aggregate\n" ^ show r) true (List.mem "aggregate" (fired r))

let test_slice_never_closed () =
  let ch = Lazy.force valid in
  let r = run_pass ~from:50 ch in
  Alcotest.(check int) ("slice exit\n" ^ show r) 0 r.code;
  Alcotest.(check bool) "slice not closed" false (closed r);
  Alcotest.(check bool) "slice composes" true
    (Yojson.Safe.Util.to_bool (field r "composes"));
  (* The same dropped hint that fails the standalone run is not visible to a
     composing slice: only the combine step's aggregate sum catches it.  The
     slice says so by not claiming closure. *)
  let r = run_pass ~from:50 ~hints:(drop_one_hint ch) ch in
  Alcotest.(check bool) "slice with dropped hint: not closed" false (closed r);
  Alcotest.(check bool) "slice with dropped hint: agg_equal false" false
    (Yojson.Safe.Util.to_bool (field r "agg_equal"))

let () =
  Alcotest.run "swiftsync_pass"
    [ ( "regtest",
        [ Alcotest.test_case "valid chain 0..tip: PASS, closed, scripts_run = inputs" `Quick
            test_valid_full_chain;
          Alcotest.test_case "bad signature: FAIL" `Quick test_bad_signature;
          Alcotest.test_case "bad merkle root: FAIL" `Quick test_bad_merkle_root;
          Alcotest.test_case "hint removed: FAIL" `Quick test_hint_removed;
          Alcotest.test_case "extra hint: FAIL" `Quick test_extra_hint;
          Alcotest.test_case "composing slice never closed" `Quick test_slice_never_closed ] ) ]
