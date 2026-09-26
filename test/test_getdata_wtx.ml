(* getdata serving decision per inv type — Core parity
   (bitcoin-core/src/net_processing.cpp ProcessGetData / FindTxForGetData /
   ProcessGetBlockData):

     MSG_WTX (5)                  hash = WTXID, lookup by wtxid, WITH witness
     MSG_WITNESS_TX (0x40000001)  hash = txid,  lookup by txid,  WITH witness
     MSG_TX (1)                   hash = txid,  lookup by txid,  NO witness
     MSG_BLOCK (2)                                               NO witness
     MSG_WITNESS_BLOCK (0x40000002)                              WITH witness
     unserveable                  -> batched into one notfound

   On master every tx type went through a txid-keyed Mempool.get, so a
   MSG_WTX getdata for a segwit tx (wtxid <> txid) always answered notfound —
   the failure seen live on regtest: Core A "Requesting wtx <wtxid>" ->
   "received: notfound", tx never reaches Core A's mempool.

   These tests drive the REAL Peer.handle_getdata over a socketpair against a
   REAL mempool (entries added via Mempool.add_transaction) and decode the
   bytes that hit the wire. *)

open Camlcoin


(* ---------- fixtures ---------- *)

let funding_txid = Types.hash256_of_hex
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"

let segwit_tx : Types.transaction = Types.{
    version = 2l;
    inputs = [{ previous_output = { txid = funding_txid; vout = 0l };
                script_sig = Cstruct.empty; sequence = 0xFFFFFFFDl }];
    outputs = [{ value = 990_000L;
                 script_pubkey = Cstruct.of_string
                     ("\x00\x14" ^ String.make 20 '\x11') }];
    witnesses = [{ items = [Cstruct.of_string (String.make 71 '\x30');
                            Cstruct.of_string ("\x02" ^ String.make 32 '\x22')] }];
    locktime = 0l;
  }

let txid = Crypto.compute_txid segwit_tx
let wtxid = Crypto.compute_wtxid segwit_tx

let ser f x = let w = Serialize.writer_create () in f w x;
  Cstruct.to_string (Serialize.writer_to_cstruct w)
let with_wit_bytes = ser Serialize.serialize_transaction segwit_tx
let no_wit_bytes = ser Serialize.serialize_transaction_no_witness segwit_tx

let with_mempool f =
  let path = Test_tmp.fresh ~label:"getdata_wtx" () in
  let db = Storage.ChainDB.create path in
  let utxo = Utxo.UtxoSet.create db in
  Utxo.UtxoSet.add utxo funding_txid 0 Utxo.{
      value = 1_000_000L;
      script_pubkey = Cstruct.of_string ("\x00\x14" ^ String.make 20 '\x33');
      height = 0; is_coinbase = false };
  let mp = Mempool.create ~network:Consensus.regtest ~require_standard:false
      ~verify_scripts:false ~utxo ~current_height:200 () in
  (match Mempool.add_transaction mp segwit_tx with
   | Ok _ -> ()
   | Error e -> Alcotest.failf "fixture add_transaction failed: %s" e);
  Fun.protect ~finally:(fun () -> Storage.ChainDB.close db) (fun () -> f mp)

(* ---------- wire capture ---------- *)

let read_exact fd n =
  let b = Bytes.create n in
  let rec go off = if off < n then begin
      let k = Unix.read fd b off (n - off) in
      if k = 0 then failwith "eof"; go (off + k) end in
  go 0; Bytes.to_string b

(* Read all complete v1 messages currently buffered on [fd]. *)
let drain fd =
  Unix.set_nonblock fd;
  let rec loop acc =
    match (try Some (read_exact fd 24) with
        | Unix.Unix_error ((Unix.EAGAIN | Unix.EWOULDBLOCK), _, _) -> None) with
    | None -> List.rev acc
    | Some hdr ->
      let cmd = String.sub hdr 4 12 in
      let cmd = match String.index_opt cmd '\000' with
        | Some i -> String.sub cmd 0 i | None -> cmd in
      let len = Int32.to_int (String.get_int32_le hdr 16) in
      Unix.clear_nonblock fd;
      let payload = read_exact fd len in
      Unix.set_nonblock fd;
      loop ((cmd, payload) :: acc)
  in
  loop []

let run_getdata ?(lookup_block = fun _ -> None) mp items =
  let (s1, s2) = Unix.socketpair Unix.PF_UNIX Unix.SOCK_STREAM 0 in
  let fd = Lwt_unix.of_unix_file_descr s1 in
  let peer = Peer.make_peer ~network:Consensus.regtest ~addr:"127.0.0.1"
      ~port:18444 ~id:7 ~direction:Peer.Inbound ~fd () in
  (* Same wiring as lib/cli.ml's getdata listener. *)
  let lookup_tx h = Option.map (fun e -> e.Mempool.tx) (Mempool.get mp h) in
  let lookup_wtx h =
    Option.map (fun e -> e.Mempool.tx) (Mempool.get_by_wtxid mp h) in
  Lwt_main.run
    (Peer.handle_getdata peer items ~lookup_block ~lookup_tx ~lookup_wtx
       ~tip_height:0 ~lookup_block_height:(fun _ -> None));
  let msgs = drain s2 in
  Lwt_main.run (Peer.disconnect peer);
  Unix.close s2;
  msgs

let inv t h = { P2p.inv_type = t; hash = h }

let notfound_items payload =
  match P2p.deserialize_payload P2p.Notfound
          (Serialize.reader_of_cstruct (Cstruct.of_string payload)) with
  | P2p.NotfoundMsg l -> l
  | _ -> Alcotest.fail "not a notfound payload"

let hex s = Types.hash256_to_hex_display s

(* ---------- tests ---------- *)

let test_fixture_is_segwit () =
  Alcotest.(check bool) "wtxid <> txid (fixture exercises the bug)" false
    (Cstruct.equal txid wtxid);
  Alcotest.(check bool) "with-witness bytes carry marker 00 01" true
    (with_wit_bytes.[4] = '\000' && with_wit_bytes.[5] = '\001')

let test_mempool_wtxid_index () =
  with_mempool (fun mp ->
      Alcotest.(check bool) "get_by_wtxid wtxid -> found" true
        (Mempool.get_by_wtxid mp wtxid <> None);
      Alcotest.(check bool) "get_by_wtxid txid -> absent (segwit)" true
        (Mempool.get_by_wtxid mp txid = None);
      Alcotest.(check bool) "contains_wtxid" true (Mempool.contains_wtxid mp wtxid);
      Mempool.remove_transaction mp txid;
      Alcotest.(check bool) "index cleared on remove" true
        (Mempool.get_by_wtxid mp wtxid = None);
      (match Mempool.add_transaction mp segwit_tx with
       | Ok _ -> () | Error e -> Alcotest.failf "re-add: %s" e);
      Mempool.clear mp;
      Alcotest.(check bool) "index cleared on clear" true
        (Mempool.get_by_wtxid mp wtxid = None))

let expect_tx name expected = function
  | ("tx", payload) ->
    let hx x = String.concat "" (List.init (String.length x)
                                   (fun i -> Printf.sprintf "%02x" (Char.code x.[i]))) in
    Alcotest.(check string) name (hx expected) (hx payload)
  | (cmd, _) -> Alcotest.failf "%s: expected tx, got %S" name cmd

let test_msg_wtx_served_with_witness () =
  with_mempool (fun mp ->
      match run_getdata mp [inv P2p.InvWtx wtxid] with
      | [m] -> expect_tx "MSG_WTX(wtxid) -> tx WITH witness" with_wit_bytes m
      | l -> Alcotest.failf "expected 1 message, got %d%s" (List.length l)
               (match l with [("notfound", _)] -> " (notfound: the master bug)"
                           | _ -> ""))

let test_msg_tx_served_without_witness () =
  with_mempool (fun mp ->
      match run_getdata mp [inv P2p.InvTx txid] with
      | [m] -> expect_tx "MSG_TX(txid) -> tx WITHOUT witness" no_wit_bytes m
      | l -> Alcotest.failf "expected 1 message, got %d" (List.length l))

let test_msg_witness_tx_served_with_witness () =
  with_mempool (fun mp ->
      match run_getdata mp [inv P2p.InvWitnessTx txid] with
      | [m] -> expect_tx "MSG_WITNESS_TX(txid) -> tx WITH witness" with_wit_bytes m
      | l -> Alcotest.failf "expected 1 message, got %d" (List.length l))

let test_unserveable_batched_notfound () =
  with_mempool (fun mp ->
      (* MSG_WTX keyed by the TXID of a segwit tx is not a match (the hash is a
         wtxid); MSG_TX keyed by the wtxid likewise. *)
      let msgs = run_getdata mp
          [inv P2p.InvWtx txid; inv P2p.InvWtx wtxid; inv P2p.InvTx wtxid] in
      Alcotest.(check (list string)) "commands" ["tx"; "notfound"]
        (List.map fst msgs);
      let nf = notfound_items (List.assoc "notfound" msgs) in
      Alcotest.(check (list string)) "notfound items (in order)"
        [hex txid; hex wtxid]
        (List.map (fun (iv : P2p.inv_vector) -> hex iv.hash) nf))

(* Block serving. *)
let block : Types.block =
  let cb : Types.transaction = Types.{
      version = 1l;
      inputs = [{ previous_output = { txid = zero_hash; vout = -1l };
                  script_sig = Cstruct.of_string "\x01\x01";
                  sequence = 0xFFFFFFFFl }];
      outputs = [{ value = 0L; script_pubkey = Cstruct.of_string "\x51" }];
      witnesses = [{ items = [Cstruct.create 32] }];
      locktime = 0l } in
  Types.{ header = { version = 0x20000000l; prev_block = zero_hash;
                     merkle_root = zero_hash; timestamp = 0l; bits = 0x207fffffl;
                     nonce = 0l };
          transactions = [cb; segwit_tx] }

let block_hash = Crypto.compute_block_hash block.Types.header
let block_bytes = ser Serialize.serialize_block block
let block_no_wit_bytes =
  let w = Serialize.writer_create () in
  Serialize.serialize_block_header w block.Types.header;
  Serialize.write_compact_size w (List.length block.Types.transactions);
  List.iter (Serialize.serialize_transaction_no_witness w) block.Types.transactions;
  Cstruct.to_string (Serialize.writer_to_cstruct w)

let lookup_block h =
  if Cstruct.equal h block_hash then Some (Cstruct.of_string block_bytes)
  else None

let expect_block name expected = function
  | [("block", payload)] ->
    Alcotest.(check bool) name true (payload = expected)
  | l -> Alcotest.failf "%s: got %s" name (String.concat "," (List.map fst l))

let test_msg_block_without_witness () =
  with_mempool (fun mp ->
      expect_block "MSG_BLOCK -> block WITHOUT witness" block_no_wit_bytes
        (run_getdata ~lookup_block mp [inv P2p.InvBlock block_hash]))

let test_msg_witness_block_with_witness () =
  with_mempool (fun mp ->
      expect_block "MSG_WITNESS_BLOCK -> block WITH witness" block_bytes
        (run_getdata ~lookup_block mp [inv P2p.InvWitnessBlock block_hash]))

let () =
  Alcotest.run "getdata_wtx" [
    "getdata", [
      Alcotest.test_case "fixture is segwit" `Quick test_fixture_is_segwit;
      Alcotest.test_case "mempool wtxid index" `Quick test_mempool_wtxid_index;
      Alcotest.test_case "MSG_WTX with witness" `Quick test_msg_wtx_served_with_witness;
      Alcotest.test_case "MSG_TX no witness" `Quick test_msg_tx_served_without_witness;
      Alcotest.test_case "MSG_WITNESS_TX with witness" `Quick
        test_msg_witness_tx_served_with_witness;
      Alcotest.test_case "unserveable -> one notfound" `Quick
        test_unserveable_batched_notfound;
      Alcotest.test_case "MSG_BLOCK no witness" `Quick test_msg_block_without_witness;
      Alcotest.test_case "MSG_WITNESS_BLOCK with witness" `Quick
        test_msg_witness_block_with_witness;
    ];
  ]
