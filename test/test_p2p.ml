(* Tests for P2P message serialization *)

open Camlcoin

(* Helper to create a test hash *)
let test_hash () : Types.hash256 =
  let h = Cstruct.create 32 in
  for i = 0 to 31 do
    Cstruct.set_uint8 h i (i * 7 mod 256)
  done;
  h

(* Helper to create a test net_addr *)
let test_net_addr () : Types.net_addr =
  let addr = Cstruct.create 16 in
  (* IPv4-mapped: 10 zeros, 2 0xFF bytes, 4 IPv4 bytes *)
  Cstruct.set_uint8 addr 10 0xFF;
  Cstruct.set_uint8 addr 11 0xFF;
  Cstruct.set_uint8 addr 12 127;
  Cstruct.set_uint8 addr 13 0;
  Cstruct.set_uint8 addr 14 0;
  Cstruct.set_uint8 addr 15 1;
  { services = 1L; addr; port = 8333 }

(* Test command string conversions *)
let test_command_roundtrip () =
  let commands = [
    P2p.Version; P2p.Verack; P2p.Ping; P2p.Pong;
    P2p.Getaddr; P2p.Addr; P2p.Inv; P2p.Getdata;
    P2p.Notfound; P2p.Getblocks; P2p.Getheaders;
    P2p.Headers; P2p.Block; P2p.Tx; P2p.Mempool;
    P2p.Reject; P2p.Sendheaders; P2p.Sendcmpct;
    P2p.Feefilter; P2p.Wtxidrelay; P2p.Sendaddrv2;
    P2p.Alert
  ] in
  List.iter (fun cmd ->
    let s = P2p.command_to_string cmd in
    let cmd' = P2p.command_of_string s in
    Alcotest.(check bool) "command roundtrip" true
      (cmd = cmd')
  ) commands

let test_command_unknown () =
  let cmd = P2p.command_of_string "customcmd" in
  match cmd with
  | P2p.Unknown "customcmd" -> ()
  | _ -> Alcotest.fail "Expected Unknown command"

(* Test inventory type conversions *)
let test_inv_type_roundtrip () =
  let inv_types = [
    P2p.InvError; P2p.InvTx; P2p.InvBlock;
    P2p.InvFilteredBlock; P2p.InvCompactBlock;
    P2p.InvWitnessTx; P2p.InvWitnessBlock
  ] in
  List.iter (fun inv_type ->
    let n = P2p.inv_type_to_int32 inv_type in
    let inv_type' = P2p.inv_type_of_int32 n in
    Alcotest.(check bool) "inv_type roundtrip" true
      (inv_type = inv_type')
  ) inv_types

(* Test reject code conversions *)
let test_reject_code_roundtrip () =
  let codes = [
    P2p.RejectMalformed; P2p.RejectInvalid;
    P2p.RejectObsolete; P2p.RejectDuplicate;
    P2p.RejectNonstandard; P2p.RejectDust;
    P2p.RejectInsufficientFee; P2p.RejectCheckpoint
  ] in
  List.iter (fun code ->
    let n = P2p.reject_code_to_int code in
    let code' = P2p.reject_code_of_int n in
    Alcotest.(check bool) "reject_code roundtrip" true
      (code = code')
  ) codes

(* Test verack message serialization *)
let test_verack_roundtrip () =
  let payload = P2p.VerackMsg in
  let serialized = P2p.serialize_message P2p.mainnet_magic payload in
  let msg = P2p.deserialize_message serialized in
  Alcotest.(check int32) "magic" P2p.mainnet_magic msg.magic;
  match msg.payload with
  | P2p.VerackMsg -> ()
  | _ -> Alcotest.fail "Expected VerackMsg"

(* Test ping/pong message serialization *)
let test_ping_roundtrip () =
  let nonce = 0x123456789ABCDEF0L in
  let payload = P2p.PingMsg nonce in
  let serialized = P2p.serialize_message P2p.mainnet_magic payload in
  let msg = P2p.deserialize_message serialized in
  match msg.payload with
  | P2p.PingMsg n ->
    Alcotest.(check int64) "ping nonce" nonce n
  | _ -> Alcotest.fail "Expected PingMsg"

let test_pong_roundtrip () =
  let nonce = 0xFEDCBA9876543210L in
  let payload = P2p.PongMsg nonce in
  let serialized = P2p.serialize_message P2p.mainnet_magic payload in
  let msg = P2p.deserialize_message serialized in
  match msg.payload with
  | P2p.PongMsg n ->
    Alcotest.(check int64) "pong nonce" nonce n
  | _ -> Alcotest.fail "Expected PongMsg"

(* Test version message serialization *)
let test_version_roundtrip () =
  let version_msg : Types.version_msg = {
    protocol_version = 70016l;
    services = 1L;
    timestamp = 1699999999L;
    addr_recv = test_net_addr ();
    addr_from = test_net_addr ();
    nonce = 0xABCDEF1234567890L;
    user_agent = "/camlcoin:0.1.0/";
    start_height = 800000l;
    relay = true;
  } in
  let payload = P2p.VersionMsg version_msg in
  let serialized = P2p.serialize_message P2p.mainnet_magic payload in
  let msg = P2p.deserialize_message serialized in
  match msg.payload with
  | P2p.VersionMsg v ->
    Alcotest.(check int32) "protocol_version" 70016l v.protocol_version;
    Alcotest.(check int64) "services" 1L v.services;
    Alcotest.(check int64) "timestamp" 1699999999L v.timestamp;
    Alcotest.(check string) "user_agent" "/camlcoin:0.1.0/" v.user_agent;
    Alcotest.(check int32) "start_height" 800000l v.start_height;
    Alcotest.(check bool) "relay" true v.relay
  | _ -> Alcotest.fail "Expected VersionMsg"

(* Test inv message serialization *)
let test_inv_roundtrip () =
  let hash = test_hash () in
  let inv_vectors = [
    { P2p.inv_type = P2p.InvTx; hash };
    { P2p.inv_type = P2p.InvBlock; hash };
    { P2p.inv_type = P2p.InvWitnessTx; hash };
  ] in
  let payload = P2p.InvMsg inv_vectors in
  let serialized = P2p.serialize_message P2p.mainnet_magic payload in
  let msg = P2p.deserialize_message serialized in
  match msg.payload with
  | P2p.InvMsg ivs ->
    Alcotest.(check int) "inv count" 3 (List.length ivs);
    let first = List.hd ivs in
    Alcotest.(check bool) "first type is InvTx"
      true (first.inv_type = P2p.InvTx);
    Alcotest.(check bool) "hash matches"
      true (Cstruct.equal first.hash hash)
  | _ -> Alcotest.fail "Expected InvMsg"

(* Test getdata message serialization *)
let test_getdata_roundtrip () =
  let hash = test_hash () in
  let inv_vectors = [
    { P2p.inv_type = P2p.InvBlock; hash };
  ] in
  let payload = P2p.GetdataMsg inv_vectors in
  let serialized = P2p.serialize_message P2p.mainnet_magic payload in
  let msg = P2p.deserialize_message serialized in
  match msg.payload with
  | P2p.GetdataMsg ivs ->
    Alcotest.(check int) "getdata count" 1 (List.length ivs)
  | _ -> Alcotest.fail "Expected GetdataMsg"

(* Test getblocks message serialization *)
let test_getblocks_roundtrip () =
  let hash1 = test_hash () in
  let hash2 = Cstruct.create 32 in
  let payload = P2p.GetblocksMsg {
    version = 70016l;
    locator_hashes = [hash1];
    hash_stop = hash2;
  } in
  let serialized = P2p.serialize_message P2p.mainnet_magic payload in
  let msg = P2p.deserialize_message serialized in
  match msg.payload with
  | P2p.GetblocksMsg { version; locator_hashes; hash_stop } ->
    Alcotest.(check int32) "version" 70016l version;
    Alcotest.(check int) "locator count" 1 (List.length locator_hashes);
    Alcotest.(check bool) "hash_stop is zero"
      true (Cstruct.equal hash_stop hash2)
  | _ -> Alcotest.fail "Expected GetblocksMsg"

(* Test getheaders message serialization *)
let test_getheaders_roundtrip () =
  let hash1 = test_hash () in
  let hash2 = Cstruct.create 32 in
  let payload = P2p.GetheadersMsg {
    version = 70016l;
    locator_hashes = [hash1; hash1];
    hash_stop = hash2;
  } in
  let serialized = P2p.serialize_message P2p.mainnet_magic payload in
  let msg = P2p.deserialize_message serialized in
  match msg.payload with
  | P2p.GetheadersMsg { version; locator_hashes; _ } ->
    Alcotest.(check int32) "version" 70016l version;
    Alcotest.(check int) "locator count" 2 (List.length locator_hashes)
  | _ -> Alcotest.fail "Expected GetheadersMsg"

(* Test headers message serialization *)
let test_headers_roundtrip () =
  let header : Types.block_header = {
    version = 1l;
    prev_block = Cstruct.create 32;
    merkle_root = Cstruct.create 32;
    timestamp = 1231006505l;
    bits = 0x1d00ffffl;
    nonce = 2083236893l;
  } in
  let payload = P2p.HeadersMsg [header; header] in
  let serialized = P2p.serialize_message P2p.mainnet_magic payload in
  let msg = P2p.deserialize_message serialized in
  match msg.payload with
  | P2p.HeadersMsg headers ->
    Alcotest.(check int) "header count" 2 (List.length headers);
    let h = List.hd headers in
    Alcotest.(check int32) "version" 1l h.version;
    Alcotest.(check int32) "timestamp" 1231006505l h.timestamp
  | _ -> Alcotest.fail "Expected HeadersMsg"

(* Test addr message serialization *)
let test_addr_roundtrip () =
  let addr = test_net_addr () in
  let payload = P2p.AddrMsg [(1699999999l, addr)] in
  let serialized = P2p.serialize_message P2p.mainnet_magic payload in
  let msg = P2p.deserialize_message serialized in
  match msg.payload with
  | P2p.AddrMsg addrs ->
    Alcotest.(check int) "addr count" 1 (List.length addrs);
    let (ts, a) = List.hd addrs in
    Alcotest.(check int32) "timestamp" 1699999999l ts;
    Alcotest.(check int) "port" 8333 a.port
  | _ -> Alcotest.fail "Expected AddrMsg"

(* Test sendcmpct message serialization *)
let test_sendcmpct_roundtrip () =
  let payload = P2p.SendcmpctMsg { announce = true; version = 2L } in
  let serialized = P2p.serialize_message P2p.mainnet_magic payload in
  let msg = P2p.deserialize_message serialized in
  match msg.payload with
  | P2p.SendcmpctMsg { announce; version } ->
    Alcotest.(check bool) "announce" true announce;
    Alcotest.(check int64) "version" 2L version
  | _ -> Alcotest.fail "Expected SendcmpctMsg"

(* Test feefilter message serialization *)
let test_feefilter_roundtrip () =
  let payload = P2p.FeefilterMsg 1000L in
  let serialized = P2p.serialize_message P2p.mainnet_magic payload in
  let msg = P2p.deserialize_message serialized in
  match msg.payload with
  | P2p.FeefilterMsg feerate ->
    Alcotest.(check int64) "feerate" 1000L feerate
  | _ -> Alcotest.fail "Expected FeefilterMsg"

(* Test reject message serialization *)
let test_reject_roundtrip () =
  let payload = P2p.RejectMsg {
    message = "tx";
    ccode = P2p.reject_code_to_int P2p.RejectInvalid;
    reason = "bad-txns-inputs-missingorspent";
    data = test_hash ();
  } in
  let serialized = P2p.serialize_message P2p.mainnet_magic payload in
  let msg = P2p.deserialize_message serialized in
  match msg.payload with
  | P2p.RejectMsg { message; ccode; reason; _ } ->
    Alcotest.(check string) "message" "tx" message;
    Alcotest.(check int) "ccode" 0x10 ccode;
    Alcotest.(check string) "reason"
      "bad-txns-inputs-missingorspent" reason
  | _ -> Alcotest.fail "Expected RejectMsg"

(* Test empty payload messages *)
let test_empty_payloads () =
  let payloads = [
    P2p.GetaddrMsg;
    P2p.MempoolMsg;
    P2p.SendheadersMsg;
    P2p.WtxidrelayMsg;
    P2p.SendaddrV2Msg;
  ] in
  List.iter (fun payload ->
    let serialized = P2p.serialize_message P2p.mainnet_magic payload in
    let msg = P2p.deserialize_message serialized in
    (* Header is 24 bytes, payload should be empty *)
    Alcotest.(check int) "message size" 24 (Cstruct.length serialized);
    Alcotest.(check int32) "magic" P2p.mainnet_magic msg.magic
  ) payloads

(* Test different network magics *)
let test_network_magic () =
  let magics = [
    P2p.mainnet_magic;
    P2p.testnet_magic;
    P2p.regtest_magic;
    P2p.signet_magic;
  ] in
  List.iter (fun magic ->
    let payload = P2p.VerackMsg in
    let serialized = P2p.serialize_message magic payload in
    let msg = P2p.deserialize_message serialized in
    Alcotest.(check int32) "magic matches" magic msg.magic
  ) magics

(* Test message header structure *)
let test_message_header_structure () =
  let payload = P2p.PingMsg 12345L in
  let serialized = P2p.serialize_message P2p.mainnet_magic payload in
  (* Check header is at least 24 bytes *)
  Alcotest.(check bool) "message >= 24 bytes"
    true (Cstruct.length serialized >= 24);
  (* First 4 bytes should be magic *)
  let magic = Cstruct.LE.get_uint32 serialized 0 in
  Alcotest.(check int32) "magic at offset 0" P2p.mainnet_magic magic;
  (* Bytes 4-15 should be command (null-padded "ping") *)
  let cmd = Cstruct.sub serialized 4 12 in
  let cmd_str = Cstruct.to_string cmd in
  Alcotest.(check bool) "command starts with ping"
    true (String.sub cmd_str 0 4 = "ping");
  (* Bytes 16-19 should be payload length (8 for int64 nonce) *)
  let len = Cstruct.LE.get_uint32 serialized 16 in
  Alcotest.(check int32) "payload length" 8l len

(* Test checksum validation *)
let test_checksum_invalid () =
  let payload = P2p.VerackMsg in
  let serialized = P2p.serialize_message P2p.mainnet_magic payload in
  (* Corrupt the checksum (bytes 20-23) *)
  let corrupted = Cstruct.sub_copy serialized 0 (Cstruct.length serialized) in
  Cstruct.set_uint8 corrupted 20 0xFF;
  try
    let _ = P2p.deserialize_message corrupted in
    Alcotest.fail "Should have failed with checksum mismatch"
  with Failure msg ->
    Alcotest.(check bool) "checksum error"
      true (String.sub msg 0 8 = "checksum")

(* Test helper functions *)
let test_empty_net_addr () =
  let addr = P2p.empty_net_addr () in
  Alcotest.(check int64) "services" 0L addr.services;
  Alcotest.(check int) "port" 0 addr.port;
  Alcotest.(check int) "addr len" 16 (Cstruct.length addr.addr)

let test_ipv4_to_net_addr () =
  let ipv4 = Cstruct.create 4 in
  Cstruct.set_uint8 ipv4 0 192;
  Cstruct.set_uint8 ipv4 1 168;
  Cstruct.set_uint8 ipv4 2 1;
  Cstruct.set_uint8 ipv4 3 1;
  let addr = P2p.ipv4_to_net_addr ~services:1L ipv4 8333 in
  Alcotest.(check int64) "services" 1L addr.services;
  Alcotest.(check int) "port" 8333 addr.port;
  (* Check IPv4-mapped format *)
  Alcotest.(check int) "byte 10" 0xFF (Cstruct.get_uint8 addr.addr 10);
  Alcotest.(check int) "byte 11" 0xFF (Cstruct.get_uint8 addr.addr 11);
  Alcotest.(check int) "byte 12" 192 (Cstruct.get_uint8 addr.addr 12)

(* Test transaction message *)
let test_tx_roundtrip () =
  let tx : Types.transaction = {
    version = 2l;
    inputs = [{
      previous_output = {
        txid = Cstruct.create 32;
        vout = 0l;
      };
      script_sig = Cstruct.empty;
      sequence = 0xFFFFFFFFl;
    }];
    outputs = [{
      value = 50_000_000L;
      script_pubkey = Cstruct.concat [Cstruct.of_string "\x00\x14"; Cstruct.create 20];
    }];
    witnesses = [];
    locktime = 0l;
  } in
  let payload = P2p.TxMsg tx in
  let serialized = P2p.serialize_message P2p.mainnet_magic payload in
  let msg = P2p.deserialize_message serialized in
  match msg.payload with
  | P2p.TxMsg tx' ->
    Alcotest.(check int32) "version" 2l tx'.version;
    Alcotest.(check int) "inputs" 1 (List.length tx'.inputs);
    Alcotest.(check int) "outputs" 1 (List.length tx'.outputs);
    Alcotest.(check int64) "value"
      50_000_000L (List.hd tx'.outputs).value
  | _ -> Alcotest.fail "Expected TxMsg"

(* Test block message *)
let test_block_roundtrip () =
  let header : Types.block_header = {
    version = 1l;
    prev_block = Cstruct.create 32;
    merkle_root = Cstruct.create 32;
    timestamp = 1231006505l;
    bits = 0x1d00ffffl;
    nonce = 2083236893l;
  } in
  let tx : Types.transaction = {
    version = 1l;
    inputs = [{
      previous_output = {
        txid = Cstruct.create 32;
        vout = 0xFFFFFFFFl;
      };
      script_sig = Cstruct.of_string "coinbase";
      sequence = 0xFFFFFFFFl;
    }];
    outputs = [{
      value = 50_00000000L;
      script_pubkey = Cstruct.create 25;
    }];
    witnesses = [];
    locktime = 0l;
  } in
  let block : Types.block = { header; transactions = [tx] } in
  let payload = P2p.BlockMsg block in
  let serialized = P2p.serialize_message P2p.mainnet_magic payload in
  let msg = P2p.deserialize_message serialized in
  match msg.payload with
  | P2p.BlockMsg b ->
    Alcotest.(check int32) "header version" 1l b.header.version;
    Alcotest.(check int) "tx count" 1 (List.length b.transactions)
  | _ -> Alcotest.fail "Expected BlockMsg"

(* Property-based tests *)
let arb_nonce =
  QCheck.int64

let test_ping_pong_property =
  QCheck.Test.make ~count:100 ~name:"ping/pong nonce roundtrip"
    arb_nonce
    (fun nonce ->
      let payload = P2p.PingMsg nonce in
      let serialized = P2p.serialize_message P2p.mainnet_magic payload in
      let msg = P2p.deserialize_message serialized in
      match msg.payload with
      | P2p.PingMsg n -> n = nonce
      | _ -> false
    )

(* ============================================================================
   BIP 152 Compact Block Tests
   ============================================================================ *)

(* Helper to create a test block *)
let make_test_block () : Types.block =
  let header : Types.block_header = {
    version = 0x20000000l;
    prev_block = test_hash ();
    merkle_root = test_hash ();
    timestamp = 1699999999l;
    bits = 0x1d00ffffl;
    nonce = 12345l;
  } in
  let coinbase : Types.transaction = {
    version = 1l;
    inputs = [{
      previous_output = { txid = Types.zero_hash; vout = 0xFFFFFFFFl };
      script_sig = Cstruct.of_string "\x03\x01\x02\x03";
      sequence = 0xFFFFFFFFl;
    }];
    outputs = [{
      value = 5000000000L;
      script_pubkey = Cstruct.concat [Cstruct.of_string "\x00\x14"; Cstruct.create 20];
    }];
    witnesses = [];
    locktime = 0l;
  } in
  let tx1 : Types.transaction = {
    version = 2l;
    inputs = [{
      previous_output = { txid = test_hash (); vout = 0l };
      script_sig = Cstruct.empty;
      sequence = 0xFFFFFFFEl;
    }];
    outputs = [{
      value = 1000000L;
      script_pubkey = Cstruct.concat [Cstruct.of_string "\x00\x14"; Cstruct.create 20];
    }];
    witnesses = [{ Types.items = [Cstruct.create 71; Cstruct.create 33] }];
    locktime = 0l;
  } in
  { header; transactions = [coinbase; tx1] }

(* Test compact block creation *)
let test_compact_block_creation () =
  let blk = make_test_block () in
  let cb = P2p.create_compact_block blk in
  (* Should have correct header *)
  Alcotest.(check int32) "header version" blk.Types.header.Types.version cb.P2p.header.Types.version;
  Alcotest.(check int32) "header timestamp" blk.Types.header.Types.timestamp cb.P2p.header.Types.timestamp;
  (* Coinbase should be prefilled at index 0 *)
  Alcotest.(check int) "prefilled count" 1 (List.length cb.P2p.prefilled_txs);
  let ptx = List.hd cb.P2p.prefilled_txs in
  Alcotest.(check int) "prefilled index" 0 ptx.P2p.index;
  Alcotest.(check int32) "prefilled tx version" 1l ptx.P2p.tx.Types.version;
  (* Should have short IDs for non-coinbase transactions *)
  Alcotest.(check int) "short_ids count" 1 (List.length cb.P2p.short_ids)

(* Test cmpctblock message serialization roundtrip *)
let test_cmpctblock_roundtrip () =
  let block = make_test_block () in
  let cb = P2p.create_compact_block block in
  let payload = P2p.CmpctblockMsg cb in
  let serialized = P2p.serialize_message P2p.mainnet_magic payload in
  let msg = P2p.deserialize_message serialized in
  match msg.payload with
  | P2p.CmpctblockMsg cb' ->
    Alcotest.(check int32) "header version" cb.header.version cb'.header.version;
    Alcotest.(check int64) "nonce" cb.nonce cb'.nonce;
    Alcotest.(check int) "short_ids count"
      (List.length cb.short_ids) (List.length cb'.short_ids);
    Alcotest.(check int) "prefilled count"
      (List.length cb.prefilled_txs) (List.length cb'.prefilled_txs);
    (* Verify short IDs match *)
    List.iter2 (fun a b ->
      Alcotest.(check int64) "short_id" a b
    ) cb.short_ids cb'.short_ids
  | _ -> Alcotest.fail "Expected CmpctblockMsg"

(* Test getblocktxn message serialization roundtrip *)
let test_getblocktxn_roundtrip () =
  let req : P2p.block_txns_request = {
    block_hash = test_hash ();
    indexes = [0; 2; 5];  (* differential encoded: 0, 1, 2 *)
  } in
  let payload = P2p.GetblocktxnMsg req in
  let serialized = P2p.serialize_message P2p.mainnet_magic payload in
  let msg = P2p.deserialize_message serialized in
  match msg.payload with
  | P2p.GetblocktxnMsg req' ->
    Alcotest.(check bool) "block_hash"
      true (Cstruct.equal req.block_hash req'.block_hash);
    Alcotest.(check (list int)) "indexes" req.indexes req'.indexes
  | _ -> Alcotest.fail "Expected GetblocktxnMsg"

(* Test blocktxn message serialization roundtrip *)
let test_blocktxn_roundtrip () =
  let tx : Types.transaction = {
    version = 2l;
    inputs = [{
      previous_output = { txid = test_hash (); vout = 1l };
      script_sig = Cstruct.empty;
      sequence = 0xFFFFFFFEl;
    }];
    outputs = [{
      value = 500000L;
      script_pubkey = Cstruct.concat [Cstruct.of_string "\x00\x14"; Cstruct.create 20];
    }];
    witnesses = [{ Types.items = [Cstruct.create 64] }];
    locktime = 0l;
  } in
  let resp : P2p.block_txns = {
    block_hash = test_hash ();
    txs = [tx];
  } in
  let payload = P2p.BlocktxnMsg resp in
  let serialized = P2p.serialize_message P2p.mainnet_magic payload in
  let msg = P2p.deserialize_message serialized in
  match msg.payload with
  | P2p.BlocktxnMsg resp' ->
    Alcotest.(check bool) "block_hash"
      true (Cstruct.equal resp.block_hash resp'.block_hash);
    Alcotest.(check int) "txs count"
      (List.length resp.txs) (List.length resp'.txs);
    let tx' = List.hd resp'.txs in
    Alcotest.(check int32) "tx version" 2l tx'.version
  | _ -> Alcotest.fail "Expected BlocktxnMsg"

(* Test SipHash key derivation and short ID computation *)
let test_siphash_short_id () =
  let header_hash = test_hash () in
  let nonce = 0x123456789ABCDEF0L in
  let (k0, k1) = Crypto.SipHash.derive_keys header_hash nonce in
  (* Keys should be deterministic *)
  let (k0', k1') = Crypto.SipHash.derive_keys header_hash nonce in
  Alcotest.(check int64) "k0 deterministic" k0 k0';
  Alcotest.(check int64) "k1 deterministic" k1 k1';
  (* Different nonce should give different keys *)
  let (k0'', k1'') = Crypto.SipHash.derive_keys header_hash (Int64.add nonce 1L) in
  Alcotest.(check bool) "different nonce different k0" true (k0 <> k0'' || k1 <> k1'');
  ignore k1'';
  (* Compute short ID *)
  let wtxid = test_hash () in
  let short_id = Crypto.compute_short_txid k0 k1 wtxid in
  (* Short ID should be 6 bytes (48 bits) *)
  let mask_6bytes = 0xFFFFFFFFFFFFL in
  Alcotest.(check int64) "short_id is 6 bytes"
    short_id (Int64.logand short_id mask_6bytes)

(* Test block reconstruction *)
let test_block_reconstruction () =
  let blk : Types.block = make_test_block () in
  let blk_txs : Types.transaction list = blk.transactions in
  let cb = P2p.create_compact_block blk in
  let header_hash = Crypto.compute_block_hash cb.header in
  let (k0, k1) = Crypto.SipHash.derive_keys header_hash cb.nonce in

  (* Create lookup table with all non-coinbase transactions *)
  let non_coinbase = List.tl blk_txs in
  let lookup = P2p.create_tx_lookup ~k0 ~k1 non_coinbase in

  (* Attempt reconstruction *)
  match P2p.reconstruct_block cb lookup with
  | P2p.ReconstructComplete reconstructed ->
    let recon_txs : Types.transaction list = reconstructed.transactions in
    Alcotest.(check int32) "reconstructed header version"
      blk.header.version reconstructed.header.version;
    Alcotest.(check int) "reconstructed tx count"
      (List.length blk_txs) (List.length recon_txs);
    (* Verify transactions match *)
    List.iteri (fun i (orig : Types.transaction) ->
      let recon : Types.transaction = List.nth recon_txs i in
      Alcotest.(check int32) (Printf.sprintf "tx %d version" i)
        orig.version recon.version
    ) blk_txs
  | P2p.ReconstructNeedTxs missing ->
    Alcotest.fail (Printf.sprintf "Missing %d transactions" (List.length missing))
  | P2p.ReconstructFailed msg ->
    Alcotest.fail msg

(* Test reconstruction with missing transactions *)
let test_block_reconstruction_missing () =
  let blk = make_test_block () in
  let cb = P2p.create_compact_block blk in

  (* Create empty lookup table *)
  let lookup : P2p.tx_lookup = { by_short_id = Hashtbl.create 0 } in

  match P2p.reconstruct_block cb lookup with
  | P2p.ReconstructNeedTxs missing ->
    (* Should be missing non-coinbase transactions *)
    Alcotest.(check int) "missing tx count" 1 (List.length missing)
  | P2p.ReconstructComplete _ ->
    Alcotest.fail "Should not complete with empty lookup"
  | P2p.ReconstructFailed msg ->
    Alcotest.fail msg

(* Test differential index encoding *)
let test_differential_indices () =
  (* Absolute indices: 0, 5, 7, 10 *)
  (* Differential: 0, (5-0-1)=4, (7-5-1)=1, (10-7-1)=2 *)
  let hash = test_hash () in
  let req = P2p.make_getblocktxn_request hash [0; 5; 7; 10] in
  Alcotest.(check (list int)) "differential indices"
    [0; 4; 1; 2] req.indexes;
  (* Decode back to absolute *)
  let decoded = P2p.decode_differential_indices req.indexes in
  Alcotest.(check (list int)) "decoded absolute"
    [0; 5; 7; 10] decoded

(* Test compact block tx count *)
let test_compact_block_tx_count () =
  let blk = make_test_block () in
  let cb = P2p.create_compact_block blk in
  let count = P2p.compact_block_tx_count cb in
  Alcotest.(check int) "tx count"
    (List.length blk.Types.transactions) count

(* Test cmpctblock command in command list *)
let test_cmpctblock_command () =
  let cmd = P2p.command_of_string "cmpctblock" in
  Alcotest.(check bool) "cmpctblock command"
    true (cmd = P2p.Cmpctblock);
  let s = P2p.command_to_string P2p.Cmpctblock in
  Alcotest.(check string) "cmpctblock string" "cmpctblock" s

let () =
  let open Alcotest in
  run "P2P" [
    "commands", [
      test_case "command roundtrip" `Quick test_command_roundtrip;
      test_case "unknown command" `Quick test_command_unknown;
      test_case "cmpctblock command" `Quick test_cmpctblock_command;
    ];
    "inv_types", [
      test_case "inv_type roundtrip" `Quick test_inv_type_roundtrip;
    ];
    "reject_codes", [
      test_case "reject_code roundtrip" `Quick test_reject_code_roundtrip;
    ];
    "messages", [
      test_case "verack roundtrip" `Quick test_verack_roundtrip;
      test_case "ping roundtrip" `Quick test_ping_roundtrip;
      test_case "pong roundtrip" `Quick test_pong_roundtrip;
      test_case "version roundtrip" `Quick test_version_roundtrip;
      test_case "inv roundtrip" `Quick test_inv_roundtrip;
      test_case "getdata roundtrip" `Quick test_getdata_roundtrip;
      test_case "getblocks roundtrip" `Quick test_getblocks_roundtrip;
      test_case "getheaders roundtrip" `Quick test_getheaders_roundtrip;
      test_case "headers roundtrip" `Quick test_headers_roundtrip;
      test_case "addr roundtrip" `Quick test_addr_roundtrip;
      test_case "sendcmpct roundtrip" `Quick test_sendcmpct_roundtrip;
      test_case "feefilter roundtrip" `Quick test_feefilter_roundtrip;
      test_case "reject roundtrip" `Quick test_reject_roundtrip;
      test_case "tx roundtrip" `Quick test_tx_roundtrip;
      test_case "block roundtrip" `Quick test_block_roundtrip;
      test_case "empty payloads" `Quick test_empty_payloads;
      test_case "cmpctblock roundtrip" `Quick test_cmpctblock_roundtrip;
      test_case "getblocktxn roundtrip" `Quick test_getblocktxn_roundtrip;
      test_case "blocktxn roundtrip" `Quick test_blocktxn_roundtrip;
    ];
    "network", [
      test_case "network magic" `Quick test_network_magic;
    ];
    "structure", [
      test_case "message header structure" `Quick test_message_header_structure;
      test_case "checksum invalid" `Quick test_checksum_invalid;
    ];
    "helpers", [
      test_case "empty_net_addr" `Quick test_empty_net_addr;
      test_case "ipv4_to_net_addr" `Quick test_ipv4_to_net_addr;
    ];
    "compact_blocks", [
      test_case "compact block creation" `Quick test_compact_block_creation;
      test_case "siphash short id" `Quick test_siphash_short_id;
      test_case "block reconstruction" `Quick test_block_reconstruction;
      test_case "reconstruction missing" `Quick test_block_reconstruction_missing;
      test_case "differential indices" `Quick test_differential_indices;
      test_case "compact block tx count" `Quick test_compact_block_tx_count;
    ];
    "property", [
      QCheck_alcotest.to_alcotest test_ping_pong_property;
    ];
  ]
