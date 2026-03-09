open Camlcoin

(* Helper to create a hex string from bytes *)
let _hex_of_cstruct cs =
  let buf = Buffer.create (Cstruct.length cs * 2) in
  for i = 0 to Cstruct.length cs - 1 do
    Buffer.add_string buf (Printf.sprintf "%02x" (Cstruct.get_uint8 cs i))
  done;
  Buffer.contents buf

let cstruct_of_hex s =
  let len = String.length s / 2 in
  let buf = Cstruct.create len in
  for i = 0 to len - 1 do
    let byte = int_of_string ("0x" ^ String.sub s (i * 2) 2) in
    Cstruct.set_uint8 buf i byte
  done;
  buf

(* CompactSize tests *)
let test_compact_size_small () =
  (* Value < 0xFD should be 1 byte *)
  let w = Serialize.writer_create () in
  Serialize.write_compact_size w 0x42;
  let cs = Serialize.writer_to_cstruct w in
  Alcotest.(check int) "length" 1 (Cstruct.length cs);
  Alcotest.(check int) "value" 0x42 (Cstruct.get_uint8 cs 0)

let test_compact_size_fd () =
  (* Value 0xFD-0xFFFF should be 0xFD + 2 bytes *)
  let w = Serialize.writer_create () in
  Serialize.write_compact_size w 0x1234;
  let cs = Serialize.writer_to_cstruct w in
  Alcotest.(check int) "length" 3 (Cstruct.length cs);
  Alcotest.(check int) "marker" 0xFD (Cstruct.get_uint8 cs 0);
  Alcotest.(check int) "low byte" 0x34 (Cstruct.get_uint8 cs 1);
  Alcotest.(check int) "high byte" 0x12 (Cstruct.get_uint8 cs 2)

let test_compact_size_fe () =
  (* Value 0x10000-0xFFFFFFFF should be 0xFE + 4 bytes *)
  let w = Serialize.writer_create () in
  Serialize.write_compact_size w 0x12345678;
  let cs = Serialize.writer_to_cstruct w in
  Alcotest.(check int) "length" 5 (Cstruct.length cs);
  Alcotest.(check int) "marker" 0xFE (Cstruct.get_uint8 cs 0)

let test_compact_size_roundtrip () =
  let values = [0; 1; 0xFC; 0xFD; 0xFFFF; 0x10000; 0xFFFFFF] in
  List.iter (fun n ->
    let w = Serialize.writer_create () in
    Serialize.write_compact_size w n;
    let cs = Serialize.writer_to_cstruct w in
    let r = Serialize.reader_of_cstruct cs in
    let result = Serialize.read_compact_size r in
    Alcotest.(check int) (Printf.sprintf "roundtrip %d" n) n result
  ) values

(* Block header tests - should always be 80 bytes *)
let test_block_header_size () =
  let header : Types.block_header = {
    version = 1l;
    prev_block = Types.zero_hash;
    merkle_root = Types.zero_hash;
    timestamp = 1231006505l;
    bits = 0x1d00ffffl;
    nonce = 2083236893l;
  } in
  let w = Serialize.writer_create () in
  Serialize.serialize_block_header w header;
  let cs = Serialize.writer_to_cstruct w in
  Alcotest.(check int) "header size" 80 (Cstruct.length cs)

let test_block_header_roundtrip () =
  let header : Types.block_header = {
    version = 536870912l;
    prev_block = Types.hash256_of_hex "0000000000000000000000000000000000000000000000000000000000000000";
    merkle_root = Types.hash256_of_hex "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";
    timestamp = 1231006505l;
    bits = 0x1d00ffffl;
    nonce = 2083236893l;
  } in
  let w = Serialize.writer_create () in
  Serialize.serialize_block_header w header;
  let cs = Serialize.writer_to_cstruct w in
  let r = Serialize.reader_of_cstruct cs in
  let result = Serialize.deserialize_block_header r in
  Alcotest.(check int32) "version" header.version result.version;
  Alcotest.(check int32) "timestamp" header.timestamp result.timestamp;
  Alcotest.(check int32) "bits" header.bits result.bits;
  Alcotest.(check int32) "nonce" header.nonce result.nonce

(* Transaction tests *)
let test_simple_tx_roundtrip () =
  let tx : Types.transaction = {
    version = 1l;
    inputs = [{
      previous_output = {
        txid = Types.hash256_of_hex "0000000000000000000000000000000000000000000000000000000000000000";
        vout = 0xffffffffl;
      };
      script_sig = cstruct_of_hex "04ffff001d0104";
      sequence = 0xffffffffl;
    }];
    outputs = [{
      value = 5000000000L;
      script_pubkey = cstruct_of_hex "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac";
    }];
    witnesses = [];
    locktime = 0l;
  } in
  let w = Serialize.writer_create () in
  Serialize.serialize_transaction w tx;
  let cs = Serialize.writer_to_cstruct w in
  let r = Serialize.reader_of_cstruct cs in
  let result = Serialize.deserialize_transaction r in
  Alcotest.(check int32) "version" tx.version result.version;
  Alcotest.(check int) "input count" (List.length tx.inputs) (List.length result.inputs);
  Alcotest.(check int) "output count" (List.length tx.outputs) (List.length result.outputs);
  Alcotest.(check int32) "locktime" tx.locktime result.locktime

(* Test coinbase-style transaction roundtrip *)
let test_coinbase_tx () =
  (* Create a coinbase-like transaction *)
  let coinbase_script = cstruct_of_hex "04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73" in
  let pubkey_script = cstruct_of_hex "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac" in
  let tx : Types.transaction = {
    version = 1l;
    inputs = [{
      previous_output = {
        txid = Types.hash256_of_hex "0000000000000000000000000000000000000000000000000000000000000000";
        vout = 0xffffffffl;
      };
      script_sig = coinbase_script;
      sequence = 0xffffffffl;
    }];
    outputs = [{
      value = 5000000000L;  (* 50 BTC *)
      script_pubkey = pubkey_script;
    }];
    witnesses = [];
    locktime = 0l;
  } in
  let w = Serialize.writer_create () in
  Serialize.serialize_transaction w tx;
  let cs = Serialize.writer_to_cstruct w in
  let r = Serialize.reader_of_cstruct cs in
  let result = Serialize.deserialize_transaction r in
  Alcotest.(check int32) "version" tx.version result.version;
  Alcotest.(check int) "inputs" 1 (List.length result.inputs);
  Alcotest.(check int) "outputs" 1 (List.length result.outputs);
  Alcotest.(check int64) "output value" 5000000000L (List.hd result.outputs).value

(* Test segwit transaction *)
let test_segwit_tx () =
  let tx : Types.transaction = {
    version = 2l;
    inputs = [{
      previous_output = {
        txid = Types.hash256_of_hex "1111111111111111111111111111111111111111111111111111111111111111";
        vout = 0l;
      };
      script_sig = Cstruct.create 0;  (* empty for native segwit *)
      sequence = 0xfffffffel;
    }];
    outputs = [{
      value = 100000L;
      script_pubkey = cstruct_of_hex "0014751e76e8199196d454941c45d1b3a323f1433bd6";
    }];
    witnesses = [{
      items = [
        cstruct_of_hex "304402203f004eeed0cef2715643e2a78e2f5ab6d91a3b4e3e5f5d5f5d5f5d5f5d5f5d5f02203f004eeed0cef2715643e2a78e2f5ab6d91a3b4e3e5f5d5f5d5f5d5f5d5f5d5f01";
        cstruct_of_hex "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
      ];
    }];
    locktime = 0l;
  } in
  let w = Serialize.writer_create () in
  Serialize.serialize_transaction w tx;
  let cs = Serialize.writer_to_cstruct w in
  let r = Serialize.reader_of_cstruct cs in
  let result = Serialize.deserialize_transaction r in
  Alcotest.(check int32) "version" tx.version result.version;
  Alcotest.(check int) "witnesses" (List.length tx.witnesses) (List.length result.witnesses);
  let wit = List.hd result.witnesses in
  Alcotest.(check int) "witness items" 2 (List.length wit.items)

(* Test version message roundtrip *)
let test_version_msg_roundtrip () =
  let ipv6_mapped_ipv4 = Cstruct.create 16 in
  (* Set IPv6-mapped IPv4 prefix: ::ffff:127.0.0.1 *)
  Cstruct.set_uint8 ipv6_mapped_ipv4 10 0xff;
  Cstruct.set_uint8 ipv6_mapped_ipv4 11 0xff;
  Cstruct.set_uint8 ipv6_mapped_ipv4 12 127;
  Cstruct.set_uint8 ipv6_mapped_ipv4 13 0;
  Cstruct.set_uint8 ipv6_mapped_ipv4 14 0;
  Cstruct.set_uint8 ipv6_mapped_ipv4 15 1;
  let msg : Types.version_msg = {
    protocol_version = 70016l;
    services = 1L;
    timestamp = 1234567890L;
    addr_recv = { services = 1L; addr = ipv6_mapped_ipv4; port = 8333 };
    addr_from = { services = 1L; addr = ipv6_mapped_ipv4; port = 8333 };
    nonce = 0x1234567890abcdefL;
    user_agent = "/camlcoin:0.1.0/";
    start_height = 500000l;
    relay = true;
  } in
  let w = Serialize.writer_create () in
  Serialize.serialize_version_msg w msg;
  let cs = Serialize.writer_to_cstruct w in
  let r = Serialize.reader_of_cstruct cs in
  let result = Serialize.deserialize_version_msg r in
  Alcotest.(check int32) "protocol_version" msg.protocol_version result.protocol_version;
  Alcotest.(check int64) "services" msg.services result.services;
  Alcotest.(check string) "user_agent" msg.user_agent result.user_agent;
  Alcotest.(check int32) "start_height" msg.start_height result.start_height;
  Alcotest.(check bool) "relay" msg.relay result.relay

(* Integer roundtrip tests *)
let test_int32_le_roundtrip () =
  let values = [0l; 1l; 0xFFl; 0xFFFFl; 0x7FFFFFFFl; -1l] in
  List.iter (fun v ->
    let w = Serialize.writer_create () in
    Serialize.write_int32_le w v;
    let cs = Serialize.writer_to_cstruct w in
    let r = Serialize.reader_of_cstruct cs in
    let result = Serialize.read_int32_le r in
    Alcotest.(check int32) "int32 roundtrip" v result
  ) values

let test_int64_le_roundtrip () =
  let values = [0L; 1L; 0xFFL; 0xFFFFL; 0x7FFFFFFFL; -1L; 5_000_000_000L] in
  List.iter (fun v ->
    let w = Serialize.writer_create () in
    Serialize.write_int64_le w v;
    let cs = Serialize.writer_to_cstruct w in
    let r = Serialize.reader_of_cstruct cs in
    let result = Serialize.read_int64_le r in
    Alcotest.(check int64) "int64 roundtrip" v result
  ) values

(* QCheck property tests for CompactSize *)
let qcheck_compact_size_roundtrip =
  QCheck.Test.make ~count:1000 ~name:"compact_size roundtrip"
    QCheck.(int_range 0 0xFFFFFF)
    (fun n ->
      let w = Serialize.writer_create () in
      Serialize.write_compact_size w n;
      let cs = Serialize.writer_to_cstruct w in
      let r = Serialize.reader_of_cstruct cs in
      let result = Serialize.read_compact_size r in
      result = n)

let qcheck_int32_roundtrip =
  QCheck.Test.make ~count:1000 ~name:"int32_le roundtrip"
    QCheck.int32
    (fun v ->
      let w = Serialize.writer_create () in
      Serialize.write_int32_le w v;
      let cs = Serialize.writer_to_cstruct w in
      let r = Serialize.reader_of_cstruct cs in
      let result = Serialize.read_int32_le r in
      result = v)

let () =
  let open Alcotest in
  run "test_serialize" [
    "compact_size", [
      test_case "small value" `Quick test_compact_size_small;
      test_case "0xFD marker" `Quick test_compact_size_fd;
      test_case "0xFE marker" `Quick test_compact_size_fe;
      test_case "roundtrip" `Quick test_compact_size_roundtrip;
    ];
    "integers", [
      test_case "int32_le roundtrip" `Quick test_int32_le_roundtrip;
      test_case "int64_le roundtrip" `Quick test_int64_le_roundtrip;
    ];
    "block_header", [
      test_case "size is 80 bytes" `Quick test_block_header_size;
      test_case "roundtrip" `Quick test_block_header_roundtrip;
    ];
    "transaction", [
      test_case "simple tx roundtrip" `Quick test_simple_tx_roundtrip;
      test_case "coinbase tx" `Quick test_coinbase_tx;
      test_case "segwit tx" `Quick test_segwit_tx;
    ];
    "version_msg", [
      test_case "roundtrip" `Quick test_version_msg_roundtrip;
    ];
    "property_tests", [
      QCheck_alcotest.to_alcotest qcheck_compact_size_roundtrip;
      QCheck_alcotest.to_alcotest qcheck_int32_roundtrip;
    ];
  ]
