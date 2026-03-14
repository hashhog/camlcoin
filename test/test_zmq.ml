(* Tests for ZMQ notification module *)

open Camlcoin

(* ============================================================================
   Test Helpers
   ============================================================================ *)

(* Generate a random-ish hash for testing *)
let make_test_hash (seed : int) : Types.hash256 =
  let h = Cstruct.create 32 in
  for i = 0 to 31 do
    Cstruct.set_uint8 h i ((seed * (i + 1)) mod 256)
  done;
  h

(* Create a minimal test transaction *)
let make_test_tx () : Types.transaction =
  let txid = make_test_hash 42 in
  let input : Types.tx_in = {
    previous_output = { txid; vout = 0l };
    script_sig = Cstruct.of_string "\x00";
    sequence = 0xFFFFFFFFl;
  } in
  let output : Types.tx_out = {
    value = 1_000_000L;
    script_pubkey = Cstruct.of_string "\x76\xa9\x14";
  } in
  Types.{
    version = 1l;
    inputs = [input];
    outputs = [output];
    witnesses = [];
    locktime = 0l;
  }

(* Create a minimal test block *)
let make_test_block () : Types.block =
  let header : Types.block_header = {
    version = 1l;
    prev_block = make_test_hash 0;
    merkle_root = make_test_hash 1;
    timestamp = 1234567890l;
    bits = 0x1d00ffffl;
    nonce = 12345l;
  } in
  let tx = make_test_tx () in
  Types.{ header; transactions = [tx] }

(* ============================================================================
   Unit Tests
   ============================================================================ *)

(* Test: topic_to_string returns correct topic names *)
let test_topic_to_string () =
  Alcotest.(check string) "hashblock" "hashblock"
    (Zmq_notify.topic_to_string Zmq_notify.HashBlock);
  Alcotest.(check string) "hashtx" "hashtx"
    (Zmq_notify.topic_to_string Zmq_notify.HashTx);
  Alcotest.(check string) "rawblock" "rawblock"
    (Zmq_notify.topic_to_string Zmq_notify.RawBlock);
  Alcotest.(check string) "rawtx" "rawtx"
    (Zmq_notify.topic_to_string Zmq_notify.RawTx);
  Alcotest.(check string) "sequence" "sequence"
    (Zmq_notify.topic_to_string Zmq_notify.Sequence)

(* Test: disabled notifier returns true for all notifications *)
let test_disabled_notifier () =
  let notifier = Zmq_notify.create_disabled () in
  Alcotest.(check bool) "is_enabled" false (Zmq_notify.is_enabled notifier);
  (* All notifications should succeed (no-op) *)
  let hash = make_test_hash 1 in
  Alcotest.(check bool) "notify_hashblock" true
    (Zmq_notify.notify_hashblock notifier hash);
  Alcotest.(check bool) "notify_hashtx" true
    (Zmq_notify.notify_hashtx notifier hash);
  let block = make_test_block () in
  Alcotest.(check bool) "notify_rawblock" true
    (Zmq_notify.notify_rawblock notifier block);
  let tx = make_test_tx () in
  Alcotest.(check bool) "notify_rawtx" true
    (Zmq_notify.notify_rawtx notifier tx);
  Alcotest.(check bool) "notify_block_connect" true
    (Zmq_notify.notify_block_connect notifier hash);
  Alcotest.(check bool) "notify_tx_acceptance" true
    (Zmq_notify.notify_tx_acceptance notifier hash 1L);
  (* Cleanup *)
  Zmq_notify.shutdown notifier

(* Test: Config.parse_topic_name parses all topic names *)
let test_parse_topic_name () =
  let open Zmq_notify.Config in
  Alcotest.(check (option (testable
    (Fmt.of_to_string (fun t -> Zmq_notify.topic_to_string t))
    (=)))) "hashblock"
    (Some Zmq_notify.HashBlock) (parse_topic_name "hashblock");
  Alcotest.(check (option (testable
    (Fmt.of_to_string (fun t -> Zmq_notify.topic_to_string t))
    (=)))) "pubhashblock"
    (Some Zmq_notify.HashBlock) (parse_topic_name "pubhashblock");
  Alcotest.(check (option (testable
    (Fmt.of_to_string (fun t -> Zmq_notify.topic_to_string t))
    (=)))) "hashtx"
    (Some Zmq_notify.HashTx) (parse_topic_name "hashtx");
  Alcotest.(check (option (testable
    (Fmt.of_to_string (fun t -> Zmq_notify.topic_to_string t))
    (=)))) "rawblock"
    (Some Zmq_notify.RawBlock) (parse_topic_name "rawblock");
  Alcotest.(check (option (testable
    (Fmt.of_to_string (fun t -> Zmq_notify.topic_to_string t))
    (=)))) "rawtx"
    (Some Zmq_notify.RawTx) (parse_topic_name "rawtx");
  Alcotest.(check (option (testable
    (Fmt.of_to_string (fun t -> Zmq_notify.topic_to_string t))
    (=)))) "sequence"
    (Some Zmq_notify.Sequence) (parse_topic_name "sequence");
  (* Invalid topic returns None *)
  Alcotest.(check bool) "invalid" true
    (parse_topic_name "invalid" = None)

(* Test: Config.parse_zmq_option parses -zmqpub options *)
let test_parse_zmq_option () =
  let open Zmq_notify.Config in
  (* Valid option *)
  let opt = parse_zmq_option "-zmqpubhashblock=tcp://127.0.0.1:28332" in
  (match opt with
   | Some { topic; address } ->
     Alcotest.(check string) "topic" "hashblock"
       (Zmq_notify.topic_to_string topic);
     Alcotest.(check string) "address" "tcp://127.0.0.1:28332" address
   | None -> Alcotest.fail "expected Some");
  (* With 'pub' prefix *)
  let opt2 = parse_zmq_option "-zmqpubpubhashtx=tcp://127.0.0.1:28333" in
  (match opt2 with
   | Some { topic; address } ->
     Alcotest.(check string) "topic" "hashtx"
       (Zmq_notify.topic_to_string topic);
     Alcotest.(check string) "address" "tcp://127.0.0.1:28333" address
   | None -> Alcotest.fail "expected Some for pubhashtx");
  (* Invalid prefix *)
  let opt3 = parse_zmq_option "-notzmq=blah" in
  Alcotest.(check bool) "invalid prefix" true (opt3 = None);
  (* Invalid topic *)
  let opt4 = parse_zmq_option "-zmqpubinvalid=tcp://x" in
  Alcotest.(check bool) "invalid topic" true (opt4 = None);
  (* No equals sign *)
  let opt5 = parse_zmq_option "-zmqpubhashblock" in
  Alcotest.(check bool) "no equals" true (opt5 = None)

(* Test: Config.build_configs groups options by address *)
let test_build_configs () =
  let open Zmq_notify.Config in
  let opts = [
    { topic = Zmq_notify.HashBlock; address = "tcp://127.0.0.1:28332" };
    { topic = Zmq_notify.HashTx; address = "tcp://127.0.0.1:28332" };
    { topic = Zmq_notify.RawBlock; address = "tcp://127.0.0.1:28333" };
  ] in
  let configs = build_configs opts in
  (* Should have 2 configs (2 different addresses) *)
  Alcotest.(check int) "num configs" 2 (List.length configs);
  (* Find config for 28332 *)
  let cfg1 = List.find_opt (fun (c : Zmq_notify.endpoint_config) -> c.address = "tcp://127.0.0.1:28332") configs in
  (match cfg1 with
   | Some c ->
     Alcotest.(check int) "topics on 28332" 2 (List.length c.topics);
     Alcotest.(check bool) "has hashblock" true
       (List.mem Zmq_notify.HashBlock c.topics);
     Alcotest.(check bool) "has hashtx" true
       (List.mem Zmq_notify.HashTx c.topics)
   | None -> Alcotest.fail "expected config for 28332");
  (* Find config for 28333 *)
  let cfg2 = List.find_opt (fun (c : Zmq_notify.endpoint_config) -> c.address = "tcp://127.0.0.1:28333") configs in
  (match cfg2 with
   | Some c ->
     Alcotest.(check int) "topics on 28333" 1 (List.length c.topics);
     Alcotest.(check bool) "has rawblock" true
       (List.mem Zmq_notify.RawBlock c.topics)
   | None -> Alcotest.fail "expected config for 28333")

(* Test: create_from_options with empty list returns disabled notifier *)
let test_create_from_empty_options () =
  let notifier = Zmq_notify.Config.create_from_options [] in
  Alcotest.(check bool) "is_enabled" false (Zmq_notify.is_enabled notifier);
  Zmq_notify.shutdown notifier

(* Test: create notifier with topics *)
let test_create_notifier () =
  let config : Zmq_notify.endpoint_config = {
    address = "tcp://127.0.0.1:28332";
    topics = [Zmq_notify.HashBlock; Zmq_notify.HashTx];
    high_water_mark = 100;
  } in
  let notifier = Zmq_notify.create [config] in
  Alcotest.(check bool) "is_enabled" true (Zmq_notify.is_enabled notifier);
  (* Send some notifications *)
  let hash = make_test_hash 99 in
  Alcotest.(check bool) "notify_hashblock" true
    (Zmq_notify.notify_hashblock notifier hash);
  Alcotest.(check bool) "notify_hashtx" true
    (Zmq_notify.notify_hashtx notifier hash);
  (* Sequence number should have incremented *)
  let seq_block = Zmq_notify.get_sequence notifier Zmq_notify.HashBlock in
  let seq_tx = Zmq_notify.get_sequence notifier Zmq_notify.HashTx in
  (match seq_block with
   | Some s -> Alcotest.(check int32) "hashblock sequence" 1l s
   | None -> Alcotest.fail "expected sequence for hashblock");
  (match seq_tx with
   | Some s -> Alcotest.(check int32) "hashtx sequence" 1l s
   | None -> Alcotest.fail "expected sequence for hashtx");
  (* RawBlock was not configured, so no sequence *)
  let seq_raw = Zmq_notify.get_sequence notifier Zmq_notify.RawBlock in
  Alcotest.(check bool) "rawblock not configured" true (seq_raw = None);
  (* Shutdown *)
  Zmq_notify.shutdown notifier;
  Alcotest.(check bool) "is_enabled after shutdown" false
    (Zmq_notify.is_enabled notifier)

(* Test: message queueing works *)
let test_message_queue () =
  let config : Zmq_notify.endpoint_config = {
    address = "tcp://127.0.0.1:28332";
    topics = [Zmq_notify.HashBlock];
    high_water_mark = 10;
  } in
  let notifier = Zmq_notify.create [config] in
  (* No callback set, so messages should be queued *)
  let hash1 = make_test_hash 1 in
  let hash2 = make_test_hash 2 in
  let hash3 = make_test_hash 3 in
  let _ = Zmq_notify.notify_hashblock notifier hash1 in
  let _ = Zmq_notify.notify_hashblock notifier hash2 in
  let _ = Zmq_notify.notify_hashblock notifier hash3 in
  (* Check queue *)
  let msgs = Zmq_notify.get_queued_messages notifier Zmq_notify.HashBlock in
  Alcotest.(check int) "queue length" 3 (List.length msgs);
  (* First message should have sequence 0 *)
  (match msgs with
   | msg :: _ ->
     Alcotest.(check int32) "first seq" 0l msg.sequence;
     Alcotest.(check string) "topic" "hashblock" msg.topic
   | [] -> Alcotest.fail "expected messages");
  (* Drain queue *)
  let drained = Zmq_notify.drain_queue notifier Zmq_notify.HashBlock in
  Alcotest.(check int) "drained length" 3 (List.length drained);
  let remaining = Zmq_notify.get_queued_messages notifier Zmq_notify.HashBlock in
  Alcotest.(check int) "remaining length" 0 (List.length remaining);
  Zmq_notify.shutdown notifier

(* Test: high water mark limits queue size *)
let test_high_water_mark () =
  let config : Zmq_notify.endpoint_config = {
    address = "tcp://127.0.0.1:28332";
    topics = [Zmq_notify.HashBlock];
    high_water_mark = 3;
  } in
  let notifier = Zmq_notify.create [config] in
  (* Send 5 notifications, only 3 should be queued *)
  for i = 1 to 5 do
    let hash = make_test_hash i in
    let _ = Zmq_notify.notify_hashblock notifier hash in
    ()
  done;
  let msgs = Zmq_notify.get_queued_messages notifier Zmq_notify.HashBlock in
  Alcotest.(check int) "queue limited to hwm" 3 (List.length msgs);
  Zmq_notify.shutdown notifier

(* Test: send callback is called *)
let test_send_callback () =
  let config : Zmq_notify.endpoint_config = {
    address = "tcp://127.0.0.1:28332";
    topics = [Zmq_notify.HashBlock; Zmq_notify.HashTx];
    high_water_mark = 100;
  } in
  let notifier = Zmq_notify.create [config] in
  let sent_messages = ref [] in
  (* Set callback *)
  Zmq_notify.set_send_callback notifier (fun msg ->
    sent_messages := msg :: !sent_messages;
    true
  );
  (* Send notifications *)
  let hash1 = make_test_hash 1 in
  let hash2 = make_test_hash 2 in
  let _ = Zmq_notify.notify_hashblock notifier hash1 in
  let _ = Zmq_notify.notify_hashtx notifier hash2 in
  (* Check callback was called *)
  Alcotest.(check int) "callback called twice" 2 (List.length !sent_messages);
  (* Messages should not be queued when callback succeeds *)
  let queued = Zmq_notify.get_queued_messages notifier Zmq_notify.HashBlock in
  Alcotest.(check int) "not queued" 0 (List.length queued);
  Zmq_notify.shutdown notifier

(* Test: failed callback queues messages *)
let test_failed_callback_queues () =
  let config : Zmq_notify.endpoint_config = {
    address = "tcp://127.0.0.1:28332";
    topics = [Zmq_notify.HashBlock];
    high_water_mark = 100;
  } in
  let notifier = Zmq_notify.create [config] in
  (* Set callback that fails *)
  Zmq_notify.set_send_callback notifier (fun _msg -> false);
  let hash = make_test_hash 1 in
  let _ = Zmq_notify.notify_hashblock notifier hash in
  (* Should be queued after failure *)
  let queued = Zmq_notify.get_queued_messages notifier Zmq_notify.HashBlock in
  Alcotest.(check int) "queued after failure" 1 (List.length queued);
  Zmq_notify.shutdown notifier

(* Test: sequence encoding is little-endian *)
let test_sequence_encoding () =
  let config : Zmq_notify.endpoint_config = {
    address = "tcp://127.0.0.1:28332";
    topics = [Zmq_notify.HashBlock];
    high_water_mark = 100;
  } in
  let notifier = Zmq_notify.create [config] in
  let captured_msgs = ref [] in
  Zmq_notify.set_send_callback notifier (fun msg ->
    captured_msgs := msg :: !captured_msgs;
    true
  );
  let hash = make_test_hash 1 in
  let _ = Zmq_notify.notify_hashblock notifier hash in
  (* Check sequence encoding *)
  (match !captured_msgs with
   | [msg] ->
     (* Encode the sequence *)
     let parts = Zmq_notify.Encoding.encode_message msg in
     Alcotest.(check int) "3 parts" 3 (List.length parts);
     let seq_bytes = List.nth parts 2 in
     Alcotest.(check int) "seq length" 4 (String.length seq_bytes);
     (* Verify it's little-endian 0 *)
     Alcotest.(check char) "byte 0" '\x00' seq_bytes.[0];
     Alcotest.(check char) "byte 1" '\x00' seq_bytes.[1];
     Alcotest.(check char) "byte 2" '\x00' seq_bytes.[2];
     Alcotest.(check char) "byte 3" '\x00' seq_bytes.[3]
   | _ -> Alcotest.fail "expected one message");
  Zmq_notify.shutdown notifier

(* Test: raw block notification includes serialized block *)
let test_rawblock_content () =
  let config : Zmq_notify.endpoint_config = {
    address = "tcp://127.0.0.1:28332";
    topics = [Zmq_notify.RawBlock];
    high_water_mark = 100;
  } in
  let notifier = Zmq_notify.create [config] in
  let captured_msgs = ref [] in
  Zmq_notify.set_send_callback notifier (fun msg ->
    captured_msgs := msg :: !captured_msgs;
    true
  );
  let block = make_test_block () in
  let _ = Zmq_notify.notify_rawblock notifier block in
  (match !captured_msgs with
   | [msg] ->
     Alcotest.(check string) "topic" "rawblock" msg.topic;
     (* Verify we can deserialize the block *)
     let r = Serialize.reader_of_cstruct (Cstruct.of_string msg.data) in
     let deserialized = Serialize.deserialize_block r in
     Alcotest.(check int32) "version" block.header.version
       deserialized.header.version;
     Alcotest.(check int) "tx count" 1 (List.length deserialized.transactions)
   | _ -> Alcotest.fail "expected one message");
  Zmq_notify.shutdown notifier

(* Test: sequence notification for block connect *)
let test_sequence_block_connect () =
  let config : Zmq_notify.endpoint_config = {
    address = "tcp://127.0.0.1:28332";
    topics = [Zmq_notify.Sequence];
    high_water_mark = 100;
  } in
  let notifier = Zmq_notify.create [config] in
  let captured_msgs = ref [] in
  Zmq_notify.set_send_callback notifier (fun msg ->
    captured_msgs := msg :: !captured_msgs;
    true
  );
  let hash = make_test_hash 100 in
  let _ = Zmq_notify.notify_block_connect notifier hash in
  (match !captured_msgs with
   | [msg] ->
     Alcotest.(check string) "topic" "sequence" msg.topic;
     (* Data should be 33 bytes: 32-byte hash + 1-byte label *)
     Alcotest.(check int) "data length" 33 (String.length msg.data);
     (* Last byte should be 'C' for connect *)
     Alcotest.(check char) "label" 'C' msg.data.[32]
   | _ -> Alcotest.fail "expected one message");
  Zmq_notify.shutdown notifier

(* Test: sequence notification for tx acceptance includes mempool sequence *)
let test_sequence_tx_acceptance () =
  let config : Zmq_notify.endpoint_config = {
    address = "tcp://127.0.0.1:28332";
    topics = [Zmq_notify.Sequence];
    high_water_mark = 100;
  } in
  let notifier = Zmq_notify.create [config] in
  let captured_msgs = ref [] in
  Zmq_notify.set_send_callback notifier (fun msg ->
    captured_msgs := msg :: !captured_msgs;
    true
  );
  let txid = make_test_hash 200 in
  let mempool_seq = 12345L in
  let _ = Zmq_notify.notify_tx_acceptance notifier txid mempool_seq in
  (match !captured_msgs with
   | [msg] ->
     Alcotest.(check string) "topic" "sequence" msg.topic;
     (* Data should be 41 bytes: 32-byte hash + 1-byte label + 8-byte mempool seq *)
     Alcotest.(check int) "data length" 41 (String.length msg.data);
     (* Label should be 'A' for acceptance *)
     Alcotest.(check char) "label" 'A' msg.data.[32];
     (* Check mempool sequence *)
     let mp_seq_cs = Cstruct.of_string (String.sub msg.data 33 8) in
     let mp_seq = Cstruct.LE.get_uint64 mp_seq_cs 0 in
     Alcotest.(check int64) "mempool sequence" mempool_seq mp_seq
   | _ -> Alcotest.fail "expected one message");
  Zmq_notify.shutdown notifier

(* Test: hash is reversed (display format) *)
let test_hash_reversal () =
  let config : Zmq_notify.endpoint_config = {
    address = "tcp://127.0.0.1:28332";
    topics = [Zmq_notify.HashBlock];
    high_water_mark = 100;
  } in
  let notifier = Zmq_notify.create [config] in
  let captured_msgs = ref [] in
  Zmq_notify.set_send_callback notifier (fun msg ->
    captured_msgs := msg :: !captured_msgs;
    true
  );
  (* Create a known hash *)
  let hash = Cstruct.create 32 in
  for i = 0 to 31 do
    Cstruct.set_uint8 hash i i  (* 0, 1, 2, ..., 31 *)
  done;
  let _ = Zmq_notify.notify_hashblock notifier hash in
  (match !captured_msgs with
   | [msg] ->
     Alcotest.(check int) "data length" 32 (String.length msg.data);
     (* First byte in message should be last byte of hash (31) *)
     Alcotest.(check int) "first byte reversed" 31 (Char.code msg.data.[0]);
     (* Last byte in message should be first byte of hash (0) *)
     Alcotest.(check int) "last byte reversed" 0 (Char.code msg.data.[31])
   | _ -> Alcotest.fail "expected one message");
  Zmq_notify.shutdown notifier

(* Test: Encoding.decode_message *)
let test_decode_message () =
  let msg : Zmq_notify.zmq_message = {
    topic = "hashblock";
    data = String.make 32 'x';
    sequence = 42l;
  } in
  let parts = Zmq_notify.Encoding.encode_message msg in
  let decoded = Zmq_notify.Encoding.decode_message parts in
  (match decoded with
   | Some d ->
     Alcotest.(check string) "topic" msg.topic d.topic;
     Alcotest.(check string) "data" msg.data d.data;
     Alcotest.(check int32) "sequence" msg.sequence d.sequence
   | None -> Alcotest.fail "decode failed");
  (* Invalid decode *)
  let bad = Zmq_notify.Encoding.decode_message ["a"; "b"] in
  Alcotest.(check bool) "bad decode" true (bad = None);
  let bad2 = Zmq_notify.Encoding.decode_message ["a"; "b"; "c"] in  (* seq too short *)
  Alcotest.(check bool) "bad seq length" true (bad2 = None)

(* Test: Lwt async wrappers work correctly *)
let test_lwt_wrappers () =
  let notifier = Zmq_notify.create_disabled () in
  let open Lwt.Infix in
  let test =
    let hash = make_test_hash 42 in
    Zmq_notify.Lwt.notify_hashblock notifier hash >>= fun result ->
    Alcotest.(check bool) "lwt notify_hashblock" true result;
    Zmq_notify.Lwt.notify_hashtx notifier hash >>= fun result ->
    Alcotest.(check bool) "lwt notify_hashtx" true result;
    Lwt.return_unit
  in
  Lwt_main.run test;
  Zmq_notify.shutdown notifier

(* Test: default notifier configuration *)
let test_default_notifier () =
  let notifier = Zmq_notify.create_default () in
  Alcotest.(check bool) "is_enabled" true (Zmq_notify.is_enabled notifier);
  (* Should have all topics configured *)
  let seq_block = Zmq_notify.get_sequence notifier Zmq_notify.HashBlock in
  let seq_tx = Zmq_notify.get_sequence notifier Zmq_notify.HashTx in
  let seq_raw_block = Zmq_notify.get_sequence notifier Zmq_notify.RawBlock in
  let seq_raw_tx = Zmq_notify.get_sequence notifier Zmq_notify.RawTx in
  let seq_sequence = Zmq_notify.get_sequence notifier Zmq_notify.Sequence in
  Alcotest.(check bool) "has hashblock" true (seq_block <> None);
  Alcotest.(check bool) "has hashtx" true (seq_tx <> None);
  Alcotest.(check bool) "has rawblock" true (seq_raw_block <> None);
  Alcotest.(check bool) "has rawtx" true (seq_raw_tx <> None);
  Alcotest.(check bool) "has sequence" true (seq_sequence <> None);
  Zmq_notify.shutdown notifier

(* ============================================================================
   Test Runner
   ============================================================================ *)

let () =
  let open Alcotest in
  run "ZMQ Notifications" [
    "topic_names", [
      test_case "topic_to_string" `Quick test_topic_to_string;
    ];
    "disabled_notifier", [
      test_case "all notifications succeed" `Quick test_disabled_notifier;
    ];
    "config_parsing", [
      test_case "parse_topic_name" `Quick test_parse_topic_name;
      test_case "parse_zmq_option" `Quick test_parse_zmq_option;
      test_case "build_configs" `Quick test_build_configs;
      test_case "create_from_empty_options" `Quick test_create_from_empty_options;
    ];
    "notifier_lifecycle", [
      test_case "create notifier" `Quick test_create_notifier;
      test_case "default notifier" `Quick test_default_notifier;
    ];
    "message_queue", [
      test_case "message queueing" `Quick test_message_queue;
      test_case "high water mark" `Quick test_high_water_mark;
    ];
    "send_callback", [
      test_case "callback is called" `Quick test_send_callback;
      test_case "failed callback queues" `Quick test_failed_callback_queues;
    ];
    "message_format", [
      test_case "sequence encoding" `Quick test_sequence_encoding;
      test_case "rawblock content" `Quick test_rawblock_content;
      test_case "sequence block connect" `Quick test_sequence_block_connect;
      test_case "sequence tx acceptance" `Quick test_sequence_tx_acceptance;
      test_case "hash reversal" `Quick test_hash_reversal;
      test_case "decode message" `Quick test_decode_message;
    ];
    "lwt_integration", [
      test_case "lwt wrappers" `Quick test_lwt_wrappers;
    ];
  ]
