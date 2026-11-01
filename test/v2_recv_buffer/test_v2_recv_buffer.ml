(* BIP-324 v2 receive path: allocation budget and pre-version decoy bound
   (security audit 2026-10-31, H3).

   [P2p.v2_receive_bytes] used to run [Cstruct.concat [recv_buffer; data]]
   on every read, so a 4 MB packet arriving in 4 KiB reads allocated and
   copied ~2 GB.  Decoy (ignore-bit) packets were accepted before the
   version packet without limit, so the cost was reachable without a
   version message.

   The allocation budget is measured from outside: after every read we look
   at the bigarray backing [state.recv_buffer] and add its size whenever it
   is a new one.  Core (net.cpp V2Transport::ReceivedBytes) grows its
   buffer with a bounded reserve-ahead, so total allocation stays linear in
   the packet size. *)

open Camlcoin

let magic = P2p.regtest_magic

let get_v2 = function
  | P2p.V2 s -> s
  | P2p.V1 _ -> Alcotest.fail "expected a V2 transport"

(* Full handshake between two state machines; returns (initiator, responder)
   both in the application phase. *)
let handshake () =
  let is = get_v2 (P2p.create_v2_transport ~initiating:true ~magic) in
  let rs = get_v2 (P2p.create_v2_transport ~initiating:false ~magic) in
  let pump src dst =
    let b = P2p.v2_get_bytes_to_send src in
    if Cstruct.length b > 0 then
      Alcotest.(check bool) "handshake bytes accepted" true
        (P2p.v2_receive_bytes dst b)
  in
  pump is rs; pump rs is; pump is rs;
  Alcotest.(check bool) "responder in app phase" true
    (rs.recv_state = P2p.V2RecvApp);
  (is, rs)

(* Responder whose peer is a "shadow" initiator: we compute the initiator's
   cipher ourselves so we can choose what follows the garbage terminator
   (the real initiator state machine always emits its version packet first).
   Returns the responder (in V2RecvVersion), the shadow cipher and the AAD
   the first packet must carry (the initiator's garbage). *)
let responder_awaiting_version () =
  let is = get_v2 (P2p.create_v2_transport ~initiating:true ~magic) in
  let rs = get_v2 (P2p.create_v2_transport ~initiating:false ~magic) in
  let ecdh_secret =
    P2p.compute_ecdh_secret is.our_privkey rs.our_ellswift_pubkey
      is.our_ellswift_pubkey true in
  let shadow =
    P2p.init_bip324_cipher ~ecdh_secret ~initiator:true ~network_magic:magic in
  let hello = P2p.v2_get_bytes_to_send is in
  Alcotest.(check bool) "pubkey+garbage accepted" true
    (P2p.v2_receive_bytes rs hello);
  Alcotest.(check bool) "terminator accepted" true
    (P2p.v2_receive_bytes rs shadow.send_garbage_terminator);
  Alcotest.(check bool) "responder waits for version" true
    (rs.recv_state = P2p.V2RecvVersion);
  (rs, shadow, is.send_garbage)

let feed_chunked state bytes chunk ~on_read =
  let n = Cstruct.length bytes in
  let rec go off =
    if off < n then begin
      let len = min chunk (n - off) in
      (* Fresh copy per read, as peer.ml does with Cstruct.of_bytes. *)
      let ok = P2p.v2_receive_bytes state (Cstruct.sub_copy bytes off len) in
      if not ok then Alcotest.fail "v2_receive_bytes rejected valid bytes";
      on_read ();
      go (off + len)
    end
  in
  go 0

(* Sum of the sizes of every distinct backing buffer recv_buffer has used. *)
let alloc_tracker state =
  let last = ref (Cstruct.empty).Cstruct.buffer in
  let total = ref 0 and count = ref 0 in
  let observe () =
    let b = state.P2p.recv_buffer.Cstruct.buffer in
    if b != !last then begin
      last := b;
      incr count;
      total := !total + Bigarray.Array1.dim b
    end
  in
  (observe, total, count)

let test_4mb_packet_4k_reads_alloc_budget () =
  let is, rs = handshake () in
  let cipher = Option.get is.cipher in
  let contents_len = 3_999_000 in
  let contents = Cstruct.create contents_len in
  for i = 0 to contents_len - 1 do
    Cstruct.set_uint8 contents i ((i * 31 + 7) land 0xff)
  done;
  let ct = P2p.bip324_encrypt cipher ~aad:Cstruct.empty ~contents ~ignore:false in
  let observe, total, count = alloc_tracker rs in
  feed_chunked rs ct 4096 ~on_read:observe;
  Alcotest.(check bool) "packet decoded" true (P2p.v2_message_complete rs);
  Alcotest.(check bool) "contents byte-exact" true
    (Cstruct.equal rs.recv_decode_buffer contents);
  let budget = 3 * Cstruct.length ct in
  Printf.printf "4 MB packet in 4 KiB reads: %d buffers, %d bytes allocated \
                 (budget %d)\n%!" !count !total budget;
  if !total > budget then
    Alcotest.failf "receive buffer allocated %d bytes in %d buffers for one \
                    %d-byte packet (budget %d)" !total !count
      (Cstruct.length ct) budget

(* Decoy packets before the version packet are bounded: a peer that never
   sends version cannot make us decrypt an unbounded stream. *)
let test_pre_version_decoy_flood_rejected () =
  let rs, shadow, garbage = responder_awaiting_version () in
  let decoy_len = 1_000_000 in
  let rec flood i aad =
    if i > 20 then
      Alcotest.fail "20 MB of decoys before version were all accepted"
    else begin
      let ct = P2p.bip324_encrypt shadow ~aad
          ~contents:(Cstruct.create decoy_len) ~ignore:true in
      if P2p.v2_receive_bytes rs ct then begin
        Alcotest.(check bool) "still waiting for version" true
          (rs.recv_state = P2p.V2RecvVersion);
        flood (i + 1) Cstruct.empty
      end else i
    end
  in
  let rejected_at = flood 1 garbage in
  Printf.printf "decoy flood rejected at decoy #%d (%d bytes each)\n%!"
    rejected_at decoy_len;
  Alcotest.(check bool) "rejected within 5 MB of decoys" true (rejected_at <= 5)

(* A few decoys before version (what BIP-324 allows a sender to do) still
   complete the handshake, and the first one carries the garbage AAD. *)
let test_small_pre_version_decoys_accepted () =
  let rs, shadow, garbage = responder_awaiting_version () in
  let aad = ref garbage in
  for _ = 1 to 3 do
    let ct = P2p.bip324_encrypt shadow ~aad:!aad
        ~contents:(Cstruct.create 1000) ~ignore:true in
    aad := Cstruct.empty;
    Alcotest.(check bool) "decoy accepted" true (P2p.v2_receive_bytes rs ct)
  done;
  let version = P2p.bip324_encrypt shadow ~aad:Cstruct.empty
      ~contents:Cstruct.empty ~ignore:false in
  Alcotest.(check bool) "version accepted" true (P2p.v2_receive_bytes rs version);
  Alcotest.(check bool) "responder reaches app phase" true
    (rs.recv_state = P2p.V2RecvApp)

(* Framing stays byte-exact for a stream of mixed packets (empty, small,
   large, decoys) cut at arbitrary read boundaries, including several
   packets in one read and a read that ends inside the 3-byte length. *)
let test_mixed_stream_random_chunks () =
  let is, rs = handshake () in
  let cipher = Option.get is.cipher in
  Random.init 324;
  let sizes = [0; 1; 2; 13; 4095; 4096; 4097; 70_000; 0; 300_000;
               1_000_000; 5; 262_144; 262_145; 9] in
  let expected = ref [] in
  let stream =
    Cstruct.concat (List.concat_map (fun sz ->
        let c = Cstruct.create sz in
        for i = 0 to sz - 1 do Cstruct.set_uint8 c i (Random.int 256) done;
        let decoy = Random.int 4 = 0 in
        let d = if decoy then
            [P2p.bip324_encrypt cipher ~aad:Cstruct.empty
               ~contents:(Cstruct.create (Random.int 5000)) ~ignore:true]
          else [] in
        expected := c :: !expected;
        d @ [P2p.bip324_encrypt cipher ~aad:Cstruct.empty ~contents:c
               ~ignore:false]) sizes) in
  let expected = List.rev !expected in
  let got = ref [] in
  let drain () =
    while P2p.v2_message_complete rs do
      got := rs.recv_decode_buffer :: !got;
      rs.recv_decode_buffer <- Cstruct.empty;
      rs.recv_state <- P2p.V2RecvApp;
      if not (P2p.v2_receive_bytes rs Cstruct.empty) then
        Alcotest.fail "drain rejected buffered bytes"
    done
  in
  let n = Cstruct.length stream in
  let rec go off =
    if off < n then begin
      let len = min (n - off)
          (match Random.int 4 with
           | 0 -> 1 + Random.int 3
           | 1 -> 1 + Random.int 200
           | 2 -> 1 + Random.int 9000
           | _ -> 1 + Random.int 600_000) in
      if not (P2p.v2_receive_bytes rs (Cstruct.sub_copy stream off len)) then
        Alcotest.fail "valid stream rejected";
      drain ();
      go (off + len)
    end
  in
  go 0;
  let got = List.rev !got in
  Alcotest.(check int) "message count" (List.length expected) (List.length got);
  List.iteri (fun i (e, g) ->
      if not (Cstruct.equal e g) then
        Alcotest.failf "message %d (%d bytes) corrupted" i (Cstruct.length e))
    (List.combine expected got);
  Alcotest.(check int) "nothing left over" 0 (Cstruct.length rs.recv_buffer)

(* A tampered packet is still rejected (the auth tag covers every byte that
   the in-place buffer assembled). *)
let test_tampered_packet_rejected () =
  let is, rs = handshake () in
  let cipher = Option.get is.cipher in
  let ct = P2p.bip324_encrypt cipher ~aad:Cstruct.empty
      ~contents:(Cstruct.create 500_000) ~ignore:false in
  let bad = Cstruct.sub_copy ct 0 (Cstruct.length ct) in
  let pos = 250_000 in
  Cstruct.set_uint8 bad pos (Cstruct.get_uint8 bad pos lxor 1);
  let rejected = ref false in
  let n = Cstruct.length bad in
  let rec go off =
    if off < n && not !rejected then begin
      let len = min 4096 (n - off) in
      if not (P2p.v2_receive_bytes rs (Cstruct.sub_copy bad off len)) then
        rejected := true;
      go (off + len)
    end
  in
  go 0;
  Alcotest.(check bool) "tampered packet rejected" true !rejected;
  Alcotest.(check bool) "no message delivered" false (P2p.v2_message_complete rs)

let () =
  Alcotest.run "v2_recv_buffer" [
    "v2_recv_buffer", [
      Alcotest.test_case "4 MB packet in 4 KiB reads stays within allocation budget"
        `Quick test_4mb_packet_4k_reads_alloc_budget;
      Alcotest.test_case "decoy flood before version is rejected"
        `Quick test_pre_version_decoy_flood_rejected;
      Alcotest.test_case "small decoys before version still accepted"
        `Quick test_small_pre_version_decoys_accepted;
      Alcotest.test_case "mixed packet stream in random reads is byte-exact"
        `Quick test_mixed_stream_random_chunks;
      Alcotest.test_case "tampered packet is rejected"
        `Quick test_tampered_packet_rejected;
    ]
  ]
