(* Unrequested blocks during IBD are dropped, not pooled (security audit
   2026-10-31 H7) -- end-to-end regtest repro.

   During IBD [Sync.receive_block] stored every block it had not requested
   in [ibd.orphan_blocks] (up to 750 entries, each up to a 4 MB message, no
   header/PoW/size check).  One peer could therefore pin ~3 GB of heap.

   The test boots a fresh regtest node and connects an honest peer that
   announces 5 headers but withholds the bodies, so the node sits in IBD
   with a request outstanding.  An attacker (NODE_WITNESS only, never a
   download peer) then sends [n_blocks] unrequested ~3.5 MB blocks with no
   valid PoW and an unknown parent.  The node's RSS must not grow by
   anything like the bytes sent.

     dune build @test/ibd_orphan_blocks/runtest *)

open Camlcoin

(* ---- chain building ---------------------------------------------------- *)

let op_true = Cstruct.of_string "\x51"

let remine (block : Types.block) : Types.block =
  let h = ref block.Types.header in
  let n = ref 0l in
  while not (Consensus.hash_meets_target (Crypto.compute_block_hash !h)
               !h.Types.bits) do
    n := Int32.add !n 1l;
    h := { !h with Types.nonce = !n }
  done;
  { block with Types.header = !h }

let build_block ?(fee = 0L) ?(tag = 0) ?(txs = []) ~prev_hash ~height
    ~prev_time () : Types.block =
  let extra_nonce = Cstruct.create 8 in
  Cstruct.LE.set_uint64 extra_nonce 0 (Int64.of_int ((tag * 1_000_000) + height));
  let mk wr =
    Mining.create_coinbase ~height ~total_fee:fee ~payout_script:op_true
      ~extra_nonce ~witness_root:wr ~network_type:Consensus.Regtest ()
  in
  let witness_root = Mining.compute_witness_merkle_root (mk None :: txs) in
  let coinbase = mk (Some witness_root) in
  let all = coinbase :: txs in
  let merkle_root, _ = Crypto.merkle_root (List.map Crypto.compute_txid all) in
  remine
    { Types.header =
        { version = 4l; prev_block = prev_hash; merkle_root;
          timestamp = Int32.add prev_time 600l;
          bits = Consensus.regtest.pow_limit; nonce = 0l };
      transactions = all }

let hash_of (b : Types.block) = Crypto.compute_block_hash b.Types.header

(* ---- node + RPC -------------------------------------------------------- *)

let free_port () =
  let s = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Unix.bind s (Unix.ADDR_INET (Unix.inet_addr_loopback, 0));
  let p = match Unix.getsockname s with
    | Unix.ADDR_INET (_, p) -> p | _ -> assert false in
  Unix.close s; p

let main_exe =
  let p = Filename.concat (Sys.getcwd ()) "../../bin/main.exe" in
  if Sys.file_exists p then p else failwith ("missing " ^ p)

let read_file p =
  let ic = open_in_bin p in
  Fun.protect ~finally:(fun () -> close_in ic)
    (fun () -> really_input_string ic (in_channel_length ic))

type node = { pid : int; rpcport : int; p2pport : int; datadir : string }

let rpc_raw node meth params : (Yojson.Safe.t, string) result =
  let cookie = String.trim (read_file (Filename.concat node.datadir ".cookie")) in
  let body = Yojson.Safe.to_string
      (`Assoc [ "jsonrpc", `String "1.0"; "id", `Int 1;
                "method", `String meth; "params", `List params ]) in
  Lwt_main.run (
    let open Lwt.Syntax in
    Lwt.catch (fun () ->
        let* _, b = Cohttp_lwt_unix.Client.post
            ~headers:(Cohttp.Header.init_with "Authorization"
                        ("Basic " ^ Base64.encode_string cookie))
            ~body:(Cohttp_lwt.Body.of_string body)
            (Uri.of_string (Printf.sprintf "http://127.0.0.1:%d/" node.rpcport)) in
        let* s = Cohttp_lwt.Body.to_string b in
        match Yojson.Safe.from_string s with
        | `Assoc kv ->
          (match List.assoc_opt "error" kv with
           | Some `Null | None ->
             Lwt.return (Ok (Option.value ~default:`Null (List.assoc_opt "result" kv)))
           | Some e -> Lwt.return (Error (Yojson.Safe.to_string e)))
        | _ -> Lwt.return (Error s))
      (fun e -> Lwt.return (Error (Printexc.to_string e))))

let start_node ?(connect = "127.0.0.1:1") datadir rpcport p2pport =
  let log = Filename.concat datadir "node.log" in
  let fd = Unix.openfile log [Unix.O_WRONLY; Unix.O_CREAT; Unix.O_APPEND] 0o600 in
  let args = [| main_exe; "--network=regtest"; "--datadir=" ^ datadir;
                "--rpchost=127.0.0.1"; Printf.sprintf "--rpcport=%d" rpcport;
                Printf.sprintf "--port=%d" p2pport; "--metricsport=0";
                "--nodnsseed"; "--connect=" ^ connect |] in
  let pid = Unix.create_process main_exe args Unix.stdin fd fd in
  Unix.close fd;
  let node = { pid; rpcport; p2pport; datadir } in
  let rec ready n =
    if n = 0 then failwith ("node did not come up; log:\n" ^ read_file log)
    else if not (Sys.file_exists (Filename.concat datadir ".cookie")) then
      (Unix.sleepf 0.2; ready (n - 1))
    else match rpc_raw node "getblockcount" [] with
      | Ok _ -> ()
      | Error _ -> Unix.sleepf 0.2; ready (n - 1) in
  ready 600;
  node

let stop_node node =
  ignore (rpc_raw node "stop" []);
  let rec wait n =
    match Unix.waitpid [Unix.WNOHANG] node.pid with
    | 0, _ when n > 0 -> Unix.sleepf 0.1; wait (n - 1)
    | 0, _ ->
      (* our own child, still up after 30 s: force it *)
      (try Unix.kill node.pid Sys.sigkill with _ -> ());
      ignore (Unix.waitpid [] node.pid)
    | _ -> ()
    | exception Unix.Unix_error (Unix.ECHILD, _, _) -> () in
  wait 300

(* ---- a v1 P2P peer ----------------------------------------------------- *)

let magic = Consensus.regtest.Consensus.magic

let send fd payload =
  let data = P2p.serialize_message magic payload in
  let bytes = Cstruct.to_bytes data in
  let rec go off =
    if off < Bytes.length bytes then
      go (off + Unix.write fd bytes off (Bytes.length bytes - off)) in
  go 0

(* Read exactly [n] bytes before [deadline]; None on timeout or EOF. *)
let read_exact fd n deadline =
  let buf = Bytes.create n in
  let rec go off =
    if off = n then Some buf
    else
      let left = deadline -. Unix.gettimeofday () in
      if left <= 0. then None
      else match Unix.select [fd] [] [] left with
        | [], _, _ -> None
        | _ ->
          let r = Unix.read fd buf off (n - off) in
          if r = 0 then None else go (off + r) in
  go 0

let read_msg fd deadline : P2p.message_payload option =
  match read_exact fd 24 deadline with
  | None -> None
  | Some hdr ->
    let len = Int32.to_int (Bytes.get_int32_le hdr 16) in
    match read_exact fd len deadline with
    | None -> None
    | Some body ->
      let all = Cstruct.of_bytes (Bytes.cat hdr body) in
      (try Some (P2p.deserialize_message all).P2p.payload
       with _ -> Some (P2p.UnknownMsg { cmd = "undecodable"; payload = Cstruct.empty }))

(* Everything the node sends within [secs]; answers pings. *)
let collect fd secs =
  let deadline = Unix.gettimeofday () +. secs in
  let rec go acc =
    match read_msg fd deadline with
    | None -> List.rev acc
    | Some (P2p.PingMsg n) -> send fd (P2p.PongMsg n); go acc
    | Some m -> go (m :: acc) in
  go []

let rec connect_peer ?(ua = "/h7-test:0.1/") ?(services = 9L) node =
  let fd = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Unix.connect fd (Unix.ADDR_INET (Unix.inet_addr_loopback, node.p2pport));
  handshake ~ua ~services fd

and handshake ~ua ~services fd =
  let addr = P2p.empty_net_addr () in
  send fd (P2p.make_version_msg ~protocol_version:70016l ~services
             ~timestamp:(Int64.of_float (Unix.gettimeofday ()))
             ~addr_recv:addr ~addr_from:addr ~nonce:(Random.int64 Int64.max_int)
             ~user_agent:ua ~start_height:0l ~relay:true);
  let deadline = Unix.gettimeofday () +. 15. in
  let rec hs ver ack =
    if not (ver && ack) then
      match read_msg fd deadline with
      | None -> Alcotest.fail "P2P handshake timed out"
      | Some (P2p.VersionMsg _) -> send fd P2p.VerackMsg; hs true ack
      | Some P2p.VerackMsg -> hs ver true
      | Some _ -> hs ver ack in
  hs false false;
  ignore (collect fd 0.5);
  fd



(* ---- the attack ------------------------------------------------------- *)

let n_blocks = 200
let script_bytes = 3_500_000

let rss_kb pid =
  let ic = open_in (Printf.sprintf "/proc/%d/status" pid) in
  Fun.protect ~finally:(fun () -> close_in ic) @@ fun () ->
  let rec go () =
    let l = input_line ic in
    if String.length l > 6 && String.sub l 0 6 = "VmRSS:" then
      Scanf.sscanf l "VmRSS: %d kB" (fun k -> k)
    else go () in
  go ()

(* ~3.5 MB block: one tx whose scriptSig is [script_bytes] of zeros.
   Unknown parent, nonce [n] (distinct hash), PoW not met: none of that is
   checked before an unrequested body is pooled. *)
let fat_block n : Types.block =
  let g = Consensus.regtest.Consensus.genesis_header in
  let prev = Cstruct.create 32 in
  Cstruct.set_uint8 prev 0 0xab;
  let tx = Types.{ version = 1l;
                   inputs = [ { previous_output = { txid = Cstruct.create 32; vout = 0l };
                                script_sig = Cstruct.create script_bytes;
                                sequence = 0xffffffffl } ];
                   outputs = [ { value = 0L; script_pubkey = op_true } ];
                   witnesses = []; locktime = 0l } in
  Types.{ header = { g with prev_block = prev; nonce = Int32.of_int n };
          transactions = [ tx ] }

type outcome = {
  ibd_active : bool;      (* node asked the honest peer for a block *)
  sent : int;             (* fat blocks written before EOF *)
  pong : bool;            (* attacker's ping answered after the flood *)
  rss_before_kb : int;
  rss_after_kb : int;
  alive : bool;
}

let run_attack () : outcome =
  let datadir =
    (* Under the build dir, not /tmp (tmpfs is RAM on maxbox). *)
    let d = Filename.concat (Sys.getcwd ())
        (Printf.sprintf "ibd_orphan_h7_%d" (Unix.getpid ())) in
    Test_tmp.rm_rf d; Unix.mkdir d 0o700;
    if Sys.getenv_opt "CAMLCOIN_H7_KEEP" = None then
      at_exit (fun () -> Test_tmp.rm_rf d)
    else at_exit (fun () -> prerr_endline ("kept datadir " ^ d));
    d in
  let rpcport = free_port () and p2pport = free_port () in
  let g = Consensus.regtest.Consensus.genesis_header in
  let prev = ref (Crypto.compute_block_hash g, g.Types.timestamp) in
  let headers = List.init 5 (fun i ->
      let b = build_block ~prev_hash:(fst !prev) ~height:(i + 1)
          ~prev_time:(snd !prev) () in
      prev := (hash_of b, b.Types.header.Types.timestamp);
      b.Types.header) in
  (* The honest peer is the node's --connect (outbound) peer, so the node
     header-syncs from it and then enters IBD proper (Sync.start_ibd); an
     inbound-only peer would only ever see post-IBD gap-fill. *)
  let lsock = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Unix.setsockopt lsock Unix.SO_REUSEADDR true;
  Unix.bind lsock (Unix.ADDR_INET (Unix.inet_addr_loopback, 0));
  Unix.listen lsock 4;
  let lport = match Unix.getsockname lsock with
    | Unix.ADDR_INET (_, p) -> p | _ -> assert false in
  let node = start_node ~connect:(Printf.sprintf "127.0.0.1:%d" lport)
      datadir rpcport p2pport in
  Fun.protect ~finally:(fun () -> stop_node node) @@ fun () ->
  (* The node dials BIP-324 v2 first and falls back to v1 on a new socket
     when that fails: close anything that does not open with the v1 magic. *)
  let magic_bytes =
    let b = Bytes.create 4 in Bytes.set_int32_le b 0 magic; Bytes.to_string b in
  let accept_deadline = Unix.gettimeofday () +. 60. in
  let rec accept_v1 () =
    let left = accept_deadline -. Unix.gettimeofday () in
    if left <= 0. then Alcotest.fail "node never dialled its --connect peer over v1";
    match Unix.select [lsock] [] [] left with
    | [], _, _ -> accept_v1 ()
    | _ ->
      let fd, _ = Unix.accept lsock in
      let buf = Bytes.create 4 in
      let first =
        match Unix.select [fd] [] [] 10. with
        | [], _, _ -> ""
        | _ -> (try Bytes.sub_string buf 0 (Unix.recv fd buf 0 4 [Unix.MSG_PEEK])
                with _ -> "") in
      if first = magic_bytes then fd
      else (Unix.close fd; accept_v1 ()) in
  let honest = accept_v1 () in
  Unix.close lsock;
  let honest = handshake ~ua:"/h7-honest:0.1/" ~services:9L honest in
  send honest (P2p.HeadersMsg headers);
  (* Serve headers, withhold bodies, until the node asks for one. *)
  let deadline = Unix.gettimeofday () +. 90. in
  let rec wait_getdata () =
    if Unix.gettimeofday () > deadline then false
    else match read_msg honest (Unix.gettimeofday () +. 1.) with
      | Some (P2p.GetdataMsg _) -> true
      | Some (P2p.GetheadersMsg { locator_hashes; _ }) ->
        (* Answer like a real peer: the chain, or nothing once the node's
           locator already starts at our tip. *)
        let tip = Cstruct.to_string
            (Crypto.compute_block_hash (List.nth headers 4)) in
        (match locator_hashes with
         | h :: _ when Cstruct.to_string h = tip -> send honest (P2p.HeadersMsg [])
         | _ -> send honest (P2p.HeadersMsg headers));
        wait_getdata ()
      | Some (P2p.PingMsg n) -> send honest (P2p.PongMsg n); wait_getdata ()
      | _ -> wait_getdata () in
  let ibd_active = wait_getdata () in
  let attacker = connect_peer ~ua:"/h7-attacker:0.1/" ~services:8L node in
  Unix.sleepf 1.0;
  let rss_before_kb = rss_kb node.pid in
  (* Keep the honest peer's socket drained so the node never blocks on it. *)
  let drain_honest () =
    match Unix.select [honest] [] [] 0. with
    | [], _, _ -> ()
    | _ -> (match read_msg honest (Unix.gettimeofday () +. 1.) with
        | Some (P2p.PingMsg n) -> (try send honest (P2p.PongMsg n) with _ -> ())
        | _ -> ()) in
  let sent = ref 0 in
  (try
     for n = 1 to n_blocks do
       send attacker (P2p.BlockMsg (fat_block n));
       incr sent;
       ignore (collect attacker 0.01);
       drain_honest ()
     done
   with _ -> ());
  (* The node handles one peer's messages in order: a pong to a ping sent
     after the flood means every block before it went through receive_block. *)
  let pong =
    try
      send attacker (P2p.PingMsg 0x4837L);
      let deadline = Unix.gettimeofday () +. 120. in
      let rec go () =
        if Unix.gettimeofday () > deadline then false
        else match read_msg attacker (Unix.gettimeofday () +. 1.) with
          | Some (P2p.PongMsg 0x4837L) -> true
          | Some (P2p.PingMsg n) -> send attacker (P2p.PongMsg n); go ()
          | _ -> drain_honest (); go () in
      go ()
    with _ -> false in
  Unix.sleepf 2.0;
  let rss_after_kb = rss_kb node.pid in
  let alive = (match rpc_raw node "getblockcount" [] with Ok _ -> true | Error _ -> false) in
  (try Unix.close honest with _ -> ());
  (try Unix.close attacker with _ -> ());
  { ibd_active; sent = !sent; pong; rss_before_kb; rss_after_kb; alive }

let outcome = lazy (run_attack ())

let sent_mb o = o.sent * script_bytes / 1_000_000

let describe o =
  Printf.sprintf "ibd_active=%b sent=%d (~%d MB) pong=%b rss_before=%d MB \
                  rss_after=%d MB growth=%d MB alive=%b"
    o.ibd_active o.sent (sent_mb o) o.pong (o.rss_before_kb / 1024)
    (o.rss_after_kb / 1024) ((o.rss_after_kb - o.rss_before_kb) / 1024) o.alive

(* Instrument check: the node was in IBD with a request outstanding, the
   whole flood was delivered and processed, and the node survived.  If this
   fails the RSS case says nothing. *)
let test_attack_ran () =
  let o = Lazy.force outcome in
  print_endline (describe o);
  Alcotest.(check bool) ("node in IBD (asked honest peer for a body): " ^ describe o)
    true o.ibd_active;
  Alcotest.(check int) ("whole flood sent: " ^ describe o) n_blocks o.sent;
  Alcotest.(check bool) ("flood processed (pong after it): " ^ describe o) true o.pong;
  Alcotest.(check bool) ("node still answers RPC: " ^ describe o) true o.alive

(* Retaining the flood costs at least its wire size (~700 MB here; master
   grew ~750 MB).  Allow transient garbage up to half of it (the fixed node
   grows ~135 MB while it chews through the flood). *)
let test_flood_not_retained () =
  let o = Lazy.force outcome in
  let growth_mb = (o.rss_after_kb - o.rss_before_kb) / 1024 in
  Alcotest.(check bool)
    (Printf.sprintf "RSS growth %d MB < %d MB (half of the ~%d MB sent): %s"
       growth_mb (sent_mb o / 2) (sent_mb o) (describe o))
    true (growth_mb < sent_mb o / 2)

let () =
  Alcotest.run "ibd_orphan_blocks_e2e"
    [ "h7",
      [ Alcotest.test_case "attack ran (in-IBD node took the whole flood)" `Slow
          test_attack_ran;
        Alcotest.test_case "unrequested IBD blocks are not retained in memory" `Slow
          test_flood_not_retained ] ]
