(* BIP-157 responses with backpressure (security audit 2026-10-31 H9).

   With --blockfilterindex on, every 37-byte getcfilters made camlcoin do up
   to 1,000 index reads and fire one [Lwt.async] send per filter, and
   getcfheaders / getcfcheckpt fired their single reply the same way.  The
   listener returned at once, so the peer's message loop went straight on to
   read the next request while the replies piled up behind the peer's send
   lock: a peer that sends getcfilters and never reads grows an unbounded
   queue of pending sends (and the filters they hold) in the node.

   Bitcoin Core stops processing a peer's messages while its send queue is
   over the send buffer (net.cpp fPauseSend / net_processing.cpp
   ProcessMessages), and camlcoin's own handle_getdata awaits each send.
   With the replies awaited, the node reads no further requests from a peer
   that is not draining its replies.

     dune build @test/cfilters_backpressure/runtest *)

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

let hex_of_cstruct cs =
  let b = Buffer.create (2 * Cstruct.length cs) in
  for i = 0 to Cstruct.length cs - 1 do
    Buffer.add_string b (Printf.sprintf "%02x" (Cstruct.get_uint8 cs i))
  done;
  Buffer.contents b

let block_hex b =
  let w = Serialize.writer_create () in
  Serialize.serialize_block w b;
  hex_of_cstruct (Serialize.writer_to_cstruct w)

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

let rpc node meth params =
  match rpc_raw node meth params with
  | Ok r -> r
  | Error e -> Alcotest.failf "rpc %s: %s" meth e

let block_count node =
  match rpc node "getblockcount" [] with `Int n -> n | _ -> -1

let start_node datadir rpcport p2pport =
  (* --blockfilterindex: the BIP-157 handlers are only wired with the index on *)
  let log = Filename.concat datadir "node.log" in
  let fd = Unix.openfile log [Unix.O_WRONLY; Unix.O_CREAT; Unix.O_APPEND] 0o600 in
  let args = [| main_exe; "--network=regtest"; "--datadir=" ^ datadir;
                "--rpchost=127.0.0.1"; Printf.sprintf "--rpcport=%d" rpcport;
                Printf.sprintf "--port=%d" p2pport; "--metricsport=0";
                "--nodnsseed"; "--connect=127.0.0.1:1";
                "--blockfilterindex=1" |] in
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

let connect_peer ?rcvbuf node =
  let fd = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  (* Before connect, so the window we advertise is small from the start. *)
  Option.iter (fun n -> Unix.setsockopt_int fd Unix.SO_RCVBUF n) rcvbuf;
  Unix.connect fd (Unix.ADDR_INET (Unix.inet_addr_loopback, node.p2pport));
  let addr = P2p.empty_net_addr () in
  send fd (P2p.make_version_msg ~protocol_version:70016l ~services:9L
             ~timestamp:(Int64.of_float (Unix.gettimeofday ()))
             ~addr_recv:addr ~addr_from:addr ~nonce:(Random.int64 Int64.max_int)
             ~user_agent:"/h9-test:0.1/" ~start_height:0l ~relay:true);
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

(* ---- fixture ------------------------------------------------------------ *)

let chain_len = 200

type fixture = { node : node; hashes : Types.hash256 array (* index = height *) }

let fixture : fixture Lazy.t = lazy (
  (* Under the build dir, not /tmp (maxbox's /tmp is a RAM tmpfs).
     CAMLCOIN_H9_DATADIR keeps it (and node.log) for inspection. *)
  let datadir = match Sys.getenv_opt "CAMLCOIN_H9_DATADIR" with
    | Some d -> Unix.mkdir d 0o700; d
    | None ->
      let d = Filename.concat (Sys.getcwd ())
          (Printf.sprintf "cfilters_h9_%d" (Unix.getpid ())) in
      Test_tmp.rm_rf d;
      Unix.mkdir d 0o700;
      at_exit (fun () -> Test_tmp.rm_rf d);
      d in
  let rpcport = free_port () and p2pport = free_port () in
  let g = Consensus.regtest.Consensus.genesis_header in
  let prev = ref (Crypto.compute_block_hash g, g.Types.timestamp) in
  let blocks = List.init chain_len (fun i ->
      let b = build_block ~prev_hash:(fst !prev) ~height:(i + 1)
          ~prev_time:(snd !prev) () in
      prev := (hash_of b, b.Types.header.Types.timestamp);
      b) in
  let node = start_node datadir rpcport p2pport in
  at_exit (fun () -> stop_node node);
  List.iter (fun b ->
    match rpc node "submitblock" [ `String (block_hex b) ] with
    | `Null -> ()
    | r -> failwith ("submitblock: " ^ Yojson.Safe.to_string r)) blocks;
  if block_count node <> chain_len then
    failwith (Printf.sprintf "prefix: height %d, want %d"
                (block_count node) chain_len);
  let hashes = Array.of_list
      (Crypto.compute_block_hash g :: List.map hash_of blocks) in
  { node; hashes })

let getcfilters ~start ~stop_hash =
  P2p.GetcfiltersMsg { filter_type = 0; start_height = Int32.of_int start; stop_hash }

let cfilters msgs =
  List.filter_map (function
      | P2p.CfilterMsg { block_hash; _ } -> Some block_hash | _ -> None) msgs

(* bytesrecv of our own connection, found by its user agent. *)
let peer_bytesrecv node =
  match rpc node "getpeerinfo" [] with
  | `List peers ->
    List.find_map (function
        | `Assoc kv when List.assoc_opt "subver" kv = Some (`String "/h9-test:0.1/") ->
          (match List.assoc_opt "bytesrecv" kv with Some (`Int n) -> Some n | _ -> None)
        | _ -> None) peers
  | _ -> None

(* ---- cases -------------------------------------------------------------- *)

(* Positive control: a peer that reads gets every filter, in height order. *)
let test_reader_gets_filters () =
  let f = Lazy.force fixture in
  let fd = connect_peer f.node in
  send fd (getcfilters ~start:1 ~stop_hash:f.hashes.(chain_len));
  let got = cfilters (collect fd 5.0) in
  Unix.close fd;
  Alcotest.(check int) "one cfilter per height in [1, tip]" chain_len
    (List.length got);
  Alcotest.(check bool) "cfilters arrive in height order" true
    (List.for_all2 Cstruct.equal got
       (Array.to_list (Array.sub f.hashes 1 chain_len)))

(* getcfheaders / getcfcheckpt still answer once their reply is awaited. *)
let test_cfheaders_cfcheckpt_answer () =
  let f = Lazy.force fixture in
  let fd = connect_peer f.node in
  let stop_hash = f.hashes.(chain_len) in
  send fd (P2p.GetcfheadersMsg { filter_type = 0; start_height = 1l; stop_hash });
  send fd (P2p.GetcfcheckptMsg { filter_type = 0; stop_hash });
  let got = collect fd 3.0 in
  Unix.close fd;
  let n_hashes = List.find_map (function
      | P2p.CfheadersMsg { filter_hashes; _ } -> Some (List.length filter_hashes)
      | _ -> None) got in
  Alcotest.(check (option int)) "cfheaders: one filter hash per height"
    (Some chain_len) n_hashes;
  Alcotest.(check bool) "cfcheckpt answered" true
    (List.exists (function P2p.CfcheckptMsg _ -> true | _ -> false) got)

(* The audit's attack: a peer with a tiny receive window sends many
   getcfilters and never reads.  Each request (61 bytes on the wire) asks
   for [chain_len] cfilters (~13 KB).  Without backpressure the node keeps
   reading requests and queues every reply in memory; with it, the node
   stops reading once the socket buffers between us are full. *)
let n_requests = 4000
let request_bytes = 24 + 1 + 4 + 32

(* Generous: what the kernel buffers on both sides of loopback can hold
   (a few MB of replies = a few hundred requests), far under [n_requests]. *)
let max_requests_read = n_requests / 4

let test_slow_reader_bounded () =
  let f = Lazy.force fixture in
  let fd = connect_peer ~rcvbuf:4096 f.node in
  Fun.protect ~finally:(fun () -> Unix.close fd) @@ fun () ->
  let msg = getcfilters ~start:1 ~stop_hash:f.hashes.(chain_len) in
  let one = Cstruct.to_bytes (P2p.serialize_message magic msg) in
  Alcotest.(check int) "request size" request_bytes (Bytes.length one);
  let all = Bytes.concat Bytes.empty (List.init n_requests (fun _ -> one)) in
  (* Non-blocking: once the node stops reading, our send buffer fills too;
     give up after 2 s without progress rather than block forever. *)
  Unix.set_nonblock fd;
  let total = Bytes.length all in
  let rec write off =
    if off >= total then off
    else match Unix.select [] [fd] [] 2.0 with
      | _, [], _ -> off
      | _ ->
        match Unix.write fd all off (total - off) with
        | n -> write (off + n)
        | exception Unix.Unix_error ((Unix.EAGAIN | Unix.EWOULDBLOCK), _, _) ->
          write off in
  let written = write 0 in
  (* Let the node read whatever it is going to read (it drops us after its
     10 s send timeout; sample well before that). *)
  let rec settle last n =
    Unix.sleepf 0.5;
    match peer_bytesrecv f.node with
    | Some b when b <> last && n > 0 -> settle b (n - 1)
    | Some b -> b
    | None -> last in
  let recv = settle (-1) 8 in
  let read_requests = recv / request_bytes in
  Printf.printf "slow reader: wrote %d requests, node read ~%d (bytesrecv %d)\n%!"
    (written / request_bytes) read_requests recv;
  Alcotest.(check bool) "our connection is still listed" true (recv >= 0);
  Alcotest.(check bool)
    (Printf.sprintf
       "node stops reading a peer that does not drain its cfilters \
        (read ~%d of %d requests, bound %d)"
       read_requests (written / request_bytes) max_requests_read)
    true (read_requests <= max_requests_read);
  (* The node is still serving RPC. *)
  Alcotest.(check int) "node still answers RPC" chain_len (block_count f.node)

let () =
  Random.self_init ();
  Alcotest.run "cfilters_backpressure"
    [ "bip157",
      [ Alcotest.test_case "reading peer gets every cfilter" `Quick
          test_reader_gets_filters;
        Alcotest.test_case "cfheaders and cfcheckpt answer" `Quick
          test_cfheaders_cfcheckpt_answer;
        Alcotest.test_case "slow reader: bounded getcfilters backlog" `Quick
          test_slow_reader_bounded ] ]
