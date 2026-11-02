(* Anti-DoS work threshold on the P2P header and block paths (security
   audit 2026-10-31 H5).

   Once camlcoin had connected any block it ran every network headers batch
   through [process_headers] with the work gate off, and stored an
   unsolicited [block] body whatever its work as long as it was at most 288
   above the tip.  Any peer could therefore store a cheap fork off an old
   height (headers and bodies), which Bitcoin Core never does:
   net_processing.cpp ProcessHeadersMessage ignores a batch that claims less
   than GetAntiDoSWorkThreshold() (the larger of nMinimumChainWork and the
   tip's work less 144 blocks of proof), the BLOCK handler only sets
   min_pow_checked when prev work + the header's proof reaches it, and
   validation.cpp AcceptBlock does not store a block nobody asked for unless
   it has at least the tip's work.

   On regtest every block has 2 units of work, so with a 200-block chain the
   threshold sits at height ~56: a fork off height 10 is low-work; a batch
   from height 50 that reaches height 190 is not.

     dune build @test/antidos_work_threshold/runtest *)

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

let best_hash node =
  match rpc node "getbestblockhash" [] with `String s -> s | _ -> ""

let start_node datadir rpcport p2pport =
  let log = Filename.concat datadir "node.log" in
  let fd = Unix.openfile log [Unix.O_WRONLY; Unix.O_CREAT; Unix.O_APPEND] 0o600 in
  let args = [| main_exe; "--network=regtest"; "--datadir=" ^ datadir;
                "--rpchost=127.0.0.1"; Printf.sprintf "--rpcport=%d" rpcport;
                Printf.sprintf "--port=%d" p2pport; "--metricsport=0";
                "--nodnsseed"; "--connect=127.0.0.1:1" |] in
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

let connect_peer node =
  let fd = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Unix.connect fd (Unix.ADDR_INET (Unix.inet_addr_loopback, node.p2pport));
  let addr = P2p.empty_net_addr () in
  send fd (P2p.make_version_msg ~protocol_version:70016l ~services:9L
             ~timestamp:(Int64.of_float (Unix.gettimeofday ()))
             ~addr_recv:addr ~addr_from:addr ~nonce:(Random.int64 Int64.max_int)
             ~user_agent:"/h5-test:0.1/" ~start_height:0l ~relay:true);
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

type fixture = {
  node : node;
  main : Types.block array;  (* main.(h - 1) is the block at height h *)
}

let genesis_hash () =
  Crypto.compute_block_hash Consensus.regtest.Consensus.genesis_header

let main_hash f h =
  if h = 0 then genesis_hash () else hash_of f.main.(h - 1)

let main_time f h =
  if h = 0 then Consensus.regtest.Consensus.genesis_header.Types.timestamp
  else f.main.(h - 1).Types.header.Types.timestamp

(* [n] blocks on top of main height [fork], tagged so they differ from the
   main chain and from other forks. *)
let fork_blocks f ~fork ~n ~tag =
  let prev = ref (main_hash f fork, main_time f fork) in
  List.init n (fun i ->
    let b = build_block ~tag ~prev_hash:(fst !prev) ~height:(fork + i + 1)
        ~prev_time:(snd !prev) () in
    prev := (hash_of b, b.Types.header.Types.timestamp);
    b)

let fixture : fixture Lazy.t = lazy (
  (* Under the build dir, not /tmp (see test_cmpctblock_pending).
     CAMLCOIN_H5_DATADIR keeps it (and node.log) for inspection. *)
  let datadir = match Sys.getenv_opt "CAMLCOIN_H5_DATADIR" with
    | Some d -> Unix.mkdir d 0o700; d
    | None ->
      let d = Filename.concat (Sys.getcwd ())
          (Printf.sprintf "antidos_h5_%d" (Unix.getpid ())) in
      Test_tmp.rm_rf d;
      Unix.mkdir d 0o700;
      at_exit (fun () -> Test_tmp.rm_rf d);
      d in
  let rpcport = free_port () and p2pport = free_port () in
  let g = Consensus.regtest.Consensus.genesis_header in
  let prev = ref (Crypto.compute_block_hash g, g.Types.timestamp) in
  let blocks = Array.init chain_len (fun i ->
      let b = build_block ~prev_hash:(fst !prev) ~height:(i + 1)
          ~prev_time:(snd !prev) () in
      prev := (hash_of b, b.Types.header.Types.timestamp);
      b) in
  let n1 = start_node datadir rpcport p2pport in
  Array.iter (fun b ->
    match rpc n1 "submitblock" [ `String (block_hex b) ] with
    | `Null -> ()
    | r -> failwith ("submitblock: " ^ Yojson.Safe.to_string r)) blocks;
  let c = block_count n1 in
  stop_node n1;
  if c <> chain_len then
    failwith (Printf.sprintf "prefix: height %d, want %d" c chain_len);
  (* Restart so the node boots FullySynced (header tip == block tip skips
     the blocking header sync) and the post-IBD listeners are live. *)
  let node = start_node datadir rpcport p2pport in
  at_exit (fun () -> stop_node node);
  let log = Filename.concat datadir "node.log" in
  let contains hay needle =
    let n = String.length needle and h = String.length hay in
    let rec go i = i + n <= h && (String.sub hay i n = needle || go (i + 1)) in
    go 0 in
  let rec synced n =
    if n = 0 then failwith ("node did not start FullySynced; log:\n" ^ read_file log)
    else if block_count node = chain_len
         && contains (read_file log) "Skipping blocking header sync" then ()
    else (Unix.sleepf 0.2; synced (n - 1)) in
  synced 300;
  Unix.sleepf 0.5;
  { node; main = blocks })

let hex h = Types.hash256_to_hex_display h

let header_known node h =
  match rpc_raw node "getblockheader" [ `String (hex h) ] with
  | Ok _ -> true
  | Error _ -> false

let body_stored node h =
  match rpc_raw node "getblock" [ `String (hex h); `Int 0 ] with
  | Ok (`String s) -> s <> ""
  | _ -> false

let headers_msg blocks =
  P2p.HeadersMsg (List.map (fun b -> b.Types.header) blocks)

(* ---- cases -------------------------------------------------------------- *)

(* A peer sends headers of a cheap fork off height 10, far below the
   threshold: none of them may enter the block index. *)
let test_low_work_fork_headers_not_stored () =
  let f = Lazy.force fixture in
  let fork = fork_blocks f ~fork:10 ~n:5 ~tag:1 in
  let fd = connect_peer f.node in
  send fd (headers_msg fork);
  ignore (collect fd 2.0);
  Unix.close fd;
  List.iteri (fun i b ->
    Alcotest.(check bool)
      (Printf.sprintf "low-work fork header %d (height %d) not stored" i (11 + i))
      false (header_known f.node (hash_of b))) fork;
  Alcotest.(check int) "tip unchanged" chain_len (block_count f.node)

(* An unsolicited block whose header we have never seen, off height 10:
   neither its header nor its body may be stored. *)
let test_unsolicited_low_work_block_old_height () =
  let f = Lazy.force fixture in
  let b = List.hd (fork_blocks f ~fork:10 ~n:1 ~tag:2) in
  let fd = connect_peer f.node in
  send fd (P2p.BlockMsg b);
  ignore (collect fd 2.0);
  Unix.close fd;
  Alcotest.(check bool) "old-height unsolicited block: header not stored" false
    (header_known f.node (hash_of b));
  Alcotest.(check bool) "old-height unsolicited block: body not written" false
    (body_stored f.node (hash_of b))

(* An unsolicited side block just below the tip (fork off tip-3, one block):
   its header claims enough work for the index, but it has less work than
   the tip and nobody asked for it, so its body is not written (Core
   AcceptBlock !fRequested && !fHasMoreOrSameWork). *)
let test_unsolicited_less_work_than_tip_not_written () =
  let f = Lazy.force fixture in
  let b = List.hd (fork_blocks f ~fork:(chain_len - 3) ~n:1 ~tag:3) in
  let fd = connect_peer f.node in
  send fd (P2p.BlockMsg b);
  ignore (collect fd 2.0);
  Unix.close fd;
  Alcotest.(check bool) "near-tip less-work unsolicited block: body not written"
    false (body_stored f.node (hash_of b));
  Alcotest.(check int) "tip unchanged" chain_len (block_count f.node)

(* Core judges the claimed work of the whole batch, not each header: a
   fork from 150 blocks below the tip (outside the 144-block near-tip
   window, so its first headers are below the threshold on their own) whose
   batch reaches the threshold is stored in full.  It ends below the tip, so
   the active chain does not move. *)
let test_batch_reaching_threshold_stored () =
  let f = Lazy.force fixture in
  let fork = fork_blocks f ~fork:(chain_len - 150) ~n:140 ~tag:4 in
  let fd = connect_peer f.node in
  send fd (headers_msg fork);
  ignore (collect fd 2.0);
  Unix.close fd;
  Alcotest.(check bool) "first header (below the threshold alone) stored" true
    (header_known f.node (hash_of (List.hd fork)));
  Alcotest.(check bool) "last header stored" true
    (header_known f.node (hash_of (List.nth fork (List.length fork - 1))));
  Alcotest.(check int) "tip unchanged" chain_len (block_count f.node)

(* Warden review of #45, point 1: a valid fork header off height 10
   followed by a header that links to it but whose hash does not meet its
   own (much harder) nBits.  The batch's CLAIMED work is huge, but Core runs
   CheckHeadersPoW before the anti-DoS threshold and stores nothing from a
   batch that fails it; the valid first header must not get in on the
   second header's unearned claim. *)
let test_bad_pow_tail_stores_nothing () =
  let f = Lazy.force fixture in
  let a = List.hd (fork_blocks f ~fork:10 ~n:1 ~tag:6) in
  let bad =
    { a.Types.header with
      Types.prev_block = hash_of a;
      timestamp = Int32.add a.Types.header.Types.timestamp 600l;
      bits = 0x1d00ffffl; nonce = 0l } in
  Alcotest.(check bool) "control: second header really fails its own target"
    false (Consensus.hash_meets_target (Crypto.compute_block_hash bad) bad.bits);
  let fd = connect_peer f.node in
  send fd (P2p.HeadersMsg [ a.Types.header; bad ]);
  ignore (collect fd 2.0);
  Unix.close fd;
  Alcotest.(check bool) "fork header before a bad-PoW header not stored" false
    (header_known f.node (hash_of a));
  Alcotest.(check bool) "bad-PoW header not stored" false
    (header_known f.node (Crypto.compute_block_hash bad));
  Alcotest.(check int) "tip unchanged" chain_len (block_count f.node)

(* Warden review of #45, point 2: a fork header off height 10 followed by
   the node's own (known) tip header.  The batch does not link, so it is
   not the already-validated-work case: nothing from it may be stored. *)
let test_known_last_header_does_not_skip_gate () =
  let f = Lazy.force fixture in
  let a = List.hd (fork_blocks f ~fork:10 ~n:1 ~tag:7) in
  let tip = f.main.(chain_len - 1) in
  Alcotest.(check bool) "control: last header is known" true
    (header_known f.node (hash_of tip));
  let fd = connect_peer f.node in
  send fd (P2p.HeadersMsg [ a.Types.header; tip.Types.header ]);
  ignore (collect fd 2.0);
  Unix.close fd;
  Alcotest.(check bool) "fork header before a known tip header not stored"
    false (header_known f.node (hash_of a));
  Alcotest.(check int) "tip unchanged" chain_len (block_count f.node)

(* [n] blocks on top of main height [fork] where block [bad] (0-based) has a
   timestamp far below its parent's median time past; every block, the bad
   one included, meets its own target and links to the one before. *)
let fork_with_bad_time f ~fork ~n ~tag ~bad =
  let prev = ref (main_hash f fork, main_time f fork) in
  List.init n (fun i ->
    let pt = if i = bad then Int32.sub (snd !prev) 100_000l else snd !prev in
    let b = build_block ~tag ~prev_hash:(fst !prev) ~height:(fork + i + 1)
        ~prev_time:pt () in
    prev := (hash_of b, b.Types.header.Types.timestamp);
    b)

(* The batch as a whole claims enough work (it is the batch of
   [test_batch_reaching_threshold_stored]) and is continuous with valid
   PoW, but its second header fails validation (time-too-old).  The one
   valid header before it is far below the threshold on its own, so it must
   not be kept on work only the later, rejected headers claimed. *)
let test_low_work_prefix_of_failing_batch_not_kept () =
  let f = Lazy.force fixture in
  let fork = fork_with_bad_time f ~fork:(chain_len - 150) ~n:140 ~tag:8 ~bad:1 in
  let fd = connect_peer f.node in
  send fd (headers_msg fork);
  ignore (collect fd 2.0);
  Unix.close fd;
  Alcotest.(check bool) "low-work valid prefix of a failing batch not stored"
    false (header_known f.node (hash_of (List.hd fork)));
  Alcotest.(check bool) "invalid header not stored" false
    (header_known f.node (hash_of (List.nth fork 1)))

(* Control for the case above: the same shape, but the bad header comes
   late, after a valid prefix that reaches the threshold on its own.  That
   prefix is kept (Core ProcessNewBlockHeaders keeps the headers accepted
   before the first invalid one). *)
let test_threshold_prefix_of_failing_batch_kept () =
  let f = Lazy.force fixture in
  let fork = fork_with_bad_time f ~fork:(chain_len - 150) ~n:140 ~tag:9 ~bad:130 in
  let fd = connect_peer f.node in
  send fd (headers_msg fork);
  ignore (collect fd 2.0);
  Unix.close fd;
  Alcotest.(check bool) "first header of a threshold-reaching prefix stored"
    true (header_known f.node (hash_of (List.hd fork)));
  Alcotest.(check bool) "last valid header stored" true
    (header_known f.node (hash_of (List.nth fork 129)));
  Alcotest.(check bool) "invalid header not stored" false
    (header_known f.node (hash_of (List.nth fork 130)));
  Alcotest.(check int) "tip unchanged" chain_len (block_count f.node)

(* Consensus positive control: a legitimate higher-work fork (off tip-5,
   eight blocks) still lands.  Its first blocks have less work than the tip,
   so they connect only because the node requested them after the headers
   (Core: fRequested); the peer serves getdata and re-announces. *)
let test_higher_work_reorg_lands () =
  let f = Lazy.force fixture in
  let fork_at = chain_len - 5 in
  let fork = fork_blocks f ~fork:fork_at ~n:8 ~tag:5 in
  let tip = List.nth fork (List.length fork - 1) in
  let by_hash = Hashtbl.create 16 in
  List.iter (fun b -> Hashtbl.replace by_hash (Cstruct.to_string (hash_of b)) b) fork;
  let fd = connect_peer f.node in
  Fun.protect ~finally:(fun () -> Unix.close fd) @@ fun () ->
  send fd (headers_msg fork);
  let deadline = Unix.gettimeofday () +. 60. in
  let last_announce = ref (Unix.gettimeofday ()) in
  let rec loop () =
    if best_hash f.node = hex (hash_of tip) then ()
    else if Unix.gettimeofday () > deadline then ()
    else begin
      List.iter (function
          | P2p.GetdataMsg items ->
            List.iter (fun (iv : P2p.inv_vector) ->
              match Hashtbl.find_opt by_hash (Cstruct.to_string iv.hash) with
              | Some b -> send fd (P2p.BlockMsg b)
              | None -> ()) items
          | P2p.GetheadersMsg _ -> send fd (headers_msg fork)
          | _ -> ()) (collect fd 0.5);
      if Unix.gettimeofday () -. !last_announce > 3. then begin
        last_announce := Unix.gettimeofday ();
        send fd (headers_msg fork)
      end;
      loop ()
    end in
  loop ();
  Alcotest.(check string) "node reorged onto the heavier fork" (hex (hash_of tip))
    (best_hash f.node);
  Alcotest.(check int) "height is the fork tip's" (fork_at + 8)
    (block_count f.node)

let () =
  Alcotest.run "antidos_work_threshold"
    [ "h5",
      [ Alcotest.test_case "low-work fork headers not stored" `Slow
          test_low_work_fork_headers_not_stored;
        Alcotest.test_case "unsolicited low-work block (old height) not stored"
          `Slow test_unsolicited_low_work_block_old_height;
        Alcotest.test_case "unsolicited less-work-than-tip block not written"
          `Slow test_unsolicited_less_work_than_tip_not_written;
        Alcotest.test_case "batch reaching the threshold stored whole" `Slow
          test_batch_reaching_threshold_stored;
        Alcotest.test_case "bad-PoW tail: nothing from the batch stored" `Slow
          test_bad_pow_tail_stores_nothing;
        Alcotest.test_case "known last header does not skip the gate" `Slow
          test_known_last_header_does_not_skip_gate;
        Alcotest.test_case "low-work prefix of a failing batch not kept" `Slow
          test_low_work_prefix_of_failing_batch_not_kept;
        Alcotest.test_case "threshold-reaching prefix of a failing batch kept"
          `Slow test_threshold_prefix_of_failing_batch_kept;
        Alcotest.test_case "higher-work reorg still lands" `Slow
          test_higher_work_reorg_lands ] ]
