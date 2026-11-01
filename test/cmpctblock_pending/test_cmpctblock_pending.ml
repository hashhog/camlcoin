(* cmpctblock end to end (security audit 2026-10-31 C3).

   camlcoin ran [reconstruct_from_mempool] on every cmpctblock it got while
   FullySynced and kept every incomplete one in a global table keyed by
   block hash: no header check, no cap, no expiry, no removal on
   disconnect, and a blocktxn from ANY peer completed it.  The audit sent
   393 MB of random-header cmpctblocks and RSS went 0.54 -> 7.0 GB.

   Each stored entry is answered with a getblocktxn, so the getblocktxn
   replies a peer receives are the entries it created.  Bitcoin Core
   (net_processing.cpp CMPCTBLOCK / ProcessCompactBlockTxns) keeps nothing
   for a header with an unknown parent (it sends getheaders), keeps a
   partial block only for a valid header near the tip, at most 3 peers per
   block, and matches blocktxn to the peer that was asked.

   The node is booted twice on regtest: once to take 101 blocks over
   submitblock, then again so it starts FullySynced (header tip == block
   tip skips the blocking header sync).

     dune build @test/cmpctblock_pending/runtest *)

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

(* Spend output 0 of [cb] (an OP_TRUE coinbase) back to OP_TRUE. *)
let spend_coinbase (cb : Types.transaction) ~fee : Types.transaction =
  let value = (List.hd cb.Types.outputs).Types.value in
  { Types.version = 2l;
    inputs = [ { Types.previous_output =
                   { Types.txid = Crypto.compute_txid cb; vout = 0l };
                 script_sig = Cstruct.empty; sequence = 0xffffffffl } ];
    outputs = [ { Types.value = Int64.sub value fee; script_pubkey = op_true } ];
    witnesses = []; locktime = 0l }

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
             ~user_agent:"/c3-test:0.1/" ~start_height:0l ~relay:true);
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

let getblocktxns msgs =
  List.filter_map (function P2p.GetblocktxnMsg r -> Some r | _ -> None) msgs

let getdata_has msgs hash =
  List.exists (function
      | P2p.GetdataMsg items ->
        List.exists (fun (iv : P2p.inv_vector) -> Cstruct.equal iv.hash hash) items
      | _ -> false) msgs

(* ---- fixture ------------------------------------------------------------ *)

type fixture = {
  node : node;
  mutable tip_hash : Types.hash256;
  mutable tip_time : int32;
  mutable height : int;
  spendable : Types.transaction;  (* coinbase of block 1, mature *)
}

let fixture : fixture Lazy.t = lazy (
  (* Under the build dir, not /tmp: on maxbox's tmpfs the restart came
     back at height 0 (the 101 submitted blocks were gone), on disk it
     does not.  Removed at exit, after [stop_node] (at_exit is LIFO).
     CAMLCOIN_C3_DATADIR keeps it (and node.log) for inspection. *)
  let datadir = match Sys.getenv_opt "CAMLCOIN_C3_DATADIR" with
    | Some d -> Unix.mkdir d 0o700; d
    | None ->
      let d = Filename.concat (Sys.getcwd ())
          (Printf.sprintf "cmpctblock_c3_%d" (Unix.getpid ())) in
      Test_tmp.rm_rf d;
      Unix.mkdir d 0o700;
      at_exit (fun () -> Test_tmp.rm_rf d);
      d in
  let rpcport = free_port () and p2pport = free_port () in
  let g = Consensus.regtest.Consensus.genesis_header in
  let prev = ref (Crypto.compute_block_hash g, g.Types.timestamp) in
  let blocks = List.init 101 (fun i ->
      let b = build_block ~prev_hash:(fst !prev) ~height:(i + 1)
          ~prev_time:(snd !prev) () in
      prev := (hash_of b, b.Types.header.Types.timestamp);
      b) in
  let n1 = start_node datadir rpcport p2pport in
  List.iter (fun b ->
    match rpc n1 "submitblock" [ `String (block_hex b) ] with
    | `Null -> ()
    | r -> failwith ("submitblock: " ^ Yojson.Safe.to_string r)) blocks;
  let c = block_count n1 in
  stop_node n1;
  if c <> 101 then failwith (Printf.sprintf "prefix: height %d, want 101" c);
  let node = start_node datadir rpcport p2pport in
  at_exit (fun () -> stop_node node);
  (* RPC can answer before the chain is restored: wait for the boot that
     skips the blocking header sync, i.e. starts FullySynced. *)
  let log = Filename.concat datadir "node.log" in
  let contains hay needle =
    let n = String.length needle and h = String.length hay in
    let rec go i = i + n <= h && (String.sub hay i n = needle || go (i + 1)) in
    go 0 in
  let rec synced n =
    if n = 0 then failwith ("node did not start FullySynced; log:\n" ^ read_file log)
    else if block_count node = 101
         && contains (read_file log) "Skipping blocking header sync" then ()
    else (Unix.sleepf 0.2; synced (n - 1)) in
  synced 300;
  Unix.sleepf 0.5;
  { node; tip_hash = fst !prev; tip_time = snd !prev; height = 101;
    spendable = List.hd (List.hd blocks).Types.transactions })

(* A header at tip+1 with valid regtest PoW (its body is irrelevant). *)
let child_header f ~tag =
  (build_block ~tag ~prev_hash:f.tip_hash ~height:(f.height + 1)
     ~prev_time:f.tip_time ()).Types.header

let random_short_ids n = List.init n (fun _ -> Random.int64 0xFFFF_FFFF_FFFFL)

let cmpct ?(short_ids = random_short_ids 2) header =
  P2p.CmpctblockMsg
    { P2p.header; nonce = Random.int64 Int64.max_int; short_ids;
      prefilled_txs = [] }

(* Partial blocks one peer may hold (Core MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK
   is 3; the audit fix caps a peer at the same). *)
let cap = 3

(* ---- cases -------------------------------------------------------------- *)

(* The audit's message: random header (unknown parent, no PoW). *)
let test_random_header () =
  let f = Lazy.force fixture in
  let fd = connect_peer f.node in
  let hdr =
    { Types.version = 0x20000000l;
      prev_block = Cstruct.of_string (String.init 32 (fun _ -> Char.chr (Random.int 256)));
      merkle_root = Cstruct.of_string (String.init 32 (fun _ -> Char.chr (Random.int 256)));
      timestamp = Int32.of_float (Unix.gettimeofday ());
      bits = 0x207fffffl; nonce = 1l } in
  send fd (cmpct ~short_ids:(random_short_ids 50) hdr);
  let got = collect fd 2.0 in
  Unix.close fd;
  Alcotest.(check int)
    "random-header cmpctblock: no getblocktxn (nothing kept)" 0
    (List.length (getblocktxns got))

(* Six valid headers at tip+1 from one peer, each missing its txs. *)
let test_per_peer_cap () =
  let f = Lazy.force fixture in
  let fd = connect_peer f.node in
  for tag = 1 to 6 do send fd (cmpct (child_header f ~tag:(100 + tag))) done;
  let got = collect fd 3.0 in
  Unix.close fd;
  let n = List.length (getblocktxns got) in
  Alcotest.(check bool)
    (Printf.sprintf "valid compact blocks still get getblocktxn (got %d)" n)
    true (n >= 1);
  Alcotest.(check bool)
    (Printf.sprintf "one peer holds at most %d partial blocks (got %d)"
       cap n)
    true (n <= cap)

(* Duplicate short ids: Core READ_STATUS_FAILED -> getdata the full block. *)
let test_duplicate_short_ids () =
  let f = Lazy.force fixture in
  let fd = connect_peer f.node in
  let hdr = child_header f ~tag:200 in
  send fd (cmpct ~short_ids:[ 42L; 42L ] hdr);
  let got = collect fd 2.0 in
  Unix.close fd;
  Alcotest.(check int) "duplicate short ids: no getblocktxn" 0
    (List.length (getblocktxns got));
  Alcotest.(check bool) "duplicate short ids: full block requested" true
    (getdata_has got (Crypto.compute_block_hash hdr))

(* A real block whose tx is not in our mempool: the getblocktxn round trip
   completes it only for the peer that was asked. *)
let test_blocktxn_bound_to_peer () =
  let f = Lazy.force fixture in
  let tx = spend_coinbase f.spendable ~fee:1000L in
  let b = build_block ~fee:1000L ~tag:300 ~txs:[ tx ] ~prev_hash:f.tip_hash
      ~height:(f.height + 1) ~prev_time:f.tip_time () in
  let a = connect_peer f.node in
  let c = connect_peer f.node in
  (* Whatever the asserts say, later cases build on the node's real tip. *)
  Fun.protect ~finally:(fun () ->
    Unix.close a; Unix.close c;
    if best_hash f.node = Types.hash256_to_hex_display (hash_of b) then begin
      f.tip_hash <- hash_of b; f.tip_time <- b.Types.header.Types.timestamp;
      f.height <- f.height + 1
    end) @@ fun () ->
  send a (P2p.CmpctblockMsg (P2p.create_compact_block b));
  let got = collect a 2.0 in
  Alcotest.(check int) "asking peer gets one getblocktxn" 1
    (List.length (getblocktxns got));
  let resp = P2p.BlocktxnMsg { P2p.block_hash = hash_of b; txs = [ tx ] } in
  send c resp;
  ignore (collect c 1.5);
  Alcotest.(check int) "blocktxn from a peer that was not asked: not connected"
    f.height (block_count f.node);
  send a resp;
  let rec wait n =
    if block_count f.node = f.height + 1 || n = 0 then ()
    else (Unix.sleepf 0.1; wait (n - 1)) in
  wait 100;
  Alcotest.(check int) "blocktxn from the asking peer: connected" (f.height + 1)
    (block_count f.node);
  Alcotest.(check string) "tip is the reconstructed block"
    (Types.hash256_to_hex_display (hash_of b)) (best_hash f.node)

(* Consensus positive control: a coinbase-only compact block reconstructs
   without a round trip and connects. *)
let test_valid_compact_connects () =
  let f = Lazy.force fixture in
  let b = build_block ~tag:400 ~prev_hash:f.tip_hash ~height:(f.height + 1)
      ~prev_time:f.tip_time () in
  let fd = connect_peer f.node in
  send fd (P2p.CmpctblockMsg (P2p.create_compact_block b));
  let rec wait n =
    if block_count f.node = f.height + 1 || n = 0 then ()
    else (Unix.sleepf 0.1; wait (n - 1)) in
  wait 100;
  Unix.close fd;
  Alcotest.(check int) "valid compact block connects" (f.height + 1)
    (block_count f.node);
  Alcotest.(check string) "tip is the compact block"
    (Types.hash256_to_hex_display (hash_of b)) (best_hash f.node);
  f.tip_hash <- hash_of b; f.tip_time <- b.Types.header.Types.timestamp;
  f.height <- f.height + 1

let () =
  Random.self_init ();
  Alcotest.run "cmpctblock_pending"
    [ "cmpctblock",
      [ Alcotest.test_case "random header keeps nothing" `Quick test_random_header;
        Alcotest.test_case "per-peer cap" `Quick test_per_peer_cap;
        Alcotest.test_case "duplicate short ids" `Quick test_duplicate_short_ids;
        Alcotest.test_case "blocktxn bound to the asking peer" `Quick
          test_blocktxn_bound_to_peer;
        Alcotest.test_case "valid compact block connects" `Quick
          test_valid_compact_connects ] ]
