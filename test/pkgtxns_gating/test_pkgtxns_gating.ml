(* pkgtxns from a peer we never negotiated package relay with is ignored
   (security audit 2026-10-31 H8).

   camlcoin handed every pkgtxns straight to Mempool.accept_package, which
   verifies scripts synchronously on the Lwt loop.  There was no
   sendpackages check and no per-peer rate limit: the tx listener's
   Peer.check_rate_limit and ATMP gate were bypassed, so any peer that
   finished the handshake could push 25-tx packages through script
   verification as fast as it could write.  BIP-331 relays packages only
   between peers that BOTH sent sendpackages between VERSION and VERACK;
   camlcoin never sends it, so no pkgtxns it receives is legitimate.

   Each case sends a package that the node does accept as plain txs (the
   control proves it), so a package that shows up in getrawmempool was taken
   from pkgtxns.  The node is booted twice on regtest: once to take 103
   blocks over submitblock, then again so it starts FullySynced (the tx
   listener only relays while FullySynced).

     dune build @test/pkgtxns_gating/runtest *)

open Camlcoin

(* ---- chain building ---------------------------------------------------- *)

(* Coinbases pay to P2WSH(OP_TRUE): standard, and spent by a witness that
   just pushes the script, so no keys are needed. *)
let op_true = Cstruct.of_string "\x51"
let p2wsh_true = Cstruct.append (Cstruct.of_string "\x00\x20") (Crypto.sha256 op_true)

let remine (block : Types.block) : Types.block =
  let h = ref block.Types.header in
  let n = ref 0l in
  while not (Consensus.hash_meets_target (Crypto.compute_block_hash !h)
               !h.Types.bits) do
    n := Int32.add !n 1l;
    h := { !h with Types.nonce = !n }
  done;
  { block with Types.header = !h }

let build_block ~prev_hash ~height ~prev_time () : Types.block =
  let extra_nonce = Cstruct.create 8 in
  Cstruct.LE.set_uint64 extra_nonce 0 (Int64.of_int height);
  let mk wr =
    Mining.create_coinbase ~height ~total_fee:0L ~payout_script:p2wsh_true
      ~extra_nonce ~witness_root:wr ~network_type:Consensus.Regtest ()
  in
  let witness_root = Mining.compute_witness_merkle_root [ mk None ] in
  let coinbase = mk (Some witness_root) in
  let merkle_root, _ = Crypto.merkle_root [ Crypto.compute_txid coinbase ] in
  remine
    { Types.header =
        { version = 4l; prev_block = prev_hash; merkle_root;
          timestamp = Int32.add prev_time 600l;
          bits = Consensus.regtest.pow_limit; nonce = 0l };
      transactions = [ coinbase ] }

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

(* Spend output 0 of [prev] (a P2WSH(OP_TRUE) output) back to P2WSH(OP_TRUE). *)
let spend (prev : Types.transaction) ~fee : Types.transaction =
  let value = (List.hd prev.Types.outputs).Types.value in
  { Types.version = 2l;
    inputs = [ { Types.previous_output =
                   { Types.txid = Crypto.compute_txid prev; vout = 0l };
                 script_sig = Cstruct.empty; sequence = 0xfffffffdl } ];
    outputs = [ { Types.value = Int64.sub value fee; script_pubkey = p2wsh_true } ];
    witnesses = [ { Types.items = [ op_true ] } ]; locktime = 0l }

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

let connect_peer ?(sendpackages = false) node =
  let fd = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Unix.connect fd (Unix.ADDR_INET (Unix.inet_addr_loopback, node.p2pport));
  let addr = P2p.empty_net_addr () in
  send fd (P2p.make_version_msg ~protocol_version:70016l ~services:9L
             ~timestamp:(Int64.of_float (Unix.gettimeofday ()))
             ~addr_recv:addr ~addr_from:addr ~nonce:(Random.int64 Int64.max_int)
             ~user_agent:"/h8-test:0.1/" ~start_height:0l ~relay:true);
  let deadline = Unix.gettimeofday () +. 15. in
  let rec hs ver ack =
    if not (ver && ack) then
      match read_msg fd deadline with
      | None -> Alcotest.fail "P2P handshake timed out"
      | Some (P2p.VersionMsg _) ->
        if sendpackages then send fd (P2p.make_sendpackages_msg ());
        send fd P2p.VerackMsg; hs true ack
      | Some P2p.VerackMsg -> hs ver true
      | Some _ -> hs ver ack in
  hs false false;
  ignore (collect fd 0.5);
  fd


(* ---- fixture ------------------------------------------------------------ *)

type fixture = {
  node : node;
  coinbases : Types.transaction array;  (* coinbases of blocks 1..3, mature *)
}

let n_blocks = 103

let fixture : fixture Lazy.t = lazy (
  (* Under the build dir, not /tmp (maxbox's /tmp is tmpfs; see the C3
     test).  Removed at exit, after [stop_node] (at_exit is LIFO).
     CAMLCOIN_H8_DATADIR keeps it (and node.log) for inspection. *)
  let datadir = match Sys.getenv_opt "CAMLCOIN_H8_DATADIR" with
    | Some d -> Unix.mkdir d 0o700; d
    | None ->
      let d = Filename.concat (Sys.getcwd ())
          (Printf.sprintf "pkgtxns_h8_%d" (Unix.getpid ())) in
      Test_tmp.rm_rf d;
      Unix.mkdir d 0o700;
      at_exit (fun () -> Test_tmp.rm_rf d);
      d in
  let rpcport = free_port () and p2pport = free_port () in
  let g = Consensus.regtest.Consensus.genesis_header in
  let prev = ref (Crypto.compute_block_hash g, g.Types.timestamp) in
  let blocks = List.init n_blocks (fun i ->
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
  if c <> n_blocks then
    failwith (Printf.sprintf "prefix: height %d, want %d" c n_blocks);
  let node = start_node datadir rpcport p2pport in
  at_exit (fun () -> stop_node node);
  let log = Filename.concat datadir "node.log" in
  let contains hay needle =
    let n = String.length needle and h = String.length hay in
    let rec go i = i + n <= h && (String.sub hay i n = needle || go (i + 1)) in
    go 0 in
  let rec synced n =
    if n = 0 then failwith ("node did not start FullySynced; log:\n" ^ read_file log)
    else if block_count node = n_blocks
         && contains (read_file log) "Skipping blocking header sync" then ()
    else (Unix.sleepf 0.2; synced (n - 1)) in
  synced 300;
  Unix.sleepf 0.5;
  { node;
    coinbases = Array.of_list
        (List.map (fun b -> List.hd b.Types.transactions)
           (List.filteri (fun i _ -> i < 3) blocks)) })

(* A parent spending coinbase [i] and a child spending the parent: a
   child-with-parents package, each tx valid and standard on its own. *)
let package f i =
  let parent = spend f.coinbases.(i) ~fee:1000L in
  let child = spend parent ~fee:1000L in
  [ parent; child ]

let mempool_txids node =
  match rpc node "getrawmempool" [] with
  | `List l -> List.filter_map (function `String s -> Some s | _ -> None) l
  | r -> Alcotest.failf "getrawmempool: %s" (Yojson.Safe.to_string r)

let txid_hex tx = Types.hash256_to_hex_display (Crypto.compute_txid tx)

let in_pool node txs =
  let pool = mempool_txids node in
  List.length (List.filter (fun tx -> List.mem (txid_hex tx) pool) txs)

(* Poll up to [secs] for [want] of [txs] to land; returns how many did. *)
let wait_in_pool node txs ~want secs =
  let deadline = Unix.gettimeofday () +. secs in
  let rec go () =
    let n = in_pool node txs in
    if n >= want || Unix.gettimeofday () > deadline then n
    else (Unix.sleepf 0.1; go ()) in
  go ()

(* ---- cases -------------------------------------------------------------- *)

(* The audit's message: pkgtxns from a peer that sent no sendpackages. *)
let test_unannounced_peer_ignored () =
  let f = Lazy.force fixture in
  let pkg = package f 0 in
  let fd = connect_peer f.node in
  send fd (P2p.PkgtxnsMsg { P2p.pkg_txs = pkg });
  ignore (collect fd 2.0);
  Unix.close fd;
  Alcotest.(check int) "un-negotiated pkgtxns: nothing enters the mempool"
    0 (wait_in_pool f.node pkg ~want:1 1.0)

(* The peer sent sendpackages, but camlcoin did not: not negotiated. *)
let test_peer_announced_only_ignored () =
  let f = Lazy.force fixture in
  let pkg = package f 1 in
  let fd = connect_peer ~sendpackages:true f.node in
  send fd (P2p.PkgtxnsMsg { P2p.pkg_txs = pkg });
  ignore (collect fd 2.0);
  Unix.close fd;
  Alcotest.(check int) "one-sided sendpackages: nothing enters the mempool"
    0 (wait_in_pool f.node pkg ~want:1 1.0)

(* Control: the same shape of package, sent as two plain tx messages, is
   accepted, so the two checks above can see an accepted package. *)
let test_control_plain_tx_accepted () =
  let f = Lazy.force fixture in
  let pkg = package f 2 in
  let fd = connect_peer f.node in
  List.iter (fun tx -> send fd (P2p.TxMsg tx)) pkg;
  let n = wait_in_pool f.node pkg ~want:2 10.0 in
  Unix.close fd;
  Alcotest.(check int) "control: both txs relayed as tx messages are accepted"
    2 n

let () =
  Random.self_init ();
  Alcotest.run "pkgtxns_gating" [
    "pkgtxns_gating", [
      Alcotest.test_case "pkgtxns from un-negotiated peer is ignored" `Slow
        test_unannounced_peer_ignored;
      Alcotest.test_case "pkgtxns after peer-only sendpackages is ignored" `Slow
        test_peer_announced_only_ignored;
      Alcotest.test_case "control: same package as tx messages is accepted" `Slow
        test_control_plain_tx_accepted;
    ]
  ]
