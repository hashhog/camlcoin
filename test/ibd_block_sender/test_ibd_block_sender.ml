(* IBD block bodies are bound to the peer they are in flight with (security
   audit 2026-10-31 H6).

   During IBD [Sync.receive_block] matched an incoming body on its hash only
   and recorded the peer the slot had been requested from.  Any peer could
   therefore answer a getdata sent to someone else; when that body failed
   validation, the block processor scored the *requested* peer 100
   ("invalid_block" -> ban), so an attacker could get honest peers banned
   one at a time (an eclipse aid).  Core only clears a block request for the
   peer it is in flight with (net_processing.cpp RemoveBlockRequest takes
   from_peer) and blames the actual sender (mapBlockSource / BlockChecked).

   The test boots a fresh regtest node, connects an honest peer and an
   attacker.  The honest peer announces a short chain; whenever the node asks
   the honest peer for a block, the attacker immediately sends a body with the
   right header and a wrong transaction list (bad merkle root).  The node must
   ignore that body, keep the requested peer, and finish the sync from it.

     dune build @test/ibd_block_sender/runtest *)

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

let connect_peer ?(ua = "/h6-test:0.1/") ?(services = 9L) node =
  let fd = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Unix.connect fd (Unix.ADDR_INET (Unix.inet_addr_loopback, node.p2pport));
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

let chain_len = 5

let make_chain () =
  let g = Consensus.regtest.Consensus.genesis_header in
  let prev = ref (Crypto.compute_block_hash g, g.Types.timestamp) in
  Array.init chain_len (fun i ->
    let b = build_block ~prev_hash:(fst !prev) ~height:(i + 1)
        ~prev_time:(snd !prev) () in
    prev := (hash_of b, b.Types.header.Types.timestamp);
    b)

(* Same header (so the same hash), different body: an extra copy of the
   coinbase makes the merkle root wrong.  Not a witness error, so the
   processor's BLOCK_MUTATED exemption does not apply and it scores. *)
let junk_body (b : Types.block) : Types.block =
  { b with Types.transactions = b.Types.transactions @ [List.hd b.Types.transactions] }

let contains hay needle =
  let n = String.length needle and h = String.length hay in
  let rec go i = i + n <= h && (String.sub hay i n = needle || go (i + 1)) in
  go 0

let peer_connected node ua =
  match rpc node "getpeerinfo" [] with
  | `List ps ->
    List.exists (function
        | `Assoc kv ->
          (match List.assoc_opt "subver" kv with
           | Some (`String s) -> contains s ua
           | _ -> false)
        | _ -> false) ps
  | _ -> false

type outcome = {
  height : int;
  honest_up : bool;           (* node still lists the honest peer *)
  honest_eof : bool;          (* node closed the honest peer's socket *)
  junk_sent : int;            (* bodies the attacker slipped in *)
  log : string;
}

let run_attack () : outcome =
  let datadir = match Sys.getenv_opt "CAMLCOIN_H6_DATADIR" with
    | Some d -> Unix.mkdir d 0o700; d
    | None ->
      (* Under the build dir, not /tmp (tmpfs is RAM on maxbox). *)
      let d = Filename.concat (Sys.getcwd ())
          (Printf.sprintf "ibd_sender_h6_%d" (Unix.getpid ())) in
      Test_tmp.rm_rf d;
      Unix.mkdir d 0o700;
      at_exit (fun () -> Test_tmp.rm_rf d);
      d in
  let rpcport = free_port () and p2pport = free_port () in
  let blocks = make_chain () in
  let by_hash = Hashtbl.create 16 in
  Array.iter (fun b -> Hashtbl.replace by_hash (Cstruct.to_string (hash_of b)) b) blocks;
  let node = start_node datadir rpcport p2pport in
  Fun.protect ~finally:(fun () -> stop_node node) @@ fun () ->
  let honest = connect_peer ~ua:"/h6-honest:0.1/" node in
  (* NODE_WITNESS only, no NODE_NETWORK: the node never picks the attacker
     as a download peer, so every getdata goes to the honest peer and every
     body the attacker sends is for a slot in flight with someone else. *)
  let attacker = connect_peer ~ua:"/h6-attacker:0.1/" ~services:8L node in
  let headers = P2p.HeadersMsg (Array.to_list (Array.map (fun b -> b.Types.header) blocks)) in
  let honest_eof = ref false and attacker_eof = ref false in
  let junk_sent = ref 0 in
  send honest headers;
  (* Both peers answer getheaders with the chain, so whichever one the node
     syncs headers from, it learns the same 5 headers. *)
  let serve fd =
    let rec drain acc =
      (* one non-blocking pass over what is already buffered *)
      match Unix.select [fd] [] [] 0.05 with
      | [], _, _ -> List.rev acc
      | _ ->
        (match read_msg fd (Unix.gettimeofday () +. 2.) with
         | None ->
           if fd == honest then honest_eof := true else attacker_eof := true;
           List.rev acc
         | Some m -> drain (m :: acc)) in
    if (fd == honest && !honest_eof) || (fd == attacker && !attacker_eof) then ()
    else
      List.iter (function
          | P2p.PingMsg n -> (try send fd (P2p.PongMsg n) with _ -> ())
          | P2p.GetheadersMsg _ -> (try send fd headers with _ -> ())
          | P2p.GetdataMsg items ->
            List.iter (fun (iv : P2p.inv_vector) ->
              match Hashtbl.find_opt by_hash (Cstruct.to_string iv.hash) with
              | None -> ()
              | Some b when fd == honest ->
                (* the attacker races in with a junk body first ... *)
                (try send attacker (P2p.BlockMsg (junk_body b)); incr junk_sent
                 with _ -> ());
                Unix.sleepf 0.3;
                (* ... then the requested peer serves the real one *)
                (try send fd (P2p.BlockMsg b) with _ -> honest_eof := true)
              | Some _ -> ())
              items
          | _ -> ()) (drain [])
  in
  let deadline = Unix.gettimeofday () +. 60. in
  let last_announce = ref (Unix.gettimeofday ()) in
  let rec loop () =
    if block_count node >= chain_len && Unix.gettimeofday () > !last_announce +. 1.
    then ()
    else if Unix.gettimeofday () > deadline then ()
    else begin
      serve honest; serve attacker;
      if Unix.gettimeofday () -. !last_announce > 3. && not !honest_eof then begin
        last_announce := Unix.gettimeofday ();
        (try send honest headers with _ -> honest_eof := true)
      end;
      Unix.sleepf 0.1;
      loop ()
    end in
  loop ();
  (* give a ban a moment to land *)
  Unix.sleepf 1.0;
  serve honest;
  let o = { height = block_count node;
            honest_up = peer_connected node "/h6-honest:0.1/";
            honest_eof = !honest_eof;
            junk_sent = !junk_sent;
            log = Filename.concat datadir "node.log" } in
  (try Unix.close honest with _ -> ());
  (try Unix.close attacker with _ -> ());
  o

let outcome = lazy (run_attack ())

let describe o =
  Printf.sprintf "height=%d honest_up=%b honest_eof=%b junk_sent=%d"
    o.height o.honest_up o.honest_eof o.junk_sent

(* Instrument check: the attack actually ran (the node asked for blocks
   and the attacker raced a junk body against at least one request).  If
   this fails the other cases say nothing. *)
let test_attack_ran () =
  let o = Lazy.force outcome in
  print_endline (describe o);
  Alcotest.(check bool) "attacker raced at least one junk body" true (o.junk_sent > 0)

let test_requested_peer_not_banned () =
  let o = Lazy.force outcome in
  Alcotest.(check bool)
    ("requested (honest) peer not disconnected for another peer's body: " ^ describe o)
    false o.honest_eof;
  Alcotest.(check bool)
    ("requested (honest) peer still in getpeerinfo: " ^ describe o)
    true o.honest_up

let test_sync_completes_from_requested_peer () =
  let o = Lazy.force outcome in
  Alcotest.(check int) ("IBD completes from the honest peer: " ^ describe o)
    chain_len o.height

let () =
  Alcotest.run "ibd_block_sender"
    [ "h6",
      [ Alcotest.test_case "attack ran (junk body raced a getdata)" `Slow
          test_attack_ran;
        Alcotest.test_case "block body from a non-requested peer does not get the requested peer banned"
          `Slow test_requested_peer_not_banned;
        Alcotest.test_case "IBD completes from the requested peer" `Slow
          test_sync_completes_from_requested_peer ] ]
