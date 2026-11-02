(* A crash between the two chainstate commits must boot to a consistent tip
   (security audit H11 + H12, item fix-camlcoin-sec-h11).

   camlcoin keeps its coins in two RocksDB instances: rocksdb_utxo/ (the set
   block validation and gettxoutsetinfo read) and the chainstate column
   families (a mirror of the coins, plus the tip, the height index, undo and
   bodies).  A WriteBatch is per instance, so every commit is two writes,
   rocksdb_utxo first.  Boot compared the two recorded tip HEIGHTS only.

   H11: the IBD flush writes rocksdb_utxo (coins + tip_height H), then the
   chainstate coins, then the tip.  Killed in between, boot sees rdb_tip H
   above chain_tip F.  Under assumevalid (the default, and how a real IBD
   runs) no bodies or undo are stored, so the reconcile fails, the tip is
   rewound to 0, and rocksdb_utxo is left full.  The next boot skips the
   check (blocks_synced = 0) and the node re-syncs from genesis against
   the coin set of H.

   H12: a reorg writes the new branch's coins to rocksdb_utxo, then the
   chainstate batch (tip, height index, undo).  Killed in between, the
   chainstate still names the old branch.  Heights cannot tell which
   branch a coin set belongs to.

   Core has one coins DB: DB_HEAD_BLOCKS goes in the same batch as the coins
   and ReplayBlocks rolls forward by hash at boot (txdb.cpp BatchWrite,
   validation.cpp ReplayBlocks).

   Each case forks a child that runs the library's own IBD or reorg path and
   SIGKILLs itself from the existing write-fault hook at the first chainstate
   write after rocksdb_utxo has committed, i.e. exactly between the two
   commits.  The parent then boots bin/main.exe on the datadir and compares
   it over RPC with a clean node built the same way without the crash.

     dune build @test/two_db_commit_marker/runtest --force *)

open Camlcoin

(* ---------- blocks ---------- *)

let op_true = Cstruct.of_string "\x51"

let remine (block : Types.block) : Types.block =
  let h = ref block.Types.header in
  let n = ref 0l in
  let found = ref false in
  while (not !found) && Int32.compare !n 5_000_000l < 0 do
    h := { !h with Types.nonce = !n };
    if Consensus.hash_meets_target (Crypto.compute_block_hash !h) !h.Types.bits
    then found := true
    else n := Int32.add !n 1l
  done;
  if not !found then failwith "remine: no nonce found";
  { block with Types.header = !h }

let make_block ~prev_hash ~prev_time ~height ?(fee = 0L) ?(tag = 0)
    (txs : Types.transaction list) : Types.block =
  let extra_nonce = Cstruct.create 8 in
  Cstruct.LE.set_uint64 extra_nonce 0 (Int64.of_int (height + (tag lsl 32)));
  let mk wr =
    Mining.create_coinbase ~height ~total_fee:fee ~payout_script:op_true
      ~extra_nonce ~witness_root:wr ~network_type:Consensus.Regtest ()
  in
  let placeholder = mk None in
  let wr = Mining.compute_witness_merkle_root (placeholder :: txs) in
  let coinbase = mk (Some wr) in
  let all = coinbase :: txs in
  let merkle_root, _ = Crypto.merkle_root (List.map Crypto.compute_txid all) in
  remine { Types.header = { version = 4l; prev_block = prev_hash; merkle_root;
                            timestamp = Int32.add prev_time 600l;
                            bits = Consensus.regtest.pow_limit; nonce = 0l };
           transactions = all }

let spend ?(fee = 1000L) ?(tag = 0) (prev : Types.hash256) (value : int64) =
  let pad = Cstruct.create 22 in
  Cstruct.set_uint8 pad 0 0x6a; Cstruct.set_uint8 pad 1 0x14;
  Cstruct.set_uint8 pad 2 tag;
  { Types.version = 2l;
    inputs = [ { Types.previous_output = { Types.txid = prev; vout = 0l };
                 script_sig = Cstruct.create 0; sequence = 0xFFFFFFFFl } ];
    outputs = [ { Types.value = Int64.sub value fee; script_pubkey = op_true };
                { Types.value = 0L; script_pubkey = pad } ];
    witnesses = []; locktime = 0l }

let hash_of (b : Types.block) = Crypto.compute_block_hash b.Types.header
let hex_of_hash h = Types.hash256_to_hex_display h
let cb_txid (b : Types.block) = Crypto.compute_txid (List.hd b.Types.transactions)
let subsidy = Consensus.block_subsidy_for_network Consensus.Regtest 1

let block_hex (b : Types.block) =
  let w = Serialize.writer_create () in
  Serialize.serialize_block w b;
  let s = Serialize.writer_to_string w in
  String.concat "" (List.init (String.length s) (fun i ->
    Printf.sprintf "%02x" (Char.code s.[i])))

(* Extend [prev] by one block.  [txs] spend; [fee] goes to the coinbase. *)
let next ?(tag = 0) ?(txs = []) (prev : Types.block) height =
  let fee = Int64.of_int (1000 * List.length txs) in
  make_block ~prev_hash:(hash_of prev) ~prev_time:prev.Types.header.Types.timestamp
    ~height ~fee ~tag txs

(* ---------- IBD chain (H11) ----------
   Bodies 1..1000 are connected by the child's IBD; it flushes at 500 and
   at 1000 (utxo_flush_interval) and is killed inside the second flush, so
   the crash window is 501..1000.  Headers run to [ibd_top] so that 1..1000
   sit more than two weeks of work below the best header: the assumevalid
   path then skips scripts AND skips storing bodies and undo, as on mainnet.
   Block 600 spends coinbase 1 and creates O1; block 1001 spends O1. *)

let ibd_top = 3100
let ibd_head = 1000

type ibd_chain = {
  blocks : Types.block array;      (* index = height, 1..ibd_top *)
  bad_1001 : Types.block;          (* on 1000: re-spends coinbase 1 *)
}

let build_ibd_chain () =
  let net = Consensus.regtest in
  let genesis = { Types.header = net.Consensus.genesis_header; transactions = [] } in
  let blocks = Array.make (ibd_top + 1) genesis in
  let o1 = ref Types.zero_hash in
  for h = 1 to ibd_top do
    let txs =
      if h = 600 then begin
        let t = spend ~tag:6 (cb_txid blocks.(1)) subsidy in
        o1 := Crypto.compute_txid t; [ t ]
      end
      else if h = 1001 then [ spend ~tag:11 !o1 (Int64.sub subsidy 1000L) ]
      else []
    in
    let prev =
      if h = 1 then None else Some blocks.(h - 1) in
    blocks.(h) <-
      (match prev with
       | Some p -> next ~tag:1 ~txs p h
       | None ->
         make_block ~prev_hash:net.Consensus.genesis_hash
           ~prev_time:net.Consensus.genesis_header.Types.timestamp ~height:1
           ~tag:1 txs)
  done;
  let bad_1001 =
    next ~tag:99 ~txs:[ spend ~tag:99 (cb_txid blocks.(1)) subsidy ]
      blocks.(1000) 1001 in
  { blocks; bad_1001 }

(* ---------- reorg chain (H12) ----------
   Common 1..103.  Branch A: 104 (spends coinbase 1 -> OA), 105..108.
   Branch B: 104 (spends coinbase 1 -> OB), 105, 106, then 107 (spends OB)
   and 107bad (spends coinbase 1 again).  The child connects A..105, then
   B106 makes B heavier and the reorg is killed between its two commits. *)

type reorg_chain = {
  common : Types.block list;       (* 1..103 *)
  a : Types.block array;           (* index 104..108 *)
  b : Types.block array;           (* index 104..107 *)
  b107_bad : Types.block;
}

let build_reorg_chain () =
  let net = Consensus.regtest in
  let first = make_block ~prev_hash:net.Consensus.genesis_hash
      ~prev_time:net.Consensus.genesis_header.Types.timestamp ~height:1 ~tag:1 [] in
  let common = Array.make 104 first in
  for h = 2 to 103 do common.(h) <- next ~tag:1 common.(h - 1) h done;
  let cb1 = cb_txid common.(1) in
  let a = Array.make 109 first and b = Array.make 108 first in
  a.(104) <- next ~tag:1 ~txs:[ spend ~tag:41 cb1 subsidy ] common.(103) 104;
  for h = 105 to 108 do a.(h) <- next ~tag:1 a.(h - 1) h done;
  let tb = spend ~tag:42 cb1 subsidy in
  b.(104) <- next ~tag:2 ~txs:[ tb ] common.(103) 104;
  b.(105) <- next ~tag:2 b.(104) 105;
  b.(106) <- next ~tag:2 b.(105) 106;
  b.(107) <- next ~tag:2
      ~txs:[ spend ~tag:43 (Crypto.compute_txid tb) (Int64.sub subsidy 1000L) ]
      b.(106) 107;
  let b107_bad = next ~tag:3 ~txs:[ spend ~tag:44 cb1 subsidy ] b.(106) 107 in
  { common = Array.to_list (Array.sub common 1 103); a; b; b107_bad }

(* ---------- child: build a datadir, optionally crash it ---------- *)

(* The layout bin/main.exe opens: <datadir>/chainstate + <datadir>/rocksdb_utxo,
   with the second attached to the first (cli.ml). *)
let open_layout datadir =
  let db = Storage.ChainDB.create ~write_buffer_mb:4 ~block_cache_mb:8
      (Filename.concat datadir "chainstate") in
  let rdb = Rocksdb_store.open_db ~write_buffer_mb:4 ~block_cache_mb:8
      (Filename.concat datadir "rocksdb_utxo") in
  Storage.ChainDB.attach_rocksdb_utxo db rdb;
  db, rdb

let accept state (b : Types.block) =
  match Sync.validate_header state b.Types.header with
  | Ok entry -> Sync.accept_header state entry
  | Error e -> failwith ("validate_header: " ^ e)

let cf_tip db = Storage.ChainDB.get_chain_tip db

(* What the crash hook does to the stores right before the SIGKILL, to model
   datadirs written by other builds. *)
type crash =
  | Clean                         (* no crash: the reference node *)
  | Kill                          (* kill between the two commits *)
  | Kill_unmarked                 (* ... and drop the head marker (older build) *)
  | Kill_wedged                   (* ... and leave what master's boot left:
                                     no marker, chain_tip 0 *)
  | Kill_forged_marker            (* ... and point the marker at a block that
                                     is not in the header index *)

let head_marker_key = Rocksdb_store.meta_key "head_blocks"

let doctor kind db rdb =
  match kind with
  | Clean | Kill -> ()
  | Kill_unmarked -> Rocksdb_store.delete rdb head_marker_key
  | Kill_wedged ->
    Rocksdb_store.delete rdb head_marker_key;
    Storage.ChainDB.set_chain_tip db (Cstruct.create 32) 0
  | Kill_forged_marker ->
    let old = match cf_tip db with
      | Some (h, _) -> Cstruct.to_string h | None -> String.make 32 '\000' in
    let forged = String.make 32 '\x5a' in
    Rocksdb_store.put rdb head_marker_key
      (forged ^ old ^ Rocksdb_store.encode_tip_height ibd_head)

let kill_self () =
  Unix.kill (Unix.getpid ()) Sys.sigkill;
  Unix._exit 99

(* Run [f] in a forked child.  [Kill*] children must die by SIGKILL; a
   [Clean] child must exit 0. *)
let in_child ~kind f =
  match Unix.fork () with
  | 0 ->
    (try f (); Unix._exit 0 with e ->
       Printf.printf "  child raised: %s\n%!" (Printexc.to_string e);
       Unix._exit 3)
  | pid ->
    (match snd (Unix.waitpid [] pid), kind with
     | Unix.WSIGNALED s, (Kill | Kill_unmarked | Kill_wedged | Kill_forged_marker)
       when s = Sys.sigkill -> ()
     | Unix.WEXITED 0, Clean -> ()
     | Unix.WEXITED n, _ -> Alcotest.failf "child exited %d" n
     | _ -> Alcotest.fail "child: unexpected status")

let ibd_child (c : ibd_chain) ~kind path () =
  let net = { Consensus.regtest with
              Consensus.assume_valid_hash = Some (hash_of c.blocks.(ibd_top)) } in
  let db, rdb = open_layout path in
  let state = Sync.create_chain_state db net in
  let utxo = Utxo.OptimizedUtxoSet.create ~cache_size:100_000 ~rocksdb:rdb db in
  Sync.shared_utxo_set := Some utxo;
  for h = 1 to ibd_top do accept state c.blocks.(h) done;
  state.Sync.blocks_synced <- 0;
  state.Sync.sync_state <- Sync.SyncingBlocks;
  let ibd = Sync.create_ibd_state ~utxo_set:utxo state in
  for h = 1 to ibd_head do
    let b = c.blocks.(h) in
    Sync.queue_add ibd
      { Sync.hash = hash_of b; height = h;
        download_state = Sync.Downloaded { block = b; peer_id = None };
        tried_peers = [] }
  done;
  if kind <> Clean then
    Fatal.write_fault_hook := Some (fun what ->
      (* rocksdb_utxo already holds the coins of [ibd_head]; the chainstate
         does not yet. *)
      if what = "batch_write"
         && Rocksdb_store.get_tip_height rdb = Some ibd_head
         && (match cf_tip db with Some (_, h) -> h <> ibd_head | None -> true)
      then begin doctor kind db rdb; kill_self () end);
  (match Lwt_main.run (Sync.process_downloaded_blocks ~max_blocks:ibd_head ibd)
   with
   | Ok n when n = ibd_head -> ()
   | Ok n -> failwith (Printf.sprintf "IBD connected %d" n)
   | Error e -> failwith e);
  (* Never reached by a [Kill*] child. *)
  if Storage.ChainDB.has_block db (hash_of c.blocks.(700)) then
    failwith "assumevalid IBD stored a body: the case would not model mainnet";
  (match cf_tip db with
   | Some (_, h) when h = ibd_head -> ()
   | _ -> failwith "clean IBD did not commit the tip");
  Rocksdb_store.close rdb;
  Storage.ChainDB.close db

let at_tip state (b : Types.block) =
  accept state b;
  match Lwt_main.run (Sync.process_new_block ~f_requested:true state b) with
  | Ok () -> ()
  | Error e -> failwith (Printf.sprintf "process_new_block: %s" e)

let reorg_child (blocks : Types.block list) ~crash_on path () =
  let db, rdb = open_layout path in
  let state = Sync.create_chain_state db Consensus.regtest in
  let utxo = Utxo.OptimizedUtxoSet.create ~cache_size:100_000 ~rocksdb:rdb db in
  Sync.shared_utxo_set := Some utxo;
  state.Sync.sync_state <- Sync.FullySynced;
  List.iter (fun b ->
    (match crash_on with
     | Some (trigger, (new_tip : Types.block), (old_tip : Types.block))
       when Cstruct.equal (hash_of b) (hash_of trigger) ->
       let key = Storage.ChainDB.rocksdb_utxo_key (cb_txid new_tip) 0 in
       Fatal.write_fault_hook := Some (fun what ->
         (* rocksdb_utxo holds the new branch; the chainstate still names
            the old tip. *)
         if what = "batch_write" && Rocksdb_store.get rdb key <> None
            && (match cf_tip db with
                | Some (h, _) -> Cstruct.equal h (hash_of old_tip)
                | None -> false)
         then kill_self ())
     | _ -> ());
    at_tip state b) blocks;
  Rocksdb_store.close rdb;
  Storage.ChainDB.close db

(* ---------- parent: boot bin/main.exe on a datadir ---------- *)

let main_exe =
  let p = Filename.concat (Sys.getcwd ()) "../../bin/main.exe" in
  if Sys.file_exists p then p else failwith ("missing " ^ p)

let free_port () =
  let s = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Unix.bind s (Unix.ADDR_INET (Unix.inet_addr_loopback, 0));
  let p = match Unix.getsockname s with
    | Unix.ADDR_INET (_, p) -> p | _ -> assert false in
  Unix.close s; p

let read_file p =
  let ic = open_in_bin p in
  Fun.protect ~finally:(fun () -> close_in ic)
    (fun () -> really_input_string ic (in_channel_length ic))

let http_post port ~auth body =
  let s = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Fun.protect ~finally:(fun () -> try Unix.close s with _ -> ()) (fun () ->
    Unix.connect s (Unix.ADDR_INET (Unix.inet_addr_loopback, port));
    let req = Printf.sprintf "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\n\
                              Connection: close\r\nAuthorization: Basic %s\r\n\
                              Content-Type: application/json\r\n\
                              Content-Length: %d\r\n\r\n%s"
        (Base64.encode_string auth) (String.length body) body in
    ignore (Unix.write_substring s req 0 (String.length req));
    let buf = Buffer.create 4096 and b = Bytes.create 65536 in
    let rec rd () =
      match Unix.select [s] [] [] 120.0 with
      | [], _, _ -> ()
      | _ ->
        let n = try Unix.read s b 0 65536 with Unix.Unix_error _ -> 0 in
        if n > 0 then (Buffer.add_subbytes buf b 0 n; rd ()) in
    rd ();
    let r = Buffer.contents buf in
    match String.index_opt r '{' with
    | Some i -> String.sub r i (String.length r - i)
    | None -> failwith ("no JSON in RPC reply: " ^ r))

type node = { call : string -> Yojson.Safe.t list -> Yojson.Safe.t;
              log : string }

(* Boot main.exe on [datadir], wait for RPC, run [f], stop the node over RPC
   (a clean shutdown, so the next boot of the same datadir is a normal one). *)
let with_node datadir f =
  let rpcport = free_port () and p2pport = free_port ()
  and mport = free_port () in
  let log = Filename.concat datadir "node.log" in
  let fd = Unix.openfile log [Unix.O_WRONLY; Unix.O_CREAT; Unix.O_APPEND] 0o600 in
  let args = [| main_exe; "--network=regtest"; "--datadir=" ^ datadir;
                "--rpchost=127.0.0.1"; Printf.sprintf "--rpcport=%d" rpcport;
                Printf.sprintf "--port=%d" p2pport;
                Printf.sprintf "--metricsport=%d" mport; "--nodnsseed";
                "--dbcache=65536";
                "--connect=127.0.0.1:1" |] in
  let pid = Unix.create_process main_exe args Unix.stdin fd fd in
  Unix.close fd;
  let cookie = Filename.concat datadir ".cookie" in
  let raw meth params =
    let body = Yojson.Safe.to_string
        (`Assoc [ "jsonrpc", `String "1.0"; "id", `Int 1;
                  "method", `String meth; "params", `List params ]) in
    Yojson.Safe.from_string (http_post rpcport ~auth:(read_file cookie) body) in
  let call meth params =
    match raw meth params with
    | `Assoc kv ->
      (match List.assoc_opt "error" kv with
       | Some (`Assoc _ as e) ->
         failwith (Printf.sprintf "%s: %s" meth (Yojson.Safe.to_string e))
       | _ -> (match List.assoc_opt "result" kv with Some r -> r | None -> `Null))
    | j -> failwith ("bad reply: " ^ Yojson.Safe.to_string j) in
  let alive () = match Unix.waitpid [Unix.WNOHANG] pid with
    | 0, _ -> true | _ -> false | exception Unix.Unix_error _ -> false in
  let reap () =
    (try ignore (raw "stop" []) with _ -> ());
    let rec wait n =
      match Unix.waitpid [Unix.WNOHANG] pid with
      | 0, _ when n > 0 -> Unix.sleepf 0.1; wait (n - 1)
      | 0, _ ->
        (* our own child, still up after 60 s: force it *)
        (try Unix.kill pid Sys.sigkill with _ -> ());
        ignore (Unix.waitpid [] pid)
      | _ -> ()
      | exception Unix.Unix_error (Unix.ECHILD, _, _) -> () in
    wait 600 in
  Fun.protect ~finally:reap (fun () ->
    let rec ready n =
      if not (alive ()) then
        failwith ("node exited during boot; log:\n" ^ read_file log)
      else if n = 0 then failwith ("node RPC did not come up; log:\n" ^ read_file log)
      else match Sys.file_exists cookie && (ignore (call "getblockcount" []); true) with
        | true -> ()
        | false | exception _ -> Unix.sleepf 0.2; ready (n - 1) in
    ready 900;
    f { call; log })

let to_int = function `Int n -> n | j -> failwith ("int: " ^ Yojson.Safe.to_string j)
let to_str = function `String s -> s | j -> Yojson.Safe.to_string j

(* The fields of gettxoutsetinfo that describe the coin set itself. *)
let utxo_summary (n : node) =
  match n.call "gettxoutsetinfo" [] with
  | `Assoc kv ->
    List.map (fun k -> k, (match List.assoc_opt k kv with
        | Some v -> Yojson.Safe.to_string v | None -> "<absent>"))
      [ "height"; "bestblock"; "txouts"; "total_amount"; "hash_serialized_3" ]
  | j -> failwith ("gettxoutsetinfo: " ^ Yojson.Safe.to_string j)

let contains ~sub s =
  let n = String.length sub in
  let rec go i = i + n <= String.length s
                 && (String.sub s i n = sub || go (i + 1)) in
  go 0

(* The boot log must show which recovery ran, so a pass cannot come from
   some other path happening to land on the same state. *)
let check_log (n : node) what sub =
  Alcotest.(check bool) what true (contains ~sub (read_file n.log))

let show_summary s =
  String.concat " " (List.map (fun (k, v) -> k ^ "=" ^ v) s)

let check_summary what ~expected ~got =
  Printf.printf "  %s\n    got      %s\n    expected %s\n%!" what
    (show_summary got) (show_summary expected);
  Alcotest.(check (list (pair string string))) what expected got

(* submitblock: [None] when accepted (Core returns null), else the reason. *)
let submit (n : node) b =
  match n.call "submitblock" [ `String (block_hex b) ] with
  | `Null -> None
  | j -> Some (to_str j)

(* After the node stopped: the chainstate coin mirror must hold exactly the
   coins rocksdb_utxo holds.  gettxout / ChainDB.get_utxo read the mirror
   first, so a coin it kept after rocksdb_utxo spent it would be a ghost. *)
let check_mirror datadir =
  let db, rdb = open_layout datadir in
  Fun.protect ~finally:(fun () ->
      Rocksdb_store.close rdb; Storage.ChainDB.close db) (fun () ->
    let set iter =
      let l = ref [] in
      iter (fun txid vout data -> l := (Cstruct.to_string txid, vout, data) :: !l);
      List.sort compare !l in
    let r = set (Rocksdb_store.iter_utxos rdb)
    and c = set (Storage.ChainDB.iter_utxos db) in
    let extra = List.filter (fun x -> not (List.mem x r)) c
    and missing = List.filter (fun x -> not (List.mem x c)) r in
    Printf.printf "  coin mirror: rocksdb_utxo %d, chainstate %d \
                   (only in chainstate %d, only in rocksdb_utxo %d)\n%!"
      (List.length r) (List.length c) (List.length extra) (List.length missing);
    Alcotest.(check int) "no coin only in the chainstate mirror" 0
      (List.length extra);
    Alcotest.(check int) "no coin missing from the chainstate mirror" 0
      (List.length missing))

(* ---------- shared fixtures ---------- *)

let ibd_chain = lazy (build_ibd_chain ())
let reorg_chain = lazy (build_reorg_chain ())

(* NOT Test_tmp: a datadir under /tmp/camlcoin_* has its chainstate/
   deleted by Cf_chainstate's at_exit in EVERY process that opened it,
   bin/main.exe included, so the second boot of the same datadir would
   start from an empty chainstate.  These cases boot one datadir several
   times, so they use their own prefix and clean up here. *)
let scratch = ref []
let () = at_exit (fun () -> List.iter Test_tmp.rm_rf !scratch)
let dir label =
  let p = Printf.sprintf "%s/h11_two_db_%s_%d_%d"
      (Filename.get_temp_dir_name ()) label (Unix.getpid ())
      (List.length !scratch) in
  Test_tmp.rm_rf p;
  Unix.mkdir p 0o755;
  scratch := p :: !scratch;
  p

(* gettxoutsetinfo of a clean node, computed once per fixture. *)
let memo f = let v = ref None in fun () ->
    match !v with Some x -> x | None -> let x = f () in v := Some x; x

let ibd_reference = memo (fun () ->
  let c = Lazy.force ibd_chain in
  let path = dir "h11_ibd_ref" in
  in_child ~kind:Clean (ibd_child c ~kind:Clean path);
  with_node path (fun n ->
    let at_head = utxo_summary n in
    (match submit n c.blocks.(ibd_head + 1) with
     | None -> () | Some e -> Alcotest.failf "reference 1001: %s" e);
    (at_head, utxo_summary n)))

let genesis_reference = memo (fun () ->
  let path = dir "h11_genesis_ref" in
  with_node path utxo_summary)

let crashed_ibd kind =
  let c = Lazy.force ibd_chain in
  let path = dir "h11_ibd_crash" in
  in_child ~kind (ibd_child c ~kind path);
  (* the instrument: the child really died between the two commits *)
  let db, rdb = open_layout path in
  let rdb_tip = Rocksdb_store.get_tip_height rdb and cf = cf_tip db in
  Rocksdb_store.close rdb; Storage.ChainDB.close db;
  Printf.printf "  after kill -9: rocksdb_utxo tip %s, chainstate tip %s\n%!"
    (match rdb_tip with Some h -> string_of_int h | None -> "none")
    (match cf with Some (_, h) -> string_of_int h | None -> "none");
  Alcotest.(check (option int)) "rocksdb_utxo committed the head" (Some ibd_head)
    rdb_tip;
  Alcotest.(check bool) "chainstate tip not committed" true
    (match cf with Some (_, h) -> h < ibd_head | None -> true);
  path

(* ---------- H11 cases ---------- *)

(* Kill inside the IBD flush; boot must land on a tip whose coin set is the
   one a clean node has there, and keep validating from it. *)
let test_ibd_flush_crash () =
  let c = Lazy.force ibd_chain in
  let ref_head, ref_1001 = ibd_reference () in
  let path = crashed_ibd Kill in
  with_node path (fun n ->
    check_summary "recovered coin set == clean node at 1000"
      ~expected:ref_head ~got:(utxo_summary n);
    check_log n "boot rolled forward by the head marker (mirror rebuilt)"
      "coin mirror rebuilt from rocksdb_utxo";
    (* consensus: a block re-spending a coin spent inside the crash window
       (coinbase 1, spent at 600) stays invalid ... *)
    let bad = submit n c.bad_1001 in
    Printf.printf "  1001 re-spending coinbase 1: %s\n%!"
      (match bad with None -> "ACCEPTED" | Some e -> e);
    Alcotest.(check bool) "re-spend of a window-spent coin rejected" true
      (bad <> None);
    (* ... and a block spending a coin created inside the window (O1, 600)
       stays valid. *)
    let good = submit n c.blocks.(ibd_head + 1) in
    Printf.printf "  1001 spending O1: %s\n%!"
      (match good with None -> "accepted" | Some e -> e);
    Alcotest.(check (option string)) "1001 spending a window coin accepted"
      None good;
    check_summary "coin set after 1001 == clean node" ~expected:ref_1001
      ~got:(utxo_summary n));
  check_mirror path;
  (* a second, clean boot keeps the state *)
  with_node path (fun n ->
    check_summary "second boot keeps the coin set" ~expected:ref_1001
      ~got:(utxo_summary n))

(* A rewind to genesis must wipe rocksdb_utxo: re-syncing from block 1 on
   top of the coins of 1000 meets every coin twice (BIP30 / spent inputs). *)
let rewind_to_genesis_is_clean kind () =
  let c = Lazy.force ibd_chain in
  let gen = genesis_reference () in
  let path = crashed_ibd kind in
  with_node path (fun n ->
    check_summary "rewound coin set == fresh node at genesis"
      ~expected:gen ~got:(utxo_summary n);
    check_log n "boot wiped the coin stores" "wiped both coin stores";
    for h = 1 to 3 do
      match submit n c.blocks.(h) with
      | None -> ()
      | Some e -> Alcotest.failf "re-sync block %d rejected: %s" h e
    done;
    Alcotest.(check int) "re-sync from genesis connects" 3
      (to_int (n.call "getblockcount" [])));
  check_mirror path;
  with_node path (fun n ->
    Alcotest.(check int) "second boot keeps the re-synced tip" 3
      (to_int (n.call "getblockcount" [])))

(* ---------- H12 case ---------- *)

let reorg_reference blocks label = memo (fun () ->
  let path = dir label in
  in_child ~kind:Clean (reorg_child blocks ~crash_on:None path);
  with_node path utxo_summary)

let ref_b106 = memo (fun () ->
  let r = Lazy.force reorg_chain in
  reorg_reference (r.common @ [ r.b.(104); r.b.(105); r.b.(106) ]) "h12_ref_b" ())

let ref_a108 = memo (fun () ->
  let r = Lazy.force reorg_chain in
  reorg_reference (r.common @ Array.to_list (Array.sub r.a 104 5)) "h12_ref_a" ())

let test_reorg_crash () =
  let r = Lazy.force reorg_chain in
  let ref_b = ref_b106 () and ref_a = ref_a108 () in
  let path = dir "h12_reorg_crash" in
  let blocks = r.common @ [ r.a.(104); r.a.(105); r.b.(104); r.b.(105); r.b.(106) ] in
  in_child ~kind:Kill
    (reorg_child blocks ~crash_on:(Some (r.b.(106), r.b.(106), r.a.(105))) path);
  with_node path (fun n ->
    let best = to_str (n.call "getbestblockhash" []) in
    Printf.printf "  best after boot: %s (B106 %s, A105 %s)\n%!" best
      (hex_of_hash (hash_of r.b.(106))) (hex_of_hash (hash_of r.a.(105)));
    check_summary "recovered coin set == clean node at B106"
      ~expected:ref_b ~got:(utxo_summary n);
    check_log n "boot rolled forward by the head marker (blocks replayed)"
      "coin mirror replayed from block data";
    Alcotest.(check string) "getblockhash 104 is on the recovered branch"
      (hex_of_hash (hash_of r.b.(104)))
      (to_str (n.call "getblockhash" [ `Int 104 ]));
    (* consensus: coinbase 1 is spent on B104; spending it again is invalid *)
    let bad = submit n r.b107_bad in
    Printf.printf "  B107 re-spending coinbase 1: %s\n%!"
      (match bad with None -> "ACCEPTED" | Some e -> e);
    Alcotest.(check bool) "re-spend of a B-spent coin rejected" true (bad <> None);
    Alcotest.(check (option string)) "B107 spending OB (created on B104) accepted"
      None (submit n r.b.(107));
    Alcotest.(check int) "tip 107" 107 (to_int (n.call "getblockcount" [])));
  check_mirror path;
  (* The recovered branch must still be disconnectable (its undo data must
     have survived the crash): A106..A108 outweigh B107. *)
  with_node path (fun n ->
    for h = 106 to 108 do ignore (submit n r.a.(h)) done;
    Alcotest.(check string) "reorg back to A108"
      (hex_of_hash (hash_of r.a.(108))) (to_str (n.call "getbestblockhash" []));
    check_summary "coin set after reorg back == clean node at A108"
      ~expected:ref_a ~got:(utxo_summary n));
  check_mirror path

let () =
  Alcotest.run "two_db_commit_marker" [
    "H11 IBD flush", [
      Alcotest.test_case "kill between rocksdb_utxo and chainstate commits \
                          recovers to the committed coin set" `Quick
        test_ibd_flush_crash;
      Alcotest.test_case "unmarked datadir: rewind to genesis wipes \
                          rocksdb_utxo" `Quick
        (rewind_to_genesis_is_clean Kill_unmarked);
      Alcotest.test_case "datadir already rewound to 0 over a full \
                          rocksdb_utxo is wiped at boot" `Quick
        (rewind_to_genesis_is_clean Kill_wedged);
      Alcotest.test_case "head marker naming an unknown block is not \
                          trusted" `Quick
        (rewind_to_genesis_is_clean Kill_forged_marker);
    ];
    "H12 reorg", [
      Alcotest.test_case "kill between the reorg's two commits recovers \
                          to the new branch, which stays disconnectable" `Quick
        test_reorg_crash;
    ];
  ]
