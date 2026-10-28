(* Rpc.start_rpc_server must bind the address it is given.

   It used to hand Conduit [`TCP (`Port port)] with no source address, which
   Conduit binds to INADDR_ANY: the node logged "Starting RPC server on
   127.0.0.1:8357" while mainnet listened on 0.0.0.0:8357.  Core binds
   -rpcbind (default loopback only, httpserver.cpp HTTPBindAddresses).

   The bound address is read from /proc/net/tcp (the kernel's own view of the
   LISTEN socket), and cross-checked by connecting through 127.0.0.2: on Linux
   all of 127/8 reaches lo, so a socket bound to 127.0.0.1 refuses it while a
   wildcard socket accepts it. *)

open Camlcoin

let make_rpc_ctx db_path =
  let db = Storage.ChainDB.create db_path in
  let utxo = Utxo.UtxoSet.create db in
  let mempool =
    Mempool.create ~network:Consensus.regtest ~require_standard:false
      ~verify_scripts:false ~utxo ~current_height:0 ()
  in
  let network = Consensus.regtest in
  let chain_state = Sync.create_chain_state db network in
  let peer_manager = Peer_manager.create network in
  let fee_estimator = Fee_estimation.create () in
  Rpc.create_context ~chain:chain_state ~mempool ~peer_manager ~wallet:None
    ~fee_estimator ~network ()

let pick_free_port () =
  let s = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Unix.bind s (Unix.ADDR_INET (Unix.inet_addr_any, 0));
  let port =
    match Unix.getsockname s with
    | Unix.ADDR_INET (_, p) -> p
    | _ -> assert false
  in
  Unix.close s;
  port

(* /proc/net/tcp local_address is "AABBCCDD:PPPP": the IPv4 address as a
   host-order (little-endian on x86) hex word, the port in hex. State 0A is
   LISTEN.  Returns the dotted-quad of every LISTEN socket on [port]. *)
let listen_addrs_on port =
  let ic = open_in "/proc/net/tcp" in
  let rec loop acc =
    match input_line ic with
    | exception End_of_file -> close_in ic; List.rev acc
    | line ->
      let fields =
        List.filter (fun s -> s <> "") (String.split_on_char ' ' line) in
      (match fields with
       | _sl :: local :: _rem :: st :: _ when st = "0A" ->
         (match String.split_on_char ':' local with
          | [a; p] when int_of_string ("0x" ^ p) = port ->
            let w = int_of_string ("0x" ^ a) in
            let ip = Printf.sprintf "%d.%d.%d.%d"
                (w land 0xff) ((w lsr 8) land 0xff)
                ((w lsr 16) land 0xff) ((w lsr 24) land 0xff) in
            loop (ip :: acc)
          | _ -> loop acc)
       | _ -> loop acc)
  in
  ignore (input_line ic);  (* header *)
  loop []

let can_connect ip port =
  let s = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Fun.protect ~finally:(fun () -> try Unix.close s with _ -> ())
    (fun () ->
       try Unix.connect s (Unix.ADDR_INET (Unix.inet_addr_of_string ip, port));
         true
       with Unix.Unix_error _ -> false)

(* Start the RPC server on [host], wait for its LISTEN socket to appear, and
   return (bound addresses, reachable via 127.0.0.1, reachable via
   127.0.0.2).  Lwt.pick cancels the server once the probe is done. *)
let probe_bind host =
  Test_tmp.with_dir ~label:"rpc_bind_host" (fun db_path ->
    let ctx = make_rpc_ctx db_path in
    let port = pick_free_port () in
    let server =
      Rpc.start_rpc_server ~ctx ~host ~port ~rpc_user:"u" ~rpc_password:"p"
        ~cookie_password:None ()
    in
    let rec wait n =
      match listen_addrs_on port with
      | [] when n > 0 -> Lwt.bind (Lwt_unix.sleep 0.05) (fun () -> wait (n - 1))
      | addrs ->
        Lwt.return (addrs, can_connect "127.0.0.1" port,
                    can_connect "127.0.0.2" port)
    in
    Lwt_main.run
      (Lwt.pick [ Lwt.bind server (fun () -> Lwt.fail_with "server exited");
                  wait 100 ]))

let check_bind ~host ~expect_addr ~expect_127_0_0_2 =
  let addrs, lo1, lo2 = probe_bind host in
  Alcotest.(check (list string))
    (Printf.sprintf "LISTEN address for host %s" host) [expect_addr] addrs;
  Alcotest.(check bool) "reachable on 127.0.0.1" true lo1;
  Alcotest.(check bool) "reachable on 127.0.0.2" expect_127_0_0_2 lo2

let test_default_host_is_loopback () =
  Alcotest.(check string) "default rpc_host" "127.0.0.1"
    Cli.default_config.rpc_host;
  check_bind ~host:Cli.default_config.rpc_host ~expect_addr:"127.0.0.1"
    ~expect_127_0_0_2:false

let test_wildcard_host_binds_all () =
  check_bind ~host:"0.0.0.0" ~expect_addr:"0.0.0.0" ~expect_127_0_0_2:true

let () =
  Alcotest.run "rpc_bind_host"
    [ ( "rpc_bind_host",
        [ Alcotest.test_case "default --rpchost binds 127.0.0.1 only" `Quick
            test_default_host_is_loopback;
          Alcotest.test_case "--rpchost 0.0.0.0 binds the wildcard" `Quick
            test_wildcard_host_binds_all ] ) ]
