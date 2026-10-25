(* REST /rest/mempool/{info,contents}.json served on the JSON-RPC port.
   Core mounts REST on the shared HTTP listener; the regtest harness reaches
   camlcoin's REST through --rpcport, where every GET used to answer 405. *)

open Camlcoin

let db_path = Test_tmp.register "/tmp/camlcoin_test_rest_mempool_rpc_port_db"

let rec rm_rf path =
  if Sys.file_exists path then begin
    if Sys.is_directory path then begin
      Array.iter (fun f -> rm_rf (Filename.concat path f)) (Sys.readdir path);
      Unix.rmdir path
    end else Unix.unlink path
  end

let free_port () =
  let s = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Unix.bind s (Unix.ADDR_INET (Unix.inet_addr_loopback, 0));
  let p = match Unix.getsockname s with
    | Unix.ADDR_INET (_, p) -> p | _ -> assert false in
  Unix.close s; p

let make_ctx () =
  rm_rf db_path;
  let db = Storage.ChainDB.create db_path in
  let utxo = Utxo.UtxoSet.create db in
  let mempool = Mempool.create ~network:Consensus.regtest
      ~require_standard:false ~verify_scripts:false ~utxo ~current_height:0 () in
  let network = Consensus.regtest in
  let ctx = Rpc.create_context
      ~chain:(Sync.create_chain_state db network) ~mempool
      ~peer_manager:(Peer_manager.create network) ~wallet:None
      ~fee_estimator:(Fee_estimation.create ()) ~network () in
  (db, ctx)

let get port path =
  let uri = Uri.of_string (Printf.sprintf "http://127.0.0.1:%d%s" port path) in
  let open Lwt.Syntax in
  let* resp, body = Cohttp_lwt_unix.Client.get uri in
  let* b = Cohttp_lwt.Body.to_string body in
  Lwt.return (Cohttp.Response.status resp, b)

let test_rest_on_rpc_port () =
  let db, ctx = make_ctx () in
  let port = free_port () in
  Rpc.rest_hook := Some Rest.dispatch_rest;
  let result = Lwt_main.run (
    let open Lwt.Syntax in
    Lwt.async (fun () ->
      Rpc.start_rpc_server ~ctx ~host:"127.0.0.1" ~port
        ~rpc_user:"u" ~rpc_password:"p" ~cookie_password:None ());
    let* () = Lwt_unix.sleep 0.5 in
    let* info = get port "/rest/mempool/info.json" in
    let* contents = get port "/rest/mempool/contents.json" in
    let* other = get port "/notrest" in
    Lwt.return (info, contents, other)) in
  let (is, ib), (cs, cb), (os, _) = result in
  Alcotest.(check bool) "info 200" true (is = `OK);
  (match Yojson.Safe.from_string ib with
   | `Assoc f ->
     Alcotest.(check bool) "info has size" true (List.mem_assoc "size" f)
   | _ -> Alcotest.fail "info not an object");
  Alcotest.(check bool) "contents 200" true (cs = `OK);
  Alcotest.(check string) "empty mempool contents" "{}"
    (Yojson.Safe.to_string (Yojson.Safe.from_string cb));
  Alcotest.(check bool) "non-REST GET still 405" true (os = `Method_not_allowed);
  Storage.ChainDB.close db;
  rm_rf db_path

let () =
  Alcotest.run "REST mempool on RPC port"
    [ "rpc-port", [ "GET /rest/mempool/* on rpcport", `Quick, test_rest_on_rpc_port ] ]
