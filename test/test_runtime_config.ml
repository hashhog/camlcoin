(* Tests for Runtime_config: PID file, conf parsing, debug categories,
   log-file reopen, ready-fd. The daemonize() entry point is NOT exercised
   directly because it would terminate the test runner via the parent fork
   exit. We instead verify the components it composes (fork-safe stdio
   redirect, PID file write, etc.). *)

open Camlcoin

(* ============================================================================
   Helpers
   ============================================================================ *)

let with_temp_dir (f : string -> 'a) : 'a =
  let tmp = Filename.temp_file "camlcoin-test-" "" in
  Unix.unlink tmp;
  Unix.mkdir tmp 0o700;
  let cleanup () =
    let rm_rf path =
      let rec walk p =
        if Sys.file_exists p then begin
          if Sys.is_directory p then begin
            Array.iter (fun child -> walk (Filename.concat p child))
              (Sys.readdir p);
            (try Unix.rmdir p with _ -> ())
          end else
            (try Unix.unlink p with _ -> ())
        end
      in walk path
    in
    rm_rf tmp
  in
  let result =
    try f tmp
    with exn -> cleanup (); raise exn
  in
  cleanup ();
  result

let write_file (path : string) (content : string) : unit =
  let oc = open_out path in
  output_string oc content;
  close_out oc

let read_file (path : string) : string =
  let ic = open_in path in
  let n = in_channel_length ic in
  let s = really_input_string ic n in
  close_in ic;
  s

(* ============================================================================
   Conf-file parsing
   ============================================================================ *)

let test_parse_empty () =
  with_temp_dir (fun dir ->
    let p = Filename.concat dir "empty.conf" in
    write_file p "";
    let opts = Runtime_config.parse_conf_file ~network:`Mainnet p in
    Alcotest.(check int) "no entries" 0 (List.length opts))

let test_parse_simple () =
  with_temp_dir (fun dir ->
    let p = Filename.concat dir "simple.conf" in
    write_file p "rpcuser=alice\nrpcpassword=secret\nmaxoutbound=16\n";
    let opts = Runtime_config.parse_conf_file ~network:`Mainnet p in
    Alcotest.(check (option string)) "rpcuser"
      (Some "alice") (Runtime_config.get_string opts "rpcuser");
    Alcotest.(check (option string)) "rpcpassword"
      (Some "secret") (Runtime_config.get_string opts "rpcpassword");
    Alcotest.(check (option int)) "maxoutbound"
      (Some 16) (Runtime_config.get_int opts "maxoutbound"))

let test_parse_comments_and_whitespace () =
  with_temp_dir (fun dir ->
    let p = Filename.concat dir "c.conf" in
    write_file p
      "# this is a comment\n  \n\
       rpcuser =  alice  \n\
       # another comment\n\
       prune=550\n";
    let opts = Runtime_config.parse_conf_file ~network:`Mainnet p in
    Alcotest.(check (option string)) "trimmed value"
      (Some "alice") (Runtime_config.get_string opts "rpcuser");
    Alcotest.(check (option int)) "prune" (Some 550)
      (Runtime_config.get_int opts "prune"))

let test_parse_sections () =
  with_temp_dir (fun dir ->
    let p = Filename.concat dir "s.conf" in
    write_file p
      "rpcuser=fallback\n\
       [main]\n\
       rpcuser=mainuser\n\
       [test]\n\
       rpcuser=testuser\n\
       [regtest]\n\
       rpcuser=regtestuser\n";
    let m = Runtime_config.parse_conf_file ~network:`Mainnet p in
    let t = Runtime_config.parse_conf_file ~network:`Testnet p in
    let r = Runtime_config.parse_conf_file ~network:`Regtest p in
    Alcotest.(check (option string)) "main user"
      (Some "mainuser") (Runtime_config.get_string m "rpcuser");
    Alcotest.(check (option string)) "test user"
      (Some "testuser") (Runtime_config.get_string t "rpcuser");
    Alcotest.(check (option string)) "regtest user"
      (Some "regtestuser") (Runtime_config.get_string r "rpcuser"))

let test_parse_bool () =
  with_temp_dir (fun dir ->
    let p = Filename.concat dir "b.conf" in
    write_file p
      "daemon=1\nprinttoconsole=true\nfoo=no\nbar=YES\n";
    let opts = Runtime_config.parse_conf_file ~network:`Mainnet p in
    Alcotest.(check (option bool)) "daemon=1"
      (Some true) (Runtime_config.get_bool opts "daemon");
    Alcotest.(check (option bool)) "printtoconsole=true"
      (Some true) (Runtime_config.get_bool opts "printtoconsole");
    Alcotest.(check (option bool)) "foo=no"
      (Some false) (Runtime_config.get_bool opts "foo");
    Alcotest.(check (option bool)) "bar=YES (case-insensitive)"
      (Some true) (Runtime_config.get_bool opts "bar"))

let test_parse_get_all () =
  with_temp_dir (fun dir ->
    let p = Filename.concat dir "ga.conf" in
    write_file p "connect=10.0.0.1:8333\nconnect=10.0.0.2:8333\n";
    let opts = Runtime_config.parse_conf_file ~network:`Mainnet p in
    let conns = Runtime_config.get_all opts "connect" in
    Alcotest.(check int) "two connect lines" 2 (List.length conns);
    Alcotest.(check (list string))
      "preserves order"
      ["10.0.0.1:8333"; "10.0.0.2:8333"] conns)

let test_parse_missing_file () =
  with_temp_dir (fun dir ->
    let p = Filename.concat dir "does-not-exist.conf" in
    let opts = Runtime_config.parse_conf_file ~network:`Mainnet p in
    Alcotest.(check int) "missing file => empty" 0 (List.length opts))

(* ============================================================================
   PID file
   ============================================================================ *)

let test_pid_write_and_read () =
  with_temp_dir (fun dir ->
    let path = Filename.concat dir "test.pid" in
    (match Runtime_config.write_pid_file path with
     | Ok () -> ()
     | Error e -> Alcotest.fail e);
    Alcotest.(check bool) "pid file exists" true (Sys.file_exists path);
    let s = read_file path in
    let pid = int_of_string (String.trim s) in
    Alcotest.(check int) "stored PID == self" (Unix.getpid ()) pid;
    Runtime_config.remove_pid_file ();
    Alcotest.(check bool) "pid file removed" false (Sys.file_exists path))

let test_pid_refuses_live_owner () =
  with_temp_dir (fun dir ->
    let path = Filename.concat dir "live.pid" in
    (* Fork a child that sleeps; capture its PID, write it to the pid file,
       then attempt write_pid_file and assert it refuses. We can't use our
       own PID because write_pid_file specifically allows that case (so an
       --restart from the same process can reclaim its file). *)
    let r, w = Unix.pipe () in
    match Unix.fork () with
    | 0 ->
      (* Child: signal parent we're alive then sleep. *)
      Unix.close r;
      let _ = Unix.write_substring w "x" 0 1 in
      Unix.close w;
      Unix.sleep 5;
      exit 0
    | child_pid ->
      Unix.close w;
      let buf = Bytes.create 1 in
      let _ = Unix.read r buf 0 1 in
      Unix.close r;
      write_file path (Printf.sprintf "%d\n" child_pid);
      let res = Runtime_config.write_pid_file path in
      (* Reap the child to avoid leaving zombies. *)
      (try Unix.kill child_pid Sys.sigterm with _ -> ());
      let _ = (try Unix.waitpid [] child_pid with _ -> (0, Unix.WEXITED 0)) in
      (match res with
       | Ok () ->
         Alcotest.fail "should have refused: file names a live process"
       | Error _ -> ()))

let test_pid_overrides_dead () =
  with_temp_dir (fun dir ->
    let path = Filename.concat dir "dead.pid" in
    (* PID 0 is never a real process; helper treats <=0 as not alive. *)
    write_file path "0\n";
    (match Runtime_config.write_pid_file path with
     | Ok () -> ()
     | Error e -> Alcotest.fail e);
    Runtime_config.remove_pid_file ())

(* ============================================================================
   Debug categories
   ============================================================================ *)

let test_debug_resolve_empty () =
  Alcotest.(check (list string)) "empty input"
    [] (Runtime_config.resolve_debug_categories [])

let test_debug_resolve_csv () =
  Alcotest.(check (list string)) "csv split + flatten"
    ["NET"; "RPC"; "MEMPOOL"]
    (Runtime_config.resolve_debug_categories ["NET,RPC"; "MEMPOOL"])

let test_debug_resolve_all () =
  Alcotest.(check (list string)) "'all' clears list"
    [] (Runtime_config.resolve_debug_categories ["all"]);
  Alcotest.(check (list string)) "'1' clears list"
    [] (Runtime_config.resolve_debug_categories ["1"])

let test_debug_resolve_none () =
  let r = Runtime_config.resolve_debug_categories ["none"] in
  Alcotest.(check int) "'none' returns sentinel"
    1 (List.length r);
  Alcotest.(check string) "sentinel value"
    "__none__" (List.hd r)

(* ============================================================================
   Overlay precedence (CLI > conf > default)
   ============================================================================ *)

let test_overlay_cli_wins () =
  let v = Runtime_config.overlay_string
    ~cli:(Some "fromcli") ~conf:(Some "fromconf") ~default:"def" in
  Alcotest.(check string) "cli beats conf" "fromcli" v

let test_overlay_conf_fills () =
  let v = Runtime_config.overlay_string
    ~cli:None ~conf:(Some "fromconf") ~default:"def" in
  Alcotest.(check string) "conf used" "fromconf" v

let test_overlay_default () =
  let v = Runtime_config.overlay_string
    ~cli:None ~conf:None ~default:"def" in
  Alcotest.(check string) "default used" "def" v

let test_overlay_int () =
  let cli_only = Runtime_config.overlay_int
    ~cli:(Some 5) ~conf:(Some 10) ~default:1 in
  let conf_only = Runtime_config.overlay_int
    ~cli:None ~conf:(Some 10) ~default:1 in
  let default = Runtime_config.overlay_int
    ~cli:None ~conf:None ~default:1 in
  Alcotest.(check int) "cli wins" 5 cli_only;
  Alcotest.(check int) "conf used" 10 conf_only;
  Alcotest.(check int) "default" 1 default

let test_overlay_bool () =
  (* When cli_set=true, cli_value wins regardless of conf. *)
  let v = Runtime_config.overlay_bool
    ~cli_set:true ~cli_value:false ~conf:(Some true) ~default:true in
  Alcotest.(check bool) "explicit cli=false beats conf=true" false v;
  let v2 = Runtime_config.overlay_bool
    ~cli_set:false ~cli_value:false ~conf:(Some true) ~default:false in
  Alcotest.(check bool) "no cli => conf wins" true v2

(* ============================================================================
   Log file install + reopen (SIGHUP)
   ============================================================================ *)

let test_logfile_install_and_reopen () =
  with_temp_dir (fun dir ->
    let path = Filename.concat dir "camlcoin.log" in
    Runtime_config.install_log_file_reporter ~also_console:false path;
    Logs.set_level (Some Logs.Info);
    Logs.info (fun m -> m "marker-before-rotate");
    let before = read_file path in
    Alcotest.(check bool) "logfile got first marker"
      true (String.length before > 0);
    (* Simulate rotation: rename and request a reopen. *)
    let rotated = path ^ ".1" in
    Unix.rename path rotated;
    Runtime_config.reopen_log_file ();
    Logs.info (fun m -> m "marker-after-rotate");
    let after_path = read_file path in
    Alcotest.(check bool) "new file created on reopen"
      true (Sys.file_exists path);
    Alcotest.(check bool) "new file contains post-rotate marker"
      true (String.length after_path > 0);
    (* Reset reporter so subsequent tests aren't logged into our temp file. *)
    Logs.set_reporter Logs.nop_reporter)

let test_pending_sighup_drain () =
  (* No log file installed: drain is a no-op + clears flag. *)
  Runtime_config.pending_sighup := true;
  Runtime_config.drain_pending_sighup ();
  Alcotest.(check bool) "flag cleared"
    false !Runtime_config.pending_sighup

(* ============================================================================
   Ready-fd handshake
   ============================================================================ *)

let test_ready_fd_writes_and_closes () =
  let r, w = Unix.pipe () in
  let w_int : int = (Obj.magic (w : Unix.file_descr) : int) in
  Runtime_config.signal_ready ~fd:w_int ();
  (* Read should see one byte then EOF. *)
  let buf = Bytes.create 4 in
  let n = Unix.read r buf 0 4 in
  Alcotest.(check int) "one byte read" 1 n;
  Alcotest.(check char) "ready byte" '1' (Bytes.get buf 0);
  (try Unix.close r with _ -> ())

let test_ready_fd_none_is_noop () =
  (* Just make sure signal_ready () with no fd does not raise. *)
  Runtime_config.signal_ready ();
  Alcotest.(check pass) "noop" () ()

(* ============================================================================
   Suite
   ============================================================================ *)

let () =
  let open Alcotest in
  run "runtime_config" [
    "conf_parsing", [
      test_case "empty file" `Quick test_parse_empty;
      test_case "simple key=value" `Quick test_parse_simple;
      test_case "comments and whitespace" `Quick
        test_parse_comments_and_whitespace;
      test_case "section selection" `Quick test_parse_sections;
      test_case "bool coercion" `Quick test_parse_bool;
      test_case "get_all returns multiple" `Quick test_parse_get_all;
      test_case "missing file => empty" `Quick test_parse_missing_file;
    ];
    "pid_file", [
      test_case "write/read/remove" `Quick test_pid_write_and_read;
      test_case "refuses live owner" `Quick test_pid_refuses_live_owner;
      test_case "overrides dead pid" `Quick test_pid_overrides_dead;
    ];
    "debug_categories", [
      test_case "empty input" `Quick test_debug_resolve_empty;
      test_case "csv split" `Quick test_debug_resolve_csv;
      test_case "all/1 special" `Quick test_debug_resolve_all;
      test_case "none/0 sentinel" `Quick test_debug_resolve_none;
    ];
    "overlay", [
      test_case "cli wins" `Quick test_overlay_cli_wins;
      test_case "conf fills" `Quick test_overlay_conf_fills;
      test_case "default fallback" `Quick test_overlay_default;
      test_case "int overlay" `Quick test_overlay_int;
      test_case "bool overlay" `Quick test_overlay_bool;
    ];
    "logfile", [
      test_case "install + SIGHUP-rotate" `Quick
        test_logfile_install_and_reopen;
      test_case "pending sighup drain" `Quick
        test_pending_sighup_drain;
    ];
    "ready_fd", [
      test_case "writes one byte and closes" `Quick
        test_ready_fd_writes_and_closes;
      test_case "no fd is no-op" `Quick test_ready_fd_none_is_noop;
    ];
  ]
