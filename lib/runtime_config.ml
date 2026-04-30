(* Runtime configuration: PID file, daemon mode, config file parsing,
   log-file rotation (SIGHUP), debug-category filter, ready-fd handshake.

   Closes the operational-parity gap with Bitcoin Core's
   src/init.cpp + src/util/system.cpp (g_pidfile_path, daemon()) and the
   "-conf=", "-debug=<cat>", "-printtoconsole" CLI surface.

   Design notes:
   - All operations are best-effort and never fatal except where the operator
     has explicitly requested a hard guarantee (e.g. PID file already exists
     for a live process => we refuse to start, mirroring Core's behaviour).
   - This module is pure I/O and global mutable state (file descriptors,
     reporter ref). It is NOT Lwt-aware: the daemonize() fork must run BEFORE
     Lwt_main.run, because Lwt_engine state does not survive a fork.
   - ZMQ wiring is intentionally NOT done here. The lib/zmq_notify.ml +
     lib/zmq_socket.ml scaffolding remains as TCP-mock; binding -lzmq is
     deferred (see HANDOFF report). *)

(* ============================================================================
   Config-file parsing (--conf=<file>)
   ----------------------------------------------------------------------------
   Bitcoin Core's bitcoin.conf grammar: key=value lines, '#' comments, blank
   lines ignored, whitespace trimmed. Section headers like [main] / [test]
   are recognised but for camlcoin we treat them as scope hints only — the
   running --network value selects the active section.
   ============================================================================ *)

let trim s =
  let n = String.length s in
  let i = ref 0 in
  while !i < n && (s.[!i] = ' ' || s.[!i] = '\t') do incr i done;
  let j = ref (n - 1) in
  while !j >= !i && (s.[!j] = ' ' || s.[!j] = '\t' || s.[!j] = '\r') do
    decr j
  done;
  if !j < !i then "" else String.sub s !i (!j - !i + 1)

(* Parse a config file into an association list of (key, value) pairs.
   Accepts [main] / [test] / [regtest] sections — keys inside a non-matching
   section are silently dropped (matches Core's chainparamsbase.cpp). *)
let parse_conf_file ~(network : [`Mainnet | `Testnet | `Regtest])
    (path : string) : (string * string) list =
  if not (Sys.file_exists path) then []
  else begin
    let ic = open_in path in
    let active_section = match network with
      | `Mainnet -> "main"
      | `Testnet -> "test"
      | `Regtest -> "regtest"
    in
    let current_section = ref "main" in (* default scope is mainnet *)
    let acc = ref [] in
    (try
       while true do
         let raw = input_line ic in
         let line = trim raw in
         if line = "" then ()
         else if line.[0] = '#' then ()
         else if String.length line >= 2
                 && line.[0] = '['
                 && line.[String.length line - 1] = ']' then
           current_section :=
             String.sub line 1 (String.length line - 2)
         else if !current_section = active_section
                 || !current_section = "main" then begin
           match String.index_opt line '=' with
           | Some i ->
             let k = trim (String.sub line 0 i) in
             let v = trim (String.sub line (i + 1)
                             (String.length line - i - 1)) in
             if k <> "" then acc := (k, v) :: !acc
           | None -> ()
         end
       done;
       assert false
     with End_of_file -> close_in ic);
    List.rev !acc
  end

(* Convenience getters with type coercion.

   Lookup returns the LAST matching value so that an explicit section
   override (e.g. [main] rpcuser=mainuser) wins over an earlier global
   default in the same file (rpcuser=fallback). Mirrors Core's
   ArgsManager::GetArg precedence within a single config file. *)
let assoc_last_opt key opts =
  List.fold_left (fun acc (k, v) ->
    if k = key then Some v else acc
  ) None opts

let get_string opts key = assoc_last_opt key opts
let get_int opts key = match assoc_last_opt key opts with
  | None -> None
  | Some v -> (try Some (int_of_string (trim v)) with _ -> None)
let get_bool opts key = match assoc_last_opt key opts with
  | None -> None
  | Some v -> (match String.lowercase_ascii (trim v) with
    | "1" | "true" | "yes" | "on" -> Some true
    | "0" | "false" | "no" | "off" -> Some false
    | _ -> None)

(* Collect all values for a key (e.g. multiple connect= lines). *)
let get_all opts key =
  List.filter_map (fun (k, v) -> if k = key then Some v else None) opts

(* ============================================================================
   PID file (--pid=<path>)
   ----------------------------------------------------------------------------
   Mirrors src/init/common.cpp::CreatePidFile + g_pidfile_path:
   - write current PID to <datadir>/<basename>.pid (or override path)
   - if existing file points at a live PID, refuse to start
   - register Stdlib at_exit hook to remove on graceful shutdown
   ============================================================================ *)

let pid_path_ref : string option ref = ref None

(* Returns true if a process with [pid] is alive (kill 0). *)
let pid_alive (pid : int) : bool =
  if pid <= 0 then false
  else
    try Unix.kill pid 0; true
    with
    | Unix.Unix_error (Unix.ESRCH, _, _) -> false
    | Unix.Unix_error (Unix.EPERM, _, _) -> true (* exists, not ours *)
    | _ -> false

let read_pid_file (path : string) : int option =
  try
    let ic = open_in path in
    let line = try input_line ic with End_of_file -> "" in
    close_in ic;
    (try Some (int_of_string (trim line)) with _ -> None)
  with _ -> None

(* Write our PID to [path]. Refuse if [path] already names a live process.
   On success, register an at_exit hook that unlinks the file. *)
let write_pid_file (path : string) : (unit, string) result =
  (match read_pid_file path with
   | Some old_pid when pid_alive old_pid && old_pid <> Unix.getpid () ->
     Error (Printf.sprintf
              "PID file %s already names live PID %d — refusing to start"
              path old_pid)
   | _ ->
     try
       (* Create parent dir if needed *)
       (try Unix.mkdir (Filename.dirname path) 0o755
        with Unix.Unix_error (Unix.EEXIST, _, _) -> ());
       let fd = Unix.openfile path
           [Unix.O_WRONLY; Unix.O_CREAT; Unix.O_TRUNC] 0o644 in
       let s = Printf.sprintf "%d\n" (Unix.getpid ()) in
       let _ = Unix.write_substring fd s 0 (String.length s) in
       Unix.close fd;
       pid_path_ref := Some path;
       at_exit (fun () ->
         match !pid_path_ref with
         | Some p ->
           (try Unix.unlink p with _ -> ());
           pid_path_ref := None
         | None -> ());
       Ok ()
     with exn ->
       Error (Printf.sprintf "failed to write PID file %s: %s"
                path (Printexc.to_string exn)))

(* Explicit removal — used by graceful shutdown so the file is gone before
   the supervisor's restart watchdog observes a stale file. The at_exit hook
   is still in place as a safety net for crashes. *)
let remove_pid_file () : unit =
  match !pid_path_ref with
  | Some p ->
    (try Unix.unlink p with _ -> ());
    pid_path_ref := None
  | None -> ()

(* ============================================================================
   Daemonize (--daemon)
   ----------------------------------------------------------------------------
   Standard double-fork sequence + setsid; redirect stdio to /dev/null (or to
   the configured log file if --printtoconsole=false). Returns only in the
   grandchild — parent and intermediate child exit immediately.

   Must run BEFORE Lwt_main.run and BEFORE write_pid_file (so the PID stored
   is the daemon's, not the parent shell's).
   ============================================================================ *)

let redirect_stdio_to_devnull () =
  try
    let null = Unix.openfile "/dev/null" [Unix.O_RDWR] 0 in
    Unix.dup2 null Unix.stdin;
    Unix.dup2 null Unix.stdout;
    Unix.dup2 null Unix.stderr;
    Unix.close null
  with _ -> ()

let daemonize () : unit =
  (* First fork: detach from controlling terminal. *)
  (match Unix.fork () with
   | 0 -> ()
   | _ -> exit 0);
  (* New session leader. *)
  let _ = (try Unix.setsid () with _ -> 0) in
  (* Second fork: ensure we cannot reacquire a terminal. *)
  (match Unix.fork () with
   | 0 -> ()
   | _ -> exit 0);
  (* chdir / so we don't pin a mountpoint. *)
  (try Unix.chdir "/" with _ -> ());
  (* Tighten umask. *)
  let _ = Unix.umask 0o027 in
  redirect_stdio_to_devnull ()

(* ============================================================================
   Log-file output + SIGHUP rotation
   ----------------------------------------------------------------------------
   When --logfile=<path> is set, install a Logs reporter that writes to the
   file in addition to (or instead of) stderr. SIGHUP closes and reopens the
   file descriptor, mirroring Core's UninterruptibleSleep + log rotate.
   ============================================================================ *)

(* Mutable state so SIGHUP can redirect through the same Buffer. *)
type log_target = {
  mutable path : string;
  mutable oc : out_channel;
  mutable mutex : Mutex.t;
}

let log_target_ref : log_target option ref = ref None

let open_log_channel (path : string) : out_channel =
  (* Append, create-if-missing, mode 0644. *)
  open_out_gen [Open_wronly; Open_append; Open_creat] 0o644 path

let install_log_file_reporter ~(also_console : bool)
    (path : string) : unit =
  let oc = open_log_channel path in
  let lt = { path; oc; mutex = Mutex.create () } in
  log_target_ref := Some lt;
  let pp_header = Logs_fmt.pp_header in
  let report _src level ~over k msgf =
    let k _ = over (); k () in
    msgf @@ fun ?header ?tags:_ fmt ->
    let now =
      let t = Unix.gettimeofday () in
      let tm = Unix.gmtime t in
      Printf.sprintf "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ"
        (tm.tm_year + 1900) (tm.tm_mon + 1) tm.tm_mday
        tm.tm_hour tm.tm_min tm.tm_sec
        (int_of_float (mod_float (t *. 1000.0) 1000.0))
    in
    Mutex.lock lt.mutex;
    let buf = Buffer.create 128 in
    let ppf = Format.formatter_of_buffer buf in
    Format.fprintf ppf "%s " now;
    pp_header ppf (level, header);
    Format.kfprintf
      (fun ppf ->
         Format.fprintf ppf "@.";
         Format.pp_print_flush ppf ();
         let line = Buffer.contents buf in
         (try
            output_string lt.oc line;
            flush lt.oc
          with _ -> ());
         if also_console then begin
           (try
              output_string stderr line;
              flush stderr
            with _ -> ())
         end;
         Mutex.unlock lt.mutex;
         k ())
      ppf fmt
  in
  Logs.set_reporter { Logs.report }

let reopen_log_file () : unit =
  match !log_target_ref with
  | None -> ()
  | Some lt ->
    Mutex.lock lt.mutex;
    (try close_out_noerr lt.oc with _ -> ());
    (try lt.oc <- open_log_channel lt.path with _ -> ());
    Mutex.unlock lt.mutex

(* SIGHUP handler: triggers reopen on the next event-loop tick. We cannot do
   I/O directly inside a Sys.set_signal callback without risking reentrancy
   into the Mutex, so we just flip a flag and let the main loop poll it. *)
let pending_sighup = ref false

let install_sighup_handler () : unit =
  try
    Sys.set_signal Sys.sighup
      (Sys.Signal_handle (fun _ -> pending_sighup := true))
  with _ -> ()

(* Called periodically (e.g. from the status thread) to action a pending
   SIGHUP. Safe to call when there is no log file configured — it is a
   cheap flag check + no-op. *)
let drain_pending_sighup () : unit =
  if !pending_sighup then begin
    pending_sighup := false;
    reopen_log_file ();
    Logs.info (fun m -> m "SIGHUP: log file reopened")
  end

(* ============================================================================
   Debug categories (--debug=<cat>,...)
   ----------------------------------------------------------------------------
   Bitcoin Core's -debug=<cat> grammar accepts a comma-separated list, with
   the special tokens "1" / "all" enabling everything and "0" / "none"
   disabling. We reuse cli.ml::setup_logging but with the parsed list.
   ============================================================================ *)

(* Split on commas, trim each token, drop empty. *)
let split_categories (s : string) : string list =
  if s = "" then []
  else
    String.split_on_char ',' s
    |> List.map trim
    |> List.filter (fun t -> t <> "")

(* Parse a list of CLI --debug=... values into the canonical category list
   passed to cli.ml::setup_logging. Returns [] for "all enabled" semantics
   matching the existing setup_logging contract (categories=[] ⇒ all). *)
let resolve_debug_categories (raw : string list) : string list =
  let toks =
    raw
    |> List.concat_map split_categories
    |> List.map String.lowercase_ascii
  in
  if List.exists (fun t -> t = "0" || t = "none") toks then
    (* Disable verbose: keep default level only. cli.ml clamps non-listed
       sources to Warning when categories <> []; the empty-list semantics is
       "all enabled". To mean "no categories enabled" we return a single
       sentinel that no Logs.Src will match — i.e. all sources clamp to
       Warning. *)
    ["__none__"]
  else if List.exists (fun t -> t = "1" || t = "all") toks then
    [] (* empty ⇒ all enabled per existing setup_logging contract *)
  else
    raw |> List.concat_map split_categories |> List.filter (fun s -> s <> "")

(* ============================================================================
   Ready-fd handshake (--ready-fd=<N>)
   ----------------------------------------------------------------------------
   When the launcher is a supervisor (systemd Type=notify, runit, custom),
   it can pass an open file descriptor to the daemon. The daemon writes a
   single byte to that fd once initialisation has completed (RPC bound, P2P
   listening), then closes it. Equivalent to systemd's sd_notify(READY=1)
   without the dbus dep.
   ============================================================================ *)

let signal_ready ?(fd : int option) () : unit =
  match fd with
  | None -> ()
  | Some n ->
    (try
       let unix_fd : Unix.file_descr = Obj.magic (n : int) in
       let _ = Unix.write_substring unix_fd "1" 0 1 in
       (try Unix.close unix_fd with _ -> ())
     with _ -> ())

(* ============================================================================
   Combined CLI overlay
   ----------------------------------------------------------------------------
   Helpers that merge a --conf file's values into a value already supplied
   on the command line. CLI wins; conf file is fallback. This matches
   Bitcoin Core's ArgsManager precedence (cli > conf > default).
   ============================================================================ *)

let overlay_string ~cli ~conf ~default = match cli with
  | Some v -> v
  | None ->
    (match conf with
     | Some v -> v
     | None -> default)

let overlay_int ~cli ~conf ~default = match cli with
  | Some v -> v
  | None ->
    (match conf with
     | Some v -> v
     | None -> default)

let overlay_bool ~cli_set ~cli_value ~conf ~default =
  if cli_set then cli_value
  else
    (match conf with
     | Some v -> v
     | None -> default)
