(* Test-only temp-dir lifecycle.

   /tmp on maxbox is a tmpfs. A ChainDB opened under /tmp/camlcoin_* used
   to fallocate a 256 MiB WAL (see Cf_chainstate.open_db) and never unlink
   it, so one evening of the suite leaked 23 GiB of RAM. Every path created
   through this module is unlinked in [Fun.protect] and again at_exit.
   Dummy RPC contexts should use [chaindb], which is ONE store per test
   binary rather than one per case. *)

open Camlcoin

let rec rm_rf path =
  if Sys.file_exists path then begin
    if Sys.is_directory path then begin
      Array.iter
        (fun n ->
          if n <> "." && n <> ".." then rm_rf (Filename.concat path n))
        (Sys.readdir path);
      try Unix.rmdir path with _ -> ()
    end else
      try Unix.unlink path with _ -> ()
  end

let paths : string list ref = ref []
let seq = ref 0

let register path =
  paths := path :: !paths;
  path

let fresh ?(label = "db") ?(mkdir = false) () =
  incr seq;
  let path =
    Printf.sprintf "/tmp/camlcoin_%s_%d_%d" label (Unix.getpid ()) !seq
  in
  if mkdir then
    (try Unix.mkdir path 0o755
     with Unix.Unix_error (Unix.EEXIST, _, _) -> ());
  register path

let with_dir ?(label = "db") ?(mkdir = false) f =
  let path = fresh ~label ~mkdir () in
  Fun.protect ~finally:(fun () -> rm_rf path) (fun () -> f path)

let shared_dir =
  lazy
    (let path = Printf.sprintf "/tmp/camlcoin_shared_%d" (Unix.getpid ()) in
     (try Unix.mkdir path 0o755
      with Unix.Unix_error (Unix.EEXIST, _, _) -> ());
     register path)

let shared_path () = Lazy.force shared_dir

let shared_chaindb =
  lazy (Storage.ChainDB.create (shared_path ()))

let chaindb () = Lazy.force shared_chaindb

let with_chaindb f =
  with_dir ~label:"chaindb" (fun path ->
      let db = Storage.ChainDB.create path in
      Fun.protect
        ~finally:(fun () -> try Storage.ChainDB.close db with _ -> ())
        (fun () -> f db))

let in_reexec_child () =
  (* These tests re-invoke the same executable as a helper process.
     Module-load [register] of a shared /tmp path would otherwise make
     the child's at_exit unlink the parent's fixture. *)
  Sys.getenv_opt "CAMLCOIN_TEST_BOOT_GUARD_TARGET" <> None
  || Sys.getenv_opt "CAMLCOIN_FIX64_SERVER" <> None

let () =
  at_exit (fun () ->
      if not (in_reexec_child ()) then begin
        (try
           if Lazy.is_val shared_chaindb then
             Storage.ChainDB.close (Lazy.force shared_chaindb)
         with _ -> ());
        List.iter (fun p -> try rm_rf p with _ -> ()) !paths
      end)
