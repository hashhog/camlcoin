(* Control for the /tmp/camlcoin_* test-DB leak.

   1. A body that fails after creating a ChainDB still unlinks the dir
      ([Fun.protect]).
   2. [Test_tmp.chaindb] is one handle per binary.
   3. CAMLCOIN_TEST_TMP_FAIL=1 exits 2 after creating the shared DB so a
      caller can assert the dir is gone after a failing process. *)

let test_fun_protect_cleans_on_failure () =
  let path = Test_tmp.fresh ~label:"failing_case" () in
  let db = Camlcoin.Storage.ChainDB.create path in
  let threw = ref false in
  (try
     Fun.protect
       ~finally:(fun () ->
         (try Camlcoin.Storage.ChainDB.close db with _ -> ());
         Test_tmp.rm_rf path)
       (fun () ->
         threw := true;
         raise (Failure "deliberate"))
   with Failure msg when msg = "deliberate" -> ());
  Alcotest.(check bool) "body raised" true !threw;
  Alcotest.(check bool) "dir unlinked after failure" false
    (Sys.file_exists path)

let test_shared_is_one_chaindb () =
  let db1 = Test_tmp.chaindb () in
  let db2 = Test_tmp.chaindb () in
  Alcotest.(check bool) "same handle" true (db1 == db2)

let () =
  if Sys.getenv_opt "CAMLCOIN_TEST_TMP_FAIL" = Some "1" then begin
    ignore (Test_tmp.chaindb ());
    Printf.eprintf "deliberate fail; db at %s\n%!" (Test_tmp.shared_path ());
    exit 2
  end;
  Alcotest.run "tmp_cleanup"
    [
      ( "teardown",
        [
          Alcotest.test_case "Fun.protect unlinks on failure" `Quick
            test_fun_protect_cleans_on_failure;
          Alcotest.test_case "shared fixture is one ChainDB" `Quick
            test_shared_is_one_chaindb;
        ] );
    ]
