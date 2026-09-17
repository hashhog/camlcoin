(* Control: README must not claim Core dual-chainstate uncaveated
   while getchainstates is single-chainstate.

   QUEUES.md item 4. The 2026-09-07 review found the Features bullet
     "AssumeUTXO (BIP-199, snapshot loading, dual chainstate, background validation)"
   with no caveat, while boot-smoke probe_bgval reports
   SKIP:single-chainstate (handle_getchainstates always emits a 1-element
   chainstates array).

   Command:
     dune exec --no-buffer test/test_readme_assumeutxo_caveat.exe

   Red: the uncaveated Features bullet is present and "single-chainstate"
   is unnamed. Green: that bullet is gone and the README names the
   single-chainstate fact next to AssumeUTXO.
*)

let pass_count = ref 0
let fail_count = ref 0

let check name cond msg =
  if cond then begin
    incr pass_count;
    Printf.printf "  PASS  %s\n%!" name
  end else begin
    incr fail_count;
    Printf.printf "  FAIL  %s: %s\n%!" name msg
  end

let read_file path =
  let ic = open_in_bin path in
  let n = in_channel_length ic in
  let s = really_input_string ic n in
  close_in ic;
  s

let contains hay needle =
  let n = String.length needle in
  let h = String.length hay in
  let rec go i =
    if i + n > h then false
    else if String.sub hay i n = needle then true
    else go (i + 1)
  in
  n = 0 || go 0

let find_named name =
  let rooted =
    [
      name;
      Filename.concat ".." name;
      Filename.concat "../.." name;
      Filename.concat "../../camlcoin" name;
      Filename.concat "/home/work/hashhog/camlcoin" name;
    ]
  in
  let from_exe =
    try
      let dir = Filename.dirname Sys.executable_name in
      [
        Filename.concat dir name;
        Filename.concat (Filename.concat dir "..") name;
        Filename.concat
          (Filename.concat (Filename.concat dir "..") "..")
          name;
      ]
    with _ -> []
  in
  try List.find Sys.file_exists (rooted @ from_exe)
  with Not_found -> failwith ("missing " ^ name)

let uncaveated_bullet =
  "AssumeUTXO (BIP-199, snapshot loading, dual chainstate, background \
   validation)"

(* A Features bullet that lists dual chainstate as a delivered capability,
   with no "not"/single-chainstate caveat on the same line. *)
let features_advertises_dual text =
  let lines = String.split_on_char '\n' text in
  List.exists
    (fun line ->
      let n = String.length line in
      let is_bullet =
        n >= 2
        && ((line.[0] = '-' && line.[1] = ' ')
           || (line.[0] = '*' && line.[1] = ' '))
      in
      is_bullet
      && contains line "AssumeUTXO"
      && contains line "dual chainstate"
      && not (contains line "single-chainstate")
      && not (contains line "single chainstate")
      && not (contains line "not Core")
      && not (contains line "not dual"))
    lines

let () =
  Printf.printf
    "Running README AssumeUTXO single-chainstate caveat control...\n%!";
  let readme_path = find_named "README.md" in
  let readme = read_file readme_path in
  let rpc_path = find_named "lib/rpc.ml" in
  let rpc = read_file rpc_path in
  check "README.md found" true readme_path;
  check "AssumeUTXO still documented"
    (contains readme "AssumeUTXO")
    "do not delete the feature; caveat it";
  check "snapshot loading still documented"
    (contains readme "loadtxoutset" || contains readme "--import-utxo")
    "snapshot loading should remain in the README";
  check "uncaveated Features bullet is gone"
    (not (contains readme uncaveated_bullet))
    "README still lists dual chainstate, background validation with no caveat";
  check "single-chainstate caveat present"
    (contains readme "single-chainstate"
    || contains readme "single chainstate")
    "README must name the boot-smoke SKIP:single-chainstate fact";
  check "Features bullet does not advertise dual chainstate as delivered"
    (not (features_advertises_dual readme))
    "a Features bullet still lists dual chainstate without a not/single caveat";
  check "handle_getchainstates still emits one chainstate"
    (contains rpc "(\"chainstates\",  `List [chainstate])")
    "rpc.ml no longer constructs a 1-element chainstates array — update \
     README if dual chainstate landed";
  Printf.printf "\nREADME AssumeUTXO caveat: %d passed, %d failed\n%!"
    !pass_count !fail_count;
  if !fail_count > 0 then exit 1
  else Printf.printf "All README AssumeUTXO caveat tests passed!\n%!"
