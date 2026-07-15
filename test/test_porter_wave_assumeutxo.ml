(* Porter-wave assumeutxo changes — camlcoin.

   Two changes, both attaching at the assume_utxo.ml chokepoint
   ([get_assumeutxo_for_hash] / [available_snapshot_heights]):

   Change 1 — regtest Core-parity assumeutxo entries (unblocks boot-smoke):
     bitcoin-core/src/kernel/chainparams.cpp CRegTestParams::m_assumeutxo_data
     (heights 110/200/299) mirrored verbatim into camlcoin's REGTEST-only
     built-in table ([core_regtest_au_data], seeded into [regtest_au_data]).

   Change 2 — HASHHOG_CAMPAIGN_ASSUMEUTXO campaign flag (unblocks M2):
     read once at startup, appends JSON entries to the running network's
     assumeutxo allowlist. Unset => bit-identical to pre-campaign behavior.

   Spec: receipts/PORTER-WAVE-WORKORDER.md,
   receipts/CAMPAIGN-SNAPSHOT-TABLE-SPEC.md. *)

open Camlcoin

let test_passed name =
  Printf.printf "  [PASS] %s\n" name

let test_failed name msg =
  Printf.printf "  [FAIL] %s: %s\n" name msg;
  exit 1

let check name cond msg =
  if cond then test_passed name else test_failed name msg

(* ============================================================================
   Change 1 — Core-parity regtest entries (110 / 200 / 299)
   ============================================================================ *)

(* Quadruples copied verbatim from
   bitcoin-core/src/kernel/chainparams.cpp:607-628 (CRegTestParams). *)
let core_regtest_quadruples = [
  (110,
   "6affe030b7965ab538f820a56ef56c8149b7dc1d1c144af57113be080db7c397",
   "b952555c8ab81fec46f3d4253b7af256d766ceb39fb7752b9d18cdf4a0141327",
   111L);
  (200,
   "385901ccbd69dff6bbd00065d01fb8a9e464dede7cfe0372443884f9b1dcf6b9",
   "17dcc016d188d16068907cdeb38b75691a118d43053b8cd6a25969419381d13a",
   201L);
  (299,
   "7cc695046fec709f8c9394b6f928f81e81fd3ac20977bb68760fa1faa7916ea2",
   "d2b051ff5e8eef46520350776f4100dd710a63447a8e01d917e92e79751a63e2",
   334L);
]

let test_change1_core_regtest_builtins_present () =
  let name = "Change-1: Core regtest 110/200/299 quadruples present verbatim" in
  let ok =
    List.for_all (fun (height, blockhash_display, hash_serialized_display, chain_tx_count) ->
      let blockhash = Types.hash256_of_hex
          (let buf = Buffer.create 64 in
           for i = 31 downto 0 do
             Buffer.add_string buf (String.sub blockhash_display (i * 2) 2)
           done;
           Buffer.contents buf)
      in
      match Assume_utxo.get_assumeutxo_for_hash ~network:Consensus.regtest blockhash with
      | None -> false
      | Some p ->
        p.height = height
        && Int64.equal p.chain_tx_count chain_tx_count
        && Types.hash256_to_hex_display p.coins_hash = hash_serialized_display
        && Types.hash256_to_hex_display p.blockhash = blockhash_display
    ) core_regtest_quadruples
  in
  check name ok "one or more of the Core regtest 110/200/299 entries is missing or mismatched"

let test_change1_available_heights_include_boot_smoke_299 () =
  let name = "Change-1: available_snapshot_heights(regtest) includes 110/200/299" in
  let heights = Assume_utxo.available_snapshot_heights Consensus.regtest in
  check name
    (List.mem 110 heights && List.mem 200 heights && List.mem 299 heights)
    (Printf.sprintf "heights=[%s]"
       (String.concat "," (List.map string_of_int heights)))

(* NOTE: mainnet_au_data currently carries 5 Core-published heights (840k /
   880k / 910k / 935k / 944183) — the pre-existing
   test_w138_assumeutxo.ml "INV-4: 4 mainnet heights present" pin is stale
   (dates from before the 944183 entry was added) and already fails on an
   unmodified checkout; not something this porter-wave change touches or
   fixes. This test pins the CURRENT (correct) 5-height set instead. *)
let test_change1_mainnet_testnet4_untouched () =
  let name = "Change-1: mainnet/testnet4 tables untouched (regtest-only widening)" in
  let mainnet_heights = Assume_utxo.available_snapshot_heights Consensus.mainnet in
  let testnet4_heights = Assume_utxo.available_snapshot_heights Consensus.testnet4 in
  check name
    (mainnet_heights = [840_000; 880_000; 910_000; 935_000; 944_183]
     && testnet4_heights = [])
    (Printf.sprintf "mainnet=[%s] testnet4=[%s]"
       (String.concat "," (List.map string_of_int mainnet_heights))
       (String.concat "," (List.map string_of_int testnet4_heights)))

(* ============================================================================
   Change 2 — HASHHOG_CAMPAIGN_ASSUMEUTXO
   ============================================================================ *)

(* GATE 3: unset-flag bit-identical proof. Ensures the var is unset (test
   runners can inherit an unrelated environment), then asserts the lookup
   helpers return EXACTLY the pre-campaign values — same 4 mainnet heights,
   same 0 testnet4 heights, same Core regtest 110/200/299 — proving
   [load_campaign_assumeutxo_from_env] with the var unset never mutates any
   table (it is a single Sys.getenv_opt and nothing else). *)
let test_change2_unset_flag_bit_identical () =
  let name = "Change-2: unset HASHHOG_CAMPAIGN_ASSUMEUTXO is bit-identical" in
  (* No Unix.unsetenv in this OCaml/Unix version; putenv "" is treated as
     unset by load_campaign_assumeutxo_from_env itself (the "unset or empty"
     clause) so this is an equivalent, in-contract way to neutralize it. *)
  Unix.putenv "HASHHOG_CAMPAIGN_ASSUMEUTXO" "";
  let before_mainnet = Assume_utxo.available_snapshot_heights Consensus.mainnet in
  let before_testnet4 = Assume_utxo.available_snapshot_heights Consensus.testnet4 in
  let before_regtest = Assume_utxo.available_snapshot_heights Consensus.regtest in
  Assume_utxo.load_campaign_assumeutxo_from_env ~network:Consensus.mainnet ();
  Assume_utxo.load_campaign_assumeutxo_from_env ~network:Consensus.testnet4 ();
  Assume_utxo.load_campaign_assumeutxo_from_env ~network:Consensus.regtest ();
  let after_mainnet = Assume_utxo.available_snapshot_heights Consensus.mainnet in
  let after_testnet4 = Assume_utxo.available_snapshot_heights Consensus.testnet4 in
  let after_regtest = Assume_utxo.available_snapshot_heights Consensus.regtest in
  check name
    (before_mainnet = after_mainnet
     && before_testnet4 = after_testnet4
     && before_regtest = after_regtest
     && after_mainnet = [840_000; 880_000; 910_000; 935_000; 944_183]
     && after_testnet4 = []
     && List.mem 110 after_regtest && List.mem 200 after_regtest
     && List.mem 299 after_regtest)
    "table(s) changed after calling the loader with the env var unset"

let write_file path contents =
  let oc = open_out path in
  output_string oc contents;
  close_out oc

let temp_campaign_fixture ?(entries : string = "") () =
  let path = Printf.sprintf "/tmp/camlcoin_campaign_test_%d_%d.json"
      (Unix.getpid ()) (Random.int 1_000_000) in
  write_file path (Printf.sprintf "[%s]" entries);
  path

(* A well-formed campaign entry at a height that does NOT collide with any
   built-in mainnet/testnet4/regtest entry (Core mainnet heights 840k/880k/
   910k/935k, Core regtest 110/200/299). Mirrors the Track-B 481823 shape
   from CAMPAIGN-SNAPSHOT-TABLE-SPEC.md, using a dummy but well-formed hash. *)
let campaign_entry_json ~height ~blockhash_display ~hash_serialized_display
    ~chain_tx_count =
  Printf.sprintf
    {|{"height": %d, "blockhash": "%s", "hash_serialized": "%s", "m_chain_tx_count": %Ld}|}
    height blockhash_display hash_serialized_display chain_tx_count

let dummy_hash_display (seed : int) : string =
  Printf.sprintf "%02x" seed |> fun byte -> String.concat "" (List.init 32 (fun _ -> byte))

let test_change2_campaign_appends_mainnet () =
  let name = "Change-2: campaign entry appends to mainnet allowlist without disturbing built-ins" in
  Assume_utxo.clear_campaign_assumeutxo ();
  let before = Assume_utxo.available_snapshot_heights Consensus.mainnet in
  let entry_hash = dummy_hash_display 0xab in
  let entry = campaign_entry_json ~height:481_823
      ~blockhash_display:entry_hash ~hash_serialized_display:entry_hash
      ~chain_tx_count:249_036_369L in
  let path = temp_campaign_fixture ~entries:entry () in
  Unix.putenv "HASHHOG_CAMPAIGN_ASSUMEUTXO" path;
  Assume_utxo.load_campaign_assumeutxo_from_env ~network:Consensus.mainnet ();
  (* No Unix.unsetenv in this OCaml/Unix version; putenv "" is treated as
     unset by load_campaign_assumeutxo_from_env itself (the "unset or empty"
     clause) so this is an equivalent, in-contract way to neutralize it. *)
  Unix.putenv "HASHHOG_CAMPAIGN_ASSUMEUTXO" "";
  let after = Assume_utxo.available_snapshot_heights Consensus.mainnet in
  let blockhash = Types.hash256_of_hex
      (let buf = Buffer.create 64 in
       for i = 31 downto 0 do
         Buffer.add_string buf (String.sub entry_hash (i * 2) 2)
       done;
       Buffer.contents buf)
  in
  let resolved =
    Assume_utxo.get_assumeutxo_for_hash ~network:Consensus.mainnet blockhash in
  Assume_utxo.clear_campaign_assumeutxo ();
  (try Sys.remove path with _ -> ());
  check name
    (before = [840_000; 880_000; 910_000; 935_000; 944_183]
     && List.mem 481_823 after
     && List.for_all (fun h -> List.mem h after) before
     && (match resolved with Some p -> p.height = 481_823 | None -> false))
    (Printf.sprintf "before=[%s] after=[%s] resolved=%b"
       (String.concat "," (List.map string_of_int before))
       (String.concat "," (List.map string_of_int after))
       (resolved <> None))

let test_change2_campaign_regtest_routes_via_register_regtest () =
  let name = "Change-2: regtest campaign entries route through register_regtest_assumeutxo" in
  let entry_hash = dummy_hash_display 0xcd in
  let entry = campaign_entry_json ~height:5_000
      ~blockhash_display:entry_hash ~hash_serialized_display:entry_hash
      ~chain_tx_count:5_001L in
  let path = temp_campaign_fixture ~entries:entry () in
  Unix.putenv "HASHHOG_CAMPAIGN_ASSUMEUTXO" path;
  Assume_utxo.load_campaign_assumeutxo_from_env ~network:Consensus.regtest ();
  (* No Unix.unsetenv in this OCaml/Unix version; putenv "" is treated as
     unset by load_campaign_assumeutxo_from_env itself (the "unset or empty"
     clause) so this is an equivalent, in-contract way to neutralize it. *)
  Unix.putenv "HASHHOG_CAMPAIGN_ASSUMEUTXO" "";
  let heights = Assume_utxo.available_snapshot_heights Consensus.regtest in
  (try Sys.remove path with _ -> ());
  check name
    (List.mem 5_000 heights && List.mem 110 heights && List.mem 299 heights)
    (Printf.sprintf "regtest heights=[%s]"
       (String.concat "," (List.map string_of_int heights)))

(* Collision refusal: a campaign entry whose height collides with a
   BUILT-IN entry (Core regtest height 110) must refuse to start (exit 1).
   Runs in a forked child so the refusal's [exit 1] doesn't kill the test
   binary — mirrors the Unix.fork pattern already used in
   test_runtime_config.ml / test_fix64_tls.ml / test_w124_operator.ml. *)
let test_change2_collision_with_builtin_refuses_to_start () =
  let name = "Change-2: campaign entry colliding with a built-in height refuses to start (exit 1)" in
  let colliding_hash = dummy_hash_display 0xef in
  let entry = campaign_entry_json ~height:110 (* collides with Core regtest builtin *)
      ~blockhash_display:colliding_hash ~hash_serialized_display:colliding_hash
      ~chain_tx_count:999L in
  let path = temp_campaign_fixture ~entries:entry () in
  (* Flush before forking so the child doesn't re-emit the parent's
     buffered-but-unflushed stdout on its own exit. *)
  flush stdout;
  (match Unix.fork () with
   | 0 ->
     (* Child: suppress the [fail] banner's stderr noise, then attempt the
        colliding load. Must exit(1); anything else is a test bug. *)
     (try
        let devnull = Unix.openfile "/dev/null" [Unix.O_WRONLY] 0o644 in
        Unix.dup2 devnull Unix.stderr;
        Unix.close devnull
      with _ -> ());
     Unix.putenv "HASHHOG_CAMPAIGN_ASSUMEUTXO" path;
     Assume_utxo.load_campaign_assumeutxo_from_env ~network:Consensus.regtest ();
     (* Should be unreachable — collision must have triggered exit 1 above. *)
     exit 42
   | child_pid ->
     let (_, status) = Unix.waitpid [] child_pid in
     (try Sys.remove path with _ -> ());
     (match status with
      | Unix.WEXITED 1 -> test_passed name
      | Unix.WEXITED n ->
        test_failed name (Printf.sprintf "child exited %d, expected 1" n)
      | Unix.WSIGNALED n ->
        test_failed name (Printf.sprintf "child killed by signal %d" n)
      | Unix.WSTOPPED n ->
        test_failed name (Printf.sprintf "child stopped by signal %d" n)))

(* ============================================================================
   Runner
   ============================================================================ *)

let () =
  Random.self_init ();
  Printf.printf "Porter-wave assumeutxo tests (camlcoin)\n";
  Printf.printf "== Change 1: regtest Core-parity entries ==\n";
  test_change1_core_regtest_builtins_present ();
  test_change1_available_heights_include_boot_smoke_299 ();
  test_change1_mainnet_testnet4_untouched ();
  Printf.printf "== Change 2: HASHHOG_CAMPAIGN_ASSUMEUTXO ==\n";
  test_change2_unset_flag_bit_identical ();
  test_change2_campaign_appends_mainnet ();
  test_change2_campaign_regtest_routes_via_register_regtest ();
  test_change2_collision_with_builtin_refuses_to_start ();
  Printf.printf "All porter-wave assumeutxo tests passed!\n"
