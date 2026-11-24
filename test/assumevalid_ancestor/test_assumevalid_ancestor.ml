(* is_assume_valid: O(1) per block, same answers as the prev_block walk.

   [Sync.is_assume_valid] runs for every block that IBD connects.  It used
   to call [Sync.get_ancestor] twice, once from the assumevalid block and
   once from the best header, and each call followed [prev_block] one
   Hashtbl hop at a time: about (938k - h) + (tip - h) hops per block on
   mainnet, ~1.9M at genesis.

   [ref_is_assume_valid] below is the pre-fix body verbatim, built on
   [Sync.get_ancestor] (unchanged by the fix).  Every test compares the
   production gate against it, on header trees with forks above and below
   the assumevalid block, best-header reorgs both ways, tips whose ancestry
   has a hole, and assumevalid blocks off the best chain.  The work-bound
   test is the one that fails on the pre-fix tree: it counts minor-heap
   words per call, which the walk inflates by ~8 words per hop.

   Uses only APIs that exist before the fix, so it builds on master too. *)

open Camlcoin

(* -- reference: the pre-fix is_assume_valid, verbatim ------------------- *)

let ref_is_assume_valid (state : Sync.chain_state) (block_hash : Types.hash256)
    (height : int) : bool =
  let two_weeks_secs = 60 * 60 * 24 * 7 * 2 in
  match state.Sync.network.Consensus.assume_valid_hash with
  | None -> false
  | Some av_hash ->
    (match Hashtbl.find_opt state.Sync.headers (Cstruct.to_string av_hash) with
     | None -> false
     | Some av_entry ->
       (match Hashtbl.find_opt state.Sync.headers (Cstruct.to_string block_hash) with
        | None -> false
        | Some this_entry ->
          (match Sync.get_ancestor state av_entry height with
           | None -> false
           | Some anc when not (Cstruct.equal anc.Sync.hash block_hash) -> false
           | _ ->
             (match state.Sync.tip with
              | None -> false
              | Some best ->
                (match Sync.get_ancestor state best height with
                 | None -> false
                 | Some b when not (Cstruct.equal b.Sync.hash block_hash) -> false
                 | _ ->
                   Consensus.work_compare best.Sync.total_work
                     state.Sync.network.Consensus.minimum_chain_work >= 0
                   && Sync.get_block_proof_equivalent_time best this_entry
                      > two_weeks_secs)))))

(* -- synthetic header trees -------------------------------------------- *)

let le_of_int n =
  let c = Cstruct.create 32 in
  let v = ref n and i = ref 0 in
  while !v > 0 && !i < 32 do
    Cstruct.set_uint8 c !i (!v land 0xff);
    v := !v lsr 8;
    incr i
  done;
  c

let fresh_hash rng =
  let c = Cstruct.create 32 in
  for i = 0 to 31 do Cstruct.set_uint8 c i (Random.State.int rng 256) done;
  c

(* Regtest bits: GetBlockProof = 2, so a block is "two weeks buried" once
   the best header has > 4032 more work units (> 2016 blocks at inc 2). *)
let child rng (parent : Sync.header_entry) inc : Sync.header_entry =
  { Sync.header = { parent.Sync.header with Types.prev_block = parent.Sync.hash };
    hash = fresh_hash rng;
    height = parent.Sync.height + 1;
    total_work = Consensus.work_add parent.Sync.total_work (le_of_int inc) }

let insert (state : Sync.chain_state) (e : Sync.header_entry) =
  Hashtbl.replace state.Sync.headers (Cstruct.to_string e.Sync.hash) e

(* [n] blocks on top of [from], each adding [inc] work.  [via_accept] goes
   through [Sync.accept_header], which moves the best header on more work. *)
let extend ?(via_accept = false) rng state from n inc =
  let out = Array.make n from in
  let cur = ref from in
  for i = 0 to n - 1 do
    let e = child rng !cur inc in
    if via_accept then Sync.accept_header state e else insert state e;
    out.(i) <- e;
    cur := e
  done;
  out

let with_av (base : Sync.chain_state) ?min_work av =
  let min_work =
    match min_work with
    | Some w -> w
    | None -> base.Sync.network.Consensus.minimum_chain_work
  in
  { base with
    Sync.network = { base.Sync.network with
                     Consensus.assume_valid_hash = av;
                     minimum_chain_work = min_work } }

let hex h = Types.hash256_to_hex_display h

(* Production answer, checked against the reference, then returned. *)
let gate ?(what = "") s (e : Sync.header_entry) h =
  let want = ref_is_assume_valid s e.Sync.hash h in
  let got = Sync.is_assume_valid s e.Sync.hash h in
  if want <> got then
    Alcotest.failf "%s is_assume_valid %s @%d (entry height %d, tip %s): \
                    reference %b, production %b"
      what (hex e.Sync.hash) h e.Sync.height
      (match s.Sync.tip with
       | Some t -> Printf.sprintf "%d %s" t.Sync.height (hex t.Sync.hash)
       | None -> "none")
      want got;
  got

let genesis_of st = Option.get st.Sync.tip

(* -- 1. property: random forked trees, random tips, random av ---------- *)

let test_property_matches_walk () =
  let total = ref 0 and trues = ref 0 in
  for seed = 1 to 8 do
    Test_tmp.with_chaindb (fun db ->
        let base = Sync.create_chain_state db Consensus.regtest in
        let rng = Random.State.make [| seed; 0xa55e |] in
        let genesis = genesis_of base in
        let all = ref [ genesis ] in
        let tips = ref [] in
        let add arr =
          Array.iter (fun e -> all := e :: !all) arr;
          if Array.length arr > 0 then tips := arr.(Array.length arr - 1) :: !tips
        in
        let main = extend rng base genesis (2600 + Random.State.int rng 800) 2 in
        add main;
        (* forks off random existing entries; long and heavy enough that
           blocks on them get two weeks of burial, so a stale index would
           change answers rather than hide behind condition 5 *)
        for _ = 1 to 8 do
          let pool = Array.of_list !all in
          let fp = pool.(Random.State.int rng (Array.length pool)) in
          add (extend rng base fp
                 (1 + Random.State.int rng 2500) (1 + Random.State.int rng 6))
        done;
        (* a branch whose parent is NOT in the table: a hole in the ancestry *)
        let ghost = child rng main.(999) 2 in
        let orphan = extend rng base ghost 300 3 in
        add orphan;
        let pool = Array.of_list !all in
        let pick () = pool.(Random.State.int rng (Array.length pool)) in
        let pick_main () = main.(Random.State.int rng (Array.length main)) in
        let branch_tips = Array.of_list !tips in
        (* an ancestor of [e] (or [e]), via the unchanged walk; None in a hole *)
        let ancestor_of (s : Sync.chain_state) (e : Sync.header_entry) =
          Sync.get_ancestor s e (Random.State.int rng (e.Sync.height + 1))
        in
        for round = 1 to 12 do
          (* half way, the missing parent arrives: the hole is filled *)
          if round = 7 then insert base ghost;
          (* every few rounds a full sweep from the main tip *)
          (* best headers are mostly branch ends, as in a real header tree *)
          let tip =
            if round mod 4 = 1 then main.(Array.length main - 1)
            else if Random.State.bool rng then
              branch_tips.(Random.State.int rng (Array.length branch_tips))
            else pick ()
          in
          let avs =
            [ Some (pick ()).Sync.hash;
              Some (pick_main ()).Sync.hash;
              (match Random.State.int rng 3 with
               | 0 -> Some orphan.(Random.State.int rng 300).Sync.hash
               | 1 -> Some (fresh_hash rng)
               | _ -> None) ]
          in
          List.iter (fun av ->
              let min_work =
                if Random.State.int rng 6 = 0 then
                  Consensus.work_add tip.Sync.total_work (le_of_int 1)
                else Consensus.regtest.Consensus.minimum_chain_work
              in
              let s = with_av base ~min_work av in
              s.Sync.tip <- Some tip;
              let query e h =
                incr total;
                if gate ~what:(Printf.sprintf "seed %d round %d" seed round) s e h
                then incr trues
              in
              if round mod 4 = 1 then
                for _ = 1 to 1500 do let e = pick () in query e e.Sync.height done
              else
                for _ = 1 to 90 do
                  (* where the answers differ: the tip's and av's ancestry *)
                  let e =
                    let anc_or_pick from =
                      match from with
                      | Some f -> (match ancestor_of s f with Some a -> a | None -> pick ())
                      | None -> pick ()
                    in
                    match Random.State.int rng 3 with
                    | 0 -> anc_or_pick (Some tip)
                    | 1 ->
                      anc_or_pick
                        (match av with
                         | Some h -> Hashtbl.find_opt s.Sync.headers (Cstruct.to_string h)
                         | None -> None)
                    | _ -> pick ()
                  in
                  let h =
                    match Random.State.int rng 6 with
                    | 0 -> e.Sync.height + Random.State.int rng 5 - 2
                    | 1 -> Random.State.int rng (tip.Sync.height + 3) - 1
                    | _ -> e.Sync.height
                  in
                  query e h
                done)
            avs
        done)
  done;
  (* negative control on the instrument: a property that only ever saw
     [false] would pass with the gate hard-wired off *)
  Alcotest.(check bool)
    (Printf.sprintf "sampled both answers (%d true of %d)" !trues !total)
    true (!trues > 1000 && !trues < !total)

(* -- 2. fork of the assumevalid block still checks scripts -------------- *)

let test_fork_of_av_checks_scripts () =
  Test_tmp.with_chaindb (fun db ->
      let base = Sync.create_chain_state db Consensus.regtest in
      let rng = Random.State.make [| 42 |] in
      let genesis = genesis_of base in
      let main = extend rng base genesis 3100 2 in   (* main.(i) at height i+1 *)
      let av = main.(999) in                          (* height 1000 *)
      (* lower-work sibling branch from 500 up past the av height *)
      let side = extend rng base main.(499) 600 2 in  (* heights 501..1100 *)
      let s = with_av base (Some av.Sync.hash) in
      s.Sync.tip <- Some main.(3099);
      let chk name expect e =
        Alcotest.(check bool) name expect (gate ~what:name s e e.Sync.height)
      in
      chk "main 700: ancestor of av, on best chain, buried -> skip" true main.(699);
      chk "av itself -> skip" true av;
      chk "side 700: fork below av -> scripts checked" false side.(199);
      chk "side 1000: fork at av height -> scripts checked" false side.(499);
      chk "side 1100: fork above av -> scripts checked" false side.(599);
      chk "main 1500: above av -> scripts checked" false main.(1499);
      chk "main tip: not buried -> scripts checked" false main.(3099);
      Alcotest.(check bool) "side 700 asked at the av-ancestor's height of 700"
        false (gate s side.(199) 700);
      (* best header moves to a heavier fork from 800 that leaves av behind *)
      let heavy = extend rng base main.(799) 2500 3 in  (* heights 801..3300 *)
      s.Sync.tip <- Some heavy.(2499);
      chk "main 700: common to av and best -> skip" true main.(699);
      chk "main 800: fork point -> skip" true main.(799);
      chk "main 900: ancestor of av, NOT on best chain -> checked" false main.(899);
      chk "heavy 900: on best chain, NOT ancestor of av -> checked" false heavy.(99);
      chk "av, off the best chain -> checked" false av;
      (* and back *)
      s.Sync.tip <- Some main.(3099);
      chk "back on main: main 900 -> skip" true main.(899);
      chk "back on main: heavy 900 -> checked" false heavy.(99))

(* -- 3. index correct after header reorgs through accept_header -------- *)

let test_reorg_via_accept_header () =
  Test_tmp.with_chaindb (fun db ->
      let base = Sync.create_chain_state db Consensus.regtest in
      let rng = Random.State.make [| 7 |] in
      let genesis = genesis_of base in
      let main = extend ~via_accept:true rng base genesis 3500 2 in
      let s = with_av base (Some main.(1999).Sync.hash) in   (* av @2000 *)
      let chk name expect e =
        Alcotest.(check bool) name expect (gate ~what:name s e e.Sync.height)
      in
      Alcotest.(check int) "tip on main" 3500 (Option.get s.Sync.tip).Sync.height;
      chk "main 1000 skip" true main.(999);
      chk "main 1600 only 1900 behind tip (< 2 weeks) -> checked" false main.(1599);
      (* heavier fork from 1500 accepted through accept_header *)
      let fork = extend ~via_accept:true rng s main.(1499) 1500 3 in
      Alcotest.(check bool) "accept_header moved tip to the fork" true
        (Cstruct.equal (Option.get s.Sync.tip).Sync.hash fork.(1499).Sync.hash);
      chk "after reorg: main 1000 skip" true main.(999);
      chk "after reorg: main 1600 off best chain -> checked" false main.(1599);
      chk "after reorg: fork 1600 not av ancestor -> checked" false fork.(99);
      chk "after reorg: main 1500 fork point, buried -> skip" true main.(1499);
      (* main overtakes again *)
      let main2 = extend ~via_accept:true rng s main.(3499) 2000 2 in
      Alcotest.(check bool) "tip back on main" true
        (Cstruct.equal (Option.get s.Sync.tip).Sync.hash main2.(1999).Sync.hash);
      chk "main back: main 1600 skip" true main.(1599);
      chk "main back: av 2000 skip" true main.(1999);
      chk "main back: fork 1600 checked" false fork.(99);
      chk "main back: main 2100 above av -> checked" false main.(2099);
      (* a lower-height but heavier best header (tip height goes DOWN) *)
      let short = extend rng s main.(1799) 1000 20 in    (* heights 1801..2800 *)
      s.Sync.tip <- Some short.(999);
      chk "short heavy tip: main 1000 skip" true main.(999);
      chk "short heavy tip: main 1900 checked" false main.(1899);
      chk "short heavy tip: av checked" false main.(1999);
      Alcotest.(check bool) "height above the new tip -> checked" false
        (gate s main2.(500) main2.(500).Sync.height))

(* -- 4. work per call does not grow with chain height ----------------- *)

let test_constant_work_per_call () =
  Test_tmp.with_chaindb (fun db ->
      let base = Sync.create_chain_state db Consensus.regtest in
      let rng = Random.State.make [| 99 |] in
      let genesis = genesis_of base in
      let main = extend rng base genesis 20_000 2 in
      let s = with_av base (Some main.(14_999).Sync.hash) in
      s.Sync.tip <- Some main.(19_999);
      (* first call may build whatever index the gate keeps *)
      ignore (Sync.is_assume_valid s main.(0).Sync.hash 1);
      let n = 500 in
      let ok = ref 0 in
      let before = Gc.minor_words () in
      for i = 0 to n - 1 do
        if Sync.is_assume_valid s main.(i).Sync.hash (i + 1) then incr ok
      done;
      let per_call = (Gc.minor_words () -. before) /. float_of_int n in
      Alcotest.(check int) "all 500 early blocks skip scripts" n !ok;
      (* the walk allocates a 32-byte key string + an option per hop:
         ~35k hops here, ~280k words per call.  O(1) is a few hundred. *)
      Alcotest.(check bool)
        (Printf.sprintf "minor-heap words per call %.0f < 5000 \
                         (chain 20000, av 15000)" per_call)
        true (per_call < 5000.))

let () =
  Alcotest.run "assumevalid_ancestor"
    [ ( "is_assume_valid",
        [ Alcotest.test_case "property: same answers as the prev_block walk"
            `Slow test_property_matches_walk;
          Alcotest.test_case "fork of assumevalid block still checks scripts"
            `Quick test_fork_of_av_checks_scripts;
          Alcotest.test_case "best-chain index correct after header reorgs"
            `Quick test_reorg_via_accept_header;
          Alcotest.test_case "work per call is O(1), not O(height)"
            `Quick test_constant_work_per_call ] ) ]
