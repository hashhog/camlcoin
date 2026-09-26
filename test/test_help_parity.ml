(* R5 help-parity: every method camlcoin DISPATCHES must be LISTED by `help`,
   and `help <method>` must answer for it (Core rpc/server.cpp help()).

   tools/r5_probe.py grades a method "help-parity: not listed in help" when it
   answers but its name is not the first token of a non-"==" line of `help`.
   On 2026-09-26 camlcoin answered 7 R5 operator-subset methods it did not list
   (gettxoutproof, verifytxoutproof, prioritisetransaction, scantxoutset,
   decodescript, combinerawtransaction, createmultisig) plus 27 more, and
   `help <anything>` returned "Help for specific commands not implemented".

   The dispatched set is read from the SOURCE of lib/rpc.ml (the `| "name" ->`
   arms of dispatch_rpc and dispatch_wait_rpc), not from a hand-kept list, so a
   method added to the dispatcher without a help line fails this test. The
   instrument is checked before it is trusted: it must find >= 100 arms and
   must find arms we know exist.

   CONTROL: `dune exec --no-buffer test/test_help_parity.exe` *)

open Camlcoin

(* ---------- locate + parse lib/rpc.ml ------------------------------------ *)

let read_file path =
  let ic = open_in_bin path in
  let len = in_channel_length ic in
  let s = really_input_string ic len in
  close_in ic;
  s

let rpc_source () =
  let candidates = [ "../lib/rpc.ml"; "lib/rpc.ml"; "../../lib/rpc.ml";
                     "../../../lib/rpc.ml" ] in
  match List.find_opt Sys.file_exists candidates with
  | Some p -> read_file p
  | None ->
    Alcotest.failf "lib/rpc.ml not found from cwd %s" (Sys.getcwd ())

(* Lines of the top-level function [let <name>] up to the next column-0 let. *)
let function_lines (src : string) (name : string) : string list =
  let lines = String.split_on_char '\n' src in
  let header = "let " ^ name ^ " " in
  let rec skip = function
    | [] -> Alcotest.failf "function %s not found in lib/rpc.ml" name
    | l :: rest ->
      if String.length l >= String.length header
         && String.sub l 0 (String.length header) = header
      then take [] rest
      else skip rest
  and take acc = function
    | [] -> List.rev acc
    | l :: rest ->
      if String.length l >= 4 && String.sub l 0 4 = "let " then List.rev acc
      else take (l :: acc) rest
  in
  skip lines

(* Method-name arms: lines of the form `  | "a" ->` or `  | "a" | "b" ->`
   at the dispatcher's own indentation (2 spaces), so string patterns in
   nested matches inside a handler arm are not mistaken for methods. *)
let arm_re = Str.regexp "^  | \"\\([a-z0-9_]+\\)\""
let alt_re = Str.regexp "| \"\\([a-z0-9_]+\\)\""

let arms_of (lines : string list) : string list =
  List.concat_map (fun l ->
      if Str.string_match arm_re l 0 then begin
        let acc = ref [] in
        let pos = ref 0 in
        (try
           while true do
             let _ = Str.search_forward alt_re l !pos in
             acc := Str.matched_group 1 l :: !acc;
             pos := Str.match_end ()
           done
         with Not_found -> ());
        List.rev !acc
      end else [])
    lines

let dispatched_methods () : string list =
  let src = rpc_source () in
  let names =
    arms_of (function_lines src "dispatch_rpc")
    @ arms_of (function_lines src "dispatch_wait_rpc")
  in
  List.sort_uniq compare names

(* ---------- ctx + help helpers ------------------------------------------ *)

let dummy_tip (height : int) : Sync.header_entry =
  { header = { version = 1l; prev_block = Types.zero_hash;
               merkle_root = Types.zero_hash; timestamp = 0l;
               bits = 0l; nonce = 0l };
    hash = Types.zero_hash;
    height;
    total_work = Cstruct.create 32 }

let with_ctx f =
  Test_tmp.with_chaindb (fun db ->
      let utxo = Utxo.UtxoSet.create db in
      let mp = Mempool.create ~network:Consensus.regtest
          ~require_standard:false ~verify_scripts:false ~utxo
          ~current_height:1 () in
      let chain = Sync.create_chain_state db Consensus.regtest in
      chain.tip <- Some (dummy_tip 1);
      let ctx : Rpc.rpc_context = {
        chain; mempool = mp;
        peer_manager = Peer_manager.create Consensus.regtest;
        wallet = None; wallet_manager = None;
        fee_estimator = Fee_estimation.create ();
        network = Consensus.regtest; filter_index = None; utxo = None;
        data_dir = None; snapshot_activation = None;
      } in
      f ctx)

let help_string ctx params =
  match Rpc.dispatch_rpc ctx "help" params with
  | Ok (`String s) -> s
  | Ok j -> Alcotest.failf "help: expected string, got %s"
              (Yojson.Safe.to_string j)
  | Error (c, m) -> Alcotest.failf "help: error (%d) %s" c m

(* The r5_probe.py help_lists() rule, verbatim in OCaml. *)
let first_token line =
  match String.split_on_char ' ' (String.trim line) with
  | t :: _ -> (match String.split_on_char '(' t with h :: _ -> h | [] -> t)
  | [] -> ""

let listed_names (help : string) : string list =
  List.filter_map (fun l ->
      let l = String.trim l in
      if l = "" || l.[0] = '=' then None else Some (first_token l))
    (String.split_on_char '\n' help)

(* ---------- tests -------------------------------------------------------- *)

let test_instrument_sane () =
  let d = dispatched_methods () in
  if List.length d < 100 then
    Alcotest.failf "source scan found only %d dispatch arms -- the parser \
                    is broken, not the help list" (List.length d);
  List.iter (fun m ->
      Alcotest.(check bool) ("scan finds " ^ m) true (List.mem m d))
    [ "getblockchaininfo"; "help"; "waitfornewblock"; "gettxoutproof";
      "createmultisig" ];
  (* Synthetic control: top-level arms (incl. or-patterns) are read; a
     string pattern nested inside a handler arm is not. *)
  Alcotest.(check (list string)) "arm parser control"
    [ "alpha"; "beta"; "gamma" ]
    (arms_of [ "  | \"alpha\" ->"; "  | \"beta\" | \"gamma\" ->";
               "    | \"nested\" -> x"; "  | _ -> ()" ])

let test_every_dispatched_method_listed () =
  with_ctx (fun ctx ->
      let listed = listed_names (help_string ctx []) in
      (* Negative control: the listing parser does not say yes to anything. *)
      Alcotest.(check bool) "control: bogus name not listed" false
        (List.mem "nosuchmethod" listed);
      let missing =
        List.filter (fun m -> not (List.mem m listed)) (dispatched_methods ())
      in
      if missing <> [] then
        Alcotest.failf "%d dispatched method(s) missing from help: %s"
          (List.length missing) (String.concat " " missing))

let test_every_listed_method_dispatched () =
  with_ctx (fun ctx ->
      let d = dispatched_methods () in
      let phantom =
        List.filter (fun m -> not (List.mem m d))
          (listed_names (help_string ctx []))
      in
      if phantom <> [] then
        Alcotest.failf "help lists method(s) that do not dispatch: %s"
          (String.concat " " phantom))

let test_help_command_answers () =
  with_ctx (fun ctx ->
      List.iter (fun m ->
          let s = help_string ctx [ `String m ] in
          let line1 =
            match String.split_on_char '\n' s with l :: _ -> l | [] -> ""
          in
          if first_token line1 <> m then
            Alcotest.failf "help %s: first line is %S, want the %s signature"
              m line1 m)
        (dispatched_methods ());
      Alcotest.(check string) "help <unknown> (Core server.cpp)"
        "help: unknown command: nosuchmethod"
        (help_string ctx [ `String "nosuchmethod" ]))

(* Core's exact one-line signatures (bitcoin-core `help`, v31.99). *)
let core_signatures = [
  "gettxoutproof [\"txid\",...] ( \"blockhash\" )";
  "verifytxoutproof \"proof\"";
  "prioritisetransaction \"txid\" ( dummy ) fee_delta";
  "scantxoutset \"action\" ( [scanobjects,...] )";
  "decodescript \"hexstring\"";
  "combinerawtransaction [\"hexstring\",...]";
  "createmultisig nrequired [\"key\",...] ( \"address_type\" )";
]

let test_core_signatures () =
  with_ctx (fun ctx ->
      let lines =
        List.map String.trim
          (String.split_on_char '\n' (help_string ctx []))
      in
      List.iter (fun sig_ ->
          Alcotest.(check bool) ("listing has: " ^ sig_) true
            (List.mem sig_ lines))
        core_signatures;
      (* help <m> leads with the same signature, then Core's description. *)
      let s = help_string ctx [ `String "gettxoutproof" ] in
      Alcotest.(check bool) "help gettxoutproof has Core description" true
        (try
           ignore (Str.search_forward
                     (Str.regexp_string
                        "Returns a hex-encoded proof that \"txid\" was \
                         included in a block.") s 0);
           true
         with Not_found -> false))

let () =
  Alcotest.run "help_parity" [
    "help", [
      Alcotest.test_case "source-scan instrument is sane" `Quick
        test_instrument_sane;
      Alcotest.test_case "every dispatched method is listed" `Quick
        test_every_dispatched_method_listed;
      Alcotest.test_case "every listed method dispatches" `Quick
        test_every_listed_method_dispatched;
      Alcotest.test_case "help <method> answers for every method" `Quick
        test_help_command_answers;
      Alcotest.test_case "Core signatures for the 7 R5 methods" `Quick
        test_core_signatures;
    ];
  ]
