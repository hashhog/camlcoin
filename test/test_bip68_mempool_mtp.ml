(* BIP68 / BIP113 time locks in the mempool use the ACTIVE CHAIN's MTPs.

   Core: CheckFinalTxAtTip uses nBlockTime = tip->GetMedianTimePast();
   CalculateLockPointsAtTip / CheckSequenceLocksAtTip evaluate a relative
   time lock with nCoinTime = GetAncestor(max(coin_height-1,0))->MTP (a
   mempool coin counts at tip+1, so its nCoinTime is the tip's MTP) against
   the tip's MTP.  A lock of n units passes iff tip_mtp >= coin_time + 512n.

   b08ea33's mempool read [current_median_time], which nothing ever set (0):
   every time-based nLockTime was non-final and every time-based relative
   lock (n >= 1) unsatisfiable, whatever the chain said.  The fix wires a
   provider (cli.ml -> Sync.get_mtp_for_height_strict); this test injects a
   synthetic chain: header h has timestamp T0 + 512h, so the MTP of the
   window ending at h-1 is the timestamp of h-6. *)

open Camlcoin

let test_db_path = Test_tmp.register "/tmp/camlcoin_test_bip68_mempool_mtp_db"

let rec rm_rf path =
  if Sys.file_exists path then begin
    if Sys.is_directory path then begin
      Array.iter (fun f -> rm_rf (Filename.concat path f)) (Sys.readdir path);
      Unix.rmdir path
    end else Unix.unlink path
  end

let tip = 100
let t0 = 1_600_000_000
let ts h = Int32.of_int (t0 + 512 * h)
(* f h = MTP of the block at h-1 = timestamp of h-6 (monotone chain). *)
let provider ?(floor = 11) h = if h >= floor then Some (ts (h - 6)) else None
let tip_mtp = ts (tip + 1 - 6)

let spk = Cstruct.of_string "\x76\xa9\x14test_script_pubkey\x88\xac"
let out v = Types.{ value = v; script_pubkey = spk }
let input ?(sequence = 0xFFFFFFFFl) txid vout =
  Types.{ previous_output = { txid; vout }; script_sig = Cstruct.of_string "\x00";
          sequence }
let tx2 ?(locktime = 0l) inputs outputs =
  Types.{ version = 2l; inputs; outputs; witnesses = []; locktime }
let time_lock n = Int32.logor 0x00400000l (Int32.of_int n)

let c50 = Types.hash256_of_hex
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
let c90 = Types.hash256_of_hex
    "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098"

let with_mempool ?(prov = Some (fun h -> provider h)) f =
  rm_rf test_db_path;
  let db = Storage.ChainDB.create test_db_path in
  let utxo = Utxo.UtxoSet.create db in
  List.iter (fun (txid, h) ->
    Utxo.UtxoSet.add utxo txid 0
      Utxo.{ value = 1_000_000L; script_pubkey = spk; height = h; is_coinbase = false })
    [ (c50, 50); (c90, 90) ];
  let mp = Mempool.create ~network:Consensus.regtest ~require_standard:false
      ~verify_scripts:false ~utxo ~current_height:tip () in
  Mempool.set_mtp_provider mp prov;
  Fun.protect ~finally:(fun () -> Storage.ChainDB.close db; rm_rf test_db_path)
    (fun () -> f mp)

let show = function Ok _ -> "accepted" | Error e -> "rejected: " ^ e
let accepted name r = Alcotest.(check bool) (name ^ " (" ^ show r ^ ")") true (Result.is_ok r)
let rejected name r = Alcotest.(check bool) (name ^ " (" ^ show r ^ ")") false (Result.is_ok r)
let add mp tx = Mempool.add_transaction mp tx

(* coin@90: coin_time = ts 84, tip_mtp = ts 95 -> exactly 11 units of slack. *)
let test_relative_time_boundary () =
  with_mempool (fun mp ->
    accepted "coin@90 time lock 11 (tip_mtp == coin_time + 11*512)"
      (add mp (tx2 [input ~sequence:(time_lock 11) c90 0l] [out 990_000L])));
  with_mempool (fun mp ->
    rejected "coin@90 time lock 12"
      (add mp (tx2 [input ~sequence:(time_lock 12) c90 0l] [out 990_000L])))

(* A mempool parent's coin time is the tip MTP: lock 1 unsatisfied, 0 ok. *)
let test_mempool_parent_time_lock () =
  let with_parent f = with_mempool (fun mp ->
    let p = tx2 [input c50 0l] [out 990_000L] in
    (match add mp p with Ok _ -> () | Error e -> Alcotest.failf "parent: %s" e);
    f mp (Crypto.compute_txid p)) in
  with_parent (fun mp ptxid ->
    rejected "mempool parent, time lock 1"
      (add mp (tx2 [input ~sequence:(time_lock 1) ptxid 0l] [out 980_000L])));
  with_parent (fun mp ptxid ->
    accepted "CONTROL mempool parent, time lock 0"
      (add mp (tx2 [input ~sequence:(time_lock 0) ptxid 0l] [out 980_000L])))

(* BIP113: time-based nLockTime is final iff nLockTime < tip MTP. *)
let test_time_nlocktime () =
  let seq = 0xFFFFFFFEl in
  with_mempool (fun mp ->
    accepted "nLockTime = tip_mtp - 1"
      (add mp (tx2 ~locktime:(Int32.sub tip_mtp 1l)
                 [input ~sequence:seq c50 0l] [out 990_000L])));
  with_mempool (fun mp ->
    rejected "nLockTime = tip_mtp"
      (add mp (tx2 ~locktime:tip_mtp [input ~sequence:seq c50 0l] [out 990_000L])))

(* Fail closed: an unresolvable coin window rejects a time lock but never
   touches a height lock. *)
let test_fail_closed () =
  let prov = Some (fun h -> provider ~floor:60 h) in
  with_mempool ~prov (fun mp ->
    rejected "coin@50 time lock 1, window unresolvable"
      (add mp (tx2 [input ~sequence:(time_lock 1) c50 0l] [out 990_000L])));
  with_mempool ~prov (fun mp ->
    accepted "CONTROL coin@50 height lock 1, window unresolvable"
      (add mp (tx2 [input ~sequence:1l c50 0l] [out 990_000L])))

(* NEGATIVE CONTROL: no provider = b08ea33 semantics (MTP 0): a lock the
   chain satisfies by ~50 units is still refused, and so is a past nLockTime. *)
let test_no_provider_is_old_behaviour () =
  with_mempool ~prov:None (fun mp ->
    rejected "no provider: coin@50 time lock 1"
      (add mp (tx2 [input ~sequence:(time_lock 1) c50 0l] [out 990_000L])));
  with_mempool ~prov:None (fun mp ->
    rejected "no provider: nLockTime = tip_mtp - 1"
      (add mp (tx2 ~locktime:(Int32.sub tip_mtp 1l)
                 [input ~sequence:0xFFFFFFFEl c50 0l] [out 990_000L])))

let () =
  Alcotest.run "bip68_mempool_mtp" [
    "mtp", [
      Alcotest.test_case "relative time lock boundary (11 ok / 12 refused)" `Quick
        test_relative_time_boundary;
      Alcotest.test_case "mempool parent: time lock 1 refused, 0 ok" `Quick
        test_mempool_parent_time_lock;
      Alcotest.test_case "BIP113 nLockTime vs tip MTP" `Quick test_time_nlocktime;
      Alcotest.test_case "fail closed on unresolvable window" `Quick test_fail_closed;
      Alcotest.test_case "NEG CONTROL no provider = old behaviour" `Quick
        test_no_provider_is_old_behaviour;
    ];
  ]
