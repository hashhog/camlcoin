(* BIP-331: Package Relay handlers.

   The wire-level encode/decode of [sendpackages], [getpkgtxns], and [pkgtxns]
   lives in [P2p].  Pre-VERACK [sendpackages] capture lives in [Peer].  This
   module wires the post-handshake message exchange into the mempool:
     - getpkgtxns: peer asks for full transactions by wtxid; reply with the
       subset we have (via [pkgtxns]).
     - pkgtxns: peer delivers a topologically-sorted package; validate it via
       [Mempool.accept_package].

   Reference: bitcoin-core has not yet shipped BIP-331 in [src/]; we follow the
   BIP text and the existing camlcoin serialization in [P2p]. *)

let log_src = Logs.Src.create "PKG-RELAY" ~doc:"BIP-331 package relay"
module Log = (val Logs.src_log log_src : Logs.LOG)

(* Look up a transaction by its wtxid in our mempool.  The mempool is keyed by
   txid (legacy hash), so we scan entries to find a wtxid match.  This is O(N)
   per request; acceptable since [getpkgtxns] is rare and bounded by
   [P2p.max_package_txs] = 25 wtxids per request. *)
let lookup_tx_by_wtxid (mp : Mempool.mempool) (wtxid : Types.hash256)
    : Types.transaction option =
  let result = ref None in
  Hashtbl.iter (fun _k (entry : Mempool.mempool_entry) ->
    if !result = None && Cstruct.equal entry.wtxid wtxid then
      result := Some entry.tx
  ) mp.entries;
  !result

(* Handle an incoming [getpkgtxns]: respond with a [pkgtxns] containing the
   transactions we have (silently dropping unknown wtxids — peer can retry).
   The reply is in the same order as the request to make matching easy.
   Per BIP-331 we send back even partial sets; an empty reply is allowed. *)
let handle_getpkgtxns (mp : Mempool.mempool) (peer : Peer.peer)
    (msg : P2p.getpkgtxns_msg) : unit Lwt.t =
  let n_req = List.length msg.pkg_wtxids in
  if n_req = 0 then Lwt.return_unit
  else begin
    let txs = List.filter_map (lookup_tx_by_wtxid mp) msg.pkg_wtxids in
    Log.debug (fun m ->
      m "getpkgtxns from peer %d: %d/%d wtxids matched" peer.id
        (List.length txs) n_req);
    Peer.send_message peer (P2p.PkgtxnsMsg { pkg_txs = txs })
  end

(* Package relay is negotiated only when BOTH sides sent sendpackages
   between VERSION and VERACK (BIP-331).  A peer's own sendpackages is not
   enough: camlcoin does not announce sendpackages, so [sendpackages_sent]
   is never set and no peer is negotiated. *)
let negotiated (peer : Peer.peer) : bool =
  peer.sendpackages_sent && peer.sendpackages_received

(* Handle an incoming [pkgtxns]: validate the package via the cluster mempool
   accept-package routine.  Logs the outcome; partial acceptance keeps the
   accepted txs and discards the rejected ones.  We do not echo back any
   inv/tx — relay is driven by the existing [TxMsg] listener once individual
   transactions are accepted into the mempool.

   Security audit 2026-10-31 H8: this used to run [Mempool.accept_package]
   (synchronous script verification on the Lwt loop) for every pkgtxns from
   any peer, with no negotiation check and outside the tx listener's
   [Peer.check_rate_limit] and ATMP gate.  Now:
     - un-negotiated pkgtxns is ignored (Core ignores messages for features
       that were not negotiated);
     - a negotiated one counts against the same per-peer budget as [tx]
       messages and runs inside [gate] ([Cli.atmp_relay_gate]), so packages
       and relay txs share one bound on concurrent accepts. *)
let handle_pkgtxns ?gate (mp : Mempool.mempool) (peer : Peer.peer)
    (msg : P2p.pkgtxns_msg) : unit Lwt.t =
  let n = List.length msg.pkg_txs in
  if not (negotiated peer) then begin
    Log.debug (fun m ->
      m "pkgtxns from peer %d without sendpackages negotiation, ignoring"
        peer.id);
    Lwt.return_unit
  end else if n = 0 then Lwt.return_unit
  else if n > Mempool.max_package_count then begin
    Log.warn (fun m ->
      m "pkgtxns from peer %d exceeds max_package_count (%d > %d), ignoring"
        peer.id n Mempool.max_package_count);
    Lwt.return_unit
  end else if not (Peer.check_rate_limit peer) then begin
    Log.debug (fun m ->
      m "pkgtxns from peer %d over the per-peer rate limit, ignoring" peer.id);
    Lwt.return_unit
  end else begin
    let accept () =
      let%lwt () = Lwt.pause () in
      Lwt.return (Mempool.accept_package mp msg.pkg_txs) in
    let%lwt result = match gate with
      | Some g -> Lwt_pool.use g accept
      | None -> accept () in
    (match result with
     | Mempool.PackageAccepted entries ->
       Log.info (fun m ->
         m "pkgtxns from peer %d: accepted %d/%d transactions"
           peer.id (List.length entries) n)
     | Mempool.PackagePartial { accepted; rejected } ->
       Log.info (fun m ->
         m "pkgtxns from peer %d: accepted %d, rejected %d"
           peer.id (List.length accepted) (List.length rejected))
     | Mempool.PackageRejected reason ->
       Log.debug (fun m ->
         m "pkgtxns from peer %d: package rejected: %s" peer.id reason));
    Lwt.return_unit
  end

(* Convenience: dispatch any P2P message to the right handler.  Non-package
   messages return [Lwt.return_unit].  Wire as a peer_manager listener in
   [Cli.run]. *)
let dispatch ?gate (mp : Mempool.mempool) (msg : P2p.message_payload)
    (peer : Peer.peer) : unit Lwt.t =
  match msg with
  | P2p.GetpkgtxnsMsg m -> handle_getpkgtxns mp peer m
  | P2p.PkgtxnsMsg m -> handle_pkgtxns ?gate mp peer m
  | _ -> Lwt.return_unit
