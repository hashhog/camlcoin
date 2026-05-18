# W148 Headers-first sync + chain selection + reorg — camlcoin (OCaml)

Wave: W148 — the headers-first IBD pipeline and chain-selection /
reorg machinery: every layer of code that touches `m_block_index`,
`CChain`, `setBlockIndexCandidates`, `m_best_header`, `nChainWork`,
`nChainTx`, `BLOCK_VALID_*`, `ActivateBestChain`, `ConnectTip`,
`DisconnectTip`, `FindMostWorkChain`, `ProcessNewBlockHeaders`,
`ProcessHeadersMessage`.

Bitcoin Core references:

- `bitcoin-core/src/validation.cpp`
  - L2929-2992: `Chainstate::DisconnectTip` — read block + undo,
    `DisconnectBlock`, prune-lock retreat, `m_chain.SetTip(*pprev)`,
    mempool reorg-pool, `BlockDisconnected` signal.
  - L3005-3108: `Chainstate::ConnectTip` — `assert(pindexNew->pprev ==
    m_chain.Tip())`, `ConnectBlock`, `m_chain.SetTip(*pindexNew)`,
    `MaybeValidateSnapshot`, `BlockConnected` signal.
  - L3114-3171: `Chainstate::FindMostWorkChain` — walks
    `setBlockIndexCandidates.rbegin()`, checks every ancestor for
    `BLOCK_FAILED_VALID` / `!BLOCK_HAVE_DATA`, prunes failed forks.
  - L3191-3274: `Chainstate::ActivateBestChainStep` — disconnect
    tip-back-to-fork, connect fork-forward-to-MostWork, releases
    cs_main between iterations (`fContinue = false` on tip advance).
  - L3323-3520: `Chainstate::ActivateBestChain` — outer loop, retries
    while `m_best_header > m_chain.Tip()->nChainWork`.
  - L4186-4239: `ChainstateManager::AcceptBlockHeader` — duplicate
    detection, `BLOCK_FAILED_VALID` on duplicate AND on parent
    (`bad-prevblk`), `CheckBlockHeader`, `ContextualCheckBlockHeader`,
    `AddToBlockIndex` (sets `nChainWork`, `m_best_header` pointer
    if heavier).
  - L4242-4270: `ChainstateManager::ProcessNewBlockHeaders` —
    AssertLockNotHeld(cs_main), iterates `AcceptBlockHeader` under
    cs_main, calls `NotifyHeaderTip`.
- `bitcoin-core/src/chain.h`
  - L29: `MAX_FUTURE_BLOCK_TIME = 2*60*60` (7200 s).
  - L37: `TIMESTAMP_WINDOW = MAX_FUTURE_BLOCK_TIME`.
  - L46-73: validity bitfield `BLOCK_VALID_TREE=2`,
    `BLOCK_VALID_TRANSACTIONS=3`, `BLOCK_VALID_CHAIN=4`,
    `BLOCK_VALID_SCRIPTS=5`, `BLOCK_FAILED_VALID=0x20`,
    `BLOCK_FAILED_CHILD=0x40`.
  - L118: `arith_uint256 nChainWork{}` per-block cumulative work.
- `bitcoin-core/src/chain.cpp`
  - L26-43: `LocatorEntries(const CBlockIndex* index)` — exponentially
    spaced ancestors via `GetAncestor` (skiplist), 1×10 + 2×N pattern,
    always includes genesis.
  - L50-: `CChain::FindFork(pindex)` — walks back via `pindex->pprev`
    until either chain contains the index.
- `bitcoin-core/src/net_processing.cpp`
  - L100: `HEADERS_RESPONSE_TIME = 2min` per-peer getheaders timeout.
  - L130: `MAX_BLOCKS_IN_TRANSIT_PER_PEER = 16`.
  - L2650-2700: `ProcessHeadersMessage` — `nUnconnectingHeaders`
    accounting, `MAX_NUM_UNCONNECTING_HEADERS_MSGS=10`, peer-misbehavior
    on excess, `getheaders` re-fire on partial connection.
  - L2829-2872: `MaybeSendGetHeaders` — single-flight per peer keyed
    on `peer.m_last_getheaders_timestamp`.
- `bitcoin-core/src/net_processing.h`
  - L50: `MAX_HEADERS_RESULTS = 2000`.

camlcoin reference points:

- `lib/sync.ml:99-103` — `sync_state = Idle | SyncingHeaders |
  SyncingBlocks | FullySynced`.
- `lib/sync.ml:112-117` — `header_entry { header; hash; height;
  total_work }`.
- `lib/sync.ml:136-199` — `chain_state` record (`tip`,
  `headers_synced`, `blocks_synced`, `invalidated_blocks`).
- `lib/sync.ml:820-870` — `validate_header` (header acceptance gate).
- `lib/sync.ml:873-888` — `accept_header` (writes `state.tip`,
  `set_height_hash`, `set_header_tip`).
- `lib/sync.ml:923-982` — `process_headers` (batch entry point).
- `lib/sync.ml:986-1011` — `build_locator`.
- `lib/sync.ml:1130-1363` — `sync_headers` / `sync_iteration`
  (Lwt-driven IBD header-sync loop).
- `lib/sync.ml:2648-2678` — `find_fork_point`.
- `lib/sync.ml:2680-2694` — `collect_path`.
- `lib/sync.ml:2931` — `let max_reorg_depth = 100`.
- `lib/sync.ml:3168-3339` — `disconnect_block_into_batch`.
- `lib/sync.ml:3349-3497` — `connect_block_into_batch`.
- `lib/sync.ml:3555-3743` — `reorganize` (the only reorg orchestrator).
- `lib/sync.ml:3803-3952` — `try_attach_side_branch_and_reorg` (the
  only caller of `reorganize` outside RPC).
- `lib/sync.ml:4358-4573` — `process_new_block` (post-IBD block
  receive path).
- `lib/sync.ml:4237-4356` — `connect_stored_blocks` (gap-fill drain).
- `lib/sync.ml:4720-4745` — `find_best_valid_tip` (best-work header
  candidate scan; `setBlockIndexCandidates` analog).
- `lib/sync.ml:4750-` — `invalidate_block`.
- `lib/cli.ml:1207-1232` — post-IBD `BlockMsg` listener (only caller
  of `process_new_block` outside IBD pipeline).
- `lib/cli.ml:916-961` — post-IBD `HeadersMsg` listener.

---

## BUG-1 — `reorganize` is unreachable from the P2P block path: a heavier competing chain delivered via P2P is never selected as the active tip [P0-CONSENSUS]

- **File:** `lib/sync.ml:4358-4573` (`process_new_block`),
  `lib/cli.ml:1207-1232` (post-IBD `BlockMsg` listener)
- **Core ref:** `bitcoin-core/src/validation.cpp:3323` (`ActivateBestChain`
  invoked from `ProcessNewBlock` regardless of whether the block
  extends the active tip or a side branch)

**Description.** Core's `ProcessNewBlock` → `AcceptBlock` →
`ActivateBestChain` runs unconditionally for every accepted block,
calling `FindMostWorkChain` to select the best-work tip; if the
new block sits on a heavier fork, `ActivateBestChainStep` performs
the disconnect-then-reconnect. In camlcoin, the only way to reach
`reorganize` outside the `invalidateblock` RPC is the
`try_attach_side_branch_and_reorg` helper at
`lib/sync.ml:3803-3952`, which is **only called from
`mining.ml:765`** (the `submitblock` RPC). The post-IBD P2P
`BlockMsg` listener (`lib/cli.ml:1207-1232`) calls
`Sync.process_new_block`, which has the following gate at L4400-4408:

```ocaml
let connects_to_tip =
  if height <> state.blocks_synced + 1 then false
  else if state.blocks_synced = 0 && height = 0 then true
  else match block_tip state with
    | None -> false
    | Some bt -> Cstruct.equal block.header.prev_block bt.hash
in
if not connects_to_tip then begin
  Logs.debug (fun m -> m "Received block %s ... does not extend tip, storing");
  Storage.ChainDB.store_block state.db hash block;
  let connected = connect_stored_blocks state in
  ...
  Ok ()
end
```

A block whose `prev_block` is the **header** tip of a heavier fork
(but not the validated **block** tip of the current active chain)
falls into this branch: it is persisted to disk, but no reorg is
triggered. `connect_stored_blocks` at L4237 walks
`state.blocks_synced+1` using `get_header_at_height` which reads the
`set_height_hash` mapping — but that mapping was overwritten in
`accept_header` (BUG-2 below), so the stored block can never be
drained either.

**Excerpt** (`lib/cli.ml:1207-1232` — the post-IBD wiring):

```ocaml
Peer_manager.add_listener peer_manager (fun msg _peer ->
  match msg with
  | P2p.BlockMsg block when !ibd_state_ref = None
                            && chain.sync_state = Sync.FullySynced ->
    (match Sync.process_new_block chain block with
     | Ok () -> ...
     | Error e ->
       Logs.debug (fun m -> m "Post-IBD block rejected: %s" e);
       Lwt.return_unit)
  | _ -> Lwt.return_unit);
```

**Impact.** Once camlcoin reaches `FullySynced`, any reorg
delivered via the normal P2P INV / GETDATA / BLOCK flow is **silently
ignored** — the heavier chain's blocks accumulate on disk but the
validated tip stays pinned to the original chain. This is the most
fundamental headers-first chain-selection invariant in Bitcoin Core
and it is structurally absent in camlcoin. The node will diverge
from the rest of the network the first time a 2-block reorg
happens. The only fix paths are (a) a peer sending the heavier
chain explicitly via `submitblock` RPC, or (b) an operator manually
calling `invalidateblock` on the old tip — neither of which is
expected to happen in production. Effectively: **camlcoin is a
"never reorgs from P2P" node**.

---

## BUG-2 — `accept_header` unconditionally overwrites the active-chain `set_height_hash` mapping for any incoming header at the same height [P0-CONSENSUS]

- **File:** `lib/sync.ml:873-888` (`accept_header`)
- **Core ref:** `bitcoin-core/src/validation.cpp:3078`
  (`m_chain.SetTip(*pindexNew)` runs only inside `ConnectTip` —
  the height→pindex mapping is only written during active-chain
  advance, NEVER during header acceptance for a side branch)

**Description.** Core separates **header acceptance** from
**active-chain commit**: `AcceptBlockHeader` inserts into
`m_block_index` (keyed by hash), but the height→CBlockIndex* vector
inside `CChain` is only mutated during `ConnectTip` / `DisconnectTip`.
Side-branch headers live in `m_block_index` but **never** appear in
`CChain[]`.

camlcoin's `accept_header` does both in one shot:

```ocaml
let accept_header (state : chain_state) (entry : header_entry) : unit =
  let hash_key = Cstruct.to_string entry.hash in
  Hashtbl.replace state.headers hash_key entry;
  Storage.ChainDB.store_block_header state.db entry.hash entry.header;
  Storage.ChainDB.set_height_hash state.db entry.height entry.hash;  (* <-- UNCONDITIONAL *)
  let is_new_tip = match state.tip with
    | None -> true
    | Some tip -> Consensus.work_compare entry.total_work tip.total_work > 0
  in
  if is_new_tip then begin
    state.tip <- Some entry;
    Storage.ChainDB.set_header_tip state.db entry.hash entry.height;
    state.headers_synced <- entry.height
  end
```

The `set_height_hash` call (L878) is **unconditional**, but the
`is_new_tip` gate at L880-883 only covers `set_header_tip`. So
every header — even one on a less-work sibling — overwrites the
canonical height→hash mapping read by `compute_expected_bits`
(L2099), `compute_median_time_past` (L2065), `fill_download_queue`
(L1644), and `connect_stored_blocks` (L4237).

**Excerpt** (`lib/storage.ml:578-579`):

```ocaml
let set_height_hash t (height : int) (hash : Types.hash256) =
  Cf_chainstate.put_block_height t.cf height hash
```

(No comparison, no work gate, single value per height.)

**Impact.** Compounds catastrophically with BUG-1: a peer sending a
single heavier-tip header replaces the height-hash mapping for the
disputed height, so subsequent `compute_expected_bits` reads on the
ORIGINAL chain's height (now pointing at the sibling fork) return
WRONG difficulty bits, every subsequent active-chain block fails
the `header.bits <> expected_bits` gate, IBD wedges. The classic
fleet-pattern "two-pipeline guard": one side of the code (`state.tip`)
correctly gates on work, the other side (`set_height_hash`) does not.

---

## BUG-3 — `max_reorg_depth = 100` rejects valid heavier-work reorgs of depth > 100; comment falsely claims parity with a non-existent Core `-maxreorgdepth` knob [P0-CONSENSUS]

- **File:** `lib/sync.ml:2926-2931`
- **Core ref:** Core has **no** `MAX_REORG_DEPTH` constant and **no**
  `-maxreorgdepth` CLI option; `ActivateBestChainStep` accepts reorgs
  of arbitrary depth as long as `nChainWork` is strictly heavier
  (`bitcoin-core/src/validation.cpp:3191-3274`).

**Description.** camlcoin's `reorganize` (L3555) caps the disconnect
and connect depth at 100 blocks, returning an `Error "Reorg depth
... exceeds MAX_REORG_DEPTH=100"` for any deeper switch. The comment
above L2931 reads:

```ocaml
(* Cap multi-block reorg depth.  Rolling back more than this many blocks
   is almost certainly a misconfigured peer or a malicious attempt to
   replace deep history; abort rather than burn unbounded I/O.  Bitcoin
   Core has the same conceptual cap via the [-maxreorgdepth] knob (default
   100 in [validation.h]'s [DEFAULT_MAX_REORG_DEPTH]).  *)
let max_reorg_depth = 100
```

`-maxreorgdepth` does **not exist** in current Bitcoin Core:

```
$ grep -rn "maxreorgdepth\|MAX_REORG_DEPTH\|DEFAULT_MAX_REORG_DEPTH" \
        bitcoin-core/src/
(no results)
```

The only depth-keyed constant near this is `MIN_BLOCKS_TO_KEEP = 288`
(`bitcoin-core/src/validation.h:76`) which gates **pruning**, not
reorg depth.

**Excerpt** (`lib/sync.ml:3570-3577`):

```ocaml
let disconnect_depth = current_tip.height - fork_point.height in
let connect_depth = new_tip.height - fork_point.height in
if disconnect_depth > max_reorg_depth
   || connect_depth > max_reorg_depth then
  Error (Printf.sprintf
    "Reorg depth %d exceeds MAX_REORG_DEPTH=%d (disconnect=%d, connect=%d)"
    (max disconnect_depth connect_depth) max_reorg_depth
    disconnect_depth connect_depth)
```

**Impact.** A legitimate >100-block reorg (e.g. recovery from a
multi-day network partition, an assumevalid checkpoint replay, or
the bitcoin-core-style "consensus split repair") will be rejected
by camlcoin while every other peer accepts it. Permanent fork from
network. Less likely in steady-state mainnet but **guaranteed to
trigger on testnet4** where 100+ block reorgs have happened
historically. Worst-case: a heavier chain forms on the network
during a multi-hour camlcoin downtime; on restart the operator
cannot recover because every reorg attempt aborts at depth 101.
Comment-as-confession archetype — fleet pattern.

---

## BUG-4 — `validate_header` does not propagate `BLOCK_FAILED_VALID` to children: a child of an invalidated header is accepted without `bad-prevblk` rejection [P0-CDIV]

- **File:** `lib/sync.ml:820-870` (`validate_header`)
- **Core ref:** `bitcoin-core/src/validation.cpp:4220-4223`:
  ```cpp
  if (pindexPrev->nStatus & BLOCK_FAILED_VALID) {
      LogDebug(BCLog::VALIDATION, "header %s has prev block invalid: %s\n",
               hash.ToString(), block.hashPrevBlock.ToString());
      return state.Invalid(BlockValidationResult::BLOCK_INVALID_PREV, "bad-prevblk");
  }
  ```

**Description.** Core marks descendants of a failed block with
`BLOCK_FAILED_CHILD` lazily via the prev-block check at
`AcceptBlockHeader` time — any header whose parent has
`BLOCK_FAILED_VALID` is rejected with `bad-prevblk`. camlcoin's
`validate_header` reads the parent header from `state.headers` and
returns success as long as PoW / MTP / timestamp / checkpoint /
timewarp pass; it never consults `state.invalidated_blocks`:

```ocaml
let parent_key = Cstruct.to_string header.prev_block in
match Hashtbl.find_opt state.headers parent_key with
| None -> Error "Unknown parent header"
| Some parent ->
  if not (Consensus.hash_meets_target hash header.bits) then
    Error "Insufficient proof of work"
  ...  (* nothing checks Hashtbl.mem state.invalidated_blocks parent_key *)
```

**Impact.** After an operator-issued `invalidateblock` (or after a
block fails validation in `process_new_block` and is marked invalid
at L4557-4558), camlcoin still accepts children of the invalidated
block from peers via headers-first sync. The invalidation chain
only propagates statically via `find_descendants` (L4700) at
`invalidateblock` issue time, never to NEW children that arrive
afterwards. A malicious peer can keep flooding low-work descendants
of an invalidated chain, padding `state.headers` indefinitely and
wasting CPU on PoW checks.

---

## BUG-5 — `find_best_valid_tip` does not check whether the candidate's ancestors are invalidated: descendant of `BLOCK_FAILED_VALID` selected as the best valid tip [P0-CDIV]

- **File:** `lib/sync.ml:4720-4745` (`find_best_valid_tip`)
- **Core ref:** `bitcoin-core/src/validation.cpp:3132-3167`
  (`FindMostWorkChain`: walks `pindexTest = pindexNew` back to
  `m_chain.Contains(pindexTest)`, returns null if any ancestor is
  `BLOCK_FAILED_VALID`)

**Description.** `find_best_valid_tip` iterates every header in
`state.headers`, returning the one with the highest `total_work`
that (a) is not directly in `invalidated_blocks` and (b) has block
data on disk. It does NOT walk the candidate's ancestor chain to
check whether any **intermediate** ancestor is in
`invalidated_blocks`.

```ocaml
let find_best_valid_tip (state : chain_state) : header_entry option =
  let best : header_entry option ref = ref None in
  Hashtbl.iter (fun key (entry : header_entry) ->
    if not (Hashtbl.mem state.invalidated_blocks key) then begin  (* <-- only direct check *)
      let have_data =
        entry.height = 0 || Storage.ChainDB.has_block state.db entry.hash
      in
      if have_data then begin
        match !best with
        | None -> best := Some entry
        | Some b ->
          if Consensus.work_compare entry.total_work b.total_work > 0 then
            best := Some entry
      end
    end
  ) state.headers;
  !best
```

`invalidate_block` (L4750) calls `find_descendants` at issue time to
also flag children — but that is a snapshot: any header that
arrives AFTER an `invalidateblock` whose parent is invalidated
becomes a new candidate that `find_best_valid_tip` will pick
(compounds with BUG-4).

**Impact.** Operator issues `invalidateblock` on a known-bad block
B at height H. Six hours later a peer relays a 5-deep descendant
of B (heights H+1..H+5). `find_best_valid_tip` returns the
descendant. The subsequent `reorganize` call then walks
`find_fork_point` back to the common ancestor (somewhere before H)
and tries to disconnect/reconnect — only to fail mid-way when one
of the connect-side blocks (which IS the invalidated B at height H)
fails validation, leaving the chain partially rewound.

---

## BUG-6 — `note_unconnecting_headers` exceeded path drops `sync_state` to Idle without misbehavior-scoring or disconnecting the peer; "disconnect" comment is a lie [P0-SEC]

- **File:** `lib/sync.ml:1338-1357` (post-process_headers Error case)
- **Core ref:** `bitcoin-core/src/net_processing.cpp` —
  `ProcessHeadersMessage` increments `nUnconnectingHeaders` and
  calls `MaybePunishNodeForBlock` / disconnect on exceeding
  `MAX_NUM_UNCONNECTING_HEADERS_MSGS=10`.

**Description.** When `process_headers` returns `Error "Unknown
parent header"` more than `max_num_unconnecting_headers_msgs` (10)
times from the same peer, camlcoin sets `state.sync_state <- Idle`
but **leaves the peer connected** and never invokes any
ban-score / misbehavior path. The log message claims to "drop the
sync_peer", but `sync_peer` is just a mutable `int option` field;
the peer is not handed to `Peer_manager.disconnect` or scored.

```ocaml
let exceeded = note_unconnecting_headers state peer.Peer.id in
if exceeded then begin
  Logs.warn (fun m ->
    m "Peer %d exceeded MAX_NUM_UNCONNECTING_HEADERS_MSGS=%d, dropping sync_peer"
      peer.Peer.id max_num_unconnecting_headers_msgs);
  reset_unconnecting_headers state peer.Peer.id;
  state.sync_state <- Idle;
  Lwt.return_unit
end
```

**Impact.** A malicious peer can spam unconnecting headers
indefinitely. After the 10th batch, camlcoin stops trying to use
that peer for HEADER sync — but the peer remains connected and can
keep sending other message types (txs, blocks, getheaders requests
back at camlcoin), and a future peer-rotation may even re-attempt
header sync from the same peer. This is the exact DoS vector the
W83 _header-sync-dos-cross-impl-audit pre-fix recovery doc cited
("Pattern B") for fleet-wide closure — closure incomplete here:
camlcoin counts the messages but never punishes.

---

## BUG-7 — `process_headers` post-header-flood `state.sync_state <- Idle` is not coupled with peer disconnect / ban-score; "disconnecting (header flood)" log is misleading [P0-SEC]

- **File:** `lib/sync.ml:1275-1284`
- **Core ref:** `bitcoin-core/src/net_processing.cpp` —
  presync-low-work / commitment-mismatch peer is misbehavior-scored
  100 and disconnected (`MaybePunishNodeForBlock`).

**Description.** When a peer exceeds `max_headers_per_peer`
(2_000_000) headers in a single sync session AND our tip work is
below `minimum_chain_work`, camlcoin logs "disconnecting (header
flood)" and sets `state.sync_state <- Idle`. Same pattern as BUG-6
— the peer is NOT actually disconnected, and the per-peer
`headers_from_peer` counter is never reset, so on the next
sync_iteration we still serve no headers but the peer remains
connected and can keep flooding.

```ocaml
if Consensus.work_compare tip_work
     state.network.minimum_chain_work < 0 then begin
  Logs.warn (fun m ->
    m "Peer %d sent %d headers with insufficient chain work, \
       disconnecting (header flood)" peer.id new_count);
  state.sync_state <- Idle;
  Lwt.return_unit
end
```

**Impact.** Memory exhaustion DoS: the peer can keep us in
`SyncingHeaders` indefinitely. Counter-intuitively, after this
branch fires we revert to `Idle` — so on the NEXT peer-rotation we
try header sync again, potentially from the same malicious peer
(no ban score persisted).

---

## BUG-8 — `process_headers` generic Error case sets sync_state <- Idle without misbehavior-scoring on PoW / MTP / future-time / timewarp / checkpoint violations [P0-SEC]

- **File:** `lib/sync.ml:1358-1361`
- **Core ref:** `bitcoin-core/src/net_processing.cpp:2784-2790` —
  `ProcessHeadersMessage` returns; the caller
  (`PeerManagerImpl::ProcessMessage`) escalates the
  `BlockValidationState` result via `MaybePunishNodeForBlock`
  which DOES disconnect for `BlockValidationResult::BLOCK_INVALID_*`.

**Description.** Every header-validation failure path
(`"Insufficient proof of work"`, `"Header timestamp too far in
future"`, `"Header timestamp not greater than median-time-past"`,
`"time-timewarp-attack"`, checkpoint mismatch, `"too-little-chainwork"`)
funnels into a single `Error e -> Logs.err ... ; state.sync_state
<- Idle ; Lwt.return_unit` block. The peer that sent the invalid
header is never ban-scored or disconnected.

```ocaml
| Error e ->
  Logs.err (fun m -> m "Header validation failed: %s" e);
  state.sync_state <- Idle;
  Lwt.return_unit
```

**Impact.** A peer that wants to keep this node permanently stuck
in `Idle` (i.e. never syncing) only needs to send a single header
with a bogus PoW or MTP. The node logs an error, sets `Idle`, and
hangs there until human intervention. No automatic recovery
because the only mechanism that re-enters `SyncingHeaders` is
`start_header_sync` from `cli.ml`'s periodic poll — and on the
next poll, the same misbehaving peer will be picked again.

---

## BUG-9 — `compute_expected_bits` reads `get_header_at_height` (active-chain height map) instead of walking the candidate block's OWN parent chain — wrong difficulty on side branches [P0-CDIV]

- **File:** `lib/sync.ml:2099-2148`
  (`compute_expected_bits`)
- **Core ref:** `bitcoin-core/src/pow.cpp` `GetNextWorkRequired`
  takes `const CBlockIndex* pindexLast` (the **block's own**
  parent index, walked via `GetAncestor` for retarget-boundary
  computation); active-chain membership is irrelevant.

**Description.** `compute_expected_bits` calls
`get_header_at_height state (height - 1)` to fetch the parent
header. `get_header_at_height` resolves through
`Storage.ChainDB.get_hash_at_height` which is the canonical
height→hash mapping that BUG-2 overwrites unconditionally. So:

- On the active chain: returns the active parent. Correct.
- On a side branch: returns the active-chain block at `height-1`,
  not the side branch's parent. **Wrong difficulty.**

`try_attach_side_branch_and_reorg` (L3850-3865) acknowledges this
hazard and falls back to `parent.header.bits` for regtest, but the
production path through `reorganize`'s
`connect_block_into_batch` (L3361) calls `compute_expected_bits`
without the workaround, and post-IBD's `process_new_block` (L4425)
also uses it directly.

```ocaml
else begin
  match get_header_at_height state (height - 1) with  (* ACTIVE-CHAIN read *)
  | Some parent ->
    ...
    (match Consensus.testnet_min_difficulty_bits
             ~prev_block_time:parent.header.timestamp
             ~current_time:block_header.timestamp
             ...) with
     | Some min_bits -> min_bits
     | None -> parent.header.bits)
  | None -> network.pow_limit
end
```

**Impact.** A reorg whose connect-side blocks span a retarget
boundary (every 2016th block) computes the expected `nBits` from
the WRONG ancestors (the about-to-be-disconnected chain rather
than the new chain), and the connect-side block fails the
`expected_bits` gate. The reorg aborts. Same hazard for testnet
min-difficulty handling: 20-min-after-parent rule reads the WRONG
parent timestamp. On mainnet this is "very rare" only because
reorgs are rare; on testnet4 it triggers reliably.

---

## BUG-10 — entire `block_status` validity bitfield (`BLOCK_VALID_TREE`, `BLOCK_VALID_TRANSACTIONS`, `BLOCK_VALID_CHAIN`, `BLOCK_VALID_SCRIPTS`, `BLOCK_FAILED_CHILD`) is DEAD CODE — defined in `lib/storage.ml`'s `FlatFileStorage`, never read by production `ChainDB` [P0]

- **File:** `lib/storage.ml:1091-1233` (definition),
  `lib/storage.ml:1138` (`FlatFileStorage` module)
- **Core ref:** `bitcoin-core/src/chain.h:46-73` — validity bitfield
  is the canonical mechanism for tracking how far a block has
  progressed through the validation pipeline.

**Description.** camlcoin defines a faithful Core-style validity
bitfield in `storage.ml`:

```ocaml
type block_status =
  | Block_valid_unknown
  | Block_valid_header
  | Block_valid_tree         (* Header connects to known chain *)
  | Block_valid_transactions
  | Block_valid_chain        (* Outputs are spendable *)
  | Block_valid_scripts      (* Scripts verified *)
  | Block_have_data
  | Block_have_undo
  | Block_failed
  | Block_failed_child
  | Block_pruned

type block_index_entry = {
  file_pos : flat_file_pos;
  ...
  status : block_status list;
  ...
}
```

with full serialisation/deserialisation via `serialize_entry` /
`deserialize_entry` at L1235-1260. All of this lives inside
**`module FlatFileStorage`** (L1138), and `FlatFileStorage` is
referenced exclusively from `test/test_storage.ml` — zero callers
in `lib/`, `bin/`, or production wiring:

```
$ grep -rn "FlatFileStorage" lib/ bin/
(nothing)
$ grep -rn "FlatFileStorage" test/
test/test_storage.ml:307:  let storage = Storage.FlatFileStorage.create ...
test/test_storage.ml:311:  let pos = Storage.FlatFileStorage.write_block ...
... (8 hits, all in the test file)
```

The production path uses `module ChainDB` (L497, backed by
RocksDB). `ChainDB` does NOT carry the validity bitfield — the
only flags it persists are a single `set_block_invalidated` boolean
keyed by hash (`Hashtbl.t state.invalidated_blocks` mirror).

**Impact.** Fleet-pattern "dead-class": every reference to
`Block_valid_*` / `Block_failed_child` / `Block_have_undo` in the
production code path is a no-op. The headers-first chain selection
algorithm Core uses depends on this bitfield — `FindMostWorkChain`
prunes by `BLOCK_FAILED_VALID`, `ActivateBestChain` advances by
`BLOCK_VALID_SCRIPTS`. Without these, camlcoin's chain selection
degenerates to "highest total_work header that has block data on
disk", with no record of how far a candidate has been validated
beyond raw header acceptance. Cross-cites W138 dead-class pattern
(9 of 10 impls confirm at the snapshot/UTXO layer).

---

## BUG-11 — `accept_header` only updates `state.tip` on strict `> 0` work increase: ties (`equal-work fork`) are silently dropped, but `set_height_hash` STILL overwrites [P1]

- **File:** `lib/sync.ml:879-888`
- **Core ref:** `bitcoin-core/src/validation.cpp:4233`
  `AddToBlockIndex(block, m_best_header)` — Core's
  `m_best_header` advances on `>=` (first-seen rule preserves the
  prior best on tie, but `m_block_index` still stores both).

**Description.** L880-883:

```ocaml
let is_new_tip = match state.tip with
  | None -> true
  | Some tip -> Consensus.work_compare entry.total_work tip.total_work > 0
in
if is_new_tip then begin
  state.tip <- Some entry;
  ...
end
```

`Consensus.work_compare > 0` requires STRICT-greater-than. For a
sibling with EQUAL work (same height + same difficulty), `state.tip`
stays on the original. But (compounding with BUG-2) `set_height_hash`
at L878 STILL overwrites the height→hash mapping with the sibling.

**Impact.** Tie-break inconsistency: in-memory `state.tip` and
on-disk `get_hash_at_height` disagree about which fork is canonical.
A subsequent `compute_expected_bits` reads the sibling's bits (via
disk), while `block_tip` reads the original (via in-memory tip).
For honest networks this is rare; for adversarial scenarios this
is reachable.

---

## BUG-12 — `find_fork_point` walks parent links via `Hashtbl.find_opt state.headers`; if the in-memory header map evicts headers (post-restart restore is bounded to `tip_height` walk), the walk silently truncates and returns the wrong fork point [P1]

- **File:** `lib/sync.ml:2648-2678` (`find_fork_point`)
- **Core ref:** `bitcoin-core/src/chain.cpp:50-` (`CChain::FindFork`
  uses CBlockIndex::pprev pointer + skiplist — never fails
  silently because `m_block_index` retains every accepted header).

**Description.** The error arms in `find_fork_point`:

```ocaml
| None -> Error "Cannot find fork point (missing parent of current)"
| None -> Error "Cannot find fork point (missing parent of new)"
| None, _ -> Error "Cannot find fork point (missing parent)"
| _, None -> Error "Cannot find fork point (missing parent)"
```

assume the in-memory `state.headers` map contains every ancestor
back to genesis. `restore_chain_state` at L690-755 walks heights
`0..tip_height` from disk and populates the map — but only along
the active chain (`get_hash_at_height` returns the active-chain
mapping). Side-branch headers on disk (written by
`register_side_branch_header` at L3787) are not re-loaded on
restart. So after a restart:

- `state.headers` contains the active chain (height 0 .. tip).
- The disk has side-branch headers but they are not in memory.
- `find_fork_point` between the active tip and a side-branch tip
  fails because the side-branch's parents aren't in memory.

`reorganize` returns Error, no reorg. Compounds with BUG-1.

**Impact.** Side-branch acceptance via `try_attach_side_branch_and_reorg`
followed by daemon restart loses the ability to reorg back. The
operator must `invalidateblock` the old tip to force the chain
elsewhere — and `find_descendants` would also fail to walk the
side branch.

---

## BUG-13 — `process_new_block`'s `too-far-ahead` gate uses `state.blocks_synced + 288`, not `ActiveHeight() + MIN_BLOCKS_TO_KEEP` — the gate is consistent for the validated tip but DOES NOT reject blocks above the header tip [P2]

- **File:** `lib/sync.ml:4395-4398`
- **Core ref:** `bitcoin-core/src/validation.cpp:4325`
  `fTooFarAhead{pindex->nHeight > ActiveHeight() + int(MIN_BLOCKS_TO_KEEP)}`

**Description.** Core anchors the cap at `ActiveHeight()`, but
during IBD the header tip can be 100k+ blocks ahead of
`blocks_synced`. In camlcoin the cap is `state.blocks_synced +
288`, so a peer who sends a block at `blocks_synced + 5000`
correctly fails the gate. But the comment at L4386-4393 cites
"ActiveHeight()" — fleet-pattern "off-by-pipeline-stage".

In practice this is harmless on the rejection side (more strict
than Core), but compounds with BUG-1: a block on a heavier
sibling chain at sibling-height = blocks_synced + 50 is stored on
disk (not too-far-ahead, not rejected) and accumulates.

**Impact.** Disk fills with stored-but-never-connectable blocks
on a sibling chain. Low severity because the cap prevents
runaway; correct-direction divergence.

---

## BUG-14 — `disconnect_to_target` (the only rollback used by `dumptxoutset` / `invalidateblock`) does not perform `apply_tx_in_undo`-style overwrite-detection: silently corrupts UTXO set if undo data references already-restored coins [P1]

- **File:** `lib/sync.ml:2709-2804`
- **Core ref:** `bitcoin-core/src/validation.cpp:2929-2992`
  `DisconnectTip` calls `DisconnectBlock` which calls
  `ApplyTxInUndo` with `is_overwrite` detection. Returns
  `DISCONNECT_UNCLEAN` on overwrite; caller logs warning.

**Description.** `disconnect_block_into_batch` (L3168, used by
`reorganize`) DOES implement the full G1-G13 gate set including
`apply_tx_in_undo`. But the SECOND disconnect path —
`disconnect_to_target` at L2709, used by
`Storage.ChainDB.disconnect_to_height` (line 7100-ish in rpc.ml's
`invalidateblock`-without-reorg-target path) — is the OLD simple
implementation:

```ocaml
List.iter (fun (tx_undo : Utxo.tx_undo) ->
  List.iter
    (fun (outpoint, (utxo_entry : Utxo.utxo_entry)) ->
      let data = encode_utxo utxo_entry.value
                   utxo_entry.script_pubkey
                   utxo_entry.height
                   utxo_entry.is_coinbase in
      Storage.ChainDB.batch_store_utxo batch
        outpoint.Types.txid
        (Int32.to_int outpoint.Types.vout)
        data
    ) tx_undo.spent_outputs
) undo.tx_undos;
```

No `is_overwrite` check, no `Disconnect_unclean` flag, no
recovery for pre-0.10 undo records with `height = 0`. If a coin
is already live in the UTXO set when we try to "restore" it from
undo data, we silently overwrite the live coin's metadata with
the undo's metadata. Two-pipeline guard: the `reorganize`-side
disconnect is W92-grade Core-parity, the `disconnect_to_target`
side is the W14-era pre-fix path.

**Impact.** Reachable via `dumptxoutset` (rolls back to a target
height before dumping) and the `invalidateblock` RPC's
without-utxo-set fallback. If the chainstate has any latent
inconsistency (coinbase txid collision, BIP-30 pair around
91722/91812 on mainnet, etc.) the rollback corrupts the UTXO set
permanently. Cross-cite Pattern D-FULL closure 2026-05-05.

---

## BUG-15 — `request_headers` does NOT mark the per-peer `m_last_getheaders_timestamp` equivalent; rate limiting `getheaders_rate_limit = 2.0` is only checked in PRESYNC/REDOWNLOAD `should_request_more_headers`, NOT in main `sync_iteration` [P1]

- **File:** `lib/sync.ml:1107-1125` (`request_headers`),
  `lib/sync.ml:1227-1266` (`sync_iteration` send path)
- **Core ref:** `bitcoin-core/src/net_processing.cpp:2829`
  `if (current_time - peer.m_last_getheaders_timestamp >
   HEADERS_RESPONSE_TIME)` — single-flight per peer keyed on a
  per-peer timestamp updated AFTER every send.

**Description.** `sync_iteration` uses `pending_getheaders` (a
single-int counter, L1227) to avoid double-firing — but this is
NOT per-peer. If `sync_headers` is invoked concurrently for two
peers (`start_header_sync` is called on every peer in
`cli.ml`-controlled rotation), each invocation has its own
`pending_getheaders` closure and they don't coordinate. The
per-peer `last_getheaders_time` field on `peer_header_sync` (L77)
is only updated by `mark_getheaders_sent`, which is called from
the PRESYNC/REDOWNLOAD path (line 634-635) but not from the main
`request_headers` (which is what the post-IBD `cli.ml` listener at
L935 calls).

```ocaml
let mark_getheaders_sent (ps : peer_header_sync) : unit =
  ps.last_getheaders_time <- Unix.gettimeofday ()
```

Search for `mark_getheaders_sent` callers — only 0 hits in the
production header-sync path:

```
$ grep -n mark_getheaders_sent lib/sync.ml
634:let mark_getheaders_sent (ps : peer_header_sync) : unit =
```

(Definition only; no callers.)

**Impact.** During parallel peer rotations, camlcoin can send
many overlapping `getheaders` to the same peer, wasting bandwidth
and triggering peer-side `MisbehavingFromTooManyGetheaders`
discipline. Latent dead-helper at call-site.

---

## BUG-16 — `max_headers_per_message = 2000` constant defined but never enforced as a receive-side gate on `process_headers` input [P2]

- **File:** `lib/sync.ml:221` (definition; 0 referenced usage)
- **Core ref:** `bitcoin-core/src/net_processing.cpp:2966-2974`
  Core rejects headers messages with `> MAX_HEADERS_RESULTS=2000`
  entries via `MisbehavingFromHeadersMessage`.

**Description.** The deserializer in `lib/p2p.ml:528-529` does
cap at 2000 via `max_headers_count`:

```ocaml
let deserialize_headers_msg r : Types.block_header list =
  let count = Serialize.read_compact_size r in
  if count > max_headers_count then
    failwith ...
```

But `process_headers` itself never re-checks `List.length headers
<= 2000` — so if the deserializer is replaced (e.g. via the
`block_import.ml` framed-block path) or if a malformed peer
sneaks past with a 1999-entry message and the deserializer's
check is off by one, no second-layer defense.

```
$ grep -n max_headers_per_message lib/sync.ml lib/peer.ml \
                                  lib/peer_manager.ml
lib/peer.ml:640: (comment only — "exactly 81 × max_headers_per_message")
lib/sync.ml:221: let max_headers_per_message = 2000  (* definition *)
```

Zero referenced usages. Dead constant.

**Impact.** Defense-in-depth gap. Reaches P2 only because the
p2p.ml layer already caps.

---

## BUG-17 — `restore_chain_state` walks heights `0..tip_height` linearly; if a header is missing for any height in the range it silently breaks the work-accumulation chain (`parent_work = zero_work`) [P1]

- **File:** `lib/sync.ml:719-740`
- **Core ref:** `bitcoin-core/src/validation.cpp:6042-6080`
  `LoadBlockIndex` walks every entry in the `blocks` LevelDB
  table; missing entries are a hard error (`AbortNode`).

**Description.** L725-730:

```ocaml
let parent_work = if h = 0 then Consensus.zero_work else
  match Hashtbl.find_opt state.headers
      (Cstruct.to_string header.prev_block) with
  | Some parent -> parent.total_work
  | None -> Consensus.zero_work
in
```

If the parent isn't in the in-memory map (just-built up at this
point — earlier iterations populated it, so the `prev_block`
hash should resolve), the code falls through to `zero_work`. So
a single missing header at height `h` resets `total_work` for
every descendant restored after it.

**Impact.** Database corruption — a missing height→hash mapping
at height H — silently produces incorrect `total_work` for every
height > H. `state.tip` then reports an artificially low total
work, peers' headers with the SAME real chain work are seen as
"heavier" and trigger a useless re-sync. The recovery doc
`CORE-PARITY-AUDIT/_post-reorg-consistency-fleet-result-2026-05-05.md`
already addressed atomicity; this is the read-side counterpart
that remains.

---

## BUG-18 — `register_side_branch_header` does NOT write `set_height_hash` (correct, per the side-branch contract) but DOES write `store_block_header` — and the loader `restore_chain_state` only walks active-chain heights, so side-branch headers are not reloaded on restart [P1]

- **File:** `lib/sync.ml:3780-3787` (`register_side_branch_header`),
  `lib/sync.ml:690-755` (`restore_chain_state`)
- **Core ref:** `bitcoin-core/src/validation.cpp:6042-6080`
  `LoadBlockIndex` iterates the entire `blocks` LevelDB key range
  via cursor — side-branch headers ARE reloaded.

**Description.** `register_side_branch_header` is correctly
careful NOT to overwrite `set_height_hash` (the bug BUG-2 should
have applied):

```ocaml
let register_side_branch_header (state : chain_state) (entry : header_entry)
    : unit =
  let hash_key = Cstruct.to_string entry.hash in
  Hashtbl.replace state.headers hash_key entry;
  Storage.ChainDB.store_block_header state.db entry.hash entry.header
```

But `restore_chain_state` only walks heights `0..tip_height`:

```ocaml
for h = 0 to tip_height do
  match Storage.ChainDB.get_hash_at_height db h with
  | Some hash ->
    (match Storage.ChainDB.get_block_header db hash with
     | Some header -> ...
```

Side-branch headers stored via `register_side_branch_header` are
never enumerated. They live on disk forever, never re-loaded.
Subsequent calls to `try_attach_side_branch_and_reorg` cannot
find the side-branch parent, so even submitted-block-side reorg
becomes unreachable after a restart.

**Impact.** State loss across restart: a side-branch accepted in
session A is invisible to session B. Compounds with BUG-12.

---

## BUG-19 — Locator construction (`build_locator`) reads from disk (`get_hash_at_height`) every iteration; if the active-chain map is mid-corruption from a partial reorg, the locator hashes point into an inconsistent fork [P2]

- **File:** `lib/sync.ml:986-1011`
- **Core ref:** `bitcoin-core/src/chain.cpp:26-43` —
  `LocatorEntries` walks `index->pprev` in memory, never touches
  on-disk state, guaranteeing internal consistency.

**Description.** Each iteration of `build_locator` calls
`Storage.ChainDB.get_hash_at_height state.db height` — a separate
disk read. There is no transaction/snapshot semantic; a concurrent
header acceptance via `accept_header` (BUG-2) can mutate
`set_height_hash` between iterations, so the resulting locator
mixes hashes from before and after a side-branch overwrite.

**Impact.** Peers can see an inconsistent locator (e.g. height
1000 → active-chain hash, height 999 → sibling-chain hash). Peer
returns headers that don't connect to anything we have. Headers
sync wedges. Failure mode usually manifests as "Unknown parent
header" → BUG-6 path → Idle.

---

## BUG-20 — `IsInitialBlockDownload` analog: 4-state enum (`Idle`/`SyncingHeaders`/`SyncingBlocks`/`FullySynced`) does NOT latch on Core's combined `(tip_recent && chain_work >= minimum_chain_work)` rule [P2]

- **File:** `lib/sync.ml:99-103`,
  `lib/sync.ml:4014` (`sync_state <- FullySynced` transition)
- **Core ref:** `bitcoin-core/src/validation.cpp:3283-3291`
  `UpdateIBDStatus`: `if (!CurrentChainstate().m_chain.IsTipRecent
   (MinimumChainWork(), m_options.max_tip_age)) return;` —
  one-way latch (`m_cached_is_ibd.store(false)`).

**Description.** camlcoin's sync state machine transitions to
`FullySynced` when `blocks_synced >= tip_height`
(`lib/sync.ml:4008-4014`), with no check on:

- `tip_recent` — Core requires the tip's timestamp to be within
  `max_tip_age` (default 24h) of NodeClock::now.
- `chain_work >= MinimumChainWork` — already checked at header
  sync entry (L1316) but not re-checked at the SyncingBlocks →
  FullySynced transition.

So after IBD on a hostile peer that fed a low-work chain, camlcoin
can declare `FullySynced` with `blocks_synced == tip_height` even
though the chain is below minimum work. The post-IBD listener
then starts accepting unsolicited `BlockMsg` and `HeadersMsg`.

**Impact.** A peer-driven eclipse attack that feeds a low-work
fork can graduate camlcoin to `FullySynced` and lock the node onto
the fork. Core's `IsInitialBlockDownload` defends against this by
remaining `true` until both conditions are satisfied; camlcoin's
exit gate is weaker.

---

## BUG-21 — `nChainTx` (cumulative tx count) is NOT maintained on `header_entry`; `getblockheader` reports `n_tx` via a separate `store_block_ntx` (block-body-time) and there is no `chain_tx_count` analog [P2]

- **File:** `lib/sync.ml:112-117` (`header_entry` definition)
- **Core ref:** `bitcoin-core/src/chain.h:135-140`
  `CBlockIndex::nChainTx` — sum of `nTx` for this block and every
  ancestor. Used by `getchaintxstats`, `verifychain`, and the
  RPC `getblockchaininfo` `chainwork`/`tx_count` reporting.

**Description.** `header_entry` carries only `total_work`. The
per-block `nTx` is stored separately via
`Storage.ChainDB.store_block_ntx` (L4337) after a successful
connect, but there's no cumulative `chain_tx_count` field that
gets incremented atomically with `total_work`.

**Impact.** `getchaintxstats` (if/when implemented) cannot compute
historical tx rates from header-only data; `getblockheader` cannot
return `nChainTx`. RPC parity gap, fleet-pattern "missing W148
field".

---

## BUG-22 — `m_best_invalid` analog (best-work invalid chain warning) is NOT tracked; `CheckForkWarningConditions` (warn-on-`large-work-invalid-chain`) absent [P3]

- **File:** `lib/sync.ml:state.invalidated_blocks` (only the set;
  no work-best aggregate)
- **Core ref:** `bitcoin-core/src/validation.cpp:1945-1961`
  `CheckForkWarningConditions` warns the operator (and emits
  kernel notification `LARGE_WORK_INVALID_CHAIN`) when an
  invalid chain has more than 6 blocks of work over the current
  tip.

**Description.** Bitcoin Core tracks the best-work invalid chain
via `m_chainman.m_best_invalid` and warns the operator
("Warning: Found invalid chain more than 6 blocks longer than our
best chain. This could be due to database corruption or consensus
incompatibility with peers.") when the gap exceeds 6 blocks of
work. This is a critical operator signal that the node is
diverging from network consensus. camlcoin has no equivalent.

**Impact.** Operator loses early-warning signal for consensus
incompatibility / database corruption. Mainnet-relevant for any
operator running camlcoin alongside Core fleet.

---

## BUG-23 — `setBlockIndexCandidates` analog: `find_best_valid_tip` is O(N) over the entire `state.headers` Hashtbl on every reorg attempt; no ordered set, no candidate prune [P3]

- **File:** `lib/sync.ml:4720-4745`
- **Core ref:** `bitcoin-core/src/validation.cpp:3122`
  `std::set<CBlockIndex*, CBlockIndexWorkComparator>
   setBlockIndexCandidates.rbegin()` — O(log N) best-candidate
  lookup, plus `PruneBlockIndexCandidates` removes stale tips.

**Description.** camlcoin iterates `Hashtbl.iter` over every
header in memory each time `find_best_valid_tip` is called. With
2 M+ accepted headers (testnet/mainnet sync), this is a
multi-second linear scan that runs on every `invalidate_block`,
every reorg trigger, every "is there a better tip?" check.

```ocaml
Hashtbl.iter (fun key (entry : header_entry) ->
  if not (Hashtbl.mem state.invalidated_blocks key) then begin
    let have_data = ...
    if have_data then begin
      match !best with
      | None -> best := Some entry
      | Some b ->
        if Consensus.work_compare entry.total_work b.total_work > 0 then
          best := Some entry
    end
  end
) state.headers
```

**Impact.** Performance regression on large header sets; not a
correctness issue but a fleet-pattern "no ordered candidates"
hazard that compounds with BUG-1 (when reorg DOES eventually get
wired in, it'll be slow).

---

## BUG-24 — Reorg-path `compute_expected_bits` uses active-chain reads inside `connect_block_into_batch` BUT acknowledges the same hazard at `try_attach_side_branch_and_reorg`; not closed [P0-CDIV, cross-cite BUG-9]

- **File:** `lib/sync.ml:3361` (`connect_block_into_batch`),
  `lib/sync.ml:3860-3865`
  (`try_attach_side_branch_and_reorg`'s workaround)
- **Core ref:** see BUG-9.

**Description.** `try_attach_side_branch_and_reorg` at L3850-3865
acknowledges the hazard:

```ocaml
let expected_bits =
  if state.network.pow_no_retargeting then parent.header.bits
  else if height mod Consensus.difficulty_adjustment_interval = 0
  then compute_expected_bits state height block.header
  else parent.header.bits
in
```

So for non-retarget heights on a side branch, the helper falls
back to `parent.header.bits`. But the moment `reorganize` enters
`connect_block_into_batch` (L3361):

```ocaml
let expected_bits = compute_expected_bits state height block.header in
```

— with no workaround. And `compute_expected_bits` walks
`get_header_at_height (height - 1)` which is the ACTIVE chain (BUG-2
overwrites notwithstanding).

**Impact.** During a reorg's connect-side, every block at a
retarget boundary on the new chain is checked against the OLD
chain's pre-retarget difficulty. The W2016 (retarget) reorg case
is the most common failure mode. Cross-cite BUG-9; same root,
two distinct call sites.

---

## BUG-25 — Two-pipeline guard: `process_new_block`'s post-IBD path reads `Consensus.get_block_script_flags` directly (no assumevalid skip), but `connect_block_into_batch` reads `is_assume_valid` to decide flags — divergent flag computation between post-IBD and reorg paths [P2]

- **File:** `lib/sync.ml:4448-4450` (`process_new_block`),
  `lib/sync.ml:3400-3404` (`connect_block_into_batch`)
- **Core ref:** `bitcoin-core/src/validation.cpp:2440-2530`
  `ConnectBlock` reads `nBlockMaxScriptSize`, `IsAssumevalidedAt`,
  and `flags` via a single helper, identical regardless of
  caller.

**Description.** `process_new_block` (the post-IBD P2P entry):

```ocaml
let validation_flags =
  Consensus.get_block_script_flags height state.network
in
... ~skip_scripts:false ...
```

`connect_block_into_batch` (the reorg-side):

```ocaml
let skip_scripts = is_assume_valid state height in
let validation_flags =
  if skip_scripts then 0
  else Consensus.get_block_script_flags height state.network
in
```

So during a reorg whose connect-side is BELOW `assume_valid_hash`,
script verification is skipped; via post-IBD it's not (which is
actually safer, but inconsistent). The W41 audit recovery doc
already cited this asymmetry; fleet-pattern "two-pipeline guard".

**Impact.** Performance hit on reorgs that re-connect through
pre-assumevalid heights, minor. Acceptable as a deliberate
conservatism for post-IBD, but should be documented; currently
just two parallel code paths that disagree.

---

## BUG-26 — `connect_stored_blocks` walks `next_height = blocks_synced + 1` linearly with no termination on missing blocks; can recurse 800k+ times if `get_header_at_height` returns Some but `has_block` returns false [P2]

- **File:** `lib/sync.ml:4237-4356`
- **Core ref:** N/A — Core's `ActivateBestChain` outer loop
  releases cs_main and breaks on tip-advance failure.

**Description.** `connect_stored_blocks` is recursive:

```ocaml
let rec connect_stored_blocks (state : chain_state) : int =
  let next_height = state.blocks_synced + 1 in
  match get_header_at_height state next_height with
  | None -> 0
  | Some entry ->
    let extends_tip = ... in
    if not extends_tip then 0
    else if not (Storage.ChainDB.has_block state.db entry.hash) then 0
    ...
    1 + connect_stored_blocks state
```

Tail-recursion in OCaml *is* compiled to a loop, so stack
overflow is not the concern — but the function holds the chain
state implicitly (no Lwt yield, no cs_main release equivalent)
for the entire walk. During gap-fill drain of 100k+ stored blocks
this monopolizes a single thread for minutes.

**Impact.** During post-IBD catch-up after a long camlcoin
downtime where peers backfilled many blocks, a single
`connect_stored_blocks` call can starve the Lwt scheduler.
Side-effect: peers time out, get disconnected, IBD partially
fails. Cross-cite W43.

---

## BUG-27 — `accept_header`'s `set_header_tip` IS gated on `is_new_tip` (correct), but `state.headers_synced` and `state.tip` updates are interleaved with `set_header_tip` outside a transactional write; crash between L885-L886 leaves `state.headers_synced` advanced but `set_header_tip` not persisted [P2]

- **File:** `lib/sync.ml:884-887`
- **Core ref:** `bitcoin-core/src/validation.cpp`
  `m_chainman.m_best_header` and `m_chain.SetTip` are in-memory
  pointers committed atomically inside `ConnectTip`; on-disk
  persistence via `FlushStateToDisk` is a separate
  always-after-commit step.

**Description.**

```ocaml
if is_new_tip then begin
  state.tip <- Some entry;                                  (* in-memory *)
  Storage.ChainDB.set_header_tip state.db entry.hash entry.height;  (* disk *)
  state.headers_synced <- entry.height                      (* in-memory *)
end
```

A crash between L885 and L886 (the disk write) is recoverable —
`restore_chain_state` rebuilds from `get_header_tip`. But a crash
between L886 and L887 leaves the on-disk header tip ahead of
the recovered `state.headers_synced` — minor inconsistency, but
the in-memory invariant `state.headers_synced == state.tip.height`
is violated for the next cleanup pass.

**Impact.** Latent state-recovery hazard, low probability; fixed
by either (a) writing the disk before the in-memory mutation or
(b) wrapping all three in a single RocksDB batch.

---

## BUG-28 — No `MaybeSendGetHeaders` analog (single-flight per-peer with `HEADERS_RESPONSE_TIME` timeout): camlcoin sends one `getheaders` from `request_headers` and waits via `read_message_with_timeout`, but a peer that responds with a 1-header batch (not 2000) is implicitly treated as "tip reached" without re-firing `getheaders` to discover whether the peer had more [P3]

- **File:** `lib/sync.ml:1309-1326` (the `count < max_headers` branch)
- **Core ref:** `bitcoin-core/src/net_processing.cpp:2696-2702`
  Core ALWAYS re-fires `getheaders` after a valid header batch:
  `bool sent_getheaders = MaybeSendGetHeaders(pfrom, locator, peer);`

**Description.**

```ocaml
if count = P2p.max_headers_count then begin
  ...sync_iteration ()
end
else begin
  (* Got fewer than max — peer's tip reached. *)
  ...
end
```

camlcoin treats `count < 2000` as terminal. Core only treats
exactly-zero-headers as terminal; for `0 < count < 2000` Core
still re-fires a follow-up `getheaders` (using the new tip's
locator) — because the peer's `MAX_HEADERS_RESULTS` cap might
not be exactly 2000 (it's a peer-side decision).

**Impact.** Tail-of-IBD slowdown: a peer that legitimately
caps at 1000 headers per response is treated as "done", camlcoin
moves to `SyncingBlocks` and re-requests headers only on the
next peer rotation. Adds 30-60s to IBD tail.

---

## Fleet-pattern smells

1. **"Dead-class" pattern (W138-grade, this wave's instance: BUG-10)**
   The full Core `block_status` validity bitfield is defined in
   `lib/storage.ml`'s `FlatFileStorage` module — full
   serialise/deserialise/round-trip implementation — but the
   production `ChainDB` doesn't use it; only `set_block_invalidated`
   (a single boolean) is wired. Same template as W138's
   ChainstateManager / DualChainstateManager / BackgroundValidator
   pattern: a faithful Core-style data structure built but
   wired only into tests.

2. **"Two-pipeline guard" 15th distinct extension (BUG-9 & BUG-24
   compound, BUG-14 vs. `disconnect_block_into_batch`, BUG-25)**
   The `reorganize` codepath (post-W92) has Core-grade gates
   (Disconnect_ok/Disconnect_unclean/Disconnect_failed tri-result,
   apply_tx_in_undo, full G1-G13 set) but parallel
   `disconnect_to_target` and `process_new_block` paths are
   stuck at the pre-fix simple implementation. The `is_assume_valid`
   flag-derivation split between paths is the same template.

3. **"Comment-as-confession" 5th instance (BUG-3)**
   `let max_reorg_depth = 100` cites a `[-maxreorgdepth]` knob in
   `DEFAULT_MAX_REORG_DEPTH` that does not exist in Bitcoin Core —
   a fabricated reference, comparable to W141's "comment-as-confession"
   archetype in clearbit/rustoshi (3rd & 4th).

4. **"Plumb-then-no-call" / dead-helper-at-call-site (BUG-15)**
   `mark_getheaders_sent` is defined, has the right signature,
   has the right purpose — and has ZERO callers in the production
   header-sync path. The per-peer `last_getheaders_time` field
   is read by `should_request_more_headers` but never written
   from `request_headers`. Identical to nimrod W141 BUG-24 plumb-gate-then-flip.

5. **"P0-CONSENSUS: reorg-not-wired" (BUG-1)**
   The full reorg machinery exists, but the P2P block-arrival
   path doesn't invoke it. Cross-cite Pattern Y (which closed
   submitblock side-branch acceptance) — Pattern Y closed the
   submitblock → reorganize edge, but never closed
   process_new_block → reorganize. Two halves of the same
   architectural gap closed in stages, only one stage done.

6. **"Default-install consensus divergence: 100-block cap"
   (BUG-3)**
   camlcoin alone in the fleet caps reorg depth. Any deep reorg
   (test net4 has historical 100+ block reorgs) wedges the
   node. Likely 1-of-10 in the fleet; should be verified against
   sibling impls in the next sweep.

7. **"Header-acceptance overwrites active-chain map" (BUG-2)**
   set_height_hash is called unconditionally on every header
   acceptance, not gated on work-compare. The same shape as
   ouroboros W128 BUG-3 (banman conflates) — one mutation
   serves two semantically distinct purposes.

8. **"DoS gap on peer misbehavior": (BUG-6 + BUG-7 + BUG-8)**
   Three distinct paths — `note_unconnecting_headers`-exceeded,
   `max_headers_per_peer`-exceeded, generic header-validation
   error — all log "disconnecting" / "dropping" but actually just
   set `sync_state <- Idle`. The peer remains connected and
   continues to participate. Fleet-pattern "log-claims-action-not-taken".
