# W134 BIP-37 Bloom Filter (legacy SPV) — camlcoin (OCaml)

Wave: W134 — BIP-37 Bloom Filter (legacy SPV).
Scope: `CBloomFilter` construction / `MurmurHash3` schedule / `insert` /
`contains` / `IsRelevantAndUpdate` / `IsWithinSizeConstraints` /
`CRollingBloomFilter`, the `filterload` / `filteradd` / `filterclear`
P2P handlers, `MSG_FILTERED_BLOCK` getdata responses (`CMerkleBlock` =
`CBlockHeader` + `CPartialMerkleTree`), `NODE_BLOOM` advertisement
gate, `peerbloomfilters` operator flag, and the BIP-111 disconnect
semantics for sending filter messages to a non-NODE_BLOOM peer.

Bitcoin Core references:
- `bitcoin-core/src/common/bloom.{h,cpp}` — `CBloomFilter` + `CRollingBloomFilter`
- `bitcoin-core/src/merkleblock.{h,cpp}` — `CPartialMerkleTree` +
  `CMerkleBlock`, plus the helpers `BitsToBytes` / `BytesToBits`
- `bitcoin-core/src/net_processing.cpp:4963-5033` — `FILTERLOAD` /
  `FILTERADD` / `FILTERCLEAR` handlers, plus the `MSG_FILTERED_BLOCK`
  branch of `ProcessGetBlockData` (`net_processing.cpp:2438-2458`)
- `bitcoin-core/src/net_processing.cpp:3676-3691` — `SetTxRelay()`
  decision at VERSION handshake (the `fRelay || (peer.m_our_services &
  NODE_BLOOM)` condition that gates whether a `TxRelay` struct is
  attached at all)
- `bitcoin-core/src/net_processing.h:44` — `DEFAULT_PEERBLOOMFILTERS =
  false`
- `bitcoin-core/src/init.cpp:572,1104-1105` — `-peerbloomfilters` arg
  and the `g_local_services |= NODE_BLOOM` flip
- `bitcoin-core/src/hash.cpp` — `MurmurHash3()` (x86_32) reference impl

BIPs:
- BIP-37 (Connection Bloom filtering — filterload / filteradd /
  filterclear / merkleblock semantics, BLOOM_UPDATE_* enum, the
  IsRelevantAndUpdate auto-add behaviour, MAX_BLOOM_FILTER_SIZE /
  MAX_HASH_FUNCS protocol limits)
- BIP-111 (NODE_BLOOM service bit + mandatory disconnect for filter
  messages on non-NODE_BLOOM peers)

Methodology: read Core refs, synthesize a 30-gate audit matrix,
classify against camlcoin's de-facto BIP-37 surface
(`lib/bloom.ml`, `lib/peer.ml`, `lib/peer_manager.ml`, `lib/sync.ml`,
`lib/p2p.ml`, `lib/rpc.ml`). Catalogue BUGs by severity:
- **P0-CDIV**: protocol divergence that produces observably wrong
  responses to a BIP-37 SPV client (broken filter, wrong wire format,
  no merkleblock served) or to a peer behaving correctly under BIP-111
- **P1**: BIP-37 / BIP-111 surface absent or mis-wired but the
  divergence is narrower (e.g. missing operator gate, missing
  CRollingBloomFilter)
- **P2**: hygiene / performance / dead code
- **P3**: surface / doc / naming drift

Prior work on the same code path:
- W110 (this same module, earlier wave) added `lib/bloom.ml` from
  scratch with G1–G24 covered, including MurmurHash3, sizing
  constructor, `IsRelevantAndUpdate`, outpoint serialization,
  P2PK/multisig detection, and `IsWithinSizeConstraints`.
  W110 closed BUG-1/2/3/4/5/6/7 from its own catalogue (filterload /
  filteradd / filterclear / merkleblock wire format / DoS disconnect /
  bloom module entirely).
- W117 (BIP-155 networks), W118 (wallet), and W121 (BIP-157 compact
  filters) overlap on `peer.ml` / `peer_manager.ml` but do not touch
  the BIP-37 dispatch arms or the `bloom_filter` field on `Peer.peer`.
- W134 audits the **structural gaps still present** after W110: the
  `MSG_FILTERED_BLOCK` getdata branch, the broken empty-filter
  construction in `FilterAddMsg`, the missing relay-on-filterload
  flip, the absent `CRollingBloomFilter`, the missing per-peer
  TxRelay struct gate, plus several spec-correctness drifts in the
  W110 bloom.ml.

## Architectural baseline (what camlcoin has and what it doesn't)

camlcoin's de-facto BIP-37 surface:

  - `lib/bloom.ml` — `Bloom.t` record (`vdata` / `n_hash_funcs` /
    `n_tweak` / `n_flags`), `Bloom.create`, `Bloom.murmurhash3`,
    `Bloom.bloom_hash`, `Bloom.insert`, `Bloom.contains`,
    `Bloom.is_full` / `Bloom.is_empty` (Core-removed),
    `Bloom.is_within_size_constraints`, `Bloom.insert_outpoint` /
    `Bloom.contains_outpoint`, `Bloom.iter_pushdata`, `Bloom.is_p2pk` /
    `Bloom.is_multisig`, `Bloom.is_relevant_and_update`,
    `Bloom.serialize` / `Bloom.deserialize` (`filterload` wire codec).
    No `CRollingBloomFilter` analogue at all.
  - `lib/peer.ml` — `peer_services.bloom = NODE_BLOOM`,
    `peer_bloom_filters : bool ref` (operator gate, default false),
    `set_peer_bloom_filters`, `our_services ()` ORs in
    `NODE_BLOOM` when the operator gate is on, `peer.bloom_filter :
    Bloom.t option` (per-peer state initialised to None).
  - `lib/peer_manager.ml:1830-1894` — `FilterLoadMsg` / `FilterAddMsg`
    / `FilterClearMsg` dispatch arms with BIP-111 disconnect on
    non-NODE_BLOOM; `announce_tx` (`peer_manager.ml:1379-1402`)
    applies `Bloom.is_relevant_and_update` before queueing an
    `InvTx` / `InvWtx`.
  - `lib/sync.ml:4628` — `MEMPOOL` handler gates on
    `(Peer.our_services ()).bloom` (BIP-111 §3 mempool gate).
  - `lib/p2p.ml` — `FilterLoadMsg` / `FilterAddMsg` / `FilterClearMsg`
    / `MerkleBlockMsg` variants in `message_payload`,
    `command_of_string` covers all four commands, wire (de)serializer
    for all four. `InvFilteredBlock` (type 3) in the `inv_type`
    enum.
  - `lib/rpc.ml:7568-7715` — `w47b_build_partial_merkle_tree` /
    `w47b_parse_partial_merkle_tree` (CalcTreeWidth, TraverseAndBuild,
    TraverseAndExtract) — but used only for the `gettxoutproof` /
    `verifytxoutproof` RPCs, **not** wired to a P2P `MerkleBlockMsg`
    send path.

camlcoin **lacks** Core's `CRollingBloomFilter` entirely; no rotating
generations, no auto-reset of `nTweak`, no `FastRange32` indexing.
This is consequential because Core uses `CRollingBloomFilter` for
several BIP-37-adjacent rate-limit / dedup paths (the per-tx-relay
`m_recently_announced_invs` is a rolling bloom, as is
`g_recent_rejects` for inv dedup). camlcoin substitutes a hashtable
in `Peer.tx_inventory_known` (per-peer) and a hashtable in
`peer_manager.tx_recently_rejected`, neither of which expires entries
on a rotating-generation schedule. That gap is BIP-37-adjacent
rather than BIP-37 per se, and we capture it as a P2 finding only.

camlcoin **lacks** Core's `Peer::TxRelay` struct as a separately
attached optional structure. Core only allocates `TxRelay` at VERSION
handshake when `fRelay || (peer.m_our_services & NODE_BLOOM)`; on a
block-relay-only or feeler connection (where neither holds), the
peer literally has no `TxRelay` and any incoming `filterload` /
`filteradd` / `filterclear` / `mempool` returns early because
`GetTxRelay()` is nullptr. camlcoin always allocates a
`bloom_filter : Bloom.t option = None` field on every peer, which
means a block-relay-only camlcoin peer that receives `filterload`
will happily store the filter (after passing the NODE_BLOOM gate),
even though it should not relay txs to that peer at all. This is a
subtle BIP-37 divergence and is captured in BUG-9.

## Findings summary

**11 BUGs catalogued.** Severity distribution:
- **P0-CDIV**: 3 (BUG-1 / BUG-2 / BUG-3)
- **P1**: 4 (BUG-4 / BUG-5 / BUG-6 / BUG-7)
- **P2**: 3 (BUG-8 / BUG-9 / BUG-10)
- **P3**: 1 (BUG-11)

### BUG-1 (P0-CDIV) — `FilterAddMsg` creates a broken zero-size filter when no prior filterload

Location: `lib/peer_manager.ml:1870-1878`.

```
(* No filter loaded yet; insert acts like filterload with empty filter.
   Core does not require filterload first; we mirror that behaviour. *)
let f = { Bloom.vdata = Bytes.create 0;
          n_hash_funcs = 0; n_tweak = 0;
          n_flags = Bloom.bloom_update_none } in
Bloom.insert f data;
peer.Peer.bloom_filter <- Some f
```

This is wrong in **three** ways. First, the inline comment "Core does
not require filterload first; we mirror that behaviour" is
**factually false**: Core requires a prior `filterload` and on
filteradd without filter `Misbehaving(peer, "bad filteradd message")`
is invoked (`net_processing.cpp:5002-5008`):

```
} else if (auto tx_relay = peer.GetTxRelay(); tx_relay != nullptr) {
    LOCK(tx_relay->m_bloom_filter_mutex);
    if (tx_relay->m_bloom_filter) {
        tx_relay->m_bloom_filter->insert(vData);
    } else {
        bad = true;     // <-- no prior filterload = misbehavior
    }
}
if (bad) {
    Misbehaving(peer, "bad filteradd message");
}
```

Second, `Bloom.insert` short-circuits on zero-vdata (CVE-2013-5700
guard at `bloom.ml:140`), so the stored "filter" is a degenerate
record with `vdata = ""`, `n_hash_funcs = 0`, `n_tweak = 0`. Any
subsequent `contains` call against this filter returns `true` for
every input (CVE-2013-5700 path: empty vData ⇒ match-all). Effect:
**a malicious or buggy peer can force the relay path into
"match-all" mode**, which a) defeats the whole point of bloom
filtering (the peer receives every transaction we know about) and
b) opens a DoS surface because a single 1-byte filteradd silently
disables filtering for that peer indefinitely.

Third, even if the empty-filter path were intended, the comment
documents a behaviour that contradicts the code: the code does NOT
mirror Core, it diverges from Core.

This is a "test-comment-as-confession" pattern (META-PATTERN from
W122): the inline rationalization in the comment is factually
wrong, and the code's actual behaviour produces a
protocol-divergent, DoS-relevant outcome. Severity: P0-CDIV.

Fix: replace the no-filter arm with `misbehaving peer 100 "filteradd
without prior filterload"` (Core uses score 100 = disconnect; see
`net_processing.h`'s `DISCOURAGEMENT_THRESHOLD`) and `remove_peer`.

### BUG-2 (P0-CDIV) — `MSG_FILTERED_BLOCK` getdata branch absent in `handle_getdata`

Location: `lib/peer.ml:1454-1528` (`handle_getdata`).

The `getdata` dispatcher matches only `InvBlock` / `InvWitnessBlock` /
`InvTx` / `InvWtx` / `InvWitnessTx` / `InvCompactBlock`. Every other
inv-type (including `InvFilteredBlock = 3`, which IS defined in
`p2p.ml:174`) falls through to the wildcard `_ -> not_found := iv ::
!not_found` branch, sending a `notfound` reply.

Core's behaviour at `net_processing.cpp:2438-2458` is:

```
} else if (inv.IsMsgFilteredBlk()) {
    bool sendMerkleBlock = false;
    CMerkleBlock merkleBlock;
    if (auto tx_relay = peer.GetTxRelay(); tx_relay != nullptr) {
        LOCK(tx_relay->m_bloom_filter_mutex);
        if (tx_relay->m_bloom_filter) {
            sendMerkleBlock = true;
            merkleBlock = CMerkleBlock(*pblock, *tx_relay->m_bloom_filter);
        }
    }
    if (sendMerkleBlock) {
        MakeAndPushMessage(pfrom, NetMsgType::MERKLEBLOCK, merkleBlock);
        for (const auto& [tx_idx, _] : merkleBlock.vMatchedTxn)
            MakeAndPushMessage(pfrom, NetMsgType::TX, TX_NO_WITNESS(*pblock->vtx[tx_idx]));
    }
}
```

Effect: a BIP-37 SPV client connecting to camlcoin and requesting
`MSG_FILTERED_BLOCK` for an unconfirmed-block walk receives a
**`notfound` reply instead of the merkleblock**, breaking the SPV
walk completely. The hostname/port advertises NODE_BLOOM, the peer
loads a filter, then every subsequent filtered-block request fails
silently. camlcoin would be unable to serve BIP-37 SPV clients
end-to-end.

Note: the partial-merkle-tree construction is available in
`rpc.ml:7619-7651` (`w47b_build_partial_merkle_tree`), so this is a
wiring gap, not a missing algorithm. The fix is to add a
`InvFilteredBlock` arm to `handle_getdata` that calls a new
`Merkleblock.build_for_filter` helper (or moves
`w47b_build_partial_merkle_tree` to a shared module), constructs a
`MerkleBlockMsg`, and follows up with `TxMsg` for each matched
transaction (the "client did not see" follow-up at
`net_processing.cpp:2456`). Severity: P0-CDIV.

### BUG-3 (P0-CDIV) — `relay` field is not flipped on filterload / filterclear

Location: `lib/peer.ml:265` (the `relay` field), `lib/peer_manager.ml:1837-1862`
(no flip), `lib/peer_manager.ml:1883-1894` (no flip).

Core's filterload handler unconditionally sets
`tx_relay->m_relay_txs = true` AND `pfrom.m_relays_txs = true`
(`net_processing.cpp:4980-4983`):

```
{
    LOCK(tx_relay->m_bloom_filter_mutex);
    tx_relay->m_bloom_filter.reset(new CBloomFilter(filter));
    tx_relay->m_relay_txs = true;
}
pfrom.m_bloom_filter_loaded = true;
pfrom.m_relays_txs = true;
```

Core's filterclear handler ALSO sets `tx_relay->m_relay_txs = true`
(`net_processing.cpp:5028`):

```
{
    LOCK(tx_relay->m_bloom_filter_mutex);
    tx_relay->m_bloom_filter = nullptr;
    tx_relay->m_relay_txs = true;
}
pfrom.m_bloom_filter_loaded = false;
pfrom.m_relays_txs = true;
```

The intent is: a peer that explicitly opts in by sending filterload
(or opts out of filtering by sending filterclear) has expressed
willingness to receive tx relay, and Core flips the relay flag on
to reflect that — even if the peer initially set `fRelay=false` in
its VERSION message. This is BIP-37 §"Operation" semantics.

camlcoin's `Peer.peer.relay` is populated from `v.relay` at
`process_version_msg` (`peer.ml:743`) and never updated thereafter.
A peer that started with `relay=false`, then sends `filterload`, ends
up in a contradictory state: from Core's perspective the peer
should now receive filtered tx relay; from camlcoin's perspective
the `peer.relay = false` snapshot still wins and `announce_tx`
might short-circuit on it elsewhere. The narrow effect today is
limited because camlcoin's `announce_tx` does not actually consult
`peer.relay` (it only checks `peer.bloom_filter`), but the
divergence is real and any future code that DOES gate on
`peer.relay` would behave wrong. Severity: P0-CDIV (latent, but a
specification-level divergence).

Fix: in the `FilterLoadMsg` and `FilterClearMsg` arms, after the
NODE_BLOOM gate passes and before storing/clearing the filter,
`peer.Peer.relay <- true`.

### BUG-4 (P1) — `CBloomFilter::IsRelevantAndUpdate` scans inputs even when filter found an output (Core scans all outputs THEN gates on found before scanning inputs, but ALWAYS scans all outputs first)

Location: `lib/bloom.ml:307-363` (`is_relevant_and_update`).

Re-read of Core (`bloom.cpp:95-161`) reveals the contract is:

1. If filter contains the txid → `fFound = true` (line 102-104).
2. **For each output, iterate all script pushdata elements**:
   - If filter contains the element → `fFound = true` and per-flag
     outpoint insert; **then `break` to next output**.
3. After outputs: if `fFound`, return true.
4. **Only if NOT fFound, scan inputs** (line 141).
5. For each input, check prevout match → return true on match.
6. For each input, scan scriptSig pushdata elements → return true on
   match.

camlcoin's implementation matches steps 1-3 and 5-6 but uses
`List.iteri` over outputs and never short-circuits inside an output's
pushdata iteration once a match is found. Core uses `break` after a
match-and-insert inside one output's pushdata loop (`bloom.cpp:133`):

```
if (data.size() != 0 && contains(data))
{
    fFound = true;
    if ((nFlags & BLOOM_UPDATE_MASK) == BLOOM_UPDATE_ALL)
        insert(COutPoint(hash, i));
    else if ((nFlags & BLOOM_UPDATE_MASK) == BLOOM_UPDATE_P2PUBKEY_ONLY)
    {
        ...
    }
    break;     // <-- after matching one push, stop scanning this output's pushes
}
```

camlcoin's `iter_pushdata script (fun data -> if contains filter
data then ...)` does NOT `break`. It runs to the end of the script.
This means a single output that contains multiple pushdata items, any
of which match the filter, will produce **multiple `insert_outpoint`
calls for the same `(hash, i)` outpoint** instead of one. That is a
performance bug, but it ALSO subtly affects the
`UPDATE_P2PUBKEY_ONLY` decision: if the first matching push is a
non-pubkey data element and the second is the pubkey, the
"break-after-first-match" semantic in Core would mean we test the
script type once on the first match; camlcoin retests every match,
which can lead to extra useless `is_p2pk`/`is_multisig` calls (no
correctness difference, since the type doesn't change between
pushes — but the outpoint may be inserted multiple times, polluting
the filter with the same bit-pattern multiple times).

This is consequential because `Bloom.insert` is idempotent on the
final filter state (re-setting the same bits is a no-op) BUT each
call advances internal counters. The narrow correctness divergence
is that **a non-matching subsequent output's pushdata** can still
short-circuit if we set `found = true` and exit the `iter_pushdata`
prematurely in Core; camlcoin's behaviour is also wrong in the
opposite direction: it continues scanning subsequent pushes WITHIN
the same output even after a match. Severity: P1 (correctness drift
on the per-output break semantics; observable false-positive
inflation when multiple pushdata items in a single output match).

Fix: refactor `iter_pushdata` to allow early termination (return
`bool` or take a continuation with abort), and `break` after the
first matching push in the same output.

### BUG-5 (P1) — `CRollingBloomFilter` entirely absent

Location: `lib/bloom.ml` (no analogue).

`bloom.h:108-125` defines `CRollingBloomFilter` with a generation-based
rotation scheme:

```
class CRollingBloomFilter
{
public:
    CRollingBloomFilter(unsigned int nElements, double nFPRate);
    void insert(std::span<const unsigned char> vKey);
    bool contains(std::span<const unsigned char> vKey) const;
    void reset();
...
};
```

This is used by net_processing for several per-peer rate-limit /
dedup paths:
- `Peer::TxRelay::m_recently_announced_invs` (a `CRollingBloomFilter`
  to dedup recently-announced inv hashes per peer)
- `g_recent_rejects` (a `CRollingBloomFilter` for inv dedup across
  recently-rejected txs)
- `g_recent_confirmed_transactions` (a `CRollingBloomFilter` for
  confirmed-tx inv dedup)

camlcoin substitutes a plain hashtable in
`Peer.peer.tx_inventory_known` and similar fields, which has no
generation-based expiry — entries live forever until the peer
disconnects. That is a memory/perf footgun and a subtle behavioural
divergence (Core's rolling-bloom forgets entries after ~N
insertions, so the dedup is "approximate" and self-resetting;
camlcoin's hashtable is exact but unbounded). Severity: P1.

Fix: implement `CRollingBloomFilter` in `bloom.ml` with the same
generation-rotation semantics, and wire it into the dedup paths in
`peer_manager.ml` and `peer.ml`.

### BUG-6 (P1) — `Bloom.create` clamps `n_elements` to ≥1, diverging from Core's no-clamp behaviour

Location: `lib/bloom.ml:114`:

```
let n_elements = max 1 n_elements in  (* guard divide-by-zero *)
```

Core's `CBloomFilter` constructor at `bloom.cpp:26-42` does NOT
clamp `nElements`. With `nElements = 0`:
- `vData = std::min((unsigned int)(-1/LN2SQUARED * 0 * log(fpRate)),
  MAX_BLOOM_FILTER_SIZE * 8) / 8 = 0`
- `nHashFuncs = std::min((unsigned int)(0 * 8 / 0 * LN2),
  MAX_HASH_FUNCS) = undefined behaviour (div by zero in 0 / 0)`

So Core has its own UB on `nElements = 0`. But camlcoin's clamp
changes the behaviour from "UB / weird filter" to "1-element
filter", which means if some caller passes `nElements = 0` deliberately
(e.g. as a sentinel for "empty / placeholder filter"), camlcoin
allocates an N-bit array where Core would build a zero-size filter
(which then triggers the CVE-2013-5700 match-all guard).

This is a subtle behavioural divergence on the `nElements = 0` edge
case. Severity: P1 (narrow but real). Fix: remove the `max 1`
clamp; on `nElements = 0`, follow Core: vdata = `""`, nHashFuncs =
0, and let the CVE-2013-5700 guard at `insert` / `contains` /
`is_relevant_and_update` do its job.

### BUG-7 (P1) — `Bloom.create` rounds float→int with `int_of_float` (truncates toward zero), but Core's `(unsigned int)` cast on negative double is UB and on positive double truncates toward zero — these *coincide* for the well-formed input range but differ on out-of-range inputs

Location: `lib/bloom.ml:115-122`.

Core's cast: `(unsigned int)(-1/LN2SQUARED * nElements * log(fpRate))`.
For `fpRate < 1`, `log(fpRate) < 0`, so the value inside the parens
is positive; cast to `unsigned int` truncates toward zero. OK.

For `fpRate ≥ 1`, `log(fpRate) ≥ 0`, so the inside-parens value is
≤ 0; cast of a negative double to `unsigned int` is implementation-
defined in C++ (UB-adjacent in C, modular in C++20). Most compilers
produce a "wraparound" result that yields a huge `unsigned int`
which then clamps via `std::min` to `MAX_BLOOM_FILTER_SIZE * 8`.

OCaml's `int_of_float` for a negative double rounds toward zero
(`-0.5` → 0, `-1.5` → -1) and the result is a signed OCaml int. The
subsequent `min raw (max_bloom_filter_size * 8)` returns the
negative value (since it's smaller than the positive bound),
producing a negative `size_bits`, which then divides to a negative
`size_bytes`, and `Bytes.make size_bytes ...` raises `Invalid_argument`.

So for `fpRate ≥ 1`, **Core silently produces a maximally-sized
filter, but camlcoin raises an exception** that propagates out of
the filterload handler in `peer_manager.ml`, which has no `try`
around `Bloom.deserialize`'s call — meaning a maliciously-crafted
filterload with `fpRate ≥ 1` could crash the peer message loop.

In practice, `fpRate` is not sent on the wire (the wire format
serializes the resulting `vData` / `nHashFuncs` / `nTweak` / `nFlags`
post-construction, not the input `nElements` / `nFPRate`), so this
is a constructor-side issue only, exploitable from inside the
node's own code that calls `Bloom.create` with operator/runtime-
controlled `fpRate`. Severity: P1.

Fix: clamp `raw` to `[0, MAX * 8]` before subtracting/dividing.

### BUG-8 (P2) — `Bloom.is_full` / `Bloom.is_empty` are dead code (Core removed these in PR #9054)

Location: `lib/bloom.ml:166-179`.

```
let is_full (filter : t) : bool = ...
let is_empty (filter : t) : bool = ...
```

Core removed `IsFull` / `IsEmpty` from `CBloomFilter` in PR #9054
(merged 2017). They were used in an optimization path that
short-circuited `IsRelevantAndUpdate` on a fully-empty or fully-full
filter; that optimization was removed when the per-tx-relay tracking
was redesigned. camlcoin still carries these dead helpers (G10 in
the W110 audit framing), and the bloom.ml comment block at the top
still lists them as part of the audit matrix.

Severity: P2 (dead code; no correctness issue, but the audit-frame
implies they're spec-mandated when they're not). Fix: delete them,
or tag with a clear "Core-removed; camlcoin keeps for sentinel test
shape" comment.

### BUG-9 (P2) — No `TxRelay`-struct gate on filterload (camlcoin stores filter even on block-relay-only peer)

Location: `lib/peer_manager.ml:1837-1862`.

Core only allocates the `Peer::TxRelay` struct on connections where
either `fRelay=true` OR `peer.m_our_services & NODE_BLOOM`
(`net_processing.cpp:3682-3691`):

```
if (!pfrom.IsBlockOnlyConn() &&
    !pfrom.IsFeelerConn() &&
    (fRelay || (peer.m_our_services & NODE_BLOOM))) {
    auto* const tx_relay = peer.SetTxRelay();
    ...
}
```

When `TxRelay` is not allocated (block-relay-only or feeler), a
later `filterload` enters the handler, but `peer.GetTxRelay()` is
nullptr and the handler is a no-op (it does not return-early
explicitly but the `tx_relay != nullptr` guard at line 4976 skips
the filter store).

camlcoin always allocates `bloom_filter : Bloom.t option = None` on
every peer (`peer.ml:424`). On a block-relay-only camlcoin peer (no
`block_relay_only=true` gate in the FilterLoadMsg arm), the filter
IS stored, the NODE_BLOOM advertisement gate passes, and the peer
ends up with a working filter that the announce_tx code then
consults — even though the peer should be receiving NO transaction
relay at all on a block-relay-only connection. Severity: P2
(narrow; block-relay-only inbound connections that send filterload
are unusual, but the divergence is real).

Fix: in the FilterLoadMsg arm, also gate on `not
peer.Peer.block_relay_only` and on `peer.Peer.relay = true ||
(Peer.our_services ()).bloom` (mirror Core's
`fRelay || (m_our_services & NODE_BLOOM)` post-handshake check).

### BUG-10 (P2) — `is_relevant_and_update` does not handle the wtxid-vs-txid distinction (BIP-339)

Location: `lib/bloom.ml:307` (the function signature accepts `txid_bytes
: bytes` and uses it for both the contains() check and the inserted
outpoint).

BIP-37 predates BIP-339 (wtxid relay), and Core's
`IsRelevantAndUpdate` uses `tx.GetHash()` (= the txid, not wtxid):
`bloom.cpp:102-104`:

```
const Txid& hash = tx.GetHash();
if (contains(hash.ToUint256()))
    fFound = true;
```

camlcoin's wrapper `peer_manager.ml:1389-1390` passes `txid_bytes =
Cstruct.to_bytes txid`, which is the right value. But the caller
context is `announce_tx`, which receives both `~txid` and `~wtxid`
as parameters. There is no per-output check whether the filter was
loaded with wtxid-relay-aware semantics (BIP-339 does not change
BIP-37 filter semantics — filters are still on txid — but the call
site should document this and the function signature should accept
a `Types.txid` newtype, not a generic `bytes`, to make the txid-not-
wtxid invariant explicit).

Severity: P2 (no correctness issue; surface clarity / type safety
only). Fix: rename the parameter `txid_bytes` and add a comment that
BIP-37 always uses txid even when the announcing peer is wtxid-relay.

### BUG-11 (P3) — W110 audit-matrix comments in `bloom.ml` reference gates by W110 numbering, drift risk

Location: `lib/bloom.ml:1-65` and inline `G1` / `G2` / ... markers.

The bloom module's prologue and inline comments tag each constant /
function with the W110 audit gate number (G1 through G24 etc.).
W134 re-audits the same module with a different gate decomposition
(this document), so the W110 gate labels in the source are now
historical. This is harmless but the inline `G3`, `G4`, ... markers
can mislead a future reader into thinking the W134 audit and the
W110 audit share gate numbering. Severity: P3 (cosmetic). Fix: add a
top-of-file comment that gate numbers refer to W110 only, and that
the W134 audit numbering lives in `audit/w134_bip37_bloom_filter.md`.

## 30-gate matrix

The 30-gate decomposition for W134 is:

| Gate | Topic | Verdict |
|------|-------|---------|
| G1  | `MAX_BLOOM_FILTER_SIZE = 36000` (bytes) | PASS |
| G2  | `MAX_HASH_FUNCS = 50` | PASS |
| G3  | `LN2SQUARED` full-precision constant | PASS |
| G4  | `BLOOM_UPDATE_NONE = 0` | PASS |
| G5  | `BLOOM_UPDATE_ALL = 1` | PASS |
| G6  | `BLOOM_UPDATE_P2PUBKEY_ONLY = 2` | PASS |
| G7  | `BLOOM_UPDATE_MASK = 3` | PASS |
| G8  | `nFlags & BLOOM_UPDATE_MASK` masking on insert decision | PASS |
| G9  | MurmurHash3 (x86_32) byte-exact against Core hash_tests.cpp vectors | PASS |
| G10 | Hash schedule `nHashNum * 0xFBA4C795 + nTweak` | PASS |
| G11 | Bit index = `MurmurHash3(...) % (vData.size() * 8)` | PASS |
| G12 | Constructor sizing: `min(-1/LN2² × N × log(fp), MAX×8) / 8` | PASS |
| G13 | Constructor `nHashFuncs = min(vData×8/N × LN2, MAX_HASH_FUNCS)` | PASS |
| G14 | CVE-2013-5700 empty-vData guard in insert/contains | PASS |
| G15 | `IsWithinSizeConstraints` (≤36000 bytes AND ≤50 hash funcs) | PASS |
| G16 | `IsRelevantAndUpdate`: txid match → fFound | PASS |
| G17 | `IsRelevantAndUpdate`: per-output scriptPubKey pushdata scan | PASS |
| G18 | `IsRelevantAndUpdate`: break after first matching push in same output | **BUG-4 (P1)** |
| G19 | `IsRelevantAndUpdate`: `UPDATE_ALL` → insert outpoint on match | PASS |
| G20 | `IsRelevantAndUpdate`: `UPDATE_P2PUBKEY_ONLY` → only for P2PK/multisig | PASS |
| G21 | `IsRelevantAndUpdate`: scan inputs ONLY if fFound = false after outputs | PASS |
| G22 | `IsRelevantAndUpdate`: per-input prevout match → return true | PASS |
| G23 | `IsRelevantAndUpdate`: per-input scriptSig pushdata scan | PASS |
| G24 | Outpoint wire serialization: txid (32 LE) ‖ vout (4 LE) | PASS |
| G25 | `filterload` wire deserialization (vData / nHashFuncs / nTweak / nFlags) | PASS |
| G26 | `filteradd` ≤ 520-byte (MAX_SCRIPT_ELEMENT_SIZE) wire guard | PASS |
| G27 | `filteradd` requires prior `filterload`; misbehavior on bare filteradd | **BUG-1 (P0-CDIV)** |
| G28 | `filterload` / `filteradd` / `filterclear` flip `relay = true` | **BUG-3 (P0-CDIV)** |
| G29 | `MSG_FILTERED_BLOCK` getdata → emit `merkleblock` + matched txs | **BUG-2 (P0-CDIV)** |
| G30 | `CRollingBloomFilter` (generation-rotation + FastRange32 indexing) | **BUG-5 (P1)** |

Additional bugs outside the 30-gate matrix but inside W134 scope:
BUG-6 (constructor clamp), BUG-7 (negative-float crash), BUG-8
(dead is_full/is_empty), BUG-9 (TxRelay-struct gate), BUG-10
(wtxid type clarity), BUG-11 (gate-numbering drift).

## Universal patterns / META-PATTERNS observed

1. **"test-comment-as-confession"** (META-PATTERN from W122) — BUG-1's
   inline comment `"Core does not require filterload first; we mirror
   that behaviour"` is factually wrong (Core does misbehavior-disconnect
   on bare filteradd, `net_processing.cpp:5002-5008`). The comment
   rationalizes a degenerate-filter outcome that opens a DoS-relevant
   "match-all" path. Add to the project META-PATTERN list as a
   recurrence (W122 saw it in blockbrew TestBIP158Vectors; W134 sees
   it in camlcoin peer_manager.ml). Fleet sweep target: grep every
   impl for inline comments asserting "matches Core" near non-Core
   code.

2. **"helper-exists-but-not-wired"** — BUG-2 is the classic
   helper-exists shape (W120 dead-helper pattern). camlcoin has a
   complete partial-merkle-tree builder
   (`rpc.ml:7619-7651`) used by gettxoutproof RPC, but the same
   helper is not wired to the `MSG_FILTERED_BLOCK` P2P path. The
   audit framework reliably surfaces "helper exists" + cross-references
   "is it called in this context" → same finding shape as W120
   nimrod validateRbfDiagram, FIX-79 ouroboros cfheaders defensive,
   FIX-81 lunarblock BIP-157 dispatch.

3. **"setter-never-flipped on protocol event"** — BUG-3 mirrors the
   FIX-79/FIX-81 pattern of "Core flips a flag on a protocol event;
   implementation never flips it". Core flips `m_relay_txs = true`
   on filterload / filterclear; camlcoin does not flip
   `peer.relay`. Same shape as FIX-71's "BIP-157 gate plumbed but
   never flipped TRUE" cross-wave activation: the gate exists, but
   the protocol event that should flip it is not wired.

4. **"Core-deleted-but-still-here"** — BUG-8 (`is_full` / `is_empty`)
   represents code that was removed from Core but persists in
   camlcoin because the W110 audit gates included G10 = "isFull /
   isEmpty short-circuit". W134 corrects the audit framing: these
   helpers are no longer canonical and the audit gate G10 from W110
   is **architecturally stale**.

## What this audit does NOT cover

- The BIP-157 compact-filter side is **out of scope** (W121 / W122
  covered that).
- The BIP-37 client side (we receive `merkleblock` from a remote node
  and verify it against our chain) is out of scope; camlcoin's
  `MerkleBlockMsg` is currently a wire format only with no consumer
  besides the dispatch arm that drops it.
- BIP-37 fee-filter interactions are partially covered (the
  `passes_feefilter` check in `peer.ml:1764` runs alongside the
  bloom filter check), but the interaction between filter-match and
  feefilter-threshold is not separately audited.
- The legacy DoS-disconnect threshold (Core's discouragement
  threshold = 100; camlcoin's `misbehaving` score system uses
  similar semantics) is assumed to be calibrated and is not
  separately verified here.
