# W132: BIP-68 / BIP-112 / BIP-113 nSequence + OP_CSV + MTP (camlcoin)

**Wave**: W132 (DISCOVERY)
**Impl**: camlcoin (OCaml)
**Date**: 2026-05-17
**Status**: DISCOVERY — **11 BUGS / 30 GATES** (3 P0-CONSENSUS / 2 P1 / 4 P2 / 2 P3)
**Tests added**: `test/test_w132_nsequence_csv_mtp.ml` (30 audit-status tests)
**Code under audit**:
- `lib/script.ml` lines 119-120 (script flag constants), 2306-2365 (OP_CHECKSEQUENCEVERIFY interpreter)
- `lib/consensus.ml` lines 814-819 (`median_time_past` from list), 860-898 (script-flag gating per height), 1339 (`median_time_past` block-index field for BIP-9)
- `lib/validation.ml` lines 763-799 (`is_tx_final` BIP-113 helper), 1000-1057 (`check_sequence_locks` BIP-68 helper), 1478-1498 (CSV-aware locktime flag plumbing), 1567-1577 (`locktime_cutoff_fast`), 1700-1717 (assumevalid path SeqLocks plumbing), 1942-1956 (full-path SeqLocks plumbing)
- `lib/sync.ml` lines 2065-2091 (`compute_median_time_past` / `compute_median_time_for_display`), 2150-2153 (`get_mtp_for_height` helper)
- `lib/mempool.ml` lines 2113, 2125-2131 (mempool BIP-68 entry without per-coin MTP callback)
- `lib/assume_utxo.ml` lines 1156-1196 (assumeutxo background validator hard-coding `median_time = 0l`)
- `lib/miniscript.ml` lines 124-127 (BIP-68 / BIP-65 constants for miniscript synthesis)

**Reference**:
- `bitcoin-core/src/consensus/tx_verify.cpp` lines 17-37 (`IsFinalTx`), 39-95 (`CalculateSequenceLocks`), 97-110 (`EvaluateSequenceLocks` / `SequenceLocks`)
- `bitcoin-core/src/script/interpreter.cpp` lines 561-593 (OP_CHECKSEQUENCEVERIFY dispatch), 1782-1826 (`CheckSequence`), 1755-1779 (`CheckLockTime` SEQUENCE_FINAL check)
- `bitcoin-core/src/chain.h` lines 231-245 (`GetMedianTimePast`, `nMedianTimeSpan = 11`)
- `bitcoin-core/src/validation.cpp` lines 147-167 (`CheckFinalTxAtTip`), 200-244 (`CalculateLockPointsAtTip`), 246-272 (`CheckSequenceLocksAtTip`), 2478-2482 (`nLockTimeFlags` from `DEPLOYMENT_CSV`), 4080-4149 (`ContextualCheckBlockHeader` / `ContextualCheckBlock`)
- `bitcoin-core/src/policy/policy.h` line 138 (`STANDARD_LOCKTIME_VERIFY_FLAGS`)
- `bitcoin-core/src/consensus/consensus.h` line 28 (`LOCKTIME_VERIFY_SEQUENCE`)
- `bitcoin-core/src/primitives/transaction.h` lines 74-104 (`CTxIn::SEQUENCE_FINAL`, `MAX_SEQUENCE_NONFINAL`, `SEQUENCE_LOCKTIME_DISABLE_FLAG`, `SEQUENCE_LOCKTIME_TYPE_FLAG`, `SEQUENCE_LOCKTIME_MASK`, `SEQUENCE_LOCKTIME_GRANULARITY`)
- BIP-68, BIP-112, BIP-113

**Severity legend**:
- **P0-CONSENSUS**: directly-observable block-validation divergence vs. Core
- **P0-CDIV**: consensus-relevant policy / mempool divergence (block-relay impact)
- **P1**: correctness gap visible at the RPC / mempool surface
- **P2**: structural / robustness gap (no clear divergence today)
- **P3**: documentation / convention drift

---

## Summary

camlcoin's BIP-68 / BIP-112 / BIP-113 stack is **substantially present**:
the OP_CHECKSEQUENCEVERIFY opcode is wired in `script.ml:2306-2365`,
`check_sequence_locks` is invoked from BOTH the full path and the assume-valid
fast path in `validate_block_with_utxos` (`validation.ml:1713/1953`),
`is_tx_final` is BIP-113-aware via the `lock_time_cutoff` switch at
`validation.ml:946-948/1573-1577`, and `compute_median_time_past` is plumbed
through every validation call site that has a `chain_state`.

However, the per-coin MTP lookup that BIP-68 requires (Core's
`block.GetAncestor(coin_height - 1)->GetMedianTimePast()`) has **two
independent off-by-one / wrong-source bugs** that produce real divergence:

1. **BUG-1 (P0-CONSENSUS)**: `sync.ml:2065-2075` `compute_median_time_past`
   computes the MTP **of the block at `height - 1`**, not the MTP **of the
   block at `height`**. When `get_mtp_for_height` is invoked as a BIP-68
   callback at `validation.ml:1041, 1709, 1949` with argument `utxo.height - 1`,
   it returns the MTP of the block at `utxo.height - 2` (shifted by one block
   earlier than Core's `block.GetAncestor(utxo.height - 1)->GetMedianTimePast()`).

2. **BUG-2 (P0-CDIV)**: `mempool.ml:2113, 2127-2130` passes
   `utxo_mtps.(i) <- mp.current_median_time` and DOES NOT supply
   `?get_mtp_at_height`, so `check_sequence_locks` falls back to using the
   chain-tip MTP as the per-coin MTP. With `input_mtp == median_time` and a
   non-zero time-based seq-lock offset, the check becomes "fail iff
   `median_time < median_time + offset`", which always fails for any
   `offset > 0`. **Every time-based BIP-68 mempool admission with a non-zero
   masked offset is rejected.**

3. **BUG-3 (P0-CDIV)**: `assume_utxo.ml:1158` hard-codes
   `let median_time = 0l in (* TODO: compute properly from chain *)` in the
   assumeutxo background validator. Every BIP-113 IsFinalTx call from the
   background validator runs with `nBlockTime = 0`, so any time-based
   nLockTime ≥ 1 fails IsFinalTx in the locktime branch (and any non-final
   tx with `nLockTime` in the timestamp range becomes "permanently locked"
   from the background validator's viewpoint).

The remaining BUGs are smaller (no LockPoints data structure for mempool
reorg invalidation; magic-number `9` for `SEQUENCE_LOCKTIME_GRANULARITY`;
inconsistent `max 0` guard between two BIP-68 call sites; no
`MAX_SEQUENCE_NONFINAL` constant; CSV deployment is buried-only with no
BIP-9 record; no test-coverage for the off-by-one MTP nor the mempool
MTP-source bug).

**Verdict counts**:

| Verdict      | Count |
|-------------:|------:|
| PRESENT      |    18 |
| PARTIAL      |     8 |
| **MISSING**  |   **4** |
| Total gates  |    30 |

**BUG priority counts**:

| Priority         | Count |
|-----------------:|------:|
| **P0-CONSENSUS** |   **1** |
| **P0-CDIV**      |   **2** |
| P1               |     2 |
| P2               |     4 |
| P3               |     2 |
| Total bugs       |    11 |

---

## Bug catalogue (11)

### BUG-1 (P0-CONSENSUS, gate G14, G27): `get_mtp_for_height` is **off-by-one** — it returns MTP of `(h-1)` when Core's `block.GetAncestor(h)->GetMedianTimePast()` returns MTP including block `h` itself.

- **camlcoin**: `sync.ml:2065-2075`
  ```ocaml
  let compute_median_time_past (state : chain_state) (height : int) : int32 =
    let rec collect acc h count =
      if count <= 0 || h < 0 then acc
      else match get_header_at_height state h with
        | Some entry -> collect (entry.header.timestamp :: acc) (h - 1) (count - 1)
        | None -> acc
    in
    let timestamps = collect [] (height - 1) 11 in   (* <-- height - 1, exclusive *)
    Consensus.median_time_past timestamps
  ```
  And `sync.ml:2151`:
  ```ocaml
  let get_mtp_for_height (state : chain_state) (h : int) : int32 =
    compute_median_time_past state h
  ```
  So `get_mtp_for_height (utxo_height - 1)` returns MTP of timestamps
  `[utxo_height - 2 .. utxo_height - 12]` — **11 blocks ending one before
  `utxo_height - 1`**.

- **Core**: `chain.h:231-245` `CBlockIndex::GetMedianTimePast()` starts at
  `this` (inclusive) and walks `pprev` 11 times:
  ```cpp
  const CBlockIndex* pindex = this;
  for (int i = 0; i < nMedianTimeSpan && pindex; i++, pindex = pindex->pprev)
      *(--pbegin) = pindex->GetBlockTime();
  ```
  And `tx_verify.cpp:74`:
  ```cpp
  const int64_t nCoinTime{Assert(block.GetAncestor(std::max(nCoinHeight - 1, 0)))->GetMedianTimePast()};
  ```
  → MTP of timestamps `[coin_height - 1 .. coin_height - 11]` — **11 blocks
  ending at `coin_height - 1`**.

- **Effect**: the camlcoin per-coin MTP is shifted by exactly one block toward
  the past. Time-based BIP-68 sequence locks may pass in camlcoin and fail in
  Core (or vice versa) at the boundary where the older `MTP[h-2]` block's
  timestamp differs materially from `MTP[h-1]`. Probability of an actual block
  split is low because timestamps are quasi-monotone, but the divergence is
  **directly-observable** and constructible (an attacker who controls 11
  consecutive blocks can put a large jump between `MTP[h-2]` and `MTP[h-1]`,
  then craft a time-based seq-lock tx that camlcoin accepts and Core
  rejects).

- **Note**: the **block-level** MTP feeding the timestamp / time-too-old
  / BIP-113 IsFinalTx cutoff is computed by the *same* `compute_median_time_past`
  call but with `height = current_block_being_validated`, which happens to
  equal Core's `pindexPrev->GetMedianTimePast()` (because camlcoin's
  off-by-one collects `[curr-1..curr-11]`, which is the same window). So the
  BIP-113 path is correct **only because of a compensating off-by-one in the
  caller** — the underlying primitive is wrong, and BIP-68's per-coin MTP
  call (which adds its own `coin_height - 1`) ends up at `coin_height - 2`.

- **Recommended fix**: introduce a `mtp_of_block_at state h` primitive that
  computes MTP **inclusive of block `h`** (matching `compute_median_time_for_display`
  at `sync.ml:2083-2091`, which is the correct shape), and switch
  `get_mtp_for_height` to use it. Then audit every call site of
  `compute_median_time_past` to confirm the "MTP of pindexPrev" callers
  pass `h = pindexPrev.height + 1` and the "MTP of block at h" callers
  pass `h` directly.

---

### BUG-2 (P0-CDIV, gate G16): mempool BIP-68 entry uses **chain-tip MTP** as the per-coin MTP, so every time-based seq-lock with a non-zero masked offset is rejected.

- **camlcoin**: `mempool.ml:2113`
  ```ocaml
  utxo_mtps.(i) <- mp.current_median_time;
  ```
  and `mempool.ml:2127-2130`:
  ```ocaml
  if not (Validation.check_sequence_locks tx
            ~block_height:(mp.current_height + 1)
            ~median_time:mp.current_median_time
            ~utxo_heights ~utxo_mtps ~flags ()) then
    Error "Transaction sequence locks not satisfied (BIP68)"
  ```
  The optional `?get_mtp_at_height` callback is NOT passed. Inside
  `check_sequence_locks` (`validation.ml:1040-1042`):
  ```ocaml
  let input_mtp = match get_mtp_at_height with
    | Some f -> f (max 0 (utxo_heights.(i) - 1))
    | None -> utxo_mtps.(i)
  in
  ```
  with `utxo_mtps.(i) == mp.current_median_time == median_time`, so
  `input_mtp == median_time` for every time-based input. The check is then
  `median_time < median_time + offset`, which is **always true** for `offset > 0`,
  i.e. `ok := false`.

- **Core**: `validation.cpp:200-243` `CalculateLockPointsAtTip` walks
  `block.GetAncestor(nCoinHeight - 1)->GetMedianTimePast()` (tx_verify.cpp:74)
  for **every** input that has bit 22 set. Mempool entries get the **same**
  per-coin MTP that block validation would compute.

- **Effect**: any mempool admission of a v2 tx with a time-based BIP-68
  seq-lock and a non-zero offset is silently rejected by camlcoin's mempool,
  even though it is structurally valid and the network would accept it.
  Miners using camlcoin's mempool exclude these txs from blocks; relay
  drops them. **All time-locked HTLC / Lightning-channel-style mempool
  paths that depend on BIP-68 time semantics are broken.** Block validation
  itself is correct (because the IBD/connect path passes `get_mtp_at_height`
  at `sync.ml:2412/2425`); the bug is mempool-only.

- **Recommended fix**: thread a `get_mtp_at_height : int -> int32` callback
  into the mempool state (alongside the existing `current_median_time` /
  `current_height`), or pass it explicitly at every `submit_tx` /
  `try_add_tx_with_fees` call site. Note this is also covered by the
  "off-by-one" of BUG-1 — both must be fixed together for Core parity.

---

### BUG-3 (P0-CDIV, gate G15): assumeutxo background validator hard-codes `median_time = 0l`.

- **camlcoin**: `assume_utxo.ml:1156-1196`
  ```ocaml
  | Some block ->
    (* Validate block against IBD chainstate *)
    let median_time = 0l in (* TODO: compute properly from chain *)
    let flags = Validation.get_script_flags_for_height ~network next_height in
    ...
    match Validation.accept_block ~network ~block ~height:next_height
            ~expected_bits:header_entry.header.bits
            ~median_time
            ~base_lookup
            ...
  ```
  The `median_time` value is plumbed through `accept_block` to:
  - `check_block`'s "time-too-old" gate (`validation.ml:849`) —
    `block.header.timestamp <= 0l` is always false → never trips.
  - `check_block`'s BIP-113 `locktime_cutoff` (`validation.ml:945-948`) —
    cutoff becomes `0l` when CSV is active.
  - `validate_block_with_utxos`' fast-path `locktime_cutoff_fast`
    (`validation.ml:1573-1577`) — same `0l` cutoff.
  - `check_sequence_locks` per-coin `input_mtp` fallback when
    `get_mtp_at_height` is None (also the case here since the
    assumeutxo path does not pass it).

- **Core**: `validation.cpp:147-167` `CheckFinalTxAtTip` uses
  `active_chain_tip.GetMedianTimePast()`; the assumeutxo
  `kernel::ChainstateRole::BACKGROUND` path runs the same `ConnectBlock`
  with the **real** MTP from the index.

- **Effect**: while the background validator catches up to its snapshot,
  every BIP-113 IsFinalTx call runs with `nBlockTime = 0`. Any
  time-based-locktime tx in the timestamp range (`nLockTime >= 500_000_000`)
  is treated as non-final at the background validator. The background
  chain may diverge from the foreground chain at any block containing
  such a tx, leading to an assumeutxo validation failure and aborting the
  snapshot finalisation.

- **Recommended fix**: replace `median_time = 0l` with
  `Sync.compute_median_time_past chain next_height` (the real chain state
  the background validator already has access to via `ibd_chainstate`),
  and pass `?get_mtp_at_height:(Some (Sync.get_mtp_for_height ibd_chainstate.chain))`
  to `accept_block` so BIP-68 callbacks resolve correctly. Also rolls back
  the TODO at `assume_utxo.ml:1158`.

---

### BUG-4 (P1, gate G24): no `LockPoints` data structure for mempool entries — sequence-lock validity is not re-checked on reorg.

- **camlcoin**: `mempool.ml:2127-2131` runs `check_sequence_locks` at tx
  admission only. The `mempool_entry` record (`mempool.ml:71+`) has no
  `lock_points` field. On a reorg, `mempool.ml` does not call
  `TestLockPointValidity` / re-evaluate `CheckSequenceLocksAtTip` for
  resurrected entries.

- **Core**: `validation.cpp:200-243` `CalculateLockPointsAtTip` stores
  `{min_height, min_time, maxInputBlock}` per entry; `TestLockPointValidity`
  re-checks `maxInputBlock` is still on the active chain after each block
  connect/disconnect; `CheckSequenceLocksAtTip` re-evaluates against the
  new tip. Entries whose `maxInputBlock` was reorged out are removed.

- **Effect**: after a reorg that disconnects a block, mempool entries that
  depended on time/height locks anchored at that block are NOT cleared.
  The mempool can hold txs whose sequence locks no longer hold against
  the new chain; if mined, the block fails validation and the miner has
  wasted work. (Block validation itself catches this — so it is "only"
  a mempool consistency bug, hence P1 not P0.)

---

### BUG-5 (P1, gate G3, G29): `is_tx_final` accepts a 32-bit `block_height` `int` parameter but Core's `nLockTime` semantics are 32-bit unsigned. camlcoin's `Int64.of_int block_height` then comparing to `locktime_unsigned` (Int64) is safe **iff** `block_height` is non-negative. For a malformed cached tip with negative height the comparison underflows.

- **camlcoin**: `validation.ml:771-799`
  ```ocaml
  let is_tx_final (tx : Types.transaction) ~(block_height : int) ~(block_time : int32)
      : bool =
    if tx.locktime = 0l then
      true
    else begin
      let locktime_unsigned = Int64.logand (Int64.of_int32 tx.locktime) 0xFFFFFFFFL in
      let locktime_satisfied =
        if locktime_unsigned < 500_000_000L then
          Int64.of_int block_height > locktime_unsigned
        else
          let block_time_unsigned = Int64.logand (Int64.of_int32 block_time) 0xFFFFFFFFL in
          block_time_unsigned > locktime_unsigned
      in
      ...
  ```
  No defence on `block_height < 0`. In practice all call sites pass a
  validated chain height, but the helper is exported and there is no
  pre-condition assertion.

- **Core**: `tx_verify.cpp:17-37` `IsFinalTx` takes
  `int nBlockHeight, int64_t nBlockTime` and Core's call sites always
  pass `pindex->nHeight + 1` (non-negative). The check is `(int64_t)tx.nLockTime < nBlockHeight`;
  the cast is symmetric. Core also has `Assume(nBlockHeight >= 0)` at the
  surrounding call sites implicitly via the chain index invariant.

- **Effect**: trivial — but the helper is a documented public API of
  `validation.ml` and lacks the explicit bound check that the rest of the
  file applies to other primitives.

---

### BUG-6 (P2, gate G2): `SEQUENCE_LOCKTIME_GRANULARITY` is a **magic-number 9** with no named constant.

- **camlcoin**: `validation.ml:1046` `let time_offset64 = Int64.of_int (masked lsl 9) in`
  with no comment naming the BIP-68 granularity. Future contributors editing
  this line will not immediately see that 9 is a consensus parameter.

- **Core**: `primitives/transaction.h:114`
  `static const int SEQUENCE_LOCKTIME_GRANULARITY = 9;` — a named constant.

- **Effect**: pure maintenance. Same for `SEQUENCE_LOCKTIME_MASK = 0x0000ffff`
  (camlcoin uses `0xFFFFl` and `0x0000FFFFL` raw, no name), and
  `SEQUENCE_LOCKTIME_TYPE_FLAG = (1 << 22) = 0x00400000` (camlcoin uses
  `0x00400000l` raw at `validation.ml:1027` and `0x00400000L` at
  `script.ml:2347`; the same constant appears in `miniscript.ml:125` as
  `1 lsl 22` — three different spellings of one BIP constant).

---

### BUG-7 (P2, gate G7): no `MAX_SEQUENCE_NONFINAL` constant.

- **camlcoin**: `wallet.ml` (FIX-70 default nSequence is `0xfffffffd` per
  the W120 BIP-125 fix) — but `MAX_SEQUENCE_NONFINAL = SEQUENCE_FINAL - 1 = 0xfffffffe`
  is never named.

- **Core**: `primitives/transaction.h:82`
  `static const uint32_t MAX_SEQUENCE_NONFINAL{SEQUENCE_FINAL - 1};`

- **Effect**: the named constant is used by Core's CLTV path (interpreter.cpp
  `CheckLockTime` at line 1755-1779) — specifically that "BIP-65 final-iff
  all inputs == 0xffffffff". camlcoin's `script.ml:2297` open-codes
  `Int32.equal inp.sequence 0xFFFFFFFFl` instead. Functionally equivalent;
  named constant absent.

---

### BUG-8 (P2, gate G9): inconsistent `max 0` guard between two `check_sequence_locks` call sites.

- **camlcoin**: `validation.ml:1709`
  ```ocaml
  utxo_mtps_arr.(j) <- (match get_mtp_at_height with
    | Some f -> f (max 0 (utxo.height - 1))
    | None -> median_time)
  ```
  vs. `validation.ml:1949`:
  ```ocaml
  utxo_mtps.(j) <- (match get_mtp_at_height with
    | Some f -> f (utxo.height - 1)
    | None -> median_time)
  ```
  The fast (assumevalid) path uses `max 0`, the full path does not. The
  full path relies on `compute_median_time_past` tolerating negative
  heights (it does — `h < 0` returns the empty accumulator), so the
  outcome is identical, but the asymmetry is bug-bait.

- **Core**: `tx_verify.cpp:74` uses `std::max(nCoinHeight - 1, 0)` in both
  paths uniformly.

- **Effect**: stylistic / future-proofing.

---

### BUG-9 (P2, gate G19): `compute_median_time_past` (validation MTP) and `compute_median_time_for_display` (RPC MTP) diverge by exactly one block, and the two functions are not described as "the same MTP function with different inclusion semantics" anywhere in the codebase.

- **camlcoin**: `sync.ml:2065-2075` (validation) collects from `height - 1`
  inclusive; `sync.ml:2083-2091` (display) collects from `height` inclusive.
  This **deliberate** asymmetry exists because validation wants
  "pindexPrev's MTP" and RPC wants "this-block's MTP". The intent is
  correct, but it confuses BUG-1 because there is no shared primitive
  "MTP of block at height `H` inclusive" that both call sites can share.

- **Recommended**: factor the inclusive primitive
  `mtp_inclusive_of_block_at state h` and re-implement both wrappers in
  terms of it. Then BUG-1's fix is a single-line redirect of
  `get_mtp_for_height` to the inclusive primitive.

---

### BUG-10 (P3, gate G8): CSV is **buried-only** in camlcoin (no BIP-9 deployment record).

- **camlcoin**: `consensus.ml:265` defines `csv_height` per network; the
  BIP-9 deployment table at `consensus.ml:1262+` does not include a CSV
  entry. Comment at `consensus.ml:1714-1717`:
  > "BIP65/BIP66/CSV/SegWit are buried-only in this implementation (no BIP9 ...)"

- **Core**: `versionbits.cpp` + `chainparams.cpp:540` historically tracked
  CSV (BIP9 bit 0). Modern Core kernel/chainparams agrees that CSV is now
  fully buried on every network (mainnet activated at 419328); the BIP-9
  deployment record is retained for `getdeploymentinfo` RPC parity.

- **Effect**: `getdeploymentinfo` / `getblockchaininfo` RPC outputs will
  lack the `csv` deployment row that Core emits. Pure cosmetic for fresh
  syncs; could be a corpus-diff finding (FIX-80 closed analogous BIP-34/65/66
  records in `eb97184`).

---

### BUG-11 (P3, gate G13): comment at `script.ml:2334-2339` correctly explains the unsigned-32-bit cast for `inp.sequence` but the **height-based** branch in `validation.ml:1026` uses `Int32.logand seq32 0xFFFFl` and `Int32.to_int` *without* the same masking discipline (it relies on the BIP-68 mask being below `Int32.max_int`, which is true).

- **camlcoin**: `validation.ml:1023-1030`
  ```ocaml
  if Int32.logand seq32 0x80000000l <> 0l then
    ()  (* Sequence lock disabled for this input, skip *)
  else begin
    let masked = Int32.to_int (Int32.logand seq32 0xFFFFl) in
    if Int32.logand seq32 0x00400000l = 0l then begin
      let required_height = utxo_heights.(i) + masked in
      ...
  ```
  - The `Int32.logand seq32 0x80000000l` for the disable-flag check works
    because `0x80000000l` is `Int32.min_int` (signed) and the high bit is
    preserved through `logand`.
  - The masking is correct, but the code doesn't show the parallel
    structure with `script.ml:2340-2350` (which DOES mask through Int64).
    A reader following one path doesn't easily port understanding to the
    other.

- **Effect**: pure documentation / parallel-implementation hygiene.

---

## Audit gates (30)

The table below maps the BIP-68/112/113 spec surface to camlcoin source
locations. Each row records the audit status (PRESENT / PARTIAL / MISSING)
and the Core reference. Tests in `test/test_w132_nsequence_csv_mtp.ml`
encode each row as one xfail-or-pass alcotest case.

### BIP-68: relative-locktime sequence numbers (10 gates)

| #  | Gate                                                              | Status   | Core ref                                | camlcoin loc                                                |
|---:|-------------------------------------------------------------------|----------|-----------------------------------------|-------------------------------------------------------------|
| G1 | `SEQUENCE_LOCKTIME_DISABLE_FLAG = (1 << 31)` honoured              | PRESENT  | `transaction.h:93`                       | `validation.ml:1023` (`0x80000000l`), `script.ml:2326/2342` |
| G2 | `SEQUENCE_LOCKTIME_GRANULARITY = 9` named                          | PARTIAL  | `transaction.h:114`                      | `validation.ml:1046` magic 9 — **BUG-6**                    |
| G3 | `SEQUENCE_FINAL = 0xffffffff` honoured                             | PRESENT  | `transaction.h:76`                       | `validation.ml:796`, `script.ml:2297`                       |
| G4 | `SEQUENCE_LOCKTIME_MASK = 0x0000ffff` honoured                     | PRESENT  | `transaction.h:104`                      | `validation.ml:1026` (`0xFFFFl`)                            |
| G5 | `SEQUENCE_LOCKTIME_TYPE_FLAG = (1 << 22)` honoured                 | PRESENT  | `transaction.h:99`                       | `validation.ml:1027` (`0x00400000l`)                        |
| G6 | tx.version < 2 ⇒ BIP-68 not enforced                               | PRESENT  | `tx_verify.cpp:51`                       | `validation.ml:1015`                                        |
| G7 | `MAX_SEQUENCE_NONFINAL = SEQUENCE_FINAL - 1` named                 | MISSING  | `transaction.h:82`                       | not present — **BUG-7**                                     |
| G8 | CSV deployment recorded in BIP-9 table for `getdeploymentinfo`     | MISSING  | `chainparams.cpp:540`                    | `consensus.ml` buried-only — **BUG-10**                     |
| G9 | both BIP-68 call sites use `std::max(coin_h - 1, 0)` symmetrically  | PARTIAL  | `tx_verify.cpp:74`                       | one with `max 0`, one without — **BUG-8**                   |
| G10| height-based lock semantics: pass iff `block.height >= utxo.height + seq` | PRESENT  | `tx_verify.cpp:90` + `:101`              | `validation.ml:1029-1030`                                   |

### BIP-68 time-based lock (5 gates)

| #  | Gate                                                              | Status   | Core ref                                | camlcoin loc                                                |
|---:|-------------------------------------------------------------------|----------|-----------------------------------------|-------------------------------------------------------------|
| G11| time-based lock uses `(seq & MASK) << GRANULARITY` for offset      | PRESENT  | `tx_verify.cpp:88`                       | `validation.ml:1046`                                        |
| G12| per-coin MTP is `block.GetAncestor(coin_h - 1)->GetMedianTimePast` | PARTIAL  | `tx_verify.cpp:74`                       | `validation.ml:1041` but **BUG-1** off-by-one underlies it  |
| G13| `inp.sequence` zero-extended (uint32 semantics) at script CSV     | PRESENT  | `interpreter.cpp:1786`                   | `script.ml:2334-2340` w/ explanatory comment — **BUG-11** is doc-only |
| G14| `get_mtp_for_height (h)` returns MTP-inclusive-of-block-at-`h`     | MISSING  | `chain.h:233`                            | `sync.ml:2151` calls validation MTP → **BUG-1**             |
| G15| BIP-68 enforced on the IBD assume-valid fast path too              | PRESENT  | `validation.cpp:2480-2482`               | `validation.ml:1493-1498`, `:1713-1717`                     |

### BIP-112 OP_CHECKSEQUENCEVERIFY interpreter (8 gates)

| #  | Gate                                                              | Status   | Core ref                                | camlcoin loc                                                |
|---:|-------------------------------------------------------------------|----------|-----------------------------------------|-------------------------------------------------------------|
| G16| OP_CSV (`0xb2`) decoded as `OP_CHECKSEQUENCEVERIFY`                | PRESENT  | `interpreter.cpp:561`                    | `script.ml:82, 219, 322`                                    |
| G17| `SCRIPT_VERIFY_CHECKSEQUENCEVERIFY` flag gated at height          | PRESENT  | `validation.cpp` GetBlockScriptFlags     | `consensus.ml:894-898`, `validation.ml:320-322`             |
| G18| flag-clear → behave as NOP3                                       | PRESENT  | `interpreter.cpp:563-566`                | `script.ml:2307-2313`                                       |
| G19| script arg parsed as up-to-5-byte CScriptNum w/ MINIMALDATA       | PRESENT  | `interpreter.cpp:573-574`                | `script.ml:2318-2321`                                       |
| G20| negative script arg ⇒ `SCRIPT_ERR_NEGATIVE_LOCKTIME`               | PRESENT  | `interpreter.cpp:579-580`                | `script.ml:2322-2323`                                       |
| G21| script arg with disable flag ⇒ NOP (success)                       | PRESENT  | `interpreter.cpp:585-586`                | `script.ml:2326-2327`                                       |
| G22| tx.version < 2 ⇒ `SCRIPT_ERR_UNSATISFIED_LOCKTIME`                | PRESENT  | `interpreter.cpp:1790-1791`              | `script.ml:2330-2331`                                       |
| G23| `CheckSequence` masked compare w/ TYPE_FLAG bucket check          | PRESENT  | `interpreter.cpp:1797-1818`              | `script.ml:2340-2358`                                       |

### BIP-113 median-time-past locktime (4 gates)

| #  | Gate                                                              | Status   | Core ref                                | camlcoin loc                                                |
|---:|-------------------------------------------------------------------|----------|-----------------------------------------|-------------------------------------------------------------|
| G24| `CheckFinalTxAtTip` uses `tip.GetMedianTimePast()` (not block.time)| PRESENT  | `validation.cpp:147-167`                 | `validation.ml:945-948, 1573-1577`                          |
| G25| pindexPrev MTP used in `ContextualCheckBlock` BIP-113 cutoff      | PRESENT  | `validation.cpp:4135-4146`               | `validation.ml:945-948`                                     |
| G26| `IsFinalTx` strict-less-than semantics (`locktime < nBlockHeight`)| PRESENT  | `tx_verify.cpp:17-37`                    | `validation.ml:771-799`                                     |
| G27| BIP-113 cutoff feeds BOTH full and assume-valid paths             | PARTIAL  | `validation.cpp:4146` runs unconditionally | full: `validation.ml:945-948`; fast: `:1573-1577`; assumeutxo: **BUG-3** (`median_time = 0l`) |

### Mempool / LockPoints (3 gates)

| #  | Gate                                                              | Status   | Core ref                                | camlcoin loc                                                |
|---:|-------------------------------------------------------------------|----------|-----------------------------------------|-------------------------------------------------------------|
| G28| mempool entries store per-tx `LockPoints` w/ `maxInputBlock`      | MISSING  | `validation.cpp:200-243`                 | `mempool.ml` mempool_entry has no `lock_points` — **BUG-4** |
| G29| `TestLockPointValidity` re-runs sequence-lock check on reorg      | MISSING  | `validation.cpp:246-272`                 | `mempool.ml` reorg path absent — **BUG-4**                  |
| G30| mempool BIP-68 entry uses per-coin MTP via `get_mtp_at_height`    | PARTIAL  | `tx_verify.cpp:74` via `CalculateLockPointsAtTip` | `mempool.ml:2127-2130` does NOT pass `?get_mtp_at_height` — **BUG-2** |

---

## Cross-references to prior waves

- **W80** (test_script.ml::G1-G6 OP_CSV gate tests) covers G18-G23 here.
- **W93 Bug 5/6/10** closed the gap of running BIP-68 / IsFinalTx on the
  assume-valid path (G15, G27 full-path) — but NOT the assumeutxo
  background-validator path, which still has **BUG-3**.
- **FIX-70** (W120) updated the wallet's default nSequence to `0xfffffffd`
  matching Core's BIP-125 RBF default — adjacent to G7 here but not the
  same constant (`MAX_SEQUENCE_NONFINAL` vs. `MAX_BIP125_RBF_SEQUENCE`).

## Out of scope (deferred to future waves)

- **BIP-65 OP_CHECKLOCKTIMEVERIFY semantics** beyond the `SEQUENCE_FINAL`
  check at `script.ml:2297` (the W127 / W128-adjacent CLTV audit).
- **BIP-125 nSequence default semantics** in wallet construction (already
  audited in W120 + FIX-70).
- **Anti-fee-sniping locktime randomisation** (audited in W113 BUG-6 /
  W129 G27).
- **Miniscript timelock combining rules** (`miniscript.ml:152-160`
  `combine_timelocks`) — separate Taproot/Miniscript wave material.
- **`getblockheader.mediantime` RPC output** uses
  `compute_median_time_for_display` (`sync.ml:2083-2091`) which IS
  inclusive-of-block-at-`h` and therefore correct — distinct from the
  validation MTP that BUG-1 hits.
