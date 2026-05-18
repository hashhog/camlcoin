# W147 UTXO database / chainstate (CCoinsView + CCoinsViewCache + CCoinsViewDB) — camlcoin (OCaml)

Wave: W147 — the persistence and in-memory cache fences that mediate
every UTXO read and every block-driven UTXO mutation. Covers
`CCoinsView` interface contract, `CCoinsViewCache` Fresh/Dirty/Erased
flag accounting, `CCoinsViewDB` leveldb layout (`C`-prefix keys, coin
compression, obfuscate-key, BEST_BLOCK / HEAD_BLOCKS replay marker),
`FlushStateToDisk` triggers, and `AddCoins` / `SpendCoin` plumbing.

Bitcoin Core references:

- `bitcoin-core/src/coins.h:308-341` — abstract `CCoinsView`:
  `GetCoin`, `HaveCoin`, `GetBestBlock`, `GetHeadBlocks`, `BatchWrite`,
  `Cursor`.  Every concrete backend (`CCoinsViewDB`,
  `CCoinsViewCache`, `CCoinsViewBacked`) MUST implement the full set.
- `bitcoin-core/src/coins.cpp:83-130` — `CCoinsViewCache::GetCoin` /
  `AddCoin` with FRESH-flag accounting (FRESH = parent does not have the
  coin OR has it spent-but-not-DIRTY; only then can a later spend
  short-circuit and drop the entry without flushing to parent).
- `bitcoin-core/src/coins.cpp:142-151` — `AddCoins`: coinbase is
  ALWAYS passed `possible_overwrite=true` to handle pre-BIP-30
  duplicate-coinbase blocks (91722 / 91812 on mainnet).
- `bitcoin-core/src/coins.cpp:208-277` — `CCoinsViewCache::BatchWrite`
  is the merge engine: walks the parent's cursor, applies DIRTY-only
  entries, throws `std::logic_error` if a child FRESH flag is
  misapplied to a coin that exists in the parent.
- `bitcoin-core/src/coins.cpp:279-300` — `Flush` (will_erase=true) /
  `Sync` (will_erase=false): two-mode flush, the difference being
  whether DIRTY entries are kept in the cache after the parent has
  observed them.
- `bitcoin-core/src/coins.cpp:153-175` — `SpendCoin`: FRESH entries are
  ERASED entirely; DIRTY entries become a spent-but-DIRTY tombstone
  that must propagate to parent on flush.
- `bitcoin-core/src/txdb.cpp:23-25` — chainstate keys:
  `DB_COIN='C'`, `DB_BEST_BLOCK='B'`, `DB_HEAD_BLOCKS='H'`. The 'C'
  key is followed by `CoinEntry { uint256 hash, VARINT vout }`.
- `bitcoin-core/src/txdb.cpp:100-164` — `CCoinsViewDB::BatchWrite`:
  every flush writes BOTH `Vector(hashBlock, old_tip)` to `DB_HEAD_BLOCKS`
  BEFORE coin mutations, then erases HEAD_BLOCKS and writes
  `hashBlock` to `DB_BEST_BLOCK` AFTER mutations.  On startup, an
  out-of-band HEAD_BLOCKS means the previous flush was torn — the
  daemon refuses to start and demands `-reindex-chainstate`.
- `bitcoin-core/src/compressor.cpp:55-95` — `CompressScript` /
  `DecompressScript`: P2PKH / P2SH / P2PK templates compressed to a
  1-byte tag + 20/32 raw bytes.
- `bitcoin-core/src/compressor.cpp:149-194` — `CompressAmount` /
  `DecompressAmount`: exponent + mantissa packing.
- `bitcoin-core/src/dbwrapper.cpp:253-261` and
  `bitcoin-core/src/dbwrapper.h:192` — `OBFUSCATION_KEY` constant
  `"\x00obfuscate_key"` (14 bytes); every value in the chainstate
  leveldb is XOR'd with the 8-byte key looped to length on
  read/write.
- `bitcoin-core/src/validation.cpp:2702-2855` —
  `Chainstate::FlushStateToDisk` modes: `IF_NEEDED`, `PERIODIC`,
  `ALWAYS`, `FORCE_FLUSH`, `FORCE_SYNC`, plus the size-based gate
  (default `nCoinCacheUsage = 450 MiB`).  Triggered from
  `ConnectTip`, `DisconnectTip`, `LoadGenesisBlock`, shutdown,
  `assumeutxo` load, and every `ProcessNewBlock`.
- `bitcoin-core/src/validation.cpp:6021` — `validated_cs.ForceFlushStateToDisk()`
  on assumeUTXO snapshot consolidation.
- `bitcoin-core/src/coins.h:228-245` — `CCoinsViewCursor` abstract
  iterator (NOT a callback): `Valid()`, `Next()`, `GetKey`, `GetValue`,
  `GetBestBlock`.  Consumers can stop early and pass the cursor
  between threads.

camlcoin reference points:

- `lib/utxo.ml:18-40` — `utxo_entry` and `serialize_utxo_entry`
  (production on-disk format; non-Core)
- `lib/utxo.ml:313-557` — `OptimizedUtxoSet` (LIVE production UTXO
  cache; no FRESH/DIRTY/ERASED tracking)
- `lib/utxo.ml:566-664` — `connect_block_optimized` (UTXO mutation on
  block connect)
- `lib/utxo.ml:701-1052` — `coin`, `cache_entry` (Fresh/Dirty/Erased),
  `UTXO_VIEW` module type, `DbView`, `UtxoCache` (Core-faithful design,
  used only by `assume_utxo`)
- `lib/storage.ml:471-820` — `ChainDB` (UTXO + chain_tip persistence)
- `lib/cf_chainstate.ml:43-491` — RocksDB column-family chainstate
  backend
- `lib/rocksdb_store.ml` — second, parallel RocksDB UTXO store
- `lib/compressor.ml:144-194` — `compress_amount` / `decompress_amount`
- `lib/compressor.ml:306-460` — `compress_script` / `decompress_script`
  (only wired into `assume_utxo` snapshot path, NOT live UTXO writes)
- `lib/cli.ml:362-404` — UTXO subsystem boot: opens BOTH
  `chainstate-rocks/` and `rocksdb_utxo/`

This audit cross-cites W100 (`test/test_w100_coins_view_cache.ml`)
which previously catalogued BUG-1..BUG-10 against
`UtxoCache` + `OptimizedUtxoSet`.  The W147 findings below extend that
list with the on-disk format, two-pipeline persistence, obfuscation,
and atomicity gaps that W100 did not cover.

---

## BUG-1 — production on-disk UTXO format diverges from Core: no `CompressAmount`, no `CompressScript`, no varint `(height<<1)|isCoinbase` packing [P0]

- **File:** `lib/utxo.ml:25-40` (`serialize_utxo_entry` /
  `deserialize_utxo_entry`) + `lib/utxo.ml:755-773`
  (`DbView.serialize_coin` / `deserialize_coin`) +
  `lib/sync.ml:1983-1991` (`encode_utxo`) +
  `lib/cf_chainstate.ml:232-248` (`put_utxo` / `get_utxo`)
- **Core ref:** `bitcoin-core/src/coins.h` `Coin::Serialize` and
  `bitcoin-core/src/compressor.h:99-110` `TxOutCompression`

**Description.** Bitcoin Core's chainstate leveldb stores each coin as

```
VARINT((height << 1) | isCoinbase)   // 1-5 bytes; ≤63 fits in 1 byte
VARINT(CompressAmount(value))        // 1-9 bytes; typical 1-3
ScriptCompression(scriptPubKey)      // 1-byte tag + 20/32 bytes for
                                     // P2PKH / P2SH / P2PK templates
```

camlcoin's production writer emits a hand-rolled, non-Core format
(`lib/utxo.ml:26-31`):

```ocaml
let serialize_utxo_entry w (e : utxo_entry) =
  Serialize.write_int64_le w e.value;                 (* 8 bytes, no compression *)
  Serialize.write_compact_size w (Cstruct.length e.script_pubkey);
  Serialize.write_bytes w e.script_pubkey;            (* full raw script *)
  Serialize.write_int32_le w (Int32.of_int e.height); (* 4 bytes *)
  Serialize.write_uint8 w (if e.is_coinbase then 1 else 0)
```

The three other writer sites (`DbView.serialize_coin` at L757-763,
`encode_utxo` in `sync.ml:1983-1991`, and the legacy
`Utxo.UtxoSet.add` at L99-107) all emit the same non-Core layout.

**Excerpt** (`lib/sync.ml:1983-1991`, redundant third copy):

```ocaml
let encode_utxo (value : int64) (script : Cstruct.t) (height : int)
    (is_coinbase : bool) : string =
  let w = Serialize.writer_create () in
  Serialize.write_int64_le w value;
  Serialize.write_compact_size w (Cstruct.length script);
  Serialize.write_bytes w script;
  Serialize.write_int32_le w (Int32.of_int height);
  Serialize.write_uint8 w (if is_coinbase then 1 else 0);
  Cstruct.to_string (Serialize.writer_to_cstruct w)
```

**Impact.** Three compounding problems:

1. **On-disk size blowout.** Mainnet's ~115M UTXOs at Core's compressed
   format average ~25 bytes per coin (P2PKH/P2WPKH compress to ~25, P2SH
   to ~25, P2PK to ~33). camlcoin's format averages ~38 bytes for the
   same workload (8 value + 1 compact-size + 25 script + 4 height + 1
   cb).  Disk footprint is roughly +50%.
2. **Operator cannot transplant Core chainstates.** A Core node's
   `chainstate/` LevelDB and a camlcoin `chainstate-rocks/utxo` CF are
   byte-incompatible at the value level — even ignoring the leveldb vs
   rocksdb backend choice and the key-prefix divergence (BUG-2 below).
3. **`Compressor` module is dead on the live path.** `lib/compressor.ml`
   contains a faithful 460-LOC port of `compress_amount` and
   `compress_script` with the on-curve secp256k1 round-trip check.
   `grep` confirms it is invoked from `lib/assume_utxo.ml` (snapshot
   format only) and `test/test_compressor.ml` — and from NOWHERE on
   the live read/write path.  Classic two-pipeline guard:
   Core-faithful module ships dead-code parallel to the live "ad-hoc"
   path.

Severity P0 (not P0-CDIV because this is on-disk format only, not
wire-level consensus output) because the divergence forecloses any
future cross-impl chainstate import/export tooling and silently
inflates RSS / disk by ~50% during IBD.

---

## BUG-2 — chainstate UTXO key layout is `txid32 ++ vout_le32`, not Core's `'C' ++ uint256 ++ VARINT(vout)` [P0]

- **File:** `lib/cf_chainstate.ml:229-248` (`utxo_key`, `put_utxo`,
  `get_utxo`, `delete_utxo`)
- **Core ref:** `bitcoin-core/src/txdb.cpp:23, 43-49` (`DB_COIN='C'`,
  `CoinEntry::SERIALIZE_METHODS`)

**Description.** Core's chainstate key is

```
uint8_t('C') || uint256(outpoint.hash) || VARINT(outpoint.n)
```

camlcoin emits

```ocaml
let utxo_key (txid : Types.hash256) (vout : int) : string =
  let buf = Bytes.create 36 in
  Cstruct.blit_to_bytes txid 0 buf 0 32;
  Bytes.set buf 32 (Char.chr (vout land 0xff));
  Bytes.set buf 33 (Char.chr ((vout lsr 8) land 0xff));
  Bytes.set buf 34 (Char.chr ((vout lsr 16) land 0xff));
  Bytes.set buf 35 (Char.chr ((vout lsr 24) land 0xff));
  Bytes.unsafe_to_string buf
```

Two divergences:

1. **No `'C'` prefix.** Core uses the `'C'` byte to namespace coin
   entries inside a flat leveldb (alongside `'B'` = best block, `'H'`
   = head blocks).  camlcoin puts coin entries in a dedicated
   `cfh_utxo` column family, so no prefix is needed for namespacing
   within the DB — but the absence makes the key byte-incompatible
   with any Core chainstate export, and the operator cannot run
   `bitcoin-cli` `gettxout` against the file.
2. **Fixed 4-byte little-endian `vout`, not VARINT.** Core's
   `VARINT(uint32_t)` encoder writes 1 byte for `vout < 128` (the
   common case — 99%+ of mainnet outpoints).  camlcoin always writes 4
   bytes.  +3 bytes per coin × 115M UTXOs ≈ +345 MiB key space on
   mainnet.

**Excerpt** (`lib/cf_chainstate.ml:232-239`).

**Impact.** Same family as BUG-1 — disk bloat plus no cross-impl
interop with Core's chainstate.  Also: because the key is fixed-width
binary, prefix-seek iterators (used by `iter_utxos` and Core's
`Cursor`) cannot stop early on a partial txid; every `iter_utxos` is a
full-CF scan.

---

## BUG-3 — chainstate value bytes are NOT obfuscated; `OBFUSCATION_KEY` is absent from production storage [P0-SEC]

- **File:** `lib/cf_chainstate.ml` (entire module — `grep -n
  "obfuscate" lib/cf_chainstate.ml` returns 0 hits) +
  `lib/rocksdb_store.ml` (also 0 hits) + `lib/storage.ml`
- **Core ref:** `bitcoin-core/src/dbwrapper.cpp:253-261`,
  `bitcoin-core/src/dbwrapper.h:42, 192` (`OBFUSCATION_KEY = "\x00obfuscate_key"`)

**Description.** Core stores every value in the chainstate leveldb
XOR'd with an 8-byte random key looped to the value's length.  The key
itself is written under the special key `"\x00obfuscate_key"` and is
loaded on `CDBWrapper` open.  Purpose:

- Prevent anti-virus heuristics from flagging the file because raw
  scriptPubKey bytes can look like x86 code patterns.
- Prevent grep-by-known-template (P2WPKH OP_DUP ...) on someone else's
  chainstate dir.

camlcoin's chainstate stores raw, unobfuscated coin values.  Anti-virus
false-positives WILL fire on Windows for `chainstate-rocks/*.sst`
files containing OP_RETURN OP_PUSH 0x07 0xff 0xfe Ord Inscription
witness data (common since Ord 2023), and on production deployments
the chainstate is fully grep-able.

The mempool persistence path (`lib/mempool.ml:3500-3729`) DOES
implement the obfuscation protocol — it correctly reads/writes the
`v2` mempool.dat format with the 8-byte XOR key at byte offset 8.
The chainstate path does not.  Fleet-pattern smell: "two-pipeline
guard, obfuscation half-implemented" — one persistence layer correct,
the other absent.

**Impact.** Operator visibility leak + AV breakage on Windows.  Not a
consensus issue but a documented Core security/usability invariant
that camlcoin silently violates.

---

## BUG-4 — chainstate has no `DB_HEAD_BLOCKS` / mid-flush replay marker: torn writes leave silently-inconsistent UTXOs [P0]

- **File:** `lib/cf_chainstate.ml:271-277` (`put_chain_state` —
  used only for `tip_hash`, `tip_height`, `header_tip_hash`,
  `header_tip_height`) + `lib/storage.ml:621-659` (`apply_block_atomic`)
- **Core ref:** `bitcoin-core/src/txdb.cpp:100-164`
  (`CCoinsViewDB::BatchWrite`)

**Description.** Core's `CCoinsViewDB::BatchWrite` writes BOTH

```
batch.Erase(DB_BEST_BLOCK);
batch.Write(DB_HEAD_BLOCKS, Vector(new_hashBlock, old_tip));
```

BEFORE it writes any coin mutations.  Then it streams coin
puts/deletes, and finally:

```
batch.Erase(DB_HEAD_BLOCKS);
batch.Write(DB_BEST_BLOCK, hashBlock);
```

Result: a crash midway through the coin stream leaves the leveldb in
a state where `DB_BEST_BLOCK` does not exist, `DB_HEAD_BLOCKS` lists
the *intended* new tip + the *prior* tip.  On boot, Core detects the
non-null `DB_HEAD_BLOCKS`, refuses to start, and demands
`-reindex-chainstate` so the operator can re-validate the partial
state from a known-good height.

camlcoin's `apply_block_atomic` (`lib/storage.ml:630-659`) writes
`tip_hash`, `tip_height`, `header_tip_hash`, `header_tip_height` in the
SAME batch as the coin mutations.  No HEAD_BLOCKS vector is written.
On a crash mid-batch, RocksDB's WAL DOES preserve atomicity for that
single batch — so the cf_chainstate side is recoverable as
all-or-nothing.

But: `apply_block_atomic` then writes a SECOND batch to
`rocksdb_utxo` (`lib/storage.ml:657-659`).  A crash between the two
commits leaves `chain_tip` advanced + `rocksdb_utxo` un-updated.  The
comment at L625-629 admits the hazard:

```ocaml
(* Commit order is CF-first so a crash between the two commits leaves
   rdb_tip < chain_tip, which [cli.ml]'s boot consistency check
   already handles (rewinds blocks_synced to rdb_tip; the next IBD
   re-processes the gap using RocksDB as the authoritative pre-gap
   UTXO snapshot via [get_utxo]'s fallback path). *)
```

This is a comment-as-confession.  The boot consistency check in
`lib/cli.ml:380-394` only handles the case where `rdb_tip <
chain_tip` (rewind).  It cannot handle:

- The reverse case (`rdb_tip > chain_tip`) — never reached in normal
  operation but reachable via reindex partial restart.
- The case where the crash happens DURING the cf_chainstate batch
  itself.  RocksDB WAL replay handles this, but only because all four
  `chain_state` keys live in one CF batch with the coin mutations.
  There's no Core-style HEAD_BLOCKS marker to detect that the prior
  flush was partial across DIFFERENT runs (e.g. an operator manually
  resets `rocksdb_utxo` while `cf_chainstate` is intact).
- A power-loss before the WAL is fsync'd: RocksDB WAL is not synced
  per-batch by default (only per checkpoint), so RocksDB's atomic
  unit is NOT strictly per-batch under power loss.

**Impact.** Latent torn-write hazard.  In practice the boot
consistency check + IBD re-validation papers over most cases, but
there is no equivalent of Core's "refuse-to-start until operator
acks" gate.  A silently inconsistent UTXO set + advanced chain_tip
produces non-deterministic block-validation errors downstream (the
W14 "live wedge papered over by env-var stopgap" pattern in another
quad-wave).

---

## BUG-5 — `Utxo.UtxoCache` (the Core-faithful CCoinsViewCache analog) is dead code on the live path; only used by `assume_utxo` + tests [P0]

- **File:** `lib/utxo.ml:830-1052` (`UtxoCache` module — 222 LOC)
- **Core ref:** `bitcoin-core/src/coins.h:344-561`
  (`CCoinsViewCache`)

**Description.** camlcoin has a faithful port of Core's three-state
(Fresh / Dirty / Erased) cache as `Utxo.UtxoCache`, complete with
`UTXO_VIEW` module type, `DbView` parent-view abstraction, and
hierarchical caching.  Its `add_coin` / `spend_coin` / `flush` /
`memory_usage` / `needs_flush` / `maybe_flush` mirror Core API.

But `grep -rn "UtxoCache" lib/` returns only two consumer files:

```
lib/assume_utxo.ml      (snapshot loader + dead create_chainstate)
lib/utxo.ml             (the module itself)
```

The live IBD / sync / mining / block_import paths consume
`OptimizedUtxoSet` instead — a simpler LRU + dirty-Hashtbl design
WITHOUT FRESH / DIRTY / ERASED flag accounting.

`assume_utxo.ml:1240-1273` admits the architecture:

```
[node_state] / [active_chainstate] / [background_chainstate] /
[has_snapshot_chainstate] / [create_chainstate] are never instantiated
anywhere in the codebase. They were a 2026-04-29 design draft for
in-process Core-style dual-chainstate switching that camlcoin never
integrated.
```

So `UtxoCache` itself is reachable only via:

1. The W93 / W138 dead `assume_utxo.create_chainstate` (admitted).
2. `assume_utxo.load_snapshot` (live, on the snapshot-load path).
3. `assume_utxo.run_background_validation` (the W138 dead-class
    pattern).
4. The `test_w100_coins_view_cache` regression suite + the
   `test_utxo.ml` "UtxoCache" group.

**Impact.** The fleet-pattern "two-pipeline guard / dead class with
full method surface" lives here.  Every consensus property the
W100/W138 wave catalogued for `UtxoCache` (FRESH-flag accounting,
parent-fetch staying-clean, BatchWrite filtering DIRTY-only) does NOT
constrain the live IBD path; the live path uses `OptimizedUtxoSet`
which has none of those invariants and which W100 BUG-9 + BUG-10
documented as having additional correctness gaps the Core-faithful
module fixes.

Cross-cite: fleet-pattern from quad-runs W138 (8 of 10 impls show
"defined class + full method surface + zero production callers").
This is the 9th impl to confirm the pattern at the chainstate layer.

---

## BUG-6 — `connect_block_to_cache` (assume_utxo path) calls `add_coin ~possible_overwrite:false` for ALL outputs including coinbase; BIP-30 duplicate-coinbase will throw [P0-CONSENSUS]

- **File:** `lib/assume_utxo.ml:1068-1078`
- **Core ref:** `bitcoin-core/src/coins.cpp:142-151` (`AddCoins`)

**Description.** Core's `AddCoins` (`coins.cpp:142-151`) sets the
`possible_overwrite` argument as follows:

```cpp
void AddCoins(CCoinsViewCache& cache, const CTransaction &tx, int nHeight, bool check_for_overwrite) {
    bool fCoinbase = tx.IsCoinBase();
    const Txid& txid = tx.GetHash();
    for (size_t i = 0; i < tx.vout.size(); ++i) {
        bool overwrite = check_for_overwrite ? cache.HaveCoin(COutPoint(txid, i)) : fCoinbase;
        // Coinbase transactions can always be overwritten, in order to correctly
        // deal with the pre-BIP30 occurrences of duplicate coinbase transactions.
        cache.AddCoin(COutPoint(txid, i), Coin(tx.vout[i], nHeight, fCoinbase), overwrite);
    }
}
```

Key invariant: for coinbase transactions, `overwrite` is ALWAYS true
(unless the caller explicitly asks for the HaveCoin pre-check via
`check_for_overwrite`).  This handles BIP-30 duplicate-coinbase blocks
91722 and 91812 on mainnet, where two coinbase transactions share the
same txid and the second one's outputs MUST overwrite the first.

camlcoin's `connect_block_to_cache` (`assume_utxo.ml:1070-1077`):

```ocaml
List.iteri (fun vout out ->
  let outpoint = { Types.txid; vout = Int32.of_int vout } in
  let coin : Utxo.coin = {
    txout = { Types.value = out.Types.value; script_pubkey = out.script_pubkey };
    height;
    is_coinbase;
  } in
  Utxo.UtxoCache.add_coin cache outpoint coin ~possible_overwrite:false
) tx.Types.outputs
```

`possible_overwrite:false` is passed unconditionally for both
coinbase and non-coinbase outputs.

`Utxo.UtxoCache.add_coin` (`utxo.ml:899-947`) raises a `failwith` when
the key already exists in cache or parent unless `possible_overwrite`
is true:

```ocaml
| Some (Dirty existing_coin) ->
  if not possible_overwrite then
    failwith (Printf.sprintf "add_coin: overwriting dirty coin at %s:%ld without possible_overwrite"
      (Types.hash256_to_hex_display outpoint.txid) outpoint.vout);
  ...
```

**Impact.** On any chain that includes mainnet height 91722 or 91812
(replayed during background validation per assume_utxo), the second
coinbase's `add_coin` throws OCaml `Failure` and aborts the
background validation thread.  Background validation NEVER completes
on mainnet via the assume_utxo path.

Note this only fires on the dead/dormant assume_utxo path (per BUG-5),
so the live IBD path remains unaffected.  Still P0-CONSENSUS-class
because once anyone wires `run_background_validation` to a real
caller, mainnet IBD via assume_utxo halts at the first BIP-30 block.

---

## BUG-7 — `OptimizedUtxoSet.flush` writes ONLY to `rocksdb_utxo`, leaving the `cf_chainstate` UTXO column family empty after IBD [P0]

- **File:** `lib/utxo.ml:455-495` (`flush`), with the bug
  acknowledged in `lib/utxo.ml:497-511` (the comment introducing
  `persist_dirty_atomic`)
- **Core ref:** `bitcoin-core/src/coins.cpp:208-277` (`BatchWrite`
  flushes through the SINGLE parent — no split-store hazard exists in
  Core)

**Description.** The cli wires camlcoin to TWO parallel UTXO stores:

```ocaml
(* lib/cli.ml:362-374 *)
let utxo = Utxo.UtxoSet.create db in       (* legacy chain_state CF UTXO *)
...
let rocksdb_path = Filename.concat config.data_dir "rocksdb_utxo" in
let rocksdb = Rocksdb_store.open_db rocksdb_path in
Storage.ChainDB.attach_rocksdb_utxo db rocksdb;
```

`OptimizedUtxoSet.flush` writes to whichever backend is attached.
When `rocksdb_utxo` is attached (always, in production), the flush
takes the `Some rdb` branch (`lib/utxo.ml:458-474`) and writes ONLY
to the standalone rocksdb_utxo store.  The cf_chainstate `utxo` CF
remains empty for every UTXO created during IBD.

The mining-driven `persist_dirty_atomic` (used by `Mining.submit_block`,
`lib/utxo.ml:512-535`) writes to BOTH stores — exactly because the
author discovered that `dumptxoutset` (which uses
`iter_utxos` → cf_chainstate iter) emits a 51-byte header-only
snapshot with 0 coins:

```
This is the persistence path used by [Mining.submit_block] (which
drives [connect_block_optimized] to mutate the in-memory dirty set
but otherwise relies on [flush] — and [flush] only writes to
rocksdb_utxo, leaving cf_chainstate empty).  The dump path
([Storage.ChainDB.iter_utxos] + [dumptxoutset]) iterates
cf_chainstate, which is why a regtest node fed only via
[submitblock] dumped a 51-byte header-only snapshot with 0 coins
before this fix.
```

The "fix" patched only the mining path.  The IBD path still leaves
cf_chainstate empty.

**Impact.** Every operator-visible feature that calls
`iter_utxos` on a post-IBD node returns an EMPTY set or a partial set
that contains ONLY post-IBD mining coins:

- `dumptxoutset` — emits header-only / partial snapshot
- `scantxoutset` — never finds historical coins
- RPC `gettxoutsetinfo` total counts and value
- BIP-157 filter index re-build path
- `compute_utxo_hash` (`assume_utxo.ml:805-872`) and
  `compute_utxo_muhash` (`assume_utxo.ml:912-...`) — both iterate
  cf_chainstate and miss everything except newly-mined post-IBD coins

This is a confirmed two-pipeline guard (W100 BUG-7 surface).  Until
all UTXO mutations route through `persist_dirty_atomic` (or both
stores collapse to one), the two stores diverge during every IBD.

---

## BUG-8 — `OptimizedUtxoSet.add` is called with the same `is_coinbase=tx_idx=0` flag on EVERY output of the coinbase but NEVER uses Core's `possible_overwrite=true` for BIP-30 [P0]

- **File:** `lib/utxo.ml:566-647` (`connect_block_optimized`, the
  LIVE production block-connect path)
- **Core ref:** `bitcoin-core/src/coins.cpp:142-151` (`AddCoins`)

**Description.** Same shape as BUG-6 but on the LIVE IBD path.
`OptimizedUtxoSet.add` (`utxo.ml:384-389`) is:

```ocaml
let add (t : t) (txid : Types.hash256) (vout : int)
    (entry : utxo_entry) : unit =
  let key = utxo_key txid vout in
  Perf.LRU.put t.cache key entry;
  Hashtbl.replace t.dirty key (`Added entry)
```

`Hashtbl.replace` happily overwrites.  This is fine for BIP-30
(coinbase txid collision at h=91722 / 91812 — the second coinbase wins
and its outputs replace the first), but ONLY by accident — the code
neither checks `HaveCoin` (the `check_for_overwrite` branch in Core)
nor asserts `is_coinbase=true` when an overwrite happens.

Practical effect on mainnet IBD: the live path silently overwrites
the first 91722 / 91812 coinbase outputs with the second.  The first
coinbase's outputs are therefore unspendable but DO NOT appear in
the UTXO set — which matches Core's post-91812 behaviour and is
correct for mainnet sync.  Bug surfaces only on:

1. A regtest / testnet variant where someone DELIBERATELY creates a
   non-coinbase tx that hashes to an existing txid (cryptographically
   impractical, ignore).
2. A reorg that disconnects the SECOND 91812 coinbase but not the
   first — `disconnect_block` would need to restore the first 91722
   coinbase's outputs.  camlcoin's `apply_tx_in_undo`
   (`sync.ml:3087-3127`) does treat this as `Disconnect_unclean`, but
   the `OptimizedUtxoSet.add` overwrite happens silently with no
   audit-trail flag (Core sets `fClean=false` and propagates).

Severity P0 because the divergence is silent and only the audit-trail
side is missing; the actual UTXO state is correct on mainnet.

---

## BUG-9 — `UtxoCache.get_coin` marks every parent-fetched entry as `Dirty`; clean read-throughs are re-written to disk on flush [P1 / W100 BUG-1 carry-forward]

- **File:** `lib/utxo.ml:867-885` (`UtxoCache.get_coin`)
- **Core ref:** `bitcoin-core/src/coins.cpp:68-81` (`FetchCoin` —
  parent-fetched entries are stored WITHOUT DIRTY)

**Description.** This is a carry-forward of W100 BUG-1, re-anchored
here because the W100 fix never landed.  The code itself admits the
problem (`lib/utxo.ml:875-879`):

```ocaml
(* Cache the result from parent without Dirty flag. We use Dirty here
   only for bookkeeping (it's an unmodified copy). A proper clean cache
   state would avoid unnecessary writes on flush, but we keep Dirty
   for simplicity since spend_coin handles the transition correctly. *)
let entry = Dirty coin in
```

Comment-as-confession.  Core's `FetchCoin` returns the parent's coin
to the cache without setting DIRTY; Core's `BatchWrite` then walks
the cursor's iterator and continues if `!it->second.IsDirty()`.
camlcoin's UtxoCache.flush (L986-1015) writes Fresh OR Dirty
unconditionally:

```ocaml
Hashtbl.iter (fun key entry ->
  ...
  match entry with
  | Fresh coin | Dirty coin ->
    let data = DbView.serialize_coin coin in
    Storage.ChainDB.batch_store_utxo batch txid vout data
```

**Impact.** Every read-through cached during IBD ends up re-written
to disk on every flush.  Approximate cost on mainnet: ~50% of UTXOs
read during validation are also outputs of the same block (recent
coins), but ~50% are reads against the legacy disk state — and those
all get re-written every 500 blocks.  RocksDB compaction load is
roughly 2× what it should be.

Carry-forward re-anchor (4th instance in the quad-wave campaign);
see W124 BUG-13 and W125 BUG-15+17 for prior examples.

---

## BUG-10 — `UtxoCache.add_coin` performs a `DbView.have_coin` (disk hit) on EVERY add when the entry is not in the cache [P1]

- **File:** `lib/utxo.ml:919-927` (`UtxoCache.add_coin`)
- **Core ref:** `bitcoin-core/src/coins.cpp:89-122` (`AddCoin` — no
  disk hit; uses `try_emplace`)

**Description.** Core's `AddCoin` uses `cacheCoins.try_emplace`: if
the outpoint is already in the cache (regardless of FRESH/DIRTY
state), the existing entry's flags decide whether to promote to
FRESH or DIRTY.  No call to `base->HaveCoin` is required.

camlcoin's UtxoCache.add_coin (`lib/utxo.ml:919-927`):

```ocaml
| None ->
  if not (DbView.have_coin t.parent outpoint) then
    Fresh coin
  else begin
    if not possible_overwrite then
      failwith (...);
    Dirty coin
  end
```

`DbView.have_coin` → `Storage.ChainDB.get_utxo` → RocksDB lookup.  One
disk hit per cache-miss `add_coin`.  During IBD, every newly-created
UTXO triggers this round-trip.

**Impact.** Throughput regression on the assume_utxo / snapshot
loader path.  At ~115M UTXOs per snapshot, that's 115M extra RocksDB
point-lookups served by the disk just to populate the cache.  The
live IBD path uses `OptimizedUtxoSet` so this hazard does not affect
IBD — but it does affect every `load_snapshot` (the live consumer of
`UtxoCache`).

---

## BUG-11 — `default_max_cache_bytes = 1 GiB`; comment says "default 450MB" — Core's nCoinCacheUsage default is 450 MiB [P3 / doc drift + parity gap]

- **File:** `lib/utxo.ml:808-812` and `lib/utxo.ml:825-827`
- **Core ref:** `bitcoin-core/src/init.cpp` (`-dbcache=450` default
  in MiB)

**Description.** The constant and the comment disagree:

```ocaml
(* lib/utxo.ml:808-812 *)
(** Default max cache size: 1GB worth of entries.
    Assuming ~100 bytes per entry average, this is ~10M entries.
    Reduced from 2GB: the dirty set + LRU + OCaml GC overhead
    caused RSS to reach 12+ GB at the previous setting. *)
let default_max_cache_bytes = 1 * 1024 * 1024 * 1024

(* lib/utxo.ml:825-827 *)
(** Layered UTXO cache with parent view abstraction.
    Accumulates changes in memory and flushes to parent when:
    - Cache exceeds max_size (default 450MB)
```

Code says 1 GiB; nearby comment says 450 MB.  Core's default is 450
MiB (operator override via `-dbcache=<MiB>`).

There is also no `-dbcache` CLI flag in camlcoin (`grep dbcache` over
`bin/main.ml` and `lib/runtime_config.ml` returns 0 hits) — so the
operator has no knob to widen the cache for low-end IBD or shrink it
on a memory-constrained VPS.

**Impact.** Comment-vs-code drift; soft Core-parity gap (no operator
knob).  Severity P3.

---

## BUG-12 — `UtxoCache.needs_flush` / `maybe_flush` are defined but never called outside `utxo.ml` — the size-based flush trigger is dead [P1]

- **File:** `lib/utxo.ml:1017-1024`
- **Core ref:** `bitcoin-core/src/validation.cpp:2702-2855`
  (`FlushStateToDisk` — IF_NEEDED / PERIODIC / ALWAYS modes, all
  size-driven)

**Description.** `grep -rn "needs_flush\|maybe_flush" lib/` returns
matches ONLY inside `utxo.ml` itself.  No consumer calls them.
Consequently the size-based flush trigger never fires; the live IBD
path flushes on a fixed block interval (`utxo_flush_interval = 500`,
`sync.ml:1519`) plus a fixed dirty-count gate
(`sync.ml:2574-2575: dirty_count > 500_000`).  No memory-pressure gate.

Core's `FlushStateToDisk` uses (validation.cpp:2786-2810) a 5-mode
state machine:

- `NONE` — only commit if there's free space
- `IF_NEEDED` — cache-size gate
- `PERIODIC` — every 1hr or 24hr depending on PERIODIC vs LARGE
- `ALWAYS` — wallet-eviction triggers
- `FORCE_FLUSH` — shutdown / assume-utxo / reorg

camlcoin has none of these; the trigger is a two-line block-count
heuristic that ignores the configured `default_max_cache_bytes`
entirely.

**Impact.** Heavy IBD on a node with 32 GiB RAM and a 450 MiB target
cache will overshoot the target by 50-100× before the block-count
gate trips at 500 blocks.  The cache grows until the 500-block window
elapses, then dumps the whole batch — RocksDB's WAL backs up, IBD
stalls.

---

## BUG-13 — no `BatchWrite` chunking; the full dirty set is committed in one RocksDB WriteBatch (`approximate_size` / `batch_write_bytes` absent) [P1]

- **File:** `lib/utxo.ml:455-495` (`OptimizedUtxoSet.flush`) +
  `lib/rocksdb_store.ml:77-96` (`flush_dirty`) +
  `lib/cf_chainstate.ml:424-426` (`batch_write`)
- **Core ref:** `bitcoin-core/src/txdb.cpp:131-154`
  (`CCoinsViewDB::BatchWrite` flushes a partial batch when
  `batch.ApproximateSize() > m_options.batch_write_bytes`; default
  `batch_write_bytes = 16 MiB`)

**Description.** Core caps any single leveldb WriteBatch at ~16 MiB
to keep the WAL bounded.  When the dirty set exceeds the cap, Core
writes the partial batch, clears it, optionally simulates a crash
(`simulate_crash_ratio`), and continues.

camlcoin builds a single Hashtbl with EVERY dirty entry, serializes
each one, and submits the entire WriteBatch to RocksDB in one call
(`rocksdb_store.ml:77-96`):

```ocaml
let flush_dirty ?(tip_height : int option) (t : t)
    (dirty : (string, [ `Added of Cstruct.t | `Removed ]) Hashtbl.t) : unit =
  let wb = Rocksdb.write_batch_create () in
  Hashtbl.iter (fun key entry -> ...) dirty;
  ...
  Rocksdb.write_batch_write t.db wb;
  Rocksdb.write_batch_destroy wb
```

For a 4M-entry LRU + ~500K dirty entries averaging 50 bytes/value,
that's a ~25 MiB WriteBatch per flush — within RocksDB's tolerance.
But the legacy `OptimizedUtxoSet.flush` ALSO supports the LogStorage
backend (`lib/utxo.ml:475-491`) which has no WAL size limit; if a
500K-entry batch is built, the OCaml process holds 500K serialized
strings + the WriteBatch in memory before the commit returns.

**Impact.** Throughput-cliff at very large flush windows.  Not a
correctness issue on the current code paths (rocksdb_utxo is the live
backend, RocksDB handles 25 MiB batches), but it does foreclose a
future scenario where the cache target moves to 4-8 GiB.

---

## BUG-14 — no `WARN_FLUSH_COINS_COUNT` / no `simulate_crash_ratio` / no `CheckDiskSpace` gate [P2]

- **File:** `lib/utxo.ml:455-495` (flush path) +
  `lib/cli.ml:1682-1704` (shutdown flush)
- **Core ref:** `bitcoin-core/src/txdb.cpp:30` (`WARN_FLUSH_COINS_COUNT
  = 10_000_000`) + `bitcoin-core/src/txdb.cpp:147-153`
  (`simulate_crash_ratio`) + `bitcoin-core/src/validation.cpp:2750+`
  (`CheckDiskSpace`)

**Description.** Core warns on flushes larger than 10M entries
("Flushing large (%d entries) UTXO set to disk, it may take several
minutes") and supports `-dbcrashratio` for chaos-testing the
crash-recovery path.  Before every flush, Core calls
`CheckDiskSpace(MIN_DISK_SPACE_FOR_BLOCK_FILES)` (50 MiB).

camlcoin has none of these.  No warn-on-large flush, no chaos knob,
no disk-space pre-check.

**Impact.** Operator UX gap.  W100 BUG-5 documented the disk-space
pre-check absence; this BUG re-anchors it because the W100 fix never
landed.  On a full disk, RocksDB returns an error from
`write_batch_write` and `Rocksdb.write_batch_write` raises an OCaml
exception; the IBD loop bubbles it up and the daemon exits.  Better
than silent corruption, worse than Core's pre-flush check.

---

## BUG-15 — `tip_hash` and `tip_height` are TWO SEPARATE chain_state keys, not a single packed `DB_BEST_BLOCK` uint256 [P1]

- **File:** `lib/cf_chainstate.ml:273-277` +
  `lib/storage.ml:662-695` (`set_chain_tip`, `get_chain_tip`,
  `set_header_tip`, `get_header_tip`)
- **Core ref:** `bitcoin-core/src/txdb.cpp:24, 85-90`
  (`DB_BEST_BLOCK='B'` — single key, value = `uint256`)

**Description.** Core stores `hashBestChain` under the single 1-byte
key `'B'`.  The height is NOT stored on disk; it is recovered from
the block index at startup (`BlockMap` keyed by `hashBlock`).
Storing only the hash means there is exactly one byte that can be
torn during a flush — the value, which is 32 bytes, is committed
atomically as a single leveldb entry.

camlcoin stores FOUR keys: `tip_hash`, `tip_height`,
`header_tip_hash`, `header_tip_height`.  Each is committed as a
separate KV op inside a single RocksDB WriteBatch.  RocksDB
guarantees the batch is all-or-nothing, so atomicity is preserved
within ONE batch.  But:

1. `set_chain_tip` and `set_header_tip` use SEPARATE batches
   (`lib/storage.ml:662-668, 680-686`).  A crash between them leaves
   `chain_tip` advanced + `header_tip` stale (or vice versa).
2. The hash and height of the tip are decoupled: if a coding bug
   writes one but not the other, `get_chain_tip` returns the partial
   state as `Some (hash, 0)` or panics on `decode_height` if the
   value is corrupt.

**Excerpt** (`lib/storage.ml:662-686`):

```ocaml
let set_chain_tip t (hash : Types.hash256) (height : int) =
  let batch = Cf_chainstate.batch_create t.cf in
  Cf_chainstate.batch_put_chain_state batch "tip_hash"
    (Cstruct.to_string hash);
  Cf_chainstate.batch_put_chain_state batch "tip_height"
    (encode_height height);
  Cf_chainstate.batch_write batch
(* and below: set_header_tip in a SEPARATE batch *)
let set_header_tip t (hash : Types.hash256) (height : int) =
  let batch = Cf_chainstate.batch_create t.cf in
  Cf_chainstate.batch_put_chain_state batch "header_tip_hash"
    (Cstruct.to_string hash);
  Cf_chainstate.batch_put_chain_state batch "header_tip_height"
    (encode_height height);
  Cf_chainstate.batch_write batch
```

**Impact.** Latent atomicity gap.  In practice the live code paths
that call `set_chain_tip` (sync.ml, cli.ml, block_import.ml) also
call `set_header_tip` later, so the gap is brief.  But there's no
single Core-parity API surface (`SetBestBlock(uint256)`) — and
operators reading the chainstate via debugging tools must remember to
read TWO keys.

---

## BUG-16 — `set_chain_tip` writes the tip OUTSIDE the UTXO mutation batch in the live IBD path (`sync.ml:2578-2582`) [P0]

- **File:** `lib/sync.ml:2568-2588` (the periodic flush gate in the
  IBD `step` loop)
- **Core ref:** `bitcoin-core/src/txdb.cpp:100-164`
  (`BatchWrite` writes coins + BEST_BLOCK in ONE batch)

**Description.** Core's per-flush invariant: coins + best-block hash
are written in a single leveldb batch.  Crash between coins and
best-block is impossible.

camlcoin's IBD periodic flush:

```ocaml
(* lib/sync.ml:2578-2582 *)
if ibd.blocks_since_flush >= utxo_flush_interval || dirty_too_large then begin
  flush_utxos ibd;           (* batch 1: UTXO mutations into rocksdb_utxo *)
  ibd.blocks_since_flush <- 0;
  (* Also update chain tip in DB *)
  Storage.ChainDB.set_chain_tip ibd.chain.db entry.hash height;
                              (* batch 2: chain_tip into cf_chainstate, SEPARATE batch *)
```

Two RocksDB batches.  Crash between them leaves `rocksdb_utxo` ahead
of `cf_chainstate.tip_hash`.  The boot consistency check
(`lib/cli.ml:380-394`) rewinds `chain.blocks_synced` to whichever is
lower — but the recovery semantics work ONLY because IBD is
idempotent over the gap.  Outside IBD (e.g. via `block_import`),
re-validation is not guaranteed.

**Impact.** Latent loss-of-atomicity hazard during IBD.  Cross-cites
the comment-as-confession at `lib/storage.ml:625-629` (BUG-4 above).
The boot consistency check paper-overs the gap during normal IBD;
it does not cover the assume_utxo activation path or any future
"snapshot-then-resume" mode.

---

## BUG-17 — `apply_block_atomic` commits cf_chainstate FIRST, rocksdb_utxo SECOND — two separate commits, not one atomic write [P0]

- **File:** `lib/storage.ml:621-659` (`apply_block_atomic`)
- **Core ref:** `bitcoin-core/src/txdb.cpp:100-164`
  (`CCoinsViewDB::BatchWrite` — one leveldb batch, one commit)

**Description.** `apply_block_atomic` advertises atomicity in its
name and comment ("Atomically apply a block's UTXO delta and advance
both backends' tips"), but the implementation commits TWO RocksDB
DBs SEQUENTIALLY:

```ocaml
(* lib/storage.ml:656-659 *)
Cf_chainstate.batch_write cf_batch;          (* commit 1: cf_chainstate *)
(match t.rocksdb_utxo with
 | None -> ()
 | Some r -> Rocksdb_store.batch_write ~tip_height r rdb_ops)  (* commit 2: rocksdb_utxo *)
```

The two batches go to TWO DIFFERENT RocksDB instances (different
WALs, different SST trees).  A crash between them leaves one
authoritative and one stale.  The comment at `lib/storage.ml:625-629`
admits the asymmetry but only handles the `rdb < chain_tip` case
(`cli.ml:380-394`).

Atomicity claim in the function name is misleading.  Core's
`apply_block_atomic`-equivalent is a single `m_db->WriteBatch(batch)`
call; the property is "single underlying leveldb commit," not
"sequence of commits where the recovery code papers over the gap."

**Excerpt** (`lib/storage.ml:630-659`).

**Impact.** Same family as BUG-4 / BUG-16.  Latent torn-write
across two RocksDB instances.  Aggravated by BUG-7 (the two stores
already DIVERGE during IBD because `OptimizedUtxoSet.flush` only
writes to one of them).

---

## BUG-18 — no `Cursor()` analog: `iter_utxos` is a callback iterator that cannot be paused, passed between threads, or scoped to a key prefix [P1]

- **File:** `lib/storage.ml:822-833` (`iter_utxos`) +
  `lib/cf_chainstate.ml:330-331, 346-347, 450-456` (`cf_iter`)
- **Core ref:** `bitcoin-core/src/coins.h:228-245`
  (`CCoinsViewCursor`)

**Description.** Core exposes `CCoinsViewCursor` as an abstract
iterator: `Valid()`, `Next()`, `GetKey`, `GetValue`, `GetBestBlock`.
Consumers (e.g. `dumptxoutset`, `gettxoutsetinfo`,
`MuHashCoinSet`) use it to stream the UTXO set with backpressure.

camlcoin exposes only `iter_utxos t f` — a callback that runs to
completion or panics.  No early stop, no resumption, no cursor object
to pass into a worker thread.  Inside `cf_chainstate.cf_iter`, the
underlying RocksDB iterator is created and destroyed in one call.

**Impact.** Functionality gap.  `dumptxoutset` is forced to buffer
the entire UTXO set in OCaml lists before writing (`utxo.ml:271-293`,
`mining.ml:892-902`, `assume_utxo.ml:783-820`) — RSS spike of ~3-5
GiB on mainnet (115M coins × ~38 bytes plus pointer overhead).  An
RPC `interruptionRequested` flag is impossible to honour mid-iter
because there's no way to stop the C++ side.

---

## BUG-19 — `iter_utxos` iterates ONLY `cf_chainstate.utxo` CF, NOT `rocksdb_utxo` — partial set returned for any caller post-IBD [P0]

- **File:** `lib/storage.ml:822-833`
- **Core ref:** `bitcoin-core/src/coins.h:336` (`Cursor()` — single
  store, no fallback)

**Description.** As established in BUG-7, the live IBD path writes
to `rocksdb_utxo` only.  `iter_utxos` (`lib/storage.ml:822`) reads
from `t.cf.cfh_utxo` — the cf_chainstate UTXO CF, which is empty
during IBD.

```ocaml
let iter_utxos t f =
  Rocksdb.cf_iter t.cf.db t.cf.cfh_utxo (fun key value ->
    if String.length key = 36 then begin
      ...
      f txid vout value
    end)
```

No fallback to `t.rocksdb_utxo`.  Every consumer
(`utxo.ml:277`, `mining.ml:894`, `rpc.ml:7123-7244`,
`rpc.ml:7322-7356`, `assume_utxo.ml:783, 805, 872, 912`) gets the
empty CF result.

**Impact.** Compounds BUG-7.  Every RPC that calls iter_utxos
(`gettxoutsetinfo`, `scantxoutset`, `compute_utxo_hash`,
`compute_utxo_muhash`, `dumptxoutset`) returns an empty or
post-IBD-only UTXO set on a node that has run an IBD.  This is the
direct cause of the 51-byte snapshot the BUG-7 comment documents.

---

## BUG-20 — `set_chain_tip (Cstruct.create 32) 0` writes a 32-byte zero hash for "reset"; `get_chain_tip` returns `Some (00…00, 0)`, indistinguishable from a valid hash-zero tip [P2]

- **File:** `lib/cli.ml:380-394`
- **Core ref:** `bitcoin-core/src/txdb.cpp:85-90` (`GetBestBlock` —
  returns `uint256()` when key is missing, treats missing-key as
  "empty chainstate")

**Description.** Core's chainstate boot uses missing `DB_BEST_BLOCK`
as the unambiguous signal "fresh / empty chainstate."  No key, no
value — `GetBestBlock` returns `uint256{}` (the null hash) only by
default, distinct from an existing key whose value is all-zero.

camlcoin's reset path:

```ocaml
(* lib/cli.ml:387-388 *)
chain.blocks_synced <- 0;
Storage.ChainDB.set_chain_tip db
  (Cstruct.create 32) 0
```

Writes a 32-byte zero buffer as the value.  `get_chain_tip` later
reads back `Some (Cstruct of 32 zeros, 0)` — not `None`.

```ocaml
(* lib/storage.ml:670-677 *)
let get_chain_tip t : (Types.hash256 * int) option =
  match Cf_chainstate.get_chain_state t.cf "tip_hash",
        Cf_chainstate.get_chain_state t.cf "tip_height" with
  | Some hash_str, Some height_str ->
    let hash = Cstruct.of_string hash_str in
    let height = decode_height height_str in
    Some (hash, height)
  | _ -> None
```

**Impact.** Diagnostic ambiguity.  A debugger comparing tip_hash to
`Cstruct.create 32` cannot tell whether the chainstate was reset or
whether someone wrote a literal zero-hash value (which CAN appear in
some testnets via the all-zero pre-block).  Severity P2 because the
height = 0 disambiguates in practice, but the API surface is muddier
than Core.

---

## BUG-21 — `decode_height` uses `Int32.to_int` on a big-endian uint32 — heights between 2^31 and 2^32 silently corrupt on 32-bit builds [P3]

- **File:** `lib/cf_chainstate.ml:199-201` (`decode_height`)
- **Core ref:** Core stores no height key (BUG-15 cross-cite); height
  is `int` (signed 64-bit).

**Description.** OCaml's `int` on 32-bit native is 31 bits; on 64-bit
native it is 63 bits.  `Int32.to_int` on a 32-bit build silently
overflows when the int32 has the high bit set (i.e. `height >
0x7fff_ffff`, which is ~2.1 billion blocks ≈ 40,000 years at 10
min/block).  Cosmetic — but the OCaml convention is to use `Int32` end-to-end or assert the platform is 64-bit.

Also: `encode_height` accepts OCaml `int` and silently truncates to
int32:

```ocaml
let encode_height (h : int) : string =
  let cs = Cstruct.create 4 in
  Cstruct.BE.set_uint32 cs 0 (Int32.of_int h);
  Cstruct.to_string cs
```

`Int32.of_int 2_500_000_000` is silently negative — no overflow check.

**Impact.** P3, far-future correctness only.

---

## BUG-22 — height is stored on disk as 4-byte big-endian; Core uses VARINT for the in-coin height field (huge size win) [P3]

- **File:** `lib/cf_chainstate.ml:194-197` (`encode_height`) +
  `lib/utxo.ml:30` (in-coin height write_int32_le)
- **Core ref:** `bitcoin-core/src/coins.h` `Coin::Serialize` —
  `VARINT((height << 1) | isCoinbase)` packs height + coinbase flag
  into 1 byte for heights ≤ 63 (every coinbase up to mainnet h≈64).

**Description.** Two height storage sites, both fixed-width:

1. `cf_chainstate.encode_height` (height→hash CF): 4-byte BE.  Core
   doesn't store this at all (built from the block index at startup).
2. `utxo.serialize_utxo_entry` (per-coin height): 4-byte LE + 1-byte
   is_coinbase = 5 bytes.  Core packs both into a varint = 1 byte for
   recent heights (the common case mid-IBD).

The 4 bytes (vs Core's 1-byte typical) × 115M UTXOs ≈ +450 MiB on
mainnet just for the height field.

**Impact.** Disk bloat, cosmetic.  P3.

---

## BUG-23 — `OptimizedUtxoSet` has no FRESH/DIRTY/ERASED accounting; spend-of-just-added is two ops instead of one [P0]

- **File:** `lib/utxo.ml:313-557` (`OptimizedUtxoSet`)
- **Core ref:** `bitcoin-core/src/coins.cpp:153-175` (`SpendCoin` —
  Fresh entries are ERASED entirely, never propagated to parent)

**Description.** `OptimizedUtxoSet` uses a 2-state dirty hashtable
(`Added of utxo_entry | Removed`).  There is no FRESH flag; every
spend writes a `Removed` tombstone to the dirty hashtable, even when
the same outpoint was Added in the SAME flush window.

The `remove_fast` helper (`utxo.ml:426-435`) DOES short-circuit when
the entry is currently Added:

```ocaml
match Hashtbl.find_opt t.dirty key with
| Some (`Added _) ->
  (* Created and spent in same flush window — just remove both *)
  Hashtbl.remove t.dirty key
| _ ->
  Hashtbl.replace t.dirty key `Removed
```

But the regular `remove` (L394-419) does not.  Result: in the live
IBD path, every "create-and-spend-in-same-block" outpoint (typical
for chained intra-block tx) triggers a write of `Added` + a write
of `Removed` to the dirty set, even though both will cancel out at
flush time.

`remove_fast` is called in approximately one site (lib/sync.ml: spent
outpoints during IBD).  `remove` is the API used by mining,
block_import, reorg.  The lack of FRESH means a reorg-spend of a
recent UTXO writes the Removed marker that propagates to disk; on
flush the entry is deleted from `rocksdb_utxo` — and then on the
re-add (next block in the new chain), a new key is written.  Net
effect: O(n) writes per reorg even when the same coins re-appear.

**Impact.** Throughput regression on reorgs and IBD.  Cross-cites
W100 BUG-8 ("Fresh→spend removes entry entirely; subsequent add_coin
sees cache-miss"); this BUG re-anchors that against the live path.

---

## BUG-24 — `OptimizedUtxoSet.remove` performs disk fallback then unconditionally writes `Removed` — race window where entry is missing from cache AND not yet flushed [P1 / W100 BUG-9 carry-forward]

- **File:** `lib/utxo.ml:394-419` (`OptimizedUtxoSet.remove`)
- **Core ref:** `bitcoin-core/src/coins.cpp:153-175` (`SpendCoin` —
  single-step state transition: cache fetch → mark spent, no removal
  from cache)

**Description.** Carry-forward of W100 BUG-9:

```ocaml
let remove (t : t) (txid : Types.hash256) (vout : int)
    : utxo_entry option =
  let key = utxo_key txid vout in
  (* Try to find existing entry: LRU cache, dirty set, then DB *)
  let existing = ... (* possibly disk read *) ... in
  Perf.LRU.remove t.cache key;
  Hashtbl.replace t.dirty key `Removed;
  existing
```

Between `Perf.LRU.remove` and `Hashtbl.replace`, a concurrent
`exists` call (line 437-448) that races into the `None` cache-miss
branch will hit the DB-fallback path and observe the entry as still
present (because the flush has not yet committed the Removed
tombstone).  OCaml is single-threaded so the actual race is not
between OS threads but between Lwt fibers that yield — and `exists`
does not yield, so the actual window is bounded.

Still, the API contract is non-trivial: `remove` returns the spent
entry but ALSO commits a `Removed` flag; a caller that calls `remove`
purely to read the entry pollutes the dirty set with a tombstone.

**Impact.** Soft semantics gap.  P1 because OCaml's single-thread
serialization papers over the race; correctness restored if the
Lwt scheduler interleaves an `exists` between the two statements
(it currently does not, but future async refactors could).

---

## BUG-25 — `clear_cache` silently drops un-flushed dirty entries [P1 / W100 BUG-10 carry-forward]

- **File:** `lib/utxo.ml:551-556`
  (`OptimizedUtxoSet.clear_cache`) + `lib/utxo.ml:1036-1042`
  (`UtxoCache.clear`)
- **Core ref:** `bitcoin-core/src/coins.cpp:302-308`
  (`CCoinsViewCache::Reset` — Asserts/clears cleanly because it's
  only called when the caller knows there's nothing dirty)

**Description.**

```ocaml
let clear_cache t =
  Perf.LRU.clear t.cache;
  Hashtbl.clear t.dirty;
  t.stats <- Perf.create_utxo_stats ()
```

Drops the dirty hashtable without checking `Hashtbl.length t.dirty > 0`.
If a caller invokes `clear_cache` after a `connect_block_optimized`
mutated the dirty set but before the periodic flush fired, every
UTXO mutation from that block is silently lost.

Same hazard in `UtxoCache.clear` (L1036).

**Impact.** Latent silent corruption hazard.  Currently no
production caller invokes `clear_cache` between mutation and flush,
but the API admits the failure mode.  W100 BUG-10 already documented
this; carry-forward re-anchor.

---

## BUG-26 — `dirty_count > 500_000` is the only memory-pressure gate for the live IBD flush; no byte-size accounting [P2]

- **File:** `lib/sync.ml:2574-2577`
- **Core ref:** `bitcoin-core/src/validation.cpp:2780-2790`
  (`if (cache_size > nCoinCacheUsage)`)

**Description.** Core's IBD flush trigger is byte-size on
`pcoinsTip->DynamicMemoryUsage()`.  camlcoin uses dirty entry count
on the live path:

```ocaml
(* lib/sync.ml:2574-2577 *)
let dirty_too_large = match ibd.utxo_set with
  | Some utxo -> Utxo.OptimizedUtxoSet.dirty_count utxo > 500_000
  | None -> false
in
```

A 500K-entry dirty set with all P2WSH 34-byte scripts is ~17 MiB.
With all 280-byte witness commitments it's ~140 MiB.  The byte cost
swings by 10× depending on script type, and the gate fires at the
same entry count regardless.

The `OptimizedUtxoSet.t` record exposes no `memory_usage`
field — only `dirty_count` (`utxo.ml:537-539`).

**Impact.** IBD pressure-flush tuning is decoupled from actual RAM
pressure.  Operator on 8 GiB RAM may OOM during a witness-heavy
spike (e.g. inscription-heavy blocks 800K-820K); operator on 128 GiB
flushes too aggressively on a P2WPKH spike.

---

## BUG-27 — no `ChainStateFlushed` / `UpdatedBlockTip` signal emitted after a flush completes [P2 / W100 BUG-6 carry-forward]

- **File:** `lib/utxo.ml:455-495`, `lib/sync.ml:1958-1980`
  (flush sites — no signal callback)
- **Core ref:** `bitcoin-core/src/validation.cpp:2835`
  (`signals.ChainStateFlushed`) called after every flush

**Description.** Core fires `signals->ChainStateFlushed(hashBlock)`
after every flush so wallet / index subscribers can persist their
own state at a known-good chain height.  camlcoin's flush emits a
single debug log line:

```ocaml
Logs.debug (fun m -> m "Flushed %d dirty UTXO entries to disk" count)
```

No callback, no ZMQ notification, no signal.

**Impact.** Wallet-state and index re-derivation cannot synchronise
with chainstate flushes.  P2 — the live wallet path in camlcoin is
minimal so the consequence is mostly latent.

---

## BUG-28 — no `Uncache` API to forget a clean parent-fetched entry; LRU eviction is the only mechanism, no Core-equivalent precise drop [P3]

- **File:** `lib/utxo.ml:313-557` (`OptimizedUtxoSet`) +
  `lib/utxo.ml:830-1052` (`UtxoCache`)
- **Core ref:** `bitcoin-core/src/coins.cpp:310-330`
  (`CCoinsViewCache::Uncache`)

**Description.** Core's `Uncache(outpoint)` drops a specific outpoint
from the cache without affecting any flags or DIRTY entries.  Used by
mempool-eviction logic when a tx is removed and its inputs no longer
need to stay hot.

camlcoin's caches only support LRU eviction (`Perf.LRU.put` reaches
capacity and drops the oldest entry).  No precise `Uncache`.  A
caller that wants to drop a specific outpoint must either wait for
LRU eviction or call `remove`, which writes a `Removed` tombstone
(wrong semantics — the outpoint is unspent, not spent).

**Impact.** Cosmetic API gap.  P3.

---

## BUG-29 — `OptimizedUtxoSet.dirty` Hashtbl uses string keys; outpoint key construction allocates a `Bytes.create 36` per access (utxo_key) [P3 perf]

- **File:** `lib/utxo.ml:332-341` (`OptimizedUtxoSet.utxo_key`)
- **Core ref:** `bitcoin-core/src/coins.h` (`COutPoint` is a POD,
  hashed by `SaltedOutpointHasher` with no allocation)

**Description.** Every `get` / `add` / `remove` / `exists` / `flush`
constructs a fresh 36-byte `Bytes.create` per call (`utxo.ml:333-341`).
At ~115M UTXOs and ~4-5 UTXO ops per tx, this is ~500M allocations
per IBD just for cache keys.

OCaml's minor heap absorbs these but the GC compaction churn is
visible.  Core uses an open-addressing hashmap keyed on the raw
`COutPoint` struct, no hashing-allocation overhead.

**Impact.** P3 perf — RSS / GC pause time during IBD.

---

## BUG-30 — `MoneyRange` is NOT validated on UTXO deserialize; a corrupted on-disk value field can produce negative or > MAX_MONEY input sums [P0]

- **File:** `lib/utxo.ml:34-40` (`deserialize_utxo_entry`),
  `lib/utxo.ml:766-773` (`DbView.deserialize_coin`)
- **Core ref:** `bitcoin-core/src/consensus/amount.h:27`
  (`MoneyRange`) called in `Coin::Unserialize` → triggers an assertion
  if `CompressAmount` decodes to out-of-range.

**Description.** camlcoin's `deserialize_utxo_entry`:

```ocaml
let deserialize_utxo_entry r : utxo_entry =
  let value = Serialize.read_int64_le r in       (* NO MoneyRange check *)
  let script_len = Serialize.read_compact_size r in
  let script_pubkey = Serialize.read_bytes r script_len in
  let height = Int32.to_int (Serialize.read_int32_le r) in
  let is_coinbase = Serialize.read_uint8 r <> 0 in
  { value; script_pubkey; height; is_coinbase }
```

A corrupted-on-disk 8-byte LE value that decodes to `Int64.min_int`
(or 21M+1) is accepted silently.  Downstream
`connect_block_optimized` (`utxo.ml:609`):

```ocaml
input_sum := Int64.add !input_sum entry.value;
```

`Int64.add` wraps on overflow — a poisoned UTXO with value =
`Int64.max_int` plus any other input makes `input_sum` wrap to
negative, which then satisfies `output_sum > !input_sum` (now false)
and the block is accepted.

Worse: `Consensus.is_valid_money` IS checked in `validation.ml`
(L823) when summing outputs — but NOT when reading inputs from the
UTXO set.  A poisoned UTXO entry is the missing fence.

**Impact.** Latent vulnerability if disk corruption or attacker-write
to the chainstate file occurs.  Lower than P0-CONSENSUS because
exploit requires write-to-disk attacker — but Core treats this as a
mandatory `Assert` (chainstate corruption → fail-fast).  Severity P0
because the missing fence enables silent over-spend on any chain
build atop a corrupted chainstate, and there is no MoneyRange check
on read at any of the four deserialize sites.

---

## Fleet patterns observed

- **Two-pipeline guard, chainstate persistence**: TWO parallel UTXO
  stores (`chainstate-rocks/utxo` CF and `rocksdb_utxo/`) coexist on
  disk.  The IBD path writes to one, the mining path writes to both,
  iter_utxos reads only the first.  Cross-cite: this is the
  **N-th distinct extension** of the W76+ two-pipeline guard pattern
  (camlcoin W141 was the 14th overall; this is the chainstate
  manifestation).  BUG-7 and BUG-19 are the proximate consequences.
- **Dead class with full method surface (W138 fleet-pattern, 9/10
  impls)**: `Utxo.UtxoCache` is a faithful CCoinsViewCache port with
  Fresh/Dirty/Erased + memory tracking + needs_flush.  Zero live
  callers.  BUG-5 catalogues this directly; BUG-12 catalogues the
  dead size-based flush trigger inside it.  This is the 9-of-10 →
  **10-of-10 fleet-wide assumeUTXO dead-class pattern**.
- **Comment-as-confession** (4 instances within this audit, the
  cumulative quad-wave is now well past a dozen):
  - `lib/utxo.ml:875-879` — admits `get_coin` marks read-through as
    `Dirty` for "simplicity"
  - `lib/storage.ml:625-629` — admits the two-batch commit window in
    `apply_block_atomic` is "handled" by a boot rewind, not avoided
  - `lib/utxo.ml:497-511` — admits `flush` skips cf_chainstate
  - `lib/utxo.ml:808-812` — comment says 450MB, code says 1 GiB
- **Carry-forward re-anchor (4th instance in this campaign)**: W100
  BUG-1 / BUG-9 / BUG-10 / BUG-6 re-anchored here as BUG-9 / BUG-24 /
  BUG-25 / BUG-27.  The W100 fixes never landed; the bugs continue
  to bite.
- **Compressor-half-wired**: `lib/compressor.ml` ships a faithful
  port of `CompressAmount` / `CompressScript`, including the
  libsecp256k1 on-curve check.  Only `assume_utxo` uses it.  The
  live read/write path uses raw 8-byte LE + 4-byte LE + 1-byte cb.
  Same shape as W141 `compress_amount` half-wire-ups (camlcoin
  W141 7th two-pipeline extension).
- **Obfuscation-half-implemented**: mempool.dat correctly XORs values
  on read/write; chainstate values are stored raw.  Same shape as the
  compressor half-wire.

---

## Surface count summary

- **P0-SEC**: 1 (BUG-3, obfuscation absent)
- **P0-CONSENSUS**: 1 (BUG-6, AddCoins overwrite false on coinbase
  in assume_utxo)
- **P0**: 9 (BUG-1, 2, 4, 5, 7, 8, 16, 17, 19, 23, 30)
- **P1**: 7 (BUG-9, 10, 12, 13, 15, 24, 25)
- **P2**: 3 (BUG-14, 26, 27)
- **P3**: 4 (BUG-11, 20, 21, 22, 28, 29)

(Some bugs span multiple severities; the count above uses primary
classification.)

Total: 30 bugs catalogued.

The biggest-magnitude finding is the cluster of **BUG-1 + BUG-2 +
BUG-3 + BUG-4 + BUG-7 + BUG-19**: camlcoin's chainstate is
byte-incompatible with Core at every layer of the persistence stack,
and the two parallel UTXO stores on disk diverge during every IBD.
The biggest-risk finding is **BUG-30** (no MoneyRange check on
UTXO deserialize) — a corrupted disk entry can produce silent
over-spend.  The most actionable single-line fix is **BUG-11** (the
default-cache-size comment vs code drift); the most actionable
architectural fix is **BUG-7+19** (route `OptimizedUtxoSet.flush`
through `persist_dirty_atomic` so both stores stay in sync).
