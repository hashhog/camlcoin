# W138 assumeUTXO snapshots — camlcoin (OCaml)

Wave: W138 — assumeUTXO snapshot load / dump / background validation
(`loadtxoutset` / `dumptxoutset` / `getchainstates` parity, plus the
in-memory dual-chainstate plumbing Core's `ChainstateManager` needs).

This is the SECOND assumeUTXO discovery wave in camlcoin's history. W102
(commit `cb6130a`, May 12 2026) catalogued 15 bugs across the
metadata/coin/checksum and load-time-preconditions surface (B1-B15), most
of which were subsequently closed in commit `ab6025c`
("fix(snapshot): AssumeUTXO load-time validation guards (W102 B1-B7)").
W138 expands the surface beyond the W102 footprint, focusing on:

- Wire-format alignment with Core's `SnapshotMetadata` (5-byte magic vs
  4-byte `MessageStartChars`, version handling, throw-shape vs
  result-shape).
- `ActivateSnapshot` / `MaybeValidateSnapshot` lifecycle gates that exist
  in Core but have no camlcoin analog (`m_target_blockhash`,
  `InvalidateCoinsDBOnDisk`, `BLOCK_OPT_WITNESS` faking on the snapshot
  chain index, `m_chain_tx_count` write-back, `MaybeRebalanceCaches`).
- `getchainstates` RPC (absent in camlcoin).
- RPC-side surface that Core flips on a successful `loadtxoutset`:
  `RemoveLocalServices(NODE_NETWORK)` +
  `AddLocalServices(NODE_NETWORK_LIMITED)` (W138-new).
- Per-coin sanity checks Core enforces in `PopulateAndValidateSnapshot`
  (`outpoint.n >= UINT32_MAX` check absent — W102 B1/B2 are present;
  this is a W102-overlooked vout-sanity finding).
- The `node_state` / `active_chainstate` / `background_chainstate` /
  `create_chainstate` / `has_snapshot_chainstate` /
  `run_background_validation` / `connect_block_to_cache` cluster — all
  ~210 LOC of which has zero callers (orphan code, per the W47 / W102
  cleanup epitaph at `assume_utxo.ml:1240-1273` and re-confirmed by
  full-tree grep on 2026-05-18). The W47 cleanup deleted the
  no-callers `activate_snapshot` shell but left the entire dual-state
  machinery behind it intact.

Bitcoin Core references:
- `bitcoin-core/src/node/utxo_snapshot.cpp` (94 LOC) — `WriteSnapshotBaseBlockhash`,
  `ReadSnapshotBaseBlockhash`, `FindAssumeutxoChainstateDir`.
- `bitcoin-core/src/node/utxo_snapshot.h` (136 LOC) — `SnapshotMetadata`
  Serialize/Unserialize, magic/version constants, `SNAPSHOT_BLOCKHASH_FILENAME`,
  `SNAPSHOT_CHAINSTATE_SUFFIX`.
- `bitcoin-core/src/validation.cpp:5588-6232` — `ChainstateManager::ActivateSnapshot`,
  `PopulateAndValidateSnapshot`, `MaybeValidateSnapshot`,
  `LoadAssumeutxoChainstate`, `AddChainstate`,
  `Chainstate::InvalidateCoinsDBOnDisk`.
- `bitcoin-core/src/rpc/blockchain.cpp:3072-3519` — `dumptxoutset`,
  `loadtxoutset`, `getchainstates`, `PrepareUTXOSnapshot`,
  `WriteUTXOSnapshot`, `CreateUTXOSnapshot`.
- `bitcoin-core/src/kernel/chainparams.cpp` — `m_assumeutxo_data`,
  `AssumeutxoForBlockhash`, `AssumeutxoForHeight`,
  `GetAvailableSnapshotHeights`.

BIPs: **none** (assumeUTXO is a Core-internal optimization, not a
consensus / wire BIP). However it interacts with BIP-159 (NODE_NETWORK_LIMITED)
on the network-services side and BIP-113 (median-time-past) on the
background-validation side (W102 B12 still open).

## Methodology

1. Read Core refs (`node/utxo_snapshot.{h,cpp}`, validation
   `ActivateSnapshot` through `InvalidateCoinsDBOnDisk`,
   `rpc/blockchain.cpp` `dumptxoutset` + `loadtxoutset` +
   `getchainstates`).
2. Synthesize a 30-gate audit matrix.
3. Classify each gate against camlcoin (`lib/assume_utxo.ml` 1273 LOC,
   `lib/rpc.ml:6714-7190` handlers, `bin/main.ml:497-544` CLI).
4. Catalogue BUGs by severity (P0-CDIV / P1 / P2 / P3).
5. Write `test/test_w138_assumeutxo.ml` and register in `test/dune`.
6. Watch for universal patterns to flag for fleet sweeps.

Prior camlcoin work in this area (preserved as starting baseline):
- W102 (cb6130a + ab6025c) — load-time preconditions B1-B7
  (`coin.height > base_height`, MoneyRange, trailing bytes, header-chain
  membership, double-activation guard, mempool-empty check, work
  comparison) all CLOSED. B8-B15 remain various severities — re-pinned
  in W138 where applicable but NOT re-counted as W138 NEW.
- W47 (`cd23dac`) — `activate_snapshot` removed (no callers).
- (`a1646c6`) — atomic dumptxoutset write (`.incomplete` + fsync +
  rename) — verified.
- (`695a867`) — Full uncompressed-P2PK decompression for
  `ScriptCompression`.

## Architectural baseline (what camlcoin has, what it doesn't)

camlcoin's assumeUTXO surface lives in **one 1273-LOC file**
(`lib/assume_utxo.ml`):

- Wire format: `serialize_metadata` / `deserialize_metadata` (5-byte
  magic + version + 4-byte network_magic + 32-byte blockhash + 8-byte
  coins_count = 51 bytes total).
- Per-coin codec: `serialize_coin_body` / `deserialize_coin_body`
  (VARINT code, VARINT CompressAmount, ScriptCompression) — **byte-
  exact with Core** as of W47.
- Streaming reader (`Stream_reader`) — 1-MiB chunks, soft/hard top-up.
- Hardcoded `mainnet_au_data` for 4 heights (840k / 880k / 910k /
  935k) lifted from Core 31.99 chainparams.cpp; `testnet4_au_data` is
  an empty list (deliberately — Core has no published testnet4
  AssumeUTXO heights).
- `write_snapshot` / `iter_snapshot_coins` (atomic write protocol;
  per-txid grouping; B1/B2/B3 load-time guards from W102).
- `load_snapshot` (writes coins into a sibling `chainstate_snapshot/`
  RocksDB dir).
- `compute_utxo_hash_from_db` (HASH_SERIALIZED-equivalent SHA256d) +
  `compute_utxo_muhash_from_db` (MuHash3072 via `Muhash` module).
- `verify_loaded_utxo_hash` — strict gate matching Core
  `validation.cpp:5902-5915`.
- `verify_loaded_utxo_muhash` — for `gettxoutsetinfo "muhash"`.
- Background-validation skeleton (`run_background_validation`) — Lwt
  thread that walks IBD blocks from genesis to `target_height` and
  compares the IBD UTXO hash at the snapshot height. **Zero callers
  outside the file**, see Out-of-scope note.
- RPC handlers `handle_loadtxoutset` + `handle_dumptxoutset` +
  `parse_dumptxoutset_target` (in `lib/rpc.ml:6714-7190`).
- CLI: `--import-utxo` calls `load_snapshot` directly from
  `bin/main.ml:531`.

What camlcoin **does not** have (W138 audit surface):

- `getchainstates` RPC (Core `rpc/blockchain.cpp:3462-3519`).
- `m_target_blockhash` / `MaybeValidateSnapshot` —
  the post-load background-completion handshake that flips
  `m_assumeutxo` from `UNVALIDATED` → `VALIDATED` and renames the
  snapshot dir to `_INVALID` on failure (Core
  `validation.cpp:5967-6077`).
- `Chainstate::InvalidateCoinsDBOnDisk` — the
  `<chaindir>_INVALID` rename-on-failure forensics primitive (Core
  `validation.cpp:6201-6230`).
- `BLOCK_OPT_WITNESS` faking on every block index between
  `AFTER_GENESIS_START` and the snapshot tip (Core
  `validation.cpp:5928-5945`). camlcoin's index has no `nStatus`
  bitfield, so this is moot — but downstream
  `NeedsRedownload()` parity is also absent.
- `index->m_chain_tx_count = au_data.m_chain_tx_count` write-back at
  load (Core `validation.cpp:5949`). camlcoin stores
  `chain_tx_count` in `assumeutxo_params` (W47) but never writes it
  into the chain index — `getblockheader.nTx` for snapshot-base
  blocks is therefore wrong (or 0) until the background sync reaches
  the snapshot height.
- `WriteSnapshotBaseBlockhash` / `ReadSnapshotBaseBlockhash` —
  the `<chainstate_snapshot>/base_blockhash` sidecar file Core uses
  to reconstruct the dual-chainstate setup across restarts (Core
  `node/utxo_snapshot.cpp:22-81`). Without it, camlcoin cannot
  reconstruct a snapshot-based chainstate after a restart; the
  snapshot data sits in `chainstate_snapshot/` but the live daemon
  uses `chainstate/` (the genesis-rooted IBD chainstate).
- `FindAssumeutxoChainstateDir` — Core's startup helper
  (`node/utxo_snapshot.cpp:83-92`) that picks up the
  `<datadir>/chainstate_snapshot` dir on init.
- `NODE_NETWORK` → `NODE_NETWORK_LIMITED` swap on successful
  `loadtxoutset` (Core `rpc/blockchain.cpp:3432-3435`). camlcoin's
  `peer.ml::our_services` advertises `NODE_NETWORK` unconditionally
  after a snapshot load.
- `outpoint.n >= UINT32_MAX` sanity (Core
  `validation.cpp:5814-5816`) — present in a comment at
  `assume_utxo.ml:516` but never enforced.
- `MaybeRebalanceCaches` — cache reapportionment across snapshot
  + IBD chainstates (Core `validation.cpp:6085-6115`).
- `AddChainstate` / mempool transfer between chainstates (Core
  `validation.cpp:6170-6187`).
- `Chainstate::m_from_snapshot_blockhash` getter (`SnapshotBase`,
  Core `validation.cpp:1885-1887`) — partly emulated by
  `chainstate.from_snapshot_blockhash` but the field is set only by
  `load_snapshot`, never read by anything outside that file.
- `getchaintxstats` post-snapshot parity (Core's value derives from
  `index->m_chain_tx_count` which we don't populate).
- Snapshot-mode P2P-services bit broadcasting via `version` /
  `addr` / `addrv2` after a snapshot load.

## 30-gate matrix (W138)

### G1-G5: Wire format / metadata

- **G1: Snapshot magic prefix.** Core (`node/utxo_snapshot.h:28`):
  `SNAPSHOT_MAGIC_BYTES = {'u','t','x','o', 0xff}` — five bytes
  written by `SnapshotMetadata::Serialize` and verified by
  `Unserialize`. **camlcoin** (`assume_utxo.ml:15`): `Cstruct.of_string
  "utxo\xff"` — **byte-identical** to Core. **Match.**

- **G2: Snapshot version constant.** Core
  (`node/utxo_snapshot.h:39`): `VERSION = 2`. **camlcoin**
  (`assume_utxo.ml:18`): `snapshot_version = 2`. **Match.** Note
  camlcoin uses a single `<>` check (`version <> snapshot_version`)
  while Core uses a `std::set<uint16_t>` containment check
  (`m_supported_versions.contains(version)`). The intent is
  identical; the camlcoin form forecloses on future Core
  multi-version support (version 1 was retired before W47 anyway).

- **G3: MessageStart / network_magic.** Core stores 4 bytes from
  `pchMessageStart` (e.g. mainnet `{0xf9, 0xbe, 0xb4, 0xd9}`).
  **camlcoin** (`assume_utxo.ml:54`): `Serialize.write_int32_le w
  m.network_magic` — writes the same 4 bytes when invoked with the
  mainnet magic, but the **interpretation** differs subtly:
  camlcoin stores the magic as an int32 in HOST byte order and
  serializes LE; Core stores it as 4 raw bytes. For
  mainnet/testnet/testnet4/regtest the wire result is the same
  (verified by `test_w102_b14`), but for any future big-endian
  magic constant the camlcoin form would diverge. **P3: cosmetic
  storage-form drift** — fix is to keep a `bytes(4)` field rather
  than `int32`.

- **G4: Throw vs Result error shape on bad magic.** Core
  (`node/utxo_snapshot.h:77-79`): throws
  `std::ios_base::failure("Invalid UTXO set snapshot magic bytes...")`.
  **camlcoin** (`assume_utxo.ml:67-68`): returns
  `Error "Invalid UTXO snapshot magic bytes"` — same wording stem
  but **structurally different**: callers must match `Error` not
  catch an exception. RPC bridge in `lib/rpc.ml:6726-6728` does
  propagate the error correctly. **P3: surface-form drift, not a
  divergence.**

- **G5: Network mismatch error message.** Core
  (`node/utxo_snapshot.h:91-101`): emits two distinct error
  messages, one when the metadata's network is recognized
  ("The network of the snapshot (...) does not match the network of
  this node (...)"), the other for unknown magics
  ("This snapshot has been created for an unrecognized network..."). 
  **camlcoin** (`assume_utxo.ml:78-80`): emits one generic
  message: `"Network mismatch: snapshot is for network 0x%08lx,
  node is 0x%08lx"`. Operators don't get the human-readable network
  name ("mainnet") that Core's `ChainTypeToString` produces. **P3:
  operator-experience drift.**

### G6-G10: Lifecycle / activation gates (Core ActivateSnapshot)

- **G6: Double-activation guard.** Core
  (`validation.cpp:5600-5602`): `if (m_from_snapshot_blockhash)
  return Error "Can't activate a snapshot-based chainstate more
  than once"`. **camlcoin** (`rpc.ml:6789-6796`): probes
  `Sys.file_exists snapshot_db_path` — if `chainstate_snapshot/`
  already exists, reject with the same wording. **Match (W102 B5
  closure).** Pinned by `test_b5_double_snapshot_activation_guarded`.

- **G7: AssumeutxoForBlockhash whitelist gate.** Core
  (`validation.cpp:5603-5609`): refuses any snapshot whose
  `base_blockhash` is not in `AssumeutxoForBlockhash`; error
  enumerates available heights via `GetAvailableSnapshotHeights`.
  **camlcoin** (`rpc.ml:6745-6756`): refuses via
  `get_assumeutxo_for_hash`; error does NOT enumerate available
  heights (just emits "Assumeutxo height in snapshot metadata not
  recognized (%d) - refusing to load snapshot"). **P3: missing
  available-heights hint in error message.** Operator who hits this
  with the wrong snapshot has no way to know which heights are
  accepted without inspecting source. **NEW BUG-W138-1.**

- **G8: Base block in header chain.** Core
  (`validation.cpp:5611-5615`):
  `snapshot_start_block = m_blockman.LookupBlockIndex(base_blockhash);
  if (!snapshot_start_block) return Error "...must appear in the
  headers chain..."`. **camlcoin** (`rpc.ml:6773-6778`): uses
  `Sync.has_header`. **Match (W102 B4 closure).**

- **G9: Base block not in invalid chain.** Core
  (`validation.cpp:5617-5620`): refuses if `BLOCK_FAILED_VALID` set
  on `snapshot_start_block`. **camlcoin**: **NO equivalent check.**
  camlcoin has no per-header invalidity bitfield exposed to the
  RPC path (validity-tracking is per-block, not per-header). A
  user with a known-bad header in their chain could theoretically
  activate the snapshot against it. The risk is small (W102 B4
  already requires the header to be in the synced chain, so
  invalid headers would be rejected upstream), but the explicit
  gate is absent. **P2: belt-and-suspenders absent. NEW BUG-W138-2.**

- **G10: best_header has snapshot_start_block as ancestor.** Core
  (`validation.cpp:5622-5624`): refuses
  `!m_best_header || m_best_header->GetAncestor(snapshot_start_block->nHeight)
   != snapshot_start_block` — a forked-headers chain with more
  work than the snapshot's chain must be present. **camlcoin**:
  **NO equivalent check.** `Sync.has_header` only confirms the
  header is in the headers DB, not that it's an ancestor of the
  current best header. A user could activate a snapshot at a
  block on a stale-but-known fork. **P1: silent fork-divergence
  on snapshot activate. NEW BUG-W138-3.**

### G11-G15: Snapshot file content validation

- **G11: `coin.height > base_height` rejection.** Core
  (`validation.cpp:5814-5819`). **camlcoin**
  (`assume_utxo.ml:570-575`): present (W102 B1 closure).
  **Match.** Pinned by
  `test_b1_coin_height_exceeds_base_rejected`.

- **G12: `outpoint.n >= UINT32_MAX` rejection.** Core
  (`validation.cpp:5814-5815`): part of the SAME condition as
  G11 (joined by `||`). **camlcoin**
  (`assume_utxo.ml:516,553-569`): the comment at line 516
  documents the requirement, but **the check is NOT
  enforced**. `Serialize.read_compact_size` returns a 64-bit
  size and camlcoin clamps via `Int32.of_int vout_int` —
  values close to UINT32_MAX silently truncate to negative
  int32 and are stored as such, which then survives downstream
  rejection by `MoneyRange`/Coin checks. **P0-CDIV: a hostile
  snapshot with a vout near 2^32 could be loaded into the
  chainstate as a coin with a negative vout, which would not
  match any consensus outpoint and could be exploited by an
  attacker to plant unspendable phantom UTXOs.** Practical
  impact is low (vout-near-UINT32_MAX is not a real coin), but
  this is a documented Core check that camlcoin claims to
  enforce and does not. **NEW BUG-W138-4.**

- **G13: `MoneyRange(coin.out.nValue)` rejection.** Core
  (`validation.cpp:5820-5823`). **camlcoin**
  (`assume_utxo.ml:576-581`): present (W102 B2 closure).
  **Match.** Pinned by
  `test_b2_coin_value_exceeds_max_money_rejected`.

- **G14: Trailing bytes after coins_count rejection.** Core
  (`validation.cpp:5872-5883`). **camlcoin**
  (`assume_utxo.ml:587-594`): present (W102 B3 closure).
  **Match.** Pinned by
  `test_b3_trailing_bytes_after_coins_rejected`.

- **G15: `coins_per_txid > coins_left` rejection.** Core
  (`validation.cpp:5804-5806`). **camlcoin**
  (`assume_utxo.ml:550-552`): present. **Match.** Not in W102
  but pinned by a new W138 test.

### G16-G20: Post-load chainstate finalization

- **G16: `coins_cache.SetBestBlock(base_blockhash)` after coin
  load.** Core (`validation.cpp:5870-5893`): explicitly sets
  the coins-cache best-block to the snapshot base after the
  bulk load. **camlcoin** (`assume_utxo.ml:754-755`): uses
  `Storage.ChainDB.set_chain_tip db metadata.base_blockhash
  params.height`. **Functional match**, different primitive.

- **G17: `m_chain_tx_count = au_data.m_chain_tx_count` write-back.** Core
  (`validation.cpp:5949`): explicitly stores the hardcoded
  `chain_tx_count` (e.g. 991_032_194 for height 840k) on the
  snapshot-tip block index after load. **camlcoin**:
  `chain_tx_count` lives in `assumeutxo_params` (W47 work) but
  is **NEVER WRITTEN INTO THE BLOCK INDEX or anywhere visible
  to RPCs.** The fields `m_chain_tx_count`, `nTx` on a
  snapshot-tip header therefore stay at their default (0 or
  the IBD-computed value, which is wrong since IBD hasn't
  reached the snapshot height yet). `getblockheader` /
  `getchaintxstats` will return wrong txcount values for the
  snapshot-tip block. **P0-CDIV: client-observable wrong
  values on `getblockheader.nTx` / `getchaintxstats` after a
  successful `loadtxoutset`.** **NEW BUG-W138-5.**

- **G18: `BLOCK_OPT_WITNESS` faking on snapshot chain
  index.** Core (`validation.cpp:5928-5945`): walks the
  snapshot chain from genesis+1 to the snapshot tip, sets
  `BLOCK_OPT_WITNESS` on each index entry when segwit is
  deployment-active. Required so `Chainstate::NeedsRedownload`
  doesn't ask for `-reindex` on the next startup. **camlcoin**:
  no per-header bitfield exposed; `NeedsRedownload` itself is
  absent. **P2: would surface if camlcoin ever added
  reindex-on-witness-missing logic.** **NEW BUG-W138-6
  (precondition for a feature camlcoin doesn't have yet).**

- **G19: `WriteSnapshotBaseBlockhash` sidecar after load.** Core
  (`node/utxo_snapshot.cpp:22-46`): writes
  `<chainstate_snapshot>/base_blockhash` so the next startup
  can re-find the snapshot chainstate. **camlcoin**: **ABSENT.**
  The snapshot-dir is created (`chainstate_snapshot/`) but no
  sidecar file. On restart there is no way to reconstruct
  which block the chainstate was anchored to. **P1: restart-
  safety gap.** Combined with the dormant `node_state` cluster
  this means a snapshot load is effectively single-process —
  the snapshot data is on disk after `loadtxoutset` but only
  the just-completed RPC call "knows" about it. **NEW
  BUG-W138-7.**

- **G20: `ReadSnapshotBaseBlockhash` + `LoadAssumeutxoChainstate`
  on startup.** Core (`validation.cpp:6151-6168` +
  `node/utxo_snapshot.cpp:48-81`): on init, finds
  `chainstate_snapshot/`, reads the base_blockhash sidecar,
  reconstructs the `Chainstate` keyed by that block. **camlcoin**:
  **ABSENT.** Even if a snapshot dir is on disk, daemon startup
  ignores it. The live chainstate is `chainstate/` (IBD-rooted),
  full-stop. **P0-CDIV: snapshot loaded by `loadtxoutset` is
  invisible to the running daemon after restart — the RPC
  response advertises success, the disk has the coin data, but
  none of the running services consult it.** **NEW BUG-W138-8.**

### G21-G25: Background validation / completion handshake

- **G21: `m_target_blockhash` set on background chainstate.** Core
  (`validation.cpp:6176`): when a snapshot chainstate is
  added, the prior (IBD) chainstate's `m_target_blockhash`
  is set to the snapshot's base. The IBD chainstate then
  validates forwards until it reaches that target and
  `MaybeValidateSnapshot` flips the assumeutxo state to
  `VALIDATED`. **camlcoin**: **ABSENT.** No
  `m_target_blockhash` field; no `MaybeValidateSnapshot`
  call. **P0-CDIV: assumeutxo `unvalidated → validated`
  transition never happens.** The
  `assumeutxo_state_to_string` enum exists
  (`assume_utxo.ml:26-30`) but no production code path ever
  flips a snapshot chainstate from `Unvalidated` to
  `Validated`. **NEW BUG-W138-9.**

- **G22: `MaybeValidateSnapshot` background completion.** Core
  (`validation.cpp:5967-6077`): once the IBD chainstate
  reaches the snapshot target, recompute its UTXO hash and
  compare to `au_data.hash_serialized`; on success flip
  `unvalidated_cs.m_assumeutxo = VALIDATED`; on failure call
  `handle_invalid_snapshot()` → fatal error + rename to
  `_INVALID` + node shutdown. **camlcoin**: the skeleton
  exists (`run_background_validation` at
  `assume_utxo.ml:1099-1238`) but **never invoked**. Even if
  someone did invoke it, the success path sets
  `snapshot_chainstate.assumeutxo_state <- Validated`
  (`assume_utxo.ml:1127`) but the chainstate it mutates is
  in a `node_state` value that nothing outside the file
  reads. **P0-CDIV: dormant.** **NEW BUG-W138-10.**

- **G23: `InvalidateCoinsDBOnDisk` rename to `_INVALID`.** Core
  (`validation.cpp:6201-6230`): on `MaybeValidateSnapshot`
  failure (hash mismatch), the snapshot dir is renamed to
  `<chainstate_snapshot>_INVALID` for forensics, the node
  shuts down with a fatal error pointing operators at the
  preserved dir. **camlcoin**: **ABSENT.** No rename, no
  fatal-error handler, no `<datadir>_INVALID` artifact.
  Background-validation failure paths set
  `assumeutxo_state <- Invalid` and log to `Logs.err`
  (`assume_utxo.ml:1138-1141`) but the on-disk
  `chainstate_snapshot/` is left in place; a subsequent
  re-attempt would (incorrectly) hit the B5 double-activation
  guard and refuse to load a fresh snapshot. **P1:
  re-attempt-after-failure broken; no forensic artifact.**
  **NEW BUG-W138-11.**

- **G24: `cleanup_bad_snapshot` rollback on
  `PopulateAndValidateSnapshot` failure.** Core
  (`validation.cpp:5677-5694`): if population fails midway,
  the partially-written snapshot dir is destroyed
  (`DeleteCoinsDBFromDisk`) so the next `loadtxoutset`
  attempt starts clean. **camlcoin**: `load_snapshot`
  closes the input channel on `Failure`/`End_of_file`/`exn`
  (`assume_utxo.ml:766-771`) but **does NOT remove the
  partially-populated `chainstate_snapshot/` dir.** A
  truncated snapshot file leaves a half-written RocksDB
  that will trip B5 on the next attempt. **P1: re-attempt-
  after-partial-load broken.** **NEW BUG-W138-12.**

- **G25: `m_target_utxohash` for in-process post-validation
  hash record.** Core (`validation.cpp:6073`): on successful
  background validation, records
  `validated_cs.m_target_utxohash =
  AssumeutxoHash{validated_cs_stats->hashSerialized}` so
  callers can introspect. **camlcoin**: absent — moot
  consequence of G22. **NEW BUG-W138-13 (folded into G22).**

### G26-G30: RPC surface + ops

- **G26: `getchainstates` RPC.** Core
  (`rpc/blockchain.cpp:3462-3519`): returns
  `{headers, chainstates: [{blocks, bestblockhash, bits,
   target, difficulty, verificationprogress,
   snapshot_blockhash?, coins_db_cache_bytes,
   coins_tip_cache_bytes, validated}]}`. **camlcoin**:
  **NO handler.** Search for `getchainstates` in
  `lib/rpc.ml` returns one occurrence — a help string —
  but no command dispatch. **P1: RPC absent; tooling that
  inspects chainstate state (Sparrow, btc-rpc-explorer,
  some block explorers) can't probe a camlcoin instance the
  same way.** **NEW BUG-W138-14.**

- **G27: `loadtxoutset` post-success services swap.** Core
  (`rpc/blockchain.cpp:3432-3435`): on a successful
  `loadtxoutset`, calls
  `node.connman->RemoveLocalServices(NODE_NETWORK);
   node.connman->AddLocalServices(NODE_NETWORK_LIMITED);` —
  signal to peers that this node is no longer a full historical
  server (since the snapshot doesn't have the pre-snapshot
  blocks). **camlcoin** (`rpc.ml:6885-6902`): returns success
  with no equivalent service-flag mutation. **P1: peers
  will continue requesting historical blocks from a camlcoin
  node that just loaded a snapshot and doesn't have them.**
  **NEW BUG-W138-15.**

- **G28: `dumptxoutset.txoutset_hash` is MuHash3072 over
  POST-restored state, not snapshot-file state.** Core
  (`rpc/blockchain.cpp:3285,3345`): `txoutset_hash` is the
  `hashSerialized` value of `PrepareUTXOSnapshot`, computed
  against the chainstate at the rollback target (i.e. the
  state the dump file represents). **camlcoin**
  (`rpc.ml:7167-7182`): `txoutset_hash` is computed via
  `compute_utxo_muhash_from_db` AFTER the post-dump rollback
  restore — so it reflects the live tip, not the dumped
  historical state. **The code has an explicit TODO
  (`rpc.ml:7179` `TODO(W47-followup)`).** This is **W102
  B10**, re-pinned but already known. Severity stays at
  **P1** (operator-visible hash divergence vs Core).

- **G29: `dumptxoutset` response missing `nchaintx` field.** Core
  (`rpc/blockchain.cpp:3346`): response includes
  `nchaintx = tip->m_chain_tx_count`. **camlcoin**
  (`rpc.ml:7183-7190`): emits `coins_written`, `base_hash`,
  `base_height`, `path`, `txoutset_hash` — **omits**
  `nchaintx`. This is **W102 B9**, re-pinned. Already
  known. **P1.**

- **G30: Pruned-mode `loadtxoutset` precondition.** Core has
  no explicit pruned-mode check on `loadtxoutset` (snapshot
  load works regardless of prune state on the receiving
  node), but `dumptxoutset` does (`rpc/blockchain.cpp:3164-3170`).
  **camlcoin** (`rpc.ml:7049-7058`): pruned-mode pre-check on
  `dumptxoutset` is present. **Match** for the dump path. The
  load path has no pruned-mode interaction. Pin-only test.

## Universal patterns surfaced (cross-impl candidates)

- **"orphan dual-chainstate dormant cluster"** — camlcoin has
  `node_state` + `active_chainstate` + `background_chainstate`
  + `create_chainstate` + `has_snapshot_chainstate` +
  `run_background_validation` + `connect_block_to_cache`,
  all written without callers (the W47 commit deleted the
  `activate_snapshot` shell but left this surface intact).
  The fleet should audit for similar "dormant assumeutxo
  scaffolding" in rustoshi / blockbrew / ouroboros — when an
  impl adopts the Core dual-chainstate skeleton without
  wiring it, the failure mode is silent: load+verify hash
  succeeds, but the chainstate is a parallel disk artifact
  the running daemon never uses. Pattern: grep each impl for
  the equivalent of `m_target_blockhash` /
  `MaybeValidateSnapshot` and confirm a non-test caller
  exists in the IBD path.

- **"snapshot-base sidecar absent → restart-invisible load"** —
  Core's
  `<chainstate_snapshot>/base_blockhash` sidecar is what
  makes the snapshot durable across restarts. Any impl that
  writes a snapshot chainstate dir but omits the sidecar has
  G19/G20 — load succeeds at the RPC but is invisible after
  restart. Worth a fleet sweep.

- **"NODE_NETWORK_LIMITED swap after loadtxoutset missing"** —
  Core does this in the RPC handler, not in
  `ChainstateManager::ActivateSnapshot`, so it's easy to
  miss in impls that ported the validation lifecycle. Any
  impl that supports `loadtxoutset` should verify the
  service-bits swap. P1 because honest peers waste bandwidth
  requesting pre-snapshot blocks from a node that doesn't
  have them.

- **"hardcoded `chain_tx_count` parameter stored but never
  written back to chain index"** — Core writes
  `au_data.m_chain_tx_count` onto the snapshot-tip block
  index at `validation.cpp:5949` so RPCs like
  `getblockheader.nTx` and `getchaintxstats` return correct
  values immediately after load. Impls that store the
  number in chainparams but never propagate it (camlcoin
  W138-5) will silently emit wrong `nTx` values for the
  snapshot-tip block. Same audit-shape question for every
  impl that has the chainparams entry.

- **"audit-on-audit: prior audit's gates re-pinned + new
  surface added"** — W102 covered 15 gates and closed B1-B7.
  W138 expands the surface to 30 gates by stepping out one
  layer (Core RPC handler + post-load handshake + restart
  recovery) and finds 10 new bugs. Pattern is reusable: when
  a subsystem has a prior W### audit, extend the methodology
  with the missing Core surfaces rather than re-grading the
  same gates.

- **"vout-near-UINT32_MAX truncates to negative int32 silently"** —
  G12. Any impl that uses 32-bit-int representation for
  outpoint.n and reads via a 64-bit decoder without an
  explicit `>= UINT32_MAX` check will have the same gap.
  Worth a fleet sweep: rustoshi (Rust `u32` is safe by
  construction), blockbrew (Go `uint32` ditto), but
  any impl marshalling through int64 → int32 conversion
  unchecked is suspect.

## BUG catalogue (NEW in W138)

| ID | Sev | Gate | Description |
|---|---|---|---|
| BUG-W138-1 | P3 | G7 | `loadtxoutset` "Assumeutxo height not recognized" error does not enumerate available snapshot heights (Core does via `GetAvailableSnapshotHeights`). `rpc.ml:6753-6756`. Operator can't recover without source-diving. |
| BUG-W138-2 | P2 | G9 | No `BLOCK_FAILED_VALID` check on snapshot start block. Core `validation.cpp:5617-5620`. camlcoin has no per-header invalidity bitfield exposed; W102 B4 header-chain check is upstream gate but explicit invalid-chain gate absent. |
| BUG-W138-3 | P1 | G10 | No "best_header has snapshot_start_block as ancestor" check (Core `validation.cpp:5622-5624`). User could activate a snapshot at a block on a known-but-stale fork. |
| BUG-W138-4 | P0-CDIV | G12 | `outpoint.n >= UINT32_MAX` check absent (Core `validation.cpp:5814-5816`; documented in comment at `assume_utxo.ml:516`). `Int32.of_int vout_int` silently truncates large values to negative int32. |
| BUG-W138-5 | P0-CDIV | G17 | `au_data.m_chain_tx_count` (e.g. 991_032_194 for 840k) is stored in `assumeutxo_params` but **never written into the block index**. `getblockheader.nTx` / `getchaintxstats` return wrong values for snapshot-tip block until background sync reaches it (which it never does because of G22). Core `validation.cpp:5949`. |
| BUG-W138-6 | P2 | G18 | `BLOCK_OPT_WITNESS` faking on snapshot chain index absent. camlcoin has no `nStatus` bitfield, so the immediate consequence is moot, but `NeedsRedownload` parity is also absent so the gate is open. |
| BUG-W138-7 | P1 | G19 | `WriteSnapshotBaseBlockhash` sidecar (`<chainstate_snapshot>/base_blockhash`) absent. No way to reconstruct snapshot chainstate on restart. Core `node/utxo_snapshot.cpp:22-46`. |
| BUG-W138-8 | P0-CDIV | G20 | `LoadAssumeutxoChainstate` on startup absent. Even with sidecar present (G19), daemon ignores `chainstate_snapshot/` on init. Snapshot data on disk is invisible to the running daemon after restart. Core `validation.cpp:6151-6168`. |
| BUG-W138-9 | P0-CDIV | G21 | `m_target_blockhash` field absent on chainstate. The `unvalidated → validated` snapshot transition never happens. `assumeutxo_state_to_string` exists but no production code flips a snapshot chainstate from `Unvalidated` to `Validated`. Core `validation.cpp:6176`. |
| BUG-W138-10 | P0-CDIV | G22 | `MaybeValidateSnapshot` background completion handshake absent (skeleton `run_background_validation` exists at `assume_utxo.ml:1099-1238` but never invoked; mutates a `node_state` value nothing else reads). |
| BUG-W138-11 | P1 | G23 | `InvalidateCoinsDBOnDisk` rename-to-`_INVALID` absent. Failed background validation leaves `chainstate_snapshot/` intact, which trips B5 double-activation on re-attempt. |
| BUG-W138-12 | P1 | G24 | `cleanup_bad_snapshot` (remove partial dir on `PopulateAndValidateSnapshot` failure) absent. Truncated snapshot file leaves a half-written RocksDB; re-attempt fails B5. Core `validation.cpp:5677-5694`. |
| BUG-W138-13 | P1 | G25 | (Folded into G22) `m_target_utxohash` post-validation record absent. |
| BUG-W138-14 | P1 | G26 | `getchainstates` RPC absent. No way to introspect dual-chainstate state via JSON-RPC. |
| BUG-W138-15 | P1 | G27 | `loadtxoutset` does not call `RemoveLocalServices(NODE_NETWORK)` + `AddLocalServices(NODE_NETWORK_LIMITED)` on success. Peers continue requesting historical blocks the snapshot-loaded node doesn't have. Core `rpc/blockchain.cpp:3432-3435`. |
| BUG-W138-16 | P1 | G28 | `dumptxoutset.txoutset_hash` reflects post-restore live tip, not the dumped historical state. **W102 B10 re-pinned** (explicit `TODO(W47-followup)` at `rpc.ml:7179`). |
| BUG-W138-17 | P1 | G29 | `dumptxoutset` response omits `nchaintx`. **W102 B9 re-pinned.** |
| BUG-W138-18 | P3 | G3 | Network magic stored as `int32` host-byte-order rather than 4 raw bytes; LE serialize coincides for current networks but future big-endian magic would diverge. `assume_utxo.ml:54`. |
| BUG-W138-19 | P3 | G4 | Throw-on-bad-magic shape divergence (Core: `std::ios_base::failure`; camlcoin: `Error string`). Surface-only drift. |
| BUG-W138-20 | P3 | G5 | Network-mismatch error message generic ("Network mismatch: snapshot is for network 0x%08lx, node is 0x%08lx") rather than Core's human-readable "The network of the snapshot (mainnet) does not match the network of this node (testnet4)". |
| BUG-W138-21 | P1 | G7 | `node_state` / `active_chainstate` / `background_chainstate` / `create_chainstate` / `has_snapshot_chainstate` / `run_background_validation` / `connect_block_to_cache` cluster has zero callers outside `assume_utxo.ml`. **~210 LOC of orphan dual-chainstate scaffolding**, retained per epitaph comment at `assume_utxo.ml:1240-1273`. Distinct from G22/G9-G13 because those are functional gates; this is dead-code load on the codebase. |

Total **NEW in W138**: **21 BUGs** (4 P0-CDIV, 11 P1, 2 P2, 4 P3).

Additionally **8 W102 bugs re-pinned**:
- W102-B8 (re-pinned) — `mainnet_au_data` for heights 880k/910k/935k
  carry `coins_count = 0L` rather than the canonical Core figure,
  bypassing the metadata `coins_count` check at
  `assume_utxo.ml:706-709` for those heights. Camlcoin's check only
  fires when the params `coins_count` is non-zero. **P2**.
- W102-B9 — `dumptxoutset.nchaintx` field absent (= W138 BUG-16).
- W102-B10 — `dumptxoutset.txoutset_hash` post-rollback drift
  (= W138 BUG-15).
- W102-B11 — `mainnet_au_data` 3/4 entries have `coins_count=0L`
  bypass (= W102-B8 above).
- W102-B12 — `connect_block_to_cache` uses
  `let median_time = 0l in (* TODO: compute properly from chain *)`
  at `assume_utxo.ml:1158`. BIP-113 not honoured in background
  validation. Inert (G22 absent), but the bug remains.
- W102-B13 — 5-byte magic 'utxo\xff' is camlcoin/Core-aligned but
  diverges from theoretical Core variant impls; pin-only.
- W102-B14 — metadata block is exactly 51 bytes; pin-only.
- W102-B15 — `load_snapshot` does not activate a chainstate
  (= W138 BUG-8 / -9 / -10 collectively).

## What camlcoin gets RIGHT (regression-pin notes)

- **W47 wire-format byte-exact codec.** `serialize_metadata` produces
  byte-identical metadata to Core's `SnapshotMetadata::Serialize`
  (pinned by `test_b14_metadata_size_and_layout`).
- **W47 ScriptCompression / CompressAmount byte-exact** via
  `lib/compressor.ml` (test_compressor coverage).
- **W47 per-txid grouping.** `write_snapshot` produces
  Core-format groups (32-byte txid prefix + CompactSize count + coin
  body sequence).
- **W47 atomic-write protocol.** `<path>.incomplete` + fsync +
  rename (commit `a1646c6`; pinned by
  `test_snapshot_atomic_write`).
- **W102 B1-B7 closures** — all 7 load-time preconditions present
  and tested.
- **MuHash3072 plumbing.** `compute_utxo_muhash_from_db` exists,
  is correct, and is wired through `handle_gettxoutsetinfo
  hash_type=muhash` (pinned by `test_muhash_*`).
- **Strict gate uses HASH_SERIALIZED, not MuHash.**
  `verify_loaded_utxo_hash` correctly uses SHA256d (Core
  `validation.cpp:5902-5915` parity), not MuHash; the docstring
  at `assume_utxo.ml:935-973` explicitly rationalizes the
  choice. Pinned by
  `test_verify_loaded_utxo_hash_rejects_muhash_value`.
- **Whitelist-keyed-by-hash lookup.** `get_assumeutxo_for_hash`
  refuses any base_blockhash not in `mainnet_au_data` (W102 B-G7
  closure); pinned.

## Verification

`test/test_w138_assumeutxo.ml` — 30 W138 gate tests across the 6
G-bands (wire/metadata, ActivateSnapshot lifecycle, content
validation, post-load finalization, background-validation
completion, RPC surface).

camlcoin gotcha (per FIX-80 / FIX-77 / W133 / W137 audit pattern):
if `dune runtest` stalls, run the pre-built
`_build/default/test/test_w138_assumeutxo.exe` directly.

## Out of scope (for future waves)

- Closure of any BUG above; W138 is discovery-only.
- BIP-113 in `connect_block_to_cache` (W102 B12 re-pinned but
  inert because G22 absent).
- W102 B8/B11 `coins_count=0L` bypass for 3/4 mainnet entries —
  re-pinned but not re-counted.
- Full dual-chainstate integration into camlcoin's `Sync` /
  `Block_import` / `Peer_manager` (architectural change).
- Snapshot-mode P2P-services bit broadcasting via `version` /
  `addr` / `addrv2` after a snapshot load.
- `MaybeRebalanceCaches` cache reapportionment.
- Snapshot resume / chunked load (Core doesn't support this either).
