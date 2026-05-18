# W146 Block storage layer (blkXXXXX.dat + revXXXXX.dat + block-index DB)
camlcoin (OCaml)

Wave: W146 — the on-disk block bodies, undo data and block-index persistence
layer that Bitcoin Core implements in `bitcoin-core/src/node/blockstorage.{h,cpp}`
(roughly `BlockManager::{FindNextBlockPos, FlushBlockFile, WriteBlock,
WriteBlockUndo, ReadBlock, ReadBlockUndo, FlushChainstateBlockFile}`) and the
LevelDB block-index it maintains in `bitcoin-core/src/txdb.{h,cpp}` under the
single-byte CF prefixes `b/f/l/F/R/t`.

Core references:

- `bitcoin-core/src/node/blockstorage.h:119` — `BLOCKFILE_CHUNK_SIZE = 16 MiB`
- `bitcoin-core/src/node/blockstorage.h:121` — `UNDOFILE_CHUNK_SIZE = 1 MiB`
- `bitcoin-core/src/node/blockstorage.h:123` — `MAX_BLOCKFILE_SIZE = 128 MiB`
- `bitcoin-core/src/node/blockstorage.cpp:58-62` — DB prefixes `'f'` BlockFiles,
  `'b'` BlockIndex, `'F'` Flag, `'R'` ReindexFlag, `'l'` LastBlock
- `bitcoin-core/src/index/txindex.cpp:31` — DB prefix `'t'` TxIndex
- `bitcoin-core/src/node/blockstorage.cpp:833-921` — `FindNextBlockPos` +
  `m_block_file_seq.Allocate` chunk-allocation + flush-on-rotate
- `bitcoin-core/src/node/blockstorage.cpp:742-769` — `FlushBlockFile` /
  `FlushUndoFile` (per-file fdatasync + AllocateFileRange truncate-down on
  finalize)
- `bitcoin-core/src/node/blockstorage.cpp:945-985` — `FindUndoPos` +
  `WriteBlockUndo`; undo blob followed by 32-byte SHA256d checksum bound to
  `pprev->GetBlockHash()` via `HashWriter << pprev_hash << undo`
- `bitcoin-core/src/node/blockstorage.cpp:967-1024` — `WriteBlockUndo`
  ordering: append undo, fsync, **then** atomically update the in-memory
  `nUndoPos` / `BLOCK_HAVE_UNDO` flag and mark `m_dirty_blockindex`
- `bitcoin-core/src/node/blockstorage.cpp:1098-1132` — `ReadRawBlock`
  magic-mismatch rejection
- `bitcoin-core/src/node/blockstorage.cpp:1134-1165` — `WriteBlock`
  magic-prefix + size-prefix + serialized block
- `bitcoin-core/src/node/blockstorage.cpp:1167-1215` —
  `InitBlocksdirXorKey` + `xor.dat` (every byte of every blk/rev file is
  XOR'd with an 8-byte key drawn at first run, exposed via
  `m_blocks_xor_key`); production behavior since v25 (2023) and the default
  since v28
- `bitcoin-core/src/kernel/chainparams.cpp:117-120 / 235-238 / 335-338 /
  479 / 560-563` — `pchMessageStart` for mainnet / testnet3 / testnet4 /
  signet / regtest (byte order on disk is exactly the order listed —
  `F9 BE B4 D9`, `0B 11 09 07`, `1C 16 3F 28`, `0A 03 CF 40`,
  `FA BF B5 DA`)

camlcoin reference points:

- `lib/storage.ml:1050-1791` — `FlatFileStorage` module: 740 LOC of
  blk/rev/index implementation. **Zero non-test callers** in `lib/` or
  `bin/` (see BUG-1).
- `lib/storage.ml:1066` — `max_blockfile_size = 0x8000000` (matches Core)
- `lib/storage.ml:1071-1078` — only mainnet / testnet4 / regtest magics
  declared; testnet3 + signet missing entirely
- `lib/storage.ml:1352-1383` — `find_next_block_pos`: rotation, no
  flush, no chunk allocation, no disk-space check
- `lib/storage.ml:1386-1427` — `write_block`: `open / lseek / write / close`
  per block, no `fsync`, no `fdatasync`, no pre-allocation
- `lib/storage.ml:1400-1410, 1530-1538` — header magic serialisation:
  treats `t.magic` as int32 and emits **LSB first** (reverses Core's
  byte order)
- `lib/storage.ml:1262-1294` — `save_index` writes the entire
  `index.dat` blob to a tmp file then `Unix.rename`; no incremental,
  no LevelDB, no `m_dirty_blockindex`/`m_dirty_fileinfo` set
- `lib/storage.ml:1207-1219` — `status_to_int` synthetic mapping of
  validity-level flags to bits 16-21; the on-disk bitmask is not the
  Core `nStatus` value
- `lib/storage.ml:1208-1232` — `Block_pruned` mapped to bit 9 (Core has
  no pruned bit; pruning is signalled by `~BLOCK_HAVE_DATA`)
- `lib/storage.ml:855-859` — `store_block_ntx` writes `n` as a
  side-table key in `cfh_chain_state`; Core stores `nTx` (and the
  cumulative `nChainTx`) inside `CDiskBlockIndex`
- `lib/storage.ml:564-575, 564-619` — `ChainDB.store_block` /
  `store_undo_data` / `get_undo_data`: the live production write/read
  path. Writes blocks **into RocksDB CFs** (one entry per block keyed
  by block hash) — does **not** use the blk/rev flat-file format
- `lib/cf_chainstate.ml:43-74` — CF names: `block_header`, `block_data`,
  `tx`, `utxo`, `block_height`, `tx_index`, `chain_state`,
  `undo_data`, `invalidated`, `ban_list`. None of these store the
  Core `'f'/'b'/'l'/'F'/'R'` schema.
- `lib/storage.ml:861-896` — undo data path: stored under
  `cfh_undo_data` with a trailing `sha256(undo)` checksum (single
  SHA-256, **not** SHA256d, **not** bound to `pprev_hash`); rev*.dat
  flat file is never written on the live path
- `lib/sync.ml:2443-2488` — assume-valid IBD branch: `if not ibd_mode
  then begin … store_block; store_undo_data end` — during IBD blocks
  are NOT persisted at all; only the UTXO delta is applied via
  `OptimizedUtxoSet`
- `lib/block_import.ml:55-156` — the `--import-blocks` driver writes
  blocks via `ChainDB.store_block`, not via `FlatFileStorage`
- `lib/reindex.ml:1-202` — `-reindex` only clears the RocksDB CFs
  (`cf_utxo`, `cf_chain_state`, `cf_undo_data`); never persists or
  reads a `DB_REINDEX_FLAG` byte, never walks blk*.dat files

The W109 audit catalogued 29 prior bugs against the same `FlatFileStorage`
module (`test/test_w109_block_index.ml:1-80`). Many remain open because the
module itself is dead code on the production path (BUG-1 below); the
findings in this audit either re-anchor those bugs on the production
ChainDB / Cf_chainstate path or expose new gaps that W109 did not touch
(magic byte order, XOR obfuscation, testnet3/signet magics, undo checksum
domain separation, DB_REINDEX_FLAG, two-pipeline guard between the
flat-file and CF stacks).

---

## BUG-1 — Entire `FlatFileStorage` module is dead code: blk/rev flat-file storage has zero production callers; production writes blocks into RocksDB CFs [P0]

- **File:** `lib/storage.ml:1050-1791` (740 LOC), used only by
  `test/test_w109_block_index.ml` and `test/test_storage.ml`
- **Core ref:** `bitcoin-core/src/node/blockstorage.{h,cpp}` — block
  bodies and undo blobs MUST live in `blocks/blk?????.dat` and
  `blocks/rev?????.dat` files; the LevelDB at `blocks/index/` only
  stores `CDiskBlockIndex` records that point INTO those files via
  `FlatFilePos`.

**Description.** `Storage.FlatFileStorage` declares the complete
public surface for blk/rev flat-file storage:
`create`, `write_block`, `read_block`, `read_block_at_pos`,
`write_undo`, `read_undo`, `find_next_block_pos`, `save_index`,
`load_index`, `prune_one_block_file`, `prune_block_files`, etc.
Every production write path on `master` writes to RocksDB instead:

```
$ grep -rn "FlatFileStorage\\." camlcoin/lib/ camlcoin/bin/
(no matches)

$ grep -rn "store_block\\b" camlcoin/lib/ camlcoin/bin/
lib/block_import.ml:63:        Storage.ChainDB.store_block db hash block;
lib/sync.ml:2446:            Storage.ChainDB.store_block ibd.chain.db entry.hash block;
lib/sync.ml:3426:            Storage.ChainDB.batch_store_block batch entry.hash block;
lib/sync.ml:3892:            Storage.ChainDB.store_block state.db hash block;
lib/sync.ml:4414:            Storage.ChainDB.store_block state.db hash block;
lib/sync.ml:4465:            Storage.ChainDB.store_block state.db hash block;
lib/mining.ml:916:           Storage.ChainDB.store_block chain.db hash block;
```

`ChainDB.store_block` (`storage.ml:564-568`) writes the full
serialised block as a single value under
`cfh_block_data[block_hash]`. RocksDB compresses each block
independently; pruning, reindex-from-flat-files, and cross-impl
block-file recovery are all impossible on this layout.

**Excerpt** (the dead module header, `lib/storage.ml:1050-1063`):

```ocaml
(* ============================================================================
   Flat File Block Storage (Bitcoin Core blk/rev format)
   Reference: Bitcoin Core's node/blockstorage.cpp and flatfile.cpp
   Bitcoin stores blocks in sequential flat files (blk00000.dat,
   blk00001.dat, ...) with a simple format: [magic:4][size:4][block_data:N]
   repeated.

   This implementation:
   - Uses blk{nnnnn}.dat files with 128MB max size
   - Tracks file position for each block via FlatFilePos
   - Maintains a block index (hash -> file_pos) for fast lookups
   - Persists the index to disk for fast startup
   ============================================================================ *)
```

**Impact.**

- Cross-impl block recovery is broken: a camlcoin datadir cannot be
  pointed at `bitcoin-core -loadblock` or vice versa; the entire blk
  storage layer disappears once the `FlatFileStorage.t` reference is
  garbage-collected.
- Pruning correctness is irreparable: `prune_block_files` /
  `find_files_to_prune` (`storage.ml:1697-1749`) operate on
  `FlatFileStorage.t.file_info[]`, which is never populated; the live
  pruning RPC has no effect on the actual `cfh_block_data` size.
- Every W109 finding against `FlatFileStorage` (29 bugs) sits behind
  this dead-code wall; fixing them does nothing until the live path
  is rewired through the module.
- Classic **dead-class fleet pattern** (5th camlcoin instance after
  W138 `run_background_validation`, W139 nothing-on-restart,
  W141 multiple-publishers, W143 `Crypto.witness_merkle_root`). The
  W109 audit comment in `test_w109_block_index.ml:5-80` mirrors this:
  29 enumerated gaps against an implementation that no callers touch.
- **Two-pipeline guard:** `FlatFileStorage` and `Cf_chainstate.cf_block_data`
  are two coexisting block-storage stacks. Future contributors will
  not know which one is canonical; a fix landed on one path silently
  has no effect on the other. First camlcoin BLK-storage instance of
  this pattern.

---

## BUG-2 — `write_block` / `write_undo` byte-reverse the network magic on disk: every produced blk/rev file is incompatible with Bitcoin Core readers and any tool that follows BIP-0152 magic conventions [P0-CDIV]

- **File:** `lib/storage.ml:1400-1410` (`write_block` header buffer),
  `lib/storage.ml:1530-1538` (`write_undo` header buffer),
  `lib/storage.ml:1448-1456` (`read_block_at_pos` magic verification —
  symmetric error, so the round-trip locally is silently OK)
- **Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:117-120` —
  mainnet `pchMessageStart = { 0xf9, 0xbe, 0xb4, 0xd9 }`,
  written to disk byte-for-byte by `WriteBlock` (`blockstorage.cpp:1152`,
  `fileout << GetParams().MessageStart() << block_size`). The
  `MessageStartChars` operator<< serialises the 4 bytes **in array
  order**, not as a little-endian uint32_t.

**Description.** `Storage.mainnet_magic` is declared as the OCaml
int32 `0xF9BEB4D9l`. The on-disk write code at `storage.ml:1402-1405`
emits bytes via a shift-right ladder:

```ocaml
Bytes.set header_buf 0 (Char.chr (Int32.to_int (Int32.logand t.magic 0xFFl)));
Bytes.set header_buf 1 (Char.chr (Int32.to_int (Int32.logand (Int32.shift_right_logical t.magic 8) 0xFFl)));
Bytes.set header_buf 2 (Char.chr (Int32.to_int (Int32.logand (Int32.shift_right_logical t.magic 16) 0xFFl)));
Bytes.set header_buf 3 (Char.chr (Int32.to_int (Int32.logand (Int32.shift_right_logical t.magic 24) 0xFFl)));
```

For mainnet that writes the byte sequence `D9 B4 BE F9` — i.e. the
little-endian serialisation of the int32 `0xF9BEB4D9`. Core reads four
raw bytes and expects them to **equal** `{ 0xf9, 0xbe, 0xb4, 0xd9 }`
(`MessageStartChars` is a `std::array<std::byte, 4>`). Result: a
camlcoin-produced blk file fails Core's magic check on byte 0
(`D9 != F9`) at `bitcoin-core/src/node/blockstorage.cpp:1104`.

`read_block_at_pos` (`storage.ml:1448-1456`) reads the four bytes back
the same way and compares against `t.magic`, so the round-trip
**within camlcoin** is consistent — which is why this stayed latent.
The bug only becomes visible when:

1. A user points `bitcoin-core -loadblock` at camlcoin's blk files;
2. A user runs `bitcoin-core --datadir=...` against a camlcoin
   datadir;
3. A camlcoin node attempts to read blk files written by Core (the
   `-importblocks` workflow);
4. A future commit reads the magic with a `byte[]` API (e.g. `crypto`
   hash-prefix detection) — at which point the in-house byte-reverse
   stops being self-consistent.

**Excerpt** (the writing path, `storage.ml:1400-1411`):

```ocaml
(* Write magic and size *)
let header_buf = Bytes.create 8 in
Bytes.set header_buf 0 (Char.chr (Int32.to_int (Int32.logand t.magic 0xFFl)));
Bytes.set header_buf 1 (Char.chr (Int32.to_int (Int32.logand
  (Int32.shift_right_logical t.magic 8) 0xFFl)));
Bytes.set header_buf 2 (Char.chr (Int32.to_int (Int32.logand
  (Int32.shift_right_logical t.magic 16) 0xFFl)));
Bytes.set header_buf 3 (Char.chr (Int32.to_int (Int32.logand
  (Int32.shift_right_logical t.magic 24) 0xFFl)));
```

Fix sketch: change the magic literals to be in **byte order**
(`0xD9B4BEF9l` is the int32 representation when read LE-first, but the
cleanest fix is to store the magic as a 4-byte string, not int32).
Same fix at the four `write_*` and one `read_block_at_pos` sites
(plus the matching `write_undo` site).

**Impact.** P0-CDIV (cross-impl interop break): every camlcoin
blk/rev file is rejected by Bitcoin Core (`Block magic mismatch ...`
error in `ReadRawBlock` at `blockstorage.cpp:1104-1108`). Any
hash-block-detection tool (linkme-detector, electrs, fulcrum, mempool
.space ingestion scripts, the BIP-152 compact-block-magic recipe in
`doc/zmq.md`) sees a totally different magic prefix. The
**byte-order-reversed magic** pattern matches the W141 fleet-wide
"ZMQ hash byte-order LE vs Core display-order" pattern — three
camlcoin instances of the same root cause (int32 LE vs raw bytes)
now: P2P magic (correct in p2p.ml because it goes through
`Cstruct.LE.set_uint32`), ZMQ hash (W141), and now blk-file magic.

**Severity rationale.** If FlatFileStorage were live this would be
straight P0-CONSENSUS-class user-visible breakage. Because the
module is dead code (BUG-1), the *practical* impact is P3 — but as
soon as the wire-up is done (the documented intent of W109's BUG-21
recovery story) the impact reverts to P0-CDIV. Filed at P0-CDIV
because the dead-code guard is not a permanent shield.

---

## BUG-3 — Block-undo checksum is single SHA-256 of `undo_data` only; Core uses SHA256d of `pprev_hash || undo_data` (forge-vector for chain-reorg undo binding) [P0-CDIV]

- **File:** `lib/storage.ml:865-868, 879-881` (`store_undo_data` /
  `get_undo_data`); also `lib/storage.ml:1023-1048`
  (`serialize_block_undo` / `deserialize_block_undo`)
- **Core ref:** `bitcoin-core/src/node/blockstorage.cpp:697-730`
  (`ReadBlockUndo`): the undo blob is followed by a 32-byte
  `uint256 hashChecksum` computed by `HashWriter` over `pprev_hash`
  **concatenated** with the serialised undo data. The hash function
  is `Hash` (`SHA-256d`), not single SHA-256.

**Description.** `ChainDB.store_undo_data` computes:

```ocaml
let store_undo_data t (block_hash : Types.hash256) (undo_data : string) =
  let checksum = Crypto.sha256 (Cstruct.of_string undo_data) in
  Cf_chainstate.put_undo_data t.cf block_hash
    (undo_data ^ Cstruct.to_string checksum)
```

That is single SHA-256 over the undo bytes alone. Core's checksum is:

```cpp
HashVerifier verifier{filein};
verifier << index.pprev->GetBlockHash();
verifier >> blockundo;
uint256 hashChecksum;
filein >> hashChecksum;
if (hashChecksum != verifier.GetHash()) { return false; }
```

i.e. `SHA-256d(pprev_hash || undo_data)`. The `pprev_hash` binding is
the load-bearing security property: it prevents an attacker who can
flip a single undo blob from re-using a valid checksum to substitute
undo data from a **different parent**. Without it, any blk-archive
attacker with write access to the undo CF can swap two undo records
between blocks that share a common spent-output structure but
different parents — and the disconnect will silently succeed.

**Excerpt** (`storage.ml:861-881`):

```ocaml
(* Undo data storage - keyed by block hash for chain reorganizations.
   We append a sha256 checksum to the value (matching the legacy
   LogStorage layout) so corruption from a torn write surfaces as a
   [None] read instead of a silently-bad block disconnect. *)
let store_undo_data t (block_hash : Types.hash256) (undo_data : string) =
  let checksum = Crypto.sha256 (Cstruct.of_string undo_data) in
  Cf_chainstate.put_undo_data t.cf block_hash
    (undo_data ^ Cstruct.to_string checksum)

let get_undo_data t (block_hash : Types.hash256) : string option =
  match Cf_chainstate.get_undo_data t.cf block_hash with
  | None -> None
  | Some raw ->
    let len = String.length raw in
    if len < 32 then None
    else
      let data = String.sub raw 0 (len - 32) in
      let stored_checksum = String.sub raw (len - 32) 32 in
      let computed = Crypto.sha256 (Cstruct.of_string data) in
      if Cstruct.to_string computed = stored_checksum then Some data
      else None  (* checksum mismatch = corrupt *)
```

Note `serialize_block_undo` at `storage.ml:1023-1030` does the
**same wrong checksum** (single SHA-256) at the flat-file undo level,
so the dead-code flat-file path duplicates the bug; switching to
`FlatFileStorage` later inherits it. Both call sites omit
`pprev_hash` from the hash domain.

**Impact.**

- Cross-impl undo-file portability is broken (a Core node cannot read
  a camlcoin undo blob; a camlcoin node cannot read a Core revXXXXX
  .dat).
- The checksum is missing the `pprev_hash` domain separation, so it
  no longer detects "wrong parent" attacks during a reorg. An
  adversarial datadir with write access can swap undo blobs between
  blocks with matching transaction-shape distributions and the
  disconnect path silently restores the wrong UTXOs. (Realistic
  threat: a malicious operator preparing a chain-state datadir for
  distribution.)
- Same fleet pattern as W141 (single-SHA vs SHA256d) and W124 (HMAC
  domain confusion). Re-anchor of W109 BUG-12 + restatement against
  the LIVE undo path; W109 had it filed only against
  `FlatFileStorage`.

---

## BUG-4 — `find_next_block_pos` rotates by simply incrementing `last_file`; never calls a `FlushBlockFile` / `fdatasync` before opening the new file [P0]

- **File:** `lib/storage.ml:1354-1383`
- **Core ref:** `bitcoin-core/src/node/blockstorage.cpp:886-901`
  (`FindNextBlockPos` calls `FlushBlockFile(last_blockfile,
  fFinalize=true, finalize_undo)` on every rotation, with a comment
  explicitly warning that without this flush a crash during reindex
  leaves the undo file inconsistent).

**Description.** The camlcoin rotation path is purely an
in-memory cursor bump:

```ocaml
if fi.n_size + add_size > max_blockfile_size then begin
  (* Move to next file *)
  t.last_file <- t.last_file + 1;
  let new_arr = Array.make (t.last_file + 1) (empty_file_info ()) in
  Array.blit t.file_info 0 new_arr 0 (Array.length t.file_info);
  t.file_info <- new_arr
end;
```

There is no flush of the previous file, no `fdatasync`, no `fsync`
anywhere in the entire flat-file path:

```
$ grep -n "fsync\|fdatasync" lib/storage.ml | head
148:   records have been fsynced.
188:   (* fsync the journal so it is durable before we apply *)
190:   (try Unix.fsync fd with Unix.Unix_error _ -> ());
321:   1. Write all operations to the journal file and fsync
```

The three fsync sites are inside the (legacy) `FileStorage` WAL,
**not** the block-file writers. `write_block`'s sequence is
`open / lseek / write / write / close`; the close does not guarantee
data has reached the platter.

**Excerpt** (`storage.ml:1395-1414`):

```ocaml
let file_path = block_file_path t pos.file_num in
let flags = [Unix.O_WRONLY; Unix.O_CREAT] in
let fd = Unix.openfile file_path flags 0o644 in
(* Seek to position before header *)
let _ = Unix.lseek fd (pos.pos - storage_header_bytes) Unix.SEEK_SET in
... write_header ...
let _ = Unix.write fd header_buf 0 8 in
(* Write block data *)
let _ = Unix.write fd (Cstruct.to_bytes block_data) 0 block_size in
Unix.close fd;
```

The page-cache eviction policy of Linux + the lack of `O_SYNC`
means a crash within the kernel writeback window of `dirty_writeback
_centisecs` (5 s by default) loses the tail of the current blk file.
On recovery there is no replay path because (a) the block-index
points at the unflushed tail, (b) there is no reindex flag (see
BUG-7), and (c) the magic-check on read produces `None` (corruption
indistinguishable from "we never wrote it"). Re-anchor of W109
BUG-26 ("write_block races on concurrent access — no mutex around
file open/lseek/write") but framed against the rotation case
specifically.

**Impact.** Crash-window data loss + silent reindex requirement.
On a 128 MiB blk file rotation under load, up to a full chunk of
writes can be lost. The undo file behaves identically. Combined
with BUG-3 (undo checksum doesn't bind pprev_hash), recovery from
this state is impossible without a full re-IBD.

---

## BUG-5 — No `posix_fallocate` / `BLOCKFILE_CHUNK_SIZE` / `UNDOFILE_CHUNK_SIZE` pre-allocation: every block extends the file byte-by-byte; fragmentation + page-fault storms on mainnet [P1]

- **File:** `lib/storage.ml:1395-1414` (`write_block`),
  `lib/storage.ml:1525-1541` (`write_undo`)
- **Core ref:** `bitcoin-core/src/node/blockstorage.h:119-123`
  (`BLOCKFILE_CHUNK_SIZE = 16 MiB`, `UNDOFILE_CHUNK_SIZE = 1 MiB`);
  `bitcoin-core/src/node/blockstorage.cpp:909-918`
  (`m_block_file_seq.Allocate(pos, nAddSize, out_of_space)` →
  `posix_fallocate` on Linux / `F_PREALLOCATE` on macOS) inside
  `FindNextBlockPos`.

**Description.** `write_block` opens the file with `O_CREAT |
O_WRONLY` and writes `block_size + 8` bytes at exactly the offset of
the previous tail. There is no `Unix.ftruncate`, no `Unix.fallocate`
(OCaml stdlib has no `posix_fallocate` binding, but
`extunix.posix_fallocate` is available; the project does not depend
on it). On ext4/xfs the file grows in extents of `block_size`,
producing thousands of small extents per blk file (~1000-2000
blocks at typical mainnet sizes), so:

- IBD throughput drops on rotational disks because every block writes
  to a freshly-allocated extent (no run-of-extents to coalesce);
- on read, `read_block_at_pos` causes a fresh `BlockReader` open per
  block and every block hits a page fault for the metadata block
  pointer, because the extent tree is dispersed;
- pruning leaks free space: even after `Sys.remove blk_path`, the
  freed extents are tiny and likely below the filesystem reuse
  threshold, so subsequent allocations don't reclaim them
  efficiently.

Core's `m_block_file_seq.Allocate` pre-extends the file by 16 MiB
(blk) or 1 MiB (rev), so the kernel sees one large allocation and
the on-disk extent layout is contiguous.

**Excerpt** (`storage.ml:1395-1414`):

```ocaml
let file_path = block_file_path t pos.file_num in
let flags = [Unix.O_WRONLY; Unix.O_CREAT] in
let fd = Unix.openfile file_path flags 0o644 in
let _ = Unix.lseek fd (pos.pos - storage_header_bytes) Unix.SEEK_SET in
(* No fallocate / ftruncate — file extends to (pos + add_size) on first
   write, exactly the same as Core *without* its Allocate path *)
let _ = Unix.write fd header_buf 0 8 in
let _ = Unix.write fd (Cstruct.to_bytes block_data) 0 block_size in
Unix.close fd;
```

**Impact.** P1 because performance and fragmentation effects are
visible on mainnet IBD (Core's `Allocate` was added precisely
because byte-by-byte extension was the historical hotspot on
spinning disks). Combined with BUG-1 (FlatFileStorage is dead code),
the realised impact is nil today, but as soon as the production
write path is migrated this becomes a measurable regression versus
Core. Re-anchor of W109 BUG-15 with concrete fix path.

---

## BUG-6 — `save_index` writes the entire block-index as one binary blob to `index.dat`; no LevelDB, no `b/f/l/F` schema, no `m_dirty_blockindex`/`m_dirty_fileinfo` lazy flush [P1]

- **File:** `lib/storage.ml:1262-1295` (`save_index`)
- **Core ref:** `bitcoin-core/src/node/blockstorage.cpp:510-540`
  (`WriteBlockIndexDB` — writes one LevelDB CWriteBatch keyed on
  `'b' + hash` (block-index entry), `'f' + file_num` (file info),
  `'l'` (last block file index); `bitcoin-core/src/txdb.cpp:23-83`
  for the BlockTreeDB / chainstate layout); only `m_dirty_blockindex`
  and `m_dirty_fileinfo` entries are written per call (lazy).

**Description.** camlcoin produces `index.dat` (`storage.ml:1264-1294`):

```ocaml
let path = index_path t in
let tmp = path ^ ".tmp" in
let oc = open_out_bin tmp in
output_string oc "BLKIDX01";  (* Magic + version *)
write_le32 oc (Int32.of_int (Hashtbl.length t.block_index));
write_le32 oc (Int32.of_int t.last_file);
write_le32 oc (Int32.of_int (Array.length t.file_info));
Array.iter ... t.file_info;       (* every CBlockFileInfo, every save *)
Hashtbl.iter ... t.block_index;   (* every CBlockIndex, every save *)
close_out oc;
Unix.rename tmp path;
```

That is an `O(n)` full-rewrite of the entire on-disk index on every
save, plus the `BLKIDX01` magic and per-entry `int32-LE` length
prefix are **camlcoin-internal**: they cannot be read by any tool
that understands Core's `blocks/index/` LevelDB layout. There is no
`m_dirty_blockindex`/`m_dirty_fileinfo` short-list — the only
guard is the single `t.dirty` boolean (`storage.ml:1262`).

No DB write-batch atomicity either: the tmp + rename is atomic for
the *file* rename, but if the process crashes mid-write of the
`.tmp` the next `save_index` overwrites the .tmp with a fresh
attempt; if the process crashes BETWEEN the write of the tmp and
the rename of `index.dat`, the prior `index.dat` is intact but the
in-memory block index has accepted later blocks that aren't yet
persisted. Re-anchor of W109 BUG-17, BUG-18, BUG-21 against the
same code.

**Impact.** P1. Practical effects: `save_index` is O(n) so it gets
slower with chain length (eventually multi-second on mainnet);
`reindex` from the index alone is impossible (would have to scan
every blk file via `ReadRawBlock`); cross-impl recovery via
`bitcoin-core -reindex` against the same datadir is impossible.

---

## BUG-7 — No `DB_REINDEX_FLAG` ('R') persistence; `reindex.ml` clears CFs in-place without writing a recovery flag, so a crash mid-reindex leaves no marker for the next start [P1]

- **File:** `lib/reindex.ml:65-119` (`pre_open_wipe`) +
  `lib/reindex.ml:148-202` (`replay_stored_blocks`)
- **Core ref:** `bitcoin-core/src/node/blockstorage.cpp:74-86`
  (`BlockTreeDB::WriteReindexing` and `ReadReindexing`):

```cpp
bool BlockTreeDB::WriteReindexing(bool fReindexing) {
    if (fReindexing) {
        return Write(DB_REINDEX_FLAG, uint8_t{'1'});
    } else {
        return Erase(DB_REINDEX_FLAG);
    }
}

bool BlockTreeDB::IsReindexing() const {
    return Exists(DB_REINDEX_FLAG);
}
```

This single byte is the entire recovery contract: when set, Core
restarts will re-trigger reindexing from genesis even if the
operator did not pass `-reindex` on the second start.

**Description.** `reindex.ml:pre_open_wipe` clears the three RocksDB
CFs (`cf_utxo`, `cf_chain_state`, `cf_undo_data`) and `rm -rf`s
`rocksdb_utxo/`, but it never writes a "reindex in progress" marker.
A crash between phase 1 (CF clear) and phase 2 (`replay_stored_blocks`
walks every retained block) leaves the datadir in a state where:

- `cf_block_header` / `cf_block_data` still have N validated blocks;
- `cf_utxo` is empty;
- `cf_chain_state` has no `tip_hash`/`tip_height`;
- the next daemon start sees `Storage.ChainDB.get_chain_tip = None`
  and treats the datadir as fresh-from-genesis, but the block CFs
  are populated — so the boot path takes the
  "header_tip retained → restore" branch (`reindex.ml:84-92`) and
  silently exits the reindex flow without finishing it.

Operator only learns the problem when they run `getblockchaininfo`
and see height 0 with non-empty block storage.

**Excerpt** (`reindex.ml:84-92` plus the missing flag set):

```ocaml
(* Clear only the chain-tip pointer (tip_hash, tip_height),
   keeping the header tip intact. restore_chain_state needs
   header_tip_hash + header_tip_height to reload the in-memory
   header chain from cf_block_header — which is what drives the
   post-wipe block replay. *)
let n_chain = Cf_chainstate.cf_clear_chain_tip_only cf in
Logs.info (fun m ->
  m "reindex: cleared %d chain-tip entries from cf_chain_state \
     (header_tip retained)" n_chain);
let n_undo = Cf_chainstate.cf_clear_undo_data cf in
(* MISSING: Cf_chainstate.put_chain_state cf "reindex_flag" "1" *)
Cf_chainstate.close cf;
```

**Impact.** P1 silent reindex abandonment on crash. Same fleet
pattern as the "plumb-gate-then-flip" finding (W141 nimrod) — the
infrastructure for graceful reindex resume is missing one byte.

---

## BUG-8 — No `xor.dat` block-file obfuscation: production-default Bitcoin Core 25+ XORs every byte of blk*.dat / rev*.dat with an 8-byte key drawn at first run; camlcoin reads/writes plain bytes [P2]

- **File:** `lib/storage.ml:1395-1414, 1525-1541` (write paths,
  unaware of XOR); `lib/storage.ml:1436-1481` (read path, same)
- **Core ref:** `bitcoin-core/src/node/blockstorage.cpp:1167-1215`
  (`InitBlocksdirXorKey`): on first run, draws 8 random bytes;
  persists them at `blocks/xor.dat`; every subsequent
  `AutoFile`-mediated read/write XORs the payload with the key
  cycled mod 8 (`Obfuscation::operator()`). Default-on since v25
  (2023); enforced via `use_xor` opt with default true since v28
  (2024).

**Description.** camlcoin's FlatFileStorage neither writes
`xor.dat` on init (`storage.ml:1335-1346` `create`) nor XORs the
payload on read (`read_block_at_pos` line 1466 reads raw bytes
into `block_buf`). A camlcoin datadir produced by a future
FlatFileStorage migration cannot be opened with `bitcoin-core
--datadir=...` because every byte is XOR'd against zeros (read OK
because XOR with zero is identity → if Core's xor.dat is all zeros,
no harm — but Core only writes an all-zero key when explicitly
configured via `-blocksxor=0`). With Core's default (random key)
this is a hard incompatibility.

**Impact.** P2 cross-impl incompatibility, but only realised once
FlatFileStorage is wired in. The same module already documents the
intent to be Core-compatible (`storage.ml:1052-1056`), so the gap is
substantive when the dead-code wall is dismantled. Compounds with
BUG-2 (magic byte order).

---

## BUG-9 — `Storage.testnet3_magic` and `signet_magic` are entirely absent: `FlatFileStorage` cannot persist blocks on either testnet3 or signet; the only declared network magics are mainnet, testnet4, regtest [P2]

- **File:** `lib/storage.ml:1071-1078`
- **Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:235-238`
  (testnet3 `0B 11 09 07`), `bitcoin-core/src/kernel/chainparams.cpp:479`
  (signet — derived dynamically from the signet challenge hash, but
  the production-default signet is `0A 03 CF 40`)

**Description.** Three magics are declared:

```ocaml
let mainnet_magic = 0xF9BEB4D9l
let testnet4_magic = 0x1C163F28l
let regtest_magic = 0xDAB5BFFAl
```

No `testnet3_magic`, no `signet_magic`. `Consensus.network_config`
(`consensus.ml`) does support a `Testnet3` and `Signet` variant, but
the flat-file persistence layer cannot serialise blocks for either
chain because there is no magic constant to write. A node started
on signet would either (a) fall through to the OCaml exception path
in `FlatFileStorage.create` (no `~magic` default is supplied) or
(b) silently use `mainnet_magic` if a future contributor adds the
default. Both outcomes are wrong.

The `p2p.ml` module has its own duplicate magic table
(`p2p.ml:20 regtest_magic = 0xDAB5BFFAl`, `p2p.ml:21 signet_magic =
0x40CF030Al`) — note `0x40CF030Al` is the byte-reverse of
`0x0A03CF40` and exposes the same int32-vs-bytes confusion as BUG-2.

**Impact.** P2 testnet3/signet operator surface, hard-to-reach
because of BUG-1 (the module isn't live). Same "two-pipeline" fleet
pattern: `Storage.*_magic` (this file) and `P2p.*_magic`
(`p2p.ml:18-21`) are two parallel constant tables; a fix in one is
not propagated to the other.

---

## BUG-10 — `OptimizedUtxoSet` writes UTXOs straight to a separate `rocksdb_utxo/` DB outside the CF chainstate; chain-tip atomicity is per-batch-of-2, not single-batch — crash window between the two writes leaves `cf_utxo` ahead of `rocksdb_utxo` or vice versa [P1]

- **File:** `lib/storage.ml:630-659` (`apply_block_atomic`),
  `lib/rocksdb_store.ml:42-72` (`batch_write` with embedded
  `tip_height`), `lib/storage.ml:498-526` (the `rocksdb_utxo`
  attached-handle mechanism)
- **Core ref:** `bitcoin-core/src/txdb.cpp:23-83`
  (`CCoinsViewDB::BatchWrite`): a single `CDBBatch` writes all UTXO
  inserts + deletes AND the new `DB_BEST_BLOCK` pointer in one atomic
  LevelDB commit.

**Description.** camlcoin's atomicity story for IBD is split across
two stores: `cf_utxo` (inside the main CF chainstate) and
`rocksdb_utxo/` (a separate RocksDB). The commit order is "CF first,
RocksDB second":

```ocaml
Cf_chainstate.batch_write cf_batch;
(match t.rocksdb_utxo with
 | None -> ()
 | Some r -> Rocksdb_store.batch_write ~tip_height r rdb_ops)
```

A crash between these two batches leaves the two stores **disagreeing
on the tip height**. The comment at `storage.ml:624-629` documents
the intended recovery:

> "Commit order is CF-first so a crash between the two commits
>  leaves rdb_tip < chain_tip, which cli.ml's boot consistency
>  check already handles (rewinds blocks_synced to rdb_tip; the
>  next IBD re-processes the gap using RocksDB as the authoritative
>  pre-gap UTXO snapshot via get_utxo's fallback path)."

But that compensation reads RocksDB as the **authoritative** UTXO
source on a crash window, while the CF store had been advanced past
it. If a downstream code path consults `cf_utxo` directly (e.g. the
fast-path `OptimizedUtxoSet.get` that doesn't fall through to
RocksDB on every miss), it will see UTXOs that the
`blocks_synced=rdb_tip` rewind has effectively unspent. This is the
"two-pipeline guard" pattern with a documented but fragile rewind.

Core avoids this entirely by putting `DB_BEST_BLOCK` and every UTXO
mutation in a single `CDBBatch` — LevelDB's atomic commit guarantees
either everything or nothing.

**Impact.** P1 IBD crash-window inconsistency. The compensation
path makes the "best case" workable, but is a "two-pipeline guard
14th distinct extension" pattern: there are now TWO authoritative
UTXO sources, and the consistency check between them lives in
`cli.ml:rewind-on-boot`, NOT in the storage layer.

---

## BUG-11 — `cfh_block_data` puts the **entire serialized block** as one RocksDB CF value: no per-position retrieval, no `getblock verbosity=3` raw-bytes fast path, every block re-serialise on every read [P2]

- **File:** `lib/storage.ml:564-575` (`store_block` / `get_block`),
  `lib/cf_chainstate.ml:213-220` (`put_block_data` /
  `get_block_data` / `delete_block_data`)
- **Core ref:** `bitcoin-core/src/node/blockstorage.cpp:1134-1165`
  (`WriteBlock`): block data lives in the blk*.dat **flat file**,
  and `CDiskBlockIndex` stores the `FlatFilePos` (file_num + offset)
  inside the LevelDB index. `ReadRawBlock`
  (`blockstorage.cpp:1083-1132`) supports a `(offset, size)` partial
  read used by REST `/rest/block/notxdetails` to return a sliced
  payload without decoding.

**Description.** camlcoin's CF approach means every block read is
`cf_get(cfh_block_data, hash) → string → deserialise_block → use`,
which:

- breaks O(1) random-access to a single transaction in a block via
  its `FlatFilePos + tx_offset` (no offset is stored — see W109
  BUG-7 / `m_chain_tx_count`);
- prevents the `REST /rest/block.bin` raw-bytes-pass-through
  optimisation;
- consumes more RocksDB block-cache than necessary (a hot block
  pins the entire ~1 MB value, where Core's flat-file approach
  uses OS page cache more flexibly).

The benefit (single batch write) is partially recouped by Core's
LevelDB index batch atomicity, which writes the
`CDiskBlockIndex` + `'l' = nLastFile` in one commit AFTER the
flat-file data is `fsync`ed.

**Impact.** P2 on-disk efficiency and architectural divergence;
also blocks the REST partial-block path entirely. Re-anchor of W109
BUG-21 against the live path.

---

## BUG-12 — Production-path block storage (sync.ml assume-valid IBD) writes NO block bodies AND NO undo data to disk; `if not ibd_mode then` gate skips both [P0-CDIV / data-loss]

- **File:** `lib/sync.ml:2443-2488`
- **Core ref:** `bitcoin-core/src/validation.cpp:3340-3406`
  (`AcceptBlock`): on `pblock != nullptr`, **always**
  `WriteBlock(...)` and update `nFile`/`nDataPos` even during
  assumevalid IBD. Core's "assumevalid" cuts script verification, NOT
  block persistence. Block bodies + undo data MUST be persisted so
  that:
  - reorg below the assumevalid height has the prevout data;
  - the txindex / blockfilterindex / coinstats indexers can be
    re-derived;
  - pruning has something to prune;
  - other nodes can sync FROM us.

**Description.** camlcoin's IBD branch:

```ocaml
(* Fix 3: Skip block/undo storage during assume-valid IBD *)
if not ibd_mode then begin
  (* Store block *)
  Storage.ChainDB.store_block ibd.chain.db entry.hash block;
  ...
  Storage.ChainDB.store_undo_data ibd.chain.db entry.hash
    (Cstruct.to_string (Serialize.writer_to_cstruct uw))
end;
```

The comment "Fix 3" frames it as a fix; the practical effect is
that a camlcoin node IBD'd via assumevalid:

1. Has NO `cf_block_data` entries below the tip's assumevalid
   height (cannot serve `getblock` for historical blocks);
2. Has NO `cf_undo_data` entries below that height (cannot
   `disconnectblock` to reorg out the assumevalid range);
3. Has no rev*.dat either (FlatFileStorage is dead — BUG-1);
4. Cannot answer `getrawtransaction` for any historical txid
   (txindex hits an empty DB);
5. Cannot serve as a sync source to peers because `cfh_block_data
   .get(hash) == None` for every pre-assumevalid block.

This is the **most consequential live finding** of this audit:
camlcoin's IBD path produces a node that is by Core's definition a
"pruned node" but without any of the pruning machinery to advertise
that to peers (NODE_NETWORK_LIMITED, NODE_NETWORK_NLU). Mainnet
peers will request historical blocks from us and we will silently
return `notfound`.

**Excerpt** (`sync.ml:2443-2488`):

```ocaml
append_filter_if_enabled ibd.chain ~block ~height
  ~spent_utxos:spent_utxo_list;
(* Fix 3: Skip block/undo storage during assume-valid IBD *)
if not ibd_mode then begin
  (* Store block *)
  Storage.ChainDB.store_block ibd.chain.db entry.hash block;
  (* Build undo data from validation's spent_utxo_list (Fix 1) *)
  ...
  Storage.ChainDB.store_undo_data ibd.chain.db entry.hash
    (Cstruct.to_string (Serialize.writer_to_cstruct uw))
end;
```

**Impact.** P0-CDIV (consensus divergence pathway):

- Reorg of any block below the assumevalid height triggers
  `MissingUndoData` (`storage.ml:1797-1808`): the disconnect_block
  helper returns `Error (MissingUndoData block_hash)` and the node
  cannot follow the new chain — silently wedges.
- We do not advertise NODE_NETWORK_LIMITED, so other nodes will
  request blocks we don't have. Per BIP-159 we are misrepresenting
  our service flags.
- Re-IBD-from-checkpoint is impossible because the assumevalid
  blocks are also not stored.

Fleet pattern: matches the "comment-as-confession" finding (5th
camlcoin instance — W141 BUG-13, W138 BUG-3, W139 BUG-7, W142
BUG-1, **W146 BUG-12**): the comment "Fix 3: Skip block/undo
storage during assume-valid IBD" documents a behaviour-skip as if
it were a bug fix when in fact it's a P0-CDIV regression vs Core.

---

## BUG-13 — `find_next_block_pos` has no `nMinDiskSpace` / `out_of_space` check; the node can fill `/` silently and segfault on `write` failure [P1]

- **File:** `lib/storage.ml:1352-1383`
- **Core ref:** `bitcoin-core/src/node/blockstorage.cpp:909-914`:
  `bytes_allocated = m_block_file_seq.Allocate(pos, nAddSize,
  out_of_space); if (out_of_space) { fatalError(_("Disk space is too
  low!")); return {}; }`

**Description.** camlcoin's path never reads `statvfs`, never
checks free space, and never reacts to `ENOSPC`:

```ocaml
let _ = Unix.write fd header_buf 0 8 in
let _ = Unix.write fd (Cstruct.to_bytes block_data) 0 block_size in
```

The two `Unix.write` results are bound to `_` and discarded. A
short-write (signals `ENOSPC` on Linux as a partial result, not an
exception) leaves the file truncated mid-block; the magic-prefix
read on next start will fail without indicating which block was
torn.

**Impact.** P1 disk-fill failure mode + silent corruption. Re-anchor
of W109 BUG-14.

---

## BUG-14 — No `CleanupBlockRevFiles` equivalent: on restart after a partial reindex, stale `blk*.dat`/`rev*.dat` files above the new tip are not removed; future writes append to wrong-version files [P2]

- **File:** `lib/reindex.ml` (no `cleanup_block_rev_files` helper),
  `lib/storage.ml` (no `unlink_pruned_files` analog used by reindex)
- **Core ref:** `bitcoin-core/src/node/blockstorage.cpp:654-688`
  (`CleanupBlockRevFiles`): walks `blocks/` directory, removes all
  `rev?????.dat` and any `blk?????.dat` past the first contiguous gap.

**Description.** Currently a moot point because FlatFileStorage is
dead (BUG-1), but as soon as the live path is migrated, a
`-reindex` against a partially-pruned datadir will leave gaps in
the blk-file sequence and the index `last_file` cursor will collide
with stale files. Re-anchor of W109 BUG-22.

**Impact.** P2 startup-state-cleanup gap.

---

## BUG-15 — `file_info` array is grown with `Array.make (n) (empty_file_info ())`: every slot in the freshly allocated tail aliases the same mutable record [P2]

- **File:** `lib/storage.ml:1358-1370`
- **Core ref:** N/A (OCaml-specific aliasing footgun)

**Description.** Both rotation branches use:

```ocaml
let new_arr = Array.make (t.last_file + 1) (empty_file_info ()) in
Array.blit t.file_info 0 new_arr 0 (Array.length t.file_info);
```

`Array.make n x` shares `x` across all `n` slots. The subsequent
`Array.blit` overwrites slots `0 .. old_len-1` with the prior
records, but if there's a gap — i.e. `t.last_file + 1 > old_len +
1` — the slots between the old end and `last_file` all alias the
**same** `empty_file_info ()` instance. Because `block_file_info`
is a `mutable` record, mutating one slot mutates them all.

The current rotation code does `t.last_file <- t.last_file + 1`, so
the new array is exactly `old_len + 1` slots, and only slot
`last_file` is the newly-allocated one — no aliasing in steady state.
However, the `write_undo` path at `storage.ml:1515-1519` has the
same idiom but with `Array.make (file_num + 1)`, and `file_num` is
read from a block's `entry.file_pos.file_num` — an attacker (or a
prune/rewind scenario) could induce `file_num >> old_len`, at which
point slots `old_len .. file_num - 1` would all be the **same**
shared record, and mutating one (e.g. via concurrent block writes)
mutates the others.

**Impact.** P2 latent OCaml aliasing footgun. Unlikely to be hit in
production today because the rotation invariants are tight, but
will silently corrupt `file_info` state if those invariants break
(prune + write across a wide file-num gap).

---

## BUG-16 — `flat_file_pos.file_num` is `int` (63-bit OCaml integer), serialised as `int32` LE: file numbers above 2^31-1 overflow silently [P3]

- **File:** `lib/storage.ml:1186-1193` (`serialize_pos` /
  `deserialize_pos`)
- **Core ref:** `bitcoin-core/src/flatfile.h` (`FlatFilePos`):
  `int nFile;` (also signed 32-bit, so Core has the same ceiling,
  but Core explicitly uses VARINT in `CDiskBlockIndex` to dodge the
  overflow risk on disk)

**Description.** camlcoin stores `file_num` as `int32` LE:

```ocaml
let serialize_pos w (p : flat_file_pos) =
  Serialize.write_int32_le w (Int32.of_int p.file_num);
  Serialize.write_int32_le w (Int32.of_int p.pos)
```

`Int32.of_int p.file_num` wraps silently when `p.file_num > 2^31-1`.
At 128 MiB per file, exhausting int32 file numbers requires
~256 EiB of chain data (irrelevant), but the same int32 wrap on
`p.pos` matters: every blk file is 128 MiB = 2^27 bytes, well below
int32 range. The bug is the absence of explicit overflow handling
in `Int32.of_int`; OCaml truncates silently. The Core equivalent
field would either be a 32-bit type explicitly or wrapped in a
checked converter.

**Impact.** P3 cosmetic on file-num, P2 latent on pos in a future
hypothetical larger-file mode.

---

## BUG-17 — `ReadBlockFromDisk` equivalent (`read_block_at_pos`) has no obfuscation-key XOR (BUG-8 cross-cite) AND no SHA256d block-hash verification before returning [P2]

- **File:** `lib/storage.ml:1429-1483` (`read_block_at_pos`)
- **Core ref:** `bitcoin-core/src/node/blockstorage.cpp:1052-1080`
  (`ReadBlock`): after deserialisation, computes
  `block.GetHash()` and compares against the expected hash from the
  index entry: `if (block.GetHash() != block_hash) { return false; }`

**Description.** camlcoin reads, deserialises, and returns
`Some block` without verifying that the block hash matches the
caller's expectation. Compared to Core's `ReadBlock`:

```cpp
if (block.GetHash() != index.GetBlockHash()) {
    LogError(...);
    return false;
}
```

A bit-flip in the on-disk blob that doesn't violate the magic
check (e.g. flipping a bit in `merkle_root` or any transaction
body) will pass `read_block_at_pos` and yield a `Some bogus_block`
result. The deserialisation may produce a hash mismatch but the
caller has no signal — `block_hash != Crypto.compute_block_hash
block.header` is not checked anywhere downstream of
`read_block_at_pos`.

**Impact.** P2 silent corruption pathway on read. Same fleet pattern
as the W139 hotbuns "bucket-grid shape mismatch" finding — the
underlying primitive isn't wrong, but the consistency cross-check
is missing.

---

## BUG-18 — Block status bitmask uses synthetic bits 16-21 for validity levels (mapped via `status_to_int`) instead of Core's 3-bit `BLOCK_VALID_MASK = 0x07`; `IsValid` / `RaiseValidity` semantics absent [P2]

- **File:** `lib/storage.ml:1207-1232` (`status_to_int` /
  `int_to_status`)
- **Core ref:** `bitcoin-core/src/chain.h:111-130`:

```cpp
enum BlockStatus : uint32_t {
    BLOCK_VALID_UNKNOWN      =    0,
    BLOCK_VALID_RESERVED     =    1,
    BLOCK_VALID_TREE         =    2,
    BLOCK_VALID_TRANSACTIONS =    3,
    BLOCK_VALID_CHAIN        =    4,
    BLOCK_VALID_SCRIPTS      =    5,
    BLOCK_VALID_MASK         =    BLOCK_VALID_RESERVED | BLOCK_VALID_TREE |
                                  BLOCK_VALID_TRANSACTIONS | BLOCK_VALID_CHAIN |
                                  BLOCK_VALID_SCRIPTS,
    BLOCK_HAVE_DATA          =    8,
    BLOCK_HAVE_UNDO          =   16,
    ...
};
```

The validity level is **3 bits in positions 0-2** (the
`BLOCK_VALID_MASK` enumerated value of 0x07), NOT a separate bit per
level.

**Description.** camlcoin maps each validity level to a unique bit
above 16 in `status_to_int` (lines 1207-1219):

```ocaml
let status_to_int = function
  | Block_valid_unknown      -> 16
  | Block_valid_header       -> 17
  | Block_valid_tree         -> 18
  | Block_valid_transactions -> 19
  ...
  | Block_have_data          ->  3
  | Block_have_undo          ->  4
  ...
```

So setting `Block_valid_scripts` does NOT imply
`Block_valid_chain` (they are distinct bits 21 and 20). In Core,
raising validity to `BLOCK_VALID_SCRIPTS = 5` overwrites the 3-bit
field so the level is monotonically increasing; here the level is
a multi-bit FLAG SET that can in principle contain multiple
validity levels at once. `RaiseValidity(BLOCK_VALID_SCRIPTS)` is
not expressible: there's no equivalent helper that clears bits
16..20 before setting bit 21.

**Impact.** P2 semantic divergence. `getblockheader` validity
reporting silently differs from Core's; `invalidateblock` /
`reconsiderblock` cannot reproduce the exact post-mortem state of
a Core node. Re-anchor of W109 BUG-1, BUG-3, BUG-4 against the
live `status_to_int` definitions.

---

## BUG-19 — `read_undo` / `write_undo` do not verify magic prefix at file boundaries: a torn write leaves the next undo blob's "header" overlapping the previous blob's tail, and `read_undo` will silently return wrong data [P2]

- **File:** `lib/storage.ml:1552-1591` (`read_undo`),
  `lib/storage.ml:1505-1550` (`write_undo`)
- **Core ref:** `bitcoin-core/src/node/blockstorage.cpp:697-730`:
  the undo file uses the **same** `pchMessageStart || size`
  prefix per record and Core verifies the magic on every read via
  `AutoFile`/`BufferedReader` framing.

**Description.** `read_undo` reads the 8-byte header at the
recorded position, **only extracts the size** (lines 1572-1576),
and proceeds — there is no `Int32.equal magic t.magic` check (cf.
`read_block_at_pos` at line 1456 which does check, albeit with the
reversed-byte-order bug from BUG-2). A truncated undo file where
two records overlap will silently deserialise the second record's
tail as part of the first.

**Excerpt** (`storage.ml:1572-1581`):

```ocaml
let size =
  (Char.code (Bytes.get header_buf 4))
  lor (Char.code (Bytes.get header_buf 5) lsl 8)
  lor (Char.code (Bytes.get header_buf 6) lsl 16)
  lor (Char.code (Bytes.get header_buf 7) lsl 24) in
let undo_buf = Bytes.create size in
let n = Unix.read fd undo_buf 0 size in
Unix.close fd;
if n <> size then None
else begin
  let r = Serialize.reader_of_cstruct (Cstruct.of_bytes undo_buf) in
  try Some (deserialize_block_undo r)
```

**Impact.** P2 silent corruption-pathway in undo files. Combined
with BUG-3 (no `pprev_hash` binding) and BUG-4 (no flush on
rotation), the undo path has three independent failure modes that
can all yield "valid-looking" but wrong block-undo data.

---

## BUG-20 — `prune_one_block_file` sets `Block_pruned` as a positive status flag instead of clearing `BLOCK_HAVE_DATA` / `BLOCK_HAVE_UNDO` per Core convention; `IsBlockPruned` semantics drift [P2]

- **File:** `lib/storage.ml:1652-1686` (`prune_one_block_file`),
  `lib/storage.ml:1638-1642` (`is_block_pruned`)
- **Core ref:** `bitcoin-core/src/node/blockstorage.cpp:609-613`
  (`IsBlockPruned`): `return m_have_pruned && !(block.nStatus &
  BLOCK_HAVE_DATA) && (block.nTx > 0);` — no positive "pruned"
  bit; "pruned" is encoded as "block has nTx > 0 (we received it)
  AND we currently don't have its data".

**Description.** camlcoin's pruning path adds a positive flag:

```ocaml
let new_status =
  Block_pruned ::
  (List.filter (fun s ->
    s <> Block_have_data && s <> Block_have_undo
  ) entry.status)
in
```

This works *intrasystem*, but:

1. Cross-impl exchange of `CDiskBlockIndex` records is impossible —
   Core has no Block_pruned bit, so a `BLKIDX01` index serialised
   by camlcoin with `Block_pruned` set is read by Core as `nStatus
   = 0x200` which is undefined.
2. The "pruned" condition is not equivalent to Core's: Core
   considers a block pruned iff `nTx > 0` AND `!BLOCK_HAVE_DATA`.
   camlcoin's flag does not require `nTx > 0`; a block we never
   received but had a header for would still be `Block_pruned` if
   it had ever transited the pruning path (which it would not in
   practice, but the definition is loose).

Re-anchor of W109 BUG-23.

**Impact.** P2 semantic + interop divergence on pruned datadirs.

---

## BUG-21 — Two-pipeline guard: `FlatFileStorage` and `Cf_chainstate` both implement undo-data storage with DIFFERENT checksum domains (single SHA-256(undo) at flat-file level, single SHA-256(undo) again at CF level — see BUG-3); neither matches Core's SHA256d(pprev_hash || undo) [P2]

- **File:** `lib/storage.ml:1024-1048` (`serialize_block_undo`
  embeds a 32-byte SHA-256 checksum into the serialised blob) and
  `lib/storage.ml:865-868` (`store_undo_data` appends a
  32-byte SHA-256 checksum to the value). Both use `Crypto.sha256`
  (single SHA-256).
- **Core ref:** `bitcoin-core/src/node/blockstorage.cpp:967-1024`
  (`WriteBlockUndo`): one SHA256d, bound to `pprev_hash`.

**Description.** Two parallel undo persistence paths each compute
their own checksum, both single SHA-256, neither bound to
`pprev_hash`. The two paths are also not interchangeable: the
flat-file path appends the checksum to the **serialised undo blob**
(so the checksum is INSIDE the size-prefixed body framed by the
magic), whereas the CF path appends it to the value AFTER the
framing. A future read attempt against blobs produced by the wrong
writer fails. This is the "two-pipeline guard" pattern.

**Impact.** P2 architectural divergence with concrete data-loss
pathways if either pipeline is wired in to the other.

---

## BUG-22 — `delete_block` / `delete_undo_data` do not free the underlying RocksDB SST space until the next major compaction; pruning RPC returns success without shrinking disk footprint until a manual `compact_range` runs [P3]

- **File:** `lib/storage.ml:842-847` (`delete_block` /
  `batch_delete_block`), `lib/storage.ml:883-884`
  (`delete_undo_data`), `lib/cf_chainstate.ml:219-220`
  (`delete_block_data`)
- **Core ref:** flat-file pruning is `Sys.remove` on the actual
  blk*.dat — disk space is reclaimed instantly. RocksDB's `Delete`
  only places a tombstone; the space is reclaimed asynchronously
  when SSTs are compacted.

**Description.** Pruning via the CF path (the live path) does NOT
free disk space proportionally to the number of blocks deleted; it
inserts tombstones whose lifetime is governed by RocksDB's level
compaction triggers. On a 100 GiB chainstate, a `prune` RPC may
report "freed 50 GB" but the disk usage drops by only a few GB
until the next major compaction runs (could be hours/days).

**Impact.** P3 operational surprise; the RPC contract leaks.

---

## BUG-23 — `Cf_chainstate.cf_invalidated` stores per-hash "manually invalidated" but does NOT propagate `BLOCK_FAILED_CHILD` to descendants on a single batch — every descendant requires a separate read+write round-trip [P3]

- **File:** `lib/storage.ml:721-735` (`set_block_invalidated` /
  `is_block_invalidated`)
- **Core ref:** `bitcoin-core/src/validation.cpp` `InvalidateBlock`:
  walks descendants and writes `BLOCK_FAILED_CHILD` for each, all
  in one DB batch.

**Description.** `ChainDB.set_block_invalidated` writes one CF
entry per hash; there is no batch wrapper that applies the failure
status to the entire subtree. Re-anchor: the in-memory chain
walking happens in `sync.ml`, but the DB state may be out of sync
with the in-memory state across crash boundaries.

**Impact.** P3 latent crash-recovery gap.

---

## BUG-24 — `FlatFileStorage.iter_blocks` does not respect any sort order; Core's `LoadBlockIndexGuts` returns blocks in `nFile` then `nDataPos` order so the in-memory chain reconstruction is deterministic [P3]

- **File:** `lib/storage.ml:1593-1598`
- **Core ref:** `bitcoin-core/src/node/blockstorage.cpp:118-141`
  (`LoadBlockIndexDB`): pcursor seeks by key, which is `(b, hash)`
  — sorted lexicographically by hash. Then the in-memory rebuild
  uses `pprev` linkage to order by height.

**Description.** `iter_blocks` is `Hashtbl.iter`, which is
unordered. Any caller that depends on iteration order (a
hypothetical "validate all stored blocks in height order" tool)
must re-sort — and on a malformed datadir where some blocks have
broken `pprev` links, the recovery walk is non-deterministic.

**Impact.** P3 minor; relevant only on recovery paths.

---

## BUG-25 — `storage_header_bytes` is hardcoded to `8`; Core's `STORAGE_HEADER_BYTES = MESSAGE_START_SIZE + sizeof(unsigned int) = 4 + 4 = 8`, so the value matches numerically, but camlcoin has NO compile-time link to Core's definition — a future Core change (e.g. extending to support 64-bit sizes) silently breaks [P3]

- **File:** `lib/storage.ml:1069`
- **Core ref:** `bitcoin-core/src/node/blockstorage.h:114`:
  `static constexpr unsigned int STORAGE_HEADER_BYTES = 8;` —
  defined as a single symbol with provenance noted in a comment.

**Description.** camlcoin declares the constant as a magic literal:

```ocaml
(** Storage header size: 4 bytes magic + 4 bytes block size *)
let storage_header_bytes = 8
```

If Core ever extends the size field to 64 bits (block weight is
already pushing the 32-bit limit on individual block payloads —
`MAX_SIZE` is `0x02000000 = 32 MiB`, so this is unlikely, but the
extension has been discussed), camlcoin will silently diverge.

**Impact.** P3 future-proofing gap.

---

## Fleet patterns observed in this audit

- **Dead-class fleet pattern (5th camlcoin instance after W138/W139/W141/W143):**
  `FlatFileStorage` (740 LOC) declared with full API, zero
  production callers (BUG-1).
- **Comment-as-confession (5th camlcoin instance):** `sync.ml:2443`
  `(* Fix 3: Skip block/undo storage during assume-valid IBD *)` —
  a behaviour-skip framed as a fix; the practical consequence is
  P0-CDIV (BUG-12).
- **Two-pipeline guard (14th distinct fleet extension; 6th camlcoin):**
  three separate storage backends (`FileStorage` legacy WAL,
  `FlatFileStorage` blk/rev, `Cf_chainstate` CF) — three distinct
  undo-checksum domains, three distinct magic-handling paths.
  See BUG-21.
- **Byte-order-reversed magic / int32-vs-bytes confusion (3rd
  camlcoin instance):** W141 ZMQ hash byte order LE, `p2p.ml:21
  signet_magic = 0x40CF030Al` (byte-reverse of Core's
  `0A 03 CF 40`), and now `storage.ml:1402-1410` (BUG-2).
- **Carry-forward re-anchor (3rd camlcoin instance after W144 BUG-3,
  W145 BUG-1):** W109's 29 bugs against `FlatFileStorage` carry
  forward intact because the module is dead — W146 re-anchors them
  against the live path (BUGs 3, 4, 5, 6, 7, 10, 11, 13, 14, 18,
  19, 20).
- **Plumb-gate-then-flip (echoed from W141 nimrod):** the
  `if not ibd_mode then begin ... store_block; store_undo_data end`
  guard in `sync.ml:2443-2488` (BUG-12) — the writer infrastructure
  is fully plumbed but a single boolean disables it entirely. Same
  structure as nimrod W141 BUG-26 (getzmqnotifications "field never
  assigned").
- **OCaml-specific aliasing footgun:** BUG-15 (`Array.make` sharing
  a mutable record). First camlcoin instance of this language
  pattern in the campaign.

## Severity rollup

| Severity     | Count |
|--------------|-------|
| P0-CDIV      |   3   |
| P0           |   2   |
| P1           |   5   |
| P2           |  11   |
| P3           |   5   |
| **Total**    | **26**|

The four most consequential live findings:

1. **BUG-12** (P0-CDIV) — IBD path does not persist blocks or undo
   data; node cannot reorg below the assumevalid height, cannot serve
   `getblock` for historical heights, misrepresents service flags.
2. **BUG-3** (P0-CDIV) — Undo checksum is single SHA-256(undo) with
   no `pprev_hash` binding; cross-impl interop broken AND a
   forge-vector for chain-reorg undo binding within a single chain.
3. **BUG-1** (P0) — 740 LOC `FlatFileStorage` module is dead code;
   29 prior bugs carry forward unfixable until the live path is
   rewired.
4. **BUG-2** (P0-CDIV, latent) — Network magic written
   byte-reversed; every blk*.dat camlcoin will produce (when
   FlatFileStorage is live) is rejected by Core. Compounds with
   BUG-8 (no XOR), BUG-9 (no testnet3/signet magic).

## What W146 covered that W109 did not

- The LIVE production path (`Cf_chainstate.cf_block_data` / 
  `cf_undo_data` + `Rocksdb_store`): BUGs 3, 10, 11, 12, 22.
- The byte-order-reversal of the network magic on disk: BUG-2.
- The block-file XOR obfuscation: BUG-8.
- The testnet3 / signet magic absence: BUG-9.
- The `DB_REINDEX_FLAG` byte: BUG-7.
- The `sync.ml` `if not ibd_mode` guard that suppresses block/undo
  persistence: BUG-12.
- The undo-checksum `pprev_hash` binding: BUG-3 / BUG-21 (W109
  BUG-12 only flagged the SHA256 vs SHA256d, not the domain
  separation).
