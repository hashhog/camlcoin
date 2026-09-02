# camlcoin

A Bitcoin full node implementation in OCaml.

## Status — v1.0.0

**Label: "Replay-verified"**
(`receipts/RELEASE-v1.0-SCORECARD.md`, §What each label means). That label is
deliberately weaker than "Validated", and the scorecard spells out why: it means
camlcoin agreed with Core on every block the nightly instruments showed it — 169
distilled real mainnet blocks, 10 block-context corpus entries, and its row in the
nightly corpus sweep — and that the 26,067-height stateless replay has since
COMPLETED: 26,067 distinct heights, `accept` on every one, 0 disagreements, 0
harness-limit rows, against 51,512 rejected control twins (scorecard footnote
[1], which also records that the first run silently compared only 65% of its
input and had to be re-run).
> **What that does and does not mean.** It is a *stateless* re-check of each block
> against Core's rules with scripts on. It is **not** a from-genesis reproduction
> of Core's UTXO set, and this node still has **no from-genesis evidence at all**. The git tag `v0.1.0-beta1`
(`receipts/RELEASE-v1.0-FREEZE.md`) says the same thing from the other side: `rc`
is reserved for an independent from-genesis `--assumevalid=0` reproduction of
Core's UTXO-set commitment, and `beta` means that receipt does not exist
(`receipts/beta1-tag-drafts-2026-08-20.md:23-27`). Neither label certifies wallet
or fund-custody readiness — see `SECURITY.md`.

**camlcoin has not been shown to validate the chain from genesis.** There is no
camlcoin row in the reproduction ledger (`receipts/TRUST-ANCHOR.md:140-145`) and
no camlcoin replay ledger in `CORE-PARITY-AUDIT/replay-ledgers/`.
`receipts/SYNCS.md:29` records the live mainnet chainstate as a Core-format UTXO
snapshot bootstrap at base height 944183, with "from-genesis full script
validation **UNKNOWN** — no banked AV=0/genesis replay found". Two capture
receipts written 15 seconds apart on 2026-07-30 disagree with each other:
`receipts/T2-capture-camlcoin-20260730T235234Z.md` reports a MISMATCH whose
"got" value is the literal sentinel `deadbeefdeadbeef…` (a harness self-test),
and `receipts/T2-capture-camlcoin-20260730T235249Z.md` reports a MATCH; neither
was ever ratified into the ledger, and the second says of itself "This receipt is
EVIDENCE, not a ledger entry." The release scorecard adjudicates them: both were
written the same day as `8c56180`, whose commit body documents a four-branch
mock-RPC self-test that emits exactly a MISMATCH receipt followed by a MATCH
receipt, and a `deadbeef` sentinel is not a chain value — so on that evidence
these are self-test output, not captures
(`receipts/RELEASE-v1.0-SCORECARD.md`, camlcoin row). Do not read either as a
from-genesis proof. A reader of this repository alone should assume camlcoin's
from-genesis validation is untested.

**Operator RPC parity: 50 of Bitcoin Core's 85** — arithmetically the lowest in
the fleet *in this run*; two probe runs ten minutes apart disagreed by ±2 on other
nodes with no deploy between them, so treat the ranking as run-scoped. From
the 103-method R5 operator probe run 2026-09-01
(`tools/diff-test-artifacts/r5-probe/20260901T182642Z.json`): camlcoin 50 PASS /
35 FAIL, Bitcoin Core 85 PASS on the same probe, 18 methods unmeasured
(`SKIP-REGTEST`) for every node including Core. Failures include wrong error
codes (`getmempoolentry` on a transaction not in the mempool returns `-1` where
Core returns `-5`) and calls that succeed where Core errors
(`getblockstats` with an invalid stat name).

**Known gaps in this repo** (`receipts/UNIT-BASELINE-v1.0.md`, 2026-09-01): the
suite went 26 failing → 0 across 109 test executables, but 24 gates in
`test_w109_block_index` are carried as explicit skips (`W109-G2` … `W109-G29` —
Core-internal structures such as the skip list, VARINT `CDiskBlockIndex`, the
LevelDB `BlockTreeDB`, 16 MiB preallocation and `nMinDiskSpace`, which have no
camlcoin equivalent); `G17` and `G25` are flagged for a behavioural re-check
before closing. Four real bugs were fixed and mutation-verified in that pass,
including `f7d05a8`: before it, a wrong passphrase on an empty wallet could
unlock it with a 47-byte garbage key.

**Fleet-wide comparison:** `receipts/RELEASE-v1.0-SCORECARD.md` in the hashhog
meta-repo, which is **not public** — see the note below.

> **The cited paths are NOT publicly readable — do not treat them as evidence.**
> Paths beginning `receipts/`, `tools/`, `docs/` and `CORE-PARITY-AUDIT/` refer to
> the hashhog meta-repo, which is a **private** repository, not to this one. They
> are provenance for the maintainers. From outside, any claim resting only on such
> a path is **unverified**, and you should read it as such.
>
> Two of those paths are unreadable even with the meta-repo in hand: the R5 probe
> JSON is gitignored (`.gitignore:60  tools/diff-test-artifacts/`) and so are the
> nightly `diffguard-*.log` files (`.gitignore:43  *.log`). Regenerate the probe
> JSON with `python3 tools/r5_probe.py` against a running fleet.
>
> **What you can check from this repository alone:** build it, run its own test
> suite, and reproduce its behaviour against Bitcoin Core yourself. That is the
> evidence this repo actually ships.

## Quick Start

### Docker

```bash
docker build -t camlcoin .
docker run -v camlcoin-data:/data -p 48347:48347 -p 48337:48337 camlcoin
```

### From Source

Toolchain: OCaml >= 4.14.0 (`camlcoin.opam`; 4.14.2 below, Docker uses 5.1) with dune >= 3.0 and opam.
System libraries (linked by `lib/dune`; secp256k1 is vendored): librocksdb-dev, libssl-dev (libcrypto), libzmq (libzmq.so.5), libgmp-dev, libffi-dev, libev-dev, pkg-config, a C++ runtime (libstdc++).

```bash
opam switch create . 4.14.2 --deps-only -y
eval $(opam env)
opam install . --deps-only --with-test -y
dune build
dune exec camlcoin -- --network=testnet --debug
```

## Features

- Full block and transaction validation (SegWit, Taproot, BIP68 sequence locks, BIP-141 weighted sigops with witness discount)
- Script interpreter (P2PKH, P2SH, P2WPKH, P2WSH, P2TR, P2A anchors, legacy sighash with FindAndDelete/OP_CODESEPARATOR, NULLFAIL, MINIMALIF, witness cleanstack, P2SH push-only)
- Header-first sync with anti-DoS (PRESYNC/REDOWNLOAD strategy, constant memory per peer)
- Parallel block download with chain reorganization support
- UTXO set with layered cache and batch flushing (RocksDB-backed, dirty/fresh flags)
- Cluster mempool (union-find clustering, linearization, full RBF, v3/TRUC policy, P2A anchor outputs)
- Package relay (BIP-331, 1p1c topology, CPFP fee-bumping, ephemeral anchors)
- Compact block relay (BIP-152, SipHash, short IDs, block reconstruction, high-bandwidth mode)
- BIP-324 v2 encrypted transport (ElligatorSwift key exchange, ChaCha20-Poly1305 AEAD)
- BIP-155 ADDRv2 (Tor v3, I2P, CJDNS network addresses)
- BIP-133 feefilter (Poisson timing, noise rounding, block-relay-only exclusion)
- BIP-9 versionbits soft fork activation tracking
- Eclipse attack protections (bucketing, multi-criteria eviction, netgroup diversity, anchors)
- Stale peer eviction (headers timeout, block stalling, ping timeout)
- Inventory trickling (Poisson-scheduled tx relay, 5s inbound, 2s outbound)
- Misbehavior scoring and peer banning (100-point threshold, 24h bans)
- Checkpoint verification (hardcoded checkpoints, assume_valid, minimum_chain_work)
- HD wallet (BIP-39 mnemonic, BIP-32/44/84/86, BnB+SRD coin selection, PBKDF2-SHA512 encryption, multi-wallet)
- PSBT (BIP-174, all roles: creator/updater/signer/combiner/finalizer/extractor, taproot support)
- Output descriptors (BIP-380-386, checksum, parsing, script generation, range expansion)
- Miniscript (type system, script generation/decompilation, optimal satisfaction with DP, wsh integration)
- AssumeUTXO (BIP-199, snapshot loading, dual chainstate, background validation)
- Block pruning (-prune=N, 550MB minimum, 288 block safety margin)
- Block indexes (hash index, height index, BIP-157/158 compact block filters with GCS)
- Flat file block storage (blk/rev files, block index, 128MB file rotation)
- Fee estimation (bucket-based tracking, confirmation time analysis)
- Block template construction (getblocktemplate, coinbase, witness commitment)
- REST API (block, tx, headers, chaininfo, mempool, blockhashbyheight; .json/.hex/.bin formats)
- ZMQ notifications (hashblock, hashtx, rawblock, rawtx, sequence topics)
- Tor and I2P proxy support (SOCKS5, I2P SAM protocol, stream isolation)
- Hardware-accelerated cryptography (libsecp256k1 FFI, batch Schnorr verification)
- Regtest mode (generate, generatetoaddress, generateblock RPCs, 150-block halving)
- Chain management (invalidateblock, reconsiderblock RPCs, descendant tracking)

## Configuration

### CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--network=NET` | `mainnet` | Network: mainnet, testnet, regtest |
| `--datadir=DIR` | `~/.camlcoin` | Data directory |
| `--rpchost=HOST` | `127.0.0.1` | RPC server bind address |
| `--rpcport=PORT` | per-network | RPC server port |
| `--rpcuser=USER` | `camlcoin` | RPC username |
| `--rpcpassword=PASS` | `camlcoin` | RPC password |
| `--port=PORT` | per-network | P2P listen port |
| `--maxoutbound=N` | `8` | Maximum outbound peers |
| `--maxinbound=N` | `117` | Maximum inbound peers |
| `--connect=ADDR` | none | Connect to specific peer (repeatable) |
| `--debug` | off | Enable debug logging |
| `--disablewallet` | off | Disable wallet functionality |
| `--prune=N` | `0` | Prune target in MB (0=disabled) |
| `--benchmark` | off | Run performance benchmarks and exit |
| `--import-blocks=PATH` | none | Import blocks from file (`-` for stdin) |
| `--import-utxo=PATH` (alias `--load-snapshot=PATH`) | none | Load a Bitcoin Core `dumptxoutset` snapshot file. Wire format is byte-identical to Core 31.99 (`utxo\xff` magic, version 2, ScriptCompression-encoded coins). The file is verified against camlcoin's hardcoded AssumeUTXO heights (840k / 880k / 910k / 935k mainnet) before any coin is loaded. |

Cookie-based authentication is generated automatically in `$datadir/.cookie`.

## RPC API

JSON-RPC modelled on Bitcoin Core's, with batch request support. Not behaviourally compatible: on the 2026-09-01 operator probe camlcoin answers 50 of the 103 probed methods correctly against Core's 85 — the lowest of the ten implementations — with 35 failures, including wrong error codes and calls that succeed where Core errors (`tools/diff-test-artifacts/r5-probe/20260901T182642Z.json`).

| Category | Methods |
|----------|---------|
| Blockchain | `getbestblockhash`, `getblock`, `getblockchaininfo`, `getblockcount`, `getblockhash`, `getblockheader`, `getblockstats`, `getblockfilter`, `getdifficulty`, `gettxout` |
| Transactions | `getrawtransaction`, `sendrawtransaction`, `decoderawtransaction`, `signrawtransactionwithkey` |
| Mempool | `getmempoolancestors`, `getmempooldescendants`, `getmempoolentry`, `getmempoolinfo`, `getrawmempool`, `testmempoolaccept` |
| Mining | `getblocktemplate`, `getmininginfo`, `submitblock`, `generate`, `generatetoaddress`, `generateblock` |
| Network | `addnode`, `clearbanned`, `disconnectnode`, `getconnectioncount`, `getnetworkinfo`, `getpeerinfo`, `listbanned`, `setban` |
| Wallet | `getbalance`, `getnewaddress`, `listtransactions`, `listunspent`, `sendtoaddress`, `signrawtransactionwithwallet` |
| PSBT | `analyzepsbt`, `combinepsbt`, `converttopsbt`, `createpsbt`, `decodepsbt`, `finalizepsbt`, `utxoupdatepsbt` |
| Descriptors | `deriveaddresses`, `getdescriptorinfo`, `listdescriptors` |
| Util | `estimatesmartfee`, `validateaddress` |
| Chain Mgmt | `invalidateblock`, `reconsiderblock` |
| assumeUTXO | `loadtxoutset`, `dumptxoutset` |
| Control | `help`, `stop`, `uptime` |
| Debug | `getperfstats` |

REST API available with endpoints for blocks, transactions, headers, chain info, mempool, and block hash by height.

## Monitoring

No built-in Prometheus exporter. Monitor via RPC calls to `getblockchaininfo`, `getpeerinfo`, `getmempoolinfo`, and `getnetworkinfo`.

## Architecture

camlcoin uses OCaml's algebraic data types to model Bitcoin protocol structures as precise sum and product types, catching malformed data at parse time rather than through runtime checks. Protocol messages, script opcodes, and transaction components are all represented as variants, and the script interpreter uses pattern matching for opcode dispatch. The Lwt cooperative threading library handles all network I/O, with each peer connection running as a lightweight Lwt thread managed by the peer manager.

The storage layer combines LevelDB for the block index and chain metadata with RocksDB for the UTXO set. The UTXO cache implements a layered architecture with an in-memory LRU cache of up to 4 million entries backed by RocksDB, using dirty/fresh flags to minimize disk writes during batch flush. OCaml's GC is tuned for server workloads: a 32MB minor heap reduces collection frequency during block validation, and relaxed compaction thresholds trade memory for throughput on high-RAM systems.

Cryptographic operations use FFI bindings to libsecp256k1 for ECDSA and Schnorr signature verification, with batch verification support to amortize overhead. Hardware-accelerated SHA256 stubs provide native-speed hashing for block and transaction ID computation. The signature cache stores verified signatures to avoid redundant verification during mempool acceptance and block validation.

The wallet implements BIP-39 mnemonic seed generation with BIP-32/44/84/86 hierarchical deterministic key derivation, supporting P2PKH, P2WPKH, and P2TR address types. Coin selection uses a combination of Branch-and-Bound and Single Random Draw algorithms. PSBT support covers all roles defined in BIP-174 (creator, updater, signer, combiner, finalizer, extractor), and the miniscript compiler uses dynamic programming for optimal witness satisfaction.

## License

MIT
