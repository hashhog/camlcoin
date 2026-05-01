# camlcoin

A Bitcoin full node implementation in OCaml.

## Quick Start

### Docker

```bash
docker build -t camlcoin .
docker run -v camlcoin-data:/data -p 48347:48347 -p 48337:48337 camlcoin
```

### From Source

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

Bitcoin Core-compatible JSON-RPC with batch request support.

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
