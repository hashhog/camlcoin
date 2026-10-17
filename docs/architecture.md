# Architecture

camlcoin is one OCaml library (`lib/`, library name `camlcoin`) and a thin executable
(`bin/main.ml`) that parses flags and calls `Cli.run`. Network I/O uses Lwt cooperative
threads on one main thread; script checks run on OCaml 5 domains.

## Startup and threads

| File | Role |
|---|---|
| `bin/main.ml` | Command-line flags (Cmdliner), config-file overlay, then `Cli.run`. |
| `lib/cli.ml` | Node configuration, startup order (chainstate, RPC, P2P, wallet), sync loop, signal handling, shutdown. |
| `lib/runtime_config.ml` | Config-file parser, PID file, daemon mode, log file and `SIGHUP` reopen, `--ready-fd`. |
| `lib/main_thread.ml` | The single Lwt thread that owns chain state; every block connect and chain-reading RPC runs through it (Core's `cs_main`). |
| `lib/fatal.ml`, `lib/gc_guard.ml` | System faults (I/O error, out of memory) end in a clean halt; heap-compaction guard. |

## Data types and encoding

| File | Role |
|---|---|
| `lib/types.ml` | Blocks, headers, transactions, outpoints as OCaml records and variants. |
| `lib/serialize.ml` | Bitcoin wire serialization (CompactSize, VarInt, witness encoding). |
| `lib/crypto.ml`, `lib/schnorr_stubs.c`, `lib/sha256_accel_stubs.c` | Hashes, ECDSA and Schnorr through the vendored libsecp256k1 (`vendor/secp256k1`), batch verification. |
| `lib/address.ml` | Base58Check and Bech32/Bech32m addresses. |
| `lib/consensus.ml` | Chain parameters for mainnet, testnet4 and regtest; consensus constants; checkpoints and assume-valid. |

## Validation

| File | Role |
|---|---|
| `lib/script.ml` | Script interpreter: legacy, P2SH, SegWit v0, Taproot/Tapscript, sighash. |
| `lib/sig_cache.ml` | Cache of successful script checks. |
| `lib/validation.ml` | Block and transaction checks, `ConnectBlock`, the parallel script-check queue (`--par`), BIP-9 deployments. |
| `lib/sync.ml` | Headers-first sync with PRESYNC/REDOWNLOAD anti-DoS, block download scheduling, reorganization, `invalidateblock`. |
| `lib/assume_utxo.ml`, `lib/compressor.ml` | AssumeUTXO snapshot table, `dumptxoutset`/`loadtxoutset` file format (Core's), coin compression. |
| `lib/reindex.ml`, `lib/block_import.ml` | `--reindex` and `--import-blocks`. |

## Storage

| File | Role |
|---|---|
| `lib/cf_chainstate.ml` | RocksDB with column families in `<datadir>/chainstate/chainstate-rocks`: block index, headers, block bodies, undo data, chain tip. |
| `lib/utxo.ml`, `lib/rocksdb_store.ml` | UTXO set in `<datadir>/rocksdb_utxo`, fronted by an in-memory LRU cache with dirty/fresh flags (`--dbcache`). |
| `lib/storage.ml` | Storage interface, the older file-based store with write-ahead log, pruning, flat-file helpers. |
| `lib/migration.ml` | One-shot migration from the old `data.log` store (`--migrate-logstorage-to-rocksdb`). |
| `lib/rocksdb.ml`, `lib/rocksdb_stubs.c` | Minimal RocksDB bindings. |
| `lib/block_index.ml`, `lib/coinstats_index.ml`, `lib/txospender_index.ml`, `lib/muhash.ml` | Optional indexes: BIP-157/158 filters, per-height MuHash coin stats, spent-outpoint index. |

## P2P

| File | Role |
|---|---|
| `lib/p2p.ml` | P2P message encoding, BIP-324 v2 transport, BIP-155 addrv2, SOCKS5 / Tor / I2P SAM dialing. |
| `lib/peer.ml` | One peer connection: handshake, message loop, inventory, compact blocks (BIP-152), feefilter. |
| `lib/peer_manager.ml` | Address manager (`peers.dat`), outbound selection, inbound limits, eviction, banning, anchors. |
| `lib/asmap.ml` | ASMap lookup for `--asmap`. |
| `lib/bloom.ml` | BIP-37 bloom filters (`--peerbloomfilters`). |
| `lib/package_relay.ml` | BIP-331 package relay messages. |

## Mempool and mining

| File | Role |
|---|---|
| `lib/mempool.ml` | Mempool acceptance and policy, RBF, TRUC (v3), ancestor/descendant limits, packages, `mempool.dat`. |
| `lib/fee_estimation.ml` | Fee estimator (`estimatesmartfee`). |
| `lib/mining.ml` | Block templates (`getblocktemplate`), `submitblock`, regtest `generate*`. |

## RPC and notifications

| File | Role |
|---|---|
| `lib/rpc.ml` | JSON-RPC server and every RPC handler; `dispatch_rpc` is the method table. |
| `lib/rpc_help_text.ml` | `help "<method>"` text. |
| `lib/rest.ml` | Read-only REST interface (`--rest`). |
| `lib/tip_notifier.ml` | Tip-change notification for `waitfor*` RPCs. |
| `lib/zmq_notify.ml`, `lib/zmq_socket.ml`, `lib/zmq_bindings.ml`, `lib/zmq_stubs.c` | ZeroMQ publishers over libzmq. |
| `lib/perf.ml`, `lib/connect_prof.ml` | Performance counters (`getperfstats`) and `--benchmark`. |

## Wallet

| File | Role |
|---|---|
| `lib/wallet.ml` | HD wallets (BIP-32/44/84/86), keys, coin selection (Branch-and-Bound, SRD), signing, encryption, multi-wallet under `<datadir>/wallets/`. |
| `lib/bip39.ml` | Mnemonic seeds. |
| `lib/descriptor.ml`, `lib/miniscript.ml` | Output descriptors (BIP-380 to 386) and miniscript. |
| `lib/psbt.ml` | PSBT (BIP-174, BIP-371 Taproot fields). |
| `lib/payjoin.ml`, `lib/bip21.ml` | BIP-78 payjoin sender and receiver, BIP-21 URIs. |

## Other directories

| Path | Contents |
|---|---|
| `test/` | Test suite (Alcotest), run by `dune test`. `test/support/` holds shared helpers. |
| `resources/` | Bitcoin Core test vectors (`script_tests.json`, `sighash.json`), the BIP-39 word list, Core's RPC parameter counts. |
| `vendor/secp256k1/` | Vendored libsecp256k1. |
| `repair/` | Offline height-index repair tool. |
| `phaseb-shim/` | Script-verification shim for cross-implementation test harnesses. |
| `waveb-boundary-harness/` | Maintainers' harness for the script-exception blocks; needs block fixtures that are not in this repository. |
