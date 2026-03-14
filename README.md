# camlcoin

A Bitcoin full node implementation in OCaml.

## What is it?

Maybe you've wondered what it takes to validate a Bitcoin transaction from
scratch. camlcoin is a from-scratch Bitcoin full node written in OCaml that
does exactly that, using algebraic data types for protocol structures, pattern
matching for opcode dispatch, and Lwt for async I/O.

## Current status

- [x] Project scaffold and dune build system
- [x] Core types (transactions, blocks, headers) with algebraic data types
- [x] Binary serialization (CompactSize, little-endian, segwit)
- [x] Cryptographic primitives (SHA256d, RIPEMD160, secp256k1 ECDSA)
- [x] Merkle root computation
- [x] Address encoding (Base58Check, Bech32/Bech32m, WIF)
- [x] Script interpreter (opcodes, stack machine, P2PKH/P2SH/P2WPKH/P2WSH/P2TR, legacy sighash with FindAndDelete/OP_CODESEPARATOR, witness cleanstack, P2SH push-only, MINIMALIF)
- [x] Consensus parameters (difficulty adjustment, testnet walk-back, BIP94, rewards)
- [x] BIP9 version bits (soft fork activation state machine, signal counting)
- [x] Storage layer (blocks, UTXOs, chain state, batch writes)
- [x] Block and transaction validation (weight, sigops, Merkle, coinbase, BIP68 sequence locks)
- [x] P2P message serialization (version, inv, getdata, blocks, headers, tx)
- [x] Peer connections and handshake (TCP/Lwt, version/verack, ping/pong)
- [x] Peer manager and discovery (DNS seeds, connection pool, addr relay)
- [x] Header synchronization (BIP-130, block locators, proof-of-work tracking, anti-DoS)
- [x] Header-sync anti-DoS (PRESYNC/REDOWNLOAD strategy, constant memory per peer)
- [x] Block synchronization (IBD, parallel downloads, chain reorganization)
- [x] UTXO set with cache (block connect/disconnect, maturity checks)
- [x] Undo data for chain reorganizations (tx_undo, block_undo, checksums)
- [x] Mempool (fee-rate prioritization, eviction, dependency tracking, RBF)
- [x] Fee estimation (bucket-based tracking, confirmation time analysis)
- [x] Block template construction (getblocktemplate, coinbase, witness commitment)
- [x] CPU miner for regtest (proof-of-work search, nonce iteration)
- [x] JSON-RPC interface
- [x] Wallet (key generation, UTXO tracking, coin selection, tx signing)
- [x] Command-line interface
- [x] Test suite (Alcotest unit tests, QCheck property-based tests)
- [x] Performance optimization (LRU cache, compact headers, benchmarks)
- [x] Misbehavior scoring and peer banning (100-point threshold, 24h bans)
- [ ] Compact block relay (BIP 152)
- [ ] Bloom filters (BIP 37)

## Quick start

```
opam switch create . 4.14.2 --deps-only -y
eval $(opam env)
opam install . --deps-only --with-test -y
dune build
dune exec camlcoin -- --help
dune exec camlcoin -- --network regtest --debug
dune exec camlcoin -- --benchmark
```

## Project structure

```
camlcoin/
  bin/main.ml         entry point
  lib/
    types.ml          protocol data types
    serialize.ml      binary serialization
    crypto.ml         hash functions, signatures
    address.ml        address encoding
    script.ml         script interpreter
    consensus.ml      consensus parameters, BIP9 versionbits
    validation.ml     block/tx validation
    storage.ml        block/utxo storage
    utxo.ml           UTXO set with LRU cache
    p2p.ml            network protocol
    peer.ml           peer connections
    peer_manager.ml   connection pool and discovery
    sync.ml           chain synchronization
    mempool.ml        transaction pool
    fee_estimation.ml fee rate estimation
    mining.ml         block template and miner
    rpc.ml            JSON-RPC server
    wallet.ml         HD wallet, UTXO tracking, tx signing
    perf.ml           performance utilities and benchmarks
    cli.ml            command line interface
    camlcoin.ml       library interface
  test/               unit tests
  resources/          BIP39 wordlist
```

## Running tests

```
dune test
```
