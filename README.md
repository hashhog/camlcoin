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
- [x] Script interpreter (opcodes, stack machine, P2PKH/P2SH/P2WPKH/P2WSH/P2TR)
- [x] Consensus parameters (difficulty, rewards, network configs)
- [x] Storage layer (blocks, UTXOs, chain state, batch writes)
- [x] Block and transaction validation (weight, sigops, Merkle, coinbase)
- [x] P2P message serialization (version, inv, getdata, blocks, headers, tx)
- [x] Peer connections and handshake (TCP/Lwt, version/verack, ping/pong)
- [x] Peer manager and discovery (DNS seeds, connection pool, addr relay)
- [x] Header synchronization (BIP-130, block locators, proof-of-work tracking)
- [ ] Block synchronization
- [ ] Mempool
- [ ] JSON-RPC interface
- [ ] Wallet functionality

## Quick start

```
opam switch create . 4.14.2 --deps-only -y
eval $(opam env)
opam install . --deps-only --with-test -y
dune build
dune exec camlcoin
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
    consensus.ml      consensus parameters
    validation.ml     block/tx validation
    storage.ml        block/utxo storage
    p2p.ml            network protocol
    peer.ml           peer connections
    peer_manager.ml   connection pool and discovery
    sync.ml           chain synchronization
    mempool.ml        transaction pool
    rpc.ml            JSON-RPC server
    wallet.ml         key management
    cli.ml            command line interface
    camlcoin.ml       library interface
  test/               unit tests
```

## Running tests

```
dune test
```
