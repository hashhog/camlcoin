# camlcoin

A Bitcoin full node implementation in OCaml.

## What is it?

Maybe you've wondered what it takes to validate a Bitcoin transaction from
scratch. camlcoin is a from-scratch Bitcoin full node written in OCaml that
does exactly that, using algebraic data types for protocol structures, pattern
matching for opcode dispatch, and Lwt for async I/O.

## Current status

- [x] Project scaffold and dune build system
- [ ] Core types and serialization
- [ ] Cryptographic primitives (SHA256, RIPEMD160, secp256k1)
- [ ] Address encoding (Base58Check, Bech32)
- [ ] Script interpreter
- [ ] Block and transaction validation
- [ ] P2P networking
- [ ] Chain synchronization
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
    consensus.ml      validation rules
    storage.ml        block/utxo storage
    p2p.ml            network protocol
    peer.ml           peer connections
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
