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
- [x] Script interpreter (opcodes, stack machine, P2PKH/P2SH/P2WPKH/P2WSH/P2TR/P2A, legacy sighash with FindAndDelete/OP_CODESEPARATOR, witness cleanstack, P2SH push-only, MINIMALIF, NULLFAIL)
- [x] Consensus parameters (difficulty adjustment, testnet walk-back, BIP94, rewards)
- [x] BIP9 version bits (soft fork activation state machine, signal counting)
- [x] Storage layer (blocks, UTXOs, chain state, batch writes, flat files)
- [x] Block and transaction validation (weight, sigops, Merkle, coinbase, BIP68 sequence locks)
- [x] P2P message serialization (version, inv, getdata, blocks, headers, tx)
- [x] Peer connections and handshake (TCP/Lwt, version/verack, ping/pong)
- [x] Peer manager and discovery (DNS seeds, connection pool, addr relay)
- [x] Header synchronization (BIP-130, block locators, proof-of-work tracking, anti-DoS)
- [x] Header-sync anti-DoS (PRESYNC/REDOWNLOAD strategy, constant memory per peer)
- [x] Block synchronization (IBD, parallel downloads, chain reorganization)
- [x] UTXO set with cache (block connect/disconnect, maturity checks, layered cache with batch flushing)
- [x] Undo data for chain reorganizations (tx_undo, block_undo, checksums)
- [x] Mempool (fee-rate prioritization, eviction, dependency tracking, full RBF, ancestor/descendant limits, v3/TRUC policy, cluster mempool with linearization, P2A anchor outputs)
- [x] Fee estimation (bucket-based tracking, confirmation time analysis)
- [x] Block template construction (getblocktemplate, coinbase, witness commitment)
- [x] CPU miner for regtest (proof-of-work search, nonce iteration)
- [x] JSON-RPC interface (batch requests, parallel processing)
- [x] Wallet (BIP-39 mnemonic, BIP-32/44/84/86 derivation, coin selection with BnB+SRD, passphrase encryption with PBKDF2-SHA512, multi-wallet support)
- [x] Command-line interface
- [x] Test suite (Alcotest unit tests, QCheck property-based tests)
- [x] Performance optimization (LRU cache, compact headers, benchmarks, parallel validation)
- [x] Hardware-accelerated cryptography (libsecp256k1 FFI, batch Schnorr verification, ECDSA fast path)
- [x] Misbehavior scoring and peer banning (100-point threshold, 24h bans)
- [x] Pre-handshake message rejection (60s timeout, self-connection detection)
- [x] Inventory trickling (Poisson-scheduled tx relay, 5s inbound, 2s outbound)
- [x] Eclipse attack protections (bucketing, multi-criteria eviction, netgroup diversity, anchors)
- [x] Stale peer eviction (headers timeout, block stalling, ping timeout, 45s check)
- [x] Checkpoint verification (hardcoded checkpoints, assume_valid, minimum_chain_work)
- [x] sendrawtransaction broadcast (mempool validation, maxfeerate/maxburnamount, peer relay)
- [x] getrawtransaction RPC (mempool lookup, txindex, blockhash param, verbose JSON)
- [x] Flat file block storage (blk/rev files, block index, 128MB file rotation)
- [x] Block pruning (-prune=N, 550MB minimum, txindex incompatible, 288 block safety margin)
- [x] Coinbase maturity (100-block delay for coinbase spends, enforced in block validation and mempool)
- [x] Wallet encryption (encryptwallet, walletpassphrase, walletlock, passphrase change, timeout-based auto-lock)
- [x] Block indexes (hash index, height index, BIP-157/158 compact block filters with GCS)
- [x] Compact block relay (BIP 152, SipHash, short IDs, block reconstruction)
- [x] Package relay (BIP 331, 1p1c topology, CPFP fee-bumping, topological sort, ephemeral anchors)
- [x] PSBT (BIP-174, creator/updater/signer/combiner/finalizer/extractor roles, taproot support)
- [x] Output descriptors (BIP 380-386, checksum, parsing, script generation, range expansion)
- [x] Miniscript (type system, script generation, satisfaction, parsing, wsh(miniscript) support)
- [x] BIP-133 feefilter (Poisson timing, noise rounding, block-relay-only exclusion)
- [x] AssumeUTXO (BIP 199, snapshot loading, dual chainstate, background validation)
- [x] REST API (block, tx, headers, chaininfo, mempool, blockhashbyheight, .json/.hex/.bin formats)
- [x] ZMQ notifications (hashblock, hashtx, rawblock, rawtx, sequence topics, 4-byte LE sequence numbers)
- [x] Regtest mode (generate, generatetoaddress, generateblock RPCs, instant mining)
- [x] Block invalidation (invalidateblock, reconsiderblock RPCs, descendant tracking, chain reorg)
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
    storage.ml        block/utxo storage, flat files
    utxo.ml           UTXO set, layered cache with batch flushing
    p2p.ml            network protocol
    peer.ml           peer connections
    peer_manager.ml   connection pool and discovery
    sync.ml           chain synchronization
    mempool.ml        transaction pool, cluster mempool, linearization
    fee_estimation.ml fee rate estimation
    mining.ml         block template and miner
    rpc.ml            JSON-RPC server
    rest.ml           REST API server
    wallet.ml         HD wallet, BIP-39/44/84/86, coin selection, encrypted storage, multi-wallet
    bip39.ml          mnemonic generation and seed derivation
    block_index.ml    block indexes, BIP-157/158 filters, height index
    psbt.ml           PSBT (BIP-174) multi-party signing
    descriptor.ml     output descriptors (BIP 380-386)
    miniscript.ml     miniscript (type system, script generation, satisfaction)
    assume_utxo.ml    assumeUTXO (BIP 199, snapshot loading, background validation)
    zmq_notify.ml     ZeroMQ pub/sub notifications for blocks and transactions
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
