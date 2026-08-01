# Changelog

All notable changes to camlcoin are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-07-31

First stable release of camlcoin, a Bitcoin full node implementation in OCaml.

### Highlights

- Full block and transaction validation (SegWit, Taproot, BIP68 sequence locks,
  BIP-141 weighted sigops with witness discount)
- Script interpreter (P2PKH, P2SH, P2WPKH, P2WSH, P2TR, P2A anchors, legacy
  sighash with FindAndDelete/OP_CODESEPARATOR, NULLFAIL, MINIMALIF)
- Header-first sync with anti-DoS (PRESYNC/REDOWNLOAD strategy) and parallel
  block download with chain reorganization support
- RocksDB-backed UTXO set with layered cache and batch flushing
- Cluster mempool (union-find clustering, linearization, full RBF, v3/TRUC
  policy, P2A anchor outputs)
- Package relay (BIP-331), compact block relay (BIP-152), BIP-324 v2 encrypted
  transport, BIP-155 ADDRv2, BIP-133 feefilter, BIP-9 versionbits
- AssumeUTXO (BIP-199): snapshot loading, dual chainstate, background validation
- HD wallet (BIP-39/32/44/84/86, BnB+SRD coin selection), PSBT (BIP-174),
  output descriptors (BIP-380-386), Miniscript
- Block pruning, BIP-157/158 compact block filters, flat-file block storage
- Bitcoin Core-compatible JSON-RPC (with batch support), REST API, ZMQ
  notifications, Tor/I2P proxy support, regtest mode

### Consensus / policy parity fixes (pre-release hardening)

- RBF Rule 5 bounds distinct clusters, not evicted entries; Core v31 cluster
  limits with staged RBF removals before the gate
- Unconditional P2SH|WITNESS|TAPROOT script flags and Core's replace-then-OR
- Dropped RBF Rule 2 (HasNoNewUnconfirmed) for cluster-mempool Core parity
- `submitblock` checks `nBits == required` difficulty (`bad-diffbits`) and runs
  the context-free CheckBlock merkle check eagerly (`bad-txnmrklroot`)
- Witness-commitment block errors map to their BIP-22 reject tokens
- P2P reorg: activate-best-chain, undo persist, unspendable filter
- `--noassumevalid` flag to disable assumevalid (full script validation)
- Correct testnet4 magic byte order; advertise the real min-relay fee in
  feefilter; compact-block getblocktxn round-trip carries mempool matches
  (BIP-152 overlap bug)
- AssumeUTXO background validation now computes median-time-past from the
  header chain (BIP-113) instead of passing 0, so the nTime > MTP rule and
  BIP-68/113 lock-time cutoffs are enforced on the snapshot path

### Performance

- Parallel script-verify Domain pool (Core CCheckQueue parity)
- Eliminated O(N²) whole-pool scans and O(pool) per-accept GC churn wedging
  the RPC domain under mempool saturation

### Build / packaging

- Requires OCaml >= 5.1 (Domain/Mutex.protect); verified with OCaml 5.1.1
- User-local RocksDB include path (~/.local/include) baked into dune
  foreign-stubs flags; CPATH remains an override
- Declared the `bigstring` shim dependency in the opam file
- Enabled CI and release GitHub Actions workflows
