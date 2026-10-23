# camlcoin

A Bitcoin full node written from scratch in OCaml. One of the ten [hashhog](https://github.com/hashhog) nodes.

> **Experimental.** hashhog nodes are independent re-implementations of Bitcoin Core for research and testing. Do not use them with real funds.

## Status

| Area | State |
|---|---|
| Mainnet validation | Validated mainnet from genesis to height 958,794 with script checks on, in 48 consecutive ranges (each range starts from the UTXO set the previous one ended with). The final UTXO set matched Bitcoin Core's `gettxoutsetinfo` `hash_serialized_3` there (`29692050…6e7af0`, 166,180,925 coins). A second, single-build check (SwiftSync-verified, 2026-10-08) re-ran every block 1 to 958,794 with scripts on and closed on the same hash; it exercises the validation rules, not the UTXO store, and its receipt is in the project's private meta-repo, so you cannot check it from here. How to reproduce: [docs/status.md](docs/status.md). |
| Consensus vectors | Passes all 1,222 entries of Bitcoin Core's `script_tests.json` and Core's `sighash.json` vectors. See [docs/status.md](docs/status.md#cores-test-vectors). |
| RPC | 152 JSON-RPC methods: 126 with Core's names, plus 26 of camlcoin's own (most of them BIP-78 payjoin). Optional read-only REST. See [docs/rpc.md](docs/rpc.md). |
| P2P | Headers-first sync, parallel block download, BIP-324 v2 transport, BIP-152 compact blocks, BIP-155 addrv2, SOCKS5/Tor/I2P outbound. |
| Wallet | Descriptor HD wallets (BIP-32/39/44/84/86), PSBT, multi-wallet. No `bumpfee` or `sendmany`. Not audited. |
| Known limitations | AssumeUTXO (`loadtxoutset`, `--import-utxo`) loads a snapshot into the single chainstate; there is no second, background-validating chainstate. No signet. See [docs/status.md](docs/status.md#known-limitations). |

Last updated: 2026-10-17.

## Quick start

Needs OCaml 5 (tested with 5.3.0), opam 2, dune 3, a C/C++ compiler and the RocksDB,
OpenSSL, ZeroMQ, GMP and libffi libraries. libsecp256k1 is vendored. On Debian 13:

```bash
sudo apt-get install -y build-essential git pkg-config opam ocaml librocksdb-dev libssl-dev libzmq5 libgmp-dev libffi-dev
opam init -y --compiler=ocaml-system && eval $(opam env)
git clone https://github.com/hashhog/camlcoin.git
cd camlcoin
opam install . --deps-only --with-test -y
dune build
./_build/default/bin/main.exe --version
```

Start a regtest node in a throwaway data directory and make an RPC call:

```bash
export DATADIR=$(mktemp -d)
./_build/default/bin/main.exe --network=regtest --datadir="$DATADIR" > "$DATADIR/node.log" 2>&1 &
sleep 5
curl -s --user "$(cat "$DATADIR/.cookie")" -d '{"method":"getblockchaininfo","params":[]}' http://127.0.0.1:18443/
curl -s --user "$(cat "$DATADIR/.cookie")" -d '{"method":"stop","params":[]}' http://127.0.0.1:18443/
```

If your system OCaml is older than 5, see [docs/building.md](docs/building.md), which
also lists what each library is for.

## Running

```bash
./_build/default/bin/main.exe --network=mainnet --datadir="$HOME/.camlcoin"
./_build/default/bin/main.exe --network=testnet --datadir="$HOME/.camlcoin/testnet"
./_build/default/bin/main.exe --network=regtest --datadir="$HOME/.camlcoin/regtest"
```

`--network=testnet` selects testnet4. The data directory is used as given, with no
per-network subdirectory, so give each network its own. Defaults are `~/.camlcoin`,
`~/.camlcoin/testnet3` (testnet4 data, despite the name) and `~/.camlcoin/regtest`.

| Network | P2P port | RPC port |
|---|---|---|
| mainnet | 8333 | 8332 |
| testnet (testnet4) | 18333 | 18332 |
| regtest | 18444 | 18443 |

RPC binds to `127.0.0.1`. A Prometheus metrics endpoint listens on all interfaces, port 9332
(`--metricsport=0` turns it off; a busy port only logs a warning).

A full mainnet node keeps every block: plan for about 1 TB of fast disk, or use
`--prune=550` (or larger, in MiB). Give it at least 32 GB of RAM. `--dbcache=<entries>`
sizes the UTXO cache (default 4,000,000 entries, about 1 GiB). `--noassumevalid`
checks every script from genesis instead of trusting the built-in assume-valid block.

All flags, the config file, the data directory layout and logging are in
[docs/running.md](docs/running.md).

## RPC

camlcoin aims to match Bitcoin Core's JSON-RPC interface: same method names, parameters,
result shapes and error codes. It accepts HTTP Basic auth with the `.cookie` file written
to the data directory at startup, or with `--rpcuser`/`--rpcpassword` (both default to
`camlcoin`; change them if the RPC port is reachable by anyone else):

```bash
curl -s --user "$(cat "$DATADIR/.cookie")" \
  -d '{"jsonrpc":"1.0","id":1,"method":"getblockcount","params":[]}' http://127.0.0.1:18443/
```

The method list and known differences from Core are in [docs/rpc.md](docs/rpc.md).

## Development

```bash
dune test
```

The suite needs no network and no running node; Core's script and sighash vectors are
in `resources/`. See [docs/status.md](docs/status.md#test-suite) for what it covers.

```
bin/main.ml       entry point and command-line flags
lib/cli.ml        node startup, shutdown and the sync loop
lib/validation.ml block and transaction validation; lib/script.ml is the interpreter
lib/utxo.ml       UTXO set and caches; lib/cf_chainstate.ml is the RocksDB chainstate
lib/sync.ml       headers-first sync and block download
lib/peer*.ml      P2P connections, addrman, relay
lib/mempool.ml    mempool policy, RBF, packages
lib/rpc.ml        JSON-RPC; lib/rest.ml is REST
lib/wallet.ml     HD wallet; lib/psbt.ml, lib/descriptor.ml, lib/miniscript.ml
test/             test suite; resources/ holds Core's test vectors
```

The full map is in [docs/architecture.md](docs/architecture.md). See
[CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE).
