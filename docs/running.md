# Running camlcoin

The binary is `_build/default/bin/main.exe` after `dune build` (see
[building.md](building.md)). Examples below use `camlcoin` for it:

```bash
alias camlcoin="$PWD/_build/default/bin/main.exe"
camlcoin --help
```

## Networks

| `--network=` | Chain | Default datadir | P2P port | RPC port |
|---|---|---|---|---|
| `mainnet` (default) | mainnet | `~/.camlcoin` | 8333 | 8332 |
| `testnet` | testnet4 | `~/.camlcoin/testnet3` | 18333 | 18332 |
| `regtest` | regtest | `~/.camlcoin/regtest` | 18444 | 18443 |

There is no signet. `testnet` uses testnet4's chain parameters, but the default ports
and directory name are testnet3's; pass `--port` and `--rpcport` if you want testnet4's
usual 48333/48332.

The data directory is used as given: camlcoin does not add a per-network subdirectory.
Do not point two networks at the same `--datadir`.

## Command-line flags

Flags take `--flag=value` or `--flag value`. `camlcoin --help` prints the full text for
each one.

### General

| Flag | Default | Meaning |
|---|---|---|
| `-n`, `--network=NETWORK` | `mainnet` | `mainnet`, `testnet` (testnet4) or `regtest`. |
| `-d`, `--datadir=DIR` | per network | Data directory. |
| `--conf=FILE` | `<datadir>/camlcoin.conf` | Config file (see below). |
| `--daemon` | off | Fork to the background after startup. Use `--logfile` to keep logs. |
| `--pid=PATH` | `<datadir>/camlcoin.pid` | PID file. Startup refuses if it names a live process. |
| `--ready-fd=N` | none | Write one byte to fd N once RPC and P2P are up. |
| `--disablewallet` | off | Do not load wallets. |
| `--version` | | Print the version and exit. |

### Chain and validation

| Flag | Default | Meaning |
|---|---|---|
| `--noassumevalid` | off | Check every script from genesis (Core's `-assumevalid=0`). |
| `--prune=MIB` | `0` | `0` keeps all blocks, `1` allows `pruneblockchain` only, `>=550` prunes to that many MiB. |
| `--dbcache=ENTRIES` | `4000000` | UTXO cache size in entries (about 256 bytes each). Also sizes the RocksDB caches. |
| `--par=N` | `0` | Script-check threads: `0` all cores, `1` serial, `n<0` leave that many cores free. |
| `--reindex` | off | Wipe the chainstate and rebuild it from the stored blocks. |
| `--txindex=VAL` | | Accepted for compatibility; the transaction index is always kept. |
| `--blockfilterindex=VAL` | `0` | `1`/`basic` keeps a BIP-158 filter index (`indexes/blockfilter/basic`). |
| `--coinstatsindex=VAL` | `0` | `1` keeps a per-height MuHash index for `gettxoutsetinfo` at past heights. |
| `--txospenderindex=VAL` | `0` | `1` keeps a spent-outpoint index for `gettxspendingprevout` on confirmed spends. |
| `--import-utxo=PATH` | none | Load a Bitcoin Core `dumptxoutset` file into a fresh chainstate, then sync forward. Alias `--load-snapshot`. |
| `--import-blocks=PATH` | none | Import framed blocks from a file (`-` for stdin) instead of P2P. |
| `--migrate-logstorage-to-rocksdb` | off | Migrate a datadir from the old `data.log` storage to RocksDB, then exit. |
| `--benchmark` | off | Run micro-benchmarks and exit. |

`--import-utxo` only accepts snapshots whose block hash and coin count match the
built-in AssumeUTXO table (mainnet heights 840,000, 880,000, 910,000 and 935,000), and
only when the chainstate is empty.

### P2P

| Flag | Default | Meaning |
|---|---|---|
| `-p`, `--port=PORT` | per network | P2P listen port. |
| `--maxoutbound=N` | `8` | Outbound connection limit. |
| `--maxinbound=N` | `117` | Inbound connection limit. |
| `-c`, `--connect=ADDR` | none | Connect only to this peer (repeatable). Disables DNS seeds and automatic outbound. |
| `--nodnsseed` | off | Do not query DNS seeds. |
| `--externalip=IP[:PORT]` | none | Address to advertise to peers (repeatable). |
| `--discover[=0\|1]` | `1` | Learn our address from peers. Off by default when `--externalip` is set. |
| `--peerbloomfilters=BOOL` | `false` | Serve BIP-37 bloom filters and advertise `NODE_BLOOM`. |
| `--asmap=FILE` | none | Bucket peers by ASN using an asmap file. |
| `--proxy=HOST:PORT` | none | SOCKS5 proxy for outbound connections. |
| `--onion=HOST:PORT` | none | SOCKS5 proxy for `.onion` peers. |
| `--i2psam=HOST:PORT` | none | I2P SAM bridge for `.b32.i2p` peers. |
| `--i2p-private-key=PATH` | none | Keep a persistent I2P destination key in this file. |
| `--cjdnsreachable` | off | Dial CJDNS (`fc00::/8`) addresses directly. |

### RPC, REST and notifications

| Flag | Default | Meaning |
|---|---|---|
| `--rpchost=HOST` | `127.0.0.1` | RPC bind address. |
| `--rpcport=PORT` | per network | RPC port. |
| `--rpcuser=USER` | `camlcoin` | RPC user name. |
| `--rpcpassword=PASS` | `camlcoin` | RPC password. Change it; the default is accepted. |
| `--rpc-tls-cert=PATH`, `--rpc-tls-key=PATH` | none | Serve RPC over HTTPS. Both are required. |
| `--rest` | off | Enable the read-only REST interface. Needs `--restport` too. |
| `--restport=PORT` | RPC port | REST port. It must differ from the RPC port: if they are equal, no REST endpoints are served (a warning is logged). |
| `--restbind=HOST` | `--rpchost` | REST bind address. |
| `--rest-tls-cert=PATH`, `--rest-tls-key=PATH` | none | Serve REST over HTTPS. |
| `--zmqpub=OPT` | none | ZeroMQ publisher, e.g. `--zmqpub=hashblock=tcp://127.0.0.1:28332`. Topics: `hashblock`, `hashtx`, `rawblock`, `rawtx`, `sequence`. Repeatable. |
| `--metricsport=PORT` | `9332` | Prometheus metrics port; `0` disables it. |

### Logging

| Flag | Default | Meaning |
|---|---|---|
| `--debug` | off | Debug-level logging for everything. |
| `--debug-cat=CAT` | none | Log only these categories (comma-separated, repeatable): `NET`, `PEER`, `RPC`, `REST`, `MEMPOOL`, `VALIDATION`, `MINING`, `WALLET`, `PKG-RELAY`, `PayJoin`; `all`/`none` also work. Everything else, including the startup messages, is then not logged. |
| `--logfile=PATH` | none | Write logs to this file instead of stderr (appends). `SIGHUP` reopens it for log rotation. |
| `--printtoconsole=BOOL` | | With `--logfile`, also keep logging to stderr. |

Logs go to stderr by default. `SIGTERM` and `SIGINT` shut the node down cleanly, like
the `stop` RPC.

## Config file

camlcoin reads `<datadir>/camlcoin.conf` (or `--conf=FILE`) if it exists. The grammar is
Bitcoin Core's: `key=value` lines, `#` comments, and `[main]`, `[test]` and `[regtest]`
sections. Keys before the first section, and keys under `[main]`, apply to every network;
`[test]` and `[regtest]` keys apply only to that network. Command-line flags win over the
file.

Keys read from the file: `rpchost`, `rpcport`, `rpcuser`, `rpcpassword`, `port`,
`connect` (repeatable), `dnsseed`, `assumevalid` (`0` disables it), `maxoutbound`,
`maxinbound`, `prune`, `dbcache`, `par`, `peerbloomfilters`, `externalip`, `discover`,
`asmap`, `proxy`, `onion`, `i2psam`, `i2pprivatekey`, `cjdnsreachable`, `rest`,
`restport`, `restbind`, `rpctlscert`, `rpctlskey`, `resttlscert`, `resttlskey`,
`blockfilterindex`, `coinstatsindex`, `txospenderindex`, `zmqpub`, `reindex`,
`metricsport`, `debug` (a category list), `logfile`, `printtoconsole`, `pid`, `daemon`.

`config.example.toml` in the repository root is not in this format and is not read.

Example (`regtest` on non-default ports):

```bash
export DATADIR=$(mktemp -d)
cat > "$DATADIR/camlcoin.conf" <<'EOF'
[regtest]
rpcport=28443
port=28444
EOF
camlcoin --network=regtest --datadir="$DATADIR" --metricsport=0 > "$DATADIR/node.log" 2>&1 &
sleep 5
curl -s --user "$(cat "$DATADIR/.cookie")" -d '{"method":"getnetworkinfo","params":[]}' http://127.0.0.1:28443/ | head -c 200; echo
curl -s --user "$(cat "$DATADIR/.cookie")" -d '{"method":"stop","params":[]}' http://127.0.0.1:28443/
```

## Data directory

After a regtest run the data directory holds:

```
.cookie              RPC cookie, rewritten at every start
camlcoin.pid         PID file while the node runs
chainstate/          RocksDB: block index, headers, block bodies, undo data, chain state
rocksdb_utxo/        RocksDB: UTXO set
indexes/             optional indexes (blockfilter, coinstats, txospender)
wallets/, wallet.json  wallets
peers.dat            address manager
mempool.dat          mempool saved at shutdown
fee_estimates.dat    fee estimator state
```

## Resources

A full mainnet node needs about 1 TB of fast disk for the block chain, or much less with
`--prune=550` or more. Give it at least 32 GB of RAM; the UTXO cache (`--dbcache`) is
about 1 GiB of that by default, and OCaml's heap adds overhead during initial sync.

## Monitoring

The metrics server listens on all interfaces, port 9332 (`--metricsport`). Any path
returns three Prometheus gauges:
`bitcoin_blocks_total`, `bitcoin_peers_connected` and `bitcoin_mempool_size`. For more,
poll `getblockchaininfo`, `getpeerinfo`, `getmempoolinfo` and `getnetworkinfo` over RPC.
