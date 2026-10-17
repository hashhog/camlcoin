# JSON-RPC and REST

camlcoin serves JSON-RPC over HTTP on the RPC port (8332 mainnet, 18332 testnet4,
18443 regtest), bound to `127.0.0.1` by default. It aims to match Bitcoin Core: the same
method names, positional and named parameters, result shapes and error codes. JSON-RPC
1.0 and 2.0 requests and batches are accepted.

## Authentication

HTTP Basic auth, with either

- the cookie: `<datadir>/.cookie` holds `__cookie__:<random>`, rewritten at every start;
- or `--rpcuser`/`--rpcpassword` (config keys `rpcuser`/`rpcpassword`). Both default to
  `camlcoin`, and the default is accepted, so set your own if anyone else can reach the
  port.

```bash
curl -s --user "$(cat "$DATADIR/.cookie")" \
  -d '{"jsonrpc":"1.0","id":1,"method":"getblockcount","params":[]}' http://127.0.0.1:18443/
```

Wallet methods take the wallet from the URL, as in Core:

```bash
curl -s --user "$(cat "$DATADIR/.cookie")" -d '{"method":"createwallet","params":["demo"]}' http://127.0.0.1:18443/
curl -s --user "$(cat "$DATADIR/.cookie")" -d '{"method":"getnewaddress","params":[]}' http://127.0.0.1:18443/wallet/demo
```

`help` lists every method; `help "<method>"` gives its description.

## Methods

The list below is the node's own `help` output (152 methods), grouped the way `help`
groups them. Methods marked † are not in Bitcoin Core.

| Group | Methods |
|---|---|
| Blockchain | `getbestblockhash` `getblock` `getblockchaininfo` `getblockcount` `getsyncstate`† `getblockhash` `getblockheader` `getblockstats` `getblockfilter` `scanblocks` `scantxoutset` `getdeploymentinfo` `getdifficulty` `getchaintips` `getchainstates` `getchaintxstats` `getindexinfo` `verifychain` `verifytxoutproof` `waitfornewblock` `waitforblock` `waitforblockheight` `pruneblockchain` `gettxout` `gettxoutproof` `gettxspendingprevout` `invalidateblock` `reconsiderblock` `preciousblock` |
| Mining | `getblocktemplate` `getmininginfo` `getnetworkhashps` `getprioritisedtransactions` `prioritisetransaction` `submitblock` `submitheader` |
| Regtest mining | `generate` `generatetoaddress` `generateblock` |
| Mempool | `dumpmempool`† `getmempoolancestors` `getmempooldescendants` `getmempoolentry` `getmempoolinfo` `getorphantxs` `getrawmempool` `importmempool` `loadmempool`† `savemempool` `testmempoolaccept` |
| Network | `addnode` `addpeeraddress` `clearbanned` `disconnectnode` `getaddednodeinfo` `getaddrmaninfo` `getblockfrompeer` `getconnectioncount` `getnetworkinfo` `getnettotals` `getnodeaddresses` `getpeerinfo` `listbanned` `ping` `setban` `setnetworkactive` |
| Raw transactions | `createrawtransaction` `combinerawtransaction` `decoderawtransaction` `decodescript` `getrawtransaction` `sendrawtransaction` `signrawtransactionwithkey` `submitpackage` |
| PSBT | `analyzepsbt` `combinepsbt` `converttopsbt` `createpsbt` `decodepsbt` `descriptorprocesspsbt` `finalizepsbt` `joinpsbts` `utxoupdatepsbt` `walletcreatefundedpsbt` `fundrawtransaction` `walletprocesspsbt` |
| Descriptors | `deriveaddresses` `getdescriptorinfo` `listdescriptors` |
| Util | `getmemoryinfo` `createmultisig` `estimatesmartfee` `estimaterawfee` `signmessage` `signmessagewithprivkey` `verifymessage` `validateaddress` |
| Wallet | `getbalance` `getbalances` `getnewaddress` `getwalletinfo` `gettransaction` `getaddressinfo` `importdescriptors` `listwallets` `createwallet` `loadwallet` `unloadwallet` `listtransactions` `listunspent` `lockunspent` `listlockunspent` `sendtoaddress` `send` `backupwallet` `restorewallet` `signrawtransactionwithwallet` `rescanblockchain` `importprivkey`† `sethdseed`† `encryptwallet` `walletpassphrase` `walletlock` |
| Control | `getrpcinfo` `help` `logging` `stop` `uptime` |
| Performance | `getperfstats`† |
| AssumeUTXO | `loadtxoutset` `dumptxoutset` `gettxoutsetinfo` `scrubunspendable`† |
| Payjoin (BIP-78)† | `checkpayjoinreplay` `decodeoriginalpsbt` `expirepayjoinrequest` `getpayjoinerror` `getpayjoinrequest` `getpayjointlsinfo` `getpayjoinversion` `listpayjoinsessions` `payjoinadjustfee` `payjoinaddinput` `payjoinmodifyoutput` `payjoinreceive` `receiveraddinputs` `selectpayjoinutxos` `sendpayjoinrequest` `validatefeeoutputindex` `validateoriginalpsbt` `validatepayjoincontenttype` `verifypayjoinnodouble` |

The non-Core methods: `getsyncstate` (header and block sync progress), `dumpmempool` and
`loadmempool` (dump the mempool; reload `mempool.dat`), `getperfstats` (block-connect
timing counters), `scrubunspendable` (remove provably unspendable outputs from the UTXO
set), `importprivkey` and `sethdseed` (legacy-wallet calls that Core has removed), and the
payjoin group.

## Known differences from Core

- **Missing methods.** Compared with Bitcoin Core's RPC table, camlcoin does not have:
  `abandontransaction`, `abortrescan`, `bumpfee`, `psbtbumpfee`, `sendall`, `sendmany`,
  `getrawchangeaddress`, `getreceivedbyaddress`, `getreceivedbylabel`,
  `listreceivedbyaddress`, `listreceivedbylabel`, `listsinceblock`, `listlabels`,
  `getaddressesbylabel`, `setlabel`, `listaddressgroupings`, `listwalletdir`,
  `keypoolrefill`, `walletpassphrasechange`, `setwalletflag`, `migratewallet`,
  `createwalletdescriptor`, `gethdkeys`, `getdescriptoractivity`, `walletdisplayaddress`,
  `enumeratesigners`, `simulaterawtransaction`, `importprunedfunds`, `removeprunedfunds`,
  `generatetodescriptor`, `getrawaddrman`, `getmempoolcluster`,
  `getmempoolfeeratediagram`, `getprivatebroadcastinfo`, `abortprivatebroadcast`,
  `sendmsgtopeer`, `addconnection`, `echo`, `echojson`, `echoipc`, `setmocktime`,
  `mockscheduler`, `syncwithvalidationinterfacequeue`. Calling one returns `-32601`
  (method not found).
- **`getchainstates`** always reports one chainstate. `loadtxoutset` and `--import-utxo`
  write the snapshot into the node's only chainstate; there is no background chainstate
  that re-validates from genesis up to the snapshot (single-chainstate design).
- **`getrawtransaction`** finds confirmed transactions without `-txindex`: the
  transaction index is always kept and `--txindex` is ignored.
- **`estimatesmartfee` / `estimaterawfee`** use a bucket estimator that lacks parts of
  Core's `TxConfirmStats` (no failure-average matrix, no unconfirmed-transaction circular
  buffer), so estimates can differ from Core's on the same mempool history. The gaps are
  pinned in `test/test_w139_fee_estimation.ml`.

## REST

Start the node with `--rest` and a `--restport` different from the RPC port. Unlike Core,
camlcoin does not serve REST on the RPC port: with `--rest` alone it logs a warning and
serves no REST endpoints. REST needs no authentication and binds to `--rpchost` unless
`--restbind` is given. Endpoints (`.json`, `.hex` or `.bin`):

| Endpoint | Returns |
|---|---|
| `/rest/block/<hash>.<fmt>` | block with transaction details |
| `/rest/block/notxdetails/<hash>.<fmt>` | block with txids only |
| `/rest/headers/<hash>.<fmt>?count=<n>` | up to `n` headers from `hash` |
| `/rest/tx/<txid>.<fmt>` | transaction |
| `/rest/chaininfo.json` | same as `getblockchaininfo` |
| `/rest/mempool/info.json`, `/rest/mempool/contents.json` | mempool summary and contents |
| `/rest/blockhashbyheight/<height>.<fmt>` | block hash at a height |
| `/rest/blockfilter/basic/<hash>.<fmt>` | BIP-158 filter (needs `--blockfilterindex=1`) |
| `/rest/blockfilterheaders/basic/<hash>.<fmt>?count=<n>` | filter headers (needs `--blockfilterindex=1`) |

Core's `/rest/getutxos` is not implemented.

```bash
camlcoin --network=regtest --datadir="$DATADIR" --rest --restport=18445 --metricsport=0 > "$DATADIR/node.log" 2>&1 &
sleep 5
curl -s http://127.0.0.1:18445/rest/chaininfo.json | head -c 120; echo
curl -s http://127.0.0.1:18445/rest/blockhashbyheight/0.hex; echo
```

## ZeroMQ

`--zmqpub=<topic>=<address>` publishes `hashblock`, `hashtx`, `rawblock`, `rawtx` or
`sequence` notifications in Core's format, e.g.
`--zmqpub=hashblock=tcp://127.0.0.1:28332`. The option is repeatable.
