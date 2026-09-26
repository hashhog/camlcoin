(* Per-command description text served by [help "<command>"].

   GENERATED -- do not hand-edit Core rows. For every method camlcoin dispatches
   that Bitcoin Core also implements, the text is the FIRST description
   paragraph of Core's own `help <command>` (bitcoin-core build-wallet,
   /Satoshi:31.99.0/, regtest, 2026-09-26). Rows marked "camlcoin extension"
   (and the two removed legacy-wallet RPCs) are camlcoin-authored.

   The signature line itself is NOT here: it lives in Rpc.help_sections, the
   same table the bare `help` listing is printed from, so the listing and
   `help <command>` cannot disagree. *)

let descriptions : (string * string) list = [
  ("addnode", {|Attempts to add or remove a node from the addnode list.
Or try a connection to a node once.
Nodes added using addnode (or -connect) are protected from DoS disconnection and are not required to be
full nodes/support SegWit as other outbound peers are (though such peers will not be synced from).
Addnode connections are limited to 8 at a time and are counted separately from the -maxconnections limit.|});
  ("addpeeraddress", {|Add the address of a potential peer to an address manager table. This RPC is for testing only.|});
  ("analyzepsbt", {|Analyzes and provides information about the current status of a PSBT and its inputs|});
  ("backupwallet", {|Safely copies the current wallet file to the specified destination, which can either be a directory or a path with a filename.|});
  ("checkpayjoinreplay", {|camlcoin extension (BIP-78). Detect a replayed Original PSBT.|});
  ("clearbanned", {|Clear all banned IPs.|});
  ("combinepsbt", {|Combine multiple partially signed Bitcoin transactions into one transaction.
Implements the Combiner role.|});
  ("combinerawtransaction", {|Combine multiple partially signed transactions into one transaction.
The combined transaction may be another partially signed transaction or a 
fully signed transaction.|});
  ("converttopsbt", {|Converts a network serialized transaction to a PSBT. This should be used only with createrawtransaction and fundrawtransaction
createpsbt and walletcreatefundedpsbt should be used for new applications.|});
  ("createmultisig", {|Creates a multi-signature address with n signatures of m keys required.
It returns a json object with the address and redeemScript.|});
  ("createpsbt", {|Creates a transaction in the Partially Signed Transaction format.
Implements the Creator role.
Note that the transaction's inputs are not signed, and
it is not stored in the wallet or transmitted to the network.|});
  ("createrawtransaction", {|Create a transaction spending the given inputs and creating new outputs.
Outputs can be addresses or data.
Returns hex-encoded raw transaction.
Note that the transaction's inputs are not signed, and
it is not stored in the wallet or transmitted to the network.|});
  ("createwallet", {|Creates and loads a new wallet.|});
  ("decodeoriginalpsbt", {|camlcoin extension (BIP-78). Decode a base64 Original PSBT as received by a PayJoin receiver.|});
  ("decodepsbt", {|Return a JSON object representing the serialized, base64-encoded partially signed Bitcoin transaction.|});
  ("decoderawtransaction", {|Return a JSON object representing the serialized, hex-encoded transaction.|});
  ("decodescript", {|Decode a hex-encoded script.|});
  ("deriveaddresses", {|Derives one or more addresses corresponding to an output descriptor.
Examples of output descriptors are:
    pkh(<pubkey>)                                     P2PKH outputs for the given pubkey
    wpkh(<pubkey>)                                    Native segwit P2PKH outputs for the given pubkey
    sh(multi(<n>,<pubkey>,<pubkey>,...))              P2SH-multisig outputs for the given threshold and pubkeys
    raw(<hex script>)                                 Outputs whose output script equals the specified hex-encoded bytes
    tr(<pubkey>,multi_a(<n>,<pubkey>,<pubkey>,...))   P2TR-multisig outputs for the given threshold and pubkeys|});
  ("descriptorprocesspsbt", {|Update all segwit inputs in a PSBT with information from output descriptors, the UTXO set or the mempool. 
Then, sign the inputs we are able to with information from the output descriptors.|});
  ("disconnectnode", {|Immediately disconnects from the specified peer node.|});
  ("dumpmempool", {|camlcoin extension. Dump the in-memory mempool contents.|});
  ("dumptxoutset", {|Write the serialized UTXO set to a file. This can be used in loadtxoutset afterwards if this snapshot height is supported in the chainparams as well.|});
  ("encryptwallet", {|Encrypts the wallet with 'passphrase'. This is for first time encryption.
After this, any calls that interact with private keys such as sending or signing 
will require the passphrase to be set prior to making these calls.
Use the walletpassphrase call for this, and then walletlock call.
If the wallet is already encrypted, use the walletpassphrasechange call.
** IMPORTANT **
For security reasons, the encryption process will generate a new HD seed, resulting
in the creation of a fresh set of active descriptors. Therefore, it is crucial to
securely back up the newly generated wallet file using the backupwallet RPC.|});
  ("estimaterawfee", {|WARNING: This interface is unstable and may disappear or change!|});
  ("estimatesmartfee", {|Estimates the approximate fee per kilobyte needed for a transaction to begin
confirmation within conf_target blocks if possible and return the number of blocks
for which the estimate is valid. Uses virtual transaction size as defined
in BIP 141 (witness data is discounted).|});
  ("expirepayjoinrequest", {|camlcoin extension (BIP-78). Expire a PayJoin receiver session.|});
  ("finalizepsbt", {|Finalize the inputs of a PSBT. If the transaction is fully signed, it will produce a
network serialized transaction which can be broadcast with sendrawtransaction. Otherwise a PSBT will be
created which has the final_scriptSig and final_scriptwitness fields filled for inputs that are complete.
Implements the Finalizer and Extractor roles.|});
  ("fundrawtransaction", {|If the transaction has no inputs, they will be automatically selected to meet its out value.
It will add at most one change output to the outputs.
No existing outputs will be modified unless "subtractFeeFromOutputs" is specified.
Note that inputs which were signed may need to be resigned after completion since in/outputs have been added.
The inputs added will not be signed, use signrawtransactionwithkey
or signrawtransactionwithwallet for that.
All existing inputs must either have their previous output transaction be in the wallet
or be in the UTXO set. Solving data must be provided for non-wallet inputs.
Note that all inputs selected must be of standard form and P2SH scripts must be
in the wallet using importdescriptors (to calculate fees).
You can see whether this is the case by checking the "solvable" field in the listunspent output.
Note that if specifying an exact fee rate, the resulting transaction may have a higher fee rate
if the transaction has unconfirmed inputs. This is because the wallet will attempt to make the
entire package have the given fee rate, not the resulting transaction.|});
  ("generate", {|has been replaced by the -generate cli option. Refer to -help for more information.|});
  ("generateblock", {|Mine a set of ordered transactions to a specified address or descriptor and return the block hash.
Transaction fees are not collected in the block reward.|});
  ("generatetoaddress", {|Mine to a specified address and return the block hashes.|});
  ("getaddednodeinfo", {|Returns information about the given added node, or all added nodes
(note that onetry addnodes are not listed here)|});
  ("getaddressinfo", {|Return information about the given bitcoin address.
Some of the information will only be present if the address is in the active wallet.|});
  ("getaddrmaninfo", {|Provides information about the node's address manager by returning the number of addresses in the `new` and `tried` tables and their sum for all networks.|});
  ("getbalance", {|Returns the total available balance.
The available balance is what the wallet considers currently spendable, and is
thus affected by options which limit spendability such as -spendzeroconfchange.|});
  ("getbalances", {|Returns an object with all balances in BTC.|});
  ("getbestblockhash", {|Returns the hash of the best (tip) block in the most-work fully-validated chain.|});
  ("getblock", {|If verbosity is 0, returns a string that is serialized, hex-encoded data for block 'hash'.
If verbosity is 1, returns an Object with information about block <hash>.
If verbosity is 2, returns an Object with information about block <hash> and information about each transaction.
If verbosity is 3, returns an Object with information about block <hash> and information about each transaction, including prevout information for inputs (only for unpruned blocks in the current best chain).|});
  ("getblockchaininfo", {|Returns an object containing various state info regarding blockchain processing.|});
  ("getblockcount", {|Returns the height of the most-work fully-validated chain.
The genesis block has height 0.|});
  ("getblockfilter", {|Retrieve a BIP 157 content filter for a particular block.|});
  ("getblockfrompeer", {|Attempt to fetch block from a given peer.|});
  ("getblockhash", {|Returns hash of block in best-block-chain at height provided.|});
  ("getblockheader", {|If verbose is false, returns a string that is serialized, hex-encoded data for blockheader 'hash'.
If verbose is true, returns an Object with information about blockheader <hash>.|});
  ("getblockstats", {|Compute per block statistics for a given window. All amounts are in satoshis.
It won't work for some heights with pruning.|});
  ("getblocktemplate", {|If the request parameters include a 'mode' key, that is used to explicitly select between the default 'template' request or a 'proposal'.
It returns data needed to construct a block to work on.
For full specification, see BIPs 22, 23, 9, and 145:
    https://github.com/bitcoin/bips/blob/master/bip-0022.mediawiki
    https://github.com/bitcoin/bips/blob/master/bip-0023.mediawiki
    https://github.com/bitcoin/bips/blob/master/bip-0009.mediawiki#getblocktemplate_changes
    https://github.com/bitcoin/bips/blob/master/bip-0145.mediawiki|});
  ("getchainstates", {|Return information about chainstates.|});
  ("getchaintips", {|Return information about all known tips in the block tree, including the main chain as well as orphaned branches.|});
  ("getchaintxstats", {|Compute statistics about the total number and rate of transactions in the chain.|});
  ("getconnectioncount", {|Returns the number of connections to other nodes.|});
  ("getdeploymentinfo", {|Returns an object containing various state info regarding deployments of consensus changes.
Consensus changes for which the new rules are enforced from genesis are not listed in "deployments".|});
  ("getdescriptorinfo", {|Analyses a descriptor.|});
  ("getdifficulty", {|Returns the proof-of-work difficulty as a multiple of the minimum difficulty.|});
  ("getindexinfo", {|Returns the status of one or all available indices currently running in the node.|});
  ("getmemoryinfo", {|Returns an object containing information about memory usage.|});
  ("getmempoolancestors", {|If txid is in the mempool, returns all in-mempool ancestors.|});
  ("getmempooldescendants", {|If txid is in the mempool, returns all in-mempool descendants.|});
  ("getmempoolentry", {|Returns mempool data for given transaction|});
  ("getmempoolinfo", {|Returns details on the active state of the TX memory pool.|});
  ("getmininginfo", {|Returns a json object containing mining-related information.|});
  ("getnettotals", {|Returns information about network traffic, including bytes in, bytes out,
and current system time.|});
  ("getnetworkhashps", {|Returns the estimated network hashes per second based on the last n blocks.
Pass in [blocks] to override # of blocks, -1 specifies since last difficulty change.
Pass in [height] to estimate the network speed at the time when a certain block was found.|});
  ("getnetworkinfo", {|Returns an object containing various state info regarding P2P networking.|});
  ("getnewaddress", {|Returns a new Bitcoin address for receiving payments.
If 'label' is specified, it is added to the address book 
so payments received with the address will be associated with 'label'.|});
  ("getnodeaddresses", {|Return known addresses, after filtering for quality and recency.
These can potentially be used to find new peers in the network.
The total number of addresses known to the node may be higher.|});
  ("getorphantxs", {|Shows transactions in the tx orphanage.|});
  ("getpayjoinerror", {|camlcoin extension (BIP-78). Returns the well-known PayJoin error codes.|});
  ("getpayjoinrequest", {|camlcoin extension (BIP-78 sender). Build a BIP-21 payment request carrying a pj= endpoint.|});
  ("getpayjointlsinfo", {|camlcoin extension (BIP-78). Returns the PayJoin TLS endpoint configuration.|});
  ("getpayjoinversion", {|camlcoin extension (BIP-78). Returns the supported PayJoin protocol version(s).|});
  ("getpeerinfo", {|Returns data about each connected network peer as a json array of objects.|});
  ("getperfstats", {|camlcoin extension. Returns internal block-connect performance counters.|});
  ("getprioritisedtransactions", {|Returns a map of all user-created (see prioritisetransaction) fee deltas by txid, and whether the tx is present in mempool.|});
  ("getrawmempool", {|Returns all transaction ids in memory pool as a json array of string transaction ids.|});
  ("getrawtransaction", {|By default, this call only returns a transaction if it is in the mempool. If -txindex is enabled
and no blockhash argument is passed, it will return the transaction if it is in the mempool or any block.
If a blockhash argument is passed, it will return the transaction if
the specified block is available and the transaction is in that block.|});
  ("getrpcinfo", {|Returns details of the RPC server.|});
  ("getsyncstate", {|camlcoin extension. Returns header/block synchronisation progress.|});
  ("gettransaction", {|Get detailed information about in-wallet transaction <txid>|});
  ("gettxout", {|Returns details about an unspent transaction output.|});
  ("gettxoutproof", {|Returns a hex-encoded proof that "txid" was included in a block.|});
  ("gettxoutsetinfo", {|Returns statistics about the unspent transaction output set.
Note this call may take some time if you are not using coinstatsindex.|});
  ("gettxspendingprevout", {|Scans the mempool (and the txospenderindex, if available) to find transactions spending any of the given outputs|});
  ("getwalletinfo", {|Returns an object containing various wallet state info.|});
  ("help", {|List all commands, or get help for a specified command.|});
  ("importdescriptors", {|Import descriptors. This will trigger a rescan of the blockchain based on the earliest timestamp of all descriptors being imported. Requires a new wallet backup.
When importing descriptors with multipath key expressions, if the multipath specifier contains exactly two elements, the descriptor produced from the second element will be imported as an internal descriptor.|});
  ("importmempool", {|Import a mempool.dat file and attempt to add its contents to the mempool.
Warning: Importing untrusted files is dangerous, especially if metadata from the file is taken over.|});
  ("importprivkey", {|Adds a private key (as returned by dumpprivkey) to your wallet. (Legacy-wallet RPC; removed from Bitcoin Core.)|});
  ("invalidateblock", {|Permanently marks a block as invalid, as if it violated a consensus rule.|});
  ("joinpsbts", {|Joins multiple distinct PSBTs with different inputs and outputs into one PSBT with inputs and outputs from all of the PSBTs
No input in any of the PSBTs can be in more than one of the PSBTs.|});
  ("listbanned", {|List all manually banned IPs/Subnets.|});
  ("listdescriptors", {|List all descriptors present in a wallet.|});
  ("listlockunspent", {|Returns list of temporarily unspendable outputs.
See the lockunspent call to lock and unlock transactions for spending.|});
  ("listpayjoinsessions", {|camlcoin extension (BIP-78). List active PayJoin receiver sessions.|});
  ("listtransactions", {|If a label name is provided, this will return only incoming transactions paying to addresses with the specified label.
Returns up to 'count' most recent transactions ordered from oldest to newest while skipping the first number of 
transactions specified in the 'skip' argument. A transaction can have multiple entries in this RPC response. 
For instance, a wallet transaction that pays three addresses — one wallet-owned and two external — will produce 
four entries. The payment to the wallet-owned address appears both as a send entry and as a receive entry. 
As a result, the RPC response will contain one entry in the receive category and three entries in the send category.|});
  ("listunspent", {|Returns array of unspent transaction outputs
with between minconf and maxconf (inclusive) confirmations.
Optionally filter to only include txouts paid to specified addresses.|});
  ("listwallets", {|Returns a list of currently loaded wallets.
For full information on the wallet, use "getwalletinfo"|});
  ("loadmempool", {|camlcoin extension. Load the mempool from mempool.dat in the data directory.|});
  ("loadtxoutset", {|Load the serialized UTXO set from a file.
Once this snapshot is loaded, its contents will be deserialized into a second chainstate data structure, which is then used to sync to the network's tip. Meanwhile, the original chainstate will complete the initial block download process in the background, eventually validating up to the block that the snapshot is based upon.|});
  ("loadwallet", {|Loads a wallet from a wallet file or directory.
Note that all wallet command-line options used when starting bitcoind will be
applied to the new wallet.|});
  ("lockunspent", {|Updates list of temporarily unspendable outputs.
Temporarily lock (unlock=false) or unlock (unlock=true) specified transaction outputs.
If no transaction outputs are specified when unlocking then all current locked transaction outputs are unlocked.
A locked transaction output will not be chosen by automatic coin selection, when spending bitcoins.
Manually selected coins are automatically unlocked.
Locks are stored in memory only, unless persistent=true, in which case they will be written to the
wallet database and loaded on node start. Unwritten (persistent=false) locks are always cleared
(by virtue of process exit) when a node stops or fails. Unlocking will clear both persistent and not.
Also see the listunspent call|});
  ("logging", {|Gets and sets the logging configuration.
When called without an argument, returns the list of categories with status that are currently being debug logged or not.
When called with arguments, adds or removes categories from debug logging and return the lists above.
The arguments are evaluated in order "include", "exclude".
If an item is both included and excluded, it will thus end up being excluded.
The valid logging categories are: addrman, bench, blockstorage, cmpctblock, coindb, estimatefee, http, i2p, ipc, kernel, leveldb, libevent, mempool, mempoolrej, net, privatebroadcast, proxy, prune, qt, rand, reindex, rpc, scan, selectcoins, tor, txpackages, txreconciliation, validation, walletdb, zmq
In addition, the following are available as category names with special meanings:
  - "all",  "1" : represent all logging categories.|});
  ("payjoinaddinput", {|camlcoin extension (BIP-78). Receiver input contribution to a PayJoin proposal.|});
  ("payjoinadjustfee", {|camlcoin extension (BIP-78). Take extra fee from the sender's fee output, bounded by maxadditionalfeecontribution.|});
  ("payjoinmodifyoutput", {|camlcoin extension (BIP-78). Change the value of one output of a PayJoin proposal PSBT.|});
  ("payjoinreceive", {|camlcoin extension (BIP-78 receiver). Process a sender's Original PSBT and return the PayJoin proposal PSBT.|});
  ("ping", {|Requests that a ping be sent to all other nodes, to measure ping time.
Results are provided in getpeerinfo.
Ping command is handled in queue with all other commands, so it measures processing backlog, not just network ping.|});
  ("preciousblock", {|Treats a block as if it were received before others with the same work.|});
  ("prioritisetransaction", {|Accepts the transaction into mined blocks at a higher (or lower) priority|});
  ("pruneblockchain", {|Attempts to delete block and undo data up to a specified height or timestamp, if eligible for pruning.
Requires `-prune` to be enabled at startup. While pruned data may be re-fetched in some cases (e.g., via `getblockfrompeer`), local deletion is irreversible.|});
  ("receiveraddinputs", {|camlcoin extension (BIP-78). Alias of payjoinaddinput.|});
  ("reconsiderblock", {|Removes invalidity status of a block, its ancestors and its descendants, reconsider them for activation.
This can be used to undo the effects of invalidateblock.|});
  ("rescanblockchain", {|Rescan the local blockchain for wallet related transactions.
Note: Use "getwalletinfo" to query the scanning progress.
The rescan is significantly faster if block filters are available
(using startup option "-blockfilterindex=1").|});
  ("restorewallet", {|Restores and loads a wallet from backup.|});
  ("savemempool", {|Dumps the mempool to disk. It will fail until the previous dump is fully loaded.|});
  ("scanblocks", {|Return relevant blockhashes for given descriptors (requires blockfilterindex).
This call may take several minutes. Make sure to use no RPC timeout (bitcoin-cli -rpcclienttimeout=0)|});
  ("scantxoutset", {|Scans the unspent transaction output set for entries that match certain output descriptors.
Examples of output descriptors are:
    addr(<address>)                      Outputs whose output script corresponds to the specified address (does not include P2PK)
    raw(<hex script>)                    Outputs whose output script equals the specified hex-encoded bytes
    combo(<pubkey>)                      P2PK, P2PKH, P2WPKH, and P2SH-P2WPKH outputs for the given pubkey
    pkh(<pubkey>)                        P2PKH outputs for the given pubkey
    sh(multi(<n>,<pubkey>,<pubkey>,...)) P2SH-multisig outputs for the given threshold and pubkeys
    tr(<pubkey>)                         P2TR
    tr(<pubkey>,{pk(<pubkey>)})          P2TR with single fallback pubkey in tapscript
    rawtr(<pubkey>)                      P2TR with the specified key as output key rather than inner
    wsh(and_v(v:pk(<pubkey>),after(2)))  P2WSH miniscript with mandatory pubkey and a timelock|});
  ("scrubunspendable", {|camlcoin extension. Operator one-shot: remove provably unspendable outputs (OP_RETURN / oversize scripts) from the UTXO set.|});
  ("selectpayjoinutxos", {|camlcoin extension (BIP-78). Choose wallet UTXOs to contribute to a PayJoin proposal.|});
  ("send", {|EXPERIMENTAL warning: this call may be changed in future releases.|});
  ("sendpayjoinrequest", {|camlcoin extension (BIP-78 sender). Send an Original PSBT to the pj= endpoint of a BIP-21 URI and validate the proposal.|});
  ("sendrawtransaction", {|Submit a raw transaction (serialized, hex-encoded) to the network.|});
  ("sendtoaddress", {|Send an amount to a given address.
Requires wallet passphrase to be set with walletpassphrase call if wallet is encrypted.|});
  ("setban", {|Attempts to add or remove an IP/Subnet from the banned list.|});
  ("sethdseed", {|Set or generate a new HD wallet seed. (Legacy-wallet RPC; removed from Bitcoin Core.) The seed may be hex (16..64 bytes) or a BIP-39 mnemonic.|});
  ("setnetworkactive", {|Disable/enable all p2p network activity.|});
  ("signmessage", {|Sign a message with the private key of an address
Requires wallet passphrase to be set with walletpassphrase call if wallet is encrypted.|});
  ("signmessagewithprivkey", {|Sign a message with the private key of an address|});
  ("signrawtransactionwithkey", {|Sign inputs for raw transaction (serialized, hex-encoded).
The second argument is an array of base58-encoded private
keys that will be the only keys used to sign the transaction.
The third optional argument (may be null) is an array of previous transaction outputs that
this transaction depends on but may not yet be in the block chain.|});
  ("signrawtransactionwithwallet", {|Sign inputs for raw transaction (serialized, hex-encoded).
The second optional argument (may be null) is an array of previous transaction outputs that
this transaction depends on but may not yet be in the block chain.
Requires wallet passphrase to be set with walletpassphrase call if wallet is encrypted.|});
  ("stop", {|Request a graceful shutdown of Bitcoin Core.|});
  ("submitblock", {|Attempts to submit new block to network.
See https://en.bitcoin.it/wiki/BIP_0022 for full specification.|});
  ("submitheader", {|Decode the given hexdata as a header and submit it as a candidate chain tip if valid.
Throws when the header is invalid.|});
  ("submitpackage", {|Submit a package of raw transactions (serialized, hex-encoded) to local node.
The package will be validated according to consensus and mempool policy rules. If any transaction passes, it will be accepted to mempool.
This RPC is experimental and the interface may be unstable. Refer to doc/policy/packages.md for documentation on package policies.
Warning: successful submission does not mean the transactions will propagate throughout the network.|});
  ("testmempoolaccept", {|Returns result of mempool acceptance tests indicating if raw transaction(s) (serialized, hex-encoded) would be accepted by mempool.|});
  ("unloadwallet", {|Unloads the wallet referenced by the request endpoint or the wallet_name argument.
If both are specified, they must be identical.|});
  ("uptime", {|Returns the total uptime of the server.|});
  ("utxoupdatepsbt", {|Updates all segwit inputs and outputs in a PSBT with data from output descriptors, the UTXO set, txindex, or the mempool.|});
  ("validateaddress", {|Return information about the given bitcoin address.|});
  ("validatefeeoutputindex", {|camlcoin extension (BIP-78). Validate the sender's additionalfeeoutputindex against a PSBT.|});
  ("validateoriginalpsbt", {|camlcoin extension (BIP-78). Run the receiver-side checks on an Original PSBT.|});
  ("validatepayjoincontenttype", {|camlcoin extension (BIP-78). Check that a Content-Type header value is acceptable for a PayJoin request.|});
  ("verifychain", {|Verifies blockchain database.|});
  ("verifymessage", {|Verify a signed message.|});
  ("verifypayjoinnodouble", {|camlcoin extension (BIP-78). Check that candidate outpoints were not already offered in another PayJoin session.|});
  ("verifytxoutproof", {|Verifies that a proof points to a transaction in a block, returning the transaction it commits to
and throwing an RPC error if the block is not in our best chain|});
  ("waitforblock", {|Waits for a specific new block and returns useful info about it.|});
  ("waitforblockheight", {|Waits for (at least) block height and returns the height and hash
of the current tip.|});
  ("waitfornewblock", {|Waits for any new block and returns useful info about it.|});
  ("walletcreatefundedpsbt", {|Creates and funds a transaction in the Partially Signed Transaction format.
Implements the Creator and Updater roles.
All existing inputs must either have their previous output transaction be in the wallet
or be in the UTXO set. Solving data must be provided for non-wallet inputs.|});
  ("walletlock", {|Removes the wallet encryption key from memory, locking the wallet.
After calling this method, you will need to call walletpassphrase again
before being able to call any methods which require the wallet to be unlocked.|});
  ("walletpassphrase", {|Stores the wallet decryption key in memory for 'timeout' seconds.
This is needed prior to performing transactions related to private keys such as sending bitcoins|});
  ("walletprocesspsbt", {|Update a PSBT with input information from our wallet and then sign inputs
that we can sign for.
Requires wallet passphrase to be set with walletpassphrase call if wallet is encrypted.|});
]

let find (cmd : string) : string option = List.assoc_opt cmd descriptions
