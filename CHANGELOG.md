# Changelog

## v1.0.0 (unreleased)

Changes since `v0.1.0-beta1`:

- b50b715 test: update stale pins to Core behaviour; skip W109 architecture gates
- a0768ad test(fix64): run the TLS round-trip server out of process; stop leaking datadirs
- f7d05a8 fix(wallet): reject wrong-length keying material (Core crypter.cpp:65)
- ab2dd04 fix(mempool): allow TRUC sibling replacement (Core truc_policy.cpp:237)
- d020348 fix(rpc): getrawtransaction block context per Core TxToJSON
- 49043c4 fix(mining): getblocktemplate fields per Core rpc/mining.cpp
- d543784 docs: SECURITY.md, toolchain versions (release hygiene)
- 46d6136 fix(rpc): embed Core's arity table in the binary (#103 follow-up)
- b969605 test(w112): fix a coin-flip flaky assertion on the compact-block nonce
- 12cf8a9 fix(rpc): implement the dispatcher arity check every handler already defers to
- 5920c6c fix(test): consensus vector suite could not find its vectors
- c8aed18 test: wire test_txospender_livereorg into dune — it had no stanza at all
- 5cb7596 fix(rpc): the integer conversion runs before the lookup, and disconnectnode accepts Core's by-id call
- 610709e fix(rpc): read integer arguments at Core's width, and honour the ones we read
- 757a9c6 feat(rpc): implement createrawtransaction's `version` argument
- 813ce09 fix(rpc): submitblock decode failure reports Core's token, not the decoder's own text
- 1000779 fix(rpc): createrawtransaction non-numeric sequence is ignored; fractional sequence is -1
- 266426b fix(rpc): createrawtransaction rejects replaceable=true contradicted by its sequences
- 1b4058e fix(rpc): createrawtransaction rejects an out-of-int32 vout instead of wrapping it to 0
- 29eb66f feat(shim): camlcoin per-height MTP — BIP-68 time locks stop spuriously failing
- e3a4226 fix(rpc): getchaintips reports the VALIDATED tip, not the best-work header tip (#43 camlcoin slice)
- e7a9b4d test(consensus): work-vs-length + byte-order chain-selection pins (#47)
- 7d79b6f fix(p2p): dropped sends are loud; stale-tip challenge and compact-block slot no longer strand (#74)
- 4fe156d refactor(sync): delete dead degenerate locator builders (second-implementation traps)
- 388b65f fix(sync): take reorg undo data from validation instead of re-deriving it

