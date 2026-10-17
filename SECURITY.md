# Security policy

camlcoin is an experimental, from-scratch Bitcoin full node in OCaml, one of the ten
[hashhog](https://github.com/hashhog) nodes. It is for research and testing. Do not use
it with real funds: the wallet has not been audited and there are no fund-safety
guarantees.

## Supported versions

| Version | Supported |
|---|---|
| latest tag | best effort |
| `master` | best effort |

There is no security SLA and no release-signing key yet.

## Reporting a vulnerability

Do not open a public GitHub issue for problems in consensus, P2P or wallet code: a public
report could put other nodes or users at risk.

Report privately by email to `max@dockyard.navy`.

Include the affected code, a reproduction (a regtest script, a malformed message, or a
block or transaction), the impact, and a suggested fix if you have one. We will agree a
fix and disclosure timeline with you and credit you if you wish.

## In scope

- Consensus divergence: camlcoin accepting a block or transaction that Bitcoin Core
  rejects, or rejecting one that Core accepts.
- Remotely triggerable crashes, hangs, or memory or CPU exhaustion in P2P message
  handling or block and transaction decoding.
- Wallet safety: signing with the wrong key, spends the network rejects, backups that
  cannot be restored, wrong fees.
- Chainstate corruption after a crash or an unclean shutdown.

## Out of scope

- Sync speed.
- Problems that need an already compromised host.
- The default RPC credentials (`camlcoin`/`camlcoin`): they are documented, and RPC
  binds to `127.0.0.1` by default. Set your own if the port is reachable by others.

## Fixing

Consensus fixes come with a test that fails before the fix and passes after it, and with
evidence that the new behaviour matches Bitcoin Core (see
[CONTRIBUTING.md](CONTRIBUTING.md#consensus-changes)).
