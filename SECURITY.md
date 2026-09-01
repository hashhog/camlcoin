# Security Policy — camlcoin

camlcoin is a from-scratch Bitcoin full-node implementation in OCaml, part of the
[hashhog](https://github.com/hashhog) fleet of ten independent nodes that
cross-validate each other and Bitcoin Core.

## Project maturity — read this first

camlcoin is a **pre-release validator**: a node you can build and run *beside*
Bitcoin Core with `consensus-diff` as a live divergence alarm. It has NOT
completed an independent `--assumevalid=0` genesis→tip validation, and it
currently runs loopback-pinned to a Core peer in the fleet.

**It is NOT fund-capable.** Do not custody funds on it. There are no fund-grade
guarantees. Run from a pinned commit or tag.

## Supported versions

| Version | Supported |
|---------|-----------|
| `v0.1.0-beta1` | Best-effort; no security SLA until a final `v1.0.0` |
| pre-release (`master`) | Best-effort |

Release-signing key fingerprint: to be published with v1.0.0.

## Reporting a vulnerability

**Please do NOT open a public GitHub issue** for anything in the consensus, P2P, or
wallet paths — a public report could put real Bitcoin nodes or funds at risk.

Report privately to the maintainer:

- **Email:** `max@dockyard.navy`  <!-- TODO(max): confirm or replace with a dedicated security alias -->

Include the affected path, a deterministic reproduction (a diff-test corpus entry,
regtest script, or malformed message), impact, and any suggested fix. We coordinate
a fix + disclosure timeline and credit you if you wish.

## In scope (highest priority)

- **Consensus divergence** — camlcoin accepting a block/tx Core rejects, or vice-versa.
- **Remotely-triggerable crashes / OOM / resource exhaustion** in the P2P or
  block/tx decode paths, including GC-pressure amplification.
- **Wallet funds-safety** — wrong-key signing, a spend the node reports valid that
  the network rejects, un-recoverable backups, fee miscalculation.
- **Chainstate corruption on crash** (WAL-backed recovery; regressions are in scope).

## Out of scope

- IBD/sync performance characteristics.
- Issues requiring an already-compromised host.

## Disclosure

Coordinated disclosure. Consensus fixes are verified with `../tools/verify-fix.sh` and
gated through the differential corpus before they are considered landed.
