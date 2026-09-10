# Changelog

## v1.0.1 (unreleased)

Changes since `v1.0.0`:

- fix: gettxoutsetinfo hashes the committed UTXO set without flushing (STALE-UTXO-READ)
- 5be08ee docs: say the cited paths are private before the claims that rest on them
- fc8935d revert: stop the UTXO-reporting RPCs writing to disk
- e66171f fix: scantxoutset's force-flush left the same unmarked UTXO set
- 49aa827 fix: the RPC force-flush left the UTXO set ahead of the durability marker
- 3ea57e5 fix: resolve the validated tip from the active chain, not the coins-DB marker
- 57ae4b0 fix: dump the validated tip, and mirror flushed UTXOs into the iterated backend
- d09b2a7 fix: resolve an already-known header by hash, not by height
- 194328b feat: HASHHOG_UNSAFE_SNAPSHOT_HEIGHT — accept an un-anchored UTXO snapshot

