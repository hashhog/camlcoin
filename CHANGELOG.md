# Changelog

## v1.0.1 (unreleased)

Changes since `v1.0.0`:

- fix: stall class (231 CRITICALs) — do not rotate peers during a header-ahead catch-up, ignore VERSION-height liars, keep the header tip on gap-fill connect, re-enter catch-up IBD after FullySynced. Control: `dune exec --no-buffer test/test_stall_class_231.exe`. Diagnosis: `docs/STALL-CLASS-231-CRITICALS.md`
- fix: skip the UTXO LRU during snapshot import so RPC can bind at soak-315000
- fix: block download follows the snapshot base when headers race ahead (gap-fill GetAncestor, skip PRESYNC after assumeUTXO)
- fix: loadtxoutset activates the snapshot tip and persists it (boot-smoke tip/restart)
- fix: HASH_SERIALIZED emits coins in numeric vout order, not LE32 key order
- fix: gettxoutsetinfo hashes the committed UTXO set without flushing (STALE-UTXO-READ)
- 5be08ee docs: say the cited paths are private before the claims that rest on them
- fc8935d revert: stop the UTXO-reporting RPCs writing to disk
- e66171f fix: scantxoutset's force-flush left the same unmarked UTXO set
- 49aa827 fix: the RPC force-flush left the UTXO set ahead of the durability marker
- 3ea57e5 fix: resolve the validated tip from the active chain, not the coins-DB marker
- 57ae4b0 fix: dump the validated tip, and mirror flushed UTXOs into the iterated backend
- d09b2a7 fix: resolve an already-known header by hash, not by height
- 194328b feat: HASHHOG_UNSAFE_SNAPSHOT_HEIGHT — accept an un-anchored UTXO snapshot

