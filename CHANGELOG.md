# Changelog

## v1.0.2 — 2026-09-17

- fix: getblockchaininfo reports pruned:true + pruneheight when historical block bodies are missing (snapshot-boot prefix hole); getblockhash of an in-range unretained height is -1 "Block not available (pruned data)", not -8. Control: `dune exec --no-buffer test/test_pruned_history.exe`. Does not backfill genesis→floor; do not bounce the mainnet pin this run.
- fix: after a restart that already restored a header chain, skip the blocking header-sync loop (it skip-waits a 2000-known getheaders reply and never enables message loops). A known batch after we sent getheaders is the reply, not a leftover. Control: `dune exec --no-buffer test/test_stale_locator.exe`. Live 2026-09-17 restart wedge at 967394 — do not bounce the mainnet pin this run.
- fix: bind RPC before reloading mempool.dat; parse the dump from one Cstruct instead of copying the unread tail per tx. Control: `dune exec --no-buffer test/test_mempool_boot_load.exe`. Live 16–20 min boot stall was the quadratic Cstruct copy plus a synchronous load ahead of the RPC listener; do not bounce the mainnet pin to apply this.
- fix: getheaders locator is GetLocator(pindexBestHeader), not the height-index row at the block tip. 2000-known replies rerequest from the tip instead of rotating. VERSION start_height is replaced by the observed headers height. Control: `dune exec --no-buffer test/test_stale_locator.exe`. Live wedge at 967188 — do not bounce the 7921e5a pin to apply this; promote, then `bash tools/stop_mainnet.sh camlcoin` only when a human asks. After that restart the tip must leave 967188 within 10 min.
- docs: caveat the AssumeUTXO dual-chainstate claim; getchainstates is one chainstate
- 4ccdd13 test: hermetic @runtest for the v1.0.2 unit gate
- df7708f fix: stall class — no VERSION-liar rotation during header-ahead catch-up
- d3ec57c docs: CHANGELOG for write-only snapshot import
- f70954a fix: skip the UTXO LRU during snapshot import so RPC can bind
- 3dabf43 fix: request block_tip+1 when headers race past the snapshot base
- 76d7a58 fix: loadtxoutset activates the snapshot tip and persists it
- 472a487 fix: seed snapshot-base headers so header-sync starts at the assumeUTXO base
- 79f9bc9 fix: HASH_SERIALIZED emits coins in numeric vout order
- c48ff9b fix: gettxoutsetinfo hashes the committed UTXO set without flushing


## v1.0.2 — 2026-09-17

Changes since `v1.0.0`:

- fix: bind RPC before reloading mempool.dat; parse the dump from one Cstruct (no per-tx remaining-tail copy). Control: `dune exec --no-buffer test/test_mempool_boot_load.exe`
- fix: getheaders locator is GetLocator(pindexBestHeader); 2000-known replies rerequest from the tip. Control: `dune exec --no-buffer test/test_stale_locator.exe`
- docs: caveat the AssumeUTXO dual-chainstate claim; `getchainstates` reports a single chainstate (boot-smoke `bgval SKIP (single-chainstate)`). Control: `dune exec --no-buffer test/test_readme_assumeutxo_caveat.exe`
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

