# Stall class: 231 CRITICALs in 30 days

Diagnosed 2026-09-16T20:30Z from `fleet-monitor-history.jsonl`
(PLAN.md window ending 2026-09-10T02:30Z) and the live unit
`hashhog-camlcoin-mainnet` (pid 669962, up since 2026-09-13 15:05
EDT, pin `7921e5a`). Log: `/data/nvme1/hashhog-mainnet/camlcoin/restart.log`.
Do not restart this node to "nudge" it — that is the named hazard.

Control (this commit): `dune exec --no-buffer test/test_stall_class_231.exe`.

## What "231 CRITICALs" counts

`tools/fleet-monitor.sh` writes every tick into the JSONL unthrottled
(`all_alerts`) and pages on a 1 h `{node, kind, level}` throttle
(`ALERT_THROTTLE_S=3600`). PLAN.md's "camlcoin 231" (2026-09-10) is the
cited figure this queue item names. Recomputed with the same method as
ouroboros's 70 / clearbit's 132 (1 h throttle on `all_alerts`):

| window | raw JSONL CRITICAL | 1 h throttle |
|---|---:|---:|
| 30 d to 2026-09-10T02:30Z | 1107 (132 `lag` + 964 `tip_age` + 11 `rpc_fail`) | **105** (12 `lag` + 87 `tip_age` + 6 `rpc_fail`) |
| 30 d to 2026-09-16T20:10Z | 1996 | **179** (109 `tip_age` + 43 `no_progress` + 27 `rpc_fail`) |

PLAN's 231 sits next to raw-`lag` + throttled-`tip_age` + raw-`rpc_fail`
(132+87+11 = 230). Zero CRITICAL `lag` in the *throttle* sense would
under-count the 70 h freeze: the JSONL stores every 5-min tick, and
that freeze paged every hour. The mechanism below does not depend on
which denominator you pick. The node is not falling hundreds of blocks
behind in a split; it **freezes tens to hundreds of blocks off tip for
hours to days**, headers still advancing.

## The 30-day timeline is two long freezes plus the class that remains

Same-tip, lag>0, status=OK episodes ≥20 min in the PLAN window (3 of
them, 85 h stuck) and since:

| start (UTC) | end | frozen tip | max lag | duration | notes |
|---|---|---:|---:|---:|---|
| 2026-08-11 02:30 | 14:01 | 961084 | 928 | **11.51 h** | poisoned height-index; repair `9be15de`. Restart mid-catch-up tripped the **re-anchor deadlock** (headers already on disk, from-genesis getheaders → "2000 known → stale → fail") |
| 2026-08-11 16:21 | 19:21 | 962013 | 31 | 3.00 h | post-repair residual: IBD flipped FullySynced at the restore tip and stopped downloading |
| 2026-08-17 16:10 | 08-20 14:15 | 962909 | 407 | **70.08 h** | 2.9-day stall named in `cli.ml` at-tip gap fill; headers at 963307 |
| 2026-09-11 19:59 | 09-12 16:55 | 966548 | 147 | 20.92 h | this boot's pin |
| 2026-09-15 22:06 | 09-16 20:06+ | 967188 | 128 | **≥22 h, live** | **this class, live** |

The re-anchor-on-restart deadlock (receipts/camlcoin-repair-executed-2026-08-11.md)
is **closed in source** (`24e8e2c` W146, `test_w146_restart_header_gap.exe`):
restore walks the block-header CF so `state.tip` is the stored header
tip and the genesis re-anchor fires only when those bytes are absent.
It is still a **live-ops hazard** because the production pin is
`7921e5a` (2026-09-07) and PLAN.md forbids restarting camlcoin. W146
is in that pin; the 22 h freeze below is **not** a restart.

## Live signature (this boot, still wedged at diagnosis)

`getblockchaininfo`: `blocks=967188`, `headers=967316`,
`bestblockhash=000000000000000000011446…`, `initialblockdownload=false`.
`getchaintips`: active at 967188, headers-only branchlen 128 at 967316.
Core `:8332` at 967316. 8 outbound peers. RSS ~7.3 GiB. Pin sha256
`f7be1b51…` = `deploy/camlcoin/main.exe` = `7921e5a`.

This process, 2026-09-13 15:05 EDT → 2026-09-16 20:11Z:

- IBD 966722→966862 in 564 s, then FullySynced.
- **2614** `At-tip gap fill: block tip N behind header tip M; requesting 16 block(s) from peer P (walked K headers)` — the 30 s status tick **does** request `block_tip+1`.
- **2690** `Post-IBD gap-fill: requesting N missing blocks`.
- **17208** `Stale tip check (no update for Ns), polling peer P (peer reports height 972471 vs our 967188)`.
- **3584** `Tip severely stale, rotating longest-behind peer`.
- **18243** `All 2000 headers rejected (2000 known) / locator may be stale`.
- **0** `Block … failed validation`. **0** `Snapshot-bootstrap` / re-anchor.
- **556** `BIP68 time-lock FAIL … input_mtp=0 median_time=0` (mempool path; MTP walk miss — not the connect stall).

The 22 h freeze at 967188 started with a 2-header gap
(`requesting 2 block(s) … walked 2 headers`) and grew to 128 as
headers kept moving. Gap fill never stopped asking. Blocks never
connected.

## Root cause

Near-tip **headers-first download is scheduled onto VERSION-height
liars, and the stall-clock treats "no *block* tip update" as "kill a
peer"** while a header-ahead catch-up is in flight. The 2000-known
getheaders loop is the same *symptom* as the re-anchor deadlock
(locator does not match the header tip the liar will serve) with a
different *trigger* (stale-tip poll, not a genesis re-anchor).

1. **`Peer.best_height` is VERSION `start_height`.** Handshake writes
   it (`peer.ml`); `on_headers_received` only raises it. A peer
   advertising `972471` (≈5.1k above the real chain) always wins
   `check_stale_tip`'s "highest reported height" sort. Honest peers at
   967316 lose. The same VERSION-as-network-tip class as clearbit's
   132 CRITICALs.

2. **`pm.our_height` is the *block* tip.** The status loop writes
   `set_height block_height`. Stale-tip therefore sees
   `972471 > 967188` and treats every liar as "ahead" even when our
   *headers* are at the real tip. `last_tip_update` only resets on a
   *block* connect (`notify_tip_updated`), so a 128-header gap with a
   frozen block tip looks 22 h stale.

3. **Rotation at 2× 30 min kills in-flight getdata.** After 3600 s
   with `higher_peers <> []`, `remove_peer` on the longest-behind
   (often the one we just sent 16 `getdata` to). A 16-block witness
   getdata does not finish in the rotation window. The 30 s gap-fill
   tick sends the same 16 to whoever `get_download_peers` returns
   first. Cycle. 3584 rotations this boot.

4. **Catch-up IBD is sticky.** `ensure_catchup_ibd` required
   `not !catchup_ibd_started`. The first IBD (boot 966722→966862)
   sets the flag forever. `start_ibd` already accepts `FullySynced`,
   but the CLI never calls it again. The 16-block at-tip fill is the
   only remaining downloader, and it is fire-and-forget (no in-flight
   map, no stall timeout). Core's `FindNextBlocksToDownload` runs
   from `SendMessages` regardless of IBD state.

5. **`process_new_block` / `connect_stored_blocks` rewind `state.tip`.**
   The W43 comment says they stopped overwriting the header tip; the
   assignment `state.tip <- Some entry` is still there (blame
   `0c39f1be`, 2026-03-29) and `apply_block_atomic` persists
   `header_tip` to the connected block. If a single gap block had
   connected, `next_blocks_to_download` would see tip==blocks_synced
   and request nothing while `headers_synced` stayed 128 ahead. That
   is the remaining re-anchor-adjacent hazard on restart: a rewound
   on-disk `header_tip` makes W146 restore the *block* tip, not the
   header chain.

Contributing, not sufficient: outbound-only; mempool 159k txs on the
same Lwt domain; BIP68 mempool checks with `median_time=0` (hash-linked
MTP miss); `peer_manager.build_locator` walks the height index (active
chain only), so a liar matching at genesis replies with headers 1–2000.

## What a fix control has to fail on

Not another watchdog and not a log-grep. A test that:

- asserts `should_rotate_stale_peer` is false while
  `header_height > block_height` even after 22 h, and still true when
  header==block after 2× the interval;
- asserts VERSION `start_height` 972471 vs header 967316 is **not**
  plausible (`CanServeBlocks` analogue: do not treat VERSION as tip);
- asserts `header_tip_after_block_connect` keeps height 20 when
  connecting height 11, and that `next_blocks_to_download` then still
  returns height 12 (rewind → 0 hashes is the bug);
- asserts `should_start_catchup_ibd` is true for FullySynced +
  header-ahead after the first IBD (`already_started=true`).

Control: `dune exec --no-buffer test/test_stall_class_231.exe`.

The live pin is still `7921e5a`. This commit is source-only; it is not
a deploy. PLAN.md still forbids restarting camlcoin until a human asks.

## Instruments

- `/home/work/hashhog/fleet-monitor-history.jsonl`
- `/data/nvme1/hashhog-mainnet/camlcoin/restart.log`
- RPC `:8357` `getblockchaininfo` / `getchaintips` / `getpeerinfo`
- `lib/peer_manager.ml` (`check_stale_tip`, `build_locator`,
  `version_height_is_plausible`, `should_rotate_stale_peer`)
- `lib/sync.ml` (`header_tip_after_block_connect`,
  `should_start_catchup_ibd`, `process_new_block`,
  `connect_stored_blocks`, `next_blocks_to_download`)
- `lib/cli.ml` (`ensure_catchup_ibd`, at-tip gap fill)
- `24e8e2c` (W146 restore, 2026-08-11), `3dabf43` (GetAncestor gap
  fill, 2026-09-12, **not in the live pin**)
