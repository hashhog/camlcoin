#!/bin/bash
# gc_load_test.sh — EXECUTED before/after gate for the camlcoin hot-path
# compaction fix (2026-06-09).
#
# Reproduces the "detached gc_thread timer starves under synchronous load"
# pathology on regtest and measures whether the in-hot-path Gc_guard checks
# bound the heap peak:
#
#   topology  A (miner, standalone)  <--P2P-->  B (MEASURED, --connect A)
#             B must reach FullySynced via REAL P2P IBD — the at-tip gc
#             machinery is FullySynced-gated (a standalone regtest node stays
#             Idle forever and would show zero [gc] lines for the wrong
#             reason). Gate: getblockchaininfo.initialblockdownload==false.
#   phase 1   offline-built p2wpkh fan-out + spend txs (test_framework
#             builders, no wallet RPC) flooded at B via parallel
#             sendrawtransaction workers  -> ATMP / sendraw hot path.
#   phase 2   flood continues while A mines every ~2 s -> B connects blocks
#             carrying the relayed txs via the real at-tip P2P path
#             -> block-connect / drain hot path.
#
# Measurements (all read BEFORE killing the node):
#   - max heap-BEFORE from B's '[gc] at-tip compaction (...): ... (XMB->YMB)'
#     lines within the load window (the honest OCaml-heap peak metric),
#   - reason-tag histogram (pre arm: threshold/time-floor only; post arm must
#     show hot-path:* tags),
#   - 1/s VmRSS + VmHWM sampler of B (and A) to CSV,
#   - cgroup memory.peak + memory.events oom_kill from INSIDE the
#     regtest-slot scope (a pre-arm cgroup OOM-kill is itself a valid
#     "unbounded" verdict — the harness survives it).
#
# Usage (MUST be wrapped in the slot helper — the load is heavy):
#   REGTEST_SLOTS=1 REGTEST_MEM=12G tools/regtest-slot.sh -- \
#     bash camlcoin/test/gc_load_test.sh --node-bin <main.exe> --arm pre|post
#
# Knobs (identical across arms for a valid comparison):
#   GCLOAD_THRESHOLD_MB (512)  exported as CAMLCOIN_COMPACT_THRESHOLD_MB —
#                              the post binary honors it; the pre binary
#                              ignores it (hardcoded 3 GiB), which is exactly
#                              the unfixed behavior under test.
#   GCLOAD_INITIAL_BLOCKS (1001) GCLOAD_WARM_COINBASES (300)
#   GCLOAD_COLD_COINBASES (600) GCLOAD_FANOUT (20) GCLOAD_CHILD_OUTS (20)
#   GCLOAD_WORKERS (8) GCLOAD_MINE_BLOCKS (20) GCLOAD_MINE_INTERVAL (2)
#   GCLOAD_PAUSE_B (1)
#
# Scratch: /tmp/hashhog-gcload-<arm>/ (trap-cleaned). Results survive at
# /tmp/hashhog-gcload/results-<arm>/ for the cross-arm comparison.
set -uo pipefail

# ── args ───────────────────────────────────────────────────────────────────
# --node-bin   binary for node B (the MEASURED node — pre or post fix)
# --infra-bin  binary for node A (miner/relay infrastructure; defaults to
#              --node-bin). Pass the POST binary for A in BOTH arms so the
#              load generator is identical across arms and self-caps its own
#              heap inside the shared cgroup — only B's binary varies.
NODE_BIN="" ARM="" INFRA_BIN=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --node-bin)  NODE_BIN="$2"; shift 2;;
        --infra-bin) INFRA_BIN="$2"; shift 2;;
        --arm)       ARM="$2"; shift 2;;
        *) echo "unknown arg: $1" >&2; exit 2;;
    esac
done
[[ -x "$NODE_BIN" ]] || { echo "FAIL: --node-bin '$NODE_BIN' not executable" >&2; exit 2; }
INFRA_BIN="${INFRA_BIN:-$NODE_BIN}"
[[ -x "$INFRA_BIN" ]] || { echo "FAIL: --infra-bin '$INFRA_BIN' not executable" >&2; exit 2; }
[[ "$ARM" == "pre" || "$ARM" == "post" ]] || { echo "FAIL: --arm must be pre|post" >&2; exit 2; }

TF_PATH="/home/work/hashhog/bitcoin-core/test/functional"
[[ -d "$TF_PATH/test_framework" ]] || { echo "FAIL: test_framework not at $TF_PATH" >&2; exit 2; }

# ── knobs / layout ─────────────────────────────────────────────────────────
THRESHOLD_MB="${GCLOAD_THRESHOLD_MB:-512}"
INITIAL_BLOCKS="${GCLOAD_INITIAL_BLOCKS:-1001}"
# Coinbase split (calibration-driven, 2026-06-10):
#  - WARM set: flooded at B via sendrawtransaction (ATMP/sendraw hot-path
#    churn). These txs land in B's mempool AND sig cache.
#  - COLD set: fed ONLY to A and mined into the phase-2 fat blocks. B has
#    never seen them, so the catch-up burst must FULL-VERIFY every input —
#    the allocation-heavy synchronous stretch the un-fixed timers cannot
#    interrupt (the mainnet drain/re-IBD pathology shape). A warm B (sig
#    cache primed by its own flood) was observed connecting 20 fat blocks
#    in ~2 s, far too cheap to stress anything.
#  (Two RBF-replacement-round variants were tried and DROPPED: a
#  replacement against an ~19k-entry mempool costs ~0.7-2 s of synchronous
#  conflict-scan CPU — allocation-LIGHT, starvation-heavy — wedging B for
#  tens of minutes while blocking the block phase.)
WARM_COINBASES="${GCLOAD_WARM_COINBASES:-300}"
COLD_COINBASES="${GCLOAD_COLD_COINBASES:-600}"
FANOUT="${GCLOAD_FANOUT:-20}"
CHILD_OUTS="${GCLOAD_CHILD_OUTS:-20}"
WORKERS="${GCLOAD_WORKERS:-8}"
MINE_BLOCKS="${GCLOAD_MINE_BLOCKS:-20}"
MINE_INTERVAL="${GCLOAD_MINE_INTERVAL:-2}"
# SIGSTOP B while A mines, so B catches up through a sustained synchronous
# multi-block connect burst (process_new_block + connect_stored_blocks) —
# the starvation stretch no Lwt timer can interrupt. SIGSTOP/SIGCONT keeps B
# FullySynced (no restart, no run_ibd hand-off).
PAUSE_B="${GCLOAD_PAUSE_B:-1}"

A_P2P=29611; A_RPC=29612
B_P2P=29621; B_RPC=29622

SCRATCH="/tmp/hashhog-gcload-$ARM"
OUT="/tmp/hashhog-gcload/results-$ARM"
DA="$SCRATCH/node-a"; DB="$SCRATCH/node-b"
LOG_A="$DA/node.log"; LOG_B="$DB/node.log"

# Identical env across arms; pre binary ignores the knob (hardcoded 3 GiB).
export CAMLCOIN_COMPACT_THRESHOLD_MB="$THRESHOLD_MB"
# Mirror the soak-proven production glibc tuning (start_mainnet.sh) so the
# off-heap half behaves the same in both arms.
export MALLOC_ARENA_MAX=2
export MALLOC_TRIM_THRESHOLD_=131072

log() { echo "[gcload:$ARM $(date +%H:%M:%S)] $*" >&2; }
PIDS=()
cleanup() {
    set +e
    # Preserve node logs for post-mortem even on early FAIL exits.
    [[ -f "$LOG_A" && ! -f "$OUT/node_a.log" ]] && cp "$LOG_A" "$OUT/node_a.log"
    [[ -f "$LOG_B" && ! -f "$OUT/node_b.log" ]] && cp "$LOG_B" "$OUT/node_b.log"
    for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done
    sleep 1
    for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null; done
    fuser -k "$A_RPC/tcp" "$A_P2P/tcp" "$B_RPC/tcp" "$B_P2P/tcp" >/dev/null 2>&1
    rm -rf "$SCRATCH"
}
trap cleanup EXIT

rm -rf "$SCRATCH" "$OUT"
mkdir -p "$DA" "$DB" "$OUT"
fuser -k "$A_RPC/tcp" "$A_P2P/tcp" "$B_RPC/tcp" "$B_P2P/tcp" >/dev/null 2>&1 || true
sleep 1

rpc() { # rpc <port> <cookie-file> <method> [params-json]
    local port="$1" ck="$2" method="$3" params="${4:-[]}"
    curl -s --max-time 120 -u "$(cat "$ck" 2>/dev/null)" \
        --data-binary "{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"$method\",\"params\":$params}" \
        "http://127.0.0.1:${port}/" 2>/dev/null
}

wait_rpc() { # wait_rpc <pid> <port> <cookie-file> <name> <secs>
    local pid="$1" port="$2" ck="$3" name="$4" secs="$5"
    local deadline=$(( $(date +%s) + secs ))
    while (( $(date +%s) < deadline )); do
        kill -0 "$pid" 2>/dev/null || { log "FAIL: $name exited during startup"; return 1; }
        [[ -f "$ck" ]] && rpc "$port" "$ck" getblockcount | grep -q '"result"' && return 0
        sleep 1
    done
    log "FAIL: $name RPC never responded within ${secs}s"; return 1
}

# ── helper python (offline tx builder + flood workers + miner) ─────────────
PY="$SCRATCH/gcload.py"
cat > "$PY" <<'PYEOF'
import sys, json, base64, urllib.request, urllib.parse, http.client, time
TF = "/home/work/hashhog/bitcoin-core/test/functional"
sys.path.insert(0, TF)
from test_framework.key import ECKey
from test_framework.messages import (CTransaction, CTxIn, CTxOut, COutPoint,
                                     CTxInWitness, COIN)
from test_framework.script import (CScript, OP_0, hash160,
    SegwitV0SignatureHash, SIGHASH_ALL,
    OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG)
from test_framework.address import key_to_p2wpkh

SECRET = "1f" * 32  # deterministic load key
priv = ECKey(); priv.set(bytes.fromhex(SECRET), compressed=True)
pub  = priv.get_pubkey().get_bytes()
pkh  = hash160(pub)
spk  = CScript([OP_0, pkh])
addr = key_to_p2wpkh(pub, main=False)
SEQ  = 0xfffffffd
SCRIPTCODE = CScript([OP_DUP, OP_HASH160, pkh, OP_EQUALVERIFY, OP_CHECKSIG])

# Fast signer: coincurve (libsecp256k1, ~50 us/sign, low-S DER) when present;
# pure-python test_framework ECKey (~10 ms/sign) as fallback. Same key.
try:
    import coincurve
    _cck = coincurve.PrivateKey(bytes.fromhex(SECRET))
    def sign_digest(d): return _cck.sign(d, hasher=None)
except ImportError:
    def sign_digest(d): return priv.sign_ecdsa(d)

def mkrpc(url, cookie_file):
    with open(cookie_file) as f:
        cookie = f.read().strip()
    auth = "Basic " + base64.b64encode(cookie.encode()).decode()
    _id = [0]
    def rpc(method, params=None, timeout=180):
        _id[0] += 1
        body = json.dumps({"jsonrpc": "1.0", "id": _id[0], "method": method,
                           "params": params or []}).encode()
        req = urllib.request.Request(url, data=body,
            headers={"Authorization": auth, "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            d = json.loads(r.read())
        return d.get("result"), d.get("error")
    return rpc

class KeepAliveRPC:
    """Persistent-connection JSON-RPC client for the flood workers (urllib
    opens a fresh TCP connection per call, which caps the flood rate)."""
    def __init__(self, url, cookie_file):
        u = urllib.parse.urlparse(url)
        self.host, self.port = u.hostname, u.port
        with open(cookie_file) as f:
            cookie = f.read().strip()
        self.headers = {
            "Authorization": "Basic " + base64.b64encode(cookie.encode()).decode(),
            "Content-Type": "application/json"}
        self.conn = None
        self._id = 0
    def _connect(self):
        self.conn = http.client.HTTPConnection(self.host, self.port, timeout=120)
    def call(self, method, params=None):
        self._id += 1
        body = json.dumps({"jsonrpc": "1.0", "id": self._id, "method": method,
                           "params": params or []})
        for attempt in (0, 1):
            try:
                if self.conn is None:
                    self._connect()
                self.conn.request("POST", "/", body, self.headers)
                resp = self.conn.getresponse()
                d = json.loads(resp.read())
                return d.get("result"), d.get("error")
            except Exception:
                try: self.conn.close()
                except Exception: pass
                self.conn = None
                if attempt == 1:
                    raise
        return None, {"message": "unreachable"}

def build_spend(prev_txid_hex, prev_vout, in_value, out_values):
    tx = CTransaction(); tx.version = 2
    tx.vin  = [CTxIn(COutPoint(int(prev_txid_hex, 16), prev_vout), b"", SEQ)]
    tx.vout = [CTxOut(v, spk) for v in out_values]
    tx.wit.vtxinwit = [CTxInWitness()]
    sh = SegwitV0SignatureHash(SCRIPTCODE, tx, 0, SIGHASH_ALL, in_value)
    tx.wit.vtxinwit[0].scriptWitness.stack = [
        sign_digest(sh) + bytes([SIGHASH_ALL]), pub]
    return tx

cmd = sys.argv[1]

if cmd == "addr":
    print(addr)

elif cmd == "minechunk":
    # minechunk <url> <cookie> <total> <chunk>
    rpc = mkrpc(sys.argv[2], sys.argv[3])
    total, chunk = int(sys.argv[4]), int(sys.argv[5])
    done = 0
    while done < total:
        n = min(chunk, total - done)
        res, err = rpc("generatetoaddress", [n, addr])
        if err: print(f"ERR generatetoaddress: {err}", file=sys.stderr); sys.exit(1)
        done += n
        print(f"mined {done}/{total}", file=sys.stderr)

elif cmd == "mineloop":
    # mineloop <url> <cookie> <nblocks> <interval_s>
    rpc = mkrpc(sys.argv[2], sys.argv[3])
    n, iv = int(sys.argv[4]), float(sys.argv[5])
    for i in range(n):
        res, err = rpc("generatetoaddress", [1, addr])
        if err: print(f"ERR mineloop blk {i}: {err}", file=sys.stderr); sys.exit(1)
        time.sleep(iv)
    print("mineloop done", file=sys.stderr)

elif cmd == "build":
    # build <a_url> <a_cookie> <n_warm> <n_cold> <fanout> <child_outs> <outdir>
    # Writes parents_warm/children_warm (coinbases 1..n_warm, flooded at B)
    # and parents_cold/children_cold (coinbases n_warm+1..n_warm+n_cold, fed
    # only to A and mined — COLD at B, forcing full script verification on
    # the catch-up connect burst).
    rpc = mkrpc(sys.argv[2], sys.argv[3])
    n_warm, n_cold = int(sys.argv[4]), int(sys.argv[5])
    fanout, child_outs = int(sys.argv[6]), int(sys.argv[7])
    outdir = sys.argv[8]
    PARENT_FEE = 20000
    CHILD_FEE  = 8000
    t0 = time.time()
    sets = [("warm", 1, n_warm), ("cold", n_warm + 1, n_warm + n_cold)]
    for name, h0, h1 in sets:
        with open(f"{outdir}/parents_{name}.txt", "w") as pf, \
             open(f"{outdir}/children_{name}.txt", "w") as cf:
            for h in range(h0, h1 + 1):
                bh, err = rpc("getblockhash", [h])
                if err: print(f"ERR getblockhash {h}: {err}", file=sys.stderr); sys.exit(1)
                blk, err = rpc("getblock", [bh, 2])
                if err: print(f"ERR getblock {h}: {err}", file=sys.stderr); sys.exit(1)
                cb = blk["tx"][0]
                val = int(round(cb["vout"][0]["value"] * COIN))
                share = (val - PARENT_FEE) // fanout
                parent = build_spend(cb["txid"], 0, val, [share] * fanout)
                pf.write(parent.serialize_with_witness().hex() + "\n")
                # txid_hex is RPC-order hex (matches COutPoint's int(txid, 16)
                # convention used in build_spend).
                ptxid = parent.txid_hex
                cshare = (share - CHILD_FEE) // child_outs
                for i in range(fanout):
                    child = build_spend(ptxid, i, share, [cshare] * child_outs)
                    cf.write(child.serialize_with_witness().hex() + "\n")
                if h % 100 == 0:
                    print(f"built {h}/{n_warm + n_cold} fan-outs "
                          f"({time.time()-t0:.0f}s)", file=sys.stderr)
    print(f"build done in {time.time()-t0:.0f}s", file=sys.stderr)

elif cmd == "send":
    # send <url> <cookie> <file> <shard_idx> <shard_n> <ignore_errors>
    rpc = KeepAliveRPC(sys.argv[2], sys.argv[3])
    path, idx, n = sys.argv[4], int(sys.argv[5]), int(sys.argv[6])
    ignore = sys.argv[7] == "1"
    ok = err_n = 0
    first_errs = []
    t0 = time.time()
    with open(path) as f:
        for i, line in enumerate(f):
            if i % n != idx: continue
            raw = line.strip()
            if not raw: continue
            try:
                res, err = rpc.call("sendrawtransaction", [raw])
                if err:
                    err_n += 1
                    if len(first_errs) < 3: first_errs.append(str(err))
                else: ok += 1
            except Exception as e:
                err_n += 1
                if len(first_errs) < 3: first_errs.append(repr(e))
                if not ignore: raise
    print(f"SENT shard {idx}/{n} ok={ok} err={err_n} in {time.time()-t0:.0f}s "
          f"first_errs={first_errs}", file=sys.stderr)

elif cmd == "mpcount":
    rpc = mkrpc(sys.argv[2], sys.argv[3])
    res, err = rpc("getmempoolinfo")
    print(0 if err or not res else res.get("size", 0))

else:
    print(f"unknown cmd {cmd}", file=sys.stderr); sys.exit(2)
PYEOF

ADDR=$(python3 "$PY" addr) || { log "FAIL: addr derivation failed"; exit 2; }
log "load address: $ADDR (threshold knob ${THRESHOLD_MB}MB; pre binary ignores it)"

# ── 1. node A (miner, standalone) ──────────────────────────────────────────
log "booting node A (miner) rpc=$A_RPC p2p=$A_P2P"
"$INFRA_BIN" --network regtest --datadir "$DA" \
    --port "$A_P2P" --rpcport "$A_RPC" >"$LOG_A" 2>&1 &
A_PID=$!; PIDS+=("$A_PID")
wait_rpc "$A_PID" "$A_RPC" "$DA/.cookie" "node A" 60 || exit 2

log "mining $INITIAL_BLOCKS blocks on A ($(( INITIAL_BLOCKS - 100 )) mature coinbases)"
python3 "$PY" minechunk "http://127.0.0.1:$A_RPC/" "$DA/.cookie" "$INITIAL_BLOCKS" 100 \
    2>>"$OUT/harness.log" || { log "FAIL: initial mining failed"; exit 2; }
HA=$(rpc "$A_RPC" "$DA/.cookie" getblockcount | grep -o '"result":[0-9]*' | cut -d: -f2)
[[ "${HA:-0}" -eq "$INITIAL_BLOCKS" ]] || { log "FAIL: A height ${HA:-?} != $INITIAL_BLOCKS"; exit 2; }
[[ $(( WARM_COINBASES + COLD_COINBASES )) -le $(( INITIAL_BLOCKS - 100 )) ]] \
    || { log "FAIL: warm+cold coinbases exceed mature supply"; exit 2; }

# Overlap the (CPU-bound, A-only) offline flood construction with A's 60 s
# no-peer window below.
log "building flood in background: warm=$WARM_COINBASES + cold=$COLD_COINBASES fan-outs x $FANOUT spends x $CHILD_OUTS outs (~$(( (WARM_COINBASES + COLD_COINBASES) * (FANOUT + 1) )) signed txs)"
python3 "$PY" build "http://127.0.0.1:$A_RPC/" "$DA/.cookie" \
    "$WARM_COINBASES" "$COLD_COINBASES" "$FANOUT" "$CHILD_OUTS" "$SCRATCH" \
    2>>"$OUT/harness.log" &
BUILD_PID=$!; PIDS+=("$BUILD_PID")

# camlcoin gotcha: a node only enables its P2P message loops (which feed the
# listener dispatch, incl. the getheaders RESPONDER) after its own startup
# sync phase ends. Two fresh camlcoin nodes that connect immediately
# deadlock in mutual sync_headers (each waits for headers the other's
# disabled responder will never send). A exits the phase via the 60 s
# no-peer bailout ("No peers connected after 60s") — so B must boot only
# AFTER that line appears in A's log.
log "waiting for A's 60s no-peer bailout (enables its getheaders responder)"
deadline=$(( $(date +%s) + 150 ))
until grep -q "No peers connected after 60s" "$LOG_A" 2>/dev/null; do
    (( $(date +%s) < deadline )) || { log "FAIL: A never enabled message loops"; exit 2; }
    kill -0 "$A_PID" 2>/dev/null || { log "FAIL: A died while waiting"; exit 2; }
    sleep 2
done
log "A message loops enabled"

# ── 2. node B (MEASURED) — real P2P IBD so FullySynced arms the gc gate ────
boot_b() { # boot_b <phase-label>
    "$NODE_BIN" --network regtest --datadir "$DB" \
        --port "$B_P2P" --rpcport "$B_RPC" \
        --connect "127.0.0.1:$A_P2P" >>"$LOG_B" 2>&1 &
    B_PID=$!; PIDS+=("$B_PID")
    wait_rpc "$B_PID" "$B_RPC" "$DB/.cookie" "node B ($1)" 60 || return 1
    local deadline=$(( $(date +%s) + 180 )) armed=0 r
    while (( $(date +%s) < deadline )); do
        r=$(rpc "$B_RPC" "$DB/.cookie" getblockchaininfo)
        echo "$r" | grep -q '"initialblockdownload":false' && { armed=1; break; }
        kill -0 "$B_PID" 2>/dev/null || { log "FAIL: B died during IBD ($1)"; return 1; }
        sleep 2
    done
    [[ "$armed" == 1 ]] || { log "FAIL: B never reached FullySynced ($1)"; return 1; }
    return 0
}

log "booting node B (measured) rpc=$B_RPC p2p=$B_P2P --connect A"
boot_b "initial IBD" || exit 2
HB=$(rpc "$B_RPC" "$DB/.cookie" getblockcount | grep -o '"result":[0-9]*' | cut -d: -f2)
log "B FullySynced at height ${HB:-?} after initial IBD"

# camlcoin gotcha #2 (pre-existing bug, found by this harness 2026-06-09):
# the at-tip P2P block-connect path (Sync.process_new_block) never calls
# Mempool.remove_for_block/update_height, so mempool.current_height stays at
# its Mempool.create boot value — 0 for a node that just IBD'd from genesis —
# and EVERY coinbase spend is rejected "Spending immature coinbase". The
# live mainnet node never sees this because it always boots from an existing
# datadir. Mirror that shape: restart B on its synced datadir (mempool is
# created at height ~501), with A mined a few blocks ahead so the second
# boot re-arms FullySynced via a real header+block sync.
log "restarting B on its synced datadir (fixes mempool boot height; A +5 ahead)"
kill "$B_PID" 2>/dev/null
for i in $(seq 1 30); do kill -0 "$B_PID" 2>/dev/null || break; sleep 1; done
kill -0 "$B_PID" 2>/dev/null && { kill -9 "$B_PID"; sleep 1; }
python3 "$PY" minechunk "http://127.0.0.1:$A_RPC/" "$DA/.cookie" 5 5 \
    2>>"$OUT/harness.log" || { log "FAIL: pre-restart mining failed"; exit 2; }
boot_b "restart" || exit 2
HB=$(rpc "$B_RPC" "$DB/.cookie" getblockcount | grep -o '"result":[0-9]*' | cut -d: -f2)
log "B FullySynced at height ${HB:-?} after restart — gc machinery + mempool armed"

# ── 3. RSS sampler (1/s, both nodes; VmHWM captured every tick) ────────────
RSS_CSV="$OUT/rss.csv"
echo "ts,b_vmrss_kb,b_vmhwm_kb,a_vmrss_kb" > "$RSS_CSV"
(
    while kill -0 "$B_PID" 2>/dev/null; do
        brss=$(awk '/VmRSS/{print $2}'  "/proc/$B_PID/status" 2>/dev/null || echo 0)
        bhwm=$(awk '/VmHWM/{print $2}'  "/proc/$B_PID/status" 2>/dev/null || echo 0)
        arss=$(awk '/VmRSS/{print $2}'  "/proc/$A_PID/status" 2>/dev/null || echo 0)
        echo "$(date +%s),${brss:-0},${bhwm:-0},${arss:-0}" >> "$RSS_CSV"
        sleep 1
    done
) &
SAMPLER_PID=$!; PIDS+=("$SAMPLER_PID")

# ── 4. offline flood construction (started in background above) ────────────
wait "$BUILD_PID" || { log "FAIL: flood construction failed"; exit 2; }
[[ -s "$SCRATCH/parents_warm.txt" && -s "$SCRATCH/children_warm.txt" \
   && -s "$SCRATCH/parents_cold.txt" && -s "$SCRATCH/children_cold.txt" ]] \
    || { log "FAIL: flood files empty"; exit 2; }
log "flood construction complete"

# Load window starts here: only [gc] lines after this mark count.
LOG_MARK=$(wc -l < "$LOG_B")
LOAD_T0=$(date +%s)
log "LOAD START (B log mark line $LOG_MARK)"

# ── 5. phase 1: parents then parallel children flood at B ──────────────────
set +e
flood_b() { # flood_b <file> — $WORKERS parallel keep-alive shards, waits all
    local file="$1" w; local fpids=()
    for (( w=0; w<WORKERS; w++ )); do
        python3 "$PY" send "http://127.0.0.1:$B_RPC/" "$DB/.cookie" \
            "$file" "$w" "$WORKERS" 1 2>>"$OUT/harness.log" &
        fpids+=("$!")
    done
    PIDS+=("${fpids[@]}")
    for w in "${fpids[@]}"; do wait "$w" 2>/dev/null; done
}

log "phase 1a: sending $WARM_COINBASES warm parent fan-outs to B"
python3 "$PY" send "http://127.0.0.1:$B_RPC/" "$DB/.cookie" \
    "$SCRATCH/parents_warm.txt" 0 1 1 2>>"$OUT/harness.log"

log "phase 1b: flooding $((WARM_COINBASES * FANOUT)) warm children at B with $WORKERS workers"
flood_b "$SCRATCH/children_warm.txt"

# Feed A the COLD set only (tx relay B->A is not functional on this
# pinned-loopback topology — observed: A mempool stays 0 — so B's warm set
# never reaches A and the mined blocks stay COLD for B). Foreground: A's
# mempool must be full BEFORE mining so every phase-2 block is fat.
log "feeding A the cold set ($((COLD_COINBASES * (FANOUT + 1))) txs)"
python3 "$PY" send "http://127.0.0.1:$A_RPC/" "$DA/.cookie" \
    "$SCRATCH/parents_cold.txt" 0 1 1 2>>"$OUT/harness.log"
python3 "$PY" send "http://127.0.0.1:$A_RPC/" "$DA/.cookie" \
    "$SCRATCH/children_cold.txt" 0 2 1 2>>"$OUT/harness.log" &
AF1=$!
python3 "$PY" send "http://127.0.0.1:$A_RPC/" "$DA/.cookie" \
    "$SCRATCH/children_cold.txt" 1 2 1 2>>"$OUT/harness.log" &
AF2=$!
PIDS+=("$AF1" "$AF2")
wait "$AF1" 2>/dev/null; wait "$AF2" 2>/dev/null
AMP=$(python3 "$PY" mpcount "http://127.0.0.1:$A_RPC/" "$DA/.cookie" 2>/dev/null)
log "A mempool after cold feed: ${AMP:-?} txs"

# ── 6. phase 2: mining (fat COLD blocks) with B paused -> catch-up burst ───
# SIGSTOP B for the whole mining window: A mines $MINE_BLOCKS blocks (the
# first several FAT, full of txs B has NEVER validated); on SIGCONT B
# discovers them via the buffered invs / stale-tip getheaders and connects
# them in a sustained synchronous burst (process_new_block +
# connect_stored_blocks) doing FULL script verification — the
# allocation-heavy stretch the un-fixed timer machinery cannot interrupt.
# SIGSTOP keeps B FullySynced (no restart, no run_ibd hand-off).
if [[ "$PAUSE_B" == 1 ]]; then
    log "phase 2: SIGSTOP B, then mining $MINE_BLOCKS fat cold blocks on A every ${MINE_INTERVAL}s"
    kill -STOP "$B_PID" 2>/dev/null
else
    log "phase 2: mining $MINE_BLOCKS fat cold blocks on A every ${MINE_INTERVAL}s (B live)"
fi
python3 "$PY" mineloop "http://127.0.0.1:$A_RPC/" "$DA/.cookie" \
    "$MINE_BLOCKS" "$MINE_INTERVAL" 2>>"$OUT/harness.log" &
MINER_PID=$!; PIDS+=("$MINER_PID")
wait "$MINER_PID" 2>/dev/null
log "mining loop done"
if [[ "$PAUSE_B" == 1 ]]; then
    kill -CONT "$B_PID" 2>/dev/null
    log "SIGCONT B — cold catch-up connect burst begins"
fi

# ── 7. converge: B must reach A's tip (proves B alive + connecting) ────────
HA=$(rpc "$A_RPC" "$DA/.cookie" getblockcount | grep -o '"result":[0-9]*' | cut -d: -f2)
deadline=$(( $(date +%s) + 300 )); HB=0
while (( $(date +%s) < deadline )); do
    kill -0 "$B_PID" 2>/dev/null || break
    HB=$(rpc "$B_RPC" "$DB/.cookie" getblockcount | grep -o '"result":[0-9]*' | cut -d: -f2)
    [[ -n "$HB" && "$HB" == "$HA" ]] && break
    sleep 2
done
B_ALIVE=no; kill -0 "$B_PID" 2>/dev/null && B_ALIVE=yes
# Settle window: with the un-fixed binary the in-load timers (gc_thread,
# status loop) are starved by the synchronous flood, so its FIRST compaction
# happens only after the load quiesces — its [gc] heap-before line is the
# honest accumulation high-water mark and must land inside the measurement
# window. (Time-floor fires from the 30 s status tick once last_compact is
# >120 s old; 90 s covers it in both arms.)
if [[ "$B_ALIVE" == yes ]]; then
    log "settle 90s (lets the deferred/starved compaction emit its [gc] line)"
    sleep 90
    # B may have caught up during settle (it was busy at convergence-poll time).
    HB2=$(rpc "$B_RPC" "$DB/.cookie" getblockcount | grep -o '"result":[0-9]*' | cut -d: -f2)
    [[ -n "${HB2:-}" ]] && HB="$HB2"
fi
LOAD_T1=$(date +%s)
log "load end: A=$HA B=${HB:-?} b_alive=$B_ALIVE duration=$(( LOAD_T1 - LOAD_T0 ))s"
# stay in set +e: the measurement section must run even after a pre-arm OOM

# ── 8. measurements (BEFORE killing anything) ──────────────────────────────
VMHWM_KB=$(awk '/VmHWM/{print $2}' "/proc/$B_PID/status" 2>/dev/null || echo 0)
# Fallback to the sampler's last view if B is already dead (OOM case).
[[ "${VMHWM_KB:-0}" -gt 0 ]] || VMHWM_KB=$(awk -F, 'NR>1{if($3>m)m=$3}END{print m+0}' "$RSS_CSV")
VMHWM_MB=$(( VMHWM_KB / 1024 ))
MAX_RSS_KB=$(awk -F, 'NR>1{if($2>m)m=$2}END{print m+0}' "$RSS_CSV")
MAX_RSS_MB=$(( MAX_RSS_KB / 1024 ))

CGPATH=$(cut -d: -f3 "/proc/self/cgroup" | tail -1)
CG="/sys/fs/cgroup${CGPATH}"
CG_PEAK_MB=$(( $(cat "$CG/memory.peak" 2>/dev/null || echo 0) / 1048576 ))
OOM_KILLS=$(awk '/^oom_kill /{print $2}' "$CG/memory.events" 2>/dev/null || echo 0)

cp "$LOG_B" "$OUT/node_b.log" 2>/dev/null || true
cp "$LOG_A" "$OUT/node_a.log" 2>/dev/null || true

WINDOW="$OUT/gc_window.log"
tail -n "+$(( LOG_MARK + 1 ))" "$OUT/node_b.log" > "$WINDOW" 2>/dev/null || touch "$WINDOW"

GC_LINES=$(grep -cF '[gc] at-tip compaction' "$WINDOW" || true)
HOT_LINES=$(grep -cE '\[gc\] at-tip compaction \(hot-path' "$WINDOW" || true)
# Starvation evidence: the status loop ticks every 30 s when healthy; a
# shortfall vs wall-clock expectation = Lwt-timer starvation (the same
# starvation that defers the un-fixed gc_thread indefinitely).
STATUS_TICKS=$(grep -c 'Status:' "$WINDOW" || true)
EXPECTED_TICKS=$(( (LOAD_T1 - LOAD_T0) / 30 ))
PEAK_HEAP_BEFORE_MB=$(grep -F '[gc] at-tip compaction' "$WINDOW" \
    | grep -oE '\([0-9]+MB->' | grep -oE '[0-9]+' | sort -n | tail -1)
PEAK_HEAP_BEFORE_MB=${PEAK_HEAP_BEFORE_MB:-0}
MAX_HEAP_AFTER_MB=$(grep -F '[gc] at-tip compaction' "$WINDOW" \
    | grep -oE '\->[0-9]+MB\)' | grep -oE '[0-9]+' | sort -n | tail -1)
MAX_HEAP_AFTER_MB=${MAX_HEAP_AFTER_MB:-0}
TAGS=$(grep -oE '\[gc\] at-tip compaction \([a-z:-]+\)' "$WINDOW" \
    | sed 's/.*(\(.*\))/\1/' | sort | uniq -c | awk '{printf "%s=%s ", $2, $1}')

{
    echo "arm=$ARM"
    echo "node_bin=$NODE_BIN"
    echo "threshold_knob_mb=$THRESHOLD_MB"
    echo "load_duration_s=$(( LOAD_T1 - LOAD_T0 ))"
    echo "height_a=$HA height_b=${HB:-?} b_alive=$B_ALIVE"
    echo "peak_heap_before_mb=$PEAK_HEAP_BEFORE_MB"
    echo "max_heap_after_mb=$MAX_HEAP_AFTER_MB"
    echo "gc_lines_in_window=$GC_LINES hotpath_lines=$HOT_LINES"
    echo "status_ticks_in_window=$STATUS_TICKS expected~$EXPECTED_TICKS (shortfall = timer starvation)"
    echo "tags: ${TAGS:-none}"
    echo "b_vmhwm_mb=$VMHWM_MB b_max_sampled_rss_mb=$MAX_RSS_MB"
    echo "cgroup_peak_mb=$CG_PEAK_MB oom_kills=$OOM_KILLS"
} | tee "$OUT/summary.txt" >&2

echo "GCLOAD camlcoin arm=$ARM peak_heap_before_mb=$PEAK_HEAP_BEFORE_MB \
hotpath_compactions=$HOT_LINES gc_lines=$GC_LINES vmhwm_mb=$VMHWM_MB \
cgroup_peak_mb=$CG_PEAK_MB oom_kills=$OOM_KILLS b_alive=$B_ALIVE \
heights=$HA/${HB:-?} tags='${TAGS:-none}'"

# Harness succeeded if we got a measurement; an OOM-killed B in the pre arm
# is a valid (unbounded) data point, not a harness failure.
exit 0
