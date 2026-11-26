"""Record Core v31.1's Solver type for hostile bare P2PK / bare multisig shapes.

r3fix-camlcoin-p2pk-multisig-input-standard.  Starts a throwaway regtest bitcoind
(Core v31.1) on a scratch datadir, asks `decodescript` for each script's "type"
(GetTxnOutputType(Solver(script))), stops it, and writes core_solver_vectors.ml,
which test_r3fix_p2pk_multisig_input_standard.ml replays against camlcoin's
validate_inputs_standardness.  Python 3 standard library only.

usage: python3 gen_core_solver_vectors.py <path to bitcoind v31.1> <scratch dir> <out.ml>
"""
import base64, hashlib, json, os, random, socket, subprocess, sys, time, urllib.request
from collections import Counter

def push(d: bytes) -> bytes:
    n = len(d)
    if n < 0x4c: return bytes([n]) + d
    if n <= 0xff: return b"\x4c" + bytes([n]) + d
    return b"\x4d" + n.to_bytes(2, "little") + d

def key(h, n): return bytes([h]) + bytes([0x11] * (n - 1))
K33 = [key(h, 33) for h in (0x02, 0x03)]
K65 = [key(h, 65) for h in (0x04, 0x06, 0x07)]
BAD = [key(h, 33) for h in (0x00, 0x04, 0x05, 0x06, 0xff)] + [key(h, 65) for h in (0x00, 0x02, 0x03, 0x05)] + [key(0x02, 32), key(0x02, 34), key(0x04, 64), key(0x04, 66), b""]

def num(n, style):
    """script number n encoded as an opcode/push, in one of several styles."""
    if style == "op":
        return b"\x00" if n == 0 else (bytes([0x50 + n]) if 1 <= n <= 16 else None)
    if style == "push1":   # 1-byte push (minimal only for 17..127)
        return b"\x01" + bytes([n]) if 0 <= n <= 127 else None
    if style == "push2":   # non-minimal 2-byte push
        return b"\x02" + n.to_bytes(2, "little")
    if style == "pd1":     # PUSHDATA1 1-byte (non-minimal push)
        return b"\x4c\x01" + bytes([n]) if n <= 127 else None
    if style == "neg":     # 0x81-style negative
        return b"\x01" + bytes([0x80 | n]) if n <= 127 else None
    return None

# KEYS: the key table the OCaml test rebuilds (index -> key bytes).  Every key in a
# shape's key list is pushed with a direct push; anything else goes in prefix/suffix.
KEYS = K33 + K65 + BAD
def shape(prefix: bytes, keys: list, suffix: bytes):
    return (prefix, keys, suffix)
def build(sh):
    prefix, keys, suffix = sh
    return prefix + b"".join(push(KEYS[i]) for i in keys) + suffix

shapes = []
GOOD = list(range(len(K33) + len(K65)))
NBAD = range(len(K33) + len(K65), len(KEYS))
# P2PK shapes
for i in range(len(KEYS)):
    k = KEYS[i]
    shapes.append(shape(b"", [i], b"\xac"))
    shapes.append(shape(b"", [i], b"\xad"))
    if len(k) in (33, 65):
        shapes.append(shape(b"\x4c" + bytes([len(k)]) + k + b"\xac", [], b""))  # PUSHDATA1 key
        shapes.append(shape(b"", [i], b"\xac\xac"))
        shapes.append(shape(b"", [i], b""))
# multisig shapes: m and n in several encodings, keys mostly compressed
rng = random.Random(31)
styles = ["op", "push1", "push2", "pd1", "neg"]
for m in range(0, 22):
    for n in sorted({m - 1, m, m + 1, 1, 3, 16, 17, 20, 21}):
        if n < 0 or n > 22: continue
        for ms in styles:
            for ns in styles:
                me, ne = num(m, ms), num(n, ns)
                if me is None or ne is None: continue
                if rng.random() > 0.25 and not (ms == ns == "op"): continue
                keys = [rng.choice(GOOD) for _ in range(n)]
                shapes.append(shape(me, keys, ne + b"\xae"))
# key-level hostile multisig
for b in NBAD:
    shapes.append(shape(b"\x51", [b], b"\x51\xae"))
    shapes.append(shape(b"\x51", [0, b], b"\x52\xae"))
for i in (0, len(K33)):
    k = KEYS[i]
    shapes.append(shape(b"\x51\x4c" + bytes([len(k)]) + k, [], b"\x51\xae"))                    # PUSHDATA1 key
    shapes.append(shape(b"\x51\x4d" + len(k).to_bytes(2, "little") + k, [], b"\x51\xae"))       # PUSHDATA2 key
    shapes.append(shape(b"\x51\x4e" + len(k).to_bytes(4, "little") + k, [], b"\x51\xae"))       # PUSHDATA4 key
    shapes.append(shape(b"\x51", [i], b"\x51\xaf"))                                              # CMSVERIFY
    shapes.append(shape(b"\x51", [i], b"\x51\xae\xae"))                                         # trailing
    shapes.append(shape(b"\x51", [i], b"\x51\x61\xae"))                                         # NOP before CMS
    shapes.append(shape(b"\x61\x51", [i], b"\x51\xae"))                                         # NOP first
    shapes.append(shape(b"\x51", [i], b"\x00\x51\xae"))                                         # OP_0 between
    shapes.append(shape(b"\x4f", [i], b"\x51\xae"))                                              # OP_1NEGATE m
for raw in [b"\xae", b"\x51\xae", b"\x51\x51\xae", b"\x00\x00\xae", b"\x51\x4c\x21\xae", b"\x51\x21" + K33[0][:10] + b"\xae"]:
    shapes.append(shape(raw, [], b""))
seen, uniq = set(), []
for sh in shapes:
    s = build(sh)
    if s not in seen: seen.add(s); uniq.append(sh)

bitcoind, work, out = sys.argv[1], sys.argv[2], sys.argv[3]
core_sha = hashlib.sha256(open(bitcoind, "rb").read()).hexdigest()
os.makedirs(work, exist_ok=True)
def free_port():
    with socket.socket() as so:
        so.bind(("127.0.0.1", 0)); return so.getsockname()[1]
rpcport, p2pport = free_port(), free_port()
proc = subprocess.Popen([bitcoind, "-regtest", f"-datadir={work}", f"-rpcport={rpcport}", f"-port={p2pport}",
                         "-listen=0", "-connect=0", "-server=1", "-printtoconsole=0"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
def call(method, params):
    cookie = open(os.path.join(work, "regtest", ".cookie")).read().strip()
    req = urllib.request.Request(f"http://127.0.0.1:{rpcport}/", json.dumps({"id": 1, "method": method, "params": params}).encode(),
                                 {"Authorization": "Basic " + base64.b64encode(cookie.encode()).decode()})
    try:
        with urllib.request.urlopen(req, timeout=30) as r: return json.loads(r.read())
    except urllib.error.HTTPError as e: return json.loads(e.read())
rows = []
try:
    for _ in range(120):
        try:
            if call("getblockcount", []).get("result") == 0: break
        except Exception: pass  # noqa: BLE001
        time.sleep(0.5)
    else:
        raise RuntimeError("bitcoind did not come up")
    for sh in uniq:
        s = build(sh)
        ans = call("decodescript", [s.hex()])
        t = (ans.get("result") or {}).get("type")
        if t is None: raise RuntimeError(f"decodescript {s.hex()}: {ans}")
        rows.append((sh, hashlib.sha256(s).hexdigest(), t))
finally:
    try: call("stop", [])
    except Exception: pass  # noqa: BLE001
    try: proc.wait(60)
    except subprocess.TimeoutExpired: proc.kill()
print("vectors", len(rows), dict(Counter(t for _, _, t in rows)), "core sha256", core_sha)
with open(out, "w") as h:
    h.write("(* GENERATED by gen_core_solver_vectors.py (same directory): Core v31.1\n"
            "   decodescript \"type\" (= Solver) for each script, recorded on regtest.\n"
            f"   Core bitcoind sha256 {core_sha}.\n"
            "   A script is prefix ^ (direct push of keys.(i) for i in idx) ^ suffix; sha is the\n"
            "   sha256 of that script as sent to Core. *)\n")
    h.write("let keys = [|\n")
    for k in KEYS: h.write(f'  "{k.hex()}";\n')
    h.write("|]\n\n(* (prefix, key indices, suffix, sha256, Core type) *)\nlet vectors = [\n")
    for (pre, idx, suf), sha, t in rows:
        h.write(f'  ("{pre.hex()}", [{"; ".join(map(str, idx))}], "{suf.hex()}", "{sha}", "{t}");\n')
    h.write("]\n")
