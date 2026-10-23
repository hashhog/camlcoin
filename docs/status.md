# Status: how to check it yourself

Every row of the README's status table can be checked from this repository or from a
Bitcoin Core node you run yourself.

## Mainnet validation

camlcoin was run over mainnet from genesis to height 958,794 with script checks on. The
run was done as 48 consecutive ranges: each range loaded the UTXO set the previous range
ended with and validated the next blocks. The ranges did not all use the same camlcoin
commit. At height 958,794 the UTXO set's `hash_serialized_3` was

```
29692050559b8f064a03af9cd605040e71d1d978fa22947c079cc7e5546e7af0   (166,180,925 coins)
```

which is what Bitcoin Core reports at that height. The 48-range run above is not a single
build, and no single, uninterrupted node run from genesis to that height has been recorded.

A separate check used one build, `camlcoin swiftsync-pass` at commit `e54cf90` (binary
sha256 `959914fb…6b87`). It validated every block from 1 to 958,794 with script checks on
(3,429,543,565 inputs, each handed to the script checker) in 24 ranges run in parallel,
and the resulting set closed on the same hash and coin count as above on 2026-10-08. This
is a SwiftSync-style pass (draft BIP 457): spent coins come from Bitcoin Core's undo data,
checked against a salted hash aggregate, and no UTXO set is kept. It exercises the block
validation rules (`Validation.accept_block` with scripts on). It does not exercise the
node's UTXO cache, flush, undo writer, assume-valid gate or BIP30 lookup. The receipt
(commands, negative controls, result files) is in the hashhog meta-repo, which is private,
so this paragraph is a claim you cannot verify from this repository.

To reproduce it in one run (this takes days and about 1 TB of disk):

```bash
export DATADIR=/path/to/empty/dir
camlcoin --network=mainnet --datadir="$DATADIR" --noassumevalid > "$DATADIR/node.log" 2>&1 &
# wait until getblockcount is above 958794, then:
curl -s --user "$(cat "$DATADIR/.cookie")" \
  -d "{\"method\":\"dumptxoutset\",\"params\":[\"$DATADIR/utxo-958794.dat\",\"\",{\"rollback\":958794}]}" \
  http://127.0.0.1:8332/
```

`dumptxoutset` with a `rollback` height rewinds the UTXO set to that height, writes it,
and restores the tip. Its result has `coins_written` and `txoutset_hash`; the latter is
`hash_serialized_3`. Run the same `dumptxoutset` call on a Bitcoin Core node to get Core's
value. The same call works on regtest, which is a quick way to try it (with a regtest
node running as in the README's quick start):

```bash
curl -s --user "$(cat "$DATADIR/.cookie")" \
  -d '{"method":"generatetoaddress","params":[60,"bcrt1qzeglnekd2ev00jruxvmxv5nx2ufn2l6vj2eecy"]}' \
  http://127.0.0.1:18443/ | head -c 100; echo
curl -s --user "$(cat "$DATADIR/.cookie")" \
  -d "{\"method\":\"dumptxoutset\",\"params\":[\"$DATADIR/utxo-50.dat\",\"\",{\"rollback\":50}]}" \
  http://127.0.0.1:18443/
```

## Core's test vectors

`resources/` holds Bitcoin Core's `script_tests.json` and `sighash.json`. Both are part of
`dune test`, and can be run alone from the `test/` directory (the sighash test looks for
`../resources/`, so it fails when started from the repository root):

```bash
cd test
dune exec --no-buffer ./test_script_vectors.exe
dune exec --no-buffer ./test_sighash_vectors.exe
cd ..
```

The first prints a summary; all 1,222 entries pass:

```
=== Script Test Vector Results ===
Total tests: 1222 (non-witness: 1109, witness: 113)
  PASS:  1222
  FAIL:  0
```

## Test suite

```bash
dune test
```

`dune test` builds and runs every test in `test/dune`: on 2026-10-17 that was 134
Alcotest executables with 3,977 test cases, plus a handful of standalone checks that
print their own pass/fail lines. It exits non-zero if any test fails. It needs no
network, no running node and no Bitcoin Core checkout. Alcotest writes per-test output
under `_build/default/test/_build/_tests/`.

The suite covers serialization, script and sighash (Core's vectors), block and
transaction validation, UTXO cache and chainstate durability, reorgs, header sync, P2P
messages and peer management, BIP-324, compact blocks, mempool policy and packages, fee
estimation, block templates, RPC result shapes and error codes, REST, ZeroMQ, wallet,
PSBT, descriptors, miniscript and AssumeUTXO.

Some tests pin known gaps: their names say `MISSING`, `PARTIAL` or `BUG-<n>`, and they
pass while the gap is present. Read the test before treating a pass as "this matches
Core".

Executables declared in `test/dune` with `(executable …)` rather than `(test …)` are not
part of `dune test`; they need extra input (block dumps) or run for a long time. Their
comments in `test/dune` say how to run them.

## Known limitations

- The from-genesis result above comes from 48 ranges on more than one commit, not from
  one uninterrupted run of one binary.
- AssumeUTXO (`loadtxoutset`, `--import-utxo`) writes the snapshot into the node's only
  chainstate. Nothing re-validates the chain from genesis up to the snapshot afterwards,
  and `getchainstates` always reports a single chainstate.
- No signet. `--network=testnet` is testnet4, on testnet3's default ports (18333/18332).
- Several Core RPC methods are missing, including `bumpfee`, `sendmany`, `sendall`,
  `listsinceblock` and `getrawchangeaddress`; see [rpc.md](rpc.md#known-differences-from-core).
- The fee estimator is simpler than Core's, so `estimatesmartfee` can differ.
- The default RPC user and password (`camlcoin`/`camlcoin`) are accepted. Set your own,
  or use the cookie, if the RPC port is reachable by others.
- The Prometheus metrics port (9332) listens on all interfaces.
- `config.example.toml` and the `Dockerfile` are out of date: the first is not in the
  format camlcoin reads, and the second passes a network name camlcoin rejects.
- Memory use on mainnet is high (OCaml heap plus the UTXO cache); give it 32 GB or more.
- The wallet has not been audited. Do not use it with real funds.
