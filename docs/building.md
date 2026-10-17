# Building camlcoin

## Toolchain

- OCaml 5 (tested with 5.3.0). The code uses OCaml 5 domains, so OCaml 4.x does not
  build it, although `camlcoin.opam` still says `>= 4.14.0`.
- opam 2 and dune 3 (dune is installed by opam with the other dependencies).
- A C and C++ compiler (`build-essential`): the C stubs in `lib/*_stubs.c` and the
  vendored libsecp256k1 in `vendor/secp256k1` are compiled by dune.

## System libraries

The library links `-lcrypto -lrocksdb -l:libzmq.so.5 -lstdc++` (`lib/dune`); the opam
packages `zarith` and `ctypes` need GMP and libffi. On Debian 13 or Ubuntu 24.04:

```bash
sudo apt-get install -y build-essential git pkg-config opam ocaml librocksdb-dev libssl-dev libzmq5 libgmp-dev libffi-dev
```

| Package | Used for |
|---|---|
| `librocksdb-dev` | chainstate, UTXO set and indexes |
| `libssl-dev` | `libcrypto` (hashing in the C stubs) |
| `libzmq5` | ZeroMQ notifications (linked as `libzmq.so.5`; the `-dev` package also works) |
| `libgmp-dev` | `zarith` (big integers) |
| `libffi-dev` | `ctypes-foreign` |

## OCaml dependencies

If your distribution's OCaml is 5.x (Debian 13 ships 5.3.0), use it as the opam
compiler. From the repository root:

```bash
opam init -y --compiler=ocaml-system
eval $(opam env)
opam install . --deps-only --with-test -y
```

If it is older, create an opam switch with OCaml 5.3.0 instead (`opam switch create`,
see opam's documentation) and run the `opam install` line in it.

The dependencies are declared in `dune-project` (`camlcoin.opam` is generated from it).
`--with-test` adds `alcotest` and `qcheck`, which `dune test` needs.

## Build

```bash
dune build
./_build/default/bin/main.exe --version
```

`dune build` builds the node (`_build/default/bin/main.exe`), the test executables, and
three small helper programs: `repair/` (an offline height-index repair tool),
`phaseb-shim/` (a script-verification shim used by cross-implementation test harnesses)
and `waveb-boundary-harness/` (needs fixtures outside this repository). C compiler warnings from the vendored libsecp256k1 are
expected.

There are no build variants or optional features: everything (wallet, REST, ZeroMQ,
indexes) is compiled in and switched on or off at run time with flags (see
[running.md](running.md)).

## Docker

The `Dockerfile` in the repository is not maintained: its default command passes
`--network=testnet4`, which camlcoin does not accept (use `--network=testnet`). Build from
source as above.

## Reproducible builds

There is no reproducible-build recipe yet. To check which source a binary came from,
build the same commit with the same OCaml version and opam package versions
(`opam list --installed` records them) and compare.
