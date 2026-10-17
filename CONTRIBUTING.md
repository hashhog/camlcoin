# Contributing to camlcoin

## Build and test

See [docs/building.md](docs/building.md) for the toolchain and system libraries. Then:

```bash
opam install . --deps-only --with-test -y
dune build
dune test
```

`dune test` must pass before a pull request is merged. It needs no network and no
running node.

New test files go in `test/` and must be added to `test/dune`: either to the `names` list
of the main `(tests …)` stanza or as their own `(test …)` stanza. A file that is only
declared as an `(executable …)` does not run under `dune test`. Use Alcotest, like the
rest of the suite.

Format new OCaml with `ocamlformat` (the repository has an `.ocamlformat`); do not
reformat code your change does not otherwise touch.

## Pull requests

- One change per pull request, against `master`.
- Every behaviour change comes with a test that fails before the change and passes after
  it. If an existing test asserts the old behaviour, change that test in the same pull
  request and say why.
- Do not delete or disable a test to make the suite pass.
- Update `docs/` when you change a flag, a config key or an RPC method.

## Commit messages

Conventional-commit prefixes: `fix:`, `feat:`, `perf:`, `refactor:`, `test:`, `docs:`,
`build:`, `ci:`. The subject says what changed; the body says why, and for a fix, how it
was found and how the test reproduces it.

## Consensus changes

camlcoin must accept exactly the blocks and transactions Bitcoin Core accepts. A change to
block, transaction or script validation, the UTXO set, or chain selection needs evidence
of Core equivalence in the pull request: the Core source it follows (file and function), a
test on a case where the old code and Core disagreed, and the result of Core's script and
sighash vectors (`test/test_script_vectors.ml`, `test/test_sighash_vectors.ml`) or an
equivalent regtest comparison against a Core node. Also state what could make a valid
block invalid, or an invalid block valid, with your change, and which test covers that.
