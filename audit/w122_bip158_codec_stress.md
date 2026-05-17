# W122: BIP-158 GCS Codec Stress-Vector Audit (camlcoin)

**Wave**: W122 (codec stress sub-audit; follow-on to W121 #BUG-12 +
haskoin W121 addendum BUG-16)
**Impl**: camlcoin (OCaml)
**Date**: 2026-05-17
**Status**: **VERIFIED CLEAN** (no bug found)
**Tests added**: 41 (test/test_w122_gcs_codec_stress.ml)
**Code under audit**: `lib/block_index.ml` lines 111-257 (GolombRice
writer/reader); 269-435 (GCS filter build/decode/match).

## Motivation

Per haskoin commit `4a2de0f` (W121 addendum BUG-16 P0 fix), haskoin's
`bitWriterWrite` silently truncated bits when `numBits + bufferBits > 64`,
corrupting Golomb-Rice streams whenever a quotient ≥ 64 followed a
non-byte-aligned prior write.  The literal failing trace: seven small
values that left `bwBits=5`, then a value with `q=8191` (`0xFFFFFFFF`
at P=19) decoded as `31457264` instead.

The exposed pre-requisite for the bug is a Word64-wide bit-packing
buffer that the encoder shifts past during a single multi-bit write.
Core itself uses an 8-bit `m_buffer` (`streams.h` BitStreamWriter) and
splits each `Write(data, nbits)` call into at most one byte-completing
write per loop iteration (`bits = std::min(8 - m_offset, nbits)`).
GolombRiceEncode in `util/golombrice.h` further caps each `Write(~0ULL,
nbits)` call to `nbits ≤ 64`, so Core is structurally immune.

Core's reference vector file `src/test/data/blockfilters.json` covers
heights `[0, 2, 3, 15007, 49291, 180480, 926485, 987876, 1263442,
1414221]`.  None of these produce a Golomb-Rice quotient ≥ 64 at the
basic-filter parameter P=19, so they cannot catch the haskoin failure
mode in any port.  camlcoin's `test_block_index.ml` test_bip158_vector_*
suite passes 4 of these vectors byte-for-byte; the codec is byte-aligned
on those inputs and the bug would not appear even if present.

This audit re-runs the codec against the exact failure-mode space
(quotients 64/65/100/200/1000/8191 + non-aligned starts + mixed
streams) and asserts both the round-trip identity and the architectural
preconditions for immunity.

## Verdict

**VERIFIED CLEAN**.  camlcoin's GolombRice writer is byte-buffered:

```ocaml
type bit_writer = {
  mutable buffer : int;      (* Current byte being assembled, MSB-first *)
  mutable offset : int;      (* Number of high-order bits already written (0-8) *)
  ...
}
```

The inner `write_bits` loop bounds each iteration to `take = min (8 -
offset) nbits ≤ 8`, with the high-order bits extracted via
`Int64.shift_right_logical value (nbits - take)`.  The shift amount is
always in `[0, 56]` (since `nbits - take ≥ 64 - 8 = 56` at the
high-bit end, and decreases by `take ≤ 8` per iteration), so no
out-of-range OCaml Int64 shifts occur.

The encoder `GolombRice.encode` further caps each unary unit write to
64 bits via `let nbits = min remaining 64`, so even adversarial
quotients up to OCaml's `max_int` (2^62) are serialised correctly one
64-bit unary span at a time.

The haskoin BUG-16 class is structurally absent: there is no Word64
buffer to overflow.  41 stress tests added against the exact failure
corners pass on the first run.  No code changes required.

## Stress matrix

| Group | Coverage | Status |
|-------|----------|--------|
| S1 unary size invariant | q ∈ {0, 1, 8, 63, 64, 65, 100, 200, 1000} | PASS (9/9) |
| S2 unaligned-offset unary | pad ∈ {1, 3, 5, 7} × q ∈ {64, 65, 100} | PASS (8/8) |
| S3 single-value round trip | q ∈ {0, 1, 63, 64, 65, 100, 200, 1000, 8191, 65535} | PASS (10/10) |
| S4 haskoin BUG-16 exact trace | 7 small + offset-5 pad + q=8191 at P=19 | PASS (1/1) |
| S5 mixed-quotient stream | {q=0, 30, 65, 120} encoded → decoded identity | PASS (1/1) |
| S6 high-P stress | P=32 with values up to 2^47 | PASS (1/1) |
| S7 byte-boundary sweep | offset ∈ {0..7} × q=64 | PASS (8/8) |
| S8 Core regression | BIP-158 blockfilters.json genesis row | PASS (1/1) |
| AS1 audit-status | source-level guard against future Word64 refactor | PASS (1/1) |
| AS2 audit-status | encode-loop bounds writes to ≤64 bits | PASS (1/1) |

Total **41/41 pass**.  Run with:

```bash
cd /home/work/hashhog/camlcoin
dune build
_build/default/test/test_w122_gcs_codec_stress.exe
```

## Findings

### Why camlcoin is immune to haskoin BUG-16

Three architectural properties combine:

1. **8-bit buffer width** (line 117-122): the writer's `buffer` field
   is a regular OCaml `int`, holding at most one byte's worth of
   in-flight bits.  There is no Word64 register that could overflow
   when shifting a multi-bit value past the high end.

2. **Byte-bounded inner loop** (line 146-167): `write_bits` extracts
   at most `8 - offset ≤ 8` bits per iteration.  The extraction
   formula
   ```ocaml
   let bits = Int64.(to_int (logand
     (shift_right_logical !value (!nbits - take))
     (of_int ((1 lsl take) - 1)))) in
   ```
   uses `take ≤ 8`, so `1 lsl take ≤ 256` (safe in OCaml's 63-bit
   `int`), and `shift_right_logical` of an `Int64` by `nbits - take`
   (with `nbits ≤ 64` and `take ≥ 1`) is always in the legal `[0,
   63]` range.

3. **64-bit cap in `encode`** (line 189-194): the unary-write fast path
   splits `q` into chunks of at most 64 bits via `let nbits = min
   remaining 64`.  Even an absurdly large quotient (e.g. `q ≈ 2^62`)
   serialises correctly as a sequence of 64-bit-all-ones spans
   terminated by a single 0 bit.

These properties match Core's `BitStreamWriter` and `GolombRiceEncode`
contract exactly.  Forward-regression guards `AS1` and `AS2` in the
test file pin the source-level shape (no `mutable buffer : int64`, no
`Word64 buffer` comment, presence of `let nbits = min remaining 64`),
so any future "performance refactor" that introduces a wider register
fails first inside the audit suite.

### Subordinate observations

- **Decoder symmetry**: `read_bits` (line 220-241) mirrors the writer's
  byte-buffered semantics with no Word64 accumulator.  The `result`
  variable is an `Int64` but each iteration shifts it left by `take ≤
  8` before OR'ing the next chunk in, so the cumulative shift width is
  bounded by the total `nbits` argument (≤ 64).

- **W121 BUG-12 is the related-but-distinct latent risk** that the
  encoder converts `q` from `Int64` to `int` for the loop counter
  (`let q_int = Int64.to_int q`).  On a 32-bit OCaml runtime (rare;
  bytecode-only), OCaml's `int` is 31 bits and a quotient `> 2^30`
  wraps silently.  On 64-bit (the only supported camlcoin build),
  `int` is 63 bits and the wrap point is `q > 2^62`, well beyond any
  practical input.  W121's `bug12_quotient_truncation` test already
  documents this and we keep that test as-is.

- **`decode` uses `int` for `q`** (line 250): same 32-bit-runtime
  caveat as BUG-12, structurally bounded by `Int64.shift_left (of_int
  !q) p` afterward.  Practical Golomb-Rice decoding terminates well
  before `q` exceeds reasonable bounds because the source stream is
  finite, but a maliciously-crafted decoder input (sequence of 1-bits
  exceeding `max_int`) could spin a Long Time.  This is a DoS-class
  concern flagged for a future "BIP-158 decoder hardening" wave; out
  of scope for W122 (codec correctness only).

- **`match_element` / `match_any` early-exit** (line 387-388): the
  early-exit `if Int64.compare !value query > 0 then i := filter.n`
  uses `Int64.compare`, which handles values up to `Int64.max_int =
  2^63 - 1`.  The hash query range is `[0, N*M)` where `N ≤
  ~2^25` and `M = 784931 ≈ 2^20`, so `N*M ≤ 2^45` and the comparison
  is unambiguous.

## Cross-impl context

Per memory index: this is the 1st of 10 W122 codec-stress audits.
haskoin (the trigger) flipped its `xit` test to `it` and added 4
FIX-69 stress tests covering distinct cross-boundary corners.  camlcoin
is the second impl to exercise these vectors and the first to verify
the byte-buffered architecture is structurally immune.

Expected outcomes for the remaining 8 impls vary by buffer width:

- **Word64-style** packers (haskoin-style, plus potentially nimrod /
  rustoshi / blockbrew if they use a u64 register): vulnerable to
  haskoin BUG-16; audit may find similar truncations.
- **Byte-buffered** (Core-style, camlcoin, hotbuns probably, lunarblock
  probably): structurally immune; audit verifies architectural
  pre-conditions.

This audit's `AS1`/`AS2` source-level guards demonstrate the cleanest
form of the "structural immunity" pattern and are reusable as a
template by sister audits.

## Files

- Audit doc: `audit/w122_bip158_codec_stress.md` (this file)
- Test file: `test/test_w122_gcs_codec_stress.ml` (41 tests, 484 LOC)
- dune declaration: `test/dune` (added `test_w122_gcs_codec_stress`)

## References

- BIP-158 §"Set Construction" + §"Encoding"
- bitcoin-core/src/util/golombrice.h `GolombRiceEncode`
- bitcoin-core/src/streams.h `BitStreamWriter::Write`
- bitcoin-core/src/blockfilter.{cpp,h}
- bitcoin-core/src/test/blockfilter_tests.cpp `gcsfilter_test`
- bitcoin-core/src/test/data/blockfilters.json
- haskoin commit `4a2de0f` (FIX-69 BUG-16 P0 fix)
- camlcoin commit `c33ce47` (W121 audit, W121 BUG-12 latent flag)
