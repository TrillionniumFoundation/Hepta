# Experimental runtime UTF-8 library

The [P12 blocker ledger](BLOCKERS.md) still calls for a production standard
library. [`hepta_utf8` 0.1.0](../stdlib/utf8/hepta.toml) is a bounded source-only
increment: ordinary Hepta functions decode and validate borrowed byte ranges.
There is no compiler intrinsic, foreign call, allocation, implicit import, or
change to the compiler's source/literal validation. P12 remains PARTIAL.

This is repository-local experimental source, not a stable API or a bundled
Python-package resource. Vendor the manifest together with `src/lib.hepta` and
use an explicit local dependency:

```toml
[dependencies]
utf8 = { path = "../vendor/hepta_utf8" }
```

Then `import utf8;`. The [locked frame example](../examples/packages/utf8_scan/src/main.hepta)
scans text inside a byte frame, iterates decoded scalar values and rejects a
truncated final sequence through the actual public CLI:

```sh
python -m hepta run examples/packages/utf8_scan --locked --backend c --json
python -m hepta run examples/packages/utf8_scan --locked --backend rust --json
```

Each selected native compiler is required. Rust uses the repository's pinned
1.90.0 toolchain. Content locks bind bytes; they are not signatures or correctness
certificates. This package is independent of other open standard-library drafts.

## API contract

Both functions take `input: read [u8], start: usize, end: usize`, with an explicit
half-open byte range `[start, end)`. Bytes before `start` and at/after `end` are
ignored and may be malformed. Neither function mutates any input byte.

- `decode_next(...) -> Decoded { scalar: u32, next: usize, ok: bool }` decodes
  **one** scalar at `start`. Success returns its Unicode scalar value and the
  absolute index immediately after that scalar. Trailing bytes need not be
  valid. Invalid bounds, an empty range, malformed input or a truncated first
  scalar return `scalar = 0`, `next = start`, `ok = false`. NUL is a successful
  scalar value zero, so callers must inspect `ok`.
- `validate(...) -> Validation { scalars: usize, error: usize, ok: bool }` scans
  the entire range. Success returns the count of Unicode scalars and `error =
  end`, including success with count zero for an empty valid range. On malformed
  or truncated input, `scalars` counts the valid prefix and `error` is the absolute
  index of the **lead byte of the first invalid sequence**, not the offending
  continuation byte. Invalid bounds return `scalars = 0`, `error = start`,
  `ok = false` without indexing.

Valid bounds satisfy `start <= end <= len(input)`. Both functions reject invalid
bounds before reading. Multi-byte branches first require enough bytes in
`end - start`, then check every continuation byte and the E0/ED/F0/F4 restrictions.
Only canonical UTF-8 encodings of Unicode scalar values U+0000–U+10FFFF excluding
U+D800–U+DFFF are accepted. Overlong forms, lone continuation bytes, surrogates,
values above U+10FFFF and obsolete five/six-byte forms fail.

BOM U+FEFF, NUL and Unicode noncharacters are accepted as ordinary scalar values.
No replacement character is inserted. The API does not normalize, strip a BOM,
reject application-specific control characters, count grapheme clusters, or
perform case folding. Combining marks and emoji joiners each count as scalars.
This is not a Unicode property database, string container, transcoder or streaming
state machine. A chunk ending inside a scalar fails; a caller must preserve the
unfinished bytes and choose a new complete range explicitly.

## Resource and arithmetic boundaries

The decoder reads at most four bytes per call and uses constant auxiliary space.
The validator advances by one to four bytes on each successful iteration. The
count cannot exceed the consumed byte count; validated bounds ensure every
index addition stays at or below `end`. There is no recursion or lookup table.

Both functions declare zero heap allocations, no blocking, no suspension and no
spawning, with conservative `panic` effects for the checker's arithmetic/indexing
rules. No `write` or `unsafe` effect is required. Those declarations do not prove
machine-code panic freedom, a process-wide memory/CPU quota or concurrent foreign
memory safety. Finite native tests do not constitute a formal refinement proof.

The common public-consumer C profile cannot create zero-sized backing arrays.
Its empty-range tests use nonempty backing arrays. The separate C adapter oracle
also exercises true zero-length native views; that is not public ABI qualification.
Huge valid slices are not allocated for tests; overflow safety at those sizes is
an algebraic argument, while `usize`-maximum invalid bounds are executed.

## Reproducible qualification

```sh
HEPTA_UTF8_BACKEND=c python -m unittest discover -s tests -p test_stdlib_utf8.py -v
HEPTA_UTF8_BACKEND=rust python -m unittest discover -s tests -p test_stdlib_utf8.py -v
python tools/stdlib_utf8_oracle.py
```

The 12-method public suite executes both optimization levels and requires the
selected compiler without optional native skips. C uses UBSan. Python's strict
UTF-8 decoder independently supplies scalar values, valid-prefix lengths and
error positions. The suite covers all single bytes, scalar and malformed sequence
boundaries, truncated ranges, arbitrary bytes, nonzero offsets, repeated decoding,
all subranges of a mixed-width string, invalid bounds, complete input preservation,
resource/effect/type refusals, both frontend lowerings, relocated/stale package
locks and the checked-in example through a real CLI subprocess. Generated source
is batched to bound translation-unit size without dropping cases.

The independently written supplemental oracle exhausts every Unicode scalar and
all one/two-byte inputs, adds malformed three/four-byte boundary classes, seeded
arbitrary inputs/ranges and every subrange of mixed valid buffers. It drives the
actual generated C library through a **compiler-private ctypes adapter**, at O0
and O3 with UBSan. This is not a supported ABI, native Rust result or a substitute
for the public-consumer tests. The oracle records exact library/tool identities
and counts. Its explicit 64-bit host requirement matches this C backend's profile.

Rust-selected runs also build a native `no_std` object. A C-selected run only
checks Rust/no_std frontend emission; that is not a native Rust pass. Read-only
exact-head CI selects actual C and pinned Rust on Linux x86-64/ARM64 with Python
3.11/3.13. Inspect hosted results for the published commit separately. Full-project,
production-library, formal, performance and release qualification remain open.
