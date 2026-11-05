# Experimental source-only standard library

The [P12 ledger](BLOCKERS.md) calls for a production standard library. The first
bounded module here is `hepta_bytes` version `0.1.0`: ordinary Hepta source under
[`stdlib/bytes`](../stdlib/bytes/hepta.toml), loaded through the existing local
package architecture. It adds no compiler intrinsic, runtime, foreign call,
registry, build script, or implicit import. P12 remains PARTIAL.

This is a repository-local prototype, not a stable 1.0 API or an installed
Python-package resource. Keep its manifest and source together when vendoring it,
and use a local dependency path. Bundled distribution, broader APIs, compatibility
and platform qualification remain open.

## Byte codecs

Add a dependency to the application's `hepta.toml` (relative to that manifest):

```toml
[dependencies]
bytes = { path = "../vendor/hepta_bytes" }
```

Then `import bytes;`. The [packet example](../examples/packages/byte_packet/src/main.hepta)
uses the checkout's library with a portable content lock:

```sh
python -m hepta run examples/packages/byte_packet --locked --backend c --json
python -m hepta run examples/packages/byte_packet --locked --backend rust --json
```

The selected native compiler is required. The Rust path requires the repository's
pinned rustc 1.90.0. Content locks bind the source bytes; they do not sign authorship
or establish functional correctness.

For each width `16`, `32`, `64` and order `le` (little endian), `be` (big endian):

- `read_u16_le(input: read [u8], offset: usize) -> ReadU16` reads two bytes.
  Other widths return `ReadU32`/`ReadU64` and read four/eight bytes.
- `ReadU16 { value: u16, ok: bool }` has concrete width-matched counterparts.
  A failed read returns `ok = false` and `value = 0`; zero is also a valid value,
  so callers must inspect `ok`.
- `write_u16_le(output: mut [u8], offset: usize, value: u16) -> bool` writes two
  bytes. Other widths accept matching unsigned types and write four/eight bytes.
  A failed write returns false and leaves **every** destination byte unchanged.
  Success changes only the requested width at the offset.

Offsets are byte offsets. No alignment or host byte-order assumption applies.
Both operations first reject offsets beyond the slice length, then compare width
against `length - offset`. They never form an unchecked `offset + width`, and
perform no indexing or mutation until both bounds checks succeed. Writing uses
explicit shifts and narrowing casts; reading widens bytes before shifting.

```hepta
let mut data: [u8; 4] = [0, 0, 0, 0];
let stored = bytes::write_u32_be(mut data, 0, 16909060);
let decoded = bytes::read_u32_be(read data, 0);
// stored is true; data is [1, 2, 3, 4]; decoded.ok is true.
```

Read functions declare `panic`; writers declare `panic, write`. The checker
conservatively tracks arithmetic, indexing and shifts even after these explicit
guards. All twelve functions declare zero heap allocation, no blocking, no
suspension and no spawning through the existing resource clauses. This is not a
process-wide memory bound, formal panic-freedom proof, or signal/crash-atomic
transaction guarantee. There are no unsafe operations or foreign assumptions.

Concrete result records deliberately avoid generic/ADT requirements, keeping this
module inside both existing backend subsets. It does not provide signed/floating
codecs, variable-length integers, cursors, I/O, a general serialization format, or
the rest of a production standard library.

## Reproducible qualification

```sh
HEPTA_BYTES_BACKEND=c python -m unittest discover -s tests -p test_stdlib_bytes.py -v
HEPTA_BYTES_BACKEND=rust python -m unittest discover -s tests -p test_stdlib_bytes.py -v
HEPTA_BYTES_BACKEND=c python tests/stdlib_bytes_boundary_oracle.py
HEPTA_BYTES_BACKEND=rust python tests/stdlib_bytes_boundary_oracle.py
```

Each run requires its selected compiler and runs 13 methods with no optional native
fallback. The six oracle methods compare all output bytes with Python `to_bytes`
and independently read arbitrary bytes with `from_bytes`: 24 written values and
24 independent reads per width/order, including zero, maximum, top bit, asymmetric
and alternating bytes, and seeded samples. They do not rely on round trips alone.

Three bounds methods cover short nonempty slices, aligned and unaligned offsets,
exact last-valid offsets, one-byte overruns, offsets beyond the end, and the
qualified 64-bit `usize` maximum. Every destination byte is checked after writes,
including rejected writes. Each native corpus executes at both optimization levels;
C additionally uses undefined-behavior sanitization. The other methods check
invalid consumers, effects/resource declarations, package-lock relocation and
staleness, and the checked-in example through the real public CLI.

The separately generated 136-case boundary oracle covers every nonempty short
length and offsets near unsigned overflow, with high-bit write values and complete
byte comparisons. It reuses the locked-package native execution fixture, but
constructs its cases and expected values independently of the primary corpus.

The Rust selection additionally builds a native `no_std` object. Without rustc,
the C selection verifies Rust/no_std lowering only; this is explicitly frontend
evidence, not a native Rust pass. Empty fixed arrays are outside the shared C
profile, so the shared corpus uses nonempty arrays. The read-only exact-head CI
matrix selects both backends on Linux x86-64 and ARM64. Its current results must
be checked separately; local success does not assert hosted success.

Finite tests do not close the full project, language soundness, native platform,
performance, production-library, or release-authority gates.
