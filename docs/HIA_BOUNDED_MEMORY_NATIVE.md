# HIA ownership of the VM's fill and overlapping move helpers

The explicit selector `HEPTA_HIA_BOUNDED_MEMORY_MANIFEST` makes
`hepta.hia_bounded_memory.fill_bytes` and `move_bytes` enter the compiled
`examples/hia_bootstrap/bounded_memory.hepta` owner. The ordinary VM already
uses these public helpers for `buffer.fill`, `buffer.fill_range` and
`buffer.move_within`; those call sites and their resource/trap accounting are
unchanged. Selected execution does not enter either retained Python body.

HIA owns the complete helper decision: exact-kind refusal, destination/count
range checks, fill-value or source-range checks in their original order,
zero-length admission, and all mutations of the original buffer. HIA's bulk
operations implement the native fill and both directions of overlapping move.
The Python adapter only observes exact object kind, integer sign/bit length/low
bits, buffer address and extent, and renders the HIA-selected exception. It
holds the buffer export and Python GIL for the complete foreign call.

## Preserved domain

The original public domain is exact `bytearray` and exact Python `int` values.
Boolean/integer/buffer subclasses and other objects retain their original
refusal without running foreign conversion, comparison or length hooks. A
fixed 80-byte packet records representation facts for every integer; arbitrary
precision integers do not pass through decimal conversion or truncating
admission. Negative or high-word facts are rejected by HIA, before any write.

There is no new bytearray-size ceiling. All original accepted extents are
representable by the native length ABI. A zero-length fill still validates its
byte value, and a zero-length move still validates both source and destination.
Invalid destination/count precedes invalid fill value or source range exactly
as before. Errors preserve these complete messages:

- `E_HIA_VM_RANGE: invalid owned-byte extent`
- `E_HIA_VM_VALUE: expected u8`

No selected image failure falls back. An absent selector retains the original
reference behavior. An explicitly empty selector, missing manifest or changed
packaged HIA source refuses before a retained owner can run. The installed
resource uses the same source identity as the source-tree component.

## Construction and verification

`tools/generate_hia_bounded_memory.py` reproduces the single `.hepta` source.
The generator does not run in selected helper execution. The immutable original
Python file is retained as `tests/fixtures/bounded_memory_a7710b5.py.txt`; source
tests compare the retained functions' AST with that exact independent fixture.

`tools/build_hia_bounded_memory.py` requires either a matching-current-source
cold report or an explicit `--development` choice. The development label does
not qualify current source. The builder checks the complete native compilation
receipt, compiler/source custody and full captured output before publishing its
manifest. Independent VM observations run before native component construction.

The component tests exercise complete error/message and output-byte comparisons,
all small overlap arrangements, deterministic larger cases, 64 MiB mutation,
ordinary VM resource/trap receipts, missing/drifted sources, and actual isolated
sdist-to-wheel installation. They also run both complete original memory test
modules with the two retained bodies forbidden, including the unchanged libc
comparisons and 4 MiB allocation test's original 64 KiB scratch ceiling.

`tools/qualify_hia_bounded_memory_callers.py` runs six complete original test
modules under the selected HIA owner. The original test IDs and native
Clang/libc callers are retained without filtering. It records planned, started
and stopped IDs, observed native fill/move calls and unchanged source/image
pins. Any skip, expected failure, unexpected success, error or failure refuses
this caller gate. The complete suite's actual compiler subprocess deadlines
remain unchanged.

## Remaining boundaries

This is ownership of the two existing bulk-memory helpers. It does not replace
the complete VM, Python object transport, owner allocation, other byte operations,
Core verifier, compiler seed, loader or installation tooling. Native component
success is not an all-input formal equivalence proof or whole-product
qualification. The independent Python reference remains needed until those
larger owners and final cutover are qualified.
