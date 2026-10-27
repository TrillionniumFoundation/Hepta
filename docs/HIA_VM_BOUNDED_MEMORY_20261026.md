# HIA interpreter bounded host scratch (P5 resource efficiency)

The existing HIA Core verifier, Owner/Loan lifetimes, memory trap semantics,
and LLVM backend remain unchanged. Only the Python interpreter's host
implementation of \`buffer.fill\`, \`buffer.fill_range\` and overlapping
\`buffer.move_within\` is replaced by \`hepta.hia_bounded_memory\`.

Previously each such operation could materialize an O(request length)
temporary Python bytearray/bytes object in addition to the HIA Owner.
The helper uses **at most 4096 bytes per copied temporary block** and the
fixed-size fill pattern, regardless of request size. For overlaps it walks
from the end only when destination falls strictly inside the source range;
otherwise it walks forward. Bounds are checked before mutation, and zero
count never forms a pointer or byte slice.

This is a host-interpreter allocation improvement, **not** a claim of bounded
process RSS, no Python runtime allocations, or source/native compiler
refinement. LLVM still uses actual native memset/memmove. The helper's
logic is intentionally separate from Core type/borrow checking and cannot
mint an owner, weaken a loan or override an existing validation result.

## Executed local deterministic differential

On Python 3.13.5 the source-identical helper and test file passed
\`python -m unittest tests.test_hia_bounded_memory -v\`: **4/4**, with 600
seeded independent reference comparisons of overlap, fill, edge widths,
size zero, error-before-mutation and lengths crossing 4096. That qualifies
the bounded Python byte manipulation, not the complete HIA interpreter
and not native machine-code equivalence.

## Independent native libc oracle addendum

The exact revised Python 3.13.5 helper/test files additionally executed
1,000 seeded, paired byte-buffer cases against the host Linux libc
`memmove` and `memset` through `ctypes` (2,000 native comparisons).
All outcomes matched, and all **5/5** unit methods passed. This validates
the interpreter helper's concrete byte behavior against libc on this host,
NOT the Hepta LLVM emitter or source-to-native refinement.

## Exact-source acceptance still required

\`\`\`sh
python -m unittest tests.test_hia_bounded_memory tests.test_hia_program \
  tests.test_hia_bulk_memory tests.test_hia_overlap_move \
  tests.test_hia_range_fill_v6 tests.test_hia_program_llvm -v
\`\`\`

Real CPU/RSS/long-running p99, formal compiler refinement and physical/GPU
resource qualification are still open. \`whole_project_blockers_closed=false\`.
