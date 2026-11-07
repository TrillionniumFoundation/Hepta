# Experimental slice ordering library

The source-only `hepta_ordering` local package is an incremental P12 standard
library building block. Version `0.1.0` is experimental, not a stable API or a
production-library qualification. No compiler intrinsic, backend change,
external dependency, unsafe operation or foreign implementation is involved.
It is repository-local source, not bundled with the Python distribution.

## Use

Add a local dependency pointing to `stdlib/ordering`:

```toml
[dependencies]
order = { path = "../../stdlib/ordering" }
```

The path is relative to the consuming package. Import `order`, then call one
of six functions. Both `i32` and `u64` have the same API:

- `sort_i32(values: mut [i32], start: usize, end: usize) -> bool`
- `lower_bound_i32(values: read [i32], start: usize, end: usize, needle: i32) -> SearchIndex`
- `upper_bound_i32(values: read [i32], start: usize, end: usize, needle: i32) -> SearchIndex`

Replace `i32` with `u64` for the unsigned variants. `SearchIndex` has
`index: usize` and `ok: bool` fields. The private sift helpers are not API.

Every range is half-open `[start, end)`, and valid exactly when
`start <= end <= len(values)`. Valid empty ranges, including one at the slice's
end, are supported. Invalid ranges return `false` from sort, or
`SearchIndex { index: 0, ok: false }` from search, without indexing or mutation.
Always inspect `ok`; zero is a valid successful insertion index too.

Sorting orders only the selected range in nondecreasing order and leaves every
other element unchanged. It returns true for every valid range, including an
empty or already sorted one. It uses iterative heapsort, with worst-case
O(n log n) comparisons, O(1) auxiliary storage and no recursive calls. It is
not a stable sort. These are algorithm properties, not measured performance
or a formal verification of the emitted machine code.

Search **requires the selected range already to be nondecreasing**. It does
not validate sortedness. Lower bound returns the first index whose value is
at least `needle`; upper bound returns the first whose value is greater.
Either can return `end`, and both return `start` for an empty range. Returned
indices are absolute slice indices, not offsets into the selected range.
`ok` certifies valid bounds only, not whether the needle exists or whether
the input was sorted. Do not index a search result without first checking it
is below `end`. On sorted input, `upper.index - lower.index` is the duplicate
count. Both searches use O(log n) comparisons and O(1) auxiliary storage.

The functions declare conservative `panic` effects because indexing and
integer arithmetic are checked. Sort additionally declares `write`. Every
function declares zero modeled heap allocations, no blocking, suspension or
spawning. These frontend contracts do not establish whole-process memory,
CPU/time bounds, foreign behavior or a language soundness proof.

## Arithmetic and mutation boundaries

Range checks happen before subtraction or indexing. For accepted bounds,
`count = end - start` and every heap-relative index is below `count`. The
sift loop enters only when `root < count / 2`, bounding `2 * root + 1` and
its possible right child without multiplying an arbitrary user index.
The binary-search midpoint is `low + (high - low) / 2`, not `(low + high) / 2`.
Sort compares values without subtracting them, preserving signed and unsigned
extrema. No `usize`-maximum invalid bound is added to another index.

The checked-in [example](../examples/ordering/src/main.hepta) sorts a middle
range and counts duplicate sensor values while retaining both sentinels:

```sh
python -m hepta run examples/ordering --backend c --locked --json
python -m hepta run examples/ordering --backend rust --locked --json
```

Its manifest uses the normal loader and committed content lock. No test
helper substitutes for the public CLI in that example.

## Reproducible validation

```sh
python -m unittest discover -s tests -p test_stdlib_ordering.py -v
HEPTA_ORDERING_BACKEND=rust python -m unittest discover -s tests -p test_stdlib_ordering.py -v
python tests/stdlib_ordering_oracle.py --output ordering-oracle.json
```

The selected native compiler is mandatory; missing tools fail, never skip.
The 12-method suite runs actual locked-package executables at both -O0 and
-O3. The C lane enables UBSan and requires empty stderr. Expectations are
computed independently with Python `sorted`, `bisect_left` and `bisect_right`:

- 112 sort vectors across both types include fixed patterns, extrema,
  duplicate-heavy arrays, random interior ranges and 256/257-element heaps.
  Every element is compared, including all elements outside the range.
- 960 independent search calls use pre-sorted Python vectors, excluded
  unsorted sentinels, duplicates, extreme needles and empty ranges. They do
  not depend on this library's sort producing their input.
- 22 boundary cases exercise all three APIs on empty/singleton/invalid ranges,
  including `usize` maximum. Rejected sorts preserve the complete array.
- Repeated sort, consumer type/mode/mutability/effect refusals, source resource
  contracts, both frontend lowerings, a relocatable/stale content lock and
  the actual example CLI are covered. Rust lanes also build a no_std object.

The separately written `tests/stdlib_ordering_oracle.py` executes the library's
real generated C through a compiler-private ctypes test adapter. At each of
-O0 and -O3 with UBSan, it checks 28,475 valid sorts, 18,336 invalid sorts,
498,452 search calls and 28,475 idempotence checks against Python oracles. The
corpus includes every range of exhaustive length-0–5 ternary arrays, extrema,
random arrays up to 257 elements, complete exterior preservation and invalid
`SIZE_MAX` bounds. This adapter covers zero-length native views without
constructing Hepta zero-sized arrays. It is not a supported foreign ABI, public
Hepta-consumer coverage, Rust evidence or a proof about enormous valid slices.
Its deterministic corpus is identical at both optimization levels. Output
artifacts use a temporary directory; `--output` optionally retains the report.

The exact-PR-head read-only workflow runs the suite on actual Linux x86-64
and ARM64, with C and pinned Rust 1.90.0. C jobs also run the independent
adapter oracle at both optimization levels. Local C execution is not a native
Rust or hosted-CI result. Both lowerings and no_std emission can be checked
without Rust; that is explicitly frontend-only evidence.

The shared C subset does not support zero-length fixed arrays, so empty
ranges are exercised with nonempty backing arrays. True zero-length backing
arrays are not part of the public-consumer corpus; only the separate C adapter
exercises zero-length native views. Custom comparators, generic or
resource-owning elements, stable sorting, parallel sorting, other scalar
types, semantic/API compatibility, distribution/signing and overall P12
closure remain open. No broad native, proof, performance or release gate is
claimed by this focused library qualification.

### Retained local validation history

The initial unbatched consumer suite had 11 passing methods and one failed
method because a GCC subprocess reported `Killed signal terminated program
cc1` while compiling the large generated i32 corpus. The operating-system
cause was not established. A second unbatched run passed all 12 methods. The
final suite splits generated cases into bounded translation units, preserving
every vector and assertion and both optimization levels; this bounds per-build
input size without changing library code or suppressing failures. The final
12-method suite passes on Python 3.12.14 and 3.13.5 with GCC 14.2.0. These later
results do not reclassify the initial failure. Rust was unavailable locally;
native Rust and exact-head hosted outcomes remain separate pending evidence.
