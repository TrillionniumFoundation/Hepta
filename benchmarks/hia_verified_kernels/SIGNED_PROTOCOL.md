# Signed scalar protocol, version 1

This protocol compares 33 fixed signed scalar cells against independently
written optimized Rust functions. It is separate from the existing byte-kernel
v6 campaign and its v7 address-layout extension. Those original results and
sources remain unchanged.

## Semantics and transport

The matrix contains the eleven i64 wrapping/checked arithmetic, division,
remainder, negation and shift cells; identity, wrapping addition, checked
addition and arithmetic right shift at each of i8/i16/i32; and wrapping and
checked conversion for five signed/unsigned type pairs. The exact ordered
inventory is in `PROTOCOL_SIGNED_V1.json`.

HIA functions retain their actual signed Core parameter and result types. The
verified foreign ABI accepts two raw 64-bit SysV argument words, interprets the
low bits at the declared width, and sign-extends signed results to a raw return
word. The second argument of unary cells is declared u64 and ignored. No
transport adapters are added to the HIA Core. Rust exports two `u64` arguments
and one `u64` result, with explicit casts implementing the same interpretation.
The C harness calls both entries through the same raw-word function type.

Checked operations use identical success and failure conditions. Division
truncates toward zero; remainder has the dividend's sign. Both reject division
by zero and the signed minimum divided by minus one. Checked shifts validate
the entire normalized signed count before x86 or Rust narrows it; left shift
may discard result bits. Checked casts require the mathematical source value
to fit the target range. Failures call `abort()` in both arms.

## Inputs and functional observations

Each cell has exactly 64 predetermined legal input pairs, including applicable
boundary values and at least 48 seeded rows. Narrow cells retain arbitrary
high bits in their incoming words. A fixed xorshift64* generator and per-cell
seed derivation make every input reproducible. Each cell's JSON input matrix
and little-endian binary triples retain both raw arguments and the independently
calculated expected word.

The 33 cells currently contain 2,112 legal pairs and 78 invalid pairs. Unbounded
Python integer arithmetic computes the reference values and trap conditions;
the Core interpreter must agree before native images are built. The same input
matrix is then checked against both native arms. Every invalid pair executes
in a separate forked child with core dumps disabled, a two-second deadline,
and an exact SIGABRT requirement. Invalid inputs are never timed.

The driver reads the expected library SHA-256, copies exactly those bytes into
a Linux memfd, installs write/grow/shrink/seal locks, and loads that sealed
image. The resolved entry must belong to the exact link map returned for
that sealed handle; an identically named function in a dependency is refused.
Its binding record includes the actual image digest, input and trap digests,
image base, symbol address and offset, current CPU and affinity count. The
original library path cannot substitute different bytes after admission.

## Timing

After all 66 functional cases pass, each implementation/cell pair receives
three warmup batches and 21 measured batches of 1,048,576 calls. Arguments
cycle through all 64 pairs; every return word contributes to a wrapping
checksum. The indirect call, input lookup and checksum loop are present in
both arms. Every batch is checked against the full expected checksum.

The campaign pins one explicitly selected CPU, uses `CLOCK_MONOTONIC_RAW`, and
retains all warmup and measurement rows. The driver reports elapsed integer
nanoseconds; the Python reader derives ns/call and the median using all 21
measurement samples. A fixed shuffle chooses the complete 66-case order.
There are no per-cell retries or substituted samples. Affinity does not grant
exclusive use of the processor.

Rust is compiled as an optimized native-target cdylib with `panic=abort` and
one codegen unit. Each HIA function selects the scalar register backend and
must complete independent final-ELF validation with the fixed 15,000 ms proof
deadline before execution. A proof
failure ends the campaign; it never selects an unverified fallback.

## Running and retained output

From a committed source checkout on Linux x86-64:

```bash
python -B tools/benchmark_hia_verified_signed.py --output /absolute/new/output --cpu 4
```

Use a CPU allowed by that process's affinity. Before scheduling a benchmark on
a shared machine, check its existing owner and workload. Dependencies are GCC
or a compatible C compiler, Rust, GNU ld, the project's pinned Z3, and the
normal HIA Python dependencies.

Two modes support implementation work without producing performance results:

```bash
python -B tools/benchmark_hia_verified_signed.py --output /absolute/new/prepared --prepare-only --allow-dirty
python -B tools/benchmark_hia_verified_signed.py --output /absolute/new/functional --cpu 4 --functional-only --allow-dirty
```

Preparation validates and stores the complete source/input inventory and Core
reference observations. Functional mode additionally builds, proves and
executes all HIA/Rust success and abort controls. `--allow-dirty` is refused for
a timing campaign. A dirty development run is reported with its exact source
hashes and does not establish committed-source performance qualification.
For measurement, every executed source byte is compared with its raw blob in
the declared commit, independently of index flags and replacement objects.
The identified Git executable, checkout/worktree pointer and index identity
are retained and rechecked after the campaign; Git routing overrides are refused.

The output directory retains `RESULT.json`, the protocol, a source snapshot,
all Core programs, legal/trap input files, linked libraries, object/proof
artifacts, original stdout and stderr, command receipts, compiler identities
(including the actual rustc behind a launcher), runtime dependency hashes,
CPU/platform/load information, active `HEPTA_HIA_*_MANIFEST` selectors and a
final file manifest. Compiler and runtime binary identities are checked again
before and after the measurement phase. A failure preserves
completed observations and records its error without declaring completion.

Results characterize these scalar leaves under this calling and input model.
They do not assign a whole-language safety or performance ranking.
