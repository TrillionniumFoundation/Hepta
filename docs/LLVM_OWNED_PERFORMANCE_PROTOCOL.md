# Frozen owned-byte native qualification, version 1

This protocol is committed before the first performance measurement. Its
producer is tools/qualify_llvm_owned.py. There is no command-line option to
change workloads, sample counts, ordering, compilation flags or thresholds.
Unit tests explicitly simulate timings when exercising report validation;
those tests do not run the timed driver or produce a qualification receipt.

## Scope and baselines

All application logic on the LLVM path starts as the existing Hepta source in
examples/llvm_owned/owned.hepta and qualification.hepta. Its typed AST and
independently checked resource graph determine the LLVM. The native compiler
replays that exact source origin before emitting each object or shared library.
The retained report binds the precise generic specializations, semantic and
resource identities, emitted LLVM and compiler tree. The Rust metadata gate
remains required; native LLVM code generation does not invoke generated Rust
or C code or fall back to either backend.

The first baseline is the identical Hepta source lowered to Rust 1.90.0.
The second is the independent handwritten Rust source in reference.rs. It
uses safe Vec and slice operations, fallible exact reservation, initialization,
ownership transfer, iteration and explicit drop. This is a useful concrete
Rust implementation, not proof that it is the fastest possible Rust program.
Both Rust paths use optimization level 3, checked arithmetic, panic abort and
one codegen unit. LLVM uses Clang 20 or later, -O3, and explicit corresponding
overflow and bounds guards. The independent C backend with GCC and UBSan
participates in correctness only.

No result from these workloads establishes whole-language performance, general
Rust superiority, a verified compiler refinement, an arbitrary C++ migration
guarantee, stored-lifetime-record LLVM support or cross-target execution.

## Fixed workloads

| Export | Resource and computation | Timed size |
| --- | --- | ---: |
| full_lifecycle | Fallible owner construction, byte initialization, generic move, returned shared slice access, checksum and drop | 4,093 bytes |
| constructor_error | Fallible zeroed allocation followed by explicit constructor rejection and cleanup | 4,093 bytes |
| two_stage | First owner fill, second allocation, borrowed reads and writes, checksum including the zeroed tail, cleanup on success and failure | 4,093 plus 4,110 bytes |

The native C driver dynamically resolves the scalar C export once, warms it
with 8,192 calls, then times 1,048,576 calls for full_lifecycle/two_stage and
8,388,608 calls for constructor_error in an uninterrupted native loop.
No Python or ctypes dispatch is inside the measured region. The seed sequence
is ((call_index modulo 64) * 17 + 13) modulo 97 + 1. The native result checksum
is independently reconstructed from Python byte/integer formulas before timing.
The larger error-path call count was selected before the first measurement:
an optimizer can remove unobserved initialization, leaving a short allocation
and cleanup sequence. Even a 10 nanosecond call would then exceed 50 ms, while
the LLVM path writes at most about 32 GiB if it retains all initialization.
This is an estimate, not an empirical calibration or a guarantee of duration.
The timing includes native dispatch, allocation, initialization, accesses and
cleanup. Allocation elimination performed by an optimizer is permitted and can
affect a baseline; the report does not equate source-level requests with actual
allocator calls in timed kernels.

There are seven groups, three kernels and three timed implementations: all 63
samples are retained. Kernel order rotates by group. Implementation order
rotates by group plus kernel position, and reverses on odd groups. Every
subprocess inherits the lowest permitted logical CPU affinity. This reduces
migration; it does not provide a dedicated CPU or control external host load.
No pilot timings, calibration, outlier deletion, retry or best-run selection
are part of this protocol.

## Acceptance fixed before measurement

Every native sample must last at least 50 milliseconds and at most 30 seconds.
For each kernel/implementation series, median absolute deviation divided by its
median must be at most 5%. A quality violation yields
measurement_inconclusive regardless of favorable speed ratios.

For each kernel and each Rust baseline, form the seven paired LLVM time /
baseline time ratios and take their median. Every kernel ratio must be at most
1.20. The geometric mean of the three kernel ratios must be at most 1.10,
independently against each baseline. A stable result that violates either
threshold is performance_failed. Only complete correctness, resource observation,
measurement quality and both baseline gates produce passed.

## Correctness and failure observations

Before timing, all four libraries execute 196 deterministic vectors each,
covering zero lengths, byte wraparound, ordinary lengths, constructor rejection,
double allocation, early cleanup and impossible capacities. The report records
all cases and reconstructible observation digests: 784 actual native calls.

An additional C observer links the actual LLVM object and wraps malloc, calloc
and free with volatile counters. It executes success, explicit early cleanup,
empty second allocation, actual second-allocation refusal while an earlier
owner is live, and capacity rejection. Its required counts are seven successful
allocations, seven frees, zero live allocations and one injected refusal.

The public LLVM compilation API must reject a rehashed free-deleted module
before invoking native compilation. A separate negative control then explicitly
compiles that altered LLVM outside the production API and executes it. The
observer must fail and report actual remaining live allocations. Optimizers
may remove newly unused allocations after drop deletion; the test requires
every allocation that actually remains to be observed unreleased, rather than
inventing pre-optimization allocation counts.

## Evidence and replay

The JSON receipt retains protocol/input/source/compiler identities; exact LLVM;
Rust, LLVM and C native receipts; separately emitted object and measured shared
library hashes; native driver and observer build commands; toolchain identities;
wall-clock compilation durations; complete finite cases; actual refusal and
negative-control process outputs; every measured process output, elapsed time,
checksum, clock resolution and process peak RSS; paired metrics and host context.
Process peak RSS is recorded, not used as a heap-allocation peak measurement.

Temporary native build products are deleted after their identities and outputs
are retained to fit the constrained build environment. Objects are separate
emissions of the measured sources; only the LLVM object is a link input to the
untimed resource observer. This distinction appears in the report.

Evidence-only hardening after the two recorded attempts retains a failed native
command separately from the complete successful sample rows. A failure during
sampling preserves the already completed sample list and the current failed
sample's command, exit status and bounded stdout/stderr. Timeout, encoding and
output-budget errors additionally retain the available raw bytes as base64
prefixes, byte hashes, total file sizes, retained sizes and explicit truncation
flags. The capture rejection code is distinct from the actual child exit
status; a process that exited zero but exceeded an output/encoding budget is
still rejected. Resource-observer evidence is populated as commands complete,
so a later observer failure does not erase earlier output. Reports carrying a
failed-command or failed-sample marker cannot validate as successful.

These changes affect failure evidence collection only. The frozen protocol,
source, handwritten Rust baseline, driver, work counts, ordering and thresholds
remain identical and are checked against the original committed receipt by
regression tests. Input/compiler hashes distinguish each implementation.

validate_report replays source generation, source identities, finite oracles,
native build bindings, the full sample inventory and all fixed decisions.
Its default requires a pass; require_pass=False permits auditing a complete
failed/inconclusive attempt without admitting it as a release pass. JSON alone
does not authenticate an arbitrary third-party claim of native execution.

Run once from a clean committed checkout, with the pinned native toolchain:

    python3 -m tools.qualify_llvm_owned --output NEW-RECEIPT.json

The first complete receipt must be retained even if it fails. A future protocol
revision must state what concrete validity issue it resolves and preserve this
attempt; changing thresholds to turn the observed outcome into a pass is not a
permitted qualification method.
