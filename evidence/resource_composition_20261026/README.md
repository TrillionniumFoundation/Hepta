# Resource composition candidate: execution evidence

The implementation and prerequisite fixes are published through
`7ef57d1b380e73269f592fa26fe95f9636c88586`. The complete local source qualification
below executed the earlier frozen `3a424e427b378400802c9e3c2fef558c0a352756`.
The later commits change documentation, prerequisite tests, workflow wiring and
the locked QEMU download address; the Hepta compiler bytes and native benchmark
protocols remain identical. These identities are kept distinct.

## Completed local source qualification

| Item | Actual result |
| --- | --- |
| Planned / completed gates | 50 / 50 |
| Passed / failed gates | 48 / 2 |
| Unit and integration tests | 2,093; zero skips, failures or errors |
| Frozen source | 920 files, unchanged before/after |
| Scalar performance | 42 samples; measurement-inconclusive |
| Owned performance | 63 samples; measurement-inconclusive |
| Performance failures | One scalar and five owned series exceed the fixed 5% relative-MAD limit |
| Speed-ratio failures | None; this does not override the measurement-quality failures |

The four new local-view, task/I/O, C++ composed-migration and direct-LLVM gates
passed. All source reports, gate logs, available native artifacts and exact
source/Git bindings are retained in [source_candidate](source_candidate/README.md).
Deleted temporary namespaces and excluded external toolchains are explicitly
inventoried; this is not a complete preserved execution environment.

The [independent performance review](../composition_performance_review_20261027/README.md)
recomputes all 105 samples and their process-observation associations without
calling a compiler, benchmark or the production evaluation functions. It
preserves both inconclusive outcomes and does not establish an uncontended host
or the cause of measurement variation.

## Hosted execution and prerequisites

The four-host Rust/C ABI runs passed for the recorded 19299, 3a, 8dcb and 7ef
commits. The [current 7ef host appendix](../ci_prerequisites_20261026/hosts_7ef57d1b/README.md)
binds the unmodified reports to provider run/head identities and exact source
replay. These host profiles do not qualify every LLVM backend on those hosts.

The earlier full CI failures remain in
[ci_prerequisites_20261026](../ci_prerequisites_20261026/README.md), with separate
19299 and 3a appendices. The
[QEMU source repair](../ci_prerequisites_20261026/qemu_source_repair/README.md)
records the actual snapshot HTTP 503, the identical package from the explicit
Ubuntu archive address, and the fresh installer result and executable identity.

At this checkpoint, the full hosted 7ef qualification and a restarted local HIA
qualification are still running. The first local HIA attempt lost its execution
session during unit regression and has no terminal result; it is not qualified.
Its retained plan and interruption observation will accompany the completed
attempt, without assigning an invented exit code or completed-test count.

## Acceptance boundary

The complete seven-stage production goal remains open. See
[BLOCKERS.md](../../docs/BLOCKERS.md) for P01–P12: general lifetime/trait
composition, compiler refinement and soundness, whole-process budgets, broad
services and C/C++ migration, physical hardware/GPU, general performance and
agent productivity, and the production ecosystem remain scoped or unproved.
Historical actual model trials are separately identified; fixture qualification
does not count as a new model trial or a demonstrated agent benefit.
