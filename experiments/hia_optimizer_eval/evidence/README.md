# Attempt registry

Every directory contains the exact `report.json` and `plan.json`, a lossless
`tar.xz` archive of **all regular files** in that attempt directory, and `retention.json`.
The retention manifest gives each original file's byte count and SHA-256, the
archive identity, and verification that every member was read back and matched.
The archives include actual generated source, native binaries, raw commands,
profiles, samples and model responses. They are not rebuilt substitutes.

| Directory | Actual outcome and use |
| --- | --- |
| `bench_missing_profile_runtime` | First development attempt: four native backends built; both PGO builds failed because compiler-rt was absent. All 84 scheduled slots remain, including 28 unavailable-PGO slots. Its inherited `ru_maxrss` metric was subsequently diagnosed; this is not the final memory evidence. |
| `bench_complete_pre_freeze` | Six native backends, actual C/C++ instrumentation PGO, 864 finite native correctness observations and 84 timing samples. Quality passed; fixed noninferiority thresholds failed. This predates the allocator-attribute change. |
| `agent_socket_failure` | All 32 native controls passed. The restricted environment denied the private server socket; zero model requests were made. |
| `agent_source_drift` | All 32 controls and both format probes passed. Seventeen actual requests returned: two probes and 15 task cells. All 15 repairs failed. Adding new compiler modules changed the source inventory before the last cell, so execution stopped and the attempt is incomplete. It cannot support a productivity advantage. |
| `codegen_ablation` | Separate exploratory checked-to-wrapping-sum experiment, 144 finite correctness observations and 28 paired executions, complete disassembly. Different semantics outside the finite domain; explicitly not an admitted optimizer transformation. |
| `bench_final` | Frozen final source, all six native builds and actual C/C++ PGO, 864 finite correctness observations, all 84 timing samples. Source/tool/artifact identity stable; computed quality passed, all ten fixed noninferiority comparisons failed. Shared-host interference is disclosed in `../results.md`; no samples were excluded. |
| `agent_final` | Frozen final source, all 32 controls and both format probes passed; all 18 requests returned, all 16 cells completed, zero successful repairs. Exact model/runtime and source/tool identities stable. All failed attempts and their costs are retained. |

The first development attempts preserve their captured inputs and outputs but
do not retroactively inherit the final source identity. Final frozen attempts
also include complete copies of their hash-bound source files in
`source_snapshot`. Infrastructure repair is recorded as a new attempt; no raw
failure is overwritten and no result is selected by relaxing a threshold.

The final benchmark archive additionally contains clearly identified post-run
disassembly observations. Its original measured report and plan are unchanged.
The allocator-return `noalias` declaration did not change the final HIA binary:
it has the same SHA-256 as the earlier complete run. Timing variation between
those runs is not attributed to that declaration.

After archive readback and per-file hash verification, the old temporary raw
directories and the final agent's temporary tree were removed to recover space
on the full shared filesystem. All their regular-file bytes remain in these
archives. Compiler/model binaries outside the attempt directories are identified
by hash in the reports and are not bundled here.

`clang_profile_runtime.json` records the exact official Ubuntu snapshot package,
its verified apt metadata hash, and the extracted profiling archive identity.
The package was extracted into `/tmp`; no system installation was performed.
