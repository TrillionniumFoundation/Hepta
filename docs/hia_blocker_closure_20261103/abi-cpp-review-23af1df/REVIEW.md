# Independent strict host artifact review — 23af1df

## Result and source identity

All **7 conventional ABI artifacts and 7 real upstream C++ artifacts** pass the existing strict, finite host qualification checks at source `23af1df3eed65230137aa54ab8b10eac3520abd3`, tree `1a6c0c6801e8c4be5117018b8052d289f6546e99`. The review was read-only: it inspected existing GitHub Actions metadata and ZIP bytes, without rerunning CI, compiling, executing archive contents, or requesting a model.

- ABI workflow: [41610850348](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41610850348), all 8 jobs completed successfully. The separate standalone AArch64 job/artifact is excluded from this review and assigned to the integrator.
- C++ workflow: [41610850213](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41610850213), all 7 jobs completed successfully.
- Every inspected ZIP matches GitHub's advertised byte count and SHA-256. The review records hashes for **131 key raw JSON/log members**.
- Independent C++ retained-file verification additionally rehashed **514 members, 30,480,988 bytes**, including all 14 retained Hepta consumer objects, executed native programs, and native process streams. Every retained file name, byte count, and SHA-256 matched its original manifest. The decoded raw execution stdout equals the reported observations.
- Reports and evidence remain scoped; they do not close all P0–P7 requirements, prove whole-language safety, or permit production activation.

## Actual matrix

| Host | Compiler | ABI artifact | C++ artifact | Rust native target observed |
| --- | --- | --- | --- | --- |
| Linux x86-64 | GCC | 13218254214 | 13218358642 | x86_64-unknown-linux-gnu |
| Linux x86-64 | Clang | 13219570062 | 13218254090 | x86_64-unknown-linux-gnu |
| Linux AArch64 | GCC | 13219520231 | 13219132225 | aarch64-unknown-linux-gnu |
| Linux AArch64 | Clang | 13219281326 | 13219335888 | aarch64-unknown-linux-gnu |
| Windows x86-64 | MSVC | 13218957886 | 13217969796 | x86_64-pc-windows-msvc |
| Windows x86-64 | Clang | 13218194480 | 13219361024 | x86_64-pc-windows-msvc |
| macOS AArch64 | Clang | 13219655039 | 13219495277 | aarch64-apple-darwin |

Compiler predefined-macro identities agree with the reported actual host system/architecture. Target triples differ in ordinary vendor/OS spelling between C/C++ drivers and Rust; the original triples are retained in `native-identities.json`. Windows C++ has actual retained executable bytes, exit-zero process records and matching raw output; it was not replaced by a unit-test stub.

## Checkout and source-byte checks

All seven C++ reports have equal before/after source checkout identities, exact commit/tree, empty tracked status before and after, and no casefold collision. All seven ABI artifacts have exact source-before/source-after logs and **zero-byte** tracked-before/tracked-after logs.

The independent full Git-tree listing contains **8,659 tracked paths**. Its NUL-separated bytes are retained as `tracked-paths.nul` (655,309 bytes), SHA-256 `62e8d12878e48bb864679944f90b36aa84d3d8a71da0fe26be4ad4e7c165044b`. All seven C++ path-count/hash declarations match this complete listing. An independent casefold check over file names and all directory prefixes found no collisions.

ABI reports bind 403 implementation files and 6 migration fixture files per host; all reported hashes match the exact Git blobs. C++ reports bind 197 source inputs per host. Linux and macOS match all 197 raw Git blobs. Both Windows reports match 189 raw blobs and have only LF-to-CRLF materialization differences in the same eight authored example files, with no other mismatch:

- `examples/cpp/upgrade/adapter.hpp`
- `examples/cpp/upgrade/consumer.hepta`
- `examples/cpp/upgrade/contract.json`
- `examples/cpp/upgrade/harness.cpp`
- `examples/cpp/upgrade/recovery_worker.cpp`
- `examples/cpp/upstream_host/README.md`
- `examples/cpp/upstream_host/consumer.hepta`
- `examples/cpp/upstream_host/harness.cpp`

The Windows checkout is tracked-clean according to Git. That does **not** make these eight physical files byte-identical to the raw blobs.

## Actual observations and controls

### ABI and finite C translation

Each of the seven ABI hosts executes two optimization profiles with 181 foreign calls per profile, and rejects three changed type declarations plus one actually compiled wrong C echo. The corresponding finite stb-divide qualification records, per host:

- 21,453 distinct inputs and 42,906 input/configuration pairs across two variants;
- 514,872 native function observations;
- 696 separate HIA interpreter observations;
- 24 native target-only trap processes;
- three whole-bundle refusal controls, one wrong-code execution with exit code 2, and the C++ entry refusal `E_CPP_PROJECT_PROFILE`.

The generated native route for these stb targets is Rust. The HIA interpreter observations are explicitly separate, and the reports say that an HIA native route was neither requested nor executed for this cohort.

**Native-byte boundary:** the ABI matrix qualifier builds its matrix object and executables in a temporary directory. The artifact retains their reported hashes, actual command/observation receipts and compiler identities, but not those temporary binary bytes. This review therefore does not claim to have independently rehashed the ABI matrix object/executable files. C++ retained native binaries were independently rehashed as described above. Standalone HIA LLVM/native evidence is handled separately by the integrator.

### Real upstream C++ reuse

Every C++ host runs both pinned nlohmann/json versions, 3.11.3 and 3.12.0. Each version reports 98 direct/Hepta cases, 32 lifecycle cases, 1,024 concurrent calls and ordinary live allocation delta zero. The retained registry allocation count is two on Linux/macOS and three on Windows; this is not a zero-allocation claim.

All seven artifacts pass the same 12 exact negative evidence controls. Four reject a persistently dirty checkout, absent final identity, changed source tree, and casefold-colliding paths. The other eight retain compiler/process/probe/contract/raw-stream/Rust-identity refusal coverage. Actual wrong-code execution is rejected with exit code 2 and the incompatible signature is rejected with `E_CPP_NATIVE`.

These are Rust-backed Hepta consumers reusing an unchanged C++ library. They do not prove foreign-library memory safety, arbitrary C++ translation, all foreign allocation failure recovery, or asynchronous foreign-call cancellation.

## Test execution and platform conditions

Each C++ host's retained unit log reports **16 tests, OK, no test skip**. Every ABI host reports 11 adapter tests, 16 capture tests and 4 original-type/process tests, all OK with no individual test skips. The five POSIX ABI hosts additionally retain **20 ownership/capture tests, OK**.

Workflow conditions remain explicit: the two Windows ABI jobs skip the whole POSIX-only ownership/capture step, and non-Windows jobs skip Windows Visual Studio setup. Those conditional nonexecutions are recorded in `workflow-metadata.json`; this report does not turn them into executed Windows POSIX coverage.

## Retained audit records and historical negatives

- `review.json`: all 14 qualification summaries, source checks, native counts, scoped claims and key member identities.
- `member-sha256.tsv`: 131 raw selected JSON/log member hashes.
- `native-identities.json`: original compiler/native target identities, C++ native byte and stream verification, and ABI temporary-binary limitation.
- `workflow-metadata.json`: complete observed job steps and artifact metadata for the two completed workflows.
- `tracked-paths.nul`: exact source-tree path inventory used for independent count/hash/casefold verification.

Earlier `final-host-artifact-review-5c3741d`, `strict-host-review-d562d6d`, and `strict-host-review-1629a03` directories remain unchanged. In particular, the three dirty 5c C++ checkouts and the two d562 Windows preflight failures are retained as historical failures; new successful observations do not retroactively qualify them.
