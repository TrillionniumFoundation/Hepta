# One candidate, 35 explicit native, hosted and Rust shadow gates

`tools/qualify_hia_unified.py` now emits `hepta.hia.unified-qualification.v4`.
This document keeps its existing path so earlier links remain valid. Historical
v3 receipts retain their original single-process unit gate and are not relabelled.
The current plan contains **35 gates**: the earlier 24-gate converged plan,
ten existing hosted/native/formal/application gates, and one independently
reported Agent-query mechanism gate. All run against the same unchanged,
committed source tree. The native and Rust convergence gates include:

| Gate | Actual execution | Success condition |
| --- | --- | --- |
| `unit_regression` | Complete source discovery, every module in a fresh process, two workers; no retries | Independent discovery equals every actual discovered/started/finished ID, with zero skips, expected failures, errors or failures |
| `rust_shadow_cargo` | The pinned Cargo and Rust compiler build and execute the real shadow crate tests, locked and offline | Nonempty complete test results, zero failures, ignored tests or filters, and successful process exit |
| `rust_shadow_parity` | The Python-to-Rust scalar, owned-verifier, call, chain, scalar VM, byte-owner/bulk/chain VM and exact-binary crosscheck tests | A completed nonempty unittest report with zero skips, failures and errors |
| `agent_query_semantics` | Existing single/batch queries, transitive/CFG/control slices, display identity and untrusted-render controls | A completed nonempty unittest report with zero skips, failures and errors; this is mechanical qualification, not an AI-model productivity trial |
| `cpp_composed_implementation_llvm` | Actual Clang AST migration of the supported composed-owner C++ implementations, direct LLVM compilation and native lifecycle controls | Fresh report, successful exit, and the existing `cpp_composed_to_llvm` replay validator |
| `llvm_local_stored_views` | Actual source-bound LLVM, Rust and C local-view execution and negative controls | Fresh report, successful exit, and the existing local-view replay validator |
| `task_io_composition` | Three repetitions of the actual task/I/O native cases | Fresh report, successful exit, and the existing task/I/O replay validator |

The existing upstream C++ library bridge gate remains separate from the actual
implementation rewrite. Its evidence cannot be used to claim that those
upstream library implementations have been translated.

## Imported hosted profiles

These gates execute existing producers and call
`release_check.require_collected_qualification` with their existing names.
No alternate receipt validator or weaker acceptance rule is introduced.

| Unified gate | Existing producer and fixed run parameters | Shared validator name |
| --- | --- | --- |
| `bounded_concurrency` | `validate_groups.py`, 3 repetitions | `bounded_concurrency` |
| `shared_runtime` | `validate_shared_runtime.py`, 3 repetitions | `shared_runtime` |
| `independent_concurrent_ir` | `validate_concurrent_ir.py`, actual native and graph mutation controls | `independent_concurrent_ir` |
| `structured_task_trees` | `validate_task_tree.py`, 3 repetitions | `structured_task_trees` |
| `bounded_async_io` | `validate_io.py`, 3 repetitions | `bounded_async_io` |
| `native_host_gcc` | `validate_native_host.py`, explicit GCC family, Linux/x86_64 | `native_host_abi` |
| `native_host_clang` | `validate_native_host.py`, explicit Clang family, Linux/x86_64 | `native_host_abi` |
| `provenance_and_type_core` | `verify_memory.py`, selected Lean executable and existing negative mutations | `provenance_and_type_core` |
| `formal_core` | `verify_formal.py`, selected Lean executable and existing negative mutations | `formal_core` |
| `application_performance` | `benchmark_applications.py`, 3 trials, 96 requests, 16 warmups | `application_performance` |

The two host ABI gates select separate compiler paths and explicitly require
`--cc-family gcc` or `--cc-family clang`. The native-host producer verifies the
actual compiler family; an executable's filename or symlink does not establish
that identity. Both receipts retain actual-host restrictions and do not credit
cross-host results.

The last two gates are `application_performance`, then
`standalone_performance`. The application producer measures **sequential,
in-process ABI requests**. These are not external network-service measurements,
concurrent client load, or service-level-objective qualification. Existing
application scopes, raw observations and performance regressions remain in the
producer report.

## Reproducible execution

Commit tracked source before running. Select a new output directory, preferably
outside the checkout. The collector records the actual Git commit, commands,
bounded process logs, report digests and source snapshots before and after all
gates. Every planned gate executes even after another fails. A missing report,
an interrupted test suite, a skipped test or a malformed report prevents that
gate from passing. Imported reports replay their existing validators, which own
their exact success conventions: some valid hosted reports use only
`status=passed`, while other producers also emit `ok`. The collector requires a
successful validator and an actual zero process exit. Neither success field
alone grants qualification. Report intake reuses the existing stable,
bounded, no-follow evidence reader.

The Rust component lock now includes Cargo 1.90.0. The existing bootstrap
installer checks the official archive checksum and each installed payload.
Fetch locked dependencies before the frozen run:

```sh
cargo fetch --locked --manifest-path rust/hia-core-shadow/Cargo.toml
```

Pass the selected executable with `--cargo /absolute/path/to/cargo`. The collector
makes the same Cargo available to Python's real crosscheck tests, exports the
selected `RUSTC`, enforces offline Cargo execution, and places build outputs under
the evidence directory. It restores the caller's environment even after failure.

V4 also refuses new untracked implementation or test files. Its snapshot records
separately the optional local NDU upstream export and generated build provenance;
those dependency inputs are not claimed to belong to the Hepta Git commit.
Only the two exact Cargo output roots beneath `rust/hia-core-shadow/target` and
`rust/hia-ndu-bridge/target` are omitted as generated build products. An arbitrary
source directory named `target` remains in the source inventory.

The complete unit gate no longer applies the old 1,800-second aggregate kill to
all tests. `tools/qualify_hia_unit.py` freezes the complete ID set and schedules
modules by descending discovered case count, with alphabetical ties. Each child
records the actual ID at start and finish, terminal unittest counts and complete
bounded logs. A 600-second cooperative deadline is checked at tool polls and
test boundaries; the parent has a 900-second process-group bound. A child-created
session is outside that process-group cleanup guarantee. This is explicitly a
partitioned regression, not a single-process full-suite run or a performance
experiment. Every failed module remains in the final matrix and is not retried.

Replay uses independent source discovery, strict duplicate-free JSON, bound
child/log files and consistent summary counts. Omitting an entire module and
recomputing the aggregate cannot pass. Fresh start records, immutable per-gate
checkpoints and an interruption/final report preserve completed observations.
A partial checkpoint never qualifies the complete plan.
The qualification workflow installs pinned Cargo and fetches dependencies before
entering this offline phase.

`--cc` defaults to the resolved `gcc` executable. It supplies the GCC ABI gate,
C comparisons in existing hosted paths, and the application measurement. The
Clang ABI gate uses `--clang`. The workflow passes `/usr/bin/gcc` and
`/usr/lib/llvm-20/bin/clang` explicitly and installs LLVM's `llvm-readobj` tools.
Both RV64 and AArch64 qualification use the selected `--linker`; RV64 object
inspection uses `llvm-readobj` beside the selected Clang.

Every unified child process also receives `CC`, `HEPTA_LLD`,
`HEPTA_LLVM_READOBJ`, `HEPTA_QEMU_AARCH64`, and `HEPTA_QEMU_RISCV64`, in addition
to the existing compiler/proof variables. The workflow exports the same tool
choices for its other qualification steps. A local invocation can use the same
explicit arguments as the workflow:

```sh
hepta_toolchains=/absolute/path/to/toolchains
python tools/qualify_hia_unified.py \
  --output-directory /absolute/path/to/new-evidence \
  --clang /usr/lib/llvm-20/bin/clang --cc /usr/bin/gcc \
  --rustc "$hepta_toolchains/rust-1.90.0/bin/rustc" \
  --cargo "$hepta_toolchains/rust-1.90.0/bin/cargo" \
  --lean "$hepta_toolchains/lean-4.19.0/bin/lean" \
  --linker "$hepta_toolchains/rust-1.90.0/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld" \
  --qemu-aarch64 "$hepta_toolchains/qemu-8.2.2/qemu-aarch64-static" \
  --qemu-riscv64 /usr/bin/qemu-riscv64 \
  --qemu-system-arm /usr/bin/qemu-system-arm --cxx /usr/bin/g++
```

The broader `tools/release_check.py` retains additional frontend, ABI, namespace,
migration and application profiles. Importing these selected hosted gates does
not complete that broader plan or turn hosted guarantees into standalone-Core
guarantees.

## Scope and regressions

Rust remains a shadow; these checks do not transfer production admission from
the existing Python Core. The raw Cargo result parser counts actual test
binaries, rejects an empty run, and retains failures and ignored/filtered counts.
The collector regression exercises every planned command and confirms that
zero exits without native reports and forged hosted reports containing only
success flags cannot pass. Protocol controls also check the fixed 35-gate
inventory, repetitions, request denominator, compiler-family selections,
performance ordering, exact workflow shell/CLI expansion, environment transfer
and restoration, and delegated status-only receipt handling. These are collector
protocol tests rather than native qualification evidence; the frozen 35-gate
run must still execute each real producer.

The schema continues to report `full_six_deliverables_complete=false` and
`full_seven_deliverables_complete=false`. The Rust byte-owner/chain execution gate is
a finite resource VM; it does not qualify general resource execution or change
production admission authority.
General recursive ADTs, universal C/C++ migration, real-model productivity,
physical devices, compiler refinement and general Rust performance superiority
require their own evidence. Adding or passing a gate does not establish any of
those broader claims.
