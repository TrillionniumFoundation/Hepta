# HIA P0–P7 integration contract

The current acceptance stages are P0 through P7 below. This historical filename
and the collector's `full_seven_deliverables_complete` compatibility field do
not define a different roadmap. The normative executable profile is
[HIA_PROGRAM.md](HIA_PROGRAM.md), with version selection owned by
`hepta/hia_schema.py` and exposed by `python -m hepta hia schema`.

This integration joins the nominal-resource implementation from
`a3fe747676e408707bbc3a8725fb62969734b690` and the v1–v6 memory/native-guard
implementation from `1b222302381008685b6985a7db101959145bbf2d`. It adds one
unambiguous admission path and executable qualifications. A passing finite
gate does not imply completion of the broader language-replacement goal.
The empty-owner native-drop fix and its original observation tests are also
carried from upstream `65a4bf82025cecf0684f2d65174ff0d3d8e96915`: logical
destruction of an empty owner must not introduce an observable `free(NULL)`
call absent from the interpreter's resource ledger.

## Acceptance boundaries

| Stage | Integrated implementation and executable evidence | Remaining obligation before the complete goal can pass |
| --- | --- | --- |
| P0. Single semantics | Shared `hia_schema` registry and public discovery command; distinct nominal namespace; primitive v1–v7 grammar rules; explicit legacy adapter; normalization, editing, interpretation and native code use reverified Core | Every frontend/backend must use the same registry; incompatible and ambiguous legacy inputs must reject; existing correctness regressions remain required |
| P1. Resources and memory | Generic products/enums, local stored/reborrowed loans, direct record-field borrowing, fallible allocation and cooperative cancellation compose with bulk/move/swap/offset/range memory operations; v7 adds recursive buffer chains; composite v3 adds explicit partial-record initialization, field movement and reinitialization over that same primitive v7 | General address-based typed places/layouts and initialization, escaping stored borrows, arbitrary recursive heap ADTs, concurrent scheduling and channels remain unsupported |
| P2. Core to native | Source adapters feed independent Core admission; native/interpreter controls cover scalar, control, ownership and failure paths; Rust shadow supplies independently implemented finite checks; selected Core has a Lean operational model | Return/trap/effect/resource correspondence must hold for every admitted construct; selected theorems do not prove Python export, LLVM refinement, optimization premises or whole-compiler soundness |
| P3. C migration | Compilation-database partitions and complete active-declaration dispositions; finite standalone HIA modules plus upstream Ring-Buffer through contracted safe Hepta/Rust migration | Arbitrary C, unlisted macro configurations, inferred resource contracts and migration labor cost are unqualified; record-view migration is not standalone HIA lowering |
| P4. C++ reuse and migration | Owner/template native paths and separate multi-object RAII bridges; selected captured Clang `if constexpr` instances lower only their evaluated branches with complete-pattern ODR checks; vector/deque and two nlohmann/json releases exercise copied-value dependencies, reverse destruction and publication after cleanup | General templates/STL and arbitrary object models remain open; selected object lifecycles and general constant-evaluation contexts are not enabled by branch selection; ABI, lifetime, safety and equivalence require separate evidence; foreign noexcept termination is not recovery |
| P5. CPU/GPU performance | Frozen 63-sample CPU performance protocol with earlier failed studies retained | Representative applications, same-semantics layout/vector gains, robust performance distributions and actual GPU execution remain required; no universal Rust superiority follows |
| P6. Agent-native development | Semantic editing, bounded context, snapshot checks, full public-consumer revalidation and primitive v1–v7 local incremental sessions with exact body/callee-interface dependencies; frozen task/interface experiment protocols | Full diagnostics, additional semantic profiles for incremental validation and real-model task/budget comparisons must establish success or cost benefit; reduced static body-check work and scripted fixtures do not establish model productivity |
| P7. Hardware and production | Linux x86-64 execution; AArch64 and RV64GC LP64D execution under QEMU; historical Cortex-M4 Rust/BSP regression remains separate | Physical boards, MMIO/IRQ/DMA, real workloads, sustained operation, resource boundaries and fault recovery require actual execution evidence |

“Static” means checked before execution for the admitted finite language.
“Dynamic” means an emitted/evaluated runtime check. “External” means a condition
on the compiler, allocator, platform or foreign environment. Their exact scope
is described in [HIA_PROGRAM.md](HIA_PROGRAM.md); none is interchangeable with
an absolute safety claim about all native programs.

## One frozen integration run

Commit the complete source before invoking the v2 collector (19 scoped gates). The collector writes
a command plan, executes all gates against that exact source, retains stdout,
stderr and per-gate reports, rejects skipped test runs as complete passes and
compares source snapshots before and after. Native and formal reports bind
their own selected tools/artifacts. Performance is the last functional gate.

```sh
python tools/qualify_hia_unified.py \
  --output-directory /tmp/hepta-seven-stage-new \
  --clang /absolute/path/to/clang \
  --rustc /absolute/path/to/rustc \
  --qemu-aarch64 /absolute/path/to/qemu-aarch64-static \
  --qemu-riscv64 /absolute/path/to/qemu-riscv64-static \
  --qemu-system-arm /absolute/path/to/qemu-system-arm \
  --linker /absolute/path/to/rust-lld \
  --lean /absolute/path/to/lean --cxx /absolute/path/to/g++
```

Cargo 1.90.0 and its locked dependencies must be available for the new Rust
shadow tests. Put its binary on PATH with the pinned rustc, and set
`CARGO_TARGET_DIR` to a build directory outside the source checkout so generated
artifacts cannot change the source snapshot. Distinguish the Rust modes:
its scalar interpreter admits resource-free programs under v1..v7, while
`--owned-shadow` independently checks Owner/Loan CFG rules including the v7
chain grammar. Static ownership checking is not dynamic chain execution or
an allocator-fault equivalence proof. The independent `--owned-run` execution
oracle executes the closed primitive v1–v7 resource ISA, including checked bulk
operations and iterative chains, and emits the distinct
`hepta.hia.rust-owned-execution.v2` report. It preserves old input ledgers,
version gates, scalar public entries and stopped resource accounting. Nominal
inputs must be normalized and independently checked as primitive Core first;
the Rust interpreter never invokes the Python interpreter. See
[HIA_RUST_RESOURCE_EXECUTION_V2.md](HIA_RUST_RESOURCE_EXECUTION_V2.md) for exact
coverage and limits. A test's presence is not a recorded execution result.
Rust cannot grant production native
admission. Budget analyzers also retain their own exact version and operation
limits; recognizing v7 never permits treating a dynamic chain destructor as
one constant-time/free event.

Run the full Linux native-isolation suite with a native Linux Python exposing
`fcntl.F_ADD_SEALS`, `F_GET_SEALS`, `F_SEAL_WRITE`, `F_SEAL_GROW`,
`F_SEAL_SHRINK` and `F_SEAL_SEAL`, and with actual kernel memfd sealing support.
The Python version number alone does not establish those capabilities: a
portable Python 3.12.14 build in the first round-2 run lacked all six constants,
whereas the selected native `/usr/bin/python3` 3.12.3 exposes them. The pinned
artifact loader continues to fail closed when sealing is unavailable. Do not
remove its seal verification or skip the native-isolation tests to obtain a
passing run. The qualification plan records the selected Python executable in
every Python command; retained host probes record its bytes, version and actual
write/grow/shrink rejection by the kernel.

The earlier separately frozen experiments remain documented in
`experiments/hia_edit_study_20261026/README.md`. The new atomic maintenance plan is
in `experiments/hia_atomic_maintenance_20261027/README.md`. Inference must not overlap
performance timing. Results belong to their exact source commit and retained
plan, rather than whichever branch head later happens to be current.

## Rules for interpreting a delivery

- Report test denominators, negative controls and actual target execution.
- Count C and C++ configuration matrices separately, and do not count scalar
  migration as proof of ownership-contract migration.
- Count original-language bridges separately from direct HIA implementations.
- Preserve failures, skips, timeouts, environment problems and unsuccessful
  model outputs; never select only favorable runs.
- Keep source compatibility, observable behavior, safety checks, ABI evidence
  and performance as distinct acceptance dimensions.
- Keep `full_seven_deliverables_complete` false until all obligations in the
  right-hand column have actual supporting evidence.

No credential, physical device, unavailable host, or model family is inferred
from a local toolchain. QEMU execution is labeled as QEMU execution. A failed
performance or productivity gate is an engineering result and must be reported.

## Follow-up qualification profiles

The original 19-gate collector keeps its existing denominator. New independent
qualification tools record their own frozen inputs, commands and outcomes;
their existence is not a claim that they have run:

```sh
python tools/qualify_hia_partial_records.py \
  --clang /absolute/path/to/clang \
  --rust-vm /absolute/path/to/hia-core-shadow \
  --output-directory /tmp/hepta-partial-records-new
python tools/qualify_cpp_constexpr.py \
  --clang /absolute/path/to/clang --clangxx /absolute/path/to/clang++ \
  --output-directory /tmp/hepta-cpp-constexpr-new
```

The partial-record profile compares nominal Python execution, independently
admitted primitive Python execution, the independent Rust VM and real LLVM
native execution, including allocator order and deliberately incorrect native
controls. The constexpr profile compares defined unsigned inputs against the
separately built original C++ library and a standalone HIA object with no
original C++ implementation linked into the target. These remain finite
profiles, separate from whole-language refinement, performance, model benefit,
GPU and physical-board qualification.
