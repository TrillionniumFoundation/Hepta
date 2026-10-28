# Seven-stage HIA integration contract

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
| 1. Semantics and format | Shared `hia_schema` registry; distinct nominal namespace; primitive v1–v7 grammar rules; explicit legacy adapter; normalization, loading, editing, interpretation and native code use reverified Core | New frontends/backends must use the same registry and cannot infer a grammar from conflicting legacy fields |
| 2. Resource composition | Generic products/enums, local stored/reborrowed loans, direct record-field borrowing, fallible allocation and cooperative cancellation compose with bulk/move/swap/offset/range memory operations; v7 adds dynamically allocated recursive buffer chains and composite v2 composition | General recursive heap ADTs/trees, escaping stored borrows, general asynchronous scheduling and channels remain unsupported |
| 3. Source/Core/machine correspondence | Source adapters feed independent Core admission; native/interpreter controls cover scalar, control, ownership and failure paths; a selected actual Core program has a separate Lean operational model and checked universal arithmetic property | The selected theorem does not prove the Python exporter, every verifier rule, LLVM refinement or whole-compiler soundness |
| 4. C migration | Complete compilation-database partitions; every active declaration has a disposition; finite standalone HIA modules plus unchanged upstream Ring-Buffer and an independent caller TU through contracted safe Hepta/Rust migration | Arbitrary C, unlisted macro configurations, inferred resource contracts and migration labor cost are unqualified; record-view migration is not standalone HIA lowering |
| 5. C++ migration | Owner/template native paths remain separate from new multi-object RAII bridges; real vector/deque and two nlohmann/json releases exercise copied-value dependencies, reverse destruction and publication after cleanup | General templates/STL, arbitrary object models and historical-library replacement are unqualified; foreign noexcept termination is retained and cannot be counted as recovery |
| 6. Platforms/devices | Linux x86-64 execution, AArch64 and RV64GC LP64D machine-code execution under QEMU, explicit finite runtimes and scalar/runtime ABI calls; historical Cortex-M4 Rust/BSP regression remains separate | Native standalone HIA on other OS/ABI families, physical boards, device protocols, DMA/interrupt/GPU behavior require their own execution evidence |
| 7. Performance/agent benefit | Frozen 63-sample performance protocol; earlier failed studies retained; a new two-family/four-interface/four-task atomic maintenance study requires both helper repairs and native partial-fix negatives | Finite interface/task comparisons cannot establish all-workload Rust superiority, representative maintenance productivity or total development-cost improvement |

“Static” means checked before execution for the admitted finite language.
“Dynamic” means an emitted/evaluated runtime check. “External” means a condition
on the compiler, allocator, platform or foreign environment. Their exact scope
is described in [HIA_PROGRAM.md](HIA_PROGRAM.md); none is interchangeable with
an absolute safety claim about all native programs.

## One frozen integration run

Commit the complete source before invoking the v3 collector (35 scoped gates;
see [the current qualification plan](HIA_UNIFIED_QUALIFICATION_V3.md)). The collector writes
a command plan, executes all gates against that exact source, retains stdout,
stderr and per-gate reports, rejects skipped test runs as complete passes and
compares source snapshots before and after. Native and formal reports bind
their own selected tools/artifacts. Performance is the last functional gate.

```sh
python tools/qualify_hia_unified.py \
  --output-directory /tmp/hepta-seven-stage-new \
  --clang /absolute/path/to/clang \
  --cc /absolute/path/to/gcc \
  --rustc /absolute/path/to/rustc \
  --cargo /absolute/path/to/cargo \
  --qemu-aarch64 /absolute/path/to/qemu-aarch64-static \
  --qemu-riscv64 /absolute/path/to/qemu-riscv64-static \
  --qemu-system-arm /absolute/path/to/qemu-system-arm \
  --linker /absolute/path/to/rust-lld \
  --lean /absolute/path/to/lean --cxx /absolute/path/to/g++
```

Cargo 1.90.0 and its locked dependencies must be available for the Rust
shadow tests. Fetch the locked dependencies before the frozen run. The
collector uses the selected `--cargo` and `--rustc` and places
`CARGO_TARGET_DIR` under the new evidence directory, outside the checkout
in the example above.

Within primitive v1–v7, the default Rust checker and `--scalar-run` accept
only resource-free scalar programs. `--owned-shadow` statically checks the
typed owner/loan CFG subset, including v7 chain transitions. `--owned-run`
executes the finite `cfg-call-byte-owner-bulk-v3` profile: byte-owner/loan operations,
CFG/loops, bounded internal resource calls and the six v2–v6 fill/copy/move/swap/range
operations, with scalar public entry/results.
Python/Rust checks compare complete resource ledgers, steps, results and stop
codes; selected LLVM/native allocator controls are separate execution evidence.
Chain operations/types and direct nominal input remain outside
this runtime profile. Python Core remains the standalone/native admission authority;
these scoped checks do not prove general resource safety or backend refinement.
See the [consumer support table](HIA_PROGRAM.md) and
[finite Rust execution profile](HIA_RUST_BYTE_OWNER_VM_20261027.md).
The static budget analyzer rejects v7 instead of counting a dynamic
chain destructor as one constant-time/free event.

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
