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
| 1. Semantics and format | Shared `hia_schema` registry; distinct nominal namespace; primitive v1–v6 grammar rules; explicit legacy adapter; normalization, loading, editing, interpretation and native code use reverified Core | New frontends/backends must use the same registry and cannot infer a grammar from conflicting legacy fields |
| 2. Resource composition | Generic products/enums, local stored/reborrowed loans, direct record-field borrowing, fallible allocation and cooperative cancellation compose with bulk/move/swap/offset/range memory operations | Recursive heap ADTs, escaping stored borrows, general asynchronous scheduling and channels remain unsupported |
| 3. Source/Core/machine correspondence | Source adapters feed independent Core admission; native/interpreter controls cover scalar, control, ownership and failure paths; a selected actual Core program has a separate Lean operational model and checked universal arithmetic property | The selected theorem does not prove the Python exporter, every verifier rule, LLVM refinement or whole-compiler soundness |
| 4. C migration | Explicit complete compilation-database partitions; two configurations and two translation units per finite module; every active declaration receives a disposition; original/native/interpreter behavior checked independently | Arbitrary C, all unlisted macro configurations, general cross-module resource contracts and migration labor cost are unqualified |
| 5. C++ migration | Existing owner and instantiated-template paths plus separately compiled macro variants; original implementation excluded from direct HIA target link; bridge and native evidence remain separate | General templates/STL, exceptions/RTTI, arbitrary object models and historical-library replacement remain unqualified |
| 6. Platforms/devices | Linux x86-64 execution, AArch64 machine-code execution under QEMU, and explicit finite multi-owner runtime; historical Cortex-M4 Rust/BSP regression remains separate | Native standalone HIA on other OS/ABI families, physical boards, device protocols, DMA/interrupt/GPU behavior require their own execution evidence |
| 7. Performance/agent benefit | Frozen 63-sample performance protocol and separate two-model/four-interface/eight-task native repair study; failed runs and wrong-but-valid edits retained | A single finite pass cannot establish all-workload Rust superiority, multi-family model benefit or total development-cost improvement |

“Static” means checked before execution for the admitted finite language.
“Dynamic” means an emitted/evaluated runtime check. “External” means a condition
on the compiler, allocator, platform or foreign environment. Their exact scope
is described in [HIA_PROGRAM.md](HIA_PROGRAM.md); none is interchangeable with
an absolute safety claim about all native programs.

## One frozen integration run

Commit the complete source before invoking the collector. The collector writes
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
  --qemu-system-arm /absolute/path/to/qemu-system-arm \
  --linker /absolute/path/to/rust-lld \
  --lean /absolute/path/to/lean
```

The separately frozen model experiment is documented in
`experiments/hia_edit_study_20261026/README.md`. Its inference must not overlap
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
