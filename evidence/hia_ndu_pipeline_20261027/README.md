# Bounded HIA / native NDU implementation and evidence — 2026-10-27

This delivery contains working, separately checked mechanisms and their actual
execution evidence. **The finite local qualification passed; the six broad
research/production goals remain open.**

## Exact source and executable results

- Actual local tested commit: `c4309712d8f4d21563a26c174391bd66195a9e34`.
- GitHub-published source commit: `e1473a42f6b9a50a42f8cca8fadff47e709cf4d4`.
- Both have the identical Git tree: `f0625fe5579fcfd0c712cd37da88455c1ae39fa0`.
- Base: `3db07aa877ab1a5fc00560d7037e6efbc884fc1f` (draft PR #323).
- Delivery: [draft PR #328](https://github.com/TrillionniumFoundation/Hepta/pull/328).

The connector recreated commit author/timestamp metadata. Local test results are
attributed to the actual local SHA, not relabelled as execution of the GitHub
commit. `publication-provenance.json` records all seven exact tree matches, and
`tested-source.bundle` preserves the original tested commits. The actual host CI
did separately execute the published source SHA.

| Executed gate | Observed result |
| --- | --- |
| Full Python regression | 2640 tests; 0 failures; 0 errors; 0 skips |
| Focused Python regression | 198 tests; zero failures/errors/skips |
| Rust resource crate | 54 tests; zero failures/ignored/filtered tests |
| Rust/Python owner CFG | 179 pairs over 18 programs, including stop/resource ledgers |
| C/C++ native migration | 551 inputs × two implementations = 1,102 result executions |
| Migration interpreter differential | 188 Python/Rust pairs; C++ owner subset is 112 of 475 native cases, selected by size ≤17 |
| Translation controls | Proved wrapping rewrite; replayed wrong-value/trap counterexamples; loops unknown; forged receipt refused |
| Real-host C ABI | Seven jobs, two optimization levels each, 2,534 foreign-call observations; 21 ill-typed declarations and seven compiled wrong echoes rejected |

Focused/full/Rust/tool-internal test sets overlap. Their counts must not be
added into a purported unique-test total. The real-host evidence is for the
existing declared Hepta C ABI profile, with explicit foreign assumptions, not
new HIA multiversion support on all seven targets.

The seven actual host jobs cover Linux x86-64 GCC/Clang, Linux AArch64 GCC/Clang,
Windows x86-64 MSVC/Clang, and macOS AArch64 Clang. Their exact uploaded ZIP
archives and reports are retained with independently checked GitHub artifact
digests. These ZIPs contain reports/logs, **not** the platform native executables.
[Actual source-host workflow](https://github.com/TrillionniumFoundation/Hepta/actions/runs/40551242969).

## Six acceptance conditions

| Stage | Implemented and measured | Remaining closure condition |
| --- | --- | --- |
| 1 — Semantic entrance | This candidate's frontends, verifier, interpreter and LLVM emitter consume canonical HIA Core; tests bind one frozen version | The independently advanced PR #325 is not consolidated. Three shared paths conflict, including incompatible `hia optimize` arguments and bridge/build protocols |
| 2 — Resource core | Bounded byte-owner CFG, internal calls, owner transfer/return, call-scoped loans, shared budgets and allocation-failure ledgers execute in Rust/Python | Escaping/returned loans, general composed resources and the requested complete failure/cancellation equivalence are not implemented by this Rust subset |
| 3 — Behavior preservation | Fresh Z3 proof of all-input acyclic scalar values and first traps is independent of resource/type legality; unknown or disproved candidates cannot be accepted | Calls, loops, general resources, floating point and concurrency are outside this proof encoder; no native backend refinement theorem |
| 4 — Finite NDU | Original pinned Rust NDU evaluator, exact build provenance, finite actions, common-budget controls, measured costs and mandatory abstention | No incremental performance value over fixed/simple selection has been established |
| 5 — Migration/ABI | Actual migrated Core and original C/C++ native implementations compared; declared C ABI ran on seven real hosts | General large-project translation, arbitrary C++ library contracts and every target/ABI feature remain open |
| 6 — Runtime/ISA | Sealed generations, leases, rollback, stale/ABA refusal, cancellable bounded background jobs; separately verified finite x86 recipes | Profitable measured background publication, general live owner/state migration, and integrating ISA search into live publication remain open |

## Negative optimization results are retained

The frozen equal-budget protocol uses six proposals and the same observations
for fixed recipe, seeded random selection, simple observed enumeration and the
actual NDU evaluator. It executed 49 training plus 35 holdout samples: 16.8 million
timed native calls, with warmups recorded separately. The baseline and all six
candidates produced **identical complete shared-library bytes** under LLVM O3.
All four policies abstained. Search, proof, compilation, measurement, losing
candidates and actual policy overhead remain charged. This is paired replay of
one observation table, not a sequential-learning experiment. Empirical timing
envelopes are not statistical confidence intervals.

The separate finite x86 experiment completely enumerated 146 recipes. Actual
Z3 checks disproved 139 and proved seven equivalent. All seven and the LLVM
baseline were assembled, byte-inspected and executed. The finite minimum body
is five bytes, `48 8d 47 0c c3`, identical to LLVM's body. All seven timing
envelopes overlap after 56 samples and 11.2 million timed calls. This is a byte
minimum in the declared grammar, not minimum runtime, a whole-program optimum,
or an NDU learning result.

Background qualification made three real NDU calls. Its measured one-call
horizon abstained. A positive **synthetic-cost lifecycle control** published a
generation; a behaviorally wrong candidate was then refused. The publication
exercises real proof, compile, sealing, generation and cleanup paths, but its
synthetic economics are not evidence of real acceleration. Runtime generations
were destroyed according to their lifecycle; their reports and hashes remain,
but those transient generation bytes are not in this archive.

## Failures, compatibility repair and scope

Run 1 on `c8c11a4c51a16d262663d5f8181a96cac98a04d8` retained 2,633 tests,
42 failure entries, 21 error entries and 12 skips. These are 63 unittest entries
across 38 test methods plus one class setup, not 63 independent defects.
Sixty-one entries shared missing Python `fcntl.F_SEAL_*` names; the remaining
failures exposed absent ARM board-emulator/cross-stdlib prerequisites. Twelve
C++ skips were caused by an unresolved default Clang++ path.

The compatibility repair uses checked Linux UAPI constants where Python does
not export their names, while retaining actual kernel sealing and readback.
Actual cross-target libraries, QEMU, selected Clang++ and other prerequisites
were installed and checked. The affected 49-test compatibility regression passed
without skips. Run 2 then repeated the full frozen qualification. No tests were
removed, no functional/resource acceptance threshold was relaxed, and failed
evidence was not overwritten. ARM board observations use QEMU, not physical
hardware; the separate seven-host ABI results are real host processes.

NDU remains advisory. Source legality, a fresh functional proof, native artifact
checks and publication/lifetime checks retain independent authority. The verifier,
proof encoder, Z3, compiler/assembler, loader, trusted host measurements and
trusted runtime form part of the current trusted computing base. A resource
cap here is a recorded-expenditure admission threshold, not an OS preemptive
quota. Whole-language soundness, absolute Rust safety equivalence, universal
Rust performance superiority and global optimality have not been proved.

## Contents and reconstruction

- `acceptance.json`: machine-readable status and explicit open-stage flags.
- `run1-qualification.json`, `run2-qualification.json`: original summary/log
  records with exact source inventories and command outcomes.
- `evidence-ledger.md` / `.json`: independent counting and hash audit.
- `publication-provenance.json`, `tested-source.bundle`: original-source identity.
- `PR325_INTEGRATION_REPORT.md`: source-bound, read-only contract/conflict review;
  it does not attribute the other branch's test or performance results here.
- `raw-evidence.tar.gz`, `raw-evidence-manifest.json`: 924
  files, all reopened and compared byte-for-byte after packaging. Both full
  qualification directories, retained migration/NDU/x86 artifacts, actual Linux
  NDU/Rust oracle binaries, pinned NDU build inputs, prerequisite receipts,
  seven-host CI uploads and historical development attempts are included.

Historical evidence remains under `historical/` and is not assigned to the final
frozen SHA. Large external toolchain distributions are not bundled; their
authenticated source and payload pins are in the prerequisite receipts.

To restore the exact local tested history in an existing clone containing the
base commit:

```sh
git fetch origin 3db07aa877ab1a5fc00560d7037e6efbc884fc1f
git bundle verify evidence/hia_ndu_pipeline_20261027/tested-source.bundle
git fetch evidence/hia_ndu_pipeline_20261027/tested-source.bundle HEAD
git switch --detach c4309712d8f4d21563a26c174391bd66195a9e34
```

The complete build and qualification commands are in
[`docs/HIA_NDU_PIPELINE.md`](../../docs/HIA_NDU_PIPELINE.md); both raw runs also
retain their exact argv in `frozen-plan.json`. Reproduction needs the documented
real toolchains, Z3, native execution permissions and pinned upstream source.

`six_stages_closed=false`, `scientific_incremental_advantage_established=false`,
`whole_language_soundness_proved=false`, and `global_optimality_established=false`
are deliberate acceptance results.
