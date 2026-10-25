# Hepta P0–P7 follow-up: source/evidence ledger

Scope: stacked development chain PR #48 → PR #51 → PR #52.
Upstream immutable bases: PR #48 `e84fba15b347a9e23b0d6e607224031668d8207f`,
PR #51 `2627ff630afdc240c1095da2eb3d7313e719cfa2`.
This document distinguishes added executable code, evidence actually
observed on one host, and production acceptance obligations not discharged.

| Stage | Added in current stack | Still-blocking production criterion |
| --- | --- | --- |
| P0 | Strict HEAD-bound workflows and source snapshots | Complete current HEAD release validation and independent review |
| P1 | Canonical field-inventory/claims gate on scalar HSIR; existing CFG/SSA | Owner/loan/drop/provenance semantics, sound source-to-IR and backend refinement |
| P2 | Shared C/C++ migration of initialized automatic scalar locals, assignment and compound `while`; checked resource clauses | Real C packages across target configs, pointer/alias/allocation contracts, complete declared-source denominator and L2 qualification |
| P3 | Exact ELF/COFF/Mach-O x86_64/ARM64 target-object profiles and real compiler probe | Independent native target compilers, bidirectional ABI calls, platform host execution |
| P4 | Strict C++20 L1 stateless and stateful translation; storage/thread-local fail-closed | Broader classes, STL, templates, callbacks, RAII/exception source migration and L2/L3 memory safety |
| P5 | One C++→Hepta→C/LLVM SSA native differential test with compiled wrong-implementation control | Arbitrary Owners, pointers, Effects and target optimizations with independent refinement and performance data |
| P6 | Native-prevalidated pinned Agent function-contract diff with conservative proof flags | Real agent/model same-budget trials, actual correction costs and larger multi-file operations |
| P7 | Four explicit noalloc/no-block/no-suspend/no-spawn clauses on scalar generated functions, plus prior QEMU board evidence | Actual physical boards/DMA/IRQ, GPU, long-running services, memory and p99 load tests |

## Actual local evidence from this editing session

- Clang 17 AST smoke used real Clang++20 AST for initialized stateful locals
  and while loops; isolated lowering smoke completed 8 accepted/rejected
  expectation cases. This did not run the repository Hepta checker/rustc.
- A real C++ compiled static-local function produced call sequence 2, 4, 6
  for repeated argument 2; the strict converter now rejects this persistent
  storage shape rather than replacing it with an automatic local.
- Independent Clang 17 object-header probe produced 5/5 target objects.
  Exact generated object digests and fixture digest are checked into
  `evidence/target_object_format_probe_20261025.json`.
- Repository-native C++/Hepta/C, direct LLVM, and pinned Agent tests have
  executable test files but are not claimed as run in this local environment.

## Review rules

- Do not attribute the local scalar smoke or object-format probe to full
  Hepta native compilation, ABI compatibility or Rust-level safety.
- Source migration success is an L1 candidate, not L2/L3 certification;
  signed overflow is compared only over the original defined-input domain.
- A stable signature/effect/resource diff does not prove unchanged behavior.
- CI queued/unknown/not-run is never PASS, even when CI is not the current
  execution priority. PR #51 and #52 remain Draft until their real gates pass.
- Whole project status remains `whole_project_blockers_closed=false`.

## P1 nested semantics integrity extension

The scalar-only canonical-HSIR-to-CFG adapter additionally checks exact
reviewed field sets for function, parameter, expression, statement and
type nodes. The independent scalar path cannot silently drop unreviewed
new ABI/effect/borrow attributes even when supplied in a rehashed snapshot.
This is a subset-admission hardening step, not general HSIR v1 owner/loan
semantics, a compiler refinement proof, or formal soundness.
