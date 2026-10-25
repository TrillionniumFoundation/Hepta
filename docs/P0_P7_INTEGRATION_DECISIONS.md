# P0–P7 integration baseline: execution ownership and remaining gates

This document is a merge-safety checkpoint, **not** a declaration that any
production P0–P7 gate has closed. Do not cherry-pick entire PR trees into main.

## Pinned independent candidate heads (2026-10-25)
- Main 0.2: `48600e3126f7ddf930ed4006476dd01d7a92e473`
- PR #14: `66b3359d384e4cf4496ca40bf499994575ffd3ca`
- PR #36: `0dbae1504ad6acf1939fe02c6934a3435bb16d25`
- PR #37: `af3f406f4d980ae2e8c5fca23b4ed12bee5195af`
- PR #41, stacked #37: `bbf1d0eaec8337abde4a3af8f23c0f341f543247`
- PR #42, stacked #37: `0851f0a37a377ef9f704c8b3a72567693b530f0c`

PR #14 and #36 diverge from main; PR #37 and #36 also contain diverged
history as of these heads. PR #14 is a much larger worktree (1000+ files)
and includes generated evidence. PR #41 and #42 contain independent symlink
publication fixes: preserve both regression contracts when integrating P6.

## Semantic authority decision (proposed, requires source-level review)

| Interface/ownership | Preferred foundation | Integration action |
|---|---|---|
| Language AST, parser, checker, Rust reference | main + qualified #14 extensions | Reconcile source and tests, no automatic replacement |
| Canonical semantic snapshot | #14 `semantic_ir.py` compared with #36 `hsir.py` | Adopt one versioned canonical schema; map the other as adapter only |
| Ownership / resource / concurrent verification | #14 `resource_ir.py`, `concurrent_ir.py` | Retain independent validation; prove source-to-IR lowering next |
| CFG, dominators, scalar SSA, LLVM lowering | #37 | Rebase on chosen canonical semantic snapshot before integration |
| C-project migration | #14 `c_migrate.py`, `c_migration_project.py` | Compare #36 `c2hepta.py` negative oracle; never maintain two unqualified authorities |
| C++ reuse/migration | #14 `cpp_contracts.py` and #36 `cpp2hepta.py` | Keep safe external bridge and unqualified source conversion as separate products |
| Multi-file Agent commits | #14 `workspace.py` / `protocol_v3.py` | Retain durable v4 as publication authority; absorb #37 preview checks only if useful |
| Native LLVM publication | #37 + #41 + #42 | Fix both symlink paths; exact-head execute tests before merge |

This is an explicit hypothesis, not verified interface equivalence. `semantic_ir`,
`hsir`, and `hmir` may have different invariants. Nothing is removed or
declared redundant without reviewing typed fields, user-facing CLI contract,
consumer graphs, adversarial tests and actual lowering.

## Local repeatable premerge file audit

From a checkout containing all Git objects:

```sh
python tools/audit_parallel_prs.py \
  --base 48600e3126f7ddf930ed4006476dd01d7a92e473 \
  --candidate pr14=66b3359d384e4cf4496ca40bf499994575ffd3ca \
  --candidate pr36=0dbae1504ad6acf1939fe02c6934a3435bb16d25 \
  --candidate pr37=af3f406f4d980ae2e8c5fca23b4ed12bee5195af \
  --output /tmp/hepta-p0-integration-audit.json
python -m unittest discover -s tests -p test_parallel_pr_audit.py -v
```

The auditor verifies full commit SHA identities and that every candidate
descends from the selected main base. It inspects exact base-to-head changed
paths, ancestry, overlapping paths and predefined semantic-authority paths.
It rejects missing objects, invalid inputs and pre-existing evidence output.
It has no auto-merge mode and never represents a successful audit as approval.
Overlapping file paths are not necessarily merge conflicts; disjoint files can
implement conflicting semantics. Both require manual source and native review.

## P1–P7 open acceptance gates

| Stage | Required closure evidence |
|---|---|
| P1 | Unified typed ownership/effect/provenance IR with independent negative tests, source-to-IR and IR-to-backend refinements |
| P2 | Complete active C translation-unit inventory with recorded compilation database, safe/checked/unsupported accounting, independent differential execution |
| P3 | Bidirectional C and selected C++ ABI runtime qualifications for real GCC, Clang, MSVC, x86-64, ARM64, and relevant standard libraries |
| P4 | cpp2hepta L0/L1/L2/L3 differentiation; classes, RAII, STL, concrete templates, exceptions and invalid retention or alias behavior must not be silently certified safe |
| P5 | Actual LLVM-native representative applications, no undisclosed fallback to Rust/C, CPU/RSS/throughput/p95/p99/size comparisons and failing-input regression tests |
| P6 | Real Agent/model tasks and fair 2×2 baselines, exact receipt/cost accounting, immutable workspace transactions with crash injection |
| P7 | Physical target execution including MMIO/IRQ/DMA preconditions, multicore contention and sustained workload resource and recovery metrics |

PR #14 reports a frozen local 36-gate/998-test subset qualification, but its
own ledger keeps the broader P01–P12 blockers open and actual model trials at
zero. Neither that report nor isolated #36/#37 tests automatically qualify a
new integration SHA. Do not alter the production blocker ledger until gates
are actually run and evidence is bound to the exact final source.
