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


## Executed 2026-10-25 P0/P1 integration gate increment

A GitHub object-tree inventory was captured at the exact pinned heads above and
stored in evidence/integration/p0-frozen-heads-20261025.json.
Compared with main 0.2: PR #14 changes 1065 paths, PR #36 changes 35, and
PR #37 changes 61. PR #14/#36 and PR #14/#37 have five shared changed paths
each; all five have different final objects. PR #36/#37 share 34 changed
paths, with 23 identical final objects and 11 different final objects.
GitHub compare reported main as the common ancestor of all three heads.
This is metadata-only source identity evidence, not a merge result.

The old path-only auditor has been upgraded to hepta.integration-audit.v2.
It reads exact Git tree object IDs and modes and reports identical-vs-different
objects without hiding rename/delete edges. It classifies paths sharing a
semantic role across different filenames, including semantic_ir.py and
hsir.py, hmir.py versus cfg.py/ssa.py, two C migrators, C++ bridge
components and Agent transaction implementations. Its output is always
manual-review-only. Missing objects and path/tampering errors reject.

**Verified HSIR wire-version collision:** PR #14
hepta/semantic_ir.py and PR #36 hepta/hsir.py both export the
literal hepta.hsir.v0 but use incompatible envelopes. The first uses
profile=checked_typed_ast_not_verified_mir, module, project_sha256,
external_obligations and an embedded payload sha256. The second uses
status=checked_frontend_snapshot_not_proved, program,
external_assumptions, typed_expression_count, and a separate
HSIRSnapshot canonical-JSON hash. They also carry different explicit
unproved safety claim names. Reusing the version label is **not** a safe
forward/backward-compatible schema transition.

tools/audit_hsir_wire.py independently reads serialized exports with
duplicate-key rejection, verifies the profile-specific canonical SHA-256,
source identity and unproved claim fields, and refuses to mark different
envelopes compatible. Exit 3 denotes a validly digested schema collision;
exit 2 means invalid input or an unavailable output; exit 0 means only
same wire format, **not** semantic equivalence or safe merge. Use:

    python tools/audit_hsir_wire.py --left /tmp/pr14-hsir.json \
      --right /tmp/pr36-hsir.json --output /tmp/hsir-wire-review.json

A real producer-generated snapshot from *each* head and a mapping
implementation have not yet been tested in one compiler runtime. The
canonical schema version and any lossless, independently checked mapping
remain P1 blockers. Never remove unknown obligations or silently promote a
foreign assumption to proved during conversion.

**Local targeted test result:** python -m unittest discover -s tests
-p 'test_*audit.py' -v passed **14/14** in an isolated Python 3.13.5
working directory, including a newly created native Git repository used for
rename and byte-object identity checks. Four exact Git blob identities for
the tested files were independently fetched from the updated PR head and
match the local tested bytes. This session did **not** fetch the entire Hepta
worktree or run Rust/Clang/Lean/QEMU/real model qualification. Remote CI and
final production P0–P7 gates are not inferred from these focused tests.

**Still required to close P0/P1:** select a single canonical typed snapshot
and version it, compare all fields and consumer APIs, add real producer and
consumer integration fixtures, prove or independently test source-to-IR
preservation, and rerun native and resource-negative suites on the new
integration SHA.
