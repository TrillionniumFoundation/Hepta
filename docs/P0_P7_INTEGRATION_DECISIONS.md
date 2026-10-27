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
-p 'test_*audit.py' -v passed **19/19** in an isolated Python 3.13.5
working directory, including a newly created native Git repository used for
rename and byte-object identity checks, plus an adversarial deeply nested HSIR JSON rejection. Four exact Git blob identities for
the tested files were independently fetched from the updated PR head and
match the local tested bytes. This session did **not** fetch the entire Hepta
worktree or run Rust/Clang/Lean/QEMU/real model qualification. Remote CI and
final production P0–P7 gates are not inferred from these focused tests.

**Still required to close P0/P1:** select a single canonical typed snapshot
and version it, compare all fields and consumer APIs, add real producer and
consumer integration fixtures, prove or independently test source-to-IR
preservation, and rerun native and resource-negative suites on the new
integration SHA.


## Consumer graph verified against the pinned producer commits

Source inspection of the precise Git blobs finds that the collision is not
isolated to JSON export:

- PR #14: hepta/pipeline.py hsir_analysis calls
  hepta.semantic_ir.lower_checked_program; hepta/cli.py publishes the
  resulting hepta.hsir.export.v0 wrapper. HMIR and resource lowering in this
  branch are separate checked-AST/IR paths, not downstream consumers of
  PR #36's HSIRSnapshot class.
- PR #36: hepta/cli.py builds an HSIRSnapshot with
  hepta.hsir.lower_checked_program and passes it to
  hepta.llvm_scalar_backend.emit_scalar_llvm. The LLVM reader checks the
  checked_frontend_snapshot_not_proved marker and scalar/effect limits.
- PR #37: hepta/cfg.py lower_hsir_cfg requires the PR #36 HSIRSnapshot
  class and digest/schema/status profile; hepta/ssa.py consumes its CFG,
  hepta/ssa_verify.py checks SSA against that same CFG, and
  hepta/llvm_ssa_backend.py consumes both verified SSA and CFG. CLI wires
  these stages separately from the PR #14 HMIR resource paths.

The CFG input guard means a direct PR #14 dict is expected to **reject** at
the PR #37 HSIRSnapshot/type-status boundary. That is desirable fail-closed
behavior, not evidence of cross-branch semantic interoperability.

Next integration deliverable: a versioned canonical v1 snapshot format and
consumer conformance tests for both producer histories, with explicit typed
expression, borrow/owner, lifecycle, provenance, external-obligation and
source/project identity mapping. Unsupported transformations must reject,
and neither snapshot family may have its unproved claims upgraded implicitly.
Only after such a mapping is validated should the CFG/SSA/LLVM consumer be
retargeted. These actions are not completed in this PR.


## Actual producer CLI output envelopes (additional P1 guard)

Source inspection confirms PR #14 hepta hsir outputs an
hepta.hsir.export.v0 wrapper with an hsir member and a separate validation
report; PR #36 hepta hsir outputs HSIRSnapshot.as_dict() and appends a
reference_validation field *after* calculating the payload SHA-256.
PR #37 CFG/SSA/LLVM consumes PR #36's checked snapshot classes.

The P1 wire audit now accepts these two specific command envelopes for
**audit only**. It hashes and validates the embedded original semantic
payload without trusting either outside validation field as part of its
cryptographic identity. A deliberately modified reference_validation
status leaves the underlying payload hash unchanged; that metadata therefore
must never be used by this tool to claim a native pass or semantics proof.
Unknown wrapper forms, nested mismatched producers, malformed sidecars,
duplicate JSON keys and forged true proof claims refuse. The actual CLI-form
comparison is included in the 19 passing synthetic/regression tests.

Only source and output-shape inspections were performed for the producer
branches; actual Hepta native producer commands were not run here.


## P1 versioned scalar HSIR compatibility boundary (additive integration candidate)

The checked source-semantic owner remains `hepta.semantic_ir` with
`hepta.hsir.v0`. The *derived*, restricted scalar CFG/SSA input has now been
renamed to `hepta.hsir.scalar.v1` rather than exporting an incompatible
`hepta.hsir.v0` payload under the same schema name. `lower_hsir_cfg`
requires this exact version. The adapter continues to bind
`source_semantic_sha256`, reject owner/loan/FFI/provenance obligations and
preserve explicit false proof claims. A legacy derived v0 snapshot is rejected,
not silently relabeled. The original audit's PR #14 versus PR #36 historical
v0 collision remains a real finding for those frozen branches; this versioned
candidate removes ambiguity *only along this integrated adapter/CFG path*.

Executable source-to-canonical-to-derived-to-CFG/SSA tests and downgrade
negative cases are in `tests/test_hsir_bridge.py`. Full native refinement,
ownership-aware SSA and formal language soundness are **not proven**.
