# HIA Agent patch impact — static call-graph receipt (2026-10-26)

**Status:** stacked engineering candidate on PR #189 (HIA v4) exact source; not a
whole-project acceptance claim. CI scheduling is not a development blocker;
actual semantic/native tests and exact SHA evidence remain separate gates.

## Why this is one owner, not a competing compiler or patch engine

`hepta.hia_patch_impact.analyze_patch_impact(document, request)` calls the
**existing** `hia_program.verify_program` and
`hia_program_tools.apply_program_patch`. It has no editor, parser, checker,
codegen, or LLVM emitter of its own. Existing `hepta.hia.patch.v1` and v2
interface-preserve/migrate semantics are unchanged. All proof and safety
obligations remain enforced by the same full-module verifier.

The observer accepts only the actual verified candidate and matching
`hepta.hia.patch-result.v1/v2` receipt. Before constructing any report, it
rechecks exact before/after program hashes, full-module verification,
interface-change inventory and v2 explicit migration/qualification claims.
Typed Boolean `is` checks reject `False` disguised as integer `0`.

## Scope of the static analysis

The two complete **verified** program snapshots are traversed for the
closed `call` operation. Both old and new reverse call graphs are retained:
removing a call edge cannot erase an earlier impacted caller. Every changed
function definition is a direct seed, including changed operations, effects,
resource-lifetime instructions, CFG, or signature. A bounded iterative
reverse closure returns all directly and transitively affected callers.

The canonical SHA-256 receipt `hepta.hia.patch-impact.v1` records:

- Exact before/after immutable Core digests and original patch-result schema.
- Directly changed functions and interface-changed functions separately.
- A conservative set of potentially affected functions and a distinct set
  having no static call path to a modified definition.
- Every old/new direct call edge in deterministic sorted order.
- Explicitly FALSE claims for dynamic call reachability, functional
  equivalence, external caller validation, native execution and hardware.

These are **test-selection suggestions**, not a proof that an unaffected
function returns the same value or has unchanged resource costs. Resource
allocator pressure and external consumers are outside the static call graph.
A valid report never implicitly publishes a patched program.

## HIA v3 Agent convergence

The work is stacked on PR #186's versioned same-owner `buffer.move_within`
program and directly exercises its genuine `move_program` test fixture.
It includes the relevant **parallel PR #185 Agent v3-policy regressions**
in an adapted test suite rather than importing its incompatible v3 helper
or overriding the stronger PR #186 ARM64/LLVM implementation:

- Valid v3 whole-module/body patches and legacy v1 patch version retention.
- Explicit v2 preserve/migrate policy and unchanged external-ABI nonclaims.
- Rejection of owner-vs-mutbuf and incorrect usize `memmove` arguments.
- Rejection of missing `write` effects even with `migrate` authorization.
- Old/new reverse caller closure including unrelated functions.
- Stale snapshot and forged Boolean/inventory/receipt rejection.

## Versioned HIA v4 integration

The source stack is a genuine two-parent merge of PR #189's existing
`buffer.swap` / reverified four-op peephole path and the Agent read-only
impact work. All four Agent file blobs were transplanted unchanged onto
the exact PR #189 Git tree; neither the v4 instruction verifier, optimizer,
interpreter nor LLVM code generator was replaced.

A new in-repository regression uses PR #188/189's *actual* `swap_program`
v4 fixture: an allowed body-only byte constant patch changes observed
interpreter results while preserving the ABI, and an attempt to perform
`buffer.swap` with an owner instead of a unique mutable loan is rejected,
even with `migrate` authorization. Its execution remains unqualified until
run against the merged exact checkout.

## Agent CLI

The existing `hepta hia` subcommand now provides a read-only entry point:

    hepta hia impact ./program-v3.hia --request ./patch-v2.json

It returns `hepta.hia.impact-query.v1` with the verified-but-unpublished
patch receipt and conservative impact analysis. Unlike `hia patch --output`,
this command never exposes a published candidate or creates a destination.
The normal CLI's bounded ordinary-file reader and JSON diagnostics remain
in effect. A dedicated regression checks the command's real arguments and
that no output file is created; that full-repository CLI test still requires
execution on the exact stacked checkout.

## Actual evidence and limits

The exact new helper source passed Python 3.13.5 `py_compile` and six isolated
protocol tests against a minimal *stub* for the existing validator and patcher.
The new actual-Hepta in-repository tests were syntax-compiled but **not run
against the full pinned Hepta checkout** in this environment (the repository
cannot be git-cloned here and the required pinned Rust/Clang20 is absent).
No CI status, incomplete smoke or ancestor result is called a pass.

Exact checkout verification:

    python -m unittest tests.test_hia_patch_impact tests.test_hia_overlap_move \
      tests.test_hia_interface_policy tests.test_hia_v2_agent_policy_integration -v

This does **not** close P0 canonical merge, P1 general memory provenance,
P2 whole-backend refinement, P3 cross-toolchain C/C++ ABI, P4 arbitrary
C++ translation, P5 real-agent/model cost A/B, P6 physical hardware and
stable p99, or P7 formal source-to-native soundness.

`whole_project_blockers_closed=false`
