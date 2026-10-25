# P0/P4/P6 source-bound integration hardening (2026-10-25)

Exact upstream PR #48 commit: e84fba15b347a9e23b0d6e607224031668d8207f.
This is an incremental Draft contribution, not a language-release qualification.

## P1: canonical HSIR fail-closed admission

The scalar CFG/SSA adapter now requires the complete reviewed canonical HSIR
v0 top-level field inventory, the complete set of false prototype proof claims,
and empty, properly typed nominal/foreign/volatile/Owned inventories. Rehashed
snapshots that omit external obligations or introduce unreviewed semantic fields
reject; a digest cannot be a substitute for checking the supported subset.
This adds no new Ownership/Provenance/Drop semantics or whole-language proof.

## P4: hidden C++ preprocessing

The strict cpp2hepta L1 pilot had rejected lines beginning with # but not the
equivalent C++20 %: preprocessing digraph. Clang also accepts directives after
comments and directives formed by physical line splicing. These forms were
reproduced with real Clang 17 at -std=c++20 -Werror.

Since this L1 translator has no build-configuration or preprocessor capture,
any # or %: token sequence or backslash-newline in the source now rejects
conservatively, even inside comments/strings. More permissive handling
requires a project-aware source-identity and macro model.

## P6: canonical semantic evidence

The existing read-only Agent semantic query previously checked that HSIR
supplied a 64-character SHA-256 string, not that the hash matched its payload.
It now recomputes the digest using the sole canonical semantic IR serializer,
requires the known v0 prototype claim flags to be false, and rejects malformed
native-validation metadata as a structured WorkspaceError.

## P0: bounded qualification

The exact-head workflow runs the HSIR bridge, C++ L1 and Agent semantic-inspection
test suites including the new negative controls. The existing full pinned release
workflow is also enabled for this branch. Both must report complete results for
the *new exact HEAD* before their results can be called passed. None of P0-P7 or P01-P12
is marked complete by this change. whole_project_blockers_closed=false.

## P1 addendum: no semantic widening through scalar SSA effects

The canonical scalar HSIR bridge now validates that function declared and
inferred Effects are well-formed lists restricted to the existing `panic`
subset, with no implicit effects beyond the declared upper bound. It checks
only the already-supported function-level zero-allocation/nonblocking/
non-suspend/non-spawn resource clauses, rejecting malformed, missing, unknown,
nonzero, incorrectly typed or elevated values. The boolean `false` is not
permitted as a substitute for numeric `heap_allocations=0`.

Negative tests reseal malicious HSIR snapshots to ensure that a correct
SHA-256 digest is not mistaken for a semantic proof. The original canonical
source encoder and full frontend continue to be the authority; this narrow
adapter does not become a separate borrow checker or general optimizer MIR.
