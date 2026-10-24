# Conservative scalar policy composition

Candidate base: #20, `64c85e4716eb9882bdd667beffe7e36f2fc30fb9`.
Same-instance donor: #21, `32f858f6b0bdbe40837302b1a439a9ded7bd8032`.
This is a new draft child, not a merge into either owner branch or a declaration
that this historical line is canonical. Latest #14 at
`cbb03dfd6efbe68253c2be1e59eacdeb93f9dfc5` is not imported; its namespace/provider,
backend/workspace and 21-gate evidence are not qualification of this candidate.

## Source composition

The existing #20 `_active_declarations`, `_physical_location_files` and
`_ast_objects` are unchanged. They still inventory active translation-unit
state, reject header globals/prototypes/function definitions and unknown or
cross-file function locations, and preserve ordinary header type context.
Only the scalar AST acquisition point changes to the #21 same-instance envelope.
Original `ast_json` property order must be preserved for physical-file elision.
No duplicate #18 main-only inventory is introduced.

The #19 direct-library guard already present in #20 remains byte-identical in
`tools/c2hepta.py`, with all its tests retained. It rejects resolved source,
output and report path aliases before reading or publishing. It is not universal
hardlink equivalence, destination no-overwrite, or namespace race protection.
The scalar pilot's existing atomic no-overwrite publication also remains intact.

The #21 helper, Python transport, checksum lock, offline build script and two
new test modules are copied without semantic changes. C++ and project migration
remain separate consumers and are not claimed to gain this macro policy.

## Explicit policy reconciliation, not a miscompilation claim

#20 deliberately accepted an operator macro and demonstrated correct results
for six defined input pairs. The historical fixture and generated/original
comparison remain available at the immutable donor source:

[Historical OP differential fixture](https://github.com/TrillionniumFoundation/Hepta/blob/64c85e4716eb9882bdd667beffe7e36f2fc30fb9/tests/test_c_migrate_active_translation_unit.py#L147-L181).

This candidate chooses the stricter supported-source policy: actual active
main-file macro expansions reject. Its test retains the exact OP source, the
same six defined input pairs, and original-C native oracle, but now explicitly
requires `E_C_MACRO`, empty converted output and no published/staged files.
The two other include-only operator and semicolon cases retain their original
C/generated-C/wrong-result differential checks. This does not claim those
include-token origins or transitive header/configuration bytes are frozen.

Five existing macro inventory tests now report `E_C_MACRO` before the later
`E_C_TOPLEVEL` inventory check: first/after/nested macro globals, header-defined
macro expanded in main, and main macro typedef. The inputs, no-output assertions
and rejection requirements are unchanged. Non-macro declaration negatives still
reach the full inventory, including header state/prototypes/bodies and synthetic
missing-location rejection. Diagnostic precedence is an intentional consequence
of the early macro gate, not a removed safety assertion.

## Validation boundaries

The unchanged five #21 regression tests against this exact #20 base produced
eight failing assertions, zero errors. This includes dependency-policy tests,
not eight distinct semantic miscompilations. After composition, all 54 focused
migration tests passed. Full exact-source and independent-review results are
reported with the draft publication, not inherited from #20 or #21 receipts.

The required pinned helper, runtime limits and build profile are documented in
[C_SCALAR_FRONTEND.md](C_SCALAR_FRONTEND.md). Plain included-header typedefs,
header-internal macros, inactive branches and unused macros retain their stated
behavior. No general preprocessor audit, complete dependency CAS, arbitrary
translation equivalence, whole-language soundness or production qualification
is established. No remote CI, merge, network-permission change or deployment.
