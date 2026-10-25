# HSIR v1 integration envelope — P1 implementation checkpoint

This change adds a concrete versioned cross-branch exchange format to the
PR #14 language pipeline. It does not complete language-wide typed MIR,
memory safety proof, provenance semantics, CFG/SSA refinement, direct LLVM
code generation, or universal C/C++ migration.

## Commands and behavior

- Existing: python -m hepta hsir SOURCE --frontend-only
  remains the original hepta.hsir.export.v0 interface.
- New: python -m hepta hsir-v1 SOURCE --frontend-only
  emits hepta.hsir.integration.export.v1 with an embedded
  hepta.hsir.integration.v1 identity-bound snapshot.
- Omit --frontend-only to retain the normal native compilation gate.
  The resulting pipeline status still determines native qualification.
  The v1 envelope independently claims no native validation, and no
  cached reference_validation metadata may promote that claim.

The v1 export is computed only after the existing PR #14 checked front end
and v0 producer succeed, with source/project identity rechecked against the
active analysis object. A failure rejects the new export with ok=false,
status=rejected, never partial-success output.

## Two explicitly different v0 producer profiles

| Source | Required discriminator | Wire type |
|---|---|---|
| PR #14 semantic_ir.py | profile=checked_typed_ast_not_verified_mir | Source-bound dict with typed display fields, foreign obligations and embedded SHA-256 |
| PR #36 hsir.py | status=checked_frontend_snapshot_not_proved | Frozen snapshot with structural type descriptors and separate SHA-256 |

Both use the label hepta.hsir.v0; this does not imply equivalence. The new
hepta/hsir_v1.py module accepts either unwrapped producer v0 payload after
independently recomputing the canonical content SHA-256. For PR #36 the
caller extracts HSIRSnapshot.as_dict(); an unbound CLI
reference_validation sidecar is not payload provenance. PR #36's compiler
module is not merged here.

The common v1 projection provides function names, ownership parameter modes,
declared and inferred effects, resource metadata, return mode/source where
known, and ABI direction. PR #14's string types are marked
producer_display_only; PR #36's structured type values are marked
producer_structural_unverified. Cross-profile type equivalence is false.
Unmodeled return-loan provenance on PR #36 is unknown, not a safe default.

The entire original source payload, foreign assumptions, external obligations
where available, and both identity layers remain retained. Verification
reconstructs v1 from embedded v0, rejecting even rehashed tampered projections.
Proof claims remain false. No successful projection gives codegen authority.

## Tests and blocked consumers

Local isolated Python 3.13.5:
python -m unittest discover -s tests -p test_hsir_v1.py -v
passed 14/14 against the exact uploaded source and tests. Cases include
deterministic identities, foreign obligations, project mismatch, forged proof
claims, hash tampering, untyped expressions, invalid ownership, expression
count mismatch, duplicate keys, NaN and deeply nested JSON.

Additional real parser/checker/pipeline/CLI integration cases are in
tests/test_hsir_v1_pipeline.py but were not executed here because the
complete PR #14 checkout was unavailable in the local environment. No remote
CI qualification is claimed.

PR #37 CFG/SSA/LLVM still consumes the different PR #36 HSIRSnapshot and
its structural expression model. The v1 projection intentionally cannot
be passed to native codegen. A future consumer adapter must preserve typed
expressions, effects, control-flow, provenance and loans with independent
checks. P0 source consolidation, complete P1 semantics, P2–P7 production
gates and original P01–P12 blockers remain open.

## P1 safety repair: bind resource receipts to actual producer semantics

The independently checked resource-graph entrypoint must not accept a merely
hash-consistent HSIR payload on the basis of equal source_sha256, project id,
and function names. An attacker can change a function's declared effects,
return type or the external obligation inventory, recompute both v0/v1 hashes,
and preserve all three coarse identity checks. The resource graph would still
be generated from the original accepted AST; without replay, the receipt could
bind conflicting descriptions of the *same* source.

The P1 resource integration now runs the original semantic_ir.lower_checked_program
against the actual checked Program and CheckResult with the same project identity,
then compares the **entire canonical v0 payload and its SHA-256** with the v1
producer's embedded source. Disagreement is E_HSIR_RESOURCE_SNAPSHOT_MISMATCH.
This happens before independent resource CFG generation, and does not infer any
native safety or compiler refinement from passing the comparison.

Tests in tests/test_hsir_v1_resource.py mutate effects, return type, and
foreign obligations, recompute valid legacy and v1 identities, and require
rejection against the unchanged frontend-checked source. This repairs the
source-to-HSIR binding, not machine pointer provenance, native codegen proofs,
or the remaining global P0–P7 / P01–P12 production acceptance gates.
