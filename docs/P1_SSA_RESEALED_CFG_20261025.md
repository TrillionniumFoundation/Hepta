# P1: fail-closed scalar SSA input validation (2026-10-25)

This draft adds defensive admission to the existing `hepta.ssa` pass. It does **not**
introduce a second semantic authority, new ownership checker, or backend.

A content hash on an external CFG snapshot is an identity check, not proof that
the payload came from Hepta's compiler. Previously a rehashed input could
place JSON arrays in type/operator/effect fields and trigger an unstructured
Python `TypeError` instead of a stable `SSARejected` diagnostic. The source
input also accepted JSON's nonstandard `NaN`/infinity tokens.

The updated SSA boundary requires exactly the known scalar type fields,
string-valued operation tags, finite numeric literals and a list of known
effect names. It rejects unknown fields, unhashable symbols and nonfinite JSON
constants before emitting an SSA snapshot. Negative controls mutate a
valid scalar CFG, reseal its digest, and require fail-closed structured
rejections.

The original algorithm (CFG dominance, liveness-based PHI placement, typed
SSA versioning, independent structural verifier) is not altered.

## Remaining limits

This is boundary hardening for a *restricted scalar* IR. It does not prove
source-to-CFG semantic fidelity, ownership/loan/provenance soundness, FFI
contracts, complete formal SSA validation or compiler backend refinement.
P0–P7 and P01–P12 production gates remain open.

`whole_project_blockers_closed=false`.
