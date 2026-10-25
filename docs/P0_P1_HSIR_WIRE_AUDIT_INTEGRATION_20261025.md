# P0/P1: exact upstream HSIR FFI audit guard integration (2026-10-25)

## Source identity / no parallel implementation

Target parent: PR #101 exact commit `b95b4cd4473e39d349be28049b48005b9ea40eb4`.
Imported original work: PR #100 exact commit `9664a09aa6e4ac6c4d9a53fbfa37b10e0d94b701`.
Only the two previously unchanged audit/test paths are updated, by exact
existing Git blob identities (not rewritten/cherry-pick approximations):

- `tools/audit_hsir_wire.py`: baseline 67810810317cbc8baeae330cf6171b50014f62c5 -> c35358ab4da1c355ce5dda38f4591e0b8ca0f60a
- `tests/test_hsir_wire_audit.py`: baseline cda33c2ac5fb8ce77619a0e4b2c0223f7bb9c287 -> d9b5af47eb9d3e28e75bd475edab9766d2c2dbee

Both baseline blob identities were checked against the target tree before
replacing them; no C/C++ migrator, semantic owner, CFG/SSA or native backend
file was modified by the transplant.

## Exact functionality and acceptance

The audit tool rejects rehashed canonical HSIR v0 external obligations
with forged `status`, duplicate/unknown reasons, missing or extra
contract fields. It accepts only the reviewed unresolved source-bound
obligation envelope. This is a *wire-audit guard*, not a memory-safety
proof, FFI contract discharge or whole-language verification.

PR #100's author ran 15/15 focused tests against exact source blobs.
That evidence belongs to that isolated source snapshot; the integrated
HEAD has not been re-qualified in this tool runtime.

The versioned derived scalar `hepta.hsir.scalar.v1` remains separate
from the canonical checked-source `hepta.hsir.v0` (PR #97 integration).
Do not infer semantic equivalence from either the digest or schema label.

All P0–P7/P01–P12 production blockers remain open unless independently
qualified; `whole_project_blockers_closed=false`.
