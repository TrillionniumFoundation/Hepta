# P1: HSIR v1 + independent owned-resource CFG integration

This increment is stacked on PR #53 and uses the already-qualified PR #14
resource lowering and independent verifier, not a second ownership algorithm.

## Implemented

The command `python -m hepta hsir-v1-resource SOURCE --frontend-only`
uses the existing checked project pipeline and the lossless v1 source-bound
HSIR, then runs `lower_resource_ir` and `verify_resource_ir` on the same
parsed program. It rejects project/source identity changes, a different
function inventory, unsupported resource/borrowed-storage/IO profiles,
invalid foreign obligations, forged proof claims and invalid resource graphs.
The returned binding hashes both the v1 HSIR and the independently checked
resource CFG. The original `hsir` and `hsir-v1` commands are unchanged.

The original checked frontend and any Rust native qualification remain
authoritative. `--frontend-only` can never become a native pass merely
because this resource verifier succeeds. Resource verification checks the
finite abstract ownership/loan graph; it is not a source-to-resource-IR
refinement theorem, machine-level pointer provenance proof or full compiler
safety certificate.

## Verification state

Tests added in `tests/test_hsir_v1_resource.py` cover a real owned-buffer
program, a multi-file owned library, source identity mutation, forged v1
proof, rejected frontends and unsupported clauses. These tests are committed
but were not run in this session; no claim of passing or P1 closure is made.

Still open: universal lifetime/outlives/trait semantics, source-to-IR proof,
resource-aware SSA/LLVM, foreign contract qualification, broad C/C++ safe
migration, hardware qualification, and all P0-P7 / P01-P12 system gates.
