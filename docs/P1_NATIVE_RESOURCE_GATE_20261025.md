# P1/P5 — Mandatory source-bound Resource IR gate in strict LLVM builds

This document records a scoped implementation increment, **not** full P1 completion.

## Exact stacking / sole authority

- Base: PR #121 exact head b236d424ef8b155812cb014e20217403a2d28d3f, stacked on PR #111 / #107.
- Sole source semantic producer: hepta.semantic_ir.lower_checked_program.
- Sole checked-source resource lowering: hepta.resource_lowering.lower_resource_ir.
- Independent resource CFG/loan validator: hepta.resource_ir.verify_resource_ir.
- Rust native reference remains mandatory; no parallel checker or backend.
- Keep whole_project_blockers_closed=false and existing legacy proof claims.

## Real native entrypoint blocker closed within strict scalar scope

Previously build_llvm_ssa_source could publish an LLVM artifact after Rust
reference, canonical HSIR, CFG and SSA validation without requiring the
existing source-bound Resource IR check. Resource inspect/export entrypoints
did not enforce the native codegen entrypoint.

Now the strict source-native LLVM pipeline executes
hepta.native_resource_gate.qualify_native_resource_source immediately after
canonical HSIR rederivation and BEFORE CFG/SSA/native compilation.

The native resource gate:
1. Requires a checker-accepted AST and exact canonical HSIR SHA-256.
2. Re-lowers this AST using the existing hepta.resource-ir.v3 authority.
3. Rechecks source identity through verify_resource_source_origin, not
   merely a self-rehashed JSON resource artifact.
4. Independently verifies the resource graph's loan/ownership/CFG properties,
   complete function inventory, and absence of unverified foreign obligations.
5. Requires every proof-claim value to be the exact bool; 0 is not false.
6. Rejects unsupported profiles/operations and forged source/project
   identities before a machine-code compiler is invoked.
7. Adds source_bound_resource_cfg_checked=true and a source-bound
   hepta.native.resource-gate.v1 receipt to the strict native build,
   including its exact resource_ir_sha256 identity.

This is a mandatory source-bound *abstract resource validation* for the strict
Hepta→LLVM CLI. Legacy lower-level LLVM entrypoints retain explicitly
unqualified semantics; this change does not grant them a source proof.

## Explicitly unproved scope

The resource CFG abstracts copied scalar values and is NOT executable HMIR.
No proof yet establishes the source→resource lowering preserves functional
value semantics. The LLVM backend does NOT consume resource operations for
native code generation. Full pointer provenance, general Drop/unwind, stored
borrows, callbacks, C++ ownership, concurrent aliasing and general FFI
memory safety remain open.

Keep the following false:
- source_to_resource_ir_refinement_proved
- native_codegen_consumes_resource_ir
- whole_language_memory_safety_proved

The strict native backend remains the limited i32/u32 scalar SSA profile.
Resource-using code outside that subset may pass the independent resource
verifier but cannot be silently promoted to a qualified native artifact.

## Canonical project identity bug found and repaired

The first integration uncovered an actual P0/P1 mismatch: the scalar HSIR
adapter built a canonical snapshot with project_sha256=null, but the resource
source-origin checker built its canonical snapshot with project_sha256 set to
the loaded project graph identity. Since the project field participates in
the canonical digest, those two valid same-source snapshots could NEVER have
the same SHA when invoked by the strict native CLI.

The adapter and its source-projection verifier now accept the optional
project_sha256 argument; default null preserves existing caller behavior.
The strict native pipeline passes the exact same LoadedProject.identity to
both the canonical/scalar HSIR projection and Resource IR source verifier,
and binds it in the native receipt. A different or stale project graph SHA
causes a controlled origin rejection. No parallel semantic authority added.

Tests now explicitly cover matching project SHA, default/unbound backward
compatibility, and rejection of two different project identities.

## Whole-receipt rejection boundary

The strict LLVM consumer no longer trusts only a handful of positive booleans
on the Resource IR receipt. It calls require_native_resource_receipt, which
independently checks its complete versioned field inventory, exact positive
and negative claims, source/project/canonical/resource digests, provenance
schema and function count. A forged or incomplete receipt cannot authorize
Clang or artifact publication.

Negative tests include bool-versus-int impersonation, removed/added fields,
wrong source identity, missing Resource IR digest, stale project SHA and
mismatched function counts. The actual verifier source's Git blob
50a7db3286801be98cee07277587349d7d76bfe8 was used in an isolated
Python 3.13.5 harness (controlled Resource IR dependencies):
13/13 isolated tests passed, including 300 deterministic source replay and
tampering cases. This is not an integrated Hepta native validation.

## Test changes

tests/test_native_resource_gate.py adds:
- Checked scalar-loop positive Resource IR source receipt;
- Exact source-hash and stale-program rejection;
- Proof boolean/int confusion and unproved foreign obligations rejection;
- Forged source-origin receipt rejection;
- Native source-build refusal before Clang and no publication on gate failure.

tests/test_llvm_ssa_cli.py now asserts the new mandatory receipt and repairs
mock native compiler function signatures for the existing (ssa,cfg) contract,
so artifact digest failure tests exercise the intended rejection stage.

Reproduction from an exact-source checkout:
    python -m unittest tests.test_native_resource_gate tests.test_resource_source_origin -v
    python -m unittest tests.test_llvm_ssa_cli tests.test_llvm_ssa_integration -v
    python -m unittest discover -s tests -v

These tests are committed, but full Hepta native Rust/Clang qualification has
not been run in the current GitHub-connector-only environment. No CI outcome
is being treated as a development dependency.

## Next semantic engineering priority

- Make typed Place/Move/Loan/Drop/Provenance first-class in a single
  executable HMIR, with conditional Drop, partial initialization and failure
  control flow.
- Independently verify source AST→HMIR and HMIR→LLVM/refinement against the
  Rust reference on positive, negative and adversarial source programs.
- Expand C/C++ migration, ABI, Agent, hardware and production tests only
  under the same semantic authority, without elevating unproved claims.
