# P1: source-bound HSIR v0 -> native-checked scalar CFG/SSA

This PR extends the versioned HSIR v1 consumer (the PR #55 line of work)
without making unqualified ownership, pointer, FFI or effect conversions.

## Executable interface

    python -m hepta ssa-v1-verify source.hepta \
      --source-bound-hsir pr14-exported-hsir-v0.json --rustc /path/to/pinned/rustc

The HSIR input is the *inner* source-bound v0 object emitted by the PR #14
hepta hsir command, not the outer hepta.hsir.export.v0 result. The input is
bounded and parsed with duplicate JSON-key rejection. The existing Rust native
validation in the PR #37 CLI runs **before** imported source lowering. An
incorrect or unavailable reference compiler fails the command.

The entire original v0 producer is retained in the signed v1 integration
envelope. Its exact SHA-256 and source SHA-256 are checked. The source path
must match exactly, including the span paths. Import/module graphs, resources,
external obligations, owned types, volatile accesses and unknown assumptions
are prohibited in this narrow migration profile.

## Why this is not a JSON field renaming

PR #14's expression types are display strings, while PR #37 uses structured
type values. We **do not** turn a claimed string type into a trusted
structural type. Instead:

1. Parse and type/effect-check the original exact source with PR #37's own
   frontend. Reject if the checked source SHA-256 differs from PR #14 v0.
2. Emit a real frozen_snapshot_v0 with PR #37's checked producer.
3. Compare the two representations node-by-node: source spans, scalar
   primitive types, expression kinds/operators/values/arity, binding type
   annotations, local ownership modes, public signatures, branch and loop
   statements, declared/inferred effects and resource envelopes.
4. Require that every function is a local, nongeneric, by-value scalar
   function. Only i32/i64/u32/u64/bool, integer/bool literals, names, limited
   arithmetic, comparisons, boolean logic, let/assignment, if, while and
   return/expr are accepted. No borrowed inputs, casts, calls, raw pointers,
   foreign functions, match, for, indexing, structs, dynamic resources,
   allocation, volatile access or unproven assumptions are admitted.
5. Send the freshly checked PR #37 native snapshot, **never** the imported
   mutable JSON, into the pre-existing CFG -> pruned scalar SSA -> independent
   verifier. Bind the source PR #14 v0 hash and consumer v0 hash separately.

Source byte identity is necessary but not sufficient: the two independent
typed representations must have matching fields throughout the accepted
subset. The v1 report sets independent_scalar_reparse_checked=true only
for the successfully rechecked source-bound producer. It still reports
native_codegen_qualified_by_adapter=false, memory_safety_proved=false,
source_to_ir_semantics_proved=false, foreign_contracts_proved=false.

The original frozen_snapshot_v0 consumer path remains unchanged.

## Tests and qualification

tests/test_source_bound_scalar_consumer.py adds 12 integration/negative
cases using the actual PR #37 parser/checker/CFG/SSA: a loop+if PHI program,
deterministic identities, source-byte mismatch, missing source, forged
expression type/effect/ownership with correctly recomputed producer/v1
hashes, foreign-obligation rejection, adversarial unhashable operator rejection, unsupported-call conversion refusal
and the real CLI help contract.

The test's source-bound producer fixture encodes the documented PR #14 AST
wire shape using PR #37's parser, **not the independent PR #14 compiler**.
Real cross-branch producer output and an identical native host must be
separately qualified. These tests have been committed but have **not yet been
run** against the complete Hepta branch in the current tool environment.
A successful test would establish only bounded compiler-interface agreement,
not behavioral equivalence, zero runtime cost or Rust-wide performance.

The P0 branch consolidation, full P1 memory/provenance/lifetime IR,
P2–P7 platform/migration/performance/Agent qualification, and original
P01–P12 system blockers remain open.


## Agent-facing malformed import diagnostics

The imported-data path now catches HSIRV1Rejected in the standard typed-IR
error branch and reports status=rejected with the precise E_HSIR_V1_* code,
instead of presenting malformed or duplicate-key HSIR as an unrelated
E_DRIVER failure. A new regression stubs only the native analyze_project
result and supplies duplicate JSON keys to the actual CLI. The test is
native-toolchain-independent but has not been executed in this session.
