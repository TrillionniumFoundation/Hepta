# HIA P0/P2 exact checked compiler identity during source-native publication

This is a scoped hardening of the existing
`build_checked_hepta_hia_native` for **both** the finite scalar and
finite Owned source-to-HIA profiles. It adds no source checker, parser,
Resource IR checker, SSA converter, native emitter or migration engine.

The existing `hepta.pipeline.compiler_hash()` is the repository's
single compiler-implementation identity: it deterministically hashes
all `hepta/*.py` modules. The actual `analyze_project(...,
native=True, backend="rust")` receipt provides its exact
`compiler_sha256`, already associated with pinned native Rust
validation.

The source-facing HIA builder now rejects a missing, ill-typed or
noncanonical hexadecimal compiler identity, and refuses if the current
compiler implementation differs from the Rust-qualified one. It
rechecks that same exact identity:

1. just after Rust validation and before source-to-Core lowering;
2. immediately after source-to-Core lowering (before LLVM emission);
3. before native compilation;
4. after native compilation but before artifact publication;
5. after no-replace hardlink publication and exact-byte replay,
   retracting only its own published link on rejection.

The native emitter separately checks its own implementation/toolchain
identity. The new source gate closes the gap for **source checker,
Resource IR, scalar converter and owner bridge** mutation during
native codegen; a successful LLVM emitter-only hash is not a complete
source-compiler identity.

`tests/test_hia_compiler_identity.py` provides source-scoped negative
controls for missing/boolean/incorrect compiler identity, compiler
drift before lowering and drift after the mocked lowering for both
profiles. All native calls are mocked in these negative tests, and
must not occur when the gate rejects.

Run on an exact checkout (no CI dependency):

```sh
python -m unittest tests.test_hia_compiler_identity \
  tests.test_hia_scalar_owned_convergence \
  tests.test_hia_source_bridge tests.test_hia_owned_source_bridge -v
```

Compiler hashes prevent unintended version drift, **not malicious
forgery, unrecorded native linkage, hardware/provenance violations or
formal compiler-refinement gaps**. Do not promote this to a
whole-language security proof.

`whole_project_blockers_closed=false`.
