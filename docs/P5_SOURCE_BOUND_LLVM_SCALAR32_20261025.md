# P5: source-bound checked i32/u32 LLVM integration

## Source identities and integration decisions

- Starting main candidate: 51287478afcab344e210580f162f59e353b2abd9.
- SSA effect/resource prerequisite: 2dc0422822196906d84b7d6a40c7bdb8aa3e2055
  (local cherry-pick 2e20327).
- Reviewed optional LLVM-origin implementation:
  96cfdba333ff5bd7cc9cadcd5702b59b6db1efab, PR #108.

This integration ports the useful textual profile and exact SSA/CFG origin
checks from #108 without replacing its entire older backend tree. It retains
main's checked unsigned arithmetic, unsigned comparison predicates, hashed
scalar32 profile marker, bounded Clang capture, no-replace output publication,
and ELF/COFF/Mach-O section-payload bounds.

## Changes

1. Native compiler entrypoints now reject LLVM text outside the scalar
   generator's bounded vocabulary, including extra declarations, globals,
   raw memory operations, inline assembly, and unknown calls. Both signed
   and unsigned generated modules are supported. This vocabulary check does
   not establish that a module implements a particular source program.
2. When SSA and CFG snapshots are supplied, the backend reruns the independent
   SSA verifier and regenerates the exact expected LLVM module. Rehashed
   return-value, signedness, overflow-intrinsic, provenance, or profile changes
   cannot reuse that source identity.
3. The source-facing build pipeline always supplies both snapshots and
   requires the native receipt to report the origin recheck. The flag is also
   exposed in the outer build receipt. Supplying only one snapshot is rejected.
   Standalone IR APIs retain an explicitly unqualified mode whose origin flag
   is false; this mode cannot be promoted through the source-facing pipeline.
4. Object-format qualification now rejects malformed input types, unknown
   targets, and invalid ELF identification/header versions while preserving
   the stronger existing payload, relocation, and load-command bounds.
5. The capture test uses a real generated profile fixture. Native-receipt
   corruption tests retain all valid identity fields before changing the
   tested field, so artifact-digest rejection is actually exercised.
6. Removed an imported TestCase class from the target test module; it caused
   eight backend tests to be run twice and inflate the apparent test count.

## Native execution evidence

Environment: Linux x86_64, Ubuntu Clang 20.1.2
(0ubuntu1~24.04.3), rustc 1.90.0 (1159e78c4 2025-09-14).
The pinned Rust gate remains enabled. The disk was full, so native test files
and the pinned Rust installation were placed in a RAM temporary directory.

- Clang executable SHA-256:
  b15e7640bf3082f36ef14321711706b265df3058721e3c2caef3a4b83895d07d.
- rustc executable SHA-256:
  e6abf55ab1859e7c990be77fd593f51661ea99fb2fde626ae9f4108aaa34e7fa.
- Compiler Python-tree hash for this test run:
  a30285c039e259e775075b2d98ffe9927f4b7492a2c997f93f1207c4bc96a395.
- Frozen differential Hepta source SHA-256:
  4463616c5cde875b6c47498ed95ec7720ba66e2cce7e7ae6a7a1f9e7cd86ad7c.

The new differential fixture contains 20 exported functions, with homogeneous
i32 or u32 types per function and both kinds in the same module. The same
checked Hepta source is compiled into an actual pinned-Rust shared library
and an actual LLVM/Clang shared library. Both are executed:

- 2,412 scalar cases, 4,824 native function invocations: all agree with the
  explicit mathematical expected result.
- Covered signed/unsigned add, subtract, multiply, all six comparison
  predicates, signed negation, and unsigned loop/branch PHIs.
- Inputs include signed extrema, unsigned values on both sides of 2^31,
  2^32-1, Cartesian edge combinations, and fixed-seed random cases.
- Fourteen isolated processes test overflowing signed/unsigned add, subtract,
  multiply, and signed minimum negation on both backends. All terminate with
  SIGABRT, matching the checked-arithmetic contract.
- Origin-bound i32/u32 objects compile on all five existing target triples:
  Linux x86_64/aarch64, Windows x86_64 MSVC, and Darwin x86_64/aarch64.
  Cross-target objects are not executed or ABI-qualified.
- Existing five-target object/corruption tests remain active, including 25
  malformed/truncated objects and out-of-file payload tests.

Final focused run: **36 unique tests, zero failures/errors/skips**, covering:

    python3 -m unittest \
      tests.test_llvm_ssa_origin tests.test_llvm_ssa_backend \
      tests.test_llvm_ssa_capture tests.test_llvm_ssa_object_layout \
      tests.test_llvm_ssa_target tests.test_llvm_ssa_integration \
      tests.test_llvm_ssa_cli tests.test_llvm_ssa_native_differential -v

For the recorded environment, PATH included /usr/lib/llvm-20/bin and the
installed Rust bin directory; RUSTC selected that exact rustc and TMPDIR
selected the RAM test directory. No gate was disabled to obtain this result.

## Remaining scope and independently observed dependency

The additional existing test_stateful_migration_llvm test failed before LLVM,
with E_C_FOR_SHAPE in C++ for-loop migration under Clang 20. That failure is
reported to the migration integration owner; it is not included as a passing
LLVM result or converted to a skip.

These results close the tested scalar32 native input/provenance integration
gap. They do not prove general backend refinement, full-language soundness,
arbitrary C/C++ translation, general memory/ownership LLVM lowering, foreign
code safety, or cross-target execution. The corresponding receipt claims
remain false. Bounded compiler subprocess capture is not an operating-system
sandbox, and this workflow does not defend against a malicious compiler or a
malicious same-user filesystem adversary.
