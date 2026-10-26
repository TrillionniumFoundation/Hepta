# HIA P1/P2: verified v1–v6 Core ↔ native child differential

**Primary owner:** `hepta.hia_program.verify_program` plus the existing
`hia_program_runtime.execute_program`, `hia_program_llvm` and
`hia_source_bridge`. This feature adds **no alternative parser, type checker,
ownership checker, VM or native backend**.

## Entrypoints and proof scope

1. `compare_verified_hia_program(core, native_library, cases)`:
   re-verifies the immutable existing executable Core and invokes its **existing**
   interpreter, while running provided native scalar functions in short-lived
   child processes. It independently invokes the existing HIA LLVM emitter
   as an export-ABI profile gate; it does NOT authenticate the native library
   as output of that emitter.
2. `qualify_executable_hia_program(core, cases, clang=...)`:
   additionally compiles the verified Core using existing
   `hia_program_llvm.build_program_native`, cross-checks Core and native
   artifact identities, then compares finite VM/native observations.
   This is **standalone Core**, not authenticated Hepta source.
3. `qualify_checked_hia_source(source, cases, profile="owned", ...)`:
   compiles from Hepta through the existing **pinned Rust** source gate,
   `hia_source_bridge.build_checked_hepta_hia_native`, Resource IR and
   the **single HIA Core native emitter**. It independently reloads current
   source and reproduces the same Core and Resource IR/project/compiler
   digests before/after the finite native comparison.

The historical `qualify_scalar_source` remains an older scalar-profile
adapter only. New v6 Owned compilation must use the third entrypoint above.

## Closed finite ABI profile

The initial executable-v6 differential supports **only** functions with
homogeneous `i32` or homogeneous `u32` arguments and one scalar return of
the same type; nested internal operations may use the existing supported
Owner, Borrow, Drop and byte-memory semantics. Corpus must cover the **exact
complete native export inventory**, not a handpicked subset.

The existing HIA VM records finite resource state and normal-path cleanup.
Native child observations check scalar outputs and specific
`SIGABRT`/normal outcomes only. Matching scalar returns do **not** establish
native allocator cleanup or pointer-provenance correctness. Independent
allocator/fault instrumentation remains mandatory for those claims.

The child transport handles signed/unsigned 32-bit values, max 256 cases,
max 16 arguments/case, 64 KiB corpus, up to 8 MiB native image, short-lived
isolated Python `-I` processes and file-backed 4 KiB stdout/stderr caps.
An observed `SIGABRT` matches only a Core VM defined trap. Timeouts, VM
budget exhaustion, SIGSEGV, unexpected exits, wrong results, missing exports,
changed native bytes, and malformed source/receipt identities reject.

This is **not** a hardware/OS security sandbox; the native code and installed
compiler/loader/runtime remain trusted.

## Evidence separation

The comparable direct-core API produces
`native_compiled_from_program_verified=false` and
`checked_hepta_source_replayed=false`. The standalone build path only
upgrades the first when actual Core codegen succeeds. The source path can
upgrade both after pinned Rust and complete source identity replay.
All paths preserve `backend_refinement_proved=false` and
`whole_language_soundness_proved=false`.

## Tests

    python -m unittest tests.test_hia_native_differential tests.test_hia_v6_differential -v

Local Linux Python 3.13.5/Clang17:

- 7/7 actual C shared-object subprocess transport regressions passed:
  signed/unsigned, two real SIGABRTs, SIGSEGV refusal, output flood,
  missing corpus, wrong return, budget and invalid-library controls.
- 2/2 isolated v6-adapter tests passed, against mocked v6 verification/VM
  dependencies but **real** Clang17 native shared-library calls.
- The actual HIA v6 parser/verifier/VM source tests and Clang20+ source-native
  tests have **not** been executed on a full Hepta checkout here.
  The test file retains conditional Clang20 and pinned-Rust qualifications.
  Clang17 transport success is not a substitute for the native HIA Clang20 gate.

Exact tested Python module Git blob:
`a5904898e943b5ee4de7d92791ba83c44f07b181`.
The new v6 test file is a checked-in qualification input, not a passed
full-repository claim.

## Still open

Full general Ownership SSA, source/Core/backend semantic refinement,
mixed-width/multi-result ABI, arbitrary C/C++, all-host MSVC/Clang/GCC,
GPU/NPU/DMA hardware and real-model agent/economic qualifications remain
OPEN/PARTIAL. `whole_project_blockers_closed=false`.
