# HIA P2: source-bound finite LLVM/native differential evidence

**Scope:** checked `i32`/`u32` SSA only. This document accompanies
`hepta.hia_native_differential`, not a claim of completed Owned SSA v1,
general backend equivalence, whole-language safety or arbitrary C/C++ ABI.

## Existing authorities reused

`qualify_scalar_source(source, cases, rustc=..., clang=...)` compiles
the source through the existing pinned Rust gate, source-bound HIA scalar
Core, Resource IR gate, existing scalar LLVM emitter and strict object
publisher. It separately re-analyzes the current source, re-derives the
canonical semantic graph, CFG, SSA, Resource IR receipt and the exact
HIA core digest. It requires all of those identities to match the
native build receipt and rejects changed project graphs.

It prepares the existing source-qualified `HIAScalarOracle`; the new
`compare_oracle_with_native` **does not** implement another parser,
checker, compiler, SSA algorithm or LLVM emitter.

## Finite differential protocol

- Corpus covers **every exported function**, 1–32 supported functions,
  max 256 total cases, max 16 scalar arguments/call and 64 KiB corpus.
  Inputs must be actual JSON-like Python integers (not Boolean impostors)
  inside exact signed/unsigned 32-bit ranges.
- Results are executed in fresh isolated child processes. A valid
  unsigned/signed integer result is compared with the existing HIA
  scalar SSA oracle. The observed native `SIGABRT` is counted as a
  *finite matching checked-arithmetic trap* **only when** the oracle
  also predicts that trap. Segfaults/other signals/nonzero exit,
  unexpected outputs, timeouts and oracle budget exhaustion reject.
- Native child uses Python `-I`, no shell, no repository imports and
  `RLIMIT_CORE=0`. This is **not** a secure OS/process sandbox and
  does not prevent hostile native code from accessing host resources.
  Execute only artifacts obtained from the reviewed Hepta compiler path.
- Binary is a non-symlink regular file capped at 8 MiB. Exact bytes are
  reread between cases and after the final run. Receipt includes
  artifact SHA-256, corpus SHA-256, observed counts, project/Core/SSA
  and compiler identities on the source-qualified route.
- This is a *finite observation*, not exhaustive equivalence, soundness
  of the native compiler, general FFI compatibility or physical-board
  execution. Crashes with matching SIGABRT are not accepted as a proof
  of the precise underlying crash cause.

## Test execution

    python -m unittest tests.test_hia_native_differential -v

A C-built shared-library control checks the child ABI and error/trap
classification without claiming it represents compiled Hepta. An
additional Hepta end-to-end test requires pinned Rust and native Clang:
it compiles two mixed i32/u32 exports through the actual Core/LLVM path,
then checks eight values/traps.

Local Linux Python 3.13.5 / Clang 17 child-boundary controls: **5/5 passed**
with a real compiled `.so`, including two actual `SIGABRT` observations.
The combined test module also ran its full 6-test inventory, with the
real-Hepta end-to-end test **skipped** because rustc was unavailable
in this container. These observations are bound to the exact new module
Git blob `7274927ef0ba005418785092d091dd03797a5eb2` and test blob
`53f666e3e16d5b9c7b399666a565ba4abe248006`.
The full Hepta checkout, pinned rustc-native and AArch64 target suites
were **not executed** in this container.

## Still open

General executable Ownership/Borrow/Drop/Provenance SSA is not implemented,
and current Owned LLVM still interprets checked AST for numeric operations.
Cross-ABI, all-target native and physical DMA/GPU/IRQ, arbitrary C++ migration,
real-model Agent A/B, sustained p99 benchmarks and formal refinements
remain open. `whole_project_blockers_closed=false`.
