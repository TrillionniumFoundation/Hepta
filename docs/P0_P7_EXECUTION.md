# Hepta P0–P7 execution ledger (2026-10-24)

This document distinguishes **implemented prototype work** from **qualified
production behavior**. A passing subset is not a passing production gate.

## P0 frozen starting reference

- Repository: `TrillionniumFoundation/Hepta`, default branch `main`.
- Baseline commit: `48600e3126f7ddf930ed4006476dd01d7a92e473`.
- Baseline Git tree: `c17e7d055ee1b8d45cb0359f36c94640ac88c183`.
- Published Hepta 0.2 source snapshot from `artifacts/release-validation.json`:
  `0b7a747bd732cea30d2e914c7080ac58086e11eca4fec44b0592d4b23d1b772f`.
- Published 0.2 qualification: 13/13 subset gates reported passed; 393 unit and
  integration tests reported passed, no skipped tests. The latest `main` commit
  was a README update; the artifact is for the exact snapshot named inside it,
  **not** an independently rerun qualification of this branch.
- Published `whole_project_blockers_closed=false` and P01–P12 still open.

The local environment used for the first migration slice has Python 3, Clang
17 and GCC. It does not have `rustc`, `cargo`, Lean, physical target boards or
access to clone GitHub. Thus local targeted tests can be reported, but **P0
full-release replay and P7 hardware qualification are not passed**. A full
qualifying rerun requires the pinned Rust toolchain, actual cross-target tools,
Lean 4.19.0, QEMU and a pinned, unchanged project source snapshot.

## P1/P3 experimental slice

The new `hepta.hsir` module is a deliberately restricted, validated expression
IR, not the final whole-language IR. It supports copy-only i32/u32 values,
pure parameter references, literals, checked signed arithmetic, wrapping
unsigned arithmetic, scalar comparisons, return statements, and total if/else.
It rejects unknown IR nodes rather than interpreting them as text fragments.

`tools/c2hepta.py` asks Clang to parse a C11 translation unit into a real JSON
AST. It accepts only exported, fully defined scalar functions with exactly
one terminal return or a total `if/else`. It rejects pointer operations,
globals, macros/preprocessing, user typedefs, promoted/narrowed arithmetic,
varargs, hidden ABI features, C++, calls, loops, and all unsupported operators.
C's unsigned wrap is preserved using Hepta `wrapping_*` operations. C signed
overflow is undefined; the emitted Hepta checks and may panic on overflow;
therefore functional parity is claimed **only for C-defined inputs**. No
runtime or native performance advantage is claimed.

Usage from the repository root:

```sh
python tools/c2hepta.py sample.c -o generated.hepta --report migration.json
python tools/c2hepta.py sample.c -o generated.hepta --report migration.json \
  --verify-native --rustc /path/to/pinned/rustc
python -m unittest discover -s tests -p test_c2hepta.py -v
```

`--verify-native` is fail closed: it demands successful Hepta frontend validation
and the existing Rust backend. Without the native verification flag the report
keeps `backend_validation=not_run`; the migration remains an experimental HSIR
subset even if its checks pass. Frontend qualification is recorded separately.
A rejected file emits a JSON reason and exits with code 2; it does not emit a
partial new `.hepta` file or overwrite previously generated output.

The targeted test suite exercises Clang acceptance/rejection, positive ABI
scalar emission, unsigned arithmetic, proof-obligation rejection, deterministic
HSIR identities, and GCC execution against defined arithmetic expectations.
The GCC check **does not execute generated Hepta** and cannot close P3. No AI
coding productivity data was collected.

## Remaining release gates

| Phase | State | Non-negotiable completion evidence |
| --- | --- | --- |
| P0 | **Blocked** | Full clean-tree P0 replay using pinned native Rust/GCC/Clang and complete reports. |
| P1 | **Partial** | Whole-language HSIR, borrow/provenance/regions, effect/refinement soundness and Rust backend equivalence. |
| P2 | **Partial** | Real multi-target C ABI calling/layout differential, Windows/AArch64 actual host execution, FFI lifetime audits. |
| P3 | **Experimental subset** | Real C project conversion, Hepta native compile/execute, coverage, cross-checks, performance and migration safety level. |
| P4 | **Open** | C++ class/template/exception/destructor wrapper generation, ABI matrix, independently verified lifetime contracts. |
| P5 | **Open** | C++ source conversion with strict/checked/legacy classifications, adversarial behavior and resource benchmarks. |
| P6 | **Open** | Production Rust-native compiler, multi-file semantic transactions, proof/receipt binding and incremental build. |
| P7 | **Open** | Host ARM/x86/Windows and embedded boards, GPU, failure injection, memory/latency/stress evidence. |

Never turn a gate green because an optional dependency was missing, because a
frontend accepted a file, because a fixture passed instead of a real model,
or because a C binary ran when the generated Hepta artifact did not.
