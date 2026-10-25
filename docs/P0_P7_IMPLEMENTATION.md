# Hepta 0.2 → Agent-native systems language: P0–P7 engineering ledger

## P0 frozen reference (not a claim that this development branch passed it)

- Repository: `TrillionniumFoundation/Hepta`
- Reference main commit: `48600e3126f7ddf930ed4006476dd01d7a92e473`
- Reference release evidence: `artifacts/release-validation.json`, schema `hepta.release.v2`
- Reference source snapshot SHA-256: `0b7a747bd732cea30d2e914c7080ac58086e11eca4fec44b0592d4b23d1b772f`
- Reference compiler SHA-256: `909819724de6654794d11dcc49148c5852f197843e5d9ba7c7671c3468b110ab`
- Reference test report: 393 unit/integration tests, 13 passing release gates (reference commit only).
- Reference release claims: `whole_project_blockers_closed=false`; 0 measured provider-backed AI-model runs; no whole-language soundness, global memory budget, hardware execution, general performance superiority or agent productivity proof.

A successful reference release is *not* automatically a successful qualification of changes made on this branch. Regenerate receipts from the final candidate commit before calling any new gate passed. The current profile is a research prototype.

## New incremental deliverables

- **P0 — current-commit qualification gate:** `.github/workflows/hepta-qualification.yml`
  installs pinned Rust/Lean/QEMU toolchains and re-runs the complete existing
  release suite plus new P2/P4 regressions. It uploads exact-source evidence
  and cancels superseded PR runs. A queued/incomplete GitHub Actions run never
  qualifies P0; verify the final head SHA, success conclusion and artifacts.


- **P2 — Independent host C ABI:** `tools/abi_host_probe.py` executes a 16-way GCC/Clang producer-consumer matrix at -O0/-O2 on the available host, verifies nested structures, callbacks, scalar calling convention and a seeded fault control. Evidence is `artifacts/host-abi-gcc-clang-20261024.json`, bound to the generator's SHA. This is *not* a Hepta or cross-target qualification.
- **P1 identity defense:** `HSIRSnapshot.as_dict` now rechecks its canonical
  content digest and schema; stale or altered snapshots reject before consumers
  can read the mutable JSON view. A digest is not a signature or soundness proof.
- **P2 — cross-target C object profiles:** `tools/cross_target_abi_probe.py`
  compiles Clang C11 object and LLVM IR for x86-64 Linux, AArch64 Linux and
  Windows x64 MSVC. Target static layout assertions and a deliberate incorrect
  offset negative control passed locally on all three profiles. No cross-target
  execution, independent C compiler, Hepta cross-ABI roundtrip or hardware
  qualification is implied. The fixture executes again in PR qualification.
- **P1 — HSIR v0:** `hepta.hsir` serializes a checker-accepted source AST into a deterministic typed semantic snapshot. It preserves type metadata, argument modes, declared/transitive effects, resource clauses, C ABI direction and explicit external assumptions. It rejects missing inferred expression types and checker errors. It does **not** replace Rust lowering, model loan identities, prove pointer provenance, or establish Rust/C lowering refinement.
- **P5 native differential gate added:** the C++20 L1 fixture now builds a
  Clang++ native reference with L0 bridge and compares finite results against
  the converted Hepta cdylib, requiring pinned rustc. In the partial local
  checkout that test skipped, so its native qualification is still pending.
- **P5 — C++20 integer source migration bootstrap:** `hepta.cpp2hepta` invokes real Clang++ AST and emits L1 Hepta candidates for isolated `noexcept int(int...)` free functions and locally inferred int variables, with strict rejection of unsupported classes, templates, overloads, headers, pointers and global state. Native validation, differential behavior, C++ ABI equivalence and full P5 remain **open**; C++ mangled symbol names are deliberately not preserved. Tests: `tests/test_cpp2hepta.py` (3 local passing tests).
- **P4 — C++ bridge bootstrap:** `hepta.cpp_bridge` uses actual Clang++ C++20 ASTs to produce L0 C wrappers for unoverloaded `noexcept int(int...)` free functions, plus C header and non-qualification manifest. GCC C callers have linked and executed against Clang++ wrapper/original on the available host; Class construction, general lifetimes and C++ ABI profiles remain unimplemented. An opt-in status-return bridge now catches ordinary C++ exceptions and a host GCC C caller / Clang++ implementation test verifies local RAII destructor execution; the exception payload is discarded and the foreign code remains unverified.
- **P3 — Clang AST C migrator:** `hepta.c2hepta` accepts an intentionally restricted standalone C11 signed `int` function subset; performs an actual Clang semantic parse; transforms local variables, arithmetic, comparisons, if/else, and bounded-form while/for constructs; and rejects all unsupported syntax. Every output is tagged **L1 / candidate_unverified** and declares C UB, ABI, native validation, and differential-testing obligations. It never labels a generated candidate fully safe or equivalent merely because it parsed.

- **P6 additional enforcement:** the direct LLVM profile now checks that all
  checked arithmetic retains declared and inferred `panic` effects; verifies
  its source IR SHA-256 and profile before compiler invocation; records Clang
  identity; and atomically publishes the output on the destination filesystem.
  Its guarded CFG profile includes signed i32 comparisons and an if/else with
  one explicit return per arm. Local native comparison against independent GCC
  included 103 extra branch inputs and negative control-flow cases. The actual
  Hepta parser/checker/HSIR branch integration is a required current-head test.
  This is not general SSA/phi, arbitrary CFG or whole-language refinement.
- **P6 — independent scalar LLVM/Clang native pilot:** `hepta.llvm_scalar_backend` lowers a closed, pretyped `i32` subset directly from HSIR to LLVM IR. Signed arithmetic uses explicit overflow detection and abort; forbidden effects and ownership modes reject. A GCC C reference and LLVM native library were compared on 100 seeded valid inputs per operation, plus wrapping and overflow-child negative tests. On the local isolated subset, three P6 tests passed and two required full compiler integration tests were skipped; the new `build-llvm-scalar` CLI requires real pinned rustc validation before lowering. This is **not** a whole-language LLVM backend, production performance qualification, or P6 gate closure.
- **P4 host-only qualification receipt:** `artifacts/cpp-bridge-exception-host-20261024.json` captures GCC/Clang executable identity, source hashes and five actual exception/RAII tests. The host-only script is `tools/verify_cpp_bridge_host.py`; it deliberately reports `whole_p4_gate_closed=false`.

## Acceptance gates (the definition of done)

| Stage | Scope and required evidence | Status following this incremental change |
|---|---|---|
| P0 | Freeze precise commit, environment/toolchain identity and reference receipts; re-run on final candidate | Reference frozen; pinned all-gate PR workflow added; **candidate requalification pending** |
| P1 | Typed HSIR, borrowing/lifetime/resource/Effect/Capability semantics; Rust reference equivalence and safety negative tests | HSIR v0 snapshot; **full semantic proof and equivalent codegen open** |
| P2 | Portable C ABI profiles and real GCC/Clang/MSVC bidirectional host runs | GCC/Clang host C/C 16/16 plus three Clang cross-target object-layout profiles passed; **Hepta cross-target execution gate open** |
| P3 | Real C project source migration, build, differential fuzz and verified migration levels L0–L3 | Clang subset L1 candidate; **larger projects/L2/L3 open** |
| P4 | Verified C++ bridge including exceptions, destructors and ABI profiles | Narrow L0 C bridge plus opt-in catch/status and RAII host tests; **full P4 open** |
| P5 | C++ migration including template, class, RAII/STL, L1–L3 evidence | Strict C++20 integer-function L1 candidate; native C++/Hepta differential test added but not qualified; **full P5 open** |
| P6 | LLVM/MLIR backend with semantics, memory, CPU/RSS and p95/p99 regressions | Direct LLVM i32 expression/if-else CFG, effect consistency and host differential; **full P6 open** |
| P7 | Multi-file agent protocol v3, soundness, physical hardware and real-model independent benchmarks | **Open** |

Original Hepta 0.2 P01–P12 blockers in `docs/BLOCKERS.md` also remain open; no existing blocker is silently closed by this ledger. P6–P7 require additional target machines and controlled provider/hardware environments.

## Reproduction starting points

Run these from a **complete** checkout, with a pinned Rust toolchain before
concluding P0/P5/P6. In a partial checkout, skipped integration tests cannot
count as pass.

```sh
python tools/cross_target_abi_probe.py --output artifacts/abi-cross-target.json
python -m unittest discover -s tests -p test_cross_target_abi_probe.py -v
python -m unittest discover -s tests -p test_llvm_scalar_backend.py -v
python -m unittest discover -s tests -p test_cpp2hepta.py -v
```


```sh
python -m unittest discover -s tests -p 'test_hsir.py' -v
python -m unittest discover -s tests -p 'test_c2hepta.py' -v
python -m unittest discover -s tests -p 'test_cpp_bridge.py' -v
python -m unittest discover -s tests -p 'test_cpp2hepta.py' -v
python -m hepta hsir examples/parser.hepta > /tmp/parser-hsir.json
python -m hepta migrate-c examples/interop/c11_small.c -o /tmp/standalone.hepta
python -m hepta migrate-cpp examples/interop/cpp_noexcept.cc -o /tmp/cpp_migrated.hepta
python -m hepta check /tmp/standalone.hepta
python tools/abi_host_probe.py --output /tmp/host-abi.json
python tools/abi_fuzz.py --cc clang --output /tmp/abi-matrix-clang.json
python tools/verify_cpp_bridge_host.py --output /tmp/cpp-bridge-host.json
python -m unittest discover -s tests -p test_llvm_scalar_backend.py -v
python -m hepta build-llvm-scalar examples/llvm_scalar.hepta --rustc /path/to/pinned/rustc --output /tmp/hepta_scalar.so
python tools/release_check.py
```

The `hsir` command requires the normal real native Rust check and returns nonzero on rejection. The `migrate-c` command emits only a candidate: follow with native Hepta validation and an independent C/Hepta differential + ABI run on the **same target**. Do not accept frontend-only, unsupported, not-run or unavailable results as passed.
