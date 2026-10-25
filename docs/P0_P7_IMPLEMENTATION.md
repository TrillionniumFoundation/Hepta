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

- **P1 — HSIR v0:** `hepta.hsir` serializes a checker-accepted source AST into a deterministic typed semantic snapshot. It preserves type metadata, argument modes, declared/transitive effects, resource clauses, C ABI direction and explicit external assumptions. It rejects missing inferred expression types and checker errors. It does **not** replace Rust lowering, model loan identities, prove pointer provenance, or establish Rust/C lowering refinement.
- **P3 — Clang AST C migrator:** `hepta.c2hepta` accepts an intentionally restricted standalone C11 signed `int` function subset; performs an actual Clang semantic parse; transforms local variables, arithmetic, comparisons, if/else, and bounded-form while/for constructs; and rejects all unsupported syntax. Every output is tagged **L1 / candidate_unverified** and declares C UB, ABI, native validation, and differential-testing obligations. It never labels a generated candidate fully safe or equivalent merely because it parsed.

## Acceptance gates (the definition of done)

| Stage | Scope and required evidence | Status following this incremental change |
|---|---|---|
| P0 | Freeze precise commit, environment/toolchain identity and reference receipts; re-run on final candidate | Reference frozen; **candidate requalification pending** |
| P1 | Typed HSIR, borrowing/lifetime/resource/Effect/Capability semantics; Rust reference equivalence and safety negative tests | HSIR v0 snapshot; **full semantic proof and equivalent codegen open** |
| P2 | Portable C ABI profiles and real GCC/Clang/MSVC bidirectional host runs | Existing narrow C ABI only; **open** |
| P3 | Real C project source migration, build, differential fuzz and verified migration levels L0–L3 | Clang subset L1 candidate; **larger projects/L2/L3 open** |
| P4 | Verified C++ bridge including exceptions, destructors and ABI profiles | **Open** |
| P5 | C++ migration including template, class, RAII/STL, L1–L3 evidence | **Open** |
| P6 | LLVM/MLIR backend with semantics, memory, CPU/RSS and p95/p99 regressions | **Open** |
| P7 | Multi-file agent protocol v3, soundness, physical hardware and real-model independent benchmarks | **Open** |

Original Hepta 0.2 P01–P12 blockers in `docs/BLOCKERS.md` also remain open; no existing blocker is silently closed by this ledger. P6–P7 require additional target machines and controlled provider/hardware environments.

## Reproduction starting points

```sh
python -m unittest discover -s tests -p 'test_hsir.py' -v
python -m unittest discover -s tests -p 'test_c2hepta.py' -v
python -m hepta hsir examples/parser.hepta > /tmp/parser-hsir.json
python -m hepta migrate-c path/to/standalone.c -o /tmp/standalone.hepta
python -m hepta check /tmp/standalone.hepta
python tools/release_check.py
```

The `hsir` command requires the normal real native Rust check and returns nonzero on rejection. The `migrate-c` command emits only a candidate: follow with native Hepta validation and an independent C/Hepta differential + ABI run on the **same target**. Do not accept frontend-only, unsupported, not-run or unavailable results as passed.
