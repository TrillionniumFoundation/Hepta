# Hepta P0–P7 direct execution ledger — 2026-10-25

This ledger reports **executed source changes**, their evidence and unfinished obligations. CI status is not used to decide whether to continue P0–P7 implementation. An implemented guard or a standalone compiler probe is **not** production gate closure.

Integration branch: `assistant/hepta-p0-p7-semantic-budget-20261025`, based on upstream PR #75, keeping the canonical `hepta.semantic_ir` authority and the single C/C++ scalar lowerer.

| Stage | Changes delivered in this branch | Actual acceptance scope | Still open |
|---|---|---|---|
| P0 | New source-bound changes committed and published as Draft PR #83; preserved existing canonical full-release gate and focused source qualification entry points | Remote source commit identities confirmed; no full end-to-end acceptance asserted | Exact integrated HEAD full source/toolchain execution, qualified consolidation and release review |
| P1 | `HSIRSnapshot.as_dict` enforces closed derived schema, all expressions counted, absence of elevated proof flags and known nested fields; CFG calls this structural gate | Added positive/negative executable regression tests; code submitted, not represented as passing a real rustc check | Resource/loan/provenance/effects SSA across all language features, independent translation refinement proof |
| P2 | Bounded host ABI test subprocesses; C-build captures rechecked against exact compile database, target and ABI-macro model | **Actually executed standalone Linux x86_64 C11 GCC 14 / Clang 17: 8/8 binary pairs passed, 2/2 compiled wrong-code controls rejected.** Exact tool source blob `ce72df2e51059866795ae415aec29296cb40273d`, full finite receipt in `evidence/dual_c_host_20261025.json`. | Real Hepta artifacts, Windows/MSVC/macOS/ARM ABI calls and broad ABI syntax/semantic coverage |
| P3 | Clang project capture now enforces canonical manifest identity, complete command/configuration denominator and full recorded dependency list, even after resealing | Added forged manifest/model/flag/missing-dependency negative tests; suite not locally re-run | Whole real C projects, L2/L3 ownership-safe conversion, complete configuration and semantic equivalence |
| P4 | Restricted C++ L1 migrator pins resolved compiler SHA-256, enforces native target/64-bit model and fails on changed compiler before publication | Host Clang++17 native target/macros observed; regression cases committed, Hepta-native differential not re-run here | Arbitrary classes/RAII/templates/STL/exceptions and C++ ABI compatibility |
| P5 | ELF/COFF/Mach-O section-payload range guards plus injected corrupted-object tests; bounded native compiler capture retained | Earlier independent object probes and negative controls; general LLVM SSA backend not proven | Real signed/owned type lowering, cross-target linking/runtime and Rust application performance |
| P6 | Workspace pin rejects elevated proof flags and malformed source inventories; Agent function IDs normalized across version roots; graph SHA detects changes in imported modules | Positive/negative regression test files committed; no actual AI-model trials | End-to-end multi-file workflows, provider repetitions, measured Agent labor/cost and equivalence verification |
| P7 | Native-host test subprocesses use bounded file-backed capture | Host C ABI baseline is not physical hardware qualification | Embedded boards, DMA/IRQ/GPU, target-specific resource proofs and long-run fault injection |

## Bounded and independent evidence

- `tools/probe_dual_c_host.py`: actual local executed source, not just a designed test or mock. Eight compiler/optimization pairs and two compiled incorrect implementations. The tool **does not compile any Hepta code**; its role is a host C ABI cross-compiler preflight.
- `tests/test_hsir_bridge.py`: rejects forged/rehashed scalar CFG input with new effect/ownership fields or an incomplete expression inventory.
- `tests/test_c_project.py`: rejects tampered and even resealed compile-database capture bundles.
- `tests/test_agent_semantics.py` and `tests/test_agent_contract_diff.py`: assert stable relative function identity and full project import-graph source identity, not merely the entry file.
- `tests/test_cpp2hepta_l1.py`: rejects foreign target architectures and 32-bit pointer models rather than silently migrating with the wrong native ABI profile.

**Scope claims:** Whole-language soundness not proved; resource limits not globally proved; original C/C++ semantic equivalence not proved; no broad Rust speed superiority proved; full Hepta compiler/hardware/model-provenance tests not executed during this direct session; all P0–P7 and original P01–P12 production obligations remain OPEN or PARTIAL.

`whole_project_blockers_closed=false`.
