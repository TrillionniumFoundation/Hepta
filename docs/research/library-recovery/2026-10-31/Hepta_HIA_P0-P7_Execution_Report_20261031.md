# Hepta Intelligent Assembly (HIA) P0–P7 — exact-source execution report

**Date:** 2026-10-31 UTC  
**Scope:** `TrillionniumFoundation/Hepta`, with existing `hepta-private-ci` native NDU integration as a dependency.  
**Status:** Two source changes published in separate stacked **draft** PRs, both scoped CI gates successful. **No P0–P7 production stage declared closed.**

## Source modifications and validated outcomes

| Scope | GitHub PR and exact head | Changes | Exact-head evidence |
|---|---|---|---|
| P0 | [#459](https://github.com/TrillionniumFoundation/Hepta/pull/459) · `29246ef7fae6277a29f1712c352eec8f6d1e6a4f` | Bound original HIA JSON text input by UTF-8 bytes **before** whole-string encoding; 4 changed paths | [Scoped CI 41181936828](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41181936828): **12 + 52 tests pass**, 0 failures/errors/skips |
| P5 | [#460](https://github.com/TrillionniumFoundation/Hepta/pull/460) · `33d989298adbf5923bef164bd3aa17224b105428` | Bound UTF-8 admission for full-cost ledger, native observer registration and native paired replay; 7 changed paths | [Scoped CI 41182093805](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41182093805): **21 + 13 tests pass**, 0 failures/errors/skips; real Linux ELF controls included |

P0 #459 is stacked onto [#458](https://github.com/TrillionniumFoundation/Hepta/pull/458) at exact `1a7559360ae6a7e15003c390ebaea2da476f11b8` (the prior mutable-caller-owned snapshot repair). P5 #460 is independently stacked onto [#457](https://github.com/TrillionniumFoundation/Hepta/pull/457) at `5b895342d6d0c8c9a4e8d68147ac619ebef20dcb` (the existing paired task-level NDU economics gate). Neither is merged into `main`. Evidence is attributed to its own head, not to main or another branch.

## P0–P7 gating matrix

| Stage | Evidence or actual source increment now available | Open production blockers / closing experiment |
|---|---|---|
| P0 — unified HIA Core/version/snapshot | Existing v8 opcode catalog + #458 bounded detached caller-owned source + new #459 bounded text; corresponding CI pass | Single integrated exact head, checker/VM/Rust validator/LLVM semantic alignment and independent full regression; non-atomic nested mutations and full interpreter/native refinement unproved |
| P1 — ownership/provenance/effects/exits | Existing owner/loan/effects and finite resource/exit qualification in #418/#434 | General pointer provenance, complete lifetime/ABI obligations, asynchronous failure, multi-module and source/native soundness proof |
| P2 — native code/ABI/targets | Existing direct LLVM/native Linux target and bounded ABI profiles | Real x86-64/AArch64/Windows independent toolchain runtime proof, ABI matrix and unqualified target rejection |
| P3 — C/C++ conversion | Existing finite Clang-AST/C++ RAII and GSL migration/upgrade studies | Full third-party project preservation; macros/templates/exceptions/callbacks; baseline and actual human maintenance cost |
| P4 — safe global optimization | Existing finite guarded source transformations, verifier and native observations | Provable obligations of general transforms, full-system strong Rust/C/C++ baseline and measurable prospective benefit |
| P5 — NDU/fixed/DP economics | Prior native NDU advisory connection; original complete-cost, ELF observer, paired sign tests; new #460 input hardening and 34 scoped tests pass | **Positive future net economic benefit is still unproved; prior full-cost study was negative**. Need genuine prospective code, independent measured full costs and heldout comparisons |
| P6 — Agent coding | Existing agent instruction discovery and controlled trial workflows | Fresh unseen real-project tasks under equal model/tool budgets and verified total end-to-end human/model/dev cost; provider quota limitations |
| P7 — dynamic deployment | Existing execution authority, final-use/fence and ledger research paths | Physical host crash/restart/rollback/fence/stale generation and resource accounting demonstration over durable normal deployment path |

## Safety and evidence limitations

- UTF-8 admission is a **bounded pre-encoding operation**; it does not establish full-process RSS upper limits or simultaneous atomic snapshots of concurrently edited nested caller-owned dictionaries/lists.
- P5 signed/task-level positive fixture results do **not** authorize execution, release or claims of real statistical generalization. The research gate's authority remains `DENY_ALL`.
- The two new GitHub PRs are **Draft / unmerged**. The precisely referenced scoped workflows succeeded; broad CI workflows run independently and have not been used to claim overall P0–P7 closure.
- P0–P7 is a large, staged research/engineering program. This report describes source work and checks accomplished in this session; no global-optimality or unconditional Rust-safety claim is made.

## Immediate integration order

1. Independently review and merge (or reject) #458 then #459 without bypassing final-head source identity tests.
2. Independently review #455 → #456 → #457 → #460 in their correct stacked order, preserving all historical negative evidence and `DENY_ALL`.
3. Align these branches on a single versioned HIA Core only after explicit source-map/semantic and dependency review. Re-run checker, interpreter, Rust verifier, native LLVM and resource failures on the **merged exact SHA**.
4. Register real prospective, non-synthetic third-party work and matching Rust/C/C++ fixed/DP/NDU controls with complete costs. No production activation until corresponding safety, economic and runtime acceptance gates actually pass.