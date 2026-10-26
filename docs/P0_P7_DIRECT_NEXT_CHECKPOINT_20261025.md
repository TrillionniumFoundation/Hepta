# P0–P7 direct implementation checkpoint — 2026-10-25

This is a source-engineering checkpoint on the present unified Owned LLVM
compiler, **not** completion of its production/security/research gates. Do not
wait on GitHub CI to continue implementation; do not upgrade unexecuted native,
real-model or device checks to passed.

## Exact dependencies

- Stable main source: `ac4f02bc7a57766254aa30f67b2c8ff1126f8966`.
- Current unified source donor PR #135: `c483b4cedcc03a8bfcbe02d3c6b3f644f8c8af59`.
- Its parent PR #133: `a60e7344bf07b510e570fa9fb582da130e13ab94`,
  introducing a bounded Owned ELF dynamic export/import ABI gate.
- Resource-capable PR #115 code qualification: source
  `2f8cd75d5ab5dba08f130561c1b9198c76e6ba6e` with 46 planned gates,
  44 passed/2 failed performance stability thresholds and 1,369 tests passed
  without skips. Its evidence-only archive head is `a04ae789b2348504089e2c3484178998a6f332ba`.
- Additional helper/test donor PR #132:
  `dd60810f8052ed7d8f998e7e55cb53698a8888a4`.

## Implemented on this successor branch

| Phase | New source engineering | Safety/profile bounds |
| --- | --- | --- |
| P0 | Source-verifiable terminal stderr unittest count; no test-controlled stdout/stderr preface can inflate a passing count; retains original 46-gate collector and strict evidence reader | No CI requirement for further development; no proof the entire release is qualified |
| P1 | Preserve #135 canonical typed HSIR, scalar SSA origin, resource/loan verification and source checks | General lifetime/type generics, machine pointer provenance and full backend refinement remain open |
| P2/P3 | Preserve Clang C build configuration/provenance, native ELF dynamic imports/exports, and real selected C migrations | Arbitrary C/C++ ABI, all target hosts and unproven foreign contracts remain open |
| P4 | Hook existing exclusive-byte-owner C++ to Hepta conversion to one exact regular-file publisher, including original source/compiler post-publication replay and adversarial mutation test | Only reviewed resource-owner protocol; arbitrary C++ RAII, STL, templates, exceptions and L2/L3 remain open |
| P5 | Hook BOTH backend and source-facing Owned LLVM paths to shared exact-byte publication after native identity/ELF-dynamic-ABI checks; add positive allocation-free/nonblocking/nonspawning/nonsuspending static resource clauses, with literal/effect rejection | No global allocator or process-wide budget; no universal performance win; stored lifetime records, tasks and general target backends remain unsupported |
| P6 | Preserve #135 typed pinned Agent contract/volatile/foreign obligation diff and immutable source snapshots | Real model-provider 2x2 A/B/cost measurement still zero at last verified source |
| P7 | Preserve original Linux x86-64, qualified Windows ABI and QEMU reports with exact original source IDs | Real physical boards, DMA, GPU/NPU, long-lived services and multicore failure/recovery remain unqualified |

## Direct execution performed, without CI

The exact Git blob `dd3b95638e797c0f37a987c3f342ffc75d71e89b` for
`hepta/artifact_publication.py` was reconstructed locally and its
`git hash-object` independently matched that blob SHA. A separate local
nine-test suite passed all nine against these exact bytes. It exercised
normal publication, refusal of symlinks, FIFOs and stale bytes, same-inode
mutation cleanup, competing destination replacement protection and native
`clang -x ir` → ELF object publication → `gcc` C executable execution
(return code 0). A separate five-test local unittest parser probe also passed.
These tests do **not** require Rust or GitHub Actions.
A separate twelve-case local source-contract policy probe passed **12/12**,
including supported zero-allocation/nonblocking clauses, Boolean/integer type
confusion, transitive allocation/blocking/spawning effects, float counts and
unsupported process-wide memory claims. This is **isolated policy execution**,
not the entire Hepta frontend/backend or native resource application.

After integrating the shared publisher, the source-facing Owned LLVM pipeline
also performs a post-publication source-graph and compiler identity recheck,
removing its own still-identical output upon stale input. A new native test
injects an imported-source edit during publication; that full Hepta test is
committed but has not executed here.

Complete Hepta Python/Rust/Clang20/native/Lean/device test suites on the new
combined source SHA have not executed in the current environment, which has
Clang 17 and GCC but lacks `rustc`, Clang 20, QEMU, physical boards and GPU
devices. Re-execution remains required before promotion, without stopping
further code development.

## Local non-CI acceptance commands on a complete checkout

```sh
python3 -m unittest \
  tests.test_artifact_publication \
  tests.test_release_unittest_summary \
  tests.test_cpp_owned_migrate \
  tests.test_llvm_owned_backend \
  tests.test_elf_shared_abi_native \
  tests.test_ssa_verify tests.test_c_project \
  tests.test_agent_contract_diff tests.test_agent_semantics -v

python3 tools/release_check.py --output-directory evidence/next-full-local-candidate \
  --continue-on-failure
```

Always record the **exact final code SHA** in each receipt. The 2 prior
performance-quality failures must be resolved with reproducible sampling and
the originally frozen acceptance criteria; do not relax thresholds or cherry
pick samples. Keep `whole_project_blockers_closed=false` unless every
claimed requirement and target is independently qualified.
