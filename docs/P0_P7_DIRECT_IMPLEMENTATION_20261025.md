# P0–P7 direct engineering checkpoint — 2026-10-25

This is an exact-source **engineering candidate**, not a production release or a
whole-language safety proof. The user requested direct implementation without
waiting for CI. No CI status is used to claim a blocker is closed.

## Git identities and provenance

- Parent unified owned-resource candidate with archived execution records:
  `a04ae789b2348504089e2c3484178998a6f332ba`.
- Original tested source of that candidate:
  `2f8cd75d5ab5dba08f130561c1b9198c76e6ba6e`.
- Earlier 13 disjoint P0–P6 source/test blobs imported from the exact tree
  `68f165d0d88e860297f39fc60b06e34a7049835e`.
  The old `tools/release_check.py` blob was **not** copied because the newer
  owning LLVM candidate added six gate types. Its guard changes were ported
  onto the newer source explicitly.

## Implemented in the current branch

| Phase | Actual source change | Scope / limitations |
| --- | --- | --- |
| P0 | Port stable regular-file evidence reader to the current 46-gate collector; parse a terminal unittest stderr success footer, never stdout test chatter; retain stderr and skip/failed results | Prevents passive stale/symlink replay and fake unittest counts, not independent cryptographic attestation |
| P1 | Exact JSON literal source/SSA origin; closed PHI/SSA nested inventories; reject zero-input entry PHIs | Bounded scalar SSA, not general lifetime/alias provenance or whole-language soundness |
| P2/P3 | Captured C translation unit dependency provenance, byte count and typed ABI manifest enforcement | Actual listed compilation database only; unsupported arbitrary C and cross-compiler configurations still reject |
| P4 | C++ scalar value class postpublication identity, and actual owning-C++ byte protocol migration using shared exact-byte native-Hepta source publication | Only closed scalar/trivial value class and closed exclusive-byte owner protocols; general RAII not automated |
| P5 | Scalar LLVM native object publication; owned LLVM source and backend native publication both use exact staged data/inode checks; finite source-checked zero-allocation/nonblocking resource clauses now lower through owned LLVM | Scalar and finite owned-byte profiles only, not full-memory LLVM backend or cross-target owned execution; static clauses are not full-process budgets |
| P6 | Pinned Agent semantics return lifetime/volatile inventory and typed bool/int/foreign-obligation diff | Versioned read-only metadata only; no live model A/B or functional equivalence proof |
| P7 | No unsupported real-device execution claim was changed | Physical board, DMA, GPU/NPU and long-running service qualification remain open |

The new module `hepta/artifact_publication.py` checks ordinary file type,
inode, exact bytes and name identity before and after a no-replace hard-link.
A failed publication only unlinks a destination that still refers to its own
staged inode. It is used in both the new owning LLVM source/native compilation
paths and the owning C++ source migrator. Tests inject mutations and symlink
path swaps, including a competing file which must **not** be deleted.

An independent **real native object smoke execution** also completed on
the available Linux host: Clang generated a 616-byte x86-64 ELF object from
minimal LLVM IR, the shared publication helper bound its 616 exact bytes to
a new hard link, GCC linked a C executable, and executing the binary returned
`hepta_native_check(41) == 42`. A matching in-repository native regression
has been committed. This exercises publication with actual executable object
bytes but does **not** run the Hepta source language or qualify owned LLVM
semantic refinement.

A further **9/9 isolated negative/positive resource-clause tests passed**.
The bounded owned LLVM emitter no longer rejects all resource clauses
unconditionally: it accepts checked `heap_allocations=0`, `may_block=false`,
`may_suspend=false`, and `may_spawn=false` only with exact JSON/Python literal
types and transitive effect exclusions. The source and LLVM positive smoke
test is committed but not executed on the full source in this environment.
This is a finite compile-time contract facility, not a universal memory budget.

A local isolated Python/POSIX probe of this publication helper initially found
that hard-link creation legitimately changes inode `ctime`. The implementation
was corrected to recheck post-link identity while retaining unchanged inode,
mode, size, mtime and **exact bytes**. After correction, **10/10 tests passed**.
A second isolated test probe for unittest footer and evidence file identity
passed **10/10**. This is executable helper-algorithm evidence, **not** the
entire Hepta repository's native suite. The corresponding source tests are
committed and must run in a complete exact-source checkout.

## Existing owned candidate qualification (historical, not this branch)

The original tested source `2f8cd75d...` completed 46 gates, 44 passed,
2 failed, 1,369 unittest cases passed, zero skipped. Failure was limited to
two **measurement quality** conditions: scalar LLVM Rust
`branch_accumulate` relative MAD 10.3231% (limit 5%);
owned LLVM `constructor_error` Rust 7.8514% and LLVM 6.1607% (limit 5%).
Timing ratios satisfied their fixed speed limits, but **both metrics remain
`measurement_inconclusive`**. Do not drop outliers, loosen the limits or
count an earlier successful run as this source's acceptance.

## Required engineering qualification (without CI dependency)

On the pinned source checkout with the documented exact Rust/Clang/GCC
versions and appropriate hardware, execute local targeted regressions:

```sh
python -m unittest -v \
  tests.test_release_file_identity tests.test_release_unittest_summary \
  tests.test_release_collection tests.test_ssa_verify tests.test_ssa_scalar \
  tests.test_c_project tests.test_cpp_class_migrate tests.test_cpp_owned_migrate \
  tests.test_artifact_publication tests.test_llvm_ssa_target \
  tests.test_llvm_owned_backend tests.test_agent_contract_diff tests.test_agent_semantics
```

Then execute the exact-version native qualification with an empty output
directory and retain all results, including failures:

```sh
python tools/release_check.py --output-directory evidence/p0_p7_next_exact_head \
  --continue-on-failure
```

No action in this branch declares that the last command executed successfully.
Source code revisions after any local measurement invalidate that measurement's
exact-SHA qualification.

## Unclosed acceptance conditions

- P0/P1: complete semantic refinement, pointer/alias/provenance soundness and
  lifetime/trait coverage; exact integrated source execution.
- P2/P3: industrial C source coverage, cross-GCC/Clang/MSVC ABI matrices on
  real target hosts and full migration cost.
- P4: general nontrivial RAII, inheritance, templates and exception migration;
  foreign library ownership remains an explicit assumption.
- P5: independent owned LLVM across more language types/targets; fully
  qualified repeatable latency/RSS/performance trials; retain all regressions.
- P6: controlled real Agent/model runs with actual provider receipts,
  independent holdout, objective quality and costs.
- P7: actual ARM/MCU boards, MMIO/IRQ/DMA ownership and device qualification,
  GPU/NPU codegen + execution, and sustained production services.

The software cannot declare unavailable physical devices, secrets/network,
compiler soundness theorems or independently unobserved benchmarks as passed.
`whole_project_blockers_closed=false`.
