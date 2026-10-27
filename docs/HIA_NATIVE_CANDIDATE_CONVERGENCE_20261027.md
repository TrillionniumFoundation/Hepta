# HIA v7 and native resource candidate convergence

This integration preserves three immutable candidates in one Git history:

- PR #319: `209fa298127adf41b24d128d0291dcb4a0649c73` — the v7 HIA,
  Rust shadow, migration intake, source identity and bounded Agent-input stack.
- PR #318: `ca00645b409b13aaea9d5f74cb9d942c555dae49` — the strictly scoped
  v6 fallible-owner cyclic live-payload bound, retaining the v7 refusal.
- PR #115: `4ac39e626acd7f78e2f66708be741e78308b4e6a` — native local
  stored views, task/I/O composition, actual two-to-four-owner C++ implementation
  migration and the typed C native qualification callers.

The #318 merge has no source conflicts. Its 26 selected owner-budget and Agent
JSON regressions executed successfully before the #115 integration. The #115
three-way merge has only two textual conflicts: the backend imports and the
toolchain-selection test module. Both runtime composition and bounded compiler
identity are retained. Both added compiler-reader negative tests remain active.
No whole-file side selection substitutes for this reconciliation.

## Executed integration checks

The following local checks ran on the combined source with Python 3.12 and the
host GCC. These are separate selected suites, not complete release qualification:

```sh
python -m unittest tests.test_toolchain_selection \
  tests.test_llvm_local_views.LocalViewLoweringTests \
  tests.test_task_io.TaskIoSourceTests \
  tests.test_task_io.TaskIoFailureRetentionTests \
  tests.test_hia_unified_qualification tests.test_qualification_environment \
  tests.test_cpp_composed_harness -v
# 38 tests: passed, zero skips.

python -m unittest tests.test_hia_migration_file_intake \
  tests.test_hia_l1_receipt tests.test_compiler_hash_identity \
  tests.test_hia_schema_binding_audit \
  tests.test_hia_p1_scoped_try_new_v7_guard tests.test_hia_scoped_alloc_loops \
  tests.test_hia_inmemory_agent_node_ceiling \
  tests.test_hia_surrogate_predecode -q
# 50 tests: passed, zero skips.
```

The first exploratory invocation exposed a real non-textual integration
conflict: the older full-qualification workflow omitted the newer mandatory
`--qemu-riscv64` argument. The workflow now installs the distribution `qemu-user`
package and explicitly passes RV64 QEMU and the C++ compiler. The test executes
the actual shell expansion and CLI parser, and confirms that removing the RV64
argument fails before qualification runs. The previously pinned AArch64 QEMU
installer and its checksums are unchanged. RV64 tool identity is recorded by its
existing qualifier; the distribution RV64 binary is not represented as the
SHA-locked AArch64 binary.

That exploratory invocation also selected a misspelled test class and attempted
the C++ CLI test before Clang was available. The corrected class passed above;
absence of Clang was not counted as C++ migration success. The native Clang/Rust
C++ migration, native local-view execution, Rust shadow, formal, cross-target,
performance, real-model and full-release gates require their own actual runs.

## Subsequent native execution on the converged code

The [retained native observations](../evidence/hia_native_convergence_20261027/README.md)
record 28 passing C++ composition/LLVM/ABI tests, 88 passing C/C++/HIA migration
tests, and 12 passing task/I/O regressions. The system-Python task/I/O qualifier
also passed all ten cases for three repetitions with 27 native executions and
strict final-report readback. Restricted-executor failures and an incomplete
portable-Python persisted report remain separate; neither is promoted to a
successful qualification. These are selected gates for the recorded code
commit, not whole-project or later-commit qualification.

## Scope

Historical evidence imported from #115 remains associated with its original
source identities. It does not qualify this merged source. The v6 cyclic peak
proof does not acquire v7 resource authority. Local source-to-C/LLVM views do not
imply support for arbitrary stored lifetimes or all C record-view programs in
standalone HIA. Actual C++ implementation migration remains distinct from a
retained native C++ contract bridge.

`whole_project_blockers_closed=false`. General source/native refinement,
universal C/C++ safe translation, full Rust performance parity, physical-device
qualification and the complete P0–P7 production goal remain open.
