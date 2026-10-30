# Six-track implementation advance

Baseline: `192d2cbba7e49bde3b03af73685ecf96f6fb1b05` (the integration proposed in
PR #405, not `main`). This increment implements all six work streams and keeps
completion criteria distinct from implementation and finite observations.

| Priority | Concrete implementation | Evidence and remaining boundary |
| --- | --- | --- |
| Unified semantics | Production CFG/resource kernel; shared verifier/VM/LLVM successor and edge binding; owner/loan/return rules; VM budget order; chain layout; cache policy v4 | Local production regressions and 56 independent old/new VM comparisons pass. Actual native C-ABI/allocator observations are required by the new CI. Full operational semantics and backend refinement remain unproved. |
| Verified optimization | Strict guarded proposal-to-Core-to-LLVM-to-target-to-final-inode binding, including compiler/solver/source drift and interrupted-publication withdrawal | The three baseline defects are retained as negative controls. Eleven boundary tests pass locally. Two tests require actual Clang and pinned Z3; they are not replaced by mocks in native qualification. This does not admit arbitrary loop or peak-resource rewrites. |
| Real C++ maintenance | Two pinned historical INIReader revisions; generated checked Hepta decision logic, real C11/GCC output, C++ callback lease adapter, declaration dispositions | Independent native originals and migrated components execute. Exact Boolean output streams, object lifecycles, allocator failure, callback exceptions and the real `-3` read-error upgrade are retained. C++/STL/parser boundaries remain; whole-component translation and low human cost are unproved. |
| NDU incremental value | Exact shared-acquisition portfolio DP, independent enumeration oracle, retained-image and scratch budgets, real competing verified candidate bank | Prospective protocol fixes two groups, five arms, complete own evidence costs and cold native build accounting. The original Rust NDU is invoked, not simulated. Competition and net gain are outcomes, not required positive labels. No learned-model or general-global-optimum claim. |
| Agent development | Function-focused context, exact interfaces/return-loan origins, opcode discovery, whole-module patch recheck, fresh maintenance protocol and controls | Context bytes are measured separately from tokens or productivity. Missing actual model execution remains blocked; no old model run is relabelled as fresh evidence. Review cost and uncontrolled provider/cache effects remain explicit. |
| Target interfaces | Actual Linux pthread/eventfd native harness, resource ledger, cancellation, startup/completion faults and recovery | Host-reference and actual Hepta cohorts are separate. CI requires Hepta object linkage and sealed execution on native x86_64 and AArch64 hosts. Physical devices, MMIO, DMA and hardware interrupts remain unqualified. |

## Source and evidence discipline

The local Git proxy was unavailable. The pinned source snapshot was obtained
through GitHub and every materialized upstream file checked against its Git
blob identity. Remote commits are built on the complete upstream Git tree;
files absent from the local snapshot are not deleted. Full-checkout CI supplies
the native toolchains and the original pinned NDU source.

The prospective portfolio runner compares its implementation, source package,
fixtures, protocol and builder bytes with the supplied registration commit
before the first calibration. Every failed episode and negative saving is
retained. A missing cost is null, not zero. The outer original-NDU builder starts
from an absent target directory and includes process startup and the inner
manifest write; tool acquisition and complete lifetime costs are still outside
that measured scope.

The Agent contexts use the real full-module checker. Focused context is a
view, not a claim that hidden functions cannot matter; call interfaces and
formal loan origins are retained and the patch is checked against the complete
module snapshot. Authored positive/negative controls are not model trials.

## Required native execution

`.github/workflows/hepta-six-track-advance.yml` checks the exact PR head, then
runs shared-semantic, artifact-binding, real-C++ and actual-host qualifications.
Both native-host jobs upload original outputs on failure as well as success.
The separate portfolio job builds original finite NDU
`4b6391e116949af0c7e59776baead67271856bdb` with Rust 1.95.0 and executes all
registered control arms. Correct execution and profitable NDU selection are
reported separately.

Passing CI does not change the following completion flags:

```json
{
  "all_six_user_acceptance_conditions_closed": false,
  "whole_language_soundness_proved": false,
  "backend_refinement_proved": false,
  "whole_real_cpp_component_migrated": false,
  "low_human_migration_cost_established": false,
  "ndu_complete_lifetime_net_gain_proved": false,
  "agent_productivity_superiority_established": false,
  "physical_MMIO_DMA_interrupt_qualified": false,
  "release_qualified": false
}
```

Detailed component scope is in `HIA_SHARED_SEMANTIC_KERNEL.md`,
`guarded-native-binding-contract.md`, `HIA_REAL_CPP_INIH_COMPONENT.md`,
`HIA_PORTFOLIO_PLANNING.md` and `linux-host-interface-qualification.md`.
Local evidence and upcoming CI runs must be cited using their own exact source
identities; later documentation does not become a rerun of an earlier binary.
