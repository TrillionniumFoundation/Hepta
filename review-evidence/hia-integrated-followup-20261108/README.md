# Integrated loader, lease and acceptance follow-up

This change is based on PR #808 source `ffa64c93`. The tested code and support
identities are commit `07a944fa`, tree `f1750f6d049c90f4c26620b6905f6380b3b90c7b`;
this evidence-only addition does not change those executable sources.

The narrow Safe Core checker now admits one reviewed RELRO authority whose
actual protected pages cover the GOT without changing executable pages. New
regressions fail against the original checker in five subcases. The existing
#809 PT_LOAD order and explicit dual-hash fixes are reconciled with v13.
Lease calls and buffer records use the retained database identity after admission
rather than a caller-owned mutable dictionary. Complete NDU cohorts and costs
are rechecked at finalization, preserving the original failures and thresholds.

Local validation: 45 Safe Core tests, three positive programs, five semantic
counterexamples and 29 fresh SMT replays passed. The integrated release,
contract, cohort and lease suite passed 62 methods. Its original missing-sparse-
fixture errors remain in the gzip log; restoring the exact unchanged benchmark
files resolved them. The native bounded v13 qualification passed all 1,183
checks. The ordinary B1/B2/B3 images match; the mutation chain retains its own
fixed point. See validation.json for source identities and durations.

The Safe Core ZIP contains complete images, queries, original-file manifest and
raw logs. The compressed selfhost report contains the complete 26 MB report;
it is not the separate 674+ MB child-artifact directory and is not presented as
a standalone cold replay bundle. Exact-head source CI must retain its own full
raw artifact set. Component logs and qualifications are separate observations,
not counts to sum as unique tests. Relocation's 33-method run and preserved old-
clock failure are under ../relocation-timeout-marker-20261109/.

No default release lock, online installation, universal compiler/ABI/FFI/ISA
proof, unfamiliar-provider transcript/invoice or stable NDU economic benefit is
established by this source follow-up. Overall six-track acceptance remains HOLD.
