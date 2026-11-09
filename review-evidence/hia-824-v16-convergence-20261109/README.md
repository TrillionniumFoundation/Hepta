# Converge PR #824 repairs with the advanced v16 source baseline

The previous PR head `feb0acd0f90acad8a1631a154bd0c70562897e48`
completed all 19 workflows successfully on attempt 1. Complete workflow metadata
is retained in `previous-feb0-workflows.json`. It was not merged: meanwhile
#817/#808 advanced both source baseline refs to
`6ecd8023615a6e0b2dc269379fb059c656b38b6f`, creating content conflicts.

Local integration commit `240717b6d5ed6e18e823b19ed2c263ba15cabd86`, tree
`e46c8f222a436907e5f6e6c0343ae9f9df8b9971`, resolves those conflicts:

- Preserve v16 compiler/generator, effects, u16, checked casts, complete language
  input inventory and its 1183 scalar assertions byte-for-byte from 6ecd.
  Regenerate the support identity for the combined seed-package source bytes.
- Preserve #824 supplied-image IMUL, snapshot actual-byte/FD guards,
  prepared/persistent interval and canonical JSON repairs, original-budget
  native reference-runner tests, scalar pump containment and original archive
  regression controls. Existing historical evidence is retained from both sides.
- Combine 6ecd's uninterrupted attempted-prefix/stop-order checks with #824's
  canonical summary equality, exact integer accounting and pump bounds.
  Carry all three independent prefix/measurement test methods, keeping the
  existing 23 controls. The exact-source hard denominator is now 26.
- Keep the retained scalar archive in the standalone CI sparse checkout.

The authored completed-call outer-boundary fixture now declares its audit-error
stop before leaving subsequent calls unstarted. This is a fixture adaptation to
the runner's real stop rule; it does not relax a production interval or budget.

## Evidence boundaries

`integrated.log` passes **261 unique tests** in 62.377 seconds, with zero
failures, errors, skips or expected failures. This includes the 26 scalar and
70 native budget/proof/machine tests; those counts are not additive. The
original native bridge's current dependency identity check passed again.

`scalar.log` passes 26 tests without skips. `language-source.log` passes all
12 language source/reference methods, including the actual 1183-scalar inventory.
`v16-contract-cast-fragment.log` passes 35 selected source/contract, explicit-v2
unsigned cast and original copied-fragment controls without skips. These
component sets overlap other suites and are not added into a unique total.

`v16-source.log` is an **interrupted, incomplete attempt**, not a cold replay
PASS: an overly broad test selection entered SelfhostColdReplayTests after its
language source methods. It was stopped because a full retained cold run exceeds
the available local disk budget. Full new-head source-only cold and native
language qualification remain independent CI gates. The previous v14 18-test /
910-check native language report is preserved with its original source hashes;
it is not attributed to this v16 integration.

`first-sparse-driver-error.log` records a separate setup error before integrated
test collection: local merge processing restored sparse-checkout rules and
removed the out-of-sparse evidence driver from the working directory. Its Git
blob was unchanged and restored before the separate integrated run. No test
failure or incomplete attempt is overwritten or relabelled.

No metadata-main lock or live configuration/state/journal is changed. Main was
read at `74063163ad19d096a4ff9a66a6f25728e6ce0d8f`, still selecting source2598
and runtime4cd85c99. This update only advances the owned #824 candidate branch.
The source baselines require new exact-head CI/review before any integration,
then merge-commit CI and the final original successful source artifact for any
new default lock. General Core/compiler/ABI/resources/FFI/ISA/loading theorems,
the original stranger-Agent lifecycle/provider bill and stable fair full-cost
NDU economic benefit remain HOLD.
