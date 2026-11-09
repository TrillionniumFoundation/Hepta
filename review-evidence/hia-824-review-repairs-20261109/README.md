# PR #824 scalar review and native-deadline follow-up

This update retains original head `9ba2a6202277e3d3418d3a8205450973174eb812`
and its CI/review history. Review comment `4509542158` identified a genuine
contradiction: an outer scalar interval of 943,383,830 ns was accepted although
the last retained call ended at offset 1,280,472,124 ns.

The verifier now requires exact nonnegative integer outer measurements and
contains every attempted call end inside that outer interval. Canonical JSON
comparison also prevents float/Boolean aliases from replacing exact retained
cell offsets or recomputed counts. The original 128-cell/64-native/307-object
archive remains a positive control. The scalar module now has 19 tests; both
the exact-source count and standalone scalar workflow's retained-fixture
sparse path are updated.

The native deadline test now enters the real admitted evaluation before its
test-only waiting barrier. It forwards the real reference runner and checks
the exact original remaining timeout, actual start and confirmed termination.
The 3000 ms total/1000 ms native budgets and original deadline+650 ms absolute
bound are unchanged. A separate expired-admission case starts neither runner
and consumes no native budget. Complete original failure and real-runner
evidence remains in `hia-native-deadline-test-20261109-5e86`.

## Final source validation

Local tested commit `03c7d220447d7ea2a3df93cf56c53a08e2404a3c`, tree
`36efdd6bb3c1fc2c90eef40e498473c89944c2bb`, passed **254 unique tests** in
66.670 seconds, with zero failures, errors, skips or expected failures. This
includes the 70-test native family and all 19 scalar controls; component and
earlier aggregate counts overlap and must not be added to this denominator.
The native stream cases use the previously recovered original CI executable
and receipt whose existing identity checker is printed in the retained log.

The exact new CI step was also executed locally: 19 tests passed, then the
unchanged original scalar archive replayed successfully with zero new native
or provider calls. The generated v14 support contract passes `--check`; every
one of the earlier targeted 105-check report's 252 source hashes still equals
this source. The 105 checks were not rerun and do not replace new-head CI or
full v14 source-only cold qualification.

## Preserved failed integration attempt

`first-sparse-failure.log` is the complete earlier result: 250 tests ran with
one `setUpClass` error because the local sparse checkout omitted the committed
original scalar archive. The intended collection had 253 identities; the
three retained-archive cases could not start. That attempt remains failed.
Restoring the unchanged archive (SHA256 `d9025d10bacdd5e8558625c26fce40130effc87e05fe962a2387bfd4680add6d`),
declaring its standalone-CI sparse path, and completing the additional canonical
summary repair produced the separate final 254-test run. The original log is
neither overwritten nor restamped.

The independent review confirmed the original outer counterexample and three
summary-type controls now reject, the original archive still verifies, and the
deadline test keeps its original contract. No self-approval or forced review
resolution is part of this update. Source CI, general compiler/machine proof,
the original stranger-Agent lifecycle/provider costs and stable NDU economic
value remain separate gates; overall acceptance remains **HOLD**.
