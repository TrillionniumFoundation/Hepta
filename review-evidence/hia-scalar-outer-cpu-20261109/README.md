# Independent scalar CPU accounting review

## Final integrated repair

The CPU repair passed 28/28 scalar methods on the actual source checkout.
The same twelve-module integration suite passed **263 unique tests** in
69.343 seconds, zero failures/errors/skips/expected failures. This includes
the 70 native-family and 28 scalar controls; overlapping counts are not added.
Tested local implementation is `5301c60d0d1e50fed9cb9d12677e1423b56801c3`,
tree `47e5cc5afe7f53de5b8b108f39fe351efe2b6bd4`. Later changes add evidence only.

The original #824 candidate completed 19/19 workflows on attempt 1 and its
exact-head code/security reviews reported no findings. During this independent
repair, #824 was merged by parallel work as
`dfde9df60e80d820e25527bc75624a063a92a36d` with the same original tree
`03fed48a967fd33a2cd864c2ac5db8616abb1724`. The follow-up repair must target
that actual merged source baseline and obtain its own CI/review. No successful
old run or historical review is erased; it does not waive the new CPU defect.

All 253 closed selfhost input identities still match the original candidate
CI cold/language reports. Those reports and their original subject are audited
under `hia-edf-ci-independent-20261109`; they are not a new full CI qualification
or a final merged-source release lock for this repair. New source CI remains
required. The raw measurement's build/final-write exclusion flags are not an
independent hardware or billing attestation and do not establish global cost.

Fresh formal online installation verification remains PASS for the public
2598 source only. See `hia-online-fresh-20261109`: complete inventory/owner
visibility and an authenticated admission barrier are still missing, so no
online configuration or controller mutation was attempted.

## Original defect and independent counterexamples

Reviewed source: PR #824 head edf48dcf9190b177740eb2802c26f24cfec3c936,
tree 03fed48a967fd33a2cd864c2ac5db8616abb1724.

The verifier ignored `measurement.outer_cpu_ns` completely. The original
retained 128-cell campaign reports outer CPU parent 967221000 ns and children
186165000 ns, with attempted-call totals 624900000 and 119849000 ns. Replacing
the outer counters by zeros, negative integers, Booleans or a string was still
accepted as ORIGINAL_BYTES_AND_ACCOUNTING_VERIFIED. The original object bytes,
row costs, wall intervals and summary decision statistics remained unchanged.
`outer-cpu-reproduction.json` records those four old acceptances. No native or
provider call was made.

`outer-cpu.patch` adds a single shared CPU audit to live summary publication and
independent verification. It requires exactly parent/children domains, exact
nonnegative integer counters and each enclosing counter >= the sum of all
attempted counters in that domain, including failed and audit-error attempts.
It does not compare CPU against wall time or add nested costs a second time.

Counter basis is identical: `cpu()` reads RUSAGE_SELF and RUSAGE_CHILDREN,
adding user and system seconds and rounding each domain to nanoseconds. The
outer start is before initial admission; each call's before/after reads are
nested; the outer end CPU read follows all calls, final identity and source
capture. Additional admission/audit/export CPU is expected, so equality of
outer counters to call sums is not required. These remain trusted local
process receipts, not proof of hardware activity or remote cost attestation.

All original 26 scalar method IDs remain. Two new methods cover exact-boundary
and overhead positive controls, missing/wrong-key/type/understated counters,
an incomplete failed-native fixture and the retained original full campaign.
The exact old checker runs 28 methods with 16 failed subtests (`red.log`);
the candidate runs all 28 with zero skips and no failures (`green.log`). The
small runner loads isolated copies and only reads the original archive; it
does not modify the parent's source checkout or launch a native evaluator.

No fresh benchmark, stable NDU economic gain, provider bill or general task
value has been established. Prepared/persistent experimental conclusions keep
their existing finite within-host scope. The missing economic evidence is an
independent real task cohort and frozen utility/cost evaluator, matched
training/tuning/resources across strong ordinary and NDU controls, all failed
and censored attempts, startup/acquisition/build/provider/billing costs and
independent repeat uncertainty; authored same-pool tables cannot supply it.
