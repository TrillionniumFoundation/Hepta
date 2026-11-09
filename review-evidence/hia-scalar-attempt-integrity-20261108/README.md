# Scalar-controller attempted-call evidence integrity

Upstream source: PR #812, `987cc402bc105e2ccbb896d4e29cc2da6f7288e8`.
This follow-up repairs the review finding that an incomplete pair could bypass
both cells' evidence audit. It does not change the frozen campaign or its
performance observations.

Every attempted cell now reads and checks its retained result and observations,
including every nested raw-byte object. Native request bytes and present pump
streams must retain their byte representation. Failed calls retain their error,
absent result, partial streams and nonnegative measured costs; this does not
admit their decision or relabel a partial stream as complete. A successful cell
receives the full winner/request/response/cleanup audit even if its paired arm
failed. Only the paired timing comparison requires two successful cells.

The end-to-end independent-verifier fixture accepts a complete set of retained
bytes for an explicitly incomplete campaign and preserves `INCOMPLETE`. Removing
the successful result, failed observations, failed stdout or failed stderr makes
verification refuse. Additional controls reject a wrong winner hidden behind a
failed partner and malformed failure costs/statuses. Unstarted cells cannot
retain synthetic execution observations.

The execution environment reset during this task. The exact upstream assessor
and test files were retrieved again and reconstructed in a minimal checkout.
Eleven offline tests ran against both versions: the original assessor has 14
failing subcases, while the candidate passes all eleven with no errors or
skips. The existing production-selector test requires the full repository and
was excluded from this minimal-checkout run; this is not a full repository CI
claim. Source hashes and raw logs are in `validation.json`,
`original-tests.log` and `candidate-tests.log`.

All new inputs are authored integrity/accounting fixtures. No native evaluator,
provider, application workload or new timing campaign was invoked. The change
does not establish incremental NDU value, stable performance or economic gain.

The root integration restored the complete PR812 checkout and ran the whole
`tests.test_hia_scalar_controller_controls` module: 12/12 passed, no skips
(0.147 seconds), including the original production-selector no-dispatch test.
This resolves the minimal-checkout omission above; it adds no native campaign.
