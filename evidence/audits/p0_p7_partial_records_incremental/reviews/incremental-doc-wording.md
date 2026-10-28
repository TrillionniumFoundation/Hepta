# Follow-up: canonical no-op qualification for session concurrency

Static read-only confirmation against frozen `d942f18b`:

- `_prepare_program_patch` in `hepta/hia_program_tools.py` permits replacing a
  function, operation or terminator with its current contents. It checks the
  expected canonical digest but does not require the candidate to differ.
- `IncrementalVerifier._verify_locked` in `hepta/hia_incremental.py` accepts the
  verified candidate and stores its snapshot even when the canonical digest is
  unchanged. No session revision counter invalidates the old digest.
- Therefore, if a legal canonical no-op acquires the lock first, a changing
  patch naming the same original digest can subsequently succeed too. Their
  returned programs may differ. The existing concurrent changing-patch test
  remains valid and is not a test of this no-op ordering.

The sentence in `docs/HIA_INCREMENTAL_VERIFICATION.md` saying that two patches
for one baseline cannot both commit different results needs this qualification.
Suggested replacement:

> A session serializes its operations and checks each patch's expected digest
> against the current baseline under the same lock. If the first accepted patch
> changes the digest, the next patch naming the old digest is rejected as stale;
> an accepted canonical no-op leaves that digest valid. Multiple sessions are
> independent.

This is a documentation correction based on source inspection, not a newly
executed program or test result. No repository document or implementation file
was changed by this review. A later documentation-only correction should retain
the original execution binding to `d942f18b`.
