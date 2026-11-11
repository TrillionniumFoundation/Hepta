# Exact v63 complete retained regression: terminal HOLD

This addendum records the terminal result of the run that was still active in
evidence commit `91aaaed70ca3c26f778afe4490b5ded6972853b2`. Earlier reports and
observations are unchanged. The tested product remains exactly
`93d66bcc3acb88212c9b153d7852ba22eeab24c8`, tree
`0a67bf07951505a50e9aeb888f1c2c448d1eb816`.

## Result and limits

The actual ROG full retained regression ran **4,031 tests**, with **two failures,
zero errors and 143 skip records**. Its result is **HOLD**. The two failures are:

- `CompositeBulkNativeTests.test_full_native_oracles_and_strict_retained_receipts`:
  the selected QEMU differed from the repository's reviewed executable.
- `JsonPreflightHiaNativeTests.test_existing_api_dispatch_and_unchanged_original_regressions`:
  the nine original child tests exposed two exact diagnostic differences between
  native dispatch and the retained API. A later stale six-test parent assertion
  also needs correction, but was not reached in this failed execution.

Skip records identify absent explicit native/compiler/proof fixture selections.
One is a `setUpClass` skip covering three formal-test methods, so restoring the
environment can change the executed-test count. A later qualification must
discover and execute its complete current suite; 4,031 is not a target to freeze.
`skip-source-env-mapping.json` maps the observed omissions to source variables.
`c80-named-prerequisite-live-discovery.json` is a later read-only discovery of
surviving prerequisite paths. Their presence alone does not qualify their bytes,
current source bindings, or a later run.

The strict full runner returned exit 1. The outer process guardian also reports
HOLD, while independently observing complete cleanup, the leader reaped, kernel
ECHILD, and no remaining direct/adopted children. Input source identities were
preserved. Cleanup under hard SIGKILL, host loss or privileged namespace
interference is not claimed. The separate cold deadline remains 180 seconds.

Both exact-tree GitHub Core workflows already passed 298 source controls and
555 native unittest cases. Those scoped passes do not override this complete
retained-suite HOLD. The original Core CI omitted the full native preflight
test class; the failed complete run establishes why that gate must be included.
Whole-native delivery, default cutover and old-stack retirement remain open.

## Original evidence and durable custody

The JSON files copied here are original issued bytes, without normalization.
`full-retained-regression.json` has SHA-256
`4e607d85c58dcc666ce2202fc40a2e2f8503cbdd6a2a6eeb5ed0728014aca196`;
`guardian.json` has SHA-256
`40c1be26ef807f3f8e356863330a3dbeffb19d057b313d4219f7b5e3d8e89276`.

The separate home archive on ROG preserves 931 original report/log/compiler
files, totaling 138,711,147 decoded bytes. Its 9,894,472-byte gzip archive has
SHA-256 `7a6eb1b5279546a49f007e2abe994a36726c528fc45b4ecf57c66c1083d909b6`.
The recorded archive members were read back and fsynced. The archive itself is
not embedded in this Git checkpoint; `PRESERVATION.json` identifies its actual
location and scope. Source snapshots and unlisted compiled payloads are not
claimed preserved by that archive.

Both original GitHub artifact ZIPs are separately retained on ROG, with exact
size/hash, creation, fsync and readback receipts included here. GitHub's seven-day
artifact expiration is not treated as durable retention. The original
53,303-byte external-guardian control archive is embedded here with SHA-256
`916195860b2462b97fe39c6ac47d4f8ff93355ea946c1ca8d761025d826fe261`.
Its five controls exercised normal completion, deadline, SIGINT, SIGTERM and
BaseException paths with actual descendants. This is distinct from the full
qualification's terminal guardian record.

No original failure has been replaced with a later successful observation.
Every subsequent fix needs new source identity, regeneration and qualification.
