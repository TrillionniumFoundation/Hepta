# Independent original candidate CI artifact audit

This audit reads the untouched ZIP from original source CI run `42574596830`,
attempt 1, artifact `13654684567`, for candidate
`edf48dcf9190b177740eb2802c26f24cfec3c936`, tree
`03fed48a967fd33a2cd864c2ac5db8616abb1724`.

The 38,116,519-byte archive has SHA256
`d053d024bc07cea7a6f290c385ee48ae6a9acee7ce3b0832a0629c8c1a350494`.
Its 29,184 unique members pass CRC checks. No bulk extraction, native execution,
new cold qualification, new benchmark, live-service mutation or default-lock
publication occurs during this audit.

## Checked records

- All **253** cold/full/language source-manifest entries are identical across
  the three original reports, match actual Git source bytes from the reviewed
  tree, and match every corresponding source-only cold export member.
- The original v16 cold report passes **11/11** checks in **118.686899132 s**,
  within the unchanged **180-second** qualification limit. Its owned-process
  request fixes that absolute deadline. Cleanup took **9.442274 ms**, within
  the unchanged **3-second** limit, with the leader reaped, final kernel
  `ECHILD` observed, no direct children remaining and no cleanup errors.
- The nested full qualification passes **1545/1545** checks in
  **117.592872840 s**. All 22 named phase-report digests and zero-exit records
  were checked, as were all 12 original/modified B1–B3/M1–M3 produced image
  hashes across nested and language reports. A separate standalone warm report
  is not present; the nested full report is not relabelled as a separate run.
- Native language qualification passes **1196/1196** checks, with **1183 scalar
  witnesses** and **10/10** native-report assertions, zero skipped assertions.
  The original independent-reference and native-assertion report digests match.
- All **379** Hepta files in the candidate release lock match the actual Git
  tree. The runtime identity remains commit `4cd85c99…` / tree `6b78d53b…`;
  the lock's 13 runtime file bytes were not independently re-fetched here.
  The unchanged original lock is 48,630 bytes with SHA256
  `52b639b1a5b6f642df86f22388d71323fd0613b07e483c7a41593796f05e1cf8`.

The lock is **a candidate artifact**, not a final merged-source artifact. It is
not eligible to replace the default lock under the user's final-source contract.
No source-base merge qualification follows merely from this artifact audit.

## Scope and remaining HOLD

The reports establish finite execution and input/source identity observations
for the declared bounded v16 profile. They explicitly do not prove full Core,
whole compiler, general ABI/resources/FFI/full ISA or loader correctness.
Trusted host dependencies, local timing/process receipts and loader/hardware
assumptions remain. The process owner explicitly records
`historical_descendant_inventory_complete: false`; final cleanup is not a
claim of complete historical observation or a production admission freeze.

The lock retains `source_lock_only: true`; deployment, default-branch update,
first-use, NDU value and runtime source-only-loading assertions remain false.
The original unfamiliar-Agent full verification/evaluation/adoption contract,
provider invoice and stable fair full-cost NDU economic benefit remain HOLD.

`audit.py` reproduces these read-only integrity checks, `audit.log` records the
successful run, `audit.json` gives the scoped result, and
`source-identities.json` retains every verified source identity. Counts overlap
and are not additive independent test totals.
