# First full8 attempt on public 699de39 — actual failure checkpoint

**This archive preserves a failed qualification attempt. It is not a passing
qualification, and it does not close all P0–P7 blockers.** It captures the original
attempt and its independent review before the separately recorded retry.

The tested public source is `699de39a8e92e0f083df316ecc5333fb3ecf8571`, tree
`592b6114f659fb18b13ad3fa5ed5e213ecdb92b5`. The original process started at
**2026-10-29 11:19:50.848112 UTC** and finished at
**11:46:56.129112 UTC**, with return code **1** and recorded wall time
**1,625.2810017620068 seconds**.

## Actual recorded result

| Observation | Original result |
| --- | --- |
| Full integrated gates | **6/8 passed** |
| Nonpassing gates | `full_regression`, `merge_and_profile_coverage` |
| Python regression | **3,628 methods: 3,627 ok + 1 ERROR** |
| Python failures / skips | **0 / 0** |
| Rust tests | **88 passed** |
| Source files independently checked against raw Git | **4,385, unchanged** |
| External files independently rehashed | **440, unchanged** |
| Independent record-integrity review | **75 checks passed**, no audit-integrity findings |

The one recorded error is
`test_cpp_constructors.CppConstructorTests.test_real_nondefault_boost_and_vector_constructor_roundtrips_and_allocation_refusal`.
The actual `/usr/bin/g++ -std=c++20 -M` dependency command failed because
`boost/math/distributions/students_t.hpp` was unavailable. The exact command,
compiler diagnostic, traceback, and `FAILED (errors=1)` regression footer are
preserved. The gate failures remain failures; an environment repair or later
successful retry does not rewrite this result.

The independent review establishes that the original reports, raw logs, method
counts, source identities, and external-input identities are consistent. Its
successful integrity check is separate from the failed qualification itself.

## Complete original input set

The compressed archive contains exactly these original inputs, preserving every
file and directory, original bytes, relative paths, and permission modes:

- Complete `final-qualification-699de39/`: **50 files**, including original
  process/invocation records, source inventories, qualification report, logs,
  original safety stdout, and retained target-profile fixtures.
- Complete `final-run-independent-review-699de39/`: **16 files**, including the
  independent auditor, full method-status index, original diagnostic extraction,
  review manifest, and the earlier `parser-attempt01/` failure.
- Original `run_final_integrated_699de39.py`.
- Original `source-publication-699de39.json`.

There are **68 original file members** plus their directories. No original input
is modified, deleted, or renamed. The earlier parser failure is retained as an
audit-tool development failure, separate from the actual Boost-related runtime
qualification error. The collector does not recreate missing temporary native
binaries or claim that the original safety binaries were retained.

The archive intentionally contains only the four input groups above. This README,
collector, manifest, credential scan, summary, and publication receipts are
separate control files. The archive does not include retry results, current
toolchains, extra source checkouts, private signed transport references, or the
separately frozen hosted-CI evidence.

## Verification and publication

`MANIFEST.json` records the complete original membership, SHA-256, Git blob
identity, byte count, and permission mode. Tar timestamps are set to zero for
deterministic packaging; this does not change original file bytes or modes.
Every compressed member was read back **as a stream**, and its exact bytes,
SHA-256, Git blob identity, and mode were checked. The original directories were
then inventoried again and all original file hashes and modes rechecked.

`publication-payloads.json` defines the exact publication files and archive
identity. An archive at most 12,000,000 bytes is published whole; a larger archive
uses explicitly ordered parts no larger than 4 MiB, with complete reconstruction
verification. `PUBLIC_FILES.json` is the selected public allowlist and
`freeze-receipt.json` binds the collection results.

A limited ten-pattern credential scan covers all 68 original files and the
generated public files. No private transport reference files are read. No native
program, test suite, workflow, source modification, or qualification retry is
performed by this checkpoint collector. The Python production authority and
`no_change` optimization policy are not altered.
