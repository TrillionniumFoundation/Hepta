# Current-head paid-retention local qualification

A fresh local attempt executed the published portable twelve-case gate on source commit `f90dc793ef94dbf0c7fe3c0431c4f4d1c9768471`, tree `e2a9a55a31287c8c5932c2db486f4a2afe81bf14`, and passed all **12 tests with zero skips, failures or errors**. The receipt records a clean source before and after. The checkout was sparse: unrelated historical evidence, experiments, artifacts and reports were omitted from the working directory. Its Git commit/tree and all seven snapshotted input files were exact.

This evidence-only commit has that source head as its parent. The PR source head remains fixed. This is a local qualification result; at 2026-11-09 15:46:41 UTC, the [push gate](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42646271786) and [PR gate](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42646285018) were both **queued**. See [HOSTED_CI.json](HOSTED_CI.json) and the two original decoded API snapshots. Hosted CI has not been substituted with the local result.

## Original bytes and identity checks

[original-attempt.tar.xz](original-attempt.tar.xz) retains all **164 original files, 1,076,903 bytes** written beneath the original attempt directory. This includes the execution receipt, verbatim workflow step and stdout/stderr, all seven source snapshots including `source/.github/workflows/hia-paid-observation-retention.yml`, the running/final qualification receipts, ten fixture groups, actual databases, owners, protocol/source copies and all journals that the tests wrote. Original unit controls that wrote only databases are retained as such; no missing in-memory results have been invented.

- Archive: **36,236 bytes**, SHA256 `c777510c5731d9301b8f4eb6b8857b522031f39034417d627f418b0607a8af79`.
- [FILE_INDEX.json](FILE_INDEX.json): SHA256 `4513093fc634f303688365ff245b58c1cc2d014befe5ace58cf049f1f4af8d76`.
- Original [EXECUTION.json](EXECUTION.json): SHA256 `90c8f45fa748f27f30af42f259bb4ba8f18fd7d676793513f20edd524ada2b10`.
- Original final [QUALIFICATION.json](QUALIFICATION.json): SHA256 `9145e0246b58d4b701ca0034cab20fdb37b8f3600d11d47145c0552d07df2b42`.

The read-only packager reread every indexed archive member and required byte equality to the original files. [BYTE_AUDIT.json](BYTE_AUDIT.json) also checks all twelve expected, loaded and actually executed IDs; zero skips/errors/failures; ten retained fixture groups; all seven published source identities; clean before/after state; and the unchanged **2,000,000,000 ns cell budget**. The executed shell step is byte-identical to the published workflow's run block. Its stdout is byte-identical to the retained test log. The full hidden workflow snapshot is present and matches the published workflow's SHA256 `720b315a885957d148dd6e55861dea6025139689ecbe08671f60675699cd91cc`.

The [packager](package-original-local.py) and [expected identities](expected.json) are retained for review. Packaging imported or executed no producer, worker or test. It normalized archive container metadata; original file contents were preserved verbatim. It did not replay any old operation.

## Observed execution and costs

The fresh attempt ran from **2026-11-09 15:43:18.506920 UTC** to **15:43:26.184730 UTC**, exited 0, and produced `PASS_CURRENT_HEAD_12_TESTS`.

| Measurement | Observed value |
| --- | ---: |
| Qualification wrapper's suite wall | 7,363,924,888 ns |
| Qualification wrapper's parent CPU | 538,883,000 ns |
| Qualification wrapper's child CPU | 6,020,739,000 ns |
| Root wrapper's outer elapsed | 7.9166509520000545 s |
| Root wrapper's setup wall | 0.23820943300052022 s |
| Root wrapper's workflow-step wall | 7.654178963999584 s |

These are different nested scopes; they must not be summed. They are local observed timings, without independent timing attestation, and do not establish full monetary cost.

## Earlier failures and NDU boundary

The original eleven-case development attempt's **three failures remain failures with unresolved causes**. This new success does not retrospectively explain them. The earlier deterministic deadline counterexample and its failed-before/passed-after records remain in the [source PR's original evidence](https://github.com/TrillionniumFoundation/Hepta/tree/f90dc793ef94dbf0c7fe3c0431c4f4d1c9768471/review-evidence/hia-paid-retention-20261109). The old audit session 17910's exit remains UNKNOWN.

NDU remains **NOT_RUN**, with zero real Agent/provider calls. The retained pilot's strongest VOI/MPC controls remain tied. Synthetic fees, the known task partition and the incomplete billed-cost boundary have not become NDU-value or independent-holdout evidence. **P5 remains HOLD.**
