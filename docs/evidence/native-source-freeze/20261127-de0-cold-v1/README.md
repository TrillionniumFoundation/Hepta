# Exact unified native cold failure, 2026-11-27

The source was `de0c0325ef1ece788666695638b6bebbdc329eda` with Git tree `62102d919de9eeb79e02a5d79e0651ffa182816f`. This was one actual new seven-stage construction, native source export, and full cold attempt using the newly matched seven native roots. No prior cold pass was transferred.

The seven construction stages passed with 4,442 nodes and 45 installed tools. Native execution took 68.365655125 seconds and cleanup took 33.234555 milliseconds; its external observation took 108.482662781 seconds. The native exporter passed both modes and checked all 1,282 native source files (247,298,524 bytes), excluding host-language files and compiled images.

The full cold **failed at its original 180-second deadline**. The actual owner receipt reports leader status 124, timeout, 180.004272250 seconds to deadline observation, and 33.564060 milliseconds of bounded cleanup. The outer native entry returned 1 after 199.915616713 seconds. The 180/3-second limits, 60 phases, 479,882 planned nodes, 14 checks, and scheduler capacities 2/1/2/4 were unchanged. No post-bootstrap, release, installation, or installed rebuild was started.

At terminal readback, 25 archives were nonempty. This is a physical observation, not a claim that all 25 archives were sealed or admitted. The custody report pins all 101 remaining qualification files, totaling 615,912,050 bytes. The original and modified scalar-cast drivers had advanced beyond the preceding failed attempt; the names phases were partly recorded. The full catalog remains incomplete.

The starting machine was the 32-thread AMD RYZEN AI MAX+ 395, with load average 21.14 and about 34.5 GiB available memory. Complete read-only resource samples and the actual trace are retained. CPU signal readback distinguishes master children with observed child processes from those without. Large archive headers declare one file, so quadratic name lookup is not the leading explanation for their cost.

The independent read-only journal decoder verifies each observed node against the frozen plan and fully decodes physical backward references. Its 227,477-byte report has SHA-256 `ed5e1280affe1762c7ae66528487769c1dd8218cc1f486b8b7f76af55d53292d`. Nine inspected journals were complete; original names stopped after 14,049 of 19,314 nodes and modified names after 19,133 of 19,314 nodes. This diagnostic does not turn complete journals into admitted phase archives. Actual `HIASBR01` receipt PIDs and `SIGCHLD` parent chains unambiguously attribute all sampled completed-phase children to their phase drivers. The killed names parents cannot be fully attributed from the retained terminal signal records, so the report leaves them unmapped.

| Completed journal | Driver user CPU seconds | Actual subprocess elapsed seconds |
| --- | ---: | ---: |
| Original signed | 14.11 | 7.724802701 |
| Modified signed | 14.11 | 7.921831010 |
| Original scalar casts | 13.05 | 6.345967865 |
| Modified scalar casts | 14.61 | 6.552531802 |

These are different measurements: signal CPU accounting and the sum of actual child-receipt elapsed times. They are not subtracted or represented as a complete profiler. The read-only diagnostic scripts and exact source/report hashes are retained. Later optimization or hardware load changes cannot retroactively change this failed qualification.

`native-de0-cold-failure.tar.gz` contains 23 original evidence members, including the native owner receipt, full 7,066,068-byte execution trace, resource samples, construction/export reports, campaign logs, and custody inventory. Every member is pinned by its `MANIFEST.json`. The archive is 471,809 bytes with SHA-256 `70e5a1d515aa27b8f16b2a7ba471805dd70154bb5a2388bb36a99a3c1da0edd2`. All members were independently decoded and verified after transfer.

The original transport difficulties and a CPU-name capitalization preflight failure are retained separately from the one actual native campaign. The preflight started no native child; the subsequent uncertain launch acknowledgement was reconciled using the same terminal identity and idempotency key. Incomplete archive transport was not labeled a complete transfer: an independently pinned member manifest verified all required complete members, while source bytes were obtained by exact Git fetch and tree/source readback.

No failed report, receipt, budget, or assertion was modified. These records do not qualify the full cold, native delivery, or whole HIA stack, and do not authorize deleting the legacy implementation before its remaining gates close.
