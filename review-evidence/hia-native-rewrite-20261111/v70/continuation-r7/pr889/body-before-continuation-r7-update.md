# HIA native self-rewrite v70 — current integration state

Published source: `67382498b9d60bfecf3696d8c2cb632d8f20281b`  
Tree: `4412879c31f0a9fe489a76f123b919936f8bed67`  
Parent: `8aadee8b8bfc1bda940c9c32b2964429be358e1c`

**This remains a draft. Whole native delivery, default/native selection, live migration, and deletion of the previous owners remain false.**

## What this integration changes

The structural-budget policy now has an HIA controller and native value-graph/binary-integer transport. Its existing public signatures, original resource limits, rejection ordering, and independent reference controls remain part of the acceptance contract.

The latest source commit fixes the two program-execution fixture setup errors observed on its parent: after cold admission, the fixture creates the explicitly configured evidence parent; the builder continues to own exclusive candidate creation. Only that test file and its regenerated support-contract/inventory records changed in this commit. All 3 modified files were checked byte-for-byte, and the complete 3,005-file Git tree was independently reconstructed. There were no additions or deletions in this fixture revision.

## Results bound to the tested source

| Source and gate | Actual result |
| --- | --- |
| `67382498`, original precommit generation/static checks | 7/7 PASS. Contract/inventory generation and original coverage stayed consistent. |
| `67382498`, independent remote clean-source gate | 8/8 stages PASS in 447.586 s; 527 original source tests and the three original scalar-proof tests passed. Source, harness, and interpreter identities were unchanged. |
| `67382498`, [GitHub push run 43107212082](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43107212082), source job 130813541472 | PASS: 527 tests in 1,182.155 s. The original job log confirms the full source commit. |
| Same exact-source push run, native job 130813542162 | **FAIL**: original cold replay hit the unchanged 180 s qualification limit; 6/11 checks passed, actual elapsed 180.192985790 s, return code -9. The owned-child cleanup completed inside the original 3 s cleanup allowance. Later native steps did not run. |
| Associated [PR run 43107221239](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43107221239), actual checkout `89dfe6899f48fc1e2b7c10d2760ac9915584dc5d` | The GitHub-generated merge commit passed 527 source tests in 935.095 s. Its native job independently failed cold replay at 180.181247886 s, 6/11 checks, with owned cleanup complete. This is not an exact-`67382498` observation. |
| New independent remote cold/full qualification for `67382498` | Pending source-matched preparation and execution. The original outer 7,200 s limit, nice 0, unchanged internal stage limits, and original runtime are retained. |

The prior [push run 43098596489](https://github.com/TrillionniumFoundation/Hepta/actions/runs/43098596489) on `8aadee8b` passed its 527 source tests, all 11 cold checks in 142.882019752 s, and 1,242 language checks. That run subsequently failed with two execution-fixture setup errors; its later native steps were skipped. The new fixture commit does not turn that failed run into a pass.

## Cold-timeout investigation

All three original CI artifact ZIPs were downloaded and matched against their original published sizes and SHA-256 digests. Their original cold reports were transferred and verified in full. The phase comparison also retains 109 original phase/index files and three analysis reports.

Both new failing cold runs completed 34 of 38 qualification phases before the limit, without recorded completed-phase exceptions. The original/modified `names` and `exports` phases remained pending. The previously passing run completed all 38. Multiple earlier phases and the work before them took longer in the failing runs; the cause beyond those recorded timings remains unresolved. No deadline, check, input domain, or process-isolation requirement has been relaxed.

## Native owners under development outside this published tree

- **Public heap:** r6's real native controller/payload compilation and 12 targeted controls passed, including source-object identities and report aliases. Its first run of the 134 original public tests retained 11 failure events in five methods that injected the old Python implementation. A separate r7 migrates those injections to the actual consumed native continuation and tests the unchanged 1,024/64/32,768 resource boundaries. The new reference and native groups each passed 134/134 with zero errors/skips; the job has an authoritative successful terminal. Eighteen real boundary observations and two caller-mutation controls passed, with zero old-policy calls. Final composition/pinning/exception-close controls and integration remain pending.
- **Normalization:** the original baseline reporting failure and every subsequent difference remain retained. r4 corrected the original cause-chain and retained-error/root-release discrepancies; six ancestor-note differences remained. Separate controls found four Unicode-length priority differences and two temporary-object lifetime differences. The frozen r5 source addresses those specific findings; its functional result is still separate from complete owner qualification. Physical recursion compatibility and the complete note coordinator remain open.
- **Existing `e03c82d1` deadline failures:** the four-case diagnostic retained the original test bodies and 3,000/1,000 ms limits and completed with two PASS/two ERROR. Within each failing context window, 158 fresh full-source digest calls occupied 2.3915 s / 2.3387 s. These instrumented observations do not replace the original failed full qualification. No cross-public-call source-byte, digest, or mtime cache was introduced.

## Evidence and remaining acceptance

[Audit commit 285a5fdb](https://github.com/TrillionniumFoundation/Hepta/commit/285a5fdb0183139c32e7e6a5a7d164cfc17a5f90) adds the exact fixture publication proof, the complete original `8aade` independent-source-gate archive, full CI logs/cold reports, original phase records, and the native-owner observations. Its index is [continuation-evidence-index-r6.json](https://github.com/TrillionniumFoundation/Hepta/blob/285a5fdb0183139c32e7e6a5a7d164cfc17a5f90/review-evidence/hia-native-rewrite-20261111/v70/continuation-evidence-index-r6.json). Earlier records, including the original failed full qualification and fixture failures, remain in its ancestry. The previous PR description is preserved there as a historical snapshot.

Complete current-source cold/full qualification, the remaining native owners, native CLI/service/worker/runtime/build delivery, and the final replacement/removal gates are still required. This PR does not perform or claim default/live migration or legacy deletion.
