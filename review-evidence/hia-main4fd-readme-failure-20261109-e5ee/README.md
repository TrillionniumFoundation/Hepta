# Main 4fd6b62 original CI readback

Exact commit `4fd6b62b442e4198f43bf3595fa9e35b0f438102`, tree `cb6e378d2ddf64fbde32817a5285eb3a24eaddac`. This package freezes the fixed two-workflow cohort, all on attempt 1, and retains the original returned JSON bytes plus both complete public job logs. Public installation result: **FAILURE**. CodeQL: **4/4 jobs success**.

- [HIA public release consistency](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42579114133), run 42579114133, push, failure.
- [Push on main](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42579114279), run 42579114279, dynamic, success.

Both original public jobs fail with public README is empty at the discovery gate. Native examples and installation-manifest equality did not execute. The partial uploaded artifacts are failure evidence, not complete public installation acceptance.

Both public logs show the exact commit after `git log -1 --format=%H`. Both rows completed source materialization and source-contract verification before the discovery step. Original uploaded-artifact ID, size and digest lines match GitHub metadata. The ZIPs were not downloaded by this observer. CodeQL job identities here use the original API records; no separate CodeQL checkout-log audit is claimed.

`readback.json` records the concrete job IDs, steps, actual discovery errors where present, source-helper results, and original artifact metadata. `files.json` hashes all package members except itself. No original failure is erased or retried, and these records do not substitute for the reconciled document candidate or a later main commit. No project code, native programs, compiler, Lean or solver ran locally.
