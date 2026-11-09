# Main 3586de2 original CI readback

Exact commit `3586de2e86031bccf9c37d210fde84dac766d1c7`, tree `a3fa0ac98769cd4a1aadd8513c4c88d5c3172930`. This package freezes the fixed two-workflow cohort, all on attempt 1, and retains the original returned JSON bytes plus both complete public job logs. Public installation result: **SUCCESS**. CodeQL: **4/4 jobs success**.

- [Push on main](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42578232105), run 42578232105, dynamic, success.
- [HIA public release consistency](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42578231472), run 42578231472, push, success.

Both public installation jobs and all four CodeQL jobs succeeded on first attempts at this exact main commit. Later main4fd has its own distinct failure record.

Both public logs show the exact commit after `git log -1 --format=%H`. Both rows completed source materialization and source-contract verification before the discovery step. Original uploaded-artifact ID, size and digest lines match GitHub metadata. The ZIPs were not downloaded by this observer. CodeQL job identities here use the original API records; no separate CodeQL checkout-log audit is claimed.

`readback.json` records the concrete job IDs, steps, actual discovery errors where present, source-helper results, and original artifact metadata. `files.json` hashes all package members except itself. No original failure is erased or retried, and these records do not substitute for the reconciled document candidate or a later main commit. No project code, native programs, compiler, Lean or solver ran locally.
