# PR817 published 6a CI final readback

Head: `6a8c297b3f8f21506d11c2cb093c1c58d84ffe55`. Tree: `635d02f8f2b8151ae4697365e1962b070e4015a3`.

Observed 2026-11-09 05:01:17 UTC; all job metadata retrieved 05:01:51 UTC. All 19 workflows completed successfully on attempt 1. Initialization completed at 04:58:44 UTC, with 80 successful jobs.

The complete set contains 114 jobs: 113 successful and one conditional skip. The skipped job is `Optional original native NDU qualification`, gated by workflow_dispatch and run_native_ndu. This pull_request event did not request it. No claim is made that the optional job ran.

Checkout scope: 17 workflow configurations explicitly select the event head. Linux and Safe Core actually checked out d8dbec3de419ae45f719774dccbdfecb8bfa4493, whose tree matches the 6a source tree; they did not check out the later prospective merge 8cbe. Independent audit: ../ci-6a-default-checkout-review/review.json. The exact-source and focused fixture logs separately identify actual 6a.

The 723 unique registration inventory retains 712 sharded IDs plus 11 disjoint deadline IDs. Focused capture, deadline, relocation runner and grammar job logs are retained unchanged in this directory.

| Run | Workflow | Event | Result | Jobs |
| --- | --- | --- | --- | --- |
| [42558245653](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42558245653) | HIA exact source closure | push | success, attempt 1 | {'success': 1} |
| [42558245656](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42558245656) | HIA NDU scalar caller selection integration | push | success, attempt 1 | {'success': 1} |
| [42558251835](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42558251835) | Hepta actual host ABI qualification | pull_request | success, attempt 1 | {'success': 8} |
| [42558251836](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42558251836) | Hepta real upstream C++ host qualification | pull_request | success, attempt 1 | {'success': 7} |
| [42558251849](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42558251849) | HIA Agent native tools | pull_request | success, attempt 1 | {'success': 1} |
| [42558251854](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42558251854) | HIA projected guarded-slice kernel research (DENY_ALL) | pull_request | success, attempt 1 | {'success': 1} |
| [42558251855](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42558251855) | HIA verified optimization and native NDU integration | pull_request | success, attempt 1 | {'success': 1} |
| [42558251861](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42558251861) | HIA P0 native NDU p99 and protocol acceptance (research DENY_ALL) | pull_request | success, attempt 1 | {'success': 1} |
| [42558251862](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42558251862) | HIA shared full eleven acceptance (DENY_ALL) | pull_request | success, attempt 1 | {'success': 2} |
| [42558251864](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42558251864) | HIA finite CRC context and static controls | pull_request | success, attempt 1 | {'success': 1} |
| [42558251869](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42558251869) | HIA intelligent assembly closure | pull_request | success, attempt 1 | {'success': 1, 'skipped': 1} |
| [42558251871](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42558251871) | HIA initialization frontier research (Python only, DENY_ALL) | pull_request | success, attempt 1 | {'success': 80} |
| [42558251886](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42558251886) | HIA direct x86-64 machine backend | pull_request | success, attempt 1 | {'success': 1} |
| [42558251908](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42558251908) | HIA captured C application on native Linux hosts | pull_request | success, attempt 1 | {'success': 2} |
| [42558251915](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42558251915) | HIA unified candidate source qualification | pull_request | success, attempt 1 | {'success': 1} |
| [42558251920](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42558251920) | HIA Linux native component and evidence contract | pull_request | success, attempt 1 | {'success': 1} |
| [42558251928](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42558251928) | HIA six-outcome source and application gates | pull_request | success, attempt 1 | {'success': 1} |
| [42558251955](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42558251955) | HIA round4 runtime controls | pull_request | success, attempt 1 | {'success': 1} |
| [42558252105](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42558252105) | HIA Safe Core final image | pull_request | success, attempt 1 | {'success': 1} |

These hosted results do not overwrite either preserved historical 108-method local failure record. They do not by themselves establish full Core self-hosting, general machine/ABI/resource/FFI correctness, Agent adoption, or stable incremental/economic benefit. No workflow was rerun or cancelled by this observer.
