# Final CI readback for PR817 source candidate B

**All 19 applicable workflows report success for head `6ecd8023615a6e0b2dc269379fb059c656b38b6f`.** The exact Git tree is `4c51962e030e9ea39c6498224c99eb40fbdd2f35`. The official final snapshot was read at 2026-11-09 06:19:37 UTC; the source branch still pointed to that head.

Guarded-slice reached success on attempt 3; shared-kernel reached success on attempt 2. The other 17 workflows succeeded on attempt 1. The earlier two guarded and one shared dependency-download failures remain preserved as failures. They were not overwritten by later success.

## Workflow conclusions

| Run | Event | Workflow | Attempt | Conclusion |
| --- | --- | --- | ---: | --- |
| [42565815198](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42565815198) | pull_request | HIA six-outcome source and application gates | 1 | success |
| [42565815288](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42565815288) | pull_request | HIA round4 runtime controls | 1 | success |
| [42565815128](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42565815128) | pull_request | HIA direct x86-64 machine backend | 1 | success |
| [42565815275](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42565815275) | pull_request | HIA captured C application on native Linux hosts | 1 | success |
| [42565815129](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42565815129) | pull_request | HIA finite CRC context and static controls | 1 | success |
| [42565815093](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42565815093) | pull_request | Hepta actual host ABI qualification | 1 | success |
| [42565815367](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42565815367) | pull_request | HIA Linux native component and evidence contract | 1 | success |
| [42565815253](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42565815253) | pull_request | HIA Agent native tools | 1 | success |
| [42565815350](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42565815350) | pull_request | HIA Safe Core final image | 1 | success |
| [42565815235](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42565815235) | pull_request | HIA shared full eleven acceptance (DENY_ALL) | 2 | success |
| [42565815332](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42565815332) | pull_request | HIA initialization frontier research (Python only, DENY_ALL) | 1 | success |
| [42565815228](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42565815228) | pull_request | HIA projected guarded-slice kernel research (DENY_ALL) | 3 | success |
| [42565815126](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42565815126) | pull_request | HIA intelligent assembly closure | 1 | success |
| [42565815024](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42565815024) | pull_request | HIA unified candidate source qualification | 1 | success |
| [42565815021](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42565815021) | pull_request | Hepta real upstream C++ host qualification | 1 | success |
| [42565815059](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42565815059) | pull_request | HIA verified optimization and native NDU integration | 1 | success |
| [42565807355](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42565807355) | push | HIA exact source closure | 1 | success |
| [42565807356](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42565807356) | push | HIA frozen scalar controller controls | 1 | success |
| [42565807348](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42565807348) | push | HIA NDU scalar caller selection integration | 1 | success |

## Job records and the applicable test inventory

The latest job records across these workflows contain **114 successes and one conditional skipped job**, for 115 records. The skipped job is `Optional original native NDU qualification`, whose unchanged guard requires an explicit `workflow_dispatch` and `inputs.run_native_ndu`; this cohort ran via pull requests and pushes. Host-specific conditional skipped steps remain visible in the original metadata. This is not a claim of zero skips across all jobs or steps.

The shared-kernel attempt-2 API also carries forward the original successful source-controls execution under a new latest-attempt job record. Its old execution timestamps are preserved. It is not counted as a fresh second execution.

Initialization completed all 80 jobs on attempt 1. Five retained focus logs show the 11 cleanup/deadline tests, 8 real-PTY observation tests, 41 capture tests, 11 relocation-runner-b tests, and 10 relocation grammar tests, each at the actual B checkout. The shard registry asserted 712 existing combined IDs, 11 disjoint deadline IDs, and a union of 723. That registry is a named subset of the broader workflow.

The original known-child observation reported PID 2277, starttime 3383 and process group 2276. It observed that identity absent after 0.066691701 seconds, within the same original 1.5-second total deadline. The production cleanup scope remains the leader and captured streams; this fixture observation is not a proof about every arbitrary descendant. Earlier local 108-method failures remain separate historical executions.

## Checkout and artifact identities

Seventeen workflow configurations explicitly request the event head. The two default-checkout workflows (Linux and Safe Core, three jobs) actually used `16add3df22d58fd5486541837cdaf73a21317c49`, parents `20eace…` and B, with the same `4c51962e…` tree. They did not check out B as a commit. Their original logs and artifacts were independently checked in `../pr817-b6ecd-readonly-review/default-checkout/`. The exact-source audit is separate in `../pr817-b6ecd-readonly-review/exact-source/`.

The raw exact-source log binds the primary checkout to B and includes the actual current-compiler borrowed-buffer lifecycle step. Later dependency checkouts in selected logs have their own pinned identities and are not confused with the main source.

| Artifact | ID | Bytes | Official SHA256 |
| --- | ---: | ---: | --- |
| exact_source / hia-exact-source-6ecd8023615a6e0b2dc269379fb059c656b38b6f | 13652892138 | 36367360 | `sha256:819cdb66f6fd7cb1de3c02f52bdabfbb27f009f30f849778d132df29f83ea8cc` |
| scalar_selection / hia-ndu-scalar-selection-6ecd8023615a6e0b2dc269379fb059c656b38b6f | 13651783665 | 8087254 | `sha256:829735b11f5a4be9eb30e0eaee180dc7cca6b1fc3f93797e2d343b3c8d2dfad0` |
| controller / hia-scalar-controller-controls-6ecd8023615a6e0b2dc269379fb059c656b38b6f | 13652586985 | 1695614 | `sha256:d46fb19432aea914534506a81f44b2d86786adbc0bb26fdd5c61911f6f7fefb6` |
| ndu / hia-verified-optimization-6ecd8023615a6e0b2dc269379fb059c656b38b6f | 13653895483 | 19759307 | `sha256:d8ad94fe9ab18679c1475de2e490c03620081e58bad52654031c73253e2d1dff` |
| shared / hia-shared-kernel-6ecd8023615a6e0b2dc269379fb059c656b38b6f-42565815235-2 | 13653386407 | 6565999 | `sha256:9fe4600679be0a07c34e2562591551b9702bf49386fd7c55cf1a66e2f6bf57c3` |
| shared / hia-shared-source-controls-42565815235-1 | 13652338443 | 5886 | `sha256:0c7ba7f99e9921fb9c6cf50c257114942387a5f36cf3f2731be561718846f813` |

## Failed attempts and retry boundary

The two initial Lean-acquisition workflows failed after four HTTP 504 download responses. Guarded attempt 2 failed the same acquisition stage again. Dependent proof steps had not run at those failed points; the underlying gateway cause remains unknown. Root explicitly triggered standard single-job reruns, preserving each earlier raw run/job/log package. Shared attempt 2 then acquired the same fixed Lean and completed its proof; root used that concrete availability evidence for one further guarded retry, which succeeded. Source, hashes, the original four-download-attempt budget, timeouts and proof gates were unchanged. This observer triggered no retries or cancellations.

Guarded success still declares the twelve wider obligations unproved. Shared success retains its narrow syntax scope and DENY_ALL. CI success does not establish full Core selfhosting, a general machine-correctness theorem, provider adoption, or stable economic gain. Merging, publication and public installation belong to the separately recorded next steps.

## Retained files

`final-runs.json` is the original REST body for the nineteen terminal workflows. `final-head-ref.json` is the actual branch-ref body at that observation. The seventeen `final-jobs-*.tool.json` files preserve the successful purpose-built job response envelopes; initialization and final NDU retain their full REST bodies. Original focus logs, acquisition-failure packages, successful later attempts and relevant artifact metadata are included in the recursive file manifest. No large original ZIP was duplicated for this readback.
